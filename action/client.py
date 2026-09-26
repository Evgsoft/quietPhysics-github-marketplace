#!/usr/bin/env python3
"""Lightweight QuietPhysics Closed-Source Client Runner for Customer GitHub Actions."""

import base64
import json
import os
import sys
import urllib.request
import urllib.error
from typing import Optional


# Every comment this action posts starts with this header (see
# src/quietphysics/cli/github_reporter.py's generate_pr_comment_markdown,
# which builds the markdown this client receives and posts verbatim).
# Used to find a prior QuietPhysics comment on the same PR so a re-run
# updates it in place instead of piling up a new comment on every push -
# see plans/03-github-action-client.md #8.
COMMENT_MARKER = "## \U0001f6e1️ QuietPhysics Security Invariant Gate"


def parse_pr_number(ref: str) -> Optional[int]:
    """Extracts the PR number from a GITHUB_REF like 'refs/pull/12/merge'.

    Pulled out of main() as its own pure function so it's directly
    unit-testable without mocking a network call or running the whole
    script - see plans/03-github-action-client.md #3.
    """
    if "refs/pull/" not in ref:
        return None
    try:
        return int(ref.split("/")[2])
    except (IndexError, ValueError):
        return None


def build_pr_comment_request(
    markdown_body: str,
    github_token: str,
    repo: str,
    pr_number: int,
    comment_id: Optional[int] = None
) -> urllib.request.Request:
    """Builds (but does not send) the GitHub API request to post or update a
    PR comment. Also its own function for the same testability reason as
    parse_pr_number() above - a test can inspect the constructed
    Request's URL/headers/body without ever touching the network.

    With comment_id, PATCHes that existing comment instead of creating a
    new one - see find_existing_comment_id() and plans/03-github-action-client.md #8.
    """
    if comment_id is not None:
        comment_url = f"https://api.github.com/repos/{repo}/issues/comments/{comment_id}"
        method = "PATCH"
    else:
        comment_url = f"https://api.github.com/repos/{repo}/issues/{pr_number}/comments"
        method = "POST"
    payload = json.dumps({"body": markdown_body}).encode("utf-8")
    return urllib.request.Request(
        comment_url,
        data=payload,
        headers={
            "Authorization": f"Bearer {github_token}",
            "Accept": "application/vnd.github.v3+json",
            "Content-Type": "application/json"
        },
        method=method
    )


def find_existing_comment_id(github_token: str, repo: str, pr_number: int, max_pages: int = 10) -> Optional[int]:
    """Looks for a prior QuietPhysics comment on this PR (identified by
    COMMENT_MARKER) so a re-run can update it instead of posting a new one
    every time. Returns None on any lookup failure - the caller falls back
    to posting a fresh comment, same as before this existed.
    """
    for page in range(1, max_pages + 1):
        list_url = f"https://api.github.com/repos/{repo}/issues/{pr_number}/comments?per_page=100&page={page}"
        req = urllib.request.Request(
            list_url,
            headers={
                "Authorization": f"Bearer {github_token}",
                "Accept": "application/vnd.github.v3+json"
            },
            method="GET"
        )
        try:
            with urllib.request.urlopen(req, timeout=10) as resp:
                comments = json.loads(resp.read().decode("utf-8"))
        except Exception:
            return None

        for comment in comments:
            if COMMENT_MARKER in comment.get("body", ""):
                return comment.get("id")

        if len(comments) < 100:
            return None

    return None


def main():
    api_url = os.getenv("QP_API_URL", "http://localhost:8000/v1/evaluate").rstrip("/")
    if not api_url.endswith("/v1/evaluate"):
        api_url = f"{api_url}/v1/evaluate"

    api_key = os.getenv("QP_API_KEY", "").strip()
    if not api_key:
        print("❌ QP_API_KEY is not set. Add your QuietPhysics API key as a repository secret named QP_API_KEY.")
        sys.exit(1)

    # /v1/evaluate accepts the per-tenant key above on its own - a shared
    # Basic Auth pair used to be required on every route, including this
    # one, but the real signup flow never actually issued that credential
    # to a customer anywhere, so requiring it here left every real
    # customer stuck with a working API key and no way to proceed (see
    # plans/06-github-marketplace-publishing.md Milestone 0). Sent only
    # if both are provided - optional, not required. Still required on
    # every other route (onboarding, deactivation, /docs), which this
    # client doesn't call.
    basic_auth_username = os.getenv("QP_BASIC_AUTH_USERNAME", "").strip()
    basic_auth_password = os.getenv("QP_BASIC_AUTH_PASSWORD", "").strip()

    scenario = os.getenv("INPUT_SCENARIO", "all")
    mode = os.getenv("INPUT_MODE", "pr-regression")
    github_token = os.getenv("GITHUB_TOKEN")
    fail_on_regression = os.getenv("INPUT_FAIL_ON_REGRESSION", "true").lower() == "true"
    post_pr_comment = os.getenv("INPUT_POST_PR_COMMENT", "true").lower() == "true"

    payload = {
        "scenario_id": scenario,
        "mode": mode,
        "repo_name": os.getenv("GITHUB_REPOSITORY", "client-org/infrastructure"),
        "commit_sha": os.getenv("GITHUB_SHA", "HEAD"),
    }

    headers = {
        "X-API-Key": api_key,
        "Content-Type": "application/json",
        "User-Agent": "QuietPhysics-GitHub-Action/1.0"
    }
    if basic_auth_username and basic_auth_password:
        basic_auth_token = base64.b64encode(
            f"{basic_auth_username}:{basic_auth_password}".encode("utf-8")
        ).decode("ascii")
        headers["Authorization"] = f"Basic {basic_auth_token}"

    req_data = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(
        api_url,
        data=req_data,
        headers=headers,
        method="POST"
    )

    print(f"📡 Sending PR diff to QuietPhysics Cloud ({api_url})...")
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            data = json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as e:
        err_msg = e.read().decode("utf-8")
        print(f"❌ QuietPhysics API Error ({e.code}): {err_msg}")
        sys.exit(1)
    except Exception as e:
        print(f"❌ Failed to connect to QuietPhysics Cloud: {e}")
        sys.exit(1)

    verdict = data.get("verdict", "BLOCKED")
    exit_code = data.get("exit_code", 1)
    pr_markdown = data.get("pr_comment_markdown", "")

    print(f"\n--- QuietPhysics Cloud Verification Result ---")
    print(f"Verdict:         {verdict}")
    print(f"Tests Passed:    {data.get('passed_tests')}/{data.get('total_tests')}")
    print(f"Execution SLA:   {data.get('execution_time_ms')} ms (Sub-200ms Deterministic)")
    print("----------------------------------------------\n")

    # Set GitHub Actions output parameters if running in CI
    if "GITHUB_OUTPUT" in os.environ:
        with open(os.environ["GITHUB_OUTPUT"], "a") as f:
            f.write(f"verdict={verdict}\n")
            f.write(f"violations-count={data.get('failed_tests', 0)}\n")
            f.write(f"passed-count={data.get('passed_tests', 0)}\n")

    # Post PR Comment using GitHub API if enabled
    if post_pr_comment and pr_markdown and github_token:
        repo = os.getenv("GITHUB_REPOSITORY")
        pr_num = parse_pr_number(os.getenv("GITHUB_REF", ""))

        if repo and pr_num:
            existing_comment_id = find_existing_comment_id(github_token, repo, pr_num)
            c_req = build_pr_comment_request(pr_markdown, github_token, repo, pr_num, comment_id=existing_comment_id)
            try:
                urllib.request.urlopen(c_req, timeout=10)
                if existing_comment_id:
                    print(f"✅ Updated QuietPhysics verification report on PR #{pr_num}")
                else:
                    print(f"✅ Posted QuietPhysics verification report to PR #{pr_num}")
            except Exception as err:
                print(f"ℹ️ Could not post PR comment: {err}")

    if fail_on_regression and exit_code != 0:
        print(f"\n🚨 DEPLOYMENT BLOCKED BY QUIETPHYSICS (Exit Code {exit_code})")
        sys.exit(exit_code)
    else:
        print(f"\n✅ DEPLOYMENT APPROVED BY QUIETPHYSICS")
        sys.exit(0)


if __name__ == "__main__":
    main()
