"""Load the waiver file from the repository default branch through the GitHub REST contents API (Stream A). Standard library only.

Trust rule (spec section 4.3): the file is read ONLY at the head of the repository default branch, never from the pull request, so a waiver added
in a PR applies only after it is merged. The API host is the constant api.github.com (no GITHUB_API_URL: the token must not be sent anywhere an
environment variable can redirect it). Every failure means no waivers at all, a fixed reason code and no file content in any message.

Test-only switch: ``QP_TEST_GITHUB_API_BASE`` (an ``http://127.0.0.1:<port>`` or ``http://localhost:<port>`` base) replaces
``https://api.github.com`` for the two waiver requests, and ONLY while ``QP_TEST_ALLOW_HTTP_LOCALHOST == "1"``. It is never mapped from action.yml.
"""

import base64
import json
import os
import re
import stat
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from typing import Callable, List, Mapping, NamedTuple, Optional

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from manifest_filter import ManifestError, _yaml_documents, _OPAQUE  # noqa: E402  (the restricted YAML reader; JSON is deliberately not accepted)

API_HOST = "api.github.com"
BUDGET_SECONDS = 20.0
MAX_FILE_BYTES = 64 * 1024
MAX_ENTRIES = 50
MAX_EVENT_BYTES = 1024 * 1024
MAX_RESPONSE_BYTES = 128 * 1024

_PATH = re.compile(r"[A-Za-z0-9._/-]{1,200}")
_BRANCH = re.compile(r"[A-Za-z0-9._/-]{1,200}")
_REPO = re.compile(r"[A-Za-z0-9_.-]{1,100}/[A-Za-z0-9_.-]{1,100}")
_SHA = re.compile(r"[0-9a-f]{40}")
_TOKEN = re.compile(r"[\x21-\x7e]+")
_RULE = re.compile(r"QP-[A-Z0-9]{2,8}-[0-9]{3}", re.ASCII)
_RESOURCE = re.compile(r"[\x21-\x7e]{1,300}")
_REASON = re.compile(r"[\x20-\x7e]{10,240}")
_DATE = re.compile(r"([0-9]{4})-([0-9]{2})-([0-9]{2})", re.ASCII)
_KEYS = {"rule", "resource", "reason", "expires"}
_PR_EVENTS = ("pull_request", "pull_request_target")
_OTHER_EVENTS = ("push", "merge_group", "workflow_dispatch", "schedule")
QUOTE_HINT = 'expires must be a quoted date, for example expires: "2026-12-31"'


class WaiverResult(NamedTuple):
    waivers: List[dict]          # [{"rule_id", "resource", "reason", "expires"}], only entries that passed the client checks
    notes: List[str]             # lines to append to the PR comment (for example "Waivers were not applied: <code>")
    warnings: List[str]          # texts for ::warning annotations
    code: Optional[str]          # fixed reason code when waivers were not applied, else None


def path_problem(path: str) -> Optional[str]:
    """Why ``waivers-file`` may not be used, or None. Pattern [A-Za-z0-9._/-]{1,200}, no leading '/' or './', no '//', no '..' segment."""
    if not _PATH.fullmatch(path):
        return "waivers-file must match [A-Za-z0-9._/-] and be 1 to 200 characters long."
    if path.startswith("/") or path.startswith("./") or "//" in path or ".." in path.split("/") or path == ".":
        return "waivers-file must be a relative path inside the repository (no leading '/' or './', no '//', no '..' segment)."
    return None


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None


class _Failed(Exception):
    def __init__(self, code: str):
        super().__init__(code)
        self.code = code


def _api_base(env: Mapping[str, str]) -> str:
    # KNOWN TAMPERING SURFACE (documented in action/README.md): this test hook ships in production code. It is honoured only with
    # QP_TEST_ALLOW_HTTP_LOCALHOST=1 AND a loopback http base, is never mapped from action.yml, and a workflow step that can write GITHUB_ENV can
    # already read the token and edit the Action anyway.
    base = (env.get("QP_TEST_GITHUB_API_BASE") or "").strip()
    if base and env.get("QP_TEST_ALLOW_HTTP_LOCALHOST") == "1":
        try:
            parts = urllib.parse.urlsplit(base)
            if parts.scheme == "http" and parts.hostname in ("127.0.0.1", "localhost") and parts.port and not parts.path.strip("/") \
                    and parts.username is None and not parts.query and not parts.fragment:
                return f"http://{parts.hostname}:{parts.port}"
        except ValueError:
            pass
    return "https://" + API_HOST


def _valid_date(text: str) -> bool:
    m = _DATE.fullmatch(text)
    if not m:
        return False
    year, month, day = (int(g) for g in m.groups())
    leap = year % 4 == 0 and (year % 100 != 0 or year % 400 == 0)
    days = [31, 29 if leap else 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31]
    return year >= 1 and 1 <= month <= 12 and 1 <= day <= days[month - 1]


def _read_event(path: str) -> Optional[str]:
    """The repository default branch named in the event payload, or None. At most 1 MiB is read."""
    try:
        with open(path, "rb") as f:
            raw = f.read(MAX_EVENT_BYTES + 1)
        if len(raw) > MAX_EVENT_BYTES:
            return None
        event = json.loads(raw.decode("utf-8"))
    except (OSError, ValueError, RecursionError):
        return None
    repo = event.get("repository") if isinstance(event, dict) else None
    branch = repo.get("default_branch") if isinstance(repo, dict) else None
    if not isinstance(branch, str) or not _BRANCH.fullmatch(branch):
        return None
    if branch[0] in "-/" or ".." in branch or "//" in branch or branch.endswith("/"):
        return None
    return branch


def _get(url: str, accept: str, token: str, deadline: float, clock: Callable[[], float]) -> bytes:
    remaining = deadline - clock()
    if remaining <= 0:
        raise _Failed("timeout")
    request = urllib.request.Request(url, headers={"Authorization": f"Bearer {token}", "Accept": accept, "X-GitHub-Api-Version": "2022-11-28",
                                                    "User-Agent": "QuietPhysics-GitHub-Action/1.0"}, method="GET")
    opener = urllib.request.build_opener(_NoRedirect)
    try:
        with opener.open(request, timeout=max(0.5, remaining)) as resp:
            data = resp.read(MAX_RESPONSE_BYTES + 1)
    except urllib.error.HTTPError as exc:
        if exc.code == 404:
            raise _Failed("not_found") from None
        if 300 <= exc.code < 400:
            raise _Failed("redirect_refused") from None
        raise _Failed(f"http_{exc.code}" if 100 <= exc.code <= 599 else "http_error") from None
    except (urllib.error.URLError, TimeoutError, OSError, ValueError):
        raise _Failed("unreachable") from None
    except Exception:
        raise _Failed("request_failed") from None
    if len(data) > MAX_RESPONSE_BYTES:
        raise _Failed("response_too_large")
    return data


def _parse_file(text: str) -> List[dict]:
    """The sendable entries of a waiver file, or raises _Failed(code). Anything outside the supported subset ignores the whole file."""
    text = text.replace("\r\n", "\n")
    if text.lstrip(" \t\r\n")[:1] in ("{", "["):
        raise _Failed("json_not_supported")
    try:
        documents = _yaml_documents(text)
    except ManifestError:
        raise _Failed("unsupported_yaml") from None
    except RecursionError:
        raise _Failed("unsupported_yaml") from None
    if len(documents) != 1:
        raise _Failed("empty_file" if not documents else "multiple_documents")
    doc = documents[0]
    if not isinstance(doc, dict) or set(doc) != {"waivers"}:
        raise _Failed("unexpected_structure")
    entries = doc["waivers"]
    if entries is None:
        entries = []
    if not isinstance(entries, list):
        raise _Failed("unexpected_structure")
    if len(entries) > MAX_ENTRIES:
        raise _Failed("too_many_entries")
    out = []
    for entry in entries:
        if not isinstance(entry, dict):
            continue
        if any(v is _OPAQUE for v in entry.values()):
            raise _Failed("unquoted_date" if entry.get("expires") is _OPAQUE else "unsupported_value")
        if set(entry) != _KEYS or not all(isinstance(v, str) for v in entry.values()):
            continue
        if (_RULE.fullmatch(entry["rule"]) and _RESOURCE.fullmatch(entry["resource"]) and _REASON.fullmatch(entry["reason"])
                and _valid_date(entry["expires"])):
            out.append({"rule_id": entry["rule"], "resource": entry["resource"], "reason": entry["reason"], "expires": entry["expires"]})
    return out


def _workspace_copy(workspace: str, path: str) -> Optional[bytes]:
    """The waiver file as the pull request has it (regular file inside the workspace, at most 64 KiB), or None when it does not exist.
    A file that exists but cannot be read safely returns a marker that never equals the trusted bytes."""
    full = os.path.join(workspace, path)
    try:
        st = os.lstat(full)
    except OSError:
        return None
    try:
        real, root = os.path.realpath(full), os.path.realpath(workspace)
        if not stat.S_ISREG(st.st_mode) or st.st_size > MAX_FILE_BYTES or os.path.commonpath([real, root]) != root:
            return b"\x00unreadable"
        with open(full, "rb") as f:
            return f.read(MAX_FILE_BYTES + 1)
    except (OSError, ValueError):
        return b"\x00unreadable"


def load_waivers(env: Mapping[str, str], token: str, workspace: str, *, clock: Callable[[], float] = time.monotonic) -> WaiverResult:
    path = env.get("INPUT_WAIVERS_FILE") or ""
    if not path.strip():
        return WaiverResult([], [], [], None)

    def not_applied(code: str, detail: str = "") -> WaiverResult:
        note = f"Waivers were not applied: {code}" + (f" ({detail})" if detail else "")
        return WaiverResult([], [note], [note], code)

    if path_problem(path):
        return not_applied("bad_path")
    repo = (env.get("GITHUB_REPOSITORY") or "").strip()
    if not _REPO.fullmatch(repo):
        return not_applied("bad_repository")
    default_branch = _read_event(env.get("GITHUB_EVENT_PATH") or "")
    if default_branch is None:
        return not_applied("bad_event")
    event = (env.get("GITHUB_EVENT_NAME") or "").strip()
    if event in _PR_EVENTS:
        if (env.get("GITHUB_BASE_REF") or "") != default_branch:
            return WaiverResult([], [f"Waivers apply only to pull requests targeting `{default_branch}`."], [], None)
    elif event not in _OTHER_EVENTS:
        return not_applied("unsupported_event")
    if not token or not _TOKEN.fullmatch(token):
        return not_applied("no_token")

    base = _api_base(env)
    deadline = clock() + BUDGET_SECONDS
    repo_path = urllib.parse.quote(repo, safe="/")
    trusted: Optional[bytes] = None
    try:
        # The branch-only endpoint: /commits/{name} accepts a branch OR a tag, so a tag named like the default branch could win the resolution.
        branch_raw = _get(f"{base}/repos/{repo_path}/branches/{urllib.parse.quote(default_branch, safe='/')}", "application/vnd.github+json", token, deadline, clock)
        try:
            branch_meta = json.loads(branch_raw.decode("utf-8"))
        except (ValueError, RecursionError):
            return not_applied("bad_response")
        commit = branch_meta.get("commit") if isinstance(branch_meta, dict) else None
        sha_text = commit.get("sha") if isinstance(commit, dict) else None
        if not isinstance(sha_text, str) or not _SHA.fullmatch(sha_text):
            return not_applied("bad_response")
        try:
            raw = _get(f"{base}/repos/{repo_path}/contents/{urllib.parse.quote(path, safe='/')}?ref={sha_text}", "application/vnd.github+json", token, deadline, clock)
        except _Failed as exc:
            if exc.code != "not_found":
                raise
            raw = None                                            # a missing file is the normal "no waivers" state, silent
        if raw is not None:
            try:
                meta = json.loads(raw.decode("utf-8"))
            except (ValueError, RecursionError):
                raise _Failed("bad_response") from None
            size = meta.get("size") if isinstance(meta, dict) else None
            if (not isinstance(meta, dict) or meta.get("type") != "file" or meta.get("encoding") != "base64" or isinstance(size, bool)
                    or not isinstance(size, int) or not isinstance(meta.get("content"), str)):
                raise _Failed("bad_response")
            if size > MAX_FILE_BYTES:
                raise _Failed("file_too_large")
            try:
                trusted = base64.b64decode("".join(meta["content"].split()), validate=True)
            except ValueError:
                raise _Failed("bad_response") from None
            if len(trusted) > MAX_FILE_BYTES:
                raise _Failed("file_too_large")
        notes: List[str] = []
        waivers: List[dict] = []
        if trusted is not None:
            try:
                waivers = _parse_file(trusted.decode("utf-8"))
            except UnicodeDecodeError:
                raise _Failed("not_utf8") from None
    except _Failed as exc:
        if exc.code == "unquoted_date":
            return not_applied(exc.code, QUOTE_HINT)
        return not_applied(exc.code)
    mine = _workspace_copy(workspace, path)
    if mine is not None and mine != trusted:
        notes.append("This change edits the waiver file; the new waivers apply after it is merged.")
    return WaiverResult(waivers, notes, [], None)
