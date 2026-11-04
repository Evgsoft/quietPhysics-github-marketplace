#!/usr/bin/env python3
"""Lightweight QuietPhysics Closed-Source Client Runner for Customer GitHub Actions."""

import base64
import email.utils
import http.client
import json
import os
import random
import re
import ssl
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from typing import Callable, Optional, Tuple

# The composite action runs this file as a script; tests load it by path. Either way the sibling modules sit next to it.
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import payload as payload_module  # noqa: E402
import waivers as waivers_module  # noqa: E402


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


def _bot_marker_comment_id(comment) -> Optional[int]:
    """The id of a comment written by a bot that carries the marker, else None. Anyone can paste the marker into a comment of their
    own; updating that one would let them redirect the report, so only a bot's comment counts. Odd shapes never raise."""
    if not isinstance(comment, dict) or not isinstance(comment.get("body"), str) or COMMENT_MARKER not in comment["body"]:
        return None
    user, comment_id = comment.get("user"), comment.get("id")
    if not isinstance(user, dict) or user.get("type") != "Bot":
        return None
    return comment_id if isinstance(comment_id, int) and not isinstance(comment_id, bool) else None


def find_existing_comment_id(github_token: str, repo: str, pr_number: int, max_pages: int = 10) -> Optional[int]:
    """Looks for a prior QuietPhysics comment on this PR (a bot's comment carrying COMMENT_MARKER) so a re-run can update it
    instead of posting a new one every time. Returns None on any lookup failure - the caller then posts a fresh comment.
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
                comments = json.loads(resp.read(MAX_RESPONSE_BYTES).decode("utf-8"))
        except Exception:
            return None
        if not isinstance(comments, list):
            return None

        for comment in comments:
            found = _bot_marker_comment_id(comment)
            if found is not None:
                return found

        if len(comments) < 100:
            return None

    return None


# The contract version this client speaks. Sent on every request so qp-service answers errors as
# RFC 9457 problem details (a clear title, detail and request id) instead of the legacy
# {"error": "<string>"} body. plans/09-qp-service-update-plan.md section 4.
API_VERSION = "1"


def build_headers(api_key: str, basic_auth_username: str = "", basic_auth_password: str = "") -> dict:
    headers = {
        "X-API-Key": api_key,
        "X-QP-Api-Version": API_VERSION,
        "Content-Type": "application/json",
        "User-Agent": "QuietPhysics-GitHub-Action/1.0",
    }
    if basic_auth_username and basic_auth_password:
        token = base64.b64encode(f"{basic_auth_username}:{basic_auth_password}".encode("utf-8")).decode("ascii")
        headers["Authorization"] = f"Basic {token}"
    return headers


def build_oidc_headers(jwt: str) -> dict:
    """OIDC form: the token as Bearer, and nothing else that authenticates (no X-API-Key, no Basic)."""
    return {
        "Authorization": f"Bearer {jwt}",
        "X-QP-Api-Version": API_VERSION,
        "Content-Type": "application/json",
        "User-Agent": "QuietPhysics-GitHub-Action/1.0",
    }


_CONTROL = re.compile(r"[\x00-\x1f\x7f-\x9f]")
_CREDENTIAL = re.compile(r"[\x21-\x7e]+")
LOCAL_HOSTS = ("localhost", "127.0.0.1", "::1")
MAX_RESPONSE_BYTES = 8 * 1024 * 1024
READ_CHUNK = 64 * 1024


# Secrets of this run (the minted OIDC token, the runner request token): anything printed through clean() has them removed.
_REDACT: list = []


def clean(value, limit: int = 500) -> str:
    """Server text made safe to print: control characters become spaces and '::' is broken up, so the answer of the
    server (untrusted) can neither start a workflow command nor add a line to GITHUB_OUTPUT."""
    text = str(value)
    for secret in _REDACT:
        text = text.replace(secret, "***")
    text = _CONTROL.sub(" ", text)
    return re.sub(r":(?=:)", ": ", text)[:limit]


def count(value) -> int:
    return value if isinstance(value, int) and not isinstance(value, bool) and value >= 0 else 0


def api_url_problem(url: str) -> Optional[str]:
    """Why the URL may not be used (never repeats it), or None. Credentials travel to it, so https; plain http only for loopback."""
    try:
        parts = urllib.parse.urlsplit(url)
        host, _ = parts.hostname, parts.port
    except ValueError:
        return "api-url is not a valid URL."
    no_userinfo = parts.username is None and parts.password is None
    if no_userinfo and host and (parts.scheme == "https" or (parts.scheme == "http" and host in LOCAL_HOSTS)):
        return None
    return "api-url must use https (plain http is accepted only for localhost, 127.0.0.1 and ::1) and must not contain credentials."


def api_origin(url: str) -> str:
    """scheme://host[:port] of an already validated URL: the log never shows a path or a query (they can carry a token)."""
    parts = urllib.parse.urlsplit(url)
    host = f"[{parts.hostname}]" if ":" in (parts.hostname or "") else parts.hostname
    return f"{parts.scheme}://{host}" + (f":{parts.port}" if parts.port else "")


def parse_bool(name: str, env_name: str, default: bool = True, empty_is_default: bool = False) -> bool:
    """Exactly true or false (case-insensitive, stripped); unset means ``default`` (true unless a caller says otherwise). An empty value is an
    error unless ``empty_is_default``. A typo must not silently turn the gate into report-only."""
    value = os.getenv(env_name)
    if value is None:
        return default
    value = value.strip().lower()
    if not value and empty_is_default:
        return default
    if value not in ("true", "false"):
        print(f"❌ {name} must be exactly 'true' or 'false'.")
        sys.exit(1)
    return value == "true"


class NoRedirect(urllib.request.HTTPRedirectHandler):
    """urllib would resend X-API-Key and Authorization to the new location; a redirect is an error instead."""

    def redirect_request(self, *args, **kwargs):
        return None


def error_text(body: str) -> str:
    """A human-readable line for an HTTP error body: RFC 9457 problem details (v1), the legacy
    {"error": "..."} body, or the raw text if it is neither. Never raises."""
    try:
        parsed = json.loads(body)
    except (TypeError, ValueError, RecursionError):
        return clean(body)
    if not isinstance(parsed, dict):
        return clean(body)
    title, detail, legacy = parsed.get("title"), parsed.get("detail"), parsed.get("error")
    if title or detail:
        text = ": ".join(clean(part) for part in (title, detail, legacy) if part)
        if parsed.get("code"):
            text += f" [{clean(parsed['code'], 60)}]"
        if parsed.get("request_id"):
            text += f" (request id {clean(parsed['request_id'], 80)})"
        return text[:500]
    if legacy:
        return clean(legacy)
    return clean(body)


def analysis_notes(data: dict) -> list:
    """Lines to print so nobody mistakes a built-in demo scenario for an analysis of their own code."""
    notes = []
    if data.get("analysis_source", "fixture") == "fixture":
        notes.append("⚠️ Demo scenario result: no Terraform plan was analysed. This verdict comes from a "
                     "built-in scenario, not from your code.")
    warnings = data.get("warnings")
    for warning in warnings[:50] if isinstance(warnings, list) else []:
        notes.append(f"⚠️ {clean(warning)}")
    return notes


# --- Service-error policy -----------------------------------------------------
#
# A QuietPhysics outage must not silently approve a PR, and a hiccup must not
# block every customer's merge. So the client separates two kinds of failure:
#
#   * a SERVICE error - the API could not give an answer: HTTP 5xx, HTTP 429,
#     a timeout, a refused or dropped connection. These are retried a bounded
#     number of times with exponential backoff and jitter (honouring
#     Retry-After). If the answer still does not come, `on-service-error`
#     decides: `fail` (default, exit 1) or `warn` (exit 0 with a loud warning
#     and verdict=UNAVAILABLE).
#   * everything else stays FAIL-CLOSED regardless of that setting: a 401/403
#     (bad or revoked key, billing), any other 4xx (our request is wrong), a
#     200 whose body is not a valid verdict, and above all an actual BLOCKED
#     verdict. `warn` can only ever turn "the service did not answer" into a
#     warning; it can never turn an answer into an approval.
#
# The request is a pure evaluation (no state is changed server-side), so a
# retried POST is safe.

RETRYABLE_STATUS = frozenset({429, 500, 502, 503, 504})

# Defaults; each can be overridden by an environment variable (used by the tests
# and by anyone who needs a different budget). Bounded on every axis: attempts,
# the size of one wait, and the total wall-clock the step may spend on the API.
DEFAULT_MAX_ATTEMPTS = 4
DEFAULT_BASE_DELAY = 1.0      # seconds; doubles each retry, with jitter
DEFAULT_MAX_DELAY = 20.0      # cap for one backoff wait (Retry-After is capped by the budget instead)
DEFAULT_TOTAL_BUDGET = 120.0  # seconds across all attempts and waits
DEFAULT_REQUEST_TIMEOUT = 30.0


class ServiceError(Exception):
    """The API could not give an answer (retries exhausted or budget spent)."""

    def __init__(self, detail: str, attempts: int):
        super().__init__(detail)
        self.detail = detail
        self.attempts = attempts


class ClientError(Exception):
    """A non-retryable HTTP answer (401/403/other 4xx). Always fail-closed."""

    def __init__(self, status: int, body: str):
        super().__init__(f"HTTP {status}")
        self.status = status
        self.body = body


class TlsError(Exception):
    """A TLS or certificate failure: the server cannot be authenticated, so this is never a retried service error."""


def read_limited(resp, deadline: float, clock: Callable[[], float]) -> Tuple[bytes, bool]:
    """Reads the body in chunks against a monotonic deadline, at most MAX_RESPONSE_BYTES. Returns (bytes, was_cut). A slow-drip or
    endless answer therefore cannot outlast the retry budget or fill the runner's memory. Raises TimeoutError at the deadline."""
    read = getattr(resp, "read1", None) or resp.read       # read1 returns what has arrived instead of waiting for a full chunk
    chunks, size = [], 0
    while size <= MAX_RESPONSE_BYTES:
        if clock() > deadline:
            raise TimeoutError("response deadline")
        piece = read(min(READ_CHUNK, MAX_RESPONSE_BYTES + 1 - size))
        if not piece:
            break
        chunks.append(piece)
        size += len(piece)
    data = b"".join(chunks)
    return data[:MAX_RESPONSE_BYTES], size > MAX_RESPONSE_BYTES


def is_tls_error(exc: BaseException) -> bool:
    return isinstance(exc, ssl.SSLError) or isinstance(getattr(exc, "reason", None), ssl.SSLError)


def parse_retry_after(value: Optional[str], now: Optional[float] = None) -> Optional[float]:
    """Seconds to wait from a Retry-After header: delta-seconds or an HTTP date.
    None if absent or unparseable (the caller then uses its own backoff)."""
    if not value:
        return None
    value = value.strip()
    try:
        return max(0.0, float(value))
    except ValueError:
        pass
    try:
        when = email.utils.parsedate_to_datetime(value)
    except (TypeError, ValueError):
        return None
    if when is None:
        return None
    current = time.time() if now is None else now
    return max(0.0, when.timestamp() - current)


def backoff_delay(attempt: int, base: float, cap: float, rand: Callable[[], float] = random.random) -> float:
    """Exponential backoff with jitter: attempt 1 -> ~base, 2 -> ~2*base, ... capped.
    Jitter keeps a fleet of CI jobs that failed together from retrying together."""
    ceiling = min(cap, base * (2 ** (attempt - 1)))
    return ceiling * (0.5 + 0.5 * rand())


def _float_env(name: str, default: float) -> float:
    try:
        return float(os.getenv(name, "") or default)
    except ValueError:
        return default


def _is_misconfigured(body: str) -> bool:
    try:
        parsed = json.loads(body)
    except (TypeError, ValueError, RecursionError):
        return False
    return isinstance(parsed, dict) and parsed.get("code") == "misconfigured"


def call_with_retries(
    make_request: Callable[[], urllib.request.Request],
    *,
    max_attempts: Optional[int] = None,
    base_delay: Optional[float] = None,
    max_delay: Optional[float] = None,
    total_budget: Optional[float] = None,
    request_timeout: Optional[float] = None,
    sleep: Callable[[float], None] = time.sleep,
    clock: Callable[[], float] = time.monotonic,
    rand: Callable[[], float] = random.random,
    log: Callable[[str], None] = print,
) -> dict:
    """POST and parse the JSON answer, retrying only service errors.

    Returns the parsed body of a 200. Raises ClientError for a non-retryable
    HTTP status and ServiceError once the retry budget is spent. A 200 whose
    body is not JSON is not retried: it is a wrong URL or a proxy page, not an
    outage, and approving on it would be fail-open.
    """
    max_attempts = max_attempts or int(_float_env("QP_RETRY_MAX_ATTEMPTS", DEFAULT_MAX_ATTEMPTS))
    base_delay = _float_env("QP_RETRY_BASE_DELAY", DEFAULT_BASE_DELAY) if base_delay is None else base_delay
    max_delay = _float_env("QP_RETRY_MAX_DELAY", DEFAULT_MAX_DELAY) if max_delay is None else max_delay
    total_budget = _float_env("QP_RETRY_TOTAL_BUDGET", DEFAULT_TOTAL_BUDGET) if total_budget is None else total_budget
    request_timeout = _float_env("QP_REQUEST_TIMEOUT", DEFAULT_REQUEST_TIMEOUT) if request_timeout is None else request_timeout

    started = clock()
    last = "no attempt was made"
    attempt = 0
    while attempt < max_attempts:
        attempt += 1
        remaining = total_budget - (clock() - started)
        if remaining <= 0.5:
            raise ServiceError(f"retry budget of {total_budget:.0f}s spent; last error: {last}", attempt - 1)

        retry_after: Optional[float] = None
        try:
            timeout = min(request_timeout, remaining)
            deadline = clock() + timeout
            with urllib.request.urlopen(make_request(), timeout=timeout) as resp:
                data, cut = read_limited(resp, deadline, clock)
            if cut:
                raise ClientError(200, "the response is larger than 8 MiB")
            try:
                raw = data.decode("utf-8")
                parsed = json.loads(raw)
            except ValueError as exc:
                raise ClientError(200, "the response was not JSON") from exc
            if not isinstance(parsed, dict):
                raise ClientError(200, "the response was not a JSON object")
            return parsed
        except urllib.error.HTTPError as exc:
            body = ""
            try:
                body = read_limited(exc, deadline, clock)[0].decode("utf-8", "replace")
            except Exception:
                pass
            if exc.code not in RETRYABLE_STATUS or (exc.code == 503 and _is_misconfigured(body)):
                raise ClientError(exc.code, body) from exc       # a server misconfiguration is a failure, not an outage to wait out or warn about
            last = f"HTTP {exc.code}"
            retry_after = parse_retry_after(exc.headers.get("Retry-After") if exc.headers else None)
        except ClientError:
            raise
        except (urllib.error.URLError, TimeoutError, ConnectionError, OSError, http.client.HTTPException) as exc:
            # URLError wraps refused/reset/DNS; socket timeouts surface as TimeoutError/OSError;
            # a body cut off mid-read is http.client.IncompleteRead (an HTTPException, not an OSError).
            # The type only: the text of an exception can carry a URL or a header.
            if is_tls_error(exc):       # checked here because ssl.SSLError is an OSError; an unauthenticated server is never retried
                raise TlsError() from None
            reason = getattr(exc, "reason", None)
            last = type(reason if isinstance(reason, BaseException) else exc).__name__

        if attempt >= max_attempts:
            break
        wait = retry_after if retry_after is not None else backoff_delay(attempt, base_delay, max_delay, rand)
        remaining = total_budget - (clock() - started)
        if wait >= remaining:
            raise ServiceError(
                f"next retry would need {wait:.0f}s but only {max(remaining, 0):.0f}s of the retry budget is left; last error: {last}",
                attempt,
            )
        log(f"⚠️ QuietPhysics API not available ({last}); retry {attempt}/{max_attempts - 1} in {wait:.1f}s"
            + (" (Retry-After)" if retry_after is not None else ""))
        sleep(wait)

    raise ServiceError(f"{last} after {attempt} attempt(s)", attempt)


def service_unavailable(policy: str, err: ServiceError, github_output: Optional[str], summary_path: Optional[str]) -> int:
    """Apply the on-service-error policy. Returns the process exit code."""
    msg = (f"QuietPhysics could not be reached: {err.detail}. NO security verdict was produced for this change "
           f"(on-service-error: {policy}).")
    if github_output:
        with open(github_output, "a") as f:
            f.write("verdict=UNAVAILABLE\n")
            f.write("violations-count=0\n")
            f.write("passed-count=0\n")
    if summary_path:
        with open(summary_path, "a") as f:
            f.write(f"### QuietPhysics: no verdict\n{msg}\n")
    if policy == "warn":
        print(f"::warning title=QuietPhysics unavailable::{msg} The check was NOT run - review this change manually.")
        print("\n⚠️ QUIETPHYSICS UNAVAILABLE - continuing because on-service-error is 'warn'. This is NOT an approval.")
        return 0
    print(f"::error title=QuietPhysics unavailable::{msg} Set on-service-error: warn to let the job pass with a warning instead.")
    print("\n🚨 QUIETPHYSICS UNAVAILABLE - failing closed (on-service-error: fail).")
    return 1


# --- OIDC token request -------------------------------------------------------
TOKEN_HOST_SUFFIX = ".actions.githubusercontent.com"
TOKEN_TIMEOUT = 10.0
TOKEN_MAX_BYTES = 64 * 1024
TOKEN_ATTEMPTS = 3
_JWT_SHAPE = re.compile(r"[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+")
NO_TOKEN_MESSAGE = ("cannot verify: pull requests from forks do not receive an OIDC token (or `permissions: id-token: write` is missing "
                    "from the job). No security check ran for this change.")


class TokenRequestError(Exception):
    """kind: refused (bad URL, TLS, a redirect or a 4xx other than 403/404/429, a control character: always fails), permission (403/404: always fails),
    service (429, 5xx, connection errors, a bad body: per on-service-error)."""

    def __init__(self, kind: str, detail: str, attempts: int = 1):
        super().__init__(detail)
        self.kind, self.detail, self.attempts = kind, detail, attempts


def token_request_url(raw_url: str, audience: str) -> str:
    """The runner's URL with the audience parameter set exactly once; https and *.actions.githubusercontent.com only (plain http to
    loopback only when the test switch is on). Never repeats the URL in an error."""
    try:
        parts = urllib.parse.urlsplit(raw_url)
        host, _ = parts.hostname, parts.port
    except ValueError:
        raise TokenRequestError("refused", "the token URL of the runner is not a valid URL") from None
    allowed = parts.scheme == "https" and bool(host) and host.endswith(TOKEN_HOST_SUFFIX) and len(host) > len(TOKEN_HOST_SUFFIX)
    if os.getenv("QP_TEST_ALLOW_HTTP_LOCALHOST") == "1" and parts.scheme == "http" and host in LOCAL_HOSTS:
        allowed = True
    if not allowed or parts.username is not None or parts.password is not None:
        raise TokenRequestError("refused", "the token URL of the runner is not an https address under actions.githubusercontent.com; it was not contacted")
    query = [(k, v) for k, v in urllib.parse.parse_qsl(parts.query, keep_blank_values=True) if k != "audience"]
    query.append(("audience", audience))
    encoded = urllib.parse.urlencode(query, quote_via=urllib.parse.quote)
    return urllib.parse.urlunsplit((parts.scheme, parts.netloc, parts.path, encoded, ""))


def _read_token_body(resp) -> bytes:
    deadline = time.monotonic() + TOKEN_TIMEOUT
    chunks, size = [], 0
    while size <= TOKEN_MAX_BYTES:
        if time.monotonic() > deadline:
            raise TimeoutError("token response deadline")
        piece = resp.read(TOKEN_MAX_BYTES + 1 - size)
        if not piece:
            break
        chunks.append(piece)
        size += len(piece)
    return b"".join(chunks)


def request_oidc_token(raw_url: str, request_token: str, audience: str) -> str:
    """GET the runner's token endpoint; returns the JWT (not yet masked). Raises TokenRequestError."""
    url = token_request_url(raw_url, audience)
    opener = urllib.request.build_opener(NoRedirect)
    base = _float_env("QP_RETRY_BASE_DELAY", DEFAULT_BASE_DELAY)
    last = "no attempt was made"
    for attempt in range(1, TOKEN_ATTEMPTS + 1):
        req = urllib.request.Request(url, headers={"Authorization": f"bearer {request_token}", "Accept": "application/json; api-version=2.0",
                                                   "User-Agent": "QuietPhysics-GitHub-Action/1.0"}, method="GET")
        try:
            with opener.open(req, timeout=TOKEN_TIMEOUT) as resp:
                data = _read_token_body(resp)
            if len(data) > TOKEN_MAX_BYTES:
                raise TokenRequestError("service", "the token response is larger than 64 KiB", attempt)
            try:
                parsed = json.loads(data.decode("utf-8"))
            except (ValueError, RecursionError):
                raise TokenRequestError("service", "the token response was not JSON", attempt) from None
            value = parsed.get("value") if isinstance(parsed, dict) else None
            if not isinstance(value, str) or len(value) > TOKEN_MAX_BYTES or not _JWT_SHAPE.fullmatch(value):
                raise TokenRequestError("service", "the token response did not hold a token", attempt)
            return value
        except TokenRequestError:
            raise
        except urllib.error.HTTPError as exc:
            exc.close()
            if exc.code in (403, 404):
                raise TokenRequestError("permission", f"the runner refused the token request (HTTP {exc.code}); the job needs `permissions: id-token: write`", attempt) from None
            if exc.code == 429:
                raise TokenRequestError("service", "the token request was answered with HTTP 429", attempt) from None
            if not 500 <= exc.code <= 599:   # a redirect or a client error means the request itself is wrong: no outage policy applies
                raise TokenRequestError("refused", f"the token request was answered with HTTP {exc.code}", attempt) from None
            last = f"HTTP {exc.code}"
        except (ValueError, http.client.InvalidURL, http.client.CannotSendRequest):
            # A control character in the runner's URL or token: http.client's message quotes the offending value, so say nothing of it.
            raise TokenRequestError("refused", "the token URL or the request token of the runner contains a character that cannot be sent", attempt) from None
        except (urllib.error.URLError, TimeoutError, ConnectionError, OSError, http.client.HTTPException) as exc:
            if is_tls_error(exc):
                raise TokenRequestError("refused", "the TLS connection to the token endpoint failed", attempt) from None
            reason = getattr(exc, "reason", None)
            last = type(reason if isinstance(reason, BaseException) else exc).__name__
        if attempt < TOKEN_ATTEMPTS:
            time.sleep(backoff_delay(attempt, base, 5.0))
    raise TokenRequestError("service", f"the token request failed ({last}) after {TOKEN_ATTEMPTS} attempts", TOKEN_ATTEMPTS)


def write_verdict_output(verdict: str, github_output: Optional[str], summary_path: Optional[str], title: str, msg: str) -> None:
    if github_output:
        with open(github_output, "a") as f:
            f.write(f"verdict={verdict}\nviolations-count=0\npassed-count=0\n")
    if summary_path:
        with open(summary_path, "a") as f:
            f.write(f"### QuietPhysics: {title}\n{msg}\n")


def token_failure(err: TokenRequestError, github_output: Optional[str], summary_path: Optional[str]) -> int:
    msg = f"No OIDC token could be obtained: {err.detail}. NO security verdict was produced for this change."
    write_verdict_output("UNAVAILABLE", github_output, summary_path, "no verdict", msg)
    print(f"::error title=QuietPhysics OIDC token::{clean(msg)}")
    print("\n🚨 QUIETPHYSICS UNAVAILABLE - failing closed (no token, no request).")
    return 1


def no_token(policy: str, github_output: Optional[str], summary_path: Optional[str]) -> int:
    if policy == "skip":
        write_verdict_output("SKIPPED", github_output, summary_path, "skipped", NO_TOKEN_MESSAGE + " (on-no-token: skip) This is NOT an approval and NOT a gate.")
        print(f"::warning title=QuietPhysics skipped::{NO_TOKEN_MESSAGE} (on-no-token: skip) This is NOT an approval and NOT a gate.")
        print("\n⚠️ QUIETPHYSICS SKIPPED - no OIDC token.")
        return 0
    write_verdict_output("UNAVAILABLE", github_output, summary_path, "no verdict", NO_TOKEN_MESSAGE)
    print(f"::error title=QuietPhysics no OIDC token::{NO_TOKEN_MESSAGE} Set on-no-token: skip to let the job pass with a warning instead.")
    print("\n🚨 QUIETPHYSICS UNAVAILABLE - failing closed (on-no-token: fail).")
    return 1


ANALYSED_SOURCES = ("tfplan", "manifests")


def nothing_analysed(github_output: Optional[str], summary_path: Optional[str]) -> int:
    """Neither a supported resource nor a supported manifest remained: nothing is sent, and this is not an approval."""
    msg = "Nothing QuietPhysics checks was found in the Terraform plan or the Kubernetes manifests, so nothing was analysed. This is NOT an approval."
    if github_output:
        with open(github_output, "a") as f:
            f.write("verdict=SKIPPED\nviolations-count=0\npassed-count=0\n")
    if summary_path:
        with open(summary_path, "a") as f:
            f.write(f"### QuietPhysics: skipped\n{msg}\n")
    print(f"::warning title=QuietPhysics skipped::{msg}")
    print("\n⚠️ QUIETPHYSICS SKIPPED - nothing to analyse.")
    return 0


ADVISORY_BANNER = "> ℹ️ **Advisory mode:** QuietPhysics reports its findings on this pull request but does not fail the job because of them."


def parse_block_on(env) -> str:
    value = (env.get("INPUT_BLOCK_ON") or "").strip().lower() or "any"
    if value not in ("any", "high", "critical"):
        hint = " To never block, use advisory: true." if value == "none" else ""
        print(f"❌ block-on must be 'any', 'high' or 'critical'.{hint}")
        sys.exit(1)
    return value


def final_exit(verdict, exit_code: int, fail_on_regression: bool, on_inconclusive: str, analysis_requested: bool, advisory: bool = False) -> int:
    """Print the closing line and return the exit code. ``fail_on_regression`` is whether the verdict is enforced (fail-on-regression is true and
    advisory is false): when it is not, no verdict fails."""
    if verdict == "INCONCLUSIVE":
        msg = "QuietPhysics could not reach a verdict (INCONCLUSIVE): a value the rules need was unknown or withheld. This is NOT an approval."
        if fail_on_regression and on_inconclusive == "fail":
            print(f"::error title=QuietPhysics inconclusive::{msg}")
            print("\n🚨 INCONCLUSIVE - failing because on-inconclusive is 'fail'.")
            return 1
        print(f"::warning title=QuietPhysics inconclusive::{msg}")
        print("\n⚠️ INCONCLUSIVE - review this change manually.")
        return 0
    if verdict == "BLOCKED" or exit_code != 0:
        if fail_on_regression:
            code = exit_code if 1 <= exit_code <= 255 else 1      # 256 would reach the shell as 0
            print(f"\n🚨 DEPLOYMENT BLOCKED BY QUIETPHYSICS (Exit Code {code})")
            return code
        if verdict == "BLOCKED":
            if advisory:
                print("::warning title=QuietPhysics advisory::The verdict is BLOCKED; not failing the job because advisory is true.")
                print("\n⚠️ QuietPhysics verdict is BLOCKED; not failing because advisory mode is on.")
            else:
                print("\n⚠️ QuietPhysics verdict is BLOCKED; not failing because fail-on-regression is false (report-only).")
            return 0
    print("\n✅ DEPLOYMENT APPROVED BY QUIETPHYSICS")
    return 0


def main():
    api_url = os.getenv("QP_API_URL", "http://localhost:8000/v1/evaluate").rstrip("/")
    if not api_url.endswith("/v1/evaluate"):
        api_url = f"{api_url}/v1/evaluate"

    api_key = os.getenv("QP_API_KEY", "").strip()
    auth = (os.getenv("INPUT_AUTH") or "").strip().lower() or "api-key"
    if auth not in ("api-key", "oidc", "auto"):
        print("❌ auth must be 'api-key', 'oidc' or 'auto'.")
        sys.exit(1)
    on_no_token = (os.getenv("INPUT_ON_NO_TOKEN") or "").strip().lower() or "fail"
    if on_no_token not in ("fail", "skip"):
        print("❌ on-no-token must be 'fail' or 'skip'.")
        sys.exit(1)
    oidc_url = (os.getenv("ACTIONS_ID_TOKEN_REQUEST_URL") or "").strip()
    oidc_request_token = (os.getenv("ACTIONS_ID_TOKEN_REQUEST_TOKEN") or "").strip()
    have_oidc = bool(oidc_url and oidc_request_token)
    if auth == "api-key":
        auth_mode = "key"
    elif auth == "oidc":
        auth_mode = "oidc" if have_oidc else "none"
    else:
        auth_mode = "oidc" if have_oidc else ("key" if api_key else "none")
    if auth_mode == "key" and not api_key:
        print("❌ QP_API_KEY is not set. Add your QuietPhysics API key as a repository secret named QP_API_KEY.")
        sys.exit(1)
    problem = api_url_problem(api_url)
    if problem:
        print(f"❌ {problem}")
        sys.exit(1)

    # /v1/evaluate accepts the per-tenant key above on its own; the shared Basic Auth pair is optional and sent only if both are provided
    # (plans/06-github-marketplace-publishing.md Milestone 0). It is base64-encoded in the header, so it needs no character check.
    basic_auth_username = os.getenv("QP_BASIC_AUTH_USERNAME", "").strip()
    basic_auth_password = os.getenv("QP_BASIC_AUTH_PASSWORD", "").strip()
    if (auth == "oidc" or auth_mode == "oidc") and (basic_auth_username or basic_auth_password):
        print("❌ basic-auth-username / basic-auth-password cannot be combined with OIDC: the Basic header is never sent beside a token. Remove them.")
        sys.exit(1)

    if auth_mode == "key" and not _CREDENTIAL.fullmatch(api_key):
        print("❌ QP_API_KEY contains a space, a control character or a non-ASCII character; it cannot be sent as a header. Check the secret.")
        sys.exit(1)
    fail_on_regression = parse_bool("fail-on-regression", "INPUT_FAIL_ON_REGRESSION")
    post_pr_comment = parse_bool("post-pr-comment", "INPUT_POST_PR_COMMENT")
    advisory = parse_bool("advisory", "INPUT_ADVISORY", default=False, empty_is_default=True)
    block_on = parse_block_on(os.environ)
    waivers_file = os.getenv("INPUT_WAIVERS_FILE") or ""
    waivers_file = waivers_file if waivers_file.strip() else ""          # not stripped otherwise: a trailing newline is a bad path, not a good one
    if waivers_file and waivers_module.path_problem(waivers_file):
        print(f"❌ {waivers_module.path_problem(waivers_file)}")
        sys.exit(1)
    enforced = fail_on_regression and not advisory
    # The token goes into a header only when a comment is posted.
    github_token = (os.getenv("GITHUB_TOKEN") or "").strip()
    if post_pr_comment and github_token and not _CREDENTIAL.fullmatch(github_token):
        print("❌ GITHUB_TOKEN contains a space, a control character or a non-ASCII character; it cannot be sent as a header. Check the token, or set post-pr-comment: false.")
        sys.exit(1)
    # What to do when the API cannot answer after retries. Default `fail`
    # (owner decision D-01: fail closed for now). `warn` is documented in the README.
    on_service_error = (os.getenv("INPUT_ON_SERVICE_ERROR", "fail").strip().lower() or "fail")
    if on_service_error not in ("fail", "warn"):
        print(f"❌ on-service-error must be 'fail' or 'warn', got {on_service_error!r}.")
        sys.exit(1)

    if auth_mode == "none":
        sys.exit(no_token(on_no_token, os.environ.get("GITHUB_OUTPUT"), os.environ.get("GITHUB_STEP_SUMMARY")))

    try:
        payload, notes = payload_module.build_payload(os.environ, os.getenv("GITHUB_WORKSPACE") or ".")
    except payload_module.PayloadError as e:
        print(f"❌ QuietPhysics did not send anything: {e}")
        sys.exit(1)
    except Exception as e:  # fail closed; the type only, an exception text could carry input content
        print(f"❌ QuietPhysics did not send anything: the input could not be prepared ({type(e).__name__}).")
        sys.exit(1)
    for note in notes:
        print(f"ℹ️ {note}")

    analysis_requested = "api_version" in payload
    if not analysis_requested:
        print("::warning title=QuietPhysics demo scenario::This run used a built-in demo scenario and did not analyse your repository. "
              "Set plan-file or manifest-files to check your own Terraform plan or Kubernetes manifests.")
    # Already validated by build_payload in the upload modes; in the legacy mode an invalid value is ignored.
    on_inconclusive = payload_module.parse_on_inconclusive(os.environ) if analysis_requested else "warn"
    if not analysis_requested and (block_on != "any" or waivers_file):
        print("ℹ️ block-on and waivers-file are ignored because this run uses a built-in demo scenario (set plan-file or manifest-files).")
    if payload_module.nothing_to_analyse(payload):
        sys.exit(nothing_analysed(os.environ.get("GITHUB_OUTPUT"), os.environ.get("GITHUB_STEP_SUMMARY")))

    # Policy: the threshold and the waivers of the default branch (the loader is the only code that reads them; it fails closed).
    comment_notes: list = []
    policy_sent = False
    if analysis_requested:
        loaded = waivers_module.load_waivers(os.environ, github_token, os.getenv("GITHUB_WORKSPACE") or ".") if waivers_file else waivers_module.WaiverResult([], [], [], None)
        for warning in loaded.warnings:
            print(f"::warning title=QuietPhysics waivers::{clean(warning)}")
        comment_notes = list(loaded.notes)
        if block_on != "any" or loaded.waivers:
            try:
                payload = payload_module.attach_policy(payload, {"block_on": block_on, "waivers": loaded.waivers})
            except payload_module.PayloadError as e:
                print(f"❌ QuietPhysics did not send anything: {e}")
                sys.exit(1)
            policy_sent = "policy" in payload

    if auth_mode == "oidc":
        audience = (os.getenv("INPUT_OIDC_AUDIENCE") or "").strip() or (urllib.parse.urlsplit(api_url).hostname or "").lower()
        _REDACT.append(oidc_request_token)
        try:
            jwt = request_oidc_token(oidc_url, oidc_request_token, audience)
        except TokenRequestError as e:
            if e.kind == "service":
                sys.exit(service_unavailable(on_service_error, ServiceError(e.detail, e.attempts),
                                             os.environ.get("GITHUB_OUTPUT"), os.environ.get("GITHUB_STEP_SUMMARY")))
            sys.exit(token_failure(e, os.environ.get("GITHUB_OUTPUT"), os.environ.get("GITHUB_STEP_SUMMARY")))
        print(f"::add-mask::{jwt}", flush=True)       # before anything else can print it
        _REDACT.append(jwt)
        headers = build_oidc_headers(jwt)
    else:
        headers = build_headers(api_key, basic_auth_username, basic_auth_password)
    if analysis_requested:
        req_data, extra_headers = payload_module.encode_body(payload)
        headers.update(extra_headers)
        print(f"📦 Uploading {len(req_data)} bytes (reduced plan and manifests only).")
    else:
        req_data = json.dumps(payload).encode("utf-8")

    def make_request() -> urllib.request.Request:
        return urllib.request.Request(api_url, data=req_data, headers=headers, method="POST")

    urllib.request.install_opener(urllib.request.build_opener(NoRedirect))
    print(f"📡 Requesting a QuietPhysics verdict ({api_origin(api_url)})...")
    try:
        data = call_with_retries(make_request)
    except ClientError as e:
        # 401/403 (bad or revoked key), any other 4xx, or a 200 that is not a verdict:
        # fail-closed and NOT subject to on-service-error.
        if 300 <= e.status < 400:
            print(f"❌ QuietPhysics API answered with a redirect (HTTP {e.status}). Redirects are never followed, because they would resend "
                  "your credentials to another address. Check api-url.")
        else:
            print(f"❌ QuietPhysics API Error ({e.status}): {error_text(e.body)}")
        sys.exit(1)
    except TlsError:
        print("❌ The TLS connection to the QuietPhysics API failed (certificate or handshake). The server could not be authenticated, so nothing "
              "more was sent and no verdict was produced. Check api-url. This is never treated as a service outage.")
        sys.exit(1)
    except ServiceError as e:
        sys.exit(service_unavailable(
            on_service_error, e, os.environ.get("GITHUB_OUTPUT"), os.environ.get("GITHUB_STEP_SUMMARY")))
    except Exception as e:  # the type only, an exception text could carry a URL or a header
        print(f"❌ QuietPhysics request failed ({type(e).__name__}).")
        sys.exit(1)

    if analysis_requested and data.get("analysis_source") not in ANALYSED_SOURCES:
        print("❌ QuietPhysics ran no analysis of your plan or manifests: the service answered from a built-in scenario "
              "(detection is off or in shadow mode on the server). This is not a verdict on your change.")
        sys.exit(1)

    verdict = data.get("verdict", "BLOCKED")
    if verdict not in ("APPROVED", "BLOCKED", "INCONCLUSIVE"):
        print("❌ QuietPhysics answered with an unknown verdict; failing closed.")
        sys.exit(1)
    exit_code = data.get("exit_code", 1)
    exit_code = exit_code if isinstance(exit_code, int) and not isinstance(exit_code, bool) else 1
    pr_markdown = data.get("pr_comment_markdown", "")
    if not isinstance(pr_markdown, str):
        pr_markdown = ""
    for secret in _REDACT:
        pr_markdown = pr_markdown.replace(secret, "***")
    # Added after the redaction; the marker stays line 1 so the previous comment is still found.
    if pr_markdown and advisory:
        parts = pr_markdown.split("\n", 1)
        pr_markdown = parts[0] + "\n" + ADVISORY_BANNER + ("\n" + parts[1] if len(parts) > 1 else "")
    applied = data.get("policy_applied") if isinstance(data.get("policy_applied"), dict) else {}
    rejected = applied.get("rejected") if isinstance(applied.get("rejected"), list) else []
    codes = sorted({r["code"] for r in rejected if isinstance(r, dict) and isinstance(r.get("code"), str) and re.fullmatch(r"[a-z_]{1,40}", r["code"])})
    if rejected:
        # counts and fixed codes only: no waiver text travels back into the comment
        comment_notes.append(f"{len(rejected)} waiver(s) in the waiver file were rejected by the server" + (f" (reason codes: {', '.join(codes)})." if codes else "."))
    if applied and applied.get("waivers_applied") is False:
        print("::notice title=QuietPhysics waivers::The server is ignoring waivers (waivers_applied is false); block-on is still applied.")
    if pr_markdown and comment_notes:
        pr_markdown += "".join(f"\n\n> ℹ️ {clean(note, 300)}" for note in comment_notes)

    print(f"\n--- QuietPhysics Cloud Verification Result ---")
    print(f"Verdict:         {verdict}")
    print(f"Tests Passed:    {clean(data.get('passed_tests'), 40)}/{clean(data.get('total_tests'), 40)}")
    print(f"Execution time:  {clean(data.get('execution_time_ms'), 40)} ms")
    if data.get("request_id"):
        print(f"Request id:      {clean(data['request_id'], 80)}")
    print("----------------------------------------------")
    for note in analysis_notes(data):
        print(note)
    if policy_sent and not isinstance(data.get("policy_applied"), dict):
        print("::warning title=QuietPhysics policy::The server did not apply block-on/waivers (an older server ignores them), so the stricter default verdict stands.")
    print()

    # Set GitHub Actions output parameters if running in CI
    if "GITHUB_OUTPUT" in os.environ:
        with open(os.environ["GITHUB_OUTPUT"], "a") as f:
            f.write(f"verdict={verdict}\n")
            f.write(f"violations-count={count(data.get('failed_tests'))}\n")
            f.write(f"passed-count={count(data.get('passed_tests'))}\n")
            # true only when this run's configuration could fail the job for this verdict: an INCONCLUSIVE verdict with on-inconclusive: warn cannot
            f.write(f"enforced={'true' if enforced and not (verdict == 'INCONCLUSIVE' and on_inconclusive != 'fail') else 'false'}\n")

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
                print(f"ℹ️ Could not post PR comment: {clean(err)}")

    sys.exit(final_exit(verdict, exit_code, enforced, on_inconclusive, analysis_requested, advisory))


if __name__ == "__main__":
    main()
