"""Credential check shared by plan_reduce and manifest_filter (plans/09-reference/action-upload-spec.md section 3, rev 4). Standard library only.

The check DETECTS and never rewrites: replacing a span inside a value the rules read changed verdicts in review (a deleted statement, a
swallowed `../..`), so a value that looks like a credential is refused instead. Best effort: a credential-shaped value that is not
caught is not protected."""

import json
import re
from typing import Any, Iterable, List, Set

MIN_SECRET = 8                       # shorter exact secrets would hit ordinary words
MAX_JSON_NESTING = 16                # JSON documents inside JSON strings (each level doubles the escaping, so real input stops far earlier)

# Every pattern is linear on hostile input: fixed prefixes, bounded or run-anchored quantifiers (the JWT lookbehind makes only the
# start of a base64url run a candidate, so a long run is not rescanned from each of its positions).
_PATTERNS = [(kind, re.compile(pattern)) for kind, pattern in (
    ("private_key", r"-----BEGIN [A-Z ]{0,30}PRIVATE KEY-----"),
    ("bearer_token", r"(?i:bearer\s+[A-Za-z0-9._~+/=-]{20,})"),
    ("jwt", r"(?<![A-Za-z0-9_-])eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*"),
    ("aws_access_key_id", r"(?:AKIA|ASIA)[0-9A-Z]{16}"),
    ("github_token", r"gh[pousr]_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{10,}"),
    ("gitlab_token", r"glpat-[A-Za-z0-9_-]{20,}"),
    ("slack_token", r"xox[a-z]-[A-Za-z0-9-]{10,}|xapp-[A-Za-z0-9-]{10,}"),
    ("stripe_key", r"(?:sk|rk)_(?:live|test)_[A-Za-z0-9]{8,}"),
    ("google_api_key", r"AIza[0-9A-Za-z_-]{35}"),
    ("url_password", r"(?<=://)[^/\s:@]+:[^/\s@]+(?=@)"),
)]


class _Pairs(list):
    """A parsed JSON object as its (key, value) pairs, so a duplicate key cannot hide a value."""


def _decode(text: str) -> Any:
    """The JSON value a string holds, or None (not JSON, too deep for the parser, a huge number)."""
    if text.lstrip(" \t\n\r")[:1] not in ("{", "[", '"'):
        return None
    try:
        return json.loads(text, object_pairs_hook=_Pairs)
    except (ValueError, RecursionError):
        return None


def _kinds_in(text: str, secrets: List[str], found: Set[str]) -> None:
    for kind, pattern in _PATTERNS:
        if kind not in found and pattern.search(text):
            found.add(kind)
    if "own_secret" not in found and any(secret in text for secret in secrets):
        found.add("own_secret")


def find_credentials(value: Any, extra_secrets: Iterable[str] = ()) -> List[str]:
    """Sorted unique kinds of credential found in every string of value, dict keys included. A string that parses as JSON is checked
    as raw text and leaf by leaf (an escape such as \\u0049 hides a credential from the raw text only). Iterative; never raises on
    depth; never returns matched text."""
    secrets = sorted({s for s in extra_secrets if isinstance(s, str) and len(s) >= MIN_SECRET})
    found: Set[str] = set()
    stack = [(value, 0)]
    while stack:
        item, nesting = stack.pop()
        if isinstance(item, str):
            _kinds_in(item, secrets, found)
            parsed = _decode(item) if nesting < MAX_JSON_NESTING else None
            if parsed is not None:
                stack.append((parsed, nesting + 1))
        elif isinstance(item, _Pairs):
            for key, child in item:
                stack.append((key, nesting))
                stack.append((child, nesting))
        elif isinstance(item, dict):
            for key, child in item.items():
                stack.append((key, nesting))
                stack.append((child, nesting))
        elif isinstance(item, list):
            stack.extend((child, nesting) for child in item)
    return sorted(found)
