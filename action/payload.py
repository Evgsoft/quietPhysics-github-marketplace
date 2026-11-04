"""Build and encode the /v1/evaluate request (plans/09-reference/action-upload-spec.md section 6). Standard library only."""

import gzip
import json
import os
import re
import stat
from typing import Any, Dict, List, Mapping, Tuple

from manifest_filter import ManifestError, collect_manifests
from plan_locations import build_location_map
from plan_reduce import PlanError, infer_account_ids, load_spec, reduce_plan_with_stats
from scrub import MIN_SECRET

# Hard-coded copies of the server's defaults (QP_MAX_BODY_BYTES, QP_MAX_RESOURCE_CHANGES, depth rule).
MAX_PLAN_FILE_BYTES = 100 * 1024 * 1024
MAX_BODY_BYTES = 8 * 1024 * 1024
MAX_RESOURCE_CHANGES = 5000
MAX_DEPTH = 64
GZIP_OVER_BYTES = 16 * 1024

_ACCOUNT_ID = re.compile(r"[0-9]{12}", re.ASCII)


class PayloadError(Exception):
    """The request cannot be built. The message never repeats plan or manifest content."""


def parse_on_inconclusive(env: Mapping[str, str]) -> str:
    value = (env.get("INPUT_ON_INCONCLUSIVE") or "warn").strip().lower()
    if value not in ("warn", "fail"):
        raise PayloadError("on-inconclusive must be 'warn' or 'fail'.")
    return value


def parse_on_sensitive(env: Mapping[str, str]) -> str:
    value = (env.get("INPUT_ON_SENSITIVE") or "fail").strip().lower()
    if value not in ("fail", "send"):
        raise PayloadError("on-sensitive must be 'fail' or 'send'.")
    return value


def _own_secrets(env: Mapping[str, str]) -> List[str]:
    """The run's own credentials: passed to the scrub so they can never travel inside a plan or a manifest."""
    names = ("QP_API_KEY", "GITHUB_TOKEN", "QP_BASIC_AUTH_USERNAME", "QP_BASIC_AUTH_PASSWORD", "ACTIONS_ID_TOKEN_REQUEST_TOKEN")
    return sorted({value for value in ((env.get(name) or "").strip() for name in names) if len(value) >= MIN_SECRET})


def nothing_to_analyse(payload: Mapping[str, Any]) -> bool:
    """True for an upload request that carries neither a plan nor manifests (nothing was found to analyse)."""
    return "api_version" in payload and "plan" not in payload and "kubernetes_manifests" not in payload


def attach_policy(payload: Dict[str, Any], policy: Any) -> Dict[str, Any]:
    """Merge ``policy`` into an upload payload after the limit checks and re-run them on the merged payload (PayloadError when over).
    Not attached when there is nothing to analyse, the payload is not an upload request (no api_version) or the policy is None."""
    if policy is None or "api_version" not in payload or nothing_to_analyse(payload):
        return payload
    merged = dict(payload)
    merged["policy"] = policy
    _check_limits(merged)
    return merged


def _parse_account_ids(raw: str) -> List[str]:
    if not raw.strip():
        return []
    ids = [part.strip() for part in raw.split(",")]
    if not all(_ACCOUNT_ID.fullmatch(part) for part in ids):
        raise PayloadError("aws-account-ids must be comma-separated 12-digit AWS account ids.")
    return ids


def _manifest_patterns(raw: str) -> List[str]:
    # A comma also separates patterns, unless a pattern uses {a,b} braces (those are refused later, never split).
    lines = raw.splitlines()
    if "{" not in raw:
        lines = [piece for line in lines for piece in line.split(",")]
    return [line.strip() for line in lines if line.strip()]


def _reject_constant(_name: str) -> Any:
    raise ValueError("NaN and Infinity are not valid JSON")


def _inside(path: str, root: str) -> bool:
    try:
        return os.path.commonpath([path, root]) == root
    except ValueError:
        return False


def _plan_path(path: str, base_dir: str, env: Mapping[str, str]) -> str:
    """Real path of the plan file; it must lie inside the workspace or RUNNER_TEMP (a plan file is read and uploaded)."""
    real = os.path.realpath(os.path.join(base_dir, path))
    roots = [os.path.realpath(base_dir)]
    if (env.get("RUNNER_TEMP") or "").strip():
        roots.append(os.path.realpath(env["RUNNER_TEMP"].strip()))
    if not any(_inside(real, root) for root in roots):
        raise PayloadError("The plan file must be inside the workspace or the runner temp directory.")
    return real


def _read_plan(path: str) -> Any:
    try:
        # O_NONBLOCK: opening a FIFO must not wait for a writer; the type is checked on the opened descriptor.
        # O_NOFOLLOW: the path was resolved and checked a moment ago; a symlink swapped in since then must not be followed.
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | getattr(os, "O_NONBLOCK", 0))
        with os.fdopen(fd, "rb") as handle:
            if not stat.S_ISREG(os.fstat(handle.fileno()).st_mode):
                raise PayloadError("The plan file must be a regular file.")
            data = handle.read(MAX_PLAN_FILE_BYTES + 1)
        if len(data) > MAX_PLAN_FILE_BYTES:
            raise PayloadError("The plan file is larger than 100 MiB.")
        return json.loads(data.decode("utf-8"), parse_constant=_reject_constant)
    except PayloadError:
        raise
    except OSError:
        raise PayloadError("The plan file could not be read.") from None
    except RecursionError:
        raise PayloadError("The plan file nests too deeply.") from None
    except ValueError:
        raise PayloadError("The plan file is not valid UTF-8 JSON.") from None


def _depth_exceeds(value: Any, limit: int) -> bool:
    """The server's rule, iteratively: a container is one level, scalars add none."""
    stack = [(value, 1)]
    while stack:
        node, depth = stack.pop()
        if not isinstance(node, (dict, list)):
            continue
        if depth > limit:
            return True
        children = node.values() if isinstance(node, dict) else node
        stack.extend((child, depth + 1) for child in children if isinstance(child, (dict, list)))
    return False


def _compact(payload: Any) -> bytes:
    return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _check_limits(payload: Dict[str, Any]) -> None:
    changes = payload.get("plan", {}).get("resource_changes", [])
    if len(changes) > MAX_RESOURCE_CHANGES:
        raise PayloadError(f"The plan has {len(changes)} supported resource changes; the limit is {MAX_RESOURCE_CHANGES}. "
                           "Split the plan or plan fewer resources per run.")
    if _depth_exceeds(payload, MAX_DEPTH):
        raise PayloadError(f"The request nests deeper than {MAX_DEPTH} levels. Simplify the deeply nested attribute values.")
    try:
        size = len(_compact(payload))
    except (ValueError, RecursionError):
        raise PayloadError("The request could not be serialised.") from None
    if size > MAX_BODY_BYTES:
        raise PayloadError(f"The request is {size} bytes; the limit is {MAX_BODY_BYTES}. Plan fewer resources per run.")


def build_payload(env: Mapping[str, str], base_dir: str = ".") -> Tuple[Dict[str, Any], List[str]]:
    mode, repo, sha = env.get("INPUT_MODE", "pr-regression"), env.get("GITHUB_REPOSITORY", "client-org/infrastructure"), env.get("GITHUB_SHA", "HEAD")
    plan_file = (env.get("INPUT_PLAN_FILE") or "").strip()
    patterns = _manifest_patterns(env.get("INPUT_MANIFEST_FILES") or "")
    if not plan_file and not patterns:
        return {"scenario_id": env.get("INPUT_SCENARIO", "all"), "mode": mode, "repo_name": repo, "commit_sha": sha}, []

    parse_on_inconclusive(env)
    on_sensitive = parse_on_sensitive(env)
    secrets = _own_secrets(env)
    configured_ids = _parse_account_ids(env.get("INPUT_AWS_ACCOUNT_IDS") or "")
    payload: Dict[str, Any] = {"api_version": "1", "mode": mode, "repo_name": repo, "commit_sha": sha}
    notes: List[str] = []
    if (env.get("INPUT_SCENARIO") or "all") != "all":
        notes.append("The scenario input is ignored because plan-file or manifest-files is set.")

    try:
        if plan_file:
            _add_plan(payload, notes, env, base_dir, plan_file, configured_ids, on_sensitive, secrets)
        if patterns:
            spec = load_spec()
            manifests = collect_manifests(patterns, base_dir, spec["kubernetes"], extra_secrets=secrets)
            if manifests:
                payload["kubernetes_manifests"] = manifests
            notes.append(f"Kubernetes manifests: {len(manifests)} file(s) with supported kinds will be analysed.")
        if configured_ids and "aws_account_ids" not in payload and not nothing_to_analyse(payload):
            payload["aws_account_ids"] = sorted(set(configured_ids))
    except (PlanError, ManifestError) as err:
        raise PayloadError(f"The input was refused: {err}") from None
    except (KeyError, TypeError):
        raise PayloadError("The allow-list spec is malformed.") from None
    except RecursionError:
        raise PayloadError("The input nests too deeply.") from None

    if not nothing_to_analyse(payload):
        _check_limits(payload)
    return payload, notes


def _add_plan(payload: Dict[str, Any], notes: List[str], env: Mapping[str, str], base_dir: str, plan_file: str,
              configured_ids: List[str], on_sensitive: str, secrets: List[str]) -> None:
    plan = _read_plan(_plan_path(plan_file, base_dir, env))
    spec = load_spec()
    # "withhold" only detects: a gate that cannot see a value cannot be trusted to approve, so withheld values are never sent.
    reduced, stats = reduce_plan_with_stats(plan, spec, sensitive="send" if on_sensitive == "send" else "withhold", extra_secrets=secrets)
    _refuse_credentials(stats["credentials"])
    if on_sensitive == "fail" and (stats["sensitive_attributes"] or stats["sensitive_withheld"]):
        names = ", ".join(stats["sensitive_attributes"]) or "(unnamed)"
        raise PayloadError(f"Attributes the rules read are marked sensitive in the plan: {names}. Nothing was sent. Remove sensitive() from what the rules "
                           "read, or set on-sensitive: send to upload those values.")
    notes.append(f"Plan: {stats['kept']} resource change(s) of supported types kept, {len(stats['dropped_types'])} other type(s) dropped.")
    if not stats["kept"]:
        notes.append("Nothing QuietPhysics checks was found in the plan, so the plan is not sent.")
        return
    payload["plan"] = reduced
    account_ids = sorted(set(infer_account_ids(plan)) | set(configured_ids))
    if account_ids:
        payload["aws_account_ids"] = account_ids
    addresses = [c["address"] for c in reduced["resource_changes"] if isinstance(c.get("address"), str)]
    locations = build_location_map(plan, base_dir, env.get("INPUT_TERRAFORM_DIR") or ".", addresses) if addresses else {}
    if locations:
        payload["location_map"] = locations
    if stats["sensitive_attributes"]:
        notes.append(f"on-sensitive: send: the values of {len(stats['sensitive_attributes'])} sensitive declared attribute(s) are uploaded.")


def _refuse_credentials(found: List[Dict[str, str]]) -> None:
    """A value the rules read looks like a credential: nothing is rewritten and nothing is sent (an attacker can only block their own PR)."""
    if found:
        listing = ", ".join(f"{item['attribute']} ({item['kind']})" for item in found)
        raise PayloadError(f"A value the rules read looks like a credential: {listing}. It was not uploaded and nothing was sent. Remove the secret from "
                           "those attributes (reference it from a secret store instead); there is deliberately no override.")


def encode_body(payload: Dict[str, Any]) -> Tuple[bytes, Dict[str, str]]:
    body = _compact(payload)
    headers = {"Content-Type": "application/json", "X-QP-Api-Version": "1"}
    if len(body) > GZIP_OVER_BYTES:
        body = gzip.compress(body, mtime=0)
        headers["Content-Encoding"] = "gzip"
    return body, headers
