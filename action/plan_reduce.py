"""Reduce a Terraform plan to what the rules read (plans/09-reference/action-upload-spec.md section 3). Standard library only."""

import json
import os
import re
import sys
from typing import Any, Dict, Iterable, List, Optional, Tuple

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from scrub import MIN_SECRET, find_credentials  # noqa: E402


class PlanError(Exception):
    """The plan cannot be reduced. The message never repeats plan content."""


MAX_DEPTH = 200                      # input levels read without recursion errors; deeper is refused
_DEEP = "The plan nests deeper than the supported 200 levels."
_VERSION = re.compile(r"(\d{1,3})\.(\d{1,4})")
_ACTIONS = frozenset({"no-op", "create", "read", "update", "delete"})
_PRUNED = object()

# Same patterns as the server's infer_account_ids (the test compares them, \d included).
_MODES = ("withhold", "send")
_ARN_ACCOUNT = re.compile(r"arn:aws[a-z-]*:[a-z0-9-]+:[a-z0-9-]*:(\d{12}):")
_ACCOUNT_ID = re.compile(r"\d{12}")


def load_spec(path: Optional[str] = None) -> Dict[str, Any]:
    path = path or os.path.join(os.path.dirname(os.path.abspath(__file__)), "spec.json")
    try:
        with open(path, "r", encoding="utf-8") as handle:
            spec = json.load(handle)
    except (OSError, ValueError, RecursionError):
        raise PlanError("The allow-list spec could not be read.") from None
    if not isinstance(spec, dict):
        raise PlanError("The allow-list spec must be a JSON object.")
    return spec


class _Run:
    """Counters for one reduction, plus the credential findings (the data itself is never altered)."""

    def __init__(self, sensitive: str, extra_secrets: Iterable[str]) -> None:
        self.withhold = sensitive == "withhold"
        self.withheld = 0
        self.names: set = set()
        self.credentials: set = set()
        self._secrets = [s for s in extra_secrets if isinstance(s, str) and len(s) >= MIN_SECRET]

    def check(self, attribute: str, value: Any) -> Any:
        """Records the kinds of credential in a value that will be sent, under the attribute's name; returns the value."""
        self.credentials.update((attribute, kind) for kind in find_credentials(value, self._secrets))
        return value


def _check_spec(spec: Any) -> Tuple[Dict[str, List[str]], Dict[str, Dict[str, List[str]]]]:
    if not isinstance(spec, dict):
        raise PlanError("The allow-list spec must be a JSON object.")
    terraform, nested = spec.get("terraform"), spec.get("terraform_nested", {})
    if not isinstance(terraform, dict) or not isinstance(nested, dict):
        raise PlanError("The allow-list spec is malformed.")
    for attrs in terraform.values():
        if not isinstance(attrs, list) or not all(isinstance(a, str) for a in attrs):
            raise PlanError("The allow-list spec is malformed.")
    for per_type in nested.values():
        if not isinstance(per_type, dict) or not all(isinstance(k, list) and all(isinstance(s, str) for s in k) for k in per_type.values()):
            raise PlanError("The allow-list spec is malformed.")
    return terraform, nested


def _is_depth_ok(value: Any, depth: int) -> bool:
    """Whether the containers under value stay within MAX_DEPTH (iterative; value sits at depth)."""
    stack = [(value, depth)]
    while stack:
        node, d = stack.pop()
        if isinstance(node, (dict, list)):
            if d > MAX_DEPTH:
                return False
            stack.extend((child, d + 1) for child in (node.values() if isinstance(node, dict) else node))
    return True


def _walk(value: Any, marker: Any, run: _Run, depth: int) -> Any:
    """Copy of a declared value In withhold mode a leaf or container whose sensitive marker is exactly True is
    replaced by None in place (never deleted: a missing key would read as "not set" and could approve a risky rule)."""
    holder: List[Any] = [None]
    stack = [(value, marker, holder, 0, depth)]
    while stack:
        v, m, parent, key, d = stack.pop()
        if m is True and run.withhold:
            if v is not None:
                run.withheld += 1
            parent[key] = None
        elif isinstance(v, str) or v is None or isinstance(v, (bool, int, float)):
            parent[key] = v
        elif isinstance(v, dict):
            if d > MAX_DEPTH:
                raise PlanError(_DEEP)
            out = parent[key] = {}
            for k, child in v.items():
                if not isinstance(k, str):
                    raise PlanError("The plan has a non-string key.")
                out[k] = None
                stack.append((child, m.get(k, False) if isinstance(m, dict) else False, out, k, d + 1))
        elif isinstance(v, list):
            if d > MAX_DEPTH:
                raise PlanError(_DEEP)
            out = parent[key] = [None] * len(v)
            for i, child in enumerate(v):
                stack.append((child, m[i] if isinstance(m, list) and i < len(m) else False, out, i, d + 1))
        else:
            raise PlanError("The plan holds a value that is not JSON.")
    return holder[0]


def _has_true(marker: Any) -> bool:
    stack = [marker]
    while stack:
        node = stack.pop()
        if node is True:
            return True
        if isinstance(node, dict):
            stack.extend(node.values())
        elif isinstance(node, list):
            stack.extend(node)
    return False


def _copy_marker(marker: Any, depth: int) -> Any:
    """Copy of an unknown/sensitive marker. Only booleans (and null) are legal leaves; anything else is refused, never echoed."""
    holder: List[Any] = [None]
    stack = [(marker, holder, 0, depth)]
    while stack:
        m, parent, key, d = stack.pop()
        if m is None or isinstance(m, bool):
            parent[key] = m
        elif isinstance(m, (dict, list)):
            if d > MAX_DEPTH:
                raise PlanError(_DEEP)
            if isinstance(m, dict):
                out = parent[key] = {}
                for k, child in m.items():
                    out[k] = None
                    stack.append((child, out, k, d + 1))
            else:
                out = parent[key] = [None] * len(m)
                stack.extend((child, out, i, d + 1) for i, child in enumerate(m))
        else:
            raise PlanError("A plan marker holds something other than true or false.")
    return holder[0]


def _top_marker(marker: Any, attrs: List[str], nested: Dict[str, List[str]], run: _Run, expand_over: Any = None, sent: bool = True) -> Any:
    """A whole-object marker cut to the declared attributes (and, for a nested attribute, to its declared sub-keys).
    expand_over: the state a sensitive `true` covers; the server does not inherit a root `true`, so it is written per attribute.
    sent: whether the result travels (its keys are then checked for credentials)."""
    if marker is True and isinstance(expand_over, dict):
        return {attr: True for attr in attrs if attr in expand_over}
    if isinstance(marker, bool):
        return marker
    if not isinstance(marker, dict):
        raise PlanError("A plan marker must be an object or a boolean.")
    out: Dict[str, Any] = {}
    for attr in attrs:
        if attr not in marker:
            continue
        child = marker[attr]
        if attr in nested:
            if isinstance(child, dict):
                child = {k: child[k] for k in nested[attr] if k in child}
            elif not isinstance(child, bool):
                child = False                                    # the server reads anything but true as "not marked"
        out[attr] = run.check(attr, _copy_marker(child, 6)) if sent else _copy_marker(child, 6)
    return out


def _state(state: Any, attrs: List[str], nested: Dict[str, List[str]], marker: Any, run: _Run) -> Optional[Dict[str, Any]]:
    if state is None:
        return None
    if not isinstance(state, dict):
        raise PlanError("A change's before/after must be an object or null.")
    out: Dict[str, Any] = {}
    for attr in attrs:
        if attr not in state:
            continue
        value = state[attr]
        if attr in nested:
            value = {k: value[k] for k in nested[attr] if k in value} if isinstance(value, dict) else None
        sensitive = True if marker is True else (marker.get(attr, False) if isinstance(marker, dict) else False)
        if attr in nested and isinstance(sensitive, dict):
            sensitive = {k: sensitive[k] for k in nested[attr] if k in sensitive}      # markers on dropped sub-keys do not count
        if _has_true(sensitive):
            run.names.add(attr)
        out[attr] = run.check(attr, _walk(value, sensitive, run, 6))
    return out


def _optional_str(entry: Dict[str, Any], key: str, run: _Run) -> Optional[str]:
    value = entry.get(key)
    if value is None:
        return None
    if not isinstance(value, str):
        raise PlanError("A resource_changes entry has a field of the wrong type.")
    return run.check("address", value)


def _reduce_entry(entry: Dict[str, Any], attrs: List[str], nested: Dict[str, List[str]], run: _Run) -> Dict[str, Any]:
    address = entry.get("address")
    if not isinstance(address, str):
        raise PlanError("A resource_changes entry has no string address.")
    out: Dict[str, Any] = {"address": run.check("address", address)}
    for key in ("mode", "type", "name", "module_address"):
        value = _optional_str(entry, key, run)
        if value is not None:
            out[key] = value
    index = entry.get("index")
    if index is not None:
        if isinstance(index, bool) or not isinstance(index, (str, int)):
            raise PlanError("A resource_changes entry has an index of the wrong type.")
        out["index"] = run.check("address", index)
    change = entry.get("change")
    if not isinstance(change, dict):
        raise PlanError("A resource_changes entry has no change object.")
    actions = change.get("actions")
    if not isinstance(actions, list) or not actions or not all(isinstance(a, str) and a in _ACTIONS for a in actions):
        raise PlanError("A change has missing or unknown actions.")
    states = {"before_sensitive": change.get("before"), "after_sensitive": change.get("after")}
    markers = {key: _top_marker(change[key], attrs, nested, run, states.get(key), key == "after_unknown" or run.withhold)
               for key in ("after_unknown", "before_sensitive", "after_sensitive") if change.get(key) is not None}
    if not run.withhold:
        for key in ("before_sensitive", "after_sensitive"):
            if key in markers:
                # The values are sent, so they are no longer withheld. But a sensitive attribute that HAS no value (null or missing) must
                # stay marked: the server reads "sensitive and no value" as withheld (Unknown), not as absent.
                source, state = change.get(key), states.get(key)
                markers[key] = {attr: True for attr in attrs
                                if isinstance(source, dict) and source.get(attr) is True and (not isinstance(state, dict) or state.get(attr) is None)}
    result: Dict[str, Any] = {"actions": list(actions)}
    if "before" in change:
        result["before"] = _state(change["before"], attrs, nested, change.get("before_sensitive"), run)
    if "after" in change:
        result["after"] = _state(change["after"], attrs, nested, change.get("after_sensitive"), run)
    result.update(markers)
    out["change"] = result
    return out


def _reduce_expressions(expressions: Dict[str, Any], attrs: List[str], run: _Run, depth: int) -> Dict[str, Any]:
    """Keep, per declared attribute, only the lists of strings under the key "references", with the nesting around them.
    Containers left empty are pruned (the server reads only references, not positions)."""
    out: Dict[str, Any] = {}
    for attr in attrs:
        if attr not in expressions or not isinstance(expressions[attr], (dict, list)):
            continue
        holder: List[Any] = [None]
        created = []                                            # parents before children
        stack = [(expressions[attr], holder, 0, depth)]
        while stack:
            node, parent, key, d = stack.pop()
            if d > MAX_DEPTH:
                raise PlanError(_DEEP)
            if isinstance(node, list):
                container: Any = []
                items = [(child, None) for child in node]
            else:
                container = {}
                items = [(child, k) for k, child in node.items() if k != "references"]
                refs = node.get("references")
                if isinstance(refs, list):
                    if not _is_depth_ok(refs, d + 1):
                        raise PlanError(_DEEP)
                    container["references"] = [r for r in refs if isinstance(r, str)]
            parent[key] = container
            created.append((container, parent, key))
            for child, name in items:
                if isinstance(child, (dict, list)):
                    if name is None:
                        container.append(None)
                        name = len(container) - 1
                    stack.append((child, container, name, d + 1))
        for container, parent, key in reversed(created):
            if isinstance(container, list):
                container[:] = [x for x in container if x is not _PRUNED]
            if not container:
                if isinstance(parent, dict):
                    del parent[key]
                else:
                    parent[key] = _PRUNED
        if holder[0] is not _PRUNED and holder[0] is not None:
            out[attr] = run.check(attr, holder[0])
    return out


def _reduce_configuration(config: Any, terraform: Dict[str, List[str]], run: _Run) -> Optional[Dict[str, Any]]:
    """root_module.resources and module_calls.<name>.module.resources (nested, iterative) of kept types, references only.
    Modules that end up with nothing are left out."""
    root = config.get("root_module") if isinstance(config, dict) else None
    if not isinstance(root, dict):
        return None
    nodes: List[Tuple[Dict[str, Any], int, Optional[str]]] = []
    stack = [(root, -1, None, 3)]
    while stack:
        module, parent, name, depth = stack.pop()
        if depth > MAX_DEPTH:
            raise PlanError(_DEEP)
        resources = []
        raw = module.get("resources")
        for res in raw if isinstance(raw, list) else ():
            if not isinstance(res, dict) or not isinstance(res.get("type"), str) or res["type"] not in terraform or res.get("mode", "managed") != "managed":
                continue
            address, rname, expressions = res.get("address"), res.get("name"), res.get("expressions")
            if not (isinstance(address, str) and isinstance(rname, str) and isinstance(expressions, dict)):
                continue
            resources.append({"address": run.check("address", address), "mode": "managed", "type": res["type"], "name": run.check("address", rname),
                              "expressions": _reduce_expressions(expressions, terraform[res["type"]], run, depth + 3)})
        nodes.append(({"resources": resources}, parent, name))
        index = len(nodes) - 1
        calls = module.get("module_calls")
        for call_name, call in reversed(list(calls.items())) if isinstance(calls, dict) else ():
            inner = call.get("module") if isinstance(call, dict) else None
            if isinstance(inner, dict):
                stack.append((inner, index, call_name, depth + 3))
    alive = [bool(out["resources"]) for out, _, _ in nodes]
    for i in range(len(nodes) - 1, 0, -1):
        if alive[i]:
            alive[nodes[i][1]] = True
    for i in range(1, len(nodes)):
        if alive[i]:
            out, parent, name = nodes[i]
            calls_out = nodes[parent][0].setdefault("module_calls", {})
            calls_out[run.check("address", name or "")] = {"module": out}
    return {"root_module": nodes[0][0]} if alive[0] else None


def reduce_plan_with_stats(plan: Any, spec: Dict[str, Any], sensitive: str = "withhold",
                           extra_secrets: Iterable[str] = ()) -> Tuple[Dict[str, Any], Dict[str, Any]]:
    if not isinstance(sensitive, str) or sensitive not in _MODES:
        raise PlanError("The sensitive mode must be 'withhold' or 'send'.")
    terraform, nested = _check_spec(spec)
    if not isinstance(plan, dict):
        raise PlanError("The plan must be a JSON object.")
    version = plan.get("format_version")
    if not isinstance(version, str) or not _VERSION.fullmatch(version):
        raise PlanError("The plan has no valid format_version.")
    entries = plan.get("resource_changes")
    if entries is None:
        entries = []
    if not isinstance(entries, list):
        raise PlanError("resource_changes must be a list.")

    run, kept, dropped = _Run(sensitive, extra_secrets), [], set()
    for entry in entries:
        if not isinstance(entry, dict) or not isinstance(entry.get("type"), str):
            raise PlanError("A resource_changes entry must be an object with a string type.")
        rtype = entry["type"]
        if rtype not in terraform:
            dropped.add(rtype)
            continue
        mode = entry.get("mode")
        if mode is not None and not isinstance(mode, str):
            raise PlanError("A resource_changes entry has a mode of the wrong type.")
        if mode not in (None, "managed"):
            continue
        kept.append(_reduce_entry(entry, terraform[rtype], nested.get(rtype, {}), run))

    reduced: Dict[str, Any] = {"format_version": version, "resource_changes": kept}
    configuration = _reduce_configuration(plan.get("configuration"), terraform, run)
    if configuration is not None:
        reduced["configuration"] = configuration
    stats = {"kept": len(kept), "dropped_types": sorted(dropped), "sensitive_withheld": run.withheld,
             "sensitive_attributes": sorted(run.names),
             "credentials": [{"attribute": attribute, "kind": kind} for attribute, kind in sorted(run.credentials)]}
    return reduced, stats


def _usable(marker: Any, key: str) -> bool:
    return not (marker is True or (isinstance(marker, dict) and marker.get(key) is True))


def infer_account_ids(plan: Any) -> List[str]:
    """Sorted 12-digit account ids, exactly as the server's infer_account_ids: Known arn and owner_id (never account_id, which an
    author can set) of the `before` state only (what exists today; `after` is the author's input) of every resource_changes entry,
    dropped types and no-ops included; an attribute marked sensitive is skipped. Never raises."""
    found = set()
    entries = plan.get("resource_changes") if isinstance(plan, dict) else None
    for entry in entries if isinstance(entries, list) else ():
        change = entry.get("change") if isinstance(entry, dict) else None
        state = change.get("before") if isinstance(change, dict) else None
        if not isinstance(state, dict):
            continue
        hidden = change.get("before_sensitive")
        arn = state.get("arn")
        match = _ARN_ACCOUNT.match(arn) if isinstance(arn, str) and _usable(hidden, "arn") else None
        if match:
            found.add(match.group(1))
        value = state.get("owner_id")
        if isinstance(value, str) and _ACCOUNT_ID.fullmatch(value) and _usable(hidden, "owner_id"):
            found.add(value)
    return sorted(found)


def reduce_plan(plan: Any, spec: Dict[str, Any], sensitive: str = "withhold", extra_secrets: Iterable[str] = ()) -> Dict[str, Any]:
    return reduce_plan_with_stats(plan, spec, sensitive, extra_secrets)[0]
