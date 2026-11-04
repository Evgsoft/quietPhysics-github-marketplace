"""file:line of Terraform resources, found client-side (plans/09-reference/action-upload-spec.md section 4). Standard library only."""

import os
import re
import stat
from typing import Any, Dict, Iterable, List, Optional, Tuple

MAX_TF_FILES = 2000
MAX_TF_BYTES = 2 * 1024 * 1024
MAX_TOTAL_SCAN_BYTES = 20 * 1024 * 1024
MAX_ADDRESS_CHARS = 4096
MAX_MODULE_DEPTH = 64

# Anchored at the line start and with no nested quantifiers, so a hostile line cannot cause backtracking.
_HEADER = re.compile(r'[ \t]*resource[ \t]+"([^"\n]*)"[ \t]+"([^"\n]*)"[ \t]*\{')
# What can change the lexer state: a string (skipped whole), a line comment, a block comment, a heredoc.
_TOKEN = re.compile(r'"(?:[^"\\]+|\\.)*"?|#|//|/\*|<<-?([A-Za-z_][A-Za-z0-9_]*)')

Key = Tuple[str, str]


def _real(path: str) -> Optional[str]:
    try:
        return os.path.realpath(path)
    except (OSError, ValueError):
        return None


def _inside(path: str, base: str) -> bool:
    return path == base or path.startswith(base.rstrip(os.sep) + os.sep)


def _skip_instance_key(addr: str, i: int) -> int:
    """addr[i] is '['; return the index after the matching ']', or -1 when the key is not a number or a quoted string."""
    n = len(addr)
    i += 1
    if i < n and addr[i] == '"':
        i += 1
        while i < n and addr[i] != '"':
            i += 2 if addr[i] == "\\" else 1
        i += 1
    else:
        start = i
        while i < n and addr[i].isascii() and addr[i].isdigit():
            i += 1
        if i == start:
            return -1
    return i + 1 if i < n and addr[i] == "]" else -1


def _parse_address(addr: Any) -> Optional[Tuple[Tuple[str, ...], str, str]]:
    """'module.a["k"].aws_x.y[0]' -> (("a",), "aws_x", "y"); None for anything that is not a managed resource address."""
    if not isinstance(addr, str) or len(addr) > MAX_ADDRESS_CHARS:
        return None
    segments: List[str] = []
    i, n = 0, len(addr)
    while True:
        j = i
        while j < n and addr[j] not in ".[":
            j += 1
        if j == i:
            return None
        segments.append(addr[i:j])
        i = j
        if i < n and addr[i] == "[":
            i = _skip_instance_key(addr, i)
            if i < 0:
                return None
        if i == n:
            break
        if addr[i] != ".":
            return None
        i += 1
    prefix = segments[:-2]
    if len(segments) < 2 or len(prefix) % 2 or len(prefix) // 2 > MAX_MODULE_DEPTH:
        return None
    if any(prefix[k] != "module" for k in range(0, len(prefix), 2)):
        return None
    return tuple(prefix[1::2]), segments[-2], segments[-1]


def _module_dir(plan: Any, names: Tuple[str, ...], tf_dir: str, base: str) -> Optional[str]:
    """Directory of the module reached through `names`, following local sources call by call; None when unknown or outside base."""
    config = plan.get("configuration") if isinstance(plan, dict) else None
    module = config.get("root_module") if isinstance(config, dict) else None
    cur = tf_dir
    for name in names:
        calls = module.get("module_calls") if isinstance(module, dict) else None
        call = calls.get(name) if isinstance(calls, dict) else None
        source = call.get("source") if isinstance(call, dict) else None
        if not isinstance(source, str) or not source.startswith(("./", "../")):
            return None
        cur = _real(os.path.join(cur, source))
        if cur is None or not _inside(cur, base):
            return None
        module = call.get("module")
    return cur


def _headers(text: str, wanted: Optional[set]) -> List[Tuple[Key, int]]:
    """(type, name) and 1-based line of each real `resource` header; comments, heredocs and strings never match."""
    found: List[Tuple[Key, int]] = []
    in_block = False
    heredoc = None
    for lineno, line in enumerate(text.split("\n"), 1):
        pos = 0
        if in_block:
            end = line.find("*/")
            if end < 0:
                continue
            in_block, pos = False, end + 2
        elif heredoc is not None:
            if line.strip() == heredoc:
                heredoc = None
            continue
        else:
            m = _HEADER.match(line)
            if m and (wanted is None or (m.group(1), m.group(2)) in wanted):
                found.append(((m.group(1), m.group(2)), lineno))
        while True:
            tok = _TOKEN.search(line, pos)
            if tok is None:
                break
            text_tok = tok.group()
            if text_tok[0] == '"':
                pos = tok.end()
            elif text_tok in ("#", "//"):
                break
            elif text_tok == "/*":
                end = line.find("*/", tok.end())
                if end < 0:
                    in_block = True
                    break
                pos = end + 2
            else:
                heredoc = tok.group(1)
                break
    return found


_OVER_BUDGET = object()


class _Scanner:
    """One per build_location_map call: the shared byte budget and a cache of headers by real path, so a file reached
    through many symlinks or modules is read, charged and parsed once."""

    def __init__(self, base: str) -> None:
        self.base = base
        self.remaining = MAX_TOTAL_SCAN_BYTES
        self.cache: Dict[str, Any] = {}

    def headers(self, path: str) -> Any:
        """[(key, line)] of the file, None when it is skipped, _OVER_BUDGET when the budget cannot pay for it."""
        real = _real(path)
        if real is None or not _inside(real, self.base):
            return None
        if real in self.cache:
            return self.cache[real]
        result: Any = None
        try:
            size = os.stat(real).st_size
            if stat.S_ISREG(os.stat(real).st_mode) and size <= MAX_TF_BYTES:
                if size > self.remaining:
                    return _OVER_BUDGET 
                with open(real, "rb") as f:
                    data = f.read(MAX_TF_BYTES + 1)
                if len(data) <= MAX_TF_BYTES:
                    if len(data) > self.remaining:
                        return _OVER_BUDGET
                    self.remaining -= len(data)
                    result = _headers(data.decode("utf-8-sig", errors="replace"), None)
        except OSError:
            result = None
        self.cache[real] = result
        return result


def _scan_directory(directory: str, scanner: _Scanner, wanted: set) -> Dict[Key, Dict[str, Any]]:
    """Locations of the wanted (type, name) pairs among the *.tf files directly in `directory`; ambiguous pairs are left out,
    and so is everything when some file could not be scanned for lack of budget (it could hide a duplicate)."""
    try:
        names = sorted(e.name for e in os.scandir(directory) if e.name.endswith(".tf"))
    except OSError:
        return {}
    if len(names) > MAX_TF_FILES:
        return {}  # cannot rule out a duplicate in an unscanned file, so guess nothing
    rel_dir = os.path.relpath(directory, scanner.base).replace(os.sep, "/")
    hits: Dict[Key, List[Dict[str, Any]]] = {}
    for name in names:
        found = scanner.headers(os.path.join(directory, name))
        if found is _OVER_BUDGET:
            return {}
        if found is None:
            continue
        rel = name if rel_dir == "." else rel_dir + "/" + name
        for key, line in found:
            if key in wanted:
                hits.setdefault(key, []).append({"file": rel, "line": line})
    return {key: found[0] for key, found in hits.items() if len(found) == 1}


def build_location_map(plan: Any, base_dir: str, terraform_dir: str, addresses: Iterable[str]) -> Dict[str, Dict[str, Any]]:
    if not isinstance(base_dir, str) or not base_dir or not isinstance(terraform_dir, str):
        return {}
    try:
        addrs = list(dict.fromkeys(a for a in addresses if isinstance(a, str)))
    except TypeError:
        return {}
    base = _real(base_dir)
    if base is None or not os.path.isdir(base):
        return {}
    tf_dir = _real(os.path.join(base, terraform_dir or "."))
    if tf_dir is None or not _inside(tf_dir, base):
        return {}

    dir_cache: Dict[Tuple[str, ...], Optional[str]] = {}
    parsed: Dict[str, Tuple[str, Key]] = {}
    wanted: Dict[str, set] = {}
    for addr in addrs:
        p = _parse_address(addr)
        if p is None:
            continue
        names, rtype, rname = p
        if names not in dir_cache:
            dir_cache[names] = _module_dir(plan, names, tf_dir, base)
        directory = dir_cache[names]
        if directory is None:
            continue
        parsed[addr] = (directory, (rtype, rname))
        wanted.setdefault(directory, set()).add((rtype, rname))

    scanner = _Scanner(base)
    scans = {d: _scan_directory(d, scanner, keys) for d, keys in wanted.items()}
    result: Dict[str, Dict[str, Any]] = {}
    for addr in addrs:
        if addr in parsed:
            directory, key = parsed[addr]
            if key in scans[directory]:
                result[addr] = dict(scans[directory][key])
    return result
