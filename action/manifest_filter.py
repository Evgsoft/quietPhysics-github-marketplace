"""Collect and redact Kubernetes manifests (plans/09-reference/action-upload-spec.md section 5). Standard library only.

There is no YAML library on the customer's runner, so this module holds a restricted block-YAML parser. Anything outside the
supported subset raises ManifestError and nothing is uploaded. Error messages carry a line number and a fixed reason, never content."""

import json
import os
import re
import stat
import sys
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from scrub import find_credentials  # noqa: E402

MAX_DEPTH = 64                    # the server's rule: the top-level mapping is level 1
MAX_NODES = 400_000               # YAML nodes (scalars, keys, collections) per file
MAX_FILE_BYTES = 1024 * 1024
MAX_FILES = 500
MAX_TOTAL_BYTES = 2 * 1024 * 1024  # all uploaded manifest text together (the server's cap)


class ManifestError(Exception):
    """Manifests cannot be collected. The message never repeats manifest content."""


class _Opaque:
    """A value we refuse to keep: a block scalar, or a plain scalar whose YAML type we do not reproduce."""


_OPAQUE = _Opaque()
_EMPTY = object()                 # a document with nothing but comments

# ---------------------------------------------------------------- plain scalars (PyYAML SafeLoader's resolution, YAML 1.1)
_NULLS = {"~", "null", "Null", "NULL", ""}
_TRUES = {"true", "True", "TRUE", "yes", "Yes", "YES", "on", "On", "ON"}
_FALSES = {"false", "False", "FALSE", "no", "No", "NO", "off", "Off", "OFF"}
_DECIMAL = re.compile(r"[-+]?(?:0|[1-9][0-9]*)")
_SIMPLE_FLOAT = re.compile(r"[-+]?[0-9]+\.[0-9]+")
# Every other form PyYAML types (octal, hex, 1_000, 1:30, 1e+3, .inf, dates, '<<', '=') is refused rather than reproduced.
_EXOTIC = re.compile(
    r"[-+]?0b[01_]+|[-+]?0[0-7_]+|[-+]?(?:0|[1-9][0-9_]*)|[-+]?0x[0-9a-fA-F_]+|[-+]?[1-9][0-9_]*(?::[0-5]?[0-9])+"
    r"|[-+]?[0-9][0-9_]*\.[0-9_]*(?:[eE][-+][0-9]+)?|\.[0-9_]+(?:[eE][-+][0-9]+)?|[-+]?[0-9][0-9_]*(?::[0-5]?[0-9])+\.[0-9_]*"
    r"|[-+]?\.(?:inf|Inf|INF)|\.(?:nan|NaN|NAN)"
    r"|[0-9]{4}-[0-9]{2}-[0-9]{2}|[0-9]{4}-[0-9]{1,2}-[0-9]{1,2}(?:[Tt]|[ \t]+)[0-9]{1,2}:[0-9]{2}:[0-9]{2}(?:\.[0-9]*)?(?:[ \t]*(?:Z|[-+][0-9]{1,2}(?::[0-9]{2})?))?"
    r"|<<|=")


def _plain(text: str) -> Any:
    if text in _NULLS:
        return None
    if text in _TRUES:
        return True
    if text in _FALSES:
        return False
    if _DECIMAL.fullmatch(text):
        try:
            return int(text)
        except ValueError:                       # more digits than Python converts
            return _OPAQUE
    if _SIMPLE_FLOAT.fullmatch(text):
        value = float(text)
        return value if value - value == 0 else _OPAQUE
    return _OPAQUE if _EXOTIC.fullmatch(text) else text


# ---------------------------------------------------------------- the parser
_COLON = re.compile(r":(?:[ \t]|$)")
_COMMENT = re.compile(r"[ \t]#")
_BLOCK = re.compile(r"[|>](?:[+-][1-9]?|[1-9][+-]?)?(?=[ \t]|$)")
_SINGLE = re.compile(r"'(?:[^']|'')*'")
_DOUBLE = re.compile(r'"(?:[^"\\]|\\.)*"')
_ESCAPE = re.compile(r"\\(x[0-9a-fA-F]{2}|u[0-9a-fA-F]{4}|U[0-9a-fA-F]{8}|.)")
_ESCAPES = {"0": "\0", "a": "\a", "b": "\b", "t": "\t", "\t": "\t", "n": "\n", "v": "\v", "f": "\f", "r": "\r", "e": "\x1b", " ": " ",
            '"': '"', "/": "/", "\\": "\\", "N": "\x85", "_": "\xa0", "L": " ", "P": " "}
_FLOW_PLAIN = re.compile(r"(?:[^,\[\]{}:#\s]+|:(?![ \t,\[\]{}]|$)|(?<=\S)#|[ \t](?!#))*")
_SPACES = re.compile(r"[ \t]*")
_SEPARATOR = re.compile(r"(?:---|\.\.\.)(?:\s|$)")
# What PyYAML refuses, plus the Unicode line breaks it honours but this parser would read as text (U+0085, U+2028, U+2029).
_UNREADABLE = re.compile("[^\x09\x0a\x0d\x20-\x7e\xa0-‧‪-퟿-�\U00010000-\U0010ffff]")


class _Parser:
    """One YAML document, line by line. Lines are never mutated; a '- key: v' item is read as a virtual line of the item's column."""

    def __init__(self, lines: List[str], first_line: int, nodes: int):
        self.lines, self.base, self.nodes = lines, first_line, nodes
        self.i = 0
        self.virt: Optional[Tuple[int, int, str]] = None

    def _fail(self, reason: str):
        raise ManifestError("line %d: %s" % (self.base + self.i + 1, reason))

    def _count(self) -> None:
        self.nodes += 1
        if self.nodes > MAX_NODES:
            self._fail("more than %d YAML nodes" % MAX_NODES)

    def _peek(self) -> Optional[Tuple[int, str]]:
        while self.i < len(self.lines):
            if self.virt and self.virt[0] == self.i:
                return self.virt[1], self.virt[2]
            raw = self.lines[self.i]
            body = raw.lstrip(" ")
            probe = body.lstrip("\t ")
            if not probe or probe[0] == "#":
                self.i += 1
                continue
            if body[0] == "\t":
                self._fail("tab indentation is not supported")
            return len(raw) - len(body), body.rstrip(" \t")
        return None

    @staticmethod
    def _is_dash(content: str) -> bool:
        return content == "-" or content[:2] in ("- ", "-\t")

    def _plain_start(self, text: str) -> None:
        if text[0] in "&*!%@`|>,]}" or (text[0] in "?-:" and (len(text) == 1 or text[1] in " \t")):
            self._fail("unsupported YAML syntax (anchor, alias, tag, directive or complex key)")

    def _tail(self, rest: str) -> None:
        stripped = rest.lstrip(" \t")
        if stripped and (stripped[0] != "#" or len(stripped) == len(rest)):
            self._fail("unexpected content after a value")

    def _quoted(self, s: str, i: int) -> Tuple[str, int]:
        match = (_SINGLE if s[i] == "'" else _DOUBLE).match(s, i)
        if not match:
            self._fail("unterminated or multi-line quoted scalar")
        body = match.group()[1:-1]
        if s[i] == "'":
            return body.replace("''", "'"), match.end()

        def unescape(m):
            code = m.group(1)
            if len(code) > 1:
                try:
                    return chr(int(code[1:], 16))
                except ValueError:
                    self._fail("invalid escape")
            if code not in _ESCAPES:
                self._fail("unknown escape")
            return _ESCAPES[code]

        return _ESCAPE.sub(unescape, body), match.end()

    def _key(self, text: str) -> Any:
        if text == "<<":
            self._fail("merge keys are not supported")
        value = _plain(text)
        return value if isinstance(value, str) else ("odd", text)   # a key that is not text can never match a read tree

    def _split_key(self, content: str) -> Optional[Tuple[Any, str]]:
        if content[0] in "\"'":
            text, end = self._quoted(content, 0)
            end = _SPACES.match(content, end).end()
            if content[end:end + 1] == ":" and (end + 1 == len(content) or content[end + 1] in " \t"):
                return text, content[end + 1:]
            return None
        if content[0] in "[{":
            return None
        match = _COLON.search(content)
        if not match:
            return None
        raw = content[:match.start()]
        if not raw.strip(" \t"):
            self._fail("invalid mapping key")
        self._plain_start(raw)
        key = raw.rstrip(" \t")
        if not key or _COMMENT.search(key):
            self._fail("invalid mapping key")
        return self._key(key), content[match.end():]

    # -- scalars and flow collections (single line only)
    def _scalar(self, text: str, parent: int, depth: int) -> Any:
        """Reads a value that starts on the current line and consumes the line (and a block scalar's body)."""
        first = text[0]
        if first in "|>":
            match = _BLOCK.match(text)
            if not match:
                self._fail("invalid block scalar header")
            self._tail(text[match.end():])
            digit = re.search("[1-9]", match.group())
            self.i += 1
            self._skip_block_body(parent, int(digit.group()) if digit else 0)
            self._count()
            return _OPAQUE                       # content is never kept
        if first in "[{":
            value, end = self._flow(text, 0, depth)
            self._tail(text[end:])
        elif first in "\"'":
            value, end = self._quoted(text, 0)
            self._count()
            self._tail(text[end:])
        else:
            cut = _COMMENT.search(text)
            plain = (text[:cut.start()] if cut else text).rstrip(" \t")
            self._plain_start(plain)
            if _COLON.search(plain):
                self._fail("a plain scalar cannot contain ': '")
            self._count()
            value = _plain(plain)
        self.i += 1
        return value

    def _skip_block_body(self, parent: int, explicit: int) -> None:
        width = parent + explicit if explicit else None
        while self.i < len(self.lines):
            raw = self.lines[self.i]
            if raw.strip(" \t"):
                spaces = len(raw) - len(raw.lstrip(" "))
                if width is None:
                    if spaces <= parent:
                        return
                    width = spaces
                if spaces < width:
                    return
            self.i += 1

    def _flow(self, s: str, i: int, depth: int) -> Tuple[Any, int]:
        depth += 1
        if depth > MAX_DEPTH:
            self._fail("nested more than %d levels deep" % MAX_DEPTH)
        self._count()
        is_map = s[i] == "{"
        close = "}" if is_map else "]"
        out: Any = {} if is_map else []
        i = _SPACES.match(s, i + 1).end()
        if s[i:i + 1] == close:
            return out, i + 1
        while True:
            if is_map:
                key, i = self._flow_key(s, i)
                i = _SPACES.match(s, i).end()
                if s[i:i + 1] != ":":
                    self._fail("a flow mapping entry needs 'key: value'")
                i = _SPACES.match(s, i + 1).end()
                if s[i:i + 1] in (",", "}"):
                    value = None
                    self._count()
                else:
                    value, i = self._flow_value(s, i, depth)
                if key in out:
                    self._fail("duplicate key")
                out[key] = value
            else:
                value, i = self._flow_value(s, i, depth)
                out.append(value)
            i = _SPACES.match(s, i).end()
            char = s[i:i + 1]
            if char == ",":
                i = _SPACES.match(s, i + 1).end()
                if s[i:i + 1] == close:
                    self._fail("a trailing comma is not supported")
            elif char == close:
                return out, i + 1
            else:
                self._fail("unterminated or multi-line flow collection")

    def _flow_plain(self, s: str, i: int) -> Tuple[str, int]:
        end = _FLOW_PLAIN.match(s, i).end()
        text = s[i:end].rstrip(" \t")
        if not text:
            self._fail("an empty flow entry")
        self._plain_start(text)
        return text, end

    def _flow_key(self, s: str, i: int) -> Tuple[Any, int]:
        self._count()
        if s[i:i + 1] in ("[", "{"):
            self._fail("a collection cannot be a mapping key")
        if s[i:i + 1] in ("'", '"'):
            return self._quoted(s, i)
        text, end = self._flow_plain(s, i)
        return self._key(text), end

    def _flow_value(self, s: str, i: int, depth: int) -> Tuple[Any, int]:
        if s[i:i + 1] in ("[", "{"):
            return self._flow(s, i, depth)
        self._count()
        if s[i:i + 1] in ("'", '"'):
            return self._quoted(s, i)
        text, end = self._flow_plain(s, i)
        return _plain(text), end

    # -- block collections
    def _node(self, depth: int, scalar_parent: Optional[int] = None) -> Any:
        indent, content = self._peek()
        if self._is_dash(content):
            return self._seq(indent, depth)
        if self._split_key(content) is not None:
            return self._map(indent, depth)
        if scalar_parent is None:
            self._fail("expected a mapping or a sequence")
        return self._scalar(content, scalar_parent, depth)

    def _map(self, n: int, depth: int) -> Dict[Any, Any]:
        depth += 1
        if depth > MAX_DEPTH:
            self._fail("nested more than %d levels deep" % MAX_DEPTH)
        self._count()
        out: Dict[Any, Any] = {}
        while True:
            line = self._peek()
            if line is None or line[0] < n:
                return out
            if line[0] > n:
                self._fail("unexpected indentation")
            pair = None if self._is_dash(line[1]) else self._split_key(line[1])
            if pair is None:
                self._fail("expected 'key: value'")
            key, rest = pair
            if key in out:
                self._fail("duplicate key")
            self._count()
            rest = rest.lstrip(" \t")
            if not rest or rest[0] == "#":
                self.i += 1
                nxt = self._peek()
                if nxt and nxt[0] > n:
                    value = self._node(depth)
                elif nxt and nxt[0] == n and self._is_dash(nxt[1]):
                    value = self._seq(n, depth)                  # a sequence at the same indent as its key
                else:
                    value = None
                    self._count()
            else:
                value = self._scalar(rest, n, depth)
            out[key] = value

    def _seq(self, n: int, depth: int) -> List[Any]:
        depth += 1
        if depth > MAX_DEPTH:
            self._fail("nested more than %d levels deep" % MAX_DEPTH)
        self._count()
        out: List[Any] = []
        while True:
            line = self._peek()
            if line is None or line[0] < n:
                return out
            if line[0] > n:
                self._fail("unexpected indentation")
            if not self._is_dash(line[1]):
                return out
            after = line[1][1:]
            inline = after.lstrip(" \t")
            gap = after[:len(after) - len(inline)]
            if "\t" in gap:
                self._fail("tab indentation is not supported")
            if not inline or inline[0] == "#":
                self.i += 1
                nxt = self._peek()
                if nxt and nxt[0] > n:
                    out.append(self._node(depth))
                else:
                    out.append(None)
                    self._count()
            else:
                self.virt = (self.i, n + 1 + len(gap), inline)
                out.append(self._node(depth, scalar_parent=n))

    def parse(self) -> Any:
        if self._peek() is None:
            return _EMPTY
        value = self._node(0, scalar_parent=-1)
        if self._peek() is not None:
            self._fail("unexpected content")
        return value


def _yaml_documents(text: str) -> List[Any]:
    if _UNREADABLE.search(text):
        raise ManifestError("the text contains characters that YAML does not allow")
    segments, current, start = [], [], 0
    for number, line in enumerate(text.split("\n")):
        if _SEPARATOR.match(line):
            tail = line[3:].strip(" \t")
            if tail and tail[0] != "#":
                raise ManifestError("line %d: content after a document marker is not supported" % (number + 1))
            segments.append((start, current))
            current, start = [], number + 1
        else:
            current.append(line)
    segments.append((start, current))
    documents, nodes = [], 0
    for first, lines in segments:
        parser = _Parser(lines, first, nodes)
        value = parser.parse()
        nodes = parser.nodes
        if value is not _EMPTY:
            documents.append(value)
    return documents


# ---------------------------------------------------------------- JSON
def _json_pairs(pairs):
    out = {}
    for key, value in pairs:
        if key in out:
            raise ValueError("duplicate key")
        out[key] = value
    return out


def _json_float(text):
    value = float(text)
    if value - value != 0:
        raise ValueError("not finite")
    return value


def _json_document(text: str) -> Any:
    """Raises ValueError (or RecursionError) when text is not one acceptable JSON value."""
    def refuse(_):
        raise ValueError("not JSON")
    value = json.loads(text, object_pairs_hook=_json_pairs, parse_constant=refuse, parse_float=_json_float)
    nodes, stack = 0, [(value, 1)]
    while stack:                                  # iterative: the parser may have built a very deep value
        item, level = stack.pop()
        nodes += 1
        if nodes > MAX_NODES:
            raise ManifestError("more than %d JSON nodes" % MAX_NODES)
        if isinstance(item, (dict, list)):
            if level > MAX_DEPTH:
                raise ManifestError("nested more than %d levels deep" % MAX_DEPTH)
            for child in (list(item.keys()) + list(item.values())) if isinstance(item, dict) else item:
                stack.append((child, level + 1))
    return value


def _documents(text: str, as_json: bool) -> List[Any]:
    stripped = text.strip(" \t\n")
    if not stripped:
        return []
    if as_json or stripped[0] in "{[":
        try:
            return [_json_document(stripped)]
        except (ValueError, RecursionError):
            if as_json:
                raise ManifestError("the file is not valid JSON") from None
    return _yaml_documents(text)


# ---------------------------------------------------------------- credential check, cut, emit
_SURROGATE = re.compile("[\ud800-\udfff]")
_UNSAFE_IN_JSON = re.compile("[\x7f-\x9f  ￾￿]")   # YAML would read these as line breaks or refuse them


def _check_kept(value: Any) -> None:
    """Refuses what cannot be kept faithfully (iterative: the cut value is at most 64 levels deep, but never trust that)."""
    stack = [value]
    while stack:
        item = stack.pop()
        if isinstance(item, str):
            if _SURROGATE.search(item):
                raise ManifestError("a kept value is not valid text")
        elif isinstance(item, dict):
            if not all(isinstance(key, str) for key in item):
                raise ManifestError("a kept mapping has a key that is not text")
            stack.extend(item.keys())
            stack.extend(item.values())
        elif isinstance(item, list):
            stack.extend(item)
        elif item is _OPAQUE:
            raise ManifestError("a kept value uses YAML syntax that is not supported (a block scalar or an ambiguous plain scalar)")


def _cut(tree: Any, value: Any) -> Tuple[bool, Any]:
    """True keeps a whole value; a dict keeps only its keys; applied to a list it applies to every element (non-mappings drop out)."""
    if tree is True:
        return True, value
    if isinstance(tree, dict) and isinstance(value, dict):
        out = {}
        for key, sub in tree.items():
            if key in value:
                found, kept = _cut(sub, value[key])
                if found:
                    out[key] = kept
        return True, out
    if isinstance(tree, dict) and isinstance(value, list):
        return True, [kept for found, kept in (_cut(tree, element) for element in value) if found]
    return False, None


def _emit(kind: str, value: Any, secrets: Tuple[str, ...]) -> str:
    """JSON text of a cut document. A value that looks like a credential is refused, never altered or dropped."""
    _check_kept(value)
    kinds = find_credentials(value, secrets)
    if kinds:
        raise ManifestError("a %s document has a value that looks like a credential (%s); nothing was uploaded" % (kind, ", ".join(kinds)))
    text = json.dumps(value, ensure_ascii=False, sort_keys=True, allow_nan=False)
    return _UNSAFE_IN_JSON.sub(lambda m: "\\u%04x" % ord(m.group()), text)


def _check_trees(trees: Any) -> None:
    if not isinstance(trees, dict):
        raise ManifestError("the read trees must be a mapping")
    stack = [trees]
    while stack:
        node = stack.pop()
        for key, sub in node.items():
            if not isinstance(key, str) or not (sub is True or isinstance(sub, dict)):
                raise ManifestError("a read tree is malformed")
            if isinstance(sub, dict):
                stack.append(sub)


def _kind_of(item: Any) -> str:
    if not isinstance(item, dict):
        raise ManifestError("a document is not a mapping")
    kind = item.get("kind")
    if not isinstance(kind, str) or not kind:
        raise ManifestError("a document has no recognisable top-level kind")
    return kind


def _items(document: Any) -> List[Tuple[str, Any]]:
    kind = _kind_of(document)
    if kind != "List":
        return [(kind, document)]
    items = document.get("items")
    if not isinstance(items, list):
        raise ManifestError("a List document has no items list")
    return [(_kind_of(item), item) for item in items]


def _redact(text: Any, trees: Any, as_json: bool, secrets: Tuple[str, ...]) -> str:
    if not isinstance(text, str):
        raise ManifestError("manifest text must be a string")
    _check_trees(trees)
    if len(text) > 2 * MAX_FILE_BYTES:
        raise ManifestError("manifest text is too large")
    text = (text[1:] if text.startswith("﻿") else text).replace("\r\n", "\n").replace("\r", "\n")
    kept = []
    for document in _documents(text, as_json):
        if document is None:                          # YAML null (empty, null, ~): the server skips these too
            continue
        for kind, item in _items(document):
            if kind in trees:
                kept.append(_emit(kind, _cut(trees[kind], item)[1], secrets))
    return "\n---\n".join(kept) + "\n" if kept else ""


def redact_manifest(text: str, trees: Dict[str, Any], extra_secrets: Iterable[str] = ()) -> str:
    return _redact(text, trees, False, tuple(extra_secrets))


# ---------------------------------------------------------------- collection
def _patterns(patterns: Any) -> List[str]:
    try:
        items = [patterns] if isinstance(patterns, str) else list(patterns)
    except TypeError:
        raise ManifestError("manifest patterns must be a list of strings") from None
    for pattern in items:
        if not isinstance(pattern, str) or not pattern.strip() or "\0" in pattern:
            raise ManifestError("a manifest pattern must be a non-empty string")
        if "{" in pattern or "}" in pattern:
            raise ManifestError("brace patterns ({a,b}) are not supported; list one pattern per line")
        if pattern.startswith(("/", "\\")) or os.path.isabs(pattern):
            raise ManifestError("manifest patterns must be relative to the repository")
    return items


def _inside(root: str, real: str) -> bool:
    return real == root or real.startswith(root.rstrip(os.sep) + os.sep)


def _expand(patterns: List[str], base_dir: str) -> List[Tuple[str, str]]:
    """Returns (relative path, real path) sorted by relative path; every pattern must match a regular file inside base_dir."""
    root = os.path.realpath(base_dir)
    base = Path(base_dir)
    by_real: Dict[str, str] = {}
    for pattern in patterns:
        matched = 0
        try:
            for path in base.glob(pattern):
                real = os.path.realpath(str(path))
                if not os.path.isfile(real):
                    continue
                rel = Path(os.path.relpath(str(path), base_dir)).as_posix()
                if not _inside(root, real):
                    raise ManifestError("%s resolves to a path outside the repository" % rel)
                matched += 1
                if real not in by_real or rel < by_real[real]:
                    by_real[real] = rel
                if len(by_real) > MAX_FILES:
                    raise ManifestError("more than %d manifest files" % MAX_FILES)
        except (OSError, ValueError, NotImplementedError, RuntimeError, re.error):
            raise ManifestError("the manifest pattern '%s' cannot be searched" % pattern) from None
        if not matched:
            raise ManifestError("the manifest pattern '%s' matches no file" % pattern)
    return sorted((rel, real) for real, rel in by_real.items())


def _read(real: str, rel: str) -> str:
    try:
        info = os.stat(real)
        if not stat.S_ISREG(info.st_mode):
            raise ManifestError("not a regular file")
        if info.st_size > MAX_FILE_BYTES:
            raise ManifestError("larger than 1 MiB")
        with open(real, "rb") as handle:
            data = handle.read(MAX_FILE_BYTES + 1)
    except OSError:
        raise ManifestError("cannot be read") from None
    if len(data) > MAX_FILE_BYTES:
        raise ManifestError("larger than 1 MiB")
    try:
        return data.decode("utf-8")
    except UnicodeDecodeError:
        raise ManifestError("not valid UTF-8") from None


def collect_manifests(patterns: Iterable[str], base_dir: str, trees: Dict[str, Any], extra_secrets: Iterable[str] = ()) -> List[str]:
    _check_trees(trees)
    secrets = tuple(extra_secrets)
    wanted = _patterns(patterns)
    if not isinstance(base_dir, str) or not os.path.isdir(base_dir):
        raise ManifestError("the repository directory does not exist")
    out, total = [], 0
    for rel, real in _expand(wanted, base_dir):
        try:
            text = _redact(_read(real, rel), trees, rel.lower().endswith(".json"), secrets)
        except ManifestError as err:
            raise ManifestError("%s: %s" % (rel, err)) from None
        if text:
            total += len(text.encode("utf-8"))
            if total > MAX_TOTAL_BYTES:
                raise ManifestError("the manifest text to upload is larger than 2 MiB")
            out.append(text)
    return out
