#!/usr/bin/env python3
"""Evolution surface v1 (architecture/evolution-surface/, EVOLUTION-SURFACE-001): reference model, DATA_CHECK_ONLY.

One closed, versioned record says, at two levels, which roles may propose, generate, test, approve and activate each
artifact class: the product level (spec v1.0 P27 and P28: the four planes' roles and the evolvable and never-autonomous
artifact classes) and the programme level (Harness-Onion's own artifacts, by repository path, and its bridge records).

`check(record)` raises `Refused(code)` on the first rule the record breaks, in the order of CODES (whole-record passes),
and otherwise returns derived facts. `decide`, `resolve`, `pr_approvers`, `pr_activators`, `derive_gate_material`, `coverage`, `check_paths` and
`check_coverage` answer questions about a valid record. The model checks roles and paths only: that activated bytes equal
approved bytes, expiry and single use, independent evidence in an evaluation bundle, and audit are contract rules for the
consumers (MAS-RA-005, R09 and the lane monitor's merge check), listed as consumer cases in the vectors.

Standard library only.
"""
from __future__ import annotations

import fnmatch
import hashlib
import json
import math
import os
import re

SCHEMA = "planeon.internal.evolution-surface/v1"
OPS = ("propose", "generate", "test", "approve", "activate")
LEVELS = ("product", "programme")
KINDS = ("AGENT", "HUMAN", "SERVICE")
PLANES = ("Runtime", "Knowledge", "Execution", "Trust")
BINDINGS = ("CONTENT", "CHANGE")
CODES = ("SHAPE", "DUPLICATE_ID", "UNKNOWN_REFERENCE", "NEVER_AUTONOMOUS", "SELF_GOVERNANCE", "SEPARATION_OF_DUTIES",
         "TWO_PERSON", "ACTIVATION_WITHOUT_APPROVAL", "APPEND_ONLY", "INDEPENDENCE", "PATHS", "INDEPENDENT_EVIDENCE",
         "COVERAGE")
REASONS = ("NOT_LISTED", "NEVER_AUTONOMOUS", "SELF_GOVERNANCE", "SEPARATION_OF_DUTIES", "APPEND_ONLY", "INDEPENDENCE")
MAX_INT = 2 ** 53 - 1
# The schema's patterns, verbatim; `re.search` is how a draft 2020-12 validator applies them. END is the end of the
# input in both ECMA-262 and Python (a plain `$` would also match before a final newline in Python).
END = r"(?![\s\S])"
ROLE_ID = re.compile(r"^[A-Z][A-Z0-9_]{0,63}" + END)
SURFACE_ID = re.compile(r"^[a-z0-9][a-z0-9-]{0,63}" + END)
SEGMENT = re.compile(r"^(?!\.\.?" + END + r")[A-Za-z0-9_.-]{1,255}" + END)
FILE_PATH = re.compile(r"^(?!/)(?!(?:.*/)?\.\.?(?:/|" + END + r"))(?:[A-Za-z0-9_.-]+/)*[A-Za-z0-9_.-]+" + END)
DIR_PATH = re.compile(r"^(?!/)(?!(?:.*/)?\.\.?(?:/|" + END + r"))(?:[A-Za-z0-9_.-]+/)+" + END)
NAME_PATTERN = re.compile(r"^[A-Za-z0-9_.*?\[\]-]{1,128}" + END)


class Refused(ValueError):
    """A record (or a request about it) breaks a rule; `code` is one of CODES."""

    def __init__(self, code: str):
        super().__init__(code)
        self.code = code


def _refuse(ok: bool, code: str) -> None:
    if not ok:
        raise Refused(code)


# ---------------------------------------------------------------- canonical form and text (as MAS-RA-001 to -004)

def _integral(value) -> bool:
    if type(value) is int:
        return abs(value) <= MAX_INT
    return type(value) is float and math.isfinite(value) and value.is_integer() and abs(value) <= MAX_INT


def _normal(value):
    if type(value) is float:
        _refuse(_integral(value), "SHAPE")
        return int(value)
    if type(value) is list:
        return [_normal(v) for v in value]
    if type(value) is dict:
        return {k: _normal(v) for k, v in value.items()}
    return value


def _jcs(value) -> str:
    if type(value) is dict:
        # RFC 8785 section 3.2.3: member names are compared as arrays of UTF-16 code units (big-endian bytes compare
        # the same way); a plain code-point sort differs once names mix characters above U+FFFF with U+E000-U+FFFF.
        items = sorted(value.items(), key=lambda item: item[0].encode("utf-16-be", "surrogatepass"))
        return "{" + ",".join(json.dumps(k, ensure_ascii=False) + ":" + _jcs(v) for k, v in items) + "}"
    if type(value) is list:
        return "[" + ",".join(_jcs(v) for v in value) + "]"
    return json.dumps(value, ensure_ascii=False, allow_nan=False)


def canonical(value) -> bytes:
    """RFC 8785 (JCS) bytes of a record: member names sorted by UTF-16 code units, no whitespace, UTF-8, integers
    without a fraction."""
    return _jcs(_normal(value)).encode("utf-8")


def digest(value) -> str:
    return "sha256:" + hashlib.sha256(canonical(value)).hexdigest()


def _no_constant(name):
    raise Refused("SHAPE")


def _members(pairs):
    names = [name for name, _ in pairs]
    _refuse(len(names) == len(set(names)), "SHAPE")
    return dict(pairs)


def _encodable(value) -> None:
    stack = [value]
    while stack:
        item = stack.pop()
        if type(item) is str:
            item.encode("utf-8")
        elif type(item) is list:
            stack.extend(item)
        elif type(item) is dict:
            stack.extend(item)
            stack.extend(item.values())


def load(text):
    """Record text as I-JSON (RFC 7493): UTF-8, no duplicate member names, no NaN or infinity, no lone surrogate (also not
    escaped); anything else is SHAPE. Returns the parsed value; `check` judges it."""
    try:
        if isinstance(text, (bytes, bytearray)):
            text = bytes(text).decode("utf-8")
        text.encode("utf-8")
        value = json.loads(text, object_pairs_hook=_members, parse_constant=_no_constant)
        _encodable(value)
        return value
    except Refused:
        raise
    except (ValueError, TypeError, RecursionError) as exc:
        raise Refused("SHAPE") from exc


# ---------------------------------------------------------------- shape (the schema's rules, mirrored)

def _str(value, pattern) -> bool:
    return type(value) is str and pattern.search(value) is not None


def _text(value) -> bool:
    return type(value) is str and 1 <= len(value) <= 2000


def _closed(value, required, optional=()) -> bool:
    return type(value) is dict and set(required) <= set(value) <= set(required) | set(optional)


def _unique(items) -> bool:
    seen = []
    for item in items:
        if item in seen:
            return False
        seen.append(item)
    return True


def _role_list(value, low=0) -> bool:
    return (type(value) is list and low <= len(value) <= 64 and all(_str(v, ROLE_ID) for v in value)
            and _unique(value))


def _bool(value) -> bool:
    return type(value) is bool


def _path_entry(e) -> bool:
    if _closed(e, ("exact",)):
        return _str(e["exact"], FILE_PATH) and len(e["exact"]) <= 4096
    if _closed(e, ("prefix",)):
        return _str(e["prefix"], DIR_PATH) and len(e["prefix"]) <= 4096
    if _closed(e, ("under", "name")):
        return _str(e["under"], DIR_PATH) and len(e["under"]) <= 4096 and _str(e["name"], NAME_PATTERN)
    return False


def _class_shape(c, level: str) -> bool:
    required = ("id", "description", "neverAutonomous", "appendOnly", "twoPerson", "approvalBinding", "governs",
                "independentOf", "operations", "grounds")
    optional = ("paths",) if level == "programme" else ()
    if not _closed(c, required, optional):
        return False
    ops = c["operations"]
    binding_ok = c["approvalBinding"] == "CONTENT" if level == "product" else c["approvalBinding"] in BINDINGS
    return (_str(c["id"], ROLE_ID) and _text(c["description"]) and _bool(c["neverAutonomous"])
            and _bool(c["appendOnly"]) and _bool(c["twoPerson"]) and type(c["approvalBinding"]) is str and binding_ok
            and _role_list(c["governs"]) and _role_list(c["independentOf"])
            and _closed(ops, OPS) and all(_role_list(ops[op]) for op in OPS)
            and type(c["grounds"]) is list and 1 <= len(c["grounds"]) <= 16 and all(_text(g) for g in c["grounds"])
            and ("paths" not in c or (type(c["paths"]) is list and 1 <= len(c["paths"]) <= 256
                                      and all(_path_entry(e) for e in c["paths"])))
            and not (c["approvalBinding"] == "CHANGE" and "paths" in c))


def _role_shape(r, level: str) -> bool:
    if level == "product":
        if not _closed(r, ("id", "kind", "plane", "description")):
            return False
        if not (type(r["plane"]) is str and r["plane"] in PLANES):
            return False
    elif not _closed(r, ("id", "kind", "description")):
        return False
    return _str(r["id"], ROLE_ID) and type(r["kind"]) is str and r["kind"] in KINDS and _text(r["description"])


def _names(value, pattern) -> bool:
    return type(value) is list and len(value) <= 64 and all(_str(v, pattern) for v in value) and _unique(value)


def _shape(doc) -> bool:
    if not _closed(doc, ("schemaVersion", "surfaceId", "version", "operations", "levels")):
        return False
    if not (doc["schemaVersion"] == SCHEMA and type(doc["schemaVersion"]) is str and _str(doc["surfaceId"], SURFACE_ID)
            and _integral(doc["version"]) and 1 <= doc["version"] <= MAX_INT
            and type(doc["operations"]) is list and doc["operations"] == list(OPS)
            and all(type(o) is str for o in doc["operations"])):
        return False
    levels = doc["levels"]
    if not _closed(levels, LEVELS):
        return False
    product, programme = levels["product"], levels["programme"]
    if not (_closed(product, ("roles", "classes")) and _closed(programme, ("roles", "classes", "coverageSkip"))):
        return False
    for level, body in (("product", product), ("programme", programme)):
        if not (type(body["roles"]) is list and 1 <= len(body["roles"]) <= 64
                and all(_role_shape(r, level) for r in body["roles"])):
            return False
        if not (type(body["classes"]) is list and 1 <= len(body["classes"]) <= 256
                and all(_class_shape(c, level) for c in body["classes"])):
            return False
    skip = programme["coverageSkip"]
    return (_closed(skip, ("rootNames", "anyDepthDirectories", "anyDepthFilePatterns"))
            and _names(skip["rootNames"], SEGMENT) and _names(skip["anyDepthDirectories"], SEGMENT)
            and _names(skip["anyDepthFilePatterns"], NAME_PATTERN))


# ---------------------------------------------------------------- the invariants

def _level(doc, level):
    body = doc["levels"][level]
    return {r["id"]: r for r in body["roles"]}, {c["id"]: c for c in body["classes"]}


def _ops(c, op) -> set:
    return set(c["operations"][op])


def _related(classes, a: str, b: str) -> bool:
    return b in classes[a]["independentOf"] or a in classes[b]["independentOf"]


def _gate_prefixes(classes) -> set:
    return {e["prefix"] for c in classes.values() if _ops(c, "approve") == {"OWNER"}
            for e in c.get("paths", ()) if "prefix" in e}


def _invariants(doc) -> None:
    views = {level: _level(doc, level) for level in LEVELS}
    bodies = {level: doc["levels"][level] for level in LEVELS}
    # DUPLICATE_ID: role and class ids are unique within a level.
    for level in LEVELS:
        body = bodies[level]
        _refuse(len(views[level][0]) == len(body["roles"]) and len(views[level][1]) == len(body["classes"]),
                "DUPLICATE_ID")
    # UNKNOWN_REFERENCE: every listed role and every independentOf class exists within the same level.
    for level in LEVELS:
        roles, classes = views[level]
        for c in classes.values():
            listed = set(c["governs"]).union(*(c["operations"][op] for op in OPS))
            _refuse(listed <= set(roles) and set(c["independentOf"]) <= set(classes), "UNKNOWN_REFERENCE")
    passes = (
        # invariant 2: a never-autonomous class lists no AGENT role in approve or activate
        ("NEVER_AUTONOMOUS", lambda roles, classes, c: not c["neverAutonomous"]
         or all(roles[r]["kind"] != "AGENT" for r in _ops(c, "approve") | _ops(c, "activate"))),
        # invariant 3: no governed role approves
        ("SELF_GOVERNANCE", lambda roles, classes, c: not (set(c["governs"]) & _ops(c, "approve"))),
        # invariant 4: no AGENT or SERVICE role both generates or tests and approves
        ("SEPARATION_OF_DUTIES", lambda roles, classes, c: all(
            roles[r]["kind"] == "HUMAN" for r in _ops(c, "approve") & (_ops(c, "generate") | _ops(c, "test")))),
        # invariant 4: twoPerson exactly when a HUMAN role both generates or tests and approves
        ("TWO_PERSON", lambda roles, classes, c: c["twoPerson"] == any(
            roles[r]["kind"] == "HUMAN" for r in _ops(c, "approve") & (_ops(c, "generate") | _ops(c, "test")))),
        # invariant 5: activation needs approval
        ("ACTIVATION_WITHOUT_APPROVAL", lambda roles, classes, c: not c["operations"]["activate"]
         or bool(c["operations"]["approve"])),
        # invariant 6: an append-only class is neither approved nor activated
        ("APPEND_ONLY", lambda roles, classes, c: not c["appendOnly"]
         or not (c["operations"]["approve"] or c["operations"]["activate"])),
        # invariant 7: related classes have disjoint generate sets
        ("INDEPENDENCE", lambda roles, classes, c: all(
            not (_ops(c, "generate") & _ops(classes[k], "generate")) for k in c["independentOf"])),
    )
    for code, ok in passes:
        for level in LEVELS:
            roles, classes = views[level]
            for c in classes.values():
                _refuse(ok(roles, classes, c), code)
    # invariant 8: path entries are unique across the programme level; the under directories of every Gate class with
    # under-plus-name entries are exactly the prefix entries of the Gate classes; and every entry at or inside a Gate
    # prefix belongs to a Gate class, so no data entry can win a path the derived list names as gate material.
    classes = views["programme"][1]
    entries = [canonical(e) for c in classes.values() for e in c.get("paths", ())]
    _refuse(len(entries) == len(set(entries)), "PATHS")
    gate = _gate_prefixes(classes)
    for c in classes.values():
        is_gate = _ops(c, "approve") == {"OWNER"}
        unders = {e["under"] for e in c.get("paths", ()) if "under" in e}
        if unders and is_gate:
            _refuse(unders == gate, "PATHS")
        if not is_gate:
            for e in c.get("paths", ()):
                where = e.get("exact", e.get("prefix", e.get("under")))
                _refuse(not any(where.startswith(g) for g in gate), "PATHS")
    # invariant 10: a content-bound class with approvers lists a tester outside its generators
    for level in LEVELS:
        for c in views[level][1].values():
            if c["approvalBinding"] == "CONTENT" and c["operations"]["approve"]:
                _refuse(bool(_ops(c, "test") - _ops(c, "generate")), "INDEPENDENT_EVIDENCE")


def check(doc) -> dict:
    """Judge a record; raise Refused(code) on the first broken rule, else return its digest and derived facts."""
    try:
        _refuse(_shape(doc), "SHAPE")
        _invariants(doc)
        return {"digest": digest(doc), "gateMaterial": _derive(doc)}
    except Refused:
        raise
    except (KeyError, TypeError, AttributeError, IndexError, ValueError, UnicodeError, RecursionError) as exc:
        raise Refused("SHAPE") from exc


# ---------------------------------------------------------------- questions about a valid record

def decide(doc, level: str, role: str, cls: str, op: str) -> dict:
    """ALLOWED exactly when `role` is listed for `op` on `cls`; otherwise DENIED with every reason that applies."""
    check(doc)
    _refuse(all(type(x) is str for x in (level, role, cls, op)) and level in LEVELS and op in OPS, "UNKNOWN_REFERENCE")
    roles, classes = _level(doc, level)
    _refuse(role in roles and cls in classes, "UNKNOWN_REFERENCE")
    c = classes[cls]
    if role in c["operations"][op]:
        return {"decision": "ALLOWED", "reasons": []}
    found = {"NOT_LISTED"}
    kind = roles[role]["kind"]
    if c["neverAutonomous"] and kind == "AGENT" and op in ("approve", "activate"):
        found.add("NEVER_AUTONOMOUS")
    if op == "approve" and role in c["governs"]:
        found.add("SELF_GOVERNANCE")
    if op == "approve" and kind != "HUMAN" and role in _ops(c, "generate") | _ops(c, "test"):
        found.add("SEPARATION_OF_DUTIES")
    if c["appendOnly"] and op in ("approve", "activate"):
        found.add("APPEND_ONLY")
    if op == "generate" and any(role in _ops(classes[k], "generate") for k in classes
                                if k != cls and _related(classes, cls, k)):
        found.add("INDEPENDENCE")
    return {"decision": "DENIED", "reasons": [r for r in REASONS if r in found]}


def _path(path) -> bool:
    """A repository path to judge: relative POSIX, no empty, '.' or '..' segment, no NUL."""
    if type(path) is not str or not 1 <= len(path) <= 4096 or path.startswith("/") or "\x00" in path:
        return False
    return all(part not in ("", ".", "..") for part in path.split("/"))


def _matches(path: str, classes) -> list:
    """The class of the single most specific entry: exact; else the longest directory, an under-plus-name entry
    beating a prefix of equal length. Two entries at the same step give more than one class (ambiguous)."""
    name = path.rsplit("/", 1)[-1]
    found = [cid for cid, c in classes.items() for e in c.get("paths", ()) if e.get("exact") == path]
    if found:
        return found
    ranked = []
    for cid, c in classes.items():
        for e in c.get("paths", ()):
            if "under" in e and path.startswith(e["under"]) and fnmatch.fnmatchcase(name, e["name"]):
                ranked.append((len(e["under"]), 1, cid))
            elif "prefix" in e and path.startswith(e["prefix"]):
                ranked.append((len(e["prefix"]), 0, cid))
    if not ranked:
        return []
    best = max(ranked)[:2]
    return [cid for length, kind, cid in ranked if (length, kind) == best]


def resolve(doc, path) -> str | None:
    """The programme class a repository path falls in, or None (no class, or ambiguous)."""
    check(doc)
    _refuse(_path(path), "SHAPE")
    found = _matches(path, _level(doc, "programme")[1])
    return found[0] if len(found) == 1 else None


def _pr(doc, paths, op: str):
    check(doc)
    _refuse(type(paths) is list and all(_path(p) for p in paths), "SHAPE")
    if not paths:
        return None
    classes = _level(doc, "programme")[1]
    sets = []
    for p in paths:
        found = _matches(p, classes)
        if len(found) != 1:
            return None
        sets.append(_ops(classes[found[0]], op))
    common = set.intersection(*sets)
    return sorted(common) if common else None


def pr_approvers(doc, paths) -> list | None:
    """The roles that may approve a PR changing `paths` (added, modified, deleted, and both sides of a rename): the
    intersection of the classes' approve sets; None when there are no paths, a path falls in no class, or none remains."""
    return _pr(doc, paths, "approve")


def pr_activators(doc, paths) -> list | None:
    """As pr_approvers, for the activate sets."""
    return _pr(doc, paths, "activate")


def _derive(doc) -> list:
    classes = _level(doc, "programme")[1]
    gate = [e for c in classes.values() if _ops(c, "approve") == {"OWNER"} for e in c.get("paths", ())]
    prefixes = [e["prefix"] for e in gate if "prefix" in e]
    kept = [e for e in gate if "under" not in e or not any(e["under"].startswith(p) for p in prefixes)]
    return sorted(kept, key=canonical)


def derive_gate_material(doc) -> list:
    """Every path entry of the repository classes whose approve set is exactly {OWNER}; under-plus-name entries that
    lie inside a derived prefix add nothing and are left out. Sorted by canonical bytes."""
    check(doc)
    return _derive(doc)


def skipped(doc, path: str) -> bool:
    """Whether the coverage check skips `path`: its first component is a root name, a directory component is an
    any-depth directory, or its file name matches an any-depth pattern. Components, never string prefixes."""
    check(doc)
    _refuse(_path(path), "SHAPE")
    return _skipped(doc["levels"]["programme"]["coverageSkip"], path)


def _skipped(skip, path: str) -> bool:
    parts = path.split("/")
    return (parts[0] in skip["rootNames"] or any(p in skip["anyDepthDirectories"] for p in parts[:-1])
            or any(fnmatch.fnmatchcase(parts[-1], pattern) for pattern in skip["anyDepthFilePatterns"]))


def _walk_error(error) -> None:
    raise Refused("COVERAGE") from error


def tree_paths(doc, root) -> list:
    """Every file under `root` outside the record's skip set, as sorted relative POSIX paths. A symbolic link is listed
    by its own path and never followed. Fails closed: a root that is not an existing directory, or a directory that
    cannot be listed, is Refused('COVERAGE'). No git object is read."""
    check(doc)
    skip = doc["levels"]["programme"]["coverageSkip"]
    root = os.fspath(root)
    _refuse(os.path.isdir(root) and not os.path.islink(root), "COVERAGE")
    found = []
    for top, dirs, files in os.walk(root, onerror=_walk_error, followlinks=False):
        rel = os.path.relpath(top, root)
        rel = "" if rel == "." else rel.replace(os.sep, "/") + "/"
        keep = []
        for d in sorted(dirs):
            if (rel == "" and d in skip["rootNames"]) or d in skip["anyDepthDirectories"]:
                continue
            if os.path.islink(os.path.join(top, d)):
                files.append(d)
            else:
                keep.append(d)
        dirs[:] = keep
        for f in files:
            path = rel + f
            if not _skipped(skip, path):
                found.append(path)
    return sorted(found)


def _gate_link(doc, root: str, path: str) -> bool:
    """Whether `path` is a symbolic link whose own path is gate material, or whose final target lies in, or contains,
    gate material inside the tree (a data-only change to the target would change what a gate path serves)."""
    full = os.path.join(root, *path.split("/"))
    if not os.path.islink(full):
        return False
    classes = _level(doc, "programme")[1]
    gate = {cid for cid, c in classes.items() if _ops(c, "approve") == {"OWNER"}}
    if any(cid in gate for cid in _matches(path, classes)):
        return True
    rel = os.path.relpath(os.path.realpath(full), os.path.realpath(root))
    if rel == ".":
        return True
    if rel == ".." or rel.startswith(".." + os.sep):
        return False
    rel = rel.replace(os.sep, "/")
    if any(cid in gate for cid in _matches(rel, classes)):
        return True
    entries = [e.get("exact", e.get("prefix", e.get("under"))) for cid in gate for e in classes[cid].get("paths", ())]
    return any(entry.startswith(rel + "/") for entry in entries)


def coverage(doc, paths) -> dict:
    """Invariant 9's report for a list of file paths: unclassified, ambiguous and the count per class."""
    check(doc)
    _refuse(type(paths) is list and all(_path(p) for p in paths), "SHAPE")
    classes = _level(doc, "programme")[1]
    report = {"files": len(paths), "unclassified": [], "ambiguous": [], "perClass": {}}
    for p in sorted(paths):
        found = _matches(p, classes)
        if not found:
            report["unclassified"].append(p)
        elif len(found) > 1:
            report["ambiguous"].append(p)
        else:
            report["perClass"][found[0]] = report["perClass"].get(found[0], 0) + 1
    return report


def check_paths(doc, paths) -> dict:
    """Invariant 9 on a list of file paths: Refused('COVERAGE') unless every path falls in exactly one class."""
    report = coverage(doc, paths)
    _refuse(not report["unclassified"] and not report["ambiguous"], "COVERAGE")
    return report


def check_coverage(doc, root) -> dict:
    """Invariant 9 on a checked-out tree: Refused('COVERAGE') unless the walk succeeds, every file outside the skip set
    falls in exactly one class, and no symbolic link is gate material or reaches gate material."""
    root = os.fspath(root)
    paths = tree_paths(doc, root)
    report = check_paths(doc, paths)
    _refuse(not any(_gate_link(doc, root, p) for p in paths), "COVERAGE")
    return report


# ---------------------------------------------------------------- the vector runner

def mutate(doc, mutation: list):
    """A copy of `doc` with each step applied: {"path": [...], "value": v} sets, {"path": [...], "delete": true} removes.
    A path step is a key, a list index, or '#ID' (the list element whose id is ID)."""
    out = json.loads(json.dumps(doc))
    for step in mutation:
        node = out
        path = step["path"]
        for key in path[:-1]:
            node = _step(node, key)
        last = path[-1]
        if type(last) is str and last.startswith("#"):
            last = next(i for i, e in enumerate(node) if e.get("id") == last[1:])
        if step.get("delete"):
            del node[last]
        elif type(node) is list and last == len(node):
            node.append(step["value"])
        else:
            node[last] = step["value"]
    return out


def _step(node, key):
    if type(key) is str and key.startswith("#"):
        return next(e for e in node if e.get("id") == key[1:])
    return node[key]


class Mismatch(AssertionError):
    """A vector the model does not reach; raised explicitly, so `python -O` cannot skip the check."""


def _expect(ok: bool, what) -> None:
    if not ok:
        raise Mismatch(what)


REQUESTS = {"decide": decide, "resolve": resolve, "pr_approvers": pr_approvers, "pr_activators": pr_activators,
            "skipped": skipped, "check_paths": check_paths}


def replay(doc, vectors) -> dict:
    """Replay every vector against `doc` (the record whose digest the vectors pin); raise Mismatch on any difference."""
    _expect(vectors["codes"] == list(CODES) and vectors["reasons"] == list(REASONS), "codes and reasons")
    facts = check(doc)
    _expect(facts["digest"] == vectors["recordDigest"], "the vectors pin another record")
    for row in vectors["decisions"]:
        got = decide(doc, row["level"], row["role"], row["class"], row["op"])
        _expect(got == row["expect"], (row["id"], got))
    for row in vectors["invariants"]:
        try:
            check(mutate(doc, row["mutation"]))
            got = None
        except Refused as refusal:
            got = refusal.code
        _expect(got == row["expect"], (row["id"], got))
    for row in vectors["texts"]:
        try:
            check(load(row["text"]))
            got = None
        except Refused as refusal:
            got = refusal.code
        _expect(got == row["expect"], (row["id"], got))
    for row in vectors["paths"]:
        got = resolve(row.get("record", doc), row["path"])
        _expect(got == row["expect"], (row["id"], got))
    for row in vectors["skip"]:
        _expect(skipped(doc, row["path"]) == row["skipped"], row["id"])
    for row in vectors["prs"]:
        _expect(pr_approvers(doc, row["paths"]) == row["approvers"], (row["id"], "approvers"))
        _expect(pr_activators(doc, row["paths"]) == row["activators"], (row["id"], "activators"))
    for row in vectors["coverage"]:
        report = coverage(doc, row["files"])
        _expect({k: report[k] for k in ("unclassified", "ambiguous")} == row["expect"], (row["id"], report))
    for row in vectors["requests"]:
        try:
            REQUESTS[row["call"]](doc, *row["args"])
            got = None
        except Refused as refusal:
            got = refusal.code
        _expect(got == row["expect"], (row["id"], got))
    derivation = vectors["derivation"]
    derived = derive_gate_material(doc)
    accepted = [e for group in derivation["acceptedExtensions"] for e in group["entries"]]
    _expect(derived == derivation["derived"], "derived list")
    _expect(derived == sorted(derivation["paD5"] + accepted, key=canonical), "derived != PA-D5 + accepted extensions")
    _expect(derivation["difference"] == sorted(accepted, key=canonical), "difference")
    for row in vectors["consumerCases"]:
        _expect(set(row) == {"id", "grounds", "case", "expected"} and all(type(row[k]) is str for k in row), row)
    return {"decisions": len(vectors["decisions"]), "invariants": len(vectors["invariants"]),
            "texts": len(vectors["texts"]), "paths": len(vectors["paths"]), "skip": len(vectors["skip"]),
            "prs": len(vectors["prs"]), "coverage": len(vectors["coverage"]), "requests": len(vectors["requests"]),
            "derived": len(derived), "consumerCases": len(vectors["consumerCases"])}


if __name__ == "__main__":
    from pathlib import Path

    here = Path(__file__).resolve().parents[1] / "architecture/evolution-surface"
    record = load((here / "evolution-surface.json").read_bytes())
    counts = replay(record, json.loads((here / "vectors.json").read_bytes()))
    print("evolution surface vectors replay: " + ", ".join("%d %s" % (n, k) for k, n in counts.items()))
