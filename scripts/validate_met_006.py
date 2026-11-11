#!/usr/bin/env python3
"""Validate MET-006 (SERVICE-EDGES-001, K = 0): V1 this packet's files by digest; E1 the service-edge record passes its checker; E2 the catalog, the graph and both catalog schemas unchanged; E3 the errata carries at their named lines; V4 the registry rider; V6 the hunk-class record under v2.4."""
from __future__ import annotations

import ast
import base64
import binascii
import builtins
import copy
import difflib
import hashlib
import json
import stat
import types
from functools import lru_cache
from pathlib import Path
from types import MappingProxyType
from typing import Any

try:
    from safe_yaml import safe_load
except ImportError:
    from scripts.safe_yaml import safe_load


ROOT = Path(__file__).resolve().parents[1]
AUTHORITY_PATH = "architecture/service-edges-authority.json"
AUTHORITY_SHA256 = "6a96655db3a98b932697f3cd9557378522ebd6a97078e0377a107f19bc1e31b8"
VALIDATOR_PATH = "scripts/validate_met_006.py"
BASE_COMMIT = "d69848cf015e7328127c1369a4c999cb50b8a861"
NEW_PACKET = "MET-006"
PREVIOUS_PACKET = "MET-PERF-049"
MAX_FILE_BYTES = 16_777_216
# Test routes cover the top-level ci/test_ files as well as tests/.
TEST_PREFIXES = ("tests/", "ci/test_")


def require(ok: bool, message: str) -> None:
    if not ok:
        raise ValueError(message)


def digest(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def canonical(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, ensure_ascii=False,
                      separators=(",", ":"), allow_nan=False).encode("utf-8")


def parse(raw: bytes) -> Any:
    def unique(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            require(key not in result, "duplicate service-edges authority member")
            result[key] = value
        return result

    def no_constant(_value: str) -> Any:
        raise ValueError("nonfinite service-edges authority number")

    return json.loads(raw, object_pairs_hook=unique, parse_constant=no_constant)


def _path(path: Any) -> None:
    require(type(path) is str and bool(path) and not path.startswith("/")
            and "\\" not in path and not any(ord(char) < 32 for char in path)
            and all(part not in ("", ".", "..") for part in path.split("/")),
            "relative source path")


def regular_bytes(path: str) -> bytes:
    _path(path)
    parent = ROOT
    for part in path.split("/")[:-1]:
        parent /= part
        require(stat.S_ISDIR(parent.lstat().st_mode), "linked source ancestor")
    target = parent / path.split("/")[-1]
    before = target.lstat()
    require(stat.S_ISREG(before.st_mode) and before.st_nlink == 1
            and before.st_size <= MAX_FILE_BYTES, "bounded regular source file")
    raw = target.read_bytes()
    after = target.lstat()
    identity = lambda row: (row.st_dev, row.st_ino, row.st_mode, row.st_nlink,
                            row.st_size, row.st_mtime_ns, row.st_ctime_ns)
    require(identity(before) == identity(after) and len(raw) == before.st_size,
            "source changed during read")
    return raw


# Exact bytes most recently proven to hash to the pin. Every call still reads
# the complete file; byte-identical input implies the identical digest, while
# any other bytes or pin are hashed in full before they are accepted.
_VERIFIED_AUTHORITY: tuple[str, bytes] | None = None


def _checked_authority_raw() -> bytes:
    global _VERIFIED_AUTHORITY
    raw = regular_bytes(AUTHORITY_PATH)
    if type(raw) is not bytes or _VERIFIED_AUTHORITY != (AUTHORITY_SHA256, raw):
        require(digest(raw) == AUTHORITY_SHA256, "service edges history authority digest")
        if type(raw) is bytes:
            _VERIFIED_AUTHORITY = (AUTHORITY_SHA256, raw)
    return raw


def fresh_authority() -> None:
    """Re-read the complete pinned authority without reparsing its JSON."""
    _checked_authority_raw()


def _sha(value: Any) -> bool:
    return type(value) is str and len(value) == 64 and all(c in "0123456789abcdef" for c in value)


def authority() -> dict[str, Any]:
    value = parse(_checked_authority_raw())
    require(type(value) is dict and set(value) == {
        "schemaVersion", "authorityPacket", "acceptedBase", "baselinePackets",
        "packetSha256", "changedFiles", "newFiles", "validatorNormalizedSha256",
    }, "closed service edges history authority")
    require(value["schemaVersion"] == "harness.planeon.ai/service-edges-authority/v1"
            and value["authorityPacket"] == NEW_PACKET
            and value["acceptedBase"] == BASE_COMMIT
            and type(value["baselinePackets"]) is dict
            and len(value["baselinePackets"]) == 297
            and NEW_PACKET not in value["baselinePackets"]
            and type(value["changedFiles"]) is dict
            and type(value["newFiles"]) is dict
            and _sha(value["packetSha256"])
            and _sha(value["validatorNormalizedSha256"]),
            "accepted 297-packet base")
    for name, expected in value["baselinePackets"].items():
        require(type(name) is str and name and "/" not in name
                and all(char in "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-" for char in name)
                and _sha(expected), "predecessor packet identity")
    for path, expected in value["newFiles"].items():
        _path(path)
        require(_sha(expected), "new source digest")
    for path in value["changedFiles"]:
        _path(path)
    special = {AUTHORITY_PATH, VALIDATOR_PATH, "task-packets/" + NEW_PACKET + ".yaml"}
    require(not (set(value["changedFiles"]) & set(value["newFiles"]))
            and not (special & (set(value["changedFiles"]) | set(value["newFiles"])))
            and all(not path.startswith("task-packets/") or path == "task-packets/README.md"
                    for path in set(value["changedFiles"]) | set(value["newFiles"])),
            "disjoint source routes and immutable predecessor packets")
    return value


def _base64(value: Any) -> bytes:
    require(type(value) is str, "inverse hunk encoding")
    try:
        raw = base64.b64decode(value, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise ValueError("inverse hunk encoding") from exc
    require(base64.b64encode(raw).decode("ascii") == value, "noncanonical inverse hunk")
    return raw


def _rules() -> MappingProxyType:
    changed = authority()["changedFiles"]
    frozen = {}
    for path, rule in changed.items():
        require(type(rule) is dict
                and set(rule) == {"beforeSha256", "afterSha256", "reverseHunks"}
                and _sha(rule["beforeSha256"]) and _sha(rule["afterSha256"])
                and rule["beforeSha256"] != rule["afterSha256"]
                and type(rule["reverseHunks"]) is list
                and 0 < len(rule["reverseHunks"]) <= 4096, "closed inverse route")
        hunks = []
        prior_at, prior_end, total = -1, 0, 0
        for hunk in rule["reverseHunks"]:
            require(type(hunk) is dict
                    and set(hunk) == {"at", "removeBase64", "insertBase64"}
                    and type(hunk["at"]) is int
                    and 0 <= hunk["at"] <= MAX_FILE_BYTES
                    and prior_at < hunk["at"] and hunk["at"] >= prior_end,
                    "ordered inverse hunk")
            removed, inserted = _base64(hunk["removeBase64"]), _base64(hunk["insertBase64"])
            require(removed != inserted, "effective inverse hunk")
            total += len(removed) + len(inserted)
            require(total <= MAX_FILE_BYTES and hunk["at"] + len(removed) <= MAX_FILE_BYTES,
                    "bounded inverse payload")
            hunks.append((hunk["at"], removed, inserted))
            prior_at, prior_end = hunk["at"], hunk["at"] + len(removed)
        frozen[path] = MappingProxyType({"beforeSha256": rule["beforeSha256"],
                                         "afterSha256": rule["afterSha256"],
                                         "reverseHunks": tuple(hunks)})
    return MappingProxyType(frozen)


_PROJECTION_RULES = _rules()


def _packet_byte_rules() -> MappingProxyType:
    record = authority()
    return MappingProxyType(dict(record["baselinePackets"],
                                 **{NEW_PACKET: record["packetSha256"]}))


_PACKET_BYTE_RULES = _packet_byte_rules()


def _new_packet_rule() -> tuple[str, str]:
    checksum = _PACKET_BYTE_RULES[NEW_PACKET]
    raw = regular_bytes("task-packets/" + NEW_PACKET + ".yaml")
    require(digest(raw) == checksum, "packet YAML drift: " + NEW_PACKET)
    return checksum, digest(canonical(safe_load(raw)))


_NEW_PACKET_RULE = _new_packet_rule()


@lru_cache(maxsize=1)
def _packet_rules_for(source_root: Path, authority_sha: str) -> MappingProxyType:
    """Freeze expected payload digests once per exact source-root/authority pin."""
    require(source_root == ROOT and authority_sha == AUTHORITY_SHA256,
            "packet source identity changed")
    _checked_authority_raw()
    own_raw = regular_bytes("task-packets/" + NEW_PACKET + ".yaml")
    require(digest(own_raw) == _NEW_PACKET_RULE[0],
            "packet YAML drift: " + NEW_PACKET)
    rules = {NEW_PACKET: _NEW_PACKET_RULE}
    for name, checksum in _PACKET_BYTE_RULES.items():
        if name == NEW_PACKET:
            continue
        raw = regular_bytes("task-packets/" + name + ".yaml")
        require(digest(raw) == checksum, "packet YAML drift: " + name)
        rules[name] = (checksum, digest(canonical(safe_load(raw))))
    return MappingProxyType(rules)


def _packet_rules() -> MappingProxyType:
    return _packet_rules_for(ROOT, AUTHORITY_SHA256)


# Only expected parsed-data digests are cached, never a validation verdict.
# Historical traversal checks just this layer's packet. Full payload validation
# hashes every supplied packet anew, and validate() rereads every on-disk YAML.


def _inverse(raw: bytes, hunks: tuple[tuple[int, bytes, bytes], ...]) -> bytes:
    cursor, chunks = 0, []
    for at, removed, inserted in hunks:
        require(type(at) is int and cursor <= at and at + len(removed) <= len(raw),
                "inverse hunk bounds")
        require(raw[at:at + len(removed)] == removed, "inverse hunk current bytes")
        chunks.extend((raw[cursor:at], inserted))
        cursor = at + len(removed)
    chunks.append(raw[cursor:])
    before = b"".join(chunks)
    require(len(before) <= MAX_FILE_BYTES, "bounded predecessor bytes")
    return before


def historical_bytes(path: str, raw: bytes) -> bytes:
    """Recheck the pinned authority and undo only this reviewed successor."""
    _checked_authority_raw()
    _path(path)
    require(type(raw) is bytes and len(raw) <= MAX_FILE_BYTES, "bounded source bytes required")
    return _undo_this_layer(path, raw)


def _undo_this_layer(path: str, raw: bytes) -> bytes:
    """Apply only this layer's reviewed inverse; callers have already rechecked authorities."""
    rule = _PROJECTION_RULES.get(path)
    if rule is None:
        return raw
    current_sha = digest(raw)
    require(current_sha in (rule["beforeSha256"], rule["afterSha256"]),
            "unreviewed current source: " + path)
    if current_sha == rule["beforeSha256"]:
        return raw
    before = _inverse(raw, rule["reverseHunks"])
    require(digest(before) == rule["beforeSha256"], "predecessor bytes: " + path)
    return before


def historical_test_bytes(raw: bytes) -> bytes:
    _checked_authority_raw()
    require(type(raw) is bytes and len(raw) <= MAX_FILE_BYTES, "bounded test bytes required")
    current_sha = digest(raw)
    matches = [path for path, rule in _PROJECTION_RULES.items()
               if path.startswith(TEST_PREFIXES) and current_sha == rule["afterSha256"]]
    require(len(matches) <= 1, "ambiguous current test")
    return _undo_this_layer(matches[0], raw) if matches else raw


def current_test_bytes(before: bytes) -> bytes:
    _checked_authority_raw()
    require(type(before) is bytes and len(before) <= MAX_FILE_BYTES, "bounded test bytes required")
    before_sha = digest(before)
    matches = [path for path, rule in _PROJECTION_RULES.items()
               if path.startswith(TEST_PREFIXES) and before_sha == rule["beforeSha256"]]
    require(len(matches) <= 1, "ambiguous predecessor test")
    if not matches:
        return before
    current = regular_bytes(matches[0])
    require(digest(current) == _PROJECTION_RULES[matches[0]]["afterSha256"],
            "current test drift")
    return current


def historical_catalog(packets: dict[str, Any]) -> dict[str, Any]:
    """Remove only this layer, leaving predecessor checks to their owners."""
    _checked_authority_raw()
    require(type(packets) is dict, "packet mapping")
    current_ids = set(_PACKET_BYTE_RULES)
    require(NEW_PACKET in current_ids and set(packets) == current_ids,
            "unexpected packet addition or loss")
    packet_raw = regular_bytes("task-packets/" + NEW_PACKET + ".yaml")
    require(digest(packet_raw) == _NEW_PACKET_RULE[0],
            "packet YAML drift: " + NEW_PACKET)
    try:
        supplied_sha = digest(canonical(packets[NEW_PACKET]))
    except (TypeError, ValueError, RecursionError) as exc:
        raise ValueError("changed packet payload: " + NEW_PACKET) from exc
    require(supplied_sha == _NEW_PACKET_RULE[1],
            "changed packet payload: " + NEW_PACKET)
    return {name: packets[name] for name in current_ids - {NEW_PACKET}}


def validate_packet_payloads(packets: dict[str, Any]) -> None:
    """Check all current payloads separately from the inherited traversal."""
    record = authority()
    rules = _packet_rules()
    require(type(packets) is dict, "packet mapping")
    old = set(record["baselinePackets"])
    require(set(packets) == old | {NEW_PACKET}, "unexpected packet addition or loss")
    require(set(rules) == old | {NEW_PACKET}
            and all(rules[name][0] == expected
                    for name, expected in record["baselinePackets"].items())
            and rules[NEW_PACKET][0] == record["packetSha256"],
            "pinned packet data inventory")
    for name, (_byte_sha, payload_sha) in rules.items():
        try:
            supplied_sha = digest(canonical(packets[name]))
        except (TypeError, ValueError, RecursionError) as exc:
            raise ValueError("changed packet payload: " + name) from exc
        require(supplied_sha == payload_sha, "changed packet payload: " + name)


# MET-006 (SERVICE-EDGES-001; the lane monitor's owner-delegated rulings MON-287-RULINGS, MON-287-CR3-AB,
# MON-287-AB-PROCEED, MON-287-CR4-RULINGS and MON-287-C1R-RULINGS) adds, in a K = 0 step, the service-edge record
# beside the catalog: architecture/service-edges.yaml with its schema, its checker scripts/validate_service_edges.py
# (SE-1 to SE-14) and its tests; the catalog, the graph and both catalog schemas stay byte-equal (Option B); and
# CONTRACT_286's errata 10-12 and the sector-catalog test's NAMING_RECORDS registration ride as authored edits at
# their named lines (048-D1 (b); MON-287-C2-RULINGS). Repository bytes are read
# only through reviewed_bytes; an era file is refused unless bound by digest on every read, a changed file by the
# authority's afterSha256. Each refusal is a pure check over the values read. Checked here (CONTRACT_287 rev 7
# section 6): V1 the packet's files; E1 the record passes its checker on this era's bytes (its counts included);
# E2 the catalog, the graph and both schemas equal their base bytes; E3 class-other hunks only on the four authored-edit
# files, at their named lines; V4 the registry rider; V6 the hunk-class record under v2.4. Last, this layer's own
# inverse hunks are the canonical ones.
PACKET_FILES = ('architecture/service-edges.yaml', 'architecture/service-edges/schema.json', 'scripts/validate_service_edges.py', 'tests/test_service_edges.py')
BASE_FILES = ('architecture/services.yaml', 'architecture/dependency-graph.yaml', 'schemas/services.schema.json', 'schemas/dependency-graph.schema.json')
REGISTRY_BASE_SHA256 = "7e9aed93d8d811ddcd8f3fe27b35ae0d9e2eede333e858ab6354b013e94931ca"
BASE_SHA256 = MappingProxyType({
    "architecture/services.yaml": "857376b5e2b10a2a2542124a7d36b770eca531d15e463d68415416b887dd90a6",
    "architecture/dependency-graph.yaml": "47986eff1832f2ed990bb9ceb2cd9aab574475df0bc20f2a39ac91c985cfd50f",
    "schemas/services.schema.json": "7aa4eedb210650120496ea5858cbde3067dfa7d9c3b5b54bf39e3655f4010f0a",
    "schemas/dependency-graph.schema.json": "9c6f18bcc26e2b574297ba3e50d2e440f67f9bb78b3b5b7cfffa179c7141c870",
})
ERA_SHA256 = MappingProxyType({
    "architecture/dependency-graph.yaml": "47986eff1832f2ed990bb9ceb2cd9aab574475df0bc20f2a39ac91c985cfd50f",
    "architecture/review-briefs/REVIEW_BRIEF_PACKET.md": "6dcff68d7e6b01823f1740063e94910edcc159a71a6ee803f1b66c62fd06e274",
    "architecture/review-record/briefs.json": "54e34e982e54f8464e886e0808bc3e20b11deef21f07b8f4b616efc4d2e1262c",
    "architecture/service-edges.yaml": "20a4b631c54dd8dbe72930b85893b0f57dbd743c7f8dc2a01298796f374444a6",
    "architecture/service-edges/schema.json": "26b2619acc3bc93000414b2643d3bd96c62fc10fa29948036502ac10a7d5dfb2",
    "architecture/services.yaml": "857376b5e2b10a2a2542124a7d36b770eca531d15e463d68415416b887dd90a6",
    "ci/chain_checkpoint.py": "9d5d2a367df20f80675724cec63f09a2f4d2feba0c43f21fc9ce5d685d828eea",
    "docs/MICROSERVICE_CATALOG.md": "699f2c0fe3ae9d95d3e6d4261d51a95199e13f17d28ffef4a2d71a8c307e8eff",
    "docs/harnesses/runtime.ai-gateway.md": "797b6fd2a10c49a17d9063d7a13654da9c3d2ea2edd665a3cd39c3d5bb18b2ea",
    "docs/harnesses/trust.observability-finops.md": "25e0be5e61350cf1ab00ab3abd654b678d4d48bed8dfad8d3d0e1fe5efe09aee",
    "schemas/dependency-graph.schema.json": "9c6f18bcc26e2b574297ba3e50d2e440f67f9bb78b3b5b7cfffa179c7141c870",
    "schemas/services.schema.json": "7aa4eedb210650120496ea5858cbde3067dfa7d9c3b5b54bf39e3655f4010f0a",
    "scripts/validate_service_edges.py": "b2e564f27699ccfeec5e4ac23ff345c33ce4308f926fe88ea2c60f3d73acfa2b",
    "tests/test_service_edges.py": "85a542eca87aa1f32dda672b895d6acefb4e53b7c9e8a2d5b5a7663afe2407ac",
})
ERRATA_LINES = MappingProxyType({
    "architecture/chain-checkpoint/README.md": (184, 189),
    "docs/repositories/00-harness-engineering.md": (1618, 1618),
    "docs/MASTER_DEVELOPMENT_PLAN.md": (3331, 3331),
    "tests/test_sector_catalog.py": (837, 912),
})
REGISTRY_PATH = "architecture/review-record/briefs.json"
PACKET_BRIEF = "architecture/review-briefs/REVIEW_BRIEF_PACKET.md"
READER_PATH = "ci/chain_checkpoint.py"
RIDERS = (("PACKET", NEW_PACKET + "/packet", PACKET_BRIEF, 1),)


def reviewed_bytes(path: str) -> bytes:
    """This packet's reviewed bytes of path; a bridged successor projects newer bytes back first."""
    return regular_bytes(path)


def _era_bytes(path: Any, raw: Any) -> bytes:
    """An era file's bytes, checked against its era digest; a path outside the era is refused."""
    expected = ERA_SHA256.get(path) if type(path) is str else None
    require(expected is not None, "MET-006 reviewed bytes are bound: " + str(path))
    require(type(raw) is bytes and digest(raw) == expected, "unreviewed MET-006 source: " + path)
    return raw


def _verified(path: str) -> bytes:
    """reviewed_bytes, checked against its era digest on every read; a path outside the era is refused before it is
    read."""
    require(type(path) is str and path in ERA_SHA256, "MET-006 reviewed bytes are bound: " + str(path))
    return _era_bytes(path, reviewed_bytes(path))


def _bound_read(path: str, expected: Any) -> bytes:
    """reviewed_bytes of a file named by an era-verified record, checked against the digest that record gives it."""
    require(type(path) is str and _sha(expected), "MET-006 bound read: " + str(path))
    _path(path)
    raw = reviewed_bytes(path)
    require(type(raw) is bytes and digest(raw) == expected, "MET-006 bound file drift: " + path)
    return raw


def _parsed(raw: Any) -> Any:
    """raw as this layer's strict JSON, or None when it is not bytes holding such JSON."""
    try:
        return parse(raw) if type(raw) is bytes else None
    except ValueError:
        return None


def _holds(check: Any) -> bool:
    """A structural check over this era's data; a malformed value does not hold."""
    try:
        return check() is True
    except (KeyError, TypeError, AttributeError, IndexError, ValueError):
        return False


def _bound(check: Any, message: str) -> None:
    require(_holds(check), message)


def _era_model(path: str, name: str) -> types.ModuleType:
    """A reference module of this era, executed from its verified bytes (no import, no bytecode); it imports only the
    standard library."""
    module = types.ModuleType(name)
    module.__file__ = str(ROOT / path)
    exec(compile(_verified(path), path, "exec", dont_inherit=True), module.__dict__)
    return module


def check_registry(raw: Any, briefs: Any) -> None:
    """V4: the registry differs from the base by exactly this packet's one rider, appended last and pointing at the
    generic packet brief with the sha256 of the brief's bytes; nothing else in it changes."""
    registry = _parsed(raw)
    _bound(lambda: type(registry) is dict and type(registry["briefs"]) is list and type(briefs) is dict
           and all(type(briefs[rider[2]]) is bytes for rider in RIDERS)
           and [entry for entry in registry["briefs"] if entry["series"].startswith(NEW_PACKET + "/")]
           == registry["briefs"][-len(RIDERS):]
           == [{"kind": rider[0], "series": rider[1], "path": rider[2], "sha256": digest(briefs[rider[2]]),
                "version": rider[3]} for rider in RIDERS]
           and digest(canonical(dict(registry, briefs=[entry for entry in registry["briefs"]
                                                      if not entry["series"].startswith(NEW_PACKET + "/")])))
           == REGISTRY_BASE_SHA256,
           "the registry differs from the base by exactly the MET-006 packet rider, pinning the generic packet "
           "brief")


def validate_registry() -> None:
    """V4 over briefs.json and the generic packet brief."""
    check_registry(_verified(REGISTRY_PATH), {PACKET_BRIEF: _verified(PACKET_BRIEF)})


def check_packet_files(files: Any) -> None:
    """V1: the packet's files are exactly these, and each one's bytes equal the sha256 pinned for it."""
    _bound(lambda: type(files) is dict and sorted(files) == sorted(PACKET_FILES) and len(files) == len(PACKET_FILES),
           "MET-006 V1 the packet files are exactly the four")
    for path in PACKET_FILES:
        _bound(lambda: type(files[path]) is bytes and digest(files[path]) == ERA_SHA256[path],
               "MET-006 V1 a packet file's bytes equal its pinned digest: " + path)


def validate_packet_files() -> None:
    check_packet_files({path: _verified(path) for path in PACKET_FILES})


def _v24_source(path: str) -> bytes:
    """The reader's era-verified bytes with one alias line: its v2.4 copy answers as `classify` (the identity rule's
    attribute names hold `classify`, not `classify_v24`)."""
    return _verified(path) + b"\nclassify = classify_v24\n"


def _era_rule(path: str, name: str) -> types.ModuleType:
    """The reader's v2.4 rule as an era model, executed from its verified bytes plus the alias line (no import, no
    bytecode); it imports only the standard library."""
    module = types.ModuleType(name)
    module.__file__ = str(ROOT / path)
    exec(compile(_v24_source(path), path, "exec", dont_inherit=True), module.__dict__)
    return module


def _v24_context(record: Any, context: Any) -> dict:
    """v2.4's inputs from this step's authority and the record's context (the reader's context_v24 form): the catalog
    pair from the authority's baselinePackets size, then countPairs; no products (K = 0); the new tests from newFiles."""
    n = len(record["baselinePackets"])
    return {"prevValidator": context["prevValidator"], "prevTest": context["prevTest"], "newPacket": context["newPacket"],
            "products": [], "steps": context["steps"],
            "pairs": [[n, n + context["steps"][1]]] + [list(pair) for pair in context["countPairs"]],
            "newTests": [p for p in record["newFiles"] if p.startswith("tests/") and p.endswith(".py")]}


def check_hunk_record(raw: Any, changed: Any, afters: Any, classify: Any, context: Any, rule_sha: Any) -> None:
    """V6 under v2.4: the record's six closed members; it names this layer's authority; the closed vocabulary and v2.4's
    digest, which the reader's copy carries; the context is this step's names with countPairs; no outcome statement; one
    class per reverse hunk for exactly the changed files; and
    every class equals v2.4's class at its position."""
    record = _parsed(raw)
    _bound(lambda: type(record) is dict and set(record) == HUNK_RECORD_MEMBERS and record["authorityPath"] == AUTHORITY_PATH
           and record["outcomeStatements"] == [],
           "MET-006 V6 the hunk-class record is closed and names this layer's authority")
    _bound(lambda: record["hunkClassVocabulary"] == list(HUNK_VOCABULARY)
           and record["hunkClassRuleSha256"] == HUNK_RULE_SHA256 == rule_sha,
           "MET-006 V6 the hunk-class record's vocabulary and rule digest are v2.4's")
    _bound(lambda: type(record["hunkClassContext"]) is dict and set(record["hunkClassContext"]) == set(HUNK_CONTEXT)
           and record["hunkClassContext"] == {"newPacket": NEW_PACKET, "prevValidator": HUNK_CONTEXT["prevValidator"],
                                              "prevTest": HUNK_CONTEXT["prevTest"], "steps": [1, 1], "countPairs": [[313, 314]]},
           "MET-006 V6 the hunk-class record's context is this step's names")
    classes = record.get("classes") if type(record) is dict else None
    _bound(lambda: type(changed) is dict and type(classes) is dict and set(classes) == set(changed)
           and all(type(classes[p]) is list and all(type(c) is str for c in classes[p])
                   and len(classes[p]) == len(changed[p].get("reverseHunks", [])) for p in changed),
           "MET-006 V6 the hunk-class record lists one class per hunk for exactly the changed files")
    for path, entry in changed.items():
        seen = set()
        for position, (cls, hunk) in enumerate(zip(classes[path], entry.get("reverseHunks", []))):
            _bound(lambda: cls in HUNK_VOCABULARY and cls == classify(
                path, afters[path], hunk["at"], _base64(hunk["removeBase64"]), _base64(hunk["insertBase64"]), context,
                seen=seen),
                   "MET-006 V6 a recorded class re-checks by position: %s hunk %d" % (path, position))


def validate_hunk_record() -> None:
    """V6 over the hunk-class record (bound by its newFiles digest), the changed files (bound by their afterSha256) and
    the reader's copy of v2.4, executed from its era-verified bytes."""
    record = authority()
    raw = _bound_read(HUNK_RECORD_PATH, record["newFiles"].get(HUNK_RECORD_PATH))
    afters = {path: _bound_read(path, entry["afterSha256"]) for path, entry in record["changedFiles"].items()
              if "reverseHunks" in entry}
    rule = _era_rule(READER_PATH, READER_NAME)
    side = _parsed(raw)
    rule_sha = HUNK_RULE_SHA256 if _verified(READER_PATH).count(
        b'RULE_V24_SHA256 = "' + HUNK_RULE_SHA256.encode("ascii") + b'"') == 1 else None
    context = _v24_context(record, side["hunkClassContext"]) if _holds(
        lambda: _v24_context(record, side["hunkClassContext"]) is not None) else None
    check_hunk_record(raw, record["changedFiles"], afters, rule.classify, context, rule_sha)


CHECKER_PATH = "scripts/validate_service_edges.py"
CHECKER_NAME = "_met_006_service_edges"
HUNK_RECORD_PATH = "architecture/chain-checkpoint/hunk-classes/287.json"
READER_NAME = "_met_006_chain_checkpoint"
HUNK_RECORD_MEMBERS = frozenset({"authorityPath", "hunkClassVocabulary", "hunkClassRuleSha256", "hunkClassContext",
                                 "classes", "outcomeStatements"})
HUNK_VOCABULARY = ("bridge", "cascade", "other", "record", "register")     # chainmech v2.4 keeps v2.3's vocabulary
NORMALISED = ("bridge", "cascade", "record", "register")                   # the mechanics forms v2.4 normalises
HUNK_RULE_SHA256 = "8c61a0df32e396d52e3c3b2dc3cef416f3d9473b684b855a18ba357377dcc0c4"
HUNK_CONTEXT = MappingProxyType({"newPacket": NEW_PACKET, "prevValidator": "scripts/validate_met_perf_049.py",
                                 "prevTest": "tests/test_met_perf_049.py", "steps": (1, 1), "countPairs": ((313, 314),)})


def check_edges(refusals: Any) -> None:
    """E1: the service-edge record passes its checker on this era's bytes: no refusal under SE-1 to SE-14 (SE-14 is the
    checker's counts against the header's)."""
    _bound(lambda: type(refusals) is list and refusals == [],
           "MET-006 E1 the service-edge record passes its checker (SE-1 to SE-14)")


def validate_edges() -> None:
    """E1: the checker, executed from its era-verified bytes, reads only era-verified bytes."""
    checker = _era_model(CHECKER_PATH, CHECKER_NAME)
    check_edges(checker.check(ROOT, read=lambda path: _verified(path) if path in ERA_SHA256 else None))


def check_base_files(files: Any, changed: Any, new: Any) -> None:
    """E2 (Option B): the catalog, the graph and both catalog schemas equal their base bytes, and this step's authority
    names none of them."""
    _bound(lambda: type(files) is dict and sorted(files) == sorted(BASE_SHA256)
           and all(type(files[path]) is bytes and digest(files[path]) == BASE_SHA256[path] for path in BASE_SHA256),
           "MET-006 E2 the catalog, the graph and both schemas equal their base bytes")
    _bound(lambda: type(changed) is dict and type(new) is dict and not set(BASE_SHA256) & (set(changed) | set(new)),
           "MET-006 E2 this step changes none of the catalog, the graph or their schemas")


def validate_base_files() -> None:
    record = authority()
    check_base_files({path: _verified(path) for path in BASE_FILES}, record["changedFiles"], record["newFiles"])


def check_errata(classes: Any, changed: Any, befores: Any) -> None:
    """E3: class-other (authored) hunks fall only on the four authored-edit files; each carries one, and each such
    hunk lies inside its named base lines: placed in the before bytes by its offset plus the earlier hunks' shift, its
    before-text is there, and the base lines it spans are within the named range; every other hunk is a mechanics form
    v2.4 normalises."""
    _bound(lambda: type(classes) is dict and type(changed) is dict
           and all(cls in NORMALISED or (cls == "other" and path in ERRATA_LINES) for path in classes for cls in classes[path]),
           "MET-006 E3 class-other hunks fall only on the four authored-edit files")
    for path, (first, last) in ERRATA_LINES.items():
        _bound(lambda: "other" in classes[path] and type(befores[path]) is bytes,
               "MET-006 E3 the errata file carries its authored hunk: " + path)
        before, shift = befores[path], 0
        for position, (cls, hunk) in enumerate(zip(classes[path], changed[path]["reverseHunks"])):
            removed, inserted = _base64(hunk["removeBase64"]), _base64(hunk["insertBase64"])
            at = hunk["at"] + shift
            shift += len(inserted) - len(removed)
            if cls == "other":
                start = before[:at].count(b"\n") + 1
                end = start + inserted[:-1].count(b"\n")
                _bound(lambda: before[at:at + len(inserted)] == inserted and first <= start and end <= last,
                       "MET-006 E3 an authored hunk lies at its named lines: %s hunk %d" % (path, position))


def validate_errata() -> None:
    """E3 over the hunk-class record (bound by its newFiles digest) and each errata file's before bytes, projected back
    through this layer's own hunks from its afterSha256-bound bytes."""
    record = authority()
    side = _parsed(_bound_read(HUNK_RECORD_PATH, record["newFiles"].get(HUNK_RECORD_PATH)))
    befores = {path: _undo_this_layer(path, _bound_read(path, record["changedFiles"][path]["afterSha256"]))
               for path in ERRATA_LINES if path in record["changedFiles"]}
    check_errata(side.get("classes") if type(side) is dict else None, record["changedFiles"], befores)


def validate_met_006(packets: dict[str, Any]) -> None:
    """Every era file first; then V1, E1 (the checker), E2 (the base files), E3 (the errata carries), V4 (the registry)
    and V6 (the hunk-class record); last, this layer's canonical hunks."""
    for path in ERA_SHA256:
        _verified(path)
    validate_packet_files()
    validate_edges()
    validate_base_files()
    validate_errata()
    validate_registry()
    validate_hunk_record()
    validate_canonical_hunks()


def _trim(at: int, removed: bytes, inserted: bytes) -> tuple[int, bytes, bytes]:
    head = 0
    while head < min(len(removed), len(inserted)) and removed[head] == inserted[head]:
        head += 1
    tail = 0
    while (tail < min(len(removed), len(inserted)) - head
           and removed[len(removed) - 1 - tail] == inserted[len(inserted) - 1 - tail]):
        tail += 1
    return at + head, removed[head:len(removed) - tail], inserted[head:len(inserted) - tail]


def canonical_hunks(after: bytes, before: bytes) -> tuple[tuple[int, bytes, bytes], ...]:
    """The canonical byte-minimal reverse hunks (record authorityHunks.algorithm) that turn after back into before."""
    current, previous = after.splitlines(keepends=True), before.splitlines(keepends=True)
    offsets = [0]
    for line in current:
        offsets.append(offsets[-1] + len(line))
    runs = []
    for tag, a, b, c, d in difflib.SequenceMatcher(None, current, previous, autojunk=False).get_opcodes():
        if tag == "equal":
            continue
        if b - a == d - c:
            runs += [_trim(offsets[a + i], current[a + i], previous[c + i]) for i in range(b - a)
                     if current[a + i] != previous[c + i]]
        else:
            runs.append(_trim(offsets[a], b"".join(current[a:b]), b"".join(previous[c:d])))
    merged: list[tuple[int, bytes, bytes]] = []
    for at, removed, inserted in runs:
        if merged and at <= merged[-1][0] + len(merged[-1][1]):
            prior_at, prior_removed, prior_inserted = merged[-1]
            merged[-1] = (prior_at, after[prior_at:at + len(removed)],
                          prior_inserted + after[prior_at + len(prior_removed):at] + inserted)
        else:
            merged.append((at, removed, inserted))
    return tuple(merged)


def check_canonical_hunks(path: str, rule: Any, after: Any) -> None:
    """Q-PERF40-4 for one path: the rule's hunks are the canonical byte-minimal ones, from this era's bytes."""
    require(type(after) is bytes and digest(after) == rule["afterSha256"], "unreviewed current source: " + path)
    before = _undo_this_layer(path, after)
    require(canonical_hunks(after, before) == rule["reverseHunks"], "canonical byte-minimal inverse hunks: " + path)


def validate_canonical_hunks() -> None:
    """Q-PERF40-4: every hunk of this layer's authority is the canonical byte-minimal one, from this era's bytes."""
    for path, rule in _PROJECTION_RULES.items():
        check_canonical_hunks(path, rule, reviewed_bytes(path))


def validate() -> None:
    record = authority()
    validator_raw = regular_bytes(VALIDATOR_PATH)
    literal = b'AUTHORITY_SHA256 = "' + AUTHORITY_SHA256.encode("ascii") + b'"'
    placeholder = b'AUTHORITY_SHA256 = "TO_BE_PINNED_AFTER_SOURCE_FREEZE"'
    require(validator_raw.count(literal) == 1
            and digest(validator_raw.replace(literal, placeholder))
            == record["validatorNormalizedSha256"], "service edges validator drift")
    paths = sorted((ROOT / "task-packets").glob("*.yaml"))
    old = set(record["baselinePackets"])
    require(len(paths) == 298 and {path.stem for path in paths} == old | {NEW_PACKET},
            "closed 298-packet catalog")
    packets = {}
    for path in paths:
        raw = regular_bytes("task-packets/" + path.name)
        expected = (record["packetSha256"] if path.stem == NEW_PACKET
                    else record["baselinePackets"][path.stem])
        require(digest(raw) == expected, "packet YAML drift: " + path.stem)
        packets[path.stem] = safe_load(raw)
    validate_packet_payloads(packets)
    packet = packets[NEW_PACKET]
    previous = packets[PREVIOUS_PACKET]
    commands = packet["offlineAcceptanceCommands"]
    require(packet["id"] == NEW_PACKET and packet["repository"] == "Harness-Engineering"
            and packet["predecessors"] == [PREVIOUS_PACKET]
            and packet["warmSourceAccess"] == "PROHIBITED_DURING_IMPLEMENTATION"
            and packet["sourceReuse"] == packet["prefetchCommands"] == []
            and packet["offlineExecution"] == previous["offlineExecution"]
            and "liveCampaignExecution" not in packet
            and len(commands) == 64
            and commands == previous["offlineAcceptanceCommands"]
            and not any(VALIDATOR_PATH in argv for argv in commands),
            "closed source-only service-edges packet and inherited commands")
    require(len(packet["allowedPaths"]) == len(set(packet["allowedPaths"]))
            and set(packet["allowedPaths"]) == set(record["changedFiles"])
            | set(record["newFiles"]) | {AUTHORITY_PATH, VALIDATOR_PATH,
                                         "task-packets/" + NEW_PACKET + ".yaml"},
            "unreviewed or omitted service-edges packet path")
    for path, rule in record["changedFiles"].items():
        current = regular_bytes(path)
        require(digest(current) == rule["afterSha256"]
                and digest(historical_bytes(path, current)) == rule["beforeSha256"],
                "unreviewed current source: " + path)
    for path, expected in record["newFiles"].items():
        require(digest(regular_bytes(path)) == expected, "new source drift: " + path)
    validate_met_006(packets)


if __name__ == "__main__":
    validate()
    print("Service edges valid: 298 current specifications at slot 287; exact 297-packet predecessor; contract reviewed.")
