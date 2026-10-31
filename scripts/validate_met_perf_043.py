#!/usr/bin/env python3
"""Validate MET-PERF-043 (END-only pytest diagnostics): ci/pytest_diagnostics.py writing version 2 records, one END per phase and no START, with every cap unchanged, its tests, its D5a oracle and the record architecture/diagnostic-end-only/ (V1-V5: the seven packet files, each equal to its adopted digest; the caps and their derived limits equal to the base module's by syntax tree, and the record version 2; the oracle identity binding the oracle's bytes; the registry's MET-PERF-043 packet rider as the one change from the base; and conftest.py, ci/parallel_suite.py and MET-PERF-041's record and authority unchanged since the base), and the exact 270-to-269 projection."""
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
    import validate_edge_record_v12 as successor
except ImportError:
    from scripts.safe_yaml import safe_load
    from scripts import validate_edge_record_v12 as successor


ROOT = Path(__file__).resolve().parents[1]
AUTHORITY_PATH = "architecture/met-perf-043-authority.json"
AUTHORITY_SHA256 = "6d11a9a751413de10af9f2ecedf89a66fa376e9c8e48e460a1fbdbf5b7ac820f"
VALIDATOR_PATH = "scripts/validate_met_perf_043.py"
BASE_COMMIT = "925debeeeaac6157bf5393148380ca01d30e7b58"
NEW_PACKET = "MET-PERF-043"
PREVIOUS_PACKET = "MET-GOV-005"
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
            require(key not in result, "duplicate END-only diagnostics authority member")
            result[key] = value
        return result

    def no_constant(_value: str) -> Any:
        raise ValueError("nonfinite END-only diagnostics authority number")

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
    """Newest first: every newer authority, then this one, each read exactly once."""
    successor._checked_authority_raw()
    return _checked_own_authority_raw()


def _checked_own_authority_raw() -> bytes:
    """Fresh complete read of this layer's authority only; callers reach newer
    authorities through exactly one successor route per public call."""
    global _VERIFIED_AUTHORITY
    raw = regular_bytes(AUTHORITY_PATH)
    if type(raw) is not bytes or _VERIFIED_AUTHORITY != (AUTHORITY_SHA256, raw):
        require(digest(raw) == AUTHORITY_SHA256, "END-only diagnostics history authority digest")
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
    }, "closed END-only diagnostics history authority")
    require(value["schemaVersion"] == "harness.planeon.ai/met-perf-043-authority/v1"
            and value["authorityPacket"] == NEW_PACKET
            and value["acceptedBase"] == BASE_COMMIT
            and type(value["baselinePackets"]) is dict
            and len(value["baselinePackets"]) == 269
            and NEW_PACKET not in value["baselinePackets"]
            and type(value["changedFiles"]) is dict
            and type(value["newFiles"]) is dict
            and _sha(value["packetSha256"])
            and _sha(value["validatorNormalizedSha256"]),
            "accepted 269-packet base")
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
    """Undo the newer successor, then this step; every authority is read once."""
    _path(path)
    require(type(raw) is bytes and len(raw) <= MAX_FILE_BYTES, "bounded source bytes required")
    rule = _PROJECTION_RULES.get(path)
    # An exact 269-era byte string is already older than the successor layer.
    # Every newer authority and this one are still rechecked before this fast return.
    if rule is not None and digest(raw) == rule["beforeSha256"]:
        _checked_authority_raw()
        return raw
    # The successor route freshly rechecks every newer authority exactly once.
    raw = successor.historical_bytes(path, raw)
    _checked_own_authority_raw()
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
    require(type(raw) is bytes and len(raw) <= MAX_FILE_BYTES, "bounded test bytes required")
    raw = successor.historical_test_bytes(raw)
    _checked_own_authority_raw()
    current_sha = digest(raw)
    matches = [path for path, rule in _PROJECTION_RULES.items()
               if path.startswith(TEST_PREFIXES) and current_sha == rule["afterSha256"]]
    require(len(matches) <= 1, "ambiguous current test")
    return _undo_this_layer(matches[0], raw) if matches else raw


def current_test_bytes(before: bytes) -> bytes:
    require(type(before) is bytes and len(before) <= MAX_FILE_BYTES, "bounded test bytes required")
    before_sha = digest(before)
    matches = [path for path, rule in _PROJECTION_RULES.items()
               if path.startswith(TEST_PREFIXES) and before_sha == rule["beforeSha256"]]
    require(len(matches) <= 1, "ambiguous predecessor test")
    if not matches:
        current = successor.current_test_bytes(before)
        _checked_own_authority_raw()
        return current
    current = successor.historical_bytes(matches[0], regular_bytes(matches[0]))
    _checked_own_authority_raw()
    require(digest(current) == _PROJECTION_RULES[matches[0]]["afterSha256"],
            "current test drift")
    return successor.current_test_bytes(current)


def historical_catalog(packets: dict[str, Any]) -> dict[str, Any]:
    """Remove only this layer, leaving predecessor checks to their owners."""
    packets = successor.historical_catalog(packets)
    _checked_own_authority_raw()
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


# MET-PERF-043 (owner decision Q-DIAG-CAP, "END-only, own PERF packet (Recommended)", with the slot order
# MON-SLOT-270-PERF; the lane monitor's rulings MON-P43-DR3, MON-P43-OR1-D1, MON-P43-CR1-KEEP, MON-P43-ORC-KEEP,
# MON-P43-ADOPT and MON-P43-MECH-GO) adopts slot 270's candidate c2: ci/pytest_diagnostics.py writes version 2 records,
# one END record per phase and no START record, with every cap unchanged; its tests tests/test_pytest_diagnostics.py and
# tests/test_diagnostic_repair.py follow it; the D5a oracle tests/test_met_perf_043_oracle.py is bound by
# architecture/oracle-identity-met-perf-043.json; and the record architecture/diagnostic-end-only/ (README.md and
# boundaries.json) states the measured boundaries and the residual R-P43-KILL. The packet's review series is registered by
# this packet's own rider in architecture/review-record/briefs.json (MET-PERF-043/packet). Repository bytes are read only
# through reviewed_bytes, so a later bridged successor projects its own edits away first; a path outside this era is
# refused before it is read, every era file is bound by digest on every read, and no directory is listed. Each refusal is
# a pure check over the values read, so every one has a failing case on plain data. Checked here: V1, the packet's files
# (exactly the seven, each equal to the sha256 of its adopted bytes, pinned below); V2, the caps unchanged (by the syntax
# tree of the module's reviewed bytes, never an import: PREFIX, MAX_RECORD_BYTES, MAX_PROCESS_BYTES, MAX_EVENTS,
# MAX_NODE_CHARS, MAX_FAILURES, PHASES, OUTCOMES, REASONS and the derived MAX_SCAN_BYTES and MAX_SCAN_LINES expressions
# are each bound once and equal the base module's, reached through this layer's own inverse and pinned by digest; and the
# record version literal is 2); V3, the oracle binding (the identity names the oracle test, its file.sha256 equals the
# oracle test's bytes and its ruling is KEEP; the oracle is hashed only); V4, the registry (it differs from the base by
# exactly the one rider, pointing at the generic packet brief with the sha256 of that brief's bytes); and V5, the
# untouched neighbours (conftest.py, ci/parallel_suite.py and MET-PERF-041's record and authority are unchanged since the
# base). No chain validator or chain test is pinned here, and no catalog file is named. Last, this layer's own inverse
# hunks are the canonical byte-minimal ones, recomputed from its era's bytes (MET-PERF-040's carried rule); through them
# MET-PERF-041's layer and every older one read their own era's module and tests.
DIAGNOSTICS = "ci/pytest_diagnostics.py"
DIAGNOSTICS_TEST = "tests/test_pytest_diagnostics.py"
REPAIR_TEST = "tests/test_diagnostic_repair.py"
ORACLE_TEST = "tests/test_met_perf_043_oracle.py"
ORACLE_IDENTITY = "architecture/oracle-identity-met-perf-043.json"
ORACLE_SCHEMA = "planeon.oracle-identity/v1"
RECORD_README = "architecture/diagnostic-end-only/README.md"
RECORD_BOUNDARIES = "architecture/diagnostic-end-only/boundaries.json"
REGISTRY_PATH = "architecture/review-record/briefs.json"
PACKET_BRIEF = "architecture/review-briefs/REVIEW_BRIEF_PACKET.md"
# V1: the packet's files, named by path; each is pinned below by the sha256 of its adopted bytes.
PACKET_FILES = (
    "ci/pytest_diagnostics.py",
    "tests/test_pytest_diagnostics.py",
    "tests/test_diagnostic_repair.py",
    "tests/test_met_perf_043_oracle.py",
    "architecture/oracle-identity-met-perf-043.json",
    "architecture/diagnostic-end-only/README.md",
    "architecture/diagnostic-end-only/boundaries.json",
)
# V2: the module's caps and their derived limits, by name; the base module (the bytes this layer's inverse gives) by
# digest; and the record version this packet writes.
CAP_NAMES = (
    "PREFIX",
    "MAX_RECORD_BYTES",
    "MAX_PROCESS_BYTES",
    "MAX_EVENTS",
    "MAX_NODE_CHARS",
    "MAX_SCAN_BYTES",
    "MAX_SCAN_LINES",
    "MAX_FAILURES",
    "PHASES",
    "OUTCOMES",
    "REASONS",
)
BASE_DIAGNOSTICS_SHA256 = "ac9e70395413356f6348180c0c61a7adec57999f770feed59967b6eac7167745"
RECORD_VERSION = 2
# V4: the registry at the base (the digest of its canonical JSON) and this packet's one rider (kind, series, path,
# version); the rider's sha256 is the generic packet brief's.
REGISTRY_BASE_SHA256 = "33177fd226f5ce53e7e014d04e58b6fce9f3ffcfc02cdc3c8d347361b334347e"
RIDERS = (("PACKET", NEW_PACKET + "/packet", PACKET_BRIEF, 1),)
# V5: the neighbours this packet leaves unchanged since the base, each pinned below by its base digest.
NEIGHBOURS = (
    "conftest.py",
    "ci/parallel_suite.py",
    "architecture/diagnostic-caps/README.md",
    "architecture/diagnostic-caps/limits.json",
    "architecture/diagnostic-caps-authority.json",
)
# Every file this era's check reads, with its digest: the packet's files, the registry, the generic packet brief and the
# neighbours.
ERA_SHA256 = MappingProxyType({
    "architecture/diagnostic-caps-authority.json": "819b038d6efc8f4bef84d38ee216386ed3e233abbd444e8b0c48ce96bd77c1cb",
    "architecture/diagnostic-caps/README.md": "8216ec1b3e12bbce15fead83884517251db77d3034ee63e7a92c24591f4af4bf",
    "architecture/diagnostic-caps/limits.json": "5b95b1a42bc15a4de3a8f74e7520ee09da94a15ddd00ef2e8da2c738ca4f0a2c",
    "architecture/diagnostic-end-only/README.md": "8cfcf561f55bea00b7ac970ef4baa1e48798dfde731aadc88c39456e49e10965",
    "architecture/diagnostic-end-only/boundaries.json": "973dd3b6f843d8a83e2fcc0cc600aa1013a4d23c6363aa5636437594c525b792",
    "architecture/oracle-identity-met-perf-043.json": "87f9d9cb48bc2e99623e25951882bcc1d1765b47ea62284e77944d07c43ca937",
    "architecture/review-briefs/REVIEW_BRIEF_PACKET.md": "6dcff68d7e6b01823f1740063e94910edcc159a71a6ee803f1b66c62fd06e274",
    "architecture/review-record/briefs.json": "3e7a3f91a27f2fd7ac2c5dc2c1a62320b90b4f0d40c03df75c286d3f9a95eaa3",
    "ci/parallel_suite.py": "4fe4e24951c6a4f023361f9e840e8343a68e5af713754ff7acdf523e475495d5",
    "ci/pytest_diagnostics.py": "289591d27e0b0e9d4918dc0c6989147d60b400dfd682d64a228031d278b19576",
    "conftest.py": "3d6acbc362d26e23b4ac578d83e8e0205adee5fa914561032a8af298f2751387",
    "tests/test_diagnostic_repair.py": "ae3a39e0debcf4096d10b6a496c748c8135794910ba410b5446cf430f418ebe4",
    "tests/test_met_perf_043_oracle.py": "83c6cd5a989c2ccd7fd293b73e75feea37232dfa91565fd2268ead20f25fb90f",
    "tests/test_pytest_diagnostics.py": "e9fb71a91f3b7ba1a8d8ddd9c311605fe9304f7b3d7b58dccf2ba758a34fddc7",
})


def reviewed_bytes(path: str) -> bytes:
    """This packet's reviewed bytes of path; a bridged successor projects newer bytes back first."""
    return successor.historical_bytes(path, regular_bytes(path))


def _era_bytes(path: Any, raw: Any) -> bytes:
    """An era file's bytes, checked against its era digest; a path outside the era is refused."""
    expected = ERA_SHA256.get(path) if type(path) is str else None
    require(expected is not None, "MET-PERF-043 reviewed bytes are bound: " + str(path))
    require(type(raw) is bytes and digest(raw) == expected, "unreviewed MET-PERF-043 source: " + path)
    return raw


def _verified(path: str) -> bytes:
    """reviewed_bytes, checked against its era digest on every read; a path outside the era is refused before it is
    read."""
    require(type(path) is str and path in ERA_SHA256, "MET-PERF-043 reviewed bytes are bound: " + str(path))
    return _era_bytes(path, reviewed_bytes(path))


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


def _tree(raw: Any) -> Any:
    """raw's syntax tree, or None when it is not bytes holding Python source; nothing is compiled or executed."""
    try:
        return ast.parse(raw) if type(raw) is bytes else None
    except (SyntaxError, ValueError):
        return None


def _caps(tree: Any) -> list:
    """Every assignment, anywhere in the tree, to a cap name: (name, the dump of its value expression), sorted."""
    return sorted((target.id, ast.dump(node.value)) for node in ast.walk(tree) if type(node) is ast.Assign
                  for target in node.targets if type(target) is ast.Name and target.id in CAP_NAMES)


def _versions(tree: Any) -> list:
    """The value of every "v" member of a dict display in the tree: a constant's value, otherwise None."""
    return [value.value if type(value) is ast.Constant else None for node in ast.walk(tree) if type(node) is ast.Dict
            for key, value in zip(node.keys, node.values) if type(key) is ast.Constant and key.value == "v"]


def check_packet_files(files: Any) -> None:
    """V1: the packet's files are exactly the seven, and each one's bytes equal the sha256 pinned for it."""
    _bound(lambda: type(files) is dict and sorted(files) == sorted(PACKET_FILES) and len(files) == len(PACKET_FILES),
           "the packet files are exactly the seven")
    for path in PACKET_FILES:
        _bound(lambda: type(files[path]) is bytes and digest(files[path]) == ERA_SHA256[path],
               "a packet file's bytes equal its pinned digest: " + path)


def validate_packet_files() -> None:
    """V1 over the seven files, each read through the era."""
    check_packet_files({path: _verified(path) for path in PACKET_FILES})


def check_caps(raw: Any, base_raw: Any) -> None:
    """V2: the base module is the pinned one; each cap and derived limit is bound exactly once in the module and its
    expression equals the base module's; and the module's one record version literal is 2 (an int)."""
    tree, base_tree = _tree(raw), _tree(base_raw)
    _bound(lambda: type(base_raw) is bytes and digest(base_raw) == BASE_DIAGNOSTICS_SHA256
           and tree is not None and base_tree is not None
           and [name for name, _value in _caps(tree)] == sorted(CAP_NAMES)
           and _caps(tree) == _caps(base_tree),
           "the diagnostics caps and their derived limits are the base's")
    _bound(lambda: _versions(tree) == [RECORD_VERSION] and type(_versions(tree)[0]) is int,
           "the diagnostics record version literal is 2")


def validate_caps() -> None:
    """V2 over the module's reviewed bytes and, through this layer's own inverse, the base module's."""
    raw = _verified(DIAGNOSTICS)
    check_caps(raw, _undo_this_layer(DIAGNOSTICS, raw))


def check_oracle(identity_raw: Any, oracle_raw: Any) -> None:
    """V3: the oracle identity names the D5a oracle test and is kept, and its file.sha256 equals the oracle test's
    bytes."""
    identity = _parsed(identity_raw)
    _bound(lambda: type(identity) is dict and identity["schemaVersion"] == ORACLE_SCHEMA
           and type(identity["file"]) is dict and identity["file"]["path"] == ORACLE_TEST
           and type(identity["ruling"]) is dict and identity["ruling"]["decision"] == "KEEP",
           "the oracle identity names the oracle test and its ruling is KEEP")
    _bound(lambda: _sha(identity["file"]["sha256"]) and type(oracle_raw) is bytes
           and identity["file"]["sha256"] == digest(oracle_raw),
           "the oracle identity's sha256 equals the oracle test's bytes")


def validate_oracle() -> None:
    """V3 over the identity and the oracle test (hashed only)."""
    check_oracle(_verified(ORACLE_IDENTITY), _verified(ORACLE_TEST))


def check_registry(raw: Any, briefs: Any) -> None:
    """V4: the registry differs from the base by exactly this packet's one rider, pointing at the generic packet brief
    with the sha256 of the brief's bytes; nothing else in it changes."""
    registry = _parsed(raw)
    _bound(lambda: type(registry) is dict and type(registry["briefs"]) is list and type(briefs) is dict
           and all(type(briefs[rider[2]]) is bytes for rider in RIDERS)
           and [entry for entry in registry["briefs"] if entry["series"].startswith(NEW_PACKET + "/")]
           == [{"kind": rider[0], "series": rider[1], "path": rider[2], "sha256": digest(briefs[rider[2]]),
                "version": rider[3]} for rider in RIDERS]
           and digest(canonical(dict(registry, briefs=[entry for entry in registry["briefs"]
                                                      if not entry["series"].startswith(NEW_PACKET + "/")])))
           == REGISTRY_BASE_SHA256,
           "the registry differs from the base by exactly the MET-PERF-043 packet rider, pinning the generic packet "
           "brief")


def validate_registry() -> None:
    """V4 over briefs.json and the generic packet brief."""
    check_registry(_verified(REGISTRY_PATH), {PACKET_BRIEF: _verified(PACKET_BRIEF)})


def check_neighbours(files: Any) -> None:
    """V5: the neighbours are exactly the five, and each one's bytes equal its base digest pinned here."""
    _bound(lambda: type(files) is dict and sorted(files) == sorted(NEIGHBOURS) and len(files) == len(NEIGHBOURS),
           "the neighbours are exactly the five")
    for path in NEIGHBOURS:
        _bound(lambda: type(files[path]) is bytes and digest(files[path]) == ERA_SHA256[path],
               "a neighbour is unchanged since the base: " + path)


def validate_neighbours() -> None:
    """V5 over the five neighbours, each read through the era."""
    check_neighbours({path: _verified(path) for path in NEIGHBOURS})


def validate_met_perf_043() -> None:
    """Every reviewed byte first; then V1 (the packet's files), V2 (the caps), V3 (the oracle), V4 (the registry) and
    V5 (the neighbours); last, this layer's canonical hunks."""
    for path in ERA_SHA256:
        _verified(path)
    validate_packet_files()
    validate_caps()
    validate_oracle()
    validate_registry()
    validate_neighbours()
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
    validator_raw = successor.historical_bytes(VALIDATOR_PATH, regular_bytes(VALIDATOR_PATH))
    literal = b'AUTHORITY_SHA256 = "' + AUTHORITY_SHA256.encode("ascii") + b'"'
    placeholder = b'AUTHORITY_SHA256 = "TO_BE_PINNED_AFTER_SOURCE_FREEZE"'
    require(validator_raw.count(literal) == 1
            and digest(validator_raw.replace(literal, placeholder))
            == record["validatorNormalizedSha256"], "END-only diagnostics validator drift")
    paths = sorted((ROOT / "task-packets").glob("*.yaml"))
    old = set(record["baselinePackets"])
    require(len(paths) == 273
            and {path.stem for path in paths} == old | {NEW_PACKET, successor.NEW_PACKET, successor.successor.NEW_PACKET, successor.successor.successor.NEW_PACKET},
            "closed 273-packet catalog retaining the 270-packet checkpoint")
    packets = {}
    for path in paths:
        if path.stem in (successor.NEW_PACKET, successor.successor.NEW_PACKET, successor.successor.successor.NEW_PACKET):
            continue
        raw = regular_bytes("task-packets/" + path.name)
        expected = record["packetSha256"] if path.stem == NEW_PACKET else record["baselinePackets"][path.stem]
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
            "closed source-only END-only-diagnostics packet and inherited commands")
    require(len(packet["allowedPaths"]) == len(set(packet["allowedPaths"]))
            and set(packet["allowedPaths"]) == set(record["changedFiles"])
            | set(record["newFiles"]) | {AUTHORITY_PATH, VALIDATOR_PATH,
                                         "task-packets/" + NEW_PACKET + ".yaml"},
            "unreviewed or omitted END-only-diagnostics packet path")
    for path, rule in record["changedFiles"].items():
        current = successor.historical_bytes(path, regular_bytes(path))
        require(digest(current) == rule["afterSha256"]
                and digest(historical_bytes(path, current)) == rule["beforeSha256"],
                "unreviewed current source: " + path)
    for path, expected in record["newFiles"].items():
        require(digest(successor.historical_bytes(path, regular_bytes(path))) == expected,
                "new source drift: " + path)
    validate_met_perf_043()


if __name__ == "__main__":
    validate()
    print("END-only pytest diagnostics valid: 273 current specifications; 270-packet checkpoint and exact 269-packet predecessor; contract reviewed.")
