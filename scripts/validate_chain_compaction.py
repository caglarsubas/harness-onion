#!/usr/bin/env python3
"""Validate the MET-PERF-042 chain compaction (C1 and C2) under the standing identity rule, and the exact 255-to-254 projection."""
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
    import validate_edge_record_v9 as successor
except ImportError:
    from scripts.safe_yaml import safe_load
    from scripts import validate_edge_record_v9 as successor


ROOT = Path(__file__).resolve().parents[1]
AUTHORITY_PATH = "architecture/chain-compaction-authority.json"
AUTHORITY_SHA256 = "1e13c34eca44de50763f41c3e2423ceada0a1a2ad47923323ab40684da4e3e06"
VALIDATOR_PATH = "scripts/validate_chain_compaction.py"
BASE_COMMIT = "29c84b36dad2f6f9822b71cd959064f0202d9868"
NEW_PACKET = "MET-PERF-042"
PREVIOUS_PACKET = "MET-ENFORCE-039"
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
            require(key not in result, "duplicate chain-compaction authority member")
            result[key] = value
        return result

    def no_constant(_value: str) -> Any:
        raise ValueError("nonfinite chain-compaction authority number")

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
        require(digest(raw) == AUTHORITY_SHA256, "chain compaction history authority digest")
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
    }, "closed chain compaction history authority")
    require(value["schemaVersion"] == "harness.planeon.ai/chain-compaction-authority/v1"
            and value["authorityPacket"] == NEW_PACKET
            and value["acceptedBase"] == BASE_COMMIT
            and type(value["baselinePackets"]) is dict
            and len(value["baselinePackets"]) == 254
            and NEW_PACKET not in value["baselinePackets"]
            and type(value["changedFiles"]) is dict
            and type(value["newFiles"]) is dict
            and _sha(value["packetSha256"])
            and _sha(value["validatorNormalizedSha256"]),
            "accepted 254-packet base")
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
    # An exact 254-era byte string is already older than the successor layer.
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


# MET-PERF-042 (CHAIN-COMPACTION-001; owner decisions Q-CC-1 (b), Q-CC-2 (a), Q-CC-3 (b), Q-CC-IDENTITY (a), Q-CC-6 (a),
# Q-CC-F1 (a), Q-CC-F2 (a) and F3, 2026-10-21) compacts the history chain's two pairwise scaffold tests in the 63 bridged
# layers (C2: each keeps its 8 own routes and the adjacent one, and one payload mutation with a table check whose oracle
# is the test's own code), shares test-side YAML parses per test module (C1, in tests/conftest.py) and adopts the
# identity rule as a standing rule. This era's check reads repository bytes only through reviewed_bytes (and the records
# directory's listing only through reviewed_tree), so a later bridged successor projects its own edits away first; a path
# outside this era is refused before it is read, and every era file is bound by digest on every read. Checked here: the
# records under architecture/chain-compaction/ (the closed directory, each record's mode and shape, no absolute local
# path); then, run by the reference model scripts/chain_identity.py from its pinned bytes (it reads nothing itself): the
# identity rule over this era's chain validators (PLAN revision 11 section 3.1, items 1-8: the walk, the class rules, the
# step rule against this layer's one-step projection, the binding rule and this head's allow-list), the conftest's
# never-shared identity tests, and the C2 shapes with the fact map recomputed from this era's test files and their
# previous-era bytes; last, this layer's canonical byte-minimal inverse hunks (MET-PERF-040's carried rule). Item 9 (the
# runtime binding check) runs in this layer's test, on the modules that test's process imports.
HEAD_MODULE = "validate_chain_compaction"
MODEL = "scripts/chain_identity.py"
RECORD_DIR = "architecture/chain-compaction"
README = RECORD_DIR + "/README.md"
COST_REPORT = RECORD_DIR + "/cost-report.json"
FACT_MAP = RECORD_DIR + "/fact-map.json"
IDENTITY_RULE = RECORD_DIR + "/identity-rule.json"
DECISIONS = RECORD_DIR + "/decisions.md"
AB = RECORD_DIR + "/ab.json"
SEEDED_FAULTS = RECORD_DIR + "/seeded-faults.json"
RECORDS = (README, COST_REPORT, FACT_MAP, IDENTITY_RULE, DECISIONS, AB, SEEDED_FAULTS)
CONFTEST = "tests/conftest.py"
HEAD_TEST = "tests/test_chain_compaction.py"
IDENTITY_TESTS = ("test_identity_rule_holds_on_the_live_chain",
                  "test_runtime_bindings_are_the_frozen_ones_around_a_fan_in_pass")
CHAIN_LAYERS = 67
# The identity rule's frozen counts (identity-rule.json, generated from the 66 layers at the accepted base) and the
# historical_bytes classes owner decision Q-CC-F2 (a) set.
RULE_SCHEMA = "harness.planeon.ai/chain-compaction-identity-rule/v1"
RULE_KEYS = ('schemaVersion',
 'packet',
 'plan',
 'source',
 'chain',
 'walkForms',
 'bindings',
 'g1',
 'g2',
 'd',
 'p0',
 'bumpVocabulary',
 'bridgeVocabulary',
 'stepRule',
 'allowList',
 'counts',
 'notOpenToNewHead',
 'evidence',
 'discrepancies')
RULE_COUNTS = MappingProxyType({'layers': 66,
 'g1': 16,
 'attributeNames': 372,
 'nodeTypes': 73,
 'eraLoaderShapes': 11,
 'eraLoaderLayers': 35,
 'builtinsImportLayers': 9,
 'moduleImportForms': 48,
 'moduleCallForms': 18,
 'functionImportForms': 9})
HISTORICAL_BYTES_CLASSES = ((192, 192), (193, "head-1"))
# The fact map's totals at this era (63 bridged layers; 2,079 route nodes dropped, each with its kept twin).
FACT_TOTALS = MappingProxyType({'baseRouteNodes': 2646,
 'droppedRouteNodes': 2079,
 'adjacentKept': 63,
 'keptTwins': 2079,
 'layers': 63,
 'functionNamesLost': 0,
 'layersWithoutReadCountTest': [192, 193]})
# M1's cost report (run 20261021T1041), its top-level keys.
COST_KEYS = ('argv', 'argv63', 'authorityReadsPerVerify', 'passB', 'passC', 'profiledSample', 'run')
MEASURED_RECORDS = ("ab.json", "seeded-faults.json")
# M2 (run 20261021T1516) on the head measured as ed000a8b, and the owner's acceptance of B1 and B4 (2026-10-21).
AB_KEYS = ('schemaVersion',
 'plan',
 'mode',
 'modeNote',
 'ownerMode',
 'source',
 'subject',
 'collected',
 'B1',
 'B2',
 'B3',
 'B4',
 'B5',
 'notPassedInHeadRuns',
 'serialSample',
 'ownerAcceptance',
 'laterLever')
AB_MODE = "PARTIAL (owner M2-PARTIAL)"
MEASURED_HEAD = "ed000a8bf4822702890f0fad2e5afc510017247f"
B3_NODES = (16560, 14916, -2079)
OWNER_ACCEPTANCE = "Accept and continue (Recommended)"
# M3 (run 20261021T1637): 559 cases, 352 run, 207 out of scope by the owner; the monitor's collection-kill ruling.
SEEDED_KEYS = ('schemaVersion',
 'plan',
 'source',
 'subject',
 'counts',
 'scope',
 'transforms',
 'partI',
 'collectionKills',
 'benign',
 'partII')
M3_CASES = (559, 352, 207)
OWNER_M3_SCOPE = "Run 352, rest out of scope (Recommended)"
COLLECTION_KILLS = ("R10-MAX-196", "R10-MAX-210", "R10-MAX-223", "R10-MAX-234", "R10-MAX-246", "R10-MAX-253")
COLLECTION_RULING = "MON-M3-COLLECT-KILL"
COLLECTION_WORDS = "killed at collection in both suites, identical refusal"
# The decisions record's section headers, each once (the owner's and the monitor's decisions, verbatim).
DECISION_HEADERS = ('## 2026-10-19, PA-D9 (D9a) (owner, principles audit; as recorded in roadmap item CHAIN-COMPACTION-001)',
 '## 2026-10-21, Q-255 slot assignment (owner via the lane monitor; verbatim as relayed, received 2026-10-21 '
 '00:16 +08:00)',
 '## 2026-10-21, Q-CAN-7, Q-CAN-4 facts and MON-CAN-WALK (monitor; verbatim)',
 '## 2026-10-21, the safety event, Q-CC-CAP and PLAN §9 (owner via the lane monitor; verbatim as relayed)',
 '## 2026-10-21, MON-M1-ACCEPT (monitor) and "Finish 255; new item" (owner via the lane monitor; verbatim as '
 'relayed)',
 '## 2026-10-21, Q-CC-B4 (owner via the lane monitor; verbatim as relayed) and MON-CC-R7-SLIPS (monitor)',
 '## 2026-10-21, "Build now" (owner via the lane monitor; verbatim as relayed) and the BUILD GO (monitor)',
 '## 2026-10-21, Q-CC-F1, Q-CC-F2 and F3 (owner via the lane monitor; verbatim as relayed) and the build '
 'resume',
 '## 2026-10-21, GO for M2 on ed000a8b (monitor; verbatim as relayed)',
 '## 2026-10-21, MON-M2-CONTROLS (monitor; verbatim as relayed)',
 '## 2026-10-21, MON-M2-STOP-LOAD (monitor; verbatim as relayed)',
 '## 2026-10-21, M2-PARTIAL (owner via the lane monitor; verbatim as relayed)',
 '## 2026-10-21, MON-255-TESTSTRING-FIX (monitor; verbatim as relayed)',
 '## 2026-10-21, MON-255-DECISIONS-KEEP (monitor; verbatim as relayed)',
 '## 2026-10-21, 255 B1/B4 "Accept and continue", M3 scope "Run 352, rest out of scope" (owner via the lane '
 'monitor; verbatim as relayed) and the M3 GO',
 '## 2026-10-21, MON-M3-COLLECT-KILL and the GO for U6 and the packet review (monitor; verbatim as relayed)',
 '## 2026-10-21, packet review r1: GO delta r2, MON-255-P1-4-NOTE, and the pre-check GO (monitor; verbatim '
 'as relayed)')
# Every file this era's check reads, with its digest: the chain validators but this one, the scaffold test files and this
# layer's test, the conftest, the reference model and the seven records.
ERA_SHA256 = MappingProxyType({
    "architecture/chain-compaction/README.md": "d6e1c60c6b3cedd868f9555c254b1b1bd64ccfd8ea458a1f32a0711505202e86",
    "architecture/chain-compaction/ab.json": "497899a2799efd48778f5250fe6cd495966999f9510e933e3083091822b552ed",
    "architecture/chain-compaction/cost-report.json": "ea50f1d56df9fac17eacfc5c04271e540d18676f15d3d6c811e1e4076f4dde44",
    "architecture/chain-compaction/decisions.md": "0c5c7d47d448b9425d959f1fe051bc70fcbea695d8584e7c4f528d963d93f1d1",
    "architecture/chain-compaction/fact-map.json": "6c955fcd42d337f4af6224515675c9d9c6931681d9e9a1d6fd80f7ed9812a64e",
    "architecture/chain-compaction/identity-rule.json": "4bfbcc0387084bd2cd5166af4eb83fb5f9ab18a16e1f289cd2727f5bbdd8bc2e",
    "architecture/chain-compaction/seeded-faults.json": "4fadc681721e0d01ea0a16d8a92441391c3fefb9ba67270b97ef7d825097ad9a",
    "scripts/chain_identity.py": "1ec764808aaf4e7f2a9eea2da605d0c12d172c5a8e4c23bf3ac79bbb1d07e753",
    "scripts/validate_admission_channel_v3.py": "c11b92c8bf5ee9e5d39d97f6c2b497200f986e615083a434c2f8feed9cf61bb9",
    "scripts/validate_admission_semantics_v2.py": "c6f79f9fd5b55ce9c13f8ffb67f4986869ba6f735d375b3f1b9e30f9281684e6",
    "scripts/validate_agent_loop.py": "1ab88fdd663eca9b0a655b7fe1bb71666c6bd2ce5ac39cd0f95df11b3f8937b4",
    "scripts/validate_backend_distribution.py": "a4c185e764ed3f848f8f097b524bf77c76ab06906280d4a8054ebf17fd762933",
    "scripts/validate_chain_depth_headroom.py": "c24392ead633dbb1dfc446297fc7d650d5a7dfbe3a1f3ac77dc002f20376f074",
    "scripts/validate_ci_runner_admission.py": "ae55845d58aaa41a0582ce401fb9da524d63480b26f421b74b7272bcaf0286f7",
    "scripts/validate_compiled_filter_programs.py": "d76ba5aee407dc66f6345be7d411be1ed93b9531457fb0a85ca844ae1f2dac24",
    "scripts/validate_compiled_filter_programs_v2.py": "5254f1082f27d92999fee78a1c1c79a1c13a76f0c930f5422b6f40841b1cbfa5",
    "scripts/validate_compiled_filter_programs_v3.py": "40270120305193664d708f616b22d93f4b578a119358f3be08d0650fca7c9b72",
    "scripts/validate_dedicated_verifier_account.py": "43000f37712c0955e98f217c2e7bd88b8c7d28c67f892fb38cdb17b5544108c3",
    "scripts/validate_diagnostic_caps.py": "6fa2d896e75476c27574f58b51bc90c774805137cec1957f953c9425e18f73d0",
    "scripts/validate_enforcement_test_plan.py": "197ecebbd8c8f339d7f895f87ee1265081432650563d0724102506284b6353db",
    "scripts/validate_host_interface_hs43.py": "5468be58d415fe931f64334ae0774b33c29350f8a34e42a0ca5a557f98930827",
    "scripts/validate_host_interface_resolution.py": "2024b3518b4ce8bf6c02d5232411372e6eb343b6055b1c33518ede4c700e57b0",
    "scripts/validate_i05_gate_channel.py": "c2bc6109313d3bbb2e32db71f9289c239ea7caecc2e0f4f7d25e813b525c4982",
    "scripts/validate_i05_gate_channel_v2.py": "e6fbb99e0d71b2557310f3dd59dd41ccd996770193811132d9f0184b46fde3d8",
    "scripts/validate_i05_gate_channel_v4.py": "530b166be074e69e32db682a1a57acbf3db50fe49e3abec00dede89e14c07f20",
    "scripts/validate_i06_backend_profile.py": "cd9196306a7aba8f964189955228ca7c36ad44f37d5d930e06832743ce560655",
    "scripts/validate_i06_backend_profile_v2.py": "6eef828e34644f38ef0b0de95fbc29c21d153216a1c64fe7427a67ef761564a0",
    "scripts/validate_i06_backend_profile_v4.py": "64b0b800cd12bb46266719b55e720d8efaf786012af594d28a80fb872dc4cc4b",
    "scripts/validate_i07_policy_write.py": "b927c83bc4e008ae6ed328ec8fb344c1cf94f7037353b670b90b24ec7f72995c",
    "scripts/validate_i07_policy_write_v2.py": "eb2ef1993758cc0b28269a54f32523b59ab2602dbaa3d28611338093f9521b49",
    "scripts/validate_in_session_predecessor_proof.py": "a548b18dc17b961c05805253c6748c62a81cf515e1e5bc1ea3407d0e014c90a7",
    "scripts/validate_isolated_network_canary.py": "5b7b7c8103ed5abb31bb13faded9dfe49a570cf540c7ae57a26b3377cc28a1ff",
    "scripts/validate_isolated_offline_runner.py": "926703968c1226e9176abc50d77da263683628d36ccd29fb6f949ecb7225c7ea",
    "scripts/validate_lab_run_plan.py": "2ce5f940eb38ca7f966b21cbca7c11f611e2590b42c2a2de03331c97bc0a0e05",
    "scripts/validate_license_amendment.py": "e5003387cd425f4a59651a72b2db3f977c529b3dd35b5ad83145cffc458ee3f7",
    "scripts/validate_license_amendment_v2.py": "fe04a039964c54b12eb2278f6da892b139f18693f128795320fe27e2de2a06ca",
    "scripts/validate_linear_history_rechecks.py": "0214e0f0e4db445c77e7942bb311f8b059a3f4871f46bfb070673ae13d2ec5b9",
    "scripts/validate_linux_runner_contract.py": "b3edcf37638a1f748d8c703f66935e8d1ede6f2edb1b94b7ff62c314365815ba",
    "scripts/validate_load_deadlines.py": "688ec02fd96714ced42a140a6c884a5b0b15b84d8a3bb1e306099be66c93eb85",
    "scripts/validate_native_profile_v2.py": "ea8ee5ee93cb1da262e9547f6d5cb8c2833b4706500691f2083c5c353e78bebd",
    "scripts/validate_native_profile_v3.py": "0246766158275970a866a3af91e08c0d5af70df01a4333c908cb075b8779c5b1",
    "scripts/validate_native_profile_v4.py": "ef2b9afea7e76cf542fff40b52fc457d10fa13f3ffeae60fcecba344eace2679",
    "scripts/validate_native_profile_v5.py": "a3b3a27f7844add477c45791773a05aac34c006af1a2796d2229d69b825eaf63",
    "scripts/validate_owner_verifier.py": "58421b31ab7dc52947978fa910d839c786bfc8584e5b92339c7180894608318e",
    "scripts/validate_packet_schema_performance.py": "1b0720f03eab04b4f991aca6d502d1a5ca86743bc9906f4c9252f450346804f2",
    "scripts/validate_parallel_suite.py": "e57a5ab51be4384b6d069ee36691d352dfe86c4ebb1408307917b3f131770954",
    "scripts/validate_parallel_suite_followup.py": "5db679faec4f8d70ee3d1e3d3e67a9bfc809aca150e535c9ba01314ce9e32d69",
    "scripts/validate_portable_warm_snapshot_temp.py": "19b48c130e9a3487db976965f2a395404d797f7cdc3a388f80d846431e436d13",
    "scripts/validate_projection_reuse.py": "7d664de01a9d2195cd326a47dc829b79c712482b7d577767d9cc93db091cecc9",
    "scripts/validate_pytest_headroom.py": "e50d7f375647a0ae0269a7a68583bbcca0bc97155e0a3d613b3b73834a3bfdd0",
    "scripts/validate_research_adoption_v2.py": "ee98ca3a34434222f3409474a74546b6f553fba326fa42380f20ad798f5822b7",
    "scripts/validate_research_adoption_v3.py": "f9c18328dca6fcc7b7fc3a909b3f595b67e51a4f28cb38f84a37ed01a785453a",
    "scripts/validate_run_events.py": "5daa07b6e2cd67c430dad2a4d61f8bca64eb1b6d54e77d97b3df181743ccc3c4",
    "scripts/validate_run_manifest.py": "1d6cdbd0724d28c484d5e88d768baaa01b4a40befed789783b8a8d53926b8771",
    "scripts/validate_seccomp_allowlists.py": "aabb268baa96c223d81374649b0534320814e1ed7f250b3f9556e0c8d5f1a019",
    "scripts/validate_seccomp_observer_listener.py": "152b6bfb669ab3ebb1feab2eee942cb42192a5f7b3ea972b4543b967146d47ea",
    "scripts/validate_seccomp_v3.py": "f9f68c5940afaef1f6282f01070ccca2a73a44e6c6650e3841a76d347c6404d1",
    "scripts/validate_seccomp_v4.py": "1144b5873786ba9eab6cd70b6ae1ef414daf3370daebc49b3db4aec7ba7c456c",
    "scripts/validate_sector_catalog.py": "c657bae1f2d81bdf9d4dc5d167ab2017e12189ff94b6e3ab6d1e78a039099657",
    "scripts/validate_sector_direction.py": "c718dab967c0c03f9aa30080b405393b46bc66cd3f1b56443886791757a0b2ed",
    "scripts/validate_selinux_matrix.py": "a2a890e9e9cfa80710158b06bb3351c803e98cbb3520ceaeb5d0898c7425a18d",
    "scripts/validate_selinux_matrix_v2.py": "6d658b7558d99c3783eea0f358506644449dff13e625c2805389abcef9da8ed5",
    "scripts/validate_selinux_matrix_v3.py": "fe5a68d60c09216d72d0cd05ae780c341d47fcaa901d023fd6f1f2fe312c4ff8",
    "scripts/validate_selinux_matrix_v4.py": "4745bb55b9d35d82ae8939214527c34164700fe0c700b18c52d29a71f313568f",
    "scripts/validate_selinux_replay.py": "a9cff5c091136eb08f9f9036c3963278998e4755aeeb7444aecea0a843d2b5a0",
    "scripts/validate_topology_coordination.py": "c0d3a05bc12b2952e6b0ee7b680272b0cdc9e193c661721144e16d079554c7cc",
    "scripts/validate_unified_roadmap.py": "8cbc60b98e0375cf45d56b97b4873e8bb51617b6f4bcf7e93780ffe28d62ae4d",
    "scripts/validate_verdict_ledger.py": "c8defd0a113665b3f48b5ba8185505332660f33176d343154cc87cfc5de1bd5b",
    "scripts/validate_verify_headroom.py": "f42e06e7ce747280e5aeee755611800ab4ce101abcadac77b62b73f2ec43e911",
    "scripts/validate_w01_amendment.py": "341abea46870557ecb7bff28f88e566eba693d1c7a091bbd8bd96595419617c9",
    "scripts/validate_w02_notes_errata.py": "46a44bc3fa533d926113faeb3be7275ad071da97f7199d87ca3a6e9ffa99238f",
    "scripts/validate_w03_amendment.py": "6397783c3b10b0553fe93f4056b8ff89900fc7ecd3f5ae041426971277cd12e5",
    "scripts/validate_w03_plan_amend_2.py": "815c7c3482bf9d18767e5b6a663723b247f5dad5d251bf47f51ef8b1582681bd",
    "scripts/validate_w03_plan_amend_3.py": "a303f57f87cdacb2d4a98932669e459a5724a12bfd163f14a4171bcc618222f5",
    "tests/conftest.py": "1810b9c0f02b6a8e7a1bff4c763a74f395f8c3292c91a2738757c5062b33cd7c",
    "tests/test_admission_channel_v3.py": "32c1dc1ae4c82e7945a52e03f819573c8da1c828d909c2c88df04e334bd54e79",
    "tests/test_admission_semantics_v2.py": "cc1fc87420eb2952005e82f9a097b22336486e35313bc041687fd22af1e1b12c",
    "tests/test_agent_loop.py": "4cfb45130c3f65e72ddad138007e04642c976408218c87d94a810e23f4a25d9b",
    "tests/test_backend_distribution.py": "266f24dd0d8859a3e1059eedb82cbc9d740cb02440e611dc13f2d0e2d3c0c038",
    "tests/test_chain_compaction.py": "e05b70f9fa611ad4bdcb2fa0db6a79b823aafb5a5e48781d72d4b973d7eda3d1",
    "tests/test_chain_depth_headroom.py": "5300eaf19119595283b15f2a2613df695ff2816b9297ed233c9c6f11f57f78bf",
    "tests/test_compiled_filter_programs.py": "ef7b579637d12f87b81c13a1beb920de04b4fd5a7e72125c8d480f9b101d520f",
    "tests/test_compiled_filter_programs_v2.py": "7c06b693962332f591405a4ed28c8fd1aff405ee3788f09962609a36560f6938",
    "tests/test_compiled_filter_programs_v3.py": "7217d624e87b62260af5dc2fae371e77b0149a7d26b92876bf238a76895ecf8f",
    "tests/test_dedicated_verifier_account.py": "dc3d9c605a1404fe94161718e99675049370f661919b3ae58a36766652e69e7f",
    "tests/test_diagnostic_caps.py": "6d7d2518d74e27e7213971c3731019d9c02e41c6adb130d040e98407e10df389",
    "tests/test_enforcement_test_plan.py": "ba07d6ed30e238dc3855a4137dda7fcb913c5c83b62a60264099b5c70b6585b2",
    "tests/test_host_interface_hs43.py": "6bc65c95c2dcb2bb2116ce51ca4c4596dc709ca310f5dd097f44d65a434eb229",
    "tests/test_host_interface_resolution.py": "ba8a12eaded885f9a6acea003ece88d7777128825e3df4c1bd044199dc53aef9",
    "tests/test_i05_gate_channel.py": "51f79e126ca1d033fc09d4273266e46fa700fd5e58ec5746a301c80dd359ce86",
    "tests/test_i05_gate_channel_v2.py": "8627b3b1f25c395d653485672bc3b8d3bcd278f2a5781425ce990f5cc02dafc7",
    "tests/test_i05_gate_channel_v4.py": "a78ec1624580e7d656f46a51725305b69ad06065a3878db8f5073e25df442da4",
    "tests/test_i06_backend_profile.py": "0e85a628426bcf3fcfccd95b3d224e84f2527a224f6a6d10d5d8bbdfecfa499a",
    "tests/test_i06_backend_profile_v2.py": "8478eb03c37fee82b1acafcbe729aede13810b7fcba2e7752893966f94c57b89",
    "tests/test_i06_backend_profile_v4.py": "73cf1bc0b72130d3fad74ce36c999093e3ef7ea5360eeeec69f3fffb7dd7541e",
    "tests/test_i07_policy_write.py": "04961a7ab17114c940ba596740f41c5aa1e81a716675d40103b02992365b79ae",
    "tests/test_i07_policy_write_v2.py": "44cad6898089e2865efc2a2796bc778b8803bf0b570db1c75bf3a742dc25681e",
    "tests/test_in_session_predecessor_proof.py": "bee8eaf8635ce48893cc20fdc0fc81561cff577ebe0029ab4d1ee19e5ffbd4d7",
    "tests/test_isolated_network_canary.py": "4c9703314339574842a337e401830ae3312c274542f0973373d3b1203317ecba",
    "tests/test_isolated_offline_runner.py": "cdedea414a87f3be79c6105a4344f3a5852b3dda9419dee93c14e059373abbc1",
    "tests/test_lab_run_plan.py": "8e9aa8baf7fbb7f124dc3a7f8d37f0c7b9393846e708934e16dd7539867d7bcf",
    "tests/test_license_amendment.py": "cf1548dd99b0fc3c78d61178309bd2e95f227afebeebee8c8c3051f16d5d187f",
    "tests/test_license_amendment_v2.py": "351a2a8f9ecce604b4603f48cf24967f93c20d0bd8234589265dd8d940f3c2f6",
    "tests/test_linear_history_rechecks.py": "4cb5d9045be7ab1fe7fed6437b3ab6c9d2e75a7eac4212cf6b87342858ff146a",
    "tests/test_linux_runner_contract.py": "0570ecc6b389d7ba6eb5df6775b9d0ad6bbaafdcb5d210eff675886de492a47a",
    "tests/test_load_deadlines.py": "fe90ea383107e822ee668a1d88d4c362d8f6e2ad6c7a2e272a532fc3d70b43b7",
    "tests/test_native_profile_v2.py": "72dcb8675da3752a739e22b9f39a948a02e9d27bfbdb632f49a6b729c5cdc5b7",
    "tests/test_native_profile_v3.py": "40f7c935206153c8195c05f839bce07cdcce15439d9484d38c490df1bbaa9141",
    "tests/test_native_profile_v4.py": "e9856c12098551262007e170d3bfbacf97bc82038d426fa57ab77b013b4164e7",
    "tests/test_native_profile_v5.py": "b0ded5a42c858ded3d5a77a6656c1e72908e061b84822a6527e599e1b21c744d",
    "tests/test_owner_verifier.py": "0b503093ea76eda55c02626759e7f39f0c9c9f2320dc49e41237635bd2f3653f",
    "tests/test_parallel_suite.py": "2b355d54493db5100aaf29d1d049d46a0b7ba12201ef96c29cd3772652370b84",
    "tests/test_parallel_suite_followup.py": "d1144ddb2dd1123e2803883e6f27332c3768b626971d4ea884b9e3e920d75b69",
    "tests/test_portable_warm_snapshot_temp.py": "e31a07993b9872fae2cf86c6ba5b9f2d5e56a8678cd5180502cbe7ff92495253",
    "tests/test_projection_reuse.py": "f215c6e12fa66af3043e4c7f16637d0c79848dd5c9e88093cb75e80f732b08b6",
    "tests/test_pytest_headroom.py": "4759c8a7e226b5fe3fac509958954894b8d1c1713986ff898d0445b93f5f5b53",
    "tests/test_research_adoption_v2.py": "cc12104f23437eb3bdc49717a57e2f4a4e9b22fae1ef873eed342e026da9b68e",
    "tests/test_research_adoption_v3.py": "418c0ce861955680c2dd8bf271af0a88b12f1cbf1a79e3695f8f9157b86bb435",
    "tests/test_run_events.py": "e9703c4781f0a6661be8c67f37537db9f230bdf5a3d2b614ab9946b143f0999e",
    "tests/test_run_manifest.py": "46db76777f5cccbc63ac374364630d1394b966c2b39a8a74df4b6f7b48c84700",
    "tests/test_seccomp_allowlists.py": "1be0a7ce13647669709cd71c9f671bb06298b88a807fba45447b161961d34143",
    "tests/test_seccomp_observer_listener.py": "5335f49b18f11706c44057fc7f3fad35db667c1091a3907ba7495cf887599aa8",
    "tests/test_seccomp_v3.py": "c561cd085def5a9d45419e29004d6db63e3d45ad349c3b3603a4a43a6982381a",
    "tests/test_seccomp_v4.py": "78c7ba1afbe8ed26c2e43283688ace9eb3e40b196a298b5f974cf8574800c19f",
    "tests/test_sector_catalog.py": "559d85889309bcf1aa74dcaa6b92075d7bd9d6c87932153075171ed74ee0d819",
    "tests/test_sector_direction.py": "36eae8f44a2eb73e5cce365bebe6926ec43a37bd17e1560b3c932554b05a8e8a",
    "tests/test_selinux_matrix.py": "3c783763f8bf42f65d98da4d8ecc7c38ad36e99286a3f3c00110f073ed4993d0",
    "tests/test_selinux_matrix_v2.py": "79343d6caac445e6c325f5161d348ffb8f675e9428244279f59f2a29001cdf8b",
    "tests/test_selinux_matrix_v3.py": "c95f7aa997996c45761609d57a03882b00d94c3a1c354c0307371a9178d4b100",
    "tests/test_selinux_matrix_v4.py": "d90095f09728d8165e21c7f695a3fff04e02ca726405fb89371f934b00e5ca27",
    "tests/test_selinux_replay.py": "0964b33aedd755db42d6803ef036a2df7b71afdd09497de2e8f92de126bb46fe",
    "tests/test_topology_coordination.py": "bc5abac95666a2b23042750508ebf3cc35d32ff428fe23acbbbc436de4a7eb6a",
    "tests/test_verdict_ledger.py": "51adefff22ed6b74cce03bb12f2bb479bc62d1ecbfc8d8520ce65880a3c7115e",
    "tests/test_verify_headroom.py": "0a196d7e9c1febf478f52f73f828cf85dc0f9c144f474cfb88f3eea85b9f19ec",
    "tests/test_w01_amendment.py": "6ab9a7fdbff86fbd3e633dd3fdbf320d72cfff091fe99904f823c6e798c4fe88",
    "tests/test_w02_notes_errata.py": "c2de2a189114977aa6fecd81c888bb2de414be33a4890db1560a37f510b76c96",
    "tests/test_w03_amendment.py": "7ae1ddbbcc095497183e7f0c92a23f376f8381308635fbdb0c37e110b9deb709",
    "tests/test_w03_plan_amend_2.py": "770868ddb72d7cd92d64e95e9731f7a21156c63201139367cfa144ff0f2c6873",
    "tests/test_w03_plan_amend_3.py": "6452e6d404f81f2d982bb2fa6e3bbbd1236df32f23542e46e6dd62b7c5ce4c90",
})
# Absolute local path markers, matched case-insensitively; spelled in parts, so this file holds none of them.
LOCAL_PATH_MARKERS = (b"/" + b"users/", b"/" + b"private/", b".local" + b"/state")


def reviewed_bytes(path: str) -> bytes:
    """This packet's reviewed bytes of path; a bridged successor projects newer bytes back first."""
    return successor.historical_bytes(path, regular_bytes(path))


def reviewed_tree(directory: str) -> dict[str, int]:
    """Every entry under directory in this packet's tree, by repository path, with its lstat mode; a bridged successor
    that adds an entry there projects it away first."""
    entries: dict[str, int] = {}
    pending = [directory.rstrip("/")]
    while pending:
        folder = pending.pop()
        for entry in sorted((ROOT / folder).iterdir()):
            relative = folder + "/" + entry.name
            entries[relative] = entry.lstat().st_mode
            if stat.S_ISDIR(entries[relative]):
                pending.append(relative)
    return entries


def _era_bytes(path: Any, raw: Any) -> bytes:
    """An era file's bytes, checked against its era digest; a path outside the era is refused."""
    expected = ERA_SHA256.get(path) if type(path) is str else None
    require(expected is not None, "MET-PERF-042 reviewed bytes are bound: " + str(path))
    require(type(raw) is bytes and digest(raw) == expected, "unreviewed CHAIN-COMPACTION source: " + path)
    return raw


def _verified(path: str) -> bytes:
    """reviewed_bytes, checked against its era digest on every read; a path outside the era is refused before it is
    read."""
    require(type(path) is str and path in ERA_SHA256, "MET-PERF-042 reviewed bytes are bound: " + str(path))
    return _era_bytes(path, reviewed_bytes(path))


def _head_bytes(raw: Any) -> bytes:
    """This layer's own bytes, bound by the authority's normalized validator digest (the head's file is not in its own
    era table)."""
    literal = b'AUTHORITY_SHA256 = "' + AUTHORITY_SHA256.encode("ascii") + b'"'
    placeholder = b'AUTHORITY_SHA256 = "TO_BE_PINNED_AFTER_SOURCE_FREEZE"'
    require(type(raw) is bytes and raw.count(literal) == 1
            and digest(raw.replace(literal, placeholder)) == authority()["validatorNormalizedSha256"],
            "the head's own bytes are its reviewed bytes")
    return raw


def _own_bytes() -> bytes:
    return _head_bytes(reviewed_bytes(VALIDATOR_PATH))


def _era_source(path: str) -> bytes:
    """The model's reader: this layer's own bytes, or an era file's verified bytes."""
    return _own_bytes() if path == VALIDATOR_PATH else _verified(path)


def _json(path: str) -> Any:
    return parse(_verified(path))


def _git_mode(mode: int) -> str | None:
    """The git mode of a regular file from its lstat mode; anything else has none."""
    if not stat.S_ISREG(mode):
        return None
    return "100755" if mode & 0o100 else "100644"


def _era_import(era: dict) -> Any:
    """An import function that resolves the named modules to this era's copies and everything else normally."""
    def era_import(name, globals=None, locals=None, fromlist=(), level=0):
        if level == 0 and name in era:
            return era[name]
        return builtins.__import__(name, globals, locals, fromlist, level)
    return era_import


def _era_model(path: str, name: str, imports: dict | None = None) -> types.ModuleType:
    """A reference module of this era, executed from its verified bytes (no import, no bytecode); named imports resolve
    to this era's copies."""
    module = types.ModuleType(name)
    module.__file__ = str(ROOT / path)
    if imports:
        namespace = dict(vars(builtins))
        namespace["__import__"] = _era_import(imports)
        module.__dict__["__builtins__"] = namespace
    exec(compile(_verified(path), path, "exec", dont_inherit=True), module.__dict__)
    return module


def check_records_tree(tree: Any) -> None:
    """The records directory holds exactly the seven records, each a regular file of git mode 100644."""
    require(type(tree) is dict and sorted(tree) == sorted(RECORDS)
            and all(_git_mode(mode) == "100644" for mode in tree.values()),
            "the records directory holds exactly its seven records, each of mode 100644")


def check_record_bytes(path: str, raw: Any) -> None:
    require(type(raw) is bytes and not any(marker in raw.lower() for marker in LOCAL_PATH_MARKERS),
            "no absolute local path in a record: " + path)


def check_cost_report(value: Any) -> None:
    require(type(value) is dict and tuple(sorted(value)) == COST_KEYS, "the cost report is M1's, with its keys")


def check_readme(text: Any) -> None:
    require(type(text) is str and all(name in text for name in MEASURED_RECORDS) and "Q-CC-F1" in text
            and "Not in this build" not in text,
            "the README describes both measured records and the one inherited edit outside C2")


def check_decisions(text: Any) -> None:
    lines = text.split("\n") if type(text) is str else []
    require(bool(lines) and all(lines.count(header) == 1 for header in DECISION_HEADERS),
            "the decisions are recorded verbatim, each section once")


def check_identity_rule(rule: Any) -> None:
    require(type(rule) is dict and tuple(rule) == RULE_KEYS and rule["schemaVersion"] == RULE_SCHEMA
            and dict(rule["counts"]) == dict(RULE_COUNTS) and rule["discrepancies"] == []
            and [(row["first"], row["last"]) for row in rule["d"]["bridgedClasses"]["historical_bytes"]]
            == list(HISTORICAL_BYTES_CLASSES), "the identity rule is the frozen record")


def check_ab(value: Any) -> None:
    """M2's record: its closed shape, its numbers (B3 equal to the collected counts; B1 the mean of its per-tree sums;
    B2 within its bounds) and the owner's acceptance of B1 and B4, verbatim."""
    require(type(value) is dict and tuple(value) == AB_KEYS and value["mode"] == AB_MODE
            and value["subject"]["measuredHead"]["commit"] == MEASURED_HEAD, "the A/B record's closed shape")
    collected, b1, b2, b3 = value["collected"], value["B1"], value["B2"], value["B3"]
    require((b3["base"], b3["head"], b3["scaffoldNodeDelta"]) == B3_NODES
            and (collected["base"], collected["head"]) == (b3["base"], b3["head"])
            and b3["head"] == b3["base"] + b3["scaffoldNodeDelta"] + b2["nodes"] and b2["nodes"] <= 700
            and len(b1["baseCpu"]) == len(b1["headCpu"]) == 2 and b1["files"] == b1["inheritedFiles"]
            and round(sum(b1["headCpu"]) / sum(b1["baseCpu"]), 4) == b1["ratio"]
            and b2["cpu"] <= b2["bound"], "the A/B record's numbers are consistent")
    acceptance = value["ownerAcceptance"]
    require(acceptance["decision"] == OWNER_ACCEPTANCE and OWNER_ACCEPTANCE in acceptance["words"]
            and acceptance["accepted"] == ["B1", "B4"] and b1["status"] == value["B4"]["status"] == "owner-accepted",
            "the A/B record carries the owner's acceptance verbatim")


def check_seeded_faults(value: Any) -> None:
    """M3's record: its closed shape, its numbers (the class totals, run plus out of scope), the six collection kills
    exactly the ruled cases, and the owner's scope and the monitor's ruling, verbatim."""
    require(type(value) is dict and tuple(value) == SEEDED_KEYS, "the seeded-faults record's closed shape")
    counts, classes = value["counts"], value["partI"]["classes"]
    require((counts["total"], counts["run"], counts["outOfScope"]) == M3_CASES
            and counts["run"] + counts["outOfScope"] == counts["total"]
            and sum(row["cases"] for row in classes.values()) == counts["total"]
            and sum(row["run"] for row in classes.values()) == counts["run"]
            and sum(row["outOfScope"] for row in classes.values()) == counts["outOfScope"]
            and sum(counts["outOfScopeByClass"].values()) == counts["outOfScope"]
            and all(row["run"] + row["outOfScope"] == row["cases"] and row["fail"] == 0
                    and row["pass"] + row["baseMissed"] + row["headOnlyKilled"] + row["headOnlyMissed"]
                    + row["collectionKilled"] == row["run"] for row in classes.values()),
            "the seeded-faults record's numbers are consistent")
    kills = value["collectionKills"]
    require(tuple(row["case"] for row in kills) == COLLECTION_KILLS
            and sum(row["collectionKilled"] for row in classes.values()) == len(COLLECTION_KILLS)
            and all(row["rc"] == {"base": 4, "head": 4} and row["nodeReports"] == {"base": 0, "head": 0}
                    and row["harnessRawLabel"] == "INVALID" and "bounded regular source file" in row["refusal"]
                    for row in kills), "the six collection kills are exactly the ruled cases")
    require(value["scope"]["decision"] == OWNER_M3_SCOPE and OWNER_M3_SCOPE in value["scope"]["words"]
            and value["partI"]["verdict"]["ruling"] == COLLECTION_RULING and value["partI"]["verdict"]["final"] == "PASS"
            and COLLECTION_WORDS in value["partI"]["words"],
            "the seeded-faults record carries the owner's scope and the monitor's ruling verbatim")


def validate_records() -> dict:
    """The records: the closed directory, every record free of absolute local paths, and each record's shape."""
    check_records_tree(reviewed_tree(RECORD_DIR))
    for path in RECORDS:
        check_record_bytes(path, _verified(path))
    check_cost_report(_json(COST_REPORT))
    check_readme(_verified(README).decode("utf-8"))
    check_decisions(_verified(DECISIONS).decode("utf-8"))
    check_ab(_json(AB))
    check_seeded_faults(_json(SEEDED_FAULTS))
    rule = _json(IDENTITY_RULE)
    check_identity_rule(rule)
    return rule


def check_summary(summary: Any, count: Any) -> None:
    require(type(summary) is dict and summary.get("layers") == CHAIN_LAYERS and summary.get("head") == count
            and summary.get("headModule") == HEAD_MODULE and summary.get("newPacket") == NEW_PACKET,
            "the identity rule ran over this era's whole chain")


def check_totals(totals: Any) -> None:
    require(type(totals) is dict and totals == dict(FACT_TOTALS), "the fact map's totals")


def validate_chain_compaction() -> None:
    """Every reviewed byte first; then the records; then, by the reference model run from this era's bytes, the
    identity rule over this era's chain validators, the conftest's never-shared identity tests, and the C2 shapes and
    fact map over this era's test files; last, this layer's canonical hunks."""
    for path in ERA_SHA256:
        _verified(path)
    rule = validate_records()
    model = _era_model(MODEL, "_met_perf_042_chain_identity")
    count = len(authority()["baselinePackets"]) + 1
    check_summary(model.check(_era_source, _undo_this_layer, rule, count), count)
    check_totals(model.check_record(_era_source, _undo_this_layer, rule, _json(FACT_MAP), HEAD_MODULE, count))
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
            == record["validatorNormalizedSha256"], "chain compaction validator drift")
    paths = sorted((ROOT / "task-packets").glob("*.yaml"))
    old = set(record["baselinePackets"])
    require(len(paths) == 258
            and {path.stem for path in paths} == old | {NEW_PACKET, successor.NEW_PACKET, successor.successor.NEW_PACKET, successor.successor.successor.NEW_PACKET},
            "closed 258-packet catalog retaining the 255-packet checkpoint")
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
            "closed source-only chain-compaction packet and inherited commands")
    require(len(packet["allowedPaths"]) == len(set(packet["allowedPaths"]))
            and set(packet["allowedPaths"]) == set(record["changedFiles"])
            | set(record["newFiles"]) | {AUTHORITY_PATH, VALIDATOR_PATH,
                                         "task-packets/" + NEW_PACKET + ".yaml"},
            "unreviewed or omitted chain-compaction packet path")
    for path, rule in record["changedFiles"].items():
        current = successor.historical_bytes(path, regular_bytes(path))
        require(digest(current) == rule["afterSha256"]
                and digest(historical_bytes(path, current)) == rule["beforeSha256"],
                "unreviewed current source: " + path)
    for path, expected in record["newFiles"].items():
        require(digest(successor.historical_bytes(path, regular_bytes(path))) == expected,
                "new source drift: " + path)
    validate_chain_compaction()


if __name__ == "__main__":
    validate()
    print("Chain compaction valid: 258 current specifications; 255-packet checkpoint and exact 254-packet predecessor; identity rule checked.")
