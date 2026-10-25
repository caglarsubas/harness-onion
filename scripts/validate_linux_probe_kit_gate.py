#!/usr/bin/env python3
"""Validate the MET-GOV-003 evolution surface record version 3 (the Linux probe kit's top-level data directory linux-probe-kit/ classified as CONTRACT_AND_SOURCE; gate material) with the D5a oracle edit, its re-issued identity and the MET-LIVE-004 brief registry entries, and the exact 261-to-260 projection."""
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
    import validate_linux_probe_interface as successor
except ImportError:
    from scripts.safe_yaml import safe_load
    from scripts import validate_linux_probe_interface as successor


ROOT = Path(__file__).resolve().parents[1]
AUTHORITY_PATH = "architecture/linux-probe-kit-gate-authority.json"
AUTHORITY_SHA256 = "bea0416fbd6ebcde23a1040f7635e26799dc3a96ea72d76024ac6af5c704450b"
VALIDATOR_PATH = "scripts/validate_linux_probe_kit_gate.py"
BASE_COMMIT = "b821ed656a9311529d23e443c8d903a17ad309d9"
NEW_PACKET = "MET-GOV-003"
PREVIOUS_PACKET = "MET-LIVE-002"
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
            require(key not in result, "duplicate linux-probe-kit-gate authority member")
            result[key] = value
        return result

    def no_constant(_value: str) -> Any:
        raise ValueError("nonfinite linux-probe-kit-gate authority number")

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
        require(digest(raw) == AUTHORITY_SHA256, "linux probe kit gate history authority digest")
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
    }, "closed linux probe kit gate history authority")
    require(value["schemaVersion"] == "harness.planeon.ai/linux-probe-kit-gate-authority/v1"
            and value["authorityPacket"] == NEW_PACKET
            and value["acceptedBase"] == BASE_COMMIT
            and type(value["baselinePackets"]) is dict
            and len(value["baselinePackets"]) == 260
            and NEW_PACKET not in value["baselinePackets"]
            and type(value["changedFiles"]) is dict
            and type(value["newFiles"]) is dict
            and _sha(value["packetSha256"])
            and _sha(value["validatorNormalizedSha256"]),
            "accepted 260-packet base")
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
    # An exact 260-era byte string is already older than the successor layer.
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


# MET-GOV-003 (roadmap LINUX-PROBE-KIT-GATE; owner decision Q-PK-1 "New data directory (Recommended)"; the lane monitor's
# owner-delegated rulings on the dossier's six questions, all (a), Q-G3-1 (a), Q-G3-CAP (a), MON-261-ORACLE-KEEP,
# MON-261-ORACLE-SLIPS, MON-261-C1-KEEP, MON-261-C2-ADOPT, MON-261-CAND and MON-261-R1-1, with the build rules B-G3-1 and
# B-G3-2) amends MET-GOV-001's evolution surface record to version 3: one CONTRACT_AND_SOURCE prefix entry,
# linux-probe-kit/, appended after release/, so that the Linux probe kit's top-level data directory is data. The record is
# gate material, so the owner approves this packet's exact head. The vectors re-pin only the record's digest; the README
# gains its "Record version 3" paragraphs and the kit's prefix in its class table; the D5a oracle test is scoped to
# version 3 by an oracle agent, and its oracle identity is re-issued in place; and two brief registry entries for the
# probe kit's next packet, MET-LIVE-004/packet and MET-LIVE-004/contract, are appended to the review-record brief registry
# (eight entries after them). Repository bytes are read only through reviewed_bytes, so a later bridged successor
# projects its own edits away first; a path outside this era is refused before it is read, every era file is bound by
# digest on every read, and no directory is listed. The bytes 260 merged of every file this packet changes in an earlier
# contract are reached through this layer's own inverse and bound by digest. Each refusal is a pure check over the values
# read, so every one has a failing case on plain data. Checked here: the freeze (this packet edits no existing file but
# chain validators, tests, the three living catalogs, the record's three files, the oracle identity and the registry); the
# file it adds (its layer test); the changed contract files hold no absolute local path; the adopted contract (the record,
# vectors and README are candidate c3's bytes, c2's record and vectors with c3's README errata, the record pinned; the
# record's change from version 2 is exactly the version and the one appended prefix entry, byte for byte in the record's
# own serialization; the vectors' only change is the re-pinned record digest); the unchanged model, executed from this
# era's verified bytes, over version 3 (its check passes and derives version 2's 31 exact or prefix gate entries; its
# vectors replay with the base's counts; linux-probe-kit/x resolves to CONTRACT_AND_SOURCE and Linux-Probe-Kit/x to no
# class, neither resolving under version 2, and a PR changing only a kit path has approvers LANE_MONITOR and OWNER,
# B-G3-2); the registry (260's merged file with exactly the two MET-LIVE-004 entries appended, each pinning its generic
# brief by sha256, B-G3-1); the oracle edit (two added lines marked MET-GOV-003, nothing else changed) and its re-issued
# identity (binding the edited file, ruling KEEP by the lane monitor; check_tree checks the identity in full, in the
# suite); and the derived gate check (the gate paths among the packet's changed files, by the base record's 31 exact or
# prefix gate entries lower-cased, which equals case-folding on this era's all-ASCII gate entries and paths, are exactly
# the record, the vectors, the README, the oracle identity and the registry, B-G3-1). Last, this layer's own inverse hunks
# are the canonical byte-minimal ones, recomputed from its era's bytes (MET-PERF-040's carried rule).
SURFACE_DIR = "architecture/evolution-surface"
RECORD_PATH = SURFACE_DIR + "/evolution-surface.json"
VECTORS_PATH = SURFACE_DIR + "/vectors.json"
README_PATH = SURFACE_DIR + "/README.md"
SURFACE_MODEL = "scripts/evolution_surface.py"
ORACLE_TEST = "tests/test_evolution_surface_oracle.py"
ORACLE_IDENTITY_PATH = "architecture/review-record/oracle-identity-evolution-surface.json"
REGISTRY_PATH = "architecture/review-record/briefs.json"
BRIEFS_DIR = "architecture/review-briefs"
PACKET_BRIEF = BRIEFS_DIR + "/REVIEW_BRIEF_PACKET.md"
CONTRACT_BRIEF = BRIEFS_DIR + "/REVIEW_BRIEF_CONTRACT.md"
HEAD_TEST = "tests/test_linux_probe_kit_gate.py"
PACKET_PATH = "task-packets/" + NEW_PACKET + ".yaml"
LIVING_CATALOGS = ("docs/MASTER_DEVELOPMENT_PLAN.md", "docs/repositories/00-harness-engineering.md",
                   "task-packets/README.md")
CONTRACT_FILES = (RECORD_PATH, VECTORS_PATH, README_PATH)
# The files of earlier contracts this packet changes: the record's three files, the oracle identity and the registry are
# gate material (B-G3-1's derived gate check names exactly these five); the oracle test is data (ORACLE_TESTS).
GATE_HITS = CONTRACT_FILES + (ORACLE_IDENTITY_PATH, REGISTRY_PATH)
CHANGED_CONTRACT = GATE_HITS + (ORACLE_TEST,)
NEW_FILES = (HEAD_TEST,)
# The adopted contract: candidate c3's bytes, the record pinned by sha256: c2's record and vectors (MON-261-C2-ADOPT) and
# the README with c3's one-sentence errata (packet review r1's R1-1, MON-261-R1-1).
ADOPTED_SHA256 = MappingProxyType({'architecture/evolution-surface/evolution-surface.json': '188c75d4be1b4c0eebfd01b9454873a09c903238ebdc05219126c734b0d245bd',
 'architecture/evolution-surface/vectors.json': 'a3e14943ba93dc2071f1d23f103719b803957299640c5d1630b2600871e091f3',
 'architecture/evolution-surface/README.md': '2dc30a7d2a7c3aee557d60371374a857566a3cdec0b19b174fc5af6d079f7d9f'})
# 260's merged bytes of every earlier contract file this packet changes, reached through this layer's own inverse.
BASE_SHA256 = MappingProxyType({'architecture/evolution-surface/evolution-surface.json': 'b1759fe4bae0d9dc111f0c4ca3cc23e891cf89d572b73929ee01f5ec7616a277',
 'architecture/evolution-surface/vectors.json': '9c0f7cf1eb0f48dab41e322d8cdffba8568a5db2ddc2a31869f6af8dd9985b56',
 'architecture/evolution-surface/README.md': '922b09a56cd09486d3ab98a8abe8c4875774579beafebff14da294d9e87723c5',
 'architecture/review-record/oracle-identity-evolution-surface.json': '0633c76dbc4ad19834df9a43278d2835a78ce741bd55373a22e0066874c3396f',
 'tests/test_evolution_surface_oracle.py': 'b05a8f096958a45ebb3ef1dfb12c99e1af54525a891f8b902416500e2e0712d8',
 'architecture/review-record/briefs.json': 'd359813a0eab9323628d9dc051af40b45e0f643fbea496dd906e8e8d6f964e44'})
# Record version 3 (DESIGN rev 3 section 2): the version, and one prefix entry appended to CONTRACT_AND_SOURCE's paths
# after release/.
RECORD_VERSION = 3
KIT_CLASS = "CONTRACT_AND_SOURCE"
KIT_PREFIX = "linux-probe-kit/"
AFTER_PREFIX = "release/"
GATE_MATERIAL = 31
# The model's replay counts over the record and its vectors, as at the base (DESIGN rev 3 section 3).
SURFACE_REPLAY = MappingProxyType({'decisions': 44,
 'invariants': 31,
 'texts': 5,
 'paths': 23,
 'skip': 8,
 'prs': 9,
 'coverage': 2,
 'requests': 10,
 'derived': 31,
 'consumerCases': 12})
# B-G3-2: the kit prefix's resolution under version 3, and a kit-only PR's approvers.
KIT_PATH = "linux-probe-kit/x"
KIT_CASE_VARIANT = "Linux-Probe-Kit/x"
KIT_PROBES = (KIT_PATH, KIT_CASE_VARIANT)
KIT_APPROVERS = ("LANE_MONITOR", "OWNER")
# The oracle edit (MON-261-ORACLE-KEEP) and its re-issued identity (Q-G3-1 (a)).
ORACLE_SHA256 = "173a0d1a0679cae5c8d79869bd48b1fe1888c40c13efc6ce2d1e5c9e4e86eb4a"
IDENTITY_SHA256 = "3f2c038b9c7ed591af81362d2cecb2543dd515b38c8a6148df4567ba5157a56b"
ORACLE_SCHEMA = "planeon.oracle-identity/v1"
ORACLE_RULING = MappingProxyType({'decision': 'KEEP',
 'by': 'LANE_MONITOR',
 'ref': 'MON-261-ORACLE-KEEP; MON-261-ORACLE-SLIPS',
 'date': '2026-10-23'})
ORACLE_MARK = b"MET-GOV-003"
ORACLE_LINES = 2
# B-G3-1: the two entries appended to 260's merged registry (by digest), in this order, each version 1.
BASE_REGISTRY_SHA256 = "d359813a0eab9323628d9dc051af40b45e0f643fbea496dd906e8e8d6f964e44"
REGISTRY_ENTRIES = (("PACKET", "MET-LIVE-004/packet", PACKET_BRIEF), ("CONTRACT", "MET-LIVE-004/contract", CONTRACT_BRIEF))
# Every file this era's check reads, with its digest: the record's three files, the oracle test and its identity, the
# registry and its two generic briefs, and the model.
ERA_SHA256 = MappingProxyType({
    "architecture/evolution-surface/README.md": "2dc30a7d2a7c3aee557d60371374a857566a3cdec0b19b174fc5af6d079f7d9f",
    "architecture/evolution-surface/evolution-surface.json": "188c75d4be1b4c0eebfd01b9454873a09c903238ebdc05219126c734b0d245bd",
    "architecture/evolution-surface/vectors.json": "a3e14943ba93dc2071f1d23f103719b803957299640c5d1630b2600871e091f3",
    "architecture/review-briefs/REVIEW_BRIEF_CONTRACT.md": "1f09d23451bf265e32e44742ca362dabf5a1090c2208c1349cbf491670798aec",
    "architecture/review-briefs/REVIEW_BRIEF_PACKET.md": "6dcff68d7e6b01823f1740063e94910edcc159a71a6ee803f1b66c62fd06e274",
    "architecture/review-record/briefs.json": "4cc369e76bc3092dd9085b393a79c2d8b641ea47a1ddb61e62c033965544ce62",
    "architecture/review-record/oracle-identity-evolution-surface.json": "3f2c038b9c7ed591af81362d2cecb2543dd515b38c8a6148df4567ba5157a56b",
    "scripts/evolution_surface.py": "f38fa6d00ec5fbbbcab8ff01d0e56824e805327b872dc1e23e579e522a681fd9",
    "tests/test_evolution_surface_oracle.py": "173a0d1a0679cae5c8d79869bd48b1fe1888c40c13efc6ce2d1e5c9e4e86eb4a",
})
# Absolute local path markers, matched case-insensitively; spelled in parts, so this file holds none of them. A marker
# counts when a path character follows it.
LOCAL_PATH_MARKERS = (b"/" + b"users/", b"/" + b"private/", b".local" + b"/state")
PATH_BYTES = b"abcdefghijklmnopqrstuvwxyz0123456789_.-/"


def reviewed_bytes(path: str) -> bytes:
    """This packet's reviewed bytes of path; a bridged successor projects newer bytes back first."""
    return successor.historical_bytes(path, regular_bytes(path))


def _era_bytes(path: Any, raw: Any) -> bytes:
    """An era file's bytes, checked against its era digest; a path outside the era is refused."""
    expected = ERA_SHA256.get(path) if type(path) is str else None
    require(expected is not None, "MET-GOV-003 reviewed bytes are bound: " + str(path))
    require(type(raw) is bytes and digest(raw) == expected, "unreviewed LINUX-PROBE-KIT-GATE source: " + path)
    return raw


def _verified(path: str) -> bytes:
    """reviewed_bytes, checked against its era digest on every read; a path outside the era is refused before it is
    read."""
    require(type(path) is str and path in ERA_SHA256, "MET-GOV-003 reviewed bytes are bound: " + str(path))
    return _era_bytes(path, reviewed_bytes(path))


def _json(path: str) -> Any:
    return parse(_verified(path))


def _holds(check: Any) -> bool:
    """A structural check over this era's data; a malformed value does not hold."""
    try:
        return check() is True
    except (KeyError, TypeError, AttributeError, IndexError, ValueError):
        return False


def _bound(check: Any, message: str) -> None:
    require(_holds(check), message)


def _local_path(raw: bytes) -> bool:
    """Whether raw holds an absolute local path: a marker, case-insensitively, followed by a path character."""
    low = raw.lower()
    for marker in LOCAL_PATH_MARKERS:
        at = low.find(marker)
        while at >= 0:
            end = at + len(marker)
            if end < len(low) and low[end:end + 1] in PATH_BYTES:
                return True
            at = low.find(marker, at + 1)
    return False


def _era_model(path: str, name: str) -> types.ModuleType:
    """A standard-library reference module of this era, executed from its verified bytes (no import, no bytecode)."""
    module = types.ModuleType(name)
    module.__file__ = str(ROOT / path)
    exec(compile(_verified(path), path, "exec", dont_inherit=True), module.__dict__)
    return module


def era_model() -> types.ModuleType:
    """The evolution surface model, executed from this era's verified bytes."""
    return _era_model(SURFACE_MODEL, "_met_gov_003_evolution_surface")


def check_freeze(changed: Any) -> None:
    """This packet edits no existing file but chain validators (scripts/validate_*.py, one level deep), tests, the three
    living catalogs, the record's three files, the oracle identity and the registry: no model, no other earlier contract
    or record and no conftest change."""
    for path in list(changed):
        require(type(path) is str and path not in ("conftest.py", "tests/conftest.py")
                and ((path.startswith("scripts/validate_") and path.endswith(".py") and path.count("/") == 1)
                     or path.startswith("tests/") or path in LIVING_CATALOGS or path in CHANGED_CONTRACT),
                "this packet edits only chain validators, tests, the three living catalogs, the record's three files, "
                "the oracle identity and the registry: " + str(path))


def check_new_files(added: Any) -> None:
    """The packet adds exactly its layer test (the layer, its authority and the packet are the chain's own files)."""
    _bound(lambda: type(added) is list and added == list(NEW_FILES), "this packet adds exactly its layer test")


def check_private(path: str, raw: Any) -> None:
    """An earlier contract file this packet changes holds no absolute local path."""
    require(type(raw) is bytes and not _local_path(raw),
            "no absolute local path in a contract file this packet changes: " + path)


def validate_files() -> None:
    """The freeze and the file this packet adds, from this era's authority; the changed contract files are private."""
    record = authority()
    check_freeze(list(_PROJECTION_RULES))
    check_new_files(list(record["newFiles"]))
    for path in CHANGED_CONTRACT:
        check_private(path, _verified(path))


def check_adopted(files: Any) -> None:
    """The record, the vectors and the README are candidate c3's bytes (MON-261-C2-ADOPT, MON-261-R1-1); the record is
    pinned."""
    for path in ADOPTED_SHA256:
        require(type(files) is dict and type(files.get(path)) is bytes and digest(files[path]) == ADOPTED_SHA256[path],
                "the record, vectors and README are the adopted c3 bytes: " + path)


def check_before(path: str, raw: Any) -> None:
    """260's merged bytes of an earlier contract file this packet changes, reached through this layer's own inverse."""
    require(path in BASE_SHA256 and type(raw) is bytes and digest(raw) == BASE_SHA256[path],
            "260's merged bytes are bound: " + path)


def _serialized(value: Any) -> bytes:
    """The record's own serialization: one-space indent, ASCII escapes, the key order kept, a final newline."""
    return (json.dumps(value, indent=1) + "\n").encode("ascii")


def _with_kit(record: Any) -> Any:
    """Version 2 with exactly version 3's two changes: the version, and the kit's prefix entry appended to
    CONTRACT_AND_SOURCE's paths; nothing else, and no key moved."""
    programme = record["levels"]["programme"]
    classes = [dict(item, paths=item["paths"] + [{"prefix": KIT_PREFIX}]) if item["id"] == KIT_CLASS else item
               for item in programme["classes"]]
    return dict(record, version=RECORD_VERSION, levels=dict(record["levels"], programme=dict(programme, classes=classes)))


def check_record(raw: Any, before: Any) -> None:
    """The record's change from 260's merged version 2 is exactly /version 2 -> 3 and one CONTRACT_AND_SOURCE prefix
    entry, linux-probe-kit/, appended after release/, byte for byte in the record's own serialization."""
    _bound(lambda: (lambda record, base: base["version"] == 2 and record["version"] == RECORD_VERSION
                    and [item["paths"][-1] for item in base["levels"]["programme"]["classes"]
                         if item["id"] == KIT_CLASS] == [{"prefix": AFTER_PREFIX}]
                    and record == _with_kit(base) and _serialized(base) == before
                    and _serialized(_with_kit(base)) == raw)(parse(raw), parse(before)),
           "the record's change from version 2 is exactly the version and the kit prefix entry after release/")


def check_vectors(raw: Any, before: Any, record_digest: Any, base_digest: Any) -> None:
    """The vectors' only change from 260's merged bytes is the re-pinned record digest: version 2's digest occurs once
    there, and putting version 3's in its place gives these bytes."""
    _bound(lambda: type(raw) is bytes and type(before) is bytes and type(record_digest) is str
           and type(base_digest) is str and record_digest != base_digest
           and parse(before)["recordDigest"] == base_digest and parse(raw)["recordDigest"] == record_digest
           and before.count(base_digest.encode("ascii")) == 1
           and before.replace(base_digest.encode("ascii"), record_digest.encode("ascii")) == raw,
           "the vectors' only change is the re-pinned record digest")


def check_gate_list(gate: Any, base_gate: Any) -> None:
    """The model derives version 2's gate list from version 3: 31 entries, each an exact path or a prefix (no
    under-plus-name entry is left in the derived list at this era)."""
    _bound(lambda: type(gate) is list and gate == base_gate and len(gate) == GATE_MATERIAL
           and all(type(entry) is dict and len(entry) == 1 and ("exact" in entry or "prefix" in entry)
                   for entry in gate),
           "the model derives version 2's 31 exact or prefix gate entries from version 3")


def _replays(model: Any, *args: Any) -> Any:
    """The model's replay counts, or None when a vector mismatches (the model raises its own Mismatch, a subclass of
    AssertionError raised explicitly, so that python -O cannot skip it)."""
    try:
        return model.replay(*args)
    except AssertionError:
        return None


def check_replay(counts: Any) -> None:
    """The model replays the re-pinned vectors over version 3 with the base's row counts."""
    _bound(lambda: counts == dict(SURFACE_REPLAY),
           "the model replays the re-pinned vectors over version 3 with the base's counts")


def _approvers(record: Any, cls: Any) -> Any:
    """The approvers of a PR whose only changed path resolves to `cls`: that class's approve set, sorted, as the model's
    pr_approvers gives them for one path; None for no class."""
    if cls is None:
        return None
    return sorted([item for item in record["levels"]["programme"]["classes"]
                   if item["id"] == cls][0]["operations"]["approve"])


def check_kit(resolved: Any, base_resolved: Any, approvers: Any) -> None:
    """B-G3-2: under version 3, linux-probe-kit/x resolves to CONTRACT_AND_SOURCE and Linux-Probe-Kit/x to no class;
    under version 2 neither resolves; and a PR whose only changed path is under linux-probe-kit/ has approvers
    LANE_MONITOR and OWNER."""
    _bound(lambda: resolved == {KIT_PATH: KIT_CLASS, KIT_CASE_VARIANT: None}
           and base_resolved == {KIT_PATH: None, KIT_CASE_VARIANT: None} and approvers == list(KIT_APPROVERS),
           "linux-probe-kit/x is CONTRACT_AND_SOURCE, Linux-Probe-Kit/x no class, and a kit-only PR has approvers "
           "LANE_MONITOR and OWNER")


def validate_contract(es: Any) -> None:
    """The adopted record, vectors and README; the record's and the vectors' change from 260's merged bytes; the
    unchanged model over version 3: its check, its derived gate list, its replay and the kit prefix's resolution."""
    files = {path: _verified(path) for path in CONTRACT_FILES}
    check_adopted(files)
    before = {path: _undo_this_layer(path, files[path]) for path in CONTRACT_FILES}
    for path in CONTRACT_FILES:
        check_before(path, before[path])
    check_record(files[RECORD_PATH], before[RECORD_PATH])
    record, base = parse(files[RECORD_PATH]), parse(before[RECORD_PATH])
    facts, base_facts = es.check(record), es.check(base)
    check_vectors(files[VECTORS_PATH], before[VECTORS_PATH], facts["digest"], base_facts["digest"])
    check_gate_list(facts["gateMaterial"], base_facts["gateMaterial"])
    check_replay(_replays(es, record, parse(files[VECTORS_PATH])))
    check_kit({path: es.resolve(record, path) for path in KIT_PROBES},
              {path: es.resolve(base, path) for path in KIT_PROBES}, _approvers(record, es.resolve(record, KIT_PATH)))


def check_registry(raw: Any, base_raw: Any, briefs: Any) -> None:
    """The registry is 260's merged file (by digest) with exactly the two MET-LIVE-004 entries appended, each pinning its
    generic brief by the sha256 of the brief's bytes, in the registry's own serialization; its schema and kinds are
    unchanged."""
    _bound(lambda: type(base_raw) is bytes and digest(base_raw) == BASE_REGISTRY_SHA256
           and (lambda registry, base: tuple(registry) == tuple(base)
                and registry["schemaVersion"] == base["schemaVersion"] and registry["kinds"] == base["kinds"]
                and registry["briefs"] == base["briefs"] + [
                    {"kind": kind, "series": series, "path": path, "sha256": digest(briefs[path]), "version": 1}
                    for kind, series, path in REGISTRY_ENTRIES]
                and _serialized(registry) == raw)(parse(raw), parse(base_raw)),
           "the registry is 260's with exactly the two MET-LIVE-004 entries appended, each pinning its brief")


def validate_registry() -> None:
    """briefs.json against 260's merged bytes (this layer's own inverse) and the two generic briefs."""
    raw = _verified(REGISTRY_PATH)
    base = _undo_this_layer(REGISTRY_PATH, raw)
    check_before(REGISTRY_PATH, base)
    check_registry(raw, base, {path: _verified(path) for path in (PACKET_BRIEF, CONTRACT_BRIEF)})


def check_oracle(identity_raw: Any, oracle_raw: Any) -> None:
    """The D5a oracle file is the oracle agent's edit, and the re-issued identity binds it, with ruling KEEP by the lane
    monitor (MON-261-ORACLE-KEEP; MON-261-ORACLE-SLIPS); check_tree checks the identity in full, in the suite."""
    _bound(lambda: type(oracle_raw) is bytes and digest(oracle_raw) == ORACLE_SHA256
           and type(identity_raw) is bytes and digest(identity_raw) == IDENTITY_SHA256
           and (lambda identity: identity["schemaVersion"] == ORACLE_SCHEMA
                and identity["file"] == {"path": ORACLE_TEST, "sha256": digest(oracle_raw)}
                and identity["ruling"] == dict(ORACLE_RULING))(parse(identity_raw)),
           "the oracle file is the agent's edit, and the re-issued identity binds it with ruling KEEP by the lane "
           "monitor")


def check_oracle_edit(raw: Any, before: Any) -> None:
    """The oracle agent's edit adds exactly two lines to 260's merged oracle file, each marked MET-GOV-003, and changes or
    removes no line."""
    _bound(lambda: type(raw) is bytes and type(before) is bytes and ORACLE_MARK not in before
           and len([line for line in raw.splitlines(keepends=True) if ORACLE_MARK in line]) == ORACLE_LINES
           and b"".join(line for line in raw.splitlines(keepends=True) if ORACLE_MARK not in line) == before,
           "the oracle edit adds exactly two MET-GOV-003 lines to 260's oracle file")


def validate_oracle() -> None:
    """The oracle file and its re-issued identity; the edit against 260's merged oracle file (this layer's own inverse)."""
    oracle = _verified(ORACLE_TEST)
    check_oracle(_verified(ORACLE_IDENTITY_PATH), oracle)
    for path in (ORACLE_IDENTITY_PATH, ORACLE_TEST):
        check_before(path, _undo_this_layer(path, _verified(path)))
    check_oracle_edit(oracle, _undo_this_layer(ORACLE_TEST, oracle))


def gate_paths(gate: list, paths: list) -> list:
    """The paths a gate entry matches: an exact path, or a path under a prefix, each compared lower-cased, which equals
    case-folding on this era's all-ASCII gate entries and changed paths (260's packet review r1's R1-2)."""
    return [path for path in paths
            if any(("exact" in entry and path.lower() == entry["exact"].lower())
                   or ("prefix" in entry and path.lower().startswith(entry["prefix"].lower())) for entry in gate)]


def check_gate_hits(gate: Any, changed: Any) -> None:
    """B-G3-1's derived gate check: the gate paths among the packet's changed files, by the base record's gate entries,
    are exactly the record, the vectors, the README, the oracle identity and the registry."""
    _bound(lambda: type(changed) is list and changed == sorted(changed)
           and gate_paths(gate, changed) == sorted(GATE_HITS),
           "the gate paths among the changed files are exactly the record, vectors, README, oracle identity and "
           "registry")


def validate_gate(es: Any) -> None:
    """The gate list derived from the base record (version 2, through this layer's own inverse) against the packet's
    changed files."""
    base = parse(_undo_this_layer(RECORD_PATH, _verified(RECORD_PATH)))
    gate = es.check(base)["gateMaterial"]
    record = authority()
    check_gate_hits(gate, sorted(set(record["changedFiles"]) | set(record["newFiles"])
                                 | {AUTHORITY_PATH, VALIDATOR_PATH, PACKET_PATH}))


def validate_linux_probe_kit_gate() -> None:
    """Every reviewed byte first; then the freeze and the file this packet adds, the adopted contract under the unchanged
    model, the registry, the oracle edit and its identity, and the derived gate check; last, this layer's canonical
    hunks."""
    for path in ERA_SHA256:
        _verified(path)
    validate_files()
    es = era_model()
    validate_contract(es)
    validate_registry()
    validate_oracle()
    validate_gate(es)
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
            == record["validatorNormalizedSha256"], "linux probe kit gate validator drift")
    paths = sorted((ROOT / "task-packets").glob("*.yaml"))
    old = set(record["baselinePackets"])
    require(len(paths) == 266
            and {path.stem for path in paths} == old | {NEW_PACKET, successor.NEW_PACKET, successor.successor.NEW_PACKET, successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.NEW_PACKET},
            "closed 266-packet catalog retaining the 261-packet checkpoint")
    packets = {}
    for path in paths:
        if path.stem in (successor.NEW_PACKET, successor.successor.NEW_PACKET, successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.NEW_PACKET):
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
            "closed source-only linux-probe-kit-gate packet and inherited commands")
    require(len(packet["allowedPaths"]) == len(set(packet["allowedPaths"]))
            and set(packet["allowedPaths"]) == set(record["changedFiles"])
            | set(record["newFiles"]) | {AUTHORITY_PATH, VALIDATOR_PATH,
                                         "task-packets/" + NEW_PACKET + ".yaml"},
            "unreviewed or omitted linux-probe-kit-gate packet path")
    for path, rule in record["changedFiles"].items():
        current = successor.historical_bytes(path, regular_bytes(path))
        require(digest(current) == rule["afterSha256"]
                and digest(historical_bytes(path, current)) == rule["beforeSha256"],
                "unreviewed current source: " + path)
    for path, expected in record["newFiles"].items():
        require(digest(successor.historical_bytes(path, regular_bytes(path))) == expected,
                "new source drift: " + path)
    validate_linux_probe_kit_gate()


if __name__ == "__main__":
    validate()
    print("Linux probe kit gate valid: 266 current specifications; 261-packet checkpoint and exact 260-packet predecessor; contract reviewed.")
