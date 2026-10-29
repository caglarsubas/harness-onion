#!/usr/bin/env python3
"""Validate the MET-LIVE-004 workload profile v2 and admission semantics v4 (LPK-1) as one combined contract, adopted as candidate c3 after its in-tree CONTRACT rounds 1 and 2 (the models over their vectors, v3 frozen, the non-chain pinned files byte-identical and the chain validators and tests in the pin lists changed only by the chain-bump vocabulary under B-L1-3; DATA_CHECK_ONLY, no gate path) with its D5a oracles and B-L1-4's pins record, and the exact 263-to-262 projection."""
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
    import validate_met_linux_009 as successor
except ImportError:
    from scripts.safe_yaml import safe_load
    from scripts import validate_met_linux_009 as successor


ROOT = Path(__file__).resolve().parents[1]
AUTHORITY_PATH = "architecture/linux-probe-kit-admission-authority.json"
AUTHORITY_SHA256 = "b4751622938a2322a1df09f1562085bc2e9e14c3c3833d89591268f983c97db6"
VALIDATOR_PATH = "scripts/validate_linux_probe_kit_admission.py"
BASE_COMMIT = "0ffa7db076a92e8bb341db4867557b894ecb5b27"
NEW_PACKET = "MET-LIVE-004"
PREVIOUS_PACKET = "MET-LIVE-003"
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
            require(key not in result, "duplicate linux-probe-kit-admission authority member")
            result[key] = value
        return result

    def no_constant(_value: str) -> Any:
        raise ValueError("nonfinite linux-probe-kit-admission authority number")

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
        require(digest(raw) == AUTHORITY_SHA256, "linux probe kit admission history authority digest")
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
    }, "closed linux probe kit admission history authority")
    require(value["schemaVersion"] == "harness.planeon.ai/linux-probe-kit-admission-authority/v1"
            and value["authorityPacket"] == NEW_PACKET
            and value["acceptedBase"] == BASE_COMMIT
            and type(value["baselinePackets"]) is dict
            and len(value["baselinePackets"]) == 262
            and NEW_PACKET not in value["baselinePackets"]
            and type(value["changedFiles"]) is dict
            and type(value["newFiles"]) is dict
            and _sha(value["packetSha256"])
            and _sha(value["validatorNormalizedSha256"]),
            "accepted 262-packet base")
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
    # An exact 262-era byte string is already older than the successor layer.
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


# MET-LIVE-004 (roadmap LINUX-PROBE-KIT-ADMISSION, LPK-1; owner decisions Q-PK-3 "Never, pinned (Recommended)", Q-PK-4
# "Upstream v1.37.1 (Recommended)" and "As steps (Recommended)"; the lane monitor's owner-delegated rulings, among them
# Q-LPK1-1 to Q-LPK1-12, Q-LPK1-D1 to Q-LPK1-D5, MON-LPK1-ADOPT-REV4, MON-LPK1-B3, MON-LPK1-SCHEMA-RUN,
# MON-LPK1-C3-ADOPT, MON-LPK1-ORACLE-R2 and MON-LPK1-B6-P1) publishes workload profile v2 and admission semantics v4 as one
# combined contract, adopted as candidate c3 after the in-tree CONTRACT rounds 1 and 2 of the MET-LIVE-004/contract
# series: architecture/admission-semantics-v4/ (README, allowlists, vectors, status and the sealed A2 file
# admission-manifests/planeon-a2.json) with its model scripts/admission_semantics_v4.py, architecture/proxy-profile-v2/
# (README, the closed profile v2 schema, vectors and status) with its model scripts/proxy_profile_v2.py, and the combined
# review set architecture/linux-probe-kit-admission/ (source-index.json, the two published rounds with their identities,
# the two D5a oracle identities and B-L1-4's mechanics-pins.json), with the two D5a oracle tests. Every non-chain file of
# design section 7's pin list stays byte-identical (admission v3 and v2, profile v1 and its amendment, I01's records, the
# plans, the edge records and the others), and the chain validators and tests among them change only by the chain-bump
# vocabulary, under the step rule (B-L1-3).
# It is data only, and no gate path: it changes no earlier contract, the review-record brief registry or the evolution
# surface record. Repository bytes and modes are read only through reviewed_bytes and reviewed_mode, so a later bridged
# successor projects its own edits away first; a path outside this era is refused before it is read, every era file is
# bound by digest on every read, and no directory is listed. Each refusal is a pure check over the values read, so every
# one has a failing case on plain data. Checked here: the freeze (this packet edits no existing file but chain validators,
# tests and the three living catalogs); the files this packet adds (exactly its own, each once; git mode 100644; no
# absolute local path); the adoption (both status records' closed shape and values: ADOPTED_DATA_CONTRACT, candidate c3,
# CONTRACT rounds 1 and 2 bound to their published records and identities, adoption MON-LPK1-C3-ADOPT, LPK-0's record by
# this era's digest; each round's record and identity; the source index's in-tree rounds; the two oracle identities, each
# binding its oracle test with ruling KEEP); the models over their vectors, each model executed from this era's verified
# bytes (v4's 141 cases through admission_semantics_v4, v3's 114 through the frozen admission_semantics_v3, the sealed A2
# file and its directory hash reproduced, and profile v2's 67 cases through proxy_profile_v2, with B-L1-1's P01 text for
# K01 and K01b and the cross-contract group through both admission models); the pins (B-L1-4's record: every
# byte-identical pin equal to its era bytes, every step-rule pin a chain file whose recorded predecessor bytes are this
# packet's inverse's, and every evolution-surface class re-derived by the era's model); the registry (261's merged
# briefs.json, unchanged, with this packet's PACKET and CONTRACT series); and the derived gate check (the gate paths among
# the packet's changed files, by the evolution surface record's 31 exact or prefix gate entries lower-cased, which equals
# case-folding on this era's all-ASCII gate entries and paths, are none). Last, this layer's own inverse hunks are the
# canonical byte-minimal ones, recomputed from its era's bytes (MET-PERF-040's carried rule).
V4_DIR = "architecture/admission-semantics-v4/"
P2_DIR = "architecture/proxy-profile-v2/"
SET_DIR = "architecture/linux-probe-kit-admission/"
V4_README = V4_DIR + "README.md"
V4_SEALED = V4_DIR + "admission-manifests/planeon-a2.json"
V4_ALLOWLISTS = V4_DIR + "allowlists.json"
V4_STATUS = V4_DIR + "status.json"
V4_VECTORS = V4_DIR + "vectors.json"
P2_README = P2_DIR + "README.md"
P2_SCHEMA = P2_DIR + "profile.schema.json"
P2_STATUS = P2_DIR + "status.json"
P2_VECTORS = P2_DIR + "vectors.json"
V4_MODEL = "scripts/admission_semantics_v4.py"
P2_MODEL = "scripts/proxy_profile_v2.py"
V3_MODEL = "scripts/admission_semantics_v3.py"
V3_VECTORS = "architecture/admission-semantics-v3/vectors.json"
SOURCE_INDEX = SET_DIR + "source-index.json"
V4_ORACLE = "tests/test_admission_semantics_v4_oracle.py"
P2_ORACLE = "tests/test_proxy_profile_v2_oracle.py"
V4_ORACLE_IDENTITY = SET_DIR + "oracle-identity-admission-v4.json"
P2_ORACLE_IDENTITY = SET_DIR + "oracle-identity-profile-v2.json"
ROUNDS = (1, 2)
REVIEW_RECORDS = tuple(SET_DIR + "review-round%d.json" % n for n in ROUNDS)
REVIEW_IDENTITIES = tuple(SET_DIR + "review-identity-round%d.json" % n for n in ROUNDS)
PINS_PATH = SET_DIR + "mechanics-pins.json"
HEAD_TEST = "tests/test_linux_probe_kit_admission.py"
PACKET_PATH = "task-packets/" + NEW_PACKET + ".yaml"
# The adopted contract (candidate c3, MON-LPK1-C3-ADOPT), the combined review set and the two D5a oracle tests.
CONTRACT_FILES = (V4_README, V4_SEALED, V4_ALLOWLISTS, V4_STATUS, V4_VECTORS, P2_README, P2_SCHEMA, P2_STATUS, P2_VECTORS,
                  V4_MODEL, P2_MODEL)
SET_FILES = (SOURCE_INDEX, V4_ORACLE_IDENTITY, P2_ORACLE_IDENTITY) + REVIEW_RECORDS + REVIEW_IDENTITIES + (PINS_PATH,)
ORACLE_TESTS = (V4_ORACLE, P2_ORACLE)
NEW_FILES = CONTRACT_FILES + SET_FILES + ORACLE_TESTS
LIVING_CATALOGS = ("docs/MASTER_DEVELOPMENT_PLAN.md", "docs/repositories/00-harness-engineering.md",
                   "task-packets/README.md")
LPK0_RECORD = "architecture/probe-kit-scope/amendment.json"
REGISTRY_PATH = "architecture/review-record/briefs.json"
PACKET_BRIEF = "architecture/review-briefs/REVIEW_BRIEF_PACKET.md"
CONTRACT_BRIEF = "architecture/review-briefs/REVIEW_BRIEF_CONTRACT.md"
SURFACE_RECORD = "architecture/evolution-surface/evolution-surface.json"
SURFACE_MODEL = "scripts/evolution_surface.py"
GATE_MATERIAL = 31
# The status records written at adoption: their closed key sets and the values this check restates.
STATUS_SCHEMAS = MappingProxyType({V4_STATUS: "planeon.internal.admission-semantics-v4-status/v1",
                                   P2_STATUS: "planeon.internal.proxy-profile-v2-status/v1"})
STATUS_KEYS = MappingProxyType({V4_STATUS: ('schemaVersion',
 'semantics',
 'supersedes',
 'packet',
 'workItem',
 'candidate',
 'base',
 'reviewSeries',
 'reviewRounds',
 'combinedReview',
 'designHistory',
 'contractState',
 'ownerDecisions',
 'obligations',
 'nativeAcceptance',
 'tenantAcceptance',
 'sealed',
 'nonClaims',
 'carried',
 'predecessorRecord',
 'readmeStatusNote',
 'admissionConfigurationInstalled',
 'signerImplemented',
 'distributionSelected',
 'productExecution',
 'runnerActivated',
 'phaseComplete',
 'independentReviewer',
 'adoption'),
                                P2_STATUS: ('schemaVersion',
 'profileId',
 'supersedes',
 'successorBeside',
 'packet',
 'workItem',
 'candidate',
 'base',
 'reviewSeries',
 'reviewRounds',
 'combinedReview',
 'designHistory',
 'contractState',
 'ownerDecisions',
 'evidenceClass',
 'nativeAcceptance',
 'nonClaims',
 'carried',
 'predecessorRecord',
 'readmeStatusNote',
 'installed',
 'wireProfile',
 'independentReviewer',
 'adoption')})
WORK_ITEM = "LINUX-PROBE-KIT-ADMISSION"
SERIES = NEW_PACKET + "/contract"
CANDIDATE = "c3"
CONTRACT_STATE = "ADOPTED_DATA_CONTRACT"
COMBINED_REVIEW = (V4_DIR, P2_DIR)
INDEPENDENT_REVIEWER = "SEPARATE_AGENT_NOT_AUTHOR"
ADOPTION = MappingProxyType({'ruling': 'MON-LPK1-C3-ADOPT',
 'by': 'LANE_MONITOR',
 'date': '2026-10-24',
 'candidate': 'c3',
 'candidateCommit': '50855a796fdbb22241900c9ef4d37be0967fbd2d',
 'check': 'ADOPTION_CHECK_C3 3a044b876a273e2e6da609ed2e367e9b19d458bae9f134f54b903347d937b523 (kept with the '
          "lane's records)"})
# The two CONTRACT rounds: verdicts and subject commits (round 2's base is round 1's subject).
ROUND_VERDICTS = ("CHANGES_REQUIRED", "PASS_FOR_ADOPTION")
ROUND_SUBJECTS = ("329a8d96697ff4232a75f5ed801bdc7f71021969", "5c32adc74e493ac38d5864689a523a20cc0c513c")
RECORD_SCHEMA = "planeon.review-record/v2"
IDENTITY_SCHEMA = "planeon.review-identity/v2"
INDEX_SCHEMA = "planeon.internal.linux-probe-kit-admission-index/v1"
DESIGN_PROOF = "the author's design proof (local, not published)"
# The D5a oracle identities (MON-LPK1-ORACLE-V4-KEEP, MON-LPK1-ORACLE-P2-KEEP, MON-LPK1-ORACLE-R2), each binding its test.
ORACLE_SCHEMA = "planeon.oracle-identity/v1"
ORACLE_COMMIT = "4ff0a830690a824d97e33b10b253a80b04b8f688"
ORACLE_BINDINGS = MappingProxyType({V4_ORACLE_IDENTITY: V4_ORACLE, P2_ORACLE_IDENTITY: P2_ORACLE})
ORACLE_RULINGS = MappingProxyType({V4_ORACLE_IDENTITY: {'decision': 'KEEP',
 'by': 'LANE_MONITOR',
 'ref': 'MON-LPK1-ORACLE-V4-KEEP; MON-LPK1-ORACLE-R2',
 'date': '2026-10-24'},
                                  P2_ORACLE_IDENTITY: {'decision': 'KEEP',
 'by': 'LANE_MONITOR',
 'ref': 'MON-LPK1-ORACLE-P2-KEEP; MON-LPK1-ORACLE-R2',
 'date': '2026-10-24'}})
# The models' vectors: v4's 141 cases, v3's 114 (each group by its count) and profile v2's 67.
V4_COUNTS = MappingProxyType({"manifest": 47, "endToEnd": 23, "finalObject": 30, "objects": 11, "directoryHash": 4,
                              "claims": 26})
V3_COUNTS = MappingProxyType({"manifest": 36, "endToEnd": 19, "finalObject": 24, "objects": 9, "directoryHash": 4,
                              "claims": 22})
POSITIVES = ("Pod", "PodInit", "PodEnv", "PodVol", "ConfigMap", "Service")
P2_COUNTS = MappingProxyType({"positive": 1, "negative": 50, "crossContract": 16, "total": 67})
# The sealed v4 A2 file and its directory hash (design rev 4 section 3.6; the v4 README).
SEALED_SIZE = 8322
SEALED_SHA256 = "92c21612304cb704d13b506c1ae885d62a47c01f0ed0d284affe563aa1868e32"
DIRECTORY_HASH = "sha256:9b1ddc1096ff0d35fb4cd5a9e5e6b4248fefc5b75b5a06f862c59d85e028ca60"
SEALED_NAME = "planeon-a2.json"
V3_SEMANTICS = "POLICY-ADMISSION-SEMANTICS/v3"
# Profile v2's refusal texts this check reads (the test checks each equals the model's own): B-L1-1's one P01 text, which
# K01 and K01b expect exactly and the README states verbatim, and the cross-contract precondition's P40 and P99.
P01_TEXT = ('P01 the profile holds a non-data value (any number parsed as a float, integral or not) or exceeds the '
 'depth, size-budget, integer-range or canonical-size bounds')
P01_CASES = ("K01", "K01b")
P40_TEXT = "P40 the binding namespace is not the sealed qualification namespace"
P99_TEXT = "P99 malformed profile data"
# B-L1-4's pins record (MON-LPK1-B6-P1): closed, its own schemaVersion and exactly two more members.
PINS_SCHEMA = "planeon.internal.linux-probe-kit-admission-pins/v1"
PINS_KEYS = ("schemaVersion", "unchangedPins", "evolutionSurfaceClasses")
PIN_KEYS = ("path", "lists", "sha256", "rule")
PIN_COUNTS = MappingProxyType({"BYTE_IDENTICAL": 70, "STEP_RULE": 7})
PIN_LISTS = ("F5.1", "F5.2", "F5.3", "F5.4", "F5.5", "F5.6", "F5.7", "F5.8", "PPS", "PPV", "PCA", "BASELINE", "F2.7")
CLASS_FORMS = ("path", "prefix", "pattern")
CLASS_NAMES = ("CONTRACT_AND_SOURCE", "ORACLE_TESTS", "REVIEW_RECORD")
CLASS_SOURCES = ("DESIGN_REV4_SECTION_2", "B-L1-4", "BASE_DERIVATION")
CLASS_ROWS = 18
# The registry is 261's merged file, unchanged: 261 registered this packet's PACKET and CONTRACT series.
REGISTRY_SHA256 = "4cc369e76bc3092dd9085b393a79c2d8b641ea47a1ddb61e62c033965544ce62"
REGISTRY_ENTRIES = (("PACKET", NEW_PACKET + "/packet", PACKET_BRIEF), ("CONTRACT", NEW_PACKET + "/contract", CONTRACT_BRIEF))
# Every file this era's check reads, with its digest: the files this packet adds, the byte-identical pins (the frozen v3
# model and vectors among them), LPK-0's merged record, the registry and the two generic briefs, and the evolution surface
# record and its model.
ERA_SHA256 = MappingProxyType({
    "architecture/admission-channel-v3-authority.json": "e6af6ae19a07090bd3b3f9a6c5735e6ca35ebd59aa4447866a08f49af51076df",
    "architecture/admission-semantics-v2/admission-manifests/planeon-a2.json": "1096b3cc71c4fe6b5a17ed61e8bf8c17ee17fcf52b192503534d60aed9ce4741",
    "architecture/admission-semantics-v3/README.md": "c3106482b4ff79649cbef7c65797c6fcd6b64f8419e871ae7d89eecad3ff98ab",
    "architecture/admission-semantics-v3/admission-manifests/planeon-a2.json": "1096b3cc71c4fe6b5a17ed61e8bf8c17ee17fcf52b192503534d60aed9ce4741",
    "architecture/admission-semantics-v3/allowlists.json": "9314cd0732880a8e6af91df562af0a392183f6ef078c12fa9b479f6953fad5d4",
    "architecture/admission-semantics-v3/status.json": "65fedb6284ae7ee70686166db0bcf0f2fdf37756b59ee3f3f8267b25b0ccfda7",
    "architecture/admission-semantics-v3/vectors.json": "a3e2dc9818742ae2188e0e83cf91bb833be836115975b3fb23d5f280f6928cc1",
    "architecture/admission-semantics-v4/README.md": "f7794aa857aa50800f05b651f7b0a56eda7407f67855bc2f0437b27b3fe297fa",
    "architecture/admission-semantics-v4/admission-manifests/planeon-a2.json": "92c21612304cb704d13b506c1ae885d62a47c01f0ed0d284affe563aa1868e32",
    "architecture/admission-semantics-v4/allowlists.json": "e399f5bbe4c5e84659693efa22f0d943e6a64ec291d3fa51dbf9c0614501e7f7",
    "architecture/admission-semantics-v4/status.json": "f2557234c7cb48f6b36c206a0730e6c7bf501fb6cc3d444e323afb9b6e2e78d4",
    "architecture/admission-semantics-v4/vectors.json": "5706b1a8df5cabd978caa219400b40a9c4ef6cbdbca8ea2f7c6f69b69474301c",
    "architecture/artifact-edges/operator-harness-engineering-v10.json": "a4fad53dfadbe8a5d79d4049fbba83173adaacec8d33df5ca377aa288539364e",
    "architecture/artifact-edges/operator-harness-engineering-v4.json": "e30772ff8826650c46d1a8d384625929975e47f2de5cc9030680b5fdb5e7fc86",
    "architecture/artifact-edges/operator-harness-engineering-v5.json": "89b47ef8f865b31911eb8da2b08a5a3c22b2d92a62599cb6fdfccbfe7f79e3c0",
    "architecture/artifact-edges/operator-harness-engineering-v6.json": "0ac7c2da62de87837f5a36a967a2c5b9c286ecab2e03f335a8eebbd32df9d24d",
    "architecture/artifact-edges/operator-harness-engineering-v7.json": "6af45e361a66331a9ee0216d3eea42f3a17770fd3c7d33e78e2a025d301bfa92",
    "architecture/artifact-edges/operator-harness-engineering-v8.json": "623cf10bf19cfba1806f5699007f39c7f6ba38f72d92069548421c4dccd21573",
    "architecture/artifact-edges/operator-harness-engineering-v9.json": "197f30e4e1e0be1dcacd71f1095c91e2333fe9d6ea05b8194578160e471605d7",
    "architecture/backend-timing-authority.json": "0c42acfbb91d50c7f93263f0d3ba5d304c4064b1758980990a09200907146cda",
    "architecture/broker-handoff-amendment.json": "1b5843241dc2574b26c8f24dae6fd6a341860cf2a6db9b0b560801e8ad629529",
    "architecture/broker-handoff-inputs/meta-before.json": "701c23be9e1e57a4fb7288abc33d84aef992b7257342b28595c27120d80948bd",
    "architecture/canonical-repair-plan-authority.json": "adee77fc1561ff5e4c6d1bc622806320c8f12e14f705e82d0be455a492d1e2f5",
    "architecture/catalog-traversal-authority.json": "c84888a7fe3fd955922cdc4e45fab7308b1fcf02ba4273173c9e534c42e82169",
    "architecture/chain-compaction/identity-rule.json": "4bfbcc0387084bd2cd5166af4eb83fb5f9ab18a16e1f289cd2727f5bbdd8bc2e",
    "architecture/ci-performance-amendment.json": "2716be38eee78aefa1b3269a3a30659ae101794da25b9ee6ab30afefbbd19b38",
    "architecture/completion-profiling-authority.json": "19b97e955a280cee0e2e9f4afa8bc38eb344f59924ef6a37dd277334cf2474d9",
    "architecture/conformance-completion-authority.json": "17447fa1df241ea8287adf1220c3804e431c0794c51d02ecc588b8269ad15b94",
    "architecture/conformance-consumer-closure-inputs/consumer-sources.json": "7ed2c605abe41e7e1122b58841455489a1b6f9bee93f95a10ad56976a4485e3d",
    "architecture/conformance-consumer-closure-inputs/meta-before.json": "b680d897ab09bd6455866dda0e13d102a156db1143db9fd707dbbc08dcbe17b8",
    "architecture/conformance-consumer-closure-inputs/product-before.json": "b94d14121eb37b7eeb2bff2a5570cf4a41e593c4d2f03de626cfbd745969d0dc",
    "architecture/conformance-consumer-closure.json": "0f42919cdd9d92685a4cd0ecd0ee471cdbdb05cd62b8cdaef334e340f14614ac",
    "architecture/conformance-performance-amendment.json": "dc6019ef0c8ddb721a3f72ee10f98bb7925cc8313b09b74793865d01602d0243",
    "architecture/conformance-performance-followup-inputs/meta-before.json": "e3e65b7b16652e13f07ce0136360f6458ceab514e03a86e195a02aee548db127",
    "architecture/conformance-performance-followup-inputs/product-before.json": "b94d14121eb37b7eeb2bff2a5570cf4a41e593c4d2f03de626cfbd745969d0dc",
    "architecture/conformance-performance-followup.json": "3e2ba8d1db0ca4ba7ea60a814cbc0f35554c3781f7b940d5c7d11c58a5932ff2",
    "architecture/conformance-performance-inputs/meta-before.json": "4554b6c7038e44de8d30a01b34bb31eddf4c0cce430a0fcc2a8451adbd0af96c",
    "architecture/conformance-performance-inputs/product-before.json": "8aae2dd20507805c1cfd91ed7836a979c5c8e0345decdbc7ac64eb87e0b5bf9e",
    "architecture/conformance-publication-authority.json": "742567802e0df4a9cb67ff029fb4f49953badf5e84117bfd935a7af4957db119",
    "architecture/conformance-reference-measurement-inputs/meta-before.json": "12e918a03c0a240e49670655e8448b5e25a49a8cf01c1662b0578ac5075f260c",
    "architecture/conformance-reference-measurement.json": "01b97634ff6d8d6251c68413838cadf6dd6b2079cde3794c31ec97cac46fd589",
    "architecture/conformance-successor-checkpoint-inputs/meta-before.json": "0a6183a74ace02dc696f23d62020790be4ac2985794bc4e6635fa8489e66c528",
    "architecture/conformance-successor-checkpoint-inputs/product-before.json": "ef184022036ccdfd94015fb92058e54968d66242a3848ae80b805ab50288a34b",
    "architecture/conformance-successor-checkpoint.json": "73488d6a0066b23a95954048ccaf4bcf78ddc0f66d88c7818db2c25ff33f128b",
    "architecture/credential-lifecycle-amendment.json": "e4f036bce09ebdea17b2b2d25d6a65678b88ec6e5dd7c18f550c3b45b6061da8",
    "architecture/credential-lifecycle-inputs/before.json": "9176a8d22bab88e48111d53540815ea8be9b2987c43ddfe824de6664971b640e",
    "architecture/credential-ordering-amendment.json": "b4d367b1ff29c92f75304504e30920da25fd682b691f14aabf5f8705d0544c21",
    "architecture/custody-handoff-amendment.json": "81a95c9d1b84aae1ae71d7fa293931fc1118eacd2083051d353875e7b55e2180",
    "architecture/edge-record-v9/review-round2.json": "220c77f3a305bd9608c2fd307c250f36880d8b143597c15115d899e6bc046cdd",
    "architecture/enforcement-integration-authority.json": "afb3b3184438de1af336930a06430255c6e75df0496412757d9c8af5335eb602",
    "architecture/evolution-surface/evolution-surface.json": "188c75d4be1b4c0eebfd01b9454873a09c903238ebdc05219126c734b0d245bd",
    "architecture/host-interface-authority.json": "f2018229e1c033bbab9bb891cf3c3a99c2acc1276e6d86606c73e97f25e8f2fc",
    "architecture/linux-probe-kit-admission/mechanics-pins.json": "de60e78717feb3304dd6032b5bc102a6f0aeeb22a6d37f710a131294f7a39d65",
    "architecture/linux-probe-kit-admission/oracle-identity-admission-v4.json": "69d141f20b2f6bff8102effec09199a0a025393170b0c4ddcd0f6f8e38956f73",
    "architecture/linux-probe-kit-admission/oracle-identity-profile-v2.json": "a1c8f0ad358b777bd89b8bc83e7259a1040cd55ce80d440e210f1d77392a4f8e",
    "architecture/linux-probe-kit-admission/review-identity-round1.json": "a99419fbddd18a8ff3066b1e0b2d944d4a1a0bf368c96b9eca0c9bbbcb4be585",
    "architecture/linux-probe-kit-admission/review-identity-round2.json": "c3ffba5fb40c7e584318b1fccd917273716a2d76778a767b1864b9e9a8643392",
    "architecture/linux-probe-kit-admission/review-round1.json": "3a3d8576ef34ec2bf2af6eed2c906c9cfed6120b1e688c5082083c38bf51419a",
    "architecture/linux-probe-kit-admission/review-round2.json": "3f0fc266ab32a6fae255d720aa4f1cfb8c11be9e2addf710e65e8ff75d762e0a",
    "architecture/linux-probe-kit-admission/source-index.json": "9fbfa668718315381957c2d1c6e486607180cb44487c465a6f36367b3ff0926d",
    "architecture/local-acceptance-authority.json": "d22a4cb6e3d0e8236722ff9bf102db9d70f39e9a1e91d8d8ca679bf03a1cbb28",
    "architecture/native-qualification-amendment.json": "e935cbd3045522cf3c5ad47161140e2444d55ebddfb74c09a641e4a0b66ca84a",
    "architecture/native-qualification-inputs/meta-before.json": "3b7929df563a6eabe5e0c9f624ef886d55e898b6ccf1d269e8cb90ae63e92905",
    "architecture/observation-enforcement-authority.json": "dc1a3745a2bc16dbf3f82753c12f25e3aeebc43c6bd4f85ca67d4f79449bda92",
    "architecture/policy-observation-amendment.json": "0df7e72a65fc5eb1c20d59b8c62ebff377f160214192d681ea7f3d29b57e38c7",
    "architecture/policy-observation-digests/README.md": "e393dd11c75f527829bb6522c5643cb593b6dc67e2788f5e280ce9de0f4166ae",
    "architecture/policy-observation-digests/definitions.json": "086692065cfc9da101f770fa39c50af2e2650a169595526e9860fc805478c2aa",
    "architecture/policy-observation-digests/review-round1.json": "6a7c55c4152b9619c3d9b26993e51ecbeb137949477f277e141815fe794cb28e",
    "architecture/policy-observation-digests/review-round2.json": "38c76f4559e0f8eb4ddf658682f96fa8daa30c8207db3d25001ac31156056a11",
    "architecture/policy-observation-digests/vectors.json": "bd9f04bd04fcccc584bcab341ec649bcead567fe349c57e30958eaaf2ea64f84",
    "architecture/probe-kit-scope/amendment.json": "3de2d73e0413388ba286899cdd364c876dfbd869510c88537da8b1c91726ef8b",
    "architecture/provider-adoption-authority.json": "9b143600b0885d8a010814720e1dd98b775faa971c27a903c8fce36f97493a56",
    "architecture/proxy-contract-amendment.json": "6c93e7db962cffa0281331c5220cdd8d5e453ab38ae39b4baa2e62be21a60600",
    "architecture/proxy-contract-inputs/baseline.json": "980ff63a57a6a167020f6d64297f946c92d7ce56b8c274b3fec56fb18bd837c1",
    "architecture/proxy-contract-inputs/profile.schema.json": "209349ccf44989566ffb39e2654fc91323b5eb2d9cbe895a4b18f33a349a226d",
    "architecture/proxy-contract-inputs/vectors.json": "edf32ddf992e06e8786fd331affdb4d2ecd5538ca874d52c37439386793a8eb7",
    "architecture/proxy-diagnostics-authority.json": "4c0fe90fa317a3c0b102710d86a3c9795244bcf0505fdebb21899905f3c3628b",
    "architecture/proxy-profile-v2/README.md": "6bda6500cf2af10c23acf09d99f95916901aa6e7729b348face9859cafd9ac8f",
    "architecture/proxy-profile-v2/profile.schema.json": "e5ef3c3d112bce97d94da4b465b52feb69935a144f26dd711440acd6c67ad592",
    "architecture/proxy-profile-v2/status.json": "950810f369e10e89224cd712d7eba2864b664ef5184152fe886a6b9351d9f685",
    "architecture/proxy-profile-v2/vectors.json": "011a650bcd2a11f2eaeba531693f3e7ee9c30c1f6ede2d5ecf87919f206affcc",
    "architecture/research-adoption-authority.json": "37fd33e216e5ec7513f3af751bf5590399f918d4cfde4eea8c7bbbc4587d752b",
    "architecture/review-briefs/REVIEW_BRIEF_CONTRACT.md": "1f09d23451bf265e32e44742ca362dabf5a1090c2208c1349cbf491670798aec",
    "architecture/review-briefs/REVIEW_BRIEF_PACKET.md": "6dcff68d7e6b01823f1740063e94910edcc159a71a6ee803f1b66c62fd06e274",
    "architecture/review-record/briefs.json": "4cc369e76bc3092dd9085b393a79c2d8b641ea47a1ddb61e62c033965544ce62",
    "architecture/validation-performance-authority.json": "88e3a3e95b32aa5eee7d34f9124bf60c724c538ba4ebad5a6ed906a0d3e62507",
    "architecture/w03-plan-v2/plan.json": "a00470238431347da82cc47b1f1b6cf7cd51042d56694eea68d1373a3aaefb67",
    "architecture/w03-plan/plan.json": "40b501f48fe0eb13d64d2e0cf7fa542817f0fa3034d86058c233d1a3accaff9a",
    "docs/alpha-2/PROXY_CONTRACT_READINESS.md": "3e3bf310ebd8a7b1aed696ed9b8d4d26cb67160aab3f862877e2b2a2e0c9f3d0",
    "scripts/admission_semantics_v3.py": "3db8f51ab55f49dc33cf6f028306bfb6d7aa1c5d7d96f264cfe709dae925ad22",
    "scripts/admission_semantics_v4.py": "4da5a71dfd4c9a3e46709ea8a754a58f48b76fe51bc2a526bfe07c40bc13b547",
    "scripts/evolution_surface.py": "f38fa6d00ec5fbbbcab8ff01d0e56824e805327b872dc1e23e579e522a681fd9",
    "scripts/policy_observation_digests.py": "01298fb5c6acdae3248174265bbe576dd553eeb19bce1a48cb1e2734972c09c5",
    "scripts/proxy_profile_v2.py": "509a4435e8bc1b8ab94efcb6fcc99e355ef27574ef0499bc4b6e89edef63fefa",
    "tests/test_admission_semantics_v4_oracle.py": "fdc2e0f59563651a069c629e332942a8d48412ee43e92d1e2b2404d1d8adf1c5",
    "tests/test_policy_observation_digests_oracle.py": "3c2ca9f02efdf16e1ef3923f05df6bdbe6f36137400d0f77633a8f105cd70437",
    "tests/test_proxy_profile_v2_oracle.py": "2f63fa5ef43d9601b7934ec326decbe4ffe5c8828c89ebc4dbc0788c88098e87",
})
# Absolute local path markers, matched case-insensitively; spelled in parts, so this file holds none of them. A marker
# counts when a path character follows it.
LOCAL_PATH_MARKERS = (b"/" + b"users/", b"/" + b"private/", b".local" + b"/state")
PATH_BYTES = b"abcdefghijklmnopqrstuvwxyz0123456789_.-/"


def reviewed_bytes(path: str) -> bytes:
    """This packet's reviewed bytes of path; a bridged successor projects newer bytes back first."""
    return successor.historical_bytes(path, regular_bytes(path))


def reviewed_mode(path: str) -> int:
    """The lstat mode of path in this packet's tree; a bridged successor projects a newer mode back first."""
    _path(path)
    return (ROOT / path).lstat().st_mode


def _era_bytes(path: Any, raw: Any) -> bytes:
    """An era file's bytes, checked against its era digest; a path outside the era is refused."""
    expected = ERA_SHA256.get(path) if type(path) is str else None
    require(expected is not None, "MET-LIVE-004 reviewed bytes are bound: " + str(path))
    require(type(raw) is bytes and digest(raw) == expected, "unreviewed LINUX-PROBE-KIT-ADMISSION source: " + path)
    return raw


def _verified(path: str) -> bytes:
    """reviewed_bytes, checked against its era digest on every read; a path outside the era is refused before it is
    read."""
    require(type(path) is str and path in ERA_SHA256, "MET-LIVE-004 reviewed bytes are bound: " + str(path))
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


def _git_mode(mode: int) -> str | None:
    """The git mode of a regular file from its lstat mode; anything else has none."""
    if not stat.S_ISREG(mode):
        return None
    return "100755" if mode & 0o100 else "100644"


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


def era_models() -> tuple:
    """(admission semantics v4, the frozen admission semantics v3, workload profile v2, the evolution surface model), each
    executed from this era's verified bytes."""
    return (_era_model(V4_MODEL, "_met_live_004_admission_semantics_v4"),
            _era_model(V3_MODEL, "_met_live_004_admission_semantics_v3"),
            _era_model(P2_MODEL, "_met_live_004_proxy_profile_v2"),
            _era_model(SURFACE_MODEL, "_met_live_004_evolution_surface"))


def check_freeze(changed: Any) -> None:
    """This packet edits no existing file but chain validators (scripts/validate_*.py, one level deep), tests and the
    three living catalogs: no model, no earlier contract or record, no registry and no conftest change."""
    for path in list(changed):
        require(type(path) is str and path not in ("conftest.py", "tests/conftest.py")
                and ((path.startswith("scripts/validate_") and path.endswith(".py") and path.count("/") == 1)
                     or path.startswith("tests/") or path in LIVING_CATALOGS),
                "this packet edits only chain validators, tests and the three living catalogs: " + str(path))


def check_new_files(added: Any) -> None:
    """The packet adds exactly the eleven contract files, the eight files of the combined review set, the two oracle tests
    and the layer's test, each once."""
    _bound(lambda: len(set(NEW_FILES)) == len(NEW_FILES) and type(added) is list
           and sorted(added) == sorted(NEW_FILES + (HEAD_TEST,)),
           "this packet adds exactly its contract files, review set, oracle tests and layer test, each once")


def check_added_file(path: str, mode: Any, raw: Any) -> None:
    """A file this packet adds is a regular file of git mode 100644 (not a link, not executable) and holds no absolute
    local path."""
    require(type(mode) is int and _git_mode(mode) == "100644",
            "a file this packet adds is a regular file of git mode 100644: " + path)
    require(type(raw) is bytes and not _local_path(raw), "no absolute local path in a file this packet adds: " + path)


def validate_files() -> None:
    """The freeze and the files this packet adds, from this era's authority and modes."""
    record = authority()
    check_freeze(list(_PROJECTION_RULES))
    check_new_files(list(record["newFiles"]))
    for path in NEW_FILES:
        check_added_file(path, reviewed_mode(path), _verified(path))


def _round_rows(rounds: Any) -> list:
    """The reviewRounds rows the status records state, from the published records' and identities' bytes."""
    rows = []
    for n, (record_raw, identity_raw) in zip(ROUNDS, rounds):
        row = {"round": n, "record": REVIEW_RECORDS[n - 1], "recordSha256": digest(record_raw),
               "identity": REVIEW_IDENTITIES[n - 1], "identitySha256": digest(identity_raw),
               "verdict": ROUND_VERDICTS[n - 1], "subjectCommit": ROUND_SUBJECTS[n - 1]}
        if n > 1:
            row["baseCommit"] = ROUND_SUBJECTS[n - 2]
        rows.append(row)
    return rows


def check_status(path: str, status: Any, rounds: Any, lpk0_raw: Any) -> None:
    """A status record's closed shape and values: LINUX-PROBE-KIT-ADMISSION adopted as MET-LIVE-004 on this era's base,
    ADOPTED_DATA_CONTRACT, candidate c3 (MON-LPK1-C3-ADOPT), the combined review of both directories, CONTRACT rounds 1 and
    2 bound to their published records and identities by digest, and LPK-0's record by this era's digest."""
    _bound(lambda: type(status) is dict and tuple(status) == STATUS_KEYS[path]
           and status["schemaVersion"] == STATUS_SCHEMAS[path] and status["packet"] == NEW_PACKET
           and status["workItem"] == WORK_ITEM and status["candidate"] == CANDIDATE and status["base"] == BASE_COMMIT
           and status["reviewSeries"] == SERIES and status["contractState"] == CONTRACT_STATE
           and status["combinedReview"] == list(COMBINED_REVIEW) and status["independentReviewer"] == INDEPENDENT_REVIEWER
           and status["nativeAcceptance"] is False and status["adoption"] == dict(ADOPTION)
           and type(rounds) is list and len(rounds) == len(ROUNDS)
           and status["reviewRounds"] == _round_rows(rounds)
           and all(tuple(row) == tuple(expected) for row, expected in zip(status["reviewRounds"], _round_rows(rounds)))
           and type(lpk0_raw) is bytes and status["predecessorRecord"]["record"] == LPK0_RECORD
           and status["predecessorRecord"]["sha256"] == digest(lpk0_raw),
           "adopted LINUX-PROBE-KIT-ADMISSION status: " + str(path))


def check_round(n: int, record_raw: Any, identity_raw: Any, brief_raw: Any) -> None:
    """CONTRACT round n is a v2 record of the MET-LIVE-004/contract series with its verdict and subject (round 1 has no
    base; a later round's base is the previous round's subject), citing the registered generic CONTRACT brief by digest,
    and its identity binds it by path and digest with the same brief, subject and base."""
    _bound(lambda: n in ROUNDS and type(record_raw) is bytes and type(identity_raw) is bytes and type(brief_raw) is bytes
           and (lambda record, identity: record["schemaVersion"] == RECORD_SCHEMA and record["kind"] == "CONTRACT"
                and record["series"] == SERIES and type(record["round"]) is int and record["round"] == n
                and record["verdict"] == ROUND_VERDICTS[n - 1] and record["subject"]["commit"] == ROUND_SUBJECTS[n - 1]
                and ((n == 1 and "base" not in record)
                     or (n > 1 and record["base"]["commit"] == ROUND_SUBJECTS[n - 2]))
                and record["briefSha256"] == digest(brief_raw)
                and identity["schemaVersion"] == IDENTITY_SCHEMA
                and identity["record"] == {"path": REVIEW_RECORDS[n - 1], "sha256": digest(record_raw)}
                and identity["briefSha256"] == record["briefSha256"] and identity["subject"] == record["subject"]
                and identity.get("base") == record.get("base"))(parse(record_raw), parse(identity_raw)),
           "a CONTRACT round is bound to its published record and identity: round %d" % n)


def check_source_index(index: Any, rounds: Any) -> None:
    """source-index.json names this packet's series on this era's base, its in-tree rounds by record digest, verdict and
    subject, and cites the design proof without a local path."""
    _bound(lambda: type(index) is dict and index["schemaVersion"] == INDEX_SCHEMA and index["packet"] == NEW_PACKET
           and index["workItem"] == WORK_ITEM and index["series"] == SERIES and index["baseMain"] == BASE_COMMIT
           and index["designProof"] == DESIGN_PROOF and type(rounds) is list and len(rounds) == len(ROUNDS)
           and index["inTreeRounds"] == [{"round": n, "recordSha256": digest(record_raw),
                                          "verdict": ROUND_VERDICTS[n - 1], "subjectCommit": ROUND_SUBJECTS[n - 1]}
                                         for n, (record_raw, _identity) in zip(ROUNDS, rounds)],
           "the source index names this packet's in-tree rounds")


def check_oracle_identity(path: str, identity_raw: Any, oracle_raw: Any) -> None:
    """A D5a oracle identity binds its oracle test by path and sha256 at the oracle candidate commit, with ruling KEEP by
    the lane monitor (check_tree checks the identity in full, in the suite)."""
    _bound(lambda: path in ORACLE_BINDINGS and type(identity_raw) is bytes and type(oracle_raw) is bytes
           and (lambda identity: identity["schemaVersion"] == ORACLE_SCHEMA
                and identity["file"] == {"path": ORACLE_BINDINGS[path], "sha256": digest(oracle_raw)}
                and identity["candidateCommit"] == ORACLE_COMMIT
                and identity["ruling"] == ORACLE_RULINGS[path])(parse(identity_raw)),
           "an oracle identity binds its oracle test, with ruling KEEP by the lane monitor: " + str(path))


def validate_adoption() -> None:
    """Both status records, every round's record and identity, the source index and the two oracle identities."""
    rounds = [(_verified(REVIEW_RECORDS[n - 1]), _verified(REVIEW_IDENTITIES[n - 1])) for n in ROUNDS]
    lpk0 = _verified(LPK0_RECORD)
    for path in (V4_STATUS, P2_STATUS):
        check_status(path, _json(path), rounds, lpk0)
    brief = _verified(CONTRACT_BRIEF)
    for n in ROUNDS:
        check_round(n, rounds[n - 1][0], rounds[n - 1][1], brief)
    check_source_index(_json(SOURCE_INDEX), rounds)
    for path, test in ORACLE_BINDINGS.items():
        check_oracle_identity(path, _verified(path), _verified(test))


def _apply_ops(value: Any, ops: Any) -> Any:
    """The vectors' operations on a deep copy: set puts value at path (member names and array indexes), delete removes
    the member at path."""
    value = copy.deepcopy(value)
    for op in ops:
        require(type(op) is dict and op.get("op") in ("set", "delete") and type(op.get("path")) is list
                and len(op["path"]) > 0, "closed vector operation")
        node = value
        for key in op["path"][:-1]:
            node = node[key]
        if op["op"] == "set":
            node[op["path"][-1]] = copy.deepcopy(op["value"])
        else:
            del node[op["path"][-1]]
    return value


def replay_admission(model: Any, vectors: Any) -> dict:
    """An admission contract's vectors through its model, as v3's layer replays v3's: the positives through the signer's
    check; then each manifest case, each end-to-end case (the derived final object and the A2 reading), each final-object,
    policy-object, directory-hash and claim case, every result compared with the case's expectation."""
    sealed, server, positives = vectors["sealed"], vectors["server"], vectors["positives"]
    namespace = sealed["namespace"]
    bad, counts = [], {}
    for name, manifest in positives.items():
        if model.check_manifest("Pod" if name.startswith("Pod") else name, manifest, namespace) is not None:
            bad.append(name)
    for row in vectors["manifest"]:
        if model.check_manifest(row["kind"], _apply_ops(positives[row["positive"]], row["ops"]), namespace) != row["expect"]:
            bad.append(row["id"])
    for row in vectors["endToEnd"]:
        final = model.final_object(row["kind"], _apply_ops(positives[row["positive"]], row.get("manifestOps", [])),
                                   dict(server, **row["serverFacts"]))
        if final != row["finalObject"] or model.check_final(row["kind"], final, sealed, row["username"]) != row["expect"]:
            bad.append(row["id"])
    for row in vectors["finalObject"]:
        if model.check_final(row["kind"], row["object"], sealed, row["username"]) != row["expect"]:
            bad.append(row["id"])
    for row in vectors["objects"]:
        if model.check_a2_objects(row["objects"], sealed) != row["expect"]:
            bad.append(row["id"])
    for row in vectors["directoryHash"]:
        files = {name: text.encode("utf-8") for name, text in row["files"].items()}
        if model.manifest_directory_hash(files) != row["expect"]:
            bad.append(row["id"])
    for row in vectors["claims"]:
        if model.check_claim(row["claim"], vectors["pinned"]) != row["expect"]:
            bad.append(row["id"])
    for group in V4_COUNTS:
        counts[group] = len(vectors[group])
    return {"positives": tuple(positives), "cases": counts, "mismatches": bad}


def check_admission_replay(label: str, result: Any, counts: Any) -> None:
    """An admission contract's vectors replay with its six positives admitted, each group at its count, and no
    mismatch."""
    _bound(lambda: result == {"positives": POSITIVES, "cases": dict(counts), "mismatches": []},
           "the admission vectors replay with every case at its count and no mismatch: " + label)


def check_sealed(raw: Any, rendered: Any, objects_refusal: Any, directory_hash: Any, pinned: Any) -> None:
    """The sealed v4 A2 file is 8322 bytes with its stated digest, equals the model's rendering of the sealed values, holds
    the policy objects the model accepts, and reproduces the pinned directory hash."""
    _bound(lambda: type(raw) is bytes and len(raw) == SEALED_SIZE and digest(raw) == SEALED_SHA256 and raw == rendered
           and objects_refusal is None and directory_hash == DIRECTORY_HASH and pinned == DIRECTORY_HASH,
           "the sealed v4 A2 file is the model's rendering with the pinned directory hash")


def check_v3_model(semantics: Any) -> None:
    """The frozen v3 model names POLICY-ADMISSION-SEMANTICS/v3."""
    _bound(lambda: semantics == V3_SEMANTICS, "the frozen admission v3 model names its semantics")


def _rehash(document: Any) -> Any:
    """Every resource's manifestDigest recomputed over the manifest's canonical JSON."""
    for resource in document["resources"]:
        resource["manifestDigest"] = "sha256:" + digest(canonical(resource["manifest"]))
    return document


def _profile_case(positive: Any, row: Any) -> Any:
    """A profile v2 case: the operations on a copy of the positive, then the rehash when the case asks for it."""
    document = _apply_ops(positive, row["ops"])
    return _rehash(document) if row["rehash"] is True else document


def _precondition(profile: Any, namespace: Any) -> list:
    """The cross-contract precondition P40, restated from proxy_profile_v2.precondition (an attribute name the frozen
    allow-list does not admit): P01 for a profile whose canonical form cannot be encoded, P99 for malformed data, P40 when
    the binding namespace is not the sealed one (the test checks it equals the model's on every case)."""
    try:
        canonical(profile)
    except ValueError:
        return [P01_TEXT]
    except (TypeError, RecursionError):
        return [P99_TEXT]
    try:
        return [] if profile["binding"]["namespace"] == namespace else [P40_TEXT]
    except (TypeError, KeyError):
        return [P99_TEXT]


def _admitted(model: Any, vectors: Any, namespace: Any, document: Any, facts: Any) -> dict:
    """Each resource of a profile v2 document through an admission model, as the cross-contract rule states: the
    signer's code, else the A2 reading of the final object under the server facts updated with the case's facts."""
    out = {}
    for resource in document["resources"]:
        manifest = resource["manifest"]
        kind = manifest["kind"]
        code = model.check_manifest(kind, manifest, namespace)
        if code is not None:
            out[kind] = code.split(" ")[0]
            continue
        final = model.final_object(kind, manifest, dict(vectors["server"], **facts))
        refusal = model.check_final(kind, final, vectors["sealed"], vectors["campaignUser"])
        out[kind] = "A2 admit" if refusal is None else "A2 " + refusal.split(" ")[0]
    return out


def replay_profile(p2: Any, v4: Any, v3: Any, vectors: Any, schema: Any, v4_vectors: Any, v3_vectors: Any) -> dict:
    """Profile v2's vectors through its model: the positive valid, each negative refused with exactly its expected text,
    and each cross-contract case's profile verdict, precondition and per-resource result under admission v4 and the
    frozen v3."""
    bad = []
    positive = vectors["positive"]
    if p2.validate(positive, schema) != []:
        bad.append("positive")
    for row in vectors["negative"]:
        if p2.validate(_profile_case(positive, row), schema) != [row["expect"]]:
            bad.append(row["id"])
    cross = vectors["crossContract"]
    namespace = cross["sealedNamespace"]
    for row in cross["cases"]:
        document = _profile_case(positive, row)
        refusals, pre = p2.validate(document, schema), _precondition(document, namespace)
        got = {"profileV2": "valid" if refusals == [] else refusals[0], "precondition": "met" if pre == [] else pre[0],
               "v4": _admitted(v4, v4_vectors, namespace, document, row["serverFacts"]),
               "v3": _admitted(v3, v3_vectors, namespace, document, row["serverFacts"])}
        if got != row["expect"]:
            bad.append(row["id"])
    return {"positive": 1, "negative": len(vectors["negative"]), "crossContract": len(cross["cases"]),
            "total": 1 + len(vectors["negative"]) + len(cross["cases"]), "mismatches": bad}


def check_profile_replay(result: Any, case_counts: Any) -> None:
    """Profile v2's 67 cases replay (one positive, 50 negatives and 16 cross-contract cases, as vectors.json counts them)
    with no mismatch."""
    _bound(lambda: result == dict(P2_COUNTS, mismatches=[]) and case_counts == dict(P2_COUNTS),
           "profile v2's 67 cases replay with no mismatch")


def check_p01(readme_raw: Any, negatives: Any) -> None:
    """B-L1-1: one P01 refusal text, stated verbatim in the README, which K01 and K01b expect exactly."""
    _bound(lambda: type(readme_raw) is bytes and readme_raw.count(P01_TEXT.encode("utf-8")) > 0
           and [row["expect"] for row in negatives if row["id"] in P01_CASES] == [P01_TEXT, P01_TEXT]
           and [row["id"] for row in negatives if row["id"] in P01_CASES] == list(P01_CASES),
           "B-L1-1's P01 text is the README's and K01's and K01b's")


def validate_models(v4: Any, v3: Any, p2: Any) -> None:
    """Admission v4's 141 cases and the sealed A2 file through v4, v3's 114 cases through the frozen v3, and profile v2's
    67 cases through profile v2 with the cross-contract group through both."""
    v4_vectors, v3_vectors, p2_vectors = _json(V4_VECTORS), _json(V3_VECTORS), _json(P2_VECTORS)
    check_v3_model(v3.SEMANTICS_V3)
    check_admission_replay("v4", replay_admission(v4, v4_vectors), V4_COUNTS)
    check_admission_replay("v3", replay_admission(v3, v3_vectors), V3_COUNTS)
    raw = _verified(V4_SEALED)
    sealed = v4_vectors["sealed"]
    check_sealed(raw, v4.manifest_file_bytes(sealed), v4.check_a2_objects(parse(raw)["items"], sealed),
                 v4.manifest_directory_hash({SEALED_NAME: raw}), v4_vectors["pinned"]["manifestDirectoryHash"])
    check_p01(_verified(P2_README), p2_vectors["negative"])
    check_profile_replay(replay_profile(p2, v4, v3, p2_vectors, _json(P2_SCHEMA), v4_vectors, v3_vectors),
                         p2_vectors["caseCounts"])


def _chain_file(path: Any) -> bool:
    """A chain validator (scripts/validate_*.py, one level deep) or a test file."""
    return type(path) is str and path.count("/") == 1 and path.endswith(".py") and (
        path.startswith("scripts/validate_") or path.startswith("tests/test_"))


def check_pins_record(record: Any) -> None:
    """B-L1-4's record is closed: its schemaVersion and exactly unchangedPins and evolutionSurfaceClasses; the pins are
    sorted, unique and closed rows (70 byte-identical, 7 under the step rule), each naming its lists, and the class rows
    are closed rows of one form each."""
    _bound(lambda: type(record) is dict and tuple(record) == PINS_KEYS and record["schemaVersion"] == PINS_SCHEMA
           and type(record["unchangedPins"]) is list and type(record["evolutionSurfaceClasses"]) is list
           and [row["path"] for row in record["unchangedPins"]] == sorted(set(row["path"] for row in record["unchangedPins"]))
           and all(type(row) is dict and tuple(row) == PIN_KEYS and _sha(row["sha256"]) and type(row["lists"]) is list
                   and len(row["lists"]) > 0 and all(label in PIN_LISTS for label in row["lists"])
                   and row["rule"] in PIN_COUNTS for row in record["unchangedPins"])
           and {rule: len([row for row in record["unchangedPins"] if row["rule"] == rule]) for rule in PIN_COUNTS}
           == dict(PIN_COUNTS)
           and len(record["evolutionSurfaceClasses"]) == CLASS_ROWS
           and all(type(row) is dict and len(row) == 3 and row.get("class") in CLASS_NAMES
                   and row.get("source") in CLASS_SOURCES and len([form for form in CLASS_FORMS if form in row]) == 1
                   for row in record["evolutionSurfaceClasses"]),
           "the mechanics pins record is closed")


def check_pin(row: Any, raw: Any, rule: Any) -> None:
    """A byte-identical pin is an era file whose bytes have its recorded sha256 and which this packet does not change; a
    step-rule pin is a chain file this packet changes, whose recorded sha256 is its predecessor bytes' (this packet's
    inverse restores them; strictcheck governs the change)."""
    _bound(lambda: (row["rule"] == "BYTE_IDENTICAL" and type(raw) is bytes and digest(raw) == row["sha256"]
                    and rule is None)
           or (row["rule"] == "STEP_RULE" and _chain_file(row["path"]) and type(rule) is dict
               and rule["beforeSha256"] == row["sha256"]),
           "an unchangedPins row holds at this era: " + str(row.get("path") if type(row) is dict else row))


def class_paths(row: Any, paths: Any) -> list:
    """The packet paths a class row covers: its path, the paths under its prefix, or the paths matching its <n> pattern
    (n a decimal number without a leading zero)."""
    if "path" in row:
        return [row["path"]] if row["path"] in paths else []
    if "prefix" in row:
        return [path for path in paths if path.startswith(row["prefix"])]
    head, tail = row["pattern"].split("<n>")
    out = []
    for path in paths:
        middle = path[len(head):len(path) - len(tail)] if len(path) > len(head) + len(tail) else ""
        if (path.startswith(head) and path.endswith(tail) and middle and middle[0] != "0"
                and all(char in "0123456789" for char in middle)):
            out.append(path)
    return out


def check_classes(rows: Any, paths: Any, resolved: Any) -> None:
    """Every class row covers at least one of the packet's paths, and the evolution surface record, run by its model from
    this era's bytes, resolves each covered path to the row's class."""
    _bound(lambda: type(rows) is list and type(paths) is list and type(resolved) is dict
           and all(len(class_paths(row, paths)) > 0
                   and all(resolved[path] == row["class"] for path in class_paths(row, paths)) for row in rows),
           "every evolution-surface class row resolves to its class at this era")


def validate_pins(es: Any) -> None:
    """B-L1-4's record: its closed shape, every pin at this era (each byte-identical pin through the era's bytes), and every
    class row re-derived by the era's evolution surface model."""
    record = _json(PINS_PATH)
    check_pins_record(record)
    rules = authority()["changedFiles"]
    for row in record["unchangedPins"]:
        raw = _verified(row["path"]) if row["rule"] == "BYTE_IDENTICAL" else None
        check_pin(row, raw, rules.get(row["path"]))
    paths = _packet_paths()
    surface = _json(SURFACE_RECORD)
    resolved = {path: es.resolve(surface, path) for row in record["evolutionSurfaceClasses"]
                for path in class_paths(row, paths)}
    check_classes(record["evolutionSurfaceClasses"], paths, resolved)


def check_registry(raw: Any, packet_brief_raw: Any, contract_brief_raw: Any) -> None:
    """The registry is 261's merged file (by digest), unchanged, and holds exactly two series of this packet: its PACKET
    and CONTRACT series, each pinning its generic brief by the sha256 of the brief's bytes."""
    _bound(lambda: type(raw) is bytes and digest(raw) == REGISTRY_SHA256 and type(packet_brief_raw) is bytes
           and type(contract_brief_raw) is bytes
           and [(entry["kind"], entry["series"], entry["path"], entry["sha256"], entry["version"])
                for entry in parse(raw)["briefs"] if entry["series"].startswith(NEW_PACKET + "/")]
           == [REGISTRY_ENTRIES[0] + (digest(packet_brief_raw), 1), REGISTRY_ENTRIES[1] + (digest(contract_brief_raw), 1)],
           "the registry is 261's, unchanged, with this packet's PACKET and CONTRACT series pinning their briefs")


def validate_registry() -> None:
    """briefs.json and the two generic briefs, all unchanged since the base."""
    check_registry(_verified(REGISTRY_PATH), _verified(PACKET_BRIEF), _verified(CONTRACT_BRIEF))


def check_gate_list(gate: Any) -> None:
    """The evolution surface record, run by its model from this era's bytes, derives 31 gate-material entries, each an
    exact path or a prefix (no under-plus-name entry is left in the derived list at this era)."""
    _bound(lambda: type(gate) is list and len(gate) == GATE_MATERIAL
           and all(type(entry) is dict and len(entry) == 1 and ("exact" in entry or "prefix" in entry)
                   for entry in gate),
           "the evolution surface record derives 31 exact or prefix gate entries")


def gate_paths(gate: list, paths: list) -> list:
    """The paths a gate entry matches: an exact path, or a path under a prefix, each compared lower-cased, which equals
    case-folding on this era's all-ASCII gate entries and changed paths (260's packet review r1's R1-2)."""
    return [path for path in paths
            if any(("exact" in entry and path.lower() == entry["exact"].lower())
                   or ("prefix" in entry and path.lower().startswith(entry["prefix"].lower())) for entry in gate)]


def check_gate_hits(gate: Any, changed: Any) -> None:
    """The derived gate check: the gate paths among the packet's changed files, by the record's gate entries, are none."""
    _bound(lambda: type(changed) is list and changed == sorted(changed) and gate_paths(gate, changed) == [],
           "the packet's changed files hold no gate path")


def _packet_paths() -> list:
    """The packet's changed and added paths, with its authority, layer and packet file."""
    record = authority()
    return sorted(set(record["changedFiles"]) | set(record["newFiles"]) | {AUTHORITY_PATH, VALIDATOR_PATH, PACKET_PATH})


def validate_gate(es: Any) -> None:
    """The gate list derived from this era's evolution surface record against the packet's changed files."""
    gate = es.check(_json(SURFACE_RECORD))["gateMaterial"]
    check_gate_list(gate)
    check_gate_hits(gate, _packet_paths())


def validate_linux_probe_kit_admission() -> None:
    """Every reviewed byte first; then the freeze and the files this packet adds, the adoption, the models over their
    vectors, the pins and classes, the registry and the derived gate check; last, this layer's canonical hunks."""
    for path in ERA_SHA256:
        _verified(path)
    validate_files()
    validate_adoption()
    v4, v3, p2, es = era_models()
    validate_models(v4, v3, p2)
    validate_pins(es)
    validate_registry()
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
            == record["validatorNormalizedSha256"], "linux probe kit admission validator drift")
    paths = sorted((ROOT / "task-packets").glob("*.yaml"))
    old = set(record["baselinePackets"])
    require(len(paths) == 270
            and {path.stem for path in paths} == old | {NEW_PACKET, successor.NEW_PACKET, successor.successor.NEW_PACKET, successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.successor.NEW_PACKET},
            "closed 270-packet catalog retaining the 263-packet checkpoint")
    packets = {}
    for path in paths:
        if path.stem in (successor.NEW_PACKET, successor.successor.NEW_PACKET, successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.successor.NEW_PACKET):
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
            "closed source-only linux-probe-kit-admission packet and inherited commands")
    require(len(packet["allowedPaths"]) == len(set(packet["allowedPaths"]))
            and set(packet["allowedPaths"]) == set(record["changedFiles"])
            | set(record["newFiles"]) | {AUTHORITY_PATH, VALIDATOR_PATH,
                                         "task-packets/" + NEW_PACKET + ".yaml"},
            "unreviewed or omitted linux-probe-kit-admission packet path")
    for path, rule in record["changedFiles"].items():
        current = successor.historical_bytes(path, regular_bytes(path))
        require(digest(current) == rule["afterSha256"]
                and digest(historical_bytes(path, current)) == rule["beforeSha256"],
                "unreviewed current source: " + path)
    for path, expected in record["newFiles"].items():
        require(digest(successor.historical_bytes(path, regular_bytes(path))) == expected,
                "new source drift: " + path)
    validate_linux_probe_kit_admission()


if __name__ == "__main__":
    validate()
    print("Linux probe kit admission valid: 270 current specifications; 263-packet checkpoint and exact 262-packet predecessor; contract reviewed.")
