#!/usr/bin/env python3
"""Validate the MET-MAS-002 run manifest contract and the exact 230-to-229 projection."""
from __future__ import annotations

import ast
import base64
import binascii
import copy
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
    import validate_agent_loop as successor
except ImportError:
    from scripts.safe_yaml import safe_load
    from scripts import validate_agent_loop as successor


ROOT = Path(__file__).resolve().parents[1]
AUTHORITY_PATH = "architecture/run-manifest-authority.json"
AUTHORITY_SHA256 = "94aecde46bdc96ffb926a1e448d32eef4620e72daa293cd65914e3029f5a1117"
VALIDATOR_PATH = "scripts/validate_run_manifest.py"
BASE_COMMIT = "c0f535b19a0bea576731ebe15d2e3cae0a4dbb23"
NEW_PACKET = "MET-MAS-002"
PREVIOUS_PACKET = "MET-MAS-001"
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
            require(key not in result, "duplicate run-manifest authority member")
            result[key] = value
        return result

    def no_constant(_value: str) -> Any:
        raise ValueError("nonfinite run-manifest authority number")

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
        require(digest(raw) == AUTHORITY_SHA256, "run manifest history authority digest")
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
    }, "closed run manifest history authority")
    require(value["schemaVersion"] == "harness.planeon.ai/run-manifest-authority/v1"
            and value["authorityPacket"] == NEW_PACKET
            and value["acceptedBase"] == BASE_COMMIT
            and type(value["baselinePackets"]) is dict
            and len(value["baselinePackets"]) == 229
            and NEW_PACKET not in value["baselinePackets"]
            and type(value["changedFiles"]) is dict
            and type(value["newFiles"]) is dict
            and _sha(value["packetSha256"])
            and _sha(value["validatorNormalizedSha256"]),
            "accepted 229-packet base")
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
    # An exact 229-era byte string is already older than the successor layer.
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


# MET-MAS-002 (roadmap MAS-RA-002) publishes the run manifest and configuration-level evaluation record contract candidate
# (architecture/run-manifest/): five closed schemas (split declaration, run manifest, evaluation record, distribution-gate
# comparison, selection record), a standard-library reference model and vectors, adopted after four independent review
# rounds, with H16's harness document and the repository schemas byte-identical. Repository bytes are read only through
# reviewed_bytes, so a later bridged successor projects its own edits away first. Every reviewed file of this era is bound
# by digest before anything is parsed, every later read is checked against that digest again, and the contract's model is
# executed from this era's reviewed bytes to replay every vector, so a later revision of the model cannot change how this
# layer judges its era. The owner's decisions, the codes, the vector counts, the critical-value table and the H16 mapping
# are restated here independently of the reviewed files.
CONTRACT_DIR = "architecture/run-manifest/"
MODEL = "scripts/run_manifest.py"
README_PATH = CONTRACT_DIR + "README.md"
SCHEMA_FILES = ("split-declaration.schema.json", "run-manifest.schema.json", "evaluation-record.schema.json",
                "distribution-gate.schema.json", "selection-record.schema.json")
SCHEMA_IDS = {"split-declaration.schema.json": "planeon.internal.split-declaration/v1",
              "run-manifest.schema.json": "planeon.internal.run-manifest/v1",
              "evaluation-record.schema.json": "planeon.internal.evaluation-record/v1",
              "distribution-gate.schema.json": "planeon.internal.distribution-gate/v1",
              "selection-record.schema.json": "planeon.internal.selection-record/v1"}
VECTORS_PATH = CONTRACT_DIR + "vectors.json"
STATUS_PATH = CONTRACT_DIR + "status.json"
H16_PATH = "docs/harnesses/trust.evaluation-assurance.md"
REVIEWED_SUBJECT = {"commit": "b3078f2e4d4f8d148e9d424369a1f4ec0c58734c", "tree": "225c5aefca2f6054b4be33d1f31a11d23382be3e"}
ROUNDS = ((1, 'CHANGES_REQUIRED'), (2, 'CHANGES_REQUIRED'), (3, 'CHANGES_REQUIRED'), (4, 'PASS_FOR_SOURCE_PUBLICATION'))
LAST_ROUND = len(ROUNDS)
REVIEW_SCHEMA = "harness.planeon.ai/run-manifest-review/v1"
STATUS_KEYS = ("schemaVersion", "workItem", "status", "contract", "reviewedSubject", "adoptionEdit", "rounds", "carried",
               "acceptance", "ownerDecisions", "nonClaims")
ROW_KEYS = ("round", "subject", "subjectTree", "verdict", "record", "snapshot", "severities")
# An earlier round's snapshot holds these files; its vectors.json (regenerated every round) is bound by digest.
SNAPSHOT_FILES = ("README.md",) + SCHEMA_FILES + ("scripts/run_manifest.py",)
CONTRACT = {"schemas": [CONTRACT_DIR + name for name in SCHEMA_FILES], "vectors": VECTORS_PATH, "model": MODEL,
            "readme": README_PATH}
STATUS_LINE = ('Status: **CONTRACT_CANDIDATE_ROUND4_AWAITING_INDEPENDENT_REVIEW**.', 'Status: **ADOPTED_CONTRACT_CANDIDATE** (independent review round 4: PASS_FOR_SOURCE_PUBLICATION; rounds and review records in `status.json`).')
SEVERITIES = ("MAJOR", "MINOR", "NOTE")
NON_CLAIMS = ["An internal contract candidate: no public contract, selector, catalog, schema or runtime change; H16's harness document and the repository schemas are byte-identical.", "No producer, consumer or service exists; the model runs only on the vectors; the R12 trial of a run-manifest record is a later parallel-lane R12 packet.", "The cited figures are the source papers' results, not platform evidence."]
ACCEPTANCE = ["MAS-RA-002-A1", "MAS-RA-002-A2", "MAS-RA-002-A3"]
DECISIONS = ["Q-MAS2-A (a)", "Q-MAS2-B (a)", "Q-MAS2-C (a)", "Q-MAS2-D (a)", "Q-230 (a)"]
CODES = ('SHAPE', 'DUPLICATE_ID', 'UNKNOWN_REFERENCE', 'PARTITION_EMPTY', 'PARTITION_OVERLAP', 'SPLIT_SUITE', 'SPLIT_AFTER_RUN', 'STARTED_BEFORE_WRITTEN', 'CONFIGURATION_MIXED', 'REPETITIONS', 'SEED_REUSED', 'TASK_SET', 'CACHE_EXCEEDS_TOKENS', 'INCOMPARABLE', 'DECISION_MISMATCH', 'HELD_OUT_SELECTION', 'SELECTION_BASIS')
CRITICAL_TABLE = ((1, 12707), (2, 4303), (3, 3183), (4, 2777), (5, 2571), (6, 2447), (7, 2365), (8, 2307), (9, 2263), (10, 2229), (11, 2201), (12, 2179), (13, 2161), (14, 2145), (15, 2132), (16, 2120), (17, 2110), (18, 2101), (19, 2094), (20, 2086), (21, 2080), (22, 2074), (23, 2069), (24, 2064), (25, 2060), (26, 2056), (27, 2052), (28, 2049), (29, 2046), (30, 2043), (40, 2022), (60, 2001), (120, 1980))
VECTOR_COUNTS = {"cases": 85, "criticalValues": 15, "texts": 2, "valid": 25}
GATE_OUTCOMES = {"partitions": ("DEVELOPMENT", "HELD_OUT"), "purposes": ("NON_REGRESSION", "IMPROVEMENT"),
                 "decisions": ("IMPROVED", "WITHIN_NOISE", "REGRESSED", "UNRESOLVED"), "minRepetitions": 3}
# The H16 state for (purpose, decision, nonInferior): NON_REGRESSION passes only a non-inferior candidate.
H16_TABLE = {("NON_REGRESSION", "IMPROVED", True): "PASS", ("NON_REGRESSION", "WITHIN_NOISE", True): "PASS",
             ("NON_REGRESSION", "WITHIN_NOISE", False): "WARN", ("NON_REGRESSION", "REGRESSED", False): "FAIL",
             ("NON_REGRESSION", "UNRESOLVED", False): "WARN", ("IMPROVEMENT", "IMPROVED", True): "PASS",
             ("IMPROVEMENT", "WITHIN_NOISE", True): "FAIL", ("IMPROVEMENT", "WITHIN_NOISE", False): "FAIL",
             ("IMPROVEMENT", "REGRESSED", False): "FAIL", ("IMPROVEMENT", "UNRESOLVED", False): "WARN"}
# H16's harness document and every repository schema stay byte-identical (Q-MAS2-A).
FROZEN_PATHS = (H16_PATH,)
FROZEN_PREFIXES = ("schemas/",)
# The adopted bytes of every contract file, round copy and review record, the status record and the model; the accepted
# base's H16 harness document.
ERA_SHA256 = MappingProxyType({
    "architecture/run-manifest/README.md": "279d374e5ddd1b6305611f3565a7af14046b305e59cf9634a88bd358818ce826",
    "architecture/run-manifest/distribution-gate.schema.json": "f521fc6691984959473ef4f184e863193c060acc0b2ed1012dcf1d2c9d3a1683",
    "architecture/run-manifest/evaluation-record.schema.json": "8b34740168f5a96f0186b69f9a1a43c544fdd971ed052f8e723c14dda1c3e625",
    "architecture/run-manifest/review-round1.json": "afa5b00fbef13310c5dfcdc6d90420d010ea9a334c45b1bcd51f159f847bc0ab",
    "architecture/run-manifest/review-round2.json": "6e6596240b6e9b8deec705245261dc926747905af61d0d61e9045b8324a509c9",
    "architecture/run-manifest/review-round3.json": "341395b9bb8bb1d049b91ac926cc4f5fcf0ad5796270ba3801b1b885df464ba8",
    "architecture/run-manifest/review-round4.json": "3d7605cf7b0c8f5bd171f36ffe2a93ca3083729ac3b62918abfa269154a0e739",
    "architecture/run-manifest/round1/README.md": "6b0d151016384ac4a63a37bd4ef4e0229281b47a72d9388d81f67be6f563cc60",
    "architecture/run-manifest/round1/distribution-gate.schema.json": "3042105eed216e28439f31613c868c07b33ce791a3ca3104f452139cfe177388",
    "architecture/run-manifest/round1/evaluation-record.schema.json": "bf1f6cee45d2083bbdf54ffaac688d143a546adbff22da6562990bbb9e4fb6b6",
    "architecture/run-manifest/round1/run-manifest.schema.json": "47ec17a9f99a0d5aa55c85fc5ed0d54e7cb226dd81b0e5567a177975b5d4b593",
    "architecture/run-manifest/round1/scripts/run_manifest.py": "712a25ea99d7a9b19ed43cd2c74c32c79038804aab39be8b05042071e351bb9b",
    "architecture/run-manifest/round1/selection-record.schema.json": "43dd05a99b299760b378d0526a501c6b989d2f7d707435cd82b7e78501bc90d3",
    "architecture/run-manifest/round1/split-declaration.schema.json": "f0247744e5f2e2c23db51ce63f7ed5a7a881f6986e2ee7d308ee5c65e6184a09",
    "architecture/run-manifest/round2/README.md": "98d347a3c54df1e6c78360f644c4b6beabb1a69168ada0f3459cc31f59c8e6ce",
    "architecture/run-manifest/round2/distribution-gate.schema.json": "f521fc6691984959473ef4f184e863193c060acc0b2ed1012dcf1d2c9d3a1683",
    "architecture/run-manifest/round2/evaluation-record.schema.json": "8b34740168f5a96f0186b69f9a1a43c544fdd971ed052f8e723c14dda1c3e625",
    "architecture/run-manifest/round2/run-manifest.schema.json": "ec62c1322179c44df40220a21806e1a0d17d25cc437a9a7e252cd4b1cf9d9636",
    "architecture/run-manifest/round2/scripts/run_manifest.py": "3810befc0ed3bd8213a8ac3d3021f19e87620d27e0e7b114263302f58ecededa",
    "architecture/run-manifest/round2/selection-record.schema.json": "43dd05a99b299760b378d0526a501c6b989d2f7d707435cd82b7e78501bc90d3",
    "architecture/run-manifest/round2/split-declaration.schema.json": "f0247744e5f2e2c23db51ce63f7ed5a7a881f6986e2ee7d308ee5c65e6184a09",
    "architecture/run-manifest/round3/README.md": "96c3b48ee170fd1adbd836b88e563ce1b541b93065fbbb84c86627664546a36d",
    "architecture/run-manifest/round3/distribution-gate.schema.json": "f521fc6691984959473ef4f184e863193c060acc0b2ed1012dcf1d2c9d3a1683",
    "architecture/run-manifest/round3/evaluation-record.schema.json": "8b34740168f5a96f0186b69f9a1a43c544fdd971ed052f8e723c14dda1c3e625",
    "architecture/run-manifest/round3/run-manifest.schema.json": "ec62c1322179c44df40220a21806e1a0d17d25cc437a9a7e252cd4b1cf9d9636",
    "architecture/run-manifest/round3/scripts/run_manifest.py": "c00dc06b8ed5efec64ef37cb44406cd94d32cc06dccde832d30d96dc2633d5e4",
    "architecture/run-manifest/round3/selection-record.schema.json": "43dd05a99b299760b378d0526a501c6b989d2f7d707435cd82b7e78501bc90d3",
    "architecture/run-manifest/round3/split-declaration.schema.json": "f0247744e5f2e2c23db51ce63f7ed5a7a881f6986e2ee7d308ee5c65e6184a09",
    "architecture/run-manifest/run-manifest.schema.json": "ec62c1322179c44df40220a21806e1a0d17d25cc437a9a7e252cd4b1cf9d9636",
    "architecture/run-manifest/selection-record.schema.json": "43dd05a99b299760b378d0526a501c6b989d2f7d707435cd82b7e78501bc90d3",
    "architecture/run-manifest/split-declaration.schema.json": "f0247744e5f2e2c23db51ce63f7ed5a7a881f6986e2ee7d308ee5c65e6184a09",
    "architecture/run-manifest/status.json": "eb3ddd45e43ab6b2dc8c1272e338c49cf15bbe91794e22ddb47026ac1b28b5b7",
    "architecture/run-manifest/vectors.json": "43bcd436efdfe4270677b7a8d04cca30859c41e6d8de1f6ff5413dc9770d44b3",
    "docs/harnesses/trust.evaluation-assurance.md": "57b73641ad2362dd31948d57ab810f76f6f5285a254545fe1a7f031b160e860c",
    "scripts/run_manifest.py": "f2861b4c23ad51fc5b8cdd9910124b23d2c114bd61786e58d93b20f42f3f423e"
})


def reviewed_bytes(path: str) -> bytes:
    """This packet's reviewed bytes of path; a bridged successor projects newer bytes back first."""
    return successor.historical_bytes(path, regular_bytes(path))


def _verified(path: str) -> bytes:
    """reviewed_bytes, checked against its era digest on every read; a path outside the era is refused."""
    raw = reviewed_bytes(path)
    expected = ERA_SHA256.get(path)
    require(expected is not None and digest(raw) == expected, "MAS-RA-002 reviewed bytes are bound: " + path)
    return raw


def _json(path: str) -> Any:
    return parse(_verified(path))


def _bound(check: Any, message: str) -> None:
    """A structural check over a module's result or a record; a malformed one is refused, not raised."""
    try:
        holds = check()
    except (KeyError, TypeError, AttributeError, IndexError, ValueError):
        holds = False
    require(holds is True, message)


def _era_model(path: str, name: str) -> types.ModuleType:
    """A reference module of this era, executed from its verified bytes."""
    module = types.ModuleType(name)
    module.__file__ = str(ROOT / path)
    exec(compile(_verified(path), path, "exec", dont_inherit=True), module.__dict__)
    return module


def validate_era_bytes() -> None:
    """Every reviewed file of this era is bound by digest before anything is parsed or executed; H16 and the schemas are
    frozen."""
    for path in _PROJECTION_RULES:
        require(path not in FROZEN_PATHS and not path.startswith(FROZEN_PREFIXES),
                "H16's harness document and the repository schemas stay byte-identical")
    for path, expected in ERA_SHA256.items():
        require(digest(reviewed_bytes(path)) == expected, "MAS-RA-002 reviewed bytes are bound: " + path)


def validate_run_manifest_status() -> None:
    """Adopted after independent review rounds, each bound to its record, the last a pass on the reviewed subject with
    nothing open; the README's status line is the one adoption edit."""
    status = _json(STATUS_PATH)
    require(type(status) is dict and set(status) == set(STATUS_KEYS)
            and status["schemaVersion"] == "planeon.internal.run-manifest-status/v1"
            and status["workItem"] == "MAS-RA-002" and status["status"] == "ADOPTED_CONTRACT_CANDIDATE"
            and status["contract"] == CONTRACT and status["reviewedSubject"] == REVIEWED_SUBJECT
            and status["acceptance"] == ACCEPTANCE and status["ownerDecisions"] == DECISIONS
            and status["nonClaims"] == NON_CLAIMS and type(status["carried"]) is list
            and all(type(row) is dict and set(row) == {"item", "severity", "to", "action"} for row in status["carried"]),
            "adopted MAS-RA-002 status")
    readme = _verified(README_PATH).decode("utf-8")
    edit = status["adoptionEdit"]
    _bound(lambda: edit == {"path": README_PATH, "replaced": STATUS_LINE[0], "with": STATUS_LINE[1],
                            "reviewedSha256": edit["reviewedSha256"], "adoptedSha256": ERA_SHA256[README_PATH]}
           and readme.count(STATUS_LINE[1]) == 1 and STATUS_LINE[0] not in readme
           and digest(readme.replace(STATUS_LINE[1], STATUS_LINE[0]).encode("utf-8")) == edit["reviewedSha256"],
           "the README's status line is the one adoption edit")
    rounds = status["rounds"]
    previous: list = []
    require(type(rounds) is list and all(type(row) is dict for row in rounds)
            and [(row.get("round"), row.get("verdict")) for row in rounds] == list(ROUNDS), "review rounds in order")
    for row in rounds:
        number = row["round"]
        earlier = number < LAST_ROUND
        require(set(row) == set(ROW_KEYS) | ({"digestOnly"} if earlier else set())
                and row["record"] == CONTRACT_DIR + "review-round%d.json" % number
                and row["snapshot"] == (CONTRACT_DIR + "round%d/" % number if earlier else None),
                "review round %d row" % number)
        if earlier:
            _bound(lambda: set(row["digestOnly"]) == {VECTORS_PATH}
                   and type(row["digestOnly"][VECTORS_PATH]) is str and len(row["digestOnly"][VECTORS_PATH]) == 64
                   and set(row["digestOnly"][VECTORS_PATH]) <= set("0123456789abcdef")
                   and all(CONTRACT_DIR + "round%d/" % number + name in ERA_SHA256 for name in SNAPSHOT_FILES),
                   "review round %d snapshot" % number)
        record = _json(row["record"])
        require(type(record) is dict and record.get("schemaVersion") == REVIEW_SCHEMA and record.get("round") == number
                and record.get("subjectCommit") == row["subject"] and record.get("subjectTree") == row["subjectTree"]
                and record.get("verdict") == row["verdict"], "review round %d identity" % number)
        actions = record.get("actions")
        require(type(actions) is dict and actions.get("filesEdited") is False and actions.get("personalDataSent") is False
                and actions.get("networkAccessed") == "none",
                "review round %d edited nothing, used no network and sent no personal data" % number)
        findings = record.get("findings")
        dispositions = record.get("dispositions")
        require(type(findings) is list and all(type(item) is dict and item.get("severity") in SEVERITIES for item in findings)
                and row["severities"] == sorted({item["severity"] for item in findings})
                and type(dispositions) is list and all(type(item) is dict and "disposition" in item and "finding" in item for item in dispositions)
                and (number > 1 or dispositions == []), "review round %d severities and dispositions" % number)
        if number > 1:   # every finding of the previous round has a recorded disposition
            require({item.get("id") for item in previous} <= {item.get("finding") for item in dispositions},
                    "review round %d disposes of every round %d finding" % (number, number - 1))
        previous = findings
    final = rounds[-1]
    require(final["subject"] == REVIEWED_SUBJECT["commit"] and final["subjectTree"] == REVIEWED_SUBJECT["tree"]
            and final["verdict"] == "PASS_FOR_SOURCE_PUBLICATION" and set(final["severities"]) <= {"NOTE"},
            "the passing round reviewed this subject and left notes only")
    require({item["id"] for item in previous} == {row["item"] for row in status["carried"]},
            "every note of the passing round is carried")


def _outcome(model: types.ModuleType, call: Any) -> Any:
    try:
        call()
    except model.Refused as refusal:
        return refusal.code
    return None


def validate_run_manifest_contract() -> None:
    """The contract's model from this era's bytes replays every vector; the codes, schema identities, counts, the
    critical-value table, the gate's outcomes and the H16 mapping are restated here."""
    model = _era_model(MODEL, "_met_mas_002_run_manifest")
    vectors = _json(VECTORS_PATH)
    schemas = {name: _json(CONTRACT_DIR + name) for name in SCHEMA_FILES}
    _bound(lambda: tuple(model.CODES) == CODES and tuple(vectors["codes"]) == CODES, "the refusal codes in their order")
    _bound(lambda: all(schemas[name]["$id"] == SCHEMA_IDS[name] for name in SCHEMA_FILES)
           and [model.SPLIT_SCHEMA, model.MANIFEST_SCHEMA, model.RECORD_SCHEMA, model.COMPARISON_SCHEMA,
                model.SELECTION_SCHEMA] == [SCHEMA_IDS[name] for name in SCHEMA_FILES], "the five schema identities")
    _bound(lambda: tuple(model.T_CRITICAL) == CRITICAL_TABLE and model.MIN_REPETITIONS == GATE_OUTCOMES["minRepetitions"]
           and tuple(model.PARTITIONS) == GATE_OUTCOMES["partitions"] and tuple(model.PURPOSES) == GATE_OUTCOMES["purposes"]
           and tuple(model.DECISIONS) == GATE_OUTCOMES["decisions"], "the critical-value table and the gate's outcomes")
    _bound(lambda: all(model.h16_state(*key) == state for key, state in H16_TABLE.items()),
           "the H16 mapping (NON_REGRESSION passes only a non-inferior candidate)")
    stores = vectors["stores"]
    checks = {"split": lambda d: model.check_split(d),
              "manifest": lambda d: model.check_manifest(d, stores["splits"]),
              "record": lambda d: model.check_record(d, stores["manifests"], stores["splits"]),
              "comparison": lambda d: model.check_comparison(d, stores["records"], stores["manifests"], stores["splits"]),
              "selection": lambda d: model.check_selection(d, stores["comparisons"], stores["records"], stores["manifests"],
                                                           stores["splits"])}
    _bound(lambda: {"cases": len(vectors["cases"]), "valid": sum(1 for row in vectors["cases"] if row["expect"] is None),
                    "texts": len(vectors["texts"]), "criticalValues": len(vectors["criticalValues"])} == VECTOR_COUNTS
           and {row["expect"] for row in vectors["cases"]} - {None} == set(CODES), "the vector counts, every code covered")
    for row in vectors["cases"]:
        facts: list = []
        got = _outcome(model, lambda: facts.append(checks[row["kind"]](row["document"])))
        _bound(lambda: got == row["expect"] and (not facts or "facts" not in row
               or {k: facts[0][k] for k in row["facts"]} == row["facts"]), "case " + str(row.get("id")))
    for row in vectors["texts"]:
        _bound(lambda: _outcome(model, lambda: checks[row["kind"]](model.parse(row["text"]))) == row["expect"],
               "text " + str(row.get("id")))
    for row in vectors["criticalValues"]:
        _bound(lambda: model.critical(row["df"]) == row["thousandths"], "critical value for df " + str(row.get("df")))


def validate_run_manifest() -> None:
    """Every reviewed byte and the adoption record first; then the contract from this era."""
    validate_era_bytes()
    validate_run_manifest_status()
    validate_run_manifest_contract()


def validate() -> None:
    record = authority()
    validator_raw = successor.historical_bytes(VALIDATOR_PATH, regular_bytes(VALIDATOR_PATH))
    literal = b'AUTHORITY_SHA256 = "' + AUTHORITY_SHA256.encode("ascii") + b'"'
    placeholder = b'AUTHORITY_SHA256 = "TO_BE_PINNED_AFTER_SOURCE_FREEZE"'
    require(validator_raw.count(literal) == 1
            and digest(validator_raw.replace(literal, placeholder))
            == record["validatorNormalizedSha256"], "run manifest validator drift")
    paths = sorted((ROOT / "task-packets").glob("*.yaml"))
    old = set(record["baselinePackets"])
    require(len(paths) == 259
            and {path.stem for path in paths} == old | {NEW_PACKET, successor.NEW_PACKET, successor.successor.NEW_PACKET, successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.NEW_PACKET},
            "closed 259-packet catalog retaining the 230-packet checkpoint")
    packets = {}
    for path in paths:
        if path.stem in (successor.NEW_PACKET, successor.successor.NEW_PACKET, successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.NEW_PACKET):
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
            "closed source-only run-manifest packet and inherited commands")
    require(len(packet["allowedPaths"]) == len(set(packet["allowedPaths"]))
            and set(packet["allowedPaths"]) == set(record["changedFiles"])
            | set(record["newFiles"]) | {AUTHORITY_PATH, VALIDATOR_PATH,
                                         "task-packets/" + NEW_PACKET + ".yaml"},
            "unreviewed or omitted run-manifest packet path")
    for path, rule in record["changedFiles"].items():
        current = successor.historical_bytes(path, regular_bytes(path))
        require(digest(current) == rule["afterSha256"]
                and digest(historical_bytes(path, current)) == rule["beforeSha256"],
                "unreviewed current source: " + path)
    for path, expected in record["newFiles"].items():
        require(digest(successor.historical_bytes(path, regular_bytes(path))) == expected,
                "new source drift: " + path)
    validate_run_manifest()


if __name__ == "__main__":
    validate()
    print("Run manifest valid: 259 current specifications; 230-packet checkpoint and exact 229-packet predecessor; contract reviewed.")
