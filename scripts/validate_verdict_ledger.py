#!/usr/bin/env python3
"""Validate the MET-MAS-001 verdict and evidence ledger contract and the exact 229-to-228 projection."""
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
    import validate_run_manifest as successor
except ImportError:
    from scripts.safe_yaml import safe_load
    from scripts import validate_run_manifest as successor


ROOT = Path(__file__).resolve().parents[1]
AUTHORITY_PATH = "architecture/verdict-ledger-authority.json"
AUTHORITY_SHA256 = "67831f983b0173d5ad6243080270a3d2e1c0522f2427196f46630a2e965a2539"
VALIDATOR_PATH = "scripts/validate_verdict_ledger.py"
BASE_COMMIT = "8d10a9d504660212fa7c1a589a3ca2180f50908d"
NEW_PACKET = "MET-MAS-001"
PREVIOUS_PACKET = "MET-ADOPT-003"
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
            require(key not in result, "duplicate verdict-ledger authority member")
            result[key] = value
        return result

    def no_constant(_value: str) -> Any:
        raise ValueError("nonfinite verdict-ledger authority number")

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
        require(digest(raw) == AUTHORITY_SHA256, "verdict ledger history authority digest")
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
    }, "closed verdict ledger history authority")
    require(value["schemaVersion"] == "harness.planeon.ai/verdict-ledger-authority/v1"
            and value["authorityPacket"] == NEW_PACKET
            and value["acceptedBase"] == BASE_COMMIT
            and type(value["baselinePackets"]) is dict
            and len(value["baselinePackets"]) == 228
            and NEW_PACKET not in value["baselinePackets"]
            and type(value["changedFiles"]) is dict
            and type(value["newFiles"]) is dict
            and _sha(value["packetSha256"])
            and _sha(value["validatorNormalizedSha256"]),
            "accepted 228-packet base")
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
    # An exact 228-era byte string is already older than the successor layer.
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


# MET-MAS-001 (roadmap MAS-RA-001) publishes the verdict and evidence ledger contract candidate
# planeon.internal.verdict-ledger/v1 (architecture/verdict-ledger/): its closed schema, check-kind registry, standard-library
# reference model and vectors, adopted after five independent review rounds, with H16's harness document and the
# repository schemas byte-identical. Repository bytes are read only through reviewed_bytes, so a later bridged successor
# projects its own edits away first. Every reviewed file of this era is bound by digest before anything is parsed, every
# later read is checked against that digest again, and the contract's model is executed from this era's reviewed bytes to
# replay every vector, so a later revision of the model cannot change how this layer judges its era. The owner's
# decisions, the vector counts, the refusal codes and the H16 mapping are restated here independently of the reviewed files.
CONTRACT_DIR = "architecture/verdict-ledger/"
MODEL = "scripts/verdict_ledger.py"
README_PATH = CONTRACT_DIR + "README.md"
SCHEMA_PATH = CONTRACT_DIR + "ledger.schema.json"
KINDS_PATH = CONTRACT_DIR + "check-kinds.json"
VECTORS_PATH = CONTRACT_DIR + "vectors.json"
STATUS_PATH = CONTRACT_DIR + "status.json"
H16_PATH = "docs/harnesses/trust.evaluation-assurance.md"
LEDGER_SCHEMA = "planeon.internal.verdict-ledger/v1"
REVIEWED_SUBJECT = {"commit": "2cf5617b55bf992ed77debc174cfd13ba40d1737", "tree": "d6496f1a28f140fd1c7165d0ba07e288dd2924a8"}
ROUNDS = ((1, 'CHANGES_REQUIRED'), (2, 'CHANGES_REQUIRED'), (3, 'PASS_FOR_SOURCE_PUBLICATION'), (4, 'PASS_FOR_SOURCE_PUBLICATION'), (5, 'PASS_FOR_SOURCE_PUBLICATION'))
LAST_ROUND = len(ROUNDS)
REVIEW_SCHEMA = "harness.planeon.ai/verdict-ledger-review/v1"
STATUS_KEYS = ("schemaVersion", "workItem", "status", "contract", "reviewedSubject", "adoptionEdit", "rounds", "carried",
               "acceptance", "ownerDecisions", "nonClaims")
ROW_KEYS = ("round", "subject", "subjectTree", "verdict", "record", "snapshot", "severities")
# An earlier round's snapshot holds these files; its vectors.json (regenerated every round, about 600 KB) is bound by digest.
SNAPSHOT_FILES = ("README.md", "ledger.schema.json", "check-kinds.json", "scripts/verdict_ledger.py")
CONTRACT = {"schema": SCHEMA_PATH, "checkKinds": KINDS_PATH, "vectors": VECTORS_PATH, "model": MODEL, "readme": README_PATH}
# The one adoption edit: the README's candidate status line becomes the adopted one.
STATUS_LINE = ('Status: **CONTRACT_CANDIDATE_ROUND5_AWAITING_INDEPENDENT_REVIEW**.', 'Status: **ADOPTED_CONTRACT_CANDIDATE** (independent review round 5: PASS_FOR_SOURCE_PUBLICATION; rounds and review records in `status.json`).')
SEVERITIES = ("MAJOR", "MINOR", "NOTE")
NON_CLAIMS = ["An internal contract candidate: no public contract, selector, catalog, schema or runtime change; H16's harness document and the repository schemas are byte-identical.", "No producer, consumer, service or signing path exists; the model runs only on the vectors.", "The cited figures are the source papers' results, not platform evidence."]
ACCEPTANCE = ["MAS-RA-001-A1", "MAS-RA-001-A2", "MAS-RA-001-A3"]
DECISIONS = ["Q-MAS1-A (a)", "Q-MAS1-B (a)", "Q-MAS1-C (a)", "Q-229 (a)"]
CODES = ('LEDGER_SHAPE', 'DUPLICATE_ID', 'UNKNOWN_REFERENCE', 'ROLLOUT_SET', 'CHECK_OMITTED', 'EVIDENCE_KIND_UNKNOWN', 'NOT_EVIDENCE', 'EVIDENCE_KIND_NOT_ALLOWED', 'PRODUCER_ROLE_NOT_ALLOWED', 'EVIDENCE_PROVENANCE', 'CONTEXTS_NOT_ISOLATED', 'CONTEXT_NOT_FRESH', 'GENERATING_CONTEXT_VERDICT', 'VERDICT_PRODUCER_ROLE', 'DETERMINISTIC_ORDER', 'DETERMINISTIC_OVERRIDE', 'NO_EVIDENCE', 'NO_DECIDING_CHECK', 'INTERMEDIATE_TARGET', 'CONSENSUS_ONLY', 'CONSISTENCY_ONLY', 'DISAGREEMENT_UNADJUDICATED', 'VALUE_NOT_ESTABLISHED', 'EVIDENCE_REF_UNBOUND', 'UNRESOLVED_CHECKS_MISMATCH', 'UNRESOLVED_PROMOTED', 'STATUS_MISMATCH')
HISTORY_CODES = ('HISTORY_SHAPE', 'HISTORY_SUBJECT', 'HISTORY_ID_REUSED', 'HISTORY_BROKEN', 'HISTORY_RETRY')
H16_STATES = {"PASS": "PASS", "FAIL": "FAIL", "UNRESOLVED": "WARN"}
VECTOR_COUNTS = {"aggregation": 6, "histories": 12, "ledgers": 112, "scopeDigests": 2, "texts": 7, "valid": 16}
# H16's harness document and every repository schema stay byte-identical: the contract is an internal candidate (Q-MAS1-B).
FROZEN_PATHS = (H16_PATH,)
FROZEN_PREFIXES = ("schemas/",)
# The adopted bytes of every contract file, round copy and review record, the status record and the model; the accepted
# base's H16 harness document.
ERA_SHA256 = MappingProxyType({
    "architecture/verdict-ledger/README.md": "dde6efc45fc2e1ad675635d0a18a1d6a82b49c960616af239f47071e2914e3f7",
    "architecture/verdict-ledger/check-kinds.json": "d53c5fb8e125c0c6588a327433870a3e6838328e741b12865691c5c2c6e3a3ac",
    "architecture/verdict-ledger/ledger.schema.json": "8a570cfb26b16fb3f7fa1cf799bd564fe717fd3d356dbca890dab747b2dc9326",
    "architecture/verdict-ledger/review-round1.json": "c18c809d964ae67414a738400c81e1497eaa8e06cc3d056a901aee58089d4d51",
    "architecture/verdict-ledger/review-round2.json": "89b5b9804d1154da1323e449c0ced602c1fbbc9c0d6d444a2676b8a49b78a3e2",
    "architecture/verdict-ledger/review-round3.json": "3dfa7e2e0b6cffa008bc8216768c90e2f345ea79e360632aaccc59c8c9a635d0",
    "architecture/verdict-ledger/review-round4.json": "e69531fd5da78fc66ea4ac92dcc6c15316f59c73114dc985e5d5c14b7b4d8036",
    "architecture/verdict-ledger/review-round5.json": "1f6a2873952bdc24b94b2dd3f461783d3290e26d0a4dec019f83333b325ba9fd",
    "architecture/verdict-ledger/round1/README.md": "bdb063cab8368e8a5e98b10cb6c8c518766814cc967877bd2fcc40ad87969092",
    "architecture/verdict-ledger/round1/check-kinds.json": "116715b6553f26c103ebfcb10206be1b15076843b7811970a614103d0a0a62bf",
    "architecture/verdict-ledger/round1/ledger.schema.json": "5fbfa1a1ea4bd9eaf323162aa09bf18e3102964bfd55eb5cac53a5ffd9d3b000",
    "architecture/verdict-ledger/round1/scripts/verdict_ledger.py": "56b7b5f6b4f4cf5191f1b919349f672b093757ff77645437f57cfdac7561d5c3",
    "architecture/verdict-ledger/round2/README.md": "de3e486329da2a6bcc1cafb379f1aedc5977e94530ad4e8fc06aefa6e76b9078",
    "architecture/verdict-ledger/round2/check-kinds.json": "06836ef84cbc004e5847202027a73cf8bcb0c7d3d1302e993b0d805f56a6d17c",
    "architecture/verdict-ledger/round2/ledger.schema.json": "f55e995d77d62f0fe587822ad29ba435089605fd7b791bf8f34bf63c8dd1ad1f",
    "architecture/verdict-ledger/round2/scripts/verdict_ledger.py": "4d783fedb6a43b0a98743f307642e848289318559054a31a7a27dd1f9ad39868",
    "architecture/verdict-ledger/round3/README.md": "4f2c8a384dcaca912ae8f8b7de7a56e999e2d4b5c42a4082a096d454c521158e",
    "architecture/verdict-ledger/round3/check-kinds.json": "d53c5fb8e125c0c6588a327433870a3e6838328e741b12865691c5c2c6e3a3ac",
    "architecture/verdict-ledger/round3/ledger.schema.json": "8a570cfb26b16fb3f7fa1cf799bd564fe717fd3d356dbca890dab747b2dc9326",
    "architecture/verdict-ledger/round3/scripts/verdict_ledger.py": "0902a5014544810799c4dad654011cdd1e382069eaec0d63b46dc4dfd55fab53",
    "architecture/verdict-ledger/round4/README.md": "669bf9e6b3c2725eb25a17e77164cb76bd7c869ab7c557d4d36d4838cb312a75",
    "architecture/verdict-ledger/round4/check-kinds.json": "d53c5fb8e125c0c6588a327433870a3e6838328e741b12865691c5c2c6e3a3ac",
    "architecture/verdict-ledger/round4/ledger.schema.json": "8a570cfb26b16fb3f7fa1cf799bd564fe717fd3d356dbca890dab747b2dc9326",
    "architecture/verdict-ledger/round4/scripts/verdict_ledger.py": "5b58a689e7c2d4e3f73ede724c92bd3f1085601114f66f8d4ec20ee808906307",
    "architecture/verdict-ledger/status.json": "ede913b97c7f869f1945c9114469a8876cb4f27487cc5f544a30819bc8c4ff76",
    "architecture/verdict-ledger/vectors.json": "d2331fc2278c7bc48f1c107586ac29e466fbd9216c33b6c060fee3af7ce585b5",
    "docs/harnesses/trust.evaluation-assurance.md": "57b73641ad2362dd31948d57ab810f76f6f5285a254545fe1a7f031b160e860c",
    "scripts/verdict_ledger.py": "5b58a689e7c2d4e3f73ede724c92bd3f1085601114f66f8d4ec20ee808906307"
})


def reviewed_bytes(path: str) -> bytes:
    """This packet's reviewed bytes of path; a bridged successor projects newer bytes back first."""
    return successor.historical_bytes(path, regular_bytes(path))


def _verified(path: str) -> bytes:
    """reviewed_bytes, checked against its era digest on every read; a path outside the era is refused."""
    raw = reviewed_bytes(path)
    expected = ERA_SHA256.get(path)
    require(expected is not None and digest(raw) == expected, "MAS-RA-001 reviewed bytes are bound: " + path)
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
        require(digest(reviewed_bytes(path)) == expected, "MAS-RA-001 reviewed bytes are bound: " + path)


def validate_verdict_ledger_status() -> None:
    """Adopted after independent review rounds, each bound to its record, the last a pass on the reviewed subject with
    nothing open; the README's status line is the one adoption edit."""
    status = _json(STATUS_PATH)
    require(type(status) is dict and set(status) == set(STATUS_KEYS)
            and status["schemaVersion"] == "planeon.internal.verdict-ledger-status/v1"
            and status["workItem"] == "MAS-RA-001" and status["status"] == "ADOPTED_CONTRACT_CANDIDATE"
            and status["contract"] == CONTRACT and status["reviewedSubject"] == REVIEWED_SUBJECT
            and status["acceptance"] == ACCEPTANCE and status["ownerDecisions"] == DECISIONS
            and status["nonClaims"] == NON_CLAIMS and type(status["carried"]) is list
            and all(type(row) is dict and set(row) == {"item", "severity", "to", "action"} for row in status["carried"]),
            "adopted MAS-RA-001 status")
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
                and type(dispositions) is list and all(type(item) is dict and "status" in item for item in dispositions)
                and (number > 1 or dispositions == []), "review round %d severities and dispositions" % number)
        if number > 1:   # every finding of the previous round has a recorded disposition
            require({item.get("id") for item in previous} <= {item.get("id") for item in dispositions},
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


def validate_verdict_ledger_contract() -> None:
    """The contract's model from this era's bytes replays every vector; the codes, counts, schema identity and the H16
    mapping are restated here."""
    model = _era_model(MODEL, "_met_mas_001_verdict_ledger")
    kinds, vectors, schema = _json(KINDS_PATH), _json(VECTORS_PATH), _json(SCHEMA_PATH)
    _bound(lambda: tuple(model.CODES) == CODES and tuple(model.HISTORY_CODES) == HISTORY_CODES
           and tuple(vectors["codes"]) == CODES and tuple(vectors["historyCodes"]) == HISTORY_CODES,
           "the ledger's refusal codes in their order")
    _bound(lambda: model.SCHEMA == LEDGER_SCHEMA and schema["$id"] == LEDGER_SCHEMA
           and schema["properties"]["schemaVersion"] == {"const": LEDGER_SCHEMA}
           and kinds["schemaVersion"] == model.KINDS_SCHEMA and kinds["h16EvidenceState"] == H16_STATES,
           "the ledger schema identity and the H16 mapping (UNRESOLVED is WARN)")
    _bound(lambda: {key: len(vectors[key]) for key in ("ledgers", "texts", "histories", "aggregation", "scopeDigests")}
           | {"valid": sum(1 for row in vectors["ledgers"] if row["expect"] is None)} == VECTOR_COUNTS
           and {row["expect"] for row in vectors["ledgers"]} - {None} == set(CODES),
           "the vector counts, every refusal code covered")
    for row in vectors["ledgers"]:
        facts: list = []
        got = _outcome(model, lambda: facts.append(model.check_ledger(row["ledger"], kinds)))
        _bound(lambda: got == row["expect"] and (not facts or [facts[0][key] for key in
               ("status", "h16EvidenceState", "ledgerDigest")] == [row[key] for key in
               ("status", "h16EvidenceState", "ledgerDigest")]), "ledger vector " + str(row.get("id")))
        if "withoutOwnRule" in row:
            _bound(lambda: _outcome(model, lambda: model.check_ledger(row["ledger"], kinds, (row["expect"],)))
                   == row["withoutOwnRule"], "ledger vector %s without its own rule" % row.get("id"))
    for row in vectors["texts"]:
        _bound(lambda: _outcome(model, lambda: model.check_text(row["text"], kinds)) == row["expect"],
               "text vector " + str(row.get("id")))
    for row in vectors["histories"]:
        _bound(lambda: _outcome(model, lambda: model.check_history(row["ledgers"], kinds)) == row["expect"],
               "history vector " + str(row.get("id")))
    for row in vectors["aggregation"]:
        _bound(lambda: model.aggregate([{"verdict": value} for value in row["claimVerdicts"]],
                                       [{}] * row["policyViolations"], ["K"] * row["unresolvedChecks"]) == row["status"]
               and H16_STATES[row["status"]] == row["h16EvidenceState"], "aggregation row " + str(row.get("id")))
    for row in vectors["scopeDigests"]:
        _bound(lambda: model.scope_digest(row["scope"]) == row["scopeDigest"], "scope digest " + str(row.get("id")))


def validate_verdict_ledger() -> None:
    """Every reviewed byte and the adoption record first; then the contract from this era."""
    validate_era_bytes()
    validate_verdict_ledger_status()
    validate_verdict_ledger_contract()


def validate() -> None:
    record = authority()
    validator_raw = successor.historical_bytes(VALIDATOR_PATH, regular_bytes(VALIDATOR_PATH))
    literal = b'AUTHORITY_SHA256 = "' + AUTHORITY_SHA256.encode("ascii") + b'"'
    placeholder = b'AUTHORITY_SHA256 = "TO_BE_PINNED_AFTER_SOURCE_FREEZE"'
    require(validator_raw.count(literal) == 1
            and digest(validator_raw.replace(literal, placeholder))
            == record["validatorNormalizedSha256"], "verdict ledger validator drift")
    paths = sorted((ROOT / "task-packets").glob("*.yaml"))
    old = set(record["baselinePackets"])
    require(len(paths) == 236
            and {path.stem for path in paths} == old | {NEW_PACKET, successor.NEW_PACKET, successor.successor.NEW_PACKET, successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.successor.NEW_PACKET},
            "closed 236-packet catalog retaining the 229-packet checkpoint")
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
            "closed source-only verdict-ledger packet and inherited commands")
    require(len(packet["allowedPaths"]) == len(set(packet["allowedPaths"]))
            and set(packet["allowedPaths"]) == set(record["changedFiles"])
            | set(record["newFiles"]) | {AUTHORITY_PATH, VALIDATOR_PATH,
                                         "task-packets/" + NEW_PACKET + ".yaml"},
            "unreviewed or omitted verdict-ledger packet path")
    for path, rule in record["changedFiles"].items():
        current = successor.historical_bytes(path, regular_bytes(path))
        require(digest(current) == rule["afterSha256"]
                and digest(historical_bytes(path, current)) == rule["beforeSha256"],
                "unreviewed current source: " + path)
    for path, expected in record["newFiles"].items():
        require(digest(successor.historical_bytes(path, regular_bytes(path))) == expected,
                "new source drift: " + path)
    validate_verdict_ledger()


if __name__ == "__main__":
    validate()
    print("Verdict ledger valid: 236 current specifications; 229-packet checkpoint and exact 228-packet predecessor; contract reviewed.")
