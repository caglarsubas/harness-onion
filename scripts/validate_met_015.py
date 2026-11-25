#!/usr/bin/env python3
"""Validate MET-015 (the execml grrt weights EXEC-ML-ADOPT-PINS-001, GR-REDTEAM-FIXTURES-001 and MODEL-WEIGHTS-POLICY-001, K = 1): V1 this packet's files by digest; the product packet by the authority's productPackets digest and its comparator pin; E1 each member's checker and, where it has one, its model from their era bytes; E2 the base files unchanged; E3 the authored edits at their named lines; V4 the registry rider; V6 the hunk-class record under v2.5."""
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
AUTHORITY_PATH = "architecture/execml-grrt-weights-authority.json"
AUTHORITY_SHA256 = "761b8eda945f72b7b6df423b685bee3638911e4d5e13c3b87a6afad55bfec259"
VALIDATOR_PATH = "scripts/validate_met_015.py"
BASE_COMMIT = "12ecc897dece54c7332eaad18e4c4b92243a0f08"
NEW_PACKET = "MET-015"
PREVIOUS_PACKET = "MET-014"
PRODUCT_PACKETS = ("EXEC-ML-ADOPT-PINS-001",)
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
            require(key not in result, "duplicate execml-grrt-weights authority member")
            result[key] = value
        return result

    def no_constant(_value: str) -> Any:
        raise ValueError("nonfinite execml-grrt-weights authority number")

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
        require(digest(raw) == AUTHORITY_SHA256, "execml grrt weights history authority digest")
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
        "packetSha256", "changedFiles", "newFiles", "validatorNormalizedSha256", "productPackets",
        "productComparators",
    }, "closed execml grrt weights history authority")
    require(value["schemaVersion"] == "harness.planeon.ai/execml-grrt-weights-authority/v1"
            and value["authorityPacket"] == NEW_PACKET
            and value["acceptedBase"] == BASE_COMMIT
            and type(value["baselinePackets"]) is dict
            and len(value["baselinePackets"]) == 320
            and NEW_PACKET not in value["baselinePackets"]
            and type(value["changedFiles"]) is dict
            and type(value["newFiles"]) is dict
            and _sha(value["packetSha256"])
            and _sha(value["validatorNormalizedSha256"]),
            "accepted 320-packet base")
    require(type(value["productPackets"]) is dict
            and list(value["productPackets"]) == list(PRODUCT_PACKETS)
            and all(_sha(sha) for sha in value["productPackets"].values())
            and not set(PRODUCT_PACKETS) & (set(value["baselinePackets"]) | {NEW_PACKET}),
            "product packets")
    require(type(value["productComparators"]) is dict
            and list(value["productComparators"]) == [p for p in PRODUCT_PACKETS if p in value["productComparators"]]
            and all(type(pin) is dict and set(pin) == {"packet", "sha256"} and type(pin["packet"]) is str
                    and _sha(pin["sha256"]) and value["baselinePackets"].get(pin["packet"]) == pin["sha256"]
                    for pin in value["productComparators"].values()),
            "product comparators")
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
                                 **{NEW_PACKET: record["packetSha256"]},
                                 **record["productPackets"]))


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
    require(NEW_PACKET in current_ids and set(packets) == current_ids | set(PRODUCT_PACKETS),
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
    return {name: packets[name] for name in current_ids - {NEW_PACKET} - set(PRODUCT_PACKETS)}


def validate_packet_payloads(packets: dict[str, Any]) -> None:
    """Check all current payloads separately from the inherited traversal."""
    record = authority()
    rules = _packet_rules()
    require(type(packets) is dict, "packet mapping")
    old = set(record["baselinePackets"])
    require(set(packets) == old | {NEW_PACKET} | set(PRODUCT_PACKETS), "unexpected packet addition or loss")
    require(set(rules) == old | {NEW_PACKET} | set(PRODUCT_PACKETS)
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


# MET-015 (rulings: CONTRACT_297 section 2) publishes, in a K = 1 step, the product packet
# EXEC-ML-ADOPT-PINS-001 (R08: the scikit-learn and ONNX Runtime provider dossiers; its bytes by the authority's
# productPackets digest, its comparator EXEC-TEMPORAL-PINS-001 by R13's pin) and two in-repo contracts, each a
# record with its checker and test: GR-REDTEAM-FIXTURES-001 (R12, the red-team and safety fixture pack with
# synthetic rows, vectors and a reference model) and MODEL-WEIGHTS-POLICY-001 (R06, the model weights record and
# the v3 licence amendment: vectors, no model). Repository bytes are read only through reviewed_bytes; an era
# file is refused unless bound by digest on every read, a changed file by the authority's afterSha256. Each
# refusal is a pure check over the values read. Checked here: V1 the packet's fourteen files by digest; E1 per
# member, its checker and its model from their era bytes (the record passes its checker; GR-REDTEAM-FIXTURES-001's
# vectors also replay here through its model to their expectation; MODEL-WEIGHTS-POLICY-001 has no replay half,
# its checker's MW_VECTORS row checks its vectors); E2 the base files unchanged; E3 class-other hunks only at the
# named spans, read under v2.5; V4 the registry rider; V6 the hunk-class record under v2.5. Last, this layer's
# own inverse hunks are the canonical ones.
PACKET_FILES = (
    'architecture/model-weights/record.json',
    'architecture/model-weights/schema.json',
    'architecture/model-weights/vectors.json',
    'architecture/redteam-fixtures/record.json',
    'architecture/redteam-fixtures/schema.json',
    'architecture/redteam-fixtures/vectors.json',
    'legal/license-policy-amendment-v3/README.md',
    'legal/license-policy-amendment-v3/amendment.json',
    'scripts/redteam_fixtures.py',
    'scripts/validate_model_weights.py',
    'scripts/validate_redteam_fixtures.py',
    'task-packets/EXEC-ML-ADOPT-PINS-001.yaml',
    'tests/test_model_weights.py',
    'tests/test_redteam_fixtures.py',
)
BASE_FILES = (
    'architecture/artifact-edges/README-v13.md',
    'architecture/artifact-edges/operator-harness-engineering-v13.json',
    'architecture/broker-handoff-inputs-v2/channel.schema.json',
    'architecture/broker-handoff-inputs-v2/vectors.json',
    'architecture/decision-record/README.md',
    'architecture/decision-record/decision-record.schema.json',
    'architecture/decision-record/reason-codes.json',
    'architecture/decision-record/status.json',
    'architecture/decision-record/vectors.json',
    'architecture/regulatory-alignment-README.md',
    'architecture/regulatory-alignment.json',
    'architecture/replay-fixtures/blobs/1bc09642184d86e64d54ef2a4953b1f7c31e9895c9b61f1eb5388a89709d1005',
    'architecture/replay-fixtures/blobs/579a20ff1a7d66537d3dcfebb9bb4737af33b958fb035d3e4f1bf4c8b06577d3',
    'architecture/replay-fixtures/blobs/5a199d83be3aa60ee4d49a525404f9645731bc2d8a3aeb509b0ec6f7d6e2e19a',
    'architecture/replay-fixtures/blobs/747cdabd6bf031f659e13d3e82220675c2d4efefa870565345c1aedb32e24655',
    'architecture/replay-fixtures/blobs/acc5ae84d03f6482f941175e523f5ea0be8ad8b9fd9c90e78264ec051af6c591',
    'architecture/replay-fixtures/blobs/af07c72fda48892f71f1742b49448e25711e971752223620d32a74631f48aaaa',
    'architecture/replay-fixtures/blobs/e5f1eb4d806641698a35efe20e098efd20d7d57a9b90ee69079d5bb650920726',
    'architecture/replay-fixtures/fixtures/fx-dev-0001.t1.json',
    'architecture/replay-fixtures/fixtures/fx-dev-0001.v1.json',
    'architecture/replay-fixtures/fixtures/fx-dev-0002.t1.json',
    'architecture/replay-fixtures/fixtures/fx-dev-0002.v1.json',
    'architecture/replay-fixtures/fixtures/split-fx-dev.json',
    'architecture/replay-fixtures/record.json',
    'architecture/replay-fixtures/schema.json',
    'architecture/replay-fixtures/vectors.json',
    'architecture/research-adoption-v2/README.md',
    'architecture/research-adoption-v2/crosswalk.json',
    'architecture/research-adoption-v2/review-round1.json',
    'architecture/research-adoption-v2/review-round2.json',
    'architecture/research-adoption-v2/review-round3.json',
    'architecture/research-adoption-v2/review-round4.json',
    'architecture/research-adoption-v2/round2/README.md',
    'architecture/research-adoption-v2/round2/crosswalk.json',
    'architecture/research-adoption-v2/round2/scripts/research_adoption_v2.py',
    'architecture/research-adoption-v2/round3/README.md',
    'architecture/research-adoption-v2/round3/crosswalk.json',
    'architecture/research-adoption-v2/round3/scripts/research_adoption_v2.py',
    'architecture/research-adoption-v2/status.json',
    'architecture/run-manifest/README.md',
    'architecture/run-manifest/distribution-gate.schema.json',
    'architecture/run-manifest/evaluation-record.schema.json',
    'architecture/run-manifest/review-round1.json',
    'architecture/run-manifest/review-round2.json',
    'architecture/run-manifest/review-round3.json',
    'architecture/run-manifest/review-round4.json',
    'architecture/run-manifest/round1/README.md',
    'architecture/run-manifest/round1/distribution-gate.schema.json',
    'architecture/run-manifest/round1/evaluation-record.schema.json',
    'architecture/run-manifest/round1/run-manifest.schema.json',
    'architecture/run-manifest/round1/scripts/run_manifest.py',
    'architecture/run-manifest/round1/selection-record.schema.json',
    'architecture/run-manifest/round1/split-declaration.schema.json',
    'architecture/run-manifest/round2/README.md',
    'architecture/run-manifest/round2/distribution-gate.schema.json',
    'architecture/run-manifest/round2/evaluation-record.schema.json',
    'architecture/run-manifest/round2/run-manifest.schema.json',
    'architecture/run-manifest/round2/scripts/run_manifest.py',
    'architecture/run-manifest/round2/selection-record.schema.json',
    'architecture/run-manifest/round2/split-declaration.schema.json',
    'architecture/run-manifest/round3/README.md',
    'architecture/run-manifest/round3/distribution-gate.schema.json',
    'architecture/run-manifest/round3/evaluation-record.schema.json',
    'architecture/run-manifest/round3/run-manifest.schema.json',
    'architecture/run-manifest/round3/scripts/run_manifest.py',
    'architecture/run-manifest/round3/selection-record.schema.json',
    'architecture/run-manifest/round3/split-declaration.schema.json',
    'architecture/run-manifest/run-manifest.schema.json',
    'architecture/run-manifest/selection-record.schema.json',
    'architecture/run-manifest/split-declaration.schema.json',
    'architecture/run-manifest/status.json',
    'architecture/run-manifest/vectors.json',
    'legal/license-policy-amendment-v2/README.md',
    'legal/license-policy-amendment-v2/REVIEW_BRIEF.md',
    'legal/license-policy-amendment-v2/amendment.json',
    'legal/license-policy-amendment-v2/review-round1.json',
    'legal/license-policy-amendment-v2/review-round2.json',
    'legal/license-policy-amendment-v2/review-round3.json',
    'legal/license-policy-amendment-v2/round1/legal/license-policy-amendment-v2/README.md',
    'legal/license-policy-amendment-v2/round1/legal/license-policy-amendment-v2/REVIEW_BRIEF.md',
    'legal/license-policy-amendment-v2/round1/legal/license-policy-amendment-v2/amendment.json',
    'legal/license-policy-amendment-v2/round1/legal/license-policy-amendment-v2/vectors.json',
    'legal/license-policy-amendment-v2/round1/scripts/license_amendment_v2.py',
    'legal/license-policy-amendment-v2/round2/legal/license-policy-amendment-v2/README.md',
    'legal/license-policy-amendment-v2/round2/legal/license-policy-amendment-v2/REVIEW_BRIEF.md',
    'legal/license-policy-amendment-v2/round2/legal/license-policy-amendment-v2/amendment.json',
    'legal/license-policy-amendment-v2/round2/scripts/license_amendment_v2.py',
    'legal/license-policy-amendment-v2/status.json',
    'legal/license-policy-amendment-v2/vectors.json',
    'legal/license-policy-amendment/README.md',
    'legal/license-policy-amendment/REVIEW_BRIEF.md',
    'legal/license-policy-amendment/amendment.json',
    'legal/license-policy-amendment/review-round1.json',
    'legal/license-policy-amendment/review-round2.json',
    'legal/license-policy-amendment/review-round3.json',
    'legal/license-policy-amendment/review-round4.json',
    'legal/license-policy-amendment/round1/README.md',
    'legal/license-policy-amendment/round1/REVIEW_BRIEF.md',
    'legal/license-policy-amendment/round1/amendment.json',
    'legal/license-policy-amendment/round1/scripts/license_amendment.py',
    'legal/license-policy-amendment/round1/vectors.json',
    'legal/license-policy-amendment/round2/README.md',
    'legal/license-policy-amendment/round2/REVIEW_BRIEF.md',
    'legal/license-policy-amendment/round2/amendment.json',
    'legal/license-policy-amendment/round2/scripts/license_amendment.py',
    'legal/license-policy-amendment/round2/vectors.json',
    'legal/license-policy-amendment/round3/README.md',
    'legal/license-policy-amendment/round3/REVIEW_BRIEF.md',
    'legal/license-policy-amendment/round3/amendment.json',
    'legal/license-policy-amendment/round3/scripts/license_amendment.py',
    'legal/license-policy-amendment/round3/vectors.json',
    'legal/license-policy-amendment/status.json',
    'legal/license-policy-amendment/vectors.json',
    'legal/third-party-license-policy.yaml',
    'scripts/broker_handoff_transcript_v2.py',
    'scripts/decision_record.py',
    'scripts/license_amendment.py',
    'scripts/license_amendment_v2.py',
    'scripts/replay_fixtures.py',
    'scripts/validate_decision_record.py',
    'scripts/validate_edge_record_v13.py',
    'scripts/validate_regulatory_alignment.py',
    'scripts/validate_replay_fixtures.py',
    'task-packets/EXEC-TEMPORAL-PINS-001.yaml',
    'tests/test_decision_record.py',
    'tests/test_edge_record_v13.py',
    'tests/test_regulatory_alignment.py',
)
REGISTRY_BASE_SHA256 = "d025907a514fe67c39d8ce53030fc7d50c8fb61f3aa62b5a82e3dfda31b83c44"
BASE_SHA256 = MappingProxyType({
    "architecture/artifact-edges/README-v13.md": "4c15590d34eabee19fd8396888be4d0b0ffdfd1496955d98dcda255ffa5af7b3",
    "architecture/artifact-edges/operator-harness-engineering-v13.json": "4f1b77aa3c0ae93307d2b793d92de2416af8630c27688f925745350c7cbd1226",
    "architecture/broker-handoff-inputs-v2/channel.schema.json": "b050af6bec767beef0796ee4a25edb76b6e761a9b793a4ffd16b4907e910f34e",
    "architecture/broker-handoff-inputs-v2/vectors.json": "b6154ebc18fe2fcb552971f88af5065441f757eba1b70cddef0090fda260a43d",
    "architecture/decision-record/README.md": "0ff769568fe284f437d781aec649cf3ba1bdbd8efa4b7511481b56607e5d4233",
    "architecture/decision-record/decision-record.schema.json": "56e9694bfb93c04c66e058eeda412b6e8ca187c9d66285baec717112f659bad6",
    "architecture/decision-record/reason-codes.json": "86b72e8a3737004914a1a0a4c92927a107ad406ed0c09a37a09ba00083e2fa53",
    "architecture/decision-record/status.json": "fe54c9b78f133c63e339316730090263469def180d298180aeb9dffea63474d2",
    "architecture/decision-record/vectors.json": "a2183e019321f6a7b1f721d56ce76953670a584af99013c1828f1016f102cb62",
    "architecture/regulatory-alignment-README.md": "5fce1c75110b0222f603ea0fed3a2af705ec4e0dc06f3c68b9ec8c24f69de733",
    "architecture/regulatory-alignment.json": "98532820261fa1a51a67998fff1126586329a5b5ef7fe09e0e026501b24e95e1",
    "architecture/replay-fixtures/blobs/1bc09642184d86e64d54ef2a4953b1f7c31e9895c9b61f1eb5388a89709d1005": "1bc09642184d86e64d54ef2a4953b1f7c31e9895c9b61f1eb5388a89709d1005",
    "architecture/replay-fixtures/blobs/579a20ff1a7d66537d3dcfebb9bb4737af33b958fb035d3e4f1bf4c8b06577d3": "579a20ff1a7d66537d3dcfebb9bb4737af33b958fb035d3e4f1bf4c8b06577d3",
    "architecture/replay-fixtures/blobs/5a199d83be3aa60ee4d49a525404f9645731bc2d8a3aeb509b0ec6f7d6e2e19a": "5a199d83be3aa60ee4d49a525404f9645731bc2d8a3aeb509b0ec6f7d6e2e19a",
    "architecture/replay-fixtures/blobs/747cdabd6bf031f659e13d3e82220675c2d4efefa870565345c1aedb32e24655": "747cdabd6bf031f659e13d3e82220675c2d4efefa870565345c1aedb32e24655",
    "architecture/replay-fixtures/blobs/acc5ae84d03f6482f941175e523f5ea0be8ad8b9fd9c90e78264ec051af6c591": "acc5ae84d03f6482f941175e523f5ea0be8ad8b9fd9c90e78264ec051af6c591",
    "architecture/replay-fixtures/blobs/af07c72fda48892f71f1742b49448e25711e971752223620d32a74631f48aaaa": "af07c72fda48892f71f1742b49448e25711e971752223620d32a74631f48aaaa",
    "architecture/replay-fixtures/blobs/e5f1eb4d806641698a35efe20e098efd20d7d57a9b90ee69079d5bb650920726": "e5f1eb4d806641698a35efe20e098efd20d7d57a9b90ee69079d5bb650920726",
    "architecture/replay-fixtures/fixtures/fx-dev-0001.t1.json": "7270f3af455f87e6cb1160b8f15bfe6e00c7602178c52bef6ec7ba1d37a3cdca",
    "architecture/replay-fixtures/fixtures/fx-dev-0001.v1.json": "694eca20522587acee03495c0a026b74f529988f819c1836dc11a750793bb225",
    "architecture/replay-fixtures/fixtures/fx-dev-0002.t1.json": "081a2f36d05dc04aaa70921ac7a73beef6814937761b8601ed0b65ddee56ca10",
    "architecture/replay-fixtures/fixtures/fx-dev-0002.v1.json": "83e07494c62c0651ea6c7ca6e85fdb83cba18cddfa2d29a02a251f2c1fb59904",
    "architecture/replay-fixtures/fixtures/split-fx-dev.json": "4d41d4b3831364c1b11432f12652590ce3b20c4923f2eced5a67a4cc12821251",
    "architecture/replay-fixtures/record.json": "9d36696bb1e28507713e72357d49a404478fef65fc60862535db1bc322e93b9b",
    "architecture/replay-fixtures/schema.json": "dd8242f5965f3d89a801005b8de92d923fb7ba621532d637b4b50669113d1f19",
    "architecture/replay-fixtures/vectors.json": "da29179b1ef8d6b439659a696a077ba4d7be835cf9db764c04f746088ad59f1e",
    "architecture/research-adoption-v2/README.md": "8b73cd069511db4ea2246b7a022eb2d7c5905ca9b6374bdf9e48977b08d07a7c",
    "architecture/research-adoption-v2/crosswalk.json": "e1b57c70a63f9b71994b2c25b4c786c9721f34ef34f08729ae6e9fc209010a75",
    "architecture/research-adoption-v2/review-round1.json": "aa1ccb39c6192453f190b36e81b754cd4e0e7300ca9c340b054f2879f9c07eb8",
    "architecture/research-adoption-v2/review-round2.json": "32699fce4b20a8944661a3750eccdb928c5d27c5964b735a155aca67ecc50162",
    "architecture/research-adoption-v2/review-round3.json": "ba8a8468fe39d026cda1230e78047d0c7011f9897893299630660a3405d7cf5f",
    "architecture/research-adoption-v2/review-round4.json": "cb4e7e28cea677c4a2a1d0f90f4a4d8af71d85db351955bb161d3dd409782d2f",
    "architecture/research-adoption-v2/round2/README.md": "53c5499a68e4a53e86ed4273962585a32643929bbbda8c5b070e6d3d79678173",
    "architecture/research-adoption-v2/round2/crosswalk.json": "76d5a8fc1835504713c2c304f8ca6f4a6ebbdd66f45945aa0f47ed69195e02b7",
    "architecture/research-adoption-v2/round2/scripts/research_adoption_v2.py": "21ea93817dfe50567c9733e34af5e0d19a7f7df5e7b9cc0cdaa43abe1b1a7de1",
    "architecture/research-adoption-v2/round3/README.md": "8cf678ca238dd60811eed9baa637f2f36a91ca83bb8e172a9ee76e82180ddb56",
    "architecture/research-adoption-v2/round3/crosswalk.json": "393304168587335e8e773c2300053937ac9afd4af0a139cc0c384ce783d94a6b",
    "architecture/research-adoption-v2/round3/scripts/research_adoption_v2.py": "ca9dfda2e4fef6c625b9f6e5b35fd07de2279d20df7b6949c3f699de63f33f68",
    "architecture/research-adoption-v2/status.json": "90b7ecf0718a3b100ad1d3824e2f4d71c3e04a58f787f438abc51bcde1cc4d81",
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
    "legal/license-policy-amendment-v2/README.md": "740ee084dcadaa9f3880f99b04dd6ad3f15c8cb55389864f4f226ee470c7f3ce",
    "legal/license-policy-amendment-v2/REVIEW_BRIEF.md": "b3e5ea8514301708e6438b27cb526bbf9a353fc4255e4b6108beda7f6d93fd83",
    "legal/license-policy-amendment-v2/amendment.json": "05984db7339c60cf0d4b9acc1179bd0b5fbb16c6f2f4dd554889388133e8f3a7",
    "legal/license-policy-amendment-v2/review-round1.json": "0fbbaa289ae5a0bc77aaeb0293910bacecfef9ddcf06ff1ddd90eba66f97689a",
    "legal/license-policy-amendment-v2/review-round2.json": "d75eecb7e012f5dcbcf4b61b747a2dfb5bbd9101806514cdec43ee7b4bc3931e",
    "legal/license-policy-amendment-v2/review-round3.json": "10831f2e1166c7e669f490069d77062a95ab6a76c4e72dfa3c7b44ee128adfb1",
    "legal/license-policy-amendment-v2/round1/legal/license-policy-amendment-v2/README.md": "d2c390a1367b9213ec19e2054c98de54291cc025fc8de24c685b47b9006bcc9a",
    "legal/license-policy-amendment-v2/round1/legal/license-policy-amendment-v2/REVIEW_BRIEF.md": "32cd0720aefaf1201f9a1d0c1f6d15c4ecc71a655050cf633c702e5d6c331324",
    "legal/license-policy-amendment-v2/round1/legal/license-policy-amendment-v2/amendment.json": "d58079a2d9565c7bf358fad0661985bc399ed0828a3de243fe91e7bd3ce12bbd",
    "legal/license-policy-amendment-v2/round1/legal/license-policy-amendment-v2/vectors.json": "fbc93a278671e77cf2ea9534acc37bff03d50de94dedb32db15621f26f820ec0",
    "legal/license-policy-amendment-v2/round1/scripts/license_amendment_v2.py": "45d344ca15a9862ea4ce293e62875592721559e6dc813af662f85e8e1983e149",
    "legal/license-policy-amendment-v2/round2/legal/license-policy-amendment-v2/README.md": "55e99f3035852e1a5ef60cd12cfeead6ac728ffdd20ef8dd9b3ea76511238dcb",
    "legal/license-policy-amendment-v2/round2/legal/license-policy-amendment-v2/REVIEW_BRIEF.md": "8caeef9c9983e5b6901dceeebd628b7c3c56b81176e62ff1dda0fd24d55528ea",
    "legal/license-policy-amendment-v2/round2/legal/license-policy-amendment-v2/amendment.json": "818aaedd4ab01295f57754035ea673baac7762fa4e48f255449e1a05241183e0",
    "legal/license-policy-amendment-v2/round2/scripts/license_amendment_v2.py": "d9a2ff19ce90f0994681f5098afe0b80195c3804196257b122e0289087a46574",
    "legal/license-policy-amendment-v2/status.json": "2b760f53dca5fcd627b7684549bb5402ab8f357a237881ba4cdba72c824821cf",
    "legal/license-policy-amendment-v2/vectors.json": "aaab430c9f011e164915e83677997cfbe6b62b29e3ca923a5c23b7a680ebd6b9",
    "legal/license-policy-amendment/README.md": "ba204cc0bd86444028355725546d2b0971dfe5d6bef8b06f9f7156dd93380646",
    "legal/license-policy-amendment/REVIEW_BRIEF.md": "6c70d5672446ae5a0739fff0be8cfcd9fe1683f1dc37194653b295ad39fe4251",
    "legal/license-policy-amendment/amendment.json": "f6a8c0796857cf40906df3e6bc483122988b91271cc77b3aaed4d4e213d864c2",
    "legal/license-policy-amendment/review-round1.json": "01c48cf4d3fe5ed2fc4f3695dab9ebe5a98222c8e1973177893cb4c3773a4a2d",
    "legal/license-policy-amendment/review-round2.json": "10133203680941956eaee43dde7628c417834c2148c344ffb4d1bff30558f93c",
    "legal/license-policy-amendment/review-round3.json": "e073b9d6385fa571ff80a4bae7ba9980855c890375a53220469a72241b17fd8c",
    "legal/license-policy-amendment/review-round4.json": "46189374349481dadceed5c631be43ee6ead055dccb23bb17f357be4b48df6a9",
    "legal/license-policy-amendment/round1/README.md": "057078e15b0f694efbe008f69b4a206e717481332129846c1d14e1c9020ea573",
    "legal/license-policy-amendment/round1/REVIEW_BRIEF.md": "12da796fb7c6ff152e0f56be45c43a4c5bfeea8527d342e811899a092749130b",
    "legal/license-policy-amendment/round1/amendment.json": "b99a38851035f6944f1bee6548f5a59625c683594ce1739b9b5d7a77b1bc244e",
    "legal/license-policy-amendment/round1/scripts/license_amendment.py": "34f51249de4270caa64cfbfb84136aa315f28a6a91ae063158151644e64f9cbd",
    "legal/license-policy-amendment/round1/vectors.json": "d53e4bfec04df55014ef6171f5d140eb3b3cee5eac252c4bb8d209365bb58a46",
    "legal/license-policy-amendment/round2/README.md": "ceb46141a8677255067557e1e55d0a3b5b803a422b3ab914585f167a8d6020c0",
    "legal/license-policy-amendment/round2/REVIEW_BRIEF.md": "7bfe81322949c5319fdc3063b88d2fac52c8a5e9e49572312a4dd07b471f011b",
    "legal/license-policy-amendment/round2/amendment.json": "b95016325e35470bd654d6353697ae7aa5625458d3ce2110dee85e921f15f95f",
    "legal/license-policy-amendment/round2/scripts/license_amendment.py": "b944b02edc9bcacc226d16d32850b0f258938ad4549129ba207f4c9fc845e99c",
    "legal/license-policy-amendment/round2/vectors.json": "bf4aa6d0200f5ed443666348f851fa9b74b462e2fdb4247a5dbcd10651190f69",
    "legal/license-policy-amendment/round3/README.md": "86bc4c7bb6eba3dbfac186df7ed0cdd8538ecaae9e966d3edad9943eb024ce54",
    "legal/license-policy-amendment/round3/REVIEW_BRIEF.md": "d4475c1b2f74df031cd444edd771cf4f7f80fc37202e6da748aa4f38ef0b8cd2",
    "legal/license-policy-amendment/round3/amendment.json": "7c956dabbf0c24a00080dfd80483b917ba3d0c588f355a96580867c589a10827",
    "legal/license-policy-amendment/round3/scripts/license_amendment.py": "9f4a1c3766488010964d9f622c2580fb636ade015fe7695964fb51ecbdce9f66",
    "legal/license-policy-amendment/round3/vectors.json": "b4eaaed5852665fd6f2f69808ec4e89bc784b076ccdfac3486f7de5fc38fda99",
    "legal/license-policy-amendment/status.json": "38706b716665b9073ee07e7c77fcdce08f7d39fb2fb03c97a530e40011cad2fc",
    "legal/license-policy-amendment/vectors.json": "fd2af21605c04420f76d148b71cf39e026251931df215e77eafce8c925549b24",
    "legal/third-party-license-policy.yaml": "fa3a4398acafc3960eaaae9f5396d4e96d91e6ff252b83f6c53e1f5f0d8a40d0",
    "scripts/broker_handoff_transcript_v2.py": "6344e54d229ef46efa3698e2068b05ff247257750307ad749ddc2bbad06e94f9",
    "scripts/decision_record.py": "af6bb14bb7b779f9764b5a8c7a116012837bbeacae9e7aee25ea54f1e6d39b6f",
    "scripts/license_amendment.py": "58758a4a7bb6bbcf49daf1880cc423566da306cfd90dceadfa1b4b7c53ec28cd",
    "scripts/license_amendment_v2.py": "0f87f029d3227960a103174d86d3c37c6c8b83e0d0ae766a089288bf85294e14",
    "scripts/replay_fixtures.py": "4e3f0157c43d14e46c53cd0617cc935d8b61df3f782fb00cd5b9d8b9c74c9e3e",
    "scripts/validate_decision_record.py": "49a9f0cac29ea11e68085c73e3eeddecdcba0cbe8b69905fec92572bb4cd5a84",
    "scripts/validate_edge_record_v13.py": "f3d3eb218e709d81b6ca110e1d3e1df268097c48888acbbf9e7b8f799690d2e4",
    "scripts/validate_regulatory_alignment.py": "4814b82e3ffafe976f80e3adb755dca531a4fc76b5df43fc15f8627936ad926b",
    "scripts/validate_replay_fixtures.py": "fa02798902d24cbe22e95ae6e4c9773c89b2d7da33ac00ec94ba92e92da18bc5",
    "task-packets/EXEC-TEMPORAL-PINS-001.yaml": "3015206b52c26128331794bf96796ec7fcbfc283455c58b1510f6ce0232fcba7",
    "tests/test_decision_record.py": "1b3f7163ec1022927e6b71aa8db1f40205410b8bb2edc21196404ca1d4a5b452",
    "tests/test_edge_record_v13.py": "e5593e6fc2ce2127e937ec40b5956b60843cdb22d1a82ee32b60572ac8bb1eb9",
    "tests/test_regulatory_alignment.py": "fd54dc2ef2a28881717f605af9da58a26b0087cdc1658e2ad10f249868323913",
})
ERA_SHA256 = MappingProxyType({
    "architecture/artifact-edges/README-v13.md": "4c15590d34eabee19fd8396888be4d0b0ffdfd1496955d98dcda255ffa5af7b3",
    "architecture/artifact-edges/operator-harness-engineering-v13.json": "4f1b77aa3c0ae93307d2b793d92de2416af8630c27688f925745350c7cbd1226",
    "architecture/broker-handoff-inputs-v2/channel.schema.json": "b050af6bec767beef0796ee4a25edb76b6e761a9b793a4ffd16b4907e910f34e",
    "architecture/broker-handoff-inputs-v2/vectors.json": "b6154ebc18fe2fcb552971f88af5065441f757eba1b70cddef0090fda260a43d",
    "architecture/decision-record/README.md": "0ff769568fe284f437d781aec649cf3ba1bdbd8efa4b7511481b56607e5d4233",
    "architecture/decision-record/decision-record.schema.json": "56e9694bfb93c04c66e058eeda412b6e8ca187c9d66285baec717112f659bad6",
    "architecture/decision-record/reason-codes.json": "86b72e8a3737004914a1a0a4c92927a107ad406ed0c09a37a09ba00083e2fa53",
    "architecture/decision-record/status.json": "fe54c9b78f133c63e339316730090263469def180d298180aeb9dffea63474d2",
    "architecture/decision-record/vectors.json": "a2183e019321f6a7b1f721d56ce76953670a584af99013c1828f1016f102cb62",
    "architecture/model-weights/record.json": "0e2f083f97089a0099064ccafd1778c4af22773d206494eed716b811f1266ce3",
    "architecture/model-weights/schema.json": "de04c8d21c105a7f953ae07d703b9568dad4f21115b08a49c4ed0de5b14e3295",
    "architecture/model-weights/vectors.json": "86ccfff1d25b5f6326b1b568334bb0b983e3733386ac833e0d8a30ea2bedcdd6",
    "architecture/redteam-fixtures/record.json": "22cba7f750a9859757dcf98ca4c8f34c0292397a2b2869406e3148f41371d508",
    "architecture/redteam-fixtures/schema.json": "c8efa99c951236f10840776c87a1947ecb966996fa37fc6a84f4efdb695e330d",
    "architecture/redteam-fixtures/vectors.json": "3927dbf02217cb2be6661218213ba79ed41311683e19aae4eb404129a0c9ba51",
    "architecture/regulatory-alignment-README.md": "5fce1c75110b0222f603ea0fed3a2af705ec4e0dc06f3c68b9ec8c24f69de733",
    "architecture/regulatory-alignment.json": "98532820261fa1a51a67998fff1126586329a5b5ef7fe09e0e026501b24e95e1",
    "architecture/replay-fixtures/blobs/1bc09642184d86e64d54ef2a4953b1f7c31e9895c9b61f1eb5388a89709d1005": "1bc09642184d86e64d54ef2a4953b1f7c31e9895c9b61f1eb5388a89709d1005",
    "architecture/replay-fixtures/blobs/579a20ff1a7d66537d3dcfebb9bb4737af33b958fb035d3e4f1bf4c8b06577d3": "579a20ff1a7d66537d3dcfebb9bb4737af33b958fb035d3e4f1bf4c8b06577d3",
    "architecture/replay-fixtures/blobs/5a199d83be3aa60ee4d49a525404f9645731bc2d8a3aeb509b0ec6f7d6e2e19a": "5a199d83be3aa60ee4d49a525404f9645731bc2d8a3aeb509b0ec6f7d6e2e19a",
    "architecture/replay-fixtures/blobs/747cdabd6bf031f659e13d3e82220675c2d4efefa870565345c1aedb32e24655": "747cdabd6bf031f659e13d3e82220675c2d4efefa870565345c1aedb32e24655",
    "architecture/replay-fixtures/blobs/acc5ae84d03f6482f941175e523f5ea0be8ad8b9fd9c90e78264ec051af6c591": "acc5ae84d03f6482f941175e523f5ea0be8ad8b9fd9c90e78264ec051af6c591",
    "architecture/replay-fixtures/blobs/af07c72fda48892f71f1742b49448e25711e971752223620d32a74631f48aaaa": "af07c72fda48892f71f1742b49448e25711e971752223620d32a74631f48aaaa",
    "architecture/replay-fixtures/blobs/e5f1eb4d806641698a35efe20e098efd20d7d57a9b90ee69079d5bb650920726": "e5f1eb4d806641698a35efe20e098efd20d7d57a9b90ee69079d5bb650920726",
    "architecture/replay-fixtures/fixtures/fx-dev-0001.t1.json": "7270f3af455f87e6cb1160b8f15bfe6e00c7602178c52bef6ec7ba1d37a3cdca",
    "architecture/replay-fixtures/fixtures/fx-dev-0001.v1.json": "694eca20522587acee03495c0a026b74f529988f819c1836dc11a750793bb225",
    "architecture/replay-fixtures/fixtures/fx-dev-0002.t1.json": "081a2f36d05dc04aaa70921ac7a73beef6814937761b8601ed0b65ddee56ca10",
    "architecture/replay-fixtures/fixtures/fx-dev-0002.v1.json": "83e07494c62c0651ea6c7ca6e85fdb83cba18cddfa2d29a02a251f2c1fb59904",
    "architecture/replay-fixtures/fixtures/split-fx-dev.json": "4d41d4b3831364c1b11432f12652590ce3b20c4923f2eced5a67a4cc12821251",
    "architecture/replay-fixtures/record.json": "9d36696bb1e28507713e72357d49a404478fef65fc60862535db1bc322e93b9b",
    "architecture/replay-fixtures/schema.json": "dd8242f5965f3d89a801005b8de92d923fb7ba621532d637b4b50669113d1f19",
    "architecture/replay-fixtures/vectors.json": "da29179b1ef8d6b439659a696a077ba4d7be835cf9db764c04f746088ad59f1e",
    "architecture/research-adoption-v2/README.md": "8b73cd069511db4ea2246b7a022eb2d7c5905ca9b6374bdf9e48977b08d07a7c",
    "architecture/research-adoption-v2/crosswalk.json": "e1b57c70a63f9b71994b2c25b4c786c9721f34ef34f08729ae6e9fc209010a75",
    "architecture/research-adoption-v2/review-round1.json": "aa1ccb39c6192453f190b36e81b754cd4e0e7300ca9c340b054f2879f9c07eb8",
    "architecture/research-adoption-v2/review-round2.json": "32699fce4b20a8944661a3750eccdb928c5d27c5964b735a155aca67ecc50162",
    "architecture/research-adoption-v2/review-round3.json": "ba8a8468fe39d026cda1230e78047d0c7011f9897893299630660a3405d7cf5f",
    "architecture/research-adoption-v2/review-round4.json": "cb4e7e28cea677c4a2a1d0f90f4a4d8af71d85db351955bb161d3dd409782d2f",
    "architecture/research-adoption-v2/round2/README.md": "53c5499a68e4a53e86ed4273962585a32643929bbbda8c5b070e6d3d79678173",
    "architecture/research-adoption-v2/round2/crosswalk.json": "76d5a8fc1835504713c2c304f8ca6f4a6ebbdd66f45945aa0f47ed69195e02b7",
    "architecture/research-adoption-v2/round2/scripts/research_adoption_v2.py": "21ea93817dfe50567c9733e34af5e0d19a7f7df5e7b9cc0cdaa43abe1b1a7de1",
    "architecture/research-adoption-v2/round3/README.md": "8cf678ca238dd60811eed9baa637f2f36a91ca83bb8e172a9ee76e82180ddb56",
    "architecture/research-adoption-v2/round3/crosswalk.json": "393304168587335e8e773c2300053937ac9afd4af0a139cc0c384ce783d94a6b",
    "architecture/research-adoption-v2/round3/scripts/research_adoption_v2.py": "ca9dfda2e4fef6c625b9f6e5b35fd07de2279d20df7b6949c3f699de63f33f68",
    "architecture/research-adoption-v2/status.json": "90b7ecf0718a3b100ad1d3824e2f4d71c3e04a58f787f438abc51bcde1cc4d81",
    "architecture/review-briefs/REVIEW_BRIEF_PACKET.md": "6dcff68d7e6b01823f1740063e94910edcc159a71a6ee803f1b66c62fd06e274",
    "architecture/review-record/briefs.json": "bbc8a5cf8c567228639b22b82f7307d25a4e7e4612a7906d62e86da35a34cd35",
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
    "ci/chain_checkpoint.py": "8c8789073698f4e7441b6fda6e7fae8675ad9e8cdd3b30c1a4471809fdc874a0",
    "legal/license-policy-amendment-v2/README.md": "740ee084dcadaa9f3880f99b04dd6ad3f15c8cb55389864f4f226ee470c7f3ce",
    "legal/license-policy-amendment-v2/REVIEW_BRIEF.md": "b3e5ea8514301708e6438b27cb526bbf9a353fc4255e4b6108beda7f6d93fd83",
    "legal/license-policy-amendment-v2/amendment.json": "05984db7339c60cf0d4b9acc1179bd0b5fbb16c6f2f4dd554889388133e8f3a7",
    "legal/license-policy-amendment-v2/review-round1.json": "0fbbaa289ae5a0bc77aaeb0293910bacecfef9ddcf06ff1ddd90eba66f97689a",
    "legal/license-policy-amendment-v2/review-round2.json": "d75eecb7e012f5dcbcf4b61b747a2dfb5bbd9101806514cdec43ee7b4bc3931e",
    "legal/license-policy-amendment-v2/review-round3.json": "10831f2e1166c7e669f490069d77062a95ab6a76c4e72dfa3c7b44ee128adfb1",
    "legal/license-policy-amendment-v2/round1/legal/license-policy-amendment-v2/README.md": "d2c390a1367b9213ec19e2054c98de54291cc025fc8de24c685b47b9006bcc9a",
    "legal/license-policy-amendment-v2/round1/legal/license-policy-amendment-v2/REVIEW_BRIEF.md": "32cd0720aefaf1201f9a1d0c1f6d15c4ecc71a655050cf633c702e5d6c331324",
    "legal/license-policy-amendment-v2/round1/legal/license-policy-amendment-v2/amendment.json": "d58079a2d9565c7bf358fad0661985bc399ed0828a3de243fe91e7bd3ce12bbd",
    "legal/license-policy-amendment-v2/round1/legal/license-policy-amendment-v2/vectors.json": "fbc93a278671e77cf2ea9534acc37bff03d50de94dedb32db15621f26f820ec0",
    "legal/license-policy-amendment-v2/round1/scripts/license_amendment_v2.py": "45d344ca15a9862ea4ce293e62875592721559e6dc813af662f85e8e1983e149",
    "legal/license-policy-amendment-v2/round2/legal/license-policy-amendment-v2/README.md": "55e99f3035852e1a5ef60cd12cfeead6ac728ffdd20ef8dd9b3ea76511238dcb",
    "legal/license-policy-amendment-v2/round2/legal/license-policy-amendment-v2/REVIEW_BRIEF.md": "8caeef9c9983e5b6901dceeebd628b7c3c56b81176e62ff1dda0fd24d55528ea",
    "legal/license-policy-amendment-v2/round2/legal/license-policy-amendment-v2/amendment.json": "818aaedd4ab01295f57754035ea673baac7762fa4e48f255449e1a05241183e0",
    "legal/license-policy-amendment-v2/round2/scripts/license_amendment_v2.py": "d9a2ff19ce90f0994681f5098afe0b80195c3804196257b122e0289087a46574",
    "legal/license-policy-amendment-v2/status.json": "2b760f53dca5fcd627b7684549bb5402ab8f357a237881ba4cdba72c824821cf",
    "legal/license-policy-amendment-v2/vectors.json": "aaab430c9f011e164915e83677997cfbe6b62b29e3ca923a5c23b7a680ebd6b9",
    "legal/license-policy-amendment-v3/README.md": "ca6e12ff8fa36abf701a5452c77ce8e1524021d367d04e04ed435b9745043773",
    "legal/license-policy-amendment-v3/amendment.json": "bd945219dff8005353765c3d59992a853bd96cc9b1a4a3e059d64359707bc1fc",
    "legal/license-policy-amendment/README.md": "ba204cc0bd86444028355725546d2b0971dfe5d6bef8b06f9f7156dd93380646",
    "legal/license-policy-amendment/REVIEW_BRIEF.md": "6c70d5672446ae5a0739fff0be8cfcd9fe1683f1dc37194653b295ad39fe4251",
    "legal/license-policy-amendment/amendment.json": "f6a8c0796857cf40906df3e6bc483122988b91271cc77b3aaed4d4e213d864c2",
    "legal/license-policy-amendment/review-round1.json": "01c48cf4d3fe5ed2fc4f3695dab9ebe5a98222c8e1973177893cb4c3773a4a2d",
    "legal/license-policy-amendment/review-round2.json": "10133203680941956eaee43dde7628c417834c2148c344ffb4d1bff30558f93c",
    "legal/license-policy-amendment/review-round3.json": "e073b9d6385fa571ff80a4bae7ba9980855c890375a53220469a72241b17fd8c",
    "legal/license-policy-amendment/review-round4.json": "46189374349481dadceed5c631be43ee6ead055dccb23bb17f357be4b48df6a9",
    "legal/license-policy-amendment/round1/README.md": "057078e15b0f694efbe008f69b4a206e717481332129846c1d14e1c9020ea573",
    "legal/license-policy-amendment/round1/REVIEW_BRIEF.md": "12da796fb7c6ff152e0f56be45c43a4c5bfeea8527d342e811899a092749130b",
    "legal/license-policy-amendment/round1/amendment.json": "b99a38851035f6944f1bee6548f5a59625c683594ce1739b9b5d7a77b1bc244e",
    "legal/license-policy-amendment/round1/scripts/license_amendment.py": "34f51249de4270caa64cfbfb84136aa315f28a6a91ae063158151644e64f9cbd",
    "legal/license-policy-amendment/round1/vectors.json": "d53e4bfec04df55014ef6171f5d140eb3b3cee5eac252c4bb8d209365bb58a46",
    "legal/license-policy-amendment/round2/README.md": "ceb46141a8677255067557e1e55d0a3b5b803a422b3ab914585f167a8d6020c0",
    "legal/license-policy-amendment/round2/REVIEW_BRIEF.md": "7bfe81322949c5319fdc3063b88d2fac52c8a5e9e49572312a4dd07b471f011b",
    "legal/license-policy-amendment/round2/amendment.json": "b95016325e35470bd654d6353697ae7aa5625458d3ce2110dee85e921f15f95f",
    "legal/license-policy-amendment/round2/scripts/license_amendment.py": "b944b02edc9bcacc226d16d32850b0f258938ad4549129ba207f4c9fc845e99c",
    "legal/license-policy-amendment/round2/vectors.json": "bf4aa6d0200f5ed443666348f851fa9b74b462e2fdb4247a5dbcd10651190f69",
    "legal/license-policy-amendment/round3/README.md": "86bc4c7bb6eba3dbfac186df7ed0cdd8538ecaae9e966d3edad9943eb024ce54",
    "legal/license-policy-amendment/round3/REVIEW_BRIEF.md": "d4475c1b2f74df031cd444edd771cf4f7f80fc37202e6da748aa4f38ef0b8cd2",
    "legal/license-policy-amendment/round3/amendment.json": "7c956dabbf0c24a00080dfd80483b917ba3d0c588f355a96580867c589a10827",
    "legal/license-policy-amendment/round3/scripts/license_amendment.py": "9f4a1c3766488010964d9f622c2580fb636ade015fe7695964fb51ecbdce9f66",
    "legal/license-policy-amendment/round3/vectors.json": "b4eaaed5852665fd6f2f69808ec4e89bc784b076ccdfac3486f7de5fc38fda99",
    "legal/license-policy-amendment/status.json": "38706b716665b9073ee07e7c77fcdce08f7d39fb2fb03c97a530e40011cad2fc",
    "legal/license-policy-amendment/vectors.json": "fd2af21605c04420f76d148b71cf39e026251931df215e77eafce8c925549b24",
    "legal/third-party-license-policy.yaml": "fa3a4398acafc3960eaaae9f5396d4e96d91e6ff252b83f6c53e1f5f0d8a40d0",
    "scripts/broker_handoff_transcript_v2.py": "6344e54d229ef46efa3698e2068b05ff247257750307ad749ddc2bbad06e94f9",
    "scripts/decision_record.py": "af6bb14bb7b779f9764b5a8c7a116012837bbeacae9e7aee25ea54f1e6d39b6f",
    "scripts/license_amendment.py": "58758a4a7bb6bbcf49daf1880cc423566da306cfd90dceadfa1b4b7c53ec28cd",
    "scripts/license_amendment_v2.py": "0f87f029d3227960a103174d86d3c37c6c8b83e0d0ae766a089288bf85294e14",
    "scripts/redteam_fixtures.py": "6a8d2e368d5895125d618e6a2d257c03a38b84c09f89b36b25d444d8ebd42773",
    "scripts/replay_fixtures.py": "4e3f0157c43d14e46c53cd0617cc935d8b61df3f782fb00cd5b9d8b9c74c9e3e",
    "scripts/validate_decision_record.py": "49a9f0cac29ea11e68085c73e3eeddecdcba0cbe8b69905fec92572bb4cd5a84",
    "scripts/validate_edge_record_v13.py": "f3d3eb218e709d81b6ca110e1d3e1df268097c48888acbbf9e7b8f799690d2e4",
    "scripts/validate_license_amendment.py": "ff7b81ba0ed906f7c4dc69397d20f5adc4926cd43ea466f73b53808a74b52164",
    "scripts/validate_license_amendment_v2.py": "526e252cb82feb457a2ccdff7b4821ad91d67f90931f94e0615b169a70cf5656",
    "scripts/validate_model_weights.py": "27fd70749930d104e74c3a173be79bc25945a44352d7e609937089e09716f969",
    "scripts/validate_redteam_fixtures.py": "fdeda77d86774c2fd1dc89343e215c099b38bca25c3f203a42c5f380f139d7ee",
    "scripts/validate_regulatory_alignment.py": "4814b82e3ffafe976f80e3adb755dca531a4fc76b5df43fc15f8627936ad926b",
    "scripts/validate_replay_fixtures.py": "fa02798902d24cbe22e95ae6e4c9773c89b2d7da33ac00ec94ba92e92da18bc5",
    "task-packets/EXEC-ML-ADOPT-PINS-001.yaml": "05b84bf42325995eb928c310623fa109aba2e99fc0765701e23569565d89734f",
    "task-packets/EXEC-TEMPORAL-PINS-001.yaml": "3015206b52c26128331794bf96796ec7fcbfc283455c58b1510f6ce0232fcba7",
    "tests/test_decision_record.py": "1b3f7163ec1022927e6b71aa8db1f40205410b8bb2edc21196404ca1d4a5b452",
    "tests/test_edge_record_v13.py": "e5593e6fc2ce2127e937ec40b5956b60843cdb22d1a82ee32b60572ac8bb1eb9",
    "tests/test_model_weights.py": "529af8b0516aaeef7a01d060edfefb6531fcc883236f653bb3500ea9262ebaaf",
    "tests/test_redteam_fixtures.py": "fd53c6a5175ec3c4225b19e894b82b85c9d414a8b9d853167e2f8ca750e5a093",
    "tests/test_regulatory_alignment.py": "fd54dc2ef2a28881717f605af9da58a26b0087cdc1658e2ad10f249868323913",
})
ERRATA_LINES = MappingProxyType({
    "architecture/oracle-identity-met-014.json": ((5, 5), (28, 29), (55, 55)),
    "docs/repositories/08-mas-harness-execution-plane.md": ((174, 174),),
    "task-packets/README.md": ((1871, 1871),),
    "tests/test_ci_performance.py": ((169, 169),),
    "tests/test_credential_lifecycle.py": ((362, 362),),
    "tests/test_met_014_oracle.py": (
        (1764, 1765), (1767, 1767), (1769, 1769), (1771, 1771), (1773, 1776), (1778, 1781),
    ),
})
REGISTRY_PATH = "architecture/review-record/briefs.json"
PACKET_BRIEF = "architecture/review-briefs/REVIEW_BRIEF_PACKET.md"
READER_PATH = "ci/chain_checkpoint.py"
RIDERS = (("PACKET", NEW_PACKET + "/packet", PACKET_BRIEF, 1),)
HUNK_RECORD_MEMBERS = frozenset({"authorityPath", "hunkClassVocabulary", "hunkClassRuleSha256", "hunkClassContext",
                                 "classes", "outcomeStatements"})
HUNK_VOCABULARY = ("bridge", "cascade", "other", "record", "register")     # chainmech v2.5 keeps v2.3's vocabulary
NORMALISED = ("bridge", "cascade", "record", "register")                   # the mechanics forms v2.5 normalises
HUNK_RULE_SHA256 = "106e577175d692a5d627b2b21a0adfab8c4cb9cc4e06d7d45d97be5ef663c778"


def reviewed_bytes(path: str) -> bytes:
    """This packet's reviewed bytes of path; a bridged successor projects newer bytes back first."""
    return regular_bytes(path)


def _era_bytes(path: Any, raw: Any) -> bytes:
    """An era file's bytes, checked against its era digest; a path outside the era is refused."""
    expected = ERA_SHA256.get(path) if type(path) is str else None
    require(expected is not None, "MET-015 reviewed bytes are bound: " + str(path))
    require(type(raw) is bytes and digest(raw) == expected, "unreviewed MET-015 source: " + path)
    return raw


def _verified(path: str) -> bytes:
    """reviewed_bytes, checked against its era digest on every read; a path outside the era is refused before it is
    read."""
    require(type(path) is str and path in ERA_SHA256, "MET-015 reviewed bytes are bound: " + str(path))
    return _era_bytes(path, reviewed_bytes(path))


def _bound_read(path: str, expected: Any) -> bytes:
    """reviewed_bytes of a file named by an era-verified record, checked against the digest that record gives it."""
    require(type(path) is str and _sha(expected), "MET-015 bound read: " + str(path))
    _path(path)
    raw = reviewed_bytes(path)
    require(type(raw) is bytes and digest(raw) == expected, "MET-015 bound file drift: " + path)
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
           "the registry differs from the base by exactly the MET-015 packet rider, pinning the generic packet "
           "brief")


def validate_registry() -> None:
    """V4 over briefs.json and the generic packet brief."""
    check_registry(_verified(REGISTRY_PATH), {PACKET_BRIEF: _verified(PACKET_BRIEF)})


def check_packet_files(files: Any) -> None:
    """V1: the packet's files are exactly these, and each one's bytes equal the sha256 pinned for it."""
    _bound(lambda: type(files) is dict and sorted(files) == sorted(PACKET_FILES) and len(files) == len(PACKET_FILES),
           "MET-015 V1 the packet files are exactly the fourteen")
    for path in PACKET_FILES:
        _bound(lambda: type(files[path]) is bytes and digest(files[path]) == ERA_SHA256[path],
               "MET-015 V1 a packet file's bytes equal its pinned digest: " + path)


def validate_packet_files() -> None:
    check_packet_files({path: _verified(path) for path in PACKET_FILES})


def _v25_source(path: str) -> bytes:
    """The reader's era-verified bytes with one alias line: its v2.5 copy answers as `classify` (the identity rule's
    attribute names hold `classify`, not `classify_v25`)."""
    return _verified(path) + b"\nclassify = classify_v25\n"


def _era_rule(path: str, name: str) -> types.ModuleType:
    """The reader's v2.5 rule as an era model, executed from its verified bytes plus the alias line (no import, no
    bytecode); it imports only the standard library."""
    module = types.ModuleType(name)
    module.__file__ = str(ROOT / path)
    exec(compile(_v25_source(path), path, "exec", dont_inherit=True), module.__dict__)
    return module


def _v24_context(record: Any, context: Any) -> dict:
    """v2.5's inputs from this step's authority and the record's context (the reader's context_v24 form): the catalog
    pair from the authority's baselinePackets size, then countPairs; the products from the authority's productPackets (K = 1); the new tests from newFiles."""
    n = len(record["baselinePackets"])
    return {"prevValidator": context["prevValidator"], "prevTest": context["prevTest"], "newPacket": context["newPacket"],
            "products": list(record["productPackets"]), "steps": context["steps"],
            "pairs": [[n, n + context["steps"][1]]] + [list(pair) for pair in context["countPairs"]],
            "newTests": [p for p in record["newFiles"] if p.startswith("tests/") and p.endswith(".py")]}


def check_hunk_record(raw: Any, changed: Any, afters: Any, classify: Any, context: Any, rule_sha: Any) -> None:
    """V6 under v2.5: the record's six closed members; it names this layer's authority; the closed vocabulary and v2.5's
    digest, which the reader's copy carries; the context is this step's names with countPairs; no outcome statement; one
    class per reverse hunk for exactly the changed files; and
    every class equals v2.5's class at its position."""
    record = _parsed(raw)
    _bound(lambda: type(record) is dict and set(record) == HUNK_RECORD_MEMBERS and record["authorityPath"] == AUTHORITY_PATH
           and record["outcomeStatements"] == [],
           "MET-015 V6 the hunk-class record is closed and names this layer's authority")
    _bound(lambda: record["hunkClassVocabulary"] == list(HUNK_VOCABULARY)
           and record["hunkClassRuleSha256"] == HUNK_RULE_SHA256 == rule_sha,
           "MET-015 V6 the hunk-class record's vocabulary and rule digest are v2.5's")
    _bound(lambda: type(record["hunkClassContext"]) is dict and set(record["hunkClassContext"]) == set(HUNK_CONTEXT)
           and record["hunkClassContext"] == {"newPacket": NEW_PACKET, "prevValidator": HUNK_CONTEXT["prevValidator"],
                                              "prevTest": HUNK_CONTEXT["prevTest"], "steps": [1, 2], "countPairs": []},
           "MET-015 V6 the hunk-class record's context is this step's names")
    classes = record.get("classes") if type(record) is dict else None
    _bound(lambda: type(changed) is dict and type(classes) is dict and set(classes) == set(changed)
           and all(type(classes[p]) is list and all(type(c) is str for c in classes[p])
                   and len(classes[p]) == len(changed[p].get("reverseHunks", [])) for p in changed),
           "MET-015 V6 the hunk-class record lists one class per hunk for exactly the changed files")
    for path, entry in changed.items():
        seen = set()
        for position, (cls, hunk) in enumerate(zip(classes[path], entry.get("reverseHunks", []))):
            _bound(lambda: cls in HUNK_VOCABULARY and cls == classify(
                path, afters[path], hunk["at"], _base64(hunk["removeBase64"]), _base64(hunk["insertBase64"]), context,
                seen=seen),
                   "MET-015 V6 a recorded class re-checks by position: %s hunk %d" % (path, position))


def validate_hunk_record() -> None:
    """V6 over the hunk-class record (bound by its newFiles digest), the changed files (bound by their afterSha256) and
    the reader's copy of v2.5, executed from its era-verified bytes."""
    record = authority()
    raw = _bound_read(HUNK_RECORD_PATH, record["newFiles"].get(HUNK_RECORD_PATH))
    afters = {path: _bound_read(path, entry["afterSha256"]) for path, entry in record["changedFiles"].items()
              if "reverseHunks" in entry}
    rule = _era_rule(READER_PATH, READER_NAME)
    side = _parsed(raw)
    rule_sha = HUNK_RULE_SHA256 if _verified(READER_PATH).count(
        b'RULE_V25_SHA256 = "' + HUNK_RULE_SHA256.encode("ascii") + b'"') == 1 else None
    context = _v24_context(record, side["hunkClassContext"]) if _holds(
        lambda: _v24_context(record, side["hunkClassContext"]) is not None) else None
    check_hunk_record(raw, record["changedFiles"], afters, rule.classify, context, rule_sha)


def _era_import(era: dict) -> Any:
    """An import function that resolves the named modules to this era's executed copies and everything else normally."""
    def era_import(name, globals=None, locals=None, fromlist=(), level=0):
        if level == 0 and name in era:
            return era[name]
        return builtins.__import__(name, globals, locals, fromlist, level)
    return era_import


def _era_model(path: str, name: str, imports: dict | None = None) -> types.ModuleType:
    """A reference module of this era, executed from its reviewed bytes; named imports resolve to this era's copies."""
    module = types.ModuleType(name)
    module.__file__ = str(ROOT / path)
    if imports:
        namespace = dict(vars(builtins))
        namespace["__import__"] = _era_import(imports)
        module.__dict__["__builtins__"] = namespace
    exec(compile(_verified(path), path, "exec", dont_inherit=True), module.__dict__)
    return module


def check_errata(classes: Any, changed: Any, befores: Any) -> None:
    """E3: class-other (authored) hunks fall only on the named files; each carries one, and each such hunk lies inside one
    of its file's named base-line spans: placed in the before bytes by its offset plus the earlier hunks' shift, its
    before-text is there, and the base lines it spans are within the span; every other hunk is a mechanics form v2.5
    normalises."""
    _bound(lambda: type(classes) is dict and type(changed) is dict
           and all(cls in NORMALISED or (cls == "other" and path in ERRATA_LINES) for path in classes for cls in classes[path]),
           "MET-015 E3 class-other hunks fall only on the named files")
    for path, spans in ERRATA_LINES.items():
        _bound(lambda: "other" in classes[path] and type(befores[path]) is bytes,
               "MET-015 E3 the named file carries its authored hunk: " + path)
        before, shift = befores[path], 0
        for position, (cls, hunk) in enumerate(zip(classes[path], changed[path]["reverseHunks"])):
            removed, inserted = _base64(hunk["removeBase64"]), _base64(hunk["insertBase64"])
            at = hunk["at"] + shift
            shift += len(inserted) - len(removed)
            if cls == "other":
                start = before[:at].count(b"\n") + 1
                end = start + inserted[:-1].count(b"\n")
                _bound(lambda: before[at:at + len(inserted)] == inserted
                       and any(first <= start and end <= last for first, last in spans),
                       "MET-015 E3 an authored hunk lies at its named lines: %s hunk %d" % (path, position))


def validate_errata() -> None:
    """E3 over the hunk-class record (bound by its newFiles digest) and each named file's before bytes, projected back
    through this layer's own hunks from its afterSha256-bound bytes."""
    record = authority()
    side = _parsed(_bound_read(HUNK_RECORD_PATH, record["newFiles"].get(HUNK_RECORD_PATH)))
    befores = {path: _undo_this_layer(path, _bound_read(path, record["changedFiles"][path]["afterSha256"]))
               for path in ERRATA_LINES if path in record["changedFiles"]}
    check_errata(side.get("classes") if type(side) is dict else None, record["changedFiles"], befores)


MEMBERS = (                                     # CONTRACT_297 section 1's order
    MappingProxyType({"item": "GR-REDTEAM-FIXTURES-001", "module": "redteam_fixtures",
                      "model": "scripts/redteam_fixtures.py", "modelName": "_met_015_redteam_fixtures",
                      "checker": "scripts/validate_redteam_fixtures.py", "checkerName": "_met_015_validate_redteam_fixtures",
                      "record": "architecture/redteam-fixtures/record.json", "vectors": "architecture/redteam-fixtures/vectors.json",
                      "schema": "architecture/redteam-fixtures/schema.json",
                      "bases": ()}),
    MappingProxyType({"item": "MODEL-WEIGHTS-POLICY-001", "module": "model_weights",
                      "model": None, "modelName": None,
                      "checker": "scripts/validate_model_weights.py", "checkerName": "_met_015_validate_model_weights",
                      "record": "architecture/model-weights/record.json", "vectors": "architecture/model-weights/vectors.json",
                      "schema": "architecture/model-weights/schema.json",
                      "bases": ()}),
)
REDTEAM, WEIGHTS = MEMBERS
SLOT = 297
HUNK_RECORD_PATH = "architecture/chain-checkpoint/hunk-classes/297.json"
READER_NAME = "_met_015_chain_checkpoint"
HUNK_CONTEXT = MappingProxyType({"newPacket": NEW_PACKET, "prevValidator": "scripts/validate_met_014.py",
                                 "prevTest": "tests/test_met_014.py", "steps": (1, 2), "countPairs": ()})


def _era_checker(member: Any) -> tuple:
    """A member's model and checker, each executed from its era-verified bytes (no import from this layer); the
    checker's imports of the model, and of a base model the member names, resolve to the era copies: under `scripts`
    (CONTRACT_295 4a N2) and under their bare names (ORC-295-C2-Q1 (a)), the same objects. Each base runs with the
    bases listed before it injected, the model with all of them (CONTRACT_296 4a difference 1 (ii); BUILD_PLAN_296
    ERR-4), and a member with no model gets its checker alone with its bases (difference 1 (i))."""
    era = {}

    def injected() -> dict | None:
        return dict(era, scripts=types.SimpleNamespace(**era)) if era else None
    for name, path in member["bases"]:
        era[name] = _era_model(path, "_met_015_" + name, injected())
    model = None
    if member["model"] is not None:
        model = _era_model(member["model"], member["modelName"], injected())
        era[member["module"]] = model
    checker = _era_model(member["checker"], member["checkerName"], injected())
    return model, checker


def check_redteam_fixtures(vectors: Any, refusals: Any, replayed: Any) -> None:
    """E1 (GR-REDTEAM-FIXTURES-001): the record passes the era checker (GRRT_SHAPE to GRRT_VECTOR) over this era's bytes;
    and the head itself replays every vector, by the vectors file's own list and independently of the checker's,
    through the era model to its expectation (the count is the parsed list's length)."""
    _bound(lambda: type(refusals) is list and refusals == [],
           "MET-015 E1 the red-team fixture record passes its checker (GRRT_SHAPE to GRRT_VECTOR)")
    _bound(lambda: type(vectors) is dict and type(vectors["cases"]) is list and len(vectors["cases"]) > 0
           and type(replayed) is list and len(replayed) == len(vectors["cases"]) and all(ok is True for ok in replayed),
           "MET-015 E1 every red-team fixture vector replays through its era model to its expectation")


def validate_redteam_fixtures(packets: Any) -> None:
    """E1 over era bytes only: the era checker's refusals through the era reader, and each vector's replay."""
    model, checker = _era_checker(REDTEAM)
    vectors = json.loads(_verified(REDTEAM["vectors"]))
    check_redteam_fixtures(vectors, checker.check(_era_read), [model.replay(case)[0] for case in vectors["cases"]])


def check_model_weights(refusals: Any) -> None:
    """E1 (MODEL-WEIGHTS-POLICY-001): the record passes the era checker (MW_POLICY to MW_VECTORS) over this era's bytes; the
    member has no model: its checker's own MW_VECTORS row checks every vector and the fail-closed probe, so
    there is no replay half (CONTRACT_297 section 3's E1 form for this member)."""
    _bound(lambda: type(refusals) is list and refusals == [],
           "MET-015 E1 the model weights record passes its checker (MW_POLICY to MW_VECTORS)")


def validate_model_weights(packets: Any) -> None:
    """E1 over era bytes only: the era checker's refusals through the era reader; the head reads no vectors."""
    model, checker = _era_checker(WEIGHTS)
    check_model_weights(checker.check(_era_read))


def _era_read(path: Any) -> bytes:
    """The checker's injected reader: an era file's verified bytes; any other path is refused (a ValueError), so a
    packet reference outside the era does not resolve."""
    return _verified(path)


def check_base_files(files: Any, changed: Any, new: Any) -> None:
    """E2: EXEC-TEMPORAL-PINS-001's YAML (the comparator), MAS-RA-002's run-manifest files, HR-REPLAY-FIXTURES-001's
    files, research-adoption-v2, the base licence policy, A1 and A2 with their two amendment scripts, and 296's
    members' files (CONTRACT_297 section 1 less the two licence validators the cascade rewrites, ERR-5) equal their
    base bytes, and this step's authority names none of them."""
    _bound(lambda: type(files) is dict and sorted(files) == sorted(BASE_SHA256)
           and all(type(files[path]) is bytes and digest(files[path]) == BASE_SHA256[path] for path in BASE_SHA256),
           "MET-015 E2 the base files equal their base bytes")
    _bound(lambda: type(changed) is dict and type(new) is dict and not set(BASE_SHA256) & (set(changed) | set(new)),
           "MET-015 E2 this step changes no base file")


def validate_base_files() -> None:
    record = authority()
    check_base_files({path: _verified(path) for path in BASE_FILES}, record["changedFiles"], record["newFiles"])


def validate_met_015(packets: dict[str, Any]) -> None:
    """Every era file first; then V1 (the packet's files), E1 per member in section 1's order (the checker and the
    model), E2 (the base files), E3 (the authored edits), V4 (the registry) and V6 (the hunk-class record); last,
    this layer's canonical hunks."""
    for path in ERA_SHA256:
        _verified(path)
    validate_packet_files()
    validate_redteam_fixtures(packets)
    validate_model_weights(packets)
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
            == record["validatorNormalizedSha256"], "execml grrt weights validator drift")
    paths = sorted((ROOT / "task-packets").glob("*.yaml"))
    old = set(record["baselinePackets"])
    require(len(paths) == 322 and {path.stem for path in paths} == old | {NEW_PACKET} | set(PRODUCT_PACKETS),
            "closed 322-packet catalog")
    packets = {}
    for path in paths:
        raw = regular_bytes("task-packets/" + path.name)
        expected = (record["packetSha256"] if path.stem == NEW_PACKET
                    else record["productPackets"][path.stem] if path.stem in PRODUCT_PACKETS
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
            "closed source-only execml-grrt-weights packet and inherited commands")
    require(len(packet["allowedPaths"]) == len(set(packet["allowedPaths"]))
            and set(packet["allowedPaths"]) == set(record["changedFiles"])
            | set(record["newFiles"]) | {AUTHORITY_PATH, VALIDATOR_PATH,
                                         "task-packets/" + NEW_PACKET + ".yaml"}
            | {"task-packets/" + name + ".yaml" for name in PRODUCT_PACKETS},
            "unreviewed or omitted execml-grrt-weights packet path")
    for path, rule in record["changedFiles"].items():
        current = regular_bytes(path)
        require(digest(current) == rule["afterSha256"]
                and digest(historical_bytes(path, current)) == rule["beforeSha256"],
                "unreviewed current source: " + path)
    for path, expected in record["newFiles"].items():
        require(digest(regular_bytes(path)) == expected, "new source drift: " + path)
    validate_met_015(packets)


if __name__ == "__main__":
    validate()
    print("Execml grrt weights valid: 322 current specifications at slot 297; exact 320-packet predecessor; contract reviewed.")
