#!/usr/bin/env python3
"""Validate MET-014 (the grdec regalign edgev13 GR-DECISION-RECORD-001, REG-ALIGN-001 and EDGE-V13, K = 0): V1 this packet's files by digest; E1 each member's checker and, where it has one, its model from their era bytes; E2 the base files unchanged; E3 the authored edits at their named lines; V4 the registry rider; V6 the hunk-class record under v2.5."""
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
    import validate_met_015 as successor
except ImportError:
    from scripts.safe_yaml import safe_load
    from scripts import validate_met_015 as successor


ROOT = Path(__file__).resolve().parents[1]
AUTHORITY_PATH = "architecture/grdec-regalign-edgev13-authority.json"
AUTHORITY_SHA256 = "bb59ffa714cb708283cd8b26302e4d30af925a86b7029a1e891fcd66fc5f9ff2"
VALIDATOR_PATH = "scripts/validate_met_014.py"
BASE_COMMIT = "4b1386e0bf22e5d33c052ed27befc014614ac820"
NEW_PACKET = "MET-014"
PREVIOUS_PACKET = "MET-013"
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
            require(key not in result, "duplicate grdec-regalign-edgev13 authority member")
            result[key] = value
        return result

    def no_constant(_value: str) -> Any:
        raise ValueError("nonfinite grdec-regalign-edgev13 authority number")

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
        require(digest(raw) == AUTHORITY_SHA256, "grdec regalign edgev13 history authority digest")
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
    }, "closed grdec regalign edgev13 history authority")
    require(value["schemaVersion"] == "harness.planeon.ai/grdec-regalign-edgev13-authority/v1"
            and value["authorityPacket"] == NEW_PACKET
            and value["acceptedBase"] == BASE_COMMIT
            and type(value["baselinePackets"]) is dict
            and len(value["baselinePackets"]) == 319
            and NEW_PACKET not in value["baselinePackets"]
            and type(value["changedFiles"]) is dict
            and type(value["newFiles"]) is dict
            and _sha(value["packetSha256"])
            and _sha(value["validatorNormalizedSha256"]),
            "accepted 319-packet base")
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
    # An exact 319-era byte string is already older than the successor layer.
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


# MET-014 (rulings: CONTRACT_296 section 2) publishes, in a K = 0 step, three in-repo contracts, each a record
# with its checker and test: GR-DECISION-RECORD-001 (R12, the decision record and its fail-closed envelope, with
# vectors and a reference model), REG-ALIGN-001 (R03, the regulatory alignment record: no vectors, no model) and
# EDGE-V13 (R10, the operator edge record v13, the no-receipt TERMINAL amendment, with the v2 transcript model
# over the v13 vectors). Repository bytes are read only through reviewed_bytes; an era file is refused unless
# bound by digest on every read, a changed file by the authority's afterSha256. Each refusal is a pure check over
# the values read. Checked here: V1 the packet's nineteen files by digest; E1 per member, its checker and its
# model from their era bytes (the record passes its checker; GR-DECISION-RECORD-001's vectors also replay here
# through its model to their expectation; REG-ALIGN-001 has no replay half, and EDGE-V13's positives replay in
# its checker's EV_V2 row); E2 the base files unchanged; E3 class-other hunks only at the
# named spans, read under v2.5; V4 the registry rider; V6 the hunk-class record under v2.5. Last, this layer's
# own inverse hunks are the canonical ones.
PACKET_FILES = (
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
    'scripts/broker_handoff_transcript_v2.py',
    'scripts/decision_record.py',
    'scripts/validate_decision_record.py',
    'scripts/validate_edge_record_v13.py',
    'scripts/validate_regulatory_alignment.py',
    'tests/test_decision_record.py',
    'tests/test_edge_record_v13.py',
    'tests/test_regulatory_alignment.py',
)
BASE_FILES = (
    'architecture/approval-outcome/record.json',
    'architecture/approval-outcome/schema.json',
    'architecture/approval-outcome/vectors.json',
    'architecture/artifact-edges/operator-harness-engineering-v10.json',
    'architecture/artifact-edges/operator-harness-engineering-v11.json',
    'architecture/artifact-edges/operator-harness-engineering-v12.json',
    'architecture/artifact-edges/operator-harness-engineering-v2.json',
    'architecture/artifact-edges/operator-harness-engineering-v3.json',
    'architecture/artifact-edges/operator-harness-engineering-v4.json',
    'architecture/artifact-edges/operator-harness-engineering-v5.json',
    'architecture/artifact-edges/operator-harness-engineering-v6.json',
    'architecture/artifact-edges/operator-harness-engineering-v7.json',
    'architecture/artifact-edges/operator-harness-engineering-v8.json',
    'architecture/artifact-edges/operator-harness-engineering-v9.json',
    'architecture/artifact-edges/operator-harness-engineering.json',
    'architecture/broker-handoff-inputs/channel.schema.json',
    'architecture/broker-handoff-inputs/meta-before.json',
    'architecture/broker-handoff-inputs/vectors.json',
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
    'scripts/approval_outcome.py',
    'scripts/safe_yaml.py',
)
REGISTRY_BASE_SHA256 = "c41250415d701bf32c3b918d5598ef26c4078b3a5e009a7ef8ce2306aa6d7512"
BASE_SHA256 = MappingProxyType({
    "architecture/approval-outcome/record.json": "88e83285ecb02b654c6cdece8f88e1712a935bdc8e287ba5929ed237edfdec1e",
    "architecture/approval-outcome/schema.json": "9761fea64edd60d94f2a334c71124dbac4a064094c8092cc40a05bf9368b89e6",
    "architecture/approval-outcome/vectors.json": "7be26fb683f82cdff1a306a1f3a4cdc13be1eb9eebb29578bc4ff6365523472a",
    "architecture/artifact-edges/operator-harness-engineering-v10.json": "a4fad53dfadbe8a5d79d4049fbba83173adaacec8d33df5ca377aa288539364e",
    "architecture/artifact-edges/operator-harness-engineering-v11.json": "9188980f0ce211e2939d431d900a7aff77262de3a973009666ed13f3ef3cbd77",
    "architecture/artifact-edges/operator-harness-engineering-v12.json": "3587488b040f1c23f95f847dd3f1e15b97fa6ca705b6dca429d1cc6d64f3a5c7",
    "architecture/artifact-edges/operator-harness-engineering-v2.json": "749e70f174d638468bf45d7316e8f5201c3323f6348a78c7b9a22d3a571ccc32",
    "architecture/artifact-edges/operator-harness-engineering-v3.json": "106ea91aa09c2d377adf3b514a228331d6a805bd1a17e641ecaa23b3c39115f3",
    "architecture/artifact-edges/operator-harness-engineering-v4.json": "e30772ff8826650c46d1a8d384625929975e47f2de5cc9030680b5fdb5e7fc86",
    "architecture/artifact-edges/operator-harness-engineering-v5.json": "89b47ef8f865b31911eb8da2b08a5a3c22b2d92a62599cb6fdfccbfe7f79e3c0",
    "architecture/artifact-edges/operator-harness-engineering-v6.json": "0ac7c2da62de87837f5a36a967a2c5b9c286ecab2e03f335a8eebbd32df9d24d",
    "architecture/artifact-edges/operator-harness-engineering-v7.json": "6af45e361a66331a9ee0216d3eea42f3a17770fd3c7d33e78e2a025d301bfa92",
    "architecture/artifact-edges/operator-harness-engineering-v8.json": "623cf10bf19cfba1806f5699007f39c7f6ba38f72d92069548421c4dccd21573",
    "architecture/artifact-edges/operator-harness-engineering-v9.json": "197f30e4e1e0be1dcacd71f1095c91e2333fe9d6ea05b8194578160e471605d7",
    "architecture/artifact-edges/operator-harness-engineering.json": "54bdc2d22676720419f51cd1bad5eedc909e6f848ed09cd363e351889af9d1fe",
    "architecture/broker-handoff-inputs/channel.schema.json": "e7e9558fb50b7ba804222065734d1d4fb4694327bb2427a34ef8dffc945d56f9",
    "architecture/broker-handoff-inputs/meta-before.json": "701c23be9e1e57a4fb7288abc33d84aef992b7257342b28595c27120d80948bd",
    "architecture/broker-handoff-inputs/vectors.json": "80d8da953c41ef544ecf0cd4a0f62b98316b018bfbdc39c550c320f68ab603c4",
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
    "scripts/approval_outcome.py": "b9b7835b578c106e2b3470e33f60f9955fcf89d5e7a03c32716c92e0bbce6b37",
    "scripts/safe_yaml.py": "99c673560e65e58cdc1abe86e53472feaf93e546dd76cb9f3ba051beef5c49d7",
})
ERA_SHA256 = MappingProxyType({
    "architecture/approval-outcome/record.json": "88e83285ecb02b654c6cdece8f88e1712a935bdc8e287ba5929ed237edfdec1e",
    "architecture/approval-outcome/schema.json": "9761fea64edd60d94f2a334c71124dbac4a064094c8092cc40a05bf9368b89e6",
    "architecture/approval-outcome/vectors.json": "7be26fb683f82cdff1a306a1f3a4cdc13be1eb9eebb29578bc4ff6365523472a",
    "architecture/artifact-edges/README-v13.md": "4c15590d34eabee19fd8396888be4d0b0ffdfd1496955d98dcda255ffa5af7b3",
    "architecture/artifact-edges/operator-harness-engineering-v10.json": "a4fad53dfadbe8a5d79d4049fbba83173adaacec8d33df5ca377aa288539364e",
    "architecture/artifact-edges/operator-harness-engineering-v11.json": "9188980f0ce211e2939d431d900a7aff77262de3a973009666ed13f3ef3cbd77",
    "architecture/artifact-edges/operator-harness-engineering-v12.json": "3587488b040f1c23f95f847dd3f1e15b97fa6ca705b6dca429d1cc6d64f3a5c7",
    "architecture/artifact-edges/operator-harness-engineering-v13.json": "4f1b77aa3c0ae93307d2b793d92de2416af8630c27688f925745350c7cbd1226",
    "architecture/artifact-edges/operator-harness-engineering-v2.json": "749e70f174d638468bf45d7316e8f5201c3323f6348a78c7b9a22d3a571ccc32",
    "architecture/artifact-edges/operator-harness-engineering-v3.json": "106ea91aa09c2d377adf3b514a228331d6a805bd1a17e641ecaa23b3c39115f3",
    "architecture/artifact-edges/operator-harness-engineering-v4.json": "e30772ff8826650c46d1a8d384625929975e47f2de5cc9030680b5fdb5e7fc86",
    "architecture/artifact-edges/operator-harness-engineering-v5.json": "89b47ef8f865b31911eb8da2b08a5a3c22b2d92a62599cb6fdfccbfe7f79e3c0",
    "architecture/artifact-edges/operator-harness-engineering-v6.json": "0ac7c2da62de87837f5a36a967a2c5b9c286ecab2e03f335a8eebbd32df9d24d",
    "architecture/artifact-edges/operator-harness-engineering-v7.json": "6af45e361a66331a9ee0216d3eea42f3a17770fd3c7d33e78e2a025d301bfa92",
    "architecture/artifact-edges/operator-harness-engineering-v8.json": "623cf10bf19cfba1806f5699007f39c7f6ba38f72d92069548421c4dccd21573",
    "architecture/artifact-edges/operator-harness-engineering-v9.json": "197f30e4e1e0be1dcacd71f1095c91e2333fe9d6ea05b8194578160e471605d7",
    "architecture/artifact-edges/operator-harness-engineering.json": "54bdc2d22676720419f51cd1bad5eedc909e6f848ed09cd363e351889af9d1fe",
    "architecture/broker-handoff-inputs-v2/channel.schema.json": "b050af6bec767beef0796ee4a25edb76b6e761a9b793a4ffd16b4907e910f34e",
    "architecture/broker-handoff-inputs-v2/vectors.json": "b6154ebc18fe2fcb552971f88af5065441f757eba1b70cddef0090fda260a43d",
    "architecture/broker-handoff-inputs/channel.schema.json": "e7e9558fb50b7ba804222065734d1d4fb4694327bb2427a34ef8dffc945d56f9",
    "architecture/broker-handoff-inputs/meta-before.json": "701c23be9e1e57a4fb7288abc33d84aef992b7257342b28595c27120d80948bd",
    "architecture/broker-handoff-inputs/vectors.json": "80d8da953c41ef544ecf0cd4a0f62b98316b018bfbdc39c550c320f68ab603c4",
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
    "architecture/review-briefs/REVIEW_BRIEF_PACKET.md": "6dcff68d7e6b01823f1740063e94910edcc159a71a6ee803f1b66c62fd06e274",
    "architecture/review-record/briefs.json": "38c3a2b9b76ec7fec4bb8bf4865b97ef6995db4ad132666bc93f4f4afe87cf00",
    "ci/chain_checkpoint.py": "8c8789073698f4e7441b6fda6e7fae8675ad9e8cdd3b30c1a4471809fdc874a0",
    "scripts/approval_outcome.py": "b9b7835b578c106e2b3470e33f60f9955fcf89d5e7a03c32716c92e0bbce6b37",
    "scripts/broker_handoff_transcript_v2.py": "6344e54d229ef46efa3698e2068b05ff247257750307ad749ddc2bbad06e94f9",
    "scripts/decision_record.py": "af6bb14bb7b779f9764b5a8c7a116012837bbeacae9e7aee25ea54f1e6d39b6f",
    "scripts/safe_yaml.py": "99c673560e65e58cdc1abe86e53472feaf93e546dd76cb9f3ba051beef5c49d7",
    "scripts/validate_broker_handoff.py": "e7484442e8116c4fd9760c187c862ce3f5f12ac7795841635225d1983ab4aee6",
    "scripts/validate_decision_record.py": "49a9f0cac29ea11e68085c73e3eeddecdcba0cbe8b69905fec92572bb4cd5a84",
    "scripts/validate_edge_record_v13.py": "f3d3eb218e709d81b6ca110e1d3e1df268097c48888acbbf9e7b8f799690d2e4",
    "scripts/validate_proxy_contract.py": "45cb0a20b530d60a832a9ae1d78ae88ae5f1a22863332c5733f82fe3363e7b69",
    "scripts/validate_regulatory_alignment.py": "4814b82e3ffafe976f80e3adb755dca531a4fc76b5df43fc15f8627936ad926b",
    "tests/test_decision_record.py": "1b3f7163ec1022927e6b71aa8db1f40205410b8bb2edc21196404ca1d4a5b452",
    "tests/test_edge_record_v13.py": "e5593e6fc2ce2127e937ec40b5956b60843cdb22d1a82ee32b60572ac8bb1eb9",
    "tests/test_regulatory_alignment.py": "fd54dc2ef2a28881717f605af9da58a26b0087cdc1658e2ad10f249868323913",
})
ERRATA_LINES = MappingProxyType({
    "architecture/oracle-identity-met-013.json": ((5, 5), (28, 29), (56, 56)),
    "tests/test_ci_performance.py": ((169, 169),),
    "tests/test_credential_lifecycle.py": ((362, 362),),
    "tests/test_met_013_oracle.py": ((1574, 1576), (1580, 1582), (1585, 1586), (1588, 1588), (1590, 1592)),
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
    return successor.historical_bytes(path, regular_bytes(path))


def _era_bytes(path: Any, raw: Any) -> bytes:
    """An era file's bytes, checked against its era digest; a path outside the era is refused."""
    expected = ERA_SHA256.get(path) if type(path) is str else None
    require(expected is not None, "MET-014 reviewed bytes are bound: " + str(path))
    require(type(raw) is bytes and digest(raw) == expected, "unreviewed MET-014 source: " + path)
    return raw


def _verified(path: str) -> bytes:
    """reviewed_bytes, checked against its era digest on every read; a path outside the era is refused before it is
    read."""
    require(type(path) is str and path in ERA_SHA256, "MET-014 reviewed bytes are bound: " + str(path))
    return _era_bytes(path, reviewed_bytes(path))


def _bound_read(path: str, expected: Any) -> bytes:
    """reviewed_bytes of a file named by an era-verified record, checked against the digest that record gives it."""
    require(type(path) is str and _sha(expected), "MET-014 bound read: " + str(path))
    _path(path)
    raw = reviewed_bytes(path)
    require(type(raw) is bytes and digest(raw) == expected, "MET-014 bound file drift: " + path)
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
           "the registry differs from the base by exactly the MET-014 packet rider, pinning the generic packet "
           "brief")


def validate_registry() -> None:
    """V4 over briefs.json and the generic packet brief."""
    check_registry(_verified(REGISTRY_PATH), {PACKET_BRIEF: _verified(PACKET_BRIEF)})


def check_packet_files(files: Any) -> None:
    """V1: the packet's files are exactly these, and each one's bytes equal the sha256 pinned for it."""
    _bound(lambda: type(files) is dict and sorted(files) == sorted(PACKET_FILES) and len(files) == len(PACKET_FILES),
           "MET-014 V1 the packet files are exactly the nineteen")
    for path in PACKET_FILES:
        _bound(lambda: type(files[path]) is bytes and digest(files[path]) == ERA_SHA256[path],
               "MET-014 V1 a packet file's bytes equal its pinned digest: " + path)


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
    pair from the authority's baselinePackets size, then countPairs; no products (K = 0); the new tests from newFiles."""
    n = len(record["baselinePackets"])
    return {"prevValidator": context["prevValidator"], "prevTest": context["prevTest"], "newPacket": context["newPacket"],
            "products": [], "steps": context["steps"],
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
           "MET-014 V6 the hunk-class record is closed and names this layer's authority")
    _bound(lambda: record["hunkClassVocabulary"] == list(HUNK_VOCABULARY)
           and record["hunkClassRuleSha256"] == HUNK_RULE_SHA256 == rule_sha,
           "MET-014 V6 the hunk-class record's vocabulary and rule digest are v2.5's")
    _bound(lambda: type(record["hunkClassContext"]) is dict and set(record["hunkClassContext"]) == set(HUNK_CONTEXT)
           and record["hunkClassContext"] == {"newPacket": NEW_PACKET, "prevValidator": HUNK_CONTEXT["prevValidator"],
                                              "prevTest": HUNK_CONTEXT["prevTest"], "steps": [1, 1], "countPairs": []},
           "MET-014 V6 the hunk-class record's context is this step's names")
    classes = record.get("classes") if type(record) is dict else None
    _bound(lambda: type(changed) is dict and type(classes) is dict and set(classes) == set(changed)
           and all(type(classes[p]) is list and all(type(c) is str for c in classes[p])
                   and len(classes[p]) == len(changed[p].get("reverseHunks", [])) for p in changed),
           "MET-014 V6 the hunk-class record lists one class per hunk for exactly the changed files")
    for path, entry in changed.items():
        seen = set()
        for position, (cls, hunk) in enumerate(zip(classes[path], entry.get("reverseHunks", []))):
            _bound(lambda: cls in HUNK_VOCABULARY and cls == classify(
                path, afters[path], hunk["at"], _base64(hunk["removeBase64"]), _base64(hunk["insertBase64"]), context,
                seen=seen),
                   "MET-014 V6 a recorded class re-checks by position: %s hunk %d" % (path, position))


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
           "MET-014 E3 class-other hunks fall only on the named files")
    for path, spans in ERRATA_LINES.items():
        _bound(lambda: "other" in classes[path] and type(befores[path]) is bytes,
               "MET-014 E3 the named file carries its authored hunk: " + path)
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
                       "MET-014 E3 an authored hunk lies at its named lines: %s hunk %d" % (path, position))


def validate_errata() -> None:
    """E3 over the hunk-class record (bound by its newFiles digest) and each named file's before bytes, projected back
    through this layer's own hunks from its afterSha256-bound bytes."""
    record = authority()
    side = _parsed(_bound_read(HUNK_RECORD_PATH, record["newFiles"].get(HUNK_RECORD_PATH)))
    befores = {path: _undo_this_layer(path, _bound_read(path, record["changedFiles"][path]["afterSha256"]))
               for path in ERRATA_LINES if path in record["changedFiles"]}
    check_errata(side.get("classes") if type(side) is dict else None, record["changedFiles"], befores)


MEMBERS = (                                     # CONTRACT_296 section 1's order
    MappingProxyType({"item": "GR-DECISION-RECORD-001", "module": "decision_record",
                      "model": "scripts/decision_record.py", "modelName": "_met_014_decision_record",
                      "checker": "scripts/validate_decision_record.py", "checkerName": "_met_014_validate_decision_record",
                      "record": "architecture/decision-record/reason-codes.json", "vectors": "architecture/decision-record/vectors.json",
                      "bases": ()}),
    MappingProxyType({"item": "REG-ALIGN-001", "module": "regulatory_alignment",
                      "model": None, "modelName": None,
                      "checker": "scripts/validate_regulatory_alignment.py", "checkerName": "_met_014_validate_regulatory_alignment",
                      "record": "architecture/regulatory-alignment.json", "vectors": None,
                      "bases": ()}),
    MappingProxyType({"item": "EDGE-V13", "module": "broker_handoff_transcript_v2",
                      "model": "scripts/broker_handoff_transcript_v2.py", "modelName": "_met_014_broker_handoff_transcript_v2",
                      "checker": "scripts/validate_edge_record_v13.py", "checkerName": "_met_014_validate_edge_record_v13",
                      "record": "architecture/artifact-edges/operator-harness-engineering-v13.json", "vectors": "architecture/broker-handoff-inputs-v2/vectors.json",
                      "schema": "architecture/broker-handoff-inputs-v2/channel.schema.json",
                      "bases": (('safe_yaml', 'scripts/safe_yaml.py'), ('validate_proxy_contract', 'scripts/validate_proxy_contract.py'))}),
)
DECISION, ALIGNMENT, EDGE = MEMBERS
SLOT = 296
HUNK_RECORD_PATH = "architecture/chain-checkpoint/hunk-classes/296.json"
READER_NAME = "_met_014_chain_checkpoint"
HUNK_CONTEXT = MappingProxyType({"newPacket": NEW_PACKET, "prevValidator": "scripts/validate_met_013.py",
                                 "prevTest": "tests/test_met_013.py", "steps": (1, 1), "countPairs": ()})


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
        era[name] = _era_model(path, "_met_014_" + name, injected())
    model = None
    if member["model"] is not None:
        model = _era_model(member["model"], member["modelName"], injected())
        era[member["module"]] = model
    checker = _era_model(member["checker"], member["checkerName"], injected())
    return model, checker


def check_decision_record(vectors: Any, refusals: Any, replayed: Any) -> None:
    """E1 (GR-DECISION-RECORD-001): the record passes the era checker (DR_SHAPE to DR_VECTOR) over this era's bytes;
    and the head itself replays every vector, by the vectors file's own list and independently of the checker's,
    through the era model to its expectation (the count is the parsed list's length)."""
    _bound(lambda: type(refusals) is list and refusals == [],
           "MET-014 E1 the decision record passes its checker (DR_SHAPE to DR_VECTOR)")
    _bound(lambda: type(vectors) is dict and type(vectors["cases"]) is list and len(vectors["cases"]) > 0
           and type(replayed) is list and len(replayed) == len(vectors["cases"]) and all(ok is True for ok in replayed),
           "MET-014 E1 every decision record vector replays through its era model to its expectation")


def validate_decision_record(packets: Any) -> None:
    """E1 over era bytes only: the era checker's refusals through the era reader, and each vector's replay."""
    model, checker = _era_checker(DECISION)
    vectors = json.loads(_verified(DECISION["vectors"]))
    check_decision_record(vectors, checker.check(_era_read), [model.replay(case)[0] for case in vectors["cases"]])


def check_regulatory_alignment(refusals: Any) -> None:
    """E1 (REG-ALIGN-001): the record passes the era checker (RA_SHAPE to RA_SOURCES) over this era's bytes; the
    member has no vectors file and no model, so there is no replay half (CONTRACT_296 4a difference 3)."""
    _bound(lambda: type(refusals) is list and refusals == [],
           "MET-014 E1 the regulatory alignment record passes its checker (RA_SHAPE to RA_SOURCES)")


def validate_regulatory_alignment(packets: Any) -> None:
    """E1 over era bytes only: the era checker's refusals through the era reader; no vectors are read."""
    model, checker = _era_checker(ALIGNMENT)
    check_regulatory_alignment(checker.check(_era_read))


def check_edge_v13(refusals: Any) -> None:
    """E1 (EDGE-V13): the record passes the era checker (EV_V1 to EV_HUNKS) over this era's bytes; the checker's own
    EV_V2 row replays every positive vector through the era model under the era v13 schema, a raise not an acceptance,
    so the head has no replay half (CONTRACT_296 4a difference 4 as BUILD_PLAN_296 ERR-6 restates it)."""
    _bound(lambda: type(refusals) is list and refusals == [],
           "MET-014 E1 the edge v13 record passes its checker (EV_V1 to EV_HUNKS)")


def validate_edge_v13(packets: Any) -> None:
    """E1 over era bytes only: the era checker's refusals through the era reader, its model and bases from _era_checker
    (difference 1 (ii)); no vectors are read (ERR-6)."""
    model, checker = _era_checker(EDGE)
    check_edge_v13(checker.check(_era_read))


def _era_read(path: Any) -> bytes:
    """The checker's injected reader: an era file's verified bytes; any other path is refused (a ValueError), so a
    packet reference outside the era does not resolve."""
    return _verified(path)


def check_base_files(files: Any, changed: Any, new: Any) -> None:
    """E2: HR-APPROVAL-OUTCOME-001's and HR-REPLAY-FIXTURES-001's files, the v1 broker-handoff inputs, safe_yaml and
    the v1-v12 edge records (CONTRACT_296 section 1 less the two scripts the cascade rewrites, BUILD_PLAN_296 ERR-5)
    equal their base bytes, and this step's authority names none of them."""
    _bound(lambda: type(files) is dict and sorted(files) == sorted(BASE_SHA256)
           and all(type(files[path]) is bytes and digest(files[path]) == BASE_SHA256[path] for path in BASE_SHA256),
           "MET-014 E2 the base files equal their base bytes")
    _bound(lambda: type(changed) is dict and type(new) is dict and not set(BASE_SHA256) & (set(changed) | set(new)),
           "MET-014 E2 this step changes no base file")


def validate_base_files() -> None:
    record = authority()
    check_base_files({path: _verified(path) for path in BASE_FILES}, record["changedFiles"], record["newFiles"])


def validate_met_014(packets: dict[str, Any]) -> None:
    """Every era file first; then V1 (the packet's files), E1 per member in section 1's order (the checker and the
    model), E2 (the base files), E3 (the authored edits), V4 (the registry) and V6 (the hunk-class record); last,
    this layer's canonical hunks."""
    for path in ERA_SHA256:
        _verified(path)
    validate_packet_files()
    validate_decision_record(packets)
    validate_regulatory_alignment(packets)
    validate_edge_v13(packets)
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
    validator_raw = successor.historical_bytes(VALIDATOR_PATH, regular_bytes(VALIDATOR_PATH))
    literal = b'AUTHORITY_SHA256 = "' + AUTHORITY_SHA256.encode("ascii") + b'"'
    placeholder = b'AUTHORITY_SHA256 = "TO_BE_PINNED_AFTER_SOURCE_FREEZE"'
    require(validator_raw.count(literal) == 1
            and digest(validator_raw.replace(literal, placeholder))
            == record["validatorNormalizedSha256"], "grdec regalign edgev13 validator drift")
    paths = sorted((ROOT / "task-packets").glob("*.yaml"))
    old = set(record["baselinePackets"])
    require(len(paths) == 322
            and {path.stem for path in paths} == old | {NEW_PACKET, successor.NEW_PACKET, *successor.PRODUCT_PACKETS},
            "closed 322-packet catalog retaining the 320-packet checkpoint")
    packets = {}
    for path in paths:
        if path.stem == successor.NEW_PACKET:
            continue
        if path.stem in successor.PRODUCT_PACKETS:
            continue
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
            "closed source-only grdec-regalign-edgev13 packet and inherited commands")
    require(len(packet["allowedPaths"]) == len(set(packet["allowedPaths"]))
            and set(packet["allowedPaths"]) == set(record["changedFiles"])
            | set(record["newFiles"]) | {AUTHORITY_PATH, VALIDATOR_PATH,
                                         "task-packets/" + NEW_PACKET + ".yaml"},
            "unreviewed or omitted grdec-regalign-edgev13 packet path")
    for path, rule in record["changedFiles"].items():
        current = successor.historical_bytes(path, regular_bytes(path))
        require(digest(current) == rule["afterSha256"]
                and digest(historical_bytes(path, current)) == rule["beforeSha256"],
                "unreviewed current source: " + path)
    for path, expected in record["newFiles"].items():
        require(digest(successor.historical_bytes(path, regular_bytes(path))) == expected,
                "new source drift: " + path)
    validate_met_014(packets)


if __name__ == "__main__":
    validate()
    print("Grdec regalign edgev13 valid: 322 current specifications at slot 296; 320-packet checkpoint and exact 319-packet predecessor; contract reviewed.")
