#!/usr/bin/env python3
"""Validate MET-013 (the three hr contracts HR-COMPACTION-GOV-001, HR-REPLAY-FIXTURES-001 and HR-APPROVAL-OUTCOME-001, K = 0): V1 this packet's files by digest; E1 each member's checker and model from their era bytes; E2 MAS-RA-008's and MAS-RA-002's files unchanged; E3 the authored edits at their named lines; V4 the registry rider; V6 the hunk-class record under v2.5."""
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
AUTHORITY_PATH = "architecture/three-hr-contracts-authority.json"
AUTHORITY_SHA256 = "44fa1f441b92a8dab63cea40742b0fea558eaefc6db00ceb3eb21510971f0db3"
VALIDATOR_PATH = "scripts/validate_met_013.py"
BASE_COMMIT = "6437de35186c458e671a4b659390d2b5f3909c8d"
NEW_PACKET = "MET-013"
PREVIOUS_PACKET = "MET-012"
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
            require(key not in result, "duplicate three-hr-contracts authority member")
            result[key] = value
        return result

    def no_constant(_value: str) -> Any:
        raise ValueError("nonfinite three-hr-contracts authority number")

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
        require(digest(raw) == AUTHORITY_SHA256, "three hr contracts history authority digest")
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
    }, "closed three hr contracts history authority")
    require(value["schemaVersion"] == "harness.planeon.ai/three-hr-contracts-authority/v1"
            and value["authorityPacket"] == NEW_PACKET
            and value["acceptedBase"] == BASE_COMMIT
            and type(value["baselinePackets"]) is dict
            and len(value["baselinePackets"]) == 318
            and NEW_PACKET not in value["baselinePackets"]
            and type(value["changedFiles"]) is dict
            and type(value["newFiles"]) is dict
            and _sha(value["packetSha256"])
            and _sha(value["validatorNormalizedSha256"]),
            "accepted 318-packet base")
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


# MET-013 (rulings: CONTRACT_295 section 2) publishes, in a K = 0 step, three in-repo contracts, each a record
# with its schema, vectors, reference model, checker and test: HR-COMPACTION-GOV-001 (R08, the agent loop's
# compaction amendment over MAS-RA-008), HR-REPLAY-FIXTURES-001 (R12, the replay-fixture contract over MAS-RA-002's
# run manifest) and HR-APPROVAL-OUTCOME-001 (R04 and R12, the approval outcome contract). Repository bytes are
# read only through reviewed_bytes; an era file is refused unless bound by digest on every read, a changed file
# by the authority's afterSha256. Each refusal is a pure check over the values read. Checked here: V1 the
# packet's thirty files by digest; E1 per member, its checker and its model from their era bytes (the record passes
# its checker, and every vector replays through its model to its expectation); E2 MAS-RA-008's and MAS-RA-002's
# files unchanged; E3 class-other hunks only at the named spans, read under v2.5; V4 the registry rider; V6 the
# hunk-class record under v2.5. Last, this layer's own inverse hunks are the canonical ones.
PACKET_FILES = (
    'architecture/agent-loop-compaction/record.json',
    'architecture/agent-loop-compaction/schema.json',
    'architecture/agent-loop-compaction/vectors.json',
    'architecture/approval-outcome/record.json',
    'architecture/approval-outcome/schema.json',
    'architecture/approval-outcome/vectors.json',
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
    'scripts/agent_loop_compaction.py',
    'scripts/approval_outcome.py',
    'scripts/replay_fixtures.py',
    'scripts/validate_agent_loop_compaction.py',
    'scripts/validate_approval_outcome.py',
    'scripts/validate_replay_fixtures.py',
    'tests/test_agent_loop_compaction.py',
    'tests/test_approval_outcome.py',
    'tests/test_replay_fixtures.py',
)
BASE_FILES = (
    'architecture/agent-loop/README.md',
    'architecture/agent-loop/loop-profile.schema.json',
    'architecture/agent-loop/loop-trace.schema.json',
    'architecture/agent-loop/review-round1.json',
    'architecture/agent-loop/review-round10.json',
    'architecture/agent-loop/review-round2.json',
    'architecture/agent-loop/review-round3.json',
    'architecture/agent-loop/review-round4.json',
    'architecture/agent-loop/review-round5.json',
    'architecture/agent-loop/review-round6.json',
    'architecture/agent-loop/review-round7.json',
    'architecture/agent-loop/review-round8.json',
    'architecture/agent-loop/review-round9.json',
    'architecture/agent-loop/round1/README.md',
    'architecture/agent-loop/round1/loop-profile.schema.json',
    'architecture/agent-loop/round1/loop-trace.schema.json',
    'architecture/agent-loop/round1/scripts/agent_loop.py',
    'architecture/agent-loop/round10/README.md',
    'architecture/agent-loop/round10/loop-profile.schema.json',
    'architecture/agent-loop/round10/loop-trace.schema.json',
    'architecture/agent-loop/round10/scripts/agent_loop.py',
    'architecture/agent-loop/round2/README.md',
    'architecture/agent-loop/round2/loop-profile.schema.json',
    'architecture/agent-loop/round2/loop-trace.schema.json',
    'architecture/agent-loop/round2/scripts/agent_loop.py',
    'architecture/agent-loop/round3/README.md',
    'architecture/agent-loop/round3/loop-profile.schema.json',
    'architecture/agent-loop/round3/loop-trace.schema.json',
    'architecture/agent-loop/round3/scripts/agent_loop.py',
    'architecture/agent-loop/round4/README.md',
    'architecture/agent-loop/round4/loop-profile.schema.json',
    'architecture/agent-loop/round4/loop-trace.schema.json',
    'architecture/agent-loop/round4/scripts/agent_loop.py',
    'architecture/agent-loop/round5/README.md',
    'architecture/agent-loop/round5/loop-profile.schema.json',
    'architecture/agent-loop/round5/loop-trace.schema.json',
    'architecture/agent-loop/round5/scripts/agent_loop.py',
    'architecture/agent-loop/round6/README.md',
    'architecture/agent-loop/round6/loop-profile.schema.json',
    'architecture/agent-loop/round6/loop-trace.schema.json',
    'architecture/agent-loop/round6/scripts/agent_loop.py',
    'architecture/agent-loop/round7/README.md',
    'architecture/agent-loop/round7/loop-profile.schema.json',
    'architecture/agent-loop/round7/loop-trace.schema.json',
    'architecture/agent-loop/round7/scripts/agent_loop.py',
    'architecture/agent-loop/round8/README.md',
    'architecture/agent-loop/round8/loop-profile.schema.json',
    'architecture/agent-loop/round8/loop-trace.schema.json',
    'architecture/agent-loop/round8/scripts/agent_loop.py',
    'architecture/agent-loop/round9/README.md',
    'architecture/agent-loop/round9/loop-profile.schema.json',
    'architecture/agent-loop/round9/loop-trace.schema.json',
    'architecture/agent-loop/round9/scripts/agent_loop.py',
    'architecture/agent-loop/status.json',
    'architecture/agent-loop/vectors.json',
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
    'scripts/agent_loop.py',
    'scripts/run_manifest.py',
)
REGISTRY_BASE_SHA256 = "3337df8acda134549b700ad2e7b35d042b5580255e449a3ffe7b9030a9234aea"
BASE_SHA256 = MappingProxyType({
    "architecture/agent-loop/README.md": "666c4221d3edbdd5187c17db9c43c122b1f7900a9fa0b3ddc430db3bee2b8e5a",
    "architecture/agent-loop/loop-profile.schema.json": "d75a5b943929f7678c8e8c8cacf2e937312bcc06caf15018de73ae9b9abac0bb",
    "architecture/agent-loop/loop-trace.schema.json": "3be32ceee16c2bbbeaf945ee8231a16e4a74fc2ddce46ebafdf7bee9d7868b6e",
    "architecture/agent-loop/review-round1.json": "fd62e36f2d1b44d646a80c0fbd91bfcf9774c23fd7e9d35dc03183af41cb3aca",
    "architecture/agent-loop/review-round10.json": "548d0f9d9d89d7e16d07394302a28a8e94af39ce022ef053bbb1422fb44b7855",
    "architecture/agent-loop/review-round2.json": "cd8742c7529004e28eaf67c9e0299ce383b81f504c94c5dcbf781cacf831c8f0",
    "architecture/agent-loop/review-round3.json": "70c6556f46046c65d583db22da3551d47fbb45afe43ef7f0400cc12c9bb445f5",
    "architecture/agent-loop/review-round4.json": "f51a47644a3872aa76a96b9fa4aa62e95669d78d7f881e5bd6930fb709df39af",
    "architecture/agent-loop/review-round5.json": "ba609ca5da2c65a1a0a0249c0ac16135ed4ecf72cfaae5f0d6d5883423edf233",
    "architecture/agent-loop/review-round6.json": "9166f0ad2e25dffe026440be14cd8de91ef1fa50f9aaa29b5b4da42a5c56585f",
    "architecture/agent-loop/review-round7.json": "f7228cfdde5a17082b6ad41f7719b95de04da16d9cbd2bb57b69128f5343812d",
    "architecture/agent-loop/review-round8.json": "c184b6d6172f4a2c274e9d958774dc1de48a6a822875239e4f68d82d227a85b1",
    "architecture/agent-loop/review-round9.json": "46a3ada7331be83a9316bd7fac7e15e17e6e63fe3a68c172c5c3ec95fd165fd1",
    "architecture/agent-loop/round1/README.md": "515d77014f9179803f0e2ab49a1835a23ab6aceea223b937c8bae944534542d6",
    "architecture/agent-loop/round1/loop-profile.schema.json": "416ce6adfe06d55f208e5edc9935cc874d92f02c34db83ba089b60c62e838852",
    "architecture/agent-loop/round1/loop-trace.schema.json": "d6e0041953a21fd464bb87490fe11976ec60cea32953b9ae9a9d4c14d0b7f451",
    "architecture/agent-loop/round1/scripts/agent_loop.py": "819c980b122698f5af3d194ea5f41603d72cee84bd1ed1719bc61a05fe69a8f7",
    "architecture/agent-loop/round10/README.md": "9e6fb062c36de9a04b1ad9aeebef3b89d0cdc5975c6a6c37eb48416197d014db",
    "architecture/agent-loop/round10/loop-profile.schema.json": "d75a5b943929f7678c8e8c8cacf2e937312bcc06caf15018de73ae9b9abac0bb",
    "architecture/agent-loop/round10/loop-trace.schema.json": "3be32ceee16c2bbbeaf945ee8231a16e4a74fc2ddce46ebafdf7bee9d7868b6e",
    "architecture/agent-loop/round10/scripts/agent_loop.py": "8474e7546294ec48250b3f531f5061777134212c033928cbf0ec911eab1ff8bf",
    "architecture/agent-loop/round2/README.md": "8c9c5cab7c4948dc83ca500fd2b3314d45043a617f826979c211f1de17168083",
    "architecture/agent-loop/round2/loop-profile.schema.json": "d75a5b943929f7678c8e8c8cacf2e937312bcc06caf15018de73ae9b9abac0bb",
    "architecture/agent-loop/round2/loop-trace.schema.json": "d6e0041953a21fd464bb87490fe11976ec60cea32953b9ae9a9d4c14d0b7f451",
    "architecture/agent-loop/round2/scripts/agent_loop.py": "b54e5d147feb1c31b1b351ef56c88f77fa0bdd927a23776827c35dd2275f31dd",
    "architecture/agent-loop/round3/README.md": "1cc77952ea7b1fb12daeb0183008a379a0463945fef775e8c1f97ae5ea8bfc52",
    "architecture/agent-loop/round3/loop-profile.schema.json": "d75a5b943929f7678c8e8c8cacf2e937312bcc06caf15018de73ae9b9abac0bb",
    "architecture/agent-loop/round3/loop-trace.schema.json": "3be32ceee16c2bbbeaf945ee8231a16e4a74fc2ddce46ebafdf7bee9d7868b6e",
    "architecture/agent-loop/round3/scripts/agent_loop.py": "d0f9b3b8b586d835b88ca88eeb46971a7be1d29f62223eaf9827eaf7f8a24eae",
    "architecture/agent-loop/round4/README.md": "ed63353c6ea8fa13a5860533eef357d594cc816fe3643c457f20f43759d2adfe",
    "architecture/agent-loop/round4/loop-profile.schema.json": "d75a5b943929f7678c8e8c8cacf2e937312bcc06caf15018de73ae9b9abac0bb",
    "architecture/agent-loop/round4/loop-trace.schema.json": "3be32ceee16c2bbbeaf945ee8231a16e4a74fc2ddce46ebafdf7bee9d7868b6e",
    "architecture/agent-loop/round4/scripts/agent_loop.py": "8342fb92a2375c866840f6a49dcdbae70f7a35ea10f24b58a80086b63b04886c",
    "architecture/agent-loop/round5/README.md": "1209240831307fa7e45765ed84914f49fd1d229961945ccc6bc344fc9d6f1135",
    "architecture/agent-loop/round5/loop-profile.schema.json": "d75a5b943929f7678c8e8c8cacf2e937312bcc06caf15018de73ae9b9abac0bb",
    "architecture/agent-loop/round5/loop-trace.schema.json": "3be32ceee16c2bbbeaf945ee8231a16e4a74fc2ddce46ebafdf7bee9d7868b6e",
    "architecture/agent-loop/round5/scripts/agent_loop.py": "a7fa569761461d62538799ab96ebb24a59a0419f775c2982bffc01d8d8b7ce1e",
    "architecture/agent-loop/round6/README.md": "087e8fd1a6e496799d30f8aaf4426dccdf3d27d898d2adca20ad39da52bbaaeb",
    "architecture/agent-loop/round6/loop-profile.schema.json": "d75a5b943929f7678c8e8c8cacf2e937312bcc06caf15018de73ae9b9abac0bb",
    "architecture/agent-loop/round6/loop-trace.schema.json": "3be32ceee16c2bbbeaf945ee8231a16e4a74fc2ddce46ebafdf7bee9d7868b6e",
    "architecture/agent-loop/round6/scripts/agent_loop.py": "058b3c95bc50f81bb519f34ea7ed53b5e421bfc0b0dbdffea1e311cdc82e09b1",
    "architecture/agent-loop/round7/README.md": "fcdf0707edc32ff405ccfb511c46d93ef6030d20cff4d8ded0987e6c6c3f4ef0",
    "architecture/agent-loop/round7/loop-profile.schema.json": "d75a5b943929f7678c8e8c8cacf2e937312bcc06caf15018de73ae9b9abac0bb",
    "architecture/agent-loop/round7/loop-trace.schema.json": "3be32ceee16c2bbbeaf945ee8231a16e4a74fc2ddce46ebafdf7bee9d7868b6e",
    "architecture/agent-loop/round7/scripts/agent_loop.py": "71d4f9d08af7329094b616d5c8343c733f31bec881599f98cd130add0b74d361",
    "architecture/agent-loop/round8/README.md": "c63e554f8ca0b522ac35f6bdcc24035ea58ef467858477c0071c159c1ef01467",
    "architecture/agent-loop/round8/loop-profile.schema.json": "d75a5b943929f7678c8e8c8cacf2e937312bcc06caf15018de73ae9b9abac0bb",
    "architecture/agent-loop/round8/loop-trace.schema.json": "3be32ceee16c2bbbeaf945ee8231a16e4a74fc2ddce46ebafdf7bee9d7868b6e",
    "architecture/agent-loop/round8/scripts/agent_loop.py": "075b0e2fef646ea6b4c2bc6f0cfbdcfbde290b69c91f0a0872ca5100616a5982",
    "architecture/agent-loop/round9/README.md": "53e451f800d56870c33261b6c73be11e01f409d497103afd2e9be36e82b5cc16",
    "architecture/agent-loop/round9/loop-profile.schema.json": "d75a5b943929f7678c8e8c8cacf2e937312bcc06caf15018de73ae9b9abac0bb",
    "architecture/agent-loop/round9/loop-trace.schema.json": "3be32ceee16c2bbbeaf945ee8231a16e4a74fc2ddce46ebafdf7bee9d7868b6e",
    "architecture/agent-loop/round9/scripts/agent_loop.py": "7b3aba35d720813265a89aa4bce2ddf24329b59d082b9160815ce03f19f3a3d0",
    "architecture/agent-loop/status.json": "0410907c3f6b9ac6907fcadc7767678b01c65c24593b0d5ae84a95ca63c581ad",
    "architecture/agent-loop/vectors.json": "b48e27f1be3cc0ce575d874d6c90cfe23837ee2a9abe6331c18a72e176d85429",
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
    "scripts/agent_loop.py": "f9a1fb1441a39efa6e566b26474f25f30106e4bbf6be4919d31ac69dddc48e68",
    "scripts/run_manifest.py": "f2861b4c23ad51fc5b8cdd9910124b23d2c114bd61786e58d93b20f42f3f423e",
})
ERA_SHA256 = MappingProxyType({
    "architecture/agent-loop-compaction/record.json": "ecb642d36078aa72bab4affce486af963296d0de688bd1f76417a7610dcb1a2b",
    "architecture/agent-loop-compaction/schema.json": "7c417668a36a8a825aa157909b51794980b2c57f7d94892f973d612e844e78d9",
    "architecture/agent-loop-compaction/vectors.json": "e3f144fe37258e95cd152fb799706a3ee66380708f63031f488d420113e7c3a4",
    "architecture/agent-loop/README.md": "666c4221d3edbdd5187c17db9c43c122b1f7900a9fa0b3ddc430db3bee2b8e5a",
    "architecture/agent-loop/loop-profile.schema.json": "d75a5b943929f7678c8e8c8cacf2e937312bcc06caf15018de73ae9b9abac0bb",
    "architecture/agent-loop/loop-trace.schema.json": "3be32ceee16c2bbbeaf945ee8231a16e4a74fc2ddce46ebafdf7bee9d7868b6e",
    "architecture/agent-loop/review-round1.json": "fd62e36f2d1b44d646a80c0fbd91bfcf9774c23fd7e9d35dc03183af41cb3aca",
    "architecture/agent-loop/review-round10.json": "548d0f9d9d89d7e16d07394302a28a8e94af39ce022ef053bbb1422fb44b7855",
    "architecture/agent-loop/review-round2.json": "cd8742c7529004e28eaf67c9e0299ce383b81f504c94c5dcbf781cacf831c8f0",
    "architecture/agent-loop/review-round3.json": "70c6556f46046c65d583db22da3551d47fbb45afe43ef7f0400cc12c9bb445f5",
    "architecture/agent-loop/review-round4.json": "f51a47644a3872aa76a96b9fa4aa62e95669d78d7f881e5bd6930fb709df39af",
    "architecture/agent-loop/review-round5.json": "ba609ca5da2c65a1a0a0249c0ac16135ed4ecf72cfaae5f0d6d5883423edf233",
    "architecture/agent-loop/review-round6.json": "9166f0ad2e25dffe026440be14cd8de91ef1fa50f9aaa29b5b4da42a5c56585f",
    "architecture/agent-loop/review-round7.json": "f7228cfdde5a17082b6ad41f7719b95de04da16d9cbd2bb57b69128f5343812d",
    "architecture/agent-loop/review-round8.json": "c184b6d6172f4a2c274e9d958774dc1de48a6a822875239e4f68d82d227a85b1",
    "architecture/agent-loop/review-round9.json": "46a3ada7331be83a9316bd7fac7e15e17e6e63fe3a68c172c5c3ec95fd165fd1",
    "architecture/agent-loop/round1/README.md": "515d77014f9179803f0e2ab49a1835a23ab6aceea223b937c8bae944534542d6",
    "architecture/agent-loop/round1/loop-profile.schema.json": "416ce6adfe06d55f208e5edc9935cc874d92f02c34db83ba089b60c62e838852",
    "architecture/agent-loop/round1/loop-trace.schema.json": "d6e0041953a21fd464bb87490fe11976ec60cea32953b9ae9a9d4c14d0b7f451",
    "architecture/agent-loop/round1/scripts/agent_loop.py": "819c980b122698f5af3d194ea5f41603d72cee84bd1ed1719bc61a05fe69a8f7",
    "architecture/agent-loop/round10/README.md": "9e6fb062c36de9a04b1ad9aeebef3b89d0cdc5975c6a6c37eb48416197d014db",
    "architecture/agent-loop/round10/loop-profile.schema.json": "d75a5b943929f7678c8e8c8cacf2e937312bcc06caf15018de73ae9b9abac0bb",
    "architecture/agent-loop/round10/loop-trace.schema.json": "3be32ceee16c2bbbeaf945ee8231a16e4a74fc2ddce46ebafdf7bee9d7868b6e",
    "architecture/agent-loop/round10/scripts/agent_loop.py": "8474e7546294ec48250b3f531f5061777134212c033928cbf0ec911eab1ff8bf",
    "architecture/agent-loop/round2/README.md": "8c9c5cab7c4948dc83ca500fd2b3314d45043a617f826979c211f1de17168083",
    "architecture/agent-loop/round2/loop-profile.schema.json": "d75a5b943929f7678c8e8c8cacf2e937312bcc06caf15018de73ae9b9abac0bb",
    "architecture/agent-loop/round2/loop-trace.schema.json": "d6e0041953a21fd464bb87490fe11976ec60cea32953b9ae9a9d4c14d0b7f451",
    "architecture/agent-loop/round2/scripts/agent_loop.py": "b54e5d147feb1c31b1b351ef56c88f77fa0bdd927a23776827c35dd2275f31dd",
    "architecture/agent-loop/round3/README.md": "1cc77952ea7b1fb12daeb0183008a379a0463945fef775e8c1f97ae5ea8bfc52",
    "architecture/agent-loop/round3/loop-profile.schema.json": "d75a5b943929f7678c8e8c8cacf2e937312bcc06caf15018de73ae9b9abac0bb",
    "architecture/agent-loop/round3/loop-trace.schema.json": "3be32ceee16c2bbbeaf945ee8231a16e4a74fc2ddce46ebafdf7bee9d7868b6e",
    "architecture/agent-loop/round3/scripts/agent_loop.py": "d0f9b3b8b586d835b88ca88eeb46971a7be1d29f62223eaf9827eaf7f8a24eae",
    "architecture/agent-loop/round4/README.md": "ed63353c6ea8fa13a5860533eef357d594cc816fe3643c457f20f43759d2adfe",
    "architecture/agent-loop/round4/loop-profile.schema.json": "d75a5b943929f7678c8e8c8cacf2e937312bcc06caf15018de73ae9b9abac0bb",
    "architecture/agent-loop/round4/loop-trace.schema.json": "3be32ceee16c2bbbeaf945ee8231a16e4a74fc2ddce46ebafdf7bee9d7868b6e",
    "architecture/agent-loop/round4/scripts/agent_loop.py": "8342fb92a2375c866840f6a49dcdbae70f7a35ea10f24b58a80086b63b04886c",
    "architecture/agent-loop/round5/README.md": "1209240831307fa7e45765ed84914f49fd1d229961945ccc6bc344fc9d6f1135",
    "architecture/agent-loop/round5/loop-profile.schema.json": "d75a5b943929f7678c8e8c8cacf2e937312bcc06caf15018de73ae9b9abac0bb",
    "architecture/agent-loop/round5/loop-trace.schema.json": "3be32ceee16c2bbbeaf945ee8231a16e4a74fc2ddce46ebafdf7bee9d7868b6e",
    "architecture/agent-loop/round5/scripts/agent_loop.py": "a7fa569761461d62538799ab96ebb24a59a0419f775c2982bffc01d8d8b7ce1e",
    "architecture/agent-loop/round6/README.md": "087e8fd1a6e496799d30f8aaf4426dccdf3d27d898d2adca20ad39da52bbaaeb",
    "architecture/agent-loop/round6/loop-profile.schema.json": "d75a5b943929f7678c8e8c8cacf2e937312bcc06caf15018de73ae9b9abac0bb",
    "architecture/agent-loop/round6/loop-trace.schema.json": "3be32ceee16c2bbbeaf945ee8231a16e4a74fc2ddce46ebafdf7bee9d7868b6e",
    "architecture/agent-loop/round6/scripts/agent_loop.py": "058b3c95bc50f81bb519f34ea7ed53b5e421bfc0b0dbdffea1e311cdc82e09b1",
    "architecture/agent-loop/round7/README.md": "fcdf0707edc32ff405ccfb511c46d93ef6030d20cff4d8ded0987e6c6c3f4ef0",
    "architecture/agent-loop/round7/loop-profile.schema.json": "d75a5b943929f7678c8e8c8cacf2e937312bcc06caf15018de73ae9b9abac0bb",
    "architecture/agent-loop/round7/loop-trace.schema.json": "3be32ceee16c2bbbeaf945ee8231a16e4a74fc2ddce46ebafdf7bee9d7868b6e",
    "architecture/agent-loop/round7/scripts/agent_loop.py": "71d4f9d08af7329094b616d5c8343c733f31bec881599f98cd130add0b74d361",
    "architecture/agent-loop/round8/README.md": "c63e554f8ca0b522ac35f6bdcc24035ea58ef467858477c0071c159c1ef01467",
    "architecture/agent-loop/round8/loop-profile.schema.json": "d75a5b943929f7678c8e8c8cacf2e937312bcc06caf15018de73ae9b9abac0bb",
    "architecture/agent-loop/round8/loop-trace.schema.json": "3be32ceee16c2bbbeaf945ee8231a16e4a74fc2ddce46ebafdf7bee9d7868b6e",
    "architecture/agent-loop/round8/scripts/agent_loop.py": "075b0e2fef646ea6b4c2bc6f0cfbdcfbde290b69c91f0a0872ca5100616a5982",
    "architecture/agent-loop/round9/README.md": "53e451f800d56870c33261b6c73be11e01f409d497103afd2e9be36e82b5cc16",
    "architecture/agent-loop/round9/loop-profile.schema.json": "d75a5b943929f7678c8e8c8cacf2e937312bcc06caf15018de73ae9b9abac0bb",
    "architecture/agent-loop/round9/loop-trace.schema.json": "3be32ceee16c2bbbeaf945ee8231a16e4a74fc2ddce46ebafdf7bee9d7868b6e",
    "architecture/agent-loop/round9/scripts/agent_loop.py": "7b3aba35d720813265a89aa4bce2ddf24329b59d082b9160815ce03f19f3a3d0",
    "architecture/agent-loop/status.json": "0410907c3f6b9ac6907fcadc7767678b01c65c24593b0d5ae84a95ca63c581ad",
    "architecture/agent-loop/vectors.json": "b48e27f1be3cc0ce575d874d6c90cfe23837ee2a9abe6331c18a72e176d85429",
    "architecture/approval-outcome/record.json": "88e83285ecb02b654c6cdece8f88e1712a935bdc8e287ba5929ed237edfdec1e",
    "architecture/approval-outcome/schema.json": "9761fea64edd60d94f2a334c71124dbac4a064094c8092cc40a05bf9368b89e6",
    "architecture/approval-outcome/vectors.json": "7be26fb683f82cdff1a306a1f3a4cdc13be1eb9eebb29578bc4ff6365523472a",
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
    "architecture/review-record/briefs.json": "5442a7dd8e2a51f9e6494530744ec553f3b37f1f0c58cdb0545f96fd1ab4c46b",
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
    "scripts/agent_loop.py": "f9a1fb1441a39efa6e566b26474f25f30106e4bbf6be4919d31ac69dddc48e68",
    "scripts/agent_loop_compaction.py": "0bc4f4c2566152c67769a25fe110dc2c60ef7ada9897a689091034d38c641887",
    "scripts/approval_outcome.py": "b9b7835b578c106e2b3470e33f60f9955fcf89d5e7a03c32716c92e0bbce6b37",
    "scripts/replay_fixtures.py": "4e3f0157c43d14e46c53cd0617cc935d8b61df3f782fb00cd5b9d8b9c74c9e3e",
    "scripts/run_manifest.py": "f2861b4c23ad51fc5b8cdd9910124b23d2c114bd61786e58d93b20f42f3f423e",
    "scripts/validate_agent_loop_compaction.py": "74f626fc206edb2dd09d798e3c3c75bb55a63656cecfc7b4a72903c56a533340",
    "scripts/validate_approval_outcome.py": "19cde90072ba7e34904a6d5bcb2ef0e0b7e9cce661a672a37885ae0f556435a7",
    "scripts/validate_replay_fixtures.py": "fa02798902d24cbe22e95ae6e4c9773c89b2d7da33ac00ec94ba92e92da18bc5",
    "tests/test_agent_loop_compaction.py": "f9d531b1deeca6a5a1b8c9617ae670f9f17340d2d4f784a8d5c387608d5ec81d",
    "tests/test_approval_outcome.py": "d6d7796ad42bdb78df9ab9bfe605df77001a0a9ae882ba6fb2a875c983025775",
    "tests/test_replay_fixtures.py": "56afb1042fa17ee6642f35d35f817b395f62f633fb92c12b566cedab3cff8e29",
})
ERRATA_LINES = MappingProxyType({
    "tests/test_ci_performance.py": ((169, 169),),
    "tests/test_credential_lifecycle.py": ((362, 362),),
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
    require(expected is not None, "MET-013 reviewed bytes are bound: " + str(path))
    require(type(raw) is bytes and digest(raw) == expected, "unreviewed MET-013 source: " + path)
    return raw


def _verified(path: str) -> bytes:
    """reviewed_bytes, checked against its era digest on every read; a path outside the era is refused before it is
    read."""
    require(type(path) is str and path in ERA_SHA256, "MET-013 reviewed bytes are bound: " + str(path))
    return _era_bytes(path, reviewed_bytes(path))


def _bound_read(path: str, expected: Any) -> bytes:
    """reviewed_bytes of a file named by an era-verified record, checked against the digest that record gives it."""
    require(type(path) is str and _sha(expected), "MET-013 bound read: " + str(path))
    _path(path)
    raw = reviewed_bytes(path)
    require(type(raw) is bytes and digest(raw) == expected, "MET-013 bound file drift: " + path)
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
           "the registry differs from the base by exactly the MET-013 packet rider, pinning the generic packet "
           "brief")


def validate_registry() -> None:
    """V4 over briefs.json and the generic packet brief."""
    check_registry(_verified(REGISTRY_PATH), {PACKET_BRIEF: _verified(PACKET_BRIEF)})


def check_packet_files(files: Any) -> None:
    """V1: the packet's files are exactly these, and each one's bytes equal the sha256 pinned for it."""
    _bound(lambda: type(files) is dict and sorted(files) == sorted(PACKET_FILES) and len(files) == len(PACKET_FILES),
           "MET-013 V1 the packet files are exactly the thirty")
    for path in PACKET_FILES:
        _bound(lambda: type(files[path]) is bytes and digest(files[path]) == ERA_SHA256[path],
               "MET-013 V1 a packet file's bytes equal its pinned digest: " + path)


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
           "MET-013 V6 the hunk-class record is closed and names this layer's authority")
    _bound(lambda: record["hunkClassVocabulary"] == list(HUNK_VOCABULARY)
           and record["hunkClassRuleSha256"] == HUNK_RULE_SHA256 == rule_sha,
           "MET-013 V6 the hunk-class record's vocabulary and rule digest are v2.5's")
    _bound(lambda: type(record["hunkClassContext"]) is dict and set(record["hunkClassContext"]) == set(HUNK_CONTEXT)
           and record["hunkClassContext"] == {"newPacket": NEW_PACKET, "prevValidator": HUNK_CONTEXT["prevValidator"],
                                              "prevTest": HUNK_CONTEXT["prevTest"], "steps": [1, 1], "countPairs": []},
           "MET-013 V6 the hunk-class record's context is this step's names")
    classes = record.get("classes") if type(record) is dict else None
    _bound(lambda: type(changed) is dict and type(classes) is dict and set(classes) == set(changed)
           and all(type(classes[p]) is list and all(type(c) is str for c in classes[p])
                   and len(classes[p]) == len(changed[p].get("reverseHunks", [])) for p in changed),
           "MET-013 V6 the hunk-class record lists one class per hunk for exactly the changed files")
    for path, entry in changed.items():
        seen = set()
        for position, (cls, hunk) in enumerate(zip(classes[path], entry.get("reverseHunks", []))):
            _bound(lambda: cls in HUNK_VOCABULARY and cls == classify(
                path, afters[path], hunk["at"], _base64(hunk["removeBase64"]), _base64(hunk["insertBase64"]), context,
                seen=seen),
                   "MET-013 V6 a recorded class re-checks by position: %s hunk %d" % (path, position))


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
           "MET-013 E3 class-other hunks fall only on the named files")
    for path, spans in ERRATA_LINES.items():
        _bound(lambda: "other" in classes[path] and type(befores[path]) is bytes,
               "MET-013 E3 the named file carries its authored hunk: " + path)
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
                       "MET-013 E3 an authored hunk lies at its named lines: %s hunk %d" % (path, position))


def validate_errata() -> None:
    """E3 over the hunk-class record (bound by its newFiles digest) and each named file's before bytes, projected back
    through this layer's own hunks from its afterSha256-bound bytes."""
    record = authority()
    side = _parsed(_bound_read(HUNK_RECORD_PATH, record["newFiles"].get(HUNK_RECORD_PATH)))
    befores = {path: _undo_this_layer(path, _bound_read(path, record["changedFiles"][path]["afterSha256"]))
               for path in ERRATA_LINES if path in record["changedFiles"]}
    check_errata(side.get("classes") if type(side) is dict else None, record["changedFiles"], befores)


MEMBERS = (                                     # CONTRACT_295 section 1's order
    MappingProxyType({"item": "HR-COMPACTION-GOV-001", "module": "agent_loop_compaction",
                      "model": "scripts/agent_loop_compaction.py", "modelName": "_met_013_agent_loop_compaction",
                      "checker": "scripts/validate_agent_loop_compaction.py", "checkerName": "_met_013_validate_agent_loop_compaction",
                      "record": "architecture/agent-loop-compaction/record.json", "vectors": "architecture/agent-loop-compaction/vectors.json",
                      "bases": ()}),
    MappingProxyType({"item": "HR-REPLAY-FIXTURES-001", "module": "replay_fixtures",
                      "model": "scripts/replay_fixtures.py", "modelName": "_met_013_replay_fixtures",
                      "checker": "scripts/validate_replay_fixtures.py", "checkerName": "_met_013_validate_replay_fixtures",
                      "record": "architecture/replay-fixtures/record.json", "vectors": "architecture/replay-fixtures/vectors.json",
                      "bases": (('run_manifest', 'scripts/run_manifest.py'),)}),
    MappingProxyType({"item": "HR-APPROVAL-OUTCOME-001", "module": "approval_outcome",
                      "model": "scripts/approval_outcome.py", "modelName": "_met_013_approval_outcome",
                      "checker": "scripts/validate_approval_outcome.py", "checkerName": "_met_013_validate_approval_outcome",
                      "record": "architecture/approval-outcome/record.json", "vectors": "architecture/approval-outcome/vectors.json",
                      "bases": ()}),
)
COMPACTION, REPLAY, APPROVAL = MEMBERS
SLOT = 295
HUNK_RECORD_PATH = "architecture/chain-checkpoint/hunk-classes/295.json"
READER_NAME = "_met_013_chain_checkpoint"
HUNK_CONTEXT = MappingProxyType({"newPacket": NEW_PACKET, "prevValidator": "scripts/validate_met_012.py",
                                 "prevTest": "tests/test_met_012.py", "steps": (1, 1), "countPairs": ()})


def _era_checker(member: Any) -> tuple:
    """A member's model and checker, each executed from its era-verified bytes (no import from this layer); the
    checker's imports of the model, and of a base model the member names, resolve to the era copies: under `scripts`
    (CONTRACT_295 4a N2) and under their bare names (ORC-295-C2-Q1 (a)), the same objects."""
    model = _era_model(member["model"], member["modelName"])
    era = {member["module"]: model}
    for name, path in member["bases"]:
        era[name] = _era_model(path, "_met_013_" + name)
    checker = _era_model(member["checker"], member["checkerName"], dict(era, scripts=types.SimpleNamespace(**era)))
    return model, checker


def check_compaction(vectors: Any, refusals: Any, replayed: Any) -> None:
    """E1 (HR-COMPACTION-GOV-001): the record passes the era checker (CG_SHAPE to CG_VECTOR) over this era's bytes; and
    the head itself replays every vector, by the vectors file's own list and independently of the checker's, through the
    era model to its expectation (the count is the parsed list's length)."""
    _bound(lambda: type(refusals) is list and refusals == [],
           "MET-013 E1 the compaction record passes its checker (CG_SHAPE to CG_VECTOR)")
    _bound(lambda: type(vectors) is dict and type(vectors["cases"]) is list and len(vectors["cases"]) > 0
           and type(replayed) is list and len(replayed) == len(vectors["cases"]) and all(ok is True for ok in replayed),
           "MET-013 E1 every compaction vector replays through its era model to its expectation")


def validate_compaction(packets: Any) -> None:
    """E1 over era bytes only: the era checker's refusals through the era reader, and each vector's replay."""
    model, checker = _era_checker(COMPACTION)
    vectors = json.loads(_verified(COMPACTION["vectors"]))
    check_compaction(vectors, checker.check(_era_read), [model.replay(case)[0] for case in vectors["cases"]])


def check_replay_fixtures(vectors: Any, refusals: Any, replayed: Any) -> None:
    """E1 (HR-REPLAY-FIXTURES-001): the record passes the era checker (RF_SHAPE to RF_VECTOR) over this era's bytes; and
    the head itself replays every vector, by the vectors file's own list and independently of the checker's, through the
    era model over the vectors' stores and MAS-RA-002's era model to its expectation (the count is the parsed list's
    length)."""
    _bound(lambda: type(refusals) is list and refusals == [],
           "MET-013 E1 the replay-fixture record passes its checker (RF_SHAPE to RF_VECTOR)")
    _bound(lambda: type(vectors) is dict and type(vectors["cases"]) is list and len(vectors["cases"]) > 0
           and type(replayed) is list and len(replayed) == len(vectors["cases"]) and all(ok is True for ok in replayed),
           "MET-013 E1 every replay-fixture vector replays through its era model to its expectation")


def validate_replay_fixtures(packets: Any) -> None:
    """E1 over era bytes only: the era checker's refusals through the era reader, and each vector's replay through the
    era model's replay_vectors (ORC-295-C2-Q2 (a)), with MAS-RA-002's run_manifest from its era bytes (a base file)."""
    model, checker = _era_checker(REPLAY)
    vectors = json.loads(_verified(REPLAY["vectors"]))
    rm = _era_model(REPLAY["bases"][0][1], "_met_013_" + REPLAY["bases"][0][0])
    check_replay_fixtures(vectors, checker.check(_era_read),
                          model.replay_vectors(vectors["cases"], vectors["stores"], rm))


def check_approval_outcome(vectors: Any, refusals: Any, replayed: Any) -> None:
    """E1 (HR-APPROVAL-OUTCOME-001): the record passes the era checker (AO_RECORD to AO_VECTOR) over this era's bytes;
    and the head itself replays every vector, by the vectors file's own list and independently of the checker's,
    through the era model to its expectation (the count is the parsed list's length)."""
    _bound(lambda: type(refusals) is list and refusals == [],
           "MET-013 E1 the approval outcome record passes its checker (AO_RECORD to AO_VECTOR)")
    _bound(lambda: type(vectors) is dict and type(vectors["cases"]) is list and len(vectors["cases"]) > 0
           and type(replayed) is list and len(replayed) == len(vectors["cases"]) and all(ok is True for ok in replayed),
           "MET-013 E1 every approval outcome vector replays through its era model to its expectation")


def validate_approval_outcome(packets: Any) -> None:
    """E1 over era bytes only: the era checker's refusals through the era reader, and each vector's replay."""
    model, checker = _era_checker(APPROVAL)
    vectors = json.loads(_verified(APPROVAL["vectors"]))
    check_approval_outcome(vectors, checker.check(_era_read), [model.replay(case)[0] for case in vectors["cases"]])


def _era_read(path: Any) -> bytes:
    """The checker's injected reader: an era file's verified bytes; any other path is refused (a ValueError), so a
    packet reference outside the era does not resolve."""
    return _verified(path)


def check_base_files(files: Any, changed: Any, new: Any) -> None:
    """E2: MAS-RA-008's and MAS-RA-002's files equal their base bytes, and this step's authority names none of them."""
    _bound(lambda: type(files) is dict and sorted(files) == sorted(BASE_SHA256)
           and all(type(files[path]) is bytes and digest(files[path]) == BASE_SHA256[path] for path in BASE_SHA256),
           "MET-013 E2 the base files equal their base bytes")
    _bound(lambda: type(changed) is dict and type(new) is dict and not set(BASE_SHA256) & (set(changed) | set(new)),
           "MET-013 E2 this step changes no base file")


def validate_base_files() -> None:
    record = authority()
    check_base_files({path: _verified(path) for path in BASE_FILES}, record["changedFiles"], record["newFiles"])


def validate_met_013(packets: dict[str, Any]) -> None:
    """Every era file first; then V1 (the packet's files), E1 per member in section 1's order (the checker and the
    model), E2 (the base files), E3 (the authored edits), V4 (the registry) and V6 (the hunk-class record); last,
    this layer's canonical hunks."""
    for path in ERA_SHA256:
        _verified(path)
    validate_packet_files()
    validate_compaction(packets)
    validate_replay_fixtures(packets)
    validate_approval_outcome(packets)
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
            == record["validatorNormalizedSha256"], "three hr contracts validator drift")
    paths = sorted((ROOT / "task-packets").glob("*.yaml"))
    old = set(record["baselinePackets"])
    require(len(paths) == 319 and {path.stem for path in paths} == old | {NEW_PACKET},
            "closed 319-packet catalog")
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
            "closed source-only three-hr-contracts packet and inherited commands")
    require(len(packet["allowedPaths"]) == len(set(packet["allowedPaths"]))
            and set(packet["allowedPaths"]) == set(record["changedFiles"])
            | set(record["newFiles"]) | {AUTHORITY_PATH, VALIDATOR_PATH,
                                         "task-packets/" + NEW_PACKET + ".yaml"},
            "unreviewed or omitted three-hr-contracts packet path")
    for path, rule in record["changedFiles"].items():
        current = regular_bytes(path)
        require(digest(current) == rule["afterSha256"]
                and digest(historical_bytes(path, current)) == rule["beforeSha256"],
                "unreviewed current source: " + path)
    for path, expected in record["newFiles"].items():
        require(digest(regular_bytes(path)) == expected, "new source drift: " + path)
    validate_met_013(packets)


if __name__ == "__main__":
    validate()
    print("Three hr contracts valid: 319 current specifications at slot 295; exact 318-packet predecessor; contract reviewed.")
