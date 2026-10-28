#!/usr/bin/env python3
"""Validate the MET-MAS-006 agent-loop contract and the exact 231-to-230 projection."""
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
    import validate_compiled_filter_programs as successor
except ImportError:
    from scripts.safe_yaml import safe_load
    from scripts import validate_compiled_filter_programs as successor


ROOT = Path(__file__).resolve().parents[1]
AUTHORITY_PATH = "architecture/agent-loop-authority.json"
AUTHORITY_SHA256 = "f30abee6325b2eb17edd2a20788c7fd99908be13a5bd115554183fe2b5dbbfaa"
VALIDATOR_PATH = "scripts/validate_agent_loop.py"
BASE_COMMIT = "82804a0cdaa3d005e7d9f7daa9c886b3bc1c6f0f"
NEW_PACKET = "MET-MAS-006"
PREVIOUS_PACKET = "MET-MAS-002"
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
            require(key not in result, "duplicate agent-loop authority member")
            result[key] = value
        return result

    def no_constant(_value: str) -> Any:
        raise ValueError("nonfinite agent-loop authority number")

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
        require(digest(raw) == AUTHORITY_SHA256, "agent loop history authority digest")
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
    }, "closed agent loop history authority")
    require(value["schemaVersion"] == "harness.planeon.ai/agent-loop-authority/v1"
            and value["authorityPacket"] == NEW_PACKET
            and value["acceptedBase"] == BASE_COMMIT
            and type(value["baselinePackets"]) is dict
            and len(value["baselinePackets"]) == 230
            and NEW_PACKET not in value["baselinePackets"]
            and type(value["changedFiles"]) is dict
            and type(value["newFiles"]) is dict
            and _sha(value["packetSha256"])
            and _sha(value["validatorNormalizedSha256"]),
            "accepted 230-packet base")
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
    # An exact 230-era byte string is already older than the successor layer.
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


# MET-MAS-006 (roadmap MAS-RA-008) publishes the agent-loop kernel and tool-gateway contract candidate
# (architecture/agent-loop/): two closed schemas (the loop profile with its budgets, retry and revision bounds, hooks,
# gates and tool manifests; the loop trace with its steps, tool calls and results, delegations and terminal status), a
# standard-library reference model and vectors, adopted after ten independent review rounds, with H10's and H11's
# harness documents and the repository schemas byte-identical. Repository bytes are read only through reviewed_bytes, so
# a later bridged successor projects its own edits away first. Every reviewed file of this era is bound by digest before
# anything is parsed, every later read is checked against that digest again, and the contract's model is executed from
# this era's reviewed bytes to replay every vector, so a later revision of the model cannot change how this layer judges
# its era. The owner's decisions, the codes, the schema identities, the loop bounds and the vector counts are restated
# here independently of the reviewed files.
CONTRACT_DIR = "architecture/agent-loop/"
MODEL = "scripts/agent_loop.py"
README_PATH = CONTRACT_DIR + "README.md"
SCHEMA_FILES = ("loop-profile.schema.json", "loop-trace.schema.json")
SCHEMA_IDS = {"loop-profile.schema.json": "planeon.internal.agent-loop-profile/v1",
              "loop-trace.schema.json": "planeon.internal.agent-loop-trace/v1"}
VECTORS_PATH = CONTRACT_DIR + "vectors.json"
VECTORS_SCHEMA = "planeon.internal.agent-loop-vectors/v1"
STATUS_PATH = CONTRACT_DIR + "status.json"
H10_PATH = "docs/harnesses/execution.orchestration.md"
H11_PATH = "docs/harnesses/execution.tool-skill-sandbox.md"
REVIEWED_SUBJECT = {"commit": "d6ad8f0801da22091f0c543879dde26817e20590", "tree": "72cb7d18f8e5ae81866458a79a0228506238736b"}
ROUNDS = ((1, 'CHANGES_REQUIRED'), (2, 'CHANGES_REQUIRED'), (3, 'CHANGES_REQUIRED'), (4, 'CHANGES_REQUIRED'), (5, 'CHANGES_REQUIRED'), (6, 'CHANGES_REQUIRED'), (7, 'CHANGES_REQUIRED'), (8, 'CHANGES_REQUIRED'), (9, 'CHANGES_REQUIRED'), (10, 'CHANGES_REQUIRED'))
LAST_ROUND = len(ROUNDS)
REVIEW_SCHEMA = "harness.planeon.ai/agent-loop-review/v1"
STATUS_KEYS = ("schemaVersion", "workItem", "status", "contract", "reviewedSubject", "adoptionEdit", "rounds", "carried",
               "acceptance", "ownerDecisions", "nonClaims", "finalRoundFixes")
ROW_KEYS = ("round", "subject", "subjectTree", "verdict", "record", "snapshot", "severities")
# An earlier round's snapshot holds these files; its vectors.json (regenerated every round) is bound by digest.
SNAPSHOT_FILES = ("README.md",) + SCHEMA_FILES + ("scripts/agent_loop.py",)
CONTRACT = {"schemas": [CONTRACT_DIR + name for name in SCHEMA_FILES], "vectors": VECTORS_PATH, "model": MODEL,
            "readme": README_PATH}
STATUS_LINE = ('Status: **CONTRACT_CANDIDATE** (under independent review).', 'Status: **ADOPTED_CONTRACT_CANDIDATE** (independent review rounds 1-10, the last final by owner decision; its findings fixed after it; rounds, review records and fixes in `status.json`).')
SEVERITIES = ("MAJOR", "MINOR", "NOTE")
NON_CLAIMS = ["An internal contract candidate: no public contract, selector, catalog, schema or runtime change; H10's and H11's harness documents and the repository schemas are byte-identical.", "No agent-loop kernel, tool gateway or broker exists; the model runs only on the vectors.", "The cited figures are the source papers' results, not platform evidence."]
ACCEPTANCE = ["MAS-RA-008-A1", "MAS-RA-008-A2", "MAS-RA-008-A3"]
DECISIONS = ["Q-MAS8-A (a)", "Q-MAS8-B (a)", "Q-MAS8-C (a)", "Q-MAS8-D (a)", "Q-231 (a)"]
# The owner's cap (via the lane monitor, verbatim, and its date): the last round is final; its findings were fixed or
# carried after it, in the fixed subject, which changes only these files.
OWNER_CAP = ('MAS-RA-008 cap: contract review round 10 is FINAL. MINORs and NOTEs found there are fixed or carried without another round; any MAJOR comes to the owner (via me) first.', '2026-10-13')
FIXED_SUBJECT = {"commit": "03709498e24f554b578ba4467c03dc15d0ae1322", "tree": "662efe420b6055856d14fb18427465079a65a8d7"}
FIXED_FILES = ('architecture/agent-loop/README.md', 'architecture/agent-loop/vectors.json', 'scripts/agent_loop.py')
FINAL_DISPOSITIONS = (('R10-1', 'FIXED'), ('R10-2', 'FIXED'), ('R10-3', 'FIXED'))
PROFILE_CODES = ('SHAPE', 'DUPLICATE_ID', 'HOOK_CONFLICT')
TRACE_CODES = ('SHAPE', 'DUPLICATE_ID', 'STEP_ORDER', 'UNKNOWN_REFERENCE', 'HOOK_CONFLICT', 'HOOK_NOT_REGISTERED', 'RECURSION_DEPTH', 'DELEGATION', 'TOTALS_MISMATCH', 'BUDGET_EXCEEDED', 'ERROR_TRACE', 'INVALID_TOOL_INPUT', 'CAPABILITY_MISMATCH', 'CAPABILITY_EXPIRED', 'CREDENTIAL_RULE', 'TRUST_LABEL', 'PROVENANCE', 'UNGATED_CONSUMPTION', 'GATE_OVERRIDDEN', 'RETRY_WITHOUT_TRACE', 'RETRY_BOUND', 'UNKNOWN_SIDE_EFFECT_RETRIED', 'REVISION_BOUND', 'HANDOFF_MISSING', 'TERMINAL_STATUS')
VECTOR_COUNTS = {"cases": 210, "profiles": 9, "texts": 4, "traces": 28, "valid": 41}
# Q-MAS8-B (a): recursion depth at most 1, no override; Q-MAS8-C (a): step retries default 1, at most 3; revision rounds a
# separate budget, default 3, at most 3.
LOOP_BOUNDS = {"recursionDepth": 1, "stepRetries": 3, "stepRetriesDefault": 1, "revisionRounds": 3,
               "revisionRoundsDefault": 3}
# H10's and H11's harness documents and every repository schema stay byte-identical (Q-MAS8-A).
FROZEN_PATHS = (H10_PATH, H11_PATH)
FROZEN_PREFIXES = ("schemas/",)
# The adopted bytes of every contract file, round copy and review record, the status record and the model; the accepted
# base's H10 and H11 harness documents.
ERA_SHA256 = MappingProxyType({
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
    "docs/harnesses/execution.orchestration.md": "d54d2937d78bc78984a524fdf7769ec10d8e13ff5d3102881d1d5372533c79e3",
    "docs/harnesses/execution.tool-skill-sandbox.md": "894ef8182df30896ef713d2e46be5601feab234703752eb8243786d419d4556b",
    "scripts/agent_loop.py": "f9a1fb1441a39efa6e566b26474f25f30106e4bbf6be4919d31ac69dddc48e68"
})


def reviewed_bytes(path: str) -> bytes:
    """This packet's reviewed bytes of path; a bridged successor projects newer bytes back first."""
    return successor.historical_bytes(path, regular_bytes(path))


def _verified(path: str) -> bytes:
    """reviewed_bytes, checked against its era digest on every read; a path outside the era is refused."""
    raw = reviewed_bytes(path)
    expected = ERA_SHA256.get(path)
    require(expected is not None and digest(raw) == expected, "MAS-RA-008 reviewed bytes are bound: " + path)
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
    """Every reviewed file of this era is bound by digest before anything is parsed or executed; H10, H11 and the
    schemas are frozen."""
    for path in _PROJECTION_RULES:
        require(path not in FROZEN_PATHS and not path.startswith(FROZEN_PREFIXES),
                "H10's and H11's harness documents and the repository schemas stay byte-identical")
    for path, expected in ERA_SHA256.items():
        require(digest(reviewed_bytes(path)) == expected, "MAS-RA-008 reviewed bytes are bound: " + path)


def validate_agent_loop_status() -> None:
    """Adopted after independent review rounds, each bound to its record; the last, final by the owner's cap, left MINOR
    and NOTE findings only, each fixed or carried after it in the fixed subject, which differs from the last round's
    subject only in the files the record names; the README's status line is the one adoption edit."""
    status = _json(STATUS_PATH)
    require(type(status) is dict and set(status) == set(STATUS_KEYS)
            and status["schemaVersion"] == "planeon.internal.agent-loop-status/v1"
            and status["workItem"] == "MAS-RA-008" and status["status"] == "ADOPTED_CONTRACT_CANDIDATE"
            and status["contract"] == CONTRACT and status["reviewedSubject"] == REVIEWED_SUBJECT
            and status["acceptance"] == ACCEPTANCE and status["ownerDecisions"] == DECISIONS
            and status["nonClaims"] == NON_CLAIMS and type(status["carried"]) is list
            and all(type(row) is dict and set(row) == {"item", "severity", "to", "action"} for row in status["carried"]),
            "adopted MAS-RA-008 status")
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
        earlier = True   # every round is snapshotted: the adopted bytes are the fixed subject's, not a round's
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
            and final["verdict"] == "CHANGES_REQUIRED" and set(final["severities"]) <= {"MINOR", "NOTE"},
            "the final round reviewed this subject and left no MAJOR finding")
    fixes = status["finalRoundFixes"]
    _bound(lambda: fixes == {"ownerDecision": OWNER_CAP[0], "ownerDecisionDate": OWNER_CAP[1],
                             "reviewedSubject": REVIEWED_SUBJECT, "fixedSubject": FIXED_SUBJECT,
                             "changedFiles": list(FIXED_FILES), "dispositions": fixes["dispositions"]}
           and [(item["finding"], item["disposition"]) for item in fixes["dispositions"]] == list(FINAL_DISPOSITIONS)
           and [item["id"] for item in previous] == [finding for finding, _ in FINAL_DISPOSITIONS]
           and all(type(item["evidence"]) is str and set(item) == {"finding", "disposition", "evidence"}
                   for item in fixes["dispositions"]),
           "the final round's findings are each fixed or carried under the owner's cap")
    carried = {finding for finding, disposition in FINAL_DISPOSITIONS if disposition == "CARRIED"}
    require({item["id"] for item in previous if item["id"] in carried} == {row["item"] for row in status["carried"]},
            "every carried finding of the final round is recorded")
    snapshot = CONTRACT_DIR + "round%d/" % LAST_ROUND
    for name in SNAPSHOT_FILES:   # the fixed subject differs from the last round's only in the files the record names
        source = CONTRACT_DIR + name if name != MODEL else MODEL
        changed = source in FIXED_FILES
        require((ERA_SHA256[snapshot + name] != ERA_SHA256[source]) == changed or source == README_PATH,
                "the fixes change only the files the record names: " + source)
    _bound(lambda: (final["digestOnly"][VECTORS_PATH] != ERA_SHA256[VECTORS_PATH]) == (VECTORS_PATH in FIXED_FILES),
           "the fixes change only the files the record names: " + VECTORS_PATH)


def _outcome(model: types.ModuleType, call: Any) -> Any:
    try:
        call()
    except model.Refused as refusal:
        return refusal.code
    return None


def validate_agent_loop_contract() -> None:
    """The contract's model from this era's bytes replays every vector; the codes, schema identities, the owner's loop
    bounds and the counts are restated here."""
    model = _era_model(MODEL, "_met_mas_006_agent_loop")
    vectors = _json(VECTORS_PATH)
    schemas = {name: _json(CONTRACT_DIR + name) for name in SCHEMA_FILES}
    _bound(lambda: vectors["schemaVersion"] == VECTORS_SCHEMA and vectors["evidenceClass"] == "DATA_CHECK_ONLY",
           "the vectors' identity")
    _bound(lambda: tuple(model.PROFILE_CODES) == PROFILE_CODES and tuple(vectors["profileCodes"]) == PROFILE_CODES
           and tuple(model.TRACE_CODES) == TRACE_CODES and tuple(vectors["traceCodes"]) == TRACE_CODES,
           "the refusal codes in their order")
    _bound(lambda: all(schemas[name]["$id"] == SCHEMA_IDS[name] for name in SCHEMA_FILES)
           and [model.PROFILE_SCHEMA, model.TRACE_SCHEMA] == [SCHEMA_IDS[name] for name in SCHEMA_FILES],
           "the two schema identities")
    profile = schemas["loop-profile.schema.json"]["properties"]
    _bound(lambda: (model.MAX_DEPTH, model.MAX_STEP_RETRIES, model.MAX_REVISION_ROUNDS)
           == (LOOP_BOUNDS["recursionDepth"], LOOP_BOUNDS["stepRetries"], LOOP_BOUNDS["revisionRounds"])
           and profile["budgets"]["properties"]["recursionDepth"]["maximum"] == LOOP_BOUNDS["recursionDepth"]
           and profile["retry"]["properties"]["stepRetries"]["maximum"] == LOOP_BOUNDS["stepRetries"]
           and profile["retry"]["properties"]["stepRetries"]["default"] == LOOP_BOUNDS["stepRetriesDefault"]
           and profile["revision"]["properties"]["rounds"]["maximum"] == LOOP_BOUNDS["revisionRounds"]
           and profile["revision"]["properties"]["rounds"]["default"] == LOOP_BOUNDS["revisionRoundsDefault"],
           "the owner's loop bounds (Q-MAS8-B, Q-MAS8-C)")
    stores = vectors["stores"]
    checks = {"profile": lambda d: model.check_profile(d),
              "trace": lambda d: model.check_trace(d, stores["profiles"], stores["traces"])}
    _bound(lambda: {"cases": len(vectors["cases"]), "valid": sum(1 for row in vectors["cases"] if row["expect"] is None),
                    "texts": len(vectors["texts"]), "profiles": len(stores["profiles"]),
                    "traces": len(stores["traces"])} == VECTOR_COUNTS
           and {row["expect"] for row in vectors["cases"] if row["kind"] == "profile"} - {None} == set(PROFILE_CODES)
           and {row["expect"] for row in vectors["cases"] if row["kind"] == "trace"} - {None} == set(TRACE_CODES),
           "the vector counts, every code covered")
    for row in vectors["cases"]:
        facts: list = []
        got = _outcome(model, lambda: facts.append(checks[row["kind"]](row["document"])))
        _bound(lambda: got == row["expect"] and (not facts or "facts" not in row
               or {k: facts[0][k] for k in row["facts"]} == row["facts"]), "case " + str(row.get("id")))
    for row in vectors["texts"]:
        _bound(lambda: _outcome(model, lambda: checks[row["kind"]](model.parse(row["text"]))) == row["expect"],
               "text " + str(row.get("id")))


def validate_agent_loop() -> None:
    """Every reviewed byte and the adoption record first; then the contract from this era."""
    validate_era_bytes()
    validate_agent_loop_status()
    validate_agent_loop_contract()


def validate() -> None:
    record = authority()
    validator_raw = successor.historical_bytes(VALIDATOR_PATH, regular_bytes(VALIDATOR_PATH))
    literal = b'AUTHORITY_SHA256 = "' + AUTHORITY_SHA256.encode("ascii") + b'"'
    placeholder = b'AUTHORITY_SHA256 = "TO_BE_PINNED_AFTER_SOURCE_FREEZE"'
    require(validator_raw.count(literal) == 1
            and digest(validator_raw.replace(literal, placeholder))
            == record["validatorNormalizedSha256"], "agent loop validator drift")
    paths = sorted((ROOT / "task-packets").glob("*.yaml"))
    old = set(record["baselinePackets"])
    require(len(paths) == 269
            and {path.stem for path in paths} == old | {NEW_PACKET, successor.NEW_PACKET, successor.successor.NEW_PACKET, successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.NEW_PACKET},
            "closed 269-packet catalog retaining the 231-packet checkpoint")
    packets = {}
    for path in paths:
        if path.stem in (successor.NEW_PACKET, successor.successor.NEW_PACKET, successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.NEW_PACKET):
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
            "closed source-only agent-loop packet and inherited commands")
    require(len(packet["allowedPaths"]) == len(set(packet["allowedPaths"]))
            and set(packet["allowedPaths"]) == set(record["changedFiles"])
            | set(record["newFiles"]) | {AUTHORITY_PATH, VALIDATOR_PATH,
                                         "task-packets/" + NEW_PACKET + ".yaml"},
            "unreviewed or omitted agent-loop packet path")
    for path, rule in record["changedFiles"].items():
        current = successor.historical_bytes(path, regular_bytes(path))
        require(digest(current) == rule["afterSha256"]
                and digest(historical_bytes(path, current)) == rule["beforeSha256"],
                "unreviewed current source: " + path)
    for path, expected in record["newFiles"].items():
        require(digest(successor.historical_bytes(path, regular_bytes(path))) == expected,
                "new source drift: " + path)
    validate_agent_loop()


if __name__ == "__main__":
    validate()
    print("Agent loop valid: 269 current specifications; 231-packet checkpoint and exact 230-packet predecessor; contract reviewed.")
