#!/usr/bin/env python3
"""Validate the MET-GOV-001 evolution surface record v1 (who may propose, generate, test, approve and activate each artifact class; gate material) and the exact 257-to-256 projection."""
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
    import validate_policy_observation_digests as successor
except ImportError:
    from scripts.safe_yaml import safe_load
    from scripts import validate_policy_observation_digests as successor


ROOT = Path(__file__).resolve().parents[1]
AUTHORITY_PATH = "architecture/evolution-surface-authority.json"
AUTHORITY_SHA256 = "978c57e3715a2edd7cf6d3ffd7df38430e452739bfc4b6d72e5424cba1d8ef4c"
VALIDATOR_PATH = "scripts/validate_evolution_surface.py"
BASE_COMMIT = "26a8affbc289132a80c3c3b1c1b41a19ce2a358b"
NEW_PACKET = "MET-GOV-001"
PREVIOUS_PACKET = "MET-ENFORCE-040"
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
            require(key not in result, "duplicate evolution-surface authority member")
            result[key] = value
        return result

    def no_constant(_value: str) -> Any:
        raise ValueError("nonfinite evolution-surface authority number")

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
        require(digest(raw) == AUTHORITY_SHA256, "evolution surface history authority digest")
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
    }, "closed evolution surface history authority")
    require(value["schemaVersion"] == "harness.planeon.ai/evolution-surface-authority/v1"
            and value["authorityPacket"] == NEW_PACKET
            and value["acceptedBase"] == BASE_COMMIT
            and type(value["baselinePackets"]) is dict
            and len(value["baselinePackets"]) == 256
            and NEW_PACKET not in value["baselinePackets"]
            and type(value["changedFiles"]) is dict
            and type(value["newFiles"]) is dict
            and _sha(value["packetSha256"])
            and _sha(value["validatorNormalizedSha256"]),
            "accepted 256-packet base")
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
    # An exact 256-era byte string is already older than the successor layer.
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


# MET-GOV-001 (roadmap EVOLUTION-SURFACE-001; owner decisions Q-ES-1..7, "Accept, but gate it (Recommended)", with Q-ES-6
# (b), Q-ES-CAP (a), Q-ES-D1 (a) to Q-ES-D3 (a), Q-GOV-CAP and the owner's NOTE fold, 2026-10-21; packet id MON-ES-ID)
# adopts the evolution surface record v1: which roles may propose, generate, test, approve and activate each artifact
# class, at the product and the programme level, with its schema, its standard-library reference model and its
# replayable vectors. Five independent contract review rounds ran (the fifth PASS_FOR_ADOPTION), and the owner folded
# round 5's four NOTEs (G1R5-1 to G1R5-4) with no further round. The record is gate material (Q-ES-6 (b)): the owner
# approves its merge per PR, bound to the head. Repository bytes and modes are read only through reviewed_bytes and
# reviewed_mode, and the contract directory's listing only through reviewed_tree, so a later bridged successor projects
# its own edits away first; a path outside this era is refused before it is read, and every era file is bound by digest
# on every read. Each refusal is a pure check over the values read, so every one has a failing case on plain data.
# Checked here: the freeze (this packet changes nothing under architecture/ and not the model, and under architecture/ it
# adds only the contract's directory besides its own authority, which validate() pins); the files this packet adds (new, each once; the contract directory closed with
# its five round snapshots; mode 100644; no absolute local path); the adoption (the contract files are the adopted bytes;
# the status record's closed shape and values; the owner's NOTE fold bound by digest, with round 5's snapshot as its
# reviewed side; the README's one adoption edit; the five review rounds bound to their published records by digest,
# each record's subject, verdict and findings equal to its round's; round 5's four NOTEs carried to the fold); and the
# record, its schema and its vectors naming the same contract. This layer reads no model: the packet's own tests replay
# the model and its vectors on every verify. Last, this layer's own inverse hunks are the canonical byte-minimal ones,
# recomputed from its era's bytes (MET-PERF-040's carried rule).
CONTRACT_DIR = "architecture/evolution-surface"
RECORD_PATH = CONTRACT_DIR + "/evolution-surface.json"
SCHEMA_PATH = CONTRACT_DIR + "/evolution-surface.schema.json"
VECTORS_PATH = CONTRACT_DIR + "/vectors.json"
README_PATH = CONTRACT_DIR + "/README.md"
BRIEF_PATH = CONTRACT_DIR + "/REVIEW_BRIEF.md"
MODEL_PATH = "scripts/evolution_surface.py"
STATUS_PATH = CONTRACT_DIR + "/status.json"
RECORDS = tuple(CONTRACT_DIR + "/review-round%d.json" % number for number in range(1, 6))
# Each round's subject snapshot (vectors bound by digest only, as MET-MAS-004 did) and its directories.
SNAPSHOT_NAMES = ("README.md", "REVIEW_BRIEF.md", "evolution-surface.json", "evolution-surface.schema.json",
                  "scripts/evolution_surface.py")
SNAPSHOTS = tuple(CONTRACT_DIR + "/round%d/%s" % (number, name) for number in range(1, 6) for name in SNAPSHOT_NAMES)
SNAPSHOT_DIRS = (tuple(CONTRACT_DIR + "/round%d" % number for number in range(1, 6))
                 + tuple(CONTRACT_DIR + "/round%d/scripts" % number for number in range(1, 6)))
# The adopted subject, the status record, the five review records and the round snapshots.
SUBJECT = (RECORD_PATH, SCHEMA_PATH, VECTORS_PATH, README_PATH, BRIEF_PATH, MODEL_PATH)
RECORD_FILES = (STATUS_PATH,) + RECORDS + SNAPSHOTS
NEW_FILES = SUBJECT + RECORD_FILES
DIRECTORY_FILES = SUBJECT[:5] + RECORD_FILES
ADOPTED_SHA256 = MappingProxyType({
    "architecture/evolution-surface/evolution-surface.json": "44dd288ccf888506d432b8f4b9ba72ab635e39185e9f07074a1606a97d223040",
    "architecture/evolution-surface/evolution-surface.schema.json": "a777ee09e6ce17f137d7f158b71f05f3f6eff205f7f627bb9de917cec82f5ada",
    "architecture/evolution-surface/vectors.json": "49c484302705217493411e7a6c7f8d352e0aaae6814be1a0f7031524e98ab512",
    "architecture/evolution-surface/README.md": "6705a308b3748a201e8cee7448740b5ef4099c3b2d5c0c1769bb95c4175934ed",
    "architecture/evolution-surface/REVIEW_BRIEF.md": "4b89f81d3355aeeea26e935e93619001e38771689addc845ffe9dec10676ae61",
    "scripts/evolution_surface.py": "f38fa6d00ec5fbbbcab8ff01d0e56824e805327b872dc1e23e579e522a681fd9",
})
# The status record written at adoption: its closed key sets and its values, restated.
STATUS_SCHEMA = "planeon.internal.evolution-surface-status/v1"
STATUS_KEYS = ("schemaVersion", "workItem", "packet", "status", "contract", "reviewedSubject", "noteFold",
               "adoptionEdit", "rounds", "carried", "ownerDecisions", "nonClaims")
CONTRACT = {"record": RECORD_PATH, "schema": SCHEMA_PATH, "vectors": VECTORS_PATH, "model": MODEL_PATH,
            "readme": README_PATH}
# Round 5's subject (PASS_FOR_ADOPTION) and the owner's fold of its four NOTEs (MON-GOV-R5-KEEP; "Fold small fixes, no
# round (Recommended)"): each file the fold changed, as (round 5's digest, the fold's digest).
REVIEWED_SUBJECT = {"commit": "72901245456b93012316041d085aaa4377d2eb1d", "tree": "add5ba4be50f711b6fcb7574a4ebe09e335079b0"}
FOLD_KEYS = ("commit", "tree", "decision", "ruling", "items", "files", "check")
FOLD = {"commit": "82186be408e0fbe165f8b86531059197c8e2da7c", "tree": "6cc2acd5efbeba7677d78a08560f1741896b24c7",
        "decision": "Fold small fixes, no round (Recommended)", "ruling": "MON-GOV-R5-KEEP",
        "items": ["G1R5-1", "G1R5-2", "G1R5-3", "G1R5-4"],
        "check": "the packet review after the chain mechanics checks the fold first"}
FOLD_FILE_KEYS = ("reviewedSha256", "foldSha256")
FOLD_FILES = MappingProxyType({
    "architecture/evolution-surface/README.md": ("289db88bbb52cb4bea183123ab156594b96940dac2499a16aadcb24a3ab3c4a4",
        "7fb87670c95433a47c1a022dc41c91f6e4cda63b58f0d81522f7261ee47d67e4"),
    "architecture/evolution-surface/vectors.json": ("f263222665824613a6ccee55601cf8d38053ae82cafea211141ecd3b5072dd58",
        "49c484302705217493411e7a6c7f8d352e0aaae6814be1a0f7031524e98ab512"),
    "scripts/evolution_surface.py": ("514f73ba94493ee27c797f079b51a3b1d79587fe881ab9a843a0e9e9072ca283",
        "f38fa6d00ec5fbbbcab8ff01d0e56824e805327b872dc1e23e579e522a681fd9"),
    "tests/test_evolution_surface.py": ("93fc61bc5db5761622891edbd83f8036f8ea41dbbc01022b256f4a004c00a672",
        "aaf600ef3d7fe73dced1276701c0f6ae06c59654c57093c60e38038864e3eb18"),
})
EDIT_KEYS = ("path", "replaced", "with", "foldSha256", "adoptedSha256")
STATUS_BEFORE = "Status: **CONTRACT_CANDIDATE** (internal, DATA_CHECK_ONLY; independent contract review pending)."
STATUS_AFTER = ("Status: **ADOPTED_CONTRACT_CANDIDATE** (internal, DATA_CHECK_ONLY; independent contract review round 5:\n"
                "PASS_FOR_ADOPTION, with the owner's NOTE fold; rounds and review records in `status.json`).")
OWNER_DECISIONS = ("Q-ES-1..7 (owner, 2026-10-21): \"Accept, but gate it (Recommended)\"; Q-ES-6 (b): gate material",
 "Q-ES-CAP (owner, 2026-10-21): \"(a) Build rev 4 (Recommended)\"",
 "Q-ES-D1 (owner, 2026-10-21): \"(a) Add all 12 + own (Recommended)\"",
 "Q-ES-D2 (owner, 2026-10-21): \"(a) Verifier + runner docs (Recommended)\"",
 "Q-ES-D3 (owner, 2026-10-21): \"(a) Monitor, head-bound (Recommended)\"",
 "MON-ES-ID (monitor, 2026-10-21): packet id MET-GOV-001",
 "Q-GOV-CAP (owner, 2026-10-21): \"One delta r5, then cap (Recommended)\"",
 "MON-GOV-R5-KEEP and the owner's NOTE fold (2026-10-21): \"Fold small fixes, no round (Recommended)\"")
NON_CLAIMS = ("An internal contract candidate: nothing runs and nothing is enforced; MAS-RA-005's admission gate and R09 consume the record later, and until then the lane monitor applies the programme level by hand.",
 "No harness document, repository schema or earlier contract changes.",
 "Roles and paths are declared data; the record does not authenticate who acts.")
# (round, subject commit, subject tree, verdict, the vectors' digest at that round, the finding ids) in order.
ROUND_KEYS = ("round", "subject", "subjectTree", "verdict", "record", "recordSha256", "severities", "snapshot",
              "digestOnly")
ROUNDS = ((1, "a47b58ee3f8b12d57fc2bd813df11828d30041b2", "b444006b37f27d0d539b9c01b2b978e564ca51bf", "CHANGES_REQUIRED",
  "c928432e1bf4be35f1792b5b672d55112cbf5bd59937f970ee973d73a956cd37",
  ("G1R1-1",
 "G1R1-2",
 "G1R1-3",
 "G1R1-4",
 "G1R1-5",
 "G1R1-6",
 "G1R1-7",
 "G1R1-8",
 "G1R1-9",
 "G1R1-10")),
 (2, "60b37471b1dfee55a6a7484e76da864c102d86b8", "eda9e8c2263a995f727daa9c9ca4c80a565c097e", "CHANGES_REQUIRED",
  "d506be12e942c4a6fd558fcaf0868925dc3b8affe0fc328024ecc41acc05316e",
  ("G1R2-1",
 "G1R2-2",
 "G1R2-3",
 "G1R2-4")),
 (3, "1d517f1e26b386b552cd394e482932b1302372d8", "2580d9befd1cd71d6df791b7902af331f5d2f663", "CHANGES_REQUIRED",
  "430f89cd3c28abe6e0fc9e514c4876452a5cc93a7f8087e6b3ec0ef8f401766b",
  ("G1R3-1",
 "G1R3-2",
 "G1R3-3")),
 (4, "97fa3e8b81184f08fba3d30495450a9fcde87b2d", "de64d05274bad094fb64ef24cc54643dc612469d", "CHANGES_REQUIRED",
  "430f89cd3c28abe6e0fc9e514c4876452a5cc93a7f8087e6b3ec0ef8f401766b",
  ("G1R4-1",
 "G1R4-2")),
 (5, "72901245456b93012316041d085aaa4377d2eb1d", "add5ba4be50f711b6fcb7574a4ebe09e335079b0", "PASS_FOR_ADOPTION",
  "f263222665824613a6ccee55601cf8d38053ae82cafea211141ecd3b5072dd58",
  ("G1R5-1",
 "G1R5-2",
 "G1R5-3",
 "G1R5-4")))
RECORD_SCHEMA = "harness.planeon.ai/governance-contract-review/v1"
RECORD_KEYS = MappingProxyType({1: ('schemaVersion', 'kind', 'round', 'reviewDate', 'subjectCommit', 'subjectTree', 'briefSha256', 'rulesSha256', 'wrapperSha256', 'reviewer', 'verdict', 'bindingRules', 'findings', 'checked'),
                                2: ('schemaVersion', 'kind', 'round', 'reviewDate', 'subjectCommit', 'subjectTree', 'briefSha256', 'rulesSha256', 'wrapperSha256', 'reviewer', 'verdict', 'bindingRules', 'dispositions', 'findings', 'checked'), 3: ('schemaVersion', 'kind', 'round', 'reviewDate', 'subjectCommit', 'subjectTree', 'briefSha256', 'rulesSha256', 'wrapperSha256', 'reviewer', 'verdict', 'bindingRules', 'dispositions', 'findings', 'checked'), 4: ('schemaVersion', 'kind', 'round', 'reviewDate', 'subjectCommit', 'subjectTree', 'briefSha256', 'rulesSha256', 'wrapperSha256', 'reviewer', 'verdict', 'bindingRules', 'dispositions', 'findings', 'checked'), 5: ('schemaVersion', 'kind', 'round', 'reviewDate', 'subjectCommit', 'subjectTree', 'briefSha256', 'rulesSha256', 'wrapperSha256', 'reviewer', 'verdict', 'bindingRules', 'dispositions', 'findings', 'checked')})
CARRIED_KEYS = ("item", "severity", "to", "action")
CARRIED_TO = "the owner's NOTE fold (82186be4)"
SURFACE_SCHEMA = "planeon.internal.evolution-surface/v1"
VECTORS_SCHEMA = "planeon.internal.evolution-surface-vectors/v1"
# Every file this era's check reads, with its digest: the files this packet adds under the contract directory and the
# model.
ERA_SHA256 = MappingProxyType({
    "architecture/evolution-surface/evolution-surface.json": "44dd288ccf888506d432b8f4b9ba72ab635e39185e9f07074a1606a97d223040",
    "architecture/evolution-surface/evolution-surface.schema.json": "a777ee09e6ce17f137d7f158b71f05f3f6eff205f7f627bb9de917cec82f5ada",
    "architecture/evolution-surface/vectors.json": "49c484302705217493411e7a6c7f8d352e0aaae6814be1a0f7031524e98ab512",
    "architecture/evolution-surface/README.md": "6705a308b3748a201e8cee7448740b5ef4099c3b2d5c0c1769bb95c4175934ed",
    "architecture/evolution-surface/REVIEW_BRIEF.md": "4b89f81d3355aeeea26e935e93619001e38771689addc845ffe9dec10676ae61",
    "scripts/evolution_surface.py": "f38fa6d00ec5fbbbcab8ff01d0e56824e805327b872dc1e23e579e522a681fd9",
    "architecture/evolution-surface/status.json": "bb77c3449a0bd577ce54b8e79f5705d784a1590681142a5a19fe5ee3c430f125",
    "architecture/evolution-surface/review-round1.json": "ee803c3a647092075625ae8520cc0c820e17acd6f42b25695335a8fd58f65244",
    "architecture/evolution-surface/review-round2.json": "069d00325a589711b854d81f760308534ad65c4a456164f6b0c5e5e54e59b03b",
    "architecture/evolution-surface/review-round3.json": "df2a8761668d6f5500ec4c0cea89c6a26efa2e579666a96c2625f46ba11304e0",
    "architecture/evolution-surface/review-round4.json": "193c6fb6dcec8134d1d89369c996c3d62ab7f36643048277168d3a3b3c2c7d5b",
    "architecture/evolution-surface/review-round5.json": "dcd467bad420fd3eb5d29fa518a539ca4ac6c5350bd5e5b2f7610c5c9a6cb16c",
    "architecture/evolution-surface/round1/README.md": "be0eec942b95207999ee8cc0cf338bfc055363a617de853e2b4a68addf2b5982",
    "architecture/evolution-surface/round1/REVIEW_BRIEF.md": "4b89f81d3355aeeea26e935e93619001e38771689addc845ffe9dec10676ae61",
    "architecture/evolution-surface/round1/evolution-surface.json": "44dd288ccf888506d432b8f4b9ba72ab635e39185e9f07074a1606a97d223040",
    "architecture/evolution-surface/round1/evolution-surface.schema.json": "a777ee09e6ce17f137d7f158b71f05f3f6eff205f7f627bb9de917cec82f5ada",
    "architecture/evolution-surface/round1/scripts/evolution_surface.py": "c7b860aaed77a0d48c35ffb61d8c98a3e87a87cd74a536dc4edcecd95cb16ec1",
    "architecture/evolution-surface/round2/README.md": "e3ab42ec1c51006442206b370992ac9fde5e274577ac20641b548fe04b05af7c",
    "architecture/evolution-surface/round2/REVIEW_BRIEF.md": "4b89f81d3355aeeea26e935e93619001e38771689addc845ffe9dec10676ae61",
    "architecture/evolution-surface/round2/evolution-surface.json": "44dd288ccf888506d432b8f4b9ba72ab635e39185e9f07074a1606a97d223040",
    "architecture/evolution-surface/round2/evolution-surface.schema.json": "a777ee09e6ce17f137d7f158b71f05f3f6eff205f7f627bb9de917cec82f5ada",
    "architecture/evolution-surface/round2/scripts/evolution_surface.py": "c26b01df4f7603ae4b013cfb7bb7e7d81ab62c3274873bea049990c459f2993b",
    "architecture/evolution-surface/round3/README.md": "c9396f215e90ab4df3bc59fea0dcde7b00edbef29e4f46598302b5b154070bbf",
    "architecture/evolution-surface/round3/REVIEW_BRIEF.md": "4b89f81d3355aeeea26e935e93619001e38771689addc845ffe9dec10676ae61",
    "architecture/evolution-surface/round3/evolution-surface.json": "44dd288ccf888506d432b8f4b9ba72ab635e39185e9f07074a1606a97d223040",
    "architecture/evolution-surface/round3/evolution-surface.schema.json": "a777ee09e6ce17f137d7f158b71f05f3f6eff205f7f627bb9de917cec82f5ada",
    "architecture/evolution-surface/round3/scripts/evolution_surface.py": "ab378a381a9c374cb2ac14ef1535ca29e2bb9de153c22db245afe8685b1001c1",
    "architecture/evolution-surface/round4/README.md": "d4b51fb8aa8961bc4f45c82472f4ade96f638b6cd98b226628f9c98c2e5335b0",
    "architecture/evolution-surface/round4/REVIEW_BRIEF.md": "4b89f81d3355aeeea26e935e93619001e38771689addc845ffe9dec10676ae61",
    "architecture/evolution-surface/round4/evolution-surface.json": "44dd288ccf888506d432b8f4b9ba72ab635e39185e9f07074a1606a97d223040",
    "architecture/evolution-surface/round4/evolution-surface.schema.json": "a777ee09e6ce17f137d7f158b71f05f3f6eff205f7f627bb9de917cec82f5ada",
    "architecture/evolution-surface/round4/scripts/evolution_surface.py": "1229dc433ecc5ebc619e5b508249e13590739be875da0ce461f43c054bb3eaba",
    "architecture/evolution-surface/round5/README.md": "289db88bbb52cb4bea183123ab156594b96940dac2499a16aadcb24a3ab3c4a4",
    "architecture/evolution-surface/round5/REVIEW_BRIEF.md": "4b89f81d3355aeeea26e935e93619001e38771689addc845ffe9dec10676ae61",
    "architecture/evolution-surface/round5/evolution-surface.json": "44dd288ccf888506d432b8f4b9ba72ab635e39185e9f07074a1606a97d223040",
    "architecture/evolution-surface/round5/evolution-surface.schema.json": "a777ee09e6ce17f137d7f158b71f05f3f6eff205f7f627bb9de917cec82f5ada",
    "architecture/evolution-surface/round5/scripts/evolution_surface.py": "514f73ba94493ee27c797f079b51a3b1d79587fe881ab9a843a0e9e9072ca283",
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
    require(expected is not None, "MET-GOV-001 reviewed bytes are bound: " + str(path))
    require(type(raw) is bytes and digest(raw) == expected, "unreviewed EVOLUTION-SURFACE-001 source: " + path)
    return raw


def _verified(path: str) -> bytes:
    """reviewed_bytes, checked against its era digest on every read; a path outside the era is refused before it is
    read."""
    require(type(path) is str and path in ERA_SHA256, "MET-GOV-001 reviewed bytes are bound: " + str(path))
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


def check_freeze(changed: Any, added: Any) -> None:
    """This packet changes nothing under architecture/ and not the model, and under architecture/ it adds only the
    contract's directory (its own authority is not among the authority's newFiles; validate() pins it)."""
    for path in list(changed):
        require(type(path) is str and not path.startswith("architecture/") and path != MODEL_PATH,
                "no earlier contract, record or model changes, and under architecture/ only the contract's directory "
                "is added: " + str(path))
    for path in list(added):
        require(type(path) is str and (not path.startswith("architecture/") or path.startswith(CONTRACT_DIR + "/")),
                "no earlier contract, record or model changes, and under architecture/ only the contract's directory "
                "is added: " + str(path))


def check_new_files(added: Any, changed: Any) -> None:
    """The packet adds the contract's files, its records and round snapshots and the model as new files, each once."""
    _bound(lambda: len(set(NEW_FILES)) == len(NEW_FILES) and not set(NEW_FILES) & set(changed)
           and {path for path in added if path.startswith(CONTRACT_DIR + "/") or path == MODEL_PATH} == set(NEW_FILES),
           "the contract's files, records and round snapshots are new in this packet, each once")


def check_contract_tree(mode: Any, tree: Any) -> None:
    """The contract directory is a directory (not a link) holding exactly its files and its five round snapshots, each
    file a regular file of git mode 100644 and each snapshot folder a directory."""
    require(type(mode) is int and stat.S_ISDIR(mode), "the contract directory is a directory, not a link")
    _bound(lambda: type(tree) is dict and sorted(tree) == sorted(DIRECTORY_FILES + SNAPSHOT_DIRS)
           and all(_git_mode(tree[path]) == "100644" for path in DIRECTORY_FILES)
           and all(stat.S_ISDIR(tree[path]) for path in SNAPSHOT_DIRS),
           "the contract directory holds exactly its files and five round snapshots, each file of mode 100644")


def check_added_file(path: str, mode: Any, raw: Any) -> None:
    """A file this packet adds is a regular file of git mode 100644 (not a link, not executable) and holds no absolute
    local path."""
    require(type(mode) is int and _git_mode(mode) == "100644",
            "a file this packet adds is a regular file of git mode 100644: " + path)
    require(type(raw) is bytes and not _local_path(raw), "no absolute local path in a file this packet adds: " + path)


def validate_files() -> None:
    """The freeze, the files this packet adds and the contract directory, from this era's authority, modes and
    listing."""
    record = authority()
    check_freeze(list(_PROJECTION_RULES), list(record["newFiles"]))
    check_new_files(list(record["newFiles"]), list(_PROJECTION_RULES))
    check_contract_tree(reviewed_mode(CONTRACT_DIR), reviewed_tree(CONTRACT_DIR))
    for path in NEW_FILES:
        check_added_file(path, reviewed_mode(path), _verified(path))


def check_status(status: Any) -> None:
    """The status record's closed shape and values: EVOLUTION-SURFACE-001 adopted as MET-GOV-001, its contract files,
    round 5's subject, the owner decisions and the non-claims as adopted."""
    _bound(lambda: type(status) is dict and tuple(status) == STATUS_KEYS and status["schemaVersion"] == STATUS_SCHEMA
           and status["workItem"] == "EVOLUTION-SURFACE-001" and status["packet"] == NEW_PACKET
           and status["status"] == "ADOPTED_CONTRACT_CANDIDATE" and tuple(status["contract"]) == tuple(CONTRACT)
           and status["contract"] == CONTRACT and tuple(status["reviewedSubject"]) == tuple(REVIEWED_SUBJECT)
           and status["reviewedSubject"] == REVIEWED_SUBJECT and status["ownerDecisions"] == list(OWNER_DECISIONS)
           and status["nonClaims"] == list(NON_CLAIMS), "adopted evolution surface status")


def check_subject(path: str, raw: Any) -> None:
    require(path in ADOPTED_SHA256 and type(raw) is bytes and digest(raw) == ADOPTED_SHA256[path],
            "the contract files are the adopted bytes: " + path)


def check_fold(status: Any, readme: Any, reviewed: Any) -> None:
    """The owner's NOTE fold is bound by digest: its commit, tree, decision, ruling and items, and each file it changed
    as (round 5's digest, the fold's digest), round 5's side equal to round 5's snapshot; the README's status line is
    the one adoption edit on the fold's README."""
    _bound(lambda: tuple(status["noteFold"]) == FOLD_KEYS
           and all(status["noteFold"][key] == value for key, value in FOLD.items())
           and tuple(status["noteFold"]["files"]) == tuple(FOLD_FILES)
           and all(tuple(status["noteFold"]["files"][path]) == FOLD_FILE_KEYS
                   and (status["noteFold"]["files"][path]["reviewedSha256"],
                        status["noteFold"]["files"][path]["foldSha256"]) == pair
                   for path, pair in FOLD_FILES.items())
           and type(reviewed) is dict and sorted(reviewed) == [README_PATH, MODEL_PATH]
           and all(type(raw) is bytes and digest(raw) == FOLD_FILES[path][0] for path, raw in reviewed.items()),
           "the owner's NOTE fold is bound by digest: G1R5-1 to G1R5-4 on round 5's subject")
    _bound(lambda: tuple(status["adoptionEdit"]) == EDIT_KEYS and status["adoptionEdit"]["path"] == README_PATH
           and status["adoptionEdit"]["replaced"] == STATUS_BEFORE and status["adoptionEdit"]["with"] == STATUS_AFTER
           and status["adoptionEdit"]["foldSha256"] == FOLD_FILES[README_PATH][1] and type(readme) is bytes
           and status["adoptionEdit"]["adoptedSha256"] == digest(readme)
           and readme.count(STATUS_AFTER.encode("utf-8")) == 1 and readme.count(STATUS_BEFORE.encode("utf-8")) == 0
           and digest(readme.replace(STATUS_AFTER.encode("utf-8"), STATUS_BEFORE.encode("utf-8")))
           == FOLD_FILES[README_PATH][1],
           "the README's status line is the one adoption edit")


def check_rounds(rounds: Any) -> None:
    """Five rounds in order; the first four required changes, the fifth passed with NOTEs only on round 5's subject."""
    _bound(lambda: type(rounds) is list and [row["round"] for row in rounds] == [row[0] for row in ROUNDS]
           and [row["verdict"] for row in rounds] == [row[3] for row in ROUNDS]
           and rounds[-1]["verdict"] == "PASS_FOR_ADOPTION" and rounds[-1]["subject"] == REVIEWED_SUBJECT["commit"]
           and rounds[-1]["severities"] == ["NOTE"],
           "five review rounds in order; the fifth passed with NOTEs only on round 5's subject")


def check_round(number: int, row: Any, record: Any, raw: Any) -> None:
    """Review round `number` is bound to its published record by digest; the record's subject, verdict, round and
    findings are the round's, and the row names its snapshot and its vectors' digest."""
    _, commit, tree, verdict, vectors, ids = ROUNDS[number - 1]
    _bound(lambda: type(row) is dict and tuple(row) == ROUND_KEYS and row["round"] == number
           and row["subject"] == commit and row["subjectTree"] == tree and row["verdict"] == verdict
           and row["record"] == RECORDS[number - 1] and type(raw) is bytes and digest(raw) == row["recordSha256"]
           and row["snapshot"] == CONTRACT_DIR + "/round%d/" % number and row["digestOnly"] == {VECTORS_PATH: vectors}
           and type(record) is dict and tuple(record) == RECORD_KEYS[number]
           and record["schemaVersion"] == RECORD_SCHEMA and record["round"] == number
           and record["subjectCommit"] == commit and record["subjectTree"] == tree and record["verdict"] == verdict
           and tuple(finding["id"] for finding in record["findings"]) == ids
           and row["severities"] == sorted({finding["severity"] for finding in record["findings"]}),
           "review round %d is bound to its record and its subject" % number)


def check_carried(status: Any, last: Any) -> None:
    """Round 5's four NOTEs are carried to the owner's fold, each with its required change as the action."""
    _bound(lambda: type(status["carried"]) is list and all(tuple(row) == CARRIED_KEYS for row in status["carried"])
           and [(row["item"], row["severity"], row["to"], row["action"]) for row in status["carried"]]
           == [(finding["id"], finding["severity"], CARRIED_TO, finding["requiredChange"]) for finding in last["findings"]]
           and [row["item"] for row in status["carried"]] == FOLD["items"],
           "round 5's four NOTEs are carried to the owner's fold, each with its action")


def validate_adoption() -> None:
    """The status record, the adopted files, the NOTE fold and the adoption edit, the five rounds with their published
    records, and the carried NOTEs."""
    status = _json(STATUS_PATH)
    check_status(status)
    for path in SUBJECT:
        check_subject(path, _verified(path))
    check_fold(status, _verified(README_PATH),
               {README_PATH: _verified(CONTRACT_DIR + "/round5/README.md"),
                MODEL_PATH: _verified(CONTRACT_DIR + "/round5/scripts/evolution_surface.py")})
    check_rounds(status["rounds"])
    records = []
    for number, row in enumerate(status["rounds"], 1):
        raw = _verified(RECORDS[number - 1])
        records.append(parse(raw))
        check_round(number, row, records[-1], raw)
    check_carried(status, records[-1])


def check_documents(record: Any, schema: Any, vectors: Any) -> None:
    """The record, its schema and its vectors name the same contract."""
    _bound(lambda: type(record) is dict and record["schemaVersion"] == SURFACE_SCHEMA and type(schema) is dict
           and schema["$id"] == SURFACE_SCHEMA and type(vectors) is dict and vectors["schemaVersion"] == VECTORS_SCHEMA,
           "the record, its schema and its vectors name the same contract")


def validate_contract() -> None:
    check_documents(_json(RECORD_PATH), _json(SCHEMA_PATH), _json(VECTORS_PATH))


def validate_evolution_surface() -> None:
    """Every reviewed byte first; then the freeze and the files this packet adds, the adoption and the contract's
    documents; last, this layer's canonical hunks."""
    for path in ERA_SHA256:
        _verified(path)
    validate_files()
    validate_adoption()
    validate_contract()
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
            == record["validatorNormalizedSha256"], "evolution surface validator drift")
    paths = sorted((ROOT / "task-packets").glob("*.yaml"))
    old = set(record["baselinePackets"])
    require(len(paths) == 262
            and {path.stem for path in paths} == old | {NEW_PACKET, successor.NEW_PACKET, successor.successor.NEW_PACKET, successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.NEW_PACKET},
            "closed 262-packet catalog retaining the 257-packet checkpoint")
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
            "closed source-only evolution-surface packet and inherited commands")
    require(len(packet["allowedPaths"]) == len(set(packet["allowedPaths"]))
            and set(packet["allowedPaths"]) == set(record["changedFiles"])
            | set(record["newFiles"]) | {AUTHORITY_PATH, VALIDATOR_PATH,
                                         "task-packets/" + NEW_PACKET + ".yaml"},
            "unreviewed or omitted evolution-surface packet path")
    for path, rule in record["changedFiles"].items():
        current = successor.historical_bytes(path, regular_bytes(path))
        require(digest(current) == rule["afterSha256"]
                and digest(historical_bytes(path, current)) == rule["beforeSha256"],
                "unreviewed current source: " + path)
    for path, expected in record["newFiles"].items():
        require(digest(successor.historical_bytes(path, regular_bytes(path))) == expected,
                "new source drift: " + path)
    validate_evolution_surface()


if __name__ == "__main__":
    validate()
    print("Evolution surface valid: 262 current specifications; 257-packet checkpoint and exact 256-packet predecessor; contract reviewed.")
