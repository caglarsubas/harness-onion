#!/usr/bin/env python3
"""Validate the MET-ENFORCE-039 I06 backend profile v4 (the policy observer's ClusterRole, pinned exactly) and edge record v8 and the exact 254-to-253 projection."""
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
    import validate_chain_compaction as successor
except ImportError:
    from scripts.safe_yaml import safe_load
    from scripts import validate_chain_compaction as successor


ROOT = Path(__file__).resolve().parents[1]
AUTHORITY_PATH = "architecture/i06-backend-profile-v4-authority.json"
AUTHORITY_SHA256 = "dce0115183f4bb9e15cfc0ef320f64123bf19de02cb9e4c27804b93bf1cb293f"
VALIDATOR_PATH = "scripts/validate_i06_backend_profile_v4.py"
BASE_COMMIT = "585364b94e3e4a8bf1418ef750ce3d71cd38f95a"
NEW_PACKET = "MET-ENFORCE-039"
PREVIOUS_PACKET = "MET-PERF-041"
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
            require(key not in result, "duplicate i06-backend-profile-v4 authority member")
            result[key] = value
        return result

    def no_constant(_value: str) -> Any:
        raise ValueError("nonfinite i06-backend-profile-v4 authority number")

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
        require(digest(raw) == AUTHORITY_SHA256, "i06 backend profile v4 history authority digest")
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
    }, "closed i06 backend profile v4 history authority")
    require(value["schemaVersion"] == "harness.planeon.ai/i06-backend-profile-v4-authority/v1"
            and value["authorityPacket"] == NEW_PACKET
            and value["acceptedBase"] == BASE_COMMIT
            and type(value["baselinePackets"]) is dict
            and len(value["baselinePackets"]) == 253
            and NEW_PACKET not in value["baselinePackets"]
            and type(value["changedFiles"]) is dict
            and type(value["newFiles"]) is dict
            and _sha(value["packetSha256"])
            and _sha(value["validatorNormalizedSha256"]),
            "accepted 253-packet base")
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
    # An exact 253-era byte string is already older than the successor layer.
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


# MET-ENFORCE-039 (roadmap I06-RBAC-V4; candidate 2 adopted by the lane monitor, owner-delegated, 2026-10-19, after two
# independent contract review rounds, the second PASS_FOR_ADOPTION) publishes the I06 backend profile v4 (owner decisions
# Q-HE4-6 (a) and Q-RBAC-1 to Q-RBAC-8 (a), monitor decisions Q-RBAC-9 (a), Q-RBAC-10 and Q-RBAC-11 (a)): a delta
# successor that imports I06 v3 unchanged (check_evidence is v3's function object) and pins the policy observer's one
# closed ClusterRole and binding exactly (the role document and criteria RB00 to RB07); and the operator ->
# harness-engineering edge record v8 (v7's 62 rows plus 4 for HE-008 and HE-004-I01). MET-PERF-041 then took slot 253
# (owner Q-253-DIAG (a)), so this is the 254th packet: it is built on 253's merge (BASE_COMMIT) while every contract round
# was pinned to 252's (REVIEW_BASE), and MET-PERF-041 changed no file of this era; the status record's one slot value
# moved from 253 to 254 (the lane monitor's decision MON-254-SLOTEDIT, option (a)), recorded as slotEdit.
# Repository bytes and modes are read only through reviewed_bytes and reviewed_mode, and the contract directory's listing
# only through reviewed_tree, so a later bridged successor projects its own edits away first; a path outside this era is
# refused before it is read, and every era file is bound by digest on every read. Checked here: the freeze (every file
# under I06 v1 to v3 and native-profile v1 to v5, their seven models and edge records v1 to v7 by exact path and digest,
# the contract builder's frozen set, with the three models the v4 model runs restated; nothing under those directories
# changed or added, and no edge record but v8's two files added); the contract's files (new, each once; the contract
# directory closed; mode 100644; no absolute local path); the adoption (the adopted files are candidate 2's bytes except
# edge record v8's four providerPacket values and the status record's adoption fields and slot edit, without which (and
# with the slot and base reverted) the record is candidate 2's byte for byte; the slot edit as the monitor decided it; two
# review rounds bound to their published records and subject candidates, round 1 also
# to the source index; the verbatim adoption decision; the closed findings as round 2 resolved them); the source index's
# pins; edge record v8 (it supersedes v7 by digest and packet, carries v7's 62 rows exactly and in order, and registers
# the four I06 v4 files with their exact bytes and modes, providerCommit null and providerPacket this packet); and the v4
# model, executed from this era's bytes with this era's I06 v1 and v3 models (and v3's native-profile v4 model) as its
# imports, replaying every vector over its pinned inputs (151 checks), with I06 v3's own replay (151 checks) as a
# control. This layer's own inverse hunks are the canonical byte-minimal ones, recomputed from its era's bytes
# (MET-PERF-040's carried rule).
V4_DIR = "architecture/i06-backend-profile-v4/"
EDGES_DIR = "architecture/artifact-edges/"
V4_README = V4_DIR + "README.md"
V4_CRITERIA = V4_DIR + "criteria.json"
V4_RBAC = V4_DIR + "observer-rbac.json"
V4_VECTORS = V4_DIR + "vectors.json"
V4_INDEX = V4_DIR + "source-index.json"
STATUS_PATH = V4_DIR + "status.json"
V4_MODEL = "scripts/i06_backend_profile_v4.py"
V3_MODEL = "scripts/i06_backend_profile_v3.py"
V1_MODEL = "scripts/i06_backend_profile.py"
NP4_MODEL = "scripts/native_qualification_v4.py"
V3_VECTORS = "architecture/i06-backend-profile-v3/vectors.json"
V7_EDGE = EDGES_DIR + "operator-harness-engineering-v7.json"
V8_EDGE = EDGES_DIR + "operator-harness-engineering-v8.json"
V8_README = EDGES_DIR + "README-v8.md"
# The adopted subject, and candidate 2's nine files (the subject and the status record) with their reviewed digests
# (r2 PASS_FOR_ADOPTION); edge record v8 and the status record differ from candidate 2 only by the adoption edits.
SUBJECT = (V4_README, V4_CRITERIA, V4_RBAC, V4_VECTORS, V4_INDEX, V4_MODEL, V8_EDGE, V8_README)
CANDIDATE_FILES = SUBJECT + (STATUS_PATH,)
CANDIDATE_SHA256 = MappingProxyType({
    V4_README: "d58b0385299d3f393c4f1ae936e18c8f45b9ae0f0c469f0c29627dd8ecb705ae",
    V4_CRITERIA: "10aa3a8fe08a930e3a4a13f7a11b38404cd82bd1a12164a40ef13141af37d09a",
    V4_RBAC: "71305d7f7ab231e01b33b4de43f3a49efa37f6e1fb463b98b076e9b216e266d8",
    V4_VECTORS: "27aba3bf7296a08b90adef1663d6498fda9ae98499707d0c0950aa6c4ba14eb7",
    V4_INDEX: "2f2238e3ba5965d010036efe61de1da0a180c7edbd8e0632b9b1f91df0f9372f",
    V4_MODEL: "7f97acfe9060e79c101f264f5bf61610bf421326c689216cbaf41df7e38e6d2a",
    V8_EDGE: "719b71549c33228c559026e9a1b5ad5a848c67c384b705f5bfa91a79d4cf02c7",
    V8_README: "e5dea489087b0d58c9e1559ce6ee1a07ef2e7567a9d04841d80b3f20e67dc0d9",
    STATUS_PATH: "e0f60b00f03b0317bbdf85643cbdca1506773d94cda6691a72961e3c9523b930",
})
CANDIDATE_LINES = 739
TBD = b'"providerPacket": "TBD"'
ASSIGNED = ('"providerPacket": "%s"' % NEW_PACKET).encode("ascii")
# Every contract round was pinned to 252's merge (the source index's base and tree), the status record's reviewBase; the
# packet is built on 253's (BASE_COMMIT), the status record's baseMain.
REVIEW_BASE = "27c54605a3dcdbe86522a6bd18a5e19faa5cb40b"
REVIEW_BASE_TREE = "334820b5cfc09d41824c2db07f385f765aba70fb"
# The slot edit, restated (the lane monitor's decision MON-254-SLOTEDIT, option (a), 2026-10-20): MET-PERF-041 took slot
# 253, so the status record's slot value moved from 253 to 254; reverting it is part of giving candidate 2's record back.
SLOT_EDIT = MappingProxyType({"before": 253, "after": 254, "decision": "owner Q-253-DIAG (a): MET-PERF-041 took slot 253"})
SLOT_EDIT_KEYS = ("before", "after", "decision")
RECORDS = tuple(V4_DIR + "review-round%d.json" % number for number in (1, 2))
NEW_FILES = CANDIDATE_FILES + RECORDS
CONTRACT_TREE = frozenset(path for path in NEW_FILES if path.startswith(V4_DIR))
# (round, verdict, the subject candidate's contract builder SHA-256, the round's finding ids) in order; round n reviewed
# candidate n, and round 2 the adopted candidate 2.
ROUNDS = ((1,
  'CHANGES_REQUIRED',
  'c46edf13d77f2fafd6889ef53715075a888f77adb0f4720aea729f35f2702efd',
  ('R1-1', 'R1-2', 'R1-3', 'R1-4', 'R1-5')),
 (2, 'PASS_FOR_ADOPTION', '99ba072c75c7ba843ed0d5bda0f6ba38deb1fdb6f6df28ac2ad2a7417d197a78', ('R2-1', 'R2-2')))
# Each round's subject candidate, file by file (no round copy is published; the digests are restated here).
ROUND_SUBJECTS = MappingProxyType({
    1: MappingProxyType({
        V4_README: "35d385c43710ed43170f02a1610929517a349021899486f162e1305c44672f1e",
        V4_CRITERIA: "38f775d4894eb48be268fc15f1f547bf0bd00f18b2842b10c49bb8476c27fb1a",
        V4_RBAC: "71305d7f7ab231e01b33b4de43f3a49efa37f6e1fb463b98b076e9b216e266d8",
        V4_VECTORS: "fc9bac94c60c53a69f5cf25af0ce2e5946d7c490211ac1693c60038a90544ad9",
        V4_INDEX: "4b824e2bc4c1bb519d4d33c50dcbd2f11f233a1b9af0cb991f72df083524df87",
        V4_MODEL: "efd50b51e8d45524459e20d343e2180abb09088358c57ed7e9882d9df259c991",
        V8_EDGE: "da6ba2ccbc157ce4fc89bbed5b84434e50bf98fd27a2120ba3d7d101cb1e6b26",
        V8_README: "b3172a640d0f59a02bd4a92dfe8b68e54c57ddd82a85b81a11e1ad12a5516184",
        STATUS_PATH: "bf6f6344156d059017ee9081e70921ba324535cfdb55214b07a93e9e65f0ac89",
    }),
    2: MappingProxyType({
        V4_README: "d58b0385299d3f393c4f1ae936e18c8f45b9ae0f0c469f0c29627dd8ecb705ae",
        V4_CRITERIA: "10aa3a8fe08a930e3a4a13f7a11b38404cd82bd1a12164a40ef13141af37d09a",
        V4_RBAC: "71305d7f7ab231e01b33b4de43f3a49efa37f6e1fb463b98b076e9b216e266d8",
        V4_VECTORS: "27aba3bf7296a08b90adef1663d6498fda9ae98499707d0c0950aa6c4ba14eb7",
        V4_INDEX: "2f2238e3ba5965d010036efe61de1da0a180c7edbd8e0632b9b1f91df0f9372f",
        V4_MODEL: "7f97acfe9060e79c101f264f5bf61610bf421326c689216cbaf41df7e38e6d2a",
        V8_EDGE: "719b71549c33228c559026e9a1b5ad5a848c67c384b705f5bfa91a79d4cf02c7",
        V8_README: "e5dea489087b0d58c9e1559ce6ee1a07ef2e7567a9d04841d80b3f20e67dc0d9",
        STATUS_PATH: "e0f60b00f03b0317bbdf85643cbdca1506773d94cda6691a72961e3c9523b930",
    }),
})
# A review record names its subject candidate, the candidate's builder and its README in its subject line.
SUBJECT_LINE = "tools/w03/i06-rbac candidate %d (build_contract.py sha256 %s, README sha256 %s)"
STATUS_KEYS = ("schemaVersion", "contract", "supersedes", "workItem", "packet", "slot", "status", "candidate", "baseMain",
               "reviewBase", "keeps", "contracts", "ownerDecisions", "discharges", "observerRole", "residuals",
               "r10CrossCheck", "counts", "carried", "nonClaims", "rounds", "adoption", "adoptedSubject", "adoptionEdit",
               "slotEdit", "independentReviewer", "readmeStatusNote", "recordPaths", "closedFindings")
# The keys the adoption added and candidate 2's values of the keys it changed: removing the one, reverting the slot edit
# and restoring the other (candidate 2's base, the review base; the carried rows without the adoption's two and without
# their actions; and candidate 2's one earlier round) gives candidate 2's status record back, byte for byte.
ADOPTION_KEYS = frozenset({"reviewBase", "adoptedSubject", "adoptionEdit", "slotEdit", "independentReviewer",
                           "readmeStatusNote", "recordPaths", "closedFindings"})
CANDIDATE_VALUES = MappingProxyType({"packet": "TBD", "status": "CONTRACT_CANDIDATE", "baseMain": REVIEW_BASE,
                                     "adoption": None})
ADOPTION_CARRIED = 2
ROUND_KEYS = ("round", "candidate", "subjectBuilderSha256", "verdict", "recordSha256", "record", "subjectSha256",
              "severities")
EARLIER_KEYS = ROUND_KEYS[:5]
EDIT_KEYS = ("path", "replaced", "with", "count", "rows", "candidateSha256", "adoptedSha256", "lineCount")
# The first line of the decisions record's 2026-10-19 adoption section, verbatim (the lane monitor's owner-delegated
# adoption).
ADOPTION = {'decidedBy': 'the lane monitor, owner-delegated',
 'date': '2026-10-19',
 'decision': 'Monitor: ADOPT candidate 2 for slot 253 (I06-RBAC-V4), on r2 PASS_FOR_ADOPTION (fb0f3a5d). The '
             'files: README d58b0385, observer-rbac.json 71305d7f, criteria 10aa3a8f, vectors 27aba3bf, status '
             'e0f60b00, source-index 2f2238e3, model 7f97acfe, edge v8 719b7154 (66 rows), README-v8 e5dea489, '
             'builder 99ba072c. Keep c2 frozen and carry R2-1 and R2-2 in status.json at adoption.'}
ACTIONS = {"filesEdited": False, "networkAccessed": "none", "personalDataSent": False, "inventoryToolingAttempted": False}
CLOSED_FINDINGS = {'R1-1': 'CLOSED in round 2',
 'R1-2': 'CLOSED in round 2',
 'R1-3': 'CLOSED in round 2',
 'R1-4': 'CLOSED in round 2',
 'R1-5': 'CLOSED in round 2',
 'R2-1': "CARRIED as the monitor's adoption directs (see carried)",
 'R2-2': "CARRIED as the monitor's adoption directs (see carried)"}
CARRIED = (("R2-1 (contract review round 2, NOTE): check_vectors pins each section's case ids in order, the XR01 and XR02 "
  "anchors and v4's ids disjoint from v3's, but not a case's content under a pinned id (CO02 or CO03 repointed to "
  'another object case, or XR03 made a copy of XR02, was accepted)',
  "a later I06 successor's model (optional hardening, not blocking)"),
 ("R2-2 (contract review round 2, NOTE): RB07's roleRef test reads two invalid roleRef kinds naming the observer's "
  "ClusterRole (a lower-case 'clusterrole', and kind Role in a ClusterRoleBinding) as valid instead of refusing "
  "them; the apiserver rejects both and R10's producer refuses such a roleRef as Malformed (R99), so this is no "
  'live bypass',
  "a later I06 successor's model (optional hardening, not blocking)"),
 ('the provisioning route, under SC03, OR02 and the certificate rule; check_observer_document on the vendored '
  'document and check_observer_rbac on the manifest before applying',
  'HE-008 (Q-RBAC-4 (a), Q-RBAC-8 (a))'),
 ('the observer accepts a snapshot only through check_observer_snapshot, on the RBAC lists of the same read at the '
  "snapshot's one resourceVersion (the caller obligation); the Secret residual's re-assessment; the audit-check "
  'decision',
  'HE-004-I01 (Q-RBAC-3 (a), Q-RBAC-4 (a), Q-RBAC-5 (a))'),
 ('403 on reads outside the role; the certificate subject; the stock system:authenticated roles; the audit check '
  'if adopted',
  'T04 (Q-RBAC-7 (a))'),
 ("the system:authenticated limit: only bindings naming User planeon:policy-observer are pinned, with RB07's role "
  'references; grants that reach the observer through system:authenticated beyond the stock bootstrap ones are '
  'neither pinned nor seen by I06 when they are reads',
  'T04 (a cluster-wide check over non-stock bindings to Group system:authenticated) and HE-004-I01 (Q-RBAC-11 '
  '(a))'),
 ("narrowing the writer's role names (Role planeon-policy-observer)",
  'W02G-F2 and an I07 successor (Q-RBAC-3 (a))'),
 ('adding this packet to OBS-RBAC-1 by PACKETS_ADDED, with its id',
  'the next W03 plan amendment (Q-RBAC-6 (a); Q-A3-6 (a); AMEND-2 C3-2)'),
 ("the HE-004C design text's '20 pairs': 20 request specs, 19 (group, resource) pairs; R116 enumerates correctly",
  "a clarifying note at R10's next MODEL_DEFINED touch (R10 is not edited here)"))
NON_CLAIMS = ['I06 v1, v2 and v3, native-profile v1 to v5 and edge records v1 to v7 are byte-identical; this packet adds files '
 'only.',
 "No evidence rule changes: check_evidence is v3's function object, and production evidence stays refused.",
 'No cluster is observed and nothing is provisioned; the request-attribute mapping is confirmed only by T04.',
 'Grants that reach the observer through system:authenticated beyond the stock bootstrap ones are not pinned '
 '(Q-RBAC-11 (a)).']
# The source index: its closed keys, its subject (the contract's files that adoption does not rewrite) and its inputs.
INDEX_KEYS = ("schemaVersion", "round", "baseMain", "baseTree", "subject", "predecessorInputs", "r10Inputs",
              "earlierRounds")
INDEX_SUBJECT = (V4_README, V4_CRITERIA, V4_RBAC, V4_VECTORS, V4_MODEL, V8_README)
INDEX_INPUTS = (
    "architecture/i06-backend-profile-v3/README.md",
    "architecture/i06-backend-profile-v3/criteria.json",
    "architecture/i06-backend-profile-v3/vectors.json",
    "scripts/i06_backend_profile_v3.py",
    "scripts/i06_backend_profile.py",
    "scripts/i06_backend_profile_v2.py",
    "scripts/native_qualification_v4.py",
    "architecture/i06-backend-profile/identity-closure.json",
    "architecture/i06-backend-profile/writer-inventory.json",
    "architecture/i06-backend-profile/upstream-bootstrap-rbac-v1.37.1.json",
    "architecture/i06-backend-profile/README.md",
    "architecture/i07-policy-write-v3/vectors.json",
    "architecture/i07-policy-write-v3/policy-kinds.json",
    "architecture/w03-obligation-amendment-2/amendment.json",
    "architecture/w03-obligation-amendment-2/status.json",
    "architecture/w03-obligation-amendment-3/amendment.json",
    "architecture/w03-plan-v2/plan.json",
    "architecture/native-profile-v4/status.json",
    "architecture/native-profile-v5/README.md",
    "architecture/native-profile-v5/status.json",
    "architecture/artifact-edges/operator-harness-engineering-v7.json",
    "architecture/artifact-edges/README-v7.md",
)
EDGE_V7_SHA256 = "6af45e361a66331a9ee0216d3eea42f3a17770fd3c7d33e78e2a025d301bfa92"
# Edge record v7's packet (252's), which v8 supersedes; since slot 254 it is no longer the previous packet.
V7_PACKET = "MET-ENFORCE-038"
V7_ROWS = 62
EDGE_ARTIFACT = "i06-backend-profile-v4-observer-rbac"
EDGE_KEYS = ("schemaVersion", "graph", "consumer", "provider", "artifact", "ownerDecision", "rules", "notArtifacts",
             "statuses", "artifacts", "supersedes", "ownerDecisions", "notes")
EDGE_ROW_KEYS = ("providerPath", "providerCommit", "sha256", "mode", "consumerPath", "consumerPacket", "relation", "status",
                 "providerPacket")
CONSUMER_PREFIX = "host-enforcement/contracts/i06-v4/"
# Edge record v8's four new rows: (provider path, provider commit, consumer path, consumer packet). The four files this
# packet publishes carry providerCommit null and providerPacket NEW_PACKET.
NEW_ROWS = (('architecture/i06-backend-profile-v4/observer-rbac.json',
  None,
  'host-enforcement/contracts/i06-v4/observer-rbac.json',
  'HE-008'),
 ('architecture/i06-backend-profile-v4/README.md', None, 'host-enforcement/contracts/i06-v4/README.md', 'HE-008'),
 ('architecture/i06-backend-profile-v4/criteria.json',
  None,
  'host-enforcement/contracts/i06-v4/criteria.json',
  'HE-004-I01'),
 ('architecture/i06-backend-profile-v4/vectors.json',
  None,
  'host-enforcement/contracts/i06-v4/vectors.json',
  'HE-004-I01'))
# The v4 model's pinned inputs and the vectors' counts (README "Counts": 151 checks), and I06 v3's (151 checks).
V4_INPUTS = {"v3Vectors": V3_VECTORS, "v3Criteria": "architecture/i06-backend-profile-v3/criteria.json",
             "criteria": V4_CRITERIA, "observerRbac": V4_RBAC,
             "i07Vectors": "architecture/i07-policy-write-v3/vectors.json",
             "inventory": "architecture/i06-backend-profile/writer-inventory.json",
             "closure": "architecture/i06-backend-profile/identity-closure.json",
             "bootstrap": "architecture/i06-backend-profile/upstream-bootstrap-rbac-v1.37.1.json"}
V4_COUNTS = {"documentNegative": 7, "objectsAccepted": 6, "objectsNegative": 61, "snapshotAccepted": 2,
             "snapshotNegative": 14, "crossVersion": 6, "composed": 7}
V4_CHECKS = 151
V3_INPUTS = {"v1Vectors": "architecture/i06-backend-profile/vectors.json",
             "v2Vectors": "architecture/i06-backend-profile-v2/vectors.json",
             "w02aVectors": "architecture/native-profile-v4/vectors.json",
             "w02aSchema": "architecture/native-profile-v4/qualification.schema.json",
             "w02aV2Vectors": "architecture/native-profile-v2/vectors.json",
             "inventory": V4_INPUTS["inventory"], "closure": V4_INPUTS["closure"], "bootstrap": V4_INPUTS["bootstrap"]}
V3_COUNTS = {"evidenceAccepted": 7, "snapshotAccepted": 5, "evidenceNegative": 91, "snapshotNegative": 38,
             "crossVersion": 7}
V3_CHECKS = 151
# The models the v4 model runs (it imports I06 v1 and v3; v3 imports native-profile v4), restated by exact path and
# digest (they are also members of the frozen set below).
MODEL_FREEZE = MappingProxyType({
    V1_MODEL: "bea3c953573478be5b03ab81b4ebd859da62d1eaa2a1be8f361b9dd39a98555e",
    V3_MODEL: "dfb00e90199d436ae63b79261f2e04870d7861cb0f7a424971657a4d777754de",
    NP4_MODEL: "f7c718072d1ffbb9b8bbc310e6141d476ea5f25296f70ff8c1bc9ada3db02387",
})
# I06 v1 to v3 and native-profile v1 to v5 (their directories): no file under them changes or is added here. Every file
# under them, their seven models and edge records v1 to v7 (exact paths; never a listing there) are the contract
# builder's frozen set, whose canonical digest is restated; with the source index's other inputs and the repository
# registry they are bound by digest below.
FROZEN_PREFIXES = ("architecture/i06-backend-profile/", "architecture/i06-backend-profile-v2/",
                   "architecture/i06-backend-profile-v3/", "architecture/native-qualification-inputs/",
                   "architecture/native-profile-v2/", "architecture/native-profile-v3/",
                   "architecture/native-profile-v4/", "architecture/native-profile-v5/")
FROZEN_MODELS = ("scripts/i06_backend_profile.py", "scripts/i06_backend_profile_v2.py", "scripts/i06_backend_profile_v3.py",
                 "scripts/native_qualification_v2.py", "scripts/native_qualification_v3.py", NP4_MODEL,
                 "scripts/native_qualification_v5.py")
FROZEN_SET_COUNT = 145
FROZEN_SET_SHA256 = "ebefa005de7dd6f476551303567bce65d7bfad1f3b6e96f2650f727be349862c"
FROZEN_PATHS = (
    "architecture/artifact-edges/README-v2.md",
    "architecture/artifact-edges/README-v3.md",
    "architecture/artifact-edges/README-v4.md",
    "architecture/artifact-edges/README-v5.md",
    "architecture/artifact-edges/README-v6.md",
    "architecture/artifact-edges/README-v7.md",
    "architecture/artifact-edges/README.md",
    "architecture/artifact-edges/operator-harness-engineering-v2.json",
    "architecture/artifact-edges/operator-harness-engineering-v3.json",
    "architecture/artifact-edges/operator-harness-engineering-v4.json",
    "architecture/artifact-edges/operator-harness-engineering-v5.json",
    "architecture/artifact-edges/operator-harness-engineering-v6.json",
    "architecture/artifact-edges/operator-harness-engineering-v7.json",
    "architecture/artifact-edges/operator-harness-engineering.json",
    "architecture/i06-backend-profile-v2/README.md",
    "architecture/i06-backend-profile-v2/REVIEW_BRIEF.md",
    "architecture/i06-backend-profile-v2/criteria.json",
    "architecture/i06-backend-profile-v2/review-round1.json",
    "architecture/i06-backend-profile-v2/review-round2.json",
    "architecture/i06-backend-profile-v2/review-round3.json",
    "architecture/i06-backend-profile-v2/round1/README.md",
    "architecture/i06-backend-profile-v2/round1/REVIEW_BRIEF.md",
    "architecture/i06-backend-profile-v2/round1/criteria.json",
    "architecture/i06-backend-profile-v2/round1/i06_backend_profile_v2.py",
    "architecture/i06-backend-profile-v2/round1/vectors.json",
    "architecture/i06-backend-profile-v2/round2/README.md",
    "architecture/i06-backend-profile-v2/round2/REVIEW_BRIEF.md",
    "architecture/i06-backend-profile-v2/round2/criteria.json",
    "architecture/i06-backend-profile-v2/round2/i06_backend_profile_v2.py",
    "architecture/i06-backend-profile-v2/round2/vectors.json",
    "architecture/i06-backend-profile-v2/source-index.json",
    "architecture/i06-backend-profile-v2/status.json",
    "architecture/i06-backend-profile-v2/vectors.json",
    "architecture/i06-backend-profile-v3/README.md",
    "architecture/i06-backend-profile-v3/REVIEW_BRIEF.md",
    "architecture/i06-backend-profile-v3/criteria.json",
    "architecture/i06-backend-profile-v3/source-index.json",
    "architecture/i06-backend-profile-v3/vectors.json",
    "architecture/i06-backend-profile/README.md",
    "architecture/i06-backend-profile/REVIEW_BRIEF.md",
    "architecture/i06-backend-profile/criteria.json",
    "architecture/i06-backend-profile/identity-closure.json",
    "architecture/i06-backend-profile/review-round1.json",
    "architecture/i06-backend-profile/review-round2.json",
    "architecture/i06-backend-profile/round1/README.md",
    "architecture/i06-backend-profile/round1/REVIEW_BRIEF.md",
    "architecture/i06-backend-profile/round1/criteria.json",
    "architecture/i06-backend-profile/round1/i06_backend_profile.py",
    "architecture/i06-backend-profile/round1/identity-closure.json",
    "architecture/i06-backend-profile/round1/source-index.json",
    "architecture/i06-backend-profile/round1/upstream-bootstrap-rbac-v1.37.1.json",
    "architecture/i06-backend-profile/round1/vectors.json",
    "architecture/i06-backend-profile/round1/writer-inventory.json",
    "architecture/i06-backend-profile/source-index.json",
    "architecture/i06-backend-profile/status.json",
    "architecture/i06-backend-profile/upstream-bootstrap-rbac-v1.37.1.json",
    "architecture/i06-backend-profile/upstream-facts-v1.37.1.json",
    "architecture/i06-backend-profile/vectors.json",
    "architecture/i06-backend-profile/writer-inventory.json",
    "architecture/i07-policy-write-v3/policy-kinds.json",
    "architecture/i07-policy-write-v3/vectors.json",
    "architecture/native-profile-v2/README.md",
    "architecture/native-profile-v2/REVIEW_BRIEF.md",
    "architecture/native-profile-v2/qualification.schema.json",
    "architecture/native-profile-v2/review-round1.json",
    "architecture/native-profile-v2/review-round2.json",
    "architecture/native-profile-v2/review-round3.json",
    "architecture/native-profile-v2/round1/README.md",
    "architecture/native-profile-v2/round1/REVIEW_BRIEF.md",
    "architecture/native-profile-v2/round1/native_qualification_v2.py",
    "architecture/native-profile-v2/round1/qualification.schema.json",
    "architecture/native-profile-v2/round1/source-index.json",
    "architecture/native-profile-v2/round1/vectors.json",
    "architecture/native-profile-v2/round2/README.md",
    "architecture/native-profile-v2/round2/REVIEW_BRIEF.md",
    "architecture/native-profile-v2/round2/native_qualification_v2.py",
    "architecture/native-profile-v2/round2/qualification.schema.json",
    "architecture/native-profile-v2/round2/source-index.json",
    "architecture/native-profile-v2/round2/vectors.json",
    "architecture/native-profile-v2/source-index.json",
    "architecture/native-profile-v2/status.json",
    "architecture/native-profile-v2/vectors.json",
    "architecture/native-profile-v3/README.md",
    "architecture/native-profile-v3/REVIEW_BRIEF.md",
    "architecture/native-profile-v3/qualification.schema.json",
    "architecture/native-profile-v3/review-round1.json",
    "architecture/native-profile-v3/review-round2.json",
    "architecture/native-profile-v3/review-round3.json",
    "architecture/native-profile-v3/review-round4.json",
    "architecture/native-profile-v3/review-round5.json",
    "architecture/native-profile-v3/review-round6.json",
    "architecture/native-profile-v3/round1/README.md",
    "architecture/native-profile-v3/round1/REVIEW_BRIEF.md",
    "architecture/native-profile-v3/round1/native_qualification_v3.py",
    "architecture/native-profile-v3/round1/qualification.schema.json",
    "architecture/native-profile-v3/round1/vectors.json",
    "architecture/native-profile-v3/round2/README.md",
    "architecture/native-profile-v3/round2/REVIEW_BRIEF.md",
    "architecture/native-profile-v3/round2/native_qualification_v3.py",
    "architecture/native-profile-v3/round2/qualification.schema.json",
    "architecture/native-profile-v3/round2/vectors.json",
    "architecture/native-profile-v3/round3/README.md",
    "architecture/native-profile-v3/round3/REVIEW_BRIEF.md",
    "architecture/native-profile-v3/round3/native_qualification_v3.py",
    "architecture/native-profile-v3/round3/qualification.schema.json",
    "architecture/native-profile-v3/round3/vectors.json",
    "architecture/native-profile-v3/round4/README.md",
    "architecture/native-profile-v3/round4/REVIEW_BRIEF.md",
    "architecture/native-profile-v3/round4/native_qualification_v3.py",
    "architecture/native-profile-v3/round4/qualification.schema.json",
    "architecture/native-profile-v3/round4/vectors.json",
    "architecture/native-profile-v3/round5/README.md",
    "architecture/native-profile-v3/round5/REVIEW_BRIEF.md",
    "architecture/native-profile-v3/round5/native_qualification_v3.py",
    "architecture/native-profile-v3/round5/qualification.schema.json",
    "architecture/native-profile-v3/round5/vectors.json",
    "architecture/native-profile-v3/source-index.json",
    "architecture/native-profile-v3/status.json",
    "architecture/native-profile-v3/vectors.json",
    "architecture/native-profile-v4/README.md",
    "architecture/native-profile-v4/REVIEW_BRIEF.md",
    "architecture/native-profile-v4/qualification.schema.json",
    "architecture/native-profile-v4/review-round1.json",
    "architecture/native-profile-v4/review-round2.json",
    "architecture/native-profile-v4/review-round3.json",
    "architecture/native-profile-v4/source-index.json",
    "architecture/native-profile-v4/status.json",
    "architecture/native-profile-v4/vectors.json",
    "architecture/native-profile-v5/README.md",
    "architecture/native-profile-v5/qualification.schema.json",
    "architecture/native-profile-v5/review-round1.json",
    "architecture/native-profile-v5/review-round2.json",
    "architecture/native-profile-v5/review-round3.json",
    "architecture/native-profile-v5/review-round4.json",
    "architecture/native-profile-v5/source-index.json",
    "architecture/native-profile-v5/status.json",
    "architecture/native-profile-v5/vectors.json",
    "architecture/native-qualification-inputs/meta-before.json",
    "architecture/native-qualification-inputs/qualification.schema.json",
    "architecture/native-qualification-inputs/vectors.json",
    "architecture/repositories.yaml",
    "architecture/w03-obligation-amendment-2/amendment.json",
    "architecture/w03-obligation-amendment-2/status.json",
    "architecture/w03-obligation-amendment-3/amendment.json",
    "architecture/w03-plan-v2/plan.json",
    "scripts/i06_backend_profile.py",
    "scripts/i06_backend_profile_v2.py",
    "scripts/i06_backend_profile_v3.py",
    "scripts/native_qualification_v2.py",
    "scripts/native_qualification_v3.py",
    "scripts/native_qualification_v4.py",
    "scripts/native_qualification_v5.py",
)
FROZEN_MESSAGE = ("I06 v1 to v3 and native-profile v1 to v5 (their models included) and edge records v1 to v7 stay "
                  "byte-identical")
ERA_SHA256 = MappingProxyType({
    "architecture/artifact-edges/README-v2.md": "0cded3e3499b8afe64c82a021a8a499c9b2fce5671ea5ae434b3330c26db3a2b",
    "architecture/artifact-edges/README-v3.md": "d6edd8cc7f8b209c1cf7bd0a16a941e0661ef040f8920cbdbda4c323c0f0f011",
    "architecture/artifact-edges/README-v4.md": "11e6bbefc27d82d359c7f48a873374786a760881693fd7d9ec7e88916ab2558b",
    "architecture/artifact-edges/README-v5.md": "6409a17c2fb0b5ae5df3055c86a3e4cb1e2cb3deacd490c4d547cc1d50a9b6ad",
    "architecture/artifact-edges/README-v6.md": "ce15ee36e15964a08fc83a495f2bd453ebe375c77e37d386f00c2803ec4e73f7",
    "architecture/artifact-edges/README-v7.md": "7131d500eac2085871254a250a4a84c24b17456891dd5f3b2478d85153f1a378",
    "architecture/artifact-edges/README-v8.md": "e5dea489087b0d58c9e1559ce6ee1a07ef2e7567a9d04841d80b3f20e67dc0d9",
    "architecture/artifact-edges/README.md": "5d62a665da2c6e75dce900cb4ef52e74aa14e537bdaeededb7568589339daa9f",
    "architecture/artifact-edges/operator-harness-engineering-v2.json": "749e70f174d638468bf45d7316e8f5201c3323f6348a78c7b9a22d3a571ccc32",
    "architecture/artifact-edges/operator-harness-engineering-v3.json": "106ea91aa09c2d377adf3b514a228331d6a805bd1a17e641ecaa23b3c39115f3",
    "architecture/artifact-edges/operator-harness-engineering-v4.json": "e30772ff8826650c46d1a8d384625929975e47f2de5cc9030680b5fdb5e7fc86",
    "architecture/artifact-edges/operator-harness-engineering-v5.json": "89b47ef8f865b31911eb8da2b08a5a3c22b2d92a62599cb6fdfccbfe7f79e3c0",
    "architecture/artifact-edges/operator-harness-engineering-v6.json": "0ac7c2da62de87837f5a36a967a2c5b9c286ecab2e03f335a8eebbd32df9d24d",
    "architecture/artifact-edges/operator-harness-engineering-v7.json": "6af45e361a66331a9ee0216d3eea42f3a17770fd3c7d33e78e2a025d301bfa92",
    "architecture/artifact-edges/operator-harness-engineering-v8.json": "623cf10bf19cfba1806f5699007f39c7f6ba38f72d92069548421c4dccd21573",
    "architecture/artifact-edges/operator-harness-engineering.json": "54bdc2d22676720419f51cd1bad5eedc909e6f848ed09cd363e351889af9d1fe",
    "architecture/i06-backend-profile-v2/README.md": "553880b957586dbfa50eabc4a99d51735eef2a1b0a82641ea51d8e3ea8cf72eb",
    "architecture/i06-backend-profile-v2/REVIEW_BRIEF.md": "f65c1ef1fbe43013c06f962a2ffde8d231a70392603ecc44850481c5ae8ec739",
    "architecture/i06-backend-profile-v2/criteria.json": "026206c57d3025c0f0129b6615e46c83d5a8000ddc3288f000a1fe4570050cda",
    "architecture/i06-backend-profile-v2/review-round1.json": "b1f6501655c1860d5b3c79e8de2b9080e4b373ad81d057904e2f0af5b7f35332",
    "architecture/i06-backend-profile-v2/review-round2.json": "a5eefd7c6fb0f53f2a14880a079a69bd786c95be1ca8b3a3c5ab7c6de04cc0df",
    "architecture/i06-backend-profile-v2/review-round3.json": "1a04fb792d080ee70f24fc93da68df8238a1593e91c9072c2e6dd3f75bf48bd2",
    "architecture/i06-backend-profile-v2/round1/README.md": "e8f64f90a58584200ead369fe402e738e2ec6c6cbb326bfb3674d75e45780ae7",
    "architecture/i06-backend-profile-v2/round1/REVIEW_BRIEF.md": "fa9e538c961b432bbde0889416739dd3aa142f383403c2885c345800d2078cf5",
    "architecture/i06-backend-profile-v2/round1/criteria.json": "fbb42e2c30f44ba8c6da19527830eedf9c80bb53b3e80697c5093b72091a44d9",
    "architecture/i06-backend-profile-v2/round1/i06_backend_profile_v2.py": "53e978b1c09e9c78c2c7b189d0f02a52c4cac94866b41cbb5fbcafa308603592",
    "architecture/i06-backend-profile-v2/round1/vectors.json": "32d4ea806d4f3a721ee8f62e028139c2d7835a856d5d59288e7e46bb04c743bc",
    "architecture/i06-backend-profile-v2/round2/README.md": "2440b7965b05003b049283c71ab24ab636285c3edd51fea04803dd187cbe5489",
    "architecture/i06-backend-profile-v2/round2/REVIEW_BRIEF.md": "bbca03819363d29bc3d3c63c64a77e5a9272bc878f0860ab4ae35e714f65556c",
    "architecture/i06-backend-profile-v2/round2/criteria.json": "026206c57d3025c0f0129b6615e46c83d5a8000ddc3288f000a1fe4570050cda",
    "architecture/i06-backend-profile-v2/round2/i06_backend_profile_v2.py": "3d157d6c0a396e87449d4227c352c7c502dead9eff28fef73eeb504cdf8cc4d5",
    "architecture/i06-backend-profile-v2/round2/vectors.json": "1a5e168f0d8fff233f5072b1440e75a633b38e428f87b2893a96e579122a430e",
    "architecture/i06-backend-profile-v2/source-index.json": "372216008e01a99963033412ea9add4453bd95b18fa4bdece78a7d15e14f249f",
    "architecture/i06-backend-profile-v2/status.json": "44217baf7857b86abfa9c8ccadb953e2678592e437c9caf049096c402abb9c20",
    "architecture/i06-backend-profile-v2/vectors.json": "1a5e168f0d8fff233f5072b1440e75a633b38e428f87b2893a96e579122a430e",
    "architecture/i06-backend-profile-v3/README.md": "9ee406f43060f266a7b5dd2679aa8352f0815584c45e33d0ab193ea7f90c0c77",
    "architecture/i06-backend-profile-v3/REVIEW_BRIEF.md": "ca7bbf5e858c940b32058acf8475242fb1ad898afb92584bfac7f79914f93891",
    "architecture/i06-backend-profile-v3/criteria.json": "752533c57b5f93e4c4158a9c17b52eb88d236a3632ab0b66b669e8f8041f57c7",
    "architecture/i06-backend-profile-v3/source-index.json": "7740a01dcd1a9fe41a106532d5ddde37a1cce70e2244c6638d480953532a14c1",
    "architecture/i06-backend-profile-v3/vectors.json": "4752b648abdd82d21ea622a1b26c721143577478c0a2491204e0d584c1d6f081",
    "architecture/i06-backend-profile-v4/README.md": "d58b0385299d3f393c4f1ae936e18c8f45b9ae0f0c469f0c29627dd8ecb705ae",
    "architecture/i06-backend-profile-v4/criteria.json": "10aa3a8fe08a930e3a4a13f7a11b38404cd82bd1a12164a40ef13141af37d09a",
    "architecture/i06-backend-profile-v4/observer-rbac.json": "71305d7f7ab231e01b33b4de43f3a49efa37f6e1fb463b98b076e9b216e266d8",
    "architecture/i06-backend-profile-v4/review-round1.json": "06e61ab685c20345c6d6205c024ee8fc924a770c09f54a1156566cb8b5467299",
    "architecture/i06-backend-profile-v4/review-round2.json": "fb0f3a5d010e872b516b3f9d598d67be2158bd14df755dc5e00f223adc8449f8",
    "architecture/i06-backend-profile-v4/source-index.json": "2f2238e3ba5965d010036efe61de1da0a180c7edbd8e0632b9b1f91df0f9372f",
    "architecture/i06-backend-profile-v4/status.json": "589ffb47b9883f8f1a8127dd80c6ccbe2345e21da705a7c6b06e9e9a01a887ad",
    "architecture/i06-backend-profile-v4/vectors.json": "27aba3bf7296a08b90adef1663d6498fda9ae98499707d0c0950aa6c4ba14eb7",
    "architecture/i06-backend-profile/README.md": "ccf952d40b4f6229c0cdea79f976253cd4abb19438c1eebc5794e748a708e4b7",
    "architecture/i06-backend-profile/REVIEW_BRIEF.md": "80db3bb8d0eb2a98ac6bd2cfe140837edd64f91ede315de92810afb6ca11cfe9",
    "architecture/i06-backend-profile/criteria.json": "95f893a9988b81042598d9c469c669e7401975f1367043a55540471e70fc5d1b",
    "architecture/i06-backend-profile/identity-closure.json": "0a9b82ffa2d63bf48a8850574cdf3ece02bf1913f33a72cbb96ed30a40f1f3bb",
    "architecture/i06-backend-profile/review-round1.json": "95d11f53f44d6a984f1dea1d74eec300906f27bb8322bdba169f9cc0e610e373",
    "architecture/i06-backend-profile/review-round2.json": "c46c825e59efa8ba7a79e1db5efff5b981e10147e826542b6967b24921b90235",
    "architecture/i06-backend-profile/round1/README.md": "eb872992371d242a3c033775318d7b1b94413964676ecc8c72a80bae9dcead1b",
    "architecture/i06-backend-profile/round1/REVIEW_BRIEF.md": "343f1aa12050dc8e43cb723bf902be2857f404646658630dfd1a6a5605e303ec",
    "architecture/i06-backend-profile/round1/criteria.json": "c729c67924169f599c7beefcab83857b06c0c947264259cc74d6cf5f452c73e7",
    "architecture/i06-backend-profile/round1/i06_backend_profile.py": "3698c048a56df3728b8c132627eed92ac14f6c37507255eb25591034185fdf75",
    "architecture/i06-backend-profile/round1/identity-closure.json": "73ac718f6199fba3f88b0b54ec0835ce2b5c6620612e92342d6b2585fcde532a",
    "architecture/i06-backend-profile/round1/source-index.json": "b631ef894cf13ad9664d864c3b829e033f157153d938f94147669974bf4284c6",
    "architecture/i06-backend-profile/round1/upstream-bootstrap-rbac-v1.37.1.json": "e9727e7b321b4e1c0ad9244eb97deb3da2c78f576c6be23df01530e8452ea71f",
    "architecture/i06-backend-profile/round1/vectors.json": "005ecbe66edb71d591a3b745315fd73f1b73feb97bc2a29835ec93e75779ffb8",
    "architecture/i06-backend-profile/round1/writer-inventory.json": "fd57c98726020adf66585e54d431d40203704739e51ba55ad9def89223b709b6",
    "architecture/i06-backend-profile/source-index.json": "c7aaeb7e06a075cd4730d7c6beef4187dfa305f7e3520a8963bb4504447e5b01",
    "architecture/i06-backend-profile/status.json": "73d8df607e90568e06f14b3548f8c727805f68072d9753134a32a2eb049f60c3",
    "architecture/i06-backend-profile/upstream-bootstrap-rbac-v1.37.1.json": "7529c2a713af2fb90163175924c264d95f4242d7e0c26b1452c77febb13ed50e",
    "architecture/i06-backend-profile/upstream-facts-v1.37.1.json": "354f048c06cbfd9e88f9e1042abf9322f759bb9d9082209a2188af091c89c7af",
    "architecture/i06-backend-profile/vectors.json": "b9c57d64eab03f307e10b02152426a10ebac2fd27102e27ef5873b5865be4cee",
    "architecture/i06-backend-profile/writer-inventory.json": "8e6b3b7565cfc93a61162b84d740cffb2871eb66ab85e8c4e80ac813f1af3077",
    "architecture/i07-policy-write-v3/policy-kinds.json": "4e427204b89959cb855d8641c3fa6f95d358b0b6a6a7730bfc7776adc4a173c0",
    "architecture/i07-policy-write-v3/vectors.json": "c4c24c5ff15618aa2f0fe0f016011359bc4316220c6e40d5168f9ee24b6f736d",
    "architecture/native-profile-v2/README.md": "7eb2bf5f8e78bf19f942893f57da5e7ca519bdf134c26b98d7b79ef4cc47fc89",
    "architecture/native-profile-v2/REVIEW_BRIEF.md": "30e896dafecdc5d4e78852b526dde7ba8108c28e998afe47d608ce5ec567a345",
    "architecture/native-profile-v2/qualification.schema.json": "55bd641fd229f21e04ec00813bcfe600890584e982e290a210720ac5cb160ab0",
    "architecture/native-profile-v2/review-round1.json": "9100034ec9d171ddad87d85c4c31b1a3ec9ee681060abb4ba85cbcc20816ef1c",
    "architecture/native-profile-v2/review-round2.json": "1a94aaca6c2309e795a3ca709096d79003c61eecdf31e408957f03937ec376ed",
    "architecture/native-profile-v2/review-round3.json": "a28bf4b9df183075eeef071d8af557ae1edd7bee92193612cfeb255ee763caf1",
    "architecture/native-profile-v2/round1/README.md": "c1a31789aa73f8faa8770d8434754fb4b6bad2ae3d22ffff5cb59b7970e1a073",
    "architecture/native-profile-v2/round1/REVIEW_BRIEF.md": "20c1be5f95806f4b2b4cba477b2fec9c946bd368b5ca017a9ceb3851c8391923",
    "architecture/native-profile-v2/round1/native_qualification_v2.py": "abaa6e7cc90bf17b149b92704593edc048f626d79c1321dee55a142930545d19",
    "architecture/native-profile-v2/round1/qualification.schema.json": "649b2b09e60e7dac860f6ef4756ffd1a335d058ad44039be41bb66ae8bfd2a63",
    "architecture/native-profile-v2/round1/source-index.json": "feebab9064aa92e5d1f7173bb1768dc97906304e39db65954da5360707d83f10",
    "architecture/native-profile-v2/round1/vectors.json": "3c56ad834cf5f448c3eae8003844aa5462c3e3ca0eb7b9ead0bbbf5c5fa22ea5",
    "architecture/native-profile-v2/round2/README.md": "a3056f6c6201da90e19ee3611aa357914cfdf2a8855ddc01d1c98c99912f37ac",
    "architecture/native-profile-v2/round2/REVIEW_BRIEF.md": "7ca5dc4475ad712a1a891ec086124c2f13284a61a5e9dfdacc96036f32b18599",
    "architecture/native-profile-v2/round2/native_qualification_v2.py": "89dade2161713ac36a7c0b41514f2a234caf9bbab1a39fee1b759f8b6da470d6",
    "architecture/native-profile-v2/round2/qualification.schema.json": "6e34577ea6946500eb0ccaeecaa3a0477386951a411ab3fc7795cf8e7bd18535",
    "architecture/native-profile-v2/round2/source-index.json": "d813a19991c3a3927f10841e8889493b2252fb0fc88e3d3eff707c3ea6a142eb",
    "architecture/native-profile-v2/round2/vectors.json": "7e0358dbb8897892b573e0ca67f25c6591212c89fd5b4664dc8079a8676e507c",
    "architecture/native-profile-v2/source-index.json": "a531cd4bd2c29a50459e93847119009b59b6690ac5628c0f737644cef504b5c7",
    "architecture/native-profile-v2/status.json": "ccd7bc05c1cd36ea29511cbb058f55d90d46128bdc8188d8135220479ebd5212",
    "architecture/native-profile-v2/vectors.json": "6d58d1f36b7bce5739b94dd89512d358b96878c70e1de7cf8f399050b881b396",
    "architecture/native-profile-v3/README.md": "93b6f3897f4011ab85832b4319db44e4e1e94566adf61062a6170d1437dfcf50",
    "architecture/native-profile-v3/REVIEW_BRIEF.md": "0a1f639db5db1d73e9a977519923d1158edff26e2b337a1ad7e5a59e2c874f4a",
    "architecture/native-profile-v3/qualification.schema.json": "ae5cbb6aa39f4edfa2d9919f25e55bad9ab214a99ca927c5afe7e2d943946ac5",
    "architecture/native-profile-v3/review-round1.json": "6c2b96c5ad22be96c0c9877a62496930077514e686d18102d2ba9bfd6bd54706",
    "architecture/native-profile-v3/review-round2.json": "d7efcbbb00bbc32cd9d9fdeacd4413e7fd2f63a4f7be415c3082b6fe9ab1d741",
    "architecture/native-profile-v3/review-round3.json": "5a9db56cc15cd08615b395696d020e0771a574d2c7d8d77be03cdf6c7bcbad34",
    "architecture/native-profile-v3/review-round4.json": "853aa4dc70e0ebaa20d1e05ef7ba4f8fca7c06550e91ba3142d30f8260f82990",
    "architecture/native-profile-v3/review-round5.json": "2bea5b50f492de29bd0fc2b8beddb0447f6146bf63c86fa520464b1bb739306f",
    "architecture/native-profile-v3/review-round6.json": "dce53008c9b21f670935a6fb0c434678dec2538599fc757c46ac5a54a718c929",
    "architecture/native-profile-v3/round1/README.md": "516317ed1cc2a4e54321a3aa3e8f54aac65f9b7bce9c36d3657c2a018d3b7ab9",
    "architecture/native-profile-v3/round1/REVIEW_BRIEF.md": "c236defae99762b03ebcbcd9c2f0a8b0d5500eed748cd3a1590b1597e30041ad",
    "architecture/native-profile-v3/round1/native_qualification_v3.py": "0aa9e0de38a987ce2563a439bf321f06f4dcfb7308c6f80594d59e8d81812bdd",
    "architecture/native-profile-v3/round1/qualification.schema.json": "c959ce273084b55154fb5d2f9582620a0f0a825217305fe5188ecadbc295f2ea",
    "architecture/native-profile-v3/round1/vectors.json": "fc311fb5f19af5584e7832da8dff46fa1d976ce784ae5541df9a3433b9cd372f",
    "architecture/native-profile-v3/round2/README.md": "39ce4ad70ec47294598e7285506f021b8ce4924c7bc5a48ae7973446d376a79a",
    "architecture/native-profile-v3/round2/REVIEW_BRIEF.md": "63375780b780bac82304ad8a9767bea4ee162caf6f7185c24466462fc68f761b",
    "architecture/native-profile-v3/round2/native_qualification_v3.py": "7288eebe50502ad0d71002f29a185e017f43b364d503f14ca130e229e00d7849",
    "architecture/native-profile-v3/round2/qualification.schema.json": "50b79787c28c1e819990cbc1fdef0b204a6b9696fd46822787f4f7ec35d22697",
    "architecture/native-profile-v3/round2/vectors.json": "faf3bf9e97ae7e7e5d3374a019fcc2236df37e98421b0d8a381854ca1ef81bb8",
    "architecture/native-profile-v3/round3/README.md": "69954f5f9cf139781db74870d90575f6c6ce1eff7ee2d6ade07b26e2dc521fb4",
    "architecture/native-profile-v3/round3/REVIEW_BRIEF.md": "1d19093bd4965839f02a4b6cccf9f163a48447f8c68d8e3d797792cb884a9fdf",
    "architecture/native-profile-v3/round3/native_qualification_v3.py": "07622432075e39ffd193b40e1e303524bf7574e88e37990ad5bf8aaf78f36497",
    "architecture/native-profile-v3/round3/qualification.schema.json": "554686b161ccb89e0f3d4c1249a7821b346dce2babd43d748a4ca6f15fa19b15",
    "architecture/native-profile-v3/round3/vectors.json": "80d006cab395db8bb6137d46e2fdb3e8f3a767870ed3929dd2382f9a12c6b0b2",
    "architecture/native-profile-v3/round4/README.md": "35f50fcdbea157765fa8e2fa34b47b8041a1a2da07f41e9bf3774213979c9d36",
    "architecture/native-profile-v3/round4/REVIEW_BRIEF.md": "75cb1e9f248f912b849136e738a39a352780c43a24a6f9a6fae84cd7218dd5d7",
    "architecture/native-profile-v3/round4/native_qualification_v3.py": "d946c7a748a9891f76f998abb1b72da5b7eab582c93a32f6223745ff26fbc112",
    "architecture/native-profile-v3/round4/qualification.schema.json": "ae5cbb6aa39f4edfa2d9919f25e55bad9ab214a99ca927c5afe7e2d943946ac5",
    "architecture/native-profile-v3/round4/vectors.json": "2d3995922b96533191f07b331303eaeecb3163df39e04e04d1bb8476951fcf43",
    "architecture/native-profile-v3/round5/README.md": "5627b9ee17348555979124afc4ab4376632c026aca82a34544b083fc5ef48a18",
    "architecture/native-profile-v3/round5/REVIEW_BRIEF.md": "b24b249613514f41ce93d0b4e012bdcbf289ec287b722dad13ecd37dd501efb5",
    "architecture/native-profile-v3/round5/native_qualification_v3.py": "b9f492b73501f66f6751448aacf9c48ff43c62f27b6536e3ca3f06ce763a677b",
    "architecture/native-profile-v3/round5/qualification.schema.json": "ae5cbb6aa39f4edfa2d9919f25e55bad9ab214a99ca927c5afe7e2d943946ac5",
    "architecture/native-profile-v3/round5/vectors.json": "b19fdd2239302bba62f798ece847aa93ad098fde638b914f981b0cf1f746ccd0",
    "architecture/native-profile-v3/source-index.json": "9be53fc877302c20f5e4f191adac9070e3e547d4ba81e441cee905f333ef3d50",
    "architecture/native-profile-v3/status.json": "f242944dd7a03eb64fd4f14d811711f7ed4ccf9bdb00bca82ea8abbaa5cb0538",
    "architecture/native-profile-v3/vectors.json": "14af47a69c972039294be8659c31332acd5326bfb0a3a38384a2c6bf9d11fe6d",
    "architecture/native-profile-v4/README.md": "a4205a5388dc83827bb39670bcc9477b030f29829128abf19f7578321c170174",
    "architecture/native-profile-v4/REVIEW_BRIEF.md": "293b9fc1f4affd9be0ff5d38bbc15dae902c22f5761a0ecdbc82d4f9c24fefea",
    "architecture/native-profile-v4/qualification.schema.json": "c3e91c087ebc6a13e8a96a066f80710ac968c8def434d1d1b97415811715ed10",
    "architecture/native-profile-v4/review-round1.json": "6a22a9ae1d422def7d487780da79b9ddb84d9283dabf53a7c5bfc952463e34d9",
    "architecture/native-profile-v4/review-round2.json": "09d4035d8ab726e432a636aab9176a4d8b0a93041345b6cf7ee04a9aab89066b",
    "architecture/native-profile-v4/review-round3.json": "60f72eef0be1fea1a99ed883ff514aab966a2fee9e3bf84c0b39ac227a38e8a3",
    "architecture/native-profile-v4/source-index.json": "6e2c325054ffd5edee3d71c4163dd38bef42b6b255bbdeae5e2c37814ef178fb",
    "architecture/native-profile-v4/status.json": "b998d1151cfe7fada1d4e30829064ceaad5d9c1220f407c6c865bc47c197143c",
    "architecture/native-profile-v4/vectors.json": "dede64ab3202a9e28094f062b5dad868c13ca02423e2380af8666ecf2e7a86e6",
    "architecture/native-profile-v5/README.md": "76b584ca769f0afdd5142fcf3f96e3b5b2d053a172d5713f970dc77594e77692",
    "architecture/native-profile-v5/qualification.schema.json": "70bda12463cee83301bc10fa6285023dc0e07b281a87ca70d44ec746cf262113",
    "architecture/native-profile-v5/review-round1.json": "0626a1f6f2bc878b25256dfa071b47ffe73f67a423c3c183e6b8d898235e8aab",
    "architecture/native-profile-v5/review-round2.json": "695cf190ea0f277b574f43b8c00ffdefeb20650403e7166319e5371524f7a44f",
    "architecture/native-profile-v5/review-round3.json": "3b5f9dec0c436618057910e8fb10257cb21cc363bc12ac7441be3831f33bcc32",
    "architecture/native-profile-v5/review-round4.json": "b8356184bd7ec0f4f50c9e6463ca6c6403e037d2f8a1eaa0a6bd3dcb552bda4f",
    "architecture/native-profile-v5/source-index.json": "68cd8f2777405b9a5c6605c99f96d03de317d0444c562f8b0b019a57a4f9fd08",
    "architecture/native-profile-v5/status.json": "13c78f09c5c50ae4f531b2cef69b4f735bc9499358db914dfdfbb1648fc7dad0",
    "architecture/native-profile-v5/vectors.json": "b630c362b20bfa7b362bb2ee28734a403303a0dc54b2d627c11a332b226333a1",
    "architecture/native-qualification-inputs/meta-before.json": "3b7929df563a6eabe5e0c9f624ef886d55e898b6ccf1d269e8cb90ae63e92905",
    "architecture/native-qualification-inputs/qualification.schema.json": "bef248bfa82b234124c014f98e40c5791bced3171bb118b7ed1bb7b8daaf95c3",
    "architecture/native-qualification-inputs/vectors.json": "cd1be009b721bb596887335184a33ab8e1f24aed8215477b63e28f058110748f",
    "architecture/repositories.yaml": "02190a668c6a9114b3733724bec4e552c553867e789b0802f6aaa6759148051d",
    "architecture/w03-obligation-amendment-2/amendment.json": "a1d861866136a52c378777ab4bb974df856cccf147551b0dab8c4fad8f234f0b",
    "architecture/w03-obligation-amendment-2/status.json": "caf4cf34f8b4dbb995b47efc97688f235634cf9850e817f8c936cc9dce8491b5",
    "architecture/w03-obligation-amendment-3/amendment.json": "ddf5e9abd4c23d4fb09031693466079c68ea2a07c8068a5cdcde0b9bb7d2882b",
    "architecture/w03-plan-v2/plan.json": "a00470238431347da82cc47b1f1b6cf7cd51042d56694eea68d1373a3aaefb67",
    "scripts/i06_backend_profile.py": "bea3c953573478be5b03ab81b4ebd859da62d1eaa2a1be8f361b9dd39a98555e",
    "scripts/i06_backend_profile_v2.py": "58ceb7a6817aab512a56f9f2a614868ce27660d174be353c5629cc8de335e426",
    "scripts/i06_backend_profile_v3.py": "dfb00e90199d436ae63b79261f2e04870d7861cb0f7a424971657a4d777754de",
    "scripts/i06_backend_profile_v4.py": "7f97acfe9060e79c101f264f5bf61610bf421326c689216cbaf41df7e38e6d2a",
    "scripts/native_qualification_v2.py": "c72b6e18044f685c646756a1574bd81cd24f1475d7eda326778d70d1314ef68b",
    "scripts/native_qualification_v3.py": "2ef5c14ad5d8c962cf3703ccd076059685ed8dcc852059e4f863e8d9dc8965ad",
    "scripts/native_qualification_v4.py": "f7c718072d1ffbb9b8bbc310e6141d476ea5f25296f70ff8c1bc9ada3db02387",
    "scripts/native_qualification_v5.py": "d9926f4d18c82a5da31b903fea47c42319d29268a63a26171a7e71aa4c2480a5",
})
# Absolute local path markers, matched case-insensitively; spelled in parts, so this file holds none of them.
LOCAL_PATH_MARKERS = (b"/" + b"users/", b"/" + b"private/", b".local" + b"/state")


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


def _verified(path: str) -> bytes:
    """reviewed_bytes, checked against its era digest on every read; a path outside the era is refused before it is
    read."""
    expected = ERA_SHA256.get(path) if type(path) is str else None
    require(expected is not None, "MET-ENFORCE-039 reviewed bytes are bound: " + str(path))
    raw = reviewed_bytes(path)
    require(type(raw) is bytes and digest(raw) == expected, "unreviewed I06-RBAC-V4 source: " + path)
    return raw


def _json(path: str) -> Any:
    return parse(_verified(path))


def _holds(check: Any) -> bool:
    """A structural check over a module's result or this era's data; a malformed value does not hold."""
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


def _texts(values: Any) -> bool:
    return type(values) is list and len(values) > 0 and all(type(text) is str and text.strip() != "" for text in values)


def _dump(value: Any) -> bytes:
    """A record's bytes as the contract builder writes them (indent 1, UTF-8, a final newline)."""
    return (json.dumps(value, indent=1, ensure_ascii=False) + "\n").encode("utf-8")


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


def era_modules() -> types.SimpleNamespace:
    """This era's native-profile v4 and I06 v1 models, I06 v3 with those two as its imports, and the v4 model with I06
    v1 and v3 as its imports."""
    np4 = _era_model(NP4_MODEL, "_met_enforce_039_native_qualification_v4")
    i06v1 = _era_model(V1_MODEL, "_met_enforce_039_i06_backend_profile")
    i06v3 = _era_model(V3_MODEL, "_met_enforce_039_i06_backend_profile_v3",
                       {"i06_backend_profile": i06v1, "native_qualification_v4": np4})
    i06v4 = _era_model(V4_MODEL, "_met_enforce_039_i06_backend_profile_v4",
                       {"i06_backend_profile": i06v1, "i06_backend_profile_v3": i06v3})
    require(i06v4.v1 is i06v1 and i06v4.v3 is i06v3 and i06v3.v1 is i06v1 and i06v3.w02a is np4
            and i06v4.check_evidence is i06v3.check_evidence,
            "I06 v4 runs this era's I06 v1 and v3 models, and v3 this era's native-profile v4 model")
    return types.SimpleNamespace(np4=np4, i06v1=i06v1, i06v3=i06v3, i06v4=i06v4)


def validate_freeze() -> None:
    """No file this packet changes or adds is a frozen path, sits under a predecessor's directory, or is an edge record
    other than v8's two files; the models the v4 model runs are these bytes at these exact paths; and the contract
    builder's frozen set (every file under I06 v1 to v3 and native-profile v1 to v5, their seven models and edge records
    v1 to v7) is this era's, by its restated digest."""
    for path in list(_PROJECTION_RULES) + list(authority()["newFiles"]):
        require(path not in FROZEN_PATHS and not path.startswith(FROZEN_PREFIXES)
                and (not path.startswith(EDGES_DIR) or path in (V8_EDGE, V8_README)), FROZEN_MESSAGE)
    for path, expected in MODEL_FREEZE.items():
        require(ERA_SHA256.get(path) == expected and digest(_verified(path)) == expected,
                "the models I06 v4 runs are frozen by exact path and digest: " + path)
    builder_set = {path: digest(_verified(path)) for path in FROZEN_PATHS
                   if path.startswith(FROZEN_PREFIXES) or path in FROZEN_MODELS or path.startswith(EDGES_DIR)}
    require(len(builder_set) == FROZEN_SET_COUNT and digest(canonical(builder_set)) == FROZEN_SET_SHA256,
            "the frozen set is the contract builder's, by exact path and digest")


def validate_contract_files() -> None:
    """The packet adds the contract's files as new files, each once; the contract directory holds exactly its files;
    every contract file is a regular file of git mode 100644, not a link and not executable; and none holds an absolute
    local path."""
    new = authority()["newFiles"]
    require(len(set(NEW_FILES)) == len(NEW_FILES) and not set(NEW_FILES) & set(_PROJECTION_RULES)
            and {path for path in new if path.startswith(V4_DIR) or path in (V4_MODEL, V8_EDGE, V8_README)}
            == set(NEW_FILES), "the contract's files are new in this packet, each once")
    require(stat.S_ISDIR(reviewed_mode(V4_DIR[:-1])), "the contract directory is a directory, not a link")
    tree = reviewed_tree(V4_DIR)
    require(set(tree) == CONTRACT_TREE, "the contract directory holds exactly its files")
    for path in NEW_FILES:
        mode = reviewed_mode(path)
        require(stat.S_ISREG(mode) and not mode & 0o111, "a contract file is a regular file of git mode 100644: " + path)
        raw = _verified(path).lower()
        require(not any(marker in raw for marker in LOCAL_PATH_MARKERS),
                "no absolute local path in a file this packet adds: " + path)


def candidate_status(status: dict) -> bytes:
    """The status record without its adoption fields, with its slot edit reverted and candidate 2's values restored:
    candidate 2's bytes exactly when the adoption only added those fields and moved the slot."""
    reverted = {key: value for key, value in status.items() if key not in ADOPTION_KEYS}
    reverted.update(CANDIDATE_VALUES)
    reverted["slot"] = status["slotEdit"]["before"]
    reverted["carried"] = [{"item": row["item"], "to": row["to"]} for row in status["carried"][ADOPTION_CARRIED:]]
    reverted["rounds"] = [{key: row[key] for key in EARLIER_KEYS} for row in status["rounds"][:1]]
    return _dump(reverted)


def validate_adoption() -> dict:
    """Adopted after two independent review rounds, each bound to its published record and its subject candidate's
    exact files; the adopted files are candidate 2's bytes except edge record v8's four providerPacket values and the
    status record's adoption fields and slot edit; the slot edit is the monitor's; the closed findings are round 2's
    resolutions."""
    status = _json(STATUS_PATH)
    _bound(lambda: type(status) is dict and tuple(status) == STATUS_KEYS
           and status["schemaVersion"] == "planeon.internal.i06-backend-profile-v4-status/v1"
           and status["workItem"] == "I06-RBAC-V4" and status["packet"] == NEW_PACKET
           and status["status"] == "ADOPTED" and status["candidate"] == 2 and status["adoption"] == ADOPTION
           and status["baseMain"] == BASE_COMMIT and status["reviewBase"] == REVIEW_BASE
           and status["independentReviewer"] == "SEPARATE_AGENT_NOT_AUTHOR"
           and all(type(status[key]) is str and status[key].strip() != "" for key in ("readmeStatusNote", "recordPaths"))
           and "no README line moved" in status["readmeStatusNote"]
           and "recorded here only, as slotEdit" in status["readmeStatusNote"]
           and status["closedFindings"] == CLOSED_FINDINGS and tuple(status["closedFindings"]) == tuple(CLOSED_FINDINGS)
           and status["nonClaims"] == NON_CLAIMS and type(status["carried"]) is list
           and all(type(row) is dict and tuple(row) == ("item", "to", "action") and type(row["action"]) is str
                   and row["action"].strip() != "" for row in status["carried"])
           and [(row["item"], row["to"]) for row in status["carried"]] == list(CARRIED),
           "adopted I06-RBAC-V4 status")
    _bound(lambda: type(status["slotEdit"]) is dict and tuple(status["slotEdit"]) == SLOT_EDIT_KEYS
           and status["slotEdit"] == dict(SLOT_EDIT) and status["slot"] == SLOT_EDIT["after"],
           "the slot edit is the monitor's: slot 253 -> 254, recorded as slotEdit")
    _bound(lambda: digest(candidate_status(status)) == CANDIDATE_SHA256[STATUS_PATH],
           "the status record is candidate 2's with only the adoption fields added")
    for path in SUBJECT:
        if path != V8_EDGE:
            require(digest(_verified(path)) == CANDIDATE_SHA256[path], "the adopted files are candidate 2: " + path)
    edge = _verified(V8_EDGE)
    _bound(lambda: edge.count(ASSIGNED) == 4 and TBD not in edge and edge.count(b"\n") == CANDIDATE_LINES
           and digest(edge.replace(ASSIGNED, TBD)) == CANDIDATE_SHA256[V8_EDGE],
           "edge record v8 is candidate 2 with exactly four providerPacket values set, on the same lines")
    edit = status["adoptionEdit"]
    _bound(lambda: type(status["adoptedSubject"]) is dict and tuple(status["adoptedSubject"]) == SUBJECT
           and status["adoptedSubject"] == {path: digest(_verified(path)) for path in SUBJECT}
           and type(edit) is dict and tuple(edit) == EDIT_KEYS
           and edit == {"path": V8_EDGE, "replaced": TBD.decode("ascii"), "with": ASSIGNED.decode("ascii"), "count": 4,
                        "rows": [row[0] for row in NEW_ROWS], "candidateSha256": CANDIDATE_SHA256[V8_EDGE],
                        "adoptedSha256": digest(edge), "lineCount": CANDIDATE_LINES},
           "the status records the adopted files and the one adoption edit")
    rounds = status["rounds"]
    _bound(lambda: type(rounds) is list and len(rounds) == len(ROUNDS)
           and all(type(row) is dict and tuple(row) == ROUND_KEYS for row in rounds)
           and [(row["round"], row["verdict"], row["subjectBuilderSha256"], row["record"], row["candidate"])
                for row in rounds] == [(number, verdict, builder, RECORDS[number - 1], number)
                                       for number, verdict, builder, _ids in ROUNDS],
           "two review rounds in order, the last on the adopted candidate 2")
    records = []
    for (number, verdict, builder, ids), row in zip(ROUNDS, rounds):
        record = _json(row["record"])
        _bound(lambda: type(record) is dict and digest(_verified(row["record"])) == row["recordSha256"]
               and type(row["subjectSha256"]) is dict and tuple(row["subjectSha256"]) == CANDIDATE_FILES
               and row["subjectSha256"] == dict(ROUND_SUBJECTS[number])
               and record["round"] == number and record["verdict"] == verdict
               and record["subject"] == SUBJECT_LINE % (number, builder, ROUND_SUBJECTS[number][V4_README])
               and record["reviewer"] == "independent agent" and record["actions"] == ACTIONS
               and tuple(finding["id"] for finding in record["findings"]) == ids
               and row["severities"] == sorted({finding["severity"] for finding in record["findings"]}),
               "review round %d is bound to its record and its subject candidate" % number)
        records.append(record)
    _bound(lambda: rounds[-1]["subjectSha256"] == dict(CANDIDATE_SHA256) and rounds[-1]["severities"] == ["NOTE"],
           "the passing round left NOTEs only, and reviewed candidate 2")
    checks = records[1]["checks"]

    def resolution(name: str) -> list:
        return [check["result"] for check in checks
                if check["check"].startswith(name + ",") or check["check"].startswith(name + " and ")]
    _bound(lambda: list(CLOSED_FINDINGS) == [name for row in ROUNDS for name in row[3]]
           and all(CLOSED_FINDINGS[name] == "CLOSED in round 2" and len(resolution(name)) == 1
                   and resolution(name)[0].startswith("RESOLVED.") for name in ROUNDS[0][3])
           and all(CLOSED_FINDINGS[name].startswith("CARRIED ") and CARRIED[n][0].split(" ")[0] == name
                   for n, name in enumerate(ROUNDS[1][3]))
           and any(check["check"].startswith("Replay over ") and check["result"].startswith("PASS. v4 check_vectors "
                                                                                             "gives 151 checks")
                   for check in checks),
           "the closed findings are round 2's resolutions")
    return status


def validate_source_index(status: dict) -> None:
    """The source index is round 2 over the accepted base; its earlier round is the status record's round 1; its R10
    inputs are the status record's cross-check commit; and every pin it holds (subject and predecessor inputs) holds over
    this era's bytes."""
    index = _json(V4_INDEX)
    _bound(lambda: type(index) is dict and tuple(index) == INDEX_KEYS
           and index["schemaVersion"] == "planeon.internal.i06-backend-profile-v4-index/v1" and index["round"] == 2
           and index["baseMain"] == REVIEW_BASE and index["baseTree"] == REVIEW_BASE_TREE
           and tuple(row["path"] for row in index["subject"]) == INDEX_SUBJECT
           and tuple(row["path"] for row in index["predecessorInputs"]) == INDEX_INPUTS
           and {key: index["r10Inputs"][key] for key in ("repository", "commit", "tree")}
           == {key: status["r10CrossCheck"][key] for key in ("repository", "commit", "tree")}
           and index["earlierRounds"] == [{key: row[key] for key in EARLIER_KEYS} for row in status["rounds"][:1]],
           "the source index is round 2 over the accepted base; round 1 is the published record")
    for key in ("subject", "predecessorInputs"):
        for row in index[key]:
            _bound(lambda: type(row) is dict and tuple(row) == ("path", "sha256") and row["path"] in ERA_SHA256
                   and digest(_verified(row["path"])) == row["sha256"],
                   "every source-index pin holds: %s" % (row.get("path") if type(row) is dict else row,))


def validate_edge_record_v8() -> None:
    """Edge record v8 supersedes v7 by its digest and packet and keeps v7's edge, rules, statuses and 62 rows exactly and
    in order; each of its four new rows registers its provider file's exact bytes and mode before use, under the R10
    contracts directory, with providerCommit null and providerPacket NEW_PACKET."""
    v7, v8 = _json(V7_EDGE), _json(V8_EDGE)
    _bound(lambda: digest(_verified(V7_EDGE)) == EDGE_V7_SHA256 and type(v8) is dict and tuple(v8) == EDGE_KEYS
           and v8["schemaVersion"] == v7["schemaVersion"] == "planeon.internal.artifact-edge-registry/v2"
           and all(v8[key] == v7[key] for key in ("graph", "consumer", "provider", "ownerDecision", "rules",
                                                   "notArtifacts", "statuses"))
           and v8["supersedes"] == {"path": V7_EDGE, "sha256": "sha256:" + EDGE_V7_SHA256, "packet": V7_PACKET}
           and v8["artifact"] == EDGE_ARTIFACT and _texts(v8["ownerDecisions"]) and _texts(v8["notes"]),
           "edge record v8 supersedes v7 by its digest and packet and keeps v7's edge, rules and statuses")
    _bound(lambda: len(v7["artifacts"]) == V7_ROWS and v8["artifacts"][:V7_ROWS] == v7["artifacts"]
           and all(list(row) == list(old) for row, old in zip(v8["artifacts"], v7["artifacts"]))
           and len(v8["artifacts"]) == V7_ROWS + len(NEW_ROWS),
           "edge record v8 carries v7's 62 rows exactly and in order")
    for number, (row, (path, commit, consumer, packet)) in enumerate(zip(v8["artifacts"][V7_ROWS:], NEW_ROWS),
                                                                      V7_ROWS + 1):
        _bound(lambda: tuple(row) == EDGE_ROW_KEYS and commit is None and path in NEW_FILES
               and row["providerPath"] == path and row["providerCommit"] is None and row["providerPacket"] == NEW_PACKET
               and row["consumerPath"] == consumer and consumer.startswith(CONSUMER_PREFIX)
               and row["consumerPacket"] == packet and row["relation"] == "BYTE_IDENTICAL"
               and row["status"] == "REGISTERED_BEFORE_USE"
               and row["sha256"] == digest(_verified(path)) and row["mode"] == _git_mode(reviewed_mode(path)) == "100644",
               "edge record v8 row %d registers its provider's exact bytes and mode before use: %s" % (number, path))
    providers = [row["providerPath"] for row in v8["artifacts"]]
    consumers = [row["consumerPath"] for row in v8["artifacts"][V7_ROWS:]]
    _bound(lambda: len(set(providers)) == len(providers) and len(set(consumers)) == len(consumers)
           and not set(consumers) & {row["consumerPath"] for row in v7["artifacts"]},
           "each provider path, and each new consumer path, is registered once")


def replay_models(m: types.SimpleNamespace) -> None:
    """The v4 model replays every vector over its pinned inputs, and I06 v3 its own as a control, each read through this
    era's verified bytes."""
    v4_vectors, v3_vectors = _json(V4_VECTORS), _json(V3_VECTORS)
    _bound(lambda: dict(m.i06v4.V4_INPUTS) == V4_INPUTS and dict(m.i06v4.VECTOR_COUNTS) == V4_COUNTS
           and {key: len(v4_vectors[key]) for key in V4_COUNTS} == V4_COUNTS
           and dict(m.i06v3.V3_INPUTS) == V3_INPUTS and {key: len(v3_vectors[key]) for key in V3_COUNTS} == V3_COUNTS,
           "the models' pinned inputs and the vectors' counts")
    v4_files = {path: _verified(path) for path in V4_INPUTS.values()}
    _bound(lambda: m.i06v4.check_vectors(v4_vectors, v4_files) == V4_CHECKS,
           "I06 v4 replays every vector over its pinned inputs")
    v3_files = {path: _verified(path) for path in V3_INPUTS.values()}
    _bound(lambda: m.i06v3.check_vectors(v3_vectors, v3_files) == V3_CHECKS,
           "I06 v3 replays every vector over its pinned inputs")


def validate_i06_backend_profile_v4() -> None:
    """Every reviewed byte first; then the freeze, the contract's files, the adoption record, the source index and edge
    record v8; then the v4 model (and I06 v3 as a control) from this era's bytes, replaying every vector; last, this
    layer's canonical hunks."""
    for path in ERA_SHA256:
        _verified(path)
    validate_freeze()
    validate_contract_files()
    status = validate_adoption()
    validate_source_index(status)
    validate_edge_record_v8()
    replay_models(era_modules())
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


def validate_canonical_hunks() -> None:
    """Q-PERF40-4: every hunk of this layer's authority is the canonical byte-minimal one, from this era's bytes."""
    for path, rule in _PROJECTION_RULES.items():
        after = reviewed_bytes(path)
        require(type(after) is bytes and digest(after) == rule["afterSha256"], "unreviewed current source: " + path)
        before = _undo_this_layer(path, after)
        require(canonical_hunks(after, before) == rule["reverseHunks"], "canonical byte-minimal inverse hunks: " + path)


def validate() -> None:
    record = authority()
    validator_raw = successor.historical_bytes(VALIDATOR_PATH, regular_bytes(VALIDATOR_PATH))
    literal = b'AUTHORITY_SHA256 = "' + AUTHORITY_SHA256.encode("ascii") + b'"'
    placeholder = b'AUTHORITY_SHA256 = "TO_BE_PINNED_AFTER_SOURCE_FREEZE"'
    require(validator_raw.count(literal) == 1
            and digest(validator_raw.replace(literal, placeholder))
            == record["validatorNormalizedSha256"], "i06 backend profile v4 validator drift")
    paths = sorted((ROOT / "task-packets").glob("*.yaml"))
    old = set(record["baselinePackets"])
    require(len(paths) == 269
            and {path.stem for path in paths} == old | {NEW_PACKET, successor.NEW_PACKET, successor.successor.NEW_PACKET, successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.NEW_PACKET},
            "closed 269-packet catalog retaining the 254-packet checkpoint")
    packets = {}
    for path in paths:
        if path.stem in (successor.NEW_PACKET, successor.successor.NEW_PACKET, successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.NEW_PACKET):
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
            "closed source-only i06-backend-profile-v4 packet and inherited commands")
    require(len(packet["allowedPaths"]) == len(set(packet["allowedPaths"]))
            and set(packet["allowedPaths"]) == set(record["changedFiles"])
            | set(record["newFiles"]) | {AUTHORITY_PATH, VALIDATOR_PATH,
                                         "task-packets/" + NEW_PACKET + ".yaml"},
            "unreviewed or omitted i06-backend-profile-v4 packet path")
    for path, rule in record["changedFiles"].items():
        current = successor.historical_bytes(path, regular_bytes(path))
        require(digest(current) == rule["afterSha256"]
                and digest(historical_bytes(path, current)) == rule["beforeSha256"],
                "unreviewed current source: " + path)
    for path, expected in record["newFiles"].items():
        require(digest(successor.historical_bytes(path, regular_bytes(path))) == expected,
                "new source drift: " + path)
    validate_i06_backend_profile_v4()


if __name__ == "__main__":
    validate()
    print("I06 backend profile v4 valid: 269 current specifications; 254-packet checkpoint and exact 253-packet predecessor; contract reviewed.")
