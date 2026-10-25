#!/usr/bin/env python3
"""Validate the MET-ENFORCE-040 operator edge record v9 (the I01 wire schema and vectors, registered before use) and the exact 256-to-255 projection."""
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
    import validate_evolution_surface as successor
except ImportError:
    from scripts.safe_yaml import safe_load
    from scripts import validate_evolution_surface as successor


ROOT = Path(__file__).resolve().parents[1]
AUTHORITY_PATH = "architecture/edge-record-v9-authority.json"
AUTHORITY_SHA256 = "2a7f76e8d8dfb8eea9af0744f247bb43de14d5b2b86e03591148ce0ac70fd5ca"
VALIDATOR_PATH = "scripts/validate_edge_record_v9.py"
BASE_COMMIT = "6835a6edf7137ba11d4aed4b93c02be4c8694369"
NEW_PACKET = "MET-ENFORCE-040"
PREVIOUS_PACKET = "MET-PERF-042"
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
            require(key not in result, "duplicate edge-record-v9 authority member")
            result[key] = value
        return result

    def no_constant(_value: str) -> Any:
        raise ValueError("nonfinite edge-record-v9 authority number")

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
        require(digest(raw) == AUTHORITY_SHA256, "edge record v9 history authority digest")
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
    }, "closed edge record v9 history authority")
    require(value["schemaVersion"] == "harness.planeon.ai/edge-record-v9-authority/v1"
            and value["authorityPacket"] == NEW_PACKET
            and value["acceptedBase"] == BASE_COMMIT
            and type(value["baselinePackets"]) is dict
            and len(value["baselinePackets"]) == 255
            and NEW_PACKET not in value["baselinePackets"]
            and type(value["changedFiles"]) is dict
            and type(value["newFiles"]) is dict
            and _sha(value["packetSha256"])
            and _sha(value["validatorNormalizedSha256"]),
            "accepted 255-packet base")
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
    # An exact 255-era byte string is already older than the successor layer.
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


# MET-ENFORCE-040 (roadmap EDGE-V9; candidate 2 adopted by the lane monitor, owner-delegated, 2026-10-22, after two
# independent contract review rounds, the second PASS_FOR_ADOPTION) publishes the operator -> harness-engineering edge
# record v9: edge record v8's 66 rows plus 2 that register the I01 wire's channel schema and vectors
# (architecture/policy-observation-inputs/, MET-REPAIR-010) before HE-004-I01 vendors them under
# host-enforcement/contracts/i01-v1/ (owner decisions Q-HE4I1-10 (a) and Q-I01A-1; the lane monitor's owner-delegated
# Q-EV9-1 to Q-EV9-5 and Q-EV9-1b, all as recommended). It is the first packet built under MET-PERF-042's identity rule
# and step rule. Repository bytes and modes are read only through reviewed_bytes and reviewed_mode, and the record
# directory's listing only through reviewed_tree, so a later bridged successor projects its own edits away first; a path
# outside this era is refused before it is read, and every era file is bound by digest on every read. Each refusal is a
# pure check over the values read, so every one has a failing case on plain data. Checked here: the freeze (edge records
# v1 to v8 with their READMEs and the two provider files are this era's bytes, this packet changes none of them, and
# under architecture/artifact-edges/ it adds only v9's two files); the files this packet adds (new, each once; the
# record directory architecture/edge-record-v9/ closed; mode 100644; no absolute local path); the adoption (the two
# contract files are the adopted candidate 2's bytes; the status record's closed shape and values; the two review rounds
# bound to their published records by digest, each record's subject equal to its round's; the verbatim adoption
# decision; the slip record; the closed findings as round 2 resolved them and the carried rows); and edge record v9
# (v8's 66 rows exactly and in order; the 2 new rows BYTE_IDENTICAL and REGISTERED_BEFORE_USE with their providers'
# exact bytes and mode 100644, the consumer paths under the R10 contracts directory, consumer HE-004-I01 and no
# providerPacket; v8 superseded by digest and packet; v8's decision, rules, exclusions and statuses kept, and every key
# in v8's order). This layer cannot read git history: the contract builder proved each new row's providerCommit (the
# file's last-change commit at the accepted base) from git, and this layer restates it and checks the files' bytes and
# modes, as 244's split did. Last, this layer's own inverse hunks are the canonical byte-minimal ones, recomputed from
# its era's bytes (MET-PERF-040's carried rule).
EDGES_DIR = "architecture/artifact-edges/"
RECORD_DIR = "architecture/edge-record-v9"
V8_EDGE = EDGES_DIR + "operator-harness-engineering-v8.json"
V9_EDGE = EDGES_DIR + "operator-harness-engineering-v9.json"
V9_README = EDGES_DIR + "README-v9.md"
STATUS_PATH = RECORD_DIR + "/status.json"
RECORDS = (RECORD_DIR + "/review-round1.json", RECORD_DIR + "/review-round2.json")
# The adopted subject (candidate 2; review round 2, PASS_FOR_ADOPTION) and the record directory's three files.
SUBJECT = (V9_EDGE, V9_README)
RECORD_FILES = (STATUS_PATH,) + RECORDS
NEW_FILES = SUBJECT + RECORD_FILES
ADOPTED_SHA256 = MappingProxyType({
    V9_EDGE: "197f30e4e1e0be1dcacd71f1095c91e2333fe9d6ea05b8194578160e471605d7",
    V9_README: "8cde7d199a00dd19edd9b8fc699b4f065d730ab245af7af77edca9e32a8fbf09",
})
# The two provider files the new rows register, and the R10 directory HE-004-I01 vendors them into (Q-EV9-2 (a)).
PROVIDERS = ('architecture/policy-observation-inputs/channel.schema.json',
 'architecture/policy-observation-inputs/vectors.json')
PROVIDER_COMMIT = "108e61953d522106db7c8de65ee19120a952853b"
CONSUMER_PREFIX = "host-enforcement/contracts/i01-v1/"
CONSUMER_PACKET = "HE-004-I01"
# Edge record v9's two new rows: (provider path, provider commit, consumer path, consumer packet). Each commit is the
# file's last-change commit at the accepted base, proved from git by the contract builder (this layer reads no history).
NEW_ROWS = (('architecture/policy-observation-inputs/channel.schema.json',
  '108e61953d522106db7c8de65ee19120a952853b',
  'host-enforcement/contracts/i01-v1/channel.schema.json',
  'HE-004-I01'),
 ('architecture/policy-observation-inputs/vectors.json',
  '108e61953d522106db7c8de65ee19120a952853b',
  'host-enforcement/contracts/i01-v1/vectors.json',
  'HE-004-I01'))
EDGE_V8_SHA256 = "623cf10bf19cfba1806f5699007f39c7f6ba38f72d92069548421c4dccd21573"
# Edge record v8's packet (254's), which v9 supersedes.
V8_PACKET = "MET-ENFORCE-039"
V8_ROWS = 66
EDGE_SCHEMA = "planeon.internal.artifact-edge-registry/v2"
EDGE_ARTIFACT = "policy-observation-i01-wire"
EDGE_KEYS = ("schemaVersion", "graph", "consumer", "provider", "artifact", "ownerDecision", "rules", "notArtifacts",
             "statuses", "artifacts", "supersedes", "ownerDecisions", "notes")
KEPT_KEYS = ("schemaVersion", "graph", "consumer", "provider", "ownerDecision", "rules", "notArtifacts", "statuses")
EDGE_ROW_KEYS = ("providerPath", "providerCommit", "sha256", "mode", "consumerPath", "consumerPacket", "relation",
                 "status")
SUPERSEDES_KEYS = ("path", "sha256", "packet")
# The record's eight quoted decisions, in order, by their verbatim openings: owner Q-HE4I1-10 (a) and Q-I01A-1, then the
# lane monitor's Q-EV9-1 (a) to Q-EV9-5 (a) and Q-EV9-1b (a).
DECISION_OPENINGS = ('Q-HE4I1-10 (owner via the lane monitor, 2026-10-21, verbatim): "10 (a):',
 'Q-I01A-1 (owner via the lane monitor, 2026-10-21, verbatim): "Q-I01A-1:',
 'Q-EV9 (the lane monitor, owner-delegated, 2026-10-22, verbatim): "Q-EV9-1 (a):',
 'Q-EV9 (the lane monitor, owner-delegated, 2026-10-22, verbatim): "Q-EV9-2 (a):',
 'Q-EV9 (the lane monitor, owner-delegated, 2026-10-22, verbatim): "Q-EV9-3 (a):',
 'Q-EV9 (the lane monitor, owner-delegated, 2026-10-22, verbatim): "Q-EV9-4:',
 'Q-EV9 (the lane monitor, owner-delegated, 2026-10-22, verbatim): "Q-EV9-5 (a):',
 'Q-EV9 (the lane monitor, owner-delegated, 2026-10-22, verbatim): "Q-EV9-1b = (a)**, monitor decision '
 '(owner-delegated):')
# Edge records v1 to v8 and their READMEs (exact paths; never a listing there) and the two provider files stay
# byte-identical: each is bound by its digest below, and no file this packet changes or adds is one of them.
FROZEN_EDGES = ('architecture/artifact-edges/README.md',
 'architecture/artifact-edges/README-v2.md',
 'architecture/artifact-edges/README-v3.md',
 'architecture/artifact-edges/README-v4.md',
 'architecture/artifact-edges/README-v5.md',
 'architecture/artifact-edges/README-v6.md',
 'architecture/artifact-edges/README-v7.md',
 'architecture/artifact-edges/README-v8.md',
 'architecture/artifact-edges/operator-harness-engineering.json',
 'architecture/artifact-edges/operator-harness-engineering-v2.json',
 'architecture/artifact-edges/operator-harness-engineering-v3.json',
 'architecture/artifact-edges/operator-harness-engineering-v4.json',
 'architecture/artifact-edges/operator-harness-engineering-v5.json',
 'architecture/artifact-edges/operator-harness-engineering-v6.json',
 'architecture/artifact-edges/operator-harness-engineering-v7.json',
 'architecture/artifact-edges/operator-harness-engineering-v8.json')
FROZEN_PATHS = FROZEN_EDGES + PROVIDERS
# The status record written at adoption: its closed key sets and its values, restated.
STATUS_SCHEMA = "planeon.internal.edge-record-v9-status/v1"
SLOT = 256
STATUS_KEYS = ("schemaVersion", "workItem", "packet", "slot", "status", "adoption", "baseMain", "adoptedSubject",
               "builder", "independentReviewer", "rounds", "closedFindings", "carried", "slips", "nonClaims")
ADOPTION_KEYS = ("decidedBy", "date", "decision")
# The lane monitor's owner-delegated adoption, verbatim (the decisions record's 2026-10-22 adoption section).
ADOPTION = {'decidedBy': 'the lane monitor, owner-delegated',
 'date': '2026-10-22',
 'decision': '[lane monitor] **ADOPTED**: EDGE-V9 candidate 2 as is (edge v9 197f30e4, README-v9 8cde7d19, '
             'builder 6573f4d0). Monitor decision (owner-delegated), on delta r2 PASS_FOR_ADOPTION.'}
BUILDER_KEYS = ("path", "sha256", "rerunAtBase")
BUILDER = {'path': "build_contract.py (kept with the lane's records)",
 'sha256': '6573f4d00ccd86bb182ef9244c3709c95edbb4f17472a0d28cd0ac44738d6de9',
 'rerunAtBase': 'E1-4: candidate 2 was built at 6835a6edf7137ba11d4aed4b93c02be4c8694369 (MET-PERF-042 '
                'merged) and its two runs were byte-identical; adoption re-checked edge v8, both provider '
                'files and the free paths there, by exact path'}
ROUND_KEYS = ("round", "record", "recordSha256", "verdict", "base", "subjectSha256", "builderSha256", "briefSha256",
              "severities")
SEVERITY_KEYS = ("MAJOR", "MINOR", "NOTE")
# (round, verdict, base, the subject candidate's builder SHA-256, the review brief's SHA-256, the finding ids) in order;
# round 1 reviewed candidate 1 at 254's merge, round 2 the adopted candidate 2 at this packet's base.
ROUNDS = ((1,
  'CHANGES_REQUIRED',
  '29c84b36dad2f6f9822b71cd959064f0202d9868',
  '6920125293ad6234af3363ebd65562d23ed7b1f1f09a8d073e68a79ceec3f1cc',
  '312b33ad46a2ac320dabfb4e7b558e42934be1d248795692d85ffba3be324696',
  ('E1-1', 'E1-2', 'E1-3', 'E1-4', 'E1-5')),
 (2,
  'PASS_FOR_ADOPTION',
  '6835a6edf7137ba11d4aed4b93c02be4c8694369',
  '6573f4d00ccd86bb182ef9244c3709c95edbb4f17472a0d28cd0ac44738d6de9',
  'e5389095f8c6aa89dc928092649819f5436830ffcabc348182c79a375ddc7822',
  ('E2-1', 'E2-2')))
ROUND_SUBJECTS = MappingProxyType({
    1: MappingProxyType({
        V9_EDGE: "6d4f92f70cfb97686f23389e00a25b3eb20b72257abad3b38c8684edbda35826",
        V9_README: "a5f34c9ef92015903431910b09d08d61c031542c17f700b7a24709d38504b502",
    }),
    2: ADOPTED_SHA256,
})
# Each published review record's closed key order, and its subject line's keys.
RECORD_KEYS = MappingProxyType({1: ('subject', 'reviewer', 'verdict', 'findings', 'checks', 'actions'),
 2: ('round', 'subject', 'reviewer', 'verdict', 'round1Resolutions', 'findings', 'checks', 'actions')})
SUBJECT_KEYS = ("edgeV9Sha256", "readmeV9Sha256", "builderSha256", "base")
ACTIONS = {"filesEdited": False, "networkAccessed": "none", "personalDataSent": False, "edgeDirListed": False}
RESOLUTION_KEYS = ("id", "status", "evidence")
CLOSED_FINDINGS = {'E1-1': 'CLOSED in round 2 (Q-EV9-1b (a): the readiness doc named as deliberately unregistered)',
 'E1-2': 'CLOSED in round 2 (the replay-scope note)',
 'E1-3': 'CLOSED in round 2 (every added path checked free by exact path)',
 'E1-4': 'CLOSED in round 2 (the builder re-run at the mechanics base)',
 'E1-5': 'DISCHARGED at adoption (recorded below)'}
CARRIED_KEYS = ("item", "to", "action")
CARRIED = (('E2-1 (contract review round 2, NOTE)', 'kept as adopted'),
 ('E2-2 (contract review round 2, NOTE)', "the lane's builder"),
 ("255's identity rule (E1-4)", "this packet's pre-check and verify"))
# The monitor's slip ruling, recorded at adoption (MON-256-LSTREE-SLIP).
SLIP_KEYS = ("id", "ruling", "what")
SLIPS = ({'id': 'MON-256-LSTREE-SLIP',
  'ruling': 'accepted by the lane monitor, 2026-10-22',
  'what': 'while checking that v9 was free, the author listed architecture/artifact-edges/ at the base and '
          'printed only the count of matching names (0); no name was shown or used; it was re-checked by '
          'exact path, and every later check is by exact path only'},)
NON_CLAIMS = ('Edge records v1 to v8 and EDGE-2 are byte-identical.',
 "No R10 file changes in this packet; HE-004-I01's U7 vendors the two registered files later.",
 'docs/alpha-2/POLICY_OBSERVATION_READINESS.md and architecture/proxy-contract-inputs/vectors.json are not '
 'registered (Q-EV9-1b (a); the replay-scope note).')
# Every file this era's check reads, with its digest: the five files this packet adds, edge records v1 to v8 with their
# READMEs, and the two provider files.
ERA_SHA256 = MappingProxyType({
    "architecture/artifact-edges/README-v2.md": "0cded3e3499b8afe64c82a021a8a499c9b2fce5671ea5ae434b3330c26db3a2b",
    "architecture/artifact-edges/README-v3.md": "d6edd8cc7f8b209c1cf7bd0a16a941e0661ef040f8920cbdbda4c323c0f0f011",
    "architecture/artifact-edges/README-v4.md": "11e6bbefc27d82d359c7f48a873374786a760881693fd7d9ec7e88916ab2558b",
    "architecture/artifact-edges/README-v5.md": "6409a17c2fb0b5ae5df3055c86a3e4cb1e2cb3deacd490c4d547cc1d50a9b6ad",
    "architecture/artifact-edges/README-v6.md": "ce15ee36e15964a08fc83a495f2bd453ebe375c77e37d386f00c2803ec4e73f7",
    "architecture/artifact-edges/README-v7.md": "7131d500eac2085871254a250a4a84c24b17456891dd5f3b2478d85153f1a378",
    "architecture/artifact-edges/README-v8.md": "e5dea489087b0d58c9e1559ce6ee1a07ef2e7567a9d04841d80b3f20e67dc0d9",
    "architecture/artifact-edges/README-v9.md": "8cde7d199a00dd19edd9b8fc699b4f065d730ab245af7af77edca9e32a8fbf09",
    "architecture/artifact-edges/README.md": "5d62a665da2c6e75dce900cb4ef52e74aa14e537bdaeededb7568589339daa9f",
    "architecture/artifact-edges/operator-harness-engineering-v2.json": "749e70f174d638468bf45d7316e8f5201c3323f6348a78c7b9a22d3a571ccc32",
    "architecture/artifact-edges/operator-harness-engineering-v3.json": "106ea91aa09c2d377adf3b514a228331d6a805bd1a17e641ecaa23b3c39115f3",
    "architecture/artifact-edges/operator-harness-engineering-v4.json": "e30772ff8826650c46d1a8d384625929975e47f2de5cc9030680b5fdb5e7fc86",
    "architecture/artifact-edges/operator-harness-engineering-v5.json": "89b47ef8f865b31911eb8da2b08a5a3c22b2d92a62599cb6fdfccbfe7f79e3c0",
    "architecture/artifact-edges/operator-harness-engineering-v6.json": "0ac7c2da62de87837f5a36a967a2c5b9c286ecab2e03f335a8eebbd32df9d24d",
    "architecture/artifact-edges/operator-harness-engineering-v7.json": "6af45e361a66331a9ee0216d3eea42f3a17770fd3c7d33e78e2a025d301bfa92",
    "architecture/artifact-edges/operator-harness-engineering-v8.json": "623cf10bf19cfba1806f5699007f39c7f6ba38f72d92069548421c4dccd21573",
    "architecture/artifact-edges/operator-harness-engineering-v9.json": "197f30e4e1e0be1dcacd71f1095c91e2333fe9d6ea05b8194578160e471605d7",
    "architecture/artifact-edges/operator-harness-engineering.json": "54bdc2d22676720419f51cd1bad5eedc909e6f848ed09cd363e351889af9d1fe",
    "architecture/edge-record-v9/review-round1.json": "0265457922a7074cff647b73749936f1556b9bc341d3fbc4c73df1165f30290b",
    "architecture/edge-record-v9/review-round2.json": "220c77f3a305bd9608c2fd307c250f36880d8b143597c15115d899e6bc046cdd",
    "architecture/edge-record-v9/status.json": "1ad0cdfee8c1b8b2578826240c1e82ed423ef6ee10da22a6ef500d115af9c06c",
    "architecture/policy-observation-inputs/channel.schema.json": "fb69b77201d9b6275a19667a5f5770537f382ddb11309095733628c8430bdc0e",
    "architecture/policy-observation-inputs/vectors.json": "1bfb46776636f800e38ab6a8f94a0989aa38513fb4a28ef18e61e732a115c124",
})
# Absolute local path markers, matched case-insensitively; spelled in parts, so this file holds none of them. A marker
# counts when a path character follows it, so a review record's own list of the patterns it scanned for (round 2's
# hygiene check names them, each followed by a comma) is not a path, as the adoption's own check allowed.
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
    require(expected is not None, "MET-ENFORCE-040 reviewed bytes are bound: " + str(path))
    require(type(raw) is bytes and digest(raw) == expected, "unreviewed EDGE-V9 source: " + path)
    return raw


def _verified(path: str) -> bytes:
    """reviewed_bytes, checked against its era digest on every read; a path outside the era is refused before it is
    read."""
    require(type(path) is str and path in ERA_SHA256, "MET-ENFORCE-040 reviewed bytes are bound: " + str(path))
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


def _texts(values: Any) -> bool:
    return type(values) is list and len(values) > 0 and all(type(text) is str and text.strip() != "" for text in values)


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
    """No file this packet changes or adds is an edge record v1 to v8, their READMEs or a provider file, and under
    architecture/artifact-edges/ it adds only v9's two files."""
    for path in list(changed) + list(added):
        require(type(path) is str and path not in FROZEN_PATHS
                and (not path.startswith(EDGES_DIR) or (path in SUBJECT and path in added and path not in changed)),
                "edge records v1 to v8, their READMEs and the two provider files stay byte-identical, and only v9's "
                "two files are added under architecture/artifact-edges/: " + str(path))


def check_new_files(added: Any, changed: Any) -> None:
    """The packet adds the contract's two files and the three records as new files, each once."""
    _bound(lambda: len(set(NEW_FILES)) == len(NEW_FILES) and not set(NEW_FILES) & set(changed)
           and {path for path in added if path.startswith(EDGES_DIR) or path.startswith(RECORD_DIR + "/")}
           == set(NEW_FILES), "the contract's files and records are new in this packet, each once")


def check_record_tree(mode: Any, tree: Any) -> None:
    """The record directory is a directory (not a link) holding exactly its three records, each a regular file of git
    mode 100644."""
    require(type(mode) is int and stat.S_ISDIR(mode), "the record directory is a directory, not a link")
    _bound(lambda: type(tree) is dict and sorted(tree) == sorted(RECORD_FILES)
           and all(_git_mode(entry) == "100644" for entry in tree.values()),
           "the record directory holds exactly its three records, each of mode 100644")


def check_added_file(path: str, mode: Any, raw: Any) -> None:
    """A file this packet adds is a regular file of git mode 100644 (not a link, not executable) and holds no absolute
    local path."""
    require(type(mode) is int and _git_mode(mode) == "100644",
            "a file this packet adds is a regular file of git mode 100644: " + path)
    require(type(raw) is bytes and not _local_path(raw), "no absolute local path in a file this packet adds: " + path)


def validate_files() -> None:
    """The freeze, the files this packet adds and the record directory, from this era's authority, modes and listing."""
    record = authority()
    check_freeze(list(_PROJECTION_RULES), list(record["newFiles"]))
    check_new_files(list(record["newFiles"]), list(_PROJECTION_RULES))
    check_record_tree(reviewed_mode(RECORD_DIR), reviewed_tree(RECORD_DIR))
    for path in NEW_FILES:
        check_added_file(path, reviewed_mode(path), _verified(path))


def check_status(status: Any) -> None:
    """The status record's closed shape and values: EDGE-V9 adopted as MET-ENFORCE-040 at slot 256 on this era's
    base, by a separate reviewer, with the adopted subject, the builder and the non-claims as adopted; the adoption
    decision verbatim; the slip record present."""
    _bound(lambda: type(status) is dict and tuple(status) == STATUS_KEYS and status["schemaVersion"] == STATUS_SCHEMA
           and status["workItem"] == "EDGE-V9" and status["packet"] == NEW_PACKET and status["slot"] == SLOT
           and type(status["slot"]) is int and status["status"] == "ADOPTED" and status["baseMain"] == BASE_COMMIT
           and status["independentReviewer"] == "SEPARATE_AGENT_NOT_AUTHOR"
           and tuple(status["adoptedSubject"]) == SUBJECT and status["adoptedSubject"] == dict(ADOPTED_SHA256)
           and tuple(status["builder"]) == BUILDER_KEYS and status["builder"] == BUILDER
           and status["nonClaims"] == list(NON_CLAIMS), "adopted EDGE-V9 status")
    _bound(lambda: tuple(status["adoption"]) == ADOPTION_KEYS and status["adoption"] == ADOPTION,
           "the adoption is the lane monitor's decision, verbatim")
    _bound(lambda: type(status["slips"]) is list and len(status["slips"]) == len(SLIPS)
           and all(tuple(row) == SLIP_KEYS for row in status["slips"])
           and status["slips"] == [dict(row) for row in SLIPS], "the slip record is present: MON-256-LSTREE-SLIP")


def check_subject(path: str, raw: Any) -> None:
    require(path in ADOPTED_SHA256 and type(raw) is bytes and digest(raw) == ADOPTED_SHA256[path],
            "the contract files are the adopted candidate 2: " + path)


def check_rounds(rounds: Any) -> None:
    """Two rounds in order; the last passed with NOTEs only, on the adopted candidate 2."""
    _bound(lambda: type(rounds) is list and [row["round"] for row in rounds] == [row[0] for row in ROUNDS]
           and rounds[-1]["verdict"] == "PASS_FOR_ADOPTION" and rounds[-1]["subjectSha256"] == dict(ADOPTED_SHA256)
           and rounds[-1]["severities"]["MAJOR"] == rounds[-1]["severities"]["MINOR"] == 0
           and rounds[-1]["severities"]["NOTE"] > 0,
           "two review rounds in order; the passing round left NOTEs only and reviewed the adopted candidate 2")


def check_round(number: int, row: Any, record: Any, raw: Any) -> None:
    """Review round `number` is bound to its published record by digest; the record's subject (the candidate's two
    files, its builder and its base), verdict, reviewer, actions and findings are the round's."""
    _, verdict, base, builder, brief, ids = ROUNDS[number - 1]
    subject = ROUND_SUBJECTS[number]
    _bound(lambda: type(row) is dict and tuple(row) == ROUND_KEYS and row["round"] == number
           and row["record"] == RECORDS[number - 1] and type(raw) is bytes and digest(raw) == row["recordSha256"]
           and row["verdict"] == verdict and row["base"] == base and row["builderSha256"] == builder
           and row["briefSha256"] == brief and tuple(row["subjectSha256"]) == SUBJECT
           and row["subjectSha256"] == dict(subject) and type(record) is dict and tuple(record) == RECORD_KEYS[number]
           and record.get("round", number) == number and tuple(record["subject"]) == SUBJECT_KEYS
           and record["subject"] == {"edgeV9Sha256": subject[V9_EDGE], "readmeV9Sha256": subject[V9_README],
                                     "builderSha256": builder, "base": base}
           and record["verdict"] == verdict and record["reviewer"] == "independent agent"
           and record["actions"] == ACTIONS and tuple(finding["id"] for finding in record["findings"]) == ids
           and tuple(row["severities"]) == SEVERITY_KEYS
           and row["severities"] == {name: len([finding for finding in record["findings"]
                                                if finding["severity"] == name]) for name in SEVERITY_KEYS},
           "review round %d is bound to its record and its subject" % number)


def check_findings(status: Any, records: Any) -> None:
    """The closed findings are round 2's resolutions of round 1's findings (RESOLVED ones closed in round 2, the CARRIED
    one discharged at adoption); the carried rows are round 2's two notes and the identity rule's carry, each with its
    action."""
    _bound(lambda: tuple(status["closedFindings"]) == tuple(CLOSED_FINDINGS)
           and status["closedFindings"] == CLOSED_FINDINGS
           and tuple(CLOSED_FINDINGS) == ROUNDS[0][5]
           and [row["id"] for row in records[1]["round1Resolutions"]] == list(ROUNDS[0][5])
           and all(tuple(row) == RESOLUTION_KEYS and type(row["evidence"]) is str and row["evidence"].strip() != ""
                   and row["status"] in ("RESOLVED", "CARRIED")
                   and CLOSED_FINDINGS[row["id"]].startswith("CLOSED in round 2" if row["status"] == "RESOLVED"
                                                             else "DISCHARGED at adoption")
                   for row in records[1]["round1Resolutions"]),
           "the closed findings are round 2's resolutions")
    _bound(lambda: type(status["carried"]) is list
           and all(tuple(row) == CARRIED_KEYS and type(row["action"]) is str and row["action"].strip() != ""
                   for row in status["carried"])
           and [(row["item"], row["to"]) for row in status["carried"]] == list(CARRIED)
           and tuple(item.split(" ")[0] for item, _ in CARRIED[:2]) == ROUNDS[1][5],
           "the carried rows are round 2's notes and the identity rule's carry, each with its action")


def validate_adoption() -> None:
    """The status record, the adopted files, the two rounds with their published records, and the findings."""
    status = _json(STATUS_PATH)
    check_status(status)
    for path in SUBJECT:
        check_subject(path, _verified(path))
    check_rounds(status["rounds"])
    records = []
    for number, row in enumerate(status["rounds"], 1):
        raw = _verified(RECORDS[number - 1])
        records.append(parse(raw))
        check_round(number, row, records[-1], raw)
    check_findings(status, records)


def check_edge_record(v8: Any, v9: Any, v8_raw: Any, providers: Any) -> None:
    """Edge record v9 supersedes v8 by its digest and packet, keeps v8's decision, rules, exclusions, statuses and key
    order and v8's 66 rows exactly and in order; each new row registers its provider file's exact bytes and mode before
    use, under the R10 contracts directory, with its restated last-change commit and no providerPacket."""
    _bound(lambda: type(v8_raw) is bytes and digest(v8_raw) == EDGE_V8_SHA256 and type(v9) is dict
           and tuple(v9) == tuple(v8) == EDGE_KEYS and v9["schemaVersion"] == EDGE_SCHEMA
           and all(v9[key] == v8[key] for key in KEPT_KEYS) and tuple(v9["supersedes"]) == SUPERSEDES_KEYS
           and v9["supersedes"] == {"path": V8_EDGE, "sha256": "sha256:" + EDGE_V8_SHA256, "packet": V8_PACKET}
           and v9["artifact"] == EDGE_ARTIFACT and _texts(v9["notes"]) and _texts(v9["ownerDecisions"])
           and len(v9["ownerDecisions"]) == len(DECISION_OPENINGS)
           and all(text.startswith(opening) for text, opening in zip(v9["ownerDecisions"], DECISION_OPENINGS)),
           "edge record v9 supersedes v8 by its digest and packet and keeps v8's decision, rules, exclusions, statuses "
           "and key order")
    _bound(lambda: len(v8["artifacts"]) == V8_ROWS and v9["artifacts"][:V8_ROWS] == v8["artifacts"]
           and all(list(row) == list(old) for row, old in zip(v9["artifacts"], v8["artifacts"]))
           and len(v9["artifacts"]) == V8_ROWS + len(NEW_ROWS),
           "edge record v9 carries v8's 66 rows exactly and in order")
    for number, (row, spec) in enumerate(zip(v9["artifacts"][V8_ROWS:], NEW_ROWS), V8_ROWS + 1):
        path, commit, consumer, packet = spec
        _bound(lambda: type(row) is dict and tuple(row) == EDGE_ROW_KEYS and path in PROVIDERS
               and row["providerPath"] == path and row["providerCommit"] == commit == PROVIDER_COMMIT
               and row["consumerPath"] == consumer and consumer == CONSUMER_PREFIX + path.split("/")[-1]
               and row["consumerPacket"] == packet == CONSUMER_PACKET and row["relation"] == "BYTE_IDENTICAL"
               and row["status"] == "REGISTERED_BEFORE_USE" and type(providers[path][0]) is bytes
               and row["sha256"] == digest(providers[path][0]) and type(providers[path][1]) is int
               and row["mode"] == _git_mode(providers[path][1]) == "100644",
               "edge record v9 row %d registers its provider's exact bytes and mode before use: %s" % (number, path))


def check_registered_once(v8: Any, v9: Any) -> None:
    providers = [row["providerPath"] for row in v9["artifacts"]]
    consumers = [row["consumerPath"] for row in v9["artifacts"][V8_ROWS:]]
    _bound(lambda: len(set(providers)) == len(providers) and len(set(consumers)) == len(consumers)
           and not set(consumers) & {row["consumerPath"] for row in v8["artifacts"]},
           "each provider path, and each new consumer path, is registered once")


def validate_edge_record() -> None:
    """Edge record v9 against v8's era bytes and the two provider files' era bytes and modes."""
    v8_raw = _verified(V8_EDGE)
    v8, v9 = parse(v8_raw), _json(V9_EDGE)
    providers = {path: (_verified(path), reviewed_mode(path)) for path in PROVIDERS}
    check_edge_record(v8, v9, v8_raw, providers)
    check_registered_once(v8, v9)


def validate_edge_record_v9() -> None:
    """Every reviewed byte first; then the freeze and the files this packet adds, the adoption and edge record v9; last,
    this layer's canonical hunks."""
    for path in ERA_SHA256:
        _verified(path)
    validate_files()
    validate_adoption()
    validate_edge_record()
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
            == record["validatorNormalizedSha256"], "edge record v9 validator drift")
    paths = sorted((ROOT / "task-packets").glob("*.yaml"))
    old = set(record["baselinePackets"])
    require(len(paths) == 266
            and {path.stem for path in paths} == old | {NEW_PACKET, successor.NEW_PACKET, successor.successor.NEW_PACKET, successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.NEW_PACKET},
            "closed 266-packet catalog retaining the 256-packet checkpoint")
    packets = {}
    for path in paths:
        if path.stem in (successor.NEW_PACKET, successor.successor.NEW_PACKET, successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.NEW_PACKET):
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
            "closed source-only edge-record-v9 packet and inherited commands")
    require(len(packet["allowedPaths"]) == len(set(packet["allowedPaths"]))
            and set(packet["allowedPaths"]) == set(record["changedFiles"])
            | set(record["newFiles"]) | {AUTHORITY_PATH, VALIDATOR_PATH,
                                         "task-packets/" + NEW_PACKET + ".yaml"},
            "unreviewed or omitted edge-record-v9 packet path")
    for path, rule in record["changedFiles"].items():
        current = successor.historical_bytes(path, regular_bytes(path))
        require(digest(current) == rule["afterSha256"]
                and digest(historical_bytes(path, current)) == rule["beforeSha256"],
                "unreviewed current source: " + path)
    for path, expected in record["newFiles"].items():
        require(digest(successor.historical_bytes(path, regular_bytes(path))) == expected,
                "new source drift: " + path)
    validate_edge_record_v9()


if __name__ == "__main__":
    validate()
    print("Edge record v9 valid: 266 current specifications; 256-packet checkpoint and exact 255-packet predecessor; contract reviewed.")
