#!/usr/bin/env python3
"""Validate the MET-ENFORCE-041 I01 digest contract (the seven projection objects and four enforcement digests, DATA_CHECK_ONLY) with operator edge record v10, and the exact 258-to-257 projection."""
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
    import validate_review_record as successor
except ImportError:
    from scripts.safe_yaml import safe_load
    from scripts import validate_review_record as successor


ROOT = Path(__file__).resolve().parents[1]
AUTHORITY_PATH = "architecture/policy-observation-digests-authority.json"
AUTHORITY_SHA256 = "d0507aaf7e7a5c5826ce362263bd950b41c58bac0398513aa839c79b083bebf2"
VALIDATOR_PATH = "scripts/validate_policy_observation_digests.py"
BASE_COMMIT = "30f41e6f5fb2ffdcef7d72e9e90825e66a17cca7"
NEW_PACKET = "MET-ENFORCE-041"
PREVIOUS_PACKET = "MET-GOV-001"
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
            require(key not in result, "duplicate policy-observation-digests authority member")
            result[key] = value
        return result

    def no_constant(_value: str) -> Any:
        raise ValueError("nonfinite policy-observation-digests authority number")

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
        require(digest(raw) == AUTHORITY_SHA256, "policy observation digests history authority digest")
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
    }, "closed policy observation digests history authority")
    require(value["schemaVersion"] == "harness.planeon.ai/policy-observation-digests-authority/v1"
            and value["authorityPacket"] == NEW_PACKET
            and value["acceptedBase"] == BASE_COMMIT
            and type(value["baselinePackets"]) is dict
            and len(value["baselinePackets"]) == 257
            and NEW_PACKET not in value["baselinePackets"]
            and type(value["changedFiles"]) is dict
            and type(value["newFiles"]) is dict
            and _sha(value["packetSha256"])
            and _sha(value["validatorNormalizedSha256"]),
            "accepted 257-packet base")
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
    # An exact 257-era byte string is already older than the successor layer.
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


# MET-ENFORCE-041 (roadmap DIGEST-CONTRACT; owner decisions Q-HE4I1-2 (c)+(a) and Q-DIG-3 / Q-DIG-7 "Accept, check at
# T04"; the lane monitor's owner-delegated Q-I01B-1 to Q-I01B-5, Q-DIG-1, 2, 4-6 and 8-18, Q-CB-1 to Q-CB-16, R1-A to
# R3-B, R-C1-9, R-C2, R-ORC and the adoption, all 2026-10-22) adopts the I01 digest contract: how the policy observer
# derives the I01 v1 answer's seven projection objects and four enforcement digests, as closed definitions, a
# standard-library reference model (scripts/policy_observation_digests.py) and replayable vectors, and publishes operator
# edge record v10, which registers the contract's three data files and the proxy-contract vectors (PPV) for HE-004-I01B
# before use. Candidate 4 was adopted by the lane monitor after three design and four contract review rounds by separate
# agents (contract round 4 PASS_FOR_ADOPTION, NOTEs only). Repository bytes and modes are read only through
# reviewed_bytes and reviewed_mode, and the contract directory's listing only through reviewed_tree, so a later bridged
# successor projects its own edits away first; a path outside this era is refused before it is read, and every era file
# is bound by digest on every read. Each refusal is a pure check over the values read, so every one has a failing case on
# plain data. Checked here: the freeze (this packet changes nothing under architecture/, the model or any frozen file:
# edge records v1 to v9 with their READMEs, the I01 wire's channel schema, vectors and readiness document, PPV, and the
# model's frozen I06 inputs and frozen models; under architecture/ it adds only the contract's directory and edge record
# v10 with its README); the files this packet adds (new, each once; the contract directory closed with its design
# folder; mode 100644; no absolute local path); the adoption (the six adopted files are candidate 4's bytes; the status
# record's closed shape and values with the lane monitor's adoption decision verbatim; the seven reviews bound to their
# published records by digest, each record's verdict, subject and findings equal to its row's; each published brief the
# redacted copy its row names, by digest; the carried items, C1-1 first, and the slips); edge record v10 (v9's 68 rows
# exactly and in order; the 4 new rows BYTE_IDENTICAL, REGISTERED_BEFORE_USE and mode 100644, the three contract rows
# with providerCommit null and providerPacket MET-ENFORCE-041 under host-enforcement/contracts/i01-digests-v1/, the PPV
# row at host-enforcement/contracts/i01-v1/proxy-contract-vectors.json with its restated last-change commit, each with
# its provider's exact era bytes, consumer HE-004-I01B; v9 superseded by digest and packet; v9's decision, rules,
# exclusions, statuses and key order kept); and the model replaying its vectors: the reference model and the frozen
# models it imports are executed from this era's verified bytes (never imported from the tree), the model's vector check
# runs over the era's vectors and frozen files and must return its check count with no error, and definitions.json is
# the model's definitions by the vectors' canonical pin. This layer cannot read git history: the contract builder and
# the adoption proved each provider commit from git (PPV's last-change commit, and null for the three files this packet
# publishes), and this layer restates them and checks the files' bytes and modes, as 244's split did. VPO is never
# imported here: its validate_messages on the complete positive runs in this packet's layer test (C1-1). Last, this
# layer's own inverse hunks are the canonical byte-minimal ones, recomputed from its era's bytes (MET-PERF-040's carried
# rule).
CONTRACT_DIR = "architecture/policy-observation-digests"
DESIGN_DIR = CONTRACT_DIR + "/design"
README_PATH = CONTRACT_DIR + "/README.md"
DEFINITIONS_PATH = CONTRACT_DIR + "/definitions.json"
VECTORS_PATH = CONTRACT_DIR + "/vectors.json"
STATUS_PATH = CONTRACT_DIR + "/status.json"
MODEL_PATH = "scripts/policy_observation_digests.py"
EDGES_DIR = "architecture/artifact-edges/"
V9_EDGE = EDGES_DIR + "operator-harness-engineering-v9.json"
V10_EDGE = EDGES_DIR + "operator-harness-engineering-v10.json"
V10_README = EDGES_DIR + "README-v10.md"
# The seven review records and their published (redacted) briefs, in review order: design rounds 1 to 3, then contract
# rounds 1 to 4.
RECORDS = (tuple(DESIGN_DIR + "/review-round%d.json" % number for number in range(1, 4))
           + tuple(CONTRACT_DIR + "/review-round%d.json" % number for number in range(1, 5)))
BRIEFS = (tuple(DESIGN_DIR + "/REVIEW_BRIEF_R%d.md" % number for number in range(1, 4))
          + tuple(CONTRACT_DIR + "/REVIEW_BRIEF_R%d.md" % number for number in range(1, 5)))
# The adopted subject (candidate 4; contract review round 4, PASS_FOR_ADOPTION), in the status record's order.
SUBJECT = (README_PATH, DEFINITIONS_PATH, VECTORS_PATH, MODEL_PATH, V10_EDGE, V10_README)
RECORD_FILES = (STATUS_PATH,) + RECORDS + BRIEFS
NEW_FILES = SUBJECT + RECORD_FILES
DIRECTORY_FILES = SUBJECT[:3] + RECORD_FILES
ADOPTED_SHA256 = MappingProxyType({
    "architecture/policy-observation-digests/README.md": "e393dd11c75f527829bb6522c5643cb593b6dc67e2788f5e280ce9de0f4166ae",
    "architecture/policy-observation-digests/definitions.json": "086692065cfc9da101f770fa39c50af2e2650a169595526e9860fc805478c2aa",
    "architecture/policy-observation-digests/vectors.json": "bd9f04bd04fcccc584bcab341ec649bcead567fe349c57e30958eaaf2ea64f84",
    "scripts/policy_observation_digests.py": "01298fb5c6acdae3248174265bbe576dd553eeb19bce1a48cb1e2734972c09c5",
    "architecture/artifact-edges/operator-harness-engineering-v10.json": "a4fad53dfadbe8a5d79d4049fbba83173adaacec8d33df5ca377aa288539364e",
    "architecture/artifact-edges/README-v10.md": "3ae925596532dc491ceee829893793b49fb684a501ecdc049db6651062e79128",
})
# Edge record v10: v9's members, its 68 rows, and the 4 rows it adds (provider path, provider commit, consumer path,
# provider packet). The three contract files are published by this packet (providerCommit null, providerPacket
# MET-ENFORCE-041, Q-CB-2 (a)); PPV is already on main, with its last-change commit restated and no providerPacket.
EDGE_SCHEMA = "planeon.internal.artifact-edge-registry/v2"
EDGE_ARTIFACT = "policy-observation-i01-digests"
EDGE_KEYS = ("schemaVersion", "graph", "consumer", "provider", "artifact", "ownerDecision", "rules", "notArtifacts",
             "statuses", "artifacts", "supersedes", "ownerDecisions", "notes")
KEPT_KEYS = ("schemaVersion", "graph", "consumer", "provider", "ownerDecision", "rules", "notArtifacts", "statuses")
PROVIDED_ROW_KEYS = ("providerPath", "providerCommit", "sha256", "mode", "consumerPath", "consumerPacket", "relation",
                     "status")
PUBLISHED_ROW_KEYS = PROVIDED_ROW_KEYS + ("providerPacket",)
SUPERSEDES_KEYS = ("path", "sha256", "packet")
EDGE_V9_SHA256 = "197f30e4e1e0be1dcacd71f1095c91e2333fe9d6ea05b8194578160e471605d7"
V9_PACKET = "MET-ENFORCE-040"
V9_ROWS = 68
CONSUMER_PACKET = "HE-004-I01B"
DIGESTS_CONSUMER_DIR = "host-enforcement/contracts/i01-digests-v1/"
PPV_PATH = "architecture/proxy-contract-inputs/vectors.json"
PPV_CONSUMER = "host-enforcement/contracts/i01-v1/proxy-contract-vectors.json"
PPV_COMMIT = "33de300cabb497044c679d51df13d36d14a4b906"
NEW_ROWS = ((DEFINITIONS_PATH, None, DIGESTS_CONSUMER_DIR + "definitions.json", NEW_PACKET),
            (VECTORS_PATH, None, DIGESTS_CONSUMER_DIR + "vectors.json", NEW_PACKET),
            (README_PATH, None, DIGESTS_CONSUMER_DIR + "README.md", NEW_PACKET),
            (PPV_PATH, PPV_COMMIT, PPV_CONSUMER, None))
PROVIDERS = tuple(row[0] for row in NEW_ROWS)
# The record's four quoted decisions, in order, by their labels: the lane monitor's Q-DIG-16 (a) and Q-DIG-18 (a), the
# contract build GO, the slot and Q-CB-2 (a).
DECISION_LABELS = ('Q-DIG-16 (a) and Q-DIG-18 (a)', 'Contract build GO', 'Slot', 'Q-CB-2')
DECISION_FORM = " (the lane monitor, owner-delegated, 2026-10-22, verbatim): \""
# Frozen files (exact paths; architecture/artifact-edges/ is never listed): edge records v1 to v9 and their READMEs, the
# I01 wire's channel schema, vectors and readiness document, PPV, and the model's frozen I06 inputs and frozen models.
FROZEN_EDGES = ('architecture/artifact-edges/README.md',
 'architecture/artifact-edges/README-v2.md',
 'architecture/artifact-edges/README-v3.md',
 'architecture/artifact-edges/README-v4.md',
 'architecture/artifact-edges/README-v5.md',
 'architecture/artifact-edges/README-v6.md',
 'architecture/artifact-edges/README-v7.md',
 'architecture/artifact-edges/README-v8.md',
 'architecture/artifact-edges/README-v9.md',
 'architecture/artifact-edges/operator-harness-engineering.json',
 'architecture/artifact-edges/operator-harness-engineering-v2.json',
 'architecture/artifact-edges/operator-harness-engineering-v3.json',
 'architecture/artifact-edges/operator-harness-engineering-v4.json',
 'architecture/artifact-edges/operator-harness-engineering-v5.json',
 'architecture/artifact-edges/operator-harness-engineering-v6.json',
 'architecture/artifact-edges/operator-harness-engineering-v7.json',
 'architecture/artifact-edges/operator-harness-engineering-v8.json',
 'architecture/artifact-edges/operator-harness-engineering-v9.json')
WIRE = ("architecture/policy-observation-inputs/channel.schema.json", "architecture/policy-observation-inputs/vectors.json",
        "docs/alpha-2/POLICY_OBSERVATION_READINESS.md")
FROZEN_INPUTS = ("architecture/i06-backend-profile/identity-closure.json",
                 "architecture/i06-backend-profile/writer-inventory.json",
                 "architecture/i06-backend-profile/upstream-bootstrap-rbac-v1.37.1.json")
NP4_MODEL = "scripts/native_qualification_v4.py"
ADM_MODEL = "scripts/admission_semantics_v3.py"
V1_MODEL = "scripts/i06_backend_profile.py"
V3_MODEL = "scripts/i06_backend_profile_v3.py"
V4_MODEL = "scripts/i06_backend_profile_v4.py"
FROZEN_MODELS = (ADM_MODEL, V1_MODEL, V3_MODEL, V4_MODEL, NP4_MODEL)
FROZEN_PATHS = FROZEN_EDGES + WIRE + (PPV_PATH,) + FROZEN_INPUTS + FROZEN_MODELS
# The files the model's vector check reads besides the vectors, and its check count at this era (320: 16 helper checks,
# the definitions pin, the per-vector checks and the complete I01 positive's 5).
MODEL_FILES = FROZEN_INPUTS + FROZEN_MODELS
VECTOR_CHECKS = 320
# The status record written at adoption: its closed key sets and its values, restated.
STATUS_SCHEMA = "planeon.internal.policy-observation-digests-status/v1"
WORK_ITEM = "DIGEST-CONTRACT (the I01 digest contract)"
SLOT = 258
STATUS_KEYS = ("schemaVersion", "workItem", "packet", "slot", "status", "adoption", "baseMain", "adoptedSubject",
               "builder", "independentReviewers", "reviews", "briefRedactions", "carried", "slips", "nonClaims")
ADOPTION_KEYS = ("decidedBy", "date", "decision", "condition", "readoption", "readoptionCondition",
                 "supersededAdoption")
# The lane monitor's owner-delegated adoption rule (R-C2 (a), 2026-10-22), verbatim, and its re-adoption after round 4.
ADOPTION = {'decidedBy': 'the lane monitor, owner-delegated (2026-10-22)',
 'date': '2026-10-22',
 'decision': 'A clean r3 goes straight to adoption without asking me again. Anything above NOTE comes back '
             'to me.',
 'condition': 'contract review round 3 clean (NOTE findings only)',
 'readoption': 'a clean r4 means re-adoption, a new commit replacing 871d582b, with status.json gaining '
               'contract round 4',
 'readoptionCondition': 'contract review round 4 clean (NOTE findings only), after the D5a oracle tests '
                        'found two contract-text gaps (F-ORC-1, F-ORC-2; R-ORC (a))',
 'supersededAdoption': 'candidate 3, local commit 871d582b1ae18b621340578d1772988b320ad8f4, never pushed, '
                       'kept on the local branch met-enforce-041-adoption-c3-871d582b'}
ADOPTION_QUOTE = "A clean r3 goes straight to adoption without asking me again. Anything above NOTE comes back to me."
BUILDER_KEYS = ("path", "sha256", "determinism")
BUILDER = {'path': "build_contract.py (kept with the lane's records)",
 'sha256': {'c1': 'ac0a181bc58bdc979a06d4da461306a72dd11bc0d84a5345ac621f0b16b8c052',
            'c2': '789fb94f6edded4e89c18080dca3be23d63d0c5cc35d68370efb8f1ddda81545',
            'c3': '0f9911fce052af213ed180407f7708186244bec18e378cdcc2a5992219f736c3',
            'c4': '8d0567ff1dfc00887f013af8663bdf2e0c0cbc6416860438aac53d85df9db61e'},
 'determinism': "each candidate's STAGE build and two fresh builds were byte-identical; contract reviews 2 "
                'and 3 re-ran the builder twice into fresh directories'}
INDEPENDENT_REVIEWERS = "SEPARATE_AGENTS_NOT_AUTHOR (one fresh agent per round)"
REVIEW_KEYS = ("review", "record", "recordSha256", "verdict", "base", "subject", "brief", "briefSha256", "findings",
               "severities")
SEVERITY_ORDER = ("MAJOR", "MINOR", "NOTE")
# (review, verdict, base, subject, the reviewed brief's SHA-256, the finding ids) in order.
REVIEWS = (('design round 1',
  'CHANGES_REQUIRED',
  '26a8affb',
  {'DESIGN.md rev 1': 'f03d8091a3cb4de460e60666f22194a2b37a844a4c4ecbff3d4da062ce41cd7e'},
  'b0caf537f233c555922ff2e23b85e4e3c8d276cc87e5db41d3101093bc1b1c81',
  ('D1-1',
   'D1-2',
   'D1-3',
   'D1-4',
   'D1-5',
   'D1-6',
   'D1-7',
   'D1-8',
   'D1-9',
   'D1-10',
   'D1-11',
   'D1-12',
   'D1-13',
   'D1-14',
   'D1-15',
   'D1-16',
   'D1-17',
   'D1-18',
   'D1-19')),
 ('design round 2',
  'CHANGES_REQUIRED',
  '26a8affb',
  {'DESIGN.md rev 2': '206f293b79c74dddab43dd7343c4d97fca626fd634fd2d6c7eba8431055829a0'},
  '4e59dea57140f8814b675a8615978b03080aa1c8a3b56077499ac3e481493087',
  ('D2-1', 'D2-2', 'D2-3', 'D2-4', 'D2-5', 'D2-6', 'D2-7')),
 ('design round 3',
  'PASS_FOR_CONTRACT',
  '26a8affb',
  {'DESIGN.md rev 3': '73cd9f6ddeab744b6b9c222204a9bdd4d0a0eef54e4c6f6321fe80bf28a9c083'},
  '9dd961b0d6753ad1b2cf544a7a7ee23665b64952f9c829da8017fe608d68e0b4',
  ('D3-1', 'D3-2', 'D3-3', 'D3-4', 'D3-5', 'D3-6', 'D3-7')),
 ('contract round 1',
  'CHANGES_REQUIRED',
  '30f41e6f5fb2ffdcef7d72e9e90825e66a17cca7',
  'candidate 1',
  '970bb67a7bf0c1d1419c93fd8eefa9167614bdc964c17da1bac030099be3a8a6',
  ('C1-1', 'C1-2', 'C1-3', 'C1-4', 'C1-5', 'C1-6', 'C1-7', 'C1-8', 'C1-9', 'C1-10', 'C1-11')),
 ('contract round 2',
  'PASS_FOR_ADOPTION',
  '30f41e6f5fb2ffdcef7d72e9e90825e66a17cca7',
  'candidate 2',
  'c6ca3cffe9183a441231b234072da52b3bfbd6bf1e72020c1e84be3eba7e8169',
  ('C2-1', 'C2-2', 'C2-3')),
 ('contract round 3',
  'PASS_FOR_ADOPTION',
  '30f41e6f5fb2ffdcef7d72e9e90825e66a17cca7',
  'candidate 3',
  'a6deff5e0e4d93ffabf904bd4f46c630a05f68f89780213aab2e358bff1542b0',
  ('C3-1', 'C3-2')),
 ('contract round 4',
  'PASS_FOR_ADOPTION',
  '30f41e6f5fb2ffdcef7d72e9e90825e66a17cca7',
  'candidate 4',
  '51aa5b6dd4b10ed795ce1d446c7ed055f89ebbe61662c4b034f22c48082fa0e3',
  ('C4-1', 'C4-2')))
# Each published review record's closed key order.
RECORD_KEYS = MappingProxyType({1: ('subject',
     'reviewer',
     'model',
     'brief',
     'verdict',
     'findings',
     'adversarialCases',
     'questions',
     'checks',
     'notChecked'),
 2: ('subject',
     'reviewer',
     'model',
     'brief',
     'verdict',
     'round1',
     'round1Cases',
     'findings',
     'adversarialCases',
     'checks',
     'notChecked'),
 3: ('subject',
     'reviewer',
     'model',
     'brief',
     'verdict',
     'verdictNote',
     'round2',
     'round1Regressions',
     'earlierCases',
     'findings',
     'adversarialCases',
     'adversarialTally',
     'checks',
     'notChecked'),
 4: ('subject',
     'reviewer',
     'model',
     'brief',
     'verdict',
     'verdictNote',
     'findings',
     'mutations',
     'attackCases',
     'questions',
     'checks',
     'notChecked'),
 5: ('subject',
     'reviewer',
     'model',
     'brief',
     'verdict',
     'verdictNote',
     'round1',
     'findings',
     'mutations',
     'attackCases',
     'questions',
     'checks',
     'notChecked'),
 6: ('subject',
     'reviewer',
     'model',
     'brief',
     'verdict',
     'verdictNote',
     'diff',
     'c2VectorsIdentical',
     'findings',
     'checks',
     'notChecked'),
 7: ('subject',
     'reviewer',
     'model',
     'brief',
     'verdict',
     'verdictNote',
     'diff',
     'c3VectorsIdentical',
     'probes',
     'findings',
     'checks',
     'notChecked')})
REDACTION_KEYS = ("brief", "reviewedSha256", "publishedSha256", "substitutions")
SUBSTITUTION_KEYS = ("fromSha256", "from", "to", "count")
# Every brief was redacted by the same two substitutions (LOCAL-PATHS): each replaced string named by its SHA-256 and a
# description, never by the path itself.
SUBSTITUTIONS = ({'fromSha256': '1eedbfd71339d2596624d83bc7c0daa404c937e39dd76bf8af995e65b0181c67',
  'from': "the lane's CI state directory (home-relative)",
  'to': '<workspace>/',
  'count': 4},
 {'fromSha256': 'c955eccd4877ecd86f04647fba45d5d4709507b644e193fc7ac9a182d0459ec8',
  'from': "the session's temporary directory",
  'to': '<scratch>/',
  'count': 2})
CARRIED_KEYS = ("item", "to", "action")
# (item, to) in order; C1-1 (ruled binding) is carried to this packet's layer test.
CARRIED = (('C1-1 (contract review round 1, ruled binding)', "this packet's layer test"),
 ("D3-1 and C1-7 (the capture gate's inputs)", 'HE-004-I01B (R10)'),
 ('Q-CB-11 (a)', 'HE-004-I01B (R10)'),
 ('Section 6 (the configuration successor)', 'HE-004-I01B and HE-008'),
 ('Q-CB-15 (a) and contract review round 2', 'the List-form revision (several NetworkPolicies)'),
 ('The residuals R-ADM-LIST, R-PSA-CONFIG, R-NET-DATAPATH, R-NET-AGENT, R-DEFAULTS, R-RBAC-COMPLETE and '
  'R-BROKER-LIVE',
  'T04 (and HE-005 where named)'),
 ('C3-1 (contract review round 3, NOTE)', 'a later contract revision'),
 ('C3-2 (contract review round 3, NOTE)', 'kept as adopted'),
 ('C4-1 (contract review round 4, NOTE)', 'a later contract revision'),
 ('C4-2 (contract review round 4, NOTE)', 'a later contract revision'))
C1_1_ACTION = ('tests/test_policy_observation_digests.py asserts, with no skip, expected-failure mark or import guard, '
 'validate_messages(...) == [] and validate_profile(...) == [] on the complete positive, and that each '
 'refuses when one preexisting reference changes (README section 10)')
SLIP_KEYS = ("id", "ruling", "what")
SLIPS = (('MON-DIG-LSTREE', 'KEEP, the lane monitor under owner delegation, 2026-10-22'),
 ('MON-DIG-R3-BRIEF-NAME', 'KEEP, the lane monitor under owner delegation, 2026-10-22'),
 ('MON-DIG-BUILD-ETP-IMPORT', 'KEEP, the lane monitor under owner delegation, 2026-10-22'),
 ('MON-DIG-BUILD-LSTREE', 'KEEP, the lane monitor under owner delegation, 2026-10-22'),
 ('MON-DIG-BUILD-NOPAUSE', 'KEEP, the lane monitor under owner delegation, 2026-10-22'),
 ('MON-DIG-CR1-WC', 'KEEP, the lane monitor under owner delegation, 2026-10-22'),
 ('MON-DIG-CR2-SHOWS', 'KEEP, the lane monitor under owner delegation, 2026-10-22'),
 ('MON-DIG-ORACLE-GREP', 'KEEP, the lane monitor under owner delegation, 2026-10-22'),
 ('MON-DIG-ORACLE-SLIPS', 'KEEP, the lane monitor under owner delegation, 2026-10-22'),
 ('MON-DIG-CR4-BG',
  "disclosed in contract review round 4's record; reported to the lane monitor, 2026-10-22"))
NON_CLAIMS = ('DATA_CHECK_ONLY: the model returns errors or derived values, never a protected handle or native '
 'acceptance.',
 'No R10 file changes in this packet; HE-004-I01B vendors the four rows edge v10 registers.',
 'The I01 v1 wire (channel schema, vectors, readiness document) is unchanged.',
 "VPO's validate_messages on the complete positive runs in this packet's layer test, in the pre-check and "
 'verify only (Q-CB-6 (b)); no builder or reviewer imported VPO after MON-DIG-BUILD-ETP-IMPORT.')
# Every file this era's check reads, with its digest: the files this packet adds under the contract directory, the model
# and edge record v10 with its README, and the frozen files.
ERA_SHA256 = MappingProxyType({
    "architecture/artifact-edges/README-v10.md": "3ae925596532dc491ceee829893793b49fb684a501ecdc049db6651062e79128",
    "architecture/artifact-edges/README-v2.md": "0cded3e3499b8afe64c82a021a8a499c9b2fce5671ea5ae434b3330c26db3a2b",
    "architecture/artifact-edges/README-v3.md": "d6edd8cc7f8b209c1cf7bd0a16a941e0661ef040f8920cbdbda4c323c0f0f011",
    "architecture/artifact-edges/README-v4.md": "11e6bbefc27d82d359c7f48a873374786a760881693fd7d9ec7e88916ab2558b",
    "architecture/artifact-edges/README-v5.md": "6409a17c2fb0b5ae5df3055c86a3e4cb1e2cb3deacd490c4d547cc1d50a9b6ad",
    "architecture/artifact-edges/README-v6.md": "ce15ee36e15964a08fc83a495f2bd453ebe375c77e37d386f00c2803ec4e73f7",
    "architecture/artifact-edges/README-v7.md": "7131d500eac2085871254a250a4a84c24b17456891dd5f3b2478d85153f1a378",
    "architecture/artifact-edges/README-v8.md": "e5dea489087b0d58c9e1559ce6ee1a07ef2e7567a9d04841d80b3f20e67dc0d9",
    "architecture/artifact-edges/README-v9.md": "8cde7d199a00dd19edd9b8fc699b4f065d730ab245af7af77edca9e32a8fbf09",
    "architecture/artifact-edges/README.md": "5d62a665da2c6e75dce900cb4ef52e74aa14e537bdaeededb7568589339daa9f",
    "architecture/artifact-edges/operator-harness-engineering-v10.json": "a4fad53dfadbe8a5d79d4049fbba83173adaacec8d33df5ca377aa288539364e",
    "architecture/artifact-edges/operator-harness-engineering-v2.json": "749e70f174d638468bf45d7316e8f5201c3323f6348a78c7b9a22d3a571ccc32",
    "architecture/artifact-edges/operator-harness-engineering-v3.json": "106ea91aa09c2d377adf3b514a228331d6a805bd1a17e641ecaa23b3c39115f3",
    "architecture/artifact-edges/operator-harness-engineering-v4.json": "e30772ff8826650c46d1a8d384625929975e47f2de5cc9030680b5fdb5e7fc86",
    "architecture/artifact-edges/operator-harness-engineering-v5.json": "89b47ef8f865b31911eb8da2b08a5a3c22b2d92a62599cb6fdfccbfe7f79e3c0",
    "architecture/artifact-edges/operator-harness-engineering-v6.json": "0ac7c2da62de87837f5a36a967a2c5b9c286ecab2e03f335a8eebbd32df9d24d",
    "architecture/artifact-edges/operator-harness-engineering-v7.json": "6af45e361a66331a9ee0216d3eea42f3a17770fd3c7d33e78e2a025d301bfa92",
    "architecture/artifact-edges/operator-harness-engineering-v8.json": "623cf10bf19cfba1806f5699007f39c7f6ba38f72d92069548421c4dccd21573",
    "architecture/artifact-edges/operator-harness-engineering-v9.json": "197f30e4e1e0be1dcacd71f1095c91e2333fe9d6ea05b8194578160e471605d7",
    "architecture/artifact-edges/operator-harness-engineering.json": "54bdc2d22676720419f51cd1bad5eedc909e6f848ed09cd363e351889af9d1fe",
    "architecture/i06-backend-profile/identity-closure.json": "0a9b82ffa2d63bf48a8850574cdf3ece02bf1913f33a72cbb96ed30a40f1f3bb",
    "architecture/i06-backend-profile/upstream-bootstrap-rbac-v1.37.1.json": "7529c2a713af2fb90163175924c264d95f4242d7e0c26b1452c77febb13ed50e",
    "architecture/i06-backend-profile/writer-inventory.json": "8e6b3b7565cfc93a61162b84d740cffb2871eb66ab85e8c4e80ac813f1af3077",
    "architecture/policy-observation-digests/README.md": "e393dd11c75f527829bb6522c5643cb593b6dc67e2788f5e280ce9de0f4166ae",
    "architecture/policy-observation-digests/REVIEW_BRIEF_R1.md": "b42755352b00d26bd1ec15375ab6889ff970cd620a713404800181c8d1f90606",
    "architecture/policy-observation-digests/REVIEW_BRIEF_R2.md": "cca0d8f31434934281ca2142e124a41e87e799e0275b75e7d9152f83e2cff87a",
    "architecture/policy-observation-digests/REVIEW_BRIEF_R3.md": "f52f507fceda2768a995f49c625080633ab68155c6788b5b2a5e66968597aecc",
    "architecture/policy-observation-digests/REVIEW_BRIEF_R4.md": "4e8eeb929ed6c5f41b01dcf7ba1ada1c7acb4ccec9455699570c6b99831f2e73",
    "architecture/policy-observation-digests/definitions.json": "086692065cfc9da101f770fa39c50af2e2650a169595526e9860fc805478c2aa",
    "architecture/policy-observation-digests/design/REVIEW_BRIEF_R1.md": "0ef80d824b5c23c8f0e7009d657cfcef246248eca01841c2960f484757c20e54",
    "architecture/policy-observation-digests/design/REVIEW_BRIEF_R2.md": "21583900bdf11f06f65b766405bc12152c68ad551ec212b8a833c2bf85f41a20",
    "architecture/policy-observation-digests/design/REVIEW_BRIEF_R3.md": "90b3f1ba37e6c307365f161808c4d2442cca691e0a63704c4e38d980842c915e",
    "architecture/policy-observation-digests/design/review-round1.json": "46f233d50620c5b6fee8c55f2a35c568db8d2cb0f15b2b35f8c7c37483583a2b",
    "architecture/policy-observation-digests/design/review-round2.json": "7226f334e4327da6212d76a8c6851a3b3e4f8e6c44f62365c7325b705ee898e1",
    "architecture/policy-observation-digests/design/review-round3.json": "f684b90f6c231d7220f52f35bb8b388519facaaaf4d058a354295898e8690017",
    "architecture/policy-observation-digests/review-round1.json": "6a7c55c4152b9619c3d9b26993e51ecbeb137949477f277e141815fe794cb28e",
    "architecture/policy-observation-digests/review-round2.json": "38c76f4559e0f8eb4ddf658682f96fa8daa30c8207db3d25001ac31156056a11",
    "architecture/policy-observation-digests/review-round3.json": "92ca9a332b2cbddfbd92fd64df89d6e3d57c65f4e9c66ae881f7d4678a49749b",
    "architecture/policy-observation-digests/review-round4.json": "e5f8f0fe94ebf12039255daf7663ac2d2e00f3309ed2ebc30c7499460bf4fb96",
    "architecture/policy-observation-digests/status.json": "4b20c7c17990f95246d84a110bed7c2745e7adf9e8676da26f2cf6b96fb4dc99",
    "architecture/policy-observation-digests/vectors.json": "bd9f04bd04fcccc584bcab341ec649bcead567fe349c57e30958eaaf2ea64f84",
    "architecture/policy-observation-inputs/channel.schema.json": "fb69b77201d9b6275a19667a5f5770537f382ddb11309095733628c8430bdc0e",
    "architecture/policy-observation-inputs/vectors.json": "1bfb46776636f800e38ab6a8f94a0989aa38513fb4a28ef18e61e732a115c124",
    "architecture/proxy-contract-inputs/vectors.json": "edf32ddf992e06e8786fd331affdb4d2ecd5538ca874d52c37439386793a8eb7",
    "docs/alpha-2/POLICY_OBSERVATION_READINESS.md": "65778040919c5eb7335f2c104d983ca920b877b1b123f961556a6bcae36d232c",
    "scripts/admission_semantics_v3.py": "3db8f51ab55f49dc33cf6f028306bfb6d7aa1c5d7d96f264cfe709dae925ad22",
    "scripts/i06_backend_profile.py": "bea3c953573478be5b03ab81b4ebd859da62d1eaa2a1be8f361b9dd39a98555e",
    "scripts/i06_backend_profile_v3.py": "dfb00e90199d436ae63b79261f2e04870d7861cb0f7a424971657a4d777754de",
    "scripts/i06_backend_profile_v4.py": "7f97acfe9060e79c101f264f5bf61610bf421326c689216cbaf41df7e38e6d2a",
    "scripts/native_qualification_v4.py": "f7c718072d1ffbb9b8bbc310e6141d476ea5f25296f70ff8c1bc9ada3db02387",
    "scripts/policy_observation_digests.py": "01298fb5c6acdae3248174265bbe576dd553eeb19bce1a48cb1e2734972c09c5",
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
    require(expected is not None, "MET-ENFORCE-041 reviewed bytes are bound: " + str(path))
    require(type(raw) is bytes and digest(raw) == expected, "unreviewed DIGEST-CONTRACT source: " + path)
    return raw


def _verified(path: str) -> bytes:
    """reviewed_bytes, checked against its era digest on every read; a path outside the era is refused before it is
    read."""
    require(type(path) is str and path in ERA_SHA256, "MET-ENFORCE-041 reviewed bytes are bound: " + str(path))
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


def check_era_models(models: Any) -> None:
    """The model runs this era's frozen models: its I06 v4 is this era's, with this era's I06 v1 and v3, and v3 with
    this era's I06 v1 and native-profile v4."""
    _bound(lambda: type(models) is tuple and len(models) == 5 and models[0].i06v4 is models[1]
           and models[1].v1 is models[3] and models[1].v3 is models[2] and models[2].v1 is models[3]
           and models[2].w02a is models[4], "the model runs this era's frozen models: I06 v4 with I06 v1 and v3")


def era_models() -> tuple:
    """This era's reference model, executed from its verified bytes with this era's frozen models as its imports
    (admission v3, I06 v1, and I06 v4 with I06 v1 and v3, and v3 with I06 v1 and native-profile v4); VPC's three helpers
    resolve normally, as the contract pins them by behaviour vectors, not by file digest. Returns (the model, I06 v4,
    I06 v3, I06 v1, native-profile v4)."""
    np4 = _era_model(NP4_MODEL, "_met_enforce_041_native_qualification_v4")
    adm = _era_model(ADM_MODEL, "_met_enforce_041_admission_semantics_v3")
    i06v1 = _era_model(V1_MODEL, "_met_enforce_041_i06_backend_profile")
    i06v3 = _era_model(V3_MODEL, "_met_enforce_041_i06_backend_profile_v3",
                       {"i06_backend_profile": i06v1, "native_qualification_v4": np4})
    i06v4 = _era_model(V4_MODEL, "_met_enforce_041_i06_backend_profile_v4",
                       {"i06_backend_profile": i06v1, "i06_backend_profile_v3": i06v3})
    model = _era_model(MODEL_PATH, "_met_enforce_041_policy_observation_digests",
                       {"admission_semantics_v3": adm, "i06_backend_profile": i06v1, "i06_backend_profile_v4": i06v4})
    models = (model, i06v4, i06v3, i06v1, np4)
    check_era_models(models)
    return models


def check_freeze(changed: Any, added: Any) -> None:
    """This packet changes nothing under architecture/, not the model and no frozen file, and under architecture/ it adds
    only the contract's directory and edge record v10 with its README; no frozen file is added either."""
    for path in list(changed):
        require(type(path) is str and not path.startswith("architecture/") and path != MODEL_PATH
                and path not in FROZEN_PATHS,
                "no earlier contract, record, frozen model or edge record changes, and under architecture/ only the "
                "contract's directory and edge record v10 with its README are added: " + str(path))
    for path in list(added):
        require(type(path) is str and path not in FROZEN_PATHS
                and (not path.startswith("architecture/") or path.startswith(CONTRACT_DIR + "/")
                     or path in (V10_EDGE, V10_README)),
                "no earlier contract, record, frozen model or edge record changes, and under architecture/ only the "
                "contract's directory and edge record v10 with its README are added: " + str(path))


def check_new_files(added: Any, changed: Any) -> None:
    """The packet adds the contract's files, its status record, review records and briefs, the model and edge record
    v10 with its README as new files, each once."""
    _bound(lambda: len(set(NEW_FILES)) == len(NEW_FILES) and not set(NEW_FILES) & set(changed)
           and {path for path in added if path.startswith(CONTRACT_DIR + "/") or path in (MODEL_PATH, V10_EDGE, V10_README)}
           == set(NEW_FILES), "the contract's files, records and briefs, the model and edge record v10 are new in this "
           "packet, each once")


def check_contract_tree(mode: Any, tree: Any) -> None:
    """The contract directory is a directory (not a link) holding exactly its files and its design folder, each file a
    regular file of git mode 100644 and the design folder a directory."""
    require(type(mode) is int and stat.S_ISDIR(mode), "the contract directory is a directory, not a link")
    _bound(lambda: type(tree) is dict and sorted(tree) == sorted(DIRECTORY_FILES + (DESIGN_DIR,))
           and all(_git_mode(tree[path]) == "100644" for path in DIRECTORY_FILES) and stat.S_ISDIR(tree[DESIGN_DIR]),
           "the contract directory holds exactly its files and its design folder, each file of mode 100644")


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
    """The status record's closed shape and values: DIGEST-CONTRACT adopted as MET-ENFORCE-041 at slot 258 on this era's
    base, by separate reviewers, with the adopted subject, the builder and the non-claims as adopted."""
    _bound(lambda: type(status) is dict and tuple(status) == STATUS_KEYS and status["schemaVersion"] == STATUS_SCHEMA
           and status["workItem"] == WORK_ITEM and status["packet"] == NEW_PACKET and status["slot"] == SLOT
           and type(status["slot"]) is int and status["status"] == "ADOPTED" and status["baseMain"] == BASE_COMMIT
           and status["independentReviewers"] == INDEPENDENT_REVIEWERS
           and tuple(status["adoptedSubject"]) == SUBJECT and status["adoptedSubject"] == dict(ADOPTED_SHA256)
           and tuple(status["builder"]) == BUILDER_KEYS and status["builder"] == BUILDER
           and status["nonClaims"] == list(NON_CLAIMS), "adopted DIGEST-CONTRACT status")


def check_adoption(adoption: Any) -> None:
    """The adoption is the lane monitor's owner-delegated decision, quoted verbatim, with its condition and the
    re-adoption after contract round 4."""
    _bound(lambda: type(adoption) is dict and tuple(adoption) == ADOPTION_KEYS and adoption == ADOPTION
           and adoption["decision"] == ADOPTION_QUOTE, "the adoption is the lane monitor's decision, verbatim")


def check_subject(path: str, raw: Any) -> None:
    require(path in ADOPTED_SHA256 and type(raw) is bytes and digest(raw) == ADOPTED_SHA256[path],
            "the contract files are the adopted candidate 4: " + path)


def check_reviews(reviews: Any, last: Any) -> None:
    """Seven reviews in order; design round 3 passed for the contract, and contract round 4, the last, passed for
    adoption with NOTEs only on candidate 4, whose files its record names."""
    _bound(lambda: type(reviews) is list and [row["review"] for row in reviews] == [row[0] for row in REVIEWS]
           and [row["verdict"] for row in reviews] == [row[1] for row in REVIEWS]
           and reviews[2]["verdict"] == "PASS_FOR_CONTRACT" and reviews[-1]["verdict"] == "PASS_FOR_ADOPTION"
           and reviews[-1]["subject"] == "candidate 4" and tuple(reviews[-1]["severities"]) == ("NOTE",)
           and type(last) is dict and last["subject"]["files"] == dict(ADOPTED_SHA256),
           "seven reviews in order; the last passed with NOTEs only on the adopted candidate 4")


def _subject_named(subject: Any, record: Any) -> bool:
    """A design round names its DESIGN.md revision by digest; a contract round names its candidate."""
    if type(subject) is dict:
        return len(subject) == 1 and [{"design": label, "sha256": value} for label, value in subject.items()] == [record]
    return type(record) is dict and type(record["candidate"]) is int and subject == "candidate %d" % record["candidate"]


def check_review(number: int, row: Any, record: Any, raw: Any) -> None:
    """Review `number` is bound to its published record by digest; the record's verdict, reviewer, brief, subject and
    findings are the row's, and the row's severities are the record's counts."""
    name, verdict, base, subject, brief, ids = REVIEWS[number - 1]
    _bound(lambda: type(row) is dict and tuple(row) == REVIEW_KEYS and row["review"] == name
           and row["record"] == RECORDS[number - 1] and type(raw) is bytes and digest(raw) == row["recordSha256"]
           and row["verdict"] == verdict and row["base"] == base and row["subject"] == subject
           and row["brief"] == BRIEFS[number - 1] and row["briefSha256"] == brief and row["findings"] == list(ids)
           and type(record) is dict and tuple(record) == RECORD_KEYS[number] and record["verdict"] == verdict
           and record["reviewer"] == "independent agent" and record["brief"]["sha256"] == brief
           and _subject_named(subject, record["subject"])
           and tuple(finding["id"] for finding in record["findings"]) == ids
           and row["severities"] == {level: len([finding for finding in record["findings"]
                                                 if finding["severity"] == level])
                                     for level in SEVERITY_ORDER
                                     if [finding for finding in record["findings"] if finding["severity"] == level]}
           and tuple(row["severities"]) == tuple(level for level in SEVERITY_ORDER if level in row["severities"]),
           "review %d is bound to its record and its subject" % number)


def check_redactions(status: Any, briefs: Any) -> None:
    """Each published brief is the redacted copy its review's row names: the reviewed brief's digest, the published
    brief's digest and the two substitutions."""
    _bound(lambda: type(status["briefRedactions"]) is list
           and [row["brief"] for row in status["briefRedactions"]] == list(BRIEFS)
           and all(tuple(row) == REDACTION_KEYS and row["reviewedSha256"] == review["briefSha256"]
                   and type(briefs[row["brief"]]) is bytes and row["publishedSha256"] == digest(briefs[row["brief"]])
                   and all(tuple(item) == SUBSTITUTION_KEYS for item in row["substitutions"])
                   and row["substitutions"] == [dict(item) for item in SUBSTITUTIONS]
                   for row, review in zip(status["briefRedactions"], status["reviews"]))
           and len(status["briefRedactions"]) == len(status["reviews"]),
           "each published brief is the redacted copy its review names, by digest")


def check_carried(status: Any) -> None:
    """The carried items are present in order, each with its action; C1-1 is carried to this packet's layer test."""
    _bound(lambda: type(status["carried"]) is list
           and all(tuple(row) == CARRIED_KEYS and type(row["action"]) is str and row["action"].strip() != ""
                   for row in status["carried"])
           and [(row["item"], row["to"]) for row in status["carried"]] == list(CARRIED)
           and status["carried"][0]["action"] == C1_1_ACTION,
           "the carried items are present, C1-1 first and carried to this packet's layer test")


def check_slips(status: Any) -> None:
    """The slips are present in order, each with its ruling and what happened."""
    _bound(lambda: type(status["slips"]) is list
           and all(tuple(row) == SLIP_KEYS and type(row["what"]) is str and row["what"].strip() != ""
                   for row in status["slips"])
           and [(row["id"], row["ruling"]) for row in status["slips"]] == list(SLIPS),
           "the slips are present, each with its ruling")


def validate_adoption() -> None:
    """The status record, the adoption, the adopted files, the seven reviews with their published records and briefs,
    the carried items and the slips."""
    status = _json(STATUS_PATH)
    check_status(status)
    check_adoption(status["adoption"])
    for path in SUBJECT:
        check_subject(path, _verified(path))
    records = []
    for number, row in enumerate(status["reviews"], 1):
        raw = _verified(RECORDS[number - 1])
        records.append(parse(raw))
        check_review(number, row, records[-1], raw)
    check_reviews(status["reviews"], records[-1])
    check_redactions(status, {path: _verified(path) for path in BRIEFS})
    check_carried(status)
    check_slips(status)


def check_edge_record(v9: Any, v10: Any, v9_raw: Any) -> None:
    """Edge record v10 supersedes v9 by its digest and packet, keeps v9's decision, rules, exclusions, statuses and key
    order, quotes its four decisions, and carries v9's 68 rows exactly and in order."""
    _bound(lambda: type(v9_raw) is bytes and digest(v9_raw) == EDGE_V9_SHA256 and type(v10) is dict
           and tuple(v10) == tuple(v9) == EDGE_KEYS and v10["schemaVersion"] == EDGE_SCHEMA
           and all(v10[key] == v9[key] for key in KEPT_KEYS) and tuple(v10["supersedes"]) == SUPERSEDES_KEYS
           and v10["supersedes"] == {"path": V9_EDGE, "sha256": "sha256:" + EDGE_V9_SHA256, "packet": V9_PACKET}
           and v10["artifact"] == EDGE_ARTIFACT and _texts(v10["notes"]) and _texts(v10["ownerDecisions"])
           and len(v10["ownerDecisions"]) == len(DECISION_LABELS)
           and all(text.startswith(label + DECISION_FORM) and text.endswith("\"")
                   for text, label in zip(v10["ownerDecisions"], DECISION_LABELS)),
           "edge record v10 supersedes v9 by its digest and packet and keeps v9's decision, rules, exclusions, statuses "
           "and key order")
    _bound(lambda: len(v9["artifacts"]) == V9_ROWS and v10["artifacts"][:V9_ROWS] == v9["artifacts"]
           and all(list(row) == list(old) for row, old in zip(v10["artifacts"], v9["artifacts"]))
           and len(v10["artifacts"]) == V9_ROWS + len(NEW_ROWS),
           "edge record v10 carries v9's 68 rows exactly and in order")


def check_new_row(number: int, row: Any, spec: Any, raw: Any, mode: Any) -> None:
    """A new row registers its provider file's exact era bytes and mode before use, for HE-004-I01B: a contract file
    published by this packet with providerCommit null and providerPacket MET-ENFORCE-041 under the digests directory, or
    PPV with its restated last-change commit and no providerPacket."""
    path, commit, consumer, packet = spec
    _bound(lambda: type(row) is dict
           and tuple(row) == (PUBLISHED_ROW_KEYS if packet is not None else PROVIDED_ROW_KEYS)
           and row["providerPath"] == path and row["providerCommit"] == commit and row["consumerPath"] == consumer
           and row["consumerPacket"] == CONSUMER_PACKET and row["relation"] == "BYTE_IDENTICAL"
           and row["status"] == "REGISTERED_BEFORE_USE"
           and (row["providerPacket"] == NEW_PACKET and commit is None
                and consumer == DIGESTS_CONSUMER_DIR + path.split("/")[-1] if packet is not None
                else commit == PPV_COMMIT and path == PPV_PATH and consumer == PPV_CONSUMER)
           and type(raw) is bytes and row["sha256"] == digest(raw)
           and type(mode) is int and row["mode"] == _git_mode(mode) == "100644",
           "edge record v10 row %d registers its provider's exact bytes and mode before use: %s" % (number, path))


def check_registered_once(v9: Any, v10: Any) -> None:
    providers = [row["providerPath"] for row in v10["artifacts"]]
    consumers = [row["consumerPath"] for row in v10["artifacts"][V9_ROWS:]]
    _bound(lambda: len(set(providers)) == len(providers) and len(set(consumers)) == len(consumers)
           and not set(consumers) & {row["consumerPath"] for row in v9["artifacts"]},
           "each provider path, and each new consumer path, is registered once")


def validate_edge_record() -> None:
    """Edge record v10 against v9's era bytes and the four provider files' era bytes and modes."""
    v9_raw = _verified(V9_EDGE)
    v9, v10 = parse(v9_raw), _json(V10_EDGE)
    check_edge_record(v9, v10, v9_raw)
    for number, (row, spec) in enumerate(zip(v10["artifacts"][V9_ROWS:], NEW_ROWS), V9_ROWS + 1):
        check_new_row(number, row, spec, _verified(spec[0]), reviewed_mode(spec[0]))
    check_registered_once(v9, v10)


def check_vector_replay(model: Any, vectors: Any, files: Any) -> None:
    """The model's vector check replays every vector over this era's frozen files with no error and returns its check
    count."""
    _bound(lambda: model.check_vectors(vectors, files) == VECTOR_CHECKS,
           "the model replays its vectors over this era's frozen files with no error")


def check_definitions(vectors: Any, raw: Any) -> None:
    """definitions.json is the model's definitions: its canonical digest is the vectors' pin, which the vector check
    compares with the model's definitions()."""
    _bound(lambda: type(raw) is bytes and vectors["contract"] == {"path": DEFINITIONS_PATH,
                                                                   "canonicalSha256": digest(canonical(parse(raw)))},
           "definitions.json is the model's definitions, by the vectors' canonical pin")


def validate_model() -> None:
    """The model, run from this era's bytes with this era's frozen models, replays its vectors; definitions.json is its
    definitions."""
    model = era_models()[0]
    vectors = _json(VECTORS_PATH)
    check_vector_replay(model, vectors, {path: _verified(path) for path in MODEL_FILES})
    check_definitions(vectors, _verified(DEFINITIONS_PATH))


def validate_policy_observation_digests() -> None:
    """Every reviewed byte first; then the freeze and the files this packet adds, the adoption, edge record v10 and the
    model's vector replay; last, this layer's canonical hunks."""
    for path in ERA_SHA256:
        _verified(path)
    validate_files()
    validate_adoption()
    validate_edge_record()
    validate_model()
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
            == record["validatorNormalizedSha256"], "policy observation digests validator drift")
    paths = sorted((ROOT / "task-packets").glob("*.yaml"))
    old = set(record["baselinePackets"])
    require(len(paths) == 261
            and {path.stem for path in paths} == old | {NEW_PACKET, successor.NEW_PACKET, successor.successor.NEW_PACKET, successor.successor.successor.NEW_PACKET},
            "closed 261-packet catalog retaining the 258-packet checkpoint")
    packets = {}
    for path in paths:
        if path.stem in (successor.NEW_PACKET, successor.successor.NEW_PACKET, successor.successor.successor.NEW_PACKET):
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
            "closed source-only policy-observation-digests packet and inherited commands")
    require(len(packet["allowedPaths"]) == len(set(packet["allowedPaths"]))
            and set(packet["allowedPaths"]) == set(record["changedFiles"])
            | set(record["newFiles"]) | {AUTHORITY_PATH, VALIDATOR_PATH,
                                         "task-packets/" + NEW_PACKET + ".yaml"},
            "unreviewed or omitted policy-observation-digests packet path")
    for path, rule in record["changedFiles"].items():
        current = successor.historical_bytes(path, regular_bytes(path))
        require(digest(current) == rule["afterSha256"]
                and digest(historical_bytes(path, current)) == rule["beforeSha256"],
                "unreviewed current source: " + path)
    for path, expected in record["newFiles"].items():
        require(digest(successor.historical_bytes(path, regular_bytes(path))) == expected,
                "new source drift: " + path)
    validate_policy_observation_digests()


if __name__ == "__main__":
    validate()
    print("Policy observation digests valid: 261 current specifications; 258-packet checkpoint and exact 257-packet predecessor; contract reviewed.")
