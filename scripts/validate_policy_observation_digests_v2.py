#!/usr/bin/env python3
"""Validate the MET-ENFORCE-042 I01 digest contract v2 (S1, with W1 and edge record v11), adopted as candidate c4 after its in-tree CONTRACT rounds 1 to 3 (the model over its vectors with its frozen models, admission v4's sealed rendering, B-I01S-1's binding, edge record v11, the non-chain pinned files byte-identical and the chain validators and tests in the pin lists changed only by the chain-bump vocabulary under B-L1-3; DATA_CHECK_ONLY; gate material only through the registry rider, GATE_REVIEW_PROCESS) with its D5a oracle and B-L1-4's pins record, and the exact 265-to-264 projection."""
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
    import validate_met_linux_008 as successor
except ImportError:
    from scripts.safe_yaml import safe_load
    from scripts import validate_met_linux_008 as successor


ROOT = Path(__file__).resolve().parents[1]
AUTHORITY_PATH = "architecture/policy-observation-digests-v2-authority.json"
AUTHORITY_SHA256 = "5736dfa81baa277843721b41afffa815d71da03a35a46af4f82bcaf3c3112479"
VALIDATOR_PATH = "scripts/validate_policy_observation_digests_v2.py"
BASE_COMMIT = "a88276171453760e46b28e8f6f0c0bb4bbfade5d"
NEW_PACKET = "MET-ENFORCE-042"
PREVIOUS_PACKET = "MET-LINUX-009"
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
            require(key not in result, "duplicate policy-observation-digests-v2 authority member")
            result[key] = value
        return result

    def no_constant(_value: str) -> Any:
        raise ValueError("nonfinite policy-observation-digests-v2 authority number")

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
        require(digest(raw) == AUTHORITY_SHA256, "policy observation digests v2 history authority digest")
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
    }, "closed policy observation digests v2 history authority")
    require(value["schemaVersion"] == "harness.planeon.ai/policy-observation-digests-v2-authority/v1"
            and value["authorityPacket"] == NEW_PACKET
            and value["acceptedBase"] == BASE_COMMIT
            and type(value["baselinePackets"]) is dict
            and len(value["baselinePackets"]) == 264
            and NEW_PACKET not in value["baselinePackets"]
            and type(value["changedFiles"]) is dict
            and type(value["newFiles"]) is dict
            and _sha(value["packetSha256"])
            and _sha(value["validatorNormalizedSha256"]),
            "accepted 264-packet base")
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
    # An exact 264-era byte string is already older than the successor layer.
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


# MET-ENFORCE-042 (roadmap S1, the I01 digest contract v2, with W1 and S2; the lane monitor's owner-delegated rulings,
# among them MON-I01S-1 to MON-I01S-14, MON-I01S-D1 to MON-I01S-D3, MON-I01S-DESIGN-CLOSED, MON-I01S-C4-ADOPT,
# MON-I01S-ORACLE-KEEP and MON-I01S-MECH-GO; the build rules B-I01S-1, BP-1 to BP-11, B-L1-3 and B-L1-4) publishes the
# I01 digest contract v2 beside the frozen v1, adopted as candidate c4 after the in-tree CONTRACT rounds 1 to 3 of the
# MET-ENFORCE-042/contract series: architecture/policy-observation-digests-v2/ (README, definitions, vectors, status,
# the source index, the three rounds' records with their identities, the D5a oracle identity and B-L1-4's
# mechanics-pins.json) with its model scripts/policy_observation_digests_v2.py, edge record v11 with its README, and the
# D5a oracle test, with the registry rider: briefs.json gains this packet's PACKET and CONTRACT series. It is gate
# material only through the registry (GATE_REVIEW_PROCESS): the owner approves the merge per PR, bound to the head. Every
# non-chain file of design section 2's untouched list stays byte-identical, and the chain validators and tests among them
# change only by the chain-bump vocabulary, under the step rule (B-L1-3). Repository bytes and modes are read only
# through reviewed_bytes and reviewed_mode, so a later bridged successor projects its own edits away first; a path outside
# this era is refused before it is read, every era file is bound by digest on every read, and no directory is listed.
# Each refusal is a pure check over the values read, so every one has a failing case on plain data. Checked here: the
# freeze (this packet edits no existing file but chain validators, tests, the three living catalogs and the registry);
# the files this packet adds (exactly its own, each once; git mode 100644; no absolute local path); the adoption
# (status.json's closed shape and values: ADOPTED_DATA_CONTRACT, candidate c4, CONTRACT rounds 1 to 3 bound to their
# published records and identities, adoption MON-I01S-C4-ADOPT, the oracle member bound to the oracle identity's digest
# and I01 v1's status record by this era's digest; each round's record and identity; the source index's in-tree rounds;
# the oracle identity binding the oracle test with ruling KEEP); the model over its vectors, executed from this era's
# verified bytes with this era's frozen models as its imports (323 checks: the 16 helper vectors, the definitions pin,
# the 298 vector checks and the complete positive's 8), with definitions.json the model's definitions by the vectors'
# pin; the byte-equality (the model's SEALED_NAMESPACE, read from its source, is admission v4's sealed namespace and the
# complete positive's, and admission v4's renderer, the model's admission import, renders the sealed values to v4's
# published planeon-a2.json with its pinned directory hash); B-I01S-1 (the v2 complete binding is I01 v1's with exactly
# its two named members changed and v1's profileDigest, and no vector operation sets binding.profileDigest); edge record
# v11 (v10's members and 72 rows unchanged and in order, the seven new rows from this era's bytes and modes, and v10
# superseded by digest); the pins (B-L1-4's record: every byte-identical pin equal to its era bytes, every step-rule pin a
# chain file whose recorded predecessor bytes are this packet's inverse's, the registry row naming the base's entries by
# canonical digest and count, and every evolution-surface class re-derived by the era's model); the registry (the
# mechanics base's ten entries unchanged and in order, by this layer's inverse and the pins record, followed by exactly
# this packet's PACKET and CONTRACT entries, each pinning its generic brief, in the registry's own serialization); and
# the derived gate check (the gate paths among the packet's changed files, by the evolution surface record's 31 exact or
# prefix gate entries lower-cased, which equals case-folding on this era's all-ASCII gate entries and paths, are exactly
# the registry). The W1 assertions (VPO's validate_messages and profile v2 on the complete positive) are the head test's,
# which the pre-check and the verify run. Last, this layer's own inverse hunks are the canonical byte-minimal ones,
# recomputed from its era's bytes (MET-PERF-040's carried rule).
CONTRACT_DIR = "architecture/policy-observation-digests-v2/"
README_PATH = CONTRACT_DIR + "README.md"
DEFINITIONS_PATH = CONTRACT_DIR + "definitions.json"
VECTORS_PATH = CONTRACT_DIR + "vectors.json"
STATUS_PATH = CONTRACT_DIR + "status.json"
SOURCE_INDEX = CONTRACT_DIR + "source-index.json"
ORACLE_IDENTITY = CONTRACT_DIR + "oracle-identity-policy-observation-digests-v2.json"
PINS_PATH = CONTRACT_DIR + "mechanics-pins.json"
ROUNDS = (1, 2, 3)
REVIEW_RECORDS = tuple(CONTRACT_DIR + "review-round%d.json" % n for n in ROUNDS)
REVIEW_IDENTITIES = tuple(CONTRACT_DIR + "review-identity-round%d.json" % n for n in ROUNDS)
MODEL_PATH = "scripts/policy_observation_digests_v2.py"
ORACLE_TEST = "tests/test_policy_observation_digests_v2_oracle.py"
EDGES_DIR = "architecture/artifact-edges/"
EDGE_V10 = EDGES_DIR + "operator-harness-engineering-v10.json"
EDGE_V11 = EDGES_DIR + "operator-harness-engineering-v11.json"
EDGE_README = EDGES_DIR + "README-v11.md"
HEAD_TEST = "tests/test_policy_observation_digests_v2.py"
PACKET_PATH = "task-packets/" + NEW_PACKET + ".yaml"
# The adopted contract (candidate c4, MON-I01S-C4-ADOPT) with B-L1-4's pins record, the model, edge record v11 and the
# D5a oracle test: the files this packet adds besides its layer, its test, its authority and its packet file.
CONTRACT_FILES = (README_PATH, DEFINITIONS_PATH, VECTORS_PATH, STATUS_PATH, SOURCE_INDEX,
                  ORACLE_IDENTITY) + REVIEW_RECORDS + REVIEW_IDENTITIES + (PINS_PATH,)
NEW_FILES = CONTRACT_FILES + (MODEL_PATH, ORACLE_TEST, EDGE_V11, EDGE_README)
LIVING_CATALOGS = ("docs/MASTER_DEVELOPMENT_PLAN.md", "docs/repositories/00-harness-engineering.md",
                   "task-packets/README.md")
# I01 v1 (MET-ENFORCE-041), frozen beside v2: its status record and its vectors (B-I01S-1's complete binding).
V1_STATUS = "architecture/policy-observation-digests/status.json"
V1_VECTORS = "architecture/policy-observation-digests/vectors.json"
PREDECESSOR_PACKET = "MET-ENFORCE-041"
# The frozen models the v2 model imports (directly or through I06 v4), its frozen inputs and profile v2's schema: the
# files its replay pins by sha256 (its FROZEN_MODELS, FROZEN_INPUTS and PROFILE_SCHEMA).
V4_MODEL = "scripts/admission_semantics_v4.py"
P2_MODEL = "scripts/proxy_profile_v2.py"
I06V1_MODEL = "scripts/i06_backend_profile.py"
I06V3_MODEL = "scripts/i06_backend_profile_v3.py"
I06V4_MODEL = "scripts/i06_backend_profile_v4.py"
NQ4_MODEL = "scripts/native_qualification_v4.py"
FROZEN_MODELS = (V4_MODEL, P2_MODEL, I06V1_MODEL, I06V3_MODEL, I06V4_MODEL, NQ4_MODEL)
FROZEN_INPUTS = ("architecture/i06-backend-profile/identity-closure.json",
                 "architecture/i06-backend-profile/writer-inventory.json",
                 "architecture/i06-backend-profile/upstream-bootstrap-rbac-v1.37.1.json")
P2_SCHEMA = "architecture/proxy-profile-v2/profile.schema.json"
P2_VECTORS = "architecture/proxy-profile-v2/vectors.json"
V4_DIR = "architecture/admission-semantics-v4/"
V4_README = V4_DIR + "README.md"
V4_VECTORS = V4_DIR + "vectors.json"
V4_SEALED = V4_DIR + "admission-manifests/planeon-a2.json"
REGISTRY_PATH = "architecture/review-record/briefs.json"
PACKET_BRIEF = "architecture/review-briefs/REVIEW_BRIEF_PACKET.md"
CONTRACT_BRIEF = "architecture/review-briefs/REVIEW_BRIEF_CONTRACT.md"
SURFACE_RECORD = "architecture/evolution-surface/evolution-surface.json"
SURFACE_MODEL = "scripts/evolution_surface.py"
GATE_MATERIAL = 31
# status.json as written at adoption: its closed key set and the values this check restates.
STATUS_SCHEMA = "planeon.internal.policy-observation-digests-v2-status/v1"
STATUS_KEYS = ('schemaVersion',
 'workItem',
 'packet',
 'slot',
 'candidate',
 'base',
 'supersedes',
 'reviewSeries',
 'reviewRounds',
 'designHistory',
 'contractState',
 'candidateState',
 'predecessorRecord',
 'oracle',
 'ownerDecisions',
 'evidenceClass',
 'nativeAcceptance',
 'nonClaims',
 'carried',
 'readmeStatusNote',
 'installed',
 'wireContract',
 'independentReviewer',
 'adoption')
SERIES = NEW_PACKET + "/contract"
CANDIDATE = "c4"
# The contract's own base (status.json's base and the source index's baseMain): 263's merge, where c1-c4 were built.
CONTRACT_BASE = "675daccbc8a060d88245f79bf124f0cc6c59d0c2"
CONTRACT_STATE = "ADOPTED_DATA_CONTRACT"
INDEPENDENT_REVIEWER = "SEPARATE_AGENT_NOT_AUTHOR"
EVIDENCE_CLASS = "UNIT_VERIFICATION_ONLY"
ADOPTION = MappingProxyType({'ruling': 'MON-I01S-C4-ADOPT',
 'by': 'LANE_MONITOR',
 'date': '2026-10-25',
 'candidate': 'c4',
 'candidateCommit': '99c0e1db2305220d76079a6e25b5c4db5845be6a',
 'rebasedCommit': '2af5ce2355da7540f85ce1c23d77f924332433c6',
 'rebasedOnto': 'a88276171453760e46b28e8f6f0c0bb4bbfade5d',
 'rebase': 'c1-c4 rebased onto the mechanics base (264 merged), conflict-free and patch-identical; the '
           'contract files are byte-identical',
 'check': 'ADOPTION_CHECK_C4 923f849200ebb565501293fae2dfbc7fb90c232375ac34d6700a7307c05669c0 (kept with the '
          "lane's records)"})
# The three CONTRACT rounds: verdicts and subject commits (each later round's base is the previous round's subject).
ROUND_VERDICTS = ("CHANGES_REQUIRED", "CHANGES_REQUIRED", "PASS_FOR_ADOPTION")
ROUND_SUBJECTS = ('6cc40a1e31f40f73792dec7e48b687f02d2393ee',
 '4a310a82b3b4fc32d0b431659f074a84eee0cf70',
 'b8049763e4326acfba7d2ab85a93305c3689f30b')
ROUND_ROW_KEYS = ("round", "record", "recordSha256", "identity", "identitySha256", "verdict")
RECORD_SCHEMA = "planeon.review-record/v2"
IDENTITY_SCHEMA = "planeon.review-identity/v2"
INDEX_SCHEMA = "planeon.internal.policy-observation-digests-v2-index/v1"
# The D5a oracle identity (MON-I01S-ORACLE-KEEP; MON-I01S-ORACLE-REFUSAL-FORM), binding the oracle test.
ORACLE_SCHEMA = "planeon.oracle-identity/v1"
ORACLE_COMMIT = "cf1475cb922877bef4810f9a46762bc56415ac7e"
ORACLE_RULING = MappingProxyType({'decision': 'KEEP',
 'by': 'LANE_MONITOR',
 'ref': 'MON-I01S-ORACLE-KEEP; MON-I01S-ORACLE-REFUSAL-FORM',
 'date': '2026-10-25'})
# The model's replay (README section 10): 16 helper vectors, the definitions pin, 298 vector checks and the complete
# positive's 8 make 323.
MODEL_CHECKS = 323
HELPER_VECTORS = 16
VECTOR_CHECKS = 298
COMPLETE_CHECKS = 8
# F4 and DR1-F11: the sealed namespace and values, and admission v4's published sealed file and directory hash.
SEALED_NAMESPACE = "planeon-qual"
SEALED_VALUES = MappingProxyType({"ipFamily": "IPv4", "serviceCIDR": "10.96.0.0/12", "defaultTolerationSeconds": 300})
COMPLETE_SNAPSHOT = "qual"
SEALED_NAME = "planeon-a2.json"
SEALED_SIZE = 8322
SEALED_SHA256 = "92c21612304cb704d13b506c1ae885d62a47c01f0ed0d284affe563aa1868e32"
DIRECTORY_HASH = "sha256:9b1ddc1096ff0d35fb4cd5a9e5e6b4248fefc5b75b5a06f862c59d85e028ca60"
# B-I01S-1: the complete binding's two changed members, the unit-namespace fence and v1's profileDigest.
BINDING_CHANGES = (("enforcementPins", "admissionFenceDigest"), ("projections", "admissionPolicy", "projectionDigest"))
UNIT_FENCE = "sha256:8004085f93b447942e2aeffd00856e7dc485a063445a40c3518c60d6bd3c503f"
V1_PROFILE_DIGEST = "sha256:cdf3f7337ae938da6998d4084cca76300f31e72ecaac27a6d968b8dba4fa167b"
UNIT_VECTOR = "P-UNIT"
# BP-7: edge record v11 is v10 with its carried members and 72 rows, plus seven rows for HE-004-I01B4 (MON-I01S-D3), under
# v10's provenance rule (F6): the three files this packet publishes with providerCommit null and providerPacket this
# packet; the four files already on main at their last-change commit (263's merge) and with no providerPacket.
EDGE_ROWS_V10 = 72
EDGE_CARRIED = ("schemaVersion", "graph", "consumer", "provider", "ownerDecision", "rules", "notArtifacts", "statuses",
                "ownerDecisions")
EDGE_ARTIFACT = "policy-observation-i01-digests-v2"
EDGE_CONSUMER = "HE-004-I01B4"
ON_MAIN_COMMIT = "675daccbc8a060d88245f79bf124f0cc6c59d0c2"
EDGE_ROWS = ((DEFINITIONS_PATH, None, "host-enforcement/contracts/i01-digests-v2/definitions.json", NEW_PACKET),
             (VECTORS_PATH, None, "host-enforcement/contracts/i01-digests-v2/vectors.json", NEW_PACKET),
             (README_PATH, None, "host-enforcement/contracts/i01-digests-v2/README.md", NEW_PACKET),
             (V4_README, ON_MAIN_COMMIT, "host-enforcement/contracts/admission-v4/README.md", None),
             (V4_VECTORS, ON_MAIN_COMMIT, "host-enforcement/contracts/admission-v4/vectors.json", None),
             (V4_SEALED, ON_MAIN_COMMIT, "host-enforcement/contracts/admission-v4/admission-manifests/planeon-a2.json",
              None),
             (P2_VECTORS, ON_MAIN_COMMIT, "host-enforcement/contracts/i01-v2/proxy-profile-v2-vectors.json", None))
# B-L1-4's pins record: closed, its own schemaVersion and exactly two more members.
PINS_SCHEMA = "planeon.internal.policy-observation-digests-v2-pins/v1"
PINS_KEYS = ("schemaVersion", "unchangedPins", "evolutionSurfaceClasses")
PIN_KEYS = ("path", "lists", "sha256", "rule")
REGISTRY_PIN_KEYS = ("path", "lists", "sha256", "rule", "entries")
PIN_COUNTS = MappingProxyType({"BYTE_IDENTICAL": 250, "STEP_RULE": 2, "BASE_ENTRIES": 1})
PIN_LISTS = ("POD1", "PODM", "PODO", "PODA", "PODL", "PODT", "AS3M", "I06M", "NQ4M", "I06IN", "CS", "PV", "RD", "PPS",
             "PPV", "BASELINE", "PCA", "EDGES", "ADM2", "ADM3", "ADM4", "PP2", "LPKP", "LRR", "REGISTRY")
CLASS_FORMS = ("path", "pattern")
CLASS_NAMES = ("CONTRACT_AND_SOURCE", "ORACLE_TESTS", "REVIEW_RECORD", "GATE_REVIEW_PROCESS")
CLASS_SOURCES = ("DESIGN_REV3_SECTION_2", "B-L1-4")
CLASS_ROWS = 21
# The registry rider (design section 8; DR1-F7): the mechanics base's ten entries (264's merged registry, by digest),
# then this packet's two entries, in this order, each version 1.
BASE_ENTRIES = 10
BASE_REGISTRY_SHA256 = "b3681815203c426db5ceabbd52b49ba281be21c2df017b865181848a0e8ad8db"
REGISTRY_ENTRIES = (("PACKET", NEW_PACKET + "/packet", PACKET_BRIEF), ("CONTRACT", NEW_PACKET + "/contract", CONTRACT_BRIEF))
GATE_HITS = (REGISTRY_PATH,)
# Every file this era's check reads, with its digest: the files this packet adds, the byte-identical pins (the frozen
# models and inputs, I01 v1, admission v4's and profile v2's files and edge record v10 among them), the registry and the
# two generic briefs, and the evolution surface record and its model.
ERA_SHA256 = MappingProxyType({
    "architecture/admission-semantics-v2/README.md": "48e44b8d6a1c2fca5fffbad9c2fb97daf79ff5efeab221a781ec50e17ba1b9bf",
    "architecture/admission-semantics-v2/REVIEW_BRIEF.md": "06d3700c8f944d965d5c5c866f3a33e713565a9f67c1ab43167dd77da45ac189",
    "architecture/admission-semantics-v2/admission-manifests/planeon-a2.json": "1096b3cc71c4fe6b5a17ed61e8bf8c17ee17fcf52b192503534d60aed9ce4741",
    "architecture/admission-semantics-v2/allowlists.json": "2ab837aa50b7ee7fe58a19c9bc0aae67edb49ad4a143e19f928bc42def9bb863",
    "architecture/admission-semantics-v2/review-round1.json": "d14b2a293dcb4121fe177cf4ff2906bacfb210ca8df2fdbffb18b86d86194296",
    "architecture/admission-semantics-v2/review-round2.json": "db699de93ca7103501409e5bbad2614927551cd5905d8f371aff78dd0076629b",
    "architecture/admission-semantics-v2/round1/README.md": "a846ffce1075f33c165de99c69e23aa9737449485204f72d91df44ead58cb485",
    "architecture/admission-semantics-v2/round1/REVIEW_BRIEF.md": "96a1587e852ba85e2c0ac10244436f55097718ffd937085ae6fb40ba01ba1d77",
    "architecture/admission-semantics-v2/round1/admission-manifests/planeon-a2.json": "03653abf30414bf643e1ce3f88025a641c1f9b7bb8fc055ee2f5885beb139e73",
    "architecture/admission-semantics-v2/round1/admission_semantics_v2.py": "e948bb170f0c89a8a2d650e9a788087868fd1d4c4c51d4eacdb8fd683089cdbe",
    "architecture/admission-semantics-v2/round1/allowlists.json": "c9229ebfd6b06049fe1c3381edfc64c47f6c80ae58613cc3aa57cddd3d2ecf1e",
    "architecture/admission-semantics-v2/round1/source-index.json": "9aae1c36e30f111d7aa12630df3aa56f0ae3aa036d098cf58b13fc1c5b1adeb0",
    "architecture/admission-semantics-v2/round1/vectors.json": "af97e67f5524905cc2e274323d52dcec5fb9437ddb54d1989c9af837b779591c",
    "architecture/admission-semantics-v2/source-index.json": "6aaf3de6dd35b672254792d51dfd057f06f9878ef553c03b754dfec48b223ee9",
    "architecture/admission-semantics-v2/status.json": "6e58e6e957c71b6a945cdbfbcbca5bbf5d6b537b2d21a14bfe39806707692486",
    "architecture/admission-semantics-v2/vectors.json": "4b79b1ae23993d923d24a26a9e05ae2ea7a013bd722af5e8901176e08b98b2de",
    "architecture/admission-semantics-v3/README.md": "c3106482b4ff79649cbef7c65797c6fcd6b64f8419e871ae7d89eecad3ff98ab",
    "architecture/admission-semantics-v3/admission-manifests/planeon-a2.json": "1096b3cc71c4fe6b5a17ed61e8bf8c17ee17fcf52b192503534d60aed9ce4741",
    "architecture/admission-semantics-v3/allowlists.json": "9314cd0732880a8e6af91df562af0a392183f6ef078c12fa9b479f6953fad5d4",
    "architecture/admission-semantics-v3/status.json": "65fedb6284ae7ee70686166db0bcf0f2fdf37756b59ee3f3f8267b25b0ccfda7",
    "architecture/admission-semantics-v3/vectors.json": "a3e2dc9818742ae2188e0e83cf91bb833be836115975b3fb23d5f280f6928cc1",
    "architecture/admission-semantics-v4/README.md": "f7794aa857aa50800f05b651f7b0a56eda7407f67855bc2f0437b27b3fe297fa",
    "architecture/admission-semantics-v4/admission-manifests/planeon-a2.json": "92c21612304cb704d13b506c1ae885d62a47c01f0ed0d284affe563aa1868e32",
    "architecture/admission-semantics-v4/allowlists.json": "e399f5bbe4c5e84659693efa22f0d943e6a64ec291d3fa51dbf9c0614501e7f7",
    "architecture/admission-semantics-v4/status.json": "f2557234c7cb48f6b36c206a0730e6c7bf501fb6cc3d444e323afb9b6e2e78d4",
    "architecture/admission-semantics-v4/vectors.json": "5706b1a8df5cabd978caa219400b40a9c4ef6cbdbca8ea2f7c6f69b69474301c",
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
    "architecture/artifact-edges/README-v10.md": "3ae925596532dc491ceee829893793b49fb684a501ecdc049db6651062e79128",
    "architecture/artifact-edges/README-v11.md": "eff0f9c639f3ef0f3676f4f34bb669a6d9b3169321ac230f7593afa5b93f6a16",
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
    "architecture/artifact-edges/operator-harness-engineering-v11.json": "9188980f0ce211e2939d431d900a7aff77262de3a973009666ed13f3ef3cbd77",
    "architecture/artifact-edges/operator-harness-engineering-v2.json": "749e70f174d638468bf45d7316e8f5201c3323f6348a78c7b9a22d3a571ccc32",
    "architecture/artifact-edges/operator-harness-engineering-v3.json": "106ea91aa09c2d377adf3b514a228331d6a805bd1a17e641ecaa23b3c39115f3",
    "architecture/artifact-edges/operator-harness-engineering-v4.json": "e30772ff8826650c46d1a8d384625929975e47f2de5cc9030680b5fdb5e7fc86",
    "architecture/artifact-edges/operator-harness-engineering-v5.json": "89b47ef8f865b31911eb8da2b08a5a3c22b2d92a62599cb6fdfccbfe7f79e3c0",
    "architecture/artifact-edges/operator-harness-engineering-v6.json": "0ac7c2da62de87837f5a36a967a2c5b9c286ecab2e03f335a8eebbd32df9d24d",
    "architecture/artifact-edges/operator-harness-engineering-v7.json": "6af45e361a66331a9ee0216d3eea42f3a17770fd3c7d33e78e2a025d301bfa92",
    "architecture/artifact-edges/operator-harness-engineering-v8.json": "623cf10bf19cfba1806f5699007f39c7f6ba38f72d92069548421c4dccd21573",
    "architecture/artifact-edges/operator-harness-engineering-v9.json": "197f30e4e1e0be1dcacd71f1095c91e2333fe9d6ea05b8194578160e471605d7",
    "architecture/artifact-edges/operator-harness-engineering.json": "54bdc2d22676720419f51cd1bad5eedc909e6f848ed09cd363e351889af9d1fe",
    "architecture/backend-distribution/review-round1.json": "7121854c36005edaf3120de42e2ec6c51acfdc2ed314d7d471e6ea61d99df547",
    "architecture/backend-distribution/review-round2.json": "2d58ad8885952adbf816bbffb4adfcdce9ffee84f11129b7ac1bb209feb5e1f7",
    "architecture/backend-distribution/review-round3.json": "9a4c6a78ccc206b27e2d18fdcd5d5ebec785bee7011f2c7ad711a2cfdae38bf8",
    "architecture/backend-distribution/review-round4.json": "77e40813c9914c45ceaf397d0fef6ba890732faf2d9c5e5adb90987e5bdfe403",
    "architecture/backend-distribution/review-round5.json": "277c45930217b8d870393dcbc84e0be4e41809275dff769e8292327ab8842cc8",
    "architecture/compiled-filter-programs-v2/review-round1.json": "19d910b9e42e0a1bf94875211394c481c25e9234a95c0c20cf26ee0318465412",
    "architecture/compiled-filter-programs-v3/review-round1.json": "7df04fd0ca592ad6e8600521a280e3bf78b685c721196826f93ead00160c3d4a",
    "architecture/compiled-filter-programs-v3/review-round2.json": "55f7698fceda8bdadd7ca411b69d956c1f65fcb12862246391846aca387a6cb3",
    "architecture/compiled-filter-programs/reviews/review-round1.json": "04456f1a6ae1413bcee5cd9800dcd4da10a5478febf05bb70c8b992612f8fda5",
    "architecture/compiled-filter-programs/reviews/review-round2.json": "7da105f1b0485790e1959d30d08abbb6d11bd077d741d37ef7da06a346d86a6b",
    "architecture/compiled-filter-programs/reviews/review-round3.json": "5c6be3c9d2d5eca3a62e23cb420a94e3decbe6c9f03a8aa9b3f60079f239f56d",
    "architecture/compiled-filter-programs/reviews/review-round4.json": "853520a74b591cd0966c94e08328b1f56a1aa1c2d9e3da6c344c438f848206a6",
    "architecture/edge-record-v9/review-round1.json": "0265457922a7074cff647b73749936f1556b9bc341d3fbc4c73df1165f30290b",
    "architecture/edge-record-v9/review-round2.json": "220c77f3a305bd9608c2fd307c250f36880d8b143597c15115d899e6bc046cdd",
    "architecture/enforcement-test-plan/review-round1.json": "bd4c45e1c514dac45e1f32029462ac1bb8b984e57a3a3c2fdc5184cd5de1c0d4",
    "architecture/enforcement-test-plan/review-round2.json": "8d1eb0ce4734f8b2e5692aad9ba95622d7a2007dcd4d5af4f5667e3fe1b8efac",
    "architecture/enforcement-test-plan/review-round3.json": "a93e318279792543722238bc7395a2e0f35d9169b81346b34194fc66e9367f4e",
    "architecture/enforcement-test-plan/review-round4.json": "06b595e86862f76bc635334137c83798125ec9b5f5892522175abccf86bffda8",
    "architecture/evolution-surface/evolution-surface.json": "188c75d4be1b4c0eebfd01b9454873a09c903238ebdc05219126c734b0d245bd",
    "architecture/evolution-surface/review-round1.json": "ee803c3a647092075625ae8520cc0c820e17acd6f42b25695335a8fd58f65244",
    "architecture/evolution-surface/review-round2.json": "069d00325a589711b854d81f760308534ad65c4a456164f6b0c5e5e54e59b03b",
    "architecture/evolution-surface/review-round3.json": "df2a8761668d6f5500ec4c0cea89c6a26efa2e579666a96c2625f46ba11304e0",
    "architecture/evolution-surface/review-round4.json": "193c6fb6dcec8134d1d89369c996c3d62ab7f36643048277168d3a3b3c2c7d5b",
    "architecture/evolution-surface/review-round5.json": "dcd467bad420fd3eb5d29fa518a539ca4ac6c5350bd5e5b2f7610c5c9a6cb16c",
    "architecture/host-interface-amendment-hs43/review-round1.json": "e47b7bbf02eab405a149fe4d32cbe322e2478fa0c02175047382acbc7e1d93b9",
    "architecture/host-interface-amendment-hs43/review-round2.json": "e44df5199a7a36b5d4d4b4f3724ae5c1eb20b381b3f5f17f7320602980069ba1",
    "architecture/host-interface-amendment-hs43/review-round3.json": "59224861c3dbbf167af96350e1716773ffe1cff61aaaf3211541f6e8f2bd5438",
    "architecture/host-interface-amendment-hs43/review-round4.json": "bf6fa6912571e3bdfb344d84e5b1cc54c0e866c25a06a4009788bff05c0190d4",
    "architecture/host-interface-amendment-hs53/review-round1.json": "3c61bfe50e8dcceb8588ed73d308b1ba3cbcc5780cc5c4cfe2dd2235746cbebb",
    "architecture/host-interface-amendment-hs53/review-round2.json": "f5eb711f951e8a6d831f505c09481f6584ae3cf0e923089827e8281b00706fa3",
    "architecture/host-interface-amendment-hs53/review-round3.json": "88213cff08c2ed6206d04c1a8a6bc8583a0c5519b743d805d44bebede4fc6409",
    "architecture/host-interface-amendment-hs53/review-round4.json": "5a8b8552e0b3dcc3669192298a2d2f540368b2d7844de693d7fbdaa214e24d1f",
    "architecture/host-interface-amendment-hs53/review-round5.json": "ba55a54bbcb4752cae0daa64bd91ca2e3932a9e7d12a3d8aa96e12fb60bf89de",
    "architecture/host-interface-amendment-hs53/review-round6.json": "27764aaa83b46d3a8d4a87108649ac821954a5c5f64aa7d12e2f34ea634b8615",
    "architecture/host-interface-amendment-hs53/review-round7.json": "897df943326a299f41bd351325f00ff89abc111b84e9f0aee74151825bec288a",
    "architecture/host-interface-amendment-hs53/review-round8.json": "360b8cd6934043bd7af06712611660c09f86f5544a6cac81623834916a1a04ab",
    "architecture/host-interface-amendment-w02d/review-round1.json": "5f32cb233e2ff865c60a716e918974c8f12bc522dd50e068650080279036f967",
    "architecture/host-interface-amendment-w02d/review-round2.json": "322fd998ca4c359e072ec8ccfc67d332945f8325d4eb68161b1ca34df2508d86",
    "architecture/host-interface-amendment-w02d/review-round3.json": "d8aeecb0e82f4c10ca02debf9ac592e51d9289809cc0f56a84570cc70ce2ff51",
    "architecture/host-interface-amendment-w02d/review-round4.json": "a672b082bfca8ac6017affdaa6052804e1782bde927d6bb0d2b82633dab06618",
    "architecture/i05-gate-channel-v2/review-round1.json": "3c6eee315794439cb8b6759583796250d674f1a7cb6952f1111e7056dc60223f",
    "architecture/i05-gate-channel-v4/review-round1.json": "84487e57ceacc3ab4912f8e330911c525f46d87ed5386a6dc120850fa952d635",
    "architecture/i05-gate-channel-v4/review-round2.json": "b843768262c7d3314f38f1bfb6fd51656e1227c17880c7dc56fbc2e25c0f5632",
    "architecture/i05-gate-channel-v4/review-round3.json": "8d5b2be8692fd5ba5d0821b28ef4503c0ca4989f0e3bc9c87ebee59c1000dadc",
    "architecture/i05-gate-channel-v4/review-round4.json": "b2160bd504407d2b6cc9387c3e878a7992e91b6cf446ae4b7174ee11d533cfcf",
    "architecture/i05-gate-channel-v4/review-round5.json": "8b9ba30264fde2e62e7f807bc23d4c6f1868ae1b172e6fef1cee3557c3425b30",
    "architecture/i05-gate-channel/review-round1.json": "6acb048519e2929fbda6b9f1a1d87b6f07ab8ed7284cb859065334d9b11ed4c5",
    "architecture/i05-gate-channel/review-round2.json": "183944cccf2dcb4d8c5577338c52adb4e7e6ab6c1fafe8bea6c68d22e1eb76b8",
    "architecture/i05-gate-channel/review-round3.json": "cc0553095d5a2e7790d63302c82275b2c35618b3bf20ddf55d43dceae1725e9d",
    "architecture/i06-backend-profile-v2/review-round1.json": "b1f6501655c1860d5b3c79e8de2b9080e4b373ad81d057904e2f0af5b7f35332",
    "architecture/i06-backend-profile-v2/review-round2.json": "a5eefd7c6fb0f53f2a14880a079a69bd786c95be1ca8b3a3c5ab7c6de04cc0df",
    "architecture/i06-backend-profile-v2/review-round3.json": "1a04fb792d080ee70f24fc93da68df8238a1593e91c9072c2e6dd3f75bf48bd2",
    "architecture/i06-backend-profile-v4/review-round1.json": "06e61ab685c20345c6d6205c024ee8fc924a770c09f54a1156566cb8b5467299",
    "architecture/i06-backend-profile-v4/review-round2.json": "fb0f3a5d010e872b516b3f9d598d67be2158bd14df755dc5e00f223adc8449f8",
    "architecture/i06-backend-profile/identity-closure.json": "0a9b82ffa2d63bf48a8850574cdf3ece02bf1913f33a72cbb96ed30a40f1f3bb",
    "architecture/i06-backend-profile/review-round1.json": "95d11f53f44d6a984f1dea1d74eec300906f27bb8322bdba169f9cc0e610e373",
    "architecture/i06-backend-profile/review-round2.json": "c46c825e59efa8ba7a79e1db5efff5b981e10147e826542b6967b24921b90235",
    "architecture/i06-backend-profile/upstream-bootstrap-rbac-v1.37.1.json": "7529c2a713af2fb90163175924c264d95f4242d7e0c26b1452c77febb13ed50e",
    "architecture/i06-backend-profile/writer-inventory.json": "8e6b3b7565cfc93a61162b84d740cffb2871eb66ab85e8c4e80ac813f1af3077",
    "architecture/i07-policy-write-v2/review-round1.json": "38fc2d83fc07e32f6550d84ed1a8b0843c1322a31258c481b30f4c586bbb439d",
    "architecture/i07-policy-write/review-round1.json": "837333a076eb794c501d1d2cf754a360eda13d52179423d1199f6cdd60ed4a5a",
    "architecture/lab-run-plan/review-round1.json": "d6fa8b0f24a7761eb8c8c0b0cd1a4c14dc8f7204070848aff018467cbd16a308",
    "architecture/lab-run-plan/review-round2.json": "2f2f17a788e5e167942d45f802ddb054ef7a677b2b413b511882d6159ebb643d",
    "architecture/lab-run-plan/review-round3.json": "ba5aecc5833175f04021002771f5d0c6c82946e03727d12b90d6afc5fffcfed4",
    "architecture/lab-run-plan/review-round4.json": "7c994afa6b602b2bf6c884011b4a04033a125804c921725e31cd4beee23b6ec7",
    "architecture/lab-run-plan/review-round5.json": "2493f9bc8323626f2edb36a8752bb7b5bf9fcc7e372caaa4b1dd4b1940c626a8",
    "architecture/linux-probe-kit-admission/mechanics-pins.json": "de60e78717feb3304dd6032b5bc102a6f0aeeb22a6d37f710a131294f7a39d65",
    "architecture/native-profile-v2/review-round1.json": "9100034ec9d171ddad87d85c4c31b1a3ec9ee681060abb4ba85cbcc20816ef1c",
    "architecture/native-profile-v2/review-round2.json": "1a94aaca6c2309e795a3ca709096d79003c61eecdf31e408957f03937ec376ed",
    "architecture/native-profile-v2/review-round3.json": "a28bf4b9df183075eeef071d8af557ae1edd7bee92193612cfeb255ee763caf1",
    "architecture/native-profile-v3/review-round1.json": "6c2b96c5ad22be96c0c9877a62496930077514e686d18102d2ba9bfd6bd54706",
    "architecture/native-profile-v3/review-round2.json": "d7efcbbb00bbc32cd9d9fdeacd4413e7fd2f63a4f7be415c3082b6fe9ab1d741",
    "architecture/native-profile-v3/review-round3.json": "5a9db56cc15cd08615b395696d020e0771a574d2c7d8d77be03cdf6c7bcbad34",
    "architecture/native-profile-v3/review-round4.json": "853aa4dc70e0ebaa20d1e05ef7ba4f8fca7c06550e91ba3142d30f8260f82990",
    "architecture/native-profile-v3/review-round5.json": "2bea5b50f492de29bd0fc2b8beddb0447f6146bf63c86fa520464b1bb739306f",
    "architecture/native-profile-v3/review-round6.json": "dce53008c9b21f670935a6fb0c434678dec2538599fc757c46ac5a54a718c929",
    "architecture/native-profile-v4/review-round1.json": "6a22a9ae1d422def7d487780da79b9ddb84d9283dabf53a7c5bfc952463e34d9",
    "architecture/native-profile-v4/review-round2.json": "09d4035d8ab726e432a636aab9176a4d8b0a93041345b6cf7ee04a9aab89066b",
    "architecture/native-profile-v4/review-round3.json": "60f72eef0be1fea1a99ed883ff514aab966a2fee9e3bf84c0b39ac227a38e8a3",
    "architecture/native-profile-v5/review-round1.json": "0626a1f6f2bc878b25256dfa071b47ffe73f67a423c3c183e6b8d898235e8aab",
    "architecture/native-profile-v5/review-round2.json": "695cf190ea0f277b574f43b8c00ffdefeb20650403e7166319e5371524f7a44f",
    "architecture/native-profile-v5/review-round3.json": "3b5f9dec0c436618057910e8fb10257cb21cc363bc12ac7441be3831f33bcc32",
    "architecture/native-profile-v5/review-round4.json": "b8356184bd7ec0f4f50c9e6463ca6c6403e037d2f8a1eaa0a6bd3dcb552bda4f",
    "architecture/policy-observation-digests-authority.json": "d0507aaf7e7a5c5826ce362263bd950b41c58bac0398513aa839c79b083bebf2",
    "architecture/policy-observation-digests-v2/README.md": "fbb28445c5ec35bbf65bec5d852bd94de8b7c4acf8d2c239ee234e00c10d6090",
    "architecture/policy-observation-digests-v2/definitions.json": "fef08fddfb94e06eeff5bc4bdaf37246f9142fd072dd6427f629350c8d5cb2f2",
    "architecture/policy-observation-digests-v2/mechanics-pins.json": "3709c19e62f0fcc78a13f6996ad4c8036cd3174613d96e42b3dc51f940b205b5",
    "architecture/policy-observation-digests-v2/oracle-identity-policy-observation-digests-v2.json": "8be40cf6df8c720cca291251a1f9efb705a2c92d5733c3c230ef387601289f2d",
    "architecture/policy-observation-digests-v2/review-identity-round1.json": "67e109dcafee8767052a4d9c59082e0d91f59de2a3bbacbc4d632592b09145c7",
    "architecture/policy-observation-digests-v2/review-identity-round2.json": "58629e2e48a4bd8608285a0d3191eefebb344cce1414fdbccc81106b23f3ffc2",
    "architecture/policy-observation-digests-v2/review-identity-round3.json": "4da01b3de1fe60a3fdbf801a03de6a1f82c3c8c8a808a0ae71d4b73aa3044b6a",
    "architecture/policy-observation-digests-v2/review-round1.json": "b25518c92858807cae84a069f85b39e6323a68c622f8aa3189282f7d153a8c4d",
    "architecture/policy-observation-digests-v2/review-round2.json": "5851a7c526f5c2cce57959bfa0e48b893204b596c1e2f08fdd3536f18f10b2bb",
    "architecture/policy-observation-digests-v2/review-round3.json": "d0815a653139528d7dd44f8209819fdaf2b36f8554425143c1614715833f4796",
    "architecture/policy-observation-digests-v2/source-index.json": "0d0f5d73ed0e31d7bc8215557c856a93e6e56c1e1dbe6710a7f8d49f488cceb0",
    "architecture/policy-observation-digests-v2/status.json": "447442592a7c4b4e734cdfb801d8c739a466bb1e4a32ff4425db2a74f6a5a431",
    "architecture/policy-observation-digests-v2/vectors.json": "68eab4709431f73ce6f977aad7e5a087dccf9b5635c4ce04b8c08387bdce2594",
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
    "architecture/proxy-contract-amendment.json": "6c93e7db962cffa0281331c5220cdd8d5e453ab38ae39b4baa2e62be21a60600",
    "architecture/proxy-contract-inputs/baseline.json": "980ff63a57a6a167020f6d64297f946c92d7ce56b8c274b3fec56fb18bd837c1",
    "architecture/proxy-contract-inputs/profile.schema.json": "209349ccf44989566ffb39e2654fc91323b5eb2d9cbe895a4b18f33a349a226d",
    "architecture/proxy-contract-inputs/vectors.json": "edf32ddf992e06e8786fd331affdb4d2ecd5538ca874d52c37439386793a8eb7",
    "architecture/proxy-profile-v2/README.md": "6bda6500cf2af10c23acf09d99f95916901aa6e7729b348face9859cafd9ac8f",
    "architecture/proxy-profile-v2/profile.schema.json": "e5ef3c3d112bce97d94da4b465b52feb69935a144f26dd711440acd6c67ad592",
    "architecture/proxy-profile-v2/status.json": "950810f369e10e89224cd712d7eba2864b664ef5184152fe886a6b9351d9f685",
    "architecture/proxy-profile-v2/vectors.json": "011a650bcd2a11f2eaeba531693f3e7ee9c30c1f6ede2d5ecf87919f206affcc",
    "architecture/research-adoption-v2/review-round1.json": "aa1ccb39c6192453f190b36e81b754cd4e0e7300ca9c340b054f2879f9c07eb8",
    "architecture/research-adoption-v2/review-round2.json": "32699fce4b20a8944661a3750eccdb928c5d27c5964b735a155aca67ecc50162",
    "architecture/research-adoption-v2/review-round3.json": "ba8a8468fe39d026cda1230e78047d0c7011f9897893299630660a3405d7cf5f",
    "architecture/research-adoption-v2/review-round4.json": "cb4e7e28cea677c4a2a1d0f90f4a4d8af71d85db351955bb161d3dd409782d2f",
    "architecture/review-briefs/REVIEW_BRIEF_CONTRACT.md": "1f09d23451bf265e32e44742ca362dabf5a1090c2208c1349cbf491670798aec",
    "architecture/review-briefs/REVIEW_BRIEF_PACKET.md": "6dcff68d7e6b01823f1740063e94910edcc159a71a6ee803f1b66c62fd06e274",
    "architecture/review-record/briefs.json": "0b5ef207c92b68b89c537aedb32bbd88e03be6f2ba19bd78b5d2a9963f861e20",
    "architecture/run-events/review-round1.json": "b4f4b48bbd561ec82bbd5f873ea3785724bb5945c09cfde47a6d1432ada681ef",
    "architecture/run-events/review-round2.json": "bc7d6ea733d4424e581e0f37039310ec7be36c8451b0978a494af53f258f18c9",
    "architecture/run-events/review-round3.json": "a2ed3853df082695146ab1e2e950fefc7b4afd4bee6eb9d236bf45a22eedc8f9",
    "architecture/run-manifest/review-round1.json": "afa5b00fbef13310c5dfcdc6d90420d010ea9a334c45b1bcd51f159f847bc0ab",
    "architecture/run-manifest/review-round2.json": "6e6596240b6e9b8deec705245261dc926747905af61d0d61e9045b8324a509c9",
    "architecture/run-manifest/review-round3.json": "341395b9bb8bb1d049b91ac926cc4f5fcf0ad5796270ba3801b1b885df464ba8",
    "architecture/run-manifest/review-round4.json": "3d7605cf7b0c8f5bd171f36ffe2a93ca3083729ac3b62918abfa269154a0e739",
    "architecture/seccomp-allowlists-v3/review-round1.json": "daa6105613c0d6981f0db230c5f00db919b4c446aa25c7a8c03e754d438f548c",
    "architecture/seccomp-allowlists-v3/review-round2.json": "02a2bfefd385ae7520b786fbf239a4f78192312d5f348400aa970a4b3968bd62",
    "architecture/seccomp-allowlists-v4/review-round1.json": "8739fb46e9d6719d1ff41165f57dfa92a4a60582cf1f8c6c7884bb66fedc0b6c",
    "architecture/seccomp-allowlists-v4/review-round2.json": "39dce3f3e8f2424a7f3c4dcabf172b589b3e7ce8eb7153297f68d6fcd536a7f2",
    "architecture/seccomp-allowlists-v4/review-round3.json": "3ca2648f1827febe0b9121644d6d16f988f8eb64e23507c2f043caabb5f634cb",
    "architecture/seccomp-allowlists/review-round1.json": "66e073daad7c3e8937036fe9c3e3188c5ea39c5c142585caad499db9272843a1",
    "architecture/seccomp-allowlists/review-round2.json": "f033e367510a8e4d0b26ff159ae4a86bea9dc217a6455e6ea895272efdea99db",
    "architecture/seccomp-allowlists/review-round3.json": "5bf54b2f65aff009b4d8f275a52ed52dc61f1f2cd25de5073a99039fb83f9ffd",
    "architecture/sector-catalog/review-round4.json": "8d18b27dcd008f651f10dbe296c1afe64ad4bd41e20461f987da40ad1513ec8e",
    "architecture/selinux-matrix-v2/review-round1.json": "459d874f7e3c50fdaac86f4a57eaeeaf756caf71f9b87dc07c9c46c3a07e3d32",
    "architecture/selinux-matrix-v2/review-round2.json": "8f85b3c53c8a6b3e121ce3defb9df2f1c007e75146b917bcbdc9b44e768b328c",
    "architecture/selinux-matrix-v3/review-round1.json": "94a1fce3b7531432a87be81f466af4671fea3c3881ba13409407e834e9576736",
    "architecture/selinux-matrix-v3/review-round2.json": "0e0cbc69ea49f5a5a88607e7043a51cb78ea862aa7bb51fe589809bdf05eea9b",
    "architecture/selinux-matrix-v3/review-round3.json": "ddab1e126bf69be0156902959070c6a5b4b42dcb8698a2a3f9657251e80cd894",
    "architecture/selinux-matrix-v3/review-round4.json": "dae36843afa3e31acb116c96704ceafcadfb002290254c781dfff3b25e4b8aa9",
    "architecture/selinux-matrix-v4/review-round1.json": "af8f98f5fff373f6a5540d6258ec805f5fede8b1a5d3ce9850456c9099c009af",
    "architecture/selinux-matrix-v4/review-round2.json": "8cc287e6775f6cd555341e4a8e56fcdcaeea6e0d70f091d95434c68ba2bb14fd",
    "architecture/selinux-matrix-v4/review-round3.json": "658e0023d8db01d34f7804cd94d7d5cb6f1ce1b73eed3c3b15596baabb969c08",
    "architecture/selinux-matrix-v4/review-round4.json": "ca6bebf969e10c91ac0d38592412c7c7f3b93001ae093025711ab82bd46c2958",
    "architecture/selinux-matrix-v4/review-round5.json": "613249dc780292d5cc01a440bd17648405d5b2fa1caa6180c272b5428d5a60fc",
    "architecture/selinux-matrix-v4/review-round6.json": "932c283388b7e74a3b673e12e71604c731549016d1ee997e349f8e07e7122283",
    "architecture/selinux-matrix-v4/review-round7.json": "34b3e6cff7738576072b3f601680bccf143aa9e59d2d3c107865cc8f54a489dc",
    "architecture/selinux-matrix/review-round1.json": "8ae893dae83114df36f30f93651dd3d729d2de7c5e024651cac81921dc735fb3",
    "architecture/selinux-matrix/review-round2.json": "36e5a007b420b998029695eb4329187a6a2e7e351d804df62db08c90b7a316d1",
    "architecture/selinux-matrix/review-round3.json": "2b3761ac9b13acc0cb3a3629fcb496e306398d52f44e98ae22689054756ec050",
    "architecture/topology-coordination/review-round1.json": "086592ecf26b92c4272b7c9e478363711e43abe97cb3c9a42bd6f31889904b55",
    "architecture/topology-coordination/review-round2.json": "40fcf361b9a30e05d0cbffbb1a332459accd456614a0e95cc5a12cf64e61760b",
    "architecture/topology-coordination/review-round3.json": "5dbe150451847d1deac0dc0208b5c17503e4eeb732fd1e022703d5045f9bc8b4",
    "architecture/topology-coordination/review-round4.json": "e21270fa189ddcc0ffe9cba4774ee716f0c6e17c1393f8e3462650722341fa23",
    "architecture/topology-coordination/review-round5.json": "9c5e083d855ffa8f4f0d1b495a3037e3d26a0e7d087d76d671b153ff188b8b34",
    "architecture/verdict-ledger/review-round1.json": "c18c809d964ae67414a738400c81e1497eaa8e06cc3d056a901aee58089d4d51",
    "architecture/verdict-ledger/review-round2.json": "89b5b9804d1154da1323e449c0ced602c1fbbc9c0d6d444a2676b8a49b78a3e2",
    "architecture/verdict-ledger/review-round3.json": "3dfa7e2e0b6cffa008bc8216768c90e2f345ea79e360632aaccc59c8c9a635d0",
    "architecture/verdict-ledger/review-round4.json": "e69531fd5da78fc66ea4ac92dcc6c15316f59c73114dc985e5d5c14b7b4d8036",
    "architecture/verdict-ledger/review-round5.json": "1f6a2873952bdc24b94b2dd3f461783d3290e26d0a4dec019f83333b325ba9fd",
    "architecture/w02-adm-f/review-round1.json": "acd1e7f0ce7b85eb44c4278355db88102cd3c2ca88a78e1f137376950755935c",
    "architecture/w02-adm-f/review-round2.json": "7cc7456d01896203003d269804a9c1f50f663c5dc6f83d1bd93683660c7fd206",
    "architecture/w02-notes-errata/review-round1.json": "35b046c1b31dd062c91856b21869aad97f777e7298a0c3d6c28cc09ff21a4d8f",
    "architecture/w02-notes-errata/review-round2.json": "14cebfdf3b596b186360cf6897dd96a5f2b23a0d910b8bf7728067b82d3835fb",
    "architecture/w02-notes-errata/review-round3.json": "8de69961b8699064bc2729381591acbb05636e0301b494b12bea42e43e14738d",
    "architecture/w02-notes-errata/review-round4.json": "4177faaf9e33f8c06cf758ef514dfbc4e409b2ed6554db0ec022015e2eaed7b6",
    "architecture/w02-notes-errata/review-round5.json": "56e7ac7e08ec23712d20549feffe192b1c3de84ca12e74a3cff2b97a8ec5830f",
    "architecture/w02-notes-errata/review-round6.json": "8925fba2fba2547d5b67b7e40b411ad3208d29f61f4d8bd2900a45022045ecea",
    "architecture/w03-obligation-amendment-2/review-round1.json": "3d8ea6892f6f2b43cb8fc87b14a2504521c31a981c3d4826a22497dd2ee11f25",
    "architecture/w03-obligation-amendment-2/review-round2.json": "bc8d3b7241e8e603cf89f54db11feadc787f1affc4cf20ef2471de0798c85e8f",
    "architecture/w03-obligation-amendment-2/review-round3.json": "dd87d3e917081b1d10fffec8fba06c95551d7c6291dbf0e077061a2a1fe507ea",
    "architecture/w03-obligation-amendment-3/review-round1.json": "126af92049598048b7375ee5959eb2ecbf26e3512c9f16a10a57a9c1ee120519",
    "architecture/w03-obligation-amendment-3/review-round2.json": "df49466e204b3dbc1c8d5ba0e2109473b6394290d57c7c6a3282dfc00cf14ed1",
    "architecture/w03-obligation-amendment-3/review-round3.json": "6fba6636847758910c19c8c817c5b1e2451b814c551ad4125b7f50e578563991",
    "architecture/w03-obligation-amendment-3/review-round4.json": "f38a2b7b33d1fe3ed9432066792e1713608c6068d29f4da0abf5640e8d471eb2",
    "architecture/w03-plan-v2/review-round1.json": "71bb08a2f5567fab8d166a47329b9a97614771247fafe3407f6c5ce17811ee05",
    "architecture/w03-plan-v2/review-round2.json": "f13174528454c52828e95de115766a2adf9c557e73ea84e6bbd76e987a4bb00e",
    "architecture/w03-plan-v2/review-round3.json": "99f19b62fa940276773fcd4399cc337bc5da88fab055f81e1e0a9afa0f63190e",
    "architecture/w03-plan-v2/review-round4.json": "8296a17515e9f9d5bca3964fc41759e7a7161a218ba0373b7a147e7acd0e2864",
    "docs/alpha-2/POLICY_OBSERVATION_READINESS.md": "65778040919c5eb7335f2c104d983ca920b877b1b123f961556a6bcae36d232c",
    "legal/license-policy-amendment-v2/review-round1.json": "0fbbaa289ae5a0bc77aaeb0293910bacecfef9ddcf06ff1ddd90eba66f97689a",
    "legal/license-policy-amendment-v2/review-round2.json": "d75eecb7e012f5dcbcf4b61b747a2dfb5bbd9101806514cdec43ee7b4bc3931e",
    "legal/license-policy-amendment-v2/review-round3.json": "10831f2e1166c7e669f490069d77062a95ab6a76c4e72dfa3c7b44ee128adfb1",
    "legal/license-policy-amendment/review-round1.json": "01c48cf4d3fe5ed2fc4f3695dab9ebe5a98222c8e1973177893cb4c3773a4a2d",
    "legal/license-policy-amendment/review-round2.json": "10133203680941956eaee43dde7628c417834c2148c344ffb4d1bff30558f93c",
    "legal/license-policy-amendment/review-round3.json": "e073b9d6385fa571ff80a4bae7ba9980855c890375a53220469a72241b17fd8c",
    "legal/license-policy-amendment/review-round4.json": "46189374349481dadceed5c631be43ee6ead055dccb23bb17f357be4b48df6a9",
    "scripts/admission_semantics_v2.py": "b62a8c43a82f3e280da38b1dab5241f9b50fc0ef7ba6cf83c7a5f9b147d18d39",
    "scripts/admission_semantics_v3.py": "3db8f51ab55f49dc33cf6f028306bfb6d7aa1c5d7d96f264cfe709dae925ad22",
    "scripts/admission_semantics_v4.py": "4da5a71dfd4c9a3e46709ea8a754a58f48b76fe51bc2a526bfe07c40bc13b547",
    "scripts/evolution_surface.py": "f38fa6d00ec5fbbbcab8ff01d0e56824e805327b872dc1e23e579e522a681fd9",
    "scripts/i06_backend_profile.py": "bea3c953573478be5b03ab81b4ebd859da62d1eaa2a1be8f361b9dd39a98555e",
    "scripts/i06_backend_profile_v3.py": "dfb00e90199d436ae63b79261f2e04870d7861cb0f7a424971657a4d777754de",
    "scripts/i06_backend_profile_v4.py": "7f97acfe9060e79c101f264f5bf61610bf421326c689216cbaf41df7e38e6d2a",
    "scripts/native_qualification_v4.py": "f7c718072d1ffbb9b8bbc310e6141d476ea5f25296f70ff8c1bc9ada3db02387",
    "scripts/policy_observation_digests.py": "01298fb5c6acdae3248174265bbe576dd553eeb19bce1a48cb1e2734972c09c5",
    "scripts/policy_observation_digests_v2.py": "e1ba63d9e5ab8c27d4c509b2a0f2293921c681b74be7b9a8a4df2a63a75f40a3",
    "scripts/proxy_profile_v2.py": "509a4435e8bc1b8ab94efcb6fcc99e355ef27574ef0499bc4b6e89edef63fefa",
    "tests/test_policy_observation_digests_oracle.py": "3c2ca9f02efdf16e1ef3923f05df6bdbe6f36137400d0f77633a8f105cd70437",
    "tests/test_policy_observation_digests_v2_oracle.py": "5aea247e2621dbd1dc95a4f6ce8bc0ad5e28fc04c2e9d6274195e57476871cf1",
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


def _era_bytes(path: Any, raw: Any) -> bytes:
    """An era file's bytes, checked against its era digest; a path outside the era is refused."""
    expected = ERA_SHA256.get(path) if type(path) is str else None
    require(expected is not None, "MET-ENFORCE-042 reviewed bytes are bound: " + str(path))
    require(type(raw) is bytes and digest(raw) == expected, "unreviewed DIGEST-CONTRACT-V2 source: " + path)
    return raw


def _verified(path: str) -> bytes:
    """reviewed_bytes, checked against its era digest on every read; a path outside the era is refused before it is
    read."""
    require(type(path) is str and path in ERA_SHA256, "MET-ENFORCE-042 reviewed bytes are bound: " + str(path))
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
    this era's I06 v1 and native-profile v4 (the model's admission v4 and profile v2 imports are this era's copies by its
    era imports)."""
    _bound(lambda: type(models) is tuple and len(models) == 8 and models[0].i06v4 is models[1]
           and models[1].v1 is models[3] and models[1].v3 is models[2] and models[2].v1 is models[3]
           and models[2].w02a is models[4], "the model runs this era's frozen models: I06 v4 with I06 v1 and v3")


def era_models() -> tuple:
    """This era's reference model, executed from its verified bytes with this era's frozen models as its imports
    (admission v4, profile v2, I06 v1, and I06 v4 with I06 v1 and v3, and v3 with I06 v1 and native-profile v4), and the
    evolution surface model; VPC's three helpers resolve normally, as the contract pins them by behaviour vectors, not by
    file digest. Returns (the model, I06 v4, I06 v3, I06 v1, native-profile v4, admission v4, profile v2, the evolution
    surface model)."""
    np4 = _era_model(NQ4_MODEL, "_met_enforce_042_native_qualification_v4")
    v4 = _era_model(V4_MODEL, "_met_enforce_042_admission_semantics_v4")
    p2 = _era_model(P2_MODEL, "_met_enforce_042_proxy_profile_v2")
    i06v1 = _era_model(I06V1_MODEL, "_met_enforce_042_i06_backend_profile")
    i06v3 = _era_model(I06V3_MODEL, "_met_enforce_042_i06_backend_profile_v3",
                       {"i06_backend_profile": i06v1, "native_qualification_v4": np4})
    i06v4 = _era_model(I06V4_MODEL, "_met_enforce_042_i06_backend_profile_v4",
                       {"i06_backend_profile": i06v1, "i06_backend_profile_v3": i06v3})
    model = _era_model(MODEL_PATH, "_met_enforce_042_policy_observation_digests_v2",
                       {"admission_semantics_v4": v4, "i06_backend_profile": i06v1, "i06_backend_profile_v4": i06v4,
                        "proxy_profile_v2": p2})
    es = _era_model(SURFACE_MODEL, "_met_enforce_042_evolution_surface")
    models = (model, i06v4, i06v3, i06v1, np4, v4, p2, es)
    check_era_models(models)
    return models


def check_freeze(changed: Any) -> None:
    """This packet edits no existing file but chain validators (scripts/validate_*.py, one level deep), tests, the three
    living catalogs and the registry: no model, no earlier contract or record, no edge record and no conftest change."""
    for path in list(changed):
        require(type(path) is str and path not in ("conftest.py", "tests/conftest.py")
                and ((path.startswith("scripts/validate_") and path.endswith(".py") and path.count("/") == 1)
                     or path.split("/")[0] == "tests" or path in LIVING_CATALOGS or path == REGISTRY_PATH),
                "this packet edits only chain validators, tests, the three living catalogs and the registry: " + str(path))


def check_new_files(added: Any) -> None:
    """The packet adds exactly the thirteen files of the contract directory, the model, edge record v11 and its README,
    the oracle test and the layer's test, each once."""
    _bound(lambda: len(set(NEW_FILES)) == len(NEW_FILES) and type(added) is list
           and sorted(added) == sorted(NEW_FILES + (HEAD_TEST,)),
           "this packet adds exactly its contract files, model, edge record, oracle test and layer test, each once")


def check_added_file(path: str, mode: Any, raw: Any) -> None:
    """A file this packet adds is a regular file of git mode 100644 (not a link, not executable) and holds no absolute
    local path."""
    require(type(mode) is int and _git_mode(mode) == "100644",
            "a file this packet adds is a regular file of git mode 100644: " + path)
    require(type(raw) is bytes and not _local_path(raw), "no absolute local path in a file this packet adds: " + path)


def validate_files() -> None:
    """The freeze and the files this packet adds, from this era's authority and modes."""
    record = authority()
    check_freeze(list(_PROJECTION_RULES))
    check_new_files(list(record["newFiles"]))
    for path in NEW_FILES:
        check_added_file(path, reviewed_mode(path), _verified(path))


def _round_rows(rounds: Any) -> list:
    """The binding members of status.json's reviewRounds rows, from the published records' and identities' bytes."""
    return [{"round": n, "record": REVIEW_RECORDS[n - 1], "recordSha256": digest(record_raw),
             "identity": REVIEW_IDENTITIES[n - 1], "identitySha256": digest(identity_raw),
             "verdict": ROUND_VERDICTS[n - 1]} for n, (record_raw, identity_raw) in zip(ROUNDS, rounds)]


def check_status(status: Any, rounds: Any, oracle_identity_raw: Any, predecessor_raw: Any) -> None:
    """status.json's closed shape and values: MET-ENFORCE-042 on the contract's base, ADOPTED_DATA_CONTRACT, candidate c4
    (MON-I01S-C4-ADOPT), unit evidence only (not native, not installed, not a wire contract), the CONTRACT rounds 1 to 3
    bound to their published records and identities by digest, the oracle member bound to the oracle identity's digest,
    and I01 v1's status record by this era's digest."""
    _bound(lambda: type(status) is dict and tuple(status) == STATUS_KEYS and status["schemaVersion"] == STATUS_SCHEMA
           and status["packet"] == NEW_PACKET and status["candidate"] == CANDIDATE and status["base"] == CONTRACT_BASE
           and status["reviewSeries"] == SERIES and status["contractState"] == CONTRACT_STATE
           and status["independentReviewer"] == INDEPENDENT_REVIEWER and status["evidenceClass"] == EVIDENCE_CLASS
           and status["nativeAcceptance"] is False and status["installed"] is False and status["wireContract"] is False
           and status["adoption"] == dict(ADOPTION) and type(rounds) is list and len(rounds) == len(ROUNDS)
           and type(status["reviewRounds"]) is list
           and [{key: row[key] for key in ROUND_ROW_KEYS} for row in status["reviewRounds"]] == _round_rows(rounds)
           and type(oracle_identity_raw) is bytes and status["oracle"]["identity"] == ORACLE_IDENTITY
           and status["oracle"]["identitySha256"] == digest(oracle_identity_raw)
           and status["oracle"]["tests"] == ORACLE_TEST
           and type(predecessor_raw) is bytes and status["predecessorRecord"]["record"] == V1_STATUS
           and status["predecessorRecord"]["sha256"] == digest(predecessor_raw)
           and status["predecessorRecord"]["packet"] == PREDECESSOR_PACKET,
           "adopted DIGEST-CONTRACT-V2 status: candidate c4 with rounds 1 to 3, the oracle and v1's record by digest")


def check_round(n: int, record_raw: Any, identity_raw: Any, brief_raw: Any) -> None:
    """CONTRACT round n is a v2 record of the MET-ENFORCE-042/contract series with its verdict and subject (round 1 has
    no base; a later round's base is the previous round's subject), citing the registered generic CONTRACT brief by
    digest, and its identity binds it by path and digest with the same brief, subject and base."""
    _bound(lambda: n in ROUNDS and type(record_raw) is bytes and type(identity_raw) is bytes and type(brief_raw) is bytes
           and (lambda record, identity: record["schemaVersion"] == RECORD_SCHEMA and record["kind"] == "CONTRACT"
                and record["series"] == SERIES and type(record["round"]) is int and record["round"] == n
                and record["verdict"] == ROUND_VERDICTS[n - 1] and record["subject"]["commit"] == ROUND_SUBJECTS[n - 1]
                and ((n == 1 and "base" not in record)
                     or (n > 1 and record["base"]["commit"] == ROUND_SUBJECTS[n - 2]))
                and record["briefSha256"] == digest(brief_raw)
                and identity["schemaVersion"] == IDENTITY_SCHEMA
                and identity["record"] == {"path": REVIEW_RECORDS[n - 1], "sha256": digest(record_raw)}
                and identity["briefSha256"] == record["briefSha256"] and identity["subject"] == record["subject"]
                and identity.get("base") == record.get("base"))(parse(record_raw), parse(identity_raw)),
           "a CONTRACT round is bound to its published record and identity: round %d" % n)


def check_source_index(index: Any, rounds: Any) -> None:
    """source-index.json names this packet's series on the contract's base and its in-tree rounds by record and identity
    path and digest."""
    _bound(lambda: type(index) is dict and index["schemaVersion"] == INDEX_SCHEMA and index["packet"] == NEW_PACKET
           and index["series"] == SERIES and index["baseMain"] == CONTRACT_BASE and type(rounds) is list
           and len(rounds) == len(ROUNDS)
           and index["inTreeRounds"] == [{"round": n, "record": REVIEW_RECORDS[n - 1], "recordSha256": digest(record_raw),
                                          "identity": REVIEW_IDENTITIES[n - 1], "identitySha256": digest(identity_raw)}
                                         for n, (record_raw, identity_raw) in zip(ROUNDS, rounds)],
           "the source index names this packet's in-tree rounds")


def check_oracle_identity(identity_raw: Any, oracle_raw: Any) -> None:
    """The D5a oracle identity binds the oracle test by path and sha256 at the oracle candidate commit, with ruling KEEP by
    the lane monitor (check_tree checks the identity in full, in the suite)."""
    _bound(lambda: type(identity_raw) is bytes and type(oracle_raw) is bytes
           and (lambda identity: identity["schemaVersion"] == ORACLE_SCHEMA
                and identity["file"] == {"path": ORACLE_TEST, "sha256": digest(oracle_raw)}
                and identity["candidateCommit"] == ORACLE_COMMIT
                and identity["ruling"] == dict(ORACLE_RULING))(parse(identity_raw)),
           "the oracle identity binds the D5a oracle test, with ruling KEEP by the lane monitor")


def validate_adoption() -> None:
    """status.json, every round's record and identity, the source index and the oracle identity."""
    rounds = [(_verified(REVIEW_RECORDS[n - 1]), _verified(REVIEW_IDENTITIES[n - 1])) for n in ROUNDS]
    oracle_identity = _verified(ORACLE_IDENTITY)
    check_status(_json(STATUS_PATH), rounds, oracle_identity, _verified(V1_STATUS))
    brief = _verified(CONTRACT_BRIEF)
    for n in ROUNDS:
        check_round(n, rounds[n - 1][0], rounds[n - 1][1], brief)
    check_source_index(_json(SOURCE_INDEX), rounds)
    check_oracle_identity(oracle_identity, _verified(ORACLE_TEST))


def _vector_checks(vectors: Any) -> int:
    """The checks the model's replay makes over its vector rows (each pinned projection, enforcement digest and gate, each
    observation list and each same or differs relation), counted from the rows' expectations."""
    total = 0
    for row in vectors["vectors"]:
        expect = row["expect"]
        total += len(expect.get("projections", {})) + len(expect.get("enforcement", {})) + len(expect.get("gates", {}))
        total += (1 if "observation" in expect else 0) + len(expect.get("same", {})) + len(expect.get("differs", {}))
    return total


def check_replay(count: Any, vectors: Any, definitions_raw: Any) -> None:
    """The model replays its vectors with 323 checks (README section 10): the 16 helper vectors, the definitions pin, the
    298 vector checks counted from the rows and the complete positive's 8; and definitions.json is the model's
    definitions by the vectors' canonical pin."""
    _bound(lambda: type(count) is int and count == MODEL_CHECKS and type(definitions_raw) is bytes
           and len(vectors["helpers"]) == HELPER_VECTORS and _vector_checks(vectors) == VECTOR_CHECKS
           and count - HELPER_VECTORS - 1 - VECTOR_CHECKS == COMPLETE_CHECKS
           and vectors["contract"] == {"path": DEFINITIONS_PATH,
                                       "canonicalSha256": digest(canonical(parse(definitions_raw)))},
           "the model replays its vectors with 323 checks, the complete positive's 8 among them")


def _module_constant(raw: Any, name: str) -> Any:
    """The constant a module-level `name = <constant>` assignment binds in the source raw, else None."""
    values = [node.value.value for node in ast.parse(raw).body
              if isinstance(node, ast.Assign) and len(node.targets) == 1 and isinstance(node.targets[0], ast.Name)
              and node.targets[0].id == name and isinstance(node.value, ast.Constant)]
    return values[0] if len(values) == 1 else None


def check_sealed(raw: Any, rendered: Any, directory_hash: Any, namespace: Any, v4_sealed: Any, complete_snapshot: Any,
                 qual: Any) -> None:
    """F4 and DR1-F11: the model's SEALED_NAMESPACE is admission v4's sealed namespace and the complete positive's
    qualification namespace, with v4's sealed values; admission v4's renderer, the model's admission import, renders them
    to v4's published planeon-a2.json (8322 bytes with its stated digest), whose directory hash is v4's pinned one and the
    qual snapshot's pinned manifest hash."""
    _bound(lambda: namespace == SEALED_NAMESPACE and v4_sealed == dict(SEALED_VALUES, namespace=SEALED_NAMESPACE)
           and complete_snapshot == COMPLETE_SNAPSHOT
           and qual["configuration"]["qualificationNamespace"] == SEALED_NAMESPACE
           and qual["configuration"]["sealedAdmission"] == dict(SEALED_VALUES)
           and qual["configuration"]["pinnedManifestHash"] == DIRECTORY_HASH
           and type(raw) is bytes and len(raw) == SEALED_SIZE and digest(raw) == SEALED_SHA256 and raw == rendered
           and directory_hash == DIRECTORY_HASH,
           "the model's sealed namespace and admission v4's rendering are v4's sealed planeon-a2.json")


def validate_model(models: Any, vectors: Any) -> None:
    """The model's replay of its vectors with this era's frozen files, then the sealed namespace and admission v4's
    rendering of the sealed values."""
    model, v4 = models[0], models[5]
    files = {path: _verified(path) for path in FROZEN_MODELS + FROZEN_INPUTS + (P2_SCHEMA,)}
    check_replay(model.check_vectors(vectors, files), vectors, _verified(DEFINITIONS_PATH))
    namespace = _module_constant(_verified(MODEL_PATH), "SEALED_NAMESPACE")
    qual = vectors["fixtures"]["snapshots"][COMPLETE_SNAPSHOT]
    raw = _verified(V4_SEALED)
    check_sealed(raw, v4.manifest_file_bytes(dict(qual["configuration"]["sealedAdmission"], namespace=namespace)),
                 v4.manifest_directory_hash({SEALED_NAME: raw}), namespace, _json(V4_VECTORS)["sealed"],
                 vectors["complete"]["snapshot"], qual)


def _changed_members(old: Any, new: Any, path: tuple = ()) -> list:
    """The member paths at which two JSON values differ: a member present in one only, or a differing value."""
    if type(old) is dict and type(new) is dict:
        out = []
        for key in sorted(set(old) | set(new)):
            out += [path + (key,)] if key not in old or key not in new else _changed_members(old[key], new[key],
                                                                                              path + (key,))
        return out
    return [] if old == new else [path]


def _sets_profile_digest(op: Any) -> bool:
    """Whether a vector operation sets binding.profileDigest: its path is binding.profileDigest or below it, or the
    whole binding."""
    return op["path"][:2] == ["binding", "profileDigest"] or op["path"] == ["binding"]


def check_binding(binding: Any, v1_binding: Any, unit_digest: Any, rows: Any) -> None:
    """B-I01S-1: the v2 complete binding is I01 v1's with exactly two members changed, the admission fence (v4's
    unit-namespace directory hash) and the admissionPolicy projection digest (P-UNIT's re-derived digest); its
    profileDigest is v1's, the digest of v1's complete profile; and no vector operation sets binding.profileDigest."""
    _bound(lambda: type(binding) is dict and type(v1_binding) is dict
           and _changed_members(v1_binding, binding) == sorted(BINDING_CHANGES)
           and binding["enforcementPins"]["admissionFenceDigest"] == UNIT_FENCE
           and binding["projections"]["admissionPolicy"]["projectionDigest"] == unit_digest
           and binding["profileDigest"] == v1_binding["profileDigest"] == V1_PROFILE_DIGEST
           and type(rows) is list and not any(_sets_profile_digest(op) for row in rows for op in row["ops"]),
           "B-I01S-1: the v2 complete binding is v1's with its two named members changed and v1's profileDigest")


def validate_binding(vectors: Any) -> None:
    """B-I01S-1 over this era's v2 and v1 vectors."""
    unit = [row for row in vectors["vectors"] if row["id"] == UNIT_VECTOR]
    check_binding(vectors["fixtures"]["bindings"]["complete"], _json(V1_VECTORS)["fixtures"]["bindings"]["complete"],
                  unit[0]["expect"]["projections"]["admissionPolicy"]["digest"] if len(unit) == 1 else None,
                  vectors["vectors"])


def _edge_rows(files: Any, modes: Any) -> list:
    """The seven rows edge record v11 adds, from this era's bytes and modes of their provider paths."""
    rows = []
    for path, commit, consumer, packet in EDGE_ROWS:
        row = {"providerPath": path, "providerCommit": commit, "sha256": digest(files[path]),
               "mode": _git_mode(modes[path]), "consumerPath": consumer, "consumerPacket": EDGE_CONSUMER,
               "relation": "BYTE_IDENTICAL", "status": "REGISTERED_BEFORE_USE"}
        if packet is not None:
            row["providerPacket"] = packet
        rows.append(row)
    return rows


def check_edge(v11: Any, v10: Any, v10_raw: Any, rows: Any) -> None:
    """BP-7: edge record v11 is v10 with its member order and carried members unchanged, its own artifact name, v10's 72
    rows unchanged and in order, then exactly the seven new rows, and it supersedes v10 by digest."""
    _bound(lambda: type(v11) is dict and type(v10) is dict and tuple(v11) == tuple(v10)
           and all(v11[key] == v10[key] for key in EDGE_CARRIED) and v11["artifact"] == EDGE_ARTIFACT
           and len(v10["artifacts"]) == EDGE_ROWS_V10 and v11["artifacts"][:EDGE_ROWS_V10] == v10["artifacts"]
           and v11["artifacts"][EDGE_ROWS_V10:] == rows and type(v10_raw) is bytes
           and v11["supersedes"] == {"path": EDGE_V10, "sha256": "sha256:" + digest(v10_raw), "packet": PREDECESSOR_PACKET},
           "edge record v11 is v10's members and 72 rows with exactly the seven new rows, superseding v10 by digest")


def validate_edge() -> None:
    """Edge record v11 against v10 and the provider files' bytes and modes at this era."""
    files = {path: _verified(path) for path, _commit, _consumer, _packet in EDGE_ROWS}
    modes = {path: reviewed_mode(path) for path in files}
    v10_raw = _verified(EDGE_V10)
    check_edge(_json(EDGE_V11), parse(v10_raw), v10_raw, _edge_rows(files, modes))


def _chain_file(path: Any) -> bool:
    """A chain validator (scripts/validate_*.py, one level deep) or a test file."""
    return type(path) is str and path.count("/") == 1 and path.endswith(".py") and (
        path.startswith("scripts/validate_") or path.startswith("tests/test_"))


def check_pins_record(record: Any) -> None:
    """B-L1-4's record is closed: its schemaVersion and exactly unchangedPins and evolutionSurfaceClasses; the pins are
    sorted, unique and closed rows (250 byte-identical, 2 under the step rule, and the registry's base entries), each
    naming its lists, and the class rows are closed rows of one form each."""
    _bound(lambda: type(record) is dict and tuple(record) == PINS_KEYS and record["schemaVersion"] == PINS_SCHEMA
           and type(record["unchangedPins"]) is list and type(record["evolutionSurfaceClasses"]) is list
           and [row["path"] for row in record["unchangedPins"]] == sorted(set(row["path"] for row in record["unchangedPins"]))
           and all(type(row) is dict and row["rule"] in PIN_COUNTS
                   and tuple(row) == (REGISTRY_PIN_KEYS if row["rule"] == "BASE_ENTRIES" else PIN_KEYS)
                   and _sha(row["sha256"]) and type(row["lists"]) is list and len(row["lists"]) > 0
                   and all(label in PIN_LISTS for label in row["lists"]) for row in record["unchangedPins"])
           and {rule: len([row for row in record["unchangedPins"] if row["rule"] == rule]) for rule in PIN_COUNTS}
           == dict(PIN_COUNTS)
           and len(record["evolutionSurfaceClasses"]) == CLASS_ROWS
           and all(type(row) is dict and len(row) == 3 and row.get("class") in CLASS_NAMES
                   and row.get("source") in CLASS_SOURCES and len([form for form in CLASS_FORMS if form in row]) == 1
                   for row in record["evolutionSurfaceClasses"]),
           "the mechanics pins record is closed")


def check_pin(row: Any, raw: Any, rule: Any) -> None:
    """A byte-identical pin is an era file whose bytes have its recorded sha256 and which this packet does not change; a
    step-rule pin is a chain file this packet changes, whose recorded sha256 is its predecessor bytes' (this packet's
    inverse restores them; strictcheck governs the change); the base-entries row is the registry, which this packet
    changes, with the base's ten entries (check_registry compares them)."""
    _bound(lambda: (row["rule"] == "BYTE_IDENTICAL" and type(raw) is bytes and digest(raw) == row["sha256"]
                    and rule is None)
           or (row["rule"] == "STEP_RULE" and _chain_file(row["path"]) and type(rule) is dict
               and rule["beforeSha256"] == row["sha256"])
           or (row["rule"] == "BASE_ENTRIES" and row["path"] == REGISTRY_PATH and row["lists"] == ["REGISTRY"]
               and type(row["entries"]) is int and row["entries"] == BASE_ENTRIES and type(rule) is dict),
           "an unchangedPins row holds at this era: " + str(row.get("path") if type(row) is dict else row))


def class_paths(row: Any, paths: Any) -> list:
    """The packet paths a class row covers: its path, or the paths matching its <n> pattern (n a decimal number without a
    leading zero)."""
    if "path" in row:
        return [row["path"]] if row["path"] in paths else []
    head, tail = row["pattern"].split("<n>")
    out = []
    for path in paths:
        middle = path[len(head):len(path) - len(tail)] if len(path) > len(head) + len(tail) else ""
        if (path.startswith(head) and path.endswith(tail) and middle and middle[0] != "0"
                and all(char in "0123456789" for char in middle)):
            out.append(path)
    return out


def check_classes(rows: Any, paths: Any, resolved: Any) -> None:
    """Every class row covers at least one of the packet's paths, and the evolution surface record, run by its model from
    this era's bytes, resolves each covered path to the row's class."""
    _bound(lambda: type(rows) is list and type(paths) is list and type(resolved) is dict
           and all(len(class_paths(row, paths)) > 0
                   and all(resolved[path] == row["class"] for path in class_paths(row, paths)) for row in rows),
           "every evolution-surface class row resolves to its class at this era")


def _packet_paths() -> list:
    """The packet's changed and added paths, with its authority, layer and packet file."""
    record = authority()
    return sorted(set(record["changedFiles"]) | set(record["newFiles"]) | {AUTHORITY_PATH, VALIDATOR_PATH, PACKET_PATH})


def validate_pins(es: Any) -> None:
    """B-L1-4's record: its closed shape, every pin at this era (each byte-identical pin through the era's bytes), and every
    class row re-derived by the era's evolution surface model."""
    record = _json(PINS_PATH)
    check_pins_record(record)
    rules = authority()["changedFiles"]
    for row in record["unchangedPins"]:
        raw = _verified(row["path"]) if row["rule"] == "BYTE_IDENTICAL" else None
        check_pin(row, raw, rules.get(row["path"]))
    paths = _packet_paths()
    surface = _json(SURFACE_RECORD)
    resolved = {path: es.resolve(surface, path) for row in record["evolutionSurfaceClasses"]
                for path in class_paths(row, paths)}
    check_classes(record["evolutionSurfaceClasses"], paths, resolved)


def _serialized(registry: Any) -> bytes:
    """The registry's own serialization: one-space indent, ASCII escapes, key order kept and a final newline."""
    return (json.dumps(registry, indent=1) + "\n").encode("ascii")


def check_registry(raw: Any, base_raw: Any, briefs: Any, pin: Any) -> None:
    """The registry is the mechanics base's (264's merged file, by digest, through this layer's inverse) with its schema,
    kinds and ten entries unchanged and in order (and those entries' canonical digest and count the pins record's),
    followed by exactly this packet's PACKET and CONTRACT entries, each pinning its generic brief by the sha256 of the
    brief's bytes, in the registry's own serialization."""
    _bound(lambda: type(raw) is bytes and type(base_raw) is bytes and digest(base_raw) == BASE_REGISTRY_SHA256
           and type(briefs) is dict and type(pin) is dict and pin["path"] == REGISTRY_PATH
           and pin["rule"] == "BASE_ENTRIES" and pin["entries"] == BASE_ENTRIES
           and (lambda registry, base: tuple(registry) == tuple(base)
                and registry["schemaVersion"] == base["schemaVersion"] and registry["kinds"] == base["kinds"]
                and len(base["briefs"]) == BASE_ENTRIES and registry["briefs"][:BASE_ENTRIES] == base["briefs"]
                and digest(canonical(registry["briefs"][:BASE_ENTRIES])) == pin["sha256"]
                and registry["briefs"][BASE_ENTRIES:] == [
                    {"kind": kind, "series": series, "path": path, "sha256": digest(briefs[path]), "version": 1}
                    for kind, series, path in REGISTRY_ENTRIES]
                and _serialized(registry) == raw)(parse(raw), parse(base_raw)),
           "the registry is the base's ten entries followed by exactly this packet's two entries, each pinning its brief")


def validate_registry() -> None:
    """briefs.json against 264's merged bytes (this layer's own inverse), B-L1-4's registry row and the two generic
    briefs."""
    raw = _verified(REGISTRY_PATH)
    pins = [row for row in _json(PINS_PATH)["unchangedPins"] if row["path"] == REGISTRY_PATH]
    check_registry(raw, _undo_this_layer(REGISTRY_PATH, raw),
                   {path: _verified(path) for path in (PACKET_BRIEF, CONTRACT_BRIEF)}, pins[0] if len(pins) == 1 else None)


def check_gate_list(gate: Any) -> None:
    """The evolution surface record, run by its model from this era's bytes, derives 31 gate-material entries, each an
    exact path or a prefix (no under-plus-name entry is left in the derived list at this era)."""
    _bound(lambda: type(gate) is list and len(gate) == GATE_MATERIAL
           and all(type(entry) is dict and len(entry) == 1 and ("exact" in entry or "prefix" in entry)
                   for entry in gate),
           "the evolution surface record derives 31 exact or prefix gate entries")


def gate_paths(gate: list, paths: list) -> list:
    """The paths a gate entry matches: an exact path, or a path under a prefix, each compared lower-cased, which equals
    case-folding on this era's all-ASCII gate entries and changed paths (260's packet review r1's R1-2)."""
    return [path for path in paths
            if any(("exact" in entry and path.lower() == entry["exact"].lower())
                   or ("prefix" in entry and path.lower().startswith(entry["prefix"].lower())) for entry in gate)]


def check_gate_hits(gate: Any, changed: Any) -> None:
    """The derived gate check (261's form; design section 8, BP-10): the gate paths among the packet's changed files, by
    the record's gate entries, are exactly the registry."""
    _bound(lambda: type(changed) is list and changed == sorted(changed) and gate_paths(gate, changed) == list(GATE_HITS),
           "the gate paths among the packet's changed files are exactly the registry")


def validate_gate(es: Any) -> None:
    """The gate list derived from this era's evolution surface record against the packet's changed files."""
    gate = es.check(_json(SURFACE_RECORD))["gateMaterial"]
    check_gate_list(gate)
    check_gate_hits(gate, _packet_paths())


def validate_policy_observation_digests_v2() -> None:
    """Every reviewed byte first; then the freeze and the files this packet adds, the adoption, the model over its vectors
    and admission v4's rendering, B-I01S-1's binding, edge record v11, the pins and classes, the registry and the derived
    gate check; last, this layer's canonical hunks."""
    for path in ERA_SHA256:
        _verified(path)
    validate_files()
    validate_adoption()
    models = era_models()
    vectors = _json(VECTORS_PATH)
    validate_model(models, vectors)
    validate_binding(vectors)
    validate_edge()
    validate_pins(models[7])
    validate_registry()
    validate_gate(models[7])
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
            == record["validatorNormalizedSha256"], "policy observation digests v2 validator drift")
    paths = sorted((ROOT / "task-packets").glob("*.yaml"))
    old = set(record["baselinePackets"])
    require(len(paths) == 270
            and {path.stem for path in paths} == old | {NEW_PACKET, successor.NEW_PACKET, successor.successor.NEW_PACKET, successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.NEW_PACKET},
            "closed 270-packet catalog retaining the 265-packet checkpoint")
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
            "closed source-only policy-observation-digests-v2 packet and inherited commands")
    require(len(packet["allowedPaths"]) == len(set(packet["allowedPaths"]))
            and set(packet["allowedPaths"]) == set(record["changedFiles"])
            | set(record["newFiles"]) | {AUTHORITY_PATH, VALIDATOR_PATH,
                                         "task-packets/" + NEW_PACKET + ".yaml"},
            "unreviewed or omitted policy-observation-digests-v2 packet path")
    for path, rule in record["changedFiles"].items():
        current = successor.historical_bytes(path, regular_bytes(path))
        require(digest(current) == rule["afterSha256"]
                and digest(historical_bytes(path, current)) == rule["beforeSha256"],
                "unreviewed current source: " + path)
    for path, expected in record["newFiles"].items():
        require(digest(successor.historical_bytes(path, regular_bytes(path))) == expected,
                "new source drift: " + path)
    validate_policy_observation_digests_v2()


if __name__ == "__main__":
    validate()
    print("Policy observation digests v2 valid: 270 current specifications; 265-packet checkpoint and exact 264-packet predecessor; contract reviewed.")
