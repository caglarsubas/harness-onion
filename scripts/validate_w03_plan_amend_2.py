#!/usr/bin/env python3
"""Validate the MET-ENFORCE-032 W03 obligation-register amendment 2 and the exact 244-to-243 projection."""
from __future__ import annotations

import ast
import base64
import binascii
import builtins
import copy
import difflib
import hashlib
import json
import re
import stat
import types
from functools import lru_cache
from pathlib import Path
from types import MappingProxyType
from typing import Any

try:
    from safe_yaml import safe_load
    import validate_topology_coordination as successor
except ImportError:
    from scripts.safe_yaml import safe_load
    from scripts import validate_topology_coordination as successor


ROOT = Path(__file__).resolve().parents[1]
AUTHORITY_PATH = "architecture/w03-plan-amend-2-authority.json"
AUTHORITY_SHA256 = "0052047a9a868185769fe6744eb38bcda9d61d96ae82178de6b2ce784299c12e"
VALIDATOR_PATH = "scripts/validate_w03_plan_amend_2.py"
BASE_COMMIT = "b0635f81e5ba3b6538fc0cfd28a78f0fea962f50"
NEW_PACKET = "MET-ENFORCE-032"
PREVIOUS_PACKET = "MET-ENFORCE-031"
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
            require(key not in result, "duplicate w03-plan-amend-2 authority member")
            result[key] = value
        return result

    def no_constant(_value: str) -> Any:
        raise ValueError("nonfinite w03-plan-amend-2 authority number")

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
        require(digest(raw) == AUTHORITY_SHA256, "w03 plan amendment 2 history authority digest")
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
    }, "closed w03 plan amendment 2 history authority")
    require(value["schemaVersion"] == "harness.planeon.ai/w03-plan-amend-2-authority/v1"
            and value["authorityPacket"] == NEW_PACKET
            and value["acceptedBase"] == BASE_COMMIT
            and type(value["baselinePackets"]) is dict
            and len(value["baselinePackets"]) == 243
            and NEW_PACKET not in value["baselinePackets"]
            and type(value["changedFiles"]) is dict
            and type(value["newFiles"]) is dict
            and _sha(value["packetSha256"])
            and _sha(value["validatorNormalizedSha256"]),
            "accepted 243-packet base")
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
    # An exact 243-era byte string is already older than the successor layer.
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


# MET-ENFORCE-032 (roadmap W03-PLAN-AMEND-2; adopted by the lane monitor's owner-delegated decision, 2026-10-16, after
# three independent review rounds) publishes W03 obligation-register amendment 2 and the operator -> harness-engineering
# edge record v4. The amendment applies after amendment 1: plan v2's HE-004 is refined into its five parts (closed change
# kind REFINED), I01, the observer's read grants and wrapper evidence and the I05 v4 adoption gain obligations, and
# packets and shares are added. Edge record v4 is v3's 33 rows, unchanged and in order, plus 12 rows registered before
# use. Plan v2, amendment 1, edge record v3 and the 12 registered provider files stay byte-identical. Repository bytes and
# modes are read only through reviewed_bytes and reviewed_mode, so a later bridged successor projects its own edits away
# first; a path outside this era is refused before it is read, and every era file is bound by digest on every read. The
# bindings, the change kinds and the refinement rule, both edge records and the adoption record are restated and checked
# here, independently of the contract's builder. This layer's own inverse hunks are the canonical byte-minimal ones,
# recomputed from its era's bytes (MET-PERF-040's carried rule).
AM2_DIR = "architecture/w03-obligation-amendment-2/"
EDGES_DIR = "architecture/artifact-edges/"
AMENDMENT = AM2_DIR + "amendment.json"
README_PATH = AM2_DIR + "README.md"
STATUS_PATH = AM2_DIR + "status.json"
V4_EDGE = EDGES_DIR + "operator-harness-engineering-v4.json"
V4_README = EDGES_DIR + "README-v4.md"
V3_EDGE = EDGES_DIR + "operator-harness-engineering-v3.json"
PLAN_V2 = "architecture/w03-plan-v2/plan.json"
AMENDMENT_1 = "architecture/w03-obligation-amendment-1/amendment.json"
# The reviewed subject in the review records' order, and the adopted candidate 4's bytes as the adoption names them.
SUBJECT = (AMENDMENT, README_PATH, V4_EDGE, V4_README)
ADOPTED_SHA256 = {AMENDMENT: "a1d861866136a52c378777ab4bb974df856cccf147551b0dab8c4fad8f234f0b",
                  README_PATH: "ae51309afc5258371c78a0ba6ef55bf39439f79cb7f1ecc7fc8ae02f5caf9b16",
                  V4_EDGE: "e30772ff8826650c46d1a8d384625929975e47f2de5cc9030680b5fdb5e7fc86",
                  V4_README: "11e6bbefc27d82d359c7f48a873374786a760881693fd7d9ec7e88916ab2558b"}
BASE_MAIN = "b0635f81e5ba3b6538fc0cfd28a78f0fea962f50"
REVIEW_BASE = "fd362f9eb64d6e9928f26fac5e339a50b8dee516"
ROUNDS = ((1, "CHANGES_REQUIRED"), (2, "CHANGES_REQUIRED"), (3, "PASS_FOR_ADOPTION"))
STATUS_KEYS = ("schemaVersion", "workItem", "amendmentId", "status", "adoption", "baseMain", "reviewBase", "adoptedSubject",
               "independentReviewer", "readmeStatusNote", "recordPaths", "rounds", "closedFindings", "carried", "nonClaims")
ROW_KEYS = ("round", "record", "recordSha256", "verdict", "subjectSha256", "snapshot", "keptCopies")
ADOPTION = {"decidedBy": "the lane monitor, owner-delegated", "date": "2026-10-16",
            "decision": "[lane monitor] **ADOPTED**: W03-PLAN-AMEND-2 contract candidate 4. Monitor decision "
                        "(owner-delegated), 2026-10-16. It rests on review r3 PASS_FOR_ADOPTION, and every owner and monitor "
                        "answer it carries is already recorded."}
CLOSED_FINDINGS = {**{"C1-%d" % n: "CLOSED in round 2" for n in range(1, 15) if n not in (9, 12, 14)},
                   **{"C1-%d" % n: "CLOSED in round 3" for n in (9, 12, 14)},
                   "C1-15": "DISCHARGED at mechanics (see carried)",
                   **{"C2-%d" % n: "CLOSED in round 3" for n in range(1, 7)},
                   "C3-1": "APPLIED in candidate 4 (the adopted amendment.json and README.md: OBS-RBAC-1's first sentence)"}
CARRIED = (("C3-2 (contract review round 3, NOTE)", "the packet review"),
           ("C1-15 (contract review round 1, NOTE)", "the packet mechanics"))
NON_CLAIMS = ["Plan v2, amendment 1 and edge record v3 are byte-identical.",
              "No R10 file changes in this packet.",
              "The 12 files edge record v4 adds are registered, not used, until the R10 consumer packets."]
# Both READMEs keep their reviewed candidate status (readmeStatusNote).
CANDIDATE = "Status: **CONTRACT_CANDIDATE_AWAITING_INDEPENDENT_REVIEW**"
# C3-1, applied in candidate 4: OBS-RBAC-1's first sentence names HE-004C's requests.
C3_1_TEXT = ("The policy observer's Kubernetes read grants are exactly those HE-004C's requests need: HE-004B1's request "
             "specs, API discovery, nonResourceURL /metrics (ADM-4) and /readyz (OR07).")
REFINED_PACKET = "HE-004"
CHANGE_KINDS = frozenset({"ADDED", "REFINED", "PACKETS_ADDED"})
# A decision id as the records write it (Q-HE4-1, Q-HE4-3/4, Q-HE4A-B2, Q-HE4B-10).
DECISION_ID = re.compile(r"\bQ-[A-Z0-9]+(?:-[A-Z0-9]+)*(?:/[0-9]+)?")
V3_ROWS = 33
V3_PACKET = "MET-ENFORCE-029"
EDGE_ROW_KEYS = ("providerPath", "providerCommit", "sha256", "mode", "consumerPath", "consumerPacket", "relation", "status")
CONSUMER_PREFIX = "host-enforcement/contracts/"
# Edge record v4's 12 new rows: (provider path, provider commit, consumer path, consumer packet). Each commit is the file's
# last-change commit at the accepted base, and its bytes there are the bytes pinned below, as the packet's builder proved
# from git at both the review base and the accepted base (review note C1-15); the files are frozen in this era.
NEW_ROWS = (
    ("architecture/i06-backend-profile-v2/vectors.json",
     "4f75dedd20f1ebbe262799651abed8f5ee2fe502", "host-enforcement/contracts/i06-v2/vectors.json", "HE-004"),
    ("architecture/i06-backend-profile-v2/criteria.json",
     "4f75dedd20f1ebbe262799651abed8f5ee2fe502", "host-enforcement/contracts/i06-v2/criteria.json", "HE-004"),
    ("architecture/i06-backend-profile-v2/README.md",
     "4f75dedd20f1ebbe262799651abed8f5ee2fe502", "host-enforcement/contracts/i06-v2/README.md", "HE-004"),
    ("architecture/i06-backend-profile/identity-closure.json",
     "fe50b57c0e6b6d5e5732b1b346bbad8727959a6f", "host-enforcement/contracts/i06-v1/identity-closure.json", "HE-004"),
    ("architecture/i06-backend-profile/writer-inventory.json",
     "fe50b57c0e6b6d5e5732b1b346bbad8727959a6f", "host-enforcement/contracts/i06-v1/writer-inventory.json", "HE-004"),
    ("architecture/i06-backend-profile/upstream-bootstrap-rbac-v1.37.1.json",
     "fe50b57c0e6b6d5e5732b1b346bbad8727959a6f", "host-enforcement/contracts/i06-v1/upstream-bootstrap-rbac-v1.37.1.json", "HE-004"),
    ("architecture/i06-backend-profile/README.md",
     "fe50b57c0e6b6d5e5732b1b346bbad8727959a6f", "host-enforcement/contracts/i06-v1/README.md", "HE-004"),
    ("architecture/admission-semantics-v3/vectors.json",
     "4196dae972f2a2636a5176e2cef440c01bf03a98", "host-enforcement/contracts/admission-v3/vectors.json", "HE-004"),
    ("architecture/admission-semantics-v3/README.md",
     "4196dae972f2a2636a5176e2cef440c01bf03a98", "host-enforcement/contracts/admission-v3/README.md", "HE-004"),
    ("architecture/admission-semantics-v3/admission-manifests/planeon-a2.json",
     "4196dae972f2a2636a5176e2cef440c01bf03a98", "host-enforcement/contracts/admission-v3/admission-manifests/planeon-a2.json", "HE-004"),
    ("architecture/i05-gate-channel-v4/README.md",
     "fd362f9eb64d6e9928f26fac5e339a50b8dee516", "host-enforcement/contracts/i05-v4/README.md", "HE-003A3"),
    ("architecture/i05-gate-channel-v4/vectors.json",
     "fd362f9eb64d6e9928f26fac5e339a50b8dee516", "host-enforcement/contracts/i05-v4/vectors.json", "HE-003A3"),
)
# Plan v2, amendment 1, edge record v3 and the 12 registered provider files stay byte-identical.
FROZEN_PATHS = (
    "architecture/admission-semantics-v3/README.md",
    "architecture/admission-semantics-v3/admission-manifests/planeon-a2.json",
    "architecture/admission-semantics-v3/vectors.json",
    "architecture/artifact-edges/operator-harness-engineering-v3.json",
    "architecture/i05-gate-channel-v4/README.md",
    "architecture/i05-gate-channel-v4/vectors.json",
    "architecture/i06-backend-profile-v2/README.md",
    "architecture/i06-backend-profile-v2/criteria.json",
    "architecture/i06-backend-profile-v2/vectors.json",
    "architecture/i06-backend-profile/README.md",
    "architecture/i06-backend-profile/identity-closure.json",
    "architecture/i06-backend-profile/upstream-bootstrap-rbac-v1.37.1.json",
    "architecture/i06-backend-profile/writer-inventory.json",
    "architecture/w03-obligation-amendment-1/amendment.json",
    "architecture/w03-plan-v2/plan.json",
)
ERA_SHA256 = MappingProxyType({
    "architecture/admission-semantics-v3/README.md": "c3106482b4ff79649cbef7c65797c6fcd6b64f8419e871ae7d89eecad3ff98ab",
    "architecture/admission-semantics-v3/admission-manifests/planeon-a2.json": "1096b3cc71c4fe6b5a17ed61e8bf8c17ee17fcf52b192503534d60aed9ce4741",
    "architecture/admission-semantics-v3/vectors.json": "a3e2dc9818742ae2188e0e83cf91bb833be836115975b3fb23d5f280f6928cc1",
    "architecture/artifact-edges/README-v4.md": "11e6bbefc27d82d359c7f48a873374786a760881693fd7d9ec7e88916ab2558b",
    "architecture/artifact-edges/operator-harness-engineering-v3.json": "106ea91aa09c2d377adf3b514a228331d6a805bd1a17e641ecaa23b3c39115f3",
    "architecture/artifact-edges/operator-harness-engineering-v4.json": "e30772ff8826650c46d1a8d384625929975e47f2de5cc9030680b5fdb5e7fc86",
    "architecture/i05-gate-channel-v4/README.md": "b0af1f8784c7e9bcdd3793a1002d1000e222a13e5a7613b50b04ce5a116ed04d",
    "architecture/i05-gate-channel-v4/vectors.json": "f314610f7ee3feb08533cb535f0a4c19fc991384b852b99a50a1646b0739b1e9",
    "architecture/i06-backend-profile-v2/README.md": "553880b957586dbfa50eabc4a99d51735eef2a1b0a82641ea51d8e3ea8cf72eb",
    "architecture/i06-backend-profile-v2/criteria.json": "026206c57d3025c0f0129b6615e46c83d5a8000ddc3288f000a1fe4570050cda",
    "architecture/i06-backend-profile-v2/vectors.json": "1a5e168f0d8fff233f5072b1440e75a633b38e428f87b2893a96e579122a430e",
    "architecture/i06-backend-profile/README.md": "ccf952d40b4f6229c0cdea79f976253cd4abb19438c1eebc5794e748a708e4b7",
    "architecture/i06-backend-profile/identity-closure.json": "0a9b82ffa2d63bf48a8850574cdf3ece02bf1913f33a72cbb96ed30a40f1f3bb",
    "architecture/i06-backend-profile/upstream-bootstrap-rbac-v1.37.1.json": "7529c2a713af2fb90163175924c264d95f4242d7e0c26b1452c77febb13ed50e",
    "architecture/i06-backend-profile/writer-inventory.json": "8e6b3b7565cfc93a61162b84d740cffb2871eb66ab85e8c4e80ac813f1af3077",
    "architecture/w03-obligation-amendment-1/amendment.json": "2a98e28989f41d69b27a580db8113e56d5adc1fcc1a4b96517997ce7b01f4bd2",
    "architecture/w03-obligation-amendment-2/README.md": "ae51309afc5258371c78a0ba6ef55bf39439f79cb7f1ecc7fc8ae02f5caf9b16",
    "architecture/w03-obligation-amendment-2/REVIEW_BRIEF.md": "8aeb6319bb41627edb166a6378cfca41bb6aab6759bb81e7cd80b6ae99ea6702",
    "architecture/w03-obligation-amendment-2/amendment.json": "a1d861866136a52c378777ab4bb974df856cccf147551b0dab8c4fad8f234f0b",
    "architecture/w03-obligation-amendment-2/review-round1.json": "3d8ea6892f6f2b43cb8fc87b14a2504521c31a981c3d4826a22497dd2ee11f25",
    "architecture/w03-obligation-amendment-2/review-round2.json": "bc8d3b7241e8e603cf89f54db11feadc787f1affc4cf20ef2471de0798c85e8f",
    "architecture/w03-obligation-amendment-2/review-round3.json": "dd87d3e917081b1d10fffec8fba06c95551d7c6291dbf0e077061a2a1fe507ea",
    "architecture/w03-obligation-amendment-2/round1/architecture/artifact-edges/README-v4.md": "af0b82b3906daf059a354876d6a0df9abc61dd0c029af1ccd41c08e12ba5084b",
    "architecture/w03-obligation-amendment-2/round1/architecture/artifact-edges/operator-harness-engineering-v4.json": "a485965a65070c7bb8660ae0f47b10a2eea8bd4988b4272c665a15ed22800a09",
    "architecture/w03-obligation-amendment-2/round1/architecture/w03-obligation-amendment-2/README.md": "cfb355ffcb187002f63bdc406c0310e028f9b40ad4bd48af24eccc0aeccdf040",
    "architecture/w03-obligation-amendment-2/round1/architecture/w03-obligation-amendment-2/amendment.json": "b1272b6c3f8945832a240eb6262528b31a9a81edc4cab2461b9835fa3b2a68d8",
    "architecture/w03-obligation-amendment-2/round2/architecture/artifact-edges/README-v4.md": "d76c176d98a43398de2e46d524d3cafb5b0c1a8f5284ff7a9c96958600114351",
    "architecture/w03-obligation-amendment-2/round2/architecture/artifact-edges/operator-harness-engineering-v4.json": "0fb56e0a9c4c265110cf54e369ca0af8fa0adee0b7dc826840ea657a39426672",
    "architecture/w03-obligation-amendment-2/round2/architecture/w03-obligation-amendment-2/README.md": "f30da109aeac2d56ea49863f285a285807bc10fd00cbcb5e9f5cbe4eda8d57e4",
    "architecture/w03-obligation-amendment-2/round2/architecture/w03-obligation-amendment-2/amendment.json": "08c4cf9487dad4a151d1058bc6102e3605bb25abb7441136a5f5de65efe64fcf",
    "architecture/w03-obligation-amendment-2/round3/architecture/w03-obligation-amendment-2/README.md": "12aa75c3b669c85e429e2c90e7ac9848d557d6d75f792a9bd3ae3827d33d3b40",
    "architecture/w03-obligation-amendment-2/round3/architecture/w03-obligation-amendment-2/amendment.json": "6c650a16be2748887be50ac23e446679e424ede4a9fc8d1df8428f2441e56fc7",
    "architecture/w03-obligation-amendment-2/status.json": "caf4cf34f8b4dbb995b47efc97688f235634cf9850e817f8c936cc9dce8491b5",
    "architecture/w03-plan-v2/plan.json": "a00470238431347da82cc47b1f1b6cf7cd51042d56694eea68d1373a3aaefb67",
})


def reviewed_bytes(path: str) -> bytes:
    """This packet's reviewed bytes of path; a bridged successor projects newer bytes back first."""
    return successor.historical_bytes(path, regular_bytes(path))


def reviewed_mode(path: str) -> int:
    """The lstat mode of path in this packet's tree; a bridged successor projects a newer mode back first."""
    _path(path)
    return (ROOT / path).lstat().st_mode


def _verified(path: str) -> bytes:
    """reviewed_bytes, checked against its era digest on every read; a path outside the era is refused before it is
    read."""
    expected = ERA_SHA256.get(path) if type(path) is str else None
    require(expected is not None, "W03-PLAN-AMEND-2 reviewed bytes are bound: " + str(path))
    raw = reviewed_bytes(path)
    require(type(raw) is bytes and digest(raw) == expected, "unreviewed W03-PLAN-AMEND-2 source: " + path)
    return raw


def _json(path: str) -> Any:
    return parse(_verified(path))


def _bound(check: Any, message: str) -> None:
    """A structural check over this era's data; a malformed value is refused, not raised."""
    try:
        holds = check()
    except (KeyError, TypeError, AttributeError, IndexError, ValueError):
        holds = False
    require(holds is True, message)


def _git_mode(mode: int) -> str | None:
    """The git mode of a regular file from its lstat mode; anything else has none."""
    if not stat.S_ISREG(mode):
        return None
    return "100755" if mode & 0o100 else "100644"


def _texts(values: Any) -> bool:
    return type(values) is list and len(values) > 0 and all(type(text) is str and text.strip() != "" for text in values)


def validate_amendment_2_status() -> None:
    """Adopted after three independent review rounds, each bound to its record and its exact subject bytes, the last a
    PASS_FOR_ADOPTION; the adopted files are candidate 4, which is candidate 3 with only C3-1's text applied."""
    status = _json(STATUS_PATH)
    _bound(lambda: type(status) is dict and tuple(status) == STATUS_KEYS
           and status["schemaVersion"] == "planeon.internal.w03-obligation-amendment-2-status/v1"
           and status["workItem"] == status["amendmentId"] == "W03-PLAN-AMEND-2" and status["status"] == "ADOPTED"
           and status["adoption"] == ADOPTION and status["baseMain"] == BASE_MAIN and status["reviewBase"] == REVIEW_BASE
           and status["adoptedSubject"] == ADOPTED_SHA256 and tuple(status["adoptedSubject"]) == SUBJECT
           and status["independentReviewer"] == "SEPARATE_AGENT_NOT_AUTHOR"
           and all(type(status[key]) is str and status[key] != "" for key in ("readmeStatusNote", "recordPaths"))
           and status["closedFindings"] == CLOSED_FINDINGS and status["nonClaims"] == NON_CLAIMS
           and type(status["carried"]) is list
           and all(type(row) is dict and tuple(row) == ("item", "to", "action") and type(row["action"]) is str
                   and row["action"] != "" for row in status["carried"])
           and [(row["item"], row["to"]) for row in status["carried"]] == list(CARRIED),
           "adopted W03-PLAN-AMEND-2 status")
    for path in SUBJECT:
        require(digest(_verified(path)) == ADOPTED_SHA256[path], "the adopted files are candidate 4: " + path)
    rounds = status["rounds"]
    _bound(lambda: type(rounds) is list and len(rounds) == len(ROUNDS)
           and all(type(row) is dict and tuple(row) == ROW_KEYS for row in rounds)
           and [(row["round"], row["verdict"]) for row in rounds] == list(ROUNDS),
           "three review rounds in order, the last PASS_FOR_ADOPTION")
    for number, row in enumerate(rounds, 1):
        snapshot, kept = row["snapshot"], row["keptCopies"]
        record = _json(row["record"]) if row["record"] == AM2_DIR + "review-round%d.json" % number else None
        _bound(lambda: type(record) is dict and digest(_verified(row["record"])) == row["recordSha256"]
               and record["subject"] == row["subjectSha256"] and tuple(record["subject"]) == SUBJECT
               and record["verdict"] == row["verdict"] and snapshot == AM2_DIR + "round%d/" % number
               and type(kept) is list and len(set(kept)) == len(kept) and set(kept) <= set(SUBJECT)
               and all(digest(_verified(snapshot + path)) != ADOPTED_SHA256[path] for path in kept)
               and row["subjectSha256"] == {path: digest(_verified(snapshot + path if path in kept else path))
                                            for path in SUBJECT},
               "review round %d is bound to its record and its exact subject bytes" % number)
    last = rounds[-1]["snapshot"]
    candidate3, adopted = _json(last + AMENDMENT), _json(AMENDMENT)

    def c3_1() -> bool:
        before = [row for row in candidate3["changes"] if row["obligation"] == "OBS-RBAC-1"]
        after = [row for row in adopted["changes"] if row["obligation"] == "OBS-RBAC-1"]
        patched = copy.deepcopy(candidate3)
        for row in patched["changes"]:
            if row["obligation"] == "OBS-RBAC-1":
                row["text"] = after[0]["text"]
        lines3 = _verified(last + README_PATH).decode("utf-8").split("\n")
        lines4 = _verified(README_PATH).decode("utf-8").split("\n")
        differ = [index for index, (old, new) in enumerate(zip(lines3, lines4)) if old != new]
        return (len(before) == len(after) == 1 and before[0]["text"] != after[0]["text"]
                and after[0]["text"].startswith(C3_1_TEXT) and patched == adopted
                and len(lines3) == len(lines4) and len(differ) == 1 and lines4[differ[0]].startswith("| OBS-RBAC-1 |")
                and after[0]["text"] in lines4[differ[0]])
    _bound(c3_1, "candidate 4 is candidate 3 with only C3-1's OBS-RBAC-1 text applied")
    for path in (README_PATH, V4_README):
        text = _verified(path).decode("utf-8")
        require(text.count("Status: **") == 1 and text.count(CANDIDATE) == 1,
                "the README keeps its reviewed candidate status line: " + path)


def validate_amendment() -> None:
    """The bindings, the closed change kinds and the refinement rule, over plan v2 and amendment 1 as this era holds them:
    every obligation that lists HE-004 after amendment 1 has exactly one REFINED row, its first; each REFINED row keeps
    plan v2's text byte for byte and replaces HE-004 by its parts in place; the parts cover HE-004's exactly; no row keeps
    HE-004; ADDED rows add new obligations; PACKETS_ADDED rows extend the list so far; shares name listed packets; and
    every decision a change cites is recorded."""
    plan, first, record = _json(PLAN_V2), _json(AMENDMENT_1), _json(AMENDMENT)
    _bound(lambda: record["schemaVersion"] == "planeon.internal.w03-obligation-amendment/v2"
           and record["id"] == "W03-PLAN-AMEND-2"
           and record["amends"] == {"path": PLAN_V2, "sha256": "sha256:" + digest(_verified(PLAN_V2)),
                                    "packet": "MET-ENFORCE-024"}
           and record["after"] == {"path": AMENDMENT_1, "sha256": "sha256:" + digest(_verified(AMENDMENT_1)),
                                   "packet": "MET-ENFORCE-025"},
           "the amendment binds plan v2 and amendment 1 by their bytes")
    _bound(lambda: type(record["changeKinds"]) is dict and set(record["changeKinds"]) == CHANGE_KINDS
           and all(type(text) is str and text != "" for text in record["changeKinds"].values())
           and type(record["changes"]) is list and len(record["changes"]) > 0
           and all(type(row) is dict and row["change"] in record["changeKinds"] for row in record["changes"]),
           "the closed change kinds")
    _bound(lambda: _texts(record["ownerDecisions"]), "the recorded decisions are non-empty texts")
    decided = {name for text in record["ownerDecisions"] for name in DECISION_ID.findall(text)}
    _bound(lambda: all(type(row["source"]) is str and row["source"] != ""
                       and set(DECISION_ID.findall(row["source"])) <= decided for row in record["changes"]),
           "every decision a change cites is recorded")
    texts = {row["id"]: row["text"] for row in plan["obligations"]}
    lists = {row["id"]: list(row["packets"]) for row in plan["obligations"]}
    earlier = set(texts)
    for row in first["changes"]:
        earlier.add(row["obligation"])
        if "packets" in row:
            lists[row["obligation"]] = list(row["packets"])
    holders = sorted(name for name, packets in lists.items() if REFINED_PACKET in packets)
    refinements = record["packetRefinements"]
    _bound(lambda: type(refinements) is list and [row["packet"] for row in refinements] == [REFINED_PACKET]
           and type(refinements[0]["parts"]) is list and len(refinements[0]["parts"]) > 0
           and all(type(part["id"]) is str and part["id"] != "" for part in refinements[0]["parts"])
           and len({part["id"] for part in refinements[0]["parts"]}) == len(refinements[0]["parts"])
           and len(holders) > 0,
           "HE-004 is the one refined packet, with named parts")
    parts = [part["id"] for part in refinements[0]["parts"]]
    seen: set[str] = set()
    refined: list[str] = []
    named: list[str] = []
    for row in record["changes"]:
        name, kind = row["obligation"], row["change"]
        first_row = name not in seen
        seen.add(name)
        if kind == "ADDED":
            _bound(lambda: first_row and type(name) is str and name not in earlier and type(row["text"]) is str
                   and row["text"] != "" and _texts(row["packets"]) and len(set(row["packets"])) == len(row["packets"]),
                   "an ADDED row adds an obligation absent from plan v2 and amendment 1: " + str(name))
        elif kind == "REFINED":
            _bound(lambda: first_row and name in holders and row["text"] == texts.get(name)
                   and row["replaced"] == REFINED_PACKET and _texts(row["parts"])
                   and len(set(row["parts"])) == len(row["parts"]) and set(row["parts"]) <= set(parts)
                   and row["packets"] == [packet for listed in lists[name]
                                          for packet in (row["parts"] if listed == REFINED_PACKET else [listed])],
                   "a REFINED row is the first row of an HE-004 obligation, keeps plan v2's text byte for byte and "
                   "replaces HE-004 by its parts: " + str(name))
            refined.append(name)
            named.extend(row["parts"])
        else:
            _bound(lambda: name in lists and _texts(row["packetsAdded"])
                   and not set(row["packetsAdded"]) & set(lists[name])
                   and len(set(row["packetsAdded"])) == len(row["packetsAdded"])
                   and row["packets"] == lists[name] + row["packetsAdded"],
                   "a PACKETS_ADDED row extends the obligation's list so far: " + str(name))
        _bound(lambda: REFINED_PACKET not in row["packets"], "no row keeps HE-004: " + str(name))
        _bound(lambda: "shares" not in row or (type(row["shares"]) is dict and len(row["shares"]) > 0
                                               and set(row["shares"]) <= set(row["packets"])
                                               and _texts(list(row["shares"].values()))),
               "every share names a packet in its row's list: " + str(name))
        lists[name] = list(row["packets"])
    _bound(lambda: sorted(refined) == holders and len(refined) == len(holders),
           "every obligation that lists HE-004 after amendment 1 has exactly one REFINED row")
    _bound(lambda: set(named) == set(parts), "the REFINED rows' parts are exactly HE-004's parts")


def validate_edge_record_v4() -> None:
    """Edge record v4 supersedes v3 by its digest and keeps v3's edge, rules, statuses and 33 rows exactly and in order;
    each of its 12 new rows registers its provider file's exact bytes and mode, before use, under the R10 contracts
    directory; its quoted decisions are the amendment's."""
    v3, v4, amendment = _json(V3_EDGE), _json(V4_EDGE), _json(AMENDMENT)
    _bound(lambda: type(v4) is dict and tuple(v4) == tuple(v3)
           and v4["schemaVersion"] == v3["schemaVersion"] == "planeon.internal.artifact-edge-registry/v2"
           and all(v4[key] == v3[key] for key in ("graph", "consumer", "provider", "ownerDecision", "rules",
                                                    "notArtifacts", "statuses"))
           and v4["supersedes"] == {"path": V3_EDGE, "sha256": "sha256:" + digest(_verified(V3_EDGE)), "packet": V3_PACKET}
           and _texts(v4["ownerDecisions"]) and all(text in amendment["ownerDecisions"] for text in v4["ownerDecisions"])
           and _texts(v4["notes"]),
           "edge record v4 supersedes v3 by its digest and keeps v3's edge, rules and statuses")
    _bound(lambda: len(v3["artifacts"]) == V3_ROWS and v4["artifacts"][:V3_ROWS] == v3["artifacts"]
           and all(list(row) == list(old) for row, old in zip(v4["artifacts"], v3["artifacts"]))
           and len(v4["artifacts"]) == V3_ROWS + len(NEW_ROWS),
           "edge record v4 carries v3's 33 rows exactly and in order")
    for index, (row, (path, commit, consumer, packet)) in enumerate(zip(v4["artifacts"][V3_ROWS:], NEW_ROWS), V3_ROWS + 1):
        _bound(lambda: tuple(row) == EDGE_ROW_KEYS and row["providerPath"] == path and row["providerCommit"] == commit
               and row["consumerPath"] == consumer and consumer.startswith(CONSUMER_PREFIX)
               and row["consumerPacket"] == packet and row["relation"] == "BYTE_IDENTICAL"
               and row["status"] == "REGISTERED_BEFORE_USE"
               and row["sha256"] == digest(_verified(path)) and row["mode"] == _git_mode(reviewed_mode(path)),
               "edge record v4 row %d registers its provider's exact bytes and mode before use: %s" % (index, path))
    providers = [row["providerPath"] for row in v4["artifacts"]]
    consumers = [row["consumerPath"] for row in v4["artifacts"][V3_ROWS:]]
    _bound(lambda: len(set(providers)) == len(providers) and len(set(consumers)) == len(consumers)
           and not set(consumers) & {row["consumerPath"] for row in v3["artifacts"]},
           "each provider path, and each new consumer path, is registered once")


def validate_w03_plan_amend_2() -> None:
    """Every reviewed byte and the adoption record first; then the amendment's rules and edge record v4."""
    for path in FROZEN_PATHS:
        require(path not in _PROJECTION_RULES,
                "plan v2, amendment 1, edge record v3 and the registered provider files stay byte-identical")
    for path in ERA_SHA256:
        _verified(path)
    validate_amendment_2_status()
    validate_amendment()
    validate_edge_record_v4()
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
            == record["validatorNormalizedSha256"], "w03 plan amendment 2 validator drift")
    paths = sorted((ROOT / "task-packets").glob("*.yaml"))
    old = set(record["baselinePackets"])
    require(len(paths) == 269
            and {path.stem for path in paths} == old | {NEW_PACKET, successor.NEW_PACKET, successor.successor.NEW_PACKET, successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.NEW_PACKET},
            "closed 269-packet catalog retaining the 244-packet checkpoint")
    packets = {}
    for path in paths:
        if path.stem in (successor.NEW_PACKET, successor.successor.NEW_PACKET, successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.NEW_PACKET):
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
            "closed source-only w03-plan-amend-2 packet and inherited commands")
    require(len(packet["allowedPaths"]) == len(set(packet["allowedPaths"]))
            and set(packet["allowedPaths"]) == set(record["changedFiles"])
            | set(record["newFiles"]) | {AUTHORITY_PATH, VALIDATOR_PATH,
                                         "task-packets/" + NEW_PACKET + ".yaml"},
            "unreviewed or omitted w03-plan-amend-2 packet path")
    for path, rule in record["changedFiles"].items():
        current = successor.historical_bytes(path, regular_bytes(path))
        require(digest(current) == rule["afterSha256"]
                and digest(historical_bytes(path, current)) == rule["beforeSha256"],
                "unreviewed current source: " + path)
    for path, expected in record["newFiles"].items():
        require(digest(successor.historical_bytes(path, regular_bytes(path))) == expected,
                "new source drift: " + path)
    validate_w03_plan_amend_2()


if __name__ == "__main__":
    validate()
    print("W03 obligation-register amendment 2 valid: 269 current specifications; 244-packet checkpoint and exact 243-packet predecessor; contract reviewed.")
