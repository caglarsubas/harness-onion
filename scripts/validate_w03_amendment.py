#!/usr/bin/env python3
"""Validate the MET-ENFORCE-024 W03 plan amendment and the exact 227-to-226 projection."""
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
    import validate_research_adoption_v2 as successor
except ImportError:
    from scripts.safe_yaml import safe_load
    from scripts import validate_research_adoption_v2 as successor


ROOT = Path(__file__).resolve().parents[1]
AUTHORITY_PATH = "architecture/w03-amendment-authority.json"
AUTHORITY_SHA256 = "69985eb830b2ef2f6e15f4fc99d2d2462c42215f2108f9a2906f5002dda1b846"
VALIDATOR_PATH = "scripts/validate_w03_amendment.py"
BASE_COMMIT = "a2eab9365c8663cc1ae23a666e864b821f600fa6"
NEW_PACKET = "MET-ENFORCE-024"
PREVIOUS_PACKET = "MET-PERF-037"
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
            require(key not in result, "duplicate w03-amendment authority member")
            result[key] = value
        return result

    def no_constant(_value: str) -> Any:
        raise ValueError("nonfinite w03-amendment authority number")

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
        require(digest(raw) == AUTHORITY_SHA256, "W03 amendment history authority digest")
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
    }, "closed W03 amendment history authority")
    require(value["schemaVersion"] == "harness.planeon.ai/w03-amendment-authority/v1"
            and value["authorityPacket"] == NEW_PACKET
            and value["acceptedBase"] == BASE_COMMIT
            and type(value["baselinePackets"]) is dict
            and len(value["baselinePackets"]) == 226
            and NEW_PACKET not in value["baselinePackets"]
            and type(value["changedFiles"]) is dict
            and type(value["newFiles"]) is dict
            and _sha(value["packetSha256"])
            and _sha(value["validatorNormalizedSha256"]),
            "accepted 226-packet base")
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
    # An exact 226-era byte string is already older than the successor layer.
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


# MET-ENFORCE-024 (roadmap W03-AMEND) publishes the W03 plan v2 with the owner's HE-002 decisions Q-HE2-A to Q-HE2-G (via
# the lane monitor), the operator -> harness-engineering buildArtifact edge registry record and the supplementary I05 v3
# vectors that close AF2-I05-1. Repository bytes are read only through reviewed_bytes, so a later bridged successor
# projects its own edits away first. Every reviewed file of this era is bound by digest before anything is parsed, every
# later read is checked against that digest again, and the reference modules are executed from this era's reviewed bytes
# (the plan model, the I05 v3 model and the safe_yaml that reads the repository registry; none of them imports another
# era module, so no import hook is needed), so a later revision of any of them cannot change how this layer judges its
# era. The decisions, the plan changes, the edge and the closure of AF2-I05-1 are restated here independently of the
# reviewed files; the artifacts' file modes rest on the review and the edge record's digest.
PLAN_DIR = "architecture/w03-plan-v2/"
PLAN_PATH = PLAN_DIR + "plan.json"
V1_PLAN = "architecture/w03-plan/plan.json"
PLAN_MODEL = "scripts/w03_plan_v2.py"
EDGE_PATH = "architecture/artifact-edges/operator-harness-engineering.json"
SUPPLEMENT_PATH = "architecture/i05-gate-channel-v3-supplement/vectors.json"
SUPPLEMENT_STATUS = "architecture/i05-gate-channel-v3-supplement/status.json"
I05_STATUS = "architecture/i05-gate-channel-v3/status.json"
I05_MODEL = "scripts/i05_gate_channel_v3.py"
I05_VECTORS = "architecture/i05-gate-channel-v3/vectors.json"
I05_SCHEMA = "architecture/i05-gate-channel-v3/channel.schema.json"
REPOSITORIES = "architecture/repositories.yaml"
SAFE_YAML = "scripts/safe_yaml.py"
STATUS_PATH = PLAN_DIR + "status.json"
REVIEWED_SUBJECT = {"commit": "a83bb56428e305942f76813dae9c5f96f975cf52", "tree": "49ffcbbe13c944d218085284ed2067040b45adb2"}
ROUNDS = ((1, 'CHANGES_REQUIRED'), (2, 'CHANGES_REQUIRED'), (3, 'CHANGES_REQUIRED'), (4, 'PASS_FOR_SOURCE_PUBLICATION'))
LAST_ROUND = len(ROUNDS)
REVIEW_SCHEMA = "harness.planeon.ai/w03-amendment-review/v1"
STATUS_KEYS = ("schemaVersion", "workItem", "status", "reviewedSubject", "supersedes", "rounds", "carried", "nonClaims")
ROW_KEYS = ("round", "subject", "subjectTree", "verdict", "record", "snapshot", "severities")
SEVERITIES = ("MAJOR", "MINOR", "NOTE")
NON_CLAIMS = ["No R10 module logic exists; nothing is enrolled on a host.", "E01-E12 stay OPEN_UNPROVEN.",
              "The consumer side of the edge (R10's bytes) is checked by R10's own packets, not by this repository."]
DECISIONS = (("Q1", "a"), ("Q2", "a"), ("Q3", "a"), ("Q5", "a"), ("Q-L3", "L3-a"), ("Q-S", "S-b"), ("Q-HE2-A", "a"),
             ("Q-HE2-B", "a"), ("Q-HE2-C", "a"), ("Q-HE2-D", "a"), ("Q-HE2-E", "a+b"), ("Q-HE2-F", "all-five"),
             ("Q-HE2-G", "b"))
ADDED_PACKETS = ("W03-AMEND", "HE-002B", "HE-002C", "HE-002S")
OBLIGATION_PACKETS = {"I05-3": ["HE-002C", "HE-003"], "I05-4": ["W03-AMEND", "HE-002"], "I05-5": ["HE-002"],
                      "I05-6": ["HE-003"], "I07-2": ["HE-002C", "HE-007"], "I07-3": ["HE-002"], "I07-4": ["HE-002B"],
                      "I07-5": ["HE-003"], "GATE-OPENAT": ["HE-002C", "T04"], "EDGE-1": ["W03-AMEND"],
                      "SEC-4": ["HE-002S", "HE-004", "HE-005", "HE-006", "HE-007"],
                      "HI-7": ["HE-002S", "HE-004", "HE-005", "HE-006", "HE-007", "HE-008"]}
EDGE = {"graph": "buildArtifact", "consumer": "operator", "provider": "harness-engineering"}
EDGE_COUNTS = {("HE-000", "IN_USE"): 4, ("HE-002", "REGISTERED_BEFORE_USE"): 13}
SUPPLEMENT_EQUALS = (("S01", "S02"), ("S03", "S04"))
CLOSES = "AF2-I05-1 (architecture/i05-gate-channel-v3/status.json:58)"
SUPPLEMENT_STATUS_RECORD = {"schemaVersion": "planeon.internal.effect-gate-supplement-status/v1", "workItem": "W03-AMEND",
                            "status": "ADOPTED_FOR_SOURCE_PUBLICATION", "contract": "architecture/i05-gate-channel-v3/",
                            "closes": {"finding": "AF2-I05-1", "source": "architecture/i05-gate-channel-v3/status.json:58",
                                       "planObligation": "I05-4", "transcripts": ["S01", "S02", "S03", "S04"]},
                            "alsoPinned": {"accumulation": "S05", "queueOrder": "S06"}}
CLOSURE_ROW = {"consumerPath": "host-enforcement/licenses/closure-1.99.0.json", "consumerPacket": "HE-001"}
ARTIFACT_LABEL = "w03-transport-and-effect-gate-contracts"
HEX = frozenset("0123456789abcdef")
INJECTIONS = ("STORAGE_FAIL_NEXT", "STORAGE_FAIL_AFTER", "MARKER_FAIL_NEXT")
EDGE_KEYS = ("schemaVersion", "graph", "consumer", "provider", "artifact", "ownerDecision", "rules", "statuses", "artifacts",
             "notArtifacts")
ARTIFACT_KEYS = ("providerPath", "providerCommit", "sha256", "mode", "consumerPath", "consumerPacket", "relation", "status")
SUPPLEMENT_KEYS = ("schemaVersion", "evidenceClass", "contract", "closes", "configs", "transcripts")
TRANSCRIPT_KEYS = ("id", "intent", "config", "events", "outputs", "final")
# The v1 plan record, its README and model, and the repository registry stay byte-identical: v2 and the edge record are
# published beside them.
FROZEN_PATHS = (V1_PLAN, "architecture/w03-plan/README.md", "scripts/w03_plan.py", REPOSITORIES, I05_STATUS)
# The adopted bytes of every reviewed file, round copy and review record, the status record and the plan model; the
# accepted base's v1 plan, I05 v3 model, vectors and schema, repository registry and safe_yaml.
ERA_SHA256 = MappingProxyType({
    "architecture/artifact-edges/README.md": "5d62a665da2c6e75dce900cb4ef52e74aa14e537bdaeededb7568589339daa9f",
    "architecture/artifact-edges/operator-harness-engineering.json": "54bdc2d22676720419f51cd1bad5eedc909e6f848ed09cd363e351889af9d1fe",
    "architecture/i05-gate-channel-v3-supplement/README.md": "c90eacd3692af35fa2f35083779780e93acb4c1b14dbf7b790f28a42ec099ed3",
    "architecture/i05-gate-channel-v3-supplement/status.json": "59c582724ad6621b8961f26b250c4badda440d0552703f138a20175472d8f35b",
    "architecture/i05-gate-channel-v3-supplement/vectors.json": "1c00bdb3ea112af6098a09158cce3e4a7a6098c9670f490ead4ca65d8bdbb5ac",
    "architecture/i05-gate-channel-v3/channel.schema.json": "3bfee13c9d32e82fe5ab908eb6f716bc11881f9d57b324f8ea4a21a3ad35356f",
    "architecture/i05-gate-channel-v3/status.json": "7cd5302ba7fe8bbb47b2859c4311e247ae6d730cf37d31d8c7140a61e3e8c5c4",
    "architecture/i05-gate-channel-v3/vectors.json": "ab75d86fe54ade7ee2695ef84b200d0473e14e4112e64e7702032593658763ed",
    "architecture/repositories.yaml": "02190a668c6a9114b3733724bec4e552c553867e789b0802f6aaa6759148051d",
    "architecture/w03-plan-v2/README.md": "7c31269df72b6f2530e9beceb78db0d0593678d1d50a1d31366b128320e6cbb3",
    "architecture/w03-plan-v2/plan.json": "a00470238431347da82cc47b1f1b6cf7cd51042d56694eea68d1373a3aaefb67",
    "architecture/w03-plan-v2/review-round1.json": "71bb08a2f5567fab8d166a47329b9a97614771247fafe3407f6c5ce17811ee05",
    "architecture/w03-plan-v2/review-round2.json": "f13174528454c52828e95de115766a2adf9c557e73ea84e6bbd76e987a4bb00e",
    "architecture/w03-plan-v2/review-round3.json": "99f19b62fa940276773fcd4399cc337bc5da88fab055f81e1e0a9afa0f63190e",
    "architecture/w03-plan-v2/review-round4.json": "8296a17515e9f9d5bca3964fc41759e7a7161a218ba0373b7a147e7acd0e2864",
    "architecture/w03-plan-v2/round1/README.md": "bbee02e08d3f6107979b821e703e0d63e517633cb2c27ce86a3ba18be1ebdcb4",
    "architecture/w03-plan-v2/round1/artifact-edges/README.md": "6acd7c1154d781fc0d4d2327bfcbc0b505e9664b436d67152f178c08857087eb",
    "architecture/w03-plan-v2/round1/artifact-edges/operator-harness-engineering.json": "768767a32fbce04e5254cd9d349a517b9288d361b424c45c906d1f7a40970a0e",
    "architecture/w03-plan-v2/round1/i05-gate-channel-v3-supplement/README.md": "f434934d286e8b9e6d98f896372b0c58fb6353207fb7acfa6836d4af555097e8",
    "architecture/w03-plan-v2/round1/i05-gate-channel-v3-supplement/vectors.json": "3c135d5c01a4e40b1cc2bc3c8dd546b3768d05746f6f766173c7b308e23368bd",
    "architecture/w03-plan-v2/round1/plan.json": "13288e0c0ddacaad1a7c5aedd899e41c864c5b9192379c841f4b9c8add73f2ec",
    "architecture/w03-plan-v2/round1/scripts/w03_plan_v2.py": "5d6e23a65cb2a318d21cfee5bfeb23bb69f213936c29d05985509f6e55e4093f",
    "architecture/w03-plan-v2/round2/README.md": "9d4a038dc9942bd1964dc0024abce9a40ef779df29e0d641de296d3d9f0b6568",
    "architecture/w03-plan-v2/round2/artifact-edges/README.md": "6d1053bda9e26bd8703f3b28d1f827342884b0069a98cbb53f4f1fcb49f63274",
    "architecture/w03-plan-v2/round2/artifact-edges/operator-harness-engineering.json": "5fb326278b6f505d8dfaafade6f81c6e2b4b11a0ed078da38d02d79ce458acd8",
    "architecture/w03-plan-v2/round2/i05-gate-channel-v3-supplement/README.md": "6ed7d2befdbaa4d8fd72d8c86655d1638ccab39b1bf941b9913be7620b617743",
    "architecture/w03-plan-v2/round2/i05-gate-channel-v3-supplement/vectors.json": "f75e03a1e5ec3ca0eff50a8b357154eb72e5e9d2d2c5a27a0afc69ffcc9fcf67",
    "architecture/w03-plan-v2/round2/plan.json": "a00470238431347da82cc47b1f1b6cf7cd51042d56694eea68d1373a3aaefb67",
    "architecture/w03-plan-v2/round2/scripts/w03_plan_v2.py": "9c8de58d86802355556560078168e58d38be0654fc7ac8a04cf02fb9fe41b56e",
    "architecture/w03-plan-v2/round3/README.md": "1751d74ad59b02a228e10a1f5b139cfc7708a8348bd1ebf6d55355a559ed4be5",
    "architecture/w03-plan-v2/round3/artifact-edges/README.md": "480c8c302e154b037840c6c6fea56981a9066589a9e3977e4c144b4dd924757e",
    "architecture/w03-plan-v2/round3/artifact-edges/operator-harness-engineering.json": "d4538abb108810e9152176844cfc609e4be21915128a4692fd71eb146009ee5c",
    "architecture/w03-plan-v2/round3/i05-gate-channel-v3-supplement/README.md": "e593d328a28fcb690815e989b842c298b0495c3f780cd5553a7057fef4443c30",
    "architecture/w03-plan-v2/round3/i05-gate-channel-v3-supplement/vectors.json": "a0215e534d53dc713493966e225e943583a772cab5db711bdf86e69da037d247",
    "architecture/w03-plan-v2/round3/plan.json": "a00470238431347da82cc47b1f1b6cf7cd51042d56694eea68d1373a3aaefb67",
    "architecture/w03-plan-v2/round3/scripts/w03_plan_v2.py": "9c8de58d86802355556560078168e58d38be0654fc7ac8a04cf02fb9fe41b56e",
    "architecture/w03-plan-v2/status.json": "bad52796a4f191e9e5802b3b0e9d0609e2fee22d4c21e26b4975f955e7762466",
    "architecture/w03-plan/plan.json": "40b501f48fe0eb13d64d2e0cf7fa542817f0fa3034d86058c233d1a3accaff9a",
    "scripts/i05_gate_channel_v3.py": "2c7985b539c0ce8eb79eaabfa1f1ab7d43bdca7515defc590a76ecb1697ca959",
    "scripts/safe_yaml.py": "99c673560e65e58cdc1abe86e53472feaf93e546dd76cb9f3ba051beef5c49d7",
    "scripts/w03_plan_v2.py": "9c8de58d86802355556560078168e58d38be0654fc7ac8a04cf02fb9fe41b56e"
})


def reviewed_bytes(path: str) -> bytes:
    """This packet's reviewed bytes of path; a bridged successor projects newer bytes back first."""
    return successor.historical_bytes(path, regular_bytes(path))


def _verified(path: str) -> bytes:
    """reviewed_bytes, checked against its era digest on every read; a path outside the era is refused."""
    raw = reviewed_bytes(path)
    expected = ERA_SHA256.get(path)
    require(expected is not None and digest(raw) == expected, "W03-AMEND reviewed bytes are bound: " + path)
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


def _hex(value: Any, length: int) -> bool:
    return type(value) is str and len(value) == length and set(value) <= HEX


def _era_model(path: str, name: str) -> types.ModuleType:
    """A reference module of this era, executed from its verified bytes."""
    module = types.ModuleType(name)
    module.__file__ = str(ROOT / path)
    exec(compile(_verified(path), path, "exec", dont_inherit=True), module.__dict__)
    return module


def validate_era_bytes() -> None:
    """Every reviewed file of this era is bound by digest before anything is parsed or executed; v1 is frozen."""
    for path in FROZEN_PATHS:
        require(path not in _PROJECTION_RULES, "the W03 plan v1 record must stay byte-identical")
    for path, expected in ERA_SHA256.items():
        require(digest(reviewed_bytes(path)) == expected, "W03-AMEND reviewed bytes are bound: " + path)


def validate_w03_amendment_status() -> None:
    """Adopted after independent review rounds, each bound to its record, the last a pass on the reviewed subject; v2
    supersedes the byte-identical v1 plan."""
    status = _json(STATUS_PATH)
    require(type(status) is dict and set(status) == set(STATUS_KEYS)
            and status["schemaVersion"] == "planeon.internal.w03-amendment-status/v1"
            and status["workItem"] == "W03-AMEND" and status["status"] == "ADOPTED_FOR_SOURCE_PUBLICATION"
            and status["reviewedSubject"] == REVIEWED_SUBJECT and status["nonClaims"] == NON_CLAIMS
            and status["supersedes"] == {"path": V1_PLAN, "sha256": ERA_SHA256[V1_PLAN], "by": PLAN_PATH}
            and type(status["carried"]) is list
            and all(type(row) is dict and set(row) == {"item", "to", "action"} for row in status["carried"]),
            "adopted W03-AMEND status")
    rounds = status["rounds"]
    previous: list = []
    require(type(rounds) is list and all(type(row) is dict for row in rounds)
            and [(row.get("round"), row.get("verdict")) for row in rounds] == list(ROUNDS), "review rounds in order")
    for row in rounds:
        number = row["round"]
        require(set(row) == set(ROW_KEYS) and row["record"] == PLAN_DIR + "review-round%d.json" % number
                and row["snapshot"] == (PLAN_DIR + "round%d/" % number if number < LAST_ROUND else None),
                "review round %d row" % number)
        record = _json(row["record"])
        require(type(record) is dict and record.get("schemaVersion") == REVIEW_SCHEMA and record.get("round") == number
                and record.get("subjectCommit") == row["subject"] and record.get("subjectTree") == row["subjectTree"]
                and record.get("verdict") == row["verdict"], "review round %d identity" % number)
        actions = record.get("actions")
        require(type(actions) is dict and actions.get("filesEdited") is False and actions.get("personalDataSent") is False,
                "review round %d edited nothing and sent no personal data" % number)
        findings = record.get("findings")
        dispositions = record.get("dispositions")
        require(type(findings) is list and all(type(item) is dict and item.get("severity") in SEVERITIES for item in findings)
                and row["severities"] == sorted({item["severity"] for item in findings})
                and type(dispositions) is list and all(type(item) is dict and "disposition" in item for item in dispositions)
                and (number > 1 or dispositions == []), "review round %d severities and dispositions" % number)
        if number > 1:   # every finding of the previous round has a recorded disposition
            require({item.get("id") for item in previous} <= {item.get("id") for item in dispositions},
                    "review round %d disposes of every round %d finding" % (number, number - 1))
        previous = findings
    final = rounds[-1]
    require(final["subject"] == REVIEWED_SUBJECT["commit"] and final["subjectTree"] == REVIEWED_SUBJECT["tree"]
            and set(final["severities"]) <= {"NOTE"}, "the passing round reviewed this subject and left notes only")
    require({item["id"] for item in previous} == {row["item"] for row in status["carried"]},
            "every note of the passing round is carried")


def validate_plan_v2() -> None:
    """The v2 plan model from this era's bytes: every v1 rule on v2 and the exact v1 -> v2 amendment; the decisions and
    the plan changes restated here."""
    plan = _era_model(PLAN_MODEL, "_met_enforce_024_w03_plan_v2").check(_verified_or_cited)
    v1 = _json(V1_PLAN)

    def changes() -> bool:
        packets = [row["id"] for row in plan["packets"]]
        added = [pid for pid in packets if pid not in {row["id"] for row in v1["packets"]}]
        obligations = {row["id"]: row["packets"] for row in plan["obligations"]}
        return (tuple(added) == ADDED_PACKETS and all(obligations[k] == v for k, v in OBLIGATION_PACKETS.items())
                and {row["id"] for row in v1["obligations"]} <= set(obligations))

    _bound(lambda: [(row["id"], row["selected"]) for row in plan["ownerDecisions"]] == list(DECISIONS) and changes()
           and plan["schemaVersion"] == "planeon.internal.w03-plan/v2",
           "the v2 plan carries the owner's HE-002 decisions and plan changes")


def _verified_or_cited(path: str) -> bytes:
    """The plan model's reader: era files are digest-checked; the sources the plan cites are read as reviewed bytes."""
    return _verified(path) if path in ERA_SHA256 else reviewed_bytes(path)


def _graph_edges(registry: Any) -> list:
    """Every edge the registry's acyclicity rule covers: all graphs, minus its declared exclusions."""
    excluded = set(registry["dependencySemantics"]["acyclicityExclusions"])
    edges = []
    for graph, body in registry["dependencyGraphs"].items():
        for row in body["edges"]:
            if row.get("selectionType") not in excluded:
                edges.append((graph, row["consumer"], row["provider"]))
    return edges


def validate_edge_registry() -> None:
    """The edge's identity, every artifact's exact bytes on this side, and acyclicity with the repository registry."""
    record = _json(EDGE_PATH)
    safe_yaml = _era_model(SAFE_YAML, "_met_enforce_024_safe_yaml")
    registry = safe_yaml.safe_load(_verified(REPOSITORIES))

    def artifact(row) -> bool:
        derived = row["relation"] == "DERIVED"
        published = row["providerCommit"] is None
        extra = set(row) - set(ARTIFACT_KEYS)
        return (set(ARTIFACT_KEYS) <= set(row)
                and extra == ({"consumerSha256", "derivation"} if derived else set()) | ({"providerPacket"} if published else set())
                and row["relation"] in ("BYTE_IDENTICAL", "DERIVED") and row["status"] in record["statuses"]
                and row["mode"] in ("100644", "100755") and _hex(row["sha256"], 64)
                and (not derived or (_hex(row["consumerSha256"], 64) and row["consumerSha256"] != row["sha256"]
                                     and type(row["derivation"]) is str and row["derivation"] != ""))
                and (row.get("providerPacket") == NEW_PACKET and row["providerPath"] == SUPPLEMENT_PATH if published
                     else _hex(row["providerCommit"], 40)))

    def identity() -> bool:
        counts = {}
        for row in record["artifacts"]:
            counts[(row["consumerPacket"], row["status"])] = counts.get((row["consumerPacket"], row["status"]), 0) + 1
        return (type(record) is dict and set(record) == set(EDGE_KEYS)
                and record["schemaVersion"] == "planeon.internal.artifact-edge-registry/v1"
                and {key: record[key] for key in EDGE} == EDGE and counts == EDGE_COUNTS
                and set(record["statuses"]) == {"IN_USE", "REGISTERED_BEFORE_USE"}
                and all(artifact(row) for row in record["artifacts"])
                and len({row["consumerPath"] for row in record["artifacts"]}) == len(record["artifacts"])
                and len({row["providerPath"] for row in record["artifacts"]}) == len(record["artifacts"])
                and [row["relation"] for row in record["artifacts"]].count("DERIVED") == 1
                and record["artifact"] == ARTIFACT_LABEL
                and len(record["notArtifacts"]) == 1 and set(record["notArtifacts"][0]) == {*CLOSURE_ROW, "reason"}
                and {key: record["notArtifacts"][0][key] for key in CLOSURE_ROW} == CLOSURE_ROW)

    _bound(identity, "the operator -> harness-engineering buildArtifact edge record")
    for row in record["artifacts"]:
        path = row["providerPath"]
        require(type(path) is str and digest(reviewed_bytes(path)) == row["sha256"],
                "a registered artifact matches its provider bytes: %s" % path)

    # Conditional whenCapability edges are included as well (stricter than the registry's rule, which excludes only its
    # declared acyclicityExclusions); harness-engineering consumes no repository, so the edge cannot close a cycle.
    def acyclic() -> bool:
        ids = {row["id"] for row in registry["repositories"]}
        if not {EDGE["consumer"], EDGE["provider"]} <= ids:
            return False
        if any(body_row["consumer"] == EDGE["provider"] for body in registry["dependencyGraphs"].values()
               for body_row in body["edges"]):
            return False   # the record's rule: harness-engineering consumes no repository in any graph
        edges = _graph_edges(registry) + [("buildArtifact", EDGE["consumer"], EDGE["provider"])]
        if any(consumer == EDGE["provider"] and provider == EDGE["consumer"] for _, consumer, provider in edges):
            return False
        for graph in {g for g, _, _ in edges}:
            succ = {}
            for g, consumer, provider in edges:
                if g == graph:
                    succ.setdefault(consumer, set()).add(provider)
            state = {}

            def visit(node) -> bool:
                if state.get(node) == 1:
                    return False
                if state.get(node) == 2:
                    return True
                state[node] = 1
                ok = all(visit(nxt) for nxt in succ.get(node, ()))
                state[node] = 2
                return ok

            if not all(visit(node) for node in list(succ)):
                return False
        return True

    _bound(acyclic, "the edge keeps every unconditional repository graph acyclic")


def validate_supplement() -> None:
    """The supplementary transcripts replay exactly through this era's I05 v3 model; the equals relations hold and the
    two references differ."""
    supplement = _json(SUPPLEMENT_PATH)
    v3 = _json(I05_VECTORS)
    schema = _json(I05_SCHEMA)
    model = _era_model(I05_MODEL, "_met_enforce_024_i05_gate_channel_v3")
    status = _json(SUPPLEMENT_STATUS)
    v3_status = _verified(I05_STATUS).decode("utf-8").splitlines()
    _bound(lambda: {key: status[key] for key in SUPPLEMENT_STATUS_RECORD} == SUPPLEMENT_STATUS_RECORD
           and status["reviewedSubject"] == REVIEWED_SUBJECT and status["adoptionRecord"] == STATUS_PATH
           and set(status) == {*SUPPLEMENT_STATUS_RECORD, "contractBytes", "reviewedSubject", "adoptionRecord"}
           and "AF2-I05-1" in v3_status[57], "the supplement status record closes AF2-I05-1")
    _bound(lambda: type(supplement) is dict and set(supplement) == set(SUPPLEMENT_KEYS)
           and supplement["schemaVersion"] == "planeon.internal.effect-gate-supplement/v1"
           and supplement["evidenceClass"] == "DATA_CHECK_ONLY" and supplement["closes"] == CLOSES
           and all(set(row) == set(TRANSCRIPT_KEYS) | ({"equals"} if row["id"] in ("S01", "S03") else set())
                   and row["config"] == "ACTIVE" for row in supplement["transcripts"])
           and supplement["contract"] == {"path": I05_VECTORS, "sha256": ERA_SHA256[I05_VECTORS],
                                          "model": {"path": I05_MODEL, "sha256": ERA_SHA256[I05_MODEL]}}
           and supplement["configs"] == {"ACTIVE": {"vectorsPath": I05_VECTORS, "key": ["configs", "ACTIVE"]}}
           and [row["id"] for row in supplement["transcripts"]] == ["S01", "S02", "S03", "S04", "S05", "S06"],
           "the supplementary vectors file")
    by_id = {}
    for row in supplement["transcripts"]:
        outputs, final = model.replay(v3["configs"]["ACTIVE"], row["events"], schema)
        require(outputs == row["outputs"] and final == row["final"], "supplement transcript " + row["id"])
        by_id[row["id"]] = row
    channel = lambda row: [o for o, e in zip(row["outputs"], row["events"]) if e["type"] not in INJECTIONS]
    for left, right in SUPPLEMENT_EQUALS:
        require(by_id[left].get("equals") == right and (channel(by_id[left]), by_id[left]["final"])
                == (channel(by_id[right]), by_id[right]["final"]), "supplement %s equals %s" % (left, right))
    require(by_id["S02"]["final"] != by_id["S04"]["final"], "the two replacement references differ")


def validate_w03_amendment() -> None:
    """Every reviewed byte and the adoption record first; then the plan, the edge and the supplement from this era."""
    validate_era_bytes()
    validate_w03_amendment_status()
    validate_plan_v2()
    validate_edge_registry()
    validate_supplement()


def validate() -> None:
    record = authority()
    validator_raw = successor.historical_bytes(VALIDATOR_PATH, regular_bytes(VALIDATOR_PATH))
    literal = b'AUTHORITY_SHA256 = "' + AUTHORITY_SHA256.encode("ascii") + b'"'
    placeholder = b'AUTHORITY_SHA256 = "TO_BE_PINNED_AFTER_SOURCE_FREEZE"'
    require(validator_raw.count(literal) == 1
            and digest(validator_raw.replace(literal, placeholder))
            == record["validatorNormalizedSha256"], "W03 amendment validator drift")
    paths = sorted((ROOT / "task-packets").glob("*.yaml"))
    old = set(record["baselinePackets"])
    require(len(paths) == 259
            and {path.stem for path in paths} == old | {NEW_PACKET, successor.NEW_PACKET, successor.successor.NEW_PACKET, successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.NEW_PACKET},
            "closed 259-packet catalog retaining the 227-packet checkpoint")
    packets = {}
    for path in paths:
        if path.stem in (successor.NEW_PACKET, successor.successor.NEW_PACKET, successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.NEW_PACKET):
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
            "closed source-only w03-amendment packet and inherited commands")
    require(len(packet["allowedPaths"]) == len(set(packet["allowedPaths"]))
            and set(packet["allowedPaths"]) == set(record["changedFiles"])
            | set(record["newFiles"]) | {AUTHORITY_PATH, VALIDATOR_PATH,
                                         "task-packets/" + NEW_PACKET + ".yaml"},
            "unreviewed or omitted w03-amendment packet path")
    for path, rule in record["changedFiles"].items():
        current = successor.historical_bytes(path, regular_bytes(path))
        require(digest(current) == rule["afterSha256"]
                and digest(historical_bytes(path, current)) == rule["beforeSha256"],
                "unreviewed current source: " + path)
    for path, expected in record["newFiles"].items():
        require(digest(successor.historical_bytes(path, regular_bytes(path))) == expected,
                "new source drift: " + path)
    validate_w03_amendment()


if __name__ == "__main__":
    validate()
    print("W03 amendment valid: 259 current specifications; 227-packet checkpoint and exact 226-packet predecessor; plan v2, edge and supplement reviewed.")
