#!/usr/bin/env python3
"""Validate the MET-LINUX-007 lab run-plan contract v1 and the exact 251-to-250 projection."""
from __future__ import annotations

import ast
import base64
import binascii
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
    import validate_native_profile_v5 as successor
except ImportError:
    from scripts.safe_yaml import safe_load
    from scripts import validate_native_profile_v5 as successor


ROOT = Path(__file__).resolve().parents[1]
AUTHORITY_PATH = "architecture/lab-run-plan-authority.json"
AUTHORITY_SHA256 = "20af44f23b646b940cd604b2407b5dad350e43944a89c62908de2eb09a2f48cc"
VALIDATOR_PATH = "scripts/validate_lab_run_plan.py"
BASE_COMMIT = "f560209d04b7e0f07b2480219718a8a6dbdb21ef"
NEW_PACKET = "MET-LINUX-007"
PREVIOUS_PACKET = "MET-ENFORCE-037"
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
            require(key not in result, "duplicate lab-run-plan authority member")
            result[key] = value
        return result

    def no_constant(_value: str) -> Any:
        raise ValueError("nonfinite lab-run-plan authority number")

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
        require(digest(raw) == AUTHORITY_SHA256, "lab run-plan history authority digest")
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
    }, "closed lab run-plan history authority")
    require(value["schemaVersion"] == "harness.planeon.ai/lab-run-plan-authority/v1"
            and value["authorityPacket"] == NEW_PACKET
            and value["acceptedBase"] == BASE_COMMIT
            and type(value["baselinePackets"]) is dict
            and len(value["baselinePackets"]) == 250
            and NEW_PACKET not in value["baselinePackets"]
            and type(value["changedFiles"]) is dict
            and type(value["newFiles"]) is dict
            and _sha(value["packetSha256"])
            and _sha(value["validatorNormalizedSha256"]),
            "accepted 250-packet base")
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
    # An exact 250-era byte string is already older than the successor layer.
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


# MET-LINUX-007 (roadmap LAB-RUNPLAN-001; owner VR-D1, 2026-10-17, the owner's 2026-10-15 Linux-capacity decision and
# Q-RP-0..9 (a), 2026-10-19, relayed by the lane monitor) publishes the lab run-plan contract v1
# (architecture/lab-run-plan/): closed schemas for a qualification run plan on the owner's GCP compute, its lease and its
# teardown-residual report, their vectors, the offline checker scripts/lab_run_plan.py and a status record that adopts
# them after independent review. DATA_CHECK_ONLY: nothing here touches a cloud, holds a credential or applies anything.
# The artifact edge records and the repository registry stay byte-identical; R12's edge comes later (Q-RP-9 (a)).
# Repository bytes are read only through reviewed_bytes, and the contract's file modes and directory listing only through
# reviewed_mode and reviewed_tree, so a later bridged successor projects its own edits away first. Every reviewed file is
# bound by digest before anything is parsed and on every later read; the checker is executed from this era's bytes, never
# imported. Checked here independently of the checker: the three schemas use only the closed keyword subset, every object
# schema is closed with every property required, and they restate the schema versions, gates, viewer roles, residual
# classes and resource classes; each positive plan's canonical sha256 is recomputed here and bound by its lease and its
# report, its cost lines recompute under its ceiling, its observer holds the roles that list every class, and it carries
# no '@' and only invented identifiers, its project id only once; the negatives' and parse negatives' identifiers and
# targets are restated; the checker imports only the restated standard-library modules and names no file writer, process
# or network call. Then the checker, executed from its verified bytes on the verified schemas and vectors, holds the
# restated class roles and forbidden shapes, each free-text negative trips exactly one shape and every shape is tripped,
# and it accepts the three positives and refuses each negative and parse negative with its recorded refusal. The status record, the review binding,
# the README status line and the contract's closed file set and modes are restated; no contract file holds an absolute
# local path; and this layer's own inverse hunks are canonical.
CONTRACT_DIR = "architecture/lab-run-plan/"
README_PATH = CONTRACT_DIR + "README.md"
REVIEW_BRIEF_PATH = CONTRACT_DIR + "REVIEW_BRIEF.md"
PLAN_SCHEMA = CONTRACT_DIR + "run-plan.schema.json"
LEASE_SCHEMA = CONTRACT_DIR + "lease.schema.json"
TEARDOWN_SCHEMA = CONTRACT_DIR + "teardown-report.schema.json"
VECTORS_PATH = CONTRACT_DIR + "vectors.json"
STATUS_PATH = CONTRACT_DIR + "status.json"
CHECKER = "scripts/lab_run_plan.py"
EDGES_DIR = "architecture/artifact-edges/"
REPOSITORIES = "architecture/repositories.yaml"
# The eight contract files in the status record's order; the review records joined them at adoption. Each is a regular
# file of git mode 100644, and the contract directory holds nothing else.
CONTRACT_FILES = (README_PATH, REVIEW_BRIEF_PATH, PLAN_SCHEMA, LEASE_SCHEMA, TEARDOWN_SCHEMA, VECTORS_PATH, STATUS_PATH,
                  CHECKER)
# (round, record, subject commit, subject tree, verdict, findings as (id, severity)), in order.
ROUNDS = (
    (1, 'architecture/lab-run-plan/review-round1.json', '7c744bb044d533da9f35e10fba2dbe975add4c1c', '19a7638284330511839b0be72966ee2d0efdccb3', 'CHANGES_REQUIRED', (('RP1-1', 'MINOR'), ('RP1-2', 'MINOR'), ('RP1-3', 'MINOR'), ('RP1-4', 'MINOR'), ('RP1-5', 'MINOR'), ('RP1-6', 'MINOR'), ('RP1-7', 'MINOR'), ('RP1-8', 'MINOR'), ('RP1-9', 'MINOR'), ('RP1-10', 'MINOR'), ('RP1-11', 'MINOR'), ('RP1-12', 'MINOR'), ('RP1-13', 'NOTE'), ('RP1-14', 'NOTE'), ('RP1-15', 'NOTE'), ('RP1-16', 'NOTE'), ('RP1-17', 'NOTE'), ('RP1-18', 'NOTE'), ('RP1-19', 'NOTE'))),
    (2, 'architecture/lab-run-plan/review-round2.json', 'c62698480d4cb51e90a1c45d1bc1cfa0518dfeeb', '767d5fd7df8e67344f48289237d0cdc8dfaba4e5', 'CHANGES_REQUIRED', (('RP2-1', 'MINOR'), ('RP2-2', 'MINOR'), ('RP2-3', 'MINOR'), ('RP2-4', 'MINOR'), ('RP2-5', 'MINOR'), ('RP2-6', 'MINOR'), ('RP2-7', 'MINOR'), ('RP2-8', 'NOTE'), ('RP2-9', 'NOTE'), ('RP2-10', 'NOTE'), ('RP2-11', 'NOTE'), ('RP2-12', 'NOTE'), ('RP2-13', 'NOTE'))),
    (3, 'architecture/lab-run-plan/review-round3.json', '88291da1a91e294a29052379c6b69a0cd5f1f2f4', '20bbd829515daeefadaf4bd69ff8321c6d2f980f', 'CHANGES_REQUIRED', (('RP3-1', 'MINOR'), ('RP3-2', 'MINOR'), ('RP3-3', 'NOTE'), ('RP3-4', 'NOTE'), ('RP3-5', 'NOTE'))),
    (4, 'architecture/lab-run-plan/review-round4.json', '5bbb90e299cfedbd718ce5901246a0a531001e2f', '21feb044c983ca5cb3e57cdd8aaf317b6edd6bfb', 'CHANGES_REQUIRED', (('RP4-1', 'MINOR'), ('RP4-2', 'NOTE'), ('RP4-3', 'NOTE'), ('RP4-4', 'NOTE'))),
    (5, 'architecture/lab-run-plan/review-round5.json', '305918af9de0996199e7f51a98c377ee41e1f18c', '50bdc21081bfbd128d878874a4419c25b57ffd4e', 'PASS_FOR_SOURCE_PUBLICATION', (('RP5-1', 'NOTE'), ('RP5-2', 'NOTE'), ('RP5-3', 'NOTE'), ('RP5-4', 'NOTE'))),
)
REVIEW_RECORDS = tuple(row[1] for row in ROUNDS)
NEW_FILES = CONTRACT_FILES + REVIEW_RECORDS
CONTRACT_TREE = frozenset(path for path in NEW_FILES if path.startswith(CONTRACT_DIR))
# MET-LINUX-007 is written in exactly these files.
NAMING_FILES = frozenset(['architecture/lab-run-plan/README.md',
 'architecture/lab-run-plan/REVIEW_BRIEF.md',
 'architecture/lab-run-plan/status.json',
 'scripts/lab_run_plan.py'])
# Every review subject is one commit on this base (the 250th packet's merge).
REVIEW_BASE = "f560209d04b7e0f07b2480219718a8a6dbdb21ef"
SCHEMAS = {"plan": PLAN_SCHEMA, "lease": LEASE_SCHEMA, "teardown": TEARDOWN_SCHEMA}
SCHEMA_VERSIONS = {"plan": "planeon.internal.lab-run-plan/v1", "lease": "planeon.internal.lab-run-lease/v1",
                   "teardown": "planeon.internal.lab-run-teardown/v1"}
SCHEMA_TOP_KEYS = ("$id", "title", "type", "description", "additionalProperties", "required", "properties")
# The closed keyword subset the checker implements; the schemas declare no external dialect.
SCHEMA_SUBSET = frozenset({"$id", "title", "description", "type", "properties", "required", "additionalProperties", "items",
                           "minItems", "maxItems", "uniqueItems", "enum", "const", "pattern", "minLength", "maxLength",
                           "minimum", "maximum", "exclusiveMinimum"})
OBJECT_KEYWORDS = frozenset({"properties", "required", "additionalProperties"})
GATES = ("CONF-LINUX-001", "W06", "PACKET")
VIEWER_ROLES = ("roles/compute.viewer", "roles/logging.viewer", "roles/monitoring.viewer", "roles/iam.securityReviewer")
KEEP_CLASSES = ("PROJECT", "BILLING_LINK", "AUDIT_LOGS", "OBSERVER_IDENTITY")
ALWAYS_KEPT = frozenset({"PROJECT", "OBSERVER_IDENTITY"})
# Every class a teardown report lists, in this order (the lane monitor kept all eighteen, 2026-10-19).
RESOURCE_CLASSES = ("INSTANCES", "INSTANCE_GROUPS", "INSTANCE_TEMPLATES", "DISKS", "SNAPSHOTS", "IMAGES", "ADDRESSES",
                    "NETWORKS", "SUBNETWORKS", "FIREWALL_RULES", "ROUTES", "ROUTERS", "NAT_GATEWAYS", "FORWARDING_RULES",
                    "BUCKETS", "SERVICE_ACCOUNTS", "SERVICE_ACCOUNT_KEYS", "IAM_BINDINGS_ADDED")
VECTORS_KEYS = ("schemaVersion", "evidenceClass", "positives", "negatives", "parseNegatives")
VECTORS_SCHEMA = "planeon.internal.lab-run-plan-vectors/v1"
POSITIVE_KEYS = ("id", "intent", "plan", "lease", "teardown")
NEGATIVE_KEYS = ("id", "intent", "positive", "target", "ops", "refusal")
PARSE_KEYS = ("id", "intent", "raw", "refusal")
# The positives' gates and plan sha256 (canonical JSON: sorted keys, no whitespace, UTF-8), in order.
POSITIVES = (
    ('P0', 'CONF-LINUX-001', '24a93e8d2299ffbb2fd6d73bd54fd077781dec55548441be49abbbc52670f427'),
    ('P1', 'W06', '18a0c419d8571873d6e9cb6bac9b313f0fe8854ab1a13d831a79ea9b7e8d28b4'),
    ('P2', 'PACKET', '1f3f6a16c3a66fec09cb42b27edb5f1f049f2fde5597de95afb212e9bec6e9ae'),
)
# The negatives' identifiers, in order, and how many refuse a plan, a lease, a teardown report, and a report checked
# against a changed lease; then the parse negatives' identifiers.
NEGATIVE_IDS = ('N01',
 'N02',
 'N03',
 'N04',
 'N05',
 'N06',
 'N07',
 'N08',
 'N09',
 'N10',
 'N11',
 'N12',
 'N13',
 'N14',
 'N15',
 'N16',
 'N17',
 'N18',
 'N19',
 'N20',
 'N21',
 'N22',
 'N23',
 'N24',
 'N25',
 'N26',
 'N27',
 'N28',
 'N29',
 'N30',
 'N31',
 'N32',
 'N33',
 'N34',
 'N35',
 'N36',
 'N37',
 'N38',
 'N39',
 'N40',
 'N41',
 'N42',
 'N43',
 'N44',
 'N45',
 'N46',
 'N47',
 'N48',
 'N49',
 'N50',
 'N51',
 'N52',
 'N53',
 'N54',
 'N55',
 'N56',
 'N57',
 'N58',
 'N59',
 'N60',
 'N61',
 'N62',
 'N63',
 'N64',
 'N65',
 'N66',
 'N67',
 'N68',
 'L01',
 'L02',
 'L03',
 'L04',
 'L05',
 'L06',
 'L07',
 'L08',
 'L09',
 'L10',
 'L11',
 'T01',
 'T02',
 'T03',
 'T04',
 'T05',
 'T06',
 'T07',
 'T08',
 'T09',
 'T10',
 'T11',
 'T12',
 'T13',
 'T14',
 'T15',
 'T16',
 'T17',
 'T18',
 'T19',
 'T20')
NEGATIVE_COUNTS = {"plan": 68, "lease": 11, "teardown": 19, "lease-at-teardown": 1}
PARSE_IDS = ('S01', 'S02', 'S03', 'S04', 'S05', 'S06', 'S07', 'S08', 'S09')
FREE_TEXT_REFUSAL = "no credential, account identity or billing account in "
# The viewer roles that list each class (review round 2, RP2-2): every observer holds all three.
CLASS_ROLES = MappingProxyType({**{name: ("roles/compute.viewer",) for name in RESOURCE_CLASSES[:14]},
                                "BUCKETS": ("roles/iam.securityReviewer",),
                                "SERVICE_ACCOUNTS": ("roles/iam.securityReviewer",),
                                "SERVICE_ACCOUNT_KEYS": ("roles/iam.securityReviewer",),
                                "IAM_BINDINGS_ADDED": ("roles/iam.securityReviewer", "roles/logging.viewer")})
OBSERVER_ROLES = frozenset({"roles/compute.viewer", "roles/logging.viewer", "roles/iam.securityReviewer"})
# The checker's forbidden free-text shapes, in its order; each has a negative of its own.
FORBIDDEN_SHAPES = ("@", "-----BEGIN", "PRIVATE KEY", "AKIA[0-9A-Z]{4}", "ASIA[0-9A-Z]{4}", "AIza[0-9A-Za-z_-]{4}",
                    "gh[pousr]_[0-9A-Za-z]{4}", "github_pat_", "xox[abpr]-", "ya29\\.[0-9A-Za-z_-]{4}", "1//[0-9A-Za-z_-]{4}",
                    "(?i)gserviceaccount", "private_key_id", "GOCSPX-", "[0-9A-Fa-f]{6}-[0-9A-Fa-f]{6}-[0-9A-Fa-f]{6}")
# Invented identifiers only (Q-RP-3 (a)).
INVENTED_PREFIX = "example-"
APPROVAL_PREFIX = "OA-EXAMPLE-"
# The checker's imports, all standard library, and the names it may never use: no file writer, process or network call.
CHECKER_IMPORTS = frozenset({"__future__", "datetime", "hashlib", "ipaddress", "json", "math", "re", "sys", "pathlib",
                             "typing"})
CHECKER_FORBIDDEN_NAMES = frozenset({"open", "exec", "eval", "compile", "__import__", "getattr", "globals", "os", "socket",
                                     "subprocess", "shutil", "urllib"})
CHECKER_FORBIDDEN_ATTRIBUTES = frozenset({"open", "write_text", "write_bytes", "touch", "unlink", "rmdir", "mkdir", "rename",
                                          "replace", "chmod", "symlink_to", "system", "popen", "urlopen", "connect"})
CHECKER_COUNTS = {"positives": 3, "plan": 68, "lease": 11, "teardown": 20, "parse": 9}
# The decisions, verbatim, in the status record's order: (id, date, source).
DECISIONS = (
    ("Q-RP-0..9", "2026-10-19", "owner decisions relayed by the lane monitor; the message quoted verbatim"),
    ("VR-D1", "2026-10-17", "owner, as the roadmap item LAB-RUNPLAN-001 records it"),
    ("LINUX-CAPACITY", "2026-10-15", "owner via the lane monitor, as the roadmap items CONF-LINUX-001 and W06 record it"),
    ("MON-18-CLASSES-KEEP-R1", "2026-10-19", "the lane monitor on review round 1; the message quoted verbatim"),
    ("MON-R3-KEEP-IF-OWN-NOTES", "2026-10-19",
     "the lane monitor on an earlier round-3 attempt, voided under this condition; the message quoted verbatim"),
)
DECISION_TEXTS = MappingProxyType({
    "Q-RP-0..9": "Monitor relay, owner decisions on LAB-RUNPLAN-001, 2026-10-19:\n- Q-RP-0 (a): clean room. Design from the roadmap text (VR-D1) and the 2026-10-15 decision only; the owner's lab repo is not read.\n- Q-RP-3 (a): no org project ids published. The plan declares it's separate, the owner confirms that at approval, and the vectors use invented ids.\n- Q-RP-4 (a): a dedicated read-only observer per run, with closed viewer roles, no exported keys, payload-free.\n- Q-RP-1, 2, 5, 6, 7, 8, 9: all (a) as in PLAN.md: three documents with one checker; the rate-card cost recomputed against the owner's ceiling, with budgets alert-only; no exposure by default; approval binds the plan sha256 through the lease; id MET-LINUX-007 (confirmed free on main); runbook in the README only; R12 edge later.\nSLOT 251 is yours (MET-LINUX-007). Record these verbatim and dated. GO for the contract draft and the contract review rounds (light, no network; no credentials, project ids or account identities anywhere). The pre-check, dry run and push need my word.",
    "VR-D1": "run-plan contract in the full set",
    "LINUX-CAPACITY": "Linux capacity for CONF-LINUX-001 and W06 is the owner's GCP compute, and each run plan goes to "
                      "the owner first",
    "MON-18-CLASSES-KEEP-R1": "Monitor: keep the 18 resource classes. They're stricter and within the owner's (a). Keep round 1: its slips were harmless and it didn't pass anyway. Carry on with r2.",
    "MON-R3-KEEP-IF-OWN-NOTES": "Monitor: (a) keep round 3, on one condition. The memory directory is shared with the primary lane, so confirm the two notes the reviewer opened were your own lane's (W04/parallel) and held no W03/R10 design material. Record their file names in the round's disclosure. If either was a primary-lane note, choose (b) and void the round instead. Give the exact prefix inline in round 4's prompt, as you planned. Candidate 4 then goes to round 4.",
})
# The README keeps its candidate status line after adoption; the adoption is recorded in the status record only.
CANDIDATE = "CONTRACT_CANDIDATE_AWAITING_INDEPENDENT_REVIEW"
STATUS_LINE = "Status: **" + CANDIDATE + "**"
STATUS_KEYS = ("schemaVersion", "packet", "roadmapItem", "contractState", "evidenceClass", "base", "contractFiles",
               "reviewRounds", "ownerDecisions", "cleanRoom", "notPublished", "consumers", "reviewerIndependence",
               "cloudRunExecuted", "costIncurred", "credentialsHandled", "nativeAcceptance", "tenantAcceptance",
               "carriedNotes", "adoptionEdit")
FALSE_FLAGS = ("cloudRunExecuted", "costIncurred", "credentialsHandled", "nativeAcceptance", "tenantAcceptance")
NOT_PUBLISHED = ["credentials", "project ids of the owner's organisation", "account identities", "approval identities"]
ROUND_KEYS = ("round", "record", "recordSha256", "subject", "verdict", "findings")
RECORD_KEYS = ("round", "subjectCommit", "subjectTree", "base", "verdict", "findings", "checked")
FINDING_KEYS = ("id", "severity", "file", "line", "summary", "evidence")
CARRIED = ('RP2-13', 'RP5-1', 'RP5-2', 'RP5-3', 'RP5-4')
# The passing round's subject bytes of every contract file the adoption left unchanged: status.json alone was edited.
REVIEWED_SHA256 = {'architecture/lab-run-plan/README.md': '4b1c79b626e12107e00c3558d1730d1dc119a7fdc8d5218efbb177ab9a12fae5',
 'architecture/lab-run-plan/REVIEW_BRIEF.md': '193c44fc3aee001934991ab44203b4ee24b08d7377d6817300aac5785a2a0499',
 'architecture/lab-run-plan/lease.schema.json': '97b8ec19465c16a041782a4d33ddf8e8f61373576c38b6128bbcf4a15575c96b',
 'architecture/lab-run-plan/run-plan.schema.json': 'f59b9a41e5444403c30f42820c876cd2baee57cb84d6018c3d58de1bea5dcbd5',
 'architecture/lab-run-plan/teardown-report.schema.json': '9d69ecccc8fb6a402830df406656e2c29a724669b4945dd7c6e457268ab81218',
 'architecture/lab-run-plan/vectors.json': '92ac4a5ecee41151a92191b37fb84d138a6642be06d66ee8139828c4ebae9679',
 'scripts/lab_run_plan.py': 'b438951ca38516b67fbe6a195f2000fedf02470487d6c3231b30b6e09bc7a3bf'}
LOCAL_PATH_MARKERS = (b"/users/", b"/private/", b"/home/", b".local/state", b"/tmp/claude")
PATH_FOLLOWERS = frozenset(b"abcdefghijklmnopqrstuvwxyz0123456789._-~/")
# The artifact edge records and the repository registry: no file changed or added (R12's edge comes later).
FROZEN_DIRS = (EDGES_DIR,)
FROZEN_PATHS = (
    "architecture/artifact-edges/README-v2.md",
    "architecture/artifact-edges/README-v3.md",
    "architecture/artifact-edges/README-v4.md",
    "architecture/artifact-edges/README-v5.md",
    "architecture/artifact-edges/README-v6.md",
    "architecture/artifact-edges/README.md",
    "architecture/artifact-edges/conformance-labs-harness-engineering.json",
    "architecture/artifact-edges/operator-harness-engineering-v2.json",
    "architecture/artifact-edges/operator-harness-engineering-v3.json",
    "architecture/artifact-edges/operator-harness-engineering-v4.json",
    "architecture/artifact-edges/operator-harness-engineering-v5.json",
    "architecture/artifact-edges/operator-harness-engineering-v6.json",
    "architecture/artifact-edges/operator-harness-engineering.json",
    "architecture/repositories.yaml",
)
# The adopted bytes of every contract file.
ERA_SHA256 = MappingProxyType({
    "architecture/lab-run-plan/README.md": "4b1c79b626e12107e00c3558d1730d1dc119a7fdc8d5218efbb177ab9a12fae5",
    "architecture/lab-run-plan/REVIEW_BRIEF.md": "193c44fc3aee001934991ab44203b4ee24b08d7377d6817300aac5785a2a0499",
    "architecture/lab-run-plan/lease.schema.json": "97b8ec19465c16a041782a4d33ddf8e8f61373576c38b6128bbcf4a15575c96b",
    "architecture/lab-run-plan/review-round1.json": "d6fa8b0f24a7761eb8c8c0b0cd1a4c14dc8f7204070848aff018467cbd16a308",
    "architecture/lab-run-plan/review-round2.json": "2f2f17a788e5e167942d45f802ddb054ef7a677b2b413b511882d6159ebb643d",
    "architecture/lab-run-plan/review-round3.json": "ba5aecc5833175f04021002771f5d0c6c82946e03727d12b90d6afc5fffcfed4",
    "architecture/lab-run-plan/review-round4.json": "7c994afa6b602b2bf6c884011b4a04033a125804c921725e31cd4beee23b6ec7",
    "architecture/lab-run-plan/review-round5.json": "2493f9bc8323626f2edb36a8752bb7b5bf9fcc7e372caaa4b1dd4b1940c626a8",
    "architecture/lab-run-plan/run-plan.schema.json": "f59b9a41e5444403c30f42820c876cd2baee57cb84d6018c3d58de1bea5dcbd5",
    "architecture/lab-run-plan/status.json": "81c4e9988cb29b93d8abbef7b4bf5d5330cb2e7c1af4429a9b78fe5c6f26e039",
    "architecture/lab-run-plan/teardown-report.schema.json": "9d69ecccc8fb6a402830df406656e2c29a724669b4945dd7c6e457268ab81218",
    "architecture/lab-run-plan/vectors.json": "92ac4a5ecee41151a92191b37fb84d138a6642be06d66ee8139828c4ebae9679",
    "scripts/lab_run_plan.py": "b438951ca38516b67fbe6a195f2000fedf02470487d6c3231b30b6e09bc7a3bf",
})


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
    """reviewed_bytes, checked against its era digest on every read; a path outside the era is refused."""
    expected = ERA_SHA256.get(path)
    require(expected is not None, "MET-LINUX-007 reviewed bytes are bound: " + path)
    raw = reviewed_bytes(path)
    require(type(raw) is bytes and digest(raw) == expected, "unreviewed lab run-plan source: " + path)
    return raw


def _json(path: str) -> Any:
    return parse(_verified(path))


def _holds(check: Any) -> bool:
    """A structural check over a module's result or a record; a malformed one does not hold."""
    try:
        return check() is True
    except (KeyError, TypeError, AttributeError, IndexError, ValueError):
        return False


def _bound(check: Any, message: str) -> None:
    require(_holds(check), message)


def _era_model(path: str, name: str) -> types.ModuleType:
    """A reference module of this era, executed from its verified bytes (no import, no bytecode)."""
    module = types.ModuleType(name)
    module.__file__ = str(ROOT / path)
    exec(compile(_verified(path), path, "exec", dont_inherit=True), module.__dict__)
    return module


def local_paths(raw: bytes) -> list:
    """Every marker occurrence followed by a path character: an absolute local path, not a quoted pattern."""
    low, hits = raw.lower(), []
    for marker in LOCAL_PATH_MARKERS:
        at = low.find(marker)
        while at != -1:
            end = at + len(marker)
            if end < len(low) and (low[end] in PATH_FOLLOWERS or low[end] >= 0x80):
                hits.append((marker, at))
            at = low.find(marker, at + 1)
    return hits


def _strings(value: Any) -> list[str]:
    """Every string in a JSON value, keys included."""
    if type(value) is str:
        return [value]
    if type(value) is list:
        return [text for item in value for text in _strings(item)]
    if type(value) is dict:
        return [text for key, item in value.items() for text in [key] + _strings(item)]
    return []


def validate_contract_files() -> None:
    """No artifact edge record or the registry is changed or added; the contract's files are new here, each once; the
    contract directory holds exactly its files; every contract file is a regular file of git mode 100644, not a symlink
    and not executable; and none holds an absolute local path."""
    new = authority()["newFiles"]
    for path in list(_PROJECTION_RULES) + list(new):
        require(path not in FROZEN_PATHS and not path.startswith(FROZEN_DIRS),
                "the artifact edge records and the repository registry stay byte-identical")
    require(len(set(NEW_FILES)) == len(NEW_FILES) and set(NEW_FILES) <= set(new)
            and {path for path in new if path.startswith(CONTRACT_DIR) or path == CHECKER} == set(NEW_FILES),
            "the contract's files are new in this packet, each once")
    require(stat.S_ISDIR(reviewed_mode(CONTRACT_DIR[:-1])), "the contract directory is a directory, not a link")
    tree = reviewed_tree(CONTRACT_DIR)
    require(set(tree) == CONTRACT_TREE, "the contract directory holds exactly its files")
    for path in NEW_FILES:
        mode = tree[path] if path in tree else reviewed_mode(path)
        require(stat.S_ISREG(mode) and not mode & 0o111, "a contract file is a regular file of git mode 100644: " + path)
        require(not local_paths(_verified(path)), "no absolute local path in a contract file: " + path)


def validate_status() -> None:
    """Adopted after independent review bound to its records and subjects; every other adopted byte is the passing
    subject's; the decisions are verbatim; the notes are carried; nothing was run, spent or held."""
    status = _json(STATUS_PATH)
    for path, expected in REVIEWED_SHA256.items():
        require(digest(_verified(path)) == expected, "the adopted contract is the reviewed subject: " + path)
    _bound(lambda: tuple(status) == STATUS_KEYS
           and status["schemaVersion"] == "planeon.internal." + NEW_PACKET.lower() + "-status/v1"
           and status["packet"] == NEW_PACKET and status["roadmapItem"] == "LAB-RUNPLAN-001"
           and status["contractState"] == "ADOPTED_DATA_CONTRACT" and status["evidenceClass"] == "DATA_CHECK_ONLY"
           and status["base"] == REVIEW_BASE and status["contractFiles"] == list(CONTRACT_FILES)
           and type(status["cleanRoom"]) is str and "Q-RP-0 (a)" in status["cleanRoom"]
           and status["notPublished"] == NOT_PUBLISHED
           and set(status["consumers"]) == {"R12"} and type(status["consumers"]["R12"]) is str
           and "Q-RP-9 (a)" in status["consumers"]["R12"]
           and status["reviewerIndependence"] == "SEPARATE_AGENT_NOT_AUTHOR"
           and all(status[key] is False for key in FALSE_FLAGS)
           and type(status["adoptionEdit"]) is str and status["adoptionEdit"] != ""
           and tuple(status["carriedNotes"]) == CARRIED
           and all(type(text) is str and text != "" for text in status["carriedNotes"].values()),
           "adopted MET-LINUX-007 status")
    _bound(lambda: len(status["ownerDecisions"]) == len(DECISIONS)
           and all(tuple(row) == ("id", "date", "decision", "source") and (row["id"], row["date"], row["source"])
                   == (name, date, source) and row["decision"] == DECISION_TEXTS[name]
                   for row, (name, date, source) in zip(status["ownerDecisions"], DECISIONS)),
           "the decisions, verbatim")
    rows = status["reviewRounds"]
    _bound(lambda: len(rows) == len(ROUNDS) and all(
        tuple(row) == ROUND_KEYS and row["round"] == number and row["record"] == record
        and row["recordSha256"] == "sha256:" + digest(_verified(record))
        and row["subject"] == {"commit": commit, "tree": tree, "base": REVIEW_BASE} and row["verdict"] == verdict
        and row["findings"] == ["%s %s" % finding for finding in findings]
        for row, (number, record, commit, tree, verdict, findings) in zip(rows, ROUNDS)),
           "every review round is bound to its record and subject")
    for number, record_path, commit, tree, verdict, findings in ROUNDS:
        record = _json(record_path)
        _bound(lambda: tuple(record) == RECORD_KEYS and record["round"] == number
               and (record["subjectCommit"], record["subjectTree"], record["base"]) == (commit, tree, REVIEW_BASE)
               and record["verdict"] == verdict
               and [(row["id"], row["severity"]) for row in record["findings"]] == list(findings)
               and all(tuple(row) == FINDING_KEYS for row in record["findings"])
               and type(record["checked"]) is list and record["checked"] != [],
               "the round-%d record is its round's" % number)
    _bound(lambda: ROUNDS[-1][4] == "PASS_FOR_SOURCE_PUBLICATION"
           and all(row[4] == "CHANGES_REQUIRED" for row in ROUNDS[:-1])
           and all(severity == "NOTE" for _id, severity in ROUNDS[-1][5]),
           "the last round passes with notes only")


def validate_readme() -> None:
    """The README keeps its candidate status line and names this packet in its title; MET-LINUX-007 is written in exactly
    the restated files."""
    lines = _verified(README_PATH).decode("utf-8").splitlines()
    statuses = [line for line in lines if line.startswith("Status:")]
    require(len(statuses) == 1 and statuses[0].startswith(STATUS_LINE)
            and lines[0].startswith("# ") and lines[0].endswith("(" + NEW_PACKET + ")"),
            "the README keeps its candidate status line: " + README_PATH)
    require({path for path in NEW_FILES if NEW_PACKET.encode("ascii") in _verified(path)} == NAMING_FILES,
            "MET-LINUX-007 is written in exactly the restated contract files")


def _closed(schema: Any) -> bool:
    """The closed subset, restated: only its keywords; every object schema is exactly a closed object requiring each of
    its properties once; items only on an array schema."""
    if type(schema) is not dict or not set(schema) <= SCHEMA_SUBSET:
        return False
    if OBJECT_KEYWORDS & set(schema) or schema.get("type") == "object":
        properties = schema.get("properties")
        if not (schema.get("type") == "object" and schema.get("additionalProperties") is False
                and type(properties) is dict and type(schema.get("required")) is list
                and len(schema["required"]) == len(set(schema["required"])) == len(properties)
                and set(schema["required"]) == set(properties)):
            return False
        if not all(_closed(child) for child in properties.values()):
            return False
    if "items" in schema and (schema.get("type") != "array" or not _closed(schema["items"])):
        return False
    return True


def validate_schemas() -> dict:
    """Each schema is closed in the subset, names its schema version as its $id and its constant, and restates the gates,
    viewer roles, residual classes and the eighteen resource classes, each a count from zero."""
    loaded = {kind: _json(path) for kind, path in SCHEMAS.items()}
    for kind, schema in loaded.items():
        _bound(lambda: tuple(schema) == SCHEMA_TOP_KEYS and _closed(schema)
               and schema["$id"] == SCHEMA_VERSIONS[kind] == schema["properties"]["schemaVersion"]["const"]
               and schema["required"][0] == "schemaVersion", "a closed schema in the subset: " + SCHEMAS[kind])
    plan, report = loaded["plan"]["properties"], loaded["teardown"]["properties"]
    _bound(lambda: tuple(plan["purpose"]["properties"]["gate"]["enum"]) == GATES
           and tuple(plan["observer"]["properties"]["roles"]["items"]["enum"]) == VIEWER_ROLES
           and plan["observer"]["properties"]["exportedKeys"] == {"const": False}
           and plan["observer"]["properties"]["payloadFree"] == {"const": True}
           and plan["observer"]["properties"]["scope"] == {"const": "RUN_PROJECT"}
           and plan["budget"]["properties"]["alertOnly"] == {"const": True}
           and plan["credentials"]["properties"]["inPlan"] == {"const": False}
           and plan["credentials"]["properties"]["heldBy"] == {"const": "OWNER"}
           and plan["project"]["properties"]["separateFromLabFoundation"] == {"const": True}
           and tuple(plan["teardown"]["properties"]["keep"]["items"]["enum"]) == KEEP_CLASSES
           and tuple(report["kept"]["items"]["enum"]) == KEEP_CLASSES
           and tuple(report["resources"]["required"]) == tuple(report["resources"]["properties"]) == RESOURCE_CLASSES
           and all(rule == {"type": "integer", "minimum": 0} for rule in report["resources"]["properties"].values())
           and report["payloadFree"] == {"const": True},
           "the schemas restate the gates, viewer roles, residual and resource classes")
    return loaded


def _cost_holds(cost: Any) -> bool:
    """Each line item is a rate card SKU in its unit at quantity times price within half a cent; the total is their sum
    within half a cent and stays at or under the ceiling."""
    rates = {rate["sku"]: (rate["unit"], rate["price"]) for rate in cost["rateCard"]["rates"]}
    items = cost["lineItems"]
    return (len(rates) == len(cost["rateCard"]["rates"]) and len({item["sku"] for item in items}) == len(items)
            and all(item["sku"] in rates and item["unit"] == rates[item["sku"]][0]
                    and abs(item["amount"] - item["quantity"] * rates[item["sku"]][1]) <= 0.005 + 1e-9 for item in items)
            and abs(cost["total"] - sum(item["amount"] for item in items)) <= 0.005 + 1e-9 and cost["total"] <= cost["ceiling"])


def validate_vectors() -> dict:
    """The vectors file is closed; each positive's plan sha256 is recomputed here and bound by its lease and report, its
    report counts every class at zero, its cost recomputes and it carries no '@' and only invented identifiers; the
    negatives' identifiers, positives and targets are restated."""
    vectors = _json(VECTORS_PATH)
    _bound(lambda: tuple(vectors) == VECTORS_KEYS and vectors["schemaVersion"] == VECTORS_SCHEMA
           and vectors["evidenceClass"] == "DATA_CHECK_ONLY" and len(vectors["positives"]) == len(POSITIVES),
           "a closed vectors file")
    for row, (name, gate, sha) in zip(vectors["positives"], POSITIVES):
        plan, lease, report = row["plan"], row["lease"], row["teardown"]
        _bound(lambda: tuple(row) == POSITIVE_KEYS and row["id"] == name and plan["purpose"]["gate"] == gate
               and digest(canonical(plan)) == sha == lease["planSha256"] == report["planSha256"]
               and lease["planId"] == plan["planId"] and report["leaseId"] == lease["leaseId"]
               and report["observer"] == plan["observer"]["identity"]
               and report["namePrefix"] == plan["teardown"]["namePrefix"]
               and tuple(report["resources"]) == RESOURCE_CLASSES and set(report["resources"].values()) == {0}
               and ALWAYS_KEPT <= set(report["kept"]) <= set(plan["teardown"]["keep"]),
               "positive %s is bound to its recomputed plan sha256" % name)
        _bound(lambda: _cost_holds(plan["cost"]), "positive %s's cost recomputes under its ceiling" % name)
        _bound(lambda: OBSERVER_ROLES <= set(plan["observer"]["roles"])
               and OBSERVER_ROLES == {role for roles in CLASS_ROLES.values() for role in roles},
               "positive %s's observer holds the roles that list every class" % name)
        _bound(lambda: not any("@" in text for text in _strings(row))
               and sum(text.count(plan["project"]["id"]) for text in _strings(plan)) == 1
               and not any(plan["project"]["id"] in text for text in _strings(lease) + _strings(report))
               and plan["project"]["id"].startswith(INVENTED_PREFIX) and plan["workload"]["repository"].startswith(INVENTED_PREFIX)
               and all(machine["image"]["project"].startswith(INVENTED_PREFIX) for machine in plan["machines"])
               and lease["approval"]["reference"].startswith(APPROVAL_PREFIX),
               "positive %s carries only invented identifiers" % name)
    negatives = vectors["negatives"]
    counts = {kind: 0 for kind in NEGATIVE_COUNTS}
    for row in negatives:
        _bound(lambda: tuple(row) == NEGATIVE_KEYS and row["target"] in counts
               and row["positive"] in range(len(POSITIVES)) and type(row["ops"]) is list and row["ops"] != []
               and type(row["refusal"]) is str and row["refusal"] != "", "a closed negative vector")
        counts[row["target"]] += 1
    require(tuple(row["id"] for row in negatives) == NEGATIVE_IDS and counts == NEGATIVE_COUNTS,
            "the negatives' identifiers and targets are restated")
    for row in vectors["parseNegatives"]:
        _bound(lambda: tuple(row) == PARSE_KEYS and type(row["raw"]) is str and row["raw"] != ""
               and type(row["refusal"]) is str and row["refusal"] != "", "a closed parse negative")
    require(tuple(row["id"] for row in vectors["parseNegatives"]) == PARSE_IDS, "the parse negatives' identifiers are restated")
    return vectors


def validate_checker(loaded: dict) -> dict:
    """The checker imports only the restated modules and names no file writer, process or network call; executed from its
    verified bytes, it holds the restated constants, accepts each verified schema, computes each positive's restated plan
    sha256, and replays every vector to its recorded result."""
    raw = _verified(CHECKER)
    tree = ast.parse(raw)
    imported = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported |= {alias.name for alias in node.names}
        elif isinstance(node, ast.ImportFrom):
            imported.add(node.module)
    names = {node.id for node in ast.walk(tree) if isinstance(node, ast.Name)}
    attributes = {node.attr for node in ast.walk(tree) if isinstance(node, ast.Attribute)}
    require(imported == CHECKER_IMPORTS and not names & CHECKER_FORBIDDEN_NAMES
            and not attributes & CHECKER_FORBIDDEN_ATTRIBUTES,
            "the checker imports only the standard library and names no file writer, process or network call")
    checker = _era_model(CHECKER, "_met_linux_007_lab_run_plan")
    _bound(lambda: checker.CONTRACT_DIR == CONTRACT_DIR and checker.SCHEMA_PATHS == SCHEMAS
           and checker.VECTORS_PATH == VECTORS_PATH and set(checker.SCHEMA_KEYWORDS) == SCHEMA_SUBSET
           and tuple(checker.RESOURCE_CLASSES) == RESOURCE_CLASSES and set(checker.ALWAYS_KEPT) == ALWAYS_KEPT
           and checker.CLASS_ROLES == dict(CLASS_ROLES)
           and tuple(shape.pattern for shape in checker.FORBIDDEN_TEXT) == FORBIDDEN_SHAPES,
           "the checker holds the restated constants")
    for kind, path in SCHEMAS.items():
        _bound(lambda: checker.strict(_verified(path)) == loaded[kind] and checker.check_schema(loaded[kind]) is None,
               "the checker accepts the schema: " + path)
    vectors = checker.strict(_verified(VECTORS_PATH))
    tripped = [0] * len(FORBIDDEN_SHAPES)
    for row in vectors["negatives"]:
        if row["refusal"].startswith(FREE_TEXT_REFUSAL):
            found = [index for index, shape in enumerate(checker.FORBIDDEN_TEXT) for op in row["ops"]
                     if type(op.get("value")) is str and shape.search(op["value"])]
            require(len(found) == 1, "each free-text negative trips exactly one forbidden shape: " + row["id"])
            tripped[found[0]] += 1
    require(all(tripped), "every forbidden shape has a negative of its own")
    _bound(lambda: all(checker.plan_sha256(row["plan"]) == sha for row, (_name, _gate, sha) in zip(vectors["positives"],
                                                                                                 POSITIVES)),
           "the checker computes each positive's restated plan sha256")
    _bound(lambda: checker.replay(vectors, loaded) == CHECKER_COUNTS,
           "the checker accepts each positive and refuses each negative as recorded")
    return checker


def validate_lab_run_plan() -> None:
    """The contract's files, then every reviewed byte, the adoption record and the README; then the schemas, the vectors
    and the checker's replay; last, this layer's canonical hunks."""
    for path in ERA_SHA256:
        _verified(path)
    validate_contract_files()
    validate_status()
    validate_readme()
    loaded = validate_schemas()
    validate_vectors()
    validate_checker(loaded)
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
            == record["validatorNormalizedSha256"], "lab run-plan validator drift")
    paths = sorted((ROOT / "task-packets").glob("*.yaml"))
    old = set(record["baselinePackets"])
    require(len(paths) == 256
            and {path.stem for path in paths} == old | {NEW_PACKET, successor.NEW_PACKET, successor.successor.NEW_PACKET, successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.NEW_PACKET},
            "closed 256-packet catalog retaining the 251-packet checkpoint")
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
            "closed source-only lab-run-plan packet and inherited commands")
    require(len(packet["allowedPaths"]) == len(set(packet["allowedPaths"]))
            and set(packet["allowedPaths"]) == set(record["changedFiles"])
            | set(record["newFiles"]) | {AUTHORITY_PATH, VALIDATOR_PATH,
                                         "task-packets/" + NEW_PACKET + ".yaml"},
            "unreviewed or omitted lab-run-plan packet path")
    for path, rule in record["changedFiles"].items():
        current = successor.historical_bytes(path, regular_bytes(path))
        require(digest(current) == rule["afterSha256"]
                and digest(historical_bytes(path, current)) == rule["beforeSha256"],
                "unreviewed current source: " + path)
    for path, expected in record["newFiles"].items():
        require(digest(successor.historical_bytes(path, regular_bytes(path))) == expected,
                "new source drift: " + path)
    validate_lab_run_plan()


if __name__ == "__main__":
    validate()
    print("Lab run-plan contract valid: 256 current specifications; 251-packet checkpoint and exact 250-packet predecessor; contract reviewed.")
