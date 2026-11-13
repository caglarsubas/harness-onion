#!/usr/bin/env python3
"""Validate MET-PERF-047 (CHAIN-COMPACTION-002): the shadow chain checkpoint in a K = 0 step (V1-V6: the packet's seven files by digest and the oracle binding; the ledger; the conftest's guarded load; the registry rider; the attested digests; the hunk-class record)."""
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
    import validate_met_verify_007 as successor
except ImportError:
    from scripts.safe_yaml import safe_load
    from scripts import validate_met_verify_007 as successor


ROOT = Path(__file__).resolve().parents[1]
AUTHORITY_PATH = "architecture/chain-checkpoint-authority.json"
AUTHORITY_SHA256 = "2099a4748ca5234608d967568b9e2140b74a33d285dc4db187cdd0c53a9c7236"
VALIDATOR_PATH = "scripts/validate_met_perf_047.py"
BASE_COMMIT = "dcf11803fca83454cb0660ffd88b65ce06a22a0f"
NEW_PACKET = "MET-PERF-047"
PREVIOUS_PACKET = "MET-ADOPT-007"
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
            require(key not in result, "duplicate chain-checkpoint authority member")
            result[key] = value
        return result

    def no_constant(_value: str) -> Any:
        raise ValueError("nonfinite chain-checkpoint authority number")

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
        require(digest(raw) == AUTHORITY_SHA256, "chain checkpoint history authority digest")
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
    }, "closed chain checkpoint history authority")
    require(value["schemaVersion"] == "harness.planeon.ai/chain-checkpoint-authority/v1"
            and value["authorityPacket"] == NEW_PACKET
            and value["acceptedBase"] == BASE_COMMIT
            and type(value["baselinePackets"]) is dict
            and len(value["baselinePackets"]) == 288
            and NEW_PACKET not in value["baselinePackets"]
            and type(value["changedFiles"]) is dict
            and type(value["newFiles"]) is dict
            and _sha(value["packetSha256"])
            and _sha(value["validatorNormalizedSha256"]),
            "accepted 288-packet base")
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
    # An exact 288-era byte string is already older than the successor layer.
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


# MET-PERF-047 (roadmap CHAIN-COMPACTION-002; the lane monitor's owner-delegated rulings MON-282-ASSIGN, MON-282C-RULED,
# MON-282-CR5-CLOSE, MON-282-W1-A2, MON-282-CR6-KEEP, MON-282-W2-RULED, MON-282-W2-ORDER and MON-282-W2-WRITESET)
# records, in a K = 0 step, the shadow chain checkpoint: the
# ledger of chain layers 189-281 at the checkpoint tree (architecture/chain-checkpoint/record.json, written by the
# lane-run writer scripts/chain_checkpoint_writer.py), its README and vectors, the shadow-only reader
# ci/chain_checkpoint.py that the root conftest.py loads guarded in the outermost session, the module tests
# tests/test_chain_checkpoint.py and the D5a oracle tests/test_met_perf_047_oracle.py with its identity. This layer binds
# no PRODUCT_PACKETS, so the catalog holds C = 289 packets at slot S = 282. Its authority keeps the eight-member form; its
# hunk classes live in its closed hunk-class record (architecture/chain-checkpoint/hunk-classes/282.json), which the
# authority's own newFiles names by sha256 (MON-282-W1-A2). Repository bytes are read only through reviewed_bytes, so a
# later bridged successor projects its own edits away first; an era file is refused unless it is bound by digest on
# every read; the ledger (never an era file) and the hunk-class record are bound by the authority's newFiles digest, a
# ledger-named file by the bound ledger's digest and a changed file by the authority's afterSha256; no directory is
# listed. Each refusal is
# a pure check over the values read, so every one has a failing case on plain data. Checked here: V1, the packet's files
# (exactly these, each equal to the sha256 pinned below); V2, the ledger (its closed members, slot 282 over the
# 288-packet baseline, the owner's parameters, the full-run proof, both stated differences with the capture variables,
# only ruled check pairs, its size, its exclusion, and its layers equal to the chain walk 189-281, none attesting an
# excluded file); V3, the root conftest.py's guarded
# load of the reader, in the outermost session only, and its docstring; V4, the registry (it differs from the base by
# exactly the one rider); V5, every attested file's checkpoint digest equals its reviewed bytes (this validator's with
# its pin line normalized, v2.1's validatorNormalizedSha256 rule); V6, this step's
# hunk-class record (MON-282-W1-A2 condition 8: its closed members, the authority's path, the vocabulary, the rule's
# sha256 (chainmech v2.3's), the context against this step's names, one class per hunk for exactly the changed files, and every class
# re-checked by position by the reader's copy of the class rule). Last, this layer's own inverse hunks are the canonical
# byte-minimal ones (MET-PERF-040's carried rule).
CHECKPOINT_DIR = "architecture/chain-checkpoint"
LEDGER_PATH = CHECKPOINT_DIR + "/record.json"
LEDGER_SCHEMA = "harness.planeon.ai/chain-checkpoint/v1"
HUNK_RECORD_PATH = CHECKPOINT_DIR + "/hunk-classes/282.json"
READER_PATH = "ci/chain_checkpoint.py"
READER_NAME = "_met_perf_047_chain_checkpoint"
CONFTEST_PATH = "conftest.py"
ORACLE_IDENTITY = CHECKPOINT_DIR + "/oracle-identity.json"
ORACLE_SCHEMA = "planeon.oracle-identity/v1"
ORACLE_TEST = "tests/test_met_perf_047_oracle.py"
REGISTRY_PATH = "architecture/review-record/briefs.json"
PACKET_BRIEF = "architecture/review-briefs/REVIEW_BRIEF_PACKET.md"
CHECKPOINT_SLOT = 282
CHECKPOINT_BASELINE = 288
FIRST_LAYER = (189, "validate_unified_roadmap")
PREVIOUS_LAYER = "validate_authority_map"
# V1: the packet's files, named by path; each is pinned below by the sha256 of its adopted bytes.
PACKET_FILES = (
    "architecture/chain-checkpoint/README.md",
    "architecture/chain-checkpoint/oracle-identity.json",
    "architecture/chain-checkpoint/vectors.json",
    "ci/chain_checkpoint.py",
    "scripts/chain_checkpoint_writer.py",
    "tests/test_chain_checkpoint.py",
    "tests/test_met_perf_047_oracle.py",
)
# V2: the ledger's closed members, the owner's parameters (MON-CC2-D5-D8, MON-CC2-D9) and the writing run's two stated
# differences, always together (Q-282C-3, MON-282-Q1Q3).
LEDGER_MEMBERS = frozenset({"schemaVersion", "checkpointSlot", "checkpointBaseline", "writingCommit", "writingTree",
                            "parameters", "normalisedRecordClass", "layers", "checkPairs", "fullRunProof", "writingRun",
                            "sizeBound", "sizeBytes", "exclusion"})
# V2: the exclusion (MON-282-W2-RULED, MON-282-W2-WRITESET): this step's own products, never a layer's input, equal to
# the bounded build's write set: its authority, its hunk-class record and the ledger (files, sorted), and this
# validator's AUTHORITY_SHA256 pin line (pinLine).
EXCLUSION_FILES = ("architecture/chain-checkpoint-authority.json", "architecture/chain-checkpoint/hunk-classes/282.json",
                   "architecture/chain-checkpoint/record.json")
PARAMETERS = MappingProxyType({"cadenceSlots": 10, "sampleFraction": 0.1, "fullRunOn": "owner-named slot", "nShadow": 10,
                               "shadowCapSeconds": 15, "workers": 8})
SHADOW_IN = ("verify", "dryRunOnly")
STATED = ("direct: argv 63 runs outside ci/run_packet_argv.py, with -p scripts.chain_checkpoint_writer and the capture "
          "variables",
          "serial: the -p option keeps ci/parallel_suite.py's serial loop (one process); the verify runs 8 workers")
CAPTURE_ENV = ("CHAIN_CHECKPOINT_CAPTURE_DIR", "CHAIN_CHECKPOINT_CAPTURE_ROOT")
LAYER_MEMBERS = frozenset({"slot", "module", "validatorPath", "validatorSha256", "authorityPath", "authoritySha256",
                           "inputs", "nodes", "seconds"})
TEST_MEMBERS = frozenset({"testFilePath", "testFileSha256"})
# V3: the root conftest.py's guarded load (D7 (a)) and its docstring (the contract's text).
CONFTEST_LINES = (
    '_OUTERMOST = "PLANEON_PARALLEL_SUITE_SERIAL" not in _environ   # read once, before the parallel suite sets it\n',
    "def _load_checkpoint_reader():\n",
    '    path = _Path(__file__).parent / "ci" / "chain_checkpoint.py"\n',
    '    spec = _spec_from_file_location("_planeon_met_perf_047_chain_checkpoint", path)\n',
    "if _OUTERMOST:\n    try:\n        _CHECKPOINT = _load_checkpoint_reader()\n    except Exception as _exc:\n",
)
CONFTEST_DOC = ("Source-only diagnostics and the chain checkpoint's shadow reader (MET-PERF-047): no selection, fixture "
                "or authority changes; the reader only observes and records, never changes a session's outcome, and a "
                "missing or failing reader prints one class-C line.")
# V4: the registry at the base (the digest of its canonical JSON) and this packet's one rider (kind, series, path,
# version), appended last; the rider's sha256 is the generic packet brief's.
REGISTRY_BASE_SHA256 = "003ddbc1f3202c94961930de17f80505b06e78b94b68bbfcddf35350fdb98123"
RIDERS = (("PACKET", NEW_PACKET + "/packet", PACKET_BRIEF, 1),)
# V6: the hunk-class record's closed form and this step's class context (MON-282-W1-A2 conditions 1', 3 and 8).
HUNK_RECORD_MEMBERS = frozenset({"authorityPath", "hunkClassVocabulary", "hunkClassRuleSha256", "hunkClassContext",
                                 "classes"})
HUNK_VOCABULARY = ("bridge", "cascade", "other", "record", "register")     # chainmech v2.3 (MON-282-W2-RULED)
HUNK_RULE_SHA256 = "007112479ff663fea703347aed5e8f8ee9ff39a540118002dfd7b42ac592748f"
HUNK_CONTEXT = MappingProxyType({"newPacket": NEW_PACKET, "prevValidator": "scripts/validate_authority_map.py",
                                 "prevTest": "tests/test_authority_map.py", "steps": (1, 1)})
# Every era file with its digest: the packet's files, the root conftest.py, the registry and the generic packet brief.
# The ledger is never an era file: the authority's newFiles names it (MON-282-W2-ORDER).
ERA_SHA256 = MappingProxyType({
    "architecture/chain-checkpoint/README.md": "2fc8b151fe1aa16d4480b850177512f99d8109dc0e1ec0cebd58f379717ed8d8",
    "architecture/chain-checkpoint/oracle-identity.json": "a50796dccbe32fff1e3511fa190b47d01fe87e2cd56cb1c40850bcdaceaacb46",
    "architecture/chain-checkpoint/vectors.json": "ff3cf522c77a513e4401aa0d22378c249a85865f78ff28b018a170339cad3097",
    "architecture/review-briefs/REVIEW_BRIEF_PACKET.md": "6dcff68d7e6b01823f1740063e94910edcc159a71a6ee803f1b66c62fd06e274",
    "architecture/review-record/briefs.json": "bf42d8f42759df7afb90e7c86b8e9e862a50024356d368dc5d43ec73cf99bbbc",
    "ci/chain_checkpoint.py": "b66d601e387c181d627d2e210fe5db40bf6ae3ec2e12f1369b0215d9a57b046b",
    "conftest.py": "23395db8132224f09353ed6f89411dc4a20f87e5a33c55708febcc570cfbb324",
    "scripts/chain_checkpoint_writer.py": "22c74b740b1d50ec6745edc7f4d5caa650281cec430b7af3ed01481187f9aafe",
    "tests/test_chain_checkpoint.py": "79990c15850f9b1e49fad1bd53791ca49846b9ac129e6ce3b760cb2f25d30ed5",
    "tests/test_met_perf_047_oracle.py": "6f601d0478d3160832b60e50e6f5d7854c75b1d1c8755f0812d3293fa5f999f1",
})


def reviewed_bytes(path: str) -> bytes:
    """This packet's reviewed bytes of path; a bridged successor projects newer bytes back first."""
    return successor.historical_bytes(path, regular_bytes(path))


def _era_bytes(path: Any, raw: Any) -> bytes:
    """An era file's bytes, checked against its era digest; a path outside the era is refused."""
    expected = ERA_SHA256.get(path) if type(path) is str else None
    require(expected is not None, "MET-PERF-047 reviewed bytes are bound: " + str(path))
    require(type(raw) is bytes and digest(raw) == expected, "unreviewed CHAIN-COMPACTION-002 source: " + path)
    return raw


def _verified(path: str) -> bytes:
    """reviewed_bytes, checked against its era digest on every read; a path outside the era is refused before it is
    read."""
    require(type(path) is str and path in ERA_SHA256, "MET-PERF-047 reviewed bytes are bound: " + str(path))
    return _era_bytes(path, reviewed_bytes(path))


def _bound_read(path: str, expected: Any) -> bytes:
    """reviewed_bytes of a file named by an era-verified record, checked against the digest that record gives it."""
    require(type(path) is str and _sha(expected), "MET-PERF-047 bound read: " + str(path))
    _path(path)
    raw = reviewed_bytes(path)
    require(type(raw) is bytes and digest(raw) == expected, "MET-PERF-047 bound file drift: " + path)
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


def _era_model(path: str, name: str) -> types.ModuleType:
    """A reference module of this era, executed from its verified bytes (no import, no bytecode); it imports only the
    standard library."""
    module = types.ModuleType(name)
    module.__file__ = str(ROOT / path)
    exec(compile(_verified(path), path, "exec", dont_inherit=True), module.__dict__)
    return module


def check_packet_files(files: Any) -> None:
    """V1: the packet's files are exactly these, and each one's bytes equal the sha256 pinned for it."""
    _bound(lambda: type(files) is dict and sorted(files) == sorted(PACKET_FILES) and len(files) == len(PACKET_FILES),
           "the packet files are exactly the seven")
    for path in PACKET_FILES:
        _bound(lambda: type(files[path]) is bytes and digest(files[path]) == ERA_SHA256[path],
               "a packet file's bytes equal its pinned digest: " + path)


def validate_packet_files() -> None:
    """V1 over the packet's files, each read through the era."""
    check_packet_files({path: _verified(path) for path in PACKET_FILES})


def _layer_holds(layer: Any) -> bool:
    keys = set(layer) if type(layer) is dict else set()
    return (type(layer) is dict and keys - TEST_MEMBERS == LAYER_MEMBERS and keys & TEST_MEMBERS in (set(), TEST_MEMBERS)
            and type(layer["slot"]) is int and type(layer["module"]) is str
            and layer["validatorPath"] == "scripts/" + layer["module"] + ".py"
            and _sha(layer["validatorSha256"]) and type(layer["authorityPath"]) is str
            and _sha(layer["authoritySha256"]) and type(layer["inputs"]) is dict
            and all(type(p) is str and _sha(d) for p, d in layer["inputs"].items())
            and type(layer["nodes"]) is list and type(layer["seconds"]) in (int, float)
            and (not keys & TEST_MEMBERS or (type(layer["testFilePath"]) is str and _sha(layer["testFileSha256"]))))


def check_ledger(raw: Any, walk: Any, baseline: Any) -> None:
    """V2: the ledger's closed members; slot 282 over the 288-packet baseline; the owner's parameters with shadowIn one of
    the two modes; the full-run proof (every collected node executed, none deselected, none attested); both stated
    differences with the capture variables; only ruled check pairs; its size within its bound; and its layers, in
    order, the chain walk below slot 282 (walk: each layer's reviewed validator bytes, by path)."""
    ledger = _parsed(raw)
    _bound(lambda: type(ledger) is dict and set(ledger) == LEDGER_MEMBERS and ledger["schemaVersion"] == LEDGER_SCHEMA
           and ledger["checkpointSlot"] == CHECKPOINT_SLOT and ledger["checkpointBaseline"] == CHECKPOINT_BASELINE == baseline,
           "the ledger is the closed slot-282 checkpoint over the 288-packet baseline")
    _bound(lambda: type(ledger["parameters"]) is dict and set(ledger["parameters"]) == set(PARAMETERS) | {"shadowIn"}
           and all(ledger["parameters"][k] == v and type(ledger["parameters"][k]) is type(v) for k, v in PARAMETERS.items())
           and ledger["parameters"]["shadowIn"] in SHADOW_IN and type(ledger["normalisedRecordClass"]) is bool,
           "the ledger's parameters are the owner's numbers")
    proof = ledger.get("fullRunProof") if type(ledger) is dict else None
    _bound(lambda: type(proof) is dict and set(proof) == {"collected", "executed", "deselected", "attested"}
           and type(proof["collected"]) is int and proof["collected"] > 0 and proof["executed"] == proof["collected"]
           and proof["deselected"] == 0 and proof["attested"] == 0,
           "the ledger's full-run proof: every collected node executed")
    run = ledger.get("writingRun") if type(ledger) is dict else None
    _bound(lambda: type(run) is dict and run["statedDifferences"] == list(STATED)
           and run["captureEnv"] == list(CAPTURE_ENV) and run["captureObservesOnly"] is True
           and type(run["outsideReads"]) is int and _sha(run["argvRunSummarySha256"]),
           "the writing run states both differences and the capture variables")
    _bound(lambda: type(ledger["checkPairs"]) is list and all(
        type(p) is dict and set(p) == {"layerSlot", "pairsPath", "ids", "type"} and p["type"] == "supersession"
        and type(p["ids"]) is list and len(p["ids"]) == 2 and len(set(p["ids"])) == 2 for p in ledger["checkPairs"]),
           "the ledger's check pairs are ruled supersessions")
    _bound(lambda: type(ledger["sizeBound"]) is int and ledger["sizeBytes"] == len(raw) <= ledger["sizeBound"],
           "the ledger's size is its length, within its bound")
    _bound(lambda: type(ledger["layers"]) is list and all(_layer_holds(layer) for layer in ledger["layers"]),
           "the ledger's layers have their closed members")
    _bound(lambda: ledger["exclusion"] == {"files": list(EXCLUSION_FILES), "pinLine": VALIDATOR_PATH}
           and not any(set(_attested(layer)) & set(EXCLUSION_FILES) for layer in ledger["layers"]),
           "the ledger's exclusion is this step's write set, and no layer attests an excluded file")
    check_walk(ledger["layers"], walk)


def check_walk(layers: Any, sources: Any) -> None:
    """V2's chain walk: the ledger's layers are consecutive from 189 (validate_unified_roadmap) to 281 (this layer's
    predecessor), and each layer's reviewed validator binds the next one (189 by its runner import, every later one
    by its successor import), the last binding this layer's validator."""
    _bound(lambda: type(layers) is list and type(sources) is dict and [layer["slot"] for layer in layers]
           == list(range(FIRST_LAYER[0], CHECKPOINT_SLOT)) and (layers[0]["slot"], layers[0]["module"]) == FIRST_LAYER
           and layers[-1]["module"] == PREVIOUS_LAYER,
           "the ledger's layers are the chain walk 189-281")
    names = [layer["module"] for layer in layers] + [VALIDATOR_PATH[len("scripts/"):-len(".py")]]
    for index, layer in enumerate(layers):
        bind = " " + names[index + 1] + " import " if index == 0 else "import " + names[index + 1] + " as successor\n"
        _bound(lambda: sources[layer["validatorPath"]].decode("utf-8").count(bind) >= 1,
               "the ledger's layers are the chain walk 189-281: slot %s binds its successor" % layer["slot"])


def check_ledger_bound(raw: Any, named: Any, era: Any) -> None:
    """V2: the ledger's bytes hash to the digest the authority's newFiles names for it, and the ledger is never an era
    file (MON-282-W2-ORDER: the head pins the authority, the authority names the ledger, the ledger attests the
    validator's normalized bytes)."""
    _bound(lambda: LEDGER_PATH not in era and _sha(named) and type(raw) is bytes and digest(raw) == named,
           "the ledger is bound by the authority's newFiles digest")


def _ledger() -> bytes:
    """The ledger's reviewed bytes, bound by the authority's newFiles digest."""
    named = authority()["newFiles"].get(LEDGER_PATH)
    _path(LEDGER_PATH)
    raw = reviewed_bytes(LEDGER_PATH)
    check_ledger_bound(raw, named, ERA_SHA256)
    return raw


def validate_ledger() -> None:
    """V2 over the bound ledger, the chain walk and the authority's baseline."""
    raw = _ledger()
    ledger = _parsed(raw)
    require(type(ledger) is dict and type(ledger.get("layers")) is list, "the ledger is the closed slot-282 checkpoint")
    walk = {layer["validatorPath"]: _bound_read(layer["validatorPath"], layer["validatorSha256"])
            for layer in ledger["layers"] if _layer_holds(layer)}
    check_ledger(raw, walk, len(authority()["baselinePackets"]))


def check_conftest(raw: Any) -> None:
    """V3: the root conftest.py loads the reader by path, guarded and in the outermost session only, and keeps the
    contract's docstring."""
    _bound(lambda: type(raw) is bytes and all(raw.decode("utf-8").count(line) == 1 for line in CONFTEST_LINES),
           "the root conftest.py loads the chain checkpoint reader guarded, outermost only")
    _bound(lambda: " ".join(ast.parse(raw.decode("utf-8")).body[0].value.value.split()) == CONFTEST_DOC,
           "the root conftest.py's docstring is the contract's")


def validate_conftest() -> None:
    """V3 over the era-verified root conftest.py."""
    check_conftest(_verified(CONFTEST_PATH))


def check_oracle(identity_raw: Any, oracle_raw: Any) -> None:
    """V1's oracle binding: the oracle identity names the D5a oracle test and is kept, and its file.sha256 equals the
    oracle test's bytes."""
    identity = _parsed(identity_raw)
    _bound(lambda: type(identity) is dict and identity["schemaVersion"] == ORACLE_SCHEMA
           and type(identity["file"]) is dict and identity["file"]["path"] == ORACLE_TEST
           and type(identity["ruling"]) is dict and identity["ruling"]["decision"] == "KEEP",
           "the oracle identity names the oracle test and its ruling is KEEP")
    _bound(lambda: _sha(identity["file"]["sha256"]) and type(oracle_raw) is bytes
           and identity["file"]["sha256"] == digest(oracle_raw),
           "the oracle identity's sha256 equals the oracle test's bytes")


def validate_oracle() -> None:
    """The oracle binding over the identity and the oracle test (hashed only)."""
    check_oracle(_verified(ORACLE_IDENTITY), _verified(ORACLE_TEST))


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
           "the registry differs from the base by exactly the MET-PERF-047 packet rider, pinning the generic packet "
           "brief")


def validate_registry() -> None:
    """V4 over briefs.json and the generic packet brief."""
    check_registry(_verified(REGISTRY_PATH), {PACKET_BRIEF: _verified(PACKET_BRIEF)})


def _attested(layer: dict) -> dict:
    files = {layer["validatorPath"]: layer["validatorSha256"], layer["authorityPath"]: layer["authoritySha256"],
             **layer["inputs"]}
    if "testFilePath" in layer:
        files[layer["testFilePath"]] = layer["testFileSha256"]
    return files


def _attested_digest(path: str, raw: Any) -> Any:
    """V5: a file's attested digest; this validator's own bytes with its one pin line set to the placeholder, under
    v2.1's validatorNormalizedSha256 rule as validate() applies it (MON-282-W2-RULED); None when that line is not one."""
    if path != VALIDATOR_PATH:
        return digest(raw)
    literal = b'AUTHORITY_SHA256 = "' + AUTHORITY_SHA256.encode("ascii") + b'"'
    if raw.count(literal) != 1:
        return None
    return digest(raw.replace(literal, b'AUTHORITY_SHA256 = "TO_BE_PINNED_AFTER_SOURCE_FREEZE"'))


def check_attested(ledger: Any, read: Any) -> None:
    """V5: every attested file of every layer has the checkpoint digest the ledger records for it (this validator by its
    normalized digest)."""
    for layer in ledger["layers"]:
        for path, expected in _attested(layer).items():
            _bound(lambda: _sha(expected) and _attested_digest(path, read(path, expected)) == expected,
                   "an attested file's checkpoint digest equals its reviewed bytes: %s (slot %s)" % (path, layer["slot"]))


def _ledger_bound_read(path: str, expected: str) -> bytes:
    _path(path)
    raw = reviewed_bytes(path)
    require(type(raw) is bytes, "MET-PERF-047 attested read: " + path)
    return raw


def validate_attested() -> None:
    """V5 over the bound ledger's attested files, each read through reviewed_bytes."""
    ledger = _parsed(_ledger())
    require(type(ledger) is dict and type(ledger.get("layers")) is list
            and all(_layer_holds(layer) for layer in ledger["layers"]), "the ledger's layers are the chain walk 189-281")
    check_attested(ledger, _ledger_bound_read)


def check_hunk_record(raw: Any, changed: Any, afters: Any, classify: Any, rule_sha: Any) -> None:
    """V6 (MON-282-W1-A2 condition 8): the record's closed members; it names this layer's authority; the closed
    vocabulary and the pinned rule's sha256 (chainmech v2.3's), which the reader's copy of the rule also carries; the context is this
    step's names; it lists one class per reverse hunk for exactly the changed files; and every class equals the rule's
    class at its position, under this step's context."""
    record = _parsed(raw)
    _bound(lambda: type(record) is dict and set(record) == HUNK_RECORD_MEMBERS
           and record["authorityPath"] == AUTHORITY_PATH,
           "the hunk-class record is closed and names this layer's authority")
    _bound(lambda: record["hunkClassVocabulary"] == list(HUNK_VOCABULARY)
           and record["hunkClassRuleSha256"] == HUNK_RULE_SHA256 == rule_sha,
           "the hunk-class record's vocabulary and rule digest are the pinned ones")
    _bound(lambda: type(record["hunkClassContext"]) is dict and set(record["hunkClassContext"]) == set(HUNK_CONTEXT)
           and all(record["hunkClassContext"][k] == (list(v) if type(v) is tuple else v) for k, v in HUNK_CONTEXT.items()),
           "the hunk-class record's context is this step's names")
    classes = record.get("classes") if type(record) is dict else None
    _bound(lambda: type(changed) is dict and type(classes) is dict and set(classes) == set(changed)
           and all(type(classes[p]) is list and all(type(c) is str for c in classes[p])
                   and len(classes[p]) == len(changed[p]["reverseHunks"]) for p in changed),
           "the hunk-class record lists one class per hunk for exactly the changed files")
    steps = tuple(HUNK_CONTEXT["steps"])
    for path, entry in changed.items():
        seen = set()
        for position, (cls, hunk) in enumerate(zip(classes[path], entry["reverseHunks"])):
            _bound(lambda: cls in HUNK_VOCABULARY and cls == classify(
                path, afters[path], hunk["at"], _base64(hunk["removeBase64"]), _base64(hunk["insertBase64"]),
                HUNK_CONTEXT["prevValidator"], HUNK_CONTEXT["prevTest"], NEW_PACKET, steps, seen=seen),
                   "a recorded class re-checks by position: %s hunk %d" % (path, position))


def validate_hunk_record() -> None:
    """V6 over the authority's hunk-class record (bound by its newFiles digest), the changed files (bound by their
    afterSha256) and the reader's copy of the class rule, executed from its era-verified bytes."""
    record = authority()
    raw = _bound_read(HUNK_RECORD_PATH, record["newFiles"].get(HUNK_RECORD_PATH))
    afters = {path: _bound_read(path, entry["afterSha256"]) for path, entry in record["changedFiles"].items()}
    reader = _era_model(READER_PATH, READER_NAME)
    rule_sha = HUNK_RULE_SHA256 if _verified(READER_PATH).decode("utf-8").count(
        'RULE_SHA256 = "' + HUNK_RULE_SHA256 + '"') == 1 else None
    check_hunk_record(raw, record["changedFiles"], afters, reader.classify, rule_sha)


def validate_met_perf_047(packets: dict[str, Any]) -> None:
    """Every era file first; then V1 (the packet's files and the oracle binding), V2 (the ledger), V3 (the conftest),
    V4 (the registry), V5 (the attested digests) and V6 (the hunk-class record); last, this layer's canonical hunks."""
    for path in ERA_SHA256:
        _verified(path)
    validate_packet_files()
    validate_oracle()
    validate_ledger()
    validate_conftest()
    validate_registry()
    validate_attested()
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
    validator_raw = successor.historical_bytes(VALIDATOR_PATH, regular_bytes(VALIDATOR_PATH))
    literal = b'AUTHORITY_SHA256 = "' + AUTHORITY_SHA256.encode("ascii") + b'"'
    placeholder = b'AUTHORITY_SHA256 = "TO_BE_PINNED_AFTER_SOURCE_FREEZE"'
    require(validator_raw.count(literal) == 1
            and digest(validator_raw.replace(literal, placeholder))
            == record["validatorNormalizedSha256"], "chain checkpoint validator drift")
    paths = sorted((ROOT / "task-packets").glob("*.yaml"))
    old = set(record["baselinePackets"])
    require(len(paths) == 300
            and {path.stem for path in paths} == old | {NEW_PACKET, successor.NEW_PACKET, *successor.PRODUCT_PACKETS, successor.successor.NEW_PACKET, *successor.successor.PRODUCT_PACKETS, successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.NEW_PACKET, *successor.successor.successor.successor.successor.successor.PRODUCT_PACKETS},
            "closed 300-packet catalog retaining the 289-packet checkpoint")
    packets = {}
    for path in paths:
        if path.stem in (successor.NEW_PACKET, successor.successor.NEW_PACKET, *successor.successor.PRODUCT_PACKETS, successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.NEW_PACKET, *successor.successor.successor.successor.successor.successor.PRODUCT_PACKETS):
            continue
        if path.stem in successor.PRODUCT_PACKETS:
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
            "closed source-only chain-checkpoint packet and inherited commands")
    require(len(packet["allowedPaths"]) == len(set(packet["allowedPaths"]))
            and set(packet["allowedPaths"]) == set(record["changedFiles"])
            | set(record["newFiles"]) | {AUTHORITY_PATH, VALIDATOR_PATH,
                                         "task-packets/" + NEW_PACKET + ".yaml"},
            "unreviewed or omitted chain-checkpoint packet path")
    for path, rule in record["changedFiles"].items():
        current = successor.historical_bytes(path, regular_bytes(path))
        require(digest(current) == rule["afterSha256"]
                and digest(historical_bytes(path, current)) == rule["beforeSha256"],
                "unreviewed current source: " + path)
    for path, expected in record["newFiles"].items():
        require(digest(successor.historical_bytes(path, regular_bytes(path))) == expected,
                "new source drift: " + path)
    validate_met_perf_047(packets)


if __name__ == "__main__":
    validate()
    print("Chain checkpoint valid: 300 current specifications at slot 282; 289-packet checkpoint and exact 288-packet predecessor; contract reviewed.")
