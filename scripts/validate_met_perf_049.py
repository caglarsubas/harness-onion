#!/usr/bin/env python3
"""Validate MET-PERF-049 (CHAIN-COMPACTION-002's ledger rewrite step, K = 0): V1 this packet's files by digest; C1 the ledger; C2 its hunk side record; C3-C9 the reader, the v2.4 rule, the conftest, MET-PERF-048's inert provisions, twelve workers, the bridged layer's projection and the demotion; V4 the registry rider; V6 the hunk-class record under v2.4."""
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
except ImportError:
    from scripts.safe_yaml import safe_load


ROOT = Path(__file__).resolve().parents[1]
AUTHORITY_PATH = "architecture/ledger-rewrite-authority.json"
AUTHORITY_SHA256 = "dd053460d88acb523a3f47333511c4b3d483b0883fa1201fcb18617d8d563ddb"
VALIDATOR_PATH = "scripts/validate_met_perf_049.py"
BASE_COMMIT = "0fd885ff3a9a80f8882ec4a03e0d16e95675868c"
NEW_PACKET = "MET-PERF-049"
PREVIOUS_PACKET = "MET-ADOPT-008"
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
            require(key not in result, "duplicate ledger-rewrite authority member")
            result[key] = value
        return result

    def no_constant(_value: str) -> Any:
        raise ValueError("nonfinite ledger-rewrite authority number")

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
    global _VERIFIED_AUTHORITY
    raw = regular_bytes(AUTHORITY_PATH)
    if type(raw) is not bytes or _VERIFIED_AUTHORITY != (AUTHORITY_SHA256, raw):
        require(digest(raw) == AUTHORITY_SHA256, "ledger rewrite history authority digest")
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
    }, "closed ledger rewrite history authority")
    require(value["schemaVersion"] == "harness.planeon.ai/ledger-rewrite-authority/v1"
            and value["authorityPacket"] == NEW_PACKET
            and value["acceptedBase"] == BASE_COMMIT
            and type(value["baselinePackets"]) is dict
            and len(value["baselinePackets"]) == 296
            and NEW_PACKET not in value["baselinePackets"]
            and type(value["changedFiles"]) is dict
            and type(value["newFiles"]) is dict
            and _sha(value["packetSha256"])
            and _sha(value["validatorNormalizedSha256"]),
            "accepted 296-packet base")
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
    """Recheck the pinned authority and undo only this reviewed successor."""
    _checked_authority_raw()
    _path(path)
    require(type(raw) is bytes and len(raw) <= MAX_FILE_BYTES, "bounded source bytes required")
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
    _checked_authority_raw()
    require(type(raw) is bytes and len(raw) <= MAX_FILE_BYTES, "bounded test bytes required")
    current_sha = digest(raw)
    matches = [path for path, rule in _PROJECTION_RULES.items()
               if path.startswith(TEST_PREFIXES) and current_sha == rule["afterSha256"]]
    require(len(matches) <= 1, "ambiguous current test")
    return _undo_this_layer(matches[0], raw) if matches else raw


def current_test_bytes(before: bytes) -> bytes:
    _checked_authority_raw()
    require(type(before) is bytes and len(before) <= MAX_FILE_BYTES, "bounded test bytes required")
    before_sha = digest(before)
    matches = [path for path, rule in _PROJECTION_RULES.items()
               if path.startswith(TEST_PREFIXES) and before_sha == rule["beforeSha256"]]
    require(len(matches) <= 1, "ambiguous predecessor test")
    if not matches:
        return before
    current = regular_bytes(matches[0])
    require(digest(current) == _PROJECTION_RULES[matches[0]]["afterSha256"],
            "current test drift")
    return current


def historical_catalog(packets: dict[str, Any]) -> dict[str, Any]:
    """Remove only this layer, leaving predecessor checks to their owners."""
    _checked_authority_raw()
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


# MET-PERF-049 (CHAIN-COMPACTION-002's ledger rewrite step; the lane monitor's owner-delegated rulings MON-286-RULINGS,
# MON-286-WTRIAL-RULE, MON-C286-Q1-T1, MON-C286-Q2-E1, MON-286-CR1, MON-286-C1B-GO and MON-286-W-PLAN) records, in a
# K = 0 step, the second chain checkpoint: the ledger of chain layers 189-285 over the 296-packet baseline, written by
# a full writing run under the owner's head-bound approval, its reverse hunks in a closed side record, and the
# reader's class cache, class rule v2.4, the demoted (authored) classification, MET-PERF-048's inert provisions and
# twelve parallel-suite workers. Repository bytes are read only through reviewed_bytes; an era file is refused unless
# bound by digest on every read; the ledger and its side record are bound by the authority (never era files), a
# changed file by the authority's afterSha256. Each refusal is a pure check over the values read. Checked here
# (CONTRACT_286 r4 section 5): V1 the packet's files; C1 the ledger; C2 the side record; C3 the reader's caches and
# rule set; C4 the v2.4 rule copy; C5 tests/conftest.py's once-flag; C6 P-048-1..4, inert; C7 WORKERS 12; C8 285's
# bridged layer reads through the projection; C9 the demotion's kinds and record fields; V4 the registry rider;
# V6 the hunk-class record under v2.4. Last, this layer's own inverse hunks are the canonical ones.
PACKET_FILES = ('architecture/chain-checkpoint/README.md', 'architecture/chain-checkpoint/vectors.json', 'ci/chain_checkpoint.py', 'ci/parallel_suite.py', 'conftest.py', 'docs/alpha-2/PARALLEL_SUITE_PERF035.md', 'scripts/chain_checkpoint_writer.py', 'tests/conftest.py', 'tests/test_chain_checkpoint.py', 'tests/test_parallel_suite.py')
REGISTRY_BASE_SHA256 = "3b44949522550ff54142bd27efa7b31833191fa524a661c36611d4f928de1bc1"
PREVIOUS_CHECKPOINT = (282, "434df59dc4992bf2af92d5781cf83d8147d6f229a86b19efbf7c7b885ce6e11d")
TESTS_CONFTEST_BASE_SHA256 = "1b67efa897df8c7fdbd4c3cc3bd5b6ccd8f1e1bdce32b135f273f943570301b1"
ROOT_CONFTEST_BASE_SHA256 = "23395db8132224f09353ed6f89411dc4a20f87e5a33c55708febcc570cfbb324"
TESTS_CONFTEST_EDITS = ((b'_CHAIN_PRELOADED = False     # MET-PERF-049 (286 3.5): the chain preload, collect and freeze run once per process\n\n\n', b''), (b'    global _CHAIN_PRELOADED\n', b''), (b'        # MET-PERF-049 (286 3.5, MP049-C1-13): only the process\'s first module that has the chain imports it; the flag\n        # is set only after the imports, the collect and the freeze have all completed (a raise leaves it unset, and a\n        # module whose rootpath lacks the chain neither imports nor uses up the flag).\n        if not _CHAIN_PRELOADED and (collector.config.rootpath / "scripts" / "validate_credential_lifecycle.py").is_file():\n', b'        if (collector.config.rootpath / "scripts" / "validate_credential_lifecycle.py").is_file():\n'), (b'            gc.freeze()\n            _CHAIN_PRELOADED = True\n', b'            gc.freeze()\n'))
ROOT_CONFTEST_EDITS = ((b'prints one class-C line. MET-PERF-049 (P-048-2, inert at 286): one guarded collection hook calls the reader\'s selection\nentry point only when the reader exposes one (no reader does at 286; MET-PERF-048\'s G1 module would), and a failure\nthere is one class-C line with the selection unchanged."""', b'prints one class-C line."""'), (b'def pytest_collection_modifyitems(session, config, items):\n    # MET-PERF-049 P-048-2: inert unless the reader exposes a selection entry point.\n    reader = _READER.get("reader")\n    select = getattr(reader, "select", None) if reader is not None else None\n    if select is None:\n        return\n    try:\n        select(items, config)\n    except Exception as exc:\n        _checkpoint_line("chain-checkpoint shadow: class C, the reader\'s selection raised: %s" % type(exc).__name__)\n\n\n', b''))
ERA_SHA256 = MappingProxyType({
    "architecture/chain-checkpoint/README.md": "d9a12f7f761035661d89aff35921e2a30a0dcd42ba72e39721bfa504eaf2ece4",
    "architecture/chain-checkpoint/vectors.json": "a8911ef07ac5db98675de99e09db609596c22fedbe959282a63b6a941cf1287a",
    "architecture/review-briefs/REVIEW_BRIEF_PACKET.md": "6dcff68d7e6b01823f1740063e94910edcc159a71a6ee803f1b66c62fd06e274",
    "architecture/review-record/briefs.json": "345fd81a3bfc7429a96bc7b8201c163e7d7c7c5ae7d9932d986244a5316cfba3",
    "ci/chain_checkpoint.py": "9d5d2a367df20f80675724cec63f09a2f4d2feba0c43f21fc9ce5d685d828eea",
    "ci/parallel_suite.py": "9f212f315d1d37b906366b4d595705dc3246bc3bffb2e7d5ffc0707fe8bec524",
    "conftest.py": "ca9230511c1c4c14aed3099fb82733900491893c70538b644a3f4d33aa304fad",
    "docs/alpha-2/PARALLEL_SUITE_PERF035.md": "57241b5ca23282d5c75bbebb77c16d0c363444bee5c4a826db9fde7cff4c910b",
    "scripts/chain_checkpoint_writer.py": "e0d7aefa7aa60d0727507f2094e3a476241c3189b4dc05038c79130a01768866",
    "tests/conftest.py": "262e50d941b15a41cd129f4f06f35f8dce82d29798e6935f697f24dbc8de95f3",
    "tests/test_chain_checkpoint.py": "9da122b14545bef7704f4c7af191fe96147cddd4533dcde42338d4d7ec5ee90e",
    "tests/test_parallel_suite.py": "56a41eacdcbb72939ca5b2fe1cb82de269fb62fceb3cb5823fe16ddc73022f6d",
})
REGISTRY_PATH = "architecture/review-record/briefs.json"
PACKET_BRIEF = "architecture/review-briefs/REVIEW_BRIEF_PACKET.md"
READER_PATH = "ci/chain_checkpoint.py"
RIDERS = (("PACKET", NEW_PACKET + "/packet", PACKET_BRIEF, 1),)


def reviewed_bytes(path: str) -> bytes:
    """This packet's reviewed bytes of path; a bridged successor projects newer bytes back first."""
    return regular_bytes(path)


def _era_bytes(path: Any, raw: Any) -> bytes:
    """An era file's bytes, checked against its era digest; a path outside the era is refused."""
    expected = ERA_SHA256.get(path) if type(path) is str else None
    require(expected is not None, "MET-PERF-049 reviewed bytes are bound: " + str(path))
    require(type(raw) is bytes and digest(raw) == expected, "unreviewed MET-PERF-049 source: " + path)
    return raw


def _verified(path: str) -> bytes:
    """reviewed_bytes, checked against its era digest on every read; a path outside the era is refused before it is
    read."""
    require(type(path) is str and path in ERA_SHA256, "MET-PERF-049 reviewed bytes are bound: " + str(path))
    return _era_bytes(path, reviewed_bytes(path))


def _bound_read(path: str, expected: Any) -> bytes:
    """reviewed_bytes of a file named by an era-verified record, checked against the digest that record gives it."""
    require(type(path) is str and _sha(expected), "MET-PERF-049 bound read: " + str(path))
    _path(path)
    raw = reviewed_bytes(path)
    require(type(raw) is bytes and digest(raw) == expected, "MET-PERF-049 bound file drift: " + path)
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
           "the registry differs from the base by exactly the MET-PERF-049 packet rider, pinning the generic packet "
           "brief")


def validate_registry() -> None:
    """V4 over briefs.json and the generic packet brief."""
    check_registry(_verified(REGISTRY_PATH), {PACKET_BRIEF: _verified(PACKET_BRIEF)})


CHECKPOINT_DIR = "architecture/chain-checkpoint"
LEDGER_PATH = CHECKPOINT_DIR + "/record.json"
LEDGER_SCHEMA = "harness.planeon.ai/chain-checkpoint/v1"
HUNK_RECORD_PATH = CHECKPOINT_DIR + "/hunk-classes/286.json"
SIDE_PATH = CHECKPOINT_DIR + "/ledger-hunks/286.json"
READER_NAME = "_met_perf_049_chain_checkpoint"
WRITER_PATH = "scripts/chain_checkpoint_writer.py"
CONFTEST_PATH, TESTS_CONFTEST = "conftest.py", "tests/conftest.py"
SUITE_PATH, SUITE_TEST = "ci/parallel_suite.py", "tests/test_parallel_suite.py"
PAGE_PATH = "docs/alpha-2/PARALLEL_SUITE_PERF035.md"
README_PATH, VECTORS_PATH = CHECKPOINT_DIR + "/README.md", CHECKPOINT_DIR + "/vectors.json"
G1_MODULE = "ci/chain_checkpoint_g1.py"
BRIDGED_LAYER = "scripts/validate_met_adopt_008.py"
CHECKPOINT_SLOT, CHECKPOINT_BASELINE = 286, 296
FIRST_LAYER, PREVIOUS_LAYER = (189, "validate_unified_roadmap"), "validate_met_adopt_008"
SIZE_CAP = 16_777_216
WORKERS_COUNT = 12
LEDGER_MEMBERS = frozenset({"schemaVersion", "checkpointSlot", "checkpointBaseline", "writingCommit", "writingTree",
                            "parameters", "normalisedRecordClass", "layers", "checkPairs", "fullRunProof", "writingRun",
                            "sizeBound", "sizeBytes", "exclusion"})
RUN_MEMBERS = frozenset({"statedDifferences", "captureEnv", "captureObservesOnly", "outsideReads", "argvRunSummarySha256",
                         "verifyReference"})
EXCLUSION_FILES = ("architecture/chain-checkpoint/hunk-classes/286.json", "architecture/chain-checkpoint/ledger-hunks/286.json",
                   "architecture/chain-checkpoint/record.json", "architecture/ledger-rewrite-authority.json")
PARAMETERS = MappingProxyType({"cadenceSlots": 10, "sampleFraction": 0.1, "fullRunOn": "owner-named slot", "nShadow": 10,
                               "shadowCapSeconds": 15, "workers": WORKERS_COUNT})
SHADOW_IN = ("verify", "dryRunOnly")
STATED = ("direct: argv 63 runs outside ci/run_packet_argv.py, with -p scripts.chain_checkpoint_writer and the capture "
          "variables",
          "serial: the -p option keeps ci/parallel_suite.py's serial loop (one process); the verify runs 12 workers")
CAPTURE_ENV = ("CHAIN_CHECKPOINT_CAPTURE_DIR", "CHAIN_CHECKPOINT_CAPTURE_ROOT")
VERIFY_REFERENCE = "the previous checkpoint: slot %d, record.json sha256 %s" % PREVIOUS_CHECKPOINT
LAYER_MEMBERS = frozenset({"slot", "module", "validatorPath", "validatorSha256", "authorityPath", "authoritySha256",
                           "inputs", "nodes", "seconds"})
TEST_MEMBERS = frozenset({"testFilePath", "testFileSha256"})
SIDE_MEMBERS = frozenset({"authorityPath", "path", "beforeSha256", "afterSha256", "reverseHunks"})
ENTRY_KEYS = frozenset({"beforeSha256", "afterSha256", "reverseHunksRecord"})
RULE_DIGESTS = MappingProxyType({"RULE_V22_SHA256": "c4a77f027b244d6f1c22178fadfa7c0d4b6f7b607ada89b2eebdebc01417427b",
                                 "RULE_SHA256": "007112479ff663fea703347aed5e8f8ee9ff39a540118002dfd7b42ac592748f",
                                 "RULE_V24_SHA256": "8c61a0df32e396d52e3c3b2dc3cef416f3d9473b684b855a18ba357377dcc0c4"})
V24_MARKS = (b"# ---- chainmech v2.4's class rule", b"# ---- end of chainmech v2.4's class rule ----\n")
V24_LINES = (b'CONTEXT_KEYS_V24 = CONTEXT_KEYS | {"countPairs"}\n',
             b'SIDE_MEMBERS_V24 = SIDE_MEMBERS | {"outcomeStatements"}')
C6_READER = (b'G1_MODULE = "ci/chain_checkpoint_g1.py"', b'SIGNAL_RELATIVE = ".planeon/chain-checkpoint-g1-signal.json"',
             b"SIGNAL_MAX = 4096\n", b"        if not (self.root / G1_MODULE).is_file():\n            return\n",
             b"os.O_NOFOLLOW")
C6_WRITER = (b'SIGNAL_RELATIVE = ".planeon/chain-checkpoint-g1-signal.json"', b"if signal_present(")
C7_LINES = MappingProxyType({
    SUITE_TEST: (b"    assert SUITE.WORKERS == 12\n",),
    README_PATH: (b"keeps the parallel suite's serial loop, where the verify runs 12 workers.",
                  b"An outcome that differs between that run and the 12-worker verify 0 is"),
    PAGE_PATH: (b"to 12 worker processes (MET-PERF-049; 8 before), by the",),
    WRITER_PATH: (b'the verify runs %d workers" % workers', b'"statedDifferences": stated(workers)')})
C8_FORM = b"    result = model.check(reviewed_bytes, frozenset(packets))\n"
C8_READ = b"    return successor.historical_bytes(path, regular_bytes(path))\n"
C9_READER = (b'"demoted": ("\xe2\x80\x94", "neutral"), "demoted-outcome-explained": ("\xe2\x80\x94", "pending isolation")}',
             b'"attestedFraction": ', b'"isolation": self.isolation, "modeOfRecord": self.mode_of_record}',
             b'kind="demoted", countEffect=COUNT_EFFECT["demoted"][1])')
TESTS_CONFTEST_LINES = (b"\n_CHAIN_PRELOADED = False ", b"    global _CHAIN_PRELOADED\n",
                        b"        if not _CHAIN_PRELOADED and (collector.config.rootpath",
                        b"            gc.freeze()\n            _CHAIN_PRELOADED = True\n")
HUNK_RECORD_MEMBERS = frozenset({"authorityPath", "hunkClassVocabulary", "hunkClassRuleSha256", "hunkClassContext",
                                 "classes", "outcomeStatements"})
HUNK_VOCABULARY = ("bridge", "cascade", "other", "record", "register")     # chainmech v2.4 keeps v2.3's vocabulary
HUNK_RULE_SHA256 = "8c61a0df32e396d52e3c3b2dc3cef416f3d9473b684b855a18ba357377dcc0c4"
HUNK_CONTEXT = MappingProxyType({"newPacket": NEW_PACKET, "prevValidator": "scripts/validate_met_adopt_008.py",
                                 "prevTest": "tests/test_met_adopt_008.py", "steps": (1, 1), "countPairs": ((312, 313),)})


def _tree(raw: Any) -> Any:
    return ast.parse(raw.decode("utf-8")) if type(raw) is bytes else None


def _assigned(tree: Any, name: str) -> list:
    return [node for node in tree.body if isinstance(node, ast.Assign) and len(node.targets) == 1
            and isinstance(node.targets[0], ast.Name) and node.targets[0].id == name]


def _function(tree: Any, name: str) -> Any:
    found = [node for node in ast.walk(tree) if isinstance(node, ast.FunctionDef) and node.name == name]
    return found[0] if len(found) == 1 else None


def _absent(path: str) -> bool:
    """True when nothing (no file, link or directory) is at path."""
    try:
        (ROOT / path).lstat()
    except FileNotFoundError:
        return True
    return False


def check_packet_files(files: Any) -> None:
    """V1: the packet's files are exactly these, and each one's bytes equal the sha256 pinned for it."""
    _bound(lambda: type(files) is dict and sorted(files) == sorted(PACKET_FILES) and len(files) == len(PACKET_FILES),
           "MET-PERF-049 V1 the packet files are exactly the ten")
    for path in PACKET_FILES:
        _bound(lambda: type(files[path]) is bytes and digest(files[path]) == ERA_SHA256[path],
               "MET-PERF-049 V1 a packet file's bytes equal its pinned digest: " + path)


def validate_packet_files() -> None:
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


def _attested(layer: dict) -> dict:
    files = {layer["validatorPath"]: layer["validatorSha256"], layer["authorityPath"]: layer["authoritySha256"],
             **layer["inputs"]}
    if "testFilePath" in layer:
        files[layer["testFilePath"]] = layer["testFileSha256"]
    return files


def check_walk(layers: Any, sources: Any) -> None:
    """C1's chain walk: the ledger's layers are consecutive from 189 to 285 (this layer's predecessor), and each layer's
    reviewed validator binds the next one, the last binding this layer's validator."""
    _bound(lambda: type(layers) is list and type(sources) is dict and [layer["slot"] for layer in layers]
           == list(range(FIRST_LAYER[0], CHECKPOINT_SLOT)) and (layers[0]["slot"], layers[0]["module"]) == FIRST_LAYER
           and layers[-1]["module"] == PREVIOUS_LAYER,
           "MET-PERF-049 C1 the ledger's layers are the chain walk 189-285")
    names = [layer["module"] for layer in layers] + [VALIDATOR_PATH[len("scripts/"):-len(".py")]]
    for index, layer in enumerate(layers):
        bind = " " + names[index + 1] + " import " if index == 0 else "import " + names[index + 1] + " as successor\n"
        _bound(lambda: sources[layer["validatorPath"]].decode("utf-8").count(bind) >= 1,
               "MET-PERF-049 C1 the chain walk: slot %s binds its successor" % layer["slot"])


def check_ledger(raw: Any, walk: Any, baseline: Any, entry: Any) -> None:
    """C1: the ledger is named by this step's authority (its record.json entry's afterSha256, in the three-key form); its
    closed members; slot 286 over the 296-packet baseline; the owner's parameters with WORKERS 12; the full-run proof;
    both stated differences, the capture variables and the verify reference to slot 282's record; ruled check pairs;
    sizeBytes <= sizeBound <= 16 MiB; the exclusion equal to the write set; and the layers, the chain walk 189-285."""
    ledger = _parsed(raw)
    _bound(lambda: type(entry) is dict and set(entry) == ENTRY_KEYS and _sha(entry["afterSha256"])
           and type(raw) is bytes and digest(raw) == entry["afterSha256"]
           and entry["beforeSha256"] == PREVIOUS_CHECKPOINT[1],
           "MET-PERF-049 C1 the ledger is named by this step's authority over slot 282's record")
    _bound(lambda: type(ledger) is dict and set(ledger) == LEDGER_MEMBERS and ledger["schemaVersion"] == LEDGER_SCHEMA
           and ledger["checkpointSlot"] == CHECKPOINT_SLOT and ledger["checkpointBaseline"] == CHECKPOINT_BASELINE == baseline,
           "MET-PERF-049 C1 the ledger is the closed slot-286 checkpoint over the 296-packet baseline")
    _bound(lambda: type(ledger["parameters"]) is dict and set(ledger["parameters"]) == set(PARAMETERS) | {"shadowIn"}
           and all(ledger["parameters"][k] == v and type(ledger["parameters"][k]) is type(v) for k, v in PARAMETERS.items())
           and ledger["parameters"]["shadowIn"] in SHADOW_IN and type(ledger["normalisedRecordClass"]) is bool,
           "MET-PERF-049 C1 the ledger's parameters are the owner's numbers")
    proof = ledger.get("fullRunProof") if type(ledger) is dict else None
    _bound(lambda: type(proof) is dict and set(proof) == {"collected", "executed", "deselected", "attested"}
           and type(proof["collected"]) is int and proof["collected"] > 0 and proof["executed"] == proof["collected"]
           and proof["deselected"] == 0 and proof["attested"] == 0,
           "MET-PERF-049 C1 the ledger's full-run proof: every collected node executed")
    run = ledger.get("writingRun") if type(ledger) is dict else None
    _bound(lambda: type(run) is dict and set(run) == RUN_MEMBERS and run["statedDifferences"] == list(STATED)
           and run["captureEnv"] == list(CAPTURE_ENV) and run["captureObservesOnly"] is True
           and type(run["outsideReads"]) is int and _sha(run["argvRunSummarySha256"])
           and run["verifyReference"] == VERIFY_REFERENCE,
           "MET-PERF-049 C1 the writing run states both differences, the capture variables and the verify reference")
    _bound(lambda: type(ledger["checkPairs"]) is list and all(
        type(p) is dict and set(p) == {"layerSlot", "pairsPath", "ids", "type"} and p["type"] == "supersession"
        and type(p["ids"]) is list and len(p["ids"]) == 2 and len(set(p["ids"])) == 2 for p in ledger["checkPairs"]),
           "MET-PERF-049 C1 the ledger's check pairs are ruled supersessions")
    _bound(lambda: type(ledger["sizeBound"]) is int and ledger["sizeBytes"] == len(raw) <= ledger["sizeBound"] <= SIZE_CAP,
           "MET-PERF-049 C1 the ledger's size is its length, within its bound, within 16 MiB")
    _bound(lambda: type(ledger["layers"]) is list and all(_layer_holds(layer) for layer in ledger["layers"]),
           "MET-PERF-049 C1 the ledger's layers have their closed members")
    _bound(lambda: ledger["exclusion"] == {"files": list(EXCLUSION_FILES), "pinLine": VALIDATOR_PATH}
           and not any(set(_attested(layer)) & set(EXCLUSION_FILES) for layer in ledger["layers"]),
           "MET-PERF-049 C1 the ledger's exclusion is this step's write set, and no layer attests an excluded file")
    check_walk(ledger["layers"], walk)


def _ledger() -> tuple:
    """The ledger's reviewed bytes and its record.json entry in this step's authority."""
    entry = authority()["changedFiles"].get(LEDGER_PATH)
    _path(LEDGER_PATH)
    return reviewed_bytes(LEDGER_PATH), entry


def validate_ledger() -> None:
    raw, entry = _ledger()
    ledger = _parsed(raw)
    require(type(ledger) is dict and type(ledger.get("layers")) is list,
            "MET-PERF-049 C1 the ledger is the closed slot-286 checkpoint over the 296-packet baseline")
    walk = {layer["validatorPath"]: _bound_read(layer["validatorPath"], layer["validatorSha256"])
            for layer in ledger["layers"] if _layer_holds(layer)}
    check_ledger(raw, walk, len(authority()["baselinePackets"]), entry)


def check_side(side_raw: Any, named: Any, entry: Any, live: Any) -> None:
    """C2: the side record's closed members, its digest in newFiles, its authorityPath; the entry's exact three keys with
    reverseHunksRecord {path, sha256} naming the side record and its digest; the side record's path, beforeSha256 and
    afterSha256 equal the entry's; and its hunks reproduce slot 282's record byte-exactly from the live ledger."""
    side = _parsed(side_raw)
    _bound(lambda: _sha(named) and type(side_raw) is bytes and digest(side_raw) == named and type(side) is dict
           and set(side) == SIDE_MEMBERS and side["authorityPath"] == AUTHORITY_PATH and side["path"] == LEDGER_PATH
           and type(side["reverseHunks"]) is list,
           "MET-PERF-049 C2 the side record is closed, named in newFiles and names this layer's authority")
    _bound(lambda: type(entry) is dict and set(entry) == ENTRY_KEYS and entry["reverseHunksRecord"] == {
        "path": SIDE_PATH, "sha256": named} and (side["beforeSha256"], side["afterSha256"])
           == (entry["beforeSha256"], entry["afterSha256"]),
           "MET-PERF-049 C2 the record.json entry is the three-key form naming the side record")

    def replayed() -> bool:
        cur, prior = live, None
        for hunk in sorted(side["reverseHunks"], key=lambda h: -h["at"]):
            remove, insert = _base64(hunk["removeBase64"]), _base64(hunk["insertBase64"])
            if set(hunk) != {"at", "removeBase64", "insertBase64"} or type(hunk["at"]) is not int or (
                    prior is not None and hunk["at"] + len(remove) > prior) or cur[hunk["at"]:hunk["at"] + len(remove)] != remove:
                return False
            cur, prior = cur[:hunk["at"]] + insert + cur[hunk["at"] + len(remove):], hunk["at"]
        return digest(live) == side["afterSha256"] and digest(cur) == side["beforeSha256"] == PREVIOUS_CHECKPOINT[1]
    _bound(replayed, "MET-PERF-049 C2 the side record's hunks reproduce slot 282's record")


def validate_side() -> None:
    record = authority()
    raw, entry = _ledger()
    named = record["newFiles"].get(SIDE_PATH)
    check_side(_bound_read(SIDE_PATH, named) if _sha(named) else None, named, entry, raw)


def check_reader(reader: Any, readme: Any) -> None:
    """C3: L1 and L2 by syntax tree (rebuild's `classes` keyword, None by default; the Reader's per-invocation memo);
    RULES_BY_SHA keyed by the v2.2, v2.3 and v2.4 digests; COUNT_EFFECT equal to the README's countEffect table."""
    tree = _tree(reader)
    _bound(lambda: reader.count(b"\ndef rebuild(path, live, newer, norm, budget=None, classes=None):\n") == 1
           and _function(tree, "_rebuilt") is not None and b"self._l2[key] = value" in reader
           and b"self._l1, self._l2, self._land" in reader,
           "MET-PERF-049 C3 the reader's L1 and L2 caches")
    _bound(lambda: all(len(_assigned(tree, name)) == 1 and _assigned(tree, name)[0].value.value == value
                       for name, value in RULE_DIGESTS.items())
           and {key.id for key in _assigned(tree, "RULES_BY_SHA")[0].value.keys} == set(RULE_DIGESTS),
           "MET-PERF-049 C3 RULES_BY_SHA holds the v2.2, v2.3 and v2.4 digests")
    rows = {}
    for line in readme.decode("utf-8").splitlines():
        cells = [c.strip() for c in line.strip().strip("|").split("|")]
        if line.startswith("| ") and len(cells) == 4 and cells[2] in ("restart", "neutral", "count", "pending isolation"):
            rows[cells[0]] = (cells[1], cells[2])
    effect = ast.literal_eval(_assigned(tree, "COUNT_EFFECT")[0].value) if len(_assigned(tree, "COUNT_EFFECT")) == 1 else None
    _bound(lambda: rows.pop("agree") == ("—", "count") and rows == effect,
           "MET-PERF-049 C3 COUNT_EFFECT equals the README's table")


def check_rule(reader: Any) -> None:
    """C4: the reader's v2.4 block is byte-equal to the pinned tool, and the v2.4 context and member sets are bound."""
    _bound(lambda: reader.count(V24_MARKS[0]) == 1 and reader.count(V24_MARKS[1]) == 1
           and digest(reader[reader.index(V24_MARKS[0]):reader.index(V24_MARKS[1]) + len(V24_MARKS[1])]) == HUNK_RULE_SHA256
           and all(reader.count(line) == 1 for line in V24_LINES),
           "MET-PERF-049 C4 the reader's v2.4 rule copy is the pinned tool")


def _reversed(raw: Any, edits: Any) -> Any:
    """The digest of raw with each (new, old) edit taken back, or None when an edit is not found exactly once."""
    for new, old in edits:
        if raw.count(new) != 1:
            return None
        raw = raw.replace(new, old)
    return digest(raw)


def check_tests_conftest(raw: Any) -> None:
    """C5: tests/conftest.py's once-per-process flag, set only after the preload completes; its edits taken back give
    the base's bytes, so the recursion-limit and path restores are unchanged."""
    _bound(lambda: type(raw) is bytes and all(raw.count(line) == 1 for line in TESTS_CONFTEST_LINES)
           and len(_assigned(_tree(raw), "_CHAIN_PRELOADED")) == 1
           and _reversed(raw, TESTS_CONFTEST_EDITS) == TESTS_CONFTEST_BASE_SHA256,
           "MET-PERF-049 C5 tests/conftest.py's once-per-process flag, and nothing else")


def check_provisions(reader: Any, writer: Any, conftest: Any, g1_present: Any) -> None:
    """C6: P-048-1..4, inert at 286: the G1 module is loaded only when present, and it is absent; the signal file's
    HOME-relative path, its 4,096-byte bound and its link refusal in the reader; the writer's refusal while it is present;
    the root conftest's one guarded selection hook (its edits taken back give the base's bytes)."""
    _bound(lambda: g1_present is False and all(reader.count(line) == 1 for line in C6_READER[:4])
           and reader.count(C6_READER[4]) >= 1 and all(writer.count(line) >= 1 for line in C6_WRITER)
           and conftest.count(b'getattr(reader, "select", None)') == 1
           and _reversed(conftest, ROOT_CONFTEST_EDITS) == ROOT_CONFTEST_BASE_SHA256,
           "MET-PERF-049 C6 MET-PERF-048's provisions are present and inert")


def check_workers(suite: Any, texts: Any) -> None:
    """C7: WORKERS is 12 by syntax tree (one module-level int assignment); the live pin, the README's two worker lines,
    the status page's line and the writer's STATED (formatted from parameters.workers) follow it."""
    found = _assigned(_tree(suite), "WORKERS")
    _bound(lambda: len(found) == 1 and isinstance(found[0].value, ast.Constant) and type(found[0].value.value) is int
           and found[0].value.value == WORKERS_COUNT and suite.count(b"\nWORKERS = ") == 1,
           "MET-PERF-049 C7 WORKERS is 12, once")
    _bound(lambda: type(texts) is dict and set(texts) == set(C7_LINES)
           and all(texts[path].count(line) == 1 for path, lines in C7_LINES.items() for line in lines)
           and texts[SUITE_TEST].count(b"    assert SUITE.WORKERS == 8\n") == 0,
           "MET-PERF-049 C7 the pin, the README, the page and the writer follow WORKERS")


def check_bridged(raw: Any) -> None:
    """C8 (MA008-P1-3): 285's bridged layer reads its era through this step's projection (successor.historical_bytes
    over the live bytes), and its inherited A5 replays the authority-map model over those projected bytes, so 286's
    rider in the registry is undone first; never the live bytes."""
    _bound(lambda: type(raw) is bytes and raw.count(C8_FORM) == 1 and raw.count(C8_READ) == 1
           and raw.count(b"model.check(regular_bytes") == 0 and raw.count(b"import validate_met_perf_049 as successor\n") >= 1,
           "MET-PERF-049 C8 285's layer reads through this step's projection")


def check_demotion(reader: Any) -> None:
    """C9: the demotion's kinds in COUNT_EFFECT (pending isolation included), v2.4's member set with outcomeStatements,
    and the record's demoted, attestedFraction, isolation and modeOfRecord fields."""
    _bound(lambda: all(reader.count(line) == 1 for line in C9_READER),
           "MET-PERF-049 C9 the demotion's kinds and record fields")


def validate_sources() -> None:
    """C3-C9 over the era-verified reader, writer, conftests, suite, README, page and the bound bridged layer."""
    reader, writer, readme = _verified(READER_PATH), _verified(WRITER_PATH), _verified(README_PATH)
    check_reader(reader, readme)
    check_rule(reader)
    check_tests_conftest(_verified(TESTS_CONFTEST))
    check_provisions(reader, writer, _verified(CONFTEST_PATH), not _absent(G1_MODULE))
    check_workers(_verified(SUITE_PATH), {path: _verified(path) for path in C7_LINES})
    check_bridged(_bound_read(BRIDGED_LAYER, authority()["changedFiles"][BRIDGED_LAYER]["afterSha256"]))
    check_demotion(reader)


def check_hunk_record(raw: Any, changed: Any, afters: Any, classify: Any, context: Any, rule_sha: Any) -> None:
    """V6 under v2.4: the record's six closed members; it names this layer's authority; the closed vocabulary and v2.4's
    digest, which the reader's copy carries; the context is this step's names with countPairs; no outcome statement; one
    class per reverse hunk for exactly the changed files (record.json's entry, which has no hunks, an empty list); and
    every class equals v2.4's class at its position."""
    record = _parsed(raw)
    _bound(lambda: type(record) is dict and set(record) == HUNK_RECORD_MEMBERS and record["authorityPath"] == AUTHORITY_PATH
           and record["outcomeStatements"] == [],
           "MET-PERF-049 V6 the hunk-class record is closed and names this layer's authority")
    _bound(lambda: record["hunkClassVocabulary"] == list(HUNK_VOCABULARY)
           and record["hunkClassRuleSha256"] == HUNK_RULE_SHA256 == rule_sha,
           "MET-PERF-049 V6 the hunk-class record's vocabulary and rule digest are v2.4's")
    _bound(lambda: type(record["hunkClassContext"]) is dict and set(record["hunkClassContext"]) == set(HUNK_CONTEXT)
           and record["hunkClassContext"] == {"newPacket": NEW_PACKET, "prevValidator": HUNK_CONTEXT["prevValidator"],
                                              "prevTest": HUNK_CONTEXT["prevTest"], "steps": [1, 1], "countPairs": [[312, 313]]},
           "MET-PERF-049 V6 the hunk-class record's context is this step's names")
    classes = record.get("classes") if type(record) is dict else None
    _bound(lambda: type(changed) is dict and type(classes) is dict and set(classes) == set(changed)
           and all(type(classes[p]) is list and all(type(c) is str for c in classes[p])
                   and len(classes[p]) == len(changed[p].get("reverseHunks", [])) for p in changed)
           and classes.get(LEDGER_PATH, []) == [] and "reverseHunks" not in changed.get(LEDGER_PATH, {}),
           "MET-PERF-049 V6 the hunk-class record lists one class per hunk for exactly the changed files")
    for path, entry in changed.items():
        seen = set()
        for position, (cls, hunk) in enumerate(zip(classes[path], entry.get("reverseHunks", []))):
            _bound(lambda: cls in HUNK_VOCABULARY and cls == classify(
                path, afters[path], hunk["at"], _base64(hunk["removeBase64"]), _base64(hunk["insertBase64"]), context,
                seen=seen),
                   "MET-PERF-049 V6 a recorded class re-checks by position: %s hunk %d" % (path, position))


def _v24_source(path: str) -> bytes:
    """The reader's era-verified bytes with one alias line: its v2.4 copy answers as `classify` (the identity rule's
    attribute names hold `classify`, not `classify_v24`)."""
    return _verified(path) + b"\nclassify = classify_v24\n"


def _era_rule(path: str, name: str) -> types.ModuleType:
    """The reader's v2.4 rule as an era model, executed from its verified bytes plus the alias line (no import, no
    bytecode); it imports only the standard library."""
    module = types.ModuleType(name)
    module.__file__ = str(ROOT / path)
    exec(compile(_v24_source(path), path, "exec", dont_inherit=True), module.__dict__)
    return module


def _v24_context(record: Any, context: Any) -> dict:
    """v2.4's inputs from this step's authority and the record's context (the reader's context_v24 form): the catalog
    pair from the authority's baselinePackets size, then countPairs; no products (K = 0); the new tests from newFiles."""
    n = len(record["baselinePackets"])
    return {"prevValidator": context["prevValidator"], "prevTest": context["prevTest"], "newPacket": context["newPacket"],
            "products": [], "steps": context["steps"],
            "pairs": [[n, n + context["steps"][1]]] + [list(pair) for pair in context["countPairs"]],
            "newTests": [p for p in record["newFiles"] if p.startswith("tests/") and p.endswith(".py")]}


def validate_hunk_record() -> None:
    """V6 over the hunk-class record (bound by its newFiles digest), the changed files (bound by their afterSha256) and
    the reader's copy of v2.4, executed from its era-verified bytes."""
    record = authority()
    raw = _bound_read(HUNK_RECORD_PATH, record["newFiles"].get(HUNK_RECORD_PATH))
    afters = {path: _bound_read(path, entry["afterSha256"]) for path, entry in record["changedFiles"].items()
              if "reverseHunks" in entry}
    rule = _era_rule(READER_PATH, READER_NAME)
    side = _parsed(raw)
    rule_sha = HUNK_RULE_SHA256 if _verified(READER_PATH).count(
        b'RULE_V24_SHA256 = "' + HUNK_RULE_SHA256.encode("ascii") + b'"') == 1 else None
    context = _v24_context(record, side["hunkClassContext"]) if _holds(
        lambda: _v24_context(record, side["hunkClassContext"]) is not None) else None
    check_hunk_record(raw, record["changedFiles"], afters, rule.classify, context, rule_sha)


def validate_met_perf_049(packets: dict[str, Any]) -> None:
    """Every era file first; then V1, C1 (the ledger), C2 (the side record), C3-C9 (the sources), V4 (the registry) and
    V6 (the hunk-class record); last, this layer's canonical hunks."""
    for path in ERA_SHA256:
        _verified(path)
    validate_packet_files()
    validate_ledger()
    validate_side()
    validate_sources()
    validate_registry()
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
    validator_raw = regular_bytes(VALIDATOR_PATH)
    literal = b'AUTHORITY_SHA256 = "' + AUTHORITY_SHA256.encode("ascii") + b'"'
    placeholder = b'AUTHORITY_SHA256 = "TO_BE_PINNED_AFTER_SOURCE_FREEZE"'
    require(validator_raw.count(literal) == 1
            and digest(validator_raw.replace(literal, placeholder))
            == record["validatorNormalizedSha256"], "ledger rewrite validator drift")
    paths = sorted((ROOT / "task-packets").glob("*.yaml"))
    old = set(record["baselinePackets"])
    require(len(paths) == 297 and {path.stem for path in paths} == old | {NEW_PACKET},
            "closed 297-packet catalog")
    packets = {}
    for path in paths:
        raw = regular_bytes("task-packets/" + path.name)
        expected = (record["packetSha256"] if path.stem == NEW_PACKET
                    else record["baselinePackets"][path.stem])
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
            "closed source-only ledger-rewrite packet and inherited commands")
    require(len(packet["allowedPaths"]) == len(set(packet["allowedPaths"]))
            and set(packet["allowedPaths"]) == set(record["changedFiles"])
            | set(record["newFiles"]) | {AUTHORITY_PATH, VALIDATOR_PATH,
                                         "task-packets/" + NEW_PACKET + ".yaml"},
            "unreviewed or omitted ledger-rewrite packet path")
    for path, rule in record["changedFiles"].items():
        current = regular_bytes(path)
        require(digest(current) == rule["afterSha256"]
                and digest(historical_bytes(path, current)) == rule["beforeSha256"],
                "unreviewed current source: " + path)
    for path, expected in record["newFiles"].items():
        require(digest(regular_bytes(path)) == expected, "new source drift: " + path)
    validate_met_perf_049(packets)


if __name__ == "__main__":
    validate()
    print("Ledger rewrite valid: 297 current specifications at slot 286; exact 296-packet predecessor; contract reviewed.")
