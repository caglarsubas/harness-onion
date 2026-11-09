#!/usr/bin/env python3
"""Validate MET-PERF-045 (PERF-045): the verify-floor cuts C1+, C2 and C3 in a K = 0 step (V1-V4: the four packet files pinned; the cuts by syntax tree: the in-session readiness proof, the weights table, the two test-local share points and their key order; the registry's MET-PERF-045 packet rider as the one change from the base; the neighbours unchanged), and the exact 277-to-276 projection."""
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
    import validate_met_sector_005 as successor
except ImportError:
    from scripts.safe_yaml import safe_load
    from scripts import validate_met_sector_005 as successor


ROOT = Path(__file__).resolve().parents[1]
AUTHORITY_PATH = "architecture/quiet-host-cuts-authority.json"
AUTHORITY_SHA256 = "3d77dca1e2bdcfe4b94a68f3b01f59b742f1d36227467115f3ccdfdd8de70062"
VALIDATOR_PATH = "scripts/validate_met_perf_045.py"
BASE_COMMIT = "01a788b08727df74cc0f0ad3d27ffc50b80c5672"
NEW_PACKET = "MET-PERF-045"
PREVIOUS_PACKET = "MET-SECTOR-004"
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
            require(key not in result, "duplicate quiet-host-cuts authority member")
            result[key] = value
        return result

    def no_constant(_value: str) -> Any:
        raise ValueError("nonfinite quiet-host-cuts authority number")

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
        require(digest(raw) == AUTHORITY_SHA256, "quiet host cuts history authority digest")
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
    }, "closed quiet host cuts history authority")
    require(value["schemaVersion"] == "harness.planeon.ai/quiet-host-cuts-authority/v1"
            and value["authorityPacket"] == NEW_PACKET
            and value["acceptedBase"] == BASE_COMMIT
            and type(value["baselinePackets"]) is dict
            and len(value["baselinePackets"]) == 280
            and NEW_PACKET not in value["baselinePackets"]
            and type(value["changedFiles"]) is dict
            and type(value["newFiles"]) is dict
            and _sha(value["packetSha256"])
            and _sha(value["validatorNormalizedSha256"]),
            "accepted 280-packet base")
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
    # An exact 280-era byte string is already older than the successor layer.
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


# MET-PERF-045 (PERF-045; the owner's "Cuts + quiet host" with MON-277-FLOOR, and the lane monitor's owner-delegated
# rulings MON-277-PERF-PLAN, MON-277-CR1-KEEP, MON-277-REV2-GO, MON-277-CR2-KEEP, MON-277-REV3-GO and MON-277-MECH-GO)
# adopts contract rev 3's three verify-floor cuts in a K = 0 step: this layer binds no PRODUCT_PACKETS, so the catalog
# holds C = 281 packets at slot S = 277. C1+: tests/linux_runner/test_build_and_predecessors.py proves the parent test's
# readiness step from the session's own outcome of READINESS_NODE (MET-PERF-030's in-session mechanism) and re-runs the
# validator only when that node is not in the session or its outcome record is partial. C2:
# ci/parallel_suite_weights.json is the measured table weights_276 (gate material). C3: test-local exact sharing in two
# tests, restored after each: release_profile.safe_load in the class probe and native_qualification_v4.schema_errors in
# the v4 history-chain test, whose key keeps each value's own insertion order and never sorts. The packet's review
# series is registered by its own rider in architecture/review-record/briefs.json (MET-PERF-045/packet). Repository
# bytes are read only through reviewed_bytes, so a later bridged successor projects its own edits away first; a path
# outside this era is refused before it is read and every era file is bound by digest on every read. Each refusal is a
# pure check over the values read, so every one has a failing case on plain data. Checked here: V1, the packet's files
# (exactly the four, each equal to the sha256 pinned below; two of them are chain tests, whose era bytes hold this
# step's own count and successor edits); V2, the cuts, by the syntax tree of their reviewed bytes, never an import (C1+:
# READINESS_NODE bound once to the readiness node, the proof function returning the mode IN_SESSION_PROOF, called once
# by the parent test; C2: the table is a JSON object of test-file paths to finite non-negative seconds; C3: each
# sharing helper installed exactly once, through monkeypatch inside its one test, over its share point, and the
# schema_errors key built without sorting);
# V3, the registry (the base plus exactly this packet's rider); and V4, the neighbours the cuts lean on, unchanged since
# the base (the planner ci/parallel_suite.py with its workers, the outcome recorder tests/linux_runner/conftest.py, the
# readiness node's tests/test_readiness.py, scripts/release_profile.py and scripts/native_qualification_v4.py). No chain
# validator is pinned here, and no catalog file is named. Last, this layer's own inverse hunks are the canonical
# byte-minimal ones, recomputed from its era's bytes (MET-PERF-040's carried rule).
# V1: the packet's files, named by path; each is pinned below by the sha256 of its bytes in this era.
PACKET_FILES = ("ci/parallel_suite_weights.json", "tests/linux_runner/test_build_and_predecessors.py",
                "tests/test_native_profile_v4.py", "tests/test_release_profile.py")
# V2, C1+: the readiness node whose in-session outcome proves the parent's readiness step, and the proof's mode.
READINESS_PATH = "tests/linux_runner/test_build_and_predecessors.py"
READINESS_NODE = "tests/test_readiness.py::ReadinessValidationTest::test_complete_readiness_package"
PROOF_FUNCTION = "_in_session_readiness_proof"
PROOF_MODE = "IN_SESSION_PROOF"
PARENT_TEST = "test_full_predecessor_suites_and_validators_remain_green"
# V2, C2: the weights table.
WEIGHTS_PATH = "ci/parallel_suite_weights.json"
WEIGHT_PREFIXES = ("tests/", "ci/test_")
# V2, C3: each share point (file, the patched module's name in that file, its attribute, the sharing helper, the one
# test that installs it), and the schema_errors key function, which must never sort.
SHARE_POINTS = (
    ("tests/test_release_profile.py", "rp", "safe_load", "_shared_safe_load",
     "test_no_uncoded_exception_escapes_check_over_the_class_probe"),
    ("tests/test_native_profile_v4.py", "profile", "_era_model", "_shared_era_models",
     "test_exact_current_source_and_complete_history_chain"),
)
KEY_PATH, KEY_FUNCTION = "tests/test_native_profile_v4.py", "_strict_key"
REGISTRY_PATH = "architecture/review-record/briefs.json"
PACKET_BRIEF = "architecture/review-briefs/REVIEW_BRIEF_PACKET.md"
# V3: the registry at the base (the digest of its canonical JSON) and this packet's one rider (kind, series, path,
# version), appended last; the rider's sha256 is the generic packet brief's.
REGISTRY_BASE_SHA256 = "81808da1d44fc15d51c6ca8e4d130b56bda5afb562f3033960d5bce076ad379c"
RIDERS = (("PACKET", NEW_PACKET + "/packet", PACKET_BRIEF, 1),)
# V4: the neighbours this packet leaves unchanged since the base, each pinned below by its base digest.
NEIGHBOURS = ("ci/parallel_suite.py", "tests/linux_runner/conftest.py", "tests/test_readiness.py",
              "scripts/release_profile.py", "scripts/native_qualification_v4.py")
# Every file this era's check reads, with its digest: the packet's files, the registry, the generic packet brief and the
# neighbours.
ERA_SHA256 = MappingProxyType({
    "architecture/review-briefs/REVIEW_BRIEF_PACKET.md": "6dcff68d7e6b01823f1740063e94910edcc159a71a6ee803f1b66c62fd06e274",
    "architecture/review-record/briefs.json": "415414c434b8750926fbec2b01860d0dde615223a0dd6e80934cb01eea9cc757",
    "ci/parallel_suite.py": "4fe4e24951c6a4f023361f9e840e8343a68e5af713754ff7acdf523e475495d5",
    "ci/parallel_suite_weights.json": "81579f758e8116d69c76b59b85e8dffe5dd32ad93be60cd3e2c4f967b56eebb3",
    "scripts/native_qualification_v4.py": "f7c718072d1ffbb9b8bbc310e6141d476ea5f25296f70ff8c1bc9ada3db02387",
    "scripts/release_profile.py": "666c65ac5b76ec83250a2457062154519df5361cf883d8f44e6fa4f9eb6f2b1a",
    "tests/linux_runner/conftest.py": "72366b07b6c1b8dadf1c4a9b2bd4287d5d9672790fea686dbff363fd86fa964b",
    "tests/linux_runner/test_build_and_predecessors.py": "7572a817fd7c5440405007091005b412314aae108cae95ff2550f817c87a3cff",
    "tests/test_native_profile_v4.py": "b03503ec888ffcbea429594b7f2fb2962ea59dd775c9b73dacb81db54e4c352e",
    "tests/test_readiness.py": "9694b99697768d759542b5d0cacb44ae8f04a75591254bda94555f1dc70ba280",
    "tests/test_release_profile.py": "c75280b0fd41940b47a2f456461acc6ccc5ea6a8a00a63f4ff9f41c85869457c",
})


def reviewed_bytes(path: str) -> bytes:
    """This packet's reviewed bytes of path; a bridged successor projects newer bytes back first."""
    return successor.historical_bytes(path, regular_bytes(path))


def _era_bytes(path: Any, raw: Any) -> bytes:
    """An era file's bytes, checked against its era digest; a path outside the era is refused."""
    expected = ERA_SHA256.get(path) if type(path) is str else None
    require(expected is not None, "MET-PERF-045 reviewed bytes are bound: " + str(path))
    require(type(raw) is bytes and digest(raw) == expected, "unreviewed QUIET-HOST-CUTS source: " + path)
    return raw


def _verified(path: str) -> bytes:
    """reviewed_bytes, checked against its era digest on every read; a path outside the era is refused before it is
    read."""
    require(type(path) is str and path in ERA_SHA256, "MET-PERF-045 reviewed bytes are bound: " + str(path))
    return _era_bytes(path, reviewed_bytes(path))


def _parsed(raw: Any) -> Any:
    """raw as this layer's strict JSON, or None when it is not bytes holding such JSON."""
    try:
        return parse(raw) if type(raw) is bytes else None
    except ValueError:
        return None


def _syntax(raw: Any) -> Any:
    """raw's Python syntax tree, or None when it is not bytes holding UTF-8 Python source."""
    try:
        return ast.parse(raw.decode("utf-8")) if type(raw) is bytes else None
    except (SyntaxError, UnicodeDecodeError, ValueError):
        return None


def _holds(check: Any) -> bool:
    """A structural check over this era's data; a malformed value does not hold."""
    try:
        return check() is True
    except (KeyError, TypeError, AttributeError, IndexError, ValueError):
        return False


def _bound(check: Any, message: str) -> None:
    require(_holds(check), message)


def _top_function(tree: Any, name: str) -> Any:
    """The one module-level function of that name, or None."""
    found = [node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name == name]
    return found[0] if len(found) == 1 else None


def check_packet_file(path: Any, raw: Any) -> None:
    """V1: a packet file's bytes equal the sha256 pinned for it."""
    _bound(lambda: path in PACKET_FILES and type(raw) is bytes and digest(raw) == ERA_SHA256[path],
           "the packet file's bytes equal its pinned digest: " + str(path))


def validate_packet_files() -> None:
    """V1 over the four packet files, read through the era."""
    for path in PACKET_FILES:
        check_packet_file(path, _verified(path))


def check_readiness_proof(raw: Any) -> None:
    """V2, C1+: READINESS_NODE is bound once, at module level, to the readiness node; the proof function exists once and
    names the mode IN_SESSION_PROOF exactly once (MET-PERF-030's predecessor proof keeps its own use); the parent test
    calls it exactly once."""
    def holds() -> bool:
        tree = _syntax(raw)
        binds = [node for node in tree.body if isinstance(node, ast.Assign) and len(node.targets) == 1
                 and isinstance(node.targets[0], ast.Name) and node.targets[0].id == "READINESS_NODE"]
        proof, parent = _top_function(tree, PROOF_FUNCTION), _top_function(tree, PARENT_TEST)
        in_proof = [node for node in ast.walk(proof) if isinstance(node, ast.Constant) and node.value == PROOF_MODE]
        calls = [node for node in ast.walk(parent) if isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
                 and node.func.id == PROOF_FUNCTION]
        return (len(binds) == 1 and isinstance(binds[0].value, ast.Constant) and binds[0].value.value == READINESS_NODE
                and len(in_proof) == 1 and len(calls) == 1)
    _bound(holds, "the parent test proves its readiness step from the session's readiness node")


def check_weights(raw: Any) -> None:
    """V2, C2: the table is a JSON object mapping test-file paths to finite non-negative seconds."""
    table = _parsed(raw)
    _bound(lambda: type(table) is dict and len(table) > 0
           and all(type(key) is str and key.startswith(WEIGHT_PREFIXES) and key.endswith(".py")
                   and type(value) in (int, float) and value == value and 0 <= value < float("inf")
                   for key, value in table.items()),
           "the weights table maps test files to finite non-negative seconds")


def check_share_point(raw: Any, owner: Any, attribute: Any, helper: Any, test: Any) -> None:
    """V2, C3: the sharing helper is defined once at module level and used exactly once in the file: as the value
    monkeypatch.setattr(owner, attribute, helper(...)) installs inside its one test, which takes the monkeypatch fixture
    (so pytest restores the original after the test). Other tests' own patches of the same attribute are not sharing."""
    def holds() -> bool:
        tree = _syntax(raw)
        function = _top_function(tree, test)
        uses = [node for node in ast.walk(tree) if isinstance(node, ast.Name) and node.id == helper]
        installs = [node for node in ast.walk(function) if isinstance(node, ast.Call)
                    and isinstance(node.func, ast.Attribute) and node.func.attr == "setattr"
                    and isinstance(node.func.value, ast.Name) and node.func.value.id == "monkeypatch"
                    and len(node.args) == 3 and isinstance(node.args[0], ast.Name) and node.args[0].id == owner
                    and isinstance(node.args[1], ast.Constant) and node.args[1].value == attribute
                    and isinstance(node.args[2], ast.Call) and isinstance(node.args[2].func, ast.Name)
                    and node.args[2].func.id == helper]
        return (_top_function(tree, helper) is not None and len(uses) == 1 and len(installs) == 1
                and "monkeypatch" in [arg.arg for arg in function.args.args])
    _bound(holds, "the sharing helper is installed once, through monkeypatch, inside its one test: %s.%s"
           % (owner, attribute))


def check_key_order(raw: Any) -> None:
    """V2, C3: the schema_errors key is JSON in each value's own insertion order: its key function serializes with
    json.dumps exactly once and never sorts (no sort_keys, no sorted call)."""
    def holds() -> bool:
        function = _top_function(_syntax(raw), KEY_FUNCTION)
        dumps = [node for node in ast.walk(function) if isinstance(node, ast.Call)
                 and isinstance(node.func, ast.Attribute) and node.func.attr == "dumps"]
        sorts = [node for node in ast.walk(function) if isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
                 and node.func.id == "sorted"]
        return (len(dumps) == 1 and not [kw for kw in dumps[0].keywords if kw.arg == "sort_keys"] and not sorts)
    _bound(holds, "the schema_errors key keeps each value's own key order")


def validate_cuts() -> None:
    """V2 over the three cuts' reviewed bytes."""
    check_readiness_proof(_verified(READINESS_PATH))
    check_weights(_verified(WEIGHTS_PATH))
    for path, owner, attribute, helper, test in SHARE_POINTS:
        check_share_point(_verified(path), owner, attribute, helper, test)
    check_key_order(_verified(KEY_PATH))


def check_registry(raw: Any, briefs: Any) -> None:
    """V3: the registry differs from the base by exactly this packet's one rider, appended last and pointing at the
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
           "the registry differs from the base by exactly the MET-PERF-045 packet rider, pinning the generic packet "
           "brief")


def validate_registry() -> None:
    """V3 over briefs.json and the generic packet brief."""
    check_registry(_verified(REGISTRY_PATH), {PACKET_BRIEF: _verified(PACKET_BRIEF)})


def check_neighbour(path: Any, raw: Any) -> None:
    """V4: a neighbour's bytes are its base bytes (the digest pinned for it)."""
    _bound(lambda: path in NEIGHBOURS and type(raw) is bytes and digest(raw) == ERA_SHA256[path],
           "the neighbour is unchanged since the base: " + str(path))


def validate_neighbours() -> None:
    """V4 over the five neighbours, read through the era."""
    for path in NEIGHBOURS:
        check_neighbour(path, _verified(path))


def validate_met_perf_045(packets: dict[str, Any]) -> None:
    """Every reviewed byte first; then V1 (the packet's files), V2 (the cuts), V3 (the registry) and V4 (the
    neighbours); last, this layer's canonical hunks."""
    for path in ERA_SHA256:
        _verified(path)
    validate_packet_files()
    validate_cuts()
    validate_registry()
    validate_neighbours()
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
            == record["validatorNormalizedSha256"], "quiet host cuts validator drift")
    paths = sorted((ROOT / "task-packets").glob("*.yaml"))
    old = set(record["baselinePackets"])
    require(len(paths) == 296
            and {path.stem for path in paths} == old | {NEW_PACKET, successor.NEW_PACKET, *successor.PRODUCT_PACKETS, successor.successor.NEW_PACKET, *successor.successor.PRODUCT_PACKETS, successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.NEW_PACKET, *successor.successor.successor.successor.successor.successor.PRODUCT_PACKETS, successor.successor.successor.successor.successor.successor.successor.NEW_PACKET, *successor.successor.successor.successor.successor.successor.successor.PRODUCT_PACKETS, successor.successor.successor.successor.successor.successor.successor.successor.NEW_PACKET},
            "closed 296-packet catalog retaining the 281-packet checkpoint")
    packets = {}
    for path in paths:
        if path.stem in (successor.NEW_PACKET, successor.successor.NEW_PACKET, *successor.successor.PRODUCT_PACKETS, successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.NEW_PACKET, *successor.successor.successor.successor.successor.successor.PRODUCT_PACKETS, successor.successor.successor.successor.successor.successor.successor.NEW_PACKET, *successor.successor.successor.successor.successor.successor.successor.PRODUCT_PACKETS, successor.successor.successor.successor.successor.successor.successor.successor.NEW_PACKET):
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
            "closed source-only quiet-host-cuts packet and inherited commands")
    require(len(packet["allowedPaths"]) == len(set(packet["allowedPaths"]))
            and set(packet["allowedPaths"]) == set(record["changedFiles"])
            | set(record["newFiles"]) | {AUTHORITY_PATH, VALIDATOR_PATH,
                                         "task-packets/" + NEW_PACKET + ".yaml"},
            "unreviewed or omitted quiet-host-cuts packet path")
    for path, rule in record["changedFiles"].items():
        current = successor.historical_bytes(path, regular_bytes(path))
        require(digest(current) == rule["afterSha256"]
                and digest(historical_bytes(path, current)) == rule["beforeSha256"],
                "unreviewed current source: " + path)
    for path, expected in record["newFiles"].items():
        require(digest(successor.historical_bytes(path, regular_bytes(path))) == expected,
                "new source drift: " + path)
    validate_met_perf_045(packets)


if __name__ == "__main__":
    validate()
    print("Quiet-host cuts valid: 296 current specifications at slot 277; 281-packet checkpoint and exact 280-packet predecessor; contract reviewed.")
