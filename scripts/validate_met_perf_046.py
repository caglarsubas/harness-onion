#!/usr/bin/env python3
"""Validate MET-PERF-046 (PERF-046): eight parallel-suite workers in a K = 0 step (V1-V7: the worker-count line by syntax tree; the suite, its test pin and its page against their 279 bytes; the frozen files; the record against its restatement; no stale six-worker statement)."""
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
    import validate_authority_map as successor
except ImportError:
    from scripts.safe_yaml import safe_load
    from scripts import validate_authority_map as successor


ROOT = Path(__file__).resolve().parents[1]
AUTHORITY_PATH = "architecture/parallel-workers-authority.json"
AUTHORITY_SHA256 = "e523c788f336febde04fbb1e91d25b4f6ae74c15e9debe26760669d82049fe87"
VALIDATOR_PATH = "scripts/validate_met_perf_046.py"
BASE_COMMIT = "afebb72bcf4373622eca873963ee26bb654e2346"
NEW_PACKET = "MET-PERF-046"
PREVIOUS_PACKET = "MET-VERIFY-006"
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
            require(key not in result, "duplicate parallel-workers authority member")
            result[key] = value
        return result

    def no_constant(_value: str) -> Any:
        raise ValueError("nonfinite parallel-workers authority number")

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
        require(digest(raw) == AUTHORITY_SHA256, "parallel workers history authority digest")
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
    }, "closed parallel workers history authority")
    require(value["schemaVersion"] == "harness.planeon.ai/parallel-workers-authority/v1"
            and value["authorityPacket"] == NEW_PACKET
            and value["acceptedBase"] == BASE_COMMIT
            and type(value["baselinePackets"]) is dict
            and len(value["baselinePackets"]) == 286
            and NEW_PACKET not in value["baselinePackets"]
            and type(value["changedFiles"]) is dict
            and type(value["newFiles"]) is dict
            and _sha(value["packetSha256"])
            and _sha(value["validatorNormalizedSha256"]),
            "accepted 286-packet base")
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
    # An exact 286-era byte string is already older than the successor layer.
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


# MET-PERF-046 (PERF-046; the owner's MON-OWNER-K8-G1 and the lane monitor's owner-delegated rulings MON-280-START,
# MON-280-PLAN-OK and MON-280-CR1-RULINGS) raises the parallel suite's workers from 6 to 8 in MET-PERF-039's form, in a
# K = 0 step: this layer binds no PRODUCT_PACKETS, so the catalog holds C = 287 packets at slot S = 280. The change is
# one line of ci/parallel_suite.py (WORKERS = 6 -> 8), its one live test pin (tests/test_parallel_suite.py line 817) and
# its current-status page line (docs/alpha-2/PARALLEL_SUITE_PERF035.md line 20), recorded in
# architecture/parallel-workers/workers.json. Repository bytes are read only through reviewed_bytes, so a later bridged
# successor projects its own edits away first; a path outside this era is refused before it is read and every era file
# is bound by digest on every read. Each refusal is a pure check over the values read, so every one has a failing case on
# plain data. Checked here: V1, WORKERS by the syntax tree (exactly one module-level assignment, the int 8); V2, the
# suite differs from its 279 bytes only in the worker-count line, and this layer's inverse gives those bytes back; V3,
# the test file differs from its 279 bytes plus this step's own chain edits (the count bump and the one deeper successor
# line, which a later successor projects away) only in line 817's comparison; V4, the page differs from its 279 bytes
# only in line 20, which is the exact new text; V5, the frozen files are their base bytes; V6, the record equals this
# layer's restatement (written from the record at build time), whole, canonical and type-strict, and the restatement
# states this change (the
# owner-decision ids, the suite's before digest and the weights digest); V7, no stale six-worker statement in the test
# file or the page. Last, this layer's own inverse hunks are the canonical byte-minimal ones (MET-PERF-040's rule).
SUITE_PATH = "ci/parallel_suite.py"
TEST_PATH = "tests/test_parallel_suite.py"
PAGE_PATH = "docs/alpha-2/PARALLEL_SUITE_PERF035.md"
RECORD_PATH = "architecture/parallel-workers/workers.json"
README_PATH = "architecture/parallel-workers/README.md"
WORKERS_AFTER = 8
# V2-V4: the 279 bytes each changed file is checked against (the test file's with this step's chain edits).
SUITE_BEFORE_SHA256 = "4fe4e24951c6a4f023361f9e840e8343a68e5af713754ff7acdf523e475495d5"
TEST_BEFORE_SHA256 = "3651c1b347d717338e30930e21a8a6b0c5f288e3169aa6610a9cad693b0ac93d"
PAGE_BEFORE_SHA256 = "fca0042bb87856ff88926c7a044abb7afd692c9c589f4df391be85f43735d8e8"
L1_BEFORE, L1_AFTER = b"\nWORKERS = 6\n", b"\nWORKERS = 8\n"
L2_BEFORE, L2_AFTER = b"    assert SUITE.WORKERS == 6\n", b"    assert SUITE.WORKERS == 8\n"
L3_BEFORE = b"  - The parent collects as usual and assigns whole test files to 6 worker processes (MET-PERF-039; 4 before), by the\n"
L3_AFTER = b"  - The parent collects as usual and assigns whole test files to 8 worker processes (MET-PERF-046; 6 before), by the\n"
L3_LINE = 20
# V5: the frozen files (one failing case each), each pinned in ERA_SHA256 by its base bytes.
FROZEN_PATHS = (
    "ci/parallel_suite_weights.json",
    "architecture/load-deadlines/limits.json",
    "architecture/load-deadlines/README.md",
    "architecture/pytest-headroom/workers.json",
    "architecture/pytest-headroom/README.md",
    "architecture/pytest-headroom-authority.json",
    ".github/workflows/verify.yml",
    "ci/linux-runner/launcher.py",
)
# V6: the restatement, written from the record at build time (make_layer280); the decisions and the digests it must
# state.
RESTATED_RECORD = r'''{"carried":[],"change":{"after":8,"afterSha256":"88734d3c01b2712c88baa118f7da5e75f6a9be3bb12c331e2c6edc6fbf86d026","before":6,"beforeSha256":"4fe4e24951c6a4f023361f9e840e8343a68e5af713754ff7acdf523e475495d5","name":"parallelSuiteWorkers","onlyLineChanged":{"after":"WORKERS = 8","before":"WORKERS = 6"},"path":"ci/parallel_suite.py"},"evidenceClass":"SOURCE_DELTA_ONLY","matchingFiles":[{"after":"    assert SUITE.WORKERS == 8","before":"    assert SUITE.WORKERS == 6","path":"tests/test_parallel_suite.py"},{"after":"  - The parent collects as usual and assigns whole test files to 8 worker processes (MET-PERF-046; 6 before), by the","before":"  - The parent collects as usual and assigns whole test files to 6 worker processes (MET-PERF-039; 4 before), by the","path":"docs/alpha-2/PARALLEL_SUITE_PERF035.md"}],"measurements":{"caveat":"The K 8 arm ran with 131 failing END events (the six-worker pins this packet moves), so its worker phase need not equal a passing K 8 run's; one run per arm. Peak memory was not sampled, so no peakTreeRssMiB is recorded. The dry run of this packet's head measures the result.","main":"bd882493488190747b5154e502265c12a9c251f3","method":"argv 63 of MET-VERIFY-006's head on three fresh clones, in the order K 6, K 8, K 6; the K 8 clone carried one counted edit (WORKERS = 6 -> 8), never committed","runOrder":[6,8,6],"runs":[{"arm":"A1","failedEndEvents":0,"imbalanceSeconds":16.9,"load1Mean":8.32,"summedEndSeconds":3003.8,"wallSeconds":542.98,"workerPhaseSeconds":517.5,"workers":6},{"arm":"B","failedEndEvents":131,"imbalanceSeconds":19.6,"load1Mean":12.42,"summedEndSeconds":3620.1,"wallSeconds":498.44,"workerPhaseSeconds":472.2,"workers":8},{"arm":"A2","failedEndEvents":0,"imbalanceSeconds":20.3,"load1Mean":10.78,"summedEndSeconds":3122.3,"wallSeconds":566.73,"workerPhaseSeconds":540.7,"workers":6}],"runsPerWorkerCount":1,"sixWorkerSpreadSeconds":23.2,"summarySha256":"85ab23bff6d46f109b9ddc0e987690905d1abb558b2a6207281565e82d51e14f","workerPhaseCutPercent":-10.8,"workerPhaseCutSeconds":-56.9},"ownerDecisions":[{"date":"2026-11-04","decision":"after the A/B the owner chose \"Adopt 8 workers (Recommended)\" and Q-CHAIN-GUARANTEE (a), G1 signed checkpoint. PERF-046, packet MET-PERF-046 at slot 280 right after 279 merges: WORKERS 6 → 8 plus the 131 pins.","id":"MON-OWNER-K8-G1","source":"lane monitor (relayed owner decision)"},{"date":"2026-11-05","decision":"owner's word, 2026-11-05: \"Resume R00 on slot 280 (Recommended)\". Slot 280 is MET-PERF-046 (roadmap PERF-046, lock 28): WORKERS 6 → 8 plus the 131 six-worker pins, measured by the K6/K8/K6 A/B 85ab23bf. 279's full weights refresh stays; no other change to the 900 s deadline, the 1,170 s budget or the load gate.","id":"MON-280-START","source":"lane monitor (relayed owner decision)"}],"packet":"MET-PERF-046","schemaVersion":"harness.planeon.ai/parallel-workers/v1","unchanged":[{"name":"parallelSuiteWorkerDeadlineSeconds","path":"ci/parallel_suite.py","value":900},{"name":"parallelSuiteParentNodes","path":"ci/parallel_suite.py","value":"the three MET-PERF-037 parent nodes"},{"name":"parallelSuiteSerialEnvironment","path":"ci/parallel_suite.py","value":"PLANEON_PARALLEL_SUITE_SERIAL"},{"name":"parallelSuiteWeights","path":"ci/parallel_suite_weights.json","sha256":"8e4050ce8a6a88faa357bb97e6b858003c27951bf0b71249dea68dfd3a2a1a32"},{"name":"failClosedAccounting","path":"ci/parallel_suite.py","value":"exact assignment, ownership of every report and warning, one setup and teardown per node and a call iff setup passed, every line decoded, every worker exits 0 or 1 with a failure before the deadline"},{"name":"acceptanceArgv","path":"task-packets/MET-VERIFY-006.yaml","value":"the 64 inherited commands"},{"from":"budgetSeconds: launcherSetupSeconds 60 + argvBeforeSuiteSeconds 120 + parallelSuiteDeadlineSeconds 900 + parentNodesSeconds 90, under launcherCapSeconds 1200","name":"verifyBudgetSeconds","path":"architecture/load-deadlines/limits.json","sha256":"f9c152fd4b7e074e5b63b1649e35e2cc2c651060c1ae48d91c078b8690f0f11f","value":1170},{"name":"loadGate","path":"architecture/load-deadlines/limits.json","sha256":"f9c152fd4b7e074e5b63b1649e35e2cc2c651060c1ae48d91c078b8690f0f11f","value":"the verifier bundle's pre-claim load gate; installed outside this repository; its in-repository record is verifierBundle.loadGate"},{"name":"maxProblems","path":"ci/parallel_suite.py","value":50}]}'''
RESTATED_DECISIONS = ("MON-OWNER-K8-G1", "MON-280-START")
WEIGHTS_SHA256 = "8e4050ce8a6a88faa357bb97e6b858003c27951bf0b71249dea68dfd3a2a1a32"
# V7: statements that would leave a six-worker claim behind.
STALE = {TEST_PATH: (b"SUITE.WORKERS == 6",), PAGE_PATH: (b"6 worker processes",)}
# Every file this era's check reads, with its digest.
ERA_SHA256 = MappingProxyType({
    ".github/workflows/verify.yml": "b6b8c87fc5f9615c193594c7a861a59e55022acfdb1dc9970c903af9fca22dee",
    "architecture/load-deadlines/README.md": "36ee4dd227603e6ebef164a20555c30fabfbd59c0c0dbbd2526579478dcb81c1",
    "architecture/load-deadlines/limits.json": "f9c152fd4b7e074e5b63b1649e35e2cc2c651060c1ae48d91c078b8690f0f11f",
    "architecture/parallel-workers/README.md": "17944ae77d3a1a4392e302c22478c104ac0f61bf91409c650cf730a98c2a2286",
    "architecture/parallel-workers/workers.json": "52b97272a1e517649434b816eff0671abb0a47fb39617abee71eaf0b4ca07465",
    "architecture/pytest-headroom-authority.json": "87c5201fb0dd559584df17c83f3d24536d7fadc04524f22936559978bcf2d634",
    "architecture/pytest-headroom/README.md": "c2ab3e01fbf5bae3a78a773a796eecb59daea4dcb0711d084cb92ee3bac767a0",
    "architecture/pytest-headroom/workers.json": "d0c2ebf965377756afda7da42dd8117efbdd67c0ffc10cb8ef70770efac67259",
    "ci/linux-runner/launcher.py": "8055194a640ddadc9997fdd36bb8e82f3c229b844f955832eca1b16ffa97c2a3",
    "ci/parallel_suite.py": "88734d3c01b2712c88baa118f7da5e75f6a9be3bb12c331e2c6edc6fbf86d026",
    "ci/parallel_suite_weights.json": "8e4050ce8a6a88faa357bb97e6b858003c27951bf0b71249dea68dfd3a2a1a32",
    "docs/alpha-2/PARALLEL_SUITE_PERF035.md": "b55440294af0ab7a8926cbbd6f5e62b8a50ce86d4469f83f1d47663f9c1e5372",
    "tests/test_parallel_suite.py": "8d91d0518d6ae99599b0c38abca3e601fc3da48e821a5a83e0e8f965d51461b2",
})


def reviewed_bytes(path: str) -> bytes:
    """This packet's reviewed bytes of path; a bridged successor projects newer bytes back first."""
    return successor.historical_bytes(path, regular_bytes(path))


def _era_bytes(path: Any, raw: Any) -> bytes:
    """An era file's bytes, checked against its era digest; a path outside the era is refused."""
    expected = ERA_SHA256.get(path) if type(path) is str else None
    require(expected is not None, "MET-PERF-046 reviewed bytes are bound: " + str(path))
    require(type(raw) is bytes and digest(raw) == expected, "unreviewed PARALLEL-WORKERS source: " + path)
    return raw


def _verified(path: str) -> bytes:
    """reviewed_bytes, checked against its era digest on every read; a path outside the era is refused before it is
    read."""
    require(type(path) is str and path in ERA_SHA256, "MET-PERF-046 reviewed bytes are bound: " + str(path))
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


def check_workers(raw: Any) -> None:
    """V1: exactly one module-level assignment to WORKERS, and its value is the int 8."""
    tree = _syntax(raw)

    def holds() -> bool:
        found = [node for node in tree.body if isinstance(node, ast.Assign)
                 and any(isinstance(target, ast.Name) and target.id == "WORKERS" for target in node.targets)]
        value = found[0].value if len(found) == 1 else None
        return (len(found) == 1 and len(found[0].targets) == 1 and isinstance(value, ast.Constant)
                and type(value.value) is int and value.value == WORKERS_AFTER)
    _bound(holds, "the suite assigns WORKERS exactly once, to eight")


def check_suite(raw: Any, inverse: Any) -> None:
    """V2: the suite's only difference from its 279 bytes is the worker-count line, and this layer's own inverse gives
    those bytes back."""
    _bound(lambda: raw.count(L1_AFTER) == 1 and raw.count(L1_BEFORE) == 0
           and digest(raw.replace(L1_AFTER, L1_BEFORE, 1)) == SUITE_BEFORE_SHA256
           and type(inverse) is bytes and digest(inverse) == SUITE_BEFORE_SHA256,
           "exactly the worker-count line changed in the suite")


def check_test_pin(raw: Any) -> None:
    """V3: the test file's only difference from its 279 bytes (with this step's chain edits) is line 817's comparison."""
    _bound(lambda: raw.count(L2_AFTER) == 1 and raw.count(L2_BEFORE) == 0
           and digest(raw.replace(L2_AFTER, L2_BEFORE, 1)) == TEST_BEFORE_SHA256,
           "the parallel-suite test pins eight workers and changes nothing else")


def check_page(raw: Any) -> None:
    """V4: the page's only difference from its 279 bytes is line 20, which is the exact new text."""
    _bound(lambda: raw.count(L3_AFTER) == 1 and raw.split(b"\n")[L3_LINE - 1] + b"\n" == L3_AFTER
           and digest(raw.replace(L3_AFTER, L3_BEFORE, 1)) == PAGE_BEFORE_SHA256,
           "the parallel-suite page states eight workers on line 20 and changes nothing else")


def check_frozen(path: Any, raw: Any) -> None:
    """V5: a frozen file's bytes are its base bytes (the digest pinned for it)."""
    _bound(lambda: path in FROZEN_PATHS and type(raw) is bytes and digest(raw) == ERA_SHA256[path],
           "the frozen file stays byte-identical: " + str(path))


def check_restatement(restated: Any) -> None:
    """V6, the restatement's own check: it states this change's decisions, the suite's before digest and the weights."""
    value = _parsed(restated)
    _bound(lambda: [entry["id"] for entry in value["ownerDecisions"]] == list(RESTATED_DECISIONS)
           and value["change"]["beforeSha256"] == SUITE_BEFORE_SHA256 and value["change"]["after"] == WORKERS_AFTER
           and [entry["sha256"] for entry in value["unchanged"] if entry["name"] == "parallelSuiteWeights"]
           == [WEIGHTS_SHA256],
           "the restatement states this change: the decisions, the suite's before digest and the weights")


def check_record(raw: Any, restated: Any) -> None:
    """V6: the record equals the restatement, whole, canonical and type-strict."""
    record, value = _parsed(raw), _parsed(restated)
    _bound(lambda: type(record) is dict and type(value) is dict and canonical(record) == canonical(value),
           "the closed parallel-workers record equals its restatement")


def check_stale(path: Any, raw: Any) -> None:
    """V7: no stale six-worker statement in the test file or the page."""
    _bound(lambda: path in STALE and type(raw) is bytes and not any(raw.count(word) for word in STALE[path]),
           "no stale six-worker statement: " + str(path))


def validate_met_perf_046(packets: dict[str, Any]) -> None:
    """Every reviewed byte first; then V1-V7; last, this layer's canonical hunks."""
    for path in ERA_SHA256:
        _verified(path)
    suite = _verified(SUITE_PATH)
    check_workers(suite)
    check_suite(suite, _undo_this_layer(SUITE_PATH, suite))
    check_test_pin(_verified(TEST_PATH))
    check_page(_verified(PAGE_PATH))
    for path in FROZEN_PATHS:
        check_frozen(path, _verified(path))
    check_restatement(RESTATED_RECORD.encode("utf-8"))
    check_record(_verified(RECORD_PATH), RESTATED_RECORD.encode("utf-8"))
    for path in STALE:
        check_stale(path, _verified(path))
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
            == record["validatorNormalizedSha256"], "parallel workers validator drift")
    paths = sorted((ROOT / "task-packets").glob("*.yaml"))
    old = set(record["baselinePackets"])
    require(len(paths) == 300
            and {path.stem for path in paths} == old | {NEW_PACKET, successor.NEW_PACKET, successor.successor.NEW_PACKET, successor.successor.successor.NEW_PACKET, *successor.successor.successor.PRODUCT_PACKETS, successor.successor.successor.successor.NEW_PACKET, *successor.successor.successor.successor.PRODUCT_PACKETS, successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.successor.successor.NEW_PACKET, *successor.successor.successor.successor.successor.successor.successor.successor.PRODUCT_PACKETS},
            "closed 300-packet catalog retaining the 287-packet checkpoint")
    packets = {}
    for path in paths:
        if path.stem in (successor.NEW_PACKET, successor.successor.NEW_PACKET, successor.successor.successor.NEW_PACKET, *successor.successor.successor.PRODUCT_PACKETS, successor.successor.successor.successor.NEW_PACKET, *successor.successor.successor.successor.PRODUCT_PACKETS, successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.successor.successor.NEW_PACKET, *successor.successor.successor.successor.successor.successor.successor.successor.PRODUCT_PACKETS):
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
            "closed source-only parallel-workers packet and inherited commands")
    require(len(packet["allowedPaths"]) == len(set(packet["allowedPaths"]))
            and set(packet["allowedPaths"]) == set(record["changedFiles"])
            | set(record["newFiles"]) | {AUTHORITY_PATH, VALIDATOR_PATH,
                                         "task-packets/" + NEW_PACKET + ".yaml"},
            "unreviewed or omitted parallel-workers packet path")
    for path, rule in record["changedFiles"].items():
        current = successor.historical_bytes(path, regular_bytes(path))
        require(digest(current) == rule["afterSha256"]
                and digest(historical_bytes(path, current)) == rule["beforeSha256"],
                "unreviewed current source: " + path)
    for path, expected in record["newFiles"].items():
        require(digest(successor.historical_bytes(path, regular_bytes(path))) == expected,
                "new source drift: " + path)
    validate_met_perf_046(packets)


if __name__ == "__main__":
    validate()
    print("Parallel workers valid: 300 current specifications at slot 280; 287-packet checkpoint and exact 286-packet predecessor; contract reviewed.")
