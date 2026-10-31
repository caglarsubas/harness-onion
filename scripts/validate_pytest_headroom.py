#!/usr/bin/env python3
"""Validate the MET-PERF-039 six-worker parallel suite and the exact 238-to-237 projection."""
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
    import validate_selinux_matrix_v3 as successor
except ImportError:
    from scripts.safe_yaml import safe_load
    from scripts import validate_selinux_matrix_v3 as successor


ROOT = Path(__file__).resolve().parents[1]
AUTHORITY_PATH = "architecture/pytest-headroom-authority.json"
AUTHORITY_SHA256 = "87c5201fb0dd559584df17c83f3d24536d7fadc04524f22936559978bcf2d634"
VALIDATOR_PATH = "scripts/validate_pytest_headroom.py"
BASE_COMMIT = "e7516160468c213862b337b344d240fde5f7328c"
NEW_PACKET = "MET-PERF-039"
PREVIOUS_PACKET = "MET-ENFORCE-027"
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
            require(key not in result, "duplicate pytest-headroom authority member")
            result[key] = value
        return result

    def no_constant(_value: str) -> Any:
        raise ValueError("nonfinite pytest-headroom authority number")

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
        require(digest(raw) == AUTHORITY_SHA256, "pytest headroom history authority digest")
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
    }, "closed pytest headroom history authority")
    require(value["schemaVersion"] == "harness.planeon.ai/pytest-headroom-authority/v1"
            and value["authorityPacket"] == NEW_PACKET
            and value["acceptedBase"] == BASE_COMMIT
            and type(value["baselinePackets"]) is dict
            and len(value["baselinePackets"]) == 237
            and NEW_PACKET not in value["baselinePackets"]
            and type(value["changedFiles"]) is dict
            and type(value["newFiles"]) is dict
            and _sha(value["packetSha256"])
            and _sha(value["validatorNormalizedSha256"]),
            "accepted 237-packet base")
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
    # An exact 237-era byte string is already older than the successor layer.
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


# MET-PERF-039 (owner decision Q-PERF39-1 (a), 2026-10-15, via the lane monitor) raises the parallel suite's worker count
# from 4 to 6 to restore argv 63's headroom under the 900 s worker deadline. Nothing else in the suite changes: the
# deadline, the accounting, the parent nodes, the serial rule and the weights stay as they are. Repository bytes are
# read only through reviewed_bytes, so a later bridged successor projects its own edits away first. Every input of this
# era is bound by digest before it is parsed or executed. The suite is executed from those bytes, this layer's own
# inverse must give back the 237-packet suite with exactly the one constant line different, and the record is restated
# here independently of the file it checks, which must equal it exactly (type-strict, through canonical JSON).
PARALLEL_SUITE = "ci/parallel_suite.py"
SUITE_TEST = "tests/test_parallel_suite.py"
# The current-status page states the worker count, as MET-PERF-038 updated it for the deadline (review S1-2).
SUITE_PAGE = "docs/alpha-2/PARALLEL_SUITE_PERF035.md"
WEIGHTS = "ci/parallel_suite_weights.json"
RECORD = "architecture/pytest-headroom/workers.json"
README = "architecture/pytest-headroom/README.md"
# The weights and the PERF-038 limits record stay byte-identical (the owner did not refresh the weights).
FROZEN_PATHS = ("ci/parallel_suite_weights.json", "architecture/load-deadlines/limits.json",
                "architecture/load-deadlines/README.md")
ERA_SHA256 = MappingProxyType({
    "architecture/pytest-headroom/README.md": "c2ab3e01fbf5bae3a78a773a796eecb59daea4dcb0711d084cb92ee3bac767a0",
    "architecture/pytest-headroom/workers.json": "d0c2ebf965377756afda7da42dd8117efbdd67c0ffc10cb8ef70770efac67259",
    "ci/parallel_suite.py": "4fe4e24951c6a4f023361f9e840e8343a68e5af713754ff7acdf523e475495d5",
    "tests/test_parallel_suite.py": "1d8af26e73282f6e593cb7e239cf1ba1959838b140ceca697941757d28a795ea",
    "docs/alpha-2/PARALLEL_SUITE_PERF035.md": "fca0042bb87856ff88926c7a044abb7afd692c9c589f4df391be85f43735d8e8",
    "ci/parallel_suite_weights.json": "2c1b27f6281e996accbcbc43169dec2041676f1831b0c2e02cb8e09a3395ec3f",
})
WORKERS_BEFORE, WORKERS_AFTER, DEADLINE_SECONDS = 4, 6, 900
SUITE_BEFORE_SHA256 = "14a7dd6db3d4f1b9b97408ffad49c5c977ce8813c81d975ca8dfe9d919c26b34"
PARENT_NODES_EXPECTED = frozenset({
    "tests/linux_runner/test_build_and_predecessors.py::test_full_predecessor_suites_and_validators_remain_green",
    "tests/linux_runner/test_build_and_predecessors.py::test_byte_identical_package_and_source_inventory",
    "tests/linux_runner/test_isolation.py::test_real_integration_is_not_faked_on_development_host",
})
HEADROOM = {'schemaVersion': 'harness.planeon.ai/pytest-headroom/v1',
 'packet': 'MET-PERF-039',
 'evidenceClass': 'SOURCE_DELTA_ONLY',
 'change': {'name': 'parallelSuiteWorkers',
            'path': 'ci/parallel_suite.py',
            'before': 4,
            'after': 6,
            'beforeSha256': '14a7dd6db3d4f1b9b97408ffad49c5c977ce8813c81d975ca8dfe9d919c26b34',
            'afterSha256': '4fe4e24951c6a4f023361f9e840e8343a68e5af713754ff7acdf523e475495d5',
            'onlyLineChanged': {'before': 'WORKERS = 4', 'after': 'WORKERS = 6'}},
 'matchingFiles': [{'path': 'tests/test_parallel_suite.py',
                    'before': '    assert SUITE.WORKERS == 4',
                    'after': '    assert SUITE.WORKERS == 6'},
                   {'path': 'docs/alpha-2/PARALLEL_SUITE_PERF035.md',
                    'before': '  - The parent collects as usual and assigns whole test files to 4 worker '
                              'processes, by the pinned weights in',
                    'after': '  - The parent collects as usual and assigns whole test files to 6 worker processes '
                             '(MET-PERF-039; 4 before), by the'}],
 'unchanged': [{'name': 'parallelSuiteWorkerDeadlineSeconds', 'path': 'ci/parallel_suite.py', 'value': 900},
               {'name': 'parallelSuiteParentNodes',
                'path': 'ci/parallel_suite.py',
                'value': 'the three MET-PERF-037 parent nodes'},
               {'name': 'parallelSuiteSerialEnvironment',
                'path': 'ci/parallel_suite.py',
                'value': 'PLANEON_PARALLEL_SUITE_SERIAL'},
               {'name': 'parallelSuiteWeights',
                'path': 'ci/parallel_suite_weights.json',
                'sha256': '2c1b27f6281e996accbcbc43169dec2041676f1831b0c2e02cb8e09a3395ec3f'},
               {'name': 'failClosedAccounting',
                'path': 'ci/parallel_suite.py',
                'value': 'exact assignment, ownership of every report and warning, one setup and teardown per node '
                         'and a call iff setup passed, every line decoded, every worker exits 0 or 1 with a '
                         'failure before the deadline'},
               {'name': 'acceptanceArgv',
                'path': 'task-packets/MET-ENFORCE-027.yaml',
                'value': 'the 64 inherited commands'}],
 'measurements': {'main': 'e7516160468c213862b337b344d240fde5f7328c',
                  'method': "argv 63 of MET-ENFORCE-027 on a clean checkout; the parallel suite's worker count set "
                            'for the top-level session only by an out-of-tree pytest plugin (no repository byte '
                            'change)',
                  'runs': [{'workers': 4,
                            'wallSeconds': 627.1,
                            'summedTestSeconds': 2254.6,
                            'peakTreeRssMiB': 1514,
                            'load1Mean': 8.51,
                            'load1Max': 10.53,
                            'passed': 11252,
                            'failed': 0},
                           {'workers': 6,
                            'wallSeconds': 361.0,
                            'summedTestSeconds': 1774.6,
                            'peakTreeRssMiB': 2035,
                            'load1Mean': 9.17,
                            'load1Max': 11.55,
                            'passed': 11252,
                            'failed': 0},
                           {'workers': 8,
                            'wallSeconds': 324.9,
                            'summedTestSeconds': 2030.8,
                            'peakTreeRssMiB': 2471,
                            'load1Mean': 10.48,
                            'load1Max': 14.04,
                            'passed': 11252,
                            'failed': 0}],
                  'runOrder': [4, 6, 8],
                  'runsPerWorkerCount': 1,
                  'caveat': 'The four-worker run ran first, and during its first ~300 s every file ran about 1.7 '
                            'times as long as in the six-worker run (host state, not the plan). Replaying the '
                            "six-worker run's per-file times through the suite's planner at four workers gives an "
                            'estimated 455-512 s, so six workers save about 21-29%, not 42% (source review round '
                            '1, S1-1).',
                  'estimatedFourWorkerSecondsSameConditions': {'low': 455, 'high': 512},
                  'pinnedWeightsImbalanceSixWorkers': {'slowestWorkerSeconds': 324.6,
                                                       'evenSplitSeconds': 290.8,
                                                       'parentNodesExcluded': True,
                                                       'unweightedFiles': 22}},
 'carried': [{'id': 'WEIGHTS-REFRESH',
              'decision': 'Q-PERF39-1-CONFIRM',
              'what': 'refresh ci/parallel_suite_weights.json from measured per-file times, including the 22 files '
                      'without a pinned weight',
              'how': 'a later, separate ci/ change'}],
 'ownerDecisions': [{'id': 'Q-PERF39-1',
                     'date': '2026-10-15',
                     'source': 'lane monitor (relayed owner decision)',
                     'decision': 'Owner decision Q-PERF39-1 = (a), 6 workers, 2026-10-15. MET-PERF-039 (slot 238): '
                                 'ci/parallel_suite.py WORKERS 4 → 6 plus the matching tests. Every fail-closed '
                                 'rule stays (900 s deadline, worker-exit accounting, incomplete-node refusal, '
                                 'serial fallback). Weights are not refreshed.'},
                    {'id': 'Q-PERF39-1-CONFIRM',
                     'date': '2026-10-15',
                     'source': 'lane monitor (relayed owner decision)',
                     'decision': 'The owner confirms, after seeing your correction: "proceed with 6 workers, no '
                                 'weight refresh" (2026-10-15). Record it with Q-PERF39-1. Add the weight refresh, '
                                 'including the 22 unweighted files, as a carried follow-up: a later separate ci/ '
                                 'change.'},
                    {'id': 'Q-PERF39-1-CONFIRM-2',
                     'date': '2026-10-15',
                     'source': 'lane monitor (relayed owner decision)',
                     'decision': 'The owner has seen the corrected gain (21-29%) and the 1200 s cap note and says '
                                 '"proceed with 6 workers" (2026-10-15).'}]}


def reviewed_bytes(path: str) -> bytes:
    """This packet's reviewed bytes of path; a bridged successor projects newer bytes back first."""
    return successor.historical_bytes(path, regular_bytes(path))


def _verified(path: str) -> bytes:
    """The reviewed bytes of one bound input, checked against its era digest before any use."""
    require(path in ERA_SHA256, "MET-PERF-039 reviewed bytes are bound: " + path)
    raw = reviewed_bytes(path)
    require(type(raw) is bytes and digest(raw) == ERA_SHA256[path], "unreviewed pytest-headroom source: " + path)
    return raw


def _era_suite() -> types.ModuleType:
    """The parallel suite of this era, executed from its exact reviewed bytes."""
    module = types.ModuleType("_met_perf_039_parallel_suite")
    module.__file__ = str(ROOT / PARALLEL_SUITE)
    exec(compile(_verified(PARALLEL_SUITE), PARALLEL_SUITE, "exec", dont_inherit=True), module.__dict__)
    return module


def _text(path: str) -> str:
    raw = _verified(path)
    try:
        return raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ValueError("pytest-headroom source is not UTF-8: " + path) from exc


def validate_pytest_headroom() -> None:
    """Six workers, the one-line change against the 237-packet suite, the unchanged fail-closed rules and the record."""
    for path in FROZEN_PATHS:
        require(path not in _PROJECTION_RULES, "the weights and the load-deadlines record stay byte-identical")
    for path in ERA_SHA256:
        _verified(path)
    suite = _era_suite()
    require(suite.WORKERS == WORKERS_AFTER and type(suite.DEADLINE_SECONDS) is int
            and suite.DEADLINE_SECONDS == DEADLINE_SECONDS and suite.PARENT_NODES == PARENT_NODES_EXPECTED
            and suite.SERIAL_ENV == "PLANEON_PARALLEL_SUITE_SERIAL"
            and suite.WEIGHTS_PATH == "ci/parallel_suite_weights.json",
            "six workers; deadline, parent nodes, serial rule and weights unchanged")
    raw = _verified(PARALLEL_SUITE)
    before = _undo_this_layer(PARALLEL_SUITE, raw)
    line_before = b"\nWORKERS = %d\n" % WORKERS_BEFORE
    line_after = b"\nWORKERS = %d\n" % WORKERS_AFTER
    require(digest(before) == SUITE_BEFORE_SHA256 and before.count(line_before) == 1 and raw.count(line_after) == 1
            and before.replace(line_before, line_after) == raw, "exactly the worker-count line changed")
    suite_test = _text(SUITE_TEST)
    require(suite_test.count("    assert SUITE.WORKERS == %d\n" % WORKERS_AFTER) == 1
            and "SUITE.WORKERS == %d" % WORKERS_BEFORE not in suite_test
            and suite_test.count("    assert SUITE.DEADLINE_SECONDS == %d\n" % DEADLINE_SECONDS) == 1,
            "parallel-suite test pins six workers and the unchanged deadline")
    page = _text(SUITE_PAGE)
    require(page.count("assigns whole test files to %d worker processes (MET-PERF-039; %d before), by the\n"
                       % (WORKERS_AFTER, WORKERS_BEFORE)) == 1
            and "to %d worker processes," % WORKERS_BEFORE not in page
            and page.count("within %d s (MET-PERF-038; 600 s before)." % DEADLINE_SECONDS) == 1,
            "parallel-suite page states six workers and the unchanged deadline")
    _text(README)
    record = parse(_verified(RECORD))
    require(type(record) is dict and canonical(record) == canonical(HEADROOM), "closed pytest-headroom record")
    change = HEADROOM["change"]
    require(change["before"] == WORKERS_BEFORE and change["after"] == WORKERS_AFTER
            and change["beforeSha256"] == SUITE_BEFORE_SHA256 and change["afterSha256"] == ERA_SHA256[PARALLEL_SUITE]
            and [row["id"] for row in HEADROOM["ownerDecisions"]] == ["Q-PERF39-1", "Q-PERF39-1-CONFIRM", "Q-PERF39-1-CONFIRM-2"]
            and {row["name"]: row.get("sha256") for row in HEADROOM["unchanged"]}["parallelSuiteWeights"]
            == ERA_SHA256[WEIGHTS],
            "the record states this change and the owner's decision")


def validate() -> None:
    record = authority()
    validator_raw = successor.historical_bytes(VALIDATOR_PATH, regular_bytes(VALIDATOR_PATH))
    literal = b'AUTHORITY_SHA256 = "' + AUTHORITY_SHA256.encode("ascii") + b'"'
    placeholder = b'AUTHORITY_SHA256 = "TO_BE_PINNED_AFTER_SOURCE_FREEZE"'
    require(validator_raw.count(literal) == 1
            and digest(validator_raw.replace(literal, placeholder))
            == record["validatorNormalizedSha256"], "pytest headroom validator drift")
    paths = sorted((ROOT / "task-packets").glob("*.yaml"))
    old = set(record["baselinePackets"])
    require(len(paths) == 273
            and {path.stem for path in paths} == old | {NEW_PACKET, successor.NEW_PACKET, successor.successor.NEW_PACKET, successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.NEW_PACKET},
            "closed 273-packet catalog retaining the 238-packet checkpoint")
    packets = {}
    for path in paths:
        if path.stem in (successor.NEW_PACKET, successor.successor.NEW_PACKET, successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.NEW_PACKET):
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
            "closed source-only pytest-headroom packet and inherited commands")
    require(len(packet["allowedPaths"]) == len(set(packet["allowedPaths"]))
            and set(packet["allowedPaths"]) == set(record["changedFiles"])
            | set(record["newFiles"]) | {AUTHORITY_PATH, VALIDATOR_PATH,
                                         "task-packets/" + NEW_PACKET + ".yaml"},
            "unreviewed or omitted pytest-headroom packet path")
    for path, rule in record["changedFiles"].items():
        current = successor.historical_bytes(path, regular_bytes(path))
        require(digest(current) == rule["afterSha256"]
                and digest(historical_bytes(path, current)) == rule["beforeSha256"],
                "unreviewed current source: " + path)
    for path, expected in record["newFiles"].items():
        require(digest(successor.historical_bytes(path, regular_bytes(path))) == expected,
                "new source drift: " + path)
    validate_pytest_headroom()


if __name__ == "__main__":
    validate()
    print("Pytest headroom valid: 273 current specifications; 238-packet checkpoint and exact 237-packet predecessor; six workers.")
