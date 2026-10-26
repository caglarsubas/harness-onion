#!/usr/bin/env python3
"""Validate the MET-PERF-038 load-tolerant deadlines and the exact 234-to-233 projection."""
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
    import validate_research_adoption_v3 as successor
except ImportError:
    from scripts.safe_yaml import safe_load
    from scripts import validate_research_adoption_v3 as successor


ROOT = Path(__file__).resolve().parents[1]
AUTHORITY_PATH = "architecture/load-deadlines-authority.json"
AUTHORITY_SHA256 = "f36e25091fc2c440935d0f8ae5f0687acce9998f30dff5a7cf8327b0a89ce0ab"
VALIDATOR_PATH = "scripts/validate_load_deadlines.py"
BASE_COMMIT = "5cf7faee051c670e2fba88036ff4f3c83297b716"
NEW_PACKET = "MET-PERF-038"
PREVIOUS_PACKET = "MET-MAS-003"
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
            require(key not in result, "duplicate load-deadlines authority member")
            result[key] = value
        return result

    def no_constant(_value: str) -> Any:
        raise ValueError("nonfinite load-deadlines authority number")

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
        require(digest(raw) == AUTHORITY_SHA256, "load deadlines history authority digest")
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
    }, "closed load deadlines history authority")
    require(value["schemaVersion"] == "harness.planeon.ai/load-deadlines-authority/v1"
            and value["authorityPacket"] == NEW_PACKET
            and value["acceptedBase"] == BASE_COMMIT
            and type(value["baselinePackets"]) is dict
            and len(value["baselinePackets"]) == 233
            and NEW_PACKET not in value["baselinePackets"]
            and type(value["changedFiles"]) is dict
            and type(value["newFiles"]) is dict
            and _sha(value["packetSha256"])
            and _sha(value["validatorNormalizedSha256"]),
            "accepted 233-packet base")
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
    # An exact 233-era byte string is already older than the successor layer.
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


# MET-PERF-038 (owner decision Q-PERF-DL "Bundle v4 + PERF deadlines", 2026-10-14, via the lane monitor) raises the
# in-repository limits that host load could trip under verifier bundle v4 (a load gate before the run and a 1200 s
# launcher cap, installed by the owner): the parallel suite's worker deadline 600 -> 900 s and the nested predecessor
# bound 420 -> 600 s (owner decisions Q-DL1 to Q-DL3); the workflow timeout stays 15 min, because the required verify
# runs in the owner's app verifier, never in that job (Q-DL3-B). The parallel suite stays fail-closed with the same
# workers, parent nodes and accounting; the Linux runner launcher's 900 s bound and every earlier record stating
# 420/900/15 stay unchanged. Repository bytes are read only through reviewed_bytes, so a later bridged successor projects
# its own edits away first. Every input of this era is bound by digest before it is parsed or executed, the parallel
# suite is executed from those bytes, and the limits, the budget and the owner's decisions are restated here
# independently of the limits record, which must equal them exactly (type-strict, through canonical JSON).
PARALLEL_SUITE = "ci/parallel_suite.py"
PREDECESSOR_TEST = "tests/linux_runner/test_build_and_predecessors.py"
DIAGNOSTICS_TEST = "tests/linux_runner/test_predecessor_diagnostics.py"
SUITE_TEST = "tests/test_parallel_suite.py"
WORKFLOW = ".github/workflows/verify.yml"
LAUNCHER = "ci/linux-runner/launcher.py"
SUITE_PAGE = "docs/alpha-2/PARALLEL_SUITE_PERF035.md"
# A live test that pins the predecessor diagnostics test by digest (review P2-1); it follows the raised bound.
DIAGNOSTIC_REPAIR_TEST = "tests/test_diagnostic_repair.py"
LIMITS_RECORD = "architecture/load-deadlines/limits.json"
LIMITS_README = "architecture/load-deadlines/README.md"
ERA_SHA256 = MappingProxyType({
    "ci/parallel_suite.py": "14a7dd6db3d4f1b9b97408ffad49c5c977ce8813c81d975ca8dfe9d919c26b34",
    "tests/linux_runner/test_build_and_predecessors.py": "7c52978e0dff71b747f0654ca4ea6f4b58eb2fe35c47187c51d5c06ea66b583c",
    "tests/linux_runner/test_predecessor_diagnostics.py": "3c0afe5686f0c39cea2f68d97f50549d0faba890539c3e20aae1d88b2305139f",
    "tests/test_parallel_suite.py": "d9bd0363d7ab61a0bc27f8285ed2741e9e12c1ec12f4e5953c06edaac89ad55c",
    ".github/workflows/verify.yml": "b6b8c87fc5f9615c193594c7a861a59e55022acfdb1dc9970c903af9fca22dee",
    "ci/linux-runner/launcher.py": "e402d0ca12bf56bd98984dba05e357be4d7c8997cc1a598771a0ce3cfa9a687b",
    "docs/alpha-2/PARALLEL_SUITE_PERF035.md": "2036ded08d202bbbad225e512e1b8f762b7143367d3e5d6a6b4fd98b215b8baa",
    "tests/test_diagnostic_repair.py": "7b666bb8bab73ea37037292a53e8f7029f1a9128e0d6379dd75533f2b5e558a2",
    "architecture/load-deadlines/limits.json": "f9c152fd4b7e074e5b63b1649e35e2cc2c651060c1ae48d91c078b8690f0f11f",
    "architecture/load-deadlines/README.md": "36ee4dd227603e6ebef164a20555c30fabfbd59c0c0dbbd2526579478dcb81c1",
})
DEADLINE_SECONDS, NESTED_SECONDS, WORKFLOW_MINUTES = 900, 600, 15
# The budget the deadline is chosen against (seconds, approximate, quiet host): the launcher's own setup inside the cap,
# argv 1-62 before the parallel suite, and the parent nodes after the workers.
BUDGET = MappingProxyType({"launcherCapSeconds": 1200, "launcherSetupSeconds": 60, "argvBeforeSuiteSeconds": 120,
                           "parentNodesSeconds": 90})
PARENT_NODES_EXPECTED = frozenset({
    "tests/linux_runner/test_build_and_predecessors.py::test_full_predecessor_suites_and_validators_remain_green",
    "tests/linux_runner/test_build_and_predecessors.py::test_byte_identical_package_and_source_inventory",
    "tests/linux_runner/test_isolation.py::test_real_integration_is_not_faked_on_development_host",
})
OWNER_DECISIONS = [{'id': 'Q-PERF-DL',
  'selected': 'Bundle v4 + PERF deadlines',
  'date': '2026-10-14',
  'decision': 'The owner chose "Bundle v4 + PERF deadlines": the primary builds verifier bundle v4 (a load gate '
              'before the run plus a 1200 s cap; owner root change), and YOU build a PERF packet. It takes '
              'harness-onion slot 233 now, before MAS-RA-003, which is re-based to 234 afterwards. PERF packet scope '
              '(you own the parallel suite from 216/226): raise the in-repo deadlines that load can trip: the '
              "parallel suite's 600 s deadline and the nested 420 s predecessor run, with headroom under the new "
              '1200 s cap; update the repo pins of the host limit (tests/test_ci_performance.py "host 900", the '
              'packet contract text, the workflow minutes) consistently with bundle v4; keep the parallel suite '
              "fail-closed, with the same node accounting. This is a ci/ transport change, so it needs the owner's "
              "per-head approval file. Coordinate the exact new values with the primary's bundle v4 through me."},
 {'id': 'Q-DL1',
  'selected': 'a',
  'date': '2026-10-14',
  'decision': 'parallel-suite deadline 600 → 900 s, nested predecessor 420 → 600 s, workflow timeout 15 → 20 min.'},
 {'id': 'Q-DL2',
  'selected': 'a',
  'date': '2026-10-14',
  'decision': 'keep the historical 420/900/15 records; add the successor limits record.'},
 {'id': 'Q-DL3',
  'selected': 'a',
  'date': '2026-10-14',
  'decision': "include verify.yml's timeout-minutes (bridged); leave ci/linux-runner/launcher.py's min(900) alone."},
 {'id': 'Q-V4-VALUES',
  'selected': 'a',
  'date': '2026-10-14',
  'decision': 'Bundle v4 values (owner Q-V4-1..5 (a)), for your successor record: launcher cap 1200 s; RUN_SECONDS '
              '1260; TTL 1800; load gate quiet = 5-min < 4.0 AND 1-min < 6.0, checked every poll; the wait happens '
              'BEFORE the check run is claimed (outside the job); bounded wait 3600 s, then keep waiting with '
              'escalation plus an operator override file; one setting for all three repositories.'},
 {'id': 'Q-DL3-B',
  'selected': 'b',
  'date': '2026-10-14',
  'decision': '"Keep verify.yml at 15": leave the workflow file untouched (amends Q-DL3 to (c)). The limits record '
              'and README say the workflow timeout stays at 15 min as a pinned record value, because the app '
              'verifier never runs in that workflow job. No validator-refusal change.'},
 {'id': 'Q-ORDER-187', 'selected': '187 first', 'date': '2026-10-14', 'decision': 'handle pr-187 first, then 188'}]
LIMITS = {'schemaVersion': 'harness.planeon.ai/load-deadlines/v1',
 'packet': 'MET-PERF-038',
 'evidenceClass': 'SOURCE_DELTA_ONLY',
 'verifierBundle': {'version': 'v4',
                    'launcherCapSeconds': 1200,
                    'runSeconds': 1260,
                    'ttlSeconds': 1800,
                    'loadGate': {'fiveMinuteLoadBelow': 4.0,
                                 'oneMinuteLoadBelow': 6.0,
                                 'checkedEveryPoll': True,
                                 'waitsBeforeTheCheckRunIsClaimed': True,
                                 'boundedWaitSeconds': 3600,
                                 'afterBoundedWait': 'KEEP_WAITING_WITH_ESCALATION_AND_OPERATOR_OVERRIDE_FILE'},
                    'scope': 'ONE_SETTING_FOR_ALL_THREE_REPOSITORIES',
                    'installedBy': 'the owner (root change); not part of this repository'},
 'budgetSeconds': {'launcherCapSeconds': 1200,
                   'launcherSetupSeconds': 60,
                   'argvBeforeSuiteSeconds': 120,
                   'parallelSuiteDeadlineSeconds': 900,
                   'parentNodesSeconds': 90},
 'inRepoLimits': [{'name': 'parallelSuiteWorkerDeadlineSeconds',
                   'path': 'ci/parallel_suite.py',
                   'before': 600,
                   'after': 900},
                  {'name': 'nestedPredecessorSeconds',
                   'path': 'tests/linux_runner/test_build_and_predecessors.py',
                   'before': 420,
                   'after': 600}],
 'unchanged': [{'name': 'parallelSuiteWorkers', 'path': 'ci/parallel_suite.py', 'value': 4},
               {'name': 'parallelSuiteParentNodes',
                'path': 'ci/parallel_suite.py',
                'value': 'the three MET-PERF-037 parent nodes'},
               {'name': 'linuxRunnerLauncherCapSeconds', 'path': 'ci/linux-runner/launcher.py', 'value': 900},
               {'name': 'workflowTimeoutMinutes', 'path': '.github/workflows/verify.yml', 'value': 15},
               {'name': 'historicalLimitRecords',
                'path': 'architecture/',
                'value': 'every earlier record stating 420/900/15 stays byte-identical'}]}


def reviewed_bytes(path: str) -> bytes:
    """This packet's reviewed bytes of path; a bridged successor projects newer bytes back first."""
    return successor.historical_bytes(path, regular_bytes(path))


def _verified(path: str) -> bytes:
    """The reviewed bytes of one bound input, checked against its era digest before any use."""
    require(path in ERA_SHA256, "MET-PERF-038 reviewed bytes are bound: " + path)
    raw = reviewed_bytes(path)
    require(type(raw) is bytes and digest(raw) == ERA_SHA256[path], "unreviewed load-deadlines source: " + path)
    return raw


def _era_suite() -> types.ModuleType:
    """The parallel suite of this era, executed from its exact reviewed bytes."""
    raw = _verified(PARALLEL_SUITE)
    module = types.ModuleType("_met_perf_038_parallel_suite")
    module.__file__ = str(ROOT / PARALLEL_SUITE)
    exec(compile(raw, PARALLEL_SUITE, "exec", dont_inherit=True), module.__dict__)
    return module


def _text(path: str) -> str:
    raw = _verified(path)
    try:
        return raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ValueError("load-deadlines source is not UTF-8: " + path) from exc


def validate_load_deadlines() -> None:
    """The raised limits, the unchanged fail-closed suite, the budget and the limits record, exactly."""
    for path in ERA_SHA256:
        _verified(path)
    suite = _era_suite()
    require(suite.WORKERS == 4 and type(suite.DEADLINE_SECONDS) is int and suite.DEADLINE_SECONDS == DEADLINE_SECONDS
            and suite.PARENT_NODES == PARENT_NODES_EXPECTED and suite.SERIAL_ENV == "PLANEON_PARALLEL_SUITE_SERIAL",
            "parallel-suite deadline raised, workers, parent nodes and serial rule unchanged")
    require(DEADLINE_SECONDS + BUDGET["launcherSetupSeconds"] + BUDGET["argvBeforeSuiteSeconds"]
            + BUDGET["parentNodesSeconds"] <= BUDGET["launcherCapSeconds"], "the deadline fits the launcher cap")
    nested = _text(PREDECESSOR_TEST)
    require(nested.count("timeout=%d, close_fds=True" % NESTED_SECONDS) == 2
            and nested.count('"event": "START", "timeoutSeconds": %d}' % NESTED_SECONDS) == 2
            and "timeout=420" not in nested and '"timeoutSeconds": 420' not in nested,
            "nested predecessor bound raised in both runs and both records")
    diagnostics = _text(DIAGNOSTICS_TEST)
    require(diagnostics.count('"timeout": %d, "close_fds": True,' % NESTED_SECONDS) == 1
            and diagnostics.count('"event": "START", "timeoutSeconds": %d}' % NESTED_SECONDS) == 1,
            "predecessor diagnostics expect the raised bound")
    suite_test = _text(SUITE_TEST)
    require(suite_test.count("    assert SUITE.DEADLINE_SECONDS == %d\n" % DEADLINE_SECONDS) == 1
            and "DEADLINE_SECONDS == 600" not in suite_test, "parallel-suite test pins the raised deadline")
    workflow = _text(WORKFLOW)
    require(workflow.count("timeout-minutes:") == 1 and workflow.count("    timeout-minutes: %d\n" % WORKFLOW_MINUTES) == 1,
            "workflow timeout as decided")
    require(_text(LAUNCHER).count("min(900, ") == 2, "Linux runner launcher bound unchanged")
    require(_text(SUITE_PAGE).count("within %d s (MET-PERF-038; 600 s before)." % DEADLINE_SECONDS) == 1,
            "parallel-suite page states the raised deadline")
    require(_text(DIAGNOSTIC_REPAIR_TEST).count('"%s": "%s",' % (DIAGNOSTICS_TEST, ERA_SHA256[DIAGNOSTICS_TEST])) == 1,
            "diagnostic repair test pins the raised diagnostics test")
    require(canonical(LIMITS["budgetSeconds"]) == canonical(dict(BUDGET, parallelSuiteDeadlineSeconds=DEADLINE_SECONDS)),
            "the restated budget is the checked budget")
    _text(LIMITS_README)
    record = parse(_verified(LIMITS_RECORD))
    require(type(record) is dict and set(record) == set(LIMITS) | {"ownerDecisions"}
            and canonical({key: record[key] for key in LIMITS}) == canonical(LIMITS), "closed load-deadlines limits record")
    require(canonical(record["ownerDecisions"]) == canonical(OWNER_DECISIONS), "owner decisions recorded verbatim and dated")


def validate() -> None:
    record = authority()
    validator_raw = successor.historical_bytes(VALIDATOR_PATH, regular_bytes(VALIDATOR_PATH))
    literal = b'AUTHORITY_SHA256 = "' + AUTHORITY_SHA256.encode("ascii") + b'"'
    placeholder = b'AUTHORITY_SHA256 = "TO_BE_PINNED_AFTER_SOURCE_FREEZE"'
    require(validator_raw.count(literal) == 1
            and digest(validator_raw.replace(literal, placeholder))
            == record["validatorNormalizedSha256"], "load deadlines validator drift")
    paths = sorted((ROOT / "task-packets").glob("*.yaml"))
    old = set(record["baselinePackets"])
    require(len(paths) == 267
            and {path.stem for path in paths} == old | {NEW_PACKET, successor.NEW_PACKET, successor.successor.NEW_PACKET, successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.NEW_PACKET},
            "closed 267-packet catalog retaining the 234-packet checkpoint")
    packets = {}
    for path in paths:
        if path.stem in (successor.NEW_PACKET, successor.successor.NEW_PACKET, successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.NEW_PACKET):
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
            "closed source-only load-deadlines packet and inherited commands")
    require(len(packet["allowedPaths"]) == len(set(packet["allowedPaths"]))
            and set(packet["allowedPaths"]) == set(record["changedFiles"])
            | set(record["newFiles"]) | {AUTHORITY_PATH, VALIDATOR_PATH,
                                         "task-packets/" + NEW_PACKET + ".yaml"},
            "unreviewed or omitted load-deadlines packet path")
    for path, rule in record["changedFiles"].items():
        current = successor.historical_bytes(path, regular_bytes(path))
        require(digest(current) == rule["afterSha256"]
                and digest(historical_bytes(path, current)) == rule["beforeSha256"],
                "unreviewed current source: " + path)
    for path, expected in record["newFiles"].items():
        require(digest(successor.historical_bytes(path, regular_bytes(path))) == expected,
                "new source drift: " + path)
    validate_load_deadlines()


if __name__ == "__main__":
    validate()
    print("Load deadlines valid: 267 current specifications; 234-packet checkpoint and exact 233-packet predecessor; every refusal unchanged.")
