"""MET-PERF-043 D5a oracle: END-only pytest diagnostics.

Written from DESIGN.md (rev 3, errata E1 and E2) section 2, section 5 and Appendix A alone. The module is a black
box: it is imported by path from the repository root this test runs in, and only the public names the design
states are used (``Diagnostics`` with ``start``, ``end`` and ``finish``; ``node_identity``; ``summarize_nested``;
the ``MAX_*`` constants; ``PREFIX``). Standard library and pytest only.
"""

from __future__ import annotations

import collections
import hashlib
import importlib.util
import json
import re
import sys
from pathlib import Path

import pytest

_ROOT = Path(__file__).resolve().parents[1]
_SPEC = importlib.util.spec_from_file_location(
    "met_perf_043_oracle_subject", _ROOT / "ci" / "pytest_diagnostics.py"
)
diag = importlib.util.module_from_spec(_SPEC)
sys.modules[_SPEC.name] = diag
_SPEC.loader.exec_module(diag)

# ---------------------------------------------------------------------------------------------------------------
# The design's stated values (section 2, section 5, Appendix A)
# ---------------------------------------------------------------------------------------------------------------

PREFIX_BYTES = b"PYTEST_DIAGNOSTIC="
SCHEMA = "planeon.pytest-diagnostic-summary/v2"
MAX_EVENTS = 140_000
MAX_PROCESS_BYTES = 30 * 1024 * 1024
MAX_RECORD_BYTES = 1024
MAX_FAILURES = 16
MAX_SCAN_BYTES = 32_505_856
MAX_SCAN_LINES = 154_000
INT_MAX = 10**15
COUNT_MAX = 2 * MAX_EVENTS
PHASES = ("setup", "call", "teardown")
OUTCOMES = ("passed", "failed", "skipped")
REDACTED = "<redacted-node>"
LABEL_PATTERN = re.compile(r"[A-Za-z0-9_.-]{1,32}::test_[A-Za-z0-9_]{0,31}")
HEX = frozenset("0123456789abcdef")
PRODUCER_REASONS = (
    "CLOCK",
    "ENCODING",
    "EVENT_LIMIT",
    "INVALID_NODE",
    "INVALID_PHASE",
    "INVALID_REPORT",
    "OUTPUT_LIMIT",
    "PHASE_ORDER",
    "RECORD_LIMIT",
    "SINK",
    "UNFINISHED_PHASE",
)
READER_ONLY_REASONS = (
    "AFTER_COMPLETION",
    "COUNT_MISMATCH",
    "FAILURE_DETAIL_LIMIT",
    "INPUT_LIMIT",
    "INVALID_INPUT",
    "MALFORMED_RECORD",
    "NO_COMPLETION",
    "NO_DIAGNOSTICS",
    "PARTIAL_LINE",
    "PRODUCER_INCOMPLETE",
    "SCAN_LIMIT",
    "SEQUENCE_GAP",
    "TIME_ORDER",
)
SUMMARY_MEMBERS = frozenset(
    {
        "schemaVersion",
        "buffered",
        "acceptance",
        "available",
        "status",
        "inputBytes",
        "scannedBytes",
        "inputTruncatedBytes",
        "records",
        "malformed",
        "nonDiagnosticLines",
        "completionSeen",
        "latestActive",
        "lastPhase",
        "failures",
        "failuresOmitted",
        "starts",
        "ends",
        "failed",
        "skipped",
        "sessionEnd",
        "incompleteReasons",
    }
)

NODE_A = hashlib.sha256(b"tests/test_oracle_a.py::test_one").hexdigest()
NODE_B = hashlib.sha256(b"tests/test_oracle_b.py::test_two").hexdigest()
LABEL_A = "test_oracle_a.py::test_one"
LABEL_B = "test_oracle_b.py::test_two"

# ---------------------------------------------------------------------------------------------------------------
# Calling the subject: an exception is reported by its type only, so no subject source enters a test report
# ---------------------------------------------------------------------------------------------------------------


def _call(fn, *args, **kwargs):
    try:
        return fn(*args, **kwargs)
    except Exception as exc:
        raise AssertionError(f"the subject raised {type(exc).__name__}") from None


def _check_summary_invariants(summary):
    assert type(summary) is dict, type(summary).__name__
    assert set(summary) == SUMMARY_MEMBERS, sorted(set(summary) ^ SUMMARY_MEMBERS)
    reasons = summary["incompleteReasons"]
    assert type(reasons) is list
    assert reasons == sorted(reasons), reasons
    assert "PHASE_ORDER" not in reasons, reasons
    assert summary["status"] in ("COMPLETE", "INCOMPLETE", "ABSENT")
    assert (summary["status"] == "COMPLETE") == (reasons == []), (summary["status"], reasons)
    assert summary["inputTruncatedBytes"] == summary["inputBytes"] - summary["scannedBytes"]


def summarize(data):
    summary = _call(diag.summarize_nested, data)
    _check_summary_invariants(summary)
    return summary


def identity(nodeid):
    return _call(diag.node_identity, nodeid)


# ---------------------------------------------------------------------------------------------------------------
# Record builders (Appendix A, Records)
# ---------------------------------------------------------------------------------------------------------------

_AUTO = object()
_DROP = object()


def end_rec(seq=1, t_us=10, outcome="passed", phase="call", *, node=NODE_A, duration_us=7, xfail=False,
            label=_AUTO):
    rec = {
        "v": 2,
        "seq": seq,
        "event": "END",
        "node": node,
        "phase": phase,
        "tUs": t_us,
        "outcome": outcome,
        "durationUs": duration_us,
        "xfail": xfail,
    }
    if label is _AUTO:
        if outcome != "passed":
            rec["label"] = LABEL_A
    elif label is not _DROP:
        rec["label"] = label
    return rec


def error_rec(seq=1, reason="SINK", **extra):
    rec = {"v": 2, "seq": seq, "event": "ERROR", "reason": reason, "incomplete": True}
    rec.update(extra)
    return rec


def unfinished_rec(seq=1, node=NODE_A, phase="call", label=LABEL_A):
    return error_rec(seq, "UNFINISHED_PHASE", node=node, phase=phase, label=label)


def session_end_rec(seq=1, t_us=100, *, ends=0, failed=0, skipped=0, starts=None, exit_code=0, incomplete=False,
                    reasons=(), dropped=0):
    return {
        "v": 2,
        "seq": seq,
        "event": "SESSION_END",
        "tUs": t_us,
        "exitCode": exit_code,
        "incomplete": incomplete,
        "reasons": list(reasons) if isinstance(reasons, tuple) else reasons,
        "starts": ends if starts is None else starts,
        "ends": ends,
        "failed": failed,
        "skipped": skipped,
        "dropped": dropped,
    }


def mutate(rec, **changes):
    out = dict(rec)
    for key, value in changes.items():
        if value is _DROP:
            out.pop(key, None)
        else:
            out[key] = value
    return out


def line(rec):
    return PREFIX_BYTES + json.dumps(rec, separators=(",", ":"), ensure_ascii=False).encode("utf-8") + b"\n"


def stream(*items):
    return b"".join(item if isinstance(item, bytes) else line(item) for item in items)


def good_records():
    return [
        end_rec(1, 10, phase="setup"),
        end_rec(2, 20, phase="call"),
        end_rec(3, 30, phase="teardown"),
        session_end_rec(4, 40, ends=3),
    ]


def assert_valid(item):
    summary = summarize(stream(item))
    assert (summary["records"], summary["malformed"]) == (1, 0), summary["incompleteReasons"]
    assert "MALFORMED_RECORD" not in summary["incompleteReasons"]


def assert_malformed(item):
    summary = summarize(stream(item))
    assert (summary["records"], summary["malformed"]) == (0, 1), summary["incompleteReasons"]
    assert "MALFORMED_RECORD" in summary["incompleteReasons"]


def assert_exact(actual, expected, where="value"):
    """Equality with exact types (so ``1`` is not ``True`` and a tuple is not a list)."""
    if isinstance(expected, dict):
        assert type(actual) is dict, f"{where}: {type(actual).__name__}"
        assert set(actual) == set(expected), f"{where}: members differ {sorted(set(actual) ^ set(expected))}"
        for key in expected:
            assert_exact(actual[key], expected[key], f"{where}.{key}")
    elif isinstance(expected, list):
        assert type(actual) is list, f"{where}: {type(actual).__name__}"
        assert len(actual) == len(expected), f"{where}: length {len(actual)} != {len(expected)}"
        for index, (got, want) in enumerate(zip(actual, expected)):
            assert_exact(got, want, f"{where}[{index}]")
    elif expected is None:
        assert actual is None, f"{where}: {actual!r} is not None"
    else:
        assert type(actual) is type(expected) and actual == expected, f"{where}: {actual!r} != {expected!r}"


def expected_summary(**overrides):
    base = {
        "schemaVersion": SCHEMA,
        "buffered": True,
        "acceptance": False,
        "available": True,
        "status": "INCOMPLETE",
        "inputBytes": 0,
        "scannedBytes": 0,
        "inputTruncatedBytes": 0,
        "records": 0,
        "malformed": 0,
        "nonDiagnosticLines": 0,
        "completionSeen": False,
        "latestActive": None,
        "lastPhase": None,
        "failures": [],
        "failuresOmitted": 0,
        "starts": 0,
        "ends": 0,
        "failed": 0,
        "skipped": 0,
        "sessionEnd": None,
        "incompleteReasons": [],
    }
    base.update(overrides)
    return base


# ---------------------------------------------------------------------------------------------------------------
# Appendix A as a checker for what the producer writes
# ---------------------------------------------------------------------------------------------------------------


def _is_int(value, low, high):
    return type(value) is int and low <= value <= high


def _is_node(value):
    return type(value) is str and len(value) == 64 and set(value) <= HEX


def _is_label(value):
    return type(value) is str and len(value) <= 70 and (value == REDACTED or LABEL_PATTERN.fullmatch(value) is not None)


def appendix_a_problems(rec):
    if type(rec) is not dict:
        return ["not an object"]
    problems = []
    if not (type(rec.get("v")) is int and rec.get("v") == 2):
        problems.append("v")
    if not _is_int(rec.get("seq"), 1, MAX_EVENTS):
        problems.append("seq")
    event = rec.get("event")
    if event == "END":
        want = {"v", "seq", "event", "node", "phase", "tUs", "outcome", "durationUs", "xfail"}
        if rec.get("outcome") != "passed":
            want.add("label")
            if not _is_label(rec.get("label")):
                problems.append("label")
        if not _is_node(rec.get("node")):
            problems.append("node")
        if rec.get("phase") not in PHASES:
            problems.append("phase")
        if not _is_int(rec.get("tUs"), 0, INT_MAX):
            problems.append("tUs")
        if rec.get("outcome") not in OUTCOMES:
            problems.append("outcome")
        if not _is_int(rec.get("durationUs"), 0, INT_MAX):
            problems.append("durationUs")
        if type(rec.get("xfail")) is not bool:
            problems.append("xfail")
    elif event == "ERROR":
        want = {"v", "seq", "event", "reason", "incomplete"}
        if rec.get("reason") not in PRODUCER_REASONS:
            problems.append("reason")
        if rec.get("incomplete") is not True:
            problems.append("incomplete")
        if rec.get("reason") == "UNFINISHED_PHASE":
            want |= {"node", "phase", "label"}
            if not _is_node(rec.get("node")):
                problems.append("node")
            if rec.get("phase") not in PHASES:
                problems.append("phase")
            if not _is_label(rec.get("label")):
                problems.append("label")
    elif event == "SESSION_END":
        want = {"v", "seq", "event", "tUs", "exitCode", "incomplete", "reasons", "starts", "ends", "failed",
                "skipped", "dropped"}
        if not _is_int(rec.get("tUs"), 0, INT_MAX):
            problems.append("tUs")
        if not _is_int(rec.get("exitCode"), 0, 255):
            problems.append("exitCode")
        if type(rec.get("incomplete")) is not bool:
            problems.append("incomplete")
        reasons = rec.get("reasons")
        if not (type(reasons) is list and len(reasons) <= 11 and all(r in PRODUCER_REASONS for r in reasons)):
            problems.append("reasons")
        for member in ("starts", "ends", "failed", "skipped", "dropped"):
            if not _is_int(rec.get(member), 0, COUNT_MAX):
                problems.append(member)
    else:
        return problems + [f"event {event!r}"]
    if set(rec) != want:
        problems.append(f"members {sorted(set(rec) ^ want)}")
    return problems


# ---------------------------------------------------------------------------------------------------------------
# Producer harness: a recording sink (returns the bytes written) and section 5's pinned clock
# ---------------------------------------------------------------------------------------------------------------


class _Sink:
    def __init__(self):
        self.chunks = []
        self.total = 0

    def __call__(self, data):
        self.chunks.append(bytes(data))
        self.total += len(data)
        return len(data)

    def stream(self):
        return b"".join(self.chunks)


class _PinnedClock:
    """Each call adds 0.012345 s (section 5)."""

    def __init__(self):
        self.now = 0.0

    def __call__(self):
        self.now += 0.012345
        return self.now


class _Producer:
    def __init__(self):
        self.sink = _Sink()
        self.clock = _PinnedClock()
        self.diagnostics = _call(diag.Diagnostics, self.sink, self.clock)
        self.start_calls = 0
        self.end_calls = []

    def start(self, nodeid, phase):
        self.start_calls += 1
        return _call(self.diagnostics.start, nodeid, phase)

    def end(self, nodeid, phase, outcome, duration=0.012345, xfail=False):
        self.end_calls.append((nodeid, phase, outcome, xfail))
        return _call(self.diagnostics.end, nodeid, phase, outcome, duration, xfail=xfail)

    def finish(self, exit_code=0):
        return _call(self.diagnostics.finish, exit_code)

    def records(self):
        return parse_stream(self.sink.stream())


def parse_stream(data):
    assert data == b"" or data.endswith(b"\n")
    out = []
    for raw in data.split(b"\n")[:-1]:
        assert raw.startswith(PREFIX_BYTES), raw[:40]
        out.append(json.loads(raw[len(PREFIX_BYTES):]))
    return out


def encode_records(records):
    return b"".join(line(rec) for rec in records)


N_PASS = "tests/test_oracle_p.py::test_pass"
N_FAIL = "tests/test_oracle_p.py::test_fail"
N_SKIP = "tests/test_oracle_p.py::test_skip"
N_XFAIL = "tests/test_oracle_p.py::test_xfail"
N_XPASS = "tests/test_oracle_p.py::test_xpass"
N_SETUP_ERROR = "tests/test_oracle_p.py::test_setup_error[a-1]"
N_TEARDOWN_ERROR = "tests/test_oracle_p.py::test_teardown_error"

MIXED_SCRIPT = [
    (N_PASS, [("setup", "passed", False), ("call", "passed", False), ("teardown", "passed", False)]),
    (N_FAIL, [("setup", "passed", False), ("call", "failed", False), ("teardown", "passed", False)]),
    (N_SKIP, [("setup", "skipped", False), ("teardown", "passed", False)]),
    (N_XFAIL, [("setup", "passed", False), ("call", "skipped", True), ("teardown", "passed", False)]),
    (N_XPASS, [("setup", "passed", False), ("call", "passed", True), ("teardown", "passed", False)]),
    (N_SETUP_ERROR, [("setup", "failed", False), ("teardown", "passed", False)]),
    (N_TEARDOWN_ERROR, [("setup", "passed", False), ("call", "passed", False), ("teardown", "failed", False)]),
]

LOSS_SCRIPT = MIXED_SCRIPT[:3]


def run_script(script, exit_code=1):
    producer = _Producer()
    for nodeid, phases in script:
        for phase, outcome, xfail in phases:
            producer.start(nodeid, phase)
            producer.end(nodeid, phase, outcome, 0.012345, xfail)
    producer.finish(exit_code)
    return producer


# ===============================================================================================================
# Public names and the stated caps (section 2: every cap unchanged; Appendix A: the derived scan caps)
# ===============================================================================================================


def test_public_names_are_present():
    assert callable(diag.Diagnostics)
    for name in ("start", "end", "finish"):
        assert callable(getattr(diag.Diagnostics, name))
    assert callable(diag.node_identity)
    assert callable(diag.summarize_nested)
    assert diag.PREFIX in (PREFIX_BYTES, PREFIX_BYTES.decode("ascii"))


def test_stated_cap_values_are_unchanged():
    assert_exact(diag.MAX_EVENTS, MAX_EVENTS, "MAX_EVENTS")
    assert_exact(diag.MAX_PROCESS_BYTES, MAX_PROCESS_BYTES, "MAX_PROCESS_BYTES")
    assert_exact(diag.MAX_RECORD_BYTES, MAX_RECORD_BYTES, "MAX_RECORD_BYTES")
    assert_exact(diag.MAX_FAILURES, MAX_FAILURES, "MAX_FAILURES")


def test_derived_scan_caps_have_their_stated_values():
    assert_exact(diag.MAX_SCAN_BYTES, MAX_SCAN_BYTES, "MAX_SCAN_BYTES")
    assert MAX_SCAN_BYTES == MAX_PROCESS_BYTES + 1024 * 1024
    assert_exact(diag.MAX_SCAN_LINES, MAX_SCAN_LINES, "MAX_SCAN_LINES")
    assert MAX_SCAN_LINES == MAX_EVENTS + MAX_EVENTS // 10


@pytest.mark.parametrize(
    "nodeid",
    [
        "tests/test_oracle_p.py::test_pass",
        "tests/test_oracle_p.py::test_setup_error[a-1]",
        "tests/linux_runner/test_deep.py::TestKind::test_method",
        "test_top.py::test_x",
    ],
    ids=["plain", "parametrized", "class", "top_level"],
)
def test_node_identity_node_is_the_sha256_of_the_node_id(nodeid):
    ident = identity(nodeid)
    assert ident["node"] == hashlib.sha256(nodeid.encode("utf-8")).hexdigest()
    assert _is_label(ident["label"]), ident["label"]


@pytest.mark.parametrize(
    "nodeid",
    [
        "tests/test_a.py::test_p[é]",
        "tests/" + "x" * 40 + ".py::test_y",
        "tests/test_a.py::TestK::test_m",
        "tests/test_a.py::test_" + "z" * 40,
    ],
    ids=["unicode_param", "long_file", "class", "long_test_name"],
)
def test_node_identity_label_always_meets_the_label_rule(nodeid):
    assert _is_label(identity(nodeid)["label"])


# ===============================================================================================================
# The producer (section 2, Producer)
# ===============================================================================================================


def test_producer_writes_no_start_record_for_any_phase():
    producer = run_script(MIXED_SCRIPT)
    records = producer.records()
    events = collections.Counter(rec["event"] for rec in records)
    assert "START" not in events
    assert set(events) == {"END", "SESSION_END"}
    assert events["END"] == len(producer.end_calls) == 19
    assert events["SESSION_END"] == 1
    assert records[-1]["event"] == "SESSION_END"


def test_producer_marks_every_record_version_2():
    sessions = [run_script(MIXED_SCRIPT)]
    unfinished = _Producer()
    unfinished.start(N_PASS, "setup")
    unfinished.finish(0)
    sessions.append(unfinished)
    invalid = _Producer()
    invalid.start(N_PASS, "not-a-phase")
    invalid.finish(0)
    sessions.append(invalid)
    seen = set()
    for producer in sessions:
        for rec in producer.records():
            assert type(rec["v"]) is int and rec["v"] == 2, rec
            seen.add(rec["event"])
    assert seen == {"END", "ERROR", "SESSION_END"}


def test_producer_records_follow_appendix_a():
    records = run_script(MIXED_SCRIPT).records()
    for rec in records:
        assert appendix_a_problems(rec) == [], rec
    assert [rec["seq"] for rec in records] == list(range(1, len(records) + 1))
    stamps = [rec["tUs"] for rec in records if "tUs" in rec]
    assert stamps == sorted(stamps)


def test_producer_end_label_present_exactly_when_outcome_is_not_passed():
    producer = run_script(MIXED_SCRIPT)
    ends = [rec for rec in producer.records() if rec["event"] == "END"]
    assert len(ends) == len(producer.end_calls)
    for rec, (nodeid, phase, outcome, xfail) in zip(ends, producer.end_calls):
        assert (rec["phase"], rec["outcome"], rec["xfail"]) == (phase, outcome, xfail)
        assert ("label" in rec) == (outcome != "passed"), rec
    xpass = [rec for rec in ends if rec["outcome"] == "passed" and rec["xfail"]]
    xfail_skip = [rec for rec in ends if rec["outcome"] == "skipped" and rec["xfail"]]
    assert len(xpass) == 1 and "label" not in xpass[0]
    assert len(xfail_skip) == 1 and "label" in xfail_skip[0]


def test_producer_end_label_equals_node_identity_label():
    producer = run_script(MIXED_SCRIPT)
    ends = [rec for rec in producer.records() if rec["event"] == "END"]
    labelled = 0
    for rec, (nodeid, _phase, outcome, _xfail) in zip(ends, producer.end_calls):
        ident = identity(nodeid)
        assert rec["node"] == ident["node"] == hashlib.sha256(nodeid.encode("utf-8")).hexdigest()
        if outcome != "passed":
            assert rec["label"] == ident["label"]
            labelled += 1
    assert labelled == 5


@pytest.mark.parametrize(
    "nodeid",
    [
        "tests/test_a.py::test_p[é]",
        "tests/" + "x" * 40 + ".py::test_y",
        "tests/test_a.py::TestK::test_m",
        "tests/test_a.py::test_" + "z" * 40,
    ],
    ids=["unicode_param", "long_file", "class", "long_test_name"],
)
def test_producer_failed_end_label_meets_the_rule_for_awkward_node_ids(nodeid):
    producer = _Producer()
    producer.start(nodeid, "call")
    producer.end(nodeid, "call", "failed")
    producer.finish(1)
    records = producer.records()
    for rec in records:
        assert appendix_a_problems(rec) == [], rec
    ends = [rec for rec in records if rec["event"] == "END"]
    assert len(ends) == 1
    ident = identity(nodeid)
    assert (ends[0]["node"], ends[0]["label"]) == (ident["node"], ident["label"])


def _assert_fails_closed_with_phase_order(producer, absent_labels):
    """Section 2, errata E2: with no matching phase active, end() fails closed with PHASE_ORDER exactly as in v1:
    the producer stops, the END is dropped, and the stream reads INCOMPLETE. Computing the label never raises
    (every subject call goes through _call, which fails the test on any exception)."""
    records = producer.records()
    for rec in records:
        assert appendix_a_problems(rec) == [], rec
    assert [rec for rec in records if rec["event"] == "END"] == []
    assert [rec["reason"] for rec in records if rec["event"] == "ERROR"] == ["PHASE_ORDER"]
    session_end = records[-1]
    assert session_end["event"] == "SESSION_END"
    assert session_end["incomplete"] is True
    assert "PHASE_ORDER" in session_end["reasons"]
    written = json.dumps(records)
    for label in absent_labels:
        assert label not in written
    summary = summarize(producer.sink.stream())
    assert summary["status"] == "INCOMPLETE"
    assert "PRODUCER_INCOMPLETE" in summary["incompleteReasons"]
    assert (summary["ends"], summary["lastPhase"], summary["failures"]) == (0, None, [])


@pytest.mark.parametrize(
    "active",
    [("tests/test_oracle_p.py::test_alpha", "call"), ("tests/test_oracle_p.py::test_beta", "setup")],
    ids=["other_node_active", "other_phase_active"],
)
def test_producer_end_with_no_matching_active_phase_fails_closed(active):
    beta = "tests/test_oracle_p.py::test_beta"
    producer = _Producer()
    producer.start(*active)
    producer.end(beta, "call", "failed")
    producer.start(N_PASS, "setup")  # the producer has stopped: nothing more is written
    producer.end(N_PASS, "setup", "passed")
    producer.finish(1)
    _assert_fails_closed_with_phase_order(producer, [identity(active[0])["label"], identity(beta)["label"]])


def test_producer_end_without_an_active_phase_fails_closed():
    beta = "tests/test_oracle_p.py::test_beta"
    producer = _Producer()
    producer.end(beta, "call", "failed")
    producer.start(N_PASS, "setup")  # the producer has stopped: nothing more is written
    producer.end(N_PASS, "setup", "passed")
    producer.finish(1)
    _assert_fails_closed_with_phase_order(producer, [identity(beta)["label"]])


@pytest.mark.parametrize(
    "nodeid", [N_FAIL, "tests/test_a.py::test_p[é]"], ids=["plain", "unicode_param"]
)
def test_producer_unfinished_phase_error_names_node_phase_and_label(nodeid):
    producer = _Producer()
    producer.start(nodeid, "setup")
    producer.end(nodeid, "setup", "passed")
    producer.start(nodeid, "call")
    producer.finish(0)
    records = producer.records()
    for rec in records:
        assert appendix_a_problems(rec) == [], rec
    errors = [rec for rec in records if rec["event"] == "ERROR"]
    assert len(errors) == 1
    ident = identity(nodeid)
    error = errors[0]
    assert set(error) == {"v", "seq", "event", "reason", "incomplete", "node", "phase", "label"}
    assert error["reason"] == "UNFINISHED_PHASE" and error["incomplete"] is True
    assert (error["node"], error["phase"], error["label"]) == (ident["node"], "call", ident["label"])
    session_end = records[-1]
    assert session_end["event"] == "SESSION_END"
    assert (session_end["starts"], session_end["ends"]) == (2, 1)


def test_graceful_finish_with_an_open_phase_reads_as_unfinished_and_count_mismatch():
    producer = _Producer()
    producer.start(N_FAIL, "setup")
    producer.end(N_FAIL, "setup", "passed")
    producer.start(N_FAIL, "call")
    producer.finish(0)
    summary = summarize(producer.sink.stream())
    assert summary["incompleteReasons"] == ["COUNT_MISMATCH", "PRODUCER_INCOMPLETE", "UNFINISHED_PHASE"]
    ident = identity(N_FAIL)
    assert_exact(summary["latestActive"], {"node": ident["node"], "phase": "call", "label": ident["label"]})
    assert (summary["starts"], summary["ends"]) == (2, 1)


def test_latest_active_is_none_before_finish_from_an_empty_stream():
    producer = _Producer()
    producer.start(N_FAIL, "setup")
    summary = summarize(producer.sink.stream())
    assert summary["latestActive"] is None
    assert summary["incompleteReasons"] == ["NO_COMPLETION", "NO_DIAGNOSTICS"]


def test_producer_session_end_members_and_in_memory_starts_count():
    producer = run_script(MIXED_SCRIPT)
    session_end = producer.records()[-1]
    assert set(session_end) == {
        "v", "seq", "event", "tUs", "exitCode", "incomplete", "reasons", "starts", "ends", "failed", "skipped",
        "dropped",
    }
    assert appendix_a_problems(session_end) == []
    assert session_end["starts"] == producer.start_calls == 19
    assert session_end["ends"] == 19
    assert session_end["failed"] == 3
    assert session_end["skipped"] == 2
    assert (session_end["incomplete"], session_end["reasons"], session_end["dropped"]) == (False, [], 0)


def test_producer_starts_counts_start_calls_not_records():
    producer = _Producer()
    producer.start(N_PASS, "setup")
    producer.end(N_PASS, "setup", "passed")
    producer.start(N_PASS, "call")
    producer.end(N_PASS, "call", "passed")
    producer.start(N_PASS, "teardown")
    producer.finish(0)
    records = producer.records()
    assert all(rec["event"] != "START" for rec in records)
    session_end = records[-1]
    assert (session_end["starts"], session_end["ends"]) == (3, 2)


def test_producer_stream_reads_back_complete():
    producer = run_script(MIXED_SCRIPT)
    records = producer.records()
    summary = summarize(producer.sink.stream())
    assert summary["status"] == "COMPLETE", summary["incompleteReasons"]
    assert (summary["records"], summary["ends"], summary["failed"], summary["skipped"], summary["starts"]) == (
        20, 19, 3, 2, 19,
    )
    failed_ends = [rec for rec in records if rec["event"] == "END" and rec["outcome"] == "failed"]
    assert_exact(
        summary["failures"],
        [{k: rec[k] for k in ("node", "phase", "tUs", "outcome", "durationUs", "xfail", "label")} for rec in failed_ends],
        "failures",
    )
    last_end = [rec for rec in records if rec["event"] == "END"][-1]
    want_last = {k: last_end[k] for k in ("node", "phase", "tUs", "outcome", "durationUs", "xfail")}
    want_last["event"] = "END"
    if "label" in last_end:
        want_last["label"] = last_end["label"]
    assert_exact(summary["lastPhase"], want_last, "lastPhase")


def test_producer_writes_one_error_per_stream():
    producer = _Producer()
    producer.start(N_PASS, "not-a-phase")
    producer.start(N_FAIL, "setup")
    producer.end(N_FAIL, "setup", "passed")
    producer.start(N_FAIL, "call")
    producer.finish(0)
    records = producer.records()
    for rec in records:
        assert appendix_a_problems(rec) == [], rec
    errors = [rec for rec in records if rec["event"] == "ERROR"]
    assert len(errors) == 1
    assert errors[0]["reason"] != "UNFINISHED_PHASE"
    summary = summarize(producer.sink.stream())
    assert summary["latestActive"] is None
    assert summary["status"] == "INCOMPLETE"
    assert "PRODUCER_INCOMPLETE" in summary["incompleteReasons"]


# ===============================================================================================================
# Record rules (Appendix A, Records)
# ===============================================================================================================

BASES = {
    "END_passed": end_rec(),
    "END_failed": end_rec(outcome="failed"),
    "END_skipped": end_rec(outcome="skipped"),
    "ERROR": error_rec(),
    "ERROR_unfinished": unfinished_rec(),
    "SESSION_END": session_end_rec(),
}


@pytest.mark.parametrize("name", sorted(BASES))
def test_base_records_are_valid(name):
    assert appendix_a_problems(BASES[name]) == []
    assert_valid(BASES[name])


@pytest.mark.parametrize(
    "name_member",
    [(name, member) for name in sorted(BASES) for member in sorted(BASES[name])],
    ids=lambda nm: f"{nm[0]}-{nm[1]}",
)
def test_each_member_is_required(name_member):
    name, member = name_member
    assert_malformed(mutate(BASES[name], **{member: _DROP}))


@pytest.mark.parametrize("name", sorted(BASES))
def test_an_extra_member_is_malformed(name):
    assert_malformed(mutate(BASES[name], extra=1))


@pytest.mark.parametrize(
    "rec",
    [
        {"v": 2, "seq": 1, "event": "START", "node": NODE_A, "phase": "call", "tUs": 1},
        {"v": 2, "seq": 1, "event": "START", "node": NODE_A, "phase": "call", "tUs": 1, "label": LABEL_A},
        {"v": 2, "seq": 1, "event": "START", "label": LABEL_A},
        mutate(end_rec(), event="START"),
    ],
    ids=["v1_shape", "v1_shape_with_label", "label_only", "end_members"],
)
def test_start_record_is_malformed(rec):
    assert_malformed(rec)


def test_start_records_in_a_stream_are_malformed_and_ends_still_count():
    start = {"v": 2, "seq": 1, "event": "START", "node": NODE_A, "phase": "call", "tUs": 5, "label": LABEL_A}
    summary = summarize(stream(start, end_rec(1, 10), session_end_rec(2, 20, ends=1)))
    assert summary["incompleteReasons"] == ["MALFORMED_RECORD"]
    assert (summary["malformed"], summary["records"], summary["ends"]) == (1, 2, 1)


@pytest.mark.parametrize("event", ["BEGIN", "end", "End", "SESSION_START", "", None, 1], ids=repr)
def test_unknown_event_is_malformed(event):
    assert_malformed(mutate(end_rec(), event=event))


@pytest.mark.parametrize("version", [1, 3, 0, "2", 2.0, True, None, [2]], ids=repr)
def test_version_other_than_integer_2_is_malformed(version):
    assert_malformed(mutate(end_rec(), v=version))


INT_MEMBERS = [
    ("END_passed", "seq"),
    ("END_passed", "tUs"),
    ("END_passed", "durationUs"),
    ("ERROR", "seq"),
    ("SESSION_END", "seq"),
    ("SESSION_END", "tUs"),
    ("SESSION_END", "exitCode"),
    ("SESSION_END", "starts"),
    ("SESSION_END", "ends"),
    ("SESSION_END", "failed"),
    ("SESSION_END", "skipped"),
    ("SESSION_END", "dropped"),
]


@pytest.mark.parametrize("name_member", INT_MEMBERS, ids=lambda nm: f"{nm[0]}-{nm[1]}")
def test_integer_member_accepts_a_json_integer(name_member):
    name, member = name_member
    assert_valid(mutate(BASES[name], **{member: 1}))


@pytest.mark.parametrize("name_member", INT_MEMBERS, ids=lambda nm: f"{nm[0]}-{nm[1]}")
def test_integer_member_refuses_true(name_member):
    name, member = name_member
    assert_malformed(mutate(BASES[name], **{member: True}))


@pytest.mark.parametrize("name_member", INT_MEMBERS, ids=lambda nm: f"{nm[0]}-{nm[1]}")
def test_integer_member_refuses_a_float(name_member):
    name, member = name_member
    assert_malformed(mutate(BASES[name], **{member: 1.0}))


BOUNDS = [
    ("END_passed", "seq", 1, MAX_EVENTS),
    ("END_passed", "tUs", 0, INT_MAX),
    ("END_passed", "durationUs", 0, INT_MAX),
    ("SESSION_END", "tUs", 0, INT_MAX),
    ("SESSION_END", "exitCode", 0, 255),
] + [("SESSION_END", member, 0, COUNT_MAX) for member in ("starts", "ends", "failed", "skipped", "dropped")]


@pytest.mark.parametrize("bound", BOUNDS, ids=lambda b: f"{b[0]}-{b[1]}")
def test_integer_bounds_are_inclusive(bound):
    name, member, low, high = bound
    assert_valid(mutate(BASES[name], **{member: low}))
    assert_valid(mutate(BASES[name], **{member: high}))


@pytest.mark.parametrize("bound", BOUNDS, ids=lambda b: f"{b[0]}-{b[1]}")
def test_integer_outside_its_bounds_is_malformed(bound):
    name, member, low, high = bound
    assert_malformed(mutate(BASES[name], **{member: low - 1}))
    assert_malformed(mutate(BASES[name], **{member: high + 1}))


def test_end_label_present_exactly_when_outcome_is_not_passed():
    assert_valid(end_rec(outcome="passed"))
    assert_valid(end_rec(outcome="failed"))
    assert_valid(end_rec(outcome="skipped"))
    assert_malformed(end_rec(outcome="passed", label=LABEL_A))
    assert_malformed(end_rec(outcome="passed", xfail=True, label=LABEL_A))
    assert_malformed(end_rec(outcome="failed", label=_DROP))
    assert_malformed(end_rec(outcome="skipped", label=_DROP))
    assert_malformed(end_rec(outcome="skipped", xfail=True, label=_DROP))


HOSTILE_LABELS = [
    ("over_70", "f" * 32 + "::test_" + "s" * 32),
    ("plain_71", "a" * 71),
    ("file_part_33", "f" * 33 + "::test_a"),
    ("no_test_prefix", "a.py::tst_x"),
    ("single_colon", "a.py:test_x"),
    ("empty_file_part", "::test_x"),
    ("empty", ""),
    ("trailing_newline", "a.py::test_x\n"),
    ("nul", "a.py::test_\x00x"),
    ("tab", "a.py::test_x\t"),
    ("ansi_escape", "\x1b[31ma.py::test_x"),
    ("del_char", "a.py::test_x\x7f"),
    ("non_ascii_letter", "é.py::test_x"),
    ("non_ascii_digit", "a.py::test_١"),
    ("slash", "a/b.py::test_x"),
    ("space", "a b.py::test_x"),
    ("brackets", "a.py::test_x[1]"),
    ("redacted_newline", REDACTED + "\n"),
    ("redacted_upper", "<REDACTED-NODE>"),
    ("redacted_suffix", REDACTED + "x"),
    ("int", 5),
    ("none", None),
    ("list", ["a.py::test_x"]),
    ("bool", True),
    ("object", {"a": "b"}),
]
VALID_LABELS = [
    ("redacted", REDACTED),
    ("minimal", "a::test_"),
    ("max_70", "f" * 32 + "::test_" + "s" * 31),
    ("all_classes", "Az09_.-::test_Az09_"),
    ("ordinary", LABEL_A),
]


@pytest.mark.parametrize("label", [v for _, v in HOSTILE_LABELS], ids=[k for k, _ in HOSTILE_LABELS])
def test_hostile_label_on_an_end_is_malformed(label):
    assert_malformed(end_rec(outcome="failed", label=label))


@pytest.mark.parametrize("label", [v for _, v in HOSTILE_LABELS], ids=[k for k, _ in HOSTILE_LABELS])
def test_hostile_label_on_an_unfinished_error_is_malformed(label):
    assert_malformed(unfinished_rec(label=label))


@pytest.mark.parametrize("label", [v for _, v in VALID_LABELS], ids=[k for k, _ in VALID_LABELS])
def test_valid_label_is_accepted_on_an_end_and_an_unfinished_error(label):
    assert len(label) <= 70
    assert_valid(end_rec(outcome="failed", label=label))
    assert_valid(end_rec(outcome="skipped", label=label))
    assert_valid(unfinished_rec(label=label))


HOSTILE_NODES = [
    ("upper_hex", NODE_A.upper()),
    ("short_63", NODE_A[:63]),
    ("long_65", NODE_A + "0"),
    ("non_hex", "g" * 64),
    ("hex_prefix", "0x" + NODE_A[:62]),
    ("plus_sign", "+" + NODE_A[:63]),
    ("underscore", NODE_A[:32] + "_" + NODE_A[33:]),
    ("space", " " + NODE_A[1:]),
    ("trailing_newline", NODE_A[:63] + "\n"),
    ("non_ascii_digit", NODE_A[:63] + "١"),
    ("fullwidth_digits", "０" * 64),
    ("int", 123),
    ("none", None),
    ("list", [NODE_A]),
]


def test_hostile_node_fixture_differs_from_the_valid_node():
    assert NODE_A.upper() != NODE_A


@pytest.mark.parametrize("node", [v for _, v in HOSTILE_NODES], ids=[k for k, _ in HOSTILE_NODES])
def test_hostile_node_on_an_end_is_malformed(node):
    assert_malformed(end_rec(node=node))


@pytest.mark.parametrize("node", [v for _, v in HOSTILE_NODES], ids=[k for k, _ in HOSTILE_NODES])
def test_hostile_node_on_an_unfinished_error_is_malformed(node):
    assert_malformed(unfinished_rec(node=node))


HOSTILE_PHASES = ["Call", "CALL", "call\n", " call", "", "collect", "run", None, 1, ["call"]]


@pytest.mark.parametrize("phase", PHASES)
def test_each_stated_phase_is_accepted(phase):
    assert_valid(end_rec(phase=phase))
    assert_valid(unfinished_rec(phase=phase))


@pytest.mark.parametrize("phase", HOSTILE_PHASES, ids=repr)
def test_unknown_phase_on_an_end_is_malformed(phase):
    assert_malformed(end_rec(phase=phase))


@pytest.mark.parametrize("phase", HOSTILE_PHASES, ids=repr)
def test_unknown_phase_on_an_unfinished_error_is_malformed(phase):
    assert_malformed(unfinished_rec(phase=phase))


@pytest.mark.parametrize("outcome", ["error", "xfailed", "Passed", "", None, 1, True], ids=repr)
def test_unknown_outcome_is_malformed(outcome):
    assert_malformed(end_rec(outcome="failed") | {"outcome": outcome})


@pytest.mark.parametrize("xfail", [True, False])
def test_boolean_xfail_is_accepted(xfail):
    assert_valid(end_rec(xfail=xfail))


@pytest.mark.parametrize("xfail", [0, 1, "false", "true", None], ids=repr)
def test_non_boolean_xfail_is_malformed(xfail):
    assert_malformed(end_rec(xfail=xfail))


@pytest.mark.parametrize("reason", PRODUCER_REASONS)
def test_error_accepts_each_of_the_eleven_producer_reasons(reason):
    if reason == "UNFINISHED_PHASE":
        assert_valid(unfinished_rec())
    else:
        assert_valid(error_rec(reason=reason))


@pytest.mark.parametrize(
    "reason", list(READER_ONLY_REASONS) + ["unfinished_phase", "START", "", None, 1], ids=repr
)
def test_error_refuses_reader_and_unknown_reasons(reason):
    assert_malformed(error_rec(reason=reason))


@pytest.mark.parametrize("incomplete", [False, 1, "true", None], ids=repr)
def test_error_incomplete_must_be_true(incomplete):
    assert_malformed(error_rec(incomplete=incomplete))
    assert_malformed(unfinished_rec() | {"incomplete": incomplete})


@pytest.mark.parametrize(
    "extra",
    [{"node": NODE_A}, {"phase": "call"}, {"label": LABEL_A}, {"node": NODE_A, "phase": "call", "label": LABEL_A}],
    ids=["node", "phase", "label", "all_three"],
)
def test_error_other_than_unfinished_phase_refuses_the_active_members(extra):
    assert_malformed(error_rec(reason="SINK", **extra))
    assert_malformed(error_rec(reason="PHASE_ORDER", **extra))


@pytest.mark.parametrize(
    "reasons",
    [[], list(PRODUCER_REASONS), ["SINK"] * 11, ["UNFINISHED_PHASE"], ["PHASE_ORDER", "PHASE_ORDER"]],
    ids=["empty", "all_eleven", "eleven_repeated", "unfinished", "repeated_pair"],
)
def test_session_end_reasons_accepted(reasons):
    assert_valid(session_end_rec(reasons=reasons))


@pytest.mark.parametrize(
    "reasons",
    [
        ["SINK"] * 12,
        list(PRODUCER_REASONS) + ["SINK"],
        ["NO_COMPLETION"],
        ["MALFORMED_RECORD"],
        ["sink"],
        "SINK",
        [1],
        None,
        [None],
        {"SINK": 1},
        [["SINK"]],
    ],
    ids=[
        "twelve_repeated", "twelve_distinct_plus", "reader_reason", "reader_reason_2", "lowercase", "string",
        "int_item", "none", "none_item", "object", "nested_list",
    ],
)
def test_session_end_reasons_refused(reasons):
    assert_malformed(session_end_rec(reasons=reasons))


@pytest.mark.parametrize("incomplete", [True, False])
def test_session_end_boolean_incomplete_accepted(incomplete):
    assert_valid(session_end_rec(incomplete=incomplete))


@pytest.mark.parametrize("incomplete", [0, 1, "false", None], ids=repr)
def test_session_end_non_boolean_incomplete_refused(incomplete):
    assert_malformed(session_end_rec(incomplete=incomplete))


def test_duplicate_keys_are_refused():
    body = json.dumps(end_rec(), separators=(",", ":"))
    assert_valid(PREFIX_BYTES + body.encode() + b"\n")
    assert_malformed(PREFIX_BYTES + ('{"seq":1,' + body[1:]).encode() + b"\n")
    assert_malformed(PREFIX_BYTES + (body[:-1] + ',"xfail":false}').encode() + b"\n")
    session_body = json.dumps(session_end_rec(), separators=(",", ":"))
    assert_malformed(PREFIX_BYTES + (session_body[:-1] + ',"reasons":[]}').encode() + b"\n")


@pytest.mark.parametrize(
    "body",
    [
        b"[1,2]",
        b'"END"',
        b"2",
        b"null",
        b"true",
        b"",
        b"{",
        b'{"v":2,',
        b"{v:2}",
        b"{'v':2}",
        b"NaN",
        json.dumps(end_rec(), separators=(",", ":")).encode() + b"garbage",
        json.dumps(end_rec(), separators=(",", ":")).replace('"tUs":10', '"tUs":NaN').encode(),
        json.dumps(end_rec(), separators=(",", ":")).replace('"durationUs":7', '"durationUs":Infinity').encode(),
        json.dumps(end_rec(), separators=(",", ":")).replace('"tUs":10', '"tUs":1e1').encode(),
        b"\xff\xfe\xfd",
    ],
    ids=[
        "array", "string", "number", "null", "true", "empty", "open_brace", "truncated", "bare_key", "single_quotes",
        "nan", "trailing_garbage", "nan_member", "infinity_member", "exponent_member", "bad_bytes",
    ],
)
def test_bad_json_and_non_object_bodies_are_malformed(body):
    assert_malformed(PREFIX_BYTES + body + b"\n")


@pytest.mark.parametrize("codec", ["utf-16-le", "utf-16-be", "utf-32-le", "utf-32-be"])
def test_utf16_and_utf32_bodies_are_read_by_their_leading_bytes(codec):
    body = json.dumps(end_rec(), separators=(",", ":")).encode(codec)
    assert b"\n" not in body
    data = PREFIX_BYTES + body + b"\n"
    assert len(data) <= MAX_RECORD_BYTES
    assert_valid(data)


def _padded_line(rec, total):
    body = json.dumps(rec, separators=(",", ":")).encode("ascii")
    pad = total - len(PREFIX_BYTES) - len(body) - 1
    assert pad >= 0
    padded = PREFIX_BYTES + b"{" + b" " * pad + body[1:] + b"\n"
    assert len(padded) == total
    return padded


def test_prefixed_line_of_exactly_the_record_byte_cap_with_its_newline_is_valid():
    assert_valid(_padded_line(end_rec(), MAX_RECORD_BYTES))
    assert_valid(_padded_line(end_rec(outcome="failed"), MAX_RECORD_BYTES))


def test_prefixed_line_one_byte_over_the_record_byte_cap_is_malformed():
    assert_malformed(_padded_line(end_rec(), MAX_RECORD_BYTES + 1))
    assert_malformed(_padded_line(end_rec(outcome="failed"), MAX_RECORD_BYTES + 1))


def test_record_byte_cap_does_not_apply_to_lines_without_the_prefix():
    summary = summarize(b"x" * 5000 + b"\n" + stream(*good_records()))
    assert summary["status"] == "COMPLETE", summary["incompleteReasons"]
    assert (summary["nonDiagnosticLines"], summary["malformed"], summary["records"]) == (1, 0, 4)


def test_malformed_line_is_counted_and_the_scan_continues():
    records = good_records()
    summary = summarize(stream(records[0], PREFIX_BYTES + b"{bad\n", *records[1:]))
    assert summary["incompleteReasons"] == ["MALFORMED_RECORD"]
    assert (summary["records"], summary["malformed"], summary["ends"]) == (4, 1, 3)


@pytest.mark.parametrize(
    "hostile",
    [
        end_rec(2, 20, "failed", label="ZZMARK\x1b[2J::test_x"),
        end_rec(2, 20, "failed", label="ZZMARK.py::test_" + "q" * 60),
        end_rec(2, 20, node="ZZMARK" + "0" * 58),
        end_rec(2, 20, phase="ZZMARK"),
        unfinished_rec(2, label="ZZMARK::test_\n"),
        unfinished_rec(2, phase="ZZMARK"),
        error_rec(2, reason="ZZMARK"),
        {"v": 2, "seq": 2, "event": "ZZMARK"},
        session_end_rec(2, 20, ends=1, reasons=["ZZMARK"]),
    ],
    ids=[
        "end_label_escape", "end_label_long", "end_node", "end_phase", "error_label", "error_phase", "error_reason",
        "event", "session_end_reason",
    ],
)
def test_malformed_record_text_does_not_reach_the_summary(hostile):
    summary = summarize(stream(end_rec(1, 10), hostile))
    assert summary["malformed"] == 1
    assert "MALFORMED_RECORD" in summary["incompleteReasons"]
    assert "ZZMARK" not in json.dumps(summary)


# ===============================================================================================================
# The reader (Appendix A, Reader)
# ===============================================================================================================


def test_complete_stream_summary_is_exact():
    data = stream(*good_records())
    summary = summarize(data)
    assert_exact(
        summary,
        expected_summary(
            status="COMPLETE",
            inputBytes=len(data),
            scannedBytes=len(data),
            records=4,
            completionSeen=True,
            lastPhase={
                "event": "END", "node": NODE_A, "phase": "teardown", "tUs": 30, "outcome": "passed",
                "durationUs": 7, "xfail": False,
            },
            starts=3,
            ends=3,
            sessionEnd={"exitCode": 0, "incomplete": False, "reasons": [], "dropped": 0},
        ),
        "summary",
    )


def test_empty_bytes_summary_has_every_member_at_its_initial_value():
    assert_exact(summarize(b""), expected_summary(incompleteReasons=["NO_COMPLETION", "NO_DIAGNOSTICS"]), "summary")


def test_empty_str_summary_has_every_member_at_its_initial_value():
    assert_exact(summarize(""), expected_summary(incompleteReasons=["NO_COMPLETION", "NO_DIAGNOSTICS"]), "summary")


def test_none_input_is_absent_with_initial_values():
    assert_exact(
        summarize(None),
        expected_summary(status="ABSENT", available=False, incompleteReasons=["NO_DIAGNOSTICS"]),
        "summary",
    )


class _StrSubclass(str):
    pass


class _BytesSubclass(bytes):
    pass


_VALID_STREAM = stream(*good_records())


@pytest.mark.parametrize(
    "value",
    [
        bytearray(_VALID_STREAM),
        _StrSubclass(_VALID_STREAM.decode("ascii")),
        _BytesSubclass(_VALID_STREAM),
        memoryview(_VALID_STREAM),
        0,
        [_VALID_STREAM],
    ],
    ids=["bytearray", "str_subclass", "bytes_subclass", "memoryview", "int", "list"],
)
def test_inexact_input_type_is_invalid_input_with_initial_values(value):
    assert_exact(
        summarize(value),
        expected_summary(status="INCOMPLETE", available=True, incompleteReasons=["INVALID_INPUT"]),
        "summary",
    )


def test_exact_bytes_and_str_inputs_read_the_same():
    from_bytes = summarize(_VALID_STREAM)
    from_str = summarize(_VALID_STREAM.decode("ascii"))
    assert from_bytes == from_str
    assert from_str["status"] == "COMPLETE"


def test_str_input_is_utf8_encoded_with_replacement():
    text = "naïve \ud800 line\n" + _VALID_STREAM.decode("ascii")
    summary = summarize(text)
    encoded = len(text.encode("utf-8", "replace"))
    assert (summary["inputBytes"], summary["scannedBytes"], summary["inputTruncatedBytes"]) == (encoded, encoded, 0)
    assert summary["status"] == "COMPLETE", summary["incompleteReasons"]
    assert (summary["nonDiagnosticLines"], summary["records"]) == (1, 4)


def test_input_limit_keeps_the_tail_from_the_byte_after_its_first_newline():
    tail_stream = stream(*good_records())
    total = MAX_SCAN_BYTES + 100
    head = b"a" * 10 + b"\n" + b"a" * 139 + b"\n"  # newlines at offsets 10 (cut away) and 150 (in the tail)
    filler = total - len(head) - 1 - len(tail_stream)
    data = head + b"b" * filler + b"\n" + tail_stream
    assert len(data) == total
    summary = summarize(data)
    assert summary["inputBytes"] == total
    assert summary["scannedBytes"] == total - 151
    assert summary["inputTruncatedBytes"] == 151
    assert summary["incompleteReasons"] == ["INPUT_LIMIT"]
    assert (summary["records"], summary["nonDiagnosticLines"], summary["malformed"]) == (4, 1, 0)


def test_input_limit_with_no_newline_in_the_tail_keeps_nothing():
    data = b"\n" + b"z" * MAX_SCAN_BYTES
    summary = summarize(data)
    assert summary["inputBytes"] == MAX_SCAN_BYTES + 1
    assert summary["scannedBytes"] == 0
    assert summary["inputTruncatedBytes"] == MAX_SCAN_BYTES + 1
    assert summary["incompleteReasons"] == ["INPUT_LIMIT", "NO_COMPLETION", "NO_DIAGNOSTICS"]
    assert (summary["records"], summary["nonDiagnosticLines"]) == (0, 0)


def test_input_of_exactly_the_scan_byte_cap_is_not_cut():
    tail_stream = stream(*good_records())
    exact = b"b" * (MAX_SCAN_BYTES - 1 - len(tail_stream)) + b"\n" + tail_stream
    assert len(exact) == MAX_SCAN_BYTES
    summary = summarize(exact)
    assert summary["status"] == "COMPLETE", summary["incompleteReasons"]
    assert (summary["inputBytes"], summary["scannedBytes"], summary["inputTruncatedBytes"]) == (
        MAX_SCAN_BYTES, MAX_SCAN_BYTES, 0,
    )
    assert (summary["nonDiagnosticLines"], summary["records"]) == (1, 4)


def test_input_one_byte_over_the_scan_byte_cap_is_cut():
    tail_stream = stream(*good_records())
    over = b"b" * (MAX_SCAN_BYTES - len(tail_stream)) + b"\n" + tail_stream
    assert len(over) == MAX_SCAN_BYTES + 1
    summary = summarize(over)
    assert summary["incompleteReasons"] == ["INPUT_LIMIT"]
    assert summary["scannedBytes"] == len(tail_stream)
    assert summary["inputTruncatedBytes"] == MAX_SCAN_BYTES + 1 - len(tail_stream)
    assert (summary["nonDiagnosticLines"], summary["records"]) == (0, 4)


def test_exactly_the_line_cap_is_scanned_without_scan_limit():
    data = stream(*good_records()) + b"#\n" * (MAX_SCAN_LINES - 4)
    summary = summarize(data)
    assert summary["status"] == "COMPLETE", summary["incompleteReasons"]
    assert summary["nonDiagnosticLines"] == MAX_SCAN_LINES - 4


def test_more_input_after_the_line_cap_adds_scan_limit():
    data = stream(*good_records()) + b"#\n" * (MAX_SCAN_LINES - 4 + 1)
    summary = summarize(data)
    assert summary["incompleteReasons"] == ["SCAN_LIMIT"]
    assert summary["nonDiagnosticLines"] == MAX_SCAN_LINES - 4
    assert summary["scannedBytes"] == summary["inputBytes"] == len(data)


def test_final_line_without_newline_adds_partial_line_and_stops():
    data = stream(*good_records()) + line(end_rec(5, 50))[:-1]
    summary = summarize(data)
    assert summary["incompleteReasons"] == ["PARTIAL_LINE"]
    assert (summary["records"], summary["malformed"], summary["ends"]) == (4, 0, 3)
    assert summary["scannedBytes"] == summary["inputBytes"] == len(data)


def test_partial_session_end_line_gives_partial_line_and_no_completion():
    records = good_records()
    data = stream(*records[:3]) + line(records[3])[:-5]
    summary = summarize(data)
    assert summary["incompleteReasons"] == ["NO_COMPLETION", "PARTIAL_LINE"]
    assert summary["records"] == 3


def test_contiguous_seq_has_no_sequence_gap():
    assert summarize(stream(*good_records()))["incompleteReasons"] == []


def test_skipped_seq_adds_sequence_gap():
    summary = summarize(stream(end_rec(1, 10), end_rec(3, 20), session_end_rec(4, 30, ends=2)))
    assert summary["incompleteReasons"] == ["SEQUENCE_GAP"]


def test_repeated_seq_adds_sequence_gap():
    summary = summarize(stream(end_rec(1, 10), end_rec(1, 20), session_end_rec(2, 30, ends=2)))
    assert summary["incompleteReasons"] == ["SEQUENCE_GAP"]


def test_equal_tus_is_not_time_order():
    summary = summarize(stream(end_rec(1, 20), end_rec(2, 20), session_end_rec(3, 20, ends=2)))
    assert summary["incompleteReasons"] == []


def test_tus_below_the_previous_adds_time_order():
    summary = summarize(stream(end_rec(1, 20), end_rec(2, 10), session_end_rec(3, 30, ends=2)))
    assert summary["incompleteReasons"] == ["TIME_ORDER"]


def test_session_end_tus_below_the_last_end_adds_time_order():
    summary = summarize(stream(end_rec(1, 20), session_end_rec(2, 10, ends=1)))
    assert summary["incompleteReasons"] == ["TIME_ORDER"]


def test_second_session_end_adds_after_completion():
    summary = summarize(stream(*good_records(), session_end_rec(5, 50, ends=3)))
    assert summary["incompleteReasons"] == ["AFTER_COMPLETION"]
    assert (summary["records"], summary["completionSeen"]) == (5, True)


def test_end_after_session_end_adds_after_completion():
    summary = summarize(stream(*good_records(), end_rec(5, 50)))
    assert "AFTER_COMPLETION" in summary["incompleteReasons"]
    assert summary["status"] == "INCOMPLETE"


@pytest.mark.parametrize("reason", [r for r in PRODUCER_REASONS if r != "UNFINISHED_PHASE"])
def test_error_record_adds_producer_incomplete(reason):
    summary = summarize(stream(end_rec(1, 10), error_rec(2, reason), session_end_rec(3, 20, ends=1)))
    assert summary["incompleteReasons"] == ["PRODUCER_INCOMPLETE"]
    assert summary["latestActive"] is None
    assert summary["records"] == 3


@pytest.mark.parametrize(
    "change", [{"incomplete": True}, {"reasons": ["SINK"]}, {"dropped": 1}], ids=["incomplete", "reasons", "dropped"]
)
def test_session_end_mark_adds_producer_incomplete(change):
    records = good_records()
    records[-1] = mutate(records[-1], **change)
    summary = summarize(stream(*records))
    assert summary["incompleteReasons"] == ["PRODUCER_INCOMPLETE"]


def test_exit_code_alone_adds_no_reason():
    records = good_records()
    records[-1] = mutate(records[-1], exitCode=1)
    summary = summarize(stream(*records))
    assert summary["status"] == "COMPLETE"
    assert summary["sessionEnd"]["exitCode"] == 1


def _outcome_records():
    return [
        end_rec(1, 10, "passed", "setup"),
        end_rec(2, 20, "failed", "call"),
        end_rec(3, 30, "skipped", "teardown"),
        session_end_rec(4, 40, ends=3, failed=1, skipped=1),
    ]


def test_matching_counts_are_complete():
    summary = summarize(stream(*_outcome_records()))
    assert summary["status"] == "COMPLETE", summary["incompleteReasons"]
    assert (summary["ends"], summary["failed"], summary["skipped"], summary["starts"]) == (3, 1, 1, 3)


@pytest.mark.parametrize(
    "change",
    [
        {"ends": 2, "starts": 2},
        {"ends": 4, "starts": 4},
        {"failed": 0},
        {"failed": 2},
        {"skipped": 0},
        {"skipped": 2},
        {"starts": 4},
        {"starts": 2},
    ],
    ids=["ends_low", "ends_high", "failed_low", "failed_high", "skipped_low", "skipped_high", "starts_high",
         "starts_low"],
)
def test_count_mismatch(change):
    records = _outcome_records()
    records[-1] = mutate(records[-1], **change)
    summary = summarize(stream(*records))
    assert summary["incompleteReasons"] == ["COUNT_MISMATCH"]


def test_starts_is_copied_from_session_end_and_ends_are_counted():
    records = good_records()
    records[-1] = mutate(records[-1], starts=7, ends=5)
    summary = summarize(stream(*records))
    assert (summary["starts"], summary["ends"]) == (7, 3)
    assert summary["incompleteReasons"] == ["COUNT_MISMATCH"]


def test_session_end_summary_member_holds_exactly_four_members():
    records = good_records()
    records[-1] = mutate(records[-1], exitCode=3, incomplete=True, reasons=["SINK", "SINK"], dropped=2)
    summary = summarize(stream(*records))
    assert_exact(summary["sessionEnd"], {"exitCode": 3, "incomplete": True, "reasons": ["SINK", "SINK"], "dropped": 2})
    assert summary["incompleteReasons"] == ["PRODUCER_INCOMPLETE"]


def _failed_stream(count):
    records = [end_rec(i + 1, 10 * (i + 1), "failed", "call") for i in range(count)]
    records.append(session_end_rec(count + 1, 10 * (count + 1), ends=count, failed=count))
    return stream(*records)


def test_sixteen_failures_are_kept_without_a_reason():
    summary = summarize(_failed_stream(MAX_FAILURES))
    assert summary["status"] == "COMPLETE", summary["incompleteReasons"]
    assert (len(summary["failures"]), summary["failuresOmitted"]) == (16, 0)


def test_seventeenth_failure_is_omitted_with_failure_detail_limit():
    summary = summarize(_failed_stream(MAX_FAILURES + 1))
    assert summary["incompleteReasons"] == ["FAILURE_DETAIL_LIMIT"]
    assert (len(summary["failures"]), summary["failuresOmitted"], summary["failed"]) == (16, 1, 17)
    assert [item["tUs"] for item in summary["failures"]] == [10 * (i + 1) for i in range(16)]


def test_failure_item_and_last_phase_members():
    records = [
        end_rec(1, 10, "failed", "setup", duration_us=3, xfail=True),
        end_rec(2, 20, "passed", "teardown", duration_us=4),
        session_end_rec(3, 30, ends=2, failed=1),
    ]
    summary = summarize(stream(*records))
    assert_exact(
        summary["failures"],
        [{"node": NODE_A, "phase": "setup", "tUs": 10, "outcome": "failed", "durationUs": 3, "xfail": True,
          "label": LABEL_A}],
        "failures",
    )
    assert_exact(
        summary["lastPhase"],
        {"event": "END", "node": NODE_A, "phase": "teardown", "tUs": 20, "outcome": "passed", "durationUs": 4,
         "xfail": False},
        "lastPhase",
    )


def test_last_phase_carries_the_label_of_a_non_passed_last_end():
    records = [
        end_rec(1, 10),
        end_rec(2, 20, "skipped", "call", node=NODE_B, label=LABEL_B),
        session_end_rec(3, 30, ends=2, skipped=1),
    ]
    summary = summarize(stream(*records))
    assert_exact(
        summary["lastPhase"],
        {"event": "END", "node": NODE_B, "phase": "call", "tUs": 20, "outcome": "skipped", "durationUs": 7,
         "xfail": False, "label": LABEL_B},
        "lastPhase",
    )
    assert summary["failures"] == []


def test_unfinished_phase_error_record_sets_latest_active():
    records = [end_rec(1, 10, phase="setup"), unfinished_rec(2, NODE_B, "call", LABEL_B), session_end_rec(3, 20, ends=1)]
    summary = summarize(stream(*records))
    assert summary["incompleteReasons"] == ["PRODUCER_INCOMPLETE", "UNFINISHED_PHASE"]
    assert_exact(summary["latestActive"], {"node": NODE_B, "phase": "call", "label": LABEL_B}, "latestActive")


def test_unfinished_phase_from_session_end_reasons_alone():
    records = [end_rec(1, 10), session_end_rec(2, 20, ends=1, reasons=["UNFINISHED_PHASE"])]
    summary = summarize(stream(*records))
    assert summary["incompleteReasons"] == ["PRODUCER_INCOMPLETE", "UNFINISHED_PHASE"]
    assert summary["latestActive"] is None


def test_no_session_end_adds_no_completion():
    summary = summarize(stream(end_rec(1, 10)))
    assert summary["incompleteReasons"] == ["NO_COMPLETION"]
    assert (summary["completionSeen"], summary["sessionEnd"], summary["starts"]) == (False, None, 0)


def test_no_valid_record_adds_no_diagnostics():
    assert summarize(b"plain output\n")["incompleteReasons"] == ["NO_COMPLETION", "NO_DIAGNOSTICS"]
    assert summarize(PREFIX_BYTES + b"{}\n")["incompleteReasons"] == [
        "MALFORMED_RECORD", "NO_COMPLETION", "NO_DIAGNOSTICS",
    ]


def test_reader_never_adds_phase_order():
    out_of_order = [
        end_rec(1, 10, phase="teardown"),
        end_rec(2, 20, phase="setup"),
        end_rec(3, 30, phase="call"),
        end_rec(4, 40, phase="call"),
        end_rec(5, 50, phase="call", node=NODE_B),
        session_end_rec(6, 60, ends=5),
    ]
    assert summarize(stream(*out_of_order))["incompleteReasons"] == []
    flagged = [
        end_rec(1, 10),
        error_rec(2, "PHASE_ORDER"),
        session_end_rec(3, 20, ends=1, incomplete=True, reasons=["PHASE_ORDER"], exit_code=1),
    ]
    assert summarize(stream(*flagged))["incompleteReasons"] == ["PRODUCER_INCOMPLETE"]


def test_incomplete_reasons_are_sorted():
    summary = summarize(stream(end_rec(1, 20), end_rec(3, 10), PREFIX_BYTES + b"{bad\n"))
    assert summary["incompleteReasons"] == sorted(summary["incompleteReasons"])
    assert set(summary["incompleteReasons"]) == {"MALFORMED_RECORD", "NO_COMPLETION", "SEQUENCE_GAP", "TIME_ORDER"}


def test_non_diagnostic_lines_are_counted_and_never_returned():
    records = good_records()
    data = b"QQRAWQQ one\n" + stream(*records[:2]) + b"QQRAWQQ two\n" + stream(*records[2:])
    summary = summarize(data)
    assert summary["status"] == "COMPLETE", summary["incompleteReasons"]
    assert summary["nonDiagnosticLines"] == 2
    assert "QQRAWQQ" not in json.dumps(summary)


# ===============================================================================================================
# No silent pass
# ===============================================================================================================


def _loss_stream():
    return run_script(LOSS_SCRIPT).sink.stream()


def _drop_end(data, outcome, phase, *, resequence):
    records = parse_stream(data)
    index = next(
        i for i, rec in enumerate(records)
        if rec["event"] == "END" and rec["outcome"] == outcome and rec["phase"] == phase
    )
    kept = records[:index] + records[index + 1:]
    if resequence:
        kept = [dict(rec, seq=i + 1) for i, rec in enumerate(kept)]
    return encode_records(kept)


def test_loss_stream_is_complete_before_any_loss():
    summary = summarize(_loss_stream())
    assert summary["status"] == "COMPLETE", summary["incompleteReasons"]
    assert (summary["failed"], summary["skipped"], summary["ends"]) == (1, 1, 8)


@pytest.mark.parametrize(
    "outcome_phase",
    [("failed", "call"), ("skipped", "setup"), ("passed", "call")],
    ids=["lost_failed_end", "lost_skipped_end", "lost_passing_end"],
)
def test_lost_end_is_incomplete(outcome_phase):
    outcome, phase = outcome_phase
    summary = summarize(_drop_end(_loss_stream(), outcome, phase, resequence=False))
    assert summary["status"] == "INCOMPLETE"
    assert summary["incompleteReasons"] == ["COUNT_MISMATCH", "SEQUENCE_GAP"]


@pytest.mark.parametrize(
    "outcome_phase",
    [("failed", "call"), ("skipped", "setup"), ("passed", "call")],
    ids=["lost_failed_end", "lost_skipped_end", "lost_passing_end"],
)
def test_lost_end_with_repaired_seq_is_still_incomplete(outcome_phase):
    outcome, phase = outcome_phase
    summary = summarize(_drop_end(_loss_stream(), outcome, phase, resequence=True))
    assert summary["status"] == "INCOMPLETE"
    assert summary["incompleteReasons"] == ["COUNT_MISMATCH"]


def test_truncated_stream_inside_a_line_is_incomplete():
    full = _loss_stream()
    summary = summarize(full[: len(full) - 10])
    assert summary["status"] == "INCOMPLETE"
    assert summary["incompleteReasons"] == ["NO_COMPLETION", "PARTIAL_LINE"]


def test_truncated_stream_at_a_line_boundary_is_incomplete():
    full = _loss_stream()
    cut = full[: full.rindex(b"\n", 0, len(full) - 1) + 1]
    summary = summarize(cut)
    assert summary["status"] == "INCOMPLETE"
    assert summary["incompleteReasons"] == ["NO_COMPLETION"]
    early = b"".join(full.split(b"\n")[i] + b"\n" for i in range(3))
    assert summarize(early)["incompleteReasons"] == ["NO_COMPLETION"]


# ===============================================================================================================
# The headroom (section 5): END-only, label on non-passed END: last passing 46,666, EVENT_LIMIT one test later.
# Profile: three phases per test, each `passed`, durations 0.012345 s, a clock adding 0.012345 s per call, and a
# node id with a 61-character label (written only on non-passed ENDs, so it never reaches these bytes).
# ===============================================================================================================

HEADROOM_LAST_PASSING = 46_666
HEADROOM_NODEID = "tests/test_met_perf_043_headroom.py::test_" + "p" * 25


def _headroom_session(tests):
    sink = _Sink()
    diagnostics = _call(diag.Diagnostics, sink, _PinnedClock())
    try:
        start, end = diagnostics.start, diagnostics.end
        for _ in range(tests):
            for phase in PHASES:
                start(HEADROOM_NODEID, phase)
                end(HEADROOM_NODEID, phase, "passed", 0.012345)
        diagnostics.finish(0)
    except Exception as exc:
        raise AssertionError(f"the subject raised {type(exc).__name__}") from None
    data = sink.stream()
    records = parse_stream(data)
    return {
        "events": collections.Counter(rec["event"] for rec in records),
        "errors": [rec.get("reason") for rec in records if rec["event"] == "ERROR"],
        "sessionEnd": records[-1],
        "bytes": sink.total,
        "summary": summarize(data),
    }


@pytest.fixture(scope="module")
def headroom():
    return {
        HEADROOM_LAST_PASSING: _headroom_session(HEADROOM_LAST_PASSING),
        HEADROOM_LAST_PASSING + 1: _headroom_session(HEADROOM_LAST_PASSING + 1),
    }


def test_headroom_profile_label_is_61_characters():
    assert len(identity(HEADROOM_NODEID)["label"]) == 61


def test_headroom_46666_passing_tests_fit_every_cap(headroom):
    run = headroom[HEADROOM_LAST_PASSING]
    assert run["events"] == {"END": 3 * HEADROOM_LAST_PASSING, "SESSION_END": 1}
    assert run["errors"] == []
    session_end = run["sessionEnd"]
    assert session_end["event"] == "SESSION_END"
    assert (session_end["incomplete"], session_end["reasons"], session_end["dropped"]) == (False, [], 0)
    assert (session_end["starts"], session_end["ends"]) == (3 * HEADROOM_LAST_PASSING, 3 * HEADROOM_LAST_PASSING)
    assert run["bytes"] <= MAX_PROCESS_BYTES
    summary = run["summary"]
    assert summary["status"] == "COMPLETE", summary["incompleteReasons"]
    assert (summary["malformed"], summary["ends"]) == (0, 3 * HEADROOM_LAST_PASSING)


def test_headroom_one_test_later_stops_on_event_limit(headroom):
    run = headroom[HEADROOM_LAST_PASSING + 1]
    assert "START" not in run["events"]
    session_end = run["sessionEnd"]
    assert session_end["event"] == "SESSION_END"
    assert session_end["incomplete"] is True
    assert "EVENT_LIMIT" in session_end["reasons"]
    assert "OUTPUT_LIMIT" not in session_end["reasons"]
    assert run["bytes"] <= MAX_PROCESS_BYTES


def test_producer_stopped_on_a_cap_is_incomplete(headroom):
    summary = headroom[HEADROOM_LAST_PASSING + 1]["summary"]
    assert summary["status"] == "INCOMPLETE"
    assert "PRODUCER_INCOMPLETE" in summary["incompleteReasons"]
    assert summary["malformed"] == 0
