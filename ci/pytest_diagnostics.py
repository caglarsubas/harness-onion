"""Bounded diagnostic data only; no acceptance authority or operational I/O.

The caller supplies an already-bound monotonic clock and a byte sink. Nested
pytest stderr remains buffered by the existing subprocess.run invocation.
"""
from hashlib import sha256 as _sha256
from json import dumps as _dumps, loads as _loads
from math import isfinite as _isfinite
from re import fullmatch as _fullmatch

PREFIX = b"PYTEST_DIAGNOSTIC="
MAX_RECORD_BYTES = 1024
MAX_PROCESS_BYTES = 30 * 1024 * 1024
MAX_EVENTS = 140_000
MAX_NODE_CHARS = 65_536
MAX_SCAN_BYTES = MAX_PROCESS_BYTES + 1024 * 1024
MAX_SCAN_LINES = MAX_EVENTS + MAX_EVENTS // 10
MAX_FAILURES = 16
PHASES = ("setup", "call", "teardown")
OUTCOMES = ("passed", "failed", "skipped")
REASONS = frozenset(("INVALID_NODE", "INVALID_PHASE", "INVALID_REPORT", "CLOCK",
                     "PHASE_ORDER", "ENCODING", "RECORD_LIMIT", "OUTPUT_LIMIT",
                     "EVENT_LIMIT", "SINK", "UNFINISHED_PHASE"))
_MAX_US = 10 ** 15


def node_identity(nodeid):
    """Hash the complete ID; never render its parameters or an absolute path."""
    if type(nodeid) is not str or not nodeid or len(nodeid) > MAX_NODE_CHARS:
        raise ValueError("INVALID_NODE")
    digest = _sha256(nodeid.encode("utf-8", errors="surrogatepass")).hexdigest()
    parts = nodeid.split("[", 1)[0].split("::")
    label = "<redacted-node>"
    path = parts[0]
    if (len(parts) >= 2 and path.startswith(("tests/", "ci/"))
            and all(p not in ("", ".", "..") for p in path.split("/"))
            and _fullmatch(r"[A-Za-z0-9_./-]+\.py", path)
            and _fullmatch(r"test_[A-Za-z0-9_]+", parts[-1])):
        label = path.rsplit("/", 1)[-1][:32] + "::" + parts[-1][:36]
    return {"node": digest, "label": label}


def _integer(value, maximum=_MAX_US):
    return type(value) is int and 0 <= value <= maximum


def _seconds_us(value):
    if (type(value) not in (int, float) or not _isfinite(value)
            or value < 0 or value > _MAX_US / 1_000_000):
        raise ValueError("CLOCK")
    return int(value * 1_000_000)


class Diagnostics:
    """One process, one active phase; any diagnostic loss latches incomplete."""

    def __init__(self, sink, clock, *, byte_limit=MAX_PROCESS_BYTES,
                 event_limit=MAX_EVENTS):
        if (type(byte_limit) is not int or not 3 * MAX_RECORD_BYTES <= byte_limit <= MAX_PROCESS_BYTES
                or type(event_limit) is not int or not 3 <= event_limit <= MAX_EVENTS):
            raise ValueError("invalid diagnostic limits")
        self._sink, self._clock = sink, clock
        self.byte_limit, self.event_limit = byte_limit, event_limit
        self.bytes_written = self.events_written = self.dropped = 0
        self.incomplete = False
        self.reasons = set()
        self.active = None
        self.starts = self.ends = self.failures = self.skips = 0
        self._origin = self._last = None
        self._sink_failed = self._stopped = self._finished = False

    def _time(self):
        value = self._clock()
        # Negative monotonic origins are legal; only elapsed time is rendered.
        if type(value) not in (int, float) or not _isfinite(value):
            raise ValueError("CLOCK")
        if self._origin is None:
            self._origin = value
        if self._last is not None and value < self._last:
            raise ValueError("CLOCK")
        elapsed = _seconds_us(value - self._origin)
        self._last = value
        return elapsed

    def _write(self, fields, *, control=False):
        if self._sink_failed or (self._stopped and not control):
            self.dropped += 1
            return False
        record = {"v": 2, "seq": self.events_written + 1, **fields}
        try:
            line = PREFIX + _dumps(record, sort_keys=True, separators=(",", ":"),
                                   ensure_ascii=True, allow_nan=False).encode("ascii") + b"\n"
        except Exception:
            self._fail("ENCODING")
            return False
        if len(line) > MAX_RECORD_BYTES:
            self._fail("RECORD_LIMIT")
            return False
        reserve = 0 if control else 2 * MAX_RECORD_BYTES
        event_reserve = 0 if control else 2
        if self.bytes_written + len(line) + reserve > self.byte_limit:
            if control:
                self.incomplete = True
                self.reasons.add("OUTPUT_LIMIT")
                return False
            self._fail("OUTPUT_LIMIT")
            return False
        if self.events_written + 1 + event_reserve > self.event_limit:
            if control:
                self.incomplete = True
                self.reasons.add("EVENT_LIMIT")
                return False
            self._fail("EVENT_LIMIT")
            return False
        try:
            written = self._sink(line)
            if type(written) is not int or written != len(line):
                raise OSError("short diagnostic write")
        except Exception:
            # An ambiguous sink is never retried; its contents are not exposed.
            self._sink_failed = self._stopped = self.incomplete = True
            self.reasons.add("SINK")
            self.dropped += 1
            return False
        self.bytes_written += len(line)
        self.events_written += 1
        return True

    def _fail(self, reason):
        reason = reason if reason in REASONS else "ENCODING"
        self.incomplete = True
        self.reasons.add(reason)
        if self._stopped:
            self.dropped += 1
            return
        self._stopped = True
        self.dropped += 1
        fields = {"event": "ERROR", "reason": reason, "incomplete": True}
        if reason == "UNFINISHED_PHASE" and self.active is not None:
            # A graceful finish still names the unfinished test (Q-P43-3 (a)).
            fields.update({key: self.active[key] for key in ("node", "phase", "label")})
        self._write(fields, control=True)

    def start(self, nodeid, phase):
        if self._finished:
            self._fail("PHASE_ORDER")
            return
        try:
            identity = node_identity(nodeid)
        except Exception:
            self._fail("INVALID_NODE")
            return
        if phase not in PHASES:
            self._fail("INVALID_PHASE")
            return
        if self.active is not None:
            self._fail("PHASE_ORDER")
        try:
            stamp = self._time()
        except Exception:
            self._fail("CLOCK")
            return
        # v2: the active phase is kept in memory only; START writes no record.
        self.active = {**identity, "phase": phase, "tUs": stamp}
        self.starts += 1

    def end(self, nodeid, phase, outcome, duration, *, xfail=False):
        try:
            identity = node_identity(nodeid)
        except Exception:
            self._fail("INVALID_NODE")
            return
        if phase not in PHASES:
            self._fail("INVALID_PHASE")
            return
        if outcome not in OUTCOMES or type(xfail) is not bool:
            self._fail("INVALID_REPORT")
            return
        try:
            duration_us, stamp = _seconds_us(duration), self._time()
        except Exception:
            self._fail("CLOCK")
            return
        if (self.active is None or self.active["node"] != identity["node"]
                or self.active["phase"] != phase):
            self._fail("PHASE_ORDER")
        self.active = None
        self.ends += 1
        self.failures += int(outcome == "failed")
        self.skips += int(outcome == "skipped")
        fields = {"event": "END", "node": identity["node"], "phase": phase,
                  "outcome": outcome, "durationUs": duration_us,
                  "tUs": stamp, "xfail": xfail}
        if outcome != "passed":
            # The END's own label, never the active phase's (Q-P43-1 (a), P43-D1-1).
            fields["label"] = identity["label"]
        self._write(fields)

    def finish(self, exit_code):
        """Keep existing nonzero status; never certify missing diagnostics."""
        if self._finished:
            self._fail("PHASE_ORDER")
            return 1 if exit_code == 0 else exit_code
        if self.active is not None:
            self._fail("UNFINISHED_PHASE")
        self._finished = True
        try:
            stamp = self._time()
        except Exception:
            self._fail("CLOCK")
            stamp = 0
        result = 1 if self.incomplete and exit_code == 0 else int(exit_code)
        self._write({"event": "SESSION_END", "tUs": stamp, "exitCode": result,
                     "incomplete": self.incomplete, "reasons": sorted(self.reasons),
                     "starts": self.starts, "ends": self.ends, "failed": self.failures,
                     "skipped": self.skips, "dropped": self.dropped}, control=True)
        return 1 if self.incomplete and exit_code == 0 else exit_code


def _pairs(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate diagnostic field")
        result[key] = value
    return result


def _valid_label(label):
    return (type(label) is str and len(label) <= 70
            and (label == "<redacted-node>"
                 or _fullmatch(r"[A-Za-z0-9_.-]{1,32}::test_[A-Za-z0-9_]{0,31}", label) is not None))


def _valid_node_phase(record):
    return (type(record.get("node")) is str and _fullmatch(r"[0-9a-f]{64}", record["node"]) is not None
            and type(record.get("phase")) is str and record["phase"] in PHASES)


def _valid_record(record):
    """Version 2 only: END and ERROR carry the label rules; START is malformed."""
    if (type(record) is not dict or record.get("v") != 2
            or type(record.get("v")) is not int
            or not _integer(record.get("seq"), MAX_EVENTS) or record["seq"] == 0):
        return False
    common = {"v", "seq", "event"}
    event = record.get("event")
    if event == "ERROR":
        reason = record.get("reason")
        if type(reason) is not str or reason not in REASONS:
            return False
        if reason != "UNFINISHED_PHASE":
            return set(record) == common | {"reason", "incomplete"} and record["incomplete"] is True
        return (set(record) == common | {"reason", "incomplete", "node", "phase", "label"}
                and record["incomplete"] is True and _valid_node_phase(record)
                and _valid_label(record["label"]))
    if event == "SESSION_END":
        return (set(record) == common | {"tUs", "exitCode", "incomplete", "reasons",
                                          "starts", "ends", "failed", "skipped", "dropped"}
                and _integer(record["tUs"]) and _integer(record["exitCode"], 255)
                and type(record["incomplete"]) is bool
                and type(record["reasons"]) is list and len(record["reasons"]) <= len(REASONS)
                and all(type(reason) is str and reason in REASONS for reason in record["reasons"])
                and all(_integer(record[key], MAX_EVENTS * 2) for key in
                        ("starts", "ends", "failed", "skipped", "dropped")))
    if event != "END":
        # START, like any other event, is malformed in v2.
        return False
    labelled = record.get("outcome") != "passed"
    members = common | {"node", "phase", "tUs", "outcome", "durationUs", "xfail"}
    return (set(record) == (members | {"label"} if labelled else members)
            and _valid_node_phase(record) and _integer(record["tUs"])
            and type(record["outcome"]) is str and record["outcome"] in OUTCOMES
            and _integer(record["durationUs"]) and type(record["xfail"]) is bool
            and (not labelled or _valid_label(record["label"])))


def summarize_nested(stderr):
    """Read bounded structured stderr as untrusted data, never as authority.

Returns no raw non-diagnostic output. A timeout lacking SESSION_END is always
incomplete, even if every report observed so far passed. No side channel exists.
Version 2 streams carry END records only: an END needs no prior START, and the
active phase is named only by an UNFINISHED_PHASE ERROR record.
"""
    summary = {"schemaVersion": "planeon.pytest-diagnostic-summary/v2", "buffered": True,
               "acceptance": False, "available": stderr is not None,
               "status": "INCOMPLETE", "inputBytes": 0, "scannedBytes": 0,
               "inputTruncatedBytes": 0, "records": 0, "malformed": 0,
               "nonDiagnosticLines": 0, "completionSeen": False,
               "latestActive": None, "lastPhase": None, "failures": [],
               "failuresOmitted": 0, "starts": 0, "ends": 0, "failed": 0,
               "skipped": 0, "sessionEnd": None, "incompleteReasons": []}
    reasons = set()
    if stderr is None:
        summary["status"] = "ABSENT"
        summary["incompleteReasons"] = ["NO_DIAGNOSTICS"]
        return summary
    if type(stderr) is bytes:
        raw = stderr
    elif type(stderr) is str:
        raw = stderr.encode("utf-8", errors="replace")
    else:
        summary["incompleteReasons"] = ["INVALID_INPUT"]
        return summary
    summary["inputBytes"] = len(raw)
    if len(raw) > MAX_SCAN_BYTES:
        reasons.add("INPUT_LIMIT")
        summary["inputTruncatedBytes"] = len(raw) - MAX_SCAN_BYTES
        # Retain recent activity rather than falsely naming an early phase.
        raw = raw[-MAX_SCAN_BYTES:]
        cut = raw.find(b"\n")
        raw = raw[cut + 1:] if cut >= 0 else b""
        summary["inputTruncatedBytes"] = summary["inputBytes"] - len(raw)
    summary["scannedBytes"] = len(raw)
    cursor = lines = previous_seq = 0
    previous_time = 0
    while cursor < len(raw) and lines < MAX_SCAN_LINES:
        end = raw.find(b"\n", cursor)
        if end < 0:
            reasons.add("PARTIAL_LINE")
            break
        line = raw[cursor:end]
        cursor, lines = end + 1, lines + 1
        if not line.startswith(PREFIX):
            summary["nonDiagnosticLines"] += 1
            continue
        if len(line) + 1 > MAX_RECORD_BYTES:
            summary["malformed"] += 1
            reasons.add("MALFORMED_RECORD")
            continue
        try:
            record = _loads(line[len(PREFIX):], object_pairs_hook=_pairs)
            valid = _valid_record(record)
        except Exception:
            valid = False
        if not valid:
            summary["malformed"] += 1
            reasons.add("MALFORMED_RECORD")
            continue
        summary["records"] += 1
        if record["seq"] != previous_seq + 1:
            reasons.add("SEQUENCE_GAP")
        previous_seq = record["seq"]
        if "tUs" in record:
            if record["tUs"] < previous_time:
                reasons.add("TIME_ORDER")
            previous_time = record["tUs"]
        if summary["completionSeen"]:
            reasons.add("AFTER_COMPLETION")
        event = record["event"]
        if event == "END":
            item = {key: record[key] for key in ("node", "phase", "tUs", "outcome", "durationUs", "xfail")}
            if "label" in record:
                item["label"] = record["label"]
            summary["lastPhase"] = {**item, "event": event}
            summary["ends"] += 1
            summary["failed"] += int(record["outcome"] == "failed")
            summary["skipped"] += int(record["outcome"] == "skipped")
            if record["outcome"] == "failed":
                if len(summary["failures"]) < MAX_FAILURES:
                    summary["failures"].append(item)
                else:
                    summary["failuresOmitted"] += 1
                    reasons.add("FAILURE_DETAIL_LIMIT")
        elif event == "ERROR":
            reasons.add("PRODUCER_INCOMPLETE")
            if record["reason"] == "UNFINISHED_PHASE":
                reasons.add("UNFINISHED_PHASE")
                summary["latestActive"] = {key: record[key] for key in ("node", "phase", "label")}
        else:
            summary["completionSeen"] = True
            summary["sessionEnd"] = {key: record[key] for key in
                                     ("exitCode", "incomplete", "reasons", "dropped")}
            summary["starts"] = record["starts"]
            if (record["incomplete"] or record["reasons"] or record["dropped"]):
                reasons.add("PRODUCER_INCOMPLETE")
            if "UNFINISHED_PHASE" in record["reasons"]:
                reasons.add("UNFINISHED_PHASE")
            if (any(summary[key] != record[key] for key in ("ends", "failed", "skipped"))
                    or record["starts"] != record["ends"]):
                reasons.add("COUNT_MISMATCH")
    if cursor < len(raw) and lines >= MAX_SCAN_LINES:
        reasons.add("SCAN_LIMIT")
    # The reader never adds PHASE_ORDER: a v2 stream has no START to pair.
    if not summary["completionSeen"]:
        reasons.add("NO_COMPLETION")
    if not summary["records"]:
        reasons.add("NO_DIAGNOSTICS")
    summary["incompleteReasons"] = sorted(reasons)
    if not reasons:
        summary["status"] = "COMPLETE"
    return summary
