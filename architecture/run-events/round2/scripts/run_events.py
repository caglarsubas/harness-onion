#!/usr/bin/env python3
"""Run events, OpenTelemetry GenAI mapping and MAS metrics v1 (architecture/run-events/, MAS-RA-003): reference model,
DATA_CHECK_ONLY.

Two closed, content-addressed record kinds, each checked by one function that raises `Refused(code)` on the first rule it
breaks (rules are applied as whole-record passes in the order of LOG_CODES / METRIC_CODES) and otherwise returns derived
facts:
- a run-event log: one ordered stream of RunEvents for a root run and the runs it delegated, the canonical persistence and
  replay format (owner decision Q-MAS3-B): every event has a sequence, a logical time, a time offset, its run and agent,
  its OpenTelemetry trace and span, an operation and phase, and references (never content) for its payload, input and
  output (Q-MAS3-C);
- a MAS metrics report: the coordination, reliability, verification and security metrics of one or more logs, each an
  exact integer rational with a declared unit, UNDEFINED on a zero denominator (Q-MAS3-E).

A log may name the MAS-RA-008 loop trace it was derived from; it must then equal the deterministic derivation of that
trace (`derive_log`) with the log's own run manifest, verdict ledger and root cost as the derivation's bindings. Every
referenced record is looked up by digest and must hash to it. Owner decisions (2026-10-14, via the lane monitor):
Q-MAS3-A (a) an internal candidate, H15's, H16's and H10's documents unchanged; Q-MAS3-B (a) RunEvent is the canonical
envelope, the loop trace, verdict ledger and run manifest are referenced by digest; Q-MAS3-C (a) payloads by reference
only; Q-MAS3-E (a) exact integer rationals. Standard library only. The derivation and the log, report and annotation
checks take the MAS-RA-008 model (`scripts/agent_loop.py`) as the argument `loop`, so a caller decides which bytes of it
run (the layer runs its era's).
"""
from __future__ import annotations

import calendar
import hashlib
import json
import math
import re

LOG_SCHEMA = "planeon.internal.run-event-log/v1"
METRICS_SCHEMA = "planeon.internal.mas-metrics/v1"
MAX_ITEMS = 65536
MAX_INT = 2 ** 53 - 1
# Operations: spans have a START and an END event, points one POINT event attached to an open span.
SPANS = ("RUN", "AGENT_INVOKE", "MODEL_CALL", "TOOL_CALL", "VERIFICATION")
POINTS = ("HOOK", "HANDOFF", "MESSAGE", "ENVIRONMENT", "CLAIM", "MERGE")
OPERATIONS = SPANS + POINTS
PHASES = ("START", "END", "POINT")
WORK = ("MODEL_CALL", "TOOL_CALL")
STEP_OUTCOMES = ("OK", "FAIL", "ERROR", "UNKNOWN")
RUN_OUTCOMES = ("COMPLETED", "FAILED", "HANDED_OFF", "ABORTED")
TRUST_LABELS = ("TRUSTED_TOOL_OUTPUT", "UNTRUSTED_TOOL_OUTPUT")
LOG_CODES = ("SHAPE", "DUPLICATE_ID", "SEQUENCE", "RUN_BOUNDS", "SPAN_ORDER", "RUN_SCOPE", "LOGICAL_TIME", "TIME_ORDER",
             "MESSAGE_PAIRING", "CLAIM_CONFLICT", "UNKNOWN_REFERENCE", "SOURCE_BINDING", "DERIVATION")
METRIC_CODES = ("SHAPE", "UNKNOWN_REFERENCE", "METRIC_INPUT", "METRIC_VALUE")
DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")
IDENT = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}\Z")
TRACE_ID = re.compile(r"[0-9a-f]{32}\Z")
SPAN_ID = re.compile(r"[0-9a-f]{16}\Z")


class Refused(ValueError):
    """A record breaks a rule; `code` is one of LOG_CODES or METRIC_CODES."""

    def __init__(self, code: str):
        super().__init__(code)
        self.code = code


def _refuse(ok: bool, code: str) -> None:
    if not ok:
        raise Refused(code)


# ---------------------------------------------------------------- canonical form and text (as MAS-RA-001, -002, -008)

def _integral(value) -> bool:
    if type(value) is int:
        return abs(value) <= MAX_INT
    return type(value) is float and math.isfinite(value) and value.is_integer() and abs(value) <= MAX_INT


def _normal(value):
    if type(value) is float:
        _refuse(_integral(value), "SHAPE")
        return int(value)
    if type(value) is list:
        return [_normal(v) for v in value]
    if type(value) is dict:
        return {k: _normal(v) for k, v in value.items()}
    return value


def canonical(value) -> bytes:
    """RFC 8785 (JCS) bytes of a record: keys sorted, no whitespace, UTF-8, integers without a fraction."""
    return json.dumps(_normal(value), sort_keys=True, ensure_ascii=False, separators=(",", ":"),
                      allow_nan=False).encode("utf-8")


def digest(value) -> str:
    return "sha256:" + hashlib.sha256(canonical(value)).hexdigest()


def _no_constant(name):
    raise Refused("SHAPE")


def _members(pairs):
    names = [name for name, _ in pairs]
    _refuse(len(names) == len(set(names)), "SHAPE")
    return dict(pairs)


def _encodable(value) -> None:
    """Every member name and string encodes as UTF-8 (an escaped lone surrogate does not: UnicodeEncodeError)."""
    stack = [value]
    while stack:
        item = stack.pop()
        if type(item) is str:
            item.encode("utf-8")
        elif type(item) is list:
            stack.extend(item)
        elif type(item) is dict:
            stack.extend(item)
            stack.extend(item.values())


def parse(text):
    """Record text as I-JSON (RFC 7493): UTF-8, no duplicate member names, no NaN or infinity, no lone surrogate (also not
    escaped); anything else is SHAPE."""
    try:
        if isinstance(text, (bytes, bytearray)):
            text = bytes(text).decode("utf-8")
        text.encode("utf-8")
        value = json.loads(text, object_pairs_hook=_members, parse_constant=_no_constant)
        _encodable(value)
        return value
    except Refused:
        raise
    except (ValueError, TypeError, RecursionError) as exc:
        raise Refused("SHAPE") from exc


# ---------------------------------------------------------------- shape helpers

def _ident(value) -> bool:
    return type(value) is str and IDENT.match(value) is not None


def _opt_ident(value) -> bool:
    return value is None or _ident(value)


def _digest_str(value) -> bool:
    return type(value) is str and DIGEST.match(value) is not None


def _opt_digest(value) -> bool:
    return value is None or _digest_str(value)


def _int(value, low: int, high: int) -> bool:
    return _integral(value) and low <= value <= high


def _closed(value, keys) -> bool:
    return type(value) is dict and set(value) == set(keys)


def _list(value, low: int = 0) -> bool:
    return type(value) is list and low <= len(value) <= MAX_ITEMS


def _trace_id(value) -> bool:
    return type(value) is str and TRACE_ID.match(value) is not None and set(value) != {"0"}


def _span_id(value) -> bool:
    return type(value) is str and SPAN_ID.match(value) is not None and set(value) != {"0"}


def _guarded(check):
    """Run one record check; anything malformed that slipped past the shape rules is SHAPE, never another exception."""
    try:
        return check()
    except Refused:
        raise
    except (KeyError, TypeError, AttributeError, IndexError, ValueError, UnicodeError, RecursionError) as exc:
        raise Refused("SHAPE") from exc


def _stored(stores, store: str, key):
    """The record stored under `key` in `stores[store]`, only if it hashes to `key` (content addressing); else None."""
    records = stores.get(store) if type(stores) is dict else None
    if type(records) is not dict or key not in records:
        return None
    try:
        return records[key] if digest(records[key]) == key else None
    except (Refused, TypeError, ValueError, RecursionError):
        return None


# ---------------------------------------------------------------- run-event log: shape

LOG_KEYS = ("schemaVersion", "rootRunId", "traceId", "sources", "events")
SOURCE_KEYS = ("loopTraceDigest", "runManifestDigest", "verdictLedgerDigest")
EVENT_KEYS = ("sequence", "logicalTime", "timeMs", "runId", "agentId", "spanId", "parentSpanId", "operation", "phase",
              "name", "outcome", "payloadRef", "inputHash", "outputHash", "attributes")
# Attributes per (operation, phase): a closed key set and a check per key.
_COUNT = lambda v: _int(v, 0, MAX_INT)
_ATTEMPT = lambda v: _int(v, 1, 4)
_BOOL = lambda v: type(v) is bool
ATTRIBUTES = {
    ("RUN", "START"): {"depth": lambda v: _int(v, 0, 1), "parentRunId": _opt_ident},
    # costMicros: the run's cost in millionths of the currency unit of its configuration, as MAS-RA-002's costMicros.
    ("RUN", "END"): {"tokens": _COUNT, "iterations": _COUNT, "costMicros": lambda v: v is None or _COUNT(v)},
    ("AGENT_INVOKE", "START"): {"childRunId": _ident},
    ("AGENT_INVOKE", "END"): {"tokens": _COUNT},
    ("MODEL_CALL", "START"): {"attempt": _ATTEMPT, "revisesSpanId": lambda v: v is None or _span_id(v),
                              "provider": _opt_ident, "model": _opt_ident},
    ("MODEL_CALL", "END"): {"tokens": _COUNT},
    ("TOOL_CALL", "START"): {"attempt": _ATTEMPT, "toolId": _ident, "manifestDigest": _digest_str, "inputValid": _BOOL,
                             "launched": _BOOL, "grantDigest": _digest_str},
    ("TOOL_CALL", "END"): {"tokens": _COUNT, "trustLabel": lambda v: v in TRUST_LABELS, "receiptRef": _opt_digest},
    ("VERIFICATION", "START"): {"gateId": _ident, "subjectSpanId": _span_id, "attempt": _ATTEMPT},
    ("VERIFICATION", "END"): {"tokens": _COUNT},
    ("HOOK", "POINT"): {"hookId": _ident, "event": _ident, "effect": _opt_ident,
                        "result": lambda v: v in STEP_OUTCOMES, "tokens": _COUNT},
    ("HANDOFF", "POINT"): {"reasonDigest": _digest_str, "tokens": _COUNT},
    ("MESSAGE", "POINT"): {"messageId": _ident, "direction": lambda v: v in ("SEND", "RECEIVE"), "fromAgent": _ident,
                           "toAgent": _ident, "tokens": _COUNT},
    ("ENVIRONMENT", "POINT"): {"transition": _ident, "stateDigest": _digest_str},
    ("CLAIM", "POINT"): {"claimId": _ident, "taskDigest": _digest_str, "conflictsWith": _opt_ident},
    ("MERGE", "POINT"): {"mergeId": _ident, "conflict": _BOOL},
}


def _event_shape(e) -> bool:
    if not _closed(e, EVENT_KEYS):
        return False
    op, phase = e["operation"], e["phase"]
    if op not in OPERATIONS or phase not in PHASES or (op in SPANS) == (phase == "POINT"):
        return False
    attributes = ATTRIBUTES[(op, phase)]
    outcome = e["outcome"]
    if phase == "END":
        allowed = RUN_OUTCOMES if op == "RUN" else STEP_OUTCOMES
        outcome_ok = outcome in allowed
    else:
        outcome_ok = outcome is None
    ref = e["payloadRef"]
    return (_int(e["sequence"], 1, MAX_INT) and _int(e["logicalTime"], 0, MAX_INT) and _int(e["timeMs"], 0, MAX_INT)
            and _ident(e["runId"]) and _ident(e["agentId"]) and _span_id(e["spanId"])
            and (e["parentSpanId"] is None or _span_id(e["parentSpanId"])) and _ident(e["name"]) and outcome_ok
            and (ref is None or (_closed(ref, ("digest", "store")) and _digest_str(ref["digest"]) and _ident(ref["store"])))
            and _opt_digest(e["inputHash"]) and _opt_digest(e["outputHash"])
            and _closed(e["attributes"], attributes) and all(check(e["attributes"][k]) for k, check in attributes.items())
            and (phase != "POINT" or e["parentSpanId"] is None))


def _log_shape(doc) -> None:
    _refuse(_closed(doc, LOG_KEYS) and doc["schemaVersion"] == LOG_SCHEMA and _ident(doc["rootRunId"])
            and _trace_id(doc["traceId"]) and _closed(doc["sources"], SOURCE_KEYS)
            and all(_opt_digest(doc["sources"][k]) for k in SOURCE_KEYS) and _list(doc["events"], 2)
            and all(_event_shape(e) for e in doc["events"]), "SHAPE")


# ---------------------------------------------------------------- run-event log: the rules, one whole-log pass each

def _duplicate_ids(doc, stores, loop) -> None:
    events = doc["events"]
    starts = [e["spanId"] for e in events if e["phase"] == "START"]
    for key, op in (("messageId", "MESSAGE"), ("claimId", "CLAIM"), ("mergeId", "MERGE")):
        ids = [(e["attributes"][key], e["attributes"].get("direction")) for e in events if e["operation"] == op]
        _refuse(len(ids) == len(set(ids)), "DUPLICATE_ID")
    _refuse(len(starts) == len(set(starts)), "DUPLICATE_ID")
    runs = [e["runId"] for e in events if e["operation"] == "RUN" and e["phase"] == "START"]
    _refuse(len(runs) == len(set(runs)), "DUPLICATE_ID")


def _sequence(doc, stores, loop) -> None:
    _refuse([e["sequence"] for e in doc["events"]] == list(range(1, len(doc["events"]) + 1)), "SEQUENCE")


def _run_bounds(doc, stores, loop) -> None:
    first, last = doc["events"][0], doc["events"][-1]
    _refuse(first["operation"] == "RUN" and first["phase"] == "START" and first["runId"] == doc["rootRunId"]
            and first["parentSpanId"] is None
            and (first["attributes"]["depth"] == 0) == (first["attributes"]["parentRunId"] is None)
            and last["operation"] == "RUN" and last["phase"] == "END" and last["spanId"] == first["spanId"], "RUN_BOUNDS")
    roots = [e for e in doc["events"] if e["parentSpanId"] is None and e["phase"] != "POINT"]
    _refuse(all(e["spanId"] == first["spanId"] for e in roots), "RUN_BOUNDS")


def _span_order(doc, stores, loop) -> None:
    """A span starts once, under a parent that is open at that moment, ends once with its START's parent, after every
    span it parents has ended; a point attaches to an open span; nothing follows the root's END."""
    open_spans, started, parent_of, children_open = set(), {}, {}, {}
    for e in doc["events"]:
        span, phase = e["spanId"], e["phase"]
        if phase == "START":
            parent = e["parentSpanId"]
            _refuse(span not in started and (parent is None or parent in open_spans), "SPAN_ORDER")
            started[span], parent_of[span] = e, parent
            open_spans.add(span)
            children_open[span] = 0
            if parent is not None:
                children_open[parent] += 1
        elif phase == "END":
            start = started.get(span)
            _refuse(span in open_spans and start["operation"] == e["operation"] and start["runId"] == e["runId"]
                    and start["agentId"] == e["agentId"] and e["parentSpanId"] == parent_of[span]
                    and e["name"] == start["name"] and children_open[span] == 0, "SPAN_ORDER")
            open_spans.discard(span)
            if parent_of[span] is not None:
                children_open[parent_of[span]] -= 1
        else:
            _refuse(span in open_spans, "SPAN_ORDER")
    _refuse(not open_spans, "SPAN_ORDER")


def _run_scope(doc, stores, loop) -> None:
    """Every event of a run lies inside that run's RUN span and belongs to that run's agent (one agent per run); a child
    run's RUN span opens under an AGENT_INVOKE span of its parent run that names it, at depth 1; an AGENT_INVOKE names
    exactly one child run."""
    started = {}
    run_span = {}
    for e in doc["events"]:
        if e["phase"] == "START":
            started[e["spanId"]] = e
        if e["operation"] == "RUN" and e["phase"] == "START":
            run_span[e["runId"]] = e["spanId"]
    _refuse(all(e["runId"] in run_span and e["agentId"] == started[run_span[e["runId"]]]["agentId"]
                for e in doc["events"]), "RUN_SCOPE")
    invoked = {}
    for e in doc["events"]:
        if e["phase"] != "START":
            continue
        if e["operation"] == "RUN":
            if e["parentSpanId"] is None:
                continue
            parent = started[e["parentSpanId"]]
            _refuse(parent["operation"] == "AGENT_INVOKE" and parent["attributes"]["childRunId"] == e["runId"]
                    and e["attributes"]["parentRunId"] == parent["runId"]
                    and e["attributes"]["depth"] == started[run_span[parent["runId"]]]["attributes"]["depth"] + 1,
                    "RUN_SCOPE")
            _refuse(e["parentSpanId"] not in invoked, "RUN_SCOPE")
            invoked[e["parentSpanId"]] = e["runId"]
        else:
            parent = started.get(e["parentSpanId"])
            _refuse(parent is not None and parent["runId"] == e["runId"] and e["runId"] in run_span, "RUN_SCOPE")
    for e in doc["events"]:
        if e["phase"] == "POINT":
            _refuse(started[e["spanId"]]["runId"] == e["runId"], "RUN_SCOPE")
        if e["operation"] == "AGENT_INVOKE" and e["phase"] == "END":
            _refuse(e["spanId"] in invoked, "RUN_SCOPE")
    for span, e in started.items():
        if e["operation"] == "VERIFICATION":
            subject = started.get(e["attributes"]["subjectSpanId"])
            _refuse(subject is not None and subject["runId"] == e["runId"] and subject["sequence"] < e["sequence"],
                    "RUN_SCOPE")
        if e["operation"] == "MODEL_CALL" and e["attributes"]["revisesSpanId"] is not None:
            revised = started.get(e["attributes"]["revisesSpanId"])
            _refuse(revised is not None and revised["operation"] in ("MODEL_CALL", "AGENT_INVOKE")
                    and revised["runId"] == e["runId"]
                    and revised["sequence"] < e["sequence"], "RUN_SCOPE")


def _logical_time(doc, stores, loop) -> None:
    """Logical time never decreases along the sequence, and a message is received at a later logical time than it was
    sent."""
    times = [e["logicalTime"] for e in doc["events"]]
    _refuse(all(a <= b for a, b in zip(times, times[1:])), "LOGICAL_TIME")
    sent = {e["attributes"]["messageId"]: e["logicalTime"] for e in doc["events"]
            if e["operation"] == "MESSAGE" and e["attributes"]["direction"] == "SEND"}
    for e in doc["events"]:
        if e["operation"] == "MESSAGE" and e["attributes"]["direction"] == "RECEIVE" and e["attributes"]["messageId"] in sent:
            _refuse(e["logicalTime"] > sent[e["attributes"]["messageId"]], "LOGICAL_TIME")


def _time_order(doc, stores, loop) -> None:
    """Times nest like the spans: the root run starts at 0 ms; a span ends no earlier than it starts, starts no earlier
    than its parent span starts and ends no later than its parent span ends; a point lies within its span."""
    events = doc["events"]
    _refuse(events[0]["timeMs"] == 0, "TIME_ORDER")
    start, end = {}, {}
    for e in events:
        if e["phase"] == "START":
            start[e["spanId"]] = e["timeMs"]
        elif e["phase"] == "END":
            end[e["spanId"]] = e["timeMs"]
    for e in events:
        span = e["spanId"]
        if e["phase"] == "START":
            parent = e["parentSpanId"]
            _refuse(end[span] >= e["timeMs"]
                    and (parent is None or start[parent] <= e["timeMs"] and end[span] <= end[parent]), "TIME_ORDER")
        elif e["phase"] == "POINT":
            _refuse(start[span] <= e["timeMs"] <= end[span], "TIME_ORDER")


def _message_pairing(doc, stores, loop) -> None:
    """Every received message was sent earlier in the log by its sender to its receiver with the same tokens and payload;
    the sender's event belongs to the sending agent and the receiver's to the receiving agent."""
    sent = {}
    for e in doc["events"]:
        if e["operation"] != "MESSAGE":
            continue
        a = e["attributes"]
        if a["direction"] == "SEND":
            _refuse(e["agentId"] == a["fromAgent"] and a["fromAgent"] != a["toAgent"], "MESSAGE_PAIRING")
            sent[a["messageId"]] = e
        else:
            s = sent.get(a["messageId"])
            _refuse(s is not None and e["agentId"] == a["toAgent"]
                    and (s["attributes"]["fromAgent"], s["attributes"]["toAgent"], s["attributes"]["tokens"])
                    == (a["fromAgent"], a["toAgent"], a["tokens"]) and s["payloadRef"] == e["payloadRef"],
                    "MESSAGE_PAIRING")


def _claim_conflict(doc, stores, loop) -> None:
    """A conflicting claim names an earlier claim on the same task by another agent; a claim that conflicts with no
    earlier claim names none."""
    claims = {}
    for e in doc["events"]:
        if e["operation"] != "CLAIM":
            continue
        a = e["attributes"]
        earlier = [c for c in claims.values() if c["attributes"]["taskDigest"] == a["taskDigest"]
                   and c["agentId"] != e["agentId"]]
        if a["conflictsWith"] is None:
            _refuse(not earlier, "CLAIM_CONFLICT")
        else:
            other = claims.get(a["conflictsWith"])
            _refuse(other is not None and other in earlier, "CLAIM_CONFLICT")
        claims[a["claimId"]] = e


SOURCE_STORES = (("loopTraceDigest", "traces"), ("runManifestDigest", "manifests"), ("verdictLedgerDigest", "ledgers"))


def _unknown_reference(doc, stores, loop) -> None:
    """Every named source record is stored under its digest and hashes to it."""
    for key, store in SOURCE_STORES:
        ref = doc["sources"][key]
        _refuse(ref is None or _stored(stores, store, ref) is not None, "UNKNOWN_REFERENCE")


def _source_binding(doc, stores, loop) -> None:
    """A named run manifest (MAS-RA-002) is this root run's: its runId is the log's root run id, and its ledger digest
    (or null) is the log's verdict ledger digest. The manifest and the ledger are otherwise checked by their own models."""
    manifest = _stored(stores, "manifests", doc["sources"]["runManifestDigest"])
    if manifest is None:   # none named (or UNKNOWN_REFERENCE's case)
        return
    _refuse(type(manifest) is dict and manifest.get("runId") == doc["rootRunId"]
            and "ledgerDigest" in manifest and manifest["ledgerDigest"] == doc["sources"]["verdictLedgerDigest"],
            "SOURCE_BINDING")


def bindings_of(doc) -> dict:
    """The derivation's bindings a log carries: its run manifest and verdict ledger digests and its root run's cost."""
    return {"runManifestDigest": doc["sources"]["runManifestDigest"],
            "verdictLedgerDigest": doc["sources"]["verdictLedgerDigest"],
            "costMicros": doc["events"][-1]["attributes"]["costMicros"]}


def _derivation(doc, stores, loop) -> None:
    trace = _stored(stores, "traces", doc["sources"]["loopTraceDigest"])
    if trace is None:   # none named (or UNKNOWN_REFERENCE's case)
        return
    try:
        derived = derive_log(trace, stores, loop, bindings_of(doc))
    except (loop.Refused, Refused):
        derived = None
    _refuse(derived is not None and canonical(derived) == canonical(doc), "DERIVATION")


LOG_RULES = (("DUPLICATE_ID", _duplicate_ids), ("SEQUENCE", _sequence), ("RUN_BOUNDS", _run_bounds),
             ("SPAN_ORDER", _span_order), ("RUN_SCOPE", _run_scope), ("LOGICAL_TIME", _logical_time),
             ("TIME_ORDER", _time_order), ("MESSAGE_PAIRING", _message_pairing), ("CLAIM_CONFLICT", _claim_conflict),
             ("UNKNOWN_REFERENCE", _unknown_reference), ("SOURCE_BINDING", _source_binding),
             ("DERIVATION", _derivation))


def check_log(doc: dict, stores: dict, loop) -> dict:
    """Check a run-event log against the stores (`traces`, `profiles`, `manifests`, `ledgers`: digest -> record), with
    `loop` the MAS-RA-008 model; return its facts or raise Refused."""
    def run():
        _log_shape(doc)
        for _, rule in LOG_RULES:
            rule(doc, stores, loop)
        events = doc["events"]
        return {"events": len(events), "runs": sum(1 for e in events if e["operation"] == "RUN" and e["phase"] == "START"),
                "agents": len({e["agentId"] for e in events}), "outcome": events[-1]["outcome"]}
    return _guarded(run)


# ---------------------------------------------------------------- derivation from a MAS-RA-008 loop trace

def _hex(label: str, length: int) -> str:
    return hashlib.sha256(label.encode("utf-8")).hexdigest()[:length]


def trace_id_for(root_run_id: str) -> str:
    return _hex("planeon.run-events/trace/" + root_run_id, 32)


def span_id_for(run_id: str, name: str) -> str:
    return _hex("planeon.run-events/span/%s/%s" % (run_id, name), 16)


def _seconds(stamp: str) -> int:
    """Seconds since the epoch of an agent-loop timestamp (YYYY-MM-DDTHH:MM:SSZ)."""
    return calendar.timegm((int(stamp[0:4]), int(stamp[5:7]), int(stamp[8:10]), int(stamp[11:13]), int(stamp[14:16]),
                            int(stamp[17:19]), 0, 0, 0))


NO_BINDINGS = {"runManifestDigest": None, "verdictLedgerDigest": None, "costMicros": None}


def derive_log(trace: dict, stores: dict, loop, bindings: dict | None = None) -> dict:
    """The run-event log of a loop trace that passes the MAS-RA-008 check: the root run, each step as a span (MODEL as
    MODEL_CALL, TOOL as TOOL_CALL, GATE as VERIFICATION, DELEGATE as AGENT_INVOKE around the child run's events) or as a
    point on the run span (HOOK, HANDOFF), and the run's end. Identifiers are derived from run and step ids; times are
    milliseconds from the root run's start; the logical time is the sequence number; a run's agent is its run.

    Precondition (DERIVATION otherwise): the trace ids of the delegation tree are distinct, since run and span ids are
    derived from them (MAS-RA-008 does not require it). `bindings` supplies what a loop trace does not record: the run
    manifest and verdict ledger digests and the root run's cost in micros (all null by default)."""
    bindings = NO_BINDINGS if bindings is None else bindings
    _refuse(type(bindings) is dict and set(bindings) == set(NO_BINDINGS), "DERIVATION")
    loop.check_trace(trace, stores.get("profiles", {}), stores.get("traces", {}))
    root_start = _seconds(trace["startedAt"])
    events = []
    seen_runs = set()

    def emit(**fields):
        fields["sequence"] = fields["logicalTime"] = len(events) + 1
        events.append({k: fields[k] for k in EVENT_KEYS})

    def latest(since: int) -> int:
        return max(e["timeMs"] for e in events[since:])

    def run(doc, parent_span, parent_run):
        run_id = doc["traceId"]
        _refuse(run_id not in seen_runs, "DERIVATION")
        seen_runs.add(run_id)
        run_span = span_id_for(run_id, "")
        start_ms = (_seconds(doc["startedAt"]) - root_start) * 1000
        first = len(events)
        emit(timeMs=start_ms, runId=run_id, agentId=run_id, spanId=run_span, parentSpanId=parent_span, operation="RUN",
             phase="START", name=run_id, outcome=None, payloadRef=None, inputHash=None, outputHash=None,
             attributes={"depth": doc["depth"], "parentRunId": parent_run})
        by_id = {s["stepId"]: s for s in doc["steps"]}
        for s in doc["steps"]:
            span = span_id_for(run_id, s["stepId"])
            t0 = (_seconds(s["startedAt"]) - root_start) * 1000
            t1 = t0 + s["wallClockSeconds"] * 1000
            kind, d = s["kind"], s["detail"]
            common = dict(runId=run_id, agentId=run_id, spanId=span, parentSpanId=run_span, name=s["stepId"])
            if kind in ("HOOK", "HANDOFF"):
                attributes = ({"hookId": d["hookId"], "event": d["event"], "effect": d["effect"], "result": s["outcome"],
                               "tokens": s["tokens"]} if kind == "HOOK"
                              else {"reasonDigest": digest(d["reason"]), "tokens": s["tokens"]})
                emit(timeMs=t0, runId=run_id, agentId=run_id, spanId=run_span, parentSpanId=None, operation=kind,
                     phase="POINT", name=s["stepId"], outcome=None, payloadRef=None, inputHash=None, outputHash=None,
                     attributes=attributes)
                continue
            output = s["produces"]
            ref = None if output is None else {"digest": output, "store": "artefacts"}
            if kind == "MODEL":
                revises = s["revises"]
                emit(timeMs=t0, operation="MODEL_CALL", phase="START", outcome=None, payloadRef=None,
                     inputHash=d["inputDigest"], outputHash=None,
                     attributes={"attempt": s["attempt"],
                                 "revisesSpanId": None if revises is None else span_id_for(run_id, revises),
                                 "provider": None, "model": None}, **common)
                emit(timeMs=t1, operation="MODEL_CALL", phase="END", outcome=s["outcome"], payloadRef=ref, inputHash=None,
                     outputHash=output, attributes={"tokens": s["tokens"]}, **common)
            elif kind == "TOOL":
                c, r = d["call"], d["result"]
                emit(timeMs=t0, operation="TOOL_CALL", phase="START", outcome=None, payloadRef=None,
                     inputHash=c["inputDigest"], outputHash=None,
                     attributes={"attempt": s["attempt"], "toolId": c["toolId"], "manifestDigest": c["manifestDigest"],
                                 "inputValid": c["inputValid"], "launched": c["launched"],
                                 "grantDigest": c["capability"]["grantDigest"]}, **common)
                out = r["outputDigest"]
                emit(timeMs=t1, operation="TOOL_CALL", phase="END", outcome=s["outcome"],
                     payloadRef=None if out is None else {"digest": out, "store": "tool-results"}, inputHash=None,
                     outputHash=out, attributes={"tokens": s["tokens"], "trustLabel": r["trustLabel"],
                                                 "receiptRef": r["provenance"]["receiptRef"]}, **common)
            elif kind == "GATE":
                emit(timeMs=t0, operation="VERIFICATION", phase="START", outcome=None, payloadRef=None, inputHash=None,
                     outputHash=None, attributes={"gateId": d["gateId"], "attempt": s["attempt"],
                                                  "subjectSpanId": span_id_for(run_id, d["subjectStepId"])}, **common)
                emit(timeMs=t1, operation="VERIFICATION", phase="END", outcome=s["outcome"], payloadRef=None,
                     inputHash=None, outputHash=s["errorTraceDigest"], attributes={"tokens": s["tokens"]}, **common)
            elif kind == "DELEGATE":
                child = stores["traces"][d["childTraceDigest"]]
                invoked = len(events)
                emit(timeMs=t0, operation="AGENT_INVOKE", phase="START", outcome=None, payloadRef=None, inputHash=None,
                     outputHash=None, attributes={"childRunId": child["traceId"]}, **common)
                run(child, span, run_id)
                emit(timeMs=max(t1, latest(invoked)), operation="AGENT_INVOKE", phase="END", outcome=s["outcome"],
                     payloadRef=ref, inputHash=None, outputHash=output, attributes={"tokens": s["tokens"]}, **common)
        delivered = doc["terminal"]["delivered"]
        output = None if delivered is None else by_id[delivered]["produces"]
        # A span ends no earlier than anything inside it (TIME_ORDER), so a run's END is at least its latest event.
        end_ms = max(start_ms + doc["totals"]["wallClockSeconds"] * 1000, latest(first))
        emit(timeMs=end_ms, runId=run_id, agentId=run_id, spanId=run_span, parentSpanId=parent_span, operation="RUN",
             phase="END", name=run_id, outcome=doc["terminal"]["status"],
             payloadRef=None if output is None else {"digest": output, "store": "artefacts"}, inputHash=None,
             outputHash=output, attributes={"tokens": doc["totals"]["tokens"],
                                            "iterations": doc["totals"]["iterations"],
                                            "costMicros": bindings["costMicros"] if parent_span is None else None})

    run(trace, None, trace["parentTraceId"])
    return {"schemaVersion": LOG_SCHEMA, "rootRunId": trace["traceId"], "traceId": trace_id_for(trace["traceId"]),
            "sources": {"loopTraceDigest": digest(trace), "runManifestDigest": bindings["runManifestDigest"],
                        "verdictLedgerDigest": bindings["verdictLedgerDigest"]},
            "events": events}


# ---------------------------------------------------------------- MAS metrics report

REPORT_KEYS = ("schemaVersion", "runs", "baseline", "metrics")
METRIC_KEYS = ("name", "unit", "numerator", "denominator", "state")
# (name, unit): the closed list, in report order. Each value is an exact rational in lowest terms; a zero denominator is
# UNDEFINED (Q-MAS3-E).
METRICS = (("cost_per_success", "cost-micros/success"), ("speedup", "ratio"), ("parallel_efficiency", "ratio"),
           ("message_overhead", "messages/work-span"), ("token_overhead", "ratio"), ("duplicated_work_ratio", "ratio"),
           ("conflicting_claim_rate", "ratio"), ("merge_conflict_rate", "ratio"), ("idle_time", "ms"),
           ("orchestrator_bottleneck_time", "ms"), ("invalid_actions", "count"), ("retries", "count"),
           ("replans", "count"), ("stalled_turns", "count"), ("evidence_coverage", "ratio"),
           ("unresolved_fraction", "ratio"), ("verifier_disagreement", "ratio"), ("denied_capability_attempts", "count"))


def _rational(numerator: int, denominator: int) -> tuple:
    if denominator == 0:
        return numerator, 0
    g = math.gcd(numerator, denominator)
    return numerator // g, denominator // g


def _spans(log):
    """Every span of a log: spanId -> (START event, END event)."""
    starts, ends = {}, {}
    for e in log["events"]:
        if e["phase"] == "START":
            starts[e["spanId"]] = e
        elif e["phase"] == "END":
            ends[e["spanId"]] = e
    return {span: (starts[span], ends[span]) for span in starts}


def _union(intervals) -> int:
    """The measure, in milliseconds, of a union of half-open intervals [a, b)."""
    total, end = 0, None
    for a, b in sorted(intervals):
        if end is None or a > end:
            total += b - a
            end = b
        elif b > end:
            total += b - end
            end = b
    return total


def _intersect(xs, ys):
    """The pairwise intersections of two lists of intervals (their union is the intersection of the two unions)."""
    return [(max(a, c), min(b, d)) for a, b in xs for c, d in ys if min(b, d) > max(a, c)]


def _duration(log) -> int:
    return log["events"][-1]["timeMs"] - log["events"][0]["timeMs"]


def _agents(log) -> set:
    return {e["agentId"] for e in log["events"]}


def compute_metrics(logs: list, baseline) -> list:
    """The metrics of a list of checked logs and an optional single-agent baseline log, in METRICS order."""
    values = {}
    roots_end = [log["events"][-1] for log in logs]
    costs = [e["attributes"]["costMicros"] for e in roots_end]
    successes = sum(1 for e in roots_end if e["outcome"] == "COMPLETED")
    values["cost_per_success"] = (sum(costs), successes) if all(c is not None for c in costs) else (0, 0)
    total_n = sum(_duration(log) for log in logs)
    agents = len(_agents(logs[0]))
    t1 = None if baseline is None else _duration(baseline)
    values["speedup"] = (0, 0) if t1 is None else (t1 * len(logs), total_n)
    values["parallel_efficiency"] = (0, 0) if t1 is None else (t1 * len(logs), agents * total_n)
    sends = work = send_tokens = work_tokens = 0
    duplicated = outputs = claims = conflicting = merges = merge_conflicts = 0
    idle = bottleneck = invalid = retries = replans = stalled = denied = 0
    covered = produced = unresolved = verified_ends = disagreeing = verified_subjects = 0
    for log in logs:
        spans = _spans(log)
        events = log["events"]
        root_agent = events[0]["agentId"]
        first_by_output = {}
        last_model_output = {}
        verdicts = {}   # (gateId, the subject's output bytes, or its span when it has none) -> outcomes
        verified_ok = set()   # output digests some OK verification covered
        for e in events:
            op, phase, a = e["operation"], e["phase"], e["attributes"]
            if op == "MESSAGE" and a["direction"] == "SEND":
                sends += 1
                send_tokens += a["tokens"]
            elif op == "CLAIM":
                claims += 1
                conflicting += a["conflictsWith"] is not None
            elif op == "MERGE":
                merges += 1
                merge_conflicts += a["conflict"]
            elif op in WORK and phase == "START":
                work += 1
                retries += a["attempt"] > 1
                if op == "TOOL_CALL":
                    invalid += not a["inputValid"]
                    denied += a["inputValid"] and not a["launched"]
                else:
                    replans += a["revisesSpanId"] is not None
            elif op == "VERIFICATION" and phase == "START":
                retries += a["attempt"] > 1
            elif op in WORK and phase == "END":
                work_tokens += a["tokens"]
                if e["outcome"] == "OK" and e["outputHash"] is not None:
                    outputs += 1
                    earlier = first_by_output.setdefault(e["outputHash"], set())
                    duplicated += bool(earlier - {e["agentId"]})
                    earlier.add(e["agentId"])
                if op == "MODEL_CALL" and e["outcome"] == "OK":
                    stalled += e["outputHash"] is not None and last_model_output.get(e["agentId"]) == e["outputHash"]
                    last_model_output[e["agentId"]] = e["outputHash"]
            elif op == "VERIFICATION" and phase == "END":
                verified_ends += 1
                unresolved += e["outcome"] == "UNKNOWN"
                start = spans[e["spanId"]][0]["attributes"]
                subject_bytes = spans[start["subjectSpanId"]][1]["outputHash"]
                key = (start["gateId"], subject_bytes if subject_bytes is not None else start["subjectSpanId"])
                verdicts.setdefault(key, set()).add(e["outcome"])
                if e["outcome"] == "OK" and subject_bytes is not None:
                    verified_ok.add(subject_bytes)
        # Evidence coverage is keyed by bytes, as MAS-RA-008 gates them (a gate on the same bytes decides the same): an OK
        # output (model call, untrusted tool result or delegation) is covered when some OK verification in the log
        # verified the same bytes. Trusted tool results are not gated (MAS-RA-008) and do not count.
        for span, (start, end) in spans.items():
            counted = start["operation"] in ("MODEL_CALL", "AGENT_INVOKE") or (
                start["operation"] == "TOOL_CALL" and end["attributes"]["trustLabel"] == "UNTRUSTED_TOOL_OUTPUT")
            if counted and end["outcome"] == "OK" and end["outputHash"] is not None:
                produced += 1
                covered += end["outputHash"] in verified_ok
        # Disagreement: one gate, the same subject bytes, both an OK and a FAIL verdict.
        verified_subjects += len(verdicts)
        disagreeing += sum(1 for v in verdicts.values() if {"OK", "FAIL"} <= v)
        # Idle time: each run's span less the time any of its own work spans is open. Bottleneck: the time the root
        # agent works while another agent's run is open and no other agent works.
        work_spans = [(start, end) for start, end in spans.values() if start["operation"] in WORK]
        runs = [(start, end) for start, end in spans.values() if start["operation"] == "RUN"]
        for start, end in runs:
            run_interval = [(start["timeMs"], end["timeMs"])]
            mine = [(s["timeMs"], e["timeMs"]) for s, e in work_spans if s["runId"] == start["runId"]]
            idle += (end["timeMs"] - start["timeMs"]) - _union(_intersect(mine, run_interval))
        root_work = [(s["timeMs"], e["timeMs"]) for s, e in work_spans if s["agentId"] == root_agent]
        other_work = [(s["timeMs"], e["timeMs"]) for s, e in work_spans if s["agentId"] != root_agent]
        other_runs = [(s["timeMs"], e["timeMs"]) for s, e in runs if s["agentId"] != root_agent]
        waiting = _intersect(root_work, other_runs)
        bottleneck += _union(waiting) - _union(_intersect(waiting, other_work))
    values["message_overhead"] = (sends, work)
    values["token_overhead"] = (send_tokens, work_tokens)
    values["duplicated_work_ratio"] = (duplicated, outputs)
    values["conflicting_claim_rate"] = (conflicting, claims)
    values["merge_conflict_rate"] = (merge_conflicts, merges)
    values["idle_time"] = (idle, 1)
    values["orchestrator_bottleneck_time"] = (bottleneck, 1)
    values["invalid_actions"] = (invalid, 1)
    values["retries"] = (retries, 1)
    values["replans"] = (replans, 1)
    values["stalled_turns"] = (stalled, 1)
    values["evidence_coverage"] = (covered, produced)
    values["unresolved_fraction"] = (unresolved, verified_ends)
    values["verifier_disagreement"] = (disagreeing, verified_subjects)
    values["denied_capability_attempts"] = (denied, 1)
    rows = []
    for name, unit in METRICS:
        numerator, denominator = _rational(*values[name])
        rows.append({"name": name, "unit": unit, "numerator": numerator if denominator else 0,
                     "denominator": denominator, "state": "DEFINED" if denominator else "UNDEFINED"})
    return rows


def _report_shape(doc) -> None:
    _refuse(_closed(doc, REPORT_KEYS) and doc["schemaVersion"] == METRICS_SCHEMA and _list(doc["runs"], 1)
            and all(_digest_str(r) for r in doc["runs"]) and len(set(doc["runs"])) == len(doc["runs"])
            and _opt_digest(doc["baseline"]) and _list(doc["metrics"])
            and all(_closed(m, METRIC_KEYS) and _ident(m["name"]) and type(m["unit"]) is str
                    and _int(m["numerator"], 0, MAX_INT) and _int(m["denominator"], 0, MAX_INT)
                    and m["state"] in ("DEFINED", "UNDEFINED") for m in doc["metrics"]), "SHAPE")


def check_report(doc: dict, stores: dict, loop) -> dict:
    """Check a MAS metrics report against the stores (`logs` and the log check's stores); return its facts or raise
    Refused."""
    def run():
        _report_shape(doc)
        named = doc["runs"] + ([] if doc["baseline"] is None else [doc["baseline"]])
        found = {r: _stored(stores, "logs", r) for r in named}
        _refuse(all(log is not None for log in found.values()), "UNKNOWN_REFERENCE")
        runs = [found[r] for r in doc["runs"]]
        baseline = None if doc["baseline"] is None else found[doc["baseline"]]
        for log in runs + ([] if baseline is None else [baseline]):
            try:
                check_log(log, stores, loop)
            except Refused as refusal:
                raise Refused("METRIC_INPUT") from refusal
        _refuse(len({len(_agents(log)) for log in runs}) == 1
                and (baseline is None or (len(_agents(baseline)) == 1 and doc["baseline"] not in doc["runs"])),
                "METRIC_INPUT")
        expected = compute_metrics(runs, baseline)
        _refuse(doc["metrics"] == expected, "METRIC_VALUE")
        return {"runs": len(runs), "agents": len(_agents(runs[0])),
                "undefined": [m["name"] for m in expected if m["state"] == "UNDEFINED"]}
    return _guarded(run)


# ---------------------------------------------------------------- MAST annotation (owner decision Q-MAS3-F)

ANNOTATION_SCHEMA = "planeon.internal.mast-annotation/v1"
ANNOTATION_CODES = ("SHAPE", "DUPLICATE_ID", "UNKNOWN_REFERENCE", "ANNOTATION_INPUT", "ANNOTATION_EVIDENCE")
# The MAST taxonomy (Cemri et al., "Why Do Multi-Agent LLM Systems Fail?", arXiv 2503.13657v3; the copy in
# roadmap/research/papers/2503.13657.pdf, sha256 1b9e317a2a421e60ca2b2eda4a30844557a01e63286a790890c0ecef32d25460):
# the three categories and fourteen modes with their names as the paper gives them (Figure 1 on page 2; the definitions
# in Appendix A on pages 17-18, which this contract cites and does not restate).
MAST_SOURCE = {"paper": "arXiv:2503.13657v3", "sha256": "1b9e317a2a421e60ca2b2eda4a30844557a01e63286a790890c0ecef32d25460",
               "taxonomyPage": 2, "definitionPages": [17, 18]}
MAST_CATEGORIES = {"FC1": "System Design Issues", "FC2": "Inter-Agent Misalignment", "FC3": "Task Verification"}
MAST_MODES = (("FM-1.1", "Disobey task specification", "FC1", 17), ("FM-1.2", "Disobey role specification", "FC1", 17),
              ("FM-1.3", "Step repetition", "FC1", 17), ("FM-1.4", "Loss of conversation history", "FC1", 17),
              ("FM-1.5", "Unaware of termination conditions", "FC1", 17), ("FM-2.1", "Conversation reset", "FC2", 17),
              ("FM-2.2", "Fail to ask for clarification", "FC2", 17), ("FM-2.3", "Task derailment", "FC2", 17),
              ("FM-2.4", "Information withholding", "FC2", 17), ("FM-2.5", "Ignored other agent\u2019s input", "FC2", 17),
              ("FM-2.6", "Reasoning-action mismatch", "FC2", 18), ("FM-3.1", "Premature termination", "FC3", 18),
              ("FM-3.2", "No or incomplete verification", "FC3", 18), ("FM-3.3", "Incorrect verification", "FC3", 18))
ANNOTATION_KEYS = ("schemaVersion", "logDigest", "annotations")
ENTRY_KEYS = ("annotationId", "mode", "evidence", "annotator")


def _annotation_shape(doc) -> None:
    modes = {m[0] for m in MAST_MODES}
    _refuse(_closed(doc, ANNOTATION_KEYS) and doc["schemaVersion"] == ANNOTATION_SCHEMA and _digest_str(doc["logDigest"])
            and _list(doc["annotations"], 1)
            and all(_closed(a, ENTRY_KEYS) and _ident(a["annotationId"]) and a["mode"] in modes
                    and _list(a["evidence"], 1) and all(_int(n, 1, MAX_INT) for n in a["evidence"])
                    and a["evidence"] == sorted(set(a["evidence"])) and _ident(a["annotator"])
                    for a in doc["annotations"]), "SHAPE")


def check_annotation(doc: dict, stores: dict, loop) -> dict:
    """Check a MAST annotation of a log: the log is stored under its digest and passes the log check (ANNOTATION_INPUT
    otherwise); each entry names one of the fourteen modes and the events (by sequence) it rests on, all in the annotated
    log. An annotation records a reading; it never changes a verdict or an outcome."""
    def run():
        _annotation_shape(doc)
        ids = [a["annotationId"] for a in doc["annotations"]]
        _refuse(len(ids) == len(set(ids)), "DUPLICATE_ID")
        log = _stored(stores, "logs", doc["logDigest"])
        _refuse(log is not None, "UNKNOWN_REFERENCE")
        try:
            check_log(log, stores, loop)
        except Refused as refusal:
            raise Refused("ANNOTATION_INPUT") from refusal
        count = len(log["events"])
        _refuse(all(n <= count for a in doc["annotations"] for n in a["evidence"]), "ANNOTATION_EVIDENCE")
        categories = {m[0]: m[2] for m in MAST_MODES}
        return {"annotations": len(ids), "categories": sorted({categories[a["mode"]] for a in doc["annotations"]})}
    return _guarded(run)



# ---------------------------------------------------------------- OpenTelemetry GenAI mapping (owner decision Q-MAS3-D)

# The pinned source: open-telemetry/semantic-conventions-genai at one commit (no release exists; development stability;
# re-pinned at its first release): the seven files fetched, each with its SHA-256. The operator-side builder checks this
# table against them.
OTEL_SOURCE = {"repository": "open-telemetry/semantic-conventions-genai",
               "commit": "4e8a2812139b2a999d959e3650e24dfc64e21943", "stability": "development",
               "schemaUrl": "https://opentelemetry.io/schemas/gen-ai-dev/1.42.0-dev",
               "files": {"model/gen-ai/entities.yaml": "f2bc7e63f692e5ddaf2594ca0cad25d835c6dad40157a003a4c80df2c4b2a8d0",
                         "model/gen-ai/events.yaml": "09095a702c18da3c883a5d2f053135c9ea253beac1f73079a253fe36e62f08d2",
                         "model/gen-ai/metrics.yaml": "2d96085fa29546af30de36c48579ef703365f1eb7cbc43b6a6d2d20dcef01cf6",
                         "model/gen-ai/registry.yaml": "fc7326952a9666e791a0af0ea3e07c9bdde4c46a526d36c2057685518ef37f1e",
                         "model/gen-ai/spans.yaml": "1f60d7d2685f07de8f4bb0c1834a0cf4124c2f1779ca8e855ceb131b0b48e657",
                         "model/gen-ai/token-metrics.yaml":
                             "66431869685e0f7b75d50f68fdfc228dfc0ad2a16c1188928fa69e619b4e4a19",
                         "model/manifest.yaml": "53f3589761cd853c6d234761cd07290ee6bc58b4b9758bc4b7b7039c3343e7b6"}}
# Each span operation to one OTel span: its GenAI span type (null: a plain span), kind, `gen_ai.operation.name`, name
# rule and attributes, each from an event field (`runId`, `agentId`) or a START attribute. A field that is null is left
# out (OTel attribute values are never null), and so is its `{field}` in the name. Span names hold only bounded
# identifiers (tool, gate and model ids), never run or agent ids, whose number grows with the runs (H15). A delegation is
# one `invoke_agent` span: the child RUN; its AGENT_INVOKE is a plain `delegate` span around it.
OTEL_SPANS = {
    "RUN": {"type": "gen_ai.invoke_agent.internal", "kind": "INTERNAL", "operation": "invoke_agent",
            "name": "invoke_agent", "attributes": {"gen_ai.agent.name": "agentId", "gen_ai.conversation.id": "runId"}},
    "AGENT_INVOKE": {"type": None, "kind": "INTERNAL", "operation": None, "name": "delegate",
                     "attributes": {"planeon.childRunId": "childRunId"}},
    "MODEL_CALL": {"type": "gen_ai.client.inference", "kind": "CLIENT", "operation": "chat", "name": "chat {model}",
                   "attributes": {"gen_ai.conversation.id": "runId", "gen_ai.provider.name": "provider",
                                  "gen_ai.request.model": "model"}},
    "TOOL_CALL": {"type": "gen_ai.execute_tool.internal", "kind": "INTERNAL", "operation": "execute_tool",
                  "name": "execute_tool {toolId}",
                  "attributes": {"gen_ai.tool.name": "toolId", "gen_ai.tool.call.id": "name", "gen_ai.agent.name": "agentId",
                                 "gen_ai.conversation.id": "runId"}},
    "VERIFICATION": {"type": None, "kind": "INTERNAL", "operation": None, "name": "verify {gateId}",
                     "attributes": {"planeon.gateId": "gateId"}},
}
# A VERIFICATION's END adds the GenAI evaluation event to the span it evaluated (events.yaml: parented to the evaluated
# operation's span), at the verification's end; points become span events in this contract's own namespace.
OTEL_EVALUATION_EVENT = {"name": "gen_ai.evaluation.result",
                         "attributes": {"gen_ai.evaluation.name": "gateId", "gen_ai.evaluation.score.label": "outcome"}}
OTEL_POINT_EVENTS = {op: "planeon.%s" % op.lower() for op in POINTS}
# Registry attributes this contract never emits: content and free text (Q-MAS3-C).
OTEL_NEVER_EMITTED = ("gen_ai.input.messages", "gen_ai.output.messages", "gen_ai.system_instructions",
                      "gen_ai.tool.definitions", "gen_ai.tool.call.arguments", "gen_ai.tool.call.result",
                      "gen_ai.retrieval.documents", "gen_ai.retrieval.query.text", "gen_ai.memory.records",
                      "gen_ai.memory.query.text", "gen_ai.prompt.variable", "gen_ai.evaluation.explanation",
                      "gen_ai.agent.description", "gen_ai.main_agent.description", "gen_ai.tool.description",
                      "gen_ai.skill.description")
_PLACEHOLDER = re.compile(r" \{(\w+)\}")


def to_otel(log: dict) -> list:
    """The OTel spans of a checked log, in START order: trace and span ids, parent, name, kind, start and end
    (milliseconds from the root run's start), status (ERROR for an END outcome other than OK or COMPLETED, with the
    core attribute `error.type` set to that outcome), the mapped attributes that are not null, and the span events (points,
    and the evaluation event on each evaluated span). Token counts stay `planeon.tokens` (the registry has no total-token
    attribute) and are inclusive: a run's tokens include its delegations', so they are never summed across spans; the
    plain `delegate` span carries none."""
    spans, order, starts = {}, [], {}
    for e in log["events"]:
        if e["phase"] == "START":
            spec = OTEL_SPANS[e["operation"]]
            fields = dict(e["attributes"], runId=e["runId"], agentId=e["agentId"], name=e["name"])
            attributes = {key: fields[source] for key, source in spec["attributes"].items()
                          if fields.get(source) is not None}
            if spec["operation"] is not None:
                attributes["gen_ai.operation.name"] = spec["operation"]
            name = _PLACEHOLDER.sub(lambda m: "" if fields.get(m.group(1)) is None else " %s" % fields[m.group(1)],
                                    spec["name"])
            spans[e["spanId"]] = {"traceId": log["traceId"], "spanId": e["spanId"], "parentSpanId": e["parentSpanId"],
                                  "name": name, "kind": spec["kind"], "startMs": e["timeMs"], "endMs": None,
                                  "status": "UNSET", "attributes": attributes, "events": []}
            starts[e["spanId"]] = e
            order.append(e["spanId"])
        elif e["phase"] == "END":
            span = spans[e["spanId"]]
            span["endMs"] = e["timeMs"]
            if e["outcome"] not in ("OK", "COMPLETED"):
                span["status"] = "ERROR"
                span["attributes"]["error.type"] = e["outcome"]
            if "tokens" in e["attributes"] and e["operation"] != "AGENT_INVOKE":
                span["attributes"]["planeon.tokens"] = e["attributes"]["tokens"]
            if e["operation"] == "VERIFICATION":
                start = starts[e["spanId"]]["attributes"]
                spans[start["subjectSpanId"]]["events"].append(
                    {"name": OTEL_EVALUATION_EVENT["name"], "timeMs": e["timeMs"],
                     "attributes": {"gen_ai.evaluation.name": start["gateId"],
                                    "gen_ai.evaluation.score.label": e["outcome"]}})
        else:
            spans[e["spanId"]]["events"].append({"name": OTEL_POINT_EVENTS[e["operation"]], "timeMs": e["timeMs"],
                                                 "attributes": {"planeon.%s" % k: v for k, v in
                                                                sorted(e["attributes"].items()) if v is not None}})
    return [spans[span] for span in order]


if __name__ == "__main__":
    from pathlib import Path

    import importlib.util

    root = Path(__file__).resolve().parents[1]
    spec = importlib.util.spec_from_file_location("_agent_loop", root / "scripts/agent_loop.py")
    loop_model = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(loop_model)
    vectors = json.loads((root / "architecture/run-events/vectors.json").read_bytes())
    stores = vectors["stores"]
    checks = {"log": lambda d: check_log(d, stores, loop_model), "report": lambda d: check_report(d, stores, loop_model),
              "annotation": lambda d: check_annotation(d, stores, loop_model)}
    for row in vectors["cases"]:
        try:
            facts = checks[row["kind"]](row["document"])
            got = None
        except Refused as refusal:
            got, facts = refusal.code, None
        assert got == row["expect"], (row["id"], got, row["expect"])
        if facts is not None and "facts" in row:
            assert {k: facts[k] for k in row["facts"]} == row["facts"], row["id"]
    for row in vectors["texts"]:
        try:
            checks[row["kind"]](parse(row["text"]))
            got = None
        except Refused as refusal:
            got = refusal.code
        assert got == row["expect"], row["id"]
    for row in vectors["otelProjections"]:
        assert to_otel(stores["logs"][row["log"]]) == row["spans"], row["log"]
    print("run events vectors replay: %d cases, %d texts, %d OTel projections"
          % (len(vectors["cases"]), len(vectors["texts"]), len(vectors["otelProjections"])))
