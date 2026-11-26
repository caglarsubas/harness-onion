#!/usr/bin/env python3
"""HR-COMPACTION-GOV-001 (MET-013, slot 295): the reference model of the agent loop's context-compaction clauses.

This is a successor candidate to MAS-RA-008's loop contract (architecture/agent-loop/, unchanged): the step-kind set
gains COMPACT; the hook events, the trust labels and the terminal statuses stay as MAS-RA-008 writes them. The record
is architecture/agent-loop-compaction/record.json; the vectors are architecture/agent-loop-compaction/vectors.json.

Each vector is one scenario of one clause family (C1 to C9). `evaluate(family, data)` returns (code, result): code is
None when the scenario is accepted, else the family's refusal code; result holds the derived facts a vector may pin.
The model is deterministic and reads nothing; it imports the standard library only.
"""
from __future__ import annotations

import hashlib
import json

CODES = {"C1": "CG_LOCK", "C2": "CG_RANGE", "C3": "CG_CHECKPOINT", "C4": "CG_LADDER", "C5": "CG_EPOCH",
         "C6": "CG_PROMPT", "C7": "CG_TRUST", "C8": "CG_RETENTION", "C9": "CG_GATE"}
STEP_KINDS = ("MODEL", "TOOL", "GATE", "HOOK", "HANDOFF", "DELEGATE", "COMPACT")
BRACKET_KINDS = ("HOOK", "COMPACT", "GATE")
TELEMETRY_KEYS = ("count", "durationMs", "outcome", "digest")
FALLBACK_KEYS = ("artefactDigests", "stepIds", "trustLabels")
PROFILE_COOLDOWNS = (60, 300, 900)
QUERY_HOOKS = ("MODEL_QUERY_AFTER", "MODEL_QUERY_BEFORE")
COMPACT_DETAIL = ("lockId", "rangeFirstSeq", "rangeLastSeq", "checkpointDigest", "summaryDigest", "summaryKind",
                  "summaryTrust", "summaryRoute", "epoch", "systemPromptDigest")
CONSUMERS = ("MODEL", "WRITE_TOOL", "DELEGATE", "DELIVERY", "HANDOFF")
PLACEMENTS = ("DATA", "SYSTEM_PROMPT", "INSTRUCTION_SOURCE", "PINNED")
UNTRUSTED_LABEL = "UNTRUSTED_TOOL_OUTPUT"


class Refused(Exception):
    """A clause refusal; `code` is the family's code."""

    def __init__(self, code: str, detail: str) -> None:
        super().__init__(detail)
        self.code = code


def canonical(value) -> bytes:
    """The sorted-key compact JSON form (integers and strings only in this model's inputs)."""
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def digest(value) -> str:
    return "sha256:" + hashlib.sha256(canonical(value)).hexdigest()


def bytes_digest(text: str) -> str:
    return "sha256:" + hashlib.sha256(text.encode("utf-8")).hexdigest()


def _need(ok: bool, family: str, detail: str) -> None:
    if not ok:
        raise Refused(CODES[family], detail)


# -- C1: the lock bracket ----------------------------------------------------------------------------------------------

def lock_bracket(data: dict) -> dict:
    """One lock per run; inside it only the compaction's own HOOK, COMPACT and GATE steps; never a HANDOFF; an orphan
    lock found on open is discarded, the context restored from the archive and one orphan event recorded. At unlock the
    bracket holds one or two owned COMPACT steps (a MODEL summary, and its FALLBACK after a gate FAIL); none or more
    than two is refused (#254, MET-016 F1)."""
    held, orphan, result = False, False, {"orphanEvents": 0, "restores": 0, "locksClosed": 0}
    compacts = 0
    for event in data["events"]:
        op = event["op"]
        if op == "open":
            if orphan:
                result["orphanEvents"] += 1
                result["restores"] += 1
                orphan = False
        elif op == "lock":
            _need(not held and not orphan, "C1", "a second lock in the same run")
            held, compacts = True, 0
        elif op == "step":
            if held:
                _need(event["kind"] != "HANDOFF", "C1", "a HANDOFF inside the bracket")
                _need(event["kind"] in BRACKET_KINDS and event.get("own") is True, "C1",
                      "a step that is not the compaction's own inside the bracket")
                compacts += event["kind"] == "COMPACT"
        elif op == "unlock":
            _need(held, "C1", "an unlock without a lock")
            _need(1 <= compacts <= 2, "C1", "a bracket with no COMPACT step or more than two")
            held = False
            result["locksClosed"] += 1
        elif op == "crash":
            orphan, held = held, False
    return result


# -- C2: the balanced range -------------------------------------------------------------------------------------------

def balanced_range(data: dict) -> dict:
    """A contiguous range that splits no tool exchange and holds no unsettled DELEGATE; later steps reference the
    summary forward only; no earlier record changes; every artefact digest the summary names is inside the range."""
    first, last = data["compact"]["rangeFirstSeq"], data["compact"]["rangeLastSeq"]   # COMPACT's own detail
    steps = {s["seq"]: s for s in data["steps"]}
    inside = lambda seq: first <= seq <= last
    _need(first <= last and all(seq in steps for seq in range(first, last + 1)), "C2", "the range is not contiguous")
    for step in data["steps"]:
        if step["kind"] == "TOOL":
            for seq in step.get("consumes", []):
                if steps.get(seq, {}).get("kind") == "MODEL":
                    _need(inside(seq) == inside(step["seq"]), "C2", "the range splits a tool exchange")
        if step["kind"] == "DELEGATE" and inside(step["seq"]):
            _need(step.get("settled") is True, "C2", "an unsettled DELEGATE in the range")
    _need(not data.get("rewrites"), "C2", "the compaction rewrites an earlier record")
    held = {a for seq in range(first, last + 1) for a in steps[seq].get("artefacts", [])}
    _need(set(data.get("summary", {}).get("names", [])) <= held, "C2", "the summary names a digest outside the range")
    return {"dropped": last - first + 1}


# -- C3: the checkpoint gate ------------------------------------------------------------------------------------------

def checkpoint_gate(data: dict) -> dict:
    """The archive of the full range exists, by digest, before anything is dropped; the same archive written twice is
    one record; a missing or mismatched archive is refused and nothing is dropped."""
    want = digest(data["range"])
    archives = sorted(set(data.get("archives", [])))
    named = data["compact"]["checkpointDigest"]
    _need(named == want and want in archives, "C3", "no archive of the range under the named digest")
    return {"archiveRecords": len(archives), "rangeDigest": want}


# -- C4: the failure ladder and the repeated-compaction bound ---------------------------------------------------------

def failure_ladder(data: dict) -> dict:
    """A failed MODEL summary (query or gate) falls back to a content-free FALLBACK; cooldowns rise and persist across a
    restart; telemetry is content-free; overflow is typed and handed off, never truncated; after a gate FAIL the same
    bracket appends a FALLBACK COMPACT over the same range (R2-F1)."""
    cooldowns = data["profile"]["cooldowns"]
    _need(bool(cooldowns) and all(type(c) is int and c > 0 for c in cooldowns)
          and all(a < b for a, b in zip(cooldowns, cooldowns[1:])), "C4", "the cooldown steps do not rise")
    failures, ready_at, typed, steps, waits = 0, 0, False, [], []
    for event in data["events"]:
        op = event["op"]
        if op == "attempt":
            _need(event["t"] >= ready_at, "C4", "a model-summary attempt inside the cooldown")
            if event["result"] == "OK":
                failures = 0
            else:
                wait = cooldowns[min(failures, len(cooldowns) - 1)]
                failures += 1
                ready_at = event["t"] + wait
                waits.append(wait)
        elif op == "restart":
            pass  # the cooldown state persists: ready_at is kept
        elif op == "telemetry":
            _need(set(event["record"]) <= set(TELEMETRY_KEYS), "C4", "a telemetry record with content")
        elif op == "overflow":
            typed = event.get("typed") is True
            _need(typed, "C4", "an untyped overflow")
        elif op == "handoff":
            _need(typed, "C4", "a handoff without the typed overflow")
        elif op == "truncate":
            _need(False, "C4", "truncation without the typed overflow")
        elif op == "compact":
            if event["kind"] == "FALLBACK":
                _need(set(event.get("summary", {})) <= set(FALLBACK_KEYS), "C4",
                      "a FALLBACK summary holds content or a pinned item")
                if steps:
                    _need(event.get("sameRange") is True, "C4", "the FALLBACK COMPACT does not cover the same range")
            steps.append(event["kind"])
        elif op == "gate":
            steps.append("GATE_" + event["result"])
        elif op == "unlock":
            steps.append("UNLOCK")
    result = {"cooldowns": waits, "failures": failures}
    if steps:
        _need(steps in (["MODEL", "GATE_OK", "UNLOCK"], ["MODEL", "GATE_FAIL", "FALLBACK", "UNLOCK"],
                        ["FALLBACK", "UNLOCK"]), "C4", "the bracket's steps are not in the pinned order")
        result["bracket"] = steps
        result["referenced"] = [k for k in steps if k in ("MODEL", "FALLBACK")][-1]
    return result


# -- C5: instruction epochs -------------------------------------------------------------------------------------------

def instruction_epochs(data: dict) -> dict:
    """A mid-run instruction change is a recorded delta and raises the epoch; a compaction resets it to 0 and the full
    set is re-hashed; a change with no delta record is refused."""
    epoch, deltas, rehashes = 0, 0, 0
    for event in data["events"]:
        if event["op"] == "change":
            _need(event.get("delta") is True, "C5", "an instruction change with no delta record")
            epoch, deltas = epoch + 1, deltas + 1
        elif event["op"] == "compact":
            epoch, rehashes = 0, rehashes + 1
    return {"epoch": epoch, "deltas": deltas, "rehashes": rehashes}


# -- C6: the byte-stable system prompt --------------------------------------------------------------------------------

def stable_prompt(data: dict) -> dict:
    """The system prompt's digest is equal on every MODEL step, except on the first MODEL step after a COMPACT step."""
    digests, last, after_compact = [], None, False
    for step in data["steps"]:
        if step["kind"] == "COMPACT":
            after_compact = True
        elif step["kind"] == "MODEL":
            now = bytes_digest(step["prompt"])
            _need(last is None or now == last or after_compact, "C6", "a prompt change outside a compaction")
            digests.append(now)
            last, after_compact = now, False
    return {"digests": digests}


# -- C7: summary trust ------------------------------------------------------------------------------------------------

def summary_trust(data: dict) -> dict:
    """The summary's trust is computed from the range (UNTRUSTED when any step holds or consumed an untrusted tool
    output); it enters as data only. A byte-identical summary reused over another range is checked by the COMPACT
    step against that range, whatever an earlier gate on the same bytes decided (R2-F2)."""
    labels = {s["seq"]: s["label"] for s in data.get("context", []) + data["range"]}
    untrusted = any(s["label"] == UNTRUSTED_LABEL or any(labels.get(c) == UNTRUSTED_LABEL for c in s.get("consumes", []))
                    for s in data["range"])
    computed = "UNTRUSTED" if untrusted else "TRUSTED"
    summary = data["summary"]
    _need(summary["trust"] == computed, "C7", "the summary's trust label is not the computed one")
    _need(summary.get("placement", "DATA") == "DATA", "C7", "the summary is placed with instruction authority")
    return {"computed": computed}


# -- C8: archive retention and deletion -------------------------------------------------------------------------------

def archive_retention(data: dict) -> dict:
    """The archive's retention is the trace's, never longer; a tenant deletion removes it and leaves a deletion record;
    a restore from a deleted archive fails typed, never silently."""
    _need(data["archive"]["retentionDays"] <= data["trace"]["retentionDays"], "C8", "the archive outlives its trace")
    deleted, result = False, {"deletionRecords": 0}
    for event in data.get("events", []):
        if event["op"] == "delete":
            deleted = True
            result["deletionRecords"] += 1
        elif event["op"] == "restore":
            if deleted:
                _need(event["onDeleted"] == "TYPED_ERROR", "C8", "a restore from a deleted archive continued")
                result["restore"] = "DELETED"
            else:
                result["restore"] = "RESTORED"
    return result


# -- C9: the governed summary query -----------------------------------------------------------------------------------

def governed_summary(data: dict) -> dict:
    """A MODEL summary (a supplied one included, R2-N2) passes both model-query hooks, uses a declared route and passes
    the A3 GATE on its bytes before any consumer reads it (R2-N1); a gate FAIL is never overridden and is a failed
    summary for C4. A FALLBACK summary needs no gate."""
    summary = data["summary"]
    if summary["kind"] == "FALLBACK":
        return {"gated": False}
    _need(summary["route"] in data["profile"]["routes"], "C9", "a summary query on an undeclared route")
    _need(sorted(summary["hooks"]) == list(QUERY_HOOKS), "C9", "a summary query outside the model-query hooks")
    gate = summary["gate"]
    for consumer in data.get("consumers", []):
        _need(consumer["kind"] in CONSUMERS and gate == "OK", "C9", "a consumer reads an ungated or failed summary")
    _need(not (gate == "FAIL" and data.get("override")), "C9", "a gate FAIL overridden")
    return {"gated": gate == "OK", "failedSummary": gate == "FAIL", "supplied": summary.get("effect") == "SUPPLY_OUTPUT"}


FAMILIES = {"C1": lock_bracket, "C2": balanced_range, "C3": checkpoint_gate, "C4": failure_ladder,
            "C5": instruction_epochs, "C6": stable_prompt, "C7": summary_trust, "C8": archive_retention,
            "C9": governed_summary}


def evaluate(family: str, data: dict):
    """(None, result) when accepted, (code, {}) when refused; KeyError or TypeError on a malformed scenario."""
    try:
        return None, FAMILIES[family](data)
    except Refused as refusal:
        return refusal.code, {}


def replay(case: dict):
    """(ok, got): whether the case's expectation holds, and what the model gave."""
    code, result = evaluate(case["family"], case["input"])
    expect = case["expect"]
    if "refuse" in expect:
        return code == expect["refuse"], code
    ok = code is None and all(result.get(k) == v for k, v in expect.get("result", {}).items())
    return ok, code if code else result
