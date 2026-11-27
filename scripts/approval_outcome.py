#!/usr/bin/env python3
"""HR-APPROVAL-OUTCOME-001 (MET-013, slot 295): the reference model of the approval outcome contract.

The record is architecture/approval-outcome/record.json; the vectors are architecture/approval-outcome/vectors.json.
The contract is the closed outcome set (O1-O5), the log-only audit pair (A1-A5), the statement order (S1-S5), the
scope of staff approvals (N1 scope) and the refusal rule for headless contexts (H1a, H1b, H2-H4), with R00's settings
(the open state REQUESTED, the record's fields, one sweep interval per store owner) and the rulings R2-N1, Q-TLA-1,
Q-TLA-2 (r3, r4) and the hub's N1 clause.

- simulate(scenario): the reference lifecycle of one request over timed events (ask, decide, cancel, sweep, read,
  effect); it returns the row, the audit pair, the refused operations with their typed reasons, the reads and the
  effects. It never refuses a scenario: it shows what the contract makes happen.
- check_history(history), check_read(case), check_statements(case), check_profile(profile): recorded data that breaks a
  clause is refused with its family's code, first met first: AO_SHAPE, AO_SCOPE, AO_OUTCOME, AO_AUDIT, AO_STATEMENT,
  AO_HEADLESS. Times are integer seconds. The model imports the standard library only.
"""
from __future__ import annotations

import re

OPEN = "REQUESTED"
OUTCOMES = ("APPROVED", "REJECTED", "EXPIRED", "CANCELLED", "UNAVAILABLE")
STATES = OUTCOMES + (OPEN,)
ASKED_EVENT, DECIDED_EVENT = "approval.requested.v1", "approval.decision-recorded.v1"
KINDS = ("demand", "profile", "trust")            # staff approvals; R05's customer confirmation is never a row
CUSTOMER_CONFIRMATION = "customer-confirmation"
ASK_ANSWERS = ("ELIGIBLE", "NOT_ELIGIBLE", "DENIED", "UNAVAILABLE")
DECIDE_ANSWERS = ("ELIGIBLE", "NOT_ELIGIBLE", "UNAVAILABLE")
ASK_REFUSALS = ("NOT_ELIGIBLE", "DENIED")
UNAVAILABLE_REASONS = ("PORT_UNAVAILABLE_AT_ASK", "PORT_UNAVAILABLE_AT_DECISION", "NO_CERTIFIED_GATE")
DECIDED_BY = ("HUMAN", "SYSTEM", "REQUESTER", "SUPERSEDED", "WORKLOAD", "TRIGGER", "MODEL")
DECIDER_TYPES = ("HUMAN", "WORKLOAD", "TRIGGER", "MODEL")
LAYERS = ("FLOOR", "PACK", "PROFILE", "ORGANISATION")
LAYER_RANK = {"FLOOR": 0, "PACK": 1, "PROFILE": 1, "ORGANISATION": 2}
EFFECTS = ("ALLOW", "ASK", "DENY")
SWEEP_OWNERS = ("demand", "profile", "governance")
SWEEP_MIN, SWEEP_MAX, SWEEP_DEFAULT = 1, 3600, 300
ROW_KEYS = ("requestId", "kind", "state", "subjectId", "revision", "subjectDigest", "policyRef", "policyBindingDigest",
            "ruleVersion", "mandate", "expiresAt", "asker", "askPort", "decidePort", "decisionRef", "decidedBy",
            "reasonCode", "decidingStatement")
ROW_OPTIONAL = ("businessIntentId", "payloadHash", "evidenceVersions", "preconditions", "compartment", "limits")
HISTORY_KEYS = ("row", "audit", "decisions", "gates", "effects", "now", "sweepInterval")
HISTORY_OPTIONAL = ("httpUnavailable", "grantSource")
CODES = ("AO_SHAPE", "AO_SCOPE", "AO_OUTCOME", "AO_AUDIT", "AO_STATEMENT", "AO_HEADLESS")
AUTO_APPROVE = re.compile(r"auto[._ -]?approv", re.I)
DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")
IDENT = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}\Z")


class Refused(ValueError):
    def __init__(self, code: str):
        super().__init__(code)
        self.code = code


def need(ok, code: str) -> None:
    if not ok:
        raise Refused(code)


def _guarded(run):
    try:
        return run()
    except (KeyError, TypeError, AttributeError, IndexError) as exc:
        raise Refused("AO_SHAPE") from exc


def _closed(value, keys, optional=()) -> bool:
    return type(value) is dict and set(keys) <= set(value) <= set(keys) | set(optional)


def _int(value, low=0) -> bool:
    return type(value) is int and value >= low


def _text(value) -> bool:
    return type(value) is str and value != ""


def _digest(value) -> bool:
    return type(value) is str and DIGEST.match(value) is not None


def _ident(value) -> bool:
    return type(value) is str and IDENT.match(value) is not None


# ---------------------------------------------------------------- O1, O3: the read projection

def project(row, now: int) -> str:
    """What a read reports, without a write: NONE when no row; EXPIRED for an open request at or past its expiry (O3);
    REFUSED_UNKNOWN for a stored value outside the six (O1); else the stored state."""
    if row is None:
        return "NONE"
    if row["state"] not in STATES:
        return "REFUSED_UNKNOWN"
    if row["state"] == OPEN and now >= row["expiresAt"]:
        return "EXPIRED"
    return row["state"]


def permits(outcome: str) -> bool:
    """O2: only APPROVED permits the effect."""
    return outcome == "APPROVED"


# ---------------------------------------------------------------- the lifecycle (H1b, O4, Q-TLA-2, N1, A5)

def ask_context(asker) -> str | None:
    """None when the asker may ask; else the UNAVAILABLE reason, decided before the port is asked (r4). An interactive
    human session may ask. A workload (any caller without an interactive session: a triggered run, a job, a CLI or API
    caller) may ask only through a gate of its certified trigger definition with R05 section 8's three conditions; an
    unavailable admission lookup fails closed (R2-N2)."""
    if asker["type"] == "HUMAN":
        return None
    gate = asker.get("gate")
    if not gate or gate.get("lookup") == "UNAVAILABLE":
        return "NO_CERTIFIED_GATE"
    if not (gate.get("certified") and gate.get("validAtRevalidation") and gate.get("inGates") and gate.get("admitted")):
        return "NO_CERTIFIED_GATE"
    return None


def _asker_record(asker) -> dict:
    if asker["type"] == "HUMAN":
        return {"type": "HUMAN", "requesterDigest": asker["requesterDigest"]}
    record = {"type": "WORKLOAD", "workloadDigest": asker["workloadDigest"]}
    gate = asker.get("gate") or {}
    for key in ("definitionId", "definitionVersion", "definitionDigest", "admissionRecordId"):
        if key in gate:
            record[key] = gate[key]
    return record


def simulate(scenario: dict) -> dict:
    """One request's lifecycle. Events: ask {t, asker, port, subject, expiresAt}; decide {t, reviewer, port, vote,
    reasonCode?, statement?}; cancel {t, by}; sweep {t}; read {t}; effect {t, subject}."""
    kind, quorum = scenario["kind"], scenario.get("quorum", 1)
    out = {"row": None, "audit": [], "decisions": [], "votes": [], "effects": [], "refusals": [], "reads": [],
           "portAsked": 0}

    def record(event, row, t, outcome=None, occurred=None):
        rec = {"event": event, "kind": kind, "requestId": row["requestId"], "occurredAt": t if occurred is None
               else occurred, "recordedAt": t, "sameTransaction": True}
        if event == DECIDED_EVENT:
            rec["outcome"] = outcome
        out["audit"].append(rec)

    def close(row, state, t, by, reason=None, occurred=None):
        row["state"] = state
        row["decisionRef"] = {"id": row["requestId"] + ".decision", "at": t if occurred is None else occurred}
        row["decidedBy"] = by
        row["reasonCode"] = reason
        record(DECIDED_EVENT, row, t, state, occurred)

    def expire(row, t):
        close(row, "EXPIRED", t, {"type": "SYSTEM"}, occurred=row["expiresAt"])

    for ev in scenario["events"]:
        op, t, row = ev["op"], ev["t"], out["row"]
        if op == "ask":
            if row is not None:
                out["refusals"].append("ALREADY_ASKED")
                continue
            reason, answer = ask_context(ev["asker"]), "NOT_ASKED"
            if reason is None:
                out["portAsked"] += 1
                answer = ev["port"]
                if answer in ASK_REFUSALS:            # Q-TLA-2: refused with a typed reason; nothing is written
                    out["refusals"].append(answer)
                    continue
                if answer == "UNAVAILABLE":
                    reason = "PORT_UNAVAILABLE_AT_ASK"
            s = ev["subject"]
            row = dict({"requestId": s["requestId"], "kind": kind, "state": OPEN, "subjectId": s["subjectId"],
                        "revision": s["revision"], "subjectDigest": s["subjectDigest"], "policyRef": s["policyRef"],
                        "policyBindingDigest": s["policyBindingDigest"], "ruleVersion": s["ruleVersion"],
                        "mandate": s["mandate"], "expiresAt": ev["expiresAt"], "asker": _asker_record(ev["asker"]),
                        "askPort": answer, "decidePort": "NOT_ASKED", "decisionRef": None, "decidedBy": None,
                        "reasonCode": None, "decidingStatement": None},
                       **{k: s[k] for k in ROW_OPTIONAL if k in s})
            out["row"] = row
            record(ASKED_EVENT, row, t)
            if reason is not None:                    # O4: recorded at once, never only a status code
                close(row, "UNAVAILABLE", t, {"type": "SYSTEM"}, reason)
        elif op == "decide":
            if row is None or row["state"] != OPEN:
                out["refusals"].append("NOT_OPEN")
                continue
            if t >= row["expiresAt"]:                 # A5 (a): the first mutation after the expiry writes EXPIRED
                expire(row, t)
                out["refusals"].append("EXPIRED")
                continue
            rv = ev["reviewer"]
            if rv["type"] != "HUMAN" or rv.get("isRequester"):   # H1a: no vote or outcome from anyone else
                out["refusals"].append("NOT_A_DECIDER")
                continue
            port = ev["port"]
            if port["answer"] == "UNAVAILABLE":       # N1, O4: an unreadable port at the decision is terminal
                row["decidePort"] = "UNAVAILABLE"
                close(row, "UNAVAILABLE", t, {"type": "SYSTEM"}, "PORT_UNAVAILABLE_AT_DECISION")
                continue
            if port["answer"] != "ELIGIBLE" or rv["id"] not in port["eligible"]:
                out["refusals"].append("NOT_ELIGIBLE")    # R2-N1, N1: refused; the request stays REQUESTED
                continue
            if any(v["reviewerId"] == rv["id"] for v in out["votes"]):
                out["refusals"].append("DUPLICATE_VOTE")
                continue
            if ev["vote"] == "REJECT" and not ev.get("reasonCode"):
                out["refusals"].append("REASON_REQUIRED")
                continue
            out["votes"].append({"reviewerId": rv["id"], "vote": ev["vote"], "at": t})
            out["decisions"].append({"deciderType": "HUMAN", "deciderId": rv["id"], "source": "REVIEWER",
                                     "portEligible": list(port["eligible"]), "vote": ev["vote"], "at": t})
            row["decidePort"] = "ELIGIBLE"
            row["decidingStatement"] = ev.get("statement")
            by = {"type": "HUMAN", "idDigest": rv["idDigest"]}
            if ev["vote"] == "REJECT":
                close(row, "REJECTED", t, by, ev["reasonCode"])
            elif sum(v["vote"] == "APPROVE" for v in out["votes"]) >= quorum:
                close(row, "APPROVED", t, by)
        elif op == "cancel":
            if row is None or row["state"] != OPEN:
                out["refusals"].append("NOT_OPEN")
            elif t >= row["expiresAt"]:
                expire(row, t)
                out["refusals"].append("EXPIRED")
            else:
                close(row, "CANCELLED", t, {"type": ev["by"]})
        elif op == "sweep":
            if row is not None and row["state"] == OPEN and t >= row["expiresAt"]:
                expire(row, t)
        elif op == "read":
            out["reads"].append(project(row, t))
        elif op == "effect":
            done = any(e["permitted"] for e in out["effects"])
            ok = (row is not None and row["state"] == "APPROVED" and row["decisionRef"]["at"] < t and not done
                  and all(ev["subject"].get(k) == row[k] for k in ("subjectId", "revision", "subjectDigest",
                                                                    "policyBindingDigest")))
            out["effects"].append({"at": t, "permitted": ok})
        else:
            raise KeyError(op)
    row = out["row"]
    asked = sum(a["event"] == ASKED_EVENT for a in out["audit"])
    decided = sum(a["event"] == DECIDED_EVENT for a in out["audit"])
    return {"state": None if row is None else row["state"], "reason": None if row is None else row["reasonCode"],
            "asked": asked, "decided": decided, "refusals": out["refusals"], "reads": out["reads"],
            "effects": [e["permitted"] for e in out["effects"]], "portAsked": out["portAsked"],
            "votes": len(out["votes"]), "occurredAt": None if row is None or row["decisionRef"] is None
            else row["decisionRef"]["at"], "asker": None if row is None else row["asker"]["type"], "_raw": out}


def history_of(scenario: dict, result: dict) -> dict:
    """The recorded history a simulated lifecycle leaves (for check_history)."""
    raw = result["_raw"]
    last = max([ev["t"] for ev in scenario["events"]] or [0])
    return {"row": raw["row"], "audit": raw["audit"], "decisions": raw["decisions"], "gates": [],
            "effects": [{"at": e["at"]} for e in raw["effects"] if e["permitted"]], "now": last,
            "sweepInterval": scenario.get("sweepInterval", SWEEP_DEFAULT)}


# ---------------------------------------------------------------- recorded histories

def _row_shape(row) -> bool:
    asker = row.get("asker") if type(row) is dict else None
    return (_closed(row, ROW_KEYS, ROW_OPTIONAL) and _ident(row["requestId"]) and _text(row["kind"])
            and type(row["state"]) is str and _ident(row["subjectId"]) and _int(row["revision"], 1)
            and _digest(row["subjectDigest"]) and _text(row["policyRef"]) and _digest(row["policyBindingDigest"])
            and _text(row["ruleVersion"]) and _text(row["mandate"]) and _int(row["expiresAt"])
            and type(asker) is dict and asker.get("type") in ("HUMAN", "WORKLOAD")
            and row["askPort"] in ASK_ANSWERS + ("NOT_ASKED",) and row["decidePort"] in DECIDE_ANSWERS + ("NOT_ASKED",)
            and (row["decisionRef"] is None or (_closed(row["decisionRef"], ("id", "at")) and _int(row["decisionRef"]["at"])))
            and (row["decidedBy"] is None or (type(row["decidedBy"]) is dict and row["decidedBy"].get("type") in DECIDED_BY))
            and (row["reasonCode"] is None or _text(row["reasonCode"]))
            and (row["decidingStatement"] is None or _closed(row["decidingStatement"], ("id", "version")))
            and all(k not in row or row[k] is not None for k in ROW_OPTIONAL)
            and ("payloadHash" not in row or _digest(row["payloadHash"])))


def check_history(h: dict) -> dict:
    """A recorded history: the approval row (or none), the audit records, the decisions, the gates, the effects that
    ran, the time of the check and the store owner's sweep interval."""
    def run():
        row = h["row"] if type(h) is dict else None
        need(_closed(h, HISTORY_KEYS, HISTORY_OPTIONAL) and (row is None or _row_shape(row))
             and all(type(h[k]) is list for k in ("audit", "decisions", "gates", "effects"))
             and _int(h["now"]) and _int(h["sweepInterval"], SWEEP_MIN) and h["sweepInterval"] <= SWEEP_MAX,
             "AO_SHAPE")                                   # histories bound the interval as profiles do (MET-016 F4)
        need(row is None or row["kind"] in KINDS, "AO_SCOPE")                     # N1 scope: staff approvals only
        audit, decisions = h["audit"], h["decisions"]
        need(not h.get("httpUnavailable") or (row is not None and row["state"] == "UNAVAILABLE"), "AO_OUTCOME")  # O4
        if row is not None:
            need(row["state"] in STATES, "AO_OUTCOME")                           # O1
            need(row["askPort"] not in ASK_REFUSALS, "AO_OUTCOME")               # Q-TLA-2
            if row["state"] == "APPROVED":                                       # O2, S5
                need(row["askPort"] == "ELIGIBLE" and row["decidePort"] == "ELIGIBLE", "AO_OUTCOME")
            if row["state"] == "UNAVAILABLE":                                    # the three sources
                need(row["reasonCode"] in UNAVAILABLE_REASONS, "AO_OUTCOME")
                need((row["reasonCode"] == "PORT_UNAVAILABLE_AT_ASK") == (row["askPort"] == "UNAVAILABLE")
                     and (row["reasonCode"] == "NO_CERTIFIED_GATE") == (row["askPort"] == "NOT_ASKED")
                     and (row["reasonCode"] == "PORT_UNAVAILABLE_AT_DECISION") == (row["decidePort"] == "UNAVAILABLE"),
                     "AO_OUTCOME")
            if row["state"] == "REJECTED":
                need(_text(row["reasonCode"]), "AO_OUTCOME")
            need(len(h["effects"]) <= 1, "AO_OUTCOME")                           # O2: once
        need(all(a.get("event") in (ASKED_EVENT, DECIDED_EVENT) for a in audit), "AO_AUDIT")   # A1
        need(h.get("grantSource", "ROW") == "ROW", "AO_AUDIT")                    # A3: log-only
        need(all(a.get("sameTransaction") is True for a in audit), "AO_AUDIT")    # A4
        if row is None:
            need(not audit, "AO_AUDIT")
        else:
            asked = [a for a in audit if a["event"] == ASKED_EVENT]
            decided = [a for a in audit if a["event"] == DECIDED_EVENT]
            need(len(asked) == 1 and all(a["kind"] == row["kind"] and a["requestId"] == row["requestId"] for a in audit),
                 "AO_AUDIT")                                                       # A1: the kind is a field
            terminal = row["state"] in OUTCOMES
            need(len(decided) == (1 if terminal else 0), "AO_AUDIT")              # A2: the pair is closed
            if terminal:
                need(decided[0]["outcome"] == row["state"] and row["decisionRef"] is not None
                     and decided[0]["occurredAt"] == row["decisionRef"]["at"], "AO_AUDIT")
            else:
                need(h["now"] < row["expiresAt"] + h["sweepInterval"], "AO_AUDIT")   # A5, N-11
            if row["state"] == "EXPIRED":                                         # A5, N-12; #257, MET-016 F4
                need(decided[0]["occurredAt"] == row["expiresAt"]                 # a write at E + I closes the pair
                     and row["expiresAt"] <= decided[0]["recordedAt"] <= row["expiresAt"] + h["sweepInterval"],
                     "AO_AUDIT")
        for d in decisions:                                                       # H1a, H3, R2-N1
            need(d.get("deciderType") == "HUMAN" and d.get("source") == "REVIEWER", "AO_HEADLESS")
            need(d.get("deciderId") in d.get("portEligible", []), "AO_HEADLESS")
        need(all(g.get("location") == "TRIGGER_DEFINITION" for g in h["gates"]), "AO_HEADLESS")   # H3
        if row is not None and row["asker"]["type"] == "WORKLOAD" and row["askPort"] != "NOT_ASKED":
            asker = row["asker"]                                                  # H1b: a gate's ask records it
            need(_ident(asker.get("definitionId")) and _text(asker.get("definitionVersion"))
                 and _digest(asker.get("definitionDigest")) and _ident(asker.get("admissionRecordId")), "AO_HEADLESS")
        if row is not None and row["state"] in ("APPROVED", "REJECTED"):
            need(row["decidedBy"]["type"] == "HUMAN" and decisions, "AO_HEADLESS")   # H1a
        if h["effects"]:                                                          # H4, O2
            need(row is not None and row["state"] == "APPROVED"
                 and all(e["at"] > row["decisionRef"]["at"] for e in h["effects"]), "AO_HEADLESS")
        return {"state": None if row is None else row["state"]}
    return _guarded(run)


# ---------------------------------------------------------------- consumer reads (O1, O2, O3)

def check_read(case: dict) -> dict:
    """A consumer's read of a stored row at a time: it must report the projection, permit only APPROVED and write
    nothing."""
    def run():
        row, consumer = case["row"], case["consumer"]
        need(_closed(consumer, ("reads", "permits", "writes")), "AO_SHAPE")
        projection = project(row, case["now"])
        need(consumer["reads"] == projection and consumer["permits"] is permits(projection)
             and consumer["writes"] is False, "AO_OUTCOME")
        return {"projection": projection, "permits": permits(projection)}
    return _guarded(run)


# ---------------------------------------------------------------- the statement order (S1-S5)

def evaluate_statements(statements, layers, action) -> dict:
    """Floor, then pack and profile, then organisation (stable within a layer). Any matching DENY is final (S2); else the
    last matching ALLOW or ASK decides (S1); a tool statement never allows (S3); the deciding statement is named (S4);
    a missing or failed layer, an unparseable statement, or no deciding statement gives UNAVAILABLE (S5; fail closed)."""
    if not _closed(layers, LAYERS) or any(layers[k] != "LOADED" for k in LAYERS):
        return {"decision": "UNAVAILABLE", "statement": None}
    for s in statements:
        if not (_closed(s, ("id", "version", "layer", "scope", "match", "effect")) and s["layer"] in LAYERS
                and s["scope"] in ("ACTION", "TOOL") and s["effect"] in EFFECTS
                and not (s["scope"] == "TOOL" and s["effect"] == "ALLOW")):
            return {"decision": "UNAVAILABLE", "statement": None}
    ordered = sorted(enumerate(statements), key=lambda p: (LAYER_RANK[p[1]["layer"]], p[0]))
    deny, last = None, None
    for _, s in ordered:
        if s["match"] in (action, "*"):
            if s["effect"] == "DENY":
                deny = deny or s
            else:
                last = s
    decider = deny or last
    if decider is None:
        return {"decision": "UNAVAILABLE", "statement": None}
    return {"decision": decider["effect"], "statement": {"id": decider["id"], "version": decider["version"]}}


def check_statements(case: dict) -> dict:
    """A statement set and, when given, the result a consumer claims: a tool statement that allows is refused (S3); a
    claimed result other than the evaluation (a lifted deny, ADMITTED from an unavailable policy, no deciding
    statement) is refused."""
    def run():
        need(type(case["statements"]) is list, "AO_SHAPE")
        need(not any(type(s) is dict and s.get("scope") == "TOOL" and s.get("effect") == "ALLOW"
                     for s in case["statements"]), "AO_STATEMENT")
        result = evaluate_statements(case["statements"], case["layers"], case["action"])
        if "claimed" in case:
            need(case["claimed"] == result, "AO_STATEMENT")
        return result
    return _guarded(run)


# ---------------------------------------------------------------- profiles and settings (H2, A5)

def _keys(value):
    if type(value) is dict:
        for k, v in value.items():
            yield k
            yield from _keys(v)
    elif type(value) is list:
        for v in value:
            yield from _keys(v)


def check_profile(profile: dict) -> dict:
    """One sweep interval per store owner, each 1 to 3,600 s (A5); no auto-approve flag, setting or environment
    variable anywhere (H2)."""
    def run():
        need(_closed(profile, ("sweepIntervals", "settings", "env")), "AO_SHAPE")
        sweep = profile["sweepIntervals"]
        need(_closed(sweep, SWEEP_OWNERS) and all(type(v) is int and SWEEP_MIN <= v <= SWEEP_MAX
                                                  for v in sweep.values()), "AO_AUDIT")
        names = list(_keys(profile["settings"])) + list(profile["env"])
        need(not any(AUTO_APPROVE.search(n) for n in names), "AO_HEADLESS")
        return {"owners": sorted(sweep)}
    return _guarded(run)


# ---------------------------------------------------------------- vectors

CHECKS = {"LIFECYCLE": simulate, "HISTORY": check_history, "READ": check_read, "STATEMENTS": check_statements,
          "PROFILE": check_profile}


def evaluate(check: str, data: dict):
    """(None, result) when accepted, (code, {}) when refused."""
    try:
        result = CHECKS[check](data)
    except Refused as refusal:
        return refusal.code, {}
    return None, {k: v for k, v in result.items() if not k.startswith("_")}


def replay(case: dict):
    """(ok, got): whether the case's expectation holds, and what the model gave."""
    code, result = evaluate(case["check"], case["input"])
    expect = case["expect"]
    if "refuse" in expect:
        return code == expect["refuse"], code
    ok = code is None and all(result.get(k) == v for k, v in expect.get("result", {}).items())
    return ok, code if code else result
