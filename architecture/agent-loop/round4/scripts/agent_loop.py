#!/usr/bin/env python3
"""Agent-loop kernel and tool-gateway records v1 (architecture/agent-loop/, MAS-RA-008): reference model, DATA_CHECK_ONLY.

Two closed, content-addressed record kinds, each checked by one function that raises `Refused(code)` on the first rule it
breaks (rules are applied as whole-record passes in the order of PROFILE_CODES / TRACE_CODES) and otherwise returns derived
facts:
- a loop profile: the budgets (tokens, iterations, wall-clock, recursion depth, context warning), the step-retry and
  revision bounds, the registered hooks (event, effects, scope), the deterministic gates and the tools the loop may call
  (manifest and input-schema digests, side effect, idempotency, trust, grant scope, credential parameters);
- a loop trace: the append-only steps of one loop run (MODEL, TOOL, GATE, HOOK, HANDOFF, DELEGATE) with budget accounting,
  tool calls and results, retries and revisions, and its terminal status.

Owner decisions (2026-10-13, via the lane monitor): Q-MAS8-A (a) an internal candidate, H10's and H11's documents
unchanged; Q-MAS8-B (a) recursion depth at most 1, no override; Q-MAS8-C (a) a failing step retries at most once by
default and at most 3 times, each with its error trace fed back, then a human hand-off, and revision rounds have their own
budget of at most 3; Q-MAS8-D (a) a per-call capability-token reference bound by digest to H11's grant, fields checked here,
issuing and verifying left to H11's broker. Standard library only.
"""
from __future__ import annotations

import hashlib
import json
import math
import re

PROFILE_SCHEMA = "planeon.internal.agent-loop-profile/v1"
TRACE_SCHEMA = "planeon.internal.agent-loop-trace/v1"
MAX_DEPTH = 1
MAX_STEP_RETRIES = 3
MAX_REVISION_ROUNDS = 3
MAX_ITEMS = 4096
MAX_INT = 2 ** 53 - 1
EVENTS = ("INVOKE_START", "INVOKE_END", "MODEL_QUERY_BEFORE", "MODEL_QUERY_AFTER", "TOOL_CALL_BEFORE", "TOOL_RESULT_AFTER",
          "EXEC_BEFORE", "EXEC_AFTER", "BUDGET_WARNING", "BUDGET_EXHAUSTED", "STEP_ERROR", "STEP_RETRY", "HANDOFF")
EFFECTS = ("MODIFY_INPUT", "SUPPLY_OUTPUT", "MODIFY_OUTPUT", "ABORT")
EXCLUSIVE_EFFECTS = ("MODIFY_INPUT", "SUPPLY_OUTPUT", "MODIFY_OUTPUT")
# Which effects a hook may have on which event: before an operation it may change the input, supply the output (the
# operation is then skipped) or abort; after it, change the output or abort; on the budget, error and retry events only
# abort; on HANDOFF only observe (the loop is already ending with a hand-off). The 13 events adapt JAZ's (Enter, Send,
# Complete and Exit per operation, and LLMQueryRetry); they are not JAZ's set.
EVENT_EFFECTS = {**{e: ("MODIFY_INPUT", "SUPPLY_OUTPUT", "ABORT") for e in ("INVOKE_START", "MODEL_QUERY_BEFORE",
                                                                            "TOOL_CALL_BEFORE", "EXEC_BEFORE")},
                 **{e: ("MODIFY_OUTPUT", "ABORT") for e in ("INVOKE_END", "MODEL_QUERY_AFTER", "TOOL_RESULT_AFTER",
                                                             "EXEC_AFTER")},
                 **{e: ("ABORT",) for e in ("BUDGET_WARNING", "BUDGET_EXHAUSTED", "STEP_ERROR", "STEP_RETRY")},
                 "HANDOFF": ()}
SCOPES = ("LOCAL", "DYNAMIC")
GATE_KINDS = ("SCHEMA", "LINT", "TEST", "POLICY")
SIDE_EFFECTS = ("READ_ONLY", "WRITE")
IDEMPOTENCY = ("NATIVE", "RECEIPT_KEY", "NONE")
TRUST = ("TRUSTED", "UNTRUSTED")
TRUST_LABELS = {"TRUSTED": "TRUSTED_TOOL_OUTPUT", "UNTRUSTED": "UNTRUSTED_TOOL_OUTPUT"}
KINDS = ("MODEL", "TOOL", "GATE", "HOOK", "HANDOFF", "DELEGATE")
OUTCOMES = ("OK", "FAIL", "ERROR", "UNKNOWN")
STATUSES = ("COMPLETED", "FAILED", "HANDED_OFF", "ABORTED")
ABORT_REASONS = ("BUDGET_EXHAUSTED", "HOOK_ABORT")
PROFILE_CODES = ("SHAPE", "DUPLICATE_ID", "HOOK_CONFLICT")
TRACE_CODES = ("SHAPE", "DUPLICATE_ID", "STEP_ORDER", "UNKNOWN_REFERENCE", "HOOK_CONFLICT", "HOOK_NOT_REGISTERED", "RECURSION_DEPTH",
               "DELEGATION", "TOTALS_MISMATCH", "BUDGET_EXCEEDED", "ERROR_TRACE", "INVALID_TOOL_INPUT", "CAPABILITY_MISMATCH",
               "CAPABILITY_EXPIRED", "CREDENTIAL_RULE", "TRUST_LABEL", "PROVENANCE", "UNGATED_CONSUMPTION",
               "GATE_OVERRIDDEN", "RETRY_WITHOUT_TRACE", "RETRY_BOUND", "UNKNOWN_SIDE_EFFECT_RETRIED", "REVISION_BOUND",
               "HANDOFF_MISSING", "TERMINAL_STATUS")
DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")
IDENT = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}\Z")
TIME = re.compile(r"[0-9]{4}-(0[1-9]|1[0-2])-(0[1-9]|[12][0-9]|3[01])T([01][0-9]|2[0-3]):[0-5][0-9]:[0-5][0-9]Z\Z")


class Refused(ValueError):
    """A record breaks a rule; `code` is one of PROFILE_CODES or TRACE_CODES."""

    def __init__(self, code: str):
        super().__init__(code)
        self.code = code


def _refuse(ok: bool, code: str) -> None:
    if not ok:
        raise Refused(code)


# ---------------------------------------------------------------- canonical form and text (as MAS-RA-001 and -002)

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


def parse(text):
    """Record text as I-JSON (RFC 7493): UTF-8, no duplicate member names, no NaN or infinity; anything else is SHAPE."""
    try:
        if isinstance(text, (bytes, bytearray)):
            text = bytes(text).decode("utf-8")
        text.encode("utf-8")
        return json.loads(text, object_pairs_hook=_members, parse_constant=_no_constant)
    except Refused:
        raise
    except (ValueError, TypeError, RecursionError) as exc:
        raise Refused("SHAPE") from exc


# ---------------------------------------------------------------- shape helpers

def _text(value, limit: int = 1024) -> bool:
    return (type(value) is str and 0 < len(value) <= limit
            and not any(0xD800 <= ord(c) <= 0xDFFF for c in value))


def _ident(value) -> bool:
    return type(value) is str and IDENT.match(value) is not None


def _digest_str(value) -> bool:
    return type(value) is str and DIGEST.match(value) is not None


def _opt_digest(value) -> bool:
    return value is None or _digest_str(value)


def _opt_ident(value) -> bool:
    return value is None or _ident(value)


def _int(value, low: int, high: int) -> bool:
    return _integral(value) and low <= value <= high


def _time(value) -> bool:
    return type(value) is str and TIME.match(value) is not None


def _closed(value, keys, optional=()) -> bool:
    return type(value) is dict and set(keys) <= set(value) <= set(keys) | set(optional)


def _list(value, low: int = 0) -> bool:
    return type(value) is list and low <= len(value) <= MAX_ITEMS


def _unique(values) -> None:
    values = list(values)
    _refuse(len(values) == len(set(values)), "DUPLICATE_ID")


def _guarded(check):
    """Run one record check; anything malformed that slipped past the shape rules is SHAPE, never another exception."""
    try:
        return check()
    except Refused:
        raise
    except (KeyError, TypeError, AttributeError, IndexError, ValueError, UnicodeError, RecursionError) as exc:
        raise Refused("SHAPE") from exc


# ---------------------------------------------------------------- loop profile

PROFILE_KEYS = ("schemaVersion", "profileId", "budgets", "retry", "revision", "hooks", "gates", "tools")
BUDGET_KEYS = ("tokens", "iterations", "wallClockSeconds", "recursionDepth", "contextWarningPercent")
TOOL_KEYS = ("toolId", "manifestDigest", "inputSchemaDigest", "sideEffect", "idempotency", "trust", "grantScope",
             "credentialParams")


def _profile_shape(doc) -> None:
    _refuse(_closed(doc, PROFILE_KEYS) and doc["schemaVersion"] == PROFILE_SCHEMA and _ident(doc["profileId"])
            and _closed(doc["budgets"], BUDGET_KEYS) and _int(doc["budgets"]["tokens"], 1, MAX_INT)
            and _int(doc["budgets"]["iterations"], 1, 100000) and _int(doc["budgets"]["wallClockSeconds"], 1, MAX_INT)
            and _int(doc["budgets"]["recursionDepth"], 0, MAX_DEPTH)
            and _int(doc["budgets"]["contextWarningPercent"], 1, 100)
            and _closed(doc["retry"], ("stepRetries",)) and _int(doc["retry"]["stepRetries"], 0, MAX_STEP_RETRIES)
            and _closed(doc["revision"], ("rounds",)) and _int(doc["revision"]["rounds"], 0, MAX_REVISION_ROUNDS)
            and _list(doc["hooks"]) and _list(doc["gates"]) and _list(doc["tools"]), "SHAPE")
    for h in doc["hooks"]:
        _refuse(_closed(h, ("hookId", "event", "effects", "scope")) and _ident(h["hookId"]) and h["event"] in EVENTS
                and _list(h["effects"]) and all(e in EVENT_EFFECTS[h["event"]] for e in h["effects"])
                and h["scope"] in SCOPES, "SHAPE")
    for g in doc["gates"]:
        _refuse(_closed(g, ("gateId", "kind")) and _ident(g["gateId"]) and g["kind"] in GATE_KINDS, "SHAPE")
    for t in doc["tools"]:
        _refuse(_closed(t, TOOL_KEYS) and _ident(t["toolId"]) and _digest_str(t["manifestDigest"])
                and _digest_str(t["inputSchemaDigest"]) and t["sideEffect"] in SIDE_EFFECTS
                and t["idempotency"] in IDEMPOTENCY and t["trust"] in TRUST and _text(t["grantScope"], 256)
                and _list(t["credentialParams"])
                and all(_ident(p) for p in t["credentialParams"]), "SHAPE")


def check_profile(doc: dict) -> dict:
    """A loop profile: closed shape (recursion depth at most 1, step retries at most 3, revision rounds at most 3, effects
    allowed for their event); unique hook, gate and tool IDs, hook effects and credential parameters; no two hooks on one
    event with the same exclusive effect (MODIFY_INPUT, SUPPLY_OUTPUT, MODIFY_OUTPUT), and no hook supplying the output of
    an event another hook modifies the input of, since their composition would depend on order (one hook may do both);
    ABORT composes with anything (abort wins)."""
    def run():
        _profile_shape(doc)
        _unique(h["hookId"] for h in doc["hooks"])
        _unique(g["gateId"] for g in doc["gates"])
        _unique(t["toolId"] for t in doc["tools"])
        for h in doc["hooks"]:
            _unique(h["effects"])
        for t in doc["tools"]:
            _unique(t["credentialParams"])
        for event in EVENTS:
            for effect in EXCLUSIVE_EFFECTS:
                holders = [h for h in doc["hooks"] if h["event"] == event and effect in h["effects"]]
                _refuse(len(holders) <= 1, "HOOK_CONFLICT")
            modifiers = {h["hookId"] for h in doc["hooks"] if h["event"] == event and "MODIFY_INPUT" in h["effects"]}
            suppliers = {h["hookId"] for h in doc["hooks"] if h["event"] == event and "SUPPLY_OUTPUT" in h["effects"]}
            _refuse(not modifiers or not suppliers or modifiers == suppliers, "HOOK_CONFLICT")
        return {"digest": digest(doc)}
    return _guarded(run)


# ---------------------------------------------------------------- loop trace: shape

TRACE_KEYS = ("schemaVersion", "traceId", "profileDigest", "depth", "parentTraceId", "startedAt", "steps", "terminal",
              "totals")
STEP_KEYS = ("stepId", "seq", "kind", "startedAt", "tokens", "wallClockSeconds", "outcome", "errorTraceDigest", "consumes",
             "produces", "attempt", "retryOf", "feedback", "revises", "detail")
CALL_KEYS = ("toolId", "manifestDigest", "inputDigest", "inputSchemaDigest", "inputValid", "launched", "capability",
             "timeoutSeconds", "limits", "credentials")


def _detail(kind, d) -> bool:
    if kind == "MODEL":
        return (_closed(d, ("inputDigest", "credentialRefs")) and _digest_str(d["inputDigest"])
                and _list(d["credentialRefs"]) and all(_digest_str(r) for r in d["credentialRefs"]))
    if kind == "TOOL":
        if not _closed(d, ("call", "result")):
            return False
        c, r = d["call"], d["result"]
        return (_closed(c, CALL_KEYS) and _ident(c["toolId"]) and _digest_str(c["manifestDigest"])
                and _digest_str(c["inputDigest"]) and _digest_str(c["inputSchemaDigest"]) and type(c["inputValid"]) is bool
                and type(c["launched"]) is bool
                and _closed(c["capability"], ("grantDigest", "toolId", "manifestDigest", "scope", "expiresAt"))
                and _digest_str(c["capability"]["grantDigest"]) and _ident(c["capability"]["toolId"])
                and _digest_str(c["capability"]["manifestDigest"]) and _text(c["capability"]["scope"], 256)
                and _time(c["capability"]["expiresAt"]) and _int(c["timeoutSeconds"], 1, 86400)
                and _closed(c["limits"], ("memoryBytes", "cpuMillis")) and _int(c["limits"]["memoryBytes"], 1, MAX_INT)
                and _int(c["limits"]["cpuMillis"], 1, MAX_INT) and _list(c["credentials"])
                and all(_closed(x, ("param", "brokerRef")) and _ident(x["param"]) and _digest_str(x["brokerRef"])
                        for x in c["credentials"])
                and _closed(r, ("outputDigest", "trustLabel", "provenance")) and _opt_digest(r["outputDigest"])
                and r["trustLabel"] in TRUST_LABELS.values()
                and _closed(r["provenance"], ("toolId", "callStepId", "sandboxProfileDigest", "receiptRef"))
                and _ident(r["provenance"]["toolId"]) and _ident(r["provenance"]["callStepId"])
                and _digest_str(r["provenance"]["sandboxProfileDigest"]) and _opt_digest(r["provenance"]["receiptRef"]))
    if kind == "GATE":
        return _closed(d, ("gateId", "subjectStepId")) and _ident(d["gateId"]) and _ident(d["subjectStepId"])
    if kind == "HOOK":
        return (_closed(d, ("hookId", "event", "effect")) and _ident(d["hookId"]) and d["event"] in EVENTS
                and (d["effect"] is None or d["effect"] in EFFECTS))
    if kind == "HANDOFF":
        return _closed(d, ("reason",)) and _text(d["reason"])
    if kind == "DELEGATE":
        return _closed(d, ("childTraceDigest",)) and _digest_str(d["childTraceDigest"])
    return False


def _trace_shape(doc) -> None:
    _refuse(_closed(doc, TRACE_KEYS) and doc["schemaVersion"] == TRACE_SCHEMA and _ident(doc["traceId"])
            and _digest_str(doc["profileDigest"]) and _int(doc["depth"], 0, MAX_DEPTH) and _opt_ident(doc["parentTraceId"])
            and _time(doc["startedAt"]) and _list(doc["steps"])
            and _closed(doc["terminal"], ("status", "reason", "delivered")) and doc["terminal"]["status"] in STATUSES
            and (doc["terminal"]["reason"] is None or doc["terminal"]["reason"] in ABORT_REASONS)
            and _opt_ident(doc["terminal"]["delivered"])
            and _closed(doc["totals"], ("tokens", "iterations", "wallClockSeconds"))
            and all(_int(doc["totals"][k], 0, MAX_INT) for k in ("tokens", "iterations", "wallClockSeconds")), "SHAPE")
    for s in doc["steps"]:
        _refuse(_closed(s, STEP_KEYS) and _ident(s["stepId"]) and _int(s["seq"], 1, MAX_INT) and s["kind"] in KINDS
                and _time(s["startedAt"]) and _int(s["tokens"], 0, MAX_INT) and _int(s["wallClockSeconds"], 0, MAX_INT)
                and s["outcome"] in OUTCOMES and _opt_digest(s["errorTraceDigest"]) and _list(s["consumes"])
                and all(_ident(c) for c in s["consumes"]) and _opt_digest(s["produces"])
                and _int(s["attempt"], 1, MAX_STEP_RETRIES + 1) and _opt_ident(s["retryOf"])
                and _opt_digest(s["feedback"]) and _opt_ident(s["revises"]) and _detail(s["kind"], s["detail"])
                and (s["kind"] not in ("GATE", "HOOK", "HANDOFF") or (s["consumes"] == [] and s["produces"] is None)),
                "SHAPE")


# ---------------------------------------------------------------- loop trace: the rules, one whole-trace pass each

class _View:
    def __init__(self, doc, profile, profiles, traces):
        self.doc, self.profile, self.profiles, self.traces = doc, profile, profiles, traces
        self.steps = doc["steps"]
        self.by_id = {s["stepId"]: s for s in self.steps}
        self.tools = {t["toolId"]: t for t in profile["tools"]}
        self.hooks = {h["hookId"]: h for h in profile["hooks"]}
        self.gates = {g["gateId"] for g in profile["gates"]}

    def before(self, step_id, step):
        """step_id names a step earlier in the trace than step."""
        other = self.by_id.get(step_id)
        return other is not None and other["seq"] < step["seq"]

    def child(self, step):
        return self.traces[step["detail"]["childTraceDigest"]]

    def tool(self, step):
        return self.tools[step["detail"]["call"]["toolId"]]

    def retried(self, step):
        return any(s["retryOf"] == step["stepId"] for s in self.steps)

    def unknown_unsafe(self, step):
        """A step whose side effect may have happened and must never be repeated: an UNKNOWN outcome of a write tool
        without idempotency, or a delegation whose child holds such a step (the child runs under this profile)."""
        if step["kind"] == "TOOL":
            tool = self.tool(step)
            return step["outcome"] == "UNKNOWN" and tool["sideEffect"] == "WRITE" and tool["idempotency"] == "NONE"
        if step["kind"] == "DELEGATE":
            child = _View(self.child(step), self.profile, self.profiles, self.traces)
            return any(child.unknown_unsafe(s) for s in child.steps)
        return False


def _order(doc) -> None:
    """Append order: sequence numbers strictly increase, and start times never go back or precede the trace's start."""
    steps = doc["steps"]
    _refuse(all(a["seq"] < b["seq"] and a["startedAt"] <= b["startedAt"] for a, b in zip(steps, steps[1:]))
            and all(s["startedAt"] >= doc["startedAt"] for s in steps), "STEP_ORDER")


def _references(v: _View) -> None:
    """Earlier steps, the profile's tools, gates and hooks, the delivered step, and child traces that pass their own check
    (stored under their digest)."""
    for s in v.steps:
        _refuse(all(v.before(c, s) for c in s["consumes"])
                and (s["retryOf"] is None or v.before(s["retryOf"], s))
                and (s["revises"] is None or v.before(s["revises"], s)), "UNKNOWN_REFERENCE")
        d = s["detail"]
        if s["kind"] == "TOOL":
            _refuse(d["call"]["toolId"] in v.tools, "UNKNOWN_REFERENCE")
        if s["kind"] == "GATE":
            _refuse(d["gateId"] in v.gates and v.before(d["subjectStepId"], s), "UNKNOWN_REFERENCE")
        if s["kind"] == "HOOK":
            _refuse(d["hookId"] in v.hooks, "UNKNOWN_REFERENCE")
        if s["kind"] == "DELEGATE":
            _refuse(type(v.traces) is dict and d["childTraceDigest"] in v.traces, "UNKNOWN_REFERENCE")
            try:
                child = check_trace(v.traces[d["childTraceDigest"]], v.profiles, v.traces)
            except Refused:
                child = None
            _refuse(child is not None and child["digest"] == d["childTraceDigest"], "UNKNOWN_REFERENCE")
    delivered = v.doc["terminal"]["delivered"]
    _refuse(delivered is None or delivered in v.by_id, "UNKNOWN_REFERENCE")


def _hook_registered(v: _View) -> None:
    """A hook step matches its registration (event and effect; a hook that did not succeed had no effect); a delegated loop
    (depth 1) records only DYNAMIC hooks, the ones that reach the loops a loop delegates to."""
    for s in v.steps:
        if s["kind"] == "HOOK":
            hook = v.hooks[s["detail"]["hookId"]]
            _refuse(hook["event"] == s["detail"]["event"]
                    and (s["detail"]["effect"] is None or s["detail"]["effect"] in hook["effects"])
                    and (s["outcome"] == "OK" or s["detail"]["effect"] is None)
                    and (v.doc["depth"] == 0 or hook["scope"] == "DYNAMIC"), "HOOK_NOT_REGISTERED")


def _recursion(v: _View) -> None:
    depth = v.doc["depth"]
    _refuse(depth <= v.profile["budgets"]["recursionDepth"] and (depth == 0) == (v.doc["parentTraceId"] is None),
            "RECURSION_DEPTH")
    for s in v.steps:
        if s["kind"] == "DELEGATE":
            child = v.child(s)
            _refuse(depth + 1 <= v.profile["budgets"]["recursionDepth"] and child["depth"] == depth + 1
                    and child["parentTraceId"] == v.doc["traceId"], "RECURSION_DEPTH")


def _delegation(v: _View) -> None:
    """A delegated loop runs under its parent's profile (so its tools, bounds and budgets are the parent's and the parent's
    DYNAMIC hooks are registered in it), starts no earlier than its DELEGATE step, and holds no capability grant of its
    parent or of another delegated loop."""
    grants = {s["detail"]["call"]["capability"]["grantDigest"] for s in v.steps if s["kind"] == "TOOL"}
    for s in v.steps:
        if s["kind"] == "DELEGATE":
            child = v.child(s)
            _refuse(child["profileDigest"] == v.doc["profileDigest"] and child["startedAt"] >= s["startedAt"],
                    "DELEGATION")
            own = {c["detail"]["call"]["capability"]["grantDigest"] for c in child["steps"] if c["kind"] == "TOOL"}
            _refuse(not own & grants, "DELEGATION")
            grants |= own


def _totals(v: _View) -> None:
    """The totals are the steps' sums; iterations count this loop's MODEL steps and its children's iterations. A DELEGATE
    step carries its child's tokens and wall-clock, its delivered artefact, and its result (OK exactly when the child
    COMPLETED)."""
    child_iterations = 0
    for s in v.steps:
        if s["kind"] == "DELEGATE":
            child = v.child(s)
            delivered = child["terminal"]["delivered"]
            artefact = next(c["produces"] for c in child["steps"] if c["stepId"] == delivered) if delivered else None
            _refuse(s["tokens"] == child["totals"]["tokens"]
                    and s["wallClockSeconds"] == child["totals"]["wallClockSeconds"] and s["produces"] == artefact
                    and (s["outcome"] == "OK") == (child["terminal"]["status"] == "COMPLETED"), "TOTALS_MISMATCH")
            child_iterations += child["totals"]["iterations"]
    totals = v.doc["totals"]
    _refuse(totals["tokens"] == sum(s["tokens"] for s in v.steps)
            and totals["wallClockSeconds"] == sum(s["wallClockSeconds"] for s in v.steps)
            and totals["iterations"] == sum(1 for s in v.steps if s["kind"] == "MODEL") + child_iterations,
            "TOTALS_MISMATCH")


def _budget(v: _View) -> None:
    """The totals stay within the profile's budgets, and a tool step runs no longer than its call's timeout."""
    budgets, totals = v.profile["budgets"], v.doc["totals"]
    _refuse(totals["tokens"] <= budgets["tokens"] and totals["iterations"] <= budgets["iterations"]
            and totals["wallClockSeconds"] <= budgets["wallClockSeconds"]
            and all(s["wallClockSeconds"] <= s["detail"]["call"]["timeoutSeconds"] for s in v.steps if s["kind"] == "TOOL"),
            "BUDGET_EXCEEDED")


def _error_trace(v: _View) -> None:
    """A step that did not succeed carries its diagnosis and no artefact; a step that succeeded carries no diagnosis."""
    _refuse(all((s["outcome"] == "OK") == (s["errorTraceDigest"] is None) and (s["outcome"] == "OK" or s["produces"] is None)
                for s in v.steps), "ERROR_TRACE")


def _tool_input(v: _View) -> None:
    """A call names its tool's listed manifest and input schema. Only a call whose input is valid against that schema is
    launched; a call the gateway denied before launch (an invalid input, or H11's policy, approval or isolation denial)
    FAILs with no output and no receipt."""
    for s in v.steps:
        if s["kind"] == "TOOL":
            call, result, tool = s["detail"]["call"], s["detail"]["result"], v.tool(s)
            denied = (s["outcome"] == "FAIL" and result["outputDigest"] is None
                      and result["provenance"]["receiptRef"] is None)
            _refuse((call["inputValid"] or not call["launched"]) and (call["launched"] or denied)
                    and call["inputSchemaDigest"] == tool["inputSchemaDigest"]
                    and call["manifestDigest"] == tool["manifestDigest"], "INVALID_TOOL_INPUT")


def _capability(v: _View) -> None:
    for s in v.steps:
        if s["kind"] == "TOOL":
            call = s["detail"]["call"]
            _refuse(call["capability"]["toolId"] == call["toolId"]
                    and call["capability"]["manifestDigest"] == call["manifestDigest"]
                    and call["capability"]["scope"] == v.tool(s)["grantScope"], "CAPABILITY_MISMATCH")


def _capability_expiry(v: _View) -> None:
    _refuse(all(s["detail"]["call"]["capability"]["expiresAt"] >= s["startedAt"] for s in v.steps if s["kind"] == "TOOL"),
            "CAPABILITY_EXPIRED")


def _credentials(v: _View) -> None:
    """Secrets never reach a model step's input, and a tool call carries broker references only for the parameters its
    tool declares."""
    for s in v.steps:
        if s["kind"] == "MODEL":
            _refuse(s["detail"]["credentialRefs"] == [], "CREDENTIAL_RULE")
        if s["kind"] == "TOOL":
            declared = set(v.tool(s)["credentialParams"])
            _refuse(all(x["param"] in declared for x in s["detail"]["call"]["credentials"]), "CREDENTIAL_RULE")


def _trust_label(v: _View) -> None:
    for s in v.steps:
        if s["kind"] == "TOOL":
            _refuse(s["detail"]["result"]["trustLabel"] == TRUST_LABELS[v.tool(s)["trust"]], "TRUST_LABEL")


def _provenance(v: _View) -> None:
    """A result names its own call and tool, the step's artefact is the tool's output, and a write tool that succeeded
    carries its receipt."""
    for s in v.steps:
        if s["kind"] == "TOOL":
            result = s["detail"]["result"]
            prov = result["provenance"]
            _refuse(prov["toolId"] == s["detail"]["call"]["toolId"] and prov["callStepId"] == s["stepId"]
                    and s["produces"] == result["outputDigest"]
                    and (s["outcome"] != "OK" or v.tool(s)["sideEffect"] != "WRITE" or prov["receiptRef"] is not None),
                    "PROVENANCE")


def _producers(v: _View):
    """The artefacts a deterministic gate must pass before they reach an effect: a model step's artefact and an untrusted
    tool's output."""
    return [s for s in v.steps if s["produces"] is not None and (
        s["kind"] == "MODEL" or (s["kind"] == "TOOL" and s["detail"]["result"]["trustLabel"] == "UNTRUSTED_TOOL_OUTPUT"))]


def _holders(v: _View, step):
    """The steps holding a step's bytes: the step, and every step whose artefact has the same digest."""
    return {s["stepId"] for s in v.steps if s is step or (step["produces"] is not None and s["produces"] == step["produces"])}


def _gated(v: _View, producer, before_seq) -> bool:
    """A passing deterministic gate on the producer's bytes, on any step holding them, before the consumer (a gate on the
    same bytes decides the same, so an earlier one counts)."""
    holders = _holders(v, producer)
    return any(g["kind"] == "GATE" and g["outcome"] == "OK" and g["detail"]["subjectStepId"] in holders
               and g["seq"] < before_seq for g in v.steps)


def _consumers(v: _View, producer):
    """The steps that must not consume the artefact ungated: a write tool or a delegation that consumes its bytes directly
    or through the outputs of read-only tools that read them; for a model artefact also a later model step that consumes
    its bytes directly, and the delivery. A revision of the artefact is not a consumer: it repairs it."""
    holders = _holders(v, producer)
    reach, out = set(holders), []
    for s in v.steps:
        if s["seq"] <= producer["seq"] or s["revises"] in holders or not any(c in reach for c in s["consumes"]):
            continue
        if s["kind"] == "TOOL" and v.tool(s)["sideEffect"] == "READ_ONLY":
            reach.add(s["stepId"])
        elif s["kind"] in ("TOOL", "DELEGATE"):
            out.append(s["seq"])
        elif s["kind"] == "MODEL" and producer["kind"] == "MODEL" and any(c in holders for c in s["consumes"]):
            out.append(s["seq"])
    if v.doc["terminal"]["delivered"] in holders:
        out.append(MAX_INT + 1)
    return out


def _ungated(v: _View) -> None:
    """A deterministic gate passes an artefact between its production and every consumer above, so a per-step error does
    not compound and untrusted output does not reach an effect unchecked."""
    for producer in _producers(v):
        for seq in _consumers(v, producer):
            _refuse(_gated(v, producer, seq), "UNGATED_CONSUMPTION")


def _tainted(v: _View, subject):
    """What a gate's FAIL on subject decides: the steps holding the failed bytes, every step that consumed any of them (at
    any time, before the FAIL included), except a revision of the artefact, which repairs it, and every step holding
    the bytes of any of these; with their artefact digests."""
    holders = _holders(v, subject)
    tainted, digests = set(holders), {subject["produces"]} - {None}
    changed = True
    while changed:
        changed = False
        for s in v.steps:
            if s["stepId"] in tainted or s["revises"] in holders:
                continue
            if any(c in tainted for c in s["consumes"]) or (s["produces"] is not None and s["produces"] in digests):
                tainted.add(s["stepId"])
                if s["produces"] is not None:
                    digests.add(s["produces"])
                changed = True
    return holders, tainted, digests


def _overridden(v: _View) -> None:
    """A deterministic gate's FAIL is never overridden. After the FAIL, nothing but a read-only tool (which reads, and is
    tainted in turn) or a revision of the artefact consumes anything the FAIL decides, none of it is delivered, and a
    revision returns bytes none of it holds."""
    for g in v.steps:
        if g["kind"] == "GATE" and g["outcome"] == "FAIL":
            holders, tainted, digests = _tainted(v, v.by_id[g["detail"]["subjectStepId"]])
            later = [s for s in v.steps if s["seq"] > g["seq"]]
            reader = lambda s: s["kind"] == "TOOL" and v.tool(s)["sideEffect"] == "READ_ONLY"
            _refuse(not any(any(c in tainted for c in s["consumes"]) for s in later
                            if not reader(s) and s["revises"] not in holders)
                    and v.doc["terminal"]["delivered"] not in tainted
                    and not any(s["revises"] in holders and s["produces"] in digests for s in later),
                    "GATE_OVERRIDDEN")


def _retry_trace(v: _View) -> None:
    """A retry repeats a failed step of the same kind (and tool, gate and subject, and revision target) with the next
    attempt number and the failure's error trace fed back; a step is retried at most once (the retry is retried in
    turn). A revision answers a gate that failed the artefact it revises, with that gate's error trace fed back. Any
    other step starts at attempt 1 with no feedback."""
    for s in v.steps:
        if s["retryOf"] is not None:
            prior = v.by_id[s["retryOf"]]
            same = (prior["kind"] == s["kind"] and prior["revises"] == s["revises"]
                    and (s["kind"] != "TOOL" or prior["detail"]["call"]["toolId"] == s["detail"]["call"]["toolId"])
                    and (s["kind"] != "GATE" or prior["detail"] == s["detail"]))
            _refuse(prior["outcome"] != "OK" and same and s["attempt"] == prior["attempt"] + 1
                    and s["feedback"] == prior["errorTraceDigest"], "RETRY_WITHOUT_TRACE")
        elif s["revises"] is not None:
            _refuse(s["attempt"] == 1 and any(
                g["kind"] == "GATE" and g["outcome"] == "FAIL" and g["detail"]["subjectStepId"] == s["revises"]
                and g["seq"] < s["seq"] and g["errorTraceDigest"] == s["feedback"] for g in v.steps), "RETRY_WITHOUT_TRACE")
        else:
            _refuse(s["attempt"] == 1 and s["feedback"] is None, "RETRY_WITHOUT_TRACE")
    for s in v.steps:
        _refuse(sum(1 for r in v.steps if r["retryOf"] == s["stepId"]) <= 1, "RETRY_WITHOUT_TRACE")


def _retry_bound(v: _View) -> None:
    _refuse(all(s["attempt"] <= v.profile["retry"]["stepRetries"] + 1 for s in v.steps), "RETRY_BOUND")


def _unsafe_retry(v: _View) -> None:
    """A side effect that may have happened is never repeated: no retry of an UNKNOWN write without idempotency or of a
    delegation whose child holds one. A launched write with a receipt key is retried with the same input (the same key);
    a write without idempotency only after the gateway denied the call before launch, or after a FAIL or ERROR whose
    receipt reference records the broker's evidence that it had no effect."""
    for s in v.steps:
        if s["retryOf"] is not None:
            prior = v.by_id[s["retryOf"]]
            _refuse(not v.unknown_unsafe(prior), "UNKNOWN_SIDE_EFFECT_RETRIED")
            if s["kind"] == "TOOL" and v.tool(prior)["sideEffect"] == "WRITE" and prior["detail"]["call"]["launched"]:
                idempotency = v.tool(prior)["idempotency"]
                _refuse(idempotency != "RECEIPT_KEY"
                        or s["detail"]["call"]["inputDigest"] == prior["detail"]["call"]["inputDigest"],
                        "UNKNOWN_SIDE_EFFECT_RETRIED")
                _refuse(idempotency != "NONE" or (prior["outcome"] in ("FAIL", "ERROR")
                                                  and prior["detail"]["result"]["provenance"]["receiptRef"] is not None),
                        "UNKNOWN_SIDE_EFFECT_RETRIED")


def _revision_bound(v: _View) -> None:
    """Revisions form one chain per artefact: a model step revises a model step, each step is revised at most once (a retry
    of a revision shares its target), and the chain's rounds stay within the budget. A failed gate's diagnosis is consumed
    only by a revision of the gate's subject, so no undeclared revision escapes the budget."""
    for s in v.steps:
        for c in s["consumes"]:
            gate = v.by_id[c]
            _refuse(gate["kind"] != "GATE" or gate["outcome"] == "OK"
                    or (s["kind"] == "MODEL" and s["revises"] == gate["detail"]["subjectStepId"]), "REVISION_BOUND")
    for s in v.steps:
        if s["revises"] is not None:
            _refuse(s["kind"] == "MODEL" and v.by_id[s["revises"]]["kind"] == "MODEL"
                    and sum(1 for r in v.steps if r["revises"] == s["revises"] and r["retryOf"] is None) == 1,
                    "REVISION_BOUND")
            rounds, current = 0, s
            while current["revises"] is not None:
                rounds += 1
                current = v.by_id[current["revises"]]
            _refuse(rounds <= v.profile["revision"]["rounds"], "REVISION_BOUND")


def _must_hand_off(v: _View, step) -> bool:
    """A failing step other than a gate, hook or hand-off that was not retried (its retries spent, or not taken), or a
    delegation that failed: a delegated loop's own retry and revision bounds are the bounds, so a delegation is never
    retried."""
    if step["kind"] in ("GATE", "HOOK", "HANDOFF") or step["outcome"] == "OK":
        return False
    return not v.retried(step) or step["kind"] == "DELEGATE"


def _handoff(v: _View) -> None:
    """Bounded retry, then a human: after a step that must hand off, only hook steps (aborts included) follow, then the
    HANDOFF step, and the loop ends HANDED_OFF."""
    for s in v.steps:
        if _must_hand_off(v, s):
            after = [x for x in v.steps if x["seq"] > s["seq"]]
            _refuse(all(x["kind"] in ("HOOK", "HANDOFF") for x in after) and v.doc["terminal"]["status"] == "HANDED_OFF",
                    "HANDOFF_MISSING")


def _terminal(v: _View) -> None:
    """The status is honest: HANDED_OFF ends with its single HANDOFF step, which succeeded; hooks that aborted (a hook
    that did not succeed aborts, fail closed) end the loop: they are the last steps, all on one event, followed only by
    the HANDOFF step of a loop that hands off, and otherwise the loop is ABORTED with HOOK_ABORT, the reason exactly when
    hooks aborted; COMPLETED delivers the artefact of a MODEL step that succeeded (no failing step is left unresolved:
    HANDOFF_MISSING would have refused it); only COMPLETED delivers; FAILED is a loop a deterministic gate did not pass.
    Hooks on the HANDOFF event fire only in a loop that hands off and are recorded right before the HANDOFF step, which
    is always the last (after any aborts)."""
    t, last = v.doc["terminal"], (v.steps[-1] if v.steps else None)
    _refuse((t["status"] == "ABORTED") == (t["reason"] is not None), "TERMINAL_STATUS")
    _refuse((t["status"] == "COMPLETED") == (t["delivered"] is not None), "TERMINAL_STATUS")
    _refuse((t["status"] == "HANDED_OFF") == (last is not None and last["kind"] == "HANDOFF")
            and all(s is last and s["outcome"] == "OK" for s in v.steps if s["kind"] == "HANDOFF"), "TERMINAL_STATUS")
    observers = [s for s in v.steps if s["kind"] == "HOOK" and s["detail"]["event"] == "HANDOFF"]
    tail = v.steps[:-1] if t["status"] == "HANDED_OFF" else v.steps
    _refuse(not observers or (t["status"] == "HANDED_OFF"
                              and all(a is b for a, b in zip(observers, tail[len(tail) - len(observers):]))),
            "TERMINAL_STATUS")
    tail = tail[:len(tail) - len(observers)]
    aborts = [s for s in v.steps if s["kind"] == "HOOK" and s["detail"]["event"] != "HANDOFF"
              and (s["detail"]["effect"] == "ABORT" or s["outcome"] != "OK")]
    _refuse((t["reason"] == "HOOK_ABORT") == (bool(aborts) and t["status"] == "ABORTED")
            and (not aborts or t["status"] in ("ABORTED", "HANDED_OFF"))
            and all(a is b for a, b in zip(aborts, tail[len(tail) - len(aborts):]))
            and len({a["detail"]["event"] for a in aborts}) <= 1, "TERMINAL_STATUS")
    if t["status"] == "COMPLETED":
        delivered = v.by_id[t["delivered"]]
        _refuse(delivered["kind"] == "MODEL" and delivered["produces"] is not None and delivered["outcome"] == "OK",
                "TERMINAL_STATUS")
    if t["status"] == "FAILED":
        _refuse(any(s["kind"] == "GATE" and s["outcome"] != "OK" for s in v.steps), "TERMINAL_STATUS")


RULES = (("HOOK_NOT_REGISTERED", _hook_registered), ("RECURSION_DEPTH", _recursion), ("DELEGATION", _delegation),
         ("TOTALS_MISMATCH", _totals), ("BUDGET_EXCEEDED", _budget), ("ERROR_TRACE", _error_trace),
         ("INVALID_TOOL_INPUT", _tool_input), ("CAPABILITY_MISMATCH", _capability),
         ("CAPABILITY_EXPIRED", _capability_expiry), ("CREDENTIAL_RULE", _credentials), ("TRUST_LABEL", _trust_label),
         ("PROVENANCE", _provenance), ("UNGATED_CONSUMPTION", _ungated), ("GATE_OVERRIDDEN", _overridden),
         ("RETRY_WITHOUT_TRACE", _retry_trace), ("RETRY_BOUND", _retry_bound),
         ("UNKNOWN_SIDE_EFFECT_RETRIED", _unsafe_retry), ("REVISION_BOUND", _revision_bound),
         ("HANDOFF_MISSING", _handoff), ("TERMINAL_STATUS", _terminal))
assert tuple(code for code, _ in RULES) == TRACE_CODES[5:]


def check_trace(doc: dict, profiles: dict, traces: dict) -> dict:
    """A loop trace against its profile (`profiles` maps profile digests to profiles; `traces` maps trace digests to the
    child traces DELEGATE steps name). Shape; unique step IDs, sequence numbers, capability grants, credential parameters
    per call and delegated child traces; append order; references (a stored profile that passes its own check, or fails it
    only by a hook conflict, under its digest; earlier steps; registered tools, gates and hooks; child traces that pass
    their own check); the profile's hook conflicts; then each rule over the whole trace in TRACE_CODES order."""
    def run():
        _trace_shape(doc)
        _unique(s["stepId"] for s in doc["steps"])
        _unique(s["seq"] for s in doc["steps"])
        _unique(s["detail"]["call"]["capability"]["grantDigest"] for s in doc["steps"] if s["kind"] == "TOOL")
        _unique(s["detail"]["childTraceDigest"] for s in doc["steps"] if s["kind"] == "DELEGATE")
        for s in doc["steps"]:
            if s["kind"] == "TOOL":
                _unique(x["param"] for x in s["detail"]["call"]["credentials"])
        _order(doc)
        profile = profiles.get(doc["profileDigest"]) if type(profiles) is dict else None
        try:
            check_profile(profile)
            conflict = False
        except Refused as refusal:
            _refuse(refusal.code == "HOOK_CONFLICT", "UNKNOWN_REFERENCE")
            conflict = True
        _refuse(digest(profile) == doc["profileDigest"], "UNKNOWN_REFERENCE")
        view = _View(doc, profile, profiles, traces)
        _references(view)
        _refuse(not conflict, "HOOK_CONFLICT")
        for _, rule in RULES:
            rule(view)
        return {"digest": digest(doc), "status": doc["terminal"]["status"], "steps": len(doc["steps"]),
                "iterations": doc["totals"]["iterations"]}
    return _guarded(run)


if __name__ == "__main__":
    from pathlib import Path

    root = Path(__file__).resolve().parents[1]
    vectors = json.loads((root / "architecture/agent-loop/vectors.json").read_bytes())
    stores = vectors["stores"]
    checks = {"profile": lambda d: check_profile(d),
              "trace": lambda d: check_trace(d, stores["profiles"], stores["traces"])}
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
    print("agent loop vectors replay: %d cases, %d texts" % (len(vectors["cases"]), len(vectors["texts"])))
