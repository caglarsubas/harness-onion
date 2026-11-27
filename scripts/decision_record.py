#!/usr/bin/env python3
"""Decision record (architecture/decision-record/, GR-DECISION-RECORD-001, MET-014): the reference model.

One record shape, `planeon.internal.decision-record/v1`, for four producers: the H13 edges (GUARDRAIL), the admission
scanners (ADMISSION_SCAN), the graders (GRADE) and approvals (APPROVAL, whose outcome set is HR-APPROVAL-OUTCOME-001's).
The fail-closed envelope E1-E7 decides whether one record stands; the lift rule L1-L5 decides whether a consumer may act
on an ESCALATE record. Shapes are I-JSON with integers only; `digest(x)` is `sha256:` and the hex SHA-256 of x's
canonical form (sorted keys, no whitespace, UTF-8: RFC 8785 for this integer-and-string data).

- evaluate(record) -> ("ACCEPTED", None) | ("REFUSED", code) | ("READ_FAIL_CLOSED", value) | ("MALFORMED", reason).
  A kind or decision outside the closed sets is read as the kind's fail-closed value (E7); the refusal codes run in
  CHECK_ORDER and the first one found is reported.
- lift(escalation, approval, lifted, effect) -> "ACT" | "LIFT_REFUSED": the consumer rule over two records (L1-L5).
- grade_count(record) and replay_score(record): GRADE's count and its replay-score mapping (r2 section 7 point 4).
- replay(case) -> (ok, got): one vector of architecture/decision-record/vectors.json against its expectation.
- Consumer: the packet's test seam for the lift's crash, race and repeat cases (C30 (6)); a lift is recorded by the
  effect it permits, in the same step as the effect, and a crash before the step leaves it unlifted.
Standard library only. Data checks only; it enforces nothing.
"""
from __future__ import annotations

import hashlib
import json

SCHEMA_NAME = "planeon.internal.decision-record/v1"
KINDS = ("GUARDRAIL", "ADMISSION_SCAN", "GRADE", "APPROVAL")
DECISIONS = {                                    # most to least restrictive; APPROVAL has no order (E6a)
    "GUARDRAIL": ("DENY", "ESCALATE", "TRANSFORM", "ALLOW"),
    "ADMISSION_SCAN": ("DENY", "ESCALATE", "ALLOW"),
    "GRADE": ("FAIL", "PASS"),
    "APPROVAL": ("REJECTED", "EXPIRED", "CANCELLED", "UNAVAILABLE", "APPROVED"),
}
UNORDERED = ("APPROVAL",)
FAIL_CLOSED = {"GUARDRAIL": "DENY", "ADMISSION_SCAN": "DENY", "GRADE": "UNGRADED", "APPROVAL": "UNAVAILABLE"}
PERMITTING = ("ALLOW", "PASS", "APPROVED")
STATUSES = ("DECIDED", "ERROR")
ERRORS_BEFORE_SELECTION = ("ERR_MALFORMED_INPUT", "ERR_RULE_NOT_SELECTED")
ERRORS_DURING_EVALUATION = ("ERR_EVALUATOR_UNAVAILABLE", "ERR_TIMEOUT", "ERR_INTERNAL")
ERROR_CODES = ERRORS_BEFORE_SELECTION + ERRORS_DURING_EVALUATION
SOURCES = ("DETERMINISTIC", "MODEL")
EVIDENCE_KINDS = ("POLICY_RESULT", "TRACE", "ARTIFACT")
CHECK_ORDER = ("ENVELOPE_MIXED", "EFFECTIVE_MISMATCH", "ERROR_AS_DECISION", "REASON_MISMATCH", "RULE_VERSION_MISSING",
               "MODEL_APPROVAL", "MODEL_LOWERED", "TRANSFORM_CONFLICT", "TRANSFORM_MISMATCH")
LIFT_REFUSED = "LIFT_REFUSED"
CODES = CHECK_ORDER + (LIFT_REFUSED,)
RESULTS = ("ACCEPTED", "REFUSED", "READ_FAIL_CLOSED", "UNGRADED", "ACT")
REASON_CODES = {kind: tuple("%s_%s" % (kind, value) for value in DECISIONS[kind]) for kind in KINDS}
RECORD_KEYS = ("schemaVersion", "decisionId", "kind", "subject", "envelope", "reasonCode", "rule", "evidence",
               "contributions", "transform", "escalationRef", "approval", "decidedAt", "supersedes")
SUBJECT_KEYS = ("scopeDigest", "subjectKind", "subjectDigest", "revision")
ENVELOPE_KEYS = ("status", "decision", "effectiveDecision", "error")
ERROR_KEYS = ("code", "detail")
RULE_KEYS = ("ruleId", "ruleVersion", "policyVersion", "policyBindingDigest")
EVIDENCE_KEYS = ("kind", "contentDigest", "locations", "matchFingerprint")
LOCATION_KEYS = ("path", "start", "end")
CONTRIBUTION_KEYS = ("source", "ruleId", "ruleVersion", "model", "decision", "score")
MODEL_KEYS = ("modelId", "configurationDigest", "promptDigest", "tokensIn", "tokensOut")
TRANSFORM_KEYS = ("valueBeforeDigest", "valueAfterDigest")
EFFECT_KEYS = ("at", "scopeDigest", "subjectDigest", "revision")
# DEC-ALIGN-296-FIX-001 D1: the approval row is closed to the schema's required keys and its propertyNames list (the
# required keys, then these optional ones); its members' types are HR-APPROVAL's, not checked here.
APPROVAL_REQUIRED = ("requestId", "kind", "state", "subjectId", "revision", "subjectDigest", "policyRef",
                     "policyBindingDigest", "ruleVersion", "mandate", "expiresAt", "asker", "askPort", "decidePort",
                     "decisionRef", "decidedBy", "reasonCode", "decidingStatement")
APPROVAL_OPTIONAL = ("businessIntentId", "payloadHash", "evidenceVersions", "preconditions", "compartment", "limits")
SCORE_MAX = 1_000_000
REPLAY_BLOCKED = {"status": "BLOCKED", "blockerCode": "EVALUATOR_ERROR"}


def canonical(value) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False).encode("utf-8")


def digest(value) -> str:
    return "sha256:" + hashlib.sha256(canonical(value)).hexdigest()


class Malformed(Exception):
    pass


def _need(ok, reason):
    if not ok:
        raise Malformed(reason)


def _closed(value, keys, where):
    _need(type(value) is dict and set(value) == set(keys), "%s is closed to %s" % (where, ", ".join(keys)))


def _text(value, where):
    _need(type(value) is str and value != "", where + " is a non-empty string")


def _digest_text(value, where):
    _need(type(value) is str and value.startswith("sha256:") and len(value) == 71
          and all(c in "0123456789abcdef" for c in value[7:]), where + " is a sha256 digest")


def _int(value, where, top=None):
    _need(type(value) is int and value >= 0 and (top is None or value <= top), where + " is a bounded integer")


def _shape(record):
    """The record's closed shape, without the decision value (read under E7) and without the cross-field rules."""
    _closed(record, RECORD_KEYS, "the record")
    _need(record["schemaVersion"] == SCHEMA_NAME, "schemaVersion is " + SCHEMA_NAME)
    _text(record["decisionId"], "decisionId")
    _text(record["kind"], "kind")
    _closed(record["subject"], SUBJECT_KEYS, "subject")
    _digest_text(record["subject"]["scopeDigest"], "subject.scopeDigest")
    _text(record["subject"]["subjectKind"], "subject.subjectKind")
    _digest_text(record["subject"]["subjectDigest"], "subject.subjectDigest")
    _int(record["subject"]["revision"], "subject.revision")
    envelope = record["envelope"]
    _closed(envelope, ENVELOPE_KEYS, "envelope")
    _need(envelope["status"] in STATUSES, "envelope.status is DECIDED or ERROR")
    _need(envelope["decision"] is None or type(envelope["decision"]) is str, "envelope.decision is a string or null")
    _text(envelope["effectiveDecision"], "envelope.effectiveDecision")
    if envelope["error"] is not None:
        _closed(envelope["error"], ERROR_KEYS, "envelope.error")
        _need(envelope["error"]["code"] in ERROR_CODES, "envelope.error.code is a reserved code")
        _text(envelope["error"]["detail"], "envelope.error.detail")
    _text(record["reasonCode"], "reasonCode")
    if record["rule"] is not None:
        _closed(record["rule"], RULE_KEYS, "rule")
        for key in RULE_KEYS[:3]:
            _need(type(record["rule"][key]) is str, "rule.%s is a string" % key)
        _digest_text(record["rule"]["policyBindingDigest"], "rule.policyBindingDigest")
    _need(type(record["evidence"]) is list, "evidence is a list")
    for row in record["evidence"]:
        _closed(row, EVIDENCE_KEYS, "an evidence row")
        _need(row["kind"] in EVIDENCE_KINDS, "an evidence kind is the verdict ledger's")
        _digest_text(row["contentDigest"], "evidence.contentDigest")
        _need(row["locations"] is None or type(row["locations"]) is list, "evidence.locations is a list or null")
        for spot in row["locations"] or ():
            _closed(spot, LOCATION_KEYS, "a location")
            _text(spot["path"], "location.path")
            _int(spot["start"], "location.start")
            _int(spot["end"], "location.end")
        _need(row["matchFingerprint"] is None or (type(row["matchFingerprint"]) is str and row["matchFingerprint"] != ""),
              "matchFingerprint is null or a non-empty string")                      # D1: the schema's minLength 1
    _need(type(record["contributions"]) is list, "contributions is a list")
    for row in record["contributions"]:
        _closed(row, CONTRIBUTION_KEYS, "a contribution")
        _need(row["source"] in SOURCES, "a contribution's source is DETERMINISTIC or MODEL")
        _text(row["ruleId"], "a contribution's ruleId")                              # D1
        _text(row["ruleVersion"], "a contribution's ruleVersion")
        _need((row["model"] is not None) == (row["source"] == "MODEL"), "model is set exactly for a MODEL source")
        if row["model"] is not None:
            _closed(row["model"], MODEL_KEYS, "a contribution's model")
            _text(row["model"]["modelId"], "model.modelId")
            _digest_text(row["model"]["configurationDigest"], "model.configurationDigest")
            _digest_text(row["model"]["promptDigest"], "model.promptDigest")
            _int(row["model"]["tokensIn"], "model.tokensIn")
            _int(row["model"]["tokensOut"], "model.tokensOut")
        _need(row["decision"] is None or type(row["decision"]) is str, "a contribution's decision")
        _need(row["score"] is None or (type(row["score"]) is int and 0 <= row["score"] <= SCORE_MAX), "score bound")
    if record["transform"] is not None:
        _closed(record["transform"], TRANSFORM_KEYS, "transform")
        _digest_text(record["transform"]["valueBeforeDigest"], "transform.valueBeforeDigest")
        _digest_text(record["transform"]["valueAfterDigest"], "transform.valueAfterDigest")
    is_approval = record["kind"] == "APPROVAL"
    _need(is_approval or record["escalationRef"] is None, "escalationRef is null on every kind but APPROVAL")
    if record["escalationRef"] is not None:
        _digest_text(record["escalationRef"], "escalationRef")
    _need((record["approval"] is not None) == is_approval, "approval is set exactly on kind APPROVAL")
    if is_approval:                                                              # D1: closed, no member types added
        _need(type(record["approval"]) is dict
              and set(APPROVAL_REQUIRED) <= set(record["approval"]) <= set(APPROVAL_REQUIRED + APPROVAL_OPTIONAL),
              "approval is HR-APPROVAL's row, closed to the schema's required keys and property names")
    _text(record["decidedAt"], "decidedAt")
    if record["supersedes"] is not None:
        _digest_text(record["supersedes"], "supersedes")


def _verified(record) -> bool:
    """APPROVAL's verified decision maker: HR-APPROVAL's decidedBy, a HUMAN reviewer with an id digest."""
    maker = record["approval"].get("decidedBy") if type(record["approval"]) is dict else None
    return (type(maker) is dict and maker.get("type") == "HUMAN" and type(maker.get("idDigest")) is str
            and maker["idDigest"].startswith("sha256:"))


def _rank(kind, value):
    return DECISIONS[kind].index(value)


def _refusal(record):
    """The first refusal code in CHECK_ORDER, or None."""
    kind, env = record["kind"], record["envelope"]
    status, decision, error = env["status"], env["decision"], env["error"]
    if (status == "DECIDED") != (decision is not None) or (status == "DECIDED") == (error is not None):
        return "ENVELOPE_MIXED"                                              # E1
    if env["effectiveDecision"] != (decision if status == "DECIDED" else FAIL_CLOSED[kind]):
        return "EFFECTIVE_MISMATCH"                                          # E2 (and E3 through it)
    if (status == "DECIDED") == record["reasonCode"].startswith("ERR_"):
        return "ERROR_AS_DECISION"                                           # E4
    if record["reasonCode"] != ("%s_%s" % (kind, decision) if status == "DECIDED" else error["code"]):
        return "REASON_MISMATCH"                                             # D2: KIND_DECISION, or its own error code
    rule = record["rule"]
    named = rule is not None and rule["ruleId"] != "" and rule["ruleVersion"] != ""
    if (status == "DECIDED" or error["code"] in ERRORS_DURING_EVALUATION) and not named:
        return "RULE_VERSION_MISSING"                                        # E5
    if kind == "APPROVAL":                                                   # E6a
        if any(c["source"] == "MODEL" and c["decision"] is not None for c in record["contributions"]):
            return "MODEL_APPROVAL"
        if (decision == "APPROVED" or record["escalationRef"] is not None) and not _verified(record):
            return "MODEL_APPROVAL"
    elif status == "DECIDED":                                                # E6b
        firm = [c["decision"] for c in record["contributions"] if c["source"] == "DETERMINISTIC"]
        if any(c is not None and _rank(kind, decision) > _rank(kind, c) for c in firm):
            return "MODEL_LOWERED"
    if kind == "GUARDRAIL":                                                  # E6c
        rewrites = [c for c in record["contributions"] if c["decision"] == "TRANSFORM"]
        if len(rewrites) > 1 and decision == "TRANSFORM":
            return "TRANSFORM_CONFLICT"
    if (record["transform"] is not None) != (env["effectiveDecision"] == "TRANSFORM"):
        return "TRANSFORM_MISMATCH"                                          # X3
    return None


def evaluate(record):
    """One record under the envelope: accepted, refused with the first code, or read fail closed (E7)."""
    try:
        _shape(record)
    except Malformed as exc:
        return ("MALFORMED", str(exc))
    kind, env = record["kind"], record["envelope"]
    if kind not in KINDS:
        return ("READ_FAIL_CLOSED", "DENY")                                  # E7: the most restrictive reading
    values = list(DECISIONS[kind]) + [FAIL_CLOSED[kind]]
    if (env["decision"] is not None and env["decision"] not in DECISIONS[kind]) or env["effectiveDecision"] not in values:
        return ("READ_FAIL_CLOSED", FAIL_CLOSED[kind])                       # E7: no default branch maps to allow
    if any(c["decision"] is not None and c["decision"] not in DECISIONS[kind] for c in record["contributions"]):
        return ("READ_FAIL_CLOSED", FAIL_CLOSED[kind])                       # E7 over every kind's contributions (D1)
    code = _refusal(record)
    return ("REFUSED", code) if code else ("ACCEPTED", None)


def effective(record) -> str:
    """What a consumer acts on: the accepted record's effective decision; anything else is the fail-closed value."""
    result, value = evaluate(record)
    if result == "ACCEPTED":
        return record["envelope"]["effectiveDecision"]
    kind = record.get("kind") if type(record) is dict else None
    return value if result == "READ_FAIL_CLOSED" else FAIL_CLOSED.get(kind, "DENY")


def grade_count(record) -> str:
    """GRADE's count: PASS or FAIL for an accepted DECIDED record; an ERROR record is UNGRADED, never PASS or FAIL."""
    result, _ = evaluate(record)
    if result != "ACCEPTED" or record["kind"] != "GRADE":
        return "UNGRADED"
    env = record["envelope"]
    return env["decision"] if env["status"] == "DECIDED" else "UNGRADED"


def replay_score(record):
    """r2 section 7 point 4: a GRADE ERROR maps to replay-score BLOCKED with blockerCode EVALUATOR_ERROR and the
    record as evidenceDigest, its digest (BUILD_PLAN_296 ERR-7)."""
    if grade_count(record) == "UNGRADED":
        return dict(REPLAY_BLOCKED, evidenceDigest=digest(record))
    return {"status": "SCORED", "blockerCode": None}


def lift(escalation, approval, lifted, effect) -> str:
    """L1-L5: ACT when the approval lifts this escalation for this effect, otherwise LIFT_REFUSED."""
    try:
        _closed(effect, EFFECT_KEYS, "the effect")
        _need(type(lifted) is list and all(type(x) is str for x in lifted), "lifted is a list of digests")
    except Malformed:
        return LIFT_REFUSED
    if evaluate(escalation) != ("ACCEPTED", None) or evaluate(approval) != ("ACCEPTED", None):
        return LIFT_REFUSED
    if escalation["kind"] not in ("GUARDRAIL", "ADMISSION_SCAN") or approval["kind"] != "APPROVAL":
        return LIFT_REFUSED
    if escalation["envelope"]["effectiveDecision"] != "ESCALATE":
        return LIFT_REFUSED                                                  # DENY is never liftable
    if approval["envelope"]["decision"] != "APPROVED" or not _verified(approval):
        return LIFT_REFUSED                                                  # L1
    expires = approval["approval"].get("expiresAt")
    if type(expires) is not int or effect["at"] >= expires:
        return LIFT_REFUSED                                                  # L2
    bound = [(r["subject"]["scopeDigest"], r["subject"]["subjectDigest"], r["subject"]["revision"])
             for r in (escalation, approval)]
    action = (effect["scopeDigest"], effect["subjectDigest"], effect["revision"])
    if bound[0] != bound[1] or action != bound[0]:
        return LIFT_REFUSED                                                  # L3
    own = digest(escalation)
    if approval["escalationRef"] != own:
        return LIFT_REFUSED                                                  # L4
    if own in lifted:
        return LIFT_REFUSED                                                  # L5: lifted at most once
    return "ACT"


def run(case):
    """The result of one vector's input, in its expectation's shape."""
    data = case["input"]
    if case["kind"] == "LIFT":
        got = lift(data["escalation"], data["approval"], data["lifted"], data["effect"])
        return {"result": "ACT"} if got == "ACT" else {"result": "REFUSED", "code": got}
    result, value = evaluate(data)
    if result == "REFUSED":
        return {"result": "REFUSED", "code": value}
    if result == "READ_FAIL_CLOSED":
        return {"result": "READ_FAIL_CLOSED", "effectiveDecision": value}
    if result == "ACCEPTED" and data["kind"] == "GRADE" and data["envelope"]["status"] == "ERROR":
        return {"result": "UNGRADED", "replayScore": replay_score(data)}
    return {"result": result} if result == "ACCEPTED" else {"result": result, "reason": value}


def replay(case):
    """(the vector meets its expectation, what the model gave)."""
    try:
        got = run(case)
    except (KeyError, TypeError, ValueError) as exc:
        return False, {"result": "ERROR", "reason": type(exc).__name__}
    return got == case["expect"], got


class Consumer:
    """The lift's test seam: the escalation in force per action, the lifted set, and the effects run. A lift is
    recorded by the effect it permits, in the same step; a crash before the step records neither."""

    def __init__(self):
        self.current = {}
        self.lifted = []
        self.effects = []

    @staticmethod
    def _action(record_or_effect):
        s = record_or_effect["subject"] if "subject" in record_or_effect else record_or_effect
        return (s["scopeDigest"], s["subjectDigest"], s["revision"])

    def escalate(self, record):
        """A new ESCALATE record for an action becomes the one in force (append-only history, same kind)."""
        self.current[self._action(record)] = record

    def act(self, approval, effect, crash_before_act=False):
        """Check against the escalation in force at the act, then run the effect and record the lift together."""
        escalation = self.current.get(self._action(effect))
        if escalation is None:
            return LIFT_REFUSED
        verdict = lift(escalation, approval, list(self.lifted), effect)
        if verdict != "ACT":
            return verdict
        if crash_before_act:
            return "CRASHED"
        self.lifted.append(digest(escalation))
        self.effects.append(digest(effect))
        return "ACT"
