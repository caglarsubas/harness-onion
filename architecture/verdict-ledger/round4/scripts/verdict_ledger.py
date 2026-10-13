#!/usr/bin/env python3
"""Verdict and evidence ledger v1 (architecture/verdict-ledger/, MAS-RA-001): reference model, DATA_CHECK_ONLY.

A ledger records one assessment of one delivered subject (the artifact under assessment, identified by H16's evidence scope
tuple; it may be one rollout of a pool or a revised delivery). Each claim names a requirement, the value the subject delivers
for it and the value every rollout of the pool gave (ABSENT for an omission); check outcomes are about the delivered value.
Claims link to the checks that tested them, checks to the evidence they cite (content digests) and claims to their verdicts;
the ledger verdict aggregates the claim verdicts. `parse` reads ledger text as I-JSON and `check_ledger` applies
the rules as whole-ledger passes in the order of CODES and reports the first failing one, so a ledger that breaks several
rules always reports the earliest code. It also derives the ledger status (`aggregate`), its H16 evidence state
(`h16_evidence_state`) and checks an append-only history of ledgers for one subject (`check_history`). Standard library only,
so any consumer can run it without jsonschema; `ledger.schema.json` states the same closed shape.

Owner decisions (2026-10-13, via the lane monitor): Q-MAS1-A (a) UNRESOLVED maps to the H16 evidence state WARN and stays its
own ledger value; Q-MAS1-B (a) an internal contract candidate, no H16 change; Q-MAS1-C (a) the producing context's identity
and role are modelled and a verdict from the generating context is refused; signing stays with H16's evidence signer.
"""
from __future__ import annotations

import hashlib
import json
import math
import re

SCHEMA = "planeon.internal.verdict-ledger/v1"
KINDS_SCHEMA = "planeon.internal.verdict-check-kinds/v1"
STATUSES = ("PASS", "FAIL", "UNRESOLVED")
CLAIM_VERDICTS = ("SUPPORTED", "CONTRADICTED", "NEW_VALUE_ESTABLISHED", "UNRESOLVED")
OUTCOMES = ("PASS", "FAIL", "INCONCLUSIVE")
TARGETS = ("DELIVERED", "INTERMEDIATE")
ABSENT = "ABSENT"
DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")
IDENT = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}\Z")
MAX_ITEMS = 256
MAX_SCORE = 1_000_000
LEDGER_KEYS = ("schemaVersion", "ledgerId", "subject", "rollouts", "contexts", "claims", "checks", "evidence",
               "claimVerdicts", "verdict", "supersedes")
SCOPE_KEYS = ("tenantId", "profileDigest", "bundleDigest", "routeId", "routeDigest", "subjectType", "subjectId",
              "subjectVersion", "subjectDigest")
CODES = ("LEDGER_SHAPE", "DUPLICATE_ID", "UNKNOWN_REFERENCE", "ROLLOUT_SET", "CHECK_OMITTED", "EVIDENCE_KIND_UNKNOWN",
         "NOT_EVIDENCE", "EVIDENCE_KIND_NOT_ALLOWED", "PRODUCER_ROLE_NOT_ALLOWED", "EVIDENCE_PROVENANCE",
         "CONTEXTS_NOT_ISOLATED", "CONTEXT_NOT_FRESH", "GENERATING_CONTEXT_VERDICT", "VERDICT_PRODUCER_ROLE",
         "DETERMINISTIC_ORDER", "DETERMINISTIC_OVERRIDE", "NO_EVIDENCE", "NO_DECIDING_CHECK", "INTERMEDIATE_TARGET",
         "CONSENSUS_ONLY", "CONSISTENCY_ONLY", "DISAGREEMENT_UNADJUDICATED", "VALUE_NOT_ESTABLISHED",
         "EVIDENCE_REF_UNBOUND", "UNRESOLVED_CHECKS_MISMATCH", "UNRESOLVED_PROMOTED", "STATUS_MISMATCH")
HISTORY_CODES = ("HISTORY_SHAPE", "HISTORY_SUBJECT", "HISTORY_ID_REUSED", "HISTORY_BROKEN", "HISTORY_RETRY")
STATUS_RANK = {"FAIL": 0, "UNRESOLVED": 1, "PASS": 2}
CLAIM_RANK = {"CONTRADICTED": 0, "NEW_VALUE_ESTABLISHED": 0, "UNRESOLVED": 1, "SUPPORTED": 2}


class Refused(ValueError):
    """A ledger or history breaks a rule; `code` is one of CODES or HISTORY_CODES."""

    def __init__(self, code: str):
        super().__init__(code)
        self.code = code


def _refuse(ok: bool, code: str) -> None:
    if not ok:
        raise Refused(code)


# ---------------------------------------------------------------- canonical form

def _integral(value) -> bool:
    """An integer, or a JSON number with no fractional part (JSON Schema treats 1.0 as an integer)."""
    if type(value) is int:
        return True
    return type(value) is float and math.isfinite(value) and value.is_integer() and abs(value) <= 2 ** 53


def _normal(value):
    """The ledger's values with integral floats as integers: the value space on which RFC 8785 serialization and
    Python's sorted, compact, non-ASCII-preserving JSON coincide (ASCII keys, integers, strings, null, lists, objects)."""
    if type(value) is float:
        if not _integral(value):
            raise Refused("LEDGER_SHAPE")
        return int(value)
    if type(value) is list:
        return [_normal(v) for v in value]
    if type(value) is dict:
        return {k: _normal(v) for k, v in value.items()}
    return value


def canonical(value) -> bytes:
    """RFC 8785 (JCS) bytes of a ledger-space value: keys sorted, no whitespace, UTF-8, integers without a fraction."""
    return json.dumps(_normal(value), sort_keys=True, ensure_ascii=False, separators=(",", ":"),
                      allow_nan=False).encode("utf-8")


def digest(value) -> str:
    return "sha256:" + hashlib.sha256(canonical(value)).hexdigest()


def _no_constant(name):
    raise Refused("LEDGER_SHAPE")


def _members(pairs):
    names = [name for name, _ in pairs]
    _refuse(len(names) == len(set(names)), "LEDGER_SHAPE")
    return dict(pairs)


def parse(text):
    """Parse ledger text as I-JSON (RFC 7493): UTF-8, no duplicate member names, no NaN or infinity. Any other text is
    LEDGER_SHAPE, so two consumers never read one text as two different ledgers."""
    try:
        if isinstance(text, (bytes, bytearray)):
            text = bytes(text).decode("utf-8")
        text.encode("utf-8")                    # valid Unicode only: a str holding surrogate code points is refused
        return json.loads(text, object_pairs_hook=_members, parse_constant=_no_constant)
    except Refused:
        raise
    except (ValueError, TypeError, RecursionError) as exc:
        raise Refused("LEDGER_SHAPE") from exc


def scope_digest(scope: dict) -> str:
    """subject.scopeDigest: the digest of H16's evidence scope tuple as one JSON object with exactly its nine members
    (the five digest members are sha256 digests, the others non-empty strings)."""
    _refuse(type(scope) is dict and set(scope) == set(SCOPE_KEYS)
            and all(_digest_str(v) if k.endswith("Digest") else _text(v, 256) for k, v in scope.items()), "LEDGER_SHAPE")
    return digest(scope)


# ---------------------------------------------------------------- shape

def _text(value, limit: int = 1024) -> bool:
    return (type(value) is str and 0 < len(value) <= limit
            and not any(0xD800 <= ord(c) <= 0xDFFF for c in value))


def _ident(value) -> bool:
    return type(value) is str and IDENT.match(value) is not None


def _ids(value) -> bool:
    return type(value) is list and len(value) <= MAX_ITEMS and all(_ident(v) for v in value)


def _closed(value, keys, optional=()) -> bool:
    return type(value) is dict and set(keys) <= set(value) <= set(keys) | set(optional)


def _digest_str(value) -> bool:
    return type(value) is str and DIGEST.match(value) is not None


def _rows(value) -> bool:
    return type(value) is list and 0 < len(value) <= MAX_ITEMS


def _shape(doc, kinds) -> None:
    """The closed shape (the same constraints as ledger.schema.json; uniqueness is DUPLICATE_ID's)."""
    roles = kinds["contextRoles"]
    _refuse(_closed(doc, LEDGER_KEYS) and doc["schemaVersion"] == SCHEMA and _ident(doc["ledgerId"])
            and _closed(doc["subject"], ("scopeDigest",)) and _digest_str(doc["subject"]["scopeDigest"])
            and (doc["supersedes"] is None or _digest_str(doc["supersedes"])) and _ids(doc["rollouts"]), "LEDGER_SHAPE")
    for name in ("contexts", "claims", "checks", "evidence", "claimVerdicts"):
        _refuse(_rows(doc[name]), "LEDGER_SHAPE")
    for c in doc["contexts"]:
        _refuse(_closed(c, ("contextId", "role", "inheritsFrom")) and _ident(c["contextId"]) and c["role"] in roles
                and _ids(c["inheritsFrom"]), "LEDGER_SHAPE")
    for c in doc["claims"]:
        _refuse(_closed(c, ("claimId", "requirement", "delivered", "rolloutValues")) and _ident(c["claimId"])
                and _text(c["requirement"]) and _text(c["delivered"]) and type(c["rolloutValues"]) is list
                and len(c["rolloutValues"]) <= MAX_ITEMS, "LEDGER_SHAPE")
        for v in c["rolloutValues"]:
            _refuse(_closed(v, ("rollout", "value")) and _ident(v["rollout"]) and _text(v["value"]), "LEDGER_SHAPE")
    for k in doc["checks"]:
        _refuse(_closed(k, ("checkId", "claimId", "kind", "sequence", "target", "contextId", "outcome", "evidence"),
                        ("establishedValue",))
                and _ident(k["checkId"]) and _ident(k["claimId"]) and _text(k["kind"], 64)
                and _integral(k["sequence"]) and 0 < k["sequence"] <= 1_000_000 and k["target"] in TARGETS
                and _ident(k["contextId"]) and k["outcome"] in OUTCOMES and _ids(k["evidence"])
                and ("establishedValue" not in k or _text(k["establishedValue"])), "LEDGER_SHAPE")
    for e in doc["evidence"]:
        _refuse(_closed(e, ("evidenceId", "kind", "contentDigest", "producedBy")) and _ident(e["evidenceId"])
                and _text(e["kind"], 64) and _digest_str(e["contentDigest"]) and _ident(e["producedBy"]), "LEDGER_SHAPE")
    for v in doc["claimVerdicts"]:
        _refuse(_closed(v, ("claimId", "verdict", "checks"), ("value",)) and _ident(v["claimId"])
                and v["verdict"] in CLAIM_VERDICTS and _ids(v["checks"])
                and ("value" not in v or _text(v["value"])), "LEDGER_SHAPE")
    verdict = doc["verdict"]
    _refuse(_closed(verdict, ("status", "producedBy", "evidenceRefs", "policyViolations", "unresolvedChecks", "scores"))
            and verdict["status"] in STATUSES and _ident(verdict["producedBy"])
            and type(verdict["evidenceRefs"]) is list and len(verdict["evidenceRefs"]) <= MAX_ITEMS
            and all(_digest_str(r) for r in verdict["evidenceRefs"])
            and type(verdict["policyViolations"]) is list and len(verdict["policyViolations"]) <= MAX_ITEMS
            and all(_closed(p, ("policyId", "evidenceId")) and _ident(p["policyId"]) and _ident(p["evidenceId"])
                    for p in verdict["policyViolations"])
            and _ids(verdict["unresolvedChecks"])
            and type(verdict["scores"]) is dict and len(verdict["scores"]) <= 64
            and all(_ident(n) and _integral(s) and 0 <= s <= MAX_SCORE for n, s in verdict["scores"].items()),
            "LEDGER_SHAPE")


# ---------------------------------------------------------------- the rules, one whole-ledger pass each

class _View:
    """Indexed views of a shape-checked ledger, built after DUPLICATE_ID and UNKNOWN_REFERENCE hold."""

    def __init__(self, doc, kinds):
        self.doc, self.kinds = doc, kinds
        self.contexts = {c["contextId"]: c for c in doc["contexts"]}
        self.claims = {c["claimId"]: c for c in doc["claims"]}
        self.checks = {k["checkId"]: k for k in doc["checks"]}
        self.evidence = {e["evidenceId"]: e for e in doc["evidence"]}
        self.verdicts = {v["claimId"]: v for v in doc["claimVerdicts"]}
        self.kind = {row["kind"]: row for row in kinds["checkKinds"]}
        self.role = {c: self.contexts[c]["role"] for c in self.contexts}

    def own(self, claim_id):
        return [k for k in self.doc["checks"] if k["claimId"] == claim_id]

    def deterministic(self, check):
        return self.kind[check["kind"]]["deterministic"]

    def wanted(self, verdict):
        """Outcomes are about the delivered value: SUPPORTED rests on PASS checks; CONTRADICTED and NEW_VALUE_ESTABLISHED
        (the delivered value is wrong, and a correction absent from the pool is established) rest on FAIL checks."""
        return "PASS" if verdict["verdict"] == "SUPPORTED" else "FAIL"

    def deciding(self, verdict):
        return [self.checks[c] for c in verdict["checks"] if self.checks[c]["outcome"] == self.wanted(verdict)]

    def counted(self, verdict):
        """The deciding checks that can settle a claim: those on the delivered quantity, and a deterministic FAIL on any
        target (a denial is never overridden, wherever it was observed)."""
        return [k for k in self.deciding(verdict)
                if k["target"] == "DELIVERED" or (self.deterministic(k) and k["outcome"] == "FAIL")]

    def ancestors(self, context_id):
        """The transitive closure of inheritsFrom (a cycle is refused before this is used)."""
        seen, todo = set(), list(self.contexts[context_id]["inheritsFrom"])
        while todo:
            c = todo.pop()
            if c not in seen:
                seen.add(c)
                todo.extend(self.contexts[c]["inheritsFrom"])
        return seen

    def settled(self):
        return [v for v in self.doc["claimVerdicts"] if v["verdict"] != "UNRESOLVED"]


def _duplicates(doc, kinds) -> None:
    for name, key in (("contexts", "contextId"), ("claims", "claimId"), ("checks", "checkId"),
                      ("evidence", "evidenceId"), ("claimVerdicts", "claimId")):
        values = [row[key] for row in doc[name]]
        _refuse(len(values) == len(set(values)), "DUPLICATE_ID")
    for values in ([k["sequence"] for k in doc["checks"]], [e["contentDigest"] for e in doc["evidence"]],
                   doc["rollouts"], doc["verdict"]["evidenceRefs"], doc["verdict"]["unresolvedChecks"]):
        _refuse(len(values) == len(set(values)), "DUPLICATE_ID")
    for row in doc["contexts"]:
        _refuse(len(row["inheritsFrom"]) == len(set(row["inheritsFrom"])), "DUPLICATE_ID")
    for row in doc["claims"]:
        rollouts = [v["rollout"] for v in row["rolloutValues"]]
        _refuse(len(rollouts) == len(set(rollouts)), "DUPLICATE_ID")
    for row in doc["checks"] + doc["claimVerdicts"]:
        ids = row["evidence"] if "evidence" in row else row["checks"]
        _refuse(len(ids) == len(set(ids)), "DUPLICATE_ID")


def _references(doc, kinds) -> None:
    contexts = {c["contextId"] for c in doc["contexts"]}
    claims = {c["claimId"] for c in doc["claims"]}
    checks = {k["checkId"]: k for k in doc["checks"]}
    evidence = {e["evidenceId"] for e in doc["evidence"]}
    registered = {row["kind"] for row in kinds["checkKinds"]}
    _refuse(all(set(c["inheritsFrom"]) <= contexts for c in doc["contexts"]), "UNKNOWN_REFERENCE")
    _refuse(all(k["claimId"] in claims and k["contextId"] in contexts and set(k["evidence"]) <= evidence
                and k["kind"] in registered for k in checks.values()), "UNKNOWN_REFERENCE")
    _refuse(all(e["producedBy"] in contexts for e in doc["evidence"]), "UNKNOWN_REFERENCE")
    _refuse({v["claimId"] for v in doc["claimVerdicts"]} == claims, "UNKNOWN_REFERENCE")
    _refuse(all(set(v["checks"]) <= set(checks) and all(checks[c]["claimId"] == v["claimId"] for c in v["checks"])
                for v in doc["claimVerdicts"]), "UNKNOWN_REFERENCE")
    verdict = doc["verdict"]
    _refuse(verdict["producedBy"] in contexts and set(verdict["unresolvedChecks"]) <= set(checks)
            and all(p["evidenceId"] in evidence for p in verdict["policyViolations"]), "UNKNOWN_REFERENCE")


def _rollout_set(v: _View) -> None:
    """Every claim lists exactly the ledger's rollouts; an omission is the explicit value ABSENT."""
    expected = set(v.doc["rollouts"])
    _refuse(all({r["rollout"] for r in c["rolloutValues"]} == expected for c in v.doc["claims"]), "ROLLOUT_SET")


def _check_omitted(v: _View) -> None:
    """A claim verdict accounts for every check of its claim."""
    _refuse(all(set(verdict["checks"]) == {k["checkId"] for k in v.own(cid)} for cid, verdict in v.verdicts.items()),
            "CHECK_OMITTED")


def _evidence_kind_unknown(v: _View) -> None:
    known = set(v.kinds["evidenceKinds"]) | set(v.kinds["notEvidence"])
    _refuse(all(e["kind"] in known for e in v.doc["evidence"]), "EVIDENCE_KIND_UNKNOWN")


def _not_evidence(v: _View) -> None:
    _refuse(all(e["kind"] not in v.kinds["notEvidence"] for e in v.doc["evidence"]), "NOT_EVIDENCE")


def _evidence_kind_not_allowed(v: _View) -> None:
    _refuse(all(v.evidence[e]["kind"] in v.kind[k["kind"]]["evidenceKinds"] for k in v.doc["checks"] for e in k["evidence"]),
            "EVIDENCE_KIND_NOT_ALLOWED")
    _refuse(all(v.evidence[p["evidenceId"]]["kind"] in v.kinds["policyViolationKinds"]
                for p in v.doc["verdict"]["policyViolations"]), "EVIDENCE_KIND_NOT_ALLOWED")


def _producer_role(v: _View) -> None:
    _refuse(all(v.role[k["contextId"]] in v.kind[k["kind"]]["producerRoles"] for k in v.doc["checks"]),
            "PRODUCER_ROLE_NOT_ALLOWED")


def _provenance(v: _View) -> None:
    """Who produced each piece of evidence. A generating context produces only subject outputs (what it delivered: its
    artifact, trace or diff), never a check result or a report; each report kind comes from a context of its registered
    roles (a resolver report from a resolver, a challenger report from a challenger, a verifier report from a verifier or
    an evaluator). A check cites subject outputs produced by a generating context or by its own context, reports of its
    registered kinds (only ADJUDICATION registers them), and every other kind only when its own context produced it, so no
    check reads another checking context's results except an adjudication reading their reports."""
    rules = v.kinds["provenance"]
    for e in v.doc["evidence"]:
        role = v.role[e["producedBy"]]
        _refuse(role != "GENERATOR" or e["kind"] in rules["subjectOutputs"], "EVIDENCE_PROVENANCE")
        _refuse(e["kind"] not in rules["reports"] or role in rules["reports"][e["kind"]], "EVIDENCE_PROVENANCE")
    for k in v.doc["checks"]:
        for e in (v.evidence[i] for i in k["evidence"]):
            if e["kind"] in rules["subjectOutputs"]:
                ok = v.role[e["producedBy"]] == "GENERATOR" or e["producedBy"] == k["contextId"]
            else:
                ok = e["kind"] in rules["reports"] or e["producedBy"] == k["contextId"]
            _refuse(ok, "EVIDENCE_PROVENANCE")


def _isolated(v: _View) -> None:
    """Over the transitive closure of inheritsFrom: no inheritance cycle; a generator inherits only generators (its outputs
    are the subject, fixed before any check, so they never relay a checker's history to another checker); no context but a
    generator inherits a generator's history; resolver and challenger contexts never inherit each other; no context
    inherits a verdict producer's."""
    for c in v.contexts:
        _refuse(c not in v.ancestors(c), "CONTEXTS_NOT_ISOLATED")
    for c, row in v.contexts.items():
        inherited = {v.role[a] for a in v.ancestors(c)}
        _refuse(not inherited & set(v.kinds["verdictProducerRoles"]), "CONTEXTS_NOT_ISOLATED")
        if row["role"] == "GENERATOR":
            _refuse(inherited <= {"GENERATOR"}, "CONTEXTS_NOT_ISOLATED")
        else:
            _refuse("GENERATOR" not in inherited, "CONTEXTS_NOT_ISOLATED")
        if row["role"] == "RESOLVER":
            _refuse("CHALLENGER" not in inherited, "CONTEXTS_NOT_ISOLATED")
        if row["role"] == "CHALLENGER":
            _refuse("RESOLVER" not in inherited, "CONTEXTS_NOT_ISOLATED")


def _fresh(v: _View) -> None:
    """Adjudicator and evaluator contexts start fresh: they inherit no context."""
    _refuse(all(row["inheritsFrom"] == [] for row in v.contexts.values() if row["role"] in v.kinds["verdictProducerRoles"]),
            "CONTEXT_NOT_FRESH")


def _generating_verdict(v: _View) -> None:
    _refuse(v.role[v.doc["verdict"]["producedBy"]] != "GENERATOR", "GENERATING_CONTEXT_VERDICT")


def _verdict_producer(v: _View) -> None:
    _refuse(v.role[v.doc["verdict"]["producedBy"]] in v.kinds["verdictProducerRoles"], "VERDICT_PRODUCER_ROLE")


def _deterministic_order(v: _View) -> None:
    for cid in v.claims:
        det = [k["sequence"] for k in v.own(cid) if v.deterministic(k)]
        prob = [k["sequence"] for k in v.own(cid) if not v.deterministic(k)]
        _refuse(not det or not prob or max(det) < min(prob), "DETERMINISTIC_ORDER")


def _deterministic_override(v: _View) -> None:
    """A deterministic FAIL (a failing test or schema check, a policy denial), on any target, makes its claim CONTRADICTED
    or NEW_VALUE_ESTABLISHED; no other check overrides it into SUPPORTED, and it is never left UNRESOLVED."""
    for cid, verdict in v.verdicts.items():
        if any(v.deterministic(k) and k["outcome"] == "FAIL" for k in v.own(cid)):
            _refuse(verdict["verdict"] in ("CONTRADICTED", "NEW_VALUE_ESTABLISHED"), "DETERMINISTIC_OVERRIDE")


def _no_evidence(v: _View) -> None:
    for verdict in v.settled():
        _refuse(verdict["checks"] and all(v.checks[c]["evidence"] for c in verdict["checks"]), "NO_EVIDENCE")
    _refuse(v.doc["verdict"]["status"] == "UNRESOLVED" or _relied(v), "NO_EVIDENCE")


def _no_deciding(v: _View) -> None:
    _refuse(all(v.deciding(verdict) for verdict in v.settled()), "NO_DECIDING_CHECK")


def _intermediate(v: _View) -> None:
    """A check of an upstream intermediate never confirms: a settled claim needs a deciding check on the delivered quantity
    (or a deterministic FAIL, which decides wherever it was observed)."""
    _refuse(all(v.counted(verdict) for verdict in v.settled()), "INTERMEDIATE_TARGET")


def _counted_kinds(v: _View, verdict, deterministic=None) -> set:
    return {v.evidence[e]["kind"] for k in v.counted(verdict)
            if deterministic is None or v.deterministic(k) == deterministic for e in k["evidence"]}


def _consensus(v: _View) -> None:
    """Agreement among rollouts and a recomputation that matches the pool are not confirmation on their own."""
    for verdict in v.settled():
        _refuse(bool(_counted_kinds(v, verdict) - set(v.kinds["notConfirmation"])), "CONSENSUS_ONLY")


def _consistency(v: _View) -> None:
    """A green regression run is consistency, not confirmation: when a supported claim's deterministic support is only
    regression runs, another kind of deterministic evidence must be among it (a failing-to-passing reproducer, a test,
    schema or policy result on the delivered quantity); model-based evidence such as a reading of the diff does not
    substitute."""
    for verdict in v.settled():
        if verdict["verdict"] == "SUPPORTED":
            det = _counted_kinds(v, verdict, deterministic=True)
            _refuse(not det or not det <= set(v.kinds["consistencyOnly"]), "CONSISTENCY_ONLY")


def _conflicting(v: _View, verdict) -> list:
    """The checks a settled verdict must have adjudicated: evidence-backed checks of the opposite outcome on the delivered
    quantity, and evidence-backed failures at an intermediate (a PASS at an intermediate never confirms, so it never
    conflicts with a contradiction)."""
    opposite = "FAIL" if v.wanted(verdict) == "PASS" else "PASS"
    return [k for k in (v.checks[c] for c in verdict["checks"]) if k["outcome"] == opposite and k["evidence"]
            and (k["target"] == "DELIVERED" or opposite == "FAIL")]


def _reads(v: _View, adjudication, check) -> bool:
    """The adjudication cites a report produced by the context of the check it adjudicates."""
    return any(v.evidence[e]["kind"] in v.kinds["provenance"]["reports"] and v.evidence[e]["producedBy"] == check["contextId"]
               for e in adjudication["evidence"])


def _decides(v: _View, verdict, against, value=None) -> bool:
    last = max(k["sequence"] for k in against)
    return any(k["kind"] == "ADJUDICATION" and k["sequence"] > last and k["target"] == "DELIVERED"
               and (value is None or k.get("establishedValue") == value) and all(_reads(v, k, c) for c in against)
               for k in v.deciding(verdict))


def _adjudicated(v: _View) -> None:
    """Disagreement is adjudicated once, never averaged and never retried. The adjudications of a settled claim agree in
    outcome and established value (re-adjudication belongs in a successor ledger). A settled claim with a conflicting check
    needs a deciding ADJUDICATION on the delivered quantity, sequenced after every conflicting check and citing a report of
    each one's context (a deterministic FAIL decides without one); a NEW_VALUE_ESTABLISHED claim whose checks establish more
    than one value needs such an ADJUDICATION, after every other establishing check and reading each, that establishes the
    verdict's value."""
    for verdict in v.settled():
        own = [v.checks[c] for c in verdict["checks"]]
        adjudications = [k for k in own if k["kind"] == "ADJUDICATION"]
        _refuse(len({(k["outcome"], k.get("establishedValue")) for k in adjudications}) <= 1, "DISAGREEMENT_UNADJUDICATED")
        conflicting = _conflicting(v, verdict)
        decided = any(v.deterministic(k) and k["outcome"] == "FAIL" for k in v.deciding(verdict))
        if conflicting and not decided:
            _refuse(_decides(v, verdict, conflicting), "DISAGREEMENT_UNADJUDICATED")
        establishing = [k for k in own if "establishedValue" in k and k["kind"] != "ADJUDICATION"]
        values = {k["establishedValue"] for k in own if "establishedValue" in k}
        if verdict["verdict"] == "NEW_VALUE_ESTABLISHED" and len(values) > 1:
            _refuse(_decides(v, verdict, establishing, verdict.get("value")), "DISAGREEMENT_UNADJUDICATED")


def _value(v: _View) -> None:
    """Values are bound to the delivered value. Only a check of a kind that can establish a value names one, only on the
    delivered quantity (an intermediate is another quantity), and only with a PASS (then it is the delivered value) or a
    FAIL (then it differs from it). NEW_VALUE_ESTABLISHED carries a value that
    is not ABSENT, is absent from the pool (every rollout value and the delivered value) and is established by a deciding
    check on the delivered quantity; no other verdict carries a value (SUPPORTED means the delivered value)."""
    for k in v.doc["checks"]:
        if "establishedValue" in k:
            delivered = v.claims[k["claimId"]]["delivered"]
            _refuse(v.kind[k["kind"]]["establishesValue"] and k["outcome"] != "INCONCLUSIVE" and k["target"] == "DELIVERED"
                    and (k["establishedValue"] == delivered) == (k["outcome"] == "PASS"), "VALUE_NOT_ESTABLISHED")
    for cid, verdict in v.verdicts.items():
        claim = v.claims[cid]
        if verdict["verdict"] != "NEW_VALUE_ESTABLISHED":
            _refuse("value" not in verdict, "VALUE_NOT_ESTABLISHED")
            continue
        value = verdict.get("value")
        pool = {r["value"] for r in claim["rolloutValues"]} | {claim["delivered"]}
        _refuse(value is not None and value != ABSENT and value not in pool
                and any(k.get("establishedValue") == value for k in v.deciding(verdict) if k["target"] == "DELIVERED"),
                "VALUE_NOT_ESTABLISHED")


def _relied(v: _View) -> list:
    return sorted({v.evidence[e]["contentDigest"] for verdict in v.settled() for c in verdict["checks"]
                   for e in v.checks[c]["evidence"]}
                  | {v.evidence[p["evidenceId"]]["contentDigest"] for p in v.doc["verdict"]["policyViolations"]})


def _evidence_refs(v: _View) -> None:
    _refuse(sorted(v.doc["verdict"]["evidenceRefs"]) == _relied(v), "EVIDENCE_REF_UNBOUND")


def _unresolved_checks(v: _View) -> None:
    inconclusive = sorted(k["checkId"] for k in v.doc["checks"] if k["outcome"] == "INCONCLUSIVE")
    _refuse(sorted(v.doc["verdict"]["unresolvedChecks"]) == inconclusive, "UNRESOLVED_CHECKS_MISMATCH")


def _promoted(v: _View) -> None:
    status = aggregate(v.doc["claimVerdicts"], v.doc["verdict"]["policyViolations"], v.doc["verdict"]["unresolvedChecks"])
    _refuse(not (v.doc["verdict"]["status"] == "PASS" and status == "UNRESOLVED"), "UNRESOLVED_PROMOTED")


def _status(v: _View) -> None:
    status = aggregate(v.doc["claimVerdicts"], v.doc["verdict"]["policyViolations"], v.doc["verdict"]["unresolvedChecks"])
    _refuse(v.doc["verdict"]["status"] == status, "STATUS_MISMATCH")


# The passes after UNKNOWN_REFERENCE, in CODES order (each one needs only the passes before it).
RULES = (("ROLLOUT_SET", _rollout_set), ("CHECK_OMITTED", _check_omitted),
         ("EVIDENCE_KIND_UNKNOWN", _evidence_kind_unknown), ("NOT_EVIDENCE", _not_evidence),
         ("EVIDENCE_KIND_NOT_ALLOWED", _evidence_kind_not_allowed), ("PRODUCER_ROLE_NOT_ALLOWED", _producer_role),
         ("EVIDENCE_PROVENANCE", _provenance), ("CONTEXTS_NOT_ISOLATED", _isolated), ("CONTEXT_NOT_FRESH", _fresh),
         ("GENERATING_CONTEXT_VERDICT", _generating_verdict), ("VERDICT_PRODUCER_ROLE", _verdict_producer),
         ("DETERMINISTIC_ORDER", _deterministic_order), ("DETERMINISTIC_OVERRIDE", _deterministic_override),
         ("NO_EVIDENCE", _no_evidence), ("NO_DECIDING_CHECK", _no_deciding), ("INTERMEDIATE_TARGET", _intermediate),
         ("CONSENSUS_ONLY", _consensus), ("CONSISTENCY_ONLY", _consistency),
         ("DISAGREEMENT_UNADJUDICATED", _adjudicated), ("VALUE_NOT_ESTABLISHED", _value),
         ("EVIDENCE_REF_UNBOUND", _evidence_refs), ("UNRESOLVED_CHECKS_MISMATCH", _unresolved_checks),
         ("UNRESOLVED_PROMOTED", _promoted), ("STATUS_MISMATCH", _status))
assert tuple(code for code, _ in RULES) == CODES[3:]


def aggregate(claim_verdicts: list, policy_violations: list, unresolved_checks: list) -> str:
    """FAIL if a claim is contradicted or its delivered value is wrong (a new value was established) or a policy is violated;
    otherwise UNRESOLVED if a claim or a check is unresolved; otherwise PASS. Scores never take part."""
    verdicts = [v["verdict"] for v in claim_verdicts]
    if "CONTRADICTED" in verdicts or "NEW_VALUE_ESTABLISHED" in verdicts or policy_violations:
        return "FAIL"
    if "UNRESOLVED" in verdicts or unresolved_checks:
        return "UNRESOLVED"
    return "PASS"


def h16_evidence_state(doc: dict, kinds: dict, status: str) -> str:
    """The H16 evidence state the ledger's status maps to (owner decision Q-MAS1-A: UNRESOLVED is WARN). A PASS in which a
    supported claim has no deterministic deciding check on the delivered quantity is WARN too: H16 never lets a model
    judge be the sole authority and accompanies model judgments with deterministic checks. H16's own requirements (judge
    version and calibration evidence, the scope tuple, its signer, freshness) still apply before a ledger counts."""
    state = kinds["h16EvidenceState"][status]
    if status != "PASS":
        return state
    v = _View(doc, kinds)
    for verdict in v.settled():
        if not any(v.deterministic(k) for k in v.counted(verdict)):
            return kinds["h16EvidenceState"]["UNRESOLVED"]
    return state


def check_ledger(doc: dict, kinds: dict, skip: tuple = ()) -> dict:
    """Refuse a ledger that breaks a rule (Refused with the first failing code in CODES); otherwise return its derived
    facts. `skip` disables named passes after UNKNOWN_REFERENCE (used only to show that a vector isolates its rule)."""
    try:
        _shape(doc, kinds)
        _duplicates(doc, kinds)
        _references(doc, kinds)
        view = _View(doc, kinds)
        for code, rule in RULES:
            if code not in skip:
                rule(view)
        status = aggregate(doc["claimVerdicts"], doc["verdict"]["policyViolations"], doc["verdict"]["unresolvedChecks"])
        return {"status": status, "h16EvidenceState": h16_evidence_state(doc, kinds, status), "ledgerDigest": digest(doc)}
    except Refused:
        raise
    except (KeyError, TypeError, AttributeError, IndexError, ValueError, UnicodeError, RecursionError) as exc:
        raise Refused("LEDGER_SHAPE") from exc


def check_text(text, kinds: dict) -> dict:
    """check_ledger on ledger text: `parse`, then the rules."""
    return check_ledger(parse(text), kinds)


def _new_evidence(doc, seen: set, claim_id=None) -> bool:
    """The ledger (or one claim's checks) relies on a digest no earlier ledger of the history holds."""
    if claim_id is None:
        digests = set(doc["verdict"]["evidenceRefs"])
    else:
        held = {e["evidenceId"]: e["contentDigest"] for e in doc["evidence"]}
        digests = {held[e] for k in doc["checks"] if k["claimId"] == claim_id for e in k["evidence"]}
    return bool(digests - seen)


def check_history(ledgers: list, kinds: dict) -> list:
    """An append-only history for one subject: every ledger is valid, the subject never changes, every ledger has its own
    ID, the first supersedes nothing and each later one supersedes exactly the digest of the one before it, so an edited
    earlier ledger breaks the chain. A successor never improves on its predecessor by judging the same evidence again: a
    better ledger status (FAIL, then UNRESOLVED, then PASS) needs a relied-on digest that no earlier ledger holds, and so
    does each claim whose verdict improves (CONTRADICTED or NEW_VALUE_ESTABLISHED, then UNRESOLVED, then SUPPORTED), among
    that claim's checks (HISTORY_RETRY; H16: evaluation failures do not retry into a pass). Returns the derived facts in
    order."""
    _refuse(type(ledgers) is list and 0 < len(ledgers) <= MAX_ITEMS, "HISTORY_SHAPE")
    facts, previous, ids, seen = [], None, set(), set()
    for doc in ledgers:
        result = check_ledger(doc, kinds)
        if previous is not None:
            _refuse(doc["subject"] == previous["subject"], "HISTORY_SUBJECT")
        _refuse(doc["ledgerId"] not in ids, "HISTORY_ID_REUSED")
        _refuse(doc["supersedes"] == (digest(previous) if previous is not None else None), "HISTORY_BROKEN")
        if previous is not None:
            if STATUS_RANK[result["status"]] > STATUS_RANK[facts[-1]["status"]]:
                _refuse(_new_evidence(doc, seen), "HISTORY_RETRY")
            before = {v["claimId"]: v["verdict"] for v in previous["claimVerdicts"]}
            for verdict in doc["claimVerdicts"]:
                if verdict["claimId"] in before and CLAIM_RANK[verdict["verdict"]] > CLAIM_RANK[before[verdict["claimId"]]]:
                    _refuse(_new_evidence(doc, seen, verdict["claimId"]), "HISTORY_RETRY")
        ids.add(doc["ledgerId"])
        seen |= {e["contentDigest"] for e in doc["evidence"]}
        facts.append(result)
        previous = doc
    return facts


if __name__ == "__main__":
    from pathlib import Path

    root = Path(__file__).resolve().parents[1]
    kinds = json.loads((root / "architecture/verdict-ledger/check-kinds.json").read_bytes())
    vectors = json.loads((root / "architecture/verdict-ledger/vectors.json").read_bytes())

    def outcome(doc, skip=()):
        try:
            return None, check_ledger(doc, kinds, skip)
        except Refused as refusal:
            return refusal.code, None

    for row in vectors["ledgers"]:
        got, facts = outcome(row["ledger"])
        assert got == row["expect"], (row["id"], got, row["expect"])
        if facts is not None:
            assert [facts[k] for k in ("status", "h16EvidenceState", "ledgerDigest")] == \
                [row[k] for k in ("status", "h16EvidenceState", "ledgerDigest")], row["id"]
        if "withoutOwnRule" in row:
            assert outcome(row["ledger"], (row["expect"],))[0] == row["withoutOwnRule"], row["id"]
    for row in vectors["texts"]:
        try:
            check_text(row["text"], kinds)
            got = None
        except Refused as refusal:
            got = refusal.code
        assert got == row["expect"], row["id"]
    for row in vectors["histories"]:
        try:
            check_history(row["ledgers"], kinds)
            got = None
        except Refused as refusal:
            got = refusal.code
        assert got == row["expect"], (row["id"], got, row["expect"])
    for row in vectors["aggregation"]:
        status = aggregate([{"verdict": c} for c in row["claimVerdicts"]], [{}] * row["policyViolations"],
                           ["K"] * row["unresolvedChecks"])
        assert (status, kinds["h16EvidenceState"][status]) == (row["status"], row["h16EvidenceState"]), row["id"]
    for row in vectors["scopeDigests"]:
        assert scope_digest(row["scope"]) == row["scopeDigest"], row["id"]
    print("verdict ledger vectors replay: %d ledgers, %d texts, %d histories, %d aggregation rows, %d scope digests"
          % tuple(len(vectors[k]) for k in ("ledgers", "texts", "histories", "aggregation", "scopeDigests")))
