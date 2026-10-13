#!/usr/bin/env python3
"""Verdict and evidence ledger v1 (architecture/verdict-ledger/, MAS-RA-001): reference model, DATA_CHECK_ONLY.

A ledger records one assessment of one subject. Each entry links a claim to the checks that tested it, the checks to the
evidence they cite (content digests), and the claims to their verdicts; the ledger verdict aggregates the claim verdicts.
The model refuses a ledger that breaks a rule and returns the first refusal code in a fixed order (`check_ledger`); it also
derives the ledger status (`aggregate`), its H16 evidence state (`h16_evidence_state`) and checks an append-only history
of ledgers for one subject (`check_history`). Standard library only, so any consumer can run it without jsonschema;
`ledger.schema.json` states the same closed shape for schema-based consumers.

Owner decisions (2026-10-13, via the lane monitor): Q-MAS1-A (a) UNRESOLVED maps to the H16 evidence state WARN and stays its
own ledger value; Q-MAS1-B (a) an internal contract candidate, no H16 change; Q-MAS1-C (a) the producing context's identity
and role are modelled and a verdict from the generating context is refused; signing stays with H16's evidence signer.
"""
from __future__ import annotations

import hashlib
import json
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
LEDGER_KEYS = ("schemaVersion", "ledgerId", "subject", "contexts", "claims", "checks", "evidence", "claimVerdicts",
               "verdict", "supersedes")
# The refusal codes, in the order the model applies its rules; the first failing rule is reported.
CODES = ("LEDGER_SHAPE", "DUPLICATE_ID", "UNKNOWN_REFERENCE", "EVIDENCE_KIND_UNKNOWN", "NOT_EVIDENCE",
         "EVIDENCE_KIND_NOT_ALLOWED", "PRODUCER_ROLE_NOT_ALLOWED", "CONTEXTS_NOT_ISOLATED", "ADJUDICATION_NOT_FRESH",
         "GENERATING_CONTEXT_VERDICT", "VERDICT_PRODUCER_ROLE", "DETERMINISTIC_ORDER", "DETERMINISTIC_OVERRIDE",
         "NO_EVIDENCE", "NO_DECIDING_CHECK", "INTERMEDIATE_TARGET", "CONSENSUS_ONLY", "CONSISTENCY_ONLY",
         "VALUE_NOT_ESTABLISHED",
         "EVIDENCE_REF_UNBOUND", "UNRESOLVED_CHECKS_MISMATCH", "UNRESOLVED_PROMOTED", "STATUS_MISMATCH")
HISTORY_CODES = ("HISTORY_SHAPE", "HISTORY_SUBJECT", "HISTORY_BROKEN")


class Refused(ValueError):
    """A ledger or history breaks a rule; `code` is one of CODES or HISTORY_CODES."""

    def __init__(self, code: str):
        super().__init__(code)
        self.code = code


def _refuse(ok: bool, code: str) -> None:
    if not ok:
        raise Refused(code)


def canonical(value) -> bytes:
    return json.dumps(value, sort_keys=True, ensure_ascii=False, separators=(",", ":"), allow_nan=False).encode("utf-8")


def digest(value) -> str:
    return "sha256:" + hashlib.sha256(canonical(value)).hexdigest()


def _text(value, limit: int = 1024) -> bool:
    return type(value) is str and 0 < len(value) <= limit


def _ident(value) -> bool:
    return type(value) is str and IDENT.match(value) is not None


def _ids(value) -> bool:
    return (type(value) is list and len(value) <= MAX_ITEMS and all(_ident(v) for v in value)
            and len(value) == len(set(value)))


def _closed(value, keys, optional=()) -> bool:
    return type(value) is dict and set(keys) <= set(value) <= set(keys) | set(optional)


def _shape(doc, kinds) -> None:
    """The closed shape (the same constraints as ledger.schema.json)."""
    roles = kinds["contextRoles"]
    ok = (_closed(doc, LEDGER_KEYS) and doc["schemaVersion"] == SCHEMA and _ident(doc["ledgerId"])
          and _closed(doc["subject"], ("scopeDigest",)) and type(doc["subject"]["scopeDigest"]) is str
          and DIGEST.match(doc["subject"]["scopeDigest"]) is not None
          and (doc["supersedes"] is None or (type(doc["supersedes"]) is str and DIGEST.match(doc["supersedes"]) is not None)))
    _refuse(ok, "LEDGER_SHAPE")
    for name in ("contexts", "claims", "checks", "evidence", "claimVerdicts"):
        _refuse(type(doc[name]) is list and 0 < len(doc[name]) <= MAX_ITEMS, "LEDGER_SHAPE")
    for c in doc["contexts"]:
        _refuse(_closed(c, ("contextId", "role", "inheritsFrom")) and _ident(c["contextId"]) and c["role"] in roles
                and _ids(c["inheritsFrom"]), "LEDGER_SHAPE")
    for c in doc["claims"]:
        _refuse(_closed(c, ("claimId", "requirement", "values")) and _ident(c["claimId"]) and _text(c["requirement"])
                and type(c["values"]) is list and 0 < len(c["values"]) <= MAX_ITEMS, "LEDGER_SHAPE")
        for v in c["values"]:
            _refuse(_closed(v, ("rollout", "value")) and _ident(v["rollout"]) and _text(v["value"]), "LEDGER_SHAPE")
        _refuse(len({v["rollout"] for v in c["values"]}) == len(c["values"]), "LEDGER_SHAPE")
    for k in doc["checks"]:
        _refuse(_closed(k, ("checkId", "claimId", "kind", "sequence", "target", "contextId", "outcome", "evidence"),
                        ("establishedValue",))
                and _ident(k["checkId"]) and _ident(k["claimId"]) and type(k["kind"]) is str
                and type(k["sequence"]) is int and 0 < k["sequence"] <= 1_000_000 and k["target"] in TARGETS
                and _ident(k["contextId"]) and k["outcome"] in OUTCOMES and _ids(k["evidence"])
                and ("establishedValue" not in k or _text(k["establishedValue"])), "LEDGER_SHAPE")
    for e in doc["evidence"]:
        _refuse(_closed(e, ("evidenceId", "kind", "contentDigest", "producedBy")) and _ident(e["evidenceId"])
                and type(e["kind"]) is str and type(e["contentDigest"]) is str
                and DIGEST.match(e["contentDigest"]) is not None and _ident(e["producedBy"]), "LEDGER_SHAPE")
    for v in doc["claimVerdicts"]:
        _refuse(_closed(v, ("claimId", "verdict", "checks"), ("value",)) and _ident(v["claimId"])
                and v["verdict"] in CLAIM_VERDICTS and _ids(v["checks"])
                and ("value" not in v or _text(v["value"])), "LEDGER_SHAPE")
    verdict = doc["verdict"]
    _refuse(_closed(verdict, ("status", "producedBy", "evidenceRefs", "policyViolations", "unresolvedChecks", "scores"))
            and verdict["status"] in STATUSES and _ident(verdict["producedBy"])
            and type(verdict["evidenceRefs"]) is list and len(verdict["evidenceRefs"]) <= MAX_ITEMS
            and all(type(r) is str and DIGEST.match(r) is not None for r in verdict["evidenceRefs"])
            and len(set(verdict["evidenceRefs"])) == len(verdict["evidenceRefs"])
            and type(verdict["policyViolations"]) is list and len(verdict["policyViolations"]) <= MAX_ITEMS
            and all(_closed(p, ("policyId", "evidenceId")) and _ident(p["policyId"]) and _ident(p["evidenceId"])
                    for p in verdict["policyViolations"])
            and _ids(verdict["unresolvedChecks"])
            and type(verdict["scores"]) is dict and len(verdict["scores"]) <= 64
            and all(_ident(n) and type(s) in (int, float) and type(s) is not bool for n, s in verdict["scores"].items()),
            "LEDGER_SHAPE")


def _unique(rows, key) -> dict:
    index = {}
    for row in rows:
        _refuse(row[key] not in index, "DUPLICATE_ID")
        index[row[key]] = row
    return index


def aggregate(claim_verdicts: list, policy_violations: list, unresolved_checks: list) -> str:
    """The ledger status the claim verdicts determine: FAIL if a claim is contradicted or a policy is violated; otherwise
    UNRESOLVED if a claim or a check is unresolved; otherwise PASS. Scores never take part."""
    verdicts = [v["verdict"] for v in claim_verdicts]
    if "CONTRADICTED" in verdicts or policy_violations:
        return "FAIL"
    if "UNRESOLVED" in verdicts or unresolved_checks:
        return "UNRESOLVED"
    return "PASS"


def h16_evidence_state(status: str, kinds: dict) -> str:
    """The H16 evidence state of a ledger status (owner decision Q-MAS1-A: UNRESOLVED is WARN, which blocks promotion)."""
    return kinds["h16EvidenceState"][status]


def check_ledger(doc: dict, kinds: dict) -> dict:
    """Refuse a ledger that breaks a rule (Refused with the first failing code); otherwise return its derived facts."""
    try:
        return _check_ledger(doc, kinds)
    except (KeyError, TypeError, AttributeError, IndexError) as exc:
        raise Refused("LEDGER_SHAPE") from exc


def _check_ledger(doc: dict, kinds: dict) -> dict:
    _shape(doc, kinds)
    contexts = _unique(doc["contexts"], "contextId")
    claims = _unique(doc["claims"], "claimId")
    checks = _unique(doc["checks"], "checkId")
    evidence = _unique(doc["evidence"], "evidenceId")
    verdicts = _unique(doc["claimVerdicts"], "claimId")
    _refuse(len({k["sequence"] for k in doc["checks"]}) == len(doc["checks"]), "DUPLICATE_ID")
    check_kinds = {row["kind"]: row for row in kinds["checkKinds"]}

    # References: every named claim, check, evidence and context exists; every claim has exactly one verdict.
    _refuse(all(set(c["inheritsFrom"]) <= set(contexts) and c["contextId"] not in c["inheritsFrom"]
                for c in contexts.values()), "UNKNOWN_REFERENCE")
    _refuse(all(k["claimId"] in claims and k["contextId"] in contexts and set(k["evidence"]) <= set(evidence)
                for k in checks.values()), "UNKNOWN_REFERENCE")
    _refuse(all(e["producedBy"] in contexts for e in evidence.values()), "UNKNOWN_REFERENCE")
    _refuse(set(verdicts) == set(claims), "UNKNOWN_REFERENCE")
    _refuse(all(set(v["checks"]) <= set(checks) and all(checks[c]["claimId"] == v["claimId"] for c in v["checks"])
                for v in verdicts.values()), "UNKNOWN_REFERENCE")
    verdict = doc["verdict"]
    _refuse(verdict["producedBy"] in contexts and set(verdict["unresolvedChecks"]) <= set(checks)
            and all(p["evidenceId"] in evidence for p in verdict["policyViolations"]), "UNKNOWN_REFERENCE")
    _refuse(all(k["kind"] in check_kinds for k in checks.values()), "UNKNOWN_REFERENCE")

    # Evidence kinds: closed registry; model confidence and self-reported status are never evidence.
    for e in evidence.values():
        _refuse(e["kind"] in kinds["evidenceKinds"] or e["kind"] in kinds["notEvidence"], "EVIDENCE_KIND_UNKNOWN")
        _refuse(e["kind"] not in kinds["notEvidence"], "NOT_EVIDENCE")
    for k in checks.values():
        row = check_kinds[k["kind"]]
        _refuse(all(evidence[e]["kind"] in row["evidenceKinds"] for e in k["evidence"]), "EVIDENCE_KIND_NOT_ALLOWED")
        _refuse(contexts[k["contextId"]]["role"] in row["producerRoles"], "PRODUCER_ROLE_NOT_ALLOWED")
        _refuse("establishedValue" not in k or row["establishesValue"], "VALUE_NOT_ESTABLISHED")

    # Context isolation: no checking context inherits the generator's context; resolver and challenger contexts do not
    # inherit each other; an adjudicator starts fresh; the verdict never comes from the generating context.
    role = {c: contexts[c]["role"] for c in contexts}
    for c in contexts.values():
        inherited = {role[i] for i in c["inheritsFrom"]}
        if c["role"] != "GENERATOR":
            _refuse("GENERATOR" not in inherited, "CONTEXTS_NOT_ISOLATED")
        if c["role"] == "RESOLVER":
            _refuse("CHALLENGER" not in inherited, "CONTEXTS_NOT_ISOLATED")
        if c["role"] == "CHALLENGER":
            _refuse("RESOLVER" not in inherited, "CONTEXTS_NOT_ISOLATED")
        if c["role"] == "ADJUDICATOR":
            _refuse(c["inheritsFrom"] == [], "ADJUDICATION_NOT_FRESH")
    _refuse(role[verdict["producedBy"]] != "GENERATOR", "GENERATING_CONTEXT_VERDICT")
    _refuse(role[verdict["producedBy"]] in kinds["verdictProducerRoles"], "VERDICT_PRODUCER_ROLE")

    # Deterministic first: on each claim every deterministic check precedes every model-based check, and a deterministic
    # FAIL is never overridden.
    for claim_id in claims:
        own = [k for k in checks.values() if k["claimId"] == claim_id]
        det = [k["sequence"] for k in own if check_kinds[k["kind"]]["deterministic"]]
        prob = [k["sequence"] for k in own if not check_kinds[k["kind"]]["deterministic"]]
        _refuse(not det or not prob or max(det) < min(prob), "DETERMINISTIC_ORDER")
        if any(check_kinds[k["kind"]]["deterministic"] and k["outcome"] == "FAIL" and k["target"] == "DELIVERED"
               for k in own):
            _refuse(verdicts[claim_id]["verdict"] == "CONTRADICTED", "DETERMINISTIC_OVERRIDE")

    # Claim verdicts: a settled verdict cites checks with evidence on the delivered quantity, more than agreement among
    # rollouts or a matching recomputation, and more than a green regression run without a reproducer.
    not_confirmation, consistency_only = set(kinds["notConfirmation"]), set(kinds["consistencyOnly"])
    for v in verdicts.values():
        if v["verdict"] == "UNRESOLVED":
            _refuse("value" not in v, "VALUE_NOT_ESTABLISHED")
            continue
        cited = [checks[c] for c in v["checks"]]
        _refuse(cited and all(k["evidence"] for k in cited), "NO_EVIDENCE")
        wanted = "FAIL" if v["verdict"] == "CONTRADICTED" else "PASS"
        deciding = [k for k in cited if k["outcome"] == wanted]
        _refuse(bool(deciding), "NO_DECIDING_CHECK")
        _refuse(any(k["target"] == "DELIVERED" for k in deciding), "INTERMEDIATE_TARGET")
        deciding = [k for k in deciding if k["target"] == "DELIVERED"]
        kinds_cited = {evidence[e]["kind"] for k in deciding for e in k["evidence"]}
        _refuse(bool(kinds_cited - not_confirmation), "CONSENSUS_ONLY")
        if v["verdict"] != "CONTRADICTED":   # a green regression run alone is consistency, not confirmation
            _refuse(not (kinds_cited - not_confirmation) <= consistency_only, "CONSISTENCY_ONLY")
        if v["verdict"] == "NEW_VALUE_ESTABLISHED":
            _refuse("value" in v and any(check_kinds[k["kind"]]["establishesValue"] and k.get("establishedValue") == v["value"]
                                         for k in deciding), "VALUE_NOT_ESTABLISHED")
        else:
            _refuse("value" not in v, "VALUE_NOT_ESTABLISHED")

    # The verdict's evidence references are exactly the digests of the evidence its settled claim verdicts rely on; a
    # PASS or FAIL needs at least one.
    relied = sorted({evidence[e]["contentDigest"] for v in verdicts.values() if v["verdict"] != "UNRESOLVED"
                     for c in v["checks"] for e in checks[c]["evidence"]}
                    | {evidence[p["evidenceId"]]["contentDigest"] for p in verdict["policyViolations"]})
    _refuse(sorted(verdict["evidenceRefs"]) == relied, "EVIDENCE_REF_UNBOUND")
    _refuse(verdict["status"] == "UNRESOLVED" or relied, "NO_EVIDENCE")
    inconclusive = sorted(k["checkId"] for k in checks.values() if k["outcome"] == "INCONCLUSIVE")
    _refuse(sorted(verdict["unresolvedChecks"]) == inconclusive, "UNRESOLVED_CHECKS_MISMATCH")

    status = aggregate(doc["claimVerdicts"], verdict["policyViolations"], verdict["unresolvedChecks"])
    _refuse(not (verdict["status"] == "PASS" and status == "UNRESOLVED"), "UNRESOLVED_PROMOTED")
    _refuse(verdict["status"] == status, "STATUS_MISMATCH")
    return {"status": status, "h16EvidenceState": h16_evidence_state(status, kinds), "ledgerDigest": digest(doc)}


def check_history(ledgers: list, kinds: dict) -> list:
    """An append-only history for one subject: every ledger is valid, the subject never changes, the first supersedes
    nothing and each later one supersedes exactly the digest of the one before it, so an edited earlier ledger breaks the
    chain. Returns the derived facts in order."""
    _refuse(type(ledgers) is list and 0 < len(ledgers) <= MAX_ITEMS, "HISTORY_SHAPE")
    facts, previous = [], None
    for doc in ledgers:
        result = check_ledger(doc, kinds)
        if previous is None:
            _refuse(doc["supersedes"] is None, "HISTORY_BROKEN")
        else:
            _refuse(doc["subject"] == previous["subject"], "HISTORY_SUBJECT")
            _refuse(doc["supersedes"] == digest(previous), "HISTORY_BROKEN")
        facts.append(result)
        previous = doc
    return facts


if __name__ == "__main__":
    from pathlib import Path

    root = Path(__file__).resolve().parents[1]
    kinds = json.loads((root / "architecture/verdict-ledger/check-kinds.json").read_bytes())
    vectors = json.loads((root / "architecture/verdict-ledger/vectors.json").read_bytes())
    for row in vectors["ledgers"]:
        try:
            check_ledger(row["ledger"], kinds)
            got = None
        except Refused as refusal:
            got = refusal.code
        assert got == row["expect"], (row["id"], got, row["expect"])
    print("verdict ledger vectors replay:", len(vectors["ledgers"]), "ledgers")
