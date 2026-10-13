# Verdict and evidence ledger v1 (MAS-RA-001)

Alpha 2; 2026-10-13. Status: **CONTRACT_CANDIDATE_ROUND1_AWAITING_INDEPENDENT_REVIEW**. DATA_CHECK_ONLY: an internal contract
candidate with a schema, a reference model and vectors. It changes no public contract, selector, catalog or runtime, and it
leaves H16's harness document (`docs/harnesses/trust.evaluation-assurance.md`) and the repository schemas byte-identical.

The ledger is the record an assurance run keeps when it judges claims about a subject: which claims it tested, which checks
it ran, what evidence each check cites and what it concluded. It is the contract the three MAS-harness research syntheses
agree on for the assurance plane (crosswalk `architecture/research-adoption-v2/crosswalk.json`, item MAS-RA-001, acceptance
IDs MAS-RA-001-A1 to -A3; layer L4; principle P3 "evidence over consensus").

## Files

| File | Content |
|---|---|
| `ledger.schema.json` | Draft 2020-12 schema `planeon.internal.verdict-ledger/v1`: the closed shape of one ledger |
| `check-kinds.json` | `planeon.internal.verdict-check-kinds/v1`: the context roles, the check-kind registry, the evidence kinds, what is not evidence, what is not confirmation, what is consistency only, and the H16 evidence state of each ledger status |
| `vectors.json` | 46 ledger vectors (7 valid, 39 refused, every refusal code at least once), 4 history vectors and 5 aggregation rows, each with its exact expected result |
| `../../scripts/verdict_ledger.py` | Reference model, standard library only: `check_ledger`, `aggregate`, `h16_evidence_state`, `check_history` |

The model needs no third-party package, so any consumer can run it (R12 cannot load jsonschema today); the schema states the
same closed shape for schema-based consumers, and every vector is checked against both.

## The ledger

One ledger per assessment of one subject. `subject.scopeDigest` is the digest of the H16 evidence scope tuple (tenant,
profile, bundle, route and subject digests); the ledger never widens it.

| Part | Fields | Meaning |
|---|---|---|
| Contexts | `contextId`, `role`, `inheritsFrom` | Who produced what: GENERATOR, VERIFIER, RESOLVER, CHALLENGER, ADJUDICATOR, EVALUATOR; `inheritsFrom` lists the contexts whose history a context carries |
| Claims | `claimId`, `requirement`, `values` | A requirement and the value each rollout delivered for it; an omission is the explicit value `ABSENT` |
| Checks | `checkId`, `claimId`, `kind`, `sequence`, `target`, `contextId`, `outcome`, `evidence`, optional `establishedValue` | One check of one claim: its registered kind, its order, whether it targets the DELIVERED quantity or an INTERMEDIATE one, its producer, PASS, FAIL or INCONCLUSIVE, and the evidence it cites |
| Evidence | `evidenceId`, `kind`, `contentDigest`, `producedBy` | Content-addressed evidence; the ledger holds digests, never the content |
| Claim verdicts | `claimId`, `verdict`, `checks`, optional `value` | SUPPORTED, CONTRADICTED, NEW_VALUE_ESTABLISHED (with the value) or UNRESOLVED, and the checks it rests on |
| Verdict | `status`, `producedBy`, `evidenceRefs`, `policyViolations`, `unresolvedChecks`, `scores` | PASS, FAIL or UNRESOLVED; the digests it relies on; violated policies with their evidence; the inconclusive checks; informational scores |
| `supersedes` | a ledger digest or null | The previous ledger of the same subject (append-only history) |

## Rules

Each rule is enforced by the model, has refusal vectors, and is grounded in the source papers (pages from the crosswalk):

1. **No verdict without evidence.** A settled claim verdict cites checks that cite evidence; a PASS or FAIL lists exactly the
   digests its settled claims and its policy violations rely on (NO_EVIDENCE, EVIDENCE_REF_UNBOUND).
2. **UNRESOLVED is legitimate and never becomes PASS.** Insufficient evidence leaves a claim UNRESOLVED; an unresolved claim
   or an inconclusive check keeps the ledger from PASS whatever its scores (UNRESOLVED_PROMOTED, UNRESOLVED_CHECKS_MISMATCH).
3. **Confidence is not evidence.** Model-reported confidence and self-reported status are refused as evidence
   (NOT_EVIDENCE; HarnessDev pp. 6-7, 25, 27).
4. **Deterministic first.** On each claim every deterministic check (test, schema, policy) runs before any model-based check,
   and a deterministic FAIL on the delivered quantity makes the claim CONTRADICTED; no model-based result overrides it
   (DETERMINISTIC_ORDER, DETERMINISTIC_OVERRIDE; H13's rule; HERMES pp. 15, 21-22, 29).
5. **Isolated contexts.** No checking context inherits the generator's history; resolver and challenger contexts do not
   inherit each other; an adjudicator starts fresh; a verdict produced by the generating context is refused, and only an
   ADJUDICATOR or EVALUATOR produces one (CONTEXTS_NOT_ISOLATED, ADJUDICATION_NOT_FRESH, GENERATING_CONTEXT_VERDICT,
   VERDICT_PRODUCER_ROLE; VeriHarness pp. 6, 10, 20-21). Signing stays with H16's evidence signer (owner decision Q-MAS1-C).
6. **Consensus is not correctness.** Agreement among rollouts and a recomputation that matches the pool are not confirmation;
   a claim supported only by them is refused (CONSENSUS_ONLY). The disagreement resolver and the consensus challenger are
   named, optional check kinds with their own evidence (VeriHarness pp. 2, 4, 19: 34% of unanimous claims wrong and 74% of
   disagreements containing a correct candidate, measured with Claude Opus 4.8 on APEX-Agents).
7. **Check the delivered quantity.** A claim settled only by a check of an upstream intermediate is refused
   (INTERMEDIATE_TARGET; VeriHarness pp. 10-11, 27).
8. **A green regression run is consistency, not confirmation.** It confirms only together with a failing-to-passing
   reproducer or other confirming evidence (CONSISTENCY_ONLY; HERMES).
9. **New values come from evidence.** NEW_VALUE_ESTABLISHED needs a check whose kind can establish a value and whose
   established value equals the claim's; other verdicts carry no value (VALUE_NOT_ESTABLISHED; VeriHarness pp. 3, 5-6, 12).
10. **Append-only.** A re-run is a new ledger that supersedes the previous one by digest; an earlier ledger is never edited,
    and an edit breaks the chain (`check_history`: HISTORY_BROKEN, HISTORY_SUBJECT).

Refusal codes, in the order the model applies them (the first failing rule is reported): `LEDGER_SHAPE`, `DUPLICATE_ID`,
`UNKNOWN_REFERENCE`, `EVIDENCE_KIND_UNKNOWN`, `NOT_EVIDENCE`, `EVIDENCE_KIND_NOT_ALLOWED`, `PRODUCER_ROLE_NOT_ALLOWED`,
`CONTEXTS_NOT_ISOLATED`, `ADJUDICATION_NOT_FRESH`, `GENERATING_CONTEXT_VERDICT`, `VERDICT_PRODUCER_ROLE`,
`DETERMINISTIC_ORDER`, `DETERMINISTIC_OVERRIDE`, `NO_EVIDENCE`, `NO_DECIDING_CHECK`, `INTERMEDIATE_TARGET`, `CONSENSUS_ONLY`,
`CONSISTENCY_ONLY`, `VALUE_NOT_ESTABLISHED`, `EVIDENCE_REF_UNBOUND`, `UNRESOLVED_CHECKS_MISMATCH`, `UNRESOLVED_PROMOTED`,
`STATUS_MISMATCH`.

## Check-kind registry

| Kind | Deterministic | Optional | Producer roles | Evidence kinds | Establishes a value |
|---|---|---|---|---|---|
| DETERMINISTIC_TEST | yes | no | VERIFIER, EVALUATOR | TEST_RESULT, REPRODUCER, REGRESSION_RUN | yes |
| DETERMINISTIC_SCHEMA | yes | no | VERIFIER, EVALUATOR | SCHEMA_RESULT | no |
| DETERMINISTIC_POLICY | yes | no | VERIFIER, EVALUATOR | POLICY_RESULT | no |
| MODEL_BASED_WITH_EVIDENCE | no | no | VERIFIER | ARTIFACT, TRACE, DIFF, ENVIRONMENT_STATE, DOCUMENT_EXTRACT, ROLLOUT_AGREEMENT, POOL_RECOMPUTATION | no |
| DISAGREEMENT_RESOLVER | no | yes | RESOLVER | ARTIFACT, TRACE, DIFF, ENVIRONMENT_STATE, DOCUMENT_EXTRACT, TEST_RESULT | yes |
| CONSENSUS_CHALLENGER | no | yes | CHALLENGER | ARTIFACT, TRACE, DIFF, ENVIRONMENT_STATE, DOCUMENT_EXTRACT, TEST_RESULT | no |
| ADJUDICATION | no | no | ADJUDICATOR | ARTIFACT, TRACE, DIFF, ENVIRONMENT_STATE, DOCUMENT_EXTRACT, TEST_RESULT, RESOLVER_REPORT, CHALLENGER_REPORT | yes |

Not evidence: MODEL_CONFIDENCE, SELF_REPORTED_STATUS. Not confirmation: ROLLOUT_AGREEMENT, POOL_RECOMPUTATION. Consistency
only: REGRESSION_RUN.

## Status and H16

The ledger status is FAIL if a claim is contradicted or a policy is violated, otherwise UNRESOLVED if a claim or a check is
unresolved, otherwise PASS; scores never take part (`aggregate`). In H16 terms (owner decision Q-MAS1-A): PASS is PASS, FAIL
is FAIL, and UNRESOLVED is WARN, which H16 already counts as blocking. UNRESOLVED stays its own value in the ledger, so a
consumer can tell insufficient evidence from a failure. H16's states, gates and evidence signer are unchanged; a ledger
becomes H16 evidence only through H16's own signed evidence record.

## Owner decisions (2026-10-13, owner via the lane monitor)

- Q-MAS1-A = (a): UNRESOLVED maps to H16 WARN (blocking, never PASS) and stays its own ledger value; no H16 change.
- Q-MAS1-B = (a): an internal contract candidate under architecture/verdict-ledger/, naming TRUST-EVAL-ADOPT-001 (Inspect AI)
  and R12 as future consumers; no change to H16's harness document or schemas (the I05/I07 pattern).
- Q-MAS1-C = (a): model the producing context's identity and role, refuse a verdict produced by the generating context;
  cryptographic signing stays with H16's evidence signer.

## Consumers (future, not dispatched)

TRUST-EVAL-ADOPT-001 (the Inspect AI adoption) as the first producer of ledgers inside H16 evidence records; R12 campaigns as
independent checkers. pytest stays the deterministic-check engine. MAS-RA-005 (the harness-candidate admission gate) and
MAS-RA-009 (verify-before-admit on the shared board) build on this ledger.

## Not claimed

- No producer, consumer, service or signing path exists; nothing runs a ledger outside the vectors.
- The cited figures are the papers' results, not platform evidence.
- Open items carried: OI-2 (LLM-as-a-Verifier not located; referenced by its paper only), OI-7 (the VeriHarness rollout
  dataset's licence is unchecked; no dataset is used here).
