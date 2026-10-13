# Verdict and evidence ledger v1 (MAS-RA-001)

Alpha 2; 2026-10-13. Status: **CONTRACT_CANDIDATE_ROUND3_AWAITING_INDEPENDENT_REVIEW**. DATA_CHECK_ONLY: an internal contract
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
| `check-kinds.json` | `planeon.internal.verdict-check-kinds/v1`: the context roles, the check-kind registry, the evidence kinds, evidence provenance, what is not evidence, what is not confirmation, what is consistency only, and the H16 evidence state of each ledger status |
| `vectors.json` | 112 ledger vectors (16 valid, 96 refused, every refusal code at least once), 7 raw-text vectors, 8 history vectors, 6 aggregation rows and 2 scope-digest rows, each with its exact expected result |
| `../../scripts/verdict_ledger.py` | Reference model, standard library only: `parse`, `check_text`, `check_ledger`, `aggregate`, `h16_evidence_state`, `check_history`, `canonical`, `digest`, `scope_digest`; run directly, it replays every vector |

The model needs no third-party package, so any consumer can run it (R12 cannot load jsonschema today). The schema states the
same closed shape for schema-based consumers: the model refuses a document as `LEDGER_SHAPE` exactly when the schema rejects
it. Every ledger and text vector is checked against both, and the builder also checks that agreement on every single-node
mutation of the base ledger (874 documents). Uniqueness, references and every later rule are the model's alone. Schema
patterns end with `(?![\s\S])`, which is end of input in both the ECMA-262 and the Python dialect (`$` admits a final
newline in Python). Free text must consist of Unicode scalar values: the pattern accepts any character outside the
surrogate range or a high surrogate followed by a low one, so it refuses a lone surrogate and accepts an astral-plane
character alike in Python, in ECMA-262 with the `u` flag (code points) and without it (UTF-16 code units; checked in node
24, vector L14). Agreement is stated for parsed JSON text; a Python string holding a surrogate pair as two code points cannot
come from a JSON parser.

Each refused vector that a rule pass reports also records `withoutOwnRule`, the model's result with that pass disabled:
`null` for 58 of the 76, so the vector shows that its own rule refuses it; for the other 18 it names the later rule that the
same defect also breaks (for example a check produced by the generating context also cites evidence its context did not
produce), or, for a vector with two violations, the second one.

## The ledger

One ledger per assessment of one **subject**: the delivered artifact under assessment, identified by H16's evidence scope
tuple. The subject may be one rollout of a pool or a revised delivery; the ledger records the value the subject delivers for
every claim beside the value every rollout of the pool gave, and check outcomes are about the delivered value.

| Part | Fields | Meaning |
|---|---|---|
| Subject | `subject.scopeDigest` | The digest (below) of H16's scope tuple `(tenantId, profileDigest, bundleDigest, routeId, routeDigest, subjectType, subjectId, subjectVersion, subjectDigest)` as one JSON object with exactly those nine members; the ledger never widens it |
| Rollouts | `rollouts` | The rollout pool's IDs (possibly none); every claim lists exactly these |
| Contexts | `contextId`, `role`, `inheritsFrom` | Who produced what: GENERATOR, VERIFIER, RESOLVER, CHALLENGER, ADJUDICATOR, EVALUATOR; `inheritsFrom` lists the contexts whose history a context carries |
| Claims | `claimId`, `requirement`, `delivered`, `rolloutValues` | A requirement, the value the subject delivers for it, and each rollout's value; an omission is the explicit value `ABSENT` |
| Checks | `checkId`, `claimId`, `kind`, `sequence`, `target`, `contextId`, `outcome`, `evidence`, optional `establishedValue` | One check of one claim: its registered kind, its order, whether it targets the DELIVERED quantity or an upstream INTERMEDIATE one, its producing context, and the evidence it cites. PASS supports the delivered value, FAIL contradicts it, INCONCLUSIVE does neither |
| Evidence | `evidenceId`, `kind`, `contentDigest`, `producedBy` | Content-addressed evidence; the ledger holds digests, never the content. One content digest is one evidence row, so a check result names its producing context and run in its content (two contexts' results never share a digest) |
| Claim verdicts | `claimId`, `verdict`, `checks`, optional `value` | SUPPORTED (the delivered value is right), CONTRADICTED (it is wrong), NEW_VALUE_ESTABLISHED (it is wrong and evidence establishes `value`, a correction absent from the pool) or UNRESOLVED; `checks` lists every check of the claim |
| Verdict | `status`, `producedBy`, `evidenceRefs`, `policyViolations`, `unresolvedChecks`, `scores` | PASS, FAIL or UNRESOLVED; the digests it relies on; violated policies with their POLICY_RESULT evidence; the inconclusive checks; informational integer scores (0 to 1,000,000) |
| `supersedes` | a ledger digest or null | The previous ledger of the same subject (append-only history) |

**Text, canonical form and digests.** Ledger text is I-JSON (RFC 7493): UTF-8, no duplicate member names, no NaN or
infinity. `parse` reads it and refuses anything else as `LEDGER_SHAPE` (vectors T06-T07: a parser that keeps the last of two
duplicate members would read L01 and its digest, one that keeps the first another ledger; neither may read it), and
`check_text` is `parse` followed by `check_ledger`. `digest(x)` is `sha256:` and the lowercase hex SHA-256 of the RFC 8785 (JCS) serialization
of `x`. Ledgers contain only strings, integers, null, arrays and objects (no boolean, no fraction); a number is an integer (an
integral JSON number such as `92.0` is the integer 92 and serializes as `92`; a fraction, NaN or an infinity is refused). On
that value space RFC 8785 is the sorted-key, whitespace-free, non-ASCII-preserving JSON every language produces (all member
names are ASCII), which is what the model computes. `supersedes` is the digest of the previous ledger as a whole;
`subject.scopeDigest` is the digest of the nine-member scope object (rows D01-D02).

## Rules

Each rule is enforced by the model and has refusal vectors; the grounding pages are the source papers' (crosswalk pages
checked in review round 1).

1. **No verdict without evidence.** A settled claim verdict accounts for every check of its claim and rests on checks that
   cite evidence; a PASS or FAIL lists exactly the digests its settled claims and policy violations rely on (CHECK_OMITTED,
   NO_EVIDENCE, EVIDENCE_REF_UNBOUND; VeriHarness pp. 6, 12: every record entry links claim, check, evidence and verdict).
   NO_EVIDENCE's ledger-level clause (a PASS or FAIL whose settled claims and policy violations rely on no digest, whatever
   it declares) is defence in depth: such a ledger also fails EVIDENCE_REF_UNBOUND, UNRESOLVED_PROMOTED or STATUS_MISMATCH.
2. **UNRESOLVED is legitimate and never becomes PASS.** Insufficient evidence leaves a claim UNRESOLVED; an unresolved claim
   or an inconclusive check keeps the ledger from PASS whatever its scores (UNRESOLVED_CHECKS_MISMATCH, UNRESOLVED_PROMOTED,
   STATUS_MISMATCH; VeriHarness p.3).
3. **Confidence and self-reports are not evidence.** Model-reported confidence and self-reported status are refused as
   evidence (NOT_EVIDENCE); the confidence rule is the roadmap item's and the syntheses' (MAS-RA-001), the self-report rule
   HarnessDev's (pp. 6-7, 25, 27: credit only from the real diff or final environment state). So a generating context produces
   only subject outputs (ARTIFACT, TRACE, DIFF), never a check result or a report (EVIDENCE_PROVENANCE).
4. **Deterministic first, never overridden.** On each claim every deterministic check (test, schema, policy) runs before any
   model-based check, and a deterministic FAIL, at the delivered quantity or at an intermediate, makes the claim CONTRADICTED
   or NEW_VALUE_ESTABLISHED: never SUPPORTED, never left UNRESOLVED (DETERMINISTIC_ORDER, DETERMINISTIC_OVERRIDE; H13's rule
   "a probabilistic detector cannot override a deterministic denial"; HERMES pp. 15, 21-22).
5. **Isolated contexts, traceable provenance.** Over the transitive closure of `inheritsFrom`: no cycle; a generator
   inherits only generators; no context but a generator inherits a generator's history; resolver and challenger contexts
   never inherit each other; nobody inherits a verdict producer; and every verdict producer (ADJUDICATOR, EVALUATOR) starts
   fresh, so generator, verifier and evaluator contexts are isolated (CONTEXTS_NOT_ISOLATED, CONTEXT_NOT_FRESH). A check
   cites subject outputs produced by a generating context or by its own context, reports of its registered kinds (a
   RESOLVER_REPORT from a resolver context, a CHALLENGER_REPORT from a challenger context, a VERIFIER_REPORT from a verifier
   or evaluator context; only ADJUDICATION cites them), and any other kind only when its own context produced it
   (EVIDENCE_PROVENANCE). So a resolver never reads the challenger's record nor the reverse, directly or through a generator
   that carries one's history into an output the other cites. A ledger's generator outputs are its subject, fixed before
   any check: a revised delivery (for example one continued in an adjudication context, VeriHarness p.21) is a new subject
   with its own scope tuple (a new subjectVersion and subjectDigest), assessed in its own ledger and history. Each check kind has
   its producer roles (PRODUCER_ROLE_NOT_ALLOWED); a verdict produced by the generating context is refused, and only an
   ADJUDICATOR or EVALUATOR produces one (GENERATING_CONTEXT_VERDICT, VERDICT_PRODUCER_ROLE; VeriHarness pp. 6, 10, 20-21).
   Signing stays with H16's evidence signer (owner decision Q-MAS1-C).
6. **Consensus is not correctness; disagreement is adjudicated.** Agreement among rollouts and a recomputation that matches
   the pool are not confirmation: a claim settled only by them is refused (CONSENSUS_ONLY; VeriHarness pp. 2, 4, 19 for 34%
   of unanimous claims wrong and 74% of disagreements containing a correct candidate, measured with Claude Opus 4.8 on
   APEX-Agents; pp. 10-11 for the recomputation). Disagreement is adjudicated once, never averaged and never retried
   (DISAGREEMENT_UNADJUDICATED; VeriHarness p.6: one fresh adjudication upholds, overturns or leaves findings unresolved;
   H16: judge disagreement is never silent averaging). A check conflicts with a settled verdict when it cites evidence and
   has the opposite outcome on the delivered quantity, or is a FAIL at an intermediate. A settled claim with a conflicting
   check needs a deciding ADJUDICATION on the delivered quantity, sequenced after every conflicting check and citing a
   report produced by each one's context (a deterministic FAIL decides without one); competing corrections need such an
   adjudication, reading every other establishing check's context, that establishes the verdict's value. The adjudications
   of one settled claim agree in outcome and established value: a second adjudication that differs, by another adjudicator
   or the same one, makes the disagreement unadjudicated, and a re-adjudication belongs in a successor ledger. The disagreement resolver and the consensus challenger are named, optional check
   kinds with their own evidence.
7. **Check the delivered quantity.** A claim confirmed only by checks of an upstream intermediate is refused; a deterministic
   FAIL decides wherever it was observed, and a model-based FAIL at an intermediate is a conflict to adjudicate (rule 6)
   (INTERMEDIATE_TARGET; VeriHarness pp. 10-11, 27).
8. **A green regression run is consistency, not confirmation.** When a supported claim's deterministic support is only
   regression runs, another kind of deterministic evidence must be among it: a failing-to-passing reproducer, or a test,
   schema or policy result on the delivered quantity. A model reading the diff does not substitute (CONSISTENCY_ONLY; HERMES
   p.29: a PASS from a green regression run with every reproducer discarded means consistent, not independently certified).
9. **Values are bound to the delivered value.** SUPPORTED means the delivered value; an `establishedValue` comes only from a
   check kind that can establish one and only on the delivered quantity (an intermediate is another quantity), equals the
   delivered value on a PASS and differs from it on a FAIL, and never appears on an INCONCLUSIVE check. NEW_VALUE_ESTABLISHED carries a value that is not `ABSENT`, is absent from the pool (every rollout
   value and the delivered value; a correction found in the pool is CONTRADICTED) and is established by a deciding check on
   the delivered quantity; no other verdict carries a value. Every claim lists exactly the ledger's rollouts, with `ABSENT`
   for an omission (VALUE_NOT_ESTABLISHED, ROLLOUT_SET; VeriHarness pp. 3, 5-6, 12, 19). The resolver and adjudication can
   establish a value, the challenger cannot: a challenger's correction travels as a CHALLENGER_REPORT and is established by
   the fresh ADJUDICATION that weighs it (VeriHarness p.4, Figure 3, and p.6).
10. **Append-only.** A re-run is a new ledger with its own ID that supersedes the previous one by digest; an earlier ledger is
    never edited, and an edit breaks the chain (`check_history`: HISTORY_SHAPE, HISTORY_SUBJECT, HISTORY_ID_REUSED,
    HISTORY_BROKEN; a refused member ledger reports its own code). The newest ledger is bound only once a successor or H16's
    signed evidence record names its digest.

**Order of refusal codes.** The model checks the shape, then uniqueness, then references, then applies each later rule to
the whole ledger before the next, in this order, and reports the first failing code, so a ledger that breaks several rules
always reports the earliest (the two-violation vectors pin it): `LEDGER_SHAPE`, `DUPLICATE_ID`, `UNKNOWN_REFERENCE`,
`ROLLOUT_SET`, `CHECK_OMITTED`, `EVIDENCE_KIND_UNKNOWN`, `NOT_EVIDENCE`, `EVIDENCE_KIND_NOT_ALLOWED`,
`PRODUCER_ROLE_NOT_ALLOWED`, `EVIDENCE_PROVENANCE`, `CONTEXTS_NOT_ISOLATED`, `CONTEXT_NOT_FRESH`,
`GENERATING_CONTEXT_VERDICT`, `VERDICT_PRODUCER_ROLE`, `DETERMINISTIC_ORDER`, `DETERMINISTIC_OVERRIDE`, `NO_EVIDENCE`,
`NO_DECIDING_CHECK`, `INTERMEDIATE_TARGET`, `CONSENSUS_ONLY`, `CONSISTENCY_ONLY`, `DISAGREEMENT_UNADJUDICATED`,
`VALUE_NOT_ESTABLISHED`, `EVIDENCE_REF_UNBOUND`, `UNRESOLVED_CHECKS_MISMATCH`, `UNRESOLVED_PROMOTED`, `STATUS_MISMATCH`.
`check_ledger` and `check_text` raise nothing but these refusals: any malformed input, including NaN, an infinity, a lone
surrogate or a duplicate member name (the raw-text vectors T01-T07), is `LEDGER_SHAPE`.

## Check-kind registry

| Kind | Deterministic | Optional | Producer roles | Evidence kinds | Establishes a value |
|---|---|---|---|---|---|
| DETERMINISTIC_TEST | yes | no | VERIFIER, EVALUATOR | TEST_RESULT, REPRODUCER, REGRESSION_RUN | yes |
| DETERMINISTIC_SCHEMA | yes | no | VERIFIER, EVALUATOR | SCHEMA_RESULT | no |
| DETERMINISTIC_POLICY | yes | no | VERIFIER, EVALUATOR | POLICY_RESULT | no |
| MODEL_BASED_WITH_EVIDENCE | no | no | VERIFIER | ARTIFACT, TRACE, DIFF, ENVIRONMENT_STATE, DOCUMENT_EXTRACT, ROLLOUT_AGREEMENT, POOL_RECOMPUTATION | no |
| DISAGREEMENT_RESOLVER | no | yes | RESOLVER | ARTIFACT, TRACE, DIFF, ENVIRONMENT_STATE, DOCUMENT_EXTRACT, TEST_RESULT | yes |
| CONSENSUS_CHALLENGER | no | yes | CHALLENGER | ARTIFACT, TRACE, DIFF, ENVIRONMENT_STATE, DOCUMENT_EXTRACT, TEST_RESULT | no |
| ADJUDICATION | no | no | ADJUDICATOR | ARTIFACT, TRACE, DIFF, ENVIRONMENT_STATE, DOCUMENT_EXTRACT, TEST_RESULT, RESOLVER_REPORT, CHALLENGER_REPORT, VERIFIER_REPORT | yes |

Not evidence: MODEL_CONFIDENCE, SELF_REPORTED_STATUS. Not confirmation: ROLLOUT_AGREEMENT, POOL_RECOMPUTATION. Consistency
only: REGRESSION_RUN. Subject outputs (the only kinds a generating context produces): ARTIFACT, TRACE, DIFF. Reports:
RESOLVER_REPORT from a RESOLVER context, CHALLENGER_REPORT from a CHALLENGER context, VERIFIER_REPORT from a VERIFIER or
EVALUATOR context. Policy-violation evidence: POLICY_RESULT.

## Status and H16

The ledger status is FAIL if a claim is contradicted, a new value was established (the delivered subject does not carry the
correct value) or a policy is violated; otherwise UNRESOLVED if a claim or a check is unresolved; otherwise PASS. Scores never
take part (`aggregate`). In H16 terms (owner decision Q-MAS1-A): FAIL is FAIL, UNRESOLVED is WARN, which H16 already counts as
blocking, and PASS is PASS only when every supported claim has a deterministic deciding check on the delivered quantity; a
PASS in which some claim rests on model-based checks alone is WARN, since H16 never lets a model judge be the sole
authority and accompanies model judgments with deterministic checks (`h16_evidence_state`; vector L12). The model counts a
deterministic check as support for the claim it is recorded under and cannot tell a check of a value from a check of its
form, so a producer records a format-only check (a schema check, say) under its own format requirement, not as support for
a value claim. UNRESOLVED stays its own value in the ledger, so a consumer can tell insufficient evidence from a failure.

This mapping gives the state the ledger supports, not H16 evidence. H16's own requirements still apply before a ledger counts:
judge version and calibration evidence for model judgments, the exact scope tuple, freshness, and H16's signed evidence record
from its trusted producer. H16's states, gates and signer are unchanged.

## Owner decisions (2026-10-13, owner via the lane monitor)

- Q-MAS1-A = (a): UNRESOLVED maps to H16 WARN (blocking, never PASS) and stays its own ledger value; no H16 change.
- Q-MAS1-B = (a): an internal contract candidate under architecture/verdict-ledger/, naming TRUST-EVAL-ADOPT-001 (Inspect AI)
  and R12 as future consumers; no change to H16's harness document or schemas (the I05/I07 pattern).
- Q-MAS1-C = (a): model the producing context's identity and role, refuse a verdict produced by the generating context;
  cryptographic signing stays with H16's evidence signer.

## Consumers (future, not dispatched)

TRUST-EVAL-ADOPT-001 (the Inspect AI adoption) as the first producer of ledgers inside H16 evidence records; R12 campaigns as
independent checkers, MAS-RA-010 (the MAS adversarial campaign) among them; CONF-A3-001's outcome review as the first
product consumer. pytest stays the deterministic-check engine. MAS-RA-005 (the harness-candidate admission gate) and
MAS-RA-009 (verify-before-admit on the shared board) build on this ledger.

## Not claimed

- No producer, consumer, service or signing path exists; nothing runs a ledger outside the vectors.
- Context identity and role are declared, not authenticated: one agent could appear under two context IDs, and nothing here
  proves which agent produced a row. Authentication is H16's signer (Q-MAS1-C).
- The information boundary of the grounding (a verifier never sees the grader, the rubric or reference answers; VeriHarness
  pp. 3, 7, 19, 21) is not modelled: the ledger records evidence, not what a context could read.
- Routing between consensus and disputed claims is not modelled: the ledger records the pool's values; deciding which claims
  go to the resolver or the challenger is the producer's.
- The cited figures are the papers' results, not platform evidence.
- Open items carried: OI-2 (LLM-as-a-Verifier not located; referenced by its paper only), OI-7 (the VeriHarness rollout
  dataset's licence is unchecked; no dataset is used here).
