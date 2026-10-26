# ADR 0011: H10 execution authority

Status: Accepted under MET-ADOPT-005 (owner TECH-D1 and Q-TO-6). Narrows OW-D3 for H10 only.
Owner: Harness-Engineering (R00). Date: 2026-10-26.

## Context

At harness-onion ee26624d the H10 harness document (`docs/harnesses/execution.orchestration.md`) named two defaults.
Its planning-target block preferred self-hosted Temporal and froze further PostgreSQL executor expansion, while its own
design sections made PostgreSQL leases and outbox (`planeon.orchestrator.postgres`) the baseline and said no Temporal
provider is selectable. The R08 repository plan names PostgreSQL leases/outbox as the baseline durable executor and
Temporal a separate optional provider module, and the provider catalog has a PostgreSQL record and no Temporal record.
The owner's OW-D3 (2026-10-20) had made each adoption item's baseline its harness document's planning target for H1,
H2 and H4-H16 (H3's is Agent Router), which for H10 meant `temporalio/temporal`. The owner's TECH-D1 (2026-10-26),
after an outside review of the architecture page's tech-stack view, chose "PostgreSQL-native (Recommended)" on the one
point that narrows OW-D3.

## Decision

1. **One execution authority.** For the first enterprise release PostgreSQL owns leases, task transitions,
   checkpoints, timers, retries and outbox coordination, on the tenant-supplied PostgreSQL every profile already
   requires. The PostgreSQL executor (`planeon.orchestrator.postgres`, delivered by `EXEC-ORCH-001`) is H10's
   qualified baseline, held to the roadmap's PI-DURABLE-PARITY-001 vectors, DATA-CORRECTNESS-001's fencing tokens and
   operation IDs and CONTEXT-HANDOFF-001's resume vectors.
2. **Temporal is an optional provider.** Temporal is an optional provider module that `EXEC-TEMPORAL-001` qualifies
   behind the same public task contracts; it is never a second retry or side-effect authority for a task, and it is
   selectable only with a catalog record, a repository packet and conformance evidence, as the H10 design section
   already requires. `temporalio/temporal` stays H10's adopted optional engine, not its default executor.
3. **Build versus integrate.** The owner's Q-TO-6, verbatim:

   > "ADR 0011 is the decision (Recommended)". ADR 0011 records TECH-D1 as the build-versus-integrate decision for H10's baseline only: complete the PostgreSQL executor to the parity, fencing and resume vectors, with no general-purpose engine beyond H10's contracts. Temporal's measured comparison stays in EXEC-TEMPORAL-001's qualification.

   The master plan's rule that a measured build-versus-integrate ADR precedes another general-purpose router, serving,
   workflow, retrieval or evaluation engine stays in force; this decision does not trigger it, because it builds no
   general-purpose engine.
4. **Reuse stays open.** Reusing an open-source PostgreSQL-backed durable-execution library inside the executor stays
   possible under ADR 0008's reuse-first rule if a later candidate record qualifies one; it adds no second authority.

## Superseded planning texts (for H10 only)

The texts below are not edited; they remain the record of what was planned. For H10 this ADR supersedes the part each
row names, and nothing else in its file. Line numbers are positions at ee26624d, for display only; the quoted text is
the binding locator.

| File | Lines at ee26624d | Text | Superseded for H10 |
|---|---|---|---|
| `docs/adr/0008-reuse-first-harness-implementation.md` | 14 | "Temporal self-hosted" | Temporal as a preferred planning target: it is the optional provider |
| `docs/adr/0008-reuse-first-harness-implementation.md` | 27-28 | "keep its bespoke-executor expansion" | the hold on `EXEC-ORCH-001`, for decision 3's baseline scope; the compatibility/migration decision before any Temporal implementation stays required |
| `docs/MASTER_DEVELOPMENT_PLAN.md` | 2578 | "a separately decided Temporal transition" | a Temporal transition: there is none; Temporal is optional |
| `docs/MASTER_DEVELOPMENT_PLAN.md` | 2580 | "The existing PostgreSQL durable-execution source stays historical while R08 decides the Temporal successor, migration, history replay and single side-effect authority." | this sentence only: the PostgreSQL executor is the baseline and the single side-effect authority; the line's measured build-versus-integrate rule stays in force (decision 3) |
| `docs/alpha-2/PROVIDER_ADOPTION_ROADMAP.md` | 400-401 | "Further bespoke durable-executor" | the hold for a separate adoption ADR: this ADR is that decision for the baseline scope; "Temporal is a candidate, not a selected default" stays true |
| `docs/alpha-2/HARNESS_PAPER_REPOSITORY_MAP.md` | 43 | "[temporalio/temporal](https://github.com/temporalio/temporal)" | the H10 row's upstream is the optional provider, not the baseline |
| `docs/alpha-2/HARNESS_PAPER_REPOSITORY_MAP.md` | 163-169 | "Plan self-hosted Temporal as the preferred durable execution engine." | the H10 section's preference, its freeze and "**Later coverage:** Temporal durable baseline"; the H10 document's block now holds H10's direction |
| `docs/alpha-2/HARNESS_PAPER_REPOSITORY_MAP.md` | 302 | "Temporal is a planned target, not an authorized runtime change. EXEC-ORCH-001 must not be dispatched for further bespoke executor growth." | both sentences: Temporal is the optional provider, not a planned default, and the hold ends for decision 3's baseline scope; the migration and no-dual-dispatch rules stay for any Temporal adoption |
| `docs/alpha-2/UNIFIED_ROADMAP_TRACEABILITY.md` | 87 | "Temporal adoption decision" | the H10 row's direction: this ADR is the decision (PostgreSQL baseline, Temporal optional) |
| `docs/alpha-2/UNIFIED_ROADMAP_TRACEABILITY.md` | 119 | "research adoption prefers Temporal" | the preference and the row's "Hold further bespoke dispatch", for decision 3's baseline scope; the adoption/migration ADR and no dual side-effect authority stay required for any Temporal adoption |

## Consequences

- The H10 harness document's planning-target block and the R08 plan name one default. The provider catalog already
  did, and is unchanged.
- OW-D3's other planning targets and its H3 choice are untouched.
- TECH-TRUTH-001's checker (a roadmap item) keeps the H10 document, the R08 plan and the catalog consistent.

## Review trigger

The owner reviews this ADR when EXEC-TEMPORAL-001's qualification and measured comparison complete, or when a candidate
record qualifies an open-source PostgreSQL-backed durable-execution library under ADR 0008.
