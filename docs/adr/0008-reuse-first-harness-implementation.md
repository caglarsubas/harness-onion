# ADR 0008: Reuse-first harness implementation

Status: Proposed for acceptance with MET-ADOPT-002 source gates.
Owner: Harness-Engineering (R00). Date:2026-09-15.

## Decision

Adopt mature OSS engines behind stable harness contracts. Build platform-specific admission,
tenant isolation, declarative composition, industry/data readiness, thin adapters and evidence.
Require **at least one qualified baseline for every released harness capability** at the first enterprise release.
The complete decision and per-harness responsibilities are in
[the research-led roadmap](../alpha-2/HARNESS_PAPER_REPOSITORY_MAP.md).

LiteLLM OSS-only, Temporal self-hosted, LlamaIndex local, Mem0 OSS and Inspect AI are preferred
planning targets for their specified capabilities, not catalog activations or installed providers.
Existing mature baselines (Kubernetes, RDFLib/SHACL, OPA, OTel, scikit-learn) remain and receive explicit
capability and evidence mapping. Frameworks with overlapping roles do not jointly own one authority.

## Required implementation transaction

Publish exact contract/owner packets and pinned offline dependencies first. Compare upstream fit and
license closure, implement a bounded adapter, test real pinned packages, package minimal artifacts,
then independently qualify the exact version/capability/mode/environment and tenant profile.
Neither repo popularity nor a paper citation substitutes for this sequence.

Do not expand a new general-purpose engine without a separately reviewed build-versus-integrate ADR.
In particular preserve existing EXEC-ORCH-001 source/evidence and keep its bespoke-executor expansion
on hold. Before Temporal implementation, publish a compatibility/migration decision covering task APIs,
idempotent external activities, job drain/export, workflow-version replay, no dual execution and rollback.
The current PostgreSQL state is not migrated, deleted, or reinterpreted by this META packet.

## Unchanged boundaries

16 harnesses, four planes,13 repositories; one accountable harness owner; separate typed dependency
graphs; contract-first packet PRs; no cross-schema writes. All old packet YAML, public contracts,
source-reuse/legal locks, CI isolation, budgets and live qualification gates remain unchanged.
SaaS/cloud compatibility does not authorize provisioning. Existing external systems are attachment-only
unless separately authorized. Custom adapters cannot inject code into core or certify acceptance.

## Rejected alternatives

- Adding a research appendix while keeping contradictory future build instructions.
- Counting internal modules, a database dependency or pytest as a replacement for actual OSS engine reuse.
- Replacing the entire platform with a multi-purpose vendor framework.
- Installing64 alternatives before a useful release, or counting complementary components as alternatives.
- Using source-available/enterprise-only features or paid defaults to close a baseline gap.
- Discarding existing implementation and qualification evidence during the transition.

## Consequences and rollback

More adapter/version compatibility and artifact-license work, less maintenance of general-purpose engines.
A provider failing qualification stays unavailable; evaluate the next OSS option through a reviewed successor.
Before this policy is consumed, revert the amendment as one reviewed unit. After consumption, publish a
versioned successor with consumer impact and migration. Never rewrite old evidence or rollback tenant data.
