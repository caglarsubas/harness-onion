# ADR 0010: Language placement

Status: Accepted direction under MET-GOV-004 (owner LANG-D1 and LANG-D2); a baseline, with exceptions governed below.
Owner: Harness-Engineering (R00). Date: 2026-10-26.

## Context

The owner's LANG-D1 (2026-10-25) asked for this language-placement ADR and for three things around it: a
per-deployable language decision for `ai-gateway`, `protocol-gateway` and `tool-broker` before R05 or R08 coding (the
item LANG-HOTPATH-DECISION-001), an R04 scope note, and a later Go client in R02 (SDK-GO-CLIENT-001). The owner's
LANG-D2 (2026-10-25) then fixed this ADR's content, (a) to (g) below.

Until now each repository's language choice sat in its plan's toolchain section
(`docs/repositories/NN-<repository>.md`), one plan at a time, and the Rust of R10's native roles and R12's native probes
in the alpha-2 records (`docs/alpha-2/W01_AMENDMENT_W02D.md:24` and `docs/alpha-2/ENFORCEMENT_TEST_PLAN.md:12-13`). Each
added toolchain is also a lifecycle cost in the owner-operated offline verifier, which pins the toolchains it builds
with (LANG-D2 (f)).

This ADR records the planned language of the 13 repositories of `architecture/repositories.yaml`, the 28 deployables of
`architecture/services.yaml` and five rows outside that catalogue, each tied to the lines that state it: in the
repository plans or, for R10's native roles, R12's native probes and the model backends, in the alpha-2 records under
`docs/alpha-2/`. It decides no deployable's language beyond what the repository plans state.

## Decision

### P. The policy (LANG-D2 (a), verbatim)

<!-- language-policy:begin -->
> Python is the default language for AI-native behavior, agent workflows, evaluation, model integration, and research-oriented tooling. Go is the default language for network-facing infrastructure, protocol mediation, distributed coordination, gateways, operators, control loops, and tool-dispatch services where AI-native computation is not the primary responsibility. Rust is preferred for selected memory-safety-critical, privileged native, or resource-constrained components where its guarantees provide demonstrable value. C++ is adopted primarily through established upstream dependencies, with exceptions permitted through architectural review. TypeScript is the default for browser applications, management interfaces, and the TypeScript SDK. Language selection is governed by service responsibility, operational constraints, ecosystem suitability, lifecycle costs, and benchmark evidence. No component is required to use Go merely because it is on the request path, and no component is exempt from production SLOs merely because it uses Python.
<!-- language-policy:end -->

`architecture/language-placement.json` pins this text by sha256 (`policySha256`, 4b0a8a4b…), and
`scripts/language_placement.py check` refuses the ADR if the line above changes.

### The control plane and the data plane (LANG-D2 (c))

R04 is the management application (TypeScript). The infrastructure control loop is R10's Go operator. UI architecture
does not dictate the operator's language.

**R04's scope.** R04 (`mas-harness-control-plane`) is the management application and API (`control-web`) and the
profile-compiler worker (`profile-compiler-worker`). It is not the infrastructure control loop. Its plan calls the
repository the control plane and describes an asynchronous management plane
(`docs/repositories/04-mas-harness-control-plane.md:46`). Under (c), R04 is the management application, and the
infrastructure control loop is R10's Go operator. So R04's rows are not marked CONTROL: their plane is UNSTATED, and
there is no third, management, plane value.

**The plane rule.** A row's plane is recorded only where a source states it. In `architecture/services.yaml`, kind
`agent` gives CONTROL and kind `gateway` gives DATA (plane source KIND_RULE). Kind `controller` would also give CONTROL,
but both controller rows are placed by name instead: the operator is CONTROL by (c) (OWNER_LANG_D2), and
`connector-controller` stays UNSTATED while its role is to be confirmed, so no row takes its plane from kind
`controller`. Every other row is UNSTATED (NOT_STATED), because no source states a CONTROL or DATA plane for it. That
gives 2 CONTROL rows (`operator` and `fleet-sync-agent`), 3 DATA rows (`ai-gateway`, `experience-gateway` and
`protocol-gateway`) and 23 UNSTATED rows.

### The status of each deployable

- **AS_PLANNED** (15 rows): (a) names the row's responsibility and the plans' language is (a)'s default for it, or
  (e) applies (an adopted upstream keeps its own language: `otel-collector`).
- **PENDING_HOTPATH_DECISION** (4 rows: `ai-gateway`, `experience-gateway`, `protocol-gateway` and `tool-broker`): the
  planned language, Python, differs from (a)'s Go default for gateways, protocol mediation and tool dispatch.
  LANG-HOTPATH-DECISION-001 decides.
- **CONTROL_LOOP_TO_BE_CONFIRMED** (1 row: `connector-controller`, Python): if it is a control loop, (a)'s default is
  Go. Its role is to be confirmed.
- **NO_STATED_DEFAULT** (8 rows): (a)'s lists do not name the row's responsibility. The plans' language, Python, is
  recorded, and no default is claimed. These rows are not exceptions (section G).

### The baseline (LANG-D2 (d))

The four tables below are the baseline at harness-onion main 9184f5b6: a baseline decision with allowed exceptions, not
a permanent assignment. Each table's caption pins both catalogues by sha256, so the checker, not the prose, holds the
baseline the rows are taken at.

### Adopted upstreams (LANG-D2 (e))

Adopted upstreams keep their own language, for example Java for Trino. The OTel Collector (`otel-collector`) is an
upstream pinned image (`docs/repositories/09-mas-harness-trust-plane.md:100`), recorded as UPSTREAM_OWN with no
language claimed for it. The model backend images (`model-backends`) are adopted upstreams too
(`docs/repositories/06-mas-harness-model-plane.md:100`, and the planned OSS implementations in
`docs/alpha-2/HARNESS_PAPER_REPOSITORY_MAP.md:32-35`). No backend language is claimed, because neither span states one.

### Contracts stay language-neutral (LANG-D2 (g))

Language choices must not change protocol contracts, or weaken observability, security, replayability or conformance.
The same behavioural contracts (contract vectors, R12 campaigns, MAS-RA-003 run events) are enforceable whether a
component is in Go or Python.

## The tables

Each table is rendered from `architecture/language-placement.json` by `scripts/language_placement.py`, between its
markers. The checker refuses any drift between the data, the tables, the catalogues and the cited plan lines: each
span's sha256 covers its lines with their line feeds, each span carries its evidence strings, and each row's toolchain
string occurs verbatim in one of its spans. Each cited span is located by its content: a shift of the cited lines is
accepted, and any change to their text is refused.

### Repositories

R12's first span records Node 24.20.0 LTS and Playwright as toolchain only (portal and streaming interaction), not as a
TypeScript placement. R10's second span and the `native-host-enforcement-roles` row cite W01-AMEND-QW4, "The native
roles are Rust with musl": the native roles, not all host enforcement. The owner decision W01-AMEND-QW4 is cited in
`docs/alpha-2/SECCOMP_ALLOWLISTS_V3.md:6`.

<!-- language-placement:repositories:begin -->
Repositories, rendered from `architecture/language-placement.json` by `scripts/language_placement.py`: the baseline at `architecture/services.yaml` sha256 `857376b5e2b10a2a2542124a7d36b770eca531d15e463d68415416b887dd90a6` and `architecture/repositories.yaml` sha256 `02190a668c6a9114b3733724bec4e552c553867e789b0802f6aaa6759148051d`.

| R | Repository | Id | Languages | Toolchain | Sources |
|---|---|---|---|---|---|
| R00 | `Harness-Engineering` | `harness-engineering` | PYTHON | Python 3.12.14 | `docs/repositories/00-harness-engineering.md:1231` |
| R01 | `mas-harness-contracts` | `contracts` | PYTHON | Python 3.12.14 | `docs/repositories/01-mas-harness-contracts.md:125` |
| R02 | `mas-harness-sdks` | `sdks` | PYTHON, TYPESCRIPT | Python 3.10-3.13 with development baseline 3.12.14 | `docs/repositories/02-mas-harness-sdks.md:92-94` |
| R03 | `mas-harness-industry-packs` | `industry-packs` | PYTHON | Python 3.12.14 | `docs/repositories/03-mas-harness-industry-packs.md:100-105` |
| R04 | `mas-harness-control-plane` | `control-plane` | PYTHON, TYPESCRIPT | Node 24.20.0 LTS | `docs/repositories/04-mas-harness-control-plane.md:102-103` |
| R05 | `mas-harness-runtime-plane` | `runtime-plane` | PYTHON, TYPESCRIPT | Python 3.12.14 | `docs/repositories/05-mas-harness-runtime-plane.md:88-93` |
| R06 | `mas-harness-model-plane` | `model-plane` | PYTHON | Python 3.12.14 | `docs/repositories/06-mas-harness-model-plane.md:99` |
| R07 | `mas-harness-knowledge-plane` | `knowledge-plane` | PYTHON | Python 3.12.14 | `docs/repositories/07-mas-harness-knowledge-plane.md:118` |
| R08 | `mas-harness-execution-plane` | `execution-plane` | PYTHON | Python 3.12.14 | `docs/repositories/08-mas-harness-execution-plane.md:101` |
| R09 | `mas-harness-trust-plane` | `trust-plane` | PYTHON | Python 3.12.14 | `docs/repositories/09-mas-harness-trust-plane.md:90-92` |
| R10 | `mas-harness-operator` | `operator` | GO, RUST | Go 1.26.7 | `docs/repositories/10-mas-harness-operator.md:152`; `docs/alpha-2/W01_AMENDMENT_W02D.md:24` |
| R11 | `mas-harness-distribution` | `distribution` | PYTHON | Python 3.12.14 | `docs/repositories/11-mas-harness-distribution.md:163` |
| R12 | `mas-harness-conformance-labs` | `conformance-labs` | PYTHON, RUST | Python 3.12.14 | `docs/repositories/12-mas-harness-conformance-labs.md:408-409`; `docs/alpha-2/ENFORCEMENT_TEST_PLAN.md:12-13` |
<!-- language-placement:repositories:end -->

### Deployables

<!-- language-placement:deployables:begin -->
Deployables (architecture/services.yaml), rendered from `architecture/language-placement.json` by `scripts/language_placement.py`: the baseline at `architecture/services.yaml` sha256 `857376b5e2b10a2a2542124a7d36b770eca531d15e463d68415416b887dd90a6` and `architecture/repositories.yaml` sha256 `02190a668c6a9114b3733724bec4e552c553867e789b0802f6aaa6759148051d`.

| Deployable | Owner repository | Kind | Planned language | Toolchain | Plane | Plane source | Status | Source |
|---|---|---|---|---|---|---|---|---|
| `bundle-verifier` | `mas-harness-operator` | job | GO | Go 1.26.7 | UNSTATED | NOT_STATED | AS_PLANNED | `docs/repositories/10-mas-harness-operator.md:152-154` |
| `otel-collector` | `mas-harness-trust-plane` | collector | UPSTREAM_OWN | upstream pinned images/config modules | UNSTATED | NOT_STATED | AS_PLANNED | `docs/repositories/09-mas-harness-trust-plane.md:100` |
| `operator` | `mas-harness-operator` | controller | GO | Go 1.26.7 | CONTROL | OWNER_LANG_D2 | AS_PLANNED | `docs/repositories/10-mas-harness-operator.md:152-153` |
| `policy-decision` | `mas-harness-trust-plane` | api | PYTHON | Python 3.12.14 | UNSTATED | NOT_STATED | NO_STATED_DEFAULT | `docs/repositories/09-mas-harness-trust-plane.md:90-100` |
| `sandbox-runner` | `mas-harness-execution-plane` | job | PYTHON | Python 3.12.14 | UNSTATED | NOT_STATED | NO_STATED_DEFAULT | `docs/repositories/08-mas-harness-execution-plane.md:101-102` |
| `fleet-sync-agent` | `mas-harness-operator` | agent | GO | Go 1.26.7 | CONTROL | KIND_RULE | AS_PLANNED | `docs/repositories/10-mas-harness-operator.md:152-155` |
| `guardrail-service` | `mas-harness-trust-plane` | api | PYTHON | Python 3.12.14 | UNSTATED | NOT_STATED | AS_PLANNED | `docs/repositories/09-mas-harness-trust-plane.md:90-100` |
| `usage-ledger` | `mas-harness-trust-plane` | api | PYTHON | Python 3.12.14 | UNSTATED | NOT_STATED | NO_STATED_DEFAULT | `docs/repositories/09-mas-harness-trust-plane.md:90-100` |
| `governance-service` | `mas-harness-trust-plane` | api | PYTHON | Python 3.12.14 | UNSTATED | NOT_STATED | NO_STATED_DEFAULT | `docs/repositories/09-mas-harness-trust-plane.md:90-100` |
| `domain-service` | `mas-harness-knowledge-plane` | api | PYTHON | Python 3.12.14 | UNSTATED | NOT_STATED | NO_STATED_DEFAULT | `docs/repositories/07-mas-harness-knowledge-plane.md:117-118` |
| `registry-service` | `mas-harness-trust-plane` | api | PYTHON | Python 3.12.14 | UNSTATED | NOT_STATED | NO_STATED_DEFAULT | `docs/repositories/09-mas-harness-trust-plane.md:90-100` |
| `inference-api` | `mas-harness-model-plane` | api | PYTHON | Python 3.12.14 | UNSTATED | NOT_STATED | AS_PLANNED | `docs/repositories/06-mas-harness-model-plane.md:99` |
| `connector-controller` | `mas-harness-knowledge-plane` | controller | PYTHON | Python 3.12.14 | UNSTATED | NOT_STATED | CONTROL_LOOP_TO_BE_CONFIRMED | `docs/repositories/07-mas-harness-knowledge-plane.md:117-118` |
| `memory-service` | `mas-harness-knowledge-plane` | api | PYTHON | Python 3.12.14 | UNSTATED | NOT_STATED | AS_PLANNED | `docs/repositories/07-mas-harness-knowledge-plane.md:117-118` |
| `control-web` | `mas-harness-control-plane` | web-api | TYPESCRIPT | Node 24.20.0 LTS | UNSTATED | NOT_STATED | AS_PLANNED | `docs/repositories/04-mas-harness-control-plane.md:102` |
| `ingest-worker` | `mas-harness-knowledge-plane` | worker | PYTHON | Python 3.12.14 | UNSTATED | NOT_STATED | NO_STATED_DEFAULT | `docs/repositories/07-mas-harness-knowledge-plane.md:117-118` |
| `retrieval-service` | `mas-harness-knowledge-plane` | api | PYTHON | Python 3.12.14 | UNSTATED | NOT_STATED | AS_PLANNED | `docs/repositories/07-mas-harness-knowledge-plane.md:117-118` |
| `protocol-gateway` | `mas-harness-execution-plane` | gateway | PYTHON | Python 3.12.14 | DATA | KIND_RULE | PENDING_HOTPATH_DECISION | `docs/repositories/08-mas-harness-execution-plane.md:101-102` |
| `evidence-service` | `mas-harness-trust-plane` | api | PYTHON | Python 3.12.14 | UNSTATED | NOT_STATED | AS_PLANNED | `docs/repositories/09-mas-harness-trust-plane.md:90-100` |
| `profile-compiler-worker` | `mas-harness-control-plane` | worker | PYTHON | Python 3.12.14 | UNSTATED | NOT_STATED | NO_STATED_DEFAULT | `docs/repositories/04-mas-harness-control-plane.md:103` |
| `index-worker` | `mas-harness-knowledge-plane` | worker | PYTHON | Python 3.12.14 | UNSTATED | NOT_STATED | AS_PLANNED | `docs/repositories/07-mas-harness-knowledge-plane.md:117-118` |
| `orchestration-api` | `mas-harness-execution-plane` | api | PYTHON | Python 3.12.14 | UNSTATED | NOT_STATED | AS_PLANNED | `docs/repositories/08-mas-harness-execution-plane.md:101-102` |
| `decision-service` | `mas-harness-execution-plane` | api | PYTHON | Python 3.12.14 | UNSTATED | NOT_STATED | AS_PLANNED | `docs/repositories/08-mas-harness-execution-plane.md:101-102` |
| `assurance-worker` | `mas-harness-trust-plane` | worker | PYTHON | Python 3.12.14 | UNSTATED | NOT_STATED | AS_PLANNED | `docs/repositories/09-mas-harness-trust-plane.md:90-100` |
| `tool-broker` | `mas-harness-execution-plane` | api | PYTHON | Python 3.12.14 | UNSTATED | NOT_STATED | PENDING_HOTPATH_DECISION | `docs/repositories/08-mas-harness-execution-plane.md:101-102` |
| `orchestration-worker` | `mas-harness-execution-plane` | worker | PYTHON | Python 3.12.14 | UNSTATED | NOT_STATED | AS_PLANNED | `docs/repositories/08-mas-harness-execution-plane.md:101-102` |
| `ai-gateway` | `mas-harness-runtime-plane` | gateway | PYTHON | Python 3.12.14 | DATA | KIND_RULE | PENDING_HOTPATH_DECISION | `docs/repositories/05-mas-harness-runtime-plane.md:88` |
| `experience-gateway` | `mas-harness-runtime-plane` | gateway | PYTHON | Python 3.12.14 | DATA | KIND_RULE | PENDING_HOTPATH_DECISION | `docs/repositories/05-mas-harness-runtime-plane.md:88-89` |
<!-- language-placement:deployables:end -->

### Outside the catalogue

<!-- language-placement:outsideCatalogue:begin -->
Outside the catalogue, rendered from `architecture/language-placement.json` by `scripts/language_placement.py`: the baseline at `architecture/services.yaml` sha256 `857376b5e2b10a2a2542124a7d36b770eca531d15e463d68415416b887dd90a6` and `architecture/repositories.yaml` sha256 `02190a668c6a9114b3733724bec4e552c553867e789b0802f6aaa6759148051d`.

| Row | Owner repository | Planned language | Sources |
|---|---|---|---|
| `reference-channel-ui` | `mas-harness-runtime-plane` | TYPESCRIPT | `docs/repositories/05-mas-harness-runtime-plane.md:90-93` |
| `model-backends` | `mas-harness-model-plane` | UPSTREAM_OWN | `docs/repositories/06-mas-harness-model-plane.md:100`; `docs/alpha-2/HARNESS_PAPER_REPOSITORY_MAP.md:32-35` |
| `native-host-enforcement-roles` | `mas-harness-operator` | RUST | `docs/alpha-2/W01_AMENDMENT_W02D.md:24` |
| `r12-native-probes` | `mas-harness-conformance-labs` | RUST | `docs/alpha-2/ENFORCEMENT_TEST_PLAN.md:12-13` |
| `typescript-sdk` | `mas-harness-sdks` | TYPESCRIPT | `docs/repositories/02-mas-harness-sdks.md:94` |
<!-- language-placement:outsideCatalogue:end -->

## G. Exceptions (LANG-D2 (b))

Each exception has an owner, supporting evidence and an explicit review trigger. Owners are roles (a repository and
its implementationOwnership packet in `architecture/services.yaml`), never people. There is one row for each
PENDING_HOTPATH_DECISION or CONTROL_LOOP_TO_BE_CONFIRMED deployable, five in all.

<!-- language-placement:exceptions:begin -->
Exceptions (LANG-D2 (b)), rendered from `architecture/language-placement.json` by `scripts/language_placement.py`: the baseline at `architecture/services.yaml` sha256 `857376b5e2b10a2a2542124a7d36b770eca531d15e463d68415416b887dd90a6` and `architecture/repositories.yaml` sha256 `02190a668c6a9114b3733724bec4e552c553867e789b0802f6aaa6759148051d`.

| Deployable | Status | Default | Planned | Owner (repository, packet) | Evidence | Review trigger |
|---|---|---|---|---|---|---|
| `ai-gateway` | PENDING_HOTPATH_DECISION | GO | PYTHON | `mas-harness-runtime-plane`, RUN-001 | PENDING: LANG-HOTPATH-DECISION-001's measured boundary decision and benchmark against the production SLO | the first packet that fixes `ai-gateway`'s implementation language, or LANG-HOTPATH-DECISION-001's decision, whichever comes first |
| `experience-gateway` | PENDING_HOTPATH_DECISION | GO | PYTHON | `mas-harness-runtime-plane`, RUN-EXP-001 | PENDING: LANG-HOTPATH-DECISION-001's measured boundary decision and benchmark against the production SLO | the first packet that fixes `experience-gateway`'s implementation language, or LANG-HOTPATH-DECISION-001's decision, whichever comes first |
| `protocol-gateway` | PENDING_HOTPATH_DECISION | GO | PYTHON | `mas-harness-execution-plane`, EXEC-PROT-001 | PENDING: LANG-HOTPATH-DECISION-001's measured boundary decision and benchmark against the production SLO | the first packet that fixes `protocol-gateway`'s implementation language, or LANG-HOTPATH-DECISION-001's decision, whichever comes first |
| `tool-broker` | PENDING_HOTPATH_DECISION | GO | PYTHON | `mas-harness-execution-plane`, EXEC-TOOL-001 | PENDING: LANG-HOTPATH-DECISION-001's measured boundary decision and benchmark against the production SLO | the first packet that fixes `tool-broker`'s implementation language, or LANG-HOTPATH-DECISION-001's decision, whichever comes first |
| `connector-controller` | CONTROL_LOOP_TO_BE_CONFIRMED | GO | PYTHON | `mas-harness-knowledge-plane`, KN-DATA-001 | PENDING: KN-DATA-001's (or its successor's) classification of the role as a control loop or not, and, if it is one, LANG-HOTPATH-DECISION-001's decision | the first packet that fixes `connector-controller`'s implementation language, or LANG-HOTPATH-DECISION-001's decision, whichever comes first |
<!-- language-placement:exceptions:end -->

**Bootstrap shells do not fire a trigger.** A bootstrap packet that creates only health-only shells, such as KN-001's
for R07 (`docs/repositories/07-mas-harness-knowledge-plane.md:118`: "source-only, health-only shells for exact Python
3.12.14"), does not fix an implementation language. It is not "the first packet that fixes <id>'s implementation
language".

The eight NO_STATED_DEFAULT rows (`policy-decision`, `sandbox-runner`, `usage-ledger`, `governance-service`,
`domain-service`, `registry-service`, `ingest-worker` and `profile-compiler-worker`) are recorded plans with no default
claimed. They are not exceptions under (b).

## T. Review triggers

This ADR, its data and its tables are reviewed again on:
- a new deployable or repository;
- LANG-HOTPATH-DECISION-001's decision or latency budget;
- a change to the verifier's pinned toolchains;
- the first R05 or R08 coding packet.

## Consequences

- LANG-HOTPATH-DECISION-001 is unblocked. It decides the four PENDING_HOTPATH_DECISION rows, and
  `connector-controller` if that row is a control loop.
- SDK-GO-CLIENT-001 stays P2.
- A plan change that touches a cited span (its cited text) fails the checker until the data and the
  tables are re-derived: `python3 scripts/language_placement.py check`.
- **(f)** Lifecycle cost includes each added toolchain in the owner-operated offline verifier. Today's pins, as the
  owner states them, are Python 3.12.14, Go 1.26.7, Rust 1.99.0 (confirmed by the lane monitor, MON-LANG-4) and Node.
  This ADR makes no per-plan Node claim beyond the cited spans.
- **(g)** A future language change to a row is checked against the same contract vectors and campaigns.

## Amendment 1 (MET-GOV-005, 2026-10-26): the technology record

TECH-TRUTH-001 extends this ADR's data and checker into the technology record. The owner's TECH-D1 (2026-10-26) put
the item in the tech-stack review set, the lane monitor assigned it in MON-PAR-NEXT, and MON-TT-DOSSIER ruled its
questions. `architecture/language-placement.json` moves to schema `planeon.internal.language-placement/v2`, and
`scripts/language_placement.py check` applies rules R1 to R14 in the order R1-R7, R9-R14, then R8. Each of the 28
deployables gains its runtime, frameworks, packaging, adopted upstream, implementation status and decision reference.
The two native rows (`native-host-enforcement-roles` and `r12-native-probes`) gain the same values, with runtime Rust
and packaging NATIVE_BINARY. Each selected baseline of the 16 harness documents is bound to a catalog module, an
optional adapter, a plan library or a recorded deferral, 31 rows in all. Every span now records its section. The text
above this amendment is unchanged.

- **Status and decision.** `otel-collector` is the one upstream-managed deployable: its module's image is the upstream
  `otel/opentelemetry-collector-contrib`, and it keeps that upstream's language (UPSTREAM_OWN). The other 27
  deployables are PLANNED, as `architecture/services.yaml` states; no harness-onion record states an approved or
  implemented one. The decision reference is ADR 0011 for `orchestration-api` and `orchestration-worker` (they stay
  PLANNED: ADR 0011 decides the executor, not their implementation), LANG-HOTPATH-DECISION-001 for the four
  PENDING_HOTPATH_DECISION rows, KN-DATA-001 for `connector-controller`, and this ADR for every other row.
- **The baseline bindings.** 18 rows bind a catalog module, 2 an optional adapter, 1 a plan library (`helm/helm`, on
  R10's toolchain bullet) and 10 a recorded deferral that the harness document's Delivery line names. H10's first row
  is `planeon.orchestrator.postgres`, and `temporalio/temporal`, which the H10 document calls an optional provider, is
  deferred to EXEC-TEMPORAL-001.
- **H3's divergence is recorded, not resolved.** The `runtime.ai-gateway` document's planning target is
  `BerriAI/litellm`, and its row binds that line as an OPTIONAL_ADAPTER. The roadmap's OW-D3 and H3-D1 select Agent
  Router: the row's `divergence` records that selection (`roadmapSelection`) and its deferral, RUN-GATEWAY-ADOPT-001,
  which the document's Delivery line names. The checker picks no winner.
- **Drift.** The checker also refuses a DEFAULT or CONDITIONAL providers.yaml record that names Temporal, a DEFAULT
  bound record inside a provider exclusivity group, two DEFAULT bound records for one capability, and an
  upstream-managed deployable given its repository's language (O4, O5).
- **Carried couplings.** The record pins `architecture/services.yaml`, `architecture/repositories.yaml` and
  `architecture/providers.yaml` by sha256. SERVICE-EDGES-001's services.yaml amendment needs the services.yaml pin
  re-derived and the checker re-run. A providers.yaml change needs its pin, the catalog-agreement rule (R10), the
  binding rule (R12) and the expected bindings re-derived. This amendment changes no catalog.
- **What "any change to their text is refused" covers (C2-2).** A cited span is now located in its section: its
  heading line must occur once in its file, and the cited block must occur exactly once between that heading and the
  next heading. A block moved to another section, copied into another section with the original edited, or duplicated
  within its section is refused; a move within the section is accepted. One residual is accepted and stated: a copy
  within the same section, with the original then edited, is accepted, because the cited text still stands verbatim in
  its own section. `docs/alpha-2/W01_AMENDMENT_W02D.md` and `docs/alpha-2/ENFORCEMENT_TEST_PLAN.md` each have one
  heading, so their section is the whole file: for their 4 spans, a move to the end and the copy-then-edit case are
  accepted too.

### The technology record

<!-- technology-table:begin -->
Technology (amendment 1), rendered from `architecture/language-placement.json` (schema `planeon.internal.language-placement/v2`) by `scripts/language_placement.py`: the baseline at `architecture/providers.yaml` sha256 `9e2b43dac1ca4531dcdeb3a1b6ead8002d7384e2a0d0e6b57e972accb8631c02`.

| Deployable | Runtime | Frameworks | Packaging | Upstream | Implementation status | Decision | Frameworks sources |
|---|---|---|---|---|---|---|---|
| `bundle-verifier` | Go 1.26.7 | controller-runtime, Kubebuilder/envtest, Helm 4.2.0, Cosign 3.1.3, Kustomize 5.8.1 | OCI_IMAGE | null | PLANNED | docs/adr/0010-language-placement.md | `docs/repositories/10-mas-harness-operator.md:152` |
| `otel-collector` | null | none | HELM_CHART, OCI_IMAGE | otel/opentelemetry-collector-contrib | UPSTREAM_MANAGED | docs/adr/0010-language-placement.md | none |
| `operator` | Go 1.26.7 | controller-runtime, Kubebuilder/envtest, Helm 4.2.0, Cosign 3.1.3, Kustomize 5.8.1 | HELM_CHART, OCI_IMAGE | null | PLANNED | docs/adr/0010-language-placement.md | `docs/repositories/10-mas-harness-operator.md:152` |
| `policy-decision` | Python 3.12.14 | FastAPI, Pydantic v2, psycopg 3, cryptography, HTTPX, OpenTelemetry, jsonschema, pytest, OPA | OCI_IMAGE | null | PLANNED | docs/adr/0010-language-placement.md | `docs/repositories/09-mas-harness-trust-plane.md:90-92`; `docs/repositories/09-mas-harness-trust-plane.md:100` |
| `sandbox-runner` | Python 3.12.14 | FastAPI, Pydantic v2, psycopg 3, jsonschema, cryptography, HTTPX, OpenTelemetry, MCP SDK compatible with 2026-07-28 plus 2025-11-25, A2A v1 | OCI_IMAGE | null | PLANNED | docs/adr/0010-language-placement.md | `docs/repositories/08-mas-harness-execution-plane.md:101` |
| `fleet-sync-agent` | Go 1.26.7 | controller-runtime, Kubebuilder/envtest, Helm 4.2.0, Cosign 3.1.3, Kustomize 5.8.1 | OCI_IMAGE | null | PLANNED | docs/adr/0010-language-placement.md | `docs/repositories/10-mas-harness-operator.md:152` |
| `guardrail-service` | Python 3.12.14 | FastAPI, Pydantic v2, psycopg 3, cryptography, HTTPX, OpenTelemetry, jsonschema, pytest | OCI_IMAGE | null | PLANNED | docs/adr/0010-language-placement.md | `docs/repositories/09-mas-harness-trust-plane.md:90-92` |
| `usage-ledger` | Python 3.12.14 | FastAPI, Pydantic v2, psycopg 3, cryptography, HTTPX, OpenTelemetry, jsonschema, pytest | OCI_IMAGE | null | PLANNED | docs/adr/0010-language-placement.md | `docs/repositories/09-mas-harness-trust-plane.md:90-92` |
| `governance-service` | Python 3.12.14 | FastAPI, Pydantic v2, psycopg 3, cryptography, HTTPX, OpenTelemetry, jsonschema, pytest | OCI_IMAGE | null | PLANNED | docs/adr/0010-language-placement.md | `docs/repositories/09-mas-harness-trust-plane.md:90-92` |
| `domain-service` | Python 3.12.14 | FastAPI, Pydantic v2, psycopg 3, PostgreSQL/pgvector, RDFLib, pySHACL, jsonschema, HTTPX, cryptography, OpenTelemetry | OCI_IMAGE | null | PLANNED | docs/adr/0010-language-placement.md | `docs/repositories/07-mas-harness-knowledge-plane.md:119` |
| `registry-service` | Python 3.12.14 | FastAPI, Pydantic v2, psycopg 3, cryptography, HTTPX, OpenTelemetry, jsonschema, pytest | OCI_IMAGE | null | PLANNED | docs/adr/0010-language-placement.md | `docs/repositories/09-mas-harness-trust-plane.md:90-92` |
| `inference-api` | Python 3.12.14 | FastAPI, Pydantic v2, Uvicorn, HTTPX, cryptography, structlog, SSE, OpenTelemetry | OCI_IMAGE | null | PLANNED | docs/adr/0010-language-placement.md | `docs/repositories/06-mas-harness-model-plane.md:99` |
| `connector-controller` | Python 3.12.14 | FastAPI, Pydantic v2, psycopg 3, PostgreSQL/pgvector, RDFLib, pySHACL, jsonschema, HTTPX, cryptography, OpenTelemetry | OCI_IMAGE | null | PLANNED | KN-DATA-001 | `docs/repositories/07-mas-harness-knowledge-plane.md:119` |
| `memory-service` | Python 3.12.14 | FastAPI, Pydantic v2, psycopg 3, PostgreSQL/pgvector, RDFLib, pySHACL, jsonschema, HTTPX, cryptography, OpenTelemetry | OCI_IMAGE | null | PLANNED | docs/adr/0010-language-placement.md | `docs/repositories/07-mas-harness-knowledge-plane.md:119` |
| `control-web` | Node 24.20.0 LTS | Next.js 16.3.3 Active LTS with the App Router, React 19.2, TypeScript 5, Prisma 6.19.3, PostgreSQL, AJV 8.20.0, Vitest, Playwright | HELM_CHART, OCI_IMAGE | null | PLANNED | docs/adr/0010-language-placement.md | `docs/repositories/04-mas-harness-control-plane.md:102` |
| `ingest-worker` | Python 3.12.14 | FastAPI, Pydantic v2, psycopg 3, PostgreSQL/pgvector, RDFLib, pySHACL, jsonschema, HTTPX, cryptography, OpenTelemetry | OCI_IMAGE | null | PLANNED | docs/adr/0010-language-placement.md | `docs/repositories/07-mas-harness-knowledge-plane.md:119` |
| `retrieval-service` | Python 3.12.14 | FastAPI, Pydantic v2, psycopg 3, PostgreSQL/pgvector, RDFLib, pySHACL, jsonschema, HTTPX, cryptography, OpenTelemetry | OCI_IMAGE | null | PLANNED | docs/adr/0010-language-placement.md | `docs/repositories/07-mas-harness-knowledge-plane.md:119` |
| `protocol-gateway` | Python 3.12.14 | FastAPI, Pydantic v2, psycopg 3, jsonschema, cryptography, HTTPX, OpenTelemetry, MCP SDK compatible with 2026-07-28 plus 2025-11-25, A2A v1 | OCI_IMAGE | null | PLANNED | LANG-HOTPATH-DECISION-001 | `docs/repositories/08-mas-harness-execution-plane.md:101` |
| `evidence-service` | Python 3.12.14 | FastAPI, Pydantic v2, psycopg 3, cryptography, HTTPX, OpenTelemetry, jsonschema, pytest | OCI_IMAGE | null | PLANNED | docs/adr/0010-language-placement.md | `docs/repositories/09-mas-harness-trust-plane.md:90-92` |
| `profile-compiler-worker` | Python 3.12.14 | `uv` 0.12.7 | OCI_IMAGE | null | PLANNED | docs/adr/0010-language-placement.md | `docs/repositories/04-mas-harness-control-plane.md:103` |
| `index-worker` | Python 3.12.14 | FastAPI, Pydantic v2, psycopg 3, PostgreSQL/pgvector, RDFLib, pySHACL, jsonschema, HTTPX, cryptography, OpenTelemetry | OCI_IMAGE | null | PLANNED | docs/adr/0010-language-placement.md | `docs/repositories/07-mas-harness-knowledge-plane.md:119` |
| `orchestration-api` | Python 3.12.14 | FastAPI, Pydantic v2, psycopg 3, jsonschema, cryptography, HTTPX, OpenTelemetry, MCP SDK compatible with 2026-07-28 plus 2025-11-25, A2A v1 | OCI_IMAGE | null | PLANNED | docs/adr/0011-h10-execution-authority.md | `docs/repositories/08-mas-harness-execution-plane.md:101` |
| `decision-service` | Python 3.12.14 | FastAPI, Pydantic v2, psycopg 3, jsonschema, cryptography, HTTPX, OpenTelemetry, MCP SDK compatible with 2026-07-28 plus 2025-11-25, A2A v1 | OCI_IMAGE | null | PLANNED | docs/adr/0010-language-placement.md | `docs/repositories/08-mas-harness-execution-plane.md:101` |
| `assurance-worker` | Python 3.12.14 | FastAPI, Pydantic v2, psycopg 3, cryptography, HTTPX, OpenTelemetry, jsonschema, pytest | OCI_IMAGE | null | PLANNED | docs/adr/0010-language-placement.md | `docs/repositories/09-mas-harness-trust-plane.md:90-92` |
| `tool-broker` | Python 3.12.14 | FastAPI, Pydantic v2, psycopg 3, jsonschema, cryptography, HTTPX, OpenTelemetry, MCP SDK compatible with 2026-07-28 plus 2025-11-25, A2A v1 | OCI_IMAGE | null | PLANNED | LANG-HOTPATH-DECISION-001 | `docs/repositories/08-mas-harness-execution-plane.md:101` |
| `orchestration-worker` | Python 3.12.14 | FastAPI, Pydantic v2, psycopg 3, jsonschema, cryptography, HTTPX, OpenTelemetry, MCP SDK compatible with 2026-07-28 plus 2025-11-25, A2A v1 | OCI_IMAGE | null | PLANNED | docs/adr/0011-h10-execution-authority.md | `docs/repositories/08-mas-harness-execution-plane.md:101` |
| `ai-gateway` | Python 3.12.14 | FastAPI/Starlette, Pydantic v2, HTTPX, psycopg 3, cryptography, OpenTelemetry, SSE support | OCI_IMAGE | null | PLANNED | LANG-HOTPATH-DECISION-001 | `docs/repositories/05-mas-harness-runtime-plane.md:88` |
| `experience-gateway` | Python 3.12.14 | FastAPI/Starlette, Pydantic v2, HTTPX, psycopg 3, cryptography, OpenTelemetry, SSE support | OCI_IMAGE | null | PLANNED | LANG-HOTPATH-DECISION-001 | `docs/repositories/05-mas-harness-runtime-plane.md:88`; `docs/repositories/05-mas-harness-runtime-plane.md:89` |
<!-- technology-table:end -->

### The native rows

<!-- native-table:begin -->
Native rows (amendment 1), rendered from `architecture/language-placement.json` (schema `planeon.internal.language-placement/v2`) by `scripts/language_placement.py`: the baseline at `architecture/providers.yaml` sha256 `9e2b43dac1ca4531dcdeb3a1b6ead8002d7384e2a0d0e6b57e972accb8631c02`.

| Row | Owner repository | Runtime | Frameworks | Packaging | Upstream | Implementation status | Decision |
|---|---|---|---|---|---|---|---|
| `native-host-enforcement-roles` | `mas-harness-operator` | Rust | none | NATIVE_BINARY | null | PLANNED | docs/adr/0010-language-placement.md |
| `r12-native-probes` | `mas-harness-conformance-labs` | Rust | none | NATIVE_BINARY | null | PLANNED | docs/adr/0010-language-placement.md |
<!-- native-table:end -->

### The baseline bindings

<!-- bindings-table:begin -->
Baseline bindings (amendment 1), rendered from `architecture/language-placement.json` (schema `planeon.internal.language-placement/v2`) by `scripts/language_placement.py`: the baseline at `architecture/providers.yaml` sha256 `9e2b43dac1ca4531dcdeb3a1b6ead8002d7384e2a0d0e6b57e972accb8631c02`.

| Harness | Baseline | Kind | Target | Divergence |
|---|---|---|---|---|
| `execution.ml-decision` | `scikit-learn/scikit-learn` | CATALOG_MODULE | `provider.execution.decision-sklearn` / `planeon.sklearn` | none |
| `execution.ml-decision` | `microsoft/onnxruntime` | CATALOG_MODULE | `provider.execution.decision-onnx` / `planeon.onnx` | none |
| `execution.orchestration` | `planeon.orchestrator.postgres` | CATALOG_MODULE | `module.execution.orchestration.orchestration-worker` / `planeon.orchestrator.postgres` | none |
| `execution.orchestration` | `temporalio/temporal` | DEFERRED | EXEC-TEMPORAL-001 (Delivery line) | none |
| `execution.protocol-interoperability` | `modelcontextprotocol/python-sdk` | CATALOG_MODULE | `provider.execution.protocol-mcp` / `planeon.mcp` | none |
| `execution.protocol-interoperability` | `a2aproject/a2a-python` | CATALOG_MODULE | `provider.execution.protocol-a2a` / `planeon.a2a` | none |
| `execution.tool-skill-sandbox` | `google/gvisor` | CATALOG_MODULE | `provider.execution.sandbox-gvisor` / `planeon.sandbox.gvisor` | none |
| `execution.tool-skill-sandbox` | `bytecodealliance/wasmtime` | CATALOG_MODULE | `provider.execution.sandbox-wasmtime` / `planeon.sandbox.wasmtime` | none |
| `knowledge.data-integration` | `trinodb/trino` | DEFERRED | KN-DATA-ADOPT-001 (Delivery line) | none |
| `knowledge.data-integration` | `fivetran/great_expectations` | DEFERRED | KN-DATA-ADOPT-001 (Delivery line) | none |
| `knowledge.data-integration` | `OpenLineage/OpenLineage` | DEFERRED | KN-DATA-ADOPT-001 (Delivery line) | none |
| `knowledge.domain-semantic` | `RDFLib/rdflib` | CATALOG_MODULE | `module.knowledge.domain-semantic.domain-service` / `planeon.rdflib` | none |
| `knowledge.domain-semantic` | `RDFLib/pySHACL` | CATALOG_MODULE | `module.knowledge.domain-semantic.domain-service` / `planeon.pyshacl` | none |
| `knowledge.memory-state` | `mem0ai/mem0` | DEFERRED | KN-MEM-ADOPT-001 (Delivery line) | none |
| `knowledge.retrieval-context` | `run-llama/llama_index` | DEFERRED | KN-RET-ADOPT-001 (Delivery line) | none |
| `knowledge.retrieval-context` | `pgvector/pgvector` | CATALOG_MODULE | `external.pgvector` / `tenant.pgvector` | none |
| `runtime.ai-gateway` | `BerriAI/litellm` | OPTIONAL_ADAPTER | `provider.planeon.litellm-local` / `planeon.litellm-local` | roadmap selection Agent Router (OW-D3, H3-D1), deferral RUN-GATEWAY-ADOPT-001; recorded, not resolved |
| `runtime.experience` | `ag-ui-protocol/ag-ui` | OPTIONAL_ADAPTER | `provider.planeon.experience-agui` / `planeon.experience.agui` | none |
| `runtime.experience` | `CopilotKit/CopilotKit` | DEFERRED | RUN-UI-ADOPT-001 (Delivery line) | none |
| `runtime.infrastructure` | `kubernetes/kubernetes` | CATALOG_MODULE | `provider.runtime.infrastructure.kubernetes-upstream` / `kubernetes.upstream` | none |
| `runtime.infrastructure` | `helm/helm` | PLAN_LIBRARY | `docs/repositories/10-mas-harness-operator.md` under `## Deployables and toolchain`: Helm 4.2.0 | none |
| `runtime.model-inference` | `ollama/ollama` | CATALOG_MODULE | `provider.planeon.ollama` / `planeon.ollama` | none |
| `runtime.model-inference` | `ggml-org/llama.cpp` | CATALOG_MODULE | `provider.planeon.llamacpp` / `planeon.llamacpp` | none |
| `runtime.model-inference` | `vllm-project/vllm` | CATALOG_MODULE | `provider.planeon.vllm` / `planeon.vllm` | none |
| `trust.evaluation-assurance` | `UKGovernmentBEIS/inspect_ai` | DEFERRED | TRUST-EVAL-ADOPT-001 (Delivery line) | none |
| `trust.governance-agentops` | `open-policy-agent/opa` | CATALOG_MODULE | `external.opa-engine` / `opa` | none |
| `trust.governance-agentops` | `mlflow/mlflow` | DEFERRED | TRUST-GOV-ADOPT-001 (Delivery line) | none |
| `trust.observability-finops` | `open-telemetry/opentelemetry-collector` | CATALOG_MODULE | `module.trust.observability.otel-collector` / `planeon.otel` | none |
| `trust.observability-finops` | `prometheus/prometheus` | CATALOG_MODULE | `external.otel-backend` / `prometheus` | none |
| `trust.security-safety` | `open-policy-agent/opa` | CATALOG_MODULE | `external.opa-engine` / `opa` | none |
| `trust.security-safety` | `data-privacy-stack/presidio` | DEFERRED | TRUST-SAFE-ADOPT-001 (Delivery line) | none |
<!-- bindings-table:end -->
