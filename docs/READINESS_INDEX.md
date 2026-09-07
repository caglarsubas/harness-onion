# Implementation Readiness Index

This index is the entry point for a coding agent. The architecture is planning-
ready; product implementation, release, deployment, runtime, assurance, and
tenant-acceptance evidence remain `NOT_STARTED` until their task packets run.

## Execution entry point

Current checkpoint: Phase-0 closure is recorded; Alpha-2 model implementation
requires the observation, contracts/status corrections and shared-model-contract
prerequisites. Production overview integration has its own later live gate. See
[Development status](DEVELOPMENT_STATUS.md) and
[Model prerequisites](alpha-2/MODEL_PREREQUISITES.md). The historical Phase-0
report records 107 packets; the current catalog has 132; the first repair retains its 114-packet snapshot. This index is a plan,
not proof that every packet or live evidence gate has passed.

Prerequisite: publish this planning corpus and pinned workflow once to the public
default branch, then attach the preprovisioned no-cost self-hosted runner with
the complete locked wheelhouse/tool cache. Missing prerequisites are `BLOCKED`;
there is no hosted-runner or online-fetch fallback. This is the sole initial
planning-publication exception to the packet/PR rule.
The runner image must contain the root-owned, integrity-pinned
`/opt/planeon/bin/harness-offline-launch`; after checkout it is the workflow's
only `run` command and establishes isolation before any checked-out file executes.
Its machine state is `EXTERNAL_PREREQUISITE_NOT_PROVEN`; CI remains blocked until
the signed manifest, launcher digest/version, preflight evidence, and exact runner
labels satisfy [`TRUSTED_RUNNER_CONTRACT.md`](TRUSTED_RUNNER_CONTRACT.md).

1. Read the repository-root `AGENTS.md` and `BILLING_POLICY.md`.
2. Select exactly one schema-valid YAML file from `task-packets/` whose
   predecessors have merged evidence.
3. Open the owning repository plan and every harness spec named by that packet.
4. Treat all current warm-source trees/blobs as reference-only. Use clean-room
   implementation and independent parity; no current packet authorizes copying.
5. Use the packet branch and touch only `allowedPaths`. Set
   `HARNESS_TASK_PACKET` to the hash-pinned YAML path and invoke
   `offlineExecution.wrapperArgv`; it runs local-cache-only `prefetchCommands`
   and acceptance in one deny-all-outbound process tree, hides the authority path
   from children, rechecks its digest after each command, and retains every
   requested evidence item.
   A packet with `liveCampaignExecution` still completes PR acceptance under
   deny-all. Its live argv may run only later through the externally installed,
   root-owned `/opt/planeon/bin/harness-live-campaign-launch` after that launcher
   reads only `HARNESS_LIVE_EXECUTION_ENVELOPE`; verifies independent
   `PLATFORM_RELEASE` and `TENANT_LIVE_EXECUTION` signatures over the same RFC
   8785 payload; verifies every referenced digest and embedded pre-existing
   endpoint against the two fixed local trust mounts; and verifies the separate
   digest-bound `CAPACITY_OPERATOR` authorization, proxy policy, and active
   server-side zero-cost mutation admission. It is forbidden as GitHub CI
   evidence, cannot discover or provision endpoints, and reports missing target
   capacity as `NOT_RUN_ENV_UNAVAILABLE`. The checked-out
   `ci/verify-live-campaign.sh` is an inner runner and cannot establish the trust
   boundary itself. See
   [`TRUSTED_LIVE_CAMPAIGN_RUNNER_CONTRACT.md`](TRUSTED_LIVE_CAMPAIGN_RUNNER_CONTRACT.md).
6. The protected runner supplies every mounted warm snapshot as an exact
   canonical entry in newline-delimited `HARNESS_WARM_SOURCE_ROOTS`. The launcher
   refuses undeclared detected roots, denies their read/metadata/write access,
   and scrubs their paths before implementation commands. `NONE` is valid only
   when the runner proves no warm source is mounted.
7. Merge only after all required self-hosted checks are green. A local pass, PR,
   merge, artifact, deployment, runtime check, assurance result, and tenant
   acceptance are different states.

The first executable packet is `MET-001`; subsequent work follows the predecessor
DAG, not Markdown list order alone.

The packet predecessor DAG is an implementation-order graph. For a live
conformance packet, merged source plus passing deny-all offline evidence can
unblock the next coding packet even when the environment result is
`NOT_RUN_ENV_UNAVAILABLE`. That unavailable result never satisfies release,
platform-certification, assurance, tenant-acceptance, or production-promotion
requirements; those remain blocked until their exact fresh live `PASS` evidence
exists.
Live statuses are only `PASS`, `FAIL`, `WARN`, `NOT_APPLICABLE`, and
`NOT_RUN_ENV_UNAVAILABLE`; platform and architecture are result dimensions, not
`LIVE_*` aliases. Live axes are drawn only from `DEPLOYMENT`, `RUNTIME`,
`SECURITY`, `ASSURANCE`, and `TENANT_ACCEPTANCE_CANDIDATE`, with the exact
per-packet ordered list enforced by the validator. `TENANT_ACCEPTANCE` is never
an envelope axis. `CONF-WG-001` creates an unsigned tenant-acceptance candidate
only; a separate authorized tenant signature is required for actual acceptance.

## Machine-readable authorities

| Concern | Authority |
|---|---|
| Attached-input provenance and authority | [`architecture/base-scope-sources.yaml`](../architecture/base-scope-sources.yaml) |
| Repository ownership and dependency DAG | [`architecture/repositories.yaml`](../architecture/repositories.yaml) |
| Sixteen-harness taxonomy and four deployment modes | [`architecture/taxonomy.yaml`](../architecture/taxonomy.yaml) |
| 87-record provider/module selection, dependency, and admission catalog | [`architecture/providers.yaml`](../architecture/providers.yaml) |
| 28-unit service graph, state and startup waves | [`architecture/services.yaml`](../architecture/services.yaml) |
| Cross-plane runtime-path rules | [`architecture/dependency-graph.yaml`](../architecture/dependency-graph.yaml) |
| Warm-start source commits and destinations | [`architecture/reuse-map.yaml`](../architecture/reuse-map.yaml) |
| Closed warm-source path states | [`architecture/reuse-path-index.yaml`](../architecture/reuse-path-index.yaml), [`schemas/reuse-path-index.schema.json`](../schemas/reuse-path-index.schema.json) |
| Future two-repository port authorizations (currently empty and admission-disabled) | [`architecture/porting-authorization-index.yaml`](../architecture/porting-authorization-index.yaml), [`schemas/porting-authorization.schema.json`](../schemas/porting-authorization.schema.json) |
| Destination `PORTING.yaml` record shape | [`schemas/porting-record.schema.json`](../schemas/porting-record.schema.json) |
| Source authorization | [`legal/source-reuse-authorization.yaml`](../legal/source-reuse-authorization.yaml) |
| Executable warm-snapshot integrity lock | [`ci/lock_warm_snapshot.py`](../ci/lock_warm_snapshot.py) |
| Third-party licensing | [`legal/third-party-license-policy.yaml`](../legal/third-party-license-policy.yaml), [`docs/phase-0/dependency-license-inventory.json`](phase-0/dependency-license-inventory.json) |
| Phase-0 cross-check and evidence boundaries | [`docs/phase-0/phase-0-backtest.json`](phase-0/phase-0-backtest.json), [`docs/phase-0/PHASE_0_BACKTEST.md`](phase-0/PHASE_0_BACKTEST.md) |
| Zero-bill defaults and prohibitions | [`policies/zero-bill-policy.yaml`](../policies/zero-bill-policy.yaml) |
| Provider/module and deterministic-profile-example shape | [`schemas/provider-module.schema.json`](../schemas/provider-module.schema.json) |
| Executable packet shape | [`schemas/task-packet.schema.json`](../schemas/task-packet.schema.json) |
| Readiness repair ownership and implementation gates | [`architecture/readiness-repairs.json`](../architecture/readiness-repairs.json), [`READINESS_REPAIRS.md`](alpha-2/READINESS_REPAIRS.md) |
| Approved cumulative-test and status-precedence amendment | [`architecture/readiness-repair-amendment.json`](../architecture/readiness-repair-amendment.json), [`MET-REPAIR-002`](../task-packets/MET-REPAIR-002.yaml) |
| Alpha-2 model source/destination evidence separation | [`architecture/model-evidence-boundary.json`](../architecture/model-evidence-boundary.json), [`MODEL_PREREQUISITES.md`](alpha-2/MODEL_PREREQUISITES.md) |
| External trusted-runner manifest shape | [`schemas/trusted-runner-manifest.schema.json`](../schemas/trusted-runner-manifest.schema.json), [`TRUSTED_RUNNER_CONTRACT.md`](TRUSTED_RUNNER_CONTRACT.md) |
| Closed live execution-envelope shape | [`schemas/live-campaign-execution-envelope.schema.json`](../schemas/live-campaign-execution-envelope.schema.json) |
| External trusted live-campaign boundary, dual signatures, endpoints/proxies, zero-cost admission, statuses, and evidence axes | [`TRUSTED_LIVE_CAMPAIGN_RUNNER_CONTRACT.md`](TRUSTED_LIVE_CAMPAIGN_RUNNER_CONTRACT.md) |

The public reuse authority currently contains 905 `TREE_DISCOVERY` records and
4,202 `BLOB_PENDING` records across all five exact-commit warm-start
repositories. It contains zero `BLOB_COPY_AUTHORIZED` paths, and the
porting-authorization index contains zero records. Direct reuse is therefore not
an executable option in any current packet; legal input and a future packet
revision are required first. The first two repositories are indexed from the
closed packet-reference closure; the other three are indexed from signed,
metadata-only full-tree observations that exposed no source text to the
implementation identity. Every warm-source path remains unavailable to product
implementation runs.

The Phase-0 dependency inventory is
[`docs/phase-0/dependency-license-inventory.json`](phase-0/dependency-license-inventory.json).
It records all thirteen planned repositories, distinguishes the three
repositories that are not yet created, and classifies every SPDX expression
discovered in the exact control-plane lock and root-owned offline wheel
inventories. Classification does not imply release: SBOM, notices, and approved
LGPL disposition remain mandatory release gates.

The provider authority is `PLANNED`: it defines 59 packet-owned implementation
plans, 23 tenant-supplied external prerequisites (twenty `external.*` records
plus three Kubernetes distribution choices), five contract-only
non-installables, closed public-demand/environment-fact/selector admission,
coverage of all sixteen canonical harnesses, and four deterministic profile
examples with explicit accepted selectors. Missing immutable release digests and
the absence of implementation evidence prevent any catalog record or example
from being treated as built, installable, released, deployed, or certified.

The two taxonomy production gates are fail-closed contracts, not current
assurance evidence. Each binds a closed control set with
`ALL_REQUIRED_CONTROLS`, an immutable `PRODUCTION_PROMOTION` evidence plan and
campaign, a signed trusted-producer policy/release, and the exact
tenant/profile/bundle/route/subject scope. A waiver must target the same control
and complete scope, but is documentation-only and never satisfies production
promotion. Until every required control has fresh `PASS` evidence, production
promotion remains blocked even when a waiver or source, CI, merge, artifact,
deployment, or runtime-health evidence is present.

## Repository plans

1. [`Harness-Engineering`](repositories/00-harness-engineering.md)
2. [`mas-harness-contracts`](repositories/01-mas-harness-contracts.md)
3. [`mas-harness-sdks`](repositories/02-mas-harness-sdks.md)
4. [`mas-harness-industry-packs`](repositories/03-mas-harness-industry-packs.md)
5. [`mas-harness-control-plane`](repositories/04-mas-harness-control-plane.md)
6. [`mas-harness-runtime-plane`](repositories/05-mas-harness-runtime-plane.md)
7. [`mas-harness-model-plane`](repositories/06-mas-harness-model-plane.md)
8. [`mas-harness-knowledge-plane`](repositories/07-mas-harness-knowledge-plane.md)
9. [`mas-harness-execution-plane`](repositories/08-mas-harness-execution-plane.md)
10. [`mas-harness-trust-plane`](repositories/09-mas-harness-trust-plane.md)
11. [`mas-harness-operator`](repositories/10-mas-harness-operator.md)
12. [`mas-harness-distribution`](repositories/11-mas-harness-distribution.md)
13. [`mas-harness-conformance-labs`](repositories/12-mas-harness-conformance-labs.md)

## Harness specifications

Runtime:

- [`runtime.infrastructure`](harnesses/runtime.infrastructure.md)
- [`runtime.model-inference`](harnesses/runtime.model-inference.md)
- [`runtime.ai-gateway`](harnesses/runtime.ai-gateway.md)
- [`runtime.experience`](harnesses/runtime.experience.md)

Knowledge:

- [`knowledge.domain-semantic`](harnesses/knowledge.domain-semantic.md)
- [`knowledge.data-integration`](harnesses/knowledge.data-integration.md)
- [`knowledge.retrieval-context`](harnesses/knowledge.retrieval-context.md)
- [`knowledge.memory-state`](harnesses/knowledge.memory-state.md)

Execution:

- [`execution.protocol-interoperability`](harnesses/execution.protocol-interoperability.md)
- [`execution.orchestration`](harnesses/execution.orchestration.md)
- [`execution.tool-skill-sandbox`](harnesses/execution.tool-skill-sandbox.md)
- [`execution.ml-decision`](harnesses/execution.ml-decision.md)

Trust:

- [`trust.security-safety`](harnesses/trust.security-safety.md)
- [`trust.governance-agentops`](harnesses/trust.governance-agentops.md)
- [`trust.observability-finops`](harnesses/trust.observability-finops.md)
- [`trust.evaluation-assurance`](harnesses/trust.evaluation-assurance.md)

## Supporting explanations

- [`MASTER_DEVELOPMENT_PLAN.md`](MASTER_DEVELOPMENT_PLAN.md): program milestones,
  invariants, guided gates, and evidence axes.
- [`MICROSERVICE_CATALOG.md`](MICROSERVICE_CATALOG.md): dependency modes,
  desired/observed/release state machines, propagation, and 28-unit matrix.
- [`PROVIDER_MODULE_CATALOG.md`](PROVIDER_MODULE_CATALOG.md): the planned
  provider/module inventory, deterministic closure, zero-bill admission,
  lifecycle/security/resource metadata, and immutable-release boundary.
- [`SCOPE_PROVENANCE.md`](SCOPE_PROVENANCE.md): adopted/rejected source patterns
  and the boundary between user requirements and attached-document content.
- [`TENANT_HARNESS_OVERVIEW.md`](TENANT_HARNESS_OVERVIEW.md): the approved
  organization/plane/harness status projection, authorization, navigation,
  responsive interaction, accessibility, and frontend delivery contract.
- [`task-packets/README.md`](../task-packets/README.md): the 132-packet execution
  catalog and topological delivery guidance.

## Early Linux readiness publication

[LINUX_READINESS.md](alpha-2/LINUX_READINESS.md) defines MET-LINUX-001,
MET-LINUX-002 and CONF-LINUX-001; the closed policy is
[linux-readiness.json](../architecture/linux-readiness.json). The dedicated
validator runs in MET-LINUX-001's signed seven-command offline session.
The source-only predecessor rule does not bypass the explicitly stricter
fresh native Linux gate for runtime coding. The 115-packet amendment remains
historical; that publication contained 118 packets; the current approved catalog contains 132.

## Conformance readiness amendment

[MET-REPAIR-003](../task-packets/MET-REPAIR-003.yaml),
[closed amendment](../architecture/linux-readiness-amendment.json),
[repair guide](alpha-2/LINUX_READINESS_REPAIRS.md) and
[negative validator](../scripts/validate_linux_repair.py) bind R1-R4 to exact
source-reviewed paths. CONF-FIX-001 owns the offline-wrapper/transport/canary
correction and retires insecure live-adapter execution. CONF-LINUX-001 owns the
additive handler-contract extension and named suite/campaign integration.
No missing test suite, fixture PASS or caller-provided boundary marker can
satisfy Linux qualification. Prior Linux policy bytes remain immutable.

## Assertion-only Linux legacy-test closure

- [MET-REPAIR-004](../task-packets/MET-REPAIR-004.yaml): one exact additional test path and assertion-only constraints.
- [Closed amendment](../architecture/linux-test-ownership-amendment.json): immutable predecessor source/CI/main pins, exact statement replacement and preserved native/live gates.
- [Guide and phase checkpoint](alpha-2/LINUX_TEST_OWNERSHIP_REPAIR.md): publication only; CONF-LINUX-001 implementation and native qualification remain independent.

Current catalog: 132 packets; the prior 121-packet record remains historical. Historical 118/120-packet publications remain byte-identical.

## Model fixture scope — preserved authority

- [MET-REPAIR-005](../task-packets/MET-REPAIR-005.yaml): exact helper-only grant.
- [Closed record](../architecture/model-fixture-scope-amendment.json): pinned
  baseline, helper transformation and independent evidence boundaries.
- [Development instructions](alpha-2/MODEL_FIXTURE_SCOPE_REPAIR.md): source-only
  checklist, strict verification, rollback and unchanged native runtime gate.

## Model API inventory scope — current authority

- [MET-REPAIR-006](../task-packets/MET-REPAIR-006.yaml): exact predicate-only grant.
- [Closed record](../architecture/model-api-inventory-amendment.json): immutable passing baseline, failed draft and predicate/outside-byte bindings.
- [Development instructions](alpha-2/MODEL_API_INVENTORY_REPAIR.md): historical 123-packet checkpoint, negative tests and then-pending product/native gates.

The cancelled draft CI is not PASS; no model-product acceptance is recorded.

## Approved trusted live backend enablement — MET-LIVE-001

The [coding guide](alpha-2/LIVE_BACKEND_READINESS.md) and closed
`architecture/live-backend-roadmap.json` add six sequential conformance packets
(CONF-LIVE-001 through CONF-LIVE-006), not new repositories or harnesses.
This publication recorded 130 packets; the current catalog contains 132. The 123 consumed packet YAML and all existing
architecture/legal/policy/release records remain byte-identical.

Only the six source-enablement packets may proceed before native qualification.
After their source closure, external operator installation and a fresh
independently signed native AMD64 qualification are required before
CTRL-INTEGRATE-001, MODEL-001, EXEC-001 or RUN-001. ARM64 qualification is separate.
CONF-LIVE-006 adds the twelfth possible manual campaign declaration with the
complete eight-command inventory; it grants no installation, target access,
provisioning or paid capability. The old seven-command CONF-LINUX-001 verifier
and all predecessor tests remain unchanged; the new packet has its own exact
pure authority/evidence adapter. Source fixtures never become native evidence.

Current phase/status and completed source checkpoints are in DEVELOPMENT_STATUS.md.
One packet, branch, PR and exact local/CI/main gate per run remains mandatory.

## Approved packet scalar compatibility repair — MET-REPAIR-007

The [exact correction guide](alpha-2/PACKET_SCALAR_REPAIR.md) adds MET-REPAIR-007 and
CONF-FIX-002: **132 packets**, thirteen repositories, sixteen harnesses and
**twelve** unchanged possible live declarations. The preceding 130 packet YAML
and all existing architecture/legal/policy/release bytes remain immutable.
This is the current supplement to the historical live-backend publication.

CONF-LIVE-001 is blocked after its quoted scalar identity failed before any
acceptance command or test ran. Complete CONF-FIX-002 in a separate product PR
first: change only the exact parser branch and one full-file hash assertion,
then add independent regression evidence in its three new owned files.
No packet reserialization, dependency, root policy, installation or isolation
change is authorized. Resume CONF-LIVE-001 only after corrective source,
local offline, required PR CI, merge and separate local exact-main closure.
Retain its original 103-file/120-test baseline and add corrective provenance
only within its existing paths; the six-root/eight-command inventory is fixed.
Native Linux, live backend, runtime and tenant acceptance remain separate gates.
