# Implementation Readiness Index

Current Alpha-2 dispatch: [MET-PERF-003 accounting/profiling follow-up](alpha-2/CONFORMANCE_PERFORMANCE_FOLLOWUP.md).
Catalog 148; product main9df7dd7 remains 127 files / 327 tests; both drafts unaccepted.
MET-PERF-002 source gates closed at2814402. Publish MET-PERF-003, then separate CONF-PERF-002; no timeout or workload relaxation.
CONF-PERF-001 draft13 is retained blocked history; older publication sections below are historical, not current instructions.
Accepted MET-PERF-001 main e367e89463b86ebc1b1e20563d677bdfe6694060 is preserved; this reconciliation runs both complete replays and all twenty commands.

This index is the entry point for a coding agent. The architecture is planning-
ready; product implementation, release, deployment, runtime, assurance, and
tenant-acceptance evidence remain `NOT_STARTED` until their task packets run.

## Execution entry point

Current checkpoint: Phase-0 closure is recorded; Alpha-2 model implementation
requires the observation, contracts/status corrections and shared-model-contract
prerequisites. Production overview integration has its own later live gate. See
[Development status](DEVELOPMENT_STATUS.md) and
[Model prerequisites](alpha-2/MODEL_PREREQUISITES.md). The historical Phase-0
report records 107 packets; the current catalog has 142; the first repair retains its 114-packet snapshot. This index is a plan,
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
- [`task-packets/README.md`](../task-packets/README.md): the 136-packet execution
  catalog and topological delivery guidance.

## Early Linux readiness publication

[LINUX_READINESS.md](alpha-2/LINUX_READINESS.md) defines MET-LINUX-001,
MET-LINUX-002 and CONF-LINUX-001; the closed policy is
[linux-readiness.json](../architecture/linux-readiness.json). The dedicated
validator runs in MET-LINUX-001's signed seven-command offline session.
The source-only predecessor rule does not bypass the explicitly stricter
fresh native Linux gate for runtime coding. The 115-packet amendment remains
historical; that publication contained 118 packets; the current approved catalog contains 139.

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

Current catalog: 136 packets; the prior 121-packet record remains historical. Historical 118/120-packet publications remain byte-identical.

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
This publication recorded 130 packets; the current catalog contains 142. The 123 consumed packet YAML and all existing
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

## Historical packet scalar compatibility publication — MET-REPAIR-007

The [exact correction guide](alpha-2/PACKET_SCALAR_REPAIR.md) adds MET-REPAIR-007 and
CONF-FIX-002: **132 packets**, thirteen repositories, sixteen harnesses and
**twelve** unchanged possible live declarations. The preceding 130 packet YAML
and all existing architecture/legal/policy/release bytes remain immutable.
This is the retained 132-packet publication. The successor-inventory supplement below supersedes its dispatch status.

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

## Approved cumulative inventory repair — MET-REPAIR-008

The [cumulative inventory guide](alpha-2/SUCCESSOR_INVENTORY_REPAIR.md) adds
MET-REPAIR-008 and CONF-FIX-003: **134 packets**, thirteen repositories, sixteen
harnesses and twelve unchanged possible live declarations. All 132 previous
packet YAML and existing architecture/legal/policy/release bytes are immutable
(170 files). Neither old correction record is rewritten.

MET-REPAIR-007 and CONF-FIX-002 are complete as separate source/CI/merge/local
exact-main checkpoints. Source inspection subsequently found the scalar suite's
frozen 106-file inventory rejects the next ten legitimate files; the earlier
successor-readiness inference is withdrawn, not its actual 150-test PASS.
Complete the new authority and then CONF-FIX-003 in its separate product PR:
one exact three-hunk test change and four new files, all 150 previous test IDs
plus twenty new tests. The parser and every other predecessor stay fixed.

Require complete ordered stage path sets (110, 120, 127, 135, 141, 146, 151 files),
predecessor hashes/modes, real collection and strict malformed/link/partial-stage
negatives. CONF-LIVE-006 alone may later replace the single terminal unavailable
statement after unchanged launcher manifest/preflight checks, with a bounded
SOURCE_DELTA_ONLY proof in its already-owned qualification document. That proof
is source accounting, not execution authority or a code-safety certification.

CONF-LIVE-001 remains blocked until corrective source, local offline, required
localhost PR CI, merge and local exact-main close. Then reconcile cumulative
history within its existing ten paths and unchanged six-root/eight-command
acceptance. No signed consumer packet, root policy, dependency, installation or
billing boundary changes. Native Linux and tenant acceptance remain separate;
no phase-end model-effort transition is due.

## Approved proxy contract prerequisite — MET-REPAIR-009

The [strict proxy profile](alpha-2/PROXY_CONTRACT_READINESS.md) closes credential and resource-rule
semantics for the new proxy without changing any accepted public wire schema,
134 existing packet YAML, product path grant, command inventory or signature role.
This one additive meta packet produces a 135-packet catalog and preserves all
176 predecessor authority files. It records SOURCE_INSPECTION_ONLY findings,
not a reproduced exploit or new product test failure.

Complete this authority before CONF-LIVE-003. Product implementation remains
in that packet's eight existing paths; preserve all 127 predecessor files and
279 test IDs. CONF-LIVE-004 owns actual probes, CONF-LIVE-005 the fixed client/server
candidate packaging, and CONF-LIVE-006 the already-bounded final hook. Mutual TLS,
independent server custody, actual policy/RBAC, durable reservations and exact-UID
cleanup must be tested independently; meta vectors are UNIT_VERIFICATION_ONLY.
Native qualification, runtime and tenant acceptance remain separate and unavailable.
No installation, key issuance, root-policy change, hosted runner or paid API is
part of this publication. Alpha 2 remains ongoing; no phase-end effort change is due.

## Approved protected policy observation — MET-REPAIR-010

Source-only prerequisite before CONF-LIVE-003: fixed local server-only observation,
independent operator custody and current enforcement evidence. Campaign API rules,
credentials, mutations and egress remain unchanged. The observer is a separately
installed open-source operator prerequisite, not an available or deployed product.
Current catalog 136; 135 predecessor YAML and strict proxy profile preserved.
Product stages 110/120/127/135/141/146/151 and eight paths/eight commands unchanged.
See the current dispatch link above for the closed schemas, native obligations,
recorded predecessor timing risk and separate acceptance gates. Alpha 2 ONGOING.

## Approved retained custody correction — MET-REPAIR-011

The [bounded handoff correction](alpha-2/CUSTODY_HANDOFF_REPAIR.md) adds MET-REPAIR-011 and CONF-FIX-004:
138 packets, unchanged thirteen repositories/four planes/sixteen harnesses.
The original 136 packet YAML and all prior authority records remain immutable.
CONF-FIX-004 may change only its five existing custody/supervisor/test/document
paths; old test bodies remain byte prefixes and all 279 methods remain required.
The 127-file stage and later 135/141/146/151 path counts stay unchanged.
Separate source/local/CI/merge/local exact-main closure is required before
CONF-LIVE-003 consumes the corrected checkpoint. No file-presence exemption,
path reopening, installation, new credential, dependency, native/live execution
or acceptance promotion. Prior nested-timeout failures remain unresolved history;
no timing, isolation or coverage relaxation. Alpha 2 ONGOING; effort change NOT_DUE.


## Approved bounded credential lifecycle — MET-REPAIR-012

The [credential-lifecycle correction](alpha-2/CREDENTIAL_LIFECYCLE_REPAIR.md) publishes
MET-REPAIR-012 and CONF-FIX-005: 140 packets, unchanged thirteen repositories,
four planes and sixteen harnesses. Preserve all 138 predecessor packet bytes.
CONF-FIX-004 closed at 0aa3ef3027f4a156d7ebed1b56af244e021d080a, 127 files / 305 tests;
its historical proof remains unchanged. CONF-FIX-005 supplies narrowly owned
late-credential/temporary-handle custody plus three cumulative source-accounting
adaptations, with every behavioral assertion and all 305 prior IDs retained.
Source stage counts and later eight-path proxy grant remain unchanged.
Publish and close each packet separately before CONF-LIVE-003. No product/native
execution, new installation, key, dependency, cloud action or bill in this meta
publication. Prior timing failures remain UNRESOLVED; no timeout or coverage
relaxation. Alpha 2 ONGOING; model-effort transition NOT_DUE.


## Approved credential-ordering correction — MET-REPAIR-013

The current dispatch link above is normative for the authentication-only client
credential exception. After independent signatures, kernel isolation, durable
reservation and retained custody checks, the client may authenticate only to its
pinned proxy. The server still requires fresh local policy observation and
transactional zero-cost admission before any probe, mutation or upstream
credential use. No TLS success or client receipt grants native acceptance.

Preserve all 141 predecessor packet bytes, historical authority and source locks.
Current catalog142; conformance checkpoint9df7dd7 has 127 files / 327 tests.
CONF-LIVE-003 retains eight paths/eight commands; no additional product repair
packet, signature role, endpoint, installed capability or billing permission.
This meta publication requires twenty-one offline commands and separate local,
required localhost CI, merge and local exact-main gates. Native AMD64/ARM64 and
Alpha3/4 remain waiting; Alpha 2 ONGOING, effort transition NOT_DUE.


## Approved broker handoff — MET-REPAIR-014

The current dispatch link is normative for the fixed server-local broker execution
handoff, including zero-resource probes. Broker-controlled execution, not an
observation, callback or token, enforces the policy generation. The proxy retains
exact resource/UID ownership and cleanup; the worker has no credentials or generic
execution API. New local custody and the fixed worker ABI do not change public
campaign/signature schemas, network endpoint sets or Kubernetes permissions.

Catalog143; all142 predecessor packet bytes and the accepted127-file/327-test
product checkpoint remain unchanged. Product packets003–006 keep their exact
paths/eight commands and source stages. This source-only publication requires22
commands, both complete replays, required localhost PR CI, merge and independent
local exact-main. No installation, new broker availability, paid service or live
acceptance is claimed. Alpha2 ONGOING; model-effort transition NOT_DUE.
