# Microservice Catalog and State Model

## Authority and coverage

The machine-readable authority is [`architecture/services.yaml`](../architecture/services.yaml), validated by the closed Draft 2020-12 contract [`schemas/services.schema.json`](../schemas/services.schema.json). It covers all 26 deployables declared by [`architecture/taxonomy.yaml`](../architecture/taxonomy.yaml), plus the two management-plane units `control-web` and `profile-compiler-worker`.

The catalog contains exactly 28 units. Every unit declares:

- Owner repository and harness, or `management-plane`.
- API, gateway, controller, worker, agent, collector, or job kind.
- `STATEFUL`, `STATELESS`, or `EPHEMERAL` process behavior and restart semantics.
- Owned/read-only/control stores.
- Every dependency's `SYNC`, `ASYNC`, `CONTROL`, or `ARTIFACT` mode.
- `FAIL_CLOSED` behavior or a typed `FAIL_OPEN` `degradationPolicy`.
- Readiness gates and startup wave.
- One exact implementation packet and one exact packet-authorized build path.
- `implementationStatus: PLANNED` and `evidenceStatus: NOT_STARTED`.

Dependency health is evaluated as a complete, revisioned edge snapshot. Each
edge contributes a neutral, degraded, blocked, or failed effect; no single edge
event writes the service state directly. The aggregate is recomputed after every
accepted edge revision, so dependency arrival order cannot change the result.

The service dependency graph is acyclic. Every internal dependency is in an earlier startup wave. Producer outages do not unnecessarily stop durable consumers: `profile-compiler-worker` continues already validated jobs from PostgreSQL when `control-web` is unavailable, and `orchestration-worker` continues already admitted tasks when `orchestration-api` is unavailable.

Harness-taxonomy dependency type `always` is an install-selection rule: selecting the consumer includes the provider harness. It does not assert that the provider is ready and does not override degradation. Runtime readiness comes only from each service edge's `mode`, `required`, `failureMode`, optional `selectedWhen`, and typed `degradationPolicy`.

Conditional edges use a closed `selectedWhen` predicate object, never executable
or free-form condition text. `whenCapability` edges use `anyOfCapabilities`
against signed profile capabilities. `subjectUnderEvaluation` edges use only
`anyOfSubjectHarnesses` and `anyOfSubjectCapabilities` against the explicit,
immutable assurance subject set. A conditionally selected `required: true` edge
then fails closed exactly like any other required edge, while an unselected edge
is not part of readiness.

Every value in `anyOfCapabilities` and every `disableImmediately.capability` is an exact ID from `architecture/providers.yaml#/capabilityRegistry`; local aliases are invalid. Aliases that previously combined behaviors are expressed as typed alternatives—for example, the model dependency for retrieval is selected by either `embedding.local-and-approved` or `retrieval.rerank.local`.

Runtime request branches also avoid expression text. The direct and task branches use closed `routeKind` predicates (`DIRECT_MODEL` and `TASK`); task-control uses an existing-task event predicate whose allowed events are input, cancellation, approval decision, and replay request. Optional branch edges use the same registered `anyOfCapabilities` predicate.

The taxonomy defines two production gates, `runtimeGatewayProductionAssurance`
and `decisionRouteProductionAssurance`. Each requires `PASS` evidence no older
than 86,400 seconds for its closed required-control list. Aggregation is
`ALL_REQUIRED_CONTROLS`; evidence must come from an immutable
`PRODUCTION_PROMOTION` campaign and bind SHA-256 evidence-plan, control-set,
campaign, trusted-producer-policy, producer-release, profile, bundle, route, and
subject digests. The exact scope also includes tenant, route, and subject
identity/version. A waiver must be signed, expiry-bearing, no longer than 14,400
seconds, and bind the same plan, control set, campaign, required control ID, and
exact tenant/profile/bundle/route/subject scope. It cannot override `FAIL` or
`STALE` evidence. Its effect is documentation only: it never satisfies a
production control, changes evidence to `PASS`, or permits promotion while any
required control lacks fresh `PASS` evidence.

## Dependency semantics

| Mode | Meaning | Required failure behavior |
|---|---|---|
| `SYNC` | The consumer calls the dependency while handling a request or step. | `FAIL_CLOSED` rejects the affected operation; `FAIL_OPEN` disables only the optional capability within a bounded budget. |
| `ASYNC` | The consumer receives durable work/events or exports buffered observations. | `FAIL_CLOSED` pauses dequeue/ack without losing the cursor; `FAIL_OPEN` continues existing work or buffers locally within its declared limit. |
| `CONTROL` | The dependency supplies desired state, admission, capability, lease, or health authority. | `FAIL_CLOSED` blocks new transitions; bounded `FAIL_OPEN` preserves already admitted/verified work only. |
| `ARTIFACT` | The consumer reads an immutable digest-pinned artifact or completion evidence. | Always `FAIL_CLOSED` for required artifacts. Missing, invalid, incomplete, unlicensed, or revoked content cannot activate. |

`FAIL_OPEN` never means unrestricted execution. Every such edge declares exactly one typed policy:

| Degradation policy | Contract |
|---|---|
| `disableImmediately` | Remove the named optional capability as soon as the dependency is lost. Unaffected capabilities may stay ready; requests requiring the removed capability fail with a stable dependency reason. |
| `bounded` | Continue only inside explicit `timeSeconds`, `bytes`, or `workItems` limits. `exhaustWhen` is `ANY` or `ALL`; the threshold executes a schema-enumerated `onExhaustion` action. |

The allowed exhaustion actions are `MARK_DEGRADED_AND_FAIL_READINESS` and `STOP_CLAIMING_WORK_AND_FAIL_READINESS`. They are machine enums, not operator-provided prose. Human rationale remains in the dependency's `behavior` field.

The default per-service telemetry edge is `bounded` to 300 seconds and 16 MiB; the collector-to-backend edge is 3,600 seconds and 512 MiB. These are hard catalog defaults that a profile may reduce but not increase without a reviewed contract revision. Optional producers use explicit work/time bounds, while semantic/model/tool/storage capabilities use `disableImmediately`.

External dependencies are operator-supplied Kubernetes, local OCI content, public trust material, OIDC, PostgreSQL/pgvector, OPA, local observability backends, allowlisted tenant sources/object storage, model volumes/backends, and signed catalogs/packs. The platform never creates them in a cloud account.

## Global state machines

### Desired state

```text
ABSENT → PRESENT → ACTIVE ↔ SUSPENDED
   ↑        ↓          ↓
   └────────┘        PRESENT
                       ↓
                    RETIRED
```

- `ABSENT`: the profile does not select the unit.
- `PRESENT`: artifacts/configuration are selected but the unit is not serving work.
- `ACTIVE`: the unit should run and accept its advertised capability.
- `SUSPENDED`: new work is blocked because of operator choice, dependency failure, or revocation.
- `RETIRED`: terminal desired state; historical evidence remains.

### Observed state

Normal path:

```text
UNKNOWN → ABSENT → PENDING → STARTING → READY → STOPPING → ABSENT
                         ↘ BLOCKED      ↕
                          ↘ FAILED   DEGRADED
```

- `BLOCKED` means a prerequisite, artifact, policy, environment, or earlier wave prevents startup.
- `DEGRADED` means the unit was usable but lost a bounded optional/required dependency or capability.
- `FAILED` means its own startup/reconciliation exhausted bounded retries or violated an invariant.
- Readiness is false in `PENDING`, `STARTING`, `BLOCKED`, `FAILED`, and `STOPPING`. It is true in `READY`. In `DEGRADED`, readiness is true only while the declared fail-open budget and mandatory capability set remain satisfied.
- Ephemeral jobs do not stay `READY`: successful completion creates immutable completion evidence consumed by the dependent wave, then the Job may become absent.

### Release state

```text
DRAFT → BUILT → VERIFIED → AWAITING_SIGNATURE → SIGNED → RELEASED → DEPRECATED → RETIRED
   ↘       ↘         ↘             ↘              ↘
                           FAILED or terminal REVOKED
```

`REVOKED` is terminal and overrides desired state. A hard dependency on a revoked release moves the consumer to `SUSPENDED`; no rollback may reactivate a revoked digest.

## Dependency-state propagation

The authority is an exact seventeen-row typed truth table plus a closed aggregation
contract. A normalized edge update is keyed by
`consumerServiceId+dependencyId` and accepted only at the latest monotonic
snapshot revision. Each revision is normalized to one canonical condition. At
most one explicit rule replaces that edge's previous contribution; only a
normalized healthy condition may use the closed neutral default.
Every selected dependency failure must normalize to an exact declared trigger.
An unmatched selected failure is `DependencyTriggerInvalid`, contributes
`FAILED`/`NOT_READY`, rejects new work, and retains compensation responsibility.
The reconciler then recomputes the service result from the complete edge snapshot.
It never promotes a service directly from a single recovery, optional, or
unselected event.

Contribution severity is deterministic and highest-first: `FAILED`, `BLOCKED`,
`DEGRADED`, `READY`. `READY` is the neutral contribution and projects to
`NO_CHANGE`, not a service promotion. Readiness precedence is `NOT_READY`,
`POLICY_CONTROLLED`, `NO_CHANGE`; desired-state action precedence is
`SET_SUSPENDED`, `NO_CHANGE`. Work actions are retained as an ordered unique set
using the machine-declared precedence, rather than choosing whichever update
arrived last; `NO_CHANGE` is omitted when any non-neutral action exists. The
primary non-neutral reason is selected from the highest severity, breaking
ties by lexicographic edge key; neutral reasons never replace the service's
local reason. Consequently aggregation is commutative,
associative for a fixed snapshot, and independent of event arrival order.

The final observed-state projection is the most severe dependency effect, falling
back to the service's local state only when every edge is neutral. Final readiness
similarly falls back to local readiness only when no edge contributes
`NOT_READY` or `POLICY_CONTROLLED`. A release revocation independently contributes
`SET_SUSPENDED`, is terminal, and cannot be cleared by a recovery rule. Recovery
work actions run only when the recomputed aggregate permits them.

Each trigger declares dependency mode, requirement class, event, lifecycle phase,
and degradation-budget state. `RUNTIME_DATA_PATH` is the closed aggregate
`SYNC|ASYNC`; it is not a wildcard. The table below explains the seventeen machine
rules and is not a second authority.

| Dependency condition | Consumer propagation |
|---|---|
| Required artifact is missing or unverified | Contribute `BLOCKED`, reason `DependencyArtifactUnverified`; no apply begins. |
| A required artifact becomes unverified after readiness | Contribute `DEGRADED` and `NOT_READY`, reject new work, execute the signed compensation policy, and retain state/evidence until the same artifact verifies again. |
| Required control dependency is not ready before startup | `BLOCKED`; readiness false. |
| Required control dependency is lost after readiness | `DEGRADED`; affected mutations fail closed. |
| Required synchronous dependency is lost | `DEGRADED`, readiness false, affected request returns retryable `503`. |
| Required asynchronous dependency is lost | Pause dequeue/ack, keep durable cursor/work, become `DEGRADED`, resume after recovery. |
| Optional bounded fail-open dependency is lost while its budget is available | Continue only inside its declared time/byte/work budget and emit `DependencyDegraded`. |
| Optional `disableImmediately` dependency is lost | With budget state `NOT_APPLICABLE`, remove the named capability immediately and contribute policy-controlled `DEGRADED`; this condition may never fall through to the neutral default. |
| Fail-open budget is exhausted | `DEGRADED`, readiness false until dependency or buffer recovers. |
| Optional/unselected provider is absent | Replace only that edge with a neutral `NO_CHANGE` contribution; selection logic separately stops advertising the capability. Other failed edges still control the aggregate. |
| Ephemeral dependency run fails | Fail the calling wave, start no later wave, retain immutable failure evidence. |
| Dependency release is revoked | Set hard dependents to desired `SUSPENDED`; reject new work and follow the signed compensation/termination policy for running work. |
| Required artifact verifies or is restored | Replace that edge with neutral `NO_CHANGE`, then recompute; apply may continue only if the full snapshot permits. Successful ephemeral completion uses this rule. |
| Required control dependency is restored | Replace that edge with neutral `NO_CHANGE`, then recompute; unblock mutations only if no remaining contribution blocks them. |
| Required synchronous or asynchronous dependency is restored | Replace that edge with neutral `NO_CHANGE`, then recompute; resume requests or dequeue from the durable cursor only if the aggregate permits. |
| Optional dependency recovers | Reset its degradation budget, replace its contribution with neutral `NO_CHANGE`, and recompute without overriding any other edge. |
| Optional `disableImmediately` dependency recovers | Restore the named capability only after recomputing the complete dependency snapshot; another failed edge still blocks restoration or readiness. |

Readiness probes test local invariants and hard dependencies; liveness probes test only whether the process can make progress. A dependency outage must not cause restart storms. Kubernetes conditions carry stable reason codes, observed generation, dependency digest, and transition time.

## Startup waves

The operator advances only after every required unit in a wave is `READY`, or every required ephemeral job has successful completion evidence. Optional/unselected units are `NOT_APPLICABLE` and do not block the wave.

| Wave | Units | Gate before next wave |
|---:|---|---|
| 0 | `bundle-verifier`, `otel-collector` | Bundle/trust closure verifies offline; local telemetry intake and bounded WAL are ready. |
| 1 | `operator`, `policy-decision`, `sandbox-runner` | Reconciliation/RBAC works, signed baseline policy is active, selected isolation provider passes controls. |
| 2 | `fleet-sync-agent`, `guardrail-service`, `usage-ledger`, `governance-service`, `domain-service` | Safety profiles, budgets, governance/audit, and active domain version are usable; optional fleet sync may be N/A. |
| 3 | `registry-service`, `inference-api`, `connector-controller`, `memory-service` | Catalog/revocations, local model, source control, and governed memory satisfy profile gates. |
| 4 | `control-web`, `ingest-worker`, `retrieval-service`, `protocol-gateway`, `evidence-service` | Guided setup, tenant status projections/overview, durable data/provenance, retrieval, protocol negotiation, and evidence intake are ready. |
| 5 | `profile-compiler-worker`, `index-worker`, `orchestration-api`, `decision-service`, `assurance-worker` | Deterministic compilation, index pipeline, task API, selected decision engine, and evaluation pipeline are ready. |
| 6 | `tool-broker`, `ai-gateway` | Tool authorization/receipts and signed budgeted AI routing pass end-to-end probes. |
| 7 | `orchestration-worker`, `experience-gateway` | Durable task execution/recovery and resumable tenant interactions pass. |

The waves are installation ordering, not synchronous runtime coupling. Workers consume durable stores/outboxes and continue existing admitted work when their producer API is unavailable.

## Microservice dependency and state matrix

Abbreviations: `S` = `SYNC`, `A` = `ASYNC`, `C` = `CONTROL`, `R` = `ARTIFACT`, `FC` = `FAIL_CLOSED`, `FO-D(capability)` = `disableImmediately`, and `FO-B(limit)` = `bounded`. For compactness, unannotated OTel `A/FO` rows mean `FO-B(300s/16MiB)`. External dependencies are summarized after the internal edges. All rows currently have implementation `PLANNED` and evidence `NOT_STARTED`.

| Unit | Owner / harness | Kind; behavior | Owned state/store | Internal dependencies (`mode/failure`) | Wave | Readiness gate |
|---|---|---|---|---|---:|---|
| `bundle-verifier` | operator / infrastructure | job; ephemeral | none; reads OCI/trust | none | 0 | Closure, signatures, licenses, revocations pass offline. |
| `otel-collector` | trust / observability-finops | collector; stateful | bounded local WAL | none | 0 | OTLP, tenant routing/redaction, writable buffer below limit. |
| `operator` | operator / infrastructure | controller; stateless process | CRD/status and inventory ConfigMap | verifier `R/FC` | 1 | API discovery, leader lease, CRD/RBAC, status persistence. |
| `policy-decision` | trust / security-safety | API; stateless | signed policy activation | OTel `A/FO` | 1 | OPA, signed baseline digest, tenant/deny self-tests. |
| `sandbox-runner` | execution / tool-sandbox | job; ephemeral | per-run scratch only | none | 1 | Selected isolation, deny-default network, limits, seccomp, cleanup. |
| `fleet-sync-agent` | operator / infrastructure | agent; stateless process | sync cursor in CRD status | operator `C/FC`; verifier `R/FC` | 2 | Enabled endpoint readable and last verified cursor observable; otherwise N/A. |
| `guardrail-service` | trust / security-safety | API; stateless | signed detector profiles | policy `S/FC`; OTel `A/FO` | 2 | Deterministic detector and streaming limits pass. |
| `usage-ledger` | trust / observability-finops | API; stateful | PostgreSQL `usage` | policy `S/FC`; OTel `A/FO` | 2 | RLS, idempotency, reservation reconciliation, replay vectors. |
| `governance-service` | trust / governance-agentops | API; stateful | PostgreSQL `governance` | policy `S/FC`; OTel `A/FO` | 2 | RLS, audit-chain, approval/N-of-M/waiver-expiry tests. |
| `domain-service` | knowledge / domain-semantic | API; stateful | PostgreSQL `domain` | policy `S/FC`; OTel `A/FO` | 2 | Active ontology digest, RLS, RDF/SHACL and semantic vectors. |
| `registry-service` | trust / governance-agentops | API; stateful | PostgreSQL `registry` | governance `S/FC`; policy `S/FC` | 3 | Signed catalog, RLS, release guards and revocation tests. |
| `inference-api` | model / model-inference | API; stateful | model PVC and route activation | policy `S/FC`; guardrail `S/FC`; OTel `A/FO` | 3 | Custody/license, backend/model probe, route signature, minimal inference. |
| `connector-controller` | knowledge / data-integration | controller; stateful | PostgreSQL `ingestion` | domain `S/FC`; policy `S/FC`; OTel `A/FO` | 3 | RLS, lease recovery, mapping, allowlist/SSRF and profile validation. |
| `memory-service` | knowledge / memory-state | API; stateful | PostgreSQL/pgvector `memory` | policy `S/FC`; governance `S/FC`; pgvector `S/FO-D(memory.semantic)`; OTel `A/FO` | 3 | Purpose/consent, TTL, delete/tombstone and isolation tests. |
| `control-web` | control / management | web API; stateful | PostgreSQL `control`, including tenant/plane/harness projections and cursors | policy `S/FC`; governance `S/FC`; registry `S/FC`; operator `A/FO-B(300s/1000 events)` | 4 | OIDC, RLS, signed pack/catalog, ETag/idempotency, audit chain, closed aggregation/freshness, operator scope, onion/list accessibility, zero public browser requests. |
| `ingest-worker` | knowledge / data-integration | worker; stateful | ingestion jobs/checkpoints/provenance | connector `C/FC`; domain `S/FC`; policy `S/FC`; object store `A/FO-D(storage.object-required)`; OTel `A/FO` | 4 | Lease/checkpoint recovery and atomic batch/provenance commit. |
| `retrieval-service` | knowledge / retrieval-context | API; stateful | PostgreSQL/pgvector `retrieval` | domain `S/FC`; connector `C/FC`; policy `S/FC`; inference `S/FO-D(retrieval.rerank.local)`; pgvector `S/FO-D(retrieval.vector)`; OTel `A/FO` | 4 | RLS, retrieval mode, citations/source versions, stale-index denial. |
| `protocol-gateway` | execution / protocol | gateway; stateful | PostgreSQL `protocol` | policy `S/FC`; governance `S/FC`; registry `C/FC`; OTel `A/FO` | 4 | MCP/A2A compatibility, auth, revocation and replay vectors. |
| `evidence-service` | trust / evaluation-assurance | API; stateful | PostgreSQL `evidence` + object refs | policy `S/FC`; governance `S/FC`; registry `C/FC`; object store `A/FO-D(storage.object-required)`; OTel `A/FO` | 4 | Producer signatures, evidence-axis/staleness/waiver and forgery tests. |
| `profile-compiler-worker` | control / management | worker; stateless process | compilation jobs/profile revisions | control web `A/FO-B(1800s/100 jobs)`; registry `R/FC` | 5 | Contract/catalog/pack digests, determinism, lease and atomic publish. |
| `index-worker` | knowledge / retrieval-context | worker; stateful | retrieval jobs/chunks/vectors | ingest `A/FC`; inference `S/FO-D(embedding.local-and-approved)`; policy `S/FC`; pgvector `A/FO-D(retrieval.vector)`; OTel `A/FO` | 5 | Checkpoint, create/swap, citation/source and dimension tests. |
| `orchestration-api` | execution / orchestration | API; stateful | PostgreSQL `orchestration` | protocol `S/FC`; governance `S/FC`; policy `S/FC`; OTel `A/FO` | 5 | Lifecycle, idempotency/input/cancel, budgets, atomic outbox. |
| `decision-service` | execution / ML-decision | API; stateful | PostgreSQL `decision` | connector `C/FC`; inference `S/FO-D(model.inference)`; governance `S/FC`; policy `S/FC` | 5 | Signed artifact, deterministic replay, feature provenance and RLS. |
| `assurance-worker` | trust / evaluation-assurance | worker; stateful | evidence campaigns/leases | evidence `A/FC`; ingest `C/FC` only when the immutable campaign selects `knowledge.data-integration`; inference `S/FO-D(assurance.local-model-judge)` only for model subjects/local judges; governance `S/FC`; OTel `A/FO` | 5 | Campaign/evaluator digests, lease recovery, calibration and submission. |
| `tool-broker` | execution / tool-sandbox | API; stateful | PostgreSQL `tools` | orchestration API `C/FC`; sandbox `R/FC`; policy `S/FC`; governance `S/FC`; OTel `A/FO` | 6 | Classification, approval, sandbox, receipts, idempotency, compensation. |
| `ai-gateway` | runtime / AI-gateway | gateway; stateful, metadata only | PostgreSQL `gateway`; no raw payloads | inference `S/FC`; policy `S/FC`; guardrail `S/FC`; governance `S/FC`; usage `S/FC`; orchestration API `S/FO-D(task.orchestration)`; OTel `A/FO` | 6 | Signed route/last-good, budget, upstream probe, stream/cancel tests. |
| `orchestration-worker` | execution / orchestration | worker; stateful | task leases/checkpoints | orchestration API `C/FO-B(3600s/1000 tasks)`; protocol `S/FC`; governance `S/FC`; inference `S/FO-D(model.inference)`; retrieval `S/FO-D(knowledge.retrieval)`; tools `S/FO-D(tool.governed-execution)`; OTel `A/FO` | 7 | Lease/checkpoint/state recovery, budgets, ordering and crash vectors. |
| `experience-gateway` | runtime / experience | gateway; stateful | PostgreSQL `experience` | AI gateway `S/FC`; orchestration API `S/FO-D(task.orchestration)`; governance `S/FC`; OTel `A/FO` | 7 | RLS, monotonic SSE IDs/replay, input/resume/cancel and retention. |

## Operational invariants

- A service never writes another service's schema. Cross-service state moves through APIs, immutable artifacts, or transactional outbox/inbox records.
- Tenant identity comes from verified OIDC/workload identity, never caller-supplied tenant headers.
- Required artifact, policy, signature, revocation, license, custody, and destructive-action dependencies always fail closed.
- Audit/evidence is never silently dropped. Telemetry fail-open uses content-free bounded buffering; durable audit/receipt/evidence stays in the owning store.
- Control-plane loss does not stop a locked tenant runtime. Registry loss blocks new activation but not already verified workloads. PostgreSQL loss blocks state mutations. OPA loss blocks protected actions.
- Overview browsers read only the control-owned last verified projection. Loss
  of an asynchronous status producer marks freshness/source availability and
  cannot fabricate current health or trigger a browser fan-out to runtime
  services.
- Every readiness change records observed generation, stable reason, dependency digest, transition time, and evidence reference.
- `PLANNED` is not source, CI, deployment, runtime, or acceptance proof. `NOT_STARTED` remains until a signed evidence record exists for the named gate.

## Catalog verification

The readiness package must validate:

1. The taxonomy deployable set plus the two management units equals the service-catalog set exactly.
2. IDs are unique and every dependency has mode, required flag, failure mode, and behavior.
3. Every service has owner, harness, kind, behavior, stores, readiness, startup wave, and the two status fields.
4. Internal dependency edges form a DAG and point only to earlier waves.
5. Top-level startup-wave membership matches every service's `startupWave` exactly.
6. Every `FAIL_OPEN` dependency declares `degradationPolicy.type` as `disableImmediately` or `bounded`; bounded policies include at least one positive time/byte/work limit, an `ANY`/`ALL` exhaustion rule, and a schema-enumerated exhaustion action; required artifacts are never fail-open.
7. All current implementation/evidence values are `PLANNED`/`NOT_STARTED`.
8. Every conditional/degradation capability reference resolves to the provider catalog capability registry; production-gate references resolve to the closed taxonomy registry.
9. The propagation truth table covers all seventeen canonical triggers exactly
   once. Every outcome is a per-edge replacement contribution, all neutral rows
   use `NO_CHANGE`, and every unmatched selected failure uses the declared
   fail-closed invalid-trigger contribution rather than the healthy default.
10. Full-snapshot aggregation uses the exact severity/readiness/action precedence,
    closed `RUNTIME_DATA_PATH` expansion, lexicographic tie-break, terminal
    revocation rule, and recovery gate declared by the schema; permutation of an
    identical edge snapshot produces an identical aggregate.
