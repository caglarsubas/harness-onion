# Harness Specification: `trust.observability-finops`

## Contract

| Field | Value |
|---|---|
| Plane | Trust and lifecycle |
| Owning repository | `mas-harness-trust-plane` |
| Public warm source | `llm_inference_engine`; non-public planning input metadata omitted |
| API version | `harness.planeon.ai/v1alpha1` |

## Capabilities and non-goals

This harness collects tenant-local traces, metrics, and logs; correlates work across planes; records model/tool/runtime resource usage; enforces declared budgets; exposes health/SLO views; and produces inspectable operational and FinOps evidence without a cloud billing dependency.

It does not send telemetry outside the tenant boundary, estimate vendor invoices, authorize operations, store prompts/model outputs as ordinary telemetry, or equate low cost with acceptable risk/quality. “FinOps” here means bounded consumption, capacity, attribution, and anomaly evidence—not integration with any external billing API.

## Owner and deployables

- `otel-collector`: tenant-local OpenTelemetry ingest, processing, redaction, routing, and bounded buffering.
- `usage-ledger`: authoritative request/token/tool/task/resource budget and attribution service.
- Prometheus and Jaeger are tenant-supplied open-source backends reached through the cataloged external OTel-backend prerequisite.
- There is no cataloged or selectable Loki module; Loki remains deferred comparative guidance for a future explicitly owned provider.

Telemetry attributes/instrumentation, usage semantics, and model evidence are
independent clean-room targets derived only from released contracts and
pre-recorded, digest-pinned observations under tenant-neutral names;
implementation cannot access, copy, adapt, translate, or derive code from a
warm checkout.

## Dependencies, conflicts, and ordering

- Required: `runtime.infrastructure`; `trust.security-safety` is required before classified production telemetry.
- Optional consumers/producers: every harness.
- Conflicts:
  - Any external telemetry exporter or endpoint outside the tenant boundary.
  - Payload, secret, token, prompt, output, source record, memory content, or tool credential in default telemetry.
  - Unbounded retention/cardinality/buffering.
  - Shared telemetry store that cannot enforce tenant isolation for restricted profiles.
  - Budget enforcement using eventually consistent counters where hard limits are required.

Collector/ledger baseline starts early; protected workloads become production-ready only after telemetry redaction and budget evidence pass.

## Provider implementations

- `planeon.otel`: OpenTelemetry Collector with allowlisted processors/exporters.
- `planeon.usage-postgres`: authoritative PostgreSQL budget/usage ledger.
- Capabilities `prometheus` and `jaeger` are fulfilled only through the cataloged `external.otel-backend` prerequisite and explicit tenant attestation; they are not `planeon.*` modules.
- Loki is not a selectable provider in the current catalog.

Remote SaaS and other external exporters are invalid providers and are absent from every catalog and image. Tenant-supplied telemetry backends must be open-source, non-metered, and inside the tenant boundary.

## Configuration and runtime boundaries

```yaml
telemetry:
  payloadCapture: disabled
  sampling:
    traces: decimal-string
    errorsAlways: true
  cardinality:
    maxAttributeValuesPerKey: integer
  buffer:
    maxBytes: integer
    maxAgeSeconds: integer
  retention:
    metricsDays: integer
    tracesDays: integer
    logsDays: integer
  exporters: [local-prometheus, local-jaeger]
budgets:
  - scope: tenant | profile | route | workflow
    modelCalls: integer
    inputTokens: integer
    outputTokens: integer
    toolCalls: integer
    cpuSeconds: integer
    gpuSeconds: integer
    storageBytes: integer
    windowSeconds: integer
```

- Secrets: the baseline requires none; local backend credentials, when needed, are tenant-local secret references. External exporter credentials and third-party API keys are schema-rejected.
- RBAC: collector may read only explicitly selected Kubernetes metadata; no secrets or cluster-admin. Ledger has no Kubernetes API access.
- Network: services export only to the local collector/ledger. Collector egress is restricted to selected tenant-local, open-source, non-metered backends; external exporter hosts are schema-rejected in every mode.
- Storage: ledger owns usage/budget tables with tenant RLS and atomic counters. Metrics/traces/logs use tenant-scoped backends/PVCs. Evidence digests can reference retained telemetry; raw payload storage is off.

## APIs, events, and state

```text
POST /observability/v1/usage:reserve
POST /observability/v1/usage:commit
POST /observability/v1/usage:release
GET  /observability/v1/usage
GET  /observability/v1/budgets
POST /observability/v1/budgets/{id}:evaluate
GET  /observability/v1/slos
GET  /observability/v1/health/dependencies
```

Budget states: `AVAILABLE`, `WARNING`, `EXHAUSTED`, `SUSPENDED`, `RESET_PENDING`.

Reservation states: `RESERVED → COMMITTED | RELEASED | EXPIRED`.

Emitted:

- `usage.reserved.v1`
- `usage.committed.v1`
- `budget.warning.v1`
- `budget.exhausted.v1`
- `slo.breached.v1`
- `telemetry.buffer.saturated.v1`

Consumed: task/model/tool/decision completion/failure, installation health, policy decisions, and profile budget activation.

## Failures, retry, and rollback

- Hard-budget operations reserve atomically before work. Duplicate commit/release is idempotent.
- Ledger loss blocks operations requiring hard budgets; callers that require only advisory usage may proceed if the profile explicitly allows and local outbox capacity exists.
- Collector outage buffers locally only within declared byte/time bounds; saturation drops lowest-priority telemetry by a documented order but never audit-required evidence.
- Audit/evidence loss is surfaced and can block governed state changes.
- An external exporter cannot be configured; unknown exporter identifiers fail catalog compilation.
- Configuration activation is atomic; invalid redaction/exporter policy retains last-known-good config.
- Service rollback preserves newer usage and budget reservations through compatible migrations.
- Counter reconciliation reports discrepancies; it never silently resets usage.

## Evidence and readiness gates

- Trace correlation across gateway, orchestration, model, knowledge, tool, decision, and trust boundaries.
- Tenant-neutral semantic attributes and tenant-isolation tests.
- Prompt/output/source/memory/secret redaction inspection.
- Atomic budget race, reservation expiry, retry, and reconciliation results.
- Retention, cardinality, sampling, buffer saturation, and disk-pressure behavior.
- Local dashboard/SLO availability and offline operation.
- No outbound connection under default/offline profiles.

Production readiness requires bounded storage/cardinality, redaction, budget correctness, and current dependency health evidence.

## Profile behavior

- `minimal-local`: one collector, Prometheus/Jaeger, PostgreSQL ledger, short retention.
- `enterprise`: HA collectors/ledger, explicitly attested tenant-scoped backends, SLOs, and longer policy-bounded retention.
- `airgap-enclave`: all backends local; exporters allowlist contains no external destination; bounded local storage alarms.

## Tests

- Independent clean-room parity against pre-recorded, digest-pinned vectors: OTel attributes/context/decorators, inference usage, task/tool receipts, and tenant-neutral fixtures; no warm checkout access.
- Unit: reservations, windows, counters, redaction, cardinality, retention, sampling.
- Contract: OTLP ingest, usage APIs/events, producer SDKs and evidence references.
- Security: tenant query crossover, high-cardinality attack, secret/payload injection, exporter SSRF.
- Failure: collector/ledger/backend outage, disk full, duplicate commit, expired reservation, clock skew.
- Air gap: packet capture/egress denial proves no external telemetry connection.

## Sol-high implementation packets

1. `SDK-002-telemetry`: tenant-neutral semantic attributes, context/decorators, OTel vectors, redaction, and framework-neutral instrumentation examples.
2. `TRUST-OBS-001`: local OTel Collector, explicit external-backend contract for tenant-supplied Prometheus/Jaeger, PostgreSQL usage ledger, atomic reservations/budgets, cross-plane correlation, SLO/dependency evidence, tenant isolation, retention, and bounded buffering. Loki remains non-installable comparative guidance outside this packet.
3. `TRUST-003-resilience-security`: collector/ledger/backend outages, audit buffer exhaustion, high-cardinality and forged telemetry, cross-tenant denial, and air-gap startup.

No packet may add a cloud billing API, external exporter, remote cache, paid/metered endpoint, third-party API key, or payload telemetry default.
