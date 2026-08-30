# Harness Specification: `runtime.ai-gateway`

## Contract

| Field | Value |
|---|---|
| Plane | Runtime |
| Owning repository | `mas-harness-runtime-plane` |
| API version | `harness.planeon.ai/v1alpha1` |

## Capabilities and non-goals

The AI gateway authenticates tenant requests, resolves signed logical routes, evaluates policy, enforces request/token/concurrency budgets, normalizes inference requests, streams results, applies explicitly configured fallback, and emits usage and policy evidence. It provides a stable application-facing boundary while model backends remain replaceable.

It does not load or execute models, persist prompts or conversation memory, perform retrieval, approve policy exceptions, or call an undeclared external provider. It is not a general API-management product and never adds a provider because it appears cheaper or available.

## Owner and deployables

- `ai-gateway`: required stateful metadata and streaming gateway whose request payload handling remains stateless.

LiteLLM compatibility is contract-only, non-installable guidance in this release;
there is no selectable LiteLLM adapter image or packet-owned implementation.

The gateway writes no raw business payloads to persistent storage. Signed route activation, idempotency hashes/results metadata, budget reservations, and short-lived stream cursors make the service stateful; raw prompts, raw responses, retrieved context, and conversation memory are forbidden columns.

## Dependencies, conflicts, and ordering

- Required: `runtime.infrastructure`, `runtime.model-inference`, `trust.security-safety`, `trust.governance-agentops`, `trust.observability-finops`.
- Required when `task.orchestration` is selected: `execution.orchestration`.
- Production gate: current `trust.evaluation-assurance` evidence for the gateway release and selected route class.
- Optional downstream consumer: `runtime.experience`.
- Conflicts:
  - Unsigned or mutable route configuration.
  - Fallback across data-residency, license, capability, or evaluation boundaries.
  - External provider host in offline mode or without an explicit tenant-owned endpoint declaration.
  - Logging configuration that stores prompts or outputs without a classified, approved evidence plan.

Ordering: policy, identity trust, telemetry, model route readiness, then gateway route activation.

## Provider implementations

- `planeon.gateway`: mandatory baseline implementing the normalized routing and usage contracts as an independent clean-room target from released contracts and pre-recorded, digest-pinned observations; implementation cannot access, copy, adapt, translate, or derive code from a warm checkout.
- `planeon.litellm-local`: contract-only, non-installable compatibility guidance. It is rejected as `PROVIDER_UNAVAILABLE` if requested as an active selector.

The baseline is the only selectable gateway provider. A future LiteLLM adapter
requires an owned repository packet and conformance evidence before catalog
activation; compatibility guidance alone never causes image inclusion.

## Configuration and runtime boundaries

```yaml
routes:
  - id: string
    policyDigest: sha256:...
    kind: direct-model | task
    capability: chat | responses | embeddings | rerank
    targets: [signed-model-route-id]
    fallbackMode: disabled | pre-response-only
    timeoutSeconds: integer
    budgets:
      requestsPerMinute: integer
      inputTokensPerMinute: integer
      outputTokensPerMinute: integer
      concurrentRequests: integer
privacy:
  payloadTelemetry: disabled
  headerAllowlist: [string]
streaming:
  heartbeatSeconds: integer
  drainSeconds: integer
```

- Secrets: OIDC validation uses public issuer/JWKS material. Tenant-owned compatible endpoints use secret references resolved by the destination adapter, never gateway configuration values.
- RBAC: no Kubernetes API access; a namespaced service account with token automount disabled.
- Network: ingress from experience/runtime clients; egress only to selected model-plane endpoints, the execution task-admission endpoint when `task.orchestration` is selected, trust APIs, and tenant-local OTel. No knowledge endpoint is permitted. DNS and hosts are rendered from the profile.
- Storage: optional `gateway_idempotency` and `stream_cursor` tables in its owned runtime schema; TTL defaults to seven days and one hour respectively. No raw prompt/output column is permitted.

## APIs, events, and state

```text
POST /gateway/v1/invoke
POST /gateway/v1/embeddings
POST /gateway/v1/rerank
GET  /gateway/v1/routes
GET  /gateway/v1/routes/{id}
POST /internal/v1/routes:activate
GET  /health/ready
```

`/invoke` accepts a `capability`, logical `routeId`, payload, idempotency key, correlation ID, and optional SSE response. It never accepts a backend URL or secret.

The route kind is authoritative. `direct-model` calls `inference-api`. `task` calls `orchestration-api`, whose worker owns all retrieval, context assembly, model-step, and tool-step flow. The gateway never retrieves or assembles context on either branch.

Route-policy states: `DRAFT → VERIFIED → ACTIVE`; alternatives `REJECTED`, `SUPERSEDED`, `REVOKED`.

Request states: `ADMITTED → POLICY_PENDING → ROUTED → STREAMING → COMPLETED`; alternatives `DENIED`, `RATE_LIMITED`, `TIMED_OUT`, `CANCELLED`, `FAILED`.

Emitted:

- `gateway.route.activated.v1`
- `gateway.request.denied.v1`
- `gateway.request.completed.v1`
- `gateway.budget.exhausted.v1`
- `gateway.fallback.selected.v1`

Consumed: `model.route.activated.v1`, `model.route.rejected.v1`, `policy.bundle.activated.v1`, `module.release.revoked.v1`.

## Failures, retry, and rollback

- Identity, policy, budget, route-signature, capability, or evaluation failures deny before model invocation.
- Connect timeout is two seconds; normal request timeout defaults to 30 seconds and is profile bounded.
- The gateway retries at most two compatible targets only before response bytes and only for idempotent requests.
- Policy-decision failure is fail closed. Usage-ledger failure blocks requests whose budget cannot be proven; otherwise it emits a bounded local outbox and continues only if the profile explicitly permits delayed accounting.
- Orchestration loss disables `task.orchestration` routes immediately; signed direct-model routes remain available. Retrieval/tool failures are never interpreted by the gateway and are reported through task state by orchestration.
- Route activation is atomic and retains the previous active digest on failure.
- Revoked routes reject new work immediately; in-flight work follows the revocation policy (`cancel` by default for critical revocation).

## Evidence and readiness gates

- Identity and tenant-derivation tests.
- Signed route digest and policy decision record.
- Budget correctness under concurrent requests.
- No-payload telemetry and log inspection.
- Fallback compatibility evidence.
- Streaming cancellation and partial-response behavior.
- Offline network-denial proof.
- Dependency readiness for every referenced model route.
- Branch proof that direct-model reaches inference without orchestration and task reaches orchestration without a gateway-to-knowledge/tool call.

The gateway is ready only when at least one signed, admitted model route is ready and policy/usage dependencies pass their health gates.

## Profile behavior

- `minimal-local`: one route, fallback disabled, in-memory concurrency limiter plus durable usage ledger.
- `enterprise`: multiple signed compatible routes, replicated gateway, PostgreSQL idempotency, strict budgets.
- `airgap-enclave`: local routes only, external endpoints schema-denied, no payload telemetry or remote JWKS dependency after trust import.

## Tests

- Unit: route matching, budget windows, capability checks, header filtering, fallback ordering.
- Contract: API schemas, SSE frames, idempotency, CloudEvents, model-plane compatibility.
- Security: caller-supplied tenant spoofing, unsigned routes, SSRF, header injection, secret/payload leakage.
- Failure: OPA outage, ledger outage, orchestration loss with direct-model continuity, backend pre-stream/post-stream failure, route revocation, drain timeout.
- Load: concurrency and token budget races with deterministic outcomes.
- Air gap: all requests succeed or fail for declared local reasons with egress denied.

## Sol-high implementation packets

1. `RUN-001-common-edge`: authenticated tenant context, API/error/idempotency envelope, OTel, RLS migrations, non-root image, and contract mocks shared by the gateway.
2. `RUN-GW-001-routing`: signed logical routes, policy/guardrail calls, deterministic target choice, atomic budget reservation, model/execution adapters, and usage events. LiteLLM remains non-installable comparative guidance outside this packet.
3. `RUN-GW-002-streaming`: SSE, cancellation, bounded buffers, timeouts, backpressure, pre-response-only fallback, and no-content observability.
4. `RUN-002-security-resilience`: tenant isolation, duplicate calls, OPA/ledger/model outages, last-known-good routes, audit correlation, SSRF denial, and offline egress tests.

Packets may change only runtime-plane paths plus a pinned contracts upgrade; all routing policy changes require shared golden-vector updates first.
