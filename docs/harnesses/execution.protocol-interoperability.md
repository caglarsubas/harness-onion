# Harness Specification: `execution.protocol-interoperability`

## Contract

| Field | Value |
|---|---|
| Plane | Execution |
| Owning repository | `mas-harness-execution-plane` |
| Public warm source | `data-source-harness`; non-public planning input metadata omitted |
| API version | `harness.planeon.ai/v1alpha1` |

## Capabilities and non-goals

This harness registers, validates, negotiates, and invokes agent/tool/service capabilities through MCP, A2A, OpenAPI, and AsyncAPI adapters. It normalizes authentication, capability discovery, schema validation, correlation, cancellation, and protocol evidence behind tenant-local contracts.

It does not orchestrate multi-step workflows, grant tool authorization, execute untrusted code, own business state, expose arbitrary URLs supplied by callers, or translate unsupported semantics by silently dropping them.

## Owner and deployables

- `protocol-gateway`: endpoint registry, capability projection, transport handling, auth brokering, validation, and evidence.
- Adapter images/modules: `adapter-mcp`, `adapter-a2a`, `adapter-openapi`, and `adapter-asyncapi`, independently selectable.

The governed MCP broker and protocol profiles are independent clean-room targets
derived only from released contracts and pre-recorded, digest-pinned golden
vectors; implementation cannot access, copy, adapt, translate, or derive code
from a warm checkout.

## Dependencies, conflicts, and ordering

- Required: `runtime.infrastructure`, `trust.security-safety`, `trust.governance-agentops`, `trust.observability-finops`.
- Optional: `execution.orchestration`, `execution.tool-skill-sandbox`, `runtime.experience`.
- Conflicts:
  - Endpoint scheme/host outside its rendered network intent.
  - Capability schema missing, mutable, or incompatible with the selected adapter revision.
  - Protocol translation that cannot preserve cancellation, auth, task, or error semantics required by the demand.
  - Direct credential material in endpoint configuration.
  - Stateful MCP behavior where the selected profile permits only stateless requests.

Registry/policy activation precedes endpoint availability; orchestration/tool consumers start after required endpoint health.

## Provider implementations

| Provider ID | Protocol baseline |
|---|---|
| `planeon.mcp` | Stateless MCP `2026-07-28`; compatibility adapter for `2025-11-25` |
| `planeon.a2a` | A2A v1.0 task/capability semantics |
| `planeon.openapi` | OpenAPI 3.1 operations projected as typed capabilities |
| `planeon.asyncapi` | AsyncAPI 3.x publish/subscribe capabilities for tenant-local brokers |

Deprecated MCP Roots, Sampling, or Logging are not new service dependencies. Compatibility shims are read/translate boundaries and cannot define canonical contracts.

## Configuration and runtime boundaries

```yaml
endpoints:
  - id: string
    protocol: mcp | a2a | openapi | asyncapi
    revision: string
    endpoint: https-or-internal-uri
    serverIdentity: string
    credentialSecretRef: {name: string, keyMapping: {}}
    capabilityManifestDigest: sha256:...
    allowedCapabilities: [string]
    timeoutSeconds: integer
    maxConcurrency: integer
    networkIntentId: string
    dataClassifications: [string]
translation:
  rejectLossyRequiredSemantics: true
```

- Secrets: endpoint credentials are references resolved into an outbound request; they are never returned to callers or recorded in events.
- RBAC: no Kubernetes API access. Registry roles separate `endpoint:register`, `endpoint:approve`, `capability:discover`, and `capability:invoke`.
- Network: ingress from orchestration, tool broker, and approved clients; egress only to declared endpoint hosts, policy, registry, and OTel. SSRF defenses validate resolved IPs against allowed CIDRs at connection time.
- Storage: endpoint metadata, immutable capability manifests, health state, idempotency/inbox records, and non-payload invocation receipts in protocol-owned execution tables.

## APIs, events, and state

```text
POST /protocol/v1/endpoints
GET  /protocol/v1/endpoints/{id}
POST /protocol/v1/endpoints/{id}:validate
POST /protocol/v1/endpoints/{id}:activate
GET  /protocol/v1/endpoints/{id}/capabilities
POST /protocol/v1/capabilities/{id}:invoke
POST /protocol/v1/invocations/{id}:cancel
GET  /protocol/v1/invocations/{id}
```

Endpoint states: `DECLARED → VALIDATING → VERIFIED → ACTIVE`; alternatives `INCOMPATIBLE`, `DEGRADED`, `DISABLED`, `REVOKED`.

Invocation states: `ACCEPTED → NEGOTIATING → RUNNING → SUCCEEDED`; alternatives `INPUT_REQUIRED`, `AUTH_REQUIRED`, `CANCELLED`, `TIMED_OUT`, `FAILED`, `OUTCOME_UNKNOWN`.

Emitted:

- `protocol.endpoint.verified.v1`
- `protocol.endpoint.degraded.v1`
- `protocol.capability.changed.v1`
- `protocol.invocation.started.v1`
- `protocol.invocation.completed.v1`
- `protocol.invocation.failed.v1`

Consumed: registry release/revocation, policy-bundle activation, secret-version notification, and cancellation requests.

## Failures, retry, and rollback

- Schema, identity, host, protocol-revision, or required-semantic mismatch rejects activation.
- Read-only idempotent invocation may retry three times before a remote acknowledgement. Non-idempotent capabilities never retry without a declared idempotency mechanism/receipt.
- A connection failure after possible remote execution produces `OUTCOME_UNKNOWN`, not `FAILED`.
- Cancellation is best effort at the protocol boundary; the receipt reports whether remote cancellation was acknowledged.
- Endpoint manifest activation is atomic and retains last-known-good capability projection.
- Adapter upgrade uses golden protocol traces; rollback restores the prior adapter/image and manifest projection.
- Protocol degradation never broadens allowed capability sets or network intents.

## Evidence and readiness gates

- Server identity, endpoint custody, protocol revision, manifest digest, and license.
- Capability schema and required-semantic compatibility.
- Authentication, tenant propagation, correlation, cancellation, timeout, and error mapping.
- SSRF/DNS-rebinding and secret-redaction results.
- Idempotency or non-idempotent receipt classification.
- Network-policy enforcement and offline availability.
- Compatibility traces for each supported protocol revision.

Production endpoints require verified identity, approved capabilities, passing policy, and a current conformance run.

## Profile behavior

- `minimal-local`: MCP/OpenAPI adapter, static signed registry, local endpoints only.
- `enterprise`: multiple adapters, HA gateway, dynamic health, credential rotation, and policy-based capability projection.
- `airgap-enclave`: internal endpoints only, vendored manifests/schemas, no remote discovery.

## Tests

- Independent clean-room parity against pre-recorded, digest-pinned vectors: governed MCP broker, protocol profiles, tenant context, idempotency, and receipts; no warm checkout access.
- Unit: manifest normalization, capability projection, error/state mapping, revision negotiation.
- Contract: MCP/A2A/OpenAPI/AsyncAPI golden traces and CloudEvents.
- Security: SSRF, DNS rebinding, credential reflection, tenant spoofing, schema bombs, unauthorized discovery/invoke.
- Failure: remote timeout, partial acknowledgement, cancellation race, duplicate events, adapter restart.
- Air gap: discovery/invoke against local fixtures with all external egress denied.

## Sol-high implementation packets

1. `EXEC-001-foundation`: common execution kernel, tenant DB roles/RLS, inbox/outbox, task/event contracts, images, and state-model test harness.
2. `EXEC-PROT-001`: endpoint/capability lifecycle, SSRF/auth controls, receipts, stateless MCP/current and prior revision, A2A v1, OpenAPI/AsyncAPI adapters, semantic negotiation, cancellation, and golden traces.
3. `EXEC-002-resilience`: duplicate/out-of-order events, ambiguous acknowledgements, adapter crashes, endpoint outages, tenant isolation, and air-gap invocation campaign.

Each adapter packet builds a separate artifact and must prove semantic parity or emit a compile-time incompatibility finding.
