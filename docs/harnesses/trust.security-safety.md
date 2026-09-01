# Harness Specification: `trust.security-safety`

## Contract

| Field | Value |
|---|---|
| Plane | Trust and lifecycle |
| Owning repository | `mas-harness-trust-plane` |
| Warm-source disposition | Non-public planning input metadata omitted; implementation access prohibited |
| API version | `harness.planeon.ai/v1alpha1` |

## Capabilities and non-goals

This harness establishes workload/user identity, tenant derivation, authorization, policy decisions, supply-chain verification, secret-reference admission, and input/output/runtime guardrails. It is the fail-closed enforcement boundary for data, model, protocol, tool, route, and deployment operations.

It does not define business accountability, approve exceptions, operate the AgentOps registry, measure model quality, or replace Kubernetes isolation. Security policy and guardrail verdicts are evidence inputs to governance, not governance decisions themselves.

## Owner and deployables

- `policy-decision`: OPA-based authorization and admission decision API.
- `guardrail-service`: deterministic/classifier-based input, output, and runtime checks.
- The `bundle-verifier` is owned by `runtime.infrastructure`/distribution; this harness consumes its verified artifact evidence and does not own another verifier image.

OIDC is an explicit tenant/operator-supplied external prerequisite; no Keycloak
chart is cataloged. OpenBao, SPIRE, and Presidio are deferred comparative
candidates, not installable or selectable modules in this release.

## Dependencies, conflicts, and ordering

- Required: `runtime.infrastructure`, `trust.observability-finops` for production evidence; security can bootstrap with a local bounded audit sink before observability is ready.
- Optional: `trust.governance-agentops`, `trust.evaluation-assurance` and every protected harness.
- Conflicts:
  - Caller-supplied tenant identity accepted without cryptographic binding.
  - Fail-open policy for tools, mutations, route activation, deployment, or restricted data.
  - Secret value in profile/config/event/evidence.
  - Unsigned/mutable policy or release artifact.
  - Remote guardrail/provider required by an offline profile.
  - Shared `pool` isolation where policy requires silo.

Trust roots, issuer material, baseline policies, and audit sink start before protected services.

## Provider implementations

- `planeon.policy-decision`: mandatory authorization and admission service, backed by the cataloged `external.opa-engine` prerequisite.
- Capability `identity.oidc` is fulfilled through the cataloged `external.oidc-provider` prerequisite and explicit tenant attestation; there is no `planeon.oidc` module or bundled Keycloak chart.
- `planeon.cosign`: offline self-managed Ed25519 signature verification.
- `planeon.guardrails.rules`: deterministic schema, size, allow/deny, data-classification, and secret/PII rules.

Presidio, OpenBao, and SPIRE require catalog records, repository packets, and
conformance evidence before they can become selectable; current guidance does
not install them.

No paid moderation, identity, secret, or transparency service is required.

## Configuration and runtime boundaries

```yaml
identity:
  issuers:
    - issuer: string
      audiences: [string]
      tenantClaim: string
      subjectClaim: string
      rolesClaim: string
      jwksMode: vendored | internal-endpoint
policy:
  bundleRef: oci@sha256:...
  failClosedOperations: [deploy, route-change, tool, mutation, restricted-read]
guardrails:
  inputPolicyIds: [string]
  outputPolicyIds: [string]
  runtimePolicyIds: [string]
  maximumPayloadBytes: integer
  payloadRetention: disabled
supplyChain:
  trustManifestRef: oci@sha256:...
  revocationListRef: oci@sha256:...
secrets:
  providers: [kubernetes]
```

- Secrets: service credentials are references. Trust private keys never enter the cluster build/CI path; only public keys and signed revocation/trust manifests are mounted.
- RBAC: policy/guardrail services have no cluster-admin access. Bundle verification reads declared artifacts/trust data. Identity administration is isolated from application roles.
- Network: ingress from protected services; egress to the policy engine, allowed issuer/JWKS, audit, and OTel endpoints declared by the locked profile. Offline profiles use vendored JWKS/trust data.
- Storage: immutable policy/trust artifacts in OCI; active digests and non-payload decisions in security-owned trust tables/outbox. Guardrail payload retention is off; optional classified evidence stores digest/redacted excerpt under an approved evidence plan.

## APIs, events, and state

```text
POST /trust/v1/policy:decide
POST /trust/v1/guardrails:evaluate
POST /trust/v1/artifacts:verify
GET  /trust/v1/policies/active
GET  /trust/v1/trust-manifests/active
GET  /trust/v1/decisions/{id}
```

Policy/trust bundle states: `DRAFT → VALIDATING → VERIFIED → ACTIVE`; alternatives `REJECTED`, `SUPERSEDED`, `REVOKED`.

Decision outcomes: `ALLOW`, `DENY`, `CHALLENGE`, `REDACT`, `QUARANTINE`, `ERROR_FAIL_CLOSED`.

Emitted:

- `policy.bundle.activated.v1`
- `policy.denied.v1`
- packet-local `planeon.trust.guardrail-evaluation.recorded.v1alpha1` outbox
  classification; this is internal metadata and is not represented as a public
  HarnessCloudEvent until that type exists in the contracts repository
- `artifact.verification.failed.v1`
- `trust.manifest.rotated.v1`
- `security.dependency.unavailable.v1`

Consumed: signed bundle/profile release, module revocation, approval/waiver expiry, and identity/secret rotation notifications.

## Failures, retry, and rollback

- Invalid identity, signature, digest, issuer, secret reference, or policy input fails closed.
- Read-only low-risk operations may follow a profile-declared bounded cached-decision policy; tools, mutations, route changes, and deployments never do.
- Policy queries retry three times within the caller timeout. If no authoritative answer is available, return `ERROR_FAIL_CLOSED`.
- Policy activation is atomic and retains last-known-good verified bundle.
- Critical revocation is applied immediately to new operations and emits dependency revocation events.
- Trust-key rotation requires an overlap manifest signed by the prior trusted key; rollback cannot reactivate a revoked key.
- Guardrail failure cannot return an uninspected payload. Streaming output is buffered into bounded chunks and stops on denial.
- Audit decision loss blocks protected state changes rather than silently dropping evidence.

## Evidence and readiness gates

- OIDC issuer/audience/claim and tenant-derivation tests.
- Authorization matrix and policy decision golden vectors.
- Guardrail precision/recall fixtures appropriate to selected languages/data classes.
- Signature, digest, SBOM, license, trust rotation, and revocation verification.
- Secret-reference validation and redaction campaign.
- Fail-closed dependency outage and cached-decision boundaries.
- RBAC, network, pod-security, cross-tenant, prompt injection, output injection, and data-exfiltration tests.
- Current owner/approval for every active policy bundle.

## Profile behavior

- `minimal-local`: OPA prerequisite, static local OIDC/JWKS, rule guardrails, Kubernetes Secrets, and offline Cosign verification.
- `enterprise`: HA policy/guardrail services, explicitly attested tenant OIDC and OPA prerequisites, signed policy promotion, and revocation.
- `airgap-enclave`: vendored JWKS/policies/trust/revocation; no keyless/transparency-network dependency; all guardrail models local.

## Tests

- Independent clean-room parity against pre-recorded, digest-pinned vectors: signed admission, MCP broker guards, guardrail contracts, policy/audit patterns, and release verification; no warm checkout access.
- Unit: identity derivation, decision inputs, bundle selection, trust rotation, redaction.
- Contract: all protected-service clients, APIs/events, decision golden vectors.
- Security: auth bypass, confused deputy, tenant spoofing, SSRF, prompt/tool injection, secrets, signature downgrade, revoked artifacts.
- Failure: OPA/JWKS/secret/audit/OTel outage, stale bundle, partial output stream, concurrent rotation.
- Air gap: identity, policy, guardrails, and signature verification with external network denied.

## Sol-high implementation packets

1. `TRUST-001-foundation`: tenant OIDC admission, DB roles/RLS, signed policy activation, OPA decision API, audit/outbox, and fail-closed tests.
2. `TRUST-002-guardrails`: input/output/runtime profiles, deterministic detectors, streaming evaluation, redaction, evidence, and SDK conformance. Presidio remains non-installable comparative guidance outside this packet.
3. `DIST-003-sign-promote`: offline Ed25519 Cosign ceremony, component/root signatures, trust-key overlap/rotation, revocation, and candidate/released separation.
4. `OP-002-preflight-verification`: installer-side checksum/signature/revocation/license verification and fail-before-apply behavior.
5. `TRUST-003-resilience-security`: OPA/identity/DB/audit outages, forged evidence/artifacts, cross-tenant denial, stale/revoked policy, and air-gap startup.

Every packet must leave private signing keys and secret values outside source, CI artifacts, events, and logs.

### Closed TRUST-002 service contract

TRUST-002 implements the SDK-006 contract as a tenant-facing service without
expanding its detector semantics. It pins the SDK-006 commit and reproducible
wheel digest, the contracts release manifest, and the EvidenceRecord schema.
The product owns independent fixtures; it does not copy the SDK fixture corpus
or mount any SDK, contracts, or warm-source checkout during implementation or
acceptance.

| Operation | Exact body | Result/state |
|---|---|---|
| `POST /trust/v1/guardrails:evaluate` | `profileId`, `content` | SDK result plus content-free decision/evidence metadata |
| `POST /trust/v1/guardrails/streams` | `profileId` | opaque tenant-bound stream, `OPEN`, next sequence `1` |
| `POST /trust/v1/guardrails/streams/{streamId}:push` | `sequence`, non-empty `content` | cumulative bounded evaluation and next sequence |
| `POST /trust/v1/guardrails/streams/{streamId}:finish` | `sequence` | final evaluation and `FINISHED` |

Bearer identity is verified by the TRUST-001 OIDC boundary, and organization is
never read from a body, path, header override, profile selector, or stream ID.
The active signed profile fixes stage and limits. Profiles use tenant-bound
Ed25519 signatures with purpose `GUARDRAIL_PROFILE`, monotonic versions,
predecessor digests, validity, revocation, atomic activation, and one eligible
last-known-good rollback. INPUT and RUNTIME are always `FAIL_CLOSED`.
OUTPUT/STREAMING `FAIL_OPEN` is explicit, but a detector error stays degraded
and non-releasing. Only `ALLOW` and `REDACT` release a result.

Only closed deterministic local detectors are registered. They are synchronous,
bounded by the profile content limit, and have no I/O, network, subprocess,
model, plugin, provider, download, secret, or telemetry capability. The service
does not pretend a non-cancellable in-process Python callback has a safe timeout;
instead it excludes arbitrary/untrusted callbacks and tests throwing, missing,
duplicate, and malformed detectors through the SDK fail-mode contract.

Streaming retains a cumulative buffer only in process: maximum 1,048,576 UTF-8
bytes, 128 open sessions per tenant, and a 60-second idle TTL. `OPEN` transitions
to `TERMINATED` on DENY, QUARANTINE, or ERROR_FAIL_CLOSED; to `FINISHED` on
finish; or to `EXPIRED` on TTL/capacity eviction. Every terminal transition
clears raw content. Cross-tenant access, non-monotonic sequence, replay, and
post-terminal calls fail with stable content-free codes.

Persistence is one atomic metadata-only decision, audit, and EvidenceRecord
candidate write. Evidence stays `RECEIVED` on axis `SECURITY`; it is not
`VERIFIED` evidence, governance approval, certification, promotion, deployment
proof, runtime proof, or tenant acceptance. Raw and redacted content, token
claims, subject identity, exception detail, private keys, and secret values are
forbidden from storage, events, evidence, telemetry, logs, and captured output.
The immediate REDACT response is the only place sanitized content may appear.
