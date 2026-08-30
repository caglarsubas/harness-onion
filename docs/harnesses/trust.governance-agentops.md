# Harness Specification: `trust.governance-agentops`

## Contract

| Field | Value |
|---|---|
| Plane | Trust and lifecycle |
| Owning repository | `mas-harness-trust-plane` |
| Warm-source disposition | Non-public planning input metadata omitted; implementation access prohibited |
| API version | `harness.planeon.ai/v1alpha1` |

## Capabilities and non-goals

This harness owns accountability and lifecycle governance: autonomy levels, accountable owners, approvals, N-of-M review, waivers/exceptions, control requirements, agent/tool/workflow/module registry, maturity, promotion, deprecation, revocation, and append-only audit references.

It does not authenticate identities, execute guardrails, collect raw telemetry, run evaluations, install modules, or turn a waiver into a passing control. Security produces enforcement decisions; assurance produces evidence; governance decides whether the declared evidence satisfies promotion policy.

## Owner and deployables

- `governance-service`: approval, waiver, autonomy, control requirement, and promotion gate API.
- `registry-service`: agent/workflow/tool/module/provider versions, maturity, compatibility, deprecation, and revocation.

AML catalog, policy/audit, evaluation linkage, approval, release-validation,
MCP/HITL, and promotion concepts are independent clean-room targets derived
only from released contracts and pre-recorded, digest-pinned observations;
implementation cannot access, copy, adapt, translate, or derive code from a
warm checkout. GCP, Cloud Build, Terraform, Stripe, hosted providers, and
monolithic Prisma history are excluded.

## Dependencies, conflicts, and ordering

- Required: `runtime.infrastructure`, `trust.security-safety`, `trust.observability-finops`.
- Optional: `trust.evaluation-assurance` and all governed harnesses.
- Conflicts:
  - Same actor requests and solely approves a restricted action where separation of duties is required.
  - Waiver without control ID, approver, justification, compensating control, and expiry.
  - Production promotion with missing/stale/failed mandatory evidence.
  - Revoked module/tool/workflow referenced by a new locked profile.
  - Autonomy level exceeding industry-pack/risk maximum.

Registry validation, controls, owners, and promotion policy precede module/profile production approval.

## Provider implementations

- `planeon.governance`: native PostgreSQL-backed governance service using OPA decision integration.
- `planeon.registry`: native PostgreSQL-backed registry service.

AgentOps compatibility is deferred, non-installable comparative guidance; no
cataloged adapter imports warm-source objects. No proprietary GRC, ticketing,
or workflow SaaS is required. Future adapters need catalog and packet ownership.

## Configuration and runtime boundaries

```yaml
governance:
  autonomyLevels:
    - id: observe | recommend | approve-before-act | bounded-autonomous
      maximumRisk: string
      requiredControls: [string]
  approvals:
    policies:
      - id: string
        quorum: integer
        eligibleRoles: [string]
        separationOfDuties: boolean
        expiresSeconds: integer
  waivers:
    maximumDurationSeconds: integer
    renewable: false
registry:
  maturityStates: [DRAFT, VALIDATED, CERTIFIED, DEPRECATED, RETIRED, REVOKED]
  requireSignedArtifacts: true
  requireCurrentEvidence: true
```

- Secrets: none in governance objects. External identity is derived by security; optional notification endpoints require separate connectors and secret references.
- RBAC: granular roles for request, approve, waive, register, validate, promote, deprecate, revoke, and audit view. Service identities cannot approve their own promotion.
- Network: ingress from control and governed services; egress to policy, evidence, registry artifact verifier, PostgreSQL, and OTel.
- Storage: governance-owned trust tables for controls, approvals, waivers, registry versions, transitions, and audit references. Evidence payload remains evidence-service-owned; governance stores immutable evidence IDs/digests/status/freshness.

## APIs, events, and state

```text
POST /trust/v1/approvals
GET  /trust/v1/approvals/{id}
POST /trust/v1/approvals/{id}:decide
POST /trust/v1/waivers
POST /trust/v1/waivers/{id}:revoke
GET  /trust/v1/controls/{id}/status
POST /trust/v1/registry/releases
POST /trust/v1/registry/releases/{id}:validate
POST /trust/v1/registry/releases/{id}:promote
POST /trust/v1/registry/releases/{id}:deprecate
POST /trust/v1/registry/releases/{id}:revoke
```

Approval states: `REQUESTED → APPROVED | REJECTED | EXPIRED | CANCELLED`.

Waiver states: `REQUESTED → ACTIVE → EXPIRED`; alternatives `REJECTED`, `REVOKED`.

Module/release states: `DRAFT → VALIDATED → CERTIFIED → DEPRECATED → RETIRED`; alternative `REVOKED` from any post-draft state.

Emitted:

- `approval.requested.v1`
- `approval.decided.v1`
- `waiver.activated.v1`
- `waiver.expired.v1`
- `module.release.certified.v1`
- `module.release.revoked.v1`
- `governance.promotion.denied.v1`

Consumed: evidence recorded/stale, policy denied, artifact verification, evaluation run, bundle/profile request, and task/tool approval requests.

## Failures, retry, and rollback

- Mutations require idempotency keys and ETag/expected version. Conflicting decisions return `409` and preserve the first terminal transition.
- Approval dependency loss pauses the operation; it never implies approval.
- Evidence store loss prevents promotion when current evidence cannot be proven.
- Expiry worker is idempotent; expired approval/waiver cannot authorize new operations.
- Promotion changes an immutable active pointer; failure retains the prior certified release.
- Revocation is append-only and cannot be rolled back. Replacement requires a new release/version and approval.
- Governance service rollback must preserve newer decisions, revocations, and expiries through expand/contract migrations.
- Notification failure does not change approval state; it is reported separately.

## Evidence and readiness gates

- Named accountable business, technical, data, security, and operational owners appropriate to risk.
- Complete control-to-evidence mapping and freshness.
- Separation-of-duties and quorum enforcement.
- Waiver content, compensating control, maximum duration, expiry, and downstream invalidation.
- Registry artifact/signature/license/compatibility/conformance link.
- Autonomy-risk mapping and bounded action policy.
- Promotion, rejection, deprecation, revocation, and audit-chain tests.

No production promotion may convert `NOT_RUN_ENV_UNAVAILABLE`, missing,
collecting, warning, stale, waived, or failed evidence into `PASS`. Even a
valid, signed, scope-exact waiver only documents the exception and keeps
promotion blocked until every required control has fresh `PASS` evidence.

## Profile behavior

- `minimal-local`: one accountable owner plus explicit approval for mutations, simple registry, no autonomous write actions.
- `enterprise`: role/quorum separation, multiple control frameworks, waivers, promotion rings, and native registry lifecycle.
- `airgap-enclave`: local identity/approvers and signed control/evidence bundles; no external ticketing or notification dependency.

## Tests

- Independent clean-room parity against pre-recorded, digest-pinned vectors: catalog/maturity, approvals, N-of-M, policy/audit, release validation, evaluation linkage, and rollback recommendations; no warm checkout access.
- Model-based: approval, waiver, release, revocation, and concurrent transition state machines.
- Contract: control, evidence, profile, tool/task, operator, and registry APIs/events.
- Security: self-approval, role escalation, replay, tenant crossover, stale evidence, audit tampering.
- Failure: evidence/policy/database/notification outage, expiry during execution, duplicate decisions.
- Migration: exercise independently authored compatibility fixtures without warm-checkout access or monolith-specific ID/schema coupling. AgentOps import remains non-installable comparative guidance.

## Sol-high implementation packets

1. `TRUST-001-foundation`: shared OIDC tenant admission, trust DB roles/RLS, policy/audit/outbox, and fail-closed foundations.
2. `TRUST-GOV-001`: controls, approval/quorum/separation of duties, autonomy, expiring waivers, compensating controls, exceptions, immutable audit references, and policy linkage.
3. `TRUST-REG-001`: clean-room canonical registry implementation, certification axes, evidence gates, maturity, promotion, deprecation, revocation, and signed release admission.
4. `TRUST-003-resilience-security`: evidence/policy/DB outages, forged evidence, waiver expiry, duplicate decisions, self-approval and cross-tenant denial, and air-gap startup.

Each packet separates governance decisions from security verdicts and assurance evidence ownership.
