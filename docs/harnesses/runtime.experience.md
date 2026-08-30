# Harness Specification: `runtime.experience`

## Contract

| Field | Value |
|---|---|
| Plane | Runtime |
| Owning repository | `mas-harness-runtime-plane` |
| API version | `harness.planeon.ai/v1alpha1` |

## Capabilities and non-goals

This harness exposes governed human interaction: session creation, resumable streaming, task input, approval presentation, cancellation, evidence links, and an accessible reference web client. It normalizes channel events so a tenant can replace the reference UI without changing orchestration.

It does not execute models or tools, own workflow state, decide approvals, retain long-term memory, act as the enterprise setup portal, or provide consumer social/messaging connectors in the baseline.

## Owner and deployables

- `experience-gateway`: authenticated session and resumable SSE event boundary. WebSocket is deferred comparative guidance and is not a cataloged transport module.
- `reference-channel-ui`: self-hosted Next.js 16.3.3 App Router and TypeScript
  application for tasks, input requests, approvals, citations, evidence, and
  cancellation. All assets are locally bundled for air-gapped operation.

The setup portal remains in `mas-harness-control-plane`; this UI is the tenant runtime channel.

## Dependencies, conflicts, and ordering

- Required: `runtime.infrastructure`, `runtime.ai-gateway`, `trust.security-safety`, `trust.governance-agentops`, `trust.observability-finops`.
- Required only when `task.orchestration` is selected: `execution.orchestration`.
- Optional: `knowledge.retrieval-context`, `knowledge.memory-state`, `trust.evaluation-assurance`.
- Conflicts:
  - Anonymous access for non-public profiles.
  - Shared session stores across silo tenants.
  - Channel adapter that cannot preserve approval, cancellation, evidence, and correlation semantics.
  - Payload retention without classification, TTL, and user deletion policy.

Ordering: identity, governance, and runtime routes precede the experience gateway/UI; orchestration precedes it only for the selected `task.orchestration` capability.

## Provider implementations

- `planeon.experience.sse`: mandatory reference API using HTTP and resumable SSE.
- `planeon.experience.agui`: optional AG-UI-compatible translation module, packaged independently.
- `planeon.experience.web`: reference React UI.

No third-party messaging SaaS is part of the default provider catalog.

## Configuration and runtime boundaries

```yaml
auth:
  issuer: string
  audience: string
  clientId: string
sessions:
  idleTtlMinutes: integer
  maximumTtlHours: integer
  replayWindowMinutes: integer
streaming:
  transport: sse
  heartbeatSeconds: integer
  maxBufferedEvents: integer
ui:
  basePath: string
  contentSecurityPolicy: string
  evidenceLinks: enabled | disabled
retention:
  payloadMode: none | classified
  classifiedTtlHours: integer
```

- Secrets: OIDC client secret, when needed, is a secret reference. Browser clients use authorization code with PKCE and never receive service credentials.
- RBAC: no Kubernetes API access. Runtime roles map to `task:view`, `task:submit`, `task:cancel`, `approval:view`, and `approval:act`; approval action is separately authorized.
- Network: ingress from tenant users/ingress; egress only to orchestration, governance, gateway, evidence, and OTel endpoints.
- Storage: `experience_session`, `experience_event_cursor`, and bounded redacted display projections in an experience-owned schema. Cursor TTL is bounded; raw prompt/response/context persistence and long-term memory are prohibited here. Classified source content remains in its owning service and is displayed only through authorized, expiring references.

## APIs, events, and state

```text
POST /experience/v1/sessions
GET  /experience/v1/sessions/{id}
GET  /experience/v1/sessions/{id}/events
POST /experience/v1/sessions/{id}/tasks
POST /experience/v1/tasks/{id}/input
POST /experience/v1/tasks/{id}/cancel
GET  /experience/v1/approvals
POST /experience/v1/approvals/{id}:decide
GET  /experience/v1/evidence/{id}
```

SSE frames contain event ID, type, timestamp, correlation ID, task ID, redacted display payload, and evidence references. `Last-Event-ID` resumes within the configured replay window.

Session states: `CREATED → ACTIVE → IDLE → CLOSED`; exceptions `EXPIRED`, `REVOKED`.

Emitted:

- `experience.session.created.v1`
- `experience.input.submitted.v1`
- `experience.task.cancel.requested.v1`
- `experience.approval.decided.v1`

Consumed:

- `task.state.changed.v1`
- `approval.requested.v1`
- `approval.decided.v1`
- `evidence.recorded.v1`
- `policy.denied.v1`

## Failures, retry, and rollback

- Session creation and task submission require idempotency keys.
- Duplicate approval decisions return the original terminal decision; conflicting duplicates return `409`.
- Disconnected clients resume via `Last-Event-ID`; events older than the window produce `410` plus the current task snapshot endpoint.
- Gateway/orchestrator unavailability returns a stable dependency reason and never fabricates task completion.
- Orchestration loss disables task submission/input/resume/cancel immediately, while session replay, approvals/evidence display, and direct-model interactions through the AI gateway remain available.
- Approval service failure disables action controls and remains fail closed.
- UI rollout is stateless and rolls back by image digest. Database changes use expand/contract.
- Payload deletion is idempotent and records a non-payload audit receipt.

## Evidence and readiness gates

- OIDC/PKCE and tenant identity validation.
- WCAG 2.2 AA checks for keyboard, focus, status changes, contrast, and approval affordances.
- Stream resume, duplicate event, out-of-order event, and snapshot recovery evidence.
- Approval identity, reason, expiry, and evidence-link display.
- CSP, CSRF, XSS, clickjacking, and secret/payload leakage tests.
- Session and classified-payload retention/deletion proof.
- Offline asset and font closure.

Production readiness requires an accessible UI audit, complete auth flows, replay behavior, and no external asset dependency.

## Profile behavior

- `minimal-local`: reference UI, one replica, SSE, short replay, no persisted payload.
- `enterprise`: replicated gateway, durable cursor store, HA ingress, classified retention only when approved.
- `airgap-enclave`: all assets bundled, local issuer/JWKS import, no CDN, analytics, external fonts, or messaging adapter.

## Tests

- Unit: session TTL, role mapping, event projection, redaction, conflict decisions.
- Contract: API, SSE, task/orchestration, approval/governance, and evidence links.
- Browser: submit, stream, disconnect/resume, provide input, approve/reject, cancel, inspect citation/evidence.
- Accessibility: automated checks plus keyboard and screen-reader-oriented scenarios.
- Security: XSS payloads, CSRF, tenant crossover, stolen cursor, replay outside TTL.
- Failure: orchestration, governance, database, and OTel outage behavior.
- Air gap: UI renders with network restricted to selected tenant services.

## Sol-high implementation packets

1. `RUN-001-common-edge`: authenticated tenant context, common errors/idempotency, OTel, experience-owned RLS tables, non-root images, and contract mocks.
2. `RUN-EXP-001-interactions`: sessions, replayable SSE, input-required/resume/cancel, approval/evidence projection, retention, reference web client, accessibility, and optional AG-UI translation.
3. `RUN-002-security-resilience`: tenant isolation, duplicate submissions/decisions, dependency outages, replay security, payload redaction, audit correlation, and offline asset/egress tests.

Each packet changes only named runtime-plane UI/gateway paths, contains browser and contract fixtures, and introduces no external hosted asset or analytics endpoint.
