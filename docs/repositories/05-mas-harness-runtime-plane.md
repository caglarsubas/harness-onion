# Repository Plan: `mas-harness-runtime-plane`

## Purpose and boundaries

This repository implements the tenant request edge: an AI gateway for authenticated/rate- and budget-governed routing, and an experience gateway for interaction sessions, resumable server-sent events, input requests, and reference channel adapters. It owns `runtime.ai-gateway` and `runtime.experience`.

Non-goals:

- No model execution, retrieval/indexing, workflow scheduling, tool execution, policy authoring, evidence authority, tenant setup, or Kubernetes reconciliation.
- It does not invent tenant identity, retain raw prompts by default, or route to hosted providers.
- The control plane is never called synchronously from a tenant request.

## Repository structure and exact tree

This tree projects the current task-packet `allowedPaths`. Directory entries do not authorize edits beyond the packet executed in a coding run.

```text
mas-harness-runtime-plane/
├── .github/workflows/verify.yml
├── .gitignore
├── AGENTS.md
├── CONTRIBUTING.md
├── LICENSE
├── NOTICE
├── README.md
├── SECURITY.md
├── PORTING.yaml
├── Makefile
├── pyproject.toml
├── uv.lock
├── ci/
├── src/planeon_runtime/common/
├── services/
│   ├── ai-gateway/
│   │   ├── src/{adapters,cancellation,policy,routing,streaming,usage}/
│   │   └── tests/{routing,streaming}/
│   └── experience-gateway/
│       ├── src/
│       └── tests/
├── migrations/
│   └── interaction/
├── deploy/helm/
├── reference-client/
│   └── src/app/
├── fixtures/{failures,interactions,routing,streaming}/
├── scripts/run_failure_campaign.py
├── docs/
│   ├── experience.md
│   ├── streaming.md
│   └── runbooks/
└── tests/{airgap,common,resilience,security}/
```

## Deployables and toolchain

- `ai-gateway`: Python 3.12.14, FastAPI/Starlette, Pydantic v2, HTTPX, psycopg 3, cryptography, OpenTelemetry, and SSE support; exact versions frozen in `uv.lock`.
- `experience-gateway`: same package/toolchain, separate image/process and service account.
- `reference-channel-ui`: Node 24.20.0 LTS, Next.js 16.3.3 Active LTS App
  Router, React 19.2, and TypeScript 5 in a separate non-root standalone image.
  It uses only locally bundled assets and has no Vercel, hosted analytics,
  remote-font, CDN, or runtime-package dependency.
- Both run non-root, expose HTTP health/readiness/metrics, use structured logs, and accept configuration only through validated files/environment plus secret references.
- Both are stateful services for contract metadata, idempotency, cursors, and redacted projections; neither stores raw prompts, raw responses, retrieved context, or conversation memory.

## Owned APIs, events, and stores

The machine-readable authority for both surfaces is `architecture/dependency-graph.yaml#/runtimeSurface`; the harness specifications and generated OpenAPI/CloudEvent contracts must be byte-for-byte semantic mirrors.

AI gateway:

```text
POST /gateway/v1/invoke
POST /gateway/v1/embeddings
POST /gateway/v1/rerank
GET  /gateway/v1/routes
GET  /gateway/v1/routes/{id}
```

Experience gateway:

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

The AI gateway resolves a signed local routing policy, obtains trust/guardrail/budget decisions, and selects exactly one branch. A `direct-model` route calls `inference-api`. A `task` route calls `orchestration-api`; the orchestration worker alone owns retrieval, context assembly, model steps, and governed tool flow. The AI gateway never calls a knowledge API and never retrieves or assembles context. Streaming propagates cancellation and backpressure. Experience event IDs are monotonically increasing per session; `Last-Event-ID` resumes within retention. Non-task sessions and direct-model interactions remain usable when orchestration is unselected or unavailable; task controls are disabled immediately with a stable dependency reason.

Owned PostgreSQL tables: `gateway.route_activation`, `gateway.request_dedup`, `gateway.budget_reservation`, `experience.session`, `experience.session_event`, `experience.pending_input`, `runtime.event_outbox`, and inbox tables. They contain only metadata, hashes, bounded redacted projections, cursors, and references. Raw prompt/response/context retention and conversation memory are prohibited.

AI gateway emits `gateway.route.activated.v1`, `gateway.request.denied.v1`, `gateway.request.completed.v1`, `gateway.budget.exhausted.v1`, and `gateway.fallback.selected.v1`. Experience gateway emits `experience.session.created.v1`, `experience.input.submitted.v1`, `experience.task.cancel.requested.v1`, and `experience.approval.decided.v1`. They consume the canonical model, task, approval, evidence, policy, and revocation events named in their harness specifications.

## Task-command ownership

The bootstrap packet is the sole current owner of `Makefile` and installs the
closed `ci/run_make_target.py` direct-argv dispatcher. Each later Make-using
packet owns only `ci/targets/<lowercase-packet-id>.json`, which registers its
exact targets, closed variable values, and packet-local handlers. The dispatcher
validates descriptors and executes every applicable handler cumulatively in
lexical packet order; missing, ambiguous, duplicate, undeclared-variable, or
shell-based handlers fail closed. Later packets never edit `Makefile`. The only
exception is the generic `campaign`, `evidence-verify`, and
`acceptance-package` dispatch owned and tested by `CONF-001` for conformance
campaign packets.

The same bootstrap packet is the only current owner of `PORTING.yaml` and
seeds a closed `NO_AUTHORIZATION` ledger. Reference/discovery-only packets cannot
edit it; a future copy transaction requires a revised `PORT_CANDIDATE` packet.

## Dependencies

- Upstream: contracts, SDK, trust policy/guardrail/governance/usage APIs, model plane, conditional execution plane, PostgreSQL, and OTel Collector. Knowledge-plane integration belongs to orchestration and is not a runtime-plane dependency.
- Downstream: reference UI/channel clients and conformance labs.
- Failure rules: trust/OPA and required model loss fail closed; control-plane loss has no effect; orchestration loss immediately disables task routes but leaves direct-model routes available; model/execution failures are normalized without leaking upstream details. Retrieval/tool degradation is handled only by orchestration under its signed workflow policy.

## Warm-source mapping

Public source provenance is recorded only in `architecture/reuse-map.yaml`, `architecture/reuse-path-index.yaml`, and packet `sourceReuse` entries. Non-public planning inputs have already been distilled into independent public contracts and acceptance criteria; their repository names, commits, paths, and object IDs are deliberately omitted. They are not mounted or required during implementation. No source is copy-authorized.

## PR packets

1. `RUN-001-common-edge`: package, authenticated tenant context, error/idempotency envelope, OTel, DB migrations/RLS, and images.
2. `RUN-GW-001-routing`: signed route intake, deterministic selection, policy/guardrail calls, budget reservation, model/execution adapters, and usage events.
3. `RUN-GW-002-streaming`: SSE streaming, cancellation, bounded buffers, timeouts, backpressure, fallback, and no-raw-content observability.
4. `RUN-EXP-001-interactions`: interaction lifecycle, event replay, input-required/resume/cancel, retention, and reference web client.
5. `RUN-002-security-resilience`: tenant isolation, duplicate calls, upstream outages, last-known-good route, audit correlation, and offline egress tests.

## Testing, verification, and acceptance

The `RUN-001` bootstrap packet declares
`prefetchCommands: [["make","prefetch"]]` and ordered
`offlineAcceptanceCommands:
[["make","common-contract"],["make","security"]]`.
Later packets add lint, type, coverage, contract, local integration, stream,
zero-bill, and reproducibility checks as direct argv arrays. The executor
supplies the hash-pinned packet through `HARNESS_TASK_PACKET` and invokes only
`offlineExecution.wrapperArgv: ["./ci/verify-offline.sh"]` for the complete
ordered list.

Acceptance: local OIDC, OPA, PostgreSQL, and a local model complete a direct-model interaction without orchestration or knowledge services; a separate task route reaches the execution fixture, which owns retrieval/tool calls. Interrupted SSE resumes without duplication; cancellation reaches the branch owner; invalid signatures and cross-tenant IDs fail closed; no prompt, response, or retrieved context appears in durable state/logs/traces; network-disabled runtime remains functional.

## Release and rollback

- Independently digest `ai-gateway` and `experience-gateway`; module manifests declare exact compatible contract/model/execution/trust ranges.
- Route changes use signed desired/observed activation with last-known-good rollback. Image rollback selects the prior compatible digest.
- DB migrations are expand/contract; interaction events are append-only and never destructively rolled back.

## Zero-bill rules

- Route catalog accepts only local/self-hosted endpoints explicitly supplied by the tenant; hosted-provider adapters and API-key settings are rejected by default schemas.
- No runtime downloads, remote telemetry, analytics, cloud provisioning, or external channel SaaS in core.
- Self-hosted offline CI only; no GitHub storage/cache/Packages, hosted load testing, scheduled workflows, or public tunnels.
