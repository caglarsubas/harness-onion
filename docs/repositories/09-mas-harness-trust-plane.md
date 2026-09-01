# Repository Plan: `mas-harness-trust-plane`

## Purpose and boundaries

This repository owns four independently selectable trust/lifecycle harnesses: `trust.security-safety`, `trust.governance-agentops`, `trust.observability-finops`, and `trust.evaluation-assurance`. It provides policy decisions, guardrails, approvals/waivers, module/agent registry and promotion, evidence status, bounded evaluations, usage accounting, and local observability configuration.

Non-goals:

- No identity provider implementation in core, model serving, orchestration, retrieval, setup portal, Kubernetes apply, billing/payment, or claim that telemetry alone is certification.
- Security/guardrails, governance/oversight, AgentOps, observability/usage, and evaluation/evidence remain independently selectable sub-capabilities.
- LLM-as-judge is optional and local; deterministic evaluation is always available.

## Repository structure and exact tree

This tree projects the current task-packet `allowedPaths`. Directory entries do not authorize edits beyond the packet executed in a coding run.

```text
mas-harness-trust-plane/
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
├── src/planeon_trust/
│   ├── common/
│   ├── evaluation/
│   ├── governance/
│   ├── guardrails/
│   ├── registry/
│   └── usage/
├── services/
│   ├── policy-decision/
│   ├── guardrail-service/
│   ├── governance-service/
│   ├── registry-service/
│   ├── evidence-service/
│   ├── assurance-worker/
│   └── usage-ledger/
├── migrations/{policy,guardrails,governance,registry,evidence,evaluation,usage}/
├── modules/{otel-collector,prometheus,jaeger}/
├── deploy/helm/{policy-decision,guardrail-service,governance-service,registry-service,evidence-service,assurance-worker,usage-ledger}/
├── fixtures/{attacks,evidence,evaluation,governance,guardrails,policy,registry,usage}/
├── scripts/run_failure_campaign.py
├── docs/runbooks/
└── tests/{airgap,evidence,evaluation,foundation,governance,guardrails,observability,registry,resilience,security}/
```

## Deployables and toolchain

- The repository target stack is Python 3.12.14, FastAPI, Pydantic v2,
  psycopg 3, cryptography, HTTPX, OpenTelemetry, jsonschema, and pytest; every
  admitted dependency must be exact and frozen in `uv.lock`.
- `TRUST-001` deliberately starts with a dependency-minimal ASGI service core
  and the exact offline closure `planeon-harness-sdk==0.1.0`,
  `cryptography==49.0.0`, `cffi==2.1.0`, and `pycparser==3.0`. FastAPI,
  Pydantic, HTTPX, psycopg, OpenTelemetry, an OPA binary, and a PostgreSQL
  server are not silently pulled into the bootstrap packet. Later packets must
  admit their exact local wheel/image closure and add live integration evidence
  without weakening the same core contracts.
- Deployables: `policy-decision` with OPA, `guardrail-service`, `governance-service`, `registry-service`, `evidence-service`, `assurance-worker`, and `usage-ledger`. OTel Collector/Prometheus/Jaeger are upstream pinned images/config modules, not reimplemented.
- Baseline identity uses tenant-supplied OIDC/Keycloak. OpenBao and SPIRE are optional modules.

## Owned APIs, events, and stores

```text
/trust/v1/policy:decide
/trust/v1/guardrails:evaluate
/trust/v1/approvals
/trust/v1/approvals/{id}/decision
/trust/v1/waivers
/trust/v1/registry/modules
/trust/v1/registry/agents
/trust/v1/releases
/trust/v1/promotions
/trust/v1/evidence
/trust/v1/evidence/{id}
/trust/v1/assurance/campaigns
/trust/v1/usage
/trust/v1/budgets
```

Owned PostgreSQL schemas/tables:

- `policy`: signed bundle metadata, activation, decision audit/cache metadata.
- `governance`: approval, reviewer, waiver, autonomy level, exception, tamper-evident audit chain.
- `registry`: module/agent/release versions, certification, promotion, deprecation/revocation.
- `evidence`: evidence record, control mapping, collection attempt, status, staleness, waiver link.
- `usage`: immutable usage entries, reservations, budgets, aggregates.

Evidence state is `MISSING|COLLECTING|PASS|WARN|FAIL|STALE|WAIVED`. Source, CI, merge, artifact, signature, deployment, runtime, security/evaluation, and tenant acceptance are distinct axes. Waiver requires control, approver, justification, compensating control, and expiry.

Emits approval, policy denial, waiver, release, promotion/revocation, evidence, budget, and assurance events. Consumes observations from all planes and bundle/operator/conformance evidence. It never accepts an observation as pass without control-specific validation.

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

- Upstream: contracts, SDK, PostgreSQL, OPA, tenant OIDC, local OTel/Prometheus/Jaeger, model plane only for explicitly configured local judge, and immutable signed artifacts.
- Downstream: all request/data/execution planes call policy/guardrail; control uses approval/evidence; distribution/operator use registry/admission; conformance submits evidence.
- Policy/OPA loss fails closed for tools, mutations, route changes, memory writes, and promotion. Evidence/telemetry can buffer within bounded local limits but cannot be silently dropped.

## Warm-source mapping

Public source provenance is recorded only in `architecture/reuse-map.yaml`, `architecture/reuse-path-index.yaml`, and packet `sourceReuse` entries. Non-public planning inputs have already been distilled into independent public contracts and acceptance criteria; their repository names, commits, paths, and object IDs are deliberately omitted. They are not mounted or required during implementation. No source is copy-authorized.

## PR packets

1. `TRUST-001-foundation`: tenant OIDC admission, DB roles/RLS, signed policy bundle activation, OPA decision API, audit/outbox, and fail-closed tests.
2. `TRUST-002-guardrails`: input/output/runtime profiles, streaming evaluation, detector interface, redaction, evidence, and SDK conformance.
3. `TRUST-GOV-001`: approvals, N-of-M, autonomy, waivers/expiry, exceptions, tamper-evident audit chain, and policy linkage.
4. `TRUST-REG-001`: module/agent/release registry, certification axes, promotion, deprecation, revocation, and signed release admission.
5. `TRUST-OBS-001`: OTel Collector/Prometheus/Jaeger offline modules, usage ledger, reservations/budgets, tenant isolation, and retention.
6. `TRUST-EVAL-001`: deterministic evaluators, campaigns, trace/evidence ingestion, local-model judge opt-in, calibration, staleness, and reproducibility.
7. `TRUST-003-resilience-security`: OPA/DB/collector outages, audit buffer exhaustion, forged evidence, waiver expiry, cross-tenant denial, and air-gap startup.

## Testing, verification, and acceptance

The `TRUST-001` bootstrap packet declares
`prefetchCommands: [["make","prefetch"]]` and ordered
`offlineAcceptanceCommands:
[["make","policy-vectors"],["make","security"]]`.
Later packets add lint, type, coverage, parity, policy, contract, local
integration, evidence, zero-bill, and reproducibility checks as direct argv
arrays. The executor supplies the hash-pinned packet through
`HARNESS_TASK_PACKET` and invokes only `offlineExecution.wrapperArgv:
["./ci/verify-offline.sh"]` for the complete ordered list.

Acceptance: unauthorized/malformed tenant contexts and mutations are denied; OPA outage fails closed; guardrails handle streaming; approvals/waivers enforce reviewer/expiry policy; forged/stale evidence cannot promote; usage/budget is replay-safe; each evidence axis remains independent; local deterministic campaign works with egress denied; content/secrets never enter default telemetry.

### Coding-ready `TRUST-001` slice

The bootstrap is bound to contracts commit
`2146278a95344cd2a8e22596b2f315b46edffc88`, release-manifest SHA-256
`c5dd4c39d1c69d07f8d8de3d1a09584bb906172fee2d5ac20ad25ff344b0db79`,
CON-006 mapping SHA-256
`81cc6d9ed39099534b61e45830f95af6bb215854f43dc21c37dd8080055445a3`,
and the reproducible SDK-003 wheel from commit
`a083d04fb2c0f32a1ce8373a6251e703226380c8` at SHA-256
`5a4fa30c64432622083d8a0eeb32cf3ae67fa9975795eb2f0b5a209bd76d56a5`.
No contract or SDK checkout is mounted during implementation or acceptance.

The service route is `POST /trust/v1/policy:decide`. Authentication derives
the organization and subject from a locally configured, signature-verified
OIDC token; the request body cannot carry tenant identity. RS256, ES256, and
EdDSA are supported from a closed public JWKS. Discovery and symmetric JWT
algorithms are excluded. The OPA adapter accepts only the same-pod loopback
endpoint `http://127.0.0.1:8181/v1/data/planeon/authz/decision` (or an exact
loopback equivalent) and fails closed on every transport or result error.

Signed policy artifacts are verified and staged before one atomic active-policy
switch. The immediately previous verified non-revoked policy is the only
last-known-good candidate; revocation and expiry always override rollback.
The decision cache is tenant-keyed, metadata-only, bounded to 1,024 entries and
30 seconds, excludes denials and mutations, and is cleared on every trust-state
change. An allow is returned only after decision metadata plus redacted audit
and outbox classification commit atomically.

`migrations/policy/001_foundation.sql` is the PostgreSQL authority for distinct
owner/migrator/runtime/audit-writer roles, `ENABLE` plus `FORCE ROW LEVEL
SECURITY`, transaction-local tenant context, least privilege, and append-only
audit/outbox. Offline tests validate the migration contract; they do not claim
that PostgreSQL, OPA, OIDC, Helm, Kubernetes, or OpenShift ran. Those axes remain
`NOT_RUN_ENV_UNAVAILABLE` until their separately authorized environment tests.

The Helm chart is install-inert until an operator supplies immutable image
digests and existing Secret references. It provisions no IdP, database,
registry, storage, key, credential, namespace, or cloud resource. OPA is an
optional same-pod sidecar; all images are digest-only, mutable tags are absent,
and OpenShift-compatible non-root restrictions remain mandatory.

Bootstrap acceptance is exactly `make prefetch`, `make policy-vectors`, `make
security`, the full `unittest` discovery for `tests/foundation`, and `make
zero-bill`, all through the signed hash-pinned deny-all-outbound launcher. The
packet enumerates the positive and negative identity, policy, OPA, storage,
cache, API/client, SQL, Helm, dispatcher, porting, billing, and evidence-axis
vectors that must pass before merge.

## Release and rollback

- Each sub-capability/deployable has independent image/module digest and compatibility range. Policy/evaluator bundles are separately versioned and signed.
- Policy activation is verify/stage/atomic-switch with previous bundle retained. Revocation overrides rollback.
- DB migrations use expand/contract. Audit, usage, evidence, approvals, and revocations are append-only; rollback never deletes them or changes previous decisions.

## Zero-bill rules

- No metered observability, remote judge, hosted IdP requirement, payment system, cloud key manager, external policy service, or phone-home.
- Local judge is bounded by `ExecutionBudget`; deterministic evaluators remain the default. No external provider API key is accepted in any configuration.
- Self-hosted offline CI only; no GitHub storage/cache/Packages, scheduled campaigns, external coverage/security upload, or cloud runners.
