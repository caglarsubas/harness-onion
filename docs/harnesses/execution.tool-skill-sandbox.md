# Harness Specification: `execution.tool-skill-sandbox`

## Contract

| Field | Value |
|---|---|
| Plane | Execution |
| Owning repository | `mas-harness-execution-plane` |
| Public warm source | `data-source-harness`; non-public planning input metadata omitted |
| API version | `harness.planeon.ai/v1alpha1` |

## Capabilities and non-goals

This harness registers typed tools/skills, classifies side effects and isolation needs, evaluates policy and approvals, resolves scoped credentials, launches constrained executions, captures receipts, and coordinates compensation. It supports declarative reads, trusted actions, untrusted WASM, and approved untrusted-native isolation.

It does not grant arbitrary cluster access, run caller-supplied native code in an ordinary container, treat a Kubernetes namespace as a sandbox, retry unknown side effects, expose secret values, or let model text define executable commands outside a signed tool manifest.

## Owner and deployables

- `tool-broker`: registry lookup, schema validation, policy/approval, credential brokering, lifecycle, receipts.
- `sandbox-runner`: ephemeral per-execution Job/pod with selected isolation provider.
- `wasmtime-runner`: independently packaged WASI provider.
- `native-isolation-adapter`: optional gVisor/Kata integration; no default ordinary-container fallback. MicroVM runtimes are deferred comparative guidance and are not cataloged.

Governed actions and receipts are independent clean-room targets derived only
from released contracts and pre-recorded, digest-pinned observations;
implementation cannot access, copy, adapt, translate, or derive code from a
warm checkout. Deployment/runtime admission uses SDK primitives.

## Dependencies, conflicts, and ordering

- Required: `runtime.infrastructure`, `execution.orchestration`, `trust.security-safety`, `trust.governance-agentops`, `trust.observability-finops`.
- Optional: `execution.protocol-interoperability`, `trust.evaluation-assurance`.
- Conflicts:
  - `UNTRUSTED_NATIVE` without a certified isolation runtime.
  - Write/irreversible tool without owner, side-effect class, approval, idempotency, and compensation/outcome policy.
  - Host network/PID/path, privileged mode, Docker socket, wildcard RBAC, unrestricted egress, or service-account token mount.
  - Secret value embedded in manifest/input.
  - Tool artifact or schema referenced by mutable tag.

Tool registry certification and isolation-provider readiness precede orchestration activation.

## Provider implementations

| Isolation class | Provider |
|---|---|
| `DECLARATIVE_READ` | Restricted non-privileged Job or protocol adapter |
| `TRUSTED_ACTION` | Restricted Job with scoped credential and explicit egress |
| `UNTRUSTED_WASM` | Wasmtime/WASI with preopened paths and capability grants |
| `UNTRUSTED_NATIVE` | Cataloged and certified gVisor or Kata runtime class |
| `PROHIBITED` | Compile-time rejection; no provider |

Provider selection is dictated by manifest classification and tenant platform capability, not model preference.

## Configuration and runtime boundaries

```yaml
tool:
  id: string
  version: semver
  artifactRef: oci@sha256:...
  inputSchemaDigest: sha256:...
  outputSchemaDigest: sha256:...
  isolationClass: DECLARATIVE_READ | TRUSTED_ACTION | UNTRUSTED_WASM | UNTRUSTED_NATIVE
  sideEffect: none | reversible | compensatable | irreversible
  idempotency: native | receipt-key | none
  compensationToolId: string-or-null
  credentialRefs: []
  networkIntent: []
  rbacIntent: []
  resources: {cpuMillis: integer, memoryMiB: integer, gpu: integer}
  timeoutSeconds: integer
  maxOutputBytes: integer
```

- Secrets: broker creates a per-run projection/scoped token where supported, mounted read-only and destroyed with the run. Outputs/logs are scanned and redacted.
- RBAC: broker can create/delete labelled Jobs in a dedicated execution namespace and read their status/log reference. Runner accounts contain only approved intent; token automount is off by default.
- Network: default-deny per run; only declared DNS/IP/port destinations, policy, receipt store, and OTel are allowed. Metadata endpoints are always denied.
- Storage: ephemeral emptyDir/preopened WASI paths by default. Declared input/output objects are content addressed. Tool state/receipts live in tool-owned execution tables; secrets and raw unrestricted logs do not.

## APIs, events, and state

```text
GET  /runtime/v1/tools
GET  /runtime/v1/tools/{id}/versions/{version}
POST /runtime/v1/tools/{id}:plan
POST /runtime/v1/tool-executions
GET  /runtime/v1/tool-executions/{id}
POST /runtime/v1/tool-executions/{id}:cancel
POST /runtime/v1/tool-executions/{id}:compensate
GET  /runtime/v1/tool-executions/{id}/receipt
```

Execution states: `PLANNED → POLICY_PENDING → APPROVAL_REQUIRED → AUTHORIZED → RUNNING → SUCCEEDED`; alternatives `DENIED`, `CANCELLED`, `TIMED_OUT`, `FAILED`, `OUTCOME_UNKNOWN`, with optional `COMPENSATING → COMPENSATED` or `COMPENSATION_FAILED`.

Emitted:

- `tool.execution.planned.v1`
- `tool.approval.requested.v1`
- `tool.execution.started.v1`
- `tool.execution.completed.v1`
- `tool.execution.outcome_unknown.v1`
- `tool.compensation.completed.v1`

Consumed: approval decisions, policy/revocation changes, orchestration cancellation, and isolation-provider health.

## Failures, retry, and rollback

- Validation, policy, approval, artifact, RBAC/network intent, or isolation failure prevents launch.
- Read-only/idempotent executions retry within manifest limit. Non-idempotent actions retry only with an authoritative receipt lookup proving no prior effect.
- Loss after a possible side effect is `OUTCOME_UNKNOWN` and requires operator/owner reconciliation.
- Timeout/cancel terminates the sandbox and records whether an external effect may remain.
- Compensation is a separate governed execution and never changes the original receipt.
- Tool release rollback affects new runs only; running executions remain pinned to image/schema/policy digests.
- Credential cleanup is attempted after every terminal path and independently audited.

## Evidence and readiness gates

- Tool owner, artifact/signature/SBOM/license, input/output schemas, side-effect and isolation classification.
- Policy, approval role/quorum/expiry, credential scope, RBAC/network intent.
- Non-root, seccomp, capabilities, filesystem, resource and runtime-class verification.
- Idempotency/receipt and compensation campaign.
- Secret/log/output exfiltration tests.
- Timeout, cancellation, crash, ambiguous outcome, and credential cleanup evidence.

Irreversible tools require explicit human approval for each execution unless an industry pack and governance policy expressly prohibit them entirely.

## Profile behavior

- `minimal-local`: declarative reads and pre-approved trusted actions; WASM optional; native untrusted execution disabled.
- `enterprise`: dedicated execution namespace/node pool, Wasmtime, optional certified gVisor/Kata, scoped credential broker.
- `airgap-enclave`: signed/vendored tool artifacts only; enclave-local destinations; no package install during execution.

## Tests

- Unit: manifest/classification validation, intent rendering, state transitions, receipt decisions.
- Contract: orchestration, governance, policy, secrets, execution API/events.
- Security: privilege escalation, host access, metadata access, egress bypass, fork bombs, archive/path attacks, secret exfiltration.
- Failure: job crash, broker crash, timeout race, lost receipt, ambiguous remote result, compensation failure.
- Isolation: WASI capability denial and gVisor/Kata runtime-class verification.
- Air gap: tool executes without dependency download or external DNS.

## Sol-high implementation packets

1. `EXEC-001-foundation`: shared execution kernel, tenant DB roles/RLS, inbox/outbox, task/event contracts, images, and state-model tests.
2. `EXEC-TOOL-001`: signed catalog/manifests, side-effect/isolation classification, plan API, policy/approval, scoped credentials, receipts, idempotency, ambiguous outcomes, compensation, and lifecycle.
3. `EXEC-SBX-001`: restricted Job and Wasmtime providers, default-deny intents, capability grants, resource/time limits, cleanup, and escape tests.
4. `EXEC-SBX-002`: optional gVisor/Kata manifests and fail-closed capability probes; unavailable runtime yields explicit non-certification.
5. `EXEC-002-resilience`: crashes around launch/receipt/commit, duplicates, outcome reconciliation, credential cleanup, tenant isolation, dependency outages, and air-gap campaign.

No packet may add an ordinary-container fallback for untrusted native code.
