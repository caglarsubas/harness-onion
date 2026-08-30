# Harness Specification: `execution.orchestration`

## Contract

| Field | Value |
|---|---|
| Plane | Execution |
| Owning repository | `mas-harness-execution-plane` |
| Public warm source | `data-source-harness`; non-public planning input metadata omitted |
| API version | `harness.planeon.ai/v1alpha1` |

## Capabilities and non-goals

This harness executes versioned deterministic workflows and bounded agent tasks with durable checkpoints, input/auth pauses, cancellation, timers, retries, compensation coordination, delegation budgets, and complete state-transition evidence. It selects the least complex execution form that satisfies a demand: deterministic workflow, then one agent, then multi-agent only with explicit benefit.

It does not invoke tools without the tool broker, bypass policy/approval, store long-term memory, own source/retrieval data, expose model APIs, or treat an in-memory framework graph as durable execution evidence.

## Owner and deployables

- `orchestration-api`: task submission, query, input, cancellation, workflow-version API.
- `orchestration-worker`: durable state machine, timers, activities, delegation, and outbox.

Temporal is deferred comparative guidance, not a catalog installable or selectable
provider in this release. Adding it requires a catalog record, repository packet,
and conformance evidence. The current PostgreSQL implementation is an independent
clean-room target derived only from released contracts and pre-recorded,
digest-pinned observations; implementation cannot access, copy, adapt, translate,
or derive code from a warm checkout.

## Dependencies, conflicts, and ordering

- Required: `runtime.infrastructure`, `execution.protocol-interoperability`, `trust.security-safety`, `trust.governance-agentops`, `trust.observability-finops`.
- Optional: `runtime.model-inference`, `knowledge.retrieval-context`, `knowledge.memory-state`, `execution.tool-skill-sandbox`, `runtime.experience`.
- Conflicts:
  - Workflow references unregistered capability/model/tool IDs.
  - Retry policy for an operation lacking idempotency/receipt semantics.
  - Multi-agent topology without decomposition/benefit and budget declarations.
  - Workflow version removal while active tasks reference it.
  - Direct database or HTTP activity embedded in workflow definitions.

Workflow release and dependency readiness precede task admission.

## Provider implementations

- `planeon.orchestrator.postgres`: baseline outbox/inbox, leases, timers, checkpoints, and workers using PostgreSQL.

No Temporal provider is selectable. Comparative guidance may describe the task,
workflow, evidence, idempotency, and cancellation contracts a future adapter
would have to satisfy.

## Configuration and runtime boundaries

```yaml
workflows:
  - id: string
    version: semver
    definitionDigest: sha256:...
    steps: []
    compatibility: backward | strict
execution:
  provider: planeon.orchestrator.postgres
  leaseSeconds: integer
  heartbeatSeconds: integer
  defaultTimeoutSeconds: integer
  maxTaskLifetimeSeconds: integer
budgets:
  modelCalls: integer
  delegatedAgents: integer
  toolCalls: integer
  loopIterations: integer
  retries: integer
  wallTimeSeconds: integer
```

- Secrets: no workflow definition contains secrets. Activity credentials are resolved by the protocol/tool boundary from secret references.
- RBAC: no Kubernetes API access. Roles separate workflow publish, task submit/view/cancel/input, and operations administration.
- Network: API receives tenant clients/experience; workers reach only protocol, model gateway, knowledge, tool broker, trust, state store, and OTel endpoints declared by the profile.
- Storage: workflow definitions are immutable signed artifacts. Task state, checkpoints, timers, leases, inbox/outbox, and activity receipts live only in the runtime schema; never in memory or retrieval tables.

## APIs, events, and state

```text
POST /runtime/v1/tasks
GET  /runtime/v1/tasks/{id}
POST /runtime/v1/tasks/{id}/cancel
POST /runtime/v1/tasks/{id}/input
GET  /runtime/v1/tasks/{id}/events
POST /runtime/v1/workflows
GET  /runtime/v1/workflows/{id}/versions/{version}
POST /runtime/v1/workflows/{id}/versions/{version}:activate
```

Canonical A2A-aligned task states: `TASK_STATE_SUBMITTED`, `TASK_STATE_WORKING`, `TASK_STATE_INPUT_REQUIRED`, `TASK_STATE_AUTH_REQUIRED`, `TASK_STATE_COMPLETED`, `TASK_STATE_FAILED`, `TASK_STATE_CANCELED`, and `TASK_STATE_REJECTED`.

Internal execution substates include `WAITING_TIMER`, `WAITING_APPROVAL`, `WAITING_ACTIVITY`, `COMPENSATING`, and `COMPENSATED`; these do not replace the public A2A state.

Emitted:

- `task.state.changed.v1`
- `task.input.requested.v1`
- `task.budget.exhausted.v1`
- `workflow.version.activated.v1`
- `workflow.compensation.completed.v1`

Consumed: protocol/tool/model responses, approval decisions, user input, policy changes, cancellation, and timers. State plus outbox writes are atomic; consumers de-duplicate by event ID.

## Failures, retry, and rollback

- Task submission requires an idempotency key. Repeated submission returns the original task.
- Worker leases expire and are reclaimed; checkpoint version and compare-and-swap prevent double transition.
- Activities retry only under their declared error taxonomy and idempotency/receipt policy.
- Non-idempotent ambiguous outcome pauses as `INPUT_REQUIRED`/operator review; it is never blindly retried.
- Budget exhaustion is terminal unless governance approves a new budget version.
- Cancellation prevents new activities and propagates to active boundaries; completed side effects follow compensation policy.
- Workflow activation is atomic and retains the prior version. Active tasks remain pinned to their starting version unless an explicit compatible migration exists.
- PostgreSQL loss rejects mutations; recovery resumes from committed checkpoints/outbox.

## Evidence and readiness gates

- Signed workflow digest, dependency closure, owner, risk/autonomy class, and acceptance tests.
- State-transition, lease, checkpoint, timer, idempotency, cancellation, and compensation evidence.
- Budget accounting for calls, tokens, agents, tools, retries, loops, time, CPU, memory, and GPU.
- Multi-agent benefit justification and measured comparison when selected.
- Complete activity/tool/model/retrieval evidence references.
- Crash recovery and duplicate/out-of-order event campaign.

Production activation requires certified dependencies, current policy/evaluation evidence, and no unsupported side-effect retry.

## Profile behavior

- `minimal-local`: PostgreSQL executor, one worker, deterministic/single-agent workflows, no multi-agent default.
- `enterprise`: replicated workers, partitions/queues, HA PostgreSQL, bounded multi-agent topology.
- `airgap-enclave`: local dependencies only; timers, retries, approvals, and recovery operate without management-plane connectivity.

## Tests

- Independent clean-room parity against pre-recorded, digest-pinned vectors: tasks, leases, checkpoints, workflow ontology, decisions, receipts, delegation, and durability; no warm checkout access.
- Model-based: every legal/illegal state transition and concurrent lease race.
- Contract: API/A2A state, events, protocol/tool/model/knowledge clients.
- Failure: crash before/after state and outbox commit, duplicate events, timer restart, DB outage, dependency timeout.
- Governance: approval pause/resume, budget extension, cancellation, compensation, outcome unknown.
- Multi-agent: benefit requirement, fan-out/fan-in bounds, delegation budget, partial failure.

## Sol-high implementation packets

1. `EXEC-001-foundation`: common execution kernel, tenant DB roles/RLS, inbox/outbox, canonical task/event contracts, images, and model-based state tests.
2. `EXEC-ORCH-001`: PostgreSQL workflow/task store, leases/checkpoints/timers, activity boundaries, retries/receipts, input/auth/approval pauses, budgets, cancellation, compensation coordination, deterministic/one-agent/multi-agent selection, and crash recovery.
3. `EXEC-002-resilience`: commit/outbox crashes, duplicate/out-of-order events, lease races, dependency outages, ambiguous side effects, tenant isolation, and air-gap campaign.

Packets cannot introduce direct tool execution or persistent memory writes outside their governed service APIs.
