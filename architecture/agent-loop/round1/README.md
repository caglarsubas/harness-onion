# Agent-loop kernel and tool-gateway records v1 (MAS-RA-008)

Alpha 2; 2026-10-13. Status: **CONTRACT_CANDIDATE** (under independent review). DATA_CHECK_ONLY: an internal contract
candidate with schemas, a reference model and vectors. It changes no public contract, selector, catalog or runtime, and it
leaves H10's and H11's harness documents (`docs/harnesses/execution.orchestration.md`,
`docs/harnesses/execution.tool-skill-sandbox.md`) and the repository schemas byte-identical (owner decision Q-MAS8-A).

An agent loop is a model calling tools until it delivers, fails, aborts or hands off. The three MAS-harness research
syntheses agree that its governance belongs in the harness (hooks, budgets, gates, typed tool boundaries), not in prompts,
and that its failures compound: at 85% per step, ten unchecked steps succeed about 20% of the time. This contract records
one loop: what it may spend and call (the profile) and what it did (the trace), with the rules a trace must keep
(crosswalk `architecture/research-adoption-v2/crosswalk.json`, item MAS-RA-008, acceptance IDs MAS-RA-008-A1 to -A3;
harnesses H11 `execution.tool-skill-sandbox` and H10 `execution.orchestration` primary, H13 `trust.security-safety` and
H15 `trust.observability-finops` secondary). Future consumers: R08 and CONF-A3-001, which this item gates (HO-D2), and
MAS-RA-010's adversarial campaign.

## Files

| File | Content |
|---|---|
| `loop-profile.schema.json` | `planeon.internal.agent-loop-profile/v1`: budgets, retry and revision bounds, hooks, gates and tools of one loop |
| `loop-trace.schema.json` | `planeon.internal.agent-loop-trace/v1`: the steps of one loop run, its totals and its terminal status |
| `vectors.json` | 124 cases (17 valid, 107 refused; every profile code and every trace code at least once) over shared stores (6 profile entries, two of them deliberately unusable; 4 child traces, one failing its own check) and 4 raw-text cases, each with its exact expected result |
| `../../scripts/agent_loop.py` | Reference model, standard library only: `check_profile`, `check_trace`, `parse`, `canonical`, `digest`; run directly, it replays every vector |

The schemas state the closed shapes; the model refuses a document as `SHAPE` exactly when its schema rejects it (every case
is checked against both). Uniqueness (`DUPLICATE_ID`), order, references and every later rule are the model's alone.
Records are I-JSON with integer numbers only, each within ±(2⁵³ − 1); `canonical` is RFC 8785 on that value space (as in
MAS-RA-001 and MAS-RA-002), and a record is referred to by `digest(record)` (`sha256:` and the hex SHA-256 of its canonical
form). Times are UTC `YYYY-MM-DDTHH:MM:SSZ` with field ranges checked; such strings order as the times do.

## The loop profile (A1)

- **Budgets** `{tokens, iterations, wallClockSeconds, recursionDepth, contextWarningPercent}`. `recursionDepth` is 0 or 1
  (owner decision Q-MAS8-B: at most 1 in v1, with no override). `contextWarningPercent` is the context-window threshold at
  which the kernel raises `BUDGET_WARNING`; it is declared here and not checked against a trace.
- **Bounds** `retry.stepRetries` (0 to 3) and `revision.rounds` (0 to 3), separate budgets (Q-MAS8-C: a failing step
  retries at most once by default and at most 3 times in any profile; revision rounds default 3, at most 3).
- **Hooks** `{hookId, event, effects, scope}`. The 13 events cover the loop's three operations (invoke, model query, tool
  call or sandboxed execution), before and after each, plus `BUDGET_WARNING`, `BUDGET_EXHAUSTED`, `STEP_ERROR`,
  `STEP_RETRY` and `HANDOFF`. The effects are `MODIFY_INPUT`, `SUPPLY_OUTPUT` (the operation is then skipped),
  `MODIFY_OUTPUT` and `ABORT`, each allowed only where it means something: before an operation, change its input, supply
  its output or abort; after it, change its output or abort; on the other events, only abort. An empty effect list is an
  observing hook. Scope is `LOCAL` (this loop) or `DYNAMIC` (this loop and the loops it delegates to).
- **Effects compose independently of hook order.** Two hooks with the same exclusive effect (`MODIFY_INPUT`,
  `SUPPLY_OUTPUT`, `MODIFY_OUTPUT`) on one event would make the result depend on their order, so such a profile is refused
  (`HOOK_CONFLICT`, fail closed). `ABORT` composes with anything: abort wins.
- **Gates** `{gateId, kind}`: the deterministic checks (`SCHEMA`, `LINT`, `TEST`, `POLICY`) the loop may run.
- **Tools** `{toolId, manifestDigest, inputSchemaDigest, sideEffect, idempotency, trust, grantScope, credentialParams}`:
  the signed manifest and its input schema by digest, `READ_ONLY` or `WRITE`, idempotency `NATIVE`, `RECEIPT_KEY` or
  `NONE`, whether the tool's output is `TRUSTED` or `UNTRUSTED`, the capability scope H11 grants for a call, and the
  parameters that take a brokered credential.

## The loop trace (A1, A2, A3)

`traceId`, `profileDigest`, `depth` (0, or 1 for a delegated loop) with its `parentTraceId`, `startedAt`, the steps in
append order, the `terminal` `{status, reason, delivered}` and the `totals` `{tokens, iterations, wallClockSeconds}`.

Each step has `stepId`, `seq`, `kind`, `startedAt`, `tokens`, `wallClockSeconds`, `outcome` (`OK`, `FAIL`, `ERROR`,
`UNKNOWN`), `errorTraceDigest` (the diagnosis, present exactly when the outcome is not OK), `consumes` (earlier step IDs),
`produces` (an artefact digest or null), `attempt` (1 to 4), `retryOf`, `feedback`, `revises` and a per-kind `detail`:

- **MODEL** `{inputDigest, credentialRefs}`: `credentialRefs` lists brokered credentials resolved into the model's input;
  it must be empty (secrets never reach a model).
- **TOOL** `{call, result}` (A2):
  - the **call** names the tool, its manifest digest, the input digest and the input-schema digest it was validated
    against, `inputValid`, the per-call **capability** reference `{grantDigest, toolId, manifestDigest, scope, expiresAt}`
    (Q-MAS8-D: bound by digest to H11's grant; issuing, signing and verifying stay with H11's broker, and the vectors hold
    no key material), a timeout, resource limits `{memoryBytes, cpuMillis}` and credentials as `{param, brokerRef}`
    broker references only (a value in their place is `SHAPE`);
  - the **result** carries its output digest (null when there is none), a trust label (`TRUSTED_TOOL_OUTPUT` or
    `UNTRUSTED_TOOL_OUTPUT`, from the tool's declared trust) and its **provenance** `{toolId, callStepId,
    sandboxProfileDigest, receiptRef}`.
- **GATE** `{gateId, subjectStepId}`: a deterministic check of an earlier step's artefact.
- **HOOK** `{hookId, event, effect}`: a hook that fired, with the effect it had (or null).
- **HANDOFF** `{reason}`: the loop hands off to a human.
- **DELEGATE** `{childTraceDigest}`: one level of delegation to a child loop, whose trace is stored by digest.

**Totals and budgets.** The totals are the steps' sums; iterations count MODEL steps. A DELEGATE step carries its child's
tokens and wall-clock, the child's delivered artefact as its `produces`, and an outcome that is OK exactly when the child
COMPLETED, so a delegation cannot hide spending from the parent's budget. The totals never exceed the profile's budgets.

**Model output is data until it crosses a typed boundary.** No model output reaches execution except as a tool call to a
tool the profile lists, under its listed manifest, with an input valid against the listed input schema (H11: model text
never defines executable commands outside a signed tool manifest). The capability names the same tool, manifest and the
profile's grant scope and has not expired when the call starts; each call has its own grant.

**Deterministic gates interleave with model steps** (A3). A model step's artefact is passed by a deterministic gate (an OK
GATE step on it) after it is produced and before any later model step, write tool or delivery consumes it, so a per-step
error does not compound. A read-only tool may read an ungated artefact, and a revision of the artefact is not a consumer.
A gate's FAIL is never overridden: after it, nothing but a revision consumes the artefact and it is never delivered, even
if another gate, or a later run of the same gate, passes it (H13; MAS-RA-001's rule that a model cannot overturn a
deterministic failure).

**Bounded retry, then a human** (A3, Q-MAS8-C):
- A retry names the failed step it repeats (`retryOf`), has the same kind, tool and revision target, the next attempt
  number, and the failure's error trace as its `feedback`. A step is retried at most once; the retry is retried in turn.
  Attempts stay within `stepRetries + 1`.
- A tool call that repeats the latest call with the same tool and input digest, when that call did not succeed, must be
  marked as its retry, so a loop cannot reset its attempt count by re-issuing a call.
- An `UNKNOWN` outcome on a `WRITE` tool without idempotency is never retried (H11: unknown side effects are not retried).
  A receipt-keyed or natively idempotent tool may be.
- A failing step whose retries are spent, or whose unknown side effect forbids a retry, is followed only by hook steps and
  a HANDOFF, and the loop ends HANDED_OFF.

**Revisions** (A3, Q-MAS8-C). A revision is a MODEL step that `revises` an earlier MODEL step's artefact in answer to a gate
that failed it, with that gate's error trace as its `feedback` and attempt 1. Chains of revisions of one artefact stay
within `revision.rounds`.

**Terminal status.** The status is honest:
- `COMPLETED` delivers a MODEL step's artefact (`delivered`), and every failing step other than a gate or hook was retried;
  only a COMPLETED loop delivers.
- `HANDED_OFF` ends with its single HANDOFF step.
- `ABORTED` states its reason: `HOOK_ABORT` exactly when a hook aborted, and the aborting hook step is then the last step;
  `BUDGET_EXHAUSTED` otherwise.
- `FAILED` has at least one step that did not succeed.

## Refusal codes and the order of each check

`PROFILE_CODES`: `SHAPE`, `DUPLICATE_ID`, `HOOK_CONFLICT`. A profile check raises SHAPE; then DUPLICATE_ID (hook, gate and
tool IDs; effects within a hook; credential parameters within a tool); then HOOK_CONFLICT.

`TRACE_CODES`, in check order:
1. `SHAPE`;
2. `DUPLICATE_ID`: step IDs, sequence numbers, capability grants, credential parameters within a call;
3. `STEP_ORDER`: sequence numbers strictly increase, start times never go back and never precede the trace's start;
4. `UNKNOWN_REFERENCE`: the profile (stored under its digest and passing its own check, or failing it only by a hook
   conflict), consumed, retried, revised and gated steps earlier in the trace, tools, gates and hooks the profile
   registers, child traces stored under their digest that pass their own check, and the delivered step;
5. `HOOK_CONFLICT`: the profile's hooks conflict;
6. then one whole-trace pass per rule: `HOOK_NOT_REGISTERED`, `RECURSION_DEPTH`, `TOTALS_MISMATCH`, `BUDGET_EXCEEDED`,
   `ERROR_TRACE`, `INVALID_TOOL_INPUT`, `CAPABILITY_MISMATCH`, `CAPABILITY_EXPIRED`, `CREDENTIAL_RULE`, `TRUST_LABEL`,
   `PROVENANCE`, `UNGATED_CONSUMPTION`, `GATE_OVERRIDDEN`, `RETRY_WITHOUT_TRACE`, `RETRY_BOUND`,
   `UNKNOWN_SIDE_EFFECT_RETRIED`, `REVISION_BOUND`, `HANDOFF_MISSING`, `TERMINAL_STATUS`.

`RECURSION_DEPTH`: the trace's depth is within its profile's `recursionDepth`, a depth-0 trace has no parent and a depth-1
trace has one, and a delegation is allowed only when depth + 1 is within the profile's limit and the child is at depth + 1
naming this trace as its parent. A check raises the first code it meets; nothing but these refusals escapes a check:
anything malformed is `SHAPE`.

## Binding to H10, H11, H13 and H15

H10 keeps its task API, durable execution, retries under its error taxonomy and delegation budgets; H11 keeps tool
admission, least privilege, approvals, credential brokering, sandboxes and receipts. This contract is the record of one
agent loop inside them. Its budget fields are what H15 measures; its capability references, broker-only credentials, trust
labels and output-is-data rule are H13's controls. None of their documents or schemas changes.

## Grounding (crosswalk pages)

- **JAZ** (2609.26891) pp. 4-5, 7, 13-14, 23-24: 13 hook events over invoke, model query and execution; composable
  effects with conflicts refused; local and dynamic scope; budgets and depth limits, with exhaustion as an exception and an
  aborted span. An uncapped run reached recursion depth 70 and its rules were prompt-level only, which is why execution
  stays in H11's sandboxes and depth is capped here.
- **HERMES** (2610.07832) pp. 15-16, 20-21, 23: a revision budget (default 3; returns beyond 3 are at most 0.9 points), a
  diagnosis schema, and deterministic failures that cannot become a pass.
- **HarnessDev** (2609.01437) pp. 5, 8, 22, 24, 27-28: a six-module interface, an honest tri-state status, provider-neutral
  model configuration, per-task caps, and validating final artefacts.
- **Harness-Zero** (2609.24974) pp. 2, 22-23: one execute tool, a turn limit, one level of delegation.
- Secondary: a reproduction of RLM reporting accuracy falling from 100% to 70% at depth 2; Stripe's reported rule of one
  fix attempt, then a human; the compounding figure from the Gemini synthesis.

## Owner decisions (2026-10-13, owner via the lane monitor; verbatim)

- Q-MAS8-A = (a): an internal candidate under architecture/agent-loop/, naming R08 and CONF-A3-001 as consumers; H10's and H11's documents and schemas unchanged.
- Q-MAS8-B = (a): recursion depth at most 1 in v1 with no override; deeper only by a later revision with its own evidence.
- Q-MAS8-C = (a): a failing step retries at most once by default and at most 3 times in any profile, each with its error trace fed back, then hand-off to a human; artefact revision rounds have a separate budget, default 3 and max 3.
- Q-MAS8-D = (a): a per-call capability-token reference bound by digest to H11's grant (tool, manifest, scope, expiry), with fields checked by the contract; issuing, signing and verifying stay with H11's broker; no keys in the vectors.

## Not claimed

- No kernel, gateway or broker exists; nothing writes a profile or trace outside the vectors.
- **A record, not a monitor.** A trace shows what a loop recorded. It cannot show that every step was recorded, that a
  digest names the bytes that ran, or that a step's tokens and times are true (H15 measures them; H11's receipts and H16's
  signer bind them).
- **Budget exhaustion is the kernel's statement.** The contract checks that totals never exceed the budgets; it cannot
  check that a loop ending `BUDGET_EXHAUSTED` had no room for another step.
- **Capability references only.** Grant digests, scopes and expiries are checked for consistency; whether a grant is
  genuine, signed and unrevoked is H11's broker's to verify.
- **Disguised retries of model steps** are not detectable; the iteration and token budgets bound them. Disguised tool
  retries are detected only by an identical tool and input digest.
- **Trust labels are declared, not measured.** The label follows the tool's declared trust; whether an untrusted output
  carried an injection is H13's and MAS-RA-010's.
- **Hook placement.** A hook step must match its registration; whether it fired at the right point (for example before the
  tool call it guards) is not checked.
- The cited figures are the source papers' results, not platform evidence.
