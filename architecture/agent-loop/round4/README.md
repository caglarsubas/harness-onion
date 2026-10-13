# Agent-loop kernel and tool-gateway records v1 (MAS-RA-008)

Alpha 2; 2026-10-13. Status: **CONTRACT_CANDIDATE** (under independent review). DATA_CHECK_ONLY: an internal contract
candidate with schemas, a reference model and vectors. It changes no public contract, selector, catalog or runtime, and it
leaves H10's and H11's harness documents (`docs/harnesses/execution.orchestration.md`,
`docs/harnesses/execution.tool-skill-sandbox.md`) and the repository schemas byte-identical (owner decision Q-MAS8-A).

An agent loop is a model calling tools until it delivers, fails, aborts or hands off. The three MAS-harness research
syntheses agree on two points. Its governance belongs in the harness (hooks, budgets, gates, typed tool boundaries), not
in prompts. And its failures compound: at 85% per step, ten unchecked steps succeed about 20% of the time.

This contract records one loop:
- what it may spend and call (the profile);
- what it did (the trace);
- the rules a trace must keep.

Crosswalk: `architecture/research-adoption-v2/crosswalk.json`, item MAS-RA-008, acceptance IDs MAS-RA-008-A1 to -A3.
Harnesses:
- primary: H11 `execution.tool-skill-sandbox` and H10 `execution.orchestration`;
- secondary: H13 `trust.security-safety` and H15 `trust.observability-finops`.

Future consumers:
- R08;
- CONF-A3-001, which this item gates (HO-D2);
- MAS-RA-010's adversarial campaign.

## Files

| File | Content |
|---|---|
| `loop-profile.schema.json` | `planeon.internal.agent-loop-profile/v1`: budgets, retry and revision bounds, hooks, gates and tools of one loop |
| `loop-trace.schema.json` | `planeon.internal.agent-loop-trace/v1`: the steps of one loop run, its totals and its terminal status |
| `vectors.json` | 187 cases (33 valid, 154 refused; every profile code and every trace code at least once), each with its exact expected result. They run over shared stores: 7 profile entries (two deliberately unusable) and 14 child traces (two failing their own check). Plus 4 raw-text cases. |
| `../../scripts/agent_loop.py` | Reference model, standard library only: `check_profile`, `check_trace`, `parse`, `canonical`, `digest`; run directly, it replays every vector |

**Schemas and model.** The schemas state the closed shapes. The model refuses a document as `SHAPE` exactly when its
schema rejects it; every case is checked against both. Uniqueness (`DUPLICATE_ID`), order, references and every later rule
belong to the model alone.

**Isolation.** Each refusal case is a minimal deviation. The builder checks that a case refused by a rule passes once that
rule is disabled. Six cases fall to a second rule instead, and say so in `alsoRefusedBy`:
- a delegation under a profile without delegation is also a delegation under another profile;
- a launched call with an invalid input, retried, is also a receipt-keyed write retried under another key;
- a retried delegation whose child left an unknown write also retries a failed delegation;
- a loop that ends FAILED after an unretried error, where no gate failed: two cases;
- a delivered step that ended ERROR with an artefact also delivers a step that did not succeed.

**Record format.** Records are I-JSON with integer numbers only, each within ±(2⁵³ − 1). `canonical` is RFC 8785 on that
value space (as in MAS-RA-001 and MAS-RA-002). A record is referred to by `digest(record)`: `sha256:` and the hex SHA-256
of its canonical form. Times are UTC `YYYY-MM-DDTHH:MM:SSZ` with field ranges checked; such strings order as the times do.

## The loop profile (A1)

- **Budgets** `{tokens, iterations, wallClockSeconds, recursionDepth, contextWarningPercent}`.
  - `recursionDepth` is 0 or 1 (owner decision Q-MAS8-B: at most 1 in v1, with no override).
  - `contextWarningPercent` is the context-window threshold at which the kernel raises `BUDGET_WARNING`. It is declared
    here and not checked against a trace.
- **Bounds:** `retry.stepRetries` (0 to 3, default 1) and `revision.rounds` (0 to 3, default 3). They are separate
  budgets (Q-MAS8-C: a failing step retries at most once by default and at most 3 times in any profile; revision rounds
  default 3, at most 3). The schemas carry the defaults as annotations; a producer writes both fields.
- **Hooks** `{hookId, event, effects, scope}`.
  - **Events.** 13 events: before and after each of four operations (invoke, model query, tool call, sandboxed
    execution), plus `BUDGET_WARNING`, `BUDGET_EXHAUSTED`, `STEP_ERROR`, `STEP_RETRY` and `HANDOFF`. This set is an
    adaptation of JAZ's 13 events (Enter, Send, Complete and Exit per operation, and LLMQueryRetry), not JAZ's set.
  - **Effects.** `MODIFY_INPUT`, `SUPPLY_OUTPUT` (the operation is then skipped), `MODIFY_OUTPUT` and `ABORT`. Each is
    allowed only where it means something:
    - before an operation: change its input, supply its output, or abort;
    - after an operation: change its output, or abort;
    - on the budget, error and retry events: only abort;
    - on `HANDOFF`: only observe, since the loop is already ending with a hand-off.

    An empty effect list is an observing hook.
  - **Scope.** `LOCAL` reaches only the loop that holds the hook. `DYNAMIC` reaches that loop and the loops it delegates
    to.
- **Effects compose independently of hook order.** Order-dependent pairs are refused (`HOOK_CONFLICT`, fail closed):
  - two hooks with the same exclusive effect (`MODIFY_INPUT`, `SUPPLY_OUTPUT`, `MODIFY_OUTPUT`) on one event;
  - one hook supplying the output of an event whose input another hook modifies, because the answer would depend on
    whether it saw the modified input.

  One hook may do both. `ABORT` composes with anything: abort wins.
- **Gates** `{gateId, kind}`: the deterministic checks (`SCHEMA`, `LINT`, `TEST`, `POLICY`) the loop may run.
- **Tools** `{toolId, manifestDigest, inputSchemaDigest, sideEffect, idempotency, trust, grantScope, credentialParams}`:
  - the signed manifest and its input schema, by digest;
  - the side effect: `READ_ONLY` or `WRITE`;
  - idempotency: `NATIVE`, `RECEIPT_KEY` or `NONE`;
  - H11's side-effect classes map onto two values: `none` is `READ_ONLY`; `reversible`, `compensatable` and
    `irreversible` are `WRITE`, and the class within WRITE stays H11's;
  - whether the tool's output is `TRUSTED` or `UNTRUSTED`;
  - the capability scope H11 grants for a call;
  - the parameters that take a brokered credential.

## The loop trace (A1, A2, A3)

A trace has these fields:
- `traceId` and `profileDigest`;
- `depth`: 0, or 1 for a delegated loop, with its `parentTraceId`;
- `startedAt`;
- the steps, in append order;
- `terminal`: `{status, reason, delivered}`;
- `totals`: `{tokens, iterations, wallClockSeconds}`.

Each step has these fields:
- `stepId`, `seq`, `kind`, `startedAt`, `tokens` and `wallClockSeconds`;
- `outcome`, `errorTraceDigest` and `attempt` (1 to 4), defined under Outcomes below;
- `consumes` (earlier step IDs) and `produces` (an artefact digest, or null). GATE, HOOK and HANDOFF steps neither
  consume nor produce (`SHAPE`): a gate's subject and a hook's event are in their `detail`;
- `retryOf`, `feedback` and `revises`;
- a per-kind `detail`, listed after the outcomes.

**Outcomes.** They are about the operation, not the domain answer: a read that finds no file is an OK step whose output
says so.
- `OK`: the operation completed, and its output is the step's artefact.
- `FAIL`: the operation completed with a negative result and no external effect. Examples: a gate failed the artefact,
  or the gateway refused a call before launch.
- `ERROR`: the operation did not complete. A model or tool error with no external effect, as the broker established.
- `UNKNOWN`: dispatched but not settled (H11's OUTCOME_UNKNOWN).

`errorTraceDigest` (the diagnosis) is present exactly when the outcome is not OK, and a step that is not OK produces no
artefact.

The `detail` for each kind:
- **MODEL** `{inputDigest, credentialRefs}`. `credentialRefs` lists brokered credentials resolved into the model's input,
  and it must be empty. That is what is checked: a secret inside a tool output that a model reads is H11's redaction to
  keep out. An operation whose output a hook supplied is still recorded as its step,
  after the HOOK step. A skipped model query counts as an iteration, with the tokens actually spent (0 for a cache hit).
- **TOOL** `{call, result}` (A2).
  - The **call** carries:
    - the tool, its manifest digest, the input digest, and the input-schema digest it was validated against;
    - `inputValid`, and `launched`: whether the gateway launched the call. A call is launched only with a valid input;
      H11 also denies launch for policy, approval, artifact, RBAC, network-intent or isolation reasons (its DENIED);
    - the per-call **capability** reference `{grantDigest, toolId, manifestDigest, scope, expiresAt}` (Q-MAS8-D: bound by
      digest to H11's grant). Issuing, signing and verifying stay with H11's broker, and the vectors hold no key
      material;
    - a timeout and resource limits `{memoryBytes, cpuMillis}`;
    - credentials as `{param, brokerRef}` broker references only. A value in their place is `SHAPE`.
  - The **result** carries:
    - its output digest (null when there is none);
    - a trust label, `TRUSTED_TOOL_OUTPUT` or `UNTRUSTED_TOOL_OUTPUT`, from the tool's declared trust;
    - its **provenance** `{toolId, callStepId, sandboxProfileDigest, receiptRef}`.

    A write tool that succeeded carries its receipt. For a write that ended FAIL or ERROR, `receiptRef` records the
    broker's evidence that it had no effect (a receipt or lookup reference), when there is one.
- **GATE** `{gateId, subjectStepId}`: a deterministic check of an earlier step's artefact.
- **HOOK** `{hookId, event, effect}`: a hook that fired, with the effect it had (or null). A hook step that is not OK
  had no effect and counts as an abort (fail closed): a guard that errors stops the loop.
- **HANDOFF** `{reason}`: the loop hands off to a human. It succeeds, and it is always the last step. Hooks on the
  HANDOFF event fire only in a loop that hands off; they are recorded right before the HANDOFF step, after any aborts.
- **DELEGATE** `{childTraceDigest}`: one level of delegation to a child loop, whose trace is stored by digest.

**Totals and budgets.** The totals are the steps' sums. Iterations count this loop's MODEL steps plus its children's
iterations. A DELEGATE step carries:
- its child's tokens and wall-clock;
- the child's delivered artefact, as its `produces`;
- an outcome that is OK exactly when the child COMPLETED.

So a delegation cannot hide spending from the parent's budget. The totals never exceed the profile's budgets, and a tool
step runs no longer than its call's timeout.

**Delegation** (Q-MAS8-B). A delegated loop runs at depth 1, names its parent, and runs under its parent's profile. Its
tools, bounds and budgets are therefore the parent's, and the parent's DYNAMIC hooks are registered in it. A delegated
loop records only DYNAMIC hooks. Further rules:
- it starts no earlier than its DELEGATE step;
- it holds no capability grant of its parent or of another delegated loop;
- one child trace is delegated at most once.

**Model output is data until it crosses a typed boundary.** No model output reaches execution except as a tool call to a
tool the profile lists, under its listed manifest, with an input valid against the listed input schema (H11: model text
never defines executable commands outside a signed tool manifest). A call the gateway denied before launch is recorded as
such: `launched` false, FAIL, no output and no receipt.

The call's capability:
- names the same tool and manifest, and the profile's grant scope;
- has not expired when the call starts;
- is its own grant: each call has a separate one.

**Deterministic gates interleave with model steps** (A3). Two kinds of artefact need a passing deterministic gate (an OK
GATE step on its bytes, on any step holding them) before they reach a consumer. A gate on the same bytes decides the
same, so an earlier one counts (a cache hit that reproduces gated bytes is gated):
- a model step's artefact;
- an untrusted tool's output.

The rule follows the bytes: every step whose artefact has the same digest holds them too. The consumers are:
- a write tool or a delegation that consumes the bytes, directly or through the outputs of read-only tools that read
  them (a delegated loop can write, and it cannot name its parent's steps);
- for a model artefact, also a later model step that consumes the bytes directly, and the delivery.

A model step may read untrusted tool output (that is what tools are for), and a revision of an artefact is not a
consumer of it. So a per-step error does not compound, and untrusted output does not reach an effect unchecked. The rule
covers declared consumption (`consumes`).

**A gate's FAIL is never overridden** (H13; MAS-RA-001's rule that a model cannot overturn a deterministic failure). The
FAIL decides more than its subject. It covers:
- the steps holding the failed bytes;
- every step that consumed any of them, at any time (before the FAIL included), except a revision of the artefact,
  which repairs it;
- every step holding the bytes of any of these.

After the FAIL:
- nothing but a read-only tool (which reads, and is covered in turn) or a revision of the artefact consumes any of it;
  a revision may consume all of it;
- none of it is delivered, even if another gate, or a later run of the same gate, passes it;
- a revision returns bytes none of it holds.

**Bounded retry, then a human** (A3, Q-MAS8-C).
- **What a retry is.** A retry names the failed step it repeats (`retryOf`). It has:
  - the same kind, tool (for a gate, the same gate and subject) and revision target;
  - the next attempt number;
  - the failure's error trace as its `feedback`.

  A step is retried at most once; the retry is retried in turn. Attempts stay within `stepRetries + 1`.
- **Every failing step is retried or hands off.** A failing step other than a gate, hook or hand-off that is not retried
  hands off: its retries are spent, or the loop chose not to use them. After it, only hook steps follow (an abort among
  them), then the HANDOFF step, and the loop ends HANDED_OFF: a hook abort does not replace the human (H10's operator
  review, H11's reconciliation of an unknown outcome). Re-issuing a failed call as a fresh step therefore cannot reset
  its attempt count.
- **A delegation that failed hands off; it is never retried.** A delegated loop's own retry and revision bounds are the
  bounds: retrying a delegation would re-run its unsettled side effects, retry around its hook abort or hand-off, and
  give it a second revision budget.
- **Side effects are never repeated unsafely** (H11: unknown side effects are not retried; non-idempotent actions retry
  only with an authoritative receipt lookup proving no prior effect):
  - an `UNKNOWN` write without idempotency is never retried, and neither is a delegation whose child holds one;
  - a launched receipt-keyed write is retried only with the same input (the same key);
  - a write without idempotency is retried only after the gateway denied the call before launch, or after a FAIL or
    ERROR whose receipt reference records the evidence of no effect.

**Revisions** (A3, Q-MAS8-C). A revision is a MODEL step that `revises` an earlier MODEL step's artefact, in answer to a
gate that failed it. It carries that gate's error trace as its `feedback`, and its attempt is 1. Each step is revised at
most once (a retry of a revision shares its target), so the revisions of an artefact form one chain. The chain's rounds
stay within `revision.rounds`. A failed gate's step (its diagnosis) is consumed only by a revision of its subject: a
step that reads the diagnosis is a declared revision, within the budget.

**Terminal status.** The status is honest:
- `COMPLETED` delivers (`delivered`) the artefact of a MODEL step that succeeded. Only a COMPLETED loop delivers.
- `HANDED_OFF` ends with its single HANDOFF step, which succeeded.
- Hooks that aborted (a failing hook included) end the loop: they are the last steps, all on one event (several ABORT
  hooks on one event compose), followed only by the HANDOFF-event hooks and the HANDOFF step of a loop that hands off.
- `ABORTED` states its reason: `HOOK_ABORT` exactly when hooks aborted and the loop does not hand off, and otherwise
  `BUDGET_EXHAUSTED`.
- `FAILED` is a loop that a deterministic gate did not pass, typically with its revision budget spent.

## Refusal codes and the order of each check

**Profile checks.** `PROFILE_CODES` are `SHAPE`, `DUPLICATE_ID` and `HOOK_CONFLICT`. A profile check runs them in this
order:
1. SHAPE;
2. DUPLICATE_ID: hook, gate and tool IDs; effects within a hook; credential parameters within a tool;
3. HOOK_CONFLICT.

**Trace checks.** `TRACE_CODES`, in check order:
1. `SHAPE`.
2. `DUPLICATE_ID`: step IDs, sequence numbers, capability grants, delegated child traces, and credential parameters
   within a call.
3. `STEP_ORDER`: sequence numbers strictly increase, and start times never go back or precede the trace's start.
4. `UNKNOWN_REFERENCE`, which covers:
   - the profile: stored under its digest, and passing its own check or failing it only by a hook conflict;
   - consumed, retried, revised and gated steps, which must be earlier in the trace;
   - tools, gates and hooks, which the profile must register;
   - child traces, stored under their digest and passing their own check;
   - the delivered step.
5. `HOOK_CONFLICT`: the profile's hooks conflict.
6. Then one whole-trace pass per rule:
   `HOOK_NOT_REGISTERED`, `RECURSION_DEPTH`, `DELEGATION`, `TOTALS_MISMATCH`, `BUDGET_EXCEEDED`, `ERROR_TRACE`,
   `INVALID_TOOL_INPUT`, `CAPABILITY_MISMATCH`, `CAPABILITY_EXPIRED`, `CREDENTIAL_RULE`, `TRUST_LABEL`, `PROVENANCE`,
   `UNGATED_CONSUMPTION`, `GATE_OVERRIDDEN`, `RETRY_WITHOUT_TRACE`, `RETRY_BOUND`, `UNKNOWN_SIDE_EFFECT_RETRIED`,
   `REVISION_BOUND`, `HANDOFF_MISSING`, `TERMINAL_STATUS`.

`RECURSION_DEPTH` requires:
- the trace's depth is within its profile's `recursionDepth`;
- a depth-0 trace has no parent, and a depth-1 trace has one;
- a delegation only when depth + 1 is within the profile's limit, and the child is at depth + 1 and names this trace as
  its parent.

A check raises the first code it meets. Nothing but these refusals escapes a check: anything malformed is `SHAPE`.

## Binding to H10, H11, H13 and H15

This contract is the record of one agent loop inside H10 and H11:
- H10 keeps its task API, durable execution, retries under its error taxonomy and delegation budgets.
- H11 keeps tool admission, least privilege, approvals, credential brokering, sandboxes and receipts.

H15 measures the contract's budget fields. H13's controls appear here as the capability references, broker-only
credentials, trust labels with their gate rule, and the output-is-data rule. None of the four harnesses' documents or
schemas changes.

## Grounding (crosswalk pages)

- **JAZ** (2609.26891) pp. 4-5, 7, 13-14, 23-24:
  - 13 staged hook events over invoke, model query and execution;
  - composable effects with conflicts refused;
  - local and dynamic scope;
  - budgets and depth limits, with exhaustion as an exception and an aborted span.

  An uncapped run reached recursion depth 70, and its rules were prompt-level only. That is why execution stays in H11's
  sandboxes and depth is capped here.
- **HERMES** (2610.07832) pp. 15-16, 20-21, 23: a revision budget (default 3; returns beyond 3 are at most 0.9 points), a
  diagnosis schema, and deterministic failures that cannot become a pass.
- **HarnessDev** (2609.01437) pp. 5, 8, 22, 24, 27-28: a six-module interface, an honest tri-state status,
  provider-neutral model configuration, per-task caps, and validating final artefacts.
- **Harness-Zero** (2609.24974):
  - p. 8: a turn limit;
  - pp. 2, 22-23: one execute tool, and one level of delegation.
- **Secondary:**
  - a reproduction of RLM reporting accuracy falling from 100% to 70% at depth 2;
  - Stripe's reported rule of one fix attempt, then a human;
  - the compounding figure from the Gemini synthesis.

## Owner decisions (2026-10-13, owner via the lane monitor; verbatim)

- Q-MAS8-A = (a): an internal candidate under architecture/agent-loop/, naming R08 and CONF-A3-001 as consumers; H10's and H11's documents and schemas unchanged.
- Q-MAS8-B = (a): recursion depth at most 1 in v1 with no override; deeper only by a later revision with its own evidence.
- Q-MAS8-C = (a): a failing step retries at most once by default and at most 3 times in any profile, each with its error trace fed back, then hand-off to a human; artefact revision rounds have a separate budget, default 3 and max 3.
- Q-MAS8-D = (a): a per-call capability-token reference bound by digest to H11's grant (tool, manifest, scope, expiry), with fields checked by the contract; issuing, signing and verifying stay with H11's broker; no keys in the vectors.

## Not claimed

- **No implementation.** No kernel, gateway or broker exists; nothing writes a profile or trace outside the vectors.
- **A record, not a monitor.** A trace shows what a loop recorded. It cannot show:
  - that every step was recorded;
  - that a digest names the bytes that ran;
  - that a step's tokens and times are true. H15 measures them; H11's receipts and H16's signer bind them.
- **Budget exhaustion is the kernel's statement.** The contract checks that totals never exceed the budgets. It cannot
  check that a loop ending `BUDGET_EXHAUSTED` had no room for another step.
- **Capability and receipt references only.** Grant digests, scopes, expiries and receipt references are checked for
  presence and consistency. Whether a grant or receipt is genuine, signed and unrevoked, and whether a receipt really
  proves no effect, is for H11's broker to verify. Grants are unique within a parent and its delegated loops, not across
  loops.
- **One sequential loop.** v1 records a sequential loop: after a step that must hand off, only hooks and the hand-off
  follow. Concurrent branches (parallel tool calls, or Harness-Zero's up to four concurrent delegations) where one
  branch fails cannot be recorded.
- **Undeclared attempts.** A fresh model step that reads neither a failed artefact nor its gate's diagnosis, and a new
  delegation for the same task after a delegated loop's artefact failed the parent's gate (a new child with its own
  bounds), are not revisions; the parent's iteration and token budgets bound them. Disguised model retries are likewise
  not detectable beyond the hand-off rule.
- **Trust labels are declared, not measured.** The label follows the tool's declared trust. Whether an untrusted output
  carried an injection is H13's and MAS-RA-010's; a model step reading untrusted output is allowed.
- **Hook placement.** A hook step must match its registration; HANDOFF-event hooks fire only in a loop that hands off,
  right before its HANDOFF step. Whether a hook fired at the right point otherwise (for example before the tool call it
  guards) is not checked.
- **Approvals.** H11's per-execution human approval for irreversible tools is not recorded in a call; approvals stay
  H11's.
- **A delegated trace checked alone** names its parent, but its parent's existence is checked only when the parent's
  trace is checked.
- **Timing across loops** is checked only at the delegation's start. A child's own end time is not compared with the
  parent's later steps.
- The cited figures are the source papers' results, not platform evidence.
