# Run events, OpenTelemetry GenAI mapping and MAS metrics v1 (MAS-RA-003)

Alpha 2; 2026-10-14. Status: **CONTRACT_CANDIDATE** (independent review round 2). DATA_CHECK_ONLY: an internal contract
candidate with schemas, a reference model and vectors. It changes no public contract, selector, catalog or runtime, and it
leaves H15's, H16's and H10's harness documents (`docs/harnesses/trust.observability-finops.md`,
`docs/harnesses/trust.evaluation-assurance.md`, `docs/harnesses/execution.orchestration.md`) and the repository schemas
byte-identical (owner decision Q-MAS3-A).

One ordered event model for execution, verification and replay. Every run, agent step, model call, tool call, verification
check, inter-agent message, environment transition, claim and merge is a RunEvent in one stream per root run; large
payloads are references, never content. The coordination metrics the MAS syntheses ask for (speedup, parallel efficiency,
duplicated work, conflicting claims and the rest) are computed exactly from that stream, and a trace can carry MAST
failure-mode annotations that point at its events.

Crosswalk: `architecture/research-adoption-v2/crosswalk.json`, item MAS-RA-003, acceptance IDs MAS-RA-003-A1 to -A3.
Harnesses: primary H15 `trust.observability-finops`; secondary H16 `trust.evaluation-assurance` and H10
`execution.orchestration`. Consumers (Q-MAS3-A): R09 (the trust plane) and MAS-RA-004 (coordination) and MAS-RA-006
(replay).

## Files

| File | Content |
|---|---|
| `run-event-log.schema.json` | `planeon.internal.run-event-log/v1`: one root run's ordered events, with the records it derives from |
| `mas-metrics.schema.json` | `planeon.internal.mas-metrics/v1`: the eighteen metrics of one or more logs |
| `mast-annotation.schema.json` | `planeon.internal.mast-annotation/v1`: MAST failure modes read from a log, with their evidence |
| `vectors.json` | 48 cases (14 valid, 34 refused; every log, metric and annotation code at least once) over shared stores (the agent-loop contract's profiles and traces, two run manifests and 12 logs, one of them deliberately stored under a key that is not its digest and one that fails the log check), 3 raw-text cases, the metric list, the MAST vocabulary, the OTel table with its pinned source, and 2 OTel projections |
| `../../scripts/run_events.py` | Reference model, standard library only: `check_log`, `derive_log`, `compute_metrics`, `check_report`, `check_annotation`, `to_otel`, `parse`, `canonical`, `digest`; run directly, it replays every vector and projection |

**Schemas and model.** The schemas state the closed shapes, including each operation's attribute set per phase. The model
refuses a document as `SHAPE` exactly when its schema rejects it (patterns end in `(?![\s\S])`, so a trailing newline is
refused by both; the builder checks this on every string of the valid team log, report and annotation), with one case the
schema cannot state (evidence sequence numbers in ascending order, `schemaAccepts`). Order, pairing, references and every
later rule belong to the model alone. **Isolation:** each log refusal case is a minimal deviation; with its own rule
disabled it passes.

## The run-event log (A1)

A log has a root run id, an OpenTelemetry trace id (32 hex digits, not all zero), the digests of the records it was
derived from (an MAS-RA-008 loop trace, an MAS-RA-002 run manifest, an MAS-RA-001 verdict ledger; each optional, Q-MAS3-B)
and its events. Each event has:

| Field | Meaning |
|---|---|
| `sequence` | 1, 2, … in list order |
| `logicalTime` | never decreases; a message is received at a later logical time than it was sent |
| `timeMs` | milliseconds from the root run's start (integer, Q-MAS3-E); the root run starts at 0 |
| `runId`, `agentId` | the run the event belongs to and that run's agent (one agent per run) |
| `spanId`, `parentSpanId` | the OpenTelemetry span (16 hex digits) and, for a span's START and END, its parent span |
| `operation`, `phase` | a span operation (RUN, AGENT_INVOKE, MODEL_CALL, TOOL_CALL, VERIFICATION) with START and END, or a point (HOOK, HANDOFF, MESSAGE, ENVIRONMENT, CLAIM, MERGE) attached to an open span |
| `name` | the step or run name |
| `outcome` | on END only: OK, FAIL, ERROR or UNKNOWN for a step; COMPLETED, FAILED, HANDED_OFF or ABORTED for a run |
| `payloadRef` | `{digest, store}` of the payload, or null: never the payload itself (Q-MAS3-C) |
| `inputHash`, `outputHash` | digests of the input and the output |
| `attributes` | the closed set of this operation and phase: tokens (on every END, and on HOOK and HANDOFF points); attempts; a model call's provider and model (null when unknown); tool and grant identities; gate and subject; a hook's result; message direction and peers; claim and task; merge conflict; a run's cost in micros (`costMicros`, millionths of its configuration's currency unit, as MAS-RA-002's `costMicros`; null when unknown) |

No field is meant to carry prompt, completion, tool input or tool output content (Q-MAS3-C).

Rules (codes in order): `SHAPE`; `DUPLICATE_ID` (span, run, message per direction, claim and merge ids);
`SEQUENCE`; `RUN_BOUNDS` (the root run's START first and its END last; depth 0 exactly when no parent run);
`SPAN_ORDER` (a span starts once under an open parent and ends once, with its START's identity, after every span it
parents; a point attaches to an open span; nothing outside the root); `RUN_SCOPE` (every event of a run lies in that run's
span and has that run's agent; a child run opens under the parent run's AGENT_INVOKE that names it, one level deeper; a
verification's subject and a revision's target are earlier spans of the same run); `LOGICAL_TIME`; `TIME_ORDER` (times nest
like the spans: the root starts at 0 ms; a span ends no earlier than it starts, starts no earlier than its parent starts
and ends no later than its parent ends; a point lies within its span); `MESSAGE_PAIRING` (every received message was sent
earlier by its sender to its receiver with the same tokens and payload); `CLAIM_CONFLICT` (a conflicting claim names an
earlier claim on the same task by another agent; a claim with such an earlier claim says so); `UNKNOWN_REFERENCE` (every
named source record is stored under its digest and hashes to it); `SOURCE_BINDING` (a named run manifest is this root
run's: its `runId` is the log's root run id and its `ledgerDigest` is the log's verdict ledger digest, both null or both
the same); `DERIVATION`. The manifest and the ledger are checked here for presence, digest and this binding only; their own
models (MAS-RA-002, MAS-RA-001) check them.

## Derivation from the agent loop (Q-MAS3-B)

`derive_log(trace, stores, loop, bindings)` turns an MAS-RA-008 loop trace that passes its own check into its log,
deterministically: the run as a RUN span; MODEL, TOOL, GATE and DELEGATE steps as MODEL_CALL, TOOL_CALL, VERIFICATION and
AGENT_INVOKE spans (the child run's events inside the AGENT_INVOKE span); HOOK and HANDOFF steps as points on the run span,
a hook with its result. Every step's tokens are kept. Span ids and the trace id are derived from run and step ids by
SHA-256; times are milliseconds from the root run's start (a step ends at its start plus its wall-clock seconds, and a run
or delegation ends no earlier than anything inside it); logical time is the sequence; a run's agent is its run.

- **Bindings.** A loop trace does not record the run manifest, the verdict ledger or the cost, so the derivation takes
  them as `bindings` (`runManifestDigest`, `verdictLedgerDigest`, `costMicros` for the root run; all null by default). A
  log that names a loop trace must equal the derivation with the log's own bindings (`DERIVATION`); the other rules check
  the bindings (`UNKNOWN_REFERENCE`, `SOURCE_BINDING`).
- **Precondition.** The trace ids of a delegation tree must be distinct, since run and span ids derive from them;
  MAS-RA-008 does not require it, so a tree that reuses one is refused (`DERIVATION`).
- **What a derived log leaves to the trace.** The model's provider and model identity (MAS-RA-008 records none; both
  null), a step's `retryOf`, `feedback` and `consumes`, credential references, a tool call's input-schema digest,
  capability details other than the grant digest, and budgets. The referenced trace is the record of those fields.

Every valid trace of the agent-loop vectors (36) derives into a log that passes every rule (the builder checks this). The
derivation takes the agent-loop model as an argument, so its caller decides which bytes of it run.

## MAS metrics (A2, Q-MAS3-E)

A report names one or more logs (`runs`) and optionally a `baseline`. Every named log is stored under its digest and hashes
to it (`UNKNOWN_REFERENCE`). Input conditions (`METRIC_INPUT`): every log passes the log check, the runs share one agent
count, and the baseline has one agent and is not among the runs. Each metric is an exact rational in lowest terms
(`numerator`, `denominator`) with a unit; a zero denominator is `UNDEFINED`, never 0 or infinity. A report must equal the
model's computation (`METRIC_VALUE`).

| Metric | Unit | Formula |
|---|---|---|
| cost_per_success | cost-micros/success | Σ cost micros of the root runs ÷ number of root runs COMPLETED (UNDEFINED if any cost is unknown) |
| speedup | ratio | T1 × \|runs\| ÷ Σ TN (T = root run duration; T1 the baseline's) |
| parallel_efficiency | ratio | T1 × \|runs\| ÷ (N × Σ TN), N the number of agents |
| message_overhead | messages/work-span | messages sent ÷ MODEL_CALL and TOOL_CALL spans |
| token_overhead | ratio | tokens of messages sent ÷ tokens of MODEL_CALL and TOOL_CALL spans |
| duplicated_work_ratio | ratio | OK work outputs already produced by another agent ÷ OK work outputs |
| conflicting_claim_rate | ratio | conflicting claims ÷ claims |
| merge_conflict_rate | ratio | conflicting merges ÷ merges |
| idle_time | ms | Σ over runs of the run's duration less the time any of its work spans is open |
| orchestrator_bottleneck_time | ms | time the root agent works while another agent's run is open and no other agent works |
| invalid_actions | count | tool calls with an invalid input |
| retries | count | work and verification spans at attempt > 1 |
| replans | count | model calls that revise an earlier span |
| stalled_turns | count | OK model calls whose output repeats the same agent's previous OK model output |
| evidence_coverage | ratio | OK outputs whose bytes some OK verification in the log verified ÷ OK outputs (model calls, untrusted tool results and delegations; trusted tool results are not gated, as in MAS-RA-008); keyed by bytes, since a gate on the same bytes decides the same |
| unresolved_fraction | ratio | verifications ending UNKNOWN ÷ verifications |
| verifier_disagreement | ratio | (gate, subject bytes) pairs with both an OK and a FAIL verdict ÷ (gate, subject bytes) pairs verified; a subject with no output is keyed by its span |

## MAST annotation (A3, Q-MAS3-F)

The vocabulary is the MAST taxonomy (Cemri et al., "Why Do Multi-Agent LLM Systems Fail?", arXiv 2503.13657v3; the copy
in `roadmap/research/papers/2503.13657.pdf`, sha256 `1b9e317a2a421e60ca2b2eda4a30844557a01e63286a790890c0ecef32d25460`):
three categories and fourteen modes, named as the paper's Appendix A names them (sentence case, the paper's typographic
apostrophe in FM-2.5; Figure 1 on page 2 uses title case). The definitions are in Appendix A, pages 17-18, cited here, not
restated.

| Category | Modes |
|---|---|
| FC1 System Design Issues | FM-1.1 Disobey task specification; FM-1.2 Disobey role specification; FM-1.3 Step repetition; FM-1.4 Loss of conversation history; FM-1.5 Unaware of termination conditions |
| FC2 Inter-Agent Misalignment | FM-2.1 Conversation reset; FM-2.2 Fail to ask for clarification; FM-2.3 Task derailment; FM-2.4 Information withholding; FM-2.5 Ignored other agent’s input; FM-2.6 Reasoning-action mismatch |
| FC3 Task Verification | FM-3.1 Premature termination; FM-3.2 No or incomplete verification; FM-3.3 Incorrect verification |

An annotation names a log by digest and lists entries `{annotationId, mode, evidence, annotator}`, the evidence being the
sequence numbers of the events it rests on (ascending, within the log). Codes: `SHAPE`, `DUPLICATE_ID`,
`UNKNOWN_REFERENCE` (the log is not stored under its digest), `ANNOTATION_INPUT` (the log fails the log check),
`ANNOTATION_EVIDENCE`. An annotation records a reading: it never changes a verdict, an outcome or a metric.

## OpenTelemetry GenAI mapping (A1, Q-MAS3-D)

Pinned source: `open-telemetry/semantic-conventions-genai` at commit `4e8a2812139b2a999d959e3650e24dfc64e21943` (the GenAI
conventions left `open-telemetry/semantic-conventions` after v1.41.1; the new repository has no release yet, its manifest
says stability `development` and schema URL `gen-ai-dev/1.42.0-dev`; re-pinned at its first release). The seven files are
operator-side evidence; `vectors.json` (`otelSource`) records the SHA-256 of all seven, and the builder checks each and the
table below against them: every GenAI span type exists with the stated kind, every operation name is a member of
`gen_ai.operation.name`, every attribute exists in the registry, and every attribute the span type requires is mapped.

| Operation | OTel span | Kind | `gen_ai.operation.name` | Name | Attributes (from) |
|---|---|---|---|---|---|
| RUN | `gen_ai.invoke_agent.internal` | INTERNAL | invoke_agent | `invoke_agent` | `gen_ai.agent.name` (agentId), `gen_ai.conversation.id` (runId) |
| AGENT_INVOKE | a plain span | INTERNAL | none | `delegate` | `planeon.childRunId` |
| MODEL_CALL | `gen_ai.client.inference` | CLIENT | chat | `chat {model}`, or `chat` when the model is unknown | `gen_ai.conversation.id` (runId), `gen_ai.provider.name` (provider), `gen_ai.request.model` (model) |
| TOOL_CALL | `gen_ai.execute_tool.internal` | INTERNAL | execute_tool | `execute_tool {toolId}` | `gen_ai.tool.name` (toolId), `gen_ai.tool.call.id` (name), `gen_ai.agent.name` (agentId), `gen_ai.conversation.id` (runId) |
| VERIFICATION | a plain span | INTERNAL | none | `verify {gateId}` | `planeon.gateId`; its END adds the event `gen_ai.evaluation.result` (`gen_ai.evaluation.name` gateId, `gen_ai.evaluation.score.label` outcome) to the span it evaluated |

- Trace and span ids are the log's. An attribute whose source is null is left out (OTel attribute values are never null),
  and so is its part of the name. A span's END outcome other than OK or COMPLETED sets status ERROR and the core attribute
  `error.type` (the outcome; `error.type` belongs to the core registry the GenAI manifest depends on, v1.44.0, which is not
  pinned here).
- **Delegations.** A delegation is one `invoke_agent` span, the child RUN, inside a plain `delegate` span (the
  AGENT_INVOKE), so agent invocations are not counted twice.
- **Evaluation events** are attached to the evaluated span (the pinned `events.yaml` says the event should be parented to
  the evaluated operation's span), with the verification's end time, which may be after that span's end.
- **Span names** hold only bounded identifiers (tool, gate and model ids). Run and agent ids grow with the runs (a derived
  log's agent ids are its run ids), so they stay attributes and never enter a name (H15's bounded cardinality).
- **Tokens** stay `planeon.tokens`: the registry has input and output token attributes but no total, and a run event holds
  only the total. They are inclusive (a run's tokens include its delegations'), so they are never summed across spans; the
  `delegate` span carries none.
- **Provider and model.** `gen_ai.provider.name` is required on a chat span. A log that does not know a call's provider
  (every derived log: MAS-RA-008 records none) projects a chat span without it; nothing else supplies it yet.
- Points become span events named `planeon.<operation>` with their non-null attributes under `planeon.`.
- Never emitted (Q-MAS3-C): `gen_ai.input.messages`, `gen_ai.output.messages`, `gen_ai.system_instructions`,
  `gen_ai.tool.definitions`, `gen_ai.tool.call.arguments`, `gen_ai.tool.call.result`, `gen_ai.retrieval.documents`,
  `gen_ai.retrieval.query.text`, `gen_ai.memory.records`, `gen_ai.memory.query.text`, `gen_ai.prompt.variable`,
  `gen_ai.evaluation.explanation`, `gen_ai.agent.description`, `gen_ai.main_agent.description`,
  `gen_ai.tool.description`, `gen_ai.skill.description`.

The model's `to_otel(log)` produces the spans; `vectors.json` pins the projections of the three-agent log and a derived
parent log.

## Owner decisions (2026-10-14, via the lane monitor)

Quoted verbatim, with `[…]` marking an elision; the full texts are in the operator's plan record.

- Q-233: "(a): you build MAS-RA-003 (run-event schema, OTel GenAI mapping and MAS metrics, H15) as harness-onion slot 233,
  in the gaps of HE-002S/HE-003. […]"
- Q-MAS3-A: "(a): internal candidate under architecture/run-events/; consumers R09 and MAS-RA-004/-006; H15, H16 and H10
  documents and schemas unchanged."
- Q-MAS3-B: "(a): RunEvent is the canonical envelope; loop trace, ledger and manifest referenced by digest; a deterministic
  rule derives a loop trace's events, with vectors."
- Q-MAS3-C: "(a): payloads by reference only; no content fields; OTel content attributes listed as never emitted."
- Q-MAS3-D, as decided after the source check: "(D-a): pin open-telemetry/semantic-conventions-genai at commit
  4e8a2812139b2a999d959e3650e24dfc64e21943. Download exactly the 7 files […] into operator state with sha256; record the
  development stability; re-pin at its first release."
- Q-MAS3-E: "(a): exact integer rationals with declared units; zero denominator UNDEFINED; integer ms, tokens and cost."
- Q-MAS3-F, two texts: the decision "(a): use the MAST paper (arXiv 2503.13657) verbatim with page citations. […]" and the
  owner's correction "[…] The owner placed it at roadmap/research/papers/2503.13657.pdf […] Use that file under its current
  name and record the sha256. […]" (sha256 above).

## Not claimed

- **No implementation.** No collector, exporter, store or dashboard: H15's TRUST-OBS-001 and SDK-002 own them; no telemetry
  leaves the tenant. MCP and A2A stay wire adapters; this event model is the persistence and replay format.
- **A record, not a monitor.** A log shows what was recorded. It cannot show that every event was recorded, that a digest
  names the bytes that ran, or that times and tokens are true (H15 measures them).
- **No content by design.** No field is meant for content, but identifiers of up to 64 characters (names, agent, tool and
  gate ids) could carry short text, which the contract cannot detect; tool, gate and model ids also appear in span names.
- **Derived times are approximate.** A derived step ends at its start plus whole wall-clock seconds; a run or delegation
  is stretched to end no earlier than anything inside it.
- **Expressiveness.** A received message needs its send in the same log, so a message from an external (A2A) peer cannot
  be recorded; each message id has one sender and one receiver (no broadcast); claims are never released, so handing a task
  to another agent is recorded as a conflicting claim and counts in `conflicting_claim_rate`; delegation depth is at most 1
  (from MAS-RA-008's Q-MAS8-B), so deeper MAS-RA-004 hierarchies cannot be logged yet.
- **Metric scope.** Each metric is computed from the events alone. Speedup compares the given baseline with the given runs;
  whether they solved the same task is the reporter's (MAS-RA-002's comparability locks apply). Idle and bottleneck times
  use the recorded work spans; waiting inside a span is busy time.
- **MAST is a reading.** The fourteen modes are the paper's; whether an annotation is right is the annotator's; it binds
  no verdict.
