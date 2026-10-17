# Topology and coordination v1 (MAS-RA-004)

Alpha 3 contract, built in Alpha 2 (as MAS-RA-008, owner decision Q-231); 2026-10-16. Status: **CONTRACT_CANDIDATE**
(internal, DATA_CHECK_ONLY; independent review pending). Roadmap item MAS-RA-004 (H10 primary; H9, H8, H13 secondary).

The contract fixes, as closed data with a standard-library reference model and replayable vectors:
- **A1** a TopologySpec: the agents of one task as a closed graph, one AgentSpec per role, and the MASS-style role-block
  vector derived from it;
- **A2** one Coordinator contract with two reference modes, a central coordinator and a decentralized board, both on
  exclusive leased claims with deterministic arbitration and a verify-before-merge gate by an independent verifier;
- **A3** the topology-selection rule and the agent budget.

Nothing runs. No board storage (MAS-RA-009 keeps it), no executor (EXEC-TEMPORAL-001 keeps the selection), and H10's, H9's,
H8's and H13's documents, the repository schemas and every earlier contract stay byte-identical.

## Files

| File | What it is |
|---|---|
| `topology-spec.schema.json` | `planeon.internal.topology-spec/v1` (draft 2020-12, closed) |
| `board-transcript.schema.json` | `planeon.internal.board-transcript/v1` (draft 2020-12, closed; one variant per operation) |
| `vectors.json` | `planeon.internal.topology-coordination-vectors/v1`: 66 cases (10 valid), 3 texts, 18 selection rows |
| `../../scripts/topology_coordination.py` | the reference model; `python3 scripts/topology_coordination.py` replays every vector |

The schemas carry the SHAPE rules; the model checks the same shapes (`_topology_shape`, `_op_shape`) and refuses as
SHAPE exactly when the schema rejects (every vector agrees). Rules beyond shape are the model's.

## Record format

As MAS-RA-001 to MAS-RA-003: I-JSON (RFC 7493: UTF-8, no duplicate member names, no NaN or infinity, no lone surrogate),
integers only, within ±(2⁵³−1); canonical bytes are RFC 8785 (JCS); `digest` = `sha256:` + hex of the canonical bytes.
Records refer to each other only by digest, looked up in the caller's stores, and a stored record must hash to its key.

## A1: TopologySpec

`{schemaVersion, topologyId, objectiveId, mode, agents, nodes, edges, assignmentPolicy, arbitrationPolicy, concurrency,
leaseSeconds, deadlineSeconds, agentBudget, selection}`.

- `mode` is SINGLE_AGENT, CENTRAL or DECENTRALIZED; `assignmentPolicy` is NONE, COORDINATOR_ASSIGNS or CLAIM_FROM_BOARD
  respectively; `arbitrationPolicy` is EARLIEST_THEN_NODE_ID (the only value).
- `agents`: one AgentSpec per role `{role, objectiveId, modelRef {backboneId, configurationDigest}, budgets {tokens,
  iterations, wallClockSeconds, recursionDepth}}`. The roles are COORDINATOR, WORKER and VERIFIER, in that fixed block
  order. Each role binds its own backbone (P11, HERMES: frontier models for orchestration and verification, small models
  for workers, as the role chooses); the budgets reuse the MAS-RA-008 agent-loop vocabulary (Q-M4-6 (a), Q-M4-7 (a)).
- `nodes` `[{nodeId, role}]` and `edges` `[{from, to, kind DELEGATE|MESSAGE}]` form the closed graph (Q-M4-2 (a)). The
  model derives the **role-block vector** `[#COORDINATOR, #WORKER, #VERIFIER]` (MASS: a topology as an integer vector over
  named blocks in a fixed order); the budget and the selection apply to it.
- `concurrency` is the most items held at once; `leaseSeconds` a claim's lease; `deadlineSeconds` the task's deadline;
  `agentBudget` (1..1024) the hard maximum number of agents.
- `selection` `{taskShape SEQUENTIAL|TOOL_HEAVY|DECOMPOSABLE, baselineRecordDigest, outcome}` (A3).

Refusal codes, checked as whole-record passes in this order:

| Code | Rule |
|---|---|
| SHAPE | the schema (closed shapes, enums, ranges, patterns) |
| DUPLICATE_ID | node ids, AgentSpec roles and edges are unique |
| UNKNOWN_REFERENCE | every node's role has an AgentSpec and every AgentSpec is used; edges join known nodes; the baseline record is stored, hashes to its digest and is accepted by MAS-RA-002's model |
| CONFLICTING_OBJECTIVE | every AgentSpec has the topology's single objectiveId: agents with conflicting objectives are denied until MAS-RA-010 passes (Q-M4-10 (a)) |
| MODE_STRUCTURE | SINGLE_AGENT: one WORKER node, no edges, concurrency 1. CENTRAL: exactly one COORDINATOR, at least one WORKER, and DELEGATE edges exactly from it to every other node (depth ≤ 1, Q-MAS8-B). DECENTRALIZED: no COORDINATOR, at least two WORKERs, no DELEGATE edge (peers of a root board run). In every mode: no self-edge, the mode's assignment policy, recursionDepth 1 for the COORDINATOR's AgentSpec and 0 for the others |
| BUDGET | the vector's sum ≤ agentBudget; concurrency ≤ the number of WORKERs |
| SELECTION | the rule below |

`check_run_binding(topology, manifest)` also binds a MAS-RA-002 run manifest that reports a run of the topology: the
manifest must be accepted by MAS-RA-002's model and its `configuration.agentCount` must not exceed `agentBudget` (BUDGET).

## A3: the selection rule

The topology cites a MAS-RA-002 evaluation record of the single-agent configuration (`agentCount` 1, complete). Its
**baseline** is the exact rational Σ scores / (tasks × runs × MAX_SCORE), in lowest terms (MAS-RA-002's MAX_SCORE is
10⁶). A record that is incomplete or not single-agent is refused (SELECTION).

- The task is **restricted** when its declared shape is SEQUENTIAL or TOOL_HEAVY, or its baseline is at or above
  `SELECTION_THRESHOLD`. A restricted task may be SINGLE_AGENT or ORCHESTRATOR_WORKER; an unrestricted one (DECOMPOSABLE
  and below the threshold) may also be SELF_ORGANIZING.
- The outcome must match the mode: SINGLE_AGENT ↔ SINGLE_AGENT; ORCHESTRATOR_WORKER ↔ CENTRAL with at most 4 WORKERs;
  SELF_ORGANIZING ↔ DECENTRALIZED.
- Definitions. **SEQUENTIAL**: each step needs the previous step's result, so the work does not split into independent
  items. **TOOL_HEAVY**: most steps are tool calls whose results the next step needs (environment-bound work).
  **DECOMPOSABLE**: the work splits into items that can be done and verified independently and merged.
- **`SELECTION_THRESHOLD` = 45/100**, a named parameter (owner decision Q-M4-5 (a)). Provenance: Kim et al.'s agent-scaling
  study (260 configurations; from +80.8% on decomposable work to −70.0% on sequential planning against a single agent)
  states "about 45%" only in the abstract of its first version; the later version drops the number. It is a secondary
  source, used as a declared default, and replaceable by MAS-RA-010's measurements.

## A2: the Coordinator and the board transcript

A board transcript `{schemaVersion, transcriptId, topologyDigest, items, operations}` records the operations a
coordinator board answered for one topology, each `{opId, t, agent, op, …, result}` with the answer the board gave. The
model replays them and must reach every recorded answer (REPLAY); it never invents operations.

**Board.** One record per item `{state OPEN|HELD|MERGED, holder, leaseUntil, version}`, version starting at 0 (Q-M4-3 (a):
compare-and-swap on one record per item; MAS-RA-009 keeps the storage). Before each operation at time `t`, every HELD
record whose lease ended (`leaseUntil ≤ t`) becomes OPEN (an expiry; version + 1): an expired lease can be reclaimed.

| Operation | Who | Accepted when | Effect | Refusals (in precedence order) |
|---|---|---|---|---|
| ACQUIRE | a WORKER, DECENTRALIZED only | OPEN, expectedVersion = version, fewer than `concurrency` items held | HELD by the agent for `leaseSeconds`; version + 1 | NOT_PERMITTED, MERGED, HELD, STALE_VERSION, CONCURRENCY_LIMIT |
| ASSIGN | the COORDINATOR, CENTRAL only, to a WORKER it delegates to | as ACQUIRE | HELD by the worker | NOT_PERMITTED, MERGED, HELD, STALE_VERSION, CONCURRENCY_LIMIT |
| RENEW | the holder | HELD, version match | lease from `t`; version + 1 | NOT_HOLDER, STALE_VERSION |
| RELEASE | the holder, or the COORDINATOR in CENTRAL | HELD, version match | OPEN; version + 1 | NOT_HOLDER, STALE_VERSION |
| VERIFY | any node but the holder | HELD; the verdict's MAS-RA-001 ledger names this node as a VERIFIER context and the holder as a GENERATOR context | binds the ledger's status to the current claim | NOT_HELD, SELF_VERIFICATION, LEDGER_MISMATCH |
| MERGE | the holder (single writer) | HELD, version match, the latest verdict bound to this claim is PASS | MERGED; version + 1 | NOT_HOLDER, STALE_VERSION, NO_VERDICT, VERDICT_NOT_PASS |
| MESSAGE | any node, along a MESSAGE edge | the edge exists | none | OFF_EDGE |

Every new operation after `deadlineSeconds` is DEADLINE (a retry repeats its original answer). A claim's verdicts end with the claim: a release or an expiry
clears them, a renewal keeps them.

- **Independent verification (Q-M4-9 (a)).** A merge needs a PASS verdict from a different agent context than the work's
  author, recorded as a MAS-RA-001 verdict ledger (its own rule refuses a verdict from the generating context, Q-MAS1-C).
  The holder verifying its own item is SELF_VERIFICATION; a ledger whose VERIFIER or GENERATOR context is not the
  verifying node or the holder is LEDGER_MISMATCH. This is a deliberate departure from Agensh, whose merge gate is the
  worker's own verification and self-merge.
- **Messages** are directed and typed (HERMES): `{to, messageType INTERFACE|DEPENDENCY|BEHAVIOR|TEST|CONFIGURATION,
  requiredAction NONE|ACKNOWLEDGE|CHANGE}`, one recipient, only along a declared MESSAGE edge. There is no broadcast.
- **Deterministic arbitration.** Operations apply in `(t, agent nodeId, opId)` order whatever their order in the
  transcript, so simultaneous acquires resolve the same way everywhere (vector B03 replays a reversed transcript).
- **Durable, idempotent transitions (Q-M4-8 (a)).** An operation with `retryOf` repeats an earlier operation's body, gets
  that operation's answer again and changes nothing. The central mode is executor-neutral: a durable state machine with
  idempotent transitions, recorded leases and resumption after a crash. PostgreSQL (H10's current orchestrator) and
  Temporal (the retained reference) are both admissible implementations; the contract selects neither.

Transcript refusal codes, in order: SHAPE; DUPLICATE_ID (operation ids, items); UNKNOWN_REFERENCE (the topology is
stored, hashes and passes the topology check; every agent, worker and message recipient is a node; every item is listed;
a retried operation exists; a verdict ledger is stored, hashes and is accepted by MAS-RA-001's model); MODE (a
SINGLE_AGENT topology has no board); RETRY (a retry repeats an earlier, non-retry operation's exact body); REPLAY.

## Mapping into run-events v1 (Q-M4-4 (a))

run-events v1 (MAS-RA-003) stays unchanged and remains the canonical internal record. The model derives, for every
transcript, the v1 points of its accepted operations, in application order:
- ACQUIRE / ASSIGN → `CLAIM {claimId opId, taskDigest digest({"item": item}), conflictsWith}` on the holder's run;
  `conflictsWith` names the latest earlier claim on the item by another agent (v1's CLAIM_CONFLICT rule), so a reclaim
  after a release or an expiry is recorded as a conflicting claim, v1's documented limit;
- MERGE → `MERGE {mergeId opId, conflict false}`;
- MESSAGE → a `MESSAGE` SEND on the sender's run and a RECEIVE on the recipient's;
- VERIFY → a VERIFICATION span on the verifier's run, referencing the ledger.

The steps v1 cannot represent are listed as **gaps**, carried to a run-events v2: renewals, releases, expiries, every
refused operation, retries, message types and required actions other than INTERFACE/NONE. The decentralized mode maps to
v1 as one root board run whose depth-1 children are the peers; depth stays ≤ 1.

## Vectors

`vectors.json`: `stores` (topologies, MAS-RA-002 evaluation records with their manifests and splits, MAS-RA-001 ledgers),
`cases` (40 topology, 24 transcript, 2 binding), `texts` (3 raw-text SHAPE cases) and `selection` (18 rows of the rule,
at and around the threshold). Each case is `{id, kind, intent, document, expect, facts?}`; refusals are minimal
deviations from a valid document. The records are those contracts' adopted vectors, with edited scores or agent counts
(the record at exactly 45/100, a two-agent record) and the ledgers' context ids renamed to node ids; each is checked by
its own contract's model when the vectors are built. Transcripts are hand-written (Q-M4-11 (a)): every recorded answer is
written by hand, and the model must reach it. MAS-RA-010 keeps the fake-model, fake-clock simulation with faults.

## Binding to the harnesses

- **H10** (orchestration, task API): the TopologySpec and the board semantics are H10's to adopt; its durable execution,
  retries and delegation budgets stay authoritative (MAS-RA-008's bindings unchanged).
- **H9**: MCP at the tool edge, A2A at the external agent edge (its planned SDKs); no A2A peer is modelled here.
- **H8**: the board is H8 state; MAS-RA-009 defines its storage kinds; tenant isolation, RLS and no-egress apply in
  every mode.
- **H13**: claim arbitration and the conflicting-objective denial are H13 controls.

## Grounding

- Agensh (2609.26781, design reference only): a CLAIM is advisory and append-only, with no lock, lease, expiry or release;
  collisions settle by direct message; the merge gate is self-verification plus self-merge. This contract adds
  exclusivity (leases with compare-and-swap) and an independent verify-before-merge gate as explicit choices.
- HERMES (2610.07832): directed typed messages with a required action, the single-writer rule per artifact, heterogeneous
  allocation by role.
- MASS (2502.02533): a topology as an integer vector over named blocks with a hard agent budget, bound to a backbone id.
- Kim et al. (agent scaling, secondary): the selection rule and its threshold, as above.

## Owner decisions (2026-10-16, verbatim, via the lane monitor)

- "MAS-RA-004" (slot 245, after 244).
- Owner, typed in the monitor chat: Q-M4-2 (a) "Graph + derived vector": a closed graph TopologySpec, with a MASS-style
  role-block count vector derived by the model. The budget and selection apply to the vector, and each role binds a
  backbone/model id. Q-M4-3 (a) "Exclusive leases": compare-and-swap acquire, renew and release on one board record per
  item. Conflicting acquires are refused, an expired lease can be reclaimed, and arbitration is deterministic. MAS-RA-009
  keeps the storage. Q-M4-5 (a) "Declared rule, 0.45": the request declares the task shape (sequential, tool-heavy or
  decomposable) and cites a MAS-RA-002 baseline; the outcomes are SINGLE_AGENT, ORCHESTRATOR_WORKER (≤ 4 workers) or
  SELF_ORGANIZING; the threshold is a named parameter set to 0.45, secondary, cited as Kim et al. v1, and replaceable by
  MAS-RA-010's measurements. Q-M4-9 (a) "Independent verifier": verify-before-merge needs a verdict from a different agent
  context, recorded as a MAS-RA-001 ledger entry. Self-verification alone is refused, a deliberate departure from Agensh.
- Lane monitor (owner-delegated): Q-M4-1 (a): one DATA_CHECK_ONLY contract packet covering A1–A3. Q-M4-4 (a): run-events
  v1 is unchanged, with its own board transcript mapped into it. The gaps are carried to a run-events v2. Q-M4-6 (a),
  Q-M4-7 (a) (the per-role model list is carried to a manifest revision), Q-M4-8 (a) (executor-neutral; EXEC-TEMPORAL-001
  stays the selection item), Q-M4-10 (a), Q-M4-11 (a).

## Carried

- To a run-events v2: release, lease, expiry, broadcast, depth > 1, external A2A peers, message types and required
  actions (the gaps above); MAS-RA-003's carried R3-1 (the delegate span's status) is not taken up here.
- To a run-manifest revision: a per-role model list (the manifest keeps one model field; Q-M4-7 (a)).
- To MAS-RA-010: the threshold's measurement, the simulation with faults, and lifting the conflicting-objective denial.

## Not claimed

- Nothing runs: no coordinator, board, executor or agent; no board storage (MAS-RA-009) and no executor selection
  (EXEC-TEMPORAL-001).
- Objectives, roles and verifier or generator contexts are declared, not authenticated: one agent could appear under two
  node ids (as MAS-RA-001's contexts).
- The selection threshold is a secondary, declared default, not a measurement.
- No external A2A peer, no broadcast, no hierarchy deeper than one level, no run-events v2 or manifest revision.
- No harness document, repository schema or earlier contract changes.
