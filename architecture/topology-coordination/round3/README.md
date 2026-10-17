# Topology and coordination v1 (MAS-RA-004)

Alpha 3 contract, built in Alpha 2 (as MAS-RA-008, owner decision Q-231); 2026-10-16. Status: **CONTRACT_CANDIDATE**
(internal, DATA_CHECK_ONLY; independent review round 3 pending). Roadmap item MAS-RA-004 (H10 primary; H9, H8, H13
secondary).

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
| `topology-run-binding.schema.json` | `planeon.internal.topology-run-binding/v1` (draft 2020-12, closed) |
| `vectors.json` | `planeon.internal.topology-coordination-vectors/v1`: 92 cases (13 valid), 3 texts, 18 selection rows, 2 kinds cases, 2 run-events v1 embeddings |
| `../../scripts/topology_coordination.py` | the reference model; `python3 scripts/topology_coordination.py` replays every vector |

The schemas carry the SHAPE rules; the model checks the same shapes and refuses as SHAPE exactly when the schema rejects
(every vector agrees). Rules beyond shape are the model's. The model takes MAS-RA-002's model (`runs`), MAS-RA-001's model
(`ledgers`) and MAS-RA-001's check-kinds record (`kinds`, pinned: `KINDS_DIGEST`; any other record, also one that is not
canonical JSON, is UNKNOWN_REFERENCE)
as arguments, as MAS-RA-003 takes MAS-RA-008's; the vector runner also loads MAS-RA-003's and MAS-RA-008's models for the
v1 embeddings.

## Record format

As MAS-RA-001 to MAS-RA-003: I-JSON (RFC 7493: UTF-8, no duplicate member names, no NaN or infinity, no lone surrogate),
integers only, within ±(2⁵³−1); canonical bytes are RFC 8785 (JCS); `digest` = `sha256:` + hex of the canonical bytes.
Records refer to each other only by digest, looked up in the caller's stores, and a stored record must hash to its key.

## A1: TopologySpec

`{schemaVersion, topologyId, objectiveId, mode, agents, nodes, edges, assignmentPolicy, arbitrationPolicy, concurrency,
leaseSeconds, deadlineSeconds, agentBudget, selection}`.

- `mode` is SINGLE_AGENT, CENTRAL or DECENTRALIZED; `assignmentPolicy` is NONE, COORDINATOR_ASSIGNS or CLAIM_FROM_BOARD
  respectively; `arbitrationPolicy` is EARLIEST_THEN_NODE_ID (the only value).
- `agents`: one AgentSpec per role, in any order, `{role, objectiveId, modelRef {backboneId, configurationDigest},
  budgets {tokens, iterations, wallClockSeconds, recursionDepth}}`. Each role binds its own backbone (P11, HERMES:
  frontier models for orchestration and verification, small models for workers, as the role chooses). The budgets reuse
  the MAS-RA-008 agent-loop names and ranges (iterations at most 100,000); wallClockSeconds is capped lower here (at most
  2,592,000), a subset of the loop's range (Q-M4-6 (a), Q-M4-7 (a)).
- `nodes` `[{nodeId, role}]` and `edges` `[{from, to, kind DELEGATE|MESSAGE}]` form the closed graph (Q-M4-2 (a)). The
  model derives the **role-block vector** `[#COORDINATOR, #WORKER, #VERIFIER]`: the counts in that fixed block order
  (MASS: a topology as an integer vector over named blocks in a fixed order); the budget and the selection apply to it.
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

**Run binding** `planeon.internal.topology-run-binding/v1` `{schemaVersion, topologyDigest, manifestDigest}`: a
MAS-RA-002 run manifest asserted to report a run of the topology (Q-M4-6 (a)). Codes, in order: SHAPE; UNKNOWN_REFERENCE
(the topology or the manifest is not stored, does not hash to its key, or is refused by the topology check or by
MAS-RA-002's model); BINDING (the manifest's `configuration.agentCount` is not the vector's sum: a run of the topology
reports every agent of it, which the topology already keeps within `agentBudget`). The pairing is asserted by whoever
writes the binding: MAS-RA-002's manifest cannot name its topology (carried to a run-manifest revision).

## A3: the selection rule

The topology cites a MAS-RA-002 evaluation record as its single-agent **baseline**. The record must be eligible: complete,
`agentCount` 1, a clean tree (MAS-RA-002's gate answers a dirty tree UNRESOLVED), of the DEVELOPMENT partition, and
scoring no task that a valid declaration in the stores holds out (MAS-RA-002's store-relative rule; owner decision
Q-MAS2-C (a): held-out scores are never selection input). An ineligible record is SELECTION. The baseline is the exact
rational Σ scores / (tasks × runs × MAX_SCORE), in lowest terms (MAS-RA-002's MAX_SCORE is 10⁶).

- The task is **restricted** when its declared shape is SEQUENTIAL or TOOL_HEAVY, or its baseline is at or above
  `SELECTION_THRESHOLD`. A restricted task may be SINGLE_AGENT or ORCHESTRATOR_WORKER; an unrestricted one (DECOMPOSABLE
  and below the threshold) may also be SELF_ORGANIZING.
- The outcome must match the mode: SINGLE_AGENT ↔ SINGLE_AGENT; ORCHESTRATOR_WORKER ↔ CENTRAL with at most 4 WORKERs;
  SELF_ORGANIZING ↔ DECENTRALIZED.
- Definitions. **SEQUENTIAL**: each step needs the previous step's result, so the work does not split into independent
  items. **TOOL_HEAVY**: most steps are tool calls whose results the next step needs (environment-bound work).
  **DECOMPOSABLE**: the work splits into items that can be done and verified independently and merged. The shape is
  declared by the topology's author; nothing checks that the baseline's suite is the task's.
- **`SELECTION_THRESHOLD` = 45/100**, a named parameter (owner decision Q-M4-5 (a)). Provenance: Kim et al., arXiv
  2512.08296. "About 45%" appears only in the abstract of version 1 (180 configurations); the 260 configurations and the
  range from +80.8% on decomposable work to −70.0% on sequential planning, against a single agent, are version 3's
  abstract, which drops the 45% figure. Both are as reported by the RS-CLAUDE research synthesis; the paper itself was not
  read. A secondary source, used as a declared default, replaceable by MAS-RA-010's measurements.

## A2: the Coordinator and the board transcript

A board transcript `{schemaVersion, transcriptId, tenantId, topologyDigest, items, operations}` records the operations a
coordinator board answered for one topology and tenant, each `{opId, t, agent, op, …, result}` with the answer the board gave. The
model replays them and must reach every recorded answer (REPLAY); it never invents operations.

**Board.** One record per item `{state OPEN|HELD|MERGED, holder, leaseUntil, version}`, version starting at 0 (Q-M4-3 (a):
compare-and-swap on one record per item; MAS-RA-009 keeps the storage). Before each operation at time `t`, every HELD
record whose lease ended (`leaseUntil ≤ t`) becomes OPEN (an expiry; version + 1), also after the deadline: an expired
lease can be reclaimed. A claim is the accepted ACQUIRE or ASSIGN that holds an item; its verdicts are an append-only list
beside the compare-and-swap state, not versioned by it, and end with the claim (a release or an expiry clears them, a new
claim starts empty, a renewal keeps them).

| Operation | Who | Accepted when | Effect | Refusals (in precedence order) |
|---|---|---|---|---|
| ACQUIRE | a WORKER, DECENTRALIZED only | OPEN, expectedVersion = version, fewer than `concurrency` items held | HELD by the agent until t + `leaseSeconds`; version + 1 | NOT_PERMITTED, MERGED or HELD, STALE_VERSION, CONCURRENCY_LIMIT |
| ASSIGN | the COORDINATOR, CENTRAL only, to a WORKER it delegates to | as ACQUIRE | HELD by the worker | NOT_PERMITTED, MERGED or HELD, STALE_VERSION, CONCURRENCY_LIMIT |
| RENEW | the holder | HELD, version match | lease until t + `leaseSeconds`; version + 1 | NOT_HOLDER, STALE_VERSION |
| RELEASE | the holder, or the COORDINATOR in CENTRAL | HELD, version match | OPEN; version + 1 | NOT_HOLDER, STALE_VERSION |
| VERIFY | any node but the holder | HELD; the verdict is bound to this claim (below) | appends the ledger's status and work to the claim | NOT_HELD, SELF_VERIFICATION, LEDGER_MISMATCH, VERDICT_HISTORY |
| MERGE | the holder (single writer), naming `workDigest` | HELD, version match, the claim's latest verdict on this work is PASS | MERGED; version + 1 | NOT_HOLDER, STALE_VERSION, NO_VERDICT (none on the claim), WORK_MISMATCH (none on this work), VERDICT_NOT_PASS |
| MESSAGE | any node, along a MESSAGE edge | the edge exists | none | OFF_EDGE |

Every new operation after `deadlineSeconds` is DEADLINE (a retry repeats its original answer).

- **Independent verification (Q-M4-9 (a)).** A VERIFY carries `verdict {ledgerDigest, scope}`: a MAS-RA-001 verdict
  ledger (stored, hashing to its digest, accepted by MAS-RA-001's model) and the H16 scope tuple it judges. The verdict is
  bound to this claim only if the ledger's `subject.scopeDigest` is MAS-RA-001's `scope_digest(scope)`, the scope names
  the claim (`tenantId` the transcript's tenant, `routeDigest` the transcript's topology, `subjectType` BOARD_CLAIM,
  `subjectId` transcriptId/item, `subjectVersion` the claim's opId), and the ledger has the verifying node as a VERIFIER
  context and the holder as a GENERATOR context; otherwise LEDGER_MISMATCH. So one ledger cannot verify another item,
  another holder's claim, a reclaim of the same item, or a claim of another tenant's or topology's run. Transcript ids are
  assumed unique per tenant and topology; the scope's profile, bundle and routeId are H16's and not checked here. The holder verifying its own
  claim is SELF_VERIFICATION (MAS-RA-001 also refuses a verdict from the generating context, Q-MAS1-C), a deliberate
  departure from Agensh, whose merge gate is the worker's own verification and self-merge.
- **Verdict history, per work.** The scope's `subjectDigest` is the work judged, and it is part of MAS-RA-001's subject.
  The ledgers bound to one claim on the same work, in the order bound, must stay a valid MAS-RA-001 history
  (`check_history`: one subject, each superseding its predecessor, a better status only on new evidence); otherwise the
  VERIFY is VERDICT_HISTORY. A FAIL on a work is not turned into a PASS by an unrelated ledger or by re-judging the same
  evidence, and a superseding ledger may make the status better (on new evidence) or worse. Revised work (another
  `subjectDigest`) starts its own history on the same claim, so a worker can revise without releasing the item. A MERGE
  names the work it merges and reads that work's latest status.
- **Messages** are directed and typed (HERMES): `{to, messageType INTERFACE|DEPENDENCY|BEHAVIOR|TEST|CONFIGURATION,
  requiredAction NONE|ACKNOWLEDGE|CHANGE}`, one recipient, only along a declared MESSAGE edge. There is no broadcast.
- **Deterministic arbitration.** Operations apply in `(t, agent nodeId, opId)` order whatever their order in the
  transcript, so simultaneous acquires resolve the same way everywhere (vector B03 replays a reversed transcript).
- **Durable, idempotent transitions (Q-M4-8 (a)).** An operation with `retryOf` repeats an earlier, non-retry operation's
  exact body, gets that operation's answer again and changes nothing. The repeated answer is historical: a retried
  ACCEPTED claim may since have expired, and exclusivity holds because every later RENEW, MERGE and VERIFY re-checks the
  record. The central mode is executor-neutral: a durable state machine with idempotent transitions, recorded leases and
  resumption after a crash. PostgreSQL (H10's current orchestrator) and Temporal (the retained reference) are both
  admissible implementations; the contract selects neither.

Transcript refusal codes, in order: SHAPE; DUPLICATE_ID (operation ids, items); UNKNOWN_REFERENCE (the topology is
stored, hashes and passes the topology check; `kinds` is the pinned record; every agent, worker and message recipient is
a node; every item is listed; a retried operation exists; every verdict ledger is stored, hashes and is accepted by
MAS-RA-001's model); MODE (a SINGLE_AGENT topology has no board; a transcript id that is a node id); RETRY (a retry repeats
an earlier, non-retry operation's exact body); REPLAY.

## Mapping into run-events v1 (Q-M4-4 (a))

run-events v1 (MAS-RA-003) stays unchanged and remains the canonical internal record. For every transcript the model
derives its v1 root agent and the v1 points of its accepted operations, in application order:
- the **root run's agent**: the COORDINATOR in the central mode; in the decentralized mode the board itself, named by the
  transcript's id (not a node, so v1 then counts one more agent); every other agent with points is a depth-1 child run;
- ACQUIRE / ASSIGN → `CLAIM {claimId opId, taskDigest digest({"item": item}), conflictsWith}` on the holder's run;
  `conflictsWith` names the latest earlier claim on the item by another agent (v1's CLAIM_CONFLICT rule), so a reclaim
  after a release or an expiry is recorded as a conflicting claim, v1's documented limit;
- MERGE → `MERGE {mergeId opId, conflict false}`;
- MESSAGE → a `MESSAGE` SEND on the sender's run and a RECEIVE on the recipient's, `tokens` null: the board does not know
  them, and the runs supply them when the points are embedded (the RECEIVE after the SEND).

Two embeddings in the vectors (the central and the board transcript) are v1 logs built from those points with the
tokens supplied; MAS-RA-003's own `check_log` accepts both (CLAIM_CONFLICT, MESSAGE_PAIRING, one agent per run). The
steps v1 cannot represent are listed as **gaps**, every one carried to a run-events v2: VERIFY (a verification across runs,
its ledger reference and status, several ledgers per log), RENEW, RELEASE, expiries, retries, every refused operation,
message types and required actions other than INTERFACE/NONE. Depth stays ≤ 1.

## Vectors

`vectors.json`: `codes`, `selectionThreshold`, `kindsDigest`; `stores` (topologies, MAS-RA-002 evaluation records with
their manifests and every MAS-RA-002 split declaration, MAS-RA-001 ledgers); `cases` (51 topology, 30 transcript, 11
binding); `texts` (3 raw-text SHAPE cases); `selection` (18 rows of the rule, at and around the threshold); `kindsCases`
(the central transcript checked with two other kinds records, one of them not canonical JSON); `embeddings` (2 v1
logs). Each case is `{id, kind, intent, document, expect, facts?}`; refusals are minimal deviations from a valid
document. The records are MAS-RA-002's adopted vectors, some with edited scores or agent counts; the ledgers are
MAS-RA-001's adopted vectors and histories with their context ids renamed to node ids and their subject set to the
claim they judge; each is checked by its own contract's model when the vectors are built. Transcripts are hand-written
(Q-M4-11 (a)): every recorded answer is written by hand, and the model must reach it. An author-side mutation check (55 single-point
mutants, among them every survivor the round-2 review reported) is killed by the published runner except five
equivalent ones, each with its reason (three that mask each other, killed together; ASSIGN on the board, unreachable;
a narrower except that still catches MAS-RA-002's Refused, a ValueError). MAS-RA-010 keeps the fake-model, fake-clock simulation with faults.

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
- Kim et al. (arXiv 2512.08296, secondary as reported by RS-CLAUDE, not read): the selection rule and its threshold, as
  above.

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

## Review round 1 (CHANGES_REQUIRED: 3 MAJOR, 8 MINOR, 3 NOTE) and dispositions

| Finding | Disposition |
|---|---|
| M4R1-1 MAJOR the merge gate was not bound to the work | VERIFY carries the H16 scope; the ledger's subject must be that scope and the scope this claim; MERGE names `workDigest`, which must be the verified work (WORK_MISMATCH). Vectors: a ledger reused on another item, on another holder's claim, on a reclaim of the same item, with a false scope, with another GENERATOR, and the wrong work |
| M4R1-2 MAJOR held-out scores fed the selection | Eligible baselines only: DEVELOPMENT partition, no store-relative held-out task, clean tree. The board vectors rest on a DEVELOPMENT record (3/10); refusals for a HELD_OUT, a store-held-out and a dirty record |
| M4R1-3 MAJOR the VERIFY mapping is not v1 | VERIFY is a gap now; MESSAGE carries `tokens` null, supplied by the runs; the root run's agent is named; two v1 embeddings pass MAS-RA-003's `check_log` |
| M4R1-4 MINOR expiries stopped after the deadline | Leases expire at every operation's time, also after the deadline; B01's board and gaps record them |
| M4R1-5 MINOR latest verdict across unrelated ledgers | A claim's ledgers must stay a valid MAS-RA-001 history (VERDICT_HISTORY); vectors: FAIL then an unrelated PASS refused, UNRESOLVED then PASS on new evidence accepted, PASS then FAIL refusing the merge |
| M4R1-6 MINOR T38/T39 did not reach their rules | The incomplete and the two-agent records now score 3/10 (below the threshold) |
| M4R1-7 MINOR untested rules | Vectors for every listed edge (expiry at exactly the lease end, the deadline boundary, retry after the deadline and of a retry, renewal keeping and release/expiry/reclaim clearing verdicts, precedence pairs, ASSIGN on the board, conflictsWith's latest other agent, MODE_STRUCTURE parts, a renewal's lease from its own time, a requiredAction-only gap, the bindings); a mutation check kills every meaningful mutant |
| M4R1-8 MINOR the run binding identified nothing | A closed binding record checked by the model: agentCount must equal the vector's sum (BINDING); refused manifests are UNKNOWN_REFERENCE; the pairing is caller-asserted (Not claimed) |
| M4R1-9 MINOR iterations range | Capped at 100,000 as MAS-RA-008; wallClockSeconds' narrower cap stated |
| M4R1-10 MINOR threshold provenance | arXiv 2512.08296; v1 for "about 45%" (180 configurations), v3 for 260 and +80.8% / −70.0%; as reported by RS-CLAUDE, not read (README, model docstring, Grounding) |
| M4R1-11 MINOR Carried and Not claimed | Carried lists every gap the model emits plus the board root run; Not claimed adds the caller-asserted binding, the declared task shape and baseline relevance, and historical retry answers |
| M4R1-12 NOTE kinds not pinned | `KINDS_DIGEST`; another kinds record is UNKNOWN_REFERENCE |
| M4R1-13 NOTE retried answers; VERIFY not versioned | Both stated in A2 (verdicts sit beside the compare-and-swap state) |
| M4R1-14 NOTE wording, T27, header | AgentSpec order wording fixed (vector T07); the one-worker board no longer edits concurrency; the runner asserts the header against the model |

## Review round 2 (CHANGES_REQUIRED: 3 MINOR, 2 NOTE) and dispositions

| Finding | Disposition |
|---|---|
| M4R2-1 MINOR a claim's verdict only as unique as the transcript id | The transcript carries its `tenantId`; the scope must name that tenant and the transcript's topology digest as its `routeDigest`. Vectors: another tenant, another route; the remaining assumption (transcript ids unique per tenant and topology) is in Not claimed |
| M4R2-2 MINOR one work per claim | Histories are per (claim, work): revised work starts its own history (vectors on i4: FAIL on work A, then PASS on revised work B merges B; A stays VERDICT_NOT_PASS); MERGE precedence NO_VERDICT, WORK_MISMATCH, VERDICT_NOT_PASS stated and tested |
| M4R2-3 MINOR new rules untested; the mutation claim overstated | Vectors for every reported survivor: the held-out task-ID route (T51), stores under keys records do not hash to (B12k, R10, R11), a non-BOARD_CLAIM scope, another run's transcript id, a three-ledger history and a reused ledger ID, the merge precedence, a central transcript id that is a node id (B20c), expiry after the deadline (z2), the published kinds cases, the binding's schemaVersion (R09); the mutation claim now names its scope |
| M4R2-4 NOTE an uncanonical kinds record answered SHAPE | Any kinds record other than the pinned one, canonical or not, is UNKNOWN_REFERENCE (a kinds case with 1.5) |
| M4R2-5 NOTE B09 removed four scopes | Operations no longer share verdict objects; B09 changes one operation |

## Carried

- To a run-events v2: VERIFY (cross-run verification, ledger references and status, several ledgers per log), RENEW,
  RELEASE, lease expiry, retries, refused operations, message types and required actions, the decentralized board's root
  run as an agent of its own, broadcast, depth > 1 and external A2A peers; MAS-RA-003's carried R3-1 (the delegate span's
  status) is not taken up here.
- To a run-manifest revision: a per-role model list (the manifest keeps one model field; Q-M4-7 (a)) and a field naming
  the topology a run used.
- To MAS-RA-010: the threshold's measurement, the simulation with faults, and lifting the conflicting-objective denial.

## Not claimed

- Nothing runs: no coordinator, board, executor or agent; no board storage (MAS-RA-009) and no executor selection
  (EXEC-TEMPORAL-001).
- Objectives, roles, the task shape and verifier or generator contexts are declared, not authenticated: one agent could
  appear under two node ids (as MAS-RA-001's contexts).
- The baseline's relevance to the task (that its suite is the task's) is declared, not checked; the threshold is a
  secondary, declared default, not a measurement.
- A run binding is asserted by its writer; a retried answer is historical (see A2); transcript ids are assumed unique per
  tenant and topology, and the scope's profile, bundle and routeId are not checked by the board.
- No external A2A peer, no broadcast, no hierarchy deeper than one level, no run-events v2 or manifest revision.
- No harness document, repository schema or earlier contract changes.
