# Alpha 2 — guarded-construction cost repair

## Current repair gate - MET-PERF-017

[Guard-traversal successor](GUARD_TRAVERSAL_REPAIR.md): Alpha2 ONGOING.
MET-PERF-016 DONE_SOURCE_GATES at4f7cd029 / PR132.
OPERATOR-INVENTORY-001 DONE_INSTALLED_VERIFIED; host repair is not product acceptance.
CONF-FIX-009 BLOCKED_LOCAL_ALLOWANCE_EXHAUSTED: two LOCAL slots consumed; LOCAL2 stopped at748.0667s, exit247.
MET-PERF-017 ONGOING_META_PUBLICATION:184 specifications; all182 earlier packets immutable; no product execution.
CONF-FIX-010 WAITING_PUBLICATION_AND_SAFE_DESIGN: independent design/candidate review and separate product-stage approval required.
CONF-LIVE-004/005/006 WAITING_PREDECESSOR_CORRECTION; CONF-A2-001 and Alpha3/4 WAITING.
No native/runtime/tenant acceptance; Alpha2 open; model-effort transition NOT_DUE.
Preserve the [all16 harness/paper/OSS map](HARNESS_PAPER_REPOSITORY_MAP.md).
Prior headings below are retained historical checkpoints, not current execution authority. A new allowance does not reset failed history or establish a safe repair.

## Retained planning and historical checkpoints

## Current repair gate - MET-PERF-016

[Accounting-scope amendment](ACCOUNTING_SCOPE_AMENDMENT.md): Alpha2 ONGOING.
MET-PERF-015 DONE_SOURCE_GATES at ee7a8eb / PR131.
MET-PERF-016 ONGOING_META_PUBLICATION: one accounting-only fixture exception;182 specifications,180 immutable prior packets.
CONF-FIX-009 WAITING_AMENDMENT_GATES_AND_REVIEW: prepared inherited source only; no repair or product execution in this META run.
CONF-FIX-008 BLOCKED_LOCAL_FAILURE and CONF-DIAG-004 CLOSED_PARTIAL_DIAGNOSTIC; old drafts/evidence/allowances preserved.
CONF-LIVE-004/005/006 WAITING_PREDECESSOR_CORRECTION; CONF-A2-001 and Alpha3/4 WAITING.
No native/runtime/tenant acceptance; Alpha2 open; model-effort transition NOT_DUE.
Preserve the [all16 harness/paper/OSS map](HARNESS_PAPER_REPOSITORY_MAP.md).
Only the explicit accounting exception supersedes earlier fixture restrictions. Other older headings below are retained publication checkpoints, not current execution authority.

## Retained planning and historical checkpoints

2026-09-17. MET-PERF-015 is a META-only publication. It does not execute or
modify the product. CONF-FIX-009 is the separate conditional product packet.

## Evidence and current position

MET-PERF-014 passed LOCAL, required self-hosted CI, protected merge and exact-main
at ae33beb14584c25e4eeca3bfdcf7c85d3e722fc5 / PR130. CONF-DIAG-004 consumed its
single attempt, stopped at748.029s, completed at748.111s with exit247. It
discovered1447 backend cases:1062 completed,1 unfinished,384 unreached. Only
1 of41 factory cases was reached and none finished. This is PARTIAL_DIAGNOSTIC_ONLY,
not accepted product work. At448.027s of that case (447.463s thread CPU), one
unfinished constructor had made2,362,068 file checks and2,045,346 native ticks;
check_self had not been reached. Count growth supports CPU-active guard
amplification, not an idle deadlock in the sampled interval. It does not measure
exclusive cost, an unprofiled speedup, unbounded recursion or Linux performance.

The exact source remains135 files at6785db60c96d2ec45b9188e59269b1d199769a64,
tree d24fca29ca493897021f6c5c18d7af4f81a65cf7, draft PR20. Product accepted main
remains3a81c8ffb17be9e288c4368d443c57361d5a4fc8. All original drafts, signed
custody and failed evidence stay intact. The 1617 total/1447 backend identities
in the frozen source are inherited requirements, not passes. Full retained
output is digest-bound external operator evidence; copied records are data and
must be authenticated against that custody before product work.

## Separate budgets and gates

META: LOCAL2, CI2, LOCAL_EXACT_MAIN1. Product CONF-FIX-009: LOCAL2, CI2,
LOCAL_EXACT_MAIN1. These are new finite allowances, not transfers or resets.
CONF-DIAG-004 has zero retries; CONF-FIX-008 LOCAL1 remains consumed and LOCAL2
held. No extra diagnostic/benchmark/import/collection workload is authorized.
Reserve before signing/activation; each failure, timeout or interruption counts.
Never pool partial results. LOCAL and exact-main remain750s, nested420s,
trusted900s and workflow15min. A source change needs a fresh full LOCAL within
the remaining allowance. Exhaustion requires new reviewed authority.

All43 predecessor META commands remain, with one new guard-cost validator for44.
Both complete META test replays and10 established isolation skips remain. The
exact added/expanded case inventory is frozen before activation. Preserve179
old packet YAML and all historical architecture JSON; add only MET-PERF-015 and
CONF-FIX-009 for181 specifications. Current source is checked before historical
projections; stored predecessor source is never executed.

Product implementation is blocked until all four META source gates pass and
the signed diagnostic custody is independently verified. Create one new product
branch/PR from accepted3a81c8f, compose the exact five-file6785db6 source delta as
an unaccepted input, then perform only the packet's bounded repair. Never resume,
merge, close or rewrite old drafts under this packet.

## Product scope and safety decision

The only behavioral target is retained-check cost in live_proxy_server.py:
_Files.check, _KernelNativeReads._tick, _kernel_inspection_tick,
_KernelSelfInspection._tick/_reader_tick and the root/epoch sampling they call.
Cheaper per-check computation with unchanged observations, order and refusal
semantics is preferred. No particular caching or sampling reduction is approved
in advance. First write the exact call-path/invariant design in the owned proxy
guide and get independent C1-C7 source/design review. Review the final exact
candidate again before activation/merge; evidence must identify reviewer,
candidate, changed symbols and regression IDs, not a self-certified PASS.

Any removed/relocated whole-file scan or changed sampling/call-site requires an
explicit safety argument mapping old and new pre/post-I/O freshness boundaries,
failure interleavings and ownership/cleanup. A prior successful observation is
not current evidence. Unproven equivalence blocks implementation/promotion; it
does not authorize a timeout increase or dropped assertion. A design requiring
new public authority, external enforcement, privilege, contract, path or test
migration stops for a separately reviewed amendment.

Review must distinguish immutable authenticated inputs, mutable filesystem/
mount/namespace/policy/FD observations, cheap lifetime/owner invariants and
required fresh checks around consequential I/O. Retain fail-closed behavior for
authority/expiry drift, policy changes during reads, mount/namespace replacement,
descriptor reuse, owner substitution, wrong peer roles, reentrancy, partial
acquisition and original-resource cleanup. No worker grant or early credential
access may arise from qualification. Do not weaken broker admission or mutation
ordering, and do not alter clock/watchdog behavior to obtain a pass.

## Exact five-path ownership and history

- live_proxy_server.py: narrowly reviewed guard-cost repair only; unrelated
  protocol, admission, provider and lifecycle behavior is unchanged.
- test_proxy_server.py: append independent guard-cost/failure-interleaving
  regressions; retain all old test bodies/assertions, discovery and the real
  factory composition. Only leaf OS/time/storage/transport doubles; no successful
  qualifier replacement. No fixture clock, profiler or watchdog migration.
- live_mutation_admission.py: inherited source only; byte-identical to6785db6,
  including accepted document() helper. No new implementation edit.
- test_mutation_admission.py: only extend the named _doc_current_sources and
  DocumentRepairTests.test_consumer_history_preserved current-first history bridge,
  its embedded proof digest, and append tamper regressions. Preserve every other
  inherited test/helper and all previous proof layers. Validate current exact
  sources before reversible projection6785db6 -> accepted3a81c8f. Do not fake
  current discovery, execute stored source or update an old proof in place.
- docs/live-backend/proxy.md: append the new proof layer and reviewed cost/safety
  design. Existing proof/history remains intact.

The other130 tracked files are byte/mode/size immutable; exactly135 files remain.
New tests are appended in the two owned test files, not a new sixth path.
Preserve1617 inherited IDs/1447 backend cases and their meaning, with new cases
strictly additional. Freeze final source inventory and exact ID counts before
execution. No crypto/canonical/document helper, dependency, Makefile/dispatcher,
toolchain/workflow, schema or PORTING change.

## Acceptance, not promises

Independent C1-C7 review, the full eight product commands with zero skips,
required isolated localhost CI, protected green merge and a separate exact-main
replay are all mandatory. Product passing case counts must match the frozen
inventory. A lower diagnostic counter, META green check or source review cannot
stand in for those gates. No speedup or successful repair is promised by this
publication; a candidate outside the unchanged bound remains failed.

Artifact/release locks, deployment, live Linux/OpenShift qualification, runtime,
assurance and tenant acceptance remain separate. All20 native controls remain
NOT_RUN_ENV_UNAVAILABLE. The synthetic fixture uses fixed clocks; no Mac unit
result substitutes for a real production deadline or containment test.

## Roadmap

| Phase | ID | Status | Description |
|---|---|---|---|
| Phase0 / Alpha1 | Foundation packets | DONE_RECORDED | Historical source/offline foundations |
| Alpha2 | MET-PERF-014 | DONE_SOURCE_GATES | Accepted diagnostic authority at ae33beb / PR130 |
| Alpha2 | CONF-DIAG-004 | CLOSED_PARTIAL_DIAGNOSTIC | Single attempt consumed; zero retries; guard-cost evidence only |
| Alpha2 | CONF-FIX-008 | BLOCKED_LOCAL_FAILURE | Draft PR20 unchanged; LOCAL2 held |
| Alpha2 | MET-PERF-015 | ONGOING_META_PUBLICATION | This repair authority and preserved evidence |
| Alpha2 | CONF-FIX-009 | WAITING_META_GATES_AND_INDEPENDENT_REVIEW | Separate bounded guard-cost repair, not implemented |
| Alpha2 | CONF-LIVE-004/005/006 | WAITING_PREDECESSOR_CORRECTION | Native probes, packaging and trusted campaigns |
| Alpha2 | CONF-A2-001 | WAITING | Qualified integrated read-only profile |
| Alpha3 / Alpha4 | Governed action / enterprise release | WAITING | Later disconnected qualification |

Preserve the [all16 harness/paper/OSS map](HARNESS_PAPER_REPOSITORY_MAP.md),
four planes and13 repositories, phased popular OSS integrations and production
Linux Kubernetes/OpenShift. Require **at least one qualified baseline for every
released harness capability** at the first enterprise release. No warm-source
access, downloads, paid API/key, cloud provisioning, hosted runner, external
telemetry default, root/key/admin/power change or product execution in this META
run. Alpha2 remains open; model-effort transition NOT_DUE.
