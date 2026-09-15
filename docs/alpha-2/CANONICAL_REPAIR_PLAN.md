# Alpha 2 — canonicalization repair decision and remaining readiness gate

## Current research-led implementation direction — MET-ADOPT-002

[Harness / paper / upstream repository map](HARNESS_PAPER_REPOSITORY_MAP.md)
is the current reuse-first planning amendment. It covers all16 canonical harnesses
and preserves the four planes and13 repository owners. Catalog:166 packet specifications;
all165 predecessor YAML remain byte-immutable. Proposed provider-adoption work is
non-dispatchable until exact successor packets, contracts and offline locks are published.
Require **at least one qualified baseline for every released harness capability** at the first enterprise release.
META source publication is not OSS provider implementation or qualification.
Alpha2 ONGOING: MET-ADOPT-002 ONGOING; CONF-FIX-007 PAUSED_RESEARCH_AMENDMENT.
CONF-LIVE-004 WAITING_PREDECESSOR_CORRECTION; completion C1-C7 and all independent
source gates remain mandatory. No native/tenant promotion or budget reset; effort NOT_DUE.

## Retained implementation specifications and historical checkpoints

`MET-PERF-007` publishes diagnostic findings and a bounded repair proposal. It
does not grant product edits, execute product code or declare the repair ready
to code. `CONF-PERF-005` is a proposed identifier only: there is deliberately no
executable YAML or source ownership grant until the consumer migration is exact.

## What is established

Accepted meta main `f973598a66946d5f1d06c8db71291d144c83d363` closed
`MET-PERF-006` separately through local acceptance, required localhost CI,
PR #117 merge and independent LOCAL exact-main. `CONF-DIAG-001` then completed
three signed normal/cProfile pairs on unchanged local product commit
`7939626dc6aec99b58816e3a709fd0babf3a985f`. The subject remains unaccepted and
unpushed. Accepted product main is `f988c78e93b28257810ed99e7f0c072e9b76bae5`;
draft PR #12 remains separate, with remote head `699a00c2d26e36c9c710aa85d0338f0d926073f2`.

There were 240 successful executions of 40 unique selected test IDs, not 240
different tests. All three pairs had zero skips, failures and errors. The
normal unittest durations were 12.360, 12.781 and 12.558 seconds; profiled
durations were 29.368, 32.564 and 30.059 seconds. Whole-pair wall times and full
profiles are retained. Individual full-command wall times are NOT_MEASURED:
the unchanged runner emitted no command boundary timestamps. Operator stdout
receipt times must not be substituted for execution boundaries.

Canonical validation/serialization consumed roughly 39–40% of profiled time;
scalar multiplication roughly 20%. Cumulative rows overlap and cannot be
summed. The profiler slowed the tests by 2.38–2.55 times, so this is not an
unprofiled production ranking or a speedup prediction. Setup and mocks also
contribute materially. No sleep/wake event was recorded within these three
intervals; this does not prove absence of throttling or controlled host load.

The companion `architecture/canonical-repair-plan.json` records the exact
subject, packet, source-inventory, signed-request and complete-log digests.
Repository validation checks this retained data and its consistency only; it
does not authenticate an operator run or replace independent signature/custody
verification. Raw logs and signed records remain in operator custody, not
uploaded as CI artifacts. All earlier assertion failures and broad timeout
records remain unchanged.

## Proposed smallest runtime change

Investigate only `src/harness_conformance/canonical.py` function
`require_canonical_document`. For compact JSON without a final newline, the
current condition may call `canonical_bytes` twice on the freshly parsed value.
Per-invocation reuse of encoded bytes is the candidate. It has not been
benchmarked and cannot account for every call to `canonical_bytes`; the
39–40% figure is emphatically not the potential saving of this small change.

Do not change `_validate_value`, `canonical_bytes`, secure filesystem reads,
signature arithmetic, guard frequency or pre/post-I/O observations. Do not
cache documents, authority, identities, signatures, deadlines or state across
calls. No fixture caching, global observer or dependency is proposed.

Compatibility must cover return values and exception type/code/message/order,
including valid compact and one-final-newline forms; whitespace, CRLF, extra
newline and trailing content; duplicate keys, invalid UTF-8 and malformed JSON;
NFC, Unicode escapes and surrogate errors; integer bounds, floats and constants;
depth, collection and byte bounds; and error precedence when several faults
coexist. Python input subclasses/bytearray and effectful comparisons must be
examined explicitly. Preserve their existing behavior or leave them on the
unchanged path; do not silently narrow the public input contract. Any actual
public/security semantic change requires a separate owner decision.

## Why product edit authority is still withheld

The five implementation concerns below are a design inventory, not allowedPaths:

| Concern | Existing owner path | Closure needed before an executable packet |
|---|---|---|
| Runtime candidate | `src/harness_conformance/canonical.py` | Exact function delta, immutable before bytes and independent semantic vectors |
| Historical proof interpreter | `tests/platform/linux_baseline/_successor_inventory.py` | Exact current-custody-before-history transformation, bounded regions and no generic bypass |
| Helper importer | `tests/live_backend/_inventory.py` | Exact helper digest update and unchanged read/custody checks |
| Source-proof tests | `tests/live_backend/test_supervisor.py` | Preserve every old assertion/ID and CONF-FIX-006 correction; enumerate exact necessary compatibility bridges |
| Proof document | `docs/live-backend/linux-boundary.md` | Acyclic bounded current binding and separately retained immutable old proof |

Read and cross-check all inherited consumers, including
`tests/platform/linux_baseline/test_linux_inventory.py`,
`tests/platform/linux_baseline/test_packet_scalars.py` and
`tests/platform/linux_baseline/test_successor_inventory.py`. Their inspection
does not grant edits. The existing v4 proof and CONF-FIX-006 corrective binding
pin runtime and test bytes; merely updating a top-level hash will fail these
consumers. Their old positive and independently resealed negative vectors must
remain effective. Fake historical source may never replace freshly collected
current source or be imported/executed.

Before the next source-owner publication, close `PLAN-CANON-001`: inventory the
exact accepted 127-file/362-method baseline; name each affected region and
caller; specify executable-byte versus inert-history checks and all required
fixed bridge bytes; prove a one-way, non-circular binding; enumerate new tests
without replacing old identities; and demonstrate that undeclared edits,
missing/extra files, stale current bytes, links, forged before sources and
resealed proofs still fail. This design may establish that the migration cost
outweighs the candidate benefit. In that case retain a documented no-go instead
of broadening the fix or bypassing tests.

`PLAN-CANON-001` is an internal readiness checklist item, not another execution
packet. This publication adds only `MET-PERF-007` to the existing catalog. No
consumer-migration helper, product acceptance run or new performance replay is
authorized here. A future packet must grant its exact paths before coding.

## Measurement and delivery contract for the future proposal

1. Start shared-source work from freshly verified accepted product main, never
   the unaccepted proxy subject. Bind versions, modes, sizes, digests, toolchain,
   all inherited test identities and downstream pending-branch integration.
2. Publish fixed independent valid/invalid expected outputs and exceptions,
   baseline/candidate workload, method bytes, sample/order plan and decision
   threshold before execution. Do not execute stored historical source or use
   the candidate itself as its correctness oracle. No opportunistic test subsets
   may replace acceptance, and no existing diagnostic budget is reusable.
3. Measure the same declared workload unprofiled on both versions, including
   compact, newline, rejection and representative nested documents. Bound input
   sizes, iterations, attempts and total wall time in the future packet. Record
   all samples, load, wall/monotonic time and awake intervals. Do not claim gain
   from within noise, skip regressions or weaken semantics for a threshold.
4. Run all eight existing product acceptance commands, all discovered inherited
   and new IDs, zero product skips. Preserve nested 420 seconds, trusted 900
   seconds and workflow 15 minutes. Retain full failure logs. Source/local,
   required self-hosted CI, green-only merge and independent LOCAL exact-main
   remain separate mandatory gates. Benchmark success alone is not acceptance.
5. Only after accepted repair and exact consumer closure may a separately
   authorized packet reconcile the pending proxy branch. This is not permission
   to reset the exhausted CONF-LIVE-003 retry loop, push its current subject or
   merge draft PR #12. Its broad timeout cause remains unresolved.

No built-in/provider coverage, contracts, repository graph, license, source
reuse lock, production target or billing boundary changes. Keep 16 harnesses,
four planes and 13 repositories; at least one qualified baseline per released
capability remains the release minimum. Linux Kubernetes/OpenShift is the
production target. macOS evidence is not native Linux qualification. No warm
sources, root policy, keys, OS overrides, dependencies, downloads, hosted/cloud
resources, telemetry or paid APIs are introduced.

## Status and next steps

| Phase | ID | Status at publication | Description |
|---|---|---|---|
| Phase 0 / Alpha 1 | Existing foundations | DONE_RECORDED | Historical source gates only |
| Alpha 2 | MET-PERF-006 | DONE_SOURCE_GATES_RECORDED | Accepted read-only diagnostic authority |
| Alpha 2 | CONF-DIAG-001 | DONE_MEASURED_SCOPE | Three pairs; full-command wall times unmeasured; campaign exhausted |
| Alpha 2 | MET-PERF-007 | ONGOING_PUBLICATION | This evidence-backed repair proposal and negative validation |
| Alpha 2 | PLAN-CANON-001 | WAITING_EXACT_DESIGN | Close source-history consumer migration before an executable grant |
| Alpha 2 | Proposed CONF-PERF-005 | NOT_AUTHORIZED | No YAML, branch, product edit or execution permission yet |
| Alpha 2 | CONF-LIVE-003 | BLOCKED_FULL_ACCEPTANCE | Whole-suite timeout unresolved; draft remains unmerged |
| Alpha 2 | CONF-LIVE-004/005/006 | WAITING | Probes, packaging and campaign integration |
| Alpha 2 | Native AMD64/ARM64 | NOT_RUN_ENV_UNAVAILABLE | Independent installed Linux qualification |
| Alpha 3 / Alpha 4 | Existing roadmap | WAITING | Governed actions and enterprise qualification |

Alpha 2 remains ONGOING. Model-effort transition NOT_DUE. Historical publication
tables below newer navigation remain dated evidence, not current dispatch.
