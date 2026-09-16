# Alpha 2 — bounded private document repair plan

Owner: MET-PERF-011. META_PLANNING_ONLY. This publication adds no product packet or execution allowance. Proposed product identifier CONF-PERF-006 is not dispatchable.

## Evidence and decision

Accepted META main is 5c5695e8bcd0ba95ff655b06ac397ef11f6cf0e0 (PR124). Its LOCAL, required localhost CI, merge and separate LOCAL exact-main evidence remain separate. Exact-main took 747.960 seconds against the 750-second META target; the small margin is a risk, not permission to expand limits.

CONF-DIAG-003 consumed its single attempt under signed activation307. The trusted900-second deadline ended it after902.035 operator seconds. It discovered all1397 expected backend identities, announced427 and completed426 (30.49%). The unfinished identity is test_proxy_server.BrokerCreatedTests.test_fsync_generation_loss_keeps_uid_held_without_ack; its cost is NOT_MEASURED.970 never started; all3 timing-only cases are unreached. No test FAIL/ERROR marker preceded timeout, but there is no completed suite, wrapper marker or acceptance certificate. Exact135-file/source/toolchain custody passed; no recorded sleep/thermal event or observed profiler interference. Temporary slot removed; no runner remains.

The426 completed cases contain895.804 wall /826.611 thread-CPU seconds, including observer overhead. Censored top20 self-elapsed records report canonical._validate_value218.532 seconds/65,378,542 calls, builtins.pow141.140 seconds/6,465,380 calls and isinstance96.165 seconds/322,381,015 calls. These are not full totals, cumulative times cannot be added, and unprofiled cost/speedup/full-timeout cause remain unproven. Fixture, mock and cryptographic costs also remain. Raw logs/signatures stay local; the machine record binds their digests without pretending to authenticate them.

This evidence supports investigating duplicate work inside live_mutation_admission.document, not eliminating guard calls or changing crypto. The older PLAN-CANON-001 NO_GO_AS_TIMEOUT_REPAIR decision and unauthorised CONF-PERF-005 remain unchanged.

## Proposed implementation boundary

Candidate: src/harness_conformance/live_mutation_admission.py, only function document. Eligible fast path: exact built-in bytes input with exact built-in int maximum. Every other value/maximum combination retains the original path, including bool/subclasses/effectful comparisons. No signature, parameter/default or public contract change.

Preserve the first byte-size check, require_canonical_document parsing, canonical compact-byte comparison, _bounded traversal, encoded-size check and original exception precedence. Investigate reusing fresh parsed/encoded locals and returning the detached parsed value instead of a second equivalent encode/parse round trip. Prove equivalence before selecting an exact delta. Return values must remain fresh across calls; caller mutation, later input changes, malformed data, revocation and post-I/O drift still get independently checked. No cache across calls or alias to caller objects.

Do not change canonical.py, crypto.py, schema.py, guard frequency, fixtures, authorization decisions, filesystem/network reads, journal transition rules, deadlines, C1-C7 requirements or result classification. No new dependency, OSS provider, source reuse, privileged installation or runtime download.

## Proposed repository and PR sequence

1. Publish and verify this META-only plan first, one branch/PR. This does not authorize product code or renew any allowance.
2. A later reviewed publication must supply an executable product packet, exact paths/regions/consumer migration and finite budgets. CONF-PERF-006 remains a proposal until then.
3. Preferred product starting point: fresh accepted main092fcf475c6f3ebd455e3c354cddb7664ea1f900. Start a new packet branch/PR; do not mutate, rebase, merge or close draft PR18 or drafts13/14/15 automatically.
4. First owner scope would be the private document helper, appended independent tests in tests/live_backend/test_mutation_admission.py and a new dedicated design/evidence section in docs/live-backend/proxy.md. All three are proposed paths, not allowedPaths today. Any source-history consumer edit must be explicitly enumerated before execution, never permitted as a directory wildcard.
5. The measured25fab12c168ff686e863291098fce0f3dba629bd PR18 candidate stays a135-file unaccepted source with1567 total identities/1397 backend identities. Accepted main has1277 total identities/1107 backend identities. The helper's source is compared at both revisions; its callers and source-history consumers are inventoried independently.
6. After a separate helper repair is accepted, a distinct completion-integration authority must specify how PR18's five-file delta is transferred/reconciled into a new exact candidate, preserving the original draft and all1277 predecessor plus290 appended identities/assertions. No automatic merge/cherry-pick, budget reset or alternative acceptance gate. If this separated route cannot provide representative timing, publish an explicit alternative before product work rather than silently stacking on PR18.

The source-history consumers include tests/platform/linux_baseline/_successor_inventory.py, tests/live_backend/_inventory.py and test_inventory.py, tests/live_backend/test_supervisor.py, and their proof documents/fixtures. Their exact current digests are retained in the plan. Read-only inspection is not migration closure: enumerate the concrete current-before-history bridge, mode/hash/size/blob checks, immutable original proofs and independently resealed negative vectors before granting edits. Unknown or linked files, stale current bytes, mutated old inputs and substituted proofs must still fail. Never execute stored historical source.

## Independent semantic matrix

The later product packet must freeze explicit expected results/errors, not compare only against the candidate or execute stored historical source. Add tests; preserve existing assertions and IDs.

| Group | Required cases and acceptance |
|---|---|
| Valid bytes | null, booleans, safe integers, Unicode NFC, strings, arrays, nested objects; equal values and fresh mutable return graphs |
| Canonical wire | compact bytes accepted; final LF, CRLF, whitespace, key order, escaped alternatives, duplicate keys and trailing content preserve exact rejection behavior |
| Parser errors | invalid UTF-8, malformed/truncated JSON, nonfinite/float numbers and lone surrogate cases preserve exception type/code/message/order |
| Bounds | byte length, maximum0/negative, integer bounds, depth16/17 and32/33,4096/4097 collection members, aggregate budget, per-string and encoded-size limits, including combined-fault precedence |
| Type boundary | bytes subclass, bytearray, memoryview, object/container subclasses, bool/float/custom maximum; preserve existing fallback behavior and effectful-comparison ordering |
| Detachment/freshness | mutate input object and returned value; repeated calls and changed bytes; no shared cache, poisoned result or skipped validation |
| Security consumers | malformed reservation/transcript/cleanup input, changed digest, replay, expiry/revocation, UID/label substitution, ambiguous write and resource-held failure remain fail-closed |
| Source proof | exact allowed delta; unchanged public signature, imports, shared validators/crypto and guard sites; every declared current-source/old-proof negative vector retained |

Sizes above are test boundaries, not grants to change existing limits. Review source-derived budget semantics and error precedence before freezing actual vectors. An incompatibility is a stop/no-go, not permission to narrow accepted types or weaken checks.

## Measurement and rollout gates

No benchmark or product run occurs in this META packet. Before executing the later repair, publish exact baseline/candidate commits, bytes, workload manifest and hashes, counts/order, independent vector outcomes, maximum attempts and total time. Use a separately authorized fixed unprofiled comparison on the pinned existing localhost toolchain, same immutable workload, alternating baseline/candidate order and retained per-sample wall/thread-CPU/load/awake observations. Predetermine the minimum practical gain and noise rule; if evidence is inconclusive or migration cost outweighs gain, retain NO_GO. No runtime import of stored historical source, synthetic success substitution, extra ad-hoc timing run, filtered acceptance, or claimed saving from profiled percentages.

Then require full eight-command product acceptance, every inherited identity/assertion with zero skips, exact-source required localhost CI, protected green merge and independent LOCAL exact-main. A microbenchmark does not substitute for full acceptance. Existing nested420/trusted900/workflow15-minute limits remain. The source repair alone neither closes C1-C7 nor unblocks CONF-LIVE-004; integrated completion must separately pass all those gates. Native Linux/AMD64/ARM64, artifact, deployment, runtime, assurance and tenant acceptance remain separate.

## This META publication

Preserve all169 old packet YAML, every accepted authority JSON, immutable observer, release/reuse/toolchain locks and tests. Add only MET-PERF-011, its plan/closed source-accounting validator/tests, and exact catalog/current-first navigation bridges.170 specifications. All38 predecessor commands remain; add this plan validator before full pytest for39 commands. Both full nested/outer selections, isolation skips and fresh-read/digest checks remain. No subsets, standalone repository test execution or timeout changes.

Finite META-only caps: LOCAL2, required localhost CI2, independent LOCAL exact-main1. Reserve each ordinal before signing/activation; every failure/timeout/interruption consumes it. Source fixes require remaining LOCAL and fresh exact-source full success before CI. Product runs0, diagnostics0; old budgets never reset or transfer. Use the existing signed localhost launcher/profile; no root/key/admin/power/provisioning changes. Stop on exhaustion or scope drift.

## Current roadmap

| Phase | ID | Status | Description |
|---|---|---|---|
| Phase0/Alpha1 | Foundations | DONE_RECORDED | Historical offline/source foundations only |
| Alpha2 | MET-ADOPT-002 | DONE_RECORDED | All16 harness/paper/OSS direction retained |
| Alpha2 | MET-PERF-009/PR124 | DONE_SOURCE_GATES_RECORDED | Accepted main5c5695e; no product qualification |
| Alpha2 | CONF-DIAG-003 | INCOMPLETE_DIAGNOSTIC_RETAINED |426/1397; one attempt consumed, no retry |
| Alpha2 | MET-PERF-011 | ONGOING_PUBLICATION | This bounded repair plan only |
| Alpha2 | Proposed CONF-PERF-006 | WAITING_EXACT_PACKET | No product YAML or execution grant |
| Alpha2 | CONF-FIX-007/PR18 | BLOCKED_LOCAL_BUDGET_EXHAUSTED | Preserve draft; C1-C7/full acceptance still required |
| Alpha2 | CONF-LIVE-004/005/006 | WAITING_PREDECESSOR_CORRECTION | Native probes, packaging, campaign integration |
| Alpha2 | CONF-A2-001 | WAITING | Qualified integrated read-only profile |
| Alpha3/4 | Later roadmap | WAITING | Governed actions and enterprise qualification |

The [all16 harness/paper/OSS map](HARNESS_PAPER_REPOSITORY_MAP.md), four planes and13 repository owners remain unchanged. Require **at least one qualified baseline for every released harness capability** at the first enterprise release. Linux Kubernetes/OpenShift is production; macOS is development. No proprietary dependency, paid API, hosted/cloud provisioning, online telemetry or license check. No phase-end model-effort transition is due: Alpha2 ONGOING; NOT_DUE.
