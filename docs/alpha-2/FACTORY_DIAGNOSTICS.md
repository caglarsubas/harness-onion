# Alpha 2 — bounded factory-call diagnostics

## Current repair gate - MET-PERF-015

[Guard-cost repair](GUARD_COST_REPAIR.md): Alpha2 ONGOING.
MET-PERF-014 DONE_SOURCE_GATES at ae33beb / PR130.
CONF-DIAG-004 CLOSED_PARTIAL_DIAGNOSTIC: one attempt consumed,zero retries;1062 completed/1 unfinished/384 unreached; not acceptance.
CONF-FIX-008 BLOCKED_LOCAL_FAILURE: draft PR20 at6785db6 unchanged; LOCAL1 consumed,LOCAL2 held; CI/main not run.
MET-PERF-015 ONGOING_META_PUBLICATION;181 specifications,179 immutable prior packets.
CONF-FIX-009 WAITING_META_GATES_AND_INDEPENDENT_REVIEW: separate guarded-cost design and repair; no implementation in this META run.
CONF-LIVE-004/005/006 WAITING_PREDECESSOR_CORRECTION; CONF-A2-001 and Alpha3/4 WAITING.
No native/runtime/tenant acceptance; Alpha2 open; model-effort transition NOT_DUE.
Preserve the [all16 harness/paper/OSS map](HARNESS_PAPER_REPOSITORY_MAP.md).
Older headings below are retained publication checkpoints, not current execution authority.

## Retained planning and historical checkpoints

2026-09-16. User-approved META-only publication, MET-PERF-014. The separate
CONF-DIAG-004 observation cannot run before LOCAL, required localhost CI,
protected META merge and independent exact-main source gates all pass.

## Why this packet exists

CONF-FIX-008 candidate `6785db60c96d2ec45b9188e59269b1d199769a64`, tree
`d24fca29ca493897021f6c5c18d7af4f81a65cf7`, remains draft PR20. C7 independent
source review passed, but LOCAL1 did not complete. The first five suites passed
170 tests; the backend inventory contained 1,447 cases, but no backend summary
was emitted. The last case marker was
`KernelQualificationFactoryTests.test_policy_epoch_loss_inside_real_read_is_sticky_and_closes_originals`.
The exact owned process group was stopped at 748 seconds before the 750-second
LOCAL bound. The recorded exit is 247; source stayed unchanged; the temporary
checkout and processes were removed. No observed host interruption occurred.

The source review suggests nested custody checks multiply work inside qualifier
construction. This is a hypothesis, not a proven deadlock, runtime defect or
optimization decision. The incomplete watchdog trace has inconsistent line
information and cannot settle the cause. Static review does not prove acceptable
execution cost. The new observation must separate these claims.

## Fixed subject, whole suite, no product change

The subject has exactly 135 tracked files and 1,617 static identities, including
the 1,447 backend identities. The complete inventory, exact identity list, C7
record, failed result, retained log, stop record and read-only diagnosis are
pinned as data inputs. Independently verify their original signed custody before
execution; a hash or this planning validator alone grants no authority.

The immutable diagnostic program is published in META as
`diagnostics/conf_diag_004.py`. Its equivalent literal ASCII program is embedded
in one direct `python3 -c` argv through the existing authorized transport, at most
4,096 bytes. No runtime script loader, external program path, new dependency,
source overlay, arbitrary input or root-policy change is introduced. The product
checkout is never edited; `allowedPaths` is only its read-only discovery anchor.

Normal unittest discovery and order remain unchanged for all 1,447 backend
cases. Forty-one existing factory cases (10 qualifier, 8 server and 23 HTTP)
receive call-event observation. The other 1,406 run with per-case timing only;
their inherited profiling behavior is untouched. Nothing is skipped, reordered,
substituted or classified differently. No TestCase.run, product guard, fixture,
clock, admission, cleanup, result, watchdog or sampling frequency is replaced.

## Observer boundary and interpretation

- Use standard current-thread `sys.setprofile`, not private cProfile callbacks
  or global sys.monitoring registration. Refuse ambient tracing/profiling or
  monitoring tools before installing a hook.
- Count call and return events only for ten exact filename/qualified-name/line
  identities from the failed source. Counters have fixed-size storage; do not
  retain frames, locals, arguments, return values, credentials or payloads.
- Emit cumulative progress at a two-second minimum interval, checked every 1,024
  Python call/return events. No worker, background sampler, signal handler or
  additional watchdog is introduced. The inherited stack watchdog is unchanged.
- Preserve original wall/thread-CPU observation functions; never replace the
  product's simulated clocks. Progress timestamps include observer overhead.
- Clear only the identical owned hook. Foreign hooks remain untouched; detected
  interference invalidates the observation and aborts it. Ownership snapshots do
  not prove continuous ownership or exclude transient interference.
- Timing-only cases emit null counters, not zero measured work. Return events do
  not mean a guard succeeded; exceptional returns are still events. Counts do
  not prove data freshness, safety, causation or an optimization's correctness.
- A C-level/native stall may emit no further profile events. Missing snapshots
  are NOT_MEASURED, not zero calls or a proved deadlock. If the budget prevents
  reaching a case, record that limitation; never select a subset to compensate.

The program and transport receive META-only synthetic tests for counting,
wrong identities, progress bounds, no argument/frame retention, outcome parity,
ambient/foreign hook handling, timing-only nulls and cleanup. These tests import
only the diagnostic asset and synthetic cases, never product code or fixtures.

## Execution and finite allowance

MET-PERF-014 publishes two new specifications: 179 current packets and 177
byte-immutable prior YAML files. It preserves all 42 predecessor commands and
adds one validator for 43, both full META test replays and their 10 inherited
isolation skips. Freeze exact case expansion before reservation. META allowances:
LOCAL2, CI2, LOCAL_EXACT_MAIN1; no extra META diagnostics or benchmarks.

CONF-DIAG-004 has exactly one diagnostic attempt and zero retries, reserved
durably before signing/activation. Every failure, interruption or timeout consumes
it. Use only the existing root-owned signed offline launcher and one deny-all
process tree. Pin the accepted META revision, exact subject tree and 135-file
inventory, program/argv, expected identities, interpreter/toolchain, policy,
request, stage/ordinal and output. Verify source before and after. Stop only the
owned diagnostic process group before the existing 750-second observation bound;
the trusted 900-second ceiling and inherited nested420/workflow15min boundaries
remain unchanged. One active execution; cleanup always retains evidence.

The diagnostic may produce partial counts before timing out. Even a complete
1,447-case pass is WORKLOAD_DIAGNOSTIC_ONLY, never product acceptance. No separate
probe, benchmark, ad hoc import, collection, second workload or unchanged retry.
No old budget transfers or resets: CONF-FIX-008 LOCAL1/2 remains consumed and
LOCAL2 remains held pending reviewed repair scope. Earlier exhausted drafts and
all diagnostic/benchmark history remain untouched. Publishing this packet does
not assert that CONF-DIAG-003 ran or renew its allowance.

## After observation

Retain exact counters and their limitations; determine whether guard expansion,
fixture behavior, profiler/watchdog interference or another cause is supported.
Any guard-call-site optimization, caching, changed check frequency, inherited
fixture migration or watchdog change needs a separate reviewed repair packet.
Do not weaken safety assertions or substitute a successful qualifier. Subsequent
repair still needs independent C1–C7 review, the complete eight-command source
acceptance, required localhost CI, protected merge and separate exact-main.

## Roadmap and product boundaries

| Phase | ID | Status | Description |
|---|---|---|---|
| Phase 0 / Alpha 1 | Foundation packets | DONE_RECORDED | Historical source/offline foundations |
| Alpha 2 | MET-REPAIR-018 | DONE_SOURCE_GATES | Accepted authority at 5b082fb, PR129 |
| Alpha 2 | CONF-FIX-008 | BLOCKED_LOCAL_FAILURE | Source/C7 reviewed; LOCAL1 stalled; draft PR20 |
| Alpha 2 | MET-PERF-014 | ONGOING_META_PUBLICATION | Publish this bounded read-only diagnostic authority |
| Alpha 2 | CONF-DIAG-004 | WAITING_META_SOURCE_GATES | One immutable whole-backend observation; not acceptance |
| Alpha 2 | Subsequent repair | WAITING_DIAGNOSIS_AND_REVIEW | No optimization or additional fixture migration authorized |
| Alpha 2 | CONF-LIVE-004/005/006 | WAITING_PREDECESSOR_CORRECTION | Native probes, packaging and trusted campaign integration |
| Alpha 2 | CONF-A2-001 | WAITING | Qualified integrated read-only profile |
| Alpha 3 / Alpha 4 | Governed actions / enterprise release | WAITING | Later disconnected qualification |

Preserve the [all-16 harness/paper/OSS map](HARNESS_PAPER_REPOSITORY_MAP.md),
four planes and thirteen repositories. No warm-source access, cloud provisioning,
hosted runner, paid API/key, download, telemetry default, root/key/admin/power
change, artifact release, deployment, native/runtime/assurance/tenant acceptance
or phase completion is authorized. Linux Kubernetes/OpenShift remains production;
macOS is development only. All 20 native controls remain NOT_RUN_ENV_UNAVAILABLE.
Require **at least one qualified baseline for every released harness capability**
at the first enterprise release. Alpha 2 remains open; model-effort transition NOT_DUE.
