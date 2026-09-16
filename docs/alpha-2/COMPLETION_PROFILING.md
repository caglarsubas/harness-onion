# Alpha 2 — existing PR124 reconciliation after accepted validation repair

Owner: MET-PERF-009. Status: ONGOING_PUBLICATION, not accepted. The original draft
specification below is retained history; this section is the current scope.

Accepted predecessor MET-PERF-010 is main91b320b9f8525e986260fc4792b01f125b5feae9,
with complete LOCAL, required localhost CI, protected merge and independent LOCAL
exact-main acceptance. Its source gates do not qualify any provider or product.
The original PR124 draft1886aa2272f8d8bc73da60ebd7a6738f288de5fb remains in branch
history; its five failed LOCAL attempts and two old META diagnostics are retained.

The separately approved reconciliation preserves all167 accepted packet YAML,
all accepted authority JSON, the safe fixture helper and all17 local digest
optimizations. Only84 named paths are owned; the two additional validation-owner
paths permit closed successor accounting and regressions. The diagnostic observer
stays byte-identical. No product, warm source or runtime behavior is changed.
The combined catalog contains169 specifications:167 accepted plus009/CONF-DIAG-003.

Current-first source checks normalize only through reconciled009 -> accepted010
-> older authorities, validating exact live bytes before each historical step.
All existing fresh-read, digest, duplicate-match and mutation checks remain.
Historical source is data, never imported/executed. Reject unknown/stale source,
skipped010 normalization, substituted records and added permissions.

## Execution budget and complete verification

META LOCAL maximum7 total:1–5 remain consumed; only6/7 are newly authorized.
Existing CI maximum2 and independent LOCAL exact-main maximum1 remain unchanged.
No extra META diagnostics, subsets, collection-only, benchmark or product run.
Each ordinal must be durably reserved before signing/activation; no reset or
transfer. Exactly one active verification. A bounded source correction may use
the remaining LOCAL ordinal, and CI requires fresh full exact-source LOCAL pass.

All37 accepted predecessor direct argv remain; the profiling validator is inserted
before full pytest, giving38 commands. Both complete nested and outer suites,
original tests/assertions and inherited isolation skips remain. Exact expected
case counts, including new packet-driven parameter expansions, are source/data
accounted and pinned in architecture/completion-profiling.json before execution.
Counts are expectations, not retrospective acceptance or a unique-test sum.

Use only the existing signed deny-all-outbound localhost launcher/toolchain.
Full LOCAL/exact-main <=750 seconds; nested420/trusted900/workflow15min unchanged.
No root/key/admin/power/isolation/timeout changes, new dependencies, downloads,
hosted runner, cloud provisioning, paid APIs, telemetry or artifact uploads.

Keep the existing branch and PR124; no rebase or force-push. After full LOCAL,
publish the reconciled head, verify required localhost CI and runner cleanup,
then protected squash merge the exact green head. Independently verify the
actual main commit and exact tested tree. Retain every source/signature/command/
timing/reservation/failure/cleanup record. Failure or exhaustion leaves the draft
unaccepted; any broader repair needs a separate decision.

## Product and roadmap boundaries

CONF-DIAG-003 remains WAITING_META_SOURCE_GATES: its one read-only diagnostic is
a separate subsequent turn, not execution here. Its exact25fab12/135-file subject,
1397 backend cases,1394 function profiles and3 timing-only cases are unchanged.
The previous CONF-FIX-007 LOCAL3/3 remains exhausted. Observation cannot complete
that packet. Any measured correction needs a new bounded owner decision, C1–C7,
all1277 predecessor test identities, full8-command acceptance, CI/merge/exact-main.
CONF-LIVE-004 remains WAITING_PREDECESSOR_CORRECTION;005/006 andCONF-A2-001 wait.

The adopted16-harness/four-plane/13-repository research-led OSS map is retained.
At least one qualified baseline per released capability remains the enterprise
minimum. No provider/runtime, native Linux, artifact release or tenant acceptance
is claimed. Alpha2 ONGOING; model-effort transition NOT_DUE.

| Phase | ID | Status | Description |
|---|---|---|---|
| Phase0 / Alpha1 | Foundations | DONE_RECORDED | Historical source/offline evidence |
| Alpha2 | MET-ADOPT-002 | DONE_RECORDED | Research/OSS direction retained |
| Alpha2 | MET-PERF-010 | DONE_SOURCE_GATES | Accepted validation repair |
| Alpha2 | MET-PERF-009 / PR124 | ONGOING_PUBLICATION | This reconciliation; full gates required |
| Alpha2 | CONF-DIAG-003 | WAITING_META_SOURCE_GATES | Separate read-only diagnostic |
| Alpha2 | CONF-FIX-007 | BLOCKED_LOCAL_BUDGET_EXHAUSTED | No product acceptance renewal |
| Alpha2 | CONF-LIVE-004/005/006; CONF-A2-001 | WAITING_PREDECESSOR_CORRECTION | Native/integrated qualification |
| Alpha3 / Alpha4 | Later roadmap | WAITING | Governed actions and enterprise release |

## Retained original draft specification — historical, not current allowance

# Alpha 2 - completion profiling after exhausted LOCAL acceptance

Owner: MET-PERF-009. Companion: CONF-DIAG-003. META_PLANNING_ONLY.

This amendment publishes one separate read-only diagnostic. It does not run
product code in META, repair the product, renew CONF-FIX-007, merge PR18 or open
CONF-LIVE-004. The canonical machine record is
[architecture/completion-profiling.json](../../architecture/completion-profiling.json).
All 166 predecessor YAML and prior authority files remain byte-immutable.

## Current position and why another full acceptance retry is not authorized

Accepted META main is b2705835139ece8954cf36f66ab0b5e8d8b3c10b (MET-ADOPT-002,
PR123). Accepted product main remains092fcf475c6f3ebd455e3c354cddb7664ea1f900.
The [C1-C7 completion contract](CONFORMANCE_COMPLETION.md) is unchanged.

CONF-FIX-007 is draft PR18, head25fab12c168ff686e863291098fce0f3dba629bd,
tree6f38052fb9a31e9fe8b9abb6b055ddd96f06854f. This unaccepted source contains all
135 files and 1,277 predecessor test identities plus290 appended tests. It is
the exact observed subject, not a newly accepted source predecessor.

| LOCAL | Candidate | Outcome | Retained log SHA256 |
|---|---|---|---|
| 1 | 6405c014bded2f975576ccd753804e3b12d50b20 | 900s timeout; backend error marker and incomplete suite | 03d20f32743575c7bb42c73f9616992d772d4e32a492895416a735809aa4ad9c |
| 2 | c366a3fac47d53a52a4fbe76618796e9fe196848 | 900s timeout; incomplete suite | 9855fa1836c1eade40ae2dfc589d0db33b0f82957d4af1fba1410aa44bc1ab7a |
| 3 | 25fab12c168ff686e863291098fce0f3dba629bd | 900s timeout; incomplete suite | fd62dbcbe693e99634f070e033bef4b356c571ce637dc40e910f28c5d73e3322 |

All three LOCAL allowances are consumed. CI0/2 and LOCAL exact-main0/1 remain
unexecuted; they cannot substitute for failed LOCAL acceptance. Queued checks
34934231335,34936090382,34940068069 were canceled without runner execution.
Older profiling drafts13/14/15 are retained unchanged, not alternative gates.

LOCAL3 completed five suites/170 tests, then reached917 backend progress markers
of1,397 without an E/F before timeout. This is not a completed test certificate.
The data-only ordering heuristic suggests a KernelObserverInspectionTests case;
it is not an exact interrupted-case trace or root cause. No new full-factory
watchdog was reached. Source/clone inventories were unchanged; no sleep event was
recorded. The tiny timestamp-parser benchmark was faster, but full-suite benefit
and the dominant bottleneck remain unproven. Retained host-load differences do
not by themselves establish contention or exclude code-level cost.

## One read-only diagnostic, not implementation or renewed acceptance

After this META packet passes local, required localhost CI, protected merge and
independent LOCAL exact-main, CONF-DIAG-003 may make **one attempt, zero retries**.
Its predecessor reference to CONF-FIX-007 identifies the observed incomplete
source-owner/history; successful007 acceptance is not a prerequisite for
observation, and successful observation does not complete007.

allowedPaths is the schema-required read-only discovery anchor, not a source
edit grant. Do not create a product branch, commit or PR for this diagnostic.
Use the exact existing25fab12 subject without an overlay or added observer file.
Independently verify every135-file mode/size/digest before and after. The observer
program is a META-owned diagnostic asset, not shipped product/runtime code.

The only command is the packet's exact direct Python argv, through the existing
signed python-conformance-stdlib profile and root-owned absolute
`/opt/planeon/bin/harness-offline-launch`, using empty prefetch and the existing
`./ci/verify-offline.sh` wrapper in one deny-all-outbound process tree. Never run
the inner command directly. No external script path, mutable input, shell,
command-string splitting, environment override, base64 loader or source overlay.

The readable observer is [diagnostics/conf_diag_003.py](../../diagnostics/conf_diag_003.py).
The packet transports an exact Python source literal in `python3 -c`; only
whitespace formatting is compacted with token and AST parity to meet the installed single
argument limit. A validator pins both source and argv bytes and requires AST
parity and exactly one literal exec expression, rejecting dynamic loaders and
extra arguments. The existing no-newline/4096-byte argument boundary is retained;
no root policy update or alternate launcher is required or authorized.

The observer uses stdlib unittest discovery and TextTestRunner. It runs all1,397
cases in original discovery order, including every setup/body/teardown/cleanup.
No TestCase.run override, skipped case, failfast, fixture reuse, class/method
filter, assertion change, guard cache or substituted admission/cleanup result.
The exact discovered identity count and digest must match before the runner starts.

## Measurement and compatibility boundaries

TextTestResult start/stop observers emit flushed JSON records containing the
case ID and available wall/thread-CPU/process-CPU time. For1,394 cases, stdlib
cProfile's default-timer counters supply top20 self-elapsed and top20 cumulative-elapsed
function records, call counts and recursive-call counts. It writes no profiler
file. Known repo/stdlib paths are relative; other profile paths are redacted.
Stack-only faulthandler diagnostics are armed at30 seconds, without locals,
argument values, secret contents or forced success. Existing factory diagnostics
remain untouched. Normal unittest failures/errors/skips and exit status remain.

### Pinned-interpreter compatibility correction

Native CPython3.12.14 cProfile uses interpreter-wide sys.monitoring, not the
legacy sys.getprofile hook. This observer therefore does not call its native
enable/disable methods. Instead an explicitly identity-owned current-thread
sys.setprofile adapter forwards call/return and C-call events to the installed
cProfile counter callbacks. Those private callbacks are supported here only
for pinned CPython3.12.14; other interpreter versions fail before attachment.
No CPython source is copied, no monitoring callback is replaced and no profiler
implementation is reimplemented. This diagnostic-specific adapter is not a
portable product/runtime integration.

Before any case the observer refuses ambient legacy profiling and occupied
monitoring tool IDs0-5 or their global events. Its cleanup removes only its
identical hook; a replacement hook and any newly occupied monitoring slot are
left untouched. Detected interference emits observationValid=false, suppresses
function rows and aborts the diagnostic, never fabricating a clean run.
hookOwnedAtFinish describes hook identity only, not continuous ownership.
Open observer-boundary frames are not force-flushed or claimed as complete
function calls. Synthetic tests verify actual counter records, recursion,
built-ins, thread exclusion, foreign-state preservation and setup failure.

Implementation basis: [pinned CPython counter/monitoring source](https://github.com/python/cpython/blob/v3.12.14/Modules/_lsprof.c)
and [per-interpreter monitoring specification](https://peps.python.org/pep-0669/#specification).

Three exact cases receive timing only because their inherited contract requires
no ambient observer:

- test_supervisor.PerformanceArithmeticTests.test_fixed_three_sample_workload
- test_supervisor.PerformanceSourceProofTests.test_benchmark_refuses_ambient_observer_without_replacing_it
- test_supervisor.PerformanceSourceProofTests.test_benchmark_restores_observer_after_workload_exception

These tests still execute normally. The first retains its existing fixed
benchmark profiler; the others retain their refusal/restoration assertions.
The3-case function-profile omission is declared coverage, not missing-as-zero,
test filtering or a bypass of inherited safety assertions.

Interpretation limits are mandatory:

- The observer changes cost. Overhead is unmeasured and never subtracted or
  portrayed as uninstrumented latency. One profiled run cannot prove a speedup.
- Per-case timers cover setup/body/teardown/cleanup and profiler overhead, not
  imports/discovery or class/module fixtures. Discovery has a separate timing;
  unassigned intervals are not attributed to the last test.
- Function times are elapsed, not CPU. The explicit legacy hook observes only
  its current test thread; native cProfile global enable is not used.
  Thread CPU differs from process CPU; process CPU includes other threads, not
  child processes. CPU/wall ratios are observations, not proof of scheduler cause.
- Cumulative times overlap and must not be summed. Top-N output is censored;
  absent functions are not zero-cost. Report total function count separately.
- An identical hook at finish is not proof of uninterrupted profiling. Any
  competing profiler/diagnostic interference invalidates that attribution;
  original errors remain visible. Never fight an inherited profiler or retry.
- Timeout can leave a start without a finish/profile. Mark its cost NOT_MEASURED;
  stack samples are partial evidence, not exact per-function totals. Preserve all
  prior completed records and full output, but never pool these as acceptance.
- Operator line receipt time is not an execution boundary. A watchdog can be
  canceled by inherited cleanup or fail before arming. Absence of a stack proves
  neither absence of a stall nor absence of a defect.

## Execution custody, finite allowance and failure handling

Before activation, reserve the sole CONF-DIAG-003 attempt with exclusive durable
operator storage outside disposable checkouts. Bind accepted META source gates,
packet/program bytes, subject commit/tree/inventory, exact1,397 IDs, installed
interpreter/full toolchain inventory, signed request and original failure records.
Authenticate signatures/installed custody independently; this JSON ledger grants
no execution by itself. Keep exactly one active run and retire its exact slot.

Keep nested420/trusted900/workflow15-minute limits. No timeout extension, fourth
product LOCAL retry, repeat diagnostic, old reservation rewrite or new-directory reset.
Crash, timeout, sleep or invalid performance observation after activation consumes
the attempt. Missing prerequisites before activation are unavailable, never a
reason to bypass policy, install tooling or execute outside isolation.

Retain complete output and signed custody, source/toolchain before/after checks,
wall/monotonic times and read-only awake/sleep/load/thermal observations. No host
power setting, unrelated workload termination, administrator/key change or
privileged profiler is allowed. Sleep/interference invalidates performance
interpretation, not historical retention. A timeout is an incomplete diagnostic,
not a product failure diagnosis by itself and never a WORKLOAD PASS.

META tests exercise only synthetic local observer cases and authority mutations;
they never import/discover the product suite. This packet preserves all36 prior
META commands, adds its validator (37 total), retains both full test replays and
all inherited isolation skips, and uses the normal exact signed localhost gates.

The initial META LOCAL attempts1-3 failed: a repository-tree declaration,
descriptorless synthetic stderr, then a CPython3.12 profiler-state mismatch.
All three failures and reservations remain retained in the machine record.
The user separately approved at most two additional META LOCAL attempts4/5
for this observer correction, each reserved before activation. This does not
renew CONF-FIX-007, add diagnostic retries, weaken any test or permit CI to
substitute for LOCAL acceptance. Source, CI, merge and exact-main remain separate.

## Decision after measurement and preserved product roadmap

Use available CPU/wall/call-cost evidence to identify a bounded target. If the
data cannot distinguish fixture overhead, guard expansion, serialization,
cryptography or host variability, state that uncertainty. Do not preselect a
crypto/canonical rewrite or remove repeated safety checks based on suspicion.

Any product correction requires a separately reviewed owner packet, exact paths,
consumer/source-history closure, semantic oracles and a finite fresh allowance.
That successor must reconcile how the existing PR18 candidate will be consumed;
this amendment grants no additional007 attempt or alternative merge gate. C1-C7,
all1,277 predecessor identities/assertions, the full eight-command recipe,
required localhost CI, protected green merge and independent LOCAL exact-main
remain mandatory before004. Artifact/native/runtime/assurance/tenant acceptance
remain separate. No declared completion solely from test counts or a CI badge.

The [all16 harness/paper/OSS adoption map](HARNESS_PAPER_REPOSITORY_MAP.md) remains
adopted, as do four planes/13 repositories, one accountable owner per harness,
contract-first cross-repo packets, Linux Kubernetes/OpenShift production and
macOS development. At least one qualified baseline per released capability is
the enterprise-release minimum. No warm-source observation/copy, provider
installation, license change, hosted/cloud provisioning, paid API, download or
telemetry/upload is authorized by this diagnostic.

| Phase | ID | Status at this publication | Description |
|---|---|---|---|
| Phase 0 / Alpha 1 | Foundations | DONE_RECORDED | Historical source/offline foundations |
| Alpha 2 | MET-ADOPT-002 | DONE_SOURCE_GATES_RECORDED | Adopted research-led OSS map, not provider qualification |
| Alpha 2 | CONF-FIX-007 | BLOCKED_LOCAL_BUDGET_EXHAUSTED | Draft18; three failed LOCAL attempts retained |
| Alpha 2 | MET-PERF-009 | ONGOING_PUBLICATION | This separate diagnostic amendment |
| Alpha 2 | CONF-DIAG-003 | WAITING_META_SOURCE_GATES | One full-backend read-only profiling attempt |
| Alpha 2 | Subsequent measured repair | NOT_AUTHORIZED | Requires diagnostic result and reviewed exact packet |
| Alpha 2 | CONF-LIVE-004/005/006 | WAITING_PREDECESSOR_CORRECTION | Native probes, packaging and integration |
| Alpha 2 | CONF-A2-001 | WAITING | Qualified integrated read-only profile |
| Alpha 3 / Alpha 4 | Governed actions / enterprise release | WAITING | Later capabilities and disconnected qualification |

Before consumption revert this META amendment as a reviewed unit; after
consumption publish a successor without erasing any source, attempt, trust,
nonce, resource or tenant history. Alpha2 ONGOING; model-effort transition NOT_DUE.
