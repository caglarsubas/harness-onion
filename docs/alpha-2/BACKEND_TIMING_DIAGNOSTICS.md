# Alpha 2 — full-backend timing diagnostic and canonicalization no-go

MET-PERF-008 records PLAN-CANON-001 **NO_GO_AS_TIMEOUT_REPAIR** and publishes
CONF-DIAG-002 as a separate read-only observation. It does not change product
source, implement the canonicalization proposal, reset either exhausted retry
budget, or establish the cause of the full acceptance timeout.

## Decision and evidence

MET-PERF-007 completed its source/local/required localhost CI/merge/independent
LOCAL exact-main gates at meta main a8ba81461281eda13bc67e5de8e75949b562b9df,
PR #118. Its historical proposal and raw predecessor packet remain immutable.
The later read-only design check compared 127 accepted product files and 362
AST method identities with accepted f988c78e93b28257810ed99e7f0c072e9b76bae5.
All matched. This was source inspection, not another test execution.

The proposed five-line canonical-document optimization affects eight inspected
consumer paths. The old eight-file performance proof excludes canonical.py;
both performance_history and the independent CONF-FIX-006 checkpoint bind its
unchanged bytes. The helper/importer digest, direct proof/resealing tests and
final proof fences would all need an exact reviewed migration. Current-before-
history checks and immutable originals may not be bypassed. No migration was
implemented or declared complete; the permitted no-go decision branch is closed.

At most 31,631 of 259,025 observed serialization calls could be avoided by
one-reuse-per-invocation in the selected 40-method profile: 12.21% of calls,
NOT time savings. Actual benefit is NOT_MEASURED, and the aggregate 39–40%
canonicalization profile share is not this candidate's gain. The profiles do
not explain all 1,107 backend tests. CONF-PERF-005 remains NOT_AUTHORIZED.

The companion architecture/backend-timing.json records the inspected consumer
hashes, file/method-map hashes and operator report digests. These are retained
design data, not run authentication. Raw logs/signatures stay in operator
custody. Prior failure and diagnostic records remain unchanged. The retained
three-pair CONF-DIAG-001 campaign is exhausted; no fourth pair is authorized.

## Exact diagnostic scope

Question: which full-backend test identities consume elapsed time, or which
identity is unambiguously announced but not completed before termination?

Subject: local-only 7939626dc6aec99b58816e3a709fd0babf3a985f, tree
f5a25661c2df6c87e5d3429b0b5f62511c2e5988, all 135 files and 1,277 total methods;
the entire 1,107-method backend inventory is independently pinned. It remains
unaccepted/unpushed. Draft PR #12 stays at 699a00c2d26e36c9c710aa85d0338f0d926073f2,
base f988c78e93b28257810ed99e7f0c072e9b76bae5; it must not be merged for diagnosis.

Only after MET-PERF-008 local, required localhost CI, green-only merge and
independent LOCAL exact-main gates pass, activate CONF-DIAG-002 using the existing
signed python-conformance-stdlib profile and root-owned absolute host launcher.
The schema-required branch label is descriptive, not an instruction to create
a product branch or empty PR. allowedPaths names a read-only discovery input
anchor; it is neither the complete measured file set nor a source-edit grant.
The independently pinned 135-file inventory supplies the complete source scope.
CONF-DIAG-001 is a diagnostic-order predecessor, not accepted product ancestry.

Use empty prefetch, the exact packet wrapper and one direct argv command in the
same OS-enforced deny-all-outbound process tree, through only
/opt/planeon/bin/harness-offline-launch:

```json
["python3","-m","unittest","discover","-s","tests/live_backend","-p","test_*.py","--durations","0","-v"]
```

Never run that inner command directly. Use the exact existing commit without
overlays; verify all mode/size/digest/custody and toolchain bytes before and after.
No new profiler, -k/class/method filter, failfast, skip, xfail, fixture reuse,
monkeypatch, test-run override, module injection or additional dependency.
Inherited fixed benchmark profiling remains untouched and must be reported.

## Bounds, output and interpretation

Maximum **one attempt, zero retries**, across the whole CONF-DIAG-002 campaign.
Retain a durable operator attempt reservation before launch, bound to packet,
subject and signed request. Reusing a new directory or signing another request
does not reset this count. Failure, timeout, sleep or invalid observation after
launch consumes the attempt. Preserve all such output; no partial pooling.
Missing prerequisites before launch are unavailable and do not authorize code.

Keep nested 420 seconds, trusted 900 seconds and workflow 15 minutes unchanged.
The diagnostic is not a CI/live campaign. No administrator, root policy, key,
OS power setting, thermal override, workload termination or host change is
granted. Existing nonroot signed activation only. Missing compatible policy,
source or backend is NOT_RUN_ENV_UNAVAILABLE; never substitute a launcher.

Installed Python 3.12.14 unittest already collects case durations. --durations 0
requests all of them; -v prevents sub-millisecond rows being silently omitted
from that report and records identities. The four relevant stdlib files and
complete interpreter inventory are pinned independently of the subject.

Retain complete output, signed request, packet, source inventory and toolchain
evidence, wall/monotonic session times, host load and awake/sleep observations.
An interrupted awake interval or thermal-emergency sleep invalidates performance
interpretation, not permission to erase assertions or retry. Root/policy/custody
signatures require independent audit; self-reported booleans are insufficient.

- The duration table prints only after the suite returns. A timeout may produce
  no table. Record missing durations as NOT_MEASURED, not zero.
- Per-case durations include setUp/body/tearDown/cleanup, not imports, discovery
  or separate class/module fixtures. Values print to three decimal places; their
  sum is not exact full-command wall time.
- Operator line receipt time is not an execution boundary. The last completed
  test is not necessarily the interrupted test. Name an interrupted identity
  only when the verbose start/completion stream makes it unambiguous.
- A complete diagnostic requires all 1,107 pinned identities with zero skips,
  errors and failures, all expected duration rows, unchanged source and valid
  custody. A failure/timeout is retained diagnostic evidence, not a completed
  workload PASS. One sample is not a performance SLA or measured fix.
- Even a complete diagnostic is WORKLOAD_DIAGNOSTIC_ONLY. It omits seven product
  acceptance commands and cannot authorize source push, merge, runtime/native
  qualification, assurance or tenant acceptance.

## Delivery and next decision

The generic ownership checker is unchanged. The new closed adapter removes only
the exact CONF-DIAG-002/CONF-LIVE-003 read-only anchor overlap after independently
binding both packet bytes and the whole recipe. All unrelated or duplicate
diagnostics remain errors. No diagnostic becomes a runtime source co-owner.

MET-PERF-008 preserves all 159 previous YAML and authority evidence, adds exactly
two specifications (161 total), and runs all 31 prior META commands plus its
new validator, including both full test replays and zero-bill scanning. All
metadata changes have exact reversible recipes and inherited test IDs retained.

After the diagnostic, select a bounded source-owner repair only if evidence
supports its target. Otherwise retain the uncertainty and stop that campaign.
Any shared-source repair still needs independent semantic oracles, source-history
consumer closure and full eight-command product acceptance with unchanged limits,
required localhost CI, green-only merge and independent LOCAL exact-main. Pending
proxy integration remains separately authorized; its exhausted retry loop stays
exhausted. No preselected crypto, caching or guard-removal change is authorized.

Keep sixteen harnesses/four planes/thirteen repositories, Linux Kubernetes/OCP
production, phased OSS providers and at least one qualified baseline per released
capability. No warm-source observation, source-reuse/license change, cloud/hosted
provisioning, paid API, download, external telemetry or artifact upload.

| Phase | ID | Status at publication | Description |
|---|---|---|---|
| Phase 0 / Alpha 1 | Existing foundations | DONE_RECORDED | Historical source/offline foundations |
| Alpha 2 | MET-PERF-007 | DONE_SOURCE_GATES_RECORDED | Accepted PR #118 and separate local exact-main |
| Alpha 2 | PLAN-CANON-001 | DONE_NO_GO_AS_TIMEOUT_REPAIR | Decision complete; migration/optimization not implemented |
| Alpha 2 | MET-PERF-008 / PLAN-TIMEOUT-001 | ONGOING_PUBLICATION | This bounded diagnostic authority |
| Alpha 2 | CONF-DIAG-002 | WAITING_META_SOURCE_GATES | One full-backend timing observation, zero retries |
| Alpha 2 | CONF-PERF-005 | NOT_AUTHORIZED | Proposed repair deferred |
| Alpha 2 | CONF-LIVE-003 | BLOCKED_FULL_ACCEPTANCE | Whole packet incomplete; draft #12 unmerged |
| Alpha 2 | CONF-LIVE-004/005/006 | WAITING | Probes, packaging, trusted campaign integration |
| Alpha 2 | Native AMD64/ARM64 | NOT_RUN_ENV_UNAVAILABLE | Independent installed Linux qualification |
| Alpha 3 / Alpha 4 | Existing roadmap | WAITING | Governed actions and enterprise qualification |

Alpha 2 ONGOING. Model-effort transition NOT_DUE. Older publication headings
remain dated evidence rather than current dispatch.
