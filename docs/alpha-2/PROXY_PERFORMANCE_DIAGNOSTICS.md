# Alpha 2 — bounded proxy performance investigation

MET-PERF-006 publishes measurement authority only. It does not optimize crypto,
modify product tests, rerun CONF-LIVE-003, or certify its unaccepted source.
CONF-DIAG-001 is a separate, read-only diagnostic replay of an exact local commit.
The sixteen harnesses, four planes, thirteen repositories and provider-adoption
policy remain unchanged. All 156 predecessor packet YAML remain byte-identical.
The catalog now contains 158 specifications, including two read-only measurement
roles (the retained CONF-BENCH-001 and new CONF-DIAG-001), not 158 coding PRs.

## Current position and retained failures

| Phase | ID | Status at publication | Description |
|---|---|---|---|
| Phase 0 / Alpha 1 | Existing foundations | DONE_RECORDED | Historical source/offline gates; runtime separate |
| Alpha 2 | MET-ADOPT-001 | DONE_SOURCE_GATES_RECORDED | Meta main 451cfc708bd6e708d20d905ca44165ae896a647b |
| Alpha 2 | MET-PERF-006 | ONGOING_PUBLICATION | This diagnostic authority and independent negative checks |
| Alpha 2 | CONF-DIAG-001 | WAITING_META_SOURCE_GATES | Read-only workload investigation; no source PR or merge |
| Alpha 2 | Performance repair | WAITING_DIAGNOSIS_AND_EXACT_PACKET | No arithmetic, caching or shared-source edit authorized here |
| Alpha 2 | CONF-LIVE-003 | BLOCKED_FULL_ACCEPTANCE | Local retirement source complete; whole packet incomplete |
| Alpha 2 | CONF-LIVE-004/005/006 | WAITING | Native probes, packaging and trusted integration |
| Alpha 2 | Native AMD64/ARM64 | NOT_RUN_ENV_UNAVAILABLE | Independent installed Linux qualification |
| Alpha 3 / Alpha 4 | Governed actions / enterprise qualification | WAITING | Existing release and independent tenant gates |

Recorded product main is f988c78e93b28257810ed99e7f0c072e9b76bae5.
Draft PR 12's remote checkpoint is 699a00c2d26e36c9c710aa85d0338f0d926073f2.
The diagnostic subject is local-only 7939626dc6aec99b58816e3a709fd0babf3a985f,
tree f5a25661c2df6c87e5d3429b0b5f62511c2e5988: 135 files and 1,277 test methods,
including 1,107 backend methods and the 40 selected retirement methods. These
counts are source inventory, NOT a claim that all tests passed. Do not push the
unaccepted subject, merge PR 12, or mark CONF-LIVE-003 complete for measurement.

Activation 252 / e3ea986 ran all 1,273 then-present tests and failed the new
instance-shadow cleanup regression. Its failed log is retained. The local fix
kept that test unchanged and added four further transport-custody regressions.
Activations 253 and 254 ran identical corrected source and both exceeded the
unchanged 900-second trusted limit during backend discovery/execution. The first
five suites passed; backend completion and commands 7/8 were NOT_RUN. Neither
timeout becomes PASS merely because no assertion failure preceded termination.
Exact request/log/inventory digests are in the companion diagnostic specification.

The one-second native stack sample showed bigint modular-inverse/arithmetic work.
It does not attribute total runtime to a Python function, identify hardware as
the cause, establish a regression, or justify another arithmetic optimization.
The existing private-_add optimization is already part of accepted main; do not
reapply its old authority or mistake the current code for the original baseline.

## Exact read-only replay

After MET-PERF-006 closes local, required localhost CI, merge and independent
LOCAL exact-main gates, sign CONF-DIAG-001 against the exact subject commit and
packet digest using the existing python-conformance-stdlib profile. Missing
subject, isolation, signed custody or compatible toolchain means unavailable,
not permission to substitute another commit or interpreter. No root policy,
administrator prompt, new key or software installation is required or granted.

The schema-required branch label is descriptive. Do not create a new product
branch, empty PR, source commit or accepted-source predecessor. allowedPaths
names the measured test input, not an edit grant; every product source write is
forbidden. Clone the exact existing local commit without overlays, inventory all
135 tracked files before and after, and compare mode/size/digest and Git tree.
Retain operator logs outside the checkout. No product import or execution in
the META publication; the later replay is the sole diagnostic execution role.

Through only /opt/planeon/bin/harness-offline-launch, run empty prefetch and these
two commands in order in one deny-all-outbound tree, with the exact packet wrapper:

1. python3 -m unittest discover -s tests/live_backend -p test_proxy_server.py -k BrokerCreateRetirementTests -v
2. python3 -m cProfile -s cumulative -m unittest discover -s tests/live_backend -p test_proxy_server.py -k BrokerCreateRetirementTests -v

Both commands must discover and execute exactly the same 40 pinned test IDs,
with zero skips, errors or failures. The standard-library cProfile CLI prints
complete statistics to the retained stdout log; no -o file, injected observer,
monkeypatch, module overlay, fixture cache, alternative crypto or test edit.
The profiled run covers discovery/imports, fixtures, tests and cleanup. Its CLI
defaults include subcalls and builtins; report that overhead and scope explicitly.
Compare command wall time, profiler total and per-function calls/self/cumulative
time. Distinguish crypto, JSON/source accounting, filesystem/custody and mock
overhead where present. Do not sum overlapping cumulative times or interpret
rounded output as exact precision. Missing attribution remains NOT_MEASURED.

Record interpreter/toolchain inventory, host/architecture, ordered argv, exact
test IDs/results, signed activation/request chain, packet/commit/tree/inventory,
complete launcher exit and log digest. Verify signatures and source custody
independently: DATA_CHECK_ONLY metadata or a boolean cannot prove a real run.
Require no pre-existing profiler or external Python import path/observer.

For variability, at most three successful complete pairs may be collected in
fresh signed sessions on identical source/toolchain/host, serially, not concurrently.
At most one failed/incomplete pair may be retried unchanged across this diagnostic
campaign. Retain all attempts and stop after retry exhaustion. Never pool partial
logs or combine one successful command from each failed pair into a complete pair.
Do not disturb other local workloads to improve the numbers. Report observed host
load and paired timings; no hardware-cause claim without independent evidence.
Require an uninterrupted awake interval for each diagnostic pair, and reject
intervals with host sleep or thermal-emergency events as timing baselines. Keep
awake-time/monotonic duration separate from wall-clock elapsed time. Do not
override thermal protection, power policy or another workload. If a suitable
interval is unavailable, retain the result as environment-affected and stop.
Existing nested 420 / trusted 900 seconds / workflow 15 minutes remain unchanged.

During the first META publication test run, macOS reported a 929-second sleep
starting 2026-09-14 03:35:50 +0800, with reason Dark Wake Thermal Emergency.
This observation is separate from the earlier product failures. It invalidates
that META run as a wall-clock performance baseline, not the executed assertions;
it does not prove why the previous CONF-LIVE-003 runs timed out. No OS settings
were changed and this publication grants no power-management override.

## Decision and resumption gates

This is WORKLOAD_DIAGNOSTIC_ONLY, not a subset acceptance escape hatch, full-suite
profile, before/after speedup, native campaign or product qualification. It may
report a reproducible failure and local workload hotspots; it may not conclude
that the selected class explains all 1,107 backend tests or both broad timeouts.

Produce a diagnosis with measured scope, uncertainty and a smallest-path repair
proposal if justified. A shared-crypto/accounting repair needs its own exact
source-owner packet, independently pinned oracles, unchanged malformed/signature
semantics, source-history consumer closure, baseline/candidate comparison and
full eight-command local/CI/merge/LOCAL exact-main acceptance. No optimization
algorithm or write scope is preselected. New public/security decisions still
require explicit approval. Do not restart the exhausted CONF-LIVE-003 retry loop.

The generic ownership checker remains unchanged. A digest-bound adapter may
remove only the one exact overlap diagnostic for CONF-DIAG-001's read-only test
input and CONF-LIVE-003's test owner. All other ownership errors remain errors;
neither packet becomes the other's accepted predecessor or source co-owner.

MET-PERF-006 runs all 29 prior META commands plus its new diagnostic validator,
including both complete predecessor/current test replays and zero-bill scanning.
Exact reversible catalog/navigation amendments preserve historical authorities,
old test identities and all source/release/license locks. No timeout/skip change,
warm-source access, external telemetry, download, hosted runner, cloud, paid API,
artifact upload, production mutation or tenant acceptance is authorized.

Alpha 2 remains ONGOING. Model-effort transition NOT_DUE. The provider roadmap,
at least one qualified baseline per released capability, and all later industry,
extension, release and independently signed acceptance obligations remain intact.
