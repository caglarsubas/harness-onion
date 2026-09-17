# CONF-DIAG-004 — guard amplification observed; no product acceptance

2026-09-17 · Alpha 2 · Read-only diagnostic attempt **1/1 consumed**; retries **0**.

## Outcome

The full-backend diagnostic reached the same factory test implicated in the
earlier failed LOCAL run. It was stopped at **748.029 seconds**, before the
750-second bound; launcher completion was **748.111 seconds**, exit **247**.
The observation packet is closed with **PARTIAL_DIAGNOSTIC_ONLY** evidence.
This is neither a completed backend suite nor product acceptance.

- Discovered all **1,447** expected backend identities in normal order.
- **1,062 cases completed**, one factory case was unfinished, **384 not started**.
- Only **1 of 41** counter-enabled factory cases was reached; none completed.
  The remaining 40 factory cases are **NOT_MEASURED**, not passed.
- Retained **224** progressive snapshots and **840,091 bytes** of full output.
- All **135 tracked files** matched before and after; no overlays or source edits.
- The exact temporary checkout and owned diagnostic processes were removed.
- Signed custody, reservation-before-activation and policy/toolchain/source pins
  were verified. Activation sequence: **336**. No observed sleep/wake/thermal
  interruption in the run interval; no capture errors or retries.

## Measured bottleneck

The unfinished case was
`test_proxy_server.KernelQualificationFactoryTests.test_policy_epoch_loss_inside_real_read_is_sticky_and_closes_originals`.
At its last retained snapshot, **448.027 seconds wall time** and **447.463
seconds thread CPU** had elapsed. One qualifier constructor and one
self-inspector constructor had started; neither had returned. The intended
`check_self` call had **not been reached**.

These are cumulative event counts at that snapshot, not completed operations:

| Counter | Calls | Returns |
|---|---:|---:|
| `_KernelNativeReads._tick` | 2,045,346 | 2,045,344 |
| `_KernelRootViews._reader_mounts` | 14,262 | 14,261 |
| `_KernelPolicyView._reader_epoch` | 7,132 | 7,132 |
| `_Files.check` | 2,362,068 | 2,362,067 |
| `_ServerQualificationBinding.check` | 3 | 3 |
| `_KernelSelfInspection.__init__` | 1 | 0 |
| `_KernelSelfInspection._tick` | 2,361,834 | 2,361,833 |
| `_KernelSelfInspection._reader_tick` | 2,361,823 | 2,361,821 |
| `_KernelQualification.__init__` | 1 | 0 |
| `_KernelQualification.check_self` | 0 | 0 |

The observer also counted **1,915,100,160 Python call/return events** while
filtering for these ten exact source identities. That is not a count of
security checks or successful operations. Approximately 99.87% of the measured
case wall interval was accounted for by current-thread CPU.

**Supported diagnosis:** this sampled execution is CPU-active and dominated by
extensive repeated guard work during construction. The source connects native
ticks to inspection ticks and whole retained-file scans; fresh root/epoch
sampling causes more native ticks. The progressive evidence supports guard
amplification as a concrete repair target, rather than an idle deadlock.

**Not established:** exclusive time per function, an optimal safe repair,
unbounded recursion, uninstrumented runtime, live Linux behavior, or successful
handling of the policy mutation. The test was still constructing its subject
before it installed the mutation callback.

## Source references and limits

The exact subject is commit `6785db60c96d2ec45b9188e59269b1d199769a64`,
tree `d24fca29ca493897021f6c5c18d7af4f81a65cf7`, in draft product PR20.
The accepted META authority is `ae33beb14584c25e4eeca3bfdcf7c85d3e722fc5`
(PR130). No repository or GitHub state was changed by this observation.

Relevant product locations:

- `src/harness_conformance/live_proxy_server.py:285` — inspection dispatch.
- `src/harness_conformance/live_proxy_server.py:329` — native tick.
- `src/harness_conformance/live_proxy_server.py:718` and `:1286` — root/epoch sampling.
- `src/harness_conformance/live_proxy_server.py:2310` — full retained-file scan.
- `src/harness_conformance/live_proxy_server.py:2638` and `:2656` — inspection checks and nested sampling.
- `tests/live_backend/test_proxy_server.py:74` and `:12362` — fixed simulated clock.
- `tests/live_backend/test_proxy_server.py:13690` — constructor precedes mutation/assertion.

The fixture's simulated clocks are unchanged. Real observer timing includes
profiling overhead and cannot prove native deadline performance. Return events
include exceptional returns; they do not establish successful checks. Hook
ownership snapshots were valid but are not continuous-ownership proof.
The final snapshot is a lower bound before termination. Partial observations
must not be combined with another attempt as if they formed a passing suite.
All 20 native controls remain **NOT_RUN_ENV_UNAVAILABLE**; no new native gate
was executed here.

## Roadmap position

| Phase | ID | Status | Description |
|---|---|---|---|
| Phase 0 / Alpha 1 | Foundation packets | DONE_RECORDED | Historical source/offline foundations; not universal runtime qualification |
| Alpha 2 | MET-PERF-014 | DONE_SOURCE_GATES | Diagnostic authority passed local, required CI, protected merge and exact-main |
| Alpha 2 | CONF-DIAG-004 | CLOSED_PARTIAL_DIAGNOSTIC | Single authorized observation consumed; guarded construction cost identified |
| Alpha 2 | CONF-FIX-008 | BLOCKED_LOCAL_FAILURE | Draft PR20 unchanged; LOCAL1 consumed, LOCAL2 held; no product CI/merge |
| Alpha 2 | New repair packet, ID not assigned | WAITING_REVIEWED_SCOPE | Reduce guard cost only under a reviewed safety argument and independent C1–C7 review |
| Alpha 2 | CONF-LIVE-004/005/006 | WAITING_PREDECESSOR_CORRECTION | Native probes, packaging and trusted campaign integration |
| Alpha 2 | CONF-A2-001 | WAITING | Qualified integrated read-only profile |
| Alpha 3 / Alpha 4 | Governed actions / enterprise release | WAITING | Later disconnected qualification |

Next: review [the proposed repair scope](NEXT_REPAIR_PROPOSAL.md), publish its
separate META authority, then implement only the authorized owner-repository
packet. No guard/fixture/watchdog edit or retry is authorized by this report.
Alpha 2 remains open; **model-effort transition NOT_DUE**.

## Retained evidence

- `diagnostic01-prerequisites.json`: exact authorities, old failed custody and prior source gates.
- `diagnostic01-reservation.json`: durable global attempt reservation before activation.
- `diagnostic01-activation.json`, `diagnostic01-policy.json`: signed root-authority custody.
- `diagnostic01-offline.log`: original progressive output; SHA-256
  `42fc59542ad84110e5fe79619787db3d739bb84713010efd8f326a584402184c`.
- `diagnostic01-result.json`: original terminal result; SHA-256
  `49a7e73ff5e248a4f18496248e9d83d0eeed70e42258121d2a47a8108ede67c8`.
- `diagnostic01-deadline-stop.json` and slot-specific cleanup record: exact owned-tree termination and removal.
- `audit.json`, `closeout.json`: independently rechecked retained evidence and final read-only remote snapshot.

Generated operator/evidence artifacts are outside every product repository.
No warm-source access, downloads, paid provisioning, hosted runner, new key,
administrator prompt, artifact release, deployment or tenant acceptance occurred.
