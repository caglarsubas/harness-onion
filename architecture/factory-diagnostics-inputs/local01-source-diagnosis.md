# Independent read-only diagnosis after LOCAL1 stalled

Reviewer: `/root/conf_fix_008_c7_review`; recorded by parent from the reviewer's
final message. Candidate: `6785db60c96d2ec45b9188e59269b1d199769a64`.

The strongest source-supported explanation is excessive guard-call amplification.
The retained log does not prove a deadlock or pinpoint the final executing statement.

## Evidence

- The log reaches `KernelQualificationFactoryTests.test_policy_epoch_loss_inside_real_read_is_sticky_and_closes_originals`, prints the 30-second watchdog header, then ends mid-traceback.
- That test constructs the complete qualifier at `tests/live_backend/test_proxy_server.py:13693` before installing its policy-loss callback at line `13697`. The marker does not establish that the intended injected-failure stage was reached.
- Every `_KernelSelfInspection._reader_tick` begins with `_tick`, which calls `self.binding.files.check()` over all retained file/ancestry rows (`live_proxy_server.py:2638–2669`).
- Once epoch checking is active, each outer reader tick invokes root mounts → policy epoch → root mounts (`2672–2683`).
- Each root sample visits seven descriptors, performs repeated native identity/metadata checks and seven path lookups (`472–502`). These native checks re-enter the owner tick.
- `epoch_sampling` prevents recursive resampling, but does not bypass the repeated owner, full file-custody, clock and authority-data checks. This yields substantial finite multiplicative work.
- The fixture returns fixed `self.mono` and `self.now` values (`test_proxy_server.py:12361–12362`). Simulated two-second inspection guards therefore cannot bound elapsed wall-clock CPU work. External acceptance supervision remains the real bound.

## Watchdog uncertainty

`_FactoryDiagnostics` installs repeating `faulthandler.dump_traceback_later(30,
repeat=True, exit=False)` at line `12193`. It contains no Python retry loop or
product-success substitution. However, reported `stat_path` line `535` conflicts
with the definition at `12395`, and the dump ends at an incomplete `File` entry.
The trace is insufficient to attribute the stall to that function or clear the
watchdog itself. No static evidence establishes a watchdog/runtime defect.

## Authority boundary

Reducing sampling, caching verification, moving/removing guards or changing their
frequency is not authorized by CONF-FIX-008, which prohibits guard-call-site
optimization. Changing the inherited factory clock, fixture structure or watchdog
also requires reviewed scope. Disabling the watchdog would not prove or fix the
apparent guard-cost problem.

Preserve LOCAL1 and its consumed allowance. Do not spend LOCAL2 on an unchanged
speculative retry. If LOCAL1 fails its bound, retain terminal evidence and pursue
a narrowly reviewed successor separating bounded diagnostic instrumentation from
safety-sensitive optimization. Do not relax deadlines, skip factory cases or
substitute successful qualification.

The C7 verdict remains source-only; it never established execution time. Complete
acceptance remains unproven. The reviewer executed no product code/tests and
changed no files, runner state or GitHub state.
