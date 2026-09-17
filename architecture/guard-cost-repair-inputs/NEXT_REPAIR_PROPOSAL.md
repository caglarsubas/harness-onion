# Alpha 2 — proposed follow-up to CONF-DIAG-004

Status: **PROPOSAL ONLY; NOT AN EXECUTABLE PACKET OR PRODUCT AUTHORITY**.
The observation and this note do not authorize another diagnostic attempt,
changes to guards, fixtures or watchdogs, or release of product LOCAL2.

## Finding to address

The whole-backend observation reaches the previously blocked qualifier factory
test. Progressive counters show extensive repeated native-reader, inspection
and file checks while the one qualifier/self-inspector construction remains
unfinished. Increasing counts and near-matching wall/thread-CPU time support
CPU-active guard amplification, not an idle deadlock, during these samples.
The final retained observation report supplies exact counts and censoring.

The source call chain is:

1. `_KernelNativeReads._tick` calls `_kernel_inspection_tick`.
2. That dispatches to `_KernelSelfInspection._reader_tick`, which calls `_tick`.
3. Inspection `_tick` scans retained files through `_Files.check`.
4. When epoch sampling is not already active, `_reader_tick` additionally runs
   root-mount sampling, policy-epoch sampling, and root-mount sampling again.
5. Those samples make more native reads and therefore more custody/file checks.

The `epoch_sampling` flag bounds recursive epoch sampling; this observation
does not demonstrate unbounded recursion. `_Files.check` scans all retained
rows. Counts alone do not identify each function's exclusive time or prove
which optimization is correct.

The synthetic fixture fixes `time.monotonic` and its wall clock. The observer
retains real `perf_counter` and `thread_time`. Observed durations therefore
include profiling overhead and do not measure real Linux deadlines. No live
native qualification is implied.

## Recommended publication before implementation

Publish one separate META amendment and a bounded owner-repository repair
packet, with exact predecessor source/evidence pins and updated backlog views.
Assign an ID only after checking the current canonical packet registry. Keep
the failed candidate, diagnostic allowance and old drafts immutable. Record
the new packet's finite execution allowance explicitly; do not transfer or
reset an older allowance, silently unlock CONF-FIX-008 LOCAL2, or pool partials.

The design review must distinguish:

- Immutable authenticated inputs and object/lifetime ownership checks.
- Mutable filesystem, mount, namespace, policy-epoch and descriptor identities.
- Checks required before and after each consequential observation or effect.
- Checks whose cost can be reduced without changing their semantics or order.

Prefer a cost-per-check improvement with unchanged security behavior. If a
proposal instead changes whole-file scans, sampling frequency or call sites,
it needs an explicit safety argument and fault-interleaving tests for the
checks it removes or relocates. Do not assume a cached earlier observation is
fresh. If equivalence cannot be demonstrated, retain the checks and revisit
the design rather than merely increasing the timeout.

## Required review and acceptance

- Independent C1–C7 review against the exact repair candidate.
- Preserve all original test identities and required suites; no filtered,
  substituted, skipped, reordered or successful-qualifier shortcut tests.
- Preserve fail-closed handling for authority/expiry change, policy epoch
  drift, namespace/mount replacement, FD reuse, owner replacement, wrong role,
  reentrancy, partial acquisition and original-resource cleanup.
- Preserve current public contracts, privilege/credential ordering, zero-cost
  boundaries and source-to-native evidence separation.
- Full declared eight-command product acceptance, required isolated localhost
  CI, protected merge, and an independent exact-main replay remain separate.
- Subsequent packaging, installed Linux evidence, runtime/assurance and tenant
  acceptance remain independent gates; macOS unit doubles cannot satisfy them.

No runtime/provider roadmap item is marked complete by this proposal. Preserve
the 16-harness/four-plane/13-repository map, phased OSS provider adoption and
the minimum of at least one qualified baseline per released capability.

Alpha 2 remains open; no phase-end model-effort transition is due.
