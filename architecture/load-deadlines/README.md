# Load-tolerant in-repository deadlines (MET-PERF-038)

Alpha 2A; 2026-10-14. Evidence class `SOURCE_DELTA_ONLY`.

Required verify of the 233rd packet, MET-MAS-003, first failed twice on host load: the parallel suite's 600 s worker deadline killed a
worker, and the in-session predecessor proof then found incomplete tests. The owner chose verifier bundle v4 (owner
decision Q-PERF-DL, 2026-10-14): a load gate before the run (5-minute load below 4.0 and 1-minute load below 6.0, checked
every poll, waited out before the check run is claimed) and a 1200 s launcher cap, installed by the owner as a root change.
This packet, re-based as the 234th after MET-MAS-003 (owner decision Q-ORDER-187), raises the in-repository limits that
load could trip so they fit inside that cap (owner decisions Q-DL1, Q-DL2, and Q-DL3 as amended by Q-DL3-B):

| Limit | Path | Before | After |
|---|---|---|---|
| Parallel-suite worker deadline | `ci/parallel_suite.py` | 600 s | 900 s |
| Nested predecessor bound | `tests/linux_runner/test_build_and_predecessors.py` | 420 s | 600 s |
| Workflow timeout | `.github/workflows/verify.yml` | 15 min | 15 min (unchanged) |

The budget, with the launcher's own setup counted inside the cap: about 60 s of setup, about 120 s for argv 1-62, the
900 s worker deadline and about 90 s for the parent nodes after the workers, 1170 s in all against 1200 s. A run that
reaches the deadline is already failing; under heavy load it may reach the cap during the parent nodes instead of
reporting the deadline. The workflow timeout stays at 15 min as a pinned record value: the required verify runs in the
owner's app verifier, never in that workflow job.

The parallel suite stays fail-closed: four workers, the same parent nodes, the same accounting, and a missed deadline
still fails the session. The Linux runner launcher's own 900 s bound is unchanged, and every earlier record that states
420 s, 900 s or 15 min stays byte-identical, as the record of what its packet decided (Q-DL2). `limits.json` restates the
bundle v4 values, the budget and the owner decisions verbatim; `scripts/validate_load_deadlines.py` checks it and the
changed files.
