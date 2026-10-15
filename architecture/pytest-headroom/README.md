# Pytest headroom: six parallel-suite workers (MET-PERF-039)

Alpha 2A; 2026-10-15. Evidence class `SOURCE_DELTA_ONLY`.

The outer pytest (argv 63) runs inside the parallel suite (`ci/parallel_suite.py`, MET-PERF-035) with a fail-closed
900 s worker deadline (MET-PERF-038). Under host load its margin disappeared. In the 236th packet's dry run, argv 63
took 901.5 s under a load of 13 to 14, and the whole run took 1232.7 s. Its required verify took 1006 s, with pytest at
752.65 s, under a mean load of 11.

Owner decision Q-PERF39-1 (a), 2026-10-15, relayed by the lane monitor, raises the suite's worker count from 4 to 6
with nothing else changed. After the correction below, the owner confirmed it the same day: "proceed with 6 workers, no
weight refresh", and again after seeing the corrected gain and the 1200 s cap note: "proceed with 6 workers". All
three decisions are quoted in `workers.json`.

| Setting | Path | Before | After |
|---|---|---|---|
| Parallel-suite workers | `ci/parallel_suite.py` | 4 | 6 |

## Measurements

The measurements were taken on main `e7516160`, the 237-packet main, before this packet. Each was argv 63 on a clean
checkout, with the worker count set for the top-level session only by an out-of-tree pytest plugin. No repository byte
changed. They ran once each, in the order 4, 6, 8.

| Workers | Wall | Summed test time | Peak memory of the session tree | 1-minute load, mean / max | Result |
|---|---|---|---|---|---|
| 4 | 627.1 s | 2,254.6 s | 1,514 MiB | 8.51 / 10.53 | 11,252 passed |
| 6 | 361.0 s | 1,774.6 s | 2,035 MiB | 9.17 / 11.55 | 11,252 passed |
| 8 | 324.9 s | 2,030.8 s | 2,471 MiB | 10.48 / 14.04 | 11,252 passed |

**The four-worker run overstates the gain.** It ran first, and during its first ~300 s every test file ran about 1.7
times as long as in the six-worker run. That was host state, not the plan: summed test time fell by 21% between the two
runs, which adding workers cannot cause. Replaying the six-worker run's own per-file times through the suite's planner
at four workers gives an estimated 455 to 512 s under the same conditions. So six workers save about 21% to 29%, not
the 42% the raw table shows (independent source review round 1, S1-1). Eight workers saved about another 10%, with more
memory and load, and their summed test time rose again from contention.

**The weights are not refreshed.** On the six-worker run's own per-file times, the pinned weights in
`ci/parallel_suite_weights.json` put the slowest worker about 12% above an even split: 324.6 s against 290.8 s, with the
three parent nodes excluded. Refreshed weights would recover roughly 30 s, and 22 test files have no pinned weight at
all. The owner carried this to a later, separate ci/ change.

## What changes, and what does not

Changed:
- `WORKERS` in `ci/parallel_suite.py`.
- Its one live test pin: `tests/test_parallel_suite.py` checks the current suite's constant.
- The current-status page `docs/alpha-2/PARALLEL_SUITE_PERF035.md`, which now says six worker processes (four before),
  as MET-PERF-038 updated the same page for its deadline.

Unchanged:
- Every fail-closed rule of the parallel suite:
  - the 900 s worker deadline;
  - exact assignment and ownership of every report and warning;
  - one setup and one teardown per node, and a call if and only if setup passed;
  - every stream line decoded;
  - every worker exits 0, or 1 with a failure, before the deadline.
- The three parent nodes, the serial environment rule and the serial fallback, which applies to any other invocation
  and to `WORKERS == 1`.
- The weights file, the inherited 64 acceptance commands, the Linux runner launcher's own bound, and the verifier
  bundle v4 values recorded in `architecture/load-deadlines/limits.json`.

Every earlier record that states four workers stays byte-identical, as the record of what its packet decided. The
216th, 226th and 234th layers check their own era's suite, page and test, which the inverse authority restores.

## Risks

- **The 1200 s cap.** Under heavy load the verifier's 1200 s cap, not the 900 s deadline, is the binding limit. In the
  236 dry run, argv 1-62 and 64 took about 331 s against the 120 s budgeted for them. At that load, a 21% to
  29% faster pytest leaves roughly 100 to 170 s under the cap.
- **Memory.** Peak memory rises by about 0.5 GiB, to about 2 GiB, on a 128 GiB host.
- **Load.** The extra load (about +1) comes after bundle v4's load gate, which checks only before a run is claimed.
- **Contention.** Under heavy external load the gain shrinks, which is exactly the case that motivated the change.
- **Small runners.** `WORKERS` is a fixed count: a runner with six or fewer cores would be oversubscribed.

`workers.json` records:
- the change, with the suite's digests before and after;
- the matching test and page lines;
- the unchanged settings;
- the measurements and their caveat;
- the carried follow-up;
- the owner decisions, quoted verbatim.

It is a transport change, so the owner's approval file goes on the exact head of the PR.
