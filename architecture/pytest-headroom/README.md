# Pytest headroom: six parallel-suite workers (MET-PERF-039)

Alpha 2A; 2026-10-15. Evidence class `SOURCE_DELTA_ONLY`.

The outer pytest (argv 63) runs inside the parallel suite (`ci/parallel_suite.py`, MET-PERF-035) with a fail-closed
900 s worker deadline (MET-PERF-038). Under host load its margin disappeared. In the 236th packet's dry run, argv 63
took 901.5 s under a 1-minute load of about 14. That run passed only because the workers finished just before the
deadline. Its required verify took 1006 s, with pytest at 752.65 s, under a mean load of 11.

Owner decision Q-PERF39-1 (a), 2026-10-15, relayed by the lane monitor, is quoted in `workers.json`. It raises the
suite's worker count from 4 to 6, with nothing else changed:

| Setting | Path | Before | After |
|---|---|---|---|
| Parallel-suite workers | `ci/parallel_suite.py` | 4 | 6 |

The measurements behind the decision were taken on main `e7516160`, the 237-packet main, before this packet. Each run
was argv 63 on a clean checkout. The worker count was set for the top-level session only, by an out-of-tree pytest
plugin, with no repository byte changed.

| Workers | Wall | Summed test time | Peak memory of the session tree | 1-minute load, mean / max | Result |
|---|---|---|---|---|---|
| 4 | 627.1 s | 2,254.6 s | 1,514 MiB | 8.51 / 10.53 | 11,252 passed |
| 6 | 361.0 s | 1,774.6 s | 2,035 MiB | 9.17 / 11.55 | 11,252 passed |
| 8 | 324.9 s | 2,030.8 s | 2,471 MiB | 10.48 / 14.04 | 11,252 passed |

Six workers cut argv 63's wall time by 42% against four. Eight saved another 10%, with more memory and load, and their
summed test time rose again from contention. The per-file weights (`ci/parallel_suite_weights.json`) are not refreshed.
Replaying the six-worker run's own per-file times through the suite's planner, with the pinned weights, puts the
slowest worker about 10% above an even split: 326 s against 296 s. Weights refreshed from measured times would recover
roughly 30 s of the 361 s wall time; this packet leaves that for later.

Unchanged by this packet:
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
216th, 226th and 234th layers check their own era's suite, which the inverse authority restores. The only live pin is
`tests/test_parallel_suite.py`'s constant check, which this packet updates to six.

`workers.json` records:
- the change, with the suite's digests before and after;
- the matching test line;
- the unchanged settings;
- the measurements;
- the owner decision, quoted verbatim.

It is a transport change, so the owner's approval file goes on the exact head of the PR.
