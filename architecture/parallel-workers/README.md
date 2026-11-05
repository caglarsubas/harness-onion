# Parallel workers: eight parallel-suite workers (MET-PERF-046)

Alpha 2A; 2026-11-05. Evidence class `SOURCE_DELTA_ONLY`.

The outer pytest (argv 63) runs inside the parallel suite (`ci/parallel_suite.py`, MET-PERF-035) with a fail-closed
900 s worker deadline (MET-PERF-038) and, since MET-PERF-039, six workers. Each history-chain step adds verify time,
against the verifier's 1,200 s cap and the owner's 1,000 s floor. Owner decision MON-OWNER-K8-G1 (2026-11-04, after
the A/B below) adopts eight workers; MON-280-START (2026-11-05) starts this packet with nothing else changed. Both are
quoted in `workers.json`.

| Setting | Path | Before | After |
|---|---|---|---|
| Parallel-suite workers | `ci/parallel_suite.py` | 6 | 8 |

## Measurements

One argv-63 run per arm on fresh clones of MET-VERIFY-006's head (`bd882493`), in the order K 6, K 8, K 6. The K 8
clone carried one counted edit, `WORKERS = 6` to `8`, never committed.

| Arm | Workers | argv 63 wall | Worker phase | Summed END time | Imbalance | 1-minute load, mean | Failed END events |
|---|---|---|---|---|---|---|---|
| A1 | 6 | 542.98 s | 517.5 s | 3003.8 s | 16.9 s | 8.32 | 0 |
| B | 8 | 498.44 s | 472.2 s | 3620.1 s | 19.6 s | 12.42 | 131 |
| A2 | 6 | 566.73 s | 540.7 s | 3122.3 s | 20.3 s | 10.78 | 0 |

Eight workers cut the worker phase by 56.9 s (-10.8 %) against the six-worker mean, beyond the 23.2 s spread between
the two six-worker runs. Summed END time rose 18.2 % from contention. The eight-worker arm's 131 failures are the
six-worker pins this packet moves; that arm's time need not equal a passing eight-worker run's. This packet's own dry
run measures the result.

## What changes, and what does not

Changed:
- `WORKERS` in `ci/parallel_suite.py`.
- Its one live test pin: `tests/test_parallel_suite.py` checks the current suite's constant.
- The current-status page `docs/alpha-2/PARALLEL_SUITE_PERF035.md`, which now says eight worker processes (six
  before), as MET-PERF-039 updated the same line.

Unchanged:
- Every fail-closed rule of the parallel suite, the 900 s worker deadline, the three parent nodes, the serial
  environment rule and the serial fallback.
- The weights file (MET-VERIFY-006's refresh), the inherited 64 acceptance commands, the 1,170 s budget and the
  verifier bundle's load gate recorded in `architecture/load-deadlines/limits.json`.

Every earlier record that states six or four workers stays byte-identical, as the record of what its packet decided.
Earlier layers check their own era's suite, page and test, which the inverse authority restores.

## Risks

- **Memory.** MET-PERF-039's own eight-worker run peaked at 2,471 MiB of session tree, against 2,035 MiB at six.
- **Load.** The extra load comes after the verifier bundle's load gate, which checks only before a run is claimed.
- **Small runners.** `WORKERS` is a fixed count: a runner with eight or fewer cores would be oversubscribed.
