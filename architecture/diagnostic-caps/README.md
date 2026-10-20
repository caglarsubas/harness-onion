# Pytest-diagnostics caps under the 32 MiB output ceiling (MET-PERF-041)

Alpha 2A; 2026-10-20. Evidence class `SOURCE_DELTA_ONLY`. The 253rd packet, on accepted main 27c5460 (252 packets; MET-ENFORCE-038's required verify took 857 s). Owner decisions Q-253-DIAG (a) and Q-DIAGCAP-SIZE (A), 2026-10-20, via the lane monitor, are quoted verbatim at the end and in `limits.json`.

## Why

MET-ENFORCE-039's Mac dry run (31a7d52e) failed at argv 63 with "16306 passed in 666.74s": the outer pytest's diagnostics stream (`ci/pytest_diagnostics.py`, one `Diagnostics` per pytest process, sink fd 2) reached `MAX_PROCESS_BYTES = 20 MiB` and failed closed (SESSION_END exitCode 1, failed 0, incomplete, `["OUTPUT_LIMIT"]`, dropped 3,396). It had written 94,442 records: 47,220 START (mean 235.3 B, max 244), 47,220 END (mean 208.8 B, max 213), one ERROR (96 B) and SESSION_END (200 B), 20,969,573 B in all. Under the parallel suite the parent replays every worker's reports into its own single `Diagnostics`; each worker's own sink carries only its share.

## The ceiling and the reserve

The owner's verifier (`verify_pr.py:79`, `OUTPUT_LIMIT = 32 * 1024 * 1024`, enforced at `:558`, "output ceiling exceeded") fails the run closed once the launcher's combined stdout and stderr for the whole run passes 32 MiB (33,554,432 B). It is the "32 MiB outer output ceiling" every packet contract since MET-PERF-028 keeps, and it stays unchanged. Everything except the outer pytest's diagnostics stream is about 90 KB: argv 1-62's logs 55,774 B, argv 63's non-diagnostic lines 25,000 B, argv 64 (zero_bill_scan) 956 B, the runner's per-argv echo lines 7,988 B, and the launcher's and canary's few lines. The stream gets 30 MiB (31,457,280 B), and 2 MiB (2,097,152 B, about 23 times the other output) stay reserved for everything else: `MAX_PROCESS_BYTES` + reserve = 32 MiB exactly.

## The caps

| Limit | Before | After |
|---|---|---|
| `MAX_PROCESS_BYTES` | 20 MiB | 30 MiB (31,457,280 B) |
| `MAX_EVENTS` | 100,000 | 140,000 |
| `MAX_SCAN_LINES` | 110,000 (literal) | 154,000, derived in code as `MAX_EVENTS + MAX_EVENTS // 10` |
| `MAX_SCAN_BYTES` | 21 MiB (derived) | 31 MiB, still `MAX_PROCESS_BYTES + 1024 * 1024` |

Nothing else in `ci/pytest_diagnostics.py` changes: not `MAX_RECORD_BYTES` (1,024), `MAX_NODE_CHARS` (65,536) or `MAX_FAILURES` (16), not the record schema and not any fail-closed rule. The 64 argv, `.github/workflows/verify.yml`, `conftest.py` and the verifier are unchanged. `tests/test_diagnostic_repair.py` changes only line 133, its live digest pin of the module.

## Record sizes and the pinned profiles

A START record holds the 64-hex node digest, a label of at most 70 characters (already at the schema maximum in every measured log), the phase, `seq` and `tUs`; an END record holds the node, phase, outcome, `durationUs`, `tUs`, `seq` and `xfail`. Sizes grow only by digits: `seq` gains a sixth digit after 99,999, and `tUs` and `durationUs` reach at most 10 digits inside the 1200 s verify cap. A non-control record is written only while `events_written + 1 + 2 <= event_limit` and `bytes_written + len(record) + 2 * MAX_RECORD_BYTES <= byte_limit`; SESSION_END (control) is written without the reserve.

The boundaries below come from the real module with three START/END pairs per test, a counting sink, the module's default limits and a pinned clock: the first call returns 0.0 and the n-th call 100.0 + n x 1e-6 s, so every `tUs` after the first record has exactly 9 digits. Node ids are `tests/test_<27 x>.py::test_<40 y>[i]` (a 70-character label); profile S uses `x::y[i]` (the label `<redacted-node>`).

- **W, worst case at constant maximum digits:** all three phases `teardown`, outcome `skipped`, duration 0.099999 s, `xfail` false. It is the worst case among profiles whose records all carry the same digit counts (C3-1).
- **R, realistic:** setup, call and teardown, outcome `passed`, duration 0.012345 s, `xfail` false.
- **S, small records:** as R with S's node ids.

The digits follow from the 900 s worker deadline: the parent's `tUs` stays below 1e9 us (9 digits) if collection, the three parent nodes and finish fit in the remaining 100 s, and the 6 x 900 s duration budget over the roughly 68,700 END records of a full run averages under 100,000 us (5 digits). The average bounds the mean, not each record's digit count: mixing 5- and 6-digit durations under the same budget (WB) gives 22,836 tests, 38 below W.

## Boundaries

| Profile | Module | Last passing | First failing | Reason | Stream at the last passing count |
|---|---|---|---|---|---|
| W (worst case at constant maximum digits) | after | 22,874 | 22,875 | OUTPUT_LIMIT | 31,455,196 B |
| R (realistic) | after | 23,159 | 23,160 | OUTPUT_LIMIT | 31,454,789 B |
| S (small records) | after | 23,333 | 23,334 | EVENT_LIMIT | 27,842,006 B |
| WB (W, budget-mixed 5/6-digit durations) | after | 22,836 | 22,837 | OUTPUT_LIMIT | 31,455,144 B |
| W10 (W, 10-digit `tUs`) | after | 22,775 | 22,776 | OUTPUT_LIMIT | 31,455,226 B |
| W10D (W, 10-digit `tUs` and durations) | after | 22,531 | 22,532 | OUTPUT_LIMIT | 31,455,007 B |
| W (control) | before | 15,269 | 15,270 | OUTPUT_LIMIT | 20,968,680 B |
| R (control) | before | 15,461 | 15,462 | OUTPUT_LIMIT | 20,969,647 B |
| R at 16,306 tests (the incident) | before | | fails | OUTPUT_LIMIT | first failing test 15,462 |

They are identical to contract review round 3's independent oracle. Whatever the profile, the stream never exceeds `byte_limit` (31,457,280 B; the largest first-failing stream above is 31,455,498 B, WB). At W's boundary the stream ends at 31,455,196 B; with about 90 KB of other output the whole run is about 31.55 MB against the 33.55 MB ceiling.

## Headroom

W allows 22,874 tests, 6,568 more than 253's 16,306 (6,530 under WB): about 9 packets at 700 tests per packet (an aggregate rate, 2.4 times the 20-packet mean and 1.85 times the 9-packet mean), 17 at the recent 9-packet mean of 378, and 22 at the 20-packet mean of 288. The time limits bind in the same range: at 253's load (41 ms per test) the 1200 s verify cap binds near 20,000 tests and the 900 s worker deadline near 22,000; on a quiet host (25 ms per test) the cap binds near 33,000. Diagnostics stop being the first limit under load. CHAIN-COMPACTION-001 (D9a, after slot 254) is the structural follow-up for both the time and the output ceiling.

| From -> to slot | Tests | Increment | Packets |
|---|---|---|---|
| 233 -> 234 | 10,543 -> 10,722 | +179 | 1 |
| 234 -> 238 | 10,722 -> 11,394 | +672 | 4 |
| 238 -> 241 | 11,394 -> 12,231 | +837 | 3 |
| 241 -> 244 | 12,231 -> 12,905 | +674 | 3 |
| 244 -> 246 | 12,905 -> 13,588 | +683 | 2 |
| 246 -> 250 | 13,588 -> 14,879 | +1,291 | 4 |
| 250 -> 252 | 14,879 -> 15,652 | +773 | 2 |
| 252 -> 253 | 15,652 -> 16,306 | +654 | 1 |

Only two single-packet increments were measured (179 and 654). 700 per packet is an aggregate rate; a single packet inside a multi-packet gap may have added more.

## Consumers

- `Diagnostics.__init__` (`ci/pytest_diagnostics.py`), follows the constants: accepts limits up to MAX_PROCESS_BYTES and MAX_EVENTS.
- `_valid_record` (`ci/pytest_diagnostics.py`), follows the constants: accepts seq up to MAX_EVENTS and SESSION_END counts up to 2 x MAX_EVENTS.
- `summarize_nested` (`ci/pytest_diagnostics.py`), follows the constants: reads separated nested stderr (capture_output), where each record ends its own line; the 10% allowance in the derived MAX_SCAN_LINES covers non-diagnostic stderr lines (C1-10); a full-size nested stream at the caps is scanned completely, one byte past MAX_SCAN_BYTES gives INPUT_LIMIT and one line past MAX_SCAN_LINES gives SCAN_LIMIT.
- The predecessor fallback (`tests/linux_runner/test_build_and_predecessors.py`), fits at the new caps: used when the in-session proof is unavailable, it runs the whole predecessor suite (15,971 tests in 253's proof) in a nested serial pytest, a full-size producer under the same caps, which summarize_nested must report COMPLETE; its line-59 comment ('up to 20MiB of nested structured stderr') becomes stale and stays unchanged on purpose, because the file is digest-pinned by earlier layers and a comment-only edit would add a pin churn; PREDECESSOR_OUTPUT_LIMIT (65,536) is a separate limit, unchanged.
- The parallel suite (`ci/parallel_suite.py`), no change: the parent's single stream carries every worker's replayed reports; each worker's sink carries only its share.
- MET-PERF-021's tests (`tests/test_pytest_diagnostics.py`), no edit; the oracle: uses the constants symbolically and monkeypatches the scan limits.

Known residual (C1-11), pre-existing and out of scope: the predecessor fallback's serial nested run cannot finish inside its 600 s timeout at today's size, whatever the caps.

## Pins

- Live: `tests/test_diagnostic_repair.py` line 133 pins `ci/pytest_diagnostics.py` and moves from 67416db3 to the new file's digest. Line 132 (3c0afe56, the predecessor diagnostics test) stays byte-identical; the mutant at `tests/test_load_deadlines.py:859-860` (27c5460's lines; 860-861 at this packet's head, where the bridge inserts one line above them, the content unchanged) replaces it through `reviewed_bytes`, after the successor projection, and this packet's reverse hunk spans line 133's bytes only (C3-2).
- Historical, byte-identical and reached through this packet's reverse hunks: MET-PERF-028's authority `newFiles` (`ci/pytest_diagnostics.py` 67416db3, checked through `successor.historical_bytes` by `scripts/validate_packet_schema_performance.py`, argv 51; `tests/test_diagnostic_repair.py` 89aaa588); MET-PERF-038's authority `changedFiles` (before 89aaa588, after 7b666bb8) and `scripts/validate_load_deadlines.py`'s `ERA_SHA256` (7b666bb8).

## Historical records

MET-PERF-028.yaml (sha256 cfa07a1e) stays byte-identical, with its five sentences as the record of what that packet decided:

- `Fixed added-diagnostic ceilings are20MiB/process,1024bytes/record,100000records`
- `Existing32MiB outer ceiling stays unchanged`
- `do not echo up to20MiB of metadata through pytest traceback`
- `Keep nested420/local750/trusted900/workflow15min,32MiB outer output ceiling, both full replays and all inherited skips`
- `Keep all53 commands,420/750/900s,15-minute and32MiB limits`

MET-PERF-028's authority and MET-PERF-038's records stay byte-identical, and every packet YAML's "32 MiB outer output ceiling" sentence stays true. `limits.json` lists them as `historicalLimitRecords`.

## What the layer checks

`scripts/validate_diagnostic_caps.py` reads repository bytes only through `reviewed_bytes`, binds every input by digest and checks: the three constants and the derived scan limits against `limits.json`'s "after" values; that nothing else in `ci/pytest_diagnostics.py` differs from 27c5460, by canonical hunk; the live pin; the 32 MiB ceiling, the reserve and `MAX_PROCESS_BYTES + reserve <= 32 MiB`; and every historical record. Executed once each from this era's bytes, with a counting sink, at full size:

1. profile W at 22,874 tests completes, and at 22,875 fails with OUTPUT_LIMIT and exit 1;
2. profile S at 23,333 completes, and at 23,334 fails with EVENT_LIMIT;
3. `summarize_nested` reports COMPLETE on a stream of exactly `MAX_SCAN_BYTES` and `MAX_SCAN_LINES` (W's stream padded with non-diagnostic lines), INPUT_LIMIT one byte past, and SCAN_LIMIT one line past;
4. control: the base module (27c5460's bytes, through this layer's own inverse) fails profile R at 16,306 tests with OUTPUT_LIMIT.

Measured at build time by the packet builder, in one fresh process, with the layer's own executed-check code under the repository venv's interpreter, the one the verify runs (CPython 3.12.14), at a 1-minute host load average of about 5.8 on 18 CPUs: 3.81 s and a peak RSS of 214.4 MiB for the whole set. Mutants run at small scale with the caps rewritten, and every check has a failing test.

## Owner decisions (verbatim)

Q-253-DIAG, 2026-10-20, selected "(a) ci/ cap packet first (Recommended)":

> Monitor: owner decision Q-253-DIAG (2026-10-20, via the lane monitor), verbatim: "(a) ci/ cap packet first (Recommended)". Record it verbatim and dated.
>
> What that means:
> - A small ci/ packet takes harness-onion slot 253, before I06-RBAC-V4. It raises the diagnostics caps in ci/pytest_diagnostics.py (bytes, events and the derived scan limits) and updates its bound tests and pins, with tests/test_diagnostic_repair.py's digest of the file as one of them. Follow MET-PERF-038's precedent.
> - MET-ENFORCE-039 moves to slot 254. You re-run its mechanics on the new merge, then the light checks, a delta packet review, the pre-check and the dry run.
> - You own both packets. Choose the new packet's id (a MET-PERF-04x presumably) and tell me.
>
> Gate material under D5a: ci/ needs the owner's transport approval of the exact PR head, and a per-PR merge approval. The review records need the D5a fields; this is a contract change, so include an oracle outside the candidate.
>
> Size the new caps from a measured projection rather than a guess. Use 253's 63.log counts (48,918 starts and ends, about 219 B per record), add headroom for N future packets, and state N. Also check that every consumer of these limits stays consistent: summarize_nested, test_build_and_predecessors.py, and the parallel suite's per-worker sinks, if they apply.
>
> Flow: plan and contract, then review, build, packet review, pre-check and dry run on my word, then the PR. I prepare the owner's approval command, and the verify runs after it. Light work may start now. D2's re-sim and delta r4 continue.

Q-DIAGCAP-SIZE, 2026-10-20, selected "(A) Stay under 32 MiB (Recommended)":

> Monitor: owner decision Q-DIAGCAP-SIZE (2026-10-20, via the lane monitor), verbatim: "(A) Stay under 32 MiB (Recommended)". Record it verbatim and dated.
> - Size the caps under the verifier's 32 MiB OUTPUT_LIMIT, with no root change: MAX_PROCESS_BYTES 30 MiB, MAX_EVENTS 140k, MAX_SCAN_LINES 154k, MAX_SCAN_BYTES derived.
> - State the headroom (about 9 to 22 packets) and the reserve for all other output (2 MiB).
> - Name CHAIN-COMPACTION-001 as the structural follow-up.
> Write PLAN r2 with C1-2..C1-7, then contract review r2 (fresh, D5a fields). Light work, go ahead.
