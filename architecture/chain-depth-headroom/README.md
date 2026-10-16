# Chain-depth headroom (PERF-040, MET-PERF-040)

Status: **SOURCE_CANDIDATE_ROUND2_AWAITING_INDEPENDENT_REVIEW** (brief: `REVIEW_BRIEF.md`). 2026-10-16. Slot 241, on main
`d2ef708` (240 packets). Record: `record.json`. The owner's and the monitor's decisions are quoted there verbatim.

## Why

Slot 240's verify took 994 s of the 1200 s cap, and pytest alone took 689 s. The owner decision PERF-040-FIRST puts this
packet before I05 v4 (slot 242) and LIC-HOST-A2 (slot 243), with the aim of giving back several hundred seconds.

Measured on `d2ef708` (`record.json` "measurements"; DATA_CHECK_ONLY local runs on a loaded host):
- **The chain walk.** Every projection to an older era re-reads, and byte-compares, every newer layer's authority. That is
  the exact-freshness rule decided at PERF-033 and PERF-035, which stays (Q-PERF40-2). One suite run makes 15.2 million
  authority reads, 9.3 TB in all. 31% of the test time is the reads alone.
- **Repetition.** 71% of the 12.4 million `historical_bytes` calls repeat an identical input inside the same test.
- **Growth.** Each new authority is about 70 KB larger than the last, now 1.5 MB, because the authority builder records
  whole changed lines. Each packet's chain bump rewrites the composed validators' long successor lines, two about 12 KB
  lines per validator. Every projection reads every newer authority, so each packet adds that whole size to every walk.

## What changes

Four changes, each decided (record "ownerDecisions"):

1. **Test-local exact sharing (Q-PERF40-1 (a)).** A new `tests/conftest.py` adds a function-scoped autouse fixture.
   - **What it shares.** Within one test, every loaded `validate_*` module's `historical_bytes` is memoised by its
     exact positional arguments, when each one is a `str` or `bytes` value (type and value by equality). Any other
     call reaches the real function. Every distinct input, each mutation included, still reaches the real projection.
   - **Refusals.** A refusal raises and is never memoised.
   - **Bound to one test.** A wrapper shares only while its own test is active. Outside it, a wrapper is inert and calls
     the real function. After the test, every wrapper is replaced by its real function in each module the test wrapped,
     and in every `validate_*` module first imported during the test, which may have bound a wrapper at import. A
     function that is already a wrapper is never wrapped again. The fixture is torn down after monkeypatch's teardown.
   - **What does not change.** No validator's freshness rule changes (Q-PERF40-2 (a)): every route of every validator
     still reads its authority fresh. The only validator edit in this packet is the check order of change 4. The root
     `conftest.py` (the CI diagnostics) is unchanged.
   - **Never shared.** Fifteen test-function names are never shared (`NEVER_SHARED`; record
     "testSharing.neverShared", each with its reason). Fourteen are the tests that fail when sharing is applied to every
     test (run M3): they exist to prove freshness, or the identity of these functions (Q-PERF40-1). The fifteenth passes
     under sharing, but its closing validation must stay fully fresh: it already shares through PERF-031's helper
     (source review round 1, S1-3). The two largest exist under the same name in every layer's test file, so a later
     layer's tests are covered by name.
   - **Measured, with caveats.** Run M3 applied the out-of-tree prototype to every test:
     - The summed test time fell 44% (3,074 to 1,708 s), and the wall time 41% (644 to 377 s at six workers).
     - The 1,537 failures there are the never-shared tests.
     - The prototype wrapped in the call phase only, and it shared the never-shared tests too. With those unshared, the
       expected cut is about 40%.
     - M3's host load was lower than the baseline's (8.2 against 11.1).
     - Peak tree memory rose 23% (2,737 against 2,218 MiB).
2. **Byte-minimal authority hunks (Q-PERF40-4 (a)).**
   - **The rule.** The operator-side authority builder writes canonical byte-minimal reverse hunks, computed from each
     changed file's current and base bytes (record "authorityHunks.algorithm"):
     - a line diff (`difflib`, no autojunk) of the two;
     - a changed run with the same number of lines on both sides is split per differing line pair;
     - every run keeps only the bytes that differ at its start and end;
     - a run that would touch the previous one is merged into it, so hunks stay strictly ordered, with at least one
       unchanged byte between them.
   - **Effect.** Every layer's hunk parser already accepts these (ordered, disjoint byte ranges with canonical base64).
     Recomputed on 240's own change, the hunk payload falls from 1,453 KiB to 165 KiB. No repository code changes for
     this.
   - **Guard.** This packet's layer recomputes the canonical hunks of every file its authority changes, from the base
     and current bytes, and refuses its authority unless the recorded hunks are exactly those. This takes about 0.3 s
     for 240's 188 files.
   - **Carried rule.** Every later packet's layer does the same for its own authority, because later authorities stay
     small only while their hunks stay canonical.
   - **Limit.** The parsers accept at most 4,096 hunks per file. The builder stops with an error rather than write
     more; no file comes close so far.
3. **Weights refresh (WEIGHTS-REFRESH; Q-PERF40-3 keeps six workers).**
   - **The new weights.** `ci/parallel_suite_weights.json` gets M3's per-file seconds for all 127 test files. 25 of
     them had no weight before.
   - **One scaled weight.** `tests/test_selinux_matrix_v3.py` is scaled by the replay reorder's measured effect.
   - **Planned effect.** With the planner's own rule on M3's per-file times (the matrix file's time scaled like its
     weight), the busiest of six workers falls from 357.4 s (old weights) to 274.2 s, against an even split of 274.0 s.
   - **Approval.** This is a `ci/` change, so the owner approves the exact head.
4. **Replay order (P2-1).**
   - **The change.** `replay_v5_vectors` in `scripts/validate_selinux_matrix_v3.py` (239's layer) runs the v4 vectors'
     identifier and position checks before the replay loops. The requires and messages are unchanged.
   - **The test change.** Two faults of `tests/test_selinux_matrix_v3.py::test_every_vector_replays` move to the first
     vectors v5 adds (C1780, M56), so that the replay, not the position check, still refuses them.
   - **Measured.** The file falls from 41.7 s to 17.7 s, serially with sharing. The finding is quoted in the record.

The packet adds a new history layer that bridges 240's layer. 240's carried P1-1 (bridge the `reviewed_tree` and
`reviewed_mode` hooks by hand) is not triggered: nothing is added under `architecture/compiled-filter-programs-v2/`, and
no contract file's mode changes.

## Not claimed

- No freshness rule changes, and the worker count stays six.
- The local runs are evidence for the decision, not the CI result. The packet's own dry run and verify measure that.

## Source review round 1: findings and dispositions

| Finding | Disposition |
|---|---|
| S1-1 MAJOR, sharing leaked past its test | Wrappers are inert outside their own test; teardown unwraps every wrapper in the wrapped modules and in every `validate_*` module first imported during the test. The reviewer's three reproductions now leave no wrapper behind, and `tests/test_credential_lifecycle.py` passes on its own |
| S1-2 MINOR, double wrapping | A function that is already a wrapper is never wrapped again; unwrapping follows `__wrapped__` to the real function |
| S1-3 MINOR, a missing never-shared test | `test_each_locked_input_is_checked_and_unknown_or_missing_files_refuse` added, with its reason |
| S1-4 MINOR, a weaker minimality check | The rule is now a canonical algorithm, and the guard recomputes the hunks and requires equality |
| S1-5 MINOR, planner figures | Restated with the planner's own rule: 357.4 to 274.2 s (even 274.0 s) |
| S1-6 MINOR, "no validator changes" | Now "no validator's freshness rule changes", and the P2-1 edit is named |
| S1-7 MINOR, M3 caveats | The prototype's scope, the lower load, the expected cut of about 40% and the memory rise are stated here and in the record |
| S1-8 NOTE, other tests failing before the mechanics | The brief now names every layer test that pins the weights or 239's validator |
| S1-9 NOTE, the predecessor test's reason | Corrected in the record; the owner's entry is kept as a guard |
| S1-10 NOTE, the 4,096-hunk limit | Stated under change 2 |
| S1-11 NOTE | Confirmations; no change |
