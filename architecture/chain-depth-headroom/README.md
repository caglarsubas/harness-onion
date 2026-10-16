# Chain-depth headroom (PERF-040, MET-PERF-040)

Status: **SOURCE_CANDIDATE_ROUND1_AWAITING_INDEPENDENT_REVIEW** (brief: `REVIEW_BRIEF.md`). 2026-10-16. Slot 241, on main
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
   - **Refusals and restoring.** A refusal raises and is never memoised. The real functions are restored after the
     test, after monkeypatch's own teardown.
   - **What does not change.** No validator changes (Q-PERF40-2 (a)). Every route of every validator still reads its
     authority fresh. The root `conftest.py` (the CI diagnostics) is unchanged.
   - **Never shared.** Fourteen test-function names are never shared (`NEVER_SHARED`; record
     "testSharing.neverShared", each with its reason). They are the tests that exist to prove freshness, or the identity
     of these functions, and they are exactly the tests that fail when sharing is applied to every test (run M3). The
     two largest exist under the same name in every layer's test file, so a later layer's tests are covered by name.
   - **Measured.** Run M3 applied this sharing to every test: the summed test time fell 44% (3,074 to 1,708 s) and the
     wall 41% (644 to 377 s at six workers). The 1,537 failures there are the never-shared tests.
2. **Byte-minimal authority hunks (Q-PERF40-4 (a)).**
   - **The rule.** The operator-side authority builder writes byte-minimal reverse hunks:
     - a changed run of equal line counts is split per line;
     - every run keeps only the bytes that differ;
     - runs that would touch are merged, so hunks stay strictly ordered, with at least one unchanged byte between them.
   - **Effect.** Every layer's hunk parser already accepts these (ordered, disjoint byte ranges with canonical base64).
     Recomputed on 240's own change, the hunk payload falls from 1,453 KiB to 165 KiB. No repository code changes for
     this.
   - **Guard.** This packet's layer refuses its own authority unless every hunk is minimal (no common first or last byte
     while both sides are non-empty; at least one unchanged byte between hunks).
   - **Carried rule.** Every later packet's layer checks the same of its own authority, because later authorities stay
     small only while the builder does.
3. **Weights refresh (WEIGHTS-REFRESH; Q-PERF40-3 keeps six workers).**
   - **The new weights.** `ci/parallel_suite_weights.json` gets M3's per-file seconds for all 127 test files. 25 of
     them had no weight before.
   - **One scaled weight.** `tests/test_selinux_matrix_v3.py` is scaled by the replay reorder's measured effect.
   - **Planned effect.** On M3's own times the busiest of six workers falls from 346 s (old weights) to 285 s (an even
     split).
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
