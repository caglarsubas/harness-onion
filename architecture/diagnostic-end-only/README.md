# END-only pytest diagnostics (MET-PERF-043)

Alpha 2A; 2026-10-29. Evidence class `SOURCE_DELTA_ONLY`. The 270th packet, on accepted main `925debee` (269 packets).
Owner decision Q-DIAG-CAP: "END-only, own PERF packet (Recommended)"; slot order MON-SLOT-270-PERF.

## Why

EDGE-V12's Mac dry run (slot 270 before this packet, head `d3d62951`) failed at argv 63 with 23,454 passed and 0 failed:
the outer pytest's diagnostics stream (`ci/pytest_diagnostics.py`) ended `incomplete` with `EVENT_LIMIT`. Version 1
wrote six records per test (START and END for setup, call and teardown), and `MAX_EVENTS` is 140,000, so a suite fitted
at most 23,333 tests. The byte cap (`MAX_PROCESS_BYTES`, 30 MiB) sits inside the owner's verifier ceiling of 32 MiB for
the whole run (MET-PERF-041), so raising `MAX_EVENTS` alone would have failed on `OUTPUT_LIMIT` at 23,588 tests.

## The change

One module, every cap unchanged (`MAX_EVENTS` 140,000; `MAX_PROCESS_BYTES` 30 MiB; `MAX_RECORD_BYTES` 1,024;
`MAX_NODE_CHARS` 65,536; `MAX_FAILURES` 16; `MAX_SCAN_LINES` and `MAX_SCAN_BYTES` derived as before). Records become
version 2:
- `start()` keeps every check and the active phase in memory and writes nothing;
- `end()` writes one END record, with `label` exactly when `outcome` is not `passed`; the label comes from the END's own
  node identity, so computing it never raises; an `end()` with no matching phase fails closed with PHASE_ORDER exactly
  as in version 1 (the producer stops and the END is dropped);
- an UNFINISHED_PHASE ERROR names the active `node`, `phase` and `label`;
- the reader (`summarize_nested`, summary `planeon.pytest-diagnostic-summary/v2`) accepts version 2 only, pairs nothing,
  never reports PHASE_ORDER, and checks SESSION_END's `starts` against its `ends`.
The full record and reader rules are the design's Appendix A, which the D5a oracle `tests/test_met_perf_043_oracle.py`
was written from; `architecture/oracle-identity-met-perf-043.json` binds it.

## Headroom

The real module, a counting sink, a pinned clock (0.012345 s per call), three phases per test; the last passing count:

| Profile | Bytes per test (boundary test) | Last passing | Binding cap |
|---|---|---|---|
| Version 1 (before; the mean over 1,000 tests) | 1,316 | 23,333 | EVENT_LIMIT |
| Version 2, every phase `passed` | 638 | 46,666 | EVENT_LIMIT |
| Version 2, call failed and teardown error, 70-character labels (worst case) | 800 | 39,514 | OUTPUT_LIMIT |

At 270's 23,454 tests that is 23,212 tests of headroom for a passing suite (about 68 packets at 270's +337) and 16,060
in the worst case. The design estimated 625 and 787 bytes per test; the measured values are higher by the digits `seq`
and `tUs` gain at large counts (CONTRACT r1 NOTE C1-1); the counts and caps are as designed.

## Time

This packet buys no time headroom. EDGE-V12's dry run took 1,478 s at a mean 1-minute load of 11.2, against 969.96 s
at 8.4 for slot 269; both segments slowed by about 1.5 times, so the load explains it. The verify relies on the lane
monitor's load-aware override and a quiet host.

## Consumers

`conftest.py` and `ci/parallel_suite.py` are unchanged (their calls are the same). The predecessor fallback reads a
nested stream of the same tree's producer. MET-PERF-021's tests and `tests/test_diagnostic_repair.py`'s live pin
follow the new module; MET-PERF-041's record (`architecture/diagnostic-caps/`) stays byte-identical, and its pins of
the old module are kept for its era through this packet's history-chain layer.

## Residual

- **R-P43-KILL:** a hard kill (no `finish`) no longer names the running test in a serial run: a plain serial pytest,
  the parallel suite's parent nodes (three tests, among them the in-session predecessor proof), and the predecessor
  fallback's timeout record. The worker replay loses nothing. Recovery: the last END's node digest and phase, with the
  collection order, give the next node, since the digest is the sha256 of the node id. Accepted by design review r1.

## Non-claims

No cap, verifier, argv or acceptance change; no runtime speed-up claimed; nothing installed.
