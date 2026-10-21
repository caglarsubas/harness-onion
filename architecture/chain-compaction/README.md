# Chain compaction (MET-PERF-042, CHAIN-COMPACTION-001)

The 255th packet compacts the history chain's test scaffold where the cost report shows no loss of a required check, and
makes the identity rule a standing rule (owner decision PA-D9 (D9a); plan CHAIN-COMPACTION-001 revision 11; owner
decisions Q-CC-1 (b), Q-CC-2 (a), Q-CC-3 (b), Q-CC-IDENTITY (a), Q-CC-6 (a), Q-CC-B4 (a), Q-CC-F1 (a), Q-CC-F2 (a) and
F3, all in `decisions.md`).

## What changes

- **C2, in the 63 bridged scaffold test files (slots 192-254).** In each file, only two tests change and every test
  function name stays:
  - `test_newest_authority_is_freshly_checked_on_every_route` keeps its 8 own routes and the adjacent predecessor's
    route (slot L-1). Its guarded `old_X` setup lines and its route table stay as they were. 2079 route nodes leave
    the suite, and each dropped (L, X) route has a twin with identical input in the head's fan-in.
  - `test_every_predecessor_payload_is_checked_without_a_verdict_cache` keeps one mutation (the first sorted baseline
    name). It then checks that the layer's expected-payload table (`_packet_rules()`) holds exactly the baseline names
    and the layer's own packet. Each entry must equal the sha256 of the disk YAML bytes and the sha256 of the canonical
    JSON of the test's own `safe_load` of them, computed by the test's own code, never by the layer's functions (R9).
  The head (slot 255, `tests/test_chain_compaction.py`) keeps the full fan-in: 8 own and 66 predecessor routes, every
  catalog walk and round trip, and the full payload loop. Both explicit blocks (the catalog walks and the round trips)
  failed the payload rule in M1 and are unchanged everywhere.
- **C1, in `tests/conftest.py`.** Test-side YAML parse sharing, one parse per packet YAML per test module, on the test
  module's own `safe_load` binding only. The memo is keyed by the exact argument, so changed bytes get a real parse, and
  every call returns a deep copy. It is never installed in a never-shared test, nor in a test that the conftest's
  static rule finds patching `safe_load`, `ROOT` or the tree. No validator and nothing under `scripts/` changes how it
  reads.
- **The identity rule (PLAN section 3.1).**
  - Items 1-8 are run by `scripts/chain_identity.py` (not a `validate_*` module). The layer loads it from its
    digest-pinned bytes through the era-loader shape (owner decision F3): over its era in `validate()`, and over the
    live tree in `test_identity_rule_holds_on_the_live_chain` on every verify.
  - Item 9, the runtime binding check, runs in `test_runtime_bindings_are_the_frozen_ones_around_a_fan_in_pass`.
  - Both tests are never shared.
  - The head's allow-list admits 372 attribute names, 73 node types and 11 era-loader
    shapes found in 35 layers.
- **The one inherited edit outside C2 (owner Q-CC-F1 (a)).** `tests/test_chain_depth_headroom.py::`
  `test_the_never_shared_names_are_pinned_by_name` now asserts that the live never-shared set equals slot 241's set plus
  the two identity tests above. The function name is kept, and the edit is a canonical reverse hunk.

## The records

| File | What it is |
|---|---|
| `cost-report.json` | M1's cost report (run 20261021T1041): argv 63's cpu-s per test, the generic scaffold, the pairwise tests, the authority reads and the explicit blocks' shares. |
| `fact-map.json` | Every scaffold test with its class (E, G or P) and its instances; for each dropped route, its kept twin and where its fact stays proven; each payload loop's replacement. The layer recomputes it from its era's test files and their previous-era bytes. |
| `identity-rule.json` | The frozen lists of section 3.1, generated from the 66 chain validators at 29c84b36 and the 235-254 steps. It includes the walk forms, G1, G2's positions, D's classes (`historical_bytes` as {192} and {193..head-1}, owner Q-CC-F2 (a)), the bump and bridge vocabularies, the binding names and the head allow-list, with its evidence. |
| `ab.json` | M2, the measured A/B (run 20261021T1516) on the head measured as ed000a8b, with the fix after it summarised (MON-255-TESTSTRING-FIX). B1 0.8187 over all 141 inherited files, its per-run ratios straddling the 0.88 and 0.91 lines; B2 and B3 met; B4 0.6611 (full runs) and its serial figure; walls, loads and spread. B1 and B4 are owner-accepted: "Accept and continue (Recommended)". |
| `seeded-faults.json` | M3, the seeded-fault evidence (run 20261021T1637) on the fixed head. 352 of 559 cases ran under the four approved transforms, and 207 are out of scope by the owner's "Run 352, rest out of scope (Recommended)". Part (i) passed under the monitor's ruling MON-M3-COLLECT-KILL; its six MAX_FILE_BYTES cases are listed as collection kills in both suites. The 18 benign substitutions were refused, and part (ii) passed. |
| `decisions.md` | The owner's and the lane monitor's decisions, verbatim. |

The identity-only mutants of M3 part (ii) (classes I1-I9) exist only as source text in the layer's test. The checker
parses them and refuses each with its named clause; none is imported or executed (owner rule, 2026-10-21). The layer
binds every record by digest and checks each one's closed shape; for `ab.json` and `seeded-faults.json` it also checks
that the numbers agree (B3 against the collected counts; the M3 class totals, the 352 cases run plus the 207 out of scope
making 559, and the six collection kills being exactly the ruled cases) and that the owner's words are present.

## The stated residual (section 3.1 item 10; owner Q-CC-RESIDUAL (a))

The following are not caught mechanically and rest on review:
- bytes executed through `exec` (era models), which rest on their pins;
- the head's own code within its allow-list, which the step rule freezes from the next packet on;
- interposition by a module imported only in another worker, or done lazily at call time.

## C1's exclusion rule: a stated narrowing (packet review r1 P1-4; the lane monitor's MON-255-P1-4-NOTE)

PLAN section 4 says C1 is never installed in a test that patches `safe_load`, `ROOT` or the tree. The conftest's static
rule is narrower: it reads only the test function and the same-module fixtures named in its arguments. It does not
follow a module-level helper that a test calls by name, and it does not look at patches of the YAML parser's state. So
C1 is installed in these 8 tests, which patch `ROOT` or the tree through a helper:
- `tests/test_compiled_filter_programs_v2.py`, `tests/test_compiled_filter_programs_v3.py` and
  `tests/test_lab_run_plan.py`: `test_the_contract_tree_is_read_from_the_checkout` and
  `test_the_contract_tree_is_closed_and_every_file_is_mode_100644` in each, through `_serve_tree(monkeypatch, root)`,
  which patches the layer's `ROOT`;
- `tests/test_sector_catalog.py`: `test_readiness_catalog_semantics_hold_on_the_effective_catalogs` and
  `test_applying_the_deferred_pack_path_gives_exactly_the_bound_packet_error`, through `_readiness_errors`, which patches
  `Path.read_text`.

Five more covered tests, in `tests/test_backend_distribution.py`, `tests/test_license_amendment.py`,
`tests/test_license_amendment_v2.py` and `tests/test_validation_performance.py`, touch the YAML parser's state.

Why no outcome changes: the memo is keyed by the exact argument (its type and its bytes or text). A patched `ROOT` or a
patched read gives the test different bytes, which are a different key and get a real parse. None of these tests calls
the shared binding while the parser's state is patched (packet review r1). Widening the rule would change C1; the lane
monitor carried it as a NOTE, and it is disclosed in the owner's per-PR merge question (owner Q-CC-GATE (a)).
