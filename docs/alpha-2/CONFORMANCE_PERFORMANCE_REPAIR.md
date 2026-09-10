# Alpha 2 — conformance performance repair

Approved 2026-09-10. MET-PERF-002 publishes authority only.
CONF-PERF-001 is a separate product run, branch and PR. No product source is
edited or executed by this publication. Thirteen repos/four planes/sixteen
harnesses remain unchanged; catalog146 includes both new packets.

## Evidence, diagnosis and limits

Accepted meta main3f52d53 (PR110, MET-REPAIR-015) closed source gates.
Accepted product main9df7dd7f2df8ac64096ef37d8df259761947d552,
tree1310cc74cc0ed39cfeb1068e998a0f78502a4be4, has127 files/327 tests.
Draft CONF-LIVE-003 PR12 is not complete and must not merge as a prerequisite.

Diagnostic head7b36fd6ac272d9b41d5f65ab8e4e153ab5eb621c passed all
eight local commands,385 tests/zero skips under signed activation137.
Log SHA256:931a1f6725e110e7735d6bc7d284d9677c6654184c33a4fac183b8020177975b.
Suite times: meta37/3.974s, parity14/0.007s, alpha1 9/0.006s,
runner23/0.070s, Linux87/228.973s, backend215/637.429s.
Their sum870.459s is not wrapper wall time. New58 test bodies took1.428649s
(admission20/0.187756s, client16/0.016731s, server22/1.224162s).
That excludes full import cost and does not attribute cost to a crypto function.
Historical accepted327-test sum861.866s was not a controlled comparison.

Prior4175299 local385 passed, but required run34436974320 had two
CANCELLED_NOT_PASS attempts. First produced all summaries during cancellation;
second exceeded the trusted900-second bound before backend completion.
Log hashes: dace28997696c613ba1891a1281dab400c8342f740cff20ee2d86124bd00151a
and390be265d66636cb8588ac19b34dd1fb0a392db2ac366ce5fd6b91075e106de6.
Diagnostic run34455818636 was cancelled queued, runner_id0; not CI acceptance.
Earlier2e1623d failed11 inherited fixtures from new-test import leakage;4175299
corrected new-test module/parent-attribute restoration. Keep that failed record.
Instrumentation does not count as a timing fix or reset an unchanged retry budget.

Inherited suites dominate measured execution. Inspection identifies repeated
pure-Python signing/verification and affine modular inversions as a candidate.
Function-level attribution is NOT_YET_MEASURED. No algorithm is selected here.

## Fixed investigation and decision gate

Start CONF-PERF-001 at accepted9df7dd7, not draft003. Keep crypto unchanged for
the initial full signed eight-command run. Add observational cProfile module
setup/teardown only in the supervisor test module, around its complete existing
tests; report crypto _add, _scalar_mult, sign, verify and builtins.pow call counts,
self/cumulative seconds and module wall time. Restore previous profiler state
even on failure; unsupported profiler state means no measurement, not bypass.
No production monkeypatch, selecting tests or running historical code.

Also add an ordinary discovered test for a deterministic workload: fixed existing
RFC8032 seed9d61b19d...cae7f60, messages of0,1,32,1024 bytes (byte0x61),
two repetitions of public_key, sign, valid verify and tampered-message verify
per message, three consecutive samples. Assert results; emit durations and
a deterministic digest of all results. No timing assertion in unit tests.
Record interpreter/platform, source SHA, recipe SHA, sample identity, warm/cold
definition, all samples and wrapper elapsed. The same new tests/instrumentation
must run before and after; counters are observations, never cached acceptance.

Only if the actual inherited profile confirms private affine arithmetic as the
material cost may _add be optimized. Otherwise stop and report the evidence.
The allowed candidate is pure integer arithmetic in that function only;
a broader coordinate-system/scalar/decoder redesign needs separate authority.
Require median matched fixed-workload time at most0.85 of the unoptimized
median, and complete candidate local and independent LOCAL exact-main trusted
elapsed at most750 seconds. These are repair evidence gates, not relaxed
timeouts or portable performance promises. Required localhost CI must be green.
If measurement overhead or remaining cost exceeds current limits, keep the
failure and diagnose; do not raise limits or run a selected subset.

## Exact product source scope

The machine record and inert before-source snapshot pin six existing paths.
No seventh file, fixture rewrite, new dependency or file-count stage is granted.

| Existing path | Only permitted changes |
|---|---|
| src/harness_conformance/crypto.py | _add body, at most4096 bytes; same name/args/annotation, all other bytes unchanged |
| tests/platform/linux_baseline/_successor_inventory.py | validate_composition and verify_repository source-accounting regions; append bounded independent data-only performance proof helper |
| tests/platform/linux_baseline/test_linux_inventory.py | Only test_original_files_are_unchanged_except_ten_authorized_integrations accounting region: validate actual crypto delta before historical blob comparison; preserve every original comparison |
| tests/live_backend/_inventory.py | Exact HELPER_SHA256 update to actual current helper and validate_checkpoint accounting region; verify before import |
| tests/live_backend/test_supervisor.py | Only SupervisorPredecessorTests.test_immediate_120_file_216_id_checkpoint_and_older_stages_are_immutable, _credential_inputs and _credential_repository accounting regions; append independent tests and profiling hooks |
| docs/live-backend/linux-boundary.md | Original bytes unchanged; append bounded performance note and one canonical proof fence |

The121 other files, all327 old identities and all behavioral test bodies and
parameter cases stay unchanged. Legacy accounting assertions must still compare
every old mode, length, SHA and Git blob to exact reconstructed predecessor
bytes, after checking actual current bytes/digests/delta. Never normalize
unchecked bytes or report a reconstructed snapshot as current discovery.
No new tests in the first five suite roots: their170-ID exact inventory remains
valid. Append only to supervisor's already-extensible sixth suite.

All historical scalar, custody, credential and final-hook proofs remain checked.
For historical credential proof checking, validate the new performance delta
first, reconstruct9df predecessor test/helper/document bytes as inert data, then
run the old data proof against that exact predecessor. For current collection,
use actual current AST plus fresh isolated unittest discovery, union all327
predecessors with exactly the new appended test IDs. Never execute a stored
source string, monkeypatch a validator or replace current behavior with snapshots.

Stage sets/counts remain110/120/127/135/141/146/151; no partial, extra,
out-of-order, linked, duplicate, mutated or arbitrary future source paths.
The existing pure stage-vector tests must still work without a performance
proof against historical rows; a changed row requires a complete validated
proof and actual changed bytes. Filename or proof presence alone never grants
an exemption. Original crypto is permitted during the profile-only candidate;
final repair needs a measured effective change and complete parity.

## Source proof, acyclic binding and independent tests

Five Python rows use closed fields regions, append, afterSha256, constant.
Region keys exactly match the record; replacement preserves function interface,
prefix/suffix, test identities and every non-owned byte. Each append is bounded.
constant is null except the sole imported helper checksum, which must equal
the actual current helper SHA. Mode stays100644. New append cannot define
load_tests/run/discover or introduce skip/expected-failure collection behavior.

One SOURCE_DELTA_ONLY proof contains schemaVersion,
evidenceClass, packetId, authorityDigest, baseCommit, sources (the five Python
rows), newTestIds, beforeSources (five exact inert predecessor Python strings),
and documentSuffix. The document has no self-digest and is assembled exactly:
pinned original document + bounded documentSuffix + newline + opening
harness-performance-source-proof fence + canonical proof JSON + closing fence.
The meta oracle checks against the separately pinned full product-before input.
The product helper may carry only the approved compact scope/checkpoint pins
and this pure reconstruction logic; old source strings are data only.
No self/circular digest, caller-selected oracle, unchecked after hash or
whole-file wildcard exception. The helper's own delta is validated as current
source by independent appended regressions and pinned by the importing helper.
This proof establishes scope, not algorithm correctness or performance.

Independent new behavioral cases must cover:

- Existing RFC8032 empty-message output, additional locally available independent
  published vectors, unchanged deterministic public keys/signatures and mutation
  refusal. Do not fetch vectors inside acceptance or use an external service.
- A separately written affine reference over fixed valid points, identity,
  repeated additions, extremes, negative/unreduced coordinates and both zero
  denominators. It is test-only mathematics, not imported historical source.
- Invalid public/signature lengths, S>=L, y>=Q, noncanonical sign encoding,
  small-order points, altered R/S/message, canonical payload fields, role/scope,
  validity and revocation. Preserve existing rejection behavior; any discovered
  security-semantic gap is a separate finding, not silently fixed here.
- Exact source-prefix/suffix and old-body preservation; altered helper pin,
  fabricated proof, unknown region/path, wrong before/after hash, missing/extra
  test, skip/xfail/collection override, duplicate keys, oversized append,
  symlink/hardlink/nonregular/mode changes and premature future stage refusal.
- Fresh independent actual collection across all six roots; no cache, hidden
  test, patched production verifier or mock signature acceptance.

## Acceptance, dispatch and rollback

MET-PERF-002: all24 cumulative commands, both complete meta replays, exact old144
YAML bytes, current146 packets/162 YAML, exact meta source recipes, data negatives.
No product code import/execution; no native syscall/network or key use in oracle.

CONF-PERF-001: same eight product commands, all old plus added tests, zero skips.
Nested420/trusted900 seconds/workflow15 minutes stay fixed for all applicable
runs. Every run uses the signed root-owned deny-all launcher and existing
credential-free ephemeral localhost runner; no admin/root-policy change,
download, hosted runner, paid API, cloud action or uploaded artifact.

Separate local head, required PR CI, green-only merge and independent LOCAL
exact-main gates. At most one unchanged retry, retaining all failures. After
repair source gates close, authorize a separate exact accepted-checkpoint
reconciliation before resuming draft003; its original YAML remains immutable
here. This is an additive dispatch gate, not an assertion that old003's source
pins automatically accept new crypto. Do not combine repair and proxy code.

| Phase | ID / gate | State at publication |
|---|---|---|
| Phase 0 / Alpha 1 | Foundations | DONE_RECORDED; live separate |
| Alpha 2 | MET-REPAIR-015 / PR110 | DONE_SOURCE_GATES |
| Alpha 2 | MET-PERF-002 | ONGOING authority publication |
| Alpha 2 | CONF-PERF-001 | WAITING |
| Alpha 2 | CONF-LIVE-003 / PR12 | WAITING; draft incomplete |
| Alpha 2 | CONF-LIVE-004 /005 /006 | WAITING |
| Alpha 2 | Native AMD64 / ARM64 | NOT_RUN_ENV_UNAVAILABLE |
| Alpha 2 runtime / Alpha3 / Alpha4 | Runtime core / governed actions / enterprise release | WAITING |

Alpha2 ONGOING; effort transition NOT_DUE. Source/data/CI do not establish
artifact, installation, native, runtime, assurance or tenant acceptance.
Before consumption revert a reviewed packet as one unit; after consumption use
a bounded successor. Retain prior failure evidence, immutable trust/replay/nonce
history, original source proofs and tenant data.
