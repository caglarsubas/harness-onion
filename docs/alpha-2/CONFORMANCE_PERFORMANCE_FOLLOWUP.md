# Alpha 2 — performance accounting and profiling follow-up

Approved continuation 2026-09-10. MET-PERF-003 publishes source authority only;
CONF-PERF-002 is a separate product packet, branch and PR. Catalog148 preserves
all146 earlier packet YAML byte-for-byte. Thirteen repos/four planes/sixteen
harnesses are unchanged. Neither blocked draft13 nor draft12 is a prerequisite
merge. Accepted product main remains9df7dd7f2df8ac64096ef37d8df259761947d552,
tree1310cc74cc0ed39cfeb1068e998a0f78502a4be4,127 files/327 tests.

## Retained diagnosis; no performance claim

MET-PERF-002 source gates closed at meta28144028cc1aae0453a752c273cccd7b30b3debe
(PR111). CONF-PERF-001 draft13 remains unaccepted at0b71be2e967ef217584733ccfd00b8d4c5f1699f.
Its prior9333be8c3c4e2e07ce46b63d309e946063addb6a/activation143 ran83 tests
successfully, then87 Linux tests with one error and one failure. Trusted elapsed
245.706785708 seconds; logcb97cf23c2f619d5ea07d16fadc497530c188545b0bfb16195d44246b343a2f6.
The permitted Linux test edit was still directly pinned by two non-owned consumers.

Restoring that test at0b71be2/activation144 let all first-five suites pass170
tests; backend freshly collected173 but did not finish before the unchanged
900-second trusted limit. Wrapper elapsed900.922808459 seconds; log
fec0b1cbe8e5e67978674d664f3c6313c7fca3b0c52a1ec775059c5eb7358958.
No final module profile, backend completion or final two campaign commands.
Samples3.2122713340213522,3.228328875033185,3.208423124975525 seconds shared
result digestbc73cd3ec5c69705dbde5bd15e2f9def320744d44e5b9e48985c59cdc384ba8b.
They are PARTIAL_DIAGNOSTIC_ONLY, not a matched accepted baseline or speedup.
Function attribution remains NOT_YET_MEASURED. Required CI34473478954/job102858596674
was CANCELLED_QUEUED_NO_RUNNER_NOT_PASS, runner_id0, zero uploaded artifacts.
Keep both failed logs and all earlier003 failure history; do not retry unchanged.

## Exact eight-path product authority

CONF-PERF-002 supersedes the unaccepted001 dispatch only;001 YAML and its
six-path authority stay immutable historical evidence. Start a new product
branch from accepted9df, not either draft. Prior draft13 is a reference for our
own unaccepted implementation, not an accepted source checkpoint. Preserve all
327 inherited identities and behavioral bodies; append new tests only to the
existing supervisor module. No new product file. The other119 files stay exact.

The original six paths retain their region/interface/byte/append bounds:
private crypto _add only; successor validate_composition/verify_repository plus
bounded pure proof helper; the one Linux-inventory accounting method; backend
validate_checkpoint and exact HELPER_SHA256; three supervisor accounting regions
plus appended tests/profiling; append-only linux-boundary document. All decoding,
scalar multiplication, sign/verify, roles/scope/validity/revocation and public
semantics remain unchanged. No signature acceptance cache or new dependency.

Two additional regions are exact fixed source templates, not broad edit grants:

| Path | Sole region and required bridge |
|---|---|
| tests/platform/linux_baseline/test_packet_scalars.py | ScalarIntegrityTests.test_two_exact_source_transformations_preserve_all_other_bytes: call the fixed helper's performance_current(ROOT), then pass independently validated historical bytes to unchanged check_edit; every original assertion and fixture remains |
| tests/platform/linux_baseline/test_successor_inventory.py | SuccessorInventoryTests.test_original_106_file_and_150_test_history: validate current source first, then replace only the final checksum assertion's current-disk operand with verified historical_sources[path]; expected historical checksum and every other assertion remain |

The pinned record contains exact before hashes and complete after-region strings
for both. Initial measurement uses these exact bridges too; partial or arbitrary
region alternatives fail. Preserve the old check_edit implementation unchanged.
No fixture rewrite, fake current inventory, changed checksum, monkeypatch,
hidden collection, skip/xfail, test-body rewrite or widened filesystem exemption.

Consumer graph closure must be tested end-to-end as data and actual collection:
91-file original Linux guard -> scalar exact-edit consumer -> successor history
consumer -> cumulative106/stage inventory -> backend110 -> supervisor120 ->
custody279 -> credential305 -> accepted127/327 -> actual new tests. All historical
proofs remain validated; reconstructed sources are inert and never executed.
Actual current bytes, nofollow custody, modes, hashes and bounded deltas must
pass before any historical comparison. Fresh six-root AST versus isolated
unittest discovery uses actual disk code, not stored sources. First-five roots
stay exactly170 IDs. Stages110/120/127/135/141/146/151 stay closed and ordered.

## Acyclic source proof v2

Use planeon.conformance-performance-delta/v2 and packetId CONF-PERF-002 bound
to this new authority digest. Same closed fields as v1: schemaVersion,
evidenceClass SOURCE_DELTA_ONLY, packetId, authorityDigest, baseCommit,
sources, newTestIds, beforeSources, documentSuffix. Seven Python rows only:
regions, append, afterSha256, constant. The document has no self-digest.
Exact assembly is pinned original doc + bounded documentSuffix + newline +
harness-performance-source-proof opening fence + canonical JSON + closing fence.
All beforeSources match the eight-path inert snapshot (excluding the doc).
Mode100644 and original region interfaces/prefixes/suffixes remain mandatory.
The two fixed bridges are exact byte alternatives authorized here; every other
test accounting assertion keeps its original AST. The importing helper checksum
must equal actual helper bytes. Scope proof is not crypto or performance approval.

## Lower-overhead investigation, unchanged acceptance workload

Do not infer that profiling caused all of the timeout: attribution is incomplete.
First inspect observer/source-accounting overhead. The fixed next configuration
is cProfile.Profile(subcalls=False, builtins=True), default timer, around the
entire supervisor module via setup/teardown plus failure cleanup. It retains
per-function call counts, self and cumulative times for crypto _add,
_scalar_mult, sign, verify and builtins.pow; caller-edge tables are not required.
Report module wall time and the exact configuration. Restore previous profiling
state on normal/exceptional teardown; unsupported prior state is measurement
unavailable, never a bypass. No profiling thread, signal handler or change to
trusted termination. No production monkeypatch or test selection.

One optional cumulative getstats snapshot at the end of the ordinary fixed
workload test may retain partial diagnostics without disabling/restarting the
profiler. Mark it PARTIAL_DIAGNOSTIC_ONLY and complete=false. Do not call
create_stats mid-run (it disables profiling). Partial observations never satisfy
the full-profile decision gate, reset a retry budget or establish acceptance.

Within one source-proof invocation, parsing already-custodied bytes once and
reusing that local immutable data is permitted. Every invocation must re-read
and validate current custody/bytes/digests, all historical proofs and exact
test discovery where required. No result cache across calls, fixture memoization,
cached signature decision, skipped negative, omitted history or source-execution
shortcut. Actual profiling should distinguish proof-processing from arithmetic
where possible; source inspection alone cannot choose the optimization.

Run all eight unchanged commands, zero product skips, with original crypto for
a new COMPLETE baseline. All327 plus all appended tests must execute. Same
observer, tests and fixed workload must run before and after. Existing partial
samples do not substitute. Fixed seed9d61b19d...cae7f60, messages0/1/32/1024 of
byte0x61, two repetitions of public_key/sign/valid verify/tampered-message verify,
three consecutive samples; assert results and emit deterministic result digest,
interpreter/platform, source/recipe SHA, sample identity and warm/cold definition.

Only a COMPLETE actual inherited profile confirming material _add/pow cost may
permit the same bounded private arithmetic optimization. Keep separately written
affine reference, locally available independent RFC8032 vectors and malformed,
zero-denominator, extreme/unreduced/negative coordinate parity. Preserve existing
signature rejection semantics; an unrelated security finding is a separate issue.
Candidate median <=0.85 matched baseline median; full candidate local and LOCAL
exact-main trusted elapsed <=750 seconds. No wall-clock correctness assertion.
If the full baseline still exceeds900 or attribution is insufficient, retain the
failure and stop for diagnosis; do not enlarge a timeout, run a subset or claim
an algorithm justified by an incomplete profile.

Independently reseal malformed source/proof mutations in negative tests: a wrong
helper pin, collection override, changed assertion, outside-region edit or forged
before string must fail its intended invariant, not merely a stale after digest
or stale document JSON. Check exact eight paths, old bodies/IDs, duplicates,
oversize, symlink/hardlink/nonregular/modes and premature future stage paths.

## Execution and roadmap

MET-PERF-003 runs all25 cumulative meta commands and both existing full replays;
new data-only tests never import/execute/profile product code. Validate every
exact reversible catalog/history recipe, all146 original YAML,148 packets and
164 YAML files. Preserve existing nested-isolation-owned skips; no new skip.
Source locks and existing authority records remain immutable.

Product eight-command recipe, nested420/trusted900/workflow15-minute bounds,
signed deny-all tree and credential-free ephemeral localhost runner remain.
No admin prompt/key creation/root-policy change, hosted compute, cloud, paid API,
downloads, mutable artifacts, telemetry default or uploaded artifact.
Local head, required localhost CI, green-only merge and independent LOCAL
exact-main are separate. At most one unchanged retry; failed history retained.

| Phase | ID / gate | Status at publication |
|---|---|---|
| Phase0 / Alpha1 | Foundations | DONE_RECORDED; runtime separate |
| Alpha2 | MET-PERF-002 / PR111 | DONE_SOURCE_GATES |
| Alpha2 | CONF-PERF-001 / draft13 | BLOCKED_UNACCEPTED; retained, superseded dispatch |
| Alpha2 | MET-PERF-003 | ONGOING authority publication |
| Alpha2 | CONF-PERF-002 | WAITING; separate product run |
| Alpha2 | CONF-LIVE-003 / draft12 | WAITING; separate exact-checkpoint reconciliation after repair |
| Alpha2 | CONF-LIVE-004/005/006 | WAITING |
| Alpha2 | Native AMD64/ARM64 | NOT_RUN_ENV_UNAVAILABLE |
| Alpha2 runtime / Alpha3 / Alpha4 | Runtime / governed actions / enterprise release | WAITING |

Alpha2 ONGOING; effort transition NOT_DUE. Source, CI, artifact, deployment,
native/runtime, assurance and tenant acceptance remain separate. Roll back an
unconsumed publication as a reviewed unit; after consumption use a bounded
successor. Preserve both draft/failure histories, trust/replay/nonces and tenant data.
