# Cumulative source-inventory repair — MET-REPAIR-008

Publication checkpoint: 2026-09-08. This guide is source authority, not a product
test result, signed installation permit, Linux qualification or tenant acceptance.
The current catalog has 134 packets, thirteen repositories and sixteen harnesses.

## Diagnosis and preserved evidence

Conformance main `8519225b1564834fab5bcd001c263688e6fba7fe` passed 150 tests,
zero skips and seven commands in local/head, required PR CI and separate local
exact-main. It contains 106 tracked files. PR 7 / CI 34137197794 remain valid
source-checkpoint evidence; the preceding meta authority is PR 101 at
`c526ccaa293b2113032c5a5b4a037e35baacb196`.

Subsequent SOURCE_INSPECTION_ONLY found that
`tests/platform/linux_baseline/test_packet_scalars.py` freezes its whole path
inventory to the historical 103 plus three scalar-correction additions.
CONF-LIVE-001's ten allowed paths are disjoint: 106 + 10 = 116, which violates
that equality. Its original-file hash guard also conflicts with CONF-LIVE-006's
already-declared final launcher hook. Zero product tests were executed for this
diagnosis; it must not be described as a reproduced product test failure.

The earlier conclusion that the session packet was ready to resume is withdrawn,
not the actual 150-test PASS. Preserve draft PR 6 at
`57ee9668e029b08310c57f502990e419b4a1c797`, its original pre-test parser refusal,
and cancelled CI 34115040866 as CANCELLED_NOT_PASS. The current blocker is separate.
Detailed checkpoint digests and historical raw inventories are pinned in the
amendment and [development status](../DEVELOPMENT_STATUS.md).

## Ownership and dispatch order

1. MET-REPAIR-008 owns this additive meta publication and data-only validator.
   All 132 existing packet YAML and architecture/legal/policy/release files
   remain exact (170 protected files). Preserve old authority records verbatim.
2. After source/local/required localhost CI/merge/local exact-main closure,
   execute CONF-FIX-003 alone from accepted conformance main in its own branch/PR.
3. Only after that correction closes the same gates, resume CONF-LIVE-001 and
   reconcile its inventory within its existing ten paths. Do not rewrite its
   signed YAML, six-root/eight-command acceptance or predecessor history.
4. Continue the six backend packets one per run/PR. Native qualification and
   runtime coding retain their separate, unchanged prerequisites.

This publication neither implements nor executes product source. The two source
snapshots are inert byte strings: never import, compile, eval or execute them.
The new pure validator compares metadata, byte regions and fixed hashes only.
It is a test oracle, never a launcher or an authorization service.

## Exact product correction: one existing file, four new files

| Path | Scope |
|---|---|
| `tests/platform/linux_baseline/test_packet_scalars.py` | Exactly three pinned hunks; preserve all thirty method IDs and every other byte |
| `tests/platform/linux_baseline/_successor_inventory.py` | New test-only real repository inventory helper and pure composition verifier |
| `tests/platform/linux_baseline/test_successor_inventory.py` | Exactly twenty independent regression methods listed in the amendment |
| `fixtures/platform/linux-baseline/successor-inventory.json` | Immutable 106-file/150-ID baseline, original 103/120 history, stage paths and proof bindings |
| `docs/reports/successor-inventory-repair.md` | Separate source, local, CI, merge, exact-main and unavailable runtime evidence |

Hunk one delegates only the frozen inventory test body to the new strict helper.
Hunk two adds the exact twenty test IDs to cumulative expected collection.
Hunk three corrects the inventory diagnostic to predecessor150 + added20.
The whole resulting file must hash to
`e1491e4407ff6d221871b45bbd775beb28afba11d418ae001847a512bb4b6fe6`.
The before hash, unique before/after blocks and sequential prefix/suffix hashes
are authoritative in `architecture/successor-inventory-amendment.json`.

No change to the parser, original Linux hash guard, production launcher,
Makefile, command dispatcher, workflow, toolchain or PORTING ledger is allowed.
The existing 150 tests must actually run, without skip/xfail/deselection, alongside
the twenty new tests: 170 at this correction checkpoint, zero skips. Future
backend tests remain separately accounted in the declared sixth suite.

## Complete cumulative stages

| Stage | Last complete packet | New paths in this stage | Total tracked files |
|---:|---|---:|---:|
| 0 | CONF-FIX-003 | 4, plus one exact existing-file change | 110 |
| 1 | CONF-LIVE-001 | 10 | 120 |
| 2 | CONF-LIVE-002 | 7 | 127 |
| 3 | CONF-LIVE-003 | 8 | 135 |
| 4 | CONF-LIVE-004 | 6 | 141 |
| 5 | CONF-LIVE-005 | 5 | 146 |
| 6 | CONF-LIVE-006 | 5, plus one proved launcher change | 151 |

Counts supplement exact path sets, never replace them. The amendment pins each
original packet's bytes and exact allowed paths. Accept one complete ordered
prefix only; reject every missing/extra/duplicate/path traversal, partial stage,
out-of-order stage, altered predecessor hash/size/mode, symlink, hardlink,
nonregular file or linked ancestor. Existing production bytes stay fixed except
the already-owned final hook. New source files are non-executable mode 100644.

`verify_repository(root)` must derive rows from actual tracked files, not trust
caller-supplied rows, environment flags, a filename's presence or a claimed
stage. Reject fixture tampering and duplicate JSON members before use. Retain
actual AST/collection agreement for all predecessor and correction IDs; colliding
module names require fresh child collection within the same isolated process
tree. Empty roots, load_tests filtering, substituted modules and silent omissions
must refuse. Pure synthetic vectors do not replace this real-repository check.

## Closed final launcher source proof

Stages 0–5 require the entire original launcher and no hook proof. Stage 6
requires exactly one `harness-launcher-source-proof` fenced JSON block in the
already-owned `docs/live-backend/qualification.md`. This is SOURCE_DELTA_ONLY,
not a signature, execution permission or code-safety certification.

Closed string-only fields: `schemaVersion`, `evidenceClass`, `packetId`,
`packetSha256`, `path`, `beforeSha256`, `prefixSha256`, `suffixSha256`,
`replacement`, `afterSha256`. Schema is
`harness.planeon.ai/launcher-source-delta/v1alpha1`. Packet identity/digest and
the original launcher/context hashes are fixed in the amendment. Refuse extra,
missing, duplicate, mistyped, oversized or mismatched fields.

Only the terminal ISOLATION_BACKEND_UNAVAILABLE raise after unchanged
`_verify_root_manifest()` and `preflight(...)` is replaceable. Preserve every
prefix/suffix byte. Replacement must differ, be nonempty ASCII, at most 8192
bytes, end with LF, contain no CR/NUL and keep each nonempty line indented by at
least eight spaces. Proof is at most 16 KiB, its document at most 256 KiB.
The complete result must equal exact prefix + replacement + suffix and its
claimed result digest. A fabricated proof cannot exempt arbitrary old files.

Source-region checking does not validate the semantics of replacement code.
CONF-LIVE-006 still owns review and independent negative/runtime tests, while
actual execution remains manual post-merge through the separately installed
root-owned live launcher, independent release/tenant signatures, capacity
authorization, endpoint isolation and server-side zero-cost admission.

## Verification and evidence boundaries

MET-REPAIR-008 runs all fourteen declared direct-argv acceptance commands only
through the unchanged installed signed offline launcher. No prefetch commands,
new dependencies, runtime downloads, warm-source reads, hosted runners,
artifact uploads, root modifications or administrator prompts are required.
Meta tests cover all seven complete stages and missing-path, old-byte/mode,
malformed inventory, hook-proof, packet-grant and immutable-authority mutations.
Synthetic stage-six replacement strings are inert unit data, never live code.

CONF-FIX-003 later runs its exact seven declared commands through the same
approved mechanism and records actual170/zero-skip results. The six successor
packets keep their exact eight commands. Source/head, local acceptance, required
PR CI, merge, local exact-main, artifact/build, installation, native Linux,
runtime, assurance and tenant acceptance stay separate. Unavailable native
AMD64/ARM64 evidence is NOT_RUN_ENV_UNAVAILABLE, never PASS.

## Rollback and next handoff

Before consumption, revert an unaccepted amendment as one reviewed unit; after
consumption, issue a bounded corrective successor. Never erase historical
hashes, test IDs, failure logs, activation/replay history or tenant data. Do not
resume the unaccepted draft on a stale base or amend consumed signed packet
bytes. The next product run must recheck exact main and predecessor evidence.
Alpha 2 remains ongoing; no phase-end model-effort transition is due.
