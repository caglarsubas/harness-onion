# Retained custody handoff — MET-REPAIR-011 / CONF-FIX-004

Alpha 2 · approved source-only correction · 2026-09-08.
138 packets; thirteen repositories; four planes; sixteen harnesses.

## Finding and bounded decision

At conformance main 7205075d2f234b622dd61072803b754f1dffeb79, the supervisor
verifies trust, capacity, release and the complete kit, then returns a context
without the verified trust/release/kit bytes or their retained file identities.
read_owned and read_owned_kit close their descriptors; InstalledContext retains
only selected parsed data, a kit digest and a separately reopened rootfs FD.
The fixed proxy hook is imported only when execute is called, after that loss.
CONF-LIVE-003 cannot reconstruct the original custody without reopening files.

This is SOURCE_INSPECTION_ONLY, not a reproduced exploit or a failed product
test. Prior 279-test source/CI/exact-main passes remain historical evidence;
they do not demonstrate this missing cross-component handoff.

The approved correction does not relax read-once custody. MET-REPAIR-011 owns
this authority publication; CONF-FIX-004 owns the later product correction.
One packet, branch and PR per coding run. No product edit/execution in meta CI.

## Exact product ownership

CONF-FIX-004 changes only these five EXISTING paths:

| Path | Permitted change |
|---|---|
| src/harness_conformance/live_linux_boundary.py | Named custody regions and appended internal retained-custody helpers |
| src/harness_conformance/live_supervisor.py | Named custody lifecycle/context/handoff regions and appended internal helpers |
| tests/live_backend/test_linux_boundary.py | Append new test classes/helpers; original bytes unchanged |
| tests/live_backend/test_supervisor.py | Append new test classes/helpers; original bytes unchanged |
| docs/live-backend/linux-boundary.md | Append correction report and source-delta proof; original bytes unchanged |

The machine record lists exact qualified region names and pins their original
source bytes. Outside those regions, preserve the complete original byte stream.
New helpers are append-only definitions, not module-level execution, rebinding,
monkeypatches or imports of stored source. Use existing imports or local imports
of Python 3.12.14 standard-library modules and existing pinned conformance helpers.
No new dependency or interpreter/kernel/toolchain setting.

All 122 other product files remain byte-identical. No historical test, helper,
baseline fixture, packet, Makefile/dispatcher, workflow, source lock, PORTING or
public schema changes. The original 279 test IDs and every existing assertion
remain; appended tests add coverage, never replace it. The historical 120-file
baseline fence in linux-boundary.md remains intact and unique.

This is an in-place correction of stage two, not a new source stage. The exact
path sets and counts remain 110/120/127/135/141/146/151. Preserve the original
127-file/279-ID checkpoint as history; publish the corrected checkpoint with
its actual new commit/tree/hashes/test count. Never overwrite the historical
baseline or claim its hashes describe the corrected bytes.

## Retained-custody lifecycle

1. Before any selected reference, verify fixed installed identity and both
   envelope signatures, then verify independently signed capacity. Preserve
   all existing role/scope/digest/validity checks and first-read ordering.
2. Open each authority/reference once with no-follow semantics. Retain immutable
   verified bytes and owned file/directory identities through the session.
   Include installed manifest/key/signature/executable, both trust stores,
   capacity, release, packet, campaign, bundle and signed kit members. Bound
   file count, depth, bytes and descriptors; exhaustion fails closed without
   changing process resource limits or admitting a partial custody set.
3. Keep read_owned/read_owned_kit legacy call/return contracts for existing
   consumers. Their data or cached digest alone cannot create a native lease.
   A native-owned custody registry must establish and validate every retained
   handle; no optional caller FD, path allowlist, flag, callback or mock branch
   grants authority. Existing unit tests may mock OS I/O but not production
   eligibility. No security check may be skipped because an attribute is absent.
4. NativeSupervisor alone constructs the context, binds its owner/process and
   active kernel-bound session, and transfers the retained verified material.
   The proxy consumes original release/profile/CA/observation-binding bytes;
   it does not reopen the kit. Borrow the retained verified rootfs directory
   handle instead of a second path lookup. Define one close owner for every FD.
5. Recheck each retained descriptor and named inode plus the complete ancestor
   chain: identity, file type, owner, mode, link count, size and change metadata.
   Reject replaced ancestors, renamed/rebound files, altered bytes/metadata or
   stale/revoked/expired trust. Validate all three signer windows/roles again
   before each operation and after blocking I/O. Never silently refresh files.
   Wall and monotonic deadlines cannot move backwards or extend signed expiry.
6. Preserve ambient-FD denial. An internal registry may account only for its own
   currently verified non-inherited handles, never an external FD list. Forked
   campaign children close every authority descriptor and receive no authority
   paths or bytes; the verified rootfs/channel remain their only required inputs.
7. Invalidate custody before releasing it on partial construction, reservation
   failure, boundary failure, cancellation, expiry, terminal operation or close.
   Attempt all remaining cleanup after a close error; preserve the failure and
   consumed nonce. Never double-close a recycled FD, resurrect a session, or
   report completed cleanup when it is unproven. Handle repeated close safely.

This correction does not implement the proxy client/server, observers, policy
fencing, kernel isolation redesign or probes. Credential opening still belongs
to CONF-LIVE-003 and occurs only after reservation/isolation and the required
current policy observation. Retained data cannot attest actual server containment.

## Required regressions and evidence

Use explicit unit fixtures with native OS operations mocked inside the signed
offline tree. Do not run actual live argv, native isolation, network or credential
access. Cover the native factory-to-fixed-hook path, not only an isolated data
container. Source/data success remains UNIT_VERIFICATION_ONLY.

- One first read per authority/kit member; no reopen at handoff or next operation.
- Original verified bytes and rootfs identity survive through the fixed hook.
- Every trust/manifest/reference/file/ancestor substitution and signer expiry
  refuses before side effects, including after a blocking operation.
- Caller/foreign owner/subclass/serialized/forked/closed contexts and ambient
  descriptor injection never enter production; forged signatures never select paths.
- Descriptor exhaustion, short/failed reads and initialization failure close
  all already-owned handles without a partial session or reopened fallback.
- Success, failure, cancel, expiry, repeated close and cleanup-error matrices
  retain nonce history, close each owned descriptor once and preserve failures.
- All 279 predecessor methods and original assertion bodies remain collected;
  no skipped, expected-failure, hidden or deselected cases in any of six roots.

Append exactly one bounded canonical JSON fence named harness-custody-source-proof
to the existing product document. Bind the authority digest, packet digest,
original checkpoint, two source-region deltas, test byte prefixes and added
test IDs. Include the 127-file baseline and before bytes needed by the appended
independent source guard. The proof is SOURCE_DELTA_ONLY; it is neither installed
custody, a trusted signer, code-safety approval nor permission to execute its text.
Never import/compile/execute proof or snapshot code. No self-referential document
hash: external commit/tree evidence binds the final document bytes.

The meta oracle checks closed region/prefix rules and negative synthetic data.
The later product source guard verifies the actual corrected files, original
127-file inventory and fresh AST-versus-unittest collection inside all six roots.
Use exact original definitions/byte intervals, never remove assertions or accept
arbitrary whole-file hash exemptions. Final product changes still require review
and all eight offline commands; static delta validation does not prove behavior.

## Dispatch, acceptance and rollback

| Phase | ID / gate | Current state | Meaning |
|---|---|---|---|
| Phase 0 / Alpha 1 | Recorded foundations | DONE source/offline | Live acceptance separate |
| Alpha 2 | MET-REPAIR-010 | DONE source gates | PR104 main108e619; both exact-main attempts retained |
| Alpha 2 | MET-REPAIR-011 | ONGOING publication | This bounded authority; no product fix yet |
| Alpha 2 | CONF-FIX-004 | WAITING | Five-path retained-custody correction |
| Alpha 2 | CONF-LIVE-003 | WAITING | Requires correction source/local/CI/merge/exact-main closure |
| Alpha 2 | CONF-LIVE-004/005/006 | WAITING | Probes, packaging, integration |
| Alpha 2 | Native AMD64 / ARM64 | NOT_RUN_ENV_UNAVAILABLE | Independent operator installation and qualification |
| Alpha 3 / Alpha 4 | Governed actions / enterprise matrix | WAITING | Existing DAG and acceptance gates unchanged |

CONF-LIVE-003 keeps its eight paths/eight commands. Its fixture must bind both
historical 127/279 and the actual corrected predecessor via the approved delta,
not insist that superseded files still have old hashes. CONF-LIVE-005 packages
the corrected custody implementation; CONF-LIVE-006 consumes its retained
context and must not reopen references in its final bridge. Original YAML and
public wire/signature roles remain unchanged; this dispatch addendum is explicit.

Meta authority acceptance: seventeen declared commands, local/head, required
self-hosted PR CI, merge and independent local exact-main. Product acceptance:
eight declared commands and the same separate source gates in its own run/PR.
Neither confers installed/native/runtime/assurance/tenant acceptance.

The previous 420-second nested-test timeout and unchanged successful retry remain
recorded. Timing stability is UNRESOLVED. One bounded unchanged retry may be
recorded on the same terms; never relax a timeout, skip coverage, weaken isolation
or mix an unrelated performance fix into this custody authority.

Before consumption revert the publication/correction as separately reviewed
units. After consumption use a reviewed successor; retain both checkpoints,
failed logs and immutable trust/replay/tenant data. No install, new key, root
policy change, cloud action, hosted runner, paid API, download or artifact upload.
Alpha 2 remains ONGOING; model-effort transition NOT_DUE.
