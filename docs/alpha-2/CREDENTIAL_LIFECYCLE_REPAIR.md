# Bounded credential lifecycle — MET-REPAIR-012 / CONF-FIX-005

Alpha 2 · approved 2026-09-09 · source-only authority.
140 packets, thirteen repositories, four planes, sixteen harnesses.

## Verified checkpoint and diagnosis

Meta main 7447acd1a0471cecb79da36abe6b4ff0859f0a92 published MET-REPAIR-011.
Conformance PR10 merged CONF-FIX-004 at
0aa3ef3027f4a156d7ebed1b56af244e021d080a, tree
332d823a750828cfa345cf9332a2a251d6503d15: 127 files / 305 tests.
Local head, required localhost CI34251687066 and independent local exact-main
passed all eight commands with zero skipped tests. This publication reuses
those recorded source gates; it does not rerun product acceptance.

The correction successfully retains original authority/kit bytes. A remaining
source-level integration conflict concerns later credentials: the registry is
sealed before isolation/reservation completes; read rejects new files after
seal; peer checks reject every handle outside authority, four fixed runtime
handles and the child channel/pidfd. There is no owned late-credential slot.
Keeping a credential descriptor across fixed operations therefore conflicts
with that ambient guard. Opening it early, reopening it on each call, silently
editing the sealed registry or adopting arbitrary descriptors is forbidden.

Classification: SOURCE_INSPECTION_ONLY. No runtime exploit, native operation,
credential read or newly failed product test is claimed. The previous handoff
tests use a data-returning fixed-hook adapter, not an actual credential lifecycle.

The newest three source-accounting regions also bind the current 127-file stage
and current proof directly. Their cumulative adaptation is explicitly owned
below; behavioral tests and existing test identities must not be rewritten.

## One source correction, exact ownership

CONF-FIX-005 owns the same five existing files; no new product path or stage:

| Path | Bounded change |
|---|---|
| src/harness_conformance/live_linux_boundary.py | Only named resource ownership/ambient/cleanup regions and appended private helpers |
| src/harness_conformance/live_supervisor.py | Only named fixed-hook/context/lifecycle regions and appended private helpers |
| tests/live_backend/test_linux_boundary.py | Complete old byte prefix; append new regressions/helpers |
| tests/live_backend/test_supervisor.py | Only three named source-accounting regions; all other bytes preserved; append regressions/helpers |
| docs/live-backend/linux-boundary.md | Complete old byte prefix and both old proof fences; append report and separate credential proof |

The machine record lists exact qualified source regions and pins before bytes.
No whole-file exemption. All 122 other files are unchanged by this correction.
Keep all 305 old IDs and every behavioral assertion body. Source append consists
only of definitions, not top-level imports, rebinding, monkeypatches, decorators
or executable defaults. Use local stdlib imports and existing pinned helpers;
Python 3.12.14/toolchain/dependencies remain unchanged.

The sealed initial registry is not made writable. Its original trusted bytes,
descriptor set, ancestry, read-once rules and digest checks remain immutable.
No credential enters the kit, release tree, public source proof or child process.

## Separate owned resources and ordering

1. The actual NativeSupervisor and its fixed _NativeChannel alone create and
   own the private late-resource lifecycle. Bind exact owner, process, thread,
   active session, nonce, endpoint, capacity, profile and absolute deadline.
   Serialized objects, subclasses, handles from another owner, flags and raw
   descriptor numbers never create eligibility.
2. Begin credential acquisition only after complete installed authority, all
   three valid signing roles, durable reservation, established kernel boundary
   and required independently current policy. This correction does not invent
   that policy proof: absence of the fixed proxy or its required observer/admission
   prerequisite remains NOT_RUN_ENV_UNAVAILABLE. The proxy owns authentication,
   TLS/profile validation and policy observation under unchanged MET-REPAIR-009/010.
   No caller callback or always-true observation token can satisfy those checks.
3. Derive the single campaign-client credential reference from the verified
   CAMPAIGN_PROXY entry and capacity/profile. There is no path/endpoint/backend
   parameter or generic file opener. Reject references already captured as public
   authority/kit bytes; credentials cannot be smuggled into early custody.
4. Open root-owned 0400 PEM and full ancestry no-follow exactly once. Bound one
   credential to 256 KiB, ancestry to 64 components and total persistent extra
   descriptors to 66. Retain exact verified bytes and descriptor/named-inode
   identities until session termination. No silent trust/enrollment refresh.
   Cryptographic identity and PEM validation are the fixed proxy's responsibility
   before any use; custodial bytes alone are not authentication.
5. Expose only fixed internally created temporary resources needed by that
   proxy: at most one signed numeric-family TCP transport and one Linux memfd
   simultaneously. The memfd is non-inherited, bounded by credential size, sealed
   and closed after TLS context loading. No FD adoption, arbitrary socket family,
   generic URL, descriptor list or ambient enumeration as authorization.
   The later proxy still owns exact IP/TLS identity, TLS1.3, framing and deadlines;
   the ownership primitive cannot authorize network traffic by itself.
6. Preserve complete peer/authority/revocation/expiry checks before and after
   blocking operations. Ambient validation recognizes only the exact owned
   credential ancestry and current temporary handles after checking their
   provenance/type/identity/liveness; every other descriptor still refuses.
   Read-only public authority snapshots never become mutable allowlists.
7. On normal hook return, close every temporary I/O handle before accepting the
   receipt, but retain verified credential custody for the next distinct fixed
   operation. Reject reuse of an operation, context or nonce. Check current
   authority/credential metadata again before the next call without reopening.
8. On failure, expiry, cancellation, close or partial acquisition, invalidate
   first, attempt all owned cleanup and preserve the first failure. One close
   owner per descriptor; no retry of a released/recycled descriptor number.
   Cleanup cannot resurrect a consumed nonce or declare clean when unproven.
   Child fork/exec closes all these handles and receives no credential bytes/path.

State accounting: ABSENT -> ACQUIRING -> RETAINED; RETAINED may enter one
IO_ACTIVE hook and return to RETAINED after transient cleanup. Any state may
terminate CLOSED or FAILED, with no transition out. These labels are internal
lifecycle descriptions, never a wire capability or a replacement for native gates.

## Cumulative proof without historical rewriting

Keep the historical 127-file/279-ID and corrected 127-file/305-ID checkpoints
separately. The original harness-custody-source-proof is an immutable historical
proof; never relabel its reconstruction as actual corrected source.
Append exactly one canonical harness-credential-source-proof fence with schema
planeon.internal.credential-source-delta/v1 and SOURCE_DELTA_ONLY. It binds this
authority, packet digest, exact corrected before snapshot, checkpoint, scoped
source/test-region replacements, append bytes and all new test IDs. Bounds are
128 KiB per replacement, 1 MiB per append and 2 MiB for the complete proof.
No self-referential document hash; external commit/tree evidence binds it.
No snapshot/proof source is imported, compiled or executed.

Only these source-accounting definitions may be adapted in test_supervisor.py:

- CustodySourceProofTests.inputs
- CustodySourceProofTests.test_actual_127_path_inventory_preserves_other_122_complete_file_bytes
- CustodySourceProofTests.test_original_279_methods_and_every_added_method_are_freshly_collected

The adaptations must independently verify actual correction bytes against the
new bounded delta before returning any historical view to the unchanged old
oracle tests. Actual inventory checks use current bytes, not the historical
view. Preserve every other method, ID and assertion exactly. New regressions
prove that failure in either historical or current proof cannot be bypassed.

Exact source stages stay 110/120/127/135/141/146/151. For each future stage use
only the original approved path sets; CONF-LIVE-003/004/005 add their exact
eight/six/five paths. CONF-LIVE-006 adds its five new paths and only its already
approved live_launcher.py delta. Composition must verify that original delta,
not silently exempt the launcher. This correction may change only its five paths.
Do not loosen a current source hash merely because a later filename is present.

For tests compare independent AST enumeration and fresh unittest collection
across all six suite roots. Preserve 305 prior IDs and every newly appended
method. Later tests must come from exactly the new test paths of the declared
stage and be fully collected, with no load_tests, duplicate/shadowed method,
skip, xfail, narrowed pattern or excluded suite. Historical counts are minima
within exact identity sets, never a reason to discard new tests.

## Required regressions and dispatch

Meta tests inspect inert data only: closed authority/pins, before-source hashes,
allowed regions, immutable prefixes/fences, altered proofs, every old test ID,
exact stage paths and current-versus-historical source accounting. Synthetic
data passes do not demonstrate the product correction or native resource custody.

Product tests must exercise the real factory-to-fixed-hook lifecycle with OS
observations mocked only inside the signed offline tree: two successful distinct
operations and one credential read; transient cleanup; retained metadata drift;
forged/foreign/forked owners; unlisted FD injection; early acquisition; exhaustion;
short read; cancellation/expiry during I/O; close errors and recycled descriptors.
No actual credential, socket, certificate issuance, native isolation or probe run.

| Phase | ID / gate | Status at publication | Next result |
|---|---|---|---|
| Phase 0 / Alpha 1 | Recorded foundations | DONE source/offline | Live acceptance separate |
| Alpha 2 | MET-REPAIR-011 / CONF-FIX-004 | DONE source gates | Retained 127/305 checkpoint |
| Alpha 2 | MET-REPAIR-012 | ONGOING | This authority, eighteen commands |
| Alpha 2 | CONF-FIX-005 | WAITING | Five-path correction, eight commands |
| Alpha 2 | CONF-LIVE-003 | WAITING | Consume corrected source closure |
| Alpha 2 | CONF-LIVE-004/005/006 | WAITING | Probes, packaging, integration |
| Alpha 2 | Native AMD64 / ARM64 | NOT_RUN_ENV_UNAVAILABLE | Independent installation and qualification |
| Alpha 3 / Alpha 4 | Governed actions / enterprise matrix | WAITING | Existing roadmap unchanged |

Every coding packet has independent local/head, required self-hosted PR CI,
merge and local exact-main gates. No product edits/execution occur in this meta
publication. No root install/policy/key, administrator prompt, hosted runner,
dependency download, artifact upload, cloud provisioning or paid API is authorized.

Retain previous 420-second nested-test timeout failures and unchanged retries.
Timing stability remains UNRESOLVED. One bounded unchanged retry may be recorded;
never relax timing, coverage or isolation to make a status green.
Before consumption revert a publication/correction as separately reviewed units;
after consumption use a successor, retaining signed history, failed logs, nonce
reservations and tenant data. Alpha 2 ONGOING; effort transition NOT_DUE.
