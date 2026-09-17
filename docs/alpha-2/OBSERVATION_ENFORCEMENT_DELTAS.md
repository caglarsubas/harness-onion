# Published observation delta proposal

[Publication status](OBSERVATION_ENFORCEMENT_PUBLICATION.md); no runtime authority.

# Candidate observation delta register

Alpha 2 / OBS-ARCH-DESIGN-001. Design-only, non-dispatchable. Read-only source
subject: failed candidate 14f922b5fd262f10e3c836847a9dd18a4706dee4, not accepted
main. Every proposed cadence change below is **UNAPPROVED / PROOF_REQUIRED**.
Nothing in this document edits, executes or supersedes CONF-FIX-010.

## Source boundaries and candidate split

All symbols are in `src/harness_conformance/live_proxy_server.py`. Lines refer
to that exact source revision, not a future diff.

| ID | Existing boundary | Proposed treatment, not an implementation | Lost-window proof needed |
|---|---|---|---|
| D01 | `_Files.check`, line2310: fresh fstat/named-stat/inheritance with exact field/comparison order | Preserve this leaf behavior and every invocation required by the retained local owner guards; do not memoize rows | None selected for removal; E01/E02/E09 remain mandatory |
| D02 | Native `_tick`, line329, and `_kernel_inspection_tick`, line287: exact native custody, dynamic owner dispatch, fresh original phase deadline | Preserve per-leaf tick locations and original fresh clocks; owner dispatch must not trigger a full snapshot recursively under a separately adopted contract | D03's change is not equivalent to the current full dynamic dispatch trace |
| D03 | Self `_reader_tick`, line2663: dynamic `_tick`, reader ownership, authority/session/window, then root/epoch/root unless already sampling | Retain local guards at surviving I/O boundaries and dynamic observer/broker checks; candidate moves the whole root/epoch/root resampling responsibility to an explicit coordinator | E03-E06 host stability is necessary but insufficient: every removed nested tick also removes E01/E02/E07-E09 observations; map those lost opportunities explicitly, never claim preserved counts/cadence |
| D04 | Root `_reader_mounts`, line718: owner guard, original pins, native root reads and deadlines | Preserve complete before/after root samples when invoked; candidate removes recursive full snapshots from inner owner dispatch, not root identity observations inside the sample | E03 proves intervening mount/namespace changes are excluded; E02/E08 local checks remain fresh |
| D05 | Policy `_reader_epoch`, line1286: retained mapping/FD custody, status-mount/status/status-mount, post custody | Preserve sample content, both mount brackets, native fence behavior, errors and sticky failure; no stale policy-open reuse | E03/E04 prove skipped between-leaf global resamples redundant under the new contract; not proof of unchanged trace |
| D06 | `_observe`, `_checked`, `_own` and constructors, lines2721 onward and earlier role factories | Candidate coordinator explicitly brackets each fixed component observation and applicable acquisition boundary; keep fresh policy checks surrounding component sequence | Exact startup/partial-initialization schedule and full caller map REQUIRED before any code; these functions are outside CONF-FIX-010's seven-symbol scope |
| D07 | Observer/broker `_tick`, lines2869/3003: original sockets/pidfds/path/credentials/liveness and surrounding custody | Preserve dynamic role-specific checks and no observer transport recursion | E07/E08 events cannot be replaced with a host-update exclusion claim |
| D08 | `_phase`, close/unwind, authority/reservation/credential/effect paths | Preserve original lifetime, no partial construction leaks or transferred close ownership, no credential/effect from observations | No clock renewal, early successful publication, reused-FD close or new grant; C1-C5 unchanged |

The candidate coordinator is not specified as a new public/private API, callback,
daemon or token. No new function name or invocation is executable authority. Its
exact closed call graph, bootstrap sequence and paths are a successor design
prerequisite. In particular, 'at phase boundaries' is not precise enough to code.

This proposes reducing **global resampling amplification**, not removing fresh
local file/owner/clock/peer guards at surviving boundaries. Removing a whole
sample nevertheless removes its nested custody/peer/time checks too. Keeping
`_Files.check` unchanged is not proof that its prior temporal coverage survives.
The successor must enumerate those indirect removals, prevent their mutation
windows or retain the needed observations, and explicitly justify event/lifetime
refusal timing. An E03/E04 proof alone cannot discharge E01/E02/E07-E09. Thus the
14 GuardCostObservationTests can and must retain their leaf-level assertions,
but passing them would not prove schedule equivalence. Whether the complete
implementation fits the unchanged acceptance limit remains unmeasured.

## Concrete mutation windows to resolve

| Case | Old detection opportunity | Proposed obligation |
|---|---|---|
| W01 | Mount/policy altered after native fstat, restored during subsequent fcntl; intervening native tick can reject | Independent active E03/E04 exclusion must prevent the change throughout the component, or retain the original global observation; sampling two endpoints alone fails |
| W02 | Authority file or stored custody pin changes during a root/epoch sample | Retain fresh `_Files.check` and owner/pin comparisons with original short-circuit/exception behavior; no 'sampling' flag may skip them |
| W03 | Status mount replaced while mmap still exposes matching bytes | Retain both status-mount brackets and original descriptor/path checks; additionally prove E03 for every global resample removed |
| W04 | Peer exits or its socket path is replaced during component I/O | Keep original dynamic peer ticks before/after; independent effect denial handles stopped server/worker; no reconnect |
| W05 | Revocation/expiry while a Python read is blocked | Original deadline/authority checks reject returned bytes; external admission closes independently; no lifetime renewal from a completed snapshot |
| W06 | Root/kernel view temporarily changed during bootstrap before epoch_ready | Independent Layer E must already exclude that mutation; a later successful epoch sample cannot retroactively establish bootstrap safety |
| W07 | Partial acquisition gets a real FD then its post-guard fails | Retain original close owner and unwind exactly once; never close a reused or caller-substituted descriptor |
| W08 | Cgroup/filter/code changes after qualification but before an effect | Actual external E05/E06/E10 enforcement denies/invalidates the effect; repeated observations alone do not enforce exclusion |

For each affected real leaf call, a successor must resolve both entry and exit
windows, exceptions, interrupt/unwind paths and the relevant bootstrap state.
Do not infer that these eight representative scenarios exhaust all call sites.

## Inherited test traceability

Source-only reading; no import, AST collection, test discovery or test execution.
All names below are in `tests/live_backend/test_proxy_server.py` at the exact
failed predecessor. Keep unchanged behavior unless an explicitly reviewed
successor maps an affected temporal assertion to prevention/refusal evidence.

| Existing identity / group | Design treatment |
|---|---|
| `GuardCostObservationTests` (line13902, all14 methods) | Preserve all, including syscall/field order, repeated fresh metadata, transient-path refusal before restoration, exception identity, pin rereads and comparison truthiness; D01 unchanged |
| `KernelPolicyCustodyTests.test_fresh_policy_open_each_check_retains_only_fixed_kernel_views` | Preserve fresh policy semantics; no retained-open policy snapshot as fresh evidence |
| `KernelPolicyCustodyTests.test_policy_epoch_change_during_read_refuses_even_if_hash_would_match` | Preserve detection if observed; changed scheduler additionally needs enforced exclusion of previously detected unobserved windows |
| `KernelPolicyCustodyTests.test_status_path_replacement_during_fence_is_detected` | Retain actual status-path and original custody checks; E03 needed for any reduced surrounding cadence |
| `KernelRetainedEpochTests.test_changed_even_epoch_refuses_and_cannot_be_restored` | Preserve sticky invalidation; never reopen a failed lifetime |
| `KernelRetainedEpochTests.test_epoch_change_during_fence_is_rejected` | Preserve sample integrity and fence semantics |
| `KernelRetainedEpochTests.test_already_busy_native_phase_is_not_reentered_or_renewed` | Preserve original phase and deadline; coordinator cannot renew nested work |
| `KernelRetainedEpochTests.test_mapping_substitution_closes_only_original_mapping` | Preserve exact cleanup ownership |
| `KernelEpochMountTests.test_samples_mounts_without_new_descriptors_mappings_or_policy_opens` | Preserve sample's fixed reads and no new-resource behavior |
| `KernelEpochMountTests.test_same_inode_status_bind_mount_is_not_hidden_by_retained_mapping` | Preserve mount identity, not byte/inode-only equality |

This is not an exhaustive 1,655-test migration map. No old validator/proof pin is
changed and no test is declared obsolete here. The final map must additionally
cover owner composition, actual startup factories, resource/zero-resource flows,
source accounting, worker/cleanup/terminal cases and the complete C1-C7 review.

## Go/no-go condition

Proceed to runtime implementation only when every D03-D06 directly or indirectly
removed observation has a reviewed W-case closure backed by exact active
enforcement or preserved fresh checks, including autonomous-event timing,
all unaffected local assertions remain enforceable, and an exact successor
packet explicitly adopts the changed temporal contract. Otherwise the outcome
remains BLOCKED_SAFE_DESIGN, not a failed retry or an increased timeout.
