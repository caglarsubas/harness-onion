# Published design direction — not runtime adoption

See [publication status](OBSERVATION_ENFORCEMENT_PUBLICATION.md). The text below
is an editorial repository rendering of the independently reviewed external design;
that review is not independent acceptance of this rendering or implementation.

# Observation and enforcement boundary: conditional architecture amendment

Date: 2026-09-17. Phase: Alpha 2. Design label: **OBS-ARCH-DESIGN-001**.
This label is not a task-packet ID. Status: **DESIGN_ONLY / RUNTIME_ADOPTION_BLOCKED**.
The independent review outcome and final checkpoint are separate companion files.

## 1. Decision and authority

The user approved an architecture-design amendment and independent security
review after the CONF-FIX-010 design stop. This package proposes a direction;
it does not amend accepted repository authority, authorize execution, or claim
a safe implemented replacement. No product imports, collection, tests,
benchmarks, diagnostics, runner activations, root changes or GitHub writes occur.

**Recommended direction: independently established containment first; bounded,
nonrecursive observation second; separately enforced effect admission last.**
Investigate this as a new versioned temporal contract, not an optimization that
claims to preserve the current observation trace. No check is removed now.

The decision has three gates:

1. Accept the direction for a source-only architecture publication proposal.
2. Close the concrete enforcement and interface proof obligations below, with
   independently reviewed artifacts and an exact successor packet.
3. Only then authorize implementation and reserved full acceptance. Native
   qualification remains a separate installed-target campaign.

An unresolved coverage row prevents reducing its observation schedule. If any
row needed to break the expensive cycle remains unresolved, the whole proposed
schedule is unavailable. Do not silently combine an unproved reduced schedule
with the old implementation or call the result a fallback-qualified profile.

## 2. Exact baseline and problem

- Accepted META main: `be4d79ec050f4d6d13ff9992ce425508b5e246af`, PR133,
  tree `707dffe4171d9e5eaeec563d64abb72cbd419d10`. MET-PERF-017 has separate
  retained LOCAL, required self-hosted CI, merge and exact-main evidence.
- Accepted conformance main: `3a81c8ffb17be9e288c4368d443c57361d5a4fc8`.
- Failed source candidate: `14f922b5fd262f10e3c836847a9dd18a4706dee4`,
  tree `7625f055178b6dfb4eae0ac66b64897cf4dd74e7`; not a product release.
- CONF-FIX-009: both LOCAL slots consumed; second run passed five suites/170
  tests, but the backend suite did not complete. No complete product acceptance.
- CONF-FIX-010 packet SHA256:
  `e4eea58d0f5c18444d23863a1f9179fa183491007f92ce2fa2b92cd2a5cc417f`.
  Its design gate remains STOP_NOT_WAIVE, with zero attempts consumed.

Source inspection found bounded guard amplification, not infinite recursion.
Under the documented successful-path assumptions, one root/epoch/root bracket
contains at least 284 nested native ticks, each repeating retained-file checks.
The resulting lower bound is 852 leaf calls per retained file row, excluding
other work. This is static reasoning, not measured timing or a predicted speedup.
The exact derivation is retained in the prior design-stop package listed in
OBSERVATION_ENFORCEMENT_PUBLICATION.md#sources; no benchmark or repeat execution was performed here.

Today's contract requires custody, authority, clocks and epoch rechecks after
each blocking query. Removing intermediate checks loses detection windows,
including change-and-restore between fstat and fcntl. Existing requirements also
already demand external update serialization. They do not prove that every
currently observed mutation is excluded by an installed mechanism.

| Option | Decision | Reason |
|---|---|---|
| Preserve every observation and reduce pure computation | Remains an admissible alternative | No sufficient candidate has been demonstrated; no speed claim or retry now |
| Cache successful checks or observe only at phase boundaries | Reject as an immediate repair | Misses existing transient-change detection without exclusion proof |
| Enforcement-first, explicitly revised observation schedule | Conditional preferred design | Separates prevention from observation and can remove recursive sampling only when coverage is proven |
| Add an inspector daemon, generic lease or new private grant | Not selected | Introduces authority, interface and bootstrap complexity; separate decision required |
| Raise timeouts or omit tests | Reject | Does not establish safety or a working bounded implementation |

## 3. Threat model and trust boundary

The Linux kernel and independently reviewed installed operator/root enforcement
components remain trusted. This is not attestation against a malicious machine
administrator or compromised kernel. Operator error, races, stale enrollment,
crashes and partial installation must still fail closed; being root is not proof.

Tenant/client input, adapters, campaign workers and unqualified role processes
cannot choose code, paths, labels, credentials, endpoint tuples or enforcement
generation. Treat them as potential bypass actors. Exact enrolled server,
observer and broker implementations are reviewed components, but their responses
are not enforcement proof. A compromised Python process must not create effect
authority merely by returning successful inspection results.

Memory corruption inside an otherwise trusted role is not solved by file
integrity. Do not claim complete in-process control-flow/data integrity. Either
retain checks and explicitly bound the trusted-code assumption, or separately
design independent ownership enforcement for affected state. Arbitrary adapters
must never execute inside these role processes.

macOS is a development host, not this production backend. The first native
profile remains a dedicated, existing Linux proxy/operator host with the
`SELINUX_FSVERITY_CGROUP_BPF_V1` baseline. It does not impose this profile on
every tenant Kubernetes worker. Unsupported hosts remain unavailable; there is
no automatic privileged install, new VM, cloud capacity or AppArmor fallback.

## 4. Responsibility split and bootstrap without circular qualification

### Layer E: independently installed enforcement

The existing operator is accountable for establishing protected artifacts,
labels, namespaces, cgroups, endpoint filters, update exclusion and effect
admission **before role code begins executing**. The exact installed maintainer,
artifact, version, license, configuration, update paths and enforcement semantics
must be identified. This package does not assert that such an implementation is
available. An operator declaration alone cannot close this gate.

There are two different fences: host-state stability during inspection and
per-effect admission during execution. Proving one does not prove the other.
No application-created token, retained FD, epoch value, lease, boolean, manifest
or signature grants either fence. Actual active independently established
enforcement, supported by independently verified installation and native
evidence, is the initial trust premise. Paper evidence alone cannot establish
exclusion; runtime observation can reject the premise, not create it.

Before loading roles, independent bootstrap must deny bypass update paths and
keep effect admission closed. It must remain effective if a role hangs, exits,
lies or cannot make another observation. Host-state changes are disabled for the
whole enrolled role lifetime until external quiescence, unless a separately
specified broker-owned bounded inspection mechanism is approved. No such new
mechanism or private operation is introduced by this design.

### Layer Q: private qualification and observation

Retain the installed factory-owned `_KernelQualification` interface and existing
fixed server/observer/broker/worker boundaries. No caller context or successful
response constructs a qualification object. The proposed implementation split
is an internal dependency direction, not executable pseudocode:

    private factory -> bounded snapshot traversal -> leaf reads -> local guards
    local guards -X-> snapshot traversal / observer I/O / credentials / workers

The prohibitory arrow is the proposed nonrecursive boundary. Local guards still
check their exact owner, thread/process, original resources, sticky failure,
fresh clocks, original lifetime, authority custody and applicable peer identity.
No self-only shortcut may bypass observer/broker overrides.

Initially, every existing observation remains required. For an eventual revised
schedule, each removed/repositioned native resampling call must identify the
protected facts, old trace position, lost detection window and independent
exclusion proof. State not covered by that proof retains the original fresh
checks. Exact leaf and owner guards cannot be specified by saying 'cheap enough'.
Removing a complete global sample also removes the custody/peer/clock checks
nested inside it. Keeping those guard functions unchanged does not preserve
their temporal coverage. The successor must map indirect removals too, including
autonomous-event detection latency; host-policy stability alone is insufficient.

Fresh bounded snapshots retain before/after root identity, active policy/status,
mapped-code and effective filter observations. They do not reuse a disk policy
copy, old policy-open snapshot, old mount success or old peer success. Constant
record parsing may reuse exact immutable validated bytes only; it never turns a
mutable-state observation into a cached success.

During self/peer bootstrap, enforcement exists independently; it is not assumed
because the broker whose code is being inspected reports itself qualified.
Self qualification precedes observer use; peer qualification precedes its use;
the unstarted worker has no fabricated process evidence. Original qualification,
observation, durable reservation and credential ordering remains mandatory.

### Layer A: external effect admission

The existing independent broker owns worker creation, execution and reaping.
The server alone retains its scoped API credential under the existing ordering.
External generation admission covers every effect, including an already-open
connection and a delayed request; socket-connect filtering alone is insufficient.
Zero-resource cases still require broker ownership and cannot open an API socket.

If this cannot be achieved through the existing fixed channel and independently
installed interfaces, stop and propose the exact additional interface separately.
No unspecified enforcement callback, new socket, signing role, grant or receipt
field is hidden in this design.

## 5. Generation lifecycle and failure ordering

The names below are design states, not additions to public status enums. A
generation is an externally owned enrollment identity, not a bearer capability.

| State | Entry / allowed activity | Exit rule |
|---|---|---|
| CLOSED | Effect admission denied; independently verify/install within separately authorized maintenance | Proven initial controls permit INSPECTING, not execution |
| INSPECTING | Contained roles perform fresh bounded qualification; host mutation paths excluded | Failure closes; independently authenticated observation and durable reservation are prerequisites to ACTIVE |
| ACTIVE | Only independently admitted fixed-case effects; old lifetime never extends | Normal maintenance enters DRAINING; uncertainty/revocation enters INVALIDATED immediately |
| DRAINING | Deny new operations; existing permitted work may finish within original authority/lifetime while controls stay unchanged | External proof of quiescence permits maintenance; expiry/error invalidates |
| INVALIDATED | New effects denied externally first; stop/reap workers and affected inspection/role processes; classify in-flight delivery | Never resume the old generation; uncertain termination remains HELD |
| HELD | Capacity, consumed nonce and ambiguous resource records retained; no execution | Independently authorized reconciliation, not automatic retry |
| CLOSED / fresh enrollment | Maintenance only after required quiescence and reconciled state | New non-reused generation and fresh qualification; never revive old objects |

Ordinary maintenance must not wait forever while admitting more work. Urgent
revocation closes admission before waiting for a drain or application response.
If stopping/reaping cannot be proved, admission stays closed and capacity held;
do not install changed controls into still-executable roles and report success.
The gate must not require the process being frozen or killed to release it.

On independent enforcer restart or lost durable state, startup defaults to deny.
Do not recover an ACTIVE state from a worker report, stale success, PID reuse or
repeated generation label. Generation enrollment includes exact boot/process/
artifact identity and durable anti-replay history; exact encoding must be fixed
in the successor contract without silently changing existing wire schemas.

Autonomous events are not serialized maintenance: process/peer death, time
passage, suspend/resume, clock changes, OOM, storage errors and remote API
completion need explicit handling. Retain fresh checks and original deadlines;
external admission must reject expiry even when Python is stalled. If the
existing timer model cannot enforce signed lifetime across suspend/clock change,
that environment cannot qualify; no clock-source switch is authorized here.

Effects already admitted before revocation may finish remotely. Preserve their
intent/result and possible resource ownership; do not relabel them nonexistent.
All queued actions require admission at the actual effect boundary. Uncertain
completion remains ambiguous. A new generation never launders an old queued action.

Cleanup continues only with independent current authorization, exact recorded
UID and confirmed absence. Denied cleanup stays CLEANUP_PENDING; lost create
response retains IO_AMBIGUOUS and the reserved name. No force deletion, adoption,
guessed UID, permission widening or successful terminal receipt while unresolved.

## 6. Mandatory enforcement coverage

**Every row below is OPEN_UNPROVEN for the proposed reduced schedule.** Existing
documents specify obligations; they are not an inspected installed solution.
R10 means product H1 integration owner; the independently installed operator is
the deployment enforcement owner. R12 owns reader changes and independent tests.
None of these rows grants installation authority.

| ID | Fact, actor and bypass routes | Required mediator / retained freshness | Invalidation and evidence / owners |
|---|---|---|---|
| E01 | Authority/code paths: rename, unlink, symlink/hardlink alias, retained writers, mode/label change | Independently reviewed path/ancestor and writer restrictions; keep no-follow named and retained-FD custody until proven | Deny update or drain before change; native transient rename/restore and alternate-writer tests; operator/R10, R12 verifies |
| E02 | Process-owned FDs: close/dup/reuse, fcntl inheritance, injected ancillary descriptors | Keep exact per-leaf owner, descriptor, flags and inheritance checks; fs-verity/MAC alone does not preserve a descriptor table | Sticky refusal; close only actually acquired originals, never a reused unrelated FD; OS-double and native FD tests; R12 |
| E03 | Kernel views: mount/bind/overmount, propagation, setns/unshare, namespace substitution | Independent prohibition of role mutation and exclusion of authorized host updates; original root, filesystem and namespace identity observations retained | Block if aliases/propagation escape mediator; native transient mount and namespace tests; operator/R10, R12 |
| E04 | SELinux: policy load, enforcement/permissive/boolean changes, relabel, injection privilege | Reviewed effective policy plus exclusive authorized update path; fresh active-policy/status observations, no stale open-policy snapshot | Deny first, external quiescence, change, fresh generation; both architecture ordering/ABA tests; operator/R10, R12 |
| E05 | Cgroups/BPF: migration, ancestor effective rules, attachment/link replacement, hidden maps/helpers | Independently restricted migration/update/delegation; exact effective enrolled programs and finite limits still observed | Existing sockets separately fenced under E10; ancestor/link bypass tests; operator/R10, R12 |
| E06 | Code/maps: COW writes, dlopen, mprotect, memfd, executable aliases, ptrace/process_vm, thread/fork/exec | Reviewed role policy/syscall/process lifecycle closure; fixed mapped dependency inventory; retain actual maps/labels/identity reads | File verity alone insufficient; startup versus sealed steady state separately tested; operator/R10, R12 |
| E07 | Peer/process replacement or autonomous death; socket path spoof, PID reuse | Retained pidfd/start/credentials/path and original channel checks before/after exchange; independent admission/worker ownership | Death/restart closes, no reconnect/rebinding; native fork/crash/channel-loss tests; operator, R12 |
| E08 | Time, expiry, suspend, clock rollback, deadline-extension attempts | Fresh mono/wall checks and original bounds plus independent external expiry enforcement; no returned lease | Expiry denies admission, triggers containment termination; suspend/clock/blocked-reader tests; operator, R12 |
| E09 | Observation computation: in-process mutable owner/flags, reentrancy, partial construction | Exact factory and dynamic role guards; no assumption that a kernel policy prevents Python attribute corruption | Sticky failure; retain wrong-owner/reentrancy/resource-substitution tests and declared trusted-code limit; R12 |
| E10 | Resource effects: old connections, delayed queue, RBAC/impersonation/aggregate-grant bypass | Independent per-effect generation admission and serialized full policy paths; fresh scoped authority before credentials/actions | Revoke before new effects; admitted remote work remains recorded/ambiguous; exact UID cleanup tests; operator/R10, R12 |
| E11 | Enforcer/host crash, storage/fsync ambiguity, history rollback, generation ABA | External deny-by-default restart and independently protected durable consumption; no in-process successful flag | Hold capacity/nonces, reconcile explicitly; process-kill/partial-write/reboot tests; operator/R10, R12 |
| E12 | Quiescence/cleanup: frozen-but-live roles, descendants, escaped processes, pending API work | Independent ownership and termination proof, not a freeze request or worker report; current cleanup authority | Deny first, reap/drain/retain ambiguity; never clear pending state to unblock; operator/R10, R12 |

For each row, a design-only publication may record an unresolved dependency and
the exact evidence specification needed to resolve it. Before adopting a reduced
runtime schedule, the closure dossier must name exact artifact/version/license,
enrollment facts, all permitted mutators, all bypass paths and the admission
linearization point where relevant. It must supply code/policy review, relevant
positive/negative native evidence for the enforcement premise, expected refusal
and retained records. Final native qualification of the integrated successor is
still a separate later gate. If no suitable installed implementation is found,
keep the dependency unavailable rather than hide a security subsystem in the inspector.

Kernel documentation confirms important limits: fs-verity validates protected
file data and has a distinct digest, not full process identity; seccomp filtering
is only one confinement tool; no_new_privs does not exclude every privilege
change; freezing is asynchronous and does not itself prohibit migration or
cgroup-tree changes. See the bounded primary-source notes in OBSERVATION_ENFORCEMENT_PUBLICATION.md#sources.
These are reasons to demand coverage, not claims a particular policy is safe.

## 7. Cross-repository ownership and dependency policy

Keep all 13 repositories, 16 harnesses, four planes and existing machine IDs.
No broker/inspector repository is created by this proposal.

| Owner | Proposed responsibility | Boundary / dependency |
|---|---|---|
| R00 harness-onion | Publish architecture, exact trace deltas, prerequisite feasibility, owner map, successor packets and backlog | Owns planning, not runtime enforcement |
| R01 contracts | Only if an approved change affects public installation/evidence contracts | Contract-first; no new public fields currently proposed |
| R10 mas-harness-operator / H1 | Product install/verification lifecycle and packaging requirements for a selected independent enforcer | Does not self-certify native adequacy; separate owner packet; does not embed R12 source |
| Independent installed operator/broker maintainer | Concrete host and per-effect enforcement, durable lifetime, native policy semantics | Exact OSS implementation/maintainer UNSELECTED; deployment prerequisite, not secretly a completed product module |
| R12 mas-harness-conformance-labs | Private readers/transport/worker changes; source regressions; independent exact-artifact qualification | Consumes operator evidence/interfaces, never imports operator implementation; source tests are not native qualification |
| R11 mas-harness-distribution | Pin qualified prerequisite artifacts, licenses, SBOM and offline closure after selection/release | Assembles released artifacts; does not supply a substitute unqualified broker |
| R09 trust / R04 control | Existing evidence registry and truthful administrative status projections if needed by an approved packet | No duplicate enforcement authority or synchronous browser/control-plane dependency |

Separate external deployment maintenance from R10's Kubernetes product operator;
the identical word 'operator' does not make them the same executable or grant.
Adopting an upstream solution or implementing missing external glue needs its own
decision, exact owner and authorized paths. Selection favors existing maintained
open-source components; repository popularity never substitutes for safety.

Use consumer-to-provider typed graphs: conformance -> operator runtime evidence;
distribution -> released operator artifacts; installed operator -> verified
distribution bundle occurs later. No source/build cycle or runtime Git import.
Any new contract/build/release dependency requires a registry amendment. A private
channel is not an excuse to omit its compatibility/versioning responsibilities.

The approved harness/paper/OSS map and progressive provider ledger remain in
force, including Ollama and Milvus tracks. This narrow repair does not replace
provider adoption with bespoke harness implementation. Require **at least one
qualified baseline for every released harness capability** at first enterprise
release; this design supplies no new qualified baseline.

## 8. Normative deltas needed before coding

No files listed here are modified by this external package. Publication requires
one exact META packet with allowed paths, predecessor locks and finite acceptance.

| Authority / consumer | Required amendment or preservation |
|---|---|
| NATIVE_QUALIFICATION_READINESS.md | Explicitly version any changed per-blocking-I/O schedule; Layer E premise, actor coverage, bootstrap ordering and unavailability; retain exact native restrictions |
| BROKER_HANDOFF_READINESS.md | Clarify inspection-lifetime versus effect fence, independent crash/expiry denial, already-open connections and cleanup; any new operation requires an explicit separate protocol decision |
| GUARD_TRAVERSAL_REPAIR.md / CONF-FIX-010 | Preserve stopped history/bytes; publish a successor rather than execute outside its trace-equivalence scope |
| Qualification/broker record schemas | Unchanged unless exact evidence/version change is necessary and separately approved; no record-self-signing or circular digest |
| R12 runtime and tests | Exact owner/leaf call graph, changed observation list and invariants; actual factories, leaf OS doubles, source accounting and cleanup ownership |
| Source-history proof/test contracts | Preserve all failed sources, old validators and proof anchors; explicitly map old trace-specific assertions to new prevention/refusal assertions before any test change |
| MASTER_DEVELOPMENT_PLAN / CANONICAL_REPAIR_PLAN / backlog / repository guides | One consistent phase/gate/status view; no DONE from draft publication, no rewritten historical evidence |
| Dependency registry / provider ledger | Only exact selected implementation/interface deltas, offline pin/license/support ownership, no mutable references |

This is incompatible with silently retaining CONF-FIX-010's 'all observations
unchanged' acceptance promise while deleting assertions. A successor must
enumerate each affected inherited test identity, why its temporal assumption
changes, and stronger/equivalent prevention and refusal coverage. Preserve all
unaffected 1,655 identities, the 1,485-backend inventory and historical meanings.
If no exact mapping can be agreed, do not authorize the implementation.

## 9. Acceptance and security review plan

These are required future cases, not tests executed in this design task.
The companion OBSERVATION_ENFORCEMENT_DELTAS.md identifies the source boundaries
and representative inherited assertions. It is a candidate delta register, not
the still-required exhaustive successor test/trace map or implementation approval.

| ID | Required evidence | Corresponding design obligations |
|---|---|---|
| A01 | Lost-window register: mutation after every changed leaf boundary, restored before next sample; denied externally or detected with original fresh check | E01-E09; C1/C6 |
| A02 | Real fixed factories, wrong roles/owners, dynamic peer overrides, sticky failure, original deadlines, partial acquisition and original-resource-only cleanup | E02/E07-E09; C1/C6 |
| A03 | No observer/broker self-created bootstrap grant, no token/FD/boolean callback, no credential/worker before all independent prerequisites | E01/E03-E07/E10; C2 |
| A04 | Actual effective policy/BPF/cgroup/maps on pinned AMD64 and ARM64 Linux environments, bypass attempts and denied mutation windows | E03-E06; native gate separate from source mocks |
| A05 | Concurrent normal updates, urgent invalidation, stuck reader, dead enforcer, peer restart, suspend/expiry and lost durable history | E07/E08/E11/E12; C1/C3 |
| A06 | Zero-resource and resource profiles; old connections and delayed effects; exact UID/no-adoption cleanup; denied cleanup and lost terminal delivery | E10-E12; C2-C5 |
| A07 | Fresh exact candidate inventory, source-history round trips, independent changed-symbol/test map and full unaffected regression suites | C6/C7; no historical projection as current evidence |
| A08 | Complete unchanged bounded source recipe under an explicitly reserved successor allowance, required localhost CI, protected merge and independent exact-main | Separate four source gates; no selective tests/timeout increase |
| A09 | Exact artifact/SBOM/signature, installation, native campaign, runtime assurance and tenant acceptance independently recorded | No source-to-runtime promotion |

Independent reviewers must inspect the exact implementation, not approve this
abstract split as its safety proof. Full trace counts and bounded allocation/I/O
budgets precede implementation reservation. Any performance claim then requires
authorized full-acceptance evidence; static complexity is not measured latency.
Keep the current 750/420/900-second and 15-minute source limits unless a separately
approved amendment says otherwise; this design requests no increase or budget reset.

## 10. Delivery order, rollback and current backlog

1. Complete this design and independent review; keep it external/non-dispatchable.
2. Prepare exact source-only META publication authority, including a feasibility
   evidence specification for the missing installed enforcer and the lost-window
   register. Do not activate product work from this document.
3. Resolve enforcement implementation/ownership and interface proof obligations.
   If a new interface, privilege, provider or installation is required, obtain
   that specific decision before implementation; retain existing unavailable state.
4. Publish any contracts first; then separate owner-repository packets in declared
   predecessor order. Keep implementation and independent qualification separate.
5. Full source gates precede artifact construction/installation; actual native
   AMD64/ARM64 qualification remains manual under the trusted live launcher and
   required independent signatures/capacity. No new hardware or billable service
   is provisioned to satisfy this plan.
6. Resume downstream live-probe/packaging/integration packets only when their
   exact predecessor and prerequisite gates genuinely pass.

Before implementation, withdrawing this draft changes no installed behavior.
After any future adoption, rollback denies admission, drains/reaps, preserves
nonces/UID/cleanup history, verifies compatible data and controls, and uses a
reviewed source successor. An image rollback cannot restore consumed authority
or erase an ambiguous effect. If the old profile cannot qualify, remain unavailable.

| Phase | ID | Status at this draft | Description |
|---|---|---|---|
| Phase 0 / Alpha 1 | Existing foundations | DONE_RECORDED | Historical source/offline foundations, not universal runtime acceptance |
| Alpha 2 | MET-PERF-017 | DONE_SOURCE_GATES | PR133 publication and separate exact-main evidence |
| Alpha 2 | CONF-FIX-009 | BLOCKED_LOCAL_ALLOWANCE_EXHAUSTED | Failed candidate retained, no accepted repair |
| Alpha 2 | CONF-FIX-010 | BLOCKED_SAFE_DESIGN | Original trace-preserving packet stopped, zero attempts |
| Alpha 2 | OBS-ARCH-DESIGN-001 (design label) | DESIGN_PREPARED | Conditional architecture; final review state is in the design-review provenance record |
| Alpha 2 | Successor META publication (unassigned) | WAITING_EXACT_AUTHORITY | No executable packet or acceptance allowance created here |
| Alpha 2 | Enforcement closure / native qualification | WAITING_PREREQUISITES | Exact existing implementation and all E01-E12 obligations unresolved |
| Alpha 2 | CONF-LIVE-004/005/006 | WAITING_PREDECESSORS | Native probes, packaging and trusted campaign integration |
| Alpha 2 | CONF-A2-001 | WAITING | Qualified integrated read-only profile |
| Alpha 3 / Alpha 4 | Existing later-phase packets | WAITING | Governed actions and enterprise qualification |

Alpha 2 remains open. Model-effort transition: **NOT_DUE**. Design completion
does not constitute product readiness, native PASS, runtime assurance or tenant acceptance.
