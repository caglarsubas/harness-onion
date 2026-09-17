# W01 host interfaces — candidate, not adopted

Design label `HOST-INTERFACE-DRAFT-001`; owner R00 coordinating R10/R12.
W01 is a work label, not an execution packet. All E01-E12 remain OPEN_UNPROVEN.
This candidate proposes exact integration boundaries where the existing record
is incomplete. It does not amend existing v1 schemas, sockets, roles or grants.

## 1. Preserve the existing product boundary

Keep thirteen repositories, four planes and sixteen harnesses. R10 owns the four
host modules below; R12 independently qualifies them; R11 packages released
artifacts. R01 owns changes to public contracts, if the reviewed design needs any.
No module runs inside the nonroot Kubernetes operator controller, the control-plane
web application, a tenant adapter, or a conformance reader.

Use an existing dedicated Linux qualification host. macOS remains development-only
for this backend. Do not create a VM/cluster, install policies, acquire privileges,
introduce a Kubernetes fork or turn the product operator into a cluster administrator.
Host root/kernel remain within the existing trusted boundary; tenant code is not.
Trusted-root status does not excuse operator errors, races or unmediated update paths.

No implementation language, package version or artifact is qualified here. R10's
Go toolchain is not automatically suitable for the original-parent, single-role,
mapping and sealed-lifecycle rules. Select the implementation/toolchain only after
the exact native behavior and offline license closure are reviewed.

## 2. Module/process/state contract

The names in the source column are logical R10 namespaces, not allowedPaths.
Future packets must enumerate actual files, pinned dependencies and acceptance.

| Module / logical source | Input and output | State owner | Privilege and failure boundary |
|---|---|---|---|
| host-containment / `host-enforcement/host-containment/` | Independently verified installation/enrollment; establish sealed files, labels, namespaces, delegated role cgroups and exact BPF before roles execute; output inspected installation facts, not a permission token | External installation inventory and maintenance state; not CRD status | Separate maintenance executable, outside the controller. No campaign-selected path or policy. A failed/partial install leaves roles unstarted and admission closed. Runtime update exclusion must exist even when this executable has exited. |
| capacity-broker / `host-enforcement/capacity-broker/` | Existing DISPATCH and worker FD3 protocol; independent authority and current observation; proposed native-gate action control | Durable execution consumption, generation, child identity, capacity holds, action intents and outcomes | Existing fixed native broker executable, original parent of workers. No server/API private key. Death or uncertain storage closes admission and prevents generation reuse. |
| policy-observer / `host-enforcement/policy-observer/` | Existing OBSERVE_POLICY request; actual complete current controls from independently established backend | Observation transcript only; the backend owns policy truth | Existing fixed native observer, read-only to policy. Never returns a grant. Unknown writer, watch gap, stale/partial view or generation mismatch is unavailable. |
| effect-admission / `host-enforcement/effect-admission/` | Normal requests at the existing signed KUBERNETES_API_PROXY endpoint plus proposed broker-local control channel | Independently durable per-action consumption/delivery/result records | Separate native gate in the existing API-proxy trust boundary. Owns forwarding through terminal classification. A boolean returned to the Python server cannot enable a later operation. Fail closed on peer death, expiry, invalidation or uncertain storage. |

The proposed gate's backend API credential, if one exists, belongs to the
independently operated API proxy and is NOT the protected server's existing
KUBERNETES_PROXY_SERVER_MTLS credential. No new credential is selected or issued
here. The proxy's actual upstream identity, authentication and read grants are
missing deployment inputs, and must be inventoried before this design can qualify.
The server remains the sole owner of its existing signed server-side mTLS bundle.

## 3. Current versus proposed interfaces

### Existing interfaces — byte-compatible, no changes now

| ID | Connection | Existing contract |
|---|---|---|
| I01 | Server -> observer | AF_UNIX/SOCK_SEQPACKET `/run/planeon/live-proxy/policy-observer.sock`; only OBSERVE_POLICY; exact current request/response schema |
| I02 | Server -> broker | AF_UNIX/SOCK_SEQPACKET `/run/planeon/live-proxy/capacity-broker.sock`; existing DISPATCH/transcript/resource/cleanup frames |
| I03 | Broker -> original worker | Broker-created AF_UNIX/SOCK_SEQPACKET socketpair, worker FD3; no SCM_RIGHTS or request-selected executable |
| I04 | Protected server -> existing API proxy | Already signed KUBERNETES_API_PROXY literal IP/TLS endpoint, existing server-only mTLS identity and fixed CREATE/GET/DELETE rules; no extra header/field/grant |

### Proposed integration deltas — require a reviewed successor

**I05: broker -> independent API gate.** Candidate path
`/run/planeon/live-proxy/effect-admission.sock`, AF_UNIX/SOCK_SEQPACKET, root:root
0600 below the existing root:root0700 directory. This is a proposal for a NEW
private interface, not an existing socket or installation instruction. The first
candidate requires broker and gate on the same enrolled host; a remote broker/gate
deployment needs a separate authenticated transport design, not a TCP fallback.

Both sides independently load the same verified release/capacity inputs. They
authenticate exact installed peer artifacts, manifest/trust custody, PID/start,
pidfd, SO_PEERCRED and each SCM_CREDENTIALS frame. Root UID alone is insufficient.
No descriptor passing, reconnect, alternate socket, proxy environment or caller
authority path. There is no command/URL/path/program selector in a frame.

Candidate frame data: canonical duplicate-free JSON, exact builtins, no floats,
depth <=16, <=16KiB per control datagram; sequence/hash-chain/challenge bound to the
original channel. All exchanges <=2 seconds inside the existing signed lifetime
and <=900-second execution limit. A wire schema is a W02 deliverable, not supplied
or accepted by this prose. Unknown fields and operations must refuse.

| Candidate operation | Necessary data; independently resolved, never caller authority | Meaning |
|---|---|---|
| BIND_EXECUTION | existing bindingDigest, executionId, runNonce, generation, independently enrolled server certificate digest, original worker PID/start identity | Associate one already-consumed execution with one retained broker channel; no action becomes admissible |
| ARM_ACTION | executionId, unique actionId, generation, CREATE/GET/DELETE, selected manifestDigest, exact request-template digest, recorded UID when applicable | Persist a single expected action. Acknowledgement only describes gate-owned state; it is not a capability returned to the server or worker |
| ACTION_OUTCOME | same identifiers plus NOT_FORWARDED / DELIVERED_RESULT / IO_AMBIGUOUS, bounded result digest and observed UID/resourceVersion when verified | Gate-owned delivery classification; no claim of tenant or native acceptance |
| CLOSE_GENERATION | generation and closed reason (normal drain, revocation, expiry, peer/storage/observation failure) | Deny unconsumed actions before acknowledging closure; retain every consumed action |
| GENERATION_STATUS | generation; deny/drain/held state, outstanding action IDs and durable record digest | Observation only; never an admission grant, release of capacity or proof of remote absence |

Exact key types, enum values, transcript directions, size limits, duplicate/replay
vectors and outcome-to-existing RESOURCE_RESULT mapping must be versioned together.
Do not extend I02 opportunistically or overload an old outcome enum. If an existing
public field is insufficient, R01 changes that contract before affected consumers.

**I06: current policy backend and writer mediation.** There is no selected concrete
backend yet. Its required operations are an atomic current projection, a protected
generation read, and mediation of each enrolled policy writer with the effect gate.
These are required semantics, NOT callable functions or an implicit daemon. A
complete implementation must identify actual endpoints, authentication, exact
writer paths, API/host privileges, state ownership and a native proof. Missing
I06 prevents live admission, including the existing zero-resource observation path.

This deliberate unresolved interface must not be replaced with an always-success
adapter, stored projections, a watcher, a lease, or a signed attestation alone.

## 4. Operation admission and linearization candidate

1. The server durably reserves the run; the broker separately durably consumes the
   exact execution and owns the stopped/contained worker, preserving current order.
2. Broker validates one worker resource action against the fixed case and manifest
   set. For nonempty resources, it prepares I05 ARM_ACTION before emitting the
   existing RESOURCE_ACTION to the protected server. One outstanding action only.
3. The server performs its existing fresh guards and credential custody checks,
   records create intent before send, and makes the existing normal API request.
4. The gate authenticates the original run-specific server certificate, parses the
   bounded HTTP request, independently derives the permitted route/body from its
   own signed profile, and attempts to correlate the request with the sole armed
   action. This correlation is UNRESOLVED (G09): a delayed duplicate of completed
   action A can be byte-identical to a later armed action B in the same execution
   and generation. A run certificate, request digest and one outstanding action
   do not distinguish the duplicate's origin. Unchanged I04 is not established as
   sufficient; the candidate is not adoptable until that ambiguity is resolved.
   Require a demonstrated immutable-profile/transport restriction that makes
   correlation unambiguous, or an explicitly reviewed versioned protocol amendment.
   No new header or field is authorized now; a caller-supplied actionId alone is
   not authority. Unknown or ambiguous correlation must deny, never guess.
5. **Proposed admission linearization point:** within the one protected generation/
   writer transaction, verify current scope, deadline, policy and available action;
   consume that action exactly once and fsync/read back its durable intent. Only
   the gate-owned forwarding path may then emit its request. The transaction and
   generation exclusion must span forwarding/terminal classification, not merely
   the return from an authorization callback. A real I06 backend is prerequisite.
6. The gate cannot infer that a request is NOT_FORWARDED after an uncertain send.
   Lost connection/response or uncertain durability means IO_AMBIGUOUS. Preserve
   name/UID and capacity holds. No replay, second connection retry or new generation
   may launder this action into an unconsumed slot.
7. Before advancing the broker transcript, require agreement between gate delivery
   evidence and the server's existing RESOURCE_RESULT and owned-resource journal.
   Disagreement or a lost outcome is sticky failure/HELD, never inferred success.
8. Keep post-defaulting validation and exact-UID cleanup. The proxy cannot inspect
   the final mutated object before persistence merely by validating the original
   request; existing server-side admission enforcement is still required. A returned
   bad object may already exist, so its ownership/cleanup stays recorded.

The relevant admission event is the gate-owned, durably consumed forwarding
transaction, NOT socket creation, successful TLS, ARM_ACTION acknowledgement or
worker report. Old authenticated sockets and requests waiting in parsing/queues
must pass step5 when they actually arrive there. Existing protocol restrictions
remain; HTTP/2, CONNECT, upgrade, redirect and generic proxying gain no grant.

Urgent invalidation closes admission before waiting for the Python server, worker
or ordinary drain. Actions admitted before invalidation may finish remotely and
remain recorded. Unconsumed or queued actions cannot acquire admission afterwards.
Normal compatible updates wait for externally proven drain. If drain cannot be
proved, the generation remains HELD and no update is declared safely complete.

This algorithm is a design candidate, not an assertion that kernel filters or
available Kubernetes extension points implement its transaction. In particular,
the strict original 'before committing a mutation' wording needs an explicit
interpretation/amendment: a gateway cannot make an arbitrary upstream storage
commit atomic with unrelated policy changes. No weaker guarantee is adopted here.

## 5. Generation, state and recovery contract

Use the existing conceptual states CLOSED, INSPECTING, ACTIVE, DRAINING,
INVALIDATED and HELD; these are not new public status values. Never restore ACTIVE
after restart from a journal bit. New enrollment requires exact boot/process/
artifact identity, non-reused generation, fresh controls and durable anti-replay.
Exact encoding and storage format remain versioned W02 work.

- CLOSED: deny all operations. Installation/maintenance requires separate authority.
- INSPECTING: contained roles may inspect; no action can be armed or forwarded.
- ACTIVE: existing reservation plus qualified independent backend; only one exact
  armed/consumed action and bounded worker. Expiry is checked outside Python.
- DRAINING: no new actions; original authority bounds any already admitted work.
- INVALIDATED: close gate first, stop/reap worker tree, retain in-flight ownership.
- HELD: no new generation or automatic release while local or remote state is
  uncertain. Independent reconciliation may classify it, never erase its history.

Broker, API gate and server own separate durable journals with separate fsync
failure domains. No two-store success or distributed commit is inferred from one
acknowledgement. Gate reboot, peer death, generation mismatch, partial write,
readback mismatch, full disk or lost protected history starts denied and HELD.
Suspend, wall-clock rollback and expiration cannot extend the signed lifetime.

No generic recovery RPC is proposed. Exact cleanup remains the existing scoped
operation with independently current authorization and recorded UID. If revoked,
retain CLEANUP_PENDING until externally authorized reconciliation; never re-enable
the old generation merely to delete resources.

## 6. Host startup, custody and privilege gates

The systemd-delegated hierarchy must be a versioned future native profile; current
four fixed root-level paths remain unchanged. systemd owns its hierarchy and the
delegated manager exclusively owns its subtree. Do not alias/discover arbitrary
paths or detach ancestor enterprise BPF controls to fit the current reader.

Candidate startup order: independently inspected host containment, deny-default
gate and durable stores -> observer/broker prerequisites -> qualified server ->
actual observer view -> server reservation/TLS -> broker-owned worker and execution
consumption -> specific gate-owned actions. Gate/observer/broker self-reports cannot
bootstrap the independent containment premise.

The gate introduces a new process/peer subject relative to the existing four-role
native record. Host-containment's install/lifecycle role also needs an explicit
policy boundary. Neither may be accepted under an old BROKER or SERVER record.
W02 must specify any new native-role entries, manifest binding and observation
cycle before implementation. The v1 role set must reject the new profile, not
accept it through a permissive parser or an overloaded existing role name.

Host lifecycle must exclude policy/file/mount/cgroup/program/namespace changes
for the entire inspected role lifetime and prevent retained-writer bypasses.
An ExecStartPre command alone does not prove continued exclusion after it exits.
Readiness cannot depend on cooperative updater conventions or a process holding
an application mutex when it can change the kernel policy through another path.

Worker creation must preserve original broker parentage, stopped pre-execution
containment, exact inherited FD3 and fixed executable. A systemd child service,
generic OCI execution or subreaper adoption is not automatically equivalent.
Native multi-process proof must establish stopping/reaping, cgroup emptiness,
descendant containment, PID/FD reuse refusal and expiry while Python is blocked.

No blanket CAP_SYS_ADMIN grant is selected. The successor must list each syscall,
capability, SELinux permission and phase when needed, and then demonstrate the
drop/seal boundary. Failure to name or satisfy that list blocks implementation.
Existing R12 descriptor/owner/peer/clock guards and observation cadence stay intact.

## 7. All permitted writers: required closed inventory

This is a coverage inventory, not a claim that the writer mechanisms are selected.

| Writer family | Must be mediated or excluded by actual installed controls |
|---|---|
| Host files/credentials/trust | Packaging, secret rotation, rename/link/mode/relabel, retained file writers and alternate mounts |
| Host policy and namespaces | SELinux load/booleans/permissive state; mount propagation/setns/unshare; namespace recreation |
| Cgroups/BPF/process execution | systemd/delegated manager, migration and ancestor attachments, runtime exec/injection/ptrace, loaders, memfd/COW executable changes |
| RBAC and identity | Role/ClusterRole and bindings, aggregation controller, group/identity changes, impersonation, authorization ordering/caching and privileged bypass |
| Namespace/quota/admission | Namespace replacement, quotas/limits and usage, admission config/defaulting/mutation rules, controllers and concurrent users |
| Network and API path | CNI/NetworkPolicy, routing/proxy endpoints, API-server config reload, alternate API servers, direct datastore paths and storage restore |
| Autonomous events | Peer death/restart, OOM, expiry, suspend, clock change, filesystem/storage errors and already-admitted remote completion |

Autonomous events are not 'authorized writers' that a mutex can exclude. They need
independent deny/termination and ambiguity handling. A relevant unmediated path
makes the capability unavailable, even when observations currently look correct.

## 8. Reuse policy and deployment scope

Reuse Linux SELinux/fs-verity/cgroup/BPF/pidfd primitives and systemd lifecycle
support; evaluate a maintained native HTTP/TLS stack for the gate. Do not invent
a sandbox kernel or fork Kubernetes merely to claim this profile implemented.
Concrete dependency choices need immutable versions, license/SBOM closure and
offline builds in separate owner packets. Popularity does not prove the fence.

Concrete reuse candidate: `envoyproxy/envoy` for the existing API-proxy HTTP/TLS
substrate, not a newly required tenant gateway. Its external-authorization and
external-processing filters offer request inspection and response processing.
They do not themselves demonstrate this design's durable action consumption,
writer serialization or remote-commit guarantee. A permissive failure setting or
route mutation can bypass the intended check; the exact filter chain, full-body
limits, immutable routes and failure behavior need review. Prefer evaluating this
maintained substrate before writing HTTP/TLS parsing from scratch. No Envoy
release, plugin, new RPC transport or runtime dependency is selected here. The
native-process/thread/mapping compatibility gap also remains to be resolved.

Kubernetes admission does not inspect GET/LIST/WATCH. Authorization webhooks can
cover reads but require reviewed chain/failure/cache configuration; system:masters
bypasses authorization restrictions. Neither extension by itself holds a transaction
through a remote storage commit. These are reasons to require I06 and lifecycle
proof, not permission to modify a tenant control plane.

References consulted 2026-09-17 (research, not release locks):
- https://kubernetes.io/docs/reference/access-authn-authz/admission-controllers/
- https://kubernetes.io/docs/reference/access-authn-authz/authorization/
- https://kubernetes.io/docs/reference/access-authn-authz/webhook/
- https://systemd.io/CGROUP_DELEGATION/
- https://www.envoyproxy.io/docs/envoy/latest/configuration/http/http_filters/ext_authz_filter
- https://www.envoyproxy.io/docs/envoy/latest/configuration/http/http_filters/ext_proc_filter

The Envoy pages identify development-version documentation, not a release pin.
Any implementation decision must use exact stable-source and artifact locks.

The dedicated qualification profile is not a universal production-worker profile.
For managed clusters without the required independent backend, report this live
capability unavailable. Do not market that as an air-gap/platform incompatibility
for unrelated harnesses or require tenants to surrender control-plane ownership.
Zero-resource mode still needs genuine existing observer/broker evidence; it may
not fake namespace policy or implicitly disable mandatory probes.

## 9. Cross-repository delivery and compatibility

1. Independent review of this exact candidate and the unresolved decisions.
2. One META publication packet with exact paths/source locks and bounded acceptance,
   preserving historical evidence and not marking W01 complete prematurely.
3. W02: exact versioned native/private ABI, message/record schemas, privilege and
   writer-backend scope, old/new rejection and migration vectors. R01 first if any
   public interface changes. No reinterpretation of accepted v1 data.
4. R10 source packets separately implement host/broker/observer/gate modules against
   pinned interfaces. R12 consumes released contracts/artifacts, not R10 source.
5. R11 packages released artifacts and offline dependencies; R12 independently
   qualifies exact installed artifacts on each declared Linux architecture.
6. Only after enforcement proof and complete lost-window mapping may a separately
   scoped R12 successor propose reducing recursive observations.

The R10/R12/R11 interface/build/release edges must be added explicitly before use;
the existing repository graph is unchanged by this external candidate. Sharing a
repo never merges credentials, process lifecycle, state or failure domains.

Roll back source by reviewed revert before consumption, or a compatible successor
afterwards. Never roll back consumed nonces or durable resource ownership. No
installed state is changed here. All current checks, old failed runs and deadlines
remain; no timer increase, budget reset or hidden product retry.
