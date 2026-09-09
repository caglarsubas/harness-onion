# Fixed broker execution handoff — MET-REPAIR-014

Alpha 2 · approved source-only scope · 2026-09-09. Catalog 143 packets;
thirteen repositories, four planes and sixteen harnesses remain unchanged.
This publishes a protocol and coding obligations, not an installed broker.

## Decision and precedence

CONF-LIVE-003/B1 is SOURCE_INSPECTION_ONLY: the accepted observation contract
requires atomic generation enforcement but defines only OBSERVE_POLICY, and
the fixed probes have no specified broker execution handoff. In particular,
zero-resource profiles have no Kubernetes API leg. Observing before and after
a probe detects a race but cannot prevent an effect during that race.

The approved solution is **broker-owned execution**, not a returned permission
token, lease, caller-owned descriptor or successful callback. A new, fixed,
server-local channel delegates one already-authorized fixed case to the existing
capacity broker, which owns its contained worker and the execution gate until
termination. Neither a client nor the proxy may run the worker independently.

This is the explicit local-channel/worker supplement to MET-REPAIR-009/010/013.
It adds no public campaign field, network endpoint, signing role, Kubernetes
permission, credential purpose or OBSERVE_POLICY operation. Historical guides,
records, public/private profile schemas and all 142 packet YAML remain immutable.
It does not relax client or server credential ordering. Server startup still
requires independent custody/containment, actual observation and durable whole-run
reservation before its TLS credential. Upstream credentials additionally require
a broker-controlled active operation. No client observer or broker access.

## Owners and dependency closure

| Owner | Responsibility | Must not substitute |
|---|---|---|
| Existing operator broker | Owns generation enforcement, durable execution consumption, worker creation/containment/reaping, API-proxy generation association | A watcher, current digest or root UID alone is not enforcement |
| CONF-LIVE-003 | Fixed server/broker transport and server/observer/broker custody checks; resource admission, server-only TLS API leg, UID ledger and cleanup | No direct native probe call; no delegated server isolation check in packet004 |
| CONF-LIVE-004 | Fixed worker entry, ten probe recipes, bounded resource-action requests and unsigned receipt candidate | No generic executor, caller argv/import or credentials; no self-issued execution grant |
| CONF-LIVE-005 | Reproducible client/server/worker source candidates and installation handoff | No included substitute broker/observer or automatic installation |
| CONF-LIVE-006 | End-to-end integration and separate manual native evidence checks | Source data tests cannot satisfy any native or tenant gate |

Existing product paths remain exact: 003 has eight, 004 six, 005 five and 006
five additions plus its already-approved final launcher-hook edit. Stages remain
110/120/127/135/141/146/151. Every product command set remains eight commands.
The fixed worker is packaged by the existing 005 builder/package module from
the existing 004 modules; no extra source file, dependency or product packet.
No future packet must edit 003 to add an unspecified execution interface.

The broker and observer are separately installed, reviewed open-source operator
prerequisites, not product implementations represented as DONE. The operator must
qualify all enforcement below on pre-existing capacity. No available broker,
namespace, qualified backend, native architecture or artifact is asserted here.
Absence is NOT_RUN_ENV_UNAVAILABLE, not fallback, provisioning or a native PASS.

## Fixed local channel and custody

Server connects only AF_UNIX/SOCK_SEQPACKET to
`/run/planeon/live-proxy/capacity-broker.sock`. Parent is root:root 0700; socket
root:root 0600; canonical no-follow ancestry, retained socket identity. No DNS,
TCP, environment override, reconnect, alternate path or SCM_RIGHTS. Reject and
close any received descriptors, truncation or unexpected ancillary data.

Broker executable is the preinstalled native ELF
`/opt/planeon/bin/harness-capacity-broker`, root:root 0555, with manifest/signature
`/etc/planeon/harness-capacity-broker-manifest.json[.sig]`. Use the existing root
manifest shape/version0.1.0, fixed public key/digest and release/tenant trust
mounts. Verify retained executable/manifest/trust bytes, exact installed artifact,
SO_PEERCRED and every SCM_CREDENTIALS message, UID/GID, PID/start identity, pidfd,
executable inode and independently qualified process/mapping/containment controls
before and after blocking I/O. A signed manifest declaration is insufficient.
Broker symmetrically verifies the installed server's exact custody, not just UID.

Both independently load the same operator-placed HARNESS_LIVE_EXECUTION_ENVELOPE,
verify both signatures before selected references, then independent capacity,
revocation/windows, packet006/eight commands, release/kit/plan/profile and nonce.
The request never supplies authority paths or selects an implementation.

The release-listed canonical file
`campaigns/platform/linux-baseline/broker-execution-binding.json` is mode0444,
at most64KiB/depth16, and occurs exactly once with exact size/hash in the signed
tree. It contains no release/self digest: the release hashes it, not vice versa.
Its closed binding schema pins profile and observation-binding digests, broker
manifest/executable digests, worker manifest/artifact digests and ten case-resource
sets. The disjoint union of these sets is exactly the signed profile's manifest
digests; a digest belongs to one case only, so cleanup never permits name reuse.
Empty resources require all ten sets empty and still require the local broker.
The worker manifest/artifact are independently installed and not embedded copies
of this binding. Capacity-signed profile scope/resources remain the upper bound.
Release signing alone cannot add a resource, endpoint, image or operation.

## Broker-controlled worker ABI

One fixed candidate executable, `/opt/planeon/bin/harness-live-probe-exec`,
root:root0555, invokes `live_fixed_probes.broker_worker_main()` with no arguments.
Its independent root manifest/signature is
`/etc/planeon/harness-live-probe-manifest.json[.sig]`, same closed shape/key.
005 packages this entry in addition to the already planned client/server entries;
it is not a generic Python module or script selected by a request. Its interpreter,
dependencies and archive bytes must be locally pinned and independently verified.

Only the authenticated broker creates this process, first in a stopped contained
state on pre-existing bounded capacity. FD3 is the sole inherited non-stdio
descriptor: an AF_UNIX/SOCK_SEQPACKET socketpair created and owned by the broker,
not passed through SCM_RIGHTS. No credential, Docker/containerd/SSH-agent socket,
kubeconfig or external-network capability is inherited. Stdio is non-socket and
sanitized/bounded. Locale-only environment; no runtime module/PATH/argv selector.
This FD3 exception is worker-only; server/client ambient-FD rules are unchanged.

The worker verifies its installed archive/interpreter/manifest identity, original
broker parent PID/start/pidfd and kernel peer credentials, and actual isolated
cgroup/namespace/seccomp/UID/resource controls. Reparenting or a copied descriptor
does not grant execution. Broker verifies the exact child PID/start/cgroup and
retained artifact before allowing its one START frame. START carries only the
closed execution/case/binding/request/generation identifiers. Read-only preopened
kit views are fixed by the broker's verified release, not request-supplied mounts.
No private key or authority file content is transported to the worker.

The worker may run only the fixed case selected by the independently verified
request digest. Direct invocation, arbitrary callback, wrong parent, missing
gate, stale generation, unexpected inherited FD or missing containment refuses
before probes. Product unit adapters cannot construct a protected worker.
Worker failure/EOF/expiry terminates its entire descendant tree; broker must
verify cgroup empty and all children reaped. A worker self-report is not proof.

## Atomicity, lifetime and race semantics

The broker is the enforcement owner, not merely a policy-observation consumer.
Under one serialized admission transaction it verifies current namespace UID,
complete effective RBAC, quotas/headroom, network controls and observed generation;
consumes (run binding, caseId, requestDigest) durably and associates the exact
worker PID/start/cgroup and server API-proxy identity with that generation.
It fsyncs/readbacks its consumed execution record before starting the worker.
The server first fsyncs its own RUNNING reservation; separate stores are separate
evidence, not a distributed success inferred from one acknowledgement.

All policy-changing paths relevant to that namespace/capacity must participate
in the same enforcement serialization, including indirect grants, impersonation,
aggregate roles and privileged bypass paths. A Kubernetes watch or a lease whose
expiry is checked only by the caller is insufficient. If the installed platform
cannot exclude an uncoordinated path, it cannot qualify this protocol.

A compatible control update waits until the active effect transaction drains.
Revocation, uncertain observation continuity, broker restart or urgent invalidation
first closes broker/API execution admission, stops and reaps the contained worker,
and drains or marks in-flight effects ambiguous before publishing a new executable
generation. No still-running worker or old authenticated API connection may admit
an effect under the invalid generation. This is enforced outside the worker/server
process, not by testing a response boolean. Completed pre-revocation effects are
not undone or relabeled absent; retain their ownership and cleanup records.

No success reply grants a later local execution right. After DISPATCH the server
only services the broker's bounded resource actions and collects terminal data.
The broker alone starts the worker while its enforcement gate is active. Parallel
servers/threads/processes race for the same existing quota/execution lock. One
operation wins; consumed nonces/cases never reopen, including after clean exit,
timeout or process death. Crash, partial write, fsync ambiguity or corrupt/rolled
back history holds capacity and requires external reconciliation; never repair,
truncate, reuse or automatically retry. All broker state is precreated root-owned
0700 directories/0600 regular no-follow files, with native multi-process tests.

## Closed messages and bounded transport

The private machine schema is
`architecture/broker-handoff-inputs/channel.schema.json`. All messages use canonical
JSON, exact builtins, duplicate rejection, no floats/nonfinite values, depth16.
These schemas describe data, not authority. Native custody/enforcement remain
mandatory even when every schema/hash comparison passes.

DISPATCH is one server request with bindingDigest, reservationDigest, runNonce,
caseId, requestDigest, observationDigest, generation and fresh256-bit challenge.
The requestDigest is the existing exact build_probe_request bytes. Broker rebuilds
that request independently. Observation must be current, from the authenticated
server observer and independently match the broker's current active generation.
The broker does not trust a digest alone or accept caller namespace/GVK/argv/URL.

Responses use one common executionId chosen by the broker (256-bit), echo every
DISPATCH binding field, and use a single increasing transcript sequence starting
at1 with all-zero previousDigest. Each subsequent frame in either direction
hashes the exact previous canonical frame. No skipped/duplicate/reordered frame,
new generation, restart, challenge reuse or channel replacement is accepted.
First frame is STARTED (an observation of controlled execution, never a grant).

RESOURCE_ACTION from broker selects only CREATE/GET/DELETE and one manifestDigest
in that case's already-bound set. Server replies RESOURCE_RESULT with the same
actionId, a closed outcome and bounded observed-object data. No action may remain
outstanding when another action, receipt chunk or terminal frame arrives. Worker
uses the same action vocabulary on its private FD3; broker mediates and validates
both legs rather than passing through arbitrary messages or descriptors.

RECEIPT_CHUNK frames contain canonical base64 of at most24KiB decoded data, index
starting0 and contiguous. At most171 chunks and4MiB decoded total. Chunks transport
the unchanged existing unsigned Linux receipt candidate, never executable data.
Terminal COMPLETED/FAILED/UNAVAILABLE binds exact byte size/digest, zero outstanding
actions, broker-observed worker termination and the server cleanup digest.
Missing/truncated/trailing chunks or extra frames cannot complete the operation.
No public receipt schema or signing role changes; only existing independent
qualification can elevate a candidate to native evidence. Never tenant acceptance.

Every datagram <=64KiB; DISPATCH/START/RESOURCE_ACTION <=16KiB. Handshake/control
response phases <=2 seconds, complete operation/receipt/cleanup <=900 seconds
and all signed expiries. While waiting for execution the server checks custody,
authority, observer and deadline at most every2 seconds without a keepalive grant.
Chunks cannot extend the deadline. Channel loss never reconnects or retries.
Server may send one ABORT on the same authenticated channel, with a closed reason;
broker still independently enforces expiry, invalidation and peer death.

## Resource ownership, credential access and cleanup

Broker holds the execution gate before a server resource action. Server rechecks
fresh observation, independently verified authority, active operation and durable
reservation before upstream credential acquisition/use and after blocking I/O.
The server alone owns the separate signed KUBERNETES_PROXY_SERVER_MTLS credential
and numeric TLS API leg. The broker associates this exact run certificate/profile
with the active execution generation in its independently loaded API admission;
there is no new HTTP header or extra Kubernetes field. Zero-resource mode opens
no upstream credential or API socket and refuses every RESOURCE_ACTION.

003 resolves a manifestDigest from its own immutable profile, verifies case
ownership and exact grants, and derives fixed create/get/delete paths. It records
create intent before send, refuses existing names/409 without adoption and persists
returned UID/resourceVersion after validating actual post-defaulting manifests.
API-proxy generation enforcement covers each effect and existing connections;
transport success or a post-I/O read is not that enforcement. Missing enforcement
denies the action rather than contacting a broader API endpoint.

Only server-recorded created names/UIDs may be cleaned. Fresh independent policy,
exact current labels/manifest/UID and UID-preconditioned deletion are mandatory.
No force, selector, name reuse, adoption or destructive migration reversal.
Lost create response records IO_AMBIGUOUS with null UID and holds the exact name;
no blind retry or guessed UID. Failed/expired permission records CLEANUP_PENDING
with the existing reason enum, not automatic cleanup under widened authority.

Before accepting terminal data, the server independently confirms absence of
its exact created UIDs and fsyncs the existing hash-chained internal cleanup
receipt. A worker/broker empty list cannot assert CLEAN. It sends the digest in
one CLEANUP_RECORDED frame only after no action is outstanding and receipt chunks
are complete. Broker terminal echoes this digest; FAIL/pending/ambiguous execution
never yields a PASS case. If terminal delivery is lost, both stores retain the
consumed case and known/ambiguous resources; no distributed commit is invented.
Cleanup permission after invalidation must be independently current at the broker
and API guard or cleanup waits for external reconciliation, without more egress.

## Source acceptance, native follow-up and rollback

Meta tests exercise a non-authorizing shared-state model: concurrent admission,
policy-change deferral/invalidation, replay, old-generation effects, revocation,
zero-resource mode, action/UID ownership, partial writes, crash and cleanup. Tests
must reject boolean/token-only authority and event-list-only proof of enforcement.
No test opens a socket, runs a product module/worker, issues a certificate or
simulates a native PASS. Pin all142 old packets, unchanged127/327 checkpoint and
exact meta replacement recipes; never execute historical source snapshots.

003 tests real fixed client/server factories using OS-mocked transports and all
predecessor tests, including refusal before server credentials if any prerequisite
is absent. 004 tests all ten fixed recipes and the private worker ABI. 005 builds
reproducible inert candidates for the three entries and lists broker/observer as
external unavailable prerequisites. 006 requires real installed peer/custody,
native AMD64/ARM64, coordinated policy changes during actual effects, multi-process
quota races, inherited-FD/direct-worker denial, descendant reaping, crash/lost
delivery, exact-UID cleanup and no external egress. No missing mandatory case passes.

This publication requires22 exact argv commands, including both complete replays,
in the existing signed deny-all process tree. Preserve nested420/trusted900-second
and workflow15-minute limits, bounded fix/retry and failed logs. Required localhost
PR CI, merge and independent local exact-main precede any consumer coding. No root
installation/policy change, new key, administrator prompt, download, hosted runner,
paid API, artifact upload, cloud action or native campaign in this packet.

| Phase | ID / gate | Status during publication | Description |
|---|---|---|---|
| Phase0 / Alpha1 | Foundations | DONE_RECORDED | Source/offline only |
| Alpha2 | MET-REPAIR-013 / PR108 | DONE_SOURCE_GATES | Accepted credential ordering |
| Alpha2 | MET-REPAIR-014 | ONGOING | This closed broker handoff authority |
| Alpha2 | CONF-LIVE-003 | WAITING | Preserve local drafts; finish after authority closure |
| Alpha2 | CONF-LIVE-004 | WAITING | Fixed worker and ten native probes |
| Alpha2 | CONF-LIVE-005/006 | WAITING | Packaging, integration and independent evidence |
| Alpha2 | Native AMD64/ARM64 | NOT_RUN_ENV_UNAVAILABLE | Separate installed qualification |
| Alpha3/4 | Governed actions / enterprise release | WAITING | Existing roadmap |

Before consumption revert this source publication as one reviewed unit; after
consumption use a reviewed successor. Never undo trusted state, tenant data or
historical evidence. Alpha2 remains ONGOING; model-effort transition NOT_DUE.
