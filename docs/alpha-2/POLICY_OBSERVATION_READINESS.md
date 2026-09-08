# Protected policy observation — MET-REPAIR-010

Alpha 2 · approved source-only prerequisite · 2026-09-08.
Catalog: 136 packets, thirteen repositories, four planes, sixteen harnesses.
No implementation, installation, cluster access or native qualification occurs here.

## Decision and preserved authority

The predecessor requires fresh namespace, quota, RBAC and admission observations,
but its API grant is exactly create/get/delete for run-owned Pods, ConfigMaps
and Services. Neither the schema nor semantic validator permits policy reads.
Stored release projections cannot establish present enforcement. This finding
is SOURCE_INSPECTION_ONLY; it is not a reproduced exploit or failed product test.

Preserve MET-REPAIR-009, its private profile/schema/vectors/guide, every public
wire schema/signature role and all 135 predecessor packet YAML byte-for-byte.
Add the local read-only channel below, not another campaign endpoint or broader
Kubernetes rules. The profile remains CAMPAIGN_PROXY_MTLS_ZERO_COST_V1.
No new repo, harness, public API, cloud capability, API key or paid dependency.

Current source inputs: meta main 33de300cabb497044c679d51df13d36d14a4b906,
conformance main 7205075d2f234b622dd61072803b754f1dffeb79, tree
c48d71a7c8d5ddf245e1aab8063ecd9ae2b59834, 127 files / 279 test IDs.
The existing proxy baseline preserves the complete inventory. No product or
warm-source tree is opened by this packet's acceptance.

## Separate runtime owners

| Owner | Component | Authority and scope |
|---|---|---|
| Independent capacity operator | Pre-existing protected observation service | Reports current enforcement from operator-owned capacity controls; never accepts caller API selectors or mutations |
| CONF-LIVE-003 | Fixed local channel consumer in live_proxy_server.py; data checks in live_mutation_admission.py | Verifies peer custody and bound observations; never gains observer credentials or upstream sockets |
| CONF-LIVE-004 | Fixed probe adapters | Consume server-owned verified observations; no alternate observation backend |
| CONF-LIVE-005 | Client/server candidate packaging and handoff | Documents the observer as a separately installed prerequisite, not an included or provisioned service |
| CONF-LIVE-006 | Integration and manual qualification | Rechecks native observation and fencing evidence; no source-to-native promotion |

The producer is an external operator prerequisite, like the pre-existing API
proxy and admission controls, not an unimplemented product packet disguised as
DONE. An operator must supply an open-source, reviewed implementation meeting
this protocol and the native tests below. This publication does not claim that
one is installed or available. Without it the platform source can be built,
but protected live execution is NOT_RUN_ENV_UNAVAILABLE. No configurable
callback, command, Python import or generic observer fallback is allowed.

## Fixed local transport and code custody

Only the independently installed protected proxy server may connect:
- AF_UNIX / SOCK_SEQPACKET, pathname /run/planeon/live-proxy/policy-observer.sock.
- Directory root:root 0700; socket root:root 0600; no symlink or alias ancestry.
- Peer executable /opt/planeon/bin/harness-policy-observer, root:root 0555.
- Manifest /etc/planeon/harness-policy-observer-manifest.json and .json.sig.
- Existing /etc/planeon/harness-live-runner-manifest.pub and pinned root key.
- Same closed root-manifest shape, version 0.1.0 and detached Ed25519 verification;
  launcher.path is this observer executable, not the campaign/client/server.
- Producer is a preinstalled native ELF process. Dynamic executable dependencies,
  mappings and OS containment must be independently pinned/qualified by the
  operator; a signed executable digest alone cannot prove a running process.

No TCP/DNS/socket environment option, SCM_RIGHTS FD, caller-owned socket, token
or response boolean supplies authority. Verify root-owned no-follow files and
retained identities; verify SO_PEERCRED and per-message SCM_CREDENTIALS,
UID/GID, PID/start identity, pidfd liveness, executable inode/digest and qualified
process containment before and after blocking I/O. Reject truncation, unexpected
ancillary messages or descriptor passing; close any received descriptors.
Peer replacement, socket unlink/rebind, changed manifest/executable/trust or
process restart terminates the session rather than reconnecting silently.

The observer authenticates the server symmetrically using the fixed
/opt/planeon/bin/harness-live-proxy-serve installation and retained kernel
process identity. Root UID alone is insufficient. The campaign child has no
socket mount, FD, observer path or credentials. The server constructs the local
channel only after its own installed custody and initial OS containment checks;
this is one explicit read-only server channel, not an ambient credential socket.

The new release-listed canonical file is exactly
campaigns/platform/linux-baseline/policy-observation-binding.json (0444).
Its exact path/mode/size/hash occurs once in the signed kit tree. It binds the
unchanged profile byte digest, scope, observer manifest/executable digests,
namespace UID, seven policy projection identities, and enforcement proof pins.
It contains no release/self digest, secret, endpoint or selectable file path.
Both envelope signatures cover its release. Independently verified capacity
scope/profile entries and operator-installed observer enrollment must also
match; release approval alone cannot authorize an observer.

## Closed messages and validation

The local machine definition is architecture/policy-observation-inputs/channel.schema.json.
It defines three closed data variants: binding, request and observation.
Only operation OBSERVE_POLICY exists. The request supplies bindingDigest,
runNonce, a fresh 256-bit challenge, increasing sequence and previousObservationDigest.
No namespace/name/path/GVK/verb selector, command or mutation is accepted.
The producer independently loads the same dual-signed release and capacity
from its operator placement, never from a request. Verify both envelope signatures
before selected references, then the independent capacity signature, all three
signer scopes/windows/revocation, profile, projections and observer binding.

One datagram each way, canonical JSON, request <= 16 KiB, response <= 64 KiB,
depth <= 16, no duplicates/floats/nonfinite values/builtin subclasses.
The original product canonical codec, exact integer and Unicode rules apply.
Each exchange has an absolute monotonic timeout <= 2 seconds and cannot extend
the outer <= 900-second session or signed expiry. Observation validity is
half-open and <= 5 seconds, inside profile validity. UTC and monotonic rollback
both refuse; all blocking operations recheck deadlines and peer/trust custody.

Echo challenge, bindingDigest, runNonce, sequence and previousObservationDigest
exactly. Sequence starts at one; previous digest is all-zero only for sequence
one. Preserve boot ID and generation throughout an active reservation. After
each response, retain SHA256 of its exact canonical bytes and require that digest
in the next request/response. No reboot, generation change, replay, stream gap,
rollback or reconnect can refresh an existing reservation into authority.

Response contains the exact namespace identity and seven ordered-by-key
policy identities/digests plus nonempty resourceVersion observations. Keys:
admissionPolicy, resourceQuota, limitRange, serviceAccount, rbac, networkPolicy,
mutationBroker. Match every identity and digest against the release-bound binding
and original profile; do not treat volatile resourceVersion as a replacement
for the enforcement projection digest. Quota hard/used use the six bounded
integer units from the existing profile. used <= hard and whole-run requested
headroom <= hard-used, in addition to profile quota and atomic reservations.
Even a zero-resource profile requires this local observation channel; it still
makes no Kubernetes API request and gets no API endpoint or second credential.

The enforcement record binds the same policy generation and independently
qualified admission-fence, effective-RBAC-closure, network-enforcement and host
preflight evidence digests to release-pinned expected values. The observer must
derive these from actual active controls, not echo the requested binding or
load stored projections as observations. Pure schema/semantic validation returns
DATA_CHECK_ONLY (represented by an empty error list), never a protected handle
or native acceptance. Peer custody, producer qualification and real enforcement
are separate mandatory checks even when every digest matches.

## Freshness is not transactional admission

Read-only observation cannot lock Kubernetes policy or replace mutation admission.
The separately existing capacity broker must enforce a common policy generation
at each create/get/delete and fixed probe boundary. It associates the authenticated
run-specific certificate/profile with that generation through its independently
loaded authority, not a new campaign header or additional manifest field.
Before committing a mutation, its immutable admission guard rechecks current
namespace/UID, effective RBAC, quotas, network policy and actual post-mutation
manifest under the broker's serialized admission transaction.

Changing effective controls, watch gaps, unobserved bindings, broker/observer
restart, loss of continuity or inability to fence current policy invalidates
the generation and denies new effects. Complete effective RBAC means all
applicable grants/aggregations and impersonation paths, not only named Role
objects. Producer backend observations must establish completeness; a cached
resource list with no completeness/continuity proof is unavailable.
An operator without this existing backend must qualify one separately; it
cannot substitute an always-success mock or weaken the gate.

Reserve and fsync nonce/whole-run headroom in the existing durable server store
before probe or credential access. Obtain fresh observations before opening
credentials, before each operation/mutation and after blocking I/O. Observation
is read-only: it creates no cluster resources and does not release reservations.
A stale/failed read does not permit a mutation retry. Generation drift fails
closed and retains consumed nonce/history and ambiguous resource reservations.

Cleanup retains the exact existing UID-preconditioned scope. It may proceed
only if independently current authority and the broker can still prove that
exact cleanup permission; otherwise record CLEANUP_PENDING with existing
OBSERVATION_UNAVAILABLE/UID_CHANGED/DEADLINE reasons. Never delete by selector,
force, finalize, widen scope or mark CLEAN merely because an observation expired.

## Source acceptance and native follow-up

CONF-LIVE-003 implements real fixed-path transport/validation in its existing
three modules and negative tests in its existing three tests. Its own fixture
pins this authority and the unchanged 127-file/279-ID baseline. No additional
file grant, dependency or test exception: eight paths/eight commands and stages
110/120/127/135/141/146/151 remain. Consume this amendment only after local/head,
required self-hosted PR CI, merge and independent local exact-main closure.

Meta tests exercise structural/semantic rejection and the unchanged profile's
refusal of extra policy API rules. They never open a socket, read credentials,
run product code, simulate native PASS or contact a cluster. Required native
follow-up separately covers real peer spoofing/FD injection/process replacement,
namespace policy drift and generation races during mutation, complete RBAC,
observer restart/loss, stale quota, absent producer, empty-resource mode,
credential-before-observation refusal and exact-UID cleanup after failures.
All must use independent installed custody and actual existing native capacity.

Missing backend/capacity/observer is NOT_RUN_ENV_UNAVAILABLE; malformed or
substituted authority is FAIL. Source, CI, merge, package, installation, native
AMD64/ARM64, runtime, assurance and tenant acceptance stay separate.
No new public signature role or claim of platform/tenant acceptance.

## Roadmap, timing and rollback

| Phase | ID | Publication status | Description |
|---|---|---|---|
| Phase 0 / Alpha 1 | Recorded foundations | DONE source/offline | Runtime acceptance separate |
| Alpha 2 | MET-REPAIR-009 / CONF-LIVE-001/002 | DONE source gates | Prior PR closures remain separate |
| Alpha 2 | MET-REPAIR-010 | ONGOING | This observation authority and data oracle |
| Alpha 2 | CONF-LIVE-003 | WAITING | Consume merged observation authority |
| Alpha 2 | CONF-LIVE-004/005/006 | WAITING | Probes, packaging, final integration |
| Alpha 2 | Native qualification and runtime packets | WAITING | Actual observer/capacity and native evidence |
| Alpha 3–4 | Governed actions / enterprise matrix | WAITING | Existing DAG unchanged |

MET-REPAIR-009's first local exact-main run hit the unchanged 420-second nested
predecessor timeout; an identical retry passed. Keep both results. This packet
adds data tests and must not relax that timeout, skip tests or claim timing
headroom from a retry. One bounded unchanged retry is allowed; recurring
timing failure needs diagnosis, not a green-status substitution.

Before consumption, revert this publication as one unit. After consumption use
a reviewed corrective successor; never rewrite accepted authority, trust/replay
history, tenant data or failed evidence. No root installation/runner-policy change,
key issuance, cloud action, hosted runner or artifact upload is authorized.
Alpha 2 remains ONGOING; no phase-end model-effort change is due.
