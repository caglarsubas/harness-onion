# Proxy contract readiness — MET-REPAIR-009

Alpha 2, approved 2026-09-08. This is a source-only authority supplement, not
an installed service, certificate issuer, live admission decision or runtime test.
Catalog: 135 packets, thirteen repositories, four planes and sixteen harnesses.
Twelve possible manual campaign declarations remain unchanged.

## Diagnosis and compatibility decision

Conformance main `7205075d2f234b622dd61072803b754f1dffeb79` has 127 tracked
files and 279 accepted tests. Its PR 9, required CI 34182386653 and independent
LOCAL exact-main replay remain valid source evidence. No product tests or live
requests were executed for the new diagnosis: SOURCE_INSPECTION_ONLY.

The v1alpha1 capacity schema closes its top level but leaves nested rule and
credential objects unrestricted. validate_capacity checks the seven arrays'
type/length, not their contents. The schema closure test checks only the root.
The newer fixed request builder does close campaignProxyRules; do not claim
that this narrower protection is absent or that a runtime escape was reproduced.

Decision: keep every existing public schema, signature payload/role and packet
YAML byte-identical. Publish the stricter private execution profile
`CAMPAIGN_PROXY_MTLS_ZERO_COST_V1`, a subset of existing capacity field
values, for the new proxy only. Passing legacy structural validation never
satisfies this profile. No legacy validator's return value is execution authority.
Unknown/absent/older profile means unavailable, not permissive compatibility.
Malformed or substituted authority means FAIL.

The machine definition is
[profile.schema.json](../../architecture/proxy-contract-inputs/profile.schema.json);
the independent unit-only examples are
[vectors.json](../../architecture/proxy-contract-inputs/vectors.json).
Schema validation is only a data check; it does not authenticate TLS, capacity,
actual quota, RBAC, installed custody or a kernel peer.

## Ownership and immutable dispatch

| Phase | Owner | Exact responsibility |
| --- | --- | --- |
| Alpha 2 | MET-REPAIR-009 | This meta authority, closed data oracle and tests |
| Alpha 2 | CONF-LIVE-003 | Client, server, admission, three tests, one fixture and one guide; eight existing paths |
| Alpha 2 | CONF-LIVE-004 | Actual fixed probes and native observations in six existing paths |
| Alpha 2 | CONF-LIVE-005 | Reproducible candidate archives and independent operator handoff in five existing paths |
| Alpha 2 | CONF-LIVE-006 | Final bounded launcher hook, evidence adapter and manual declaration |
| Alpha 2 | External operator/tenant | Installation, preflight, native qualification and independent acceptance |

MET-REPAIR-009 must close source/local/required localhost PR CI/merge/local
exact-main before CONF-LIVE-003 begins. This is an additional dispatch
prerequisite, not an edit of the consumed packet predecessor list.
No extra product file or test exception is granted. Stage totals remain
110/120/127/135/141/146/151. All 279 immediate predecessor IDs, original 120 IDs,
intervening source guards, six suite roots and eight product commands remain.

The profile schema and vectors are specification data only. CONF-LIVE-003
implements equivalent stdlib validation in its three new modules, with
independent negative tests in its three owned tests. It must pin this authority
and preserve the immediate 127-file/279-ID baseline in its owned fixture.
No jsonschema dependency is introduced into the product.

## Profile and digest custody

The private profile is the exact canonical JSON file
`campaigns/platform/linux-baseline/proxy-profile.json` inside the signed kit.
Its path/mode/size/SHA256 must occur exactly once in the existing release tree;
the release digest is covered by both existing envelope signatures. Its
capacityEntries are byte-for-byte equal (canonical JSON) to the corresponding
members of the independently capacity-signed authorization. Missing references,
duplicate keys, noncanonical JSON, unsupported versions and unknown fields
refuse before credential use. Maximum profile 256 KiB, depth 16, 32 manifests.
Each manifest is at most 16 KiB canonical JSON; digest means SHA256 of those
exact bytes. No self-digest or release digest is embedded in the profile:
the release hashes the profile, never a circular reference.

binding fixes tenant/environment, runNonce, capacityNonce, endpoint, apiEndpointId, namespace,
serviceAccountSubject and a UTC half-open validity window of at most 900 seconds.
These equal the independently verified envelope/capacity/plan scope; the profile
window is inside their three-signer/trust intersection. Capacity nonce and run
nonce are distinct fields, not assumed equal. Release/packet/command/source/
endpoint/capacity digests remain in the existing protected session binding.
No profile/header/FD/boolean supplied by a campaign chooses a trust source.

policy pins namespace, quota, LimitRange and ServiceAccount UIDs plus admission,
quota, LimitRange, RBAC, NetworkPolicy and fixed mutation-broker digests. Each
digest covers canonical, release-listed observation projection bytes:
`{apiVersion,kind,metadata:{name,namespace,uid},spec}`; cluster-scoped objects
use namespace null. Include enforcement configuration in spec, never volatile
status/resourceVersion. Projections reside at fixed release-listed paths
campaigns/platform/linux-baseline/proxy-policy/<field>.json, where field is
admissionPolicy, resourceQuota, limitRange, serviceAccount, rbac, networkPolicy
or mutationBroker; each matching <field>Digest pins its bytes. The namespace
identity comes from the signed namespace name/UID and a fresh server observation.
UID/resourceVersion and observed quota usage are checked
separately against the live server at admission; a stored projection is not proof
that the actual cluster still enforces it. Actual inputs must be independently
observed; a client-supplied `immutable=true` or policy digest cannot satisfy them.

The existing admissionPolicyDigest/resourceQuotaDigest/limitRangeDigest equal
profile policy, capacity, envelope where those fields exist, release-listed
policy bytes and actual independently observed server-side policy. All required
preexisting ResourceQuota/LimitRange/ServiceAccount references carry exact
API identity/namespace/name/UID/observedDigest. Other names, duplicate logical
identities (even with different bytes), writable ancestry or changed ownership
fail. Reference arrays are not wildcard permissions.

## Client authentication and transport

Only CAMPAIGN_PROXY is a campaign-client mode. Preserve the ten closed POST
paths and unchanged build_probe_request body; no URL, argv, GVK, image selection,
credential scope or namespace override is accepted. No new auth header or
bearer fallback. Production `execute_protected(request, context, deadline)`
consumes only the actual NativeSupervisor-owned InstalledContext and active
kernel-bound session; explicit injected unit adapters cannot enter that path.

Use tenant-local mutual TLS 1.3, with chain validation, EKU and identity checks,
no TLS early data or session resumption. The client pins one signed IP family/
literal/port, TLS serverName and leaf SPKI digest, plus only the release-bound
local CA. Use a numeric-family socket, not getaddrinfo/create_connection,
automatic redirects, proxy variables, DNS or IPv4/IPv6 fallback. The connected
peer tuple must still match. Server and client require certificates, no
CERT_NONE, CN-only fallback, system CA fallback, key logging, public OCSP,
certificate discovery or network key issuance.

credentialIdentities contains exactly one closed entry for this campaign client:
endpointId, purpose=CAMPAIGN_PROXY_CLIENT_MTLS, service-account subject,
expiresAt, SHA256 of leaf DER certificate and SHA256 of DER SubjectPublicKeyInfo.
The record is independently capacity-signed. Certificate identity is exactly one
URI SAN:
`urn:planeon:campaign-proxy:<tenantId>:<environmentId>:<runNonce>:<endpointId>`.
No wildcard, alternate subject or extra URI SAN is allowed. Require clientAuth
EKU, not a CA certificate, exact leaf/SPKI pins, and certificate validity
containing the profile window; credential expiry equals profile expiry.
The server derives the expected SAN from its independently loaded profile;
it never trusts request headers to choose a tenant or certificate.

The signed credentialFileReference names a root-owned 0400 PEM bundle containing
one private key and the matching short-lived leaf/chain, on the client host.
Read it once only after the supervisor boundary and durable reservation.
Match the certificate and capacity identity before use; never export the path
or bytes to the unprivileged child or evidence. A product-created sealed
Linux memfd may convey the already-verified bytes to stdlib load_cert_chain
through a retained /proc/self/fd reference; caller-owned FDs do not grant
authority. Require seals, no inherited descriptors, and close after TLS context
load. No disk temporary secret, shell/OpenSSL invocation, SDK or new dependency.
The PEM content digest may enter sanitized internal evidence, never its contents.

Revocation material is local, root-custodied and release/tenant-trust bound.
Check all three signer keys for scope/revocation/validity again at every
operation and after blocking I/O; stale stores stop execution. The proxy
credential is nonce-specific and independently enrolled for that capacity.
Compromised/revoked credential pins are removed by the external operator; a
running process must detect revocation before its next operation. No automatic
file refresh may silently replace a signed trust digest. Recheck retained
descriptor/named-inode metadata and validity without reopening an authority
path for execution. A replaced/changed/revoked enrollment or trust file stops
the process; do not silently load a new record into an active reservation.

HTTP/1.1 is one request per connection, fixed Host and application/json.
Require a single canonical Content-Length, bounded headers (16 KiB), and exact
body length; refuse chunked/TE/CL ambiguity, compression, upgrade, pipelining,
redirects, duplicate headers, absolute-form URLs, fragments, percent-encoded
path alternatives, surplus/truncated data and non-200 success transport.
Bodies are at most 16 KiB request / 4 MiB response. Handshake, header, body,
probe and cleanup share an absolute monotonic budget capped by 900 seconds
and signed expiry. Recompute remaining time after every blocking operation;
slow trickle traffic cannot extend the deadline. Connect/handshake/header
phases are additionally capped at 10 seconds each.
Rejected transport never gets retried automatically after an ambiguous mutation.
The existing receipt checker still binds case/nonce/probe/command/output and
observation time; it never grants native or tenant acceptance.

## Independent server custody

The server is a distinct operator-managed process/host, not the campaign child.
CONF-LIVE-003 defines a fixed `NativeProxyServer()` factory and `main()`;
no runtime backend/module/argv/trust/credential path selection is accepted.
CONF-LIVE-005 packages a separate fixed entry point that invokes that main:

- executable: /opt/planeon/bin/harness-live-proxy-serve, root:root 0555;
- manifest/signature: /etc/planeon/harness-live-proxy-manifest.json and .json.sig;
- public trust: the unchanged /etc/planeon/harness-live-runner-manifest.pub and
  existing pinned root-public-key digest;
- TLS server key/chain: /etc/planeon/live-proxy/server-identity.pem, root:root 0400;
- durable state: /var/lib/planeon/live-proxy, root:root 0700, precreated
  admission.lock and reservations.jsonl files root:root 0600.

Reuse the existing closed root-manifest shape/schema and detached Ed25519
verification, with launcher.path fixed to the server executable, its exact
artifact digest/version and the two existing fixed trust mounts. The server's
signed manifest is independently installed; it is NOT the client manifest and
does not pass the unchanged client installed_process helper. The new server
checks are owned only by CONF-LIVE-003. No new root key or signature role.
Existing isolation/credentialSocketsDenied/ciDenied meanings are retained.
Missing independently attested server isolation/preflight must refuse startup;
a signed declaration alone cannot establish active containment.

The only startup input is the existing HARNESS_LIVE_EXECUTION_ENVELOPE path,
placed independently by the server operator. No client request supplies it.
On this host independently verify both envelope signatures before selected
reference reads, the separate capacity signature, exact packet006/eight commands,
release/kit/profile, local trust, all scopes and nonces. Bind listener solely
to the signed CAMPAIGN_PROXY tuple; match server TLS key/certificate to signed
serverName/SPKI. Both sides use the tenant-local release-pinned CA bundle.
No generic admin/health/exec/debug endpoint is added.
No caller-owned socket, environment flag or valid client certificate bypasses
the independent source/capacity/policy checks.

For Kubernetes mutations the protected server may use only a separately
declared, already-running KUBERNETES_API_PROXY endpoint in the same signed
endpoint set and capacity, with the exact closed kubernetesApiRules.
This is a server-only leg; campaign-client KUBERNETES_API_PROXY mode stays
unsupported. Reuse the same literal-IP/TLS/size/deadline/custody protections.
No raw Kubernetes, Docker, containerd, cloud-agent socket or generic kubeconfig
is exposed to campaign code. Absent scoped server credentials/API proxy or
actual immutable admission/RBAC proof means NOT_RUN_ENV_UNAVAILABLE.
When resources is nonempty, apiEndpointId is a distinct signed
KUBERNETES_API_PROXY endpoint, and credentialIdentities has one additional
entry with purpose KUBERNETES_PROXY_SERVER_MTLS, that endpoint ID, the same
scoped service-account subject/expiry, and distinct leaf/SPKI pins. Its SAN
uses urn:planeon:capacity-proxy with the same tenant/environment/nonce/endpoint
components. Its credentialFileReference is on that signed API endpoint, opened
on the server only, using the same read-once/0400/memfd rules. No raw kubeconfig,
ambient service-account token or reused campaign key is allowed. Exact create,
get and delete API rules must cover every signed manifest, with no extra rule.
Without resources, apiEndpointId is null, the second credential and API/GVK
rules are absent. No server API request is then permitted.
Only preinstalled fixed CONF-LIVE-004 adapters may submit a manifest already
selected from the server-owned signed profile; no arbitrary callback/module.

## Exact mutations, quota and cleanup

The first profile supports only namespaced v1 Pod, immutable ConfigMap and
ClusterIP Service templates in the closed schema. It deliberately rejects
controllers, unknown kinds/fields/annotations, PVCs/PVs/StorageClasses/snapshots,
accelerators, LoadBalancer/ExternalName/NodePort, Ingress/Route, RBAC/policy/quota
changes, autoscaling, arbitrary exec and cloud/billing calls. Storage/accelerator
reference arrays must be empty in this first profile. Missing capacity required
by a probe is unavailable, not authorization to add another kind.
No destructive migration reversal or existing tenant-data mutation.

Manifests carry exactly tenant and run-nonce labels and their signed namespace/
name. Pods have one container, no init/ephemeral containers, no host namespaces,
service-account automount, extra capabilities or privilege escalation. Root
filesystem is read-only. The signed UID is 10000..2147483647, not fixed to one
UID; this retains arbitrary-nonroot qualification. Only immutable local images
already present and digest-bound to the signed release/plan are admissible.
imagePullPolicy is explicitly Never: cache loss must fail, never trigger a pull.
Container seccompProfile is explicitly RuntimeDefault; omitted or Unconfined
profiles are rejected rather than relying on cluster defaults.
No command/args/env/hostPath/network override is accepted from a request.
Workloads requiring unrepresented writable volumes are unavailable; adding
templates later requires separate reviewed profile authority, not a fallback.

Per-pod requests equal limits. Accepted quantities are bounded decimal
millicpu and decimal bytes only; no floats, exponents, negative/boolean/overflow
or alternate unit interpretation. Count pods/configmaps/services and sum
cpuMillis/memoryBytes/ephemeralStorageBytes. The reservation uses the exact
whole run's simultaneous maximum, never a caller estimate. Compare to both
signed quota headroom and independently observed actual existing usage.
ResourceQuota alone does not prove admission or billing safety.
Mutation admission must also validate actual post-defaulting/post-mutation
objects: reject an injected sidecar, image change or policy bypass.
API-server-assigned UID/resourceVersion/creation metadata and allocated
ClusterIP may be observed only as non-authorizing fields, never new endpoints.

Before any probe/credential/mutation, atomically reserve
(tenantId, environmentId, runNonce, capacityNonce, endpointId, releaseDigest,
packetDigest, commandSetDigest, profileDigest) in the server's independently
root-custodied durable store. One active operation per protected server/quota;
simultaneous requests must race for a single shared flock/transaction, not
separate per-thread/per-worker in-memory counters. Only the ten fixed operations
may be consumed once per reservation, with binding and certificate rechecked.
Close/success/failure/expiry/crash never frees a nonce. Partial journal writes,
fsync ambiguity, full storage, rollback or corrupt history fail closed; no
repair/truncation/reinitialization. Reserve then fsync+readback before side effects.
A crash leaves capacity held until externally reconciled, never optimistically
available. Native tests must exercise multiple processes, not only mocks.

Creates require absent exact names and server-side name/kind/manifest admission.
Kubernetes RBAC cannot by itself constrain a create by resourceNames; admission
must enforce those names, manifests and labels. A 409 or preexisting name is
not adopted, overwritten or deleted. Persist returned UID/resourceVersion.
Cleanup deletes only exact created name + recorded UID precondition, after
fresh scope/label/manifest ownership checks. No selector-wide/deletecollection/
namespace deletion, force/finalizer removal, existing-resource takeover or
resource-name reuse. Only confirmed absence of those exact UIDs releases
resource reservations; nonce/receipt history remains consumed permanently.

An internal cleanup receipt (not an existing public Linux case record) has
exact fields schemaVersion=planeon.internal.proxy-cleanup/v1, bindingDigest,
operation, observedAt, state, remainingResources and previousReceiptDigest.
state is CLEAN or CLEANUP_PENDING. Each remaining entry is exactly
apiVersion, kind, namespace, name, uid, manifestDigest, reasonCode; reasons
are DELETE_DENIED, UID_CHANGED, DEADLINE, IO_AMBIGUOUS or OBSERVATION_UNAVAILABLE.
No secrets, arbitrary error text or external URLs. Maximum 32 entries/16 KiB;
canonical bytes are hash-chained and fsynced alongside the consumed reservation.
CLEAN requires empty remainingResources and independently confirmed deletion;
CLEANUP_PENDING requires nonempty entries. Lost create response records
IO_AMBIGUOUS with uid=null, reserves the exact name and never deletes without
an independently recovered matching UID. No blind create/delete retry.
Existing Linux receipt shape stays unchanged and must report FAIL or
NOT_RUN_ENV_UNAVAILABLE as appropriate, never PASS for unproved cleanup.
CONF-LIVE-006 references the independent sanitized cleanup evidence without
inventing tenant acceptance or altering existing public signature fields.

## Coding acceptance and negative cases

CONF-LIVE-003 must independently cover every closed nested object (extra/missing/
wrong-type/duplicate logical key), every tenant/environment/nonce/endpoint/
subject/expiry/leaf/SPKI/CA substitution, revoked signer or credential,
cross-context/caller-owned FD, uninstalled server, missing immutable policy,
DNS/redirect/family fallback, malformed/oversize/late HTTP, every denied kind,
post-admission mutation, image substitution, numeric overflow, overlapping
quota races, replay/crash/partial-write boundaries and exact-UID cleanup.
Tests use explicit UNIT_ONLY adapters; no socket/credential/root policy/native
probe or certificate issuance is performed in offline source acceptance.

Required native follow-up is separate: real TLS chain/EKU/identity/expiry and
revocation, installed client/server custody, OS egress containment, actual
policy/RBAC denial, simultaneous process reservations, lost response/restart,
UID-reuse cleanup, workload filesystem/UID matrix and zero external egress.
Unavailable prerequisites do not pass any mandatory case.
A source fixture must not satisfy any of these native assertions.

## Evidence, rollback and sources

Meta acceptance runs fifteen direct-argv commands through the existing signed
offline launcher, then required ephemeral localhost PR CI and independent LOCAL
exact-main. Product implementation/native/runtime/assurance/tenant acceptance
remain NOT_RUN_ENV_UNAVAILABLE. No phase completion or effort transition is due.
Before consumption revert the unaccepted publication as one reviewed unit;
after consumption use a corrective successor. Preserve historical signed packet
bytes, trust/replay state, failures, test IDs and tenant data.

Implementation references (not runtime network dependencies):
[Python 3.12 SSL](https://docs.python.org/3.12/library/ssl.html),
[Kubernetes resource quotas](https://kubernetes.io/docs/concepts/policy/resource-quotas/),
[admission control](https://kubernetes.io/docs/reference/access-authn-authz/admission-controllers/),
[API concurrency](https://kubernetes.io/docs/reference/using-api/api-concepts/).
These support the platform primitives; the stricter limits above are this
project's approved profile decisions, not claims that upstream defaults enforce them.
