# Trusted Live-Campaign Runner Contract

Current Alpha-2 dispatch: [MET-REPAIR-014 broker handoff](alpha-2/BROKER_HANDOFF_READINESS.md).
Catalog 143; corrected conformance main9df7dd7 preserves 127 files / 327 tests.
MET-REPAIR-013 source gates are closed. Close this broker handoff authority before CONF-LIVE-003.
Older publication sections below retain their historical states, not current instructions.

This contract defines the runtime verification semantics for
[`live-campaign-execution-envelope.schema.json`](../schemas/live-campaign-execution-envelope.schema.json)
and the closed `liveCampaignExecution` task-packet record. The schema is the
machine-readable authority for field names and structure; this document defines
signature coverage, trust roles, digest recomputation, file custody, capacity
authorization, proxy behavior, and fail-closed execution.

A packet record declares a possible manual post-merge run. It is not itself
permission to contact a target. Missing trusted installation, envelope, local
trust, valid capacity, isolation, admission, or proxy capability yields
`NOT_RUN_ENV_UNAVAILABLE`; it never permits a weaker runner or online fallback.

## Reproducible artifact and external authority

`CONF-001` implements and reproducibly builds the trusted live-launcher artifact
and records its digest. Checked-out source, a repository script, and a freshly
built artifact have no pre-boundary authority. The artifact gains authority only
after an independent protected-owner review installs the reviewed bytes as:

```text
/opt/planeon/bin/harness-live-campaign-launch
```

The installed launcher is UID/GID `0`, mode `0555`, and version/digest-pinned by
the independently signed root-owned runner bundle at exactly:

```text
/etc/planeon/harness-live-runner-manifest.json
/etc/planeon/harness-live-runner-manifest.json.sig
/etc/planeon/harness-live-runner-manifest.pub
```

The closed manifest binds the launcher path/version/digest/owner/mode, supported
envelope and capacity-schema versions, fixed trust mounts, available isolation
backend, credential/socket denial, CI-context denial, and a passing preflight
evidence digest. Its detached Ed25519 signature and pinned public-key digest are
verified before the envelope or checkout is opened. A repository, Make target,
campaign, task packet, container entry point, or GitHub workflow cannot install,
replace, or invoke a substitute. `./ci/verify-live-campaign.sh` is an optional
inner implementation detail entered only after the trusted launcher establishes
the boundary; direct invocation fails and checked-out source is never the
pre-boundary launcher.

The packet-declared live invocation is exactly:

```text
/opt/planeon/bin/harness-live-campaign-launch
```

Its only packet-declared launcher input is the canonical absolute file path in
`HARNESS_LIVE_EXECUTION_ENVELOPE`. The fixed read-only trust mounts are exactly:

```text
/etc/planeon/trust/release-trust-bundle.json
/etc/planeon/trust/tenant-trust-bundle.json
```

There is no endpoint-manifest, packet, capacity, proxy, trust, credential, or
checkout path environment variable. Every other absolute local reference is a
field inside the dual-signed envelope. The launcher refuses GitHub Actions,
pull-request, scheduled-CI, or other CI execution context.

The placement is exclusively `PREINSTALLED_TARGET_LOCAL_EPHEMERAL_RUNNER`; no
other placement is valid. The runner may exercise a Kubernetes or OpenShift
target only through a signed `KUBERNETES_API_PROXY` or `CAMPAIGN_PROXY`
endpoint after establishing the host OS boundary.

## Exact execution-envelope shape

The envelope is a closed RFC 8785 JCS JSON object with exactly these top-level
fields, matching the machine schema:

```text
schemaVersion
packetId
packetFileReference
packetDigest
commands
commandSetDigest
conformanceKitRoot
conformanceKitDigest
campaignId
campaignDefinitionFileReference
campaignDefinitionDigest
campaignReleaseFileReference
campaignReleaseDigest
launcherDigest
bundleFileReference
bundleDigest
allowedEvidenceAxes
tenantId
environmentId
capacityAuthorizationId
capacityAuthorizationFileReference
capacityAuthorizationDigest
mutationProfile
admissionPolicyDigest
resourceQuotaDigest
endpoints
issuedAt
expiresAt
nonce
releaseTrustStoreDigest
tenantTrustStoreDigest
platformSignerKeyId
platformSignature
tenantSignerKeyId
tenantSignature
```

`schemaVersion` is
`harness.planeon.ai/live-campaign-execution-envelope/v1alpha1`. Digests use
`sha256:<64 lowercase hexadecimal characters>`. `commands` is the complete
ordered direct-argv list and equals the selected packet's
`liveCampaignExecution.commands`; `commandSetDigest` covers the canonical
ordered array. A shell executable or command string is invalid.

File digests are `sha256:` followed by SHA-256 over the file's exact bytes.
`commandSetDigest` is SHA-256 over
`UTF8("planeon.harness-live-command-set/v1alpha1\u0000")` followed by RFC 8785
JCS of `commands`. `conformanceKitDigest` is SHA-256 over
`UTF8("planeon.harness-live-tree/v1alpha1\u0000")` followed by JCS of a
UTF-8-bytewise path-sorted array whose entries are exactly `path`, `mode`,
`size`, and exact-file-byte `sha256`. Paths are slash-separated, relative,
Unicode NFC strings. Symlinks, hard-link aliases, devices, sockets, FIFOs,
unknown entry types, duplicate normalized paths, and writable files are
invalid; empty directories and timestamps are not hashed. The campaign release
contains the same tree manifest, so two implementations cannot choose different
directory-digest rules.

The launcher recomputes and compares:

- `packetDigest` against `packetFileReference`, then verifies `packetId`, exact
  commands, and axes against that packet;
- `conformanceKitDigest` as the deterministic Merkle digest of
  `conformanceKitRoot`;
- `campaignDefinitionDigest` and `campaignReleaseDigest` against their exact
  referenced files, including the campaign/release relationship;
- `launcherDigest` against its installed reviewed bytes;
- `bundleDigest` against `bundleFileReference` and the campaign release; and
- `capacityAuthorizationDigest` against
  `capacityAuthorizationFileReference`, then verifies its ID and signer; and
- both trust-store digests against the two fixed mounts.

Any mismatch is `FAIL` before campaign code. Mutable tags, Git branches, implicit
working-directory discovery, runtime downloads, or replacement files cannot
satisfy a digest.

## Signature payload and trust roles

The signature payload is exactly:

```text
UTF8("planeon.harness-live-execution-envelope/v1alpha1\u0000")
|| RFC8785_JCS(envelope with only platformSignature and tenantSignature removed)
```

Both Ed25519 signatures cover those identical UTF-8 bytes. The signer key IDs,
all digests, commands, axes, endpoints, capacity binding, mutation/admission
binding, tenant/environment, validity window, and nonce remain in the signed
payload. Signature values are unpadded base64url. Removing any other member,
substituting a null value, or changing array order changes the payload.

`platformSignerKeyId` resolves only from the fixed release trust bundle and must
have purpose `PLATFORM_RELEASE`. Its signature authorizes the immutable released
packet, conformance kit, campaign release, launcher, and bundle combination.
`tenantSignerKeyId` resolves only from the fixed tenant trust bundle and must
have purpose `TENANT_LIVE_EXECUTION` for the exact tenant and environment. Its
signature authorizes that exact released execution and endpoint set. The keys
and identities are distinct; neither role can satisfy the other.

Each trust bundle is itself locally integrity-pinned, maps a key ID to exactly
one Ed25519 public key, owner, purpose, scope, validity, and revocation state,
and contains or digest-binds the current signed revocation material. Unknown,
ambiguous, duplicated, expired, not-yet-valid, scope-mismatched, purpose-
mismatched, or revoked keys fail closed. `releaseTrustStoreDigest` and
`tenantTrustStoreDigest` must match the mounted bytes. Revocation verification
is mandatory and never performs OCSP, key-server, or public-network lookup;
air-gapped sites update both stores through local custody transfer.

The two envelope signatures do not include `CAPACITY_OPERATOR`. Capacity is an
independent third authority on the separately signed capacity authorization
described below.

## Local-reference custody

After validating the envelope path itself, the root-owned launcher derives all
other absolute local paths only from the verified envelope. It opens every
reference with no-follow semantics, rejects traversal, symlinks, noncanonical
paths, unexpected file type/owner/mode, writable parent-chain substitution, and
path changes, reads each object once, computes its digest, and retains the
opened descriptor or verified bytes. It never reopens a pathname after checking
it and never exports authority paths to campaign children.

The directly paired packet, campaign, release, launcher, kit, bundle, and trust
digests are compared to the envelope. Each endpoint TLS CA reference must have
its exact content digest in the digest-checked campaign release; each short-lived
credential reference must match the independently signed capacity
authorization's credential identity and is content-digested for the sanitized
run record. Credentials are opened only after isolation, exposed through the
least-privilege descriptor mechanism required by the pinned tool, and never
stored in evidence.

The validity interval must be well ordered and current. The launcher enforces
expiry over the complete process tree. A longer campaign uses independently
dual-signed resumable stages with linked evidence digests; it cannot extend a
timestamp or reuse a nonce.

## Signed endpoint allowlist and dynamic probes

`endpoints` is embedded in—and therefore covered by both signatures on—the
execution envelope. Each closed endpoint contains exactly:

```text
endpointId
kind
ipAddress
port
tls.serverName
tls.serverSpkiDigest
tls.caCertificateFileReference
credentialFileReference
authorizationPolicyDigest
costDisposition
accessMode
discovery
```

`discovery` is always `false`. `ipAddress` is one signed IPv4 or IPv6 literal;
the port is one signed value; TLS binds the server name, SPKI SHA-256, and local
CA reference. Endpoint kinds are exactly `KUBERNETES_API_PROXY`,
`CAMPAIGN_PROXY`, `LOCAL_REGISTRY`, and `LOCAL_EVIDENCE_SINK`.
Proxy kinds require `accessMode: PREAUTHORIZED_PROXY`; local registry and
evidence-sink kinds require `accessMode: LOCAL_PREEXISTING`. Every endpoint has
a unique `endpointId`, a digest-pinned authorization policy, and cost disposition
`SELF_HOSTED_OPEN_SOURCE_NON_METERED` or
`TENANT_SUPPLIED_OPEN_SOURCE_NON_METERED`.

Direct public Internet, cloud-management/billing APIs, provider endpoints,
link-local metadata, wildcard addresses/ports, DNS discovery, redirects to an
undeclared tuple, third-party API keys, and Unix Docker/containerd/Podman/CRI or
cloud-agent sockets are rejected even if an envelope is signed.

Workloads created during a campaign are never endpoint-authority additions.
Dynamic probes use only:

- the pre-existing signed `KUBERNETES_API_PROXY` with service-proxy/exec paths
  allowed by the independently signed capacity authorization and immutable
  campaign release; or
- the pre-existing signed `CAMPAIGN_PROXY` with logical namespace, service,
  port, protocol, method, and path policy bound by those same two digests.

Campaign code receives only the pre-existing proxy tuple. It never receives a
new Pod/Service IP, CIDR, DNS suffix, or wildcard. The proxy rejects targets not
present in both the campaign release and capacity authorization. A missing proxy
capability is `NOT_RUN_ENV_UNAVAILABLE`; it never broadens egress.

For each proxy endpoint, `authorizationPolicyDigest` must equal the active proxy
policy rendered by the digest-checked campaign release and admitted by the
capacity authorization. That policy binds allowed namespace, resource/service,
subresource, verb or method, port, path, request/response media type, and size/
time limits. For a local registry or evidence sink, the same field binds the
local read/write operation policy. A digest mismatch or policy bypass is `FAIL`.

## Independent capacity authorization and zero-cost admission

`capacityAuthorizationFileReference` names the separate local
capacity-operator-owned record whose ID and bytes must match
`capacityAuthorizationId` and `capacityAuthorizationDigest`. The trusted
launcher opens it no-follow/read-once under the same local-reference rules; it
is never fetched through a proxy. The record has its own Ed25519 signature from
a distinct tenant-trust-bundle key with purpose `CAPACITY_OPERATOR`. It binds the
tenant/environment, namespace, service account, permitted proxies and API paths,
verbs/GVKs/names, pre-existing resource references, resource quota, credential
identities, mutation profile, admission policy, validity, and nonce. The
capacity signature is neither an envelope signature nor implied by platform or
tenant execution approval.

The capacity record is a closed RFC 8785 JCS object with exactly these top-level
members; `CONF-001` must publish the corresponding `additionalProperties:
false` schema and negative vectors:

```text
schemaVersion
authorizationId
operatorId
tenantId
environmentId
namespace
serviceAccountSubject
permittedEndpointIds
kubernetesApiRules
campaignProxyRules
permittedGvksAndVerbs
preexistingResourceRefs
resourceQuotaDigest
limitRangeDigest
preallocatedStorageRefs
preallocatedAcceleratorRefs
credentialIdentities
mutationProfile
admissionPolicyDigest
validFrom
expiresAt
nonce
signerKeyId
signature
```

Every Kubernetes API rule fixes endpoint ID, verb, API group/version, resource,
namespace, name, subresource, request/response media types, and request/response
byte limits. Every campaign-proxy rule fixes endpoint ID, logical namespace,
service, port, protocol, methods, paths, and byte/time limits. Every GVK rule
fixes API group/version, kind, verbs, and permitted names. Pre-existing,
storage, and accelerator references fix API identity, namespace/name, and
observed digest; credential identities fix endpoint, purpose, subject, and
expiry without containing secret bytes. Arrays are unique and unknown members
are invalid. `mutationProfile`, `admissionPolicyDigest`, `resourceQuotaDigest`,
tenant/environment, authorization ID, and permitted endpoint IDs must equal the
execution envelope and target observation. Its signature payload is exactly:

```text
UTF8("planeon.harness-live-capacity-authorization/v1alpha1\u0000")
|| RFC8785_JCS(capacity record with only signature removed)
```

The capacity validity interval must be current and no wider than the envelope;
the record digest is SHA-256 over its exact signed bytes. `signature` is the
unpadded base64url Ed25519 signature and `signerKeyId` resolves uniquely to the
same tenant, environment, and `CAPACITY_OPERATOR` purpose.

`mutationProfile` is exactly `ZERO_INCREMENTAL_COST_KUBERNETES_V1`. Before any
checked-out code runs, the trusted launcher uses the signed proxy to prove that
the server-side capacity-operator-owned admission policy and resource quota
match `admissionPolicyDigest` and `resourceQuotaDigest`, and that the campaign
service account cannot alter or bypass them. Missing capacity is
`NOT_RUN_ENV_UNAVAILABLE`; invalid authority, a digest mismatch, or a denied/
attempted boundary bypass is `FAIL`.

The admission policy defaults to deny and rejects at minimum:

- `LoadBalancer` or `ExternalName` Services, unapproved NodePorts, external DNS,
  cluster/node/autoscaler mutations, and cloud/provider/operator CRDs;
- new StorageClasses, PersistentVolumes, dynamically provisioned PVCs,
  snapshots, object stores, accelerators, or resources outside preauthorized
  capacity;
- mutable or external image/chart/model references, runtime pulls outside the
  signed local registry/bundle, public tunnels, external telemetry, and egress;
- RBAC escalation, impersonation, and admission, webhook, namespace, quota,
  limit-range, or network-policy changes that could weaken the boundary; and
- unknown kinds, annotations, provisioners, controllers, or cost disposition.

An Ingress or OpenShift Route is allowed only when the capacity authorization
names an already running local ingress/router and preallocated host, with no
DNS, load-balancer, certificate-purchase, or cloud API. The launcher, proxies,
and admission component have no cloud credentials and never query a cloud or
billing API to infer safety.

## Canonical results and evidence axes

Every test/control result is exactly one of:

```text
PASS
FAIL
WARN
NOT_APPLICABLE
NOT_RUN_ENV_UNAVAILABLE
```

Live placement, platform, architecture, version, and custody mode are dimensions,
not result prefixes or aliases. A required `WARN`, `NOT_APPLICABLE`, or
`NOT_RUN_ENV_UNAVAILABLE` never satisfies a release or production control.

The envelope and selected packet must contain exactly these ordered axes:

| Packet | `allowedEvidenceAxes` |
|---|---|
| `CONF-A1-001` | `RUNTIME`, `ASSURANCE` |
| `CONF-A2-001` | `RUNTIME`, `ASSURANCE` |
| `CONF-A3-001` | `RUNTIME`, `ASSURANCE` |
| `CONF-AIR-001` | `DEPLOYMENT`, `RUNTIME`, `ASSURANCE` |
| `CONF-K3S-001` | `DEPLOYMENT`, `RUNTIME`, `ASSURANCE` |
| `CONF-K8S-001` | `DEPLOYMENT`, `RUNTIME`, `ASSURANCE` |
| `CONF-OCP-001` | `DEPLOYMENT`, `RUNTIME`, `ASSURANCE` |
| `CONF-SEC-001` | `SECURITY`, `ASSURANCE` |
| `CONF-UPG-001` | `DEPLOYMENT`, `RUNTIME`, `ASSURANCE` |
| `CONF-WG-001` | `ASSURANCE`, `TENANT_ACCEPTANCE_CANDIDATE` |

The only valid axis vocabulary is `DEPLOYMENT`, `RUNTIME`, `SECURITY`,
`ASSURANCE`, and `TENANT_ACCEPTANCE_CANDIDATE`. `TENANT_ACCEPTANCE` is forbidden.
A live report may reference immutable evidence from source, unit, PR, merge,
artifact/SBOM, or signature/release axes but cannot originate, replace, or
upgrade it.

`CONF-WG-001` creates an unsigned tenant-acceptance candidate containing
findings and exact evidence references. Candidate `PENDING` or `REJECTED` is
workflow metadata, not a conformance result or tenant acceptance. Only a
separate authorized tenant decision, signed outside the campaign identity and
ingested as independent acceptance evidence, may satisfy tenant acceptance.

## `CONF-001` bootstrap and tests

`CONF-001` owns the reproducible trusted-launcher build, closed envelope and
capacity contracts, generic `Makefile` dispatch, inner runner, and meta-tests.
Its exact ordered offline commands are:

```text
make meta-conformance
make build-reproducible
make zero-bill
make acceptance-package-contract
```

The generic dispatch includes `campaign`, `evidence-verify`, and
`acceptance-package`. The last command emits only an unsigned
`TENANT_ACCEPTANCE_CANDIDATE`. Building and testing the launcher does not install
it or confer authority; independent review and root-owned pinned external
installation remain prerequisites for every live run.

Negative tests must reject before campaign execution: any field/digest/command/
axis mismatch; either missing envelope signature; wrong, same, expired, or
revoked signer roles; invalid capacity signature; direct checked-out launcher or
CI use; relative/symlink/reopened references; endpoint discovery/rebinding;
metadata/cloud/billing/provider/CRI endpoints; missing isolation or proxy;
unapproved Kubernetes mutations; admission/RBAC bypass; noncanonical result or
axis; `TENANT_ACCEPTANCE`; and a campaign-generated acceptance signature.
Reports bind all verified authority and result digests without storing secrets.

## Early Linux evidence subset

CONF-LINUX-001 admits exactly DEPLOYMENT, RUNTIME, SECURITY and ASSURANCE under
the same dual-signed envelope and independent capacity authorization. It does
not admit TENANT_ACCEPTANCE or substitute fixtures/capability flags for real
Linux probe records. Only pre-existing signed proxy endpoints may execute
fixed probes; no raw container socket or new resource capacity is authorized.
Source merge with NOT_RUN_ENV_UNAVAILABLE leaves the early runtime coding gate
closed. See alpha-2/LINUX_READINESS.md; full Alpha-4 certification is unchanged.

## Approved trusted live backend enablement — MET-LIVE-001

The [coding guide](alpha-2/LIVE_BACKEND_READINESS.md) and closed
`architecture/live-backend-roadmap.json` add six sequential conformance packets
(CONF-LIVE-001 through CONF-LIVE-006), not new repositories or harnesses.
Current catalog: 130 packets. The 123 consumed packet YAML and all existing
architecture/legal/policy/release records remain byte-identical.

Only the six source-enablement packets may proceed before native qualification.
After their source closure, external operator installation and a fresh
independently signed native AMD64 qualification are required before
CTRL-INTEGRATE-001, MODEL-001, EXEC-001 or RUN-001. ARM64 qualification is separate.
CONF-LIVE-006 adds the twelfth possible manual campaign declaration with the
complete eight-command inventory; it grants no installation, target access,
provisioning or paid capability. The old seven-command CONF-LINUX-001 verifier
and all predecessor tests remain unchanged; the new packet has its own exact
pure authority/evidence adapter. Source fixtures never become native evidence.

Current phase/status and completed source checkpoints are in DEVELOPMENT_STATUS.md.
One packet, branch, PR and exact local/CI/main gate per run remains mandatory.

## Approved proxy contract prerequisite — MET-REPAIR-009

The [strict proxy profile](alpha-2/PROXY_CONTRACT_READINESS.md) closes credential and resource-rule
semantics for the new proxy without changing any accepted public wire schema,
134 existing packet YAML, product path grant, command inventory or signature role.
This one additive meta packet produces a 135-packet catalog and preserves all
176 predecessor authority files. It records SOURCE_INSPECTION_ONLY findings,
not a reproduced exploit or new product test failure.

Complete this authority before CONF-LIVE-003. Product implementation remains
in that packet's eight existing paths; preserve all 127 predecessor files and
279 test IDs. CONF-LIVE-004 owns actual probes, CONF-LIVE-005 the fixed client/server
candidate packaging, and CONF-LIVE-006 the already-bounded final hook. Mutual TLS,
independent server custody, actual policy/RBAC, durable reservations and exact-UID
cleanup must be tested independently; meta vectors are UNIT_VERIFICATION_ONLY.
Native qualification, runtime and tenant acceptance remain separate and unavailable.
No installation, key issuance, root-policy change, hosted runner or paid API is
part of this publication. Alpha 2 remains ongoing; no phase-end effort change is due.

## Approved protected policy observation — MET-REPAIR-010

Source-only prerequisite before CONF-LIVE-003: fixed local server-only observation,
independent operator custody and current enforcement evidence. Campaign API rules,
credentials, mutations and egress remain unchanged. The observer is a separately
installed open-source operator prerequisite, not an available or deployed product.
Current catalog 136; 135 predecessor YAML and strict proxy profile preserved.
Product stages 110/120/127/135/141/146/151 and eight paths/eight commands unchanged.
See the current dispatch link above for the closed schemas, native obligations,
recorded predecessor timing risk and separate acceptance gates. Alpha 2 ONGOING.

## Approved retained custody correction — MET-REPAIR-011

The [bounded handoff correction](alpha-2/CUSTODY_HANDOFF_REPAIR.md) adds MET-REPAIR-011 and CONF-FIX-004:
138 packets, unchanged thirteen repositories/four planes/sixteen harnesses.
The original 136 packet YAML and all prior authority records remain immutable.
CONF-FIX-004 may change only its five existing custody/supervisor/test/document
paths; old test bodies remain byte prefixes and all 279 methods remain required.
The 127-file stage and later 135/141/146/151 path counts stay unchanged.
Separate source/local/CI/merge/local exact-main closure is required before
CONF-LIVE-003 consumes the corrected checkpoint. No file-presence exemption,
path reopening, installation, new credential, dependency, native/live execution
or acceptance promotion. Prior nested-timeout failures remain unresolved history;
no timing, isolation or coverage relaxation. Alpha 2 ONGOING; effort change NOT_DUE.


## Approved bounded credential lifecycle — MET-REPAIR-012

The [credential-lifecycle correction](alpha-2/CREDENTIAL_LIFECYCLE_REPAIR.md) publishes
MET-REPAIR-012 and CONF-FIX-005: 141 packets, unchanged thirteen repositories,
four planes and sixteen harnesses. Preserve all 138 predecessor packet bytes.
CONF-FIX-004 closed at 0aa3ef3027f4a156d7ebed1b56af244e021d080a, 127 files / 305 tests;
its historical proof remains unchanged. CONF-FIX-005 supplies narrowly owned
late-credential/temporary-handle custody plus three cumulative source-accounting
adaptations, with every behavioral assertion and all 305 prior IDs retained.
Source stage counts and later eight-path proxy grant remain unchanged.
Publish and close each packet separately before CONF-LIVE-003. No product/native
execution, new installation, key, dependency, cloud action or bill in this meta
publication. Prior timing failures remain UNRESOLVED; no timeout or coverage
relaxation. Alpha 2 ONGOING; model-effort transition NOT_DUE.


## Approved credential-ordering correction — MET-REPAIR-013

The current dispatch link above is normative for the authentication-only client
credential exception. After independent signatures, kernel isolation, durable
reservation and retained custody checks, the client may authenticate only to its
pinned proxy. The server still requires fresh local policy observation and
transactional zero-cost admission before any probe, mutation or upstream
credential use. No TLS success or client receipt grants native acceptance.

Preserve all 141 predecessor packet bytes, historical authority and source locks.
Current catalog142; conformance checkpoint9df7dd7 has 127 files / 327 tests.
CONF-LIVE-003 retains eight paths/eight commands; no additional product repair
packet, signature role, endpoint, installed capability or billing permission.
This meta publication requires twenty-one offline commands and separate local,
required localhost CI, merge and local exact-main gates. Native AMD64/ARM64 and
Alpha3/4 remain waiting; Alpha 2 ONGOING, effort transition NOT_DUE.


## Approved broker handoff — MET-REPAIR-014

The current dispatch link is normative for the fixed server-local broker execution
handoff, including zero-resource probes. Broker-controlled execution, not an
observation, callback or token, enforces the policy generation. The proxy retains
exact resource/UID ownership and cleanup; the worker has no credentials or generic
execution API. New local custody and the fixed worker ABI do not change public
campaign/signature schemas, network endpoint sets or Kubernetes permissions.

Catalog143; all142 predecessor packet bytes and the accepted127-file/327-test
product checkpoint remain unchanged. Product packets003–006 keep their exact
paths/eight commands and source stages. This source-only publication requires22
commands, both complete replays, required localhost PR CI, merge and independent
local exact-main. No installation, new broker availability, paid service or live
acceptance is claimed. Alpha2 ONGOING; model-effort transition NOT_DUE.
