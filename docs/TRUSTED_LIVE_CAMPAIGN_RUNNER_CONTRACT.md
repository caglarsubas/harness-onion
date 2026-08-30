# Trusted Live-Campaign Runner Contract

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
