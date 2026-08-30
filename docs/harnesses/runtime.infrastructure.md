# Harness Specification: `runtime.infrastructure`

## Contract

| Field | Value |
|---|---|
| Plane | Runtime |
| Owning repository | `mas-harness-operator` |
| Supporting repository | `mas-harness-distribution` |
| API version | `harness.planeon.ai/v1alpha1` |
| Required maturity for production | `CERTIFIED` |

## Capabilities and non-goals

This harness establishes the tenant execution boundary and reconciles a locked profile into a supplied Kubernetes-compatible environment. It performs platform preflight, verifies the signed bundle, creates tenant namespaces and baseline controls, installs modules in dependency waves, reports per-module health, and supports upgrade, rollback, and retention-safe uninstall.

It does not create clusters, cloud accounts, networks, DNS zones, registries, storage services, subscriptions, or GitHub resources. It does not infer application requirements, execute models, own tenant business data, or claim that a namespace alone provides hard multi-tenant isolation.

## Owner and deployables

- `operator`: watches `HarnessInstallation` resources and reconciles modules.
- `bundle-verifier`: init/container library that verifies bundle lock, signatures, and blob digests before apply.
- `fleet-sync-agent`: optional pull-based agent for SaaS or separated management planes; consumes only locked profiles and signed bundles.
- `namespace-baseline` chart: service accounts, quotas, default-deny policies, pod-security labels, and tenant database roles.

Only `operator` is required in every cluster. `fleet-sync-agent` is forbidden in `airgap-enclave` profiles.

## Dependencies, conflicts, and ordering

- Required harnesses: none; this is the dependency root.
- Bootstrap dependencies: a local OCI registry or imported OCI layout, Kubernetes API access, a supported storage class when stateful modules are selected, and an offline release public key.
- Optional harnesses: all other harnesses.
- Conflicts:
  - `isolationMode: pool` with a high-sensitivity or industry-pack `siloRequired` finding.
  - `networkMode: offline` with any selected module declaring an external runtime endpoint.
  - `untrusted-native` sandbox selection without a cataloged and certified gVisor or Kata runtime class.
  - Any active MLX selector; MLX is contract-only and non-installable in every profile.

Installation ordering is CRDs, verifier/trust roots, namespace baseline, state stores, trust services, knowledge/model services, execution services, runtime ingress, then assurance probes.

## Provider implementations

| Provider ID | Target | Notes |
|---|---|---|
| `kubernetes.upstream` | Kubernetes 1.35–1.37 | Default managed-cluster provider |
| `kubernetes.k3s` | Supported K3s aligned to a certified upstream minor | Single-node plain-VM profile |
| `openshift.ocp` | OpenShift 4.20 baseline | Uses SCC-compatible arbitrary UID and Route support |

Provider selection is based on discovered API resources and explicit `platform.provider`; autodetection may validate but never override the tenant selection.

## Configuration and runtime boundaries

Required configuration:

```yaml
platform:
  provider: kubernetes.upstream | kubernetes.k3s | openshift.ocp
  version: semver
  architectures: [amd64 | arm64]
isolationMode: pool | bridge | silo | airgap-enclave
networkMode: online | allowlisted | offline
namespacePattern: "harness-{tenantId}"
registry:
  endpoint: string
  pullSecretRef: {name: string, namespace: string}
storage:
  defaultClass: string
  retainOnUninstall: true
trust:
  releasePublicKeyConfigMapRef: {name: string, namespace: string}
```

- Secrets: image-pull secrets and tenant bootstrap credentials are Kubernetes `Secret` references only. Values never occur in a profile, CR status, event, or log.
- RBAC: the operator has cluster-scoped read access to discovery, namespaces, storage classes, CRDs, and nodes; write access is restricted to owned CRDs and labelled `harness.planeon.ai/managed=true` resources. Tenant workloads receive namespace-scoped service accounts with token automount disabled unless a module declares and passes an RBAC intent review.
- Network: namespace baseline is default-deny ingress and egress. The operator may reach the Kubernetes API and configured registry. DNS, trust, telemetry, and inter-service routes are generated from declared network intents; implicit internet egress is prohibited.
- Storage: installation intent and status live in the Kubernetes API. Module data live on tenant PVCs or explicitly configured tenant-owned S3-compatible storage. Uninstall retains PVCs and evidence unless the user submits a separate destructive-data approval.

## APIs, events, and state

Primary API: namespaced `HarnessInstallation` CRD.

```yaml
spec:
  tenantId: string
  profileDigest: sha256:...
  bundleRef: registry/repository@sha256:...
  isolationMode: bridge
  operation: Install | Upgrade | Rollback | Uninstall
status:
  observedGeneration: integer
  phase: string
  currentBundleDigest: string
  previousReadyBundleDigest: string
  conditions: []
  modules: []
```

Installation states are `PENDING → PREFLIGHT → VERIFYING → APPLYING → HEALTH_CHECKING → READY`. Exceptional states are `BLOCKED`, `DEGRADED`, `FAILED`, `UPGRADING`, `ROLLING_BACK`, `UNINSTALLING`, and `RETIRED`. Module states are `ABSENT`, `PENDING`, `PULLING`, `VERIFYING`, `APPLYING`, `READY`, `DEGRADED`, `FAILED`, `ROLLING_BACK`, and `REMOVED`.

Conditions: `DependenciesResolved`, `ArtifactsVerified`, `Configured`, `Ready`, `Healthy`, `PolicyCompliant`, and `EvidenceCurrent`.

Emitted CloudEvents:

- `installation.condition.changed.v1`
- `installation.module.changed.v1`
- `installation.ready.v1`
- `installation.failed.v1`
- `installation.rollback.completed.v1`

Consumed events are not required for reconciliation; the CR and immutable bundle are authoritative. `fleet-sync-agent` may consume `profile.locked.v1` and `bundle.signed.v1` in connected profiles.

## Failures, retry, and rollback

- Signature, digest, platform, policy, capacity, or prerequisite failures stop before apply and set a stable reason code.
- Reconciliation is idempotent and may retry reads and declarative applies with three jittered attempts.
- Apply occurs one dependency wave at a time. A wave does not start until the preceding wave reports ready.
- A failed upgrade rolls back only resources changed in the current generation, using `previousReadyBundleDigest`.
- Database migrations must be expand/contract and compatible with the previous ready release; the operator never performs destructive schema rollback.
- Operator restart resumes from observed resource state. It does not assume a prior API call succeeded.
- Registry loss blocks new installation and upgrade but cannot stop ready workloads.
- Uninstall deletes managed stateless resources, retains PVCs/evidence, and finishes `RETIRED`; destructive storage deletion is a separate workflow.

## Evidence and readiness gates

Required evidence:

- Kubernetes/OpenShift server version and API compatibility.
- Node architecture and schedulable capacity.
- Storage class, volume expansion, and snapshot capability findings.
- Default-deny policy enforcement probe.
- Restricted pod-security/SCC admission probe.
- Artifact signature, digest, SBOM, license, and vulnerability verdicts.
- Arbitrary-UID and non-root deployment probe.
- Installation, restart recovery, upgrade, rollback, and retained-uninstall reports.

Static rendering is `NOT_RUN_ENV_UNAVAILABLE`, never live certification. Production readiness requires all mandatory conditions current and no unexpired `FAIL` evidence.

## Profile behavior

- `minimal-local`: K3s, one node, one architecture, local registry, logical isolation, minimal state stores.
- `bridge`: shared management plane with tenant namespace, roles, storage, secrets, and indexes.
- `silo`: tenant-dedicated cluster or enclave; required for hard isolation claims.
- `airgap-enclave`: no fleet agent or egress; manual signed import; all artifacts and vulnerability data vendored.

## Tests

- Unit: platform detection, dependency-wave generation, condition aggregation, reason codes.
- Contract: CRD schema round trips and bundle/profile digest agreement.
- Security: RBAC escalation denial, default-deny enforcement, unsigned/tampered bundle rejection, secret redaction.
- Failure: operator crash at every wave, registry outage, insufficient capacity, failed readiness probe, interrupted rollback.
- Compatibility: Kubernetes 1.35–1.37, K3s, OpenShift 4.20, Linux AMD64 and ARM64.
- Air gap: build/import/install with network physically disabled and no unresolved blob.

## Sol-high implementation packets

1. `OP-001-bootstrap-crd`: operator scaffold, CRD/state validation, RBAC, health, leader election, envtest, and generated-artifact drift checks.
2. `OP-002-preflight-verification`: platform, architecture, capacity, storage, network, sandbox, locked-profile, signature, digest, revocation, and license preflight; must fail before apply.
3. `OP-003-reconcile-foundation`: namespace/isolation baseline, server-side apply inventory, ordered waves, conditions, restart recovery, and evidence.
4. `OP-004-reconcile-modules`: per-module probes, dependency blocking, degradation, bounded retries, and last-success observations.
5. `OP-005-upgrade-rollback`: compatibility preflight, generation inventory, one-wave upgrade, current-generation rollback, and migration coordination.
6. `OP-006-uninstall-fleet`: retain-safe uninstall, destructive token boundary, optional connected fleet agent, and manual air-gap path.
7. `OP-007-platform-security`: upstream Kubernetes, K3s, and OpenShift render/live matrices, arbitrary UID/SCC, RBAC/network denial, and outage drills.

Each packet must run unit, contract, security, zero-bill, reproducible-build, and offline verification targets and may change no public contract without a preceding contracts PR.
