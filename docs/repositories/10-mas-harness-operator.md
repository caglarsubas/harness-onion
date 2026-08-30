# Repository Plan: `mas-harness-operator`

## Purpose and boundaries

This repository owns `runtime.infrastructure`: Kubernetes/OpenShift preflight, offline bundle verification, `HarnessInstallation` reconciliation, dependency-wave apply/health, upgrade, rollback, uninstall, and status/evidence observation. It installs only locked, signed, digest-complete profiles.

Non-goals:

- No cluster/cloud/VM/DNS/registry provisioning, GitOps server, control-plane business workflow, bundle build/signing, application policy authoring, or model download.
- Rendering or dry-run is not deployment/runtime/certification evidence.
- The operator never needs synchronous control-plane connectivity and never stores signing private keys.

## Repository structure and exact tree

This tree projects the current task-packet `allowedPaths`. Directory entries do not authorize edits beyond the packet executed in a coding run.

```text
mas-harness-operator/
├── .github/workflows/verify.yml
├── .gitignore
├── AGENTS.md
├── CONTRIBUTING.md
├── Containerfile
├── LICENSE
├── NOTICE
├── README.md
├── SECURITY.md
├── PORTING.yaml
├── Makefile
├── go.mod
├── go.sum
├── tools.lock
├── ci/
├── cmd/{operator,bundle-verifier,fleet-sync-agent}/
├── api/v1alpha1/
├── internal/
│   ├── apply/
│   ├── controller/{foundation,modules,uninstall,upgrade}/
│   ├── evidence/
│   ├── fleet/
│   ├── health/
│   ├── inventory/
│   ├── migrations/
│   ├── preflight/
│   ├── retry/
│   ├── rollback/
│   └── verify/
├── config/
│   ├── crd/
│   ├── foundation/
│   ├── manager/
│   └── rbac/
├── deploy/helm/
│   ├── operator/
│   ├── bundle-verifier/
│   └── fleet-sync-agent/
├── fixtures/{fleet,foundation,modules,platform,preflight,upgrade}/
├── scripts/{render_matrix.sh,run_operator_campaign.py}
├── docs/
│   ├── fleet-sync.md
│   ├── module-lifecycle.md
│   ├── preflight.md
│   ├── reconciliation.md
│   ├── uninstall.md
│   ├── upgrade-rollback.md
│   └── runbooks/
└── tests/{envtest,fleet,foundation,modules,platform,preflight,resilience,security,uninstall,upgrade,verify}/
```

## Deployables and toolchain

- Go 1.26.7 and auxiliary tool binaries are pinned by version and digest in `tools.lock`; controller-runtime is compatible with the Kubernetes 1.33 minimum API and certified 1.35-1.37 clients. Kubebuilder/envtest, Helm 4.2.0, Cosign 3.1.3, and Kustomize 5.8.1 digests are mandatory alongside `go.sum`.
- `mas-harness-operator`: one non-root controller image.
- `bundle-verifier`: pre-install/upgrade Job or init container using public trust keys only.
- `fleet-sync-agent`: optional module that pulls signed desired-state artifacts from an explicitly supplied local endpoint; absent in manual/air-gap profiles.

## Owned APIs, events, and stores

CRD: `HarnessInstallation.harness.planeon.ai/v1alpha1`.

Spec contains tenant/profile/bundle digests, target namespace, isolation mode, approved install/upgrade strategy, trust reference, storage retention, and module overrides permitted by the locked profile. Status contains `observedGeneration`, phase, reason, current/previous-ready bundle digests, module states, conditions, transition times, last successful reconciliation, and bounded failure summary.

Installation phases: `PENDING`, `PREFLIGHT`, `VERIFYING`, `APPLYING`, `HEALTH_CHECKING`, `READY`; exceptions `BLOCKED`, `DEGRADED`, `FAILED`, `UPGRADING`, `ROLLING_BACK`, `UNINSTALLING`, `RETIRED`. Module states: `ABSENT`, `PENDING`, `PULLING`, `VERIFYING`, `APPLYING`, `READY`, `DEGRADED`, `FAILED`, `ROLLING_BACK`, `REMOVED`.

Conditions: `DependenciesResolved`, `ArtifactsVerified`, `Configured`, `Ready`, `Healthy`, `PolicyCompliant`, and `EvidenceCurrent` with stable reason codes.

Stores: CRD/status plus an inventory ConfigMap per installation containing only resource UIDs/digests; no database. Kubernetes server-side apply owns fields under a dedicated manager. Events/evidence are emitted as Kubernetes Events plus signed contract records to a configured local evidence endpoint/outbox file; secrets are never included.

## Task-command ownership

The bootstrap packet is the sole current owner of `Makefile` and installs the
closed `ci/run_make_target.py` direct-argv dispatcher. Each later Make-using
packet owns only `ci/targets/<lowercase-packet-id>.json`, which registers its
exact targets, closed variable values, and packet-local handlers. The dispatcher
validates descriptors and executes every applicable handler cumulatively in
lexical packet order; missing, ambiguous, duplicate, undeclared-variable, or
shell-based handlers fail closed. Later packets never edit `Makefile`. The only
exception is the generic `campaign`, `evidence-verify`, and
`acceptance-package` dispatch owned and tested by `CONF-001` for conformance
campaign packets.

The same bootstrap packet is the only current owner of `PORTING.yaml` and
seeds a closed `NO_AUTHORIZATION` ledger. Reference/discovery-only packets cannot
edit it; a future copy transaction requires a revised `PORT_CANDIDATE` packet.

## Dependencies

- Contract/source and build-artifact graph: contracts/CRD/module-manifest schemas only. The operator has no distribution or plane source/build dependency and must build, test, and release independently.
- Release-set input: none. A distribution release later pins an already released operator image/chart/CRD by digest.
- Runtime integration: the installed operator consumes and verifies a released distribution workload bundle, public Cosign trust keys/revocations, Kubernetes API, and local OCI registry/layout.
- Downstream: every plane module is applied/observed; conformance consumes conditions/evidence.
- Dependency waves come only from signed `install-plan.json`. The operator does not recompute composition.

Bootstrap is phase-ordered: (1) build/release operator independently; (2) distribution pins that operator plus workload artifacts; (3) bootstrap installs the pinned operator; (4) that installed operator verifies and applies the workload portion of the bundle. The release-set edge `distribution → operator` and runtime-integration edge `operator → distribution` are deliberately in separate typed DAGs and never authorize reciprocal source imports.

## Warm-source mapping

Public source provenance is recorded only in `architecture/reuse-map.yaml`, `architecture/reuse-path-index.yaml`, and packet `sourceReuse` entries. Non-public planning inputs have already been distilled into independent public contracts and acceptance criteria; their repository names, commits, paths, and object IDs are deliberately omitted. They are not mounted or required during implementation. No source is copy-authorized.

## PR packets

1. `OP-001-bootstrap-crd`: Go scaffold, CRD/state validation, RBAC, leader election, health, image/chart, envtest, and generated-code check.
2. `OP-002-preflight-verification`: platform/architecture/storage/network/sandbox checks, locked profile/bundle closure, checksum/signature/revocation/license verification, and fail-before-apply.
3. `OP-003-reconcile-foundation`: namespace/isolation baseline, ordered waves, server-side apply/inventory, conditions, idempotency, restart recovery, and evidence.
4. `OP-004-reconcile-modules`: per-module health/probes, dependency blocking, degraded behavior, bounded retry, and last-success timestamps.
5. `OP-005-upgrade-rollback`: compatibility/preflight, generation-scoped inventory, one-wave upgrade, automatic current-generation rollback, previous-ready retention, and migration coordination.
6. `OP-006-uninstall-fleet`: safe uninstall, PVC/evidence retain-by-default, explicit destructive token, optional fleet sync, and manual air-gap path.
7. `OP-007-platform-security`: Kubernetes/OpenShift/K3s render/live matrices, arbitrary UID/SCC, default-deny/RBAC, controller compromise boundaries, and outage drills.

## Testing, verification, and acceptance

The `OP-001` bootstrap packet declares
`prefetchCommands: [["make","prefetch"]]` and ordered
`offlineAcceptanceCommands:
[["make","generated-check"],["make","envtest-offline"],["make","zero-bill"]]`.
Later packets add lint, unit, contract, local integration, security, and
reproducibility checks as direct argv arrays. The executor supplies the
hash-pinned packet through `HARNESS_TASK_PACKET` and invokes only
`offlineExecution.wrapperArgv: ["./ci/verify-offline.sh"]` for the complete
ordered list.

Acceptance: invalid/unsigned/incomplete/revoked bundles cause no Kubernetes mutation; repeated reconciliation is idempotent; operator crashes during every wave recover; failed upgrade returns to the previous ready digest without destructive DB rollback; uninstall retains PVC/evidence; control-plane/registry outage does not stop ready workloads; platform-specific unavailable tests report `NOT_RUN_ENV_UNAVAILABLE`.

## Release and rollback

- Release signed image/chart/CRD digests together; CRD storage-version changes require conversion tests and one-version compatibility.
- Rollback installs the previous operator only if it supports the stored CRD and current/previous bundle formats. Workload rollback is generation-scoped.
- Resource/PVC deletion requires explicit uninstall plus a second signed destruction authorization; finalizers protect evidence/inventory until disposition completes.

## Zero-bill rules

- No cluster/cloud/registry provisioning, subscription checks, external telemetry, hosted GitOps, automatic scale-up, or remote downloads.
- Self-hosted offline CI only; local envtest/kind/K3s/OCP supplied by operator, no GitHub storage/cache/Packages, cloud runners, schedules, or API keys.
- Fleet sync is disabled by default and accepts only allowlisted tenant-owned/local endpoints.
