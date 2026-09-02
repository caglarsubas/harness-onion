# Repository Plan: `mas-harness-distribution`

## Purpose and boundaries

This repository composes a locked tenant profile into a minimal signed OCI bundle that references only selected module images/charts and requested CPU architectures. It owns Helm composition, local OCI layout, SBOM/license/vulnerability evidence, air-gap export/import, offline verification, and release promotion.

Non-goals:

- No product service implementation, tenant-specific mega-image, cluster apply, cloud registry/account creation, source repository modification, model-license assumption, or online-only release path.
- CI may build and scan candidates but cannot access the offline release private key.
- Bundle closure never depends on runtime downloads.

## Repository structure and exact tree

This tree projects the current task-packet `allowedPaths`. Directory entries do not authorize edits beyond the packet executed in a coding run.

```text
mas-harness-distribution/
├── .github/workflows/verify.yml
├── .gitignore
├── AGENTS.md
├── CONTRIBUTING.md
├── LICENSE
├── NOTICE
├── README.md
├── SECURITY.md
├── PORTING.yaml
├── Makefile
├── pyproject.toml
├── uv.lock
├── toolchain.lock
├── ci/
├── cmd/harness-bundlectl/
│   ├── export.py
│   ├── import.py
│   ├── sign.py
│   └── verify.py
├── src/planeon_distribution/
│   ├── airgap.py
│   ├── builder.py
│   ├── helm.py
│   ├── licenses.py
│   ├── model_custody.py
│   ├── oci.py
│   ├── promotion.py
│   ├── relocation.py
│   ├── resolver.py
│   ├── sbom.py
│   ├── signing.py
│   └── vulnerabilities.py
├── charts/
├── profiles/
├── schemas/
│   └── bundle-lock.schema.json
├── policies/
├── trust/
├── fixtures/{airgap,attacks,helm,oci-layout,profiles,signing,supply-chain}/
├── scripts/{rebuild_compare.sh,render_profiles.sh,run_supply_chain_campaign.py}
├── docs/
│   ├── airgap.md
│   ├── key-rotation.md
│   ├── oci-bundle.md
│   ├── profiles.md
│   ├── release-ceremony.md
│   ├── supply-chain.md
│   └── runbooks/
└── tests/{airgap,bootstrap,build,helm,reproducibility,resolve,security,signing,supply-chain}/
```

## Package, toolchain, and interfaces

- Distribution/import/CLI: `planeon-harness-distribution` / `planeon_distribution` / `harness-bundlectl`.
- Python 3.12.14, `uv` 0.12.7, cryptography, jsonschema, PyYAML, and OCI-layout libraries frozen in `uv.lock`.
- External tools pinned by version and SHA-256 in `toolchain.lock`: Helm 4.2.0, Cosign 3.1.3, ORAS, Syft, Grype, and platform tools. Prefetch obtains them once; offline verification uses local binaries/databases only.
- Owned APIs, events, and stores: no service API, production event stream, or database. Inputs/outputs and release-state transitions are immutable files/OCI evidence artifacts.

Media types:

```text
application/vnd.planeon.harness.bundle.v1+json
application/vnd.planeon.harness.profile.v1+json
application/vnd.planeon.harness.module.v1+json
application/vnd.planeon.harness.evidence-plan.v1+json
```

`bundle.lock.json` records every blob's digest, size, media type, platform, source, license, SBOM digest, vulnerability evidence, and signature reference. Bundle ID is the SHA-256 digest of canonical `bundle.lock.json`.

CLI surface:

```text
harness-bundlectl resolve
harness-bundlectl build
harness-bundlectl scan
harness-bundlectl sign
harness-bundlectl verify
harness-bundlectl export-airgap
harness-bundlectl import-airgap
harness-bundlectl relocate
harness-bundlectl promote
```

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

- Contract/source and build-artifact graph: locked contracts/catalog schemas only; distribution never imports operator or plane implementation source.
- Release-set graph: already released operator image/chart/CRD, selected plane manifests/images/charts, signed industry packs, SBOMs, vulnerability evidence, licenses, and model custody records are pinned by version and digest.
- Runtime integration: none while building. After bootstrap, the independently installed operator consumes the verified workload bundle; distribution is not a runtime service.
- Downstream: operator installs/verifies released bundles; conformance verifies closure/airgap; meta repository locks released digest.
- No dependency on GitHub, public OCI registry, public chart repository, or control-plane service at install time.

Bootstrap is phase-ordered: the operator builds/releases independently; this repository then assembles a release set that pins that operator and selected workload artifacts; bootstrap installs the pinned operator; the installed operator verifies/applies the workload portion. The apparent `distribution → operator` release-set edge and `operator → distribution` runtime-integration edge belong to different typed DAGs and create no source/build cycle.

## Warm-source mapping

Public source provenance is recorded only in `architecture/reuse-map.yaml`, `architecture/reuse-path-index.yaml`, and packet `sourceReuse` entries. Non-public planning inputs have already been distilled into independent public contracts and acceptance criteria; their repository names, commits, paths, and object IDs are deliberately omitted. They are not mounted or required during implementation. No source is copy-authorized.

## PR packets

1. `DIST-001-bootstrap-tools`: CLI, toolchain lock/prefetch, schema validation, local OCI-layout fixture, and no-network test harness.
2. `DIST-FIX-001-cumulative-make`: bounded bootstrap correction making future descriptor-owned targets reachable without changing the closed dispatcher or existing argv.
3. `DIST-OCI-001-resolve-build`: exact module/platform closure, Helm vendoring, digest fetch, canonical lock, staging state, and minimal-profile proof.
4. `DIST-002-supply-chain`: SPDX SBOM, license allow/deny, offline Grype DB/scan, model custody, vulnerability disposition, and evidence references.
5. `DIST-003-sign-promote`: offline Ed25519 Cosign ceremony, component/root signatures, public-key rotation/overlap, revocation, atomic promotion, and candidate/released separation.
6. `DIST-AIR-001-export-import`: OCI layout archive, checksums, signatures/trust/SBOM/licenses/vulnerability DB/model manifest, physical offline verification/import, and relocation digest proof.
7. `DIST-004-helm-profiles`: minimal ARM64/AMD64, regulated OCP, bridge/silo, and air-gap profile charts with exact selected subcharts only.
8. `DIST-005-repro-security`: two-clean-build digest match, corrupt/missing/extra blob denial, path traversal/archive bombs, compromised staging, and key-revocation drills.

## Testing, verification, and acceptance

The `DIST-001` bootstrap packet declares
`prefetchCommands: [["make","prefetch"]]` and ordered
`offlineAcceptanceCommands:
[["make","fixture-verify"],["make","zero-bill"]]`.
Later packets add unit, contract, closure, offline scan, air-gap round-trip,
security, and reproducibility checks as direct argv arrays. The executor
supplies the hash-pinned packet through `HARNESS_TASK_PACKET` and invokes only
`offlineExecution.wrapperArgv: ["./ci/verify-offline.sh"]` for the complete
ordered list.

Acceptance: the minimal profile contains no unselected harness/provider/platform blobs; two clean builds are byte/digest reproducible; signatures verify with public key and no network; corrupt, extra, mutable, unlicensed, vulnerable-without-disposition, or revoked content is rejected; relocation preserves digests; runtime dependency/model fetch attempts are impossible.

## Release and rollback

- Candidate lifecycle: `DRAFT → RESOLVED → BUILT → SCANNED → AWAITING_SIGNATURE → SIGNED → RELEASED`; alternatives `FAILED`, `SUPERSEDED`, `REVOKED`.
- Private signing key stays offline. Release promotion creates an immutable released reference; no overwrite.
- Rollback builds or selects a previous released bundle digest. Revoked bundles cannot be restored. Export archives are append-only and checksum-addressed.

## Zero-bill rules

- Default target is local OCI layout/local registry supplied by the operator. No GHCR/GitHub Packages/cloud registry, cloud KMS, transparency-service requirement, remote scan API, or cloud storage.
- No hosted runners, GitHub caches/artifacts, scheduled builds, remote
  package/model download during either prefetch or offline acceptance, external
  telemetry, or API keys. Prefetch uses only the preprovisioned local cache.
- A connected operator may supply its own registry endpoints, but credentials are passed by reference and never stored in locks or logs.
