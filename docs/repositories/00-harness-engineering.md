# Repository Plan: `Harness-Engineering`

## Purpose and boundaries

This is the non-deployable program meta repository. It is the only authority for repository topology, the sixteen-harness taxonomy, warm-source authorization, cross-repository dependency locks, Sol-high task-packet format, zero-bill policy, and whole-platform release evidence.

Non-goals:

- No application, operator, runtime, chart, container image, CRD, or tenant data.
- No duplicated product schemas; it pins released `mas-harness-contracts` artifacts by digest.
- No cloud provisioning, registry hosting, runner creation, secret storage, or paid-service integration.

## Repository structure and exact tree

```text
Harness-Engineering/
├── AGENTS.md
├── LICENSE
├── NOTICE
├── README.md
├── CONTRIBUTING.md
├── SECURITY.md
├── .gitignore
├── BILLING_POLICY.md
├── Makefile
├── requirements.lock
├── pyproject.toml
├── uv.lock
├── .github/workflows/verify.yml
├── ci/{prefetch.sh,verify-offline.sh,run_packet_argv.py,network_canary.py,test_offline_runner.py}
├── architecture/
│   ├── base-scope-sources.yaml
│   ├── taxonomy.yaml
│   ├── repositories.yaml
│   ├── dependency-graph.yaml
│   ├── services.yaml
│   ├── providers.yaml
│   ├── reuse-map.yaml
│   ├── reuse-path-index.yaml
│   ├── porting-authorization-index.yaml
│   └── reuse-map.schema.json
├── legal/
│   ├── source-reuse-authorization.yaml
│   └── third-party-license-policy.yaml
├── policies/
│   └── zero-bill-policy.yaml
├── schemas/
│   ├── taxonomy.schema.json
│   ├── repositories.schema.json
│   ├── services.schema.json
│   ├── dependency-graph.schema.json
│   ├── provider-module.schema.json
│   ├── reuse-path-index.schema.json
│   ├── porting-authorization.schema.json
│   ├── porting-record.schema.json
│   ├── task-packet.schema.json
│   ├── live-campaign-execution-envelope.schema.json
│   └── release-set.schema.json
├── task-packets/
│   ├── README.md
│   └── <one-file-per-packet>.yaml
├── release/
│   ├── repos.lock.json
│   ├── fixture-release-set.yaml
│   ├── evidence-policy.yaml
│   └── evidence/
├── docs/
│   ├── adr/
│   ├── harnesses/
│   ├── repositories/
│   ├── MASTER_DEVELOPMENT_PLAN.md
│   ├── MICROSERVICE_CATALOG.md
│   ├── PROVIDER_MODULE_CATALOG.md
│   ├── READINESS_INDEX.md
│   └── SCOPE_PROVENANCE.md
├── scripts/
│   ├── validate_readiness.py
│   ├── verify_offline.sh
│   ├── network_canary.py
│   ├── validate_architecture.py
│   ├── validate_reuse.py
│   ├── validate_packet_ownership.py
│   ├── validate_release_set.py
│   └── zero_bill_scan.py
└── tests/
    ├── test_readiness.py
    ├── test_validator_units.py
    ├── test_architecture.py
    ├── test_reuse.py
    ├── test_task_packets.py
    ├── test_live_campaign_envelope.py
    ├── test_release_set.py
    └── test_zero_bill.py
```

## Packages, toolchain, and owned interfaces

- Package: private development package `harness_engineering_meta`; it is never published.
- Toolchain: Python 3.12.14, `uv` 0.12.7, JSON Schema Draft 2020-12, Ruff, mypy, pytest, PyYAML, and jsonschema. Direct and transitive versions are frozen in `uv.lock`; every packet-declared uv argv carries `--offline`, `--frozen`, and `--no-sync`.
- CLI entry point: `harness-meta` with `validate`, `reuse validate`, `packet validate`, `release validate`, and `zero-bill scan` subcommands.
- Owned artifacts: `taxonomy.yaml`, `repositories.yaml`, `services.yaml`,
  `providers.yaml`, `reuse-map.yaml`, `reuse-path-index.yaml`, the empty-by-default
  `porting-authorization-index.yaml`, source/porting schemas and authorization
  policy, task packets, the closed live-campaign execution-envelope schema, and
  `repos.lock.json`.
- APIs/events/stores: none. Files are canonical, canonicalized JSON/YAML is digestable, and release evidence is append-only in Git.

`repos.lock.json` records repository, release tag, Git SHA, OCI digest, contract version, SBOM digest, signature reference, and certification result. A lock may reference only immutable artifacts.

### Canonical machine-authority ownership

Each current authority is writable by exactly one `Harness-Engineering` packet. Paths named `schemas/` or `policies/` by packets for another repository are relative to that other repository and do not grant access to this repository.

| Owning packet | Canonical authorities |
|---|---|
| `MET-001` | `architecture/base-scope-sources.yaml`, `architecture/taxonomy.yaml`, `architecture/repositories.yaml`, `architecture/services.yaml`, `architecture/dependency-graph.yaml`, `architecture/providers.yaml`, and their five current schemas: taxonomy, repositories, services, dependency graph, and provider module. |
| `MET-002` | `architecture/reuse-map.yaml`, `architecture/reuse-path-index.yaml`, the empty `architecture/porting-authorization-index.yaml`, `schemas/reuse-path-index.schema.json`, `schemas/porting-authorization.schema.json`, `schemas/porting-record.schema.json`, `legal/source-reuse-authorization.yaml`, and `legal/third-party-license-policy.yaml`. It later produces the planned `architecture/reuse-map.schema.json`. |
| `MET-003` | `policies/zero-bill-policy.yaml`. |
| `MET-004` | `schemas/task-packet.schema.json`, `schemas/live-campaign-execution-envelope.schema.json`, and the one-file-per-packet `task-packets/` authority catalog. |
| `MET-005` (planned predecessor-gated authority) | `schemas/release-set.schema.json`, `release/repos.lock.json`, `release/fixture-release-set.yaml`, and `release/evidence-policy.yaml`; these paths do not become current authorities before this packet executes and produces evidence. |

## Dependencies

- Upstream: attached research artifacts for traceable scope; immutable source commits of the five warm repositories; released product-repository manifests.
- Downstream: every product repository consumes the taxonomy, zero-bill policy, task-packet schema, and a pinned contract release.
- The dependency-graph validator rejects cycles, dependency on another repository's `main`, Git submodules, and runtime Git dependencies.

## Warm-source mapping

Public source provenance is recorded only in `architecture/reuse-map.yaml`, `architecture/reuse-path-index.yaml`, and packet `sourceReuse` entries. Non-public planning inputs have already been distilled into independent public contracts and acceptance criteria; their repository names, commits, paths, and object IDs are deliberately omitted. They are not mounted or required during implementation. No source is copy-authorized.

## PR packets

1. `MET-001-foundation`: repository scaffold, Apache-2.0 files, toolchain, taxonomy, repository catalog, and validator tests.
2. `MET-002-reuse`: truthful reference catalog, disabled fail-closed future authorization index, non-circular destination record schema, executable snapshot locker/verifier, license policy, exact source hashes, and source-object checks.
3. `MET-003-zero-bill`: billing policy, static scanner, forbidden-pattern fixtures, and self-hosted workflow policy.
4. `MET-004-packets`: task-packet schema, packet validator, Alpha 1-4 index, predecessor/allowed-path validation, and the closed dual-signed live-campaign execution-envelope schema with negative vectors.
5. `MET-005-release-lock`: release-set schema, lock generator/checker, evidence policy, and fixture release set.

Every packet uses branch `codex/<packet-id>`, changes only named paths, opens a PR, runs self-hosted CI, and merges only after all required checks pass.

## Testing, verification, and acceptance

The `MET-001` bootstrap packet declares `prefetchCommands: []` and ordered
direct-argv `offlineAcceptanceCommands` for architecture validation and tests.
Every later meta check is likewise added as an argv array in its owning packet.
The executor passes the selected hash-pinned packet through `HARNESS_TASK_PACKET`
and invokes only `offlineExecution.wrapperArgv:
["./ci/verify-offline.sh"]`; individual acceptance commands are never run
separately.

`MET-004` runs the complete readiness validator, the dedicated 91-packet
catalog suite together with the ownership negative vectors, and the live
campaign envelope positive/negative vectors. This proves the semantic packet
boundary in addition to JSON Schema conformance.

Acceptance requires exactly 13 repository records, exactly 16 public harness
IDs, an acyclic dependency graph, complete reference-only provenance with no
unauthorized warm-source copy, no mutable artifact references, and valid task
packets whose predecessors exist.

`schemas/live-campaign-execution-envelope.schema.json` is the machine-readable
transport authority for a live run. It is closed with
`additionalProperties: false` and binds the exact packet file and digest,
ordered direct-argv commands and command-set digest, conformance kit, campaign
definition and release, launcher, tenant bundle, evidence-axis subset,
tenant/environment, independently capacity-operator-signed authorization by ID,
absolute local file reference, and digest, the fixed
`ZERO_INCREMENTAL_COST_KUBERNETES_V1` mutation profile,
admission policy and resource quota, and the local trust stores. Its endpoint
allowlist admits only `KUBERNETES_API_PROXY`, `CAMPAIGN_PROXY`,
`LOCAL_REGISTRY`, and `LOCAL_EVIDENCE_SINK`; each tuple fixes an ID, IP literal,
port, pinned TLS identity, local credential file, authorization-policy digest,
non-metered cost disposition, proxy/local access mode, and sets discovery to
false. The envelope itself requires independent `PLATFORM_RELEASE` and
`TENANT_LIVE_EXECUTION` signer key IDs and base64url signatures. It cannot grant
`TENANT_ACCEPTANCE`; `TENANT_ACCEPTANCE_CANDIDATE` remains candidate-only.

JSON Schema validates the closed structure, encodings, constants, and path/argv
constraints. Digest recomputation, RFC 8785 JCS canonicalization, signature
role/purpose/validity/revocation checks, equality with the selected packet and
campaign bytes, expiry ordering, and distinct signer enforcement are runtime
verification semantics defined by
[`TRUSTED_LIVE_CAMPAIGN_RUNNER_CONTRACT.md`](../TRUSTED_LIVE_CAMPAIGN_RUNNER_CONTRACT.md),
not claims made by JSON Schema validation.

## Release and rollback

- Tag meta releases as `meta-vMAJOR.MINOR.PATCH`; sign the tag and generated release lock offline.
- A release lock becomes authoritative only after referenced repositories independently pass source, CI, merge, artifact, signature, deployment/runtime, and conformance gates.
- Rollback creates a new lock selecting previously released immutable digests. Existing lock history is never rewritten.

## Zero-bill rules

- Only self-hosted ephemeral runners; no scheduled workflows, caches, uploaded artifacts, Packages, GHCR, Git LFS, or cloud-created runners.
- After pinned credential-free checkout, the workflow invokes only the
  preinstalled root-owned `/opt/planeon/bin/harness-offline-launch`. The runner
  exposes no cloud credentials, SSH agent, kubeconfig, Docker/containerd socket,
  or other billable broker; checked-out shell, Python, toolchain validation,
  Make, and tests begin only after host isolation.
- Declared local-cache-only `prefetchCommands` and the complete ordered
  `offlineAcceptanceCommands` list run in the same egress-denied
  `offlineExecution` process tree with no online fallback.
- No cloud CLIs, Terraform providers, paid-provider URLs, external telemetry, API-key variables, or secret values.
- PRs from forks are never executed on trusted self-hosted runners until reviewed and imported into a trusted branch.
