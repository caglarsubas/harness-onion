# Repository Plan: `mas-harness-contracts`

## Purpose and boundaries

This repository owns every public wire contract, the non-executable questionnaire rule DSL, the module/provider catalog model, deterministic profile compiler, compatibility adapters, event envelopes, and cross-language golden vectors under `harness.planeon.ai/v1alpha1`.

Non-goals:

- No UI, database, network client, Kubernetes reconciliation, bundle construction, model execution, or industry-specific answer content.
- No provider implementation and no service-owned table schema.
- No implicit prerequisite activation: prerequisites are proposed and require tenant acceptance.

## Repository structure and exact tree

This tree projects the current task-packet `allowedPaths`. Directory entries do not authorize edits beyond the packet executed in a coding run.

```text
mas-harness-contracts/
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
├── ci/
├── contracts/{catalog.lock.json,release-manifest.json}
├── src/planeon_harness_contracts/
│   ├── canonical.py
│   ├── cli.py
│   ├── commands/{validate.json,catalog.json,verify-determinism.json,compatibility.json}
│   ├── compiler.py
│   ├── errors.py
│   ├── events.py
│   ├── graph.py
│   ├── models.py
│   ├── questionnaire.py
│   ├── registry.py
│   ├── rules.py
│   ├── state_machine.py
│   ├── validation.py
│   └── generated/
├── schemas/v1alpha1/
│   ├── taxonomy/
│   ├── guidance/
│   ├── readiness/
│   ├── composition/
│   ├── lifecycle/
│   ├── status/
│   ├── events/
│   └── runtime/
├── openapi/
├── asyncapi/
├── catalog/
│   ├── harnesses/
│   └── providers/
├── compatibility/data-harness-v1/
├── generated/
├── scripts/{generate_contracts.py,check_generated.py}
├── docs/
│   ├── compiler.md
│   ├── guidance-dsl.md
│   ├── lifecycle.md
│   ├── runtime-admission.md
│   ├── status-projections.md
│   ├── taxonomy.md
│   └── migrations/data-harness-v1.md
└── tests/
    ├── unit/
    ├── contract/{test_guidance.py,test_taxonomy.py}
    ├── model/
    ├── property/test_compiler.py
    ├── compatibility/
    ├── determinism/
    ├── golden/
    ├── runtime/
    └── fixtures/{compiler,guidance,taxonomy,lifecycle,status,compatibility,runtime}/
```

## Package, toolchain, and public interfaces

- Distribution/import: `planeon-harness-contracts` / `planeon_harness_contracts`.
- Toolchain: Python 3.12.14, `uv` 0.12.7, Hatchling, jsonschema 4.x, PyYAML 6.x, Hypothesis, pytest, Ruff, and mypy; exact versions are frozen in `uv.lock`.
- CLI: `harnessctl validate|compile|explain|catalog lock|verify-determinism|evidence validate|zero-bill scan`.
- Canonical resource groups: catalog, guidance, readiness, composition, lifecycle, events, and runtime admission.
- Public kinds: `HarnessClassDefinition`, `HarnessModuleDefinition`, `FrameworkProviderDefinition`, `ModuleRelease`, `ReleaseSet`, `QuestionnaireDefinition`, `QuestionnaireSession`, `QuestionnaireAnswerSet`, `GuidanceRule`, `BusinessContext`, `DataSourceDeclaration`, `DataReadinessAssessment`, `IntegrationDeclaration`, `ControlRequirement`, `ReadinessFinding`, `TenantDemand`, `HarnessProfile`, `BillOfMaterials`, `InstallPlan`, `EvidencePlan`, `ExecutionBudget`, `Operation`, `BundleRelease`, `HarnessInstallation`, `ApprovalRequest`, `PolicyBundle`, `EvidenceRecord`, `HarnessCloudEvent`, `RuntimeTrustBundle`, `SignedAdmissionEnvelope`, `RuntimeAdmissionReceipt`, `ReplayRecord`, and `BudgetConsumption`.
- Runtime admission signatures use RFC 8785 JCS over a closed I-JSON/ASCII-key subset and Ed25519. Contracts contain public keys and deterministic interoperability signatures only; private-key custody and cryptographic implementation remain outside this repository.
- Rule operators are exactly `all`, `any`, `not`, `eq`, `in`, `exists`, `gte`, and `lte`; schemas reject executable expressions and unknown operators.
- APIs are described, not hosted, by the five OpenAPI documents. CloudEvents 1.0 event schemas are the event interface.
- Stores: none.

Compiler output is exactly `profile.json`, `bom.json`, `install-plan.json`, `evidence-plan.json`, `explanation.md`, and `profile.sha256`. It validates, normalizes, enforces closed capability roles, evaluates rules, reports readiness, proposes prerequisites and compatible provider selectors, computes closure only after tenant acceptance, resolves exactly one accepted selector per active exclusive group, rejects inactive selectors/cycles/conflicts, creates installation waves, canonicalizes JSON, hashes outputs, and explains every decision. Ranking produces recommendations only and cannot mutate a profile. A missing selector returns `NEEDS_INPUT`; multiple accepted selectors return `AMBIGUOUS_PROVIDER`.

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

`CON-001` also owns the generic `harnessctl` loader. Closed command
registrations are owned exactly by `CON-002` (`validate`, `catalog`), `CON-004`
(`verify-determinism`), and `CON-006` (`compatibility`) under
`src/planeon_harness_contracts/commands/`. A later packet may consume a command
only when its owner is in predecessor closure. The loader rejects unknown or
duplicate command names, owner/filename mismatch, shell strings, and a handler
outside the owning packet's paths.

## Dependencies

- Upstream: only the meta taxonomy/reuse policy and Python standard/library dependencies in the lock.
- Downstream: all 11 other product repositories pin a released wheel, schema archive, and catalog digest.
- Compatibility: additive optional fields remain compatible within `v1alpha1`; breaking changes require a new API version and dual-read/dual-write vectors for one minor release.

## Warm-source mapping

Public source provenance is recorded only in `architecture/reuse-map.yaml`, `architecture/reuse-path-index.yaml`, and packet `sourceReuse` entries. Non-public planning inputs have already been distilled into independent public contracts and acceptance criteria; their repository names, commits, paths, and object IDs are deliberately omitted. They are not mounted or required during implementation. No source is copy-authorized.

## PR packets

1. `CON-001-bootstrap`: package, CLI shell, schema registry, validation errors, canonical JSON, and valid/invalid fixture harness.
2. `CON-002-catalog`: sixteen harness classes, provider/module/release schemas, dependency graph, platform/resources/license constraints, and catalog lock.
3. `CON-003-guidance`: questionnaire, answer, business/readiness schemas and sandboxed rule evaluator.
4. `CON-004-compiler`: deterministic closure, prerequisite acceptance, capability-role admission, recommendation-only provider filtering, explicit tenant selector acceptance, subject-aware conditional closure, ambiguity handling, installation waves, and explanations.
5. `CON-005-lifecycle-events`: lifecycle state and tenant harness-status projection schemas, closed aggregation/freshness semantics, OpenAPI/AsyncAPI, CloudEvents envelope, compatibility policy, and imported golden vectors.
6. `CON-006-compat`: `data.harness/v1` conversion, round-trip fixtures, deprecation metadata, and migration guide.
7. `CON-007-runtime-admission-contracts`: tenant-bound signed admission envelopes, trust rotation, receipts, replay/idempotency state, budget consumption, closed denial reasons, and canonical interoperability vectors.

## Testing, verification, and acceptance

The `CON-001` bootstrap packet declares
`prefetchCommands: [["make","prefetch"]]` and ordered
`offlineAcceptanceCommands:
[["uv","build","--offline","--frozen","--no-sync"],["make","zero-bill"]]`.
Later packets add the lint, type, unit, coverage, catalog, determinism, and
zero-bill checks as direct argv arrays. The executor supplies the hash-pinned
packet through `HARNESS_TASK_PACKET` and invokes only
`offlineExecution.wrapperArgv: ["./ci/verify-offline.sh"]` for the complete
ordered list.

Determinism compiles every fixture twice in clean temporary directories and byte-compares all six outputs. Property tests cover arbitrary DAGs, cycles, capability-role violations, inactive/missing/multiple selectors, recommendation acceptance, subject-capability closure, local-judge backend input, ordering, integer resource bounds, and rule evaluation. Every lifecycle fixture proves allowed and forbidden transitions. Status golden/property tests cover every closed selection, installation, evidence and freshness state; deterministic worst-child precedence; waiver-without-pass; required immutable bindings; and exclusion of unselected harnesses from health. Runtime-contract tests additionally cover valid canonical payloads plus malformed, forged, revoked, expired, wrong-tenant, replayed, idempotency-conflict, digest-mismatch, and over-budget outcomes. They prove source-contract interoperability only and never claim a live runtime decision.

## Release and rollback

- SemVer tags and offline-signed wheel/schema/catalog digests; generated artifacts must be reproducible.
- A release publishes one immutable compatibility matrix and catalog digest. Consumers never read unreleased schemas from Git.
- Rollback pins the previous compatible contract release. Schema removal is forbidden within an API version; adapters are retired only at a documented major-version boundary.

## Zero-bill rules

- Compiler and validation perform no network calls and accept no provider credentials.
- Catalog rejects mutable OCI tags, external paid-provider requirements, runtime downloads, and modules without redistributable license disposition.
- Self-hosted CI only; no GitHub storage features, Packages, cloud CLIs, hosted runners, scheduled workflows, external telemetry, or remote caches.
