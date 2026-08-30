# Repository Plan: `mas-harness-industry-packs`

## Purpose and boundaries

This repository owns the guided enterprise setup content: universal foundational questions, sector-specific questionnaires, ontologies, readiness thresholds, regulatory/control mappings, provider preferences, representative fixtures, and deterministic pack validation. The first supported pack is white-goods manufacturing.

Non-goals:

- No tenant answer data, UI, database, workflow execution, executable rule code, model call, or network connector.
- A pack recommends requirements and providers but cannot override platform security, compatibility, license, or zero-bill policy.
- No LLM is required to complete, validate, or compile a questionnaire.

## Repository structure and exact tree

This tree projects the current task-packet `allowedPaths`. Directory entries do not authorize edits beyond the packet executed in a coding run.

```text
mas-harness-industry-packs/
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
├── src/planeon_industry_packs/
├── common/
├── packs/white-goods/
│   ├── pack.yaml
│   ├── pack.lock.json
│   ├── manifest.json
│   ├── questions/{business,data,governance,integrations}/
│   ├── rules/{data-readiness.json,governance.json}
│   ├── ontology/
│   ├── controls/
│   ├── data/
│   ├── provider-preferences/
│   ├── fixtures/{answers,demands,e2e,expected,governance,readiness,sources}/
│   └── tests/{test_business_domain.py,test_data_readiness.py,test_e2e_fixtures.py,test_governance.py,test_profiles.py}
├── schemas/
├── scripts/build_pack_manifest.py
├── docs/
│   ├── authoring.md
│   └── white-goods/{business-domain.md,certification.md,data-readiness.md,governance.md,profiles.md}
└── tests/{framework,fixtures/framework}/
```

## Package, toolchain, and owned interfaces

- Distribution/import: `planeon-harness-industry-packs` / `planeon_industry_packs`.
- Toolchain: Python 3.12.14, `uv` 0.12.7, RDFLib, pySHACL, jsonschema, PyYAML, pytest, Ruff, and mypy; exact versions are locked.
- CLI: `harness-pack validate`, `harness-pack test`, `harness-pack compile-index`, and `harness-pack package`.
- Artifact: an OCI pack artifact containing only data, schemas, fixtures, documentation, and digests; no executable hook.
- Rules use only `all|any|not|eq|in|exists|gte|lte` and may emit questions, requirements, blockers, or recommendations.
- APIs/events/stores: none. Control-plane APIs serve pack content after validating a pinned pack artifact.

Every pack versions readiness thresholds for schema validity, required-field completeness, freshness, provenance coverage, duplicate rate, sensitive-data classification, ownership, retention, and access approval. Every threshold names evidence source, evaluation method, severity, waiver eligibility, and expiry.

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

- Upstream: pinned `mas-harness-contracts` schemas/compiler and meta taxonomy.
- Downstream: control plane consumes signed pack artifacts; conformance labs consume fixtures; knowledge/trust planes consume accepted domain/control artifacts, never pack source files directly.
- Packs cannot import one another. They extend the versioned `common` pack through declared overlay/precedence rules.

## Warm-source mapping

Public source provenance is recorded only in `architecture/reuse-map.yaml`, `architecture/reuse-path-index.yaml`, and packet `sourceReuse` entries. Non-public planning inputs have already been distilled into independent public contracts and acceptance criteria; their repository names, commits, paths, and object IDs are deliberately omitted. They are not mounted or required during implementation. No source is copy-authorized.

## PR packets

1. `IND-001-framework`: loader, common eight-stage journey, rule/static-safety validation, overlay semantics, pack index, and authoring guide.
2. `IND-WG-001-business-domain`: white-goods objectives, roles, asset/product/process ontology, CTQs, KPIs, and representative answer sets.
3. `IND-WG-002-data-readiness`: source inventory, mock API/DB/file/event data, completeness/freshness/provenance/classification thresholds, and failure fixtures.
4. `IND-WG-003-governance-integrations`: regulatory/control mapping, autonomy/action categories, integration declarations, credential/side-effect questions, and waiver rules.
5. `IND-WG-004-provider-profiles`: minimal ARM64, minimal AMD64, regulated OpenShift, silo, and air-gap provider recommendations plus explicit accepted-selector fixtures and expected compiler outputs.
6. `IND-WG-005-certification-fixtures`: deterministic end-to-end fixtures and signed pack artifact manifest.

## Testing, verification, and acceptance

The `IND-001` bootstrap packet declares
`prefetchCommands: [["make","prefetch"]]` and ordered
`offlineAcceptanceCommands:
[["make","pack-framework-test"],["make","zero-bill"]]`.
Later packets add lint, type, coverage, pack validation, white-goods, index, and
reproducibility checks as direct argv arrays. The executor supplies the
hash-pinned packet through `HARNESS_TASK_PACKET` and invokes only
`offlineExecution.wrapperArgv: ["./ci/verify-offline.sh"]` for the complete
ordered list.

Acceptance proves: the journey works without an LLM; invalid/executable rules fail closed; missing business owner or data evidence blocks approval; identical answers produce identical pack requirements; all fixtures are synthetic and license-clean; and white-goods minimal/regulated/air-gap demands compile to expected digests.

## Release and rollback

- Tag packs independently as `<industry>-vMAJOR.MINOR.PATCH`; sign the pack manifest offline and record contracts/catalog digests.
- Existing questionnaire sessions remain pinned to their starting pack version. Upgrades create a new session revision and show changed questions/findings.
- Rollback selects a prior signed pack; completed evidence is re-evaluated and marked stale where thresholds differ, never silently reclassified.

## Zero-bill rules

- Packs contain no URLs requiring paid accounts, cloud resources, API keys, remote fonts/assets, executable code, or runtime downloads.
- Provider preferences select only open-source/self-hosted defaults and pre-existing tenant infrastructure.
- Self-hosted offline CI only; no GitHub storage services, hosted runners, scheduled workflows, or external evaluation APIs.
