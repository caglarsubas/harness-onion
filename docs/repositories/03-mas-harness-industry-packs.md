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
- Base toolchain: Python 3.12.14, `uv` 0.12.7,
  `jsonschema==4.24.0`, `PyYAML==6.0.2`, and `pytest==8.4.2` in the
  development group. IND-WG-001 advances the framework distribution to 0.1.1
  and adds development-only `rdflib==7.6.0` and `pyshacl==0.40.1` with an exact
  transitive offline wheel closure. The framework runtime dependencies remain
  unchanged; packet execution never resolves or downloads a package.
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

## IND-001 framework contract

IND-001 binds but does not copy the public contract release. The
`common/contracts.lock.json` authority fixes contracts commit
`2146278a95344cd2a8e22596b2f315b46edffc88`, release-manifest SHA-256
`c5dd4c39d1c69d07f8d8de3d1a09584bb906172fee2d5ac20ad25ff344b0db79`,
catalog digest
`sha256:26d442c4e90a19d767d32e80ef9df3d154b3146d3238dc0eecf29ee773913a26`,
and the exact public guidance/readiness schema paths and digests. Product
acceptance receives no upstream source path and performs no network lookup.

The common journey has exactly eight stages, in this order:

1. `business-context`
2. `domain-and-outcomes`
3. `data-readiness`
4. `governance-and-regulation`
5. `integration-readiness`
6. `harness-demand`
7. `environment-and-provider-fit`
8. `evidence-and-acceptance`

`common.foundation` 1.0.0 is immutable and industry-neutral. A sector pack
binds the common pack's computed digest and uses only `APPEND_ONLY` overlay
semantics. It may add uniquely identified content to an existing stage. It may
not replace, delete, shadow, reorder, or weaken common content, and it may not
extend another sector pack. This keeps sector guidance adjustable without
letting an industry overlay bypass foundational business, data, governance, or
acceptance gates.

The loader admits only closed data/document formats and regular files under an
explicit pack root. Links, traversal, hidden or unlisted files, executable
suffixes or modes, duplicate YAML/JSON keys, custom YAML tags, unknown fields,
unsafe rule operators, templates, code, filesystem/network targets, secrets,
and LLM prompts fail closed. Rules use the eight public guidance operators and
the four public guidance actions only.

`harness-pack validate` emits deterministic validation evidence.
`compile-index` exclusively creates canonical JSON whose file records bind
path, media type, size, and SHA-256. `package` exclusively creates a fixed-
epoch, sorted, mode-0644 tar.gz containing the computed index. Neither command
overwrites, signs, publishes, deploys, or reports runtime, assurance, or tenant
acceptance. Framework wheel/sdist, index, and pack archive all require two-build
byte identity.

## Dependencies

- Upstream: pinned `mas-harness-contracts` schemas/compiler and meta taxonomy.
- Downstream: control plane consumes signed pack artifacts; conformance labs consume fixtures; knowledge/trust planes consume accepted domain/control artifacts, never pack source files directly.
- Packs cannot import one another. They extend the versioned `common` pack through declared overlay/precedence rules.

## IND-WG-001 business-domain contract

IND-WG-001 binds exact industry-pack main commit
`a626437a18cd27d75cb96e0d846f56a235313c98`, common pack digest
`3cfea19e6e0a4a653d63622e250f40001b4f8221ebab18fa5bfc1601b8eddea3`,
and the reproducible framework 0.1.0 wheel. `white-goods` is a clean-room,
Apache-2.0 sector overlay; historical `sourceReuse` entries are provenance only
and no warm checkout is observed or mounted.

The first sector slice defines business objectives, accountable roles, four
product families, manufacturing processes, quality characteristics, CTQs,
KPIs, acceptance outcomes, and synthetic answer vectors. Plant identities,
measured values, production thresholds, customer/employee data, regulatory
conclusions, and credentials remain tenant-evidence-dependent and absent.

The ontology uses `urn:planeon:white-goods:*` for domain terms. RDF-family
content may identify only the exact W3C RDF, RDFS, XSD, OWL, and SHACL
namespaces without dereferencing them. Every other remote IRI remains invalid.
SHACL validation is local-only with imports, JavaScript, SPARQL, advanced mode,
and inference disabled. A positive graph must conform and a negative graph must
produce the expected constraint components.

Framework 0.1.1 owns the narrow semantic-identifier exception. It does not
relax the general network-target prohibition and does not alter the 0.1.0 pack
format. The packet updates deterministic wheel/sdist evidence because framework
source changed; the immutable common pack and its digest do not change.

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
[["make","pack-framework-test"],["make","build-reproducible"],["make","zero-bill"]]`.
Later packets add lint, type, coverage, pack validation, white-goods, index, and
reproducibility checks as direct argv arrays. The executor supplies the
hash-pinned packet through `HARNESS_TASK_PACKET` and invokes only
`offlineExecution.wrapperArgv: ["./ci/verify-offline.sh"]` for the complete
ordered list.

IND-WG-001 declares `prefetchCommands: [["make","prefetch"]]` and ordered
acceptance commands for `make pack PACK=white-goods`, the exact business-domain
pytest file under the repository test tree, framework reproducibility, and
zero-bill validation. Tests remain outside `packs/white-goods` because every
path beneath a distributable pack root is closed data inventory and executable
suffixes fail closed. The
packet-owned handler verifies dependency versions, closed local SHACL settings,
pack/index/archive determinism, answer-vector decisions, and false downstream
evidence flags without retaining an artifact. Registering the packet-owned Make
descriptor also updates the existing closed descriptor-inventory regression
test; the dispatcher and bootstrap-owned Makefile remain unchanged.

Acceptance proves: the journey works without an LLM; invalid/executable rules fail closed; missing business owner or data evidence blocks approval; identical answers produce identical pack requirements; all fixtures are synthetic and license-clean; and white-goods minimal/regulated/air-gap demands compile to expected digests.

## Release and rollback

- Tag packs independently as `<industry>-vMAJOR.MINOR.PATCH`; sign the pack manifest offline and record contracts/catalog digests.
- Existing questionnaire sessions remain pinned to their starting pack version. Upgrades create a new session revision and show changed questions/findings.
- Rollback selects a prior signed pack; completed evidence is re-evaluated and marked stale where thresholds differ, never silently reclassified.

## Zero-bill rules

- Packs contain no URLs requiring paid accounts, cloud resources, API keys, remote fonts/assets, executable code, or runtime downloads.
- Provider preferences select only open-source/self-hosted defaults and pre-existing tenant infrastructure.
- Self-hosted offline CI only; no GitHub storage services, hosted runners, scheduled workflows, or external evaluation APIs.
