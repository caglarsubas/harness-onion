# Repository Plan: `Harness-Engineering`

## Current adoption roadmap — MET-ADOPT-001

[Product/provider and multi-repository policy](../alpha-2/PROVIDER_ADOPTION_ROADMAP.md) is the current planning amendment.
Catalog:156 executable packet specifications (155 retained plus this meta packet);
seven extension backlog specifications remain non-dispatchable pending exact
packet/path/argv and accepted predecessor release-lock publication.
Require **at least one qualified baseline for every released harness capability** at the first enterprise release.
Alpha2 remains ONGOING. CONF-LIVE-003 draft is incomplete; native Linux is
NOT_RUN_ENV_UNAVAILABLE. Source, CI, merge, artifact and tenant acceptance differ.
The linked ownership table and machine ledger are normative for provider work;
existing public schemas, service ownership and prerequisite gates remain intact.

## Retained plan and historical publication checkpoints

Historical Alpha-2 dispatch at publication: [MET-REPAIR-016 successor checkpoint correction](../alpha-2/SUCCESSOR_CHECKPOINT_REPAIR.md).
Historical catalog155; accepted productb7586c4 has127 files /354 tests. META005 and product PERF004 source gates are closed.
Publish016, then separate CONF-FIX-006 two-path source correction; preserve354 IDs, runtime/benchmark and original proofs.
Draft12 failed one inherited127-file assertion at its approved135-file stage; no full acceptance or native promotion.
Accepted MET-PERF-001 main e367e89463b86ebc1b1e20563d677bdfe6694060 is preserved; this reconciliation runs both complete replays and all twenty commands.

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
│   ├── model-evidence-boundary.json
│   ├── readiness-repairs.json
│   ├── porting-authorization-index.yaml
│   ├── observations/data-harness-v1.json
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
├── reference-observer/
│   ├── harness-reference-observe.py
│   └── harness-reference-extract.py
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
│   ├── DEVELOPMENT_STATUS.md
│   ├── alpha-2/
│   ├── MICROSERVICE_CATALOG.md
│   ├── PROVIDER_MODULE_CATALOG.md
│   ├── READINESS_INDEX.md
│   └── SCOPE_PROVENANCE.md
├── scripts/
│   ├── validate_readiness.py
│   ├── validate_alpha2_readiness.py
│   ├── validate_readiness_repairs.py
│   ├── validate_model_usage_observation.py
│   ├── verify_offline.sh
│   ├── network_canary.py
│   ├── validate_architecture.py
│   ├── validate_reuse.py
│   ├── validate_packet_ownership.py
│   ├── validate_repository_tree_observation.py
│   ├── validate_release_set.py
│   └── zero_bill_scan.py
└── tests/
    ├── test_readiness.py
    ├── test_alpha2_readiness.py
    ├── test_readiness_repairs.py
    ├── test_model_usage_observation.py
    ├── test_validator_units.py
    ├── test_architecture.py
    ├── test_reuse.py
    ├── test_task_packets.py
    ├── test_repository_tree_observation.py
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
| `MET-002` | `architecture/reuse-map.yaml`, `architecture/reuse-path-index.yaml`, the empty `architecture/porting-authorization-index.yaml`, the separately observed structural-facts report `architecture/observations/data-harness-v1.json`, `schemas/reuse-path-index.schema.json`, `schemas/porting-authorization.schema.json`, `schemas/porting-record.schema.json`, `legal/source-reuse-authorization.yaml`, and `legal/third-party-license-policy.yaml`. It later produces the planned `architecture/reuse-map.schema.json`. |
| `MET-003` | `policies/zero-bill-policy.yaml`. |
| `MET-004` | `schemas/task-packet.schema.json`, `schemas/live-campaign-execution-envelope.schema.json`, and the one-file-per-packet `task-packets/` authority catalog. |
| `MET-005` (planned predecessor-gated authority) | `schemas/release-set.schema.json`, `release/repos.lock.json`, `release/fixture-release-set.yaml`, and `release/evidence-policy.yaml`; these paths do not become current authorities before this packet executes and produces evidence. |

## Dependencies

- Upstream: attached research artifacts for traceable scope; immutable source commits of the five warm repositories; released product-repository manifests.
- Downstream: every product repository consumes the taxonomy, zero-bill policy, task-packet schema, and a pinned contract release.
- The dependency-graph validator rejects cycles, dependency on another repository's `main`, Git submodules, and runtime Git dependencies.

## Warm-source mapping

Public source provenance is recorded only in `architecture/reuse-map.yaml`,
`architecture/reuse-path-index.yaml`, packet `sourceReuse` entries, and the three
signed metadata-only tree observations. All five approved warm repositories are
publicly named and exact-commit pinned. Their paths are unavailable to product
implementation identities, and no source is copy-authorized.

The user-authorized `data.harness/v1` observation is a manual `MET-002`
activity under the exact `referenceObservationExecution` binding. A separately
installed root-owned launcher and `planeon-reference-observer` identity may read
only the 29 declared JSON Schema blobs at the pinned commit under deny-all
egress and source-write denial. Its output contains normalized schema identities,
fields, required sets, constraints, state enums, references, and blob digests;
it excludes descriptions, examples, source text, and executable code. The later
offline acceptance run has no warm-source access. This observation grants no
copy or porting authority.

`MET-P0-001` adds a second, narrower observation mode for the other three
approved warm starts. It enumerates the full tracked Git tree at one pinned
commit but denies every source-content read, source write, source execution,
network connection, implementation-identity access, and copy authority. Each
repository uses its own packet, branch, PR, signed authority, and canonical
metadata-only report. The three reports may later populate reference-only path
authorities; they cannot authorize a port.

`MET-P0-002` consumes those reports without opening a warm checkout. It freezes
all five source trees into 905 discovery-tree and 4,202 pending-blob records,
retains zero copy authorizations, and records exact dependency-license evidence
without promoting classification into release approval.

Repository-plan paragraphs created before the observation packets that call
three inputs non-public are retained only as packet-era history. They are
non-normative and superseded by the current machine-readable five-source
authorities and the Phase-0 audit record.

## PR packets

1. `MET-001-foundation`: repository scaffold, Apache-2.0 files, toolchain, taxonomy, repository catalog, and validator tests.
2. `MET-002-reuse`: truthful reference catalog, disabled fail-closed future authorization index, non-circular destination record schema, executable snapshot locker/verifier, license policy, exact source hashes, source-object checks, and the separately launched distilled `data.harness/v1` structural observation.
3. `MET-003-zero-bill`: billing policy, static scanner, forbidden-pattern fixtures, and self-hosted workflow policy.
4. `MET-004-packets`: task-packet schema, packet validator, Alpha 1-4 index, predecessor/allowed-path validation, and the closed dual-signed live-campaign execution-envelope schema with negative vectors.
5. `MET-005-release-lock`: release-set schema, lock generator/checker, evidence policy, and fixture release set.
6. `MET-P0-001-gap-authorities`: unique correction packets, full-tree metadata observer source, closed schema, and negative vectors.
7. `MET-P0-FIX-001-tree-order`: canonical Git traversal ordering and malformed/duplicate-path regression.
8. `MET-OBS-AH-001-agent-hook`: exact-commit read-only tracked-tree metadata observation for `agent-hook-v2`.
9. `MET-OBS-OCP-001-reference-lab`: exact-commit read-only tracked-tree metadata observation for the OpenShift reference lab.
10. `MET-OBS-SDK-001-orchestra-sdk`: exact-commit read-only tracked-tree metadata observation for the Orchestra Python SDK.
11. `MET-P0-FIX-002-authority`: correct control-plane paths, SDK provenance, catalog count, and final-closure ordering before product execution.
12. `MET-P0-FIX-003-browser-authority`: include the production-derived offline browser document in the control correction boundary.
13. `MET-P0-FIX-004-reuse-authority`: include the existing reuse schema, independent validator/tests, and readiness index in final closure ownership.
14. `MET-P0-002-phase0-evidence`: five-source reference-only integration, dependency-license closure, corrected provenance, and final Phase-0 audit record.
15. `MET-A2-001-model-prerequisites`: approved Alpha-2 authority repair, narrow observation/contract packet publication, explicit original-baseline boundary and regression checks.
16. `MET-OBS-MODEL-001-usage-facts`: separately signed one-blob model-usage schema observation and source-free report validation; original source tests are not executed.

17. `MET-REPAIR-001-readiness-regressions`: publish R01–R06 corrective authority, cumulative regression gates, production integration ownership and phase-labelled evidence without claiming product fixes.
18. `MET-REPAIR-002-contract-regression-scope`: publish two exact cumulative registry-test paths and a function-bounded blocked-selection correction; preserve failed baseline and historical review evidence.
19. `MET-LINUX-001`: early Linux authority, exact 118-packet catalog, native-target evidence gates and verified contracts correction checkpoint.
20. `MET-LINUX-002`: Linux trusted-runner candidate, reproducible operator kit and isolation/build provenance probes; root installation and live evidence remain external.

Every packet uses branch `codex/<packet-id>`, changes only named paths, opens a PR, runs self-hosted CI, and merges only after all required checks pass.

21. `MET-REPAIR-003-linux-conformance-authority`: closed R1-R4 scope amendment, exact suite discovery and CONF-FIX-001 prerequisite; no product implementation or native Linux claim.
22. `MET-REPAIR-004-linux-test-ownership`: one assertion-only legacy test grant, immutable 118/120-packet history, completed runner source evidence and unchanged native/live gates.
23. `MET-REPAIR-005-model-fixture-scope`: exact model fixture-copy helper exception, immutable baseline, strict input-byte and whole-packet mutation checks; no product implementation.
24. `MET-REPAIR-006-model-api-inventory`: exact additive required-five API predicate, pinned failed-draft evidence, historical fixture routing and independent scope/safety mutations; no product implementation.
25. `MET-LIVE-001`: publish six bounded conformance backend packets, immutable predecessors and the strict source/native dispatch gate; no product or installation work.
26. `MET-REPAIR-007`: publish the exact quote-safe parser and one-hash-assertion repair authority, 164 immutable predecessor files and the additive CONF-FIX-002 dispatch prerequisite.

27. `MET-REPAIR-008`: publish the exact cumulative inventory repair, 170 immutable predecessor files, six-stage source proof and CONF-FIX-003 prerequisite.

28. `MET-REPAIR-009`: publish strict proxy authentication/admission profile, immutable 127-file/279-ID source checkpoint and additional dispatch prerequisite.
29. `MET-REPAIR-010`: publish protected read-only policy observation, exact custody/freshness/generation contracts and unchanged campaign-permission regressions.
30. `MET-REPAIR-011`: publish the bounded retained-custody handoff correction, five-path CONF-FIX-004 packet, immutable original inventory and region/prefix source-delta checks.
31. `MET-PERF-001`: measure and repair safe YAML parsing cost while preserving every assertion, both complete replays, timeouts and isolation; close independently before reconciling PR106.
32. `MET-REPAIR-012`: publish the bounded credential lifecycle, five-path CONF-FIX-005 authority and cumulative source-accounting oracle.
33. `MET-REPAIR-013`: publish the authentication-only client credential ordering exception, mandatory independent server admission and exact meta/source preservation checks.
34. `MET-REPAIR-014`: publish fixed server-local broker execution, contained worker ABI, exact cleanup and closed data-model acceptance; preserve all consumer paths and historical evidence.
35. `MET-REPAIR-015`: publish the fixed Linux qualification binding and kernel inspection contract; preserve product paths, existing privileges and separate native acceptance.

36. `MET-PERF-002`: publish the fixed performance investigation, six-path product repair and exact preservation proof; retain failures and all source/native boundaries.

37. `MET-PERF-003`: reconcile two direct historical consumers with exact eight-path source authority and measured lower-overhead profiling; retain146 old YAML and failure evidence.

38. `MET-PERF-004`: publish four exact consumer bridges, complete pinned Python source-read inventory and two observed-failure regressions; preserve148 older YAML and all source/runtime boundaries.

39. `MET-PERF-005`: define fresh reference-only measurement before bounded candidate selection, preserving failed evidence, all150 old YAML and full candidate acceptance.

40. `MET-REPAIR-016`: preserve153 packets and accepted performance history; authorize only the two-path successor checkpoint correction.

41. `MET-ADOPT-001`: approved air-gap/provider adoption policy, exact multi-repository ownership, phased coverage and source-only authority reconciliation.

## Testing, verification, and acceptance

The `MET-001` bootstrap packet declares `prefetchCommands: []` and ordered
direct-argv `offlineAcceptanceCommands` for architecture validation and tests.
Every later meta check is likewise added as an argv array in its owning packet.
The executor passes the selected hash-pinned packet through `HARNESS_TASK_PACKET`
and invokes only `offlineExecution.wrapperArgv:
["./ci/verify-offline.sh"]`; individual acceptance commands are never run
separately.

`MET-004` runs the complete readiness validator, while the Alpha-2 authority repair extends the dedicated 123-packet
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

## Early Linux implementation gate

MET-LINUX-001 owns the closed Linux policy, its validator/tests, catalog and
phase-labelled checkpoint. MET-LINUX-002 owns ci/linux-runner/,
tests/linux_runner/ and docs/linux-runner/ only. Its launcher.py, build.py and
preflight.py produce a reviewable portable candidate and operator kit; source
PASS does not grant root installation or certify Linux. Exact packet argv and
external operator custody remain mandatory.

Detailed steps, cases, evidence bindings and rollback:
[Linux readiness](../alpha-2/LINUX_READINESS.md). Full Alpha-4 enterprise
certification and tenant acceptance remain independent.

## Conformance correction authority

MET-REPAIR-003 owns the [new amendment](../../architecture/linux-readiness-amendment.json),
its validator/negative tests, current catalog and checkpoint. It preserves
architecture/linux-readiness.json byte-for-byte. The whole predecessor suite,
Linux candidate suite and new scope/discovery regressions run offline in one
signed process tree. Source publication cannot claim product repair, external
installation, native qualification or a model-effort transition.

## Assertion-only Linux test amendment

MET-REPAIR-004 owns architecture/linux-test-ownership-amendment.json and its
validator/tests. It extends the current catalog to 121, preserves the consumed
MET-REPAIR-003 record and grants CONF-LINUX-001 exactly one additional test path.
The exact six-handler assertion keeps all other test bytes unchanged; no product
or operator code is part of this publication.

## Model fixture-copy authority

MET-REPAIR-005 owns architecture/model-fixture-scope-amendment.json, the exact
source-free baseline inputs and its historical 122-packet publication. MET-REPAIR-006
owns the current successor-aware validator/test routing; those historical bytes are immutable.
It grants no runtime, source observation or root installation authority. See
[the implementation boundary](../alpha-2/MODEL_FIXTURE_SCOPE_REPAIR.md).

## Model API inventory authority

MET-REPAIR-006 owns architecture/model-api-inventory-amendment.json, the two
source-free destination/authority snapshots, dedicated validator/negative tests
and current 123-packet reconciliation. Its scoped predecessor-validator change
routes historical bytes to the pinned old packet and validates only the exact
current successor. No consumed authority, root installation or product edit.

## Approved trusted live backend enablement — MET-LIVE-001

The [coding guide](../alpha-2/LIVE_BACKEND_READINESS.md) and closed
`architecture/live-backend-roadmap.json` add six sequential conformance packets
(CONF-LIVE-001 through CONF-LIVE-006), not new repositories or harnesses.
This publication recorded 130 packets; that historical publication recorded 142. The 123 consumed packet YAML and all existing
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

## Historical packet scalar compatibility publication — MET-REPAIR-007

The [exact correction guide](../alpha-2/PACKET_SCALAR_REPAIR.md) adds MET-REPAIR-007 and
CONF-FIX-002: **132 packets**, thirteen repositories, sixteen harnesses and
**twelve** unchanged possible live declarations. The preceding 130 packet YAML
and all existing architecture/legal/policy/release bytes remain immutable.
This is the retained 132-packet publication. The successor-inventory supplement below supersedes its dispatch status.

CONF-LIVE-001 is blocked after its quoted scalar identity failed before any
acceptance command or test ran. Complete CONF-FIX-002 in a separate product PR
first: change only the exact parser branch and one full-file hash assertion,
then add independent regression evidence in its three new owned files.
No packet reserialization, dependency, root policy, installation or isolation
change is authorized. Resume CONF-LIVE-001 only after corrective source,
local offline, required PR CI, merge and separate local exact-main closure.
Retain its original 103-file/120-test baseline and add corrective provenance
only within its existing paths; the six-root/eight-command inventory is fixed.
Native Linux, live backend, runtime and tenant acceptance remain separate gates.

## Approved cumulative inventory repair — MET-REPAIR-008

The [cumulative inventory guide](../alpha-2/SUCCESSOR_INVENTORY_REPAIR.md) adds
MET-REPAIR-008 and CONF-FIX-003: **134 packets**, thirteen repositories, sixteen
harnesses and twelve unchanged possible live declarations. All 132 previous
packet YAML and existing architecture/legal/policy/release bytes are immutable
(170 files). Neither old correction record is rewritten.

MET-REPAIR-007 and CONF-FIX-002 are complete as separate source/CI/merge/local
exact-main checkpoints. Source inspection subsequently found the scalar suite's
frozen 106-file inventory rejects the next ten legitimate files; the earlier
successor-readiness inference is withdrawn, not its actual 150-test PASS.
Complete the new authority and then CONF-FIX-003 in its separate product PR:
one exact three-hunk test change and four new files, all 150 previous test IDs
plus twenty new tests. The parser and every other predecessor stay fixed.

Require complete ordered stage path sets (110, 120, 127, 135, 141, 146, 151 files),
predecessor hashes/modes, real collection and strict malformed/link/partial-stage
negatives. CONF-LIVE-006 alone may later replace the single terminal unavailable
statement after unchanged launcher manifest/preflight checks, with a bounded
SOURCE_DELTA_ONLY proof in its already-owned qualification document. That proof
is source accounting, not execution authority or a code-safety certification.

CONF-LIVE-001 remains blocked until corrective source, local offline, required
localhost PR CI, merge and local exact-main close. Then reconcile cumulative
history within its existing ten paths and unchanged six-root/eight-command
acceptance. No signed consumer packet, root policy, dependency, installation or
billing boundary changes. Native Linux and tenant acceptance remain separate;
no phase-end model-effort transition is due.

## Approved proxy contract prerequisite — MET-REPAIR-009

The [strict proxy profile](../alpha-2/PROXY_CONTRACT_READINESS.md) closes credential and resource-rule
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

The [bounded handoff correction](../alpha-2/CUSTODY_HANDOFF_REPAIR.md) adds MET-REPAIR-011 and CONF-FIX-004:
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

The [credential-lifecycle correction](../alpha-2/CREDENTIAL_LIFECYCLE_REPAIR.md) publishes
MET-REPAIR-012 and CONF-FIX-005: 140 packets, unchanged thirteen repositories,
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
Historical catalog142; conformance checkpoint9df7dd7 has 127 files / 327 tests.
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
