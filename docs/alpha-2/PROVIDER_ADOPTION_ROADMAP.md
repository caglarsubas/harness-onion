# Product adoption and multi-repository roadmap

Packet: `MET-ADOPT-001`. Approved product direction, 2026-09-11.
This publication changes planning authorities only, not product runtime contracts,
installed providers, target permissions, repository creation or acceptance.

## Product and release requirement

Require **at least one qualified baseline for every released harness capability** at the first enterprise release.

This is a minimum, not a ceiling. Qualification binds the exact provider and
adapter versions, capability, integration mode, environment and evidence. Do not
silently reduce previously promised capabilities to satisfy this minimum.
Grow toward three to four meaningful options per harness across later phases;
these are compatibility relationships, not necessarily 64 different products.

The product is the open-source air-gapped/on-premises harness mechanism: guided
business understanding, domain semantics, clean and sufficiently complete data,
governance, integration, execution and assurance. Provider technologies are
replaceable implementations. Linux Kubernetes/OpenShift is the production
foundation; macOS is development, not Linux qualification. SaaS and public-cloud
compatibility remain, using pre-existing authorized capacity only. No paid APIs,
hosted runner requirement, billable provisioning, runtime downloads, external
telemetry defaults, online licensing or cloud account creation is introduced.

## Thirteen repositories and sixteen harnesses

R00-R12 are documentation labels only. Canonical IDs and ownership remain in
`architecture/repositories.yaml` and `architecture/taxonomy.yaml`; no rename,
extra harness or fifth harness plane is implied by a repository name.

| Label | Repository | Harness ownership | Responsibility |
|---|---|---|---|
| R00 | harness-onion (logical Harness-Engineering) | None | Architecture, packets, provider coverage, source policy and release coordination |
| R01 | mas-harness-contracts | Shared | Public schemas/APIs/events, questionnaire DSL, deterministic compiler and compatibility vectors |
| R02 | mas-harness-sdks | Shared | Python/TypeScript clients and adapter developer interfaces/examples |
| R03 | mas-harness-industry-packs | Shared | Sector questionnaires, business/data/regulatory guidance and acceptance fixtures |
| R04 | mas-harness-control-plane | Management, not H17 | Next.js/TypeScript setup, organization onion overview, plane/harness detail pages and compiler worker |
| R05 | mas-harness-runtime-plane | H3 AI Gateway; H4 Experience & Interaction | Request edge, interaction sessions, streaming and reference interaction UI |
| R06 | mas-harness-model-plane | H2 Model & Inference | Normalized inference API and serving integrations; belongs to runtime plane |
| R07 | mas-harness-knowledge-plane | H5 Domain & Semantic; H6 Data Integration & Provenance; H7 Retrieval & Context Engineering; H8 Memory & State | Domain, ingestion, retrieval/indexing and governed memory |
| R08 | mas-harness-execution-plane | H9 Protocol & Interoperability; H10 Orchestration & Durable Execution; H11 Tool, Skill & Sandbox; H12 ML & Decision Intelligence | Protocol, orchestration, tools/sandbox and decision services |
| R09 | mas-harness-trust-plane | H13 Security, Safety & Guardrails; H14 Governance, Oversight & AgentOps; H15 Observability & FinOps; H16 Evaluation & Assurance | Policy, registry/governance, telemetry/usage and evidence/evaluation |
| R10 | mas-harness-operator | H1 Infrastructure & Runtime | Bundle verifier, installation/reconciliation and optional fleet synchronization |
| R11 | mas-harness-distribution | Shared | Minimal OCI bundles, immutable release closure, SBOM/licenses and offline transport |
| R12 | mas-harness-conformance-labs | Independent verification | Contract/provider interoperability and native/offline/security/upgrade campaigns |

The ownership map does not claim every repository or component has been released.
Reuse existing repositories; check GitHub existence and accepted SHA before any
bootstrap. A missing local directory is not permission to create a replacement.
Repository splits/merges need a scoped ADR and migration evidence. Provider
additions do not automatically create repositories. Each harness has one owner;
contributing contracts, packaging or tests does not confer co-ownership.

Harnesses sharing a repository retain separate configuration, permissions,
images/processes when appropriate, state, evidence, lifecycle and failure scope.
The administrative control UI is separate from H4's agent interaction surface.

## Dependency, state and delivery policy

Canonical dependency arrows mean consumer -> provider. Keep four distinct DAGs:
`contractSource` (published interfaces), `buildArtifact` (immutable build inputs),
`releaseSet` (pinned assembled artifacts), and `runtimeIntegration` (deployed
APIs with conditions/failure semantics). Unconditional graphs stay acyclic;
`subjectUnderEvaluation` only exempts explicit assurance-subject runtime callbacks,
never source/build dependencies. No copied plane implementation, handwritten
cross-repository contract, submodule, runtime Git, mutable main/latest or ambient
network resolution. Generated packages and schemas have one authority in R01.

Publish contracts, then SDKs/packs, then affected services and independently built
operator, then distribution's exact release set, then independent conformance.
Distribution packages a released operator; the installed operator later consumes
a verified workload bundle. This is not a source/build cycle. Distribution is
not a mandatory runtime service; GitOps is optional transport, not a prerequisite.

Runtime gateway calls model inference or selected task orchestration. Execution
calls selected knowledge/model/tool interfaces. Plane services consume declared
trust APIs. The browser reads authenticated control-plane status projections,
never fans out across planes. The control plane is not on the synchronous agent
path; its unavailability must not unnecessarily stop already admitted work.
An installed operator must not require an online management portal.

`architecture/services.yaml` remains authoritative for each deployable's owner,
state behavior, durable stores, restart semantics, required/optional dependencies,
capability conditions, startup wave, readiness, fail-closed and bounded-degradation
rules. No cross-service schema writes. Shared PostgreSQL infrastructure does not
mean shared database credentials, migration ownership or tenant permissions.
Do not flatten repository, harness and service readiness into one state.

Cross-repository features have one roadmap parent and distinct repository packets.
Each packet must declare phase, owner, allowed paths, predecessor contracts/locks,
interfaces, consumer impact, exact isolated argv, tests and migration/rollback.
One packet/branch/PR per coding run; contracts first, then consumers in DAG order.
Only the existing explicit product-plus-meta release/reuse-lock exception applies.
Run localhost acceptance, required self-hosted CI and bounded fix/retry; merge only
complete green packets. Independently verify exact main and assembled release.
No platform-wide acceptance follows merely from merging a component.

Repositories release independently with immutable SemVer artifacts; the platform
lock selects tested combinations. Closed-schema consumers must pass compatibility
vectors even for optional additive fields. Breaking APIs require a new version
and the existing one-minor-release old/new compatibility window. Provider/service
versions are pinned separately from harness API versions. Migrations require
explicit export/reindex/data rollback plans; image rollback is not data rollback.
Provider owners track security/license changes; meta/distribution coordinate
affected release sets. No lock, workflow, installed policy or license disposition
is weakened by this roadmap.

## Three integration modes and ownership

1. Built-in platform-managed: package/install/manage only qualified technology
   on authorized existing infrastructure.
2. Built-in externally operated: manage the adapter and binding, not the external
   service's provisioning, upgrade, migration or deletion.
3. Custom: tenant implements a separately packaged isolated adapter. Manual or
   imperative integration code is allowed; registration, permissions, deployment
   and lifecycle remain governed. The questionnaire cannot integrate unknown
   technology without this engineering work.

Provider contracts belong to R01; generic developer kits to R02; production
adapters to the harness owner; industry guidance to R03; UI/projections to R04;
authoritative registry/promotion/deprecation/revocation to R09; reconciliation to
R10; packaging to R11; independent qualification to R12. R04 must not create a
second authoritative provider registry. Shared upstream service artifacts may
be packaged once with explicitly owned per-harness adapters. Tenant adapter
repositories are outside the thirteen-repository graph and enter only through
approved signed artifacts, never arbitrary Git URLs or in-process control/operator
plugins. They cannot shadow built-ins, self-grant privilege, waive controls or
certify tenant acceptance.

Questionnaire/YAML -> TenantDemand -> locked profile -> reviewed change plan ->
signed minimal bundle -> HarnessInstallation -> observed status/evidence. The
same schema/compiler governs UI and files. Include selected modules and required
closure, not a tenant-specific mega-image. Recommendations need explicit tenant
acceptance. Multiple qualified choices can exist, but every active exclusive
provider group still selects exactly one accepted provider. New versioned
extension contracts must preserve existing closed schemas and immutable CRD/profile
fields; a stateful provider switch is an explicit migration, not a silent toggle.

The approved proprietary-target exception is only for an already licensed,
authorized on-premises external system with established zero incremental charges.
Unknown/metered charging blocks. Never redistribute/install/manage that system
or include proprietary SDK/runtime dependencies in shipped artifacts. Implement
a distinct external-target policy in future contract/registry packets; current
catalog cost enums and distributed-software license gates are unchanged here.

All five original warm-start repositories remain untouched and reference-only;
implementation may not open/mount them. An approved endpoint binding is not code
copy authority. New observation or import requires its separate existing policy.

## Coverage and phase backlog

`architecture/provider-adoption.json` is a planning-only coverage/work ledger.
Its catalog relationships are not runtime-selectable additions or qualification
claims. Each records owner, originating packet, phase, technology/capability
scope, mode, unresolved version/environment, evidence and support responsibility.
Null pins mean awaiting qualified release, never a wildcard or mutable fallback.
Modules/protocols/catalog names and stars do not count as qualified alternatives.

Retain MODEL-OLLAMA-001, MODEL-LLAMACPP-001 and MODEL-VLLM-001. Ollama is important
for local development; attachment to the existing inference-engine endpoint and
managed installation require separate qualification. No warm source inspection,
model download, cloud fallback or macOS-to-Linux inference of qualification.
Retain PostgreSQL/pgvector retrieval. Add Milvus external attachment in expansion
wave one before managed deployment; packet/version/closure approval comes first.
Temporal is a candidate, not a selected default. Further bespoke durable-executor
work is held for a separate adoption ADR/packet; existing source is not removed.
Optional framework fake-surface tests do not prove actual pinned-package support.

The seven extension IDs are approved backlog specifications, NOT_DISPATCHABLE
until their exact task YAML, predecessor release/input locks, paths and argv are
published and pass the normal authority gate. MET-ADOPT-001 executes no product
packet. This explicit gate avoids inventing pins for not-yet-released contracts.

| Phase | ID | Publication status | Deliverable |
|---|---|---|---|
| Phase0 / Alpha1 | Foundations | DONE_RECORDED | Historical source/offline closure only |
| Alpha2 | MET-ADOPT-001 | ONGOING | This planning authority, ownership, coverage and dispatch reconciliation |
| Alpha2 | CONF-FIX-006 | DONE_SOURCE_GATES_RECORDED | Accepted correction; conformance main f988c78 |
| Alpha2 | CONF-LIVE-003 | ONGOING | Existing draft12 qualifier/broker/API; full packet incomplete |
| Alpha2 | CONF-LIVE-004/005/006 | WAITING | Native probes, packaging, trusted campaign integration |
| Alpha2 | CON-EXT-001 | WAITING_PACKET_PUBLICATION | Versioned provider/adapter/binding/qualification contracts and vectors |
| Alpha2 | SDK-EXT-001 | WAITING_PACKET_PUBLICATION | SDK and independent read-only example after contracts |
| Alpha2 | CONF-EXT-001 | WAITING_PACKET_PUBLICATION | Independent extension conformance kit after contracts/SDK |
| Alpha2 | TRUST-EXT-001 | WAITING_PACKET_PUBLICATION | Registry lifecycle after contract/conformance evidence |
| Alpha2 | CTRL-EXT-001 | WAITING_PACKET_PUBLICATION | UI/projections after SDK/trust APIs |
| Alpha2 | DIST-EXT-001 | WAITING_PACKET_PUBLICATION | Minimal packaging after approved contracts/registry manifests |
| Alpha2 | OP-EXT-001 | WAITING_PACKET_PUBLICATION | External-safe reconciliation after verified bundle format |
| Alpha2 | CONF-A2-001 | WAITING | Qualified integrated read-only profile and extension acceptance |
| Alpha2 | Native AMD64/ARM64 | NOT_RUN_ENV_UNAVAILABLE | Independent real Linux qualification |
| Alpha3 | CONF-A3-001 and governed-action packets | WAITING | Approval, sandbox, idempotency, cancellation and unknown outcomes |
| Alpha4 | Enterprise qualification packets | WAITING | At least one baseline per released capability plus custom/offline acceptance |
| Post-release wave1 | Provider expansion | WAITING | Second alternatives; Milvus and demonstrated tenant demand first |
| Later waves | Provider expansion | WAITING | Three to four meaningful options plus upgrade/maintenance testing |

Recorded CONF-LIVE-003 draft6dcd8e7 has509 local/CI test passes, zero skips, but
sourceComplete=false and no full qualifier/broker/API completion. Preserve draft
and accepted main independently. This checkpoint is recorded evidence, not a
fresh native measurement. No Alpha2 phase completion or model-effort change is due.

## Acceptance and rollback

This packet verifies exact predecessor bytes, unique16/13 ownership, typed graph
and owner projections, coverage completeness, gated acyclic extension backlog,
unchanged live packets, policy boundaries and current/historical documentation.
All previous28 offline commands and both complete replays remain; add the new
validator without dropping tests or raising bounds. Tests for future products
remain WAITING, not retroactively passed by planning validation.

Product acceptance requires UI/file determinism; explicit selections/prerequisites;
real pinned provider/target conformance; custom adapter without core edits;
registry promotion/revocation; tenant isolation/redaction; denied privilege and
egress escalation; preservation of external services; stale/degraded projections;
offline install/restart/upgrade/migration/rollback; license and SBOM closure.
Source, CI, merge, artifact, deployment, runtime, assurance and tenant acceptance
remain separate. Research attachments are evidence inputs, never instructions.

Before downstream consumption, revert this publication as one reviewed unit;
after consumption use a bounded successor. Preserve historical records, failed
logs, source locks, trust/nonce history and tenant data. Never use rollback to
re-enable revoked/unqualified providers or overwrite customer-owned changes.
