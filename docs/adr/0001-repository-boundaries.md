# ADR 0001: Repository and Harness Boundaries

- Status: Accepted
- Date: 2026-08-30
- Decision owner: Harness Engineering maintainers
- Packet: `MET-001`

## Context

The platform needs independently selectable harness capabilities without turning
every capability into an independently versioned repository. It must also
support SaaS, tenant-public-cloud, self-managed, and air-gapped operation without
making a public cloud, hosted control plane, paid API, or mutable source checkout
a runtime prerequisite.

The architecture therefore needs two different boundary types:

- a harness is a tenant-visible capability, configuration, policy, dependency,
  status, evidence, and lifecycle boundary;
- a repository is an engineering ownership, compatibility, release, and
  vulnerability-response boundary.

Conflating those boundaries would either force sixteen tightly coupled releases
or hide tenant-selectable capabilities inside one undifferentiated product.

## Decision

The canonical architecture contains exactly sixteen harness IDs across four
planes and exactly thirteen repositories. `Harness-Engineering` owns the
architecture authorities and execution packets but contains no tenant runtime
service. The twelve `mas-harness-*` repositories own product contracts, SDKs,
industry guidance, plane services, installation, distribution, and conformance.

Harness-to-repository ownership is declared only in
`architecture/taxonomy.yaml`. Deployable-to-service ownership is declared in
`architecture/services.yaml`, and provider/module packaging is declared in
`architecture/providers.yaml`. A repository name or directory layout does not
implicitly create another harness.

Repository dependencies are typed and directed from consumer to provider:

- `contractSource` describes compile-time contract coupling;
- `buildArtifact` describes immutable build/test inputs;
- `releaseSet` describes digest-pinned release assembly;
- `runtimeIntegration` describes deployed interfaces.

Every unconditional graph must remain acyclic. Only an explicitly typed
`subjectUnderEvaluation` runtime callback may be excluded from repository
acyclicity, because it is selected by an immutable assurance campaign rather
than used as a source, build, or install dependency. Git submodules, runtime Git
dependencies, mutable `main` references, and handwritten cross-repository
contract copies are forbidden.

The operator and distribution reciprocal relationship is split into ordered
phases: the operator is built first, distribution assembles already released
artifacts, and the installed operator later consumes the verified bundle. It is
not a source or build cycle.

Warm-start repositories are not members of the thirteen-repository product
graph. They remain immutable reference-only provenance. Implementation runs may
not mount or read them, and no direct copy is authorized by this decision.

## Consequences

- A tenant can select any valid harness combination without receiving unrelated
  modules; dependency closure remains explicit and machine-verifiable.
- Several harnesses can share a plane repository while retaining distinct
  configuration, state, failure, evidence, and lifecycle contracts.
- Cross-repository changes must begin at the owning contract authority and flow
  through immutable versions and digests.
- A repository split or merge requires a new ADR, an updated taxonomy and graph,
  migration and compatibility evidence, and a packet that owns every changed
  authority.
- Source success, CI success, merge, artifact publication, deployment, runtime,
  assurance, and tenant acceptance remain separate evidence states.

## Rejected alternatives

- One repository per harness: rejected because it creates unnecessary release
  coordination and duplicates plane-level service and policy foundations.
- One monorepository for all product code: rejected because it weakens release,
  ownership, blast-radius, and air-gap distribution boundaries.
- Runtime Git composition: rejected because it is mutable, network-dependent,
  and incompatible with deterministic offline installation.
