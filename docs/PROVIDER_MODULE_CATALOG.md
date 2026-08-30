# Provider and Module Catalog

## Authority and evidence boundary

[architecture/providers.yaml](../architecture/providers.yaml) is the machine-readable authority for module identity, demand admission, capability selection, provider exclusivity, network targets, module compatibility, assurance subjects, dependency closure, and example profile outcomes. [schemas/provider-module.schema.json](../schemas/provider-module.schema.json) closes its record shape. [architecture/services.yaml](../architecture/services.yaml) remains authoritative for runtime service dependency modes and state propagation; the catalog binds those service identities to module identities without redefining service behavior.

The catalog and every module are `PLANNED`. Catalog presence is design evidence only. It is not source, CI, merge, artifact, signature, deployment, runtime, assurance, support, or tenant-acceptance evidence.

## Coverage snapshot

| Measure | Planned coverage | Machine-readable location |
|---|---:|---|
| Module/provider records | 87 | `modules` |
| Repository packet implementations | 59 | `implementationOwnership.*.disposition: REPOSITORY_PACKET` |
| Tenant external prerequisites | 23 | `implementationOwnership.*.disposition: EXTERNAL_PREREQUISITE` |
| Contract-only non-installables | 5 | `implementationOwnership.*.disposition: CONTRACT_ONLY` |
| Tenant-supplied prerequisite IDs | 20 | `modules[].id` beginning `external.` |
| Canonical harnesses | 16 | Runtime, knowledge, execution, and trust harness IDs |
| Registered capability/fact IDs | 312 | `capabilityRegistry` |
| Forbidden demand capabilities | 49 | `policy.forbiddenDemandCapabilities` |
| Capability implication rules | 17 | `capabilityImplications` |
| Capability-to-module bindings | 91 | `capabilityProviders` |
| Exclusive provider groups | 5 | `providerExclusivityGroups` |
| Closed network targets | 76 | `networkTargetRegistry` |
| Typed module compatibility records | 87 | `moduleCompatibility` |
| Service-to-module identities | 28 | `serviceModuleBindings` |
| Cross-model dependency satisfaction rules | 2 | `dependencySatisfaction` |
| Deterministic profile fixtures | 4 | `profileExamples` |

The three Kubernetes targets have `scope: EXTERNAL` because the tenant supplies the cluster, but they are provider alternatives rather than extra `external.*` prerequisite IDs.

## Implementation ownership and installability

Every one of the 87 module records has exactly one closed
`implementationOwnership` disposition. A `REPOSITORY_PACKET` record names one
packet in the same repository as the module owner, one implementation path
covered by that packet's `allowedPaths`, and the zero-based index of the packet
deliverable that owns the implementation. This is planning authority only: it
does not claim that the packet ran or that source, CI, merge, artifact,
deployment, runtime, or assurance evidence exists.

An `EXTERNAL_PREREQUISITE` is supplied and operated by the tenant on
non-metered capacity. It is not implemented or provisioned by this platform and
cannot satisfy release admission until its local immutable fact or artifact is
tenant-attested and pinned. The 23 records comprise the 20 `external.*`
prerequisites plus the three tenant-supplied Kubernetes distribution choices.

The five `CONTRACT_ONLY` records are `provider.planeon.mlx`,
`provider.planeon.litellm-local`, `provider.planeon.jena`,
`provider.planeon.connector-sftp`, and `provider.planeon.qdrant`. They preserve
comparative compatibility and questionnaire guidance, but are explicitly
non-installable: no current packet jointly owns a matching implementation path
and deliverable. The compiler must reject their selection with
`PROVIDER_UNAVAILABLE` before dependency closure or bundle construction. A
future implementation requires a new or revised task packet and a catalog
revision that changes the exact record to `REPOSITORY_PACKET`; documentation or
a broad repository directory alone cannot activate it.

## Deterministic profile fixtures

Each fixture carries typed Kubernetes distribution/API/grant, architecture, operating-system, isolation, connectivity, accelerator, storage-mode, resource-class/capacity, network-locality, runtime-class, and capability facts plus an explicit fact-attestation state. Provider selectors are accepted questionnaire choices and never environment facts. Numeric capacity and Kubernetes version are deliberately unresolved in design fixtures. The four catalog fixtures remain truthfully `MISSING_PLANNED`; they demonstrate deterministic compilation but cannot be released. A real release compiler accepts environment facts only when their digest is `LOCKED` and their signature is `VERIFIED`.

Every fixture also declares `assuranceSubjects` as an explicit harness-and-capability subject set. That set is separate from the installed module closure: it says what an assurance campaign evaluates, not what the installer deploys. Subject capabilities must be `PUBLIC_DEMAND` capabilities and a subset of the accepted, resolved tenant demand; selectors, environment facts, and internal provider tokens cannot be smuggled into it. Its subject-set digest and signature also remain `MISSING_PLANNED` until a release compiler serializes, hashes, and signs the exact selection. `selectedModules` is regenerated from accepted public demand, explicitly accepted selectors, signed environment facts, and fixed-point implications. `expectedClosure` is the exact dependency closure, and `externalPrerequisites` is exactly the `external.*` subset.

| Profile | Directly selected | Exact closure | External facts | Important decision |
|---|---:|---:|---:|---|
| `profile.foundation-airgap-k3s-arm64` | 11 | 30 | 11 | ARM64 K3s, local OCI layout, file ingestion, no inference or orchestration |
| `profile.whitegoods-readonly-amd64` | 20 | 41 | 11 | White-goods pack, cited retrieval, llama.cpp, MCP, read-only task experience |
| `profile.governed-action-openshift` | 22 | 46 | 14 | OpenShift, vLLM, A2A, Kata runtime class, ONNX, governed tools |
| `profile.governed-memory-dedicated-cluster` | 8 | 25 | 10 | Dedicated cluster, pgvector memory, concrete llama.cpp embedding backend |

The OpenShift governed-action fixture uses Kata, not gVisor. The catalog declares gVisor compatible with upstream Kubernetes and K3s, while the Kata provider explicitly declares OpenShift compatibility. The questionnaire request, environment facts, selected provider, excluded provider, and closure now agree.

## Closed capability admission

`capabilityAdmission` classifies 25 public demand capabilities, 24 signed environment-fact capabilities, and the exact 16 selector capabilities appearing in the five exclusive groups. Every registered capability outside those disjoint lists is `INTERNAL_ONLY`. `requestedCapabilities` admits only public demand and provider selectors; `environmentFacts.capabilities` admits only environment facts. Protocol and sandbox demands have distinct `protocol.provider.*` and `sandbox.provider.*` selectors, so requesting a capability cannot silently double as accepting an implementation. An internal token in either input is `INVALID_CAPABILITY_ROLE`, and a selector for an inactive group is `INVALID_COMBINATION` rather than a silently ignored request.

Ranking is recommendation-only. A ranked result is a `PROPOSED_SELECTOR_ONLY`; it cannot enter a profile until the tenant explicitly accepts that selector into `requestedCapabilities`. Missing active-group selection returns `NEEDS_INPUT`, multiple accepted selectors return `AMBIGUOUS_PROVIDER`, and compatibility failure never substitutes a fallback member.

`assurance.local-model-judge` activates the assurance worker and inference API, but also carries a closed conditional requirement for either `model.local-cpu` or `model.local-gpu` and one accepted `group.model-backend` selector. Missing model class or selector returns `NEEDS_INPUT`; no backend is inferred.

## Capability resolution

The compiler applies this closed algorithm:

1. Reject every requested or environment capability absent from `capabilityRegistry`, then enforce its `capabilityAdmission` classification and input context.
2. Reject any requested capability in `policy.forbiddenDemandCapabilities` before implication or provider resolution.
3. Start with only accepted public demand, explicitly accepted selectors, and signed environment facts, then apply `capabilityImplications` repeatedly to a fixed point. Implications may not satisfy explicit selection by injecting an exclusive-group selector or its concrete member-provider token.
4. Resolve every active non-exclusive `capabilityProviders` binding with `ALL`. Each executable provider token maps to exactly its one owning module; `EXACTLY_ONE` is invalid here.
5. For every activated exclusive group, read selectors only from the tenant-accepted requested input, find exactly one, map it to its declared member, and enforce `EXACTLY_ONE_EXPLICIT_SELECTOR`. Reject inactive selectors. Compatibility filtering and recommendation ranking never choose on the user's behalf.
6. Resolve `implementationOwnership`; admit only `REPOSITORY_PACKET` and `EXTERNAL_PREREQUISITE`, and reject `CONTRACT_ONLY` with `PROVIDER_UNAVAILABLE` before closure.
7. Add ordinary dependencies and subject-applicable conditional dependencies to a fixed point. Subject predicates may match explicitly selected subject harnesses or subject capabilities.
8. Re-evaluate every selected module's `capabilityCondition`; reject missing `allOf`, unsatisfied `anyOf`, or active `not` facts.
9. Validate every closure module against the signed OS, isolation, Kubernetes API/grant, storage, resource, network-locality, and runtime-class facts.
10. Require `selectedModules`, `externalPrerequisites`, and `expectedClosure` to equal the derived results and reject excluded or surplus units.

The existing per-module `providers` tokens are exposed as executable provided-capability identities by `capabilityProviders`. Every one of the 91 provider tokens resolves with `ALL` to exactly its one owning module. Exclusive-group members are selected only through accepted selector mappings; model and platform implications no longer inject a concrete member. Selection therefore does not depend on display names, YAML order, recommendation ranking, or circular `EXACTLY_ONE` resolution.

## Exclusive provider groups

| Group | Members | Activation |
|---|---:|---|
| `group.infrastructure-provider` | 3 | Any Kubernetes deployment |
| `group.model-backend` | 4 | Local CPU, local GPU, or semantic-memory request |
| `group.protocol-adapter` | 4 | MCP, A2A, OpenAPI, or AsyncAPI request |
| `group.native-sandbox-provider` | 2 | gVisor or Kata native isolation request |
| `group.decision-provider` | 3 | Deterministic ONNX decision request |

Each group contains an explicit selector-capability-to-member table. An activated group must have exactly one tenant-accepted selector and that selector's member must be the sole group member in the closure. A selector with no active group is invalid. Missing, ambiguous, duplicate, or out-of-group mappings are compile errors. Platform compatibility may reject an explicitly selected member, but it may never silently substitute another.

## Typed network closure

Every string in `network.ingressFrom` and `network.egressTo` has exactly one record in `networkTargetRegistry`. The registry fixes its target class, locality, allowed direction, resolution authority, and `LOCAL_OR_SIGNED_TENANT_PRIVATE_ONLY` address policy. All records set both `urlLiteralAllowed` and `publicHostAllowed` to `false`.

Module IDs resolve only to cluster-local services; `external.*` targets resolve only through catalog-declared tenant-local prerequisites; selectors resolve through profile or operator allowlists. The only build prefetch class is bounded to a declared command executed inside the same deny-network process tree as offline acceptance; credentials are scrubbed before either phase and the packet is hash-verified after every child process. URL syntax, hostname literals, unknown targets, direction drift, public-only providers, and undeclared external resolution fail schema or semantic validation.

## Typed compatibility and planned evidence

`moduleCompatibility` has exactly one record per module and mirrors its declared OS, Kubernetes API grant, storage mode, and resource class. It additionally types allowed isolation modes, network localities, and required runtime classes. Numeric CPU, memory, and ephemeral-storage minima remain `MISSING_PLANNED` where no measured envelope exists; the catalog does not invent capacity evidence.

Profile environment facts must cover every closure requirement. `platform-supplied` OS or runtime facts are explicit external obligations rather than wild guesses. A Kata module requires a Kata runtime-class fact, a controller requires its declared Kubernetes grant, and every storage/resource/network requirement must occur in the signed fact envelope. Planned fixtures can exercise consistency but cannot claim version, capacity, digest, or signature proof.

## Immutable assurance subjects

`assuranceSubjects.selectionMode` is always `EXPLICIT_IMMUTABLE_SUBJECT_SET`. Harness and capability IDs must be registered, unique, explicitly accepted, and the capability set must be a subset of accepted resolved demand. The subject set drives `subjectUnderEvaluation` predicates over both harness and capability IDs, while installed closure continues to be derived independently from selected providers and dependencies. Global environment facts do not become campaign subjects, and the compiler must never infer assurance subjects from every installed module.

Design fixtures use a null subject-set digest with `digestStatus: MISSING_PLANNED` and `signatureStatus: MISSING_PLANNED`. Release admission requires the canonical subject selection to be digest locked and signature verified; changing a subject produces a new immutable digest.

## Service dependency alignment

Every service in `architecture/services.yaml` maps to exactly one module through `serviceModuleBindings`. Required service edges must be present as module dependencies after translating service IDs to module IDs.

Two service dependencies require explicit satisfaction semantics:

- `external.signed-industry-packs` is satisfied by the signed `artifact.platform.industry-pack` module, not by an undeclared endpoint.
- `external.local-model-backend` is satisfied by exactly one concrete member of `group.model-backend`. Both the inference API and semantic-memory adapter declare `requiredProviderGroups: [group.model-backend]`; the profile must contain the concrete backend. The governed-memory fixture therefore selects llama.cpp and no longer treats a logical endpoint as a deployable prerequisite.

The assurance worker's data-ingestion edge is conditional, not globally hard. Its `conditionalDependencies` record selects the ingest worker only when `knowledge.data-integration` is a subject under evaluation. Its inference edge is selected for a `runtime.model-inference` subject or the explicitly accepted `assurance.local-model-judge` subject capability. A memory-only deterministic assurance profile therefore does not acquire an unrelated ingestion or inference stack; a local-judge profile cannot compile until its model class and backend selector have been accepted.

The provider graph also carries the hard control dependencies that are easy to omit when composing profiles: governance and registry for the control plane and protocol gateway, guardrails for inference and the AI gateway, governance for tool and decision paths, sandbox verification for the tool broker, and durable/source/policy prerequisites for ingestion and indexing.

## Canonical harness coverage

| Plane | Harnesses |
|---|---|
| Runtime | `runtime.infrastructure`, `runtime.model-inference`, `runtime.ai-gateway`, `runtime.experience` |
| Knowledge | `knowledge.domain-semantic`, `knowledge.data-integration`, `knowledge.retrieval-context`, `knowledge.memory-state` |
| Execution | `execution.protocol-interoperability`, `execution.orchestration`, `execution.tool-skill-sandbox`, `execution.ml-decision` |
| Trust | `trust.security-safety`, `trust.governance-agentops`, `trust.observability-finops`, `trust.evaluation-assurance` |

Catalog-only `platform.*` groupings connect contracts, SDKs, guidance, control, distribution, conformance, and external facts. They do not create extra tenant harnesses.

## Zero-bill and offline admission

Only these cost dispositions are valid:

- `SELF_HOSTED_OPEN_SOURCE_NON_METERED`
- `TENANT_SUPPLIED_OPEN_SOURCE_NON_METERED`

Admission rejects metered or pay-per-use services, provider-owned API keys or secrets, runtime package/model downloads, mutable artifact references, undeclared external egress, mandatory public-cloud control planes, hosted CI, and GitHub artifact/cache storage. The explicit forbidden-demand set also rejects hosted, metered, API-key-required, remote-provider, runtime-download, public-only, unsafe-deserialization, unbounded, mutable, and fail-open mutation demands before compilation. Air-gap closure uses imported OCI layouts, mounted artifacts, local trust and identity, and explicitly declared tenant data sources.

Tenant-supplied does not mean unverified. Every external fact still needs an owner, exact license disposition, custody, compatibility evidence, declared endpoints or mounts, resource bounds, health criteria, and an immutable fact or artifact digest before release admission.

## Required module metadata

| Concern | Required coding contract |
|---|---|
| Identity and ownership | Stable module and provider IDs, canonical/platform harness, scope, owner, kind, selection mode, install units, and closed implementation disposition with exact packet/path/deliverable ownership where implemented |
| Closure | Hard dependencies, conditional dependencies, required provider groups, capability condition |
| Configuration and secrets | Required/forbidden fields, reference-only or public-material secrets, no inline values |
| Network and RBAC | Default deny, closed local target registry, typed direction/locality/authority, no URL/public-host target, least privilege |
| Storage and retention | Mode, claims, owner, classification, default action, destructive authorization |
| Compatibility | Kubernetes distribution/API/grants, OS, architecture, storage, resource/capacity, network locality, runtime class, accelerator, isolation, and signed environment facts |
| Assurance subjects | Explicit harness/capability subject set with independent immutable digest and signature state |
| Operations | Startup/readiness/liveness, upgrade, rollback, uninstall, retention safety |
| Supply chain | SPDX/custody/source, immutable digest, SBOM, vulnerability disposition, signature, offline verification |

## Immutable release caveat

All 87 records require immutable digests, but a `PLANNED` install unit may carry `digest: null` with `digestStatus: MISSING_PLANNED`. It is not fetchable, installable, promotable, or releasable. A `CONTRACT_ONLY` record remains non-installable even if somebody supplies an artifact digest; packet ownership and a catalog revision are mandatory. Release requires every selected unit to be packet-owned or a verified external prerequisite, digest locked, license/custody approved, SBOM- and vulnerability-evidenced, signed, revocation-aware, and verified offline.

A fixture's `UNRESOLVED_UNTIL_RELEASE` disposition proves deterministic design closure only. It cannot prove build, installation, runtime health, assurance, or tenant acceptance.

## Implementation handoff

Coding agents consume this catalog only through a schema-valid task packet and the owning repository/harness contracts. One run implements one packet, touches only its `allowedPaths`, and never substitutes a hosted provider or infers that a `PLANNED` module exists. Evidence advances independently through source, CI, merge, artifact, deployment, runtime, assurance, and tenant-acceptance gates.
