# Master Development Plan

## Purpose

This is the program-level contract for building the Planeon Enterprise MAS
Harness Platform. Detailed implementation decisions live in the thirteen
repository plans, sixteen harness specifications, the planned provider/module
catalog, and versioned task packets.

The platform guides a tenant through deployment sovereignty, business outcomes,
risk, domain semantics, data readiness, integration, intelligence, execution,
assurance, and acceptance. The deterministic compiler resolves the tenant's
explicitly accepted demand into the smallest valid dependency closure and a
signed OCI profile referencing only selected immutable modules.

## Delivery milestones

### Alpha 1: business and data foundations

- Catalog all sixteen harnesses.
- Implement the questionnaire, readiness engine, compiler, white-goods pack,
  identity/policy/telemetry foundation, domain semantics, data integration,
  provenance, minimal operator, profile OCI composition, and the tenant
  organization harness-status overview.
- Certify questionnaire-to-installed-foundation behavior, accurate
  organization/plane/harness projections, accessible drill-down, and neutral
  treatment of unselected harnesses before adding an agent.

### Alpha 2: read-only intelligence

- Entry repair: publish `MET-A2-001`, then execute the separately authorized
  `MET-OBS-MODEL-001` usage-schema observation and `CON-MODEL-001` API/usage
  contract release before `MODEL-001`. Structural facts and independent
  conformance never imply an original-source test pass. See
  [prerequisite details](alpha-2/MODEL_PREREQUISITES.md) and the
  [phase-labelled checkpoint](DEVELOPMENT_STATUS.md).
- Before continuing model API coding, complete `MET-REPAIR-001`, `MET-REPAIR-002`, `CON-FIX-001`
  and `CTRL-FIX-003`. `CTRL-INTEGRATE-001` owns the production overview carryover
  and is a prerequisite of `CONF-A2-001`; fresh Alpha-1 installed evidence remains
  required independently. See [corrective scope](alpha-2/READINESS_REPAIRS.md).
  The second amendment admits two legacy registry-test corrections and only
  the implementation fix for documented blocked-selection precedence, without
  changing public semantics or weakening command-owner admission.
- Add retrieval/context, local inference, AI gateway, MCP/A2A mediation, and a
  read-only durable task.
- Certify a cited white-goods task with no write authority.

### Alpha 3: governed action and interaction

- Add memory, tool classification, sandbox providers, decision intelligence,
  approval UI, autonomy policy, AgentOps registry, compensation, and tenant
  isolation campaigns.

### Alpha 4: enterprise release

- Add trace-based assurance, upgrade/rollback/uninstall, physical air-gap
  transfer, upstream Kubernetes, K3s, OpenShift, AMD64, ARM64, adversarial, and
  full white-goods acceptance certification.

## Global architecture rules

- The control plane is never on the synchronous runtime request path.
- Browser status reads use local authenticated projections; the browser never
  fans out to product-plane services, and stale/source-unavailable data never
  becomes current health.
- Retrieval, persistent memory, and durable workflow state are separate stores
  and contracts.
- Data access never inherits tool execution authority.
- Governance defines permissible autonomy; runtime guardrails enforce decisions.
- AI gateway and inference engine have separate ownership and scaling.
- Asynchronous delivery is at least once with transactional outbox/inbox
  idempotency.
- Every provider declares configuration, secret references, RBAC, network intent,
  storage, migrations, evidence, resource envelope, compatibility, license,
  upgrade, rollback, and removal behavior.
- Every release consumes immutable upstream versions and SHA-256 digests.

## Deployment modes and billing boundary

The same contracts and independently packaged harness modules support four
deployment modes. `architecture/taxonomy.yaml#/deploymentModes` is the
machine-readable authority.

| Mode | Infrastructure and isolation | Required certification path |
|---|---|---|
| Operator-hosted SaaS | A shared asynchronous control plane on pre-authorized operator capacity; tenant identity is server-derived, data uses RLS, and each runtime uses the policy-selected namespace or dedicated-cluster boundary. | Control-plane tenant/security checks, cross-tenant adversarial certification, and lifecycle certification. |
| Tenant public cloud | A pre-existing tenant-managed Kubernetes or OpenShift API; the platform receives capability facts and least-privilege access but no cloud-account or provisioning credentials. | Live Kubernetes/OpenShift plus security certification. |
| Self-managed | Tenant-owned upstream Kubernetes, K3s on plain VMs, or OpenShift, connected or in a network silo. | The matching live platform campaign plus security certification. |
| Air-gapped | A physically disconnected tenant environment supplied through custody-controlled OCI transfer, local trust, models, dependencies, data, identity, and observability. | Physical two-zone air-gap, security, and lifecycle certification. |

In every mode, billable provisioning is `FORBIDDEN`. Existing operator or tenant
capacity may have separately approved ownership costs, but the platform cannot
create, purchase, resize, or enroll it; invoke cloud management or billing APIs;
or turn an optional integration into a paid dependency. SaaS describes the
operating and tenancy model, not a mandatory external SaaS dependency.

## Provider and module composition authority

[`architecture/providers.yaml`](../architecture/providers.yaml), constrained by
[`schemas/provider-module.schema.json`](../schemas/provider-module.schema.json),
is the deterministic provider/module selection authority. Its current status is
`PLANNED`. The catalog covers 87 module/provider records, twenty stable
`external.*` prerequisite IDs, and all sixteen canonical harnesses. Three
Kubernetes platform choices are also EXTERNAL-scope provider records, so they do
not increase the external-prerequisite count.

The catalog includes a closed capability-admission partition for public demand,
signed environment facts, and explicit provider selectors; every unclassified
registered token is internal-only. Four schema-constrained deterministic profile
examples state requested capabilities and accepted selectors, selected modules,
external prerequisites, exclusions, expected fixed-point closure, and
`UNRESOLVED_UNTIL_RELEASE` digest disposition. These examples test selection and
minimality only; they are not released bundles.

Every catalog record has exactly one implementation disposition: 59 name a
repository packet, an implementation path inside that packet's `allowedPaths`,
and an owning deliverable; 23 are pinned tenant-supplied external prerequisites
(twenty `external.*` records plus three Kubernetes distribution choices); and
five are `CONTRACT_ONLY` non-installables. The compiler rejects a contract-only
selection with `PROVIDER_UNAVAILABLE` before dependency closure or bundle
construction. Activating one requires a future packet and catalog revision,
not documentation or an unowned repository directory.

The compiler may select only explicitly accepted public capabilities, exactly one
accepted selector per active exclusive group, and their transitive closure.
Provider ranking can propose a selector but cannot mutate a profile, select a
fallback, or satisfy missing tenant input. Every record declares configuration,
forbidden fields, secret-reference mode, default-deny network intent, RBAC, storage/retention,
platform/architecture, resource/accelerator envelope, health, license/custody,
cost disposition, and upgrade/rollback/uninstall behavior. Admission accepts
only self-hosted or tenant-supplied open-source non-metered dispositions and
rejects paid/metered services, provider API keys, undeclared egress, mutable
references, hosted CI/storage dependencies, and runtime package/model downloads.

Immutable digest requirement is not immutable release evidence. Planned install
units may have `digestStatus: MISSING_PLANNED`; they cannot be fetched, installed,
promoted, or included in a released profile until version/digest, SPDX/custody,
SBOM, vulnerability disposition, signature/revocation, and offline verification
evidence exist. None of the 87 catalog records currently proves implementation,
CI, merge, artifact, deployment, runtime, assurance, or tenant acceptance. See
[`PROVIDER_MODULE_CATALOG.md`](PROVIDER_MODULE_CATALOG.md) for the complete
interpretation and handoff boundary.

## Open-source and support boundary

The platform core, contracts, reference providers, operator, distribution tools,
industry-pack framework, and conformance kit are Apache-2.0 open source. A future
enterprise-support offer is a human/service relationship, not a runtime feature:
the platform contains no license server, feature lock, phone-home check, billing
client, commercial API key, or support entitlement dependency. Pricing, SLAs,
indemnity, and certified-support matrices remain deliberately outside the coding
scope until the project adopts a separate business decision.

## Guided setup gates

1. Deployment sovereignty and isolation.
2. Business objectives, owner, workflow, and measurable KPI.
3. Risk, regulation, classification, and autonomy.
4. Domain vocabulary and canonical entities.
5. Data ownership, quality, completeness, freshness, provenance, and access.
6. Integrations, protocols, tools, credentials, and side effects.
7. Retrieval, memory, model, ML, and orchestration requirements.
8. SLO, recovery, observability, evaluation, and tenant acceptance.

No dependent stage may be approved while a mandatory preceding finding is
`OPEN`, `FAIL`, or `STALE`. Waivers require an approver, justification,
compensating control, and expiry.

## Evidence model

The program records these independently:

1. Source and porting provenance.
2. Contract and unit verification.
3. Pull-request checks.
4. Merge state.
5. Reproducible artifact and SBOM.
6. Signature and release state.
7. Deployment reconciliation.
8. Runtime health and behavior.
9. Security and assurance.
10. Tenant acceptance.

A later state never retroactively proves an earlier or different evidence axis.
Live environment campaigns are manual post-merge runs on a preinstalled
target-local ephemeral runner. Before checked-out code runs, the external
root-owned `/opt/planeon/bin/harness-live-campaign-launch` reads only
`HARNESS_LIVE_EXECUTION_ENVELOPE`; verifies independent `PLATFORM_RELEASE` and
`TENANT_LIVE_EXECUTION` signatures over the same RFC 8785 payload; recomputes
the immutable packet/command/kit/campaign/release/launcher/bundle/trust digests
and embedded pre-existing endpoints; and verifies the separate digest-bound
`CAPACITY_OPERATOR` authorization. It establishes the host OS deny-all-except-
envelope boundary and proves an active server-side zero-cost mutation policy.
Dynamic workloads are probed only through signed `KUBERNETES_API_PROXY` or
`CAMPAIGN_PROXY` endpoints; discovered addresses never broaden egress. GitHub PR checks remain deny-all and cannot consume a live result.
Missing pre-existing capacity is `NOT_RUN_ENV_UNAVAILABLE`, never a reason to
provision or an inferred pass. The complete contract is
[`TRUSTED_LIVE_CAMPAIGN_RUNNER_CONTRACT.md`](TRUSTED_LIVE_CAMPAIGN_RUNNER_CONTRACT.md).

Live result states are exactly `PASS`, `FAIL`, `WARN`, `NOT_APPLICABLE`, and
`NOT_RUN_ENV_UNAVAILABLE`; live/platform/architecture are dimensions. The
dual-signed envelope restricts each campaign to its exact validator-declared
subset of `DEPLOYMENT`, `RUNTIME`, `SECURITY`, `ASSURANCE`, and
`TENANT_ACCEPTANCE_CANDIDATE`. `TENANT_ACCEPTANCE` is forbidden. It cannot
originate source, unit, PR, merge, artifact/SBOM, signature/release, or actual
tenant-acceptance evidence. `CONF-WG-001` produces only an unsigned acceptance
candidate; a separate authorized tenant decision is required for acceptance.

Production promotion is also scope-exact. Each taxonomy production gate owns a
closed control list and uses `ALL_REQUIRED_CONTROLS`; no single passing control
or unrelated campaign can satisfy it. Admissible evidence comes only from an
immutable `PRODUCTION_PROMOTION` campaign and binds the SHA-256 evidence-plan,
control-set, campaign, trusted-producer-policy, producer-release, profile,
bundle, route, and subject digests plus tenant, route, and subject identity.
Signed waivers are short-lived records for one required control and the same
complete scope. They document an approved exception but never satisfy a
production control: promotion still requires fresh `PASS` evidence for every
required control. A waiver cannot broaden scope, convert any non-`PASS` status,
or replace `FAIL`/`STALE` evidence.

Make-based acceptance has packet-local ownership. Each product bootstrap owns
the repository `Makefile` and closed `ci/run_make_target.py` dispatcher. A later
packet owns only `ci/targets/<lowercase-packet-id>.json`, which registers its
exact target names, closed values for `BACKEND`, `CAMPAIGN`, `MODULE`, `PACK`,
or `PROVIDERS`, and direct argv templates. Matching handlers run cumulatively in
lexical packet order; missing, ambiguous, duplicate, shell-based, or undeclared
handlers fail. The only predecessor-owned exception is the `CONF-001` generic
campaign/evidence/acceptance dispatch. The readiness validator proves every Make
target has one of these authorities. Bootstrap packets alone seed inert
`PORTING.yaml` ledgers; ordinary reference-only packets cannot edit them.

## Sol-high handoff rule

Each coding run implements exactly one YAML packet from `task-packets/`. Broad
repository or harness documents are not themselves coding prompts. A packet is
ready only when every predecessor exists, all public contracts are pinned, its
allowed paths and exclusions are explicit, and its acceptance commands execute
offline.

`predecessors` orders implementation contracts, not certification claims.
Merged code and passing offline evidence—including an honest live-environment
`NOT_RUN_ENV_UNAVAILABLE`—may unblock later source work. Release and production
promotion remain separately blocked until every required live campaign has its
fresh, scope-exact `PASS` evidence.
