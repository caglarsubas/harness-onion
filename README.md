# Harness Engineering

This repository is the architecture and execution-readiness source of truth for
the Planeon Enterprise Multi-Agent-System Harness Platform.

It contains:

- a pinned provenance record for the six attached research/design inputs and their
  non-instructional authority boundary;
- the canonical sixteen-harness taxonomy;
- an explicit SaaS, tenant-public-cloud, self-managed, and air-gapped deployment matrix;
- the planned 87-record provider/module catalog, with 59 packet-owned
  implementation plans, 23 tenant-supplied external prerequisites, five
  contract-only non-installables, and four deterministic profile contracts;
- the thirteen-repository ownership and dependency model;
- path-scoped warm-start reuse and licensing records;
- one development plan per repository;
- one implementation specification per harness;
- an approved coding-ready tenant organization/plane/harness overview and
  platform-operator portfolio contract;
- PR-sized task packets for GPT-5.6 Sol high-effort coding runs; and
- offline validation for completeness, dependency ordering, and zero-bill rules.

This repository contains no tenant runtime service. Product implementations live
in their respective product repositories and consume immutable contract releases.

Start with [`docs/READINESS_INDEX.md`](docs/READINESS_INDEX.md), then hand exactly
one YAML file from `task-packets/` to a Sol high-effort coding run.
The frontend status experience is specified in
[`docs/TENANT_HARNESS_OVERVIEW.md`](docs/TENANT_HARNESS_OVERVIEW.md).

Each packet separates the local-cache preparation phase in `prefetchCommands`
from `offlineAcceptanceCommands`. Prefetch may only hydrate from the
preprovisioned, digest-locked wheelhouse/tool cache; it is not an online-fetch
fallback. Both phases must run as one deny-all-outbound process tree through the
declared `offlineExecution` OS-isolation wrapper. Both
fields contain direct argv arrays, not shell strings. The wrapper reads the
packet path from `HARNESS_TASK_PACKET` and enforces the frozen/offline `uv`
environment. The legacy `acceptanceCommands` field, recursive offline wrapper,
and prefetch/install/fetch commands in the offline list are invalid.

Live environment certification never relaxes that PR gate. The ten conformance
campaign packets declare a separate manual `liveCampaignExecution` contract for
a preinstalled target-local ephemeral runner. The only live entry point is
the external root-owned
`/opt/planeon/bin/harness-live-campaign-launch`; its only packet-declared input
is `HARNESS_LIVE_EXECUTION_ENVELOPE`. Independent `PLATFORM_RELEASE` and
`TENANT_LIVE_EXECUTION` signatures cover the same RFC 8785 envelope payload,
including exact pre-existing endpoints. Fixed release/tenant trust mounts supply
local purpose, validity, and revocation state. A separate digest-bound
`CAPACITY_OPERATOR` signature authorizes capacity. The launcher establishes host
OS deny-all-except-envelope isolation before checked-out code or credentials;
dynamic probes use only `KUBERNETES_API_PROXY` or `CAMPAIGN_PROXY`, and
server-side zero-cost admission constrains every cluster mutation. GitHub PR use is forbidden.
Missing capacity is `NOT_RUN_ENV_UNAVAILABLE`, not pass or an online fallback.
See
[`docs/TRUSTED_LIVE_CAMPAIGN_RUNNER_CONTRACT.md`](docs/TRUSTED_LIVE_CAMPAIGN_RUNNER_CONTRACT.md).

Publicly disclosed warm sources are currently reference material only: 20
tree-discovery records, 515 pending exact blobs, zero copy-authorized blobs, and an empty porting-
authorization index. Product packets use clean-room implementation and
independent parity. Any future direct reuse needs new path-level legal evidence,
an approved source-to-destination authorization, a revised packet, and a matching
destination `PORTING.yaml` record. Three non-public planning inputs are omitted
from this repository and are neither mounted nor required by implementation runs;
their useful behavior has been distilled into public contracts and acceptance
criteria without source metadata.

The packet reuse records are provenance and independent parity requirements,
not implementation-time filesystem grants. Product coding runs declare
`warmSourceAccess: PROHIBITED_DURING_IMPLEMENTATION`; they receive the packet's
contracts and fixtures, never a warm checkout path. A later source-observation
session requires its own authorization, identity, read-only snapshot, and
post-session integrity proof.

Before repository-wide or packet execution, the protected runner sets
`HARNESS_WARM_SOURCE_ROOTS` to the newline-delimited, already-canonical absolute
roots of every warm snapshot visible on that host. The trusted shell launcher
validates the list, refuses an undeclared locked snapshot detected in the
standard snapshot area, denies read/metadata/write access with macOS Sandbox or
Linux Firejail, and removes the list before repository code runs. The setting
may be `NONE` only when the protected runner proves that no warm snapshot is
mounted. Product code must never enumerate or construct this value.

Before packet execution, the public default branch must be seeded once with this
planning publication and the pinned self-hosted workflow. A no-cost self-hosted
runner and complete locked wheelhouse/tool cache must already exist. If either is
missing, execution is blocked; there is no GitHub-hosted runner or online-fetch
fallback.

The workflow runs no checked-out shell, Python, Make target, local action, or
other repository-controlled command before isolation. After the pinned
credential-free checkout it invokes only the preinstalled, root-owned absolute
host launcher `/opt/planeon/bin/harness-offline-launch`. That launcher establishes
the network, warm-root, credential, home-directory, and local-socket boundary
before it enters the checkout and invokes the repository verifier. Toolchain
validation and all tests therefore run inside isolation. See
[`docs/TRUSTED_RUNNER_CONTRACT.md`](docs/TRUSTED_RUNNER_CONTRACT.md).

## Validation

Validation is packet-owned. For example, `MET-001` declares
`prefetchCommands: []` and the ordered direct-argv
`offlineAcceptanceCommands` values
`["uv","run","--offline","--frozen","--no-sync","python","scripts/validate_architecture.py"]`
and
`["uv","run","--offline","--frozen","--no-sync","pytest","tests/test_architecture.py"]`.
The executor supplies the selected hash-pinned packet path through
`HARNESS_TASK_PACKET` and invokes only the packet's
`offlineExecution.wrapperArgv: ["./ci/verify-offline.sh"]`; the wrapper runs the
complete list in one OS-isolated process tree.

The documents under `docs/` are normative planning inputs. Machine-readable
files under `architecture/`, `legal/`, `policies/`, `schemas/`, and
`task-packets/` are validated by `scripts/validate_readiness.py`.

Product bootstrap packets alone own each repository `Makefile`. Later packets
register acceptance handlers through their exact
`ci/targets/<lowercase-packet-id>.json` path, so parallel-ready work has no
shared Makefile edit; the validator rejects unowned targets and unordered path
overlaps. Likewise, only product bootstraps seed inert `PORTING.yaml` ledgers.
Current reference-only packets cannot modify those ledgers or authorize a copy.

Provider selection is governed by
[`architecture/providers.yaml`](architecture/providers.yaml) and its closed
[`provider-module.schema.json`](schemas/provider-module.schema.json) shape. See
[`docs/PROVIDER_MODULE_CATALOG.md`](docs/PROVIDER_MODULE_CATALOG.md) for the
counts, closure rules, zero-bill admission, lifecycle/resource/security fields,
and immutable-release caveat. The catalog is entirely `PLANNED`; it is not
implementation or release evidence.

See `docs/SCOPE_PROVENANCE.md` for the authority order used to distinguish the
user's requirements from statements embedded in the attached source material.

## Non-negotiable constraints

- No cloud resource provisioning.
- No GitHub-hosted runners, GitHub Packages, GHCR, Actions artifacts, or Actions caches.
- No paid model/provider endpoint or required third-party API key.
- No runtime dependency, image, or model download.
- Every optional harness/provider is independently packaged by immutable digest.
- Existing warm-start repositories are immutable sources and are never modified.
