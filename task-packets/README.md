# Sol-High Task Packet Catalog

Current Alpha-2 dispatch: [MET-REPAIR-015 Linux qualification](../docs/alpha-2/NATIVE_QUALIFICATION_READINESS.md).
Catalog 144; corrected conformance main9df7dd7 preserves 127 files / 327 tests.
MET-REPAIR-014 source gates are closed. Close this qualification authority before CONF-LIVE-003.
Older publication sections below retain their historical states, not current instructions.
Accepted MET-PERF-001 main e367e89463b86ebc1b1e20563d677bdfe6694060 is preserved; this reconciliation runs both complete replays and all twenty commands.

This is the complete PR-sized execution queue for the Planeon Enterprise MAS Harness Platform. The rule is **one YAML file per packet, one GPT-Sol high-effort run per packet, and one pull request per packet**.

## Execution rules

1. Start only after every `predecessors` ID is merged and its offline
   implementation evidence exists. This field orders source/contract work; it
   does not assert live certification. A predecessor's
   `NOT_RUN_ENV_UNAVAILABLE` may unblock later coding after its honest offline
   evidence passes, but never satisfies a platform, assurance, release, or
   production-promotion gate. Those gates require their separately named fresh
   live `PASS` evidence.
2. Follow the displayed order. Parallel-ready packets may run concurrently only when their repositories and `allowedPaths` do not conflict; break ties lexically by packet ID.
3. Touch only `allowedPaths`; an unavoidable change outside the boundary requires a revised packet.
4. Warm-start repositories are immutable. Packet reuse entries record historical
   source-observation provenance and parity expectations; they do not expose a
   warm checkout to an implementation run. `DISCOVERY_ONLY` trees and
   `REFERENCE_ONLY` blobs remain non-copyable. All 4,202 publicly indexed blobs are
   `BLOB_PENDING`; there are zero
   current `PORT_CANDIDATE`, `BLOB_COPY_AUTHORIZED`, or porting-authorization
   records. Future direct reuse requires legal input, a revised packet carrying
   an `authorizationId` and exact source-to-destination mapping, a promoted path
   record, and a matching destination `PORTING.yaml` record. All five approved
   warm repositories are exact-commit pinned; three have only signed
   metadata-only tree observations. Warm-source paths cannot be mounted,
   discovered, or used by an implementation run.
5. Run only the declared `prefetchCommands` as the first phase inside the same
   deny-all-outbound OS-isolated process tree as acceptance. This phase may
   prepare dependencies only from the preprovisioned, digest-locked local
   wheelhouse/tool cache and is never an online-fetch fallback. Commands are
   direct argv arrays, never shell strings.
   Set `HARNESS_TASK_PACKET` to the hash-pinned packet path, then invoke the exact
   `offlineExecution.wrapperArgv`. The wrapper transports `ARGV_ARRAY_V1` and
   executes the complete ordered `offlineAcceptanceCommands` array in one
   OS-enforced, deny-all-outbound process tree with `UV_OFFLINE=1`,
   `UV_FROZEN=1`, and `UV_NO_SYNC=1`.
   The twelve conformance packets that can later exercise a live target also carry
   `liveCampaignExecution`. That is a separate manual, post-merge environment-
   evidence path. Its only entry point is the external root-owned
   `/opt/planeon/bin/harness-live-campaign-launch` on a preinstalled target-local
   ephemeral runner. Its only packet-declared input is
   `HARNESS_LIVE_EXECUTION_ENVELOPE`. `PLATFORM_RELEASE` and
   `TENANT_LIVE_EXECUTION` independently sign the same RFC 8785 envelope payload,
   which binds exact packet, commands, kit, campaign/release, launcher, bundle,
   axes, trust digests, and pre-existing endpoints. A separate digest-bound
   `CAPACITY_OPERATOR` signature authorizes capacity. The launcher establishes
   the host OS boundary before checked-out code, and proves active server-side
   zero-cost mutation admission. Dynamic probes use only signed
   `KUBERNETES_API_PROXY` or `CAMPAIGN_PROXY` endpoints. It is forbidden in
   GitHub PR checks and cannot perform endpoint discovery, cloud-management or
   billing calls, provider-key authentication, or cost-creating cluster
   mutations. A missing authority or target yields only
   `NOT_RUN_ENV_UNAVAILABLE`; offline PR acceptance must prove that unavailable
   infrastructure was not reported as passing. See
   [`../docs/TRUSTED_LIVE_CAMPAIGN_RUNNER_CONTRACT.md`](../docs/TRUSTED_LIVE_CAMPAIGN_RUNNER_CONTRACT.md).
6. Produce all `expectedEvidence`. A destination `PORTING.yaml` is required only
   for a future schema-valid, legally approved two-repository port transaction.
7. Use the declared `codex/*` branch, open a PR, monitor self-hosted required checks, fix bounded failures, and merge only when green.
8. Respect `rollback`; never perform an unplanned destructive data rollback.
9. Source, CI, merge, artifact, signature, deployment, runtime, assurance, and tenant acceptance remain separate evidence axes.
10. An unavailable required live environment reports `NOT_RUN_ENV_UNAVAILABLE`, never pass.

Schema: [`../schemas/task-packet.schema.json`](../schemas/task-packet.schema.json).
Offline validation argv: `["uv","run","--offline","--frozen","--no-sync","python","scripts/validate_readiness.py"]`.

The fixed wrapper argv is `["./ci/verify-offline.sh"]`. Bootstrap packets must
provide that interface and the generic direct-argv runner/canary in `ci/`. The
runner opens `HARNESS_TASK_PACKET` once, pins its SHA-256, extracts inline JSON
argv arrays without constructing a YAML object or invoking a shell, removes the
packet path and credential/cloud variables from every child environment, runs
the outbound-network canary first, and rechecks the packet hash after every
child command. The wrapper additionally denies writes to the packet authority.
`prefetchOutsideSession: false` requires prefetch and acceptance to share that
single isolated process tree; neither phase may perform runtime downloads or
undeclared network access.

Every product repository bootstrap packet is the sole current owner of its
`Makefile` and `ci/run_make_target.py`. The bootstrap Makefile contains fixed
bootstrap rules plus a generic target entry that delegates to that direct-argv
dispatcher. A later packet that invokes a non-bootstrap Make target must own
exactly `ci/targets/<lowercase-packet-id>.json`; it never edits `Makefile`. The
closed descriptor contains exactly `schemaVersion`, `packetId`, and `targets`.
Each target contains `name`, `acceptedVariables`, and one or more
`argvTemplate` arrays whose elements are either literal strings or a closed
`{"variable": "NAME"}` reference. The only current variable names are
`BACKEND`, `CAMPAIGN`, `MODULE`, `PACK`, and `PROVIDERS`; each descriptor fixes
an explicit value or closed enum. Shell strings and shell executables are
invalid. The dispatcher validates every descriptor, selects only exact
target/variable matches, and direct-executes applicable handlers in lexical
`packetId` order. Zero matches, duplicate packet/target records, ambiguous
variable rules, or an invalid descriptor fail closed. Repeated targets such as
`security` and `pack` therefore accumulate packet-owned checks without a shared
file edit.

The conformance bootstrap is the only explicit exception: `CONF-001` owns the
generic `campaign`, `evidence-verify`, and `acceptance-package` rules, keyed by
the closed `CAMPAIGN` value, so the twelve campaign packets neither edit
`Makefile` nor add descriptors for those rules. `CONF-002` owns a normal
packet-local descriptor for its parity targets. The readiness validator maps
every declared Make target to the bootstrap, its exact descriptor, or this
closed conformance exception and rejects every unowned command.

`PORTING.yaml` is seeded only by the twelve product-repository bootstrap
packets as an inert, no-authorization destination ledger. No current
reference/discovery-only implementation packet may edit it. A future packet may
gain that exact path only together with a schema-valid `PORT_CANDIDATE`, approved
path-level authorization, and matching source-to-destination mapping.

`liveCampaignExecution` never weakens this offline wrapper. Its dual-signed
envelope names the exact validator-declared ordered subset of `DEPLOYMENT`,
`RUNTIME`, `SECURITY`, `ASSURANCE`, and `TENANT_ACCEPTANCE_CANDIDATE`;
`TENANT_ACCEPTANCE` is forbidden. It cannot satisfy source, unit, PR-check,
merge, artifact/SBOM, signature/release, or actual tenant-acceptance evidence.
Live results use only `PASS`, `FAIL`, `WARN`, `NOT_APPLICABLE`, and
`NOT_RUN_ENV_UNAVAILABLE`; `LIVE`, `LIVE_PASS`, `LIVE_FAIL`, and `NOT_RUN` are
invalid aliases. `CONF-WG-001` may create only an unsigned
`TENANT_ACCEPTANCE_CANDIDATE`; an independent tenant signer owns acceptance.
`CONF-001` must build the reproducible trusted-launcher artifact, establish and
meta-test the generic `campaign`, `evidence-verify`, and `acceptance-package`
Make dispatch, and run `make acceptance-package-contract`. Its built artifact
has no live authority until independent review installs the pinned bytes as the
root-owned external launcher.
The legacy `acceptanceCommands` field, string commands, recursive
`["make","verify-offline"]`, shell executables, and prefetch/fetch/install/pull/
download tokens in `offlineAcceptanceCommands` are schema-invalid and must never
be hidden behind another make target or script.

## Alpha 1 — Business, governance, and data foundations

| Order | Packet | Repository | Acceptance slice |
|---:|---|---|---|
| 1 | `MET-001` | `Harness-Engineering` | Architecture and taxonomy baseline |
| 2 | `MET-002` | `Harness-Engineering` | Reference-only source catalog and future authorization protocol |
| 3 | `MET-003` | `Harness-Engineering` | Executable zero-bill policy |
| 4 | `MET-004` | `Harness-Engineering` | Packet schema, catalog, and DAG validation |
| 5 | `MET-005` | `Harness-Engineering` | Release lock and evidence axes |
| 6 | `CON-001` | `mas-harness-contracts` | Contracts package bootstrap |
| 7 | `CON-002` | `mas-harness-contracts` | Harness/provider/module catalog |
| 8 | `CON-003` | `mas-harness-contracts` | Guidance and readiness contracts |
| 9 | `CON-004` | `mas-harness-contracts` | Deterministic profile compiler |
| 10 | `CON-005` | `mas-harness-contracts` | Lifecycles, events, APIs, and vectors |
| 11 | `CON-006` | `mas-harness-contracts` | Legacy data contract compatibility |
| 12 | `CON-007` | `mas-harness-contracts` | Runtime admission, trust, receipts, replay, and budgets |
| 13 | `SDK-001` | `mas-harness-sdks` | Generated clients |
| 14 | `SDK-002` | `mas-harness-sdks` | Tenant-neutral telemetry |
| 15 | `SDK-003` | `mas-harness-sdks` | Admission, trust, receipts, and budgets |
| 16 | `SDK-004` | `mas-harness-sdks` | Protocol and event helpers |
| 17 | `SDK-005` | `mas-harness-sdks` | Optional framework integrations |
| 18 | `SDK-006` | `mas-harness-sdks` | Guardrail clients |
| 19 | `SDK-007` | `mas-harness-sdks` | Legacy Python compatibility |
| 20 | `IND-001` | `mas-harness-industry-packs` | Industry-pack framework |
| 21 | `IND-WG-001` | `mas-harness-industry-packs` | White-goods business and domain |
| 22 | `IND-WG-002` | `mas-harness-industry-packs` | White-goods data readiness |
| 23 | `IND-WG-003` | `mas-harness-industry-packs` | White-goods governance and integrations |
| 24 | `IND-WG-004` | `mas-harness-industry-packs` | White-goods provider profiles |
| 25 | `IND-WG-005` | `mas-harness-industry-packs` | White-goods certification fixtures |
| 26 | `TRUST-001` | `mas-harness-trust-plane` | Identity and policy foundation |
| 27 | `TRUST-002` | `mas-harness-trust-plane` | Local guardrails |
| 28 | `TRUST-OBS-001` | `mas-harness-trust-plane` | Usage and local observability |
| 29 | `KN-001` | `mas-harness-knowledge-plane` | Knowledge service foundation |
| 30 | `KN-DOM-001` | `mas-harness-knowledge-plane` | Domain semantics |
| 31 | `KN-DATA-001` | `mas-harness-knowledge-plane` | Connectors and ingestion |
| 32 | `KN-DATA-002` | `mas-harness-knowledge-plane` | Provenance and readiness evidence |
| 33 | `CTRL-001` | `mas-harness-control-plane` | Control service foundation |
| 34 | `CTRL-FIX-001` | `mas-harness-control-plane` | Bootstrap lineage and additive-dependency gate correction |
| 35 | `CTRL-002` | `mas-harness-control-plane` | Questionnaire journey |
| 36 | `CTRL-003` | `mas-harness-control-plane` | Demand and approvals |
| 37 | `CTRL-004` | `mas-harness-control-plane` | Compiler worker and outbox |
| 38 | `CTRL-005` | `mas-harness-control-plane` | Profile lock and bundle request |
| 39 | `CTRL-006` | `mas-harness-control-plane` | Security and browser acceptance |
| 40 | `DIST-001` | `mas-harness-distribution` | Offline tool bootstrap |
| 41 | `DIST-FIX-001` | `mas-harness-distribution` | Cumulative Make target reachability correction |
| 42 | `DIST-OCI-001` | `mas-harness-distribution` | Exact OCI closure |
| 43 | `DIST-002` | `mas-harness-distribution` | Supply-chain evidence |
| 44 | `DIST-003` | `mas-harness-distribution` | Offline signing and promotion |
| 45 | `DIST-AIR-001` | `mas-harness-distribution` | Air-gap export/import |
| 46 | `DIST-004` | `mas-harness-distribution` | Modular Helm profiles |
| 47 | `OP-001` | `mas-harness-operator` | Operator and CRD bootstrap |
| 48 | `OP-002` | `mas-harness-operator` | Preflight and verification |
| 49 | `OP-003` | `mas-harness-operator` | Foundation reconciliation |
| 50 | `CTRL-007` | `mas-harness-control-plane` | Tenant harness overview and operator portfolio |
| 51 | `CONF-001` | `mas-harness-conformance-labs` | Conformance kit |
| 52 | `CONF-002` | `mas-harness-conformance-labs` | Warm-source parity registry |
| 53 | `CONF-A1-001` | `mas-harness-conformance-labs` | Foundation certification |
| 54 | `TRUST-FIX-001` | `mas-harness-trust-plane` | Post-certification package-marker authority correction |
| 55 | `MET-P0-001` | `Harness-Engineering` | Phase-0 gap-closure packet and observer authorities |
| 56 | `MET-P0-FIX-001` | `Harness-Engineering` | Canonical full-tree metadata ordering correction |
| 57 | `MET-OBS-AH-001` | `Harness-Engineering` | agent-hook-v2 exact-commit tracked-tree observation |
| 58 | `MET-OBS-OCP-001` | `Harness-Engineering` | OpenShift reference-lab exact-commit tracked-tree observation |
| 59 | `MET-OBS-SDK-001` | `Harness-Engineering` | Orchestra SDK exact-commit tracked-tree observation |
| 60 | `TRUST-FIX-002` | `mas-harness-trust-plane` | Trust provenance and public-fork runner correction |
| 61 | `IND-FIX-001` | `mas-harness-industry-packs` | Public-fork runner correction |
| 62 | `MET-P0-FIX-002` | `Harness-Engineering` | Phase-0 packet authority and provenance correction |
| 63 | `MET-P0-FIX-003` | `Harness-Engineering` | Offline browser-document ownership correction |
| 64 | `CTRL-FIX-002` | `mas-harness-control-plane` | Tenant overview semantics, theme, and security regression correction |
| 65 | `MET-P0-FIX-004` | `Harness-Engineering` | Five-source reuse-validator ownership correction |
| 66 | `MET-P0-002` | `Harness-Engineering` | Five-source, license, provenance, and Phase-0 audit closure |

## Alpha 2 — Read-only intelligence

The readiness repair retains the historical 107-packet Phase-0 and 110-packet
Alpha-2 publication snapshots. The current catalog has 142 packets; the first repair publication retains its 114-packet snapshot. Alpha-1
status corrections and production integration appear here because their new
authority follows the merged model observation; no historical packet is
rewritten as completed live acceptance. CON-MODEL-001 requires both product
corrections. Production integration is independently required by CONF-A2-001.

| Order | Packet | Repository | Acceptance slice |
|---:|---|---|---|
| 67 | `MET-A2-001` | `Harness-Engineering` | Model prerequisite authority and evidence-boundary repair |
| 68 | `MET-OBS-MODEL-001` | `Harness-Engineering` | Model usage-schema structural observation |
| 69 | `MET-REPAIR-001` | `Harness-Engineering` | R01–R06 authority, regression gates and integration ownership |
| 70 | `MET-REPAIR-002` | `Harness-Engineering` | Bounded cumulative-test and status-precedence authority amendment |
| 71 | `CON-FIX-001` | `mas-harness-contracts` | Generated inventory, cumulative registry tests, additive lineage and documented status precedence |
| 72 | `MET-LINUX-001` | `Harness-Engineering` | Early Linux readiness authority and verified correction checkpoint |
| 73 | `CTRL-FIX-003` | `mas-harness-control-plane` | Read-time freshness, portfolio and aggregation consistency |
| 74 | `MET-LINUX-002` | `Harness-Engineering` | Portable trusted Linux runner candidate and operator kit |
| 75 | `MET-REPAIR-003` | `Harness-Engineering` | R1-R4 conformance scope, discovery and boundary repair authority |
| 76 | `CONF-FIX-001` | `mas-harness-conformance-labs` | Offline backend/transport/canary and unauthenticated live-adapter correction |
| 77 | `MET-REPAIR-004` | `Harness-Engineering` | One-assertion legacy Linux test ownership and completed runner evidence |
| 78 | `CONF-LINUX-001` | `mas-harness-conformance-labs` | Early native Linux build, isolation and minimal runtime evidence |
| 79 | `MET-REPAIR-005` | `Harness-Engineering` | Exact model generator-fixture input-copy authority |
| 80 | `MET-REPAIR-006` | `Harness-Engineering` | Additive API-inventory predicate authority; preserve every existing safety check |
| 81 | `CON-MODEL-001` | `mas-harness-contracts` | Model API, usage contracts and independent vectors |
| 82 | `MET-LIVE-001` | `Harness-Engineering` | Source-only trusted live backend roadmap |
| 83 | `MET-REPAIR-007` | `Harness-Engineering` | Exact quoted-scalar correction authority and immutable packet gate |
| 84 | `CONF-FIX-002` | `mas-harness-conformance-labs` | Quote-safe packet parser, exact hash assertion and independent regressions |
| 85 | `MET-REPAIR-008` | `Harness-Engineering` | Cumulative source-inventory authority and six-stage compatibility checks |
| 86 | `CONF-FIX-003` | `mas-harness-conformance-labs` | Exact scalar-suite inventory correction and twenty cumulative regression methods |
| 87 | `CONF-LIVE-001` | `mas-harness-conformance-labs` | Session contracts and cumulative inventory |
| 88 | `CONF-LIVE-002` | `mas-harness-conformance-labs` | Protected Linux supervisor and isolation candidate |
| 89 | `MET-REPAIR-009` | `Harness-Engineering` | Strict proxy authentication and zero-cost admission contract prerequisite |
| 90 | `MET-REPAIR-010` | `Harness-Engineering` | Protected read-only policy-observation contract prerequisite |
| 91 | `MET-REPAIR-011` | `Harness-Engineering` | Retained-custody handoff correction authority |
| 92 | `MET-PERF-001` | `Harness-Engineering` | Preserve full replays while reducing measured safe YAML parsing cost |
| 93 | `CONF-FIX-004` | `mas-harness-conformance-labs` | Retained authority handles and supervisor handoff |
| 94 | `MET-REPAIR-012` | `Harness-Engineering` | Bounded credential lifecycle authority |
| 95 | `CONF-FIX-005` | `mas-harness-conformance-labs` | Post-isolation credential custody and cumulative accounting |
| 96 | `MET-REPAIR-013` | `Harness-Engineering` | Client authentication / server execution ordering authority |
| 97 | `MET-REPAIR-014` | `Harness-Engineering` | Fixed broker-controlled execution and cleanup handoff |
| 98 | `MET-REPAIR-015` | `Harness-Engineering` | Fixed Linux qualification binding and kernel inspection contract |
| 98 | `CONF-LIVE-003` | `mas-harness-conformance-labs` | Fixed proxy transport and zero-cost admission |
| 99 | `CONF-LIVE-004` | `mas-harness-conformance-labs` | Native Linux build and ten fixed probes |
| 100 | `CONF-LIVE-005` | `mas-harness-conformance-labs` | Reproducible packaging and operator handoff |
| 101 | `CONF-LIVE-006` | `mas-harness-conformance-labs` | Trusted campaign integration and manual qualification declaration |
| 102 | `CTRL-INTEGRATE-001` | `mas-harness-control-plane` | Alpha-1 production overview integration carryover |
| 103 | `MODEL-001` | `mas-harness-model-plane` | Local inference core |
| 104 | `MODEL-002` | `mas-harness-model-plane` | Custody and signed routes |
| 105 | `MODEL-OLLAMA-001` | `mas-harness-model-plane` | Ollama provider |
| 106 | `MODEL-LLAMACPP-001` | `mas-harness-model-plane` | llama.cpp provider |
| 107 | `MODEL-VLLM-001` | `mas-harness-model-plane` | vLLM provider |
| 108 | `MODEL-003` | `mas-harness-model-plane` | Model security and telemetry |
| 109 | `KN-RET-001` | `mas-harness-knowledge-plane` | Retrieval and cited context |
| 110 | `EXEC-001` | `mas-harness-execution-plane` | Execution foundation |
| 111 | `EXEC-PROT-001` | `mas-harness-execution-plane` | Protocol gateway |
| 112 | `EXEC-ORCH-001` | `mas-harness-execution-plane` | Durable orchestration |
| 113 | `RUN-001` | `mas-harness-runtime-plane` | Runtime edge foundation |
| 114 | `RUN-GW-001` | `mas-harness-runtime-plane` | Signed routing and budgets |
| 115 | `RUN-GW-002` | `mas-harness-runtime-plane` | Streaming and cancellation |
| 116 | `CONF-A2-001` | `mas-harness-conformance-labs` | Read-only agent certification |

## Alpha 3 — Governed action and interaction

| Order | Packet | Repository | Acceptance slice |
|---:|---|---|---|
| 117 | `TRUST-GOV-001` | `mas-harness-trust-plane` | Approvals, autonomy, and waivers |
| 118 | `TRUST-REG-001` | `mas-harness-trust-plane` | AgentOps registry and promotion |
| 119 | `EXEC-TOOL-001` | `mas-harness-execution-plane` | Governed tools and compensation |
| 120 | `EXEC-SBX-001` | `mas-harness-execution-plane` | Job and Wasmtime sandboxes |
| 121 | `EXEC-SBX-002` | `mas-harness-execution-plane` | gVisor and Kata sandboxes |
| 122 | `EXEC-ML-001` | `mas-harness-execution-plane` | Local decision service |
| 123 | `KN-MEM-001` | `mas-harness-knowledge-plane` | Governed memory |
| 124 | `RUN-EXP-001` | `mas-harness-runtime-plane` | Interaction and resumable UI |
| 125 | `OP-004` | `mas-harness-operator` | Per-module reconciliation |
| 126 | `CONF-A3-001` | `mas-harness-conformance-labs` | Governed-action certification |

## Alpha 4 — Enterprise release

| Order | Packet | Repository | Acceptance slice |
|---:|---|---|---|
| 127 | `MODEL-004` | `mas-harness-model-plane` | Performance evidence |
| 128 | `TRUST-EVAL-001` | `mas-harness-trust-plane` | Assurance and evaluation |
| 129 | `TRUST-003` | `mas-harness-trust-plane` | Trust resilience |
| 130 | `KN-002` | `mas-harness-knowledge-plane` | Knowledge resilience |
| 131 | `EXEC-002` | `mas-harness-execution-plane` | Execution resilience |
| 132 | `RUN-002` | `mas-harness-runtime-plane` | Runtime resilience |
| 133 | `DIST-005` | `mas-harness-distribution` | Distribution reproducibility/security |
| 134 | `OP-005` | `mas-harness-operator` | Upgrade and rollback |
| 135 | `OP-006` | `mas-harness-operator` | Uninstall and fleet sync |
| 136 | `OP-007` | `mas-harness-operator` | Platform security |
| 137 | `CONF-K8S-001` | `mas-harness-conformance-labs` | Kubernetes live certification |
| 138 | `CONF-OCP-001` | `mas-harness-conformance-labs` | OpenShift live certification |
| 139 | `CONF-K3S-001` | `mas-harness-conformance-labs` | K3s certification |
| 140 | `CONF-AIR-001` | `mas-harness-conformance-labs` | Physical air-gap certification |
| 141 | `CONF-SEC-001` | `mas-harness-conformance-labs` | Adversarial security certification |
| 142 | `CONF-UPG-001` | `mas-harness-conformance-labs` | Lifecycle certification |
| 143 | `CONF-WG-001` | `mas-harness-conformance-labs` | White-goods enterprise acceptance |

This table is a valid topological order. Parallel execution is permitted only when all predecessors are complete and the packet boundaries do not conflict.

## Early Linux runtime coding gate

MET-LINUX-001 adds a stricter gate described in
[Linux readiness](../docs/alpha-2/LINUX_READINESS.md). CTRL-INTEGRATE-001,
MODEL-001, EXEC-001 and RUN-001 require fresh, independently verified native
Linux AMD64 PASS before runtime coding. Merged conformance source with
NOT_RUN_ENV_UNAVAILABLE does not open this gate. CTRL-FIX-003 and
CON-MODEL-001 remain source-only exceptions under their existing predecessors.
Linux ARM64 needs independent qualification before a target support/release
claim. Full Alpha-4 certification remains separate. The earlier amendment's
115-packet count is retained as historical evidence, not the current total.

## Approved conformance readiness repair

MET-REPAIR-003 publishes the [R1-R4 amendment](../docs/alpha-2/LINUX_READINESS_REPAIRS.md)
without implementing product code. CONF-FIX-001 is the next source correction;
CONF-LINUX-001 waits for its merged source and exact-main offline evidence.
The MET-REPAIR-003 publication contained 120 packets; the current catalog contains 142. The original 118-packet Linux policy and prior
107/110/114/115 snapshots remain unchanged historical records.

Both conformance packets enumerate each test-suite root explicitly. The campaign
also owns only the two missing handler-contract paths under function/member-level
limits. No blanket test/schema/ci directory authority is granted. Native AMD64
PASS is still mandatory before runtime coding, and ARM64 qualification remains
separate. There is no phase completion or automatic model-effort change.

## Assertion-only Linux test ownership

MET-REPAIR-004 follows merged CONF-FIX-001 and precedes CONF-LINUX-001. It grants
only the existing canonical-schema test's handler assertion replacement with
the exact six-handler tuple. The consumed R1-R4 record and runner correction
remain unchanged. See [the bounded test repair](../docs/alpha-2/LINUX_TEST_OWNERSHIP_REPAIR.md).
Native Linux, independent live authority and full Alpha-4 acceptance remain separate.

## Model fixture-copy amendment

MET-REPAIR-005 grants CON-MODEL-001 only the exact helper copy additions in
[the bounded fixture repair](../docs/alpha-2/MODEL_FIXTURE_SCOPE_REPAIR.md).
The current catalog has 142 packets; the earlier 121-packet publication and all
source/native gates remain unchanged. That fixture-copy grant changes no assertions;
the sole later inventory-predicate exception is MET-REPAIR-006 below.

## Model API inventory amendment

MET-REPAIR-006 follows the completed fixture authority and precedes resumption of
draft CON-MODEL-001 PR 9. It permits only required-five subset membership in the
pinned lifecycle test. Preserve its test ID and every other byte, including every
API's OpenAPI-version, no-server, nonempty-path and local-reference checks.
See [the exact inventory repair](../docs/alpha-2/MODEL_API_INVENTORY_REPAIR.md).
That 123-packet publication retains the 122-packet consumed publication unchanged.
The draft has 1048 passed, one failed, zero skipped; cancelled CI is not PASS.
Normal model-contract completeness review and full source/CI/main gates remain.

## Approved trusted live backend enablement — MET-LIVE-001

The [coding guide](../docs/alpha-2/LIVE_BACKEND_READINESS.md) and closed
`architecture/live-backend-roadmap.json` add six sequential conformance packets
(CONF-LIVE-001 through CONF-LIVE-006), not new repositories or harnesses.
This publication recorded 130 packets; the current catalog contains 142. The 123 consumed packet YAML and all existing
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

The [exact correction guide](../docs/alpha-2/PACKET_SCALAR_REPAIR.md) adds MET-REPAIR-007 and
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

The [cumulative inventory guide](../docs/alpha-2/SUCCESSOR_INVENTORY_REPAIR.md) adds
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

The [strict proxy profile](../docs/alpha-2/PROXY_CONTRACT_READINESS.md) closes credential and resource-rule
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

The [bounded handoff correction](../docs/alpha-2/CUSTODY_HANDOFF_REPAIR.md) adds MET-REPAIR-011 and CONF-FIX-004:
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

The [credential-lifecycle correction](../docs/alpha-2/CREDENTIAL_LIFECYCLE_REPAIR.md) publishes
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
Current catalog142; conformance checkpoint9df7dd7 has 127 files / 327 tests.
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
