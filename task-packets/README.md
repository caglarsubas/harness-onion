# Sol-High Task Packet Catalog

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
   `REFERENCE_ONLY` blobs remain non-copyable. All 515 publicly indexed blobs are
   `BLOB_PENDING`; there are zero
   current `PORT_CANDIDATE`, `BLOB_COPY_AUTHORIZED`, or porting-authorization
   records. Future direct reuse requires legal input, a revised packet carrying
   an `authorizationId` and exact source-to-destination mapping, a promoted path
   record, and a matching destination `PORTING.yaml` record. Non-public planning
   inputs are deliberately absent from packets and cannot be mounted, discovered,
   or used by an implementation run.
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
   The ten conformance packets that can later exercise a live target also carry
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
the closed `CAMPAIGN` value, so the ten campaign packets neither edit
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
| 12 | `SDK-001` | `mas-harness-sdks` | Generated clients |
| 13 | `SDK-002` | `mas-harness-sdks` | Tenant-neutral telemetry |
| 14 | `SDK-003` | `mas-harness-sdks` | Admission, trust, receipts, and budgets |
| 15 | `SDK-004` | `mas-harness-sdks` | Protocol and event helpers |
| 16 | `SDK-005` | `mas-harness-sdks` | Optional framework integrations |
| 17 | `SDK-006` | `mas-harness-sdks` | Guardrail clients |
| 18 | `SDK-007` | `mas-harness-sdks` | Legacy Python compatibility |
| 19 | `IND-001` | `mas-harness-industry-packs` | Industry-pack framework |
| 20 | `IND-WG-001` | `mas-harness-industry-packs` | White-goods business and domain |
| 21 | `IND-WG-002` | `mas-harness-industry-packs` | White-goods data readiness |
| 22 | `IND-WG-003` | `mas-harness-industry-packs` | White-goods governance and integrations |
| 23 | `IND-WG-004` | `mas-harness-industry-packs` | White-goods provider profiles |
| 24 | `IND-WG-005` | `mas-harness-industry-packs` | White-goods certification fixtures |
| 25 | `TRUST-001` | `mas-harness-trust-plane` | Identity and policy foundation |
| 26 | `TRUST-002` | `mas-harness-trust-plane` | Local guardrails |
| 27 | `TRUST-OBS-001` | `mas-harness-trust-plane` | Usage and local observability |
| 28 | `KN-001` | `mas-harness-knowledge-plane` | Knowledge service foundation |
| 29 | `KN-DOM-001` | `mas-harness-knowledge-plane` | Domain semantics |
| 30 | `KN-DATA-001` | `mas-harness-knowledge-plane` | Connectors and ingestion |
| 31 | `KN-DATA-002` | `mas-harness-knowledge-plane` | Provenance and readiness evidence |
| 32 | `CTRL-001` | `mas-harness-control-plane` | Control service foundation |
| 33 | `CTRL-002` | `mas-harness-control-plane` | Questionnaire journey |
| 34 | `CTRL-003` | `mas-harness-control-plane` | Demand and approvals |
| 35 | `CTRL-004` | `mas-harness-control-plane` | Compiler worker and outbox |
| 36 | `CTRL-005` | `mas-harness-control-plane` | Profile lock and bundle request |
| 37 | `CTRL-006` | `mas-harness-control-plane` | Security and browser acceptance |
| 38 | `DIST-001` | `mas-harness-distribution` | Offline tool bootstrap |
| 39 | `DIST-OCI-001` | `mas-harness-distribution` | Exact OCI closure |
| 40 | `DIST-002` | `mas-harness-distribution` | Supply-chain evidence |
| 41 | `DIST-003` | `mas-harness-distribution` | Offline signing and promotion |
| 42 | `DIST-AIR-001` | `mas-harness-distribution` | Air-gap export/import |
| 43 | `DIST-004` | `mas-harness-distribution` | Modular Helm profiles |
| 44 | `OP-001` | `mas-harness-operator` | Operator and CRD bootstrap |
| 45 | `OP-002` | `mas-harness-operator` | Preflight and verification |
| 46 | `OP-003` | `mas-harness-operator` | Foundation reconciliation |
| 47 | `CTRL-007` | `mas-harness-control-plane` | Tenant harness overview and operator portfolio |
| 48 | `CONF-001` | `mas-harness-conformance-labs` | Conformance kit |
| 49 | `CONF-002` | `mas-harness-conformance-labs` | Warm-source parity registry |
| 50 | `CONF-A1-001` | `mas-harness-conformance-labs` | Foundation certification |

## Alpha 2 — Read-only intelligence

| Order | Packet | Repository | Acceptance slice |
|---:|---|---|---|
| 51 | `MODEL-001` | `mas-harness-model-plane` | Local inference core |
| 52 | `MODEL-002` | `mas-harness-model-plane` | Custody and signed routes |
| 53 | `MODEL-OLLAMA-001` | `mas-harness-model-plane` | Ollama provider |
| 54 | `MODEL-LLAMACPP-001` | `mas-harness-model-plane` | llama.cpp provider |
| 55 | `MODEL-VLLM-001` | `mas-harness-model-plane` | vLLM provider |
| 56 | `MODEL-003` | `mas-harness-model-plane` | Model security and telemetry |
| 57 | `KN-RET-001` | `mas-harness-knowledge-plane` | Retrieval and cited context |
| 58 | `EXEC-001` | `mas-harness-execution-plane` | Execution foundation |
| 59 | `EXEC-PROT-001` | `mas-harness-execution-plane` | Protocol gateway |
| 60 | `EXEC-ORCH-001` | `mas-harness-execution-plane` | Durable orchestration |
| 61 | `RUN-001` | `mas-harness-runtime-plane` | Runtime edge foundation |
| 62 | `RUN-GW-001` | `mas-harness-runtime-plane` | Signed routing and budgets |
| 63 | `RUN-GW-002` | `mas-harness-runtime-plane` | Streaming and cancellation |
| 64 | `CONF-A2-001` | `mas-harness-conformance-labs` | Read-only agent certification |

## Alpha 3 — Governed action and interaction

| Order | Packet | Repository | Acceptance slice |
|---:|---|---|---|
| 65 | `TRUST-GOV-001` | `mas-harness-trust-plane` | Approvals, autonomy, and waivers |
| 66 | `TRUST-REG-001` | `mas-harness-trust-plane` | AgentOps registry and promotion |
| 67 | `EXEC-TOOL-001` | `mas-harness-execution-plane` | Governed tools and compensation |
| 68 | `EXEC-SBX-001` | `mas-harness-execution-plane` | Job and Wasmtime sandboxes |
| 69 | `EXEC-SBX-002` | `mas-harness-execution-plane` | gVisor and Kata sandboxes |
| 70 | `EXEC-ML-001` | `mas-harness-execution-plane` | Local decision service |
| 71 | `KN-MEM-001` | `mas-harness-knowledge-plane` | Governed memory |
| 72 | `RUN-EXP-001` | `mas-harness-runtime-plane` | Interaction and resumable UI |
| 73 | `OP-004` | `mas-harness-operator` | Per-module reconciliation |
| 74 | `CONF-A3-001` | `mas-harness-conformance-labs` | Governed-action certification |

## Alpha 4 — Enterprise release

| Order | Packet | Repository | Acceptance slice |
|---:|---|---|---|
| 75 | `MODEL-004` | `mas-harness-model-plane` | Performance evidence |
| 76 | `TRUST-EVAL-001` | `mas-harness-trust-plane` | Assurance and evaluation |
| 77 | `TRUST-003` | `mas-harness-trust-plane` | Trust resilience |
| 78 | `KN-002` | `mas-harness-knowledge-plane` | Knowledge resilience |
| 79 | `EXEC-002` | `mas-harness-execution-plane` | Execution resilience |
| 80 | `RUN-002` | `mas-harness-runtime-plane` | Runtime resilience |
| 81 | `DIST-005` | `mas-harness-distribution` | Distribution reproducibility/security |
| 82 | `OP-005` | `mas-harness-operator` | Upgrade and rollback |
| 83 | `OP-006` | `mas-harness-operator` | Uninstall and fleet sync |
| 84 | `OP-007` | `mas-harness-operator` | Platform security |
| 85 | `CONF-K8S-001` | `mas-harness-conformance-labs` | Kubernetes live certification |
| 86 | `CONF-OCP-001` | `mas-harness-conformance-labs` | OpenShift live certification |
| 87 | `CONF-K3S-001` | `mas-harness-conformance-labs` | K3s certification |
| 88 | `CONF-AIR-001` | `mas-harness-conformance-labs` | Physical air-gap certification |
| 89 | `CONF-SEC-001` | `mas-harness-conformance-labs` | Adversarial security certification |
| 90 | `CONF-UPG-001` | `mas-harness-conformance-labs` | Lifecycle certification |
| 91 | `CONF-WG-001` | `mas-harness-conformance-labs` | White-goods enterprise acceptance |

This table is a valid topological order. Parallel execution is permitted only when all predecessors are complete and the packet boundaries do not conflict.
