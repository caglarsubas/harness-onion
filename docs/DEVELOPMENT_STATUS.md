# Development checkpoint — Phase 0 to Alpha 2

Snapshot: 2026-09-05, during `MET-REPAIR-002` publication. This is a checkpoint,
not a live dashboard or certification ledger. The complete packet list and
descriptions remain in [the roadmap](../task-packets/README.md). A later run
must refresh GitHub evidence rather than infer completion from this document.

| Phase | Packet / gate | Status | Description |
|---|---|---|---|
| Phase-0 closure / Alpha 1 | `MET-P0-002` | DONE — source/PR/merge/offline | Five-source, license inventory and audit closure; meta PR 89 and exact-main run 33784371270 |
| Alpha 1 | `CTRL-007`, `CTRL-FIX-002` | DONE — recorded source/offline | Tenant overview and frontend/RLS corrections; control PR 9 |
| Alpha 1 | `CONF-A1-001` live gates | WAITING | Installed-foundation evidence; offline completion does not certify live behavior |
| Alpha 2 | `MET-A2-001` | DONE — source/PR/merge | Model prerequisites; PR 90 and required verify check independently refreshed on 2026-09-05 |
| Alpha 2 | `MET-OBS-MODEL-001` | DONE — source/PR/merge | Structural observation; PR 91 and required verify check independently refreshed on 2026-09-05; not source behavior or live evidence |
| Alpha 2 entry | `MET-REPAIR-001` | DONE — source/PR/merge/local exact-main | PR 92 at 6e6b911; required CI green and 449 passed/10 nested-isolation skips in separate local exact-main replay |
| Foundation authority | `MET-REPAIR-002` | ONGOING — scope publication | Approve exact cumulative-registry test paths and documented blocked-selection implementation correction; product fixes not yet executed |
| Foundation correction | `CON-FIX-001` | WAITING — amended authority | Baseline 181 passed/3 failed; repair inventory/lineage, legacy registry tests and documented blocked-selection precedence, then publish independent vectors |
| Alpha 1 correction | `CTRL-FIX-003` | WAITING | R03/R04/R05 read-time freshness, portfolio and aggregation parity |
| Alpha 1 integration | `CTRL-INTEGRATE-001` | WAITING | R06 authenticated production overview and durable projection adapters; separate live acceptance required |
| Alpha 2 | `CON-MODEL-001` | WAITING — corrective prerequisites | Model API/usage contracts after CON-FIX-001 and CTRL-FIX-003; full contracts suite required |
| Alpha 2 | `MODEL-001` | WAITING — prerequisites | Model repository bootstrap and local inference core |
| Alpha 2 | `MODEL-002` | WAITING | Custody and signed routes |
| Alpha 2 | `MODEL-OLLAMA-001`, `MODEL-LLAMACPP-001`, `MODEL-VLLM-001`, `MODEL-003` | WAITING | Selectable local backends, security and telemetry |
| Alpha 2 | `KN-RET-001` | WAITING | Retrieval and cited context |
| Alpha 2 | `EXEC-001`, `EXEC-PROT-001`, `EXEC-ORCH-001` | WAITING | Execution foundation, protocol gateway and durable orchestration |
| Alpha 2 | `RUN-001`, `RUN-GW-001`, `RUN-GW-002`, `CONF-A2-001` | WAITING | Runtime edge, gateway and read-only agent certification |
| Alpha 3 | `TRUST-GOV-001` through `CONF-A3-001` | WAITING | Governed actions, memory, tools, sandboxes and interaction |
| Alpha 4 | `MODEL-004` through `CONF-WG-001` | WAITING | Performance, resilience, platform and enterprise acceptance |
| Cross-phase | Artifact/SBOM, release, deployment, runtime, assurance, tenant acceptance | WAITING — independent gates | Never inferred from source/offline completion |

Verified Phase-0 references: [PR 89](https://github.com/caglarsubas/harness-onion/pull/89)
and [exact-main run](https://github.com/caglarsubas/harness-onion/actions/runs/33784371270)
at `d49eb2821419a056ded7c9a9ac2c1a214b4daeb6`.

Freshly checked Alpha-2 source/PR/merge references:
[PR 90](https://github.com/caglarsubas/harness-onion/pull/90), required
[verify run](https://github.com/caglarsubas/harness-onion/actions/runs/33850152506),
merge `db74190b89d0438e1f15040004f91fb957fd4c3e`; and
[PR 91](https://github.com/caglarsubas/harness-onion/pull/91), required
[verify run](https://github.com/caglarsubas/harness-onion/actions/runs/33883641838),
merge `2aa85c1d4ea175dc6fba935bffa5aae2fa64e3c2`.
These are PR checks, not new exact-main or live runs. Older Phase-0/control
references above remain historical snapshots, not re-executed acceptance.

MET-REPAIR-001 publication is complete:
[PR 92](https://github.com/caglarsubas/harness-onion/pull/92),
required [CI run](https://github.com/caglarsubas/harness-onion/actions/runs/33951017359),
squash commit `6e6b91115d59f4fa9be556462d4958dcfad805b6`.
The separate signed local exact-main replay passed all six commands and
449 tests with 10 expected nested-isolation skips; log SHA-256
`84b116ed8a687a4ade1f4c38f390fa37bb14e2681d580dfa4ce612768c04becd`.
This was not a new GitHub Actions exact-main run. The ephemeral runner and
temporary credentials were removed; operator diagnostics and rollback retained.

The first CON-FIX-001 baseline used the exact root-owned packet SHA-256
`fc10e7d4f40c3eacab69dc7d7ef3a23fffeca6e9080392ca26fd0c9c9f2ef9c5`
on untouched contracts main
`2146278a95344cd2a8e22596b2f315b46edffc88`.
Both generation checks passed; the entire test suite returned **181 passed,
three failed, zero skipped**. In addition to the known generated-inventory
failure, two historical registry tests assume earlier repository states.
The immutable log SHA-256 is
`8a918152e335c0d2c48fac7072b70bc3a69acea9caaf4c4a03e9a33d939f74ec`.
The status-precedence discrepancy is source-reviewed but its new regression
has not run. No product file was changed by that baseline run.

The user approved the [narrow amendment](alpha-2/READINESS_REPAIRS.md) on
2026-09-05. MET-REPAIR-002 publishes it separately; source publication, local
offline, required CI, merge and exact-main checks remain required for this
checkpoint itself. The current catalog contains 115 packets; the original
six-finding, 114-packet JSON is retained byte-identically.
Next product packet after amendment merge and exact-main verification:
CON-FIX-001 with a fresh pin for its revised YAML, never the older signature.

Standing operator permission covers packet-specific localhost runner
reauthorization without repeated permission requests, using the existing key,
local preinstalled caches, fresh isolation preflight, root-owned installation,
ephemeral credential-free execution and rollback. Administrator authentication
may still require the macOS prompt. No downloads, hosted runners, cloud
resources, broader product paths, warm-source observation/copying or live
tenant execution are granted by that permission. No phase completion is claimed.

Every progress report should show **phase, packet ID, status, description,
completed evidence, current blocker and next packet**. At a phase completion,
include the previously requested model-effort reminder without changing the
user's configured model automatically. A packet completion is not automatically
a phase completion.
