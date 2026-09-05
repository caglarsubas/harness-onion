# Development checkpoint — Phase 0 to Alpha 2

Snapshot: 2026-09-05, during `MET-REPAIR-001` publication. This is a checkpoint,
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
| Alpha 2 entry | `MET-REPAIR-001` | ONGOING — local offline PASS | R01–R06 authority and 114-packet catalog; initial exact-head replay passed 449 tests with 10 nested-isolation skips; final-head CI/merge/exact-main remain required |
| Foundation correction | `CON-FIX-001` | WAITING | R01/R02 inventory, additive release assertions and independent status vectors |
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

Operator reauthorization is complete: the existing key signed the exact
MET-REPAIR-001 packet, fresh isolation preflight passed, and launcher version
1.4.1 passed its installed self-check. Its packet SHA-256 is
`45ea3a94514ae1b7b06608fa4629603fbe3c908c726da66fa733ccaffcb03986`.
The first administrator attempt restored the previous bundle after a macOS
working-directory denial; the identical bundle passed when launched from a
readable temporary directory. No source, isolation, dependency or key change
was required, and the prior root-owned authority is retained for rollback.

Initial exact-head local replay of
`0ee855e2852b0fde17b17119a67da8d651aa4059` passed the complete declared argv:
readiness, five-source reuse, Alpha-2 and repair authority, 449 pytest cases
with 10 skips, and the zero-bill scan. Skips are the existing nested-isolation
tests under the enforced outer boundary, not product conformance passes.
The execution log SHA-256 is
`3c2b81e5f10300c6de8e221906b39053a87bb8a752a76e41da806b6722942986`.
This is local evidence, not GitHub CI, merge or exact-main acceptance. The
checkpoint update itself still requires fresh final-head replay and the
required self-hosted check on [PR 92](https://github.com/caglarsubas/harness-onion/pull/92).
Never run acceptance directly or substitute a hosted runner.
Next product packet after authority merge and exact-main acceptance: CON-FIX-001.
The [repair plan](alpha-2/READINESS_REPAIRS.md) keeps review findings, ownership,
product fixes and live acceptance distinct. No phase completion is claimed here.

Every progress report should show **phase, packet ID, status, description,
completed evidence, current blocker and next packet**. At a phase completion,
include the previously requested model-effort reminder without changing the
user's configured model automatically. A packet completion is not automatically
a phase completion.
