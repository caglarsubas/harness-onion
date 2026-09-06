# Development checkpoint — Phase 0 to Alpha 2

Snapshot: 2026-09-06, during `MET-LINUX-001` publication. This is a checkpoint,
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
| Foundation authority | `MET-REPAIR-002` | DONE — source/CI/merge/local exact-main | PR 93 at f753b99; amended cumulative regression authority |
| Foundation correction | `CON-FIX-001` | DONE — source/CI/merge/local exact-main | PR 8 at fb365aa; 758 passed, zero skips; independent status vectors and cumulative registry correction |
| Alpha 2 authority | `MET-LINUX-001` | ONGOING — local acceptance passed; publication pending | Early Linux gates, three owned packets, exact 118-packet catalog and checkpoint; fresh-head CI/merge/exact-main remain separate |
| Alpha 1 correction | `CTRL-FIX-003` | WAITING | R03/R04/R05 read-time freshness, portfolio and aggregation parity |
| Alpha 2 foundation | `MET-LINUX-002` | WAITING | Linux trusted-runner candidate, pinned build inputs and operator isolation kit |
| Alpha 2 early gate | `CONF-LINUX-001` | WAITING — Linux execution unavailable | Real Linux AMD64 build/isolation/minimal runtime baseline; ARM64 independently qualified |
| Alpha 1 integration | `CTRL-INTEGRATE-001` | WAITING — fresh Linux gate | R06 authenticated production overview and durable projection adapters; separate live acceptance required |
| Alpha 2 | `CON-MODEL-001` | WAITING — corrective prerequisites | Model API/usage contracts after CON-FIX-001 and CTRL-FIX-003; full contracts suite required |
| Alpha 2 | `MODEL-001` | WAITING — prerequisites and fresh Linux gate | Model repository bootstrap and local inference core |
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
At that historical baseline, the status-precedence discrepancy was source-reviewed
but its new regression had not run. No product file was changed by that baseline
run. The later independent regression and correction are recorded below.

The user approved the [narrow amendment](alpha-2/READINESS_REPAIRS.md) on
2026-09-05. MET-REPAIR-002 completed as
[PR 93](https://github.com/caglarsubas/harness-onion/pull/93), main
`f753b99eeeaf74b57270ab3b4fe9884cab424c37`, required
[CI 33958674483](https://github.com/caglarsubas/harness-onion/actions/runs/33958674483).
Its separate local exact-main replay passed 506 tests with ten expected
nested-isolation skips.

CON-FIX-001 completed as
[contracts PR 8](https://github.com/caglarsubas/mas-harness-contracts/pull/8).
Required [CI 33982852363](https://github.com/caglarsubas/mas-harness-contracts/actions/runs/33982852363)
passed for source `d00a298e68b49cd400115c10f273ce715818d982` through PR merge ref
`799759d4417192ec2431e844056e527ef241f505`.
Squash main is `fb365aabfd8c5560e064be5d97ff9f2bcc69c57c`; its tree matches
the tested source. Exact-head and separate local exact-main each passed all
three commands and 758 tests with no skips. Exact-main log SHA-256:
`c4fc420019527382d41ec72d06e4de91e00ebb401e9c38c78d1b40056f95429a`.
The independent pre-fix status regression was 753 passed/three failed at
`5ccac6027bc090a6332ec7eef5581d7934c59853`, log SHA-256
`2db2f4d832fc9cdd6335dd2398640baeeb6f97151571ed760faf9606422ea378`.
Keep it separate from the original CON-007 baseline. The ephemeral runner was
removed; operator evidence and rollback retained. None of these results is
Linux deployment/runtime acceptance.

The approved [early Linux amendment](alpha-2/LINUX_READINESS.md) brings the
current catalog to 118 packets. Historical 107/110/114/115 snapshots and source
locks remain unchanged. MET-LINUX-001 is the current publication. Signed local
acceptance of source `0a6fb00de344af01d27c3a66899e4a758bf8593e` passed all seven
declared commands: 577 tests passed with ten expected nested-isolation skips,
and all five authority validators plus the zero-bill scan passed. Local log
SHA-256: `0cb31f69a7ea08157c6765f1820f6b3d80302e747d9164bc7b8380dd8955f164`.
The installed host's real OS isolation probes passed separately. This is exact
committed-source evidence, not evidence for a later head, PR merge or Linux.
Required CI, merge and exact-main are still pending at this checkpoint.
Next product packet after publication closure: CTRL-FIX-003. Then implement
MET-LINUX-002 and CONF-LINUX-001; do not dispatch new runtime code until the
separate fresh native Linux AMD64 gate passes. Contract-only exceptions and
the full Alpha-4 matrix are described in the Linux plan.

The previous OS-custody blocker is resolved. The external permanent localhost
launcher is installed and verified after a directory-mode repair and a narrow
no-bytecode repair. Six generated Python cache files were quarantined with
rollback; no pinned tool inventory was relaxed or regenerated. The existing key
now authorizes exact packet/commit/profile data through a fixed, no-argument,
digest-bound maintenance helper without an administrator prompt. Successful
activation, idempotent retry, invalid-input/extra-argument refusal, inventory
self-check and installed OS isolation were independently verified. No operator
code, key or installation script is shipped in this publication.

No runner is registered at this checkpoint. The older required run
34009931651 remains CANCELLED, not PASS. Before publication, replay the updated
exact head, run required CI on its independently signed PR merge ref using an
ephemeral localhost runner, merge only green checks, and replay exact main.
Routine packet re-signing needs no renewed permission or OS authentication;
policy/toolchain/backend changes remain separate privileged maintenance.

Standing operator permission covers packet-specific localhost runner
reauthorization without repeated permission requests, using the existing key,
local preinstalled caches, fresh isolation preflight, root-owned installation,
ephemeral credential-free execution and rollback. Permission does not bypass
OS root custody: if noninteractive installation is unavailable, retain prepared
evidence and report the actual blocker. Do not automate administrator prompts,
store a password or introduce a broad privilege grant. No downloads, hosted runners, cloud
resources, broader product paths, warm-source observation/copying or live
tenant execution are granted by that permission. No phase completion is claimed.

Every progress report should show **phase, packet ID, status, description,
completed evidence, current blocker and next packet**. At a phase completion,
include the previously requested model-effort reminder without changing the
user's configured model automatically. A packet completion is not automatically
a phase completion.
