# Development checkpoint — Phase 0 to Alpha 2

Snapshot: 2026-09-07, during `MET-REPAIR-006` publication. This is a checkpoint,
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
| Alpha 2 authority | `MET-LINUX-001` | DONE — source/CI/merge/local exact-main | PR 94 at b1d7478; original 118-packet Linux gate authority, no native acceptance |
| Alpha 1 correction | `CTRL-FIX-003` | DONE — source/CI/merge/local exact-main | Control PR 10 at 1de7c40; 698 unit and 6 browser checks recorded, no Linux claim |
| Alpha 2 foundation | `MET-LINUX-002` | DONE — source/CI/merge/local exact-main | PR 95 at c37f2b7; candidate and operator kit, SOURCE_PACKAGE_ONLY |
| Alpha 2 authority | `MET-REPAIR-003` | DONE — source/CI/merge/local exact-main | Meta PR 96 at 7047ec9; consumed R1-R4 authority retained |
| Operator prerequisite | OPERATOR-RUNNER-002 (external maintenance, not a product packet) | DONE — external installation/verification | Conformance-only profile admitted; fresh signed activation and OS-denial checks passed |
| Alpha 2 correction | `CONF-FIX-001` | DONE — source/CI/merge/local exact-main | Conformance PR 4 at 07453d3; 83 tests, zero skips, full inventory closure |
| Alpha 2 authority | `MET-REPAIR-004` | DONE — source/CI/merge/local exact-main | Meta PR 97 at a50f878; 1066 tests passed, ten existing nested-isolation skips |
| Alpha 2 early gate | `CONF-LINUX-001` | WAITING — native qualification | Source kit DONE: conformance PR 5 at 88de1d9; 120 tests passed, zero skips; actual AMD64/ARM64 qualification absent |
| Alpha 1 integration | `CTRL-INTEGRATE-001` | WAITING — fresh Linux gate | R06 authenticated production overview and durable projection adapters; separate live acceptance required |
| Alpha 2 authority | `MET-REPAIR-005` | DONE — source/CI/merge/local exact-main | Meta PR 98 at f8137ea; 1168 passed, ten existing nested-isolation skips |
| Alpha 2 authority | `MET-REPAIR-006` | DONE — source/CI/merge/local exact-main | Meta PR 99 at f0ccd9f; 1295 passed, ten existing nested-isolation skips |
| Alpha 2 | `CON-MODEL-001` | DONE — source/CI/merge/local exact-main | Contracts PR 9 at e9de8e5; 1175 passed, zero skips; original-source parity and runtime unproven |
| Alpha 2 authority | `MET-LIVE-001` | ONGOING — publication | Six bounded source-only backend packets; no installation or native qualification |
| Alpha 2 backend | `CONF-LIVE-001` | WAITING | Session contracts and cumulative inventory |
| Alpha 2 backend | `CONF-LIVE-002` | WAITING | Protected Linux supervisor and isolation candidate |
| Alpha 2 backend | `CONF-LIVE-003` | WAITING | Fixed proxy transport and zero-cost admission |
| Alpha 2 backend | `CONF-LIVE-004` | WAITING | Native Linux build and ten fixed probes |
| Alpha 2 backend | `CONF-LIVE-005` | WAITING | Reproducible packaging and operator handoff |
| Alpha 2 backend | `CONF-LIVE-006` | WAITING | Trusted campaign integration and manual qualification declaration |
| Alpha 2 | `MODEL-001` | WAITING — prerequisites and fresh Linux gate | Model repository bootstrap and local inference core |
| Alpha 2 | `MODEL-002` | WAITING | Custody and signed routes |
| Alpha 2 | `MODEL-OLLAMA-001`, `MODEL-LLAMACPP-001`, `MODEL-VLLM-001`, `MODEL-003` | WAITING | Selectable local backends, security and telemetry |
| Alpha 2 | `KN-RET-001` | WAITING | Retrieval and cited context |
| Alpha 2 | `EXEC-001`, `EXEC-PROT-001`, `EXEC-ORCH-001` | WAITING | Execution foundation, protocol gateway and durable orchestration |
| Alpha 2 | `RUN-001`, `RUN-GW-001`, `RUN-GW-002`, `CONF-A2-001` | WAITING | Runtime edge, gateway and read-only agent certification |
| Alpha 3 | `TRUST-GOV-001` through `CONF-A3-001` | WAITING | Governed actions, memory, tools, sandboxes and interaction |
| Alpha 4 | `MODEL-004` through `CONF-WG-001` | WAITING | Performance, resilience, platform and enterprise acceptance |
| Cross-phase | Artifact/SBOM, release, deployment, runtime, assurance, tenant acceptance | WAITING — independent gates | Never inferred from source/offline completion |

## Current amendment boundary — trusted Linux live backend

[Backend readiness guide](alpha-2/LIVE_BACKEND_READINESS.md) adds one meta packet
and six conformance source packets: **130 packets**, thirteen repositories,
sixteen harnesses. All 123 previous packet YAML and existing architecture,
legal, policy and release records remain byte-identical. Existing source locks
and the native AMD64 runtime gate are not relaxed.

MET-REPAIR-006 completed as [meta PR 99](https://github.com/caglarsubas/harness-onion/pull/99),
merge f0ccd9f292f332a05e8eebd17a831e19989fb739, CI 34092480912.
Separate exact-main: 1295 passed, ten existing nested-isolation skips;
log e855f6dd347dc010a51442a8f84a54c9e7c64ed5dac8502d80dd09a74c6cdbac.

CON-MODEL-001 completed as [contracts PR 9](https://github.com/caglarsubas/mas-harness-contracts/pull/9),
merge e9de8e53cf036a90a03b1e114eba08fc0ba89ae3, CI 34101363187.
Separate exact-main: 1175 passed, zero failed/skipped, all 758 predecessor IDs;
log e7dbb4a26b6edf1a84edda528defef90c8cd3258b8a594fc0df156db9e5f4b5f.

CONF-LINUX-001 source kit completed as [conformance PR 5](https://github.com/caglarsubas/mas-harness-conformance-labs/pull/5),
merge 88de1d9b7272a25678b01129e51d5756dbe608ed, CI 34076298942.
Separate exact-main: 120 passed, zero skips;
log 866b0eb26f2c1a97bc106de4f4bb2366251ae09de143233a6c973ae5647b3ac8.
Native AMD64/ARM64 still NOT_RUN_ENV_UNAVAILABLE.

Next: close this authority publication, then CONF-LIVE-001 in its own source
run. The ordered six-packet implementation prepares an uninstalled candidate.
Independent native capacity, reviewed installation, release inputs and signed
manual qualification remain required before CTRL-INTEGRATE-001, MODEL-001,
EXEC-001 or RUN-001. No phase-end model-effort transition is due.

## Historical MET-REPAIR-006 publication checkpoint

The following failed-draft and pending-publication statements are preserved as
the earlier checkpoint, superseded only by the verified current source rows above.

[Exact API-inventory repair](alpha-2/MODEL_API_INVENTORY_REPAIR.md) is the current
publication: 123 packets across thirteen repositories and sixteen harnesses.
It permits only the required-five membership predicate; preserve the named test
ID and every other byte, including all safety checks on every discovered API.
The prior fixture-copy record and all consumed authorities remain immutable.

Meta PR 98 merged at f8137eab6acfa8b13051f1c4e548854fc7dc934f; required CI
34082964856 passed. Separate local exact-main: 1168 passed, ten existing
nested-isolation skips; log ada39810a672dc49dad92e353508e18e34746e3dbb243514d2188321662e02ab.

Contracts draft PR 9 remains unmerged at 47c416676b3fba105d7631c1957b9d729daa592e.
Its exact signed replay had 1048 passed, one failed, zero skipped; both generator
checks passed. All 758 predecessor IDs were retained. Log SHA-256:
9176867b7f6137870d6b33dd4c31443f3d98af9794ced6b58831aa4d96d873db.
The queued CI run 34089294582 was cancelled before a runner was assigned:
CANCELLED_NOT_PASS. The no-server issue was source-inspected and removed from
the new API, not a second executed failure. No legacy predicate edit has run.

Next: close MET-REPAIR-006 source/head, PR CI, merge and local exact-main gates;
then resume CON-MODEL-001 in its separate product run. Apply the sole predicate
change, add independent negative vectors, complete normal model-contract completeness review
and rerun the full suite. Contract-only work makes no runtime claim.
CONF-LINUX-001 source kit remains merged (PR 5, 120 passed, zero skips), but
native AMD64/ARM64 qualification remains NOT_RUN_ENV_UNAVAILABLE.
MODEL-001, CTRL-INTEGRATE-001, RUN-001 and EXEC-001 still require fresh native
AMD64 PASS. No new administrator prompt or model-effort transition is due.

## Historical MET-REPAIR-004 publication checkpoint

This earlier snapshot precedes the completed source evidence above.

[Assertion-only Linux test repair](alpha-2/LINUX_TEST_OWNERSHIP_REPAIR.md) is the
current publication. It adds one packet (121 total) and grants exactly one
additional conformance test path. The original 118-packet policy and consumed
120-packet amendment remain byte-identical. No product or privileged host change
is part of this meta PR.

CONF-FIX-001 completed as [conformance PR 4](https://github.com/caglarsubas/mas-harness-conformance-labs/pull/4),
main 07453d3e6313c836426545c454380176bc2a2ee1. Required
[CI 34052209212](https://github.com/caglarsubas/mas-harness-conformance-labs/actions/runs/34052209212)
and the separate signed local exact-main replay each passed 83 tests with no
skips. Main replay log SHA-256:
c793655198e8e0c3dfa9f5a596618b25a579e5dffc74549bd72473847c7ec889.
Meta PR 96 at 7047ec93170d5db8a148d1f6cfd34ad7877fb423 passed required
CI 34032961187 and independent local exact-main replay (955 passed, ten existing
nested-isolation skips). Its source-only closure is distinct from conformance
product repair; neither establishes Linux/runtime or tenant acceptance.

Next: close MET-REPAIR-004 publication, implement CONF-LINUX-001 in its own PR,
then independently qualify native Linux. The new test may only replace its
handler assertion with the exact six-handler tuple; all other legacy test bytes
remain unchanged. Unknown/absent Linux capacity and live isolation/proxy authority
remain NOT_RUN_ENV_UNAVAILABLE. No model-effort transition is due.

## Historical MET-REPAIR-003 publication checkpoint

The following snapshot predates the completed source correction above.

[R1-R4 repair](alpha-2/LINUX_READINESS_REPAIRS.md) is approved. MET-REPAIR-003
publishes exactly two new packets, bringing the current catalog to 120; the
original 118-packet Linux policy remains byte-identical. This is authority
work, not implementation of CONF-FIX-001 or the Linux campaign.

Latest independently checked source prerequisites:
[meta PR 95](https://github.com/caglarsubas/harness-onion/pull/95) at
c37f2b72e7449f787140553beea39ebe871f35da,
[required localhost CI](https://github.com/caglarsubas/harness-onion/actions/runs/34028811315),
and local signed exact-main replay: 249 candidate tests, 577 predecessor tests,
10 explicitly retained nested-isolation skips. Candidate digest and replay log
are recorded in architecture/linux-readiness-amendment.json. No GitHub Actions
exact-main run, Linux installation or native runtime acceptance is implied.
Control PR 10 at 1de7c405329f4458970be0187838145b4da222d8 and conformance PR 3 at
30877d289d389b29d3da9eb9a3c083c9ebc33382 are merged. The product inspection was
read-only; R1-R4 are SOURCE_INSPECTION_ONLY, not reproduced runtime failures.

Next: close this publication, implement CONF-FIX-001 as a separate PR, then
CONF-LINUX-001 source and independent native qualification. Unknown/absent
Linux capacity and the external live isolation/proxy backend remain
NOT_RUN_ENV_UNAVAILABLE. Runtime coding remains gated; no phase completion or
model-effort transition is due. Routine localhost signed activation uses
standing operator authority without another administrator prompt.

## Historical evidence retained from preceding checkpoints

The older publication-time pending states below describe their dated snapshots,
not the current table above. They are retained to avoid erasing failure/history.

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
