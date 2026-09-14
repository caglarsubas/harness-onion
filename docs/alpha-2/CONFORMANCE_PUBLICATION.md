# Alpha 2 — bounded conformance source publication

MET-PUBLISH-001 is a META-only planning/validation packet. It authorizes a later,
distinct publication run for the existing CONF-LIVE-003 owner only after its own
local head, required localhost PR CI, green-only merge and LOCAL exact-main gates.
It does not run product code or publish the product in this META coding run.

## Current evidence, not a replacement history

Accepted META predecessor: 0eb07ad1cd95de89d6e484aeb393fe1dc469ed2b (PR #120).
CONF-LIVE-003 local commit 7939626dc6aec99b58816e3a709fd0babf3a985f, tree
f5a25661c2df6c87e5d3429b0b5f62511c2e5988, completed the original eight commands:
1,277 tests in six suites, no failure/error/skip, 427.110394334 monotonic seconds
and 427.1115560531616 wall seconds. Independent audit passed; all 135 source
files and the pinned toolchain stayed unchanged; no sleep/thermal event observed.
Evidence remains LOCAL_OFFLINE_ACCEPTANCE_ONLY, not an SLA or timeout-cause proof.

The local reservation is consumed (zero remaining), as are the two earlier
diagnostic budgets. Prior assertion failures/timeouts stay failures. All 80 older
CONF-LIVE-003 signed requests plus local activation 276 remain in custody.
architecture/conformance-publication.json pins these facts and the retained
audit/log/result/signature hashes. Source records cannot authenticate signatures,
execution or acceptance; independent operator revalidation is mandatory.

The original architecture/local-acceptance.json and all 162 predecessor packet
YAML files stay byte-identical. No old budget is reopened. Catalog: 163 packets,
16 harnesses, four planes, 13 repositories. At least one qualified baseline per
released capability remains the enterprise-release minimum. Linux Kubernetes/
OpenShift is production; macOS is development, not a Linux qualification substitute.

## Later publication sequence

1. Independently reverify all META gates and the retained product local result.
   Check the full immutable source/test/toolchain inventories, packet/signatures,
   prior reservations and complete signed history. Missing or unexpected custody,
   source/toolchain drift or unsupported isolation means NOT_RUN_ENV_UNAVAILABLE.
2. Refresh GitHub before any write. Preserve existing branch
   codex/conf-live-003-proxy-admission and draft PR #12. Remote head must still be
   699a00c2d26e36c9c710aa85d0338f0d926073f2; main must still be
   f988c78e93b28257810ed99e7f0c072e9b76bae5. Confirm ancestor relationships and the
   exact 135-file tree. Reserve the publication record outside disposable workspaces.
3. Fast-forward push only the already locally accepted 7939626 commit to that
   existing branch/PR. No source edits, rebase, force push, new branch or new PR.
   The resulting pull_request event may queue CI, but only the preinstalled,
   ephemeral localhost runner may execute it. Do not create duplicate dispatches.
4. Resolve and verify the exact PR merge-ref, its ordered base/head parents and
   expected f5a25661 tree. Independently bind repository, PR, run ID/attempt, job,
   workflow digest and the fresh root-signed checkout identity before execution.
   Reserve the CI attempt before activating a runner. Never consume another job.
5. Run the unchanged eight commands through the existing installed offline
   launcher. One CI attempt, zero retries; required verify must succeed. Retain
   complete logs and independently audit command order, suite counts, signatures,
   source/toolchain custody, isolation and uninterrupted wall/monotonic timing.
   Retire the runner and its credentials on every exit path. Job success alone
   does not prove signature/source custody or release acceptance.
6. Only after that audit and all required checks/reviews pass, merge the exact
   head/base under repository protections using a permitted merge mode. Never
   bypass protection. Recheck head/base/tree immediately before mutation; verify
   merge commit, parent, tree and GitHub main afterward. Drift stops the sequence;
   a changed tree requires separate review, not a mechanical rebase or repair.
7. Reserve one separate LOCAL exact-main attempt against the verified protected
   merge commit, same tree, and independently audited required CI. Sign that exact
   identity and run the original eight commands through the installed launcher.
   No GitHub workflow_dispatch is granted for exact-main. One attempt, zero retries.
   Merge evidence and exact-main acceptance remain independent.

## Durable accounting and failure behavior

The three external records are:
- operator-attempts/MET-PUBLISH-001-CONF-LIVE-003-PUBLICATION.json
- operator-attempts/MET-PUBLISH-001-CONF-LIVE-003-CI.json
- operator-attempts/MET-PUBLISH-001-CONF-LIVE-003-MAIN.json

Create records atomically/exclusively and fsync them outside ephemeral checkouts.
Bind accepted META/packet, original product packet, stage, exact commit/tree/source
inventory, signed request and max1/retry0; CI additionally binds the exact GitHub
run/job/attempt/workflow/PR/head/base and main binds the verified merge and CI audit.
The publication record pins the intended old/new head, base and local audit;
it is not a signed execution and does not substitute for either stage reservation.

Reserve execution before runner activation or local launch. Crash, timeout,
sleep or interruption consumes that stage. New signatures/directories, process
restart or workflow rerun do not renew it. No pooling partial commands across
runs; do not reuse the completed local attempt as CI or main acceptance.
Keep all results, even failed ones. Missing prerequisites before reservation
are NOT_RUN_ENV_UNAVAILABLE, not PASS. Incomplete stages cannot unlock later ones.

For an uncertain push/merge response, inspect current remote state and retain
the evidence; do not blindly repeat a mutation. This policy grants no new product
code correction, retry or protection override. Failures needing those actions
require a separately reviewed amendment. No product execution occurs in this META run.

## Unchanged acceptance and safety boundaries

All six discovery roots and their 1,277 static identities remain pinned by the
unchanged local-acceptance specification. The original recipe has empty prefetch,
eight direct argv arrays in one deny-all-outbound process tree, full unfiltered
stdout/stderr, no new profiler, filter, skip, source overlay or timeout extension.
420-second nested, 900-second trusted and 15-minute workflow bounds remain.

Known mock regression receipts are not outer command evidence. Account for their
exact pinned sequence separately, then require all eight real outer commands and
the matching packet digest/activation marker. Report static IDs separately from
observed suite totals, not invented verbose case traces.

The campaign/evidence commands are structural verification only. All 20 native
Linux controls remain NOT_RUN_ENV_UNAVAILABLE. Source/CI/merge/artifact/deployment/
runtime/assurance/tenant states remain distinct. Neither a campaign nor this
planning validator may certify tenant acceptance or close Alpha 2.

No warm-start source access, paid API, cloud provisioning, hosted runner, runtime
download, external telemetry, root policy/key/admin change, host power change,
new dependency or billable resource. Public GitHub hosting remains bookkeeping;
execution stays on the existing localhost. Installed trust remains mandatory.

## Current backlog

| Phase | ID | Status | Description |
|---|---|---|---|
| Alpha 2 planning | MET-ACCEPT-001 | DONE_RECORDED | Prior META source gates |
| Alpha 2 qualification | CONF-LIVE-003 / local | DONE_LOCAL_ONLY | Eight commands and independent audit, allowance consumed |
| Alpha 2 planning | MET-PUBLISH-001 | ONGOING_PUBLICATION | This separate bounded publication policy |
| Alpha 2 qualification | CONF-LIVE-003 / publication | WAITING_META_SOURCE_GATES | Later push/CI/merge/LOCAL exact-main on unchanged source |
| Alpha 2 qualification | CONF-LIVE-004/005/006 | WAITING | Native probes, packaging and trusted campaign integration |
| Alpha 2 completion | CONF-A2-001 | WAITING | Qualified integrated read-only profile |
| Alpha 3 | CONF-A3-001 | WAITING | Governed actions and independent qualification |
| Alpha 4 | Enterprise qualification | WAITING | Disconnected acceptance and baseline coverage |

Alpha 2 remains ONGOING; model-effort transition NOT_DUE. These are source-time
statuses; independent post-merge operator evidence records subsequent completion
without rewriting historical evidence.
