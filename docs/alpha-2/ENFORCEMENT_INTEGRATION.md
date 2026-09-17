# Alpha 2 — host enforcement ownership and interface amendment

## Current validation repair — MET-PERF-018

[Single-traversal catalog repair](CATALOG_TRAVERSAL_REPAIR.md): Alpha2 ONGOING.
MET-ENFORCE-001 DONE_SOURCE_GATES at cdb71ae / PR135; exact-main evidence retained.
MET-PERF-018 ONGOING_SOURCE_REPAIR:187 specifications;186 accepted predecessor packets immutable.
Draft PR136 / MET-ENFORCE-002 remains BLOCKED_LOCAL_ALLOWANCE_EXHAUSTED; not imported or retried.
Repair duplicated META catalog traversals without caching authority or skipping fresh checks.
W01 ONGOING_DESIGN; W02-W07 not dispatchable; all E01-E12 OPEN_UNPROVEN.
CONF-FIX-009 BLOCKED_LOCAL_ALLOWANCE_EXHAUSTED; CONF-FIX-010 BLOCKED_SAFE_DESIGN, zero attempts.
CONF-LIVE-004/005/006 and CONF-A2-001 WAITING; Alpha3/4 WAITING; effort NOT_DUE.
Preserve the [all16 harness/paper/OSS map](HARNESS_PAPER_REPOSITORY_MAP.md).
Earlier headings are historical checkpoints, not current dispatch authority.

## Retained planning and historical checkpoints

MET-ENFORCE-001 · ONGOING_SOURCE_PUBLICATION · no runtime adoption.

## Current position

| Phase | ID | State | Deliverable |
|---|---|---|---|
| Phase0 / Alpha1 | Existing foundations | DONE_RECORDED | Historical source/offline evidence |
| Alpha2 | MET-REPAIR-019 | DONE_SOURCE_GATES | PR134 / main69dceab; LOCAL, required CI and exact-main recorded separately |
| Alpha2 | OBS-ENFORCE-FEAS-001 | DONE_FEASIBILITY_SCREEN | Source-backed research; not independent implementation review |
| Alpha2 | MET-ENFORCE-001 | ONGOING_SOURCE_PUBLICATION | Ownership, selected design directions, ordered non-dispatchable backlog |
| Alpha2 | CONF-FIX-009 | BLOCKED_LOCAL_ALLOWANCE_EXHAUSTED | Prior attempts remain consumed |
| Alpha2 | CONF-FIX-010 | BLOCKED_SAFE_DESIGN | Unchanged packet; zero attempts |
| Alpha2 | Native profile / enforcement implementation | WAITING_EXACT_SUCCESSOR | Concrete ABI, locks, review and independent evidence required |
| Alpha2 | CONF-LIVE-004/005/006; CONF-A2-001 | WAITING | Not unblocked by this source publication |
| Alpha3 / Alpha4 | Governed actions / enterprise qualification | WAITING | Existing roadmap |

## Decisions made here

The architecture decisions below are adopted for subsequent planning. They do
not change today's accepted public/native wire contracts or authorize installing
anything. Source ownership, selected design direction, released artifact and
qualified deployment are different states.

1. **R10 is the accountable source owner** for four planned host-enforcement
   modules: host-containment, capacity-broker, policy-observer and effect-admission.
   These are separately versioned host prerequisite artifacts, not code running
   inside the nonroot Kubernetes controller. No new repository or harness.
2. **Choose a versioned delegated-cgroup profile direction** for conventional
   systemd hosts. A later exact ABI amendment must enroll four canonical role
   paths under a single owned service/scope subtree, with exact ancestor/inode
   and namespace checks. No path discovery, alias, arbitrary prefix or change to
   the currently fixed root-level paths is authorized by this publication.
3. **Retain exact endpoint enforcement semantics.** Generic IP allowlists, bind
   controls, CNI presets or an eBPF tool's presence are not evidence for the
   existing seven-hook, map-free, exact local/effective-program contract. Reuse
   upstream primitives; independently inspect actual configuration. Never detach
   enterprise controls just to make our qualification count pass.
4. **Separate policy observation from effect admission.** A current observation,
   lease, token or webhook success is not an operation grant. Every fixed
   CREATE/GET/DELETE operation, including old connections and queued requests,
   requires the independent generation gate. Relevant policy writers must be
   excluded or serialized with a named linearization point. All bypass paths,
   crash/expiry behavior and admitted-but-ambiguous remote effects remain proof
   obligations. There is no hidden new socket, daemon, credential or public field.

The [ADR](../adr/0009-host-enforcement-ownership.md) records ownership boundaries.
The [machine plan](../../architecture/enforcement-integration-plan.json) is the
closed planning ledger. The [research screen](ENFORCEMENT_FEASIBILITY.md) explains
why popular upstream components are useful but not demonstrated drop-in brokers.

## Module and dependency boundaries

| Planned module | Source owner | Deployment responsibility / state |
|---|---|---|
| host-containment | operator | Independently installed host authority establishes protection before role code; NOT_IMPLEMENTED |
| capacity-broker | operator | Native ELF broker, original-parent worker custody, durable reservations, termination; NOT_IMPLEMENTED |
| policy-observer | operator | Independently current namespace/policy/capacity observation; NOT_IMPLEMENTED |
| effect-admission | operator | Deny-by-default operation/generation gate independent of Python role progress; NOT_IMPLEMENTED |
| qualification readers and adversarial campaign | conformance-labs | Consume exact interfaces/artifacts; never implement or self-certify the enforcement premise |
| artifact/SBOM/offline bundle | distribution | Assemble released prerequisites; no runtime Git or dependency downloads |
| public schemas, if needed | contracts | Sole wire/schema authority; version and migrate before affected consumers |

Logical owner namespaces are `host-enforcement/<module>/` in R10. These are
planning identifiers, **not allowedPaths globs** or an assertion those folders
exist. A later packet enumerates exact files, toolchain, locks and acceptance.
Implementation language and artifact versions are not selected here. Reuse R10's
existing toolchain only if it can prove the native lifecycle requirements; do not
silently extend either a toolchain or the stdlib-only R12 reader.

The Kubernetes controller remains nonroot, with unchanged existing application
installation responsibilities and grants. Host policy ownership above concerns
only this separate qualification-host prerequisite, not general application
policy authoring, cluster administration or a new sandbox kernel. Source owner
R10 does not replace the independently authorized deployment operator/reviewer.

Existing consumer-to-provider graphs remain unchanged. Planned R10/R12/R11/R01
interfaces must use published contracts and immutable artifacts; implementation
source must not cross repository boundaries. Exact new artifact edges must be
registered by the successor before use. Distribution packages a released owner
artifact; later installation consumes the verified bundle. No build cycle.

## Non-dispatchable delivery backlog

The identifiers in this table are work labels, not task packets or execution grants.

| Order / work label | Owner | Exit condition |
|---|---|---|
| W01 HOST_INTERFACE_SPEC | operator + meta coordination | Exact module interfaces, original-parent startup, state ownership, all permitted mutators, process/privilege boundary and failure semantics; independent design review |
| W02 NATIVE_PROFILE_CONTRACT | contracts if public; conformance-labs for private ABI | Exact delegated paths/version, old/new rejection and migration vectors, BPF policy compatibility; no implicit old-profile fallback |
| W03 HOST_PREREQUISITE_SOURCE | operator | Separately scoped owner packets, pinned toolchain/dependencies/license closure and full source gates; no root install during source testing |
| W04 ENFORCEMENT_TEST_SOURCE | conformance-labs | Independent adversarial suite and exhaustive direct/indirect observation-window map at the exact candidate revision |
| W05 HOST_ARTIFACT_CLOSURE | distribution | Released artifact digests, signatures, SBOM and offline closure |
| W06 NATIVE_ENFORCEMENT_PROOF | conformance-labs + external installed authority | Exact existing Linux target; independent signatures; E01–E12 evidence and rejection tests under the trusted live launcher |
| W07 READER_TEMPORAL_SUCCESSOR | conformance-labs | Only after the enforcement premise is proven: exact changed-trace/test mapping and separate source/CI/main/native acceptance |

W01 is the next design task; it must settle actual implementation interfaces,
not merely repeat a generic enforcement requirement. W02 follows W01. W03 and
W04 follow W02; W05 follows W03; W06 follows W04/W05; W07 follows W06. No product
packet is added here and no work label is dispatchable. If W01 cannot identify a
bounded safe mechanism, the affected capability remains unavailable. No request
for routine reapproval is needed to perform in-scope specification work.

## Gates not closed by this amendment

All E01–E12 remain OPEN_UNPROVEN; the prior matrix, private factory, current
observation cadence, clock bounds, broker transcript, credential ordering,
durable consumption and exact-UID cleanup remain unchanged. The exhaustive trace
map is still required, including nested custody/peer/clock checks and autonomous
events. Neither selected repository ownership nor an upstream README proves it.

The reviewed prior design remains reviewed only at its original scope. This new
editorial/ownership amendment has no claimed independent security review. An
exact implementation and native proof are later requirements, not tests mocked
into existence by this publication. No product/native/tenant acceptance.

## Publication acceptance and constraints

One META packet/branch/PR from69dceab; preserve185 predecessor YAML and all prior
architecture data. Add one source-only validator to47 predecessor commands for48,
including both full replays and10 established skips. Use current-first reversible
history; never execute historical source. Freeze actual new/inherited test counts
before reservation. LOCAL2/CI2/LOCAL_EXACT_MAIN1; no prior budget reset or transfer.
Keep750s local/main,420s nested,900s trusted and15min workflow bounds.

The existing signed localhost runner only: no root policy/key/admin/toolchain/
workflow changes, native campaign, product source imports, warm-start access,
download, hosted runner, paid API, artifact upload, cloud provisioning or telemetry
default. Source/CI/merge/exact-main/artifact/native/runtime/tenant states differ.
Rollback is a reviewed source revert before consumption or successor afterwards;
never erase consumed authority, failed evidence or ambiguous resources.

Preserve16 harnesses/four planes/13 repositories and the
[all16 harness-paper-OSS map](HARNESS_PAPER_REPOSITORY_MAP.md), including provider
adoption rather than rebuilding harness frameworks. Require **at least one
qualified baseline for every released harness capability** at first enterprise
release. Alpha2 remains open; model-effort transition **NOT_DUE**.
