# Independent review brief — W01

Status: **NOT_REVIEWED**. This file is authored by the implementation/design agent;
it is not an independent verdict. The prior OBS-ARCH-DESIGN-001 review does not
extend to these new interface and topology proposals.

## Decisions requiring review before adoption

| ID | Proposed direction / gap | Required disposition |
|---|---|---|
| G01 | Put per-operation enforcement in the already-authorized API-proxy boundary, not the Python campaign server | Verify exact endpoint/credential ownership, maintained OSS implementation route and complete deny/forward/record lifecycle |
| G02 | Add one broker-local private control channel, with exact action arming and consumption | Explicit versioned ABI amendment, peer subject/native qualification and resource-result compatibility; no returned-token grant |
| G03 | First candidate co-locates broker and gate on the same enrolled Linux host | Determine whether this is an acceptable optional qualification-profile restriction; do not impose it on every tenant deployment |
| G04 | No concrete complete policy-writer backend is selected | Remains a blocker. Identify all actual writer paths and native mediation, or leave this capability unavailable. A review cannot manufacture backend evidence |
| G05 | Current contract says 'before committing a mutation'; gateway owns forwarding but not arbitrary remote storage commit | Resolve semantics explicitly. Preserve already-admitted ambiguous work; do not claim an end-to-end atomic transaction from a webhook/proxy acknowledgement |
| G06 | Effect gate is a new process not covered by the existing four-role native record | Version the record/role/manifest interface; no implicit role alias or unqualified fifth process |
| G07 | Exact least-privilege host install/seal/runtime policy and worker pre-exec sequence remain unspecified | Needs syscall/capability/MAC and process-lifetime design, not generic root privileges or systemd service names |
| G08 | Independent review and native proofs absent | Keep W01 ongoing, all E01-E12 open, W02-W07 nondispatchable and CONF-FIX-009/010 blocked |

## Counterexamples the review must reject

1. Gate approves a callback; server pauses; generation invalidates; server sends
   later over an old TLS connection. Required: the independent gate owns forwarding
   and denies actions not consumed before invalidation.
2. Request is parsed/queued under generation N, but consumed after N is invalid.
   Required: current admission check at consumption, never enqueue-time permission.
3. An authorization success is cached across policy changes, or an earlier
   authorizer allows before the gate. Required: demonstrated failure/cache/ordering
   behavior, not merely a configured webhook address.
4. system:masters, impersonation, aggregate grants or another API server bypasses
   the writer gate. Required: actual exclusion/mediation and full writer closure.
5. A write passes admission, another policy writer commits, and the original write
   then reaches storage. Required: explicit admitted-versus-committed semantics;
   callbacks do not prove a storage-commit fence.
6. A create is forwarded, its result is lost, then a new generation retries the
   same name. Required: durable ambiguity, consumed intent and no name adoption/reuse.
7. Gate journal fsync succeeds but broker acknowledgement is lost. Required:
   separate durable evidence, held execution and no automatic redispatch.
8. Gate/broker/server disagree about UID or result classification. Required:
   fail/hold and retained records, never distributed success inferred from one store.
9. Broker dies while Python is stuck; gate continues accepting armed requests.
   Required: original peer-liveness and independent lifetime enforcement, no reconnect.
10. Normal maintenance changes an ancestor BPF attachment or SELinux policy while
    inspected roles still execute. Required: independent deny, quiescence, safe
    maintenance and new generation; not just before/after snapshots.
11. systemd starts the worker and broker adopts it through a pidfd. Required:
    original broker parent and FD3 lineage remain necessary; adoption is not proof.
12. Post-defaulting object differs from the signed template. Required: actual
    pre-persistence admission and retained ownership if an unexpected effect exists.
13. Zero-resource mode skips the real observer because no API action occurs.
    Required: preserve mandatory observation/broker qualification and no fake policy.
14. The new gate is enrolled as BROKER in the old four-role record. Required:
    explicit profile/role versioning and old/new rejection.
15. A candidate claims 'no new endpoint' while privately adding remote control TLS
    transport or a new proxy credential. Required: enumerate and version every
    boundary; the present candidate permits no such hidden fallback.
16. A source/mock/model test is recorded as native proof. Required: independent
    exact-artifact installed Linux evidence; all E01-E12 remain open meanwhile.

## Minimum later verification matrix

These are specifications, not executed tests or acceptance results.

| Group | Cases | Evidence class |
|---|---|---|
| T01 contract | exact fields, duplicate/unknown keys, role/version mismatch, transcript replay and wrong peer | Offline contract data tests |
| T02 lifecycle | unarmed/duplicate/cross-case action, old socket, queued action, conflicting gate/server result | Source tests of actual owner implementations |
| T03 persistence | kill at each fsync/send/result boundary, ENOSPC, partial records, lost acknowledgements, restart/rollback | Real multi-process/storage fault tests |
| T04 host | policy/load/boolean/relabel, namespaces/mount aliases, effective BPF ancestors, mappings/injection, parent/FD spoof | Independently authorized native Linux tests |
| T05 clocks | expiry with stalled Python, suspend, wall-clock rollback, peer death/restart and original deadlines | Independent native lifetime tests |
| T06 API/writers | reads, final mutated objects, controller/aggregate-role changes, privileged/alternate paths, direct-storage hazards | Exact selected backend integration tests |
| T07 cleanup | ambiguous create, conflicting UID, delete precondition, revoked cleanup, pending remote effects | Native integration plus retained resource evidence |
| T08 compatibility | old profile rejection, new profile missing gate/backend, export/upgrade/rollback without nonce reuse | Source and installed migration tests separately |

## Review result requirements

Review the exact hashes in source-index.json and this candidate's files. Return
PASS_FOR_SOURCE_PUBLICATION, CHANGES_REQUIRED or BLOCKED with numbered findings.
PASS_FOR_SOURCE_PUBLICATION must still identify G04-G07 as unresolved if they are
not concretely settled; it is not W01 completion or product/native authorization.
The reviewer must not edit product code, run tests, provision anything, access warm
sources, activate a runner or sign native/tenant acceptance.

After review, the main agent may publish a separately scoped META packet under
standing routine engineering authority. It must not treat that delegation or
the reviewer's prose as proof of an available enforcement backend.
