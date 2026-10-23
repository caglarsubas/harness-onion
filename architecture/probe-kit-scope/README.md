# The probe-kit scope amendment (MET-LIVE-002)

This record is `planeon.internal.probe-kit-scope/v1`, packet MET-LIVE-002, slot 260, work item LINUX-PROBE-KIT-SCOPE. It
is data only: it edits no pinned file and moves nothing the owner did not move. It is the successor that owner decision
Q-PK-2 ("Move them (Recommended)") asked for, to MET-LIVE-001 and MET-REPAIR-014.

The record makes these changes:
- **Moved to the kit.** The CAMPAIGN_PROXY server side, its admission module, the UID ledger and cleanup, the native
  record inspector, the worker entry, the ten case recipes and the unsigned receipt candidates move from R12's
  CONF-LIVE-003/004/005 to the operator-side probe kit, LINUX-PROBE-KIT-001.
- **Kept by R12.** R12 keeps the campaign client and the narrowed handoff, receipt verification and evidence
  verification.
- **Deferred.** The KAP leg stays deferred and unowned.

The record is `amendment.json`, its vectors are `vectors.json`, and the reference model is `scripts/probe_kit_scope.py`.
Every quote, digest and hit is read from harness-onion at the base commit `2043cc27883448e3ff030b7868110e295f32fe09`.

## Inputs, by sha256 at the base

| Input | sha256 |
|---|---|
| `docs/alpha-2/BROKER_HANDOFF_READINESS.md` (BH) | `2cc6ebef252efb33…` |
| `docs/alpha-2/PROXY_CONTRACT_READINESS.md` (PCR) | `3e3bf310ebd8a7b1…` |
| `docs/alpha-2/POLICY_OBSERVATION_READINESS.md` (POR) | `65778040919c5eb7…` |
| `docs/alpha-2/NATIVE_QUALIFICATION_READINESS.md` (NQ) | `60bed4c5358527da…` |
| `docs/alpha-2/CREDENTIAL_ORDERING_REPAIR.md` (COR, gate document) | `b2ed7fe5be1a8b23…` |
| `docs/TRUSTED_LIVE_CAMPAIGN_RUNNER_CONTRACT.md` (TLC, gate document) | `3f1bf16f6ec5d1e2…` |
| `architecture/proxy-contract-amendment.json` (PCA) | `6c93e7db962cffa0…` |
| `architecture/i05-gate-channel/README.md` (I05 v1), `-v2/README.md` (I05 v2), `-v3/README.md` (I05 v3) | `dc9aa22017b2cdf7…`, `1cb07cef90b0881c…`, `f82f43330125640d…` |
| `docs/alpha-2/I05_GATE_CHANNEL.md` (I05 guide) | `97d1172fcde8e2f0…` |
| `architecture/live-backend-roadmap.json` (LBRM), `broker-handoff-amendment.json` (BHA), `native-qualification-amendment.json` (NQA), `completion-integration.json` | `06d55fab0d0e56cb…`, `1b5843241dc2574b…`, `e935cbd3045522cf…`, `0b36ddc4626430b2…` |
| `architecture/host-interface-amendment-hs53/amendment.json` (HS53, the one `crossInputs` record) | `e4255685a38f183d…` |

The full digests are in the record.

## What moves, what R12 keeps, what is deferred, what stays unchanged

- **Moved** to `LINUX-PROBE-KIT-001`, each `SUPERSEDED_UNACCEPTED_HISTORY` in its source packet. Each moved row lists
  the supersedes rows that carry it:
  - `SERVER`
  - `ADMISSION_MODULE`
  - `UID_LEDGER`
  - `RECORD_INSPECTOR`
  - `WORKER_ENTRY`
  - `CASE_RECIPES`
  - `RECEIPT_CANDIDATES`
- **Retained** by R12:
  - `CLIENT`: the campaign client, CONF-LIVE-003 deliverable 1.
  - `CANDIDATE_HANDOFF`: CONF-LIVE-005's narrowed packaging and handoff.
  - `RECEIPT_VERIFICATION`: CONF-LIVE-004's narrowed scope.
  - `EVIDENCE_VERIFICATION`: CONF-LIVE-006 and CONF-LINUX-001.
  - `R12_OTHER`: CONF-LIVE-001/002 and CONF-LIVE-006's launcher hook.
- **Deferred:** `KAP_LEG`, `DEFERRED_UNOWNED`, under owner Q-LPK0-3 ("Server side, KAP stays (Recommended)"; option text
  "KAP stays deferred and unowned, as your LX-D1 says").
  - The source clauses are BH:35, BH:210-214 and PCR:207-225.
  - BHA's `serverOwnsApiCredential` stays an unchanged role rule with no implementing owner.
  - The resource-bearing cases stay behind the leg as an external prerequisite.
- **Unchanged:**
  - the installed identities: executables, manifests, trust anchor, TLS key, state paths and units;
  - the SERVER and WORKER roles of native-profile v4, and v5's kept record;
  - `workerEntry: live_fixed_probes.broker_worker_main`, argv and FD3. This is an installed identity string only. The
    kit owns the module of that name, and R12's same-named path is no worker source;
  - the broker binding, the socket ABI, the proxy profile, the endpoint tuple, the `caseId` enum and the vectors' worker
    digests;
  - the signing duties, with no new key or signature role;
  - CONF-LIVE-006's paths and eight commands.

The S3-14 statements above restore revision 2's text.

## The dispositions and the retired history

- **The packet dispositions.**
  - **CONF-LIVE-003** is `CONSUMED`. Deliverables 2-4 are superseded, unaccepted history; deliverable 1 is kept.
  - **CONF-LIVE-004 and CONF-LIVE-005** are `NOT_DISPATCHABLE_AS_WRITTEN`. Their narrowed scopes come from
    `R12_SUCCESSOR`.
  - **CONF-LIVE-006** is `UNCHANGED`. Its deliverable 3 is superseded for the kit's entries only: it consumes the kit's
    server and worker artifacts by digest.
- **BHA's and NQA's `dispatch` rows** stay as history.
- **`retiredHistory`** uses MET-REPAIR-018's `retiredPacket` shape exactly.
  - CONF-FIX-007 carries 018's own values.
  - CONF-FIX-008, 009 and 010 are `NON_DISPATCHABLE_RETAINED_HISTORY`, not dispatchable, with `pr` and `head` null:
    none has a PR. Owner R-S1-5 ("Retire 008 too (Recommended)") and owner Q-LPK0-4 ("Retain as history (Recommended)")
    decided this.
  - R12's published and draft server source stays as unaccepted history. Nothing is deleted.

## The supersession

Each row holds one quote. The quote occurs exactly once within its cited lines at the base, and the row's `lines` run
from the quote's first byte to its last. PCR:307-313 and COR:122-127 keep their cited sentence ranges. Line breaks are
shown as ⏎, and a long quote is shown as its start … its end. `amendment.json` holds every quote in full, with its
replacement text.

| Id | Pinned text (HO:path:lines) | Quote | Under this amendment | Unchanged (what R12_SUCCESSOR keeps) |
|---|---|---|---|---|
| S-01 | I05 v2:133-133 | it stays carried to the I04 owner (R01) and CONF-LIVE-003 | KAP_LEG → DEFERRED_UNOWNED: It stays carried to the I04 owner (R01) and the deferred, unowned KAP leg. | — |
| S-02 | I05 v2:273-273 | (R01, CONF-LIVE-003) | KAP_LEG → DEFERRED_UNOWNED: (R01, the deferred and unowned KAP leg) | — |
| S-03 | I05 v3:135-135 | it stays carried to the I04 owner (R01) and CONF-LIVE-003 | KAP_LEG → DEFERRED_UNOWNED: It stays carried to the I04 owner (R01) and the deferred, unowned KAP leg. | — |
| S-04 | I05 v3:326-326 | (R01, CONF-LIVE-003) | KAP_LEG → DEFERRED_UNOWNED: (R01, the deferred and unowned KAP leg) | — |
| S-05 | I05 v1:115-116 | it is carried to the I04 owner⏎   (R01) and CONF-LIVE-003 | KAP_LEG → DEFERRED_UNOWNED: It is carried to the I04 owner (R01) and the deferred, unowned KAP leg. | — |
| S-06 | I05 v1:277-277 | (R01, CONF-LIVE-003) | KAP_LEG → DEFERRED_UNOWNED: (R01, the deferred and unowned KAP leg) | — |
| S-07 | PCA:253-253 | Product implementation remains in the eight existing CONF-LIVE-003 paths | ADMISSION_MODULE, SERVER, UID_LEDGER → LINUX-PROBE-KIT-001: The server-side product implementation is LINUX-PROBE-KIT-001's; the client stays in the eight paths with the R12 successor. | CLIENT |
| S-08 | PCA:253-253 | fixed probes, packaging | CASE_RECIPES, RECEIPT_CANDIDATES, SERVER, WORKER_ENTRY → LINUX-PROBE-KIT-001: The fixed probes, the unsigned receipt candidates and the server and worker packaging are LINUX-PROBE-KIT-001's; the client packaging stays with the R12 successor. | CLIENT |
| S-09 | TLC:477-478 | Product implementation remains⏎in that packet's eight existing paths | ADMISSION_MODULE, SERVER, UID_LEDGER → LINUX-PROBE-KIT-001: The server-side product implementation is LINUX-PROBE-KIT-001's; the client stays in the eight paths with the R12 successor. | CLIENT |
| S-10 | TLC:479-480 | CONF-LIVE-004 owns actual probes, CONF-LIVE-005 the fixed client/server⏎candidate packaging | CASE_RECIPES, RECEIPT_CANDIDATES, SERVER, WORKER_ENTRY → LINUX-PROBE-KIT-001: The actual probes, the unsigned receipt candidates and the server and worker packaging are LINUX-PROBE-KIT-001's; the client packaging stays with the R12 successor. | CLIENT |
| S-11 | BH:35-35 | Fixed server/broker transport and server/observer/broker custody checks; resource admission | ADMISSION_MODULE, SERVER → LINUX-PROBE-KIT-001: The fixed server transport, the server-side custody checks and resource admission are LINUX-PROBE-KIT-001's. | — |
| S-12 | BH:35-35 | UID ledger and cleanup | UID_LEDGER → LINUX-PROBE-KIT-001: The UID ledger and cleanup are LINUX-PROBE-KIT-001's. | — |
| S-13 | BH:35-35 | server-only TLS API leg | KAP_LEG → DEFERRED_UNOWNED: The server-only TLS API leg (the KAP leg) is deferred and unowned (owner Q-LPK0-3). | — |
| S-14 | BH:36-36 | Fixed worker entry, ten probe recipes, bounded resource-action requests and unsigned receipt candidate | CASE_RECIPES, RECEIPT_CANDIDATES, WORKER_ENTRY → LINUX-PROBE-KIT-001: The fixed worker entry, the ten probe recipes, the bounded resource-action requests and the unsigned receipt candidates are LINUX-PROBE-KIT-001's; the resource-bearing cases stay behind the deferred KAP leg. | — |
| S-15 | BH:37-37 | Reproducible client/server/worker source candidates and installation handoff | SERVER, WORKER_ENTRY → LINUX-PROBE-KIT-001: The server and worker candidates are LINUX-PROBE-KIT-001's; the client candidate and the narrowed handoff stay with the R12 successor. | CANDIDATE_HANDOFF, CLIENT |
| S-16 | BH:43-44 | The fixed worker is packaged by the existing 005 builder/package module from⏎the existing 004 modules | WORKER_ENTRY → LINUX-PROBE-KIT-001: The fixed worker is packaged by LINUX-PROBE-KIT-001 from its own modules. | — |
| S-17 | BH:45-45 | No future packet must edit 003 to add an unspecified execution interface. | WORKER_ENTRY → LINUX-PROBE-KIT-001: No future packet must edit LINUX-PROBE-KIT-001 to add an unspecified execution interface; the worker ABI is unchanged. | — |
| S-18 | BH:95-95 | 005 packages this entry in addition to the already planned client/server entries; | SERVER, WORKER_ENTRY → LINUX-PROBE-KIT-001: LINUX-PROBE-KIT-001 packages the worker and server entries; the client entry stays with the R12 successor. | CLIENT |
| S-19 | BH:216-219 | 003 resolves a manifestDigest from its own immutable pr …  validating actual post-defaulting manifests. | ADMISSION_MODULE, UID_LEDGER → LINUX-PROBE-KIT-001: Manifest resolution, grants, create intent and the returned UID record are LINUX-PROBE-KIT-001's. | — |
| S-20 | BH:251-253 | 003 tests real fixed client/server factories using OS-m … er credentials if any prerequisite⏎is absent. | SERVER → LINUX-PROBE-KIT-001: LINUX-PROBE-KIT-001 tests the real fixed server factories; the R12 successor tests the client's. | CLIENT |
| S-21 | BH:253-253 | 004 tests all ten fixed recipes and the private worker ABI. | CASE_RECIPES, WORKER_ENTRY → LINUX-PROBE-KIT-001: LINUX-PROBE-KIT-001 tests the ten fixed recipes and the private worker ABI. | — |
| S-22 | BH:253-255 | 005 builds⏎reproducible inert candidates for the three  … server as⏎external unavailable prerequisites. | SERVER, WORKER_ENTRY → LINUX-PROBE-KIT-001: LINUX-PROBE-KIT-001 builds the server and worker candidates; the R12 successor builds the client's. | CLIENT |
| S-23 | COR:122-127 | CONF-LIVE-003 must separately test the actual fixed guard with mocked OS I/O: | SERVER, UID_LEDGER → LINUX-PROBE-KIT-001: Each listed case is tested by the owner of the side it exercises: server-side refusal, policy effects and exact-UID cleanup by LINUX-PROBE-KIT-001, client-side cases by the R12 successor. | CLIENT |
| S-24 | I05 guide:58-58 | (R01, CONF-LIVE-003) | KAP_LEG → DEFERRED_UNOWNED: (R01, the deferred and unowned KAP leg) | — |
| S-25 | NQ:38-38 | Record parser, fixed native inspector, server/observer/ …  credential ordering, transport and admission | ADMISSION_MODULE, RECORD_INSPECTOR, SERVER → LINUX-PROBE-KIT-001: The record parser, the native inspector, the server-side ownership, transport and admission are LINUX-PROBE-KIT-001's; the client's credential ordering and transport stay with the R12 successor. | CLIENT |
| S-26 | NQ:39-39 | Fixed worker; inherited broker-only control; qualified kernel/code checks through the same003-owned reader | RECORD_INSPECTOR, WORKER_ENTRY → LINUX-PROBE-KIT-001: The fixed worker and its qualified checks through the kit-owned reader are LINUX-PROBE-KIT-001's. | — |
| S-27 | NQ:40-40 | Inert reproducible entries | SERVER, WORKER_ENTRY → LINUX-PROBE-KIT-001: The server and worker entries are LINUX-PROBE-KIT-001's; the client entry and the narrowed handoff stay with the R12 successor. | CANDIDATE_HANDOFF, CLIENT |
| S-28 | NQ:44-45 | No future packet may need an unspecified callback or edit003 to close⏎this boundary. | RECORD_INSPECTOR → LINUX-PROBE-KIT-001: The boundary is closed in LINUX-PROBE-KIT-001's inspector. | — |
| S-29 | NQ:238-240 | Fixed consumer interface in live_proxy_server.py: a pri … eck_peer(role, retained_peer)`⏎and `close()`. | RECORD_INSPECTOR → LINUX-PROBE-KIT-001: The fixed consumer interface is LINUX-PROBE-KIT-001's. | — |
| S-30 | NQ:242-243 | 004's installed worker may use the same fixed reader fo … xact installed factory and parent/FD3 guards. | WORKER_ENTRY → LINUX-PROBE-KIT-001: LINUX-PROBE-KIT-001's installed worker may use the same fixed reader. | — |
| S-31 | NQ:245-245 | No future require_server_containment callback in packet004. | WORKER_ENTRY → LINUX-PROBE-KIT-001: No such callback exists in LINUX-PROBE-KIT-001's worker. | — |
| S-32 | NQ:256-257 | Product003 must exercise the real factories through OS- … ⏎all refusal gates before server credentials. | SERVER → LINUX-PROBE-KIT-001: LINUX-PROBE-KIT-001 exercises the server's real factories through OS-mocked calls; the R12 successor exercises the client's. | CLIENT |
| S-33 | POR:32-32 | Fixed local channel consumer in live_proxy_server.py; data checks in live_mutation_admission.py | ADMISSION_MODULE, SERVER → LINUX-PROBE-KIT-001: The fixed local channel consumer and the data checks are LINUX-PROBE-KIT-001's. | — |
| S-34 | POR:33-33 | Fixed probe adapters | CASE_RECIPES → LINUX-PROBE-KIT-001: The fixed probe adapters are LINUX-PROBE-KIT-001's. | — |
| S-35 | POR:34-34 | Client/server candidate packaging and handoff | SERVER → LINUX-PROBE-KIT-001: The server candidate's packaging is LINUX-PROBE-KIT-001's; the client's and the narrowed handoff stay with the R12 successor. | CANDIDATE_HANDOFF, CLIENT |
| S-36 | POR:167-168 | CONF-LIVE-003 implements real fixed-path transport/vali … d negative tests in its existing three tests. | ADMISSION_MODULE, SERVER → LINUX-PROBE-KIT-001: The server side and admission, with their negative tests, are LINUX-PROBE-KIT-001's; the client module and its tests stay with the R12 successor. | CLIENT |
| S-37 | PCR:41-41 | Client, server, admission, three tests, one fixture and one guide | ADMISSION_MODULE, SERVER → LINUX-PROBE-KIT-001: The server and admission modules and their tests are LINUX-PROBE-KIT-001's; the client and its tests stay with the R12 successor. | CLIENT |
| S-38 | PCR:42-42 | Actual fixed probes and native observations | CASE_RECIPES → LINUX-PROBE-KIT-001: The actual fixed probes are LINUX-PROBE-KIT-001's. | — |
| S-39 | PCR:43-43 | Reproducible candidate archives and independent operator handoff | SERVER, WORKER_ENTRY → LINUX-PROBE-KIT-001: The server and worker archives are LINUX-PROBE-KIT-001's; the client archive and the narrowed handoff stay with the R12 successor. | CANDIDATE_HANDOFF, CLIENT |
| S-40 | PCR:54-56 | CONF-LIVE-003⏎implements equivalent stdlib validation i … dent negative tests in its three owned tests. | ADMISSION_MODULE, SERVER → LINUX-PROBE-KIT-001: The server and admission modules' validation and their negative tests are LINUX-PROBE-KIT-001's; the client module and its tests stay with the R12 successor. | CLIENT |
| S-41 | PCR:174-174 | CONF-LIVE-003 defines a fixed `NativeProxyServer()` factory and `main()`; | SERVER → LINUX-PROBE-KIT-001: LINUX-PROBE-KIT-001 defines the fixed server factory and main. | — |
| S-42 | PCR:176-176 | CONF-LIVE-005 packages a separate fixed entry point that invokes that main: | SERVER → LINUX-PROBE-KIT-001: LINUX-PROBE-KIT-001 packages the server's fixed entry point. | — |
| S-43 | PCR:190-191 | The new server⏎checks are owned only by CONF-LIVE-003. | SERVER → LINUX-PROBE-KIT-001: The new server checks are owned by LINUX-PROBE-KIT-001. | — |
| S-44 | PCR:226-227 | Only preinstalled fixed CONF-LIVE-004 adapters may subm … selected from the server-owned signed profile | WORKER_ENTRY → LINUX-PROBE-KIT-001: Only LINUX-PROBE-KIT-001's preinstalled fixed adapters may submit such a manifest. | — |
| S-45 | PCR:307-313 | CONF-LIVE-003 must independently cover every closed nested object | ADMISSION_MODULE, SERVER, UID_LEDGER → LINUX-PROBE-KIT-001: Each listed case is covered by the owner of the code it exercises: the server, admission, UID-ledger and cleanup cases by LINUX-PROBE-KIT-001, the client's cases by the R12 successor. | CLIENT |

These rules govern the table:
- **The gate documents** TLC and COR are superseded by quote only and never edited.
- **The KAP leg** only ever appears alone in a row, with `movedTo` `DEFERRED_UNOWNED`.
- **HS53.** No quote overlaps an HS53 supersedes quote in the same file. The HS53 record is bound by sha256 in
  `crossInputs`, and it is the one file the model reads beyond the record's own rows.
- **Unquoted cells.** On a quoted row, the row's unquoted constraint and prohibition cells stay true.
  - A cell that describes a moved item binds that item's new owner, LINUX-PROBE-KIT-001.
  - A cell that describes a kept item binds R12_SUCCESSOR. That applies on every row with `keptItems`, which are,
    generated from the record:
    PCA:253-253 (S-07, CLIENT);
    PCA:253-253 (S-08, CLIENT);
    TLC:477-478 (S-09, CLIENT);
    TLC:479-480 (S-10, CLIENT);
    BH:37-37 (S-15, CANDIDATE_HANDOFF, CLIENT);
    BH:95-95 (S-18, CLIENT);
    BH:251-253 (S-20, CLIENT);
    BH:253-255 (S-22, CLIENT);
    COR:122-127 (S-23, CLIENT);
    NQ:38-38 (S-25, CLIENT);
    NQ:40-40 (S-27, CANDIDATE_HANDOFF, CLIENT);
    NQ:256-257 (S-32, CLIENT);
    POR:34-34 (S-35, CANDIDATE_HANDOFF, CLIENT);
    POR:167-168 (S-36, CLIENT);
    PCR:41-41 (S-37, CLIENT);
    PCR:43-43 (S-39, CANDIDATE_HANDOFF, CLIENT);
    PCR:54-56 (S-40, CLIENT);
    PCR:307-313 (S-45, CLIENT).
- **completion-integration.json.** Its `effectivePredecessors.CONF-LIVE-004` entry is superseded through `amends`.
  `docs/alpha-2/COMPLETION_INTEGRATION.md`'s lines 258-261, which restate that rule, are superseded through the same
  entry. The guide is a named living catalog.
- **LBRM, BHA and NQA** are succeeded only for the ownership of moved items, so their `supersededEntries` are empty.

## Statements that stay true

No quote may overlap these 12 spans. The model holds them as a fixed table.

| Pinned text | Quote that stays true (in full) |
|---|---|
| PCA:253-253 | and final hook remain with CONF-LIVE-004/005/006 |
| TLC:478-479 | preserve all 127 predecessor files and⏎279 test IDs |
| TLC:480-480 | and CONF-LIVE-006 the already-bounded final hook |
| BH:40-42 | Existing product paths remain exact: 003 has eight, 004 six, 005 five and 006⏎five additions plus its already-approved final launcher-hook edit. Stages remain⏎110/120/127/135/141/146/151. Every product command set remains eight commands. |
| COR:102-103 | CONF-LIVE-003 still owns its exact eight paths and all eight cumulative⏎commands |
| NQ:43-44 | Exact product paths/stages110/120/127/135/141/146/151 and all eight commands are⏎unchanged. |
| POR:168-169 | Its own fixture⏎pins this authority and the unchanged 127-file/279-ID baseline. |
| PCR:191-191 | No new root key or signature role. |
| PCR:41-41 | eight existing paths |
| PCR:42-42 | in six existing paths |
| PCR:43-43 | in five existing paths |
| PCR:56-57 | It must pin this authority⏎and preserve the immediate 127-file/279-ID baseline in its owned fixture. |

## Not amended

Every entry is an exact path, each with its base sha256 and a class whose path rule it meets.
- **`pinned`** (byte-identical at the era): 32 `MERGED_PACKET_YAML`, 10 `CLOSED_RECORD`, 1 `INPUTS_PINNED` and 4
  `LINEAGE_GUIDE`.
- **`named`** (governed, not byte-checked): 9 `LIVING_CATALOG`, 1 `HISTORY_SNAPSHOT`, 19 `INPUTS_SNAPSHOT`,
  16 `ROUND_SNAPSHOT`, 3 `REVIEW_RECORD`, 92 `AUTHORITY_TEXT` and 23 `RECORD_EMBEDDED_TEXT`.

**The class path rules,** in precedence order:
1. `INPUTS_PINNED`: `architecture/broker-handoff-inputs/*`, one level only. A path below
   `architecture/broker-handoff-inputs/` deeper than one level has no class. This is decided here, before rules 2-10,
   so it holds whatever the later segments are: `…/broker-handoff-inputs/round1/x.json` has no class, not
   `ROUND_SNAPSHOT`.
2. `ROUND_SNAPSHOT`: `architecture/*/round*/**`.
3. `REVIEW_RECORD`: `architecture/**/review-round*.json`.
4. `AUTHORITY_TEXT`: `architecture/*-authority.json`.
5. `INPUTS_SNAPSHOT`: `architecture/*-inputs/**`, except `architecture/broker-handoff-inputs/` (rule 1).
6. `HISTORY_SNAPSHOT`: `docs/history/*`.
7. `MERGED_PACKET_YAML`: `task-packets/*.yaml`.
8. `LINEAGE_GUIDE` and `LIVING_CATALOG`: their listed paths.
9. `CLOSED_RECORD`: its listed paths.
10. `RECORD_EMBEDDED_TEXT`: any other `architecture/*.json`.

## The predecessor table

| Item | After |
|---|---|
| EVOLUTION_SURFACE_GATE_PACKET (slot 261) | MET-LIVE-002 |
| LINUX-PROBE-KIT-ADMISSION | MET-LIVE-002, EVOLUTION_SURFACE_GATE_PACKET |
| LINUX-PROBE-KIT-001 | LINUX-PROBE-KIT-ADMISSION, NEUTRAL_INTERFACE_CONTRACT |
| R12_SUCCESSOR | MET-LIVE-002, NEUTRAL_INTERFACE_CONTRACT |
| CONF-LIVE-006 | LINUX-PROBE-KIT-001, R12_SUCCESSOR |

The three placeholders are each bound later:
- `NEUTRAL_INTERFACE_CONTRACT` by its sha256;
- `EVOLUTION_SURFACE_GATE_PACKET` by its packet id;
- `R12_SUCCESSOR` by R12's lane.

`R12_SUCCESSOR` is one unsplit placeholder, and this record fixes no split of R12's work.

## The inventory

**The declared search.**
- It runs over `docs architecture task-packets`, excluding `architecture/enforcement-test-plan`,
  `docs/alpha-2/ENFORCEMENT_TEST_PLAN.md`, `architecture/artifact-edges` and `tools`.
- **Candidate files** are the union of two `git grep -l -E` runs at the commit:
  - `CONF-LIVE-00[345]`;
  - `(^|[^[:alnum:]_./:-])00[345]([^[:alnum:]_]|$)|(packet|packets|edit|Product|product|same|Native)00[345]`.
- Each candidate's bytes come from `git show <commit>:<path>`, decoded as UTF-8 and split on `\n`.
- **A hit** is any of these:
  - a line matching `CONF-LIVE-00[345]`;
  - a line matching the standalone short form `(?<![\w./:-])00[345](?!\w)` or a glued form, if its paragraph holds a
    long-form id or a glued form. A paragraph is the maximal non-blank run in `.md` files, and the line itself elsewhere;
  - any short-form line in a `supersedes` file.

At the base the search finds 278 files and 2,423 hit lines. Its `searchDigest` is the sha256 of the compact JSON hit list
`[[path, line], …]`, ordered by path and line.

**File-level dispositions.** A `notAmended` file is `PINNED` or `NAMED` as a whole.

**Line-level dispositions.** Every hit line of a `supersedes` file, and of a file in no class, has exactly one of:
- `QUOTED`: inside a `supersedes` row's lines;
- `UNCHANGED_TRUE`: it assigns only kept items, or a path, stage or command grant that stays true;
- `NOT_OWNERSHIP`, with a reason:

  | Reason | Applies to |
  |---|---|
  | `STATUS_LINE` | status tables, checkpoints, progress narrative and process prohibitions |
  | `REVIEW_HISTORY` | finding ids and quotations of other documents |
  | `IDENTIFIER_INDEX` | index lines |
  | `DIGEST_PIN` | digest rows |
  | `ORDERING_PREREQUISITE` | "before CONF-LIVE-00x" gates |
  | `STAGE_OR_COUNT` | stage rows inside records |

**The model and the layer read only the recorded paths, at the base, with `git show`.** No listing is used.

**The build gate.** At the mechanics base M, the build:
1. Runs the search.
2. Refuses if any `supersedes`, `amends` or `pinned` path has a different sha256 at M.
3. Covers by class any hit in a recorded `named` file or a named class path.
4. Covers a hit in a recorded line-disposition file only if that file's sha256 is unchanged.
5. Reports every other hit, with a disposition from this vocabulary, in the pre-check report.
6. Refuses any hit that fits no disposition or assigns a moved item.

The adopted record is not changed. The report's list is reviewed in the packet review.

**The changed files.** The model refuses these among the packet's changed files:
- any `supersedes`, `amends`, `pinned` or `crossInputs` path, compared case-folded (BUILD_RULES S3-7);
- any gate path.

`gate_paths` must be the changed files the caller has already matched against the evolution-surface record's gate rules,
which are prefix and under-plus-name rules, case-folded.

**The registry rider.** Under the owner's 2026-10-23 registry decision ("Batch, carried by 260"), packet 260 also
carries the review-record brief registry batch:
- `architecture/review-record/briefs.json`;
- `architecture/review-record/REVIEW_BRIEF_PACKET.md`;
- `architecture/review-record/REVIEW_BRIEF_CONTRACT.md`.

These three exact paths are gate material, and they are not the scope contract's changed files. The layer checks four
things:
- it holds them as one exact constant;
- they are among the packet's changed files;
- they are exactly the gate paths among those files;
- the model, run on the changed files minus these three paths, returns no refusal.

**The layer.** It pins the adopted `amendment.json` by sha256, so a dropped or added row also fails at verify time.

## The fixed values

These values are fixed by the design and the build rules, and the model checks each one. Every other value comes from
`amendment.json`.

**Each moved item's `fromPacket`:**

| Item | fromPacket |
|---|---|
| `ADMISSION_MODULE` | CONF-LIVE-003 |
| `CASE_RECIPES` | CONF-LIVE-004 |
| `RECEIPT_CANDIDATES` | CONF-LIVE-004 |
| `RECORD_INSPECTOR` | CONF-LIVE-003 |
| `SERVER` | CONF-LIVE-003 |
| `UID_LEDGER` | CONF-LIVE-003 |
| `WORKER_ENTRY` | CONF-LIVE-004 |

**The deliverable status tokens:** `KEPT_R12` and `SUPERSEDED_UNACCEPTED_HISTORY`.

**The six `unchanged` ids:** `CONF_LIVE_006_PATHS`, `INSTALLED_IDENTITIES`, `ROLES`, `SIGNING_DUTIES`, `WIRE_AND_BINDING`, `WORKER_ENTRY_NAME`.

**The deferred row:** item `KAP_LEG`, status `DEFERRED_UNOWNED`, authority `Q-LPK0-3`, source clauses `BH:210-214`, `BH:35`, `PCR:207-225`.

**The class lists** (S3-10):
- `LINEAGE_GUIDE`: `docs/alpha-2/CONFORMANCE_COMPLETION.md`, `docs/alpha-2/CONFORMANCE_PUBLICATION.md`, `docs/alpha-2/LOCAL_ACCEPTANCE_REVALIDATION.md`, `docs/alpha-2/SUCCESSOR_CHECKPOINT_REPAIR.md`.
- `LIVING_CATALOG`: `docs/DEVELOPMENT_STATUS.md`, `docs/MASTER_DEVELOPMENT_PLAN.md`, `docs/READINESS_INDEX.md`, `docs/adr/0004-sol-high-packet-boundary.md`, `docs/alpha-2/COMPLETION_INTEGRATION.md`, `docs/alpha-2/LIVE_BACKEND_READINESS.md`, `docs/repositories/00-harness-engineering.md`, `docs/repositories/12-mas-harness-conformance-labs.md`, `task-packets/README.md`.
- `CLOSED_RECORD`: `architecture/backend-timing.json`, `architecture/broker-handoff-amendment.json`, `architecture/completion-integration.json`, `architecture/conformance-completion.json`, `architecture/conformance-publication.json`, `architecture/live-backend-roadmap.json`, `architecture/local-acceptance.json`, `architecture/native-qualification-amendment.json`, `architecture/proxy-diagnostics.json`, `architecture/unified-roadmap-backlog.json`.

**The declared search,** as `inventory.patterns` and `inventory.pathspecs` hold it, at base
`2043cc27883448e3ff030b7868110e295f32fe09`.

## The record's closed shape

Every member and row type is closed, and every list is sorted, with two exceptions:
- `inventory.pathspecs` keeps the declared search's order;
- `staysTrue` sorts by (path, `lines` as text, quote), so PCR's `191-191` comes before `41-41`.

Every member has an exact type, with bool and int kept apart (0 is not false). Three kinds of value have fixed forms:
- `lines` is `a-b`, two unpadded positive integers joined by one hyphen, with no spaces;
- a sha256 is 64 lowercase hex digits;
- `base`, `inventory.commit` and a retired packet's `head` are 40 lowercase hex digits.

The model checks all of this before any other check. A member of the wrong type or form refuses with the shape text
alone. A `lines` range in the right form but reversed (`133-132`) passes the form check, and is refused instead by the
quote check, together with the fixed-table and disposition texts it then triggers.

| Member | Row members | Sorted by |
|---|---|---|
| top level | `amends, base, crossInputs, deferred, dispositions, effectivePredecessors, inventory, moved, notAmended, ownerDecisions, packet, retained, retiredHistory, schemaVersion, slot, staysTrue, supersedes, unchanged, workItem` | — |
| `ownerDecisions` | `id, quote, section` | (id, quote) |
| `crossInputs` | `path, sha256` | path |
| `amends` | `packet, path, sha256, supersededEntries` | path |
| `dispositions` | `deliverables, disposition, packet, text`; deliverables `deliverable, status` | packet; deliverable |
| `moved` | `fromClauses, fromPacket, item, items, status, to` (`fromClauses` and `items` sorted) | item |
| `retained` | `item, packet, text` | item |
| `deferred` | `authority, item, sourceClauses, status, text` | item |
| `unchanged` | `id, text` | id |
| `retiredHistory` | `branchModified, dispatchable, head, id, pr, status` (MET-REPAIR-018's `retiredPacket`) | id |
| `supersedes` | `id, lines, path, quote, replacement, sha256`; replacement `keptBy, keptItems, movedItems, movedTo, text` | (path, first line, quote); ids S-01.. in that order |
| `staysTrue` | `lines, path, quote` | (path, lines, quote) |
| `effectivePredecessors` | `edges, placeholders`; edges `after, item` (`after` sorted) | item |
| `notAmended.pinned`, `.named` | `class, path, sha256` | path |
| `inventory` | `commit, files, pathspecs, patterns, searchDigest`; `patterns` holds exactly `ereLong, ereShort, glued, long, standalone`, each a string | — |
| inventory file rows | `PINNED` or `NAMED`: `class, disposition, hitLines, path, sha256`; `LINES`: `disposition, hitLines, lines, path, sha256` | path |
| line rows | `disposition, line`, plus `reason` for `NOT_OWNERSHIP` | line |

**What the fields mean:**
- `base` is the base commit.
- A supersedes row's `id` is its position.
- `LINES` marks a file given line-level dispositions: a `supersedes` file, or a hit file in no class.

**The fixed tables.** The model holds these as exact tables. They are the ones the design and the build rules fix:
- the 45 supersedes rows' (path, lines, quote digest, moved items, kept items);
- the 12 stays-true spans;
- the four amends rows;
- the five predecessor rows;
- each moved item's `fromPacket`;
- the deferred row's authority (Q-LPK0-3) and its source clauses;
- `base`, `inventory.pathspecs` and `inventory.patterns`.


## Reader duties

- **R12_SUCCESSOR** narrows CONF-LIVE-004 and 005 and keeps the client. It cites this record.
- **LINUX-PROBE-KIT-ADMISSION and LINUX-PROBE-KIT-001** cite this record for the items they own.
- **The neutral interface contract** defines the interface between the kit and R12's client.
- **Owner decisions.** This record quotes them in `ownerDecisions`, each checked at the contract build to occur exactly
  once within its dated section of the lane's decision record. The repository model checks only their shape.

Adoption is recorded in status.json, not here.

The review history is published in this directory as `review-history-<kind>-r<n>.json`, with its briefs as
`review-history-<kind>-r<n>-brief.md`. These are redacted records from before review-record v2. They are not
`review-round*.json` records and carry no merge authority. This packet's merge authority is its own v2
`MET-LIVE-002/packet` series.
