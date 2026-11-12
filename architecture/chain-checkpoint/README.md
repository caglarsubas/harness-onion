# The chain checkpoint (CHAIN-COMPACTION-002, G1): MET-PERF-047

This directory holds the signed checkpoint's ledger (`record.json`, written at slot 282's final commit) and its
vectors (`vectors.json`). The shadow reader is `ci/chain_checkpoint.py`; the lane-run writer is
`scripts/chain_checkpoint_writer.py`.

**G1.** Every layer above the newest checkpoint is re-executed in full on every verify. A layer at or below it was
re-executed when the checkpoint was written, and since then the ledger attests it:
- the ledger holds the layer's validator, test file, authority and captured inputs at the checkpoint tree, with its
  nodes' outcomes;
- every run rebuilds those files from the live tree and compares them;
- a head-seeded sample of the attested layers is re-executed too.

**MET-PERF-047 is shadow-only.** Every verify still runs everything in full.
- The reader only observes and records: it never changes a session's outcome.
- A missing or failing reader prints one class-C line and changes nothing.
- The sampled mode, which skips work, is MET-PERF-048's. It comes after a clean shadow period and bundle v8.

**The owner's numbers:** a new checkpoint every 10 slots (earlier on the owner's word); sample fraction f = 0.10; a full
run between checkpoints only on an owner-named slot; N_shadow = 10 consecutive clean shadow verifies, with a rewrite
inside the period; the reader capped at 15 s per run.

## The ledger (`record.json`, schema `harness.planeon.ai/chain-checkpoint/v1`)

Every digest is at the checkpoint tree.
- **The checkpoint:** `schemaVersion`, `checkpointSlot`, `checkpointBaseline`, `writingCommit` and `writingTree`.
- **`parameters`:**
  - `cadenceSlots`, `sampleFraction`, `fullRunOn`, `nShadow`, `shadowCapSeconds` and `workers`;
  - `shadowIn`: "verify", or "dryRunOnly", which the lane sets as the runner of the writing run.
- **`normalisedRecordClass`:** true when the capture names an index record.
- **`layers`:** one entry per attested layer. Each holds:
  - `slot` and `module`;
  - `validatorPath` and `validatorSha256`; `testFilePath` and `testFileSha256` (where a name-matched test exists);
    `authorityPath` and `authoritySha256`;
  - `inputs`, {path: sha256};
  - `nodes`, [{nodeSha256, setup, call, teardown}];
  - `seconds`.
- **`checkPairs`:** [{layerSlot, pairsPath, ids [a, b], type}]; the only ruled type is `supersession`.
- **The writing run:** `fullRunProof` {collected, executed, deselected, attested}, then `writingRun` {statedDifferences,
  captureEnv, captureObservesOnly, outsideReads, argvRunSummarySha256, verifyReference}.
- **The size:** `sizeBytes`, the file's own length, and `sizeBound`.
- **`exclusion`** {files, pinLine} (MON-282-W2-RULED): the step's own products, never a layer's input. `files`
  names the step's authority, its hunk-class record and `record.json`, sorted, each path once; `pinLine` names the
  head validator, attested with its one `AUTHORITY_SHA256 = "…"` line read as
  `AUTHORITY_SHA256 = "TO_BE_PINNED_AFTER_SOURCE_FREEZE"` (`pin_normalised`), since the pin is filled after the
  ledger is written. The exclusion equals the bounded build's write set. When it is present, `check_ledger` checks
  its shape and that no layer's `inputs` names an excluded file.

## The reader's interface and its record

- **The interface:**
  - `Reader(root, clock, cap, tree, in_dry_run)`, with `.start()`, `.report(nodeid, when, outcome, duration)` and
    `.finish(head_sha=None) -> (summary line, record)`;
  - `rebuild`, `sample`, `naming_authority`, `newer_authorities`, `check_ledger`, `head_slot`, `entry_fault`,
    `attach_classes`, `unauthored`, `check_pairs`, `bind_context` and `pin_normalised`, and `RULES_BY_SHA`;
  - the CLI `chain_checkpoint.py dry-run-compare LOG OUT`.
- **What a session prints:** the root conftest prints the summary line and the record as one
  `chain-checkpoint shadow record:` JSON line.
- **The record's members:**
  - `headSha`, `readerSeconds`, `capSeconds`, `overCap`, `workers` and `workersSource`;
  - `mode` ("compare", "dry-run-only: skipped" or "inactive") and `shadowIn`;
  - `naming`, `attested` and `sampled`;
  - `layers` {slot: {recorded, live, agree, writingSeconds, liveSeconds}};
  - `reverted` {slot: [[path, [[authority, {class: count}]]]]};
  - `unauthored` [paths]: attested files whose only miss is at their newest recorded step (P047-C3-4);
  - `disagreements` [{slot, where, class, kind, countEffect, detail}]: `kind` and `countEffect` from the countEffect
    table below; a class-C record's `slot` is the head's chain slot.
- **The record line's size** grows with the attested nodes: about 150 bytes per node (its recorded and live outcomes)
  and about 140 per disagreement. W measures it on the writing run and the packet record states it; the conftest
  writes the line whole, in a loop (P047-C2-8).

**How the reader rebuilds.**
- It replays, newest first, only the published `reverseHunks` of the authorities newer than the checkpoint. The apply
  is byte-exact, with each file's `afterSha256` and `beforeSha256` checked. It never uses git history.
- Every authority keeps v2.1's eight-member form and three-key hunks (the owner's MON-LPK1-B6-P1). A classed
  authority's classes live in its **hunk-class record**, `architecture/chain-checkpoint/hunk-classes/<slot>.json`
  (MON-282-W1-A2), one per classed authority from 282 on and none for older ones. It holds exactly `authorityPath`,
  `hunkClassVocabulary`, `hunkClassRuleSha256`, `hunkClassContext` and `classes` ({path: one class per reverse hunk,
  in the authority's order}). It is an ordinary new file of its step: the classed authority's own `newFiles` names
  it by sha256, and the head pins the authority, so the record is bound by sha256 with no hash cycle.
- Each changedFiles entry's shape is checked first (`entry_fault`; a broken entry is corrupt). The authority's
  hunk-class record is bound next, before any class is trusted: the authority's `newFiles` names exactly one, its
  bytes hash to the named digest, and its `authorityPath` is the authority's. A record that is missing, unnamed,
  digest-mismatched, malformed, miscounted or duplicated, or an authority that carries classes itself, is class A,
  kind input, as is a bad context, and so is a named record that is a link, not a file, or unreadable (an unnamed
  one changes nothing). Each class is re-checked by position by the rule the record names: `hunkClassRuleSha256`
  picks chainmech v2.2's, v2.3's, v2.4's or v2.5's (`RULES_BY_SHA`; the reader holds v2.3's, v2.4's and v2.5's copies, and v2.2's is
  v2.3's with `register` off; MET-PERF-049), any other digest is class A, and `hunkClassVocabulary` must be that rule's vocabulary. A
  reordered record is class A.
- A reverse hunk that carries a `class` member is checked as an entry first: a class that is not a string is a
  broken entry (corrupt); otherwise the authority carries classes itself (class A, kind input).
- It undoes only `cascade`, `bridge` and `register` hunks, plus `record` when `normalisedRecordClass` is true.
  `register` (chainmech v2.3, decided only where v2.2 says `other`, once per file) is a step's own registration: in
  `scripts/validate_readiness.py`, the new packet's ownership block, with its product lines, right after the
  previous packet's task-packets line; in `docs/MASTER_DEVELOPMENT_PLAN.md`, one open status line ticked plus one
  new open line naming the new packet.
- Rebuilt bytes are compared, never executed.
- An in-run budget stops the replay at the cap: class C, kind over-budget. A finished reading over the cap is kind
  over-cap.

**The read order (PKT1-READ-ORDER).** `start()` reads, in this order:
1. the ledger's bytes (none: the reader is inactive), then the budget's first check;
2. every authority, parsed once (a malformed one is corrupt);
3. the naming verdict (unnamed or stale: class A, kind stale, and the reading stops);
4. the ledger as JSON, then its slots (the head slot from here on), then `check_ledger`;
5. the newer authorities (one per slot), with their hunk-class records;
6. the dry-run-only skip;
7. each layer's files, newest slot first, rebuilt and compared;
8. `checkPairs`, then the sample.

Until step 4 sets it, the head slot is null: a budget stop, a failing clock or a malformed authority before then
is recorded with slot null and a detail ending "head slot unknown (the ledger was not read)".

With no ledger the reader is inactive and writes no record: `finish()` returns (None, None). In a written record,
`mode` is "inactive" when the reading stops before the compare (a stale or unnamed ledger, a corrupt ledger or
authority, or the budget before step 6).

**Classes, kinds and the stop rule (MON-282-C23, MON-282-QC31).** This countEffect table is the single source: the
record's `kind` and `countEffect`, `vectors.json` and the contract cite it, and the reader's `COUNT_EFFECT` mirrors it
(the module tests pin the two equal).

| kind | class | countEffect | cause |
|---|---|---|---|
| input | A | restart | an attested file differs after normalisation; unauthored when its only miss is at its newest recorded step |
| stale | A | restart | the record is unnamed, or named with another digest (vector 2) |
| outcome | B | restart | a node's outcome differs with no input change |
| corrupt | C | restart | the ledger (a member `check_ledger` names), an authority that does not parse, is not an object, or whose `baselinePackets`, `changedFiles` or `newFiles` is not an object, a `changedFiles` entry `entry_fault` rejects, or two newer authorities sharing a baseline or an `authorityPacket` (the detail names both); the detail names the file and the member; an authority is read before the ledger, so its refusal's slot is null |
| over-budget | C | restart | the in-run budget stopped the replay at the cap |
| over-cap | C | restart | a finished reading took longer than the cap |
| fault | C | restart | any other exception of the reader, and a failing clock (one record per reading: "the clock failed") |
| skipped | C | neutral | a dry-run-only reading, skipped in session |
| demoted | — | neutral | an attested input changed by authored, replay-verified edits that land exactly on the checkpoint digest; the layer runs live until the next rewrite (MET-PERF-049) |
| demoted-outcome-explained | — | pending isolation | a demoted layer whose live outcome differs from the record, with a matching outcomeStatements entry; the count advances only when the isolation record reads PASS (E1) |
| agree | — | count | a reading with no disagreement |

- A kind is set by cause, never by an exception's type.
- A detail names the ledger as "ledger" (`ledger layers[0].slot`, `ledger checkPairs[0]: …`) and an authority by
  its path.
- `COUNT_EFFECT` holds the disagreement kinds. An agree is not a disagreement, so it is not among them; it counts.
- A class-C record's `slot` is the head's chain slot: `checkpointSlot` plus the authorities newer than the checkpoint
  by baseline (one authority per slot: their baselines and `authorityPacket`s are distinct, or the reading is
  corrupt), or null when the ledger was not read or its slots are malformed. A fault's or a corrupt record's detail
  names its exception class; every class-C detail names the head slot and the checkpoint slot (a skip, an over-budget
  and an over-cap record name their reason). A class-A or class-B record names the layer's slot; the stale record has
  no layer, so its slot is null.
- A skip still writes its record, with the reason and the slots; one authority per slot is checked before it.
- The head slot's message names why it is unknown: the ledger was not read, is not JSON, is not an object, or its
  slots are malformed. The reader has no other source for the verify's own slot: the lane monitor compares the
  shadow record's head slot with the verify record whenever it reads a result (MON-282-CR5-CLOSE).
- The vector-11 module test runs in every verify and fails on any malformed authority file in `architecture/`, as
  the chain's own validators, which parse every authority, already do (P047-C5-6).
- Any three skips, or any three faults, within the period are a finding to the lane monitor, not only consecutive ones (MON-282-CR4-KEEP replaces MON-282-C23's "consecutive": skips stretch the period, consecutive or
  not). They are counted across verify
  records by the monitor and by MET-PERF-048, which carries their vector: no reader sees more than one session. A reader
  that keeps faulting is a ci/ defect, not a reason to re-run the period.
- A dry-run-only reading by the dry-run runner counts toward N_shadow; a skipped in-session reading does not.
  MET-PERF-048 states that rule.

**Where the reader is active.** In every outermost pytest session over a tree whose record exists: argv 63 of a verify
or a dry run, each per-file session of the pre-check, the weights measurement, and any outermost session a script
starts. Each is shadow-only.

**The writing run's two stated differences**, always given together:
1. Argv 63 runs directly, with the capture plugin.
2. It runs serial: the `-p` option keeps the parallel suite's serial loop, where the verify runs 12 workers.

The owner's approval for 282 names both. An outcome that differs between that run and the 12-worker verify 0 is
attributed to them first, and is class A only if the input set explains it.

**The workers note (MET-PERF-049).** WORKERS is 12 from slot 286 (8 before), the count the reader reads from
`ci/parallel_suite.py`. The trade-off: during a verify's suite phase, 12 of the host's 18 cores (6 performance, 12
efficiency) are busy with test workers, against 8 before, so other sessions on the host and the Ollama service slow
down for those minutes; in exchange argv 63's wall is about 94 s shorter, measured on a quiet host (the worker trial
v3, K12 against the mean of two K8 arms).

**Capture gaps:** opens by subprocesses, and files read through memory maps already open, are not seen. Process-level
caches (a module imported, or a file read into an lru cache, by an earlier node of the serial run) are charged only to the
first node that read them.

## MET-PERF-049 (slot 286): the rewrite, the class cache, class rule v2.4, the demotion, MET-PERF-048's provisions

**The ledger freeze.** Schema v1 is frozen at 286; any later member means a rewrite (VIS-048-READ).

**The rewrite.** The second checkpoint is written at 286 by a full G0 run (condition (i)) and attests layers 189-285. Its
authority names `record.json` in `changedFiles` in the plain three-key form `{beforeSha256, afterSha256, reverseHunks}`,
with the writer's 1,974 line-run reverse hunks inline (CONTRACT_286 erratum 8, the inline form); no side record exists.
The slot's hunk-class record gives `record.json` the class "other" for every hunk (V6a). The writer can still build a
side record (`check_ledger_hunks`, vectors 28-35), which binds nothing (errata 8 and 10). `record.json` is in the
exclusion, so the reader never replays it.

**Class rule v2.4** (`RULE_V24_SHA256`, `classify_v24`):
- R1, member forms: F1, one `successor...NEW_PACKET` chain (K = 0 only); F2, that chain followed by the
  `*successor...PRODUCT_PACKETS` chain (K >= 1 only); F3, an id line gains the new id, then at K >= 1 the authority's
  product ids in the key order of its `productPackets`. Anything else is other.
- R2, digit moves: cascade only for declared pairs: the catalog pair `(n, n + steps[1])`, n the authority's own
  baselinePackets size, and the context's `countPairs`. A real edit whose numbers equal a declared pair stays cascade:
  the stated limit (vector 17).
- W, the weights file: an insert of entries keyed by the step's own new test files is record; a re-measure or a duplicate
  key is other.
- A v2.4 record's context has exactly five keys (`countPairs` added), and its member set is six (`outcomeStatements`
  added). `attach_classes` picks the set by the record's own rule digest before it checks the members.

**The class cache.** L1, per session, the classes of one authority's hunks on one path, keyed by (the authority's
sha256, path), filled only by a completed ordered pass; a hit still runs the afterSha256 gate and the byte checks. L2,
inside one Reader invocation whose newer-authority set is fixed at start, one rebuild per (path, live sha256), filled only
after the afterSha256 gate. Nothing outlives the invocation (PERF-028/029, Q-PERF40-2). A cached and an uncached reading
write byte-equal records (vector 26, under a constant clock).

**The demotion (OQ-048-1 (b)).** When a path's only unexplained entry is "n of m hunks of a class not normalised", the
replay continues: every newer authority on the path, newest first, gates kept, all its hunks undone, its beforeSha256
checked, to the attested digest. On an exact landing every layer attesting the path is demoted (neutral) and runs live;
any other outcome is class A. A demoted layer's changed outcome is "demoted-outcome-explained" (pending isolation) only
with a matching outcomeStatements entry of the authoring v2.4 record; otherwise class A. The record carries `demoted`
(slot, path, authority, liveSeconds), `attestedFraction` and the explained events (`isolation`).

**The mode of record and MET-PERF-048's provisions.** MODE is the default mode. The G1 module `ci/chain_checkpoint_g1.py`
is loaded only when present (P-048-1); only then is the verifier's signal file read (P-048-3), at
`$HOME/.planeon/chain-checkpoint-g1-signal.json`, under these rules: opened without following a link, checked by fstat
(a regular file, uid 0, no group or world write bit, nlink 1, at most 4,096 bytes), at most 4,097 bytes read, I-JSON
with exactly `ledgerSha256`, `g1ModuleSha256` (64 hex), `head` (40 hex, equal to the checkout's HEAD) and `bundleId`. An
unset HOME or an absent file leaves the run in shadow mode with no record; a failing check is shadow plus one class C
record naming it. The mode of record is the verifier's declaration plus the module's presence. The writer refuses
while the file is present (P-048-4). The root conftest's collection hook calls the reader's selection entry point only
when the reader exposes one (P-048-2). At 286 the module is absent, so everything here is inert.

**Non-claims.**
- 047 saves no verify time: it adds at most 15 s.
- The completeness of a captured input set is not claimed. Shadow mode measures it.
- Nothing is claimed about any other repository.

## MET-007 (slot 288): class rule v2.5

**Class rule v2.5** (`RULE_V25_SHA256`, `classify_v25`; CONTRACT_288 rev 4 section 8.1), the block after v2.4's in
the reader, is `classify_v24` with two counted changes, so that its member forms read the K >= 1 forms the chain
tools write:
- C1, the product chain: F2's `*...PRODUCT_PACKETS` chain takes its optional receiver after the star, then at least
  one `successor.` (`*profile.successor...PRODUCT_PACKETS`, the deepen tool's form), and ends where its element ends
  (a comma or a closing bracket follows). The receiver-less form still matches; a receiver that no successor chain
  follows, or a chain that continues past its element, stays other.
- C2, the bridged loop (K >= 1 only, and only when the hunk's before-lines hold no such loop): each run `in (N, N, P)`
  of its after-lines (the keyword `in`, with no name character, ASCII or not, and no dot before it; N a
  `successor...NEW_PACKET` chain, P a v2.5 product chain) reads back as `== N` before the rest test and the F2 cut
  decide the hunk, which must still reduce exactly; F3 is not tried in a hunk where a run was read back. v2.4's K = 0
  case is unchanged.
- Era binding, by the slot the reader counts: `newer_authorities` takes `ckpt_slot` (the Reader passes the ledger's
  `checkpointSlot`) and gives each newer authority its slot, `ckpt_slot` plus its 1-based rank by ascending baseline,
  as `head_slot` counts. `attach_classes` refuses unless the record is named exactly `<slot>.json` and names
  `RULE_V25_SHA256` if and only if slot >= `V25_FROM_SLOT` (288), and it refuses when no slot is given (fail closed):
  a chosen file name never picks its own era. Records 282 to 287 keep the rule they carry. `RULES_BY_SHA` holds v2.5
  as (CLASSES, register), and a v2.5 record has v2.4's six members and five context keys. Over 286's and 287's
  records (K = 0 contexts, where v2.5's path is v2.4's) v2.5 gives exactly their recorded classes.
