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

## The reader's interface and its record

- **The interface:**
  - `Reader(root, clock, cap, tree, in_dry_run)`, with `.start()`, `.report(nodeid, when, outcome, duration)` and
    `.finish(head_sha=None) -> (summary line, record)`;
  - `rebuild`, `sample`, `naming_authority`, `newer_authorities`, `check_pairs` and `bind_context`;
  - the CLI `chain_checkpoint.py dry-run-compare LOG OUT`.
- **What a session prints:** the root conftest prints the summary line and the record as one
  `chain-checkpoint shadow record:` JSON line.
- **The record's members:**
  - `headSha`, `readerSeconds`, `capSeconds`, `overCap`, `workers` and `workersSource`;
  - `mode` and `shadowIn`;
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
- Each authority's `hunkClassContext`, `hunkClassVocabulary` and `hunkClassRuleSha256` are bound first. Each recorded
  class is re-checked by chainmech v2.2's rule.
- It undoes only `cascade` and `bridge` hunks, plus `record` when `normalisedRecordClass` is true.
- Rebuilt bytes are compared, never executed.
- An in-run budget stops the replay at the cap: class C, kind over-budget. A finished reading over the cap is kind
  over-cap.

**Classes, kinds and the stop rule (MON-282-C23, MON-282-QC31).** This countEffect table is the single source: the
record's `kind` and `countEffect`, `vectors.json` and the contract cite it, and the reader's `COUNT_EFFECT` mirrors it
(the module tests pin the two equal).

| kind | class | countEffect | cause |
|---|---|---|---|
| input | A | restart | an attested file differs after normalisation; unauthored when its only miss is at its newest recorded step |
| stale | A | restart | the record is unnamed, or named with another digest (vector 2) |
| outcome | B | restart | a node's outcome differs with no input change |
| corrupt | C | restart | the ledger, an authority (it does not parse, is not an object, or a member is malformed), a `reverseHunks` entry or a `checkPairs` entry is malformed, naming the file and the member |
| over-budget | C | restart | the in-run budget stopped the replay at the cap |
| over-cap | C | restart | a finished reading took longer than the cap |
| fault | C | restart | any other exception of the reader |
| skipped | C | neutral | a dry-run-only reading, skipped in session |
| agree | — | count | a reading with no disagreement |

- A kind is set by cause, never by an exception's type.
- A class-C record's `slot` is the head's chain slot: `checkpointSlot` plus the authorities newer than the checkpoint
  by baseline (one authority per slot: their baselines and `authorityPacket`s are distinct, or the reading is
  corrupt), or null when the ledger was not read or its slots are malformed. A fault's or a corrupt record's detail
  names its exception class; every class-C detail names the head slot and the checkpoint slot (a skip, an over-budget
  and an over-cap record name their reason). A class-A or class-B record names the layer's slot; the stale record has
  no layer, so its slot is null.
- A skip still writes its record, with the reason and the slots.
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
2. It runs serial: the `-p` option keeps the parallel suite's serial loop, where the verify runs 8 workers.

The owner's approval for 282 names both. An outcome that differs between that run and the 8-worker verify 0 is
attributed to them first, and is class A only if the input set explains it.

**Capture gaps:** opens by subprocesses, and files read through memory maps already open, are not seen. Process-level
caches (a module imported, or a file read into an lru cache, by an earlier node of the serial run) are charged only to the
first node that read them.

**Non-claims.**
- 047 saves no verify time: it adds at most 15 s.
- The completeness of a captured input set is not claimed. Shadow mode measures it.
- Nothing is claimed about any other repository.
