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
  - `disagreements` [{slot, where, class, detail}].

**How the reader rebuilds.**
- It replays, newest first, only the published `reverseHunks` of the authorities newer than the checkpoint. The apply
  is byte-exact, with each file's `afterSha256` and `beforeSha256` checked. It never uses git history.
- Each authority's `hunkClassContext`, `hunkClassVocabulary` and `hunkClassRuleSha256` are bound first. Each recorded
  class is re-checked by chainmech v2.2's rule.
- It undoes only `cascade` and `bridge` hunks, plus `record` when `normalisedRecordClass` is true.
- Rebuilt bytes are compared, never executed.
- An in-run budget stops the replay at the cap: class C, over cap.

**Classes and the stop rule.**
- **A**, an input differs after normalisation; **B**, an outcome differs with no input change; **C**, a fault of the
  reader or of the records, a dry-run-only skip, or over cap.
- Every A, B or C restarts the clean count of N_shadow (condition (v)).
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

**Capture gaps:** opens by subprocesses, and files read through memory maps already open, are not seen.

**Non-claims.**
- 047 saves no verify time: it adds at most 15 s.
- The completeness of a captured input set is not claimed. Shadow mode measures it.
- Nothing is claimed about any other repository.
