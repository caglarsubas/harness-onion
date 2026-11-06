# The chain checkpoint (CHAIN-COMPACTION-002, G1): MET-PERF-047

This directory holds the signed checkpoint's ledger and its vectors. MET-PERF-047 writes the first checkpoint, at slot
282, and ships the shadow reader `ci/chain_checkpoint.py`.

**G1.** Every layer above the newest checkpoint is re-executed in full on every verify. A layer at or below it was
re-executed when the checkpoint was written, and since then the ledger attests it:
- the ledger records each layer's validator, test file and captured inputs at the checkpoint tree, with its nodes'
  outcomes;
- every run rebuilds those files from the live tree and compares them;
- a head-seeded sample of the attested layers is re-executed too.

**MET-PERF-047 is shadow-only.** Every verify still runs everything in full.
- The reader only observes and records: it never changes a session's outcome.
- A missing or failing reader prints one class-C line and changes nothing.
- The sampled mode, which skips work, is MET-PERF-048's. It comes after a clean shadow period and bundle v8.

**The owner's numbers:** a new checkpoint every 10 slots (earlier on the owner's word); sample fraction f = 0.10; a full
run between checkpoints only on an owner-named slot; N_shadow = 10 consecutive clean shadow verifies, with a rewrite
inside the period; the reader capped at 15 s per verify.

**How the reader rebuilds.**
- It replays, newest first, only the published `reverseHunks` of the authorities newer than the checkpoint.
- The apply is byte-exact, with each file's `afterSha256` and `beforeSha256` checked. It never uses git history.
- It undoes only hunks whose recorded class is normalised: `cascade` and `bridge`, plus `record` when the writing
  run's capture names an index record.
- Each recorded class is re-checked by chainmech v2.2's rule, with the authority's `hunkClassContext`.
- Rebuilt bytes are compared, never executed.

**Classes of disagreement.** Each restarts the clean count:
- **A**, an input differs after normalisation;
- **B**, an outcome differs with no input change;
- **C**, a fault of the reader or of the records.

**The stated difference of the writing run.** Argv 1-62 and 64 run through `ci/run_packet_argv.py`. Argv 63 runs
directly, with the capture plugin of `scripts/chain_checkpoint_writer.py` and two capture variables. The plugin only
observes. The owner's head approval for 282 names that run, and a disagreement on argv 63 at 283 is first attributed
to it.

**Non-claims.**
- No verify time is saved by 047: it adds at most 15 s.
- The completeness of a captured input set is not claimed. Shadow mode measures it.
- Nothing is claimed about any other repository.
