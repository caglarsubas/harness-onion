# Artifact edge registry: v13 operator record (the broker handoff v2 inputs)

Review rounds and adoption are recorded in MET-014's packet records, not here. The v1 to v12 operator records and EDGE-2
stay byte-identical. v1's first rule applies: "a new file, or another version of a listed file, needs a new registry
record (a harness-onion meta packet) before any consumer packet uses it". HE-005D vendors MET-014's broker handoff v2
inputs, so they need this record first (EDGE-V13, Q-EV13-1 (a): a new versioned folder, so every v12 byte and pin stays
true).

## `operator-harness-engineering-v13.json` (operator -> harness-engineering, buildArtifact)

`planeon.internal.artifact-edge-registry/v2`: edge record v12's 81 artefacts, unchanged and in order, statuses included, plus 2 new
rows, each BYTE_IDENTICAL, REGISTERED_BEFORE_USE, mode 100644, consumer HE-005D: 83 rows in all. `supersedes`
binds v12 (MET-ENFORCE-043) by SHA-256: `sha256:3587488b040f1c23f95f847dd3f1e15b97fa6ca705b6dca429d1cc6d64f3a5c7`. Its notes state what the two rows are, that the vectors are
now positive plus one schema-level refusal, and that no R10 file changes in this slot. Each new row binds its file's
bytes by `sha256` alone (v12's row key set has no size key); the byte counts below are for reading.

| Provider path | SHA-256 | Bytes | Provider commit | Provider packet | Consumer packet | Consumer path | Status |
|---|---|---|---|---|---|---|---|
| `architecture/broker-handoff-inputs-v2/channel.schema.json` | `b050af6bec76…` | 43,250 | none | MET-014 | HE-005D | `host-enforcement/contracts/broker-handoff-v2/channel.schema.json` | REGISTERED_BEFORE_USE |
| `architecture/broker-handoff-inputs-v2/vectors.json` | `b6154ebc18fe…` | 63,215 | none | MET-014 | HE-005D | `host-enforcement/contracts/broker-handoff-v2/vectors.json` | REGISTERED_BEFORE_USE |

**Commits.** Edge record v10's provenance rule for files published in the same packet applies: both files are new in
MET-014, so their rows carry `providerPacket` MET-014 and `providerCommit` null.

**What changed against v12's files.** TERMINAL admits `receiptSize` 0 only with status FAILED or UNAVAILABLE, and
`receiptDigest` is then the digest of zero bytes; such a run has zero RECEIPT_CHUNK frames. COMPLETED keeps
`receiptSize` 1 or more. `channel.schema.json` is v1's with exactly two hunks in `$defs.frame.oneOf[5]` (TERMINAL):
`receiptSize.minimum` 1 becomes 0, and the payload gains the `if`/`then` that ties size 0 to FAILED or UNAVAILABLE and
the empty digest. The empty-digest const stays (Q-TLA-2 (a)): over whole transcripts the size and digest binding already
implies it, but a check of one frame on its own, such as the negative vector, has only the schema. `vectors.json` is
v1's with `positive[2]`, the no-receipt vector (STARTED, CLEANUP_RECORDED, TERMINAL FAILED with size 0, the chain
recomputed from the zero digest), and `negative`, one frame: that TERMINAL with COMPLETED, refused by the schema.

**Two statements (X3).**

1. The `/v1` frame label now covers two schema revisions, v12's and v13's. They are told apart by the digests in the v12 and v13 rows, not by the label.
2. The v2 model is valid only with the v13 schema. The model does not refuse a COMPLETED size-0 transcript; the schema's if/then does. A whole COMPLETED size-0 transcript is refused under the v13 schema and accepted under it less its `if`/`then`.

**The design's obligation (Q-TLA-1 (a)).** The DATA model fixes order, not the trigger: the design must not record cleanup on a channel that may still carry a receipt. The relaxed model clause lets cleanup be recorded with no receipt
byte; it does not say when the server records it. A cleanup before the first receipt byte of a run that has one is
refused at its next chunk, so no PASS arises, but the run is lost: a reliability defect, not a safety one. No vector
claims this.

**Consumer.** HE-005D vendors `channel.schema.json` and `vectors.json` byte-identical under
`host-enforcement/contracts/broker-handoff-v2/`. R10 keeps HE-005B's v1 copies, because the v12 rows still bind them.
The edge rule binds bytes, modes and versions, not the label.

**Replay scope.** DATA_CHECK_ONLY. The transcript model v2 (`scripts/broker_handoff_transcript_v2.py`) is v1's
`validate_transcript` with one clause changed (`payload and` dropped from the cleanup-order rule). The member checker
`scripts/validate_edge_record_v13.py` (EV_V1 to EV_HUNKS) and its test `tests/test_edge_record_v13.py` check the files,
the two hunks and the one clause; MET-014's head replays every positive through the v2 model under the v13 schema.

**Schema.** No key or status is added, so the record keeps schema v2. `ownerDecision`, `rules`, `notArtifacts`,
`statuses` and `ownerDecisions` are carried from v12 unchanged; `artifact`, `supersedes` and `notes` are this record's
own.

The boundary rule holds: the files are data contracts, not implementation source. `harness-engineering` consumes no
repository in any graph of `architecture/repositories.yaml`, so this edge cannot close a cycle. `repositories.yaml` is
unchanged.
