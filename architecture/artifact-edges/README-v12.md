# Artifact edge registry: v12 operator record (the broker handoff v1 inputs)

Review rounds and adoption are recorded in the packet's status record
(`architecture/host-interface-amendment-he5/status.json`, which covers both contract parts of the slot), not here. The
v1 to v11 operator records and EDGE-2 stay byte-identical. v1's first rule applies: "a new file, or another version of a
listed file, needs a new registry record (a harness-onion meta packet) before any consumer packet uses it". HE-005B
vendors MET-REPAIR-014's broker handoff inputs, the I02/I03 data files, so they need this record first (Q-EV12-1 (a)).
Amendment HE5 (`architecture/host-interface-amendment-he5/`), in the same slot, carries the W01 errata.

## `operator-harness-engineering-v12.json` (operator -> harness-engineering, buildArtifact)

`planeon.internal.artifact-edge-registry/v2`: edge record v11's 79 artefacts, unchanged and in order, statuses included,
plus 2 new rows, each BYTE_IDENTICAL, REGISTERED_BEFORE_USE, mode 100644, consumer HE-005B: 81 rows in all.
`supersedes` binds v11 (MET-ENFORCE-042) by SHA-256:
`sha256:9188980f0ce211e2939d431d900a7aff77262de3a973009666ed13f3ef3cbd77`. Its notes state what the two rows are, that
the vectors are positive only (DATA_CHECK_ONLY), and that no R10 file changes in this slot.

| Provider path | SHA-256 | Bytes | Provider commit | Provider packet | Consumer packet | Consumer path | Status |
|---|---|---|---|---|---|---|---|
| `architecture/broker-handoff-inputs/channel.schema.json` | `e7e9558fb50b…` | 42,572 | `8f3cc3a8ef34` | none | HE-005B | `host-enforcement/contracts/broker-handoff-v1/channel.schema.json` | REGISTERED_BEFORE_USE |
| `architecture/broker-handoff-inputs/vectors.json` | `80d8da953c41…` | 47,254 | `8f3cc3a8ef34` | none | HE-005B | `host-enforcement/contracts/broker-handoff-v1/vectors.json` | REGISTERED_BEFORE_USE |

**Commits.** Edge record v10's provenance rule applies exactly, as v11 applies it. Both files are already on main,
unchanged since their last-change commit `8f3cc3a8ef34` (MET-REPAIR-014); their rows carry that commit and no
`providerPacket`, as v10's and v11's rows for already published files do.

**Consumer.** HE-005B vendors `channel.schema.json` and `vectors.json` byte-identical under
`host-enforcement/contracts/broker-handoff-v1/`: the binding, DISPATCH, the eight broker frames and `workerStart`. The
edge rule binds bytes, modes and versions, not the label.

**Replay scope.** DATA_CHECK_ONLY. The vectors are positive only, and R10 states its negative cases in its own tests and
MODEL_DEFINED (Q-HE5-1 (a)). No R10 file changes in this slot.

**Not registered.** Only the two data files are registered. The readiness guide
`docs/alpha-2/BROKER_HANDOFF_READINESS.md` is not a consumer artefact: it stays byte-identical, and amendment HE5 records
the one sentence of it that HE5 supersedes. Amendment HE5's files, the status record, the source index and the review
records are packet records, not consumer artefacts.

**Schema.** No key or status is added, so the record keeps schema v2. `ownerDecision`, `rules`, `notArtifacts`,
`statuses` and `ownerDecisions` are carried from v11 unchanged (v11 carried them from v10); `artifact`, `supersedes`
and `notes` are this record's own.

**Open items.** The packet mechanics re-check at the mechanics base: edge record v11's SHA-256 must still be
`9188980f0ce211e2939d431d900a7aff77262de3a973009666ed13f3ef3cbd77` and its 79 rows the ones carried here, in order; the
two provider files must still have these bytes, mode and last-change commit; v12 and this README must still be free
(checked by exact path); and the builder is re-run on the mechanics base. If any differs, v12 is re-derived before it is
published.

The boundary rule holds: the files are data contracts, not implementation source. `harness-engineering` consumes no
repository in any graph of `architecture/repositories.yaml`, so this edge cannot close a cycle. `repositories.yaml` is
unchanged.
