# Artifact edge registry: v10 operator record (the I01 digest contract and the proxy-contract vectors)

Review rounds and adoption are recorded in the packet's status record, not here. The v1 to v9 operator records and
EDGE-2 stay byte-identical. v1's first rule applies: "a new file, or another version of a listed file, needs a new
registry record (a harness-onion meta packet) before any consumer packet uses it". HE-004-I01B vendors the I01 digest
contract's data files and replays the wire vectors' binding and observation cases, so they need this record first
(Q-DIG-16 (a), Q-DIG-18 (a)).

## `operator-harness-engineering-v10.json` (operator -> harness-engineering, buildArtifact)

`planeon.internal.artifact-edge-registry/v2`: edge record v9's 68 artefacts, unchanged and in order, statuses included,
plus 4 new rows, each BYTE_IDENTICAL, REGISTERED_BEFORE_USE, mode 100644, consumer HE-004-I01B. `supersedes` binds v9
(MET-ENFORCE-040, slot 256) by SHA-256: `sha256:197f30e4e1e0be1dcacd71f1095c91e2333fe9d6ea05b8194578160e471605d7`. The
record quotes the decisions behind it verbatim: Q-DIG-16 and Q-DIG-18 (a), the contract build GO, the slot, and Q-CB-2
(a).

| Provider path | SHA-256 | Bytes | Provider commit | Provider packet | Consumer packet | Consumer path | Status |
|---|---|---|---|---|---|---|---|
| `architecture/policy-observation-digests/definitions.json` | `086692065cfc…` | 35,940 | null | MET-ENFORCE-041 | HE-004-I01B | `host-enforcement/contracts/i01-digests-v1/definitions.json` | REGISTERED_BEFORE_USE |
| `architecture/policy-observation-digests/vectors.json` | `bd9f04bd04fc…` | 468,843 | null | MET-ENFORCE-041 | HE-004-I01B | `host-enforcement/contracts/i01-digests-v1/vectors.json` | REGISTERED_BEFORE_USE |
| `architecture/policy-observation-digests/README.md` | `e393dd11c75f…` | 46,944 | null | MET-ENFORCE-041 | HE-004-I01B | `host-enforcement/contracts/i01-digests-v1/README.md` | REGISTERED_BEFORE_USE |
| `architecture/proxy-contract-inputs/vectors.json` | `edf32ddf992e…` | 12,799 | `33de300cabb4` | none | HE-004-I01B | `host-enforcement/contracts/i01-v1/proxy-contract-vectors.json` | REGISTERED_BEFORE_USE |

**Commits.** The three contract files are published by this packet (MET-ENFORCE-041, slot 258), so their rows carry
`providerCommit` null and `providerPacket` MET-ENFORCE-041, as edge record v9's rows for files published by their own
packet do; the mechanics re-derive the SHA-256 from the merged bytes. PPV is already on main, unchanged since its
last-change commit `33de300cabb4`; its row carries that commit and no `providerPacket`, as v9's rows for already
published files do.

**Consumer.** HE-004-I01B vendors the contract's `definitions.json`, `vectors.json` and `README.md` under
`host-enforcement/contracts/i01-digests-v1/`, and PPV at
`host-enforcement/contracts/i01-v1/proxy-contract-vectors.json`, beside the I01 wire's schema and vectors (edge record
v9) and clear of the contract's own `vectors.json`. The edge rule binds bytes, modes and versions, not the label.

**Replay scope.** With PPV registered, R10 replays the wire vectors' binding and observation cases (VPO's
`validate_messages` reads the three PV messages, PPV's positive and CS), and the contract's own vectors, which need
nothing beyond the three contract files and the frozen I06 inputs R10 already embeds.

**Not registered.** `architecture/proxy-contract-inputs/profile.schema.json` (PPS): the replay reads only PPV's
positive, never the profile schema; TPO uses PPS only in `validate_profile` cases (re-checked at harness-onion
`30f41e6f`). `scripts/policy_observation_digests.py` and the validators: models are pinned by file sha256 or by
behaviour vectors, not copied. The status record and the review records are packet records written at adoption.

**Schema.** No key or status is added, so the record keeps schema v2. `ownerDecision`, `rules`, `notArtifacts` and
`statuses` are copied from v9; `artifact`, `supersedes`, `ownerDecisions` and `notes` are this record's own.

**Open items.** The packet mechanics re-check the merged edge v9: its SHA-256 must still be
`197f30e4e1e0be1dcacd71f1095c91e2333fe9d6ea05b8194578160e471605d7` and its 68 rows the ones carried here, in order; PPV
must still have these bytes, mode and last-change commit; v10, this README and the contract paths must still be free
(checked by exact path); and the builder is re-run on the mechanics base. If any differs, v10 is re-derived before it is
published.

The boundary rule holds: the files are data contracts and contract text, not implementation source.
`harness-engineering` consumes no repository in any graph of `architecture/repositories.yaml`, so this edge cannot close
a cycle. `repositories.yaml` is unchanged.
