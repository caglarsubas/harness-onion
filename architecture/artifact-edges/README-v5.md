# Artifact edge registry: v5 operator record (native-profile v4 and I06 v3)

Status: **CONTRACT_CANDIDATE_ROUND3_AWAITING_INDEPENDENT_REVIEW**. The v1, v2, v3 and v4 operator records and EDGE-2
stay byte-identical. v1's first rule applies: a new file needs a new registry record before any consumer packet uses it.

## `operator-harness-engineering-v5.json` (operator -> harness-engineering, buildArtifact)

`planeon.internal.artifact-edge-registry/v2`: edge record v4's 45 artefacts, unchanged and in order, statuses included,
plus 9 new rows, each BYTE_IDENTICAL, REGISTERED_BEFORE_USE, mode 100644. `supersedes` binds v4 by SHA-256
(`sha256:e30772ff8826650c46d1a8d384625929975e47f2de5cc9030680b5fdb5e7fc86`, MET-ENFORCE-032, slot 244). The record
quotes the decisions behind it: Q-NP4-15 (a) and Q-NP4D-5 (a), the edge record goes in this packet, and Q-NP4-17 (a),
one meta packet with native-profile v4 and the I06 successor.

| Provider path | Commit | SHA-256 | Consumer path | Consumer packet |
|---|---|---|---|---|
| `architecture/native-profile-v4/qualification.schema.json` | TBD (null) | `c3e91c087ebc…` | `host-enforcement/contracts/native-profile-v4/qualification.schema.json` | HE-004D1 |
| `architecture/native-profile-v4/vectors.json` | TBD (null) | `dede64ab3202…` | `host-enforcement/contracts/native-profile-v4/vectors.json` | HE-004D1 |
| `architecture/native-profile-v4/README.md` | TBD (null) | `a4205a5388dc…` | `host-enforcement/contracts/native-profile-v4/README.md` | HE-004D1 |
| `architecture/native-qualification-inputs/qualification.schema.json` | `3f52d53c39` | `bef248bfa82b…` | `host-enforcement/contracts/native-profile-v1/qualification.schema.json` | HE-004D2 |
| `architecture/native-profile-v2/qualification.schema.json` | `46bcc3e383` | `55bd641fd229…` | `host-enforcement/contracts/native-profile-v2/qualification.schema.json` | HE-004D2 |
| `architecture/native-profile-v3/qualification.schema.json` | `a29c93c781` | `ae5cbb6aa39f…` | `host-enforcement/contracts/native-profile-v3/qualification.schema.json` | HE-004D2 |
| `architecture/i06-backend-profile-v3/vectors.json` | TBD (null) | `4752b648abdd…` | `host-enforcement/contracts/i06-v3/vectors.json` | HE-004D2 |
| `architecture/i06-backend-profile-v3/criteria.json` | TBD (null) | `752533c57b5f…` | `host-enforcement/contracts/i06-v3/criteria.json` | HE-004D2 |
| `architecture/i06-backend-profile-v3/README.md` | TBD (null) | `9ee406f43060…` | `host-enforcement/contracts/i06-v3/README.md` | HE-004D2 |

**Commits and packets.** The six rows this packet publishes (native-profile v4's schema, vectors and README and I06 v3's
vectors, criteria and README) carry `providerCommit` null and `providerPacket` `TBD`, edge v3's convention for
packet-published files: their commit is the publishing packet's merge commit. The native-profile v1, v2 and v3 schema
rows already exist and carry their last-change commits (MET-REPAIR-015, MET-ENFORCE-005 and MET-ENFORCE-010).

**Consumer labels.** Each row is labelled with its first consumer: HE-004D1 (kernel captures and the inspector policy)
for the native-profile v4 rows; HE-004D2 (the I06 evidence composition with `check_qualification`, whose
`check_migration` pins and validates against the v1, v2 and v3 schemas) for the earlier schemas and the I06 v3 rows. The
edge rule binds bytes, modes and versions, not the label, so HE-004D2 relies on the same rows for the native-profile v4
files.

**Schema.** No key or status is added, so the record keeps schema v2. `ownerDecision`, `rules`, `notArtifacts` and
`statuses` are copied from v4; `artifact`, `supersedes`, `ownerDecisions` and `notes` are this record's own.

**Open items.** `providerPacket` `TBD`: the packet id is assigned with the slot when the contract is adopted, and these
six rows then name it. Edge record v4 is published by slot 244 (MET-ENFORCE-032), which must merge before this record.
When filling the six `providerPacket` values, the packet mechanics also re-check the merged edge v4: its SHA-256 must
still be `e30772ff8826650c46d1a8d384625929975e47f2de5cc9030680b5fdb5e7fc86` and its 45 rows the ones carried here, in
order. If either differs, v5 is re-derived (its `supersedes` digest and the carried rows) from the merged v4 before this
record is published (contract review round 1, N1-6).

The boundary rule holds: the files are data contracts and contract text, not implementation source.
`harness-engineering` consumes no repository in any graph of `architecture/repositories.yaml`, so this edge cannot close
a cycle.
