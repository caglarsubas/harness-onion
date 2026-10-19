# Artifact edge registry: v7 operator record (native-profile v5)

Status: **CONTRACT_CANDIDATE_ROUND4_AWAITING_INDEPENDENT_REVIEW** (review rounds and adoption in
`architecture/native-profile-v5/status.json`). The v1 to v6 operator records and EDGE-2 stay byte-identical. v1's first
rule applies: "a new file, or another version of a listed file, needs a new registry record (a harness-onion meta
packet) before any consumer packet uses it". Native-profile v5 publishes new files, so they need this record before R10
uses them.

## `operator-harness-engineering-v7.json` (operator -> harness-engineering, buildArtifact)

`planeon.internal.artifact-edge-registry/v2`: edge record v6's 56 artefacts, unchanged and in order, statuses included,
plus 6 new rows, each BYTE_IDENTICAL, REGISTERED_BEFORE_USE, mode 100644, labelled HE-004D2. `supersedes` binds v6
(MET-ENFORCE-036, slot 249) by SHA-256: `sha256:0ac7c2da62de87837f5a36a967a2c5b9c286ecab2e03f335a8eebbd32df9d24d`. The
record quotes the decisions behind it verbatim: Q-NPE-1 (c), Q-NPE-6 (a), Q-NPE-7 (a) and Q-HE4D2-3.

| Provider path | SHA-256 | Provider commit / packet | Consumer packet | Consumer path | Status |
|---|---|---|---|---|---|
| `architecture/native-profile-v5/qualification.schema.json` | `70bda12463ce…` | null / `TBD` | HE-004D2 | `host-enforcement/contracts/native-profile-v5/qualification.schema.json` | REGISTERED_BEFORE_USE |
| `architecture/native-profile-v5/vectors.json` | `b630c362b20b…` | null / `TBD` | HE-004D2 | `host-enforcement/contracts/native-profile-v5/vectors.json` | REGISTERED_BEFORE_USE |
| `architecture/native-profile-v5/README.md` | `76b584ca769f…` | null / `TBD` | HE-004D2 | `host-enforcement/contracts/native-profile-v5/README.md` | REGISTERED_BEFORE_USE |
| `architecture/native-qualification-inputs/vectors.json` | `cd1be009b721…` | `3f52d53c` | HE-004D2 | `host-enforcement/contracts/native-profile-v1/vectors.json` | REGISTERED_BEFORE_USE |
| `architecture/native-profile-v2/vectors.json` | `6d58d1f36b7b…` | `46bcc3e3` | HE-004D2 | `host-enforcement/contracts/native-profile-v2/vectors.json` | REGISTERED_BEFORE_USE |
| `architecture/native-profile-v3/vectors.json` | `14af47a69c97…` | `a29c93c7` | HE-004D2 | `host-enforcement/contracts/native-profile-v3/vectors.json` | REGISTERED_BEFORE_USE |

**Commits and packets.** The native-profile v5 rows carry `providerCommit` null and `providerPacket` `TBD`, edge v3's
convention for packet-published files: their commit is the publishing packet's merge commit, and the packet id is
assigned with the slot at adoption, as slot 246 did for edge record v5. The three history rows carry their files'
last-change commits at the accepted base, with the rows' bytes and modes, as the builder proves from git.

**Consumer label.** HE-004D2 vendors the rows and carries HE-004D1's re-vendor of the capture contract (Q-NPE-6 (a);
Q-HE4D2-3 (a) widens its three rows by the three history rows, for HE-004D2's exact replay). The edge rule binds bytes,
modes and versions, not the label.

**Carried rows.** v6's rows are kept exactly. Native-profile v4's rows (HE-004D1) and the v1, v2 and v3 schema rows
(HE-004D2) stay needed: v5 keeps native-profile v4's record contract.

**Not registered.** No other file gets a row.

**Schema.** No key or status is added, so the record keeps schema v2. `ownerDecision`, `rules`, `notArtifacts` and
`statuses` are copied from v6; `artifact`, `supersedes`, `ownerDecisions` and `notes` are this record's own.

**Open items.** `providerPacket` `TBD` is filled at adoption. The packet mechanics re-check the merged edge v6: its
SHA-256 must still be `0ac7c2da62de87837f5a36a967a2c5b9c286ecab2e03f335a8eebbd32df9d24d` and its 56 rows the ones
carried here, in order, and v7 must be the next free edge version. If either differs, v7 is re-derived before it is
published.

The boundary rule holds: the files are data contracts and contract text, not implementation source.
`harness-engineering` consumes no repository in any graph of `architecture/repositories.yaml`, so this edge cannot close
a cycle. `repositories.yaml` is unchanged.
