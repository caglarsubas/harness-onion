# Artifact edge registry: v8 operator record (I06 backend profile v4, the observer's ClusterRole)

Status: **CONTRACT_CANDIDATE_ROUND2_AWAITING_INDEPENDENT_REVIEW** (review rounds and adoption in
`architecture/i06-backend-profile-v4/status.json`). The v1 to v7 operator records and EDGE-2 stay byte-identical. v1's
first rule applies: "a new file, or another version of a listed file, needs a new registry record (a harness-onion meta
packet) before any consumer packet uses it". I06 v4 publishes new files, so they need this record before R10 uses them.

## `operator-harness-engineering-v8.json` (operator -> harness-engineering, buildArtifact)

`planeon.internal.artifact-edge-registry/v2`: edge record v7's 62 artefacts, unchanged and in order, statuses included,
plus 4 new rows, each BYTE_IDENTICAL, REGISTERED_BEFORE_USE, mode 100644. `supersedes` binds v7 (MET-ENFORCE-038, slot
252) by SHA-256: `sha256:6af45e361a66331a9ee0216d3eea42f3a17770fd3c7d33e78e2a025d301bfa92`. The record quotes the
decisions behind it verbatim: Q-RBAC-1 (a) and Q-RBAC-2, 4, 5, 6, 7 and 8 (a).

| Provider path | SHA-256 | Provider commit / packet | Consumer packet | Consumer path | Status |
|---|---|---|---|---|---|
| `architecture/i06-backend-profile-v4/observer-rbac.json` | `71305d7f7ab2…` | null / `TBD` | HE-008 | `host-enforcement/contracts/i06-v4/observer-rbac.json` | REGISTERED_BEFORE_USE |
| `architecture/i06-backend-profile-v4/README.md` | `d58b0385299d…` | null / `TBD` | HE-008 | `host-enforcement/contracts/i06-v4/README.md` | REGISTERED_BEFORE_USE |
| `architecture/i06-backend-profile-v4/criteria.json` | `10aa3a8fe08a…` | null / `TBD` | HE-004-I01 | `host-enforcement/contracts/i06-v4/criteria.json` | REGISTERED_BEFORE_USE |
| `architecture/i06-backend-profile-v4/vectors.json` | `27aba3bf7296…` | null / `TBD` | HE-004-I01 | `host-enforcement/contracts/i06-v4/vectors.json` | REGISTERED_BEFORE_USE |

**Commits and packets.** The new rows carry `providerCommit` null and `providerPacket` `TBD`, edge v3's convention for
packet-published files: their commit is the publishing packet's merge commit, and the packet id is assigned at
mechanics.

**Consumer labels (Q-RBAC-4 (a)).** HE-008 vendors the role document and the README, checks its manifest and provisions
the two objects. HE-004-I01 vendors the criteria and vectors for the observer's own pin. Both use
`host-enforcement/contracts/i06-v4/`; the edge rule binds bytes, modes and versions, not the label.

**Carried rows.** v7's rows are kept exactly, I06 v3's (HE-004D2) included: v4 imports v3, and its replay reads I06 v3's
vectors. Every other input of v4's `check_vectors` is already registered in a carried row with the same bytes:
`architecture/i06-backend-profile-v3/vectors.json` (HE-004D2), `architecture/i06-backend-profile-v3/criteria.json`
(HE-004D2), `architecture/i07-policy-write-v3/vectors.json` (HE-002),
`architecture/i06-backend-profile/writer-inventory.json` (HE-004),
`architecture/i06-backend-profile/identity-closure.json` (HE-004),
`architecture/i06-backend-profile/upstream-bootstrap-rbac-v1.37.1.json` (HE-004).

**Not registered.** `scripts/i06_backend_profile_v4.py`: models are pinned by digest, not copied. `status.json` and
`source-index.json` are packet records.

**Schema.** No key or status is added, so the record keeps schema v2. `ownerDecision`, `rules`, `notArtifacts` and
`statuses` are copied from v7; `artifact`, `supersedes`, `ownerDecisions` and `notes` are this record's own.

**Open items.** `providerPacket` `TBD` is filled at adoption. The packet mechanics re-check the merged edge v7: its
SHA-256 must still be `6af45e361a66331a9ee0216d3eea42f3a17770fd3c7d33e78e2a025d301bfa92` and its 62 rows the ones
carried here, in order, and v8 must be the next free edge version. If either differs, v8 is re-derived before it is
published.

The boundary rule holds: the files are data contracts and contract text, not implementation source.
`harness-engineering` consumes no repository in any graph of `architecture/repositories.yaml`, so this edge cannot close
a cycle. `repositories.yaml` is unchanged.
