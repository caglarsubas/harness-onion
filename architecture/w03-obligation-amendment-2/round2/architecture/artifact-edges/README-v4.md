# Artifact edge registry: v4 operator record (W03-PLAN-AMEND-2, slot 244)

Status: **CONTRACT_CANDIDATE_AWAITING_INDEPENDENT_REVIEW**. The v1, v2 and v3 operator records and EDGE-2 stay
byte-identical. v1's first rule applies: a new file needs a new registry record before any consumer packet uses it.

## `operator-harness-engineering-v4.json` (operator -> harness-engineering, buildArtifact)

`planeon.internal.artifact-edge-registry/v2`: edge record v3's 33 artefacts, unchanged and in order, statuses included,
plus 12 new rows, each BYTE_IDENTICAL, REGISTERED_BEFORE_USE, mode 100644, at its last-change commit (monitor decisions
Q-HE4B-7 (a) and the one-record sequencing, quoted in the record). Consumer packets: HE-003A3 (2 rows); HE-004 (10 rows). `supersedes` binds v3 by SHA-256
(`sha256:106ea91aa09c2d377adf3b514a228331d6a805bd1a17e641ecaa23b3c39115f3`, MET-ENFORCE-029).

| Provider path | SHA-256 | Consumer path | Consumer packet |
|---|---|---|---|
| `architecture/i06-backend-profile-v2/vectors.json` | `1a5e168f0d8f…` | `host-enforcement/contracts/i06-v2/vectors.json` | HE-004 |
| `architecture/i06-backend-profile-v2/criteria.json` | `026206c57d30…` | `host-enforcement/contracts/i06-v2/criteria.json` | HE-004 |
| `architecture/i06-backend-profile-v2/README.md` | `553880b95758…` | `host-enforcement/contracts/i06-v2/README.md` | HE-004 |
| `architecture/i06-backend-profile/identity-closure.json` | `0a9b82ffa2d6…` | `host-enforcement/contracts/i06-v1/identity-closure.json` | HE-004 |
| `architecture/i06-backend-profile/writer-inventory.json` | `8e6b3b7565cf…` | `host-enforcement/contracts/i06-v1/writer-inventory.json` | HE-004 |
| `architecture/i06-backend-profile/upstream-bootstrap-rbac-v1.37.1.json` | `7529c2a713af…` | `host-enforcement/contracts/i06-v1/upstream-bootstrap-rbac-v1.37.1.json` | HE-004 |
| `architecture/i06-backend-profile/README.md` | `ccf952d40b4f…` | `host-enforcement/contracts/i06-v1/README.md` | HE-004 |
| `architecture/admission-semantics-v3/vectors.json` | `a3e2dc981874…` | `host-enforcement/contracts/admission-v3/vectors.json` | HE-004 |
| `architecture/admission-semantics-v3/README.md` | `c3106482b4ff…` | `host-enforcement/contracts/admission-v3/README.md` | HE-004 |
| `architecture/admission-semantics-v3/admission-manifests/planeon-a2.json` | `1096b3cc71c4…` | `host-enforcement/contracts/admission-v3/admission-manifests/planeon-a2.json` | HE-004 |
| `architecture/i05-gate-channel-v4/README.md` | `b0af1f8784c7…` | `host-enforcement/contracts/i05-v4/README.md` | HE-003A3 |
| `architecture/i05-gate-channel-v4/vectors.json` | `f314610f7ee3…` | `host-enforcement/contracts/i05-v4/vectors.json` | HE-003A3 |

**Carried rows.** v3's rows are kept exactly: HE-003A2's two EFFECT_GATE v4 rows and HE-004's two OBSERVER rows were
REGISTERED_BEFORE_USE when published; HE-003A2 and HE-004A (HE-004's first part) have since merged in R10, and the rows stay
as recorded.

**Schema.** No key or status is added, so the record keeps schema v2. `ownerDecision`, `rules`, `notArtifacts` and
`statuses` are copied from v3; `supersedes`, `ownerDecisions` and `notes` are this record's own.

The boundary rule holds: the files are data contracts and contract text, not implementation source. `harness-engineering`
consumes no repository in any graph of `architecture/repositories.yaml`, so this edge cannot close a cycle.
