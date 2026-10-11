# Artifact edge registry — operator -> harness-engineering (buildArtifact)

Alpha 2A; 2026-10-11. Status: **CONTRACT_CANDIDATE_ROUND1_AWAITING_INDEPENDENT_REVIEW** (published by W03-AMEND).

`docs/alpha-2/ENFORCEMENT_INTEGRATION.md:111-113`: planned R10 interfaces "must use published contracts and immutable
artifacts; implementation source must not cross repository boundaries. Exact new artifact edges must be registered by the
successor before use." `architecture/repositories.yaml` has no operator -> harness-engineering edge, and its digest is
pinned in 58 files (outside review-round copies) at `a2eab93`, including `release/repos.lock.json`, so the edge is registered here as a separate record (owner
decision Q-HE2-A, 2026-10-11: "The owner accepts such a record as registration"). `repositories.yaml` is unchanged.

`operator-harness-engineering.json` (`planeon.internal.artifact-edge-registry/v1`) lists every harness-onion file the
operator repository (R10, `caglarsubas/mas-harness-operator`) holds or will hold, with its exact bytes:

| Provider path | Provider commit | sha256 | Consumer path | Consumer packet | Relation | Status |
|---|---|---|---|---|---|---|
| `ci/verify-offline.sh` | `0e747049cba3` | `778cb0faf597…` | `ci/verify-offline.sh` | HE-000 | BYTE_IDENTICAL | IN_USE |
| `ci/warm-source-isolation.sh` | `0e747049cba3` | `f717f62fb1c9…` | `ci/warm-source-isolation.sh` | HE-000 | BYTE_IDENTICAL | IN_USE |
| `ci/network_canary.py` | `0e747049cba3` | `1be4a837c4a5…` | `ci/network_canary.py` | HE-000 | BYTE_IDENTICAL | IN_USE |
| `ci/run_packet_argv.py` | `0e747049cba3` | `c2ed0852fa49…` | `ci/run_packet_argv.py` | HE-000 | DERIVED | IN_USE |
| `architecture/i05-gate-channel-v3/channel.schema.json` | `a2eab9365c86` | `3bfee13c9d32…` | `host-enforcement/contracts/i05-v3/channel.schema.json` | HE-002 | BYTE_IDENTICAL | REGISTERED_BEFORE_USE |
| `architecture/i05-gate-channel-v3/outcome-mapping.json` | `a2eab9365c86` | `4466f379f1cc…` | `host-enforcement/contracts/i05-v3/outcome-mapping.json` | HE-002 | BYTE_IDENTICAL | REGISTERED_BEFORE_USE |
| `architecture/i05-gate-channel-v3/vectors.json` | `a2eab9365c86` | `ab75d86fe54a…` | `host-enforcement/contracts/i05-v3/vectors.json` | HE-002 | BYTE_IDENTICAL | REGISTERED_BEFORE_USE |
| `architecture/i05-gate-channel-v3/README.md` | `a2eab9365c86` | `f82f43330125…` | `host-enforcement/contracts/i05-v3/README.md` | HE-002 | BYTE_IDENTICAL | REGISTERED_BEFORE_USE |
| `architecture/i05-gate-channel-v2/README.md` | `a2eab9365c86` | `1cb07cef90b0…` | `host-enforcement/contracts/i05-v2/README.md` | HE-002 | BYTE_IDENTICAL | REGISTERED_BEFORE_USE |
| `architecture/i05-gate-channel/README.md` | `a2eab9365c86` | `dc9aa22017b2…` | `host-enforcement/contracts/i05-v1/README.md` | HE-002 | BYTE_IDENTICAL | REGISTERED_BEFORE_USE |
| `architecture/i07-policy-write-v3/channel.schema.json` | `a2eab9365c86` | `c68721a1002f…` | `host-enforcement/contracts/i07-v3/channel.schema.json` | HE-002 | BYTE_IDENTICAL | REGISTERED_BEFORE_USE |
| `architecture/i07-policy-write-v3/policy-kinds.json` | `a2eab9365c86` | `4e427204b899…` | `host-enforcement/contracts/i07-v3/policy-kinds.json` | HE-002 | BYTE_IDENTICAL | REGISTERED_BEFORE_USE |
| `architecture/i07-policy-write-v3/vectors.json` | `a2eab9365c86` | `c4c24c5ff156…` | `host-enforcement/contracts/i07-v3/vectors.json` | HE-002 | BYTE_IDENTICAL | REGISTERED_BEFORE_USE |
| `architecture/i07-policy-write-v3/README.md` | `a2eab9365c86` | `a8c51a725b99…` | `host-enforcement/contracts/i07-v3/README.md` | HE-002 | BYTE_IDENTICAL | REGISTERED_BEFORE_USE |
| `architecture/i07-policy-write-v2/README.md` | `a2eab9365c86` | `cde20d7fee86…` | `host-enforcement/contracts/i07-v2/README.md` | HE-002 | BYTE_IDENTICAL | REGISTERED_BEFORE_USE |
| `architecture/i07-policy-write/README.md` | `a2eab9365c86` | `9e5cb3d1023b…` | `host-enforcement/contracts/i07-v1/README.md` | HE-002 | BYTE_IDENTICAL | REGISTERED_BEFORE_USE |
| `architecture/i05-gate-channel-v3-supplement/vectors.json` | `W03-AMEND` | `3c135d5c01a4…` | `host-enforcement/contracts/i05-v3-supplement/vectors.json` | HE-002 | BYTE_IDENTICAL | REGISTERED_BEFORE_USE |

`IN_USE`: held since HE-000 and registered retroactively; `REGISTERED_BEFORE_USE`: registered before HE-002 merges. The
supplementary vectors' provider commit is this packet's merge. Rules: the consumer holds exactly these bytes, and a
different version needs a new registry record first; only data contracts, contract text and transport files cross, never
product implementation source (`repositories.yaml:10`); harness-engineering consumes nothing from the operator, so the
buildArtifact graph stays acyclic. HE-001's closure table is R10's own generated file (its generator and classifier
stayed in the operator tools and harness-onion), so it is not an artifact edge.
