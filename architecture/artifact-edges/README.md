# Artifact edge registry — operator -> harness-engineering (buildArtifact)

Alpha 2A; 2026-10-11. Status: **CONTRACT_CANDIDATE_ROUND2_AWAITING_INDEPENDENT_REVIEW** (published by W03-AMEND).

`docs/alpha-2/ENFORCEMENT_INTEGRATION.md:111-113`: planned R10 interfaces "must use published contracts and immutable
artifacts; implementation source must not cross repository boundaries. Exact new artifact edges must be registered by the
successor before use." `architecture/repositories.yaml` has no operator -> harness-engineering edge, and its digest is
pinned in 58 files (outside review-round copies) at `a2eab93`, including `release/repos.lock.json`, so the edge is registered here as a separate record (owner
decision Q-HE2-A, 2026-10-11: "The owner accepts such a record as registration"). `repositories.yaml` is unchanged.

`operator-harness-engineering.json` (`planeon.internal.artifact-edge-registry/v1`) lists every harness-onion file the
operator repository (R10, `caglarsubas/mas-harness-operator`) holds or will hold, with its exact bytes:

| Provider path | Provider commit | sha256 | Mode | Consumer path | Consumer packet | Relation | Status |
|---|---|---|---|---|---|---|---|
| `ci/verify-offline.sh` | `0e747049cba3eca` | `778cb0faf597…` | 100755 | `ci/verify-offline.sh` | HE-000 | BYTE_IDENTICAL | IN_USE |
| `ci/warm-source-isolation.sh` | `0e747049cba3eca` | `f717f62fb1c9…` | 100644 | `ci/warm-source-isolation.sh` | HE-000 | BYTE_IDENTICAL | IN_USE |
| `ci/network_canary.py` | `0e747049cba3eca` | `1be4a837c4a5…` | 100755 | `ci/network_canary.py` | HE-000 | BYTE_IDENTICAL | IN_USE |
| `ci/run_packet_argv.py` | `0e747049cba3eca` | `c2ed0852fa49…` | 100755 | `ci/run_packet_argv.py` | HE-000 | DERIVED | IN_USE |
| `architecture/i05-gate-channel-v3/channel.schema.json` | `a2eab9365c8663c` | `3bfee13c9d32…` | 100644 | `host-enforcement/contracts/i05-v3/channel.schema.json` | HE-002 | BYTE_IDENTICAL | REGISTERED_BEFORE_USE |
| `architecture/i05-gate-channel-v3/outcome-mapping.json` | `a2eab9365c8663c` | `4466f379f1cc…` | 100644 | `host-enforcement/contracts/i05-v3/outcome-mapping.json` | HE-002 | BYTE_IDENTICAL | REGISTERED_BEFORE_USE |
| `architecture/i05-gate-channel-v3/vectors.json` | `a2eab9365c8663c` | `ab75d86fe54a…` | 100644 | `host-enforcement/contracts/i05-v3/vectors.json` | HE-002 | BYTE_IDENTICAL | REGISTERED_BEFORE_USE |
| `architecture/i05-gate-channel-v3/README.md` | `a2eab9365c8663c` | `f82f43330125…` | 100644 | `host-enforcement/contracts/i05-v3/README.md` | HE-002 | BYTE_IDENTICAL | REGISTERED_BEFORE_USE |
| `architecture/i05-gate-channel-v2/README.md` | `a2eab9365c8663c` | `1cb07cef90b0…` | 100644 | `host-enforcement/contracts/i05-v2/README.md` | HE-002 | BYTE_IDENTICAL | REGISTERED_BEFORE_USE |
| `architecture/i05-gate-channel/README.md` | `a2eab9365c8663c` | `dc9aa22017b2…` | 100644 | `host-enforcement/contracts/i05-v1/README.md` | HE-002 | BYTE_IDENTICAL | REGISTERED_BEFORE_USE |
| `architecture/i07-policy-write-v3/channel.schema.json` | `a2eab9365c8663c` | `c68721a1002f…` | 100644 | `host-enforcement/contracts/i07-v3/channel.schema.json` | HE-002 | BYTE_IDENTICAL | REGISTERED_BEFORE_USE |
| `architecture/i07-policy-write-v3/policy-kinds.json` | `a2eab9365c8663c` | `4e427204b899…` | 100644 | `host-enforcement/contracts/i07-v3/policy-kinds.json` | HE-002 | BYTE_IDENTICAL | REGISTERED_BEFORE_USE |
| `architecture/i07-policy-write-v3/vectors.json` | `a2eab9365c8663c` | `c4c24c5ff156…` | 100644 | `host-enforcement/contracts/i07-v3/vectors.json` | HE-002 | BYTE_IDENTICAL | REGISTERED_BEFORE_USE |
| `architecture/i07-policy-write-v3/README.md` | `a2eab9365c8663c` | `a8c51a725b99…` | 100644 | `host-enforcement/contracts/i07-v3/README.md` | HE-002 | BYTE_IDENTICAL | REGISTERED_BEFORE_USE |
| `architecture/i07-policy-write-v2/README.md` | `a2eab9365c8663c` | `cde20d7fee86…` | 100644 | `host-enforcement/contracts/i07-v2/README.md` | HE-002 | BYTE_IDENTICAL | REGISTERED_BEFORE_USE |
| `architecture/i07-policy-write/README.md` | `a2eab9365c8663c` | `9e5cb3d1023b…` | 100644 | `host-enforcement/contracts/i07-v1/README.md` | HE-002 | BYTE_IDENTICAL | REGISTERED_BEFORE_USE |
| `architecture/i05-gate-channel-v3-supplement/vectors.json` | `MET-ENFORCE-024` | `1c00bdb3ea11…` | 100644 | `host-enforcement/contracts/i05-v3-supplement/vectors.json` | HE-002 | BYTE_IDENTICAL | REGISTERED_BEFORE_USE |

`IN_USE`: held since HE-000 and registered retroactively; `REGISTERED_BEFORE_USE`: registered before HE-002 merges.
The supplementary vectors are published by this packet (`providerPacket` MET-ENFORCE-024), so their provider commit is
this packet's merge. Rules: the consumer holds exactly these bytes and modes, and a new file, or another version of a
listed file, needs a new registry record (a harness-onion meta packet) before any consumer packet uses it; only data
contracts, contract text and transport files cross, never product implementation source (`repositories.yaml:10`); no
graph of `repositories.yaml` has harness-engineering consuming the operator, so the edge keeps every unconditional graph
acyclic: harness-engineering consumes no repository in any graph, so this edge cannot close a cycle (the layer checks
every unconditional graph). Not an artifact edge (`notArtifacts`): HE-001's closure table, R10's own generated file (the
operator tool that generated it ran harness-onion's pinned classifier at `a5a0625` outside R10, and no byte of the
classifier or its inputs is in R10). The
conformance-labs repository (R12) also holds the four transport files; its edge is outside this record (owner decision
Q-HE2-A covers the operator).
