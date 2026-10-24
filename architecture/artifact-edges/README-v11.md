# Artifact edge registry: v11 operator record (the I01 digest contract v2, admission v4 and profile v2's vectors)

Review rounds and adoption are recorded in the packet's status record, not here. The v1 to v10 operator records and
EDGE-2 stay byte-identical. v1's first rule applies: "a new file, or another version of a listed file, needs a new
registry record (a harness-onion meta packet) before any consumer packet uses it". HE-004-I01B4 (S3) re-vendors the I01
digest contract v2's data files, admission v4's sealed A2 files and profile v2's vectors, so they need this record first
(Q-I01S-3; MON-I01S-D3).

## `operator-harness-engineering-v11.json` (operator -> harness-engineering, buildArtifact)

`planeon.internal.artifact-edge-registry/v2`: edge record v10's 72 artefacts, unchanged and in order, statuses included
(R10's HE-004-I01B1 still consumes the I01 v1 files), plus 7 new rows, each BYTE_IDENTICAL, REGISTERED_BEFORE_USE, mode
100644, consumer HE-004-I01B4. `supersedes` binds v10 (MET-ENFORCE-041, slot 258) by SHA-256:
`sha256:a4fad53dfadbe8a5d79d4049fbba83173adaacec8d33df5ca377aa288539364e`. Its notes quote the decisions behind it
verbatim: Q-I01S-3, MON-I01S-D3 and the F6 ruling.

| Provider path | SHA-256 | Bytes | Provider commit | Provider packet | Consumer packet | Consumer path | Status |
|---|---|---|---|---|---|---|---|
| `architecture/policy-observation-digests-v2/definitions.json` | `fef08fddfb94…` | 36,135 | null | MET-ENFORCE-042 | HE-004-I01B4 | `host-enforcement/contracts/i01-digests-v2/definitions.json` | REGISTERED_BEFORE_USE |
| `architecture/policy-observation-digests-v2/vectors.json` | `68eab4709431…` | 602,663 | null | MET-ENFORCE-042 | HE-004-I01B4 | `host-enforcement/contracts/i01-digests-v2/vectors.json` | REGISTERED_BEFORE_USE |
| `architecture/policy-observation-digests-v2/README.md` | `fbb28445c5ec…` | 60,473 | null | MET-ENFORCE-042 | HE-004-I01B4 | `host-enforcement/contracts/i01-digests-v2/README.md` | REGISTERED_BEFORE_USE |
| `architecture/admission-semantics-v4/README.md` | `f7794aa857aa…` | 40,789 | `675daccbc8a0` | none | HE-004-I01B4 | `host-enforcement/contracts/admission-v4/README.md` | REGISTERED_BEFORE_USE |
| `architecture/admission-semantics-v4/vectors.json` | `5706b1a8df5c…` | 316,811 | `675daccbc8a0` | none | HE-004-I01B4 | `host-enforcement/contracts/admission-v4/vectors.json` | REGISTERED_BEFORE_USE |
| `architecture/admission-semantics-v4/admission-manifests/planeon-a2.json` | `92c21612304c…` | 8,322 | `675daccbc8a0` | none | HE-004-I01B4 | `host-enforcement/contracts/admission-v4/admission-manifests/planeon-a2.json` | REGISTERED_BEFORE_USE |
| `architecture/proxy-profile-v2/vectors.json` | `011a650bcd2a…` | 62,297 | `675daccbc8a0` | none | HE-004-I01B4 | `host-enforcement/contracts/i01-v2/proxy-profile-v2-vectors.json` | REGISTERED_BEFORE_USE |

**Commits.** Edge record v10's provenance rule applies exactly. The three contract files are published by this packet
(MET-ENFORCE-042), so their rows carry `providerCommit` null and `providerPacket` MET-ENFORCE-042; the mechanics
re-derive the SHA-256 from the merged bytes. Admission v4's `README.md`, `vectors.json` and
`admission-manifests/planeon-a2.json` and profile v2's `vectors.json` are already on main, unchanged since their
last-change commit `675daccbc8a0`; their rows carry that commit and no `providerPacket`, as v10's rows for already
published files do.

**Consumer.** HE-004-I01B4 vendors the contract's `definitions.json`, `vectors.json` and `README.md` under
`host-enforcement/contracts/i01-digests-v2/`, admission v4's three files under
`host-enforcement/contracts/admission-v4/` (beside v10's `admission-v3/`), and profile v2's `vectors.json` at
`host-enforcement/contracts/i01-v2/proxy-profile-v2-vectors.json`, beside the I01 wire's schema and vectors and clear of
the contract's own `vectors.json`. The edge rule binds bytes, modes and versions, not the label.

**Replay scope.** With these rows R10 replays every helper vector and every vector of the contract and, of its complete
positive, v1's five checks plus the sealed-namespace equality, which need nothing beyond the three contract files and
the frozen I06 inputs R10 already embeds; profile v2's `validate` and `precondition` on the complete positive stay
harness-side, in the v2 model's replay and the packet's v2 layer test.
R10's port omits the profile-schema load and profile v2's validate and precondition. As under v1, it also leaves out the frozen-model file pins (_frozen's FROZEN_MODELS loop, scripts/proxy_profile_v2.py included), since models are pinned, not copied. Its replay therefore counts 321 checks (16 helper vectors, the definitions pin, 298 vector checks and 6 complete-positive checks), against the model's 323.
R10 also renders the sealed A2 set with admission v4 against v4's published `planeon-a2.json`, and, with profile v2's
vectors (W3), replays the wire vectors' binding and observation cases with profile v2's positive once they are
re-derived for it (the namespace members, `observation.quota` and `binding.profileDigest`).

**Not registered.** Profile v2's `profile.schema.json`: the replay above needs neither it nor `proxy_profile_v2`,
because profile v2's `validate` and `precondition` on the complete positive stay harness-side, as `validate_profile`
with profile v1's schema (PPS, which edge record v10 left unregistered) was under v1. Profile v2's `README.md` and
`status.json`, admission v4's `allowlists.json` and `status.json`, and the models
(`scripts/policy_observation_digests_v2.py`, `scripts/admission_semantics_v4.py`, `scripts/proxy_profile_v2.py`): models
are pinned by file sha256 or by behaviour vectors, not copied. The status record, the source index and the review
records are packet records, not consumer artefacts.

**Schema.** No key or status is added, so the record keeps schema v2. `ownerDecision`, `rules`, `notArtifacts`,
`statuses` and `ownerDecisions` are carried from v10 unchanged; `artifact`, `supersedes` and `notes` are this record's
own.

**Open items.** The packet mechanics re-check at the mechanics base: edge record v10's SHA-256 must still be
`a4fad53dfadbe8a5d79d4049fbba83173adaacec8d33df5ca377aa288539364e` and its 72 rows the ones carried here, in order; the
four on-main files must still have these bytes, modes and last-change commits; v11, this README and the contract paths
must still be free (checked by exact path); and the builder is re-run on the mechanics base. If any differs, v11 is
re-derived before it is published.

The boundary rule holds: the files are data contracts and contract text, not implementation source.
`harness-engineering` consumes no repository in any graph of `architecture/repositories.yaml`, so this edge cannot close
a cycle. `repositories.yaml` is unchanged.
