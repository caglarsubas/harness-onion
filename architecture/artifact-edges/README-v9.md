# Artifact edge registry: v9 operator record (the I01 wire schema and vectors)

Status: **CONTRACT_CANDIDATE_ROUND2_AWAITING_INDEPENDENT_REVIEW** (review rounds and adoption in
`architecture/edge-record-v9/status.json`). The v1 to v8 operator records and EDGE-2 stay byte-identical. v1's first
rule applies: "a new file, or another version of a listed file, needs a new registry record (a harness-onion meta
packet) before any consumer packet uses it". HE-004-I01's step U7 vendors the I01 wire's schema and vectors, so they
need this record first (owner decision Q-HE4I1-10 (a)).

## `operator-harness-engineering-v9.json` (operator -> harness-engineering, buildArtifact)

`planeon.internal.artifact-edge-registry/v2`: edge record v8's 66 artefacts, unchanged and in order, statuses included,
plus 2 new rows, each BYTE_IDENTICAL, REGISTERED_BEFORE_USE, mode 100644. `supersedes` binds v8 (MET-ENFORCE-039, slot
254) by SHA-256: `sha256:623cf10bf19cfba1806f5699007f39c7f6ba38f72d92069548421c4dccd21573`. The record quotes the
decisions behind it verbatim: Q-HE4I1-10 (a), Q-I01A-1, Q-EV9-1 to Q-EV9-5 and Q-EV9-1b.

| Provider path | SHA-256 | Bytes | Provider commit | Consumer packet | Consumer path | Status |
|---|---|---|---|---|---|---|
| `architecture/policy-observation-inputs/channel.schema.json` | `fb69b77201d9…` | 41,771 | `108e61953d52` | HE-004-I01 | `host-enforcement/contracts/i01-v1/channel.schema.json` | REGISTERED_BEFORE_USE |
| `architecture/policy-observation-inputs/vectors.json` | `1bfb46776636…` | 14,486 | `108e61953d52` | HE-004-I01 | `host-enforcement/contracts/i01-v1/vectors.json` | REGISTERED_BEFORE_USE |

**Commits.** Both files are already on main, unchanged since MET-REPAIR-010. Each row's `providerCommit` is the file's
last-change commit, and the rows carry no `providerPacket`, as edge record v4's rows for already published files did.

**Consumer (Q-EV9-2 (a)).** HE-004-I01 vendors both files under `host-enforcement/contracts/i01-v1/` and replays the
vectors' request cases against its own request check at U7. The edge rule binds bytes, modes and versions, not the
label.

**Replay scope.** HE-004-I01's U7 replays only the vectors' request cases (the request negatives and the positive's
request) against its own request check; they need nothing beyond the two registered files. The vectors' binding and
observation cases also read `architecture/proxy-contract-inputs/vectors.json`, which is not registered, so replaying
them in R10 needs a later record first.

**Not registered.** `scripts/validate_policy_observation.py`: validators and models are pinned by digest, not copied.
`docs/alpha-2/POLICY_OBSERVATION_READINESS.md`, which MET-REPAIR-010 pins beside the two files and which states the
wire's rules: a specification document that R10 reads and cites but does not vendor (Q-EV9-1b (a)). `status.json` and
the review records are packet records in `architecture/edge-record-v9/` (Q-EV9-3 (a)).

**Schema.** No key or status is added, so the record keeps schema v2. `ownerDecision`, `rules`, `notArtifacts` and
`statuses` are copied from v8; `artifact`, `supersedes`, `ownerDecisions` and `notes` are this record's own.

**Open items.** The packet mechanics re-check the merged edge v8: its SHA-256 must still be
`623cf10bf19cfba1806f5699007f39c7f6ba38f72d92069548421c4dccd21573` and its 66 rows the ones carried here, in order; both
provider files must still have these bytes, mode and last-change commit; v9, this README and
`architecture/edge-record-v9/` must still be free (checked by exact path); and the builder is re-run on the mechanics
base. If any differs, v9 is re-derived before it is published.

The boundary rule holds: the files are data contracts, not implementation source. `harness-engineering` consumes no
repository in any graph of `architecture/repositories.yaml`, so this edge cannot close a cycle. `repositories.yaml` is
unchanged.
