# Artifact edge registry: v3 operator record (MET-ENFORCE-029)

Status: **SUCCESSOR_CANDIDATE_AWAITING_INDEPENDENT_REVIEW** (review rounds and adoption in
`architecture/compiled-filter-programs-v2/status.json`). The v1 record (`operator-harness-engineering.json`, `README.md`),
the v2 record (`operator-harness-engineering-v2.json`, `README-v2.md`) and EDGE-2 (`conformance-labs-harness-engineering.json`)
stay byte-identical. v1's first rule applies: "a new file, or another version of a listed file, needs a new registry record
(a harness-onion meta packet) before any consumer packet uses it". Seccomp allowlists v4 changed EFFECT_GATE's compiled
programs, so the republished programs need this record before R10 uses them.

## `operator-harness-engineering-v3.json` (operator -> harness-engineering, buildArtifact)

`planeon.internal.artifact-edge-registry/v2`: edge record v2's 31 artefacts, unchanged and in order, plus the two EFFECT_GATE
programs that `architecture/compiled-filter-programs-v2/` republishes from seccomp allowlists v4 (owner decisions
Q-HE3A-1 (c), Q-HE3A-1b (a), Q-HE3D-3 (a) and Q-PR-1..10 (a), quoted verbatim in the record). `supersedes` binds v2 by
SHA-256 (`sha256:749e70f174d638468bf45d7316e8f5201c3323f6348a78c7b9a22d3a571ccc32`, MET-ENFORCE-025).

| Program | Provider path | SHA-256 | Consumer packet | Consumer path | Status |
|---|---|---|---|---|---|
| EFFECT_GATE aarch64 | `architecture/compiled-filter-programs-v2/programs/EFFECT_GATE.aarch64.bpf` | `8de80a2b597b…` | HE-003A2 | `host-enforcement/contracts/seccomp-v4/EFFECT_GATE.aarch64.bpf` | REGISTERED_BEFORE_USE |
| EFFECT_GATE x86_64 | `architecture/compiled-filter-programs-v2/programs/EFFECT_GATE.x86_64.bpf` | `4e516f168209…` | HE-003A2 | `host-enforcement/contracts/seccomp-v4/EFFECT_GATE.x86_64.bpf` | REGISTERED_BEFORE_USE |

Both rows are mode 100644, BYTE_IDENTICAL, with `providerCommit` null and `providerPacket` MET-ENFORCE-029, as in v2.
HE-003A2 is the R10 packet that Q-HE3D-3 (a) names for the writer executable check. It vendors both programs under
`contracts/seccomp-v4/`. Whether R10 keeps `contracts/seccomp-v3/EFFECT_GATE.*` is R10's decision.

**Carried rows (Q-PR-5).** v2's rows are kept exactly, statuses included:
- v2's two EFFECT_GATE rows (HE-002S, `contracts/seccomp-v3/`) were REGISTERED_BEFORE_USE when v2 was published. HE-002S has
  since merged, so R10 holds them now. They stay as recorded, as v2 kept v1's statuses.
- The twelve programs of the other six roles are also allowlists v4's programs (the same bytes; v4's digests and lengths
  for those roles equal v3's), so their v2 registrations stand.
- SERVER's two programs stay PUBLISHED_UNREGISTERED.

**Schema.** No key or status is added, so the record keeps schema v2 (Q-PR-3). Its keys are v2's: `ownerDecision`, `rules`,
`notArtifacts` and `statuses` are copied from v2, and `supersedes`, `ownerDecisions` and `notes` are this record's own.
A later packet that holds a program under another path, or another version, needs a new record.

The boundary rule holds: the programs are data (the v4 contract's compiled filters), not implementation source.
`harness-engineering` consumes no repository in any graph of `architecture/repositories.yaml`, so this edge cannot close a
cycle. `repositories.yaml` is unchanged.
