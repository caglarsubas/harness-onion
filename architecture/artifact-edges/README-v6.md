# Artifact edge registry: v6 operator record (MET-ENFORCE-036)

Status: **SUCCESSOR_CANDIDATE_AWAITING_INDEPENDENT_REVIEW** (review rounds and adoption in
`architecture/compiled-filter-programs-v3/status.json`). The v1 to v5 operator records and EDGE-2
(`conformance-labs-harness-engineering.json`) stay byte-identical. v1's first rule applies: "a new file, or another
version of a listed file, needs a new registry record (a harness-onion meta packet) before any consumer packet uses it".
Seccomp allowlists v5 changed OBSERVER's compiled programs, so the republished programs need this record before R10 uses
them.

## `operator-harness-engineering-v6.json` (operator -> harness-engineering, buildArtifact)

`planeon.internal.artifact-edge-registry/v2`: edge record v5's 54 artefacts, unchanged and in order, plus the two
OBSERVER programs that `architecture/compiled-filter-programs-v3/` republishes from seccomp allowlists v5. `supersedes`
binds v5 (MET-ENFORCE-033, slot 246) by SHA-256: `sha256:89b47ef8f865b31911eb8da2b08a5a3c22b2d92a62599cb6fdfccbfe7f79e3c0`.

The record quotes the decisions behind it verbatim: Q-SOL-1 (a), packet 2 of SECCOMP-OBSERVER-LISTENER; F-SOL-1's note,
the next free edge version; the lane monitor's Q-P2-1, -3 and -4 (a); and Q-P2-2 (a) with the primary lane's
path-level facts.

| Program | Provider path | SHA-256 | Consumer packet | Consumer path | Status |
|---|---|---|---|---|---|
| OBSERVER aarch64 | `architecture/compiled-filter-programs-v3/programs/OBSERVER.aarch64.bpf` | `887bf07824d7…` | HE-004-I01 | `host-enforcement/contracts/seccomp-v5/OBSERVER.aarch64.bpf` | REGISTERED_BEFORE_USE |
| OBSERVER x86_64 | `architecture/compiled-filter-programs-v3/programs/OBSERVER.x86_64.bpf` | `a20d2a956393…` | HE-004-I01 | `host-enforcement/contracts/seccomp-v5/OBSERVER.x86_64.bpf` | REGISTERED_BEFORE_USE |

Both rows are mode 100644, BYTE_IDENTICAL, with `providerCommit` null and `providerPacket` MET-ENFORCE-036, edge v3's
convention for packet-published files: their commit is that packet's merge commit. HE-004-I01 is the R10 packet that
produces I01 (HS53's F-SOL-1 and obligation O-R10-HE004-I01). The consumer paths follow R10's convention
`contracts/seccomp-v<N>/<ROLE>.<arch>.bpf`, where N is the seccomp contract version compiled from (Q-P2-2 (a)).

**Carried rows.** v5's rows are kept exactly, statuses included:
- Edge v2's two OBSERVER rows (HE-004, `contracts/seccomp-v3/`) stay unchanged (Q-P2-3 (a)). Whether R10 keeps
  `contracts/seccomp-v3/OBSERVER.*` after HE-004-I01 is R10's decision. Schema v2 has no status for a retired row, so a
  later record drops or retires those two rows if R10 removes the files.
- The twelve programs of the other six roles are also allowlists v5's programs (the same bytes: v5's digests and lengths
  for those roles equal v4's), so their registrations stand. SERVER's two programs stay PUBLISHED_UNREGISTERED.

**Not registered.** No other file gets a row (Q-P2-2 (a)). R10 has never vendored allowlists or spec texts, so seccomp
v5's allowlists and HS53's effective text need none. A possible I01 wire vector comes in a later edge record.

**Schema.** No key or status is added, so the record keeps schema v2. `ownerDecision`, `rules`, `notArtifacts` and
`statuses` are copied from v5; `artifact`, `supersedes`, `ownerDecisions` and `notes` are this record's own.

The boundary rule holds: the programs are data (the v5 contract's compiled filters), not implementation source.
`harness-engineering` consumes no repository in any graph of `architecture/repositories.yaml`, so this edge cannot close
a cycle. `repositories.yaml` is unchanged.
