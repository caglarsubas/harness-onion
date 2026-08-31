# ADR 0003: Source reuse and provenance remain closed by default

- Status: Accepted
- Date: 2026-08-30
- Owner packet: `MET-002`

## Context

The platform has five accounted warm-start inputs from planning. Two are approved
for public disclosure as exact repository and commit references. Three remain
metadata-omitted, unavailable to implementation identities, and represented only
by independently distilled contracts and acceptance criteria.

The two public references contribute 535 path records: 20 trees retained only
for discovery and 515 exact blobs retained only for clean-room behavioral or
contract parity. Repository-level consent to inspect those references does not
prove authorship, exclusive ownership, path-level license rights, or permission
to copy a blob. No current record is copy-authorized.

## Decision

We separate reference evidence from copy authority and fail closed at every
transition.

1. `architecture/reuse-map.yaml` is the public source boundary. It contains two
   immutable public SHA pins and records only the count and prohibited
   disposition of the three omitted planning inputs. “Five accounted inputs”
   therefore does not mean five publicly observable repositories or SHAs.
2. `architecture/reuse-path-index.yaml` is the exact current path/object
   inventory. Trees are `TREE_DISCOVERY`; blobs are `BLOB_PENDING`. A tree never
   grants recursive copy authority, and a pending blob never grants source access
   to an implementation identity.
3. `architecture/porting-authorization-index.yaml` is disabled and empty. Its
   current schema rejects every authorization. No existing task packet may use
   `PORT_CANDIDATE`, and no current path may use `COPY_AUTHORIZED`.
4. `legal/third-party-license-policy.yaml` classifies every provider SPDX
   expression exactly and denies unknown, missing, unresolved, or prohibited
   license evidence at release admission. Repository ownership and root-level
   licenses are never inherited as path-level copy rights.
5. `ci/lock_warm_snapshot.py` defines the only future reference-observation
   locker. It accepts direct argv, requires a detached and clean exact commit,
   proves indexed objects are local with lazy fetch disabled, removes all write
   bits, disables fetch and push, rejects alternates and linked worktrees, and
   scrubs ambient credential settings. Its packet tests use synthetic local Git
   fixtures only. The initial `MET-002` catalog publication did not open, mount,
   fetch, or inspect a warm-source checkout; the later user-authorized exception
   is bounded by the following decision.
6. The user-authorized `data.harness/v1` observation is the sole current
   reference-observation execution. The external root-owned launcher verifies
   the merged `MET-002` packet digest, signed source authority, exact pinned
   commit, and 29 indexed JSON Schema blobs; temporarily grants traversal only
   to the unprivileged observer identity; applies deny-all networking, all-write
   denial, whole-snapshot read denial, and exact-blob read exceptions; and
   restores the private parent traversal mode after the child exits. It emits
   [`architecture/observations/data-harness-v1.json`](../../architecture/observations/data-harness-v1.json)
   with 2,030 canonical structural facts and SHA-256
   `5c559a6ef3d59fa40e74ab2fb36603752751f523249da884f8e0d8daa06cfe10`.
   The report excludes source-root paths, host UID/GID and timestamps,
   descriptions, examples, source text, and executable code. A second run
   reproduced the same digest. This is observation evidence, not copy,
   adaptation, porting, CI, release, or tenant-acceptance authority.

## Future authorization transaction

Copy admission remains unavailable until a later, explicitly revised packet
implements an offline canonical-signature and tracked-evidence verifier and
enables a closed authorization schema. That future packet must provide, per
blob:

- an exact indexed repository, source commit, source path, and Git object;
- path-level ownership or license-grant, SPDX, third-party/generated-content,
  and exclusion-review evidence digests;
- an approved destination repository/path and transformation/parity intent;
- a source authority joined to destination `PORTING.yaml` by one
  `authorizationId`; and
- a non-circular transition from `SOURCE_APPROVED` to
  `DESTINATION_PREPARED`, then a separate source-material commit, then
  `APPLIED` with destination-object and parity evidence.

The source repository is never modified. Missing, mismatched, unsigned,
untracked, or digest-invalid evidence denies copy. The destination cannot merge
until its applied record and separate source-material commit validate; merge
evidence is recorded afterward and is never used to authorize itself.

## Consequences

- Current implementation is clean-room and can rely on public contracts without
  warm-source filesystem access.
- The catalog preserves provenance without publishing the identity of omitted
  inputs or fabricating unavailable SHAs.
- A future port is deliberately more expensive than reference-only parity: legal
  and technical evidence must meet at an exact blob and destination mapping.
- The synthetic locker proves enforcement mechanics, not observation of any
  current warm source.

## Rejected alternatives

- Recursive repository or directory copying from a discovery tree.
- Treating user ownership of a repository as authorship or a license grant for
  every path.
- Inferring every blob's license from a repository-root license.
- Allowing implementation identities to inspect warm-source worktrees.
- Enabling authorization before an offline signature/evidence verifier exists.
- Letting a destination PR, merge commit, or generated record authorize itself.
