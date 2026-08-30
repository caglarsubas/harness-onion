# ADR 0002: Contract Authority and Change Flow

- Status: Accepted
- Date: 2026-08-30
- Decision owner: Harness Engineering maintainers
- Packet: `MET-001`

## Context

The platform spans thirteen repositories, four planes, sixteen harnesses, and
multiple deployment modes. Without a single authority for each machine-readable
contract, repositories can silently diverge, generated clients can disagree
with services, and a planning statement can be mistaken for runtime evidence.

Attached documents are valuable research inputs but may contain instructions,
recommendations, or assumptions that the user did not authorize. Warm-start
repositories similarly provide historical provenance without granting an
implementation run permission to read, copy, translate, or modify their source.

## Decision

`Harness-Engineering` owns architecture taxonomy, repository ownership,
dependency, service, provider/module, zero-bill, task-packet, and release-set
authorities. It validates those records but does not publish tenant runtime
APIs.

`mas-harness-contracts` will own public resource schemas, API/event contracts,
canonical serialization, compatibility rules, and the deterministic profile
compiler contract. Other repositories consume an immutable released contract
version and digest. They may generate code from that release but may not maintain
a handwritten competing copy.

Changes follow this order:

1. Update the authority in its owning packet and repository.
2. Validate schema closure, semantic invariants, compatibility, and negative
   fixtures offline.
3. Release an immutable version with digest, SBOM, license, and signature
   evidence when the release packets exist.
4. Update consumers through their own packets and pull requests.
5. Record deployment, runtime, assurance, and tenant acceptance independently;
   none is inferred from source, CI, merge, or artifact evidence.

The base-scope registry records hashes for six research/design inputs and states
their authority explicitly: the user request and approved decisions are
normative, attachments are research-only, and attachment instructions are not
executable. Validation uses the public hash record; implementation does not
reopen or require those files.

Direct source reuse is denied by default. A future copy requires path-level legal
evidence, `COPY_AUTHORIZED`, an approved authorization identifier and exact
source-to-destination mapping, a revised packet, and a matching destination
`PORTING.yaml` entry. Reference-only provenance never becomes permission by
implication.

## Compatibility policy

- Additive fields require a declared compatibility window and deterministic
  defaults or explicit absence semantics.
- Breaking changes require a new version and an explicit migration path.
- Mutable tags, branches, unpinned external schemas, and runtime downloads are
  not contract authorities.
- Unknown fields and unknown enum values fail closed unless the owning contract
  explicitly defines forward-compatible handling.
- Air-gapped validation uses the same contract bytes and digests as connected
  validation; it is not a reduced contract mode.

## Consequences

- Repository teams can work independently while sharing one versioned semantic
  contract.
- Generated SDKs and services can prove which exact contract release they use.
- Planning documents remain useful without being promoted to implementation or
  operational evidence.
- Contract evolution requires more deliberate sequencing, but rollback and
  cross-version behavior become testable and reviewable.

## Rejected alternatives

- Let each service own a local schema copy: rejected because drift becomes
  undetectable and compatibility responsibility is unclear.
- Treat the meta repository as the runtime contract package: rejected because
  architecture governance and product contract releases have different owners
  and release cadences.
- Treat research or warm-source files as executable authority: rejected because
  it violates user precedence, clean-room implementation, and reproducibility.
