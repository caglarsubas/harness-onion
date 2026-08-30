# ADR 0004: Sol-High task packets are the executable change boundary

- Status: Accepted
- Date: 2026-08-30
- Decision owner: Harness Engineering maintainers
- Packet: `MET-004`

## Context

The platform spans thirteen repositories, sixteen independently selectable
harnesses, four delivery phases, and both offline and environment-dependent
verification. A repository roadmap is too broad to execute safely in one coding
run, while an informal prompt does not define path ownership, predecessor
authority, rollback, or evidence. Live conformance introduces an additional
risk: a command that can reach a tenant Kubernetes environment must not inherit
authority from source validation or CI.

The public planning bootstrap seeded the proposed packet corpus so it could be
reviewed before product work. That publication was not evidence that any packet
had executed. This decision closes the format and validation rules that turn the
catalog into the implementation queue.

## Decision

The authoritative implementation queue contains exactly 91 YAML task packets,
ordered in the Alpha 1-4 index. Each coding run implements exactly one packet on
its unique `codex/<packet-id>-<slug>` branch and changes only that packet's
repository-local `allowedPaths`. Every predecessor must exist, the complete
predecessor graph must be acyclic, and the catalog order must place each
predecessor before its consumers.

`schemas/task-packet.schema.json` is the closed Draft 2020-12 structural
authority. `scripts/validate_readiness.py` enforces catalog, repository,
predecessor, source-reuse, command, and index semantics. The pure
`scripts/validate_packet_ownership.py` layer enforces shared-path ordering,
bootstrap ownership of `Makefile` and `PORTING.yaml`, packet-local Make target
descriptors, conformance dispatch, and `harnessctl` command registration. Schema
success alone is therefore necessary but insufficient.

Every offline command is an argv array. The selected packet is hash-pinned and
executed only through `offlineExecution.wrapperArgv` in one OS-isolated,
deny-all-outbound process tree. Shell transport, recursive offline wrappers,
runtime downloads, cloud provisioning, paid providers, mutable authority, and
warm-source filesystem access remain denied.

Ten conformance packets may declare `liveCampaignExecution`, but this is a
separate manual post-merge path. The external root-owned launcher accepts only
`HARNESS_LIVE_EXECUTION_ENVELOPE`. The closed envelope binds the exact packet,
command set, conformance kit, campaign definition and release, launcher, bundle,
tenant, environment, evidence axes, zero-cost mutation policy, fixed endpoints,
trust stores, validity window, and nonce. Independent platform and tenant
signatures cover the same RFC 8785 payload; a separate capacity-operator
authorization binds pre-existing zero-incremental-cost capacity.

The envelope may authorize only `DEPLOYMENT`, `RUNTIME`, `SECURITY`, `ASSURANCE`,
and `TENANT_ACCEPTANCE_CANDIDATE` evidence. It cannot create source, CI, merge,
artifact, release-signature, or final tenant-acceptance evidence. Missing
authority, capacity, or target produces `NOT_RUN_ENV_UNAVAILABLE`, never a pass.

## Verification

- All 91 packets validate against the closed schema with unique IDs and branches.
- The catalog covers all thirteen repositories and its predecessor graph is
  closed, acyclic, and topologically indexed across Alpha 1-4.
- Negative ownership vectors reject unordered overlaps, non-owner Makefile and
  `PORTING.yaml` grants, missing target descriptors, unsafe Make variables, and
  command-owner predecessor bypass.
- Live-envelope vectors reject shell transport, unsafe paths, final acceptance
  escalation, endpoint discovery or kind widening, missing signatures, mutation
  widening, and unknown members.
- Acceptance runs through the packet-declared signed offline launcher; direct
  test execution is not packet evidence.

## Consequences

- A Sol-High coding run has a deterministic scope, predecessor contract,
  verification command set, evidence expectation, and rollback boundary.
- Harness modularity remains independent of repository count: packets can evolve
  one harness capability inside a shared plane repository without widening the
  change boundary.
- Live environment evidence remains possible for Kubernetes, OpenShift, and
  air-gapped targets without permitting PR CI to hold tenant credentials or
  cost-creating authority.
- Any public-contract, ownership, tenant-isolation, destructive-data,
  licensing, or billing-boundary change requires a revised packet and review
  before implementation.

## Rollback

Revert the task-packet schema, catalog, validators, tests, and this decision as
one compatibility unit. Never retain a partially accepted packet format or
reinterpret previously recorded evidence under a different schema.

## Rejected alternatives

- Execute repository plans directly: rejected because their scope spans many
  independently reviewable changes.
- One branch containing several ready packets: rejected because path ownership,
  evidence, and rollback would no longer be packet-local.
- Treat JSON Schema as the only validator: rejected because graph, ownership,
  index, and cross-file invariants are semantic.
- Run live campaigns in GitHub Actions: rejected because CI must remain
  credential-free, deny-all-outbound, zero-bill, and independent of tenant
  environments.
- Let one signer authorize a live run: rejected because platform release and
  tenant execution consent are separate authorities.
