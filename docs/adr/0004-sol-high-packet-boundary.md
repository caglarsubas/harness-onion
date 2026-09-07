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

The authoritative implementation queue contains exactly 132 YAML task packets,
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

`MET-002` is the sole closed exception and is an observation packet, not a
product implementation packet. Its `referenceObservationExecution` may be run
manually only after the packet authority has merged. The preinstalled,
root-owned `/opt/planeon/bin/harness-reference-observe` must verify a signed
source-authority manifest that binds the merged packet digest, exact repository,
commit, 29 indexed blob paths, canonical locked snapshot root, output path, and
the separate `planeon-reference-observer` identity. It establishes deny-all
outbound isolation before opening any source blob, denies every source write,
never executes source code, and emits only the seven closed structural fact
kinds declared by the packet. Descriptions, examples, source text, executable
logic, undeclared paths, recursive directory reads, and copy authority are
forbidden.

The observer invocation is not CI or acceptance evidence. After it emits the
distilled report, the source root is removed from the environment and remains
unavailable to the coding identity. The ordinary signed offline launcher then
validates the committed report with all warm roots hidden. Every packet other
than `MET-002`, including `CON-006`, retains
`PROHIBITED_DURING_IMPLEMENTATION` and cannot declare observation authority.

Twelve conformance packets may declare `liveCampaignExecution`, but this is a
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

- All 132 packets validate against the closed schema with unique IDs and branches.
- The catalog covers all thirteen repositories and its predecessor graph is
  closed, acyclic, and topologically indexed across Alpha 1-4.
- Negative ownership vectors reject unordered overlaps, non-owner Makefile and
  `PORTING.yaml` grants, missing target descriptors, unsafe Make variables, and
  command-owner predecessor bypass.
- Live-envelope vectors reject shell transport, unsafe paths, final acceptance
  escalation, endpoint discovery or kind widening, missing signatures, mutation
  widening, and unknown members.
- Reference-observation vectors reject every packet except `MET-002`, any source
  path outside the exact indexed list, source-code execution, source text,
  recursive reads, write access, public egress, implementation-identity access,
  CI use, and output outside the packet-owned distilled report.
- Acceptance runs through the packet-declared signed offline launcher; direct
  test execution is not packet evidence.

## Consequences

- The approved `MET-REPAIR-002` adds one authority packet, taking the current
  count to 115. It admits two legacy registry-test paths and a function-bounded
  blocked-selection correction in `CON-FIX-001`. The 181-pass/three-failure
  baseline remains failure evidence; the original six-finding JSON is immutable.

- The 2026-09-05 approved `MET-REPAIR-001` publication adds four packets for
  corrective authority, contracts regression, status consistency and production
  overview integration. Its publication count is 114; earlier 107/110-packet audit
  and publication records remain historical. Shared generator changes require
  the complete contracts suite, and integration is an explicit live gate.

- The approved Alpha-2 entry repair adds one authority publication, one exact
  model-usage schema observation and one shared model-contract packet. The
  historical Phase-0 audit retains its 107-packet snapshot. No original-source
  tests or behavioral parity are claimed from independent conformance vectors.
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

## Approved early Linux amendment

MET-LINUX-001 adds three independently owned packets, producing 118 total.
It preserves the historical 107/110/114/115 snapshots, thirteen repositories,
sixteen harnesses and every existing billing/trust/source boundary. Linux
runtime coding gates require separate fresh native evidence; a merged kit or
macOS source test cannot qualify Linux. See ../alpha-2/LINUX_READINESS.md.

## MET-REPAIR-003: bounded conformance repair

The approved amendment adds MET-REPAIR-003 and CONF-FIX-001 (120 packets total).
The historical Linux policy remains its exact 118-packet publication. Only the
amended campaign can add LINUX_READINESS to the shared HANDLERS tuple and the
control-result handler enum; every unrelated definition/member is preserved.
CONF-FIX-001 owns eight explicit paths, not ci/ or tests/ generally. It may only
adjust the named old phase-order test's OS/backend mock, never its assertions.
Explicit suite discovery avoids namespace-package omissions and breaking the
Alpha-1 directory-local import. The fixed run_packet_argv bridge satisfies the
unchanged Linux candidate transport pins. Permissive network errno results and
caller-created live proof descriptors cannot become acceptance evidence.
Makefile, generic dispatch, root installation, workflow, PORTING, dependencies,
source locks, and live endpoint/provisioning authority are unchanged.

## MET-REPAIR-004: assertion-only test ownership

That publication contains 121 packets; the current catalog contains 132. The prior 120-packet amendment and
118-packet policy remain unchanged historical records. One new predecessor and
one exact test-file path are added to CONF-LINUX-001 with an assertion-only grant:
replace the old five-handler count with equality to the exact ordered six-handler
tuple. All other legacy test bytes and the completed CONF-FIX-001 boundaries are
preserved. This publication does not implement a product test, install a runner,
add live authority or qualify native Linux. A consumed amendment is never reopened.

## MET-REPAIR-005: exact model fixture-copy ownership

The new authority publication adds one packet (122 total), not a repository or
harness. Its sole product grant is the pinned _copy_generation_inputs edit in
tests/golden/test_generated_contracts.py; copy the two required model directories
and one input-lock file only. Existing assertions and all other bytes remain
immutable. See MODEL_FIXTURE_SCOPE_REPAIR.md for the strict byte/negative tests.
No test bypass, generator weakening, source access, billing or runtime authority
is added; source, PR, exact-main and native acceptance remain separate.

## MET-REPAIR-006: exact additive API inventory ownership

The current catalog has 132 packets. The consumed MET-REPAIR-005 packet and
record remain unchanged; its whole model-packet pin is read from the immutable
pre-amendment snapshot, while the exact successor is separately validated.
Only the required-five subset predicate is authorized in the named lifecycle
test. Keep all other bytes and checks for every discovered API. This supersedes
the earlier blanket assertion exclusion only at that predicate. No fixed-six
substitute, tests suppression, file hiding or product edits in the meta run.

## Approved trusted live backend enablement — MET-LIVE-001

The [coding guide](../alpha-2/LIVE_BACKEND_READINESS.md) and closed
`architecture/live-backend-roadmap.json` add six sequential conformance packets
(CONF-LIVE-001 through CONF-LIVE-006), not new repositories or harnesses.
This publication recorded 130 packets; the current catalog contains 132. The 123 consumed packet YAML and all existing
architecture/legal/policy/release records remain byte-identical.

Only the six source-enablement packets may proceed before native qualification.
After their source closure, external operator installation and a fresh
independently signed native AMD64 qualification are required before
CTRL-INTEGRATE-001, MODEL-001, EXEC-001 or RUN-001. ARM64 qualification is separate.
CONF-LIVE-006 adds the twelfth possible manual campaign declaration with the
complete eight-command inventory; it grants no installation, target access,
provisioning or paid capability. The old seven-command CONF-LINUX-001 verifier
and all predecessor tests remain unchanged; the new packet has its own exact
pure authority/evidence adapter. Source fixtures never become native evidence.

Current phase/status and completed source checkpoints are in DEVELOPMENT_STATUS.md.
One packet, branch, PR and exact local/CI/main gate per run remains mandatory.

## Approved packet scalar compatibility repair — MET-REPAIR-007

The [exact correction guide](../alpha-2/PACKET_SCALAR_REPAIR.md) adds MET-REPAIR-007 and
CONF-FIX-002: **132 packets**, thirteen repositories, sixteen harnesses and
**twelve** unchanged possible live declarations. The preceding 130 packet YAML
and all existing architecture/legal/policy/release bytes remain immutable.
This is the current supplement to the historical live-backend publication.

CONF-LIVE-001 is blocked after its quoted scalar identity failed before any
acceptance command or test ran. Complete CONF-FIX-002 in a separate product PR
first: change only the exact parser branch and one full-file hash assertion,
then add independent regression evidence in its three new owned files.
No packet reserialization, dependency, root policy, installation or isolation
change is authorized. Resume CONF-LIVE-001 only after corrective source,
local offline, required PR CI, merge and separate local exact-main closure.
Retain its original 103-file/120-test baseline and add corrective provenance
only within its existing paths; the six-root/eight-command inventory is fixed.
Native Linux, live backend, runtime and tenant acceptance remain separate gates.
