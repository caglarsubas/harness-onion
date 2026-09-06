# R1-R4 conformance readiness repair — MET-REPAIR-003

Phase: Alpha 2 authority. Approval: 2026-09-06. Publication scope only.
Evidence: SOURCE_INSPECTION_ONLY; no exploit, native target or runtime failure
was reproduced. This record does not downgrade or relabel earlier packet-local
PASS results; it exposes missing cross-packet coverage and future Linux gates.

## Exact reviewed baseline and findings

Owned conformance source: CONF-A1-001 main
30877d289d389b29d3da9eb9a3c083c9ebc33382, PR 3.
Exact file pins, absent paths, unchanged Makefile/dispatcher/toolchain pins,
and the completed Linux candidate are in
[linux-readiness-amendment.json](../../architecture/linux-readiness-amendment.json).
No warm-start checkout was opened or copied. Implementation runs consume only
these documentary pins, never a path to another product or warm checkout.

| ID | Evidence reviewed | Impact | Owner |
| --- | --- | --- | --- |
| R1 | models.HANDLERS and control-result.schema.json enumerate five handlers; neither path was in the Linux campaign grant | LINUX_READINESS output would conflict with its published result contract | CONF-LINUX-001, after this amendment |
| R2 | tests/meta and tests/parity have no package initializer; planned tests/platform also lacks one; Python 3.12 unittest does not recurse into such directories | The declared root discovery cannot establish full predecessor/new-suite coverage | CONF-FIX-001 plus amended campaign argv |
| R3 | Both wrapper and run_packet.py require darwin-sandbox; the native candidate pins run_packet_argv.py, which is absent; canary constructs a socket before its exception handler and accepts route/timeouts | Native Linux dispatch is incompatible and network evidence may be falsely accepted | CONF-FIX-001 |
| R4 | Inner live adapter accepts a fixed descriptor payload and invokes caller argv without trusted descriptor origin/signature checks | Caller-controlled data is mistaken for live-session proof; no real compromise is claimed | CONF-FIX-001 |

The existing live launcher deliberately returns ISOLATION_BACKEND_UNAVAILABLE.
That fail-closed absence remains. Neither accepting a marker nor signing a fixture
can complete an external OS boundary or independently certify tenant acceptance.

## Ordered, single-packet work

| Phase | ID | Publication status | Description |
| --- | --- | --- | --- |
| Alpha 2 foundation | MET-LINUX-002 | DONE, source only | PR 95, c37f2b7, candidate 9065b785... |
| Alpha 2 authority | MET-REPAIR-003 | ONGOING | This scope, ordering, discovery and negative-test publication |
| Alpha 2 correction | CONF-FIX-001 | WAITING, next | Offline transport/canary correction and unsafe live-adapter retirement |
| Alpha 2 qualification | CONF-LINUX-001 | WAITING | Campaign source followed by independently authorized native Linux evidence |
| Alpha 1 integration | CTRL-INTEGRATE-001 | WAITING, native AMD64 gate | Authenticated durable tenant overview |
| Alpha 2 contracts | CON-MODEL-001 | WAITING, own predecessors | Contract-only source exception; no runtime claims |
| Alpha 2 runtime | MODEL-001 / EXEC-001 / RUN-001 | WAITING, native AMD64 gate | Model, execution and edge implementations |
| Alpha 4 | Full conformance and tenant acceptance | WAITING | Existing independently executed certification matrix |

The catalog is now 120 packets, still thirteen repositories and sixteen harnesses.
The original 118-packet Linux policy is byte-identical; its status and count are
historical publication facts. The new amendment is checked independently and
cannot overwrite the old policy or any 107/110/114/115 snapshot.

No model-effort transition is due. A packet publication is not full-phase completion.

## R1: bounded contract addition

Only append LINUX_READINESS to src/harness_conformance/models.py HANDLERS and
schemas/v1alpha1/control-result.schema.json properties.handler.enum. Preserve
every old value and order, every other Python definition byte and every other
schema member. The existing campaign-schema/Python-validator integration must
agree with both views. No new result state, tenant evidence axis, enum replacement
or unrelated shared-code cleanup is authorized.

Tests must compare all three handler representations and prove unchanged old
campaign reports/evidence for fixed inputs/time/run IDs. The amendment does not
itself modify or claim acceptance of a public product schema.

## R2: full test-discovery closure

Use separate direct argv for each named suite. This avoids both missing
namespace-package recursion and Alpha-1's existing directory-local contract
import. No package initializer or legacy Alpha-1 import rewrite is needed.
A new tests/platform package at the root of sys.path could also shadow the
standard-library platform module; explicit roots avoid that hazard.

CONF-FIX-001 runs these first four roots; CONF-LINUX-001 runs all five:

1. tests/meta
2. tests/parity
3. tests/alpha1
4. tests/fixes/runner_boundary
5. tests/platform/linux_baseline

Each uses python3 -m unittest discover -s ROOT -p test_*.py as a direct argv
array, followed in the campaign packet by the unchanged generic campaign and
evidence-verify Make targets. The campaign's live command array equals its
complete offline array; live execution remains manual through the external
launcher, never through CI or a copied command.

Inventory tests must prove each root collects tests, every existing test module
is accounted for and no new file becomes an unnoticed exclusion. Empty/missing
suites, skips introduced to hide failures, dropped vectors or fixture replacement
cannot pass. Acceptance log counts are recorded per suite, never inferred from
an exit-zero discovery that collected nothing.

## R3: narrow offline transport compatibility

CONF-FIX-001 owns only the four existing ci files named in its packet plus the
new fixed ci/run_packet_argv.py bridge, one mock-bounded old regression file,
its new tests/fixes/runner_boundary/ tree and report. Makefile, generic dispatcher,
descriptors, workflow, toolchain and PORTING stay untouched.

Both wrapper and Python executor must check actual OS against exactly
darwin-sandbox or linux-firejail; unknown/absent/mismatched values fail before
packet commands. The bridge only delegates fixed argv to existing run_packet.py.
The independently signed whole source tree covers that implementation, while
the existing Linux kit's three transport pin names remain unchanged.

Preserve no-follow root packet custody, direct argv, prefetch/acceptance ordering,
single process tree, digest rechecks and a closed child-environment allowlist.
Markers are diagnostic fields established after the trusted host boundary;
they are not permission to run outside that boundary. Do not expose authority,
warm paths, caller credentials, inherited sockets or unknown environment values.

Handle denial during socket creation on Linux and connect on macOS. Only the
backend's EPERM/EACCES counts; successful access, unsupported address family,
timeout, DNS or route failure never establishes isolation. All real probes run
only inside already authorized host isolation. New unit tests use controlled
fake sockets, not public requests.

The old tests/parity/test_packet_runner.py grant permits only explicit OS/backend
mock setup in its phase-order case. Existing commands, assertions and other tests
remain intact. No blanket regression-rewrite authority is granted.

## R4: retire unauthenticated execution, not invent live authority

ci/verify-live-campaign.py must remove subprocess/exec and reject with
DIRECT_LIVE_ADAPTER_FORBIDDEN. Caller-created pipe/file/memfd contents, magic
bytes, environment markers or removing CI variables must not invoke any command.
Negative tests must observe zero child execution and zero credential/network
access; they must not run actual live campaign argv.

The existing unavailable external isolation/proxy backend remains unavailable.
This correction does not create a replacement proof descriptor, session signer,
live launcher, provisioning helper or endpoint policy. The amended campaign may
not re-enable this retired adapter. A future usable integration requires its own
reviewed authority and independent external installation, not an online fallback.

## Acceptance, limitations and rollback

MET-REPAIR-003 runs its exact eight declared commands through the existing
signed localhost offline launcher: six authority validators, the full unchanged
meta/candidate suites plus these amendment tests, then zero-bill validation.
No product files, privileged installation, live endpoints or dependency caches
are changed by this publication.

Source, local head, required self-hosted CI, merge, local exact-main, candidate
packaging, root installation, native build/runtime, assurance and tenant
acceptance stay separate. R1-R4 remain WAITING_IMPLEMENTATION in the immutable
amendment even after this authority PR merges. Subsequent PRs/evidence records
own implementation closure, not retroactive edits to this inspection record.

Native Linux remains NOT_RUN_ENV_UNAVAILABLE until existing zero-incremental-cost
capacity, pinned native tools/caches, reviewed installation, actual isolation
negatives and signed build/runtime/campaign evidence exist. Native AMD64 is
mandatory before runtime coding; ARM64 needs independent qualification.
Removing source defects does not make macOS results into Linux evidence.

Revert an unconsumed amendment as a unit. After a consumer starts, publish a
reviewed superseding packet. Never operationally restore the unsafe live path,
erase failed runs, relax packet or source custody, create capacity or reverse
tenant data. No administrator password or authentication prompt is required for
routine existing signed packet activation.
