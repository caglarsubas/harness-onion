# Assertion-only Linux test ownership — MET-REPAIR-004

Phase: Alpha 2 authority. Approval: 2026-09-07. Publication scope only.
Current catalog: 121 packets, thirteen repositories, sixteen harnesses.

## Evidence and exact gap

CONF-FIX-001 completed in conformance PR 4 at
`07453d3e6313c836426545c454380176bc2a2ee1`. Required self-hosted CI
`34052209212` / job `101537713213` passed its exact PR merge ref. Its separate
signed local exact-main replay passed 83 tests with zero skips: meta 37, parity
14, alpha1 9, runner-boundary 23. All 60 original test IDs remain present and
the new inventory suite accounts for every collected module/method. This is
source evidence, not native Linux, live campaign, or tenant acceptance.

Read-only inspection of that exact product base confirms:

- `tests/meta/test_canonical_schema.py` SHA-256 is
  `4ff004974fc75c6ea15010eedb9d1596c002330b33596c64a888622f0bd02c8f`.
- `CanonicalSchemaTests.test_closed_vocabularies` asserts exactly five handlers.
- The already approved Linux packet must append `LINUX_READINESS` to the old
  five handlers, but did not own this existing test file.
- Adding the handler without the missing test grant would conflict with the
  regression. This diagnosis is SOURCE_INSPECTION_ONLY; no product was edited
  or hypothetical handler run in this meta publication.

## One exact additional path and statement

The sole additional product path is `tests/meta/test_canonical_schema.py`.
Only replace the following statement inside the named method:

```python
self.assertEqual(len(HANDLERS), 5)
```

with this exact statement:

```python
self.assertEqual(HANDLERS, ("STATIC_ASSERTION", "SCHEMA_ASSERTION", "LIFECYCLE_ASSERTION", "EVENT_ASSERTION", "ENVIRONMENT_CAPABILITY", "LINUX_READINESS"))
```

Preserve every other byte, including the result-state and evidence-axis
assertions, all other methods, imports and vectors. A count of six, subset,
membership, minimum, dynamic expectation or skip/xfail is not an equivalent
grant: the ordered literal tuple detects extra, missing, duplicate, changed and
reordered handlers. The future Linux-owned tests compare all three handler
views: Python HANDLERS, campaign schema and control-result schema.

New negative cases remain in `tests/platform/linux_baseline/`. They may reuse
the existing inventory helper unchanged and must cover all five declared
suite roots and retain all 83 predecessor test IDs. This amendment does not
grant write access to `tests/fixes/runner_boundary/`, the older Alpha-1 imports,
or any offline/live runner path. No new helper/session authority is introduced.

## Consumed history and current validation

`architecture/linux-readiness.json` remains the exact 118-packet historical
policy. `architecture/linux-readiness-amendment.json`, MET-REPAIR-003 and
CONF-FIX-001 remain byte-identical consumed publications. Their inspection-time
pending findings are not retrospectively rewritten as execution evidence.

The new `architecture/linux-test-ownership-amendment.json` pins that historical
record, the former Linux packet digest, the current product source evidence,
the original test and the exact new packet digests. Its strict validator rejects
unknown/missing members, scalar-type substitutions, changed evidence,
extra paths, broad directories, different assertion rules and false native/live
claims. Current validators compose the two additive deltas against the original
Linux packet expectation; they do not discard the historical constraints.

CONF-LINUX-001 changes only by one predecessor, one allowed path and bounded
contract/deliverable/evidence additions. All its other values are unchanged:
seven ordered offline/live commands, empty prefetch, source prohibition, host
launcher, dual signatures, independent capacity, namespace/quota/mutation
admission, freshness, native AMD64 gate, ARM64 qualification and rollback.

MET-REPAIR-004 implements only meta authority, validators, tests and documentation.
It neither modifies the product test nor implements the campaign. Its nine
declared commands run through the existing signed localhost offline launcher:
seven validators, complete predecessor/candidate/new tests, then zero-bill scan.
Local source, required PR CI, merge and local exact-main remain separate gates.
Root installation, toolchains, keys, sudoers, dependencies, warm-source access,
cloud/billable resources, hosted runners and live execution remain excluded.

## Development checkpoint

| Phase | ID | Status | Description |
| --- | --- | --- | --- |
| Alpha 2 authority | MET-REPAIR-003 | DONE | Consumed R1-R4 scope publication |
| Operator prerequisite | OPERATOR-RUNNER-002 | DONE externally | Conformance admission and fresh installed verification |
| Alpha 2 correction | CONF-FIX-001 | DONE | Source/CI/merge/local exact-main; 83 tests |
| Alpha 2 authority | MET-REPAIR-004 | ONGOING | This assertion-only publication; CI/merge/main independently pending |
| Alpha 2 qualification | CONF-LINUX-001 | WAITING | Its own product source PR, then independently qualified native Linux |
| Alpha 1/2 runtime | CTRL-INTEGRATE-001 / MODEL-001 / EXEC-001 / RUN-001 | WAITING | Fresh native AMD64 gate |
| Alpha 4 | Full conformance and tenant acceptance | WAITING | Independent enterprise qualification |

Linux and the usable external live isolation/proxy backend remain
NOT_RUN_ENV_UNAVAILABLE. Source merge cannot open the runtime-coding gate.
Unprotected conformance main remains a separate governance limitation; the
previous verified-CI merge gate was enforced manually, and this publication
does not change GitHub settings. No model-effort transition or full-phase
completion is due.

Rollback an unconsumed amendment as one compatibility unit. After a consumer
starts, publish reviewed superseding authority and retain the original record,
failures and signatures. Never reset activation history or operationally
restore the retired unsafe live adapter.
