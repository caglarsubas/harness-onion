# Model API inventory scope repair — MET-REPAIR-006

Approved: 2026-09-07. Authority-only publication; no product edit, accepted
model-contract release or native Linux qualification. The consumed fixture-copy
amendment and all historical records remain byte-identical.

## Finding and evidence

Untouched contracts main fb365aabfd8c5560e064be5d97ff9f2bcc69c57c passed 758
tests, zero failures/skips through the signed localhost offline launcher.
The earlier fixture-copy finding remains SOURCE_INSPECTION_ONLY.

Draft PR 9 at 47c416676b3fba105d7631c1957b9d729daa592e independently reproduced
the lifecycle test's exact-five filename failure: 1048 passed, one failed,
zero skipped; both generated checks passed. All 758 predecessor test IDs and
291 new tests were collected. Log SHA-256:
9176867b7f6137870d6b33dd4c31443f3d98af9794ced6b58831aa4d96d873db.

The readiness review missed this second fixed-inventory occurrence. Its separate
no-server issue was source-inspected and removed from the new model API within
product scope, not recorded as an executed second failure.
Queued CI 34089294582 was cancelled without runner execution: CANCELLED_NOT_PASS.
The draft remains unmerged; these results are not product acceptance.

## Sole additional product exception

Path: tests/model/test_lifecycle_contracts.py.
Original SHA-256:
53f528db6e9d3ce00a8c16e8cf24345a992b2b6130cdfb7d5a6dee02dbaed81e.
Test ID: test_five_openapi_documents_have_local_resolvable_refs_and_no_servers.

Replace only its fixed-five equality predicate with this exact statement:

```python
    assert {
        "control-plane.openapi.json",
        "distribution.openapi.json",
        "operator.openapi.json",
        "status.openapi.json",
        "trust.openapi.json",
    } <= {path.name for path in paths}
```

Preserve every other byte, including the original test name, full file discovery,
the loop over every discovered API, OpenAPI 3.1.1, absent servers member, nonempty
paths, rejection of HTTP(S) references and resolution to existing local files.
Do not fix the inventory to six, hide a file, skip/deselect/xfail/monkeypatch a test,
or weaken generator/release validation. The exact MET-REPAIR-005 helper grant
is unchanged and does not authorize other changes in either legacy file.

[The closed record](../../architecture/model-api-inventory-amendment.json) pins
the before/after predicate, original whole file and unchanged prefix/suffix.
Its destination test snapshot is data only, not an executable meta fixture or
warm-start source. The historical CON-MODEL-001 packet is separately pinned so
MET-REPAIR-005 remains validated against the exact bytes it originally consumed.
Current successor scope and raw bytes are validated independently.

## Execution order and development backlog

| Phase | ID | Publication checkpoint | Description |
|---|---|---|---|
| Alpha 2 authority | MET-REPAIR-005 | DONE — source/offline | PR 98 merged; immutable exact fixture-copy grant |
| Alpha 2 authority | MET-REPAIR-006 | ONGOING | This exact predicate grant and mutation checks |
| Alpha 2 contracts | CON-MODEL-001 | WAITING — authority | Resume draft PR 9 in its own coding run |
| Alpha 2 early gate | CONF-LINUX-001 | WAITING — native qualification | Source kit merged; native evidence absent |
| Alpha 2 runtime | MODEL-001 | WAITING | Accepted contracts plus fresh native AMD64 PASS required |
| Alpha 3–4 | Governed actions and enterprise release | WAITING | Later packet and independent acceptance gates |

Current catalog: 123 packets, thirteen repositories and sixteen harnesses.
This publication does not finish Alpha 2; no phase-end model-effort change is due.

After authority acceptance, the product run must independently test the exact
whole-file transformation, every missing required API and failed safety checks
on added APIs under existing tests/model_api/ ownership. Retain all predecessor
IDs and run the unchanged three full-suite commands. The prior 758-test suite
is a baseline, not a ceiling on new tests.

Normal model-contract completeness review remains: verified route dimensions
when public dimensions are omitted; sorted unique tenant-visible model IDs and
capability consistency; Responses error terminals after partial output; strict
admission-header transport vectors without claiming cryptographic evidence from
simulated verified-context fixtures. Predicate acceptance alone is not completion.

## Verification and rollback

Run only MET-REPAIR-006's eleven exact commands through the existing signed host
launcher: nine validators, full predecessor/current meta and runner tests, then
the zero-bill scan. Keep source/head, local offline, required localhost PR CI,
merge and separate exact-main replay distinct. Re-sign the amended product
packet only in its separate run after authority closure.

Mutation checks reject widened packet fields, altered consumed bytes or evidence,
missing required filenames, fixed-count substitutes, changed test identity,
changed discovery/iteration and weakened safety assertions. They compare stored
product bytes without importing or executing them; actual product negative
conformance tests remain a subsequent obligation.

No root policy/key/toolchain installation, new administrator prompt, warm-source
access, downloads, dependency, hosted runner, paid API, provisioning, telemetry
or live execution. Native AMD64/ARM64, artifact/SBOM, runtime, assurance and tenant
acceptance stay independently unproven.

Before consumption, revert this publication as one unit. After consumption,
publish reviewed superseding authority. Preserve historical evidence, activation
history, tenant data and all independent safety and acceptance boundaries.
