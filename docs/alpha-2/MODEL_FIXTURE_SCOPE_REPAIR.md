# Model fixture-copy scope repair — MET-REPAIR-005

Approved: 2026-09-07. This is an authority-only amendment, not model-contract
implementation or native Linux acceptance. It supersedes only the blanket
predecessor-test exclusion for the exact helper edit below. All earlier
publication records and consumed packet bytes remain immutable.

## Finding and evidence

On contracts main `fb365aabfd8c5560e064be5d97ff9f2bcc69c57c`, all three
CON-MODEL-001 offline commands passed through the signed localhost launcher:
758 tests passed, zero failures and zero skips. Log SHA-256:
`563390fc76763cc347c6327b7e219ae2077ad94592a061f92ee97a705fae9af7`.
This is local baseline evidence; it is not a new PR check or model release.

The finding is **SOURCE_INSPECTION_ONLY**, not an executed failing extension:
`tests/golden/test_generated_contracts.py::_copy_generation_inputs` copies a
fixed set of directories into two temporary generator test repositories.
That set lacks the newly required model lock, snapshots and vectors.
Strictly including those sources in the model release manifest would expose
the missing temporary inputs. Do not weaken the generator to accommodate it.

## Sole product exception

The original test file is SHA-256
`856b1d14e0f4d4ee84f6c4f973db412f9905559124091355bec7de85cc818080`.
The [closed record](../../architecture/model-fixture-scope-amendment.json)
pins its exact before/after helper and unchanged prefix/suffix. The
[source-free snapshot](../../architecture/model-fixture-inputs/test_generated_contracts.before.txt)
is our destination test, not a warm-source observation or copied warm test.

CON-MODEL-001 may only:

1. Add `tests/fixtures/model` and `contracts/model-inputs` to the existing
   helper's directory-copy list.
2. Add the exact unconditional `shutil.copy2` of
   `contracts/model-inputs.lock.json` into the temporary contracts directory.
3. Add new independent tests under its existing `tests/model_api/` ownership
   to enforce the exact whole-file transformation and all predecessor tests.

Every other byte, import, existing input and assertion remains unchanged.
No conditional existence checks, missing-input fallback, broad tree copy,
new dependency, test suppression, monkeypatch or test-only generator behavior.
The original three full-suite acceptance commands are unchanged.

## Execution order and backlog

| Phase | ID | Publication checkpoint | Description |
|---|---|---|---|
| Foundation correction | CON-FIX-001 | DONE — source/offline | Untouched 758-test baseline reverified |
| Alpha 1 correction | CTRL-FIX-003 | DONE — source/offline | Control prerequisite merged |
| Alpha 2 authority | MET-REPAIR-005 | ONGOING | This exact helper-scope grant and validation |
| Alpha 2 contracts | CON-MODEL-001 | WAITING | Separate product branch/PR after this publication closes |
| Alpha 2 early gate | CONF-LINUX-001 | WAITING — native qualification | Source kit merged; actual native AMD64/ARM64 evidence absent |
| Alpha 2 runtime | MODEL-001 | WAITING | Requires model contracts and fresh native AMD64 PASS |

The current catalog has 122 packets, thirteen repositories and sixteen harnesses.
The consumed 107/110/114/115/118/120/121-packet records remain historical.
The contract-only source exception remains; no runtime gate is opened.
Native Linux, live transport, artifacts/SBOM, deployment, assurance and tenant
acceptance remain independently unproven. No model-effort transition is due.

## Authority, verification and rollback

Publish MET-REPAIR-005 alone, run its exact declared argv under the existing
signed host boundary, verify required localhost PR CI, merge and independently
replay exact main. Only then sign the revised CON-MODEL-001 packet digest and
start its separate product run. Standing operator activation authority needs
no new administrator prompt, policy installation, key or cache.

Current-count and source-checkpoint assertions in meta tests are updated to
122 and the newly verified source states. Their historical record assertions,
all substantive negative cases, source/native separation and actual test
inventory remain intact. Mutation tests check the full packets, every record
binding, exact historical bytes and helper candidates without executing the
stored product test.

Before product consumption, revert this publication as one unit. Afterwards
publish reviewed superseding authority. Never rewrite earlier failure evidence,
reset activation history, lower source/signature/billing/native gates, or delete
tenant data.
