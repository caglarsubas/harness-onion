# Alpha 2 — model-usage structural observation

Packet: `MET-OBS-MODEL-001`. Predecessor: `MET-A2-001`, merged through
[PR 90](https://github.com/caglarsubas/harness-onion/pull/90) at
`db74190b89d0438e1f15040004f91fb957fd4c3e`.

The separately authorized localhost observer produced
[`model-usage-v2.json`](../../architecture/observations/model-usage-v2.json).
It contains **162 structural facts from one schema**, not source code, a copied
schema, original test results, or a behavioral compatibility claim.

## Provenance and custody

| Binding | Exact value |
|---|---|
| Repository | `git@github.com:caglarsubas/llm_inference_engine.git` |
| Commit | `6815c21cb10a4d7dc0b4804f6bb223afb4321e97` |
| Single source path | `contracts/prometa-model-usage-v2.schema.json` |
| Git blob | `c3ac327e2989ffbbc2452209e2a32f76be911534` |
| Source bytes SHA-256 | `845f830df424f1626717e60a5dbd05e01187f84e2e96223527cceda521f3d55a` |
| Canonical report SHA-256 | `aa5488bad4528bd4119dfe9134f517403986b6fd45408f34c508929924e764f9` |
| Merged packet SHA-256 | `7493f8f788f982df4cd6b32f3647c82f41b8989feee54fea8740fff5e61f1a9b` |
| Source authority ID | `REF-MODEL-USAGE-V2-001` |
| Observer launcher SHA-256 | `971b534767afd900f00b588cf626b79c029f784f5820608b3803dd27ae967cee` |
| Extractor SHA-256 | `c3ee70583ed0ba85693dcc3da62c40d8039919c1213facdcca3b13e172bc6a04` |

The operator reused the existing signing key, preserved the previous root-owned
trust bundles, and installed the extractor already merged by the predecessor.
The root-owned observer verified its signed source authority, packet bytes,
exact detached source commit and indexed blob, then dropped privileges to its
existing unprivileged execution identity. The logical identity remains
`planeon-reference-observer`; the host maps it to macOS `nobody`. No account or
signing key was created.

The extractor ran with deny-all networking, whole-source read denial plus one
exact-blob exception, source execution denial, all-write denial, and an empty
credential environment. Its outbound canary returned OS `EPERM` (`errno=1`).
Only the private snapshot container received a temporary observer-only search
ACL; that ACL was removed and its original state checked afterward. Source
files and repository permissions were not changed. No source path was passed
to the implementation or CI identities.

The external source-authority signature is verified **before observation**.
The repository report is not itself a standalone signed attestation and does
not contain a private key, host path, UID/GID, signature file, or timestamp.
Offline validation trusts the pinned observed report digest and binds its
metadata to the exact packet, observer artifacts and reference-only source
index. It neither opens a source checkout nor re-runs the observer. Root-owned
signature/rollback evidence remains outside this repository.

## Observed coverage

| Fact kind | Count |
|---|---:|
| `OBJECT_FIELD` | 46 |
| `REQUIRED_FIELD` | 43 |
| `VALUE_CONSTRAINT` | 58 |
| `REFERENCE_EDGE` | 12 |
| `STATE_ENUM` | 1 |
| `SCHEMA_IDENTITY` | 1 |
| `SCHEMA_DIGEST` | 1 |
| Total | 162 |

The report records 41 top-level properties and their required-property facts;
the remaining property/required facts occur at conditional JSON pointers.
Structural observations include:

- Request, invocation and attempt identities, plus route, policy, trace and
  organization/tenant fields. Conditional facts retain their JSON pointers;
  their presence is not a runtime identity or authorization guarantee.
- Nullable non-negative token counters/budgets, duration/first-token timing and
  `cost_micros`. A required property can still permit null. No measured usage,
  price, billing event or authoritative ledger behavior was observed.
- The outcome enum `ok`, `error`, `timeout`, `denied`, and null; HTTP-status
  bounds; identity-pattern constraints; and a closed top-level object.
- Historical `prometa.model-usage.v2` / `prometa.model-usage` markers. These are
  observed source identifiers, not names chosen for the tenant-neutral public API.

The seven-kind extraction grammar is intentionally lossy: it omits prose,
examples and executable implementation, and does not recreate a full schema
validator or establish complete source semantics. Regex patterns, schema IDs
and references remain inert data; the validator does not execute patterns,
fetch schema URLs, import source modules, or resolve source files.

## Validation and negative vectors

[`validate_model_usage_observation.py`](../../scripts/validate_model_usage_observation.py)
requires canonical bounded UTF-8 JSON, rejects duplicate members/non-finite
numbers/links, fixes every provenance digest and binding, and checks the closed
fact grammar, counts, ordering, uniqueness, local reference edges and required
property relationships. Source-index admission remains `BLOB_PENDING` /
`REFERENCE_ONLY_PENDING_PATH_REVIEW`; this report grants no copy rights.

[`test_model_usage_observation.py`](../../tests/test_model_usage_observation.py)
uses only the distilled report and repository-local metadata. Mutation vectors
reject packet/report/blob/artifact substitutions, widened source paths or
isolation, unknown/missing/malformed facts, duplicate observations, prose and
host-path leakage, copied-source authority, and false behavioral/acceptance
claims. These are independently authored destination-validator tests, never
original-source tests or captured source-runtime outcomes.

Run acceptance only through this packet's exact `offlineExecution.wrapperArgv`
under the separately signed, packet-pinned offline host launcher. Its declared
argv sequence validates the report, runs its test file, and validates readiness
and reuse. Source observation is manual and separate; it is forbidden in CI.
Local, PR, merge and exact-main outcomes must be recorded separately in the PR
completion checkpoint rather than inferred from this source document.

## Evidence boundary and roadmap

| Phase / dimension | State | Meaning |
|---|---|---|
| Alpha 2 · `MET-A2-001` | DONE — source/CI/merge/offline | Prerequisite authority published |
| Alpha 2 · `MET-OBS-MODEL-001` observation | DONE — structural report only | One isolated observation produced the pinned facts |
| Alpha 2 · `MET-OBS-MODEL-001` source/CI/merge/offline | Separate gates | Consult the matching PR and exact-main checkpoint |
| Original source tests | `NOT_RUN_ENV_UNAVAILABLE` | No original tests were imported or run |
| Original source behavioral parity | `NOT_ESTABLISHED` | Structural facts are not equivalence evidence |
| Source execution | `DENIED` | No source application or test code executed |
| Copy authority | `NONE` | No adaptation, translation, copying or porting authorized |
| Alpha 2 · `CON-MODEL-001` | WAITING — next | Shared API/usage contracts and independent vectors |
| Alpha 2 · `MODEL-001` | WAITING | Clean-room implementation after the contract release |
| Live release/runtime/assurance/tenant acceptance | `NOT_RUN_ENV_UNAVAILABLE` | Independent gates; not inferred from this packet |

`CON-MODEL-001` must pin this merged report and map every observed field to an
independently designed tenant-neutral field, an explicit unsupported case or a
documented omission. Nullable usage must not be replaced by invented measured
values; source fields do not authorize tenant identity, paid routes or billing.
The original-source baseline remains unavailable even if destination contract
vectors later pass.

## Rollback

Before a consumer runs, revert only this packet's report, validator, tests and
summary. Preserve the original observer/runner trust bundles for operator
rollback. Do not modify a warm source or rewrite historical observations. A
consumed report must be superseded through another authorized packet, not
silently regenerated under the same digest or broadened source scope.
