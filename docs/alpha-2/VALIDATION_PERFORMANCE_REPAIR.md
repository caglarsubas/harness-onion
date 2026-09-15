# Bounded META validation-performance repair

MET-PERF-010 · Alpha2 ONGOING · implementation candidate, not accepted release.

## Scope and evidence
The observed MET-DIAG-001 draft workload exceeded its signed window. Coarse
receipt intervals included readiness32.59s, credential predecessor variants26.50s
and canonical reuse18.33s. They include setup/output/scheduling and are not CPU
profiles. The final open reuse case is not a proven deadlock or sole cause.
No speedup has been measured. Retain the failed diagnostic and all old attempts.

This independent packet starts from accepted MET-ADOPT-002 at
b2705835139ece8954cf36f66ab0b5e8d8b3c10b, not draft009. It owns17 local digest
lookup optimizations and one temporary-fixture safe serialization helper.
No global digest/result/parsed-object cache, altered parser, early-exit change,
deleted assertion, reduced mutation matrix, fixture-lifetime change or timeout
increase is permitted. All original fresh file/read/digest checks remain.
Hash the same immutable input once during a complete recipe scan; keep every
independent transformation hash and uniqueness check.

The fixture helper uses already pinned PyYAML6.0.2 CSafeDumper where available
and SafeDumper otherwise. It preserves UTF-8, sort_keys=False, width1000 and
structural types/order/aliases/cycles. Arbitrary objects still reject. Canonical
repository data and all product parsing/serialization remain unchanged.

## Source-accounting boundary
The exact paths, logic regions, input locks, evidence hashes, budgets and new
test vectors are in ../../architecture/validation-performance.json and the
task packet. The separate authority binds all166 previous packet YAML, exact
before/after replacements and current source. Mechanical catalog counts become
167. Prior JSON authority and all original packet YAML remain byte-identical.
Stored source is data, never imported or executed.

Only the named17 functions, tests/test_reuse.py::_write_yaml/import and newly
owned files may receive logic changes. Other owned files are mechanical
count/owner/current-first accounting or current navigation only. No warm source,
product repository, API, license, dependency, runner, key or host-power changes.

## Full acceptance and finite limits
Preserve all36 predecessor argv; insert the new validator before full pytest.
All37 commands, full nested and outer suites, exact inherited isolation skips
and final zero-bill scan must complete through the existing signed localhost
launcher. No direct subset, collect-only, diagnostic, hidden warm-up or extra
baseline is authorized.

Budgets: LOCAL3 total, CI2, independent LOCAL exact-main1. LOCAL1/2 remain
consumed; the approved count-accounting amendment grants only LOCAL3 as one
supplemental attempt. No old reservation or audit is reset. Reserve before signing/
activation, failures after reservation consume an ordinal, one active run,
no reset or transfer. A source fix needs remaining LOCAL allowance and fresh
exact-source LOCAL success before CI. CI retry uses its own remaining ordinal.
Nested420s/root900s/workflow15min remain; complete LOCAL/exact-main wall time
must be <=750s. Functional pass and performance failure are separate; never
merge from a partial or over-budget repair claim.

Source inventory and the new130 parametrized regression cases are accounted
separately from ten expanded inherited cases: five custody-handoff and five
credential-lifecycle field mutations now include MET-PERF-010. Their original
test definitions remain unchanged. Thus140 total additional cases supplement
the base's recorded3726 nested/3975 outer passes. Expected candidate:3866 nested/4115 outer passes,
each with the same ten inherited skips; these are expectations, not results.
The earlier3856/4105 forecast omitted the ten inherited expansions. LOCAL2
completed all37 commands,3866/4115 passes and ten skips each in475.10s, but its
original count-gate audit remains unaccepted and retained. Corrected source must
pass fresh full LOCAL3 before CI; no retrospective acceptance or speedup claim.
Retain old test identities, parameters and assertions through exact data-only
recipes. Compare serializer shape rather than equality alone. Fresh-read,
duplicate-match, unsupported-object, tampered-input, source and budget-negative
vectors remain mandatory.

LOCAL must pass before CI. Create one branch/PR, monitor pinned self-hosted
checks, apply only bounded fixes, merge only exact-head green, then run separate
LOCAL exact-main. Do not promote GitHub merge or source tests to runtime,
artifact, native-Linux, assurance or tenant acceptance. Retire the ephemeral
runner after the gate, and keep every output/request/reservation digest.

## Preserve pending work and roadmap
PR124 remains draft1886aa2272f8d8bc73da60ebd7a6738f288de5fb. Its five LOCAL
attempts and both MET-DIAG-001 reservations remain consumed. This packet does
not edit/rebase/close/merge/retry that draft or run CONF-DIAG-003. Reconciliation
after this packet requires separate reviewed source/budget authority.
The adopted [16-harness paper/OSS map](HARNESS_PAPER_REPOSITORY_MAP.md) and
[provider roadmap](PROVIDER_ADOPTION_ROADMAP.md) remain unchanged.

| Phase | ID | Status | Description |
| --- | --- | --- | --- |
| Phase0/Alpha1 | Historical foundations | DONE_RECORDED | Source/offline evidence only |
| Alpha2 | MET-ADOPT-002 | DONE_RECORDED | Research/reuse-first map retained |
| Alpha2 | MET-DIAG-001 | DONE_OBSERVATION | Incomplete workload, no acceptance |
| Alpha2 | MET-PERF-010 | ONGOING | Bounded validation repair; full gates required |
| Alpha2 | MET-PERF-009 / PR124 | BLOCKED | Separate unaccepted draft, exhausted LOCAL |
| Alpha2 | CONF-FIX-007 / CONF-DIAG-003 | WAITING | Product work not advanced |
| Alpha2 | CONF-LIVE-004/005/006 / CONF-A2-001 | WAITING_PREDECESSOR_CORRECTION | Native/profile gates retained |

Alpha2 remains open; model-effort transition NOT_DUE.
Before merge, failed work remains draft. After merge, any revert/successor has
its own gates; no history reset, force push, old evidence rewrite or automatic
runtime rollback. Stop on scope/contract/billing/isolation drift or exhaustion.
