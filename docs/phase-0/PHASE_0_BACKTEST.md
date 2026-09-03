# Phase-0 back-test and closure record

Recorded 2026-09-04 under packet `MET-P0-002`. The machine authority is
[`phase-0-backtest.json`](phase-0-backtest.json).

## Outcome

Phase-0 is ready to close when this packet passes the signed deny-all offline
run, green self-hosted PR CI, merge, and an exact-main self-hosted replay. The
baseline now accounts for 13 planned repositories, 4 planes, 16 harnesses, 28
services, 87 provider/module records, and 107 task packets. Ten repositories
exist publicly; `mas-harness-runtime-plane`, `mas-harness-model-plane`, and
`mas-harness-execution-plane` remain intentionally uncreated until their later
packets. Planned does not mean implemented.

## Development backlog

| Label | Item | Evidence or gate |
|---|---|---|
| DONE | Phase-0 authority and ordering repairs | Meta PRs 81, 82, 86, 87, and 88 |
| DONE | Three isolated full-tree metadata observations | Meta PRs 83, 84, and 85 |
| DONE | Trust provenance and public-fork runner boundary | Trust PR 5 |
| DONE | Industry public-fork runner boundary | Industry PR 7 |
| DONE | Tenant overview native navigation, full digests, theme parity, stripe-free statuses, and audit RLS | Control PR 9 |
| DONE | Five-source reference-only index | `MET-P0-002`: 905 trees, 4,202 blobs, zero copy authorization |
| DONE | Dependency-license classification | `MET-P0-002`: 15 observed expressions, LGPL release gate, CC-BY content-only gate |
| WAITING | Final Phase-0 replay | Green PR CI, merge, and exact-main CI |
| WAITING | Runtime, model, and execution plane repository bootstraps | Later phase packets; not a Phase-0 readiness blocker |

## Cross-check results

- Signed local acceptance passed under OS-enforced deny-all outbound isolation:
  the readiness validator passed, 179 tests passed, and five environment-only
  cases were explicitly skipped.
- All five user-approved warm repositories are exact-commit pinned. The final
  three entered through signed metadata-only reports; the implementation run
  never opened a warm checkout.
- The path index is the exact union of the 535 task-packet reference paths and
  4,572 observed paths. Every one remains reference-only; no path is
  `COPY_AUTHORIZED`.
- Every SPDX expression discovered in the exact control-plane package lock and
  the three root-owned offline wheel inventories has one fail-closed policy
  class. LGPL and mixed LGPL expressions require an explicit release decision.
  `CC-BY-4.0` is restricted to attributed non-runtime content.
- The knowledge-plane contract rejects archives and compression. Its remaining
  Phase-0 license concern is covered by the shared dependency policy; neither
  point remains an unrecorded gap.
- The tenant overview uses Next.js and preserves the four-plane/sixteen-harness
  onion model with native link semantics and accessible list navigation. Source,
  CI, merge, artifact, deployment, runtime, assurance, and tenant acceptance
  remain distinct.
- Public-repository GitHub Actions run only on an ephemeral, self-hosted,
  credential-free runner through the root-owned offline launcher. No hosted
  runner, paid API, package download, cloud provisioning, or external telemetry
  default is authorized.

## Evidence boundaries

This packet may prove source and offline contract/unit behavior, followed by PR,
merge, and exact-main CI state. It produces no OCI artifact or SBOM, release
signature, deployment, runtime observation, live security/assurance result, or
tenant acceptance. Those later axes remain `NOT_RUN_NOT_IN_PACKET` or
`NOT_RUN_ENV_UNAVAILABLE`, exactly as recorded in the machine report.

The `MET-004` branch reuse predates the enforced one-packet/one-branch rule and
is retained as non-blocking historical debt rather than rewriting Git history.
Repository-plan paragraphs written before the three observation packets that
describe those sources as non-public are historical packet context and are
superseded by the current five-source machine authorities.
