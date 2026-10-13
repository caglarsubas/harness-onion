# Artifact edge registry — v2 records (MET-ENFORCE-025)

Alpha 2A; 2026-10-13. Status: **CANDIDATE** (under independent review). The v1 record
(`operator-harness-engineering.json`) and its `README.md`, published by W03-AMEND (MET-ENFORCE-024), stay byte-identical.
Its first rule applies: "a new file, or another version of a listed file, needs a new registry record (a harness-onion
meta packet) before any consumer packet uses it". This packet adds two records.

## `operator-harness-engineering-v2.json` (operator -> harness-engineering, buildArtifact)

`planeon.internal.artifact-edge-registry/v2`: v1's 17 artefacts, unchanged, plus the 14 compiled seccomp programs that
`architecture/compiled-filter-programs/` publishes (owner decisions Q-HE2S-1 (a) and Q-HE2S-2 (a), 2026-10-13, quoted in
the record). `supersedes` binds v1 by SHA-256.

| Programs | Consumer packet | Consumer path | Status |
|---|---|---|---|
| EFFECT_GATE (aarch64, x86_64) | HE-002S | `host-enforcement/contracts/seccomp-v3/EFFECT_GATE.<arch>.bpf` | REGISTERED_BEFORE_USE |
| OBSERVER | HE-004 | `…/OBSERVER.<arch>.bpf` | REGISTERED_BEFORE_USE |
| BROKER, WORKER | HE-005 | `…/BROKER.<arch>.bpf`, `…/WORKER.<arch>.bpf` | REGISTERED_BEFORE_USE |
| HOST_CONTAINMENT | HE-006 | `…/HOST_CONTAINMENT.<arch>.bpf` | REGISTERED_BEFORE_USE |
| POLICY_WRITER | HE-007 | `…/POLICY_WRITER.<arch>.bpf` | REGISTERED_BEFORE_USE |
| SERVER | — | — | PUBLISHED_UNREGISTERED |

The role-to-packet mapping is the W03 plan v2's (SEC-4 and HI-7 packets). SERVER's consumer is decided by HE-008's design;
no consumer may hold SERVER's programs until a later record registers one. A later packet that holds a program under
another path, or another version, needs a new record. v1's statuses are kept as recorded (HE-002's contract files were
REGISTERED_BEFORE_USE when v1 was published; HE-002 has since merged).

## `conformance-labs-harness-engineering.json` (conformance-labs -> harness-engineering, buildArtifact) — EDGE-2

Owner decision A13 (2026-10-11, via the lane monitor): "a separate later record in the next harness-onion meta packet that
touches the registry; R12's CONF-CI-001 bootstrap is the precedent until then". R12 (conformance-labs) holds HE-000's four
harness-onion transport files. They were read at R12's CONF-CI-001 merge commit `9766c9cb02383968499a109c36f4b7a18ec532b0`
(PR #21; the latest commit touching each of them on 2026-10-13), and only those four files:

| Path | Mode | sha256 | Relation | Status |
|---|---|---|---|---|
| `ci/verify-offline.sh` | 100755 | `778cb0faf597…` | BYTE_IDENTICAL | IN_USE |
| `ci/warm-source-isolation.sh` | 100644 | `f717f62fb1c9…` | BYTE_IDENTICAL | IN_USE |
| `ci/network_canary.py` | 100755 | `1be4a837c4a5…` | BYTE_IDENTICAL | IN_USE |
| `ci/run_packet_argv.py` | 100755 | `c2ed0852fa49…` | BYTE_IDENTICAL | IN_USE |

Each equals the provider file v1 lists at `0e747049`. R12 holds `run_packet_argv.py` unmodified (R10's is DERIVED).
`harness-engineering` consumes no repository in any graph of `architecture/repositories.yaml`, so neither edge can close a
cycle; `repositories.yaml` is unchanged.
