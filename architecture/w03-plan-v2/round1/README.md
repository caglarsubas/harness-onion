# W03 plan v2 — W03-AMEND (the owner's HE-002 decisions)

Alpha 2A; 2026-10-11. Status: **CONTRACT_CANDIDATE_ROUND1_AWAITING_INDEPENDENT_REVIEW**.

`plan.json` (`planeon.internal.w03-plan/v2`) is the successor of `../w03-plan/plan.json` (`planeon.internal.w03-plan/v1`,
MET-ENFORCE-019, sha256 `40b501f48fe0eb13d64d2e0cf7fa542817f0fa3034d86058c233d1a3accaff9a`), which stays byte-identical because later records
pin it (`architecture/backend-distribution-authority.json`, `scripts/validate_backend_distribution.py`). The model
`scripts/w03_plan_v2.py` is `scripts/w03_plan.py` with the v2 schema, the extended owner-decision and required-obligation
lists, and one more check: v2 must equal v1 with the embedded `AMENDMENT` applied, and nothing else.

## Owner decisions (2026-10-11, relayed by the lane monitor)

The owner decided the seven HE-002 questions of the R10 HE-002 design (revision 3) as recommended:

| Decision | Selected | Recorded summary |
|---|---|---|
| Q-HE2-A | a | R10 copies the six I05/I07 v3 contract fixtures and six contract READMEs byte-exact, with no model or validator code; the operator -> harness-engineering buildArtifact edge is registered as an edge-registry record (architecture/artifact-edges/) in W03-AMEND before HE-002 merges, covering HE-000's transport files retroactively; architecture/repositories.yaml is not edited. |
| Q-HE2-B | a | HE-002 is an independent implementation from the pinned contract set; the pinned models and validator lines are specification only where the READMEs are silent, each listed as model-defined behaviour; no line-by-line translation. |
| Q-HE2-C | a | HE-002 splits into HE-002 (I05 logic and the I07 frame and byte checks), HE-002B (the I07 PolicyGate) and HE-002C (the durable journal and failure-marker stores). |
| Q-HE2-D | a | Standard library only; SHA-256 tested against NIST CAVP vectors; revisited at HE-003's TLS. |
| Q-HE2-E | a+b | R10-local vectors R10-L01 to R10-L03, and the supplementary I05-4 vectors in harness-onion (architecture/i05-gate-channel-v3-supplement/, W03-AMEND). |
| Q-HE2-F | a | Plan changes: the HE-002/HE-002B/HE-002C split; the I05 and I07 channel substrate moves to HE-003; HE-002C owns the gate's single journal format, I07 records included; a new HE-002S takes SEC-4 and HI-7 for EFFECT_GATE; the vehicle is the meta packet W03-AMEND. |
| Q-HE2-G | b | The gate opens files only through one audited openat module (the EFFECT_GATE allowlist grants openat, not open); a source check forbids std::fs opens in the gate; T04's trace confirms the per-architecture syscalls; no W02d contract change. |

## What v2 changes

| Item | v1 | v2 |
|---|---|---|
| Packets | 17 | 21: W03-AMEND (meta, this packet) after W03-0; HE-002B, HE-002C and HE-002S after HE-002 |
| HE-002 summary | "I05 and I07 channels, journal and failure marker, against the v3 vectors" | I05 logic with the in-memory journal and marker, the v3 and supplementary vectors, the I07 frame and byte checks |
| HE-003 summary | I04 substrate | also the I05 and I07 channel substrate (listeners, per-frame custody, the 2-second answer bound) |
| I05-3 | HE-002, HE-003 | HE-002C, HE-003 |
| I05-4 | HE-002 | W03-AMEND (the supplementary vectors), HE-002 (R10-L01) |
| I07-2 | HE-007 | HE-002C (the gate's single journal, I07 records included), HE-007 (the writer side) |
| SEC-4, HI-7 | HE-002 among others | HE-002S instead of HE-002 |
| New obligations | — | I05-5 (HE-002), I05-6 (HE-003), I07-3 (HE-002B), I07-4 (HE-003), GATE-OPENAT (HE-002C, T04), EDGE-1 (W03-AMEND) |
| notClaimed | "No module source exists", "No toolchain is installed" | HE-001 merged the scaffold only; no artifact built for or enrolled on a host |

Every other byte of the record is v1's. The v1 rules still hold for v2: every obligation names planned packets, every
planned packet discharges an obligation, every cited source exists.

## Not claimed

No R10 module logic exists; nothing is installed or enrolled; E01-E12 stay OPEN_UNPROVEN.
