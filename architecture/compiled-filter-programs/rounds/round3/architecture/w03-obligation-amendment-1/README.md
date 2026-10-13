# W03 obligation-register amendment 1 (W03-PLAN-AMEND-1, MET-ENFORCE-025)

Alpha 2A; 2026-10-13. Status: **CANDIDATE** (under independent review). The W03 plan v2 (`architecture/w03-plan-v2/`,
MET-ENFORCE-024) stays byte-identical; `amendment.json` binds it by SHA-256 and amends its obligation register.

Owner decision Q-HE2B-2 = (a) "HE-003 owns both" (2026-10-13, via the lane monitor, verbatim): "HE-003 owns the real
10-second I07 write timer and the I07 apiserver HTTP/TLS client; HE-002B owns only the logical expiry (the TIMEOUT event,
its abort record, HELD and the IO_AMBIGUOUS answer, as in T59/T61/T62). Record it in HE-002B's design and PR now; amend
the W03 plan's obligation register in the next harness-onion meta packet that touches the plan (like EDGE-2); no extra
packet now."

| Obligation | Change | Packets | Text, ownership or share |
|---|---|---|---|
| I07-6 | ADDED | HE-003 | The real 10-second I07 write timer and the I07 apiserver HTTP/TLS client (`architecture/i07-policy-write-v3/README.md:34`, `:47-48` for the 10-second bound; Q-HE2B-2 (a) for the timer and the HTTP/TLS client) |
| I07-4 | NARROWED | HE-002B | HE-002B owns only the logical expiry of the 10-second bound: the TIMEOUT event, WRITE_TERMINAL IO_AMBIGUOUS `{aborted: UPSTREAM_TIMEOUT}`, HELD and the IO_AMBIGUOUS answer (T59, T61, T62) (`architecture/i07-policy-write-v3/README.md:34`; Q-HE2B-2 (a)) |

| SEC-4 | PACKETS_ADDED | + HE-003 | HE-003: the EFFECT_GATE call site: `main` calls the seal's stage 1 first, reads and checks only the signed configuration, calls stage 2, and exits with a distinct status on any seal error; a source check that `main` calls the seal before any socket or thread |
| HI-7 | PACKETS_ADDED | + HE-003 (HE-008 already listed) | HE-003: the call site, as for SEC-4. HE-008, for EFFECT_GATE: uid 0; the unit's start state (the full root set, or a set already reduced to the target bounding set when CAP_SETPCAP is absent); `planeon_gate_t`'s self permissions the seal needs (capability `setpcap`; process `setcap`, `getcap` and `setrlimit`), with no process `setrlimit` on other domains |
| SEC-QW4 | PACKETS_ADDED | + HE-002S | HE-002S: the steady-state source re-check of the Rust 1.99.0 std paths the gate uses after the seal, recorded in `MODEL_DEFINED.md` with source lines |

The SEC-4, HI-7 and SEC-QW4 changes follow owner decisions of 2026-10-13 (via the lane monitor, verbatim in
`amendment.json`): Q-HE2S-3 (a) and the amendment-scope decision ("add SEC-4 and HI-7 (+HE-003 call site, +HE-008 uid, unit
start state and SELinux self-permissions) and SEC-QW4 (+HE-002S steady-state re-check) to W03-PLAN-AMEND-1"), from the
HE-002S design (two-stage seal, owner decisions Q-HE2S-4 (a) and Q-HE2S-5 (a)).

In `amendment.json`, `scope` is plan v2's scope field ("W03") on every change; I07-4's narrowed ownership is in its own
`ownership` field, and each PACKETS_ADDED change lists the added packets, the full packet list after the change and each
named packet's share.

Every other obligation, packet and toolchain of plan v2 is unchanged. HE-002B has merged in R10 with this scope; I07-6 is
HE-003's.
