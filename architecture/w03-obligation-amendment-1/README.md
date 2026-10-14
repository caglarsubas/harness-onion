# W03 obligation-register amendment 1 (W03-PLAN-AMEND-1, MET-ENFORCE-025)

Alpha 2A; 2026-10-13. Status: **ADOPTED** (independent review round 4: PASS_FOR_SOURCE_PUBLICATION; rounds and review records in `architecture/compiled-filter-programs/status.json`). The W03 plan v2 (`architecture/w03-plan-v2/`,
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
| SEC-4 | PACKETS_ADDED | + HE-003, + HE-008 | HE-003: the EFFECT_GATE call site (below). HE-008, for EFFECT_GATE: the unit uses no systemd seccomp option (W02d's carried F10) and starts the gate in a start state the seal accepts, so that the seal installs exactly the published program |
| HI-7 | PACKETS_ADDED | + HE-003 (HE-008 already listed) | HE-003: the call site (below). HE-008, for EFFECT_GATE: uid 0 and gid 0; a start state the seal accepts (the full root set, or one already reduced within {CAP_SETPCAP, CAP_NET_BIND_SERVICE} whose permitted set holds `kept`, with nothing left to drop when CAP_SETPCAP is absent); the gate stays dumpable, and core_pattern is not a pipe or its helper honours RLIMIT_CORE 0; RUST_BACKTRACE unset; `planeon_gate_t`'s self permissions the seal needs (capability `setpcap`; process `setcap`, `getcap` and `setrlimit`; dir `search` and file `open` and `read` on its own proc entries for `/proc/self/status`), with no process `setrlimit` on other domains |
| SEC-QW4 | PACKETS_ADDED | + HE-002S | HE-002S: the steady-state source re-check of the Rust 1.99.0 std paths the gate uses after the seal, recorded in `MODEL_DEFINED.md` with source lines |

HE-003's share in SEC-4 and HI-7 (the EFFECT_GATE call site): `main` calls the seal's stage 1 first (core limit, ambient,
bounding set and capset down to at most {CAP_SETPCAP, CAP_NET_BIND_SERVICE}, no_new_privs), reads and checks only the
signed configuration, derives `kept` from it (CAP_NET_BIND_SERVICE exactly when the signed I04 port is below 1024, else
nothing) and passes it to stage 2 (a second single-thread check, the drop to {kept}, then the filter), and exits with a
distinct status on any seal error; a source check that no socket or thread is created before the seal completes,
covering the code between the stages.

The SEC-4, HI-7 and SEC-QW4 changes follow owner decisions of 2026-10-13 (via the lane monitor), all verbatim in
`amendment.json`: the amendment-scope decision ("add SEC-4 and HI-7 (+HE-003 call site, +HE-008 uid, unit start state and
SELinux self-permissions) and SEC-QW4 (+HE-002S steady-state re-check) to W03-PLAN-AMEND-1", read literally: HE-003 and
HE-008 are added to SEC-4, and HE-003 to HI-7, which already lists HE-008), Q-HE2S-3, and the seal's shape: Q-HE2S-4,
Q-HE2S-5, Q-HE2S-7 (the gate stays dumpable, amending Q-HE2S-4) and Q-HE2S-8. The HE-002S design they come from is
operator-side today and is published with the HE-002S pull request.

**Shares.** A share adds to the named packet's part of the obligation as plan v2 states it; it never narrows it. An
obligation's text is unchanged by PACKETS_ADDED: for SEC-QW4, "steady state is W02d v3 and T04" gains HE-002S's source
re-check beside them. In `amendment.json`, `scope` is plan v2's scope field ("W03") on every change; I07-4's narrowed
ownership is in its own `ownership` field; each PACKETS_ADDED change lists the added packets, the full packet list after
the change and each named packet's share; `shareRule` states the rule above.

Every other obligation, packet and toolchain of plan v2 is unchanged. HE-002B has merged in R10 with this scope; I07-6 is
HE-003's.
