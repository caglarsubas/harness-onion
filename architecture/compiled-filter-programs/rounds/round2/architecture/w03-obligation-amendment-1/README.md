# W03 obligation-register amendment 1 (W03-PLAN-AMEND-1, MET-ENFORCE-025)

Alpha 2A; 2026-10-13. Status: **CANDIDATE** (under independent review). The W03 plan v2 (`architecture/w03-plan-v2/`,
MET-ENFORCE-024) stays byte-identical; `amendment.json` binds it by SHA-256 and amends its obligation register.

Owner decision Q-HE2B-2 = (a) "HE-003 owns both" (2026-10-13, via the lane monitor, verbatim): "HE-003 owns the real
10-second I07 write timer and the I07 apiserver HTTP/TLS client; HE-002B owns only the logical expiry (the TIMEOUT event,
its abort record, HELD and the IO_AMBIGUOUS answer, as in T59/T61/T62). Record it in HE-002B's design and PR now; amend
the W03 plan's obligation register in the next harness-onion meta packet that touches the plan (like EDGE-2); no extra
packet now."

| Obligation | Change | Packets | Text or scope |
|---|---|---|---|
| I07-6 | ADDED | HE-003 | The real 10-second I07 write timer and the I07 apiserver HTTP/TLS client (`architecture/i07-policy-write-v3/README.md:34`, `:47-48`) |
| I07-4 | NARROWED | HE-002B | HE-002B owns only the logical expiry of the 10-second bound: the TIMEOUT event, WRITE_TERMINAL IO_AMBIGUOUS `{aborted: UPSTREAM_TIMEOUT}`, HELD and the IO_AMBIGUOUS answer (T59, T61, T62) (`architecture/i07-policy-write-v3/README.md:34`; Q-HE2B-2 (a)) |

In `amendment.json`, `scope` is plan v2's scope field ("W03") on both changes, and I07-4's narrowed ownership is in its own
`ownership` field.

Every other obligation, packet and toolchain of plan v2 is unchanged. HE-002B has merged in R10 with this scope; I07-6 is
HE-003's.
