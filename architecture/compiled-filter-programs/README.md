# Compiled seccomp filter programs (MET-ENFORCE-025)

Alpha 2A; 2026-10-13. Status: **ADOPTED** (independent review round 4: PASS_FOR_SOURCE_PUBLICATION; rounds and review records in `architecture/compiled-filter-programs/status.json`). DATA_CHECK_ONLY: published data, no runtime,
selector, catalog or schema change.

The adopted W02d v3 contract (`architecture/seccomp-allowlists-v3/`, MET-ENFORCE-020, merged as `5fab673e`) defines each
role's seccomp filter and publishes the compiled classic-BPF program only by its SHA-256 (`vectors.json` `filterDigests`)
and instruction count (`programLengths`). SEC-4 ("install exactly the compiled programs", carried to W03) needs the bytes
themselves. This directory publishes them (owner decision Q-HE2S-1 (a), 2026-10-13, via the lane monitor, verbatim: "a
harness-onion meta packet publishes the compiled seccomp programs as data files; its layer recompiles them with the
pinned v3 compiler and checks them against the published digests; R10 vendors EFFECT_GATE's two files byte-identically,
gate.py pins their sha256, and the seal embeds them"; Q-HE2S-2 (a): all seven roles on both architectures).

## Files

| File | Content |
|---|---|
| `programs/<ROLE>.<arch>.bpf` | 14 programs: BROKER, EFFECT_GATE, HOST_CONTAINMENT, OBSERVER, POLICY_WRITER, SERVER and WORKER on `aarch64` and `x86_64` |
| `index.json` | `planeon.internal.compiled-filter-programs/v1`: per program its role, architecture, path, instruction count, byte count and SHA-256; the v3 source commit and the SHA-256 of each v3 source file used |
| `../../scripts/compiled_filter_programs.py` | The publisher and checker: `--write` writes the files; without arguments it checks them |

## Format and derivation

Each file is the kernel's `struct sock_filter` array as `seccomp(SECCOMP_SET_MODE_FILTER, …)` receives it: 8 bytes per
instruction, little-endian (`u16 code, u8 jt, u8 jf, u32 k`), exactly the bytes the pinned compiler's `program_bytes`
returns. The publisher reads the v3 compiler (`scripts/seccomp_allowlists_v3.py`), policy (`allowlists.json`), syscall table
(`syscalls.json`) and vectors (`vectors.json`) from their published bytes, refuses any whose SHA-256 differs from the value
the publisher pins (and `index.json` records), executes the verified compiler bytes (no import, so no cached bytecode),
runs `compile_filter` and `program_bytes` for every role and architecture, and requires each program's SHA-256 and
instruction count to equal v3's `filterDigests` and `programLengths`. The compiler is not edited or copied; the v3 contract
stays byte-identical.

| Role | aarch64 | x86_64 |
|---|---|---|
| BROKER | 311 | 326 |
| EFFECT_GATE | 183 | 194 |
| HOST_CONTAINMENT | 130 | 141 |
| OBSERVER | 227 | 238 |
| POLICY_WRITER | 115 | 126 |
| SERVER | 261 | 276 |
| WORKER | 172 | 187 |

(instructions; each program is 8 bytes per instruction)

## Consumers

The edge registry record v2 (`architecture/artifact-edges/operator-harness-engineering-v2.json`) registers the programs
for the operator repository (R10): EFFECT_GATE's two for HE-002S, the observer's for HE-004, the broker's and the
worker's for HE-005, host containment's for HE-006 and the policy writer's for HE-007, each to be held byte-identically
under `host-enforcement/contracts/seccomp-v3/`. SERVER's two are published but not registered: no W03 packet installs the
SERVER role's program (plan v2 lists SERVER under no SEC-4 packet, and its sealed-credential code is today R12's live
backend, plan v2 obligation A1-SERVER-MEMFD, outside W03), so the consumer repository and packet are undecided.

## Not claimed

- The programs are the v3 contract's, compiled; this packet makes no new seccomp decision and reviews no rule.
- Installing a program, and proving at boot that the installed filter equals the published digest, are the consumers'
  and T04's (W02d-Q3).
