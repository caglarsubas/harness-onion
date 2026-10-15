# Per-role, per-architecture seccomp allowlists v4: W02d successor (DATA_CHECK_ONLY)

Status: **SUCCESSOR_CANDIDATE_AWAITING_INDEPENDENT_REVIEW**. Roadmap item SECCOMP-V3-READLINKAT, harness-onion slot 237.
The adopted v3 contract (`architecture/seccomp-allowlists-v3/`, `planeon.internal.seccomp-allowlists/v3`, MET-ENFORCE-020)
stays byte-identical.

This successor is v3 with exactly one rule added. Amendment HS43 of the W01 host-interface specification (MET-ENFORCE-026)
gave the effect gate a `readlinkat` duty, and its obligation O-SECCOMP-V3-READLINKAT asks for that rule:

| Role | Rule | Why | Source |
|---|---|---|---|
| EFFECT_GATE | `readlinkat` only with arg 0 (dirfd) satisfying `(arg0 & 0x80000000) == 0` | The gate checks the I07 writer's executable by reading its `/proc/<pid>/exe` link with `readlinkat` on an open `/proc/<pid>` directory descriptor | `architecture/host-interface-amendment-hs43/HOST_INTERFACE_SPEC.md:441` (§5.3 EFFECT_GATE row, seccomp), §4.3 |

Owner decisions: Q-HE3A-1 (c) and Q-HE3A-1b (a), 2026-10-13. HS43-START, 2026-10-15. The direction
`(arg0 & 0x80000000) == 0` was accepted by the lane monitor under the owner's delegation, 2026-10-15
(SECCOMP-DIRFD-DIRECTION). SEC-RL-START, 2026-10-15, starts slot 237 (lane monitor). All are recorded in
`allowlists.json`; the first four are quoted as HS43's record holds them.

The obligation names v3's EFFECT_GATE row. The repository publishes data changes as byte-identical-predecessor successors
(v2 → v3 → v4), so v4 discharges O-SECCOMP-V3-READLINKAT. The republished programs and the edge record derive from v4.

## Why one masked condition is enough

- The kernel reads `readlinkat`'s dirfd as an `int`, and classic BPF compares the low 32 bits of an argument. AT_FDCWD
  is -100, which is `0xffffff9c` in the low word. A dirfd is negative exactly when bit 31 of the low word is set.
- Requiring bit 31 clear therefore refuses AT_FDCWD in every encoding:
  - sign-extended, `0xffffffffffffff9c`;
  - zero-extended, `0x00000000ffffff9c`.

  It also refuses every other negative value, such as -1. A full 64-bit inequality with AT_FDCWD would admit the
  zero-extended form, which the kernel still reads as AT_FDCWD.
- musl implements `readlink` on aarch64 as `readlinkat(AT_FDCWD, …)`, so that call stays killed. `readlink` itself (x86_64)
  stays unlisted for the gate. Every other role's `readlinkat` and `readlink` grants are unchanged.
- The filter cannot bind which link is read: an absolute path ignores the descriptor. That is set by `planeon_gate_t`'s
  SELinux permissions, the kernel's ptrace-read rules and the gate's code (HS43 §4.3 and §5.3, obligation O-W03-WRITER-EXE).

## What changes in the data

- Schemas `planeon.internal.seccomp-syscall-table/v4` and `planeon.internal.seccomp-allowlists/v4`. The table adds the
  constants `AT_FDCWD_LOW32` (0xffffff9c) and `DIRFD_SIGN_BIT` (0x80000000), each cited to v6.12
  `include/uapi/linux/fcntl.h:93`. The model fixes both values itself and refuses a table that differs.
- EFFECT_GATE gains one duty row citing HS43. Filter digests change only for EFFECT_GATE, on both architectures:
  - x86_64: 194 → 200 instructions;
  - aarch64: 183 → 189 instructions.

  The other six roles' digests equal v3's.
- Vectors: 2971 decision checks (v3: 2953), 355 worker stack checks (unchanged) and 23 policy mutations (v3: 18).
  - The new decision checks, on both architectures, kill the gate's `readlinkat` with dirfd AT_FDCWD (both encodings),
    -1 or 0x80000000, and allow 3 and 0x7fffffff.
  - The gate's `readlink` (x86_64 only; aarch64 has no `readlink` syscall) is killed by the generic zero-argument check.
  - The generic loop adds the satisfied, high-word and bit-31-broken cases.
  - New mutations for EFFECT_GATE, all refused:
    - M19, an unconditional `readlinkat`;
    - M20, `readlinkat` with dirfd == AT_FDCWD;
    - M21, `readlink`;
    - M22, a dirfd condition whose mask lacks bit 31 (mask 0x1, value 0, which admits AT_FDCWD);
    - M23, the bit-31 condition on argument 1 instead of the dirfd.
- `scripts/seccomp_allowlists_v4.py` is the v3 model plus three policy checks for EFFECT_GATE:
  - the table's `DIRFD_SIGN_BIT` and `AT_FDCWD_LOW32` must equal the model's own fixed values;
  - every `readlinkat` alternative must include a condition on arg 0 whose mask has bit 31 and whose value clears it;
  - no `readlink`.

## What it does not do

It installs nothing and changes no role code. It does not republish the compiled filter programs or the edge record:
the primary lane does that next, from v4 (Q-HE3A-1b). The writer's executable check stays decided but open until R10
re-vendors those programs and adds the check. Every E01-E12 obligation stays OPEN_UNPROVEN.

Carried to W03 (not a seccomp rule): under these rules, musl's `realpath()` and Rust std's `read_link`,
`current_exe` and `canonicalize` kill the gate, because they reach `readlinkat(AT_FDCWD, …)` or `readlink`. The gate's
code must call `readlinkat` on the open `/proc/<pid>` descriptor, as O-W03-WRITER-EXE already requires.
