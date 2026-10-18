# Per-role, per-architecture seccomp allowlists v5: W02d successor (DATA_CHECK_ONLY)

Status: **SUCCESSOR_CANDIDATE_AWAITING_INDEPENDENT_REVIEW** (round 6, together with W01 amendment HS53). Roadmap item
SECCOMP-OBSERVER-LISTENER, packet 1 of 2. The adopted v4 contract (`architecture/seccomp-allowlists-v4/`,
`planeon.internal.seccomp-allowlists/v4`, MET-ENFORCE-027) stays byte-identical.

This successor is v4 with exactly one duty row added. Amendment HS53 of the W01 host-interface specification
(`architecture/host-interface-amendment-hs53/`, published in the same packet) gives the observer the I01 listener, and its
obligation O-SECCOMP-V5-OBSERVER-LISTENER asks for this rule:

| Role | Rule | Why | Source |
|---|---|---|---|
| OBSERVER | `bind`, `listen`; `accept4` only when the low 32 bits of arg 3 (flags) equal 0, SOCK_CLOEXEC (0x80000) or SOCK_CLOEXEC\|SOCK_NONBLOCK (0x80800) | I01 is server → observer over AF_UNIX SOCK_SEQPACKET; the observer listens and accepts | `architecture/host-interface-amendment-hs53/HOST_INTERFACE_SPEC.md:449` (§5.3 OBSERVER row as amended by HS53) |

Decisions (2026-10-17, via the lane monitor), recorded in `allowlists.json` exactly as HS53's record holds them:
- Q-SOL-1 (a), monitor: two packets, this one with HS53;
- Q-SOL-2 (a), owner: `bind` and `listen` unconditional, `accept4` flags only {0, CLOEXEC, CLOEXEC|NONBLOCK}, the
  TCP-listen boundary SELinux's;
- Q-SOL-3 (a), monitor: the socket's directory, mode and freshness come from the unit, with no new calls;
- Q-SOL-4 (a), owner: the v1 peer duties stay;
- F-SOL-1, a fact: I01's producer is R10's HE-004-I01;
- Q-SOL-5 (a), monitor: the shared socket directory;
- SOL-SYSTEMD-CLEANS, owner, and Q-SOL-7 (a), monitor: the observer binds after its seal and never unlinks; one
  directory unit keeps `/run/planeon/live-proxy`, and before the observer starts systemd removes only its stale socket
  path, as `init_t`, under SELinux matrix v6's grant. So this filter gains no `unlink` (HS53's O-W03-OBSERVER-UNIT,
  O-W03-OBSERVER-PRESTART, O-MATRIX-OBSERVER-SOCK-CLEAR).

## Why the flags and not more

- v6.12 `accept4(fd, upeer_sockaddr, upeer_addrlen, int flags)` (`net/socket.c:2030-2034`): flags is argument 3, and
  any bit outside SOCK_CLOEXEC|SOCK_NONBLOCK already fails with EINVAL (`:1982-1983`). The rule allows three of the
  four values the kernel accepts, refusing SOCK_NONBLOCK without SOCK_CLOEXEC.
- SOCK_CLOEXEC is O_CLOEXEC (02000000) and SOCK_NONBLOCK is O_NONBLOCK (00004000) on both architectures
  (`include/linux/net.h:80-83`; `include/uapi/asm-generic/fcntl.h:39,63`; arm64's `asm/fcntl.h` overrides neither).
- Like every v1-v4 condition, the check compares the low 32 bits only. The kernel reads flags as an `int`, so a value
  with high bits set and allowed low bits is the same call.
- `bind` and `listen` take a descriptor, a pointer and integers. Seccomp cannot see the descriptor's family or the
  address, so they stay unconditional. The grant therefore also reaches every TCP socket the observer holds or
  creates (it keeps `socket` for AF_INET and AF_INET6 streams, for the I06 read connection), and a `listen` without
  `bind`, which meets only SELinux's `tcp_socket listen` check. HS53 states this as residual R-OBSERVER-TCP-LISTEN and
  puts the boundary on SELinux: O-W03-OBSERVER-TCP, O-T04-HS53 and O-MATRIX-OBSERVER-TCP. Among AF_UNIX sockets, too,
  the filter cannot hold the listener to I01's path; SELinux limits who may connect and which socket files the observer
  may create.

## What changes in the data

- Schemas `planeon.internal.seccomp-syscall-table/v5` and `planeon.internal.seccomp-allowlists/v5`. The table adds:
  - the constants `SOCK_CLOEXEC` (0x80000) and `SOCK_NONBLOCK` (0x800), cited to the v6.12 headers;
  - an `accept4` citation for the flags argument.

  The model fixes both constants itself and refuses a table that differs.
- OBSERVER gains one duty row, citing HS53, before its clone3 ENOSYS row. Filter digests change only for OBSERVER, on
  both architectures:
  - x86_64: 238 → 253 instructions;
  - aarch64: 227 → 242 instructions.

  Every other role's policy entry, both runtime bases and the other six roles' digests equal v4's. The builder asserts
  this.
- The SERVER and BROKER listener row keeps v4's text "(OBSERVER is 'as SERVER without listener')", which quotes the
  unamended W01 row. Changing it would change those roles' entries; HS53 §13 records the superseded v1 derivation.
- Vectors: 3069 decision checks (v4: 2971), 365 worker stack checks (v4: 355) and 29 policy mutations (v4: 23).
  - `v5Changes` replays all 2971 v4 decision checks under v5. 2965 are unchanged. The 6 that change are OBSERVER `bind`,
    `listen` and `accept4` with zero arguments, on both architectures, from KILL_PROCESS to ALLOW. The builder refuses
    any other change.
  - New decision checks, every role and architecture: `accept4` on fd 3 with SOCK_NONBLOCK alone, with SOCK_CLOEXEC |
    SOCK_NONBLOCK and bit 0, with an undefined bit (0x40000), and with 0 and 0x80800 under a set high word.
    - In OBSERVER, the first three kill and the last two allow.
    - Roles without `accept4` kill all five.
    - SERVER, BROKER and EFFECT_GATE allow all five (their v4 grant is unconditional).
  - For OBSERVER: `bind` on fd 7 with an AF_INET-sized address and `listen` with backlog 128 are allowed. This shows the
    filter cannot see the family (R-OBSERVER-TCP-LISTEN).
  - The generic loop adds the satisfied, high-word and broken-bit cases of the three `accept4` alternatives.
  - New mutations for OBSERVER, all refused:
    - M24, an unconditional `accept4` in the HS53 row;
    - M25, `accept4` with SOCK_NONBLOCK alone;
    - M26, a flags condition masked to the SOCK_CLOEXEC bit (any other bit passes);
    - M27, the flags condition on argument 2;
    - M28, `bind` and `listen` in a row that does not cite HS53;
    - M29, `bind` in a row citing another line of the HS53 specification.
- `scripts/seccomp_allowlists_v5.py` is the v4 model plus three policy checks for OBSERVER:
  - the table's `SOCK_CLOEXEC` and `SOCK_NONBLOCK` must equal the model's fixed values;
  - `bind`, `listen` and `accept4` may come only from a duty whose source cites exactly HS53's OBSERVER row
    (`HS53_ROW`, the line `:449`, fixed in the model), never from the runtime base;
  - every `accept4` alternative is exactly `{arg 3, full mask, eq}`, and the values are exactly {0, 0x80000, 0x80800}.

## What it does not do

It installs nothing and changes no role code. It does not republish the compiled filter programs or the edge record:
packet 2 does that from v5 (O-PROGRAMS-V3-OBSERVER), and R10's HE-004-I01 then re-vendors them (O-R10-HE004-I01). The
socket's directory, mode and freshness are unit settings, not filter rules (O-W03-OBSERVER-UNIT). Every E01-E12
obligation stays OPEN_UNPROVEN.

Carried to W03 and HE-004-I01 (not a seccomp rule): by the author's reading, Rust std, mio and socket2 call `accept4` with SOCK_CLOEXEC, adding
SOCK_NONBLOCK for non-blocking listeners. A runtime that calls `accept` (no flags), or `accept4` with SOCK_NONBLOCK
alone, is killed. The observer's code must accept with one of the three allowed flag values.
