# Amendment HS43 to the W01 host-interface specification

Status: **AWAITING_REVIEW** (independent contract review). Design label `HOST-INTERFACE-DRAFT-002-HS43`, roadmap item
HS-4.3-AMEND, harness-onion slot 236 (owner decision 2026-10-15, via the lane monitor).

HS43 changes how the effect gate qualifies its two local peers (W01 §4.3) and states the one system call the writer's
executable check needs (W01 §5.3, EFFECT_GATE row). It is applied to the effective text of amendment W02D
(`architecture/host-interface-amendment-w02d/HOST_INTERFACE_SPEC.md`), which stays byte-identical, as do its record and
the reviewed v2 file under `architecture/host-interface-inputs/resolved/`.

This is a specification change only. It installs nothing, adds no allowlist data and proves no enforcement obligation;
E01-E12 stay OPEN_UNPROVEN.

## Files

| File | What it is |
|---|---|
| `amendment.json` | `planeon.internal.host-interface-amendment/v2`: the pinned W02D base and record, the owner decisions, six counted substring replacements (three DECIDED, three EDITORIAL), one disposition per cited decision, three obligations and the stated non-amendments |
| `HOST_INTERFACE_SPEC.md` | The effective specification: the W02D effective text with the six items applied |
| `scripts/host_interface_amendment_v2.py` | The standard-library model: `check(read)` checks the W02D record digest, the closed HS43 record, and that applying the items to the pinned W02D bytes gives exactly the published bytes |

## Changes

| Item | Where | Change | Decisions |
|---|---|---|---|
| H1 | §4.3 | The gate qualifies the broker by label, cgroup, pidfd/start and SO_PEERCRED, with no artifact check, and says why: the broker's `/proc/<pid>/exe` is ptrace-gated, its permitted capabilities are not a subset of the gate's and no role holds CAP_SYS_PTRACE; its executable identity follows from its label (SELinux matrix v4: entry only through `planeon_broker_exec_t`, `execute_no_trans` closed). The writer keeps the artifact check, through `readlinkat` of its exe link on an open `/proc/<pid>` directory of the frame's own process, with the kernel's preconditions stated | Q-HE2S-10, Q-HE3A-1, Q-HS43-1 |
| H2 | §5.3 EFFECT_GATE, capabilities | The gate's peer reads include the writer's ptrace-gated `exe` link | Q-HE3A-1 |
| H3 | §5.3 EFFECT_GATE, seccomp | `readlinkat` only with a dirfd other than AT_FDCWD, judged on the low 32 bits; `readlink` and `readlinkat(AT_FDCWD, …)` (musl's aarch64 `readlink`) stay KILL_PROCESS | Q-HE3A-1, Q-HE3A-1b, HS43-START |
| E1 | title | Names both amendments | — |
| E2 | head | Says HS43 is applied on top of the byte-identical W02D text | — |
| E3 | §12 (new) | Lists the items, the order of the data packets and the obligations | — |

## Why the gate can read the writer's exe link but not the broker's

Reading `/proc/<pid>/exe` is a ptrace-mode read (`PTRACE_MODE_READ_FSCREDS`). Without CAP_SYS_PTRACE, which no role
holds, the kernel allows it only when the reader's filesystem uid and gid equal the target's real, effective and saved
uids and gids, the target is dumpable, and the target's permitted capabilities are a subset of the reader's
(commoncap). SELinux then checks `file read` from the reader's domain on the target's domain, which matrix v4's
`procAccess` gives `planeon_gate_t` for both `planeon_broker_t` and `planeon_policy_writer_t`.

- The broker (uid 0) holds CAP_NET_ADMIN, CAP_BPF, CAP_SETUID and CAP_SETGID; the gate holds none (CAP_NET_BIND_SERVICE
  at most). The subset rule fails, so the gate cannot read the broker's exe link. The matrix v4 README already says so.
- The writer runs as uid 0 with an empty capability set (§5.3). It is dumpable while it changes no credentials and
  can read its own artifact (matrix v4 gives every domain READ on `planeon_policy_writer_exec_t`). The gate (uid 0)
  can therefore read its exe link. Obligation O-W03-WRITER-EXE keeps those conditions, as Q-HE3A-1b's HE-007 items say.

## The readlinkat duty and its data

The gate opens `/proc/<pid>` as a directory and calls `readlinkat(dirfd, "exe", …)`. The W02d v3 allowlist
(`architecture/seccomp-allowlists-v3/`) has no `readlinkat` for EFFECT_GATE today. Its own next packet adds the rule
(O-SECCOMP-V3-READLINKAT). Then the programs and the edge record are republished, and R10 re-vendors them and adds the
check (Q-HE3A-1b). Until then the writer's artifact check is decided but open.

The rule admits any dirfd except AT_FDCWD (-100). Two details carry over to that packet:
- musl implements `readlink` on aarch64 as `readlinkat(AT_FDCWD, …)`, so refusing AT_FDCWD keeps it killed.
  `readlink` itself (x86_64) stays unlisted.
- The kernel reads dirfd as an `int`, so the rule must judge only the low 32 bits. A full 64-bit inequality would admit
  `0x00000000ffffff9c`, which the kernel reads as AT_FDCWD.
- The v3 model's argument conditions are masked equalities. An inequality needs 32 single-bit alternatives or a model
  extension; that packet decides.

## Obligations

| Id | Owner | Summary |
|---|---|---|
| O-SECCOMP-V3-READLINKAT | the next parallel-lane packet | The EFFECT_GATE `readlinkat` rule (x86_64 and aarch64, low 32 bits ≠ AT_FDCWD), `readlink` unlisted, vectors republished |
| O-W03-WRITER-EXE | W03 (HE-007) | Writer uid/gid equal the gate's (0), dumpable, empty permitted set; the read bound to the frame's own process; exact artifact path |
| O-T04-HS43 | T04 | Native confirmation: the writer read succeeds, the broker read fails with EACCES, `readlink` and `readlinkat(AT_FDCWD, …)` kill the gate |

## Not amended

- The broker's qualification of the gate and the BIND_EXECUTION digest of it.
- The W02d v3 allowlist data, compiled programs and edge record (their own later packets).
- SELinux matrix v4, which already gives the gate the writer's and the broker's `/proc`.
- Every other W01 text, gate disposition and E01-E12 obligation.
