# Amendment HS43 to the W01 host-interface specification

Status: **AWAITING_REVIEW** (independent contract review). Design label `HOST-INTERFACE-DRAFT-002-HS43`, roadmap item
HS-4.3-AMEND, harness-onion slot 236 (owner decision 2026-10-15, via the lane monitor).

HS43 changes how the effect gate qualifies its two local peers (W01 §4.3) and states the one system call the writer's
executable check needs (W01 §5.3, EFFECT_GATE row). It is applied to the effective text of amendment W02D
(`architecture/host-interface-amendment-w02d/HOST_INTERFACE_SPEC.md`). That text stays byte-identical, as do its record,
the reviewed v2 file under `architecture/host-interface-inputs/resolved/`, and every contract file whose clauses HS43
overrides.

This is a specification change only. It installs nothing, adds no allowlist data and proves no enforcement obligation;
E01-E12 stay OPEN_UNPROVEN.

## Files

| File | What it is |
|---|---|
| `amendment.json` | `planeon.internal.host-interface-amendment/v2`: the pinned W02D base and record; the owner decisions; eight counted substring replacements (five DECIDED, three EDITORIAL); one disposition per decision; six obligations; the closed list of 16 superseded clauses; two residuals; the stated non-amendments |
| `HOST_INTERFACE_SPEC.md` | The effective specification: the W02D effective text with the eight items applied |
| `scripts/host_interface_amendment_v2.py` | The standard-library model. `check(read)` checks: the W02D record digest; the closed HS43 record; every superseded file's digest and its quoted clause; that applying the items to the pinned W02D bytes gives exactly the published bytes |

The model leaves nothing free-standing in the amended text:
- a DECIDED item must sit inside the section and lines it names, and only §4.3, §5.3 and §7 may change;
- every owner decision is cited, and each disposition lists every item that cites it;
- the title rename and the head sentence are fixed;
- section 12 is rendered from the record alone;
- the superseded clauses must be exactly the model's closed list, in order;
- the two residuals and the six obligations must all be present, in order.

## Changes

| Item | Where | Change | Decisions |
|---|---|---|---|
| H1 | §4.3 | See below | Q-HE2S-10, Q-HE2S-7, Q-HE2S-9, Q-HE3A-1, Q-HS43-1, Q-HS43-2, Q-HS43-3 |
| H2 | §5.3 EFFECT_GATE, capabilities | The gate's peer reads include the writer's ptrace-gated `exe` link | Q-HE3A-1 |
| H5 | §5.3 EFFECT_GATE, capabilities | None: the signed I04 port is 1024 or above, so the gate keeps no capability after its seal (the "below 1024" exception goes) | Q-HE2S-9 |
| H3 | §5.3 EFFECT_GATE, seccomp | `readlinkat` only with a non-negative dirfd, judged on the low 32 bits (so never AT_FDCWD in any encoding). The filter does not bind which link is read: an absolute path ignores the dirfd, so `procAccess` and the gate's code do that. `readlink` (x86_64) and `readlinkat(AT_FDCWD, …)` (musl's aarch64 `readlink`) stay KILL_PROCESS | Q-HE3A-1, Q-HE3A-1b, HS43-START, SECCOMP-DIRFD-DIRECTION |
| H4 | §7 BIND_EXECUTION | The digest is the gate's mutual qualification record, as I05 defines it, with the narrower gate-side half | Q-HE2S-10, Q-HS43-2 |
| E1 | title | Names both amendments | — |
| E2 | head | Says HS43 is applied on top of the byte-identical W02D text | — |
| E3 | §12 (new) | Rendered from the record: items, superseded clauses, residual, data order, obligations | — |

H1 makes five changes to §4.3:
- The broker's check of the gate keeps its five parts. Its artifact read works because the gate holds no capability
  (Q-HE2S-9) and stays dumpable (Q-HE2S-7).
- Peer start times are compared with a reference taken without a race: a pidfd that names the connected process
  (SO_PEERPIDFD or SCM_PIDFD), the stat read, then a pidfd poll showing the process has not exited.
- The gate qualifies the broker by label, cgroup, pidfd/start and SO_PEERCRED, with no artifact check.
- The broker's executable identity follows from its label.
- The writer keeps the artifact check: its exe link must equal the enrolled path exactly, with no " (deleted)". The
  fs-verity digest is enforced on the sealed file, not re-measured per frame. The kernel preconditions are stated.

## Why the gate can read the writer's exe link but not the broker's

Reading `/proc/<pid>/exe` is a ptrace-mode read (`PTRACE_MODE_READ_FSCREDS`). Without CAP_SYS_PTRACE, which no role
holds, the kernel allows it only when all of these hold:
- the reader's filesystem uid and gid equal the target's real, effective and saved uids and gids;
- the target is dumpable;
- the target's permitted capabilities are a subset of the reader's effective ones (commoncap, one user namespace).

SELinux then checks `file read` from the reader's domain on the target's domain. Matrix v4's `procAccess` gives that to
`planeon_gate_t` for both `planeon_broker_t` and `planeon_policy_writer_t`. Yama (`ptrace_scope` 3) limits only attach.

- **The broker:** it holds CAP_NET_ADMIN, CAP_BPF, CAP_SETUID and CAP_SETGID, and the gate holds none. The subset rule
  fails, so the gate cannot read the broker's exe link. The matrix v4 README already says so.
- **The writer:** it runs as uid 0 with an empty capability set (§5.3). It stays dumpable while its exec changes no
  credentials: no set-id bit, no file capabilities, equal uids and gids, and an artifact its starter
  (`planeon_admin_t`) can read. The gate (uid and gid 0) can therefore read its exe link.
- **The obligations:** O-W03-WRITER-EXE keeps these conditions, as Q-HE3A-1b's HE-007 items say. O-W03-PEER-EXE keeps
  the gate readable by the broker.

## Superseded clauses (owner decision Q-HS43-2 (a))

HS43 overrides 16 adopted clauses, quoted exactly in `amendment.json` and in §12. Their files stay byte-identical:
- The W01 base (`host-interface-inputs/corrected/`): both sides "authenticate exact installed peer artifacts" now
  follows §4.3: the gate does not authenticate the broker's artifact.
- I05 v1, v2 and v3, Channel 2: the gate no longer verifies the broker's executable, and "The broker verifies the
  gate's frames the same way" now means the broker's own five-part list, which HS43 does not narrow.
- I07 v1, Channel 2, inherited by v2 and v3:
  - the writer is qualified by its own §4.3 rule, not "the way it qualifies the broker";
  - its artifact check is the exact exe-link path, not a per-frame fs-verity digest.
- W01 §7's "broker peer qualification digest" becomes the mutual record, through item H4.
- Three statements each in the matrix v3 and v4 READMEs: the writer check also reads its gated exe link. The
  matrices' data are unchanged.

A successor of each contract adopts the text. This follows the W02-CLEANUP errata precedent (Q-S A).

## Residuals (owner decision Q-HS43-3 (a))

R-WRITER-PROC: a dumpable writer lets every uid-0 role with `procAccess` on it read its ptrace-gated entries. Those
roles are the server, the observer and the broker as well as the gate, and the entries are exe, cwd, root, fd, fdinfo,
environ and maps. `mem` and `process_vm_*` stay refused, because they need ptrace attach and Yama refuses it.
Obligation O-MATRIX-WRITER-PROCACCESS has the queued SELinux matrix amendment (SELINUX-MATRIX-I04-KEYCERT) evaluate
narrowing that access to the gate.

R-GATE-PROC: the gate stays dumpable (Q-HE2S-7) and holds no capability. So the broker, the server and the observer,
all uid 0 with `procAccess` on it, can read its ptrace-gated entries, for example environ, maps, cwd and the fd
links. Reopening a credential through an fd link still meets SELinux's file checks on the credential type (A09).
Obligation O-MATRIX-GATE-PROCACCESS has the same matrix amendment evaluate which of those reads the server's and the
observer's captures need; the broker keeps the gate's exe link.

## Obligations

| Id | Owner | Summary |
|---|---|---|
| O-SECCOMP-V3-READLINKAT | the next parallel-lane packet | The EFFECT_GATE `readlinkat` rule: a non-negative dirfd on the low 32 bits, one masked condition `(arg0 & 0x80000000) == 0` (direction accepted 2026-10-15); `readlink` unlisted; vectors for AT_FDCWD in both encodings and -1 |
| O-W03-WRITER-EXE | W03 (HE-007) | Writer uid/gid 0, empty permitted set (the exec raises none), dumpable through a credential-free exec; gate fs uid/gid 0; a race-free pidfd; an oversized buffer; an exact path |
| O-W03-PEER-EXE | W03 | Gate dumpable, uid/gid 0, no capability after the seal; broker fs uid/gid 0; race-free peer pidfds and start times (stat read, then pidfd poll) |
| O-MATRIX-WRITER-PROCACCESS | SELINUX-MATRIX-I04-KEYCERT | Evaluate narrowing the writer's `procAccess` to the gate |
| O-MATRIX-GATE-PROCACCESS | SELINUX-MATRIX-I04-KEYCERT | Evaluate narrowing the server's and the observer's reads of the gate's gated entries |
| O-T04-HS43 | T04 | Native confirmation. The writer read succeeds. The broker read fails with EACCES, and the audited `capability sys_ptrace` denial is expected. The broker reads the gate. On x86_64 `readlink` kills the gate, and on both architectures `readlinkat` with AT_FDCWD in either encoding, or with -1, kills it. The path check refuses a longer path and " (deleted)" |

## Not amended

- The broker's qualification of the gate (five checks); HS43 only states the kernel preconditions of its artifact read.
- The W02d v3 allowlist data, compiled programs and edge record (their own later packets, Q-HE3A-1b).
- SELinux matrix v4's `matrix.json`.
- Every other W01 text, gate disposition and E01-E12 obligation.
