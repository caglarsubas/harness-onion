# Review brief: amendment HS43 (HS-4.3-AMEND)

Review the HS43 amendment for publication: `amendment.json`, `HOST_INTERFACE_SPEC.md` and README in this directory, and
`scripts/host_interface_amendment_v2.py`. The base is the byte-identical W02D effective specification
(`architecture/host-interface-amendment-w02d/HOST_INTERFACE_SPEC.md`).

## Owner decisions it must carry out (and nothing more)

- Q-HE2S-10 (a): amend §4.3 so the gate qualifies the broker by label, cgroup, pidfd and SO_PEERCRED.
- Q-HE3A-1 (c): the gate checks the I07 writer's executable through its `/proc` exe link.
- Q-HE3A-1b (a): the check lands after a chain. First the seccomp v3 `readlinkat` duty for EFFECT_GATE, then the
  republished programs and edge record, then the R10 re-vendor and check. HE-007 obligations: writer uid/gid 0,
  dumpable, empty permitted set.
- HS43-START (2026-10-15): the EFFECT_GATE `readlinkat` duty sentence, with `readlinkat` allowed only with
  dirfd != AT_FDCWD, so musl's aarch64 `readlink` stays killed. The seccomp v3 allowlist amendment is its own next packet.
- Q-HS43-1: the gate's broker qualification drops only the artifact and keeps pidfd/start (if recorded in the record).

## Check at least

1. **Exactness.**
   - The six items apply to the W02D bytes exactly as `effective_spec` says, and the published file is the result.
   - Nothing outside §4.3, the §5.3 EFFECT_GATE row, the title, the head paragraph and the new §12 changes.
   - The W02D record and effective text are unchanged, and their digests are pinned.
2. **Technical truth of H1–H3**, against the Linux v6.12 rules and the published contracts.
   - Is the gate's read of `/proc/<pid>/exe` a `PTRACE_MODE_READ_FSCREDS` access, with these preconditions without
     CAP_SYS_PTRACE?
     - uid/gid equality;
     - the target is dumpable;
     - the commoncap permitted-subset rule;
     - SELinux `file read` on the target domain.
   - Are the stated conclusions right?
     - the broker's exe link is refused to the gate;
     - the writer's is allowed under O-W03-WRITER-EXE.
   - Does SELinux matrix v4 (`architecture/selinux-matrix-v2/matrix.json`, `procAccess`) really give `planeon_gate_t` that
     read on the writer, and the broker label's entrypoint and `execute_no_trans` closure as stated?
   - Is "low 32 bits" the right test for dirfd, since the kernel reads it as an `int`?
   - Does refusing AT_FDCWD keep musl's aarch64 `readlink` killed?
   - Is anything needed that the text omits, such as a PID-reuse window or an open of `/proc/<pid>` that the gate's
     current allowlist kills?
3. **Consistency.**
   - Other §§ that still say the gate checks the broker's artifact.
   - BIND_EXECUTION's "broker peer qualification digest".
   - The SELinux matrix v4 README statements.
   - The seccomp v3 EFFECT_GATE rows.
4. **The model.**
   - The record is closed, and EDITORIAL items are limited to the three fixed edges.
   - Dispositions cover exactly the cited decisions.
   - The obligations named in the new text equal the record's.
   - Is anything accepted that should not be?
5. **Scope.** Owner decisions only, no W03 or R10 design content, and no claim of enforcement.

Verdict: `PASS_FOR_SOURCE_PUBLICATION` or `CHANGES_REQUIRED`, with findings `{id, severity MAJOR|MINOR|NOTE, file, line,
summary, evidence}`.
