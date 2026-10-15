# Review brief: seccomp allowlists v4 (SECCOMP-V3-READLINKAT)

Review the W02d successor v4 for publication: `syscalls.json`, `allowlists.json`, `vectors.json` and README in this
directory, and `scripts/seccomp_allowlists_v4.py`. The base is the byte-identical adopted v3
(`architecture/seccomp-allowlists-v3/`, `scripts/seccomp_allowlists_v3.py`). The obligation it answers is
O-SECCOMP-V3-READLINKAT in `architecture/host-interface-amendment-hs43/amendment.json`.

## Check at least

1. **Exactly one rule added.** Against v3:
   - only EFFECT_GATE's duties gain one `readlinkat` row with `{"arg": 0, "mask": 0x80000000, "eq": 0}`;
   - the constants add only `AT_FDCWD_LOW32` and `DIRFD_SIGN_BIT`;
   - the owner decisions add only Q-HE3A-1, Q-HE3A-1b, HS43-START and SECCOMP-DIRFD-DIRECTION;
   - only EFFECT_GATE's filter digests and program lengths change.

   Diff the v3 and v4 JSON yourself.
2. **Semantics.** The compiled filter refuses:
   - AT_FDCWD in both encodings (`0xffffffffffffff9c`, `0x00000000ffffff9c`);
   - -1 and 0x80000000;
   - `readlink` (x86_64).

   It allows non-negative descriptors. Confirm `decide` and `run_filter` agree on these and on your own probes (other
   high words, other negative values). Confirm the compiled BPF compares only the low word for this condition.
3. **The model's two new checks.** They refuse an unconditional `readlinkat`, a condition that admits AT_FDCWD, a
   mask without bit 31, and a `readlink` grant for the gate. They change nothing for any other role.
4. **Consistency with HS43.**
   - §5.3 EFFECT_GATE row: "only with a non-negative directory descriptor … judged on the low 32 bits".
   - The obligation text: "one masked condition, (arg0 & 0x80000000) == 0".
   - The README's claims about musl aarch64 `readlink` and the kernel's int dirfd.
5. **Scope.** v3, the compiled programs and the edge records are untouched. No W03 or R10 content.

Verdict: `PASS_FOR_SOURCE_PUBLICATION` or `CHANGES_REQUIRED`, with findings `{id, severity MAJOR|MINOR|NOTE, file, line,
summary, evidence}`.
