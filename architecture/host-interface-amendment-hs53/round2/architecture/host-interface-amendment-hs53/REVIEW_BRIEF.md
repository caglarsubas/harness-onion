# Review brief: amendment HS53 (SECCOMP-OBSERVER-LISTENER, packet 1, round 2)

Review HS53 for publication: `amendment.json`, `HOST_INTERFACE_SPEC.md` and README in this directory, and
`scripts/host_interface_amendment_v3.py`. It is reviewed together with seccomp allowlists v5
(`architecture/seccomp-allowlists-v5/`, its own brief), which carries out HS53's obligation
O-SECCOMP-V5-OBSERVER-LISTENER.

The base is HS43's byte-identical effective text and record (`architecture/host-interface-amendment-hs43/`). The model
is HS43's `scripts/host_interface_amendment_v2.py` with HS53's constants and item places; diff the two models yourself.

## Check at least

1. **The model.** `check(read)` passes on the published files. It refuses:
   - a record whose items stray from their places: H1 outside the §5.3 OBSERVER row or changing its line or cell
     count, H2 other than the fixed pointer pair, H3 rewriting its §4.3 bullet or appending anything but bullet lines;
   - a dropped or extra superseded clause, residual or obligation;
   - an obligation named in the new text but not recorded, or recorded but not named in a DECIDED item.

   Try such mutations yourself. Confirm the v2 → v3 changes alter nothing else in the model's logic.
2. **The OBSERVER row (H1)** against the base I01 definition (`architecture/host-interface-inputs/corrected/` §3), the
   I01 guide (`docs/alpha-2/POLICY_OBSERVATION_READINESS.md`) and matrix v5 (`architecture/selinux-matrix-v3/`). Check:
   - the listener is I01's only;
   - `accept4`'s flags argument and the three values (v6.12 `net/socket.c`, `include/linux/net.h`,
     `include/uapi/asm-generic/fcntl.h`);
   - the stated seccomp limit (no descriptor family);
   - the SELinux cell, against matrix v5's socket row and closed permissions.

   The claim that AF_UNIX SOCK_SEQPACKET maps to `unix_stream_socket` is the author's reading; judge whether it is
   stated with the right weight (T04 confirms it).
3. **The TCP boundary.** Is residual R-OBSERVER-TCP-LISTEN complete and correct? In particular:
   - `name_bind` is not checked for port 0 or inside `ip_local_port_range`;
   - `listen` on an unbound TCP socket autobinds.

   Do O-W03-OBSERVER-TCP, O-T04-HS53 and O-MATRIX-OBSERVER-TCP close it?
4. **The socket file (O-W03-OBSERVER-UNIT, O-MATRIX-OBSERVER-SOCK-CLEAR).** Check against matrix v5's socket-file and
   directory grants:
   - the directory `/run/planeon/live-proxy/` is shared by three listeners (I01, I02, I05);
   - the observer clears a stale path itself before its filter is installed (Q-SOL-6 (c)), in the stated order;
   - the steady-state filter adds no unlink;
   - the fallback is named, with nothing granted now;
   - systemd's handling of the shared directory is a T04 question, not an assumption.

   Is every route achievable under the pinned contracts, and does T04 check the one that applies?
5. **The producer (H3, supersedes).** Are the 14 quoted clauses, with the stated exclusions in `notAmended`, the right
   and complete set of adopted text that says otherwise? Each quote must occur exactly once in its pinned file. Do the replacements leave the I01 wire and the v1
   peer duties untouched?
6. **Decisions.** Q-SOL-1 to Q-SOL-6 and F-SOL-1 are quoted verbatim (you cannot see the relays; check that the record
   and v5's `allowlists.json` agree), and each disposition's obligations answer it.
7. **Scope and hygiene.** HS43's files, matrix v5/v6 and seccomp v4 are untouched. No W03 or R10 content beyond the
   obligation id I01-1 and the packet name HE-004-I01. No local absolute paths.
8. **Round 1.** Check each disposition in the README's last table against `review-round1` (its findings are quoted in
   your brief), and look for regressions the changes may have caused.

Verdict: `PASS_FOR_SOURCE_PUBLICATION` or `CHANGES_REQUIRED`, with findings `{id, severity MAJOR|MINOR|NOTE, file, line,
summary, evidence}`.
