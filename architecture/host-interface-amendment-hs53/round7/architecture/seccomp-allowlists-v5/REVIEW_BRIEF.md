# Review brief: seccomp allowlists v5 (SECCOMP-OBSERVER-LISTENER, packet 1, round 7)

Review the W02d successor v5 for publication: `syscalls.json`, `allowlists.json`, `vectors.json` and README in this
directory, and `scripts/seccomp_allowlists_v5.py`. The base is the byte-identical adopted v4
(`architecture/seccomp-allowlists-v4/`, `scripts/seccomp_allowlists_v4.py`). The obligation it answers is
O-SECCOMP-V5-OBSERVER-LISTENER in `architecture/host-interface-amendment-hs53/amendment.json`, reviewed together with it.

## Check at least

1. **Exactly one row added.** Against v4, diffing the JSON yourself:
   - only OBSERVER's duties gain one row citing HS53's OBSERVER line, with `bind`, `listen` and `accept4` alternatives
     `{arg 3, full mask, eq 0 | 0x80000 | 0x80800}`;
   - the constants add only `SOCK_CLOEXEC` and `SOCK_NONBLOCK`, and the citations add those two and `accept4`;
   - the decisions add only Q-SOL-1 to Q-SOL-5, F-SOL-1, SOL-SYSTEMD-CLEANS and Q-SOL-7, as HS53's record holds them
     (HS53 also cites Q-MX6-R6, a matrix v6 decision, which v5 leaves out);
   - only OBSERVER's filter digests and program lengths change.
2. **Semantics.** The compiled filter must agree with `decide` on these and on your own probes (other bits, other high
   words, other roles):
   - OBSERVER `accept4` with flags 0, 0x80000 and 0x80800 is allowed, under any high word;
   - with 0x800, 0x80801, 0x40000, 1 and 0x80000000 it kills;
   - `bind` and `listen` are allowed with any arguments.

   Confirm the BPF compares only the low word of argument 3.
3. **The replay.** `v5Changes` lists exactly the 6 OBSERVER zero-argument `bind`, `listen` and `accept4` flips, and every
   other v4 decision check gives the same action under v5. Re-run the replay yourself.
4. **The model's new checks.** They refuse:
   - an unconditional or differently masked `accept4`;
   - a fourth flag value;
   - the condition on another argument;
   - `bind`, `listen` or `accept4` from a row that does not cite exactly HS53's OBSERVER row line, or from the runtime
     base.

   They change nothing for any other role. Mutations M24-M29 cover them.
5. **Consistency with HS53.** The §5.3 OBSERVER row and the obligation text. The README's limits: no descriptor family,
   residual R-OBSERVER-TCP-LISTEN, and the SERVER/BROKER row text kept from v4.
6. **Scope.** v4, the compiled programs and the edge records are untouched. No W03 or R10 content.
7. **Rounds 1 to 6.** Their seccomp checks passed. Confirm that since candidate 1 v5 changed only by SOL1-7 (the
   pinned row line, M29), its decision list (Q-SOL-5, SOL-SYSTEMD-CLEANS and Q-SOL-7 added; F-SOL-1 quoted with the
   author instructions elided, SOL2-5) and its README's Q-SOL-3 line (the units, SOL6-4), and that its vectors are
   byte-identical to candidate 2's.

Verdict: `PASS_FOR_SOURCE_PUBLICATION` or `CHANGES_REQUIRED`, with findings `{id, severity MAJOR|MINOR|NOTE, file, line,
summary, evidence}`.
