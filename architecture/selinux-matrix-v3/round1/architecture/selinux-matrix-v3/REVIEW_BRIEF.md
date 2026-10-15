# Independent review brief — SELinux matrix v5 (SELINUX-MATRIX-I04-KEYCERT), round 1

Status: **CONTRACT_CANDIDATE_AWAITING_INDEPENDENT_REVIEW**. The authoring agent wrote this brief. It is not a verdict.

v5 is the successor of the adopted matrix v4 `../selinux-matrix-v2/` (`planeon.internal.selinux-matrix/v4`; review round
2 PASS_FOR_SOURCE_PUBLICATION, with G1 carried). The v4 bytes stay unchanged. README.md ("What v5 changes", "HS43 /proc
evaluations", "Owner decisions and facts for v5") states what changes and why.

## Subject

The subject is these exact bytes:
- README.md, this brief, `matrix.json` and `vectors.json`;
- the reference evaluator `scripts/selinux_matrix_v3.py`.

Check them against the predecessor inputs:
- the adopted v4 matrix, its vectors, README, evaluator `scripts/selinux_matrix_v2.py` and status;
- the HS43 amendment (`architecture/host-interface-amendment-hs43/`: obligations O-MATRIX-GATE-NETBIND,
  O-MATRIX-WRITER-PROCACCESS, O-MATRIX-GATE-PROCACCESS; residuals R-WRITER-PROC, R-GATE-PROC);
- the resolved W01 specification (`architecture/host-interface-inputs/resolved/HOST_INTERFACE_SPEC.md` §4.2);
- the native profile v3 README (P1, P5).

The v4-to-v5 diffs of `matrix.json`, `vectors.json` and the evaluator are the main review surface. Nothing else in the
working tree is part of the subject.

## Owner decisions and facts the matrix must carry out

- Monitor decision (owner-delegated), 2026-10-15: define the I04 key/cert SELinux type through a matrix amendment,
  before HE-008.
- Owner decision Q-HE3D-2 (a), 2026-10-15: the gate has no allowed source for observedWorkers, so in production BIND
  fails closed until fixed. The matrix carries the grant: gate READ on the probe-worker cgroup, and `procAccess` to
  `planeon_worker_t`.
- Facts relayed by the lane monitor, 2026-10-15:
  - The I04 server credential (the KUBERNETES_API_PROXY endpoint's key and certificate chain, resolved spec §4.2) has
    no named type in v4.
  - I04 is mutual TLS 1.3. The gate reads three DER files: its serving private key (PKCS#8), its serving certificate
    chain and exactly one client CA (owner Q-HE3D-8 (a)).
  - How the server holds its trust anchor and client credential is not fixed by any published contract, so treat the
    server as reading the gate's material only if a published contract says so.
  - No published contract assigns which reader role takes the native profile's P1 and P5 captures.
  - The gate's signed configuration is at `/etc/planeon/effect-gate/config.json` and `config.json.sig`
    (Q-HE3D-5 (a)), labelled `planeon_etc_t` and writable only by `planeon_maint_t` in maintenance mode.
  - The configuration pins its credential and CA files by sha256. HE-008 fixes the credential file paths; this
    matrix fixes the type and access.
  - The config-signer public key is compiled in (Q-HE3D-7 (d)).
- Monitor decisions (owner-delegated), 2026-10-15:
  - Q-MX-1 (a): separate credential types, gate-only READ on the key, least privilege elsewhere; the key type joins A09.
    The shape, including the client CA, is the contract's.
  - Q-MX-4 (a): drop the gate's `net_bind_service` and its A48 grant.
  - Q-MX-5 (a): the Q-HE3D-2 grant as specified.
  - Q-MX-2 and Q-MX-3 (narrowing the writer's and the gate's `/proc` peers) go to the owner. Until they are answered,
    the contract keeps both peer sets and records why.
- HS43 (`architecture/host-interface-amendment-hs43/amendment.json`):
  - W01 §5.3 EFFECT_GATE has no capability (H5).
  - The three O-MATRIX obligations above.

## Questions to answer

1. **Successor fidelity.** Is v5 the v4 matrix plus exactly the disclosed changes? Those are:
   - the two new types, appended last;
   - the gate's capability entry removed;
   - the gate's READ on three cgroup types;
   - one `procAccess` entry, appended last;
   - the A09, A38, A39 and A48 changes;
   - A38.<type> and A39.<type>;
   - A67;
   - A12, A13 and A36 gaining the new types as targets.

   Is every other v4 datum unchanged, and is every v4 type, `procAccess` entry and assertion index stable? Is v4
   byte-identical?
2. **Vectors.** Is every v4 vector kept with its identifier and position? Is every changed expectation listed in
   `v5Changes` with a true reason? Does every access and mutation check produce exactly its stated result? Do all 126
   assertions hold on the v5 matrix?
3. **The I04 credentials.** Do `planeon_gate_i04_key_t` and `planeon_gate_i04_cert_t` give read only to the gate, and
   write and relabel only to the maintenance domain in the maintenance boot? Can any mutation that grants another reader
   pass A09 or A67? Is the shape (key alone; chain and client CA together) argued correctly from the facts?
4. **No capability for the gate.** Is the gate's `net_bind_service` gone from every route? Can a mutation that grants
   it pass A48?
5. **The Q-HE3D-2 grant.** Is it exactly what the gate needs to count the probe worker's processes from its cgroup, and
   no more beyond what the README states (the parents' READ group)? Does each A38.<type> and A39.<type> allow exactly
   that type's readers? Do the stated kernel facts hold for Linux v6.12: ptrace-gated entries need the uid match or
   CAP_SYS_PTRACE, and SELinux labels each `/proc/<pid>` entry with the target's domain? Do they give the gate the
   worker's ungated entries only?
6. **HS43 /proc evaluations.** Are the two "not narrowed" outcomes justified by the published native profile (P1, P5)?
   Is the statement that no published contract names the capturing role true? Do the residuals stay as HS43 states
   them?
7. **Overclaims.** Does anything claim a policy module, a compiled or loaded policy, a selected distribution, the I04
   file paths, or any E01-E12 proof?

## How to check

You may run the v4 and v5 evaluators read-only from the repository root (`python3 -I -B`, loading the scripts by path).
You may also run the builder `~/.local/state/harness-onion-ci/tools/matrix-i04/build_selinuxv3.py` against a copy of the
repository in your scratch directory, never against the worktree.

Run one process at a time, each at most 120 seconds. Do not run the repository test suite or validators, and do not
modify any repository file; scratch files go outside the repository. Stop at once when asked to pause, and continue only
when told to resume.

## Result

Write a JSON record with the round, the subject commit, a verdict (PASS_FOR_SOURCE_PUBLICATION or CHANGES_REQUIRED), and
findings, each with an id, severity (MAJOR, MINOR or NOTE), file, line, summary and evidence.
