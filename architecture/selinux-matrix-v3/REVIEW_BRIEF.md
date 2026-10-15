# Independent review brief — SELinux matrix v5 (SELINUX-MATRIX-I04-KEYCERT), round 3

Status: **CONTRACT_CANDIDATE_AWAITING_INDEPENDENT_REVIEW**. The authoring agent wrote this brief. It is not a verdict.

Round 1 (`review-round1.json`, after adoption) returned CHANGES_REQUIRED: 1 MAJOR, 5 MINOR and 7 NOTE findings, XR1-1 to
XR1-13. Round 2 (`review-round2.json`) returned CHANGES_REQUIRED: 2 MINOR and 4 NOTE findings, XR2-1 to XR2-6. Each is
answered in the bytes as listed under "Round-1 answers" and "Round-2 answers" below.

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
- Owner decisions Q-MX-2 (b) and Q-MX-3 (b), 2026-10-15 (the owner first chose "keep and record" from the earlier
  framing, then the recommendation after the analysis): the observer takes the native profile's P1 and P5 captures
  (carried to the next native-profile successor and W03); the writer's `/proc` narrows to the gate and the observer, the
  gate's to the broker and the observer, with A59 per-target pins and mutations. The same message accepts the Q-MX-1
  shape.
- HS43 (`architecture/host-interface-amendment-hs43/amendment.json`):
  - W01 §5.3 EFFECT_GATE has no capability (H5).
  - The three O-MATRIX obligations above.

## Questions to answer

1. **Successor fidelity.** Is v5 the v4 matrix plus exactly the disclosed changes? Those are:
   - the two new types, appended last;
   - the gate's capability entry removed;
   - the gate's READ on the probe-worker leaf, and narrowed `dir search` grants on its two parents;
   - one `procAccess` entry appended last (the gate to the worker), and three v4 entries removed (the server and the
     broker to the writer, the server to the gate; Q-MX-2 (b), Q-MX-3 (b));
   - the A09, A38, A39 and A48 changes;
   - A38.<type> and A39.<type>;
   - A67, A68.<class> and A38S.<type>;
   - A59.planeon_worker_t gaining the gate;
   - the evaluator's one extension (narrowed READ grants), and nothing else in the evaluator;
   - A12, A13 and A36 gaining the new types as targets.

   Is every other v4 datum unchanged, and is every v4 type and assertion index stable? Is v4 byte-identical? (`procAccess`
   entries after a removed one move up; no v4 mutation addresses `procAccess` by index.)
2. **Vectors.** Is every v4 vector kept with its identifier and position? Is every changed expectation listed in
   `v5Changes` with a true reason? Does every access and mutation check produce exactly its stated result? Do all 132
   assertions hold on the v5 matrix?
3. **The I04 credentials.** Do `planeon_gate_i04_key_t` and `planeon_gate_i04_cert_t` give read only to the gate, and
   write and relabel only to the maintenance domain in the maintenance boot? Can any mutation that grants another reader
   pass A09 or A67? Is the shape (key alone; chain and client CA together) argued correctly from the facts?
4. **No capability for the gate.** Is the gate's `net_bind_service` gone from every route? Can a mutation that grants
   it pass A48?
5. **The Q-HE3D-2 grant.** Is it exactly what Q-MX-5 (a) approved (READ on the leaf, `dir search` on its two parents,
   `procAccess` on the worker), with nothing more? Is the narrowed-grant extension closed in `check_matrix` and exact in
   `allowed`, and can a narrowed grant reach anything outside its lists? Does each A38.<type> and A39.<type> allow exactly
   that type's readers? Do the stated kernel facts hold for Linux v6.12: ptrace-gated entries need the uid match or
   CAP_SYS_PTRACE, and SELinux labels each `/proc/<pid>` entry with the target's domain? Do they give the gate the
   worker's ungated entries only?
5b. **No capability for the gate (A68).** Does any capability-class grant to the gate pass all assertions?
6. **HS43 /proc evaluations.** Do the narrowed peer sets keep every duty the published contracts state (the gate's
   writer check, the broker's artifact check, the P1 and P5 captures by the designated observer)? Do the residuals
   narrow as stated? Do A59.planeon_policy_writer_t and A59.planeon_gate_t pin the new sets?
7. **Overclaims.** Does anything claim a policy module, a compiled or loaded policy, a selected distribution, the I04
   file paths, or any E01-E12 proof?

## Round-1 answers

| Finding | Answer |
|---|---|
| XR1-1 MAJOR | The three v4 README clauses HS43 supersedes now carry HS43's replacements: the gate also reads the writer's exe link, and P1 captures read exe links |
| XR1-2 MINOR | The gate's grant on the two parents is narrowed to `dir search` (evaluator extension; A38S.<type>; N14, N15; M68-M72) |
| XR1-3 MINOR | The F2 statement names the gate's v5 read |
| XR1-4 MINOR | A68.<class>: the gate holds no permission of any capability class (N16, N17; M66, M67) |
| XR1-5 MINOR | The HS43 /proc section and its change-table row say the decision is the owner's and open (Q-MX-2, Q-MX-3), and list the options |
| XR1-6 MINOR | The Files row states the assertion count |
| XR1-7 NOTE | The /proc statement is per class (exe needs `lnk_file read`), names the dumpable precondition, and gives ungated entries as examples |
| XR1-8 NOTE | Both places name K1's carry to W01's record |
| XR1-9 NOTE | A42 and A43 cited |
| XR1-10 NOTE | One type per credential, the chain and client CA counted as one public trust bundle |
| XR1-11 NOTE | The resolved spec's server-side mechanism is stated |
| XR1-12 NOTE | Question 1 lists A59.planeon_worker_t and the new assertions |
| XR1-13 NOTE | The README says what the grant reaches on the leaf, the parents and the worker's /proc |

## Round-2 answers

| Finding | Answer |
|---|---|
| XR2-1 MINOR | P1's exe-link reads are limited to the uid-0 roles; the other-uid worker's image capture is carried to the next native-profile successor ("Still open") |
| XR2-2 MINOR | The Cgroups row, the A38/A39 per-type row and the spec mapping state the narrowed parent grant, A38S and A68 |
| XR2-3 NOTE | The exception list names the broker's read of the gate's exe link (HS43) |
| XR2-4 NOTE | "Still open" names the owner's open Q-MX-2 and Q-MX-3 |
| XR2-5 NOTE | A09, A67 and every A38.<type>/A39.<type> now cover every READ permission (A38.<type> of the two parents: every one but search). No single READ permission granted to the gate on a parent, or to the server on either I04 type, passes all assertions |
| XR2-6 NOTE | The broken line is rewrapped; A67 now precedes the per-type and A68 assertions |

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
