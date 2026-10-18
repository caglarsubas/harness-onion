# Independent review brief — SELinux matrix v6 (SELINUX-MATRIX-V6), round 4

Status: **CONTRACT_CANDIDATE_AWAITING_INDEPENDENT_REVIEW**. The authoring agent wrote this brief. It is not a verdict.

Round 1 (of candidate `7f1a4e1885eef0c4803e5d015d997436d23be0c5`) returned CHANGES_REQUIRED: 3 MAJOR, 5 MINOR and 4
NOTE findings, XV1-1 to XV1-12. README "Contract review round 1 (v6) findings and dispositions" and "Round-1 answers"
below answer each. Round 2 (of candidate `e398cb5328acb121b2cc473a5057f1febe0d784a`) returned CHANGES_REQUIRED: 2 MINOR
and 3 NOTE findings, XV2-1 to XV2-5, answered under "Round-2 answers" and in README "Contract review round 2 (v6)
findings and dispositions". Between rounds 2 and 3 the primary lane asked, through the lane monitor, for three
invariants to be explicit (README "Invariants other contracts rely on"). Round 3 (of candidate
`ce83d913abc48eded33b566bae7a23be20a02724`) returned CHANGES_REQUIRED: 1 MINOR and 4 NOTE findings, XV3-1 to XV3-5,
answered under "Round-3 answers" and in README "Contract review round 3 (v6) findings and dispositions".

v6 is the successor of the adopted matrix v5 `../selinux-matrix-v3/` (`planeon.internal.selinux-matrix/v5`; review round
4 PASS_FOR_SOURCE_PUBLICATION, with XR4-1 to XR4-4 carried). The v5 bytes stay unchanged. README.md ("What v6 changes"
and the five sections after it) states what changes and why.

## Subject

The subject is these exact bytes:
- README.md, this brief, `matrix.json` and `vectors.json` in this directory;
- the reference evaluator `scripts/selinux_matrix_v4.py`.

Check them against the predecessor inputs:
- the adopted v5 matrix, its vectors, README, `status.json` (carried XR4-1 to XR4-4) and evaluator
  `scripts/selinux_matrix_v3.py`;
- native-profile v4 + I06 v3 as adopted in the primary lane, read only at commit
  `5a3e6820cf23325dd8c68f8c083d53ac805f2b06` (`git show 5a3e6820:architecture/native-profile-v4/README.md`; it is not on
  main): P-a, P-b, ENTRY_BOUND, the Backends section, the label constants, the T04 table, the reader-duty table and the
  open items;
- the HS43 effective specification (`architecture/host-interface-amendment-hs43/HOST_INTERFACE_SPEC.md`: §4.3, §5.3,
  §5.4) and HS43's obligation O-W03-WORKER-EXEC.

The v5-to-v6 diffs of `matrix.json`, `vectors.json` and the evaluator are the main review surface. Nothing else in the
working tree is part of the subject.

## Owner and monitor decisions the matrix must carry out

- Owner, 2026-10-16 (relayed verbatim by the lane monitor; quoted in README "Owner and monitor decisions for v6"):
  Q-MX6-2 (a) every qualk8s domain closed over its declared executable types, undeclared binaries refused, helper types
  later through W02-PROD; Q-MX6-3 (a) the Pod domain included; Q-MX6-4 (a) the kubelet and the runtime: the filesystem
  mount, remount, unmount, relabelfrom/relabelto, associate and getattr permissions plus mounton on context= labels,
  init_t out of scope with a T04 obligation that systemd makes no context= mount of a declared type; Q-MX6-7 (a)
  BROKER-CLONE-INTO-CGROUP is a contract obligation, not matrix data.
- Lane monitor (owner-delegated), 2026-10-16: Q-MX6-1 (a) draft against `5a3e6820`, adopt after NP4's packet merges,
  re-checking the coupling; Q-MX6-5 (a) T04 by reference to NP4's proof ids plus matrix-local rows, no errata, so NP4
  stays byte-identical (no type renamed, no proof id added); Q-MX6-6 (a) MATRIX-READER-NARROWING folded in, `/proc`
  only; Q-MX6-8 (a) XR4-1 to XR4-3 and NP4's enrolled-file refusal in v6.
- Owner, 2026-10-16, on the fail-closed consequence: "Keep, T04 uses v5": v6 stays fail-closed; until a successor
  declares the helper types, T04 cluster qualification runs against matrix v5, recorded as a named limitation.
- Lane monitor (owner-delegated), 2026-10-16: Q-MX6D-1 (a) the transition closure for the 9 qualk8s and the 7 planeon
  sources, stated as binding R10's worker; Q-MX6D-2 (a) the enrolled-file refusal on the matrix side, the model refusal
  carried to the next native-profile successor. All quoted verbatim in README "Owner and monitor decisions for v6".

## Changed v5 data, by index (XR4-2)

- Assertions: A59 (index 66) loses v5's duplicate `planeon_broker_t` entry (the union is unchanged) and gains
  "; review XV1-12" in `ref`; A59.planeon_server_t (100), A59.planeon_observer_t (101), A59.planeon_worker_t (103) and
  A59.planeon_contain_t (106) change `allow` to their new peers and gain "; Q-MX6-6 (a), NP4 Q-NP4-16 (a)" in `ref`.
  No other v5 assertion changes, and indices 0-131 are stable; 75 assertions are appended (132-206).
- `procAccess`: 24 v5 entries removed (the server's 11 other than the observer and the broker, the broker's 13 other
  than the gate); the 21 left keep their order. No mutation addresses `procAccess` by index.
- `sourceClosures`: v5's 21 rows unchanged; 43 appended.
- New top-level keys: `mountSources`, `filesystem`, `filesystemAssociate`. Everything else, `types` included, is v5's.

## Questions to answer

1. **Successor fidelity.** Is v6 the v5 matrix plus exactly the disclosed changes, with v5 byte-identical? Is the
   evaluator v5's plus exactly the extensions in its docstring (the process and entrypoint closures, the `filesystem`
   class, the six `check_matrix` rules) and `entry_types`?
2. **Vectors.** Is every v5 vector kept with its identifier and position? Does `v6Changes` list exactly the v5 vectors
   whose expectation changes (24 access, 5 mutation), each with a true reason? Does every access and mutation check give
   its stated result, and do all 207 assertions hold? (4,531 access checks and 105 mutation checks.) (`<workspace>/tools/matrix-v6/replay_v6.py` replays everything.)
3. **The qualk8s closure.** Does every qualk8s domain, the Pod domain included, get `execute_no_trans` on nothing,
   declared or not? Is the stated consequence (helpers refused until D-HELPER-TYPES) honest and complete?
4. **The transition and entry closures.** Is the argument that `execute_no_trans` alone does not refuse an undeclared
   binary correct? Does the transition closure refuse transitions and dyntransitions of the sixteen closed sources into
   undeclared domains, the admin login and systemd, and leave every declared transition (broker to worker, runtime to
   Pod, init into each domain) as v5 had it? Does the entry closure (XV1-2) enter each closed domain only through its
   granted types, without breaking any declared transition?
5. **The `filesystem` class.** Is the kernel basis right for Linux v6.12 (`selinux_set_mnt_opts`,
   `may_context_mount_sb_relabel`, `may_context_mount_inode_relabel`, `selinux_sb_kern_mount`, `selinux_mount`,
   `selinux_umount`, `selinux_sb_statfs`, `may_create`)? Is the closure exact for the mount sources, and is the
   mount-source rule (`check_matrix`) the right scope given A47? Can a context=, fscontext=, rootcontext= or defcontext=
   mount by the kubelet or the runtime give a file an entrypoint, interpreter or other declared type, except through the
   two routes the README says data cannot close (MX6-O3)? Are those routes and the systemd row (MX6-O2) stated
   correctly? Is the A75.sock_file exception disclosed accurately?
6. **Reader narrowing.** Does every removed pair lack a duty in the published contracts (NP4's reader-duty table, W01
   §4.3 and §5.4 as amended by HS43, the v1 peer duties HS43 §4.3 keeps: `docs/alpha-2/NATIVE_QUALIFICATION_READINESS.md`,
   `docs/alpha-2/OBSERVATION_ENFORCEMENT_DESIGN.md`, `architecture/accounting-scope-inputs/readiness.json`)? Does every
   kept pair have one? Is NP4's premise P-a (the observer's `procAccess`)
   untouched? Do A59, A59.<target> and A69.* pin the new sets, and does re-adding a removed pair break them?
6b. **The primary's three invariants.** Do (a) the gate's `procAccess` to the probe worker, (b) the observer's 15
   pairs and (c) the interpreted roles' entry (the interpreter never an entrypoint) hold, and do the listed pins
   (Q14, Q54, Q57, Q72, Q81-Q97, N39, N40, A60.49, A60.52, A77.planeon_interpreter_exec_t) fail if any of them is removed?
7. **Coupling with NP4.** Does v6 keep every type name NP4 fixes and every assertion NP4 cites (A12, A32, A33, A37, A47,
   A60.15-A60.21)? Are the T04 obligation rows by reference only, with no new proof id? Is `entryTypes` derived
   correctly, and is NP4's label list copied exactly from `5a3e6820`?
8. **Carried items.** Are XR4-1 to XR4-4 closed as the README says?
9. **Overclaims.** Does anything claim a policy module, a compiled or loaded policy, a selected distribution, a helper
   type, a host filesystem type, NP4's merge, or any E01-E12 or T04 proof?

## Round-1 answers

| Finding | Answer |
|---|---|
| XV1-1 MAJOR | `relabelfrom` on container content for both mount sources (a plain context= mount sets the root context too); `associate` closed into every declared label whatever the file's type, so A73 (undeclared sample sources added) refuses fscontext= chaining and rootcontext= over container content; A70 covers the other declared labels; Q78, Q79, P21; M78 retargeted to a sealed label |
| XV1-2 MAJOR | `file entrypoint` closures for the sixteen closed domains (A60.49-A60.64; Q80, Q81, P22-P24; M100, M101, M103); README "Transitions and entry of closed sources" |
| XV1-3 MAJOR | The server keeps the observer and the broker (v1 I01/I02 peer qualification, kept by HS43 §4.3); the pair-by-pair table cites the v1 sources; A69.planeon_server_t follows |
| XV1-4 MINOR | Both records quoted verbatim; Q-MX6D-1/2 decided; the named limitation in the introduction, "Still open" and MX6-O4; "This binds R10's worker" |
| XV1-5 MINOR | MX6-O3 reworded (filesystem-supplied labels unless context=; the associate clause for entrypoint, interpreter and closure types); the `/run` rootcontext= residual stated |
| XV1-6 MINOR | A75.dir and A75.file cover the runtime socket file; `check_matrix` keeps socket-file types to `sock_file` (M102) |
| XV1-7 MINOR | broker to worker removed: W3 reads the pre-exec child in the broker's domain; no post-exec duty (N29, M99) |
| XV1-8 MINOR | MX6-O1 and MX6-O6 owned by W03's policy module and the T04 successor that adopts v6; the T04 section says no NP4 proof checks them |
| XV1-9 NOTE | The new mount API stated in the kernel basis |
| XV1-10 NOTE | "executes (execve)", the mapping route and its owner, the Pod-internal consequence, the helper list as examples |
| XV1-11 NOTE | MX6-O7 (transient units and systemd's manager interface) |
| XV1-12 NOTE | A59 deduplicated; the six new `check_matrix` rules listed |

## Round-2 answers

| Finding | Answer |
|---|---|
| XV2-1 MINOR | MX6-O8: the mount sources mount only on their own mount points, never on an ancestor of a planeon or backend path; the residual narrowed to the `/run/planeon` objects |
| XV2-2 MINOR | Every row cites NP4 proofs by reference only; MX6-O2, O3 and O5 checked by them only in part; each row names the T04 successor that adopts v6 |
| XV2-3 NOTE | Bind mounts unaffected; the disk and overlay consequence stated |
| XV2-4 NOTE | The v1 worker check of its broker stated as retired in the matrix (no pair since v3) |
| XV2-5 NOTE | The maintenance domain stated as not closed; M97's intent reworded |

## Round-3 answers

| Finding | Answer |
|---|---|
| XV3-1 MINOR | A77.<type> over every domain: each entry type enters only its own domain, the interpreter type none (M104, M105) |
| XV3-2 NOTE | Invariant (a) names the gate-to-broker pair (Q14) |
| XV3-3 NOTE | NP4 README:202-213 and the relay cited |
| XV3-4 NOTE | MX6-O8: host mount namespace, state-directory mount points and their files, `/proc`, `/sys`, propagation, `pivot_root` |
| XV3-5 NOTE | "relates to"; MX6-O4's owners named |

## How to check

Run the evaluators read-only from the repository root (`python3 -I -B`, loading the scripts by path). The replay
`<workspace>/tools/matrix-v6/replay_v6.py REPO` and the builders `build_v6.py REPO` and `make_readme_v6.py REPO` in the
same directory may be run only against a copy of the repository in your scratch directory, never against the worktree.
Read native-profile v4 only through `git show 5a3e6820:<path>`.

Run one process at a time, each at most 120 seconds. Do not run the repository test suite or validators, and do not
modify any repository file; scratch files go outside the repository. Stop at once when asked to pause, and continue only
when told to resume.

## Result

Write a JSON record with the round, the subject commit, a verdict (PASS_FOR_SOURCE_PUBLICATION or CHANGES_REQUIRED), and
findings, each with an id, severity (MAJOR, MINOR or NOTE), file, line, summary and evidence.
