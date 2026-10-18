# Independent review brief — SELinux matrix v6 (SELINUX-MATRIX-V6), round 1

Status: **CONTRACT_CANDIDATE_AWAITING_INDEPENDENT_REVIEW**. The authoring agent wrote this brief. It is not a verdict.

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
- Pending with the monitor and built with (a): Q-MX6D-1 (transition closure for the qualk8s and planeon sources) and
  Q-MX6D-2 (the enrolled-file refusal on the matrix side). Review them as the contract's own choices.

## Changed v5 data, by index (XR4-2)

- Assertions: A59 (index 66) loses `planeon_server_t` from `allow`; A59.planeon_server_t (100),
  A59.planeon_observer_t (101), A59.planeon_broker_t (102), A59.planeon_worker_t (103) and A59.planeon_contain_t (106)
  change `allow` to their new peers. Each of the six gains "; Q-MX6-6 (a), NP4 Q-NP4-16 (a)" in `ref`. No other v5
  assertion changes, and indices 0-131 are stable; 41 assertions are appended (132-172).
- `procAccess`: 25 v5 entries removed (the server's 13, the broker's 12 other than the gate and the worker); the 20 left
  keep their order. No mutation addresses `procAccess` by index.
- `sourceClosures`: v5's 21 rows unchanged; 27 appended.
- New top-level keys: `mountSources`, `filesystem`, `filesystemAssociate`. Everything else, `types` included, is v5's.

## Questions to answer

1. **Successor fidelity.** Is v6 the v5 matrix plus exactly the disclosed changes, with v5 byte-identical? Is the
   evaluator v5's plus exactly the three extensions in its docstring (process-closure branch, the `filesystem` class,
   the `check_matrix` rules for the new keys and closures) and `entry_types`?
2. **Vectors.** Is every v5 vector kept with its identifier and position? Does `v6Changes` list exactly the v5 vectors
   whose expectation changes (27 access, 5 mutation), each with a true reason? Does every access and mutation check give
   its stated result, and do all 173 assertions hold? (`<workspace>/tools/matrix-v6/replay_v6.py` replays everything.)
3. **The qualk8s closure.** Does every qualk8s domain, the Pod domain included, get `execute_no_trans` on nothing,
   declared or not? Is the stated consequence (helpers refused until D-HELPER-TYPES) honest and complete?
4. **The transition closure.** Is the argument that `execute_no_trans` alone does not refuse an undeclared binary
   correct? Does the closure refuse transitions and dyntransitions of the sixteen closed sources into undeclared domains,
   the admin login and systemd, and leave every declared transition (broker to worker, runtime to Pod, init into each
   domain) as v5 had it?
5. **The `filesystem` class.** Is the kernel basis right for Linux v6.12 (`selinux_set_mnt_opts`,
   `may_context_mount_sb_relabel`, `may_context_mount_inode_relabel`, `selinux_sb_kern_mount`, `selinux_mount`,
   `selinux_umount`, `selinux_sb_statfs`, `may_create`)? Is the closure exact for the mount sources, and is the
   mount-source rule (`check_matrix`) the right scope given A47? Can a context=, fscontext=, rootcontext= or defcontext=
   mount by the kubelet or the runtime give a file an entrypoint, interpreter or other declared type, except through the
   two routes the README says data cannot close (MX6-O3)? Are those routes and the systemd row (MX6-O2) stated
   correctly? Is the A75.sock_file exception disclosed accurately?
6. **Reader narrowing.** Does every removed pair lack a duty in the published contracts (NP4's reader-duty table, W01
   §4.3 and §5.4 as amended by HS43)? Does every kept pair have one? Is NP4's premise P-a (the observer's `procAccess`)
   untouched? Do A59, A59.<target> and A69.* pin the new sets, and does re-adding a removed pair break them?
7. **Coupling with NP4.** Does v6 keep every type name NP4 fixes and every assertion NP4 cites (A12, A32, A33, A37, A47,
   A60.15-A60.21)? Are the T04 obligation rows by reference only, with no new proof id? Is `entryTypes` derived
   correctly, and is NP4's label list copied exactly from `5a3e6820`?
8. **Carried items.** Are XR4-1 to XR4-4 closed as the README says?
9. **Overclaims.** Does anything claim a policy module, a compiled or loaded policy, a selected distribution, a helper
   type, a host filesystem type, NP4's merge, or any E01-E12 or T04 proof?

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
