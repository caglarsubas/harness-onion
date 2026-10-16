# Independent review brief — I05 broker-gate channel v4 (I05-OBSERVED-WORKERS), round 2

Status: **CONTRACT_CANDIDATE_ROUND2_AWAITING_INDEPENDENT_REVIEW**. The authoring agent wrote this brief. It is not a
verdict.

Round 1 returned CHANGES_REQUIRED: 4 MINOR findings and 4 NOTEs, IR1-1 to IR1-8. README "Round-1 findings and
dispositions" answers each one in the bytes.

v4 succeeds the adopted I05 v3 contract `../i05-gate-channel-v3/` and its supplement
`../i05-gate-channel-v3-supplement/`, whose bytes stay unchanged. README.md states what v4 changes and why. Read it in
these sections:
- "What v4 changes";
- "The observation", with rules 1-9;
- "Decisions (verbatim)";
- "Constraints".

## Subject

The subject is these exact bytes:
- README.md, this brief, and `vectors.json`;
- the reference model `scripts/i05_gate_channel_v4.py`.

Check them against the predecessor inputs:
- the adopted v3 contract (README, `channel.schema.json`, `outcome-mapping.json`, `vectors.json`, `status.json`), the
  v3 model `scripts/i05_gate_channel_v3.py`, and the supplement;
- the seccomp allowlists v4 (`architecture/seccomp-allowlists-v4/`, role EFFECT_GATE and its runtime base);
- the SELinux matrix v5 (`architecture/selinux-matrix-v3/`, the Q-HE3D-2 grant);
- the HS43 amendment (`architecture/host-interface-amendment-hs43/`).

The v3-to-v4 diff of the model is the main review surface. Nothing else in the working tree is part of the subject.

## Owner decisions and facts v4 must carry out

They are recorded verbatim in README "Decisions (verbatim)" and "Constraints", and in the author's decision record,
which your task brief names:
- **Q-I5-1..4** (owner Q-I5-4; monitor, owner-delegated, Q-I5-1..3), each (a):
  - a fresh read at every BIND;
  - every failure gives WORKER_NOT_OBSERVED, non-fatal and retryable, journaled locally, with no wire change;
  - the identity is pidfd-confirmed;
  - any member matches.
- **The v3 bytes.** The v3 frame schema and the supplement stay byte-identical.
- **SLOT241-FACTS C1-C4:**
  - C1: the seccomp v4 EFFECT_GATE allowlist;
  - C2: openat on dir fds only;
  - C3: matrix v5 reachability (the leaf's cgroup.procs, and the worker's stat and status);
  - C4: the HS43 identity, pid plus start time, race-free via pidfd.

## Confirmed readings and the author's own rules

The monitor confirmed both readings of the decisions (Q-I5-READINGS, quoted in README "Decisions"):
- "journaled locally" is a local diagnostic log;
- the cgroup check is a second `cgroup.procs` read.

Examine the rules the author added on their own:
- rule 5's bounds and parsing;
- rules 2, 8 and 9's host preconditions, carried to W03/T04.

Are they precise, and do they fail closed?

## What to check

1. **No wire change.**
   - Does every v3 and supplement transcript replay identically under v4?
   - Are the frame checks, byte checks and agreement cases unchanged?
   - Is the outcome mapping v3's?
   - Can any v4 path emit a frame, field or refusal reason that v3 could not?
2. **The observation.**
   - Do the five steps in the model match README "The observation" step for step, with each failure mapped to its local
     cause?
   - Is rule 1's race-freedom argument sound for Linux pidfds? Cover reaping, zombies, PID reuse and the poll semantics
     of a pidfd for a non-child.
   - Is any interleaving the vectors miss a real hole? For example, the worker moved into the leaf only between steps 1
     and 4.
3. **Q-I5-2.**
   - Does every refused observation leave the gate's whole snapshot unchanged?
   - Is the channel kept open and the BIND retryable?
   - Does any refusal path write the durable journal or the failure marker?
4. **Constraints C1-C4.**
   - Is every syscall the observation needs on the seccomp v4 EFFECT_GATE allowlist, its NATIVE_STATIC runtime base
     included?
   - Is every file inside the matrix v5 grant?
   - Is any ptrace-gated entry read?
   - Does any claim about kernel behaviour lack its stated basis? These are: starttime printed without ptrace access;
     `pidfd_open` without `PIDFD_THREAD` refusing a thread ID; `cgroup.procs` listing only the leaf's own TGIDs.
5. **Vectors and checker.** (Include the new O17-O19, the exact OBSERVING and the (step, cause) coverage.)
   - Is `check_vectors` closed (exact key sets, ordered IDs, floors)?
   - Does it refuse tampering?
   - Is coverage complete: every cause, every step's read failure, and the races?
   - Are the configuration and event refusals exact?
   - Is OBSERVING exactly v3's ACTIVE, converted, plus two processes?
6. **Round 1.** Does each disposition in README "Round-1 findings and dispositions" answer its finding in the bytes?
7. **Overclaims.** Does anything claim an installed gate, a real `/proc` read, R10 adoption, a native result or any
   E01-E12 proof?

## How to check

You may run the v3 and v4 models read-only from the repository root (`python3 -I -B`, loading the scripts by path), and
`check_vectors` with the pinned v3 files. You may also run the author's builders, which your task brief names,
against a copy of the repository in your scratch directory, never against the worktree.

Run one process at a time, each at most 120 seconds. Do not run the repository test suite or validators, and do not
modify any repository file. Scratch files go outside the repository. Stop at once when asked to pause, and continue only
when told to resume.

## Result

Write a JSON record with:
- the round and the subject commit;
- a verdict, PASS_FOR_SOURCE_PUBLICATION or CHANGES_REQUIRED;
- findings, each with an id, severity (MAJOR, MINOR or NOTE), file, line, summary and evidence.
