# I05 broker-gate channel v4 — I05-OBSERVED-WORKERS contract (DATA_CHECK_ONLY)

Alpha 2A; 2026-10-16. Status: **CONTRACT_CANDIDATE_ROUND1_AWAITING_INDEPENDENT_REVIEW** (brief: `REVIEW_BRIEF.md`).

v4 succeeds the adopted I05 v3 contract `../i05-gate-channel-v3/` (`planeon.internal.effect-gate-frame/v3`,
ADOPTED_DATA_CONTRACT) and its supplement `../i05-gate-channel-v3-supplement/`. Later layers pin the v3 bytes
(`architecture/enforcement-test-plan/traceability.json`), so v3 and the supplement stay byte-identical. v4 is published
beside them as a model, vectors and README successor. **The wire does not change.** Frames keep the v3 schema and version
string (`planeon.internal.effect-gate-frame/v3`), the outcome mapping is v3's, and there is no new operation, field or
refusal reason. v4 changes one thing: how the gate knows that the worker a BIND_EXECUTION names is the broker's probe
worker.

- **v3** took that from a static configuration list (`observedWorkers`). v3's own source table (README "Where each
  request value comes from") already names the source as KERNEL, "a live member of the broker's probe-worker cgroup".
- **The merged R10 gate** (HE-003D) holds that list empty and refuses a non-empty one, so every production BIND fails
  closed until this successor (owner decision Q-HE3D-2 (a)).
- **v4** defines the observation: the gate reads the kernel at every BIND.

Nothing here opens a socket, reads `/proc` or installs a gate; all E01-E12 stay OPEN_UNPROVEN.

Accepted base: main `5e83b257` (MET-ENFORCE-028, 239 packets). Publication slot 241, after slot 240 merges (lane monitor
sequencing decision SEQ-241-242).

## Files

| File | Content |
|---|---|
| `vectors.json` | `planeon.internal.effect-gate-model-vectors/v4`: v3 inputs pinned by SHA-256, one configuration (OBSERVING), 16 observation transcripts O01-O16 (each with outputs, final snapshot and local observation log), 9 configuration refusals C01-C09 and 9 event refusals E01-E09 |
| `../../scripts/i05_gate_channel_v4.py` | Reference model: the v3 model with the gate's observation (`Gate._observe_worker`), `convert_v3_config`, `replay_observed` and `check_vectors` |
| `../i05-gate-channel-v3/channel.schema.json`, `outcome-mapping.json` | Unchanged; v4 uses them as they are |

The v4 model is a copy of the v3 model with the changes below. The v3-to-v4 diff of `scripts/i05_gate_channel_v3.py` and
`scripts/i05_gate_channel_v4.py` is the review surface. Every function that checks or renders the wire (`decode_frame`,
`check_frame`, `render_request`, `template_digest`, `identity_of`, `check_agreement`) is unchanged.

`check_vectors(vectors, files)` makes 255 checks:

- **v3 replay (221 checks).** Every v3 transcript (120) and supplement transcript (6), with its configuration converted by
  `convert_v3_config`, replays under v4 to the same outputs and final snapshot. Every v3 configuration refusal (5), frame
  check (34), byte check (14) and agreement case (42) gives v3's expected answer.
- **v4 vectors (34 checks).** The 16 transcripts, 9 configuration refusals and 9 event refusals.

## What v4 changes

| Area | v3 | v4 |
|---|---|---|
| Worker source | `observedWorkers`, a static list of (pid, start ticks) pairs in the gate's configuration | No list. The configuration lists no workers. The model takes a `kernel` table (`processes`: pid, start ticks, cgroup) that stands for the kernel the gate reads. A configuration with `observedWorkers` is refused (C01). |
| BIND check | (pid, start) in the list, else WORKER_NOT_OBSERVED | The observation below, at every BIND, else WORKER_NOT_OBSERVED |
| Refusal cause | None recorded | A local diagnostic log (`Gate.observations`): (pid, start ticks, result) per observation. It is not the durable journal, not in the snapshot and not on the wire. |
| Model-only events | v3's injections | Also KERNEL_SPAWN, KERNEL_EXIT and KERNEL_MOVE (the kernel moves on), OBSERVATION_FAIL_NEXT {step} (a read fails) and OBSERVATION_RACE_NEXT {after, event} (a kernel event lands between two reads). These are test inputs, never channel frames, and their shapes are closed (E01-E09). |
| Conversion | — | `convert_v3_config`: each v3 `observedWorkers` pair becomes a live process in the probe-worker leaf. |

## The observation

The gate observes only for a BIND that passes every v3 check before it (peer, state, outstanding actions, replay,
generation, binding, certificate, manifest reuse). The gate holds a directory fd on the cgroup2 mount and one on `/proc`,
and opens every file with `openat` relative to one of them (Q-HE2S-G (b)).

| Step | Read | Pass condition | Failure (local cause) |
|---|---|---|---|
| 1 CGROUP_PROCS | `openat` `planeon.slice/planeon-capacity-broker.service/probe-worker/cgroup.procs` from the cgroup2 root fd, then `read` and `close` | The BIND's workerPid is listed | Unreadable: CGROUP_PROCS_UNREADABLE. Not listed: NOT_A_MEMBER |
| 2 PIDFD_OPEN | `pidfd_open(workerPid, 0)` | A pidfd is returned | ESRCH: PROCESS_GONE. Any other error: PIDFD_OPEN_FAILED |
| 3 STAT | `openat` `<pid>/stat` from the `/proc` fd, `read`, `close`; starttime is field 22 | starttime equals workerStartTicks | Unreadable or malformed: STAT_UNREADABLE. Gone (ENOENT or ESRCH): PROCESS_GONE. Other value: START_MISMATCH |
| 4 CGROUP_RECHECK | `cgroup.procs` of the leaf again, as in step 1 | workerPid is still listed | Unreadable: CGROUP_RECHECK_UNREADABLE. Not listed: NOT_IN_PROBE_WORKER_CGROUP |
| 5 PIDFD_ALIVE | `ppoll` (or `poll` or epoll) on the pidfd with a zero timeout, then `close` the pidfd | Not readable: the held process has not exited | Poll error: PIDFD_POLL_FAILED. Readable (exited): PIDFD_EXITED |

Rules:

1. **Race-free identity (Q-I5-3).** A PID is reused only after its process has exited and been reaped. If the pidfd
   from step 2 shows no exit at step 5, the PID named the held process for the whole span of steps 3 and 4. So the start
   time and membership that the gate read are the held process's. Step 1 runs before the pidfd exists and only selects
   candidates; step 4 re-proves membership for the held process. An exit anywhere in the span refuses, even when nothing
   else takes the PID (O16). A reuse with the same start ticks in the same leaf is caught only by step 5 (O13).
2. **Membership (Q-I5-4, owner).** The BIND's (pid, start ticks) must be a member. Other members of the leaf do not
   refuse (O02). `cgroup.procs` lists the leaf's own thread-group IDs, not its descendants', so a worker in a child of the
   leaf is NOT_A_MEMBER (fails closed). The BIND's workerPid must be a thread-group ID: `pidfd_open` without
   `PIDFD_THREAD` refuses a thread ID.
3. **A fresh read at every BIND (Q-I5-1).** The gate keeps no worker list and caches no earlier answer. A worker
   spawned after the generation started is observed at its BIND (O15). A worker that has exited is not (O05).
4. **Every failure is WORKER_NOT_OBSERVED (Q-I5-2).** Every step's failure, a kernel read error included, gives the
   existing refusal `{"result": "REFUSED", "reason": "WORKER_NOT_OBSERVED"}`.
   - It is non-fatal: the channel stays OPEN and the generation keeps its state.
   - It is retryable: a later BIND with the same values may bind (O06-O10).
   - It writes nothing durable: the gate's whole snapshot, the durable journal and the failure marker included, is
     unchanged by the refused BIND. `check_vectors` checks this for every refused observation.
   - The cause goes to the local diagnostic log. The wire answer does not say which step failed.
5. **Parsing.**
   - `cgroup.procs` is one decimal TGID per line, each line ending in a newline. Anything else is unreadable.
   - For `stat`, the gate takes the fields after the last `)` (the command name may contain spaces and parentheses).
     starttime is the 20th of those fields (field 22 of the line), a decimal integer. A line that does not parse is
     STAT_UNREADABLE.
   - The kernel prints starttime for a reader without ptrace access to the target. The fields it zeroes for such a
     reader (the memory layout and stack fields) are other fields.
   - The reads are bounded:
     - one `stat` line of at most 4096 bytes;
     - a `cgroup.procs` of at most 65536 bytes;
     - beyond either bound the read is unreadable.
6. **Reachable reads only.** The observation reads the leaf's `cgroup.procs`, the worker's ungated `/proc/<pid>/stat`,
   `pidfd_open` and a poll. It does not read `/proc/<pid>/cgroup`, `status`, `exe` or any ptrace-gated entry. It does not
   list directories (`getdents64`), watch files (inotify) or wait on a child (`waitid`).
7. **Cgroup namespace.** Steps 1 and 4 open the leaf by its path below the cgroup2 root the gate holds. A gate whose
   cgroup2 root fd is not the host's root (a private cgroup namespace or mount) reaches another directory, or none. Every
   BIND then fails closed, with CGROUP_PROCS_UNREADABLE or NOT_A_MEMBER.

## Decisions (verbatim)

- **Q-I5-DECISIONS (2026-10-16).** Owner (Q-I5-4) and lane monitor (owner-delegated Q-I5-1..3), relayed by the lane
  monitor:

  > I05 v4 decisions, 2026-10-16. Owner: Q-I5-4 = (a). The BIND's (pid, starttime) must be a member; other members
  > don't refuse. Monitor (owner-delegated): Q-I5-1 = (a): a fresh read at every BIND_EXECUTION. Q-I5-2 = (a): every
  > observation failure refuses with the existing WORKER_NOT_OBSERVED, non-fatal and retryable, journaled locally, with
  > no wire change. Q-I5-3 = (a): pidfd-confirmed: cgroup.procs → pidfd_open → stat starttime and cgroup check → pidfd
  > still not exited. Defaults B1, B4 and B6 hold as you stated. So I05 v4 is a model, vectors and README successor; the
  > v3 frame schema bytes and its supplement stay byte-identical.

- **The defaults B1, B4 and B6.** As stated to the monitor:
  - B1: `cgroup.procs` plus `/proc/<pid>/stat` starttime;
  - B4: any matching member;
  - B6: the identity is (pid, starttime).
- **SEQ-241-242 (lane monitor, 2026-10-16).** Slot 241 is I05-OBSERVED-WORKERS (I05 v4, observedWorkers from the
  probe-worker cgroup, KERNEL) in the parallel lane.

How v4 reads two phrases of the decisions (recorded for review):

- **"journaled locally".** v4 reads it as the gate's local diagnostic log, not the I05 durable journal. The durable
  journal's digest is on the wire (GENERATION_STATUS `journalDigest`), and a refused BIND must write nothing durable for
  "no wire change" and for v3 to replay. The log's storage, retention and format belong to the R10 implementation.
  The model keeps it as an in-memory list.
- **"stat starttime and cgroup check".** v4 makes the cgroup check a second read of the leaf's `cgroup.procs` (step 4),
  not a read of `/proc/<pid>/cgroup`. It stays inside the reachable set the monitor relayed (constraint C3:
  `cgroup.procs`, `stat` and `status`) and inside the matrix v5 grant (READ on the leaf only). It needs no cgroup-path
  parsing and is not affected by cgroup namespaces. Both forms are equally race-free under rule 1.

## Constraints (relayed by the lane monitor as decision texts and published pointers)

| Constraint (SLOT241-FACTS, 2026-10-16) | How v4 meets it |
|---|---|
| C1 "Seccomp allowlists v4 (main), EFFECT_GATE: only syscalls on that allowlist are usable." | The observation uses only these syscalls. `openat`, `read`, `pread64`, `fstat`, `lseek` and `close` are in the EFFECT_GATE duty rows (`architecture/seccomp-allowlists-v4/allowlists.json`). `pidfd_open` is in the row "peers qualified with pidfd, SO_PEERCRED and same-uid /proc reads". `ppoll`, `epoll_*` and (x86_64) `poll` come from the NATIVE_STATIC runtime base. No `getdents64`, `statx`, `newfstatat`, `inotify_*`, `waitid` or `pidfd_getfd`. |
| C2 "Owner Q-HE2S-G (b): the gate opens files only via openat on dir fds (no std::fs opens)." | Every open is an `openat` relative to the held cgroup2-root or `/proc` directory fd. |
| C3 "Matrix v5 (main): only the probe-worker leaf READ, search on its two parents, and procAccess to planeon_worker_t; the worker is other-uid, so only cgroup.procs, stat and status are reachable." | The path walk crosses `planeon.slice` and `planeon-capacity-broker.service` (search only) to the `probe-worker` leaf (READ: `cgroup.procs`). `/proc/<pid>/stat` uses procAccess on `planeon_worker_t`. The `status` entry is not needed. |
| C4 "HS43 precedent (owner Q-HS43-1 (a)): the identity is pid plus the start time from /proc/<pid>/stat, race-free where possible (pidfd); a pidfd for another process needs pidfd_open." | The identity is (workerPid, workerStartTicks), with the start time from `/proc/<pid>/stat` field 22. `pidfd_open` gives the pidfd, and rule 1 makes the reads race-free. |

The monitor also relayed: "Nothing in R10 fixes B1-B6. ... That rule is removed by the R10 packet that adopts your I05
v4. So I05 v4 DEFINES B1-B6, and R10 follows it."

## Vectors

The one configuration is **OBSERVING**:
- v3's ACTIVE, converted: worker 4100 (start 900001) in the leaf;
- a second leaf member, 4300 (900003);
- a process outside the leaf, 5100 (800001), in `/planeon.slice/planeon-proxy-server.service`.

`check_vectors` refuses an OBSERVING that is not exactly this extension of v3's ACTIVE.

| ID | Case | Result |
|---|---|---|
| O01 | The worker is a live leaf member with that start time | OBSERVED, binds |
| O02 | Another leaf member is named | OBSERVED (Q-I5-4) |
| O03 | A process outside the leaf | NOT_A_MEMBER; the journal digest is unchanged |
| O04 | The right PID with another start time | START_MISMATCH |
| O05 | The worker exited before the BIND | NOT_A_MEMBER |
| O06-O10 | Each step's read fails once; the retried BIND binds | CGROUP_PROCS_UNREADABLE, PIDFD_OPEN_FAILED, STAT_UNREADABLE, CGROUP_RECHECK_UNREADABLE, PIDFD_POLL_FAILED, then OBSERVED |
| O11 | Race: the worker exits after step 1 | PROCESS_GONE |
| O12 | Race: after step 1 the PID is reused outside the leaf with another start | START_MISMATCH |
| O13 | Race: after step 2 the PID is reused in the leaf with the same start | PIDFD_EXITED |
| O14 | Race: the worker is moved out of the leaf after step 3 | NOT_IN_PROBE_WORKER_CGROUP |
| O15 | A worker spawned after the generation started | OBSERVED |
| O16 | Race: the worker exits after step 4 | PIDFD_EXITED |

Every observation result occurs at least once; `check_vectors` requires this. Every injection is consumed by the end of
its transcript, and there is one observation per BIND.

**C01-C09** refuse malformed configurations:
- a static `observedWorkers` list;
- a missing, open or non-list kernel table;
- a process with another field;
- a duplicate PID, a boolean PID, a relative cgroup path or a negative start time.

**E01-E09** refuse malformed model events:
- an exit of an unknown PID;
- a spawn on a live PID;
- open spawn or move shapes, or a move to a relative cgroup;
- an unknown failure step, or a failure injection with another field;
- a race after the last step, or a race carrying a malformed event.

## Spec mapping

| Spec | Encoded by |
|---|---|
| HOST-INTERFACE-DRAFT-002 §7 BIND_EXECUTION (workerPid, workerStartTicks) | The observation; rules 1-4 |
| I05 v3 source table, workerPid/workerStartTicks: KERNEL, a live member of the probe-worker cgroup | Steps 1 and 4, rule 2 |
| Owner Q-HE3D-2 (a): BIND fails closed until the I05 successor | v4 defines the source. R10 removes its empty-list rule when it adopts v4 (monitor). |
| SELinux matrix v5, Q-HE3D-2 grant | Constraint C3, rule 6 |

## Still open

- All E01-E12 and T01-T08. The observation on a real kernel (pidfd and `stat` behaviour, the bounds in rule 5) is native
  work for R10's adoption and T04.
- The local diagnostic log's storage, rotation and access control (R10).
- How R10 adopts v4 and removes its empty-`observedWorkers` rule (R10, relayed by the monitor).
- Whether the seccomp row text "same-uid /proc reads" is reworded to cover the gate's other-uid `stat` read. The
  syscalls are already allowed; this is wording only, for a later seccomp revision.
