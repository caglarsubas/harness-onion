# SELinux domain, type, boolean and permission matrix v6 — SELINUX-MATRIX-V6 (DATA_CHECK_ONLY)

Status: **CONTRACT_CANDIDATE_AWAITING_INDEPENDENT_REVIEW**. DATA_CHECK_ONLY: no policy module is written or compiled,
nothing is loaded or installed, and all E01-E12 stay OPEN_UNPROVEN.

v6 is the successor of the adopted matrix v5 `../selinux-matrix-v3/` (`planeon.internal.selinux-matrix/v5`,
SELINUX-MATRIX-I04-KEYCERT, MET-ENFORCE-028, review round 4 PASS_FOR_SOURCE_PUBLICATION with XR4-1 to XR4-4 carried).
Later layers pin the v5 bytes, so v5 stays byte-identical and v6 is published beside it, as v5 was beside v4. v6 keeps
the v5 matrix and changes only the items below. The reference evaluator `scripts/selinux_matrix_v4.py` is the v5
evaluator with the matrix version changed and these extensions:
- a per-source closure may name `process` `transition` and `dyntransition` (a closed source enters no undeclared
  domain, by exec or by setcon, and neither the admin login nor systemd) or `file entrypoint` (a closed domain is
  entered through no type the matrix does not grant it, declared or not);
- the `filesystem` class (all ten v6.12 classmap permissions). For a mount source, every permission on a declared type
  is closed, and `relabelto` on every type, declared or not. `associate`, which the kernel checks from a file's type to
  the type of its filesystem, is closed into every declared type, whatever the file's type. Every other `filesystem`
  question is outside the matrix;
- six new `check_matrix` rules: the mount sources are exactly the declared domains, systemd excepted, that hold
  `sys_admin`, in the initial or in a user namespace; the `filesystem` table is closed and grants only from a mount
  source to a declared type; `associate` pairs name declared types, once each; the new closure shapes; no two closures
  share a domain, class and permission; a socket-file type has only the `sock_file` class.

Roadmap item SELINUX-MATRIX-V6 (MATRIX-READER-NARROWING folded in); accepted base main `b0635f8` (243 packets). The
inputs include native-profile v4 + I06 v3 as adopted in the primary lane at commit
`5a3e6820cf23325dd8c68f8c083d53ac805f2b06` ("NP4" below; `README.md` line numbers at that commit), which is not yet
merged. This contract is drafted and reviewed against it, and adopted only after NP4's packet merges, with the coupling
below re-checked (monitor Q-MX6-1 (a)). The slot is assigned at adoption.

**Named limitation (owner, 2026-10-16: "Keep, T04 uses v5").** v6 is the tightened target and stays fail-closed
(Q-MX6-2 (a)). Until a successor declares the helper types (W02-PROD D-HELPER-TYPES), T04 cluster qualification runs
against matrix v5, not v6: a policy that meets v6 refuses the backend's helper programs (below), so no cluster can run
under it yet. v6's obligation rows bind W03's policy module and the T04 successor that adopts v6; no T04 proof checks
them while T04 runs against v5.

## What v6 changes

| Source | v6 rule | Vectors |
|---|---|---|
| Owner Q-MX6-2 (a) and Q-MX6-3 (a), 2026-10-16; NP4's Backends residual (README:251-258, :337-338) | Every qualification backend domain and the Pod domain `qualk8s_container_t` is a closed source for `file execute_no_trans`. No declared type grants it to anybody (A37), so none of the nine executes (execve) any program without a transition, declared or not: an undeclared helper is refused, not outside the matrix. A60.22-A60.30, one per source | P10-P13, N38; C checks of A60.22-30; M87, M88 |
| Monitor Q-MX6D-1 (a), 2026-10-16 (owner-delegated) | The seven planeon closed sources and the nine qualk8s sources are closed for `process transition` and `dyntransition`: none enters an undeclared domain, by exec or by setcon, nor the admin login or systemd. Without it, the owner's fail-closed closure could be bypassed through a host-policy transition (for example into `mount_t`), which would also step around the mount closure below. It binds R10's worker: HS43's O-W03-WORKER-EXEC moves into data (A60.34). A60.31-A60.46 | Q75-Q77, P14-P18, O15; M89, M97, M98 |
| Review XV1-2, under Q-MX6-2 (a), Q-MX6-3 (a) and Q-MX6D-1 (a) | The same sixteen domains are closed for `file entrypoint`, checked with the entered domain as subject: each is entered only through the types the matrix grants it (its one entrypoint type; the Pod domain through container content), through no other type, declared or not. Without it a declared transition (init into a backend, the runtime into a Pod, the broker into the worker) could enter a closed domain from an undeclared binary. A60.49-A60.64 | Q80, Q81, P22-P24; M100, M101, M103 |
| Owner Q-MX6-4 (a), 2026-10-16; NP4 P-b (README:122-127) | The `filesystem` class for the two mount sources, the kubelet and the runtime: `relabelto`, `relabelfrom`, `mount`, `remount`, `unmount` and `getattr` only on `qualk8s_container_file_t` (the context= label of Pod mounts), `relabelto` on no other type, declared or not, no quota or watch permission on a declared type; `associate` into a declared label only for container content with itself, whatever the file's type; `mounton` on declared types as v5's WRITE grants give it (the runtime on container content). systemd is out of scope, with an obligation row (MX6-O2). A60.47, A60.48, A70-A76 | Q59-Q68, Q78, Q79, N30-N37, P19-P21, O09-O14; M77-M83, M90-M96, M102 |
| Monitor Q-MX6-6 (a), 2026-10-16 (MATRIX-READER-NARROWING); NP4 Q-NP4-16 (a) (README:346-355) | `/proc` only, pair by pair against the published duties. The server keeps the observer and the broker (its v1 peer qualification, unchanged by HS43 §4.3); the broker keeps the gate (§4.3). 24 v5 pairs are removed. Four per-target pins A59.<target> follow the new peers, A59's union drops a duplicate, and A69.<reader> pins each narrowed reader | Q69-Q74; N22-N29; M84-M86, M99; 24 v5 checks of removed pairs now deny them (`v6Changes`) |
| Monitor Q-MX6-8 (a): v5's carried XR4-1 to XR4-3; monitor Q-MX6D-2 (a): NP4's open enrolled-file refusal (README:606-607) | XR4-1: the Assertions rows for A09 and A67 state their full READ coverage. XR4-2: `REVIEW_BRIEF.md` lists every changed v5 assertion by index. XR4-3: the self-capture route is named ("Carried from v5"). The enrolled-file refusal: `entryTypes` derives the matrix's entry types outside NP4's label constants (`planeon_maint_exec_t`, `qualk8s_container_file_t`), obligation MX6-O5 says no enrolled file carries them, and the model refusal goes to the next native-profile successor | `entryTypes` |

Every v5 entry keeps its index in every list except `procAccess`, which loses the 24 pairs; new entries follow the
last v5 entry. Every v5 assertion keeps its index, identifier and statement; A59 and four per-target pins A59.<target>
change only their allow lists (and their `ref`). Every v5 vector keeps its identifier and position.
`v6Changes` lists the 29 v5 vectors whose expected result changes: 24 access checks of removed `/proc`
pairs and five mutation checks. M53, M73, M74 and M75 now also break the new pins, and M29 (the admin domain holds
CAP_SYS_ADMIN) is refused by `check_matrix`, because a declared holder of CAP_SYS_ADMIN must be a mount source; M91
shows A47 itself with the admin domain declared a mount source.

## The qualk8s `execute_no_trans` closure (owner Q-MX6-2 (a), Q-MX6-3 (a))

NP4 binds a backend capture to "domain entry plus measured file" only (ENTRY_BOUND, README:137-139), "because matrix v5
has no `execute_no_trans` closure for the qualk8s sources" (README:255-256), and names the closure as a residual for a
matrix successor (README:337-338). v6 closes it for all nine qualk8s domains, the Pod domain included:
- A37 (v5) already refuses `execute_no_trans` on the sixteen entrypoint types, the interpreter and container content to
  every domain. The new closures add every type the matrix does not declare, so a qualk8s process executes (execve) no
  program without a transition at all.
- What the closures do not bind: a domain may still map with PROT_EXEC any file it may `file execute` (undeclared
  libraries are outside the matrix) and run that code through a userland loader, and a `#!` script's interpreter needs
  only `file execute`, because v6.12 checks `entrypoint` and `execute_no_trans` once, on the script
  (`selinux_bprm_creds_for_exec`). For the planeon roles T04-MAPS-STATIC and T04-MAPS-INTERPRETER cover mappings; a
  successor that binds a backend capture to its running image needs the same for the backends (MX6-O1).
- The consequences are stated, not hidden. Examples of programs a policy that meets v6 refuses: the runtime's shim and
  runc, the CNI plugins, nft, the service proxy's iptables-restore and conntrack, and any mount or other helper the
  kubelet runs. With A37, a Pod process runs no second program from its own image either (N38). Until a successor
  declares the helper types with W02-PROD's D-HELPER-TYPES, each with its own entry type and transition, no cluster runs
  under v6, which is the owner's named limitation above (MX6-O4).
- NP4 is unchanged: its ENTRY_BOUND class stays as adopted. The closure is a premise a later native-profile successor
  needs to bind a backend capture to the running image; that successor, not v6, decides it (MX6-O1).

## Transitions and entry of closed sources (monitor Q-MX6D-1 (a); review XV1-2)

`execute_no_trans` decides only whether a program may run in the caller's own domain. A program can also run through a
transition into another domain, and v5 leaves transitions into undeclared domains outside the matrix (the target is not
declared). So without a second closure an undeclared helper could still run, in a host domain such as `mount_t`, and a
mount made there would sit outside the `filesystem` closure below. v6 closes `process transition` and `dyntransition`
for the sixteen closed sources: into an undeclared domain, into the admin login and into systemd they are False
(A60.31-A60.46). Transitions into declared domains keep their rows (the broker into the worker, the runtime into the
Pod domain). `dyntransition` also needs `process setcurrent` on the caller, which stays outside the matrix; the closure
makes the target side fail on its own.

**This binds R10's worker.** For `planeon_worker_t` the closure (A60.34) is HS43's obligation O-W03-WORKER-EXEC ("the
host policy gives it none into any other domain"), now in data: the worker implementation and W03's policy must hold it.
The planeon roles never exec, so for them it matches HS43.

An exec transition checks three things (v6.12 `selinux_bprm_creds_for_exec`): `process transition` from the old domain
to the new one, `file execute` from the old domain on the file, and `file entrypoint` from the new domain on the file.
The matrix closes `entrypoint` on its own types, but not on undeclared ones, so a declared transition (init into a
backend, the runtime into a Pod, the broker into the worker) could still enter a closed domain from an undeclared
binary. v6 therefore closes `file entrypoint` for the same sixteen domains: each is entered only through the types the
matrix grants it, declared or not (A60.49-A60.64). The v5 sentence that "the matrix lets each planeon domain be entered
only through its sealed entrypoint type" now holds for undeclared types too, for the seven planeon closed domains. The
maintenance domain `planeon_maint_t`, entered from the admin login only in the maintenance boot, is not a closed source:
its entry through an undeclared type stays outside the matrix, as v5 had it (review XV2-5).

## The `filesystem` class and context= mounts (owner Q-MX6-4 (a))

NP4's premise P-b needs that no file outside the enrolled set carries an entrypoint, the interpreter type or a closure
type "on any mounted filesystem, including mount-option contexts and images that carry stored labels ... including
mounts the kubelet and the runtime make at run time (both hold CAP_SYS_ADMIN, matrix A47)", and names a matrix
successor's `filesystem` closure as the residual (README:122-127). Kernel basis (v6.12 `security/selinux/hooks.c`:
`selinux_set_mnt_opts`, `may_context_mount_sb_relabel`, `may_context_mount_inode_relabel`, `selinux_sb_kern_mount`,
`selinux_mount`, `selinux_umount`, `selinux_sb_statfs`, `may_create`; for T04 to confirm):
- `fscontext=F`, and `context=C` without `fscontext=`, check `filesystem relabelfrom` on the superblock's current
  label and `relabelto` on the new one, from the mounting domain;
- `context=C` also sets the root context to C unless `rootcontext=` is given. So a plain `context=C` mount also checks
  `relabelfrom` on C (the superblock's label by then) and `associate` of C with C;
- `context=C` with `fscontext=`, `rootcontext=R` and `defcontext=D` check `relabelfrom` on the current label and
  `associate` from the new label to the superblock's label (a file type to a filesystem type, no domain);
- the mount itself checks `filesystem mount` on the resulting label, a remount `remount`, an unmount `unmount`, statfs
  `getattr`; the mountpoint needs `mounton` in its own class (a v5 WRITE-group permission); every mount, unmount and
  remount first needs CAP_SYS_ADMIN over the mount namespace (`may_mount`);
- under the new mount API, by the author's reading, `fsmount` reaches no `filesystem mount` check and `fspick` with a
  reconfigure, or `mount_setattr`, no `remount` check, while the label checks (through `vfs_get_tree`) and `mounton`
  (`selinux_move_mount`) apply on both paths. A71's `mount` and `remount` rows therefore bind the mount(2) path; the label
  closure, which P-b rests on, binds both.

Scope and grants:
- **Mount sources.** `mountSources` is `qualk8s_kubelet_t` and `qualk8s_runtime_t`. `check_matrix` requires it to be
  exactly the declared domains other than systemd that hold `sys_admin` in the initial or in a user namespace (A47; no
  declared domain holds any `cap_userns` permission). So no other declared domain can mount at all, and a domain that
  gained CAP_SYS_ADMIN without joining the closure is refused (M94).
- **Closed for the mount sources.** Every `filesystem` permission on a declared type: `relabelto`, `relabelfrom`,
  `mount`, `remount`, `unmount` and `getattr` only on `qualk8s_container_file_t`, the label the runtime and the kubelet
  give Pod mounts with context= (Pods run in the one confined `qualk8s_container_t`, without per-Pod labels; v5 review
  N7); no `quotamod`, `quotaget` or `watch`. `relabelfrom` on container content is what a plain context= mount needs
  (above). `relabelto` is closed on every type, declared or not (a per-source closure): no context= or fscontext= label
  but container content (A60.47, A60.48).
- **`associate`.** Closed into every declared label, whatever the file's type: only container content with itself (files
  on a context= mount take the mount's label). So `fscontext=` with `context=X`, and `rootcontext=X` over a
  container-content superblock, are refused for every X but container content, declared or not (A73, A74).
- **`mounton`.** v5's WRITE groups already close it on declared types: the runtime mounts on container content, the
  kubelet on no declared type (A75.<class>, A76.<class>). The runtime socket file's WRITE grant to its listener and its
  one connector is an upper bound (v3 review R18) and includes `mounton` on that socket file; A75.sock_file leaves that
  one type out, and `check_matrix` keeps every socket-file type to the `sock_file` class.
- **Outside the matrix.** systemd's mounts (owner: out of scope; MX6-O2), undeclared host domains' mounts (their
  capabilities are outside the matrix; MX6-O2), host filesystem types as superblock labels (`tmpfs`, `proc`, overlay and
  the like: the mount sources' `mount`, `relabelfrom` and the rest on them are W03's), `associate` with a host
  filesystem type, and `filesystem` permissions of domains that are not mount sources (they cannot mount; statfs by a Pod
  is W03's).

What data cannot close, and the obligation row that carries it (host filesystem types are the selected distribution's,
W03; MX6-O3):
- Labels that come from the filesystem itself need no relabel check: a block device, a loop image, erofs or squashfs
  with stored xattr labels, and native labelling such as labeled NFS v4.2 or FUSE, virtiofs and 9p where the policy uses
  `fs_use_xattr` for them. `fscontext=` alone does not override stored labels; `context=` does. So the mount sources
  mount no filesystem whose labels come from the filesystem itself unless with `context=`.
  A bind mount creates no superblock and takes no context option, so it is not affected; the runtime's bind mounts of
  Pod volumes stay possible (review XV2-3).
- `defcontext=D` on an xattr filesystem labels every file without a stored label D, and `rootcontext=R` labels the root
  directory, each with `relabelfrom` on the host filesystem type and `associate` of D or R with it. An entrypoint type is
  associated with the host type of the filesystem it is installed on. So no entrypoint, interpreter or closure
  executable-segment type may be associated with the host filesystem types of the mount sources' context= mounts. The
  consequence, stated (review XV2-3): where the selected base policy gives disk and overlay filesystems one type (`fs_t`
  in the common base policies), the mount sources can make no context= mount of a disk or overlay filesystem, so a Pod
  root needs an overlay type of its own or another route; W03 decides it, and T04 cluster qualification runs against
  matrix v5 until then (the named limitation).
- A mount source could also mount over a host-typed ancestor of a planeon or backend path (`/run` itself is `var_run_t`,
  outside the matrix) and recreate the paths below it with its own content. Data cannot close that, so obligation
  MX6-O8 does: the mount sources mount only on their own mount points, never on an ancestor of a planeon or backend path
  (review XV2-1).
- The residual: v5 creates the `/run/planeon` objects (`planeon_run_t`, the seal marker, the I05 and I07 socket files)
  on tmpfs, so their types are associated with the host tmpfs type, and `rootcontext=` with one of them can label the
  root directory of a kubelet tmpfs. A directory of that type elsewhere gives no access: readers find these objects by
  fixed path under `/run/planeon`, which the mount sources cannot mount over (`planeon_run_t` mounton, A75.dir) or, by
  MX6-O8, over any of its ancestors.
- Inside the enrolled boot, v5's A12 already refuses every write and relabel of a sealed type, so a label cannot be
  created file by file (`file create` and `relabelto` on the new type).

## Reader narrowing: the server's and the broker's `/proc` (monitor Q-MX6-6 (a))

v5 carried MATRIX-READER-NARROWING (XR4-4): "A later matrix revision evaluates narrowing the server's and broker's other
/proc reads (observer, containment, worker, backends, Pods) pair by pair, each with a duty check." NP4 states each
reader role's capture duties (Q-NP4-16 (a), README:346-355): the observer takes every P1 role capture, the P5 lifecycle
capture and every backend capture; the server and the broker take none, and NP4 leaves their other duties to this
evaluation. Those duties, from W01 §4.3 and §5.4 as amended by HS43 and from the v1 qualification HS43 keeps:
- the server qualifies its observer and broker peers (v1, I01 and I02): "Three roles qualify at server startup"; it
  retains each peer's pid, start time and pidfd and compares credentials, label, namespaces and cgroup membership with the
  enrolled role, and "Actual peer proc access must already be permitted" (`docs/alpha-2/NATIVE_QUALIFICATION_READINESS.md`,
  "Ordering, lifetime and no observation gap" and "Trusted kernel views and retained identity"; the server-side
  `KernelObserverInspectionTests` and `KernelBrokerInspectionTests`). HS43 §4.3: "SERVER and OBSERVER ... Their v1 peer
  duties are unchanged." The kernel still refuses the server the broker's ptrace-gated entries, its exe link among them
  (v5 XR3-2); the pair serves the ungated ones;
- the broker qualifies the gate (§4.3: artifact through the gate's exe link, label, cgroup, pidfd/start, SO_PEERCRED);
- the broker checks its frozen child through `/proc/<pid>` (§5.4 W3). That child has not yet executed the worker: it
  runs in `planeon_broker_t` until W5, so W3 is a read of the broker's own domain, outside the matrix (O03). After W5
  the broker uses `waitid(P_PIDFD)` and `cgroup.events` (W6), not `/proc`;
- the gate qualifies the broker and the writer, and reads its worker (v5, Q-HE3D-2 (a)): unchanged;
- no published duty has the broker read the server, the observer, containment, a backend or a Pod;
- v1's worker-side check of its original broker ("004's installed worker may use the same fixed reader for itself/original
  broker", `NATIVE_QUALIFICATION_READINESS.md`) has had no `procAccess` pair since matrix v3 (no worker-to-broker pair),
  and v6 adds none: it stays retired in the matrix, and HS43 §5.4 W3 checks the child from the broker's side (review
  XV2-4).

| Reader | v5 `procAccess` targets | v6 | Duty kept |
|---|---|---|---|
| server | observer, broker, worker, containment, eight backends, Pods (13) | observer, broker | v1 peer qualification (I01, I02; HS43 §4.3) |
| broker | gate, worker, server, observer, containment, eight backends, Pods (14) | gate | §4.3 artifact and start check |
| observer | 15 | unchanged | NP4 P1, P5 and backend captures |
| gate | broker, writer, worker | unchanged | §4.3, Q-HE3D-2 (a) |

So 24 pairs are removed and 21 remain. NP4's premise P-a needs "the observer's `/proc` access to every planeon and
qualk8s domain as matrix v5 grants it" (README:118-121), which v6 keeps unchanged. A59.planeon_server_t,
A59.planeon_observer_t, A59.planeon_worker_t and A59.planeon_contain_t follow their new peers; A59's union is unchanged
(its list loses v5's duplicate broker entry). A69.planeon_server_t and A69.planeon_broker_t (file read and open) and
their `.getattr` twins (process getattr) pin each narrowed reader over every declared domain.

Out of scope, as the decision says ("/proc only"): the server's and broker's READ on the planeon cgroup types
(A38/A39), on the pins and the seal marker (A49), their `prog_run` on containment programs (A17, A18), and W01 §5.3's
CAP_NET_ADMIN and CAP_BPF "(inspection)". "Reader roles" below still means the server, the observer and the broker for
those grants.

## Entry types outside the native profile (monitor Q-MX6-8 (a), Q-MX6D-2 (a))

NP4 left one item open: "refusing matrix v5's other ENTRYPOINT types (`planeon_maint_exec_t`,
`qualk8s_container_file_t`) on enrolled files; the model does not pin the matrix file" (README:606-607). v6 cannot change
NP4's model (no errata, Q-MX6-5 (a)). It gives the matrix's side:
- `entryTypes` in `vectors.json` lists every type that is an entrypoint into a declared domain (`entry_types`), NP4's
  sixteen label constants (copied from NP4's "Entrypoints and labels" table at `5a3e6820`) and the difference: exactly
  `planeon_maint_exec_t` (enters the maintenance domain, only in the maintenance boot, A26, A27) and
  `qualk8s_container_file_t` (enters the Pod domain from the runtime).
- Obligation MX6-O5: no enrolled planeon or backend file, closure file or interpreter copy carries either type. The
  model refusal itself goes to the next native-profile successor, which can read the list from this file.

## T04 and W03 obligations (owner Q-MX6-4 (a); monitor Q-MX6-5 (a))

v6 adds no T04 proof id. NP4's `t04Proofs` is a closed constant (README:271-273), and its proofs are fixed to what NP4
states (README:315-328): T04-ENTRYPOINT, for example, covers A12, A32, A33, A37, A60.15-A60.21 and the observer's
`procAccess` as matrix v5 grants it, and nothing v6 adds. So each row below names the NP4 proof it extends where one
exists, by reference only (monitor Q-MX6-5 (a), Q-MX6D-2 (a)), and an owner that can prove it. **No NP4 proof checks
rows MX6-O1, MX6-O4, MX6-O6, MX6-O7 or MX6-O8 today; T04-ENTRYPOINT-CENSUS and T04-LABELS check rows MX6-O2, MX6-O3 and
MX6-O5 only in part** (the census of labels on files, not the mount permissions or the model's refusal). While T04
cluster qualification runs against matrix v5 (the named limitation), none of v6's rows is checked by T04; the T04
successor that adopts v6 owns each.

| Row | Obligation | Owner |
|---|---|---|
| MX6-O1 | The installed policy holds A60.22-A60.46 and A60.49-A60.64: no qualk8s `execute_no_trans`; no transition of a closed source into an undeclared domain, the admin login or systemd; no entry into a closed domain but through its granted types. A successor that binds a backend capture to its running image needs these and a mapping proof like T04-MAPS-* for the backends | W03 policy module; the T04 successor that adopts v6 (the next native-profile successor's proof list) |
| MX6-O2 | systemd makes no context=, fscontext=, defcontext= or rootcontext= mount with a declared type (owner Q-MX6-4 (a)), and no undeclared host domain does either | W03 policy module; the T04 successor that adopts v6 (T04-ENTRYPOINT-CENSUS by reference, in part) |
| MX6-O3 | The kubelet and the runtime mount no filesystem whose labels come from the filesystem itself (xattr or native labelling: block devices, loop images, erofs or squashfs, labeled NFS, FUSE, virtiofs or 9p under `fs_use_xattr`) unless with `context=`; no entrypoint, interpreter or closure executable-segment type may be associated with the host filesystem types of their context= mounts; the `/run` rootcontext= residual stays as stated above | W03 (selection and policy module); the T04 successor that adopts v6 (T04-ENTRYPOINT-CENSUS by reference, in part) |
| MX6-O4 | Every helper program a backend component runs gets a declared type, an entry type and a transition in a later matrix successor; until then a policy that meets v6 refuses it, and T04 cluster qualification runs against v5 (owner "Keep, T04 uses v5") | W02-PROD (D-HELPER-TYPES); the matrix successor that declares them |
| MX6-O5 | No enrolled file carries `planeon_maint_exec_t` or `qualk8s_container_file_t`; the next native-profile successor refuses them in its model | the next native-profile successor (its model and proof list); the T04 successor that adopts v6 (T04-LABELS by reference, in part) |
| MX6-O6 | The server reads only its observer's and broker's `/proc`, and the broker only the gate's (A69.*) | W03 policy module; the T04 successor that adopts v6 |
| MX6-O7 | No closed source can have systemd run a program or a mount for it: no transient units (`StartTransientUnit`), no call of systemd's manager interface. A program run that way would run in `init_t` or a host domain, outside every closure here (review XV1-11) | W03 policy module; the T04 successor that adopts v6 |
| MX6-O8 | The kubelet and the runtime mount only on their own mount points (their state directories and the Pod roots they assemble), never on an ancestor of a planeon or backend path (`/run`, `/run/planeon`, `/etc`, `/opt/planeon`, another component's state directory) (review XV2-1) | W03 policy module and selection; the T04 successor that adopts v6 |

## Coupling with native-profile v4 (monitor Q-MX6-1 (a))

NP4's schema fixes matrix v5's type names as label constants, "to be cross-checked against matrix v5 by v4's layer
validator; ... a later matrix revision that changes a type needs a v4 successor or errata" (README:199-201). v6 adds,
renames and removes no type, and keeps every assertion NP4 cites (A12, A32, A33, A37, A47, A60.15-A60.21) and the
observer's `procAccess`. At adoption, after NP4's packet merges, these are re-checked against the merged bytes:
NP4's label constants (the sixteen in `entryTypes`), its `t04Proofs` constant, its reader-duty table, and the README
lines cited here. A difference returns this contract to review.

## Invariants other contracts rely on (the primary lane's W03-boundary check, 2026-10-16)

| Invariant | Who relies on it | Pinned by |
|---|---|---|
| (a) The gate keeps `procAccess` to the probe worker (v5's gate-to-worker pair, Q-HE3D-2 (a)) | HE-003A3 (I05 v4 C3): the gate reads the worker's `/proc/<pid>/stat` at every BIND | Q54; A59.planeon_worker_t allows the gate (a deny bound) |
| (b) The observer keeps `procAccess` to every planeon and qualk8s domain v5 grants it (15 pairs) | NP4 P-a (T04-ENTRYPOINT) and the P5 domain counts | Q57, Q72, Q82-Q94 (one per target); v6 changes none of the observer's entries |
| (c) The interpreted roles are entered only through their script's entrypoint type; `planeon_interpreter_exec_t` is executed in the script's domain and is never an entrypoint | NP4 §3.4 and Q-NP4D-1 (on a `#!` script v6.12 checks `entrypoint` once, on the script) | A60.49.entrypoint, A60.52.entrypoint (both refuse the interpreter type); Q81, Q95-Q97; N39, N40 |

## Owner and monitor decisions for v6

- **MATRIX-V6-DOSSIER (lane monitor, 2026-10-16)**, the tasking: "the qualk8s execute_no_trans closure (owner
  Q-NP4D-B (a): today the backends only prove "domain entry plus measured file"); a filesystem-class closure for
  context= runtime mounts by the kubelet and runtime ...; both with T04 obligations. Also evaluate folding
  MATRIX-READER-NARROWING into it: v4 states each reader role's capture duties (Q-NP4-16)." NP4's own restatements of
  Q-NP4D-B (a) and Q-NP4D-8 (a) are at README:137-139, :251-258 and :282, :294-298 (monitor MX6-PROVENANCE: cite these and
  the relay; NP4's decision record is kept outside the repository).
- **Owner, 2026-10-16 (typed in the monitor chat, relayed verbatim):** "Q-MX6-2 (a) "Close now": every qualk8s domain
  is closed over its declared executable types, undeclared binaries are refused (fail-closed), and the helper types join
  through the W02-PROD successor. Q-MX6-3 (a) "Include Pod domain": qualk8s_container_t is in the closure. Q-MX6-4 (a)
  "Kubelet + runtime": the filesystem mount, remount, unmount, relabelfrom/relabelto, associate and getattr
  permissions, plus mounton, on context= labels; init_t is stated out of scope, with a T04 obligation that systemd makes
  no context= mount of a declared type. Q-MX6-7 (a) "Contract + T04": BROKER-CLONE-INTO-CGROUP is a contract
  obligation only (HS43 §5.4 W2 plus T04-BROKER-SPAWN), with the seccomp limit stated; the transient-fork residual goes
  to T04/T05; a roadmap item closes it when native-profile v4 merges."
- **Lane monitor (owner-delegated), 2026-10-16:** "Q-MX6-1 (a): draft and review now against 5a3e6820; adopt only after
  246 merges, re-checking the coupling. Q-MX6-5 (a): T04 by reference to native-profile v4's proof ids plus matrix-local
  rows; no errata. Q-MX6-6 (a): fold MATRIX-READER-NARROWING in, /proc only, consistent with the owner's earlier
  narrowing decisions Q-MX-2/3 (b). Q-MX6-8 (a): XR4-1..3 and native-profile v4's enrolled-file refusal go in v6."
- **Owner, 2026-10-16 (typed in the monitor chat, relayed verbatim), on the v6 consequence:** "Keep, T04 uses v5". The
  monitor's recording instructions: "v6 stays fail-closed as decided in Q-MX6-2 (a). Until a successor declares the
  helper types (D-HELPER-TYPES), T04 cluster qualification runs against matrix v5. Record that as a named limitation in
  v6's README. v6 documents the tightened target."
- **Lane monitor (owner-delegated), 2026-10-16:** "Q-MX6D-1 (a): close `process transition` into undeclared domains, the
  admin login and systemd, for the 9 qualk8s and the 7 planeon sources. Without it, the owner's fail-closed closure
  (Q-MX6-2 (a)) is bypassable through a host-policy transition. For the planeon roles it matches HS43, since those roles
  never exec. The worker's O-W03-WORKER-EXEC moves into data. State explicitly that this binds R10's worker. The primary
  sees it at the W03 boundary through the contract; I'll tell it. Q-MX6D-2 (a): a matrix-side rule plus a derived list of
  entry types outside NP4's constants, an obligation row (T04-LABELS by reference), and the model refusal carried to the
  next native-profile successor. No NP4 errata (Q-MX6-5)."
- **BROKER-CLONE-INTO-CGROUP (owner Q-MX6-7 (a))** is not in this matrix: seccomp compares register arguments only, and
  clone3's flags (CLONE_INTO_CGROUP, the namespace flags) sit in a struct it cannot read; the obligation stays HS43 §5.4
  W2 and NP4's T04-BROKER-SPAWN.

## Carried from v5 (round-4 NOTEs)

| Finding | Disposition |
|---|---|
| XR4-1 | The Assertions table rows for A09 and A67 now say that they cover every READ permission, as the v5 change table did |
| XR4-2 | `REVIEW_BRIEF.md` lists every v5 assertion v6 changes, by index: A59 (index 66) and the four A59.<target> pins whose peers change (indices 100, 101, 103 and 106) |
| XR4-3 | The self-capture route, named: a process can read its own exe link, and a second process in the same domain passes the kernel's uid and capability rules when the target is dumpable (`__ptrace_may_access`, equal permitted sets). A domain's own `/proc` is outside the matrix (O03), so no `procAccess` entry is needed. NP4 does not use it: its P1 captures are LABEL_BOUND (the observed label plus the measured entrypoint file, README:113-133) |
| XR4-4 | MATRIX-READER-NARROWING, folded in above (monitor Q-MX6-6 (a)) |

## Contract review round 1 (v6) findings and dispositions

| Finding | Severity | Disposition |
|---|---|---|
| XV1-1 a plain context= mount needs relabelfrom on its label | MAJOR | `relabelfrom` on container content granted to both mount sources; `associate` closed into every declared label whatever the file's type, so A73 (now with undeclared sample sources) is what refuses fscontext= chaining and rootcontext= over container content; A70 covers the other declared labels; kernel basis states the implied root context (Q78, Q79, P21; M78 retargeted) |
| XV1-2 an undeclared binary could enter a closed domain | MAJOR | `file entrypoint` closures for the sixteen closed domains, A60.49-A60.64 (Q80, Q81, P22-P24; M100, M101, M103) |
| XV1-3 the server's v1 peer duties | MAJOR | Evaluated pair by pair: the server keeps the observer and the broker (v1 I01/I02 peer qualification, unchanged by HS43 §4.3); A69.planeon_server_t and its statement follow |
| XV1-4 decisions after the subject | MINOR | Recorded verbatim; Q-MX6D-1 and Q-MX6D-2 marked decided; the named limitation in the introduction, "Still open" and MX6-O4; "binds R10's worker" stated |
| XV1-5 MX6-O3 too narrow and too broad | MINOR | Reworded: filesystem-supplied labels (xattr or native) unless context=; the associate clause for entrypoint, interpreter and closure types; the `/run` rootcontext= residual stated |
| XV1-6 A75.dir and A75.file left out the runtime socket file | MINOR | They now cover it; `check_matrix` keeps every socket-file type to the `sock_file` class (M102) |
| XV1-7 W3 reads the pre-exec child | MINOR | broker to worker removed (no post-exec duty); A59.planeon_worker_t follows (M99) |
| XV1-8 MX6-O1 and MX6-O6 attached to a frozen proof | MINOR | Owners that can prove them (W03's policy module, the T04 successor that adopts v6); the T04 section says no NP4 proof checks them today |
| XV1-9 new mount API | NOTE | Stated in the kernel basis |
| XV1-10 scope of "runs no program" | NOTE | "executes (execve)"; the mapping route and its owner; the Pod-internal consequence; the helper list marked as examples |
| XV1-11 systemd running programs for a closed source | NOTE | MX6-O7 |
| XV1-12 duplicate in A59; check_matrix rules | NOTE | A59's list deduplicated; the six new `check_matrix` rules listed in the introduction and the evaluator |

## Contract review round 2 (v6) findings and dispositions

| Finding | Severity | Disposition |
|---|---|---|
| XV2-1 a mount over a host-typed ancestor of `/run/planeon` | MINOR | New obligation MX6-O8 (the mount sources mount only on their own mount points, never on an ancestor of a planeon or backend path); the residual sentence narrowed to the `/run/planeon` objects |
| XV2-2 rows cited NP4 proofs as extended | MINOR | Every row cites NP4 proofs by reference only; MX6-O2, MX6-O3 and MX6-O5 say those proofs check them only in part and name the T04 successor that adopts v6 |
| XV2-3 bind mounts; one filesystem type for disk and overlay | NOTE | Bind mounts stated as unaffected; the consequence for context= mounts of disk and overlay filesystems stated (W03; T04 runs against v5 meanwhile) |
| XV2-4 v1's worker check of its broker | NOTE | Stated: no worker-to-broker pair since matrix v3, none added, retired in the matrix; W3 checks from the broker's side |
| XV2-5 "each planeon domain"; M97's wording | NOTE | Narrowed to the seven planeon closed domains, the maintenance domain stated as open; M97 describes the per-permission rule |

The primary lane's W03-boundary check (relayed by the lane monitor, 2026-10-16) asked for three invariants to be
explicit; they are in "Invariants other contracts rely on", with Q82-Q97, N39 and N40 added for them.

## History: v5 (SELINUX-MATRIX-I04-KEYCERT)

v5 (MET-ENFORCE-028, main `5e83b25`) was the successor of matrix v4. Its change sections follow as published.

### What v5 changes

| Source | v5 rule | Vectors |
|---|---|---|
| Monitor decisions, 2026-10-15 (owner-delegated): the I04 key/cert types before HE-008, Q-MX-1 (a) | I04 is mutual TLS 1.3, and the gate reads three DER files: its serving private key (PKCS#8), its serving certificate chain and exactly one client CA (owner Q-HE3D-8 (a)). The resolved spec §4.2 makes the key and chain the gate's TLS listener identity, the signed KUBERNETES_API_PROXY endpoint identity. Two new CREDENTIAL types: `planeon_gate_i04_key_t` for the private key, and `planeon_gate_i04_cert_t` for the chain and the client CA. READ the gate only; WRITE and RELABEL only by the maintenance domain in the maintenance boot, like every credential. The key joins A09 (the gate's credentials); A67 keeps the public chain and CA to the gate as well (least privilege). Both types are appended after the last v4 type, so every v4 type keeps its index. A09 (a v4 assertion) and the new A67 cover every READ permission, not only `read` and `open`: no other domain gets any READ permission on the gate's three credentials or its chain and CA, `getattr` included, in any state, the maintenance boot included. The other credential assertions (A10, A11.*) keep v4's `read` and `open`. | Q49, Q50, Q55, Q56; N02-N04, N10-N13; M57, M58, M64, M65; A09 or A67, and A12, A13 and A36, list them among their targets |
| HS43 O-MATRIX-GATE-NETBIND (W01 §5.3 as amended by HS43 H5, Q-HE2S-9 (a); the monitor's Q-MX-4 (a)) | The gate holds no capability. `net_bind_service` is dropped from its capabilities and from A48's allow list: the signed I04 port is 1024 or above. A68.<class> asserts that the gate holds no permission of any capability class (`capability`, `capability2`, `cap_userns`, `cap2_userns`), so no grant, CAP_SYS_PTRACE included, can return unnoticed (review XR1-4). | N01, N16, N17; M56, M66, M67; the three v4 checks of the gate's `net_bind_service` now deny it (`v5Changes`) |
| Owner decision Q-HE3D-2 (a), 2026-10-15, with the monitor's Q-MX-5 (a): the gate's source for observedWorkers | The gate gets READ on `planeon_cgroup_worker_t` (the `probe-worker` leaf). On the two parents its path walk crosses, `planeon_cgroup_slice_t` and `planeon_cgroup_delegate_t`, it gets only `dir search` (a narrowed grant). It also gets `procAccess` on `planeon_worker_t`. A38 and A39 become union bounds that include the gate. Per-type assertions give each of the eight cgroup types exactly its readers: A38.<type> and A39.<type>, and for the two parents A38S.<type> (search only, the gate included). A59.planeon_worker_t gains the gate. | Q51-Q54; N05-N09, N14, N15; M59-M63, M68, M69; M70-M72 (narrowed grants are closed); M24 now also names A38.planeon_cgroup_broker_t and A39.planeon_cgroup_broker_t (`v5Changes`) |
| HS43 O-MATRIX-WRITER-PROCACCESS and O-MATRIX-GATE-PROCACCESS; owner decisions Q-MX-2 (b) and Q-MX-3 (b), 2026-10-15 | The observer is designated as the role that takes the native profile's P1 role captures and P5 lifecycle capture. The writer's `/proc` narrows to the gate and the observer, and the gate's to the broker and the observer: three v4 `procAccess` entries are removed (server to writer, broker to writer, server to gate). A59.planeon_policy_writer_t and A59.planeon_gate_t pin the new sets. | Q57, Q58; N18-N21; M73-M75; nine v4 checks of the removed pairs now deny them (`v5Changes`) |
| v4 carried G1 (NOTE) | "Booleans and states" names K1's carry to W01's record, as the introduction of v4 does. | — |

What the Q-HE3D-2 grant reaches:
- On the `probe-worker` leaf, the READ group on its directory and files: the leaf's control and event files, such as
  `cgroup.procs` and `cgroup.events`.
- On the slice and the delegated service cgroup, `dir search` alone: the gate walks through them but opens and reads
  nothing there (A38.<type>, A39.<type>; N14, N15).
- On the worker's processes, the `/proc` entries SELinux allows a `procAccess` peer. The kernel adds its own rules for the
  ptrace-gated entries (`exe`, `fd`, `cwd`, `environ`, `maps`, `mem`): the target must be dumpable, the reader's uid must
  match the target's unless it holds CAP_SYS_PTRACE, and the reader's capabilities must cover the target's
  (`__ptrace_may_access`, `cap_ptrace_access_check`). The worker runs as another uid, and the gate holds no capability
  (A68), so the gate reaches only the worker's ungated entries, for example `stat` and `status`.
- The probe worker's `cgroup.kill` and `cgroup.procs` stay writable only by init, the broker and, before the seal,
  containment (A42, A43; N08).

### HS43 /proc evaluations

HS43 asked this amendment to evaluate narrowing two `/proc` peer sets (O-MATRIX-WRITER-PROCACCESS,
O-MATRIX-GATE-PROCACCESS). The owner decided both on 2026-10-15 (Q-MX-2 (b), Q-MX-3 (b); "Owner decisions and facts for
v5").

SELinux labels every `/proc/<pid>` entry with the target's domain (`selinux_task_to_inode`). It checks each access by the
entry's class: a regular file needs `open` and `read`, and the `exe` link needs `lnk_file read`. The matrix's
`procAccess` pair grants all of these together with `process getattr`, so the matrix cannot give a reader the ungated
entries without the ptrace-gated ones: both are checked against the same target domain. The kernel's ptrace rules (the
target dumpable, uids matching or CAP_SYS_PTRACE, capabilities covering the target's) then decide the gated entries.

The duties that need these reads, from the published contracts:
- The gate checks the writer's executable through its exe link on every I07 frame (HS43).
- The broker checks the gate's artifact, including its exe link (HS43).
- The native profile v3 P1 role captures read each role's exe link, and the P5 lifecycle capture counts the processes of
  every planeon domain, the writer's included. No published contract named the role that takes these captures; the
  owner has now designated the observer, the inspection role and the least network-exposed of the three reader roles.
- The kernel limits which exe links any reader can read: the reader's capabilities must cover the target's
  (`cap_ptrace_access_check`) and the uids must match. The observer holds CAP_NET_ADMIN and CAP_BPF. It reads the
  gate's and the writer's exe links (neither holds a capability the observer lacks) and P5's counts, which need no gated
  entry. It cannot read the exe link of the broker (CAP_SETUID and CAP_SETGID), of the server when the server holds
  CAP_NET_BIND_SERVICE (a signed port below 1024), or of the other-uid worker. No other reader role could either: the
  server lacks the broker's capabilities as well. P1's image capture of those roles needs another route, carried to the
  next native-profile successor with the observer's designation (review XR3-2).
- The server reaches the gate only over I04 TLS and has no duty with the writer; the broker has no duty with the
  writer.

Outcome:
- **The writer (`planeon_policy_writer_t`; residual R-WRITER-PROC).** Read only by the gate and the observer. The server
  and the broker lose the writer's `/proc`. R-WRITER-PROC narrows to those two readers. `mem` and `process_vm_*` stay
  refused, because they need ptrace attach, which Yama `ptrace_scope` 3 refuses.
- **The gate (`planeon_gate_t`; residual R-GATE-PROC).** Read only by the broker and the observer. The server loses the
  gate's `/proc`. R-GATE-PROC narrows to those two readers.

The per-target assertions A59.planeon_policy_writer_t and A59.planeon_gate_t pin the new sets, and M73-M75 show that
giving any of the three removed pairs back breaks them. The observer's designation is carried to the next
native-profile successor (the primary lane's O-NATIVE-GATE-NOCAP packet) and to W03.

### Owner decisions and facts for v5

- **Q-MX-2 (b) and Q-MX-3 (b), 2026-10-15** (relayed by the lane monitor; the owner first chose "keep and record" from
  the earlier framing and then, after seeing the analysis above, chose the recommendation): the observer is designated
  as the role that takes the native profile's P1 role captures and P5 lifecycle capture, carried to the next
  native-profile successor (the primary lane's O-NATIVE-GATE-NOCAP packet) and to W03. The writer's `/proc` narrows to
  the gate and the observer, the gate's to the broker and the observer, and the server and the broker lose the reads
  they have no duty for, with A59 per-target pins and mutations. The same message accepts the Q-MX-1 shape and
  restates Q-MX-4 (a) and Q-MX-5 (a).
- **Q-HE3D-2 (a), 2026-10-15** (via the lane monitor): the gate has no allowed source for observedWorkers, so in
  production BIND fails closed until it is fixed. SELINUX-MATRIX-I04-KEYCERT carries the grant: gate READ on the
  probe-worker cgroup and `procAccess` to `planeon_worker_t`. An I05 successor that takes observedWorkers from the
  worker cgroup (KERNEL) follows this matrix.
- **Facts relayed by the lane monitor, 2026-10-15** (published-contract pointers and owner decisions):
  - The I04 server credential has no named type in v4. I04 is mutual TLS 1.3. The gate reads its serving private key
    (PKCS#8), its serving certificate chain and exactly one client CA (Q-HE3D-8 (a)), all DER. The resolved spec §4.2
    fixes the server's side as a mechanism: it pins the endpoint SPKI and keeps its own KUBERNETES_PROXY_SERVER_MTLS
    credential. No published contract fixes the server's files or has it read a file of the gate's, so the matrix
    gives the server no read of the gate's files.
  - The gate's signed configuration is at `/etc/planeon/effect-gate/config.json` and `config.json.sig` (Q-HE3D-5 (a)),
    labelled `planeon_etc_t` and written only by the maintenance domain in maintenance mode.
  - The configuration pins its credential and CA files by sha256. HE-008 fixes the credential file paths; this matrix
    fixes their type and access.
  - The config-signer public key is compiled into the binary (Q-HE3D-7 (d)), so no key file needs a type.
- **Q-MX-1 (a), monitor (owner-delegated), 2026-10-15: separate types, gate-only READ on the key, least privilege
  elsewhere; the key joins A09.** The shape is this contract's:
  - The key has its own type. It is the endpoint identity the server pins (SPKI), distinct from the gate's upstream
    client credentials, with its own installation and rotation.
  - The chain and the client CA share one type. Both are public, pinned by sha256 in the signed configuration, read by
    the gate alone and written by maintenance alone, so a third label would change no access.
  - It follows the matrix's rule of one type per credential, like the gate's two upstream credentials and one
    `qualk8s_<component>_cred_t` per API client. The chain and its one client CA count as one public trust bundle.

## History: v4 (W02e-F)

v4 is the W02e-F successor of the adopted W02e matrix `../selinux-matrix/` (`planeon.internal.selinux-matrix/v3`,
MET-ENFORCE-009, review round 3 PASS_FOR_SOURCE_PUBLICATION with K1-K6 carried). A later layer pins the v3 bytes, so v3
stays byte-identical and v4 is published beside it. v4 keeps the v3 matrix and changes only what round 3 carried to
W02e-F: K2, K3, K4 and K6. The other two round-3 findings stay carried as the v3 `status.json` records them:
- K1 to W02a-F, T04 and W01's record: A62-A65 hold under the pinned policy only. The maintenance domain's `load_policy`
  preserves boolean values by name, so as the trusted installer it can reach any boolean state, and the early
  maintenance-boot window relies on the systemd target. It needs a record-level boot-entry discriminator (a measured
  boot entry or command line) or an explicit statement in W01's record.
- K5 to W03 and T04, three requirements: `DelegateSubgroup=broker` (systemd 254 or later) for the pre-created delegated
  leaves; the maintenance unit writes the planeon booleans while running in `init_t` itself; `planeon_server_port_t` is
  assigned by portcon from the signed port at the maintenance install.

Accepted base: main `4196dae` (MET-ENFORCE-015, 214 packets). The packet that publishes v4 is claimed only after the
primary lane's PERF packet merges (owner decision, 2026-10-09).

### What v4 changed

| Finding | v4 rule | Vectors |
|---|---|---|
| K2 MINOR, A59 checked a union | One assertion per planeon target (the five resident roles, the writer, containment and the maintenance domain; the admin login is not a planeon target and its `/proc` is host policy, round-1 F5), `A59.<target>`, each allowing only that target's `procAccess` peers. A59 stays as the union bound (its statement now says so), so every v3 identifier is kept. | M51-M53 (gate to server, gate to containment, broker to maintenance: each breaks exactly its per-target assertion); M34, M45 now also name the per-target assertion |
| K3 NOTE, no assertion pinned load_policy before the seal | A66: in ENROLLED_CONTAINMENT no domain holds `security load_policy`; with A21, no `load_policy` grant is reachable in the two modelled enrolled states, and A23 pins `setenforce` in every state. That the reviewed policy is the only one loaded throughout an enrolled boot does not follow from these assertions alone: systemd may set `planeon_maintenance_mode` before the seal, which reaches a boolean combination the model does not evaluate. It rests on decision 10 and on the policy digest and booleans W01's record pins, the same dependency as K1 (round-1 F3). | M54, M55 |
| K4 NOTE, cgroup2 wording and S11 | The three cgroup2 statements are corrected under "Cgroup creation and labels". S11 now checks `dir create` against `planeon_cgroup_slice_t`, the type computed from the parent, which is what the kernel checks. | S11 |
| K6 NOTE, stale count in the brief | The v4 review brief states 109 assertions. | — |

Every v3 vector keeps its identifier and expected result, except S11 (target, K4) and M34 and M45 (they also name the
per-target assertion). The new access checks (C1623 onward for the new assertions) and M51-M55 are appended. The
evaluator `scripts/selinux_matrix_v2.py` is the v3 evaluator with only the matrix version changed.

## Files

| File | Content |
|---|---|
| `matrix.json` | `planeon.internal.selinux-matrix/v6`. It holds three booleans and three boot states, 19 domains, 58 types, 6 sockets, 4 ports, 17 transitions, 12 genfscon rules, 4 named type transitions, the capability, `bpf`, `security`, `process`, `process2` and `service` grants, 21 `/proc` pairs, 64 per-source closures, the two mount sources with their `filesystem` grants and `associate` pairs, and 189 deny assertions |
| `vectors.json` | 4,321 access checks (640 allow, 3,666 deny, 15 outside, each with its state and intent), 103 mutation checks, the W02a slot values (unchanged), `v6Changes`, which lists every v5 vector whose expected result changes under v6, with its reason, and `entryTypes` |
| `../../scripts/selinux_matrix_v4.py` | Reference evaluator (v5's, with the matrix version changed, transition closures and the `filesystem` class): `allowed`, `check_matrix`, `failed_assertions`, `w02a_slots`, `apply_ops`, `entry_types` |

## What the matrix closes

`allowed(state, source, target, class, perm)` answers True or False where the matrix is closed and None outside it.

| Closed | Exactly |
|---|---|
| The matrix's own types | Every file-class permission (`file`, `dir`, `sock_file`, `lnk_file`; all v6.12 classmap permissions in seven groups: READ, WRITE, RELABEL, EXECUTE, EXECUTE_NO_TRANS, EXECMOD, ENTRYPOINT), for every declared domain and any other domain |
| Its sockets and ports | `unix_stream_socket` `connectto`, `create`, `bind`, `listen`, `accept`; `tcp_socket` `name_bind`, `name_connect` |
| Per-source closures | The server, observer, broker, worker, gate, writer and containment get no `name_connect`, `name_bind`, `connectto` or `file execute_no_trans` on any target the matrix does not list for them, declared or not (W01 §5.3 "only" rows; reviews R5, N5). A grant to every domain never reaches a closed source: it needs an explicit grant. v6: the eight backend domains and the Pod domain get no `file execute_no_trans` on any type; these sixteen sources enter no undeclared domain, admin login or systemd (`process transition`, `dyntransition`) and are entered through no type the matrix does not grant them (`file entrypoint`); the two mount sources relabel no superblock to any type but container content |
| The `filesystem` class (v6) | For the mount sources (the kubelet and the runtime), every permission (`mount`, `remount`, `unmount`, `getattr`, `relabelfrom`, `relabelto`, `quotamod`, `quotaget`, `watch`) on a declared type, and `relabelto` on every type; `associate` into every declared type, whatever the file's type |
| Another process's `/proc` | `dir`/`file`/`lnk_file` READ on a declared domain and `process getattr` on it come only from `procAccess` |
| Process permissions on declared domains | `transition` (effective with `file execute` for the source, `file entrypoint` for the target and, after `no_new_privs`, `process2 nnp_transition`), `dyntransition`, `ptrace`, `sigkill`, `sigstop`, `signal`; on the caller itself `setexec`, `setsockcreate`, `execmem`, `execstack`, `execheap` |
| Capabilities of declared domains | Every `capability`, `capability2`, `cap_userns` and `cap2_userns` permission |
| `bpf`, `security`, `service` | Every permission listed, `service` on the matrix's unit types |

Outside the matrix (None): ordinary access to undeclared types (libraries, devices), a domain's own `/proc`, the capabilities
of undeclared host domains, other process and socket permissions (`sigchld`, `fork`, socket `read`/`write`), connections of
backend components to undeclared ports or sockets, transitions of unclosed sources into the admin login and into systemd,
which the host's login and boot policy defines (pam_selinux, `kernel_t` to `init_t`; review R3), and (v6) the `filesystem`
class outside the mount sources' closure: systemd's and undeclared domains' mounts, host filesystem types, and statfs by
domains that are not mount sources. The W03 policy module adds that access. It
may grant nothing the matrix closes beyond the matrix.

## Booleans and states

| State | planeon_containment_enabled | planeon_maintenance_mode | secure_mode_policyload | Meaning |
|---|---|---|---|---|
| ENROLLED_CONTAINMENT | 1 | 0 | 0 | Enrolled boot, S2 up to S4 |
| ENROLLED_SEALED | 0 | 0 | 1 | Enrolled boot after S4; the state every v2 record requires (W02a host lock state) |
| MAINTENANCE_BOOT | 0 | 1 | 0 | The maintenance boot entry (W01 §5.5); no planeon role starts |

Each boot leaves the initial state (1, 0, 0) by one atomic commit (selinuxfs `commit_pending_bools`), so no transient
state exists (review R10):
- the enrolled boot leaves it at S4, when containment sets `planeon_containment_enabled` = 0 and `secure_mode_policyload` = 1;
- the maintenance boot leaves it early, when a systemd unit enabled only in that boot's target sets
  `planeon_maintenance_mode` = 1 and `planeon_containment_enabled` = 0.

A boolean write needs `security setbool` and `file write` on the boolean's selinuxfs file (`sel_write_bool`). selinuxfs
labels each boolean file by genfscon, so the three planeon booleans have their own types. Only the two writers above may
write them, only in the initial state. After either commit no declared domain can write them: the maintenance domain may
change other booleans but cannot leave maintenance mode or re-enable containment (A62-A65; review N4). These assertions
hold under the pinned policy; K1 (a policy load in the maintenance boot carries boolean values into the new policy) stays
carried to W02a-F, T04 and W01's record (v4 G1).

`secure_mode_policyload` = 1 then freezes booleans, policy load and enforcing mode until reboot. The pinned binary policy
must contain the matching conditionals (W01 §5.2), and T04 checks them.

## Domains

| Kind | Domains |
|---|---|
| Resident roles | `planeon_server_t`, `planeon_observer_t`, `planeon_broker_t`, `planeon_worker_t`, `planeon_gate_t` |
| Lifecycle subjects | `planeon_policy_writer_t` (entered by the admin login through `/opt/planeon/bin/harness-policy-write`), `planeon_contain_t` (entered by init once per boot, only while `planeon_containment_enabled`) |
| Maintenance | `planeon_maint_t` (entered by the admin login, only in the maintenance boot) |
| Backend | `qualk8s_apiserver_t`, `qualk8s_controller_manager_t`, `qualk8s_scheduler_t`, `qualk8s_kubelet_t`, `qualk8s_runtime_t`, `qualk8s_datastore_t`, `qualk8s_netpol_t`, `qualk8s_proxy_t` |
| Qualification Pods | `qualk8s_container_t` |
| Admin | `planeon_admin_t`: the confined domain root logins map to (entry by host login policy) |
| System | `init_t` (systemd; entry by host boot policy) |

The process contexts equal the W02a v2 schema's fixed `processLabel` values. A domain's name is fixed by its kind:
planeon kinds start `planeon_`, backend and Pod domains start `qualk8s_`, and the system domain is `init_t`. So an upstream
unconfined or privileged type, such as container-selinux's `kubelet_t`, `container_runtime_t` or `spc_t`, or refpolicy's
`unconfined_t`, cannot appear (W02a round-2 N1; mutation M37). Confinement itself is a T04 check on the compiled policy.

## Types and rules

| Category | Types | Access |
|---|---|---|
| Entrypoints | one `*_exec_t` per role, lifecycle, maintenance and backend domain (16) | READ any domain; EXECUTE the starter only; ENTRYPOINT the entered domain only; EXECUTE_NO_TRANS nobody; WRITE/RELABEL `planeon_maint_t` only in the maintenance boot, which also enables fs-verity |
| Interpreter | `planeon_interpreter_exec_t` (Python for SERVER and WORKER) | EXECUTE init, broker, server, worker; never an entrypoint; nobody runs it without a transition |
| Sealed configuration and units | `planeon_etc_t`, `qualk8s_config_t`, `planeon_unit_file_t`, `qualk8s_unit_file_t` | READ any; WRITE/RELABEL maintenance only |
| Credentials | `planeon_server_cred_t`, `planeon_observer_cred_t`, `planeon_gate_effect_cred_t`, `planeon_gate_writer_cred_t`, `planeon_gate_i04_key_t` and `planeon_gate_i04_cert_t` (v5), `qualk8s_sa_key_t`, `qualk8s_encryption_key_t`, one `qualk8s_<component>_cred_t` per API client | READ the owners only; WRITE/RELABEL maintenance only (W01 §5.5 M5) |
| Socket files | I05, I07, observer, broker, datastore and runtime socket files | The listener and its one connector |
| Cgroups | `planeon_cgroup_{slice,contain,server,observer,gate,delegate,broker,worker}_t` | READ init, containment and the reader roles, and (v5, Q-HE3D-2 (a)) the gate on the `probe-worker` leaf, with only `dir search` on the slice and the delegated service cgroup; WRITE init, containment before the seal, and the broker on its delegated service cgroup (`delegate`) and its `broker` and `probe-worker` leaves; RELABEL nobody |
| bpffs pins, seal marker | `planeon_bpf_pin_t`, `planeon_seal_t` | READ containment and the reader roles. Pins: WRITE containment before the seal, labelled by genfscon. Seal marker: WRITE containment in the enrolled boot (S5), labelled by a named type transition |
| Boolean files | `planeon_bool_maintenance_t`, `planeon_bool_containment_t`, `planeon_bool_policyload_t` (selinuxfs genfscon) | READ any; WRITE only as described under Booleans and states |
| Journal, data | `planeon_gate_journal_t`, `qualk8s_datastore_data_t` | The owner; the maintenance domain only in the maintenance boot (reconciliation, restore: counterexample 25) |
| Container content | `qualk8s_container_file_t` | The runtime writes; the Pod domain enters it |

- **Sockets.** The gate labels its two listening sockets `planeon_i05_socket_t` and `planeon_i07_socket_t` with
  `setsockcreate`, so `connectto` tells I05 from I07. Only the broker connects to I05 and only the writer to I07. The other
  sockets keep their listener's domain as their label.
- **Ports.** `planeon_server_port_t` is the server's own signed listener (W01 §5.3, W02a `listenEndpointIds`). Only the
  server binds it, which matches the server's CAP_NET_BIND_SERVICE for a signed port below 1024. Campaign clients may
  connect from any domain except the closed planeon sources (review N2). `planeon_kubeapi_port_t` is bound by the apiserver and connected to by exactly the gate, the observer, the
  controller-manager, the scheduler, the kubelet, the network-policy agent and the service proxy (P2). `planeon_i04_port_t`
  is bound by the gate and connected to by the server. `qualk8s_kubelet_port_t` is bound by the kubelet and connected to by
  the apiserver.
- **Port numbers.** `name_bind` is not checked for ports inside `net.ipv4.ip_local_port_range`. Every labelled port must
  therefore lie outside it; that is a W03 requirement and a T04 check (review R16).
- **Cgroup creation and labels.** Containment creates the role service cgroups and the broker's leaves before the seal
  (W01 S3 "creates"), sets limits and attaches the programs; systemd reuses them at S6.
  - kernfs supports security xattrs (`SE_SBGENFS_XATTR`, `kernfs_xattr_set`), but no planeon cgroup node carries one: the
    cgroup2 root has none and nothing relabels (A44). So a named type transition under a cgroup never fires: in v6.12
    `selinux_kernfs_init_security` returns without labelling when the parent has no xattr (review N1). Eight cgroup2
    genfscon path rules therefore label the slice, the containment service, the four role services and the broker's
    two leaves. They apply when a node is instantiated, whoever creates it, and they also label the cgroup interface files
    under each path. hooks.c sets `SE_SBGENFS` for cgroup2 unconditionally, so the path rules apply without any policy
    capability. `cgroup_seclabel` only makes cgroup2 relabelable through setxattr (`selinux_is_genfs_special_handling`,
    `SBLABEL_MNT`); with it enabled an xattr would override the genfs label, which is why the relabel denials (A44, and
    no `relabelfrom` grant anywhere) carry weight (review K4).
  - The kernel checks `dir create` against the type `selinux_determine_inode_label` returns, not against the genfs type
    the new node receives. With `cgroup_seclabel` the cgroup2 mount is `SBLABEL_MNT`, so a creator's fscreate context,
    when set, is that type; otherwise it is the type computed from the parent (the slice type, or the delegate type under
    the broker's delegated cgroup). S11 checks containment's `dir create` on `planeon_cgroup_slice_t` (review K4).
    `process setfscreate` is outside the matrix, so W03 and T04 require that no creator of a planeon cgroup (systemd,
    containment, the broker) sets an fscreate context when it creates one (round-1 F4).
  - Why the matrix lists `cgroup_seclabel`: the path labels do not need it. It is listed because the base policies W03
    can select declare it, and listing it makes the relabel and fscreate consequences above explicit rather than
    depending on its absence (round-1 F4).
  - genfscon matches by prefix and the longest match wins. So no other cgroup path may begin with a planeon path; systemd's
    fixed, sealed unit names keep it that way, and W03 and T04 check it.
  - Nothing relabels a cgroup (A44). `check_matrix` refuses a named type transition under a genfs-labelled parent (M49).
  - The delegated `planeon-capacity-broker.service` directory has its own type, `planeon_cgroup_delegate_t`. The broker
    writes its `cgroup.procs`, which clone3 `CLONE_INTO_CGROUP` checks at the common ancestor.
  - The broker's WRITE grant on its delegated cgroups is an upper bound. It includes `dir create` and `rmdir`, while W01
    §5.4 needs only `cgroup.procs`, `cgroup.freeze` and `cgroup.kill`. A broker that replaced its `probe-worker` leaf after
    the seal would lose the leaf's programs, and the readers' census refuses that (review N8).
- **Objects on tmpfs and other xattr filesystems.** Four named type transitions label runtime objects at creation (review N6):
  - systemd's `/run/planeon` (`planeon_run_t`);
  - containment's seal marker `sealed` (`planeon_seal_t`);
  - the gate's `effect-admission.sock` and `policy-write.sock` (`planeon_i05_sock_t`, `planeon_i07_sock_t`).

  W03 adds the rules for the observer, broker, datastore and runtime socket files, with the names their configurations fix,
  producing the types above. Persistent objects take their types from file contexts when the maintenance boot installs
  them.
- **Pins.** bpffs cannot be relabelled, so pins take `planeon_bpf_pin_t` from the genfscon path rule `bpf /planeon`
  (review R13). Readers open pins with `BPF_F_RDONLY`, which needs read only (review R18).
- **Transitions.** Seventeen transitions: init into the daemon roles (enrolled boot), containment (before the seal) and each
  backend component; the broker into the worker and the runtime into the Pod domain, both after `no_new_privs` through
  `nnp_transition` (policy capability `nnp_nosuid_transition`; review R12); the admin login into the writer (enrolled boot)
  and into maintenance (maintenance boot).
- **Signals.** systemd signals every planeon, backend and Pod domain. The broker kills its worker (pidfd), and the runtime
  signals Pods. The admin login signals no planeon domain (review R15).
- **`/proc` access.** The observer reads the `/proc` entries of every enrolled role, lifecycle subject, backend
  component and Pod. Since v6 (monitor Q-MX6-6 (a)) the server reads only its observer's and broker's (v1 peer
  qualification) and the broker only the gate's (v5 had both read every enrolled role, lifecycle subject, backend and Pod except, by owner Q-MX-2 (b) and Q-MX-3 (b),
  the writer, and the server not the gate). The gate reads the broker, the writer and (v5, Q-HE3D-2 (a)) the worker.
  - SELinux checks a `/proc/<pid>` entry as an access to the target domain. Ptrace-gated entries (`exe`, `fd`, `cwd`,
    `environ`, `mem`) also need the kernel's own rules: the reader's capabilities must cover the target's, and the uids must
    match unless CAP_SYS_PTRACE, which no role holds; the target must also be dumpable. So the gate cannot read the
    broker's `exe`, and no role reads the other-uid worker's or the kubelet's gated entries.
  - Captures and peer checks therefore use SO_PEERCRED, SO_PEERSEC, pidfds and ungated entries (`status`, `stat`,
    `cgroup`) (review R4), except for three exe-link reads: the gate's check of the writer reads the writer's exe link
    (HS43), the broker's artifact check reads the gate's (HS43), and the native profile's P1 role captures, which the
    observer takes (owner Q-MX-2 (b), Q-MX-3 (b)), read the exe link of each role whose uid matches and whose
    capabilities the observer's cover. `procAccess` grants these reads. No reader can read the exe link of the broker
    (its capabilities), of the server while it holds CAP_NET_BIND_SERVICE, or of the other-uid worker, so P1's capture
    of their images is carried to the next native-profile successor (review XR3-2).
  - Executable identity follows from the peer's label for the broker; the writer's executable is also checked through
    its exe link (HS43). The matrix lets each planeon domain be entered only through its
    sealed entrypoint type, and the per-source closure denies `execute_no_trans` on every type, declared or not, so no
    planeon process runs another program without a transition (review N5). v6 extends the closure to every backend and
    Pod domain, closes transitions of all sixteen closed sources into undeclared domains, and closes their entry through
    any type the matrix does not grant them (the maintenance domain, which is not a closed source, aside). The W02d seccomp filters (no `execve` in the
    daemon roles) are a second, independent layer.
- **systemd.** `init_t` holds every capability except `sys_module` and `sys_rawio` (modules are disabled after S5), plus
  `wake_alarm`, `block_suspend` and `audit_read`. That includes `dac_read_search`, `sys_admin` and `setpcap`, which systemd
  needs to set the roles' bounding sets. systemd is the trusted service manager, and the deny assertions name it where
  they allow it (review R2). It loads no BPF programs: the kubelet and runtime use the cgroupfs driver and no planeon or
  backend unit uses a BPF-backed directive (`DeviceAllow`, `IPAddress*`, `RestrictNetworkInterfaces`, `SocketBind*`, ...).
  That is a W03 requirement and a T04 check (review R7).
- **Unit sources.** Every systemd unit search path and drop-in directory (`/etc/systemd/system`, `<unit>.d`, `/run/systemd/*`,
  generator and transient directories) must carry a sealed unit type; that is a W03 requirement and a T04 check (review R17).
- **Further W03 and T04 requirements implied by the closures (review N7):**
  - no planeon or backend unit sets `NoNewPrivileges=` or an option that implies it, because systemd's transitions into
    them carry no `nnp_transition`;
  - no entrypoint and no container root filesystem sits on a `nosuid` mount, because `nosuid_transition` is closed;
  - the container runtime sets no per-Pod process label (no `setexeccon`, no per-Pod MCS), because `setexec` is closed for
    it; qualification Pods run in the one confined `qualk8s_container_t`;
  - no unit uses a BPF-backed directive, because systemd has no `prog_load` and those directives would otherwise fail
    open.

## Assertions

189 deny properties, each evaluated for every listed boot state, target and source. Sources are every domain plus
`OTHER_DOMAIN`, the declared domains, or a listed set; for capabilities only declared domains count, because undeclared
host domains' capabilities are outside the matrix.

| IDs | Property | Source |
|---|---|---|
| A01-A08 | Apiserver port (P2), I04 port, datastore socket (P1), runtime socket (P9), I05 and I07: exactly the enumerated connectors and binders | W01 §2.1, §5.3; W02b; W02c |
| A09-A11.9 | Each credential readable by its owners only; A09 covers the gate's I04 private key as well (v5), over every READ permission, not only `read` and `open` (A10 and A11.* keep `read` and `open`) | W01 §5.3, §2.1 P4 |
| A12-A13 | No sealed type written or relabelled in an enrolled boot, fs-verity included; only the maintenance domain in the maintenance boot | W01 §5.5; R8 |
| A14-A19 | `prog_load`: containment before the seal and the runtime (E1). No BPF maps. `prog_run` on containment programs: containment as loader before the seal and the reader roles. `prog_run` on the runtime's programs: the runtime alone | W01 §5.1; E1; R1 |
| A20-A23 | `setbool` only by containment and systemd in the initial state; nothing after the seal; maintenance only in the maintenance boot; never `setenforce` | W01 §5.2 S4, §5.5; N4 |
| A24-A31 | Who enters containment, maintenance, the daemon roles, the worker and the writer, and in which states | W01 §5.2, §5.4, §5.5, §2.4 |
| A32-A37 | No `dyntransition` into a declared domain, no `setexec` (on the caller), no `ptrace`, no `execmem`/`execstack`/`execheap`, no `execmod`, no `execute_no_trans` on entrypoints, the interpreter or container content | W01 §5.3; R3, R11, R14 |
| A38-A44 | Cgroups (F2): search, open and read only by init, containment, the readers and (v5) the gate (A38 and A39 are the union bounds; the gate reads the probe-worker leaf and only searches its two parents); writes by init, containment before the seal and the broker on its delegated cgroups; no relabel of cgroups or pins | W01 §5.1, §5.4; F2; R6, R13 |
| A45-A48 | Capabilities of declared domains: no `dac_read_search` except systemd, none in a user namespace; `sys_admin` only systemd, kubelet and runtime; `net_bind_service` only systemd, server, admin login and runtime (v5: the gate holds none, HS43 H5) | F2; W01 §5.3; W02a N1; R2 |
| A49-A55 | Pins, seal marker, gate journal and datastore data | W01 §5.1, §5.2 S5; W02a; W02b; counterexample 25; R10 |
| A56-A59 | Units only by systemd; signals to the roles, the writer and containment only from systemd, to the worker also from the broker; no domain outside the union of the `/proc` peers reads any planeon domain's `/proc` (v6: the union is unchanged, its duplicate entry removed; the per-target pins A59.<target> follow v6's pairs) | W01 §5.3, §4.3, §5.4; R4, R15, N8; Q-MX6-6 |
| A59.* (v4) | Eight per-target assertions: each planeon resident, lifecycle and maintenance domain's `/proc` only for its own `procAccess` peers (not the admin login's) | W01 §4.3, §5.3; K2 |
| A60.* | 71 per-source closures: each closed source gets nothing beyond its listed ports, sockets and (no) `execute_no_trans`, including an undeclared port, socket and program type; v6 adds A60.22-A60.30 (the qualk8s sources' `execute_no_trans`), A60.31-A60.46 (no transition into an undeclared domain, the admin login or systemd), A60.47-A60.48 (the mount sources' `relabelto`) and A60.49-A60.64 (entry only through granted types) | W01 §5.3; R5, N5; Q-MX6-2, Q-MX6-3, Q-MX6D-1, Q-MX6-4; XV1-2 |
| A61-A65 | The server alone binds its listener; the three planeon boolean files only by their writers in the initial state, by nobody afterwards | W01 §5.3, §5.2, §5.5; N2, N4 |
| A66 (v4) | Before the seal no domain loads policy | W01 §5.2 S1, S4; K3 |
| A67 (v5) | Only the gate reads its I04 serving chain and client CA, over every READ permission, not only `read` and `open` | Resolved §4.2; Q-HE3D-8; Q-MX-1 |
| A68.* (v5) | The gate holds no permission of any capability class | W01 §5.3 as amended by HS43 H5; review XR1-4 |
| A38S.* (v5) | The slice and the delegated service cgroup are searched only by their readers and the gate | Q-HE3D-2 (a); Q-MX-5 |
| A38.*, A39.* (v5) | 16 per-type assertions, over every READ permission: each planeon cgroup type is read only by its own readers (the gate only on the probe-worker leaf; on the slice and the delegated service cgroup A38.<type> leaves out search, which A38S.<type> covers) | W01 §5.1; F2; Q-HE3D-2 (a) |
| A69.* (v6) | Four per-reader pins: the server reads only its observer's and broker's `/proc` and gets only their process attributes; the broker only the gate's | Q-MX6-6 (a); NP4 Q-NP4-16 (a); W01 §4.3 (v1 peer duties, HS43) |
| A70-A74 (v6) | The mount sources relabel from no declared label but container content; among declared labels they mount, remount, unmount and statfs only container content and use no quota or watch permission; no type but container content, declared or not, may be associated with a container-content filesystem, and container content with no other declared label | Q-MX6-4 (a); NP4 P-b; XV1-1 |
| A75.*, A76.* (v6) | `mounton`: the mount sources mount on no declared directory, file or socket file but container content (the runtime socket file's WRITE upper bound aside), and the kubelet on no container content | Q-MX6-4 (a) |

The 103 mutation checks show the assertions are not vacuous.
- 71 add a forbidden grant (M51-M55 new in v4, M56-M68 and M73-M75 new in v5, M77-M87, M91, M99 and M101 new in v6) and name exactly the assertions it breaks. For example, the server connecting to the apiserver
  port breaks A01 and its per-source closure A60.1.name_connect; containment writing an artifact before the seal (fs-verity)
  breaks A12; the maintenance domain clearing maintenance mode breaks A65.
- Six remove a per-source closure and change the result (M88-M90 and M100 new in v6).
- Twenty-six are refused by `check_matrix`:
  - an unconfined backend type;
  - an undeclared domain;
  - a world-readable credential;
  - a transition through a non-entrypoint type;
  - a dead transition, from a removed `nnp_transition`;
  - another dead transition;
  - a matrix rule entering the admin login;
  - a type transition without write on its parent;
  - a type transition under a cgroup parent;
  - a cgroup type without its genfscon rule;
  - a relabel grant on a genfs-labelled type;
  - five narrowed grants other than cgroup `dir search` (v5): a permission outside the READ group, a group other than READ,
    a missing list, search with open, and a narrowed grant on a non-cgroup type;
  - (v6) a declared domain holding CAP_SYS_ADMIN that is not a mount source (M29, M94), a mount source without it (M93), a
    `filesystem` grant to another domain (M92), an `associate` pair naming an undeclared type (M95), a `filesystem`
    closure on a domain that is not a mount source (M96), two closures for one domain, class and permission (M97, M103), a
    process closure without `dyntransition` (M98), and a socket-file type with another class (M102).

## W01 finding F2: the cgroup gate, stated exactly

F2 found that W01 §5.1 and counterexample 28 argued "no other domain can even get an O_PATH fd". But cgroup2 on kernfs
exports file handles, so `open_by_handle_at` can produce a descriptor without a path walk. The stated mechanism is replaced
by the following, which rests on the controls that actually decide.

1. **Every non-O_PATH access is the SELinux label check on the planeon cgroup types.** The check applies however the dentry
   was found, by path walk or file handle (`do_handle_open` uses `file_open_root`). Opening a role cgroup directory, or
   opening `cgroup.procs`, `cgroup.kill`, `cgroup.freeze` or a limit file, needs `open` and `read` or `write` on
   `planeon_cgroup_*_t`. Only init, containment, the reader roles and the broker get them, each within its rows
   (A38-A43; F02, F03). Since v5 the gate also reads the `probe-worker` leaf, and only searches its two parents
   (Q-HE3D-2 (a); A38.<type>, A38S.<type>, A39.<type>).
2. **An O_PATH descriptor gets no open check (`do_o_path`), so it is limited where it is obtained.**
   - A path walk needs `dir search` on the planeon slice and role directories, which the admin domain lacks (A38; F01).
   - Decoding a file handle (v6.12 `fs/fhandle.c` `may_decode_fh`) needs CAP_DAC_READ_SEARCH in the initial user
     namespace. The v6.10 relaxed path needs `O_DIRECTORY`, CAP_SYS_ADMIN in the superblock's or the mount namespace's
     user namespace, and CAP_DAC_READ_SEARCH in the caller's own user namespace. The admin domain holds neither
     `dac_read_search` (in any form) nor `sys_admin` (A45-A47; F04, F05).
   - A procfs magic link (`/proc/<pid>/fd/<n>`, `cwd`) of a process holding a cgroup descriptor is a third route. It needs
     the ptrace read check on the holder: the admin domain has no `/proc` access to any planeon domain (A59; F08), and among
     roles the kernel's capability and uid rules apply.
3. **Item 3 is the control that decides detach.** Containment attaches with `BPF_PROG_ATTACH` and BPF_F_ALLOW_MULTI, never
   with a bpf_link. A bpf_link would be reachable through `BPF_LINK_GET_FD_BY_ID` by any CAP_SYS_ADMIN holder, and that
   call has no LSM check. So detaching needs the program's descriptor. That comes only through `bpf prog_run` on the
   containment-owned program (checked in `bpf_prog_new_fd`) and a read of the pin. After the seal only the reader roles
   get either (A17-A18, A49; F06, F07).

So an O_PATH descriptor alone can neither change cgroup controls nor detach an enrolled program. The outcome W01 claimed is
unchanged: no domain outside the enumerated ones can read, write or detach planeon cgroup controls. Two things remain
open:
- the behaviour of the enrolled kernel and policy (T04);
- the residual of owner decision E1 below.

## W02a slot values

| W02a slot | Value |
|---|---|
| `roles.SERVER.cgroup.selinuxLabel` | `system_u:object_r:planeon_cgroup_server_t:s0` |
| `roles.OBSERVER.cgroup.selinuxLabel` | `system_u:object_r:planeon_cgroup_observer_t:s0` |
| `roles.BROKER.cgroup.selinuxLabel` | `system_u:object_r:planeon_cgroup_broker_t:s0` |
| `roles.WORKER.cgroup.selinuxLabel` | `system_u:object_r:planeon_cgroup_worker_t:s0` |
| `roles.EFFECT_GATE.cgroup.selinuxLabel` | `system_u:object_r:planeon_cgroup_gate_t:s0` |
| `program.pinLabel` (every pin) | `system_u:object_r:planeon_bpf_pin_t:s0` |
| `sealMarker.selinuxLabel` | `system_u:object_r:planeon_seal_t:s0` |

All values match the W02a schema patterns. Fixing them as constants in the record schema is a W02a-F revision; until then
the validator of this part pins them here.

## Confined backend types (W02a round-2 N1)

Each backend component runs in its own `qualk8s_<component>_t`, defined by the qualification backend policy module, which
W03 writes. The module must meet these requirements, and the matrix and its assertions bind them:
- no backend or Pod type is unconfined, permissive or carries a type attribute that grants unrestricted access;
- every type has exactly the closed accesses above on planeon and qualk8s objects;
- the kubelet alone connects to the runtime socket, and the apiserver alone to the datastore;
- no backend type reads a planeon credential, searches a planeon cgroup, reads a pin, reads a planeon role's `/proc` or
  enters a planeon domain;
- (v6) no backend or Pod type executes a program without a transition, is entered through a type the matrix does not
  grant it, or enters an undeclared domain, and the kubelet and the runtime mount only as the `filesystem` closure
  allows (MX6-O1, MX6-O3, MX6-O4);
- the network-policy agent and the service proxy must not need BPF: only the runtime has the E1 exception, so an
  iptables or nftables agent is a selection criterion for W03.

container-selinux's `kubelet_t` and `container_runtime_t` are unconfined types and cannot be used.

## Owner decision E1 (v3)

**E1 (2026-10-07, re-confirmed after review R7).** W01 §5.3 makes `planeon_contain_t` the only domain with
`bpf { prog_load }`. On a cgroup-v2-only host every OCI runtime loads a BPF_PROG_TYPE_CGROUP_DEVICE program per container,
so a confined runtime could not work. The owner chose an exception, stated here at its real scope.

**What the policy enforces.** `qualk8s_runtime_t` gets:
- `bpf prog_load`, CAP_BPF, and `prog_run` on its own programs only (A19);
- no maps (A16);
- no `prog_run` on containment programs (A17, A18);
- no search or open of planeon cgroups and no read of pins (A38, A49).

**What it cannot enforce.** SELinux does not restrict program type, attach type or attach target. With CAP_SYS_ADMIN,
which the runtime needs for mounts and namespaces, `bpf_ns_capable` satisfies the other BPF capability checks too, so the
runtime can load program families far beyond cgroup-device, including ones that attach to no cgroup. It can also attach a
cgroup program at an ancestor of the planeon cgroups, such as the root, through an O_PATH descriptor. An ancestor's
program is effective on a descendant cgroup when it was attached with BPF_F_ALLOW_MULTI, or, attached without it, for any
attach type on which the descendant has no program of its own (`compute_effective_progs`).

**Accepted.** The runtime is therefore a trusted backend component for its BPF use. The controls are:
- W03 selects a runtime that loads only cgroup-device programs, only on container cgroups, under the cgroupfs driver (so
  systemd loads none);
- T04 checks that natively;
- a census of the effective program set of every planeon cgroup, for every cgroup attach type, must show only the
  containment programs. That census extends the W02a readers, which today query the seven containment hooks, and is
  carried to W02a-F.

The census sees only cgroup attachments, and only at the moments it runs. The runtime's other BPF use, and attachments made
and removed between two census points, rest on W03 selection and T04 alone (review N3).

E1 amends W01 §5.3 and is carried to W01's record, W03 and T04.

## Decisions made in this contract (not in the reviewed spec)

1. The gate labels its I05 and I07 listening sockets with `setsockcreate` (the only domain with that permission). A
   requirement on the gate implementation (W03).
2. Containment creates the role cgroups and the broker's leaves before the seal (W01 S3 "creates"); cgroup2 genfscon path
   rules label them. It creates pins under the genfscon-labelled `/sys/fs/bpf/planeon`, and the seal marker under a named
   type transition. It relabels nothing.
3. fs-verity is enabled in the maintenance boot by `planeon_maint_t`, which installs the artifacts. At S3 containment only
   measures (FS_IOC_MEASURE_VERITY) and refuses to seal if an enrolled artifact lacks verity. W01 S3 says "enables
   fs-verity", which would need write access on sealed artifacts in the enrolled boot, against §5.5 (review R8).
4. S4 sets both booleans in one atomic commit; the seal marker is written in S5, after it, by the still-running containment
   process. That process can no longer be re-entered, and W02a requires the containment domain to be empty in captures
   (review R10).
5. In the maintenance boot no planeon role or the writer is entered (A30). Backend components may run there, for credential
   issuance and datastore restore.
6. The admin domain's capabilities are closed: chown, dac_override, fowner, fsetid, kill, setgid, setuid,
   net_bind_service, sys_boot (it must reboot into maintenance), sys_nice, sys_resource and audit_write. It lacks
   dac_read_search, sys_admin, sys_module, sys_ptrace, net_admin, bpf, mac_admin and mac_override. It signals no planeon
   domain and reads no role's `/proc`.
7. Peer qualification and captures use SO_PEERCRED, SO_PEERSEC, pidfds and ungated `/proc` entries; executable identity
   follows from the label and the entrypoint closure (review R4). As above, HS43 adds that the gate also reads the
   writer's exe link, the broker reads the gate's, and the native profile's P1 captures read the exe links the kernel
   allows the observer (not the broker's, the other-uid worker's, or the server's while it holds CAP_NET_BIND_SERVICE;
   NP4 binds those captures by label instead, LABEL_BOUND). Since v6 only the observer takes captures; the server keeps
   its v1 peer reads of the observer and the broker, and the broker its check of the gate.
8. Required policy capabilities: `cgroup_seclabel`, `open_perms`, `network_peer_controls`, `nnp_nosuid_transition`.
9. Backend capability sets are declared, not observed (W03 confirms them against the selected distribution): kubelet and
   runtime as listed, network-policy agent and proxy `net_admin` and `net_raw`, apiserver, controller-manager, scheduler and
   datastore none.
10. The maintenance boot enters maintenance mode through one systemd unit enabled only in that boot's target. That unit is
    the only writer of `planeon_maintenance_mode`, and only in the initial state (N4).

## History: W02e review round 1 (v3), findings and dispositions

| Finding | Disposition in round 2 |
|---|---|
| R1 MAJOR, loaders lack `prog_run` on their own programs | Containment `prog_run` on its programs before the seal, the runtime on its own; A17-A19; Q39, S03 |
| R2 MAJOR, init_t and undeclared domains closed to every capability | systemd's capability set enumerated; capability assertions over declared domains only; undeclared domains' capabilities outside (O04) |
| R3 MAJOR, no entry into the admin login or systemd; setexec target | Transitions into ADMIN and SYSTEM kinds are host policy, outside (O06, O07, M42); `setexec` checked on the caller (A33) |
| R4 MAJOR, `/proc` modelling and ptrace preconditions | `procAccess` for dir/file/lnk_file READ and `process getattr`; self outside (O03); commoncap and uid rules and ungated captures stated (decision 7); A59 |
| R5 MAJOR, per-source "only" properties open for undeclared targets | `sourceClosures` for seven planeon domains; 21 A60 assertions; P01-P06; M02-M04, M35 |
| R6 MAJOR, S3 cgroups do not exist yet; labels after the seal | Containment creates them before the seal; 16 named type transitions; `planeon_cgroup_delegate_t`; A40-A44 |
| R7 MAJOR, E1 broader than stated; systemd BPF | E1 restated at its real scope and re-confirmed by the owner; census to W02a-F; systemd BPF excluded as a W03 requirement (M10) |
| R8 MAJOR, fs-verity at S3 needs write on sealed artifacts | Moved to the maintenance boot; containment measures (decision 3); A12, M08 |
| R9 MINOR, may_decode_fh description, magic links, bpf_link | F2 item 2 corrected, magic-link route added (F08); attachment by `BPF_PROG_ATTACH` only |
| R10 MINOR, seal marker after S4, sequential booleans | Atomic S4 commit; marker written in S5 (decision 4); A52-A53; S14, S15 |
| R11 MINOR, execute_no_trans with execute | Split groups; nobody holds `execute_no_trans` (A37, M23) |
| R12 MINOR, nnp transitions | `noNewPrivs` transitions need `process2 nnp_transition`; `nnp_nosuid_transition` capability (M18) |
| R13 MINOR, bpffs cannot be relabelled | genfscon rule; no pin relabel (A44) |
| R14 MINOR, incomplete FILE_PERMS; execmod | All v6.12 file permissions; A36, M22 |
| R15 MINOR, unknown permissions raise; signals | Unknown permissions are outside (O05, O08); signals closed (A57, A58, M33) |
| R16 MINOR, name_bind inside the ephemeral range | Ports outside `ip_local_port_range` (W03/T04 requirement) |
| R17 MINOR, systemd drop-ins and unit search paths | Sealed unit types on every search path and drop-in directory (W03/T04 requirement) |
| R18 NOTE | Cgroup file assertion A39 added beside A38; readers use `BPF_F_RDONLY`; a `matrixError` vector pins the exact full message; socket-file grants stay as broad groups and are listed as upper bounds |

## History: W02e review round 2 (v3), findings and dispositions

| Finding | Disposition in round 3 |
|---|---|
| N1 MAJOR, named type transitions under cgroup2 never fire | Eight cgroup2 genfscon path rules; cgroup type transitions removed; `check_matrix` refuses a type transition under a genfs-labelled parent (M49) and a cgroup type without its genfscon rule (M50); prefix rule disclosed |
| N2 MAJOR, the server's listener contradicted its name_bind closure | `planeon_server_port_t`, bound by the server alone (A61); closed sources need explicit grants even where a port is open to every domain (P09, M46, M47) |
| N3 MINOR, E1 statement incomplete | The effective-set rule stated exactly; the census covers cgroup attachments only, at the moments it runs; other BPF use rests on W03 and T04 |
| N4 MINOR, the maintenance domain could flip planeon booleans | Per-boolean selinuxfs types; writers only in the initial state; nobody afterwards (A62-A65, S16-S18, M44) |
| N5 MINOR, executable identity needs a per-source execute closure | `file execute_no_trans` closed for the planeon sources on every type (A60.15-A60.21, P07, P08, M48); seccomp named as a second layer |
| N6 MINOR, no labelling rule for the marker, socket files and /run | Four named type transitions; the remaining socket-file rules and persistent labels assigned to W03 and file contexts |
| N7 NOTE, implied W03 requirements | Listed: no NoNewPrivileges on units, no nosuid entrypoint mounts, no per-Pod labels, no BPF-backed unit directives |
| N8 NOTE, A59 narrow, M42 message, broker delegate grants | A59 covers every planeon domain (M45); the host-policy refusal has its own message; the broker's delegate WRITE disclosed as an upper bound |

## History: W02e review round 3 (v3), findings and dispositions in v4

| Finding | Disposition |
|---|---|
| K1 MINOR, boolean carry-over on a policy load; early window | Not in W02e-F: carried to W02a-F, T04 and W01's record (stated under "Booleans and states"; v4 G1) |
| K2 MINOR, A59 checked a union | A59.<target> per target (M51-M53) |
| K3 NOTE, load_policy before the seal | A66 (M54, M55) |
| K4 NOTE, cgroup2 statements and S11 | Corrected; S11 on the slice type |
| K5 NOTE, implied W03 requirements | Not in W02e-F: carried to W03 and T04 |
| K6 NOTE, stale count | The v4 brief states 109 |

The round-1 and round-2 dispositions above are carried from v3 unchanged.

## History: W02e-F review round 1 (v4), findings and dispositions

| Finding | Disposition in round 2 |
|---|---|
| F1 MINOR, the evaluator comment still said cgroup2 has no xattr labelling | Comment above `GENFS_CATEGORIES` corrected |
| F2 MINOR, the K1 and K5 carries were attributed to the v3 README | Stated from the v3 `status.json`, including K1's carry to W01's record and K5's three requirements |
| F3 NOTE, the K3 row claimed more than the assertions show | Narrowed; the dependency on decision 10 and W01's record stated |
| F4 NOTE, the fscreate branch and the reason for `cgroup_seclabel` | Both stated; a W03 and T04 requirement on fscreate added |
| F5 NOTE, the admin login is not a per-target `/proc` target | The per-target scope is stated: planeon resident, lifecycle and maintenance domains |

## Not claimed

No policy module, compiled policy or loaded host. No observation that the kernel or the selected distribution behaves as
modelled. No seccomp filter (W02d), no admission allowlist (W02f), no selected distribution (W03). All E01-E12 stay
OPEN_UNPROVEN. The W01, W02a, W02g, W02b and W02c bytes, HS43, native-profile v4 and the adopted v3, v4 and v5 matrices
are unchanged. No helper type is declared (W02-PROD) and no host filesystem type is named (W03).

## Spec mapping

| Design text | Here |
|---|---|
| §2.1 P1 datastore `connectto` from the apiserver alone | Socket row, A05 |
| §2.1 P2 `planeon_kubeapi_port_t`, enumerated connectors, no root login | Port row, A01, A02 |
| §2.1 P4 signing key readable only by apiserver and controller-manager | `qualk8s_sa_key_t`, A10 |
| §2.1 P5 sealed control-plane configuration | `qualk8s_config_t`, `qualk8s_unit_file_t`, A12, A13 |
| §2.1 P9 runtime socket only from the kubelet | Socket row, A06 |
| §5.1 bpffs pins, `prog_run` only to readers, MULTI detach, containment owns programs | A14-A19, A49-A51; E1 |
| §5.1 `dir search` denial on planeon cgroups | A38; restated for F2 |
| §5.2 S2-S5 containment once, booleans, `secure_mode_policyload` | States, A20, A21, A24, A25, A52, A66; decisions 2-4 |
| §5.3 per-role domains and key denials | Domains, capabilities, A01-A11, A32-A37, A45-A48, A56-A60, A59.* |
| §5.4 worker exec after `no_new_privs`, kill through the pidfd | A29, A58; `nnp_transition` |
| §5.5 sealed types, `planeon_maint_t`, `planeon_maintenance_mode` | A12, A13, A22, A26, A27, A30 |
| Resolved §4.2: the gate's TLS listener identity is the signed KUBERNETES_API_PROXY endpoint identity (v5) | `planeon_gate_i04_key_t` (A09), `planeon_gate_i04_cert_t` (A67) |
| §5.3 EFFECT_GATE as amended by HS43 H5: no capability (v5) | Capabilities, A48, A68.*; O-MATRIX-GATE-NETBIND |
| NP4 Backends residual: an `execute_no_trans` closure for the qualk8s sources (v6) | A60.22-A60.30; MX6-O1, MX6-O4 |
| NP4 P-b: a `filesystem` closure for context= mounts by the kubelet and the runtime (v6) | `mountSources`, `filesystem`, `filesystemAssociate`; A60.47, A60.48, A70-A76; MX6-O2, MX6-O3 |
| §5.3 WORKER, HS43 O-W03-WORKER-EXEC: no transition into any other domain (v6; binds R10's worker) | A60.34.transition |
| Owner Q-MX6-2 (a), Q-MX6-3 (a): undeclared binaries refused, entry included (v6, review XV1-2) | A60.49-A60.64 |
| NP4 Q-NP4-16 reader duties; §4.3; §5.4 W3 (v6) | `procAccess`, A59, A59.*, A69.* |
| HS43 O-MATRIX-WRITER-PROCACCESS, O-MATRIX-GATE-PROCACCESS (v5) | "HS43 /proc evaluations"; A59.* |
| Owner decision Q-HE3D-2 (a): the gate's observedWorkers source (v5) | Cgroup row, `procAccess`, A38.*, A38S.*, A39.*, A59.planeon_worker_t |

## Still open

All E01-E12 and T01-T08. v6: the named limitation (owner "Keep, T04 uses v5": T04 cluster qualification runs against
matrix v5 until the helper types are declared); the obligation rows MX6-O1 to MX6-O8; the helper types (W02-PROD D-HELPER-TYPES); the
native-profile successor that binds backend captures to the running image and refuses the two entry types on enrolled
files; NP4's merge and the coupling re-check before adoption. The I04 credential file paths (HE-008) and their labelling as `planeon_gate_i04_key_t` and `planeon_gate_i04_cert_t` (W03). The observer's designation as the capturing role, carried to the next native-profile successor (the primary lane's O-NATIVE-GATE-NOCAP packet) and W03 (owner Q-MX-2 (b), Q-MX-3 (b)). The maintenance domain installs the I04 key and chain by creating them under a type it may open and relabelling them: it has no READ permission, `open` and `getattr` included, on `planeon_gate_i04_key_t` or `planeon_gate_i04_cert_t` (A09, A67), so it cannot write or stat them in place (HE-008, W03; review XR3-4). P1's capture of the broker's, the other-uid worker's and (with CAP_NET_BIND_SERVICE) the server's image, which no reader can take (next native-profile successor). The I05 successor that takes observedWorkers from the worker cgroup. The binary policy, its conditionals and its behaviour on the enrolled kernel (T04). The backend
policy module, the selected runtime's BPF behaviour and the selected distribution (W03). The effective-program census
(W02a-F). The seccomp filters (W02d). The W02a schema constants for these labels (W02a-F). W03-W07 remain gated. Alpha2
remains open; model-effort transition NOT_DUE.
