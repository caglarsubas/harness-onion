# W03 obligation-register amendment 3 (W03-PLAN-AMEND-3, slot 250)

Alpha 2A; 2026-10-18. Status: **CONTRACT_CANDIDATE_AWAITING_INDEPENDENT_REVIEW**. The W03 plan v2
(`architecture/w03-plan-v2/plan.json`, MET-ENFORCE-024), amendment 1 (`architecture/w03-obligation-amendment-1/`,
MET-ENFORCE-025) and amendment 2 (`architecture/w03-obligation-amendment-2/`, MET-ENFORCE-032) stay byte-identical;
`amendment.json` binds all three by SHA-256 and applies after amendments 1 and 2 (`after`, an ordered list). No edge
record is published: edge record v5 already registers HE-004D1's three rows and the native-profile v3 schema its replay
reads.

**Why.** The monitor's scope agreement AMEND3-SCOPE (2026-10-18) queues this amendment with three items. The owner's
answers to the HE-004D1 dossier (Q-HE4D1-1..12, all (a), 2026-10-18) route two duties to it (Q-HE4D1-8 and -9): the
policy observer's host policy outside the SELinux matrix, as I05-8 gives the gate its own (OBS-HOSTPOL-1), and the
broker's freeze of the probe-worker leaf at quiescent points, which native-profile v4's frozen bracket needs before any
WORKER capture qualifies (NP-9). The amendment records HE-004D1's scope under those decisions, with the residuals the
owner accepted and two hand-offs (`packetScopes`), and makes the correction Q-HE3-3 (a) asks for: amendment 1's HE-003
share in SEC-4 and HI-7 still derives a kept CAP_NET_BIND_SERVICE for a port below 1024, which Q-HE2S-9 (a) removed. The
host-field drop stays separate (AMEND3-SCOPE). All decisions, the monitor's Q-A3-1..8 on candidate 1 included, are
quoted verbatim in `amendment.json` (`ownerDecisions`), and the dossier's (a) options with them
(`packetScopes[0].decisions`; the dossier's hash is provenance only).

**HE-004D1's scope.** HE-004D1 builds in R10 the policy observer's native-profile v4 captures (one P1 capture per
resident role, the P5 lifecycle capture and one backend capture per component) and the inspector policy (NP-3), with the
capture-family checks whose vectors it replays, as owner decisions Q-HE4D1-1..12 (a) shape them (`decisions`). Captures
stay in-memory records (Q-HE4-10 (a)); check_qualification and the acceptance token stay HE-004D2's (I06-2). The host
policy its captures need outside matrix v5 and v6 is OBS-HOSTPOL-1's (HE-008, T04). NP-3's text stays plan v2's byte for
byte (architecture/w03-plan-v2/plan.json:287, row :284-292). Its first clause, "Inspection freezes through an ancestor",
is replaced by NP-9 and is not met by the inspector: under Q-HE4-3/4 (a)
(architecture/w03-obligation-amendment-2/amendment.json:18) the observer has no cgroup write grant and freezes nothing,
ancestors included (architecture/native-profile-v4/README.md:284); under Q-NP4D-8 (a) (:282) and Q-NP4D-10 (a)
(:302-303) the frozen state a WORKER capture needs comes from the broker's own write to its probe-worker leaf (NP-9).
Its second clause, "never writes the broker leaf's cgroup.freeze", is structural (:310-311). HE-004D1 discharges the
rest through native-profile v4's inspector obligation (:282-311). This records what those decisions did and narrows
nothing beyond them.

| Decision | Question | Option (a), as in the dossier |
|---|---|---|
| Q-HE4D1-1 | OUT_OF_SCOPE_HOST fields | D1 fills them from the record's declared values, marked R10-side as not observed (MODEL_DEFINED row; HE-008/T04 keep the reads), so captures stay schema-valid |
| Q-HE4D1-2 | The record's source | a new signed-configuration member naming the record file by path and sha256 (the credentials' FileRef pattern, read with `gate_sys::Dir` after the seal) |
| Q-HE4D1-3 | `else` | an observer-side load step that rewrites `if/then/else` into the subset (`allOf` of `if/then` and `anyOf[if, else]`) over the pinned bytes, tested against the 125 best-match cases with B1's localisation rule |
| Q-HE4D1-4 | Home of the raw calls | a new crate (e.g. `observer-sys`): closure +1, a fifth `UNSAFE_FILES` entry, its `FOREIGN_ITEMS`, planeon-gate untouched |
| Q-HE4D1-5 | How the new calls are issued | only through `syscall` with per-target numbers from the v6.12 UAPI (`getdents64`, `bpf`, `ioctl`, `fstatfs`), as `accept4`/`pidfd_open` are |
| Q-HE4D1-6 | Cadence | the first capture set after the first snapshot passes, then one per 60 s cycle after the cycle's scrape |
| Q-HE4D1-7 | Failure semantics | a refused or racing capture (e.g. N95's in-flight spawn) leaves the capture view unavailable in memory and is retried, no exit; setup failures (record file, configuration) exit with new statuses in 25-39 |
| Q-HE4D1-8 | Host policy | an HE-008 share in the next W03 plan amendment (the `/proc` root, cgroup2 and bpffs roots, path directories, `filesystem getattr`, same-domain `/proc`) plus a T04 check, as I05-8 |
| Q-HE4D1-9 | The quiescent freeze | the next W03 plan amendment adds it as an HE-005 obligation and D1 builds the bracket logic tested with fakes |
| Q-HE4D1-10 | Capturer authentication | carried to HE-004-I01 (nothing leaves before it) |
| Q-HE4D1-11 | Replay scope | D1 replays the capture, lifecycle and backend families (199 + 5 capture, 25 + 2 lifecycle, 5 backend) and each positive's 5 + 1 + 8 captures individually; X12-X14 under the v3 schema (registered bytes); X09-X11 from R10-built v3-shaped values; record, qualification and migration cases stay D2's. |
| Q-HE4D1-12 | File hashing inside the 2 s window | SHA-256 of enrolled files once per epoch (fs-verity files cannot change), the verity ioctl inside every inspection window |

Residuals accepted: the OUT_OF_SCOPE_HOST equalities are vacuous on HE-004D1's captures until the host-field drop;
WORKER captures qualify only once HE-005 freezes the leaf (availability, not safety). Hand-offs: HE-008 signs the
configuration member that names the record file (Q-HE4D1-2 (a), "HE-008 signs it" in the dossier's recommendation);
capturer authentication goes to HE-004-I01 (Q-HE4D1-10 (a)). Both are carried for their own rows.

| Obligation | Change | Packets after | Text and shares (ADDED) or the correction |
|---|---|---|---|
| OBS-HOSTPOL-1 | ADDED | HE-008, T04 | The policy observer's host-policy accesses outside matrix v5 and v6, which its native-profile v4 captures need (the observer's analogue of the gate's host policy in I05-8). planeon_observer_t gets exactly: (1) dir getattr, open, read and search on the /proc root, to list it for the host-wide /proc label scan; (2) dir search on the cgroup2 root and on the bpffs root, and on each directory on their paths, to walk to the planeon cgroups and pins; (3) dir search on each directory on the path of every enrolled file it opens and measures, of the seal marker /run/planeon/containment/sealed (/run among them; /run/planeon is the matrix's planeon_run_t), and of the native-profile v4 record file that Q-HE4D1-2 (a)'s configuration member names (the HE-004D1 design confirms where it lives); (4) filesystem getattr, for fstatfs, on the filesystems its captures check: procfs and cgroup2, before their contents are read, the /run tmpfs (runFsType, the seal marker's filesystem), and bpffs only if the HE-004D1 design verifies the pin mount; (5) on its own domain, the /proc access matrix v5's procAccess (unchanged in v6) gives it on other domains (dir, file and lnk_file READ and process getattr), for the P5 planeon_observer_t count. It gets no write on any of these objects. Shares: HE-008: the host policy granting planeon_observer_t these five accesses; the types of these objects (the /proc root; the cgroup2 and bpffs roots and the directories on their paths; the directories outside the matrix on the paths of the enrolled files, the seal marker and the record file, /run's among them; the filesystems in (4); the observer's own /proc entries) are host policy outside matrix v5 and v6; T04: checks on the enrolled host, per (type, class), that the installed policy grants planeon_observer_t exactly these: on the /proc root's type, class dir: getattr, open, read and search; on the types outside the matrix of the directories walked in (2) and (3), /run's among them, class dir: search; on the types of the filesystems in (4), class filesystem: getattr; on planeon_observer_t, classes dir, file and lnk_file: matrix v5's READ group, and class process: getattr present. No write on any of these pairs. Outside the check: the observer's other classes on its own type (its sockets, capability and process self rules) and all of HI-7's OBSERVER self permissions (its seal's process permissions and its own /proc/self/status reads, read on the /proc/self link included, a lnk_file of the /proc root's type) (architecture/w03-obligation-amendment-2/amendment.json:221; architecture/compiled-filter-programs/status.json:144) |
| NP-9 | ADDED | HE-005, HE-004D1, T04 | The broker freezes the probe-worker leaf at quiescent points of the worker's run and thaws it after, so that the policy observer can take a WORKER capture inside a frozen bracket: cgroup.events shows frozen 1 before and after the observer's reads, and the (pid, start) member sets and (tid, start) thread sets are equal before and after. The observer itself never freezes and never writes any cgroup.freeze (NP-3). Until the broker freezes the leaf, no WORKER capture qualifies; the residual is availability, not safety. Shares: HE-005: the quiescent-point freeze and thaw of the probe-worker leaf, through its cgroup.freeze write grant on its delegated leaves (architecture/selinux-matrix-v3/README.md:219; unchanged in matrix v6, architecture/selinux-matrix-v4/README.md:632), beside the freezes of W1-W4 and W6 (architecture/host-interface-amendment-hs43/HOST_INTERFACE_SPEC.md:462-477, :482-486). A quiescent freeze is taken only on a leaf that W1-W4 or W6 does not already hold frozen; its thaw never thaws a leaf that W1-W4 or W6 holds frozen; an expiry or invalidation inside a quiescent bracket proceeds to W6 without thawing. The points' definition, frequency and duration are HE-005's design (Q-A3-4 (a)).; HE-004D1: the frozen-bracket logic, built and tested against fakes: a WORKER capture is attempted only when cgroup.events shows frozen 1, qualifies only inside the bracket, and is otherwise refused and retried without exit; T04: proves on the enrolled host that the broker's quiescent freeze reaches frozen 1 on the probe-worker leaf, that the observer's WORKER capture is taken inside the bracket, that a quiescent thaw never thaws a leaf W1-W4 or W6 holds frozen, and that the observer writes no cgroup.freeze |
| SEC-4 | SHARE_CORRECTED | HE-002S, HE-003, HE-004A, HE-005, HE-006, HE-007, HE-008, T04 | HE-003's share, `architecture/w03-obligation-amendment-1/amendment.json:56`: "derives kept from it (CAP_NET_BIND_SERVICE exactly when the signed I04 port is below 1024, else nothing) and passes it to stage 2 (a second single-thread check, the drop to {kept}, then the filter)" becomes "refuses a signed I04 port below 1024, so kept is always empty, and calls stage 2, which takes no kept capability (a second single-thread check, the drop to the empty set, then the filter)" |
| HI-7 | SHARE_CORRECTED | HE-002S, HE-003, HE-004A, HE-005, HE-006, HE-007, HE-008, T04 | HE-003's share, `architecture/w03-obligation-amendment-1/amendment.json:78`: "derives kept from it (CAP_NET_BIND_SERVICE exactly when the signed I04 port is below 1024, else nothing) and passes it to stage 2 (a second single-thread check, the drop to {kept}, then the filter)" becomes "refuses a signed I04 port below 1024, so kept is always empty, and calls stage 2, which takes no kept capability (a second single-thread check, the drop to the empty set, then the filter)" |

Amendment 1's other lines on the gate's capabilities stay as they are, because they are still true: stage 1's "down to
at most {CAP_SETPCAP, CAP_NET_BIND_SERVICE}" is an upper bound, and every start that HE-008's HI-7 share admits is one
the seal accepts with kept empty; Q-HE3-3 named only the kept wording (monitor Q-A3-1 (a)).

**Carried** (`carried`, to later amendments):
- Native-profile v4's other W03 items without a register row: the low-port server stays dumpable; /proc carries no hidepid restriction (I05-8's HE-008 share already fixes hidepid=0 on the procfs mount, which covers part of it); private interpreter copies in the dedicated type: to a later W03 plan amendment (monitor decision Q-A3-7 (a)).
- HE-008's hand-off from Q-HE4D1-2 (a) (`packetScopes[0].handOffs[0]`): to a later W03 plan amendment (an HE-008 row) (monitor decision Q-A3-7 (a)).
- HE-004-I01's hand-off from Q-HE4D1-10 (a), capturer authentication (`packetScopes[0].handOffs[1]`), which I01-1 does not name: to a later W03 plan amendment (an HE-004-I01 row) (monitor decision Q-A3-7 (a)).
- The I06 successor packet that names the observer's grants, added to OBS-RBAC-1 by PACKETS_ADDED (amendment 2's carried C3-2, architecture/w03-obligation-amendment-2/status.json:104-108): to the amendment in which that packet has an id (monitor decision Q-A3-6 (a)).

**Change kinds** (closed, `changeKinds`): amendment 2's ADDED, REFINED and PACKETS_ADDED, unchanged, and one new kind,
SHARE_CORRECTED: one packet's share from an earlier amendment is corrected as a quoted owner decision directs, quoting
the replaced words byte for byte with the words that replace them and the whole corrected share; the obligation's text
and packet list stay as they are. It is the only kind that may narrow a share, and only as far as its decision does
(`shareRule`, `correctionRule`). Amendment 1's NARROWED kind (I07-4) records an obligation's narrowed ownership, with no
byte-quoted replacement of a share, so it does not fit this correction. This amendment uses ADDED and SHARE_CORRECTED
only. A packet scope (`packetScopeRule`) adds to a part's amendment 2 summary and shares and never narrows them.

New obligation ids: OBS-HOSTPOL-1 joins amendment 2's observer family (OBS-RBAC-1, OBS-INV-1); NP-9 continues plan v2's
native-profile family (NP-1..NP-8) beside NP-3, whose first clause it replaces.

Every other obligation, packet and toolchain of plan v2, every amendment 1 change except the corrected HE-003 share, and
every amendment 2 change is unchanged.
