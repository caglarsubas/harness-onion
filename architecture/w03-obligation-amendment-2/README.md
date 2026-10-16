# W03 obligation-register amendment 2 (W03-PLAN-AMEND-2, slot 244)

Alpha 2A; 2026-10-16. Status: **CONTRACT_CANDIDATE_AWAITING_INDEPENDENT_REVIEW**. The W03 plan v2
(`architecture/w03-plan-v2/plan.json`, MET-ENFORCE-024) and amendment 1 (`architecture/w03-obligation-amendment-1/`,
MET-ENFORCE-025) stay byte-identical; `amendment.json` binds both by SHA-256 and applies after amendment 1. The operator
edge record v4 (`architecture/artifact-edges/operator-harness-engineering-v4.json`) is published beside it.

**Why.** The policy observer, plan v2's HE-004, was split by the monitor's owner-delegated decision Q-HE4-2 (a) into a
substrate, the I06/ADM-4 data logic, the apiserver client and the captures; the I06 evidence composition (I06-2) moved to HE-004D2, after the
native-profile and I06 successors (Q-HE4B-11 (b)); I01 became a plan obligation (Q-HE4-1 (a)); the owner chose a T04 audit trace as the route for the observer's
wrapper evidence; and R10's adoption of the I05 gate channel v4 (MET-ENFORCE-030), HE-003A3, gains its obligations (I05-7,
I05-8). All decisions are quoted verbatim in `amendment.json` (`ownerDecisions`).

**Packet refinements.** HE-004 is refined into HE-004A, HE-004B1, HE-004C, HE-004D1, HE-004D2; the new packets are HE-004-I01, HE-003A3. At authoring time HE-004A has merged in R10
(main `dcaf26f`); `amendment.json` itself states no status.

| Obligation | Change | Packets after | Text (ADDED) or shares |
|---|---|---|---|
| I01-1 | ADDED | HE-004-I01 | The R10 policy observer serves I01 to the protected server as the corrected spec defines it (AF_UNIX SOCK_SEQPACKET at /run/planeon/live-proxy/policy-observer.sock; only OBSERVE_POLICY; the exact current request/response schema), after an OBSERVER seccomp successor gives it the listener (bind, listen, accept4), the republished OBSERVER programs and an edge record registering them. |
| I06-2 | REFINED | HE-004D2 | HE-004D2: the composition, check_qualification and the acceptance token bound to the record digest; the production path returns UNAVAILABLE without reaching the fixture path until W02-PROD |
| I06-3 | REFINED | HE-004B1 | HE-004B1: the producer refuses a non-resource-URL rule in a role bound directly to {User, system:apiserver}; OR03 and dangling role references refuse; other subjects' non-resource rules are dropped and counted; groups are not expanded |
| ADM-4 | REFINED | HE-004B1, HE-004C | HE-004B1: the comparison and the pre-ACTIVE record: metric name, plugin, apiserver_id_hash, Kubernetes version, observation binding (record digest or nonce, plus window), pinned and loaded hash, verdict; UNAVAILABLE unless the version is v1.37.1 and exactly one sample comes from the expected plugin; HE-004C: the metric samples it parses and the pinned hash from the observer's signed configuration |
| ADM-4 | PACKETS_ADDED | HE-004B1, HE-004C, HE-008 | HE-008: binds the pre-ACTIVE record by digest into the off-host enrollment, so no ACTIVE configuration is signed without it, and checks its observation binding against the enrollment and the window's freshness; the ALPHA metric is accepted for v1.37.1, as a residual re-checked at every Kubernetes upgrade |
| NP-3 | REFINED | HE-004D1 | HE-004D1: after native-profile v4, with no cgroup write grant for the observer |
| SEC-4 | REFINED | HE-002S, HE-003, HE-004A, HE-005, HE-006, HE-007, HE-008 | HE-004A: the OBSERVER call site and seal; HE-008: for OBSERVER: the unit uses no systemd seccomp option and starts the observer in a start state the seal accepts (bounding set already {CAP_NET_ADMIN, CAP_BPF}), so that the seal installs exactly the published OBSERVER program |
| HI-7 | REFINED | HE-002S, HE-003, HE-004A, HE-005, HE-006, HE-007, HE-008 | HE-004A: the OBSERVER seal's start and end state; HE-008: for OBSERVER: uid 0 and gid 0; the final bounding set {CAP_NET_ADMIN, CAP_BPF} at start (matrix v5 grants planeon_observer_t no setpcap); no AmbientCapabilities=; RUST_BACKTRACE unset; fds 0-2 open; the observer stays dumpable, and core_pattern is not a pipe or its helper honours RLIMIT_CORE 0; planeon_observer_t's self permissions the seal needs (process setcap, getcap and setrlimit; its own /proc/self/status reads), with no process setrlimit or getrlimit on other domains (prlimit64 is unconditional in the OBSERVER row); no Restart= before HE-004B1 and HE-004C have merged |
| SEC-4 | PACKETS_ADDED | HE-002S, HE-003, HE-004A, HE-005, HE-006, HE-007, HE-008, T04 | T04: for OBSERVER, the installed-filter proof: the installed filter equals the OBSERVER program digest, Seccomp_filters: 1, and the post-seal exit path traced |
| HI-7 | PACKETS_ADDED | HE-002S, HE-003, HE-004A, HE-005, HE-006, HE-007, HE-008, T04 | T04: for OBSERVER: PR_CAPBSET_READ(41) returns EINVAL on the target kernel (the CAP_LAST_CAP check), TSYNC, and dumpability at exec |
| OBS-RBAC-1 | ADDED | HE-004C, HE-008 | The policy observer's Kubernetes read grants are exactly those HE-004C's requests need: HE-004B1's request specs, API discovery, nonResourceURL /metrics (ADM-4) and /readyz (OR07). The I06 identity closure gives planeon:policy-observer allowedGrants: [], so the grants need an I06 successor that names them before they are provisioned; HE-004C uses them and fails closed when a read is refused; HE-008 provisions them. |
| OBS-INV-1 | ADDED | HE-008, T04 | planeon-observer: zero seccomp-kill audit records (audit type 1326) over a T04 workload that exercises every observer entry point, with a coverage report listing the entry points exercised; runtime evidence at T04 (Linux, HE-008 era). No agent builds a wrapper classifier, table or inventory, by any route, now or at T04. |
| I05-7 | ADDED | HE-003A3, T04 | At every BIND that has passed every v3 check, the gate observes the BIND's worker in I05 v4's five steps (cgroup.procs lists it; pidfd_open; the stat start time equals the BIND's; cgroup.procs again; the pidfd still alive); every failure is the existing non-fatal, retryable WORKER_NOT_OBSERVED with nothing durable written; the static observedWorkers source and R10's empty-list rule are removed. |
| I05-8 | ADDED | HE-003A3, HE-005, HE-008, T04 | I05 v4's host preconditions: the probe-worker leaf stays a domain cgroup with no threaded descendants; the gate, the broker and the worker share one pid namespace and one time namespace, or at least one boottime offset; the gate's /proc directory fd is that namespace's procfs, mounted with hidepid=0, and the gate is not in the mount's gid= group; the gate obtains its cgroup2-root and /proc directory fds at start, and has dir search on the cgroup2 root, whose own type is host policy outside matrix v5. |

**Change kinds** (closed, `changeKinds`): ADDED — a new obligation with its text, source, packets and scope, and optional
shares; REFINED — plan v2's packet in an obligation's list is replaced by its named parts, the text byte-identical to plan
v2's, with shares for the parts or any other listed packet; PACKETS_ADDED — packets added with their shares, as in
amendment 1. A share adds to the named packet's part of the obligation and never narrows it; a later share for the same
packet adds to its earlier shares (`shareRule`). Every obligation that lists HE-004 after amendment 1 has exactly one
REFINED row, its first row here; the parts named across the REFINED rows are exactly HE-004's parts; no row keeps HE-004
(`refinementRule`). `dependencyNames` maps the names of successors that are not plan v2 packets.

Every other obligation, packet and toolchain of plan v2 and every amendment 1 change is unchanged.
