# W01 host interfaces — gate resolutions, candidate v2 with amendments W02D, HS43 and HS53

Effective text of `HOST-INTERFACE-DRAFT-002` with amendment W02D (`HOST-INTERFACE-DRAFT-002-W02D`, section 11) applied.
The reviewed v2 file (`architecture/host-interface-inputs/resolved/HOST_INTERFACE_SPEC.md`) stays byte-identical;
`architecture/host-interface-amendment-w02d/amendment.json` lists every change.
Amendment HS43 (`HOST-INTERFACE-DRAFT-002-HS43`, section 12) is applied on top of that effective text, which also
stays byte-identical (`architecture/host-interface-amendment-w02d/HOST_INTERFACE_SPEC.md`);
`architecture/host-interface-amendment-hs43/amendment.json` lists its changes.
Amendment HS53 (`HOST-INTERFACE-DRAFT-002-HS53`, section 13) is applied on top of the HS43 effective text,
which also stays byte-identical (`architecture/host-interface-amendment-hs43/HOST_INTERFACE_SPEC.md`);
`architecture/host-interface-amendment-hs53/amendment.json` lists its changes.

Design label `HOST-INTERFACE-DRAFT-002`; owner R00 coordinating R10/R12.
Base: the independently reviewed corrected candidate `HOST-INTERFACE-DRAFT-001`
(`architecture/host-interface-inputs/corrected/HOST_INTERFACE_SPEC.md`, SHA256
`1b0bee7e46e3cd730b3f878179ac36d0f062ce70ed6c843788ab634aead16ef0`, verdict
PASS_FOR_SOURCE_PUBLICATION with G04-G07 and G09 open). That file stays byte-identical.
This document resolves G04, G05, G06, G07 and G09 at design level. Everything in
the base that is not amended here stays in force, including its §1 boundary, §5
generation states, §8 reuse policy and §9 delivery order.

This is a specification, not an installed gate, adopted wire ABI, native result or
proof of any enforcement obligation. All E01-E12 remain OPEN_UNPROVEN. T01-T08 are
still unexecuted specifications. W02-W07 remain work labels until their own packets.

## 0. Disposition vocabulary

- **RESOLVED_DESIGN**: a concrete mechanism is selected; every property that only an
  installed host can show is named as a residual native or source evidence item.
  A RESOLVED_DESIGN gate no longer blocks W02 design work. It closes no E row,
  grants no installation, and makes no capability available.
- **UNRESOLVABLE_WITHOUT_NATIVE_EVIDENCE**: no design-level mechanism can settle the
  question. None of the five gates uses this disposition; the residual items in
  §8 are the parts that do need native evidence.

Kernel facts below cite Linux v6.12 source (the version the native profile already
references). They are reading notes for reviewers, not observations of a host.

## 1. Owner decisions (2026-10-05, authoring session)

| ID | Gate | Selected option |
|---|---|---|
| D1 | G04 | Dedicated sealed single-node qualification control plane on the enrolled Linux host. The effect gate is the only API path outside the control plane. Resource-bearing live qualification is UNAVAILABLE on tenant-managed clusters. |
| D2 | G05 | Versioned amendment of the accepted "before committing a mutation" wording into three named checks plus a drain fence (§3). |
| D3 | G07 | Reboot-only host maintenance. Host controls are locked until reboot; a reboot ends the generation. Kubernetes policy writes still go through the gate without a reboot. |
| D4 | G09 | Transport restriction ("connection stamping") on unchanged I04; mutations are also unique by construction. |

The owner chose among options the author offered; the choice is not a review.

## 2. G04 — concrete policy backend (I06) and complete writer mediation

### 2.1 Selected backend profile: `SEALED_SINGLE_NODE_CONTROL_PLANE_V1`

I06 is no longer an abstract interface. It is one Kubernetes control plane that
runs only on the enrolled qualification host, belongs to the external operator and
serves only qualification. No Kubernetes distribution, version or artifact is
selected here; W02 lists the selection criteria and W03 selects under license and
offline closure. Whatever is selected must meet all of P1-P10:

- P1 **Single node, local storage.** The datastore listens only on an AF_UNIX
  socket whose SELinux type allows `connectto` from the apiserver domain alone. No
  TCP datastore client or peer port, and no remote replica.
- P2 **Loopback apiserver, labelled port.** The apiserver secure port binds only
  to a loopback address. That port has a dedicated SELinux port type
  (`planeon_kubeapi_port_t`). `name_connect` to it is allowed for exactly: the effect
  gate, the policy observer and the enumerated control-plane components (§2.3).
  No other domain, including the root login domain, may connect.
- P3 **No authorization bypass reachable.** Anonymous authentication off; no static
  token file; authorization is Node+RBAC from a sealed structured configuration.
  The apiserver reloads that configuration automatically when the file changes
  (Kubernetes authorization documentation), so the file must be sealed (§5.5).
  No credential for `system:masters` or any group bound to `cluster-admin` is
  present on the host during INSPECTING/ACTIVE. Because of P2, even a stray copy
  cannot reach the apiserver from an unlisted domain.
- P4 **No credential minting.** The cluster CA private key is absent from the host
  during INSPECTING/ACTIVE. CSR signing and approving controllers are disabled.
  Kubelet client-certificate rotation is off; certificates are issued only during
  reboot maintenance (§5.5) with an off-host CA. The service-account token signing
  key is readable only by the apiserver and controller-manager domains. The
  `serviceaccounts/token` create permission is in the closure table (§2.3).
- P5 **Sealed control-plane configuration.** Apiserver flags/config, admission
  configuration, authorization configuration, encryption configuration, static
  component definitions, kubelet configuration and any auto-apply manifest
  directory are files with sealed SELinux types (§5.5). No domain can write them
  outside reboot maintenance. Auto-apply directories are empty and sealed.
- P6 **Closed admission chain.** Only an enumerated built-in admission plugin set
  is enabled. ValidatingWebhookConfiguration, MutatingWebhookConfiguration and
  mutating admission policy objects must be absent. ValidatingAdmissionPolicy
  objects and bindings are policy kinds written only through I07 (§2.4).
- P7 **No aggregation or extension path.** APIService objects other than the
  built-in local ones, CustomResourceDefinitions and webhook-backed conversion are
  absent. All are policy kinds, so creating one needs the I07 writer.
- P8 **Closed in-cluster clients.** Qualification Pods mount no service-account
  token (existing profile rule). Every non-Pod API client is enumerated in §2.3.
  The service proxy and network-policy agent, if the selected distribution needs
  them, run as enrolled host components with their own identities.
- P9 **Fixed container runtime access.** The container runtime's control socket
  allows `connectto` only from the kubelet domain. No CLI client domain can
  reach it, so no one can exec into or start privileged containers around the API.
- P10 **Zero-resource uniformity.** Zero-resource executions still need the same
  observer view of this backend. A missing or unqualified I06 backend makes the
  live capability unavailable in both modes (unchanged base rule).

For tenant-managed clusters the resource-bearing live qualification capability is
reported **UNAVAILABLE**. This is a qualification-profile limit, not a claim that
unrelated harnesses are air-gap incompatible. Tenants do not hand over
control-plane ownership: the sealed cluster belongs to the operator's qualification
host.

### 2.2 API-path closure

Every way to change an I06 policy fact maps to exactly one of these:

| Path | Disposition |
|---|---|
| Kubernetes API over the loopback port | Only domains allowed by P2. Effect actions go through the gate's effect identity; policy writes through the gate's writer identity (I07); observer reads with a read-only identity; control-plane components use their own identities (§2.3) |
| Datastore | AF_UNIX `connectto` for the apiserver domain only (P1); data directory writable only by the datastore domain; restore or replace only in reboot maintenance |
| Alternate API servers / aggregation | Absent (P7); creating one is a policy write through I07 |
| Container runtime | Kubelet only (P9) |
| Control-plane configuration files | Sealed (P5, §5.5) |
| Host network to the apiserver from other nodes | Loopback-only bind, single node (P1/P2) |

### 2.3 Identity and permission closure

Only these identities can reach the apiserver. For each, the effective
permission to create, update, patch or delete a **policy kind** is listed.
Policy kinds are: Namespace, ResourceQuota, LimitRange, ServiceAccount, Role,
RoleBinding, ClusterRole, ClusterRoleBinding, NetworkPolicy,
ValidatingAdmissionPolicy(Binding), Validating/MutatingWebhookConfiguration,
APIService, CustomResourceDefinition, CertificateSigningRequest approval, plus the
`impersonate`, `escalate`, `bind` and `serviceaccounts/token` create verbs.

| Identity | Domain | Policy-kind write permission | Notes |
|---|---|---|---|
| Gate effect identity | effect gate | None | Namespace-scoped create/get/delete of the signed Pod/ConfigMap/Service kinds only |
| Gate writer identity | effect gate (used only for I07) | Exactly the policy kinds above, scoped to the qualification namespace plus the named cluster-scoped objects | Used only while the generation is CLOSED for maintenance (§2.4) |
| Observer read identity | policy observer | None | get/list/watch on policy kinds and the namespace |
| Kubelet node identity | kubelet | None | Node authorizer + NodeRestriction; no static Pod definitions in the qualification namespace |
| Controller-manager per-controller identities | controller-manager | See §2.5; every controller with policy-kind writes is disabled or profile-excluded | Per-controller credentials required, so each controller's grants are distinct |
| Scheduler | scheduler | None | — |
| Service proxy / network-policy agent (if present) | enrolled host component | None | Read and status-only grants; distribution-specific custom resources enumerated in W02 |

The observer verifies this table from actual RBAC objects in every observation
(complete effective RBAC, as POLICY_OBSERVATION_READINESS already requires). A
subject not in the table that holds any policy-kind write permission, or any
`impersonate`/`escalate`/`bind` grant, makes the generation unavailable.

### 2.4 I07: policy writer to effect gate (new private interface)

Candidate path `/run/planeon/maintenance/policy-write.sock`, AF_UNIX/SOCK_SEQPACKET,
root:root 0600, with a socket type allowing `connectto` only from the policy-writer
domain. Same frame rules as I05 (canonical JSON, exact builtins, no floats, depth
<=16, <=16 KiB, sequence/hash chain). Exact schema is W02 work. Operations:

| Operation | Meaning |
|---|---|
| WRITE_BEGIN | Writer asks for maintenance. The gate runs CLOSE_GENERATION(normal drain) and replies only after the A3 drain fence (§3.2) holds. If any action is IO_AMBIGUOUS the reply is HELD and no write is possible |
| WRITE_OBJECT | One create/update/delete of one policy kind, with the expected prior projection digest. The gate forwards it with the writer identity and records the result durably. Non-policy kinds and every effect kind are refused |
| WRITE_END | Closes maintenance. The gate stays CLOSED. A new generation needs fresh observation and enrollment (base §5); the old generation never resumes |

The writer executable is a fixed enrolled artifact (§4). It never holds an
apiserver credential and cannot reach the apiserver port (P2). Operators run it
whenever they want; the only thing they can do during ACTIVE is ask for a normal
drain.

### 2.5 Control-plane autonomous writers

These are not "authorized writers" that a lock can exclude. Each has a disposition:

| Controller / component | Effect on policy facts | Disposition |
|---|---|---|
| ClusterRole aggregation | Rewrites rules of aggregated ClusterRoles | Profile rule: the effective RBAC closure of the qualification namespace contains no ClusterRole with an aggregationRule; observer refuses otherwise |
| ServiceAccount / token controllers | Recreate a deleted default ServiceAccount | Deletion is only possible through I07; the pinned ServiceAccount UID detects recreation |
| Namespace lifecycle | Deletes namespace contents on namespace deletion | Namespace deletion is only possible through I07 |
| ResourceQuota controller | Updates `status.used` | Usage, not policy. Quota admission is re-evaluated in the apiserver at persist time (§3.2); observer still checks headroom |
| Root-CA ConfigMap publisher | Keeps one ConfigMap per namespace | Counted in observed usage; content change requires CA rotation, which is reboot maintenance |
| CSR signing / approving | Could mint credentials | Disabled (P4) |
| Garbage collector, EndpointSlice and other workload controllers | Act on objects the gate admitted | Not policy kinds; their effects are bounded by admitted objects and existing cleanup rules |

Anything the selected distribution adds (for example an embedded network-policy
agent or a manifest-apply controller) must be listed here in W02, or it is disabled.

### 2.6 Writer-family coverage (amends base §7 dispositions)

| Writer family | Mechanism |
|---|---|
| Host files / credentials / trust | fs-verity on code; sealed SELinux types writable only by the maintenance domain, which has no runtime entry (§5.5) |
| Host policy and namespaces | `secure_mode_policyload` locks policy load, booleans and enforcing mode until reboot; namespace and mount changes denied to non-maintenance domains (§5.3) |
| Cgroups / BPF / process execution | BPF load and attach only in the one-shot containment domain; sealed systemd units with SELinux `service` permissions denied to login domains; `kernel.modules_disabled=1`; `lockdown=integrity` on the enrolled boot entry; Yama `ptrace_scope=3` (§5) |
| RBAC and identity | §2.3 closure plus I07 as the only writer |
| Namespace / quota / admission | I07 only; closed admission chain (P6) |
| Network and API path | P1/P2/P7/P9; loopback-only; reboot maintenance for configuration |
| Autonomous events | Base §5 deny-first handling plus §2.5 |

Every listed mechanism is a design selection. That it is complete on a real host
is E03, E04, E05 and E10 evidence, still OPEN_UNPROVEN (§8).

## 3. G05 — admission versus storage commit (versioned amendment)

### 3.1 Accepted wording and why it needs a version

POLICY_OBSERVATION_READINESS.md currently says: "Before committing a mutation, its
immutable admission guard rechecks current namespace/UID, effective RBAC, quotas,
network policy and actual post-mutation manifest under the broker's serialized
admission transaction." A gate outside the apiserver cannot make an upstream
storage commit atomic with unrelated policy changes. That sentence cannot be met
literally by any boundary this design has, and must not be met by pretending a
gate acknowledgement is a commit.

### 3.2 Amended semantics `POLICY-ADMISSION-SEMANTICS/v2` (decision D2)

"Before committing a mutation" becomes three named checks at named positions:

- **A1 Gate admission (pre-forward linearization point).** Under the gate's single
  generation lock: verify current generation ACTIVE, scope, deadline, observed
  policy generation and the stamped armed action (§6). Then consume that action
  exactly once, fsync and read back the durable record, then send the first byte
  upstream. Nothing earlier is the admission event: not socket accept, TLS,
  ARM_ACTION acknowledgement or a worker report (unchanged base rule).
- **A2 In-chain persist check (pre-persist).** Inside the sealed apiserver, after
  mutating admission and before persistence, a ValidatingAdmissionPolicy (in-process,
  failurePolicy Fail; stable since Kubernetes v1.30) checks the final object against
  the signed manifest. Allowed differences are an enumerated per-kind
  server-populated/defaulted field set fixed in W02. The built-in quota and
  LimitRange admission plugins re-evaluate usage in the same chain. Kubernetes
  runs mutating admission before validating admission (admission-controller
  documentation), so A2 sees the post-defaulting object. A2 replaces "actual
  post-mutation manifest" in the old sentence. Its policy objects are policy kinds
  (written only through I07) and are pinned by the existing admissionPolicy and
  mutationBroker digests.
- **A3 Drain fence for policy writers.** No I07 WRITE_OBJECT, and no other writer in
  §2, commits while any action admitted under the current generation lacks a
  durable terminal classification (DELIVERED_RESULT or NOT_FORWARDED). An
  IO_AMBIGUOUS action holds the generation HELD. A normal write then cannot
  proceed until independently authorized reconciliation classifies it.

Resulting guarantee for normal operation: if a mutation reached DELIVERED_RESULT,
no mediated policy write was committed between its A1 event and its upstream
response. The synchronous create/delete response comes after the apiserver's
persist step, so the object was persisted under the policy that A1 checked.
A Pod DELETE response starts graceful termination; absence is still confirmed by
the existing exact-UID cleanup observation, not by the response.

**A4 Urgent invalidation (explicitly weaker, recorded).** Revocation, peer death,
storage failure or observation loss closes A1 immediately and does not wait for
A3. An action already admitted may still be persisted after the invalidating
change. It is recorded ADMITTED_BEFORE_INVALIDATION with its terminal or ambiguous
outcome. It is never relabelled unadmitted, never retried, and its resources stay
owned for exact-UID cleanup. The old strict wording was not achievable in this
case; this amendment says so instead of implying it.

The accepted document's bytes are not changed by this candidate. W02 carries the
amended v2 text into the owning contract with old/new vectors. A consumer reading
the v1 sentence must not cite this candidate as having met it.

### 3.3 What G05 does not claim

No end-to-end distributed transaction, no proof that the apiserver persisted
before a lost response (that is IO_AMBIGUOUS), and no ordering guarantee for
controller side effects outside §2.5. The drain fence relies on the gate being
the only writer path, which is G04 evidence.

## 4. G06 — versioned native role and manifest enrollment

### 4.1 Record and profile versions

- New record `planeon.internal.native-qualification/v2`, profile
  `SELINUX_FSVERITY_CGROUP_BPF_V2`. v1 (`.../v1`, `SELINUX_FSVERITY_CGROUP_BPF_V1`)
  is unchanged.
- **Resident roles (closed set):** SERVER, OBSERVER, BROKER, WORKER, EFFECT_GATE.
  All five are required in every v2 record. In a zero-resource execution the gate
  is present and denies every action, so the parser has no mode-dependent branch.
- **Lifecycle subjects (closed set):** HOST_CONTAINMENT and POLICY_WRITER. They
  are recorded with artifact digest, SELinux domain and entry rule, but are not
  resident roles. HOST_CONTAINMENT must have no process during INSPECTING/ACTIVE
  (§5.2). POLICY_WRITER may run but can only request a normal drain through I07.
- **Backend components:** a closed `backendComponents` object whose keys are fixed
  by the selected I06 implementation profile version (§2.3 identities), each with
  artifact digest, SELinux domain, cgroup and API identity. Unknown or missing
  keys refuse.

### 4.2 Paths and manifests (candidates; exact values are W02 data)

- Cgroups under one systemd slice: `/sys/fs/cgroup/planeon.slice/` with one
  service per resident daemon role (`planeon-proxy-server.service`,
  `planeon-policy-observer.service`, `planeon-effect-gate.service`) and
  `planeon-capacity-broker.service`. Only the broker's service has `Delegate=yes`.
  It exclusively owns two leaves, `broker` and `probe-worker`, so it satisfies
  the no-internal-process rule. This refines MET-ENFORCE-001 decision 2 (one
  owned subtree) from a single service to a single slice; reviewers should check
  that refinement explicitly.
- Gate artifact `/opt/planeon/bin/harness-effect-gate` root:root 0555; manifest
  `/etc/planeon/harness-effect-gate-manifest.json` and `.json.sig`. It uses the
  existing closed root-manifest shape and detached Ed25519 under the existing
  pinned root public key. No new root key or signing role. The same applies to
  `/opt/planeon/bin/harness-policy-write` and
  `/opt/planeon/bin/harness-host-containment`.
- The gate's TLS listener identity is the existing signed KUBERNETES_API_PROXY
  endpoint identity. The server still pins the endpoint SPKI and keeps its own
  KUBERNETES_PROXY_SERVER_MTLS credential (base §2).

### 4.3 Who qualifies whom

- BROKER qualifies EFFECT_GATE as a peer (artifact, label, cgroup, pidfd/start, SO_PEERCRED) before BIND_EXECUTION.
  Its artifact check reads the gate's `/proc/<pid>/exe` link, which the kernel allows as long as the gate holds no
  capability (the signed I04 port is 1024 or above, Q-HE2S-9 (a)), stays dumpable (Q-HE2S-7 (a)) and runs with uids
  and gids 0 that equal the broker's filesystem uid and gid (O-W03-PEER-EXE).
- A peer's start time is compared on every frame with a reference taken without a race at its first frame: the
  qualifier holds a pidfd that names the connected process itself (SO_PEERPIDFD, or SCM_PIDFD on a frame), reads
  `/proc/<pid>/stat`, and then confirms through that pidfd (poll) that the process has not exited, so the entry was
  that process's. A pidfd_open of the SO_PEERCRED pid alone does not give such a reference, because that pid may
  already name a later process (HS43).
- EFFECT_GATE qualifies the broker on every I05 frame by label, cgroup, pidfd/start and SO_PEERCRED (HS43). It does
  not check the broker's artifact. Reading `/proc/<pid>/exe` is a ptrace-mode read (PTRACE_MODE_READ_FSCREDS);
  without CAP_SYS_PTRACE, which no role holds, the kernel allows it only if the target's permitted capabilities are a
  subset of the reader's effective ones, and the broker's (§5.3) are not a subset of the gate's, so the kernel
  refuses the gate that read. The broker's executable identity follows from its label instead: SELinux matrix v4
  (`architecture/selinux-matrix-v2/`) lets `planeon_broker_t` be entered only from init through
  `planeon_broker_exec_t` and denies `execute_no_trans` on every type, so the label identifies the executable as long
  as only the enrolled broker artifact carries that type.
- EFFECT_GATE qualifies the writer on every I07 frame by artifact, label, cgroup, pidfd/start and SO_PEERCRED (HS43).
  For the artifact it opens the `/proc/<pid>` directory of the pidfd's process and confirms through the pidfd that
  the process is still alive after the open, so no PID reuse can intervene, then reads its `exe` link with
  `readlinkat` on that directory descriptor (§5.3) into a buffer longer than the enrolled writer path (§4.2); the
  link must equal that path exactly, with no " (deleted)" suffix. The fs-verity digest is enforced on the sealed file
  the path names (§4.2, at enrollment); the gate does not re-measure it per frame, which would need
  FS_IOC_MEASURE_VERITY, an ioctl its allowlist does not admit. The kernel allows the read without CAP_SYS_PTRACE
  only while the gate's filesystem uid and gid equal the writer's real, effective and saved uids and gids (all 0),
  the writer is dumpable, and the writer's permitted capabilities are a subset of the gate's effective ones, which
  the writer's empty set (§5.3) always is; SELinux matrix v4 gives `planeon_gate_t` `file read` on
  `planeon_policy_writer_t` (`procAccess`), the LSM check of that read. Yama (ptrace_scope 3) limits only ptrace
  attach, not this read, and /proc must be mounted with hidepid=0 (the default), or the gate loses sight of its
  peers' entries. Obligation O-W03-WRITER-EXE holds both sides to this. Until the gate's filter admits `readlinkat`
  (O-SECCOMP-V3-READLINKAT), the writer's artifact check is decided but open (Q-HE3A-1b) and the other four checks
  apply.
- SERVER and OBSERVER do not talk to the gate except SERVER over I04 TLS. Their v1
  peer duties are unchanged.
- I01's producer is R10's HE-004-I01: obligation I01-1 of W03-PLAN-AMEND-2 (MET-ENFORCE-032, harness-onion main
  c69e55f; owner decision Q-HE4-1 (a)), which supersedes for I01 the earlier statements that the producer is a
  pre-existing, independently installed operator prerequisite (§13). The observer listens on I01 (§5.3, HS53); both
  ends keep the v1 peer duties, the server's checks of the observer and the observer's of the server
  (`docs/alpha-2/POLICY_OBSERVATION_READINESS.md`), unchanged. HE-004-I01's design decides whether the race-free
  start-time reference above also applies to I01, and records the choice; it re-vendors the republished OBSERVER
  programs (O-PROGRAMS-V3-OBSERVER) and serves I01 (Q-SOL-4 (a), O-R10-HE004-I01).
- The gate's generation must equal the observer/broker generation carried in
  DISPATCH and BIND_EXECUTION; mismatch denies.

### 4.4 Rejection vectors (T08 additions)

v1 reader given a v2 record refuses. v2 reader given a v1 record refuses (no
fallback). A v2 record that is missing EFFECT_GATE, has an extra role, puts the
gate under the BROKER key or path, aliases a role path, or has a lifecycle subject
running inside a resident role cgroup refuses. A record with unknown
backendComponents keys refuses. Migration never reinterprets accepted v1 data and
never reuses a v1 generation or nonce.

## 5. G07 — syscall, capability, MAC, seal and original-parent lifecycle

### 5.1 Finding against the v1 inspection command set

The v1 readers use BPF_PROG_QUERY(16), BPF_PROG_GET_FD_BY_ID(13) and
BPF_OBJ_GET_INFO_BY_FD(15) and must not obtain CAP_SYS_ADMIN. In Linux v6.12
`kernel/bpf/syscall.c`:

- `bpf_prog_get_fd_by_id` requires `capable(CAP_SYS_ADMIN)`.
- `bpf_prog_query` requires `bpf_net_capable()` (CAP_NET_ADMIN or CAP_SYS_ADMIN).
- `bpf_prog_get_info_by_fd` zeroes `xlated_prog_len` without `bpf_capable()`
  (CAP_BPF or CAP_SYS_ADMIN). It withholds instructions of blinded programs
  without `bpf_dump_raw_ok`, and the dump zeroes helper-call immediates unless
  `bpf_dump_raw_ok` holds (`kallsyms_show_value`, which depends on `kptr_restrict`
  and CAP_SYSLOG).

So v1's command set needs CAP_SYS_ADMIN held from start. v2 resolves this without
CAP_SYS_ADMIN:

- Replace GET_FD_BY_ID with **BPF_OBJ_GET(7)** on bpffs pins that HOST_CONTAINMENT
  creates at fixed, sealed paths. The v6.12 `bpf_obj_get_user` path has no
  capability check; access is file permission plus SELinux `bpf` checks (to be
  confirmed in T04). Readers compare the pinned program's ID with the
  BPF_PROG_QUERY result in both local and effective views.
- Readers hold exactly CAP_NET_ADMIN (query) and CAP_BPF (unredacted translated
  instructions).
- Enrolled programs must be **helper-call-free** (no BPF_CALL in the translated
  image). Their dumps then need no `bpf_dump_raw_ok` and CAP_SYSLOG is not
  selected. `net.core.bpf_jit_harden` must be 0 or 1, so programs loaded with
  CAP_BPF are not blinded. Root-cgroup BPF filtering by cgroup ID would need a
  helper, so G04 uses SELinux `name_connect` (P2), not BPF, for the apiserver port.

**Attach and detach authority (author's reading of v6.12; T04 must confirm).**
For CGROUP_SOCK/SOCK_ADDR programs, `bpf_prog_attach` checks only the attach type
and `cgroup_bpf_prog_attach` takes the cgroup from a directory fd; neither checks a
capability. `bpf_prog_detach` → `cgroup_bpf_prog_detach` also checks none. In
`find_detach_entry`, an attachment made without BPF_F_ALLOW_MULTI can be detached
with no program fd at all ("legacy mode"). `cgroup_v1v2_get_from_fd` uses
`fdget_raw`, so an O_PATH directory fd is enough. SELinux `selinux_bpf` checks only
MAP_CREATE and PROG_LOAD. `unprivileged_bpf_disabled` applies only to map creation
and program load. So cgroup directory fds and program fds are themselves write
authority over endpoint enforcement. v2 therefore requires:

- enrolled programs attached with BPF_F_ALLOW_MULTI, so detaching needs that
  program's fd;
- planeon cgroup directories labelled with a dedicated type by containment (SELinux
  `cgroup_seclabel` policy capability), with `dir search` denied to every domain
  except planeon roles and `init_t`, so no other domain can even get an O_PATH fd;
- programs owned by `planeon_contain_t`, with `bpf { prog_run }` on them (checked in
  `bpf_prog_new_fd`) allowed only to reader domains; pins readable only by readers;
- every enrolled role's seccomp filter limits `bpf` to cmds {7, 15, 16}, so no
  attach (8), detach (9), pin (6), load (5), map create (0), link create/update/
  detach (28/29/34) or GET_FD_BY_ID (13).

### 5.2 Boot and seal sequence (enrolled boot entry)

S1. The kernel command line carries `lockdown=integrity`. SELinux is enforcing,
with the reviewed policy whose digest the record pins.
S2. systemd starts `planeon-host-containment.service` once, ordered before every
login and remote-access service, so no login session exists before S4. The unit has
`RefuseManualStart=yes` and its unit file is a sealed type. The domain transition
into `planeon_contain_t` is allowed only from `init_t` through the containment
entrypoint, and only while policy boolean `planeon_containment_enabled` is true.
S3. Containment creates or verifies role cgroups and limits, and labels the
planeon cgroup directories. It loads the helper-free map-free programs (CAP_BPF,
plus CAP_NET_ADMIN, which v6.12 `bpf_prog_load` requires for CGROUP_SOCK/SOCK_ADDR
types). It attaches them with BPF_F_ALLOW_MULTI to the seven hooks of each role
cgroup, pins and labels them in bpffs, and enables fs-verity on artifacts.
S4. Containment sets `planeon_containment_enabled=0`, then
`secure_mode_policyload=1`, both non-persistent. After this no domain can change
booleans, load policy or switch enforcing mode until reboot, and nothing can
enter `planeon_contain_t` again.
S5. Earlier in the same boot, sealed boot configuration has already loaded the
enumerated kernel module set the backend needs (for example overlay and
netfilter modules; exact list is W02 data). It has also applied the one-way
sysctls `kernel.modules_disabled=1`, `kernel.kexec_load_disabled=1`,
`kernel.yama.ptrace_scope=3` and `kernel.unprivileged_bpf_disabled=1`.
Containment only verifies these values and refuses to seal if any differs. It
then writes the seal marker to a sealed path and exits. A record from a boot
without the marker, or with any process in `planeon_contain_t`, refuses.
S6. Datastore, apiserver and other backend components start (sealed units), then
the gate (deny-default), observer, broker and server, in base §6 order.

`secure_mode_policyload` is enforced by the loaded policy's conditional rules, so
the pinned policy digest must contain them. That is reviewed with the binary
policy, not assumed from the boolean's name.

### 5.3 Per-role steady-state policy (after own seal step)

| Role | uid | Capabilities (permitted = effective; bounding equal; ambient empty) | Seccomp (mode 2, default KILL_PROCESS) | SELinux domain / key denials |
|---|---|---|---|---|
| SERVER | 0 | CAP_NET_ADMIN, CAP_BPF (inspection only); CAP_NET_BIND_SERVICE only if the signed listener port is below 1024 | Allowlist: I/O on held FDs, socket(AF_INET/AF_INET6 stream, AF_UNIX seqpacket), connect/accept4, memory and clock calls TLS needs, `bpf` with arg0 in {7,15,16}, memfd_create with flags exactly MFD_CLOEXEC and MFD_NOEXEC_SEAL for the sealed-credential path (the kernel clears the exec bits and sets F_SEAL_EXEC on every call, and further seals stay possible; the existing code passes MFD_CLOEXEC and MFD_ALLOW_SEALING and must change first, obligation O-SERVER-MEMFD), pidfd_open, inspection reads (read-only `openat`, `read`, `pread64`, `lseek`, `fstat`, `newfstatat`, `statx`, `fstatfs`, `getdents64` and `readlinkat`; `ioctl` only FS_IOC_MEASURE_VERITY; `membarrier` only cmd 0, 8 or 16 with flags 0 and cpu 0; W02d-QC). Seccomp checks only the open flags of these reads; which files they reach is set by the role's SELinux domain (`architecture/selinux-matrix-v2/`), exit. Denied: execve/execveat, clone3 (its flags are in a struct seccomp cannot read; it fails with ENOSYS rather than KILL_PROCESS, W02d-QB), clone without CLONE_THREAD, mount family, setns, unshare, ptrace, process_vm_*, init/finit_module, kexec_* | `planeon_server_t`: no execmem/execmod/execstack, no ptrace; `name_connect` only to the I04 gate port; `connectto` only to its existing observer/broker sockets; no `planeon_kubeapi_port_t` |
| OBSERVER | 0 | CAP_NET_ADMIN, CAP_BPF (inspection only) | As SERVER without its signed TCP listener; I06 read connection allowed. For I01 only, an AF_UNIX SOCK_SEQPACKET listener (HS53): `bind` and `listen`, and `accept4` only with flags 0, SOCK_CLOEXEC, or SOCK_CLOEXEC with SOCK_NONBLOCK, judged on the low 32 bits of the argument because the kernel reads it as an `int` (O-SECCOMP-V5-OBSERVER-LISTENER). Seccomp sees only a descriptor, so it cannot tell the I01 socket from any TCP socket the observer holds or creates (it keeps `socket` for AF_INET and AF_INET6 streams, for the I06 read connection): `bind` and `listen` reach those too, including a `listen` without `bind`, and the TCP-listen boundary is SELinux's (O-W03-OBSERVER-TCP, O-T04-HS53; residual R-OBSERVER-TCP-LISTEN). Among AF_UNIX sockets, too, the filter cannot hold the listener to I01's path; SELinux limits who may connect to the observer's sockets (only the server, `connectto`) and which socket files the observer may create (`planeon_observer_sock_t`). The socket's 0700 directory and its 0600 mode come from the units. The observer binds after its seal and never unlinks: one directory unit keeps /run/planeon/live-proxy for all three listeners, and before the observer starts, systemd removes only its stale I01 path (a pre-start step as init_t, which SELinux matrix v6 permits), so the filter adds no `unlink` (O-W03-OBSERVER-UNIT, O-W03-OBSERVER-PRESTART, O-MATRIX-OBSERVER-SOCK-CLEAR) | `planeon_observer_t`: `name_connect` to `planeon_kubeapi_port_t`; read-only to policy credential; the I01 listener: `create`, `bind`, `listen` and `accept` on its own `unix_stream_socket` (an AF_UNIX SOCK_SEQPACKET socket is checked in that class), socket file `planeon_observer_sock_t`, the server its only connector (SELinux matrix v5, `architecture/selinux-matrix-v3/`); no `tcp_socket` `listen` and no `node_bind` (O-W03-OBSERVER-TCP; a later matrix revision closes them in data, O-MATRIX-OBSERVER-TCP) |
| BROKER | 0 | CAP_NET_ADMIN, CAP_BPF (inspection); CAP_SETUID and CAP_SETGID, which the pre-exec child inherits and gives up in W4. No CAP_KILL: termination uses `cgroup.kill` on its own delegated leaf | As SERVER plus clone3, setresuid/setresgid, close_range, and execveat with flags limited to AT_EMPTY_PATH. The child inherits this filter, so it must cover the child's pre-exec steps; the narrower worker filter is installed in W4 and stacks on it. The inherited broker filter stays after exec and the kernel applies the most restrictive action of the two, so the broker allowlist covers the worker's (W02d-QD). The broker runs under exactly one filter, its own (W03 adds none, W02d F10), so the worker shows `Seccomp_filters: 2`. clone3 cannot be argument-filtered, so its use is bounded by `pids.max`, SELinux transitions and the W1-W6 sequence, not by seccomp | `planeon_broker_t`: `execute` only on the worker executable type, with a forced transition to `planeon_worker_t`; no other entrypoint |
| EFFECT_GATE | 0 | None: the signed I04 port is 1024 or above, so the gate keeps no capability after its seal (Q-HE2S-9 (a), HS43). It reads root-owned 0400 credentials as owner, does no BPF inspection, and qualifies peers with pidfd, SO_PEERCRED and same-uid /proc reads its policy allows, including the writer's ptrace-gated `exe` link (§4.3, HS43) | Network I/O, fsync/fdatasync, flock, the AF_UNIX listeners for I05/I07 and the I04 TLS listener; `readlinkat` only with a non-negative directory descriptor, judged on the low 32 bits of the argument because the kernel reads it as an `int`, so never AT_FDCWD in any encoding (§4.3, HS43, O-SECCOMP-V3-READLINKAT). Seccomp sees only that descriptor, and an absolute path ignores it, so which links the gate reads is set by `planeon_gate_t`'s SELinux permissions on the links' types (`procAccess` for `/proc` entries), by the kernel's ptrace-read rules and by the gate's code (O-W03-WRITER-EXE), not by the filter. `readlink` (x86_64), and `readlinkat` with AT_FDCWD (musl's `readlink` on aarch64), stay KILL_PROCESS; no exec, no clone3 (it fails with ENOSYS, W02d-QB), clone only with CLONE_THREAD | `planeon_gate_t`: sole reader of the two upstream credential files; `name_connect` to `planeon_kubeapi_port_t` |
| WORKER | signed 10000..2147483647 | Empty | The W02d worker allowlist (`architecture/seccomp-allowlists-v2/`, W02d-Q1): its CPython 3.12 runtime base, FD3 seqpacket I/O on fd 3 only, reads of the read-only root and exit; `execveat` only with flags AT_EMPTY_PATH, for W5 (W02d-QA); `clone3` fails with ENOSYS (W02d-QB); no socket creation, no `bpf`. The inherited broker filter stays installed and covers it (W02d-QD) | `planeon_worker_t`: no network `name_connect`, no ptrace, read-only root; no `execute_no_trans` on any type (SELinux matrix v4 A60.18) and no `transition` or `nnp_transition` into any declared domain (A24-A32), and the host policy gives it none into any other domain (obligation O-W03-WORKER-EXEC), so a second exec that the worker filter admits is still refused |
| POLICY_WRITER | 0 | Empty | AF_UNIX connect to I07, I/O, exit | `planeon_policy_writer_t`: `connectto` I07 only |
| HOST_CONTAINMENT | 0 | CAP_BPF and CAP_NET_ADMIN (program load), plus any capability its cgroup labelling, pinning and fs-verity steps need, which W02 enumerates; one-shot | Allowlist for the S2-S5 steps only | `planeon_contain_t`: only domain with `bpf { prog_load }`, `security { setbool }` and relabel on planeon types; enterable once per boot (S2/S4) |

The syscall names above are the policy shape. The exact per-architecture
allowlists (x86_64 and aarch64 numbers, argument filters) are W02 data (W02d; the current successor is `architecture/seccomp-allowlists-v5/`, HS53), generated
from these rows and reviewed. A syscall a role needs that is not derivable from
its row means the row is wrong and blocks implementation. It is not quietly
added to the allowlist. In every role except BROKER, `clone3` fails with ENOSYS rather than KILL_PROCESS (W02d-QB): in the CPython roles (SERVER, WORKER) glibc 2.34 and later then fall back to the thread-only `clone` rule, and the native roles' static musl runtime creates threads with `clone` only, never `clone3` (W01-AMEND-QW4). Every other call a role's allowlist does not name is KILL_PROCESS. For all roles: `no_new_privs=1` before the seccomp filter,
RLIMIT_CORE=0, no CAP_SYS_ADMIN, no CAP_SYS_PTRACE, no CAP_DAC_OVERRIDE, and no
unconfined or permissive domain anywhere on the host. Root logins map to a
confined administrator domain. That domain is denied writes to sealed types,
reads of planeon credential types, `bpf` permissions, `name_connect` to
`planeon_kubeapi_port_t`, `connectto` on runtime, datastore, I05 and I07 sockets
(I07 is reachable only by running the policy-writer entrypoint, which transitions
to `planeon_policy_writer_t`), and the `service { start stop reload }` permissions
on planeon unit types.

### 5.4 Worker pre-exec lifecycle (original parent preserved)

W1. The broker writes `cgroup.freeze=1` on its delegated `probe-worker` leaf,
which is empty, enrolled and has its limits and seven programs already present.
W2. The broker calls `clone3(CLONE_PIDFD | CLONE_INTO_CGROUP)` targeting that
leaf. In v6.12 `cgroup_post_fork` sets JOBCTL_TRAP_FREEZE on a non-kernel child of
a cgroup marked to freeze, so the child is frozen before it reaches user space.
The broker is the original parent and keeps the pidfd.
W3. While the child is frozen, the broker checks `/proc/<pid>` through the pidfd:
cgroup membership, credentials and label. It also checks the descriptor table:
only stdio and the broker-created FD3 socketpair end. The child holds no supplementary groups: the `Groups:` line
of `/proc/<pid>/status` lists none (the kernel writes `Groups:`, a tab and one space). W4's setresgid and setresuid
leave supplementary groups unchanged, so the broker must run with none (obligation O-W03-GROUPS), and neither filter
allows `setgroups`.
W4. The broker thaws the leaf. The child runs broker-owned pre-exec code only:
close_range above 3, setresgid/setresuid to the signed UID, drop all
capabilities, `no_new_privs=1`, install the worker seccomp filter (W02d). That filter admits W5's `execveat`
form and no other exec, and it stacks on the inherited broker filter.
W5. The child calls `execveat(fd, "", ..., AT_EMPTY_PATH)` on an O_PATH descriptor
of the fs-verity worker executable. The broker verified that descriptor's verity
digest before W2. The domain transition to `planeon_worker_t` happens on this
exec.
W6. The broker waits with `waitid(P_PIDFD)`. On expiry or invalidation it freezes
the leaf, kills through `cgroup.kill` (a pidfd signal needs CAP_KILL once the child runs as the signed uid, and
the broker holds none; the pidfd serves `waitid` and identity), waits until `cgroup.events`
reports `populated 0`, and only then releases the leaf. If it cannot show the leaf
is empty, it HOLDs (unchanged base rule).

No systemd child service, OCI runtime or subreaper adoption replaces W1-W6.

### 5.5 Reboot-only maintenance (decision D3)

**Sealed types** are the SELinux file types of planeon artifacts, configuration,
unit files, credentials, bpffs pins and the control-plane configuration (P5).
Only `planeon_maint_t` may write or relabel them. Entry to `planeon_maint_t` is
allowed only while policy boolean `planeon_maintenance_mode` is true. The enrolled
boot entry leaves it false and S4 freezes it with `secure_mode_policyload`. The
maintenance boot entry sets it true early in boot. Active booleans are already
pinned in the record (v1 rule), so an enrolled boot with the boolean true refuses,
and no planeon role can qualify in a maintenance boot.

M1. Any change to host policy, booleans, sealed files, BPF programs, units,
artifacts, the kernel or control-plane configuration needs a reboot into the
maintenance boot entry. In that entry `planeon_maint_t` is enterable and no planeon
role starts.
M2. Before rebooting, the operator runs I07 WRITE_BEGIN or an urgent
CLOSE_GENERATION. A reboot without it is an autonomous event: the gate starts
denied and HELD, and in-flight work is IO_AMBIGUOUS.
M3. After maintenance, the enrolled boot entry runs §5.2 again. The new boot ID
makes every prior generation unusable. Enrollment needs a fresh, non-reused
generation and fresh observation.
M4. Kubernetes policy changes do not need a reboot. They go through I07 with the
A3 drain fence.
M5. Credential issuance with the off-host CA (P4) happens only in the maintenance
entry.

## 6. G09 — request-to-action correlation by connection stamping

### 6.1 Rules (decision D4; I04 bytes unchanged)

C1. I04 already requires HTTP/1.1, one request per connection, no pipelining,
TLS 1.3 with no session resumption and no early data. The gate enforces these
rules itself; it does not rely on the client.
C2. **Flush on arm.** In the ARM_ACTION transaction for action X, under the
generation lock, the gate first closes, without forwarding, every connection of
this execution that has not yet consumed an action. It also accepts and closes
every connection pending in its listen backlog. Then it durably records ARM(X).
C3. **Stamp at accept.** Every connection the gate accepts afterwards gets the
action ID armed at that moment, or `none` if none is armed. The stamp is gate
state. Nothing from the client sets it or can change it.
C4. **Consume only the stamp.** A request may pass A1 only if its connection's stamp
equals the currently armed action, the connection's client certificate equals the
execution's bound run certificate, and the gate-derived canonical action for the
request equals X's request-template digest. Any mismatch closes the connection
without forwarding and records a correlation refusal.
C5. **One consumption per stamp.** After X is consumed, every other connection stamped
X is closed without forwarding. A connection stamped `none` never forwards.
C6. **Tombstones.** Consumed action keys stay in the gate's durable journal for the
execution's life. A gate restart starts denied (base §5) with no stamps, so it
cannot resume a connection.
C7. **Mutation uniqueness by construction.** CREATE uses signed names never reused,
and DELETE carries the recorded-UID precondition and is armed at most once per
UID. At ARM the gate refuses any mutation whose canonical key it has already
armed in this execution. GETs may repeat (status polling) because C2-C5 keep them
apart.

### 6.2 Argument against counterexample 17

Action A completes. A byte-identical duplicate of A is buffered in kernel, TLS or
parser state; then B, byte-identical to A, is armed. The duplicate's bytes sit on
some connection K that existed before ARM(B), because buffered bytes need an
existing connection. C2 closes K without forwarding (or K is A's connection and
already used, C1/C5). If K is still in the listen backlog, C2 accepts and closes
it. So the duplicate cannot reach A1 for B. By C7 the case only arises for GETs:
CREATE A and CREATE B can never be byte-identical, and DELETE is armed once per
UID.

### 6.3 Residual, stated rather than hidden

Suppose the server application opens a new connection after ARM(B) and sends bytes
identical to B. The gate cannot tell whether the server meant B or a stale resend
of A. In both cases the forwarded request is exactly the content the broker armed
as B, so no unarmed effect happens and B still happens at most once. A
misattributed result appears as gate/server disagreement in the existing
RESOURCE_RESULT agreement check (base §4 step 7) and becomes HELD. This residual
needs the server's own behaviour to cause it; transport buffering cannot. It
stays a T02 source case and a native case. The server is a reviewed component,
but its behaviour is not enforcement proof (unchanged base threat model).

No new header, field or caller-supplied action identifier is introduced.
A per-action correlation nonce (protocol amendment) stays a rejected alternative
for now. Adopting it later needs R01/R10/R12 versioning.

## 7. Amended I05 operation table (supersedes base §3 I05 table)

Unchanged fields stay as in the base. Additions:

| Operation | Addition in v2 |
|---|---|
| BIND_EXECUTION | Also binds the gate's own generation (must equal DISPATCH generation) and the peer-qualification digest of the gate's mutual qualification record (§4.3: the broker's qualification of the gate and the gate's of the broker, which HS43 narrows) |
| ARM_ACTION | Runs C2 flush before recording; refuses a repeated mutation key (C7); refuses while a WRITE_BEGIN drain is pending |
| ACTION_OUTCOME | Adds ADMITTED_BEFORE_INVALIDATION as a qualifier on DELIVERED_RESULT/IO_AMBIGUOUS (A4); still maps to the existing RESOURCE_RESULT without overloading its enum. Mapping table is W02 work |
| CLOSE_GENERATION | Normal close waits for the A3 fence; urgent close does not (A4); both deny unconsumed actions first |
| GENERATION_STATUS | Adds stamp/consumption counters and correlation-refusal count; still observation only |

## 8. What stays open after this candidate

- **E01-E12 OPEN_UNPROVEN, all.** Gate-to-row map: G04 → E03, E04, E05, E10;
  G05 → E10, E11, E12; G06 → E07; G07 → E01, E03, E04, E05, E06, E07, E08, E12;
  G09 → E10. E02 and E09 are untouched and still apply.
- **Native items:** completeness of the §2 closure on a real host (E03-E05, E10);
  whether the §5.1 kernel facts hold on the enrolled kernel and policy
  (T04); `secure_mode_policyload` conditionals in the pinned binary policy (T04);
  freeze-before-user-space under CLONE_INTO_CGROUP on the enrolled kernel (T04/T05);
  C2/C3 flush/stamp behaviour under load and restart (T02/T03); A2 field
  allowlists against real defaulting (T06).
- **W02 work:** exact wire schemas for I05/I07, v2 record schema, per-architecture
  syscall allowlists, cgroup paths, admission field allowlists, the Kubernetes
  distribution selection criteria, and the amended contract text with old/new vectors.
- **Unchanged:** I01-I04 bytes, the reuse candidate `envoyproxy/envoy` (not
  selected; its connection-level stamping would need review), 13 repositories,
  four planes, 16 harnesses, typed graphs, budgets and failed evidence.

## 9. Counterexamples added (18-28)

18. Policy writer commits an RBAC change while an admitted CREATE is in flight.
    Required: A3 blocks the write until the CREATE is classified; urgent path
    records ADMITTED_BEFORE_INVALIDATION.
19. Operator restarts host containment at runtime to attach different programs.
    Required: `RefuseManualStart`, `planeon_containment_enabled=0` under
    `secure_mode_policyload` (S4), and sealed unit types refuse it.
20. A root login uses a leftover admin kubeconfig. Required: P2 `name_connect`
    denial, independent of the credential.
21. The gate restarts mid-execution with clients connected. Required: deny-first,
    HELD, no stamps restored (C6).
22. The server opens connection K while A is armed and sends on it after B is
    armed. Required: K's stamp is A, so C4 refuses.
23. An I07 WRITE_OBJECT carries a Pod or an unknown kind. Required: refusal; writer
    identity never forwards effect kinds.
24. The aggregation controller widens an aggregated ClusterRole. Required: profile
    excludes aggregated roles from the closure; observer refuses.
25. Datastore restore at runtime. Required: AF_UNIX `connectto` and data
    directory types allow it only in reboot maintenance.
26. CSR approval mints a privileged client certificate. Required: P4 controllers
    disabled and CA key absent; P2 still mediates the path.
27. A reader keeps CAP_SYS_ADMIN "because GET_FD_BY_ID needs it." Required: v2
    removes command 13 and uses BPF_OBJ_GET on sealed pins (§5.1).
28. A root login opens an O_PATH fd on a role cgroup and detaches its enrolled
    program in legacy mode. Required: MULTI attachment (detach needs the program
    fd), `dir search` denial on labelled planeon cgroups, and `prog_run` denial on
    containment-owned programs (§5.1).

## 10. Adoption meaning

If the independent review returns PASS_FOR_SOURCE_PUBLICATION and finds G04, G05,
G06, G07 and G09 each RESOLVED_DESIGN, W01 becomes DESIGN_RESOLVED_REVIEWED. That
adopts this v2 candidate as the design-level host interface W02 must formalize. It
is not an installed ABI, not native enforcement, not coding readiness for
W03-W07, and not tenant acceptance. If the review requires changes, this snapshot
stays as an immutable historical subject and a corrected snapshot is reviewed
separately. Both verdicts are kept.

References consulted 2026-10-05 (research notes, not release pins):
- Linux v6.12 `kernel/bpf/syscall.c`, `kernel/bpf/inode.c`, `kernel/cgroup/cgroup.c`,
  `include/linux/bpf.h`, `include/linux/capability.h`, `include/linux/filter.h`,
  `kernel/ksyms_common.c`
- https://docs.kernel.org/admin-guide/cgroup-v2.html
- https://docs.kernel.org/admin-guide/sysctl/kernel.html
- https://kubernetes.io/docs/reference/access-authn-authz/validating-admission-policy/
- https://kubernetes.io/docs/reference/access-authn-authz/admission-controllers/
- https://kubernetes.io/docs/reference/access-authn-authz/authorization/

## 11. Amendment W02D (2026-10-10)

W02d (`architecture/seccomp-allowlists/`, MET-ENFORCE-017) carried six items into this record. Amendment W02D applies them, restates W02d-QB's ENOSYS refusal where rows imply KILL_PROCESS, and points at
the W02d successor (`architecture/seccomp-allowlists-v2/`). Nothing else changes; `amendment.json` beside this file
gives every change and its reason.

| Item | Where | Decisions |
|---|---|---|
| A1 | 5.3 WORKER row, seccomp | W02d-Q1, W02d-QA, W02d-QB, W02d-QD |
| A2 | 5.3 WORKER row, SELinux | W02d-QA |
| A3 | 5.3 SERVER row, seccomp (OBSERVER and BROKER inherit it) | W02d-QC |
| A4 | 5.3 SERVER row, seccomp (memfd_create) | W01-AMEND-QW3 |
| A5 | 5.3 SERVER row, seccomp (clone3) | W02d-QB |
| A6 | 5.3 EFFECT_GATE row, seccomp | W02d-QB |
| A7 | 5.3 BROKER row, seccomp | W02d-QD |
| A8 | 5.3 note | W02d-Q1 |
| A9 | 5.3 note | W02d-QB, W01-AMEND-QW4 |
| A10 | 5.4 W3 | W01-AMEND-QW2 |
| A11 | 5.4 W4 | W02d-QA, W02d-QD |
| A12 | 5.4 W6 | W01-AMEND-QW1 |

Obligations: O-SERVER-MEMFD (the sealed-credential code's memfd flags), O-W03-WORKER-EXEC (the worker's domain
transitions), O-W03-GROUPS (the broker's groups) and
O-T04-AMEND (native confirmation). Every E01-E12 obligation stays OPEN_UNPROVEN.

## 12. Amendment HS43 (2026-10-15)

HS43 changes how the effect gate qualifies its two local peers (§4.3) and states the one system call the writer's
executable check needs (§5.3); the gate's filter admits that call only once O-SECCOMP-V3-READLINKAT lands. It is
applied to the W02D effective text, which stays byte-identical; `architecture/host-interface-amendment-hs43/amendment.json`
gives every change and its reason.

| Item | Where | Decisions |
|---|---|---|
| H1 | 4.3 | Q-HE2S-10, Q-HE2S-7, Q-HE2S-9, Q-HE3A-1, Q-HS43-1, Q-HS43-2, Q-HS43-3, HS43-GATE-RESIDUAL-CONFIRM |
| H2 | 5.3 EFFECT_GATE row, capabilities | Q-HE3A-1 |
| H3 | 5.3 EFFECT_GATE row, seccomp | Q-HE3A-1, Q-HE3A-1b, HS43-START, SECCOMP-DIRFD-DIRECTION |
| H5 | 5.3 EFFECT_GATE row, capabilities | Q-HE2S-9, HS43-H5-CONFIRM |
| H4 | 7 | Q-HE2S-10, Q-HS43-2, HS43-H4-CONFIRM |

Adopted text HS43 overrides (each file stays byte-identical; HS43 governs, and a successor of that contract adopts it):

| Superseded clause | In | Replaced by |
|---|---|---|
| "authenticate exact installed peer artifacts, manifest/trust custody, PID/start," | `architecture/host-interface-inputs/corrected/HOST_INTERFACE_SPEC.md` | for I05 and I07, the rules of W01 §4.3 as amended by HS43: the gate does not authenticate the broker's installed artifact or its manifest/trust custody per frame; those rest on the broker's label, whose only entrypoint is the enrolled artifact's type (O-W03-PEER-EXE), while the broker still authenticates the gate's artifact and the gate the writer's (H1) |
| "PID/start identity, executable, label and cgroup" | `architecture/i05-gate-channel/README.md` | the gate verifies the broker's SO_PEERCRED and SCM_CREDENTIALS, pidfd/start, label and cgroup, not its executable (W01 §4.3 as amended by HS43) (H1) |
| "The broker verifies the gate's frames the same way" | `architecture/i05-gate-channel/README.md` | the broker verifies the gate's frames by SO_PEERCRED and SCM_CREDENTIALS, pidfd/start, executable, label and cgroup: its own list, which HS43 does not narrow (H1) |
| "PID/start identity, executable, label and cgroup" | `architecture/i05-gate-channel-v2/README.md` | the gate verifies the broker's SO_PEERCRED and SCM_CREDENTIALS, pidfd/start, label and cgroup, not its executable (W01 §4.3 as amended by HS43) (H1) |
| "The broker verifies the gate's frames the same way" | `architecture/i05-gate-channel-v2/README.md` | the broker verifies the gate's frames by SO_PEERCRED and SCM_CREDENTIALS, pidfd/start, executable, label and cgroup: its own list, which HS43 does not narrow (H1) |
| "PID/start identity, executable, label and cgroup" | `architecture/i05-gate-channel-v3/README.md` | the gate verifies the broker's SO_PEERCRED and SCM_CREDENTIALS, pidfd/start, label and cgroup, not its executable (W01 §4.3 as amended by HS43) (H1) |
| "The broker verifies the gate's frames the same way" | `architecture/i05-gate-channel-v3/README.md` | the broker verifies the gate's frames by SO_PEERCRED and SCM_CREDENTIALS, pidfd/start, executable, label and cgroup: its own list, which HS43 does not narrow (H1) |
| "qualifies the writer peer the way it qualifies the broker" | `architecture/i07-policy-write/README.md` | qualifies the writer peer by its own W01 §4.3 rule (HS43), which keeps the artifact check the broker's no longer has; inherited by I07 v2 and v3 (H1) |
| "writer artifact `/opt/planeon/bin/harness-policy-write` (fs-verity digest under its signed manifest, §4.2)" | `architecture/i07-policy-write/README.md` | the writer's exe link equal to the enrolled path exactly, with no " (deleted)"; the fs-verity digest is enforced on the sealed file at enrollment, not re-measured per frame (HS43); inherited by I07 v2 and v3 (H1) |
| "and the broker peer qualification digest (§4.3)" | `architecture/host-interface-amendment-w02d/HOST_INTERFACE_SPEC.md` | the peer-qualification digest of the gate's mutual qualification record, whose gate-side half HS43 narrows (H4) |
| "CAP_NET_BIND_SERVICE only with a signed port below 1024" | `architecture/native-profile-v2/README.md` | for the server only; EFFECT_GATE holds none, because its signed I04 port is 1024 or above (W01 §5.3 as amended by HS43, H5; O-NATIVE-GATE-NOCAP) (H5) |
| "Captures and peer checks therefore use SO_PEERCRED, SO_PEERSEC, pidfds and ungated entries" | `architecture/selinux-matrix/README.md` | the gate's check of the writer also reads the writer's ptrace-gated exe link (HS43); matrix.json is unchanged (H1) |
| "Executable identity follows from the peer's label" | `architecture/selinux-matrix/README.md` | for the broker; the writer's executable is also checked through its exe link (HS43) (H1) |
| "Peer qualification and captures use SO_PEERCRED, SO_PEERSEC, pidfds and ungated `/proc` entries; executable identity" | `architecture/selinux-matrix/README.md` | as above: the gate also reads the writer's exe link (HS43) (H1) |
| "Captures and peer checks therefore use SO_PEERCRED, SO_PEERSEC, pidfds and ungated entries" | `architecture/selinux-matrix-v2/README.md` | the gate's check of the writer also reads the writer's ptrace-gated exe link (HS43); matrix.json is unchanged (H1) |
| "Executable identity follows from the peer's label" | `architecture/selinux-matrix-v2/README.md` | for the broker; the writer's executable is also checked through its exe link (HS43) (H1) |
| "Peer qualification and captures use SO_PEERCRED, SO_PEERSEC, pidfds and ungated `/proc` entries; executable identity" | `architecture/selinux-matrix-v2/README.md` | as above: the gate also reads the writer's exe link (HS43) (H1) |

Stated residuals:

- R-WRITER-PROC: A dumpable writer lets every uid-0 role with procAccess on it read its ptrace-gated entries, for example exe, cwd, root, fd, fdinfo, environ and maps: the server, the observer and the broker as well as the gate. mem and process_vm_* stay refused, because they need ptrace attach, which Yama ptrace_scope 3 refuses. Follow-up: obligation O-MATRIX-WRITER-PROCACCESS, in the queued SELinux matrix amendment SELINUX-MATRIX-I04-KEYCERT (Q-HS43-3).
- R-GATE-PROC: The gate stays dumpable (Q-HE2S-7 (a)) and holds no capability, so every uid-0 role with procAccess on it (the broker, the server and the observer) can read its ptrace-gated entries, for example environ, maps, cwd and the fd links; reopening a credential through an fd link still meets SELinux's file checks on the credential type (matrix v4 A09). mem and process_vm_* stay refused, because they need ptrace attach, which Yama ptrace_scope 3 refuses. Follow-up: obligation O-MATRIX-GATE-PROCACCESS, in the queued SELinux matrix amendment SELINUX-MATRIX-I04-KEYCERT (Q-HS43-3, Q-HE2S-7).

The data follow in order (Q-HE3A-1b): the W02d v3 allowlist (`architecture/seccomp-allowlists-v3/`) gains the
EFFECT_GATE `readlinkat` rule in its own packet, then the EFFECT_GATE programs and the edge record are republished,
then R10 re-vendors them and adds the check.

Obligations: O-SECCOMP-V3-READLINKAT (the allowlist rule), O-W03-WRITER-EXE (the writer's credentials and dumpability, and the read bound to the frame's process), O-W03-PEER-EXE (the gate readable by the broker, race-free peer pidfds, and the broker's label), O-MATRIX-WRITER-PROCACCESS (narrowing the writer's /proc readers, residual R-WRITER-PROC), O-MATRIX-GATE-PROCACCESS (narrowing the gate's /proc readers, residual R-GATE-PROC), O-MATRIX-GATE-NETBIND (the gate's net_bind_service grant), O-NATIVE-GATE-NOCAP (the native profile's gate capability rule), O-T04-HS43 (native confirmation). Every E01-E12 obligation stays OPEN_UNPROVEN.

## 13. Amendment HS53 (2026-10-17)

HS53 lets the observer hold the one listener I01 needs (§5.3 OBSERVER row) and records who produces I01 (§4.3); the
observer's filter admits the listener only once O-SECCOMP-V5-OBSERVER-LISTENER lands. It is applied to the HS43
effective text, which stays byte-identical; `architecture/host-interface-amendment-hs53/amendment.json` gives every
change and its reason.

| Item | Where | Decisions |
|---|---|---|
| H1 | 5.3 OBSERVER row, seccomp and SELinux | Q-SOL-1, Q-SOL-2, Q-SOL-3, F-SOL-1, Q-SOL-5, SOL-SYSTEMD-CLEANS, Q-SOL-7, Q-MX6-R6 |
| H2 | 5.3 text after the table | Q-SOL-1 |
| H3 | 4.3 | Q-SOL-4, F-SOL-1 |

Adopted text HS53 overrides (each file stays byte-identical; HS53 governs, and a successor of that contract adopts it):

| Superseded clause | In | Replaced by |
|---|---|---|
| "Existing fixed native observer, read-only to policy" | `architecture/host-interface-inputs/corrected/HOST_INTERFACE_SPEC.md` | a fixed native observer, read-only to policy, whose I01 producer is R10's HE-004-I01 (obligation I01-1 of W03-PLAN-AMEND-2, MET-ENFORCE-032, main c69e55f; W01 §4.3 as amended by HS53) (H3) |
| "Pre-existing protected observation service" | `docs/alpha-2/POLICY_OBSERVATION_READINESS.md` | the protected observation service, whose I01 producer is R10's HE-004-I01 (obligation I01-1 of W03-PLAN-AMEND-2, MET-ENFORCE-032, main c69e55f; W01 §4.3 as amended by HS53) (H3) |
| "Documents the observer as a separately installed prerequisite, not an included or provisioned service" | `docs/alpha-2/POLICY_OBSERVATION_READINESS.md` | documents the observer as a prerequisite of live execution that R10's HE-004-I01 (obligation I01-1 of W03-PLAN-AMEND-2, MET-ENFORCE-032, main c69e55f; W01 §4.3 as amended by HS53) produces (H3) |
| "The producer is an external operator prerequisite, like the pre-existing API proxy and admission controls, not an unimplemented product packet disguised as DONE. An operator must supply an open-source, reviewed implementation meeting this protocol and the native tests below." | `docs/alpha-2/POLICY_OBSERVATION_READINESS.md` | for I01, the producer is R10's HE-004-I01 (obligation I01-1 of W03-PLAN-AMEND-2, MET-ENFORCE-032, main c69e55f; W01 §4.3 as amended by HS53), not an operator-supplied implementation; until it is installed, protected live execution stays NOT_RUN_ENV_UNAVAILABLE as this guide says. The guide's protocol, path, modes, framing, limits and peer checks are unchanged (H3) |
| "PREEXISTING_INDEPENDENTLY_INSTALLED_OPEN_SOURCE_PRODUCER" | `architecture/policy-observation-amendment.json` | the operator prerequisite of this channel record: for I01, the observer is produced by R10's HE-004-I01 (obligation I01-1 of W03-PLAN-AMEND-2, MET-ENFORCE-032, main c69e55f; W01 §4.3 as amended by HS53); the record's other fields are unchanged (H3) |
| "An absent independently installed observer remains an explicit external prerequisite, not product/native PASS." | `architecture/policy-observation-amendment.json` | an absent observer remains a prerequisite, not product/native PASS; for I01 it is produced by R10's HE-004-I01 (obligation I01-1 of W03-PLAN-AMEND-2, MET-ENFORCE-032, main c69e55f; W01 §4.3 as amended by HS53) (H3) |
| "The broker and observer are separately installed, reviewed open-source operator prerequisites, not product implementations represented as DONE." | `docs/alpha-2/BROKER_HANDOFF_READINESS.md` | for the observer, I01's producer is R10's HE-004-I01 (obligation I01-1 of W03-PLAN-AMEND-2, MET-ENFORCE-032, main c69e55f; W01 §4.3 as amended by HS53); the broker's statement is unchanged (H3) |
| "The observer is a separately installed open-source operator prerequisite, not an available or deployed product." | `docs/alpha-2/LIVE_BACKEND_READINESS.md` | for I01, the observer's producer is now R10's HE-004-I01 (obligation I01-1 of W03-PLAN-AMEND-2, MET-ENFORCE-032, main c69e55f; W01 §4.3 as amended by HS53); this summary stays the record of MET-REPAIR-010 (H3) |
| "The observer is a separately installed open-source operator prerequisite, not an available or deployed product." | `docs/READINESS_INDEX.md` | for I01, the observer's producer is now R10's HE-004-I01 (obligation I01-1 of W03-PLAN-AMEND-2, MET-ENFORCE-032, main c69e55f; W01 §4.3 as amended by HS53); this summary stays the record of MET-REPAIR-010 (H3) |
| "The observer is a separately installed open-source operator prerequisite, not an available or deployed product." | `docs/TRUSTED_LIVE_CAMPAIGN_RUNNER_CONTRACT.md` | for I01, the observer's producer is now R10's HE-004-I01 (obligation I01-1 of W03-PLAN-AMEND-2, MET-ENFORCE-032, main c69e55f; W01 §4.3 as amended by HS53); this summary stays the record of MET-REPAIR-010 (H3) |
| "The observer is a separately installed open-source operator prerequisite, not an available or deployed product." | `docs/adr/0004-sol-high-packet-boundary.md` | for I01, the observer's producer is now R10's HE-004-I01 (obligation I01-1 of W03-PLAN-AMEND-2, MET-ENFORCE-032, main c69e55f; W01 §4.3 as amended by HS53); this summary stays the record of MET-REPAIR-010 (H3) |
| "The observer is a separately installed open-source operator prerequisite, not an available or deployed product." | `docs/repositories/00-harness-engineering.md` | for I01, the observer's producer is now R10's HE-004-I01 (obligation I01-1 of W03-PLAN-AMEND-2, MET-ENFORCE-032, main c69e55f; W01 §4.3 as amended by HS53); this summary stays the record of MET-REPAIR-010 (H3) |
| "The observer is a separately installed open-source operator prerequisite, not an available or deployed product." | `docs/repositories/12-mas-harness-conformance-labs.md` | for I01, the observer's producer is now R10's HE-004-I01 (obligation I01-1 of W03-PLAN-AMEND-2, MET-ENFORCE-032, main c69e55f; W01 §4.3 as amended by HS53); this summary stays the record of MET-REPAIR-010 (H3) |
| "The observer is a separately installed open-source operator prerequisite, not an available or deployed product." | `task-packets/README.md` | for I01, the observer's producer is now R10's HE-004-I01 (obligation I01-1 of W03-PLAN-AMEND-2, MET-ENFORCE-032, main c69e55f; W01 §4.3 as amended by HS53); this summary stays the record of MET-REPAIR-010 (H3) |
| "as SERVER without the listener; the I06 read connection (connect)" | `architecture/seccomp-allowlists/README.md` | as SERVER without its signed TCP listener; the I06 read connection (connect); and, in seccomp v5, the I01 listener of W01 §5.3 as amended by HS53 (bind, listen, and accept4 with flags 0, SOCK_CLOEXEC or SOCK_CLOEXEC\|SOCK_NONBLOCK) (H1) |

Stated residuals:

- R-OBSERVER-TCP-LISTEN: The observer's filter admits bind and listen on every descriptor it holds, including any TCP socket it creates (its filter keeps socket for AF_INET and AF_INET6 streams, for the I06 read connection), because seccomp sees only the descriptor. A listen without bind reaches only SELinux's tcp_socket listen check (v6.12 net/socket.c:1883-1895 calls security_socket_listen, never security_socket_bind), and, by the author's reading of v6.12 SELinux, name_bind is not checked for port 0 or for ports inside ip_local_port_range. So unless the host policy denies planeon_observer_t tcp_socket listen, the observer can open a TCP listener; denying node_bind as well refuses a bind to any TCP port. Follow-up: obligations O-W03-OBSERVER-TCP and O-T04-HS53, then O-MATRIX-OBSERVER-TCP in data (Q-SOL-2).

The data follow in order (Q-SOL-1 (a)): the W02d allowlist successor (`architecture/seccomp-allowlists-v5/`) gains
the OBSERVER I01 listener rule in the same packet as this amendment, then the OBSERVER programs and the edge record
are republished, then R10's HE-004-I01 re-vendors them and serves I01.

Obligations: O-SECCOMP-V5-OBSERVER-LISTENER (the allowlist rule), O-W03-OBSERVER-UNIT (the socket's directory, mode and freshness), O-W03-OBSERVER-PRESTART (the pre-start removal runs as init_t), O-W03-OBSERVER-TCP (no TCP listener for the observer), O-T04-HS53 (native confirmation), O-MATRIX-OBSERVER-TCP (the observer's TCP listen closed in data), O-MATRIX-OBSERVER-SOCK-CLEAR (systemd's grant to clear a stale I01 path (met by matrix v6)), O-PROGRAMS-V3-OBSERVER (the OBSERVER programs and the edge record), O-R10-HE004-I01 (the observer serves I01). Every E01-E12 obligation stays OPEN_UNPROVEN.
