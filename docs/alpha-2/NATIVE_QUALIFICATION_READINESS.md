# Native qualification binding — MET-REPAIR-015

Alpha2 · approved source-only scope · 2026-09-10. Catalog144; thirteen
repositories, four planes and sixteen harnesses. No installation or native PASS.

## Decision, trust boundary and ownership

CONF-LIVE-003/B2 identified a missing consumer contract for the active Linux
containment required by MET-REPAIR-009/010/014. Signed executable and preflight
digests are expected values, not observations. The server must qualify itself
before opening the observer; an observation cannot bootstrap its own producer.

This amendment defines one fixed first profile:
`SELINUX_FSVERITY_CGROUP_BPF_V1`. It refines the existing
PREINSTALLED_OS_ENDPOINT_ALLOWLIST_V1 backend, not an alternate runtime selector.
It uses the trusted Linux kernel, independently installed operator authority,
integrity-protected code, enforcing mandatory policy and attached endpoint
filters. The kernel, independently reviewed root trust components and operator
are the TCB; this is not attestation against a compromised kernel or hostile
machine administrator. Tenant/client data cannot select code, policy or handles.

No new service, network endpoint, local socket, root key, signing role, public
campaign field or Kubernetes grant is added. No inspector agent or command-line
tool is called. Source readers use Python3.12.14 standard-library os, fcntl,
mmap, struct and ctypes against already installed libc/kernel interfaces.
This packet executes none of those native readers; its oracle handles data only.

This first profile is deliberately strict. It qualifies a separate pre-existing
trusted proxy/operator Linux host, not every Kubernetes worker. It does not make
SELinux or fs-verity a universal tenant workload requirement. Plain Linux/OCP,
AMD64/ARM64 and air-gap claims still require their actual native matrix evidence.
An AppArmor-only or otherwise unsupported host is unavailable for this profile,
not an automatic install, fallback or platform-wide compatibility claim.

| Owner | Required work |
|---|---|
| Existing independent operator | Preinstall/review the exact host/code/kernel policy and filters; attest the record; preserve the execution fence |
| CONF-LIVE-003 | Record parser, fixed native inspector, server/observer/broker ownership, credential ordering, transport and admission |
| CONF-LIVE-004 | Fixed worker; inherited broker-only control; qualified kernel/code checks through the same003-owned reader, never a server-check callback |
| CONF-LIVE-005 | Inert reproducible entries; inventory the prerequisite record and documented read permissions, not install or enable controls |
| CONF-LIVE-006 | Integrated refusal and real native qualification evidence; no native promotion from a valid record |

Exact product paths/stages110/120/127/135/141/146/151 and all eight commands are
unchanged. No future packet may need an unspecified callback or edit003 to close
this boundary. Preserve127 files/327 predecessor tests and all143 prior packets.

## Closed record and acyclic authority

Fixed release member:
`campaigns/platform/linux-baseline/native-qualification.json`, mode0444,
canonical JSON without a trailing newline, <=256KiB, depth16, exact builtins,
no duplicate keys/floats/nonfinite values/control characters. Occurs exactly
once in the signed kit tree with exact size/SHA256. No caller path or discovery.

The schema is `architecture/native-qualification-inputs/qualification.schema.json`.
The record contains profileDigest, exact tenant/environment/run/capacity scope,
the exact signed numeric endpoint tuples (not IDs alone), host boot/kernel/machine
identity, SELinux kernel-policy pins, four fixed role
records (SERVER/OBSERVER/BROKER/WORKER), code-file fs-verity/raw hashes and expected
process labels, namespace IDs, cgroup limits and attached-program pins.

All independently installed server/observer/broker/worker manifests use their
existing `preflightEvidenceDigest` for SHA256 of these exact record bytes.
The existing observation binding's hostPreflightDigest equals it too. Compare
all role artifact hashes to their independent manifests and every actual file.
Each role is qualified in its own lifetime; an unstarted worker is not a
running-process observation and must not be invented during server bootstrap.

The record pins the existing profile, not the release, observation binding,
broker binding, manifests, signatures or itself. Those objects refer downward to
the record, so no self/circular digest is introduced. It cannot add resources,
endpoint tuples or credential purposes beyond independently signed capacity.
Binding/artifact references outside the fixed record must still pass their
unchanged signatures, exact packet006/eight commands, windows and revocation.

A valid record is an expected configuration. Only the actual fixed factory
can acquire the retained native inspection resources and qualify active peers.
The data oracle returns errors or an empty list, never a protected handle/PASS.
The record does not replace independent operator review of the policy/program
semantics or native qualification. Artifact strings are not such review.

## Concrete native inspection ABI

Only little-endian native x86_64/AMD64 and aarch64/ARM64 are supported by this
first reader. Bind the exact independently qualified kernel release and SHA256
of /sys/kernel/notes plus /proc/sys/kernel/random/boot_id. Linux6.12 UAPI is the
layout reference; a different kernel requires independent qualification of the
same interface and exact record, not a version-number-only admission.

### Trusted kernel views and retained identity

Use canonical no-follow ancestry and fstatfs to verify procfs, sysfs, selinuxfs
and cgroup2 before interpreting their contents. Fixed roots are /proc,
/sys/kernel, /sys/fs/selinux and /sys/fs/cgroup. Refuse substituted bind mounts,
unexpected mount/namespace identity or unavailable reads. Only fixed kernel
magic links /proc/<retained-pid>/exe and ns/{user,mnt,pid,net} are exceptions to
ordinary symlink refusal; never follow request-selected proc links or map paths.

Retain original PID/start-time, pidfd and kernel credentials before/after each
exchange. Compare UID/GID, label, namespace inode set and cgroup membership to
the enrolled role; deny PID reuse, peer restart, foreign/user namespaces,
unexpected extra threads/children for SERVER, or copied handles. Actual peer
proc access must already be permitted. Do not call ptrace, setns, unshare,
mount, capset, policy loaders or broaden privileges to make inspection succeed.

Fixed cgroups are /sys/fs/cgroup/planeon-live/{proxy-server,policy-observer,
capacity-broker,probe-worker}. They must already exist with independently
enrolled inode, finite memory.max, pids.max and cpu.max values. Read only.
Validate cgroup membership against the qualified namespace view, retain each
ancestor, and compare controls before/after I/O. No new cgroup/capacity creation.

### Active SELinux policy, not a copied policy file

At /sys/fs/selinux verify filesystem type SELINUX_MAGIC, active enforcing=1,
deny_unknown=1 and the expected status version1, policyload and even sequence.
Use a read-only shared mmap of the kernel status page. Acquire sequence, a
memory fence, fields, a second fence and sequence; reject odd/changed epochs.
Keep that same boot/sequence/policyload throughout the operation, including
before and after fresh policy reads; no wraparound, reset or ABA acceptance.

Fences use only the calling process's membarrier QUERY(0),
REGISTER_PRIVATE_EXPEDITED(16), PRIVATE_EXPEDITED(8), flags0/cpu0.
The per-process registration/fence is a synchronization primitive, not a kernel
policy change. Never use global barriers. Fixed syscall numbers: x86_64
membarrier324/bpf321; aarch64 membarrier283/bpf280. Reject unavailable commands,
wrong ABI or errors; do not add libatomic, JIT code or an architecture fallback.
Both architectures require independent native ordering tests.

Fresh-open /sys/fs/selinux/policy under that unchanged status epoch, hash the
complete bounded kernel policy image (<=64MiB), then close it promptly. This
kernel interface snapshots policy at open; retaining the descriptor and merely
rereading it is not a fresh observation. EBUSY is unavailable within the bounded
read phase, not permission to use a cached disk copy. Pin active boolean state,
permissive-domain closure and role/file/socket permissions through the reviewed
exact binary policy. Also recheck /enforce and each exact enrolled process label.
The policy must deny tenant/worker domain transitions, code injection/ptrace,
execmem/execmod/execstack, relabeling and access to authority/credentials/sockets
outside their existing scopes. Inspector read permissions must already exist.

The kernel policy image reader and status layout are grounded in the
[Linux6.12 SELinux implementation](https://github.com/torvalds/linux/blob/v6.12/security/selinux/selinuxfs.c)
and [libselinux status reader](https://github.com/SELinuxProject/selinux/blob/3.8/libselinux/src/sestatus.c).
No copied library or downloaded policy is introduced.

### Actual code and mappings

Each role's executable/archive, actual /proc/<pid>/exe interpreter/native ELF,
loader and every mapped executable dependency must be in the closed file list.
Each file has canonical absolute path, root owner, non-writable exact mode,
ordinary SHA256 and a DISTINCT fs-verity SHA256 measurement. Use retained
no-follow O_RDONLY descriptors and FS_IOC_MEASURE_VERITY (0xc0046686):
native little-endian u16 algorithm/u16 digest-size followed by32 digest bytes;
initialize capacity32, require algorithm1 and returned size32. Never enable
verity, repair files or confuse the Merkle measurement with ordinary SHA256.
Bounds:128 files, <=64MiB each, <=512MiB total; no unknown lazy load after seal.

Parse a bounded complete /proc/<pid>/maps read (<=1MiB) twice around descriptor
checks; reject truncated/changing executable maps. Verify address order,
permissions, offset/device/inode and exact canonical enrolled paths. Disallow
deleted/memfd executable files, anonymous executable mappings, writable-executable
pages and unlisted executable code. Verify file offsets/segments against the
enrolled ELF artifact. ASLR addresses are observed identities, not static pins.
The only kernel executable exceptions are actual [vdso] and AMD64 [vsyscall],
with architecture/auxv/kernel identity checks; a named anonymous mapping is not
such an exception. Normal non-executable heap/stack growth is not code drift.

fs-verity protects file reads, not anonymous/COW modifications. Actual enforcing
policy must prevent executable private-page modification and new executable
mappings; mapping snapshots alone cannot prevent an in-between substitution.
File/path/label/namespace changes invalidate custody even if file bytes match.
[Kernel fs-verity documentation](https://www.kernel.org/doc/html/latest/filesystems/fsverity.html)
distinguishes its measurement from ordinary hashes and covers mmap reads.
[Kernel procfs documentation](https://www.kernel.org/doc/html/latest/filesystems/proc.html)
defines mapping identities and kernel-special versus named-anonymous regions.

### Active endpoint filters and inspection permissions

SELinux enforcement alone is NOT asserted to implement the exact signed numeric
IP/port tuple. Query attached cgroup BPF programs through fixed libc syscall
adapters, not bpftool, a shell or a caller-provided FD/command. Closed commands:
BPF_PROG_QUERY(16), BPF_PROG_GET_FD_BY_ID(13), BPF_OBJ_GET_INFO_BY_FD(15).
No load, attach/detach, link update, map access/update or program test-run.
Use the Linux6.12 union-bpf-attr/prog-info layouts with explicit 64-bit alignment,
zero initialized tails, bounded arrays and exact output lengths; reject redacted
instruction bytes or unknown fields/layouts rather than guess a version.

Required hooks for each role: INET_SOCK_CREATE(2), INET4_BIND(8), INET6_BIND(9),
INET4_CONNECT(10), INET6_CONNECT(11), UDP4_SENDMSG(14), UDP6_SENDMSG(15).
Query the role cgroup locally and with BPF_F_QUERY_EFFECTIVE(1); each required
hook must have exactly its one enrolled program in both views. Retain the cgroup
and program descriptors; compare actual program ID, type (9 or18), map count0,
non-offload ifindex0, nonempty translated instruction length/hash and query
results before/after I/O. No program-tag-only, stored ELF-only or attached-but-
different-effective-program acceptance. Maximum16 returned IDs/64KiB program.

Independent qualification reviews those exact map-free programs' semantics:
only the signed SERVER listener bind; only already-authorized numeric outbound
tuples; no UDP/raw/packet bypass or helper/map/tail-call rewriting; zero-resource
SERVER mode has no IP connect grant. Per-role tuples are an explicit subset of
the existing envelope/capacity, not a new endpoint authorization. Observer/broker
internal facilities remain separately reviewed operator responsibilities, never
a caller-selectable route or a grant carried to campaign code.
Connection lifetime is still broker-generation fenced under MET-REPAIR-014.

The [Linux BPF syscall implementation](https://github.com/torvalds/linux/blob/v6.12/kernel/bpf/syscall.c)
requires privileges for some inspection operations. The reader uses only already
authorized root inspection access; it MUST NOT obtain/add CAP_SYS_ADMIN,
CAP_NET_ADMIN, CAP_BPF or CAP_PERFMON, change SELinux permissions, or weaken
redaction to succeed. Missing inspection access is NOT_RUN_ENV_UNAVAILABLE.
These are trusted existing operator processes, not privileged tenant pods.
The [versioned UAPI](https://github.com/torvalds/linux/blob/v6.12/include/uapi/linux/bpf.h)
defines the fixed read/query structures; data fixtures are not kernel outputs.

## Ordering, lifetime and no observation gap

Server bootstrap: original installed custody → independently verified authority/
release/record → self kernel/code qualification → observer retained peer/code/
kernel qualification → actual observation → durable whole-run reservation →
server TLS credential. Broker identity/record/kernel qualification precedes
DISPATCH. Active broker operation, current observation and reservation precede
the separate API credential. Preserve the client-only MET-REPAIR-013 exception.

All checks have <=2-second bounded inspection phases within the unchanged
<=900-second/signed lifetime. Socket wait loops recheck at most every2seconds.
Each blocking read/query rechecks custody, trust, clocks and the epoch; inspection
may not recursively perform observer I/O, acquire credentials, create a worker
or mint execution authority. Every acquired descriptor has one close owner and
is non-inheritable; partial construction closes only acquired resources.

The existing independent operator/broker must serialize host policy, filter,
cgroup, label and qualified executable changes with its execution fence as well
as cluster policy. Ordinary changes wait for drain; urgent invalidation closes
admission and stops/reaps workers before changed controls become executable.
Pre/post checks detect drift but are not this exclusion mechanism. An operator
that cannot exclude bypass updates cannot qualify the profile. This preserves
MET-REPAIR-014's external-enforcement requirement; no observation-derived lease.

Fixed consumer interface in live_proxy_server.py: a private factory-owned
`_KernelQualification` with `check_self()`, `check_peer(role, retained_peer)`
and `close()`. Construction/handles only by the exact installed owner; no
caller's context, function, dictionary or descriptor can grant qualification.
004's installed worker may use the same fixed reader for itself/original broker
through its separately exact installed factory and parent/FD3 guards. Three
roles qualify at server startup; WORKER qualifies only inside broker-owned
startup. No future require_server_containment callback in packet004.

## Verification and evidence

New schema/data oracle tests cover complete four-role records; exact binding;
every closed nested shape; digest cycles/substitution; missing/excess code;
kernel/status epochs and policy ABA; changed labels/namespaces/cgroups/maps;
verity versus content hashes; missing/extra/inherited BPF hooks/programs;
redacted programs/maps/offload; before/after drift; partial/expired captures;
unsupported permissions and fake flags. A model capture has no native authority.

Product003 must exercise the real factories through OS-mocked calls, including
all refusal gates before server credentials. Unit adapters never select a
production bypass. Native006 separately requires both architectures, real
policy/filter mutation and revocation races, namespace/PID/FD spoofing,
injection/mapping replacement, original socket/credential denial, quota/cleanup,
worker reaping and exact-main/artifact binding. Record validity cannot fill any
missing installed/native/runtime/assurance/tenant gate.

Publish with23 complete declared argv commands, including both full predecessor
replays, in the existing signed deny-all tree. Preserve nested420/trusted900 and
workflow15-minute bounds and all failures. Required localhost PR CI, green-only
merge and independent LOCAL exact-main precede the next product run.

| Phase | ID | Publication state |
|---|---|---|
| Phase0 / Alpha1 | Foundations | DONE_RECORDED source/offline |
| Alpha2 | MET-REPAIR-014 / PR109 | DONE_SOURCE_GATES |
| Alpha2 | MET-REPAIR-015 | ONGOING |
| Alpha2 | CONF-LIVE-003 | WAITING for this source closure |
| Alpha2 | CONF-LIVE-004/005/006 | WAITING |
| Alpha2 | Native AMD64/ARM64 | NOT_RUN_ENV_UNAVAILABLE |
| Alpha3/4 | Governed actions / enterprise release | WAITING |

Before consumption revert this publication as a reviewed unit; after consumption
use a bounded corrective successor. Never alter installation, trusted policy,
nonce/resource history, tenant data or past evidence. No new key, admin prompt,
download, hosted runner, cloud bill or API-key dependency. Model-effort
transition NOT_DUE; Alpha2 is not complete.
