# Linux host authority v1: the owner's per-run GCP Linux hosts, their recipe and key custody (MET-LINUX-008)

Status: **CONTRACT_CANDIDATE_AWAITING_INDEPENDENT_REVIEW** (candidate c3). Roadmap item LINUX-HOST-AUTH-001, packet
MET-LINUX-008, design revision 7 with the binding build rules B-LHA-1, B-LHA-2 and B-LHA-4 to B-LHA-18. Contract rounds
run in series `MET-LINUX-008/contract` under the registered generic brief; review records and `status.json` come after
adoption. DATA_CHECK_ONLY: published data and an offline checker. Nothing here creates a project, a VM, a key or spend,
and no step here runs a cloud command.

## What this contract does

Two native runs need a host the published rules could not yet provide: CONF-LINUX-001 (R12's seven-command verifier,
unchanged) and, after CONF-LIVE-001 to CONF-LIVE-006 close at source, MET-LIVE-001's fresh native AMD64 qualification.
The owner's decision is recorded by MET-LINUX-007 (`architecture/lab-run-plan/status.json` `ownerDecisions`
LINUX-CAPACITY), but a run-plan contract does not supersede `docs/alpha-2/LINUX_READINESS.md`, whose line 162 asks for
"a new reviewed superseding authority". This packet is that authority. It:

1. supersedes the capacity predicates with that decision, member by member, bound by span at the base;
2. fixes the host recipe as data, with an operator runbook that has a check per step;
3. fixes the operator install steps for the launchers the host carries, under a new Linux trust anchor;
4. fixes the custody model for every key and credential the host's live path verifies.

**Effect.** No evidence state changes. Native AMD64 and ARM64 stay NOT_RUN_ENV_UNAVAILABLE; approving capacity is not
qualification.

**Precedence (Q-LHA-5 (a)).** The superseded texts stay byte-identical as historical text. `host-authority.json` names
each superseded predicate member by member; for runs under MET-LINUX-007's plans it governs where they differ. Every
other predicate of those files stands. An owner-approved licence charge would need a contract amendment.

## Files

| File | Content |
|---|---|
| `host-authority.json` | `planeon.internal.linux-host-authority/v1`: the superseding record |
| `host-recipe.json` | `planeon.internal.linux-host-recipe/v1`: the two hosts, access, egress, inventories, runbook steps |
| `launcher-install.json` | `planeon.internal.linux-launcher-install/v1`: the operator install steps, the signed-drop installer and the trigger units |
| `custody-model.json` | `planeon.internal.linux-key-custody/v1`: the signing authorities, per-run credentials and live custody duties |
| `*.schema.json` | one closed schema per record, plus `drop-manifest.schema.json` for the per-run drop manifest (B-LHA-4) |
| `vectors.json` | 2 positive sets, 205 record negatives, a drop-manifest positive with 10 negatives, 4 signature rows and 8 parse negatives |
| `../../scripts/linux_host_authority.py` | the offline checker, standard library only |
| `../../tests/test_linux_host_authority.py` | the candidate's own tests |

Run the checker from the repository root:

| Command | What it does |
|---|---|
| `python3 -I -B scripts/linux_host_authority.py check` | checks the schemas and the four records, re-deriving every span from the cited files |
| `python3 -I -B scripts/linux_host_authority.py replay` | the same, then replays every vector against its recorded refusal |

A refusal prints `refused: <rule>` and exits 1; a usage error exits 2.

**Parse rules and schemas.** The checker restates LAB-RUNPLAN-001's parse rules, canonical form, closed schema subset
and string rule (`scripts/lab_run_plan.py`): UTF-8 without a byte-order mark, no duplicate keys, no non-finite or
oversized numbers, no integral float, no lone surrogate. On top of them every number in these records is an integer, so
a non-integral number is refused too. Each schema declares JSON Schema draft 2020-12 at its root and otherwise uses only
the closed subset: every object closed with every key required, every keyword where it applies.

**Role labels only (B-LHA-13).** The records name the two cloud identities and the custom role by role label only:
`OWNER_ADMIN`, `OWNER_LOGIN` and `OWNER_LOGIN_BASELINE`. No record carries an identity, an account, a project id, the
custom role's full name (which on paper contains the run project's id), a key, a price, a POSIX name or a UID. The
string rule refuses an account or key shape; the role-label rule refuses a resource path with a project, folder or
organization id, a custom role's full name, an SSH key, a price, an OS Login style POSIX name and a UID.

## The superseding authority (`host-authority.json`)

**One digest rule.** Every `fileSha256` is taken at the packet's base, harness-onion main
`a88276171453760e46b28e8f6f0c0bb4bbfade5d`. Each superseded, kept, satisfied, cost-scope, reviewed and reading entry
carries `lines` (`[start, end]`, 1-based), `fragments` (`[startLine, startByte, endLine, endByte]`, 0-based UTF-8 byte
offsets within their lines, end exclusive; a fragment may cross lines and then holds the line feeds between them),
`text` (the fragments' decoded bytes joined by " … ", line feeds and indentation kept, no normalisation: B-LHA-12) and
`span` (the sha256 of the fragments' bytes, each followed by one 0x00 byte). JSON citations also carry the full member
path. The checker reads each cited file from the checkout, requires its bytes to be the base's, and re-derives every
text and span; it also pins each entry's span, so an entry cannot be re-pointed at another predicate. A whole-sentence
digest is never used. The quotes in this README are renderings, not the record's text.

**`supersedes`** (the only relaxed predicates):
- `LINUX_READINESS.md` lines 63-66: "Use only existing authorized zero-incremental-cost capacity", and "No cloud
  instance … is authorized" by its cloud-instance fragments only;
- `linux-readiness.json` `billing.capacity` and `billing.newProvisioning`;
- `LINUX_READINESS_REPAIRS.md` lines 147-149 (the "existing zero-incremental-cost capacity" condition) and line 155
  ("create capacity"), under Q-LHA-13 (a);
- `CI_CAPACITY_EXCEPTION.md` line 7, for live campaigns only: "zero-bill" and "no-cloud-provisioning";
- **the independence clause** (the owner's Q-LHA-1 (a)): `LINUX_READINESS.md` lines 66-68 ("independent signers", from
  "Missing"), the "independent" of line 147, and `evidence.requiredBindings[11]` INDEPENDENT_SIGNATURES. It is admitted
  only together with the **replacement predicate**: INDEPENDENT_SIGNATURES stays a required binding, satisfied by
  signatures of the three distinct authorities (PLATFORM_RELEASE, TENANT_LIVE_EXECUTION, CAPACITY_OPERATOR), each with
  its own key id, purpose, token and sealed backup, under one principal, with the disclosure
  `signers: SINGLE_PRINCIPAL_SEPARATED_KEYS` and the owner's answer carried verbatim.

**`satisfied`** by the replacement predicate, none relaxed further: `LINUX_READINESS.md` line 138; TRUSTED_LIVE
(`docs/TRUSTED_LIVE_CAMPAIGN_RUNNER_CONTRACT.md`) lines 456-457 and 532; `CREDENTIAL_ORDERING_REPAIR.md` line 37.

**`unchanged`**: every kept predicate of a partly relaxed sentence, each its own entry. No hosted runner, new broker,
paid key, registry egress charge or automatic package or image pull (lines 63-69); missing hardware, preloaded tooling or
OS isolation remains NOT_RUN_ENV_UNAVAILABLE; lines 101-102, read with Q-LHA-12 (no administrator login is bound at
preflight or after); the only live entry point and the three authorities (lines 146-148); the kept `billing` members
(hosted runners, paid APIs, third-party keys, raw container sockets); REPAIRS lines 147-149 and 154-156; and CI line 7's
defaults for the other scopes, with no paid API for live campaigns too. **No automatic package or image pull at any
time**: only operator-initiated, digest-pinned fetches, only inside the setup window.

**`costScope`**, kept at campaign, server, reader, cluster or endpoint level: TRUSTED_LIVE lines 442-443 (no raw
container socket or new resource capacity), CREDENTIAL_ORDERING_REPAIR.md line 94 (never "create capacity"),
NATIVE_QUALIFICATION_READINESS.md line 110, `LINUX_READINESS.md` line 163 ("Do not … destroy capacity": the plan's
teardown releases per-run capacity the plan itself created, under its lease, which is not the destruction of existing
capacity the line forbids), the endpoint cost disposition (TRUSTED_LIVE lines 241-244) and the Kubernetes
`mutationProfile` (line 339). The paid capacity is the recipe's `costScope`; inside it the campaign, the server and the
qualification reader create no capacity.

**`reviewedNotBinding`** (Q-LHA-13 (a)), each "states that packet's own publication scope, not a standing rule":
NATIVE_QUALIFICATION_READINESS.md lines 22-23 and its closing sentence (lines 281-282), and TRUSTED_LIVE lines 460-461,
484-485, 523-525, 540-541 and 560-561. This packet's new Linux trust anchor and its release-pinned local CA key are
therefore not barred by them.

**`readings`** (MON-LHA-16-1), each listing its occurrences with their spans. **The named-forms rule** (design section
4; B-LHA-11; MON-LHA-ORC-2-A): a reading covers its named forms in every superseded, kept and satisfied text, and the
checker refuses an unlisted one.
- **SIGNING_AUTHORITY**, "existing": `evidence.signingAuthority`, OPERATOR.md steps 4, 5 and 8 (lines 93, 99, 115 and
  116) and `LINUX_READINESS.md` line 147, cited for the word only (B-LHA-11). Existing signing authority is established
  by the post-merge key ceremony and recorded in `custody-model.json` before any run, never introduced during a run.
- **PRE_EXISTING**, "pre-existing", "preexisting" and "existing" operator (Q-LHA-14, the owner): installed, reviewed and
  verified by the operator before the envelope is signed, never by the campaign. For the per-run cluster the operator
  makes these resources at step 7, which the reading admits. Occurrences: MET-REPAIR-015 lines 28-29 and 37,
  `evidence.runtimeTransport`, the superseded `billing.capacity`'s PREEXISTING (`linux-readiness.json` line 117),
  TRUSTED_LIVE lines 241, 254, 257, 260, 281, 302 (`preexistingResourceRefs`), 321 (cited for
  the word, B-LHA-11; lines 321-322 read "Pre-existing, storage, and accelerator references") and 442, and
  CREDENTIAL_ORDERING_REPAIR.md line 87. "New broker" (line 65) reads with it: no broker beyond the one reviewed
  capacity broker the operator installs and verifies before the envelope is signed.

**`capacity`**: `OWNER_APPROVED_GCP_PER_RUN` under MET-LINUX-007, bound to the plan sha256, the lease, the cost ceiling
and the teardown report; the run project separate from the lab foundation with no default network; the host following
`host-recipe.json`; `licenceCharge: NONE`.

**`consumers`**: CONF-LINUX-001 runs through the external root-owned live launcher (`LINUX_READINESS.md` line 146;
TRUSTED_LIVE line 440), so its earliest full run follows CONF-LIVE-005/006's source closure. The native AMD64
qualification runs after CONF-LIVE-001 to CONF-LIVE-006, through CONF-LIVE-006's declaration and adapter. Before
CONF-LIVE-005/006 close, a lease yields only an offline-launcher preflight with HOST_ISOLATION_ONLY evidence
(OPERATOR.md lines 223-225): "This is not a product image build, live runtime test or full native release
qualification".

**`decisions`**: the owner's decision as MET-LINUX-007 records it (bound by span), and the decision lines only,
verbatim, each with its source entry; the checker pins each line's digest.

## Decisions

The owner's answers and the monitor's rulings under the owner's 2026-10-22 delegation; `host-authority.json` holds the
decision lines verbatim. In short:
- **LX-D1, LX-D2** (owner): LINUX-HOST-AUTH-001 owns the host authority, recipe and key custody, in the parallel lane.
- **Q-LHA-1** (owner): "Separated keys, disclosed (Recommended)". **Q-LHA-2** (owner): "Offline + token + sealed backup
  (Recommended)"; the manifests are signed within one hour of the preflight.
- **Q-LHA-3 to Q-LHA-13** (monitor): custody outside GCP with a host ledger exported at teardown; gate material; a new
  record supersedes by digest; G13 later; the live launcher design only; Shielded VM, serial off, OS Login 2FA, limited
  guest agent, SELinux enforcing; a no-licence-fee RHEL-10-compatible family with the spend condition; preflight only;
  an egress allowlist with a byte ceiling; admin login during setup only; every restatement superseded.
- **Q-LHA-14, Q-LHA-15, Q-LHA-16 (2)** (owner): two VMs per run; the custom ext4-verity image; the local CA key offline
  on a token with a sealed backup. **MON-LHA-16-1, MON-LHA-SPLIT, MON-LHA-12R, MON-LHA-17, LHA2-11** (monitor).
- **The owner's cap**, **MON-LHA3-1-2**, **MON-LHA-B1**, **MON-LHA-B2**; **LHA3-8** and **B-LHA-3** are superseded by
  **the owner's custom-role decision** ("Custom role on run project (Recommended)"); **Q-LHA6-3** (owner): "No login for
  admin id (Recommended)".
- **Q-LHA5-1** (owner): "Two identities + audit check (Recommended)": a separate administering identity holds and revokes
  the run's bindings; the login identity's custom role also excludes the IAM-changing permissions; the effective re-check
  runs at step 15 before the export, and the Admin Activity audit-log check from step 10 to teardown finds no IAM change
  or custom-role update granting osAdminLogin; any finding refuses the run's evidence; groups and the organization are
  detected by the effective check, not blocked; both identities are role-labelled only, named in no record.
- **MON-LHA-NO-LOCAL-BRIEF** (monitor): no local `REVIEW_BRIEF.md`; the series uses the registered generic brief.

| Answer | Applied in |
|---|---|
| Q-LHA-1 (a), owner | `supersedes` (the independence clause and its replacement predicate); `custody-model.json` `principal` and `independence`; vectors A16-A18, C17-C18 |
| Q-LHA-2 (a), owner | `custody-model.json` authorities and token sessions; runbook steps 10 and 12; launcher time limits |
| Q-LHA-3 (a), restated | `custody-model.json` `nonce`, `crossHostReplay`, `trustedClock`, `revocation`, `evidenceStore` |
| Q-LHA-5 (a) | the precedence statement; `host-authority.json` |
| Q-LHA-7 (a), restated | `launcher-install.json` `liveLauncher` (design only) |
| Q-LHA-8 (a), extended | recipe `machine`, `guestAgent`, `profile`; the preflight probe scope |
| Q-LHA-9 (a), spend condition | recipe `image` |
| Q-LHA-10 (a) to Q-LHA-13 (a) | the offline launcher's mode; recipe `egress`; recipe `access`; `supersedes`, `costScope`, `reviewedNotBinding` |
| Q-LHA-14, Q-LHA-15, Q-LHA-16 (2), owner | recipe `hosts` and `image`; the PRE_EXISTING reading; `custody-model.json` `localCa` |
| MON-LHA-16-1, MON-LHA-SPLIT, MON-LHA-12R, MON-LHA-17 | `readings`; recipe `profile`; the signed-drop installer and the effective checks; recipe `rootAliases` |
| MON-LHA3-1-2, MON-LHA-B1, MON-LHA-B2 | recipe `internalFlows`; the trigger units and `operatorUid`; `custody-model.json` `clusterCa` and `kubernetes` |
| the owner's custom-role decision | recipe `access` (`loginBaseline`, `leaseBindings`, `revocation`); runbook steps 1, 10 and 16 |
| Q-LHA5-1 (owner) and MON-LHA-REV7 | recipe `access` (two identities, `effectiveChecks`, `auditLogCheck`, `acceptedLimit`); runbook steps 1, 10, 15 and 16; `custody-model.json` holders; the recipe vectors; Not claimed; the role-label rule (B-LHA-13) |
| Q-LHA6-3 (owner) | recipe `access` `adminBaseline`, the `OWNER_ADMIN` effective checks and session checks (B-LHA-18) |

## The host recipe (`host-recipe.json`)

**Project** (LAB-RUNPLAN-001): prepared once, confirmed per run, one run at a time, no compute between runs; no default
network, no Cloud NAT, Private Google Access off; the VPC and firewall made at runbook step 2; the OS Login policy
enforced.

**Hosts** (Q-LHA-14): two AMD64 VMs per run, under one plan and lease, sized per plan.
- The **proxy/operator host** carries the proxy, observer, broker, local registry and evidence sink, the launchers, the
  signed-drop installer and trigger units, MET-REPAIR-015's profile, the locked Python, Node and Firejail. It holds no
  kubeconfig and no container-runtime socket, only the KUBERNETES_PROXY_SERVER_MTLS client credential.
- The **cluster node** carries the single-node cluster (the fixture database, the control container), its preload images
  and the pinned distribution packages; its root kubeconfig and runtime socket stay there. It needs no file after the
  revocation. "Cluster node" is this contract's term: MET-REPAIR-015's "worker" (line 29), its probe-worker cgroup
  (lines 106-107) and MET-REPAIR-014's fixed worker role are other things, the last two on the proxy/operator host.

**Internal flows** (MON-LHA3-1-2), each a VPC firewall rule: **F1** proxy/operator host to node, tcp, the cluster API
port the kit fixes (the API proxy, observer, broker and the CAMPAIGN_PROXY server's upstream); **F2** node to
proxy/operator host, tcp, the LOCAL_REGISTRY port (the node's runtime pulls preloaded images). No other internal path.
**B-LHA-6:** every proxy upstream to the cluster workloads goes through the API server on F1, by its service-proxy or
port-forward subresources as the capacity authorization's rules allow; a campaign-proxy rule that targets a NodePort, a
Service or a Pod address is refused (such a flow would be a new listed flow for the monitor). The node's LOCAL_REGISTRY
trust file, `/etc/planeon/node/local-registry-trust.pem`, is installed at step 7, before the revocation.

**Machine** (both hosts, Q-LHA-8 (a)): Shielded VM (secure boot, vTPM, integrity monitoring), serial-port access off; no
service account and no scopes; metadata `enable-oslogin=TRUE`, `enable-oslogin-2fa=TRUE`, `block-project-ssh-keys=TRUE`,
and no SSH keys, startup or shutdown scripts or guest attributes; the guest agent keeps only OS Login (NSS, PAM) and clock
sync; live migration with no automatic restart inside the lease (a reboot after qualification invalidates it,
MET-REPAIR-015 line 86); a provider-side maximum run duration with a delete action, ending no later than the lease.

**Image** (Q-LHA-9 (a), the spend condition; Q-LHA-15): an SELinux-enforcing, no-licence-fee RHEL-10-compatible family
(for example AlmaLinux 10, Rocky Linux 10 or CentOS Stream 10, on paper), pinned per plan, `licenceCharge: NONE`. The
node boots the pinned family image. The proxy/operator host boots **the custom image**, built per plan with the root
(`/usr` included) on ext4 with verity and UEFI guest features. **B-LHA-8:** the built root starts from the pinned family
image's own files, verified against that image's inventory taken before any install on the node, plus the listed
packages; step 4 labels it from its own policy's file contexts, the image inventory records each file's SELinux label, a
first-boot relabel is refused, and preflight compares the labels; the plan pins the kernel release the section-10
qualification covers and step 5 checks it in the built root. **`imageDigest`** is the sha256 of the custom image's own
inventory (path, type, mode, owner, size, sha256, SELinux label of every file), taken at step 5 from the build disk
mounted read-only and recomputed by the owner off the host. Preflight records the kernel release and the
`/sys/kernel/notes` digest and checks that lockdown keeps the BPF program information the reader needs (MET-REPAIR-015
lines 184-185 and 193).

**Host inventory** (one per host): the system trees, `/opt/planeon` (tools, cache, python, bin, work), `/etc` and the
boot chain; frozen at step 9 after the last install that changes a covered path (`gate.invalidateOn`
HOST_OR_ISOLATION_CHANGE). Left out, each with its own record: the cluster state, the host nonce ledger and logs, the
step-10 files (digest and signature), the drop targets (digest and drop-manifest signature) and, **B-LHA-9**, the
per-run private halves and requests (SPKI digest only). Both hosts' boot event logs are exported at step 9 with the
inventories. The measured-boot comparison reads the provider's Shielded VM integrity record (on paper) and replays each
host's boot event log, mapping EFI binaries by Authenticode digest and file sha256. The image re-verification runs off
host in T1: every host-inventory entry steps 7-8 did not change is compared with the image inventory. **The reading of
BUILD_INPUTS.md lines 95-103:** line 101 asks the external operator to "independently verify the image identity" and
line 103 says an "unobservable image identity blocks native qualification". This contract reads the owner's off-host
verification as that independent verification; the remainder beyond the boot chain is operator-attested. If a review
rejects this reading, qualification is blocked.

**Root aliases** (MON-LHA-17): every listed family links `/lib64` at the root and the AMD64 loader is
`/lib64/ld-linux-x86-64.so.2` (on paper). OPERATOR.md lines 171-174 fail a symlinked inventory root. The root-alias
contract MET-LINUX-009 is the precondition; it merged as this packet's base, so the step-9 check runs under it with v4
inputs. An uncovered used path stops the run at NOT_RUN_ENV_UNAVAILABLE.

**MET-REPAIR-015's profile** (MON-LHA-SPLIT), on the proxy/operator host:

| Prerequisite | Owner | Step | Check |
|---|---|---|---|
| SELinux enforcing | this recipe | 4-5 | preflight reads `/sys/fs/selinux` |
| the reviewed exact binary policy (lines 129-138), with `deny_unknown=1` (lines 114-115) | the existing independent operator | 7 | MET-REPAIR-015's reader |
| an ext4 verity-capable root and a measurement for every closed-list file (lines 147-150) | recipe: the filesystem; operator: the measurements | 4-5, 7 | the reader |
| cgroup v2; the planeon-live cgroups with finite limits (lines 106-110) | recipe: v2; operator: the cgroups | 4-5, 7 | the reader |
| one enrolled program per required BPF hook per role (lines 187-194) | the existing independent operator | 7 | the reader |
| the kernel release, notes digest and `boot_id` (lines 84-88) | recipe: recorded | 11 | preflight |
| serialised policy, filter, cgroup, label and executable changes (lines 230-236) | the existing independent operator | 7 onward | the operator's own record |

### Access (Q-LHA-12 (a), MON-LHA-12R, the owner's custom-role decision, Q-LHA5-1, Q-LHA6-3)

- **SSH only through IAP:** source 35.235.240.0/20, tcp 22 (on paper).
- **Two identities, both the owner's, by role label only:** the login identity `OWNER_LOGIN` (OS Login with 2-step
  verification, used for SSH only) and the administering identity `OWNER_ADMIN`, which alone grants and revokes the
  run's bindings, manages the custom role and performs the cloud actions of runbook steps 2, 3, 5, 6 and 16 (B-LHA-15).
  Any further permission for the login identity would be a new owner choice, for the monitor.
- **The login baseline** is the custom role `OWNER_LOGIN_BASELINE` on the run project, in place of any basic role (Owner,
  Editor or Viewer; MON-LHA-REV6). **B-LHA-15:** its permission list, recorded in the plan, holds only what SSH through
  IAP and OS Login needs; in particular no `compute.instances.osAdminLogin`, no IAM-changing permission (project,
  instance and service-account `setIamPolicy`, `iam.roles.create`, `iam.roles.update`), no service-account impersonation
  or key permission (`iam.serviceAccounts.actAs`, `getAccessToken`, `signBlob`, `signJwt`, `implicitDelegation`,
  `getOpenIdToken`, `iam.serviceAccountKeys.create`) and no tag-binding permission. `OWNER_ADMIN` creates and binds the
  role outside the run, before approval; it is kept between runs and not deleted at teardown.
- **B-LHA-18:** `OWNER_ADMIN`'s role on the run project, or on any ancestor, holds none of `compute.instances.osLogin`,
  `compute.instances.osAdminLogin` or the IAP tunnel permission. Its binding counts among the owner's baseline bindings.
- **Between runs** the run project's IAM policy holds only the baseline bindings (`OWNER_LOGIN_BASELINE`'s and
  `OWNER_ADMIN`'s) and the observer's viewer bindings: LAB-RUNPLAN-001's "owner's baseline bindings" (its README lines
  188-189). The owner confirms this at step 1.
- **Bindings granted during the lease**, each by `OWNER_ADMIN` and counted as `IAM_BINDINGS_ADDED`
  (`scripts/lab_run_plan.py` lines 66-73; LAB-RUNPLAN-001 README lines 167-168): the IAP tunnel role; the OS Login admin
  role as a separate binding for setup and install only; the non-admin login role after that.
- **The revocation** (step 10): `OWNER_ADMIN` removes the admin-login binding. No deny policy, no folder or organization
  grant. **B-LHA-10:** the runbook then waits for IAM propagation and ends every session opened with admin on both hosts;
  the check confirms that no process or session of either identity started before the revocation, that no OS Login
  sudoers entry exists, and that a fresh login cannot use sudo. An admin session from before the revocation alive at
  preflight refuses the run's evidence.
- **The effective checks** (step 1 confirmation; steps 10 and 15 effective; for both identities): the login identity's
  permissions above are absent on the project, every instance, every service account in it (B-LHA-15), **every ancestor
  folder and the organization (B-LHA-14:** folder and organization `setIamPolicy`, organization-level `iam.roles.create`
  and `iam.roles.update`), through direct, basic, custom, inherited, group, domain, principal-set and conditional grants
  (step 1 counts a conditional binding as a grant whatever its condition, and so do steps 10 and 15); the custom role's
  permission list equals the plan's; `OWNER_ADMIN` holds no login permission. Any finding refuses the run's evidence.
- **Who runs them, and how (B-LHA-17, on paper):** never the login identity. The observer reads the IAM policies of the
  run project, its instances and service accounts with its run-project viewer roles and reads the audit log;
  `OWNER_ADMIN` reads every ancestor folder's and the organization's policies and resolves the login identity's group
  membership transitively through the directory. A domain binding covering the login identity, or any principal set that
  can include it, counts as a grant; every matched role is expanded to its permissions. A check that cannot read what it
  needs fails, and the evidence is refused. B-LHA-10's propagation wait comes before the step-10 check.
- **The audit-log check (B-LHA-16):** the Admin Activity log from the step-10 revocation entry to the end of teardown
  lists every IAM policy change on the run project and its instances and every custom-role create, update, delete or
  undelete. Each entry must be one of the plan's expected entries, made by `OWNER_ADMIN`: the step-10 removal of the
  admin-login binding, the non-admin login grant if it falls in the window, and the teardown revocations. **Any other
  entry refuses the run's evidence, whatever its principal**, and any custom-role change refuses it. The final span is
  checked after the teardown completes; the evidence counts as accepted only after that.
- **The owner's accepted limit (Q-LHA5-1: "detected by the effective check, not blocked"; B-LHA-14):** group, domain,
  principal-set, folder and organization grants are detected only by the effective checks at steps 10 and 15. A grant
  made and removed between those steps, or made after step 15, is not detected. The audit log does not detect them.
- After the revocation, root-owned files on the proxy/operator host change only through the signed-drop installer, and
  at teardown `OWNER_ADMIN` revokes every binding granted since the lease started; the baseline role and bindings stay.

**Egress** (Q-LHA-11 (a)): the setup window only, operator-initiated digest-pinned fetches through one fetch tool;
destinations matched by IP ranges per plan, no paid firewall feature; the fetch tool stops at the byte ceiling and the
provider's figures are compared after the window (detection, not prevention). The deny-all egress rule is made at step 2
below the window's allow rule; step 6 removes the allow rule and the external addresses. The closure probe's expected
exceptions are the metadata address, F1 and F2. No external address or allow-egress rule at campaign time.

**Time:** chrony against the provider's internal time service; the other metadata-server uses are OS Login NSS and PAM,
the guest agent's kept features and DNS; the clock source and offset are captured at preflight.

**Packages:** on the proxy/operator host git, Firejail at `/usr/bin/firejail`, the locked Python 3.12.14 at
`/opt/planeon/python/3.12.14`, Node for the standalone control build, Go only if needed; on the node the cluster
distribution and its pinned packages. Distribution packages come from the family's dated snapshot, pinned by version and
file sha256; Firejail from EPEL as exact RPM files pinned by file sha256 (on paper); the locked Python and Node from
outside the snapshot with their source and digest closure. **The mirror rule** deliberately relaxes revision 3's "no
undated mirror" refusal: byte identity rests on the file digest. Tool and cache roots per BUILD_INPUTS.md lines 24-37.
Every automatic updater is off.

**Source:** the owned-product checkout with its `.git` and the workload commit, transferred by digest over the IAP tunnel
into the built root, with `treeSha256` per BUILD_INPUTS.md lines 49-53, so the pinned git can verify HEAD (OPERATOR.md
lines 143-148). No repository credential on the host.

**Runtime root writes (B-LHA-5)**, the closed list of runtime state paths root-owned components write after the
revocation, each with its one writer: the host ledger (launcher, proxy-client and proxy-server parts under
`/var/lib/planeon/host-ledger/`), the preflight records (`/var/lib/planeon/preflight/`, the preflight unit), the
installer log (`/var/log/planeon/signed-drop-installer.log`), the evidence sink, the journal and the node's cluster
state. Any other root write is refused; the signed-drop installer's listed targets are the only other root-owned files
that change.

**Cost scope** (each a plan line item): both hosts' machine-hours and boot disks (LAB-RUNPLAN-001), the temporary build
disk and the stored custom image (this recipe). The build minutes are the node's machine-hours.

**Teardown:** the plan's teardown governs (images and disks are counted classes, LAB-RUNPLAN-001 README line 162). The
export at step 15 comes first; the custom image and any build disk left are deleted; the per-run private halves end when
the instances and their disks are deleted, and the teardown report's zero counts are the check (B-LHA-1).

## Runbook

Ordered operator steps, each with its check. No step stores a credential in a repository, metadata or the image. The
off-host token sessions are **T1** and **T2**.

| # | Step | Check |
|---|---|---|
| 1 | Prepare or confirm the run project (LAB-RUNPLAN-001 step 1). `OWNER_ADMIN` made and bound `OWNER_LOGIN_BASELINE` before approval. | The plan's sha256 approved with every `costScope` line item; the lease active; no compute present; the custom role's id (the real id in the owner-held plan, the role label in every published rendering) and its exact permission list recorded in the plan; the owner confirms the baseline holds no basic role, that no binding (direct, group, domain, principal set, inherited, conditional) grants `OWNER_LOGIN` admin login, an IAM-changing, service-account, key or tag-binding permission on the project, its service accounts, any ancestor folder or the organization, and that `OWNER_ADMIN` holds no login permission |
| 2 | `OWNER_ADMIN`: VPC and firewall: ingress IAP tcp 22 only; F1 and F2 only; the deny-all egress rule; the window's allow rule above it | Firewall and route listing; no NAT; Private Google Access off |
| 3 | `OWNER_ADMIN`: create the cluster node from the pinned family image, with the temporary build disk attached | The node's metadata keys and refusals; no service account; Shielded VM; serial off; guest-agent features; maximum run duration |
| 4 | Setup window, with admin. On the node: take the pinned image's inventory, install the proxy/operator host's root onto the build disk from the pinned image's own files plus the listed packages (ext4 with verity; Firejail, the locked Python, Node, git, the tool and cache roots, the kit's preload for that host, the source checkout with `.git`), labelled from its own file contexts. Install the node's own packages and cluster preload. | Every digest matches; the built root verified against the image inventory; bytes under the ceiling |
| 5 | Take the custom image's inventory (with labels) from the read-only build disk and export it; the owner recomputes `imageDigest` off the host. `OWNER_ADMIN` creates the custom image (UEFI guest features), deletes the build disk and creates the proxy/operator host from the image. | `imageDigest` recorded; the kernel release checked in the built root; the build disk gone; the host booted from the recorded image; step 3's checks repeated on it |
| 6 | `OWNER_ADMIN`: close egress: remove the allow rule and both external addresses | Refusal probes (expected exceptions: the metadata address, F1, F2); the observer's listing |
| 7 | External operator installation: the kit (the cluster on the node, the namespace, the proxy), the observer, the broker, the local registry and evidence sink on the proxy/operator host, MET-REPAIR-015's policy (with `deny_unknown=1`), cgroups, BPF programs and measurements; the node's LOCAL_REGISTRY trust file | Each component's own install check (elsewhere) |
| 8 | With admin, on the proxy/operator host: the launchers' bytes; the OPERATOR.md layout (lines 132-162: work root, precreated repository directories, `.git`, work siblings, sentinel); the dedicated `OPERATOR_UID` account and the login's trigger group; the signed-drop installer and the trigger units; the per-run private halves and their requests (root-owned 0400). On the node, with admin: the per-run cluster CA issues KUBERNETES_PROXY_SERVER_MTLS from its request, RBAC is bound to that leaf's exact subject, and the proxy/operator host installs the cluster CA certificate as its trust for the API server (B-LHA-2) | Modes, owners and digests as `launcher-install.json` lists; the requests exported |
| 9 | Freeze both host inventories; the root-alias check under MET-LINUX-009 | The inventories and both boot event logs exported; the alias check PASS, or stop |
| 10 | **T1, off host:** the owner compares the measured-boot records and the unchanged inventory entries with the image inventory, renders the offline policy (its inputs carry `imageDigest`) and signs it (LINUX_RUNNER_MANIFEST); the bundles and revocation material are refreshed. **Back on the host, with admin:** install the policy and the root-alias record, `custody.json` (OPERATOR.md step 6), the bundles and revocation material. **Then revoke:** `OWNER_ADMIN` removes the admin-login binding; wait for propagation; end every admin session on both hosts. | The signatures verify; the bundle digests recorded; the effective checks pass for both identities; the custom role's permission list equals the plan's; the session and sudoers checks pass |
| 11 | Preflight: the login writes the preflight trigger file; the preflight unit runs the offline launcher's `--operator-preflight` as `OPERATOR_UID`. Probe scope: the host's credentials and sockets, the trigger endpoints, no kubeconfig or runtime socket, the node reachable only on F1, the guest agent's and OS Login's local sockets, the metadata address | HOST_ISOLATION_NEGATIVES records; `boot_id`, kernel and notes digest recorded; the labels compared |
| 12 | **T2, off host, within one hour of the step-11 preflight** (the owner's Q-LHA-2 words), in order: the local CA issues the CAMPAIGN_PROXY server TLS and CAMPAIGN_PROXY_CLIENT_MTLS leaves from the step-8 requests; CAPACITY_OPERATOR signs the capacity authorization; PLATFORM_RELEASE and TENANT_LIVE_EXECUTION sign the envelope over the bundles installed at step 10; LINUX_RUNNER_MANIFEST signs the offline manifest and then the drop manifest. The live manifest is signed only after CONF-LIVE-005/006's own preflight; until they close, T2 signs none. | Every signature verifies; T2 ends within the hour; the envelope's bundle digests equal the installed bytes |
| 13 | The login writes the certificates, manifests and signatures and the drop manifest into the drop directory; the signed-drop installer installs them | The installer's log; the launchers' own verification |
| 14 | The campaign, inside the lease and the 168-hour window (`gate.maximumEvidenceAgeHours`; out of this packet) | — |
| 15 | **First, the access re-check** (Q-LHA5-1): the step-10 effective checks and permission-list comparison again, and the audit-log check from step 10. Then the export from both hosts through the export unit: the host nonce ledger, preflight records, the inventories, logs | The re-check and the audit-log check pass, or the run's evidence is refused; export digests in the owner's custody |
| 16 | Teardown per plan: `OWNER_ADMIN` revokes every binding granted since the lease started (the baseline role and bindings stay); the instances, their disks and the custom image are deleted, which ends the per-run private halves | The plan's teardown report with zero counts; the audit-log check's final span after the teardown completes |

## Launcher install (`launcher-install.json`)

Each step is an operator duty; the repository never installs anything. Each step names its input digests and its
rollback, which is teardown: the VMs are fresh per run. No step signs an unknown candidate by moving a trust digest.

**The signed-drop installer** (MON-LHA-12R; MON-LHA3-1-2) is a reviewed root component of this packet: a root-owned path
unit and helper (`/opt/planeon/bin/planeon-signed-drop-install`), installed at step 8 and covered by the host inventory.
It runs as root when the login writes into the drop directory `/var/lib/planeon/drop` (root-owned, mode 1730, the
login's group may write; the parent chain root-owned and not group or world writable, or it refuses). It uses the kit's
verification-only Ed25519 verifier with the pinned LINUX_RUNNER_MANIFEST key, adds no cryptography and has no
certificate-chain mode. **B-LHA-4:**
- the drop manifest has its own closed schema (`drop-manifest.schema.json`, `planeon.internal.linux-drop-manifest/v1`),
  and its detached Ed25519 signature covers its UTF-8 schema id, one 0x00 byte and its exact bytes, as the policy's
  signature is formed (BUILD_INPUTS.md lines 157-160); runner-manifest signing stays over the exact bytes alone, so a
  drop-manifest signature never verifies as a manifest or policy signature, and a runner manifest or policy offered as a
  drop manifest is refused;
- the drop manifest binds the plan sha256, the instance identity, the step-11 `boot_id` and a validity window ending no
  later than the lease; it authorizes placement only;
- it installs a file only if the drop manifest verifies, lists the file's exact target and sha256, and the target and
  mode are on the fixed list (design section 6: "one of a fixed list of `/etc/planeon` paths"; B-LHA-5: each drop
  target's exact path). The drop-manifest schema's `target` is an enum of exactly the fixed list's paths, and the
  checker requires that enum to equal `launcher-install.json`'s list and each listed path to have no empty, `.` or `..`
  segment, so a path-traversal target is refused; file handling: regular files only, no-follow opens, no hardlinks,
  a copy into the root-owned staging directory, the sha256 over the staged copy, an atomic rename into the target, the
  owner and mode from the fixed list. It refuses everything else and logs every attempt.

**The fixed list (B-LHA-5)**, each root-owned 0444 at the path its consumer reads: the CAMPAIGN_PROXY server TLS and
CAMPAIGN_PROXY_CLIENT_MTLS certificates under `/etc/planeon/credentials/`; the offline manifest and its signature at
`/etc/planeon/harness-runner-manifest.json` and `.json.sig` (the fixed contract paths of
`docs/TRUSTED_RUNNER_CONTRACT.md`); once CONF-LIVE-005/006 close, the live manifest and its signature. The preflight
record is retained and exported only, because no normal invocation reads it (within MON-LHA3-1-2). Certificate validity
is checked by the components that use them; each component's own contract reads its certificate at the listed path.

**The trigger units (B-LHA-1, MON-LHA-B1)**, one reviewed family beside the installer, each installed at step 8, covered
by the host inventory, with one fixed command and no operator arguments; the trigger is root-owned and open to the
login's group only, never to `OPERATOR_UID`:
- the **preflight unit** (proxy/operator host): `planeon-preflight.path` fires on the login's write of
  `/var/lib/planeon/trigger/preflight` (its content is not read), and `planeon-preflight.service` runs
  `/opt/planeon/bin/harness-offline-launch --operator-preflight` as `OPERATOR_UID`; it writes the preflight records and
  the journal;
- the **export unit** (both hosts): `planeon-export.socket` on `/run/planeon/export.sock` (root-owned, 0660) starts
  `planeon-export.service`, which runs `/opt/planeon/bin/planeon-export` as root and streams the fixed export set over
  the one connection; it writes nothing but the journal.

| Privileged action after step 10 | UID it runs as | How a login without admin starts it |
|---|---|---|
| step-11 preflight | `OPERATOR_UID` | the preflight unit |
| step-13 pickup | root | the signed-drop installer |
| step-14 launch | per CONF-LIVE-005/006 | their non-admin entry path, a precondition on them (section 10) |
| step-15 export | root | the export unit; it is every root-only record's read path |

**The policy's `operatorUid`** is a dedicated non-root local account, made at step 8 with admin, recorded by its role
label `OPERATOR_UID` only; it is not the login identity's OS Login account, and its name and UID appear in no published or
exported record.

**The offline launcher** (MET-LINUX-005's kit, `/opt/planeon/bin/harness-offline-launch`): `--operator-preflight` only,
for HOST_ISOLATION_NEGATIVES evidence; no GitHub runner and CI_CAPACITY_EXCEPTION.md does not apply. The manifest is
signed in T2 to bind the step-11 preflight, so the preflight evidence is "independently installed and signature-bound"
(OPERATOR.md lines 223-224); it serves no normal invocation here. From OPERATOR.md lines 125-167 the layout checks (lines
132-151) and the work siblings and sentinel (lines 153-162) apply; the runner settings (lines 125-128) and the
runner-binary check (lines 134-136) do not. OPERATOR.md steps 1 to 6 apply with one change of authority: the policy and
manifest are signed by **the new Linux runner key** ("Linux authority is separate from macOS"), whose public key is
`/etc/planeon/harness-runner-manifest.pub`; `custody.json` binds it and the launcher and policy digests, written at step
10.

**Which time limit binds each signed object:** the policy, at most 24 hours (BUILD_INPUTS.md line 139), from T1; the
manifests, signed within one hour of the preflight (Q-LHA-2, the owner); the envelope and the capacity authorization,
their own validity windows. **B-LHA-11:** OPERATOR.md lines 117-118's one-hour age is the launcher's check at a normal
invocation, which this host does not make.

**The live launcher** (Q-LHA-7 (a)), design only: its bytes are CONF-LIVE-005's packaging with CONF-LIVE-006's final
hook, both WAITING; root-owned 0555. Its manifest, `.sig` and public key follow TRUSTED_LIVE lines 34-38 and are signed
by the live runner key. TRUSTED_LIVE line 43 verifies a "pinned public-key digest": if their launcher embeds the pin, the
key ceremony comes before their reproducible build, and the install checks the installed pin against
`custody-model.json`. The preflight the live manifest binds (TRUSTED_LIVE lines 40-43) is theirs. The trust bundles are
mounted read-only (root-owned 0444) at `/etc/planeon/trust/release-trust-bundle.json` and `tenant-trust-bundle.json`,
installed at step 10. No manifest is signed before its preflight, and none by the other launcher's key. After the
revocation nothing under `/etc/planeon` changes except through the signed-drop installer under a verified drop manifest.

## Custody model (`custody-model.json`)

**Signing authorities**, one Ed25519 key each with distinct key ids, purposes, tokens and sealed backups, held by the
owner (role label `OWNER`), made offline on a machine that never connects, on a hardware token with one sealed offline
backup, rotated per release or on compromise, the Ed25519 import checked at the ceremony (Q-LHA-2 (a)); the ceremony
records public-key digests and purposes only and is pending (after merge):

| Authority | Signs | Session |
|---|---|---|
| LINUX_RUNNER_MANIFEST | the offline policy (T1), the offline manifest and the drop manifest (T2) | T1, T2 |
| LIVE_RUNNER_MANIFEST | the live runner manifest, only after CONF-LIVE-005/006's own preflight | T2 |
| PLATFORM_RELEASE | the envelope's platform signature; release material and the release trust bundle's revocation | T1, T2 |
| TENANT_LIVE_EXECUTION | the envelope's tenant signature; the tenant trust bundle's revocation | T1, T2 |
| CAPACITY_OPERATOR | the capacity authorization: endpoints, namespace, `credentialIdentities`, its nonce (TRUSTED_LIVE lines 204-209, 279) | T2 |

The drop manifest authorizes placement only: the live launcher still verifies the live manifest under
LIVE_RUNNER_MANIFEST (B-LHA-4). The bundles are authored under PLATFORM_RELEASE and TENANT_LIVE_EXECUTION custody, their
digests sit in the signed envelope, they are refreshed in T1 and installed at step 10, and the route is local custody
transfer only, with no network lookup (TRUSTED_LIVE lines 179-186).

**Per-run credentials**, each from a step-8 request on the proxy/operator host, private half root-owned 0400, never
reused, ending when the instances and their disks are deleted, and named in the capacity authorization's
`credentialIdentities`:
- **the release-pinned local CA** (TRUSTED_LIVE lines 226-228, 236-238): the owner's, offline on a token supporting its
  algorithm with a sealed backup (Q-LHA-16 (2)), rotated per release. It issues, in T2, the CAMPAIGN_PROXY server TLS
  identity and CAMPAIGN_PROXY_CLIENT_MTLS (CREDENTIAL_ORDERING_REPAIR.md lines 50-52, whose "purpose grants no
  Kubernetes access", line 62). Their certificates arrive by the signed drop.
- **B-LHA-2: the per-run cluster CA**, made at step 7 on the node, issues KUBERNETES_PROXY_SERVER_MTLS at step 8 from
  its request, with admin; no new key or token. The API server's client trust holds only the cluster CA, never the local
  CA; RBAC is bound to that leaf's exact subject only, with no privileged group; the proxy/operator host trusts the
  cluster CA. No local-CA leaf authenticates to the API server.

**Endpoint server identities (B-LHA-7):** KUBERNETES_API_PROXY and CAMPAIGN_PROXY are served by **one** per-run server
TLS identity of this custody model (issuer the local CA, on the proxy/operator host, generated at step 8, ending with the
instance); it is in step 8's requests, T2's issuance, the drop list and `credentialIdentities`. LOCAL_REGISTRY and
LOCAL_EVIDENCE_SINK server identities are the campaign release's (G10), which names their issuer, custody and lifetime.

**Live custody duties** (Q-LHA-3 (a), restated): a signing registry in the owner's custody outside GCP that never signs
the same envelope or capacity nonce twice; a root-owned durable host ledger for the launcher, proxy-client and server
reservations, exported at step 15 and retained; cross-host replay closed by the envelope binding the endpoint address,
the server's fresh per-run SPKI and the validity window; host chrony plus the launchers' window checks; revocation
refreshed by local transfer in T1 and installed at step 10; the evidence store in the owner's custody from step 15.

**Independence** (Q-LHA-1 (a)): TRUSTED_LIVE requires distinct keys and identities ("neither role can satisfy the
other", line 177; CAPACITY_OPERATOR is "an independent third authority", lines 188-189). With one owner the keys are
distinct and held apart, not held by independent people, so the clause is superseded with its replacement predicate and
the custody model carries the disclosure `signers: SINGLE_PRINCIPAL_SEPARATED_KEYS` with the owner's answer verbatim.
Two evidence carriers need the disclosure before their runs, both preconditions: R12's closed evidence record
(CONF-LINUX-002) and CONF-LIVE-006's adapter (TRUSTED_LIVE lines 462-463).

## Carried notes (notes, not settled claims)

- **LHA-CN-1** (in `host-authority.json`): R12's live envelope requires `mutationProfile`
  ZERO_INCREMENTAL_COST_KUBERNETES_V1 and non-metered endpoint cost dispositions. Both concern in-cluster mutation and
  the endpoint, not the host's per-run compute that the lease bills: on paper compatible, not settled. Checked in this
  packet's CONTRACT round.
- **LHA-CN-2** (in `custody-model.json`): a single-principal CONF-LINUX-001 run under this contract uses R12's v1alpha2
  path (CONF-LINUX-002) with `signers` SINGLE_PRINCIPAL_SEPARATED_KEYS; the disclosure's honesty rests on the owner's
  custody of the trust bundles, not on R12 code. Carried into the custody model and the run plan; checked in the CONTRACT
  round.

## Vectors

`vectors.json` replays two positive sets (the published records, and the same set on another allowed image family to
show the family is data, not code) and 205 negatives against the four records: 33 on the authority (digests, member
paths, every kept predicate relaxed, the independence clause without its replacement, answer or disclosure, readings,
evidence states, decisions, role labels), 101 on the recipe (section 8 and B-LHA-5, 6, 8, 9, 10, 13 to 18), 38 on the
launchers (section 8 and B-LHA-1, 4, 5, 11) and 33 on custody (section 8, the string rule and B-LHA-2, 4, 7,
LHA-CN-2). A drop-manifest positive with 10 negatives, 4 signature rows and 8 parse negatives cover B-LHA-4, the fixed
target list and the parse rules. Each negative names the rule it backs and its recorded refusal.

## Preconditions outside this packet

- the root-alias contract MET-LINUX-009 (MON-LHA-17), before the first plan: merged as this packet's base;
- R12's `signers` evidence change CONF-LINUX-002 (Q-LHA-1), before the first CONF-LINUX-001 run;
- CONF-LIVE-006's adapter carrying the disclosure, before the live-path qualification;
- the live launcher's entry path for a login without admin, in CONF-LIVE-005/006 (MON-LHA-B1);
- CONF-LIVE-003 to CONF-LIVE-006 and MET-REPAIR-015 closed at source, before any live run;
- the kernel's independent qualification against MET-REPAIR-015's interface and record.

## Not claimed

- No GCP project, VM, key or spend exists or is created by this packet. Rate cards, image names and package versions are
  pinned per plan at setup.
- Approving capacity is not qualification; Linux evidence states do not move. Until CONF-LIVE-005/006 close, a lease
  yields only HOST_ISOLATION_ONLY preflight evidence, which is not a native qualification.
- The identity beyond the boot chain is operator-attested, under the stated reading of BUILD_INPUTS.md lines 95-103.
- No deny policy is used. That a custom role can be defined without `compute.instances.osAdminLogin` and the
  IAM-changing permissions and granted on the run project is on paper, like the other GCP facts.
- The access checks hold at the moment each runs. Group, domain, principal-set, folder and organization grants are
  detected only by the step-10 and step-15 effective checks, not blocked; a grant made and removed between them, or made
  after step 15, is not detected (the owner's Q-LHA5-1; B-LHA-14). The audit log does not detect them.
- GCP and systemd facts are on paper: the IAP range; image families with their kernels, root filesystems and licensing;
  the internal time service; OS Login, its roles and its sudoers entries; metadata keys; guest-agent features; firewall
  behaviour toward the metadata server; the maximum-run-duration delete action; the permission names; path and socket
  units.
