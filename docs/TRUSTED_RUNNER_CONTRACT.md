# Trusted Self-Hosted Runner Contract

`/opt/planeon/bin/harness-offline-launch` is an out-of-repository prerequisite,
not a file installed or updated by a pull request. The exact root-owned authority
is `/etc/planeon/harness-runner-manifest.json`, validated against
[`trusted-runner-manifest.schema.json`](../schemas/trusted-runner-manifest.schema.json).
Its detached signature and public key are respectively fixed at
`/etc/planeon/harness-runner-manifest.json.sig` and
`/etc/planeon/harness-runner-manifest.pub`.

The launcher refuses unless the signature verifies, the pinned public-key digest
matches runner-image custody, its own version and SHA-256 match the manifest, and
the launcher is UID/GID 0 mode `0555`. The manifest also admits only the exact
runner labels `self-hosted`, `harness-engineering`, `ephemeral`, and
`credential-free`, records the exhaustive canonical `isolation.warmSourceRoots`
array used to construct the child-denied environment, and carries a passing
immutable preflight evidence digest covering
network, warm-root, packet-write, credential, and socket denial. GitHub Actions
performs one pinned checkout with credential persistence disabled and invokes
the absolute launcher as its only `run` step.

No launcher binary, signed manifest, public key, or preflight evidence is present
in this planning repository. Provisioning that root-owned bundle on a matching
ephemeral runner is the explicit external prerequisite for CI; until then the
workflow remains queued or blocked and no packet may claim CI evidence. A Sol run
must not fabricate a digest, key, signature, version, preflight result, or runner
label to satisfy this prerequisite.

Before opening or executing any checked-out file, the host launcher must:

1. Resolve the checkout and every observer-owned warm snapshot to canonical,
   non-overlapping paths from a root-owned runner manifest. The manifest supplies
   the exhaustive newline-delimited `HARNESS_WARM_SOURCE_ROOTS` value; `NONE` is
   valid only when the host proves that no snapshot is mounted.
2. Establish deny-all network isolation. On macOS it must also deny read,
   metadata, and write access to each warm root. On Linux it must create an
   equivalent mount/filesystem boundary that hides or blacklists each root and
   keeps it read-only as defense in depth. Failure to establish either boundary
   blocks execution.
3. Remove cloud/provider/API-key variables, `SSH_AUTH_SOCK`, kubeconfig and
   container-client variables; hide default credential directories; and remove
   access to Docker, containerd, Podman, Kubernetes-agent, SSH-agent, and similar
   Unix sockets. The runner image contains no ambient billable credentials.
4. Remove `HARNESS_WARM_SOURCE_ROOTS` and every canonical warm path from the
   child environment and command line. Hide the runner manifest, signature,
   public key, preflight evidence, and root inventory from repository children.
   Set only the non-secret isolation proof markers required by the repository
   network canary.
5. Enter the canonical checkout and execute `./scripts/verify_offline.sh` without
   a shell command string. Repository shell, Python, Make, hooks, and tests begin
   only at this point, inside the established boundary.

The repository launcher retains an independently usable macOS/Linux fail-closed
boundary for local verification. It is an inner defense and packet-contract
implementation; it is not the GitHub workflow trust boundary. A pull request may
not change the workflow to call it directly or add any earlier repository command.

The repository packet executor passes children a closed environment allowlist,
not a filtered copy of the caller environment. Only local process identity,
workspace, temporary-directory, locked-toolchain, and non-secret isolation proof
variables survive. The task-packet path, warm-source paths, cloud/provider
variables, credentials, agent sockets, kubeconfig, container configuration, and
all unknown variables are absent from packet commands.

The outbound canary is evidence only when the named backend returns an error
code produced by its OS isolation mechanism. A timeout, DNS error, unreachable
route, or coincidentally disconnected host does not prove isolation and fails
closed. The packet digest is rechecked after the canary and after every declared
prefetch or acceptance argv.
