# Closed Linux build inputs — MET-LINUX-002

This specification is local operator-kit configuration, not a tenant wire API
or a change to `schemas/trusted-runner-manifest.schema.json`. The executable
closed validators are `common.validate_inputs` and `launcher.validate_policy`.
Unknown fields, duplicate JSON names, nonfinite values and unsafe paths fail.
All digests below are exact-byte lowercase SHA-256, without a prefix unless
explicitly stated. No sample digest in a unit test is operational authority.

## Build-input object

Exactly `schemaVersion`, `target`, `tools`, `caches`, `systemTrees`,
`systemFiles`, `source`, `recipes`:

- `schemaVersion`: `planeon.linux-build-inputs/v1`.
- `target`: exactly `os=linux`, `architecture=amd64|arm64`,
  `libc=glibc|musl`, numeric dotted `libcVersion`, `execution=NATIVE`,
  and `imageDigest=sha256:<64 hex>` for the operator's existing immutable host
  image. Runtime verifies the observable libc; an unobservable musl version
  cannot pass. Other libc targets require reviewed detection, not a guessed label.
- `tools`: a closed named map containing python, firejail and git, optionally
  uv, node, npm and make. Each record has exactly `path`, `version`, `root`,
  `inventorySha256`. Python is exactly 3.12.14 at
  `/opt/planeon/python/3.12.14/bin/python3.12`; Firejail is `/usr/bin/firejail`.
  Every required tool for the actual packet must be present. Missing executables
  fail; there is no PATH search outside the supplied locked tool directories.
- `caches`: nonempty records with exactly `root`, `inventorySha256`, `os`,
  `architecture`, `libc`, `tool`; target fields must match `target`, and `tool`
  must name a supplied pinned tool. No mutable or absent cache is admitted.
- `systemTrees`: unique `root`/`inventorySha256` records covering at least
  `/usr/lib` and `/etc/firejail`, optionally `/usr/lib64` and `/usr/libexec`.
  Pin all helper/native-library/configuration closures for the selected immutable
  host image. The same exhaustive ownership/inventory rules apply.
- `systemFiles`: exactly `/etc/ld.so.cache` and its byte digest. Global
  `/etc/ld.so.preload` is forbidden. This initial closure requires an observable
  glibc-compatible loader cache; unsupported musl layouts cannot qualify by
  borrowing glibc evidence.
- `source`: exactly `repository`, `commit`, `treeSha256`. Repository is the
  owned harness-onion or mas-harness-* family; a warm repository is forbidden.
  Commit is 40 lowercase hex characters, not a branch or tag. Tree digest covers
  `common.inventory(workspace, source=True)`. Only root `.git` transport metadata
  is excluded; hidden/untracked files and old build outputs are NOT excluded.
  The pinned Git executable separately verifies actual HEAD inside isolation.
- `recipes`: exactly `packet=SIGNED_PACKET_WRAPPER`,
  `nextStandalone=LINUX_TARGET_BUILD_ONLY`, `downloads=DENIED`,
  `hostOutputReuse=DENIED`. Build argv come only from the signed packet, not an
  arbitrary recipe string or imported script.

An inventory is a UTF-8-bytewise path-sorted JSON array. Every file entry has
exactly `path` (relative POSIX), `mode` (four octal digits), `size` (bytes), and
`sha256` (exact contents). Empty directories and timestamps are excluded.
Canonical inventory encoding uses ASCII-escaped JSON, sorted object keys,
comma/colon separators and no trailing newline. Hash that encoding. Symlinks,
hardlinks, FIFOs, sockets, devices and unknown entries fail. Changes during a
read fail; atime alone is not an integrity field. All tool/cache files and
directories must be root-owned and not group/world writable. The operator must
stage regular-file Linux closures, not point at symlinked workstation caches.
A stock distribution library tree containing SONAME symlinks is not silently
accepted: the external immutable runner image must supply a reviewed regular-file
closure. This is a strict candidate prerequisite, not a claim of out-of-box
compatibility with every distribution.

Distinct tool/cache roots may not overlap each other, the workspace, runner
home, trust or warm container. Tools sharing one root must have the same
exhaustive inventory digest. System helper/configuration/library trees and
loader-cache bytes are verified too; ELF headers alone do not establish closure.

## Signed execution policy

Exactly these fields:

| Field | Constraint |
| --- | --- |
| schemaVersion | planeon.linux-runner-policy/v1 |
| issuedAt / expiresAt | Integer epoch seconds; current, ordered, maximum 24 hours |
| operatorUid / operatorName | Dedicated non-root numeric UID and safe local name |
| workspace | One canonical direct child of /opt/planeon/work |
| runnerHome | One canonical direct child of /srv/planeon, disjoint from work/sources |
| packetSha256 | Exact fixed /opt/planeon/packet/active.yaml bytes |
| warmContainer | /srv/planeon/warm-snapshots, root-owned and non-writable by runner |
| warmRoots | Complete unique direct-child directories of warmContainer; empty allowed only when container is empty |
| inputs | Closed build-input object above |
| profileSha256 | Exact deterministic Firejail profile bytes |
| transportPins | Exactly ci/verify-offline.sh, ci/run_packet_argv.py, ci/network_canary.py and their reviewed digests |
| environment | Only pinned UV_PROJECT_ENVIRONMENT, UV_CACHE_DIR, VIRTUAL_ENV, NPM_CONFIG_CACHE, PLAYWRIGHT_BROWSERS_PATH references |

The operator request to `prepare.py` contains all these fields except
`profileSha256`, which is computed. The renderer emits only unsigned candidate
data in a new caller-owned private directory. It neither reads warm contents
nor signs, installs, downloads, builds an image, contacts a registry or executes
a packet.

Detached raw 64-byte Ed25519 policy signature covers:
`UTF8("planeon.linux-runner-policy/v1\u0000") || exact policy.json bytes`.
No RFC 8785 claim is made for this private byte-signed format. Manifest signing
is unchanged: detached Ed25519 over exact manifest bytes. Public key is strict
Ed25519 SPKI PEM, pinned by exact PEM-byte SHA-256 in root image custody.

## Native product recipes and evidence

Before a Linux-target product build the external operator supplies a clean
source tree, native ELF Python/Node/Git and architecture/libc-specific local
wheel/npm/browser caches. Python, Firejail and Git ELF machine IDs are checked
before execution; the whole inventories bind other native dependencies too.
No Darwin `.next/standalone`, `node_modules`, virtualenv, wheel, Mach-O or MLX
output is reusable as a Linux release input. Create standalone Next.js output
inside that Linux target using the existing packet's frozen offline build argv.

The kit does not provision or directly build containers. Product image/SBOM,
build-log, source-lock, base-image, recipe and cache digests must later be bound
by CONF-LINUX-001's independent evidence. Merely putting an image digest or
NATIVE string in this configuration does not qualify a release or prove physical
hardware. Native AMD64 and native ARM64 need separate external observation.
