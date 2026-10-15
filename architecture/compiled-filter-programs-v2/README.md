# Compiled seccomp filter programs v2: EFFECT_GATE republished from seccomp allowlists v4 (MET-ENFORCE-029)

Status: **SUCCESSOR_CANDIDATE_AWAITING_INDEPENDENT_REVIEW**. Roadmap item PROGRAMS-REPUBLISH, harness-onion slot 240
(planned packet MET-ENFORCE-029); review rounds and adoption are recorded in `status.json`. DATA_CHECK_ONLY: published
data, no runtime, selector, catalog or schema change. MET-ENFORCE-025's `architecture/compiled-filter-programs/` stays
byte-identical.

Seccomp allowlists v4 (`architecture/seccomp-allowlists-v4/`, MET-ENFORCE-027, merged as `e7516160`) is v3 with one rule
added: EFFECT_GATE may call `readlinkat` only with a non-negative dirfd, `(arg0 & 0x80000000) == 0`. Only EFFECT_GATE's
compiled program changes, on both architectures; v4's `filterDigests` and `programLengths` for the other six roles equal
v3's. This directory republishes EFFECT_GATE's two programs from v4 and indexes all fourteen v4 programs. The other twelve
are MET-ENFORCE-025's files: the publisher proves them byte-identical and does not re-emit them. Allowlists v4 left this
step open ("the compiled filter programs and the edge record are republished from v4 (Q-HE3A-1b)",
`architecture/seccomp-allowlists-v4/status.json`); `status.json` here records the discharge, and v4's own files stay
byte-identical.

## Decisions

- Q-HE3A-1 = (c), 2026-10-13, owner via the lane monitor, as `architecture/host-interface-amendment-hs43/amendment.json`
  records it: "(c) readlink exe for the I07 writer".
- Q-HE3A-1b = (a), 2026-10-13, owner via the lane monitor, as the same record holds it: "(a) HE-003A merges first; the
  readlink exe check is decided-but-open, landing after the chain: seccomp v3 readlinkat duty for EFFECT_GATE (parallel
  lane, with/after the slot-234 §4.3 amendment) → republished programs + edge record v3 (primary) → R10 re-vendor +
  check. HE-007 obligations: writer uid/gid 0, dumpable, empty permitted set." Allowlists v4 was the first step; this
  contract is the second; R10's HE-003A2 is the third.
- Q-HE3D-3 = (a), 2026-10-15, the lane monitor under the owner's delegation (HE-003D decisions): "the writer exe check
  isn't in HE-003D. It goes in HE-003A2 after the seccomp and programs chain merges; the enrolled path comes from the
  configuration (G4)."
- Q-PR-1..10 = (a), 2026-10-15, the lane monitor under the owner's delegation; the message, verbatim:

  > [lane monitor] PROGRAMS-REPUBLISH: Q-PR-1..10 = (a), all of them. Monitor (owner-delegated), 2026-10-15; record verbatim.
  > - a new architecture/compiled-filter-programs-v2/;
  > - only EFFECT_GATE re-emitted, with the other 12 proven equal to 232's bytes;
  > - edge record v3 = v2's 31 rows plus 2;
  > - the R10 consumer path contracts/seccomp-v4/;
  > - the other rows unchanged;
  > - the pinned v4 model plus the exact 6-instruction-block layer check;
  > - v4 vector replay;
  > - a status.json adoption discharging v4's obligation;
  > - no riders;
  > - MET-ENFORCE-029, with the contract reviewed on 9f251d5 and rebased unchanged onto 239's merge at mechanics time.
  > Go ahead with the contract design and the independent review, as light work.

## Files

| File | Content |
|---|---|
| `programs/EFFECT_GATE.<arch>.bpf` | v4's EFFECT_GATE program on `aarch64` and `x86_64` |
| `index.json` | `planeon.internal.compiled-filter-programs/v2`: all fourteen v4 programs, each with its role, architecture, repository-relative path (two here, twelve at MET-ENFORCE-025's paths), instruction count, byte count and SHA-256; the v4 source commit and the SHA-256 of each v4 source used; MET-ENFORCE-025's index by SHA-256 |
| `status.json` | Contract state, review rounds, owner decisions, the discharge of v4's open item and the work carried to R10 |
| `REVIEW_BRIEF.md` | The independent contract review's brief |
| `../../scripts/compiled_filter_programs_v2.py` | The publisher and checker: `--write` writes the two programs and `index.json`; without arguments it checks them |
| `../artifact-edges/operator-harness-engineering-v3.json`, `../artifact-edges/README-v3.md` | Edge record v3, which registers the two programs for R10 |

## Format and derivation

Each file is the kernel's `struct sock_filter` array as `seccomp(SECCOMP_SET_MODE_FILTER, …)` receives it: 8 bytes per
instruction, little-endian (`u16 code, u8 jt, u8 jf, u32 k`), exactly the bytes the pinned model's `program_bytes` returns
(the same format as MET-ENFORCE-025's). The publisher reads the v4 model (`scripts/seccomp_allowlists_v4.py`), policy
(`allowlists.json`), syscall table (`syscalls.json`) and vectors (`vectors.json`) from their published bytes, refuses any
whose SHA-256 differs from the value it pins (and `index.json` records; they equal allowlists v4's reviewed round-3
subject), and executes the verified model bytes (no import, so no cached bytecode). It runs `compile_filter` and
`program_bytes` for every role and architecture and requires:

- each program's SHA-256 and instruction count to equal v4's `filterDigests` and `programLengths`;
- the twelve programs of the other six roles to equal, byte for byte, MET-ENFORCE-025's files, which must equal
  MET-ENFORCE-025's index, itself pinned by SHA-256;
- each EFFECT_GATE program to equal MET-ENFORCE-025's v3 EFFECT_GATE program with exactly the six instructions below
  inserted at the recorded index, and nothing else different (Q-PR-6);
- every v4 EFFECT_GATE decision vector, run through the published bytes with the model's `run_filter`, to give its
  recorded action (Q-PR-7): 401 vectors, 206 on x86_64 and 195 on aarch64.

The model is not edited or copied; allowlists v4 and MET-ENFORCE-025's directory stay byte-identical.

| Role | aarch64 | x86_64 | Published at |
|---|---|---|---|
| BROKER | 311 | 326 | `architecture/compiled-filter-programs/programs/` |
| **EFFECT_GATE (changed)** | **189** (v3: 183) | **200** (v3: 194) | `architecture/compiled-filter-programs-v2/programs/` |
| HOST_CONTAINMENT | 130 | 141 | `architecture/compiled-filter-programs/programs/` |
| OBSERVER | 227 | 238 | `architecture/compiled-filter-programs/programs/` |
| POLICY_WRITER | 115 | 126 | `architecture/compiled-filter-programs/programs/` |
| SERVER | 261 | 276 | `architecture/compiled-filter-programs/programs/` |
| WORKER | 172 | 187 | `architecture/compiled-filter-programs/programs/` |

(instructions; each program is 8 bytes per instruction)

| Program | Instructions | Bytes | SHA-256 | v3 program (MET-ENFORCE-025) |
|---|---|---|---|---|
| `EFFECT_GATE.aarch64.bpf` | 189 | 1512 | `sha256:8de80a2b597b84d9f5ace818e76ef15d4b15a5b02013bb479ca4fdf73df3d044` | 183, 1464 bytes, `sha256:0ccbd7d0…7105a` |
| `EFFECT_GATE.x86_64.bpf` | 200 | 1600 | `sha256:4e516f1682098c90edd568f8f214d3de01b404a2c144104596fc4e3262f6e7a3` | 194, 1552 bytes, `sha256:ee85e9d2…86115` |

## The six-instruction block

`compile_filter` emits one number test per allowed syscall in ascending number order, each followed by its own body, and
every jump stays inside its own syscall's block. v4's rule therefore adds one block at the `readlinkat` number's sorted
position, and nothing else in the program moves or changes:

| Architecture | `readlinkat` nr | Inserted at instruction index | Between |
|---|---|---|---|
| x86_64 | 267 (0x10b) | 173 | 257 `openat` and 271 `ppoll` |
| aarch64 | 78 (0x4e) | 34 | 73 `ppoll` and 80 `fstat` |

| # | Instruction (`code jt/jf k`) | Bytes (little-endian) |
|---|---|---|
| 1 | `JEQ_K 0/5 nr`: the syscall number test | x86_64 `150000050b010000`, aarch64 `150000054e000000` |
| 2 | `LD_W_ABS 0/0 0x10`: arg 0's low 32 bits | `2000000010000000` |
| 3 | `AND_K 0/0 0x80000000`: keep bit 31 | `5400000000000080` |
| 4 | `JEQ_K 0/1 0x0`: bit 31 clear | `1500000100000000` |
| 5 | `RET 0x7fff0000`: ALLOW | `060000000000ff7f` |
| 6 | `RET 0x80000000`: KILL_PROCESS | `0600000000000080` |

The replay includes v4's 20 EFFECT_GATE `readlinkat` vectors, 10 per architecture. A dirfd of 0, 3, 0x7fffffff or
0xffffffff00000000 (high word ignored) is allowed. AT_FDCWD (0xffffffffffffff9c and 0xffffff9c), -1 and 0x80000000 kill the
process.

## Consumers

Edge record v3 (`architecture/artifact-edges/operator-harness-engineering-v3.json`) registers the two programs for the
operator repository (R10): consumer packet HE-003A2, consumer paths
`host-enforcement/contracts/seccomp-v4/EFFECT_GATE.<arch>.bpf`, BYTE_IDENTICAL, REGISTERED_BEFORE_USE (Q-PR-4). The twelve
unchanged programs keep their v2 registrations (Q-PR-5), and SERVER's stay PUBLISHED_UNREGISTERED. v2's EFFECT_GATE rows
are carried as recorded; R10 has held those v3 programs since HE-002S.

Carried to R10's HE-003A2 (R10's work; listed in `status.json`):

- vendor the two files at `host-enforcement/contracts/seccomp-v4/`, and decide whether `contracts/seccomp-v3/EFFECT_GATE.*`
  stays (R10's contract check refuses any unpinned file under `contracts/`);
- `PROVENANCE.md`;
- `gate.py`'s `CONTRACTS` and its test's contract-file count;
- the seal's `include_bytes!` paths, its length pins 194/183 → 200/189, and its digest and size pins;
- `readlinkat` leaves `KILLED_WRAPPERS`: under v4 it is argument-filtered on both targets;
- `MODEL_DEFINED.md`'s "After the seal" rows;
- the writer executable check itself: `readlinkat` on the retained `/proc/<pid>` directory descriptor, compared with the
  enrolled writer path from configuration format v2 (Q-HE3D-3 (a), O-W03-WRITER-EXE);
- HE-003D PR N1/N2.

## Not claimed

- R10's adoption: vendoring, pinning, embedding and installing these programs are HE-003A2's.
- Linux behaviour under the installed filter: the boot-time proof that the installed filter equals the published digest
  stays T04/W02a-F's (W02d-Q3). The writer executable check stays decided but open (O-W03-WRITER-EXE).
- The other roles' consumers: their programs and registrations are unchanged from MET-ENFORCE-025 and edge record v2.
- No new seccomp decision: the rule is allowlists v4's, reviewed in MET-ENFORCE-027; this contract compiles it.
