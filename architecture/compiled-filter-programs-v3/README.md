# Compiled seccomp filter programs v3: OBSERVER republished from seccomp allowlists v5 (MET-ENFORCE-036)

Status: **SUCCESSOR_CANDIDATE_AWAITING_INDEPENDENT_REVIEW**. Roadmap item SECCOMP-OBSERVER-LISTENER, packet 2 of 2,
harness-onion slot 249 (packet MET-ENFORCE-036); review rounds and adoption are recorded in `status.json`.
DATA_CHECK_ONLY: published data, no runtime, selector, catalog or schema change. MET-ENFORCE-025's
`architecture/compiled-filter-programs/` and MET-ENFORCE-029's `architecture/compiled-filter-programs-v2/` stay
byte-identical.

Seccomp allowlists v5 (`architecture/seccomp-allowlists-v5/`, MET-ENFORCE-035, merged as `f4bb0000`) is v4 with one
OBSERVER duty added, the I01 listener of W01 amendment HS53: `bind` and `listen` unconditioned, and `accept4` only when
the low 32 bits of arg 3 (flags) equal 0, SOCK_CLOEXEC (0x80000) or SOCK_CLOEXEC|SOCK_NONBLOCK (0x80800). Only OBSERVER's
compiled program changes, on both architectures; v5's `filterDigests` and `programLengths` for the other six roles equal
v4's. This directory republishes OBSERVER's two programs from v5 and indexes all fourteen v5 programs. The other twelve
are the files MET-ENFORCE-029's index lists (EFFECT_GATE's in `compiled-filter-programs-v2/`, the other ten in
`compiled-filter-programs/`): the publisher proves them byte-identical and does not re-emit them.

HS53 and allowlists v5 left this step open: obligation O-PROGRAMS-V3-OBSERVER
(`architecture/host-interface-amendment-hs53/amendment.json`) and v5's open item "OBSERVER's compiled programs and the
edge record are republished from v5 (O-PROGRAMS-V3-OBSERVER)" (`architecture/seccomp-allowlists-v5/status.json`).
`status.json` here records the discharge of both; HS53's and v5's own files stay byte-identical.

## Decisions

- Q-SOL-1 = (a), 2026-10-17, the lane monitor (owner-delegated), as `architecture/host-interface-amendment-hs53/amendment.json`
  records it: "Q-SOL-1 (a): two packets, (1) the W01 amendment (OBSERVER row, I01 only) plus seccomp v5, and (2) programs
  v3 plus edge v5. The stale H:446-447 pointer gets fixed in packet 1." Packet 1 was MET-ENFORCE-035; this is packet 2.
- F-SOL-1's note, 2026-10-17, the lane monitor, as the same record holds it: "Note: "edge v5" for packet 2 will collide in
  name with native-profile v4's edge record v5 (slot 246). Check the next free edge version at drafting time; it is
  probably v6." Edge record v5 is MET-ENFORCE-033's, so the record here is v6.
- Q-P2-1, -3 and -4 = (a), 2026-10-18, the lane monitor under the owner's delegation; the message, verbatim:

  > SLOT 249 = MET-ENFORCE-036 is confirmed (not on main, unclaimed), branch codex/met-enforce-036-observer-programs-v3,
  > and harness-onion-obsprog is registered as your worktree. Monitor decisions, consistent with 240's owner-approved
  > PROGRAMS-REPUBLISH pattern (I'll tell the owner): Q-P2-1 (a): only OBSERVER's two programs plus the index of 14.
  > Q-P2-3 (a): keep the seccomp-v3 OBSERVER rows for HE-004 unchanged. Q-P2-4 (a): one or two light contract-review
  > rounds, then adoption, then mechanics on template 248, then the packet review. Q-P2-2: I've asked the primary for the
  > HE-004-I01 vendor path(s), path level only, and will relay the answer. Until then, draft the rows as (a) with the
  > seccomp-v5/ path. GO for the contract draft and the contract review rounds (light work). The pre-check, dry run and
  > push need my word.

- Q-P2-2 = (a), 2026-10-18, the lane monitor relaying the primary lane's facts at path level; the message, verbatim:

  > Q-P2-2 = (a), with the primary lane's facts at path level: HE-004-I01 vendors
  > host-enforcement/contracts/seccomp-v5/OBSERVER.x86_64.bpf and host-enforcement/contracts/seccomp-v5/OBSERVER.aarch64.bpf,
  > mode 100644, REGISTERED_BEFORE_USE. This follows R10's convention contracts/seccomp-v<N>/<ROLE>.<arch>.bpf, where N is
  > the seccomp contract version compiled from. No other file is decided. R10 has never vendored allowlists or spec
  > texts, so v5's allowlists and HS53's effective spec need no rows. A possible I01 wire vector comes in a later edge
  > record. The v3 OBSERVER rows stay unchanged, per Q-P2-3 (a). Register the two .bpf rows only.

The quotes above are line-wrapped; `status.json` and edge record v6 hold the same four texts as one string each.

## Files

| File | Content |
|---|---|
| `programs/OBSERVER.<arch>.bpf` | v5's OBSERVER program on `aarch64` and `x86_64` |
| `index.json` | `planeon.internal.compiled-filter-programs/v3`: all fourteen v5 programs, each with its role, architecture, repository-relative path (two here, two at MET-ENFORCE-029's paths, ten at MET-ENFORCE-025's), instruction count, byte count and SHA-256; the v5 source commit and the SHA-256 of each v5 source used; MET-ENFORCE-029's index by SHA-256 |
| `status.json` | Contract state, review rounds, decisions, the discharge of HS53's and v5's open items and the work carried to R10 |
| `REVIEW_BRIEF.md` | The independent contract review's brief |
| `../../scripts/compiled_filter_programs_v3.py` | The publisher and checker: `--write` writes the two programs and `index.json`; without arguments it checks them |
| `../artifact-edges/operator-harness-engineering-v6.json`, `../artifact-edges/README-v6.md` | Edge record v6, which registers the two programs for R10 |

## Format and derivation

Each file is the kernel's `struct sock_filter` array as `seccomp(SECCOMP_SET_MODE_FILTER, …)` receives it: 8 bytes per
instruction, little-endian (`u16 code, u8 jt, u8 jf, u32 k`), exactly the bytes the pinned model's `program_bytes` returns
(the same format as MET-ENFORCE-025's and MET-ENFORCE-029's). The publisher reads the v5 model
(`scripts/seccomp_allowlists_v5.py`), policy (`allowlists.json`), syscall table (`syscalls.json`) and vectors
(`vectors.json`) from their published bytes, refuses any whose SHA-256 differs from the value it pins (and `index.json`
records; they are MET-ENFORCE-035's merged bytes), and executes the verified model bytes (no import, so no cached
bytecode). It runs `compile_filter` and `program_bytes` for every role and architecture and requires:

- each program's SHA-256 and instruction count to equal v5's `filterDigests` and `programLengths`;
- the twelve programs of the other six roles to equal, byte for byte, the files MET-ENFORCE-029's index lists, which must
  equal that index, itself pinned by SHA-256;
- each OBSERVER program to equal the earlier OBSERVER program (MET-ENFORCE-025's, which MET-ENFORCE-029's index lists)
  with exactly the two blocks below inserted at the recorded indexes, and nothing else different (Q-P2-1);
- every v5 OBSERVER decision vector, run through the published bytes with the model's `run_filter`, to give its recorded
  action: 523 vectors, 267 on x86_64 and 256 on aarch64, 44 of them `bind`, `listen` or `accept4`.

The model is not edited or copied; allowlists v5 and both earlier program directories stay byte-identical.

| Role | aarch64 | x86_64 | Published at |
|---|---|---|---|
| BROKER | 311 | 326 | `architecture/compiled-filter-programs/programs/` |
| EFFECT_GATE | 189 | 200 | `architecture/compiled-filter-programs-v2/programs/` |
| HOST_CONTAINMENT | 130 | 141 | `architecture/compiled-filter-programs/programs/` |
| **OBSERVER (changed)** | **242** (v4: 227) | **253** (v4: 238) | `architecture/compiled-filter-programs-v3/programs/` |
| POLICY_WRITER | 115 | 126 | `architecture/compiled-filter-programs/programs/` |
| SERVER | 261 | 276 | `architecture/compiled-filter-programs/programs/` |
| WORKER | 172 | 187 | `architecture/compiled-filter-programs/programs/` |

(instructions; each program is 8 bytes per instruction)

| Program | Instructions | Bytes | SHA-256 | Earlier program (MET-ENFORCE-025) |
|---|---|---|---|---|
| `OBSERVER.aarch64.bpf` | 242 | 1936 | `sha256:887bf07824d7c1e6ec6db991473935d31500e0c78fac345058972a0f777ad184` | 227, 1816 bytes, `sha256:d31c8410…3cb3707` |
| `OBSERVER.x86_64.bpf` | 253 | 2024 | `sha256:a20d2a956393b3af72799eaad5fa2c4a3cd82f38bf3842c0dea7c42012e525b9` | 238, 1904 bytes, `sha256:e793aae5…46eb25a` |

## The two inserted blocks

`compile_filter` emits one number test per allowed syscall in ascending number order, each followed by its own body. A
failed number test jumps to the next number test, and every other jump stays inside its own syscall's block. v5's rule
therefore adds blocks only at the sorted positions of the new numbers, and nothing else in the program moves or changes.
`bind` and `listen` have adjacent numbers on both architectures, so their two blocks form one four-instruction pair.

| Architecture | Block | nr | Earlier index | New index | Between |
|---|---|---|---|---|---|
| x86_64 | `bind`, `listen` | 49 (0x31), 50 (0x32) | 110 | 110 | 48 `shutdown` and 51 `getsockname` |
| x86_64 | `accept4` | 288 (0x120) | 184 | 188 | 281 `epoll_pwait` and 291 `epoll_create1` |
| aarch64 | `bind`, `listen` | 200 (0xc8), 201 (0xc9) | 134 | 134 | 198 `socket` and 203 `connect` |
| aarch64 | `accept4` | 242 (0xf2) | 175 | 179 | 233 `madvise` and 261 `prlimit64` |

"Earlier index" is the instruction in the earlier program before which the block is inserted; "new index" is the
block's first instruction in the new program (the `accept4` block moves by the pair's four).

The `bind`/`listen` pair:

| # | Instruction (`code jt/jf k`) | Bytes (little-endian) |
|---|---|---|
| 1 | `JEQ_K 0/1 nr`: the `bind` number test | x86_64 `1500000131000000`, aarch64 `15000001c8000000` |
| 2 | `RET 0x7fff0000`: ALLOW | `060000000000ff7f` |
| 3 | `JEQ_K 0/1 nr`: the `listen` number test | x86_64 `1500000132000000`, aarch64 `15000001c9000000` |
| 4 | `RET 0x7fff0000`: ALLOW | `060000000000ff7f` |

The `accept4` block:

| # | Instruction (`code jt/jf k`) | Bytes (little-endian) |
|---|---|---|
| 1 | `JEQ_K 0/10 nr`: the number test | x86_64 `1500000a20010000`, aarch64 `1500000af2000000` |
| 2 | `LD_W_ABS 0/0 0x28`: arg 3's low 32 bits | `2000000028000000` |
| 3 | `JEQ_K 0/1 0x0`: flags 0 | `1500000100000000` |
| 4 | `RET 0x7fff0000`: ALLOW | `060000000000ff7f` |
| 5 | `LD_W_ABS 0/0 0x28` | `2000000028000000` |
| 6 | `JEQ_K 0/1 0x80000`: SOCK_CLOEXEC | `1500000100000800` |
| 7 | `RET 0x7fff0000`: ALLOW | `060000000000ff7f` |
| 8 | `LD_W_ABS 0/0 0x28` | `2000000028000000` |
| 9 | `JEQ_K 0/1 0x80800`: SOCK_CLOEXEC\|SOCK_NONBLOCK | `1500000100080800` |
| 10 | `RET 0x7fff0000`: ALLOW | `060000000000ff7f` |
| 11 | `RET 0x80000000`: KILL_PROCESS | `0600000000000080` |

The replay includes v5's 44 OBSERVER listener vectors, 22 per architecture. `accept4` is allowed with flags 0, 0x80000 or
0x80800, also under a set high word (the rule compares the low 32 bits); SOCK_NONBLOCK alone (0x800), an undefined bit
(0x40000), bit 0 or bit 31 kill the process. `bind` and `listen` load no argument, so the program allows them whatever
their arguments; v5's vectors test each with two argument sets per architecture. Plain `accept` has no rule, so the
program's default action kills it; v5 has no vector for it (review note P3R1-5).

## Consumers

Edge record v6 (`architecture/artifact-edges/operator-harness-engineering-v6.json`) registers the two programs for the
operator repository (R10): consumer packet HE-004-I01, consumer paths
`host-enforcement/contracts/seccomp-v5/OBSERVER.<arch>.bpf`, BYTE_IDENTICAL, REGISTERED_BEFORE_USE, mode 100644 (Q-P2-2).
The other rows are edge record v5's, unchanged: the twelve unchanged programs keep their registrations, SERVER's stay
PUBLISHED_UNREGISTERED, and edge v2's two OBSERVER rows for HE-004 (`contracts/seccomp-v3/`) stay as recorded (Q-P2-3).

Carried to R10's HE-004-I01 (R10's work; listed in `status.json`):

- vendor the two files at `host-enforcement/contracts/seccomp-v5/`, and decide whether `contracts/seccomp-v3/OBSERVER.*`
  stays;
- the observer's installed filter is exactly these bytes (the instruction counts, byte counts and digests above);
- serve I01 on its fixed path with the v1 peer duties in both directions, and record whether HS43's race-free start-time
  reference applies to I01 (O-R10-HE004-I01, Q-SOL-4 (a));
- cite MET-ENFORCE-036, its merge commit and edge record v6 wherever R10 records the programs' provenance.

## Not claimed

- R10's adoption: vendoring, pinning, embedding and installing these programs are HE-004-I01's.
- Linux behaviour under the installed filter: the boot-time proof that the installed filter equals the published digest
  stays T04/W02a-F's (W02d-Q3).
- The TCP-listen boundary: the filter cannot tell an AF_UNIX `bind` or `listen` from a TCP one; that boundary is SELinux's
  (HS53's residual R-OBSERVER-TCP-LISTEN and its W03, matrix and T04 obligations).
- The other roles' consumers: their programs and registrations are unchanged.
- No new seccomp decision: the rule is allowlists v5's, reviewed with HS53 in MET-ENFORCE-035; this contract compiles it.
