# Review brief: compiled filter programs v3 and edge record v6 (SECCOMP-OBSERVER-LISTENER packet 2)

Review the candidate contract for publication. It consists of these new files, and nothing else changes:

- `architecture/compiled-filter-programs-v3/`: `README.md`, `REVIEW_BRIEF.md`, `index.json`, `status.json`,
  `programs/OBSERVER.aarch64.bpf` and `programs/OBSERVER.x86_64.bpf`;
- `scripts/compiled_filter_programs_v3.py`, the publisher and checker;
- `architecture/artifact-edges/operator-harness-engineering-v6.json` and `architecture/artifact-edges/README-v6.md`.

The base is harness-onion main `f4bb0000df9ec4bdaac54d3e6488d691e2001f28`, MET-ENFORCE-035's merge. The sources are
seccomp allowlists v5 (`architecture/seccomp-allowlists-v5/`, `scripts/seccomp_allowlists_v5.py`), reviewed jointly
with W01 amendment HS53 (`architecture/host-interface-amendment-hs53/`); MET-ENFORCE-029's
`architecture/compiled-filter-programs-v2/index.json`, which lists the fourteen v4 programs; and edge record v5
(MET-ENFORCE-033). The decisions are Q-SOL-1 (a) and F-SOL-1's note, as HS53's `amendment.json` holds them, and the lane
monitor's Q-P2-1..4 (a), quoted in `status.json`.

## Rules for the reviewer

- No network of any kind: no web, no git fetch or pull, no GitHub calls, no downloads. Put no personal data (names, email
  addresses, home paths) in any request, record or output.
- Read-only: write nothing in the worktree, and do not commit, stash or switch branches. Run Python only as
  `python3 -I -B`, under a timeout, and leave no `__pycache__`. The publisher without arguments only checks; never pass
  `--write`. Run no pytest, dry run, cargo or Docker.
- Read nothing of R10 (the operator repository) or of W03 drafts. The R10 facts this contract relies on are the paths
  quoted in the Q-P2-2 message and the names in `status.json` (`carriedToR10`); they are R10's work, not this contract's.
- Return the review record in your answer. The author copies it into this directory as `review-round<N>.json` at
  adoption.

## Check at least

1. **Pins.** The publisher's four v5 source digests equal the files on the base, and the base is MET-ENFORCE-035's merge
   holding v5 as adopted (`architecture/seccomp-allowlists-v5/status.json`). The model is executed from its verified
   bytes, never imported. MET-ENFORCE-029's index is pinned by SHA-256, and the files it lists are checked against it.
2. **The two programs.** `python3 -I -B scripts/compiled_filter_programs_v3.py` passes. Independently of the publisher,
   decode MET-ENFORCE-025's `OBSERVER.<arch>.bpf` (the earlier program MET-ENFORCE-029's index lists) and the new files.
   Confirm that each new program is the earlier one with exactly the README's two blocks inserted: the four-instruction
   `bind`/`listen` pair before earlier index 110 on x86_64 (nr 49, 50) and 134 on aarch64 (nr 200, 201), and the
   eleven-instruction `accept4` block before earlier index 184 on x86_64 (nr 288) and 175 on aarch64 (nr 242). Check
   that every jump stays inside its own syscall's block or lands on the next number test, so that the failed number test
   before each insertion point now reaches the inserted block and no other jump target moves. Confirm the published
   SHA-256 and lengths: x86_64 `sha256:a20d2a95…`, 253 instructions, 2024 bytes; aarch64 `sha256:887bf078…`, 242
   instructions, 1936 bytes. Both must equal v5's `filterDigests` and `programLengths`.
3. **The twelve unchanged programs.** For the six other roles, v5's `filterDigests` and `programLengths` equal v4's, and
   the v5 model compiles exactly the bytes MET-ENFORCE-029's index lists. `index.json` points to those paths: EFFECT_GATE
   in `compiled-filter-programs-v2/`, the other ten in `compiled-filter-programs/`.
4. **Vector replay.** Every v5 OBSERVER decision vector (267 x86_64, 256 aarch64; 44 of them `bind`, `listen` or
   `accept4`) runs through the published bytes to its recorded action. Add your own probes: `accept4` flags SOCK_NONBLOCK
   alone, each allowed value with other bits added, each allowed value under several high words, 0xffffffff; `bind` and
   `listen` with arbitrary arguments; plain `accept` (x86_64 43, aarch64 202); and the neighbouring numbers in the README's
   table.
5. **`index.json`.** Schema `planeon.internal.compiled-filter-programs/v3`, `DATA_CHECK_ONLY`, the same format string as
   MET-ENFORCE-029's, `source`, `predecessor` (its digest), and fourteen rows in sorted role order × (aarch64, x86_64),
   each with exactly {role, arch, path, instructions, bytes, sha256}.
6. **Edge record v6.** Edge record v5's 54 rows are carried unchanged and in order, followed by exactly two rows for the
   new programs. Check their keys, mode, consumer paths `host-enforcement/contracts/seccomp-v5/OBSERVER.<arch>.bpf`,
   consumer packet HE-004-I01, relation, status and provider packet. `supersedes` binds v5 by
   `sha256:89b47ef8f865b31911eb8da2b08a5a3c22b2d92a62599cb6fdfccbfe7f79e3c0`. The schema stays
   `planeon.internal.artifact-edge-registry/v2`, with no new key or status, and `ownerDecision`, `rules`, `notArtifacts`
   and `statuses` equal v5's. Edge v2's two OBSERVER rows for HE-004 are unchanged (Q-P2-3). The decisions are verbatim,
   and the notes are accurate.
7. **`status.json` and the READMEs.** The decisions are quoted verbatim and the same in all four files: Q-SOL-1 and
   F-SOL-1's note as HS53's `amendment.json` holds them, and the two lane-monitor messages identical across `status.json`,
   edge record v6 and the README (whose quotes are line-wrapped). The discharges name HS53's O-PROGRAMS-V3-OBSERVER (its text as `amendment.json` holds
   it) and v5's open item exactly. The carried R10 list matches the README. The state is CANDIDATE, with no review rounds
   yet.
8. **Scope and frozen records.** Only the files above are new, and no existing file changes. These stay byte-identical:
   - `architecture/compiled-filter-programs/`, `architecture/compiled-filter-programs-v2/` and their publishers;
   - `architecture/seccomp-allowlists-v3/`, `-v4/`, `-v5/` and their models;
   - `architecture/host-interface-amendment-hs53/` and `architecture/host-interface-amendment-hs43/`;
   - edge records v1 to v5 with their READMEs, EDGE-2 (`conformance-labs-harness-engineering.json`);
   - `architecture/repositories.yaml`.

   No new file holds an absolute local path. Apply the scans of `tests/test_sector_catalog.py` by reading them, not by
   running pytest:
   - no new non-Python file under `architecture/` names one of the three catalog paths or holds a base digest;
   - the publisher names no catalog and lists only its own `programs/` folder.

Verdict: `PASS_FOR_SOURCE_PUBLICATION` or `CHANGES_REQUIRED`, with findings `{id, severity MAJOR|MINOR|NOTE, file, line,
summary, evidence}`.
