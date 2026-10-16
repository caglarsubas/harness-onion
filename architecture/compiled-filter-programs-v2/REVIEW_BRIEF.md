# Review brief: compiled filter programs v2 and edge record v3 (PROGRAMS-REPUBLISH)

Review the candidate contract for publication. It consists of these new files, and nothing else changes:

- `architecture/compiled-filter-programs-v2/`: `README.md`, `REVIEW_BRIEF.md`, `index.json`, `status.json`,
  `programs/EFFECT_GATE.aarch64.bpf` and `programs/EFFECT_GATE.x86_64.bpf`;
- `scripts/compiled_filter_programs_v2.py`, the publisher and checker;
- `architecture/artifact-edges/operator-harness-engineering-v3.json` and `architecture/artifact-edges/README-v3.md`.

The base is harness-onion main `9f251d5d07772cbfb9987c422f3fca79748fad34`. The sources are seccomp allowlists v4
(`architecture/seccomp-allowlists-v4/`, `scripts/seccomp_allowlists_v4.py`; MET-ENFORCE-027, merged as `e7516160`) and
MET-ENFORCE-025's `architecture/compiled-filter-programs/` with edge record v2. The decisions are Q-HE3A-1 (c),
Q-HE3A-1b (a), Q-HE3D-3 (a) and Q-PR-1..10 (a), quoted in `status.json`.

## Rules for the reviewer

- No network of any kind: no web, no git fetch or pull, no GitHub calls, no downloads. Put no personal data (names, email
  addresses, home paths) in any request, record or output.
- Read-only: write nothing in the worktree, and do not commit, stash or switch branches. Run Python only as
  `python3 -I -B`, under a timeout, and leave no `__pycache__`. The publisher without arguments only checks; never pass
  `--write`. Run no pytest, dry run, cargo or Docker.
- Read nothing of R10 (the operator repository) or of W03 drafts. The R10 facts this contract relies on are the names
  quoted in `status.json` (`carriedToR10`); they are R10's work, not this contract's.

## Check at least

1. **Pins.** The publisher's four v4 source digests equal the files on the base and allowlists v4's reviewed round-3
   subject (`architecture/seccomp-allowlists-v4/status.json`, `source-index.json`). `e7516160` is MET-ENFORCE-027's merge
   and holds the same bytes. The model is executed from its verified bytes, never imported. MET-ENFORCE-025's index is
   pinned by SHA-256, and its files are checked against it.
2. **The two programs.** `python3 -I -B scripts/compiled_filter_programs_v2.py` passes. Independently of the publisher,
   decode MET-ENFORCE-025's v3 `EFFECT_GATE.<arch>.bpf` and the new files, and confirm that each new program is the v3
   program with exactly the six instructions in the README inserted: x86_64 at index 173 (nr 267), aarch64 at index 34
   (nr 78). Confirm the published SHA-256 and lengths: x86_64 `sha256:4e516f16…`, 200 instructions, 1600 bytes; aarch64
   `sha256:8de80a2b…`, 189 instructions, 1512 bytes. Both must equal v4's `filterDigests` and `programLengths`.
3. **The twelve unchanged programs.** For the six other roles, v4's `filterDigests` and `programLengths` equal v3's, and
   the v4 model compiles exactly MET-ENFORCE-025's bytes. `index.json` points to MET-ENFORCE-025's paths for them.
4. **Vector replay.** Every v4 EFFECT_GATE decision vector (206 x86_64, 195 aarch64; 20 of them `readlinkat`) runs through
   the published bytes to its recorded action. Add your own probes: AT_FDCWD in both encodings, -1, 0x80000000, other
   negative values and other high words.
5. **`index.json`.** Schema `planeon.internal.compiled-filter-programs/v2`, `DATA_CHECK_ONLY`, the same format string as
   MET-ENFORCE-025's, `source`, `predecessor` (its digest), and fourteen rows in sorted role order × (aarch64, x86_64),
   each with exactly {role, arch, path, instructions, bytes, sha256}.
6. **Edge record v3.** Edge record v2's 31 rows are carried unchanged and in order, followed by exactly two rows for the
   new programs. Check their keys, mode, consumer path `host-enforcement/contracts/seccomp-v4/`, consumer packet HE-003A2,
   relation, status and provider packet. `supersedes` binds v2 by
   `sha256:749e70f174d638468bf45d7316e8f5201c3323f6348a78c7b9a22d3a571ccc32`. The schema stays
   `planeon.internal.artifact-edge-registry/v2`, with no new key or status, and `ownerDecision`, `rules`, `notArtifacts`
   and `statuses` equal v2's. The owner decisions are verbatim, and the notes are accurate.
7. **`status.json` and the READMEs.** The decisions are quoted verbatim: Q-HE3A-1 and Q-HE3A-1b as the HS43 record and
   allowlists v4 hold them. The discharge names allowlists v4's open item exactly. The carried R10 list matches the README.
   The state is CANDIDATE, with no review rounds yet.
8. **Scope and frozen records.** Only the files above are new, and no existing file changes. These stay byte-identical:
   - `architecture/compiled-filter-programs/` and `scripts/compiled_filter_programs.py`;
   - `architecture/seccomp-allowlists-v3/`, `architecture/seccomp-allowlists-v4/` and both models;
   - edge records v1 and v2, EDGE-2 (`conformance-labs-harness-engineering.json`), `README.md` and `README-v2.md`;
   - `architecture/repositories.yaml` and the W03 plan v2.

   There is no rider (Q-PR-9). Apply the scans of `tests/test_sector_catalog.py` by reading them, not by running pytest:
   - no new non-Python file under `architecture/` names one of the three catalog paths or holds a base digest;
   - the publisher names no catalog and lists only its own `programs/` folder.

Verdict: `PASS_FOR_SOURCE_PUBLICATION` or `CHANGES_REQUIRED`, with findings `{id, severity MAJOR|MINOR|NOTE, file, line,
summary, evidence}`, recorded as `review-round<N>.json` in this directory.
