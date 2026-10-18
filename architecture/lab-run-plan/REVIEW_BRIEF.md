# Review brief: lab run-plan contract v1 (LAB-RUNPLAN-001, MET-LINUX-007)

Review the candidate contract for publication. It consists of these new files, and nothing else changes:

- `architecture/lab-run-plan/`: `README.md`, `REVIEW_BRIEF.md`, `run-plan.schema.json`, `lease.schema.json`,
  `teardown-report.schema.json`, `vectors.json` and `status.json`;
- `scripts/lab_run_plan.py`, the offline checker.

The base is harness-onion main `f560209d04b7e0f07b2480219718a8a6dbdb21ef`. The decisions are the owner's Q-RP-0..9 (a)
of 2026-10-19 (quoted in `status.json`), VR-D1 of 2026-10-17 and the 2026-10-15 decision on Linux capacity.

## Rules for the reviewer

- No network of any kind: no web, no git fetch or pull, no GitHub calls, no downloads, no cloud calls. Put no personal
  data (names, email addresses, account ids, home paths) in any request, record or output.
- Read-only: write nothing in the worktree, and do not commit, stash or switch branches. Run Python only as
  `python3 -I -B`, under a timeout, and leave no `__pycache__`. Run no pytest, dry run, cargo or Docker.
- Clean room (owner decision Q-RP-0 (a)): read nothing of the owner's warm-start repositories or their snapshots, and
  nothing of R10 or of W03 drafts.
- Return the review record in your answer; the author copies it into this directory at adoption.

## Check at least

1. **The checker.** `python3 -I -B scripts/lab_run_plan.py` passes. Is its closed JSON Schema subset implemented
   correctly (types, const and enum with type equality, pattern full-match, lengths, bounds, closed objects, items,
   uniqueItems)? Does `check_schema` refuse any keyword outside the subset, any object schema that is not closed, and
   any keyword where it does not apply or with a value of the wrong type? Does strict parsing refuse what the README
   says, and does the command line refuse, never trace back?
2. **The schemas.** Are all three closed? Do they say what the README says? Could a plan carry a credential, an
   account identity or an organisation project id in some field?
3. **The rules beyond the schemas.** Check the cost recomputation (rate card age, SKU and unit matching, amounts,
   coverage of every machine for the whole maximum duration, total, ceiling) and the exposure rules (external address
   reason, never-open ingress, network form). Check the observer's roles against the classes it must list, the
   residual, the run project's id appearing only as `project.id`, the lease's sha256 binding, window and preparation
   date, and the teardown's bindings, each class's scope, zero counts, kept classes, ordering and lease overrun. Can
   any rule be satisfied without meaning what it says?
4. **The vectors.**
   - Each positive must be accepted.
   - Each negative must be refused with its recorded refusal, for the reason its intent states, not by an earlier rule
     by accident. A `lease-at-teardown` negative changes the lease and checks the report. Each parse negative must be
     refused by strict parsing.
   - Are there gaps where a rule has no negative?
   - Are all ids, prices, ranges and names visibly invented: documentation networks, `example-*` projects?
5. **The README.** It must be accurate to the checker and the schemas. Check that the runbook matches the owner's
   decisions, and that "Not claimed" is honest.
6. **Privacy and scope.**
   - No credential, organisation project id, account identity or absolute local path in any new file.
   - Only the files above are new; no existing file changes.
   - Apply `tests/test_sector_catalog.py`'s scans by reading them, not by running pytest: no new non-Python file under
     `architecture/` may name one of the three catalog paths or hold a base digest.

Verdict: `PASS_FOR_SOURCE_PUBLICATION` or `CHANGES_REQUIRED`, with findings `{id, severity MAJOR|MINOR|NOTE, file, line,
summary, evidence}`.
