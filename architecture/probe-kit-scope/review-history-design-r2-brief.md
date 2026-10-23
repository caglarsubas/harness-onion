# LPK-0 (the probe-kit scope amendment): independent design review, round 2 (delta)

You are an independent reviewer. You did not write this design, its dossiers or the round-1 review. Judge whether
revision 2 resolves round 1's findings as ruled, and whether it is correct, complete and faithful to the decisions. The test is concrete: after this record, every pinned statement that gives
CONF-LIVE-003/004/005 the moved items must be superseded by a quote that matches its bytes, nothing pinned may be edited,
nothing may move that the owner did not move, and the packet must stay data. Record what you actually checked, and never
claim a check you did not run.

WORK = `<scratch>/lpk0-design-r2`. TOOLS = `<workspace>/tools/w03/probekit`.

## Hard rules (every command, no exceptions)

- **The prefix, first on every command line:**
  `while [ -e /opt/planeon/verifier-control/PAUSE ] || [ -e <scratch>/lpk0-design-r2/PAUSE ] || [ -e <workspace>/lane-guard/HOLD_BY_VERIFY ]; do sleep 5; done;`
  Wrap every command in `timeout 120`. One process at a time, in the foreground.
- **Read-only and light.** Allowed: `GIT_OPTIONAL_LOCKS=0 git -C <repo> show <commit>:<exact file>`, pruned
  `git grep -l`, `git log -1 --format=%H <commit> -- <exact path>`, and `python3 -I -B` over text saved in WORK. Not
  allowed: running any repository script, test or validator; importing any repository module (in particular
  `scripts/validate_policy_observation.py` or `scripts/validate_readiness.py`); `git show -s`,
  `git show <commit>:<directory>`, `git ls-tree` of any directory, **`git grep -l -e ''` listings**, unpruned walks.
  Write only in WORK.
- **NO network.** No email address, name or personal data anywhere. Never write the legacy brand term (the old company
  word in the workspace folder path) in any file. Cite `HO:<path>:<lines>` for harness-onion at `2043cc27`.
- **Independence:** never open the R12 repository (mas-harness-conformance-labs) in any form, nor `tools/w04/`,
  `architecture/enforcement-test-plan/`, `docs/alpha-2/ENFORCEMENT_TEST_PLAN.md` or R12's `tests/enforcement/`; exclude
  them, `scripts/validate_enforcement_test_plan.py` and `tests/test_enforcement_test_plan.py` from every grep with `:!`
  pathspecs. Read `architecture/artifact-edges/` by exact path only. In
  `docs/repositories/12-mas-harness-conformance-labs.md` read only the lines the design cites and the scope sections
  around them, and never summarise R12's test logic.
- **Forbidden paths (never read):** `<workspace>/keys`, `github-app`, `/var/db/harness-ci`, any
  `operator-private/` directory, any memory file. Under `<workspace>/tools/` open only
  `w03/probekit/` (its `lpk0/`, `LPK0_DOSSIER.md`, `DOSSIER.md` and `OWNER_DECISIONS.md`).
- **Safety:** never write, import or run code that interposes on, forwards, proxies, swaps or bypasses anything.
- Python: always `python3 -I -B`.

## Subject

- **The design:** `TOOLS/lpk0/DESIGN.md`, revision 2 (sha256 `4b490770e6efb6b681f044e630f7aabaf115c07f4e0332106007c3f9d515b892`, a copy in `DESIGN.rev2.md`). Revision 1 is
  `DESIGN.rev1.md` (`181364e6…`).
- **Round 1:** `TOOLS/lpk0/reviews/design-review-round1.json` (`b7ecb662…`): findings S1-1..S1-16 and 42 coverage rows.
- **The decisions:** `TOOLS/OWNER_DECISIONS.md` (`2de97162039dd8e474df111d44a6ee6140e1c11e324fa7740d26d051a9b4c7b6`), verbatim, including owner R-S1-5, the monitor's R-S1-4, R-S1-2,
  the rulings on S1-1, S1-3, S1-6..S1-16, Q-SC-1..5, and LX-D1's verbatim text with the correction of its attribution.
- **The dossiers:** `TOOLS/LPK0_DOSSIER.md` (`6ce99678…`) and `TOOLS/DOSSIER.md` (`4243155a…`).
- **The repository:** harness-onion at `2043cc27`, in the checkout the launch prompt names.

## What to check

1. **Each round-1 finding, one by one.** For S1-1..S1-16: resolved as round 1 required and as ruled, partly, or open.
2. **The supersession coverage, again.** Re-run round 1's search (every base line in `docs/`, `architecture/` and
   `task-packets/`, with the exclusions, naming CONF-LIVE-003/004/005 or a short form in such a sentence). For each hit,
   is it covered by a `supersedes` row, by `notAmended.pinned` or `notAmended.named`, or is it plainly not ownership? Re-check
   round 1's 42 coverage rows against revision 2. Name any hit still uncovered.
3. **The rulings carried exactly:** CONF-FIX-007..010 in `retiredHistory` (owner R-S1-5); the four dispositions (R-S1-4);
   quote rows only where a pin requires one (R-S1-2); the KAP authority quoted from owner Q-LPK0-3 and not attributed to
   LX-D1's words.
4. **Quotes that stay true** must not be quoted (S1-15): check BH:40-42, PCR:189-191's second half and COR's eight-path
   grant are excluded.
5. **The model and vectors (§5):** do the new checks (inventory, items linkage, closed vocabularies, duplicates, the
   pinned/named split) close round 1's gaps? Name any missing check.
6. **Gate material and the predecessor table:** still data only; the table acyclic and consistent with PK-D1 and the slots.
7. **Anything new** that revision 2 decides without a ruling.

## Output

Write `WORK/design-review-round2.json` (check this name: round 2 of LPK-0's design review):

```
{"subject": {"design": "LPK-0 DESIGN.md rev 2", "sha256": "4b490770"…}, "reviewer": "independent agent", "model": "<id>",
 "brief": {"path": "tools/w03/probekit/lpk0/DESIGN_REVIEW_BRIEF_R2.md", "sha256": "<as computed>"},
 "verdict": "PASS_FOR_CONTRACT" | "CHANGES_REQUIRED",
 "round1": [{"id": "S1-n", "status": "resolved|partly|open", "note"}],
 "findings": [{"id": "S2-n", "severity": "MAJOR|MINOR|NOTE", "location", "finding", "requiredChange"}],
 "supersessionCoverage": [{"statement", "path", "lines", "inDesign": true|false, "note"}],
  "checks": [{"check", "result"}], "notChecked": [...]}
```

Reply with the verdict, the brief's sha256 as you computed it, the S1 status list, any uncovered hit, and one line per
finding.
