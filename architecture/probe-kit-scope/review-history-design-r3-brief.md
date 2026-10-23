# LPK-0 (the probe-kit scope amendment): independent design review, round 3 (delta, last round)

You are an independent reviewer. You did not write this design, its dossiers or the earlier reviews.

Judge whether revision 3 resolves round 2's findings as ruled, and whether it is correct, complete and faithful to the
decisions. The test is concrete. After this record:
- every pinned statement that gives CONF-LIVE-003/004/005 a moved item is superseded by a quote that matches its bytes,
  never overlapping a statement that stays true;
- nothing pinned is edited;
- nothing moves that the owner did not move;
- the packet stays data.

Record what you actually checked, and never claim a check you did not run.

**This is the last design round (the monitor's Q-LPK0-CAP).**
- **PASS_FOR_CONTRACT** if you find no MAJOR and every coverage row is covered, or is mechanically caught by the
  design's declared search.
- **Otherwise,** each remaining MINOR or NOTE coverage item must be stated precisely enough to become a binding build
  rule.
- **A MAJOR** goes back to the monitor.

WORK = `<scratch>/lpk0-design-r3`. TOOLS = `<workspace>/tools/w03/probekit`.

## Hard rules (every command, no exceptions)

- **The prefix, first on every command line:**
  `while [ -e /opt/planeon/verifier-control/PAUSE ] || [ -e <scratch>/lpk0-design-r3/PAUSE ] || [ -e <workspace>/lane-guard/HOLD_BY_VERIFY ]; do sleep 5; done;`
  Wrap every command in `timeout 120`. Run one process at a time, in the foreground.
- **Read-only and light.**
  - Allowed:
    - `GIT_OPTIONAL_LOCKS=0 git -C <repo> show <commit>:<exact file>`;
    - pruned `git grep -l`;
    - the design's declared search itself, as `git grep -n -E <its pattern> 2043cc27 -- docs architecture task-packets`
      with its exclusions and the independence exclusions below;
    - `git log -1 --format=%H <commit> -- <exact path>`;
    - `python3 -I -B` over text saved in WORK.
  - Not allowed:
    - running any repository script, test or validator;
    - importing any repository module (in particular `scripts/validate_policy_observation.py` or
      `scripts/validate_readiness.py`);
    - `git show -s`, `git show <commit>:<directory>` or `git ls-tree` of any directory;
    - **`git grep -l -e ''` listings**, or unpruned walks.
  - Write only in WORK.
- **NO network.** No email address, name or personal data anywhere. Never write the legacy brand term (the old company
  word in the workspace folder path) in any file. If a saved repository copy contains it, scan it only by script and
  delete it after use. Cite `HO:<path>:<lines>` for harness-onion at `2043cc27`.
- **Independence.**
  - Never open the R12 repository (mas-harness-conformance-labs) in any form.
  - Never open `tools/w04/`, `architecture/enforcement-test-plan/`, `docs/alpha-2/ENFORCEMENT_TEST_PLAN.md` or R12's
    `tests/enforcement/`.
  - Exclude those paths, `scripts/validate_enforcement_test_plan.py`, `tests/test_enforcement_test_plan.py` and
    `tools/w03*` from every grep with `:!` pathspecs.
  - Read `architecture/artifact-edges/` by exact path only.
  - In `docs/repositories/12-mas-harness-conformance-labs.md`, read only the lines the design cites and the scope
    sections around them.
  - Never summarise R12's test logic, or the test lists in harness-onion guides. Read those for scope only.
- **Forbidden paths (never read):**
  - `<workspace>/keys`, `github-app`, `/var/db/harness-ci`, any `operator-private/` directory, any
    memory file;
  - under `<workspace>/tools/`, anything except `w03/probekit/`. There, open only its `lpk0/`,
    `LPK0_DOSSIER.md`, `DOSSIER.md` and `OWNER_DECISIONS.md`.
- **Safety:** never write, import or run code that interposes on, forwards, proxies, swaps or bypasses anything.
- **Python:** always `python3 -I -B`.

## Subject

- **The design:** `TOOLS/lpk0/DESIGN.md`, revision 3 (sha256
  `80add650443ccf1a90a4d4d22075d7a38709a03d23471ca1b3f2f37937ac0ae9`, a copy in `DESIGN.rev3.md`).
  - Revision 2 is `DESIGN.rev2.md` (`4b490770…`).
  - Revision 1 is `DESIGN.rev1.md` (`181364e6…`).
- **Round 2:** `TOOLS/lpk0/reviews/design-review-round2.json` (`aea54d76…`): findings S2-1..S2-14 and 51 coverage rows,
  18 of them uncovered.
- **Round 1:** `TOOLS/lpk0/reviews/design-review-round1.json` (`b7ecb662…`): 42 coverage rows.
- **The decisions:** `TOOLS/OWNER_DECISIONS.md` (`b5079ebdbf626f5ca56363d2fba319e84b30bbf5aeaedd60ee2ab4fcdf415080`),
  verbatim. In particular:
  - R-S2-A, R-S2-9 (a), R-S2-14 (a), R-S2-3 (a) and Q-LPK0-CAP;
  - the earlier rulings, as in round 2's brief.
- **The dossiers:** `TOOLS/LPK0_DOSSIER.md` (`6ce99678…`) and `TOOLS/DOSSIER.md` (`4243155a…`).
- **The repository:** harness-onion at `2043cc27`, in the checkout the launch prompt names.

## What to check

1. **Each round-2 finding, one by one.** For S2-1..S2-14, record whether it is resolved as round 2 required and as
   ruled, partly resolved, or open. Re-state any round-1 item that round 2 left partly (S1-3, 5, 6, 10, 12, 13, 15).
2. **The quotes.** For every new or changed `supersedes` row (§3.6) and every `staysTrue` row (§3.7):
   - the quote occurs exactly once within its cited lines at `2043cc27`, byte for byte;
   - no `supersedes` quote overlaps a `staysTrue` span;
   - the structured replacement names the right moved and kept items.

   For the rows marked "as in rev 2", confirm that rev 2's quotes still meet the same test.
3. **The coverage, again.** Re-run round 2's search and the design's declared search (§3.10). For every hit in
   round 1's 42 rows and round 2's 51 rows, and for any new hit, find what covers it:
   - a `supersedes` row;
   - a `staysTrue` row or an `UNCHANGED_TRUE` or `NOT_OWNERSHIP` disposition (is its reason right?);
   - a `notAmended` class (is the file a member?).

   Name any hit still uncovered, and say whether the declared search catches it mechanically.
4. **The declared search.**
   - Is it deterministic, as written?
   - Does it catch every short-form clause the design quotes?
   - Does the family-context rule keep out CONF-PERF and other families?
   - Is the byte source (`git show 2043cc27:<path>` of recorded paths only) sound?
   - Is the build gate at the mechanics base precise enough to enforce?
5. **The rulings carried exactly:**
   - `retiredHistory` in MET-REPAIR-018's six keys, with 007's values from completion-integration.json and null `pr`
     and `head` for 008..010;
   - one unsplit `R12_SUCCESSOR`;
   - the notAmended classes as exact paths, with no listings;
   - the per-entry MDP annotations;
   - the `ownerDecisions` section rule.
6. **The model and vectors (§5).** Do the checks close round 2's S2-12 gaps? Is each check decidable from the record and
   the base bytes alone? Name any missing check or vector.
7. **Gate material and the predecessor table.** Is everything still data only? Is the table acyclic, does it name only
   known items, and is it consistent with PK-D1 and the slots?
8. **Anything new** that revision 3 decides without a ruling.

## Output

Write `WORK/design-review-round3.json`. Check this name: round 3 of LPK-0's design review.

```
{"subject": {"design": "LPK-0 DESIGN.md rev 3", "sha256": "80add650"…}, "reviewer": "independent agent", "model": "<id>",
 "brief": {"path": "tools/w03/probekit/lpk0/DESIGN_REVIEW_BRIEF_R3.md", "sha256": "<as computed>"},
 "verdict": "PASS_FOR_CONTRACT" | "CHANGES_REQUIRED",
 "round2": [{"id": "S2-n", "status": "resolved|partly|open", "note"}],
 "findings": [{"id": "S3-n", "severity": "MAJOR|MINOR|NOTE", "location", "finding", "requiredChange", "buildRule"}],
 "quoteChecks": [{"path", "lines", "quote", "occurrences", "overlapsStaysTrue": true|false}],
 "supersessionCoverage": [{"statement", "path", "lines", "coveredBy", "mechanicallyCaught": true|false, "note"}],
 "checks": [{"check", "result"}], "notChecked": [...]}
```

`buildRule` is the exact rule that the build enforces for a MINOR or NOTE coverage item (Q-LPK0-CAP). Leave it empty
for other findings.

Reply with:
- the verdict;
- the brief's sha256 as you computed it;
- the S2 status list;
- any uncovered hit;
- one line per finding.
