# The I01 digest contract: independent design review, round 3 (delta)

You are an independent reviewer. You did not write this design, its dossier or the round-1 review. Judge whether
revision 3 resolves round 2's findings, and whether its changes add a new way to pass wrongly. The test is unchanged: an
observer following the design must refuse whenever the live cluster's enforcement differs from what the release binds,
and must never echo the binding. Record what you actually checked, and never claim a check you did not run.

WORK = `<scratch>/digest-design-r3`

## Hard rules (every command, no exceptions)

- **The prefix, first on every command line:**
  `while [ -e /opt/planeon/verifier-control/PAUSE ] || [ -e <scratch>/digest-design-r3/PAUSE ] || [ -e <workspace>/lane-guard/HOLD_BY_VERIFY ]; do sleep 5; done;`
  Wrap every command in `timeout 120`.
- **Read-only and light:**
  - Allowed: `git -C <repo> show <commit>:<exact path>`, `git grep -l` with pruned pathspecs, and `python3 -I -B`
    scripts that parse text you saved into WORK. Use `GIT_OPTIONAL_LOCKS=0`.
  - Not allowed: running any repository script, test, build or cargo.
  - Write only in WORK.
- **git grep -l or exact paths only. No ls-tree of any directory** (monitor rule MON-DIG-LSTREE), and no unpruned walks.
- **NO network.** Never put an email address, a name or personal data anywhere. Never write the legacy brand term (the
  old company word in the workspace folder path) in any file. Use `<workspace>/` in your record.
- **Safety:** never write, import or run code that interposes on, forwards, proxies, swaps or bypasses anything. Judge
  bypass forms on paper. No classifier or inventory tooling.
- **Independence:**
  - Never open the R12 repository, `tools/w04/`, `architecture/enforcement-test-plan/`,
    `docs/alpha-2/ENFORCEMENT_TEST_PLAN.md` or R12's `tests/enforcement/`.
  - Exclude them, and `scripts/validate_enforcement_test_plan.py` and `tests/test_enforcement_test_plan.py`, from every
    grep with `:!` pathspecs.
  - Read `architecture/artifact-edges/` by exact path only.
- **Forbidden paths (never read):**
  - `<workspace>/keys` and `github-app`;
  - `/var/db/harness-ci`;
  - any `operator-private/` directory;
  - any memory file.

  Under `<workspace>/tools/`, open only `w03/digest/`, by exact path.
- Python: always `python3 -I -B`.

## Subject

- **The design:** `<workspace>/tools/w03/digest/DESIGN.md`, revision 3 (sha256 `73cd9f6ddeab744b6b9c222204a9bdd4d0a0eef54e4c6f6321fe80bf28a9c083`, a copy
  in `DESIGN.rev3.md`). Revision 2 is `DESIGN.rev2.md` (`206f293b…`); revision 1 is `DESIGN.rev1.md` (`f03d8091…`).
- **Round 1:** `reviews/design-review-round1.json` (`46f233d5…`): findings D1-1..D1-19 and 22 attack cases.
- **Round 2:** `reviews/design-review-round2.json` (`7226f334…`): findings D2-1..D2-7, its round-1 status table and its
  22 new attack cases.
- **The decisions:** `OWNER_DECISIONS.md` (sha256 `12c71dc5f049afd66a8686c3c0c3bcddfba03d2b0aa05b22a4da90c2b69f97e0`), verbatim, including the rulings R1-A..R1-C and R2-A..R2-C.
- **The dossier:** `DOSSIER.md` (`012e83a5…`).
- **The repositories,** read through `git show` only, in the checkouts the launch prompt names: harness-onion
  (`26a8affb`) and R10 (`dd7422ed`).

## What to check

1. **Each round-2 finding.** For D2-1..D2-7, is it resolved as round 2 required, or as a ruling decided? Re-confirm that
   D1-3 and D1-14, which round 2 found only partly resolved, are now resolved, and that no other D1 finding regressed.
2. **Attack cases, all re-run on paper against revision 3:**
   - all 22 round-1 cases (round 1's tally from its record: 11 refused, 2 residual, 9 PASSES-WRONGLY);
   - all 22 round-2 new cases (round 2's tally from its record: 15 refused, 3 residual, 4 PASSES-WRONGLY).
   Take both earlier tallies from the records themselves, not from any summary, and give revision 3's tally for each set.
3. **New attack cases against the changes.** Try at least these:
   - the per-answer capture gate (§3): a set that fails between two answers; a set skipped by an escalated cycle; a wall
     clock or monotonic clock step around the 90 s bound; an answer served while a set runs;
   - the exact-name admission rule (§4.1): a renamed static object; a binding whose policyName points elsewhere;
   - the RBAC subject key and scope rule (§4.5, §5.2): a ServiceAccount subject with and without a namespace; a Group or
     User subject; a non-resource rule through a RoleBinding in the qualification namespace;
   - the named-port rule (§4.4): `endPort`; a port given as a string of digits;
   - the new residuals (R-PSA-CONFIG, R-NET-AGENT, the R-BROKER-LIVE additions): is each stated precisely enough for T04?
   - an echo path anywhere.
4. **Feasibility.** Every input still needs no new permission under `HO:architecture/i06-backend-profile-v4/observer-rbac.json`,
   no Secret data and no new host read. Is the per-answer gate implementable from what R10's capture engine already
   holds (the latest set's slots and its scheduled start)?
5. **Determinism.** Could HE-008 and the observer compute different bytes for the same cluster?
6. **Fidelity.** Does revision 3 decide anything that neither the decisions nor the rulings decided?
7. **Facts.** Spot-check the new citations: R10's set cadence, `SET_BUDGET`, the per-set slot reset, the synchronous
   set, B1's subject key and `exists`, `check_backend_capture`'s compared members, OR06's lines, and VPC's magnitude
   bound.

## Output

Write `WORK/design-review-round2.json`:

```
{"subject": {"design": "DESIGN.md rev 3", "sha256": "73cd9f6ddeab744b6b9c222204a9bdd4d0a0eef54e4c6f6321fe80bf28a9c083"}, "reviewer": "independent agent", "model": "<id>",
 "brief": {"path": "tools/w03/digest/DESIGN_REVIEW_BRIEF_R3.md", "sha256": "<as computed>"},
 "verdict": "PASS_FOR_CONTRACT" | "CHANGES_REQUIRED",
 "round2": [{"id": "D2-n", "status": "resolved|partly|open", "note"}], "round1Regressions": [...],
 "earlierCases": {"round1Tally": {"refused": 11, "residual": 2, "PASSES-WRONGLY": 9},
                  "round2NewTally": {"refused": 15, "residual": 3, "PASSES-WRONGLY": 4},
                  "rev3Tallies": {"round1Cases": {...}, "round2NewCases": {...}},
                  "cases": [{"set": "round1|round2", "case", "earlierOutcome", "rev3Outcome", "where"}]},
 "findings": [{"id": "D3-n", "severity": "MAJOR|MINOR|NOTE", "location", "finding", "requiredChange"}],
 "adversarialCases": [{"case", "outcome": "refused|residual|PASSES-WRONGLY", "where"}],
 "checks": [{"check", "result"}], "notChecked": [...]}
```

Reply with the verdict, both earlier tallies and revision 3's, the brief's sha256 as you computed it, and one line per finding.
