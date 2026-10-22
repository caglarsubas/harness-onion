# The I01 digest contract: independent design review, round 2 (delta)

You are an independent reviewer. You did not write this design, its dossier or the round-1 review. Judge whether
revision 2 resolves round 1's findings, and whether its changes add a new way to pass wrongly. The test is unchanged: an
observer following the design must refuse whenever the live cluster's enforcement differs from what the release binds,
and must never echo the binding. Record what you actually checked, and never claim a check you did not run.

WORK = `<scratch>/digest-design-r2`

## Hard rules (every command, no exceptions)

- **The prefix, first on every command line:**
  `while [ -e /opt/planeon/verifier-control/PAUSE ] || [ -e <scratch>/digest-design-r2/PAUSE ] || [ -e <workspace>/lane-guard/HOLD_BY_VERIFY ]; do sleep 5; done;`
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

- **The design:** `<workspace>/tools/w03/digest/DESIGN.md`, revision 2 (sha256 `206f293b79c74dddab43dd7343c4d97fca626fd634fd2d6c7eba8431055829a0`, a copy
  in `DESIGN.rev2.md`). Revision 1 is `DESIGN.rev1.md` (`f03d8091…`).
- **Round 1:** `reviews/design-review-round1.json` (`46f233d5…`): findings D1-1..D1-19, 22 attack cases and the
  positions on Q-DC-1..4.
- **The decisions:** `OWNER_DECISIONS.md`, verbatim, including the round-1 rulings R1-A, R1-B and R1-C.
- **The dossier:** `DOSSIER.md` (`012e83a5…`).
- **The repositories,** read through `git show` only, in the checkouts the launch prompt names: harness-onion
  (`26a8affb`) and R10 (`dd7422ed`).

## What to check

1. **Each round-1 finding.** For D1-1..D1-19, is it resolved as round 1 required, or as a ruling decided? Name any that
   is not, or is only partly resolved.
2. **All 22 round-1 attack cases.** Re-run every case in the round-1 record's `adversarialCases` on paper against
   revision 2: refused, under a named residual with its check, or still passing wrongly. Take round 1's tally from the
   record itself (11 refused, 2 residual, 9 PASSES-WRONGLY), not from any summary, and give revision 2's tally for the
   same 22 cases.
3. **New attack cases against the changes.** Try at least these:
   - the capture gates (§4.6, §5.3, §5.4): a stale or expired capture view; a slot that passed in an earlier set; a set
     where only some slots ran;
   - §4.1's rendering: sealed values that render to the pinned hash while the loaded directory holds a second file;
     a configuration successor whose three sealed values differ from the release's;
   - `podSecurityLabels` (R1-C): a label added, removed or changed; a Pod Security label on another namespace; an
     exemption in the apiserver's PodSecurity configuration;
   - §4.4's selector-free form: `ipBlock` with `except`; an ingress rule with no `from`; a `policyTypes` change;
   - §4.5's rule filter: a ClusterRoleBinding to a ClusterRole whose rules are namespaced, and a RoleBinding to a
     ClusterRole;
   - the non-resource entries: duplicates and ordering across ClusterRoles;
   - an echo path anywhere, including the fixed identities.
4. **Feasibility.** Every input still needs no new permission under `HO:architecture/i06-backend-profile-v4/observer-rbac.json`,
   no Secret data and no new host read. The new inputs are the Namespace labels, the capture verdicts and the three
   sealed admission values in the configuration successor.
5. **Determinism.** Could HE-008 and the observer compute different bytes for the same cluster? Check the sort rules,
   the integer bound, the fixed identities and the closure value's shape.
6. **Fidelity.** Does revision 2 decide anything that neither the decisions nor the rulings decided?
7. **Facts.** Spot-check the new citations: the 20 BROKER members, NP4R's class rows, `REQUIRED_BACKEND`, I07 v3's
   NetworkPolicy, `a2_objects`' four sealed values and the guard, and the PodSecurity facts.

## Output

Write `WORK/design-review-round2.json`:

```
{"subject": {"design": "DESIGN.md rev 2", "sha256": "206f293b79c74dddab43dd7343c4d97fca626fd634fd2d6c7eba8431055829a0"}, "reviewer": "independent agent", "model": "<id>",
 "brief": {"path": "tools/w03/digest/DESIGN_REVIEW_BRIEF_R2.md", "sha256": "<as computed>"},
 "verdict": "PASS_FOR_CONTRACT" | "CHANGES_REQUIRED",
 "round1": [{"id": "D1-n", "status": "resolved|partly|open", "note"}],
 "round1Cases": {"round1Tally": {"refused": 11, "residual": 2, "PASSES-WRONGLY": 9}, "rev2Tally": {...},
                "cases": [{"case", "round1Outcome", "rev2Outcome", "where"}]},
 "findings": [{"id": "D2-n", "severity": "MAJOR|MINOR|NOTE", "location", "finding", "requiredChange"}],
 "adversarialCases": [{"case", "outcome": "refused|residual|PASSES-WRONGLY", "where"}],
 "checks": [{"check", "result"}], "notChecked": [...]}
```

Reply with the verdict, the brief's sha256 as you computed it, and one line per finding.
