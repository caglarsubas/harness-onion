# The I01 digest contract: independent design review, round 1

You are an independent reviewer. You did not write this design or its dossier. Judge whether the design is correct,
complete, sound and faithful to the decisions. The test is concrete: an observer following it must refuse whenever the
live cluster's enforcement differs from what the release binds, and must never echo the binding. Record what you
actually checked, and never claim a check you did not run.

WORK = `<scratch>/digest-design-r1`

## Hard rules (every command, no exceptions)

- **The prefix, first on every command line:**
  `while [ -e /opt/planeon/verifier-control/PAUSE ] || [ -e <scratch>/digest-design-r1/PAUSE ] || [ -e <workspace>/lane-guard/HOLD_BY_VERIFY ]; do sleep 5; done;`
  Wrap every command in `timeout 120`.
- **Read-only and light:**
  - Allowed: `git -C <repo> show <commit>:<exact path>`, `git grep -l` with pruned pathspecs, and `python3 -I -B`
    scripts that parse text you saved into WORK. Use `GIT_OPTIONAL_LOCKS=0`.
  - Not allowed: running any repository script, test, build or cargo.
  - Write only in WORK.
- **git grep -l or exact paths only. No ls-tree of any directory** (monitor rule MON-DIG-LSTREE), and no unpruned walks.
- **NO network.** No personal data, addresses or names. Never write the legacy brand term (the old company word in the
  workspace folder path) in any file. Use `<workspace>/` in your record.
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

- **The design:** `<workspace>/tools/w03/digest/DESIGN.md`, revision 1 (sha256 `f03d8091…`, a copy in
  `DESIGN.rev1.md`).
- **The dossier:** `DOSSIER.md` (`012e83a5…`). Its facts cite harness-onion at `26a8affb` and R10 at `dd7422ed`.
- **The decisions:** `OWNER_DECISIONS.md`, verbatim: owner Q-HE4I1-2 (c)+(a), monitor Q-I01B-1..5, **owner Q-DIG-3/7
  "Accept, check at T04"**, monitor Q-DIG-1, 2, 4–6 and 8–18, and MON-DIG-LSTREE.
- **The repositories,** read through `git show` only, in the checkouts the launch prompt names: harness-onion
  (`26a8affb`; current main `26a8affb`) and R10 (`dd7422ed`).

## What to check

1. **Fidelity.** Is each of Q-DIG-1..18 and the owner's Q-DIG-3/7 frame carried exactly: all four digests defined now,
   every unseen part a named residual with a T04 check, and the observer's permissions unchanged? Is anything decided
   that the decisions did not decide?
2. **Soundness, adversarially, on paper.** For each projection and digest, try to construct a live cluster whose
   enforcement differs from the release's while the observer's derived value still matches. For example:
   - a second ResourceQuota;
   - a changed LimitRange `spec` with an equal digest;
   - an aggregated role;
   - a NetworkPolicy added beside the bound one;
   - a ClusterRoleBinding that reaches the namespace;
   - a broker row that matches while the live broker differs;
   - a static admission directory that matches while a dynamic ValidatingAdmissionPolicy is added;
   - an echo path anywhere.

   Does each such case either refuse, or sit under a named residual with its check?
3. **Determinism.** Are the documents fully determined: member sets, sorted sets, null against absent, the uid
   derivation, canonical bytes and integer exactness? Could HE-008 and the observer compute different bytes for the same
   cluster?
4. **Feasibility under the pinned role.** Check against `HO:architecture/i06-backend-profile-v4/observer-rbac.json` and
   `R10:host-enforcement/crates/observer/src/inputs.rs`. Can the observer read every input the design names without new
   permissions, and without using Secret data?
5. **The record facts.** Verify the design's reading of the native-profile v4 record schema:
   - `$defs.roles.BROKER`'s members;
   - `$defs.backendComponent`, with no sealed flags;
   - judge the §4.7 member choice (Q-DC-3).
6. **The wire fit.** Is it plausible that one complete I01 positive with real derived digests passes VPO unchanged?
   Read `scripts/validate_policy_observation.py`.
7. **The supersession table (§7).** Is it complete and correct against RD, NQ and PCR? Are the cycles avoided: the
   broker binding, and the release and self digests?
8. **Edge record v10 (§10).**
   - The rows and the consumer path.
   - Is PPV the right extra registration?
   - Does the I01 binding and observation replay read anything else, such as PPS or another input?
9. **The residual table (§8).** Is it complete? Is each residual stated precisely enough for T04 to check?
10. **The design questions Q-DC-1..4:** agree, or say what should change.

## Output

Write `WORK/design-review-round1.json`:

```
{"subject": {"design": "DESIGN.md rev 1", "sha256": "f03d8091…"}, "reviewer": "independent agent", "model": "<id>",
 "brief": {"path": "tools/w03/digest/DESIGN_REVIEW_BRIEF.md", "sha256": "<as computed>"},
 "verdict": "PASS_FOR_CONTRACT" | "CHANGES_REQUIRED",
 "findings": [{"id": "D1-n", "severity": "MAJOR|MINOR|NOTE", "location", "finding", "requiredChange"}],
 "adversarialCases": [{"case", "outcome": "refused|residual|PASSES-WRONGLY", "where"}],
 "questions": [{"id": "Q-DC-n", "position": "agree|amend|disagree", "reason"}],
 "checks": [{"check", "result"}], "notChecked": [...]}
```

Reply with the verdict, the brief's sha256 as you computed it, and one line per finding.
