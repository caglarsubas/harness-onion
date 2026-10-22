# The I01 digest contract: independent contract review, round 2 (candidate 2, delta)

You are an independent reviewer. You did not write the design, the contract, the build script or any earlier review.
Judge whether candidate 2 resolves contract review round 1's findings, still implements the reviewed design (revision 3) and the rulings exactly, whether its vectors pin
what they claim, and whether an observer following it refuses whenever the live cluster's enforcement differs from what
the release binds, without ever echoing the binding. Record what you actually checked, and never claim a check you did
not run.

WORK = `<scratch>/digest-contract-r2`. TOOLS = `<workspace>/tools/w03/digest`.

## Hard rules (every command, no exceptions)

- **The prefix, first on every command line:**
  `while [ -e /opt/planeon/verifier-control/PAUSE ] || [ -e <scratch>/digest-contract-r2/PAUSE ] || [ -e <workspace>/lane-guard/HOLD_BY_VERIFY ]; do sleep 5; done;`
  Wrap every command in `timeout 600`. One process at a time.
- **Light and read-only.**
  - Read repositories only through `GIT_OPTIONAL_LOCKS=0 git -C <repo> show <commit>:<exact path>` and pruned
    `git grep -l`. Never run anything inside a checkout and never write to one.
  - You may run `python3 -I -B` only over copies under WORK: copies of the STAGE files, of `TOOLS/build_contract.py`
    and `TOOLS/src/`, and the scratch copies named below.
  - **Never import `scripts/validate_policy_observation.py` (VPO) or `scripts/validate_readiness.py`, and never copy
    them into WORK.** VPO's module-level import chain executes `scripts/validate_enforcement_test_plan.py`, an
    excluded file (MON-DIG-BUILD-ETP-IMPORT). Judge VPO's rules by reading VPO's text with `git show`.
  - You may copy `scripts/validate_proxy_contract.py` (VPC) and `scripts/safe_yaml.py` by `git show` into WORK and
    import VPC: it imports only `safe_yaml`, `jsonschema` and `yaml`. Check that before importing.
  - No cargo, pytest over a repository, verifier or sim.
  - Write only in WORK.
- **git grep -l or exact paths only. No ls-tree of any directory**, and no `git show <commit>:<directory>` (that prints
  a listing). Read `architecture/artifact-edges/` by exact path only.
- **Running `build_contract.py` (ruling R-C1-9 (a)).** For your two determinism runs, the script may use, besides
  `git show <commit>:<exact file>`, exactly five read-only forms: `rev-parse`, `log -1`, `ls-tree` on one exact file
  path, `diff --name-only` and `cat-file -e`. `diff --name-only` and `log -1` must always carry an explicit pathspec
  limited to the contract's inputs. Read the script's git helper first and confirm it enforces exactly this; if it
  does not, do not run it, and record a finding.
- **NO network.** Never put an email address, a name or personal data anywhere. Never write the legacy brand term (the
  old company word in the workspace folder path) in any file; build any scan string for it from parts. Use
  `<workspace>/` in your record.
- **Safety:** never write, import or run code that interposes on, forwards, proxies, swaps or bypasses anything. Judge
  bypass forms on paper. Mutants of VPC's three helpers and of the model, under WORK only, are allowed for the mutation
  checks below. No classifier or inventory tooling.
- **Independence:** never open the R12 repository, `tools/w04/`, `architecture/enforcement-test-plan/`,
  `docs/alpha-2/ENFORCEMENT_TEST_PLAN.md` or R12's `tests/enforcement/`. Exclude them, and
  `scripts/validate_enforcement_test_plan.py` and `tests/test_enforcement_test_plan.py`, from every grep with `:!`
  pathspecs.
- **Forbidden paths (never read):** `<workspace>/keys`, `github-app`, `/var/db/harness-ci`, any
  `operator-private/` directory, any memory file. Under `<workspace>/tools/`, open only the TOOLS
  files listed under Subject, by exact path.
- Python: always `python3 -I -B`.

## Subject

- **Candidate 2, the STAGE tree** `TOOLS/contract/`:

  | Path | sha256 |
  |---|---|
  | `architecture/policy-observation-digests/README.md` | `935a61084c2a7e07b317e60a47db02ae178d273f2770e511cdc5a28d42b79a8e` |
  | `architecture/policy-observation-digests/definitions.json` | `1a97df323be20345d7bbf836e019d0eafc32d3b906e8e19254c0d45c735e4f4a` |
  | `architecture/policy-observation-digests/vectors.json` | `d34d1990e7919803c9ef9b18fcae76c9c3fd4caa11296c416ac38d25adb58e5f` |
  | `scripts/policy_observation_digests.py` | `516231ef47faefeb9369dc0a935c24c6680e4a3cc439a40af7f027dd55eb64e5` |
  | `architecture/artifact-edges/operator-harness-engineering-v10.json` | `f8264a8be26dafb58f218f7c6ecb4d23d41f12f3884f8d0ba7b23df1e9f7b615` |
  | `architecture/artifact-edges/README-v10.md` | `ba18b2a818ac688ef9cb88d05cd0d876e40ccbe93de09b76bee716a3eb8627ec` |

- **The build:** `TOOLS/build_contract.py` (`789fb94f6edded4e89c18080dca3be23d63d0c5cc35d68370efb8f1ddda81545`), `TOOLS/src/`, and the builder's report
  `TOOLS/BUILD_REPORT_C2.md` (`3fee279991e2bdc3d8ce04104a52667a44a60d157e4242d6fb1aa80cb701bc10`).
- **Candidate 1, for the delta:** `TOOLS/rounds/c1/` (the STAGE tree, `build_contract.c1.py`, `BUILD_REPORT_C1.md`).
- **Contract review round 1:** `TOOLS/reviews/contract-review-round1.json`
  (`6a7c55c4152b9619c3d9b26993e51ecbeb137949477f277e141815fe794cb28e`): findings C1-1..C1-11, its mutation lists (20
  helper mutants; 75 model mutants, 11 survivors) and its attack-case table.
- **The design:** `TOOLS/DESIGN.rev3.md` (`73cd9f6ddeab744b6b9c222204a9bdd4d0a0eef54e4c6f6321fe80bf28a9c083`).
- **The decisions:** `TOOLS/OWNER_DECISIONS.md` (`6c549188452d6840c092e50776cea8d9497d871867c9cb3a7151d6fe5c946fbd`), verbatim: R1-A..C, R2-A..C, R3-A/B, Q-CB-1..13, the C1
  handling and R-C1-9.
- **The design reviews:** `TOOLS/reviews/design-review-round1.json`, `-round2.json`, `-round3.json`.
- **The repositories:** harness-onion at **`30f41e6f`**, R10 at **`dd7422ed`**, in the checkouts the launch prompt
  names.

## What to check

1. **Each round-1 finding, one by one.** For C1-1..C1-11: resolved as the record required and the monitor accepted (C1-4
   takes all four vectors; C1-6 drops the four texts; C1-8 leaves no status line), partly resolved, or open. C1-1's
   README wording must name the layer test's assertions with no skip, expected-failure mark or import guard.
2. **The delta.** Diff candidate 2 against candidate 1 file by file. Is every change explained by a C1 finding or a
   ruling? Name any change that is not.
3. **Mutants.**
   - Re-run the 11 model mutants that survived round 1 (the record's `mutations.model`) against candidate 2, and report
     which are now killed. A survivor that changes a security outcome is a finding.
   - Re-run at least one helper mutant per VPC function (Q-CB-1). The two equivalent VPC survivors (`allow_nan=True`
     and admitting floats) may stay; record their reason.
4. **Attack cases.** Re-confirm all 67 cases (22 + 22 + 23) against candidate 2, with the tally per set next to round
   1's (20/2/0, 18/4/0, 18/5/0 as refused/residual/passes wrongly).
5. **Determinism.** Run `build_contract.py` twice into fresh WORK directories (after confirming its git helper, above)
   and compare with the STAGE tree byte for byte.
6. **The complete I01 positive.** Run VPC's `validate_profile` on its profile from a WORK copy of VPC. Do not import
   VPO; re-check on paper that the positive still satisfies VPO's comparisons if any input to it changed.
7. **Edge record v10** derived from candidate 2's final bytes; v9's 68 rows unchanged; PPS not registered.
8. **Hygiene.** No local path, legacy term or personal data in any STAGE file; no status line in the vendored README or
   README-v10; nowhere is VPC "pinned by digest".
9. **New questions Q-CB-14..16** (in BUILD_REPORT_C2.md: AP-14 beyond the C1 list; mutant 22 undetectable while v1
   has one NetworkPolicy; the layer test named in the README and docstring but not in `definitions.json`): agree, or say
   what should change.

## Output

Write `WORK/contract-review-round2.json` (check this name: it is round 2 of the **contract** review):

```
{"subject": {"candidate": 2, "files": {"<path>": "<sha256>", ...}}, "reviewer": "independent agent", "model": "<id>",
 "brief": {"path": "tools/w03/digest/CONTRACT_REVIEW_BRIEF_R2.md", "sha256": "<as computed>"},
 "verdict": "PASS_FOR_ADOPTION" | "CHANGES_REQUIRED",
 "round1": [{"id": "C1-n", "status": "resolved|partly|open", "note"}],
 "findings": [{"id": "C2-n", "severity": "BLOCKING|MAJOR|MINOR|NOTE", "location", "finding", "requiredChange"}],
 "mutations": {"helpers": [{"function", "mutation", "rejectedBy" | "equivalent: <reason>"}], "round1Survivors": [{"point", "mutation", "killedBy" | "survived"}]},
 "attackCases": {"tallies": {"round1": {...}, "round2": {...}, "round3": {...}}, "cases": [{"set", "case", "outcome", "vector"}]},
 "questions": [{"id": "Q-CB-n (14 and up)", "position": "agree|amend|disagree", "reason"}],
 "checks": [{"check", "result"}], "notChecked": [...]}
```

Reply with the verdict, the brief's sha256 as you computed it, the C1 status list, the round-1 survivors now killed
and still surviving, the tallies, the determinism result, and one line per finding.
