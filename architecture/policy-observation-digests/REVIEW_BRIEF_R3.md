# The I01 digest contract: independent contract review, round 3 (candidate 3, narrow delta)

You are an independent reviewer. You did not write the design, the contract, the build script or any earlier review.
Judge whether candidate 3 applies exactly the three narrow changes ruled after contract review round 2, and nothing
else. Candidate 2 already passed for adoption; it implemented the reviewed design (revision 3) and the rulings exactly, whether its vectors pin
what they claim, and whether an observer following it refuses whenever the live cluster's enforcement differs from what
the release binds, without ever echoing the binding. Record what you actually checked, and never claim a check you did
not run.

WORK = `<scratch>/digest-contract-r3`. TOOLS = `<workspace>/tools/w03/digest`.

## Hard rules (every command, no exceptions)

- **The prefix, first on every command line:**
  `while [ -e /opt/planeon/verifier-control/PAUSE ] || [ -e <scratch>/digest-contract-r3/PAUSE ] || [ -e <workspace>/lane-guard/HOLD_BY_VERIFY ]; do sleep 5; done;`
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
- **git grep -l or exact paths only. No ls-tree of any directory**, no `git show <commit>:<directory>` (that prints
  a listing), and no `git show -s` or any other `git show` form except `git show <commit>:<exact file>`
  (MON-DIG-CR2-SHOWS). Read `architecture/artifact-edges/` by exact path only.
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

- **Candidate 3, the STAGE tree** `TOOLS/contract/`:

  | Path | sha256 |
  |---|---|
  | `architecture/policy-observation-digests/README.md` | `ab979d024e98aa5abcaa0967a94928929c42b27650cbbf62ecfcefc60bc61d4b` |
  | `architecture/policy-observation-digests/definitions.json` | `89429eadda1d9795db1da3f48559537480a8081aa4c00032c7ff3d44491d8680` |
  | `architecture/policy-observation-digests/vectors.json` | `be9607bdf1560dc0aca60e04cdfde849c0c8828be4e815a0ea778381d26cb17e` |
  | `scripts/policy_observation_digests.py` | `c3f8de97192e12e4abdbc469e6d3e7344caac3cfe8a54519a9a902f5d64c1150` |
  | `architecture/artifact-edges/operator-harness-engineering-v10.json` | `e1a9ae47cdc65abb5a3a059506e7dd17c0d354f8f7a8060b211dad701f59e824` |
  | `architecture/artifact-edges/README-v10.md` | `c5703eed46b010b2ddca83502657145f9786fc902aaae29e70700a6928db786f` |

- **The build:** `TOOLS/build_contract.py` (`0f9911fce052af213ed180407f7708186244bec18e378cdcc2a5992219f736c3`), `TOOLS/src/`, and the builder's report
  `TOOLS/BUILD_REPORT_C3.md` (`f75d4bc468e93ffdc0696a18606334ce62bb8791ef425a27039822c68e3b1a22`).
- **Candidate 2, for the delta:** `TOOLS/rounds/c2/` (the STAGE tree, `build_contract.c2.py`, `BUILD_REPORT_C2.md`).
- **Contract review round 2:** `TOOLS/reviews/contract-review-round2.json`
  (`38c76f4559e0f8eb4ddf658682f96fa8daa30c8207db3d25001ac31156056a11`): PASS_FOR_ADOPTION on candidate 2, with NOTEs
  C2-1..C2-3.
- **The decisions:** `TOOLS/OWNER_DECISIONS.md` (`ea1cbcd2354f54fb5c229e1d22cf07f8528c7deffc6a280fab6f68141513f46b`), verbatim. The ruling R-C2 (a) admits exactly three
  changes: vector G-22b (C2-1), vector RB-32 (C2-2), and C2-3's text additions (`rbac: malformed input` in
  rbacClosureDigest's refusal list, one README §5.2 clause, and the gate's three `<key>: malformed input` texts in
  `captureGate.refusals`). Edge v10's three contract rows take the final bytes' sha256.
- **The repositories:** harness-onion at **`30f41e6f`**, in the checkout the launch prompt names (needed only for the
  determinism runs, through the build script's git helper).

## What to check

1. **The diff, c2 → c3, file by file.** Every change is one of the three ruled changes or edge v10's row digests that
   follow from them. Name any other change.
   - **The model file** may differ from candidate 2's only in the two data lists that `definitions()` returns for C2-3
     (rbacClosureDigest's refusals and `captureGate.refusals`): `definitions.json` must equal the model's
     `definitions()`, which the model's `main` checks. No derivation, check or vector code may change.
   - **`build_contract.py`** may differ only where it pins its sources' digests or names the candidate.
   - **RB-32** also pins its text for `rbacClosureDigest`, as RB-31 does; judge whether that stays within C2-2.
   - **README-v10** prints the contract rows' hashes and sizes, so those lines follow edge v10's rows.
2. **The 150 candidate-2 vectors** are byte-identical in candidate 3: compare each vector's canonical bytes by id.
3. **The two new vectors.** G-22b and RB-32 match C2-1's and C2-2's requiredChange texts and pass the model's
   self-check. G-22b refuses through the monotonic rule with the wall age inside the bound, and RB-32 gives
   "rbac: malformed subject kind".
4. **C2-3's texts** are in `definitions.json` and README §5.2 as ruled, and each added text is one the model can
   actually produce. Say how you know.
5. **Determinism.** Read the build script's git helper first; if it still allows only `git show <commit>:<file>` plus the
   five ruled forms (pathspec-limited where ruled), run `build_contract.py` twice into fresh WORK directories and
   compare with the STAGE tree byte for byte. Run the model's self-check from a WORK copy.
6. **Hygiene.** No local path, legacy term or personal data in any STAGE file; no status line in either README.

Anything you find above NOTE goes to the monitor before adoption, so classify carefully.

## Output

Write `WORK/contract-review-round3.json` (check this name: it is round 3 of the **contract** review):

```
{"subject": {"candidate": 3, "files": {"<path>": "<sha256>", ...}}, "reviewer": "independent agent", "model": "<id>",
 "brief": {"path": "tools/w03/digest/CONTRACT_REVIEW_BRIEF_R3.md", "sha256": "<as computed>"},
 "verdict": "PASS_FOR_ADOPTION" | "CHANGES_REQUIRED",
 "diff": [{"path", "change", "ruled": true|false}], "c2VectorsIdentical": true|false,
 "findings": [{"id": "C3-n", "severity": "BLOCKING|MAJOR|MINOR|NOTE", "location", "finding", "requiredChange"}],
 "checks": [{"check", "result"}], "notChecked": [...]}
```

Reply with the verdict, the brief's sha256 as you computed it, the diff summary, the 150-vector identity result,
the determinism result, and one line per finding.
