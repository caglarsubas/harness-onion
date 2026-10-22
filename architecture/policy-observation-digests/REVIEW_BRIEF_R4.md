# The I01 digest contract: independent contract review, round 4 (candidate 4, narrow text delta)

You are an independent reviewer. You did not write the design, the contract, the build script or any earlier review.
Judge whether candidate 4 applies exactly the two text clarifications ruled after the D5a oracle tests (R-ORC), and
nothing else, and whether both clauses describe the model's actual behaviour. Candidate 3 was adopted; it implemented the reviewed design (revision 3) and the rulings exactly, whether its vectors pin
what they claim, and whether an observer following it refuses whenever the live cluster's enforcement differs from what
the release binds, without ever echoing the binding. Record what you actually checked, and never claim a check you did
not run.

WORK = `<scratch>/digest-contract-r4`. TOOLS = `<workspace>/tools/w03/digest`.

## Hard rules (every command, no exceptions)

- **The prefix, first on every command line:**
  `while [ -e /opt/planeon/verifier-control/PAUSE ] || [ -e <scratch>/digest-contract-r4/PAUSE ] || [ -e <workspace>/lane-guard/HOLD_BY_VERIFY ]; do sleep 5; done;`
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

- **Candidate 4, the STAGE tree** `TOOLS/contract/`:

  | Path | sha256 |
  |---|---|
  | `architecture/policy-observation-digests/README.md` | `e393dd11c75f527829bb6522c5643cb593b6dc67e2788f5e280ce9de0f4166ae` |
  | `architecture/policy-observation-digests/definitions.json` | `086692065cfc9da101f770fa39c50af2e2650a169595526e9860fc805478c2aa` |
  | `architecture/policy-observation-digests/vectors.json` | `bd9f04bd04fcccc584bcab341ec649bcead567fe349c57e30958eaaf2ea64f84` |
  | `scripts/policy_observation_digests.py` | `01298fb5c6acdae3248174265bbe576dd553eeb19bce1a48cb1e2734972c09c5` |
  | `architecture/artifact-edges/operator-harness-engineering-v10.json` | `a4fad53dfadbe8a5d79d4049fbba83173adaacec8d33df5ca377aa288539364e` |
  | `architecture/artifact-edges/README-v10.md` | `3ae925596532dc491ceee829893793b49fb684a501ecdc049db6651062e79128` |

- **The build:** `TOOLS/build_contract.py` (`8d0567ff1dfc00887f013af8663bdf2e0c0cbc6416860438aac53d85df9db61e`), `TOOLS/src/`, and the builder's report
  `TOOLS/BUILD_REPORT_C4.md` (`69c582ee5dd04bef0317efd9ebedece1f26ec2faae495e9a0d013ebad22bbfda`).
- **Candidate 3, for the delta:** `TOOLS/rounds/c3/` (the STAGE tree, `build_contract.c3.py`, `BUILD_REPORT_C3.md`).
- **Contract review round 3:** `TOOLS/reviews/contract-review-round3.json`
  (`92ca9a332b2cbddfbd92fd64df89d6e3d57c65f4e9c66ae881f7d4678a49749b`): PASS_FOR_ADOPTION on candidate 3.
- **The decisions:** `TOOLS/OWNER_DECISIONS.md` (`8f95ea961ee9c3e728057b160a48542a8a855e249f23c75a366022a433d0921f`), verbatim. The ruling R-ORC (a) admits exactly:
  - in README §5.2 and in `definitions.json`, a clause defining the closure's caller-supplied `i06` input =
    {closure, inventory, bootstrap} (I06 v1's three frozen files, parsed as JSON, pinned in `frozenInputs`), with a
    missing or ill-shaped `i06` refusing "rbacClosureDigest: malformed input";
  - the corrected §5.2 order sentence: the namespace step first, under the closure's own malformed-input text, then
    rbac's texts and B1's, then the I06 checks;
  - edge v10's three contract-row hashes (and README-v10's table lines) following the final bytes.
  Because `definitions.json` must equal the model's `definitions()`, the `definitions.json` clause may come with a
  data-only change in the dict `definitions()` returns.
- **The oracle's two failures** (described in OWNER_DECISIONS.md's R-ORC section; you do not read the oracle test file).
- **The repositories:** harness-onion at **`30f41e6f`**, in the checkout the launch prompt names (for the determinism runs
  through the build script's git helper, and `git show 30f41e6f:<exact file>` if needed).

## What to check

1. **The diff, c3 → c4, file by file.** Every change is one R-ORC admits. Name any other change.
   - **The model file** may differ only in data inside the dict `definitions()` returns. No derivation, check or vector
     code may change. Show it, for example with an AST comparison of every function except `definitions()`.
   - **`build_contract.py`** may differ only where it pins its sources' digests, names the candidate or quotes the
     ruling.
2. **All 152 candidate-3 vectors** are byte-identical in candidate 4 (by id, canonical bytes); `vectors.json` changes at
   most in its pin of `definitions.json`.
3. **The two clauses against the model's behaviour.** Probe under WORK, on copies:
   - a closure call without `i06`, and with an `i06` missing one of its three members, refuses
     "rbacClosureDigest: malformed input";
   - with a valid `i06` built from the three frozen files at `30f41e6f` (read with `git show`, checked against their
     pinned sha256), a snapshot that fails the I06 checks refuses "rbacClosureDigest: I06 closure check not passed";
   - a missing qualification namespace refuses "rbacClosureDigest: malformed input" before any B1 text, and an input
     that reaches B1 refuses with rbac's or B1's texts.
   Does each clause now say exactly what the model does?
4. **Determinism.** Read the build script's git helper first; if it still allows only `git show <commit>:<file>` plus the
   five ruled forms (pathspec-limited where ruled), run `build_contract.py` twice into fresh WORK directories and
   compare with the STAGE tree byte for byte. Run the model's self-check from a WORK copy.
5. **Hygiene.** No local path, legacy term or personal data in any STAGE file; no status line in either README.

Anything you find above NOTE goes to the monitor before re-adoption, so classify carefully.

## Output

Write `WORK/contract-review-round4.json` (check this name: it is round 4 of the **contract** review):

```
{"subject": {"candidate": 4, "files": {"<path>": "<sha256>", ...}}, "reviewer": "independent agent", "model": "<id>",
 "brief": {"path": "tools/w03/digest/CONTRACT_REVIEW_BRIEF_R4.md", "sha256": "<as computed>"},
 "verdict": "PASS_FOR_ADOPTION" | "CHANGES_REQUIRED",
 "diff": [{"path", "change", "ruled": true|false}], "c3VectorsIdentical": true|false, "probes": [{"probe", "result"}],
 "findings": [{"id": "C4-n", "severity": "BLOCKING|MAJOR|MINOR|NOTE", "location", "finding", "requiredChange"}],
 "checks": [{"check", "result"}], "notChecked": [...]}
```

Reply with the verdict, the brief's sha256 as you computed it, the diff summary, the 152-vector identity result, the probes,
the determinism result, and one line per finding.
