# LPK-0 (the probe-kit scope amendment): independent contract review, round 1

You are an independent reviewer. You did not write this contract, its design, its build rules or any earlier review.

Judge whether contract candidate c1 is a faithful, complete and correct build of the closed design and its binding build
rules, at harness-onion `2043cc27`. The test is concrete. Under this record:
- every pinned statement that gives CONF-LIVE-003/004/005 a moved item is superseded by a quote that matches its bytes,
  with the right structured items;
- no quote overlaps a statement that stays true;
- nothing pinned is edited;
- nothing moves that the owner did not move;
- the model refuses what the design says it refuses.

Record what you actually checked, and never claim a check you did not run.

WORK = `<scratch>/lpk0-contract-r1`. TOOLS = `<workspace>/tools/w03/probekit`.

## Hard rules (every command, no exceptions)

- **The prefix, first on every command line:**
  `while [ -e /opt/planeon/verifier-control/PAUSE ] || [ -e <scratch>/lpk0-contract-r1/PAUSE ] || [ -e <workspace>/lane-guard/HOLD_BY_VERIFY ]; do sleep 5; done;`
  Wrap every command in `timeout 120`. Run one process at a time, in the foreground, with no pipes between processes.
- **Read-only and light.**
  - Allowed:
    - `GIT_OPTIONAL_LOCKS=0 git -C <repo> show 2043cc27:<exact file>`;
    - pruned `git grep -l` at `2043cc27`;
    - the declared search's two `git grep -l -E` runs exactly as the record's `inventory` states them;
    - `python3 -I -B` over files copied into WORK. That includes the candidate's own `probe_kit_scope.py`,
      `make_vectors.py` and `build_contract.py`, copied into WORK and run there, and your own independent scripts.
  - Not allowed:
    - running or importing any repository script, test or validator (in particular
      `scripts/validate_policy_observation.py` or `scripts/validate_readiness.py`);
    - `git show -s`, `git show <commit>:<directory>` or `git ls-tree` of any directory;
    - **`git grep -l -e ''` listings**, unpruned walks, or listing any directory of the checkout.
  - Write only in WORK, and never write into TOOLS.
- **NO network.** No email address, name or personal data anywhere. Never write the legacy brand term (the old company
  word in the workspace folder path) in any file. If a saved repository copy contains it, scan it only by script and
  delete it after use. Cite `HO:<path>:<lines>` at `2043cc27`.
- **Independence.**
  - Never open the R12 repository (mas-harness-conformance-labs), `tools/w04/`, `architecture/enforcement-test-plan/`,
    `docs/alpha-2/ENFORCEMENT_TEST_PLAN.md` or any `tests/enforcement/`.
  - Exclude them, `scripts/validate_enforcement_test_plan.py`, `tests/test_enforcement_test_plan.py` and `tools/w03*`
    from every grep with `:!` pathspecs.
  - Read `architecture/artifact-edges/` by exact path only.
  - Never summarise R12's test logic, or the test lists in harness-onion guides. Read those for scope only.
- **Forbidden paths (never read):**
  - `<workspace>/keys`, `github-app`, `/var/db/harness-ci`, any `operator-private/` directory, any
    memory file;
  - under `<workspace>/tools/`, anything except `w03/probekit/`. There, open only `lpk0/` and
    `OWNER_DECISIONS.md`.
- **Safety:** never write, import or run code that interposes on, forwards, proxies, swaps or bypasses anything.
- **Python:** always `python3 -I -B`.

## Subject

**The design and its binding rules:**
- `TOOLS/lpk0/DESIGN.rev3.md` (`80add650443ccf1a90a4d4d22075d7a38709a03d23471ca1b3f2f37937ac0ae9`), closed under
  Q-LPK0-CAP;
- `TOOLS/lpk0/BUILD_RULES.md` (`c71a3345ccb93cbb2f8c5a29f11aa30048dd2ba412b73809d3a65ba4a2e9d48b`), with S3-1..S3-17
  binding. Where a rule and the design differ, the rule governs.

**The decisions:** `TOOLS/OWNER_DECISIONS.md` (`30feac86f629dbb8a3524c47bd98e999afde61e1cf2097f89b80239eb1e9ad5c`),
verbatim.

**Candidate c1:** `TOOLS/lpk0/rounds/c1/`.

| File | sha256 |
|---|---|
| `amendment.json` | `596fd442951d59c9ef4743eb3179bd73fdb6707c7eba71ff3f79c8e658bd072a` |
| `vectors.json` | `9067689ca1e152a4b939fa6effdf2f8dc55599f0ca8c4429f612a3ccaadfb8fc` |
| `probe_kit_scope.py` (the model) | `f07f814858be04b9120be5e631f8ec911ff91dd04acdd059c32df53a79fb9dbd` |
| `README.md` (the contract text) | `4e069c3d16455be36ed0d1b7bc3e29adb1b33d0768409f35d44a368cd6a3c444` |
| `docs-linux-probe-kit-README.md` (the prose page) | `66d28efbb0b180fc1013fc669ad00fca1fd12a108f0cdfc8150cdf22a50e9241` |
| `build-report.json` | `0b3a1b69d6406be7ecf4980940be55ae94aeacd32f940dfb2c3d7efb47444e44` |
| `hits.json` | `4984246161aaf2c8241b428e94c6d7a31769686dc8215bd8005a93f97c7e9459` |
| `search.py`, `build_contract.py`, `make_vectors.py` | the build's scripts |

**The earlier records:** `TOOLS/lpk0/reviews/design-review-round{1,2,3}.json`.

**The repository:** harness-onion at `2043cc27`, in the checkout the launch prompt names.

## What to check

1. **Every build rule as applied, S3-1..S3-17, one by one: applied, partly, or not applied.** In particular:
   - S3-1's eight BH lines;
   - S3-2's 26 rows and four stays-true spans, quote by quote and item by item;
   - S3-3's KAP-alone rule;
   - S3-4's one-quote rows, the lines rule and PCA:253's split;
   - S3-5's COMPLETION_INTEGRATION.md handling;
   - S3-6's section check, which you re-run yourself against `OWNER_DECISIONS.md`;
   - S3-7's changed-files check;
   - S3-9's pipeline;
   - S3-10's class rules and counts;
   - S3-11's four vectors;
   - S3-13's known items;
   - S3-14's restored text;
   - S3-15's mapping;
   - S3-16's tokens.

   S3-8, S3-12 and S3-17 are mechanics rules. Check only that the contract does not contradict them, and that the README
   states S3-8's gate.
2. **The record against the base bytes, independently.** With your own script, re-extract every `supersedes` and
   `staysTrue` quote at `2043cc27`. Check that each quote occurs exactly once within its lines, and that every sha256 and
   every inventory row's hit lines are right. Re-run the declared search yourself and compare it with `hits.json` and the
   record's `searchDigest`.
3. **Every line disposition.** For each `LINES` file, read each hit line in context, for scope only. Is its disposition
   right? Is any line a moved-item assignment that needs a quote instead? Name every line you would change.
4. **The structured replacements.** Does each row's `movedItems` and `keptItems` match its quote's words and the owner's
   boundary (server side moves; client, handoff, receipt and evidence verification stay; KAP deferred)? Does each
   `text` say the same as the structured members?
5. **The model.**
   - Run the candidate model (copied to WORK) on the record and on every vector.
   - Then plant at least five mutations of your own that a correct model must refuse, and report any that pass.
   - Is any check in the design's §5 or the build rules missing from the model?
6. **The README and the prose page.** Are they faithful to the record and the decisions? Is anything stated that the
   record does not hold, or held that the README omits?
7. **Gate material.** Are the changed-files list and every path in it data under `2043cc27`'s evolution-surface record?
   Read its text; run nothing.

## Output

Write `WORK/contract-review-round1.json`. Check this name: round 1 of LPK-0's contract review.

```
{"subject": {"candidate": "LPK-0 contract c1", "amendmentSha256": "596fd442"…}, "reviewer": "independent agent", "model": "<id>",
 "brief": {"path": "tools/w03/probekit/lpk0/CONTRACT_REVIEW_BRIEF_R1.md", "sha256": "<as computed>"},
 "verdict": "PASS_FOR_ADOPTION" | "CHANGES_REQUIRED",
 "buildRules": [{"id": "S3-n", "status": "applied|partly|not applied", "note"}],
 "findings": [{"id": "C1-n", "severity": "MAJOR|MINOR|NOTE", "location", "finding", "requiredChange"}],
 "lineDispositions": [{"path", "line", "recorded", "proposed", "reason"}],
 "plantedMutations": [{"mutation", "refused": true|false, "refusal"}],
 "checks": [{"check", "result"}], "notChecked": [...]}
```

Reply with:
- the verdict;
- the brief's sha256 as you computed it;
- the build-rule status list;
- any planted mutation that passes;
- any disposition you would change;
- one line per finding.
