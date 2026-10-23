# LPK-0 (the probe-kit scope amendment): independent contract review, round 2 (the last contract round)

You are an independent reviewer. You did not write this contract, its design, its build rules or any earlier review, round 1's included.

Judge whether contract candidate c2 resolves round 1's findings as ruled and is a faithful, complete and correct build of the closed design and its binding build
rules, at harness-onion `2043cc27`. The test is concrete. Under this record:
- every pinned statement that gives CONF-LIVE-003/004/005 a moved item is superseded by a quote that matches its bytes,
  with the right structured items;
- no quote overlaps a statement that stays true;
- nothing pinned is edited;
- nothing moves that the owner did not move;
- the model refuses what the design says it refuses.

Record what you actually checked, and never claim a check you did not run.

**The monitor's cap (Q-LPK0-CCAP): this is the last contract round.**
- **PASS_FOR_ADOPTION** needs no MAJOR and every planted mutation the design or the rules require to be refused,
  refused.
- **Re-run all of round 1's planted mutations,** P1-P29, exactly as its record states them. Then plant your own, at
  least ten.
- **Remaining NOTEs** become adoption conditions, so state each one precisely.
- **A MAJOR** goes to the monitor.

WORK = `<scratch>/lpk0-contract-r2`. TOOLS = `<workspace>/tools/w03/probekit`.

## Hard rules (every command, no exceptions)

- **The prefix, first on every command line:**
  `while [ -e /opt/planeon/verifier-control/PAUSE ] || [ -e <scratch>/lpk0-contract-r2/PAUSE ] || [ -e <workspace>/lane-guard/HOLD_BY_VERIFY ]; do sleep 5; done;`
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

**The decisions:** `TOOLS/OWNER_DECISIONS.md` (`36d3c1defda9d21dbf9b795b2d5ec96fd1e2fc243a3de68cecce392956690311`),
verbatim. It includes the monitor's r1 rulings: R-C1-A in full; CONFORMANCE_CONSUMER_CLOSURE.md:112 as
ORDERING_PREREQUISITE; Q-LPK0-CCAP.

**Candidate c2:** `TOOLS/lpk0/rounds/c2/`. Candidate c1, in `rounds/c1/`, is kept for comparison.

| File | sha256 |
|---|---|
| `amendment.json` | `ac6351bb9362eb6077da572db3745aa26d17df370f51fd7fd932b0bd0ce17140` |
| `vectors.json` | `c05dffa33c2724d7f2cc6eddf3e9b31632e9af870f1002489e32baabbfdf93bf` |
| `probe_kit_scope.py` (the model, rendered from `probe_kit_scope.tmpl.py` with its fixed tables) | `4f9ddfc22b42f48ca84ddb9085549a823ef7fcb1e887c61eb8e50576ecd66d0b` |
| `README.md` (the contract text) | `ff13032db7d51d0ef861e3da489fb56bf87e58243c5d5180c26de1144e168a0e` |
| `docs-linux-probe-kit-README.md` | `66d28efbb0b180fc1013fc669ad00fca1fd12a108f0cdfc8150cdf22a50e9241` |
| `build-report.json` | `88b955b29666476ef0083961d6824705977c77d0de319d4d02c3c95417b6d9b8` |
| `status_lines.json` (S3-15's enumerated STATUS_LINE lines, C1-10) | `71aa7715745e69f5e2f548d8155b40c13c2b63867c6f16e19d20d3b38a8725ef` |
| `hits.json`, `search.py`, `build_contract.py`, `make_vectors.py`, `probe_kit_scope.tmpl.py` | the build's inputs and scripts |

**The earlier records:**
- `TOOLS/lpk0/reviews/design-review-round{1,2,3}.json`;
- contract review round 1, `TOOLS/lpk0/reviews/contract-review-round1.json` (`3c781525…`), with its findings C1-1..C1-14
  and its planted mutations P1-P29.

**The repository:** harness-onion at `2043cc27`, in the checkout the launch prompt names.

## What to check

1. **Each round-1 finding, C1-1..C1-14:** resolved as ruled, partly resolved, or open.
2. **Round 1's planted mutations, P1-P29, re-run on c2.** Copy the model into WORK and run it there. Record each
   mutation's refusal. Then plant at least ten of your own against c2's new checks:
   - the fixed tables;
   - closed members and sort orders;
   - the line-file class rule;
   - covered-means-QUOTED;
   - overlapping spans;
   - `crossInputs`;
   - case-folded changed files.

   Name every mutation that a correct model must refuse and c2 accepts.
3. **The record, against the base bytes, independently.** Check the quotes, the sha256 values, the search and the
   searchDigest, the classes, and the 16 ownerDecisions quotes per section. Confirm that the c1 → c2 changes to
   `amendment.json` are only the ruled ones:
   - `crossInputs`;
   - `class` on file rows;
   - the S-17, S-08 and S-10 texts;
   - line 112;
   - anything else C1-1..C1-14 require.

   Name any other difference.
4. **The fixed tables.** Are the model's tables exactly the rows the design and the build rules fix? Check S3-2 and
   S3-4's rows and the staysTrue spans, the amends and predecessor tables, `fromPacket` and the deferred row.
5. **The build.** Does it now refuse an unlisted hit? Does `status_lines.json` list exactly the STATUS_LINE lines,
   and is each line's disposition right? Read them in context, for scope only.
6. **Every build rule still applied,** S3-1..S3-17.
7. **The README.**
   - Can a D5a oracle author now work from it alone: the 45-row table, the 12 quotes and the closed shape?
   - Is it faithful to the record?
   - Does it state S3-7, S3-8's packet-review sentence and C1-14's sentence?
8. **Gate material.** Is every changed path, the adoption records included, data under `2043cc27`'s evolution-surface
   record?

## Output

Write `WORK/contract-review-round2.json`. Check this name: round 2 of LPK-0's contract review.

```
{"subject": {"candidate": "LPK-0 contract c2", "amendmentSha256": "ac6351bb"…}, "reviewer": "independent agent", "model": "<id>",
 "brief": {"path": "tools/w03/probekit/lpk0/CONTRACT_REVIEW_BRIEF_R2.md", "sha256": "<as computed>"},
 "verdict": "PASS_FOR_ADOPTION" | "CHANGES_REQUIRED",
 "round1": [{"id": "C1-n", "status": "resolved|partly|open", "note"}],
 "buildRules": [{"id": "S3-n", "status": "applied|partly|not applied", "note"}],
 "findings": [{"id": "C2-n", "severity": "MAJOR|MINOR|NOTE", "location", "finding", "requiredChange"}],
 "lineDispositions": [{"path", "line", "recorded", "proposed", "reason"}],
 "plantedMutations": [{"mutation", "source": "r1|r2", "required": true|false, "refused": true|false, "refusal"}],
 "checks": [{"check", "result"}], "notChecked": [...]}
```

Reply with:
- the verdict;
- the brief's sha256 as you computed it;
- the C1 status list and the build-rule status list;
- every required mutation that passes, of round 1's and your own;
- any disposition you would change;
- one line per finding.
