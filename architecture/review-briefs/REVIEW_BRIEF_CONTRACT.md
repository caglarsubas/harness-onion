# Harness-Onion contract review: generic brief (CONTRACT kind)

Review one contract candidate. You are not its author.

**The rules file.** The launch message names a local round rules file, which both records pin by `rulesSha256`. It
gives:
- the packet id, the contract directory, and your series and round;
- the subject commit and tree, and the base;
- the design records and the decisions;
- the operator rules;
- where to write your record.

Its paths are local and stay out of this published brief. This brief is the same for every contract. What is particular
to one contract lives in its rules file, its design records and its contract directory.

## The subject

- **The contract directory's README:** the contract text.
- **The record or data files** it defines, with their schemas where the contract has them.
- **The reference model or checker:** standard library only, unless the decisions allow otherwise.
- **The vectors,** and the replay that runs them.
- **The candidate's tests,** and the D5a oracle tests, which an agent other than the author wrote and which an oracle
  identity binds.

## Check (at least)

1. **Faithfulness to the decisions.**
   - Every decision the rules file names appears in the contract as decided, with nothing added that a decision
     excludes.
   - Do not reopen a decision.
2. **The record against the design.**
   - Every member: required or optional, type and form.
   - Digests are 64 lowercase hex with no prefix, unless the contract states another form.
   - Name any member that differs.
3. **The model against the README.**
   - Every check and its refusal text or code, in the order stated.
   - Look for an input where the model is wrong, undefined or stricter than stated: wrong types, duplicates, case
     variants, empty and boundary values, and unusual characters in paths.
4. **Schema and model agree,** where the contract has a schema: the model refuses exactly where the schema rejects, as
   the README states.
5. **The vectors.**
   - Each expected value follows from the design, not from the model.
   - Name any wrong expectation, and any refusal case of the design that has no vector.
   - The replay passes.
6. **The tests.**
   - The candidate's tests and the oracle tests pass.
   - The oracle is independent, as its identity states.
7. **Placement.** Every new path falls in the evolution-surface class the design says, exactly and case-folded.
8. **Privacy and supply chain.**
   - No local path, personal data or credential in any subject file, whole or split into parts.
   - No new dependency.
   - Nothing that interposes on, forwards, proxies, swaps or bypasses anything.
9. **Open questions the rules file names,** each answered with a recommendation.

## Severities and verdict

- `MAJOR`: wrong or unsafe. For example:
  - a member that differs from the design;
  - a rule the model breaks;
  - a schema and model disagreement;
  - a wrong vector expectation;
  - a decision not met;
  - a reading that lets a lane review, bind or rule on its own work.
- `MINOR`: a fixable inaccuracy or gap.
- `NOTE`: advice.

**The verdict:**
- `PASS_FOR_ADOPTION` when no MAJOR or MINOR finding remains;
- `PASS_FOR_SOURCE_PUBLICATION` when the decisions name that outcome;
- `CHANGES_REQUIRED` otherwise.

Verify every finding against the files; do not guess.

## Record

Write one `planeon.review-record/v2` record at the path the rules file names, with no absolute path in it. It holds:
- kind `CONTRACT`;
- the series and round the rules file gives;
- the subject (and `base` for a delta round);
- the review date;
- `briefSha256` (this file's sha256), `rulesSha256` and `wrapperSha256`;
- `reviewer` {model, role};
- `verdict`;
- `findings` [{id, severity, location, finding, requiredChange, blocks}];
- `checked`: one line per check above, 1 to 9;
- `questions`: your answers to check 9;
- `disclosures`: your own account of every slip or deviation, or empty when there is none.

The operator writes the identity record beside it.
