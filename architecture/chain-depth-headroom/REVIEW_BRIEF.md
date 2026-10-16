# Independent source review brief — chain-depth headroom (PERF-040), round 3

Status: **SOURCE_CANDIDATE_ROUND3_AWAITING_INDEPENDENT_REVIEW**. The authoring agent wrote this brief. It is not a
verdict. The packet mechanics (the new layer, counts, bridges, the authority) come after this review.

Round 1 returned CHANGES_REQUIRED: 1 MAJOR, 6 MINOR and 4 NOTE findings, S1-1 to S1-11. README "Source review round 1:
findings and dispositions" answers each one in the bytes. Round 2 returned CHANGES_REQUIRED: 1 MINOR and 5 NOTE findings,
S2-1 to S2-6, answered under "Source review round 2".

## Subject

These exact bytes against main `d2ef708`:
- `tests/conftest.py` (new);
- `ci/parallel_suite_weights.json`;
- `scripts/validate_selinux_matrix_v3.py` and `tests/test_selinux_matrix_v3.py` (the replay-order change);
- `architecture/chain-depth-headroom/README.md`, `record.json` and this brief.

Two author-side tools are named in your task brief and are part of the review: the byte-minimal authority builder, and
the weights generator.

## What to check

1. **Sharing is exact and test-local.**
   - Can the memo ever return a value the real call would not, within one test? Consider:
     - equal but distinct objects;
     - a str and bytes with equal content;
     - keyword calls;
     - other argument types;
     - a refusal;
     - a test that monkeypatches `historical_bytes` or a reader;
     - a module imported under two names.
   - Is everything restored after each test, and in the right order relative to monkeypatch?
   - Does any validator change?
2. **The never-shared list.**
   - Is every test whose purpose is freshness or function identity on it?
   - Does M3's failure list (record) match it exactly?
   - Is a test that would pass under sharing while losing its point (for example a freshness test written with a fresh
     input each time) missing from it?
3. **The minimal hunks.**
   - Is the builder's output always accepted by every layer's parser (strict ordering, disjointness, canonical base64)?
   - Does it always reconstruct the before bytes?
   - Is the minimality definition precise enough for the guard and the carried rule?
4. **The weights.**
   - Are they derived as the record says, with all 127 files present?
   - Is the matrix file's scaling justified?
   - Does any validator or test pin the weights' bytes directly, rather than through a projection?
5. **The replay order.**
   - Are the requires and messages unchanged?
   - Do the moved faults still test the replay?
   - Does any test or vector depend on the old order?
6. **The record.** Are the decisions quoted verbatim, and P2-1 exactly? Are the measurements stated with their caveats?
7. **Rounds 1 and 2.** Does each disposition in README's two source-review tables answer its finding in the bytes?
8. **Overclaims.** Does anything claim a CI result, a freshness change, or a worker-count change?

## How to check

You may run single test files or small sets with the shared venv's python, serially, at most 120 s each. You may run the
author's tools against a copy of the repository in your scratch directory. Do not run the full suite, a dry run, or
anything against the worktree that writes. Before the packet mechanics, every layer test that pins the weights file or
239's validator refuses the changed bytes as an unreviewed source. For example, two tests of
`tests/test_selinux_matrix_v3.py` (the history-chain and packet-bytes tests) and two of `tests/test_parallel_suite.py`
(the history-chain and reviewed-text tests). That is expected until the new layer records its inverse.

## Result

Write a JSON record with the round, the subject commit, a verdict (PASS_FOR_PACKET or CHANGES_REQUIRED), and findings,
each with an id, severity (MAJOR, MINOR or NOTE), file, line, summary and evidence.
