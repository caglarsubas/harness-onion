# MET-GOV-001 evolution surface v1: independent contract review brief

Review the contract candidate in this directory, `scripts/evolution_surface.py` and its two test files. You are not the
author. Your round number, the subject commit, the operator rules and where to write your record are in the rules file
that the launch message names; its paths are local and stay out of this published brief.

## The subject

- `README.md`: the contract.
- `evolution-surface.schema.json`: the closed draft 2020-12 schema.
- `evolution-surface.json`: the record (product and programme levels, coverage skip set).
- `vectors.json`: decisions, invariant breaks, texts, paths, skip rules, PR rows, coverage rows, the gate-material
  derivation and consumer cases.
- `<harness-onion>/scripts/evolution_surface.py`: the standard-library reference model. `python3 -I -B
  scripts/evolution_surface.py` replays every vector.
- `<harness-onion>/tests/test_evolution_surface.py`: the candidate's tests.
- `<harness-onion>/tests/test_evolution_surface_oracle.py`: the oracle tests, written by a separate agent outside the
  candidate (owner decision D5a). Its identity sidecar is named in the rules file.

The design note (revision 4) and the decisions are local records named in the rules file. Do not reopen these decisions;
check that the contract does what they say:
- the owner's Q-ES-1..7 (Q-ES-6 (b): the packet is gate material);
- Q-ES-CAP (a): build revision 4; the round-3 design fixes E3-1 to E3-10 are binding build rules, and this review checks
  them first, starting with E3-1;
- Q-ES-D1 (a), Q-ES-D2 (a) and Q-ES-D3 (a);
- the monitor's MON-ES-R1 and MON-ES-ID (packet id MET-GOV-001).

## Check (at least)

1. **The binding rules, E3-1 first.**
   - E3-1: the README and the consumer cases state that the bundle needs a passing independent result, that any failed
     mandatory independent result blocks activation whatever the self-score, that the rejection and its evidence are
     kept (E2E-14), and the E2E-16 rollback cases (allowed policy rollback with lineage kept; refused approval-free
     rollbacks).
   - E3-2 to E3-10: each is met where the design's section 13 says.
2. **The record against the design.** Every role and class of design sections 4 and 5: kinds, planes, flags, governs,
   independentOf, the five operation lists, the path entries (including C1 to C13 and the record's own entries), the
   coverage skip set and the grounds. Name any row that differs.
3. **The model against the README.** Every rule, the code order, the reason order, the path precedence, the PR rules,
   the derivation, the skip semantics and the tree walk. Look for an input where the model is wrong or undefined: ties,
   ambiguity, renames, an empty change set, symbolic links, a worktree `.git` file, unusual characters in paths.
4. **Schema and model agree:** the model refuses as SHAPE exactly when the schema rejects. Probe where they could differ
   (patterns and line ends, booleans against integers, uniqueness, `oneOf` path entries, the change-binding condition).
5. **The canonical form:** RFC 8785, with member names sorted by UTF-16 code units, and the README's note on the earlier
   models' code-point order.
6. **The vectors:** each expected value follows from the design, not from the model. Name any vector whose expectation
   is wrong, and any refusal case of the design that has no vector.
7. **The tests:** the candidate's tests and the oracle tests each pass. Do the candidate's tests prove what they claim
   (the schema agreement, the exhaustive decision sweep, coverage of the checkout)? Is the oracle independent, as its
   sidecar states?
8. **Privacy and supply chain:** no local path, personal data or credential in any subject file; the model imports only
   the standard library; the tests use only what the repository's locked environment provides.

## Severities and verdict

- `MAJOR`: wrong or unsafe. Examples: a record row that differs from the design; a rule the model breaks; a schema and
  model disagreement; a wrong vector expectation; a binding rule not met; a reading that lets an agent approve its own
  guardrail, judge, threshold, credential, gate or promotion code.
- `MINOR`: a fixable inaccuracy or gap.
- `NOTE`: advice.

Verdict: `PASS_FOR_ADOPTION` when no MAJOR or MINOR finding remains, else `CHANGES_REQUIRED`. Verify every finding
against the files; do not guess.

## Record

Write one JSON record, at the path the rules file names, with no absolute path in it:

```
{"schemaVersion": "harness.planeon.ai/governance-contract-review/v1", "kind": "MET-GOV-001 contract review",
 "round": <n>, "reviewDate": "<YYYY-MM-DD>", "subjectCommit": "<40 hex>", "subjectTree": "<40 hex>",
 "briefSha256": "<sha256 of this file>", "rulesSha256": "<sha256 of the rules file>", "wrapperSha256": "<sha256>",
 "reviewer": {"agentId": "STAMPED_BY_OPERATOR", "model": "<your exact model id>", "role": "independent contract reviewer"},
 "verdict": "PASS_FOR_ADOPTION" | "CHANGES_REQUIRED",
 "bindingRules": [{"rule": "E3-<n>", "met": true | false, "note": "..."}],
 "findings": [{"id": "G1R<n>-<m>", "severity": "MAJOR"|"MINOR"|"NOTE", "location": "...", "finding": "...", "requiredChange": "..."}],
 "checked": ["one line per check above (1 to 8), with its result"]}
```
