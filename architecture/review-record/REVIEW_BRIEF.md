# MET-GOV-002 review record v2: independent contract review brief

Review the contract candidate in this directory, `scripts/review_record.py`, the four schemas under `schemas/`, the
amendment to MET-GOV-001's evolution surface record and the candidate's test files. You are not the author. Your round
number, the subject commit, the operator rules and where to write your record are in the rules file that the launch
message names; its paths are local and stay out of this published brief.

## The subject

- `README.md`: the contract.
- `<harness-onion>/schemas/review-record.schema.json`, `review-identity.schema.json`, `oracle-identity.schema.json` and
  `review-briefs.schema.json`: the closed draft 2020-12 schemas.
- `briefs.json`: the brief registry. `legacy-review-records.json`: the frozen list.
- `vectors.json`: review, series, oracle, PR-oracle, merge, registry, frozen-list and privacy rows.
- `<harness-onion>/scripts/review_record.py`: the standard-library reference model and checker. `python3 -I -B
  scripts/review_record.py` replays every vector.
- `<harness-onion>/architecture/evolution-surface/`: the record's amendment (the GATE_REVIEW_PROCESS class) and its
  re-pins.
- `<harness-onion>/tests/test_review_record.py` and `tests/test_review_records_in_tree.py`: the candidate's tests and the
  in-suite pre-check.
- `<harness-onion>/tests/test_review_record_oracle.py`: the oracle tests, written by a separate agent outside the
  candidate (owner decision D5a), bound by `oracle-identity.json` in this directory.
- `<harness-onion>/tests/test_evolution_surface_oracle.py`: MET-GOV-001's oracle file, scoped to the record's version 2
  by the same oracle agent, bound by `oracle-identity-evolution-surface.json` in this directory.

The design dossier (revision 4) and the decisions are local records named in the rules file. Do not reopen these
decisions; check that the contract does what they say:
- the owner's Q-RR2-1..5 (a), Q-RR2-6 "Gate material", Q-RR2-CAP and D-3 (the binding is the file-byte sha256);
- the owner's Q-RR2-NAMES, "Load hashes locally (Recommended)": an owner-decided narrowing of B-8, which the README's
  "Privacy" section states. Check that the contract does what it says, and do not reopen it;
- the design decisions D-1 and D-2, which go into the owner's per-PR question;
- the binding rules B-1 to B-10 of the design's section 14. This review checks them first, starting with B-1 and B-4.

## Check (at least)

1. **The binding rules, B-1 and B-4 first, then B-2, B-3 and B-5 to B-10.** For each, state whether the contract meets
   it and where.
2. **The records against the design.** Every member of the two round records, the oracle identity, the registry and the
   frozen list: required or optional, type and form (digests as 64 lowercase hex with no prefix, times as RFC 3339 with
   an offset, agentIds as plain strings in the schemas). Name any member that differs.
3. **The model against the README.** Every check, its code order (B-6), the ruling rule, the series rule (full and delta
   rounds), the brief registry's rules (B-3), the head binding (Q-RR2-3 (a)), the oracle rules (B-5), the merge check
   and the tree walk. Look for an input where the model is wrong or undefined: overlapping registry entries, a superseded
   brief at the cut-over time, a round that is both a delta and the first round, an identity reused across records, a
   frozen record rewritten into a valid v2 set, unusual characters in paths.
4. **Schema and model agree:** the model refuses as SHAPE exactly when a schema rejects, and UNKNOWN_KIND and
   PLACEHOLDER_ID stay reachable after SHAPE.
5. **The vectors:** each expected value follows from the design, not from the model. Name any vector whose expectation
   is wrong, and any refusal case of the design's section 9 or of B-3 to B-6 that has no vector.
6. **The evolution surface amendment:** the class object, the under-plus-name entries, the `independentOf` additions,
   the re-pins, and the derived gate list of 31 entries (the four new ones named in the README).
7. **The tests:** the candidate's tests, the in-suite pre-check and the oracle tests each pass. Is the oracle
   independent, as its identity states?
8. **Privacy and supply chain:** no local path, personal data or credential in any subject file, whole or split into
   parts; privacy is matched by digest only, and no name-token digest is published (Q-RR2-NAMES); the model imports only
   the standard library.
9. **Open questions for this review,** each answered with a recommendation:
   - Q-RR2-FROZEN, as the README's frozen-list section states it;
   - any reading of the design that the rules file names as the author's own.

## Severities and verdict

- `MAJOR`: wrong or unsafe. Examples: a member that differs from the design; a rule the model breaks; a schema and model
  disagreement; a wrong vector expectation; a binding rule not met; a reading that lets a lane review, bind or rule on
  its own work.
- `MINOR`: a fixable inaccuracy or gap.
- `NOTE`: advice.

Verdict: `PASS_FOR_ADOPTION` when no MAJOR or MINOR finding remains, else `CHANGES_REQUIRED`. Verify every finding
against the files; do not guess.

## Record

Write one record in this contract's own form, `planeon.review-record/v2`, at the path the rules file names, with no
absolute path in it: kind `CONTRACT`, series `MET-GOV-002/contract`, your round, the subject
`{"repository": "harness-onion", "commit": "<40 hex>", "tree": "<40 hex>"}` (and `base` for a delta round), the
review date, `briefSha256` (this file's sha256), `rulesSha256`, `wrapperSha256`, `reviewer` {model, role}, `verdict`,
`bindingRules` [{rule: "B-<n>", met, note}], `findings` [{id: "RR2C<round>-<n>", severity, location, finding,
requiredChange, blocks}], `checked` (one line per check above, 1 to 9), `questions` (your answers to check 9) and
`disclosures` (your own account of every
slip or deviation; empty when there is none). The operator writes the identity record beside it.
