# Independent review brief: LIC-HOST-A2 (LICENCE-POLICY-AMEND), round 2

Status: **CONTRACT_CANDIDATE_ROUND2_AWAITING_INDEPENDENT_REVIEW**. The authoring agent wrote this brief. It is not a
verdict.

Round 1 returned CHANGES_REQUIRED: 3 MINOR findings and 5 NOTEs, LR1-1 to LR1-8. README "Round-1 findings and
dispositions" answers each one in the bytes.

## Subject

The subject is these exact bytes:
- README.md, this brief, `amendment.json` and `vectors.json`;
- `scripts/license_amendment_v2.py`.

Check them against:
- the base policy `legal/third-party-license-policy.yaml`;
- the adopted A1 (`legal/license-policy-amendment/`, all files, and `scripts/license_amendment.py`);
- the RA-LICENSE-001 record `architecture/research-adoption-v3/README.md` (note N-2, the phoenix-sqlean row).

The decisions to carry out are in README "Decisions" and, verbatim, in `amendment.json`:
- LIC-ZLIB: Zlib on the allowed list;
- L2-1 (a): globally;
- L2-2 (a): the effect is stated, and the research record is unchanged.

## What to check

1. **Frozen inputs.** Are the base policy, A1 and the research record byte-identical? Does `amendment.json` pin the base
   and A1's record, vectors and classifier exactly?
2. **The rule.**
   - Is Zlib classified exactly like a base default-allowed term, for every component, kind and custody?
   - Can the overlay weaken any base outcome (a denial, a review requirement, a placeholder) or any A1 outcome of another
     term?
   - Does `check` refuse an added term that overlaps a base list, an A1 class term, a decision or an election?
   - Is matching still exact?
3. **The vectors.**
   - Are the 34 cases' A1 and A2 results right under the base and A1 rules?
   - Is coverage enough: Zlib alone in each kind and custody; OR, AND and legacy forms; election ranking against the
     core licence, a tie, an exception expression, open content, the A1 class and an approved review; denial, review
     and out-of-scope blocking; near-miss identifiers; refusals?
   - Is the A1 replay's empty changed list right, and is it enforced?
4. **The record.** Are the decisions verbatim with their routes? Are P2-F1 and P2-F2 quoted exactly from their source
   (the author-side record of 223's packet review round 2, named in your task brief), with dispositions that answer
   them?
   Is the phoenix-sqlean effect stated correctly, and without changing that record?
5. **Round 1.** Does each disposition in README "Round-1 findings and dispositions" answer its finding in the bytes?
6. **Overclaims.** Does anything claim a release, a legal opinion, a switched consumer, or a change to the research
   record?

## How to check

You may run the A1 and A2 checks read-only from the repository root (`python3 -I -B`, with `scripts` put on `sys.path`
inside the command). You may run the author's builder, which your task brief names, only against a copy of the repository
in your scratch directory.

## Result

Write a JSON record with:
- the round and the subject commit;
- a verdict, PASS_FOR_SOURCE_PUBLICATION or CHANGES_REQUIRED;
- findings, each with an id, severity (MAJOR, MINOR or NOTE), file, line, summary and evidence.
