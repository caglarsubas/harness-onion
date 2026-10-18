# Independent review brief — I06 backend profile v3, round 3

Status: **CONTRACT_CANDIDATE_ROUND3_AWAITING_INDEPENDENT_REVIEW**. The authoring agent wrote this brief. It is not a
verdict.

I06 v3 is reviewed together with native-profile v4 and the operator edge record v5, as one primary-lane meta packet. The
main brief is `../native-profile-v4/REVIEW_BRIEF.md`: its rules, result format and "How to check" apply here, and its
question 8 covers I06 v3. Round 1's one I06 finding is N1-5 (NOTE) and round 2's is N2-3 (NOTE): check their
dispositions in README.md. This brief adds the I06-specific subject and questions.

## Subject

The exact bytes listed under `subject` in `source-index.json`: README.md, this brief, `criteria.json`, `vectors.json`
and the reference model `scripts/i06_backend_profile_v3.py`. Check them against:
- the adopted I06 v2 contract (README, criteria, vectors, status, model) and the W02 notes errata's effective I06 v2
  README, criteria and brief;
- the adopted I06 v1 inputs and model, which v3 imports unchanged;
- the native-profile v4 candidate (schema, vectors, model), to which v3 binds.

`diff scripts/i06_backend_profile_v2.py scripts/i06_backend_profile_v3.py` is the model's review surface: the binding
lines plus the appended `check_vectors`.

## Questions

1. **Binding only.** Is v3 exactly v2 with the W02a binding moved to native-profile v4 (`W02A_VERSION`, the v4 schema
   digest through v4's `check_record`, v4's `check_record`), the effective v2 texts adopted, and G19's refusal and the
   SC00 and SC08 texts changed accordingly, nothing else? Is keeping the evidence record version
   `planeon.internal.i06-distribution-evidence/v2` while moving the criteria to `/v3` sound?
2. **Replays.** Does every v2 evidence case replay against native-profile v4's positives with its v2 operations, with
   only the SC00 prefix and the W02a rule's own version name moved, except G19? Are the snapshot cases carried
   unchanged? Are X01-X07 correct?
3. **Distinctness.** Is G20 still an SC08 refusal with a backend W02a v4 accepts, and is G19 refused by v4's
   one-file-per-component rule?
4. **Production.** Is every production call still refused, and is "production needs a reviewed W02a revision with a
   production backend profile and an I06 successor bound to it" still stated?
