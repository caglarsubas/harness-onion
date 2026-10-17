# Independent review brief — native qualification record v4 and I06 backend profile v3, round 3

Status: **CONTRACT_CANDIDATE_ROUND3_AWAITING_INDEPENDENT_REVIEW**. The authoring agent wrote this brief. It is not a
verdict.

This is the third contract review of one primary-lane meta packet (owner decision Q-NP4-17 (a)): native-profile v4, the
I06 successor bound to it (`../i06-backend-profile-v3/`, which has its own short brief) and the operator edge record v5
(`../artifact-edges/operator-harness-engineering-v5.json` and `README-v5.md`). The contract implements the reviewed
native-profile v4 design, revision 2.2 (sha256 `9cd3a5f09b58ebcd80bdc80a733bfd8511679f1a35dca79729f75a84ae35039d`;
design round 3 PASS_FOR_CONTRACT with D3-1 to D3-6 carried to this review), and the owner and lane-monitor decisions
Q-NP4-1..17, Q-NP4D-1..10 and Q-NP4D-B. The coordinator gives you the design, the decisions record and the round-1 and
round-2 review records.

Round 1 reviewed candidate `0a2ecd7157e732b8d7965ed6e985203e733b1d19` and returned CHANGES_REQUIRED: N1-1 and N1-2
(MAJOR), N1-3 (MINOR), N1-4 to N1-6 (NOTE). Round 2 reviewed candidate `3c34a3a5ff5879d2bcf5e6691bc08eeaf59dbf41`, found
N1-1 partly resolved and the rest resolved, and returned CHANGES_REQUIRED: N2-1 (MAJOR), N2-2 and N2-3 (NOTE). This
candidate is a new commit on top of it; `git diff 3c34a3a5 HEAD` is the change surface. README "Contract review round 2
findings and dispositions" states how each finding is answered.

## Subject

The exact bytes listed under `subject` in `source-index.json`: README.md, this brief, `qualification.schema.json`,
`vectors.json` and the reference model `scripts/native_qualification_v4.py`; and, for I06 v3 and the edge record, the
bytes listed in `../i06-backend-profile-v3/source-index.json` and the edge record v5 with its README. Check them against
the predecessor inputs listed there:
- the adopted native-profile v3 contract (README, schema, vectors, status, review round 6, model) and the W02 notes
  errata (the effective v3 README, the errata record with its comment-only replacement R6-1g, the R6-3 vectors);
- HS43 (O-NATIVE-GATE-NOCAP, the replacement clause, the BROKER row's `Seccomp_filters: 2`, W1-W6);
- SELinux matrix v5 (`architecture/selinux-matrix-v3/`: types, transitions, A12, A32, A33, A35-A37, A47, A59, A60.15-21,
  A68, `procAccess`, O03);
- the native-profile v1 and v2 schemas and vectors (migration and history).

`diff scripts/native_qualification_v3.py scripts/native_qualification_v4.py` is the model's review surface; `diff
architecture/native-profile-v3/qualification.schema.json architecture/native-profile-v4/qualification.schema.json` the
schema's.

## Questions to answer

0. **Earlier findings.** For N2-1 to N2-3, and N1-1 to N1-6, is the README disposition true in these bytes? In
   particular: does the in-set census now refuse every second entry file inside the inventory under any spelling of its
   context (the round-1 probes (a)-(g), the round-2 user, role and level variants, and any other you can construct, in
   `files` and `backendFiles`), while accepting an ordinary library in its own type? Do the keyed member sets refuse
   every duplicate or omitted member and thread, inside the frozen bracket and for the no-fork roles? Does every
   forbidden field now have an equal-value and a different-value case? Give CLOSED, PARTIAL or OPEN per finding under
   `openItemStatus`, and confirm that no new rule changes a v3, errata or I06 result.
1. **Design conformance.** Does the contract implement design revision 2.2 exactly, section by section (§2 gate rule,
   §3.1-§3.7 capture routes, §4 inspector obligation, §5 migration, §6 errata and reader duties, §8 edge record, §11
   residuals), with D3-1 to D3-6 applied? List any rule the design states that the contract misses or weakens, and any
   rule the contract adds that the design does not state.
2. **Representation choices.** README "Representation choices" lists nine encodings the author chose where the design
   does not fix one. Is each sound and faithful to the design? In particular: the entrypoint constants as record fields;
   the observer's own capture without a cgroup path and with pid-only member rows; the member sets and frozen flags as
   capture fields; refusing an unfrozen WORKER capture in `check_capture`; removing the seal marker label from
   `hardeningObserved`; "one file per component" by path; the class table published as the `evidenceClasses` constant.
3. **Classes.** For every capture field, does the schema plus the model give it exactly the class of the README table,
   for every role and for the server with and without CAP_NET_BIND_SERVICE? Can a capture carry an OBSERVED claim it
   cannot have observed, or omit one it must carry, and still pass?
4. **No regression.** Does every v3 rule still hold in v4 for the fields v4 keeps? Are the twelve changed replay results
   (README "Replayed v3 cases") correct, each for its stated reason, and are the nine re-derived operations faithful to
   the v3 cases' intents? Are the errata's R6-3 cases replayed unchanged?
5. **Proofs and premises.** Is every declared premise named with a T04 proof, and is the `t04Proofs` constant the
   design's closed list? Are the residuals and their owners those of design §11?
6. **Kernel facts.** Check the `Seccomp_filters` counts against HS43, the W5 `execveat` statement, and the minimum
   kernel versions the README states (the author's reading).
7. **Vectors.** Does each case produce exactly its stated result for its stated reason? Is the low-port positive
   plausible? Try probes beyond the vectors, especially captures that mix classes.
8. **I06 v3 and the edge record.** Is I06 v3 exactly I06 v2 with the binding moved (G19's refusal and the SC08 texts
   changed accordingly, nothing else)? Does edge record v5 carry v4's 45 rows unchanged and in order, supersede v4 by
   SHA-256, and add exactly the design's rows with the right commits, packets and consumer labels?
9. **Overclaims.** Does anything claim a native observation, a measured boot, a selected distribution, installed seccomp
   filters or an E01-E12 proof?

## How to check

You may run the reference models read-only from the worktree root with the shared locked environment: `uv run --offline
--frozen --no-sync python` with `UV_PROJECT_ENVIRONMENT` set inline, on every command, to the main harness-onion
checkout's `.venv` (the coordinator gives you its path); never let uv create a `.venv` in the worktree. Add `scripts` to
`sys.path`, import `native_qualification_v4` and `i06_backend_profile_v3`, and call each model's `check_vectors` with
the vectors and the bytes of the input paths it names (`V4_INPUTS` plus `SCHEMA_PATH`; `V3_INPUTS`). Do not run the
repository test suite or validators, and do not modify any file.

## Result

Return one JSON object:
- `schemaVersion` `"planeon.internal.native-profile-v4-review/v1"`, `round` 3, `reviewDate`;
- `verdict`: PASS_FOR_SOURCE_PUBLICATION, CHANGES_REQUIRED or BLOCKED;
- `subjectSha256`: subject file name to digest, for the three subjects;
- `findings`, each with `id`, `severity` (BLOCKING / MAJOR / MINOR / NOTE), `location`, `finding` and `requiredChange`;
- `openItemStatus` (N1-1 to N1-6, N2-1 to N2-3), `designConformance` (per design section), `questionAnswers` (Q0-Q9),
  `modelExecution`, `sourcesRead`;
- `actions`, booleans: `filesEdited`, `githubMutated`, `nativeActions`, `referenceModelExecuted`,
  `repositoryValidatorsRun`, `runnerActivated`, `testsRun`, `warmSourcesAccessed`, `networkAccessed`;
- `reviewLimit`.

A PASS is not a native qualification or authorization for anything installed.

Rules: you are a separate agent from the author; read-only; no repository edits, no tests or validators, and no runner,
native, cloud or GitHub actions; no warm-source access; no network access of any kind; and never put the user's email
address, names or any personal data in any request, file or output.
