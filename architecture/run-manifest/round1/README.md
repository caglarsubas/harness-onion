# Run manifest and configuration-level evaluation records v1 (MAS-RA-002)

Alpha 2; 2026-10-13. Status: **CONTRACT_CANDIDATE_ROUND1_AWAITING_INDEPENDENT_REVIEW**. DATA_CHECK_ONLY: an internal
contract candidate with schemas, a reference model and vectors. It changes no public contract, selector, catalog or
runtime, and it leaves H16's harness document (`docs/harnesses/trust.evaluation-assurance.md`) and the repository schemas
byte-identical (owner decision Q-MAS2-A).

A qualification result is only as good as the record of what ran: which model, which harness commit, which budget, how many
agents, which locked inputs, which seeds, which tasks, how many repetitions. The three MAS-harness research syntheses agree
that the harness moves results as much as the model, so results are reported per configuration, and that stochastic agents
are gated on distributions, never on one run (crosswalk `architecture/research-adoption-v2/crosswalk.json`, item
MAS-RA-002, acceptance IDs MAS-RA-002-A1 to -A3; harnesses H16 primary, H15 and H2 secondary). Future consumers: R12
campaigns, CONF-WG-001 (the banking tenant-acceptance candidate, historical WG prefix) as its "qualified baseline" format,
and MAS-RA-005 (candidate admission).

## Files

| File | Content |
|---|---|
| `split-declaration.schema.json` | `planeon.internal.split-declaration/v1`: development and held-out task sets |
| `run-manifest.schema.json` | `planeon.internal.run-manifest/v1`: one run, written before it starts |
| `evaluation-record.schema.json` | `planeon.internal.evaluation-record/v1`: one configuration on one suite and partition |
| `distribution-gate.schema.json` | `planeon.internal.distribution-gate/v1`: a candidate record compared with a baseline record |
| `selection-record.schema.json` | `planeon.internal.selection-record/v1`: a choice among candidate configurations |
| `vectors.json` | 65 cases (20 valid, 45 refused, every refusal code at least once) over shared stores (3 splits, 34 manifests, 11 records, 5 comparisons), 2 raw-text cases and 13 critical-value rows, each with its exact expected result |
| `../../scripts/run_manifest.py` | Reference model, standard library only: `check_split`, `check_manifest`, `check_record`, `compare`, `check_comparison`, `check_selection`, `critical`, `parse`, `canonical`, `digest`; run directly, it replays every vector |

The schemas state the closed shapes; the model refuses a document as `SHAPE` exactly when its schema rejects it (every case
is checked against both). Uniqueness (`DUPLICATE_ID`), references and every later rule are the model's alone. Records are
I-JSON with integer numbers only; `canonical` is RFC 8785 on that value space (as in the verdict ledger, MAS-RA-001), and a
record is referred to by `digest(record)` (`sha256:` and the hex SHA-256 of its canonical form).

## The records

**Split declaration** (A3). `splitId`, `suiteDigest`, `declaredAt` (UTC `YYYY-MM-DDTHH:MM:SSZ`), and two partitions,
DEVELOPMENT and HELD_OUT, each a non-empty list of `{taskId, taskDigest}`; the partitions are disjoint by task ID and by
task content digest.

**Run manifest** (A1), written before its run: `runId`; `scopeDigest` (H16's scope tuple, as the verdict ledger's
`subject.scopeDigest`); `suiteDigest`; the **configuration tuple** `{model: {id, configurationDigest}, harness: {commit,
dirty}, budget: {tokensPerTask, costMicrosPerTask, wallClockSecondsPerTask}, agentCount}` (the model fields are H2's
inference-contract identity; budget caps are part of the tuple, Q-MAS2-D); the **locks** `{specsDigest, promptDigests,
toolSchemaDigests, imageDigests, dependencyLockDigests, fixtureDigest, datasetDigest, evaluator: {id, version, digest},
environmentDigest}`, every one required (H16: "A run locks suite, data, judge, subject, environment, and configuration
digests before execution"); the `seed` (`FIXED` with its value, or `PROVIDER_UNSEEDABLE` with a statement, so an absence is
stated, never silent); the `split` (declaration digest and partition); the `repetition` index; `writtenAt` and `startedAt`;
and the run's verdict-ledger digest (MAS-RA-001) or null. The split must be declared no later than the manifest is written,
and the run must start no earlier (`SPLIT_AFTER_RUN`, `STARTED_BEFORE_WRITTEN`). Environmental reproducibility is the
locks; statistical reproducibility is the distribution gate below.

**Configuration-level evaluation record** (A2): one configuration tuple, one suite, one split partition (so held-out
scores are stored apart from development scores, Q-MAS2-C), `repetitionsDeclared` k ≥ 3, and the runs: each a manifest
digest, its repetition and the per-task results `{taskId, score, tokensTotal, cacheReadTokens, costMicros}`. Scores are
integers from 0 to 1,000,000 (parts per million). Tokens and cost are reported beside the score and never gated here
(Q-MAS2-D; H15 owns cost decisions; the cache share is `cacheReadTokens / tokensTotal`). Every run's manifest must name
exactly the record's configuration, scope, suite, split and partition (`CONFIGURATION_MIXED`: the reporting tuple is never
mixed); repetition indexes are distinct and within 1..k (`REPETITIONS`); fixed seeds differ between runs (`SEED_REUSED`);
every run scores exactly the partition's tasks (`TASK_SET`). A record with fewer runs than declared is valid and
*incomplete*; a record with a dirty harness tree is valid and recorded, never hidden, but cannot qualify.

**Distribution-gate comparison** (A2, owner decision Q-MAS2-B): a baseline record and a candidate record on the same scope,
suite, split and partition (`INCOMPARABLE` otherwise), a `purpose` (`NON_REGRESSION` or `IMPROVEMENT`), a versioned
`tolerance` `{version, ppm}`, and the decision with its statistics, which must be exactly the model's (`DECISION_MISMATCH`).

**Selection record** (Q-MAS2-C): candidate records (at least two), the chosen one, and the comparisons it rests on. Every
candidate and every record a basis comparison uses must be a DEVELOPMENT record (`HELD_OUT_SELECTION`: held-out scores are
never selection input); the candidates must be comparable, the chosen record must be a candidate and every basis comparison
must compare candidates (`SELECTION_BASIS`).

## The distribution gate

Stochastic agents are gated on distributions: k ≥ 3 repetitions per task (HarnessDev's avg@3, MILO's k = 3), fixed seeds
where the provider allows them, task-clustered statistics and a versioned tolerance. The comparison is **paired** (the same
tasks on both sides) and **task-clustered** (repetitions are averaged within a task first; the interval is over tasks).

The decision is UNRESOLVED when either record is incomplete (`INCOMPLETE`), either has a dirty tree (`DIRTY_TREE`) or the
partition has fewer than two tasks (`TOO_FEW_TASKS`). Otherwise, with k_b and k_c runs, n tasks and the per-task score sums:

- D_t = k_b · sum_c(t) − k_c · sum_b(t) (the per-task mean difference, scaled by k_b · k_c);
- T = Σ D_t, Q = n · Σ D_t² − T², tol = tolerance_ppm · k_b · k_c;
- c = the two-sided 95% critical value of Student's t for n − 1 degrees of freedom, in thousandths, rounded up (a
  conservative table; a df between tabulated values uses the next lower tabulated df; above 120 the normal 1.960);
- **IMPROVED** when L = T − n · tol > 0 and L² (n − 1) 10⁶ > c² Q (the interval's lower bound exceeds the tolerance);
- **REGRESSED** when U = T + n · tol < 0 and U² (n − 1) 10⁶ > c² Q (the upper bound is below minus the tolerance);
- **WITHIN_NOISE** otherwise.

Every quantity is an integer and the comparisons are exact, so any consumer reproduces the decision bit for bit. The
statistics record `{tasks, baselineRuns, candidateRuns, scale, sumDifference, sumSquares, criticalThousandths,
meanDifferencePpm, halfWidthPpm}`; the last two are informational (floor of the mean; ceiling of the half-width). Examples
from the vectors (tolerance 10,000 ppm, n = 4, c = 3.183): a mean gain of 50,000 ± 14,529 is IMPROVED; a mean gain of
30,000 ± 85,211 is WITHIN_NOISE (a gain inside the noise is not accepted, HarnessDev's ±4.75-point band and MILO's 2.3-point
lead inside about ±2 points); a mean loss of 60,000 ± 14,529 is REGRESSED. The builder checks the critical-value table
against Student's t quantiles it computes itself.

**H16 mapping** (as the verdict ledger's, Q-MAS1-A): for `NON_REGRESSION`, IMPROVED and WITHIN_NOISE are PASS, REGRESSED is
FAIL and UNRESOLVED is WARN; for `IMPROVEMENT`, only IMPROVED is PASS, WITHIN_NOISE and REGRESSED are FAIL and UNRESOLVED is
WARN. This gives the state the comparison supports; H16's own requirements (its signed evidence record, scope, freshness)
still apply, and H16's states and signer are unchanged.

## Refusal codes

Each check raises the first code it meets, in this order: `SHAPE`, `DUPLICATE_ID`, `UNKNOWN_REFERENCE`,
`PARTITION_EMPTY`, `PARTITION_OVERLAP`, `SPLIT_SUITE`, `SPLIT_AFTER_RUN`, `STARTED_BEFORE_WRITTEN`, `CONFIGURATION_MIXED`,
`REPETITIONS`, `SEED_REUSED`, `TASK_SET`, `CACHE_EXCEEDS_TOKENS`, `INCOMPARABLE`, `DECISION_MISMATCH`,
`HELD_OUT_SELECTION`, `SELECTION_BASIS`. A check of a record also checks every record it refers to (a record its manifests
and split; a comparison its two records; a selection its comparisons and records) and reports the first code of the first
one that fails. Nothing but these refusals escapes a check: anything malformed is `SHAPE`.

## Grounding (crosswalk pages)

HarnessDev (2609.01437) pp. 1, 4, 6-8, 12-13, 23, 29: record the executor model and evaluator with every score, score a
frozen commit, store visible and held-out scores apart (direction agreement 53.1%), keep a repeated-run noise band (about
±4.75 pair points) inside which gains are not accepted, avg@3 builds, tokens reported beside capability; its
Terminus 2 / Codex CLI figure is a cited leaderboard number, not a measured result. MILO (2609.38349) pp. 9, 11, 22: k = 3
rollouts for admission, task-clustered 95% intervals of about ±2 points, fixed per-task cost caps. VeriHarness
(2610.00972) pp. 21, 27: three verifier seeds, judge-drift control, cost at list price with the cache share.
2609.26891 pp. 8, 15, 20: a distinct prompt-cache key per run and capped parallelism for cost measurement; high variance
(n = 6 needed). 2609.24974 pp. 5-7, 23: single seed-42 runs are not promotion evidence; held-out test success under the
target harness, never collection success. The RunManifest's field list follows the GPT synthesis.

## Owner decisions (2026-10-13, owner via the lane monitor; verbatim)

- Q-MAS2-A = (a): an internal candidate under architecture/run-manifest/, naming R12 campaigns, CONF-WG-001 and MAS-RA-005 as future consumers; H16's document and schemas unchanged.
- Q-MAS2-B = (a): a paired, task-clustered 95% interval of the candidate-minus-baseline difference over k ≥ 3 repetitions per task, against a versioned tolerance; outcomes IMPROVED, WITHIN_NOISE, REGRESSED, or UNRESOLVED when data is incomplete; integer arithmetic.
- Q-MAS2-C = (a): split declarations digested before the first run that uses them; held-out scores stored apart and refused as input to any selection record.
- Q-MAS2-D = (a): budget caps in the configuration tuple; per-task tokens and cost (with the cache share) reported beside the score, never gated here, since H15 owns cost decisions.

## Not claimed

- No producer, consumer or service exists; nothing writes a manifest outside the vectors. The R12 trial of a run-manifest
  record is a later parallel-lane R12 packet.
- The manifest records digests; it cannot show that the digested artefacts are the ones that ran (that is H16's run lock
  and signer), nor that every run of a configuration was recorded (a producer could omit runs; H16's campaign records
  bind the run list).
- The interval assumes the tasks are exchangeable samples; it says nothing about tasks outside the suite.
- The cited figures are the source papers' results, not platform evidence.
