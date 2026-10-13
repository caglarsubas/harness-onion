# Run manifest and configuration-level evaluation records v1 (MAS-RA-002)

Alpha 2; 2026-10-13. Status: **CONTRACT_CANDIDATE_ROUND3_AWAITING_INDEPENDENT_REVIEW**. DATA_CHECK_ONLY: an internal
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
| `vectors.json` | 85 cases (25 valid, 60 refused, every refusal code at least once) over shared stores (9 split entries, two of them deliberately not declarations; 73 manifests, 23 records, 8 comparisons), 2 raw-text cases and 15 critical-value rows, each with its exact expected result |
| `../../scripts/run_manifest.py` | Reference model, standard library only: `check_split`, `check_manifest`, `check_record`, `compare`, `h16_state`, `check_comparison`, `check_selection`, `critical`, `parse`, `canonical`, `digest`; run directly, it replays every vector |

The schemas state the closed shapes; the model refuses a document as `SHAPE` exactly when its schema rejects it (every case
is checked against both). Uniqueness (`DUPLICATE_ID`), references and every later rule are the model's alone. Records are
I-JSON with integer numbers only, each within ±(2⁵³ − 1); `canonical` is RFC 8785 on that value space (as in the verdict
ledger, MAS-RA-001), and a record is referred to by `digest(record)` (`sha256:` and the hex SHA-256 of its canonical form).

## The records

**Split declaration** (A3). `splitId`, `suiteDigest`, `declaredAt` (UTC `YYYY-MM-DDTHH:MM:SSZ`, field ranges checked; such
strings order as the times do), and two partitions, DEVELOPMENT and HELD_OUT, each a non-empty list of
`{taskId, taskDigest}`; the partitions are disjoint by task ID and by task content digest.

**Run manifest** (A1), written before its run:
- `runId`, `scopeDigest` (H16's scope tuple, as the verdict ledger's `subject.scopeDigest`) and `suiteDigest`.
- The **configuration tuple** `{model: {id, configurationDigest}, harness: {commit, dirty}, budget: {tokensPerTask,
  costMicrosPerTask, wallClockSecondsPerTask}, agentCount}`. The model fields are H2's inference-contract identity. A
  multi-agent configuration that uses several models is identified only through `configurationDigest`. Budget caps are
  part of the tuple (Q-MAS2-D), and a `costMicrosPerTask` of 0 means the configuration has no monetary budget (for
  example a local model).
- The **locks** `{specsDigest, promptDigests, toolSchemaDigests, imageDigests, dependencyLockDigests, fixtureDigest,
  datasetDigest, evaluator: {id, version, digest}, environmentDigest}`, every one required (H16: "A run locks suite,
  data, judge, subject, environment, and configuration digests before execution").
- The `seed`: `FIXED` with its value, or `PROVIDER_UNSEEDABLE` with a statement, so an absence is stated, never silent.
- The `execution` `{cacheKeyDigest, parallelism}`: a distinct prompt-cache key per run and the parallelism cap, both
  needed for honest cost measurement (2609.26891 pp. 8, 15, 20).
- The `split` (declaration digest and partition), the `repetition` index, `writtenAt` and `startedAt`.
- The run's verdict-ledger digest (MAS-RA-001), or null.

The split must be declared no later than the manifest is written, and the run must start no earlier
(`SPLIT_AFTER_RUN`, `STARTED_BEFORE_WRITTEN`; equal times are allowed). Environmental reproducibility is the locks;
statistical reproducibility is the distribution gate below.

**Configuration-level evaluation record** (A2). Its scope:
- one configuration tuple and one suite;
- one split partition, so held-out scores are stored apart from development scores (Q-MAS2-C);
- `repetitionsDeclared` k ≥ 3.

Each run gives its manifest digest, its repetition and the per-task results `{taskId, score, tokensTotal,
cacheReadTokens, costMicros}`:
- Scores are integers from 0 to 1,000,000 (parts per million).
- Tokens and cost are reported beside the score and never gated here (Q-MAS2-D; H15 owns cost decisions).
- The cache share is `cacheReadTokens / tokensTotal`, or 0 when `tokensTotal` is 0. Budget overruns are recorded, not
  gated.

The model's facts for a record add the token total and the mean tokens per task and run.

Every run's manifest must name exactly the record's configuration, scope, suite, split, partition and repetition, with
**the same locks and the same seed mode as every other run** (`CONFIGURATION_MIXED`). A configuration whose specs,
prompts, tools, images, dependencies, fixtures, dataset, evaluator or environment vary across repetitions is not one
configuration, and the reporting tuple is never mixed. The remaining rules:
- repetition indexes and prompt-cache keys are distinct (`DUPLICATE_ID`), and repetitions lie within 1..k (`REPETITIONS`);
- fixed seeds differ between runs (`SEED_REUSED`);
- every run scores exactly the partition's tasks (`TASK_SET`).

A record with fewer runs than declared is valid and *incomplete*. A record whose configuration has a dirty harness tree
is valid and recorded, never hidden, but cannot qualify.

**Distribution-gate comparison** (A2, owner decision Q-MAS2-B) compares a baseline record with a candidate record. The two
must share scope, suite, split and partition, and the **same evaluator, dataset, fixture and environment locks**: two
configurations are compared only when they were scored the same way, against VeriHarness p.21's judge drift.
`INCOMPARABLE` otherwise. The comparison also states:
- a `purpose` (`NON_REGRESSION` or `IMPROVEMENT`);
- a versioned `tolerance` `{version, ppm}`;
- the decision with its statistics, which must be exactly the model's (`DECISION_MISMATCH`).

The statistics are a closed object of bounded values: `{tasks, baselineRuns, candidateRuns, criticalThousandths,
meanDifferencePpm, halfWidthPpm, nonInferior}`, or null when the decision is UNRESOLVED.

**Selection record** (Q-MAS2-C): candidate records (at least two), the chosen one, and the comparisons it rests on. Every
candidate and every record a basis comparison uses must be a DEVELOPMENT record, and none of their development tasks may be
held out by any valid declaration in the store: matched by task content digest in any suite, and by task ID in the same
suite (`HELD_OUT_SELECTION`: held-out scores are never selection input, not even through a second declaration that lists
them as development under the same contents, the same IDs or another suite). Store entries that are not valid declarations
filed under their own digest are not declarations and are ignored. A hold-out counts whenever it is declared: once a task
is declared held out, no selection may use it, even one over runs that predate the declaration (fail closed). The
candidates must be comparable exactly as a comparison's records are (scope, suite, split, and the evaluator, dataset,
fixture and environment locks; `INCOMPARABLE`), the chosen record must be a candidate and every basis comparison must
compare candidates (`SELECTION_BASIS`). A selection records the inputs of a
choice; it does not justify the choice (a basis that favours another candidate is not refused).

## The distribution gate

Stochastic agents are gated on distributions: k ≥ 3 repetitions per task (HarnessDev's avg@3, MILO's k = 3), fixed seeds
where the provider allows them, task-clustered statistics and a versioned tolerance. The comparison is **paired** (the same
tasks on both sides) and **task-clustered** (repetitions are averaged within a task first; the interval is over tasks).

The decision is UNRESOLVED when either record is incomplete (`INCOMPLETE`), either has a dirty tree (`DIRTY_TREE`) or the
partition has fewer than two tasks (`TOO_FEW_TASKS`). Otherwise, with k_b and k_c runs, n tasks and the per-task score sums:

- D_t = k_b · sum_c(t) − k_c · sum_b(t) (the per-task mean difference, scaled by k_b · k_c);
- T = Σ D_t, Q = n · Σ D_t² − T², tol = tolerance_ppm · k_b · k_c, L = T − n · tol, U = T + n · tol;
- c = the two-sided 95% critical value of Student's t for n − 1 degrees of freedom, in thousandths, rounded up; an
  untabulated df uses the largest tabulated df below it and every df above 120 uses the df-120 value 1.980. Since t's
  quantile falls as df grows, this is never below the true quantile; the builder checks it for df 1 to 130 and a spread
  up to 4,095 against quantiles it computes itself;
- **IMPROVED** when L > 0 and L² (n − 1) 10⁶ > c² Q (the interval's lower bound exceeds the tolerance);
- **REGRESSED** when U < 0 and U² (n − 1) 10⁶ > c² Q (the upper bound is below minus the tolerance);
- **WITHIN_NOISE** otherwise;
- **nonInferior** when U > 0 and U² (n − 1) 10⁶ > c² Q (the lower bound lies above minus the tolerance).

Every comparison is exact integer arithmetic, so any consumer reproduces the decision bit for bit. It needs
arbitrary-precision integers: c² Q exceeds 2⁵³ even for small suites (about 1.8 · 10²¹ in the 200-task vector), so T and
Σ D_t² are not recorded, only the bounded statistics. `meanDifferencePpm` is the floor of the mean difference and `halfWidthPpm` the ceiling of the interval's half
width; both are informational.

Examples from the vectors (tolerance 10,000 ppm, n = 4, c = 3.183):
- a mean gain of 50,000 ± 14,529 is IMPROVED;
- a mean gain of 30,000 ± 85,211 is WITHIN_NOISE and not non-inferior, so a gain inside the noise is not accepted;
- a mean loss of 2,000 ± 1,300 is WITHIN_NOISE and non-inferior;
- a mean loss of 20,000 ± 104,766 is WITHIN_NOISE and not non-inferior;
- a mean loss of 60,000 ± 14,529 is REGRESSED.

**H16 mapping** (`h16_state`), giving the state the comparison supports:
- **NON_REGRESSION:** PASS only when the candidate is non-inferior (IMPROVED, or WITHIN_NOISE with the lower bound above
  minus the tolerance). Any other WITHIN_NOISE is WARN (inconclusive: a wide interval cannot show the candidate is no
  worse). REGRESSED is FAIL; UNRESOLVED is WARN.
- **IMPROVEMENT:** only IMPROVED is PASS; WITHIN_NOISE and REGRESSED are FAIL; UNRESOLVED is WARN.

With a tolerance of 0, non-inferiority and improvement coincide, so NON_REGRESSION passes only an IMPROVED candidate; a
non-regression gate states a positive tolerance. A record with no runs has no locks, so a comparison with it is
UNRESOLVED (INCOMPLETE, WARN) rather than INCOMPARABLE; it can never be PASS.

H16's own requirements still apply before a comparison counts:
- judge version and calibration evidence for model judgments (the locks name the evaluator; calibration is H16's);
- no LLM judge as the sole authority for deterministic or security claims;
- the signed evidence record, the scope tuple and freshness.

H16's states and signer are unchanged.

## Refusal codes and the order of each check

`CODES` lists every code: `SHAPE`, `DUPLICATE_ID`, `UNKNOWN_REFERENCE`, `PARTITION_EMPTY`, `PARTITION_OVERLAP`,
`SPLIT_SUITE`, `SPLIT_AFTER_RUN`, `STARTED_BEFORE_WRITTEN`, `CONFIGURATION_MIXED`, `REPETITIONS`, `SEED_REUSED`,
`TASK_SET`, `CACHE_EXCEEDS_TOKENS`, `INCOMPARABLE`, `DECISION_MISMATCH`, `HELD_OUT_SELECTION`, `SELECTION_BASIS`. Each check
raises the first code it meets, in its own order:

- **split:** SHAPE; DUPLICATE_ID (within a partition); PARTITION_EMPTY; PARTITION_OVERLAP.
- **manifest:** SHAPE; DUPLICATE_ID (within a lock list); UNKNOWN_REFERENCE (the split, which is then checked as a split);
  SPLIT_SUITE; SPLIT_AFTER_RUN; STARTED_BEFORE_WRITTEN.
- **record:**
  1. SHAPE;
  2. DUPLICATE_ID (manifest digests, repetitions, task IDs within a run);
  3. UNKNOWN_REFERENCE (the split and the manifests);
  4. the split's own check;
  5. then, run by run: the manifest's own check, then CONFIGURATION_MIXED;
  6. DUPLICATE_ID (prompt-cache keys);
  7. REPETITIONS, SEED_REUSED, TASK_SET, CACHE_EXCEEDS_TOKENS.
- **comparison:** SHAPE; UNKNOWN_REFERENCE; the baseline's then the candidate's record check; INCOMPARABLE;
  DECISION_MISMATCH.
- **selection:**
  1. SHAPE and DUPLICATE_ID;
  2. UNKNOWN_REFERENCE;
  3. each basis comparison's check, then each used record's check;
  4. HELD_OUT_SELECTION (partition, then the store-relative rule over the valid declarations);
  5. INCOMPARABLE;
  6. SELECTION_BASIS.

A check of a record checks every record it refers to and reports the first code of the first one that fails. Nothing but
these refusals escapes a check: anything malformed is `SHAPE`.

## Grounding (crosswalk pages)

- **HarnessDev** (2609.01437) pp. 1, 4, 6-8, 12-13, 23, 29:
  - record the executor model and evaluator with every score, and score a frozen commit;
  - store visible and held-out scores apart (direction agreement 53.1%);
  - keep a repeated-run noise band (about ±4.75 pair points) inside which gains are not accepted;
  - use avg@3 builds, and report tokens beside capability;
  - its Terminus 2 / Codex CLI figure is a cited leaderboard number, not a measured result.
- **MILO** (2609.38349):
  - k = 3 rollouts for admission and fixed per-task cost caps (pp. 9, 11, 22);
  - task-clustered 95% intervals of about ±2 points and a 2.3-point lead (pp. 1, 12). Reading that lead as noise is the
    crosswalk's, not MILO's.
- **VeriHarness** (2610.00972) pp. 21, 27: three verifier seeds, judge-drift control (base and delivered artefacts scored
  in the same grading round), cost at list price with the cache share.
- **2609.26891** pp. 8, 15, 20: a distinct prompt-cache key per run and capped parallelism (3) for cost measurement; high
  variance (n = 6 needed).
- **2609.24974** pp. 5-7, 23: single seed-42 runs are not promotion evidence; held-out test success under the target
  harness, never collection success.

Harness-Bench and HarnessOpt-Bench (secondary) report rankings that flip across models. The RunManifest's field list
follows the GPT synthesis.

## Owner decisions (2026-10-13, owner via the lane monitor; verbatim)

- Q-MAS2-A = (a): an internal candidate under architecture/run-manifest/, naming R12 campaigns, CONF-WG-001 and MAS-RA-005 as future consumers; H16's document and schemas unchanged.
- Q-MAS2-B = (a): a paired, task-clustered 95% interval of the candidate-minus-baseline difference over k ≥ 3 repetitions per task, against a versioned tolerance; outcomes IMPROVED, WITHIN_NOISE, REGRESSED, or UNRESOLVED when data is incomplete; integer arithmetic.
- Q-MAS2-C = (a): split declarations digested before the first run that uses them; held-out scores stored apart and refused as input to any selection record.
- Q-MAS2-D = (a): budget caps in the configuration tuple; per-task tokens and cost (with the cache share) reported beside the score, never gated here, since H15 owns cost decisions.

## Not claimed

- No producer, consumer or service exists; nothing writes a manifest outside the vectors. The R12 trial of a run-manifest
  record is a later parallel-lane R12 packet.
- **Digests, not proof of use.** The manifest records digests; it cannot show that the digested artefacts are the ones
  that ran (that is H16's run lock and signer).
- **No completeness proof.** A record shows one run per repetition. It cannot show that every run or retry of a
  configuration was recorded: earlier attempts of a repetition and retries are bound by H16's campaign records (H16:
  evaluation failures do not retry into a pass). Records are append-only only by content addressing; a re-run is a new
  record with its own digest.
- **Same lock, not same round.** Equal evaluator locks show the same judge; whether two records were scored in the same
  grading round (VeriHarness's judge-drift control) is not recorded.
- **Selection.** The selection rule sees only the declarations in the store it is given; a held-out task re-declared
  under a new ID, a new content digest and a new suite at once is indistinguishable from a new task.
- **Cache keys.** Prompt-cache keys must differ within a record; a candidate record may reuse its baseline's keys, which
  only matters for cost measurement (H15's).
- **Exchangeable tasks.** The interval assumes the tasks are exchangeable samples; it says nothing about tasks outside the
  suite.
- The cited figures are the source papers' results, not platform evidence.
