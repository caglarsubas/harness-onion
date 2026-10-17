# MAS-RA-004 topology and coordination v1: independent contract review brief

Review the contract candidate in this directory and `scripts/topology_coordination.py`. You are not the author. Your round
number, the subject commit and where to write your record are in the message that starts the round.

## The subject

- `README.md`: the contract.
- `topology-spec.schema.json`, `board-transcript.schema.json` and `topology-run-binding.schema.json`: closed draft
  2020-12 schemas.
- `vectors.json`: 85 cases, 3 texts, 18 selection rows and 2 run-events v1 embeddings.
- `scripts/topology_coordination.py`: the standard-library reference model. `python3 -I -B
  scripts/topology_coordination.py` replays every vector, and checks the embeddings with MAS-RA-003's model.

The model consumes MAS-RA-002 (`scripts/run_manifest.py`) and MAS-RA-001 (`scripts/verdict_ledger.py`, with its pinned
`architecture/verdict-ledger/check-kinds.json`) as arguments. The runner also uses MAS-RA-003 (`scripts/run_events.py`)
and MAS-RA-008 (`scripts/agent_loop.py`). Those are adopted contracts; do not re-review them. From round 2 on, the README
ends with the previous rounds' dispositions; check each one against its finding.

Decisions are verbatim in the README: owner Q-M4-2, 3, 5 and 9, and the monitor's owner-delegated Q-M4-1, 4, 6, 7, 8, 10
and 11, all (a). Do not reopen them. Check that the contract does what they say, and nothing they exclude.

## Check (at least)

1. **Decisions.**
   - Q-M4-2: a graph, with the vector derived; budget and selection apply to the vector; each role binds a backbone.
   - Q-M4-3: compare-and-swap on one record per item; conflicting acquires refused; expired leases reclaimable;
     deterministic arbitration.
   - Q-M4-4: run-events v1 is unchanged, with a mapping and listed gaps.
   - Q-M4-5: the declared rule, the 45/100 threshold as a named parameter, honest provenance, the three outcomes, ≤ 4
     workers.
   - Q-M4-6/7: the budget, and per-role models.
   - Q-M4-8: executor-neutral and idempotent.
   - Q-M4-9: an independent verifier recorded in a MAS-RA-001 ledger; self-verification refused.
   - Q-M4-10: one objective.
   - Q-M4-11: hand-written transcripts.
2. **The model and the README agree.** Check every rule, code order, refusal precedence, effect and derived fact.
   Look for a board state or operation sequence where the model's answer is wrong or undefined:
   - expiry at exactly `leaseUntil`;
   - operations at the same `t`;
   - a retry across an expiry or the deadline;
   - verdicts after a renewal or a reclaim;
   - a release by the coordinator of an expired claim;
   - concurrency counted after expiries;
   - a MERGE whose latest verdict is FAIL after an earlier PASS.
3. **Schemas and model agree on SHAPE.** Check every case. Try your own minimal shape deviations against both: the
   harness-onion venv's jsonschema is allowed, offline.
4. **Vectors.**
   - Is every refusal a minimal deviation that reaches the rule it names?
   - Is every transcript answer right by hand? Spot-check at least the central and board transcripts end to end.
   - Do the stores' records and ledgers pass their own contracts' models?
   - Is anything in the README untested?
5. **The run-events v1 mapping.** Would the derived CLAIM, MERGE and MESSAGE points satisfy run-events v1's rules if
   embedded in a v1 log: CLAIM_CONFLICT, MESSAGE_PAIRING and one agent per run? Read `scripts/run_events.py`
   read-only. Is the gaps list complete?
6. **Cross-contract use.**
   - The baseline from a MAS-RA-002 record: is the formula right, and are completeness and single-agent status enforced?
   - The ledger binding: context roles, and status from MAS-RA-001's own check.
   - `check_run_binding`.
   - Can a caller pass bytes that bypass these checks?
7. **Not claimed and Carried.** Is anything overclaimed? Is a carried item missing?

## Rules for the reviewer (hard)

- **Read-only.** Never edit, commit, stage, check out or rebase anything. Write only your output record and files in a
  scratch dir from `mktemp -d <scratch>/masra004-review.XXXX`, and remove that dir afterwards. Leave no
  `__pycache__`; python is always `-I -B`.
- **PAUSE.** Prefix every command with `while [ -e /opt/planeon/verifier-control/PAUSE ]; do sleep 5; done;`. Also wait
  while `<workspace>/lane-guard/HOLD_BY_VERIFY` exists.
- **Limits.** One process at a time; `timeout 600` on each; scratch memory under about 2 GB.
- **Independence.** Never read W03/R10 material:
  - mas-harness-operator* clones or worktrees;
  - roadmap/W03_PLAN.md;
  - ~/.local/state/harness-onion-ci/tools/w03/**;
  - harness-onion-w03* worktrees;
  - architecture/w03-plan*/;
  - HE-* design documents;
  - W03-lane memory.
- **No network at all.** No gh, no git fetch, push or ls-remote, no installs, no web or paper downloads. Never put
  personal data (e-mail addresses, names, account ids, usernames) in any request, header, URL or query, or in your
  output.

## Output

A JSON record in the format of `architecture/run-events/review-round*.json`:

```
{"schemaVersion": "harness.planeon.ai/mas-contract-review/v1", "kind": "MAS-RA-004 contract review",
 "round": N, "reviewDate": "2026-10-16", "subjectCommit": ..., "subjectTree": ...,
 "verdict": "CHANGES_REQUIRED" | "PASS_FOR_SOURCE_PUBLICATION",
 "findings": [{"id": "M4R<N>-<n>", "severity": "MAJOR" | "MINOR" | "NOTE", "location": ..., "finding": ...,
               "requiredChange": ...}],
 "checksRun": [...], "probes": [...], "sourcesRead": [...],
 "actions": {"filesEdited": false, "personalDataSent": false}}
```

PASS_FOR_SOURCE_PUBLICATION means no MAJOR or MINOR finding remains. Then reply with the verdict, the findings in short,
and the time span of any command over 60 s.
