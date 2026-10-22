# The I01 digest contract: independent contract review, round 1 (candidate 1)

You are an independent reviewer. You did not write the design, the contract, the build script or any earlier review.
Judge whether candidate 1 implements the reviewed design (revision 3) and the rulings exactly, whether its vectors pin
what they claim, and whether an observer following it refuses whenever the live cluster's enforcement differs from what
the release binds, without ever echoing the binding. Record what you actually checked, and never claim a check you did
not run.

WORK = `<scratch>/digest-contract-r1`. TOOLS = `<workspace>/tools/w03/digest`.

## Hard rules (every command, no exceptions)

- **The prefix, first on every command line:**
  `while [ -e /opt/planeon/verifier-control/PAUSE ] || [ -e <scratch>/digest-contract-r1/PAUSE ] || [ -e <workspace>/lane-guard/HOLD_BY_VERIFY ]; do sleep 5; done;`
  Wrap every command in `timeout 600`. One process at a time.
- **Light and read-only.**
  - Read repositories only through `GIT_OPTIONAL_LOCKS=0 git -C <repo> show <commit>:<exact path>` and pruned
    `git grep -l`. Never run anything inside a checkout and never write to one.
  - You may run `python3 -I -B` only over copies under WORK: copies of the STAGE files, of `TOOLS/build_contract.py`
    and `TOOLS/src/`, and the scratch copies named below.
  - **Never import `scripts/validate_policy_observation.py` (VPO) or `scripts/validate_readiness.py`, and never copy
    them into WORK.** VPO's module-level import chain executes `scripts/validate_enforcement_test_plan.py`, an
    excluded file (MON-DIG-BUILD-ETP-IMPORT). Judge VPO's rules by reading VPO's text with `git show`.
  - You may copy `scripts/validate_proxy_contract.py` (VPC) and `scripts/safe_yaml.py` by `git show` into WORK and
    import VPC: it imports only `safe_yaml`, `jsonschema` and `yaml`. Check that before importing.
  - No cargo, pytest over a repository, verifier or sim.
  - Write only in WORK.
- **git grep -l or exact paths only. No ls-tree of any directory**, and no `git show <commit>:<directory>` (that prints
  a listing). Read `architecture/artifact-edges/` by exact path only.
- **NO network.** Never put an email address, a name or personal data anywhere. Never write the legacy brand term (the
  old company word in the workspace folder path) in any file; build any scan string for it from parts. Use
  `<workspace>/` in your record.
- **Safety:** never write, import or run code that interposes on, forwards, proxies, swaps or bypasses anything. Judge
  bypass forms on paper. Mutants of VPC's three helpers and of the model, under WORK only, are allowed for the mutation
  checks below. No classifier or inventory tooling.
- **Independence:** never open the R12 repository, `tools/w04/`, `architecture/enforcement-test-plan/`,
  `docs/alpha-2/ENFORCEMENT_TEST_PLAN.md` or R12's `tests/enforcement/`. Exclude them, and
  `scripts/validate_enforcement_test_plan.py` and `tests/test_enforcement_test_plan.py`, from every grep with `:!`
  pathspecs.
- **Forbidden paths (never read):** `<workspace>/keys`, `github-app`, `/var/db/harness-ci`, any
  `operator-private/` directory, any memory file. Under `<workspace>/tools/`, open only the TOOLS
  files listed under Subject, by exact path.
- Python: always `python3 -I -B`.

## Subject

- **Candidate 1, the STAGE tree** `TOOLS/contract/`:

  | Path | sha256 |
  |---|---|
  | `architecture/policy-observation-digests/README.md` | `415d6fb003f8252bf8cd1e0c487761260b811ae2df18f3405596cb5389147529` |
  | `architecture/policy-observation-digests/definitions.json` | `24d4568bb6fe00b4c493a3768d625e8ea984de40a6545f14651a93ceb40f2b3d` |
  | `architecture/policy-observation-digests/vectors.json` | `3c5ed95ff83596c6f437e292bb1f5fa048cf3adfa8dd2d98afa481aa5c96e17f` |
  | `scripts/policy_observation_digests.py` | `82ae642e8981f7851f8f3b7894127c08e5c9ba9b12a1fecb4a86db18540e5b7f` |
  | `architecture/artifact-edges/operator-harness-engineering-v10.json` | `50c23e2c92b376b0db0e8ad97517aba58ebacdfdbe077280350fc74de7e6592f` |
  | `architecture/artifact-edges/README-v10.md` | `7e16d68ae20b7707548df4c398b891a56482ebedf250254dac6da3b465220a43` |

- **The build:** `TOOLS/build_contract.py` (`ac0a181bc58bdc979a06d4da461306a72dd11bc0d84a5345ac621f0b16b8c052`), `TOOLS/src/`, and the builder's report `TOOLS/BUILD_REPORT_C1.md`
  (`6f40e219fd64a2a81304d57e57e439be5e0fd3437292664bf370ab2d005ec043`), with its questions Q-CB-1..13.
- **The design:** `TOOLS/DESIGN.rev3.md` (`73cd9f6ddeab744b6b9c222204a9bdd4d0a0eef54e4c6f6321fe80bf28a9c083`).
- **The decisions:** `TOOLS/OWNER_DECISIONS.md` (`c7056161211f22609b82e41c2ca5dc8f82f8c57266f35f776965ec908f0d8452`),
  verbatim: R1-A..C, R2-A..C, R3-A, R3-B, Q-CB-1 and Q-CB-2 decided; Q-CB-3..13 are open questions you judge.
- **The design reviews:** `TOOLS/reviews/design-review-round1.json`, `-round2.json`, `-round3.json`.
- **The repositories:** harness-onion at **`30f41e6f`**, R10 at **`dd7422ed`**, in the checkouts the launch prompt
  names.

## What to check

1. **Fidelity to the design and rulings.** Every rule of DESIGN.rev3 §3-§10, D3-1..D3-7, R3-A, R3-B, Q-CB-1 and Q-CB-2
   is in the README, `definitions.json`, the model and the vectors, with nothing added that no decision covers (Q-CB-3..13
   excepted, which you judge). In particular: the per-answer capture gate with the 90 s bound on the monotonic clock and
   the wall-age refusal (D3-1, both vectors); the residual table, including R-NET-AGENT's three T04 checks and the
   custody citation (R3-A); the exact-name admission rule over (kind, name); B1's refusals first (D3-3).
2. **The model against the README.** Read `scripts/policy_observation_digests.py` in full. For each projection and
   digest, does the code compute exactly what the README says, in the stated order, with the stated refusal texts?
   Name every divergence.
3. **The vectors.** Run the model's self-check from a WORK copy. Then judge whether the vectors would catch a wrong
   model:
   - **Q-CB-1 (required by the monitor):** for each of VPC's `canonical`, `digest` and `_bounded`, name at least one
     byte-level mutation (applied to a WORK copy of VPC) that at least one vector rejects. Run them.
   - Mutate the model itself (under WORK) at the points that matter most: the gate's bound and clock, the sort rules,
     the subject key, the non-resource scope, the NetworkPolicy form check, the exact-name rule, the podSecurityLabels
     filter, the BROKER member list, and the closure value's shape. Report which mutants the vectors kill and which
     survive. A surviving mutant that changes a security outcome is a finding.
4. **Attack cases.** Re-run on paper the 22 + 22 + 23 cases from the three design reviews against candidate 1 and give
   the tally per set. Map each to its vector, as the build report claims, and check the claims.
5. **The complete I01 positive.** VPC: run `validate_profile` on its profile from a WORK copy of VPC. VPO: do not
   import it; instead, read VPO's `validate_messages` text with `git show` and check, member by member, that the
   positive satisfies every comparison it makes (the build report's Q-CB-6 proposes the import-level check move to the
   packet's layer test).
6. **Determinism.** Run `build_contract.py` twice into fresh WORK directories (it reads the repository only through
   `git show`; confirm that before running it) and compare with the STAGE tree byte for byte.
7. **Edge record v10.** v9's 68 rows unchanged and in order; the four new rows exactly as DESIGN.rev3 §10 and Q-CB-2
   say; `supersedes` correct; PPV's last-change commit and sha256 correct at `30f41e6f`; PPS not registered and the
   replay input set as claimed.
8. **Hygiene.** No local path, legacy term or personal data in any STAGE file; the README cites CS, PV and RD by
   sha256; nowhere is VPC "pinned by digest".
9. **The builder's questions Q-CB-3..13.** For each: agree, or say what should change.

## Output

Write `WORK/contract-review-round1.json` (check this name: it is round 1 of the **contract** review):

```
{"subject": {"candidate": 1, "files": {"<path>": "<sha256>", ...}}, "reviewer": "independent agent", "model": "<id>",
 "brief": {"path": "tools/w03/digest/CONTRACT_REVIEW_BRIEF_R1.md", "sha256": "<as computed>"},
 "verdict": "PASS_FOR_ADOPTION" | "CHANGES_REQUIRED",
 "findings": [{"id": "C1-n", "severity": "BLOCKING|MAJOR|MINOR|NOTE", "location", "finding", "requiredChange"}],
 "mutations": {"helpers": [{"function", "mutation", "rejectedBy"}], "model": [{"point", "mutation", "killedBy" | "survived"}]},
 "attackCases": {"tallies": {"round1": {...}, "round2": {...}, "round3": {...}}, "cases": [{"set", "case", "outcome", "vector"}]},
 "questions": [{"id": "Q-CB-n", "position": "agree|amend|disagree", "reason"}],
 "checks": [{"check", "result"}], "notChecked": [...]}
```

Reply with the verdict, the brief's sha256 as you computed it, the helper mutations and what rejected each, the
surviving model mutants, the tallies, and one line per finding.
