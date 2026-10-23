# LPK-0 (the probe-kit scope amendment): independent design review, round 1

You are an independent reviewer. You did not write this design or its dossiers. Judge whether the design is correct,
complete and faithful to the decisions. The test is concrete: after this record, every pinned statement that gives
CONF-LIVE-003/004/005 the moved items must be superseded by a quote that matches its bytes, nothing pinned may be edited,
nothing may move that the owner did not move, and the packet must stay data. Record what you actually checked, and never
claim a check you did not run.

WORK = `<scratch>/lpk0-design-r1`. TOOLS = `<workspace>/tools/w03/probekit`.

## Hard rules (every command, no exceptions)

- **The prefix, first on every command line:**
  `while [ -e /opt/planeon/verifier-control/PAUSE ] || [ -e <scratch>/lpk0-design-r1/PAUSE ] || [ -e <workspace>/lane-guard/HOLD_BY_VERIFY ]; do sleep 5; done;`
  Wrap every command in `timeout 120`. One process at a time, in the foreground.
- **Read-only and light.** Allowed: `GIT_OPTIONAL_LOCKS=0 git -C <repo> show <commit>:<exact file>`, pruned
  `git grep -l`, `git log -1 --format=%H <commit> -- <exact path>`, and `python3 -I -B` over text saved in WORK. Not
  allowed: running any repository script, test or validator; importing any repository module (in particular
  `scripts/validate_policy_observation.py` or `scripts/validate_readiness.py`); `git show -s`,
  `git show <commit>:<directory>`, `git ls-tree` of any directory, **`git grep -l -e ''` listings**, unpruned walks.
  Write only in WORK.
- **NO network.** No email address, name or personal data anywhere. Never write the legacy brand term (the old company
  word in the workspace folder path) in any file. Cite `HO:<path>:<lines>` for harness-onion at `2043cc27`.
- **Independence:** never open the R12 repository (mas-harness-conformance-labs) in any form, nor `tools/w04/`,
  `architecture/enforcement-test-plan/`, `docs/alpha-2/ENFORCEMENT_TEST_PLAN.md` or R12's `tests/enforcement/`; exclude
  them, `scripts/validate_enforcement_test_plan.py` and `tests/test_enforcement_test_plan.py` from every grep with `:!`
  pathspecs. Read `architecture/artifact-edges/` by exact path only. In
  `docs/repositories/12-mas-harness-conformance-labs.md` read only the lines the design cites and the scope sections
  around them, and never summarise R12's test logic.
- **Forbidden paths (never read):** `<workspace>/keys`, `github-app`, `/var/db/harness-ci`, any
  `operator-private/` directory, any memory file. Under `<workspace>/tools/` open only
  `w03/probekit/` (its `lpk0/`, `LPK0_DOSSIER.md`, `DOSSIER.md` and `OWNER_DECISIONS.md`).
- **Safety:** never write, import or run code that interposes on, forwards, proxies, swaps or bypasses anything.
- Python: always `python3 -I -B`.

## Subject

- **The design:** `TOOLS/lpk0/DESIGN.md`, revision 1 (sha256 `181364e6bb6bacf65f2b645bce69088c69d4c6c74e0a7a8f495d10cc31825756`,
  a copy in `DESIGN.rev1.md`).
- **The dossiers:** `TOOLS/LPK0_DOSSIER.md` (`6ce99678…`) and `TOOLS/DOSSIER.md` (`4243155a…`).
- **The decisions:** `TOOLS/OWNER_DECISIONS.md` (`d67b525dff21c752a88e0fa42b1ddb62453900cf80a8a83f7fd22e4616593004`), verbatim: owner LX-D1, LX-D2, Q-PK-1..6, Q-PK-13,
  Q-PK-ORDER, Q-LPK0-3 and Q-LPK0-4; the monitor's Q-PK-7..12, 14, Q-LPK0-1, 2, 5..12; PK-D1; the slots.
- **The repository:** harness-onion at `2043cc27`, in the checkout the launch prompt names.

## What to check

1. **Fidelity.** Is every decision carried exactly? In particular: the owner's server boundary (the admission module, the
   UID ledger and cleanup, and the native record inspector move; the KAP leg stays deferred and unowned); CONF-FIX-009/010
   as retained history with nothing deleted; the three packets' YAML byte-identical; the gate documents superseded by
   quote and not edited; the evolution-surface change kept out of this packet. Does the design decide anything the
   decisions did not?
2. **Completeness of the supersession.** Find, with pruned `git grep -l` and exact reads, every harness-onion statement
   that gives CONF-LIVE-003, 004 or 005 one of the moved items (the server, the admission module, the UID ledger and
   cleanup, the native record parser and inspector, the worker entry, the ten recipes, the receipt candidates, and their
   packaging). Is each either in `supersedes`, or covered by `notAmended` as a record or catalog that stays as history?
   Name any statement the design misses, and any it includes wrongly.
3. **Nothing pinned is edited.** Check every file the design touches or names against the pins the dossier lists
   (authority `baselinePackets`, BHA `protectedFiles`, VLB and VBH, NQA `dispatch`, the 21/23 guide pins). Would any
   change in §1 "In" break a pin or a validator (L4.1-L4.8)?
4. **The KAP leg (Q-SC-2).** Is `DEFERRED_UNOWNED` a faithful reading of "KAP stays deferred and unowned, per LX-D1"? Does
   leaving CONF-LIVE-003's YAML naming it, while no packet is dispatched to build it, create a contradiction with BHA's
   `dispatch` or with VBH's consumer-drift check?
5. **The unchanged identities.** Are the installed paths, the SERVER and WORKER roles, the protocol record's
   `workerEntry`, the broker binding, the vectors and the signing duties really unaffected by the ownership change? Does
   keeping `live_fixed_probes.broker_worker_main` (an R12 module name) as the kit's entry name create any conflict?
6. **Gate material.** Are all of the packet's paths data under the evolution-surface record at `2043cc27`
   (`architecture/evolution-surface/evolution-surface.json`, read its text; run nothing)? Check
   `architecture/probe-kit-scope/` and `docs/linux-probe-kit/` against case variants of gate paths.
7. **The predecessor table.** Acyclic, complete, and consistent with PK-D1 and the slots?
8. **The model and vectors (§5).** Do the checks cover the failure modes that matter (a quote that drifts, a missed
   clause, a moved KAP leg, an edited pinned file, a gate path)? Name a missing check.
9. **The mechanics (§6).** Is anything there inconsistent with the post-255 chain rules or the 64-argv freeze?
10. **The questions Q-SC-1..5:** agree, or say what should change.

## Output

Write `WORK/design-review-round1.json` (check this name: round 1 of LPK-0's design review):

```
{"subject": {"design": "LPK-0 DESIGN.md rev 1", "sha256": "181364e6…"}, "reviewer": "independent agent", "model": "<id>",
 "brief": {"path": "tools/w03/probekit/lpk0/DESIGN_REVIEW_BRIEF.md", "sha256": "<as computed>"},
 "verdict": "PASS_FOR_CONTRACT" | "CHANGES_REQUIRED",
 "findings": [{"id": "S1-n", "severity": "MAJOR|MINOR|NOTE", "location", "finding", "requiredChange"}],
 "supersessionCoverage": [{"statement", "path", "lines", "inDesign": true|false, "note"}],
 "questions": [{"id": "Q-SC-n", "position": "agree|amend|disagree", "reason"}],
 "checks": [{"check", "result"}], "notChecked": [...]}
```

Reply with the verdict, the brief's sha256 as you computed it, and one line per finding.
