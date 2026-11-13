# Repository Plan: `mas-harness-research-lab`

## Purpose and boundaries

R13 is the programme's research repository (kind meta, no plane): the hypothesis register, preregistered experiments,
run records, verdict-form results ledgers, one-page reports, design reads and per-scope progress documents of the
Research-Lab session (`research/README.md`, the charter). It is public; another LLM provider's GitHub App reads it and
opens issues; it never writes. The repository is evidence and proposals, never authority: what should enter the product
goes to the roadmap visionary as a proposal and through the harness-admission gate as a candidate.

Non-goals:

- No product code, no task packets, no roadmap writes, no contracts; nothing another repository imports.
- No hosted workflow, runner, artifact, cache or package; verification is the owner-operated verifier only.
- No experiment runs under the verifier: acceptance re-derives committed ledgers from committed inputs and checks
  records; heavy runs stay on the lane monitor's queue.

## Repository structure and exact tree

This tree projects the current task-packet `allowedPaths`. Directory entries do not authorize edits beyond the packet
executed in a coding run.

```text
mas-harness-research-lab/
├── .gitignore
├── LICENSE
├── README.md
├── ci/
│   ├── verify-offline.sh
│   ├── warm-source-isolation.sh
│   ├── network_canary.py
│   ├── run_packet_argv.py
│   └── zero_bill_scan.py
└── research/
    ├── README.md
    ├── MANIFEST.json
    ├── build_research.py
    ├── research.html
    ├── research.json
    ├── history.json
    ├── hypotheses/REGISTER.md
    ├── experiments/RL-nn/{PREREG.md, PREREG-REVIEW.md, runs/, data/, RESULTS.json, REPORT.md}
    ├── reads/
    ├── reviews/
    ├── progress/
    └── tools/
```

## Dependencies

- Contract/source: none. The lab reads other repositories through git-archive exports at pinned commits (the
  platform's published contracts, the conformance-labs harness, never its oracle tests); nothing is imported.
- Build artifact: none; the acceptance set is the standard library on the verifier's python-distribution profile.
- Runtime integration: none. Downstream: the bridge mirrors `research/research.html`, `research.json`, `history.json`
  and `MANIFEST.json` at each merge; proposals reach the roadmap through the visionary, never by a dependency edge.

## Warm-source mapping

None. The repository holds no warm source and no reuse index entry.

## PR packets

1. `LAB-REPO-001-repository-bootstrap`: over the owner's initial commit cc92594d (the bridge's research tree byte for
   byte with `research/MANIFEST.json`, the root README, LICENSE and the manifest tools): the exact harness-onion
   transport copies (the runner at 283's fixed form, harness-onion main e515f0b8), a standard-library zero-bill scan,
   the remaining acceptance tools (preregistration and review records, evaluator re-derivation with reproduction
   levels, privacy, page check), the bridge's research records added or modified since the base (41 and 4 files, the
   packet's frozen set), the manifest regenerated, the page rebuilt and the lab's YES record with its review record;
   verifiable only once bundle v7 is installed, through its self-retiring first-packet route.
2. `LAB-SYNC-001-research-sync`: PR 5 (branch codex/lab-sync-a2482753, head 9992d1755f71) over LAB-REPO-001's merge 2e977f4f5a31: research/** only,
   keeping LAB-REPO-001's six commands byte-exact and in order; published by MET-007 at slot 288 (K = 1) and verified
   on R13's hosted route under bundle v7's R13 policy row.

## Testing, verification, and acceptance

`LAB-REPO-001` declares `prefetchCommands: []` and ordered `offlineAcceptanceCommands` of six `python3 -I -B` argv
arrays: the zero-bill scan, the manifest check, the privacy check, the preregistration-and-review check, the evaluator
re-derivation and the page check. The executor supplies the hash-pinned packet through `HARNESS_TASK_PACKET` and
invokes only `offlineExecution.wrapperArgv: ["./ci/verify-offline.sh"]` for the complete ordered list. Later packets
add checks as direct argv arrays; each lab PR carries a PREREG, its review brief (PREREG-REVIEW.md) and a review
record in the platform's review-record v2 schema before any run, and the register's frozen digests are checked
against the folder's files at every head.

Acceptance: the head's tracked set equals the manifest; every digest named in a register row is present as a frozen
PREREG; every re-derived ledger is byte-identical; no privacy hit; the page's data record reproduces; no workflow file.

## Release and rollback

No release artifact. A merge is the publication; the bridge mirror follows. Rollback is the revert of the PR; frozen
preregistrations are never rewritten (a correction is a new version or a new experiment id).

## Zero-bill rules

No file under `.github/`; no hosted runner, Actions cache, artifact or package; no network in acceptance; the owner's
verifier is the only CI; `ci/zero_bill_scan.py` refuses any workflow file, symbolic link or bytecode entry.
