# MET-LIVE-003 (the neutral Linux probe interface as harness-onion data): independent light review, round 1

You are an independent reviewer. You did not write this design, this contract, the interface contract itself or any of
its reviews.

Judge whether MET-LIVE-003's design (revision 1) and contract candidate c1 do what the decisions ask:
- bring the four handoff files into harness-onion byte-identical;
- bind them, their source and their review chain by digest;
- bind LPK-0's `NEUTRAL_INTERFACE_CONTRACT` placeholder;
- check the interface's conformance to its own schema with a sound standard-library validator;
- state the non-claims faithfully.

This is the packet's one light review: the monitor ruled "One light review, then mechanics". Record what you actually
checked, and never claim a check you did not run.

WORK = `<scratch>/lpi-review-r1`. TOOLS = `<workspace>/tools`.

## Hard rules (every command, no exceptions)

- **The prefix, first on every command line:**
  `while [ -e /opt/planeon/verifier-control/PAUSE ] || [ -e <scratch>/lpi-review-r1/PAUSE ] || [ -e <workspace>/lane-guard/HOLD_BY_VERIFY ]; do sleep 5; done;`
  Wrap every command in `timeout 120`. Run one process at a time, in the foreground, with no pipes between processes.
- **What you may read:**
  - `TOOLS/w03/probeinterface/`, all of it;
  - the four files in `TOOLS/probekit-interface-handoff/`: `MANIFEST.json`, `probe-interface.json`,
    `probe-interface.schema.json` and `README.md`;
  - `TOOLS/w03/probekit/OWNER_DECISIONS.md`;
  - `TOOLS/w03/probekit/lpk0/adopted/amendment.json` and `README.md`.
- **What you may never read:**
  - `TOOLS/probekit-interface-extract/` or anything else under `TOOLS/`;
  - R12 (mas-harness-conformance-labs) in any form, including the R12 paths that `v1/README.md` cites. Those citations
    are for the interface's own reviewers;
  - `<workspace>/keys`, `github-app`, `/var/db/harness-ci`, any `operator-private/` directory or any
    memory file.
- **harness-onion,** if needed for the evolution-surface classes: read only
  `GIT_OPTIONAL_LOCKS=0 git -C <checkout> show 2043cc27:architecture/evolution-surface/evolution-surface.json`. There
  are no listings, and `tools/w04/` and the enforcement-test-plan paths stay excluded.
- **Running code:** you may run the candidate's `linux_probe_interface.py` and `build.py`, copied into WORK, with
  `python3 -I -B`. You may also run your own scripts, and the installed `jsonschema` library for a cross-check if this
  interpreter has it. Never run or import any repository script.
- **NO network.** No email address, name or personal data anywhere. Never write the legacy brand term (the old company
  word in the workspace folder path) in any file.
- **Safety:** never write, import or run code that interposes on, forwards, proxies, swaps or bypasses anything.

## Subject

- **The design:** `TOOLS/w03/probeinterface/DESIGN.rev1.md`
  (`4eb8c8f7cb5c8dcceed4d93c2b918e0e24e601f9a730aa556a0fff3caebd6865`).
- **Candidate c1:** `TOOLS/w03/probeinterface/rounds/c1/`:

  | File | sha256 |
  |---|---|
  | `binding.json` | `275a6d58…` |
  | `vectors.json` | `67ca9f38…` |
  | `linux_probe_interface.py` | `37bdd2d2…` |
  | `README.md` | `48f8f3b5…` |
  | `build.py` | `c4b0a361…` |
  | `v1/` | the four files |

- **The decisions:** in `TOOLS/w03/probekit/OWNER_DECISIONS.md` (`5ff6861c…`):
  - owner Q-PK-6;
  - owner "Keep them in R12 (Recommended)";
  - the monitor's placement and slot ruling;
  - the handoff note, which names the four files' digests.
- **LPK-0's adopted record:** `TOOLS/w03/probekit/lpk0/adopted/amendment.json` (`cf49670d…`).

## What to check

1. **Byte identity.** Are `rounds/c1/v1/*` byte-identical to the handoff files and to the monitor's four digests?
2. **The record.** Is it closed, and does it equal the MANIFEST? Check the source, the three review rounds and the
   files. Does the placeholder binding name LPK-0's record by its adopted digest, the right placeholder, and
   `probe-interface.json`'s digest? Are the owner decisions each quoted once in their dated section?
3. **The validator.**
   - Does it implement draft 2020-12's meaning for exactly the schema's keyword set? Find the schema's actual keywords
     yourself.
   - Does an unsupported keyword refuse?
   - Plant at least ten instance mutations of your own, and compare the validator with `jsonschema` if available
     (otherwise judge on paper). Cover required members, additional properties, const and enum, patterns, lengths, item
     counts, uniqueness, `prefixItems`, the `if`/`then` rules and `$ref`.
   - Name any disagreement.
4. **The model.**
   - Run it on the record and on every vector.
   - Plant at least eight mutations of your own: a file digest, the MANIFEST, the reviews, the placeholder, the
     non-claims, the shape and a wrong type.
   - Name any that a correct model should refuse but c1 accepts.
5. **The non-claims and the README.** Are they faithful to the MANIFEST's `ownerNotes` and `nonClaims` and to the
   owner's decision? Does the README say anything the record does not hold?
6. **Placement.** Is every new path data under `2043cc27`'s evolution-surface record, exactly and case-folded? The new
   paths are:
   - `architecture/linux-probe-interface/**`;
   - `scripts/linux_probe_interface.py`;
   - `scripts/validate_linux_probe_interface.py`;
   - the tests;
   - `task-packets/MET-LIVE-003.yaml`;
   - `architecture/linux-probe-interface-authority.json`.

## Output

Write `WORK/review-round1.json`. Check this name: round 1 of MET-LIVE-003's light review.

```
{"subject": {"design": "4eb8c8f7…", "candidate": "c1", "bindingSha256": "275a6d58…"}, "reviewer": "independent agent", "model": "<id>",
 "brief": {"path": "tools/w03/probeinterface/REVIEW_BRIEF_R1.md", "sha256": "<as computed>"},
 "verdict": "PASS_FOR_ADOPTION" | "CHANGES_REQUIRED",
 "findings": [{"id": "L1-n", "severity": "MAJOR|MINOR|NOTE", "location", "finding", "requiredChange"}],
 "validatorChecks": [{"mutation", "ours", "jsonschema", "agree"}],
 "plantedMutations": [{"mutation", "refused": true|false, "refusal"}],
 "checks": [{"check", "result"}], "notChecked": [...]}
```

Reply with:
- the verdict;
- the brief's sha256 as you computed it;
- any validator disagreement;
- any mutation that passes;
- one line per finding.
