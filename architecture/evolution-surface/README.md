# Evolution surface v1 (EVOLUTION-SURFACE-001, packet MET-GOV-001)

2026-10-21. Status: **ADOPTED_CONTRACT_CANDIDATE** (internal, DATA_CHECK_ONLY; independent contract review round 5:
PASS_FOR_ADOPTION, with the owner's NOTE fold; rounds and review records in `status.json`). Roadmap item
EVOLUTION-SURFACE-001 (H14 primary), from owner decision PA-D3 (D3a). Packet MET-GOV-001 (monitor decision MON-ES-ID).

**Record version 2** (packet MET-GOV-002, REVIEW-RECORD-V2; contract candidate, under that packet's review): the owner's
Q-RR2-6 (b) adds the programme class GATE_REVIEW_PROCESS for the review-record v2 contract
(`architecture/review-record/README.md`). The schema and the model do not change. The derived gate list grows from 27
to 31 entries (the accepted group RR2 below).

## What this contract is

The contract fixes, as closed data with a standard-library reference model and replayable vectors, which roles may
propose, generate, test, approve and activate each artifact class, at two levels:
- the **product level**: the four planes' evolution roles, the evolvable artifact classes and the never-autonomous ones
  (spec v1.0 P27, P28, E2E-13);
- the **programme level**: Harness-Onion's own artifacts, by repository path, and its bridge records. It derives the
  gate-material list.

Nothing runs and nothing is enforced here. MAS-RA-005's admission gate and R09 consume the record later. Until then, the
lane monitor applies the programme level by hand.

The record is gate material (owner decision Q-ES-6 (b), 2026-10-21): a change to it needs the owner's per-PR approval.

No harness document, repository schema or earlier contract changes.

## Files

| File | What it is |
|---|---|
| `evolution-surface.schema.json` | `planeon.internal.evolution-surface/v1` (draft 2020-12, closed) |
| `evolution-surface.json` | the record: both levels and the coverage skip set |
| `vectors.json` | `planeon.internal.evolution-surface-vectors/v1`: 44 decisions, 31 invariant breaks, 5 texts, 23 paths, 8 skip rules, 9 PR rows, 2 coverage rows, 10 request rows (9 refusals, 1 pass), the derivation, 12 consumer cases |
| `../../scripts/evolution_surface.py` | the reference model; `python3 scripts/evolution_surface.py` replays every vector |

The schema carries the SHAPE rules for I-JSON values. On those, the model refuses as SHAPE exactly when the schema rejects.
A value that is not I-JSON (a lone surrogate, a non-integral or out-of-range number, duplicate member names in text) is
SHAPE beyond the schema, so the model is never weaker than the schema. Rules beyond shape are the model's.

## Record format

As MAS-RA-001 to MAS-RA-004:
- I-JSON (RFC 7493): UTF-8, no duplicate member names, no NaN or infinity, no lone surrogate;
- integers only, within ±(2⁵³−1);
- canonical bytes by RFC 8785 (JCS), with member names sorted by UTF-16 code units (its section 3.2.3);
- `digest` is `sha256:` followed by the hex digest of the canonical bytes.

The vectors pin the record by its digest.

The earlier models (MAS-RA-001 to MAS-RA-004) sort member names by code point. The two orders differ only when names mix
characters above U+FFFF with characters from U+E000 to U+FFFF; every name in this record is ASCII. The oracle tests
found the difference; this model follows the RFC.

## The model

### Operations

`propose`, `generate`, `test`, `approve`, `activate`.

**Approval is content-bound.** It binds:
- the content: at the product level, the candidate's immutable version digest; at the programme level, the PR's full
  40-hex head sha and its tree;
- the evaluation bundle: at the product level, the digests of the evaluation evidence; at the programme level, the review
  record digests and the verify result for that head.

**Independent evidence** (P28, E2E-14).
- The bundle must hold a passing result from a `test` role outside the class's `generate` set.
- A bundle with only the generator's own result authorizes nothing.
- Any failed mandatory independent result blocks activation, whatever the self-score says. The rejection and its
  evidence are kept.

**Expiry and single use** (E2E-10).
- Product level: an approval expires after its H14 approval policy's `expiresSeconds`.
- Programme level: an approval covers one merge of the named head; a re-pushed head needs a new approval.
- Each activation consumes its approval.

**Activation** puts exactly the approved content into effect.
- Product level: Runtime activation; publication of approved knowledge; for Trust-plane artifacts, H14's
  `registry-service` promote, which moves an immutable active pointer. A digest mismatch refuses the activation, and the
  prior active version stays.
- Programme level: the merge of the approved head, under owner decision Q-ES-D3 (a):
  - the owner's per-PR question names the exact head sha;
  - before the merge, the head is the approved head and contains current main (the verifier's admission rule 2), and main
    is unchanged since the verify (the verify's main sha equals current main);
  - after the merge, main's new tree is compared with the approved head's tree;
  - the merge-decision record binds the full 40-hex head sha;
  - on any mismatch of these checks (MONITOR.md section 4) the monitor stops, records it in the merge-decision record and
    reports to the owner; any revert is a new PR, and a re-pushed head needs a new approval.

**Rollback** (E2E-16).
- Approval-free rollback exists only at the product level, for the seven evolvable classes (not never-autonomous; they
  govern no role).
- It is done by the class's activator, under policy, to the most recent earlier version that was activated under a
  then-valid approval and is still CERTIFIED in H14's terms (not deprecated, retired or revoked).
- The regressed version's artifacts and lineage are kept.
- Every other rollback is a new activation with a fresh approval: any never-autonomous class, any class that governs a
  role, and every programme-level revert.

**Change-bound approval** (`approvalBinding: "CHANGE"`), for the bridge roadmap classes only: the approval names a change
(the items and the fields), the lock holder's write activates it, and the monitor checks the written digests when the
lock is returned. No repository class may be change-bound.

**Consumer rules.** The model checks roles and paths only. Byte equality of activated and approved content, expiry, single
use, independent evidence in a bundle, the merge-check points above, and audit are rules for the consumers (MAS-RA-005,
R09, the monitor's merge check). `vectors.json` lists them as consumer cases.

### Roles

`{id, kind: AGENT | HUMAN | SERVICE, plane (product level only), description}`.
- AGENT: a model-driven actor that decides for itself.
- HUMAN: an accountable person.
- SERVICE: deterministic machinery acting under a declared policy. It may run model graders as instruments, but it
  originates no decision outside its policy. A deployment where a model-driven actor decides approvals or activations
  (rollbacks included) must declare that role an AGENT.

### Classes

```
{id, description, paths? (programme level only), neverAutonomous, appendOnly, twoPerson,
 approvalBinding: "CONTENT" | "CHANGE", governs: [roleId], independentOf: [classId],
 operations: {op: [roleId]}, grounds: [reference]}
```

- `governs`: the roles whose behaviour, evaluation or authority the class constrains.
- `independentOf`: classes whose `generate` sets must be disjoint from this one's. The relation is symmetric.
- `twoPerson`: one HUMAN role both generates or tests and approves; the approving person must differ from whoever, in
  that role, generated or tested the change. The model checks the flag, not persons.
- `grounds`: the requirement that places each listing.

### Programme paths

A path entry is `{"exact": file}`, `{"prefix": "dir/"}`, or `{"under": "dir/", "name": pattern}` (any file at any depth
below `dir/` whose file name matches `pattern` by `fnmatch.fnmatchcase`, which is case-sensitive). A path resolves to:
1. the class of an exact entry; otherwise
2. among the matching under-plus-name and prefix entries, the longest directory; on equal length an under-plus-name entry
   beats a prefix;
3. no class, when two entries still match.

A path in no class is refused, so every new top-level file needs an owner-approved revision of this record.

**Case variants of gate material** (owner decision Q-GOV-CAP, F1) fall in no class, files and links alike, so they are
refused everywhere (resolve, PR approvers and activators, coverage, the link rule): a path whose case-folded spelling
equals a case-folded gate entry, lies inside a case-folded gate directory, or is a case-folded directory that holds gate
material, while its exact spelling does not resolve to a single Gate class. On a case-insensitive file system such a path
is the gate path; on a case-sensitive one it only resembles it; either way it fails closed.

A **symbolic link** is classified by its own path, exactly as a file would be (the skip set's path rules), whatever its
target is, and it is never followed. The coverage check judges every link the walk meets, whatever its name: the skip
set only skips classification, and the any-depth skip directories are descended so that the links inside them are judged
too. The root's `.git` and `.venv` are not descended: git refuses paths inside `.git`, and a `.venv` path falls in no
class, so no PR touching one can be approved. The check refuses:
- a link whose own path is gate material, a case variant of it (F1), or stands in place of a directory that holds gate
  material: a data-only change to its target would change what gate paths serve;
- a link whose final target, judged by file identity and never by spelling (so a case-insensitive file system is
  covered), is the tree, an ancestor of the tree, gate material, or a directory that contains gate material: a data
  path would then alias gate material, and a data-only change retargeting the link would decide what that path serves;
- a dangling or looping link, or any link whose target cannot be resolved.

The rule concerns symbolic links; git records no hard links. A known residual: the target half resolves the target's
on-disk names by identity and then compares them with the gate entries; a link to a directory whose on-disk name is a
case variant of gate material and that holds only skipped files is not refused by the link rule. No gate file exists
there (a gate file in it would be listed under the case-variant name and refused by F1), so nothing gated is reached.

The tree at 29c84b3 holds no symbolic link (`git ls-tree` shows no entry of mode 120000).

A PR's **changed paths** are its added, modified and deleted paths and both sides of a rename. Its **approvers** (and
**activators**) are the intersection of the `approve` (and `activate`) sets of the classes its changed paths fall in. An
empty intersection, a path in no class, or no changed paths means none.

### The decision

`decide(record, level, role, class, op)` returns `{"decision": "ALLOWED", "reasons": []}` exactly when the role is listed
for that operation. Otherwise it returns `{"decision": "DENIED", "reasons": [...]}` with every reason that applies, in this
order:

| Reason | When |
|---|---|
| `NOT_LISTED` | always, when denied |
| `NEVER_AUTONOMOUS` | an AGENT asks to approve or activate a never-autonomous class |
| `SELF_GOVERNANCE` | a role asks to approve a class that governs it |
| `SEPARATION_OF_DUTIES` | an AGENT or SERVICE role in the class's `generate` or `test` asks to approve it |
| `APPEND_ONLY` | a role asks to approve or activate an append-only class |
| `INDEPENDENCE` | a role asks to generate a class while it generates a class related to it by `independentOf` |

A request whose level, role, class or operation is unknown or not a string is refused as UNKNOWN_REFERENCE; a malformed
path as SHAPE. Every public function judges the record first.

**Public functions:** `load`, `check`, `decide`, `resolve`, `pr_approvers`, `pr_activators`, `derive_gate_material`,
`skipped`, `tree_paths`, `coverage`, `check_paths`, `check_coverage`.

## Invariants

`check(record)` raises `Refused(code)` on the first rule broken, in this order of codes (whole-record passes), and
otherwise returns the record's digest and its derived gate-material list:

| Code | Rule |
|---|---|
| `SHAPE` | 1: the schema (closed shapes, enums, patterns, bounds); a change-bound class has no paths; I-JSON |
| `DUPLICATE_ID` | role and class ids are unique within a level |
| `UNKNOWN_REFERENCE` | 1: every referenced role and class exists within the same level |
| `NEVER_AUTONOMOUS` | 2: a never-autonomous class lists no AGENT role in `approve` or `activate` |
| `SELF_GOVERNANCE` | 3: no governed role approves |
| `SEPARATION_OF_DUTIES` | 4: no AGENT or SERVICE role both generates or tests and approves one class |
| `TWO_PERSON` | 4: `twoPerson` is true exactly when a HUMAN role both generates or tests and approves |
| `ACTIVATION_WITHOUT_APPROVAL` | 5: a non-empty `activate` needs a non-empty `approve` |
| `APPEND_ONLY` | 6: an append-only class has empty `approve` and `activate` |
| `INDEPENDENCE` | 7: related classes have disjoint `generate` sets |
| `PATHS` | 8: no path entry appears twice; the `under` directories of a Gate class with under-plus-name entries are exactly the Gate prefixes; every entry at or inside a Gate prefix belongs to a Gate class |
| `INDEPENDENT_EVIDENCE` | 10: a content-bound class with approvers lists a tester outside its generators |
| `COVERAGE` | 9: every file of the checked-out tree outside the skip set falls in exactly one class, and no symbolic link, whatever its name, is or reaches gate material (`check_coverage` walks the tree; `check_paths` judges an already filtered list) |

A Gate class is one whose `approve` set is exactly `{OWNER}`. The PATHS rule means no data entry can win a path that the
derived list names as gate material.

Two narrowings, stated:
- **Proposing is outside separation of duties.** The monitor's data approval is never sole. MONITOR.md section 4 and D5a
  require an independent review PASS on the exact head, a successful verify on it, a CLEAN PR, a head and tree check,
  review records naming reviewer and brief sha256, oracle tests outside the candidate, anything open going to the owner
  first, an immutable merge-decision record, and telling the owner. The monitor does not propose `ROADMAP_STATUS` changes,
  which it approves at the lock grant.
- **`neverAutonomous` restricts approve and activate, not generate.** Drafts by a governed agent need a non-governed,
  content-bound approval before anything changes; at the product level no governed AGENT generates a never-autonomous
  class.

## The record

### Product level

Roles: EVOLUTION_AGENT (AGENT, Execution), TASK_AGENT (AGENT, Execution; proposes only), KNOWLEDGE_CURATOR, TRUST_EVALUATOR,
TRUST_APPROVER (H14's governance-service and registry-service), RUNTIME_ACTIVATOR (SERVICE), HUMAN_APPROVER (HUMAN).

Classes: the seven evolvable ones (PROMPT, PROCEDURAL_SKILL_GRAPH, ROUTING_STRATEGY, TOOL_CONFIGURATION, MEMORY_KNOWLEDGE,
MODEL_ADAPTER, MODEL_WEIGHTS) and six never-autonomous, two-person ones. Five of those six are P27's list
(ACCEPTANCE_THRESHOLD, TRUST_POLICY, CREDENTIAL, APPROVAL_OR_ROLLOUT_GATE, PROMOTION_AUTHORITY_CODE); EVALUATOR_RUBRIC is
grounded in P27's validation checks, P28 and E2E-13.

Readings:
- HUMAN_APPROVER is the accountable approver and is not listed as governed. Where a class also constrains humans
  (credentials, promotion code), `twoPerson` stands in for self-governance.
- HUMAN_APPROVER's test of EVALUATOR_RUBRIC is human calibration; it gives that class its independent tester.
- The evolution agent's own `test` is a pre-test; the independent result a bundle must carry is TRUST_EVALUATOR's.
- CREDENTIAL and PROMOTION_AUTHORITY_CODE keep activation with HUMAN_APPROVER, stricter than the invariants need.

### Programme level

Roles: LANE_SESSION, REVIEWER_AGENT, ORACLE_AGENT, ROADMAP_VISIONARY, LANE_MONITOR (AGENT), OWNER (HUMAN), VERIFIER
(SERVICE).

Repository classes: data (approve and activate {LANE_MONITOR, OWNER}) and gate (approve {OWNER}, activate
{LANE_MONITOR, OWNER}, the monitor's merge of the owner-approved head):

| Class | Kind | Paths |
|---|---|---|
| `CONTRACT_AND_SOURCE` | data | `architecture/`, `scripts/`, `tests/`, `docs/`, `task-packets/`, `diagnostics/`, `reference-observer/`, `release/` |
| `REPOSITORY_ROOT` | data | the root files no verify argv runs or the installed environment pins |
| `GATE_CI` | gate | `ci/`, `.github/`, `pyproject.toml`, root `conftest.py` |
| `GATE_SCHEMAS` | gate | `schemas/` |
| `GATE_POLICIES` | gate | `policies/`, `AGENTS.md`, `BILLING_POLICY.md`, the zero-bill scanner and fixtures, the release evidence policy, lock and lock scripts |
| `GATE_LEGAL` | gate | `legal/`, `LICENSE`, `NOTICE` |
| `GATE_HARNESS_DOCS` | gate | `docs/harnesses/` |
| `GATE_VERIFIER_DOCS` | gate | the owner-operated verifier doc, the trusted-runner contracts, the development-CI exception, `docs/linux-runner/`, the credential-ordering repair |
| `EVOLUTION_SURFACE` | gate | this directory, its authority file and the model |
| `ORACLE_TESTS` | data | under `tests/`, `test_*oracle*.py`; independent of the candidate classes |
| `REVIEW_BRIEF`, `REVIEW_RECORD` | data | under `architecture/`, `REVIEW_BRIEF*.md` and `review-round*.json` |
| `GATE_REVIEW_BRIEF`, `GATE_REVIEW_RECORD` | gate | the same names under each gate directory |
| `GATE_REVIEW_PROCESS` | gate | `architecture/review-record/`, `architecture/review-record-authority.json`, `scripts/review_record.py`, `tests/test_review_records_in_tree.py` (record version 2); generated by LANE_SESSION, tested by REVIEWER_AGENT, ORACLE_AGENT and VERIFIER; ORACLE_TESTS, REVIEW_RECORD and GATE_REVIEW_RECORD are independent of it |

Bridge classes (no path; applied by hand): VERIFIER_BUNDLE (never autonomous; the owner installs), MERGE_DECISION_RECORD
and OWNER_DECISION_RECORD (append-only; D5a, D6a), ROADMAP_STATUS (change-bound; the monitor's lock grant) and
ROADMAP_SCOPE (change-bound; the owner).

### Why each entry sits where it does

PA-D5's gate list is `ci/`, `schemas/`, `policies/`, `legal/`, `docs/harnesses/` and the verifier docs. The owner accepted
these further entries on 2026-10-21 (Q-ES-D1 (a), Q-ES-D2 (a)):

| Candidate | Path | Why it is gate material |
|---|---|---|
| D1-i | this directory, its authority file, `scripts/evolution_surface.py` | the record defines who approves gate material (Q-ES-6 (b)) |
| C1 | `.github/` | the offline-readiness workflow must stay disabled and byte-identical; a change could reopen a runner path the zero-bill policy forbids |
| C2 | `BILLING_POLICY.md` | the zero-bill policy text (its machine form is `policies/zero-bill-policy.yaml`) |
| C3 | `release/evidence-policy.yaml` | it defines which evidence counts as passing |
| C4 | `LICENSE`, `NOTICE` | legal |
| C5 | `docs/TRUSTED_RUNNER_CONTRACT.md`, `docs/alpha-2/CI_CAPACITY_EXCEPTION.md`, `docs/linux-runner/` | the verifier's runner, its development-CI exception and the Linux runner docs (Q-ES-D2 (a)) |
| C6 | `AGENTS.md` | the agents' own execution rules (zero-bill boundary, trusted transport and launchers, "merge only when every required check is green"); rule 8 binds the merger, so the class governs the monitor |
| C7 | `scripts/zero_bill_scan.py`, `tests/fixtures/zero-bill/` | the zero-bill enforcement scanner (the last acceptance argv) and its fail-closed negative fixtures |
| C8 | `pyproject.toml` | its pytest settings load the `ci/` plugin and set the strictness of the verifier's pytest argv |
| C9 | `release/repos.lock.json` | the promotion decision, pinned to the evidence policy's digest |
| C10 | root `conftest.py` | it loads `ci/pytest_diagnostics.py` and sets the session exit status of the verifier's pytest argv |
| C11 | `scripts/check_release_lock.py`, `scripts/build_release_lock.py` | the code that checks and builds the promotion decision |
| C12 | `docs/TRUSTED_LIVE_CAMPAIGN_RUNNER_CONTRACT.md` | the manual, post-merge live-campaign launcher contract, AGENTS.md rule 12's only live-execution path |
| C13 | `docs/alpha-2/CREDENTIAL_ORDERING_REPAIR.md` | MET-REPAIR-013, the live path's only credential-ordering exception (it supersedes, for one profile, wording in C12 and rule 12) |
| RR2 | `architecture/review-record/`, `architecture/review-record-authority.json`, `scripts/review_record.py`, `tests/test_review_records_in_tree.py` | record version 2: the brief registry and the checker decide which review rounds count for a merge (Q-RR2-6 (b), 2026-10-21); the whole directory and the authority (D-1) and the in-tree pre-check (D-2) are named in the owner's per-PR ask |

Kept as data, with reasons:
- `Makefile`: no verify argv runs it. `requirements.lock`, `uv.lock`: `uv run --frozen --no-sync` uses the installed
  environment. `task-packets/`: the verifier keeps each packet's acceptance commands monotonic (admission rule 3). The
  `architecture/*-authority.json` chain records.
- `tests/conftest.py`: a suite-wide fixture that shares exact history projections. It loads no `ci/` code and does not
  touch the exit status, so it has the power of any test file.
- This packet's own tests, chain layer, packet YAML and docs: successor packets adjust predecessor layer validators and
  tests mechanically, so making them gate would make every later packet gate material. The record's content, its model
  and its authority are gate; a weakened test cannot change who may approve what.

The root `conftest.py` (C10) gates the declared pytest plugin and exit-status path, not the capability: any test module
runs code in the same pytest process. That is the residual risk the owner-operated verifier doc already names (test
contents need human review), while the standing authority merges data packets, tests included, on an agent's review. The
record makes this existing tension visible; it does not resolve it (the E1-20 note, passed to the owner).

### Stated deviation and provenance

- **A stated deviation from P28** ("can candidate authors change their own evaluation gate?"): the lane writes the review
  brief for its own candidate. Three things mitigate it: the brief is pinned by sha256 in the review record and its
  identity sidecar; the monitor checks that each review record names that brief's sha256 (D5a); and the brief governs
  the lane, so the lane never approves it.
- **Provenance:** a file name decides only a file's class. Who wrote a file is shown by its identity sidecar (D5a), not
  by its name.
- New review evidence uses the names `review-round<n>.json` and `REVIEW_BRIEF*.md`. Five historical review files at
  29c84b3 use other names; they resolve to `CONTRACT_AND_SOURCE` and are frozen.

### The coverage skip set and the walk

At the root: `.git` (a file or a directory) and `.venv`. At any depth: the directories `__pycache__`, `.pytest_cache`,
`.ruff_cache`, `.mypy_cache`, and the files matching `*.py[cod]` or named `.DS_Store`. The check matches whole path
components, never string prefixes, reads no git object and does not read `.gitignore`.

The walk fails closed: an empty root, a root that is not an existing directory (a linked root included, however it is
written), a directory that cannot be listed, or an entry that cannot be examined is refused as COVERAGE. The root is
normalized first (F3): trailing separators and `.` components are dropped, and its parent part is resolved physically,
as `realpath` does, keeping the last component itself, so `..` after a linked component means what the file system
means and a linked root is still seen as a link. One exception (F2), exactly as the owner worded it: an entry, file or
directory, that vanished (ENOENT) inside an any-depth skip directory, such as a bytecode writer's renamed temporary
file, is absent. A skip directory that itself vanished is not inside one, so it fails closed. An untracked file in a developer checkout fails the
check until it is removed or classified.

## The gate-material derivation

`derive_gate_material` returns every path entry of the classes whose `approve` set is exactly `{OWNER}`, leaving out
under-plus-name entries inside a derived prefix. At 29c84b3 that is 27 entries: PA-D5's six (its "verifier docs" read as
`docs/alpha-2/OWNER_OPERATED_VERIFIER.md` only) plus the 21 the owner accepted on 2026-10-21 (Q-ES-6 (b), Q-ES-D1 (a),
Q-ES-D2 (a)): the record's own three entries and candidates C1 to C13. Record version 2 adds the group RR2 (Q-RR2-6
(b)): four entries, so 31 entries and a difference of 25. The vectors hold PA-D5's list, each accepted group with its
grounds, and the difference; the derived list must equal PA-D5's list plus exactly the accepted extensions.

## Contract review round 1 and dispositions

Round 1 reviewed commit a47b58ee: CHANGES_REQUIRED, with every binding rule (design round 3, E3-1 to E3-10) met, 0 MAJOR,
5 MINOR and 5 NOTE findings.

| Finding | Disposition |
|---|---|
| G1R1-1 MINOR: the tree walk failed open | ADDRESSED: a root that is not an existing directory, or a directory that cannot be listed, is refused as COVERAGE; tests for a missing root, a file root, a linked root and an unreadable directory |
| G1R1-2 MINOR: "exactly when the schema rejects" was too broad | ADDRESSED: the sentence is scoped to I-JSON values, with non-I-JSON faults SHAPE beyond the schema; tests add an in-memory lone surrogate and a final-newline probe for every patterned field |
| G1R1-3 MINOR: a valid record could let a data entry win inside a Gate prefix | ADDRESSED: PATHS now also requires every entry at or inside a Gate prefix to belong to a Gate class; invariant vectors I29 to I31 |
| G1R1-4 MINOR: two accepted merge-check points missing | ADDRESSED: main unchanged since the verify, and the merge-decision record binding the full head sha, under programme activation; consumer cases K11 and K12 |
| G1R1-5 MINOR: rules and reasons of the design missing from the README | ADDRESSED: the product readings, "Why each entry sits where it does", "Stated deviation and provenance" and the E1-20 note |
| G1R1-6 NOTE: a non-string request name raised TypeError | ADDRESSED: refused as UNKNOWN_REFERENCE; request vector U04 and tests |
| G1R1-7 NOTE: the ALLOWED half of the sweep was tautological | ADDRESSED: the sweep computes the five other reasons for every listed request |
| G1R1-8 NOTE: no refusal rows for requests, paths or coverage; K07 looser than the rule | ADDRESSED: ten request vectors (U01 to U10, COVERAGE included); K07 matches the rollback target; K10 adds E2E-16's contained exposure |
| G1R1-9 NOTE: symbolic links classified by their own path | ADDRESSED: the rule is stated, and the coverage check refuses a link that is, or reaches, gate material; tests for five link cases |
| G1R1-10 NOTE: replay used assert; the packet id was not named | ADDRESSED: replay raises `Mismatch` explicitly (a test proves it); the README names MET-GOV-001 |

## Contract review round 2 and dispositions

Round 2 reviewed commit 60b37471: CHANGES_REQUIRED, every binding rule met, round 1's dispositions 8 ADDRESSED and 2
PARTLY (G1R1-4, G1R1-9), 0 MAJOR, 3 MINOR and 1 NOTE findings.

| Finding | Disposition |
|---|---|
| G1R2-1 MINOR: links named like skip-set entries escaped the link rule | ADDRESSED: the walk collects every link whatever its name; the skip set only skips classification; tests for gate-path links named `__pycache__`, `*.pyc` and `.DS_Store`, a data link named `__pycache__`, and a root `.venv` link |
| G1R2-2 MINOR: link targets judged by spelling | ADDRESSED: targets are judged by file identity (device and inode along the target's ancestry, names resolved by identity below the root); an ancestor of the tree, a dangling and a looping link are refused; tests include `../CI` and the tree's parent |
| G1R2-3 MINOR: K11's remedy inexact | ADDRESSED: K11 expects no merge, stop, record and report to the owner, a verify on current main and a new approval for a re-pushed head; the README applies stop, record and report to any mismatch |
| G1R2-4 NOTE: count, check_paths scope, lstat failures, the data-link reason, vector order, linked root | ADDRESSED: 9 refusals and 1 pass; check_paths documented as taking a filtered list; an entry that cannot be examined fails closed (test); the data-link half has its own reason; I28 precedes I29; a linked root is stated |

## Contract review round 3 and dispositions

Round 3 reviewed commit 1d517f1e: CHANGES_REQUIRED, every binding rule met, G1R2-2, G1R2-3, G1R2-4 and G1R1-4 ADDRESSED,
G1R2-1 and G1R1-9 PARTLY, 0 MAJOR, 2 MINOR and 1 NOTE findings.

| Finding | Disposition |
|---|---|
| G1R3-1 MINOR: links inside real skip directories were not judged | ADDRESSED: the any-depth skip directories are descended for the link rule; the root's `.git` and `.venv` are not, with the reason stated; tests for links inside `ci/__pycache__`, `docs/__pycache__` and `docs/.pytest_cache` |
| G1R3-2 MINOR: a link in place of a gate directory passed | ADDRESSED: a link whose own path stands in place of a directory that holds gate material is refused, mirroring the target half; tests for `docs/harnesses`, `tests/fixtures/zero-bill`, `docs/alpha-2`, `architecture/evolution-surface` and a root `ci` link |
| G1R3-3 NOTE: classification by target type; check_paths docstring; unresolvable targets; hard links | ADDRESSED: a link is classified by its own path alone (test); check_paths says it has no link rule; the README and the model name unresolvable targets and say git records no hard links |

## Contract review round 4 and dispositions; the cap

Round 4 reviewed commit 97fa3e8b: CHANGES_REQUIRED, every binding rule met, every earlier disposition ADDRESSED except
G1R1-9 (PARTLY; its remainder is G1R4-1), 0 MAJOR, 1 MINOR and 1 NOTE findings. The owner then decided Q-GOV-CAP: fold
F1 to F3, run one short delta round 5 limited to them, then cap the rounds (any further finding goes to the owner).

| Finding | Disposition |
|---|---|
| G1R4-1 MINOR: a link's own path was judged by spelling, so a case variant stood in place of gate material | ADDRESSED (F1): case variants of gate material, files and links alike, fall in no class and are refused everywhere; path vectors R19 to R23, PR vector Q09, tests |
| G1R4-2 NOTE: (a) a concurrent bytecode write in `__pycache__` could refuse the walk; (b) a linked root written with `/` or `/.` | ADDRESSED: (a) F2, an entry that vanished inside an any-depth skip directory is absent, every other failure fails closed (test), and the dry run confirms whether the verify writes bytecode into the checkout; (b) F3, the root is normalized first (tests) |

## Contract review round 5 (the last) and dispositions

Round 5 reviewed commit 72901245 under Q-GOV-CAP: PASS_FOR_ADOPTION, every binding rule met, G1R4-1 and G1R4-2
ADDRESSED, 0 MAJOR, 0 MINOR and 4 NOTE findings, none blocking the packet. The owner then decided to fold the four small
fixes with no further round; the packet review after the chain mechanics checks them first.

| Finding | Disposition |
|---|---|
| G1R5-1 NOTE: the F2 exception was broader in code than in the owner's wording, and its directory branch had no test | ADDRESSED: the code now matches the owner's wording exactly (a vanished entry is absent only inside a skip directory; a skip directory that itself vanished fails closed), the README says so, and a test covers the directory branch |
| G1R5-2 NOTE: lexical root normalization; an empty root meant the current directory | ADDRESSED: an empty root is refused; the root's parent part is resolved physically, keeping the last component; tests |
| G1R5-3 NOTE: a target-name residual for a case-variant directory holding only skipped files | ADDRESSED: the README states the residual and why nothing gated is reached |
| G1R5-4 NOTE: R19 and Q09 did not distinguish F1 | ADDRESSED: R19 is `docs/Harnesses/x.md` and Q09 adds it to a data PR; both resolved to data before F1 and to no class with it |
