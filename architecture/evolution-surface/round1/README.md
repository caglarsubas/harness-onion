# Evolution surface v1 (EVOLUTION-SURFACE-001)

2026-10-21. Status: **CONTRACT_CANDIDATE** (internal, DATA_CHECK_ONLY; independent contract review pending). Roadmap item
EVOLUTION-SURFACE-001 (H14 primary), from owner decision PA-D3 (D3a).

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
| `vectors.json` | `planeon.internal.evolution-surface-vectors/v1`: 44 decisions, 28 invariant breaks, 5 texts, 18 paths, 8 skip rules, 8 PR rows, 2 coverage rows, the derivation, 9 consumer cases |
| `../../scripts/evolution_surface.py` | the reference model; `python3 scripts/evolution_surface.py` replays every vector |

The schema carries the SHAPE rules. The model checks the same shapes and refuses as SHAPE exactly when the schema rejects.
Rules beyond shape are the model's.

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
- Programme level: the merge of the approved head. Before the merge, the head is the approved head and contains current
  main (the verifier's admission rule 2). After the merge, main's tree is compared with the head's tree; on a mismatch the
  monitor stops, records it in the merge-decision record and reports to the owner, and any revert is a new PR.

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
use, independent evidence in a bundle, and audit are rules for the consumers (MAS-RA-005, R09, the monitor's merge
check). `vectors.json` lists them as consumer cases.

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

Unknown names in a request are refused as UNKNOWN_REFERENCE; a malformed path as SHAPE. Every public function judges the
record first.

**Public functions:** `load`, `check`, `decide`, `resolve`, `pr_approvers`, `pr_activators`, `derive_gate_material`,
`skipped`, `tree_paths`, `coverage`, `check_coverage`.

## Invariants

`check(record)` raises `Refused(code)` on the first rule broken, in this order of codes (whole-record passes), and
otherwise returns the record's digest and its derived gate-material list:

| Code | Rule |
|---|---|
| `SHAPE` | 1: the schema (closed shapes, enums, patterns, bounds); a change-bound class has no paths |
| `DUPLICATE_ID` | role and class ids are unique within a level |
| `UNKNOWN_REFERENCE` | 1: every referenced role and class exists within the same level |
| `NEVER_AUTONOMOUS` | 2: a never-autonomous class lists no AGENT role in `approve` or `activate` |
| `SELF_GOVERNANCE` | 3: no governed role approves |
| `SEPARATION_OF_DUTIES` | 4: no AGENT or SERVICE role both generates or tests and approves one class |
| `TWO_PERSON` | 4: `twoPerson` is true exactly when a HUMAN role both generates or tests and approves |
| `ACTIVATION_WITHOUT_APPROVAL` | 5: a non-empty `activate` needs a non-empty `approve` |
| `APPEND_ONLY` | 6: an append-only class has empty `approve` and `activate` |
| `INDEPENDENCE` | 7: related classes have disjoint `generate` sets |
| `PATHS` | 8: no path entry appears twice; the `under` directories of a Gate class with under-plus-name entries are exactly the Gate prefixes |
| `INDEPENDENT_EVIDENCE` | 10: a content-bound class with approvers lists a tester outside its generators |
| `COVERAGE` | 9: every file of the checked-out tree outside the skip set falls in exactly one class (`check_coverage`) |

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
grounded in P27's validation checks, P28 and E2E-13. HUMAN_APPROVER's test of EVALUATOR_RUBRIC is human calibration.

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

Bridge classes (no path; applied by hand): VERIFIER_BUNDLE (never autonomous; the owner installs), MERGE_DECISION_RECORD
and OWNER_DECISION_RECORD (append-only; D5a, D6a), ROADMAP_STATUS (change-bound; the monitor's lock grant) and
ROADMAP_SCOPE (change-bound; the owner).

New review evidence uses the names `review-round<n>.json` and `REVIEW_BRIEF*.md`. Five historical review files at
29c84b3 use other names; they resolve to `CONTRACT_AND_SOURCE` and are frozen.

The root `conftest.py` (gate) gates the declared pytest plugin and exit-status path, not the capability: any test module
runs code in the same pytest process, which is the residual risk the owner-operated verifier doc already names (test
contents need human review).

### The coverage skip set

At the root: `.git` (a file or a directory) and `.venv`. At any depth: the directories `__pycache__`, `.pytest_cache`,
`.ruff_cache`, `.mypy_cache`, and the files matching `*.py[cod]` or named `.DS_Store`. The check matches whole path
components, never string prefixes, reads no git object and does not read `.gitignore`. An untracked file in a developer
checkout fails the check until it is removed or classified.

## The gate-material derivation

`derive_gate_material` returns every path entry of the classes whose `approve` set is exactly `{OWNER}`, leaving out
under-plus-name entries inside a derived prefix. At 29c84b3 that is 27 entries: PA-D5's six (its "verifier docs" read as
`docs/alpha-2/OWNER_OPERATED_VERIFIER.md` only) plus the 21 the owner accepted on 2026-10-21 (Q-ES-6 (b), Q-ES-D1 (a),
Q-ES-D2 (a)): the record's own three entries and candidates C1 to C13. The vectors hold PA-D5's list, each accepted group
with its grounds, and the difference; the derived list must equal PA-D5's list plus exactly the accepted extensions.
