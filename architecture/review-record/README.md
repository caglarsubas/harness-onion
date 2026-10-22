# Review record v2 (REVIEW-RECORD-V2, packet MET-GOV-002)

**Status:** contract candidate, under independent contract review. Not adopted. `legacy-review-records.json` is
derived at the packet's base, harness-onion 2043cc27; see "The frozen list".

A review round in Harness-Onion is two records, bound by the sha256 of the record file's bytes:
- the **review record** (`planeon.review-record/v2`), written by the reviewer agent;
- the **review identity** (`planeon.review-identity/v2`), written by the lane session that launched the reviewer.

A **brief registry** (`planeon.review-briefs/v1`) pins each series' published brief. A **frozen list**
(`planeon.legacy-review-records/v1`) names the review records that predate v2. An **oracle identity**
(`planeon.oracle-identity/v1`) binds each oracle test file written outside the candidate (owner decision D5a).

`scripts/review_record.py` is the reference model and checker, standard library only. `python3 -I -B
scripts/review_record.py` replays every vector in `vectors.json`.

## Decisions

- **The owner's Q-RR2-1..5:** "Accept all five (a) (Recommended)". As relayed:
  - two records per round, bound by digest;
  - the registry pins the published brief per kind;
  - tree-bound merges, where a squash of what was reviewed is fine;
  - the pre-check runs as a harness-onion test over every v2 record, plus the monitor's own check before each merge,
    with the legacy records frozen by a digest list;
  - merge-decision/v1 is kept, with `reviews[]` citing the v2 records by digest.
- **Q-RR2-4's condition:** "no new argv". The new test files run inside the existing outer pytest argv.
- **The owner's Q-RR2-6:** "Gate material (Recommended)". The brief registry and the checker are gate material, and their
  paths join the gate list in this packet.
- **The owner's Q-RR2-CAP:** "Fold into rev 4, no round (Recommended)". The design's binding rules B-1 to B-10 are this
  contract's first review items.
- **The owner's D-3:** "File-byte sha256 (Recommended)".
- **The owner's Q-RR2-NAMES:** "Load hashes locally (Recommended)". It narrows B-8's in-suite name check; see "Privacy".
- **Design decisions D-1 and D-2,** which go into the owner's per-PR question:
  - D-1: the whole `architecture/review-record/` directory and `architecture/review-record-authority.json` are gate
    material.
  - D-2: `tests/test_review_records_in_tree.py`, which runs the pre-check over the tree, is gate material.

## The digest rule

Every digest that binds one file to another is the sha256 of the file's bytes, written as 64 lowercase hex digits with
no prefix (owner D-3). That covers:
- identity to record;
- registry to brief;
- the frozen list;
- oracle identity to oracle file;
- v2 citations in merge-decision records.

A truncated or prefixed digest is refused. Records need not be canonical, since the binding is the file's bytes.

## The records

**Shared forms:**
- **Times** are RFC 3339 with an offset, taken from file timestamps, with up to nine fraction digits; they are compared
  at that full precision. **Dates** are RFC 3339 full dates.
- **A subject** is `{repository, commit, tree}`, where the repository is a bare name such as `harness-onion` and commit
  and tree are 40 hex. For a local design note it is `{path, sha256}`.
- **An agentId** is a tool-generated agent or session id: `^[a-z0-9][a-z0-9_-]{7,79}$`. The values
  `stamped_by_operator`, `recorded-by-the-launcher`, `unknown` and `none` are refused as placeholders. So is the v1
  placeholder `STAMPED_BY_OPERATOR`, through the pattern. The schemas type `kind` and every agentId as plain strings, so
  that UNKNOWN_KIND and PLACEHOLDER_ID are reached after SHAPE (B-6).

### `planeon.review-record/v2` (the reviewer)

| Member | Required | Meaning |
|---|---|---|
| `schemaVersion` | yes | `planeon.review-record/v2` |
| `kind` | yes | DESIGN, CONTRACT, PACKET or PR. A delta is a round with a `base`, not a kind. |
| `series` | yes | a stable id such as `MET-GOV-002/contract`; a published directory holds one series |
| `round` | yes | an integer ≥ 1 |
| `subject` | yes | what was reviewed |
| `base` | for a delta | the previous round's subject; absent for a full round |
| `reviewDate` | yes | a date |
| `briefSha256` | yes | the series' registered brief |
| `rulesSha256`, `wrapperSha256` | yes (or null) | the local round rules file and the wait wrapper |
| `reviewer` | yes | {model, role}; no agentId, because a reviewer cannot attest its own |
| `verdict` | yes | from the kind's list in the registry |
| `findings` | yes | [{id, severity: MAJOR, MINOR or NOTE, location, finding, requiredChange, blocks}] |
| `checked` | yes | strings or {check, result}, at least one |
| `disclosures` | yes | the reviewer's own account of slips; the record's digest binds it |
| `bindingRules` | no | [{rule, met, note}] |
| `dispositions` | no | [{id, status: ADDRESSED, PARTLY or NOT, note?}] |
| `notChecked`, `questions` | no | strings |

### `planeon.review-identity/v2` (the operator)

| Member | Meaning |
|---|---|
| `record` | {path, sha256}: the record it binds |
| `reviewer` | {agentId, agentType, model}; the model equals the record's |
| `operator` | {role: LANE_SESSION, agentId, lane?}. A published identity is written only by LANE_SESSION (B-10); one the monitor writes stays in the bridge. |
| `author` | {agentIds}: the session or sessions that wrote the subject |
| `briefSha256`, `rulesSha256`, `wrapperSha256`, `subject`, `base` | each equals the record's |
| `launched`, `finished` | times, with launched ≤ finished |
| `interruptions`, `operatorRelays` | lists, possibly empty |
| `runs` | [{limit, used}]: `limit` names a limit of the round's rules in words, `used` is a count |
| `ruling` | {decision: NONE_NEEDED, PENDING, KEEP or VOID; by: LANE_MONITOR or OWNER; ref; date} |

**The ruling rule:**
- NONE_NEEDED is valid only when the record's `disclosures` and the identity's `interruptions` and `operatorRelays` are
  all empty.
- Otherwise the decision is KEEP or VOID, with `by`, `ref` and `date`. It is PENDING until the monitor or the owner
  rules.
- A round counts for a merge only with NONE_NEEDED or KEEP.
- The monitor cross-checks each `ref` against its own decision records before a merge.

### `planeon.oracle-identity/v1` (the operator, for an oracle file; D5a)

| Member | Required | Meaning |
|---|---|---|
| `schemaVersion` | yes | `planeon.oracle-identity/v1` |
| `file` | yes | {path, sha256}: the oracle test file it binds, by the sha256 of its bytes |
| `oracle` | yes | {agentId, model}: the oracle agent |
| `operator` | yes | {role: LANE_SESSION, agentId, lane?}, as for review identities (B-10) |
| `author` | yes | {agentIds}: the sessions that wrote the candidate; the oracle is none of them (B-5) |
| `briefSha256` | yes | the oracle brief |
| `candidateCommit` | yes | 40 hex: the candidate commit at which the bound oracle file passes. It may be a local commit that is never pushed, which the monitor reads in the lane's local repository (RR2C2-6). |
| `launched`, `finished` | yes | times, with launched ≤ finished |
| `ruling` | yes | as for review identities |
| `disclosures` | no | strings: the oracle's slips, interruptions and operator relays |

**The author's reading (RR2C1-4).** Design section 6 gives the oracle identity "the same rule as in section 3.2" but no
`disclosures` member. Here an oracle identity carries its interruptions and relays in `disclosures`, and NONE_NEEDED is
valid only when `disclosures` is absent or empty; otherwise KEEP or VOID, as for reviews.

### File names

| File | Record | Written by |
|---|---|---|
| `review-round<n>.json` | review record | REVIEWER_AGENT |
| `review-identity-round<n>.json` | identity, beside its record | LANE_SESSION |
| `oracle-identity.json`, `oracle-identity-<part>.json` | oracle identity | LANE_SESSION |
| `REVIEW_BRIEF*.md` | pinned brief | LANE_SESSION |

**Oracle identity names are exact** (`ORACLE_NAME`, the monitor's Q-GOV2-PRE-INTREE (a)): `oracle-identity.json`, or
`oracle-identity-` followed by one or more hyphen-separated parts of `[a-z0-9]+`, then `.json`. The rule holds in every
directory. Any other name, such as the schema `oracle-identity.schema.json`, is not an oracle identity and binds nothing.
A file with a matching name that is not a valid identity is still SHAPE.

**Where records live:**
- DESIGN and CONTRACT series are published in their contract directory.
- Records of head-bound kinds (PACKET, PR) stay outside the reviewed tree, in TOOLS or the bridge, because a record
  committed into the PR would change the tree it binds.

## The brief registry (`briefs.json`)

**`kinds`** holds, for each of the four kinds, the closed verdict list and its passing subset:

| Kind | Verdicts | Passing |
|---|---|---|
| DESIGN | PASS_FOR_BUILD, CHANGES_REQUIRED | PASS_FOR_BUILD |
| CONTRACT | PASS_FOR_ADOPTION, PASS_FOR_SOURCE_PUBLICATION, CHANGES_REQUIRED | PASS_FOR_ADOPTION, PASS_FOR_SOURCE_PUBLICATION |
| PACKET | PASS_FOR_PRECHECK, PASS_FOR_PUSH, CHANGES_REQUIRED | PASS_FOR_PUSH (a pre-check clearance is no merge authority, RR2C1-9) |
| PR | PASS_FOR_PUSH, CHANGES_REQUIRED | PASS_FOR_PUSH |

**`briefs`** holds entries {kind, series (an exact id, or a prefix such as `MET-GOV-002/`), path, sha256, version,
supersedes?, supersededAt?}.

**Rules (B-3), checked when the registry is loaded** (a break is SHAPE):
- One kind per series pattern.
- Versions of one brief are chained. The chain starts at version 1, with no `supersedes`. Each older version has
  `supersededAt`, and the next one, whose `version` is the older one's plus 1, has the older one's sha256 as
  `supersedes`. A later `supersededAt` comes after an earlier one. The latest has no `supersededAt`.
- No series id is matched by two patterns (an exact id and a prefix, or two nested prefixes).
- **The author's readings** (contract r1): the +1 version rule is stricter than rev 4. "The latest has no
  `supersededAt`" means a series cannot be retired without a current brief.

**A convention, not checked at load (RR2C2-4):** a new version of a brief gets a new path, so a superseded version keeps
its own file. The in-suite tests check only each chain's latest version against the file at its path.

**Rules checked per round:**
- A round cites a brief registered for its series with the same kind; otherwise BRIEF_NOT_FOR_SERIES. A brief of another
  series is refused even when it is of the same kind.
- A superseded version is refused (BRIEF_SUPERSEDED) when the identity's `launched` is at or after `supersededAt`, or
  the record's own `reviewDate` is on or after its date.
- Local round rules files are not registered; both records pin them by `rulesSha256`.
- A published brief carries placeholders only. A registry change needs the owner's per-PR approval (Q-RR2-6).

## The checks and their codes

`check_review(record_bytes, record_path, identity_bytes, identity_path, registry, head=None, repository=None)` takes
the files' bytes and paths, never parsed objects (B-10), and checks in this order (B-6):

| Code | Rule |
|---|---|
| `NO_IDENTITY` | no identity record |
| `NO_BRIEF_DIGEST` | `briefSha256` absent, or not 64 lowercase hex |
| `SHAPE` | either record breaks its closed schema (I-JSON; digest, date, time and form rules; an operator other than LANE_SESSION), or a rule beyond the schemas (below) |
| `UNKNOWN_KIND` | a kind not in the registry |
| `BINDING` | the identity's `record` is not {the record's path, the sha256 of its bytes} |
| `PLACEHOLDER_ID` | an agentId is a placeholder or breaks the pattern |
| `NOT_INDEPENDENT` | the reviewer's agentId equals the operator's or an author's |
| `IDENTITY_MISMATCH` | model, brief, rules, wrapper, subject or base differ between the records |
| `SUBJECT_FORM` | a PACKET or PR record whose subject is not {repository, commit, tree} |
| `SUBJECT_REPOSITORY` | when a repository is given (the tree check): a subject naming another repository; R10 and R12 records live in TOOLS, not in this tree |
| `BRIEF_NOT_FOR_SERIES` | the brief is not registered for the series and kind |
| `BRIEF_SUPERSEDED` | as above |
| `VERDICT` | the verdict is not in the kind's list |
| `RULING` | PENDING or VOID; NONE_NEEDED with a disclosure, interruption or relay; KEEP without by, ref or date |
| `SUBJECT_MISMATCH` | when a head is given, for PACKET and PR only: the subject's tree is not the head's tree; a squash (another commit, the same tree) passes |
| `PRIVACY` | an absolute home-path shape, an e-mail shape or the legacy term (by a sha256 prefix), and the fixed name tokens by sha256 when a local scan has loaded them (see "Privacy"); counts only |

**SHAPE beyond the schemas (RR2C1-3, RR2C2-2).**
- **The shared patterns.** The schemas and the model carry the same patterns:
  - dates and times have years 0001 to 9999, real months, days up to 31, hours 00 to 23, minutes and seconds 00 to 59,
    and offsets up to ±23:59;
  - every integer is at most 2^53−1.
- **The model-only causes.** On I-JSON values the model refuses as SHAPE exactly when a schema rejects, except for the
  causes below. Each is fail-closed.
  - A value that is not I-JSON (a duplicate member name, NaN, a lone surrogate). The schemas apply only to I-JSON
    values; the I-JSON rows (such as `shape-duplicate-member-text`) pin this.
  - An integer written with a fraction or an exponent (`1.0`, `1e0`), which JSON Schema counts as an integer.
  - A day the month lacks (`2026-02-30`).
  - `launched` after `finished`.
- **Vectors.** The last three are pinned by vectors marked `modelOnly`, which a test checks the schemas accept. The cases
  the schemas reject too (year 0000; an integer of 2^53) are vectors marked `schemaAgrees`.

**`check_series(records, identities, registry)`** first checks every round with its identity, then:

| Code | Rule |
|---|---|
| `DUPLICATE_ROUND` | two records with one round number |
| `SERIES_GAP` | a missing round number, including a delta round whose earlier rounds are missing |
| `SERIES_FORK` | two rounds with one base, or a delta whose base is not the previous round's subject; a full round may follow any round |
| `DUPLICATE_IDENTITY` | two identities for one record, or one identity file reused |

A series runs from round 1 with no gap; a delta that is round 1 is SERIES_FORK. Design section 9's "one identity for two
records" cannot bind both, since an identity names one record by path and digest: the second record has no identity of
its own and is refused NO_IDENTITY, before DUPLICATE_IDENTITY is reached.

**Oracle identities:**
- `check_oracle(identity_bytes, identity_path, file_bytes)`: SHAPE, PLACEHOLDER_ID, then ORACLE_DIGEST (the file's
  bytes differ from the identity's digest, or the file is absent), NOT_INDEPENDENT (the oracle is the operator or an
  author, B-5), RULING (as for reviews) and PRIVACY.
- `check_pr_oracles(changed_paths, identities, read_bytes_at_head, contract_series)`: a PR with a CONTRACT series has at
  least one oracle identity, and every changed ORACLE_TESTS file (`tests/**/test_*oracle*.py`, MET-GOV-001's class)
  has an identity whose file digest matches at the head (ORACLE_MISSING, ORACLE_DIGEST). A deleted file counts as a
  changed path, with no bytes at the head (RR2C1-8).
- Only an ORACLE_AGENT fixes a defective oracle, under a new oracle identity, with the monitor's ruling; the candidate's
  author never edits the file.

**The merge** (the monitor's check, B-4): `check_merge(cited, registry, head, voided=())`.
- **The citations (RR2C1-1).** A merge-decision record cites every round of each cited head-bound series, from
  round 1, by path and sha256, record and identity alike.
- **The check:**
  - each cited series must pass `check_series`, which needs the rounds from 1 with no gap (head-less, since earlier
    rounds reviewed earlier trees);
  - its final round, the highest, must pass `check_review` against the head, with a passing verdict and a counting
    ruling. A passing round followed by CHANGES_REQUIRED does not count.
  - A cited record that cannot be read as a round (a string series and an integer round) refuses the whole merge
    with NO_HEAD_BOUND_ROUND (RR2C1-7, RR2C2-3).
  - A series that fails `check_series` counts for nothing. Without one counting series, it refuses NO_HEAD_BOUND_ROUND.
- **A VOID round** (Q-RR2-VOID (b), the monitor's ruling). A round ruled VOID stays on record, and `check_series` refuses
  it (RULING). So a series that holds a VOID round never counts for a merge, and a published one fails the in-suite
  check.
  - **Recovery always passes an owner gate.** The lane reruns under a new series id with a registry entry of its own,
    which is a registry change and so needs the owner's per-PR approval.
  - **Under a prefix entry** (Q-RR2-VOID-PREFIX (b), as corrected by contract r4, RR2C4-1). A prefix `X/` covers every
    series of packet X, since a series id has one slash. B-3 refuses an exact id beneath that prefix. So:
    - the rerun's entry uses another packet-id part (for example `X-R1/contract`, or a new prefix);
    - while any series under `X/` holds a VOID round, every series under `X/` counts for nothing until the registry
      changes. A pattern has one kind (B-3), so this stops that packet's series of that kind.
    - A series with an exact entry is under no prefix, so a voided series elsewhere never stops it.
  - **Enforcement.** The monitor enforces this at merge (MONITOR.md section 4): no cited series under a prefix entry
    counts while another series under that prefix holds a VOID round.
  - **The mechanical part:** `check_merge(cited, registry, head, voided)` takes a list of the series ids that hold a
    VOID round, which the monitor builds from its own and the owner's rulings. A cited series under a prefix counts
    for nothing while another series under that prefix is listed. Anything but a list or tuple of strings refuses the
    merge (RR2C4-3).
  - **Coverage:** every VOID ruling the monitor passes in. A VOID round is only ever made by such a ruling, so the
    list is complete when the monitor builds it from its decision records.
    - The in-suite check needs no part of it, since a published VOID round already fails there.
    - A VOID round kept only in local records never reaches the in-suite check, so the merge check is the only
      enforcement for it (RR2C4-4).
  - **A stricter question kept for the owner, if this proves fragile:** refuse prefix entries for CONTRACT, PACKET
    and PR series.
  - A later relaxation, for the owner if VOID rounds become common: `check_series` could accept VOID on a non-final
    round, which would never count. That would remove the owner gate on recovery, so it is not taken here.
- **Before each harness-onion merge the monitor also:**
  - checks the lane's record directory, so that no round after the cited final exists;
  - passes its VOID rulings to `check_merge` as `voided` (the VOID-prefix rule above);
  - reads an unpushed reviewed commit, such as a pre-squash commit, read-only from the lane's local repository;
  - runs `check_pr_oracles` and `check_tree` over the PR head's checkout (B-9).

**The tree** (`check_tree(root, legacy, registry, repository)`, the in-suite pre-check; it needs no git):
- **The registry.** Given as bytes, as the in-tree test gives it, or loaded, it holds no privacy hit (B-8, RR2C1-2).
- **Every `review-round*.json`** is on the frozen list with its digest, or else a v2 round, otherwise LEGACY_CHANGED. A
  v2 round is named `review-round<n>.json`, its `round` is n (otherwise SHAPE), and it is bound by the
  `review-identity-round<n>.json` beside it (otherwise NO_IDENTITY; RR2C1-6).
  - A frozen path whose bytes change, even into a valid v2 set, is LEGACY_CHANGED. So is a frozen record that is
    absent (RR2C1-8).
- **Series.** Each directory's v2 rounds pass `check_series`, with the repository given. A series id found in two
  directories is SERIES_FORK.
- **Oracle identities.** Every file whose name matches `ORACLE_NAME` (above) passes `check_oracle` with its file's
  bytes. That covers PRIVACY, and ORACLE_DIGEST when the file is absent. A malformed one is SHAPE.
- **Oracle tests.** Every ORACLE_TESTS file is on the frozen list with its current bytes' digest, or is bound by an
  oracle identity. A frozen oracle test that is absent is ORACLE_MISSING, and so is any other unbound one.
- **The walk.** `.git`, `__pycache__` and `.pytest_cache` are not walked. The check expects a clean checkout: an
  untracked file shaped like a record or an oracle test is judged too (RR2C1-11), as MET-GOV-001's coverage check
  judges untracked files.
- **Vectors.** The tree vectors (`trees` in `vectors.json`) are file maps that replay writes into a temporary
  directory.

## The frozen list (`legacy-review-records.json`)

`{schemaVersion, baseCommit, entries: [{path, sha256}], oracleTests: [{path, sha256}]}`. Both lists are sorted by path
and unique.
- Every review record that predates v2 is frozen by path and file digest, and stays as it is. The 155 records of the
  design's survey had become 169 at this packet's base, harness-onion 2043cc27, with 2 legacy oracle test files: the
  builder's own count line, for a list that the packet's lane copied in unopened (sha256 e33afcf6…).
- Oracle test files that predate v2 are frozen the same way, by path and file digest (design rev 4 B-9: the frozen
  list is a digest list). Any edit of one, a mechanical one included, needs an oracle identity written by an oracle
  agent. **Open question Q-RR2-FROZEN** (monitor, for the contract review): path-only freezing of legacy oracle files,
  or digest freezing with a lighter re-identity for mechanical bumps. The build keeps rev 4's stricter rule; anything
  weaker is a security trade-off for the owner.
  **Contract r1 recommended keeping it** (Q-RR2-FROZEN, monitor: settled at rev 4). A lighter re-identity would need a
  deterministic proof that a diff is only a mechanical re-pin, and it would still go to the owner.
- **How the list is built** (Q-RR2-LEGACY (c)): the list names files of every lane, so the lane that may read them all
  derives it at the packet's real base, using a deterministic builder.
  - The builder checks every path and digest against this contract's forms and refuses to write otherwise.
  - It prints counts and the file's sha256 only.
  - The packet's lane copies the file in unopened and checks its sha256.
  - Until the real list arrived, the file was a synthetic placeholder. Only `tests/test_review_records_in_tree.py`
    (run with the whole suite) depends on its contents.
- **Conditions** (contract r1, reading (d)):
  - the copied list is a gate-material change made after the contract review, so a delta contract round or the packet
    review covers it, with its sha256 checked;
  - it is rebuilt if anything merges between its build and this packet's slot.
- **Adoption impact** (contract r1 NOTE 13, for the owner's per-PR ask). From this packet's merge on, in every lane:
  - every new `review-round*.json` in harness-onion needs a v2 identity;
  - every new or edited `tests/**/test_*oracle*.py` needs an oracle identity written by an oracle agent;
  - otherwise the in-suite pre-check fails.

## Privacy

Owner decision Q-RR2-NAMES: "Load hashes locally (Recommended)". This narrows B-8 for the in-suite run:
- `NAME_TOKEN_SHA256` ships empty, because the sha256 of a short token is easily reversed. `load_name_tokens(path)` fills
  it from an unpublished local file, for the lanes' pre-push scans and the monitor's pre-merge check only.
- The in-suite PRIVACY check covers home-path shapes, e-mail shapes and the legacy term.
- No published file, vector or test holds a name token, its digest or a fragment of it. Vectors show name matching with
  made-up tokens, whose digests the row supplies (`tokenSha256`), and a test refuses any vector whose joined string
  parts form a privacy hit.
- PRIVACY scans a file's raw text and each of its parsed string values, so a JSON escape cannot hide a hit (RR2C1-10).

## Stated for the owner's per-PR ask (contract r1 NOTE 14)

- **B-2:** this packet's YAML copies the predecessor's acceptance commands (the 64 argv, unchanged), as every packet's
  chain mechanics do. No new argv: the new tests run inside the existing outer pytest argv (Q-RR2-4).
- **B-9's residual (D-2):** the in-suite pre-check is gate material, but a data-class `tests/conftest.py` fixture runs in
  the same pytest process and could interfere with it. MET-GOV-001 names the same residual for root-level test code.
  The monitor's own `check_tree` run over each PR head, before the merge, does not depend on the suite.
- **The oracle identities' `candidateCommit`** (45d818ee) is a work-in-progress commit that is squashed away and never
  pushed (owner direction). The monitor resolves it in the lane's local repository.
  - The oracle first ran against 9f88e824. Its scoped follow-up after contract r1 ran on the fix tree that became
    45d818ee, where the operator re-ran both oracle files before committing.
  - The oracle file is not expected to pass at earlier commits (contract r2 NOTE RR2C2-6).

## Merge-decision records and MONITOR.md section 4 (when this packet merges)

- `planeon.merge-decision/v1` is kept. v2 citations add optional members: identity {path, sha256}, kind, series and
  round. A v2 oracle identity is cited as {record: path, sha256, role: "ORACLE", candidateCommit}. A v2 citation's
  verdict equals the cited record's verdict exactly (B-7). Existing entries keep their form.
- **The citation duty (B-4, RR2C2-1).** The merge-decision record cites every round of each cited head-bound series,
  from round 1, by path and sha256, record and identity alike.
- **The standing authority's** "the independent review PASSed on the exact head" becomes `check_merge` passing, plus
  the monitor's own check:
  - `check_merge` runs `check_series` over each cited series;
  - then `check_review` of its final round against the head (the head or a commit with the head's tree), with a passing
    verdict and ruling NONE_NEEDED or KEEP;
  - separately, the monitor checks the lane's record directory, so that no round after the cited final exists
    (RR2C3-3);
  - and, for every cited series under a prefix entry, that no other series under that prefix holds a VOID round,
    passing its VOID rulings to `check_merge` as `voided` (Q-RR2-VOID-PREFIX (b), as corrected by RR2C4-1).
- D5a's "flag records without identity or brief digest" becomes `check_review` before each harness-onion merge.
- The gate list gains the four GATE_REVIEW_PROCESS entries below.
- R10 and R12 keep their current sidecars until they adopt v2 in their own packets.

## The evolution surface amendment (Q-RR2-6)

This packet makes version 2 of MET-GOV-001's record:
- A new programme class **GATE_REVIEW_PROCESS** (approve: OWNER), with four path entries:
  1. prefix `architecture/review-record/`
  2. exact `architecture/review-record-authority.json`
  3. exact `scripts/review_record.py`
  4. exact `tests/test_review_records_in_tree.py`
- GATE_REVIEW_BRIEF and GATE_REVIEW_RECORD gain the under-plus-name entries for `architecture/review-record/`.
- ORACLE_TESTS, REVIEW_RECORD and GATE_REVIEW_RECORD add GATE_REVIEW_PROCESS to `independentOf`.

The derived gate-material list grows from 27 to 31 entries: the four above. Every file of the checkout stays in exactly
one programme class.

## Not in scope

- Rewriting the legacy records.
- R10 and R12 adoption of v2.
- The verifier.
- DECISION-LEDGER-001.
- Any network use.
