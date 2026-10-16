# License-policy amendment LIC-HOST-A2: Zlib default-allowed (DATA_CHECK_ONLY)

Status: **CONTRACT_CANDIDATE_ROUND3_AWAITING_INDEPENDENT_REVIEW** (brief: `REVIEW_BRIEF.md`). 2026-10-16. Publication
slot 242 (LICENCE-POLICY-AMEND), after slot 241.

A2 makes the SPDX identifier `Zlib` default-allowed, everywhere and for every component, exactly as the base policy's own
`defaultAllowedSpdx` terms are. It is published as a second overlay, so these stay byte-identical:
- the base policy `legal/third-party-license-policy.yaml` (0.3.0). Records pin it by digest, and
  `scripts/validate_reuse.py` pins its version;
- the adopted amendment A1 `../license-policy-amendment/` (LIC-HOST-A1) and its classifier
  `scripts/license_amendment.py`. The 223 layer and later layers pin their bytes.

## Decisions

| ID | Date | Decision (verbatim) | Route |
|---|---|---|---|
| LIC-ZLIB | 2026-10-15 | "Monitor decision (owner-delegated), 2026-10-15: add Zlib to licence policy 0.3.0's allowed list in the next licence-layer packet, folding in LIC-HOST-F P2-F1/P2-F2; that resolves phoenix-sqlean's DENY_UNKNOWN_LICENSE (RA-LICENSE-001 note N-2)." | Lane monitor (owner-delegated); roadmap item LICENCE-POLICY-AMEND |
| L2-1 | 2026-10-16 | "L2-1 = (a): Zlib is default-allowed globally, like MIT. It's OSI-approved, permissive and Apache-compatible, matching the decided "allowed list"." | Lane monitor (owner-delegated), cross-session message |
| L2-2 | 2026-10-16 | "L2-2 = (a): A2 states the effect on phoenix-sqlean. RA-LICENSE-001's record stays byte-identical, and a later adoption revision re-runs the check." | Lane monitor (owner-delegated), cross-session message |

`amendment.json` carries each decision's verbatim text and route.

## Files

| File | Content |
|---|---|
| `amendment.json` | `planeon.internal.license-policy-amendment/v2`. It holds: the base pin; the A1 pins (record, vectors, classifier, by SHA-256); the three decisions; `additionalDefaultAllowedSpdx: ["Zlib"]` and its rule; the phoenix-sqlean effect; the carried findings P2-F1 and P2-F2, verbatim with their source; and non-claims |
| `vectors.json` | `planeon.internal.license-policy-amendment-vectors/v3`. It holds the A1 replay (the pinned A1 vectors and the exact list of A1 results that A2 changes, which is empty) and 34 cases, each with its expected A1 and A2 result |
| `../../scripts/license_amendment_v2.py` | `record`, `effective_policy` and `check`. A2 adds no classifier of its own: it builds A1's `Policy` with Zlib added to DEFAULT_ALLOWED |

## The rule

An additional default-allowed term is classified exactly as a term of the base's `defaultAllowedSpdx`:
- DEFAULT_ALLOWED for every component, kind and custody (L2-1 (a));
- A1's leaf order, election ranking, OR-choice, AND-term, legacy-slash and precedence rules apply unchanged;
- the base's release admission applies (DEFAULT_ALLOWED is an allowed final classification), and so do its requirements
  (SBOM, NOTICE).

`check` refuses an added term that is on any base list, or that is an A1 class term, decision or election. So no base or
A1 outcome of any other term changes. A compound listed exactly in the base keeps its base outcome.

Matching stays exact (`EXACT_SPDX_EXPRESSION`). Only the identifier `Zlib`, in the SPDX list's spelling, is added, and
A2 adds no case normalisation.
- SPDX itself matches identifiers case-insensitively, but the base does not. So `zlib` stays UNKNOWN.
- `zlib-acknowledgement` (another SPDX identifier), `Zlib+` and `Zlib WITH <exception>` are other terms, and they stay
  UNKNOWN.

**What A2 changes, as the vectors show:**
- **Alone.** Zlib goes from UNKNOWN to DEFAULT_ALLOWED in every component kind and every base custody. The cases
  include the zlib host library and a static library in a planeon binary. Default-allowed is not scoped like the A1
  class. `check` requires a case for each kind and custody.
- **OR.** An OR with a blocked alternative is accepted with Zlib elected. Examples: "Zlib OR SSPL-1.0", "Zlib/SSPL-1.0"
  as a legacy crate field, and "GPL-3.0-only OR Zlib", which was OPTIONAL_EXPLICIT_REVIEW.
- **AND.** "Zlib AND MIT" is accepted.
- **Election ranking.** A1's ranking puts default-allowed before every other accepted category, so Zlib is now elected
  over:
  - an allowed exception expression ("Apache-2.0 WITH LLVM-exception OR Zlib");
  - open content ("CC0-1.0 OR Zlib" for an artifact);
  - the A1 host-OS class ("LGPL-2.1-or-later OR Zlib" for glibc);
  - an approved review ("GPL-2.0-only OR Zlib" for nft).
- **Unchanged.** Ties among default-allowed terms go by canonical text ("MIT OR Zlib" elects MIT), and Apache-2.0 is still
  elected first. A base denial is never weakened ("Zlib AND SSPL-1.0" is DENIED). A review requirement or an out-of-scope
  term elsewhere in an AND still blocks it.
- **Refusals.** The parser's refusals are unchanged.

**A1's own vectors.** All 88 replay under A2 to their A1 results. The one with a Zlib leaf ("MIT OR Zlib OR Apache-2.0"
for miniz_oxide) elects Apache-2.0 either way. `check` computes the changed list and requires it to equal the recorded
list, which is empty. It also requires every changed case to contain the exact added term. A WITH term counts whole, so
"Zlib WITH LLVM-exception" is not the term Zlib, and a change to REFUSED is not exempt.

## Effect on RA-LICENSE-001 (L2-2)

`architecture/research-adoption-v3/README.md` records Arize-ai/phoenix `packages/phoenix-sqlean/` as Zlib,
DENY_UNKNOWN_LICENSE, with ceiling DESIGN_REFERENCE_ONLY (note N-2).
- **Under A2,** that directory's expression classifies as DEFAULT_ALLOWED.
- **The research record stays byte-identical.** A later research-adoption revision re-runs its check and decides the
  ceiling.
- **That revision must classify with A2.** The research-adoption model (`scripts/research_adoption_v3.py`) reads the base
  policy's lists directly, not through A1 or A2. Re-running it as it stands would still give DENY_UNKNOWN_LICENSE.
- **Not changed by this record:** the scoped artifact or any reuse decision.

## Carried findings P2-F1 and P2-F2

These are 223 MET-ENFORCE-021's (LIC-HOST-F) packet-review round-2 NOTEs. Their only record is the author-side review
file, which is not published on main. So `amendment.json` quotes each one's finding and required change verbatim, with
the source (round, date, subject commit). Both fixes are to be carried into packet 242's A2 layer
(`validate_license_amendment_v2.py`), which is not written yet, and the 242 packet review checks them. The dispositions
are in `amendment.json`:
- **P2-F1.** The layer's validator will replay every A1 and A2 vector itself through `classify`, with a ValueError counted
  as REFUSED. Its decided cases will include negative ones: an explicit-review term outside its decision's scope, a base
  denied term, an unknown term, and an open-content term outside ARTIFACT.
- **P2-F2.** The layer's verified-read helper will check era membership before it reads a path.

`check` memoises its reader per path. So A1's own check, A2's pins and A2's replay all see the same bytes of each path,
each read once. It also requires the A1 classifier it imports to be the pinned file.

Three items are carried to packet 242's layer:
- pinning that classifier's import closure (`safe_yaml.py`);
- routing the classifier identity check, which reads the module's own file, through the layer's verified reads (review
  LR2-4);
- P2-F1 and P2-F2 above.

## Not claimed

- Nothing is released by this record, and it is not legal advice. The decisions above are the approving authority.
- No consumer is switched to A2 by this record. The license gates that classify with A1 adopt A2 in their own packets.
- Consumers that read the base policy's lists directly, for example `scripts/research_adoption_v3.py`, keep Zlib UNKNOWN
  until they classify with A2.
- The zlib licence's own conditions are obligations of any reuse:
  - the origin is not misrepresented;
  - altered source versions are plainly marked;
  - the notice stays in source distributions.

  The base's NOTICE requirement and per-blob porting records carry them. This record adds no other mechanism.

## Round-1 findings and dispositions

| Finding | Disposition |
|---|---|
| LR1-1 MINOR, kinds and custodies | Zlib alone is DEFAULT_ALLOWED in cases for all 8 kinds and all 4 base custodies, and `check` requires that coverage |
| LR1-2 MINOR, consumers of the base | The README and the non-claims say that the research model reads the base directly, that the later revision must classify with A2, and that direct base readers keep Zlib UNKNOWN until then |
| LR1-3 MINOR, inexact change check | Terms are compared whole (a WITH term is not its base licence), and the REFUSED exemption is removed. A simulated drift that allows "Zlib WITH LLVM-exception" is refused |
| LR1-4 NOTE, reads and the running classifier | The reader is memoised per path, so every path is read once and A1's check, A2's pins and the replay share those bytes (answered fully in round 2, LR2-2). The imported A1 classifier must equal the pinned bytes. The packet layer pins the import closure and verifies every read |
| LR1-5 NOTE, other election changes | Cases and README cover Zlib elected over an exception expression, open content and the A1 class, and "GPL-3.0-only OR Zlib" |
| LR1-6 NOTE, SPDX case | The README and the rule state that SPDX matching is case-insensitive while the base is exact. The near-miss case uses `zlib-acknowledgement` |
| LR1-7 NOTE, dispositions | Both dispositions are in the future tense and name the 242 packet review as the check |
| LR1-8 NOTE, author-side paths | The brief no longer names author-side paths |

## Round-2 findings and dispositions

| Finding | Disposition |
|---|---|
| LR2-1 MINOR, normalisation clause | Removed. A2 adds no case normalisation, and matching stays exact |
| LR2-2 MINOR, reads | `check` memoises its reader per path (`_once`), so A1's check and A2's pins and replay see the same bytes, each path read once |
| LR2-3 NOTE, change guard | The README says what the guard checks: every changed case contains the exact added term |
| LR2-4 NOTE, classifier identity read | Carried to packet 242's layer, next to P2-F1 and P2-F2 |
| LR2-5 NOTE, a compound with Zlib for gmp | No change. This is A1's rule, and any base default-allowed term behaves the same way |
