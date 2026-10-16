# License-policy amendment LIC-HOST-A2: Zlib default-allowed (DATA_CHECK_ONLY)

Status: **CONTRACT_CANDIDATE_ROUND1_AWAITING_INDEPENDENT_REVIEW** (brief: `REVIEW_BRIEF.md`). 2026-10-16. Publication
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
| `vectors.json` | `planeon.internal.license-policy-amendment-vectors/v3`. It holds the A1 replay (the pinned A1 vectors and the exact list of A1 results that A2 changes, which is empty) and 25 cases, each with its expected A1 and A2 result |
| `../../scripts/license_amendment_v2.py` | `record`, `effective_policy` and `check`. A2 adds no classifier of its own: it builds A1's `Policy` with Zlib added to DEFAULT_ALLOWED |

## The rule

An additional default-allowed term is classified exactly as a term of the base's `defaultAllowedSpdx`:
- DEFAULT_ALLOWED for every component, kind and custody (L2-1 (a));
- A1's leaf order, election ranking, OR-choice, AND-term, legacy-slash and precedence rules apply unchanged;
- the base's release admission applies (DEFAULT_ALLOWED is an allowed final classification), and so do its requirements
  (SBOM, NOTICE).

`check` refuses an added term that is on any base list, or that is an A1 class term, decision or election. So no base or
A1 outcome of any other term changes. A compound listed exactly in the base keeps its base outcome.

Matching stays exact (`EXACT_SPDX_EXPRESSION`). Only the identifier `Zlib`, with that case, is added. `zlib`,
`Zlib-acknowledgement`, `Zlib+` and `Zlib WITH ...` stay UNKNOWN.

**What A2 changes, as the vectors show:**
- **Alone.** Zlib goes from UNKNOWN to DEFAULT_ALLOWED: as a crate, an artifact, the zlib host library, and a static
  library in a planeon binary. Default-allowed is not scoped like the A1 class.
- **OR.** An OR with a blocked alternative is accepted with Zlib elected ("Zlib OR SSPL-1.0", "Zlib/SSPL-1.0" as a legacy
  crate field).
- **AND.** "Zlib AND MIT" is accepted.
- **Election ranking.** For nft, "GPL-2.0-only OR Zlib" now elects Zlib rather than the approved review: default-allowed
  ranks before an approved review.
- **Unchanged.** Ties among default-allowed terms go by canonical text ("MIT OR Zlib" elects MIT), and Apache-2.0 is still
  elected first. A base denial is never weakened ("Zlib AND SSPL-1.0" is DENIED). A review requirement or an out-of-scope
  term elsewhere in an AND still blocks it.
- **Refusals.** The parser's refusals are unchanged.

**A1's own vectors.** All 88 replay under A2 to their A1 results. The one with a Zlib leaf ("MIT OR Zlib OR Apache-2.0"
for miniz_oxide) elects Apache-2.0 either way. `check` computes the changed list and requires it to equal the recorded
list, which is empty, and it requires every change to come through an added term.

## Effect on RA-LICENSE-001 (L2-2)

`architecture/research-adoption-v3/README.md` records Arize-ai/phoenix `packages/phoenix-sqlean/` as Zlib,
DENY_UNKNOWN_LICENSE, with ceiling DESIGN_REFERENCE_ONLY (note N-2).
- **Under A2,** that directory's expression classifies as DEFAULT_ALLOWED.
- **The research record stays byte-identical.** A later research-adoption revision re-runs its check and decides the
  ceiling.
- **Not changed by this record:** the scoped artifact or any reuse decision.

## Carried findings P2-F1 and P2-F2

These are 223 MET-ENFORCE-021's (LIC-HOST-F) packet-review round-2 NOTEs. Their only record is the author-side review
file, which is not published on main. So `amendment.json` quotes each one's finding and required change verbatim, with
the source (round, date, subject commit). The A2 layer of packet 242 carries both fixes; the dispositions are in
`amendment.json`:
- **P2-F1.** The layer's validator replays every A1 and A2 vector itself through `classify`, with a ValueError counted as
  REFUSED. Its decided cases include negative ones: an explicit-review term outside its decision's scope, a base denied
  term, an unknown term, and an open-content term outside ARTIFACT.
- **P2-F2.** The layer's verified-read helper checks era membership before it reads a path.

## Not claimed

- Nothing is released by this record, and it is not legal advice. The decisions above are the approving authority.
- No consumer of A1 is switched to A2 by this record. The license gates that classify with A1 adopt A2 in their own
  packets.
- The zlib licence's own conditions are obligations of any reuse:
  - the origin is not misrepresented;
  - altered source versions are plainly marked;
  - the notice stays in source distributions.

  The base's NOTICE requirement and per-blob porting records carry them. This record adds no other mechanism.
