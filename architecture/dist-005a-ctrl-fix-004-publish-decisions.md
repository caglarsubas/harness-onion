# MET-VERIFY-006 decisions (slot 279: DIST-005A and CTRL-FIX-004, K = 2)

This record holds the slot-279 decisions CONTRACT_279 section 7 names (erratum 2, MON-279-DEC). It sits beside
the head's authority, `architecture/dist-005a-ctrl-fix-004-publish-authority.json`, which pins it as a new file;
`architecture/chain-inheritance/` and its v3 records stay byte-identical. Each ruling below is the lane monitor's
owner-delegated ruling, verbatim as relayed.

## MON-279-OWN2

```text
MON-279-OWN2: ruled (ii)+(vi), on the visionary's reading ede04b08 (11,504 B). It is a packet-level decision, not a roadmap shift.
- DIST-005A keeps predecessors [DIST-TRANSPORT-001], R11's draft E3 as written. No edit to R11's draft for this.
- One exact-pair supersession closer at the 279 head, in the form 275 and the conformance layers use, for exactly 20 pairs:
  - 12 CTRL-FIX-004 × CTRL-INTEGRATE-001;
  - 8 DIST-005A × DIST-005.
  Each pair is keyed by both packets' id + sha256, with the reason: the superseded id under Q-VX45-6 (a) and its successor.
- The live count stays 119. There is no era bridge at the four V4 sites (276's and 278's validators and tests). 279's V4 asserts 119 and "closes exactly these 20 pairs", enumerated.
- (i) is dropped, and C-OWN-1 and C-OWN-3 stop. C-OWN-2 still holds: DIST-005A's pinned comparator is DIST-TRANSPORT-001, and it names its own ci/targets/dist-005a.json.
Conditions:
- CL-1: a vector shows the generic check still fires for any pair outside the 20 (the conformance test's property, run at 279).
- CL-2: list the closer's readers by script before the pin (MON-COUNT-CALLERS form). None may widen beyond exact pairs.
- CL-3: the 20-pair list is agreed with R04 and R11 by digest before c1. Send me the list's digest and I'll relay it.
- CL-4: the closer carries no predecessor semantics. It must not say CTRL-FIX-004 supersedes CTRL-INTEGRATE-001. VERIFIER-EXT-R04-R11's record stays unchanged.
- Gate: state the closer's path in CONTRACT_279. The gate derivation settles by count whether it is gate material (the evolution-surface prefixes); don't assume it.
Roadmap clauses come at lock 28, not now. Go ahead with the contract's ownership section.
```

## MON-279-OWN2-P1

```text
MON-279-OWN2-P1: P1 is ruled. The visionary confirmed it and corrected its note (87ee277f, 13,474 B, checked).
- The closer is the new outermost closer in validate_dispatch_ownership, defined in scripts/validate_met_verify_006.py, around 275's close_bootstrap_transport_dispatch.
- 279's V4 asserts:
  - raw count 139 = 119 + exactly the 20 pairs of list 3a8bb9f8;
  - the dispatch chain closes exactly these 20 and nothing else (CL-1 lands here);
  - dispatch-closed 0.
- Era bridges go at 276's and 278's V4 tests only: 2 sites, each fed its era's catalog, moved with the MON-COUNT-CALLERS scan. The validators' pure check_ownership is unchanged. The mutant counts (unordered_sibling) are bridged the same way.
- The standard projection applies to the changed pinned chain file, as at 275.
- P2 is rejected. CL-2 and CL-4 are unchanged.
- The gate derivation decides by count whether validate_met_verify_006.py and validate_conformance_reference_measurement.py are gate material.
CL-3: R04 says AGREE.
- Digest 3a8bb9f8 matches.
- The 12 overlap paths equal its 13 allowedPaths minus ci/targets/ctrl-fix-004.json.
- CTRL-FIX-004's sha256 is e20bde78 in all 12 pairs; CTRL-INTEGRATE-001's 28441f4f equals the YAML at 01a788b0.
- The 12 reasons share one form, and none names CTRL-FIX-004. All 20 messages are unique.
R11's AGREE is pending. You may write the contract's ownership section now. c1 waits for R11's AGREE.
```

## MON-279-P1-SITES

```text
MON-279-P1-SITES: I checked independently: identity 34fec4ea (KEEP), scan count_sites_279.out de81390d, pair list 00e80307. Against d284b243 the list's pairs are equal; only noPredecessorSemantics differs.

P1's site handling is re-ruled on the scan:
- 4 conformance RAW-COUNT tests take 275's own form, hand bumps 119 → 139: consumer_closure, performance_followup, reference_measurement exact72 and successor_checkpoint. Their dispatch == [] assertions stay.
- 3 conformance FIXED-LIST tests take 275's form too. Add the two pair strings "CTRL-FIX-004 and CTRL-INTEGRATE-001" and "DIST-005 and DIST-005A" to each allowed list.
  - The substring match must cover exactly the 20 messages and nothing else. Add a check that each string matches only its own pairs' messages in the live raw output, 12 and 8.
- 2 V4 tests (276 and 278): era-bridged, as ruled.
- 2 DISPATCH-ONLY tests: the standard cascade, 283 → 286 catalog count. Their dispatch stays [], confirmed in the targeted run.
- met_sector_003 V4 and the OTHER group are expected unaffected; the light run executes them to confirm.
- Each edited pinned test file gets the standard projection, counted by count_callers at the mechanics.
Total: 9 edited test sites plus 2 bridges, plus the cascade. The contract states these counts and backs them with a claims check.

GO for CONTRACT_279 rev 3 with all the items you listed, plus r2's rules with L2's OP-* wording fixed. Then build the CR2 delta kit (base = rev 2's subject) and send me its digests before launch.
I'm asking R04 and R11 now to re-AGREE 00e80307. CR2 can launch before their answer; c1 waits for it.
```

## MON-279-C1-SCOPE

```text
MON-279-C1-SCOPE: c1 takes 278's form, 4 paths, as you recommend.
I checked: make_c1_279 b1a42742, check_c1_279 d4e778f6, sim.out 4cd31e2c (CHECK_C1 9/9 PASS), 0 home paths.
- The meta YAML MET-VERIFY-006 and this repository's plan item come with the mechanics. The real-meta ownership count (expected 139, none naming MET-VERIFY-006) moves to the mechanics' light checks; c1 keeps the proxy count (check 8).
- Write a counted erratum to rev 5 section 8 step 1 and to the c1 phrase claim 37 checks:
  - record it in decisions.md as MON-279-C1-SCOPE;
  - re-run the claims, all passing;
  - send me the new contract digest and the claims result.
  PACKET r1's check 0 sees the erratum. The contract series stays at CR3 KEEP.
- No provisional meta YAML at c1.
GO for `make_c1_279.py <worktree> <drafts> --commit`: the local commit plus the backup ref scratch/met-verify-006-c1-<sha>. Then check_c1_279 on a git-archive export of c1. Send me c1's sha and tree and the check output digest.
Your context is about 78%. Keep the RESUME block current after the commit.
```

## The exact-pair list

The closer's list (CL-3, agreed by R04 and R11 in MON-279-CL3-CLOSED-2) has sha256
`00e80307ec3e5336d1ebb3843eaa5af75b5db8b76e08687821e00be930fca46f`: 20 pairs, 12 CTRL-FIX-004 x CTRL-INTEGRATE-001 and 8
DIST-005 x DIST-005A, each keyed by both packets' id and sha256. The head's authority pins the pairs record by
sha256 in newFiles.

## Known debt

At the base `afee03b93da691cb113da495e3be7e39695756aa`, `validate_packet_ownership` returns 119 diagnostics on the
catalog: 118 unordered same-repository overlaps and 1 product-packet overlap with a bootstrap correction. The
dispatch chain closes all 119. They stay known debt, unchanged by this step. The two products add exactly the 20
listed messages (139), and the closer removes exactly those 20.

## R04's read findings (MON-279-R04-DRAFT)

```text
- R04's read findings:
  - (a) ui-source.test.ts:11-17,29 requires createFixtureProjectionSet in the joined route sources; overview/page.tsx and organizations/page.tsx keep it.
  - (b) No existing test pins the 4 deleted loading.tsx files; accessibility-source.test.ts pins only the questionnaires, demands and profiles ones, which stay.
```

## R11's E5 question and its answer

```text
- R11's open question: is E5's wording right, and should its exact-base sentence name the descriptor's targets as DIST-TRANSPORT-001 did? Settle it in CONTRACT_279 and CR1. If it needs a change, send me the exact counted edit and I'll relay it to R11.
```

Answer (MON-279-CR1-RULINGS 6), verbatim:

```text
6. Q3, κ: adopt the reviewer's refinement. Anchors are byte-identical at 276 and the head and untouched by 279; per-anchor ratios are reported; use the median if the spread is above ±10 %. Q1: E5, no edit. Q4: both plan lines stand.
```
