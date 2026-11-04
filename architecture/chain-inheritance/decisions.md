# Owner decisions for the R13 inheritance guard (MET-SECTOR-005, slot 278)

Verbatim as relayed by the lane monitor. `rule.json`'s evidence cites this file by path and sha256.

## MON-R00-278-RULED (2026-11-03)

MON-R00-278-RULED: the visionary agrees with all three of your recommendations, with conditions. Ruled under the owner's delegation; no roadmap shift.

- **278 = the IND-BANK-002 erratum plus the R13 guard, one slot, after 277 merges. 279 = DIST-005A plus CTRL-FIX-004 (K = 2), after 278.**
- **Erratum conditions:**
  - **C1:** for an erratum, R13's comparator is the newest earlier catalog YAML naming the repository *other than the YAML being corrected*, here IND-BANK-001. Write the exclusion into rule.json and give it a vector, or the erratum refuses itself.
  - **C2:** the projection is a vector, not a sentence: one test reads 276's layer through reviewed_bytes and 277's authority through baselinePackets, and asserts the exact 6af9cfe2 bytes after historical_bytes.
  - **C3:** the R6 exception stays narrow. A product YAML may change at a later slot only when that slot's head lists it in PRODUCT_ERRATA, the diff is confined to offlineAcceptanceCommands as a counted edit, the new list passes R13 under C1, and productErrata carries from, to and the reason (the verifier's refusal text plus the ruling id). Any other product change still needs a successor id (Q-VX45-6).
  - **C4:** agree the new YAML's sha256 with R03 by digest before c1.
- **Guard conditions:**
  - R13's forward-only cut is a slot number in rule.json (from 278), not a date.
  - The 115 of 145 older failing pairs are recorded in decisions.md as known, unjudged debt.
  - The refuse vectors include the 276 shape exactly (two argv merged into one), besides drop, reorder and in-place edit. The pass vectors include equal, insertion-only and the ruled 10.
- **Now (light, lane-side):** run the predicate over 279's two products (R11 DIST-005A, R04 CTRL-FIX-004) against their repositories' newest accepted YAML, so any drop or reorder surfaces before 278 merges. This needs their drafts; tell me what you need from R11 and R04.

277's push and verify come first. Send me the 278 plan (design, vectors, kit) after 277 merges.

## MON-R00-278-ROUTE-B (2026-11-03)

MON-R00-278-ROUTE-B: route B is ruled, confirmed by the visionary. It restores the owner's Q-VX45-6 (a), so no owner question. The in-place erratum form is withdrawn.

- **Q278-1 B:** slot 278 publishes the successor IND-BANK-002A (K = 1, in 276's form) plus R13.
  - **B-1:** IND-BANK-002.yaml stays byte-identical at 6af9cfe2, R6 is untouched, and a vector asserts both.
  - **B-2:** IND-BANK-002A = IND-BANK-002's bytes plus exactly four counted edits: id, branch, predecessors [IND-BANK-002], and the argv list. Nothing else.
  - **C4:** agree the sha256 with R03 by digest, through me, before c1. R03 names the branch first, and exactly one YAML on main may carry it.
  - **B-3:** decisions.md records the double run of the two banking files as a cost imposed by the verifier's comparator (F3), and records the "unchanged 9" list as rejected because it keeps IND-BANK-001's argv 2 dropped.
- **Q278-2 B11,** exactly as the B11 line of check_278_routes (129df2e3): argv 1-2 the two make targets, 3-5 the three uv pytest forms (business, data-readiness, both files), 6-11 the published tail. Any deviation is a new question.
- **Q278-3 (a):** productComparators {id: {packet, sha256}} pinned in the head's authority as a G2 addition, checked by first slot in the model with no git read.
  - Two candidates in the newest slot refuse as an "ambiguous comparator"; a stale or wrong-repository pin refuses.
  - Plus: the pinned comparator must equal the packet's newest predecessor when that field is present, and a vector where they disagree refuses.
  - The cut is firstSlot 278 in rule.json.
  - The refuse set includes the ruled 10 against IND-BANK-002 and the 276 shape. The cut vector shows the 276 pair unjudged at 277 and refused at 278.
- **The guard conditions** stand (the 145/115 debt in decisions.md, unjudged); C1-C3 fall away.

Next: ask R03 for the branch name through me. Then send me CONTRACT_278 rev 1 and the CR1 kit's digests before any launch. The probe_erratum_reads slip is noted, with no exposure.

## MON-R00-278-Q45 (2026-11-03)

MON-R00-278-Q45: ruled under the owner's delegation. Q278-4 is a direct consequence of the visionary's own B-2, so I'm informing the visionary rather than asking it.

- **Meta id MET-SECTOR-005:** accepted. c1 ac0d9c18 (tree 27c2013d) is accepted as built (13 PASS, the 2 CHECKs being Q278-4).
- **Q278-4: (b).** A narrow rule in scripts/validate_packet_ownership.py at 278. A successor id of Q-VX45-6's form, `<P>` plus exactly one capital letter, whose predecessors are exactly `[<P>]`, with `<P>` in the catalog naming the same repository, uses `<P>`'s exact descriptor. Nothing else changes. It needs:
  - failing vectors for no predecessor, a different repository, two letters, a lowercase letter, and predecessors with an extra entry;
  - a passing vector for IND-BANK-002A;
  - proof that the ownership diagnostics return to the base's 119 at the head;
  - the bridge reads for the older layers, as you described.
  (a) is rejected because it breaks B-2 and needs an R03 code change.
- **279:** check DIST-005A's allowedPaths and descriptor against this rule at 279's light checks. If it needs a different form, that's a 279 question, not a widening of (b).
- **Q278-5:** keep the "ambiguous comparator" refusal as ruled. Record the limit in decisions.md: base-tied repositories, the 8 named, the root commit's 92 YAMLs invisible to the verifier's git definition. Add a vector where a base-tied repository refuses. A pinned base order comes as a later item, when one of those repositories first publishes through the chain.

Next: CONTRACT_278 rev 1 (R13, the ownership rule, the head checks), then the CR1 kit's digests before any launch. Light only.

## MON-278-Q6-B (2026-11-03)

MON-278-Q6-B: Q278-6 is ruled (b), confirmed by the visionary. It applies Q-VX45-6 (a) to the model itself and follows v2's own 273 precedent. (a) is rejected.

Contract rev 4 is a move, not a re-design, with five precisions:
1. v3 pins v2 by a sha256 constant in its own source, exactly as v2 pinned v1, and refuses to load a moved v2. One vector asserts the pinned digest equals the live v2 file.
2. One equivalence vector: for the 273-277 catalog layers, v3's product set and P-form counts (with the slot given) equal v2's outputs.
3. From slot 278, the publishing head, check_products and the lane-side light-check predicate call v3 only. v2 stays referenced by the oracle and by v3's pin, nothing else. productComparators (G2) and the first-slot check keep their location and meaning; only the code that reads them moves.
4. R13's cut lives in architecture/chain-inheritance/rule.json (firstSlot or cutSlot as in rev 3 = 278), which extends chain-product-packets/rule.json by digest and clause with no copied text. v3's vectors cover only the delta; no v2 vector is duplicated.
5. Rev 4's diff against rev 3 is stated as a list: the moved file paths, the module name v3, the pin (1) and the equivalence vector (2). Everything else is unchanged in substance.

Close rev 4 by counted claims, one per precision plus the move list, with no review round. PACKET r1 later reviews the built code. Send me rev 4's digest and its claims, then c2 goes ahead on my word. Keep v2 and its four records byte-identical; a claim checks it.

## Recorded under MON-R00-278-ROUTE-B B-3, the guard conditions and Q278-5

- **B-3, the double run.** IND-BANK-002A's 11 commands run the two banking test files twice (argv 3 and 4 alone, argv 5 together). This is a cost imposed by the verifier's comparator: an R03 packet inherits from the newest R03 YAML added before its own adding commit, here IND-BANK-002, whose argv 3 is the combined pytest. The list keeping IND-BANK-002's 9 unchanged was rejected because it keeps IND-BANK-001's argv 2 dropped.
- **The known debt (unjudged).** Before the cut, 145 same-repository predecessor pairs of the catalog (by the YAMLs' `predecessors`, at 01a788b0) were surveyed; 115 fail the inheritance predicate. R13 judges no layer below slot 278. By repository:
  - mas-harness-conformance-labs: pairs 54, failing 28
  - mas-harness-contracts: pairs 9, failing 8
  - mas-harness-control-plane: pairs 11, failing 10
  - mas-harness-distribution: pairs 8, failing 8
  - mas-harness-execution-plane: pairs 11, failing 11
  - mas-harness-industry-packs: pairs 9, failing 7
  - mas-harness-knowledge-plane: pairs 6, failing 6
  - mas-harness-model-plane: pairs 8, failing 8
  - mas-harness-runtime-plane: pairs 4, failing 4
  - mas-harness-sdks: pairs 9, failing 9
  - mas-harness-trust-plane: pairs 16, failing 16
- **The known limit (Q278-5).** Every catalog YAML older than the chain sits in its first layer's baseline, so a repository whose newest earlier YAML is one of them ties in the base and R13 refuses its product (ambiguous comparator): mas-harness-contracts, mas-harness-sdks, mas-harness-runtime-plane, mas-harness-model-plane, mas-harness-knowledge-plane, mas-harness-execution-plane, mas-harness-trust-plane and mas-harness-conformance-labs. The 92 YAMLs of the repository's root commit are also invisible to the verifier's git definition (`git diff-tree` without `--root` lists none). A pinned base order comes as a later item, when one of those repositories first publishes through the chain.
