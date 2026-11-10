# The era-replay reader (xi): the ruling (verbatim)

The visionary's ruling Q-286-IDENTITY, under the owner's delegation (MON-286-IDENTITY-V4), copied by script
from visionary/DESIGN-286-READ.md (sha256 0d47b20d4c9c8abeaa89a56f8bc8f250c8802b95a168447c7c50ecf058eee971), section 6, between its heading and the next heading.

## 6. Addendum (2026-11-10): Q-286-IDENTITY, the in-repo identity rule and form (xi)

Facts read at main 0fd885ff: v1's item 6 (`check_step`) closes the old head's edits with `edits == expected` over
(vi)-(x) and the four LIFT_SITES, so no existing lift site can carry `_replay`'s read and a fifth lift would be refused
exactly as the rename is. The sealed layers run their models over their own eras (255 runs v1 through `_era_source` /
`_undo_this_layer`; 274 and 284 run v2), so only the live test `test_identity_rule_holds_on_the_live_chain` (v3 over
`regular_bytes` with the head's one-step projection) sees 285's bridge. CONTRACT_286 r4 already requires the behaviour
(C8: the inherited A5 reads briefs.json through its era projection, never the live bytes); the model lacks the clause.

Ruling: **option (1) in the v2/v3 shape**, a fourth model version, not an amendment; **ruled under the owner's
delegation, not owner-level** (FYI in the morning). Precedent: v3 (MON-278-Q6-B, "ruled under the owner's delegation;
no roadmap shift") extended v2 "without changing v2", pinned v2 by a sha256 constant, and cited its decisions.md as the
rule's evidence record. v2's owner decision (Q-SEC3-TWO) was owed to a new vocabulary of product packets; (xi) adds no
new object, it realises MA008-P1-3, a note the owner accepted at lock 48, and C8, a clause of the contract in force.
Supersession of 285's A5 by 286's validator is rejected on principle: item 6 exists so that no successor can switch off
a sealed layer's check; era projection is the one lawful reading, and (xi) is that projection. Options (2) and (4)
rejected as the monitor states; (3) cannot reach the era model.

Conditions:
- C-I1 `scripts/chain_identity_v4.py` extends v3 by one step clause and nothing else: v1-v3 byte-identical, v4 pins v3
  by a sha256 constant (`pin_v3`, v3's `pin_v2` form), refuses a moved v3; one equivalence vector (v4 = v3 on a chain
  whose old head holds no reader).
- C-I2 Form (xi) in v4 as strictbridge_v2 has it: when the old head's previous-era `_replay` holds `.check(regular_bytes(`,
  the current must hold `.check(reviewed_bytes(` at that one position, direction fixed, every other node of `_replay`
  equal; required (a live-reading bridged `_replay` refuses); absent reader = (xi) 0. Older bridged layers show no
  difference, since both eras hold reviewed.
- C-I3 Implementation shape: v4 verifies (xi) on the parallel AST walk of the old head alone, then delegates to v3 with
  the old head's current bytes undone (the one token, counted 1) so v1's `edits == expected` holds unchanged. The
  projection is computed from the TRUE live bytes: v1 and v3 call `previous(path, source)` with the source they read, so
  v4 wraps `previous` for that path to project the live bytes, never the undone ones (the head's reverse hunks were
  recorded against the live file). Pins (ERA_SHA256, MODEL, IDENTITY_RULE) keep hashing the live files.
- C-I4 Record dir in the precedents' shape, `architecture/chain-era-replay/{README.md, decisions.md, rule.json,
  vectors.json}`: rule.json extends chain-inheritance/rule.json by path, sha256 and clause with the delta only; its
  evidence record is decisions.md holding this ruling verbatim as the monitor relays it; vectors: positive (286's
  bridge), negative (reader present and no lift; reverse direction; second occurrence; rename outside `_replay`; a
  `.check(` callee other than the two names), plus C-I1's equivalence vector.
- C-I5 The live test moves to v4 (`_v4()` after `_v3()`'s form, V3's digest in the pinned list); v3 stays referenced by
  its records, the oracle and v4's pin, nothing else. 286's packet YAML gains the new paths; v1-v3 stay excluded.
- C-I6 Contract r5: C8 gains "lawful under identity model v4 (xi)"; the chainmech form (xi) (§5) and v4's clause are the
  same text, cross-cited. Lock 49 records v4 + form (xi) on CHAIN-COMPACTION-002 (MET-PERF-049's packet) and the
  MA008-P1-3 first case on AUTHORITY-MAP-001, with the strictbridge, bridge_test2, v4 and rule.json digests.

Scope and timeline: 286 grows by one model file (~v3's size or less), one record dir, the test switch and the YAML
paths; one more R00 build round and one verify (about 1,100 s at argv 63), roughly a day. The worker trial (OQ-286-A)
is independent and still waits for the quiet window. 048 at 299 is unchanged: the lab's condition counts slots after
the 296 rewrite, not days; MET-PERF-049 stays 286's id. No split of 286 (it would move the rewrite to 297 and 048 to
300, an owner re-ruling for no gain).
