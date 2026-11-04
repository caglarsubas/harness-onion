# Chain inheritance (MET-SECTOR-005, the R13 guard)

This directory extends the product-packet rule (`architecture/chain-product-packets/rule.json`, cited by digest and
clause in `rule.json`'s `extends`) with one refusal, R13: a product published at slot 278 or later keeps every
acceptance command of its repository's newest earlier packet. `architecture/chain-product-packets/` and
`scripts/chain_identity_v2.py` stay byte-identical (Q278-6 (b), MON-278-Q6-B); `scripts/chain_identity_v3.py` is the
model with R13. It pins v2 by the constant `V2_SHA256` and refuses a moved or changed v2 (`pin_v2`). The design is
CONTRACT_278 rev 4 in the lane's records; `rule.json`, `vectors.json` and this README state the contract.

## The records

- `rule.json`: the delta. `refusals` is `["R13"]`; `inheritance` holds the cut (`cutSlot` 278, a slot number), the
  comparator, the first-slot reading, the predicate, the pin, the newest-predecessor rule, the six steps and the known
  limit; `pFormsFromCut` holds F6' and F9; `model` names v3 and its v2 pin.
- `vectors.json`: the delta vectors only (no v2 vector is repeated): `inheritance`, `classForms` (on v2's bases, by
  reference), the v2 pin and the 273-277 equivalence.
- `decisions.md`: the rulings verbatim, the B-3 cost, the known debt and the known limit.

## R13

For every product listed at a slot S >= 278 (`PRODUCT_PACKETS`), in order; each refusal is clause `R13`:
1. every YAML in S's catalog view (first slot below S) has a readable `repository` line (the verifier's line rule):
   else "unreadable repository line";
2. the candidates are the earlier YAMLs naming the product's repository; none is a first packet (no pin allowed:
   "unexpected comparator pin");
3. the comparator is the one candidate in the newest first slot: two refuse ("ambiguous comparator"), the base too;
4. the layer's authority pins it in `productComparators`, checked in order: "missing comparator pin", "foreign
   comparator pin", "stale comparator pin", "comparator pin digest";
5. when the product lists predecessors, the newest one present equals the comparator: none present or a mismatch
   refuses ("comparator is not the newest predecessor"), a tie refuses ("ambiguous newest predecessor");
6. every comparator argv is in the product's list, byte-exact and in order, insertions allowed (the verifier's
   `require_inherits`): else "drops or reorders commands inherited from".

A YAML's first slot is the first layer whose catalog (`baselinePackets` | {`authorityPacket`} | `productPackets` of its
authority) holds it; the first layer's baseline is the base, older than every slot. Slots below 278 are not judged.

## The P-forms from the cut

A layer at slot 278 or later that binds `PRODUCT_PACKETS` writes v2's F1-F5 and F7, F6' in place of F6
(`"productPackets", "productComparators"` closing `authority`'s key set) and F9, the `productComparators` check, as the
statement right after F7; F7 and F9 are the two statements immediately before `authority`'s first `for`. Below the cut,
v2's F1-F7 are unchanged; a missing, misplaced, repeated or guarded F9, F6 from the cut, and F6' or F9 below it refuse
(clause `P-form`). `strip_products` takes the slot as a required keyword.

## A correction to v2's README (kept byte-identical)

v2's README lists R6 (a product YAML changed at a later slot) as head-only. The verifier's P0 also refuses it: a
harness-onion PR "must add task packets and change no other packet" (verify_pr f5d42215). A changed published product
is superseded by a new id (Q-VX45-6 (a)), as IND-BANK-002A supersedes IND-BANK-002.

## Where the rules apply

The live identity test in `tests/test_chain_compaction.py` runs v3 over the live chain from slot 278 (`check`,
`check_products`, `check_inheritance`), runs v2's vectors through v3 and v3's vectors beside them, and asserts the v2
pin and the 273-277 equivalence; argv 63 runs it at every later PR. The publishing head checks its own
`productComparators` (F9 and its semantic checks).
