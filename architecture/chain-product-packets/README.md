# Chain product packets (MET-PERF-044, CHAIN-PRODUCT-PUBLISH-001)

This directory extends the history chain's identity rule (`architecture/chain-compaction/identity-rule.json`, cited by
digest in `rule.json`'s `extends`) with a pinned product-packet list: a slot may publish K >= 1 product packet YAMLs
beside its own meta packet (owner Q-SEC3-TWO, `decisions.md`). `identity-rule.json` and `scripts/chain_identity.py`
stay byte-identical; `scripts/chain_identity_v2.py` is the model with the product parameter. The design is the lane's
CHAIN-PRODUCT-PUBLISH-001 note with errata E1, sha256
`c7f0946e535fae29e29b3aaddb0ea9356f9735ec799546c165e201309019527e`; it is not in this repository, and this README,
`rule.json` and `vectors.json` state the contract.

## The records

- `rule.json`: the vocabulary. `counts` defines S (the head's slot), C (the catalog count) and P (the sum of K over
  every layer that binds `PRODUCT_PACKETS`), with C = S + P. `nReading` reads N as C in (i), (ii) and (x) and as S in
  (iii) (d = S - L) and (v) (L = S - 2). A publishing step adds (i-p)-(v-p), (ix-p) and (x-p); D, G1 and G2 take the
  product list as their one new parameter. `productId`, `productRepository` (the verifier's line rule, the twelve
  allowed names of `architecture/repositories.yaml` at dd000fef, the refused name) and `chainOnly` (R12) define a
  product. `allowedPaths` is the one list the builder, the head and the verifier share.
- `vectors.json`: every case of the design's section 5 (below).
- `decisions.md`: the owner's Q-SEC3-TWO and Q-CPP-2, verbatim.

## The accepted P-forms

A layer that binds `PRODUCT_PACKETS` writes each fragment below in the class function named, exactly once; a layer
that binds none writes none. The model undoes each by its exact inverse (matched as a whole expression by its AST,
positions ignored) before D, G1 and G2 compare, as v1 compares them.

- **F1**, `historical_catalog` (D): `set(packets) == current_ids | set(PRODUCT_PACKETS)`, undone to
  `set(packets) == current_ids`.
- **F2**, `historical_catalog` (D): `current_ids - {NEW_PACKET} - set(PRODUCT_PACKETS)`, undone to
  `current_ids - {NEW_PACKET}`.
- **F3**, `validate_packet_payloads` (G1): `set(packets) == old | {NEW_PACKET} | set(PRODUCT_PACKETS)`, undone to
  `set(packets) == old | {NEW_PACKET}`.
- **F4**, `validate_packet_payloads` (G1): `set(rules) == old | {NEW_PACKET} | set(PRODUCT_PACKETS)`, undone to
  `set(rules) == old | {NEW_PACKET}`.
- **F5**, `_packet_byte_rules` (G1): `**record["productPackets"]` as the last keyword of
  `dict(record["baselinePackets"], **{NEW_PACKET: record["packetSha256"]}, ...)`, undone by dropping it.
- **F6**, `authority` (G2): `"productPackets"` as the last element of the closed key set `set(value) == {...}`,
  undone by dropping it.
- **F7**, `authority` (G2): the one statement below, rule.json's `authorityRule` (keys equal to the list, sha256
  values, no key in `baselinePackets` or equal to `NEW_PACKET`), immediately before the body's first `for`; undone by
  removing it. Its key equality is ordered (`list(...) == list(PRODUCT_PACKETS)`): builder v2 writes the authority's
  `productPackets` keys in `PRODUCT_PACKETS` order, and a key order that differs from the list refuses (fail closed).

```python
require(type(value["productPackets"]) is dict
        and list(value["productPackets"]) == list(PRODUCT_PACKETS)
        and all(_sha(sha) for sha in value["productPackets"].values())
        and not set(PRODUCT_PACKETS) & (set(value["baselinePackets"]) | {NEW_PACKET}),
        "product packets")
```

A fragment missing, repeated or present in a layer that binds no list, F7 in another place, and, after the undo, any
class function that still names `PRODUCT_PACKETS` (a name or an attribute) or the string `"productPackets"` (a guarded
statement, or a non-exact form such as `set(PRODUCT_PACKETS + X)` or `set(successor.PRODUCT_PACKETS)`) refuse under
the clause `P-form`. After the undo, a class function that differs from its class refuses under `D`, `G1` or `G2`.

## Refusals

Every model refusal is a `ValueError` whose message starts `identity <clause>: `. Sides: the model
(`chain_identity_v2`, run by the v2 live identity test), the head (the publishing head's own `validate()`, run by
argv 63) and the verifier (the owner's bundle, parts 1-4 of Q-CPP-2).

- **R1**, an added task-packet YAML not listed in `PRODUCT_PACKETS` and `productPackets`: model clause `counts`
  (C = S + P fails); the builder; the verifier's part 2 when it is also absent from `allowedPaths`, else verify via
  argv 63.
- **R2**, a product id outside `productId` (fullmatch), equal to a chain packet id, or whose YAML `id` is not its
  stem: clause `R2`, and `binding` for a non-id element of the list; the head's F7 for a baseline id.
- **R3**, a product whose `repository` (the line rule) is `Harness-Engineering`: clause `R3`; the verifier's part 1.
- **R4**, the meta packet's argv not exactly the predecessor's 64: head-only; the verifier's parts 3 and 4.
- **R5**, a listed product whose bytes do not match its `productPackets` digest: head-only (the per-packet lookup).
- **R6**, a product YAML changed at a later slot: head-only (the closed rule and `baselinePackets`).
- **R7**, two clauses. (1) A K = 0 head binding `PRODUCT_PACKETS = ()`, or a list that is empty or repeats an id:
  model clause `binding`. Only the plain spelling is read: exactly one top-level `PRODUCT_PACKETS = (<ids>,)` with one
  name target. Any other binding of the name in the layer (an annotated, chained or augmented assignment, a tuple, list
  or starred target, a walrus, `del`, `global` or `nonlocal`, an import or a star import, a for, with or comprehension
  target, a parameter, a def or class name, an except or match capture, a type parameter, a `type PRODUCT_PACKETS = ...`
  statement, or an assignment below the top level) refuses under `binding`, naming the form. Each layer's list is read
  from its own source by AST, with no import, so a dynamic binding is outside the model. (2) A K = 0 head whose
  authority carries a `productPackets` member, empty
  or not: head-only, as the K = 0 `authority()`'s unchanged closed key set refuses the member; in the model, F6
  written in a layer that binds no list refuses under `P-form`. F7 exists only in a layer that binds the list: there,
  at K >= 1, an empty key list fails F7's list equality, and `parse()`'s duplicate-member check refuses a repeated key
  before F7 runs.
- **R8**, a listed product absent from the catalog (clause 1, model clause `counts`, head-only on the verifier side),
  or a `repository` outside the twelve names (clause 2, model clause `R8`; the verifier's part 2).
- **R9**, a display gaining a product element at a K = 0 step, or a Starred element or (v) at the wrong depth or
  layer: clause `step`.
- **R10**, a count pin or message that moves by anything but 1 + K, read per `nReading`: clause `step`.
- **R11**, a publishing meta packet's `allowedPaths` lacking a listed product, or holding another `task-packets/`
  path: clause `R11`; the head; the first also the verifier's part 2.
- **R12**, a `repository` declaration that is not one inline line, or whose line `safe_load` reads as another value:
  clause `R12`; chain-only, so verify refuses it via argv 63. Where R8 clause 2 and R12 both apply (a block-form
  declaration, or a `repository` line with an inline comment), the model refuses under `R8`; either clause is a correct
  refusal.
- **R12-L**, R12 at a later publisher (a duplicate key naming `Harness-Engineering`): clause `R12`, by the v2 live
  identity test at every later PR.

## The vectors

Each case has `expect` (`OK` or `refuse`); a refusing case names `refusal` (the id above, or `P-form`, `D`, `G1`,
`G2`), `clause` (the model clause its message starts with) and `detail` (a fragment of its message).

- `steps` (`check_step_vector`): `before` and `after` sources of one non-bridge layer L at a step to slot S with
  catalog C and K products; K0, K1, K2, K0+ (the 275 step), (iv) at 189, and their refusals.
- `products` (`check_products`), `counts` (`check_counts`), `bindings` (`layer_products`) and `allowedPaths`
  (`check_allowed_paths`): R1-R3, R7, R8, R11, R12, R12-L and the valid K = 1 and K = 2 cases. A products case has
  `listed` (a slot, as a decimal string, mapped to the product ids that layer lists), `files` (each product id mapped
  to the text of its `task-packets/<id>.yaml`) and, optionally, `chainPackets` (the chain packet ids R2 compares
  with). Its `safe_load` is the repository's `scripts/safe_yaml.safe_load` (PyYAML's CSafeLoader when present, else
  SafeLoader; both keep the last value of a duplicate key, which R12-duplicate-key, its K = 2 twin and R12-L use).
- `classForms` (`check_class_vector`): `bases` holds two modules of the five class functions in their K = 0 form (the
  head form of slot 271 and the bridged form of slot 270, at dd000fef). Each case applies its `edits` (each old text
  exactly once) to its base, binds its `products` when there are any, undoes the P-forms and compares every class
  function with its K = 0 form. K0, K1, K2 and K0+ (the publisher's bridged form) pass; partial, unbound, guarded,
  misplaced or non-exact forms refuse under `P-form`, and other edits under `D`, `G1` or `G2`; `CF-K0-with-F6` is R7's
  second clause in the model.
- `agreement`: the 22 rows (11 cases at K = 1 and K = 2) of the builder, the head, the verifier's part and verify.
  The head column names the vectors that prove it (`section:id`); in every row verify's outcome equals the head's.
- `bridgeReplay`: the bridge cases a synthetic non-bridge vector cannot carry ((ix-p), (x-p), the 275 step's S-based
  phrases and (v) at layer 274) and the K = 0 era equivalence, each with the run that proves it.
- `headOnly`: R4, R5, R6 and R7's second clause, with the head check that enforces each.

## Where the rules apply

The v2 live identity test in `tests/test_chain_compaction.py` checks the live chain with S and C apart, proves v2 = v1
on the K = 0 era, applies R2's form check, R3, R8 clause 2 and R12 to every listed product of every layer, and runs
every vector; argv 63 runs it at every later PR.
