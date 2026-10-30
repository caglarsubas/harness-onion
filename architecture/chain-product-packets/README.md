# Chain product packets (MET-PERF-044, CHAIN-PRODUCT-PUBLISH-001)

This directory extends the history chain's identity rule (`architecture/chain-compaction/identity-rule.json`, cited by
digest in `rule.json`'s `extends`) with a pinned product-packet list: a slot may publish K >= 1 product packet YAMLs
beside its own meta packet (owner Q-SEC3-TWO, `decisions.md`). `identity-rule.json` and `scripts/chain_identity.py`
stay byte-identical; `scripts/chain_identity_v2.py` is the model with the product parameter.

- `rule.json`: the vocabulary. `counts` defines S (the head's slot), C (the catalog count) and P (the sum of K over
  every layer that binds `PRODUCT_PACKETS`), with C = S + P. `nReading` reads N as C in (i), (ii) and (x) and as S in
  (iii) (d = S - L) and (v) (L = S - 2). A publishing step adds (i-p)-(v-p), (ix-p) and (x-p); D, G1 and G2 take the
  product list as their one new parameter. `productId`, `productRepository` (the verifier's line rule, the twelve
  allowed names of `architecture/repositories.yaml` at dd000fef, the refused name) and `chainOnly` (R12) define a
  product. `allowedPaths` is the one list the builder, the head and the verifier share.
- `vectors.json`: the synthetic cases (steps, products, counts, bindings, allowedPaths) and the K = 0 case.
- `decisions.md`: the owner's Q-SEC3-TWO and Q-CPP-2, verbatim.

Where the rules apply: the v2 live identity test in `tests/test_chain_compaction.py` checks the live chain with S and C
apart, proves v2 = v1 on the K = 0 era, applies R2's form check, R3, R8 clause 2 and R12 to every listed product of
every layer, and runs every vector; argv 63 runs it at every later PR. The refusals R1-R12 are in the design note
(`tools/r00/chain-product-publish-001/DESIGN.md`, E1).
