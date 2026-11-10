# The era-replay reader (xi): identity model v4

MET-PERF-049 (slot 286) extends the history chain's identity rule by one step clause, (xi), in a fourth model version,
`scripts/chain_identity_v4.py`, without changing v1, v2 or v3 (the visionary's ruling Q-286-IDENTITY under the owner's
delegation, `decisions.md`). When the old head's previous-era `_replay` hands its era model the live reader
(`<model>.check(regular_bytes, X)`), the bridged layer must hand it the projected reader (`reviewed_bytes`) at that one
position, so a sealed layer's inherited check reads its era's bytes (CONTRACT_286 C8, MA008-P1-3). The clause is the
same text as chainmech's strictbridge_v2 form (xi). `rule.json` extends `architecture/chain-inheritance/rule.json` by
path, sha256 and clause; `vectors.json` holds the positive, five negatives and the equivalence case (v4 = v3 when the
old head holds no reader).
