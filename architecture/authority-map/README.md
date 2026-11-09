# Authority map (AUTHORITY-MAP-001, MET-ADOPT-007)

`architecture/authority-map.json` (`planeon.internal.authority-map/v1`) records one effective authority for each of
nine concerns: the boundary whose state or decision determines behaviour, the non-deciding inputs it relies on, what
others may do, every enforcement point, and the behaviour when the authority is unavailable or revoked.
`scripts/authority_map.py` checks it (`check(read, packets)`, refusal codes AM_SHAPE to AM_REGISTRY). Repository
ownership says who writes code; this record says whose state or decision counts.

## The pinned semantics

The module holds 27 constants: every row's authority `{harness, component}` and its two behaviours, each bound to one
citation. A different value, or the right value cited to another line, is refused; changing a pin takes a new module
version and a new record version. The 27 fall in three classes:
- 23 stating: bound to a repository line that states the value;
- 2 item-bound: bound to the roadmap item AUTHORITY-MAP-001, because no harness line states them (AM-02's revoked
  behaviour, AM-06's authority); checked in-repo by item id, and by quote at authoring and in review;
- 2 flagged, "no stating line; nearest topical line": AM-06's unavailable behaviour
  (`docs/harnesses/execution.tool-skill-sandbox.md:148`) and AM-09's revoked behaviour
  (`docs/harnesses/runtime.infrastructure.md:196`). Their documents state no rule for those cases. These are limits
  of the record, listed as such wherever the record is published.

## FAIL_CLOSED and BLOCK_NEW_OPERATIONS, case by case

Both mean that nothing proceeds on the authority's absence; the pinned line of each case decides, not a verb.
FAIL_CLOSED, a refusal at the request's enforcement point: AM-02 unavailable (`trust.observability-finops.md:177`, hard
budgets), AM-03 unavailable (`runtime.model-inference.md:156`), AM-04 unavailable (`trust.security-safety.md:158`),
AM-05 revoked (`trust.governance-agentops.md:159`). BLOCK_NEW_OPERATIONS, work held back while the authority's state is
unavailable: AM-01 (`execution.orchestration.md:155`, rejected), AM-05 (`trust.governance-agentops.md:157`, paused),
AM-06 (`execution.tool-skill-sandbox.md:148`, flagged), AM-07 (`knowledge.memory-state.md:140`, rejected), AM-08
(`trust.governance-agentops.md:158`, held back until evidence can be proven).

## Vectors

- `budget-vectors.json`: rules B1-B5 and vectors VB-01 to VB-11, replayed by the module's reference model; each
  vector gives its per-step results and each reservation's state at the end (one terminal state once settled,
  RESERVED while open). Whether a refused reserve is kept under its key is outside these semantics (B3). Write skew,
  fencing and clocks are DATA-CORRECTNESS-001's.
- `r12-vectors.json`: R12-V1 to R12-V5, each an actor claiming an authority act on a row it does not hold; every one is
  refused by the map's rule over the vector's declared actor and act. They are data for the conformance labs, written
  here. R12-V2 names AM-04 only: its approval-expiry half is AM-05's (governance-service), held here under AM-04, the
  row whose cache it is.

## The briefs registry (V9)

`architecture/review-record/briefs.json` is accepted at its base digest, or as the base, then MET-ADOPT-007's one
`MET-ADOPT-007/packet` rider, then zero or more later packets' riders in the order they were appended (V9 (a),
MON-282-W2-RULED). Each later rider is the generic packet brief (the rider's kind, path, sha256 and version 1)
under `<id>/packet`, for an id in `check`'s packet set other than MET-ADOPT-007, and each series appears once in
the whole registry. A second MET-ADOPT-007 rider, a rider for an unknown id, a series registered twice and a rider
before MET-ADOPT-007's (the base's digest refuses it) are refused with AM_REGISTRY. The relative order of later
riders is each later packet's own check (its rider appended last).

## Reading the design

The design note's later sections (its rev 2 to rev 6 change lists) are change logs; this record and the module state
the current semantics. Non-claims are in the record's `nonClaims`.
