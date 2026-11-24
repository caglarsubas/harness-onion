# Decision record (GR-DECISION-RECORD-001, MET-014)

One record shape, `planeon.internal.decision-record/v1`, for the H13 edges (GUARDRAIL), the admission scanners
(ADMISSION_SCAN), the graders (GRADE) and approvals (APPROVAL). The fail-closed envelope (E1-E7) makes an outage, an
error or an unknown value read as the kind's fail-closed value, never as allow; a model may enrich a record but never
lower a deterministic decision and never approve.

- `decision-record.schema.json`: the record's closed shape (JSON Schema draft 2020-12).
- `reason-codes.json`: the record of this contract: the kinds, decision sets and fail-closed values, the reserved
  error codes, the per-kind reason codes, the refusal codes in their check order, the clauses E1-E7, X3 and L1-L5 as two
  rule families, one vector per refusal code, and the pins of the schema, the vectors, the reference model and
  HR-APPROVAL-OUTCOME-001's record (the APPROVAL kind's outcome set and row fields, by reference).
- `vectors.json`: the cases, each `{id, kind, input, expect}`; a RECORD case's input is one record, a LIFT case's is
  `{escalation, approval, lifted, effect}` (`lifted`: the ESCALATE records already lifted, by digest).
- `status.json`: the item's status, its producers and its consumers.
- `scripts/decision_record.py`: the reference model (standard library only); `scripts/validate_decision_record.py`: the
  checker (DR_SHAPE to DR_VECTOR); `tests/test_decision_record.py`: the tests, with the lift's seven crash, race and
  repeat cases from the TLA+ models (C30 (6)) as test cases.

The lift of an ESCALATE record is a consumer rule over two append-only records (L1-L5): an ESCALATE record is lifted at
most once, and the lift is recorded by the effect it permits, in the same commit. DENY is never liftable. Data checks
only; nothing here enforces.

Not claimed: that a decision point runs the rule its record names (H16, H13); that a point without a deadline writes
ERR_TIMEOUT. ACCESS_REVIEW is not a kind of v1 (r2 section 3, the recorded departure).
