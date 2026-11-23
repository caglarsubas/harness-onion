"""MET-013 (HR-APPROVAL-OUTCOME-001): the approval outcome record, its vectors, its reference model and its checker.

The live record passes the checker (scripts/validate_approval_outcome.py, AO_RECORD to AO_VECTOR) and validates against
its schema (architecture/approval-outcome/schema.json, JSON Schema draft 2020-12, with the repository's pinned
jsonschema), as do the vectors and the positive vectors' rows, audit records, statements and profiles against their
definitions. Every vector replays through the model (scripts/approval_outcome.py) and every model code and check is
reached; every lifecycle vector leaves a history the history check accepts; the hub's N1 clause holds in both halves,
UNAVAILABLE has its three sources and NOT_ELIGIBLE is a refusal at both points (CONTRACT_295 r4 section 3c,
ORC-295-N1-SCOPE, ORC-295-R4); a later statement never lifts a deny; then in-memory failing cases for each checker code.
Every case mutates a copy of the live bytes behind an injected reader; no file is written."""
import copy
import hashlib
import importlib.util
import json
from pathlib import Path

import jsonschema
import pytest

ROOT = Path(__file__).resolve().parents[1]


def _load(rel, name):
    spec = importlib.util.spec_from_file_location(name, ROOT / rel)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


AO = _load("scripts/validate_approval_outcome.py", "validate_approval_outcome_under_test")
MODEL = _load("scripts/approval_outcome.py", "approval_outcome_under_test")
READ = AO.disk_reader(ROOT)
RECORD = json.loads(READ(AO.RECORD_PATH))
SCHEMA = json.loads(READ(AO.SCHEMA_PATH))
VECTORS = json.loads(READ(AO.VECTORS_PATH))
CASES = {c["id"]: c for c in VECTORS["cases"]}


def _bytes(value):
    return (json.dumps(value, indent=2, ensure_ascii=False) + "\n").encode("utf-8")


def _reader(record=None, vectors=None, files=None):
    """A reader over the live bytes with overrides; every overridden file the record pins is re-pinned."""
    record = copy.deepcopy(RECORD if record is None else record)
    over = dict(files or {})
    if vectors is not None:
        over[AO.VECTORS_PATH] = _bytes(vectors)
    for key in ("schema", "vectors", "model"):
        if record[key]["path"] in over:
            record[key]["sha256"] = hashlib.sha256(over[record[key]["path"]]).hexdigest()
    over[AO.RECORD_PATH] = _bytes(record)
    return lambda path: over[path] if path in over else READ(path)


def _codes(record=None, vectors=None, files=None):
    return [code for code, _ in AO.check(_reader(record, vectors, files))]


def _validator(name):
    return jsonschema.Draft202012Validator(dict(SCHEMA["$defs"][name], **{"$defs": SCHEMA["$defs"]}))


def _lifecycle(events, **more):
    return dict({"kind": "demand", "quorum": 1, "sweepInterval": 300, "events": events}, **more)


SUBJECT = CASES["AO-O-L1"]["input"]["events"][0]["subject"]
ASK = CASES["AO-O-L1"]["input"]["events"][0]
DECIDE = CASES["AO-O-L1"]["input"]["events"][1]


def test_the_live_record_passes_and_every_document_validates_against_its_shape():
    assert AO.check(READ) == []
    jsonschema.Draft202012Validator.check_schema(SCHEMA)
    assert list(jsonschema.Draft202012Validator(SCHEMA).iter_errors(RECORD)) == []
    assert list(_validator("vectorsFile").iter_errors(VECTORS)) == []
    seen = {"row": 0, "auditRecord": 0, "statement": 0, "profile": 0}
    for case in VECTORS["cases"]:
        if case["polarity"] != "POSITIVE":
            continue
        data = case["input"]
        if case["check"] == "HISTORY":
            assert list(_validator("row").iter_errors(data["row"])) == [], case["id"]
            seen["row"] += 1
            for record in data["audit"]:
                assert list(_validator("auditRecord").iter_errors(record)) == [], case["id"]
                seen["auditRecord"] += 1
        elif case["check"] == "STATEMENTS":
            for statement in data["statements"]:
                assert list(_validator("statement").iter_errors(statement)) == [], case["id"]
                seen["statement"] += 1
        elif case["check"] == "PROFILE":
            assert list(_validator("profile").iter_errors(data)) == [], case["id"]
            seen["profile"] += 1
    assert all(seen.values()), seen


def test_every_vector_replays_and_every_code_and_check_is_reached():
    cases = VECTORS["cases"]
    listed = [v for f in RECORD["ruleFamilies"] for v in f["vectors"]]
    assert len(listed) == len(set(listed)) == len(cases) > 0
    refused = set()
    for case in cases:
        ok, got = MODEL.replay(case)
        assert ok, (case["id"], got)
        if case["polarity"] == "NEGATIVE":
            refused.add(got)
    assert refused == set(MODEL.CODES)
    assert {c["check"] for c in cases} == set(MODEL.CHECKS)


def test_every_lifecycle_vector_leaves_a_history_the_history_check_accepts():
    lifecycles = [c for c in VECTORS["cases"] if c["check"] == "LIFECYCLE"]
    assert lifecycles
    for case in lifecycles:
        result = MODEL.simulate(case["input"])
        assert MODEL.evaluate("HISTORY", MODEL.history_of(case["input"], result)) == (None, {"state": result["state"]}), \
            case["id"]


def test_n1_a_refused_decision_attempt_leaves_the_request_requested():
    refused = dict(DECIDE, port={"answer": "NOT_ELIGIBLE", "eligible": []})
    for tail, state in (([], "REQUESTED"), ([dict(DECIDE, t=20, reviewer=dict(DECIDE["reviewer"], id="rev-2"),
                                               port={"answer": "ELIGIBLE", "eligible": ["rev-2"]})], "APPROVED"),
                        ([{"op": "sweep", "t": ASK["expiresAt"] + 1}], "EXPIRED"),
                        ([{"op": "cancel", "t": 20, "by": "REQUESTER"}], "CANCELLED")):
        result = MODEL.simulate(_lifecycle([ASK, refused, {"op": "read", "t": 11}] + tail))
        assert result["refusals"] == ["NOT_ELIGIBLE"] and result["reads"] == ["REQUESTED"]
        assert result["state"] == state and result["decided"] == (0 if state == "REQUESTED" else 1)


def test_n1_an_unreadable_port_at_the_decision_records_unavailable_and_it_is_terminal():
    unreadable = dict(DECIDE, port={"answer": "UNAVAILABLE", "eligible": []})
    result = MODEL.simulate(_lifecycle([ASK, unreadable, dict(DECIDE, t=20), {"op": "cancel", "t": 21, "by": "REQUESTER"}]))
    assert (result["state"], result["reason"], result["decided"]) == ("UNAVAILABLE", "PORT_UNAVAILABLE_AT_DECISION", 1)
    assert result["refusals"] == ["NOT_OPEN", "NOT_OPEN"]


def test_unavailable_has_three_sources_and_not_eligible_is_a_refusal_at_both_points():
    at_ask = MODEL.simulate(_lifecycle([dict(ASK, port="UNAVAILABLE")]))
    headless = MODEL.simulate(_lifecycle([dict(ASK, asker={"type": "WORKLOAD", "workloadDigest": SUBJECT["subjectDigest"]})]))
    at_decision = MODEL.simulate(_lifecycle([ASK, dict(DECIDE, port={"answer": "UNAVAILABLE", "eligible": []})]))
    assert [(r["state"], r["reason"]) for r in (at_ask, at_decision, headless)] == [
        ("UNAVAILABLE", reason) for reason in MODEL.UNAVAILABLE_REASONS]
    assert headless["portAsked"] == 0 and at_ask["portAsked"] == 1
    not_at_ask = MODEL.simulate(_lifecycle([dict(ASK, port="NOT_ELIGIBLE"), {"op": "read", "t": 1}]))
    assert (not_at_ask["state"], not_at_ask["asked"], not_at_ask["refusals"], not_at_ask["reads"]) == (
        None, 0, ["NOT_ELIGIBLE"], ["NONE"])
    not_at_decision = MODEL.simulate(_lifecycle([ASK, dict(DECIDE, port={"answer": "NOT_ELIGIBLE", "eligible": []})]))
    assert (not_at_decision["state"], not_at_decision["refusals"]) == ("REQUESTED", ["NOT_ELIGIBLE"])


def test_a_later_statement_never_lifts_a_deny_and_no_value_outside_the_set_permits():
    layers = {k: "LOADED" for k in MODEL.LAYERS}
    for first in MODEL.LAYERS:
        for later in MODEL.LAYERS:
            if MODEL.LAYER_RANK[later] < MODEL.LAYER_RANK[first]:
                continue
            statements = [{"id": "d", "version": "1", "layer": first, "scope": "ACTION", "match": "a", "effect": "DENY"},
                          {"id": "l", "version": "1", "layer": later, "scope": "ACTION", "match": "a", "effect": "ALLOW"}]
            assert MODEL.evaluate_statements(statements, layers, "a") == {"decision": "DENY",
                                                                          "statement": {"id": "d", "version": "1"}}
    for value in ("PENDING", "AUTO_APPROVED", "approved", ""):
        assert MODEL.project({"state": value, "expiresAt": 0}, 0) == "REFUSED_UNKNOWN"
        assert not MODEL.permits(MODEL.project({"state": value, "expiresAt": 0}, 0))


def _record(edit):
    record = copy.deepcopy(RECORD)
    edit(record)
    return record


def _vectors(edit):
    vectors = copy.deepcopy(VECTORS)
    edit(vectors)
    return vectors


def _case(vectors, cid):
    return next(c for c in vectors["cases"] if c["id"] == cid)


def _model_importing_json():
    raw = READ(AO.MODEL_PATH)
    return {AO.MODEL_PATH: raw.replace(b"\nimport re\n", b"\nimport json\nimport re\n", 1)}


def _drop_refs(vectors, clause):
    for case in vectors["cases"]:
        case["refs"] = [r for r in case["refs"] if r != clause] or ["O1"]


RECORD_CASES = [
    lambda: _codes(record=_record(lambda r: r.update(extra=1))),
    lambda: _codes(record=_record(lambda r: r["clauses"].pop())),
    lambda: _codes(record=_record(lambda r: r["ruleFamilies"].reverse())),
    lambda: _codes(record=_record(lambda r: r.update(openState="PENDING"))),
    lambda: _codes(vectors=_vectors(lambda v: v["cases"][0].pop("title"))),
]
BASIS_CASES = [
    lambda: _codes(record=_record(lambda r: r["schema"].update(sha256="0" * 64))),
    lambda: _codes(record=_record(lambda r: r["model"].update(sha256="0" * 64))),
    lambda: _codes(files=_model_importing_json()),
]
VECTOR_CASES = [
    lambda: _codes(vectors=_vectors(lambda v: _case(v, "AO-O-L8")["expect"]["result"].update(state="UNAVAILABLE"))),
    lambda: _codes(vectors=_vectors(lambda v: _case(v, "AO-S-N8")["expect"].update(refuse="AO_AUDIT"))),
    lambda: _codes(record=_record(lambda r: r["ruleFamilies"][0]["vectors"].pop())),
    lambda: _codes(vectors=_vectors(lambda v: _drop_refs(v, "N-9"))),
    lambda: _codes(vectors=_vectors(lambda v: _case(v, "AO-S-N1").update(refs=["S5"]))),
    lambda: _codes(vectors=_vectors(lambda v: _case(v, "AO-O-L1")["refs"].append("N-7"))),
]


@pytest.mark.parametrize("run, code", [(f, "AO_RECORD") for f in RECORD_CASES] + [(f, "AO_BASIS") for f in BASIS_CASES]
                         + [(f, "AO_VECTOR") for f in VECTOR_CASES])
def test_each_checker_code_has_failing_cases(run, code):
    assert run() == [code]
