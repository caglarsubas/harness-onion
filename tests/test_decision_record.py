"""MET-014 (GR-DECISION-RECORD-001): the decision record, its fail-closed envelope, its vectors, its reference model and
its checker.

The live contract passes the checker (scripts/validate_decision_record.py, DR_SHAPE to DR_VECTOR); every RECORD vector's
record but N8's and N10's (the E7 reads of an unknown value) validates against the record schema
(architecture/decision-record/decision-record.schema.json, JSON Schema draft 2020-12, with the repository's pinned
jsonschema); every vector replays through the model (scripts/decision_record.py). The lift's crash, race and repeat
actions from the TLA+ models are the seven C30 cases below, through the model's Consumer seam (CONTRACT_296 r2
section 3a, L4). Then in-memory failing cases for each checker code. Every case mutates a copy of the live bytes behind
an injected reader; no file is written."""
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


DR = _load("scripts/validate_decision_record.py", "validate_decision_record_under_test")
MODEL = _load("scripts/decision_record.py", "decision_record_under_test")
READ = DR.disk_reader(ROOT)
RECORD = json.loads(READ(DR.RECORD_PATH))
SCHEMA = json.loads(READ(DR.SCHEMA_PATH))
VECTORS = json.loads(READ(DR.VECTORS_PATH))
CASES = {c["id"]: c for c in VECTORS["cases"]}
ESC = CASES["GR-P6"]["input"]["escalation"]
APR = CASES["GR-P6"]["input"]["approval"]
EFFECT = CASES["GR-P6"]["input"]["effect"]


def _bytes(value):
    return (json.dumps(value, indent=2, ensure_ascii=False) + "\n").encode("utf-8")


def _reader(record=None, vectors=None, files=None):
    """A reader over the live bytes with overrides; every overridden file the record pins is re-pinned."""
    record = copy.deepcopy(RECORD if record is None else record)
    over = dict(files or {})
    if vectors is not None:
        over[DR.VECTORS_PATH] = _bytes(vectors)
    for key in ("schema", "vectors", "statusRecord", "model"):
        if record[key]["path"] in over:
            record[key]["sha256"] = hashlib.sha256(over[record[key]["path"]]).hexdigest()
    over[DR.RECORD_PATH] = _bytes(record)
    return lambda path: over[path] if path in over else READ(path)


def _codes(record=None, vectors=None, files=None):
    return [code for code, _ in DR.check(_reader(record, vectors, files))]


def test_live_contract_passes_its_checker():
    assert DR.check(READ) == []
    assert DR.main([str(ROOT)]) == 0


def test_records_validate_against_the_schema():
    validator = jsonschema.Draft202012Validator(SCHEMA)
    jsonschema.Draft202012Validator.check_schema(SCHEMA)
    records = [c["input"] for c in VECTORS["cases"] if c["kind"] == "RECORD" and c["id"] not in ("GR-N8", "GR-N10")]
    records += [c["input"][k] for c in VECTORS["cases"] if c["kind"] == "LIFT" for k in ("escalation", "approval")]
    assert records
    for value in records:
        validator.validate(value)
    for vid in ("GR-N8", "GR-N10"):
        assert list(validator.iter_errors(CASES[vid]["input"])), vid


@pytest.mark.parametrize("vid", sorted(CASES))
def test_every_vector_replays(vid):
    ok, got = MODEL.replay(CASES[vid])
    assert ok, got


def test_each_refusal_code_has_its_vectors():
    for code, vids in RECORD["vectorPerCode"].items():
        assert vids and all(CASES[v]["expect"] == {"result": "REFUSED", "code": code} for v in vids)
    assert set(RECORD["vectorPerCode"]) == set(MODEL.CODES)


def test_fail_closed_never_permits():
    for kind in MODEL.KINDS:
        assert MODEL.FAIL_CLOSED[kind] not in MODEL.PERMITTING
    outage = copy.deepcopy(CASES["GR-P7"]["input"])
    assert MODEL.effective(outage) == "DENY"
    unknown = copy.deepcopy(CASES["GR-N8"]["input"])
    assert MODEL.effective(unknown) == "DENY"
    grade_error = CASES["GR-N9"]["input"]
    assert MODEL.grade_count(grade_error) == "UNGRADED"
    assert MODEL.replay_score(grade_error) == {"status": "BLOCKED", "blockerCode": "EVALUATOR_ERROR",
                                               "evidenceDigest": MODEL.digest(grade_error)}


def test_lift_refused_after_a_lift_n7f():
    assert MODEL.lift(ESC, APR, [], EFFECT) == "ACT"
    assert MODEL.lift(ESC, APR, [MODEL.digest(ESC)], EFFECT) == "LIFT_REFUSED"


def _escalation(revision=None, rid="dr-esc-test", supersedes=None):
    value = copy.deepcopy(ESC)
    value["decisionId"] = rid
    value["supersedes"] = supersedes
    if revision is not None:
        value["subject"]["revision"] = revision
    return value


def _approval(escalation, rid="dr-apr-test", expires=None):
    value = copy.deepcopy(APR)
    value["decisionId"] = rid
    value["escalationRef"] = MODEL.digest(escalation)
    value["subject"] = copy.deepcopy(escalation["subject"])
    value["approval"]["revision"] = escalation["subject"]["revision"]
    if expires is not None:
        value["approval"]["expiresAt"] = expires
    return value


def _effect(escalation, at=None):
    s = escalation["subject"]
    return {"at": EFFECT["at"] if at is None else at, "scopeDigest": s["scopeDigest"],
            "subjectDigest": s["subjectDigest"], "revision": s["revision"]}


# ---- C30 (6): the TLA+ models' crash, race and repeat actions, as test cases through the Consumer seam


def test_case_escalate_between_check_and_act():
    consumer, first = MODEL.Consumer(), _escalation()
    consumer.escalate(first)
    approval = _approval(first)
    consumer.escalate(_escalation(rid="dr-esc-later", supersedes=MODEL.digest(first)))
    assert consumer.act(approval, _effect(first)) == "LIFT_REFUSED"
    assert consumer.effects == [] and consumer.lifted == []


def test_case_crash_before_act():
    consumer, escalation = MODEL.Consumer(), _escalation()
    consumer.escalate(escalation)
    approval = _approval(escalation)
    assert consumer.act(approval, _effect(escalation), crash_before_act=True) == "CRASHED"
    assert consumer.effects == [] and consumer.lifted == []
    assert consumer.act(approval, _effect(escalation)) == "ACT"
    assert len(consumer.effects) == 1 and consumer.lifted == [MODEL.digest(escalation)]


def test_case_approval_for_superseded_escalation():
    consumer, old = MODEL.Consumer(), _escalation()
    consumer.escalate(old)
    consumer.escalate(_escalation(rid="dr-esc-new", supersedes=MODEL.digest(old)))
    assert consumer.act(_approval(old), _effect(old)) == "LIFT_REFUSED"
    assert consumer.effects == []


def test_case_effect_repeated_delivery():
    consumer, escalation = MODEL.Consumer(), _escalation()
    consumer.escalate(escalation)
    approval = _approval(escalation)
    assert consumer.act(approval, _effect(escalation)) == "ACT"
    assert consumer.act(approval, _effect(escalation)) == "LIFT_REFUSED"
    assert len(consumer.effects) == 1


def test_case_new_revision_after_approval():
    consumer, escalation = MODEL.Consumer(), _escalation(revision=3)
    consumer.escalate(escalation)
    approval = _approval(escalation)
    newer = _escalation(revision=4, rid="dr-esc-r4")
    consumer.escalate(newer)
    assert consumer.act(approval, _effect(newer)) == "LIFT_REFUSED"
    assert consumer.effects == []


def test_case_approval_expires_before_effect():
    consumer, escalation = MODEL.Consumer(), _escalation()
    consumer.escalate(escalation)
    approval = _approval(escalation, expires=EFFECT["at"])
    assert consumer.act(approval, _effect(escalation)) == "LIFT_REFUSED"
    assert consumer.effects == []


def test_case_second_approval_after_lift():
    consumer, escalation = MODEL.Consumer(), _escalation()
    consumer.escalate(escalation)
    assert consumer.act(_approval(escalation, rid="dr-apr-one"), _effect(escalation)) == "ACT"
    assert consumer.act(_approval(escalation, rid="dr-apr-two"), _effect(escalation)) == "LIFT_REFUSED"
    assert len(consumer.effects) == 1


def test_the_seven_c30_cases_are_this_file_s():
    names = set(globals())
    assert all("test_" + case in names for case in RECORD["c30Tests"]["cases"])
    assert len(RECORD["c30Tests"]["cases"]) == len(set(RECORD["c30Tests"]["cases"])) == 7


# ---- each checker code fails closed


def test_dr_shape_refuses_an_open_case():
    vectors = copy.deepcopy(VECTORS)
    vectors["cases"][0]["extra"] = 1
    assert _codes(vectors=vectors) == ["DR_SHAPE"]


def test_dr_envelope_refuses_a_permitting_fail_closed_value():
    record = copy.deepcopy(RECORD)
    record["failClosed"]["GUARDRAIL"] = "ALLOW"
    assert "DR_ENVELOPE" in _codes(record=record)


def test_dr_lift_refuses_l5_without_e1s_sentence():
    record = copy.deepcopy(RECORD)
    for row in record["clauses"]:
        if row["id"] == "L5":
            row["text"] = "The approval names the escalation."
    assert _codes(record=record) == ["DR_LIFT"]


def test_dr_codes_refuses_a_code_without_its_vector():
    record = copy.deepcopy(RECORD)
    record["vectorPerCode"]["TRANSFORM_CONFLICT"] = ["GR-N5"]
    assert _codes(record=record) == ["DR_CODES"]


def test_dr_vector_refuses_a_wrong_expectation():
    vectors = copy.deepcopy(VECTORS)
    for case in vectors["cases"]:
        if case["id"] == "GR-N7f":
            case["expect"] = {"result": "ACT"}
    assert "DR_VECTOR" in _codes(vectors=vectors)


def test_dr_vector_refuses_a_model_import():
    raw = READ(DR.MODEL_PATH) + b"\nimport os\n"
    assert "DR_VECTOR" in _codes(files={DR.MODEL_PATH: raw})
