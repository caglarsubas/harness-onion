"""MET-015 (GR-REDTEAM-FIXTURES-001): the red-team and safety fixture pack's contract, its closed schema, its vectors, its
reference model and its checker.

The live contract passes the checker (scripts/validate_redteam_fixtures.py, GRRT_SHAPE to GRRT_VECTOR); every positive
vector's manifest rows, cases and run binding validate against the closed schema (architecture/redteam-fixtures/
schema.json, JSON Schema draft 2020-12, with the repository's pinned jsonschema) and RT-N0's extra key does not; every
vector replays through the model (scripts/redteam_fixtures.py). The run binding's datasetDigest is recomputed here from
I1's words, the empty tree (D1) passes HR-REPLAY's TREE family, and RT-2's outcome table holds for each expected value.
Then in-memory failing cases for each checker code. Every case mutates a copy of the live bytes behind an injected
reader; no file is written."""
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


RT = _load("scripts/validate_redteam_fixtures.py", "validate_redteam_fixtures_under_test")
MODEL = RT.model
READ = RT.disk_reader(ROOT)
RECORD = json.loads(READ(RT.RECORD_PATH))
SCHEMA = json.loads(READ(RT.SCHEMA_PATH))
VECTORS = json.loads(READ(RT.VECTORS_PATH))
CASES = {c["id"]: c for c in VECTORS["cases"]}


def _bytes(value):
    return (json.dumps(value, indent=2, ensure_ascii=False) + "\n").encode("utf-8")


def _reader(record=None, vectors=None, files=None):
    """A reader over the live bytes with overrides; the vectors' pin follows an overridden vectors file."""
    record = copy.deepcopy(RECORD if record is None else record)
    over = dict(files or {})
    if vectors is not None:
        over[RT.VECTORS_PATH] = _bytes(vectors)
        record["vectors"]["sha256"] = hashlib.sha256(over[RT.VECTORS_PATH]).hexdigest()
    over[RT.RECORD_PATH] = _bytes(record)
    return lambda path: over[path] if path in over else READ(path)


def _codes(read):
    return [code for code, _ in RT.check(read)]


def test_the_live_contract_passes_its_checker():
    assert RT.check(READ) == []
    assert RT.main([str(ROOT)]) == 0


def test_positive_vectors_validate_against_the_closed_schema():
    defs = SCHEMA["$defs"]
    validator = jsonschema.Draft202012Validator
    validator.check_schema(SCHEMA)
    for vid in ("RT-P1", "RT-P2", "RT-P3"):
        data = CASES[vid]["input"]
        for row in data["manifest"]:
            validator(dict(defs["manifestRow"], **{"$defs": defs})).validate(row)
        for case in data["cases"]:
            validator(dict(defs["case"], **{"$defs": defs})).validate(case)
        if data["binding"] is not None:
            validator(dict(defs["runBinding"], **{"$defs": defs})).validate(data["binding"])
    document = {"schemaVersion": MODEL.SCHEMA_NAME, "rows": CASES["RT-P1"]["input"]["manifest"],
                "cases": CASES["RT-P1"]["input"]["cases"]}
    validator(SCHEMA).validate(document)
    bad = [r for r in CASES["RT-N0"]["input"]["manifest"] if "extra" in r][0]
    with pytest.raises(jsonschema.ValidationError):
        validator(dict(defs["manifestRow"], **{"$defs": defs})).validate(bad)


def test_every_vector_replays_and_each_code_has_its_one_negative():
    for case in VECTORS["cases"]:
        ok, got = MODEL.replay(case)
        assert ok, (case["id"], got)
    negatives = [c for c in VECTORS["cases"] if c["polarity"] == "negative"]
    assert sorted(c["expect"]["refuse"] for c in negatives) == sorted(MODEL.CODES)
    assert len(negatives) == len(MODEL.CODES) == len(RECORD["refusalOrder"])


def test_the_dataset_digest_is_i1s_recomputation():
    data = CASES["RT-P3"]["input"]
    canonical = lambda v: json.dumps(v, sort_keys=True, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    sets = sorted([p["setId"], hashlib.sha256(canonical(sorted(p["caseIds"]))).hexdigest()]
                  for p in data["binding"]["selections"])
    value = {"manifest": hashlib.sha256(canonical(data["manifest"])).hexdigest(), "sets": sets}
    assert data["binding"]["datasetDigest"] == "sha256:" + hashlib.sha256(canonical(value)).hexdigest()
    tree = "sha256:" + hashlib.sha256(canonical({"entries": []})).hexdigest()
    picked = sum(len(p["caseIds"]) for p in data["binding"]["selections"])
    assert data["binding"]["fixtureDigest"] == "sha256:" + hashlib.sha256(canonical([tree] * picked)).hexdigest()


def test_the_empty_tree_passes_hr_replays_tree_family():
    empty = {"entries": []}
    assert MODEL.rf._tree_shape(empty)
    MODEL.rf.check_tree_paths(empty, {})
    MODEL.rf.check_tree_order(empty)
    assert MODEL.EMPTY_TREE == empty == RECORD["emptyTree"]


@pytest.mark.parametrize("expected, status, effective, met", [
    ("REFUSE", "DECIDED", "DENY", True), ("REFUSE", "DECIDED", "ESCALATE", False),
    ("DETECT", "DECIDED", "ESCALATE", True), ("DETECT", "DECIDED", "TRANSFORM", False),
    ("ALLOW", "DECIDED", "ALLOW", True), ("ALLOW", "DECIDED", "DENY", False),
    ("FAIL_CLOSED", "ERROR", "DENY", True), ("FAIL_CLOSED", "DECIDED", "DENY", False)])
def test_rt2_outcome_table(expected, status, effective, met):
    record = copy.deepcopy(CASES["RT-E01"]["input"]["record"])
    record["envelope"]["status"] = status
    record["envelope"]["effectiveDecision"] = effective
    assert MODEL.meets(expected, record) is met


def test_a_case_breaking_two_rules_refuses_with_the_earlier_code():
    case = copy.deepcopy(CASES["RT-N1"])               # LICENCE_MISSING ...
    case["input"]["cases"][1]["caseId"] = "bad id"     # ... and CASE_ID, which the refusalOrder puts first
    assert MODEL.replay(dict(case, expect={"refuse": "CASE_ID"})) == (True, {"refuse": "CASE_ID"})


def test_shape_refusal():
    record = dict(copy.deepcopy(RECORD), extra=1)
    assert _codes(_reader(record=record)) == ["GRRT_SHAPE"]


def test_order_refusal():
    record = copy.deepcopy(RECORD)
    order = record["refusalOrder"]
    order[1], order[2] = order[2], order[1]
    assert _codes(_reader(record=record)) == ["GRRT_ORDER"]


def test_bases_refusal():
    record = copy.deepcopy(RECORD)
    record["basis"]["replayModel"]["sha256"] = "0" * 64
    assert _codes(_reader(record=record)) == ["GRRT_BASES"]


def test_codes_refusal():
    record = copy.deepcopy(RECORD)
    record["vectorPerCode"]["SHAPE"] = ["RT-N1"]
    assert _codes(_reader(record=record)) == ["GRRT_CODES"]


def test_vector_refusal():
    vectors = copy.deepcopy(VECTORS)
    target = [c for c in vectors["cases"] if c["id"] == "RT-E01"][0]
    target["expect"]["result"]["errorCode"] = "ERR_TIMEOUT"
    assert _codes(_reader(vectors=vectors)) == ["GRRT_VECTOR"]
