"""MET-007 (DATA-CORRECTNESS-001): the data-correctness contract record, its reference model and its checker.

The live record passes the checker (scripts/validate_data_correctness.py, DC_SHAPE to DC_VECTORS) and validates against
its schema (architecture/data-correctness/schema.json, JSON Schema draft 2020-12, with the repository's pinned
jsonschema); every vector replays to its expectation through the model (scripts/data_correctness.py) and every model code
is refused by one; then one in-memory failing case per checker code (CONTRACT_288 rev 3 sections 3 to 5). Every case
mutates a copy of the live bytes behind an injected reader; no file is written."""
import copy
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


DC = _load("scripts/validate_data_correctness.py", "validate_data_correctness_under_test")
MODEL = _load("scripts/data_correctness.py", "data_correctness_under_test")
READ = DC.disk_reader(ROOT)
PACKETS = DC.published_packets(ROOT)
RECORD = json.loads(READ(DC.RECORD_PATH))
SCHEMA = json.loads(READ(DC.SCHEMA_PATH))


def _reader(record=None, files=None):
    over = dict(files or {})
    if record is not None:
        over[DC.RECORD_PATH] = (json.dumps(record, indent=2) + "\n").encode("utf-8")
    return lambda path: over[path] if path in over else READ(path)


def _codes(record=None, files=None):
    return [code for code, _ in DC.check(_reader(record, files), PACKETS)]


def test_the_live_record_passes_and_validates_against_its_schema():
    assert DC.check(READ, PACKETS) == []
    jsonschema.Draft202012Validator.check_schema(SCHEMA)
    assert list(jsonschema.Draft202012Validator(SCHEMA).iter_errors(RECORD)) == []
    raw = READ(DC.RECORD_PATH) + READ(DC.SCHEMA_PATH)
    assert not any(p.encode() in raw for p in DC.CATALOG_PATHS)


def test_the_rows_are_the_effective_catalogs_durable_writers():
    writers = MODEL.durable_writers(READ, PACKETS)
    assert len(writers) == len(RECORD["deployables"]) == 24
    assert [w["stateMode"] for w in writers].count("STATEFUL") == 21
    assert [r["id"] for r in RECORD["deployables"]] == [w["id"] for w in writers]


def test_every_vector_replays_to_its_expectation_and_every_model_code_is_refused():
    paths = [p for f in RECORD["ruleFamilies"] for p in f["vectors"]]
    assert len(paths) == len(set(paths)) == 13
    refused = set()
    for path in paths:
        vector = json.loads(READ(path))
        got = MODEL.replay(vector)
        assert got == vector["expect"], vector["id"]
        if got != "ACCEPT":
            refused.add(got["refuse"])
    assert refused == set(MODEL.MODEL_CODES)
    assert not set(MODEL.MODEL_CODES) & set(DC.CODES)


@pytest.mark.parametrize("vector", [
    {"id": "x", "family": "RF-1", "setup": {}, "steps": [], "expect": "ACCEPT"},
    {"id": "x", "family": "RF-9", "setup": {}, "steps": [{"op": "replay"}], "expect": "ACCEPT"},
    {"id": "x", "family": "RF-7", "setup": {}, "steps": [{"op": "call"}], "expect": "ACCEPT"},
    {"id": "x", "family": "RF-7", "setup": {}, "steps": [{"op": "replay", "inputs": [], "consulted": []}], "expect": {"refuse": "DC_SHAPE"}},
    {"id": "x", "family": "RF-7", "setup": {}, "steps": [{"op": "replay", "inputs": [], "consulted": []}], "expect": "ACCEPT", "more": 1},
])
def test_a_malformed_vector_is_refused_by_shape(vector):
    with pytest.raises(ValueError):
        MODEL.replay(vector)


def _first_lease_row(record):
    return next(r for r in record["deployables"] if r["lease"])


def _first_derived_row(record):
    return next(r for r in record["deployables"] if r["derivedStores"])


def _mutate_shape(r):
    r["extra"] = 1


def _mutate_valued(r):
    row = _first_lease_row(r)
    row["lease"]["fencing"]["source"] = row["lease"]["source"]


def _mutate_catalog_name(r):
    r["operationIds"]["origin"] = "minted where architecture/services.yaml says"


def _mutate_basis(r):
    r["basis"]["catalog"]["sha256"] = "0" * 64


def _mutate_rows(r):
    r["deployables"][0], r["deployables"][1] = r["deployables"][1], r["deployables"][0]


def _mutate_sources(r):
    _first_lease_row(r)["lease"]["source"]["line"] += 1


def _mutate_fencing(r):
    _first_lease_row(r)["obligations"].remove("RF-2")


def _mutate_versions(r):
    kind = r["deployables"][0]["recordKinds"][0]
    kind["window"] = {"value": "N_MINUS_1_BOTH_DIRECTIONS", "source": copy.deepcopy(kind["source"])}


def _mutate_derived(r):
    _first_derived_row(r)["obligations"].remove("RF-6")


def _mutate_opids(r):
    r["operationIds"]["native"]["binds"] = ["READ"]


def _mutate_budget(r):
    r["basis"]["authorityMap"]["budgetRow"] = "AM-99"


def _mutate_counts(r):
    r["counts"]["withLease"] += 1


@pytest.mark.parametrize("mutate,code", [
    (_mutate_shape, "DC_SHAPE"), (_mutate_valued, "DC_SHAPE"), (_mutate_catalog_name, "DC_SHAPE"),
    (_mutate_basis, "DC_BASIS"), (_mutate_rows, "DC_ROWS"), (_mutate_sources, "DC_SOURCES"), (_mutate_fencing, "DC_FENCING"),
    (_mutate_versions, "DC_VERSIONS"), (_mutate_derived, "DC_DERIVED_STORES"), (_mutate_opids, "DC_OPIDS"),
    (_mutate_budget, "DC_BUDGET"), (_mutate_counts, "DC_COUNTS")])
def test_each_checker_code_has_a_failing_case(mutate, code):
    record = copy.deepcopy(RECORD)
    mutate(record)
    assert code in _codes(record)


def test_a_vector_that_replays_otherwise_is_refused():
    path = RECORD["ruleFamilies"][0]["vectors"][0]
    vector = json.loads(READ(path))
    vector["expect"] = "ACCEPT"
    assert _codes(files={path: json.dumps(vector).encode("utf-8")}) == ["DC_VECTORS"]


def test_a_vector_listed_without_its_family_or_twice_is_refused():
    record = copy.deepcopy(RECORD)
    record["ruleFamilies"][1]["vectors"].append(record["ruleFamilies"][0]["vectors"][0])
    assert "DC_VECTORS" in _codes(record)
