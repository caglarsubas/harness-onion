"""MET-015 (MODEL-WEIGHTS-POLICY-001): the model weights record, its closed schema, its vectors, the v3 licence
amendment (LIC-WEIGHTS-A3) and the checker.

The live files pass the checker (scripts/validate_model_weights.py, MW_POLICY to MW_VECTORS); the live record and every
positive vector's record validate against the closed schema (architecture/model-weights/schema.json, JSON Schema
draft 2020-12, with the repository's pinned jsonschema); every vector gives exactly its expected refusals; the
candidate-row null rule holds on the live record (each null listed by row and field; a null restriction field only on
a DENIED, UNKNOWN or undecided review row, never released, never distributed); and nulling any one of the eight
restriction fields of an allowing row is refused (fail closed). Then in-memory failing cases for each checker code.
Every case mutates a copy of the live bytes behind an injected reader; no file is written. Counts are parsed from the
files, never typed."""
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


mw = _load("scripts/validate_model_weights.py", "validate_model_weights_t297")
DISK = mw.disk_reader(ROOT)
RECORD = json.loads(DISK(mw.RECORD_PATH))
SCHEMA = json.loads(DISK(mw.SCHEMA_PATH))
VECTORS = json.loads(DISK(mw.VECTORS_PATH))
CASES = VECTORS["cases"]
POSITIVE = [c for c in CASES if c["polarity"] == "positive"]
NEGATIVE = [c for c in CASES if c["polarity"] == "negative"]


def _bytes(value):
    return json.dumps(value).encode("utf-8")


def _reader(overrides):
    def read(path):
        return overrides[path] if path in overrides else DISK(path)
    return read


def _codes(overrides):
    return [code for code, _ in mw.check(_reader(overrides))]


def _record_codes(record, sources=None):
    policy = mw.policy_facts(DISK)
    return [code for code, _ in mw.check_record(record, mw._source_reader(sources or {}), policy)]


def _case(cid):
    found = [c for c in CASES if c["id"] == cid]
    assert len(found) == 1
    return copy.deepcopy(found[0])


def test_live_files_pass():
    assert mw.check(DISK) == []
    assert mw.main([str(ROOT)]) == 0


def test_vector_counts_are_parsed():
    ids = [c["id"] for c in CASES]
    assert len(ids) == len(set(ids)) and len(POSITIVE) + len(NEGATIVE) == len(CASES)
    assert len(POSITIVE) >= 1 and len(NEGATIVE) >= 1
    covered = {code for c in NEGATIVE for code in c["expect"]["refusals"]}
    assert set(mw.CODES[2:9]) <= covered


def test_schema_validates_live_and_positive_records():
    validator = jsonschema.Draft202012Validator(SCHEMA)
    jsonschema.Draft202012Validator.check_schema(SCHEMA)
    validator.validate(RECORD)
    for case in POSITIVE:
        validator.validate(case["record"])
    extra = copy.deepcopy(RECORD)
    extra["releases"][0]["extra"] = 1
    with pytest.raises(jsonschema.ValidationError):
        validator.validate(extra)


@pytest.mark.parametrize("case", CASES, ids=[c["id"] for c in CASES])
def test_vector_gives_its_expectation(case):
    assert _record_codes(case["record"], case["sources"]) == case["expect"]["refusals"]


def test_candidate_null_rule_on_live_record():
    listed = sorted((e["row"], e["field"]) for e in RECORD["nullValues"])
    assert listed == sorted((r["id"], p) for r in RECORD["releases"] for p in mw.unread(r))
    assert RECORD["consumers"] == [] and mw.served_ids(RECORD, DISK) == []
    gaps = [r for r in RECORD["releases"] if any(r["licence"]["restrictions"][k] is None for k in mw.RESTRICTIONS)]
    assert gaps
    for r in gaps:
        lic = r["licence"]
        assert mw.release_outcome(r) == "DENY_RELEASE" and r["distributionMode"] == "NONE"
        assert lic["outcome"] in ("DENIED", "UNKNOWN") or (lic["outcome"] == "OPTIONAL_EXPLICIT_REVIEW"
                                                          and lic["decisionRef"] is None)


def test_null_restriction_never_allows():
    probes = mw.check_vectors(VECTORS, mw.policy_facts(DISK))
    assert probes > 0
    case = _case("MW-P2")
    for name in mw.RESTRICTIONS:
        record = copy.deepcopy(case["record"])
        row = record["releases"][0]
        assert mw.release_outcome(row) == "ALLOW"
        row["licence"]["restrictions"][name] = None
        record["nullValues"].append({"row": row["id"], "field": "licence.restrictions." + name, "kind": "UNREAD"})
        assert mw.release_outcome(row) == "DENY_RELEASE"
        assert _record_codes(record, case["sources"]) == ["MW_RESTRICTIONS", "MW_SERVED"]


def test_duplicate_json_key_is_refused():
    raw = DISK(mw.RECORD_PATH)
    bad = raw.replace(b'{\n  "schemaVersion"', b'{\n  "recordVersion": 1,\n  "schemaVersion"', 1)
    assert bad != raw
    assert _codes({mw.RECORD_PATH: bad}) == ["MW_SCHEMA"]


def test_sixty_three_hex_digest_is_refused():
    case = _case("MW-P2")
    file = case["record"]["releases"][0]["weights"]["files"][0]
    file["sha256"] = file["sha256"][:63]
    assert _record_codes(case["record"], case["sources"]) == ["MW_IDENTITY"]


def test_unlisted_null_is_refused():
    record = copy.deepcopy(RECORD)
    record["nullValues"] = record["nullValues"][1:]
    assert _codes({mw.RECORD_PATH: _bytes(record)}) == ["MW_SCHEMA"]


def test_null_outside_the_rule_is_refused():
    record = copy.deepcopy(RECORD)
    record["releases"][0]["licence"]["rule"] = None
    assert _codes({mw.RECORD_PATH: _bytes(record)}) == ["MW_SCHEMA"]


def test_a_served_candidate_row_is_refused():
    record = copy.deepcopy(RECORD)
    record["consumers"] = [{"path": "routes/test-bundle.json", "kind": "ROUTE_BUNDLE", "field": "modelId"}]
    source = _bytes({"routes": [{"routeId": "route-t", "modelId": record["releases"][0]["id"]}]})
    assert _codes({mw.RECORD_PATH: _bytes(record), "routes/test-bundle.json": source}) == ["MW_SERVED"]


def test_policy_pins_are_checked():
    amendment = json.loads(DISK(mw.AMENDMENT_PATH))
    flipped = copy.deepcopy(amendment)
    flipped["base"]["sha256"] = "0" * 64
    assert _codes({mw.AMENDMENT_PATH: _bytes(flipped)}) == ["MW_POLICY"]
    reordered = copy.deepcopy(amendment)
    outcomes = reordered["weightsLicenseClasses"]["outcomes"]
    outcomes[0], outcomes[1] = outcomes[1], outcomes[0]
    assert _codes({mw.AMENDMENT_PATH: _bytes(reordered)}) == ["MW_POLICY"]
    script = amendment["predecessors"][0]["scripts"][0]["path"]
    assert _codes({script: DISK(script) + b"\n"}) == ["MW_POLICY"]


def test_validator_segment_pins():
    amendment = json.loads(DISK(mw.AMENDMENT_PATH))
    pins = [(i, j, s) for i, p in enumerate(amendment["predecessors"]) for j, s in enumerate(p["scripts"])
            if "segment" in s]
    assert sorted(s["path"] for _, _, s in pins) == sorted(mw.SEGMENT_PINNED)
    anchor = (mw.SEGMENT_ANCHOR + "\n").encode("utf-8")
    for i, j, pin in pins:
        path, last = pin["path"], pin["segment"]["lastLine"]
        lines = DISK(path).splitlines(keepends=True)
        assert lines[last] == anchor and lines.count(anchor) == 1
        later = lines[:last + 1] + [b"    # a later count move\n"] + lines[last + 1:]
        assert _codes({path: b"".join(later)}) == []
        inside = list(lines)
        inside[0] = b"#" + inside[0]
        assert _codes({path: b"".join(inside)}) == ["MW_POLICY"]
        renamed = b"".join(lines).replace(anchor, b"def validate_all() -> None:\n")
        assert _codes({path: renamed}) == ["MW_POLICY"]
        short = copy.deepcopy(amendment)
        short["predecessors"][i]["scripts"][j]["segment"].update(
            {"lastLine": last - 1, "sha256": mw.digest(b"".join(lines[:last - 1]))})
        assert _codes({mw.AMENDMENT_PATH: _bytes(short)}) == ["MW_POLICY"]


def test_schema_null_rule_is_checked():
    schema = copy.deepcopy(SCHEMA)
    schema["candidateNullRule"]["fields"] = schema["candidateNullRule"]["fields"][1:]
    assert _codes({mw.SCHEMA_PATH: _bytes(schema)}) == ["MW_SCHEMA"]


def test_a_broken_vector_is_refused():
    vectors = copy.deepcopy(VECTORS)
    vectors["cases"][-1]["expect"]["refusals"] = []
    assert _codes({mw.VECTORS_PATH: _bytes(vectors)}) == ["MW_VECTORS"]
