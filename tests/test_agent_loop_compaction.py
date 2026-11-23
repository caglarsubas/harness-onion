"""MET-013 (HR-COMPACTION-GOV-001): the agent-loop compaction record, its reference model and its checker.

The live record passes the checker (scripts/validate_agent_loop_compaction.py, CG_SHAPE to CG_VECTOR) and validates
against its schema (architecture/agent-loop-compaction/schema.json, JSON Schema draft 2020-12, with the repository's
pinned jsonschema), as do the vectors; every vector replays to its expectation through the model
(scripts/agent_loop_compaction.py), every family has a positive and a negative vector and every model code is refused by
one; the byte-stable prompt digests are recomputed here; then in-memory failing cases for each checker code
(CONTRACT_295 r3 section 3a). Every case mutates a copy of the live bytes behind an injected reader; no file is
written."""
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


CG = _load("scripts/validate_agent_loop_compaction.py", "validate_agent_loop_compaction_under_test")
MODEL = _load("scripts/agent_loop_compaction.py", "agent_loop_compaction_under_test")
READ = CG.disk_reader(ROOT)
RECORD = json.loads(READ(CG.RECORD_PATH))
SCHEMA = json.loads(READ(CG.SCHEMA_PATH))
VECTORS = json.loads(READ(CG.VECTORS_PATH))


def _bytes(value):
    return (json.dumps(value, indent=2, ensure_ascii=False) + "\n").encode("utf-8")


def _reader(record=None, vectors=None, files=None):
    """A reader over the live bytes with overrides; a mutated vectors file is re-pinned in the record."""
    record = copy.deepcopy(RECORD if record is None else record)
    over = dict(files or {})
    if vectors is not None:
        over[CG.VECTORS_PATH] = _bytes(vectors)
        record["vectors"]["sha256"] = hashlib.sha256(over[CG.VECTORS_PATH]).hexdigest()
    over[CG.RECORD_PATH] = _bytes(record)
    return lambda path: over[path] if path in over else READ(path)


def _codes(record=None, vectors=None, files=None):
    return [code for code, _ in CG.check(_reader(record, vectors, files))]


def test_the_live_record_passes_and_validates_against_its_schema():
    assert CG.check(READ) == []
    jsonschema.Draft202012Validator.check_schema(SCHEMA)
    assert list(jsonschema.Draft202012Validator(SCHEMA).iter_errors(RECORD)) == []
    vectors_schema = dict(SCHEMA["$defs"]["vectorsFile"], **{"$defs": SCHEMA["$defs"]})
    assert list(jsonschema.Draft202012Validator(vectors_schema).iter_errors(VECTORS)) == []


def test_every_vector_replays_and_every_model_code_is_refused():
    cases = VECTORS["cases"]
    listed = [v for f in RECORD["ruleFamilies"] for v in f["vectors"]]
    assert len(listed) == len(set(listed)) == len(cases) > 0
    refused = set()
    for case in cases:
        ok, got = MODEL.replay(case)
        assert ok, (case["id"], got)
        if case["polarity"] == "NEGATIVE":
            refused.add(got)
    assert refused == set(MODEL.CODES.values())
    for family in RECORD["ruleFamilies"]:
        polarities = {c["polarity"] for c in cases if c["family"] == family["id"]}
        assert polarities == {"POSITIVE", "NEGATIVE"}, family["id"]


def test_the_prompt_digests_are_recomputed_from_the_prompt_bytes():
    seen = 0
    for case in VECTORS["cases"]:
        if case["family"] == "C6" and case["polarity"] == "POSITIVE":
            prompts = [s["prompt"] for s in case["input"]["steps"] if s["kind"] == "MODEL"]
            want = ["sha256:" + hashlib.sha256(p.encode("utf-8")).hexdigest() for p in prompts]
            assert case["expect"]["result"]["digests"] == want
            seen += 1
    assert seen > 0


def test_the_record_is_a_successor_of_the_base_contract_which_stays_unchanged():
    assert RECORD["stepKinds"] == RECORD["baseVocabulary"]["stepKinds"] + ["COMPACT"]
    assert "COMPACT" not in RECORD["baseVocabulary"]["stepKinds"]
    assert not CG.IMPORTS_BASE.search(READ(CG.MODEL_PATH))
    for key, path in CG.BASIS.items():
        assert RECORD["basis"][key]["sha256"] == hashlib.sha256(READ(path)).hexdigest()


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


def _first(polarity, family=None):
    return next(c["id"] for c in VECTORS["cases"] if c["polarity"] == polarity and family in (None, c["family"]))


def _sole(polarity, family):
    ids = [c["id"] for c in VECTORS["cases"] if c["polarity"] == polarity and c["family"] == family]
    assert len(ids) == 1, ids
    return ids[0]


SHAPE = [
    lambda: _codes(record=_record(lambda r: r.update(extra=1))),
    lambda: _codes(record=_record(lambda r: r.pop("outOfScope"))),
    lambda: _codes(record=_record(lambda r: r["ruleFamilies"][0].update(refusal="CG_RANGE"))),
    lambda: _codes(record=_record(lambda r: r["ruleFamilies"].reverse())),
    lambda: _codes(record=_record(lambda r: r["stepKinds"].pop())),
    lambda: _codes(record=_record(lambda r: r["profileDefaults"].update(cooldownSeconds=[60, 300]))),
    lambda: _codes(vectors=_vectors(lambda v: v["cases"][0].pop("title"))),
    lambda: _codes(vectors=_vectors(lambda v: v["cases"][0].update(polarity="NEGATIVE"))),
]
BASIS = [
    lambda: _codes(record=_record(lambda r: r["schema"].update(sha256="0" * 64))),
    lambda: _codes(record=_record(lambda r: r["basis"]["readme"].update(sha256="0" * 64))),
    lambda: _codes(record=_record(lambda r: r["successorOf"].update(status="WITHDRAWN"))),
    lambda: _codes(record=_record(lambda r: r["baseVocabulary"].update(trustLabels=["TRUSTED_TOOL_OUTPUT"]))),
]
VECTOR = [
    lambda: _codes(vectors=_vectors(lambda v: _case(v, _first("NEGATIVE", "C2"))["expect"].update(refuse="CG_LOCK"))),
    lambda: _codes(vectors=_vectors(lambda v: _case(v, "CG-C4-P4")["expect"]["result"].update(cooldowns=[60, 60, 60]))),
    lambda: _codes(record=_record(lambda r: r["ruleFamilies"][0]["vectors"].pop())),
    lambda: _codes(record=_record(lambda r: r["ruleFamilies"][1]["vectors"].append(r["ruleFamilies"][0]["vectors"][0]))),
    lambda: _codes(vectors=_vectors(lambda v: v["cases"].remove(_case(v, _sole("POSITIVE", "C2")))),
                   record=_record(lambda r: r["ruleFamilies"][1]["vectors"].remove(_sole("POSITIVE", "C2")))),
]


@pytest.mark.parametrize("run, code", [(f, "CG_SHAPE") for f in SHAPE] + [(f, "CG_BASIS") for f in BASIS]
                         + [(f, "CG_VECTOR") for f in VECTOR])
def test_each_checker_code_has_failing_cases(run, code):
    assert run() == [code]


def test_a_model_that_imports_the_base_model_is_refused():
    raw = READ(CG.MODEL_PATH).replace(b"import hashlib\n", b"import hashlib\nfrom scripts import agent_loop\n", 1)
    assert raw != READ(CG.MODEL_PATH)
    record = _record(lambda r: r["model"].update(sha256=hashlib.sha256(raw).hexdigest()))
    assert _codes(record=record, files={CG.MODEL_PATH: raw}) == ["CG_BASIS"]


@pytest.mark.parametrize("family, data, code", [
    ("C1", {"events": [{"op": "lock"}, {"op": "step", "kind": "TOOL", "own": False}]}, "CG_LOCK"),
    ("C4", {"profile": {"cooldowns": [60, 300, 900]}, "events": [{"op": "handoff"}]}, "CG_LADDER"),
    ("C9", {"profile": {"routes": ["r"]}, "summary": {"kind": "MODEL", "route": "r", "gate": "FAIL",
                                                     "hooks": list(MODEL.QUERY_HOOKS)},
            "consumers": [{"kind": "DELIVERY"}]}, "CG_GATE"),
])
def test_further_refusals_of_the_model(family, data, code):
    assert MODEL.evaluate(family, data) == (code, {})
