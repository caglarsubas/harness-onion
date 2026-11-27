"""MET-013 (HR-REPLAY-FIXTURES-001): the replay-fixture record, its worked example, its reference model and its checker.

The live record passes the checker (scripts/validate_replay_fixtures.py, RF_SHAPE to RF_VECTOR) and validates against
its schema (architecture/replay-fixtures/schema.json, JSON Schema draft 2020-12, with the repository's pinned
jsonschema), as do the vectors and every stored document against its shape's definition. Every vector replays through
the model (scripts/replay_fixtures.py, with MAS-RA-002's scripts/run_manifest.py), every record refusal code and every
verdict is reached; the draft's content digests are recomputed here from the bytes; the worked example's digest chain
is the two-run chain of ruling D1 (M0 -> t1 -> fixture -> F -> M1 -> r1 -> scoring record); the HELD_OUT_PUBLIC document
is built here in memory; then in-memory failing cases for each checker code (CONTRACT_295 r4 section 3b). Every case
mutates a copy of the live bytes behind an injected reader; no file is written."""
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


RF = _load("scripts/validate_replay_fixtures.py", "validate_replay_fixtures_under_test")
MODEL = _load("scripts/replay_fixtures.py", "replay_fixtures_under_test")
RM = _load("scripts/run_manifest.py", "run_manifest_for_replay_fixtures_under_test")
DR = _load("scripts/decision_record.py", "decision_record_for_replay_fixtures_under_test")   # injected (MET-016 F5)
READ = RF.disk_reader(ROOT)
RECORD = json.loads(READ(RF.RECORD_PATH))
SCHEMA = json.loads(READ(RF.SCHEMA_PATH))
VECTORS = json.loads(READ(RF.VECTORS_PATH))
STORES = VECTORS["stores"]


def _bytes(value):
    return (json.dumps(value, indent=2, ensure_ascii=False) + "\n").encode("utf-8")


def _pins(record):
    yield record["schema"]
    yield record["vectors"]
    yield record["model"]
    yield from record["basis"].values()
    yield record["store"]["split"]
    for key in ("fixtures", "trajectories", "blobs"):
        yield from record["store"][key]


def _reader(record=None, vectors=None, files=None):
    """A reader over the live bytes with overrides; every overridden file the record pins is re-pinned."""
    record = copy.deepcopy(RECORD if record is None else record)
    over = dict(files or {})
    if vectors is not None:
        over[RF.VECTORS_PATH] = _bytes(vectors)
    for pin in _pins(record):
        if pin["path"] in over:
            pin["sha256"] = hashlib.sha256(over[pin["path"]]).hexdigest()
    over[RF.RECORD_PATH] = _bytes(record)
    return lambda path: over[path] if path in over else READ(path)


def _codes(record=None, vectors=None, files=None):
    return [code for code, _ in RF.check(_reader(record, vectors, files))]


def _validator(name):
    return jsonschema.Draft202012Validator(dict(SCHEMA["$defs"][name], **{"$defs": SCHEMA["$defs"]}))


def _canonical_digest(value):
    raw = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def test_the_live_record_passes_and_every_document_validates_against_its_shape():
    assert RF.check(READ) == []
    jsonschema.Draft202012Validator.check_schema(SCHEMA)
    assert list(jsonschema.Draft202012Validator(SCHEMA).iter_errors(RECORD)) == []
    assert list(_validator("vectorsFile").iter_errors(VECTORS)) == []
    for row in RECORD["store"]["fixtures"]:
        assert list(_validator("fixture").iter_errors(json.loads(READ(row["path"])))) == []
    for row in RECORD["store"]["trajectories"]:
        assert list(_validator("trajectory").iter_errors(json.loads(READ(row["path"])))) == []
    shapes = {"SCORE": ("score", "score"), "VERDICT": ("verdict", "verdict"), "ARM_PAIR": ("pair", "armPair")}
    seen = 0
    for case in VECTORS["cases"]:
        if case["polarity"] == "POSITIVE" and case["check"] in shapes:
            key, name = shapes[case["check"]]
            assert list(_validator(name).iter_errors(case["input"][key])) == [], case["id"]
            seen += 1
    assert seen > 0


def test_every_vector_replays_and_every_code_and_verdict_is_reached():
    cases = VECTORS["cases"]
    listed = [v for f in RECORD["ruleFamilies"] for v in f["vectors"]]
    assert len(listed) == len(set(listed)) == len(cases) > 0
    refused, verdicts = set(), set()
    for case in cases:
        ok, got = MODEL.replay_case(case, STORES, RM, DR)
        assert ok, (case["id"], got)
        if case["polarity"] == "NEGATIVE":
            refused.add(got)
        elif case["check"] == "REPLAY":
            verdicts.add(got["verdict"])
    assert set(MODEL.RECORD_CODES) <= refused
    assert verdicts == set(MODEL.VERDICTS)


def test_replay_vectors_is_replay_case_per_vector():
    """The head's per-vector entry point (ORC-295-C2-Q2 (a)): replay_case's verdict for each vector, in order; one
    changed expectation makes exactly one False."""
    cases = VECTORS["cases"]
    got = MODEL.replay_vectors(cases, STORES, RM, DR)
    assert got == [MODEL.replay_case(case, STORES, RM, DR)[0] for case in cases] and len(got) == len(cases) > 0
    assert all(ok is True for ok in got)
    changed = copy.deepcopy(cases)
    next(case for case in changed if case["polarity"] == "NEGATIVE")["expect"] = {"refuse": "NOT_A_CODE"}
    assert MODEL.replay_vectors(changed, STORES, RM, DR).count(False) == 1


def test_evaluator_error_evidence_needs_the_injected_decision_model():
    """MET-016 F5: the EVALUATOR_ERROR evidence is checked by GR-DECISION-RECORD-001's model, injected as `dr`; without
    it the bound record cannot be checked and the result is refused, and the record is bound by computed digest."""
    case = next(c for c in VECTORS["cases"] if c["id"] == "RF-BL-P1")
    ok, got = MODEL.replay_case(case, STORES, RM, DR)
    assert ok and got["enters"] is False
    assert MODEL.evaluate(case["check"], case["input"], STORES, RM) == ("BLOCKER_UNEVIDENCED", {})
    record = case["input"]["gradeRecords"][0]
    keyed = copy.deepcopy(case)
    keyed["input"]["gradeRecords"] = {MODEL.digest(record): record}   # a store keyed by digest is not a supplied list
    assert MODEL.evaluate(keyed["check"], keyed["input"], STORES, RM, DR) == ("BLOCKER_UNEVIDENCED", {})


def test_the_drafts_content_digests_are_the_bytes_digests():
    want = {b"hello\n": "5891b5b522d5df086d0ff0b110fbd9d21bb4fc7163af34d08286a2e846f6be03",
            b"hello, world\n": "853ff93762a06ddbf722c4ebe9ddd66d8f63ddaea97f521c3ecc20da7c976020",
            b"#!/bin/sh\necho ok\n": "b4d644d4279594903f1a9911956432d9473041f2984fc6014c14d7402c7d126c"}
    for raw, hexd in want.items():
        assert hashlib.sha256(raw).hexdigest() == hexd
    entries = {}
    for row in RECORD["store"]["fixtures"]:
        fixture = json.loads(READ(row["path"]))
        for tree in ("workspaceBefore", "expectedAfter"):
            for e in fixture[tree]["entries"]:
                entries[(fixture["taskId"], tree, e["path"])] = (e["kind"], e["digest"][len("sha256:"):])
    assert entries[("fx-dev-0001", "workspaceBefore", "greeting.txt")] == ("FILE", want[b"hello\n"])
    assert entries[("fx-dev-0001", "expectedAfter", "greeting.txt")] == ("FILE", want[b"hello, world\n"])
    assert entries[("fx-dev-0002", "expectedAfter", "bin/check.sh")] == ("EXECUTABLE", want[b"#!/bin/sh\necho ok\n"])
    assert entries[("fx-dev-0002", "expectedAfter", "greeting.txt")] == ("FILE", want[b"hello\n"])
    for row in RECORD["store"]["blobs"]:
        assert hashlib.sha256(READ(row["path"])).hexdigest() == row["path"].rsplit("/", 1)[1]


def test_the_worked_example_is_the_two_run_chain_of_ruling_d1():
    fixtures = [json.loads(READ(row["path"])) for row in RECORD["store"]["fixtures"]]
    t1 = {_canonical_digest(t): t for t in (json.loads(READ(r["path"])) for r in RECORD["store"]["trajectories"])}
    m0 = {_canonical_digest(t["manifest"]) for t in t1.values()}
    assert len(m0) == 1
    for fixture in fixtures:
        assert fixture["trajectoryDigest"] in t1 and fixture["split"]["partition"] == "DEVELOPMENT"
        assert _canonical_digest(fixture) == MODEL.digest(fixture)
    befores = sorted(_canonical_digest(f["workspaceBefore"]) for f in fixtures)
    assert next(iter(t1.values()))["manifest"]["locks"]["fixtureDigest"] == _canonical_digest(befores)
    fset = sorted(_canonical_digest(f) for f in fixtures)
    u2 = next(c for c in VECTORS["cases"] if c["id"] == "RF-SC-P1")["input"]
    m1 = STORES["manifests"][u2["score"]["manifestDigest"]]
    assert u2["fixtureSet"] == fset and m1["locks"]["fixtureDigest"] == _canonical_digest(fset)
    assert _canonical_digest(m1) not in m0
    for r in u2["score"]["results"]:
        trajectory = STORES["trajectories"][r["trajectoryDigest"]]
        assert r["trajectoryDigest"] not in t1 and _canonical_digest(trajectory["manifest"]) == u2["score"]["manifestDigest"]
    assert [(r["outcome"], r["score"]) for r in u2["score"]["results"]] == [("PASSED", 1_000_000), ("ERRORED", 0)]


def test_a_held_out_fixture_built_in_memory_is_refused_in_a_public_store():
    row = RECORD["store"]["fixtures"][0]
    document = json.loads(READ(row["path"]))
    document["split"]["partition"] = "HELD_OUT"
    with pytest.raises(MODEL.Refused) as caught:
        MODEL.check_fixture(document, {})
    assert caught.value.code == "HELD_OUT_PUBLIC"
    assert MODEL.check_fixture(document, {}, public=False)["partition"] == "HELD_OUT"


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


FIXTURE_ROW = RECORD["store"]["fixtures"][0]["path"]
SPLIT_ROW = RECORD["store"]["split"]["path"]


def _edited_fixture():
    fixture = json.loads(READ(FIXTURE_ROW))
    fixture["ignoredPaths"] = [{"path": "notes.txt", "reason": "scratch output"}]
    return {FIXTURE_ROW: _bytes(fixture)}


def _edited_trajectory():
    """The recording run's lock moved off the fixture lock rule: the stored t1 changes, so its fixture no longer names it."""
    path = RECORD["store"]["trajectories"][0]["path"]
    trajectory = json.loads(READ(path))
    trajectory["manifest"]["locks"]["fixtureDigest"] = "sha256:" + "1" * 64
    return {path: _bytes(trajectory)}


SHAPE = [
    lambda: _codes(record=_record(lambda r: r.update(extra=1))),
    lambda: _codes(record=_record(lambda r: r["refusalOrder"].reverse())),
    lambda: _codes(record=_record(lambda r: r["ruleFamilies"].reverse())),
    lambda: _codes(record=_record(lambda r: r["exitCodes"]["BLOCKED"].append("EVALUATOR_ERROR"))),
    lambda: _codes(record=_record(lambda r: r["store"]["blobs"][0].update(path=RF.DIR + "blobs/renamed"))),
    lambda: _codes(vectors=_vectors(lambda v: v["cases"][0].pop("title"))),
    lambda: _codes(vectors=_vectors(lambda v: v["stores"].pop("blobs"))),
]
BASIS = [
    lambda: _codes(record=_record(lambda r: r["schema"].update(sha256="0" * 64))),
    lambda: _codes(record=_record(lambda r: r["basis"]["model"].update(sha256="0" * 64))),
    lambda: _codes(record=_record(lambda r: r["store"]["trajectories"][0].update(sha256="0" * 64))),
]
STORE = [
    lambda: _codes(files=_edited_fixture()),
    lambda: _codes(vectors=_vectors(lambda v: v["stores"]["blobs"].update({"sha256:" + "0" * 64: "not its digest"}))),
    lambda: _codes(files=_edited_trajectory()),
]
VECTOR = [
    lambda: _codes(vectors=_vectors(lambda v: _case(v, "RF-SC-N1")["expect"].update(refuse="OUTCOME_MISMATCH"))),
    lambda: _codes(vectors=_vectors(lambda v: _case(v, "RF-RP-P5")["expect"]["result"].update(divergedAtStep=3))),
    lambda: _codes(record=_record(lambda r: r["ruleFamilies"][0]["vectors"].pop())),
    lambda: _codes(record=_record(lambda r: r["ruleFamilies"][0]["codes"].append("FIXTURE_BINDING"))),
    lambda: _codes(record=_record(lambda r: next(f for f in r["ruleFamilies"] if f["id"] == "PLACEMENT")["vectors"]
                                  .remove("RF-PL-P1")),
                   vectors=_vectors(lambda v: v["cases"].remove(_case(v, "RF-PL-P1")))),
]


@pytest.mark.parametrize("run, code", [(f, "RF_SHAPE") for f in SHAPE] + [(f, "RF_BASIS") for f in BASIS]
                         + [(f, "RF_STORE") for f in STORE] + [(f, "RF_VECTOR") for f in VECTOR])
def test_each_checker_code_has_failing_cases(run, code):
    assert run() == [code]
