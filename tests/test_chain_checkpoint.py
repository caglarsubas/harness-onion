"""MET-PERF-047: the chain checkpoint's reader and writer, vectors 1-13 (architecture/chain-checkpoint/vectors.json).
The reader and the writer are loaded by path; every case builds its own small repository under tmp_path, except the
vector-11 case, which reads 281's published authority (architecture/authority-map-authority.json) at this head."""
import ast
import base64
import hashlib
import importlib.util
import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]


def _load(rel, name):
    spec = importlib.util.spec_from_file_location(name, ROOT / rel)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


CK = _load("ci/chain_checkpoint.py", "_t047_chain_checkpoint")
WR = _load("scripts/chain_checkpoint_writer.py", "_t047_chain_checkpoint_writer")
sha = lambda raw: hashlib.sha256(raw).hexdigest()
VECTORS = {v["id"]: v for v in json.loads((ROOT / "architecture/chain-checkpoint/vectors.json").read_bytes())["vectors"]}


def _repo(tmp_path, *, name_it=True, layers=((281, b"V281 = 288\n", b"def test_x():\n    assert 1\n"),), newer=()):
    """A small repository: one record, one checkpoint authority, layer files and optional newer authorities."""
    (tmp_path / "architecture/chain-checkpoint").mkdir(parents=True)
    (tmp_path / "scripts").mkdir()
    (tmp_path / "tests").mkdir()
    entries = []
    for slot, validator, test in layers:
        (tmp_path / ("scripts/validate_l%d.py" % slot)).write_bytes(validator)
        (tmp_path / ("tests/test_l%d.py" % slot)).write_bytes(test)
        (tmp_path / ("data%d.txt" % slot)).write_bytes(b"input %d\n" % slot)
        entries.append({"slot": slot, "module": "validate_l%d" % slot, "validatorPath": "scripts/validate_l%d.py" % slot,
                        "validatorSha256": sha(validator), "testFilePath": "tests/test_l%d.py" % slot,
                        "testFileSha256": sha(test), "inputs": {"data%d.txt" % slot: sha(b"input %d\n" % slot)},
                        "nodes": [{"nodeSha256": sha(("tests/test_l%d.py::test_x" % slot).encode()), "setup": "passed",
                                   "call": "passed", "teardown": "passed"}], "seconds": 1.0})
    record = {"schemaVersion": CK.SCHEMA, "checkpointSlot": 282, "checkpointBaseline": 288,
              "parameters": {"sampleFraction": 0.1}, "layers": entries, "checkPairs": [], "normalisedRecordClass": False}
    raw = (json.dumps(record, sort_keys=True) + "\n").encode()
    (tmp_path / CK.RECORD_PATH).write_bytes(raw)
    auth = {"baselinePackets": {str(i): "x" for i in range(288)}, "newFiles": {CK.RECORD_PATH: sha(raw)} if name_it else {}}
    (tmp_path / "architecture/chain-checkpoint-authority.json").write_text(json.dumps(auth))
    for i, changed in enumerate(newer, 1):
        body = {"baselinePackets": {str(j): "x" for j in range(288 + i)}, "changedFiles": changed,
                "hunkClassContext": {"newPacket": "MET-NEXT-%03d" % i, "prevValidator": "scripts/validate_prev.py",
                                     "prevTest": "tests/test_prev.py", "steps": [1, 1]}}
        (tmp_path / ("architecture/next%d-authority.json" % i)).write_text(json.dumps(body))
    return tmp_path


def _hunk(at, remove, insert, cls):
    return {"at": at, "removeBase64": base64.b64encode(remove).decode(), "insertBase64": base64.b64encode(insert).decode(),
            "class": cls}


def _reader(root, **kw):
    reader = CK.Reader(root=root, tree="0" * 40, out_dir=root, **kw)
    reader.start()
    return reader


def test_inactive_without_a_record(tmp_path):
    reader = CK.Reader(root=tmp_path, tree="0" * 40, out_dir=tmp_path)
    reader.start()
    assert not reader.active and reader.finish("a" * 40) is None


def test_v01_a_tampered_input_is_class_a_naming_its_slot(tmp_path):
    root = _repo(tmp_path)
    (root / "data281.txt").write_bytes(b"changed\n")
    reader = _reader(root)
    assert [(s, p, c) for s, p, c, _ in reader.disagreements] == [(281, "data281.txt", "A")]


def test_v02_a_record_no_authority_names_is_recorded(tmp_path):
    reader = _reader(_repo(tmp_path, name_it=False))
    assert reader.disagreements and reader.disagreements[0][1:3] == (CK.RECORD_PATH, "A")


def test_v03_and_v07_an_outcome_that_differs_is_class_b_and_nothing_raises(tmp_path):
    reader = _reader(_repo(tmp_path))
    for when, outcome in (("setup", "passed"), ("call", "failed"), ("teardown", "passed")):
        reader.report("tests/test_l281.py::test_x", when, outcome)
    line = reader.finish("b" * 40)
    assert [d[2] for d in reader.disagreements] == ["B"] and line.startswith(CK.PREFIX) and "B 1" in line


def test_v04_the_writer_refuses_a_shard_with_an_attested_node(tmp_path):
    (tmp_path / "out").mkdir()
    (tmp_path / "out/shard-1.json").write_text(json.dumps({"attested": ["n"], "collected": 0, "reports": [], "opened": {}}))
    with pytest.raises(SystemExit, match="attested run"):
        WR.assemble(tmp_path, tmp_path / "out", 282)


@pytest.mark.parametrize("pairs", [[{"layerSlot": 279, "ids": ["A-1", "A-1"], "type": "supersession"}],
                                   [{"layerSlot": 279, "ids": ["A-1", "B-1"], "type": "unruled"}],
                                   [{"layerSlot": 279, "ids": ["A-1", "B-1"], "type": "supersession"}] * 2])
def test_v05_a_check_pairs_defect_is_a_class_c_fault(pairs):
    with pytest.raises(CK.Fault):
        CK.check_pairs(pairs)


def test_v06_the_sample_is_seeded_by_the_head_tree():
    slots = list(range(189, 282))
    one = CK.sample("1" * 40, slots, 0.1)
    assert one == CK.sample("1" * 40, slots, 0.1) and one != CK.sample("2" * 40, slots, 0.1)


def test_v08_the_newest_slot_is_recorded_first(tmp_path):
    root = _repo(tmp_path, layers=((280, b"V = 1\n", b"def test_x():\n    pass\n"), (281, b"V = 2\n", b"def test_x():\n    pass\n")))
    (root / "data280.txt").write_bytes(b"x\n")
    (root / "data281.txt").write_bytes(b"y\n")
    assert [d[0] for d in _reader(root).disagreements] == [281, 280]


def test_v09_a_reader_over_the_cap_records_it_and_changes_nothing(tmp_path):
    ticks = iter(range(0, 1000, 20))
    reader = CK.Reader(root=_repo(tmp_path), tree="0" * 40, out_dir=tmp_path, clock=lambda: next(ticks))
    reader.start()
    line = reader.finish("c" * 40)
    assert reader.over_cap and "OVER CAP" in line


def test_v10_the_conftest_loads_the_reader_by_path_inside_a_guard():
    tree = ast.parse((ROOT / "conftest.py").read_bytes())
    guarded = [n for n in ast.walk(tree) if isinstance(n, ast.Try)
               and any(isinstance(h.type, ast.Name) and h.type.id == "Exception" for h in n.handlers)]
    source = (ROOT / "conftest.py").read_text()
    assert '"ci" / "chain_checkpoint.py"' in source and "_planeon_met_perf_047_chain_checkpoint" in source
    assert len(guarded) >= 4    # the load and the three hook calls


def test_v11_a_cascade_hunk_replays_clean(tmp_path):
    before, after = b"N = 288\n", b"N = 289\n"
    root = _repo(tmp_path, layers=((281, before, b"def test_x():\n    pass\n"),),
                 newer=({"scripts/validate_l281.py": {"afterSha256": sha(after), "beforeSha256": sha(before),
                                                      "reverseHunks": [_hunk(6, b"9", b"8", "cascade")]}},))
    (root / "scripts/validate_l281.py").write_bytes(after)
    assert _reader(root).disagreements == []


def test_v11_281s_published_step_classes_as_the_rule_says():
    """281's authority at this head: every hunk of a file still at its afterSha256 re-classes as the v2.2 rule does;
    the only 'other' hunks are validate_readiness's registration block and the master plan's status line."""
    auth = json.loads((ROOT / "architecture/authority-map-authority.json").read_bytes())
    others, checked = set(), 0
    for path, entry in auth["changedFiles"].items():
        live = (ROOT / path).read_bytes() if (ROOT / path).is_file() else b""
        if sha(live) != entry["afterSha256"]:
            continue
        seen = set()
        for h in entry["reverseHunks"]:
            cls = CK.classify(path, live, h["at"], base64.b64decode(h["removeBase64"]), base64.b64decode(h["insertBase64"]),
                              "scripts/validate_met_perf_046.py", "tests/test_met_perf_046.py", "MET-ADOPT-007", (1,), seen=seen)
            checked += 1
            if cls == "other":
                others.add(path)
    assert checked > 0 and others <= {"scripts/validate_readiness.py", "docs/MASTER_DEVELOPMENT_PLAN.md"}


def test_v12_one_byte_beside_the_cascade_is_class_a(tmp_path):
    before, after = b"N = 288\n", b"N = 289\n"
    root = _repo(tmp_path, layers=((281, before, b"def test_x():\n    pass\n"),),
                 newer=({"scripts/validate_l281.py": {"afterSha256": sha(after), "beforeSha256": sha(before),
                                                      "reverseHunks": [_hunk(6, b"9", b"8", "cascade")]}},))
    (root / "scripts/validate_l281.py").write_bytes(after + b"#")
    found = _reader(root).disagreements
    assert [(d[0], d[2]) for d in found] == [(281, "A")] and "afterSha256" in found[0][3]


def test_v13_a_reordered_hunk_is_recorded_naming_the_slot(tmp_path):
    before, after = b"A = 288\nB = 288\n", b"A = 289\nB = 289\n"
    hunks = [_hunk(14, b"9", b"8", "cascade"), _hunk(6, b"9", b"8", "cascade")]
    root = _repo(tmp_path, layers=((281, before, b"def test_x():\n    pass\n"),),
                 newer=({"scripts/validate_l281.py": {"afterSha256": sha(after), "beforeSha256": sha(before), "reverseHunks": hunks}},))
    (root / "scripts/validate_l281.py").write_bytes(after)
    found = _reader(root).disagreements
    assert found and found[0][0] == 281 and "out of order" in found[0][3]


def test_a_recorded_class_that_fails_the_recheck_is_recorded(tmp_path):
    before, after = b"N = 'a'\n", b"N = 'b'\n"
    root = _repo(tmp_path, layers=((281, before, b"def test_x():\n    pass\n"),),
                 newer=({"scripts/validate_l281.py": {"afterSha256": sha(after), "beforeSha256": sha(before),
                                                      "reverseHunks": [_hunk(5, b"b", b"a", "cascade")]}},))
    (root / "scripts/validate_l281.py").write_bytes(after)
    found = _reader(root).disagreements
    assert found and "fails the re-check" in found[0][3]


def test_the_reader_is_active_only_in_the_outermost_session():
    code = ("import importlib.util as u; s = u.spec_from_file_location('m', %r); m = u.module_from_spec(s); "
            "s.loader.exec_module(m); print(m.OUTERMOST)") % str(ROOT / "ci/chain_checkpoint.py")
    env = {k: v for k, v in os.environ.items() if k != CK.SERIAL_ENV}
    outer = subprocess.run([sys.executable, "-I", "-c", code], env=env, capture_output=True, text=True, check=True).stdout
    inner = subprocess.run([sys.executable, "-I", "-c", code], env=dict(env, **{CK.SERIAL_ENV: "1"}), capture_output=True,
                           text=True, check=True).stdout
    assert (outer.strip(), inner.strip()) == ("True", "False")


def test_every_vector_has_a_test():
    names = {n.name for n in ast.parse(Path(__file__).read_bytes()).body if isinstance(n, ast.FunctionDef)}
    for vid in VECTORS:
        assert any(n.startswith("test_v%02d" % vid) or ("_v%02d_" % vid) in n for n in names), vid
