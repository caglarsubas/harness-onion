"""MET-PERF-047: the chain checkpoint's reader and writer, vectors 1-13 (architecture/chain-checkpoint/vectors.json).
Each case builds its own small repository under tmp_path, except the vector-11 case on 281's published authority,
which rebuilds 281's edited files to each beforeSha256 with the reader's own rebuild, under 281's context, after every
newer authority's replay: it never requires a file to be still at 281's afterSha256. Its pending files are accepted by
rule (P047-C2-1, P047-C3-4): a later slot's real edit, or an unauthored file, which must be none in every runner
execution (HARNESS_OFFLINE_ENFORCED=1: a verify or a dry run). Of this module, only that case reads the variable;
main's offline-runner and isolation tests read it too, and the reader reads none."""
import ast
import base64
import copy
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
PARTIAL_OK = {"scripts/validate_readiness.py", "docs/MASTER_DEVELOPMENT_PLAN.md"}   # 281's own `other` hunks
LATER_EDIT = "of a class not normalised"   # a newer authority's real edit, as rebuild() words it


def _ctx(packet):
    return {"authorityPacket": packet, "hunkClassVocabulary": list(CK.CLASSES), "hunkClassRuleSha256": CK.RULE_SHA256,
            "hunkClassContext": {"newPacket": packet, "prevValidator": "scripts/validate_prev.py",
                                 "prevTest": "tests/test_prev.py", "steps": [1, 1]}}


def _repo(tmp_path, *, name_it=True, layers=((281, b"V281 = 288\n"),), newer=(), shadow_in="verify", stale=False):
    for d in ("architecture/chain-checkpoint", "scripts", "tests"):
        (tmp_path / d).mkdir(parents=True, exist_ok=True)
    entries = []
    for slot, validator in layers:
        test, auth = b"def test_x():\n    assert 1\n", b'{"layer": %d}\n' % slot
        for rel, raw in (("scripts/validate_l%d.py" % slot, validator), ("tests/test_l%d.py" % slot, test),
                         ("architecture/l%d-authority.json" % slot, auth), ("data%d.txt" % slot, b"input %d\n" % slot)):
            (tmp_path / rel).write_bytes(raw)
        entries.append({"slot": slot, "module": "validate_l%d" % slot, "validatorPath": "scripts/validate_l%d.py" % slot,
                        "validatorSha256": sha(validator), "testFilePath": "tests/test_l%d.py" % slot, "testFileSha256": sha(test),
                        "authorityPath": "architecture/l%d-authority.json" % slot, "authoritySha256": sha(auth),
                        "inputs": {"data%d.txt" % slot: sha(b"input %d\n" % slot)}, "seconds": 1.0,
                        "nodes": [{"nodeSha256": sha(("tests/test_l%d.py::test_x" % slot).encode()), "setup": "passed",
                                   "call": "passed", "teardown": "passed"}]})
    record = {"schemaVersion": CK.SCHEMA, "checkpointSlot": 282, "checkpointBaseline": 288, "layers": entries,
              "parameters": {"sampleFraction": 0.1, "shadowIn": shadow_in}, "checkPairs": [], "normalisedRecordClass": False}
    raw = (json.dumps(record, sort_keys=True) + "\n").encode()
    (tmp_path / CK.RECORD_PATH).write_bytes(raw)
    (tmp_path / "architecture/chain-checkpoint-authority.json").write_text(json.dumps(
        {"baselinePackets": {str(i): "x" for i in range(288)}, "newFiles": {CK.RECORD_PATH: sha(raw)} if name_it else {}}))
    if stale:
        (tmp_path / "architecture/zz-authority.json").write_text(json.dumps(
            {"baselinePackets": {str(i): "x" for i in range(300)}, "changedFiles": {CK.RECORD_PATH: {"afterSha256": "0" * 64}}}))
    for i, changed in enumerate(newer, 1):
        body = {"baselinePackets": {str(j): "x" for j in range(288 + i)}, "changedFiles": changed, **_ctx("MET-NEXT-%03d" % i)}
        (tmp_path / ("architecture/next%d-authority.json" % i)).write_text(json.dumps(body))
    return tmp_path


def _hunk(at, remove, insert, cls):
    return {"at": at, "removeBase64": base64.b64encode(remove).decode(), "insertBase64": base64.b64encode(insert).decode(),
            "class": cls}


def _reader(root, **kw):
    reader = CK.Reader(root=root, tree="0" * 40, **kw)
    reader.start()
    return reader


def _cascade_repo(tmp_path, live_extra=b"", hunks=None, before=b"N = 288\n", after=b"N = 289\n"):
    hunks = hunks or [_hunk(6, b"9", b"8", "cascade")]
    root = _repo(tmp_path, layers=((281, before),), newer=({"scripts/validate_l281.py": {
        "afterSha256": sha(after), "beforeSha256": sha(before), "reverseHunks": hunks}},))
    (root / "scripts/validate_l281.py").write_bytes(after + live_extra)
    return root


def test_inactive_without_a_record(tmp_path):
    reader = CK.Reader(root=tmp_path, tree="0" * 40)
    reader.start()
    assert not reader.active and reader.finish("a" * 40) == (None, None)


def test_v01_a_tampered_input_is_class_a_naming_its_slot(tmp_path):
    root = _repo(tmp_path)
    (root / "data281.txt").write_bytes(b"changed\n")
    assert [(s, p, c) for s, p, c, *_ in _reader(root).disagreements] == [(281, "data281.txt", "A")]


def test_v01_a_tampered_layer_authority_is_class_a(tmp_path):
    root = _repo(tmp_path)
    (root / "architecture/l281-authority.json").write_bytes(b"{}\n")
    assert [(s, p, c) for s, p, c, *_ in _reader(root).disagreements] == [(281, "architecture/l281-authority.json", "A")]


def test_v02_an_unnamed_record_is_recorded(tmp_path):
    found = _reader(_repo(tmp_path, name_it=False)).disagreements
    assert found[0][1:3] == (CK.RECORD_PATH, "A") and "unnamed" in found[0][3]


def test_v02_a_stale_record_is_recorded(tmp_path):
    found = _reader(_repo(tmp_path, stale=True)).disagreements
    assert found[0][1:3] == (CK.RECORD_PATH, "A") and "stale" in found[0][3]


def test_v03_and_v07_an_outcome_that_differs_is_class_b_and_the_record_holds_it(tmp_path):
    reader = _reader(_repo(tmp_path))
    for when, outcome in (("setup", "passed"), ("call", "failed"), ("teardown", "passed")):
        reader.report("tests/test_l281.py::test_x", when, outcome, 0.5)
    line, record = reader.finish("b" * 40)
    assert [d["class"] for d in record["disagreements"]] == ["B"] and line.startswith(CK.PREFIX)
    layer = record["layers"]["281"]
    assert layer["agree"] is False and layer["writingSeconds"] == 1.0 and layer["liveSeconds"] == 1.5
    assert record["attested"] == [281] and record["workersSource"]


def test_v04_the_writer_refuses_an_attested_reader_and_an_out_dir_inside(tmp_path):
    wt = tmp_path / "wt"
    (wt / "ci").mkdir(parents=True)
    (wt / "ci/chain_checkpoint.py").write_text('MODE = "sampled"\n')
    with pytest.raises(SystemExit, match="shadow mode"):
        WR.assemble(wt, tmp_path / "out", 282, "unused", measure_only=True)
    with pytest.raises(SystemExit, match="inside the worktree"):
        WR.assemble(wt, wt / "out", 282, "unused", measure_only=True)


@pytest.mark.parametrize("pairs", [[{"layerSlot": 279, "ids": ["A-1", "A-1"], "type": "supersession"}],
                                   [{"layerSlot": 279, "ids": ["A-1", "B-1"], "type": "unruled"}],
                                   [{"layerSlot": 279, "ids": ["A-1", "B-1"], "type": "supersession"}] * 2])
def test_v05_a_check_pairs_defect_is_a_class_c_fault(pairs):
    assert CK.check_pairs(pairs)


def test_v06_the_sample_is_seeded_by_the_head_tree():
    slots = list(range(189, 282))
    one = CK.sample("1" * 40, slots, 0.1)
    assert one == CK.sample("1" * 40, slots, 0.1) and one != CK.sample("2" * 40, slots, 0.1)


def test_v08_the_newest_slot_is_recorded_first(tmp_path):
    root = _repo(tmp_path, layers=((280, b"V = 1\n"), (281, b"V = 2\n")))
    (root / "data280.txt").write_bytes(b"x\n")
    (root / "data281.txt").write_bytes(b"y\n")
    assert [d[0] for d in _reader(root).disagreements] == [281, 280]


def test_v09_the_budget_stops_the_replay_as_class_c_over_budget(tmp_path):
    ticks = iter(range(0, 10 ** 6, 20))
    reader = CK.Reader(root=_repo(tmp_path), tree="0" * 40, clock=lambda: next(ticks))
    reader.start()
    line, record = reader.finish("c" * 40)
    assert reader.over_cap and "OVER CAP" in line
    # the budget stops before the ledger is read: the head slot is unknown, and the record says so (P047-C3-2)
    assert any((d["class"], d["kind"], d["slot"]) == ("C", "over-budget", None) and "head slot unknown (the ledger was not read)"
               in d["detail"] for d in record["disagreements"])


def test_v09_dry_run_only_skips_in_session_and_the_runner_compares(tmp_path):
    root = _repo(tmp_path, shadow_in="dryRunOnly")
    inside = _reader(root)
    assert inside.mode.startswith("dry-run-only") and [(d[2], d[4]) for d in inside.disagreements] == [("C", "skipped")]
    _, skipped = inside.finish("d" * 40)
    first = skipped["disagreements"][0]
    assert (first["countEffect"], first["slot"]) == ("neutral", 282) and "head slot 282, checkpoint slot 282" in first["detail"]
    node = sha(b"tests/test_l281.py::test_x")
    log = tmp_path / "argv63.log"
    log.write_text("\n".join("PYTEST_DIAGNOSTIC=" + json.dumps({"event": "END", "node": node, "phase": p, "outcome": "passed",
                                                                 "durationUs": 1000}) for p in ("setup", "call", "teardown")) + "\n")
    line = CK.dry_run_compare(log, tmp_path / "shadow.json", root=root)
    record = json.loads((tmp_path / "shadow.json").read_text())
    assert record["mode"] == "compare" and record["layers"]["281"]["agree"] is True and "mode compare" in line


def test_v10_the_conftest_loads_the_reader_by_path_inside_a_guard():
    source = (ROOT / "conftest.py").read_text()
    tree = ast.parse(source)
    guarded = [n for n in ast.walk(tree) if isinstance(n, ast.Try)
               and any(isinstance(h.type, ast.Name) and h.type.id == "Exception" for h in n.handlers)]
    assert '"ci" / "chain_checkpoint.py"' in source and "_planeon_met_perf_047_chain_checkpoint" in source
    assert len(guarded) == 5     # main's conftest has none: the line writer, the load and three hooks (P047-C3-5)
    functions = {n.name: n for n in tree.body if isinstance(n, ast.FunctionDef)}
    for name in ("_checkpoint_line", "pytest_sessionstart", "pytest_runtest_logreport", "pytest_unconfigure"):
        last = functions[name].body[-1]
        assert isinstance(last, ast.Try) and any(isinstance(h.type, ast.Name) and h.type.id == "Exception"
                                                 for h in last.handlers), name


def test_v11_a_cascade_hunk_replays_clean(tmp_path):
    assert _reader(_cascade_repo(tmp_path)).disagreements == []


def test_v11_281s_edited_files_rebuild_to_their_before_digests():
    auth = json.loads((ROOT / "architecture/authority-map-authority.json").read_bytes())
    ctx = {"newPacket": "MET-ADOPT-007", "prevValidator": "scripts/validate_met_perf_046.py",
           "prevTest": "tests/test_met_perf_046.py", "steps": [1, 1]}
    classed = copy.deepcopy(auth)
    classed.update(authorityPacket="MET-ADOPT-007", hunkClassVocabulary=list(CK.CLASSES), hunkClassRuleSha256=CK.RULE_SHA256,
                   hunkClassContext=ctx)
    newer = CK.newer_authorities(ROOT, len(auth["baselinePackets"]))
    norm, exact, partial, pending, unauthored = frozenset(("bridge", "cascade", "record")), 0, set(), 0, set()
    for path, entry in classed["changedFiles"].items():
        live = (ROOT / path).read_bytes()
        at281, reverted, unexplained = CK.rebuild(path, live, newer, norm)
        if unexplained or sha(at281) != entry["afterSha256"]:
            later = bool(unexplained) and all(detail.endswith(LATER_EDIT) for _, detail in unexplained)
            if CK.unauthored(reverted, unexplained):     # C3-4 (a): edited since its newest recorded state
                unauthored.add(path)
            else:
                assert later, (path, unexplained)     # by rule (C2-1)
            pending += 1
            continue
        seen = set()
        for h in entry["reverseHunks"]:
            h["class"] = CK.classify(path, at281, h["at"], base64.b64decode(h["removeBase64"]),
                                     base64.b64decode(h["insertBase64"]), ctx["prevValidator"], ctx["prevTest"],
                                     ctx["newPacket"], (1, 1), seen=seen)
        rebuilt, _, unexplained = CK.rebuild(path, at281, [(len(auth["baselinePackets"]), "281", classed)], norm)
        if sha(rebuilt) == entry["beforeSha256"]:
            exact += 1
        else:
            partial.add(path)
    print("vector 11: %d exact, %d partial, %d pending, %d unauthored %s" % (exact, len(partial), pending, len(unauthored),
                                                                           sorted(unauthored)))
    if os.environ.get("HARNESS_OFFLINE_ENFORCED") == "1":     # every runner execution: none unauthored (C3-4 condition 1)
        assert not unauthored, sorted(unauthored)
    assert partial <= PARTIAL_OK and exact + len(partial) + pending == len(auth["changedFiles"]) and exact > 0


def test_v12_one_byte_beside_the_cascade_is_class_a_with_its_share(tmp_path):
    found = _reader(_cascade_repo(tmp_path, live_extra=b"#")).disagreements
    assert [(d[0], d[2]) for d in found] == [(281, "A")] and "recorded cascade share 1 of 1" in found[0][3]


def test_v13_a_reordered_hunk_is_recorded_naming_the_slot(tmp_path):
    root = _cascade_repo(tmp_path, before=b"A = 288\nB = 288\n", after=b"A = 289\nB = 289\n",
                         hunks=[_hunk(14, b"9", b"8", "cascade"), _hunk(6, b"9", b"8", "cascade")])
    found = _reader(root).disagreements
    assert found and found[0][0] == 281 and "out of order" in found[0][3]


def test_a_recorded_class_that_fails_the_recheck_is_recorded(tmp_path):
    root = _cascade_repo(tmp_path, before=b"N = 'a'\n", after=b"N = 'b'\n", hunks=[_hunk(5, b"b", b"a", "cascade")])
    assert "fails the re-check" in _reader(root).disagreements[0][3]


def test_a_wrong_class_context_is_recorded(tmp_path):
    root = _cascade_repo(tmp_path)
    body = json.loads((root / "architecture/next1-authority.json").read_text())
    body["hunkClassContext"]["newPacket"] = "MET-OTHER-001"
    (root / "architecture/next1-authority.json").write_text(json.dumps(body))
    assert "newPacket is not the authority's packet" in _reader(root).disagreements[0][3]


def test_the_reader_is_active_only_in_an_outermost_session():
    code = ("import importlib.util as u; s = u.spec_from_file_location('m', %r); m = u.module_from_spec(s); "
            "s.loader.exec_module(m); print(m.OUTERMOST)") % str(ROOT / "ci/chain_checkpoint.py")
    env = {k: v for k, v in os.environ.items() if k != CK.SERIAL_ENV}
    run = lambda e: subprocess.run([sys.executable, "-I", "-c", code], env=e, capture_output=True, text=True, check=True).stdout.strip()
    assert (run(env), run(dict(env, **{CK.SERIAL_ENV: "1"}))) == ("True", "False")


def test_every_vector_has_a_test():
    names = {n.name for n in ast.parse(Path(__file__).read_bytes()).body if isinstance(n, ast.FunctionDef)}
    for vid in VECTORS:
        assert any(("_v%02d_" % vid) in n or n.startswith("test_v%02d" % vid) for n in names), vid


def test_a_later_slots_other_hunk_is_class_a_and_restarts(tmp_path):
    before, after = b"X = 'a'\nN = 288\n", b"X = 'b'\nN = 289\n"
    root = _cascade_repo(tmp_path, before=before, after=after,
                         hunks=[_hunk(5, b"b", b"a", "other"), _hunk(14, b"9", b"8", "cascade")])
    found = _reader(root).disagreements
    assert [(d[0], d[2], d[4]) for d in found] == [(281, "A", "input")] and "1 of 2 hunks of a class not normalised" in found[0][3]


def _rename(root, raw):
    path = root / "architecture/chain-checkpoint-authority.json"
    body = json.loads(path.read_text())
    body["newFiles"][CK.RECORD_PATH] = sha(raw)
    path.write_text(json.dumps(body))


def test_the_count_effect_table_is_the_single_source():
    rows = {}
    for line in (ROOT / "architecture/chain-checkpoint/README.md").read_text().splitlines():
        cells = [c.strip() for c in line.strip().strip("|").split("|")]
        if line.startswith("| ") and len(cells) == 4 and cells[2] in ("restart", "neutral", "count"):
            rows[cells[0]] = (cells[1], cells[2])
    assert rows.pop("agree") == ("—", "count") and rows == CK.COUNT_EFFECT
    vectors = json.loads((ROOT / "architecture/chain-checkpoint/vectors.json").read_bytes())
    assert "the countEffect table" in vectors["countEffectTable"]


@pytest.mark.parametrize("change, member", [(lambda r: r.update(parameters="x"), "parameters"),
                                            (lambda r: r.update(schemaVersion="other"), "schemaVersion"),
                                            (lambda r: r["layers"][0].pop("slot"), "layers[0].slot"),
                                            (lambda r: r.update(checkPairs=["x"]), "checkPairs[0]")])
def test_a_malformed_ledger_is_corrupt_by_cause(tmp_path, change, member):
    root = _repo(tmp_path)
    record = json.loads((root / CK.RECORD_PATH).read_bytes())
    change(record)
    raw = (json.dumps(record) + "\n").encode()
    (root / CK.RECORD_PATH).write_bytes(raw)
    _rename(root, raw)
    found = _reader(root).disagreements
    assert [(d[2], d[4]) for d in found] == [("C", "corrupt")] and found[0][3].startswith("Corrupt: ledger " + member)


def test_a_fault_names_its_class_and_the_head_slot(tmp_path, monkeypatch):
    root = _repo(tmp_path, newer=({},))     # one authority newer than the checkpoint: the head is slot 283
    monkeypatch.setattr(CK, "rebuild", lambda *a, **k: (_ for _ in ()).throw(RuntimeError("synthetic")))
    found = [d for d in _reader(root).disagreements if d[4] == "fault"]
    assert found and all(d[0] == 283 and d[3].startswith("RuntimeError: synthetic")
                         and d[3].endswith("head slot 283, checkpoint slot 282") for d in found)


def test_an_unauthored_file_is_listed_in_the_record(tmp_path):
    root = _repo(tmp_path)
    (root / "data281.txt").write_bytes(b"changed\n")
    _, record = _reader(root).finish("e" * 40)
    assert record["unauthored"] == ["data281.txt"] and record["disagreements"][0]["detail"].startswith("unauthored:")


def test_the_unauthored_rule():
    miss = CK.UNAUTHORED_MISS + "; recorded cascade share 1 of 1 hunks"
    assert CK.unauthored([], []) and CK.unauthored([], [("a", miss)])
    assert not CK.unauthored([("a", {"cascade": 1})], [("b", miss)])
    assert not CK.unauthored([], [("a", "1 of 2 hunks of a class not normalised")])
    assert not CK.unauthored([], [("a", "reverse hunks out of order")])


@pytest.mark.parametrize("body, member", [(b"{not json", "does not parse"), (b"[]", "is not an object"),
                                          (b'{"baselinePackets": []}', "baselinePackets is not an object")])
def test_a_malformed_authority_is_corrupt_naming_the_file(tmp_path, body, member):
    root = _repo(tmp_path)
    (root / "architecture/broken-authority.json").write_bytes(body)
    found = _reader(root).disagreements
    assert [(d[2], d[4]) for d in found] == [("C", "corrupt")]
    assert found[0][3].startswith("Corrupt: authority architecture/broken-authority.json " + member)


def test_a_broken_reverse_hunk_entry_is_corrupt(tmp_path):
    root = _cascade_repo(tmp_path, hunks=[{"at": "x", "removeBase64": "", "insertBase64": "", "class": "cascade"}])
    found = [d for d in _reader(root).disagreements if d[1] == "scripts/validate_l281.py"]
    assert [(d[2], d[4]) for d in found] == [("C", "corrupt")] and "reverseHunks[0]" in found[0][3]


def test_one_authority_per_slot(tmp_path):
    root = _repo(tmp_path, newer=({}, {}))
    second = root / "architecture/next2-authority.json"
    body = json.loads(second.read_text())
    body["authorityPacket"] = body["hunkClassContext"]["newPacket"] = "MET-NEXT-001"
    second.write_text(json.dumps(body))
    found = _reader(root).disagreements
    assert [(d[2], d[4]) for d in found] == [("C", "corrupt")] and "one authorityPacket" in found[0][3]


def test_the_slot_message_names_a_malformed_slot(tmp_path):
    root = _repo(tmp_path)
    record = json.loads((root / CK.RECORD_PATH).read_bytes())
    record["checkpointSlot"] = "282"
    raw = (json.dumps(record) + "\n").encode()
    (root / CK.RECORD_PATH).write_bytes(raw)
    _rename(root, raw)
    found = _reader(root).disagreements
    assert [(d[0], d[4]) for d in found] == [(None, "corrupt")]
    assert found[0][3].endswith("head slot unknown (the ledger's checkpointSlot or checkpointBaseline is malformed)")


def test_a_skip_checks_one_authority_per_slot_first(tmp_path):
    root = _repo(tmp_path, shadow_in="dryRunOnly", newer=({}, {}))
    second = root / "architecture/next2-authority.json"
    body = json.loads(second.read_text())
    body["authorityPacket"] = body["hunkClassContext"]["newPacket"] = "MET-NEXT-001"
    second.write_text(json.dumps(body))
    found = _reader(root).disagreements
    assert [(d[2], d[4]) for d in found] == [("C", "corrupt")] and "one authorityPacket" in found[0][3]


def test_the_member_checks(tmp_path):
    root = _repo(tmp_path)
    record = json.loads((root / CK.RECORD_PATH).read_bytes())
    record["checkPairs"] = [{"layerSlot": 279, "ids": [["A-1"], "B-1"], "type": "supersession"}]
    raw = (json.dumps(record) + "\n").encode()
    (root / CK.RECORD_PATH).write_bytes(raw)
    _rename(root, raw)
    found = _reader(root).disagreements
    assert [(d[2], d[4]) for d in found] == [("C", "corrupt")] and found[0][3].startswith("Corrupt: ledger checkPairs[0]")
    assert CK.entry_fault({"afterSha256": "a", "beforeSha256": "b",
                           "reverseHunks": [{"at": 0, "removeBase64": "", "insertBase64": "", "class": ["cascade"]}]}) == "reverseHunks[0].class"
    assert CK.bind_context("a.json", {"hunkClassContext": {"newPacket": "P", "prevValidator": "v", "prevTest": "t", "steps": [1, 1]},
                                      "authorityPacket": "P", "productPackets": ["x"]}) == "productPackets is not an object"


@pytest.mark.parametrize("raw, state", [(b"{not json\n", "the ledger is not JSON"), (b"[]\n", "the ledger is not an object")])
def test_the_slot_message_names_an_unreadable_ledger(tmp_path, raw, state):
    root = _repo(tmp_path)
    (root / CK.RECORD_PATH).write_bytes(raw)
    _rename(root, raw)
    found = _reader(root).disagreements
    assert [(d[0], d[4]) for d in found] == [(None, "corrupt")] and found[0][3].endswith("head slot unknown (%s)" % state)
