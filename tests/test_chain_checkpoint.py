"""MET-PERF-047: the chain checkpoint's reader and writer, vectors 1-14 (architecture/chain-checkpoint/vectors.json).
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
LATER_EDIT = "of a class not normalised"   # a newer authority's real edit, as rebuild() words it


def _ctx(packet):
    return {"newPacket": packet, "prevValidator": "scripts/validate_prev.py", "prevTest": "tests/test_prev.py", "steps": [1, 1]}


def _side_path(root, apath):
    return root / CK.HUNK_CLASSES_DIR / (Path(apath).stem + ".json")


def _bind(root, apath, side_raw):
    """Write a hunk-class record's bytes and name them, by sha256, in the authority's newFiles (MON-282-W1-A2)."""
    side_file = _side_path(root, apath)
    side_file.parent.mkdir(parents=True, exist_ok=True)
    side_file.write_bytes(side_raw)
    body = json.loads((root / apath).read_text())
    body.setdefault("newFiles", {})[side_file.relative_to(root).as_posix()] = sha(side_raw)
    (root / apath).write_text(json.dumps(body) + "\n")


def _write_classed(root, apath, body, packet):
    """MON-282-W1-A2: the authority in v2.1's form (each hunk's class taken out) and its closed hunk-class record,
    which the authority's newFiles names by sha256."""
    body = copy.deepcopy(body)
    classes = {}
    for path, entry in body.get("changedFiles", {}).items():
        hunks = entry.get("reverseHunks") if isinstance(entry, dict) else None
        classes[path] = [h.pop("class") for h in hunks if isinstance(h, dict) and "class" in h] if isinstance(hunks, list) else []
    (root / apath).write_text(json.dumps(body) + "\n")
    side = {"authorityPath": apath, "hunkClassVocabulary": list(CK.CLASSES), "hunkClassRuleSha256": CK.RULE_SHA256,
            "hunkClassContext": _ctx(packet), "classes": classes}
    _bind(root, apath, (json.dumps(side) + "\n").encode())


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
        body = {"authorityPacket": "MET-NEXT-%03d" % i, "baselinePackets": {str(j): "x" for j in range(288 + i)},
                "changedFiles": changed}
        _write_classed(tmp_path, "architecture/next%d-authority.json" % i, body, "MET-NEXT-%03d" % i)
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
    norm, exact, partial, pending, unauthored = CK.normalised({"normalisedRecordClass": True}), 0, set(), 0, set()
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
    # chainmech v2.3: 281's two `other` hunks (its readiness block and plan status line) are register, so none is partial
    assert not partial and exact + pending == len(auth["changedFiles"]) and exact > 0


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
    side = json.loads(_side_path(root, "architecture/next1-authority.json").read_text())
    side["hunkClassContext"]["newPacket"] = "MET-OTHER-001"
    _bind(root, "architecture/next1-authority.json", (json.dumps(side) + "\n").encode())
    assert "newPacket is not the authority's packet" in _reader(root).disagreements[0][3]


def test_the_reader_is_active_only_in_an_outermost_session():
    code = ("import importlib.util as u; s = u.spec_from_file_location('m', %r); m = u.module_from_spec(s); "
            "s.loader.exec_module(m); print(m.OUTERMOST)") % str(ROOT / "ci/chain_checkpoint.py")
    env = {k: v for k, v in os.environ.items() if k != CK.SERIAL_ENV}
    run = lambda e: subprocess.run([sys.executable, "-I", "-B", "-c", code], env=e, capture_output=True, text=True, check=True).stdout.strip()
    cache = ROOT / "ci/__pycache__"
    before = set(cache.iterdir()) if cache.is_dir() else set()
    assert (run(env), run(dict(env, **{CK.SERIAL_ENV: "1"}))) == ("True", "False")
    assert (set(cache.iterdir()) if cache.is_dir() else set()) <= before  # PKT283-PYCACHE: the child writes no __pycache__


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
    body["authorityPacket"] = "MET-NEXT-001"
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
    body["authorityPacket"] = "MET-NEXT-001"
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


@pytest.mark.parametrize("change, reason", [
    ("missing", "the hunk-class record the authority names is missing"),
    ("unnamed", "the authority's newFiles names no hunk-class record"),
    ("two", "the authority's newFiles names 2 hunk-class records"),
    ("digest", "the hunk-class record's bytes do not hash to the authority's digest"),
    ("malformed", "the hunk-class record does not parse as an object"),
    ("member", "members are not the closed set"),
    ("other", "the hunk-class record names another authority"),
    ("duplicated", "more than one hunk-class record names this authority"),
    ("cover", "does not cover exactly the authority's changed files"),
    ("count", "is not the authority's hunk count"),
    ("inside", "the authority carries hunk classes itself"),
])
def test_the_hunk_class_record_is_closed_named_and_bound_by_digest(tmp_path, change, reason):
    root = _cascade_repo(tmp_path)
    apath = "architecture/next1-authority.json"
    side_file = _side_path(root, apath)
    side = json.loads(side_file.read_text())
    body = json.loads((root / apath).read_text())
    rel = side_file.relative_to(root).as_posix()
    if change == "missing":
        side_file.unlink()
    elif change == "unnamed":
        del body["newFiles"][rel]
        (root / apath).write_text(json.dumps(body) + "\n")
    elif change == "two":
        body["newFiles"][CK.HUNK_CLASSES_DIR + "/second.json"] = body["newFiles"][rel]
        (root / apath).write_text(json.dumps(body) + "\n")
    elif change == "digest":
        side_file.write_text(json.dumps(side, indent=1) + "\n")
    elif change == "malformed":
        _bind(root, apath, b"{not json\n")
    elif change == "duplicated":
        (side_file.parent / "copy.json").write_text(json.dumps(side) + "\n")
    elif change == "inside":
        body["hunkClassContext"] = side["hunkClassContext"]
        (root / apath).write_text(json.dumps(body) + "\n")
    else:
        if change == "member":
            side["extra"] = 1
        elif change == "other":
            side["authorityPath"] = "architecture/other-authority.json"
        elif change == "cover":
            side["classes"]["scripts/other.py"] = []
        elif change == "count":
            side["classes"]["scripts/validate_l281.py"].append("cascade")
        _bind(root, apath, (json.dumps(side) + "\n").encode())
    found = _reader(root).disagreements
    assert [(d[0], d[2], d[4]) for d in found] == [(281, "A", "input")] and reason in found[0][3]


def test_a_reordered_hunk_class_record_fails_the_recheck(tmp_path):
    root = _cascade_repo(tmp_path, before=b"X = 'a'\nN = 288\n", after=b"X = 'b'\nN = 289\n",
                         hunks=[_hunk(5, b"b", b"a", "other"), _hunk(14, b"9", b"8", "cascade")])
    apath = "architecture/next1-authority.json"
    side = json.loads(_side_path(root, apath).read_text())
    side["classes"]["scripts/validate_l281.py"].reverse()
    _bind(root, apath, (json.dumps(side) + "\n").encode())
    found = _reader(root).disagreements
    assert [(d[2], d[4]) for d in found] == [("A", "input")] and "fails the re-check" in found[0][3]


def test_the_clock_failing_is_one_fault_and_never_raises(tmp_path):
    """P047-ORACLE-B1, R00's own case: a clock that works once, then raises on every reading."""
    readings = iter([0.0])

    def clock():
        for value in readings:
            return value
        raise RuntimeError("the clock is gone")
    reader = CK.Reader(root=_repo(tmp_path), tree="0" * 40, clock=clock)
    reader.start()
    for when in ("setup", "call", "teardown"):
        reader.report("tests/test_l281.py::test_x", when, "passed", 0.1)
    line, record = reader.finish("f" * 40)
    assert [(d["class"], d["kind"]) for d in record["disagreements"]] == [("C", "fault")]
    assert record["disagreements"][0]["detail"].startswith("RuntimeError: the clock failed: the clock is gone")
    assert line.startswith(CK.PREFIX) and record["mode"] == "compare" and record["layers"]["281"]["agree"] is True


@pytest.mark.parametrize("value", [object(), float("nan"), None])
def test_a_clock_reading_no_finite_number_is_one_fault(tmp_path, value):
    reader = CK.Reader(root=_repo(tmp_path), tree="0" * 40, clock=lambda: value)
    reader.start()
    _, record = reader.finish("f" * 40)
    faults = [d for d in record["disagreements"] if d["class"] == "C"]
    assert [d["kind"] for d in faults] == ["fault"] and "the clock failed" in faults[0]["detail"]


@pytest.mark.parametrize("pairs, index, reason", [
    ([{"layerSlot": 279, "ids": ["A-1", "A-1"], "type": "supersession"}], 0, "self-paired, not a pair, or unruled"),
    ([{"layerSlot": 279, "ids": ["A-1", "B-1"], "type": "unruled"}], 0, "self-paired, not a pair, or unruled"),
    ([{"layerSlot": 279, "ids": ["A-1", "B-1"], "type": "supersession"}] * 2, 1, "repeated")])
def test_a_check_pairs_detail_names_the_ledger_and_the_entry(tmp_path, pairs, index, reason):
    """P047-ORACLE-B2."""
    root = _repo(tmp_path)
    record = json.loads((root / CK.RECORD_PATH).read_bytes())
    record["checkPairs"] = pairs
    raw = (json.dumps(record) + "\n").encode()
    (root / CK.RECORD_PATH).write_bytes(raw)
    _rename(root, raw)
    found = _reader(root).disagreements
    assert [(d[1], d[2], d[4]) for d in found] == [("checkPairs", "C", "corrupt")]
    assert found[0][3].startswith("Corrupt: ledger checkPairs[%d]: %s (slot 279)" % (index, reason))


def test_a_shared_baseline_names_both_authorities(tmp_path):
    """P047-ORACLE-B3."""
    root = _repo(tmp_path, newer=({}, {}))
    second = root / "architecture/next2-authority.json"
    body = json.loads(second.read_text())
    body["baselinePackets"] = {str(j): "x" for j in range(289)}
    second.write_text(json.dumps(body))
    found = _reader(root).disagreements
    assert [(d[2], d[4]) for d in found] == [("C", "corrupt")]
    assert "share a baseline size: architecture/next1-authority.json and architecture/next2-authority.json" in found[0][3]


def test_a_shared_authority_packet_names_both_authorities(tmp_path):
    """P047-ORACLE-B3."""
    root = _repo(tmp_path, newer=({}, {}))
    second = root / "architecture/next2-authority.json"
    body = json.loads(second.read_text())
    body["authorityPacket"] = "MET-NEXT-001"
    second.write_text(json.dumps(body))
    detail = _reader(root).disagreements[0][3]
    assert "one authorityPacket (one authority per slot, P047-C4-2): architecture/next2-authority.json and " \
           "architecture/next1-authority.json" in detail


def test_unreadable_hunk_class_entries_change_nothing_unless_named(tmp_path):
    """P047-C6-5 (i): a directory, a dangling link and a link to a record, none named: nothing changes."""
    root = _cascade_repo(tmp_path)
    folder = root / CK.HUNK_CLASSES_DIR
    (folder / "dir.json").mkdir()
    (folder / "dangling.json").symlink_to(folder / "nowhere.json")
    (folder / "linked.json").symlink_to(_side_path(root, "architecture/next1-authority.json"))
    assert _reader(root).disagreements == []


def test_a_named_hunk_class_record_that_is_a_link_is_class_a(tmp_path):
    """P047-C6-5 (i): read as _read reads, so a named record that is a link is class A."""
    root = _cascade_repo(tmp_path)
    side_file = _side_path(root, "architecture/next1-authority.json")
    elsewhere = root / "elsewhere.json"
    elsewhere.write_bytes(side_file.read_bytes())
    side_file.unlink()
    side_file.symlink_to(elsewhere)
    found = _reader(root).disagreements
    assert [(d[0], d[2], d[4]) for d in found] == [(281, "A", "input")]
    assert "is a link, not a file, or unreadable" in found[0][3]


@pytest.mark.parametrize("cls, expect", [("cascade", ("A", "input", "carries hunk classes itself")),
                                         (7, ("C", "corrupt", "reverseHunks[0].class"))])
def test_a_class_key_inside_a_reverse_hunk(tmp_path, cls, expect):
    """PKT1-HUNK-CLASS-KEY: checked as an entry first (a class that is not a string is corrupt); otherwise the
    authority carries classes itself (class A)."""
    root = _cascade_repo(tmp_path)
    apath = root / "architecture/next1-authority.json"
    body = json.loads(apath.read_text())
    body["changedFiles"]["scripts/validate_l281.py"]["reverseHunks"][0]["class"] = cls
    apath.write_text(json.dumps(body) + "\n")
    found = [d for d in _reader(root).disagreements if d[1] == "scripts/validate_l281.py"]
    assert [(d[2], d[4]) for d in found] == [expect[:2]] and expect[2] in found[0][3]


@pytest.mark.parametrize("vocab, rule, reason", [
    (("bridge", "cascade", "other", "record"), "v22", None),
    (("bridge", "cascade", "other", "record", "register"), "v22", "hunkClassVocabulary is not the closed vocabulary of its rule"),
    (("bridge", "cascade", "other", "record", "register"), "none", "not a rule the reader holds (v2.2 or v2.3)")])
def test_rules_by_sha_bind_each_records_own_rule(tmp_path, vocab, rule, reason):
    """MON-282-W2-RULED: a record's hunkClassRuleSha256 picks chainmech v2.2's or v2.3's rule and its vocabulary."""
    assert CK.RULES_BY_SHA == {CK.RULE_V22_SHA256: (("bridge", "cascade", "other", "record"), False),
                               CK.RULE_SHA256: (CK.CLASSES, True)}
    assert CK.CLASSES == ("bridge", "cascade", "other", "record", "register")
    root = _cascade_repo(tmp_path)
    apath = "architecture/next1-authority.json"
    side = json.loads(_side_path(root, apath).read_text())
    side.update(hunkClassVocabulary=list(vocab), hunkClassRuleSha256=CK.RULE_V22_SHA256 if rule == "v22" else "0" * 64)
    _bind(root, apath, (json.dumps(side) + "\n").encode())
    found = _reader(root).disagreements
    if reason is None:
        assert found == []
    else:
        assert [(d[0], d[2], d[4]) for d in found] == [(281, "A", "input")] and reason in found[0][3]


def test_register_is_v23s_and_off_under_v22():
    owned = b'    authority_owner["task-packets/P-1.yaml"] = "P-1"\n'
    block = CK.BLOCK.encode() % (b"P-2", b"P-2", b"P-2", b"P-2")
    after = b"def f():\n" + owned + block + b"    return authority_owner\n"
    args = ("scripts/validate_readiness.py", after, len(b"def f():\n" + owned), block, b"", "scripts/validate_prev.py",
            "tests/test_prev.py", "P-2")
    assert CK.classify(*args, seen=set()) == "register" and CK.classify(*args, seen=set(), register=False) == "other"
    assert "register" in CK.normalised({}) and "register" not in CK.VOCABULARY_V22


@pytest.mark.parametrize("body, member", [(b"not json\n", "does not parse"), (b"[]\n", "is not an object"),
                                          (b'{"newFiles": []}\n', "newFiles is not an object")])
def test_v01_a_layer_authority_that_is_no_object_makes_the_reading_corrupt(tmp_path, body, member):
    """P047-C5-3: the layer authority stops parsing, or it or a member is a non-object: corrupt, with a null slot."""
    root = _repo(tmp_path)
    (root / "architecture/l281-authority.json").write_bytes(body)
    found = _reader(root).disagreements
    assert [(d[0], d[2], d[4]) for d in found] == [(None, "C", "corrupt")]
    assert found[0][3].startswith("Corrupt: authority architecture/l281-authority.json " + member)
    assert found[0][3].endswith("head slot unknown (the ledger was not read)")


def test_the_read_order_reads_the_authorities_before_the_ledger(tmp_path):
    """PKT1-READ-ORDER: a malformed authority is refused before a ledger that is not JSON is parsed."""
    root = _repo(tmp_path)
    raw = b"{not json\n"
    (root / CK.RECORD_PATH).write_bytes(raw)
    _rename(root, raw)
    (root / "architecture/broken-authority.json").write_bytes(b"[]")
    found = _reader(root).disagreements
    assert [(d[0], d[4]) for d in found] == [(None, "corrupt")] and "broken-authority.json" in found[0][3]
    assert found[0][3].endswith("head slot unknown (the ledger was not read)")


def _pinned_repo(tmp_path, head):
    root = _repo(tmp_path)
    (root / "scripts/validate_head.py").write_bytes(head)
    record = json.loads((root / CK.RECORD_PATH).read_bytes())
    record["exclusion"] = {"files": sorted([CK.RECORD_PATH, "architecture/chain-checkpoint-authority.json"]),
                           "pinLine": "scripts/validate_head.py"}
    record["layers"][0]["inputs"]["scripts/validate_head.py"] = sha(CK.pin_normalised(head))
    raw = (json.dumps(record) + "\n").encode()
    (root / CK.RECORD_PATH).write_bytes(raw)
    _rename(root, raw)
    return root


def test_v14_a_pin_line_only_change_reads_clean_and_any_other_edit_is_class_a(tmp_path):
    original = b'"""head"""\nAUTHORITY_SHA256 = "%s"\nX = 1\n' % (b"a" * 64)
    root = _pinned_repo(tmp_path, original)
    head = root / "scripts/validate_head.py"
    assert _reader(root).disagreements == []
    head.write_bytes(original.replace(b"a" * 64, b"b" * 64))
    assert _reader(root).disagreements == []
    for edited in (original.replace(b"X = 1", b"X = 2"), original + b'AUTHORITY_SHA256 = "c"\n'):
        head.write_bytes(edited)
        found = _reader(root).disagreements
        assert [(d[0], d[1], d[2], d[4]) for d in found] == [(281, "scripts/validate_head.py", "A", "input")]


@pytest.mark.parametrize("exclusion, member", [({"files": []}, "exclusion is not {files, pinLine}"),
                                               ({"files": ["b", "a"], "pinLine": "p"}, "exclusion.files"),
                                               ({"files": ["data281.txt"], "pinLine": "p"},
                                                "layers[0].inputs names an excluded file")])
def test_a_malformed_exclusion_is_corrupt(tmp_path, exclusion, member):
    root = _repo(tmp_path)
    record = json.loads((root / CK.RECORD_PATH).read_bytes())
    record["exclusion"] = exclusion
    raw = (json.dumps(record) + "\n").encode()
    (root / CK.RECORD_PATH).write_bytes(raw)
    _rename(root, raw)
    found = _reader(root).disagreements
    assert [(d[2], d[4]) for d in found] == [("C", "corrupt")] and found[0][3].startswith("Corrupt: ledger " + member)


def test_the_writers_exclusion_and_pin_digest_follow_the_reader():
    """MON-282-W2-RULED: the writer's exclusion, and its pin-line digest by the reader's own pin_normalised."""
    assert WR.exclusion_for(282, "scripts/validate_met_perf_047.py") == {
        "files": ["architecture/chain-checkpoint-authority.json", "architecture/chain-checkpoint/hunk-classes/282.json",
                  "architecture/chain-checkpoint/record.json"], "pinLine": "scripts/validate_met_perf_047.py"}
    raw = b'AUTHORITY_SHA256 = "x"\nY = 1\n'
    assert WR.attested_sha(raw, "a.py", "a.py", CK.pin_normalised) == sha(CK.PIN_PLACEHOLDER + b"Y = 1\n")
    assert WR.attested_sha(raw, "b.py", "a.py", CK.pin_normalised) == sha(raw)
    with pytest.raises(SystemExit, match="no single AUTHORITY_SHA256 pin line"):
        WR.attested_sha(raw + raw, "a.py", "a.py", CK.pin_normalised)


def test_dry_run_compare_reads_an_end_event_mid_line(tmp_path):
    """MON-282-DRYRUN-FIND: a teardown END event after other output on its line still counts."""
    root = _repo(tmp_path, shadow_in="dryRunOnly")
    node = sha(b"tests/test_l281.py::test_x")
    event = lambda phase: "PYTEST_DIAGNOSTIC=" + json.dumps({"event": "END", "node": node, "phase": phase,
                                                            "outcome": "passed", "durationUs": 1000})
    log = tmp_path / "argv63.log"
    log.write_text("\n".join([event("setup"), event("call"), "." + event("teardown")]) + "\n")
    CK.dry_run_compare(log, tmp_path / "shadow.json", root=root)
    record = json.loads((tmp_path / "shadow.json").read_text())
    assert record["layers"]["281"]["agree"] is True and not [d for d in record["disagreements"] if d["kind"] == "outcome"]


def test_the_writer_records_each_check_pair_once():
    """MON-282-PAIRS-DEDUPE: 279's real pairs file holds one entry per overlapping path (20) over 2 packet pairs; the
    writer records each pair once, and the reader's check_pairs reads them clean."""
    rel = "architecture/dist-005a-ctrl-fix-004-publish-pairs.json"
    document = json.loads((ROOT / rel).read_bytes())
    entries = WR.check_pairs_of(279, rel, document)
    assert len(document["pairs"]) == 20 and len(entries) == 2
    assert sorted(tuple(sorted(e["ids"])) for e in entries) == [("CTRL-FIX-004", "CTRL-INTEGRATE-001"), ("DIST-005", "DIST-005A")]
    assert {e["type"] for e in entries} == {"supersession"} and CK.check_pairs(entries) == []
    assert CK.check_pairs([dict(entries[0]), dict(entries[0])]) == ["ledger checkPairs[1]: repeated (slot 279)"]
