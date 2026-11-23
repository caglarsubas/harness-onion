"""MET-014 (EDGE-V13): operator edge record v13, the no-receipt TERMINAL amendment: its files, the transcript model v2 and
the member checker.

The live member passes its checker (scripts/validate_edge_record_v13.py, EV_V1 to EV_HUNKS); every positive is accepted
by the v2 model (scripts/broker_handoff_transcript_v2.py) under the v13 schema, and the one negative is refused by the
schema alone. The four fault actions of R10's TLA+ model (its NOTE section 7) are the four C30 cases below, through the
v2 model (CONTRACT_296 r2 section 3c). Then in-memory failing cases for each checker code. Every case mutates a copy of
the live bytes behind an injected reader, or patches the imported model; no file is written."""
import ast
import copy
import importlib.util
import json
import re
from pathlib import Path

import jsonschema
import pytest

ROOT = Path(__file__).resolve().parents[1]


def _load(rel, name):
    spec = importlib.util.spec_from_file_location(name, ROOT / rel)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


EV = _load("scripts/validate_edge_record_v13.py", "validate_edge_record_v13_under_test")
MODEL = EV.model
READ = EV.disk_reader(ROOT)
RECORD = json.loads(READ(EV.RECORD_PATH))
SCHEMA = json.loads(READ(EV.SCHEMA_PATH))
VECTORS = json.loads(READ(EV.VECTORS_PATH))
NO_RECEIPT = VECTORS["positive"][2]
C30_CASES = ("worker_no_receipt", "server_abort_then_terminal", "terminal_repeated", "lose_channel_before_terminal")


def _codes(files=None):
    over = dict(files or {})
    return [code for code, _ in EV.check(lambda path: over[path] if path in over else READ(path))]


def _accepted(frames, validate=None, schema=SCHEMA):
    return EV.accepted(validate or MODEL.validate_transcript, dict(NO_RECEIPT, frames=frames), schema)


def _v1_validate():
    """v1's validate_transcript, executed from v1's own bytes over the v2 model's helpers (the checker's EV_V2 form)."""
    node = EV.top_level(ast.parse(READ(EV.MODEL_V1_PATH).decode("utf-8")))["validate_transcript"]
    namespace = dict(vars(MODEL))
    exec(compile(ast.Module(body=[node], type_ignores=[]), EV.MODEL_V1_PATH, "exec", dont_inherit=True), namespace)
    return namespace["validate_transcript"]


def _record_bytes(record):
    return EV.dump(record, EV.RECORD_INDENT)


def test_live_member_passes_its_checker():
    assert EV.check(READ) == []
    assert EV.main([str(ROOT)]) == 0


def test_every_positive_is_accepted_under_the_v13_schema():
    assert len(VECTORS["positive"]) == 3
    for vector in VECTORS["positive"]:
        assert MODEL.validate_transcript(vector["binding"], vector["request"], vector["frames"], SCHEMA) == []


def test_the_negative_is_refused_by_the_schema_alone():
    validator = jsonschema.Draft202012Validator({**SCHEMA, "oneOf": [{"$ref": "#/$defs/frame"}]})
    (entry,) = VECTORS["negative"]
    assert entry["refusedBy"] == "channel.schema.json" and not validator.is_valid(entry["frame"])
    failed = copy.deepcopy(entry["frame"])
    failed["payload"]["status"] = "FAILED"
    assert validator.is_valid(failed)


def test_completed_size_zero_is_the_schemas_refusal():
    whole = copy.deepcopy(NO_RECEIPT["frames"])
    whole[-1]["payload"]["status"] = "COMPLETED"
    assert not _accepted(whole)
    bare = copy.deepcopy(SCHEMA)
    payload = bare["$defs"]["frame"]["oneOf"][EV.TERMINAL_INDEX]["properties"]["payload"]
    del payload["if"], payload["then"]
    assert _accepted(whole, schema=bare)


def test_v13_rows_carry_v12s_and_bind_by_sha256_alone():
    v12 = json.loads(READ(EV.V12_PATH))
    count = len(v12["artifacts"])
    assert RECORD["artifacts"][:count] == v12["artifacts"]
    assert RECORD["artifacts"][count:] == EV.expected_rows(READ)
    assert all(list(row) == list(EV.ROW_KEYS) for row in RECORD["artifacts"][count:])


# ---- C30 (6): the TLA+ model's four fault actions (R10's NOTE section 7), each a case through the v2 model


def test_case_worker_no_receipt():
    frames = copy.deepcopy(NO_RECEIPT["frames"])
    assert [f["kind"] for f in frames] == ["STARTED", "CLEANUP_RECORDED", "TERMINAL"]
    assert _accepted(frames)
    assert not _accepted(frames, _v1_validate())


def test_case_server_abort_then_terminal():
    frames = NO_RECEIPT["frames"]
    abort_def = [b for b in SCHEMA["$defs"]["frame"]["oneOf"] if b["properties"]["kind"].get("const") == "ABORT"][0]
    abort = copy.deepcopy(frames[-1])
    abort["kind"] = "ABORT"
    abort["payload"] = {"reason": abort_def["properties"]["payload"]["properties"]["reason"]["enum"][0]}
    chained = EV.chained(copy.deepcopy(frames[:2]) + [abort, copy.deepcopy(frames[-1])])
    assert EV.frame_valid(chained[2], SCHEMA)
    assert not _accepted(chained)


def test_case_terminal_repeated():
    frames = NO_RECEIPT["frames"]
    assert not _accepted(EV.chained(copy.deepcopy(frames) + [copy.deepcopy(frames[-1])]))


def test_case_lose_channel_before_terminal():
    assert not _accepted(copy.deepcopy(NO_RECEIPT["frames"][:-1]))


def test_the_four_c30_cases_are_this_file_s():
    names = set(globals())
    assert all("test_case_" + case in names for case in C30_CASES) and len(set(C30_CASES)) == 4


# ---- each checker code fails closed


def test_ev_v1_refuses_a_missing_file():
    def read(path):
        if path == EV.README_PATH:
            raise FileNotFoundError(path)
        return READ(path)
    assert [code for code, _ in EV.check(read)] == ["EV_V1"]


def test_ev_v1_refuses_another_v12():
    assert _codes({EV.V12_PATH: READ(EV.V12_PATH) + b" "}) == ["EV_V1"]


def _one_more_step(path, name="MET-999"):
    """path's bytes one chain step on, as the cascade leaves them (ERR-5): its catalog names gain one packet and its
    count one more; every other line unchanged."""
    out = []
    for line in READ(path).decode("utf-8").splitlines(keepends=True):
        body = line.rstrip("\n")
        if any(re.fullmatch(form, body) for form in EV.CASCADE[path][0]):
            body = re.sub(r"len\(packets\) == (\d+)", lambda m: "len(packets) == %d" % (int(m[1]) + 1), body)
            body = re.sub(r"valid: (\d+) packets", lambda m: "valid: %d packets" % (int(m[1]) + 1), body)
            body = re.sub(r'"\}(, "exact catalog"\)|:)$', lambda m: '", "%s"}%s' % (name, m[1]), body)
            line = body + "\n"
        out.append(line)
    return "".join(out).encode("utf-8")


def _touched(path, name):
    """path's bytes with one pinned source segment touched, its syntax tree unchanged."""
    text = READ(path).decode("utf-8")
    segment = ast.get_source_segment(text, EV.top_level(ast.parse(text))[name])
    touched = segment.replace("(", "( ", 1) if segment.startswith("def ") else segment.replace(" = ", " =  ", 1)
    assert touched != segment and text.count(segment) == 1
    return text.replace(segment, touched).encode("utf-8")


def test_ev_v1_accepts_the_next_cascade_step():
    assert _codes({path: _one_more_step(path) for path in EV.CASCADE}) == []


def test_ev_v1_refuses_a_cascade_step_on_one_base_script_alone():
    assert _codes({EV.MODEL_V1_PATH: _one_more_step(EV.MODEL_V1_PATH)}) == ["EV_V1"]


@pytest.mark.parametrize("path,name", [(p, n) for p in EV.SEGMENT_PINS for n in EV.SEGMENT_PINS[p]])
def test_ev_v1_refuses_a_touched_executed_segment(path, name):
    refusals = EV.check(lambda p: _touched(path, name) if p == path else READ(p))
    assert [code for code, _ in refusals] == ["EV_V1"] and "%s is main's source segment" % name in refusals[0][1]


def test_ev_v1_refuses_any_other_line_of_a_base_script():
    assert _codes({EV.PROXY_PATH: READ(EV.PROXY_PATH) + b"# touched\n"}) == ["EV_V1"]


def test_ev_v2_refuses_a_model_that_accepts_everything(monkeypatch):
    monkeypatch.setattr(MODEL, "validate_transcript", lambda *args: [])
    assert _codes() == ["EV_V2"]


def test_ev_v3_refuses_another_negative_rule():
    vectors = copy.deepcopy(VECTORS)
    vectors["negative"][0]["rule"] = "receiptSize 0 refused"
    assert "EV_V3" in _codes({EV.VECTORS_PATH: EV.dump(vectors)})


def test_ev_v4_refuses_another_artifact():
    record = copy.deepcopy(RECORD)
    record["artifact"] = "broker-handoff-v1"
    assert _codes({EV.RECORD_PATH: _record_bytes(record)}) == ["EV_V4"]


def test_ev_v4_refuses_a_readme_without_x3():
    readme = READ(EV.README_PATH).decode("utf-8").replace("not by the label", "by the label")
    assert _codes({EV.README_PATH: readme.encode("utf-8")}) == ["EV_V4"]


def test_ev_v5_refuses_another_superseded_packet():
    record = copy.deepcopy(RECORD)
    record["supersedes"]["packet"] = "MET-ENFORCE-042"
    assert _codes({EV.RECORD_PATH: _record_bytes(record)}) == ["EV_V5"]


def test_ev_rows_refuses_another_consumer_packet():
    record = copy.deepcopy(RECORD)
    record["artifacts"][-1]["consumerPacket"] = "HE-005B"
    assert _codes({EV.RECORD_PATH: _record_bytes(record)}) == ["EV_ROWS"]


def test_ev_hunks_refuses_a_second_changed_clause():
    source = READ(EV.MODEL_PATH).decode("utf-8")
    old = 'require(pending is None and cleanup is None and data["index"] == chunk_index, "chunk ordering")'
    assert source.count(old) == 1
    changed = source.replace(old, 'require(pending is None and data["index"] == chunk_index, "chunk ordering")')
    assert _codes({EV.MODEL_PATH: changed.encode("utf-8")}) == ["EV_HUNKS"]


def test_ev_hunks_refuses_another_import():
    assert _codes({EV.MODEL_PATH: READ(EV.MODEL_PATH) + b"\nimport os\n"}) == ["EV_HUNKS"]


def test_ev_hunks_refuses_a_third_schema_hunk():
    schema = copy.deepcopy(SCHEMA)
    schema["$comment"] = "a third hunk"
    assert set(_codes({EV.SCHEMA_PATH: EV.dump(schema)})) == {"EV_ROWS", "EV_HUNKS"}


@pytest.mark.parametrize("name", ["ZERO", "COMMON", "require", "_shape"])
def test_ev_hunks_refuses_a_copy_that_is_not_v1s(name):
    source = READ(EV.MODEL_PATH).decode("utf-8")
    node = EV.top_level(ast.parse(source))[name]
    text = ast.get_source_segment(source, node)
    changed = source.replace(text, text + "  # a comment is not a change", 1)
    assert _codes({EV.MODEL_PATH: changed.encode("utf-8")}) == []
    if name in ("ZERO", "COMMON"):
        edited = source.replace(text, text.replace("sha256:", "sha512:") if name == "ZERO"
                                else text.replace('"challenge"', '"challenge", "extra"'), 1)
    else:
        edited = source.replace(text, text.replace("raise ValueError(message)", "raise TypeError(message)")
                                if name == "require" else text.replace("16384", "16385"), 1)
    assert edited != source
    assert _codes({EV.MODEL_PATH: edited.encode("utf-8")}) == ["EV_HUNKS"]
