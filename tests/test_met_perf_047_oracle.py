"""D5a oracle tests for MET-PERF-047 (CHAIN-COMPACTION-002, G1): the chain checkpoint's shadow reader.

Owner decision D5a: a contract packet carries tests written outside the candidate, by someone who is not its
builder. This file was written from three texts only, c6's copies (they replaced W0's for every expectation), and
every expected value comes from one of them:
- README: architecture/chain-checkpoint/README.md (the contract text and its countEffect table);
- DOCSTRING: the module docstring of ci/chain_checkpoint.py;
- VECTORS: architecture/chain-checkpoint/vectors.json, vectors 1-13 and its hunkClassRecords member;
- OPERATOR: facts the operator stated in the oracle brief: the constant names (SCHEMA, RECORD_PATH, CLASSES,
  RULE_SHA256, COUNT_EFFECT), the classify(...) signature, the disagreement object's members, ROOT, 281's
  authority path and the context that classes 281's hunks (newPacket MET-ADOPT-007, prevValidator
  scripts/validate_met_perf_046.py, prevTest tests/test_met_perf_046.py, steps (1, 1)); and, in the c6 update
  note: the constants HUNK_CLASSES_DIR and SIDE_MEMBERS (the hunk-class record's five member names, a frozenset);
  CLASSES and RULE_SHA256 belong in a hunk-class record, never in an authority; the v2.1 changedFiles entry
  {afterSha256, beforeSha256, reverseHunks} with three-key hunks {at, removeBase64, insertBase64}; 281's published
  authority names no hunk-class record.

Every case is built as files under pytest's tmp_path; nothing is patched, shimmed or swapped. The reader is loaded
by file path from ROOT/ci/chain_checkpoint.py and is the only repository module loaded. Repository data read at
test time: 281's published authority and the files it names (closed paths skipped before any file is opened).

Construction assumptions. The three texts do not state these shapes; a failure that traces to one of them is a
construction slip of this file to correct, not a finding against the candidate:
- C1: authorities are found as architecture/*-authority.json (281's is architecture/authority-map-authority.json);
- C2: an authority's baseline is the member count of its baselinePackets object; checkpointBaseline is an integer
  compared with it (an authority is newer when its baseline is larger);
- C3 (answered by the operator at c6, no longer an assumption): the v2.1 entry and hunk form above; hunks are listed
  by ascending offset (VECTORS 13: descending offsets are out of order);
- C9: an authority built here holds authorityPacket, baselinePackets, changedFiles and newFiles only; the README's
  other four members of v2.1's eight-member form are not named in the texts and are taken as not required;
- C10: a hunk-class record's <slot> is its authority's chain slot (checkpointSlot plus its place among the newer
  authorities); 281's copy, newer than a slot-280 checkpoint, gets hunk-classes/281.json, as the c6 note asks
  every classed newer authority to carry its record;
- C4 (answered by the operator, MON-282-ORACLE-FACT2, no longer an assumption): an authority's newFiles maps a path
  to the lowercase hex sha256 of the file's bytes, as a plain string;
- C5: a ledger node's nodeSha256 is the sha256 of the node id's UTF-8 bytes; outcomes are pytest's words;
- C6: Reader takes a pathlib.Path root, a zero-argument clock returning seconds and a 40-hex tree;
- C7: record.json is indented JSON whose sizeBytes is the file's own length; fullRunProof and writingRun hold
  plausible fillers;
- C8: COUNT_EFFECT maps a kind to (class, countEffect) or to {"class", "countEffect"}.
"""

import base64
import hashlib
import importlib.util
import json
import re
import sys
from collections import Counter
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
READER = ROOT / "ci" / "chain_checkpoint.py"
AUTH_281 = "architecture/authority-map-authority.json"
RECORD_REL = "architecture/chain-checkpoint/record.json"
NEWER_REL = "architecture/oracle-newer-authority.json"
# README 'How the reader rebuilds': the hunk-class record and its exact five members.
HC_DIR = "architecture/chain-checkpoint/hunk-classes"
SIDE_FIVE = frozenset({"authorityPath", "hunkClassVocabulary", "hunkClassRuleSha256", "hunkClassContext", "classes"})
SCHEMA_TEXT = "harness.planeon.ai/chain-checkpoint/v1"
CAP = 15
CP = 282
HEAD_TREE = "3" * 40
HEAD_SHA = "4" * 40
NORMALISED = ("cascade", "bridge")
CTX_281 = {
    "newPacket": "MET-ADOPT-007",
    "prevValidator": "scripts/validate_met_perf_046.py",
    "prevTest": "tests/test_met_perf_046.py",
    "steps": (1, 1),
}

# README, the countEffect table: kind -> (class, countEffect); agree has no class.
TABLE = {
    "input": ("A", "restart"),
    "stale": ("A", "restart"),
    "outcome": ("B", "restart"),
    "corrupt": ("C", "restart"),
    "over-budget": ("C", "restart"),
    "over-cap": ("C", "restart"),
    "fault": ("C", "restart"),
    "skipped": ("C", "neutral"),
    "agree": (None, "count"),
}
RECORD_MEMBERS = (
    "headSha", "readerSeconds", "capSeconds", "overCap", "workers", "workersSource", "mode", "shadowIn",
    "naming", "attested", "sampled", "layers", "reverted", "unauthored", "disagreements",
)
LAYER_MEMBERS = ("recorded", "live", "agree", "writingSeconds", "liveSeconds")
ROW_MEMBERS = {"slot", "where", "class", "kind", "countEffect", "detail"}

_CLOSED_PARTS = ("enforcement_test_plan", "enforcement-test-plan")
_CLOSED_PREFIXES = ("architecture/enforcement-test-plan/", "tools/w04/", "tools/w03", "operator-private/")
_CLOSED_EXACT = ("docs/alpha-2/ENFORCEMENT_TEST_PLAN.md",)


def _closed(rel):
    """The skip list, applied to a path before any file is opened."""
    low = rel.lower()
    return (
        any(part in low for part in _CLOSED_PARTS)
        or rel.startswith(_CLOSED_PREFIXES)
        or rel in _CLOSED_EXACT
        or ".claude" in Path(rel).parts
    )


@pytest.fixture(scope="module")
def cc():
    """The reader, loaded by file path (importlib's documented recipe, under a fresh module name)."""
    name = "met_perf_047_oracle_reader"
    spec = importlib.util.spec_from_file_location(name, READER)
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod
    spec.loader.exec_module(mod)
    return mod


class OracleClockError(Exception):
    """Raised by the failing clock: a reader exception with no ruled cause (kind fault)."""


class Clock:
    """A zero-argument clock (C6) advancing `step` seconds per call; with fail_after, it raises after that many."""

    def __init__(self, step=0.001, fail_after=None):
        self.now = 0.0
        self.calls = 0
        self.step = step
        self.fail_after = fail_after

    def __call__(self):
        self.calls += 1
        if self.fail_after is not None and self.calls > self.fail_after:
            raise OracleClockError("oracle clock refused")
        self.now += self.step
        return self.now


def _sha(data):
    return hashlib.sha256(data).hexdigest()


def _put(root, rel, data):
    path = root / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data if isinstance(data, bytes) else data.encode("utf-8"))
    return _sha(path.read_bytes())


def _json_bytes(obj):
    return (json.dumps(obj, indent=1, sort_keys=True) + "\n").encode("utf-8")


def _ledger_bytes(ledger):
    """C7: sizeBytes is the file's own length (README 'sizeBytes, the file's own length')."""
    size = 0
    for _ in range(8):
        ledger["sizeBytes"] = size
        data = _json_bytes(ledger)
        if len(data) == size:
            return data
        size = len(data)
    raise AssertionError("sizeBytes did not settle")


def _snapshot(root):
    return {p.relative_to(root).as_posix(): p.read_bytes() for p in sorted(root.rglob("*")) if p.is_file()}


def _authority(packet, baseline, changed=None, new=None):
    """An authority in v2.1's form (C1, C2, C4, C9; OPERATOR c6), with no class member anywhere in it (README 'A
    classed authority's classes live in its hunk-class record')."""
    return {
        "authorityPacket": packet,
        "baselinePackets": {"ORACLE-BASE-%04d" % i: "baseline" for i in range(baseline)},
        "changedFiles": changed or {},
        "newFiles": dict(new or {}),
    }


def _named(sha):
    """OPERATOR (MON-282-ORACLE-FACT2): an authority's newFiles maps a path to the lowercase hex sha256 of the
    file's bytes, as a plain string."""
    return sha


NAMING_REL = "architecture/oracle-naming-authority.json"


def _replace_record(root, data):
    """Write record.json's new bytes and re-name their digest in the naming authority, so a test that rewrites the
    ledger changes the ledger only (else the README stale row, 'named with another digest', would be the cause)."""
    record_sha = _put(root, RECORD_REL, data)
    naming = json.loads((root / NAMING_REL).read_text(encoding="utf-8"))
    naming["newFiles"][RECORD_REL] = _named(record_sha)
    _put(root, NAMING_REL, _json_bytes(naming))


_UNKNOWN_WHY = ("not read", "not json", "not an object", "malformed")


def _class_c_slot(row, head):
    """README 'A class-C record's slot is the head's chain slot ... or null when the ledger was not read or its slots
    are malformed'; 'every class-C detail names the head slot and the checkpoint slot'; 'The head slot's message names
    why it is unknown: the ledger was not read, is not JSON, is not an object, or its slots are malformed'. The README
    fixes no reading order, so either branch may hold, each held to its own sentence. head=None: the texts do not
    place the head slot (an authority that does not parse has no baseline), so the slot the row gives is named."""
    detail = row["detail"]
    if row["slot"] is None:
        return any(why in detail.lower() for why in _UNKNOWN_WHY)
    expected = row["slot"] if head is None else head
    return _slot_is(row["slot"], expected) and str(expected) in detail and str(CP) in detail


def _b64(data):
    return base64.b64encode(data).decode("ascii")


def _hunk(at, remove, insert):
    """OPERATOR c6: a three-key reverse hunk."""
    return {"at": at, "removeBase64": _b64(remove), "insertBase64": _b64(insert)}


def _side(cc, authority_rel, classes, context):
    """README: a hunk-class record holds exactly authorityPath, hunkClassVocabulary, hunkClassRuleSha256,
    hunkClassContext and classes ({path: one class per reverse hunk, in the authority's order})."""
    return {
        "authorityPath": authority_rel,
        "hunkClassVocabulary": list(cc.CLASSES),
        "hunkClassRuleSha256": cc.RULE_SHA256,
        "hunkClassContext": dict(context, steps=list(context["steps"])),
        "classes": classes,
    }


def _attach(root, auth, slot, side, data=None, name_sha=None, write=True, name=True, rel=None):
    """README: the record is an ordinary new file of its step, HUNK_CLASSES_DIR/<slot>.json (C10), that the classed
    authority's own newFiles names by sha256. The flags build the defective variants."""
    rel = rel or "%s/%d.json" % (HC_DIR, slot)
    data = _json_bytes(side) if data is None else data
    if write:
        _put(root, rel, data)
    if name:
        auth["newFiles"][rel] = _named(name_sha or _sha(data))
    return rel


def _newer_edit(cc, root, packet, baseline, slot, rel, before, after, at, remove, insert):
    """A classed newer authority whose one reverse hunk undoes `after` to `before`; its class, labelled by the rule
    (OPERATOR), lives in its hunk-class record."""
    ctx = {"newPacket": packet, "prevValidator": "scripts/validate_s270.py", "prevTest": "tests/test_s270.py",
           "steps": (1, 1)}
    klass = cc.classify(rel, after, at, remove, insert, ctx["prevValidator"], ctx["prevTest"], packet,
                        ctx["steps"], set())
    entry = {"afterSha256": _sha(after), "beforeSha256": _sha(before), "reverseHunks": [_hunk(at, remove, insert)]}
    auth = _authority(packet, baseline, changed={rel: entry})
    _attach(root, auth, slot, _side(cc, NEWER_REL, {rel: [klass]}, ctx))
    return auth


VALIDATOR_TEXT = (
    "from pathlib import Path\n"
    "Path(__file__).resolve().parents[1].joinpath('EXECUTED-{slot}').write_text('ran')\n"
)
TEST_TEXT = VALIDATOR_TEXT + "\n\ndef test_a():\n    assert True\n\n\ndef test_b():\n    assert True\n"


def _build(cc, root, slots=(270,), checkpoint=CP, cp_baseline=0, shadow_in="verify", name_record=True,
           check_pairs=None, extra=None, validator=None, newer=(), normalised_record=False):
    """A checkpoint tree under root (README 'The ledger'): per slot a data file, a validator, a test file and a
    layer authority (not newer); record.json; an older authority naming it (C4); then `newer` [(rel, obj)].
    extra {rel: (live, recorded sha256)} joins the first layer's inputs; validator (rel, live, recorded sha256)
    replaces the first layer's validator. The validator and test files write a marker only if executed."""
    layers, nodeids = [], []
    for n, slot in enumerate(slots):
        data_rel = "data%d.txt" % slot
        val_rel = "scripts/validate_s%d.py" % slot
        test_rel = "tests/test_s%d.py" % slot
        auth_rel = "architecture/s%d-authority.json" % slot
        inputs = {data_rel: _put(root, data_rel, "data for slot %d\n" % slot)}
        val_sha = _put(root, val_rel, VALIDATOR_TEXT.format(slot=slot))
        if n == 0 and validator is not None:
            val_rel, live, val_sha = validator
            _put(root, val_rel, live)
        if n == 0 and extra:
            for rel, (live, recorded) in extra.items():
                _put(root, rel, live)
                inputs[rel] = recorded
        test_sha = _put(root, test_rel, TEST_TEXT.format(slot=slot))
        auth_sha = _put(root, auth_rel, _json_bytes(_authority("ORACLE-S%d" % slot, 0)))
        ids = ["%s::test_a" % test_rel, "%s::test_b" % test_rel]
        nodeids += ids
        layers.append({
            "slot": slot, "module": "s%d" % slot,
            "validatorPath": val_rel, "validatorSha256": val_sha,
            "testFilePath": test_rel, "testFileSha256": test_sha,
            "authorityPath": auth_rel, "authoritySha256": auth_sha,
            "inputs": inputs,
            "nodes": [{"nodeSha256": _sha(i.encode("utf-8")), "setup": "passed", "call": "passed",
                       "teardown": "passed"} for i in ids],
            "seconds": 1.0,
        })
    count = len(nodeids)
    ledger = {
        "schemaVersion": cc.SCHEMA,
        "checkpointSlot": checkpoint,
        "checkpointBaseline": cp_baseline,
        "writingCommit": "1" * 40,
        "writingTree": "2" * 40,
        "parameters": {"cadenceSlots": 10, "sampleFraction": 0.1, "fullRunOn": [], "nShadow": 10,
                       "shadowCapSeconds": CAP, "workers": 8, "shadowIn": shadow_in},
        "normalisedRecordClass": normalised_record,
        "layers": layers,
        "checkPairs": check_pairs or [],
        "fullRunProof": {"collected": count, "executed": count, "deselected": 0, "attested": count},
        "writingRun": {
            "statedDifferences": ["argv 63 runs directly, with the capture plugin",
                                  "it runs serial: the -p option keeps the parallel suite's serial loop"],
            "captureEnv": {}, "captureObservesOnly": True, "outsideReads": [],
            "argvRunSummarySha256": "5" * 64, "verifyReference": "oracle-verify-0",
        },
        "sizeBytes": 0,
        "sizeBound": 1048576,
    }
    record_sha = _put(root, RECORD_REL, _ledger_bytes(ledger))
    named = {RECORD_REL: _named(record_sha)} if name_record else {}
    _put(root, "architecture/oracle-naming-authority.json", _json_bytes(_authority("ORACLE-NAMING", 0, new=named)))
    for rel, obj in newer:
        _put(root, rel, obj if isinstance(obj, (bytes, str)) else _json_bytes(obj))
    return {"root": root, "ledger": ledger, "nodeids": nodeids}


def _rewrite_ledger(root, tree, change):
    ledger = json.loads(json.dumps(tree["ledger"]))
    change(ledger)
    _replace_record(root, _ledger_bytes(ledger))


def _read(cc, tree, clock=None, in_dry_run=False, calls=None):
    """One reading (README interface): start, each node's setup/call/teardown report, finish(head_sha)."""
    reader = cc.Reader(tree["root"], clock or Clock(), CAP, HEAD_TREE, in_dry_run)
    reader.start()
    for nodeid in tree["nodeids"]:
        for when in ("setup", "call", "teardown"):
            outcome = (calls or {}).get(nodeid, "passed") if when == "call" else "passed"
            reader.report(nodeid, when, outcome, 0.01)
    line, record = reader.finish(HEAD_SHA)
    return line, record


def _klass(value):
    return None if value in (None, "", "-", "—") else value


def _rows(record):
    """Every disagreement has the README's members and its kind's class and countEffect from the table."""
    rows = record["disagreements"]
    for row in rows:
        assert ROW_MEMBERS <= set(row), row
        assert row["kind"] in TABLE, row
        assert (_klass(row["class"]), row["countEffect"]) == TABLE[row["kind"]], row
    return rows


def _kind(record, kind):
    rows = [r for r in _rows(record) if r["kind"] == kind]
    assert rows, record["disagreements"]
    return rows


def _slot_is(value, expected):
    if expected is None:
        return value is None
    return value is not None and str(value) == str(expected)


def _text(row):
    return "%s %s" % (row.get("where"), row.get("detail"))


def _member(mapping, slot):
    return mapping[slot] if slot in mapping else mapping[str(slot)]


def test_constants_state_the_readme(cc):
    """README 'The ledger (record.json, schema harness.planeon.ai/chain-checkpoint/v1)'; README 'It undoes only
    cascade and bridge hunks, plus record when normalisedRecordClass is true'. OPERATOR: SCHEMA, RECORD_PATH,
    CLASSES (a tuple), RULE_SHA256 (the pinned class rule's digest)."""
    assert cc.SCHEMA == SCHEMA_TEXT
    assert Path(str(cc.RECORD_PATH)).as_posix().endswith(RECORD_REL)
    assert isinstance(cc.CLASSES, tuple)
    assert {"cascade", "bridge", "record"} <= set(cc.CLASSES)
    assert re.fullmatch(r"[0-9a-f]{64}", cc.RULE_SHA256)


def test_hunk_class_record_constants_state_the_readme(cc):
    """README 'A classed authority's classes live in its hunk-class record,
    architecture/chain-checkpoint/hunk-classes/<slot>.json ... It holds exactly authorityPath, hunkClassVocabulary,
    hunkClassRuleSha256, hunkClassContext and classes'. OPERATOR c6: HUNK_CLASSES_DIR, SIDE_MEMBERS (a frozenset)."""
    assert Path(str(cc.HUNK_CLASSES_DIR)).as_posix().endswith(HC_DIR)
    assert isinstance(cc.SIDE_MEMBERS, frozenset)
    assert cc.SIDE_MEMBERS == SIDE_FIVE


def test_vector_4_reader_mode_is_shadow(cc):
    """VECTORS 4 (case 'MODE = "sampled" in ci/chain_checkpoint.py'; the writer refuses a reader whose MODE is not
    shadow); README 'MET-PERF-047 is shadow-only'. Only the reader's side: the writer is not in CN."""
    assert cc.MODE == "shadow"


def test_count_effect_mirrors_the_readme_table(cc):
    """README 'This countEffect table is the single source ... the reader's COUNT_EFFECT mirrors it'; DOCSTRING
    'COUNT_EFFECT below mirrors it'; README table rows input..agree. OPERATOR: COUNT_EFFECT (shape C8)."""
    got = {}
    for kind, value in dict(cc.COUNT_EFFECT).items():
        if isinstance(value, dict):
            got[kind] = (_klass(value.get("class")), value.get("countEffect"))
        else:
            klass, effect = value
            got[kind] = (_klass(klass), effect)
    assert got == TABLE, {"COUNT_EFFECT": dict(cc.COUNT_EFFECT), "read as": got, "README table": TABLE}


def test_clean_reading_agrees_and_its_record_is_whole(cc, tmp_path):
    """README table row 'agree | - | count | a reading with no disagreement'; README 'The record's members';
    DOCSTRING 'attested (every ledger slot)'; README 'layers {slot: {recorded, live, agree, writingSeconds,
    liveSeconds}}'; README 'the reader capped at 15 s per run'; README 'prints ... the record as one ... JSON line'."""
    tree = _build(cc, tmp_path, slots=(270, 275))
    line, record = _read(cc, tree)
    assert isinstance(line, str) and "\n" not in line.strip()
    for member in RECORD_MEMBERS:
        assert member in record, member
    assert "\n" not in json.dumps(record)
    assert _rows(record) == []
    assert record["mode"] == "shadow"
    assert record["shadowIn"] == "verify"
    assert record["headSha"] == HEAD_SHA
    assert float(record["capSeconds"]) == CAP
    assert record["overCap"] is False
    assert sorted(str(s) for s in record["attested"]) == ["270", "275"]
    assert list(record["unauthored"]) == []
    for slot in (270, 275):
        layer = _member(record["layers"], slot)
        for member in LAYER_MEMBERS:
            assert member in layer, member
        assert layer["agree"] is True


def test_vector_10_reader_only_observes_and_never_executes(cc, tmp_path):
    """VECTORS 10, by README statements checkable without the conftest: 'The reader only observes and records';
    'Rebuilt bytes are compared, never executed'; 'It never uses git history' (the tree has no .git)."""
    tree = _build(cc, tmp_path)
    _put(tmp_path, "data270.txt", "tampered\n")
    before = _snapshot(tmp_path)
    _read(cc, tree, calls={tree["nodeids"][0]: "failed"})
    assert _snapshot(tmp_path) == before
    assert not [p for p in tmp_path.rglob("EXECUTED-*")]


def test_vector_10_reader_never_raises(cc, tmp_path):
    """VECTORS 10 ('a missing, unloadable or raising reader ... exit status unchanged'), checkable here as
    DOCSTRING 'nothing here raises out of a hook'; README 'it never changes a session's outcome'."""
    reader = cc.Reader(tmp_path, Clock(), CAP, HEAD_TREE, False)
    reader.start()
    reader.report("tests/test_none.py::test_none", "call", "passed", 0.0)
    reader.report(None, "bogus", object(), "not seconds")
    result = reader.finish(HEAD_SHA)
    assert isinstance(result, tuple) and len(result) == 2


def test_fault_names_its_exception_class(cc, tmp_path):
    """README fault row ('any other exception of the reader'); README 'A kind is set by cause, never by an
    exception's type'; README 'A fault's or a corrupt record's detail names its exception class'; README 'a
    class-C record's slot is the head's chain slot ... or null when the ledger was not read'."""
    tree = _build(cc, tmp_path)
    _, record = _read(cc, tree, clock=Clock(fail_after=1))
    rows = _kind(record, "fault")
    assert any("OracleClockError" in r["detail"] for r in rows), rows
    for r in rows:
        assert r["slot"] is None or _slot_is(r["slot"], CP), r
        if r["slot"] is not None:
            assert str(CP) in r["detail"], r


def test_vector_1_tampered_input_is_class_a_and_unauthored(cc, tmp_path):
    """VECTORS 1 (change data<slot>.txt after the record is written: class A; names the layer's slot and the
    file; listed as unauthored, P047-C3-4); README input row; README 'unauthored [paths]'."""
    tree = _build(cc, tmp_path)
    _put(tmp_path, "data270.txt", "tampered after the record\n")
    _, record = _read(cc, tree)
    rows = _kind(record, "input")
    assert any(_slot_is(r["slot"], 270) and "data270.txt" in _text(r) for r in rows), rows
    assert "data270.txt" in record["unauthored"]
    assert _member(record["layers"], 270)["agree"] is False


def test_vector_1_layer_authority_json_change_is_class_a(cc, tmp_path):
    """VECTORS 1 ('a JSON change to the layer authority is class A'; names the layer's slot)."""
    tree = _build(cc, tmp_path)
    rel = "architecture/s270-authority.json"
    obj = json.loads((tmp_path / rel).read_text(encoding="utf-8"))
    obj["authorityPacket"] = "ORACLE-S270-CHANGED"
    _put(tmp_path, rel, _json_bytes(obj))
    _, record = _read(cc, tree)
    assert any(_slot_is(r["slot"], 270) for r in _rows(record) if r["class"] == "A"), record["disagreements"]
    assert not [r for r in record["disagreements"] if r["kind"] == "corrupt"]


def test_vector_1_layer_authority_that_stops_parsing_is_corrupt(cc, tmp_path):
    """VECTORS 1 ('one that stops it parsing makes the reading corrupt', Q-R4-2, P047-C5-3); README corrupt row
    ('an authority that does not parse'; the detail names the file); README 'every class-C detail names the head
    slot and the checkpoint slot'."""
    tree = _build(cc, tmp_path)
    _put(tmp_path, "architecture/s270-authority.json", "{ not json\n")
    _, record = _read(cc, tree)
    rows = _kind(record, "corrupt")
    assert any("s270-authority.json" in _text(r) and _class_c_slot(r, None) for r in rows), rows


def test_vector_2_unnamed_ledger_is_stale(cc, tmp_path):
    """VECTORS 2 (omit the record from every authority: class A; no authority names record.json; names
    record.json); README stale row; README 'the stale record has no layer, so its slot is null'."""
    tree = _build(cc, tmp_path, name_record=False)
    _, record = _read(cc, tree)
    rows = _kind(record, "stale")
    assert any(r["slot"] is None and "record.json" in _text(r) for r in rows), rows


def test_vector_2_newer_authority_naming_another_digest_is_stale(cc, tmp_path):
    """VECTORS 2 (add a newer authority naming a different afterSha256: the newest naming authority names another
    digest; class A; names record.json); README stale row ('named with another digest')."""
    obj = _authority("ORACLE-NEWER", 1, new={RECORD_REL: _named("0" * 64)})
    tree = _build(cc, tmp_path, newer=[(NEWER_REL, obj)])
    _, record = _read(cc, tree)
    rows = _kind(record, "stale")
    assert any(r["slot"] is None and "record.json" in _text(r) for r in rows), rows


def test_vector_3_outcome_change_is_class_b(cc, tmp_path):
    """VECTORS 3 (report call=failed for a node the ledger records as passed: class B, a node's live outcome differs
    with no input change; names the layer's slot); README outcome row."""
    tree = _build(cc, tmp_path)
    _, record = _read(cc, tree, calls={tree["nodeids"][0]: "failed"})
    rows = _kind(record, "outcome")
    assert any(_slot_is(r["slot"], 270) for r in rows), rows
    assert not [r for r in record["disagreements"] if r["kind"] == "input"]


def test_vector_7_disagreement_is_in_layers_and_disagreements(cc, tmp_path):
    """VECTORS 7 (as vector 3, read from the record's layers and disagreements: recorded with the slot and its
    class; class A|B); README 'layers {slot: {recorded, live, agree, ...}}'. The exit status part is the conftest's:
    here, finish returns its record without raising."""
    tree = _build(cc, tmp_path)
    _, record = _read(cc, tree, calls={tree["nodeids"][1]: "failed"})
    layer = _member(record["layers"], 270)
    assert layer["agree"] is False
    assert layer["recorded"] != layer["live"]
    assert any(_slot_is(r["slot"], 270) and r["class"] in ("A", "B") for r in _rows(record)), record


PAIR = {"layerSlot": 270, "pairsPath": "tests/test_s270.py", "ids": ["test_a", "test_b"], "type": "supersession"}
PAIR_DEFECTS = {
    "self-paired": [dict(PAIR, ids=["test_a", "test_a"])],
    "unruled-type": [dict(PAIR, type="oracle-unruled")],
    "repeated": [dict(PAIR), dict(PAIR)],
}


@pytest.mark.parametrize("defect", sorted(PAIR_DEFECTS))
def test_vector_5_check_pairs_defect_is_corrupt(cc, tmp_path, defect):
    """VECTORS 5 (ids [A, A]; type unruled; one entry twice: class C, a self-paired, unruled or repeated
    check_pairs entry; names the entry's layerSlot); README checkPairs ('the only ruled type is supersession');
    README corrupt row ('the ledger (a member check_ledger names)'; the detail names the file and the member);
    README 'A class-C record's slot is the head's chain slot'."""
    tree = _build(cc, tmp_path, check_pairs=PAIR_DEFECTS[defect])
    _, record = _read(cc, tree)
    rows = _kind(record, "corrupt")
    assert any("270" in r["detail"] and "checkPairs" in _text(r) and "record.json" in _text(r) for r in rows), rows
    assert all(_slot_is(r["slot"], CP) for r in rows), rows


def test_vector_6_sample_is_seeded_by_the_head_tree(cc):
    """VECTORS 6 (sample(tree, slots, 0.1) twice and for another tree: one head tree draws one sample; two trees
    differ); README 'a head-seeded sample of the attested layers'."""
    slots = list(range(100, 300))
    first = cc.sample("a" * 40, slots, 0.1)
    again = cc.sample("a" * 40, slots, 0.1)
    other = cc.sample("b" * 40, slots, 0.1)
    assert sorted(first) == sorted(again)
    assert set(first) <= set(slots) and set(other) <= set(slots)
    assert sorted(first) != sorted(other)


def test_vector_8_two_refusing_layers_newest_first(cc, tmp_path):
    """VECTORS 8 (tamper two layers' inputs: class A; where two layers disagree, the newest slot is recorded first;
    names both slots, newest first)."""
    tree = _build(cc, tmp_path, slots=(270, 275))
    _put(tmp_path, "data270.txt", "tampered 270\n")
    _put(tmp_path, "data275.txt", "tampered 275\n")
    _, record = _read(cc, tree)
    order = [str(r["slot"]) for r in _rows(record) if r["class"] == "A"]
    assert "270" in order and "275" in order, record["disagreements"]
    assert order.index("275") < order.index("270"), order


def test_vector_9_budget_stops_the_replay_over_the_cap(cc, tmp_path):
    """VECTORS 9 (a clock advancing 20 s per tick: the budget stops the replay over 15 s, kind over-budget, class C);
    README over-budget row; README 'A class-C record's slot is the head's chain slot: checkpointSlot plus the
    authorities newer than the checkpoint'; 'every class-C detail names the head slot and the checkpoint slot (a
    skip, an over-budget and an over-cap record name their reason)'."""
    before, after = b"value=old\n", b"value=new\n"
    obj = _newer_edit(cc, tmp_path, "ORACLE-NEWER", 1, CP + 1, "edit270.txt", before, after, 6, b"new", b"old")
    tree = _build(cc, tmp_path, extra={"edit270.txt": (after, _sha(before))}, newer=[(NEWER_REL, obj)])
    _, record = _read(cc, tree, clock=Clock(step=20.0))
    rows = _kind(record, "over-budget")
    assert all(_class_c_slot(r, CP + 1) for r in rows), rows
    assert any("budget" in r["detail"].lower() or "cap" in r["detail"].lower() for r in rows), rows


def test_vector_9_dry_run_only_in_session_reading_is_skipped(cc, tmp_path):
    """VECTORS 9 (parameters.shadowIn = dryRunOnly: an in-session reading is skipped, kind skipped, countEffect
    neutral, its slot the head's, naming the head slot and the checkpoint slot); README skipped row; README 'A skip
    still writes its record, with the reason and the slots'; DOCSTRING 'skipped, which is neutral and still writes
    its record'."""
    tree = _build(cc, tmp_path, shadow_in="dryRunOnly", newer=[(NEWER_REL, _authority("ORACLE-NEWER", 1))])
    _, record = _read(cc, tree, in_dry_run=False)
    assert record["shadowIn"] == "dryRunOnly"
    rows = _kind(record, "skipped")
    assert len(rows) == 1, rows
    row = rows[0]
    assert _slot_is(row["slot"], CP + 1), row
    assert str(CP + 1) in row["detail"] and str(CP) in row["detail"], row
    assert "dry" in row["detail"].lower(), row


def test_skip_checks_one_authority_per_slot_first(cc, tmp_path):
    """README 'A skip still writes its record ...; one authority per slot is checked before it'; README corrupt
    row ('two newer authorities sharing a baseline')."""
    newer = [("architecture/oracle-newer-a-authority.json", _authority("ORACLE-NEWER-A", 1)),
             ("architecture/oracle-newer-b-authority.json", _authority("ORACLE-NEWER-B", 1))]
    tree = _build(cc, tmp_path, shadow_in="dryRunOnly", newer=newer)
    _, record = _read(cc, tree, in_dry_run=False)
    rows = _kind(record, "corrupt")
    assert any("oracle-newer-a-authority.json" in _text(r) or "oracle-newer-b-authority.json" in _text(r)
               for r in rows), rows


@pytest.mark.parametrize("shared", ["baseline", "authorityPacket"])
def test_newer_authorities_sharing_a_slot_are_corrupt(cc, tmp_path, shared):
    """README corrupt row ('two newer authorities sharing a baseline or an authorityPacket'); README 'one authority
    per slot: their baselines and authorityPackets are distinct, or the reading is corrupt'."""
    second = "ORACLE-NEWER-A" if shared == "authorityPacket" else "ORACLE-NEWER-B"
    newer = [("architecture/oracle-newer-a-authority.json", _authority("ORACLE-NEWER-A", 1)),
             ("architecture/oracle-newer-b-authority.json",
              _authority(second, 1 if shared == "baseline" else 2))]
    tree = _build(cc, tmp_path, newer=newer)
    _, record = _read(cc, tree)
    rows = _kind(record, "corrupt")
    assert any("oracle-newer-a-authority.json" in _text(r) or "oracle-newer-b-authority.json" in _text(r)
               for r in rows), rows


@pytest.mark.parametrize("data, why", [("{ not json\n", "JSON"), ("[]\n", "object")])
def test_unreadable_ledger_is_corrupt_with_a_null_slot(cc, tmp_path, data, why):
    """README corrupt row ('the ledger'; the detail names the file); README 'or null when the ledger was not read';
    README 'The head slot's message names why it is unknown: the ledger was not read, is not JSON, is not an
    object, or its slots are malformed'."""
    tree = _build(cc, tmp_path)
    _replace_record(tmp_path, data)
    _, record = _read(cc, tree)
    rows = _kind(record, "corrupt")
    assert any(r["slot"] is None and "record.json" in _text(r) and why.lower() in r["detail"].lower()
               for r in rows), rows


def test_malformed_ledger_slots_give_a_null_slot(cc, tmp_path):
    """README 'null when the ledger was not read or its slots are malformed'; README corrupt row ('the ledger (a
    member check_ledger names)')."""
    tree = _build(cc, tmp_path)
    _rewrite_ledger(tmp_path, tree, lambda ledger: ledger.__setitem__("checkpointSlot", "two-eighty-two"))
    _, record = _read(cc, tree)
    rows = _kind(record, "corrupt")
    assert any("checkpointSlot" in _text(r) for r in rows), rows
    assert all(r["slot"] is None for r in _rows(record) if r["class"] == "C"), record["disagreements"]


@pytest.mark.parametrize("member", ["layers", "parameters", "checkpointBaseline"])
def test_ledger_missing_member_is_corrupt_naming_it(cc, tmp_path, member):
    """README corrupt row ('the ledger (a member check_ledger names) ... the detail names the file and the
    member'); README 'The ledger' (the members of record.json)."""
    tree = _build(cc, tmp_path)
    _rewrite_ledger(tmp_path, tree, lambda ledger: ledger.pop(member))
    _, record = _read(cc, tree)
    rows = _kind(record, "corrupt")
    assert any("record.json" in _text(r) and member in _text(r) for r in rows), rows


@pytest.mark.parametrize("data", ["{ not json\n", "[]\n"])
def test_authority_unparsable_or_not_object_is_corrupt(cc, tmp_path, data):
    """README corrupt row ('an authority that does not parse, is not an object'; the detail names the file);
    README 'every class-C detail names ... the checkpoint slot'."""
    tree = _build(cc, tmp_path, newer=[(NEWER_REL, data)])
    _, record = _read(cc, tree)
    rows = _kind(record, "corrupt")
    assert any("oracle-newer-authority.json" in _text(r) and _class_c_slot(r, None) for r in rows), rows


@pytest.mark.parametrize("member", ["baselinePackets", "changedFiles", "newFiles"])
def test_authority_member_not_an_object_is_corrupt(cc, tmp_path, member):
    """README corrupt row ('an authority ... whose baselinePackets, changedFiles or newFiles is not an object';
    'the detail names the file and the member')."""
    obj = _authority("ORACLE-NEWER", 1)
    obj[member] = ["not", "an", "object"]
    tree = _build(cc, tmp_path, newer=[(NEWER_REL, obj)])
    _, record = _read(cc, tree)
    rows = _kind(record, "corrupt")
    assert any("oracle-newer-authority.json" in _text(r) and member in _text(r) for r in rows), rows


def test_changed_files_entry_shape_fault_is_corrupt(cc, tmp_path):
    """README 'Each changedFiles entry's shape is checked first (entry_fault; a broken entry is corrupt)'; README
    corrupt row ('a changedFiles entry entry_fault rejects'; the detail names the file and the member)."""
    obj = _authority("ORACLE-NEWER", 1, changed={"data270.txt": {"beforeSha256": "0" * 64}})
    tree = _build(cc, tmp_path, newer=[(NEWER_REL, obj)])
    _, record = _read(cc, tree)
    rows = _kind(record, "corrupt")
    assert any("oracle-newer-authority.json" in _text(r)
               and ("data270.txt" in _text(r) or "changedFiles" in _text(r)) for r in rows), rows


def test_reverse_hunks_entry_malformed_is_corrupt(cc, tmp_path):
    """README 'Each changedFiles entry's shape is checked first (entry_fault; a broken entry is corrupt)' applied to
    a reverseHunks entry that is not a hunk; README corrupt row (the detail names the file and the member)."""
    entry = {"beforeSha256": "0" * 64, "afterSha256": _sha(b"data for slot 270\n"), "reverseHunks": [7]}
    obj = _authority("ORACLE-NEWER", 1, changed={"data270.txt": entry})
    tree = _build(cc, tmp_path, newer=[(NEWER_REL, obj)])
    _, record = _read(cc, tree)
    rows = _kind(record, "corrupt")
    assert any("oracle-newer-authority.json" in _text(r)
               and any(m in _text(r) for m in ("reverseHunks", "data270.txt", "changedFiles")) for r in rows), rows


@pytest.fixture(scope="module")
def a281():
    """281's published authority under ROOT (OPERATOR: its path)."""
    return json.loads((ROOT / AUTH_281).read_text(encoding="utf-8"))


def _unb64(value):
    """OPERATOR c6: removeBase64 and insertBase64 are standard base64 of the bytes."""
    return base64.b64decode(value, validate=True)


@pytest.fixture(scope="module")
def files_281(cc, a281):
    """281's edited files, closed paths skipped before any file is opened. For each file still at 281's afterSha256
    under ROOT: its after bytes and its hunks' classes by the rule under MET-ADOPT-007's context (OPERATOR); a file
    a later slot edited is kept apart (after and classes None), as VECTORS 11 counts it apart."""
    rels = sorted(rel for rel in a281["changedFiles"] if not _closed(rel))
    out = {}
    for rel in rels:
        entry = a281["changedFiles"][rel]
        path = ROOT / rel
        after = path.read_bytes() if path.is_file() else None
        classes = None
        if after is not None and _sha(after) == entry["afterSha256"]:
            seen = set()
            classes = [cc.classify(rel, after, h["at"], _unb64(h["removeBase64"]), _unb64(h["insertBase64"]),
                                   CTX_281["prevValidator"], CTX_281["prevTest"], CTX_281["newPacket"],
                                   CTX_281["steps"], seen) for h in entry["reverseHunks"]]
        out[rel] = {"entry": entry, "after": after if classes is not None else None, "classes": classes}
    return out


# README 'It undoes only cascade and bridge hunks, plus record when normalisedRecordClass is true'.
NORMALISED_RECORD = NORMALISED + ("record",)


def _clean(files_281, normalised=NORMALISED):
    """281's current files whose every hunk is of a normalised class (cascade and bridge; plus record when the
    ledger's normalisedRecordClass is true), never an authority or a checkpoint file."""
    return [rel for rel, f in sorted(files_281.items())
            if f["classes"] and all(c in normalised for c in f["classes"])
            and not rel.endswith("-authority.json") and not rel.startswith("architecture/chain-checkpoint/")]


def _attach_281(root, auth, side):
    """The well-formed record of 281's copy (C10: hunk-classes/281.json), named in the copy's newFiles."""
    _attach(root, auth, 281, side)


def _build_281(cc, root, a281, files_281, rels, mutate=None, live=None, as_validator=None, record=_attach_281,
               normalised_record=False):
    """Checkpoint 280 with 281 as its one newer authority (281's step first, K = 0): the attested files are `rels`
    recorded at 281's beforeSha256, live at 281's after bytes (or `live`). The copy of 281's authority keeps v2.1's
    form and only those entries; their classes, labelled by the rule (OPERATOR) under MET-ADOPT-007's context
    (DOCSTRING newPacket == authorityPacket, steps == [1, 1 + K]), go in its hunk-class record, which `record`
    writes and names (README 'How the reader rebuilds'). `mutate` {rel: f([(hunk, class)])} edits a file's hunks,
    each class kept with its hunk."""
    copy = json.loads(json.dumps(a281))
    changed, classes = {}, {}
    for rel in rels:
        entry = json.loads(json.dumps(files_281[rel]["entry"]))
        pairs = list(zip(entry["reverseHunks"], files_281[rel]["classes"]))
        if mutate and rel in mutate:
            pairs = mutate[rel](pairs)
        entry["reverseHunks"] = [hunk for hunk, _ in pairs]
        classes[rel] = [klass for _, klass in pairs]
        changed[rel] = entry
    copy["changedFiles"] = changed
    copy["authorityPacket"] = CTX_281["newPacket"]
    copy["newFiles"] = dict(copy.get("newFiles") or {})
    record(root, copy, _side(cc, AUTH_281, classes, CTX_281))
    extra, validator = {}, None
    for rel in rels:
        data = (live or {}).get(rel, files_281[rel]["after"])
        recorded = files_281[rel]["entry"]["beforeSha256"]
        if rel == as_validator:
            validator = (rel, data, recorded)
        else:
            extra[rel] = (data, recorded)
    return _build(cc, root, slots=(278,), checkpoint=280, cp_baseline=len(copy["baselinePackets"]) - 1,
                  extra=extra, validator=validator, newer=[(AUTH_281, copy)], normalised_record=normalised_record)


def test_vector_11_281_hunks_class_under_its_context(cc, files_281):
    """VECTORS 11 (architecture/authority-map-authority.json classed by the rule under MET-ADOPT-007's context:
    '281's edited files rebuild to each beforeSha256 under 281's context; only validate_readiness's block and the
    master plan's status line stay partial; a file that a later slot edits for real ... is counted apart').
    OPERATOR: 281's authority path and context; README 'It undoes only cascade and bridge hunks, plus record when
    normalisedRecordClass is true' (vector 11's 'only ... stay partial' holds with record normalised, so the
    partial set is read with record undone)."""
    current = {rel: f for rel, f in files_281.items() if f["classes"] is not None}
    assert current, "no file of 281 is still at its afterSha256"
    for rel, f in current.items():
        assert set(f["classes"]) <= set(cc.CLASSES), (rel, f["classes"])
        if any(c not in NORMALISED_RECORD for c in f["classes"]):
            low = rel.lower()
            assert "validate_readiness" in low or ("master" in low and "plan" in low), (rel, f["classes"])
    assert _clean(files_281), "no file of 281 rebuilds by cascade and bridge hunks alone"


def test_d9_k0_cascade_step_reads_clean_281_first(cc, tmp_path, a281, files_281):
    """Q-282C-2 D9 vector 1 / VECTORS 11 ('a K = 0 cascade step reads clean'); README 'It replays, newest first,
    only the published reverseHunks of the authorities newer than the checkpoint. The apply is byte-exact, with each
    file's afterSha256 and beforeSha256 checked'; README 'It undoes only cascade and bridge hunks'; README 'reverted
    {slot: [[path, [[authority, {class: count}]]]]}'."""
    rels = _clean(files_281)
    assert rels
    tree = _build_281(cc, tmp_path, a281, files_281, rels)
    _, record = _read(cc, tree)
    assert _rows(record) == []
    assert _member(record["layers"], 278)["agree"] is True
    reverted = {path: pairs for path, pairs in _member(record["reverted"], 278)}
    for rel in rels:
        counts = Counter()
        for _, by_class in reverted[rel]:
            counts.update(by_class)
        assert counts == Counter(files_281[rel]["classes"]), rel


def test_vector_12_one_byte_beside_the_cascade_is_class_a(cc, tmp_path, a281, files_281):
    """VECTORS 12 (the live validator is the authority's after bytes plus one byte: class A; afterSha256 differs,
    recorded cascade share x of N; the file is unauthored; names the layer's slot); Q-282C-2 D9 vector 2."""
    rels = [rel for rel in _clean(files_281) if "cascade" in files_281[rel]["classes"]]
    assert rels, "no clean file of 281 has a cascade hunk"
    validators = [rel for rel in rels if rel.startswith("scripts/validate_")]
    rel = (validators or rels)[0]
    live = files_281[rel]["after"] + b"#"
    tree = _build_281(cc, tmp_path, a281, files_281, [rel], live={rel: live},
                      as_validator=rel if validators else None)
    _, record = _read(cc, tree)
    rows = [r for r in _kind(record, "input") if rel in _text(r)]
    assert rows and all(_slot_is(r["slot"], 278) for r in rows), record["disagreements"]
    assert any("afterSha256" in r["detail"] and "cascade" in r["detail"] and re.search(r"\d+ of \d+", r["detail"])
               for r in rows), rows
    assert rel in record["unauthored"]


def _two_hunk_files(files_281):
    return [rel for rel in _clean(files_281)
            if len({h["at"] for h in files_281[rel]["entry"]["reverseHunks"]}) >= 2]


def test_vector_13_reordered_hunks_refuse(cc, tmp_path, a281, files_281):
    """VECTORS 13 (two hunks with descending offsets: class A, a hunk out of order; names the layer's slot);
    Q-282C-2 D9 vector 3 (a reordered hunk refuses)."""
    rels = _two_hunk_files(files_281)
    if not rels:
        pytest.skip("281 has no clean file with two hunks at distinct offsets")
    rel = rels[0]
    tree = _build_281(cc, tmp_path, a281, files_281, [rel],
                      mutate={rel: lambda pairs: sorted(pairs, key=lambda p: p[0]["at"], reverse=True)})
    _, record = _read(cc, tree)
    assert any(_slot_is(r["slot"], 278) and r["kind"] == "input" for r in _rows(record) if r["class"] == "A"), \
        record["disagreements"]


def test_vector_13_missing_hunk_refuses(cc, tmp_path, a281, files_281):
    """VECTORS 13 (class A, a hunk not applying byte-exactly; names the layer's slot); Q-282C-2 D9 vector 4 (a
    missing hunk refuses); README 'with each file's afterSha256 and beforeSha256 checked'."""
    rels = _two_hunk_files(files_281)
    if not rels:
        pytest.skip("281 has no clean file with two hunks at distinct offsets")
    rel = rels[0]
    tree = _build_281(cc, tmp_path, a281, files_281, [rel], mutate={rel: lambda pairs: pairs[:-1]})
    _, record = _read(cc, tree)
    assert any(_slot_is(r["slot"], 278) and r["kind"] == "input" for r in _rows(record) if r["class"] == "A"), \
        record["disagreements"]


def _record_missing(root, auth, side):
    _attach(root, auth, 281, side, write=False)


def _record_unnamed(root, auth, side):
    _attach(root, auth, 281, side, name=False)


def _record_digest_mismatched(root, auth, side):
    _attach(root, auth, 281, side, name_sha="0" * 64)


def _record_not_json(root, auth, side):
    _attach(root, auth, 281, side, data=b"{ not json\n")


def _record_sixth_member(root, auth, side):
    _attach(root, auth, 281, dict(side, oracleNote="a sixth member"))


def _record_member_missing(root, auth, side):
    _attach(root, auth, 281, {key: value for key, value in side.items() if key != "hunkClassRuleSha256"})


def _record_foreign_authority_path(root, auth, side):
    _attach(root, auth, 281, dict(side, authorityPath=NEWER_REL))


def _record_miscounted(root, auth, side):
    classes = {rel: list(seq) + [seq[0]] for rel, seq in side["classes"].items()}
    _attach(root, auth, 281, dict(side, classes=classes))


def _record_duplicated(root, auth, side):
    _attach(root, auth, 281, side)
    _attach(root, auth, 281, side, rel=HC_DIR + "/281-again.json")


def _record_authority_carries_classes(root, auth, side):
    _attach(root, auth, 281, side)
    auth["hunkClassVocabulary"] = list(side["hunkClassVocabulary"])


def _record_bad_context(root, auth, side):
    _attach(root, auth, 281, dict(side, hunkClassContext=dict(side["hunkClassContext"], newPacket="ORACLE-NOT-281")))


RECORD_DEFECTS = {
    "missing": _record_missing,
    "unnamed": _record_unnamed,
    "digest-mismatched": _record_digest_mismatched,
    "malformed-not-json": _record_not_json,
    "malformed-sixth-member": _record_sixth_member,
    "malformed-member-missing": _record_member_missing,
    "foreign-authorityPath": _record_foreign_authority_path,
    "miscounted": _record_miscounted,
    "duplicated": _record_duplicated,
    "authority-carries-classes": _record_authority_carries_classes,
    "bad-context": _record_bad_context,
}


@pytest.mark.parametrize("defect", sorted(RECORD_DEFECTS))
def test_hunk_class_record_defect_is_class_a_input(cc, tmp_path, a281, files_281, defect):
    """README 'The authority's hunk-class record is bound next, before any class is trusted: the authority's newFiles
    names exactly one, its bytes hash to the named digest, and its authorityPath is the authority's. A record that is
    missing, unnamed, digest-mismatched, malformed, miscounted or duplicated, or an authority that carries classes
    itself, is class A, kind input, as is a bad context'; README 'It holds exactly authorityPath, ...'; DOCSTRING
    (the same list, class A; 'nothing here raises out of a hook': the reading returns). Its control is
    test_d9_k0_cascade_step_reads_clean_281_first, the same build with a well-formed record."""
    rels = _clean(files_281)
    assert rels
    tree = _build_281(cc, tmp_path, a281, files_281, rels[:1], record=RECORD_DEFECTS[defect])
    _, record = _read(cc, tree)
    rows = [r for r in _rows(record) if r["class"] == "A" and r["kind"] == "input"]
    assert any(_slot_is(r["slot"], 278) for r in rows), record["disagreements"]


def test_reordered_hunk_class_record_is_class_a(cc, tmp_path, a281, files_281):
    """README 'Each class is re-checked by position by chainmech v2.2's rule, so a reordered record is class A';
    README 'classes ({path: one class per reverse hunk, in the authority's order})'; README 'plus record when
    normalisedRecordClass is true' (so a file mixing record with cascade or bridge hunks is clean under a ledger
    whose normalisedRecordClass is true); DOCSTRING (the reading returns)."""
    rels = [rel for rel in _clean(files_281, NORMALISED_RECORD) if len(set(files_281[rel]["classes"])) >= 2]
    if not rels:
        pytest.skip("281 has no file of normalised hunks holding two different classes, record included")
    rel = rels[0]

    def reordered(root, auth, side):
        seq = list(side["classes"][rel])
        i = next(n for n, klass in enumerate(seq) if klass != seq[0])
        seq[0], seq[i] = seq[i], seq[0]
        classes = dict(side["classes"])
        classes[rel] = seq
        _attach(root, auth, 281, dict(side, classes=classes))

    tree = _build_281(cc, tmp_path, a281, files_281, [rel], record=reordered, normalised_record=True)
    _, record = _read(cc, tree)
    assert any(_slot_is(r["slot"], 278) for r in _rows(record) if r["class"] == "A"), record["disagreements"]


def test_hunk_class_record_rechecked_by_position_is_class_a(cc, tmp_path, a281, files_281):
    """README 'Each class is re-checked by position by chainmech v2.2's rule, so a reordered record is class A': the
    record's class at position 0 is swapped for the other normalised class, so only the re-check by position can
    refuse it (the record still claims a class the reader would undo); README 'one class per reverse hunk, in the
    authority's order'; DOCSTRING 'each recorded class is re-checked by the rule'."""
    rels = _clean(files_281)
    assert rels
    rel = rels[0]

    def substituted(root, auth, side):
        seq = list(side["classes"][rel])
        seq[0] = "bridge" if seq[0] == "cascade" else "cascade"
        classes = dict(side["classes"])
        classes[rel] = seq
        _attach(root, auth, 281, dict(side, classes=classes))

    tree = _build_281(cc, tmp_path, a281, files_281, [rel], record=substituted)
    _, record = _read(cc, tree)
    assert any(_slot_is(r["slot"], 278) for r in _rows(record) if r["class"] == "A"), record["disagreements"]
