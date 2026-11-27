"""D5a oracle tests for MET-016 (slot 298, K = 0): one part per fix member and the head layer.

Owner decision D5a: written outside the candidate by a non-author, black-box, from CN's texts only.
C18: every repository file is read through the head's era reader (head.reviewed_bytes or head._era_read);
the only rooted listing is current_catalog_names(), which lists names and reads no bytes.
Sources of every expected value (cited on or above each assert): CONTRACT_298 r8 (sections 1, 3a, 3c, 4,
5, 6, 7), SCOPE-298 r3 (sections 2 and 2a: F1-F5, D1-D5), the F4 erratum (9aa8556a), CONTRACT_295
section 3b, CONTRACT_296 sections 3a and 3b, GR-DECISION-RECORD-001 r2, REG-ALIGN-001 r4, the masked
MET-016 YAML, and the operator-stated facts of the brief (named "operator-stated").
Records, vectors, schemas, the table, the authority, the hunk-class record, the registry and the YAMLs
are fixtures: they are loaded and mutated, never taken as expectations.
"""

import copy
import importlib.util
import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))


def _load_head():
    spec = importlib.util.spec_from_file_location(
        "_met_016_oracle_head", ROOT / "scripts" / "validate_met_016.py"
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


head = _load_head()

BASE_MAIN = "9a78ed88ece963bc115deabd92c2beb3aa29b12b"  # CONTRACT_298 section 1 inputs
BASE_TREE8 = "816243af"  # CONTRACT_298 section 1 inputs
MEMBER_TESTS = (  # CONTRACT_298 sections 3a, 3c and 6 (the member tests take no row)
    "tests/test_agent_loop_compaction.py",
    "tests/test_replay_fixtures.py",
    "tests/test_approval_outcome.py",
    "tests/test_decision_record.py",
    "tests/test_regulatory_alignment.py",
)
ENV_CAUSES = (  # CONTRACT_295 section 3b (the blockerCode environment causes)
    "PROVIDER_UNAVAILABLE",
    "SANDBOX_UNAVAILABLE",
    "RESOURCE_UNAVAILABLE",
    "FIXTURE_UNAVAILABLE",
)
R2_CHECK_ORDER = [  # CONTRACT_296 section 3a (r2's check order, eight single-record codes)
    "ENVELOPE_MIXED",
    "EFFECTIVE_MISMATCH",
    "ERROR_AS_DECISION",
    "RULE_VERSION_MISSING",
    "MODEL_APPROVAL",
    "MODEL_LOWERED",
    "TRANSFORM_CONFLICT",
    "TRANSFORM_MISMATCH",
]
ERR_CODES = (  # GR-DECISION r2 E1 (the five reserved error codes)
    "ERR_MALFORMED_INPUT",
    "ERR_RULE_NOT_SELECTED",
    "ERR_EVALUATOR_UNAVAILABLE",
    "ERR_TIMEOUT",
    "ERR_INTERNAL",
)
RA_RULES_R4 = [  # REG-ALIGN r4 rules (CONTRACT_296 section 3b: verbatim; CONTRACT_298 section 1: unchanged)
    "state MAPPED requires carrierCheck CONFIRMED or CORRECTED.",
    "a row with candidateState MAPPED has state PARTIAL, gap kind CARRIER_UNCONFIRMED and carrierCheck NOT_CHECKED.",
    "every non-MAPPED row carries a gap with a kind from the enum and a note.",
    "every PRODUCT_GAP gap names carryingItems (roadmap ids) or, when the list is empty, noCarryingItem with the enum's one value.",
    "every EU row carries dateAsEnacted and dateAsAmended; each date object cites a source and a confirmation.",
    "a date object whose source has a held digest carries confirmation HELD_SOURCE and a locator; one whose source has none carries UNCONFIRMED.",
    "dateAlreadyPassed is computed from dateAsEnacted against draftDate.",
    "an obligationLocator naming two places gives a pdfPage for each place.",
]
RA_DRAFT_DATE = "2026-11-22"  # REG-ALIGN r4 draftDate (moved verbatim to the README, CONTRACT_296 section 3b)
RA_README = "architecture/regulatory-alignment-README.md"  # CONTRACT_296 section 3b


# ---------------------------------------------------------------- helpers (plain data only)


def current_catalog_names():
    """The current catalog's names: the sorted stems of the task-packets YAML names under the head's ROOT."""
    return sorted(path.stem for path in (head.ROOT / "task-packets").glob("*.yaml"))


def _catalog():
    return {
        name: head.safe_load(head.reviewed_bytes(f"task-packets/{name}.yaml"))
        for name in current_catalog_names()
    }


@pytest.fixture(scope="module")
def packets():
    return _catalog()


def _json(path):
    return json.loads(head.reviewed_bytes(path))


def _walk(obj):
    yield obj
    if isinstance(obj, dict):
        for value in obj.values():
            yield from _walk(value)
    elif isinstance(obj, (list, tuple)):
        for value in obj:
            yield from _walk(value)


def _first_dict_with(obj, key):
    for node in _walk(obj):
        if isinstance(node, dict) and key in node:
            return node
    return None


def _code(out):
    if isinstance(out, (tuple, list)):
        return out[0] if out else None
    return out


def _positive(case):
    return str(case.get("polarity", "")).strip().lower() in ("positive", "+", "pos", "accept", "accepted")


def _case(vectors, case_id):
    for case in vectors["cases"]:
        if case.get("id") == case_id:
            return copy.deepcopy(case)
    pytest.fail(f"construction: published case {case_id} not found")


def _bases(row):
    return {
        name: head._era_model(path, "_met_016_" + name) for name, path in row["bases"]
    }


def _reader(overrides):
    def read(path):
        if path in overrides:
            return overrides[path]
        return head._era_read(path)

    return read


def _refusal(fn, *args):
    with pytest.raises(ValueError) as info:
        fn(*args)
    return str(info.value)


def _flip(raw):
    data = bytearray(raw)
    data[len(data) // 2] ^= 0x01
    return bytes(data)


# ---------------------------------------------------------------- part 1: HR-295-FIX-001 (F1-F5)


def _compaction_steps(data):
    for node in _walk(data):
        if isinstance(node, list) and any(
            isinstance(item, dict) and item.get("kind") == "COMPACT" for item in node
        ):
            return node
    pytest.fail("construction: no step list holding a COMPACT step")


def _with_compacts(case, count):
    data = copy.deepcopy(case["input"])
    steps = _compaction_steps(data)
    seqs = [step.get("seq") for step in steps if isinstance(step, dict)]
    renumber = bool(seqs) and all(type(v) is int for v in seqs) and seqs == list(
        range(seqs[0], seqs[0] + len(seqs))
    )
    owned = [i for i, step in enumerate(steps) if isinstance(step, dict) and step.get("kind") == "COMPACT"]
    first = owned[0]
    template = copy.deepcopy(steps[first])
    for index in reversed(owned):
        del steps[index]
    for n in range(count):
        extra = copy.deepcopy(template)
        if n > 0 and isinstance(extra.get("detail"), dict):
            extra["detail"]["summaryKind"] = "FALLBACK"
            extra["detail"]["summaryRoute"] = None
        steps.insert(first + n, extra)
    if renumber:
        for offset, step in enumerate(steps):
            step["seq"] = seqs[0] + offset
    return data, len(owned)


@pytest.mark.parametrize(
    "count, expected",
    [(0, "CG_LOCK"), (1, None), (2, None), (3, "CG_LOCK")],  # SCOPE-298 r3 F1
)
def test_f1_lock_bracket_counts_owned_compact_steps(count, expected):
    """SCOPE-298 r3 F1 (CONTRACT_298 section 3a): C1 refuses 0 and 3 owned COMPACT steps with CG_LOCK; 1 and 2 pass."""
    model, _checker = head._era_checker(head.COMPACTION)
    vectors = _json(head.COMPACTION["vectors"])
    base = _case(vectors, "CG-C1-P1")  # SCOPE-298 r3 F1 (1 is CG-C1-P1, kept)
    # SCOPE-298 r3 F1: C1 is the lock-bracket family
    assert base["family"] == "C1"
    # SCOPE-298 r3 F1: CG_LOCK is C1's code
    assert model.CODES["C1"] == "CG_LOCK"
    data, owned = _with_compacts(base, count)
    # SCOPE-298 r3 F1: CG-C1-P1 holds one owned COMPACT step
    assert owned == 1
    # SCOPE-298 r3 F1
    assert _code(model.evaluate("C1", data)) == expected


def test_f1_published_compaction_positives_accepted():
    """CONTRACT_298 section 3a (F1: no committed vector flips): every published compaction positive is accepted."""
    model, _checker = head._era_checker(head.COMPACTION)
    vectors = _json(head.COMPACTION["vectors"])
    positives = [case for case in vectors["cases"] if _positive(case)]
    # CONTRACT_295 section 3a: every positive vector accepted
    assert positives
    for case in positives:
        # CONTRACT_295 section 3a; SCOPE-298 r3 F1 census
        assert _code(model.evaluate(case["family"], copy.deepcopy(case["input"]))) is None, case["id"]


def _trajectory_steps(data):
    for node in _walk(data):
        if isinstance(node, dict) and isinstance(node.get("steps"), list) and node["steps"] and all(
            isinstance(step, dict) and "actor" in step for step in node["steps"]
        ):
            return node["steps"]
    pytest.fail("construction: no trajectory steps in the case input")


def _sent_list(data):
    for node in _walk(data):
        if isinstance(node, dict):
            for key, value in node.items():
                if "sent" in key.lower() and isinstance(value, list) and value:
                    return value
    pytest.fail("construction: no sent-request list in the case input")


def _verdict(out):
    node = _first_dict_with(out, "verdict")
    if node is None:
        pytest.fail("construction: no verdict in the replay result")
    return node


def _replay_eval(model, case, data, vectors, bases):
    return model.evaluate(
        case["check"], data, vectors["stores"], bases["run_manifest"], bases["decision_record"]
    )


def _store_index(vectors, model):
    """The documents the vector set's stores name (brief l.120-121, l.198), keyed by name, path, stem, id and digest.

    CONTRACT_295.md:163-166: `fixtures/` holds the worked fixtures and their trajectories; `blobs/` holds bodies.
    """
    folder = head.REPLAY["vectors"].rsplit("/", 1)[0]
    index = {}

    def add(doc, *names):
        for name in names:
            if isinstance(name, str) and name:
                index.setdefault(name, doc)
        try:
            index.setdefault(model.digest(doc), doc)
        except (TypeError, ValueError):
            pass
        if isinstance(doc, dict):
            for key, value in doc.items():
                if key.endswith("Id") and isinstance(value, str):
                    index.setdefault(value, doc)

    def load(name):
        if name.startswith("architecture/"):
            path = name
        elif "/" in name:
            path = folder + "/" + name
        else:
            path = folder + "/fixtures/" + name
        try:
            return json.loads(head.reviewed_bytes(path))
        except (OSError, ValueError, KeyError):
            return None

    def visit(node, key):
        if isinstance(node, dict):
            if key is not None:
                add(node, key)
            for child_key, child in node.items():
                visit(child, child_key)
        elif isinstance(node, list):
            for child in node:
                visit(child, key)
        elif isinstance(node, str) and node.endswith(".json"):
            doc = load(node)
            if doc is not None:
                stem = node.rsplit("/", 1)[-1][: -len(".json")]
                add(doc, key, node, node.rsplit("/", 1)[-1], stem)

    visit(vectors.get("stores"), None)
    return index


def _resolved(data, index):
    """The case input plus every document it names through the stores, followed up to four links deep."""
    docs = [data]
    seen = set()
    frontier = [data]
    for _depth in range(4):
        found = []
        for doc in frontier:
            for node in _walk(doc):
                if isinstance(node, str) and node in index and node not in seen:
                    seen.add(node)
                    found.append(index[node])
        docs.extend(found)
        frontier = found
    return docs


def _digest_cases(model, vectors, bases):
    """Accepted REPLAY cases under DIGEST, with the fixture and trajectory they name, resolved through the stores.

    A refused REPLAY case gives a refusal code and no verdict (CONTRACT_295.md:187-191;
    HR-REPLAY-FIXTURES-001.draft-r4.md:104), so only cases the model accepts are read for a verdict.
    """
    index = _store_index(vectors, model)
    found = []
    for case in vectors["cases"]:
        if case.get("check") != "REPLAY":
            continue
        docs = _resolved(case["input"], index)
        holder = _first_dict_with(docs, "requestMatch")
        if holder is None or holder.get("requestMatch") != "DIGEST":
            continue
        out = _replay_eval(model, case, copy.deepcopy(case["input"]), vectors, bases)
        if isinstance(_code(out), str):
            continue
        found.append((copy.deepcopy(case), docs, _verdict(out)))
    return found


def test_f2_digest_missing_and_trailing_requests_diverge():
    """SCOPE-298 r3 F2 (CONTRACT_298 section 3a): under DIGEST, count and order; n + 1 for a trailing request."""
    model, _checker = head._era_checker(head.REPLAY)
    bases = _bases(head.REPLAY)
    vectors = _json(head.REPLAY["vectors"])
    exact = {
        case["id"]: (case, docs)
        for case, docs, verdict in _digest_cases(model, vectors, bases)
        if verdict.get("verdict") == "REPLAY_MATCH"
    }
    # SCOPE-298.r3.md:99: RF-RP-P1 and RF-RP-P2 replay exactly under DIGEST
    assert {"RF-RP-P1", "RF-RP-P2"} <= set(exact)
    base, docs = exact["RF-RP-P1"]
    # HR-REPLAY-FIXTURES-001.draft-r4.md:112: the trajectory's steps, from the trajectory the case names
    steps = _trajectory_steps(docs)

    missing = copy.deepcopy(base["input"])
    model_steps = [step for step in steps if step.get("actor") == "MODEL"]
    _sent_list(missing).pop()
    got = _verdict(_replay_eval(model, base, missing, vectors, bases))
    # SCOPE-298 r3 F2: a missing request diverges at its step
    assert got.get("verdict") == "REPLAY_DIVERGED"
    # SCOPE-298 r3 F2: at the step whose request is missing
    assert got.get("divergedAtStep") == model_steps[-1]["index"]

    trailing = copy.deepcopy(base["input"])
    sent = _sent_list(trailing)
    sent.append(copy.deepcopy(sent[-1]))
    got = _verdict(_replay_eval(model, base, trailing, vectors, bases))
    # SCOPE-298 r3 F2: the first extra request gives REPLAY_DIVERGED
    assert got.get("verdict") == "REPLAY_DIVERGED"
    # SCOPE-298 r3 F2: at position len(trajectory.steps) + 1 (SCOPE-298.r3.md:95-96)
    assert got.get("divergedAtStep") == len(steps) + 1
    # SCOPE-298 r3 F2 and HR-REPLAY-FIXTURES-001.draft-r4.md:178: a null after-tree
    assert got.get("afterTreeDigest") is None


def test_f2_trailing_after_final_tool_step():
    """SCOPE-298 r3 F2: a trailing request after a final TOOL step diverges at n + 1 (the pin of n + 1)."""
    model, _checker = head._era_checker(head.REPLAY)
    bases = _bases(head.REPLAY)
    vectors = _json(head.REPLAY["vectors"])
    # SCOPE-298.r3.md:100-102: the base is an accepted DIGEST replay whose trajectory ends in a TOOL step; no
    # REPLAY_MATCH is required, only no divergence before n + 1 (SCOPE-298.r3.md:95: the first extra request decides)
    tool_final = []
    for case, docs, verdict in _digest_cases(model, vectors, bases):
        steps = _trajectory_steps(docs)
        if steps[-1].get("actor") != "TOOL":
            continue
        if verdict.get("verdict") == "REPLAY_DIVERGED" and verdict.get("divergedAtStep") != len(steps) + 1:
            continue
        tool_final.append((case, steps))
    if not tool_final:
        pytest.fail("construction: no accepted DIGEST replay case ends in a TOOL step")
    base, steps = tool_final[0]
    data = copy.deepcopy(base["input"])
    sent = _sent_list(data)
    sent.append(copy.deepcopy(sent[-1]))
    got = _verdict(_replay_eval(model, base, data, vectors, bases))
    # SCOPE-298 r3 F2
    assert got.get("verdict") == "REPLAY_DIVERGED"
    # SCOPE-298 r3 F2: n + 1, which no recorded step can have (SCOPE-298.r3.md:95-97)
    assert got.get("divergedAtStep") == len(steps) + 1
    # SCOPE-298 r3 F2: a null after-tree
    assert got.get("afterTreeDigest") is None


def _blocked_row(data, cause=None):
    for node in _walk(data):
        if isinstance(node, dict) and node.get("outcome") == "BLOCKED" and node.get("blockerCode"):
            if cause is None or node.get("blockerCode") == cause:
                return node
    pytest.fail("construction: no BLOCKED result row")


def test_f3_blocked_blocker_code_must_equal_exit_code():
    """SCOPE-298 r3 F3: BLOCKED with blockerCode other than the exit code is OUTCOME_MISMATCH; RF-BL-P2 matches."""
    model, _checker = head._era_checker(head.REPLAY)
    bases = _bases(head.REPLAY)
    vectors = _json(head.REPLAY["vectors"])
    base = _case(vectors, "RF-BL-P2")  # SCOPE-298 r3 F3 (RF-BL-P2 is the matching one)
    # SCOPE-298 r3 F3: the matching case is accepted
    assert _code(_replay_eval(model, base, copy.deepcopy(base["input"]), vectors, bases)) is None
    data = copy.deepcopy(base["input"])
    row = _blocked_row(data)
    exit_node = _first_dict_with(data, "exit")
    if exit_node is not None and isinstance(exit_node["exit"], dict):
        # SCOPE-298 r3 F3: RF-BL-P2's blockerCode equals trajectory.exit.code
        assert row["blockerCode"] == exit_node["exit"].get("code")
    row["blockerCode"] = next(cause for cause in ENV_CAUSES if cause != row["blockerCode"])
    # SCOPE-298 r3 F3: refused with the existing OUTCOME_MISMATCH
    assert _code(_replay_eval(model, base, data, vectors, bases)) == "OUTCOME_MISMATCH"


def _grade_binding(data, model):
    holder = _first_dict_with(data, "gradeRecords")
    if holder is None or not isinstance(holder["gradeRecords"], list):
        pytest.fail("construction: no gradeRecords list")
    row = _blocked_row(data, "EVALUATOR_ERROR")
    records = holder["gradeRecords"]
    for index, record in enumerate(records):
        if model.digest(record) == row.get("evidenceDigest"):
            return holder, index, row
    return holder, None, row


def _rebind(model, holder, index, row, change):
    record = holder["gradeRecords"][index]
    change(record)
    row["evidenceDigest"] = model.digest(record)


def _wrong_kind(record):
    record["kind"] = "GUARDRAIL"


def _non_error(record):
    envelope = record["envelope"]
    envelope["status"] = "DECIDED"
    envelope["decision"] = "FAIL"
    envelope["effectiveDecision"] = "FAIL"
    envelope["error"] = None


def _refused_record(record):
    record["envelope"]["effectiveDecision"] = "PASS"


@pytest.mark.parametrize("mutation", ["missing", "mismatch", "wrong_kind", "non_error", "refused"])
def test_f5_evaluator_error_binds_the_supplied_record(mutation):
    """SCOPE-298 r3 F5 (CONTRACT_298 sections 3a and 7): the GRADE ERROR record is bound by computed digest."""
    model, _checker = head._era_checker(head.REPLAY)
    bases = _bases(head.REPLAY)
    vectors = _json(head.REPLAY["vectors"])
    base = _case(vectors, "RF-BL-P1")  # SCOPE-298 r3 F5 (RF-BL-P1 carries the published record)
    data = copy.deepcopy(base["input"])
    holder, index, row = _grade_binding(data, model)
    # SCOPE-298 r3 F5: digest(record) == evidenceDigest, a computed equality
    assert index is not None
    record = holder["gradeRecords"][index]
    # SCOPE-298 r3 F5: kind GRADE, envelope.status ERROR
    assert (record["kind"], record["envelope"]["status"]) == ("GRADE", "ERROR")
    # SCOPE-298 r3 F5: evaluate(record) is ACCEPTED
    assert bases["decision_record"].evaluate(copy.deepcopy(record))[0] == "ACCEPTED"
    # SCOPE-298 r3 F5: the bound GRADE ERROR record is accepted
    assert _code(_replay_eval(model, base, copy.deepcopy(data), vectors, bases)) is None
    if mutation == "missing":
        del holder["gradeRecords"][index]
    elif mutation == "mismatch":
        digest = row["evidenceDigest"]
        row["evidenceDigest"] = digest[:-1] + ("0" if digest[-1] != "0" else "1")
    elif mutation == "wrong_kind":
        _rebind(model, holder, index, row, _wrong_kind)
    elif mutation == "non_error":
        _rebind(model, holder, index, row, _non_error)
    else:
        _rebind(model, holder, index, row, _refused_record)
        # GR-DECISION r2 E2: never PASS on an ERROR record
        assert bases["decision_record"].evaluate(copy.deepcopy(holder["gradeRecords"][index]))[0] != "ACCEPTED"
    # SCOPE-298 r3 F5: missing record, digest mismatch, wrong kind, non-error grade, refused record: refused
    assert _code(_replay_eval(model, base, data, vectors, bases)) is not None


def test_f5_rf_bl_n3_binds_the_published_record_and_fails_on_outcome():
    """CONTRACT_298 section 7 (fix 1): RF-BL-N3 binds RF-BL-P1's record by computed digest; its defect is OUTCOME_MISMATCH."""
    model, _checker = head._era_checker(head.REPLAY)
    bases = _bases(head.REPLAY)
    vectors = _json(head.REPLAY["vectors"])
    p1 = _case(vectors, "RF-BL-P1")
    n3 = _case(vectors, "RF-BL-N3")
    _h1, i1, _r1 = _grade_binding(copy.deepcopy(p1["input"]), model)
    holder, index, _row = _grade_binding(n3["input"], model)
    # CONTRACT_298 section 7 (r8): RF-BL-N3's evidenceDigest is the record's computed digest
    assert index is not None and i1 is not None
    p1_record = _first_dict_with(p1["input"], "gradeRecords")["gradeRecords"][i1]
    # CONTRACT_298 section 7 (r8): RF-BL-P1's GRADE record, last in gradeRecords
    assert holder["gradeRecords"][-1] == p1_record
    # CONTRACT_298 section 7 (r8): its one defect is its outcome
    assert _code(_replay_eval(model, n3, copy.deepcopy(n3["input"]), vectors, bases)) == "OUTCOME_MISMATCH"


def _find_all(obj, key):
    return [node[key] for node in _walk(obj) if isinstance(node, dict) and key in node]


def _is_grader_error_row(node):
    if isinstance(node, dict):
        values = list(node.values())
    elif isinstance(node, list):
        values = node
    else:
        return False
    blocked = any(value == "BLOCKED" for value in values)
    zero = any((type(value) is int and value == 0) or value == "0" for value in values)
    return blocked and zero and "EVALUATOR_ERROR" in json.dumps(node, sort_keys=True)


def _blocked_rows(obj):
    """The exit-to-outcome map's grader-error row, selected by its CN content: outcome BLOCKED, score 0, and the
    EVALUATOR_ERROR condition (SCOPE-298.r3.md:134; CONTRACT_295.md:183-184); the smallest such node only."""
    rows = []
    for node in _walk(obj):
        if _is_grader_error_row(node):
            children = node.values() if isinstance(node, dict) else node
            if not any(_is_grader_error_row(child) for child in children):
                rows.append(json.dumps(node, sort_keys=True))
    return sorted(rows)


def test_f5_fixture_lock_rule_and_blocked_row_unchanged():
    """CONTRACT_298 section 1 and SCOPE-298 r3 F5 (R12 condition 1): fixtureLockRule and the BLOCKED row unchanged."""
    path = head.REPLAY["record"]
    after_raw = head.reviewed_bytes(path)
    before_raw = head._undo_this_layer(path, after_raw)
    before, after = json.loads(before_raw), json.loads(after_raw)
    # SCOPE-298 r3 F5: the record holds fixtureLockRule
    assert _find_all(after, "fixtureLockRule")
    # SCOPE-298 r3 F5 (R12 condition 1): fixtureLockRule unchanged
    assert _find_all(before, "fixtureLockRule") == _find_all(after, "fixtureLockRule")
    # SCOPE-298 r3 F5 (R12 condition 1): the BLOCKED EVALUATOR_ERROR row exists
    assert _blocked_rows(after)
    # SCOPE-298 r3 F5 (R12 condition 1): the BLOCKED EVALUATOR_ERROR row unchanged
    assert _blocked_rows(before) == _blocked_rows(after)


def test_f2_f3_f5_published_replay_positives_accepted():
    """CONTRACT_298 section 3a (no committed vector flips under F1-F4): every published replay positive accepted."""
    model, _checker = head._era_checker(head.REPLAY)
    bases = _bases(head.REPLAY)
    vectors = _json(head.REPLAY["vectors"])
    positives = [case for case in vectors["cases"] if _positive(case)]
    # CONTRACT_295 section 3b: positives exist
    assert positives
    for case in positives:
        # CONTRACT_298 section 3a; SCOPE-298 r3 census
        assert _code(_replay_eval(model, case, copy.deepcopy(case["input"]), vectors, bases)) is None, case["id"]


def _history(data):
    node = _first_dict_with(data, "sweepInterval")
    if node is None:
        pytest.fail("construction: no history with sweepInterval")
    return node


@pytest.mark.parametrize(
    "interval, expected",
    [(3601, "AO_SHAPE"), (5000, "AO_SHAPE"), (3600, None)],  # F4 erratum (SWEEP_MIN <= v <= SWEEP_MAX = 3600)
)
def test_f4_history_sweep_interval_bound(interval, expected):
    """F4 erratum (CONTRACT_298 section 3a): a history's sweepInterval above 3,600 is refused AO_SHAPE."""
    model, _checker = head._era_checker(head.APPROVAL)
    vectors = _json(head.APPROVAL["vectors"])
    base = _case(vectors, "AO-A-H2")  # SCOPE-298 r3 F4 (the boundary vector)
    data = copy.deepcopy(base["input"])
    _history(data)["sweepInterval"] = interval
    # F4 erratum: 3,601 and 5,000 decide AO_SHAPE at the shape check
    assert _code(model.evaluate(base["check"], data)) == expected


def test_f4_boundary_write_accepted_late_write_refused():
    """SCOPE-298 r3 F4: a boundary write at E + I (AO-A-H2, recordedAt 400) is accepted; a late write refused."""
    model, _checker = head._era_checker(head.APPROVAL)
    vectors = _json(head.APPROVAL["vectors"])
    # Hub ruling, reading B (SCOPE-298.r3.md:119-122, :140): the boundary write is built from a deep copy of AO-A-H2;
    # the published AO-A-H2 is not required to hold recordedAt 400.
    base = _case(vectors, "AO-A-H2")  # SCOPE-298.r3.md:121, :250
    data = copy.deepcopy(base["input"])
    request = _first_dict_with(data, "expiresAt")
    if request is None:
        pytest.fail("construction: no expiresAt in AO-A-H2")
    expires = request["expiresAt"]
    interval = _history(data)["sweepInterval"]
    # SCOPE-298.r3.md:250: AO-A-H2's E + I = 400
    assert expires + interval == 400
    writes = [node for node in _walk(data) if isinstance(node, dict) and "recordedAt" in node]
    expired = [node for node in writes if "EXPIRED" in node.values()] or [
        node for node in writes if node.get("occurredAt") == expires
    ] or writes
    if not expired:
        pytest.fail("construction: no decided write in AO-A-H2")
    # SCOPE-298.r3.md:114-116: the EXPIRED decided write at E + I (occurredAt stays expiresAt)
    expired[0]["recordedAt"] = expires + interval
    # SCOPE-298.r3.md:115-116, :121: the boundary write at E + I is accepted
    assert _code(model.evaluate(base["check"], copy.deepcopy(data))) is None
    expired[0]["recordedAt"] = expires + interval + 1
    # SCOPE-298.r3.md:117, :120: a late write is refused
    assert _code(model.evaluate(base["check"], data)) is not None


def test_f4_published_approval_positives_accepted():
    """CONTRACT_298 section 3a (no committed vector flips under F1-F4): every published approval positive accepted."""
    model, _checker = head._era_checker(head.APPROVAL)
    vectors = _json(head.APPROVAL["vectors"])
    positives = [case for case in vectors["cases"] if _positive(case)]
    # CONTRACT_295 section 3c: positives exist
    assert positives
    for case in positives:
        # CONTRACT_298 section 3a; SCOPE-298 r3 census
        assert _code(model.evaluate(case["check"], copy.deepcopy(case["input"]))) is None, case["id"]


# ---------------------------------------------------------------- part 2: DEC-ALIGN-296-FIX-001 (D1-D5)


def _accepted_records(model):
    vectors = _json(head.DECISION["vectors"])
    out = []
    for case in vectors["cases"]:
        if case.get("kind") != "RECORD":
            continue
        record = copy.deepcopy(case["input"])
        if model.evaluate(copy.deepcopy(record))[0] == "ACCEPTED":
            out.append((case["id"], record))
    return out


def _pick(records, predicate, what):
    for case_id, record in records:
        if predicate(record):
            return copy.deepcopy(record)
    pytest.fail(f"construction: no accepted published record with {what}")


def _named_contribution(record):
    return any(
        isinstance(c, dict) and isinstance(c.get("ruleId"), str) and c["ruleId"]
        for c in record.get("contributions") or []
    )


def _set_contribution(record, key, value):
    for contribution in record["contributions"]:
        if isinstance(contribution, dict) and isinstance(contribution.get("ruleId"), str) and contribution["ruleId"]:
            contribution[key] = value
            return record
    return record


@pytest.mark.parametrize("key", ["ruleId", "ruleVersion"])
def test_d1_contribution_rule_fields_non_empty(key):
    """SCOPE-298 r3 D1 point 1: a contribution's ruleId and ruleVersion are non-empty strings (paired case)."""
    model, _checker = head._era_checker(head.DECISION)
    base = _pick(_accepted_records(model), _named_contribution, "a named contribution")
    # SCOPE-298 r3 D1: the published positive stays ACCEPTED
    assert model.evaluate(copy.deepcopy(base))[0] == "ACCEPTED"
    # SCOPE-298 r3 D1: an empty string is refused
    assert model.evaluate(_set_contribution(copy.deepcopy(base), key, ""))[0] != "ACCEPTED"
    # SCOPE-298 r3 D1: a non-string is refused
    assert model.evaluate(_set_contribution(copy.deepcopy(base), key, 7))[0] != "ACCEPTED"


def test_d1_approval_row_closed():
    """SCOPE-298 r3 D1 point 2: the approval row is closed to the schema's keys (paired case)."""
    model, _checker = head._era_checker(head.DECISION)
    base = _pick(
        _accepted_records(model),
        lambda r: r.get("kind") == "APPROVAL" and isinstance(r.get("approval"), dict),
        "an approval row",
    )
    # SCOPE-298 r3 D1: the published positive stays ACCEPTED
    assert model.evaluate(copy.deepcopy(base))[0] == "ACCEPTED"
    mutated = copy.deepcopy(base)
    mutated["approval"]["oracleUnlistedKey"] = "x"
    # SCOPE-298 r3 D1: a key outside the schema's list is refused
    assert model.evaluate(mutated)[0] != "ACCEPTED"


def test_d1_match_fingerprint_empty_refused():
    """SCOPE-298 r3 D1 point 3: an evidence row's matchFingerprint of "" is refused (paired case)."""
    model, _checker = head._era_checker(head.DECISION)
    base = _pick(
        _accepted_records(model),
        lambda r: any(isinstance(e, dict) and "matchFingerprint" in e for e in r.get("evidence") or []),
        "an evidence row",
    )
    row = next(e for e in base["evidence"] if isinstance(e, dict) and "matchFingerprint" in e)
    row["matchFingerprint"] = "oracle-fingerprint"
    # SCOPE-298 r3 D1 (schema minLength 1): a non-empty fingerprint is accepted
    assert model.evaluate(copy.deepcopy(base))[0] == "ACCEPTED"
    row["matchFingerprint"] = ""
    # SCOPE-298 r3 D1: "" is refused
    assert model.evaluate(base)[0] != "ACCEPTED"


def test_d1_unknown_approval_contribution_decision_reads_fail_closed():
    """SCOPE-298 r3 D1 point 4 (GR-DECISION r2 E7): an unknown decision in an APPROVAL contribution reads fail closed."""
    model, _checker = head._era_checker(head.DECISION)
    records = _accepted_records(model)
    # GR-DECISION-RECORD-001.draft-r2.md:172 (P5, APPROVAL APPROVED): the pair is built on an accepted APPROVAL record
    base = _pick(records, lambda r: r.get("kind") == "APPROVAL", "kind APPROVAL")
    # SCOPE-298 r3 D1: the published positive stays ACCEPTED
    assert model.evaluate(copy.deepcopy(base))[0] == "ACCEPTED"
    template = next(
        (
            copy.deepcopy(c)
            for _i, record in records
            for c in record.get("contributions") or []
            if isinstance(c, dict) and c.get("source") == "MODEL" and isinstance(c.get("model"), dict)
        ),
        None,
    )
    if template is None:
        digest = next(
            (n for n in _walk(base) if isinstance(n, str) and n.startswith("sha256:") and len(n) == 71),
            "sha256:" + "0" * 64,
        )
        # GR-DECISION-RECORD-001.draft-r2.md:59: model is MAS-RA-002's model identity plus usage
        template = {
            "source": "MODEL",
            "model": {
                "modelId": "oracle-model",
                "configurationDigest": digest,
                "promptDigest": digest,
                "tokensIn": 0,
                "tokensOut": 0,
            },
        }
    rule = base.get("rule") if isinstance(base.get("rule"), dict) else {}
    template["ruleId"] = rule.get("ruleId") or template.get("ruleId") or "oracle-rule"
    template["ruleVersion"] = rule.get("ruleVersion") or template.get("ruleVersion") or "1"
    template["decision"] = None  # GR-DECISION-RECORD-001.draft-r2.md:132 (E6a: a MODEL contribution has decision null)
    template["score"] = None  # GR-DECISION-RECORD-001.draft-r2.md:59 (score 0..1,000,000 or null)
    if not isinstance(base.get("contributions"), list):
        base["contributions"] = []
    base["contributions"].append(template)
    # SCOPE-298.r3.md:159 (one paired case) with GR-DECISION-RECORD-001.draft-r2.md:132: the control is ACCEPTED
    assert model.evaluate(copy.deepcopy(base))[0] == "ACCEPTED"
    base["contributions"][-1]["decision"] = "ORACLE_UNKNOWN_DECISION"  # outside APPROVAL's set (draft-r2.md:72)
    # SCOPE-298.r3.md:158 and GR-DECISION-RECORD-001.draft-r2.md:152-153 (E7): read fail closed
    assert model.evaluate(base)[0] == "READ_FAIL_CLOSED"


def test_d1_published_positives_stay_accepted():
    """SCOPE-298 r3 D1: the published positives (P1-P8, RECORD kind) stay ACCEPTED."""
    model, _checker = head._era_checker(head.DECISION)
    vectors = _json(head.DECISION["vectors"])
    positives = [
        case for case in vectors["cases"]
        if case.get("kind") == "RECORD" and str(case.get("id", "")).split("-")[-1][:1] == "P"
    ]
    # CONTRACT_296 section 3a: positives P1-P8 exist
    assert positives
    for case in positives:
        # SCOPE-298 r3 D1: the published positives stay ACCEPTED
        assert model.evaluate(copy.deepcopy(case["input"]))[0] == "ACCEPTED", case["id"]


def test_d2_check_order_grows_by_one_after_e4():
    """SCOPE-298 r3 D2: CHECK_ORDER is r2's order with one new code after E4's ERROR_AS_DECISION."""
    model, _checker = head._era_checker(head.DECISION)
    order = list(model.CHECK_ORDER)
    # SCOPE-298 r3 D2: one entry more than GR-DECISION r2's order (CONTRACT_296 section 3a)
    assert len(order) == len(R2_CHECK_ORDER) + 1
    new_code = order[order.index("ERROR_AS_DECISION") + 1]
    # SCOPE-298 r3 D2: a new refusal code
    assert new_code not in R2_CHECK_ORDER
    # SCOPE-298 r3 D2: the others in their order, the new one after E4
    assert [code for code in order if code != new_code] == R2_CHECK_ORDER


def _new_code(model):
    order = list(model.CHECK_ORDER)
    return order[order.index("ERROR_AS_DECISION") + 1]


def test_d2_cross_kind_policy_reason_refused():
    """SCOPE-298 r3 D2: a DECIDED record's reason is its kind's code for its decision (a cross-kind reason refused)."""
    model, _checker = head._era_checker(head.DECISION)
    records = _accepted_records(model)
    decided = [
        r for _i, r in records
        if r.get("envelope", {}).get("status") == "DECIDED"
        and isinstance(r.get("reasonCode"), str) and not r["reasonCode"].startswith("ERR_")
    ]
    pair = next(
        ((a, b) for a in decided for b in decided
         if a.get("kind") != b.get("kind") and a["reasonCode"] != b["reasonCode"]),
        None,
    )
    if pair is None:
        pytest.fail("construction: no two accepted DECIDED records of different kinds")
    control, other = copy.deepcopy(pair[0]), pair[1]
    # SCOPE-298 r3 D2: the valid control is ACCEPTED
    assert model.evaluate(copy.deepcopy(control))[0] == "ACCEPTED"
    control["reasonCode"] = other["reasonCode"]
    # SCOPE-298 r3 D2: refused with the new code
    assert tuple(model.evaluate(control)) == ("REFUSED", _new_code(model))


def _error_record(model):
    return _pick(
        _accepted_records(model),
        lambda r: r.get("envelope", {}).get("status") == "ERROR"
        and isinstance(r.get("envelope", {}).get("error"), dict),
        "an ERROR envelope",
    )


def test_d2_error_reason_equals_its_error_code():
    """SCOPE-298 r3 D2: an ERROR record's reason equals its envelope.error.code (two refusals, one control)."""
    model, _checker = head._era_checker(head.DECISION)
    control = _error_record(model)
    own = control["envelope"]["error"]["code"]
    # SCOPE-298 r3 D2: the valid control's reason is its own error code
    assert control.get("reasonCode") == own
    # SCOPE-298 r3 D2: the valid control is ACCEPTED
    assert model.evaluate(copy.deepcopy(control))[0] == "ACCEPTED"
    mismatched = copy.deepcopy(control)
    mismatched["reasonCode"] = next(code for code in ERR_CODES if code != own)
    # SCOPE-298 r3 D2: a registered but mismatched error reason is refused with the new code
    assert tuple(model.evaluate(mismatched)) == ("REFUSED", _new_code(model))
    unregistered = copy.deepcopy(control)
    unregistered["reasonCode"] = "ERR_" + "ORACLE_UNREGISTERED"
    # SCOPE-298 r3 D2: an unregistered ERR_ value is refused
    assert model.evaluate(unregistered)[0] != "ACCEPTED"


def _alignment():
    path = head.ALIGNMENT["record"]
    return path, json.loads(head.reviewed_bytes(path))


def _ra_check(checker, path, record=None, readme=None):
    overrides = {}
    if record is not None:
        overrides[path] = json.dumps(record, indent=1, ensure_ascii=False).encode("utf-8") + b"\n"
    if readme is not None:
        overrides[RA_README] = readme
    return checker.check(_reader(overrides))


def test_d3_rule_one_on_both_row_lists():
    """SCOPE-298 r3 D3: an EU row in state MAPPED is refused beside the ordinary-row case; the rules unchanged."""
    _model, checker = head._era_checker(head.ALIGNMENT)
    path, record = _alignment()
    # SCOPE-298 r3 D3 and CONTRACT_298 section 1: the record's rules unchanged
    assert record["rules"] == RA_RULES_R4
    # CONTRACT_296 section 3b: the published record passes
    assert _ra_check(checker, path) == []
    eu = copy.deepcopy(record)
    eu["euDates"][0]["state"] = "MAPPED"
    # SCOPE-298 r3 D3: an EU row in state MAPPED is refused (no carrier field yet)
    assert _ra_check(checker, path, eu) != []
    row = copy.deepcopy(record)
    target = next(r for r in row["rows"] if r.get("carrierCheck") == "NOT_CHECKED")
    target["state"] = "MAPPED"
    # REG-ALIGN r4 rule 1: an ordinary row MAPPED without CONFIRMED or CORRECTED is refused
    assert _ra_check(checker, path, row) != []


@pytest.mark.parametrize("value", ["abc", "SHA256:UPPER", "prefix"])
def test_d4_source_digest_null_or_64_hex(value):
    """SCOPE-298 r3 D4: a source's sha256 is null or 64 lower hex; a sha256:-prefixed value is refused."""
    _model, checker = head._era_checker(head.ALIGNMENT)
    path, record = _alignment()
    # SCOPE-298 r3 D4: the published digest is accepted, a null source with UNCONFIRMED included
    assert _ra_check(checker, path) == []
    nulls = [s for s in record["sources"] if s.get("sha256") is None]
    # SCOPE-298 r3 D4 (REG-ALIGN r4 sources: BENCH-EU-DATES has sha256 null)
    assert nulls
    held = next(i for i, s in enumerate(record["sources"]) if isinstance(s.get("sha256"), str))
    mutated = copy.deepcopy(record)
    digest = mutated["sources"][held]["sha256"]
    if value == "prefix":
        mutated["sources"][held]["sha256"] = "sha256:" + digest
    elif value == "SHA256:UPPER":
        mutated["sources"][held]["sha256"] = digest.upper()
    else:
        mutated["sources"][held]["sha256"] = value
    # SCOPE-298 r3 D4: anything else is refused
    assert _ra_check(checker, path, mutated) != []


def test_d5_invalid_dates_refused():
    """SCOPE-298 r3 D5: an impossible day, a malformed amended date and an invalid draft day are refused."""
    _model, checker = head._era_checker(head.ALIGNMENT)
    path, record = _alignment()
    impossible = copy.deepcopy(record)
    impossible["euDates"][0]["dateAsEnacted"]["date"] = "2026-02-30"
    # SCOPE-298 r3 D5: an impossible day is refused
    assert _ra_check(checker, path, impossible) != []
    malformed = copy.deepcopy(record)
    malformed["euDates"][0]["dateAsAmended"]["date"] = "2026-8-02"
    # SCOPE-298 r3 D5: a malformed amended date is refused
    assert _ra_check(checker, path, malformed) != []
    readme = head._era_read(RA_README)
    # REG-ALIGN r4 draftDate, moved verbatim to the README (CONTRACT_296 section 3b)
    assert RA_DRAFT_DATE.encode("ascii") in readme
    bad_readme = readme.replace(RA_DRAFT_DATE.encode("ascii"), b"2026-11-31")
    # SCOPE-298 r3 D5: an invalid draft day is refused
    assert _ra_check(checker, path, None, bad_readme) != []


@pytest.mark.parametrize(
    "enacted, passed",
    [("2026-11-21", True), ("2026-11-22", False), ("2026-11-23", False)],  # SCOPE-298 r3 D5; REG-ALIGN r4 rule 7
)
def test_d5_rule_seven_strict_before(enacted, passed):
    """SCOPE-298 r3 D5: rule 7 on parsed days with the strict "before" boundary: before, on, after accepted."""
    _model, checker = head._era_checker(head.ALIGNMENT)
    path, record = _alignment()
    good = copy.deepcopy(record)
    good["euDates"][0]["dateAsEnacted"]["date"] = enacted
    good["euDates"][0]["dateAlreadyPassed"] = passed
    # SCOPE-298 r3 D5: a valid date with rule 7's flag is accepted
    assert _ra_check(checker, path, good) == []
    bad = copy.deepcopy(good)
    bad["euDates"][0]["dateAlreadyPassed"] = not passed
    # REG-ALIGN r4 rule 7: the other flag is refused
    assert _ra_check(checker, path, bad) != []


# ---------------------------------------------------------------- part 3: the head layer


def test_v1_packet_files():
    """CONTRACT_298 section 4 (V1): the packet files hold; a changed byte and a missing file are refused."""
    # CONTRACT_298 section 4: V1 passes on the live inputs
    assert head.validate_packet_files() is None
    files = {path: head.reviewed_bytes(path) for path in head.PACKET_FILES}
    # operator-stated: check_packet_files returns None on the era bytes
    assert head.check_packet_files(dict(files)) is None
    first = sorted(files)[0]
    changed = dict(files)
    changed[first] = _flip(files[first])
    # operator-stated: the message contains MET-016
    assert "MET-016" in _refusal(head.check_packet_files, changed)
    missing = dict(files)
    del missing[first]
    # operator-stated: the message contains MET-016
    assert "MET-016" in _refusal(head.check_packet_files, missing)


E1_MEMBERS = [
    ("COMPACTION", "compaction", True),
    ("REPLAY", "replay_fixtures", True),
    ("APPROVAL", "approval_outcome", True),
    ("DECISION", "decision_record", True),
    ("ALIGNMENT", "regulatory_alignment", False),
]


@pytest.mark.parametrize("row_name, suffix, has_vectors", E1_MEMBERS)
def test_e1_each_owning_record(row_name, suffix, has_vectors, packets):
    """CONTRACT_298 section 3 (E1, one per owning record): passes live; refusals and replay mutations refused."""
    row = getattr(head, row_name)
    # CONTRACT_298 section 3: E1 passes on the live inputs (the current catalog)
    assert getattr(head, "validate_" + suffix)(packets) is None
    check = getattr(head, "check_" + suffix)
    if not has_vectors:
        # operator-stated: no refusals pass
        assert check([]) is None
        # operator-stated: a non-empty refusal list is refused, message with MET-016
        assert "MET-016" in _refusal(check, [("RA_SHAPE", "oracle")])
        return
    vectors = _json(row["vectors"])
    count = len(vectors["cases"])
    # operator-stated: one boolean per case, all True, no refusals pass
    assert check(vectors, [], [True] * count) is None
    # operator-stated: a non-empty refusal list is refused
    assert "MET-016" in _refusal(check, vectors, [("ORACLE", "oracle")], [True] * count)
    one_false = [True] * count
    one_false[-1] = False
    # operator-stated: one False in replayed is refused
    assert "MET-016" in _refusal(check, vectors, [], one_false)
    # operator-stated: a replayed shorter than the cases is refused
    assert "MET-016" in _refusal(check, vectors, [], [True] * (count - 1))


def test_e1_era_checkers_pass():
    """CONTRACT_298 section 3: each owning record's era checker returns no refusals at the candidate."""
    for row in head.MEMBERS:
        _model, checker = head._era_checker(row)
        # MET-016 YAML expectedEvidence: each fixed record's checker passes (refusals [])
        assert checker.check(head._era_read) == [], row["item"]


def test_e2_base_files():
    """CONTRACT_298 section 4 (E2): base files hold; a changed byte and a base file named in changed are refused."""
    # CONTRACT_298 section 4: E2 passes on the live inputs
    assert head.validate_base_files() is None
    auth = head.authority()
    files = {path: head.reviewed_bytes(path) for path in head.BASE_FILES}
    changed, new = auth["changedFiles"], auth["newFiles"]
    # operator-stated: the era inputs pass
    assert head.check_base_files(dict(files), changed, new) is None
    first = sorted(files)[0]
    flipped = dict(files)
    flipped[first] = _flip(files[first])
    # operator-stated: a changed base byte is refused
    assert "MET-016" in _refusal(head.check_base_files, flipped, changed, new)
    named = copy.deepcopy(changed)
    named[first] = copy.deepcopy(next(iter(changed.values())))
    # operator-stated: a base file named in changed is refused
    assert "MET-016" in _refusal(head.check_base_files, dict(files), named, new)


def _set_word(value, word):
    if isinstance(value, str):
        return word
    if isinstance(value, list) and value:
        value[0] = _set_word(value[0], word)
        return value
    if isinstance(value, dict) and value:
        for key in ("class", "hunkClass", "cls"):
            if key in value:
                value[key] = word
                return value
        key = next(iter(value))
        value[key] = _set_word(value[key], word)
    return value


def _class_on_outside(classes, errata, word):
    mutated = copy.deepcopy(classes)
    if isinstance(mutated, dict):
        for path in sorted(mutated):
            if path not in errata:
                mutated[path] = _set_word(mutated[path], word)
                return mutated
    if isinstance(mutated, list):
        for entry in mutated:
            if isinstance(entry, dict) and entry.get("path") not in errata:
                rest = {k: v for k, v in entry.items() if k != "path"}
                _set_word(rest, word)
                entry.update(rest)
                return mutated
    pytest.fail("construction: no class entry outside ERRATA_LINES")


def test_e3_errata():
    """CONTRACT_298 section 4 (E3): the errata hold; an other class outside ERRATA_LINES is refused."""
    # CONTRACT_298 section 4: E3 passes on the live inputs
    assert head.validate_errata() is None
    record = _json(head.HUNK_RECORD_PATH)
    changed = head.authority()["changedFiles"]
    befores = {path: head._undo_this_layer(path, head.reviewed_bytes(path)) for path in head.ERRATA_LINES}
    # operator-stated: the era inputs pass
    assert head.check_errata(copy.deepcopy(record["classes"]), changed, befores) is None
    mutated = _class_on_outside(record["classes"], set(head.ERRATA_LINES), "other")
    # brief item 3 (operator-stated): an other class outside ERRATA_LINES is refused
    assert "MET-016" in _refusal(head.check_errata, mutated, changed, befores)


def _registry_entries(doc):
    if isinstance(doc, list):
        return doc
    lists = [value for value in doc.values() if isinstance(value, list)]
    if len(lists) != 1:
        pytest.fail("construction: the registry's entry list is not unique")
    return lists[0]


def test_v4_registry():
    """CONTRACT_298 sections 5 and 6 (V4): the registry is the base plus the one MET-016/packet rider, 45 entries."""
    # CONTRACT_298 section 4: V4 passes on the live inputs
    assert head.validate_registry() is None
    raw = head.reviewed_bytes(head.REGISTRY_PATH)
    briefs = {head.PACKET_BRIEF: head.reviewed_bytes(head.PACKET_BRIEF)}
    # operator-stated: the era inputs pass
    assert head.check_registry(raw, briefs) is None
    doc = json.loads(raw)
    entries = _registry_entries(doc)
    # CONTRACT_298 section 1 (the rider 44 -> 45); operator-stated: 45 entries
    assert len(entries) == 45
    # CONTRACT_298 section 1: the last entry is the MET-016/packet rider
    assert "MET-016/packet" in json.dumps(entries[-1])
    # CONTRACT_298 section 1: one rider only
    assert sum("MET-016/packet" in json.dumps(entry) for entry in entries) == 1
    less = copy.deepcopy(doc)
    _registry_entries(less).pop()
    # CONTRACT_298 section 5: the base without the rider is refused
    assert "MET-016" in _refusal(head.check_registry, json.dumps(less, indent=2).encode("utf-8"), briefs)
    twice = copy.deepcopy(doc)
    _registry_entries(twice).append(copy.deepcopy(entries[-1]))
    # CONTRACT_298 section 5: the rider twice is refused
    assert "MET-016" in _refusal(head.check_registry, json.dumps(twice, indent=2).encode("utf-8"), briefs)


def _v6_inputs(record):
    auth = head.authority()
    changed = auth["changedFiles"]
    afters = {path: head.reviewed_bytes(path) for path in changed}
    classify = head._era_rule(head.READER_PATH, head.READER_NAME).classify
    context = head._v24_context(auth, record["hunkClassContext"])
    return changed, afters, classify, context


def _raw(doc):
    return json.dumps(doc, indent=2, sort_keys=False).encode("utf-8") + b"\n"


def test_v6_hunk_record():
    """CONTRACT_298 section 4 (V6): the hunk-class record holds; its closed members, vocabulary and v2.5 rule pinned."""
    # CONTRACT_298 section 4: V6 passes on the live inputs
    assert head.validate_hunk_record() is None
    raw = head.reviewed_bytes(head.HUNK_RECORD_PATH)
    record = json.loads(raw)
    changed, afters, classify, context = _v6_inputs(record)
    rule = head.HUNK_RULE_SHA256
    # operator-stated: the era inputs pass
    assert head.check_hunk_record(raw, changed, afters, classify, context, rule) is None
    # operator-stated (K = 0): steps [1, 1]
    assert record["hunkClassContext"]["steps"] == [1, 1]
    # operator-stated (K = 0): countPairs []
    assert record["hunkClassContext"]["countPairs"] == []
    extra = copy.deepcopy(record)
    extra["oracleExtraMember"] = 1
    # brief item 3: the record's closed members
    assert "MET-016" in _refusal(head.check_hunk_record, _raw(extra), changed, afters, classify, context, rule)
    vocab = copy.deepcopy(record)
    vocab["classes"] = _class_on_outside(record["classes"], set(), "ORACLE_NOT_A_CLASS")
    # brief item 3: the record's vocabulary
    assert "MET-016" in _refusal(head.check_hunk_record, _raw(vocab), changed, afters, classify, context, rule)
    wrong_rule = rule[:-1] + ("0" if rule[-1] != "0" else "1")
    # brief item 3: v2.5's rule digest
    assert "MET-016" in _refusal(head.check_hunk_record, raw, changed, afters, classify, context, wrong_rule)


@pytest.mark.parametrize("key, value", [("steps", [1, 2]), ("countPairs", [[1, 1]])])
def test_v6_k0_context(key, value):
    """CONTRACT_298 section 1 (K = 0) and section 4 (V6): steps [1, 1] and countPairs [] are refused when changed."""
    raw = head.reviewed_bytes(head.HUNK_RECORD_PATH)
    record = json.loads(raw)
    mutated = copy.deepcopy(record)
    mutated["hunkClassContext"][key] = value
    changed, afters, classify, context = _v6_inputs(mutated)
    # operator-stated (K = 0): any other steps or countPairs is refused
    with pytest.raises(ValueError):
        head.check_hunk_record(_raw(mutated), changed, afters, classify, context, head.HUNK_RULE_SHA256)


def test_head_entry_and_canonical_hunks(packets):
    """CONTRACT_298 section 4: the entry runs every check in order over the current catalog."""
    # CONTRACT_298 section 4
    assert head.validate_canonical_hunks() is None
    # CONTRACT_298 section 4; MET-016 YAML expectedEvidence
    assert head.validate_met_016(packets) is None


# ---------------------------------------------------------------- part 4: YAML, catalog, table, registry


def test_packet_yaml():
    """CONTRACT_298 sections 1 and 5: MET-016's id, its predecessor MET-015 and its contracts line."""
    doc = head.safe_load(head.reviewed_bytes("task-packets/MET-016.yaml"))
    # CONTRACT_298 section 1; operator-stated
    assert head.NEW_PACKET == "MET-016"
    # CONTRACT_298 section 1
    assert doc["id"] == "MET-016"
    # CONTRACT_298 section 5
    assert doc["predecessors"] == ["MET-015"]
    # operator-stated: 16 keys
    assert len(doc) == 16
    # CONTRACT_298 section 7 (r7): the drop form's branch
    assert doc["branch"] == "codex/met-016-hrfix-decalign"
    line = doc["contracts"][0]
    # CONTRACT_298 section 5: the contracts line names the base merge commit
    assert BASE_MAIN in line
    # CONTRACT_298 section 5: and its tree
    assert BASE_TREE8 in line
    # CONTRACT_298 section 5: holding 322 immutable packets including MET-015
    assert "322 immutable packets including MET-015" in line


def test_historical_catalog_peels_to_the_era_catalog(packets):
    """CONTRACT_298 sections 1 and 4: the current catalog peels to the authority's baselinePackets ids."""
    era = head.historical_catalog(packets)
    # operator-stated: historical_catalog returns the authority's baselinePackets ids
    assert set(era) == set(head.authority()["baselinePackets"])
    # CONTRACT_298 section 1: MET-016 is the new packet, not in the era catalog
    assert "MET-016" not in era


def test_historical_catalog_refuses_one_less(packets):
    """CONTRACT_298 section 4b (N1 from current -1 id): the catalog less one id is refused, with the message."""
    less = dict(packets)
    drop = next(name for name in sorted(less) if name in head.authority()["baselinePackets"])
    del less[drop]
    # operator-stated: the refusal message
    with pytest.raises(ValueError, match="unexpected packet addition or loss"):
        head.historical_catalog(less)


def test_weights_table():
    """CONTRACT_298 section 6: raw keys equal effective keys; regular files; the two rows; 225 entries; no member row."""
    raw = head.reviewed_bytes("ci/parallel_suite_weights.json")
    pairs = json.loads(raw, object_pairs_hook=lambda items: items)
    if not isinstance(pairs, list) or not all(isinstance(item, tuple) for item in pairs):
        pytest.fail("construction: the table is not one flat mapping")
    raw_keys = [key for key, _value in pairs]
    table = json.loads(raw)
    # CONTRACT_298 section 6: raw keys equal the effective keys (no duplicate)
    assert raw_keys == list(table)
    # CONTRACT_298 section 6 (223 -> 225); operator-stated: 225 entries
    assert len(table) == 225
    # CONTRACT_298 section 6: the head test's row
    assert "tests/test_met_016.py" in table
    # CONTRACT_298 section 6: the D5a file's row
    assert "tests/test_met_016_oracle.py" in table
    for name in MEMBER_TESTS:
        # CONTRACT_298 section 6: the member tests take no row
        assert name not in table, name
    for key in raw_keys:
        # CONTRACT_298 section 6: every key names a regular file
        assert isinstance(head.reviewed_bytes(key), bytes), key
