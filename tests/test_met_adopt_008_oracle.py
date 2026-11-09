"""D5a oracle tests for MET-ADOPT-008 (slot 285; AUTHORITY-MAP-001-F, the fix of issue #237).

Owner decision D5a requires a contract packet to carry tests written outside the candidate, by
someone who is not its builder. These are those tests for the down-ledger clause and VB-11. They
are black-box: the author never saw the candidate's code or any test, and every expected value
comes from one of three sources, named in each test's docstring:

- "contract": CONTRACT_285 rev 2 with erratum 1, chiefly section 2 (the defect, #237's four
  cases, Q-285-2 (a) and the seven ops), section 3 (F1-F7 and VB-11's table) and section 3a;
  and erratum 3's restatement of section 2's sentence on advisory, quoted from the lane
  monitor's ruling MON-285-E3 (the author's CN copy holds the earlier text);
- "meta YAML": the packet's meta YAML as exported to the author (strings that name closed paths
  were masked there, and no such string is tested here);
- "operator-stated": facts the operator stated in the oracle brief, read from the base 98d1f6f1
  and the candidate: the model imports only the standard library; require()'s refusal form (a
  ValueError whose text is "AM_BUDGET: " plus the message for the budget checks); _canonical()'s
  JSON form; _Ledger(root)'s state attributes (committed, up, res, transitions) and step()'s
  answers; each op's members in STEP_MEMBERS; _ledger_state() and _budget(raw); the vectors
  file's members and serialization; the map's vectorFiles rows; and, with MON-285-E3, that the
  base's advisory branch (327-329) reads self.up and the candidate's advisory lines are
  byte-equal to the base's.

The only repository module used is scripts/authority_map.py, loaded by file path into a fresh
module object. The data files are read by literal path. Nothing is patched, shimmed or swapped:
every case is built from plain data, a fresh _Ledger or vector bytes written under tmp_path.
"""

import copy
import hashlib
import importlib.util
import json
import re
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
MODEL_PATH = ROOT / "scripts" / "authority_map.py"
VECTORS_REL = "architecture/authority-map/budget-vectors.json"
MAP_REL = "architecture/authority-map.json"
YAML_REL = "task-packets/MET-ADOPT-008.yaml"

# Operator-stated: STEP_MEMBERS (base lines 371-374), each op's step members in order.
# Contract section 2: seven ops, none of them ledger_up.
STEP_MEMBERS_STATED = {
    "reserve": ("op", "key", "amount"),
    "consume": ("op", "key", "amount"),
    "commit": ("op", "key", "transition", "amount"),
    "cancel": ("op", "key"),
    "expire": ("op", "key"),
    "ledger_down": ("op",),
    "advisory": ("op", "profileAllows", "outboxCapacity"),
}
# Contract F1: the five mutations a down ledger refuses.
MUTATING_OPS = ("reserve", "consume", "commit", "cancel", "expire")
# Operator-stated: the answers step() returns.
STEP_ANSWERS = frozenset(
    ("reserved", "committed", "replayed", "consumed", "settled", "down", "proceeds", "refused")
)
# Operator-stated: the vectors file's top members, a vector's members, a final entry's members.
TOP_MEMBERS = frozenset(("schemaVersion", "rules", "vectors", "nonClaims"))
VECTOR_MEMBERS = frozenset(("id", "name", "root", "steps", "results", "final"))
FINAL_MEMBERS = ("state", "committed", "returned")
# Contract F2 (message "vectors are VB-01 to VB-11") in require()'s operator-stated form.
IDS_REFUSAL = "AM_BUDGET: vectors are VB-01 to VB-11"
# Contract F5: the base digest of the vectors file starts e0eb278c; F4's append moves it.
BASE_VECTORS_DIGEST_PREFIX = "e0eb278c"
# Meta YAML: the prefix every acceptance argv carries.
UV_PREFIX = ["uv", "run", "--offline", "--frozen", "--no-sync", "python"]


def _reserve(key, amount):
    return {"op": "reserve", "key": key, "amount": amount}


def _consume(key, amount):
    return {"op": "consume", "key": key, "amount": amount}


def _commit(key, transition, amount):
    return {"op": "commit", "key": key, "transition": transition, "amount": amount}


def _cancel(key):
    return {"op": "cancel", "key": key}


def _expire(key):
    return {"op": "expire", "key": key}


LEDGER_DOWN = {"op": "ledger_down"}

# Contract section 3, F4: VB-11 "ledger loss with an open reservation", root 1000.
VB11_ID = "VB-11"
VB11_NAME = "ledger loss with an open reservation"
VB11_ROOT = 1000
VB11_STEPS = [
    _reserve("k1", 100),
    _commit("k1", "t1", 40),
    _reserve("k2", 100),
    _consume("k2", 20),
    dict(LEDGER_DOWN),
    _reserve("k3", 10),
    _consume("k2", 10),
    _commit("k2", "t2", 40),
    _cancel("k2"),
    _expire("k2"),
    _commit("k1", "t1", 40),
]
VB11_RESULTS = [
    "reserved",
    "committed",
    "reserved",
    "consumed",
    "down",
    "refused",
    "refused",
    "refused",
    "refused",
    "refused",
    "refused",
]
VB11_FINAL = {
    "k1": {"state": "COMMITTED", "committed": 40, "returned": 60},
    "k2": {"state": "RESERVED", "committed": 0, "returned": 0},
}
# Contract F4: "At the base the model replays VB-11 as ..." (the defect).
BASE_VB11_RESULTS = [
    "reserved",
    "committed",
    "reserved",
    "consumed",
    "down",
    "refused",
    "consumed",
    "committed",
    "refused",
    "refused",
    "replayed",
]


def _load_model():
    """Load scripts/authority_map.py by file path into a fresh module object (operator-stated:
    it imports only the standard library and runs nothing at import beyond definitions)."""
    spec = importlib.util.spec_from_file_location("met_adopt_008_oracle_authority_map", MODEL_PATH)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.fixture
def model():
    return _load_model()


def _vectors_raw():
    return (ROOT / VECTORS_REL).read_bytes()


def _vectors_doc():
    return json.loads(_vectors_raw().decode("utf-8"))


def _dump_vectors(doc):
    """Contract F4 and operator-stated: json.dumps(doc, indent=1, ensure_ascii=False) plus a newline."""
    return (json.dumps(doc, indent=1, ensure_ascii=False) + "\n").encode("utf-8")


def _write_copy(tmp_path, doc):
    path = tmp_path / "budget-vectors.json"
    path.write_bytes(_dump_vectors(doc))
    return path.read_bytes()


def _canonical_bytes(value):
    """Operator-stated: _canonical(value)'s form."""
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def _state(ledger):
    """Contract F2 (MA008-C1-1): the ledger's state form, computed here independently of the model."""
    return _canonical_bytes(
        [ledger.committed, ledger.res, sorted([list(k), v] for k, v in ledger.transitions.items())]
    )


def _snapshot(ledger):
    """Deep copies of the operator-stated state attributes committed, res, transitions and up."""
    return (
        copy.deepcopy(ledger.committed),
        copy.deepcopy(ledger.res),
        copy.deepcopy(dict(ledger.transitions)),
        ledger.up,
    )


def _final(ledger):
    """Operator-stated: final maps each reservation key to {state, committed, returned}."""
    return {key: {m: entry[m] for m in FINAL_MEMBERS} for key, entry in ledger.res.items()}


def _run(model, root, steps):
    ledger = model._Ledger(root)
    answers = [ledger.step(dict(s)) for s in steps]
    return ledger, answers


def _vector(doc, vector_id):
    found = [v for v in doc["vectors"] if v["id"] == vector_id]
    assert len(found) == 1, vector_id
    return found[0]


def _yaml_value(text, key):
    """The meta YAML's top-level `key: value` line, its value read as JSON (the meta YAML's flow form)."""
    found = re.findall(r"^%s: (.*)$" % re.escape(key), text, flags=re.MULTILINE)
    assert len(found) == 1, key
    return json.loads(found[0])


def _yaml_text():
    return (ROOT / YAML_REL).read_text(encoding="utf-8")


# 1. The down-ledger clause (contract F1, section 2 and Q-285-2 (a)).

DOWN_MUTATIONS = {
    "reserve-new-key": _reserve("k3", 10),
    "reserve-open-key": _reserve("k2", 10),
    "consume": _consume("k2", 10),
    "commit": _commit("k2", "t2", 40),
    "cancel": _cancel("k2"),
    "expire": _expire("k2"),
}


@pytest.mark.parametrize("case", sorted(DOWN_MUTATIONS))
def test_down_ledger_refuses_each_mutation_without_state_change(model, case):
    """Contract F1: "a down ledger refuses every mutation" (reserve, consume, commit, cancel and
    expire answer "refused"); contract section 2, Q-285-2 (a): "with no state change". The set-up
    is VB-11's steps 1-5 (contract section 3's table), so the ledger is down with k1 committed and
    k2 open; each mutation runs alone on a fresh ledger. State: the operator-stated attributes
    committed, res, transitions and up, and contract F2's state form."""
    ledger, answers = _run(model, VB11_ROOT, VB11_STEPS[:5])
    assert answers == VB11_RESULTS[:5]
    assert ledger.up is False
    before, before_state = _snapshot(ledger), _state(ledger)
    assert ledger.step(dict(DOWN_MUTATIONS[case])) == "refused"
    assert _snapshot(ledger) == before
    assert _state(ledger) == before_state


@pytest.mark.parametrize("op", MUTATING_OPS)
def test_down_ledger_refuses_before_the_key_is_read(model, op):
    """Contract F1: the guard sits "before `key = s["key"]` (330)", and "Nothing is read or written
    before the guard returns"; meta YAML contracts: the five ops "are refused before the key is
    read". So a down ledger answers "refused" to a mutation step that carries only its op, with no
    KeyError and no state change."""
    ledger, answers = _run(model, VB11_ROOT, VB11_STEPS[:5])
    assert answers == VB11_RESULTS[:5]
    before, before_state = _snapshot(ledger), _state(ledger)
    assert ledger.step({"op": op}) == "refused"
    assert _snapshot(ledger) == before
    assert _state(ledger) == before_state


# Contract section 2: #237's four cases, after reserve k 100, consume k 20 and ledger_down.
ISSUE_237_PREFIX = [_reserve("k", 100), _consume("k", 20), dict(LEDGER_DOWN)]
ISSUE_237_CASES = {
    "commit-k-40-base-committed": _commit("k", "t", 40),
    "consume-k-10-base-consumed": _consume("k", 10),
    "cancel-k-base-settled": _cancel("k"),
    "expire-k-base-settled": _expire("k"),
}


@pytest.mark.parametrize("case", sorted(ISSUE_237_CASES))
def test_issue_237_cases_are_refused(model, case):
    """Contract section 2: #237's four cases (reserve k 100, consume k 20, ledger_down, then commit
    k 40, consume k 10, cancel or expire) give "committed", "consumed", "settled" and "settled" at
    the base; "each must be "refused"". Q-285-2 (a): with no state change. The prefix answers and
    k's final entry (RESERVED, committed 0, returned 0) follow VB-11's table, whose k2 has the same
    history (contract section 3: steps 3-5 and the final)."""
    ledger, answers = _run(model, VB11_ROOT, ISSUE_237_PREFIX)
    assert answers == ["reserved", "consumed", "down"]
    before, before_state = _snapshot(ledger), _state(ledger)
    assert ledger.step(dict(ISSUE_237_CASES[case])) == "refused"
    assert _snapshot(ledger) == before
    assert _state(ledger) == before_state
    assert _final(ledger) == {"k": {"state": "RESERVED", "committed": 0, "returned": 0}}


def test_exact_commit_replay_while_down_is_refused(model):
    """Contract section 2, Q-285-2 (a): "an exact commit replay while the ledger is down is refused
    like every mutation, with no state change", and "Idempotency survives because the transition
    key persists": the (key, transition) entry (operator-stated: transitions is keyed by
    (key, transition) tuples) is still there after the refusal. k1's final entry follows VB-11's
    final (contract section 3)."""
    ledger, answers = _run(model, VB11_ROOT, [_reserve("k1", 100), _commit("k1", "t1", 40), LEDGER_DOWN])
    assert answers == ["reserved", "committed", "down"]
    assert ("k1", "t1") in ledger.transitions
    before, before_state = _snapshot(ledger), _state(ledger)
    assert ledger.step(_commit("k1", "t1", 40)) == "refused"
    assert _snapshot(ledger) == before
    assert _state(ledger) == before_state
    assert ("k1", "t1") in ledger.transitions
    assert _final(ledger) == {"k1": {"state": "COMMITTED", "committed": 40, "returned": 60}}


def test_exact_commit_replay_while_up_answers_replayed(model):
    """Contract section 2: "B3 governs duplicates under availability", and a re-issue with the
    ledger up answers "replayed" (`authority_map.py` 343-345); F1 changes only the down ledger.
    B3's idempotency is FIN:176 ("Duplicate commit/release is idempotent"), so the replay leaves
    the state unchanged."""
    ledger, answers = _run(model, VB11_ROOT, [_reserve("k1", 100), _commit("k1", "t1", 40)])
    assert answers == ["reserved", "committed"]
    before, before_state = _snapshot(ledger), _state(ledger)
    assert ledger.step(_commit("k1", "t1", 40)) == "replayed"
    assert _snapshot(ledger) == before
    assert _state(ledger) == before_state
    assert ledger.up is True


def _advisory_expected(s, up):
    """Contract section 2 as erratum 3 restates it (MON-285-E3): advisory proceeds while the ledger
    is up, and while down only if the profile allows and outbox capacity exists, which the ruling
    states as profileAllows is True and outboxCapacity is True; it is refused otherwise."""
    if up:
        return "proceeds"
    if s["profileAllows"] is True and s["outboxCapacity"] is True:
        return "proceeds"
    return "refused"


def _advisory_inputs():
    """The four bool combinations of the operator-stated advisory members (bools, as in the live
    vectors), plus every distinct advisory step in the live vectors, told apart by their JSON text
    so that 1 and True stay distinct."""
    found = [
        {"op": "advisory", "profileAllows": allows, "outboxCapacity": capacity}
        for allows in (True, False)
        for capacity in (True, False)
    ]
    seen = {json.dumps(s, sort_keys=True) for s in found}
    for vector in _vectors_doc()["vectors"]:
        for s in vector["steps"]:
            text = json.dumps(s, sort_keys=True)
            if s["op"] == "advisory" and text not in seen:
                seen.add(text)
                found.append(dict(s))
    return found


def test_advisory_keeps_its_own_rule_up_and_down(model):
    """Contract section 2 as erratum 3 restates it (MON-285-E3): "`advisory` reads it by its own rule
    (327-329): it proceeds while the ledger is up, and while down only if the profile allows and
    outbox capacity exists (FIN:177; erratum 3)"; F1: the guard sits after the advisory branch, and
    "`ledger_down` and `advisory` are unchanged". Up: "proceeds" for every input. Down: "proceeds"
    only when profileAllows is True and outboxCapacity is True, "refused" otherwise. Inputs: the four
    bool combinations and every advisory step in the live vectors, each on fresh ledgers holding the
    same open reservation (the up and the down ledger differ only by ledger_down); the down ledger
    stays down."""
    inputs = _advisory_inputs()
    assert len(inputs) >= 4
    for s in inputs:
        up_ledger, up_answers = _run(model, VB11_ROOT, [_reserve("k2", 100)])
        down_ledger, down_answers = _run(model, VB11_ROOT, [_reserve("k2", 100), LEDGER_DOWN])
        assert up_answers == ["reserved"]
        assert down_answers == ["reserved", "down"]
        assert _advisory_expected(s, True) == "proceeds"
        assert up_ledger.step(dict(s)) == "proceeds", s
        assert down_ledger.step(dict(s)) == _advisory_expected(s, False), s
        assert down_ledger.up is False


def test_advisory_steps_in_vb01_to_vb10_answer_their_recorded_results(model):
    """Contract F4: VB-01 to VB-10 "stay byte-equal" (the base's own vectors), and section 5, P-237:
    "VB-01 to VB-10 replay unchanged"; section 2 as erratum 3 restates it (MON-285-E3) and F1:
    advisory keeps its own rule, unchanged. So every advisory step in VB-01 to VB-10, replayed in
    its own vector on a fresh _Ledger(root), answers its recorded result, and that result is erratum
    3's rule for the ledger's up state before the step (named up or down in the message)."""
    base_ids = ["VB-%02d" % n for n in range(1, 11)]
    checked = 0
    for vector in _vectors_doc()["vectors"]:
        if vector["id"] not in base_ids:
            continue
        ledger = model._Ledger(vector["root"])
        for number, (s, recorded) in enumerate(zip(vector["steps"], vector["results"]), start=1):
            up_before = ledger.up
            answer = ledger.step(dict(s))
            if s["op"] == "advisory":
                checked += 1
                where = (vector["id"], number, "up" if up_before else "down")
                assert answer == recorded, where
                assert recorded == _advisory_expected(s, up_before), where
    assert checked >= 1


# 2. No recovery op (contract section 2 and F1, MA008-C1-6).


def test_step_members_are_seven_ops_without_ledger_up(model):
    """Contract section 2: "No `ledger_up` op exists at the base (`STEP_MEMBERS`, 371-374, has seven
    ops: reserve, consume, commit, cancel, expire, ledger_down and advisory)", and "this contract
    adds no op"; operator-stated: each op's members in STEP_MEMBERS."""
    members = model.STEP_MEMBERS
    assert sorted(members) == sorted(STEP_MEMBERS_STATED)
    assert "ledger_up" not in members
    for op, stated in STEP_MEMBERS_STATED.items():
        assert tuple(members[op]) == stated, op


def test_ledger_up_is_an_unknown_op_on_direct_calls(model):
    """Contract F1 (MA008-C1-6): "An unknown op behaves as at the base": "a direct call with no key
    raises `KeyError` (330), with a key and no open reservation answers "refused" (346), and with an
    open reservation raises `AM_BUDGET` (364), up or down alike". ledger_up is such an op (section
    2: no ledger_up op exists), so it brings no ledger back up. AM_BUDGET's form is operator-stated
    (a ValueError whose text starts "AM_BUDGET: ")."""
    for down in (False, True):
        steps = [_reserve("k2", 100)] + ([dict(LEDGER_DOWN)] if down else [])
        ledger, answers = _run(model, VB11_ROOT, steps)
        assert answers == (["reserved", "down"] if down else ["reserved"])
        with pytest.raises(KeyError):
            ledger.step({"op": "ledger_up"})
        assert ledger.step({"op": "ledger_up", "key": "k-none"}) == "refused"
        with pytest.raises(ValueError) as caught:
            ledger.step({"op": "ledger_up", "key": "k2"})
        assert str(caught.value).startswith("AM_BUDGET: ")
        assert ledger.up is (not down)


def test_budget_refuses_a_ledger_up_step(model, tmp_path):
    """Contract F1 (MA008-C1-6): `_budget` refuses an unknown op "at 397 before `step` is called",
    in require()'s operator-stated AM_BUDGET form (a ValueError, not step()'s KeyError). The copy
    replaces VB-11's step 6 (reserve k3 10, answered "refused") by {"op": "ledger_up"} and keeps the
    results, so only the op differs from the live file, which `_budget` accepts."""
    doc = _vectors_doc()
    assert model._budget(_dump_vectors(doc)) is None
    vb11 = doc["vectors"][-1]
    assert vb11["id"] == VB11_ID
    assert vb11["steps"][5] == _reserve("k3", 10)
    vb11["steps"][5] = {"op": "ledger_up"}
    with pytest.raises(ValueError) as caught:
        model._budget(_write_copy(tmp_path, doc))
    assert str(caught.value).startswith("AM_BUDGET: ")


# 3. VB-11 (contract F4 and section 3's table).


def test_vectors_file_holds_vb01_to_vb11_in_order():
    """Contract F2: the vectors are VB-01 to VB-11 (`range(1, 12)`); F4: VB-11 is "appended after
    VB-10"."""
    ids = [v["id"] for v in _vectors_doc()["vectors"]]
    assert ids == ["VB-%02d" % n for n in range(1, 12)]


def test_vb11_equals_the_contract_table():
    """Contract section 3, F4: VB-11 "ledger loss with an open reservation", root 1000, its eleven
    steps and results as the table states them, "the step members in `STEP_MEMBERS` order" (the
    operator-stated order), and "Final: k1 COMMITTED (committed 40, returned 60); k2 RESERVED
    (committed 0, returned 0)". Operator-stated: a vector's members are exactly id, name, root,
    steps, results and final."""
    vb11 = _vectors_doc()["vectors"][-1]
    assert set(vb11) == VECTOR_MEMBERS
    assert vb11["id"] == VB11_ID
    assert vb11["name"] == VB11_NAME
    assert vb11["root"] == VB11_ROOT
    assert vb11["steps"] == VB11_STEPS
    assert [list(s) for s in vb11["steps"]] == [list(STEP_MEMBERS_STATED[s["op"]]) for s in VB11_STEPS]
    assert vb11["results"] == VB11_RESULTS
    assert vb11["final"] == VB11_FINAL


def test_vectors_file_form_and_members():
    """Contract F4 and operator-stated: the file is `json.dumps(doc, indent=1, ensure_ascii=False)`
    plus a newline; its top members are schemaVersion, rules, vectors and nonClaims; each vector's
    members are exactly id, name, root, steps, results and final; each step's members are exactly
    its op's STEP_MEMBERS; final maps each reservation key to {state, committed, returned}."""
    raw = _vectors_raw()
    doc = json.loads(raw.decode("utf-8"))
    assert raw == _dump_vectors(doc)
    assert set(doc) == TOP_MEMBERS
    for vector in doc["vectors"]:
        assert set(vector) == VECTOR_MEMBERS, vector.get("id")
        assert len(vector["results"]) == len(vector["steps"]), vector["id"]
        for s in vector["steps"]:
            assert s["op"] in STEP_MEMBERS_STATED, vector["id"]
            assert set(s) == set(STEP_MEMBERS_STATED[s["op"]]), vector["id"]
        for entry in vector["final"].values():
            assert set(entry) == set(FINAL_MEMBERS), vector["id"]


def test_vb08_downs_the_ledger_before_any_reservation():
    """Contract section 2: "VB-08 ("ledger loss") downs the ledger before any reservation, so the
    vectors never reach the branch": VB-08 has a ledger_down step and no reserve step before its
    first one, so it never holds a reservation (its final is empty)."""
    vb08 = _vector(_vectors_doc(), "VB-08")
    assert vb08["name"] == "ledger loss"
    ops = [s["op"] for s in vb08["steps"]]
    assert "ledger_down" in ops
    assert "reserve" not in ops[: ops.index("ledger_down")]
    assert vb08["final"] == {}


def test_fresh_ledger_replays_vb11_from_the_table(model):
    """Contract section 3, F4: a fresh _Ledger(1000) replays the table's steps to its results and
    final; "The state after step 5 and after step 11 is byte-equal (F2's invariant, step by step)",
    in F2's state form, so steps 6-11 change nothing: no transition (k2, t2), no reservation k3, and
    the transition (k1, t1) persists (section 2)."""
    ledger = model._Ledger(VB11_ROOT)
    answers, states = [], [_state(ledger)]
    for s in VB11_STEPS:
        answers.append(ledger.step(dict(s)))
        states.append(_state(ledger))
    assert answers == VB11_RESULTS
    assert _final(ledger) == VB11_FINAL
    for number in range(6, 12):
        assert states[number] == states[5], number
    assert ledger.up is False
    assert ("k1", "t1") in ledger.transitions
    assert ("k2", "t2") not in ledger.transitions
    assert "k3" not in ledger.res


def test_fresh_ledger_replays_every_live_vector(model):
    """Contract section 5, P-237: "VB-01 to VB-10 replay unchanged", and section 6, A5: "the model
    replays every vector"; F2: the invariant "holds for VB-01 to VB-10 at the base and for VB-01 to
    VB-11 under F1": every step answering "refused" leaves F2's state form byte-equal. Each vector
    runs on a fresh _Ledger(root) (operator-stated)."""
    for vector in _vectors_doc()["vectors"]:
        ledger = model._Ledger(vector["root"])
        answers = []
        for s in vector["steps"]:
            before = _state(ledger)
            answer = ledger.step(dict(s))
            answers.append(answer)
            if answer == "refused":
                assert _state(ledger) == before, (vector["id"], len(answers))
        assert answers == vector["results"], vector["id"]
        assert _final(ledger) == vector["final"], vector["id"]


# 4. The model's replay (contract F2).


def test_budget_accepts_the_live_vectors_file(model):
    """Operator-stated: `_budget(raw)` takes the vectors file's bytes and returns None when every
    vector replays; contract F2 and F4: the live file holds VB-01 to VB-11 and each replays."""
    assert model._budget(_vectors_raw()) is None


PRE_FIX_VARIANTS = {
    "step7-consumed": {7: "consumed"},
    "step8-committed": {8: "committed"},
    "step11-replayed": {11: "replayed"},
    "base-replay": {number: answer for number, answer in enumerate(BASE_VB11_RESULTS, start=1)},
}


@pytest.mark.parametrize("variant", sorted(PRE_FIX_VARIANTS))
def test_budget_refuses_pre_fix_vb11_results(model, tmp_path, variant):
    """Contract F4: at the base the model replays VB-11 as "reserved, committed, reserved, consumed,
    down, refused, consumed, committed, refused, refused, replayed: the defect". A copy of the live
    file whose VB-11 states a pre-fix result is refused in the operator-stated AM_BUDGET form; the
    same document unchanged is accepted (control)."""
    doc = _vectors_doc()
    assert model._budget(_dump_vectors(doc)) is None
    vb11 = doc["vectors"][-1]
    assert vb11["id"] == VB11_ID
    for number, answer in PRE_FIX_VARIANTS[variant].items():
        vb11["results"][number - 1] = answer
    assert vb11["results"] != VB11_RESULTS
    with pytest.raises(ValueError) as caught:
        model._budget(_write_copy(tmp_path, doc))
    assert str(caught.value).startswith("AM_BUDGET: ")


def test_budget_refuses_vectors_without_vb11(model, tmp_path):
    """Contract F2: `_budget` reads VB-01 to VB-11 (`range(1, 12)`, message "vectors are VB-01 to
    VB-11"); require()'s form is operator-stated. A copy without VB-11 is refused with it."""
    doc = _vectors_doc()
    assert doc["vectors"][-1]["id"] == VB11_ID
    doc["vectors"] = doc["vectors"][:-1]
    with pytest.raises(ValueError) as caught:
        model._budget(_write_copy(tmp_path, doc))
    assert str(caught.value) == IDS_REFUSAL


def test_budget_refuses_a_twelfth_vector(model, tmp_path):
    """Contract F2: `_budget` reads VB-01 to VB-11 (`range(1, 12)`, message "vectors are VB-01 to
    VB-11"); require()'s form is operator-stated. A copy with a twelfth vector (VB-11's content
    under the id VB-12 and its own name) is refused with it."""
    doc = _vectors_doc()
    twelfth = copy.deepcopy(doc["vectors"][-1])
    assert twelfth["id"] == VB11_ID
    twelfth["id"] = "VB-12"
    twelfth["name"] = "oracle copy of VB-11 as a twelfth vector"
    doc["vectors"].append(twelfth)
    with pytest.raises(ValueError) as caught:
        model._budget(_write_copy(tmp_path, doc))
    assert str(caught.value) == IDS_REFUSAL


def test_ledger_state_gives_the_contract_form(model):
    """Contract F2 (MA008-C1-1): the state is exactly `_canonical([ledger.committed, ledger.res,
    sorted([list(k), v] for k, v in ledger.transitions.items())])`, and `_canonical` (182) "refuses
    the raw `transitions`, whose keys are tuples". Operator-stated: `_ledger_state(ledger)` returns
    that form, and `_canonical`'s JSON form. Checked on a fresh ledger and after each VB-11 step."""
    ledger = model._Ledger(VB11_ROOT)
    assert model._ledger_state(ledger) == _state(ledger)
    for s in VB11_STEPS:
        ledger.step(dict(s))
        got = model._ledger_state(ledger)
        assert isinstance(got, bytes)
        assert got == _state(ledger)
    assert len(ledger.transitions) >= 1
    with pytest.raises(TypeError):
        model._canonical(ledger.transitions)
    sample = {"b": [1, "é"], "a": {"z": True, "y": None}}
    assert model._canonical(sample) == _canonical_bytes(sample)


# 5. The map (contract F5).


def test_map_vectors_digest_equals_the_file_sha256():
    """Contract F5: `vectorFiles`' budget-vectors digest `e0eb278c...` becomes "the sha256 of F4's
    file", which `check` compares live; operator-stated: the map lists `vectorFiles` rows
    {"path", "sha256"}, one of them for the vectors file."""
    authority_map = json.loads((ROOT / MAP_REL).read_text(encoding="utf-8"))
    rows = [row for row in authority_map["vectorFiles"] if row["path"] == VECTORS_REL]
    assert len(rows) == 1
    assert set(rows[0]) == {"path", "sha256"}
    digest = hashlib.sha256(_vectors_raw()).hexdigest()
    assert rows[0]["sha256"] == digest
    assert not digest.startswith(BASE_VECTORS_DIGEST_PREFIX)


# 6. The meta YAML (contract sections 1 and 7; the meta YAML in CN).


def test_meta_yaml_identity():
    """Contract section 1: "The new meta is `MET-ADOPT-008` (repository Harness-Engineering ...)";
    section 7: "`predecessors: [MET-REGISTRY-001]`"; meta YAML: id, repository, branch
    codex/met-adopt-008 and predecessors."""
    text = _yaml_text()
    assert _yaml_value(text, "id") == "MET-ADOPT-008"
    assert _yaml_value(text, "repository") == "Harness-Engineering"
    assert _yaml_value(text, "branch") == "codex/met-adopt-008"
    assert _yaml_value(text, "predecessors") == ["MET-REGISTRY-001"]


def test_meta_yaml_command_count():
    """Contract section 1: "The 64 acceptance argv are inherited unchanged from MET-REGISTRY-001. No
    new argv"; section 7: "the 64 argv inherited". Meta YAML: 64 offlineAcceptanceCommands, each an
    argv of strings with the uv prefix, among them the readiness validator and the pytest run."""
    commands = _yaml_value(_yaml_text(), "offlineAcceptanceCommands")
    assert len(commands) == 64
    for argv in commands:
        assert isinstance(argv, list) and all(isinstance(a, str) for a in argv)
        assert argv[: len(UV_PREFIX)] == UV_PREFIX
    assert UV_PREFIX + ["scripts/validate_readiness.py"] in commands
    assert UV_PREFIX + ["-m", "pytest", "tests", "ci/test_offline_runner.py", "ci/test_warm_snapshot.py"] in commands


def test_meta_yaml_objective_and_allowed_paths():
    """Contract section 1 (S = 285, K = 0, C = 296, AUTHORITY-MAP-001-F) and section 7 ("296
    packets at slot 285"; allowedPaths equal to the change set, which holds F1-F7's five files, the
    head layer and test, the authority, the hunk-class record and the packet YAML: sections 3, 6
    and 7); section 9: no ledger_up op. Meta YAML: the objective's phrases, those allowedPaths and
    the excluded "a ledger_up op"."""
    text = _yaml_text()
    objective = _yaml_value(text, "objective")
    for phrase in ("the 285th chain packet", "AUTHORITY-MAP-001-F", "296 packets at slot 285", "VB-11"):
        assert phrase in objective, phrase
    allowed = _yaml_value(text, "allowedPaths")
    for path in (
        "scripts/authority_map.py",
        VECTORS_REL,
        MAP_REL,
        "architecture/authority-map/README.md",
        "tests/test_authority_map.py",
        "scripts/validate_met_adopt_008.py",
        "tests/test_met_adopt_008.py",
        "architecture/authority-map-f-authority.json",
        "architecture/chain-checkpoint/hunk-classes/285.json",
        YAML_REL,
    ):
        assert path in allowed, path
    excluded = _yaml_value(text, "excluded")
    assert any("a ledger_up op" in item for item in excluded)
