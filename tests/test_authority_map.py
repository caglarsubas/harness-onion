"""MET-ADOPT-007 (AUTHORITY-MAP-001): the authority map's record, vectors and module. Each refusal the design names
(rev 6, section 5) has a test that makes it fail; the record, the vectors and every source are read by exact path."""
import json
from pathlib import Path

import pytest

from scripts import authority_map as am

ROOT = Path(__file__).resolve().parents[1]
PATHS = (am.RECORD_PATH, am.BUDGET_PATH, am.R12_PATH, am.TECH_PATH, am.BRIEFS_PATH) + tuple(sorted(am.SOURCES))


def dump(value) -> bytes:
    return (json.dumps(value, indent=1, ensure_ascii=False) + "\n").encode("utf-8")


def files():
    return {p: (ROOT / p).read_bytes() for p in PATHS}


def run(*mutations):
    data = files()
    for mutate in mutations:
        mutate(data)
    return am.check(lambda p: data[p], frozenset())


def refuses(code, *mutations):
    with pytest.raises(ValueError) as error:
        run(*mutations)
    assert str(error.value).startswith(code + ":"), str(error.value)


def record(fn):
    def mutate(data):
        rec = json.loads(data[am.RECORD_PATH])
        fn(rec)
        data[am.RECORD_PATH] = dump(rec)
    return mutate


def vectors(path, fn):
    """Edit a vector file and re-pin it in the record, so V1 passes and the file's own check runs."""
    def mutate(data):
        doc = json.loads(data[path])
        fn(doc)
        data[path] = dump(doc)
        rec = json.loads(data[am.RECORD_PATH])
        for row in rec["vectorFiles"]:
            if row["path"] == path:
                row["sha256"] = am.digest(data[path])
        data[am.RECORD_PATH] = dump(rec)
    return mutate


def tech(fn):
    def mutate(data):
        doc = json.loads(data[am.TECH_PATH])
        fn(doc)
        data[am.TECH_PATH] = dump(doc)
    return mutate


def concern(rec, cid):
    return next(c for c in rec["concerns"] if c["id"] == cid)


def line_quote(path, n):
    return (ROOT / path).read_text(encoding="utf-8").splitlines()[n - 1].strip()[:60]


def test_the_record_passes():
    result = run()
    assert result["concerns"] == 9 and result["pins"] == 27 and result["budgetVectors"] == 10
    assert result["flagged"] == ["AM-06 whenUnavailable", "AM-09 whenRevoked"]


def test_the_authority_names_come_from_the_pins():
    assert am.authority_names("AM-04") == {"policy-decision", "planeon.policy-decision"}
    assert am.authority_names("AM-06") == {"TARGET_SYSTEM"}
    assert all(am.AUTHORITY_PINS[c][1] in am.authority_names(c) for c in am.CONCERN_IDS)


def test_the_pins_fall_in_three_classes():
    pins = [p[2] for p in am.AUTHORITY_PINS.values()] + [p[1] for p in am.BEHAVIOUR_PINS.values()]
    items = [p for p in pins if p[0] == "item"]
    assert len(pins) == 27 and len(items) == 2 and len(am.FLAGGED) == 2
    assert all(am.BEHAVIOUR_PINS[k][1][0] != "item" for k in am.FLAGGED)


# V0: shape.
def test_shape_refuses_an_extra_member():
    refuses("AM_SHAPE", record(lambda r: concern(r, "AM-01").update(extra="x")))


def test_shape_refuses_an_unknown_action():
    refuses("AM_SHAPE", record(lambda r: concern(r, "AM-04")["othersMay"][0].update(action="DECIDE")))


def test_shape_refuses_an_input_that_decides():
    refuses("AM_SHAPE", record(lambda r: concern(r, "AM-04")["inputs"][0].update(role="DECIDE")))


def test_shape_refuses_an_unknown_behaviour():
    refuses("AM_SHAPE", record(lambda r: concern(r, "AM-02")["whenUnavailable"].update(
        behaviour="ADVISORY_ONLY_IF_PROFILE_ALLOWS")))


def test_shape_refuses_two_behaviours_in_one_member():
    refuses("AM_SHAPE", record(lambda r: concern(r, "AM-02")["whenUnavailable"].update(
        behaviour=["FAIL_CLOSED", "BLOCK_NEW_OPERATIONS"])))


def test_shape_refuses_a_boolean_line():
    refuses("AM_SHAPE", record(lambda r: concern(r, "AM-01")["citations"][0].update(line=True)))


def test_shape_refuses_a_missing_behaviour():
    refuses("AM_SHAPE", record(lambda r: concern(r, "AM-01").pop("whenRevoked")))


def test_shape_refuses_a_roadmap_pin_that_is_not_lowercase_hex():
    refuses("AM_SHAPE", record(lambda r: r["roadmapPin"].update(sha256="Z" * 64)))


def test_reading_refuses_duplicate_members_and_non_utf8():
    refuses("AM_SHAPE", lambda d: d.update({am.RECORD_PATH: b'{"a": 1, "a": 2}'}))
    refuses("AM_SHAPE", lambda d: d.update({am.RECORD_PATH: b"\xff"}))


# V1: sources and vector files.
def test_sources_refuse_a_changed_byte_in_adr_0011():
    path = "docs/adr/0011-h10-execution-authority.md"
    refuses("AM_SOURCES", lambda d: d.update({path: d[path] + b" "}))


def test_sources_refuse_a_dropped_source():
    refuses("AM_SOURCES", record(lambda r: r["sources"].pop(0)))


def test_sources_refuse_a_changed_budget_vector_byte():
    refuses("AM_SOURCES", lambda d: d.update({am.BUDGET_PATH: d[am.BUDGET_PATH] + b" "}))


# V2: citations.
def test_citations_refuse_a_wrong_line():
    refuses("AM_CITATIONS", record(lambda r: concern(r, "AM-07")["citations"][0].update(
        line=concern(r, "AM-07")["citations"][0]["line"] + 1)))


def test_citations_refuse_a_paraphrased_quote():
    refuses("AM_CITATIONS", record(lambda r: concern(r, "AM-07")["citations"][0].update(quote="memory is governed")))


def test_citations_refuse_an_unpinned_item():
    refuses("AM_CITATIONS", record(lambda r: concern(r, "AM-01")["citations"].append(
        {"item": "SERVICE-EDGES-001", "quote": "edges"})))


def test_citations_refuse_a_roadmap_item_no_citation_names():
    refuses("AM_CITATIONS", record(lambda r: r["roadmapPin"]["items"].append("SERVICE-EDGES-001")))


def test_citations_refuse_a_pinned_constant_whose_quote_is_not_on_its_line(monkeypatch):
    monkeypatch.setitem(am.BEHAVIOUR_PINS, ("AM-07", "whenRevoked"),
                        ("STOP_RECALL", (am.MEM, 143, "Deletion removes everything at once")))
    refuses("AM_CITATIONS")


# V3: one authority per concern, equal to its pin.
def test_one_authority_refuses_two_authorities_for_one_concern():
    def twice(r):
        extra = json.loads(json.dumps(concern(r, "AM-03")))
        extra["authority"]["component"] = "ai-gateway"
        r["concerns"].insert(3, extra)
    refuses("AM_ONE_AUTHORITY", record(twice))


def test_one_authority_refuses_a_dropped_concern():
    refuses("AM_ONE_AUTHORITY", record(lambda r: r["concerns"].pop(8)))


def test_one_authority_refuses_a_component_row_naming_the_authority():
    refuses("AM_ONE_AUTHORITY", record(lambda r: concern(r, "AM-04")["othersMay"].append(
        {"who": "policy-decision", "whoKind": "COMPONENT", "action": "ADVISE", "note": "names the authority"})))


def test_one_authority_refuses_a_component_row_naming_the_pinned_module():
    refuses("AM_ONE_AUTHORITY", record(lambda r: concern(r, "AM-04")["othersMay"].append(
        {"who": "planeon.policy-decision", "whoKind": "COMPONENT", "action": "ADVISE", "note": "the pinned name"})))


def test_one_authority_refuses_an_input_repeating_the_authority():
    refuses("AM_ONE_AUTHORITY", record(lambda r: concern(r, "AM-04")["inputs"].append(
        {"harness": "trust.security-safety", "component": "policy-decision", "role": "EVIDENCE"})))


def test_one_authority_refuses_an_input_naming_the_authority_under_another_label():
    refuses("AM_ONE_AUTHORITY", record(lambda r: concern(r, "AM-04")["inputs"][0].update(component="policy-decision")))


def test_one_authority_refuses_the_sentinel_on_a_second_row():
    refuses("AM_ONE_AUTHORITY", record(lambda r: concern(r, "AM-07")["authority"].update(
        harness="EXTERNAL", component="TARGET_SYSTEM")))


def test_one_authority_refuses_round_1_counterexample_1_the_swapped_authority():
    def swap(r):
        c = concern(r, "AM-03")
        c["authority"].update(harness="runtime.ai-gateway", component="ai-gateway",
                              citation={"path": am.GW, "line": 52, "quote": "resolves signed logical routes"})
        c["othersMay"] = [{"who": "inference-api", "whoKind": "COMPONENT", "action": "REQUEST", "note": "moved"}]
    refuses("AM_ONE_AUTHORITY", record(swap))


# V4: enforcement points.
def test_enforcement_refuses_a_concern_with_none():
    refuses("AM_ENFORCEMENT", record(lambda r: concern(r, "AM-07").update(enforcementPoints=[])))


# V5: failure modes, equal to their pins.
def test_failure_modes_refuse_am_06_revoked_fail_closed():
    refuses("AM_FAILURE_MODES", record(lambda r: concern(r, "AM-06")["whenRevoked"].update(behaviour="FAIL_CLOSED")))


def test_failure_modes_refuse_round_1_counterexample_2_am_09_unavailable_fail_closed():
    refuses("AM_FAILURE_MODES", record(lambda r: concern(r, "AM-09")["whenUnavailable"].update(
        behaviour="FAIL_CLOSED", citation={"path": am.INFRA, "line": 61, "quote": line_quote(am.INFRA, 61)})))


def test_failure_modes_refuse_a_non_stating_citation():
    refuses("AM_FAILURE_MODES", record(lambda r: concern(r, "AM-07")["whenRevoked"].update(
        citation={"path": am.MEM, "line": 53, "quote": line_quote(am.MEM, 53)})))


# V6: the budget model.
def test_budget_refuses_vb_01_expecting_two_charges():
    refuses("AM_BUDGET", vectors(am.BUDGET_PATH, lambda d: d["vectors"][0]["final"]["k"].update(committed=80)))


def test_budget_refuses_vb_05_expecting_nothing_committed():
    refuses("AM_BUDGET", vectors(am.BUDGET_PATH, lambda d: d["vectors"][4]["final"]["k"].update(committed=0)))


def test_budget_refuses_vb_06_expecting_two_terminal_states():
    refuses("AM_BUDGET", vectors(am.BUDGET_PATH, lambda d: d["vectors"][5]["final"]["k"].update(state="EXPIRED")))


def test_budget_refuses_vb_08_proceeding_without_outbox_capacity():
    refuses("AM_BUDGET", vectors(am.BUDGET_PATH, lambda d: d["vectors"][7]["results"].__setitem__(3, "proceeds")))


def test_budget_vb_04_is_a_commit_with_no_reservation_and_a_usage_step_is_unknown():
    doc = json.loads(files()[am.BUDGET_PATH])
    assert doc["vectors"][3]["steps"] == [{"op": "commit", "key": "k", "transition": "t1", "amount": 40}]
    refuses("AM_BUDGET", vectors(am.BUDGET_PATH, lambda d: d["vectors"][3].update(
        steps=[{"op": "usage", "amount": 40}])))


def test_budget_refuses_a_dropped_non_claim():
    refuses("AM_BUDGET", vectors(am.BUDGET_PATH, lambda d: d.update(nonClaims=["semantics only"])))


# V7: reconciliation and the technology record.
def test_reconciliation_refuses_a_dropped_successor():
    refuses("AM_RECONCILIATION", record(lambda r: r["reconciliation"][2].update(successor="somewhere else")))


def test_reconciliation_agrees_with_a_matching_list():
    run(tech(lambda d: d.update(pendingReconciliation=[dict(e) for e in am.RECONCILIATION])))


def test_reconciliation_refuses_a_list_giving_entry_3_another_successor():
    def listed(d):
        entries = [dict(e) for e in am.RECONCILIATION]
        entries[2]["successor"] = "another home"
        d["pendingReconciliation"] = entries
    refuses("AM_RECONCILIATION", tech(listed))


def test_reconciliation_refuses_an_unknown_new_member():
    refuses("AM_RECONCILIATION_UNKNOWN_MEMBER",
            tech(lambda d: d.update(reconciliationList=[dict(e) for e in am.RECONCILIATION])))


# V8: the R12 vectors.
def test_r12_refuses_a_vector_expecting_accept():
    refuses("AM_R12_VECTORS", vectors(am.R12_PATH, lambda d: d["vectors"][0].update(expected="ACCEPT")))


def test_r12_refuses_a_vector_naming_no_row():
    refuses("AM_R12_VECTORS", vectors(am.R12_PATH, lambda d: d["vectors"][0].update(row="AM-10")))


def test_r12_refuses_a_vector_the_map_does_not_refuse():
    refuses("AM_R12_VECTORS", vectors(am.R12_PATH, lambda d: d["vectors"][0].update(actor="policy-decision")))
    refuses("AM_R12_VECTORS", vectors(am.R12_PATH, lambda d: d["vectors"][0].update(actor="planeon.policy-decision")))


def test_r12_refuses_an_actor_that_is_not_text():
    refuses("AM_R12_VECTORS", vectors(am.R12_PATH, lambda d: d["vectors"][0].update(actor=1)))


# V9: the registry.
def test_registry_accepts_the_one_rider_appended_last():
    def rider(d):
        reg = json.loads(d[am.BRIEFS_PATH])
        reg["briefs"].append(dict(am.RIDER))
        d[am.BRIEFS_PATH] = dump(reg)
    run(rider)


def test_registry_refuses_a_second_rider():
    def riders(d):
        reg = json.loads(d[am.BRIEFS_PATH])
        reg["briefs"] += [dict(am.RIDER), dict(am.RIDER)]
        d[am.BRIEFS_PATH] = dump(reg)
    refuses("AM_REGISTRY", riders)


# Section 8: the frozen sets of tests/test_sector_catalog.py.
def test_the_module_names_no_catalog_and_lists_no_directory():
    # The catalog names are split here so that this test file names no catalog either (LITERAL_READERS).
    text = (ROOT / "scripts/authority_map.py").read_text(encoding="utf-8")
    for token in ("providers" ".yaml", "services" ".yaml", "PROVIDER_MODULE" "_CATALOG", "sector" "-catalog", "glob(",
                  "listdir", "scandir", "os.walk"):
        assert token not in text, token
