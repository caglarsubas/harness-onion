"""MET-014 (REG-ALIGN-001): the regulatory alignment record, its README's provenance and its checker.

The live record passes the checker (scripts/validate_regulatory_alignment.py, RA_SHAPE to RA_SOURCES): its top-level
keys are exactly the 11 published ones and the README's provenance block holds the five moved keys (CONTRACT_296 r2
section 3b, Q-C296-2 (a)); then in-memory failing cases: at least one per checker code and one per rule of the record's
eight. The member has no vectors file and no model (CONTRACT_296 section 3's member table): these mutation cases are its
negatives. Every case mutates a copy of the live bytes behind an injected reader; no file is written."""
import copy
import importlib.util
import json
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
_spec = importlib.util.spec_from_file_location("validate_regulatory_alignment_under_test",
                                               ROOT / "scripts/validate_regulatory_alignment.py")
RA = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(RA)
READ = RA.disk_reader(ROOT)
RECORD = json.loads(READ(RA.RECORD_PATH))
README = READ(RA.README_PATH).decode("utf-8")


def _reader(record=None, readme=None):
    over = {RA.RECORD_PATH: (json.dumps(RECORD if record is None else record, indent=2, ensure_ascii=False) + "\n")
            .encode("utf-8"), RA.README_PATH: (README if readme is None else readme).encode("utf-8")}
    return lambda path: over[path] if path in over else READ(path)


def _codes(record=None, readme=None):
    return [code for code, _ in RA.check(_reader(record, readme))]


def _first(record, key, test):
    return next(row for row in record[key] if test(row))


def test_live_record_passes_its_checker():
    assert RA.check(READ) == []
    assert RA.main([str(ROOT)]) == 0


def test_published_keys_and_provenance():
    assert list(RECORD) == list(RA.TOP) and len(RECORD) == 11
    assert RECORD["status"] == "PUBLISHED" and RECORD["schemaVersion"] == "1.0.0"
    moved = RA.provenance(READ)
    assert sorted(moved) == sorted(RA.MOVED) and moved["intendedPath"] == RA.RECORD_PATH
    assert not set(moved) & set(RECORD)


def test_ra_shape_refuses_a_moved_key_back_in_the_record():
    record = copy.deepcopy(RECORD)
    record["draftDate"] = "2026-11-22"
    assert _codes(record=record) == ["RA_SHAPE"]


def test_ra_shape_refuses_a_draft_status():
    record = copy.deepcopy(RECORD)
    record["status"] = "DRAFT"
    assert _codes(record=record) == ["RA_SHAPE"]


def test_ra_shape_refuses_a_readme_without_provenance():
    assert _codes(readme=README.replace("## Provenance", "## History")) == ["RA_SHAPE"]


def test_ra_enums_refuses_an_unknown_state():
    record = copy.deepcopy(RECORD)
    record["rows"][0]["state"] = "COMPLIANT"
    assert "RA_ENUMS" in _codes(record=record)


def test_ra_ids_refuses_a_duplicate_row_id():
    record = copy.deepcopy(RECORD)
    record["rows"][1]["id"] = record["rows"][0]["id"]
    assert _codes(record=record) == ["RA_IDS"]


def test_ra_sources_refuses_an_unknown_source():
    record = copy.deepcopy(RECORD)
    record["rows"][0]["source"] = "NOT-A-SOURCE"
    assert _codes(record=record) == ["RA_SOURCES"]


def _rule_cases():
    out = []
    def r1(record):   # data-independent: r4 has no MAPPED row (ORC-296-Q-C1-3 (a))
        row = _first(record, "rows", lambda r: r["state"] == "PARTIAL" and r["carrierCheck"] == "NOT_CHECKED")
        row["state"] = "MAPPED"
    out.append(("rule 1", r1))
    if [r for r in RECORD["rows"] if r.get("candidateState") == "MAPPED"]:
        def r2(record):
            _first(record, "rows", lambda r: r.get("candidateState") == "MAPPED")["carrierCheck"] = "CONFIRMED"
        out.append(("rule 2", r2))

    def r3(record):
        _first(record, "rows", lambda r: r["state"] != "MAPPED")["gap"]["note"] = ""
    out.append(("rule 3", r3))
    if [r for r in RECORD["rows"] + RECORD["euDates"] if r["gap"] and r["gap"]["kind"] == "PRODUCT_GAP"]:
        def r4(record):
            row = _first(record, "rows", lambda r: r["gap"] is not None and r["gap"]["kind"] == "PRODUCT_GAP")
            row["gap"]["carryingItems"] = []
            row["gap"].pop("noCarryingItem", None)
        out.append(("rule 4", r4))

    def r5(record):
        record["euDates"][0]["dateAsAmended"]["confirmation"] = ""
    out.append(("rule 5", r5))

    def r6(record):
        row = record["euDates"][0]
        row["dateAsEnacted"]["confirmation"] = "UNCONFIRMED"
    out.append(("rule 6", r6))

    def r7(record):
        record["euDates"][0]["dateAlreadyPassed"] = not record["euDates"][0]["dateAlreadyPassed"]
    out.append(("rule 7", r7))

    def r8(record):
        record["euDates"][0]["obligationLocator"] = "Art 50(1); 50(5)"
    out.append(("rule 8", r8))
    return out


@pytest.mark.parametrize("name,mutate", _rule_cases(), ids=[n for n, _ in _rule_cases()])
def test_ra_rules_refuses_each_rule_broken(name, mutate):
    record = copy.deepcopy(RECORD)
    mutate(record)
    refusals = RA.check(_reader(record=record))
    assert "RA_RULES" in [code for code, _ in refusals], name
    if name == "rule 1":
        assert any(code == "RA_RULES" and "rule 1" in message for code, message in refusals)


def test_rules_are_the_records_eight():
    assert RECORD["rules"] == list(RA.RULES) and len(RA.RULES) == 8
