"""MET-008 (RELEASE-EVIDENCE-001): the capability evidence matrix, its projection and its checker.

The live record is its projection, passes the checker and validates against its schema; the projection raises when a
premise of its states fails; and each checker code has a vector that makes it fire on its own, with its expected list
stated. The vectors for RE_BASIS, RE_CLOSURE, RE_CELLS, RE_DOMAINS and RE_EXCLUSIONS replace release_evidence.project
with one that returns the mutated record, so RE_PROJECTION stays quiet; every vector except RE_PROFILE's stands the
registered release-profile checker in with one that accepts. RE_EXCLUSIONS' id vectors let its nine-id list lead with
the mutated id, so each reaches its own refusal. Every case works on in-memory copies behind an injected reader; no
file is written."""
import copy
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


RE = _load("scripts/validate_release_evidence.py", "validate_release_evidence_under_test")
PROJ = RE.projection
READ = RE.disk_reader(ROOT)
RAW = READ(PROJ.RECORD_PATH)
RECORD = json.loads(RAW)
SCHEMA = json.loads(READ(PROJ.SCHEMA_PATH))


def _accepting_profile(monkeypatch):
    monkeypatch.setattr(RE.validate_release_profile, "validate_release_profile", lambda: None)


def _codes(record, monkeypatch, replace=True, read=READ):
    _accepting_profile(monkeypatch)
    if replace:
        monkeypatch.setattr(RE.projection, "project", lambda _read: copy.deepcopy(record))
    return RE.validate(record, read)


def _module_row(record, index=0):
    return [r for r in record["rows"] if r["nodeClass"] != "TENANT_FACT"][index]


def _tenant_row(record):
    return next(r for r in record["rows"] if r["nodeClass"] == "TENANT_FACT")


def _blocked(row):
    return next(c for c in row["cells"].values() if c["state"] == "BLOCKED")


def test_the_live_record_is_its_projection_and_passes():
    assert RAW == PROJ.serialize(PROJ.project(READ))
    assert RE.validate(RECORD, READ) == []
    jsonschema.Draft202012Validator(SCHEMA).validate(RECORD)


def test_the_counts_and_the_cells():
    counts = RECORD["counts"]
    assert counts["rows"] == len(RECORD["rows"]) == 41 and counts["exclusionRows"] == len(RECORD["exclusionRows"]) == 9
    assert counts["cellsByState"] == {"NOT_RUN": 90, "NOT_SELECTED": 138, "BLOCKED": 472, "FAILED": 0, "QUALIFIED": 0}
    for row in RECORD["rows"] + RECORD["exclusionRows"]:
        assert list(row["cells"]) == list(PROJ.COLUMNS) and list(row["claimDomains"]) == list(PROJ.DOMAINS)
    assert list(RECORD["producerStatus"]["statuses"]) == sorted(RECORD["producerStatus"]["statuses"])


def test_tenant_rows_share_the_tenant_producer_and_module_rows_do_not():
    for row in RECORD["rows"]:
        a, c = row["cells"]["tenantAcceptance"], row["claimDomains"]["customerAcceptance"]
        if row["nodeClass"] == "TENANT_FACT":
            assert a["state"] == c["state"] == "BLOCKED" and a["producer"] == c["producer"]
            assert a["reference"] == c["reference"] == PROJ.PROFILE_PATH + "#" + row["id"]
        else:
            assert a["producer"] != c["producer"] and a["reference"] != c["reference"]


def _patched_reader(path, mutate):
    def read(p):
        raw = READ(p)
        if p != path:
            return raw
        value = json.loads(raw)
        mutate(value)
        return json.dumps(value).encode("utf-8")
    return read


def _lock_not_inert(lock):
    lock["documentKind"] = "RELEASE_SET"


def _exit_elsewhere(profile):
    profile["modules"][0]["exitEvidence"]["at"] = "CONF-WG-001"


def _fact_attested(profile):
    profile["tenantFacts"][0]["attestation"]["requirement"] = "ATTESTATION_RECORD"


@pytest.mark.parametrize("path,mutate", [
    ("release/repos.lock.json", _lock_not_inert),
    ("architecture/release-profile.json", _exit_elsewhere),
    ("architecture/release-profile.json", _fact_attested),
])
def test_the_projection_raises_when_a_premise_fails(path, mutate):
    with pytest.raises(ValueError):
        PROJ.project(_patched_reader(path, mutate))


def test_shape_a_statuses_key_that_is_neither_a_packet_id_nor_the_role_key(monkeypatch):
    bad = copy.deepcopy(RECORD)
    bad["producerStatus"]["statuses"]["human probes"] = "WAITING_OWNER"
    assert _codes(bad, monkeypatch) == ["RE_SHAPE"]


def test_shape_cells_as_a_list(monkeypatch):
    bad = copy.deepcopy(RECORD)
    bad["rows"][0]["cells"] = list(bad["rows"][0]["cells"].values())
    assert _codes(bad, monkeypatch) == ["RE_SHAPE"]


def test_shape_a_cell_without_its_date(monkeypatch):
    bad = copy.deepcopy(RECORD)
    del bad["rows"][0]["claimDomains"]["containment"]["date"]
    assert _codes(bad, monkeypatch) == ["RE_SHAPE"]


def test_profile_a_refusing_registered_checker(monkeypatch):
    def refuse():
        raise ValueError("release profile refused")
    monkeypatch.setattr(RE.validate_release_profile, "validate_release_profile", refuse)
    assert RE.validate(RECORD, READ) == ["RE_PROFILE"]


def test_basis_a_digest_that_does_not_match(monkeypatch):
    bad = copy.deepcopy(RECORD)
    bad["basis"]["releaseLock"]["sha256"] = "0" * 64
    assert _codes(bad, monkeypatch) == ["RE_BASIS"]


def test_basis_a_pin_at_another_path(monkeypatch):
    bad = copy.deepcopy(RECORD)
    bad["basis"]["deployableRecord"]["path"] = "architecture/repositories.yaml"
    assert _codes(bad, monkeypatch) == ["RE_BASIS"]


def test_closure_rows_out_of_order(monkeypatch):
    bad = copy.deepcopy(RECORD)
    bad["rows"][0], bad["rows"][1] = bad["rows"][1], bad["rows"][0]
    assert _codes(bad, monkeypatch) == ["RE_CLOSURE"]


def test_closure_a_module_row_of_the_other_class(monkeypatch):
    bad = copy.deepcopy(RECORD)
    row = _module_row(bad)
    row["nodeClass"] = "CLOSURE" if row["nodeClass"] == "SELECTED" else "SELECTED"
    assert _codes(bad, monkeypatch) == ["RE_CLOSURE"]


def test_closure_a_module_row_relabelled_as_a_tenant_fact(monkeypatch):
    bad = copy.deepcopy(RECORD)
    _module_row(bad)["nodeClass"] = "TENANT_FACT"
    assert _codes(bad, monkeypatch) == ["RE_CLOSURE"]


def test_closure_a_tenant_fact_row_relabelled_as_a_module(monkeypatch):
    bad = copy.deepcopy(RECORD)
    _tenant_row(bad)["nodeClass"] = "SELECTED"
    assert _codes(bad, monkeypatch) == ["RE_CLOSURE"]


def test_projection_a_changed_next_action(monkeypatch):
    bad = copy.deepcopy(RECORD)
    _blocked(_module_row(bad))["nextAction"] = "wait"
    assert _codes(bad, monkeypatch, replace=False) == ["RE_PROJECTION"]


def test_projection_a_raising_projection(monkeypatch):
    def broken(_read):
        raise ValueError("a premise failed")
    _accepting_profile(monkeypatch)
    monkeypatch.setattr(RE.projection, "project", broken)
    assert RE.validate(RECORD, READ) == ["RE_PROJECTION"]


def _set_reference(record, reference):
    cell = _module_row(record)["cells"]["tenantAcceptance"]
    cell["reference"] = reference


@pytest.mark.parametrize("reference", [
    "docs/README.md",                                   # a path outside basis
    "release/repos.lock.json#sourceCommit",             # a fragment on the lock
    "architecture/release-profile.json#OTHER",          # a fragment naming another row (filled in below)
    "packet:UAT-CAMPAIGN-001",                          # an unknown packet: no YAML on main
    "packet:conf-wg-001",                               # a malformed packet id
])
def test_cells_a_refused_reference(reference, monkeypatch):
    bad = copy.deepcopy(RECORD)
    if reference.endswith("#OTHER"):
        reference = PROJ.PROFILE_PATH + "#" + _module_row(bad, 1)["id"]
    _set_reference(bad, reference)
    assert _codes(bad, monkeypatch) == ["RE_CELLS"]


@pytest.mark.parametrize("state", ["QUALIFIED", "FAILED"])
def test_cells_a_qualified_or_failed_cell(state, monkeypatch):
    bad = copy.deepcopy(RECORD)
    _module_row(bad)["claimDomains"]["containment"]["state"] = state
    assert _codes(bad, monkeypatch) == ["RE_CELLS"]


def test_cells_a_status_changed_and_the_states_not(monkeypatch):
    bad = copy.deepcopy(RECORD)
    bad["producerStatus"]["statuses"]["CAP-CATALOG-001"] = "BLOCKED"
    assert _codes(bad, monkeypatch) == ["RE_CELLS"]


def test_cells_a_producer_on_a_not_selected_cell(monkeypatch):
    bad = copy.deepcopy(RECORD)
    _tenant_row(bad)["cells"]["sourceCommit"]["producer"] = "someone"
    assert _codes(bad, monkeypatch) == ["RE_CELLS"]


def test_cells_a_required_source_on_a_not_selected_cell(monkeypatch):
    bad = copy.deepcopy(RECORD)
    cell = _tenant_row(bad)["cells"]["sourceCommit"]
    assert cell["state"] == "NOT_SELECTED"
    cell["requiredSource"] = "a source"
    assert _codes(bad, monkeypatch) == ["RE_CELLS"]


def test_cells_an_empty_next_action(monkeypatch):
    bad = copy.deepcopy(RECORD)
    _blocked(_module_row(bad))["nextAction"] = ""
    assert _codes(bad, monkeypatch) == ["RE_CELLS"]


def test_cells_a_not_selected_next_action_without_its_prefix(monkeypatch):
    bad = copy.deepcopy(RECORD)
    cell = _tenant_row(bad)["cells"]["sourceCommit"]
    assert cell["state"] == "NOT_SELECTED" and cell["nextAction"].startswith("none: ")
    cell["nextAction"] = cell["nextAction"][len("none: "):]
    assert _codes(bad, monkeypatch) == ["RE_CELLS"]


def test_cells_an_owner_outside_the_pattern(monkeypatch):
    bad = copy.deepcopy(RECORD)
    _blocked(_module_row(bad))["owner"] = "the tenant"
    assert _codes(bad, monkeypatch) == ["RE_CELLS"]


def test_cells_a_date_that_is_not_as_of(monkeypatch):
    bad = copy.deepcopy(RECORD)
    _blocked(_module_row(bad))["date"] = "2026-11-15"
    assert _codes(bad, monkeypatch) == ["RE_CELLS"]


def test_domains_a_shared_producer(monkeypatch):
    bad = copy.deepcopy(RECORD)
    row = _module_row(bad)
    row["claimDomains"]["customerAcceptance"]["producer"] = row["cells"]["tenantAcceptance"]["producer"]
    assert _codes(bad, monkeypatch) == ["RE_DOMAINS"]


def test_domains_a_shared_reference(monkeypatch):
    bad = copy.deepcopy(RECORD)
    row = _module_row(bad)
    row["claimDomains"]["customerAcceptance"]["reference"] = row["cells"]["tenantAcceptance"]["reference"]
    assert _codes(bad, monkeypatch) == ["RE_DOMAINS"]


def _x_id(value):
    return lambda row: row.__setitem__("id", value)


def _x_repository(member, value):
    return lambda row: row["repository"].__setitem__(member, value)


def _x_member(member, value):
    return lambda row: row.__setitem__(member, value)


def _x_source(member, value):
    return lambda row: row["source"].__setitem__(member, value)


@pytest.mark.parametrize("mutate", [
    _x_id("distribution.Bundle"),                      # the id's grammar
    _x_id("nowhere.bundle"),                           # a registry part that is not a repository id
    _x_repository("id", "control-plane"),              # a repository id that differs from the registry part
    _x_repository("name", "another-repository"),       # a repository name that differs from the entry's
    _x_repository("rNumber", "R99"),                   # an rNumber that differs from the entry's
    _x_id("distribution.bundle-lock"),                 # a duplicate id
    _x_member("side", "CONSUMER"),                     # a side other than PRODUCER
    _x_member("rider", "RELEASE-PROFILE-001 errata (2026-10-31): F-R04-2"),  # the other repository's rider
    _x_source("registryRow", "control-plane"),         # a source for another registry row
    _x_source("mainPin", "FE49981E"),                  # a main pin that is not lower-case hex
])
def test_exclusions_a_refused_row(mutate, monkeypatch):
    bad = copy.deepcopy(RECORD)
    mutate(bad["exclusionRows"][0])
    if bad["exclusionRows"][0]["id"] != RECORD["exclusionRows"][0]["id"]:
        _exclusions_led_by(monkeypatch, bad["exclusionRows"][0]["id"])
    assert _codes(bad, monkeypatch) == ["RE_EXCLUSIONS"]


def _exclusions_led_by(monkeypatch, first_id):
    """Let RE_EXCLUSIONS' nine-id list lead with first_id, so an id vector reaches its own refusal (MET008-S1-2)."""
    entries = list(PROJ.EXCLUSIONS)
    entries[0] = (first_id,) + tuple(entries[0][1:])
    monkeypatch.setattr(PROJ, "EXCLUSIONS", tuple(entries))


def test_exclusions_an_id_equal_to_a_tenant_fact(monkeypatch):
    """No real closure-node or tenant-fact id has a repository's registry part, so each would be refused by the id's
    grammar or registry part first. The reader adds a tenant fact whose id has one, the profile pin follows the
    reader's bytes, and the nine-id list leads with it: only the node refusal decides."""
    bad = copy.deepcopy(RECORD)
    node = bad["exclusionRows"][0]["id"].split(".", 1)[0] + ".node-under-test"
    read = _patched_reader(PROJ.PROFILE_PATH, lambda profile: profile["tenantFacts"].append({"id": node}))
    bad["basis"]["profile"]["sha256"] = RE.digest(read(PROJ.PROFILE_PATH))
    bad["exclusionRows"][0]["id"] = node
    _exclusions_led_by(monkeypatch, node)
    assert _codes(bad, monkeypatch, read=read) == ["RE_EXCLUSIONS"]
