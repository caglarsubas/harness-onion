from __future__ import annotations

import json
from pathlib import Path

import pytest
import yaml

from scripts.validate_readiness_repairs import validate_repair_amendment, validate_repair_authority

ROOT = Path(__file__).resolve().parents[1]


def inputs():
    packets = {path.stem: yaml.safe_load(path.read_text(encoding="utf-8"))
               for path in (ROOT / "task-packets").glob("*.yaml")}
    record = json.loads((ROOT / "architecture/readiness-repairs.json").read_text(encoding="utf-8"))
    return packets, record


def test_corrective_authority_is_closed_without_claiming_implementation():
    assert validate_repair_authority(*inputs()) == []


@pytest.mark.parametrize("packet_id", ["MET-REPAIR-001", "CON-FIX-001", "CTRL-FIX-003", "CTRL-INTEGRATE-001", "CON-MODEL-001", "CONF-A2-001"])
def test_missing_predecessor_or_packet_is_rejected(packet_id):
    packets, record = inputs()
    del packets[packet_id]
    assert validate_repair_authority(packets, record)
    packets, record = inputs()
    packets[packet_id]["predecessors"].pop()
    assert validate_repair_authority(packets, record)


@pytest.mark.parametrize("packet_id", ["CON-FIX-001", "CTRL-FIX-003", "CTRL-INTEGRATE-001"])
@pytest.mark.parametrize("path", ["Makefile", "PORTING.yaml", "AGENTS.md", "tests/", "apps/control-web/src/lib/foundation/"])
def test_product_repair_paths_cannot_expand(packet_id, path):
    packets, record = inputs()
    packets[packet_id]["allowedPaths"].append(path)
    assert validate_repair_authority(packets, record)


@pytest.mark.parametrize("packet_id", ["CON-FIX-001", "CON-MODEL-001", "CTRL-FIX-003", "CTRL-INTEGRATE-001"])
def test_cumulative_regression_command_cannot_be_removed(packet_id):
    packets, record = inputs()
    packets[packet_id]["offlineAcceptanceCommands"].pop()
    assert validate_repair_authority(packets, record)


def test_contract_tests_cannot_be_restricted_to_the_latest_slice():
    packets, record = inputs()
    packets["CON-MODEL-001"]["offlineAcceptanceCommands"][-1][-1] = "tests/model_api"
    assert validate_repair_authority(packets, record)


@pytest.mark.parametrize("packet_id", ["MET-REPAIR-001", "CON-FIX-001", "CTRL-FIX-003", "CTRL-INTEGRATE-001"])
@pytest.mark.parametrize("field,value", [("warmSourceAccess", "AUTHORIZED_READ_ONLY_OBSERVATION"), ("referenceObservationExecution", {}), ("liveCampaignExecution", {}), ("sourceReuse", [{"reuseMode": "COPY_AUTHORIZED"}]), ("repository", "mas-harness-model-plane")])
def test_corrective_run_cannot_gain_unrelated_authority(packet_id, field, value):
    packets, record = inputs()
    packets[packet_id][field] = value
    assert validate_repair_authority(packets, record)


@pytest.mark.parametrize("index", range(6))
def test_authority_publication_cannot_close_product_findings(index):
    packets, record = inputs()
    record["findings"][index]["status"] = "DONE"
    assert validate_repair_authority(packets, record)


@pytest.mark.parametrize("field,value", [("currentPacketCount", 110), ("historicalPhaseZeroPacketCount", 114), ("historicalAlphaTwoPublicationPacketCount", 114), ("productionIntegrationOwner", "CTRL-007"), ("liveCertificationOwner", "CTRL-INTEGRATE-001"), ("evidenceBoundary", "PASS"), ("productionGate", "SOURCE_SUFFICIENT"), ("unexpected", True)])
def test_repair_record_cannot_rewrite_history_or_promote_evidence(field, value):
    packets, record = inputs()
    record[field] = value
    assert validate_repair_authority(packets, record)


@pytest.mark.parametrize("value", [None, [], "PASS", {"findings": []}, {"findings": [None] * 6}])
def test_malformed_repair_records_fail_closed(value):
    packets, _ = inputs()
    assert validate_repair_authority(packets, value)


def test_duplicate_or_wrong_owner_finding_is_rejected():
    packets, record = inputs()
    record["findings"][-1] = record["findings"][0]
    assert validate_repair_authority(packets, record)


def test_live_evidence_requirement_cannot_be_removed():
    packets, record = inputs()
    packets["CONF-A2-001"]["expectedEvidence"].pop()
    assert validate_repair_authority(packets, record)


def amendment_inputs():
    packets, _ = inputs()
    record = json.loads((ROOT / "architecture/readiness-repair-amendment.json").read_text())
    history = (ROOT / "architecture/readiness-repairs.json").read_bytes()
    return packets, record, history


def test_approved_amendment_retains_failed_baseline_and_exact_scope():
    assert validate_repair_amendment(*amendment_inputs()) == []


@pytest.mark.parametrize("packet_id", ["MET-REPAIR-002", "CON-FIX-001"])
def test_missing_amendment_packet_or_predecessor_fails_closed(packet_id):
    packets, record, history = amendment_inputs()
    del packets[packet_id]
    assert validate_repair_amendment(packets, record, history)
    packets, record, history = amendment_inputs()
    packets[packet_id]["predecessors"].pop()
    assert validate_repair_amendment(packets, record, history)


@pytest.mark.parametrize("packet_id", ["MET-REPAIR-002", "CON-FIX-001"])
@pytest.mark.parametrize("path", [
    "src/planeon_harness_contracts/command_registry.py",
    "src/planeon_harness_contracts/cli.py", "src/", "tests/", "AGENTS.md",
    "Makefile", "PORTING.yaml", ".github/workflows/verify.yml",
])
def test_amendment_cannot_authorize_registry_or_unbounded_product_edits(packet_id, path):
    packets, record, history = amendment_inputs()
    packets[packet_id]["allowedPaths"].append(path)
    assert validate_repair_amendment(packets, record, history)


@pytest.mark.parametrize("packet_id", ["MET-REPAIR-002", "CON-FIX-001"])
def test_amendment_commands_cannot_omit_cumulative_acceptance(packet_id):
    packets, record, history = amendment_inputs()
    packets[packet_id]["offlineAcceptanceCommands"].pop()
    assert validate_repair_amendment(packets, record, history)


@pytest.mark.parametrize("field,value", [
    ("failed", 0), ("passed", 184), ("skipped", 3),
    ("skipped", False), ("failed", 3.0),
    ("commit", "0" * 40), ("outputSha256", "0" * 64),
    ("packetSha256", "0" * 64), ("failures", []),
    ("execution", "GITHUB_ACTIONS_PASS"),
])
def test_failed_predecessor_evidence_cannot_be_relabelled(field, value):
    packets, record, history = amendment_inputs()
    record["baseline"][field] = value
    assert validate_repair_amendment(packets, record, history)


@pytest.mark.parametrize("field,value", [
    ("function", "classify_freshness"), ("beforeSha256", "0" * 64),
    ("expectedState", "DEGRADED"), ("higherPrecedence", []),
    ("retainedDefinitionBytes", "NONE"), ("freshnessClassifierChange", "ALLOWED"),
    ("publishedSemanticsChange", "ALLOWED"), ("productStatus", "DONE"),
    ("findingEvidence", "PASS"),
])
def test_implementation_exception_cannot_expand_or_claim_execution(field, value):
    packets, record, history = amendment_inputs()
    record["implementationException"][field] = value
    assert validate_repair_amendment(packets, record, history)


@pytest.mark.parametrize("index", range(5))
def test_each_bounded_test_and_implementation_obligation_is_required(index):
    packets, record, history = amendment_inputs()
    packets["CON-FIX-001"]["deliverables"][-5 + index] = "Drop this guard"
    assert validate_repair_amendment(packets, record, history)


def test_exclusions_and_baseline_obligation_cannot_be_removed():
    packets, record, history = amendment_inputs()
    packets["CON-FIX-001"]["excluded"] = ["No paid APIs"]
    assert validate_repair_amendment(packets, record, history)
    packets, record, history = amendment_inputs()
    packets["CON-FIX-001"]["expectedEvidence"].pop()
    assert validate_repair_amendment(packets, record, history)


def test_historical_six_finding_publication_is_byte_immutable():
    packets, record, history = amendment_inputs()
    assert validate_repair_amendment(packets, record, history + b"\n")


@pytest.mark.parametrize("record", [None, [], "PASS", {}, {"unexpected": True}])
def test_malformed_amendment_record_fails_closed(record):
    packets, _, history = amendment_inputs()
    assert validate_repair_amendment(packets, record, history)


@pytest.mark.parametrize("field,value", [
    ("liveCampaignExecution", {}), ("referenceObservationExecution", {}),
    ("warmSourceAccess", "AUTHORIZED_READ_ONLY_OBSERVATION"),
    ("sourceReuse", [{"reuseMode": "COPY_AUTHORIZED"}]),
    ("repository", "mas-harness-contracts"),
])
def test_meta_amendment_cannot_become_a_product_source_or_live_run(field, value):
    packets, record, history = amendment_inputs()
    packets["MET-REPAIR-002"][field] = value
    assert validate_repair_amendment(packets, record, history)
