from __future__ import annotations

import json
from pathlib import Path

import pytest
import yaml

from scripts.validate_readiness_repairs import validate_repair_authority

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
