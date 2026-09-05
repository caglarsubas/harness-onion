#!/usr/bin/env python3
"""Validate corrective authority; never claim that a product repair executed."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import yaml

ROOT = Path(__file__).resolve().parents[1]
UV_PYTHON = ["uv", "run", "--offline", "--frozen", "--no-sync", "python"]
CONTRACT_COMMANDS = [
    [*UV_PYTHON, "scripts/generate_contracts.py", "--check"],
    [*UV_PYTHON, "scripts/check_generated.py"],
    [*UV_PYTHON, "-m", "pytest", "tests"],
]
REPAIR_PREDECESSORS = {
    "MET-REPAIR-001": ["MET-OBS-MODEL-001", "CTRL-FIX-002"],
    "CON-FIX-001": ["CON-007", "MET-REPAIR-001"],
    "CTRL-FIX-003": ["CTRL-FIX-002", "CON-FIX-001"],
    "CTRL-INTEGRATE-001": ["CTRL-FIX-003"],
}
PRODUCT_PATHS = {
    "CON-FIX-001": [
        "tests/golden/test_generated_contracts.py", "tests/runtime/test_runtime_contracts.py",
        "tests/model/test_aggregation_interoperability.py",
        "tests/fixtures/status/aggregation-interoperability.json", "contracts/regression-inputs/",
        "scripts/generate_contracts.py", "generated/", "contracts/release-manifest.json",
        "docs/regression-policy.md",
    ],
    "CTRL-FIX-003": [
        "apps/control-web/src/lib/harness-status/aggregation.ts",
        "apps/control-web/src/lib/harness-status/projection-store.ts",
        "apps/control-web/src/lib/harness-status/http.ts",
        "apps/control-web/src/lib/harness-status/runtime.ts",
        "tests/harness-status/aggregation.test.ts", "tests/harness-status/projection-store.test.ts",
        "tests/harness-status/http.test.ts", "tests/harness-status/status-interoperability.test.ts",
        "contracts/status-regression/", "ci/targets/ctrl-fix-003.json", "docs/harness-overview.md",
    ],
    "CTRL-INTEGRATE-001": [
        "apps/control-web/src/lib/harness-status/", "apps/control-web/src/app/overview/",
        "apps/control-web/src/app/planes/", "apps/control-web/src/app/harnesses/",
        "apps/control-web/src/app/organizations/", "apps/control-web/src/app/api/v1alpha1/overview/",
        "apps/control-web/src/app/api/v1alpha1/planes/", "apps/control-web/src/app/api/v1alpha1/harnesses/",
        "apps/control-web/src/app/api/v1alpha1/organizations/", "packages/db/status-projections/",
        "packages/db/migrations/harness-status/002_durable_adapters.sql", "contracts/status-integration/",
        "tests/harness-status/", "e2e/harness-status-production.spec.ts",
        "ci/targets/ctrl-integrate-001.json", "docs/harness-overview.md",
        "docs/security/status-production-integration.md",
    ],
}
PRODUCT_COMMANDS = {
    "CON-FIX-001": CONTRACT_COMMANDS,
    "CTRL-FIX-003": [["make", "ctrl-fix-003-regression"], ["make", "overview-e2e"], ["make", "zero-bill"]],
    "CTRL-INTEGRATE-001": [["make", "status-integration-regression"], ["make", "status-integration-e2e"], ["make", "status-integration-postgres"], ["make", "zero-bill"]],
}
FINDING_OWNERS = {
    "R01": ("FOUNDATION_CORRECTION", "CON-FIX-001"),
    "R02": ("ALPHA_2_ENTRY", "CON-FIX-001"),
    "R03": ("ALPHA_1_CORRECTION", "CTRL-FIX-003"),
    "R04": ("ALPHA_1_CORRECTION", "CTRL-FIX-003"),
    "R05": ("ALPHA_1_CORRECTION", "CTRL-FIX-003"),
    "R06": ("ALPHA_1_INTEGRATION", "CTRL-INTEGRATE-001"),
}


def validate_repair_authority(packets: dict[str, Any], record: Any) -> list[str]:
    errors: list[str] = []

    def require(condition: bool, message: str) -> None:
        if not condition:
            errors.append(message)

    if not isinstance(record, dict):
        return ["repair authority must be an object"]
    constants = {
        "schemaVersion": "harness.planeon.ai/readiness-repairs/v1",
        "authorityPacket": "MET-REPAIR-001", "reviewDate": "2026-09-05",
        "reviewMethod": "READ_ONLY_SOURCE_ANALYSIS",
        "historicalPhaseZeroPacketCount": 107,
        "historicalAlphaTwoPublicationPacketCount": 110, "currentPacketCount": 114,
        "modelCodingPrerequisites": ["CON-FIX-001", "CTRL-FIX-003"],
        "productionIntegrationOwner": "CTRL-INTEGRATE-001",
        "liveCertificationOwner": "CONF-A2-001",
        "evidenceBoundary": "AUTHORITY_ONLY_NOT_PRODUCT_FIX_OR_LIVE_ACCEPTANCE",
        "productionGate": "FRESH_INSTALLED_FOUNDATION_AND_AUTHENTICATED_DURABLE_OVERVIEW_EVIDENCE_REQUIRED",
    }
    require(set(record) == {*constants, "findings"}, "repair authority fields changed")
    for field, expected in constants.items():
        require(record.get(field) == expected, f"repair authority {field} changed")
    findings = record.get("findings")
    if not isinstance(findings, list) or len(findings) != len(FINDING_OWNERS):
        errors.append("repair authority must contain exactly six findings")
    else:
        for finding, (finding_id, (phase, owner)) in zip(findings, FINDING_OWNERS.items()):
            if not isinstance(finding, dict):
                errors.append(f"{finding_id} must be an object")
                continue
            require(set(finding) == {"id", "phase", "owner", "description", "status"}, f"{finding_id} fields changed")
            require((finding.get("id"), finding.get("phase"), finding.get("owner")) == (finding_id, phase, owner), f"{finding_id} ownership changed")
            require(finding.get("status") == "WAITING_IMPLEMENTATION", f"{finding_id} publication cannot claim a product fix")
            require(isinstance(finding.get("description"), str) and len(finding["description"]) >= 20, f"{finding_id} needs a concrete description")
    for packet_id, predecessors in REPAIR_PREDECESSORS.items():
        packet = packets.get(packet_id, {})
        require(packet.get("predecessors") == predecessors, f"{packet_id} corrective predecessors changed")
        require(packet.get("warmSourceAccess") == "PROHIBITED_DURING_IMPLEMENTATION"
                and packet.get("sourceReuse") == [] and "referenceObservationExecution" not in packet
                and "liveCampaignExecution" not in packet, f"{packet_id} cannot gain source or live authority")
        repository = ("Harness-Engineering" if packet_id == "MET-REPAIR-001" else
                      "mas-harness-contracts" if packet_id == "CON-FIX-001" else "mas-harness-control-plane")
        require(packet.get("repository") == repository, f"{packet_id} repository changed")
        if packet_id in PRODUCT_PATHS:
            require(packet.get("allowedPaths") == PRODUCT_PATHS[packet_id], f"{packet_id} path boundary changed")
            require(packet.get("offlineAcceptanceCommands") == PRODUCT_COMMANDS[packet_id], f"{packet_id} regression commands changed")
            require(packet.get("prefetchCommands") == ([] if packet_id == "CON-FIX-001" else [["make", "prefetch"]]), f"{packet_id} prefetch boundary changed")
    model = packets.get("CON-MODEL-001", {})
    require(model.get("predecessors") == ["CON-007", "MET-OBS-MODEL-001", "CON-FIX-001", "CTRL-FIX-003"], "model coding must wait for both product corrections")
    require(model.get("offlineAcceptanceCommands") == CONTRACT_COMMANDS, "model contract acceptance must run the entire contracts suite")
    live = packets.get("CONF-A2-001", {})
    require(live.get("predecessors") == ["CONF-A1-001", "KN-RET-001", "MODEL-003", "RUN-GW-002", "EXEC-PROT-001", "EXEC-ORCH-001", "CTRL-INTEGRATE-001"], "Alpha-2 certification must retain foundation and production integration gates")
    require("Fresh CONF-A1-001 installed-foundation evidence and production-overview browser/API/PostgreSQL evidence are required for live certification; missing target, signed authority or durable integration is NOT_RUN_ENV_UNAVAILABLE, never PASS." in live.get("expectedEvidence", []), "live certification must not substitute source or fixture evidence")
    return errors


def main() -> int:
    try:
        packets = {path.stem: yaml.safe_load(path.read_text(encoding="utf-8"))
                   for path in (ROOT / "task-packets").glob("*.yaml")}
        record = json.loads((ROOT / "architecture/readiness-repairs.json").read_text(encoding="utf-8"))
        errors = validate_repair_authority(packets, record)
    except (OSError, ValueError, TypeError, yaml.YAMLError) as exc:
        print(f"Readiness repair authority failed: {exc}")
        return 1
    for error in errors:
        print(f"ERROR: {error}")
    if not errors:
        print("Readiness repair authority passed; product fixes and live acceptance remain unproven")
    return int(bool(errors))


if __name__ == "__main__":
    raise SystemExit(main())
