from __future__ import annotations

import copy
import importlib.util
import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "data_harness_v1_observation_validator",
    ROOT / "scripts/validate_data_harness_v1_observation.py",
)
assert SPEC and SPEC.loader
VALIDATOR = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(VALIDATOR)


def load_fixture() -> tuple[dict[str, object], bytes, dict[str, object], bytes]:
    report_raw = VALIDATOR.REPORT_PATH.read_bytes()
    report = json.loads(report_raw)
    packet, packet_bytes = VALIDATOR.load_packet()
    return report, report_raw, packet, packet_bytes


def mutated_bytes(report: dict[str, object]) -> bytes:
    return (json.dumps(report, indent=2, sort_keys=True) + "\n").encode("utf-8")


def test_observed_report_is_closed_deterministic_and_index_bound() -> None:
    report, raw, packet, packet_bytes = load_fixture()
    assert VALIDATOR.validate_report(report, raw, packet, packet_bytes) == []


def test_observed_report_rejects_source_text() -> None:
    report, _, packet, packet_bytes = load_fixture()
    candidate = copy.deepcopy(report)
    candidate["facts"][0]["description"] = "source prose"

    errors = VALIDATOR.validate_report(
        candidate,
        mutated_bytes(candidate),
        packet,
        packet_bytes,
    )

    assert any("prohibited source-text key" in error for error in errors)


def test_observed_report_rejects_host_identity_and_source_root() -> None:
    report, _, packet, packet_bytes = load_fixture()
    candidate = copy.deepcopy(report)
    candidate["authority"]["observerUid"] = 501
    candidate["authority"]["sourceRoot"] = "/private/tmp/codex-harness-warmstarts.hidden/source"

    errors = VALIDATOR.validate_report(
        candidate,
        mutated_bytes(candidate),
        packet,
        packet_bytes,
    )

    assert any("host-dependent or unknown" in error for error in errors)
    assert any("prohibited source-text key" in error for error in errors)
    assert any("warm-source filesystem path" in error for error in errors)


def test_observed_report_rejects_unknown_fact_kind() -> None:
    report, _, packet, packet_bytes = load_fixture()
    candidate = copy.deepcopy(report)
    candidate["facts"][0]["kind"] = "SOURCE_TEXT"

    errors = VALIDATOR.validate_report(
        candidate,
        mutated_bytes(candidate),
        packet,
        packet_bytes,
    )

    assert any("undeclared fact kind" in error for error in errors)


def test_observed_report_rejects_blob_not_in_reuse_index() -> None:
    report, _, packet, packet_bytes = load_fixture()
    candidate = copy.deepcopy(report)
    candidate["sources"][0]["gitObject"] = "0" * 40

    errors = VALIDATOR.validate_report(
        candidate,
        mutated_bytes(candidate),
        packet,
        packet_bytes,
    )

    assert any("Git object differs from reuse index" in error for error in errors)


def test_observed_report_rejects_copy_or_network_widening() -> None:
    report, _, packet, packet_bytes = load_fixture()
    candidate = copy.deepcopy(report)
    candidate["isolationEvidence"]["copyAuthority"] = "COPY_AUTHORIZED"
    candidate["isolationEvidence"]["outboundDenied"] = False

    errors = VALIDATOR.validate_report(
        candidate,
        mutated_bytes(candidate),
        packet,
        packet_bytes,
    )

    assert "observation isolation evidence mismatch" in errors
