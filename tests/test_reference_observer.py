from __future__ import annotations

import importlib.util
import copy
import hashlib
import json
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "harness_reference_observe",
    ROOT / "reference-observer/harness-reference-observe.py",
)
assert SPEC and SPEC.loader
OBSERVER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(OBSERVER)
EXTRACT_SPEC = importlib.util.spec_from_file_location(
    "harness_reference_extract", ROOT / "reference-observer/harness-reference-extract.py"
)
assert EXTRACT_SPEC and EXTRACT_SPEC.loader
EXTRACTOR = importlib.util.module_from_spec(EXTRACT_SPEC)
EXTRACT_SPEC.loader.exec_module(EXTRACTOR)


def record(mode: str, object_type: str, object_id: str, path: str) -> bytes:
    return f"{mode} {object_type} {object_id}\t{path}\0".encode()


def test_git_tree_traversal_is_canonicalized_by_path() -> None:
    raw = b"".join(
        [
            record("040000", "tree", "b" * 40, "src"),
            record("100644", "blob", "c" * 40, "src/main.py"),
            record("100644", "blob", "a" * 40, "README.md"),
        ]
    )
    assert [item["path"] for item in OBSERVER._parse_tracked_tree(raw)] == [
        "README.md",
        "src",
        "src/main.py",
    ]


@pytest.mark.parametrize(
    "raw",
    [
        b"",
        record("100644", "blob", "a" * 40, "../escape"),
        record("100644", "blob", "a" * 40, "same")
        + record("100644", "blob", "b" * 40, "same"),
        b"malformed\0",
    ],
)
def test_git_tree_parser_rejects_empty_unsafe_duplicate_or_malformed(raw: bytes) -> None:
    with pytest.raises(OBSERVER.LauncherError):
        OBSERVER._parse_tracked_tree(raw)


def model_authority():
    return {
        "packetId": "MET-OBS-MODEL-001",
        "repository": "git@github.com:caglarsubas/llm_inference_engine.git",
        "commit": "6815c21cb10a4d7dc0b4804f6bb223afb4321e97",
        "packetObservation": {
            "repository": "git@github.com:caglarsubas/llm_inference_engine.git",
            "commit": "6815c21cb10a4d7dc0b4804f6bb223afb4321e97",
            "sourcePaths": ["contracts/prometa-model-usage-v2.schema.json"],
            "outputPath": "architecture/observations/model-usage-v2.json",
        },
    }


def test_schema_report_names_preserve_history_and_separate_model_observation():
    assert EXTRACTOR._schema_observation_id({"packetId": "MET-002"}) == "data-harness-v1-structural-facts"
    authority = model_authority()
    original = copy.deepcopy(authority)
    assert EXTRACTOR._schema_observation_id(authority) == "model-usage-v2-structural-facts"
    assert authority == original


@pytest.mark.parametrize("field,value", [
    ("repository", "unapproved"), ("commit", "0" * 40),
    ("sourcePaths", ["tests/test_scheduler.py"]),
    ("outputPath", "architecture/observations/data-harness-v1.json"),
])
def test_model_schema_name_rejects_substituted_authority(field, value):
    authority = model_authority()
    authority["packetObservation"][field] = value
    with pytest.raises(EXTRACTOR.ObservationError):
        EXTRACTOR._schema_observation_id(authority)


def test_unknown_schema_packet_is_not_data_observation():
    with pytest.raises(EXTRACTOR.ObservationError):
        EXTRACTOR._schema_observation_id({"packetId": "UNAPPROVED-001"})


def test_synthetic_model_schema_report_has_facts_not_prose_or_test_results(tmp_path):
    # Entirely new synthetic JSON, never a warm-source fixture or observation.
    authority = model_authority()
    relative = authority["packetObservation"]["sourcePaths"][0]
    target = tmp_path / relative
    target.parent.mkdir()
    data = json.dumps({
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": "urn:synthetic:model-usage-test",
        "type": "object", "required": ["synthetic_count"],
        "properties": {"synthetic_count": {"type": "integer", "minimum": 0}},
        "description": "PROSE_MUST_NOT_APPEAR", "examples": [{"synthetic_count": 9}],
    }).encode()
    target.write_bytes(data)
    authority["sourceBindings"] = [{"path": relative, "gitObject": EXTRACTOR._git_blob_oid(data)}]
    report = EXTRACTOR._schema_report(authority, tmp_path, 1)
    assert report["observationId"] == "model-usage-v2-structural-facts"
    assert report["sources"][0]["sha256"] == hashlib.sha256(data).hexdigest()
    assert any(fact["kind"] == "REQUIRED_FIELD" for fact in report["facts"])
    encoded = json.dumps(report)
    assert "PROSE_MUST_NOT_APPEAR" not in encoded
    assert "examples" not in encoded
    assert "testResults" not in encoded
    assert str(tmp_path) not in encoded
    assert report["isolationEvidence"]["sourceCodeExecution"] == "DENIED"


def test_unknown_schema_authority_rejected_before_any_blob_read(tmp_path, monkeypatch):
    def unexpected_read(_):
        pytest.fail("unknown authority reached a source read")
    monkeypatch.setattr(EXTRACTOR, "_read_regular_file", unexpected_read)
    with pytest.raises(EXTRACTOR.ObservationError):
        EXTRACTOR._schema_report({"packetId": "UNAPPROVED-001"}, tmp_path, 1)
