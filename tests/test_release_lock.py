from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path

import jsonschema
import pytest
import yaml


ROOT = Path(__file__).resolve().parents[1]
FIXTURE_PATH = ROOT / "release/fixture-release-set.yaml"
INERT_LOCK_PATH = ROOT / "release/repos.lock.json"


def _load_module(name: str, path: Path):
    specification = importlib.util.spec_from_file_location(name, path)
    assert specification and specification.loader
    module = importlib.util.module_from_spec(specification)
    sys.modules[name] = module
    specification.loader.exec_module(module)
    return module


CHECKER = _load_module("check_release_lock", ROOT / "scripts/check_release_lock.py")
BUILDER = _load_module("build_release_lock", ROOT / "scripts/build_release_lock.py")


def fixture_document() -> dict:
    document = yaml.safe_load(FIXTURE_PATH.read_text(encoding="utf-8"))
    assert isinstance(document, dict)
    return document


def write_yaml(path: Path, document: dict) -> None:
    path.write_text(
        yaml.safe_dump(document, sort_keys=False, width=1000),
        encoding="utf-8",
    )


def validate_mutation(tmp_path: Path, document: dict):
    path = tmp_path / "mutated-release-set.yaml"
    write_yaml(path, document)
    return CHECKER.validate_release_lock(path)


def evidence_by_axis(document: dict) -> dict[str, dict]:
    return {item["axis"]: item for item in document["releaseEvidence"]}


def test_release_schema_is_closed_draft_2020_12() -> None:
    schema = json.loads(
        (ROOT / "schemas/release-set.schema.json").read_text(encoding="utf-8")
    )
    jsonschema.Draft202012Validator.check_schema(schema)
    assert schema["$schema"] == "https://json-schema.org/draft/2020-12/schema"
    assert schema["additionalProperties"] is False


def test_canonical_lock_is_explicitly_inert() -> None:
    document, report = CHECKER.validate_release_lock(INERT_LOCK_PATH)

    assert document["documentKind"] == "INERT_LOCK"
    assert document["repositories"] == []
    assert document["releaseEvidence"] == []
    assert document["promotion"] == {
        "blockers": ["NO_PRODUCT_RELEASES_PUBLISHED"],
        "decision": "BLOCKED",
        "requiredAxes": [],
        "target": "NONE",
    }
    assert report.repositories == 0
    assert report.artifacts == 0


def test_synthetic_fixture_locks_all_repositories_and_axes() -> None:
    document, report = CHECKER.validate_release_lock(FIXTURE_PATH)

    assert document["fixtureOnly"] is True
    assert report.document_kind == "SYNTHETIC_FIXTURE"
    assert report.repositories == 13
    assert report.artifacts == 13
    assert report.target == "ARTIFACT_RELEASE"
    assert report.decision == "PASS"
    assert {
        record["repositoryId"] for record in document["repositories"]
    } == {
        "harness-engineering",
        "contracts",
        "sdks",
        "industry-packs",
        "control-plane",
        "runtime-plane",
        "model-plane",
        "knowledge-plane",
        "execution-plane",
        "trust-plane",
        "operator",
        "distribution",
        "conformance-labs",
    }
    assert set(evidence_by_axis(document)) == set(CHECKER.RELEASE_AXES)


def test_builder_is_deterministic_and_refuses_overwrite(tmp_path: Path) -> None:
    first = tmp_path / "first.json"
    second = tmp_path / "second.json"

    first_text = BUILDER.build_release_lock(FIXTURE_PATH, first)
    second_text = BUILDER.build_release_lock(FIXTURE_PATH, second)

    assert first_text == second_text
    assert first.read_bytes() == second.read_bytes()
    _, report = CHECKER.validate_release_lock(first)
    assert report.repositories == 13
    with pytest.raises(CHECKER.ReleaseLockError, match="cannot create"):
        BUILDER.build_release_lock(FIXTURE_PATH, first)


def test_mutable_repository_or_artifact_reference_is_rejected(tmp_path: Path) -> None:
    for field, value in (("releaseTag", "main"), ("artifactVersion", "latest")):
        document = fixture_document()
        if field == "releaseTag":
            document["repositories"][0]["releaseTag"] = value
        else:
            document["repositories"][0]["artifacts"][0]["version"] = value
        with pytest.raises(CHECKER.ReleaseLockError, match="mutable"):
            validate_mutation(tmp_path, document)


def test_missing_repository_or_evidence_axis_is_rejected(tmp_path: Path) -> None:
    document = fixture_document()
    document["repositories"].pop()
    with pytest.raises(CHECKER.ReleaseLockError, match="schema error"):
        validate_mutation(tmp_path, document)

    document = fixture_document()
    document["repositories"][0]["componentEvidence"] = document["repositories"][0][
        "componentEvidence"
    ][:-1]
    with pytest.raises(CHECKER.ReleaseLockError, match="schema error"):
        validate_mutation(tmp_path, document)


def test_merge_pass_does_not_imply_deployment_or_runtime(tmp_path: Path) -> None:
    document = fixture_document()
    document["promotion"] = {
        "target": "PLATFORM_DEPLOYABLE",
        "decision": "BLOCKED",
        "requiredAxes": [
            "SOURCE",
            "CI",
            "MERGE",
            "ARTIFACT",
            "SIGNATURE",
            "DEPLOYMENT",
            "RUNTIME",
        ],
        "blockers": [
            "release:DEPLOYMENT:NOT_RUN_ENV_UNAVAILABLE",
            "release:RUNTIME:NOT_RUN_ENV_UNAVAILABLE",
        ],
    }

    _, report = validate_mutation(tmp_path, document)
    assert report.decision == "BLOCKED"

    document["promotion"]["decision"] = "PASS"
    document["promotion"]["blockers"] = []
    with pytest.raises(CHECKER.ReleaseLockError, match="computed BLOCKED"):
        validate_mutation(tmp_path, document)


def test_acceptance_candidate_never_equals_tenant_acceptance(tmp_path: Path) -> None:
    document = fixture_document()
    evidence = evidence_by_axis(document)
    evidence["TENANT_ACCEPTANCE"]["status"] = "PASS"

    with pytest.raises(CHECKER.ReleaseLockError, match="lacks a passing candidate"):
        validate_mutation(tmp_path, document)

    document = fixture_document()
    evidence = evidence_by_axis(document)
    evidence["TENANT_ACCEPTANCE_CANDIDATE"]["status"] = "PASS"
    evidence["TENANT_ACCEPTANCE"]["status"] = "PASS"
    evidence["TENANT_ACCEPTANCE"]["producer"] = evidence[
        "TENANT_ACCEPTANCE_CANDIDATE"
    ]["producer"]
    with pytest.raises(CHECKER.ReleaseLockError, match="independent producers"):
        validate_mutation(tmp_path, document)


def test_evidence_digest_cannot_satisfy_different_axes(tmp_path: Path) -> None:
    document = fixture_document()
    component_evidence = document["repositories"][0]["componentEvidence"]
    component_evidence[1]["evidenceDigest"] = component_evidence[0]["evidenceDigest"]

    with pytest.raises(CHECKER.ReleaseLockError, match="reused across"):
        validate_mutation(tmp_path, document)


def test_subject_or_authority_digest_mismatch_is_rejected(tmp_path: Path) -> None:
    document = fixture_document()
    document["repositories"][0]["componentEvidence"][0]["subjectDigests"] = [
        "sha256:" + "f" * 64
    ]
    with pytest.raises(CHECKER.ReleaseLockError, match="exact subjects"):
        validate_mutation(tmp_path, document)

    document = fixture_document()
    document["evidencePolicy"]["digest"] = "sha256:" + "f" * 64
    with pytest.raises(CHECKER.ReleaseLockError, match="tracked authority"):
        validate_mutation(tmp_path, document)


def test_unknown_member_and_duplicate_yaml_key_fail_closed(tmp_path: Path) -> None:
    document = fixture_document()
    document["unexpectedAuthority"] = "forbidden"
    with pytest.raises(CHECKER.ReleaseLockError, match="schema error"):
        validate_mutation(tmp_path, document)

    duplicate = tmp_path / "duplicate.yaml"
    duplicate.write_text(
        "schemaVersion: one\nschemaVersion: two\n",
        encoding="utf-8",
    )
    with pytest.raises(CHECKER.DuplicateYamlKeyError, match="duplicate YAML key"):
        CHECKER.validate_release_lock(duplicate)


def test_future_dated_and_expired_passing_evidence_is_rejected(tmp_path: Path) -> None:
    document = fixture_document()
    document["repositories"][0]["componentEvidence"][0][
        "observedAt"
    ] = "2099-01-01T00:00:00Z"
    with pytest.raises(CHECKER.ReleaseLockError, match="future-dated"):
        validate_mutation(tmp_path, document)

    document = fixture_document()
    evidence = document["repositories"][0]["componentEvidence"][0]
    evidence["observedAt"] = "2020-01-01T00:00:00Z"
    evidence["validUntil"] = "2020-01-02T00:00:00Z"
    with pytest.raises(CHECKER.ReleaseLockError, match="expired"):
        validate_mutation(tmp_path, document)
