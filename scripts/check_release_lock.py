#!/usr/bin/env python3
"""Validate one immutable cross-repository release lock without network access."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import jsonschema
import yaml


ROOT = Path(__file__).resolve().parents[1]
SCHEMA_PATH = ROOT / "schemas/release-set.schema.json"
POLICY_PATH = ROOT / "release/evidence-policy.yaml"
REGISTRY_PATH = ROOT / "architecture/repositories.yaml"

COMPONENT_AXES = ["SOURCE", "CI", "MERGE", "ARTIFACT", "SIGNATURE"]
RELEASE_AXES = [
    "DEPLOYMENT",
    "RUNTIME",
    "SECURITY",
    "ASSURANCE",
    "TENANT_ACCEPTANCE_CANDIDATE",
    "TENANT_ACCEPTANCE",
]
NON_PASSING_STATES = [
    "MISSING",
    "COLLECTING",
    "WARN",
    "FAIL",
    "NOT_APPLICABLE",
    "NOT_RUN_ENV_UNAVAILABLE",
    "STALE",
    "WAIVED",
    "PENDING",
    "REJECTED",
]
PROMOTION_GATES = {
    "NONE": {"componentAxes": [], "releaseAxes": []},
    "ARTIFACT_RELEASE": {
        "componentAxes": COMPONENT_AXES,
        "releaseAxes": [],
    },
    "PLATFORM_DEPLOYABLE": {
        "componentAxes": COMPONENT_AXES,
        "releaseAxes": ["DEPLOYMENT", "RUNTIME"],
    },
    "PLATFORM_CERTIFIED": {
        "componentAxes": COMPONENT_AXES,
        "releaseAxes": ["DEPLOYMENT", "RUNTIME", "SECURITY", "ASSURANCE"],
    },
    "TENANT_ACCEPTED": {
        "componentAxes": COMPONENT_AXES,
        "releaseAxes": RELEASE_AXES,
    },
}
MUTABLE_TOKEN = re.compile(
    r"(?:^|[/:@._+-])(?:latest|main|master|head|nightly|edge|snapshot)(?:$|[/:@._+-])",
    re.IGNORECASE,
)


class ReleaseLockError(ValueError):
    """The release lock or one of its pinned authorities failed closed."""


class DuplicateJsonKeyError(ReleaseLockError):
    """A JSON object repeated a member name."""


class DuplicateYamlKeyError(ReleaseLockError):
    """A YAML mapping repeated a key."""


class UniqueKeySafeLoader(yaml.SafeLoader):
    """PyYAML loader that rejects ambiguous mappings."""


def _construct_unique_mapping(
    loader: UniqueKeySafeLoader,
    node: yaml.MappingNode,
    deep: bool = False,
) -> dict[Any, Any]:
    loader.flatten_mapping(node)
    result: dict[Any, Any] = {}
    for key_node, value_node in node.value:
        key = loader.construct_object(key_node, deep=deep)
        if key in result:
            raise DuplicateYamlKeyError(
                f"duplicate YAML key {key!r} at line {key_node.start_mark.line + 1}"
            )
        result[key] = loader.construct_object(value_node, deep=deep)
    return result


UniqueKeySafeLoader.add_constructor(
    yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG,
    _construct_unique_mapping,
)


def _unique_json_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise DuplicateJsonKeyError(f"duplicate JSON key {key!r}")
        result[key] = value
    return result


def load_document(path: Path) -> dict[str, Any]:
    """Load JSON or YAML as a closed mapping with duplicate-key rejection."""

    try:
        text = path.read_text(encoding="utf-8")
    except OSError as exc:
        raise ReleaseLockError(f"cannot read {path}: {exc}") from exc
    try:
        if path.suffix.casefold() == ".json":
            value = json.loads(text, object_pairs_hook=_unique_json_object)
        else:
            value = yaml.load(text, Loader=UniqueKeySafeLoader)
    except (json.JSONDecodeError, yaml.YAMLError) as exc:
        raise ReleaseLockError(f"cannot parse {path}: {exc}") from exc
    if not isinstance(value, dict):
        raise ReleaseLockError(f"{path} must contain one mapping")
    return value


def sha256_reference(path: Path) -> str:
    digest = hashlib.sha256()
    try:
        with path.open("rb") as stream:
            for block in iter(lambda: stream.read(1024 * 1024), b""):
                digest.update(block)
    except OSError as exc:
        raise ReleaseLockError(f"cannot hash {path}: {exc}") from exc
    return f"sha256:{digest.hexdigest()}"


def _parse_time(value: str, label: str) -> datetime:
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ReleaseLockError(f"{label} is not RFC 3339 date-time") from exc
    if parsed.tzinfo is None:
        raise ReleaseLockError(f"{label} must include a timezone")
    return parsed.astimezone(UTC)


def _validate_policy(policy: dict[str, Any]) -> None:
    expected_keys = {"schemaVersion", "states", "scopes", "promotionGates", "rules"}
    if set(policy) != expected_keys:
        raise ReleaseLockError("evidence policy members are not closed")
    if policy.get("schemaVersion") != "harness.planeon.ai/release-evidence-policy/v1":
        raise ReleaseLockError("evidence policy schemaVersion is not v1")
    if policy.get("states") != {
        "passing": ["PASS"],
        "nonPassing": NON_PASSING_STATES,
    }:
        raise ReleaseLockError("evidence states do not preserve the closed PASS boundary")
    if policy.get("scopes") != {
        "component": COMPONENT_AXES,
        "release": RELEASE_AXES,
    }:
        raise ReleaseLockError("evidence axes or scopes are incomplete")
    if policy.get("promotionGates") != PROMOTION_GATES:
        raise ReleaseLockError("promotion gates do not match the closed evidence ladder")

    required_rules = {
        "failClosed": True,
        "exactAxisCoverageRequired": True,
        "evidenceDigestMaySatisfyOnlyOneAxis": True,
        "subjectDigestBindingRequired": True,
        "passingState": "PASS",
        "unavailableState": "NOT_RUN_ENV_UNAVAILABLE",
        "unavailableNeverPasses": True,
        "notApplicableNeverPassesByDefault": True,
        "warningNeverPasses": True,
        "waiverNeverPasses": True,
        "staleNeverPasses": True,
        "candidateNeverEqualsTenantAcceptance": True,
        "tenantAcceptanceRequiresCandidatePass": True,
        "tenantAcceptanceRequiresIndependentProducer": True,
        "futureDatedEvidenceRejected": True,
        "expiredEvidenceRejectedForPromotion": True,
        "sourceDoesNotImplyCI": True,
        "ciDoesNotImplyMerge": True,
        "mergeDoesNotImplyArtifact": True,
        "artifactDoesNotImplySignature": True,
        "signatureDoesNotImplyDeployment": True,
        "deploymentDoesNotImplyRuntime": True,
        "runtimeDoesNotImplySecurity": True,
        "securityDoesNotImplyAssurance": True,
        "assuranceDoesNotImplyTenantAcceptanceCandidate": True,
        "tenantAcceptanceCandidateDoesNotImplyTenantAcceptance": True,
        "sourceCiMergeArtifactSignatureAreComponentScoped": True,
        "deploymentRuntimeSecurityAssuranceAreEnvironmentScoped": True,
        "tenantAcceptanceIsTenantEnvironmentReleaseScoped": True,
    }
    if policy.get("rules") != required_rules:
        raise ReleaseLockError("evidence policy rules are missing, widened, or reordered")


def _schema_validator() -> jsonschema.Draft202012Validator:
    schema = load_document(SCHEMA_PATH)
    try:
        jsonschema.Draft202012Validator.check_schema(schema)
    except jsonschema.SchemaError as exc:
        raise ReleaseLockError(f"release-set schema is invalid: {exc.message}") from exc
    return jsonschema.Draft202012Validator(
        schema,
        format_checker=jsonschema.FormatChecker(),
    )


def _validate_evidence_record(
    record: dict[str, Any],
    *,
    expected_subjects: set[str],
    now: datetime,
    required_for_promotion: bool,
    evidence_axis_by_digest: dict[str, str],
) -> None:
    axis = record["axis"]
    if set(record["subjectDigests"]) != expected_subjects:
        raise ReleaseLockError(f"{axis} evidence is not bound to its exact subjects")
    digest = record["evidenceDigest"]
    previous_axis = evidence_axis_by_digest.setdefault(digest, axis)
    if previous_axis != axis:
        raise ReleaseLockError(
            f"evidence digest {digest} is reused across {previous_axis} and {axis}"
        )

    observed = _parse_time(record["observedAt"], f"{axis}.observedAt")
    valid_until = _parse_time(record["validUntil"], f"{axis}.validUntil")
    if valid_until <= observed:
        raise ReleaseLockError(f"{axis} evidence validity does not follow observation")
    if observed > now + timedelta(minutes=5):
        raise ReleaseLockError(f"{axis} evidence is future-dated")
    if required_for_promotion and record["status"] == "PASS" and valid_until <= now:
        raise ReleaseLockError(f"required {axis} PASS evidence is expired")


@dataclass(frozen=True)
class ReleaseLockReport:
    document_kind: str
    repositories: int
    artifacts: int
    target: str
    decision: str
    lock_digest: str

    def render(self) -> str:
        return (
            "release lock validation passed: "
            f"kind={self.document_kind} repositories={self.repositories} "
            f"artifacts={self.artifacts} target={self.target} "
            f"decision={self.decision} digest={self.lock_digest}"
        )


def validate_release_lock(path: Path) -> tuple[dict[str, Any], ReleaseLockReport]:
    """Validate a release lock and return its parsed form plus deterministic report."""

    document = load_document(path)
    validator = _schema_validator()
    errors = sorted(
        validator.iter_errors(document),
        key=lambda error: tuple(str(part) for part in error.absolute_path),
    )
    if errors:
        error = errors[0]
        raise ReleaseLockError(
            f"release lock schema error at {list(error.absolute_path)}: {error.message}"
        )

    policy = load_document(POLICY_PATH)
    _validate_policy(policy)
    expected_authorities = {
        "repositoryRegistry": sha256_reference(REGISTRY_PATH),
        "evidencePolicy": sha256_reference(POLICY_PATH),
    }
    for field, expected_digest in expected_authorities.items():
        if document[field]["digest"] != expected_digest:
            raise ReleaseLockError(f"{field} digest does not match tracked authority")

    generated_at = _parse_time(document["generatedAt"], "generatedAt")
    now = datetime.now(UTC)
    if generated_at > now + timedelta(minutes=5):
        raise ReleaseLockError("release lock is future-dated")

    target = document["promotion"]["target"]
    decision = document["promotion"]["decision"]
    if document["documentKind"] == "INERT_LOCK":
        expected_blockers = ["NO_PRODUCT_RELEASES_PUBLISHED"]
        if document["promotion"]["blockers"] != expected_blockers:
            raise ReleaseLockError("inert lock must preserve the no-product-release blocker")
        return document, ReleaseLockReport(
            document_kind="INERT_LOCK",
            repositories=0,
            artifacts=0,
            target=target,
            decision=decision,
            lock_digest=sha256_reference(path),
        )

    registry = load_document(REGISTRY_PATH)
    expected_repositories = {
        repository["id"]: repository["name"]
        for repository in registry.get("repositories", [])
    }
    if len(expected_repositories) != 13:
        raise ReleaseLockError("repository registry no longer contains exactly 13 entries")

    repository_records = document["repositories"]
    actual_repositories = {
        record["repositoryId"]: record["repositoryName"]
        for record in repository_records
    }
    if len(actual_repositories) != len(repository_records):
        raise ReleaseLockError("release lock repeats a repository ID")
    if actual_repositories != expected_repositories:
        raise ReleaseLockError("release lock does not cover the exact repository registry")

    if document["documentKind"] == "SYNTHETIC_FIXTURE":
        searchable = "\n".join(
            [document["releaseId"], *document["notices"]]
            + [record["releaseTag"] for record in repository_records]
        ).casefold()
        if "synthetic" not in searchable or "fixture" not in searchable:
            raise ReleaseLockError("synthetic fixture is not unmistakably labeled")
    elif "fixture" in json.dumps(document, sort_keys=True).casefold():
        raise ReleaseLockError("a real release lock contains fixture claims")

    expected_required_axes = [
        *PROMOTION_GATES[target]["componentAxes"],
        *PROMOTION_GATES[target]["releaseAxes"],
    ]
    if document["promotion"]["requiredAxes"] != expected_required_axes:
        raise ReleaseLockError("promotion requiredAxes do not match evidence policy")

    evidence_axis_by_digest: dict[str, str] = {}
    artifact_ids: set[str] = set()
    artifact_digests: set[str] = set()
    blockers: list[str] = []
    artifact_count = 0
    for record in repository_records:
        repository_id = record["repositoryId"]
        if MUTABLE_TOKEN.search(record["releaseTag"]):
            raise ReleaseLockError(
                f"repository {repository_id} uses mutable release reference "
                f"{record['releaseTag']!r}"
            )
        artifacts = record["artifacts"]
        component_subjects = {artifact["digest"] for artifact in artifacts}
        if len(component_subjects) != len(artifacts):
            raise ReleaseLockError(f"repository {repository_id} repeats an artifact digest")
        for artifact in artifacts:
            artifact_count += 1
            if MUTABLE_TOKEN.search(artifact["version"]):
                raise ReleaseLockError(
                    f"artifact {artifact['artifactId']} uses mutable version {artifact['version']!r}"
                )
            if artifact["artifactId"] in artifact_ids:
                raise ReleaseLockError(f"duplicate artifact ID {artifact['artifactId']}")
            if artifact["digest"] in artifact_digests:
                raise ReleaseLockError(f"duplicate artifact digest {artifact['digest']}")
            artifact_ids.add(artifact["artifactId"])
            artifact_digests.add(artifact["digest"])
            digests = {
                artifact["digest"],
                artifact["sbomDigest"],
                artifact["licenseDigest"],
                artifact["signatureDigest"],
            }
            if len(digests) != 4:
                raise ReleaseLockError(
                    f"artifact {artifact['artifactId']} conflates content, SBOM, license, or signature"
                )

        component_evidence = {
            item["axis"]: item for item in record["componentEvidence"]
        }
        for axis in COMPONENT_AXES:
            evidence = component_evidence[axis]
            expected_subjects = (
                {record["sourceTreeDigest"]}
                if axis in {"SOURCE", "CI", "MERGE"}
                else component_subjects
            )
            required = axis in PROMOTION_GATES[target]["componentAxes"]
            _validate_evidence_record(
                evidence,
                expected_subjects=expected_subjects,
                now=now,
                required_for_promotion=required,
                evidence_axis_by_digest=evidence_axis_by_digest,
            )
            if required and evidence["status"] != "PASS":
                blockers.append(f"{repository_id}:{axis}:{evidence['status']}")

    bundle = document["bundle"]
    assert isinstance(bundle, dict)
    bundle_digests = {
        bundle["digest"],
        bundle["sbomDigest"],
        bundle["licenseDigest"],
        bundle["signatureDigest"],
    }
    if len(bundle_digests) != 4:
        raise ReleaseLockError("bundle conflates content, SBOM, license, or signature")
    if MUTABLE_TOKEN.search(bundle["version"]):
        raise ReleaseLockError(f"bundle uses mutable version {bundle['version']!r}")

    release_evidence = {item["axis"]: item for item in document["releaseEvidence"]}
    for axis in RELEASE_AXES:
        evidence = release_evidence[axis]
        required = axis in PROMOTION_GATES[target]["releaseAxes"]
        _validate_evidence_record(
            evidence,
            expected_subjects={bundle["digest"]},
            now=now,
            required_for_promotion=required,
            evidence_axis_by_digest=evidence_axis_by_digest,
        )
        if required and evidence["status"] != "PASS":
            blockers.append(f"release:{axis}:{evidence['status']}")

    tenant_candidate = release_evidence["TENANT_ACCEPTANCE_CANDIDATE"]
    tenant_acceptance = release_evidence["TENANT_ACCEPTANCE"]
    if tenant_acceptance["status"] == "PASS":
        if tenant_candidate["status"] != "PASS":
            raise ReleaseLockError("tenant acceptance PASS lacks a passing candidate")
        if tenant_acceptance["producer"] == tenant_candidate["producer"]:
            raise ReleaseLockError(
                "tenant acceptance and its candidate require independent producers"
            )

    expected_decision = "PASS" if not blockers else "BLOCKED"
    if decision != expected_decision:
        raise ReleaseLockError(
            f"promotion decision {decision} does not match computed {expected_decision}"
        )
    if document["promotion"]["blockers"] != sorted(blockers):
        raise ReleaseLockError("promotion blockers do not match independently computed blockers")

    return document, ReleaseLockReport(
        document_kind=document["documentKind"],
        repositories=len(repository_records),
        artifacts=artifact_count,
        target=target,
        decision=decision,
        lock_digest=sha256_reference(path),
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("release_lock", type=Path)
    arguments = parser.parse_args(argv)
    try:
        _, report = validate_release_lock(arguments.release_lock)
    except (ReleaseLockError, jsonschema.ValidationError) as exc:
        print(f"release lock validation failed: {exc}", file=sys.stderr)
        return 2
    print(report.render())
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
