#!/usr/bin/env python3
"""Validate the MET-002 reference-only source and porting authorities."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from dataclasses import dataclass
from importlib.metadata import PackageNotFoundError, version
from pathlib import Path, PurePosixPath
from typing import Any

import jsonschema
import yaml


ROOT = Path(__file__).resolve().parents[1]

EXPECTED_PACKAGES = {
    "PyYAML": "6.0.2",
    "jsonschema": "4.24.0",
    "pytest": "8.4.2",
}

EXPECTED_PUBLIC_SOURCES = {
    "git@github.com:caglarsubas/llm_inference_engine.git": {
        "commit": "6815c21cb10a4d7dc0b4804f6bb223afb4321e97",
        "destinations": [
            "contracts",
            "model-plane",
            "runtime-plane",
            "trust-plane",
            "distribution",
            "conformance-labs",
        ],
        "excluded": [
            "openrouter",
            "tunnels",
            "hosted-endpoints",
            "ghcr",
            "runtime-model-downloads",
        ],
        "excludedPathPatterns": [
            r"(?i)(^|[/_\\.-])(openrouter|tunnel|hosted[_-]?provider|hosted[_-]?endpoint)([/_\\.-]|$)"
        ],
        "records": {"TREE_DISCOVERY": 8, "BLOB_PENDING": 204},
    },
    "git@github.com:caglarsubas/data-source-harness.git": {
        "commit": "858281f4b845ffacfe05cdb2c40a402c237d4c54",
        "destinations": [
            "contracts",
            "knowledge-plane",
            "execution-plane",
            "trust-plane",
            "industry-packs",
            "distribution",
            "conformance-labs",
        ],
        "excluded": [
            "hmac-production-signing",
            "fused-retrieval-memory-runtime-state",
        ],
        "excludedPathPatterns": [r"(?i)(^|[/_\\.-])hmac([^/_\\.-]*)([/_\\.-]|$)"],
        "records": {"TREE_DISCOVERY": 12, "BLOB_PENDING": 311},
    },
}

EXPECTED_NON_PUBLIC_INPUTS = {
    "count": 3,
    "disposition": "METADATA_OMITTED_FROM_PUBLIC_REPOSITORY",
    "implementationAccess": "PROHIBITED",
    "requirementDisposition": "DISTILLED_INTO_INDEPENDENT_PUBLIC_CONTRACTS_AND_ACCEPTANCE_CRITERIA",
    "copyAuthorization": "NONE",
}

EXPECTED_CURRENT_INVENTORY = {
    "treeDiscoveryRecords": 20,
    "blobPendingRecords": 515,
    "blobCopyAuthorizedRecords": 0,
    "portingAuthorizationRecords": 0,
}

AUTHORITY_PATHS = (
    "architecture/reuse-map.yaml",
    "architecture/reuse-map.schema.json",
    "architecture/reuse-path-index.yaml",
    "architecture/porting-authorization-index.yaml",
    "schemas/reuse-path-index.schema.json",
    "schemas/porting-authorization.schema.json",
    "schemas/porting-record.schema.json",
    "legal/source-reuse-authorization.yaml",
    "legal/third-party-license-policy.yaml",
)

SHA1_PATTERN = re.compile(r"^[0-9a-f]{40}$")


class ReuseValidationError(ValueError):
    """A MET-002 authority is malformed or makes an unsupported reuse claim."""


class DuplicateYamlKeyError(ReuseValidationError):
    """A YAML authority repeats a mapping key."""


class DuplicateJsonKeyError(ReuseValidationError):
    """A JSON authority repeats an object key."""


class UniqueKeySafeLoader(yaml.SafeLoader):
    """PyYAML safe loader that refuses duplicate mapping keys."""


def _construct_unique_yaml_mapping(
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
    _construct_unique_yaml_mapping,
)


def _unique_json_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise DuplicateJsonKeyError(f"duplicate JSON key {key!r}")
        result[key] = value
    return result


def load_yaml(path: Path) -> dict[str, Any]:
    try:
        with path.open("r", encoding="utf-8") as stream:
            value = yaml.load(stream, Loader=UniqueKeySafeLoader)
    except (OSError, yaml.YAMLError) as exc:
        raise ReuseValidationError(f"cannot read YAML authority {path}: {exc}") from exc
    if not isinstance(value, dict):
        raise ReuseValidationError(f"YAML authority must be a mapping: {path}")
    return value


def load_json(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(
            path.read_text(encoding="utf-8"),
            object_pairs_hook=_unique_json_object,
        )
    except (OSError, json.JSONDecodeError) as exc:
        raise ReuseValidationError(f"cannot read JSON authority {path}: {exc}") from exc
    if not isinstance(value, dict):
        raise ReuseValidationError(f"JSON authority must be an object: {path}")
    return value


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise ReuseValidationError(message)


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    try:
        with path.open("rb") as stream:
            for block in iter(lambda: stream.read(1024 * 1024), b""):
                digest.update(block)
    except OSError as exc:
        raise ReuseValidationError(f"cannot hash authority {path}: {exc}") from exc
    return digest.hexdigest()


def _validate_toolchain() -> None:
    _require(
        sys.version_info[:2] == (3, 12),
        f"Python 3.12 required, found {sys.version.split()[0]}",
    )
    for package, expected in EXPECTED_PACKAGES.items():
        try:
            actual = version(package)
        except PackageNotFoundError as exc:
            raise ReuseValidationError(f"required package is missing: {package}") from exc
        _require(actual == expected, f"{package}=={expected} required, found {actual}")


def _validate_schema(
    instance: Any,
    schema_path: Path,
    label: str,
) -> dict[str, Any]:
    schema = load_json(schema_path)
    try:
        jsonschema.Draft202012Validator.check_schema(schema)
        validator = jsonschema.Draft202012Validator(
            schema,
            format_checker=jsonschema.FormatChecker(),
        )
    except jsonschema.SchemaError as exc:
        raise ReuseValidationError(f"{label} schema is invalid: {exc.message}") from exc
    errors = sorted(
        validator.iter_errors(instance),
        key=lambda error: tuple(str(part) for part in error.absolute_path),
    )
    if errors:
        error = errors[0]
        location = "/".join(str(part) for part in error.absolute_path) or "<root>"
        raise ReuseValidationError(
            f"{label} schema violation at {location}: {error.message}"
        )
    return schema


def _safe_relative_path(path: str, *, tree: bool) -> bool:
    if not path or path.startswith("/") or "\\" in path:
        return False
    normalized = path[:-1] if tree and path.endswith("/") else path
    if not normalized or PurePosixPath(normalized).is_absolute():
        return False
    if any(part in {"", ".", ".."} for part in PurePosixPath(normalized).parts):
        return False
    return path.endswith("/") if tree else not path.endswith("/")


def _validate_reuse_map(root: Path) -> tuple[dict[str, dict[str, Any]], int]:
    reuse_map = load_yaml(root / "architecture/reuse-map.yaml")
    _validate_schema(
        reuse_map,
        root / "architecture/reuse-map.schema.json",
        "reuse map",
    )
    sources = reuse_map.get("sources")
    _require(isinstance(sources, list), "reuse map sources must be a list")
    source_by_repository = {
        source.get("repository"): source
        for source in sources
        if isinstance(source, dict)
    }
    _require(
        len(sources) == len(source_by_repository) == 2
        and set(source_by_repository) == set(EXPECTED_PUBLIC_SOURCES),
        "reuse map must contain exactly the two approved public SHA-pinned sources",
    )
    for repository, expected in EXPECTED_PUBLIC_SOURCES.items():
        source = source_by_repository[repository]
        _require(
            source
            == {
                "repository": repository,
                "commit": expected["commit"],
                "licenseDisposition": "path-review-required-before-copy",
                "destinations": expected["destinations"],
                "excluded": expected["excluded"],
                "excludedPathPatterns": expected["excludedPathPatterns"],
            },
            f"reuse source contract changed for {repository}",
        )
        for pattern in source["excludedPathPatterns"]:
            try:
                re.compile(pattern)
            except re.error as exc:
                raise ReuseValidationError(
                    f"reuse source {repository} has invalid exclusion pattern: {exc}"
                ) from exc
    _require(
        reuse_map.get("nonPublicPlanningInputs") == EXPECTED_NON_PUBLIC_INPUTS,
        "non-public planning inputs must remain metadata-omitted and inaccessible",
    )
    _require(
        reuse_map.get("pathAuthority") == "architecture/reuse-path-index.yaml"
        and reuse_map.get("authorizationAuthority")
        == "legal/source-reuse-authorization.yaml",
        "reuse map authority links changed",
    )
    return source_by_repository, 2 + EXPECTED_NON_PUBLIC_INPUTS["count"]


def _validate_path_index(
    root: Path,
    source_by_repository: dict[str, dict[str, Any]],
) -> dict[tuple[str, str], dict[str, Any]]:
    index = load_yaml(root / "architecture/reuse-path-index.yaml")
    _validate_schema(
        index,
        root / "schemas/reuse-path-index.schema.json",
        "reuse path index",
    )
    _require(
        index.get("generatedFrom")
        == "94 task packets; all current source paths are reference-only and validation status is reported separately",
        "reuse path index generation statement changed",
    )
    _require(
        index.get("defaultReuseDisposition")
        == "REFERENCE_ONLY_PENDING_PATH_REVIEW"
        and index.get("copyAuthorizationDisposition") == "COPY_AUTHORIZED",
        "reuse path index disposition contract changed",
    )
    sources = index.get("sources")
    _require(isinstance(sources, list), "reuse path index sources must be a list")
    indexed_sources = {
        source.get("repository"): source
        for source in sources
        if isinstance(source, dict)
    }
    _require(
        len(sources) == len(indexed_sources) == 2
        and set(indexed_sources) == set(EXPECTED_PUBLIC_SOURCES),
        "reuse path index public source set changed",
    )

    indexed_paths: dict[tuple[str, str], dict[str, Any]] = {}
    record_counts = {
        "TREE_DISCOVERY": 0,
        "BLOB_PENDING": 0,
        "BLOB_COPY_AUTHORIZED": 0,
    }
    for repository, expected in EXPECTED_PUBLIC_SOURCES.items():
        source = indexed_sources[repository]
        _require(
            source.get("commit") == expected["commit"],
            f"reuse path source commit changed for {repository}",
        )
        _require(
            source.get("licenseDisposition")
            == source_by_repository[repository]["licenseDisposition"]
            == "path-review-required-before-copy"
            and source.get("authorization")
            == "recorded-repository-scope-authorization",
            f"reuse path source {repository} overstates authorization",
        )
        paths = source.get("paths")
        _require(isinstance(paths, list), f"reuse path source {repository} paths must be a list")
        path_names = [entry.get("path") for entry in paths if isinstance(entry, dict)]
        _require(
            len(path_names) == len(paths) == len(set(path_names)),
            f"reuse path source {repository} has duplicate or malformed paths",
        )
        _require(path_names == sorted(path_names), f"reuse path source {repository} is not deterministic")
        source_counts = {"TREE_DISCOVERY": 0, "BLOB_PENDING": 0}
        for entry in paths:
            path = entry["path"]
            record_type = entry["recordType"]
            kind = entry["kind"]
            _require(
                SHA1_PATTERN.fullmatch(str(entry.get("gitObject", ""))) is not None,
                f"reuse path {(repository, path)} lacks an immutable Git object",
            )
            _require(
                _safe_relative_path(path, tree=kind == "tree"),
                f"reuse path {(repository, path)} is not a safe relative {kind} path",
            )
            key = (repository, path)
            _require(key not in indexed_paths, f"duplicate reuse path {key}")
            if kind == "tree":
                _require(
                    record_type == "TREE_DISCOVERY"
                    and entry.get("useModes") == ["DISCOVERY_ONLY"]
                    and entry.get("reuseDisposition") == "DISCOVERY_ONLY"
                    and entry.get("eligibleForCopyAuthorization") is False
                    and entry.get("requiredBeforeCopy")
                    == ["replaceWithExactIndexedBlobs"],
                    f"reuse tree {key} is not discovery-only",
                )
            else:
                _require(
                    kind == "blob"
                    and record_type == "BLOB_PENDING"
                    and entry.get("useModes") == ["REFERENCE_ONLY"]
                    and entry.get("reuseDisposition")
                    == "REFERENCE_ONLY_PENDING_PATH_REVIEW"
                    and entry.get("eligibleForCopyAuthorization") is True,
                    f"reuse blob {key} is not pending path review",
                )
                _require(
                    entry.get("requiredBeforeCopy")
                    == [
                        "ownerOrLicenseGrantEvidenceRecorded",
                        "spdxDispositionRecorded",
                        "thirdPartyAndGeneratedContentReviewed",
                        "excludedFeatureScanPassed",
                        "portingRecordPrepared",
                    ],
                    f"reuse blob {key} promotion gates changed",
                )
            _require(
                entry.get("ownershipEvidence")
                == {
                    "status": "REPOSITORY_SCOPE_CONSENT_ONLY",
                    "authority": "legal/source-reuse-authorization.yaml",
                    "authorshipClaim": "NONE",
                },
                f"reuse path {key} overstates ownership evidence",
            )
            _require(
                entry.get("licenseEvidence")
                == {
                    "status": "NOT_YET_VERIFIED",
                    "authority": "legal/third-party-license-policy.yaml",
                    "inferredFromRepositoryOwnership": False,
                },
                f"reuse path {key} infers or overstates license evidence",
            )
            for pattern in source_by_repository[repository]["excludedPathPatterns"]:
                _require(
                    re.search(pattern, path) is None,
                    f"reuse path {key} matches prohibited source feature pattern",
                )
            source_counts[record_type] += 1
            record_counts[record_type] += 1
            indexed_paths[key] = entry
        _require(
            source_counts == expected["records"],
            f"reuse path source counts changed for {repository}: {source_counts}",
        )
    _require(
        record_counts
        == {
            "TREE_DISCOVERY": 20,
            "BLOB_PENDING": 515,
            "BLOB_COPY_AUTHORIZED": 0,
        }
        and len(indexed_paths) == 535,
        f"reuse path inventory changed: {record_counts}",
    )
    return indexed_paths


def _validate_task_packet_closure(
    root: Path,
    indexed_paths: dict[tuple[str, str], dict[str, Any]],
) -> int:
    packet_paths = sorted((root / "task-packets").glob("*.yaml"))
    _require(len(packet_paths) == 94, f"expected 94 task packets, found {len(packet_paths)}")
    referenced: set[tuple[str, str]] = set()
    for packet_path in packet_paths:
        packet = load_yaml(packet_path)
        packet_id = packet.get("id")
        for source in packet.get("sourceReuse", []):
            _require(isinstance(source, dict), f"packet {packet_id} has malformed sourceReuse")
            repository = source.get("repository")
            _require(repository in EXPECTED_PUBLIC_SOURCES, f"packet {packet_id} cites an unknown public source")
            _require(
                source.get("commit") == EXPECTED_PUBLIC_SOURCES[repository]["commit"],
                f"packet {packet_id} cites a mutable or wrong source commit",
            )
            reuse_mode = source.get("reuseMode")
            _require(
                reuse_mode in {"DISCOVERY_ONLY", "REFERENCE_ONLY"},
                f"packet {packet_id} contains forbidden current reuse mode {reuse_mode!r}",
            )
            strategy = str(source.get("strategy", "")).casefold()
            _require(
                "implementation access" in strategy and "forbidden" in strategy,
                f"packet {packet_id} source strategy does not prohibit implementation access",
            )
            paths = source.get("paths")
            _require(
                isinstance(paths, list)
                and paths
                and all(isinstance(path, str) and path for path in paths)
                and len(paths) == len(set(paths)),
                f"packet {packet_id} source paths are empty, duplicated, or malformed",
            )
            for path in paths:
                key = (repository, path)
                _require(key in indexed_paths, f"packet {packet_id} cites unindexed source path {key}")
                expected_record = (
                    "TREE_DISCOVERY" if reuse_mode == "DISCOVERY_ONLY" else "BLOB_PENDING"
                )
                _require(
                    indexed_paths[key].get("recordType") == expected_record,
                    f"packet {packet_id} source mode conflicts with indexed path {key}",
                )
                referenced.add(key)
    _require(
        referenced == set(indexed_paths),
        "reuse path index must exactly equal the task-packet source reference closure",
    )
    return len(packet_paths)


def _validate_authorization_protocol(root: Path) -> tuple[dict[str, Any], dict[str, Any]]:
    authorization_index = load_yaml(root / "architecture/porting-authorization-index.yaml")
    authorization_schema = _validate_schema(
        authorization_index,
        root / "schemas/porting-authorization.schema.json",
        "porting authorization index",
    )
    _require(
        authorization_index
        == {
            "schemaVersion": "harness.planeon.ai/porting-authorization-index/v1alpha1",
            "status": "DISABLED_FAIL_CLOSED",
            "admissionEnabled": False,
            "authorizations": [],
        },
        "porting authorization index must remain disabled and empty",
    )
    _require(
        authorization_schema.get("properties", {})
        .get("authorizations", {})
        .get("maxItems")
        == 0,
        "current porting authorization schema does not reject every authorization",
    )
    porting_record_schema = load_json(root / "schemas/porting-record.schema.json")
    try:
        jsonschema.Draft202012Validator.check_schema(porting_record_schema)
    except jsonschema.SchemaError as exc:
        raise ReuseValidationError(
            f"destination porting-record schema is invalid: {exc.message}"
        ) from exc

    authorization = load_yaml(root / "legal/source-reuse-authorization.yaml")
    _require(
        authorization.get("status") == "recorded-repository-scope-authorization"
        and authorization.get("targetLicense") == "Apache-2.0"
        and authorization.get("scopeSource") == "architecture/reuse-map.yaml",
        "source authorization scope changed",
    )
    acquisition = authorization.get("acquisition", {})
    _require(
        acquisition
        == {
            "checkout": "detached-read-only-snapshot",
            "lockTool": "ci/lock_warm_snapshot.py",
            "directArgvOnly": True,
            "sourceCommitVerification": "required-before-and-after-reference-session",
            "objectInventoryVerification": "required-before-and-after-reference-session-with-lazy-fetch-disabled",
            "workingTreeCleanVerification": "required-before-and-after-reference-session",
            "filesystemEnforcement": "REMOVE_ALL_WRITE_BITS_AND_REQUIRE_OS_READ_ONLY_MOUNT_OR_SEPARATE_UNPRIVILEGED_OBSERVER",
            "implementationIdentityAccess": "forbidden",
            "observationIdentity": "separate-unprivileged-source-observer",
            "fetchRemoteAfterMaterialization": "disabled",
            "pushRemote": "forbidden",
            "pushCredentials": "forbidden",
            "sourceFilesystemWrites": "forbidden",
            "importMethod": "forbidden-until-approved-two-repository-transaction",
            "pathAuthority": "architecture/reuse-path-index.yaml",
            "authorizationAuthority": "architecture/porting-authorization-index.yaml",
            "authorizationSchema": "schemas/porting-authorization.schema.json",
            "destinationRecordSchema": "schemas/porting-record.schema.json",
        },
        "warm-source acquisition contract is not exact and separated",
    )
    state_machine = authorization.get("authorizationStateMachine", {})
    _require(
        state_machine.get("initial") == "REFERENCE_ONLY_PENDING_PATH_REVIEW"
        and state_machine.get("promotableTo") == "COPY_AUTHORIZED"
        and state_machine.get("admissionEnabled") is False
        and state_machine.get("admissionDisabledReason")
        == "NO_OFFLINE_SIGNATURE_AND_EVIDENCE_VERIFIER_IMPLEMENTED"
        and state_machine.get("currentCopyAuthorizedCount") == 0
        and state_machine.get("futurePromotionRequiresPacketRevision") is True
        and state_machine.get("futureAdmissionEnablementRequires")
        == [
            "canonicalAuthorizationSignatureVerifier",
            "pinnedOfflineApproverKeyFingerprint",
            "trackedEvidencePathDigestVerification",
            "exactPathIndexAuthorizationPacketDestinationJoin",
            "destinationPreparedAndAppliedRecordVerification",
        ],
        "porting admission is not fail-disabled pending a future verifier",
    )
    transaction = authorization.get("twoRepositoryTransaction", {})
    _require(
        transaction.get("joinKey") == "authorizationId"
        and transaction.get("phases")
        == ["SOURCE_APPROVED", "DESTINATION_PREPARED", "APPLIED"]
        and transaction.get("sourceRepositoryMutation") == "forbidden"
        and transaction.get("missingOrMismatchedRecord") == "DENY_COPY"
        and "source-material commit" in str(transaction.get("applyRule", ""))
        and "never self-referential" in str(transaction.get("mergeRule", "")),
        "two-repository porting transaction is circular or fail-open",
    )
    _require(
        authorization.get("currentInventory") == EXPECTED_CURRENT_INVENTORY,
        "source authorization current inventory is stale",
    )
    return authorization, porting_record_schema


def _validate_license_policy(root: Path) -> int:
    policy = load_yaml(root / "legal/third-party-license-policy.yaml")
    _require(
        policy.get("schemaVersion") == "harness.planeon.ai/license-policy/v1alpha1"
        and policy.get("policyVersion") == "0.2.0"
        and policy.get("coreLicense") == "Apache-2.0",
        "third-party license policy identity changed",
    )
    evaluation = policy.get("evaluation", {})
    _require(
        evaluation.get("failClosed") is True
        and evaluation.get("expressionMatching") == "EXACT_SPDX_EXPRESSION"
        and evaluation.get("allExpressionsMustBeClassified") is True
        and evaluation.get("unknownExpressionOutcome") == "DENY_UNKNOWN_LICENSE"
        and evaluation.get("emptyLicenseSetOutcome") == "DENY_MISSING_LICENSE",
        "third-party license classification must fail closed",
    )
    default_allowed = set(policy.get("defaultAllowedSpdx", []))
    exceptions = {
        item.get("expression")
        for item in policy.get("allowedExceptionExpressions", [])
        if isinstance(item, dict)
    }
    open_content = {
        item.get("expression")
        for item in policy.get("openContentSpdx", [])
        if isinstance(item, dict)
    }
    optional_review = set(policy.get("optionalExplicitReview", []))
    unresolved = set(policy.get("plannedUnresolvedSpdx", []))
    denied = set(policy.get("deniedForDefaultDistribution", []))
    categories = [
        default_allowed,
        exceptions,
        open_content,
        optional_review,
        unresolved,
        denied,
    ]
    for index, left in enumerate(categories):
        for right in categories[index + 1 :]:
            _require(not left & right, "SPDX classification categories overlap")
    _require(
        unresolved == {"NOASSERTION"}
        and policy.get("plannedUnresolvedRule", {}).get("releaseOutcome")
        == "DENY_RELEASE"
        and policy.get("deniedRule", {}).get("overrideAllowed") is False
        and policy.get("deniedRule", {}).get("releaseOutcome") == "DENY_RELEASE",
        "unresolved or denied licenses can enter a release",
    )
    path_policy = policy.get("pathDecisionPolicy", {})
    _require(
        path_policy.get("default") == "REFERENCE_ONLY_PENDING_PATH_REVIEW"
        and path_policy.get("missingEvidence") == "DENY_COPY"
        and path_policy.get("repositoryOwnershipInferenceAllowed") is False
        and path_policy.get("rootLicenseInheritanceAllowed") is False
        and path_policy.get("portingRecordRequiredPerBlob") is True,
        "path-level license decision policy is fail-open",
    )

    classified = set().union(*categories)
    providers = load_yaml(root / "architecture/providers.yaml")
    modules = providers.get("modules")
    _require(isinstance(modules, list), "provider catalog modules must be a list")
    expressions: set[str] = set()
    for module in modules:
        license_record = module.get("license", {})
        spdx = license_record.get("spdx")
        _require(
            isinstance(spdx, list)
            and spdx
            and all(isinstance(expression, str) and expression for expression in spdx),
            f"provider module {module.get('id')} has no license expressions",
        )
        expressions.update(spdx)
        _require(
            set(spdx) <= classified,
            f"provider module {module.get('id')} has an unclassified SPDX expression",
        )
        if "NOASSERTION" in spdx:
            _require(
                module.get("status") == "PLANNED"
                and license_record.get("custody")
                in {"COMPOSITE_REVIEW_REQUIRED", "TENANT_ATTESTED_PINNED"},
                f"provider module {module.get('id')} misuses NOASSERTION",
            )
    return len(expressions)


@dataclass(frozen=True)
class ReuseReport:
    accounted_source_inputs: int
    public_sha_pins: int
    metadata_omitted_inputs: int
    task_packets: int
    tree_discovery_records: int
    blob_pending_records: int
    blob_copy_authorized_records: int
    porting_authorization_records: int
    classified_spdx_expressions: int
    authority_digests: dict[str, str]

    def render(self) -> str:
        lines = [
            (
                f"accounted_source_inputs={self.accounted_source_inputs} "
                f"public_sha_pins={self.public_sha_pins} "
                f"metadata_omitted_inputs={self.metadata_omitted_inputs}"
            ),
            f"task_packets={self.task_packets} source_path_closure=EXACT",
            (
                f"tree_discovery_records={self.tree_discovery_records} "
                f"blob_pending_records={self.blob_pending_records} "
                f"blob_copy_authorized_records={self.blob_copy_authorized_records}"
            ),
            (
                f"porting_admission=DISABLED_FAIL_CLOSED "
                f"porting_authorization_records={self.porting_authorization_records}"
            ),
            f"classified_spdx_expressions={self.classified_spdx_expressions} license_policy=FAIL_CLOSED",
        ]
        for path, digest in sorted(self.authority_digests.items()):
            lines.append(f"authority_sha256={digest} path={path}")
        lines.append("reuse validation passed")
        return "\n".join(lines)


def validate_reuse(root: Path = ROOT, *, check_toolchain: bool = True) -> ReuseReport:
    root = root.resolve()
    if check_toolchain:
        _validate_toolchain()
    source_by_repository, accounted_sources = _validate_reuse_map(root)
    indexed_paths = _validate_path_index(root, source_by_repository)
    task_packet_count = _validate_task_packet_closure(root, indexed_paths)
    _authorization, _porting_record_schema = _validate_authorization_protocol(root)
    classified_spdx = _validate_license_policy(root)
    authority_digests = {
        relative: _sha256(root / relative)
        for relative in AUTHORITY_PATHS
    }
    return ReuseReport(
        accounted_source_inputs=accounted_sources,
        public_sha_pins=len(EXPECTED_PUBLIC_SOURCES),
        metadata_omitted_inputs=EXPECTED_NON_PUBLIC_INPUTS["count"],
        task_packets=task_packet_count,
        tree_discovery_records=EXPECTED_CURRENT_INVENTORY["treeDiscoveryRecords"],
        blob_pending_records=EXPECTED_CURRENT_INVENTORY["blobPendingRecords"],
        blob_copy_authorized_records=EXPECTED_CURRENT_INVENTORY["blobCopyAuthorizedRecords"],
        porting_authorization_records=EXPECTED_CURRENT_INVENTORY["portingAuthorizationRecords"],
        classified_spdx_expressions=classified_spdx,
        authority_digests=authority_digests,
    )


def parse_arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--root",
        type=Path,
        default=ROOT,
        help="repository root containing reuse, legal, schema, and packet authorities",
    )
    return parser.parse_args()


def main() -> int:
    arguments = parse_arguments()
    try:
        report = validate_reuse(arguments.root)
    except ReuseValidationError as exc:
        print(f"reuse validation failed: {exc}", file=sys.stderr)
        return 2
    print(report.render())
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
