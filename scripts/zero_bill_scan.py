#!/usr/bin/env python3
"""Fail closed when the Harness Engineering tree can introduce a bill."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import sys
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Any

import jsonschema
import yaml


ROOT = Path(__file__).resolve().parents[1]

EXPECTED_RUNNER_LABELS = [
    "self-hosted",
    "harness-engineering",
    "ephemeral",
    "credential-free",
]
EXPECTED_GITHUB = {
    "runnerLabels": [
        "ubuntu-latest",
        "ubuntu-24.04",
        "windows-latest",
        "macos-latest",
    ],
    "actions": ["actions/upload-artifact", "actions/cache"],
    "services": [
        "packages",
        "ghcr",
        "lfs",
        "codespaces",
        "hosted-runners",
        "advanced-security",
    ],
    "workflowTriggers": ["schedule"],
}
EXPECTED_IMPLEMENTATION_VECTORS = {
    "cloud-resource-provisioning",
    "terraform-cloud-providers",
    "mutable-image-tags",
    "mutable-chart-tags",
    "paid-or-metered-providers",
    "third-party-api-key-providers",
    "unknown-provider-cost-disposition",
    "hosted-model-providers",
    "cloud-billing-apis",
    "runtime-model-downloads",
    "runtime-package-downloads",
    "runtime-image-downloads-outside-locked-bundle",
    "external-telemetry-exporters",
    "implicit-network-package-execution",
}
ALLOWED_COST_DISPOSITIONS = {
    "SELF_HOSTED_OPEN_SOURCE_NON_METERED",
    "TENANT_SUPPLIED_OPEN_SOURCE_NON_METERED",
}
AUTHORITY_PATHS = (
    "policies/zero-bill-policy.yaml",
    "schemas/trusted-runner-manifest.schema.json",
    ".github/workflows/verify.yml",
    "scripts/zero_bill_scan.py",
    "tests/fixtures/zero-bill/cases.yaml",
    "BILLING_POLICY.md",
    "docs/TRUSTED_RUNNER_CONTRACT.md",
)
EXCLUDED_DIRECTORY_NAMES = {
    ".git",
    ".mypy_cache",
    ".pytest_cache",
    ".ruff_cache",
    ".venv",
    "__pycache__",
    "node_modules",
}
IMPLEMENTATION_ROOTS = {
    "apps",
    "charts",
    "cmd",
    "config",
    "deploy",
    "deployment",
    "helm",
    "infra",
    "manifests",
    "services",
    "src",
    "terraform",
    "workers",
}
SCANNABLE_SUFFIXES = {
    ".bash",
    ".conf",
    ".env",
    ".hcl",
    ".ini",
    ".js",
    ".json",
    ".jsx",
    ".properties",
    ".py",
    ".sh",
    ".tf",
    ".toml",
    ".ts",
    ".tsx",
    ".yaml",
    ".yml",
}


class ZeroBillScanError(ValueError):
    """A policy or scanned source is ambiguous or unreadable."""


class UniqueKeySafeLoader(yaml.SafeLoader):
    """Safe YAML loader that rejects duplicate mapping keys."""


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
            raise ZeroBillScanError(
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
            raise ZeroBillScanError(f"duplicate JSON key {key!r}")
        result[key] = value
    return result


def load_yaml(path: Path) -> dict[str, Any]:
    try:
        value = yaml.load(path.read_text(encoding="utf-8"), Loader=UniqueKeySafeLoader)
    except (OSError, UnicodeError, yaml.YAMLError) as exc:
        raise ZeroBillScanError(f"cannot read YAML {path}: {exc}") from exc
    if not isinstance(value, dict):
        raise ZeroBillScanError(f"YAML authority must be a mapping: {path}")
    return value


def load_json(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(
            path.read_text(encoding="utf-8"),
            object_pairs_hook=_unique_json_object,
        )
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise ZeroBillScanError(f"cannot read JSON {path}: {exc}") from exc
    if not isinstance(value, dict):
        raise ZeroBillScanError(f"JSON authority must be an object: {path}")
    return value


@dataclass(frozen=True, order=True)
class Finding:
    path: str
    line: int
    rule: str
    message: str

    def render(self) -> str:
        return f"{self.path}:{self.line}: {self.rule}: {self.message}"


@dataclass(frozen=True)
class ZeroBillReport:
    policy_vectors: int
    negative_fixtures: int
    scanned_files: int
    provider_modules: int
    workflows: int
    authority_digests: dict[str, str]

    def render(self) -> str:
        lines = [
            (
                "zero_bill_status=PASS "
                f"policy_vectors={self.policy_vectors} "
                f"negative_fixtures={self.negative_fixtures} "
                f"scanned_files={self.scanned_files} "
                f"provider_modules={self.provider_modules} "
                f"workflows={self.workflows}"
            )
        ]
        for path, digest in sorted(self.authority_digests.items()):
            lines.append(f"authority_sha256={digest} path={path}")
        lines.append("zero-bill scan passed")
        return "\n".join(lines)


def _finding(rule: str, path: str, message: str, line: int = 1) -> Finding:
    return Finding(path=path, line=line, rule=rule, message=message)


def _require_exact_keys(
    value: dict[str, Any],
    expected: set[str],
    *,
    label: str,
    path: str,
) -> list[Finding]:
    if set(value) == expected:
        return []
    return [
        _finding(
            "policy-contract",
            path,
            f"{label} keys changed: actual={sorted(value)} expected={sorted(expected)}",
        )
    ]


def validate_policy(policy: dict[str, Any]) -> list[Finding]:
    path = "policies/zero-bill-policy.yaml"
    findings = _require_exact_keys(
        policy,
        {
            "schemaVersion",
            "enforcement",
            "defaults",
            "forbiddenGithub",
            "forbiddenImplementation",
            "providerAdmission",
            "ci",
            "offlineVerification",
        },
        label="policy",
        path=path,
    )
    expected_sections = {
        "schemaVersion": "harness.planeon.ai/zero-bill-policy/v1alpha1",
        "enforcement": {
            "failClosed": True,
            "scanner": "scripts/zero_bill_scan.py",
            "negativeFixtureManifest": "tests/fixtures/zero-bill/cases.yaml",
            "unknownStructuredInput": "reject",
        },
        "defaults": {
            "deploymentMode": "offline",
            "allowedHosts": [],
            "runtimeDownloads": False,
            "externalTelemetry": False,
            "paidOrMeteredProviders": False,
            "thirdPartyApiKeys": False,
        },
        "forbiddenGithub": EXPECTED_GITHUB,
        "providerAdmission": {
            "allowedCostDispositions": [
                "SELF_HOSTED_OPEN_SOURCE_NON_METERED",
                "TENANT_SUPPLIED_OPEN_SOURCE_NON_METERED",
            ],
            "unknownCostDisposition": "reject",
            "paidOrMetered": "reject",
            "thirdPartyApiKey": "reject",
            "externalTelemetry": "reject",
        },
        "ci": {
            "selfHostedOnly": True,
            "requiredRunnerLabels": EXPECTED_RUNNER_LABELS,
            "ephemeralRunnerRequired": True,
            "credentialAndBrokerFreeRequired": True,
            "trustedHostLauncher": "/opt/planeon/bin/harness-offline-launch",
            "trustedRunnerManifest": "/etc/planeon/harness-runner-manifest.json",
            "trustedHostLauncherState": "EXTERNAL_PREREQUISITE_NOT_PROVEN",
            "repositoryCodeBeforeHostIsolation": False,
            "uploadArtifacts": False,
            "remoteCache": False,
            "externalForkExecution": False,
            "permissions": "contents-read",
            "monitoring": "bounded-until-terminal",
        },
        "offlineVerification": {
            "osNetworkIsolationRequired": True,
            "outboundCanaryRequired": True,
            "unsupportedIsolationBackend": "fail",
        },
    }
    for field, expected in expected_sections.items():
        if policy.get(field) != expected:
            findings.append(
                _finding(
                    "policy-contract",
                    path,
                    f"{field} is not the exact fail-closed value",
                )
            )
    vectors = policy.get("forbiddenImplementation")
    vector_set = (
        set(vectors)
        if isinstance(vectors, list)
        and all(isinstance(vector, str) for vector in vectors)
        else set()
    )
    if (
        not isinstance(vectors, list)
        or len(vectors) != len(vector_set)
        or vector_set != EXPECTED_IMPLEMENTATION_VECTORS
    ):
        findings.append(
            _finding(
                "policy-contract",
                path,
                "forbiddenImplementation must be the exact unique vector set",
            )
        )
    return sorted(set(findings))


def policy_vectors(policy: dict[str, Any]) -> set[str]:
    github = policy.get("forbiddenGithub", {})
    vectors = {
        f"github.runnerLabel:{value}" for value in github.get("runnerLabels", [])
    }
    vectors.update(f"github.action:{value}" for value in github.get("actions", []))
    vectors.update(f"github.service:{value}" for value in github.get("services", []))
    vectors.update(
        f"github.trigger:{value}" for value in github.get("workflowTriggers", [])
    )
    vectors.update(
        f"implementation:{value}"
        for value in policy.get("forbiddenImplementation", [])
    )
    return vectors


def validate_negative_fixtures(
    root: Path,
    policy: dict[str, Any],
) -> tuple[list[Finding], int]:
    relative = "tests/fixtures/zero-bill/cases.yaml"
    try:
        manifest = load_yaml(root / relative)
    except ZeroBillScanError as exc:
        return [_finding("negative-fixture-closure", relative, str(exc))], 0
    if set(manifest) != {"schemaVersion", "cases"} or manifest.get(
        "schemaVersion"
    ) != "harness.planeon.ai/zero-bill-negative-fixtures/v1alpha1":
        return [
            _finding(
                "negative-fixture-closure",
                relative,
                "fixture manifest identity or keys changed",
            )
        ], 0
    cases = manifest.get("cases")
    if not isinstance(cases, list):
        return [
            _finding(
                "negative-fixture-closure",
                relative,
                "fixture cases must be a list",
            )
        ], 0
    findings: list[Finding] = []
    ids: list[str] = []
    vectors: list[str] = []
    for index, case in enumerate(cases):
        if not isinstance(case, dict) or set(case) != {
            "id",
            "vector",
            "expectedRule",
            "targetPath",
            "content",
        }:
            findings.append(
                _finding(
                    "negative-fixture-closure",
                    relative,
                    f"case {index} is malformed or has unknown keys",
                )
            )
            continue
        if not all(
            isinstance(case[field], str) and case[field]
            for field in ("id", "vector", "expectedRule", "targetPath", "content")
        ):
            findings.append(
                _finding(
                    "negative-fixture-closure",
                    relative,
                    f"case {index} fields must be non-empty strings",
                )
            )
            continue
        ids.append(case["id"])
        vectors.append(case["vector"])
        target = PurePosixPath(case["targetPath"])
        if (
            target.is_absolute()
            or ".." in target.parts
            or "\\" in case["targetPath"]
        ):
            findings.append(
                _finding(
                    "negative-fixture-closure",
                    relative,
                    f"case {case['id']} has unsafe targetPath",
                )
            )
            continue
        rules = {
            finding.rule for finding in scan_text(target, case["content"])
        }
        if case["expectedRule"] not in rules:
            findings.append(
                _finding(
                    "negative-fixture-closure",
                    relative,
                    f"case {case['id']} does not trigger {case['expectedRule']}",
                )
            )
    if len(ids) != len(set(ids)):
        findings.append(
            _finding(
                "negative-fixture-closure",
                relative,
                "fixture IDs must be unique",
            )
        )
    expected_vectors = policy_vectors(policy)
    if len(vectors) != len(set(vectors)) or set(vectors) != expected_vectors:
        findings.append(
            _finding(
                "negative-fixture-closure",
                relative,
                "fixtures must cover every policy vector exactly once",
            )
        )
    return sorted(set(findings)), len(cases)


def _line_matches(
    findings: list[Finding],
    *,
    path: str,
    text: str,
    rule: str,
    pattern: str,
    message: str,
    flags: int = re.IGNORECASE,
) -> None:
    expression = re.compile(pattern, flags)
    for line_number, line in enumerate(text.splitlines(), start=1):
        if expression.search(line):
            findings.append(_finding(rule, path, message, line_number))


def scan_text(target: PurePosixPath, text: str) -> list[Finding]:
    """Scan one deployable target; used by both repository and fixture checks."""

    path = target.as_posix()
    lowered = path.casefold()
    findings: list[Finding] = []

    if lowered.startswith(".github/workflows/"):
        for label in EXPECTED_GITHUB["runnerLabels"]:
            _line_matches(
                findings,
                path=path,
                text=text,
                rule="github-hosted-runner",
                pattern=rf"\bruns-on\s*:\s*[^#\n]*\b{re.escape(label)}\b",
                message=f"GitHub-hosted runner label is forbidden: {label}",
            )
        _line_matches(
            findings,
            path=path,
            text=text,
            rule="github-upload-artifact",
            pattern=r"\bactions/upload-artifact(?:@|\b)",
            message="Actions artifact storage is forbidden",
        )
        _line_matches(
            findings,
            path=path,
            text=text,
            rule="github-cache",
            pattern=r"\bactions/cache(?:@|\b)",
            message="Actions cache storage is forbidden",
        )
        _line_matches(
            findings,
            path=path,
            text=text,
            rule="github-packages",
            pattern=r"\bpackages\s*:\s*write\b|npm\.pkg\.github\.com|docker\.pkg\.github\.com",
            message="GitHub Packages access is forbidden",
        )
        _line_matches(
            findings,
            path=path,
            text=text,
            rule="github-codespaces",
            pattern=r"\bcodespaces\s*:\s*(?:read|write)\b|\bdevcontainers/ci@",
            message="Codespaces-backed execution is forbidden",
        )
        _line_matches(
            findings,
            path=path,
            text=text,
            rule="github-hosted-runners-service",
            pattern=r"\bruns-on\s*:\s*[^#\n]*github-hosted",
            message="GitHub hosted-runner service is forbidden",
        )
        _line_matches(
            findings,
            path=path,
            text=text,
            rule="github-advanced-security",
            pattern=r"\bgithub/codeql-action/|\bsecurity-events\s*:\s*write\b",
            message="GitHub Advanced Security execution is forbidden",
        )
        _line_matches(
            findings,
            path=path,
            text=text,
            rule="github-schedule",
            pattern=r"^\s*schedule\s*:",
            message="scheduled workflows are forbidden",
        )
        _line_matches(
            findings,
            path=path,
            text=text,
            rule="untrusted-fork-execution",
            pattern=r"^\s*pull_request_target\s*:",
            message="pull_request_target can execute untrusted fork input",
        )
        _line_matches(
            findings,
            path=path,
            text=text,
            rule="github-secret-reference",
            pattern=r"\$\{\{\s*secrets\.",
            message="workflow secret references are forbidden",
        )

    _line_matches(
        findings,
        path=path,
        text=text,
        rule="github-ghcr",
        pattern=r"\bghcr\.io/",
        message="GHCR storage or runtime dependency is forbidden",
    )
    if target.name == ".gitattributes":
        _line_matches(
            findings,
            path=path,
            text=text,
            rule="github-lfs",
            pattern=r"\bfilter=lfs\b|\bdiff=lfs\b|\bmerge=lfs\b",
            message="Git LFS storage is forbidden",
        )

    if target.suffix.casefold() == ".tf":
        _line_matches(
            findings,
            path=path,
            text=text,
            rule="terraform-cloud-provider",
            pattern=r"\bprovider\s+\"(?:aws|azurerm|azuread|google|google-beta)\"",
            message="Terraform cloud provider is forbidden",
        )
    if re.search(
        r"(?ms)^\s*kind\s*:\s*Service\s*$.*?^\s*type\s*:\s*LoadBalancer\s*$",
        text,
    ) or re.search(
        r"(?mi)^\s*(?:kind\s*:\s*(?:Cluster|ManagedCluster|HorizontalPodAutoscaler|StorageClass)|resource\s+\"(?:aws_|google_|azurerm_)|[^#\n]*external-dns\.alpha\.kubernetes\.io/)",
        text,
    ):
        findings.append(
            _finding(
                "cloud-resource-provisioning",
                path,
                "cloud-managed infrastructure provisioning is forbidden",
            )
        )
    _line_matches(
        findings,
        path=path,
        text=text,
        rule="mutable-image-reference",
        pattern=r"(?:^\s*image\s*:|^\s*FROM\s+)\s*\S+:(?:latest|main|master|head|nightly|edge)\b",
        message="mutable image tag is forbidden",
    )
    for line_number, line in enumerate(text.splitlines(), start=1):
        match = re.search(
            r"(?:^\s*image\s*:|^\s*FROM\s+)\s*([^\s#]+)",
            line,
            re.IGNORECASE,
        )
        if match and match.group(1).casefold() != "scratch" and "@sha256:" not in match.group(1):
            findings.append(
                _finding(
                    "unlocked-image-reference",
                    path,
                    "image references must use an immutable sha256 digest",
                    line_number,
                )
            )
    if target.name.casefold() == "chart.yaml":
        _line_matches(
            findings,
            path=path,
            text=text,
            rule="mutable-chart-reference",
            pattern=r"^\s*version\s*:\s*(?:[\"']?\*[\"']?|latest|main|master|head|nightly|edge)\s*$",
            message="mutable chart version is forbidden",
        )
    _line_matches(
        findings,
        path=path,
        text=text,
        rule="paid-metered-provider",
        pattern=r"\bcostDisposition\s*:\s*(?:PAID|METERED|PAID_METERED|PAY_PER_USE)\b",
        message="paid or metered provider is forbidden",
    )
    _line_matches(
        findings,
        path=path,
        text=text,
        rule="unknown-cost-disposition",
        pattern=r"\bcostDisposition\s*:\s*(?:UNKNOWN|UNCLASSIFIED|TBD|null|~)\s*$",
        message="unknown provider cost disposition is forbidden",
    )
    _line_matches(
        findings,
        path=path,
        text=text,
        rule="third-party-api-key",
        pattern=r"\b(?:OPENAI|ANTHROPIC|OPENROUTER|AWS|AZURE|GOOGLE|GCP)_[A-Z0-9_]*(?:API_KEY|ACCESS_KEY|TOKEN|SECRET)\b|\bapiKey\s*:\s*\S+",
        message="third-party API key requirement is forbidden",
    )
    _line_matches(
        findings,
        path=path,
        text=text,
        rule="hosted-model-provider",
        pattern=r"\bprovider\s*:\s*(?:openai|anthropic|openrouter|bedrock|vertex|gemini)\b",
        message="hosted model provider is forbidden",
    )
    _line_matches(
        findings,
        path=path,
        text=text,
        rule="cloud-billing-api",
        pattern=r"cloudbilling\.googleapis\.com|billing\.microsoft\.com|ce\.[a-z0-9-]+\.amazonaws\.com|costmanagement\.azure\.com",
        message="cloud billing API dependency is forbidden",
    )
    _line_matches(
        findings,
        path=path,
        text=text,
        rule="runtime-model-download",
        pattern=r"\b(?:ollama\s+pull|huggingface-cli\s+download|snapshot_download\s*\(|hf_hub_download\s*\()",
        message="runtime model download is forbidden",
    )
    for line_number, line in enumerate(text.splitlines(), start=1):
        if re.search(r"\b(?:pip|pip3)\s+install\b|\b(?:npm|pnpm|yarn)\s+install\b", line, re.IGNORECASE):
            if not re.search(r"--offline\b|--no-index\b", line, re.IGNORECASE):
                findings.append(
                    _finding(
                        "runtime-package-download",
                        path,
                        "online package installation is forbidden",
                        line_number,
                    )
                )
    _line_matches(
        findings,
        path=path,
        text=text,
        rule="runtime-image-download",
        pattern=r"\b(?:docker|podman|crictl|nerdctl)\s+pull\b|\bimagePullPolicy\s*:\s*Always\b",
        message="runtime image download outside a locked bundle is forbidden",
    )
    _line_matches(
        findings,
        path=path,
        text=text,
        rule="external-telemetry-exporter",
        pattern=r"\b(?:OTEL_EXPORTER_OTLP_ENDPOINT|telemetryEndpoint)\s*[:=]\s*[\"']?https?://(?!localhost\b|127\.0\.0\.1\b|\[::1\])|\b(?:datadog|newrelic|honeycomb|sentry)\b",
        message="external telemetry exporter is forbidden",
    )
    _line_matches(
        findings,
        path=path,
        text=text,
        rule="implicit-network-package-execution",
        pattern=r"(?:^|\s)(?:npx|uvx|bunx|pipx\s+run)(?:\s|$)",
        message="implicit network package execution is forbidden",
    )
    return sorted(set(findings))


def _should_scan(relative: PurePosixPath) -> bool:
    if not relative.parts:
        return False
    if relative.parts[:3] == ("tests", "fixtures", "zero-bill"):
        return False
    if relative.parts[0] in {"docs", "task-packets"}:
        return False
    if relative.parts[:2] == (".github", "workflows"):
        return True
    if relative.name == ".gitattributes" or relative.suffix.casefold() == ".tf":
        return True
    if relative.name.casefold().startswith("dockerfile"):
        return True
    return (
        relative.parts[0] in IMPLEMENTATION_ROOTS
        and relative.suffix.casefold() in SCANNABLE_SUFFIXES
    )


def _iter_scannable_files(root: Path) -> list[tuple[PurePosixPath, Path]]:
    discovered: list[tuple[PurePosixPath, Path]] = []
    for current, directories, files in os.walk(root, topdown=True, followlinks=False):
        directories[:] = sorted(
            name for name in directories if name not in EXCLUDED_DIRECTORY_NAMES
        )
        current_path = Path(current)
        for name in sorted(files):
            path = current_path / name
            relative = PurePosixPath(path.relative_to(root).as_posix())
            if _should_scan(relative):
                discovered.append((relative, path))
    return discovered


def validate_workflow(path: Path, root: Path) -> list[Finding]:
    relative = path.relative_to(root).as_posix()
    try:
        workflow = load_yaml(path)
        text = path.read_text(encoding="utf-8")
    except (OSError, UnicodeError, ZeroBillScanError) as exc:
        return [_finding("workflow-contract", relative, str(exc))]
    findings = scan_text(PurePosixPath(relative), text)
    if workflow.get("permissions") != {"contents": "read"}:
        findings.append(
            _finding("workflow-contract", relative, "permissions must equal contents: read")
        )
    jobs = workflow.get("jobs")
    if not isinstance(jobs, dict) or set(jobs) != {"verify"}:
        findings.append(
            _finding("workflow-contract", relative, "workflow must contain only verify job")
        )
        return sorted(set(findings))
    job = jobs["verify"]
    expected_condition = (
        "github.event_name != 'pull_request' || "
        "github.event.pull_request.head.repo.fork == false"
    )
    if (
        not isinstance(job, dict)
        or job.get("if") != expected_condition
        or job.get("runs-on") != EXPECTED_RUNNER_LABELS
        or job.get("timeout-minutes") != 15
        or any(key in job for key in ("container", "services", "env", "continue-on-error"))
    ):
        findings.append(
            _finding(
                "workflow-contract",
                relative,
                "verify job does not match the closed runner and fork boundary",
            )
        )
        return sorted(set(findings))
    expected_steps = [
        {
            "name": "Checkout pinned action",
            "uses": "actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683",
            "with": {"persist-credentials": False, "fetch-depth": 1},
        },
        {
            "name": "Enter preinstalled trusted offline launcher",
            "run": "/opt/planeon/bin/harness-offline-launch",
        },
    ]
    if job.get("steps") != expected_steps:
        findings.append(
            _finding(
                "workflow-contract",
                relative,
                "workflow steps must be only pinned credential-free checkout and host launcher",
            )
        )
    if not re.search(r"(?m)^\s*pull_request\s*:\s*$", text) or not re.search(
        r"(?m)^\s*workflow_dispatch\s*:\s*$", text
    ):
        findings.append(
            _finding(
                "workflow-contract",
                relative,
                "only pull_request and workflow_dispatch triggers are required",
            )
        )
    return sorted(set(findings))


def validate_runner_schema(schema: dict[str, Any]) -> list[Finding]:
    path = "schemas/trusted-runner-manifest.schema.json"
    findings: list[Finding] = []
    try:
        jsonschema.Draft202012Validator.check_schema(schema)
    except jsonschema.SchemaError as exc:
        return [_finding("runner-schema", path, f"invalid JSON Schema: {exc.message}")]
    properties = schema.get("properties", {})
    expected_constants = [
        (
            properties.get("launcher", {}).get("properties", {}).get("path", {}).get("const"),
            "/opt/planeon/bin/harness-offline-launch",
        ),
        (
            properties.get("runner", {})
            .get("properties", {})
            .get("requiredLabels", {})
            .get("const"),
            EXPECTED_RUNNER_LABELS,
        ),
        (
            properties.get("isolation", {})
            .get("properties", {})
            .get("network", {})
            .get("const"),
            "OS_ENFORCED_DENY_ALL_OUTBOUND",
        ),
        (
            properties.get("signature", {})
            .get("properties", {})
            .get("algorithm", {})
            .get("const"),
            "ED25519",
        ),
    ]
    if any(actual != expected for actual, expected in expected_constants):
        findings.append(
            _finding("runner-schema", path, "trusted runner constants are not closed")
        )
    for section in ("launcher", "runner", "isolation", "preflight", "signature"):
        if properties.get(section, {}).get("additionalProperties") is not False:
            findings.append(
                _finding(
                    "runner-schema",
                    path,
                    f"{section} must reject unknown properties",
                )
            )
    return sorted(set(findings))


def validate_provider_catalog(catalog: dict[str, Any]) -> tuple[list[Finding], int]:
    path = "architecture/providers.yaml"
    findings: list[Finding] = []
    policy = catalog.get("policy", {})
    if not isinstance(policy, dict):
        return [
            _finding("provider-cost-admission", path, "provider policy must be a mapping")
        ], 0
    if (
        set(policy.get("validCostDispositions", [])) != ALLOWED_COST_DISPOSITIONS
        or policy.get("runtimeDownloadAllowed") is not False
    ):
        findings.append(
            _finding(
                "provider-cost-admission",
                path,
                "provider policy must allow exactly two non-metered dispositions and no runtime downloads",
            )
        )
    modules = catalog.get("modules")
    if not isinstance(modules, list):
        return [
            *findings,
            _finding("provider-cost-admission", path, "provider modules must be a list"),
        ], 0
    for index, module in enumerate(modules):
        if not isinstance(module, dict):
            findings.append(
                _finding("provider-cost-admission", path, f"module {index} is malformed")
            )
            continue
        module_id = str(module.get("id", f"index-{index}"))
        if module.get("costDisposition") not in ALLOWED_COST_DISPOSITIONS:
            findings.append(
                _finding(
                    "provider-cost-admission",
                    path,
                    f"module {module_id} has missing or unsafe cost disposition",
                )
            )
        configuration = module.get("configuration", {})
        if not isinstance(configuration, dict):
            configuration = {}
        if not {
            "inlineSecret",
            "apiKey",
            "mutableTag",
            "runtimeDownload",
        } <= set(configuration.get("forbiddenFields", [])):
            findings.append(
                _finding(
                    "provider-cost-admission",
                    path,
                    f"module {module_id} does not forbid billing-sensitive configuration",
                )
            )
        secrets = module.get("secrets", {})
        network = module.get("network", {})
        if not isinstance(secrets, dict):
            secrets = {}
        if not isinstance(network, dict):
            network = {}
        if (
            secrets.get("inlineValuesAllowed") is not False
            or network.get("defaultDeny") is not True
            or network.get("undeclaredExternalEgressAllowed") is not False
        ):
            findings.append(
                _finding(
                    "provider-cost-admission",
                    path,
                    f"module {module_id} has fail-open secret or egress settings",
                )
            )
    return sorted(set(findings)), len(modules)


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def scan_repository(root: Path) -> ZeroBillReport:
    root = root.resolve(strict=True)
    findings: list[Finding] = []
    try:
        policy = load_yaml(root / "policies/zero-bill-policy.yaml")
        policy_findings = validate_policy(policy)
        findings.extend(policy_findings)
    except ZeroBillScanError as exc:
        raise ZeroBillScanError(f"zero-bill policy unavailable: {exc}") from exc
    negative_fixtures = 0
    if not policy_findings:
        fixture_findings, negative_fixtures = validate_negative_fixtures(root, policy)
        findings.extend(fixture_findings)

    workflow_directory = root / ".github/workflows"
    workflows = sorted(
        [
            *workflow_directory.glob("*.yaml"),
            *workflow_directory.glob("*.yml"),
        ]
    )
    if [path.name for path in workflows] != ["verify.yml"]:
        findings.append(
            _finding(
                "workflow-contract",
                ".github/workflows",
                "exactly one verify.yml workflow is allowed",
            )
        )
    for workflow in workflows:
        findings.extend(validate_workflow(workflow, root))

    try:
        runner_schema = load_json(root / "schemas/trusted-runner-manifest.schema.json")
        findings.extend(validate_runner_schema(runner_schema))
    except ZeroBillScanError as exc:
        findings.append(
            _finding(
                "runner-schema",
                "schemas/trusted-runner-manifest.schema.json",
                str(exc),
            )
        )

    provider_modules = 0
    try:
        provider_catalog = load_yaml(root / "architecture/providers.yaml")
        provider_findings, provider_modules = validate_provider_catalog(provider_catalog)
        findings.extend(provider_findings)
    except ZeroBillScanError as exc:
        findings.append(
            _finding("provider-cost-admission", "architecture/providers.yaml", str(exc))
        )

    scanned_files = 0
    for relative, path in _iter_scannable_files(root):
        scanned_files += 1
        if path.is_symlink():
            findings.append(
                _finding(
                    "scannable-symlink",
                    relative.as_posix(),
                    "deployable scan input must not be a symlink",
                )
            )
            continue
        try:
            text = path.read_text(encoding="utf-8")
        except (OSError, UnicodeError) as exc:
            findings.append(
                _finding(
                    "unreadable-structured-input",
                    relative.as_posix(),
                    f"structured input cannot be scanned: {exc}",
                )
            )
            continue
        findings.extend(scan_text(relative, text))

    billing_policy = (root / "BILLING_POLICY.md").read_text(encoding="utf-8")
    runner_contract = (root / "docs/TRUSTED_RUNNER_CONTRACT.md").read_text(
        encoding="utf-8"
    )
    for required in (
        "tests/fixtures/zero-bill/cases.yaml",
        "separate evidence states",
        "never queries a cloud provider",
    ):
        if required not in billing_policy:
            findings.append(
                _finding("billing-policy-document", "BILLING_POLICY.md", f"missing {required!r}")
            )
    for required in (
        "closed environment allowlist",
        "does not prove isolation",
        "packet digest is rechecked",
    ):
        if required not in runner_contract:
            findings.append(
                _finding(
                    "runner-contract-document",
                    "docs/TRUSTED_RUNNER_CONTRACT.md",
                    f"missing {required!r}",
                )
            )

    unique_findings = sorted(set(findings))
    if unique_findings:
        raise ZeroBillScanError(
            "zero-bill scan found violations:\n"
            + "\n".join(finding.render() for finding in unique_findings)
        )
    vectors = policy_vectors(policy)
    if len(vectors) != 27:
        raise ZeroBillScanError(
            f"zero-bill policy vector count changed: expected=27 actual={len(vectors)}"
        )
    authority_digests = {
        relative: _sha256(root / relative) for relative in AUTHORITY_PATHS
    }
    return ZeroBillReport(
        policy_vectors=len(vectors),
        negative_fixtures=negative_fixtures,
        scanned_files=scanned_files,
        provider_modules=provider_modules,
        workflows=len(workflows),
        authority_digests=authority_digests,
    )


def parse_arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("root", nargs="?", type=Path, default=ROOT)
    return parser.parse_args()


def main() -> int:
    arguments = parse_arguments()
    try:
        report = scan_repository(arguments.root)
    except (OSError, ZeroBillScanError) as exc:
        print(f"zero-bill scan failed: {exc}", file=sys.stderr)
        return 2
    print(report.render())
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
