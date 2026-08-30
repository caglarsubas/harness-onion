from __future__ import annotations

import copy
import errno
import importlib.util
import json
import subprocess
import sys
from pathlib import Path, PurePosixPath

import jsonschema
import pytest
ROOT = Path(__file__).resolve().parents[1]


def _load_module(name: str, path: Path):
    specification = importlib.util.spec_from_file_location(name, path)
    assert specification and specification.loader
    module = importlib.util.module_from_spec(specification)
    sys.modules[specification.name] = module
    specification.loader.exec_module(module)
    return module


SCANNER = _load_module("met_003_zero_bill_scanner", ROOT / "scripts/zero_bill_scan.py")
OFFLINE_TESTS = _load_module("met_003_offline_tests", ROOT / "ci/test_offline_runner.py")
CANARY = _load_module("met_003_network_canary", ROOT / "ci/network_canary.py")
TOOLCHAIN = _load_module("met_003_toolchain", ROOT / "scripts/verify_toolchain.py")


class TestOfflinePacketRunner(OFFLINE_TESTS.OfflineRunnerTest):
    """Retain all packet-transport unit contracts under MET-003 acceptance."""


def _policy() -> dict:
    return SCANNER.load_yaml(ROOT / "policies/zero-bill-policy.yaml")


def _fixture_manifest() -> dict:
    return SCANNER.load_yaml(ROOT / "tests/fixtures/zero-bill/cases.yaml")


def test_canonical_repository_has_positive_zero_bill_report() -> None:
    report = SCANNER.scan_repository(ROOT)

    assert report.policy_vectors == 27
    assert report.negative_fixtures == 27
    assert report.workflows == 1
    assert report.provider_modules == 87
    assert report.scanned_files >= 1
    assert set(report.authority_digests) == set(SCANNER.AUTHORITY_PATHS)
    assert all(len(digest) == 64 for digest in report.authority_digests.values())
    assert report.render().endswith("zero-bill scan passed")


def test_negative_fixture_manifest_exactly_covers_policy_vectors() -> None:
    policy_vectors = SCANNER.policy_vectors(_policy())
    manifest = _fixture_manifest()

    assert manifest["schemaVersion"] == (
        "harness.planeon.ai/zero-bill-negative-fixtures/v1alpha1"
    )
    cases = manifest["cases"]
    assert isinstance(cases, list)
    assert len(cases) == len(policy_vectors) == 27
    assert len({case["id"] for case in cases}) == len(cases)
    assert {case["vector"] for case in cases} == policy_vectors

    for case in cases:
        target = PurePosixPath(case["targetPath"])
        assert not target.is_absolute() and ".." not in target.parts
        findings = SCANNER.scan_text(target, case["content"])
        rules = {finding.rule for finding in findings}
        assert findings, case["id"]
        assert case["expectedRule"] in rules, (case["id"], rules)


@pytest.mark.parametrize(
    ("section", "field", "unsafe"),
    [
        ("enforcement", "failClosed", False),
        ("defaults", "allowedHosts", ["api.example.com"]),
        ("ci", "selfHostedOnly", False),
        ("ci", "uploadArtifacts", True),
        ("offlineVerification", "unsupportedIsolationBackend", "warn"),
    ],
)
def test_policy_mutations_fail_closed(section: str, field: str, unsafe: object) -> None:
    policy = copy.deepcopy(_policy())
    policy[section][field] = unsafe

    findings = SCANNER.validate_policy(policy)
    assert {finding.rule for finding in findings} == {"policy-contract"}


def test_policy_rejects_missing_or_duplicate_vector() -> None:
    policy = copy.deepcopy(_policy())
    policy["forbiddenImplementation"].append(
        policy["forbiddenImplementation"][0]
    )

    findings = SCANNER.validate_policy(policy)
    assert any("unique vector set" in finding.message for finding in findings)


def test_duplicate_yaml_key_is_rejected(tmp_path: Path) -> None:
    authority = tmp_path / "duplicate.yaml"
    authority.write_text("defaults: {}\ndefaults: {}\n", encoding="utf-8")

    with pytest.raises(SCANNER.ZeroBillScanError, match="duplicate YAML key"):
        SCANNER.load_yaml(authority)


def test_workflow_authority_is_exact_and_fork_closed(tmp_path: Path) -> None:
    canonical = ROOT / ".github/workflows/verify.yml"
    assert SCANNER.validate_workflow(canonical, ROOT) == []

    workflow_root = tmp_path
    workflow_path = workflow_root / ".github/workflows/verify.yml"
    workflow_path.parent.mkdir(parents=True)
    workflow_path.write_text(
        canonical.read_text(encoding="utf-8").replace(
            "github.event.pull_request.head.repo.fork == false",
            "github.event.pull_request.head.repo.fork == true",
        ),
        encoding="utf-8",
    )
    findings = SCANNER.validate_workflow(workflow_path, workflow_root)
    assert "workflow-contract" in {finding.rule for finding in findings}


def _valid_runner_manifest() -> dict:
    digest = "a" * 64
    return {
        "schemaVersion": "harness.planeon.ai/trusted-runner-manifest/v1alpha1",
        "launcher": {
            "path": "/opt/planeon/bin/harness-offline-launch",
            "version": "1.3.0",
            "sha256": digest,
            "ownerUid": 0,
            "ownerGid": 0,
            "mode": "0555",
        },
        "runner": {
            "requiredLabels": SCANNER.EXPECTED_RUNNER_LABELS,
            "ephemeral": True,
            "ambientCloudCredentials": False,
            "sshAgent": False,
            "kubeconfig": False,
            "containerControlSockets": [],
            "billableBrokers": [],
        },
        "isolation": {
            "network": "OS_ENFORCED_DENY_ALL_OUTBOUND",
            "warmSourceRootEnvironment": "HARNESS_WARM_SOURCE_ROOTS",
            "warmSourceRootMode": "CANONICAL_EXHAUSTIVE_DENY_READ_METADATA_WRITE",
            "warmSourceRoots": [],
            "credentialHomeMode": "HIDDEN_OR_EMPTY",
            "localSocketMode": "CONTROL_AND_AGENT_SOCKETS_HIDDEN",
            "childPathMode": "WARM_ROOT_PATHS_SCRUBBED",
            "runnerManifestChildMode": "MANIFEST_KEY_SIGNATURE_AND_PREFLIGHT_HIDDEN",
        },
        "preflight": {
            "suiteVersion": "1.0.0",
            "status": "PASS",
            "evidenceSha256": digest,
            "networkDenied": True,
            "warmReadDenied": True,
            "warmMetadataDenied": True,
            "warmWriteDenied": True,
            "packetWriteDenied": True,
            "credentialEnvironmentScrubbed": True,
            "brokerSocketsAbsent": True,
        },
        "signature": {
            "algorithm": "ED25519",
            "signaturePath": "/etc/planeon/harness-runner-manifest.json.sig",
            "publicKeyPath": "/etc/planeon/harness-runner-manifest.pub",
            "publicKeySha256": digest,
        },
    }


def test_trusted_runner_schema_rejects_billable_or_credentialed_runner() -> None:
    schema = json.loads(
        (ROOT / "schemas/trusted-runner-manifest.schema.json").read_text(
            encoding="utf-8"
        )
    )
    validator = jsonschema.Draft202012Validator(schema)
    manifest = _valid_runner_manifest()
    validator.validate(manifest)

    unsafe = copy.deepcopy(manifest)
    unsafe["runner"]["ambientCloudCredentials"] = True
    unsafe["runner"]["requiredLabels"] = ["ubuntu-latest"]
    with pytest.raises(jsonschema.ValidationError):
        validator.validate(unsafe)


def test_runner_schema_itself_is_closed() -> None:
    schema = SCANNER.load_json(ROOT / "schemas/trusted-runner-manifest.schema.json")
    assert SCANNER.validate_runner_schema(schema) == []


def test_provider_catalog_rejects_unknown_cost_disposition() -> None:
    catalog = SCANNER.load_yaml(ROOT / "architecture/providers.yaml")
    unsafe = copy.deepcopy(catalog)
    unsafe["modules"][0]["costDisposition"] = "UNKNOWN"

    findings, module_count = SCANNER.validate_provider_catalog(unsafe)
    assert module_count == 87
    assert "provider-cost-admission" in {finding.rule for finding in findings}


def test_network_canary_requires_backend_specific_denial() -> None:
    assert CANARY.denial_is_proven("darwin-sandbox", errno.EPERM)
    assert not CANARY.denial_is_proven("darwin-sandbox", errno.ETIMEDOUT)
    assert CANARY.denial_is_proven("linux-firejail", errno.ENETUNREACH)
    assert not CANARY.denial_is_proven("unknown", errno.EPERM)


@pytest.mark.parametrize(
    ("target", "content", "expected_rule"),
    [
        (
            ".github/workflows/unsafe.yml",
            "env:\n  API_TOKEN: ${{ secrets.PROVIDER_TOKEN }}\n",
            "github-secret-reference",
        ),
        (
            "deploy/workload.yaml",
            "image: quay.io/example/service:1.2.3\n",
            "unlocked-image-reference",
        ),
        (
            "deploy/autoscale.yaml",
            "apiVersion: autoscaling/v2\nkind: HorizontalPodAutoscaler\n",
            "cloud-resource-provisioning",
        ),
    ],
)
def test_additional_fail_closed_vectors(
    target: str,
    content: str,
    expected_rule: str,
) -> None:
    rules = {
        finding.rule
        for finding in SCANNER.scan_text(PurePosixPath(target), content)
    }
    assert expected_rule in rules


def test_prefetch_entry_point_is_local_cache_only() -> None:
    prefetch = (ROOT / "ci/prefetch.sh").read_text(encoding="utf-8")
    makefile = (ROOT / "Makefile").read_text(encoding="utf-8")

    assert "scripts/verify_toolchain.py" in prefetch
    assert "HARNESS_OFFLINE_ENFORCED UV_OFFLINE UV_FROZEN UV_NO_SYNC" in prefetch
    assert not any(token in prefetch for token in ("curl ", "wget ", "pip install"))
    assert "prefetch:\n\t./ci/prefetch.sh" in makefile
    assert "python3 scripts/zero_bill_scan.py ." in makefile


def test_exact_preinstalled_toolchain_is_active() -> None:
    assert TOOLCHAIN.main() == 0


def test_predecessor_zero_bill_validator_remains_green() -> None:
    completed = subprocess.run(
        [
            sys.executable,
            str(ROOT / "scripts/validate_readiness.py"),
            "--zero-bill-only",
        ],
        cwd=ROOT,
        text=True,
        capture_output=True,
        shell=False,
        check=False,
    )
    assert completed.returncode == 0, completed.stdout + completed.stderr
