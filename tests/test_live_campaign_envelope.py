from __future__ import annotations

import copy
import json
import unittest
from collections.abc import Callable
from pathlib import Path
from typing import Any

import jsonschema

ROOT = Path(__file__).resolve().parents[1]
SCHEMA_PATH = ROOT / "schemas/live-campaign-execution-envelope.schema.json"


def sha256(character: str = "a") -> str:
    return f"sha256:{character * 64}"


def valid_envelope() -> dict[str, Any]:
    return {
        "schemaVersion": "harness.planeon.ai/live-campaign-execution-envelope/v1alpha1",
        "packetId": "CONF-K8S-001",
        "packetFileReference": "/var/lib/planeon/packets/CONF-K8S-001.yaml",
        "packetDigest": sha256("1"),
        "commands": [
            ["make", "campaign", "CAMPAIGN=kubernetes-live-matrix"],
            ["make", "evidence-verify", "CAMPAIGN=kubernetes-live-matrix"],
        ],
        "commandSetDigest": sha256("2"),
        "conformanceKitRoot": "/opt/planeon/conformance-kit",
        "conformanceKitDigest": sha256("3"),
        "campaignId": "kubernetes-live-matrix",
        "campaignDefinitionFileReference": "/opt/planeon/campaigns/kubernetes-live-matrix.json",
        "campaignDefinitionDigest": sha256("4"),
        "campaignReleaseFileReference": "/opt/planeon/releases/kubernetes-live-matrix.json",
        "campaignReleaseDigest": sha256("5"),
        "launcherDigest": sha256("6"),
        "bundleFileReference": "/var/lib/planeon/bundles/tenant-a-bundle.tar",
        "bundleDigest": sha256("7"),
        "allowedEvidenceAxes": ["DEPLOYMENT", "RUNTIME", "ASSURANCE"],
        "tenantId": "tenant-a",
        "environmentId": "airgap-k8s-a",
        "capacityAuthorizationId": "capacity-auth-20260830-a",
        "capacityAuthorizationFileReference": "/etc/planeon/authority/capacity-auth-20260830-a.json",
        "capacityAuthorizationDigest": sha256("8"),
        "mutationProfile": "ZERO_INCREMENTAL_COST_KUBERNETES_V1",
        "admissionPolicyDigest": sha256("9"),
        "resourceQuotaDigest": sha256("a"),
        "endpoints": [
            {
                "endpointId": "kubernetes-api-proxy-a",
                "kind": "KUBERNETES_API_PROXY",
                "ipAddress": "10.30.0.10",
                "port": 6443,
                "tls": {
                    "serverName": "kubernetes.internal",
                    "serverSpkiDigest": sha256("b"),
                    "caCertificateFileReference": "/etc/planeon/tls/kubernetes-ca.pem",
                },
                "credentialFileReference": "/run/planeon/credentials/kubernetes.token",
                "authorizationPolicyDigest": sha256("f"),
                "costDisposition": "TENANT_SUPPLIED_OPEN_SOURCE_NON_METERED",
                "accessMode": "PREAUTHORIZED_PROXY",
                "discovery": False,
            },
            {
                "endpointId": "local-evidence-sink-a",
                "kind": "LOCAL_EVIDENCE_SINK",
                "ipAddress": "127.0.0.1",
                "port": 9443,
                "tls": {
                    "serverName": "evidence.local",
                    "serverSpkiDigest": sha256("c"),
                    "caCertificateFileReference": "/etc/planeon/tls/evidence-ca.pem",
                },
                "credentialFileReference": "/run/planeon/credentials/evidence.token",
                "authorizationPolicyDigest": sha256("0"),
                "costDisposition": "SELF_HOSTED_OPEN_SOURCE_NON_METERED",
                "accessMode": "LOCAL_PREEXISTING",
                "discovery": False,
            },
        ],
        "issuedAt": "2026-08-30T01:00:00Z",
        "expiresAt": "2026-08-30T01:30:00Z",
        "nonce": "bm9uY2UtMjAyNjA4MzAtMDAx",
        "releaseTrustStoreDigest": sha256("d"),
        "tenantTrustStoreDigest": sha256("e"),
        "platformSignerKeyId": "platform-live-execution-2026-01",
        "platformSignature": "A" * 86,
        "tenantSignerKeyId": "tenant-a-live-execution-2026-01",
        "tenantSignature": "B" * 86,
    }


class LiveCampaignEnvelopeSchemaTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        schema = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
        jsonschema.Draft202012Validator.check_schema(schema)
        cls.validator = jsonschema.Draft202012Validator(
            schema,
            format_checker=jsonschema.FormatChecker(),
        )

    def assert_rejected(self, mutate: Callable[[dict[str, Any]], None]) -> None:
        envelope = copy.deepcopy(valid_envelope())
        mutate(envelope)
        self.assert_invalid_envelope(envelope)

    def assert_invalid_envelope(self, envelope: dict[str, Any]) -> None:
        with self.assertRaises(jsonschema.ValidationError):
            self.validator.validate(envelope)

    def test_valid_envelope(self) -> None:
        self.validator.validate(valid_envelope())

    def test_rejects_shell_argv(self) -> None:
        def mutate(envelope: dict[str, Any]) -> None:
            envelope["commands"] = [["/usr/bin/env", "bash", "-c", "make campaign"]]

        self.assert_rejected(mutate)

    def test_rejects_relative_or_traversal_paths(self) -> None:
        invalid_paths = (
            "var/lib/planeon/packets/CONF-K8S-001.yaml",
            "/var/lib/planeon/../secrets/key",
        )
        for invalid_path in invalid_paths:
            with self.subTest(invalid_path=invalid_path):
                envelope = copy.deepcopy(valid_envelope())
                envelope["packetFileReference"] = invalid_path
                self.assert_invalid_envelope(envelope)

    def test_rejects_tenant_acceptance_axis(self) -> None:
        def mutate(envelope: dict[str, Any]) -> None:
            envelope["allowedEvidenceAxes"] = ["TENANT_ACCEPTANCE"]

        self.assert_rejected(mutate)

    def test_rejects_unknown_endpoint_kind(self) -> None:
        def mutate(envelope: dict[str, Any]) -> None:
            envelope["endpoints"][0]["kind"] = "PUBLIC_MODEL_API"

        self.assert_rejected(mutate)

    def test_rejects_endpoint_discovery(self) -> None:
        def mutate(envelope: dict[str, Any]) -> None:
            envelope["endpoints"][0]["discovery"] = True

        self.assert_rejected(mutate)

    def test_rejects_untransportable_capacity_authorization(self) -> None:
        def mutate(envelope: dict[str, Any]) -> None:
            del envelope["capacityAuthorizationFileReference"]

        self.assert_rejected(mutate)

    def test_rejects_endpoint_cost_or_proxy_scope_widening(self) -> None:
        mutations = (
            ("costDisposition", "UNKNOWN"),
            ("accessMode", "LOCAL_PREEXISTING"),
            ("ipAddress", "169.254.169.254"),
        )
        for field, value in mutations:
            with self.subTest(field=field, value=value):
                envelope = copy.deepcopy(valid_envelope())
                envelope["endpoints"][0][field] = value
                self.assert_invalid_envelope(envelope)

    def test_rejects_missing_either_signature(self) -> None:
        for signature_field in ("platformSignature", "tenantSignature"):
            with self.subTest(signature_field=signature_field):
                envelope = copy.deepcopy(valid_envelope())
                del envelope[signature_field]
                self.assert_invalid_envelope(envelope)

    def test_rejects_widened_mutation_profile(self) -> None:
        def mutate(envelope: dict[str, Any]) -> None:
            envelope["mutationProfile"] = "ALLOW_DYNAMIC_CLOUD_CAPACITY_V1"

        self.assert_rejected(mutate)

    def test_rejects_extra_property(self) -> None:
        def mutate(envelope: dict[str, Any]) -> None:
            envelope["cloudProviderToken"] = "forbidden"

        self.assert_rejected(mutate)
