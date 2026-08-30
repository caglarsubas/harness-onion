from __future__ import annotations

import copy
import json
import subprocess
import sys
import unittest
from pathlib import Path

import yaml

from scripts.validate_readiness import (
    EXPECTED_REPOSITORIES,
    Validation,
    validate_provider_catalog_data,
)

ROOT = Path(__file__).resolve().parents[1]


class ReadinessValidationTest(unittest.TestCase):
    def test_complete_readiness_package(self) -> None:
        result = subprocess.run(
            [sys.executable, str(ROOT / "scripts/validate_readiness.py")],
            cwd=ROOT,
            text=True,
            capture_output=True,
            check=False,
        )
        self.assertEqual(0, result.returncode, result.stdout + result.stderr)

    def test_zero_bill_policy(self) -> None:
        result = subprocess.run(
            [sys.executable, str(ROOT / "scripts/validate_readiness.py"), "--zero-bill-only"],
            cwd=ROOT,
            text=True,
            capture_output=True,
            check=False,
        )
        self.assertEqual(0, result.returncode, result.stdout + result.stderr)


class ProviderCatalogNegativeTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.catalog = yaml.safe_load(
            (ROOT / "architecture/providers.yaml").read_text(encoding="utf-8")
        )
        cls.schema = json.loads(
            (ROOT / "schemas/provider-module.schema.json").read_text(encoding="utf-8")
        )
        cls.service_ids = {
            service["id"]
            for service in yaml.safe_load(
                (ROOT / "architecture/services.yaml").read_text(encoding="utf-8")
            )["services"]
        }

    def validate_copy(self, catalog: dict) -> list[str]:
        validation = Validation()
        validate_provider_catalog_data(
            validation,
            catalog,
            self.schema,
            EXPECTED_REPOSITORIES,
            self.service_ids,
        )
        return validation.errors

    def test_rejects_unresolved_module_dependency(self) -> None:
        catalog = copy.deepcopy(self.catalog)
        catalog["modules"][0]["dependencies"].append("missing.provider.module")
        errors = self.validate_copy(catalog)
        self.assertTrue(
            any("unknown dependency 'missing.provider.module'" in error for error in errors),
            errors,
        )

    def test_rejects_mutable_artifact_reference(self) -> None:
        catalog = copy.deepcopy(self.catalog)
        catalog["modules"][0]["installUnits"][0]["artifact"] = "example/image:latest"
        errors = self.validate_copy(catalog)
        self.assertTrue(
            any("URL or mutable artifact reference" in error for error in errors),
            errors,
        )

    def test_rejects_profile_closure_mismatch(self) -> None:
        catalog = copy.deepcopy(self.catalog)
        self.assertTrue(catalog.get("profileExamples"), "catalog has no profile examples")
        profile = catalog["profileExamples"][0]
        closure = set(profile["expectedClosure"])
        extra = next(
            module["id"] for module in catalog["modules"] if module["id"] not in closure
        )
        profile["expectedClosure"].append(extra)
        errors = self.validate_copy(catalog)
        self.assertTrue(
            any("expectedClosure does not equal computed closure" in error for error in errors),
            errors,
        )

    def test_rejects_profile_selection_not_derived_from_capabilities(self) -> None:
        catalog = copy.deepcopy(self.catalog)
        catalog["profileExamples"][0]["selectedModules"].pop()
        errors = self.validate_copy(catalog)
        self.assertTrue(
            any("deterministic capability derivation" in error for error in errors),
            errors,
        )

    def test_rejects_incompatible_profile_platform(self) -> None:
        catalog = copy.deepcopy(self.catalog)
        catalog["profileExamples"][0]["environmentFacts"]["kubernetes"] = "openshift"
        errors = self.validate_copy(catalog)
        self.assertTrue(
            any("incompatible Kubernetes platform" in error for error in errors),
            errors,
        )

    def test_planned_fixture_cannot_claim_verified_fact_attestation(self) -> None:
        catalog = copy.deepcopy(self.catalog)
        attestation = catalog["profileExamples"][0]["environmentFacts"][
            "attestation"
        ]
        attestation.update(
            {
                "digest": "sha256:" + "0" * 64,
                "digestStatus": "LOCKED",
                "signatureStatus": "VERIFIED",
            }
        )
        errors = self.validate_copy(catalog)
        self.assertTrue(
            any("must not claim signed environment evidence" in error for error in errors),
            errors,
        )

    def test_rejects_multiple_exclusive_provider_members(self) -> None:
        catalog = copy.deepcopy(self.catalog)
        profile = catalog["profileExamples"][0]
        profile["selectedModules"].append(
            "provider.runtime.infrastructure.kubernetes-upstream"
        )
        errors = self.validate_copy(catalog)
        self.assertTrue(
            any("selects multiple members of group.infrastructure-provider" in error for error in errors),
            errors,
        )

    def test_rejects_forbidden_demand_capability(self) -> None:
        catalog = copy.deepcopy(self.catalog)
        catalog["profileExamples"][0]["requestedCapabilities"].append(
            "hosted.model-provider"
        )
        errors = self.validate_copy(catalog)
        self.assertTrue(
            any(
                "forbidden demand capability 'hosted.model-provider'" in error
                for error in errors
            ),
            errors,
        )

    def test_rejects_internal_capability_as_public_demand(self) -> None:
        catalog = copy.deepcopy(self.catalog)
        catalog["profileExamples"][0]["requestedCapabilities"].append(
            "planeon.operator"
        )
        errors = self.validate_copy(catalog)
        self.assertTrue(
            any("internal or environment-only capability" in error for error in errors),
            errors,
        )

    def test_rejects_provider_selector_as_environment_fact(self) -> None:
        catalog = copy.deepcopy(self.catalog)
        catalog["profileExamples"][0]["environmentFacts"][
            "capabilities"
        ].append("provider.planeon.ollama")
        errors = self.validate_copy(catalog)
        self.assertTrue(
            any("demand, selector, or internal capability" in error for error in errors),
            errors,
        )

    def test_rejects_selector_for_inactive_group(self) -> None:
        catalog = copy.deepcopy(self.catalog)
        catalog["profileExamples"][0]["requestedCapabilities"].append(
            "provider.planeon.ollama"
        )
        errors = self.validate_copy(catalog)
        self.assertTrue(
            any("accepts inactive selector" in error for error in errors),
            errors,
        )

    def test_rejects_implication_that_silently_selects_provider(self) -> None:
        catalog = copy.deepcopy(self.catalog)
        catalog["capabilityImplications"][0]["addCapabilities"].append(
            "provider.planeon.ollama"
        )
        errors = self.validate_copy(catalog)
        self.assertTrue(
            any("silently selects an exclusive provider" in error for error in errors),
            errors,
        )

    def test_rejects_assurance_subject_not_in_accepted_demand(self) -> None:
        catalog = copy.deepcopy(self.catalog)
        catalog["profileExamples"][0]["assuranceSubjects"][
            "capabilities"
        ].append("assurance.local-model-judge")
        errors = self.validate_copy(catalog)
        self.assertTrue(
            any("not a subset of accepted resolved demand" in error for error in errors),
            errors,
        )

    def test_local_model_judge_requires_model_class_and_backend_selector(self) -> None:
        catalog = copy.deepcopy(self.catalog)
        profile = catalog["profileExamples"][0]
        profile["requestedCapabilities"].append("assurance.local-model-judge")
        errors = self.validate_copy(catalog)
        self.assertTrue(
            any("missing its required local model class" in error for error in errors),
            errors,
        )

    def test_rejects_unregistered_network_target(self) -> None:
        catalog = copy.deepcopy(self.catalog)
        catalog["modules"][0]["network"]["egressTo"].append(
            "public.example.com"
        )
        errors = self.validate_copy(catalog)
        self.assertTrue(
            any("unknown network target 'public.example.com'" in error for error in errors),
            errors,
        )

    def test_rejects_public_host_network_classification(self) -> None:
        catalog = copy.deepcopy(self.catalog)
        catalog["networkTargetRegistry"][0]["publicHostAllowed"] = True
        errors = self.validate_copy(catalog)
        self.assertTrue(
            any("public-host network targets are forbidden" in error for error in errors),
            errors,
        )

    def test_rejects_incompatible_operating_system_fact(self) -> None:
        catalog = copy.deepcopy(self.catalog)
        catalog["profileExamples"][0]["environmentFacts"][
            "operatingSystem"
        ] = "macos"
        errors = self.validate_copy(catalog)
        self.assertTrue(
            any("incompatible operating system" in error for error in errors),
            errors,
        )

    def test_rejects_missing_kubernetes_api_grant(self) -> None:
        catalog = copy.deepcopy(self.catalog)
        grants = catalog["profileExamples"][0]["environmentFacts"][
            "kubernetesApi"
        ]["grants"]
        grants.remove("CLUSTER_CONTROLLER")
        errors = self.validate_copy(catalog)
        self.assertTrue(
            any("missing Kubernetes API/RBAC grant" in error for error in errors),
            errors,
        )

    def test_rejects_incompatible_isolation_fact(self) -> None:
        catalog = copy.deepcopy(self.catalog)
        profile = next(
            item
            for item in catalog["profileExamples"]
            if item["id"] == "profile.governed-memory-dedicated-cluster"
        )
        profile["environmentFacts"]["isolation"] = "namespace"
        errors = self.validate_copy(catalog)
        self.assertTrue(
            any("isolation demand contradicts typed isolation facts" in error for error in errors),
            errors,
        )

    def test_rejects_missing_storage_mode_fact(self) -> None:
        catalog = copy.deepcopy(self.catalog)
        catalog["profileExamples"][0]["environmentFacts"]["storageModes"].remove(
            "PERSISTENT"
        )
        errors = self.validate_copy(catalog)
        self.assertTrue(
            any("missing storage mode" in error for error in errors),
            errors,
        )

    def test_rejects_missing_resource_class_fact(self) -> None:
        catalog = copy.deepcopy(self.catalog)
        classes = catalog["profileExamples"][0]["environmentFacts"][
            "resourceCapacity"
        ]["availableClasses"]
        classes.remove("MEDIUM")
        errors = self.validate_copy(catalog)
        self.assertTrue(
            any("missing resource class" in error for error in errors),
            errors,
        )

    def test_rejects_missing_network_locality_fact(self) -> None:
        catalog = copy.deepcopy(self.catalog)
        catalog["profileExamples"][0]["environmentFacts"][
            "networkLocalities"
        ].remove("TENANT_PRIVATE")
        errors = self.validate_copy(catalog)
        self.assertTrue(
            any("missing network locality" in error for error in errors),
            errors,
        )

    def test_rejects_missing_runtime_class_fact(self) -> None:
        catalog = copy.deepcopy(self.catalog)
        profile = next(
            item
            for item in catalog["profileExamples"]
            if item["id"] == "profile.governed-action-openshift"
        )
        profile["environmentFacts"]["runtimeClasses"].remove("kata")
        errors = self.validate_copy(catalog)
        self.assertTrue(
            any("missing runtime class" in error for error in errors),
            errors,
        )

    def test_planned_fixture_cannot_claim_locked_assurance_subjects(self) -> None:
        catalog = copy.deepcopy(self.catalog)
        subjects = catalog["profileExamples"][0]["assuranceSubjects"]
        subjects.update(
            {
                "subjectSetDigest": "sha256:" + "0" * 64,
                "digestStatus": "LOCKED",
                "signatureStatus": "VERIFIED",
            }
        )
        errors = self.validate_copy(catalog)
        self.assertTrue(
            any(
                "must not claim signed assurance subject evidence" in error
                for error in errors
            ),
            errors,
        )

    def test_assurance_subjects_activate_only_subject_conditional_dependencies(self) -> None:
        catalog = copy.deepcopy(self.catalog)
        profile = next(
            item
            for item in catalog["profileExamples"]
            if item["id"] == "profile.governed-memory-dedicated-cluster"
        )
        profile["assuranceSubjects"]["harnesses"].append(
            "knowledge.data-integration"
        )
        errors = self.validate_copy(catalog)
        self.assertTrue(
            any(
                "assurance subject selection activates conditional dependency"
                in error
                for error in errors
            ),
            errors,
        )

    def test_rejects_non_all_capability_provider_resolution(self) -> None:
        catalog = copy.deepcopy(self.catalog)
        catalog["capabilityProviders"][0]["resolution"] = "EXACTLY_ONE"
        errors = self.validate_copy(catalog)
        self.assertTrue(
            any("capabilityProviders resolution must be ALL" in error for error in errors),
            errors,
        )

    def test_rejects_provider_token_ownership_drift(self) -> None:
        catalog = copy.deepcopy(self.catalog)
        binding = catalog["capabilityProviders"][0]
        owner = binding["modules"][0]
        binding["modules"] = [
            module["id"]
            for module in catalog["modules"]
            if module["id"] != owner
        ][:1]
        errors = self.validate_copy(catalog)
        self.assertTrue(
            any("does not map to its owning module" in error for error in errors),
            errors,
        )

    def test_rejects_ambiguous_explicit_provider_selector(self) -> None:
        catalog = copy.deepcopy(self.catalog)
        group = next(
            item
            for item in catalog["providerExclusivityGroups"]
            if item["id"] == "group.infrastructure-provider"
        )
        group["selectors"].append(
            {
                "selectorCapability": "platform.provider.k3s",
                "memberId": "provider.runtime.infrastructure.kubernetes-upstream",
            }
        )
        errors = self.validate_copy(catalog)
        self.assertTrue(
            any(
                "selector capability 'platform.provider.k3s' maps to multiple members"
                in error
                for error in errors
            ),
            errors,
        )

    def test_rejects_denied_license_expression(self) -> None:
        catalog = copy.deepcopy(self.catalog)
        catalog["modules"][0]["license"]["spdx"] = ["SSPL-1.0"]
        errors = self.validate_copy(catalog)
        self.assertTrue(
            any("uses denied license expression" in error for error in errors),
            errors,
        )

    def test_rejects_missing_provider_edge_for_hard_service_dependency(self) -> None:
        catalog = copy.deepcopy(self.catalog)
        module = next(
            item
            for item in catalog["modules"]
            if item["id"] == "module.runtime.model-inference.inference-api"
        )
        module["dependencies"].remove("module.trust.security.guardrail-service")
        errors = self.validate_copy(catalog)
        self.assertTrue(
            any(
                "hard dependency guardrail-service is absent" in error
                for error in errors
            ),
            errors,
        )

if __name__ == "__main__":
    unittest.main()
