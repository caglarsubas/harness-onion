from __future__ import annotations

import importlib.util
import itertools
import json
import tempfile
import unittest
from pathlib import Path

import jsonschema
import yaml

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "readiness_validator",
    ROOT / "scripts/validate_readiness.py",
)
assert SPEC and SPEC.loader
VALIDATOR = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(VALIDATOR)

OWNERSHIP_SPEC = importlib.util.spec_from_file_location(
    "packet_ownership_validator",
    ROOT / "scripts/validate_packet_ownership.py",
)
assert OWNERSHIP_SPEC and OWNERSHIP_SPEC.loader
OWNERSHIP = importlib.util.module_from_spec(OWNERSHIP_SPEC)
OWNERSHIP_SPEC.loader.exec_module(OWNERSHIP)


def valid_packet_fixture() -> dict[str, object]:
    return {
        "id": "TEST-001",
        "repository": "Harness-Engineering",
        "branch": "codex/test-001",
        "objective": "Exercise one task-packet validation contract deterministically.",
        "predecessors": [],
        "allowedPaths": ["tests/"],
        "warmSourceAccess": "PROHIBITED_DURING_IMPLEMENTATION",
        "sourceReuse": [],
        "contracts": ["Consumes fixture contract"],
        "deliverables": ["One deterministic fixture."],
        "excluded": ["Production behavior."],
        "prefetchCommands": [],
        "offlineAcceptanceCommands": [["make", "test"]],
        "offlineExecution": {
            "wrapperArgv": ["./ci/verify-offline.sh"],
            "packetPathEnvironment": "HARNESS_TASK_PACKET",
            "packetPathMode": "HASH_PINNED_READ_ONCE_NO_CHILD_PATH",
            "commandTransport": "ARGV_ARRAY_V1",
            "isolation": "OS_ENFORCED_DENY_ALL_OUTBOUND",
            "sessionScope": "SINGLE_PROCESS_TREE",
            "prefetchOutsideSession": False,
            "offlineEnvironment": {
                "UV_OFFLINE": "1",
                "UV_FROZEN": "1",
                "UV_NO_SYNC": "1",
            },
        },
        "expectedEvidence": ["Schema decision."],
        "rollback": "Revert the fixture-only change.",
    }


def ownership_packet(
    packet_id: str,
    repository: str,
    *,
    predecessors: list[str] | None = None,
    allowed_paths: list[str] | None = None,
    commands: list[list[str]] | None = None,
) -> dict[str, object]:
    """Return the ownership fields consumed by the pure ownership validator."""

    return {
        "id": packet_id,
        "repository": repository,
        "predecessors": predecessors or [],
        "allowedPaths": allowed_paths or [],
        "sourceReuse": [],
        "prefetchCommands": [],
        "offlineAcceptanceCommands": commands or [],
    }


def provider_catalog_validation_errors(catalog: dict[str, object]) -> list[str]:
    schema = json.loads(
        (ROOT / "schemas/provider-module.schema.json").read_text(encoding="utf-8")
    )
    repositories = yaml.safe_load(
        (ROOT / "architecture/repositories.yaml").read_text(encoding="utf-8")
    )["repositories"]
    services = yaml.safe_load(
        (ROOT / "architecture/services.yaml").read_text(encoding="utf-8")
    )["services"]
    validation = VALIDATOR.Validation()
    VALIDATOR.validate_provider_catalog_data(
        validation,
        catalog,
        schema,
        {repository["name"] for repository in repositories},
        {service["id"] for service in services},
    )
    return validation.errors


class ValidatorUnitTest(unittest.TestCase):
    def test_packet_make_descriptor_is_exact_and_packet_local(self) -> None:
        packet = ownership_packet(
            "CON-002",
            "mas-harness-contracts",
            allowed_paths=["ci/targets/con-003.json"],
            commands=[["make", "contract-test"]],
        )
        errors = OWNERSHIP.validate_packet_ownership({"CON-002": packet})
        self.assertTrue(
            any("ci/targets/con-002.json" in error for error in errors), errors
        )

    def test_packet_make_argv_rejects_unknown_or_unsafe_variables(self) -> None:
        _, unknown_errors = OWNERSHIP.parse_make_command(
            "TEST-001", ["/usr/bin/make", "test", "TOKEN=value"]
        )
        _, unsafe_errors = OWNERSHIP.parse_make_command(
            "TEST-001", ["make", "test", "CAMPAIGN=value;id"]
        )
        _, missing_errors = OWNERSHIP.parse_make_command("TEST-001", ["make"])
        self.assertTrue(any("not declared" in error for error in unknown_errors))
        self.assertTrue(any("not a safe" in error for error in unsafe_errors))
        self.assertTrue(any("name exactly one target" in error for error in missing_errors))

    def test_generic_conformance_targets_require_conf_001_ancestor(self) -> None:
        consumer = ownership_packet(
            "CONF-A1-001",
            "mas-harness-conformance-labs",
            allowed_paths=["campaigns/alpha1/"],
            commands=[["make", "campaign", "CAMPAIGN=alpha1"]],
        )
        errors = OWNERSHIP.validate_packet_ownership({"CONF-A1-001": consumer})
        self.assertIn(
            "generic conformance packet CONF-A1-001 must depend transitively on CONF-001",
            errors,
        )

    def test_harnessctl_owner_requires_exact_descriptor(self) -> None:
        owner = ownership_packet(
            "CON-002",
            "mas-harness-contracts",
            allowed_paths=["src/planeon_harness_contracts/commands/catalog.json"],
            commands=[
                [
                    "uv",
                    "run",
                    "--offline",
                    "--frozen",
                    "--no-sync",
                    "harnessctl",
                    "validate",
                    "catalog/",
                ]
            ],
        )
        errors = OWNERSHIP.validate_packet_ownership({"CON-002": owner})
        self.assertTrue(
            any("commands/validate.json" in error for error in errors), errors
        )

    def test_harnessctl_consumer_requires_owner_predecessor_closure(self) -> None:
        owner = ownership_packet(
            "CON-002",
            "mas-harness-contracts",
            allowed_paths=[
                "src/planeon_harness_contracts/commands/validate.json",
                "src/planeon_harness_contracts/commands/catalog.json",
            ],
        )
        consumer = ownership_packet(
            "CON-004",
            "mas-harness-contracts",
            commands=[["harnessctl", "validate", "catalog/"]],
        )
        errors = OWNERSHIP.validate_packet_ownership(
            {"CON-002": owner, "CON-004": consumer}
        )
        self.assertIn(
            "packet CON-004 invokes harnessctl validate outside owner predecessor closure",
            errors,
        )

    def test_unordered_same_repository_path_overlap_is_rejected(self) -> None:
        packets = {
            "CON-002": ownership_packet(
                "CON-002",
                "mas-harness-contracts",
                allowed_paths=["schemas/shared/"],
            ),
            "CON-003": ownership_packet(
                "CON-003",
                "mas-harness-contracts",
                allowed_paths=["schemas/shared/example.json"],
            ),
        }
        errors = OWNERSHIP.validate_packet_ownership(packets)
        self.assertTrue(any("overlap" in error for error in errors), errors)

    def test_ordinary_packet_cannot_own_bootstrap_porting_ledger(self) -> None:
        packet = ownership_packet(
            "CON-002",
            "mas-harness-contracts",
            allowed_paths=["PORTING.yaml"],
        )
        errors = OWNERSHIP.validate_packet_ownership({"CON-002": packet})
        self.assertIn(
            "ordinary packet CON-002 may not own bootstrap PORTING.yaml", errors
        )

    def test_json_authority_loader_rejects_duplicate_members(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            path = Path(temporary_directory) / "duplicate.json"
            path.write_text('{"authority":1,"authority":2}', encoding="utf-8")
            with self.assertRaises(VALIDATOR.DuplicateJsonKeyError):
                VALIDATOR.load_json(path)

    def test_yaml_authority_loader_rejects_duplicate_keys(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            path = Path(temporary_directory) / "duplicate.yaml"
            path.write_text("authority: 1\nauthority: 2\n", encoding="utf-8")
            with self.assertRaises(VALIDATOR.DuplicateYamlKeyError):
                VALIDATOR.load_yaml(path)

    def test_dependency_reducer_is_order_independent_and_recovery_never_promotes(self) -> None:
        blocked = {
            "edgeKey": "consumer+database",
            "edgeContribution": {
                "severity": "BLOCKED",
                "observedStateEffect": "BLOCKED",
                "readinessEffect": "NOT_READY",
                "desiredStateAction": "NO_CHANGE",
            },
            "workAction": "BLOCK_START",
            "reason": "DependencyControlNotReady",
        }
        degraded = {
            "edgeKey": "consumer+telemetry",
            "edgeContribution": {
                "severity": "DEGRADED",
                "observedStateEffect": "DEGRADED",
                "readinessEffect": "POLICY_CONTROLLED",
                "desiredStateAction": "NO_CHANGE",
            },
            "workAction": "APPLY_DEGRADATION_POLICY",
            "reason": "DependencyDegraded",
        }
        restored = {
            "edgeKey": "fixture-dependency-edge-restored",
            "edgeContribution": {
                "severity": "READY",
                "observedStateEffect": "NO_CHANGE",
                "readinessEffect": "NO_CHANGE",
                "desiredStateAction": "NO_CHANGE",
            },
            "workAction": "RECOMPUTE_FROM_DEPENDENCY_SNAPSHOT",
            "reason": "DependencyArtifactRestored",
        }
        results = {
            json.dumps(
                VALIDATOR.reduce_dependency_contributions(list(order)),
                sort_keys=True,
            )
            for order in itertools.permutations([blocked, degraded, restored])
        }
        self.assertEqual(1, len(results))
        aggregate = VALIDATOR.reduce_dependency_contributions(
            [blocked, degraded, restored]
        )
        self.assertEqual("BLOCKED", aggregate["severity"])
        self.assertEqual("NOT_READY", aggregate["readinessEffect"])
        self.assertNotEqual("NO_CHANGE", aggregate["observedStateEffect"])

    def test_dependency_reducer_covers_immediate_disable_and_artifact_invalidation(self) -> None:
        disabled = {
            "edgeKey": "consumer+optional-model",
            "edgeContribution": {
                "severity": "DEGRADED",
                "observedStateEffect": "DEGRADED",
                "readinessEffect": "POLICY_CONTROLLED",
                "desiredStateAction": "NO_CHANGE",
            },
            "workAction": "APPLY_DEGRADATION_POLICY",
            "reason": "DependencyCapabilityDisabled",
        }
        invalidated_artifact = {
            "edgeKey": "consumer+required-artifact",
            "edgeContribution": {
                "severity": "DEGRADED",
                "observedStateEffect": "DEGRADED",
                "readinessEffect": "NOT_READY",
                "desiredStateAction": "NO_CHANGE",
            },
            "workAction": "REJECT_NEW_AND_COMPENSATE",
            "reason": "DependencyArtifactInvalidated",
        }
        restored = {
            "edgeKey": "consumer+optional-model",
            "edgeContribution": {
                "severity": "READY",
                "observedStateEffect": "NO_CHANGE",
                "readinessEffect": "NO_CHANGE",
                "desiredStateAction": "NO_CHANGE",
            },
            "workAction": "RESTORE_OPTIONAL_CAPABILITY_AND_RECOMPUTE",
            "reason": "OptionalCapabilityRestored",
        }

        disabled_result = VALIDATOR.reduce_dependency_contributions([disabled])
        self.assertEqual("DEGRADED", disabled_result["severity"])
        self.assertEqual("POLICY_CONTROLLED", disabled_result["readinessEffect"])
        invalidated_result = VALIDATOR.reduce_dependency_contributions(
            [invalidated_artifact, restored]
        )
        self.assertEqual("DEGRADED", invalidated_result["severity"])
        self.assertEqual("NOT_READY", invalidated_result["readinessEffect"])
        self.assertIn("REJECT_NEW_AND_COMPENSATE", invalidated_result["workActions"])

    def test_packet_id_extraction_uses_canonical_id_not_slug(self) -> None:
        text = "`MET-001-foundation` `MODEL-OLLAMA-001` `codex/met-001`"
        self.assertEqual(
            ["MET-001", "MODEL-OLLAMA-001"],
            VALIDATOR.extract_packet_ids(text),
        )

    def test_cycle_detection_reports_all_remaining_nodes(self) -> None:
        validation = VALIDATOR.Validation()
        VALIDATOR.assert_acyclic(
            validation,
            {"a", "b", "c"},
            {"a": ["b"], "b": ["a"], "c": []},
            "fixture",
        )
        self.assertEqual(["fixture dependency cycle: a, b"], validation.errors)

    def test_task_schema_rejects_old_multi_packet_wrapper(self) -> None:
        schema = json.loads(
            (ROOT / "schemas/task-packet.schema.json").read_text(encoding="utf-8")
        )
        with self.assertRaises(jsonschema.ValidationError):
            jsonschema.validate({"packets": []}, schema)

    def test_task_schema_rejects_mutable_source_reference(self) -> None:
        schema = json.loads(
            (ROOT / "schemas/task-packet.schema.json").read_text(encoding="utf-8")
        )
        packet = valid_packet_fixture()
        packet["sourceReuse"] = [
            {
                "repository": "git@example.invalid/source.git",
                "commit": "main",
                "reuseMode": "REFERENCE_ONLY",
                "paths": ["src/example.py"],
                "strategy": "Reference the exact source blob without modification.",
            }
        ]
        with self.assertRaises(jsonschema.ValidationError):
            jsonschema.validate(packet, schema)

    def test_task_schema_rejects_legacy_acceptance_commands(self) -> None:
        schema = json.loads(
            (ROOT / "schemas/task-packet.schema.json").read_text(encoding="utf-8")
        )
        packet = valid_packet_fixture()
        packet["acceptanceCommands"] = ["make verify-offline"]

        with self.assertRaises(jsonschema.ValidationError):
            jsonschema.validate(packet, schema)

    def test_task_schema_rejects_prefetch_smuggled_into_offline_commands(self) -> None:
        schema = json.loads(
            (ROOT / "schemas/task-packet.schema.json").read_text(encoding="utf-8")
        )
        packet = valid_packet_fixture()
        packet["offlineAcceptanceCommands"] = [
            ["make", "test"],
            ["make", "prefetch"],
        ]

        with self.assertRaises(jsonschema.ValidationError):
            jsonschema.validate(packet, schema)

    def test_task_schema_closes_live_campaign_network_authority(self) -> None:
        schema = json.loads(
            (ROOT / "schemas/task-packet.schema.json").read_text(encoding="utf-8")
        )
        packet = valid_packet_fixture()
        packet["liveCampaignExecution"] = {
            **VALIDATOR.LIVE_CAMPAIGN_EXECUTION_BASE,
            "allowedEvidenceAxes": ["RUNTIME", "ASSURANCE"],
            "commands": packet["offlineAcceptanceCommands"],
        }
        jsonschema.validate(packet, schema)

        packet["liveCampaignExecution"]["networkIsolation"] = "ALLOW_PUBLIC_EGRESS"
        with self.assertRaises(jsonschema.ValidationError):
            jsonschema.validate(packet, schema)

    def test_task_schema_closes_reference_observation_authority(self) -> None:
        schema = json.loads(
            (ROOT / "schemas/task-packet.schema.json").read_text(encoding="utf-8")
        )
        packet = valid_packet_fixture()
        packet["warmSourceAccess"] = "AUTHORIZED_READ_ONLY_OBSERVATION"
        packet["referenceObservationExecution"] = {
            **VALIDATOR.REFERENCE_OBSERVATION_EXECUTION_BASE,
            "repository": "git@github.com:caglarsubas/data-source-harness.git",
            "commit": "858281f4b845ffacfe05cdb2c40a402c237d4c54",
            "sourcePaths": VALIDATOR.DATA_HARNESS_V1_OBSERVATION_PATHS,
            "outputPath": "architecture/observations/data-harness-v1.json",
        }
        jsonschema.validate(packet, schema)

        packet["referenceObservationExecution"]["sourceCodeExecution"] = "ALLOWED"
        with self.assertRaises(jsonschema.ValidationError):
            jsonschema.validate(packet, schema)

    def test_task_schema_closes_full_tree_metadata_observation(self) -> None:
        schema = json.loads(
            (ROOT / "schemas/task-packet.schema.json").read_text(encoding="utf-8")
        )
        packet = valid_packet_fixture()
        packet["warmSourceAccess"] = "AUTHORIZED_READ_ONLY_OBSERVATION"
        packet["referenceObservationExecution"] = {
            **VALIDATOR.TREE_OBSERVATION_EXECUTION_BASE,
            **VALIDATOR.TREE_OBSERVATION_PACKETS["MET-OBS-AH-001"],
        }
        jsonschema.validate(packet, schema)

        widened = json.loads(json.dumps(packet))
        widened["referenceObservationExecution"]["sourcePaths"] = ["README.md"]
        with self.assertRaises(jsonschema.ValidationError):
            jsonschema.validate(widened, schema)

        content_read = json.loads(json.dumps(packet))
        content_read["referenceObservationExecution"]["sourceFilesystem"] = (
            "DECLARED_BLOBS_READ_METADATA_ONLY_ALL_WRITE_DENIED"
        )
        with self.assertRaises(jsonschema.ValidationError):
            jsonschema.validate(content_read, schema)

    def test_task_schema_rejects_observation_authority_on_implementation_packet(self) -> None:
        schema = json.loads(
            (ROOT / "schemas/task-packet.schema.json").read_text(encoding="utf-8")
        )
        packet = valid_packet_fixture()
        packet["referenceObservationExecution"] = {
            **VALIDATOR.REFERENCE_OBSERVATION_EXECUTION_BASE,
            "repository": "git@github.com:caglarsubas/data-source-harness.git",
            "commit": "858281f4b845ffacfe05cdb2c40a402c237d4c54",
            "sourcePaths": VALIDATOR.DATA_HARNESS_V1_OBSERVATION_PATHS,
            "outputPath": "architecture/observations/data-harness-v1.json",
        }

        with self.assertRaises(jsonschema.ValidationError):
            jsonschema.validate(packet, schema)

    def test_task_schema_rejects_repository_live_launcher(self) -> None:
        schema = json.loads(
            (ROOT / "schemas/task-packet.schema.json").read_text(encoding="utf-8")
        )
        packet = valid_packet_fixture()
        packet["liveCampaignExecution"] = {
            **VALIDATOR.LIVE_CAMPAIGN_EXECUTION_BASE,
            "allowedEvidenceAxes": ["RUNTIME", "ASSURANCE"],
            "commands": packet["offlineAcceptanceCommands"],
        }
        packet["liveCampaignExecution"]["launcherArgv"] = [
            "./ci/verify-live-campaign.sh"
        ]

        with self.assertRaises(jsonschema.ValidationError):
            jsonschema.validate(packet, schema)

    def test_task_schema_rejects_incomplete_live_trust_binding(self) -> None:
        schema = json.loads(
            (ROOT / "schemas/task-packet.schema.json").read_text(encoding="utf-8")
        )
        packet = valid_packet_fixture()
        packet["liveCampaignExecution"] = {
            **VALIDATOR.LIVE_CAMPAIGN_EXECUTION_BASE,
            "allowedEvidenceAxes": ["RUNTIME", "ASSURANCE"],
            "commands": packet["offlineAcceptanceCommands"],
        }
        del packet["liveCampaignExecution"]["tenantTrustStoreMount"]

        with self.assertRaises(jsonschema.ValidationError):
            jsonschema.validate(packet, schema)

    def test_task_schema_rejects_widened_live_mutation_authority(self) -> None:
        schema = json.loads(
            (ROOT / "schemas/task-packet.schema.json").read_text(encoding="utf-8")
        )
        packet = valid_packet_fixture()
        packet["liveCampaignExecution"] = {
            **VALIDATOR.LIVE_CAMPAIGN_EXECUTION_BASE,
            "allowedEvidenceAxes": ["RUNTIME", "ASSURANCE"],
            "commands": packet["offlineAcceptanceCommands"],
        }
        packet["liveCampaignExecution"]["mutationAdmission"] = "TENANT_ATTESTED"

        with self.assertRaises(jsonschema.ValidationError):
            jsonschema.validate(packet, schema)

    def test_task_schema_rejects_live_tenant_acceptance_axis(self) -> None:
        schema = json.loads(
            (ROOT / "schemas/task-packet.schema.json").read_text(encoding="utf-8")
        )
        packet = valid_packet_fixture()
        packet["liveCampaignExecution"] = {
            **VALIDATOR.LIVE_CAMPAIGN_EXECUTION_BASE,
            "allowedEvidenceAxes": ["ASSURANCE", "TENANT_ACCEPTANCE"],
            "commands": packet["offlineAcceptanceCommands"],
        }

        with self.assertRaises(jsonschema.ValidationError):
            jsonschema.validate(packet, schema)

    def test_task_schema_rejects_tree_as_port_candidate(self) -> None:
        schema = json.loads(
            (ROOT / "schemas/task-packet.schema.json").read_text(encoding="utf-8")
        )
        packet = valid_packet_fixture()
        packet["sourceReuse"] = [
            {
                "repository": "git@example.invalid/source.git",
                "commit": "0" * 40,
                "reuseMode": "PORT_CANDIDATE",
                "paths": ["src/"],
                "strategy": "Copy only after the exact blob is COPY_AUTHORIZED.",
            }
        ]

        with self.assertRaises(jsonschema.ValidationError):
            jsonschema.validate(packet, schema)

    def test_closed_service_schema_rejects_nested_unknown_property(self) -> None:
        schema = json.loads(
            (ROOT / "schemas/services.schema.json").read_text(encoding="utf-8")
        )
        catalog = yaml.safe_load(
            (ROOT / "architecture/services.yaml").read_text(encoding="utf-8")
        )
        catalog["services"][0]["stateBehavior"]["unknownStateClaim"] = True

        with self.assertRaises(jsonschema.ValidationError):
            jsonschema.validate(catalog, schema)

    def test_service_schema_rejects_prose_dependency_propagation(self) -> None:
        schema = json.loads(
            (ROOT / "schemas/services.schema.json").read_text(encoding="utf-8")
        )
        catalog = yaml.safe_load(
            (ROOT / "architecture/services.yaml").read_text(encoding="utf-8")
        )
        catalog["dependencyStatePropagation"][0] = {
            "rule": "required-artifact-unverified",
            "effect": "arbitrary prose",
        }

        with self.assertRaises(jsonschema.ValidationError):
            jsonschema.validate(catalog, schema)

    def test_service_schema_rejects_unpermitted_selected_failure_trigger(self) -> None:
        schema = json.loads(
            (ROOT / "schemas/services.schema.json").read_text(encoding="utf-8")
        )
        catalog = yaml.safe_load(
            (ROOT / "architecture/services.yaml").read_text(encoding="utf-8")
        )
        catalog["dependencyStatePropagation"][0]["trigger"] = {
            "mode": "ARTIFACT",
            "requirement": "REQUIRED",
            "event": "UNVERIFIED",
            "phase": "ANY",
            "degradationBudget": "NOT_APPLICABLE",
        }

        with self.assertRaises(jsonschema.ValidationError):
            jsonschema.validate(catalog, schema)

    def test_taxonomy_schema_rejects_untrusted_or_partial_production_evidence(self) -> None:
        schema = json.loads(
            (ROOT / "schemas/taxonomy.schema.json").read_text(encoding="utf-8")
        )
        taxonomy = yaml.safe_load(
            (ROOT / "architecture/taxonomy.yaml").read_text(encoding="utf-8")
        )
        taxonomy["productionGates"][0]["trustedProducer"][
            "signatureRequired"
        ] = False

        with self.assertRaises(jsonschema.ValidationError):
            jsonschema.validate(taxonomy, schema)

    def test_taxonomy_schema_rejects_waiver_as_production_satisfaction(self) -> None:
        schema = json.loads(
            (ROOT / "schemas/taxonomy.schema.json").read_text(encoding="utf-8")
        )
        taxonomy = yaml.safe_load(
            (ROOT / "architecture/taxonomy.yaml").read_text(encoding="utf-8")
        )
        satisfaction = taxonomy["productionGates"][0]["controlSatisfaction"]
        satisfaction["waiverSatisfiesPromotion"] = True
        satisfaction["waiverEffect"] = "SATISFIES_CONTROL"

        with self.assertRaises(jsonschema.ValidationError):
            jsonschema.validate(taxonomy, schema)

    def test_porting_authorization_is_fail_closed_until_verifier_version(self) -> None:
        schema = json.loads(
            (ROOT / "schemas/porting-authorization.schema.json").read_text(
                encoding="utf-8"
            )
        )
        index = yaml.safe_load(
            (ROOT / "architecture/porting-authorization-index.yaml").read_text(
                encoding="utf-8"
            )
        )
        index["authorizations"].append({"authorizationId": "PA-FORGE-001"})

        with self.assertRaises(jsonschema.ValidationError):
            jsonschema.validate(index, schema)

    def test_schema_instance_validation_enforces_date_time_format(self) -> None:
        schema = {
            "$schema": "https://json-schema.org/draft/2020-12/schema",
            "type": "object",
            "required": ["approvedAt"],
            "properties": {
                "approvedAt": {"type": "string", "format": "date-time"}
            },
        }
        with tempfile.TemporaryDirectory() as temporary_directory:
            schema_path = Path(temporary_directory) / "schema.json"
            schema_path.write_text(json.dumps(schema), encoding="utf-8")
            validation = VALIDATOR.Validation()
            VALIDATOR.validate_schema_instance(
                validation,
                schema_path,
                {"approvedAt": "not-a-date"},
                "format fixture",
            )

        self.assertTrue(
            any("not a 'date-time'" in error for error in validation.errors),
            validation.errors,
        )

    def test_dependency_graph_schema_rejects_free_form_branch_predicate(self) -> None:
        schema = json.loads(
            (ROOT / "schemas/dependency-graph.schema.json").read_text(
                encoding="utf-8"
            )
        )
        graph = yaml.safe_load(
            (ROOT / "architecture/dependency-graph.yaml").read_text(
                encoding="utf-8"
            )
        )
        graph["runtimeRequestGraph"]["branches"][0]["selectedWhen"] = (
            "signedRoute.kind == direct-model"
        )

        with self.assertRaises(jsonschema.ValidationError):
            jsonschema.validate(graph, schema)

    def test_capability_reference_validator_rejects_unregistered_id(self) -> None:
        validation = VALIDATOR.Validation()
        VALIDATOR.validate_selection_predicate_references(
            validation,
            {"anyOfCapabilities": ["local.alias"]},
            "fixture predicate",
            {"registered.capability"},
        )

        self.assertEqual(
            ["fixture predicate references unregistered capability 'local.alias'"],
            validation.errors,
        )

    def test_provider_implementation_ownership_records_are_closed(self) -> None:
        schema = json.loads(
            (ROOT / "schemas/provider-module.schema.json").read_text(encoding="utf-8")
        )
        catalog = yaml.safe_load(
            (ROOT / "architecture/providers.yaml").read_text(encoding="utf-8")
        )
        catalog["implementationOwnership"]["module.platform.contracts"][
            "undeclaredAuthority"
        ] = True

        with self.assertRaises(jsonschema.ValidationError):
            jsonschema.validate(catalog, schema)

    def test_provider_implementation_ownership_requires_complete_packet_coverage(
        self,
    ) -> None:
        catalog = yaml.safe_load(
            (ROOT / "architecture/providers.yaml").read_text(encoding="utf-8")
        )
        del catalog["implementationOwnership"]["module.platform.contracts"]
        errors = provider_catalog_validation_errors(catalog)
        self.assertTrue(
            any("must cover every module exactly once" in error for error in errors),
            errors,
        )

        catalog = yaml.safe_load(
            (ROOT / "architecture/providers.yaml").read_text(encoding="utf-8")
        )
        ownership = catalog["implementationOwnership"]["module.platform.contracts"]
        ownership["path"] = "outside/packet/authority/"
        errors = provider_catalog_validation_errors(catalog)
        self.assertTrue(
            any("is not covered by packet CON-001 allowedPaths" in error for error in errors),
            errors,
        )

        catalog = yaml.safe_load(
            (ROOT / "architecture/providers.yaml").read_text(encoding="utf-8")
        )
        ownership = catalog["implementationOwnership"]["module.platform.contracts"]
        ownership["packetId"] = "SDK-001"
        errors = provider_catalog_validation_errors(catalog)
        self.assertTrue(
            any("has the wrong repository owner" in error for error in errors),
            errors,
        )

    def test_provider_implementation_ownership_rejects_false_deliverables_and_contract_selection(
        self,
    ) -> None:
        catalog = yaml.safe_load(
            (ROOT / "architecture/providers.yaml").read_text(encoding="utf-8")
        )
        ownership = catalog["implementationOwnership"]["module.platform.contracts"]
        ownership["deliverableIndex"] = 99
        errors = provider_catalog_validation_errors(catalog)
        self.assertTrue(
            any("does not contain deliverable index 99" in error for error in errors),
            errors,
        )

        catalog = yaml.safe_load(
            (ROOT / "architecture/providers.yaml").read_text(encoding="utf-8")
        )
        catalog["profileExamples"][0]["selectedModules"].append(
            "provider.planeon.qdrant"
        )
        errors = provider_catalog_validation_errors(catalog)
        self.assertTrue(
            any("cannot be contract-only while selected" in error for error in errors),
            errors,
        )

    def test_workflow_validator_rejects_dynamic_runner_and_missing_offline_gate(self) -> None:
        workflow = """\
name: unsafe-fixture
on:
  pull_request:
permissions:
  contents: read
jobs:
  verify:
    runs-on: [self-hosted, "${{ inputs.runner }}"]
    steps:
      - run: python3 scripts/validate_readiness.py
"""
        with tempfile.TemporaryDirectory() as temporary_directory:
            path = Path(temporary_directory) / "unsafe.yml"
            path.write_text(workflow, encoding="utf-8")
            validation = VALIDATOR.Validation()
            VALIDATOR.validate_workflow(validation, path)

        self.assertTrue(
            any("computes runner labels dynamically" in error for error in validation.errors)
        )
        self.assertTrue(
            any("does not block untrusted fork execution" in error for error in validation.errors)
        )
        self.assertTrue(
            any("must execute only the preinstalled absolute host launcher" in error for error in validation.errors)
        )

    def test_workflow_validator_rejects_repository_python_before_isolation(self) -> None:
        workflow = """\
name: unsafe-pre-isolation-fixture
on:
  workflow_dispatch:
permissions:
  contents: read
jobs:
  verify:
    runs-on: [self-hosted, harness-engineering, ephemeral, credential-free]
    steps:
      - uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683
        with:
          persist-credentials: false
          fetch-depth: 1
      - run: python3 -m unittest ci/test_offline_runner.py
      - run: /opt/planeon/bin/harness-offline-launch
"""
        with tempfile.TemporaryDirectory() as temporary_directory:
            path = Path(temporary_directory) / "unsafe-python.yml"
            path.write_text(workflow, encoding="utf-8")
            validation = VALIDATOR.Validation()
            VALIDATOR.validate_workflow(validation, path)

        self.assertTrue(
            any("must execute only the preinstalled absolute host launcher" in error for error in validation.errors),
            validation.errors,
        )
        self.assertTrue(
            any("must contain only pinned checkout" in error for error in validation.errors),
            validation.errors,
        )

    def test_workflow_validator_rejects_generic_self_hosted_runner(self) -> None:
        workflow = """\
name: generic-runner-fixture
on:
  workflow_dispatch:
permissions:
  contents: read
jobs:
  verify:
    runs-on: [self-hosted, harness-engineering]
    steps:
      - uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683
        with:
          persist-credentials: false
          fetch-depth: 1
      - run: /opt/planeon/bin/harness-offline-launch
"""
        with tempfile.TemporaryDirectory() as temporary_directory:
            path = Path(temporary_directory) / "generic-runner.yml"
            path.write_text(workflow, encoding="utf-8")
            validation = VALIDATOR.Validation()
            VALIDATOR.validate_workflow(validation, path)

        self.assertTrue(
            any(
                "closed ephemeral credential-free runner labels" in error
                for error in validation.errors
            ),
            validation.errors,
        )

    def test_trusted_runner_manifest_schema_is_closed_and_fail_closed(self) -> None:
        schema = json.loads(
            (ROOT / "schemas/trusted-runner-manifest.schema.json").read_text(
                encoding="utf-8"
            )
        )
        invalid = {
            "schemaVersion": "harness.planeon.ai/trusted-runner-manifest/v1alpha1",
            "launcher": {
                "path": "/opt/planeon/bin/harness-offline-launch",
                "version": "1.0.0",
                "sha256": "0" * 64,
                "ownerUid": 0,
                "ownerGid": 0,
                "mode": "0555",
            },
            "runner": {
                "requiredLabels": ["self-hosted", "harness-engineering"],
                "ephemeral": True,
                "ambientCloudCredentials": False,
                "sshAgent": False,
                "kubeconfig": False,
                "containerControlSockets": [],
                "billableBrokers": [],
            },
        }
        with self.assertRaises(jsonschema.ValidationError):
            jsonschema.validate(invalid, schema)

    def test_workflow_validator_rejects_secrets_and_unvalidated_local_actions(self) -> None:
        workflow = """\
name: unsafe-supply-chain-fixture
on:
  workflow_dispatch:
permissions:
  contents: read
jobs:
  verify:
    runs-on: [self-hosted, harness-engineering, ephemeral, credential-free]
    env:
      PROVIDER_API_KEY: ${{ secrets.PROVIDER_API_KEY }}
    steps:
      - uses: ./unsafe-local-action
      - run: make verify-offline
"""
        with tempfile.TemporaryDirectory() as temporary_directory:
            path = Path(temporary_directory) / "unsafe-supply-chain.yml"
            path.write_text(workflow, encoding="utf-8")
            validation = VALIDATOR.Validation()
            VALIDATOR.validate_workflow(validation, path)

        self.assertTrue(
            any("references a GitHub or provider secret" in error for error in validation.errors),
            validation.errors,
        )
        self.assertTrue(
            any("unvalidated local action" in error for error in validation.errors),
            validation.errors,
        )
        self.assertTrue(
            any("prohibited credential environment" in error for error in validation.errors),
            validation.errors,
        )


if __name__ == "__main__":
    unittest.main()
