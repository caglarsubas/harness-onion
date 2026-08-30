#!/usr/bin/env python3
"""Validate the MET-001 architecture authorities and print deterministic evidence."""

from __future__ import annotations

import argparse
import hashlib
import heapq
import json
import re
import sys
from dataclasses import dataclass
from importlib.metadata import PackageNotFoundError, version
from pathlib import Path
from typing import Any, Iterable

import jsonschema
import yaml


ROOT = Path(__file__).resolve().parents[1]

EXPECTED_PACKAGES = {
    "PyYAML": "6.0.2",
    "jsonschema": "4.24.0",
    "pytest": "8.4.2",
}

EXPECTED_BASE_SOURCES = {
    "chatgpt-deep-research": (
        "225d1ebbd4f8a9de93efdb0dd78a4f576ebe56f96c21f43551d379c34cd844ef",
        "ecosystem-and-implementation-research",
    ),
    "claude-harness-compass": (
        "bcee4ea4d8a2acf7bd7f51ae5b1297036010ff23186b5a59c6c506eef4358d31",
        "taxonomy-and-composition-research",
    ),
    "enterprise-mas-presentation": (
        "54e6547fa091526d2d00e4444b9c4c3dbe1b146a4cb9eddb1096e38f75f02846",
        "architecture-synthesis-research",
    ),
    "gemini-mas-composition": (
        "70d38e233ebd6e0e31711f22e6596a5b4fe9f89843230f1e8a7f80eac5927dde",
        "multi-agent-architecture-research",
    ),
    "harness-onion-raster": (
        "15f756acd35af7d42e02000ac7ec78a4818e240e0a4c68462c48d449d1236bea",
        "tenant-overview-visual-reference",
    ),
    "harness-onion-vector": (
        "2981a007b072e6f21a3455c5200862042e20ac9c761cbce571f1f605238759a4",
        "tenant-overview-navigation-design-reference",
    ),
}

EXPECTED_REPOSITORIES = {
    "harness-engineering": "Harness-Engineering",
    "contracts": "mas-harness-contracts",
    "sdks": "mas-harness-sdks",
    "industry-packs": "mas-harness-industry-packs",
    "control-plane": "mas-harness-control-plane",
    "runtime-plane": "mas-harness-runtime-plane",
    "model-plane": "mas-harness-model-plane",
    "knowledge-plane": "mas-harness-knowledge-plane",
    "execution-plane": "mas-harness-execution-plane",
    "trust-plane": "mas-harness-trust-plane",
    "operator": "mas-harness-operator",
    "distribution": "mas-harness-distribution",
    "conformance-labs": "mas-harness-conformance-labs",
}

EXPECTED_HARNESSES = {
    "runtime.infrastructure": "operator",
    "runtime.model-inference": "model-plane",
    "runtime.ai-gateway": "runtime-plane",
    "runtime.experience": "runtime-plane",
    "knowledge.domain-semantic": "knowledge-plane",
    "knowledge.data-integration": "knowledge-plane",
    "knowledge.retrieval-context": "knowledge-plane",
    "knowledge.memory-state": "knowledge-plane",
    "execution.protocol-interoperability": "execution-plane",
    "execution.orchestration": "execution-plane",
    "execution.tool-skill-sandbox": "execution-plane",
    "execution.ml-decision": "execution-plane",
    "trust.security-safety": "trust-plane",
    "trust.governance-agentops": "trust-plane",
    "trust.observability-finops": "trust-plane",
    "trust.evaluation-assurance": "trust-plane",
}

EXPECTED_SCHEMA_FILES = {
    "taxonomy": "taxonomy.schema.json",
    "repositories": "repositories.schema.json",
    "services": "services.schema.json",
    "dependency-graph": "dependency-graph.schema.json",
    "providers": "provider-module.schema.json",
}

EXPECTED_REPOSITORY_GRAPHS = {
    "contractSource",
    "buildArtifact",
    "releaseSet",
    "runtimeIntegration",
}

EXPECTED_DEPLOYMENT_MODES = {
    "operator-hosted-saas",
    "tenant-public-cloud",
    "self-managed",
    "air-gapped",
}

ALLOWED_PLATFORM_HARNESSES = {
    "platform.conformance",
    "platform.contracts",
    "platform.control-plane",
    "platform.distribution",
    "platform.external-prerequisite",
    "platform.guidance",
    "platform.meta",
    "platform.sdk",
}

ALLOWED_COST_DISPOSITIONS = {
    "SELF_HOSTED_OPEN_SOURCE_NON_METERED",
    "TENANT_SUPPLIED_OPEN_SOURCE_NON_METERED",
}

SHA256_PATTERN = re.compile(r"^[0-9a-f]{64}$")


class ArchitectureValidationError(ValueError):
    """Raised when a MET-001 authority is malformed or internally inconsistent."""


class DuplicateYamlKeyError(ArchitectureValidationError):
    """Raised when a YAML mapping repeats a key."""


class DuplicateJsonKeyError(ArchitectureValidationError):
    """Raised when a JSON mapping repeats a key."""


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
        raise ArchitectureValidationError(f"cannot read YAML authority {path}: {exc}") from exc
    if not isinstance(value, dict):
        raise ArchitectureValidationError(f"YAML authority must be a mapping: {path}")
    return value


def load_json(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(
            path.read_text(encoding="utf-8"),
            object_pairs_hook=_unique_json_object,
        )
    except (OSError, json.JSONDecodeError) as exc:
        raise ArchitectureValidationError(f"cannot read JSON authority {path}: {exc}") from exc
    if not isinstance(value, dict):
        raise ArchitectureValidationError(f"JSON authority must be an object: {path}")
    return value


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise ArchitectureValidationError(message)


def _require_unique_strings(values: Any, label: str) -> list[str]:
    _require(
        isinstance(values, list) and all(isinstance(item, str) and item for item in values),
        f"{label} must be a list of non-empty strings",
    )
    _require(len(values) == len(set(values)), f"{label} contains duplicates")
    return values


def _validate_toolchain() -> None:
    _require(
        sys.version_info[:2] == (3, 12),
        f"Python 3.12 required, found {sys.version.split()[0]}",
    )
    for package, expected in EXPECTED_PACKAGES.items():
        try:
            actual = version(package)
        except PackageNotFoundError as exc:
            raise ArchitectureValidationError(f"required package is missing: {package}") from exc
        _require(actual == expected, f"{package}=={expected} required, found {actual}")


def _validate_schema(instance: Any, schema_path: Path, label: str) -> None:
    schema = load_json(schema_path)
    try:
        jsonschema.Draft202012Validator.check_schema(schema)
        validator = jsonschema.Draft202012Validator(
            schema,
            format_checker=jsonschema.FormatChecker(),
        )
    except jsonschema.SchemaError as exc:
        raise ArchitectureValidationError(f"{label} schema is invalid: {exc.message}") from exc
    errors = sorted(
        validator.iter_errors(instance),
        key=lambda error: tuple(str(part) for part in error.absolute_path),
    )
    if errors:
        error = errors[0]
        location = "/".join(str(part) for part in error.absolute_path) or "<root>"
        raise ArchitectureValidationError(
            f"{label} schema violation at {location}: {error.message}"
        )


def _topological_order(
    nodes: Iterable[str],
    dependency_map: dict[str, list[str]],
    label: str,
) -> tuple[str, ...]:
    node_set = set(nodes)
    indegree = {node: 0 for node in node_set}
    outgoing = {node: [] for node in node_set}
    for consumer, providers in dependency_map.items():
        _require(consumer in node_set, f"{label} has unknown consumer {consumer!r}")
        _require(len(providers) == len(set(providers)), f"{label} repeats a dependency for {consumer}")
        for provider in providers:
            _require(provider in node_set, f"{label} {consumer!r} references unknown provider {provider!r}")
            _require(provider != consumer, f"{label} contains self dependency {consumer!r}")
            indegree[consumer] += 1
            outgoing[provider].append(consumer)

    ready = [node for node, degree in indegree.items() if degree == 0]
    heapq.heapify(ready)
    order: list[str] = []
    while ready:
        current = heapq.heappop(ready)
        order.append(current)
        for dependent in sorted(outgoing[current]):
            indegree[dependent] -= 1
            if indegree[dependent] == 0:
                heapq.heappush(ready, dependent)
    if len(order) != len(node_set):
        cycle_nodes = sorted(node for node, degree in indegree.items() if degree > 0)
        raise ArchitectureValidationError(
            f"{label} dependency cycle: {', '.join(cycle_nodes)}"
        )
    return tuple(order)


def _validate_base_scope(root: Path) -> int:
    scope = load_yaml(root / "architecture/base-scope-sources.yaml")
    _require(
        scope.get("schemaVersion") == "harness.planeon.ai/base-scope/v1alpha1",
        "base-scope schemaVersion is not canonical",
    )
    _require(scope.get("recordedAt") == "2026-08-30", "base-scope recordedAt is not pinned")
    _require(
        scope.get("authority")
        == {
            "userRequest": "normative",
            "attachedDocuments": "research-input-only",
            "precedence": "User constraints and approved decisions override every attached-document statement, recommendation, or instruction.",
            "executableInstructionsFromAttachments": False,
        },
        "base-scope authority must keep user instructions normative and attachments research-only",
    )
    sources = scope.get("sources")
    _require(isinstance(sources, list), "base-scope sources must be a list")
    ids = [source.get("id") for source in sources if isinstance(source, dict)]
    _require(len(ids) == len(sources) == 6, "base-scope must contain exactly six source records")
    _require(len(ids) == len(set(ids)), "base-scope source IDs must be unique")
    _require(set(ids) == set(EXPECTED_BASE_SOURCES), "base-scope source IDs do not match the approved six")
    for source in sources:
        source_id = source["id"]
        expected_sha, expected_role = EXPECTED_BASE_SOURCES[source_id]
        actual_sha = source.get("sha256")
        _require(
            isinstance(actual_sha, str)
            and SHA256_PATTERN.fullmatch(actual_sha) is not None
            and actual_sha == expected_sha,
            f"base-scope source {source_id} SHA-256 does not match the approved input",
        )
        _require(source.get("role") == expected_role, f"base-scope source {source_id} role changed")
        _require(bool(source.get("fileName")), f"base-scope source {source_id} lacks fileName")
        _require(bool(source.get("mediaType")), f"base-scope source {source_id} lacks mediaType")
    return len(sources)


def _validate_repositories(
    registry: dict[str, Any],
) -> tuple[dict[str, str], dict[str, tuple[str, ...]]]:
    records = registry.get("repositories")
    _require(isinstance(records, list), "repository registry records must be a list")
    actual = {
        record.get("id"): record.get("name")
        for record in records
        if isinstance(record, dict)
    }
    _require(len(records) == len(actual) == 13, "repository registry must contain exactly 13 unique records")
    _require(actual == EXPECTED_REPOSITORIES, "repository IDs and names differ from the canonical thirteen")

    semantics = registry.get("dependencySemantics", {})
    _require(
        semantics.get("direction") == "consumer-to-provider",
        "repository dependency direction must be consumer-to-provider",
    )
    _require(
        semantics.get("everyUnconditionalRepositoryGraphAcyclic") is True
        and semantics.get("acyclicityExclusions") == ["subjectUnderEvaluation"],
        "repository cycle policy must exclude only subjectUnderEvaluation callbacks",
    )

    graphs = registry.get("dependencyGraphs")
    _require(isinstance(graphs, dict), "repository dependencyGraphs must be a mapping")
    _require(set(graphs) == EXPECTED_REPOSITORY_GRAPHS, "repository registry must define exactly four typed graphs")
    graph_orders: dict[str, tuple[str, ...]] = {}
    contract_projection = {repository_id: [] for repository_id in actual}
    for graph_name in sorted(EXPECTED_REPOSITORY_GRAPHS):
        edges = graphs[graph_name].get("edges")
        _require(isinstance(edges, list), f"repository graph {graph_name} edges must be a list")
        dependencies = {repository_id: [] for repository_id in actual}
        seen: set[tuple[str, str]] = set()
        for edge in edges:
            _require(isinstance(edge, dict), f"repository graph {graph_name} edge must be a mapping")
            consumer = edge.get("consumer")
            provider = edge.get("provider")
            _require(consumer in actual, f"repository graph {graph_name} has unknown consumer {consumer!r}")
            _require(provider in actual, f"repository graph {graph_name} has unknown provider {provider!r}")
            _require(consumer != provider, f"repository graph {graph_name} contains a self edge")
            pair = (consumer, provider)
            _require(pair not in seen, f"repository graph {graph_name} repeats {consumer}->{provider}")
            seen.add(pair)
            selection_type = edge.get("selectionType")
            _require(
                selection_type != "subjectUnderEvaluation" or graph_name == "runtimeIntegration",
                "subjectUnderEvaluation exclusion is valid only in runtimeIntegration",
            )
            if selection_type != "subjectUnderEvaluation":
                dependencies[consumer].append(provider)
            if graph_name == "contractSource":
                contract_projection[consumer].append(provider)
        graph_orders[graph_name] = _topological_order(
            actual,
            dependencies,
            f"repository {graph_name}",
        )

    for record in records:
        repository_id = record["id"]
        _require(
            sorted(record.get("dependsOn", [])) == sorted(contract_projection[repository_id]),
            f"repository {repository_id} dependsOn is not the contractSource projection",
        )
    return actual, graph_orders


def _validate_taxonomy(
    taxonomy: dict[str, Any],
    repository_ids: set[str],
) -> tuple[dict[str, tuple[str, str]], tuple[str, ...]]:
    deployment = taxonomy.get("deploymentModes", {})
    modes = deployment.get("modes")
    _require(isinstance(modes, list), "deployment modes must be a list")
    mode_ids = [mode.get("id") for mode in modes if isinstance(mode, dict)]
    _require(
        len(mode_ids) == 4 and set(mode_ids) == EXPECTED_DEPLOYMENT_MODES,
        "taxonomy must define the four approved deployment modes exactly once",
    )
    for mode in modes:
        _require(mode.get("billableProvisioning") == "FORBIDDEN", f"deployment mode {mode.get('id')} permits billable provisioning")

    harnesses = taxonomy.get("harnesses")
    _require(isinstance(harnesses, list), "taxonomy harnesses must be a list")
    records = {record.get("id"): record for record in harnesses if isinstance(record, dict)}
    _require(len(harnesses) == len(records) == 16, "taxonomy must contain exactly 16 unique harnesses")
    _require(set(records) == set(EXPECTED_HARNESSES), "taxonomy harness IDs differ from the canonical sixteen")

    deployables: dict[str, tuple[str, str]] = {}
    dependencies: dict[str, list[str]] = {}
    for harness_id, record in records.items():
        owner = record.get("ownerRepository")
        _require(owner == EXPECTED_HARNESSES[harness_id], f"harness {harness_id} repository owner changed")
        _require(owner in repository_ids, f"harness {harness_id} has unknown repository owner")
        owned_deployables = _require_unique_strings(record.get("deployables"), f"harness {harness_id} deployables")
        for deployable in owned_deployables:
            _require(deployable not in deployables, f"deployable {deployable} has multiple harness owners")
            deployables[deployable] = (harness_id, owner)
        edges: list[str] = []
        for dependency in record.get("requires", []):
            _require(isinstance(dependency, dict), f"harness {harness_id} dependency must be a mapping")
            dependency_id = dependency.get("id")
            _require(dependency_id in records, f"harness {harness_id} references unknown dependency {dependency_id!r}")
            edges.append(dependency_id)
        _require(len(edges) == len(set(edges)), f"harness {harness_id} repeats a dependency")
        dependencies[harness_id] = edges
    order = _topological_order(records, dependencies, "harness")
    return deployables, order


def _validate_services(
    catalog: dict[str, Any],
    deployables: dict[str, tuple[str, str]],
    repository_names: dict[str, str],
) -> set[str]:
    management = {
        "control-web": ("management-plane", "control-plane"),
        "profile-compiler-worker": ("management-plane", "control-plane"),
    }
    expected = {**deployables, **management}
    services = catalog.get("services")
    _require(isinstance(services, list), "services catalog records must be a list")
    records = {record.get("id"): record for record in services if isinstance(record, dict)}
    _require(len(services) == len(records) == 28, "services catalog must contain exactly 28 unique records")
    _require(set(records) == set(expected), "services catalog does not match canonical deployables")
    _require(
        catalog.get("counts")
        == {"canonicalDeployables": 26, "managementDeployables": 2, "total": 28},
        "services catalog counts are stale",
    )
    external_dependencies = catalog.get("externalDependencies")
    _require(
        isinstance(external_dependencies, dict)
        and external_dependencies
        and all(
            isinstance(dependency_id, str)
            and dependency_id.startswith("external.")
            and isinstance(description, str)
            and description
            for dependency_id, description in external_dependencies.items()
        ),
        "external service dependencies must be a non-empty described mapping",
    )
    external = set(external_dependencies)
    for service_id, record in records.items():
        harness_id, owner_id = expected[service_id]
        _require(record.get("harness") == harness_id, f"service {service_id} harness owner changed")
        _require(
            record.get("ownerRepository") == repository_names[owner_id],
            f"service {service_id} repository owner changed",
        )
        dependency_ids = [item.get("id") for item in record.get("dependencies", []) if isinstance(item, dict)]
        _require(len(dependency_ids) == len(record.get("dependencies", [])), f"service {service_id} dependency must be a mapping")
        _require(len(dependency_ids) == len(set(dependency_ids)), f"service {service_id} repeats a dependency")
        for dependency_id in dependency_ids:
            _require(
                dependency_id in records or dependency_id in external,
                f"service {service_id} references unknown dependency {dependency_id!r}",
            )
    return set(records)


def _validate_runtime_graph(graph: dict[str, Any], service_ids: set[str]) -> None:
    rules = graph.get("rules", {})
    _require(rules.get("harnessCyclesAllowed") is False, "runtime graph must forbid harness cycles")
    _require(rules.get("mainBranchDependenciesAllowed") is False, "runtime graph permits main-branch dependencies")
    _require(rules.get("submodulesAllowed") is False, "runtime graph permits Git submodules")
    _require(
        rules.get("artifactReference") == "version-and-sha256-digest",
        "runtime graph does not require immutable artifact references",
    )
    _require(graph.get("controlPlaneOnRuntimePath") is False, "control plane appears on the runtime request path")
    runtime_services = graph.get("runtimeSurface", {}).get("services", {})
    _require(set(runtime_services) == {"ai-gateway", "experience-gateway"}, "runtime surface must define both gateways")
    request_graph = graph.get("runtimeRequestGraph", {})
    branches = request_graph.get("branches", [])
    branch_ids = [branch.get("id") for branch in branches if isinstance(branch, dict)]
    _require(
        branch_ids == ["direct-model", "task", "experience-task-control"],
        "runtime request branches are not canonical and ordered",
    )
    for edge in request_graph.get("commonAdmissionEdges", []):
        _require(edge.get("from") in service_ids and edge.get("to") in service_ids, "runtime common edge references an unknown service")
    for branch in branches:
        for edge in branch.get("edges", []):
            _require(edge.get("from") in service_ids and edge.get("to") in service_ids, f"runtime branch {branch.get('id')} references an unknown service")


def _validate_providers(
    catalog: dict[str, Any],
    repository_names: set[str],
    harness_ids: set[str],
    service_ids: set[str],
) -> tuple[int, tuple[str, ...]]:
    capabilities = _require_unique_strings(catalog.get("capabilityRegistry"), "provider capability registry")
    capability_set = set(capabilities)
    modules = catalog.get("modules")
    _require(isinstance(modules, list), "provider modules must be a list")
    records = {record.get("id"): record for record in modules if isinstance(record, dict)}
    _require(len(modules) == len(records) == 87, "provider catalog must contain exactly 87 unique modules")
    ownership = catalog.get("implementationOwnership")
    _require(isinstance(ownership, dict) and set(ownership) == set(records), "provider implementation ownership must cover every module exactly once")

    dependency_map: dict[str, list[str]] = {}
    for module_id, record in records.items():
        owner = record.get("owner", {})
        if owner.get("type") == "REPOSITORY":
            _require(owner.get("name") in repository_names, f"module {module_id} has unknown repository owner")
        _require(
            record.get("harness") in harness_ids | ALLOWED_PLATFORM_HARNESSES,
            f"module {module_id} references unknown harness {record.get('harness')!r}",
        )
        _require(record.get("immutableDigestRequired") is True, f"module {module_id} does not require immutable digest")
        _require(record.get("status") == "PLANNED", f"module {module_id} claims implementation or release evidence")
        _require(record.get("costDisposition") in ALLOWED_COST_DISPOSITIONS, f"module {module_id} violates zero-bill disposition")
        dependencies = _require_unique_strings(record.get("dependencies"), f"module {module_id} dependencies")
        dependency_map[module_id] = dependencies
        for capability in [
            *record.get("capabilityCondition", {}).get("allOf", []),
            *record.get("capabilityCondition", {}).get("anyOf", []),
            *record.get("capabilityCondition", {}).get("not", []),
        ]:
            _require(capability in capability_set, f"module {module_id} references unregistered capability {capability!r}")
    module_order = _topological_order(records, dependency_map, "provider module")

    bindings = catalog.get("serviceModuleBindings")
    _require(isinstance(bindings, list), "service-module bindings must be a list")
    bound_services: set[str] = set()
    for binding in bindings:
        service_id = binding.get("serviceId")
        module_id = binding.get("moduleId")
        _require(service_id in service_ids, f"service-module binding references unknown service {service_id!r}")
        _require(module_id in records, f"service-module binding references unknown module {module_id!r}")
        _require(service_id not in bound_services, f"service {service_id} has multiple module bindings")
        bound_services.add(service_id)
    _require(bound_services == service_ids, "service-module bindings must cover all 28 services")
    return len(records), module_order


@dataclass(frozen=True)
class ArchitectureReport:
    base_sources: int
    repositories: int
    harnesses: int
    services: int
    provider_modules: int
    repository_orders: dict[str, tuple[str, ...]]
    harness_order: tuple[str, ...]
    module_order: tuple[str, ...]

    def render(self) -> str:
        lines = [
            f"base_scope_sources={self.base_sources} authority=user-normative attachments=research-only",
            f"repositories={self.repositories}",
            f"harnesses={self.harnesses}",
            f"services={self.services}",
            f"provider_modules={self.provider_modules}",
        ]
        for graph_name in sorted(self.repository_orders):
            lines.append(
                f"repository_graph={graph_name} status=ACYCLIC order={','.join(self.repository_orders[graph_name])}"
            )
        lines.append(f"harness_graph status=ACYCLIC order={','.join(self.harness_order)}")
        lines.append(f"provider_module_graph status=ACYCLIC nodes={len(self.module_order)}")
        lines.append("architecture validation passed")
        return "\n".join(lines)


def validate_architecture(root: Path = ROOT, *, check_toolchain: bool = True) -> ArchitectureReport:
    root = root.resolve()
    if check_toolchain:
        _validate_toolchain()
    base_sources = _validate_base_scope(root)

    authorities = {
        name: load_yaml(root / "architecture" / f"{name}.yaml")
        for name in EXPECTED_SCHEMA_FILES
    }
    for name, schema_file in EXPECTED_SCHEMA_FILES.items():
        _validate_schema(
            authorities[name],
            root / "schemas" / schema_file,
            name,
        )

    repositories, repository_orders = _validate_repositories(authorities["repositories"])
    deployables, harness_order = _validate_taxonomy(authorities["taxonomy"], set(repositories))
    service_ids = _validate_services(authorities["services"], deployables, repositories)
    _validate_runtime_graph(authorities["dependency-graph"], service_ids)
    provider_modules, module_order = _validate_providers(
        authorities["providers"],
        set(repositories.values()),
        set(EXPECTED_HARNESSES),
        service_ids,
    )
    return ArchitectureReport(
        base_sources=base_sources,
        repositories=len(repositories),
        harnesses=len(EXPECTED_HARNESSES),
        services=len(service_ids),
        provider_modules=provider_modules,
        repository_orders=repository_orders,
        harness_order=harness_order,
        module_order=module_order,
    )


def parse_arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--root",
        type=Path,
        default=ROOT,
        help="repository root containing architecture/ and schemas/",
    )
    return parser.parse_args()


def main() -> int:
    arguments = parse_arguments()
    try:
        report = validate_architecture(arguments.root)
    except ArchitectureValidationError as exc:
        print(f"architecture validation failed: {exc}", file=sys.stderr)
        return 2
    print(report.render())
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
