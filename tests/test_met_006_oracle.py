"""D5a oracle tests for MET-006 (SERVICE-EDGES-001): the service-edge record's checker and the head layer.

Owner decision D5a: a contract packet carries tests written outside the candidate, by someone who is not its
builder. These tests were written by a non-author from the texts the operator exported, never from the
candidate's code, its tests or any review. They are black-box tests: every case is built from plain data
(deep copies of the dicts the checker's own ``load`` returns, and bytes read from the repository).

Where every expected value comes from:

- CONTRACT_287 rev 8: section 3 (the header's and an entry's closed member sets), 3.1 (the fields, the
  transport forms, the callee-kind table, rule A, TLS, timeouts and their basis, retries, objectives, cache,
  degradation and audit evidence), 3.2 (the idempotency rule), 3.3 (the deadline sum), 3.4 (the graph mapping,
  the request handoff, rule B's controller handoffs and catalogGaps), 3.5 (the counts and their units), 3.6
  (request paths, maximal request paths and repeatedCalls), 3.7 (the externalProviders table and the phrase
  map), 3.8 (the externalEndpointKinds table), section 4 (the checker's rules SE-1 to SE-14), section 6 (the
  head layer's checks V1, E1, E2, E3, V4, V6) and sections 7 and 17 (the four authored edits and their lines).
- The record, the catalog and the graph as exported at c2 (architecture/service-edges.yaml,
  architecture/services.yaml, architecture/dependency-graph.yaml): only the edge keys and members each mutation
  starts from. Every expected count, mapping and repeated-call list is recomputed here from the loaded files by
  the contract's rules, not copied from the record.
- Operator-stated facts about c2: the names and signatures of ``load``, ``check_record``, ``check`` and
  ``phrase_value`` in scripts/validate_service_edges.py (refusals are ``(rule, message)`` pairs, each rule one
  of SE-1 to SE-14); and of ``authority``, ``_undo_this_layer``, ``_era_rule``, ``_v24_context``, the six
  ``check_*`` functions and the constants PACKET_FILES, BASE_FILES, ERRATA_LINES, PACKET_BRIEF, READER_PATH,
  READER_NAME and HUNK_RULE_SHA256 in scripts/validate_met_006.py; each ``check_*`` returns None or raises a
  ValueError whose message contains MET-006, and V4's message names "the MET-006 packet rider".
"""

from __future__ import annotations

import copy
import functools
import hashlib
import importlib.util
import json
import re
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
CHECKER_FILE = ROOT / "scripts" / "validate_service_edges.py"
HEAD_FILE = ROOT / "scripts" / "validate_met_006.py"

RULE_IDS = tuple(f"SE-{number}" for number in range(1, 15))
DELETE = object()

HEADER_MEMBERS = {
    "schemaVersion",
    "source",
    "externalProviders",
    "externalEndpointKinds",
    "edges",
    "handoffs",
    "graphMapping",
    "catalogGaps",
    "counts",
    "repeatedCalls",
}
ENTRY_MEMBERS = {
    "consumer",
    "dependency",
    "lifecyclePhase",
    "requiredState",
    "owner",
    "transport",
    "timeout",
    "retry",
    "objectives",
    "capacityAndOverloadRule",
    "sli",
    "cache",
    "repeatedCallJustification",
    "degradation",
    "auditEvidence",
}
COUNT_MEMBERS = {
    "edges",
    "byLifecyclePhase",
    "byProtocol",
    "byEndpointKind",
    "byIdempotency",
    "networkForms",
    "localForms",
    "viaForms",
    "numericEdges",
    "shapeOnlyEdges",
}
PHASES = {"INSTALL", "STARTUP", "ADMISSION", "INVOCATION", "BACKGROUND_RECONCILIATION", "OBSERVATION"}
PROTOCOLS = {"HTTP", "GRPC", "POSTGRESQL", "KUBERNETES_API", "OTLP", "OCI_LAYOUT", "FILESYSTEM"}
ENDPOINT_KINDS = {"SERVICE_DNS", "EXTERNAL", "UNIX_SOCKET", "ARTIFACT_PATH", "VIA"}
NETWORK_KINDS = ("SERVICE_DNS", "EXTERNAL")
LOCAL_KINDS = ("UNIX_SOCKET", "ARTIFACT_PATH")
PLATFORM_DNS_KINDS = {"api", "gateway", "web-api", "collector"}
TABLE_KINDS = PLATFORM_DNS_KINDS | {"controller", "job", "worker"}
TLS_NETWORK = {"required": True, "minVersion": "1.3"}
TLS_LOCAL = {"required": False}
TIMEOUT_MEMBERS = {
    "SYNC": {"connectSeconds", "attemptSeconds", "ceilingSeconds", "deadline", "basis"},
    "ASYNC": {"publishAckSeconds", "basis"},
    "CONTROL": {"reconcileSeconds", "basis"},
    "ARTIFACT": {"fetchSeconds", "basis"},
}
OBJECTIVES = {
    "SYNC": {"latency", "deadlinePropagation", "cancellation"},
    "ASYNC": {"lag", "acknowledgementAge"},
    "CONTROL": {"convergence"},
    "ARTIFACT": {"integrity", "readiness"},
}
UNSPECIFIED_BACKOFF = {"initialSeconds": "UNSPECIFIED", "maxSeconds": "UNSPECIFIED", "jitter": "UNSPECIFIED"}
KEBAB = re.compile(r"[a-z0-9]+(-[a-z0-9]+)*")
HEX64 = re.compile(r"[0-9a-f]{64}")
MESH_WORDS = re.compile(r"\bmesh\b|\bsidecar\b|injected proxy", re.IGNORECASE)
ELLIPSIS = "…"
CALL_PHASES = ("ADMISSION", "INVOCATION")
CALL_CLASSES = (
    ("policy", ("policy-decision", "external.opa-engine")),
    ("registry", ("registry-service",)),
    ("database", ("external.postgresql", "external.pgvector")),
)

# Section 3.7's table: external -> (value, source ref, source phrase).
EXPECTED_PROVIDERS = {
    "external.kubernetes-api": ("OPERATOR", "architecture/services.yaml#L250", "Operator-supplied"),
    "external.local-oci-source": (
        "OPERATOR",
        "architecture/services.yaml#L251",
        "operator-supplied local OCI registry",
    ),
    "external.release-trust-store": (
        "OPERATOR",
        "docs/MICROSERVICE_CATALOG.md#L74",
        f"operator-supplied {ELLIPSIS} public trust material",
    ),
    "external.oidc-provider": ("TENANT_OR_OPERATOR", "architecture/services.yaml#L253", "Tenant/operator-supplied"),
    "external.postgresql": ("TENANT_OR_OPERATOR", "architecture/services.yaml#L254", "Tenant/operator-supplied"),
    "external.pgvector": ("TENANT", "architecture/services.yaml#L255", "the tenant PostgreSQL service"),
    "external.opa-engine": ("OPERATOR", "docs/MICROSERVICE_CATALOG.md#L74", f"operator-supplied {ELLIPSIS} OPA"),
    "external.otel-backend": (
        "TENANT",
        "docs/harnesses/trust.observability-finops.md#L90",
        "Tenant-supplied telemetry backends",
    ),
    "external.tenant-source-endpoints": ("TENANT", "architecture/services.yaml#L258", "tenant data endpoints"),
    "external.tenant-object-store": ("TENANT", "architecture/services.yaml#L259", "tenant-supplied"),
    "external.tenant-model-volume": (
        "OPERATOR",
        "docs/MICROSERVICE_CATALOG.md#L74",
        f"operator-supplied {ELLIPSIS} model volumes",
    ),
    "external.local-model-backend": (
        "OPERATOR",
        "docs/MICROSERVICE_CATALOG.md#L74",
        f"operator-supplied {ELLIPSIS} model volumes/backends",
    ),
    "external.signed-catalog": (
        "PLATFORM_RELEASE",
        "architecture/services.yaml#L262",
        "Digest-pinned contract/module catalog artifact",
    ),
    "external.signed-industry-packs": (
        "PLATFORM_RELEASE",
        "architecture/services.yaml#L263",
        "Digest-pinned industry-pack artifact",
    ),
}

# Section 3.8's table: external -> (endpoint kinds, architecture/services.yaml line, phrase).
EXPECTED_ENDPOINT_KINDS = {
    "external.kubernetes-api": (("EXTERNAL",), 250, "Kubernetes, K3s, or OpenShift API"),
    "external.local-oci-source": (
        ("ARTIFACT_PATH", "EXTERNAL"),
        251,
        "Mounted OCI layout or operator-supplied local OCI registry",
    ),
    "external.release-trust-store": (("ARTIFACT_PATH",), 252, "Mounted public keys and revocation manifest"),
    "external.oidc-provider": (("EXTERNAL",), 253, "OIDC issuer"),
    "external.postgresql": (("EXTERNAL",), 254, "PostgreSQL with service-scoped roles and RLS"),
    "external.pgvector": (("EXTERNAL",), 255, "pgvector extension in the tenant PostgreSQL service"),
    "external.opa-engine": (("EXTERNAL",), 256, "Local OPA engine"),
    "external.otel-backend": (("EXTERNAL",), 257, "Prometheus and Jaeger-compatible storage"),
    "external.tenant-source-endpoints": (("EXTERNAL",), 258, "Explicitly allowlisted tenant data endpoints"),
    "external.tenant-object-store": (
        ("ARTIFACT_PATH", "EXTERNAL"),
        259,
        "Tenant PVC or tenant-supplied S3-compatible endpoint",
    ),
    "external.tenant-model-volume": (("ARTIFACT_PATH",), 260, "Pre-staged, license-approved local model artifacts"),
    "external.local-model-backend": (("EXTERNAL",), 261, "Selected Ollama, llama.cpp, or vLLM backend"),
    "external.signed-catalog": (("ARTIFACT_PATH",), 262, "Digest-pinned contract/module catalog artifact"),
    "external.signed-industry-packs": (("ARTIFACT_PATH",), 263, "Digest-pinned industry-pack artifact"),
}

# Section 3.4: the request handoff, rule B's five controller edges, their objects and the one catalog gap.
EXPECTED_REQUEST_HANDOFF = {
    "kind": "REQUEST",
    "branch": "task",
    "from": "orchestration-api",
    "to": "orchestration-worker",
    "via": "external.postgresql",
    "write": "orchestration-api->external.postgresql",
    "lease": "orchestration-worker->external.postgresql",
}
CONTROLLER_EDGES = (
    "fleet-sync-agent->operator",
    "control-web->operator",
    "ingest-worker->connector-controller",
    "retrieval-service->connector-controller",
    "decision-service->connector-controller",
)
CONTROLLER_VIAS = {"operator": "external.kubernetes-api", "connector-controller": "external.postgresql"}
CONTROLLER_OBJECTS = {
    "operator": {"kind": "KUBERNETES_RESOURCE", "resource": "HarnessInstallation", "subresource": "status"},
    "connector-controller": {
        "kind": "DATABASE_SCHEMA",
        "schema": "ingestion",
        "objects": ["sources", "profiles", "leases", "readiness", "outbox"],
    },
}
EXPECTED_GAP = {
    "edge": "control-web->operator",
    "via": "external.kubernetes-api",
    "missing": "control-web->external.kubernetes-api",
    "source": {"ref": "architecture/services.yaml#L910", "phrase": "installation projection"},
}

# Section 3.1: the one documented edge (OQ-287-1) and its split retry (section 3.2).
DOCUMENTED_OPERATIONS = [
    {"class": "idempotent-requests", "idempotency": "NATIVE", "policy": "IDEMPOTENT_ONLY", "maxAttempts": 3},
    {"class": "non-idempotent-requests", "idempotency": "NONE", "policy": "NONE", "maxAttempts": 1},
]
LINE_151 = (
    b"The gateway retries at most two compatible targets only before response bytes and only for "
    b"idempotent requests."
)

# Section 6 and sections 7 and 17.
PACKET_FOUR = (
    "architecture/service-edges.yaml",
    "architecture/service-edges/schema.json",
    "scripts/validate_service_edges.py",
    "tests/test_service_edges.py",
)
BASE_FOUR = (
    "architecture/services.yaml",
    "architecture/dependency-graph.yaml",
    "schemas/services.schema.json",
    "schemas/dependency-graph.schema.json",
)
README = "architecture/chain-checkpoint/README.md"
SECTOR_TEST = "tests/test_sector_catalog.py"
EXPECTED_ERRATA = {
    README: (184, 189),
    "docs/repositories/00-harness-engineering.md": (1618, 1618),
    "docs/MASTER_DEVELOPMENT_PLAN.md": (3331, 3331),
    SECTOR_TEST: (837, 912),
}
HUNK_RECORD = "architecture/chain-checkpoint/hunk-classes/287.json"
REGISTRY = "architecture/review-record/briefs.json"
RIDER = "MET-006/packet"

# Edge keys the mutations start from (consumer, dependency).
AI_INF = ("ai-gateway", "inference-api")
AI_POL = ("ai-gateway", "policy-decision")
AI_GRD = ("ai-gateway", "guardrail-service")
EXP_AI = ("experience-gateway", "ai-gateway")
OTEL = ("otel-collector", "external.otel-backend")
OP_K8S = ("operator", "external.kubernetes-api")
OP_BV = ("operator", "bundle-verifier")
FSA_OP = ("fleet-sync-agent", "operator")
CW_OP = ("control-web", "operator")
CW_PG = ("control-web", "external.postgresql")
IW_CC = ("ingest-worker", "connector-controller")
RS_CC = ("retrieval-service", "connector-controller")
IDX_IW = ("index-worker", "ingest-worker")
TB_SR = ("tool-broker", "sandbox-runner")
BV_OCI = ("bundle-verifier", "external.local-oci-source")
BV_RTS = ("bundle-verifier", "external.release-trust-store")
OW_PG = ("orchestration-worker", "external.postgresql")
OA_PG = ("orchestration-api", "external.postgresql")


# ---------------------------------------------------------------------------------------------------------
# Loading: exactly the two repository modules, each into a fresh module object.
# ---------------------------------------------------------------------------------------------------------


def _fresh_module(path: Path, name: str):
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@functools.lru_cache(maxsize=None)
def _checker():
    return _fresh_module(CHECKER_FILE, "met006_oracle_service_edges")


@functools.lru_cache(maxsize=None)
def _head():
    return _fresh_module(HEAD_FILE, "met006_oracle_head")


@functools.lru_cache(maxsize=None)
def _live():
    record, catalog, graph, schema = _checker().load()
    return record, catalog, graph, schema


def _copies():
    return tuple(copy.deepcopy(part) for part in _live())


def _rule_ids(result) -> list:
    ids = [pair[0] for pair in result]
    assert all(rule in RULE_IDS for rule in ids), ids
    return ids


def _refusals_after(mutate) -> list:
    record, catalog, graph, schema = _copies()
    mutate(record, catalog)
    live_record, live_catalog, _, _ = _live()
    assert (record, catalog) != (live_record, live_catalog), "the mutation changed nothing"
    return _rule_ids(_checker().check_record(record, catalog, graph, schema))


def _accepted_after(mutate) -> list:
    record, catalog, graph, schema = _copies()
    mutate(record, catalog)
    live_record, live_catalog, _, _ = _live()
    assert (record, catalog) != (live_record, live_catalog), "the mutation changed nothing"
    record["counts"] = _expected_counts(record, catalog)
    return _rule_ids(_checker().check_record(record, catalog, graph, schema))


# ---------------------------------------------------------------------------------------------------------
# Plain-data helpers over the record, the catalog and the graph.
# ---------------------------------------------------------------------------------------------------------


def _key(entry) -> str:
    return f"{entry['consumer']}->{entry['dependency']}"


def _entry(record, consumer, dependency):
    matches = [e for e in record["edges"] if e["consumer"] == consumer and e["dependency"] == dependency]
    assert len(matches) == 1, (consumer, dependency, len(matches))
    return matches[0]


def _services(catalog):
    return {service["id"]: service for service in catalog["services"]}


def _catalog_edges(catalog):
    return [
        (service["id"], dependency["id"], dependency)
        for service in catalog["services"]
        for dependency in service.get("dependencies") or []
    ]


def _catalog_field(catalog, field):
    return {(consumer, dependency): spec.get(field) for consumer, dependency, spec in _catalog_edges(catalog)}


def _dependencies_of(catalog):
    return {
        service["id"]: [dependency["id"] for dependency in service.get("dependencies") or []]
        for service in catalog["services"]
    }


def _number(value) -> bool:
    return isinstance(value, (int, float)) and not isinstance(value, bool)


def _attempt_values(retry):
    if "operations" in retry:
        return [operation.get("maxAttempts") for operation in retry["operations"]]
    return [retry.get("maxAttempts")]


def _largest_attempts(retry):
    values = _attempt_values(retry)
    if values and all(_number(value) for value in values):
        return max(values)
    return None


def _numeric_edge(entry) -> bool:
    timeout = entry["timeout"]
    if any(_number(value) for member, value in timeout.items() if member not in ("basis", "deadline")):
        return True
    backoff = entry["retry"].get("backoff") or {}
    if any(_number(backoff.get(member)) for member in ("initialSeconds", "maxSeconds")):
        return True
    return any(_number(value) and value > 1 for value in _attempt_values(entry["retry"]))


def _shape_only(entry) -> bool:
    backoff = entry["retry"].get("backoff") or {}
    terms = (
        _largest_attempts(entry["retry"]),
        entry["timeout"].get("attemptSeconds"),
        backoff.get("maxSeconds"),
    )
    return not all(_number(term) for term in terms)


def _expected_counts(record, catalog):
    """Section 3.5's units: forms for protocol, endpoint kind and the form totals; entries for edges, phases,
    numericEdges and shapeOnlyEdges; each entry without operations once and each operations class once for
    byIdempotency."""
    modes = _catalog_field(catalog, "mode")
    by_phase, by_protocol, by_kind, by_idempotency = {}, {}, {}, {}
    network = local = via = numeric = shape_only = 0

    def add(counter, name):
        counter[name] = counter.get(name, 0) + 1

    for entry in record["edges"]:
        add(by_phase, entry["lifecyclePhase"])
        for form in entry["transport"]:
            add(by_protocol, form["protocol"])
            kind = form["endpoint"]["kind"]
            add(by_kind, kind)
            network += kind in NETWORK_KINDS
            local += kind in LOCAL_KINDS
            via += kind == "VIA"
        retry = entry["retry"]
        for spec in retry.get("operations") or [retry]:
            add(by_idempotency, spec["idempotency"])
        numeric += _numeric_edge(entry)
        shape_only += modes[(entry["consumer"], entry["dependency"])] == "SYNC" and _shape_only(entry)
    return {
        "edges": len(record["edges"]),
        "byLifecyclePhase": by_phase,
        "byProtocol": by_protocol,
        "byEndpointKind": by_kind,
        "byIdempotency": by_idempotency,
        "networkForms": network,
        "localForms": local,
        "viaForms": via,
        "numericEdges": numeric,
        "shapeOnlyEdges": shape_only,
    }


def _maximal_request_paths(graph):
    """Section 3.6: paths of runtimeRequestGraph from a branch's entrypoints, caller to provider; the common
    admission edges belong to every branch whose entrypoints include ai-gateway; a maximal path is one no
    request edge of its branch extends."""
    request_graph = graph["runtimeRequestGraph"]
    common = list(request_graph["commonAdmissionEdges"])
    result = []
    for branch in request_graph["branches"]:
        edges = list(branch["edges"])
        if "ai-gateway" in branch["entrypoints"]:
            edges = common + edges
        callees = {}
        for edge in edges:
            callees.setdefault(edge["from"], []).append(edge["to"])
        maximal = []

        def walk(path, callees=callees, maximal=maximal):
            onward = [node for node in callees.get(path[-1], []) if node not in path]
            if not onward:
                maximal.append(path)
                return
            for node in onward:
                walk(path + [node])

        for entrypoint in branch["entrypoints"]:
            walk([entrypoint])
        result.append((branch["id"], maximal))
    return result


def _expected_repeated_calls(record, graph):
    """Section 3.6 (MET006-C3-4): one row per maximal request path and class reached by two or more calls
    (ADMISSION or INVOCATION edges whose consumer is a node of the path); rows sorted by branch in graph order,
    then path, then class (policy, registry, database); edges sorted."""
    rows = []
    for branch_id, paths in _maximal_request_paths(graph):
        for path in sorted(paths):
            nodes = set(path)
            calls = [e for e in record["edges"] if e["consumer"] in nodes and e["lifecyclePhase"] in CALL_PHASES]
            for class_name, callees in CALL_CLASSES:
                keys = sorted(_key(e) for e in calls if e["dependency"] in callees)
                if len(keys) >= 2:
                    rows.append({"branch": branch_id, "path": list(path), "class": class_name, "edges": keys})
    return rows


def _idempotency_problems(retry):
    """Section 3.2, items 1 and 2, as data checks over one entry's retry."""
    problems = []

    def check_class(spec, where):
        idempotency, policy, attempts = spec.get("idempotency"), spec.get("policy"), spec.get("maxAttempts")
        if policy == "IDEMPOTENT_ONLY" and idempotency != "NATIVE":
            problems.append(f"{where}: IDEMPOTENT_ONLY without NATIVE")
        if idempotency == "RECEIPT_KEY":
            if not spec.get("operationIdField") or policy != "NONE" or attempts != 1:
                problems.append(f"{where}: RECEIPT_KEY without its field, policy NONE and maxAttempts 1")
        elif "operationIdField" in spec:
            problems.append(f"{where}: operationIdField without RECEIPT_KEY")
        if idempotency == "NONE" and (policy != "NONE" or attempts != 1):
            problems.append(f"{where}: NONE with retries")

    operations = retry.get("operations")
    if operations is None:
        check_class(retry, "entry")
        return problems
    stray = {"idempotency", "policy", "maxAttempts", "operationIdField"} & set(retry)
    if stray:
        problems.append(f"entry-level {sorted(stray)} beside operations")
    names = [operation.get("class") for operation in operations]
    if len(set(names)) != len(names):
        problems.append("operations classes repeat")
    if not all(isinstance(name, str) and KEBAB.fullmatch(name) for name in names):
        problems.append("an operations class is not a kebab-case token")
    for operation in operations:
        check_class(operation, f"class {operation.get('class')}")
    return problems


def _strings(node):
    if isinstance(node, str):
        yield node
    elif isinstance(node, dict):
        for value in node.values():
            yield from _strings(value)
    elif isinstance(node, list):
        for value in node:
            yield from _strings(value)


def _line(path: str, number: int) -> bytes:
    return (ROOT / path).read_bytes().split(b"\n")[number - 1]


def _cited_line(ref: str) -> bytes:
    path, _, number = ref.partition("#L")
    return _line(path, int(number))


# ---------------------------------------------------------------------------------------------------------
# Mutation factories: each returns a callable that changes a deep copy of the record (or the catalog).
# ---------------------------------------------------------------------------------------------------------


def _setter(key, path, value):
    def mutate(record, catalog):
        node = record if key is None else _entry(record, *key)
        for step in path[:-1]:
            node = node[step]
        if value is DELETE:
            del node[path[-1]]
        else:
            node[path[-1]] = copy.deepcopy(value)

    return mutate


def _bump(path, delta):
    def mutate(record, catalog):
        node = record
        for step in path[:-1]:
            node = node[step]
        node[path[-1]] = node[path[-1]] + delta

    return mutate


def _both(*mutations):
    def mutate(record, catalog):
        for one in mutations:
            one(record, catalog)

    return mutate


def _drop_entry(key):
    def mutate(record, catalog):
        record["edges"].remove(_entry(record, *key))

    return mutate


def _duplicate_entry(key):
    def mutate(record, catalog):
        record["edges"].append(copy.deepcopy(_entry(record, *key)))

    return mutate


def _entry_like(key, consumer, dependency):
    def mutate(record, catalog):
        twin = copy.deepcopy(_entry(record, *key))
        twin["consumer"], twin["dependency"] = consumer, dependency
        record["edges"].append(twin)

    return mutate


def _catalog_kind(service_id, kind):
    def mutate(record, catalog):
        _services(catalog)[service_id]["kind"] = kind

    return mutate


def _provider_value_everywhere(external, value):
    def mutate(record, catalog):
        record["externalProviders"][external]["value"] = value
        for entry in record["edges"]:
            if entry["dependency"] == external:
                entry["owner"]["provider"] = value

    return mutate


def _repeated(transform):
    def mutate(record, catalog):
        record["repeatedCalls"] = transform(copy.deepcopy(record["repeatedCalls"]))

    return mutate


def _rows_without_last(rows):
    return rows[:-1]


def _rows_first_two_swapped(rows):
    return [rows[1], rows[0]] + rows[2:]


def _rows_first_edges_reversed(rows):
    rows[0] = dict(rows[0], edges=list(reversed(rows[0]["edges"])))
    return rows


def _rows_with_bogus_registry_row(rows):
    rows.append(dict(rows[0], **{"class": "registry"}))
    return rows


def _rows_with_trimmed_group(rows):
    index = next(i for i, row in enumerate(rows) if len(row["edges"]) >= 3)
    rows[index] = dict(rows[index], edges=rows[index]["edges"][:-1])
    return rows


def _handoff(record, kind, source, target):
    matches = [h for h in record["handoffs"] if h["kind"] == kind and h["from"] == source and h["to"] == target]
    assert len(matches) == 1
    return matches[0]


def _drop_handoff(kind, source, target):
    def mutate(record, catalog):
        record["handoffs"].remove(_handoff(record, kind, source, target))

    return mutate


def _handoff_member(kind, source, target, member, value):
    def mutate(record, catalog):
        _handoff(record, kind, source, target)[member] = copy.deepcopy(value)

    return mutate


def _drop_mapping(edge):
    def mutate(record, catalog):
        record["graphMapping"] = [row for row in record["graphMapping"] if row["edge"] != edge]

    return mutate


def _mapping_edge(edge, wrong):
    def mutate(record, catalog):
        rows = [row for row in record["graphMapping"] if row["edge"] == edge]
        assert len(rows) == 1
        rows[0]["edge"] = wrong

    return mutate


def _controller_via_not_its_store(record, catalog):
    handoff = _handoff(record, "CONTROLLER", "ingest-worker", "connector-controller")
    handoff["via"] = "policy-decision"
    handoff["consumerSide"] = "ingest-worker->policy-decision"
    handoff["controllerSide"] = "connector-controller->policy-decision"
    _entry(record, *IW_CC)["transport"] = [{"protocol": "HTTP", "endpoint": {"kind": "VIA", "via": "policy-decision"}}]


def _dns(service):
    return {
        "protocol": "HTTP",
        "endpoint": {"kind": "SERVICE_DNS", "service": service, "port": "https"},
        "tls": dict(TLS_NETWORK),
    }


BOUNDED = {
    "kind": "BOUNDED_METADATA",
    "freshness": "UNSPECIFIED",
    "revocation": "a revoked signed policy bundle invalidates every held decision at once",
    "outage": "no held decision is used while policy-decision is unavailable",
}


# ---------------------------------------------------------------------------------------------------------
# 1. The live record (sections 3 and 3.1-3.8).
# ---------------------------------------------------------------------------------------------------------


def test_check_passes_on_the_live_record():
    """Section 4 (SE-1 to SE-14) and section 6 E1: check() and check_record over load() refuse nothing."""
    assert list(_checker().check()) == []
    assert _rule_ids(_checker().check_record(*_copies())) == []


def test_header_is_a_closed_member_set():
    """Section 3: the header's closed member set, its schemaVersion and its source."""
    record = _live()[0]
    assert set(record) == HEADER_MEMBERS
    assert record["schemaVersion"] == "harness.planeon.ai/service-edges/v1alpha1"
    assert record["source"] == {
        "catalog": "architecture/services.yaml",
        "catalogVersion": "1.1.0",
        "graph": "architecture/dependency-graph.yaml",
    }


def test_one_entry_per_catalog_dependency_in_catalog_order():
    """Section 3 and SE-1: one entry per catalog dependency (129), keyed by consumer and dependency, in the
    catalog's order."""
    record, catalog, _, _ = _live()
    keys = [(entry["consumer"], entry["dependency"]) for entry in record["edges"]]
    expected = [(consumer, dependency) for consumer, dependency, _ in _catalog_edges(catalog)]
    assert len(expected) == 129
    assert keys == expected
    assert len(set(keys)) == 129


def test_entries_never_carry_the_catalog_fields():
    """Section 3 (MON-287-RULINGS Q1, Option B): an entry's closed member set, never mode, required or
    failureMode."""
    for entry in _live()[0]["edges"]:
        assert set(entry) == ENTRY_MEMBERS, _key(entry)
        assert not {"mode", "required", "failureMode"} & set(entry), _key(entry)
        assert entry["lifecyclePhase"] in PHASES, _key(entry)
        assert isinstance(entry["requiredState"], str) and KEBAB.fullmatch(entry["requiredState"]), _key(entry)


def test_counts_agree_with_section_3_5_units():
    """Section 3.5 (MET006-C3-7) and SE-14: the header's counts equal the counts recomputed by section 3.5's
    units (133 forms, 129 entries, 130 idempotency units, one numeric edge, the SYNC shape-only edges)."""
    record, catalog, _, _ = _live()
    counts = record["counts"]
    assert set(counts) == COUNT_MEMBERS
    assert counts == _expected_counts(record, catalog)
    forms = [form for entry in record["edges"] for form in entry["transport"]]
    assert len(forms) == 133
    assert sum(counts["byProtocol"].values()) == sum(counts["byEndpointKind"].values()) == 133
    assert counts["networkForms"] + counts["localForms"] + counts["viaForms"] == 133
    two_form = [entry for entry in record["edges"] if len(entry["transport"]) == 2]
    assert len(two_form) == 4
    assert {entry["dependency"] for entry in two_form} == {"external.local-oci-source", "external.tenant-object-store"}
    assert counts["edges"] == 129
    assert counts["numericEdges"] == 1
    assert [_key(entry) for entry in record["edges"] if "operations" in entry["retry"]] == ["ai-gateway->inference-api"]
    assert sum(counts["byIdempotency"].values()) == 130
    modes = _catalog_field(catalog, "mode")
    assert counts["shapeOnlyEdges"] == sum(1 for mode in modes.values() if mode == "SYNC")


def test_external_providers_follow_the_section_3_7_table():
    """Section 3.7 (MET006-C2-1, MET006-C3-1) and SE-1: the 14 rows, each {value, source: {ref, phrase}}."""
    record, catalog, _, _ = _live()
    rows = record["externalProviders"]
    assert set(rows) == set(catalog["externalDependencies"]) == set(EXPECTED_PROVIDERS)
    for external, (value, ref, phrase) in EXPECTED_PROVIDERS.items():
        assert rows[external] == {"value": value, "source": {"ref": ref, "phrase": phrase}}, external


def test_external_provider_lines_hold_every_phrase_part():
    """Section 3.7 and SE-10: each cited line exists at the head and holds every part of the phrase between
    the ellipsis marks."""
    for external, row in _live()[0]["externalProviders"].items():
        line = _cited_line(row["source"]["ref"]).decode("utf-8")
        for part in row["source"]["phrase"].split(ELLIPSIS):
            assert part.strip() in line, external


def test_external_endpoint_kinds_follow_the_section_3_8_table():
    """Section 3.8 (MET006-C3-5) and SE-1, SE-2: 14 rows citing the external's own catalog line, whose line
    holds the phrase; no row lists UNIX_SOCKET."""
    record, catalog, _, _ = _live()
    rows = record["externalEndpointKinds"]
    assert set(rows) == set(catalog["externalDependencies"]) == set(EXPECTED_ENDPOINT_KINDS)
    for external, (kinds, number, phrase) in EXPECTED_ENDPOINT_KINDS.items():
        row = rows[external]
        assert set(row) == {"kinds", "source"}, external
        assert sorted(row["kinds"]) == sorted(kinds), external
        assert row["source"] == {"ref": f"architecture/services.yaml#L{number}", "phrase": phrase}, external
        line = _line("architecture/services.yaml", number).decode("utf-8")
        assert line.strip().startswith(f"{external}:"), external
        assert phrase in line, external
    assert not any("UNIX_SOCKET" in row["kinds"] for row in rows.values())


PHRASE_CASES = [
    pytest.param("Tenant/operator-supplied", "TENANT_OR_OPERATOR", id="tenant-or-operator"),
    pytest.param("Digest-pinned industry-pack artifact", "PLATFORM_RELEASE", id="digest-pinned"),
    pytest.param("operator-supplied local OCI registry", "OPERATOR", id="operator-supplied"),
    pytest.param("the tenant PostgreSQL service", "TENANT", id="tenant"),
    pytest.param(f"operator-supplied {ELLIPSIS} public trust material", "OPERATOR", id="operator-with-ellipsis"),
    pytest.param("TENANT-SUPPLIED TELEMETRY BACKENDS", "TENANT", id="any-case-tenant"),
    pytest.param("TENANT/OPERATOR-SUPPLIED issuer", "TENANT_OR_OPERATOR", id="any-case-tenant-or-operator"),
    pytest.param("tenant/operator-supplied digest-pinned bundle", "TENANT_OR_OPERATOR", id="order-first-entry-wins"),
    pytest.param("digest-pinned operator-supplied bundle", "PLATFORM_RELEASE", id="order-digest-before-operator"),
    pytest.param("digest-pinned tenant artifact", "PLATFORM_RELEASE", id="order-digest-before-tenant"),
    pytest.param("operator-supplied tenant volumes", "OPERATOR", id="order-operator-before-tenant"),
]


@pytest.mark.parametrize(("text", "value"), PHRASE_CASES)
def test_phrase_value_applies_the_section_3_7_phrase_map(text, value):
    """Section 3.7 (the phrase map): matched in order and in any case; tenant/operator-supplied,
    digest-pinned, operator-supplied, tenant."""
    assert _checker().phrase_value(text) == value


def test_every_provider_phrase_states_its_value():
    """Section 3.7 and SE-10: each live row's phrase states the row's value by the phrase map."""
    for external, row in _live()[0]["externalProviders"].items():
        assert _checker().phrase_value(row["source"]["phrase"]) == row["value"], external


def test_owner_follows_section_3_1():
    """Section 3.1 (owner) and SE-10: consumer is the consumer's ownerRepository; a platform callee's provider
    and escalation are the callee's ownerRepository; an external's provider is its externalProviders value and
    its escalation is the consumer."""
    record, catalog, _, _ = _live()
    services = _services(catalog)
    externals = set(catalog["externalDependencies"])
    for entry in record["edges"]:
        owner = entry["owner"]
        assert set(owner) == {"provider", "consumer", "escalation"}, _key(entry)
        consumer_repository = services[entry["consumer"]]["ownerRepository"]
        assert owner["consumer"] == consumer_repository, _key(entry)
        if entry["dependency"] in externals:
            assert owner["provider"] == record["externalProviders"][entry["dependency"]]["value"], _key(entry)
            assert owner["escalation"] == consumer_repository, _key(entry)
        else:
            provider = services[entry["dependency"]]["ownerRepository"]
            assert owner["provider"] == provider, _key(entry)
            assert owner["escalation"] == provider, _key(entry)


def test_transport_forms_follow_the_callee_kind_table_and_tls():
    """Section 3.1 (transport, the callee-kind table, TLS; MET006-C3-2, MET006-C4-2) and SE-2, SE-3."""
    record, catalog, _, _ = _live()
    services = _services(catalog)
    externals = set(catalog["externalDependencies"])
    dependencies_of = _dependencies_of(catalog)
    entries = {(entry["consumer"], entry["dependency"]): entry for entry in record["edges"]}
    gaps = {row["edge"]: row for row in record["catalogGaps"]}
    for entry in record["edges"]:
        forms = entry["transport"]
        assert isinstance(forms, list) and forms, _key(entry)
        for form in forms:
            assert form["protocol"] in PROTOCOLS, _key(entry)
            kind = form["endpoint"]["kind"]
            assert kind in ENDPOINT_KINDS, _key(entry)
            if kind == "VIA":
                assert set(form) == {"protocol", "endpoint"}, _key(entry)
                assert set(form["endpoint"]) == {"kind", "via"}, _key(entry)
                via = form["endpoint"]["via"]
                assert via != entry["dependency"], _key(entry)
                if _key(entry) in gaps:
                    assert via == gaps[_key(entry)]["via"], _key(entry)
                    target = entries[(entry["dependency"], via)]
                else:
                    assert via in dependencies_of[entry["consumer"]], _key(entry)
                    target = entries[(entry["consumer"], via)]
                assert form["protocol"] in {f["protocol"] for f in target["transport"]}, _key(entry)
            else:
                assert set(form) == {"protocol", "endpoint", "tls"}, _key(entry)
                if kind in NETWORK_KINDS:
                    assert form["tls"] == TLS_NETWORK, _key(entry)
                else:
                    assert form["tls"] == TLS_LOCAL, _key(entry)
        dependency = entry["dependency"]
        if dependency in externals:
            row = record["externalEndpointKinds"][dependency]
            assert sorted(form["endpoint"]["kind"] for form in forms) == sorted(row["kinds"]), _key(entry)
            for form in forms:
                if form["endpoint"]["kind"] == "EXTERNAL":
                    assert form["endpoint"] == {"kind": "EXTERNAL", "ref": dependency}, _key(entry)
                else:
                    assert set(form["endpoint"]) == {"kind", "path"}, _key(entry)
                    assert isinstance(form["endpoint"]["path"], str) and form["endpoint"]["path"], _key(entry)
            continue
        callee_kind = services[dependency]["kind"]
        assert callee_kind in TABLE_KINDS, _key(entry)
        if callee_kind in PLATFORM_DNS_KINDS:
            assert len(forms) == 1, _key(entry)
            endpoint = forms[0]["endpoint"]
            assert set(endpoint) == {"kind", "service", "port"}, _key(entry)
            assert endpoint["kind"] == "SERVICE_DNS" and endpoint["service"] == dependency, _key(entry)
            assert endpoint["port"] in ("https", "grpc"), _key(entry)
        elif callee_kind in ("controller", "worker"):
            assert len(forms) == 1 and forms[0]["endpoint"]["kind"] == "VIA", _key(entry)
    assert not [e for e in record["edges"] if services.get(e["dependency"], {}).get("kind") == "agent"]


def test_timeouts_are_unspecified_but_the_one_documented_edge():
    """Section 3.1 (timeout and retry basis; OQ-287-1, MET006-C1-11) and SE-6: members per catalog mode, every
    value UNSPECIFIED except ai-gateway to inference-api (connect 2, ceiling 30, lines 150 and 151)."""
    record, catalog, _, _ = _live()
    modes = _catalog_field(catalog, "mode")
    for entry in record["edges"]:
        mode = modes[(entry["consumer"], entry["dependency"])]
        timeout = entry["timeout"]
        assert set(timeout) == TIMEOUT_MEMBERS[mode], _key(entry)
        if mode == "SYNC":
            assert timeout["deadline"] == "PROPAGATED", _key(entry)
        assert entry["retry"]["backoff"] == UNSPECIFIED_BACKOFF, _key(entry)
        if (entry["consumer"], entry["dependency"]) == AI_INF:
            continue
        values = [value for member, value in timeout.items() if member not in ("basis", "deadline")]
        assert all(value == "UNSPECIFIED" for value in values), _key(entry)
        assert timeout["basis"] == {"kind": "UNSPECIFIED"}, _key(entry)
        assert entry["retry"]["basis"] == {"kind": "UNSPECIFIED"}, _key(entry)
    documented = _entry(record, *AI_INF)
    timeout = documented["timeout"]
    assert timeout["connectSeconds"] == 2
    assert timeout["ceilingSeconds"] == 30
    assert timeout["attemptSeconds"] == "UNSPECIFIED"
    assert timeout["basis"]["kind"] == "DOCUMENTED_BOUND"
    assert timeout["basis"]["ref"] == "docs/harnesses/runtime.ai-gateway.md#L150"
    retry = documented["retry"]
    assert set(retry) == {"operations", "backoff", "basis"}
    assert retry["operations"] == DOCUMENTED_OPERATIONS
    assert retry["basis"]["kind"] == "DOCUMENTED_BOUND"
    assert retry["basis"]["ref"] == "docs/harnesses/runtime.ai-gateway.md#L151"


def test_documented_bounds_hash_their_cited_lines():
    """Section 3.1 (lineSha256 without its line feed; MET006-C2-9) and SE-6: both bases hash their lines at
    the head, and line 151 holds the sentence the contract quotes verbatim."""
    documented = _entry(_live()[0], *AI_INF)
    for basis in (documented["timeout"]["basis"], documented["retry"]["basis"]):
        assert HEX64.fullmatch(basis["lineSha256"])
        assert hashlib.sha256(_cited_line(basis["ref"])).hexdigest() == basis["lineSha256"]
    assert LINE_151 in _cited_line(documented["retry"]["basis"]["ref"])


def test_retry_and_idempotency_follow_section_3_2():
    """Section 3.2 (items 1 and 2; MET006-C1-5, MET006-C3-3) and SE-4: IDEMPOTENT_ONLY only with NATIVE;
    RECEIPT_KEY with operationIdField, policy NONE and maxAttempts 1; operationIdField absent otherwise; NONE
    with policy NONE and maxAttempts 1; operations classes distinct kebab-case tokens with no entry-level
    fields beside them."""
    for entry in _live()[0]["edges"]:
        retry = entry["retry"]
        assert _idempotency_problems(retry) == [], _key(entry)
        assert set(retry["backoff"]) == {"initialSeconds", "maxSeconds", "jitter"}, _key(entry)
        if "operations" in retry:
            assert set(retry) == {"operations", "backoff", "basis"}, _key(entry)
        else:
            required = {"idempotency", "policy", "maxAttempts", "backoff", "basis"}
            assert required <= set(retry) <= required | {"operationIdField"}, _key(entry)


def test_objectives_capacity_and_sli_follow_section_3_1():
    """Section 3.1 (objectives in SLO-D1's vocabulary, Q7; capacityAndOverloadRule and sli names only) and
    SE-8."""
    record, catalog, _, _ = _live()
    modes = _catalog_field(catalog, "mode")
    for entry in record["edges"]:
        mode = modes[(entry["consumer"], entry["dependency"])]
        objectives = entry["objectives"]
        assert set(objectives) == OBJECTIVES[mode], _key(entry)
        assert all(value in ("UNSPECIFIED", "REQUIRED") for value in objectives.values()), _key(entry)
        if mode == "SYNC":
            assert objectives["deadlinePropagation"] == "REQUIRED", _key(entry)
            assert objectives["cancellation"] == "REQUIRED", _key(entry)
        assert entry["capacityAndOverloadRule"] == "UNSPECIFIED", _key(entry)
        assert entry["sli"] == "UNSPECIFIED", _key(entry)


def test_degradation_and_audit_evidence_follow_the_failure_mode():
    """Section 3.1 (degradation, auditEvidence) and SE-9: FAIL_OPEN carries a named alternative and
    NOT_CARRIED or {preservedBy}; FAIL_CLOSED carries neither."""
    record, catalog, _, _ = _live()
    failure_modes = _catalog_field(catalog, "failureMode")
    for entry in record["edges"]:
        failure_mode = failure_modes[(entry["consumer"], entry["dependency"])]
        if failure_mode == "FAIL_OPEN":
            assert isinstance(entry["degradation"], str) and entry["degradation"].strip(), _key(entry)
            evidence = entry["auditEvidence"]
            if evidence != "NOT_CARRIED":
                assert isinstance(evidence, dict) and set(evidence) == {"preservedBy"}, _key(entry)
                assert isinstance(evidence["preservedBy"], str) and evidence["preservedBy"].strip(), _key(entry)
        else:
            assert failure_mode == "FAIL_CLOSED", _key(entry)
            assert entry["degradation"] is None, _key(entry)
            assert entry["auditEvidence"] is None, _key(entry)


def test_rule_a_jobs():
    """Section 3.1 (rule A; MON-287-CR3-AB, MET006-C3-2) and SE-2, SE-8: a job takes VIA
    external.kubernetes-api when the consumer depends on it; otherwise the job handed an artifact takes
    ARTIFACT_PATH with digest REQUIRED and integrity REQUIRED; tool-broker to sandbox-runner is the one
    instance."""
    record, catalog, _, _ = _live()
    services = _services(catalog)
    dependencies_of = _dependencies_of(catalog)
    modes = _catalog_field(catalog, "mode")
    entries = {(entry["consumer"], entry["dependency"]): entry for entry in record["edges"]}
    via_jobs, artifact_jobs = [], []
    for entry in record["edges"]:
        if services.get(entry["dependency"], {}).get("kind") != "job":
            continue
        forms = entry["transport"]
        if "external.kubernetes-api" in dependencies_of[entry["consumer"]]:
            assert len(forms) == 1, _key(entry)
            assert forms[0]["endpoint"] == {"kind": "VIA", "via": "external.kubernetes-api"}, _key(entry)
            api_entry = entries[(entry["consumer"], "external.kubernetes-api")]
            assert forms[0]["protocol"] in {f["protocol"] for f in api_entry["transport"]}, _key(entry)
            via_jobs.append(_key(entry))
        else:
            assert modes[(entry["consumer"], entry["dependency"])] == "ARTIFACT", _key(entry)
            for form in forms:
                assert form["endpoint"]["kind"] == "ARTIFACT_PATH", _key(entry)
                assert form["endpoint"].get("digest") == "REQUIRED", _key(entry)
                assert form["tls"] == TLS_LOCAL, _key(entry)
            assert entry["objectives"]["integrity"] == "REQUIRED", _key(entry)
            artifact_jobs.append(_key(entry))
    assert sorted(via_jobs) == ["fleet-sync-agent->bundle-verifier", "operator->bundle-verifier"]
    assert artifact_jobs == ["tool-broker->sandbox-runner"]


def test_rule_b_controller_handoffs_and_the_one_catalog_gap():
    """Sections 3.1 and 3.4 (rule B: a controller is never called; MET006-C4-2 to C4-4) and SE-13: five
    controller edges take VIA only, each mapped to one controller handoff whose via is the controller's store
    holding its object; one catalogGaps row, control-web to operator, with KUBERNETES_API from the
    controller side."""
    record, catalog, _, _ = _live()
    services = _services(catalog)
    dependencies_of = _dependencies_of(catalog)
    catalog_keys = {f"{consumer}->{dependency}" for consumer, dependency, _ in _catalog_edges(catalog)}
    controller_entries = [e for e in record["edges"] if services.get(e["dependency"], {}).get("kind") == "controller"]
    assert sorted(_key(entry) for entry in controller_entries) == sorted(CONTROLLER_EDGES)
    handoffs = [handoff for handoff in record["handoffs"] if handoff["kind"] == "CONTROLLER"]
    assert len(handoffs) == 5
    assert record["catalogGaps"] == [EXPECTED_GAP]
    missing = {row["missing"] for row in record["catalogGaps"]}
    for entry in controller_entries:
        controller = entry["dependency"]
        assert len(entry["transport"]) == 1, _key(entry)
        form = entry["transport"][0]
        assert form["endpoint"]["kind"] == "VIA" and "tls" not in form, _key(entry)
        matching = [h for h in handoffs if h["from"] == entry["consumer"] and h["to"] == controller]
        assert len(matching) == 1, _key(entry)
        handoff = matching[0]
        assert set(handoff) == {"kind", "from", "to", "via", "object", "consumerSide", "controllerSide"}
        via = handoff["via"]
        assert via == CONTROLLER_VIAS[controller], _key(entry)
        assert form["endpoint"]["via"] == via, _key(entry)
        assert via in {store["name"] for store in services[controller].get("stores") or []}, _key(entry)
        assert handoff["object"] == CONTROLLER_OBJECTS[controller], _key(entry)
        assert handoff["controllerSide"] == f"{controller}->{via}", _key(entry)
        assert handoff["controllerSide"] in catalog_keys, _key(entry)
        assert handoff["consumerSide"] == f"{entry['consumer']}->{via}", _key(entry)
        assert handoff["consumerSide"] in catalog_keys or handoff["consumerSide"] in missing, _key(entry)
    assert "external.kubernetes-api" not in dependencies_of["control-web"]
    assert EXPECTED_GAP["missing"] not in catalog_keys
    assert len(dependencies_of["control-web"]) == 7
    gap_entry = _entry(record, *CW_OP)
    assert gap_entry["transport"] == [
        {"protocol": "KUBERNETES_API", "endpoint": {"kind": "VIA", "via": "external.kubernetes-api"}}
    ]
    assert "KUBERNETES_API" in {form["protocol"] for form in _entry(record, *OP_K8S)["transport"]}


def test_worker_callees_take_via_through_a_shared_dependency():
    """Section 3.1 (the callee-kind table: worker) and SE-2, SE-3: index-worker and assurance-worker reach
    ingest-worker by VIA external.postgresql, a dependency of both sides."""
    record, catalog, _, _ = _live()
    services = _services(catalog)
    dependencies_of = _dependencies_of(catalog)
    workers = [e for e in record["edges"] if services.get(e["dependency"], {}).get("kind") == "worker"]
    assert sorted(_key(entry) for entry in workers) == ["assurance-worker->ingest-worker", "index-worker->ingest-worker"]
    for entry in workers:
        assert len(entry["transport"]) == 1, _key(entry)
        endpoint = entry["transport"][0]["endpoint"]
        assert endpoint == {"kind": "VIA", "via": "external.postgresql"}, _key(entry)
        assert endpoint["via"] in dependencies_of[entry["consumer"]], _key(entry)
        assert endpoint["via"] in dependencies_of[entry["dependency"]], _key(entry)


def test_graph_mapping_and_the_request_handoff():
    """Section 3.4 (Q6, MET006-C1-7) and SE-13: twelve of the graph's 13 request edges map to an entry by
    their (from, to) key, branch common for the 3 common admission edges; orchestration-api to
    orchestration-worker is the declared request handoff through external.postgresql."""
    record, _, graph, _ = _live()
    request_graph = graph["runtimeRequestGraph"]
    entry_keys = {_key(entry) for entry in record["edges"]}
    expected = [("common", edge["from"], edge["to"]) for edge in request_graph["commonAdmissionEdges"]]
    request_edges = len(request_graph["commonAdmissionEdges"])
    for branch in request_graph["branches"]:
        for edge in branch["edges"]:
            request_edges += 1
            if (edge["from"], edge["to"]) == ("orchestration-api", "orchestration-worker"):
                continue
            expected.append((branch["id"], edge["from"], edge["to"]))
    assert request_edges == 13
    rows = record["graphMapping"]
    assert len(rows) == 12
    assert sorted((row["branch"], row["from"], row["to"]) for row in rows) == sorted(expected)
    for row in rows:
        assert set(row) == {"branch", "from", "to", "edge"}
        assert row["edge"] == f"{row['from']}->{row['to']}"
        assert row["edge"] in entry_keys
    requests = [handoff for handoff in record["handoffs"] if handoff["kind"] == "REQUEST"]
    assert requests == [EXPECTED_REQUEST_HANDOFF]
    assert EXPECTED_REQUEST_HANDOFF["write"] in entry_keys
    assert EXPECTED_REQUEST_HANDOFF["lease"] in entry_keys


def test_request_path_edges_are_admission_or_invocation():
    """Section 3.6 and SE-7: every request-path edge (the mapped graph edges and the handoff's two store
    edges) is ADMISSION or INVOCATION and never CONTROL; no ARTIFACT edge is INVOCATION."""
    record, catalog, graph, _ = _live()
    modes = _catalog_field(catalog, "mode")
    assert graph["controlPlaneOnRuntimePath"] is False
    by_key = {_key(entry): entry for entry in record["edges"]}
    request_keys = {row["edge"] for row in record["graphMapping"]}
    request_keys |= {EXPECTED_REQUEST_HANDOFF["write"], EXPECTED_REQUEST_HANDOFF["lease"]}
    for key in request_keys:
        entry = by_key[key]
        assert entry["lifecyclePhase"] in CALL_PHASES, key
        assert modes[(entry["consumer"], entry["dependency"])] not in ("CONTROL", "ARTIFACT"), key
    for entry in record["edges"]:
        if modes[(entry["consumer"], entry["dependency"])] == "ARTIFACT":
            assert entry["lifecyclePhase"] != "INVOCATION", _key(entry)


def test_repeated_calls_are_recomputed_from_section_3_6():
    """Section 3.6 (MET006-C1-6, MET006-C3-4) and SE-11: 8, 12 and 2 maximal request paths, and the header's
    repeatedCalls equals the sorted list recomputed from the graph and the entries' phases."""
    record, _, graph, _ = _live()
    paths = dict(_maximal_request_paths(graph))
    assert {branch: len(found) for branch, found in paths.items()} == {
        "direct-model": 8,
        "task": 12,
        "experience-task-control": 2,
    }
    assert record["repeatedCalls"] == _expected_repeated_calls(record, graph)


def test_repeated_call_justification_only_where_section_3_1_puts_it():
    """Section 3.1 (cache, repeatedCallJustification) and SE-11: a statement on every grouped entry that is
    not BOUNDED_METADATA, null on every other entry."""
    record = _live()[0]
    grouped = {edge for row in record["repeatedCalls"] for edge in row["edges"]}
    for entry in record["edges"]:
        cache = entry["cache"]
        assert cache == {"kind": "NONE"} or (
            cache.get("kind") == "BOUNDED_METADATA"
            and set(cache) == {"kind", "freshness", "revocation", "outage"}
            and all(isinstance(cache[m], str) and cache[m].strip() for m in ("freshness", "revocation", "outage"))
        ), _key(entry)
        justification = entry["repeatedCallJustification"]
        if _key(entry) in grouped and cache.get("kind") != "BOUNDED_METADATA":
            assert isinstance(justification, str) and justification.strip(), _key(entry)
        else:
            assert justification is None, _key(entry)


def test_no_value_names_a_mesh():
    """SE-12 (MESH-D1): no value of the record names a mesh, a sidecar or an injected proxy."""
    assert [text for text in _strings(_live()[0]) if MESH_WORDS.search(text)] == []


# ---------------------------------------------------------------------------------------------------------
# 2. SE-1 to SE-14 (section 4): mutations of a deep copy of the live record, each refused by its rule.
# ---------------------------------------------------------------------------------------------------------

SE1_CASES = [
    pytest.param(_drop_entry(AI_GRD), id="an-entry-missing"),
    pytest.param(_duplicate_entry(AI_GRD), id="an-entry-twice"),
    pytest.param(_entry_like(AI_GRD, "ai-gateway", "registry-service"), id="an-orphan-entry"),
    pytest.param(_entry_like(AI_GRD, "ai-gateway", "unknown-service"), id="an-id-not-in-the-catalog"),
    pytest.param(_setter(None, ("externalProviders", "external.pgvector"), DELETE), id="providers-miss-an-external"),
    pytest.param(
        _setter(
            None,
            ("externalProviders", "external.unlisted-store"),
            {"value": "OPERATOR", "source": {"ref": "architecture/services.yaml#L250", "phrase": "Operator-supplied"}},
        ),
        id="providers-name-an-unknown-external",
    ),
    pytest.param(
        _setter(None, ("externalEndpointKinds", "external.signed-catalog"), DELETE),
        id="endpoint-kinds-miss-an-external",
    ),
    pytest.param(
        _setter(
            None,
            ("externalEndpointKinds", "external.unlisted-store"),
            {
                "kinds": ["EXTERNAL"],
                "source": {"ref": "architecture/services.yaml#L250", "phrase": "Kubernetes, K3s, or OpenShift API"},
            },
        ),
        id="endpoint-kinds-name-an-unknown-external",
    ),
]


@pytest.mark.parametrize("mutate", SE1_CASES)
def test_se1_coverage(mutate):
    """SE-1 (section 4): exactly one entry per catalog dependency, no orphan, every id in the catalog, and
    externalProviders and externalEndpointKinds covering the 14 externals exactly."""
    assert "SE-1" in _refusals_after(mutate)


SE2_CASES = [
    pytest.param(_setter(AI_GRD, ("mode",), "SYNC"), id="entry-carries-mode"),
    pytest.param(_setter(AI_GRD, ("required",), True), id="entry-carries-required"),
    pytest.param(_setter(AI_GRD, ("failureMode",), "FAIL_CLOSED"), id="entry-carries-failure-mode"),
    pytest.param(_setter(AI_GRD, ("sli",), DELETE), id="entry-misses-a-member"),
    pytest.param(_setter(AI_GRD, ("lifecyclePhase",), "RUNTIME"), id="phase-outside-the-enum"),
    pytest.param(_setter(AI_GRD, ("requiredState",), "Guardrail_Ready"), id="required-state-not-kebab"),
    pytest.param(_setter(AI_GRD, ("requiredState",), ""), id="required-state-empty"),
    pytest.param(
        _setter(AI_GRD, ("timeout",), {"fetchSeconds": "UNSPECIFIED", "basis": {"kind": "UNSPECIFIED"}}),
        id="sync-entry-with-artifact-timeout",
    ),
    pytest.param(
        _setter(OP_K8S, ("timeout",), {"publishAckSeconds": "UNSPECIFIED", "basis": {"kind": "UNSPECIFIED"}}),
        id="control-entry-with-async-timeout",
    ),
    pytest.param(_setter(AI_GRD, ("retry", "policy"), "ALWAYS"), id="retry-policy-outside-the-enum"),
    pytest.param(_setter(AI_GRD, ("cache",), {"kind": "LRU"}), id="cache-kind-outside-the-enum"),
    pytest.param(_setter(AI_GRD, ("transport", 0, "protocol"), "AMQP"), id="protocol-outside-the-enum"),
    pytest.param(_setter(AI_GRD, ("transport", 0, "endpoint", "port"), "8443"), id="port-not-named"),
    pytest.param(
        _setter(AI_GRD, ("transport", 0, "endpoint", "service"), "policy-decision"),
        id="service-not-the-callee",
    ),
    pytest.param(
        _setter(AI_GRD, ("transport", 0, "endpoint", "namespace"), "default"),
        id="service-dns-with-a-namespace",
    ),
    pytest.param(_setter(AI_GRD, ("transport",), []), id="transport-empty"),
    pytest.param(
        _setter(AI_GRD, ("transport",), [{"protocol": "POSTGRESQL", "endpoint": {"kind": "VIA", "via": "external.postgresql"}}]),
        id="api-callee-by-via",
    ),
    pytest.param(_setter(FSA_OP, ("transport",), [_dns("operator")]), id="controller-called-by-service-dns"),
    pytest.param(_setter(IDX_IW, ("transport",), [_dns("ingest-worker")]), id="worker-called-by-service-dns"),
    pytest.param(
        _setter(
            OP_BV,
            ("transport",),
            [
                {
                    "protocol": "FILESYSTEM",
                    "endpoint": {"kind": "ARTIFACT_PATH", "path": "bundle-verifier/job-spec", "digest": "REQUIRED"},
                    "tls": dict(TLS_LOCAL),
                }
            ],
        ),
        id="rule-a-job-with-api-takes-via",
    ),
    pytest.param(
        _setter(
            BV_RTS,
            ("transport",),
            [{"protocol": "HTTP", "endpoint": {"kind": "EXTERNAL", "ref": "external.release-trust-store"}, "tls": dict(TLS_NETWORK)}],
        ),
        id="external-kind-not-in-its-row",
    ),
    pytest.param(
        _setter(None, ("externalEndpointKinds", "external.local-oci-source", "kinds"), ["EXTERNAL"]),
        id="row-drops-a-used-kind",
    ),
    pytest.param(
        _setter(None, ("externalEndpointKinds", "external.postgresql", "source", "ref"), "architecture/services.yaml#L255"),
        id="row-cites-another-line",
    ),
    pytest.param(
        _setter(None, ("externalEndpointKinds", "external.opa-engine", "source", "phrase"), "Remote OPA cluster"),
        id="row-phrase-not-on-its-line",
    ),
    pytest.param(_setter(None, ("notes",), "an extra header member"), id="header-extra-member"),
    pytest.param(
        _setter(None, ("schemaVersion",), "harness.planeon.ai/service-edges/v1alpha2"),
        id="header-schema-version",
    ),
    pytest.param(_setter(OP_BV, ("transport", 0, "protocol"), "HTTP"), id="via-protocol-not-its-via-entrys"),
    pytest.param(_setter(CW_OP, ("transport", 0, "protocol"), "POSTGRESQL"), id="gap-via-protocol-not-controller-sides"),
    pytest.param(_catalog_kind("guardrail-service", "agent"), id="callee-kind-not-in-the-table"),
]


@pytest.mark.parametrize("mutate", SE2_CASES)
def test_se2_closed_shape(mutate):
    """SE-2 (section 4; sections 3 and 3.1): members exactly per catalog mode, closed enums, closed transport
    forms and the callee-kind table (rule A, rule B), each external form within its externalEndpointKinds row
    whose source is the external's own line holding its phrase, and the header's closed member set."""
    assert "SE-2" in _refusals_after(mutate)


SE3_CASES = [
    pytest.param(_setter(AI_GRD, ("transport", 0, "tls", "minVersion"), "1.2"), id="service-dns-tls-1-2"),
    pytest.param(_setter(AI_GRD, ("transport", 0, "tls", "minVersion"), 1.3), id="min-version-not-the-string"),
    pytest.param(_setter(AI_GRD, ("transport", 0, "tls"), {"required": True}), id="min-version-missing"),
    pytest.param(_setter(OP_K8S, ("transport", 0, "tls"), {"required": False}), id="external-form-without-tls"),
    pytest.param(_setter(BV_OCI, ("transport", 1, "tls", "minVersion"), "1.2"), id="second-form-tls-1-2"),
    pytest.param(
        _setter(BV_RTS, ("transport", 0, "tls"), {"required": True, "minVersion": "1.3"}),
        id="artifact-path-claims-network-tls",
    ),
    pytest.param(
        _setter(TB_SR, ("transport", 0, "tls"), {"required": True, "minVersion": "1.3"}),
        id="job-artifact-path-claims-network-tls",
    ),
    pytest.param(
        _setter(OP_BV, ("transport", 0, "tls"), {"required": True, "minVersion": "1.3"}),
        id="via-form-with-tls",
    ),
    pytest.param(
        _setter(IDX_IW, ("transport", 0, "endpoint", "via"), "external.tenant-object-store"),
        id="via-not-a-dependency-of-the-consumer",
    ),
]


@pytest.mark.parametrize("mutate", SE3_CASES)
def test_se3_tls(mutate):
    """SE-3 (section 4; section 3.1 tls, OQ-287-2): required true and minVersion exactly "1.3" on every
    SERVICE_DNS or EXTERNAL form, required false on UNIX_SOCKET and ARTIFACT_PATH, no tls on a VIA form, whose
    via names another dependency of the same consumer or a listed gap's via."""
    assert "SE-3" in _refusals_after(mutate)


SE4_CASES = [
    pytest.param(_setter(CW_PG, ("retry", "policy"), "IDEMPOTENT_ONLY"), id="none-with-idempotent-only"),
    pytest.param(_setter(CW_PG, ("retry", "maxAttempts"), 2), id="none-with-retries"),
    pytest.param(_setter(CW_PG, ("retry", "idempotency"), "RECEIPT_KEY"), id="receipt-key-without-its-field"),
    pytest.param(
        _both(
            _setter(CW_PG, ("retry", "idempotency"), "RECEIPT_KEY"),
            _setter(CW_PG, ("retry", "operationIdField"), "operationId"),
            _setter(CW_PG, ("retry", "policy"), "IDEMPOTENT_ONLY"),
        ),
        id="receipt-key-with-idempotent-only",
    ),
    pytest.param(
        _both(
            _setter(CW_PG, ("retry", "idempotency"), "RECEIPT_KEY"),
            _setter(CW_PG, ("retry", "operationIdField"), "operationId"),
            _setter(CW_PG, ("retry", "maxAttempts"), 2),
        ),
        id="receipt-key-retried-before-288",
    ),
    pytest.param(_setter(AI_GRD, ("retry", "operationIdField"), "requestId"), id="native-with-operation-id-field"),
    pytest.param(_setter(CW_PG, ("retry", "operationIdField"), "requestId"), id="none-with-operation-id-field"),
    pytest.param(
        _setter(AI_INF, ("retry", "operations", 1, "policy"), "IDEMPOTENT_ONLY"),
        id="class-none-with-idempotent-only",
    ),
    pytest.param(_setter(AI_INF, ("retry", "operations", 1, "maxAttempts"), 2), id="non-idempotent-class-retried"),
    pytest.param(_setter(AI_INF, ("retry", "operations", 0, "idempotency"), "NONE"), id="class-none-retried"),
    pytest.param(
        _setter(AI_INF, ("retry", "operations", 1, "idempotency"), "RECEIPT_KEY"),
        id="class-receipt-key-without-its-field",
    ),
    pytest.param(
        _both(
            _setter(AI_INF, ("retry", "operations", 0, "idempotency"), "RECEIPT_KEY"),
            _setter(AI_INF, ("retry", "operations", 0, "operationIdField"), "operationId"),
        ),
        id="class-receipt-key-with-idempotent-only",
    ),
    pytest.param(
        _setter(AI_INF, ("retry", "operations", 0, "operationIdField"), "requestId"),
        id="class-native-with-operation-id-field",
    ),
    pytest.param(
        _setter(AI_INF, ("retry", "operations", 1, "class"), "idempotent-requests"),
        id="classes-not-distinct",
    ),
    pytest.param(
        _setter(AI_INF, ("retry", "operations", 0, "class"), "Idempotent_Requests"),
        id="class-not-kebab",
    ),
    pytest.param(
        _setter(AI_INF, ("retry", "operationIdField"), "operationId"),
        id="entry-level-operation-id-field-beside-operations",
    ),
]


@pytest.mark.parametrize("mutate", SE4_CASES)
def test_se4_retry_and_idempotency(mutate):
    """SE-4 (section 4; section 3.2 items 1-3, the idempotency rule): IDEMPOTENT_ONLY only with NATIVE;
    RECEIPT_KEY names operationIdField and takes policy NONE and maxAttempts 1; operationIdField absent
    otherwise, on an entry and a class alike and at entry level beside operations; NONE takes policy NONE and
    maxAttempts 1; classes distinct kebab-case tokens; no non-idempotent class retries."""
    assert "SE-4" in _refusals_after(mutate)


SE5_CASES = [
    pytest.param(_setter(AI_INF, ("timeout", "connectSeconds"), 31), id="connect-exceeds-ceiling"),
    pytest.param(_setter(AI_INF, ("timeout", "ceilingSeconds"), 1), id="ceiling-below-connect"),
    pytest.param(_setter(AI_INF, ("timeout", "attemptSeconds"), 1), id="connect-exceeds-attempt"),
    pytest.param(
        _both(
            _setter(AI_INF, ("timeout", "attemptSeconds"), 10),
            _setter(AI_INF, ("retry", "backoff", "maxSeconds"), 1),
        ),
        id="sum-over-ceiling-by-the-largest-class",
    ),
    pytest.param(_setter(EXP_AI, ("timeout", "ceilingSeconds"), 20), id="callee-ceiling-not-below-callers"),
]


@pytest.mark.parametrize("mutate", SE5_CASES)
def test_se5_deadline(mutate):
    """SE-5 (section 4; section 3.3, MET006-C1-4, MET006-C3-6): maxAttempts x attemptSeconds + (maxAttempts -
    1) x backoff.maxSeconds <= ceilingSeconds with a split entry's largest class maxAttempts; connectSeconds
    not above attemptSeconds or ceilingSeconds; a callee's ceilingSeconds below its caller's along a request
    path."""
    assert "SE-5" in _refusals_after(mutate)


SE6_CASES = [
    pytest.param(_setter(AI_INF, ("timeout", "basis", "lineSha256"), "0" * 64), id="line-hash-differs"),
    pytest.param(
        _setter(AI_INF, ("timeout", "basis", "ref"), "docs/harnesses/runtime.ai-gateway.md#L99999"),
        id="cited-line-missing",
    ),
    pytest.param(
        _setter(AI_INF, ("timeout", "basis", "ref"), "docs/harnesses/runtime.ai-gateway.md#L149"),
        id="cited-line-moved",
    ),
    pytest.param(
        _setter(AI_INF, ("timeout", "basis", "ref"), "docs/harnesses/runtime.no-such-harness.md#L150"),
        id="cited-path-missing",
    ),
    pytest.param(
        _setter(AI_INF, ("retry", "basis", "ref"), "docs/harnesses/runtime.ai-gateway.md#L150"),
        id="retry-basis-hash-of-another-line",
    ),
    pytest.param(_setter(AI_INF, ("timeout", "basis"), {"kind": "UNSPECIFIED"}), id="numeric-timeout-without-basis"),
    pytest.param(_setter(AI_INF, ("retry", "basis"), {"kind": "UNSPECIFIED"}), id="three-attempts-without-basis"),
    pytest.param(_setter(AI_POL, ("timeout", "connectSeconds"), 1), id="number-under-unspecified-timeout-basis"),
    pytest.param(_setter(OTEL, ("timeout", "publishAckSeconds"), 5), id="async-number-under-unspecified-basis"),
    pytest.param(
        _setter(AI_POL, ("retry", "backoff", "initialSeconds"), 1),
        id="backoff-number-under-unspecified-retry-basis",
    ),
    pytest.param(
        _both(
            _setter(AI_POL, ("retry", "policy"), "IDEMPOTENT_ONLY"),
            _setter(AI_POL, ("retry", "maxAttempts"), 2),
        ),
        id="attempts-above-one-without-basis",
    ),
]


@pytest.mark.parametrize("mutate", SE6_CASES)
def test_se6_basis(mutate):
    """SE-6 (section 4; section 3.1 basis, OQ-287-1, MET006-C1-11, MET006-C3-6): a DOCUMENTED_BOUND cites a
    path and line that exist at the head and hash to lineSha256; every numeric timeout and numeric maxAttempts
    above 1 has a DOCUMENTED_BOUND basis; an UNSPECIFIED basis leaves every timeout or backoff value
    UNSPECIFIED."""
    assert "SE-6" in _refusals_after(mutate)


SE7_CASES = [
    pytest.param(_setter(AI_INF, ("lifecyclePhase",), "BACKGROUND_RECONCILIATION"), id="request-edge-in-background"),
    pytest.param(_setter(AI_POL, ("lifecyclePhase",), "STARTUP"), id="request-edge-at-startup"),
    pytest.param(_setter(AI_GRD, ("lifecyclePhase",), "INSTALL"), id="request-edge-at-install"),
    pytest.param(_setter(OW_PG, ("lifecyclePhase",), "OBSERVATION"), id="handoff-lease-edge-in-observation"),
    pytest.param(_setter(OA_PG, ("lifecyclePhase",), "BACKGROUND_RECONCILIATION"), id="handoff-write-edge-in-background"),
    pytest.param(_setter(TB_SR, ("lifecyclePhase",), "INVOCATION"), id="job-artifact-edge-invoked"),
    pytest.param(_setter(BV_OCI, ("lifecyclePhase",), "INVOCATION"), id="artifact-edge-invoked"),
]


@pytest.mark.parametrize("mutate", SE7_CASES)
def test_se7_lifecycle(mutate):
    """SE-7 (section 4; section 3.6): every request-path edge, the handoff's two store edges included, is
    ADMISSION or INVOCATION; no INSTALL or STARTUP request-path edge; an ARTIFACT edge is never INVOCATION."""
    assert "SE-7" in _refusals_after(mutate)


SE8_CASES = [
    pytest.param(_setter(AI_GRD, ("objectives", "cancellation"), DELETE), id="sync-misses-cancellation"),
    pytest.param(_setter(AI_GRD, ("objectives", "throughput"), "UNSPECIFIED"), id="name-outside-the-vocabulary"),
    pytest.param(_setter(AI_GRD, ("objectives", "deadlinePropagation"), "UNSPECIFIED"), id="sync-propagation-not-required"),
    pytest.param(_setter(AI_GRD, ("objectives", "latency"), "250ms"), id="objective-carries-a-number"),
    pytest.param(
        _setter(OTEL, ("objectives",), {"latency": "UNSPECIFIED", "deadlinePropagation": "REQUIRED", "cancellation": "REQUIRED"}),
        id="async-with-sync-names",
    ),
    pytest.param(
        _setter(OP_K8S, ("objectives",), {"convergence": "UNSPECIFIED", "lag": "UNSPECIFIED"}),
        id="control-with-an-async-name",
    ),
    pytest.param(_setter(BV_RTS, ("objectives",), {"integrity": "REQUIRED"}), id="artifact-misses-readiness"),
    pytest.param(_setter(AI_GRD, ("capacityAndOverloadRule",), "100 requests per second"), id="capacity-rule-valued"),
    pytest.param(_setter(AI_GRD, ("sli",), "p99-latency"), id="sli-valued"),
    pytest.param(_setter(TB_SR, ("objectives", "integrity"), "UNSPECIFIED"), id="rule-a-integrity-not-required"),
    pytest.param(_setter(TB_SR, ("transport", 0, "endpoint", "digest"), DELETE), id="rule-a-digest-missing"),
]


@pytest.mark.parametrize("mutate", SE8_CASES)
def test_se8_objectives(mutate):
    """SE-8 (section 4; section 3.1 objectives, Q7, MON-287-CR1-RULINGS 2): exactly the mode's names, values
    UNSPECIFIED or REQUIRED, SYNC deadlinePropagation and cancellation REQUIRED, capacityAndOverloadRule and
    sli UNSPECIFIED; on a job edge with an ARTIFACT_PATH form, integrity REQUIRED and digest REQUIRED (rule
    A)."""
    assert "SE-8" in _refusals_after(mutate)


SE9_CASES = [
    pytest.param(_setter(OTEL, ("degradation",), None), id="fail-open-without-alternative"),
    pytest.param(_setter(OTEL, ("degradation",), ""), id="fail-open-with-empty-alternative"),
    pytest.param(_setter(OTEL, ("auditEvidence",), None), id="fail-open-without-audit-evidence"),
    pytest.param(_setter(OTEL, ("auditEvidence",), {"preservedBy": ""}), id="fail-open-with-empty-preserved-by"),
    pytest.param(_setter(CW_OP, ("auditEvidence",), "DROPPED"), id="fail-open-audit-evidence-dropped"),
    pytest.param(_setter(AI_GRD, ("degradation",), "a held decision is used instead"), id="fail-closed-with-alternative"),
    pytest.param(_setter(AI_GRD, ("auditEvidence",), "NOT_CARRIED"), id="fail-closed-with-not-carried"),
    pytest.param(
        _setter(AI_GRD, ("auditEvidence",), {"preservedBy": "the gateway's own audit outbox"}),
        id="fail-closed-with-preserved-by",
    ),
]


@pytest.mark.parametrize("mutate", SE9_CASES)
def test_se9_degradation_and_audit_evidence(mutate):
    """SE-9 (section 4; section 3.1 degradation and auditEvidence, SLO-D1): a FAIL_OPEN edge carries a named
    alternative and NOT_CARRIED or {preservedBy}; a FAIL_CLOSED edge carries neither."""
    assert "SE-9" in _refusals_after(mutate)


SE10_CASES = [
    pytest.param(_setter(AI_GRD, ("owner", "provider"), "mas-harness-model-plane"), id="platform-provider-wrong"),
    pytest.param(_setter(AI_GRD, ("owner", "escalation"), "mas-harness-runtime-plane"), id="platform-escalation-not-provider"),
    pytest.param(_setter(AI_GRD, ("owner", "consumer"), "mas-harness-trust-plane"), id="consumer-not-its-repository"),
    pytest.param(_setter(OTEL, ("owner", "provider"), "OPERATOR"), id="external-provider-not-its-row"),
    pytest.param(_setter(OTEL, ("owner", "escalation"), "TENANT"), id="external-escalation-not-consumer"),
    pytest.param(
        _setter(None, ("externalProviders", "external.kubernetes-api", "source", "phrase"), "Tenant-supplied"),
        id="row-phrase-not-on-its-line",
    ),
    pytest.param(_provider_value_everywhere("external.postgresql", "TENANT"), id="row-value-not-its-phrase"),
    pytest.param(_provider_value_everywhere("external.oidc-provider", "OPERATOR"), id="phrase-map-order"),
    pytest.param(
        _setter(
            None,
            ("externalProviders", "external.signed-catalog", "source"),
            {"ref": "architecture/services.yaml#L263", "phrase": "Digest-pinned industry-pack artifact"},
        ),
        id="precedence-one-own-line-not-cited",
    ),
    pytest.param(
        _setter(
            None,
            ("externalProviders", "external.opa-engine", "source", "phrase"),
            f"operator-supplied {ELLIPSIS} Kafka",
        ),
        id="a-phrase-part-not-on-the-line",
    ),
    pytest.param(
        _setter(
            None,
            ("externalProviders", "external.otel-backend", "source", "ref"),
            "docs/harnesses/trust.observability-finops.md#L99999",
        ),
        id="row-cites-a-missing-line",
    ),
]


@pytest.mark.parametrize("mutate", SE10_CASES)
def test_se10_owner(mutate):
    """SE-10 (section 4; sections 3.1 owner and 3.7): owner per section 3.1 with each external's provider
    from externalProviders; each row's cited line exists and holds every phrase part; the phrase states the
    value by the phrase map; precedence 1 cites the external's own catalog line."""
    assert "SE-10" in _refusals_after(mutate)


SE11_CASES = [
    pytest.param(_repeated(_rows_without_last), id="a-row-missing"),
    pytest.param(_repeated(_rows_first_two_swapped), id="rows-out-of-order"),
    pytest.param(_repeated(_rows_first_edges_reversed), id="row-edges-unsorted"),
    pytest.param(_repeated(_rows_with_bogus_registry_row), id="a-row-not-recomputed"),
    pytest.param(_repeated(_rows_with_trimmed_group), id="a-group-misses-an-edge"),
    pytest.param(_setter(AI_POL, ("repeatedCallJustification",), None), id="grouped-entry-without-justification"),
    pytest.param(
        _setter(AI_GRD, ("repeatedCallJustification",), "a statement on an entry in no row"),
        id="stray-justification",
    ),
    pytest.param(_setter(AI_POL, ("cache",), BOUNDED), id="bounded-metadata-entry-keeps-justification"),
]


@pytest.mark.parametrize("mutate", SE11_CASES)
def test_se11_repeated_calls(mutate):
    """SE-11 (section 4; section 3.6, MET006-C3-4): the header's repeatedCalls equals the recomputed sorted
    list; every grouped edge is BOUNDED_METADATA or carries a justification; no justification on an entry in
    no row or on a BOUNDED_METADATA entry."""
    assert "SE-11" in _refusals_after(mutate)


SE12_CASES = [
    pytest.param(
        _setter(OTEL, ("degradation",), "Telemetry export is retried by the service mesh until the budget is exhausted."),
        id="degradation-names-a-mesh",
    ),
    pytest.param(_setter(AI_GRD, ("requiredState",), "sidecar-ready"), id="required-state-names-a-sidecar"),
    pytest.param(
        _setter(OTEL, ("auditEvidence",), {"preservedBy": "an injected proxy replays the export"}),
        id="audit-evidence-names-an-injected-proxy",
    ),
    pytest.param(
        _setter(AI_POL, ("repeatedCallJustification",), "the sidecar holds each decision for the path"),
        id="justification-names-a-sidecar",
    ),
    pytest.param(
        _setter(CW_OP, ("degradation",), "The installation projection stays readable; retries are delegated to the mesh."),
        id="retries-delegated-to-the-mesh",
    ),
]


@pytest.mark.parametrize("mutate", SE12_CASES)
def test_se12_no_mesh(mutate):
    """SE-12 (section 4; MESH-D1): no value names a mesh, a sidecar or an injected proxy, and no field
    delegates retries to infrastructure."""
    assert "SE-12" in _refusals_after(mutate)


SE13_CASES = [
    pytest.param(_drop_mapping("ai-gateway->inference-api"), id="request-edge-unmapped"),
    pytest.param(_mapping_edge("ai-gateway->inference-api", "ai-gateway->governance-service"), id="mapping-to-another-entry"),
    pytest.param(_drop_handoff("REQUEST", "orchestration-api", "orchestration-worker"), id="request-handoff-missing"),
    pytest.param(_drop_handoff("CONTROLLER", "decision-service", "connector-controller"), id="controller-handoff-missing"),
    pytest.param(
        _handoff_member("CONTROLLER", "fleet-sync-agent", "operator", "controllerSide", "operator->external.postgresql"),
        id="controller-side-not-a-catalog-edge",
    ),
    pytest.param(_controller_via_not_its_store, id="via-not-the-controllers-store"),
    pytest.param(
        _setter(RS_CC, ("transport", 0, "endpoint", "via"), "external.pgvector"),
        id="entry-via-not-its-handoffs",
    ),
    pytest.param(_setter(None, ("catalogGaps",), []), id="one-sided-via-without-a-gap"),
    pytest.param(
        _setter(None, ("catalogGaps", 0, "missing"), "control-web->external.postgresql"),
        id="gap-missing-edge-is-in-the-catalog",
    ),
]


@pytest.mark.parametrize("mutate", SE13_CASES)
def test_se13_graph_and_handoffs(mutate):
    """SE-13 (section 4; section 3.4, rule B, MET006-C4-4): every request edge maps through graphMapping to an
    entry or the request handoff; every controller entry maps to one controller handoff whose via is the
    entry's VIA via and the controller's store, controllerSide a catalog edge, consumerSide a catalog edge or a
    listed gap's missing edge; the catalog lacks every gap's missing edge."""
    assert "SE-13" in _refusals_after(mutate)


SE14_CASES = [
    pytest.param(_bump(("counts", "edges"), -1), id="edges"),
    pytest.param(_bump(("counts", "byLifecyclePhase", "INVOCATION"), -1), id="by-lifecycle-phase"),
    pytest.param(_bump(("counts", "byProtocol", "HTTP"), 1), id="by-protocol"),
    pytest.param(_bump(("counts", "byEndpointKind", "VIA"), -1), id="by-endpoint-kind"),
    pytest.param(_bump(("counts", "byIdempotency", "NONE"), -1), id="by-idempotency"),
    pytest.param(_bump(("counts", "networkForms"), -1), id="network-forms"),
    pytest.param(_bump(("counts", "localForms"), 1), id="local-forms"),
    pytest.param(_bump(("counts", "viaForms"), 1), id="via-forms"),
    pytest.param(_bump(("counts", "numericEdges"), -1), id="numeric-edges"),
    pytest.param(_bump(("counts", "shapeOnlyEdges"), -1), id="shape-only-edges"),
    pytest.param(_setter(AI_GRD, ("lifecyclePhase",), "INVOCATION"), id="phase-moved-without-recount"),
    pytest.param(_setter(AI_GRD, ("transport", 0, "protocol"), "GRPC"), id="protocol-moved-without-recount"),
]


@pytest.mark.parametrize("mutate", SE14_CASES)
def test_se14_counts(mutate):
    """SE-14 (section 4; section 3.5, MET006-C3-7): the header's counts equal the checker's recount."""
    assert "SE-14" in _refusals_after(mutate)


MULTI_RULE_CASES = [
    pytest.param(frozenset({"SE-2", "SE-3"}), _setter(AI_GRD, ("transport", 0, "tls"), DELETE), id="network-form-without-tls"),
    pytest.param(
        frozenset({"SE-2", "SE-3"}),
        _setter(IDX_IW, ("transport", 0, "endpoint", "via"), "ingest-worker"),
        id="via-names-its-own-dependency",
    ),
    pytest.param(
        frozenset({"SE-2", "SE-3"}),
        _setter(TB_SR, ("transport",), [{"protocol": "KUBERNETES_API", "endpoint": {"kind": "VIA", "via": "external.kubernetes-api"}}]),
        id="rule-a-job-without-api-takes-artifact-path",
    ),
    pytest.param(
        frozenset({"SE-2", "SE-4"}),
        _setter(AI_INF, ("retry", "idempotency"), "NATIVE"),
        id="entry-level-idempotency-beside-operations",
    ),
    pytest.param(
        frozenset({"SE-2", "SE-4"}),
        _setter(AI_INF, ("retry", "maxAttempts"), 1),
        id="entry-level-max-attempts-beside-operations",
    ),
    pytest.param(frozenset({"SE-2", "SE-5"}), _setter(AI_GRD, ("timeout", "deadline"), "LOCAL"), id="deadline-not-propagated"),
    pytest.param(frozenset({"SE-2", "SE-14"}), _setter(None, ("counts", "forms"), 133), id="counts-extra-member"),
    pytest.param(
        frozenset({"SE-2", "SE-13"}),
        _handoff_member("CONTROLLER", "fleet-sync-agent", "operator", "note", "an extra member"),
        id="controller-handoff-extra-member",
    ),
]


@pytest.mark.parametrize(("rules", "mutate"), MULTI_RULE_CASES)
def test_refusal_names_one_of_the_rules_the_contract_allows(rules, mutate):
    """Section 4: where the contract states a check under two rules (closed shape beside TLS, retry, deadline,
    counts or handoffs), the refusal names one of them."""
    assert set(_refusals_after(mutate)) & rules


# ---------------------------------------------------------------------------------------------------------
# 3. Shapes the contract accepts (sections 3.1, 3.2, 3.3): no refusal from the rule that governs them.
# ---------------------------------------------------------------------------------------------------------


def _receipt_key_entry(record, catalog):
    _entry(record, *CW_PG)["retry"].update(
        {"idempotency": "RECEIPT_KEY", "policy": "NONE", "maxAttempts": 1, "operationIdField": "operationId"}
    )


def _receipt_key_class(record, catalog):
    _entry(record, *AI_INF)["retry"]["operations"][1].update(
        {"idempotency": "RECEIPT_KEY", "operationIdField": "operationId"}
    )


def _split_entry(record, catalog):
    retry = _entry(record, *CW_PG)["retry"]
    for member in ("idempotency", "policy", "maxAttempts"):
        del retry[member]
    retry["operations"] = [
        {"class": "reads", "idempotency": "NATIVE", "policy": "NONE", "maxAttempts": 1},
        {"class": "writes", "idempotency": "NONE", "policy": "NONE", "maxAttempts": 1},
    ]


ACCEPTED_CASES = [
    pytest.param(_receipt_key_entry, id="receipt-key-entry-with-its-field"),
    pytest.param(_receipt_key_class, id="receipt-key-class-with-its-field"),
    pytest.param(_split_entry, id="operations-split-counted-per-class"),
    pytest.param(
        _both(_setter(AI_POL, ("cache",), BOUNDED), _setter(AI_POL, ("repeatedCallJustification",), None)),
        id="bounded-metadata-grouped-entry-without-justification",
    ),
]


@pytest.mark.parametrize("mutate", ACCEPTED_CASES)
def test_valid_shapes_are_accepted(mutate):
    """Sections 3.1, 3.2 and 3.5: RECEIPT_KEY with operationIdField, policy NONE and maxAttempts 1 (entry or
    class), an operations split counted once per class, and a BOUNDED_METADATA grouped entry with a null
    justification are all accepted once the counts follow section 3.5."""
    assert _accepted_after(mutate) == []


SE5_ACCEPTED_CASES = [
    pytest.param(
        _both(
            _setter(AI_INF, ("timeout", "attemptSeconds"), 9),
            _setter(AI_INF, ("retry", "backoff", "maxSeconds"), 1),
        ),
        id="sum-within-ceiling",
    ),
    pytest.param(_setter(EXP_AI, ("timeout", "ceilingSeconds"), 60), id="callee-ceiling-below-callers"),
]


@pytest.mark.parametrize("mutate", SE5_ACCEPTED_CASES)
def test_se5_accepts_deadlines_within_their_bounds(mutate):
    """Section 3.3 (SE-5): three attempts of 9 s with a 1 s backoff fit the 30 s ceiling, and a caller's
    60 s ceiling above its callee's 30 s holds the request-path rule; SE-5 refuses neither."""
    assert "SE-5" not in _refusals_after(mutate)


# ---------------------------------------------------------------------------------------------------------
# 4. The head layer (section 6): V1, E1, E2, E3, V4, V6.
# ---------------------------------------------------------------------------------------------------------


def _bytes(path) -> bytes:
    return (ROOT / path).read_bytes()


def _raises_met006(function, *arguments) -> str:
    with pytest.raises(ValueError) as caught:
        function(*arguments)
    message = str(caught.value)
    assert "MET-006" in message
    return message


def _key_for(mapping, path: str):
    matches = [key for key in mapping if str(key) == path]
    assert len(matches) == 1, path
    return matches[0]


def _authority():
    return copy.deepcopy(_head().authority())


def _digest(value: str) -> str:
    return value[len("sha256:"):] if value.startswith("sha256:") else value


def _packet_files():
    return {path: _bytes(path) for path in _head().PACKET_FILES}


def _base_files():
    return {path: _bytes(path) for path in _head().BASE_FILES}


def _befores():
    head = _head()
    return {path: head._undo_this_layer(path, _bytes(path)) for path in head.ERRATA_LINES}


def _hunk_classes():
    return json.loads(_bytes(HUNK_RECORD))["classes"]


def _dump_like(value, raw: bytes) -> bytes:
    """Serialise ``value`` in the JSON layout that reproduces ``raw`` byte for byte, when one of the common
    layouts does; otherwise two-space indentation."""
    original = json.loads(raw)
    for indent in (2, 4, 1, None):
        for sort_keys in (False, True):
            for ensure_ascii in (False, True):
                for tail in ("\n", ""):
                    options = {"indent": indent, "sort_keys": sort_keys, "ensure_ascii": ensure_ascii}
                    if (json.dumps(original, **options) + tail).encode("utf-8") == raw:
                        return (json.dumps(value, **options) + tail).encode("utf-8")
    return (json.dumps(value, indent=2) + "\n").encode("utf-8")


def test_v1_pins_exactly_the_four_packet_files():
    """Section 6 V1: PACKET_FILES names the record, its schema, the checker and tests/test_service_edges.py,
    exactly."""
    files = [str(path) for path in _head().PACKET_FILES]
    assert len(files) == 4
    assert sorted(files) == sorted(PACKET_FOUR)


def test_v1_passes_on_the_live_bytes():
    """Section 6 V1: the packet's four files pass by digest on the live bytes."""
    assert _head().check_packet_files(_packet_files()) is None


V1_FILE_CASES = [
    pytest.param("architecture/service-edges.yaml", id="record"),
    pytest.param("architecture/service-edges/schema.json", id="schema"),
    pytest.param("scripts/validate_service_edges.py", id="checker"),
    pytest.param("tests/test_service_edges.py", id="checker-tests"),
]


@pytest.mark.parametrize("path", V1_FILE_CASES)
def test_v1_refuses_a_changed_packet_file(path):
    """Section 6 V1: a packet file whose bytes differ from its pinned digest is refused."""
    files = _packet_files()
    files[_key_for(files, path)] += b"\n"
    _raises_met006(_head().check_packet_files, files)


def test_v1_refuses_a_missing_or_an_extra_file():
    """Section 6 V1: exactly the four files; a missing one or a fifth one is refused."""
    missing = _packet_files()
    missing.pop(_key_for(missing, PACKET_FOUR[0]))
    _raises_met006(_head().check_packet_files, missing)
    extra = _packet_files()
    extra["architecture/services.yaml"] = _bytes("architecture/services.yaml")
    _raises_met006(_head().check_packet_files, extra)


def test_e1_passes_on_the_checker_list():
    """Section 6 E1: the record passes the checker on the live bytes (an empty refusal list)."""
    assert _head().check_edges(list(_checker().check())) is None


def test_e1_refuses_a_non_empty_refusal_list():
    """Section 6 E1: any refusal, a counts difference included, is refused."""
    _raises_met006(_head().check_edges, [("SE-14", "the header's counts differ from the checker's")])
    record, catalog, graph, schema = _copies()
    _bump(("counts", "edges"), -1)(record, catalog)
    refusals = list(_checker().check_record(record, catalog, graph, schema))
    assert refusals
    _raises_met006(_head().check_edges, refusals)


def test_e2_names_the_four_base_files():
    """Section 6 E2 (Option B): BASE_FILES names the catalog, the graph and both catalog schemas."""
    files = [str(path) for path in _head().BASE_FILES]
    assert len(files) == 4
    assert sorted(files) == sorted(BASE_FOUR)


def test_e2_passes_on_the_live_bytes():
    """Section 6 E2: the base files equal their base bytes, and the authority names none of them."""
    authority = _authority()
    assert _head().check_base_files(_base_files(), authority["changedFiles"], authority["newFiles"]) is None


E2_FILE_CASES = [
    pytest.param("architecture/services.yaml", id="catalog"),
    pytest.param("architecture/dependency-graph.yaml", id="graph"),
    pytest.param("schemas/services.schema.json", id="catalog-schema"),
    pytest.param("schemas/dependency-graph.schema.json", id="graph-schema"),
]


@pytest.mark.parametrize("path", E2_FILE_CASES)
def test_e2_refuses_a_changed_base_file(path):
    """Section 6 E2: a base file whose bytes differ from its base digest is refused (no in-place edit)."""
    authority = _authority()
    files = _base_files()
    files[_key_for(files, path)] += b"\n"
    _raises_met006(_head().check_base_files, files, authority["changedFiles"], authority["newFiles"])


def test_e2_refuses_an_authority_naming_a_base_file():
    """Section 6 E2: the authority's changedFiles or newFiles naming a base file is refused."""
    authority = _authority()
    changed = copy.deepcopy(authority["changedFiles"])
    changed["architecture/services.yaml"] = copy.deepcopy(next(iter(authority["changedFiles"].values())))
    _raises_met006(_head().check_base_files, _base_files(), changed, authority["newFiles"])
    new = copy.deepcopy(authority["newFiles"])
    new["architecture/dependency-graph.yaml"] = hashlib.sha256(_bytes("architecture/dependency-graph.yaml")).hexdigest()
    _raises_met006(_head().check_base_files, _base_files(), authority["changedFiles"], new)


def test_e3_errata_lines_name_the_four_authored_edits():
    """Sections 6 E3, 7 and 17: ERRATA_LINES names the README paragraph (184-189), item 160 (1618), line 3331
    and NAMING_RECORDS (837-912), by their base lines."""
    lines = {str(path): tuple(span) for path, span in _head().ERRATA_LINES.items()}
    assert lines == EXPECTED_ERRATA


def test_e3_class_other_falls_only_on_the_authored_edits():
    """Sections 6 E3, 7 and 17: in 287's hunk-class record, class other appears only on the four authored-edit
    files, at least one on each (the contract fixes their named lines, not a hunk count; MON-287-C3-CLASS)."""
    holders = {path: hunks.count("other") for path, hunks in _hunk_classes().items() if "other" in hunks}
    assert set(holders) == set(EXPECTED_ERRATA)
    assert all(count >= 1 for count in holders.values())


def test_e3_undo_gives_the_authority_digests():
    """Section 6 E3 inputs: each errata file's current bytes hash to afterSha256 and _undo_this_layer's
    before bytes hash to beforeSha256."""
    changed = _authority()["changedFiles"]
    for path, before in _befores().items():
        entry = changed[str(path)]
        assert hashlib.sha256(before).hexdigest() == _digest(entry["beforeSha256"]), path
        assert hashlib.sha256(_bytes(path)).hexdigest() == _digest(entry["afterSha256"]), path


def test_errata_named_lines_hold_the_authored_text():
    """Sections 7 and 17: the README's base line 184 opens the paragraph "The rewrite.", the sector test's
    base line 837 opens NAMING_RECORDS, and the sector test gains the record and its schema."""
    befores = {str(path): before for path, before in _befores().items()}
    assert b"The rewrite." in befores[README].split(b"\n")[183]
    assert b"NAMING_RECORDS" in befores[SECTOR_TEST].split(b"\n")[836]
    after = _bytes(SECTOR_TEST)
    for name in (b"architecture/service-edges.yaml", b"architecture/service-edges/schema.json"):
        assert name not in befores[SECTOR_TEST]
        assert name in after


def test_e3_passes_on_the_live_inputs():
    """Section 6 E3: class-other hunks fall only on the four files, at their named lines."""
    assert _head().check_errata(_hunk_classes(), _authority()["changedFiles"], _befores()) is None


def _e3_other_outside(classes, befores, errata):
    path = next(p for p in sorted(classes) if p not in errata and classes[p])
    classes[path] = ["other"] + list(classes[path][1:])


def _e3_other_missing(classes, befores, errata):
    alternative = next(c for p in sorted(classes) for c in classes[p] if c != "other")
    classes[README] = [alternative if c == "other" else c for c in classes[README]]


def _e3_other_moved(classes, befores, errata):
    # MON-287-C3-CLASS: swap an other hunk with a non-other hunk of the same authored file, so the other class
    # lands on a hunk outside the named lines (swapping two other hunks would change nothing).
    path = next(p for p in sorted(errata)
                if "other" in classes.get(p, []) and any(c != "other" for c in classes.get(p, [])))
    hunks = list(classes[path])
    first = hunks.index("other")
    second = next(i for i, c in enumerate(hunks) if c != "other")
    hunks[first], hunks[second] = hunks[second], hunks[first]
    classes[path] = hunks


def _e3_before_shifted(classes, befores, errata):
    key = _key_for(befores, README)
    befores[key] = b"\n" * 50 + befores[key]


E3_CASES = [
    pytest.param(_e3_other_outside, id="other-on-a-file-outside-the-four"),
    pytest.param(_e3_other_missing, id="an-authored-file-without-its-other-hunk"),
    pytest.param(_e3_other_moved, id="other-hunk-outside-its-named-lines"),
    pytest.param(_e3_before_shifted, id="named-lines-no-longer-hold-the-hunk"),
]


@pytest.mark.parametrize("mutate", E3_CASES)
def test_e3_refuses_a_misplaced_authored_hunk(mutate):
    """Section 6 E3 (sections 7 and 17): class other on another file, an authored file without its one other
    hunk, or an other hunk outside its named base lines is refused."""
    classes = copy.deepcopy(_hunk_classes())
    befores = _befores()
    original = (copy.deepcopy(classes), dict(befores))
    mutate(classes, befores, set(EXPECTED_ERRATA))
    assert (classes, befores) != original
    _raises_met006(_head().check_errata, classes, _authority()["changedFiles"], befores)


def _rider_sites(node):
    sites = []
    if isinstance(node, dict):
        for key, value in node.items():
            if key == RIDER:
                sites.append((node, key))
            sites.extend(_rider_sites(value))
    elif isinstance(node, list):
        for index, item in enumerate(node):
            if item == RIDER or (isinstance(item, dict) and RIDER in item.values()):
                sites.append((node, index))
            sites.extend(_rider_sites(item))
    return sites


def _registry_inputs():
    head = _head()
    return _bytes(REGISTRY), {head.PACKET_BRIEF: (ROOT / head.PACKET_BRIEF).read_bytes()}


def test_v4_rider_is_appended_last():
    """Sections 6 V4 and 8: the rider MET-006/packet stands in architecture/review-record/briefs.json, last in
    its container."""
    sites = _rider_sites(json.loads(_bytes(REGISTRY)))
    assert sites
    for container, place in sites:
        if isinstance(container, dict):
            assert list(container)[-1] == place
        else:
            assert place == len(container) - 1


def test_v4_passes_on_the_live_inputs():
    """Section 6 V4: the registry differs from the base by this packet's one rider, pinning the packet
    brief."""
    raw, briefs = _registry_inputs()
    assert _head().check_registry(raw, briefs) is None


def _v4_renamed(raw, briefs):
    quoted = json.dumps(RIDER).encode("utf-8")
    assert raw.count(quoted) >= 1
    return raw.replace(quoted, json.dumps("MET-006/packed").encode("utf-8")), briefs


def _v4_removed(raw, briefs):
    data = json.loads(raw)
    for container, place in reversed(_rider_sites(data)):
        if isinstance(container, dict):
            del container[place]
        else:
            container.pop(place)
    return _dump_like(data, raw), briefs


def _v4_moved_first(raw, briefs):
    data = json.loads(raw)
    container, place = _rider_sites(data)[0]
    if isinstance(container, dict):
        value = container.pop(place)
        rest = list(container.items())
        container.clear()
        container[place] = value
        container.update(rest)
    else:
        container.insert(0, container.pop(place))
    return _dump_like(data, raw), briefs


def _v4_brief_changed(raw, briefs):
    return raw, {key: value + b"\n" for key, value in briefs.items()}


V4_CASES = [
    pytest.param(_v4_renamed, id="rider-renamed"),
    pytest.param(_v4_removed, id="rider-removed"),
    pytest.param(_v4_moved_first, id="rider-not-last"),
    pytest.param(_v4_brief_changed, id="packet-brief-not-the-pinned-one"),
]


@pytest.mark.parametrize("mutate", V4_CASES)
def test_v4_refuses_a_changed_rider(mutate):
    """Section 6 V4: a registry without exactly one rider, last, pinning the packet brief is refused, and the
    message names the MET-006 packet rider."""
    raw, briefs = _registry_inputs()
    changed_raw, changed_briefs = mutate(raw, briefs)
    assert (changed_raw, changed_briefs) != (raw, briefs)
    message = _raises_met006(_head().check_registry, changed_raw, changed_briefs)
    assert "the MET-006 packet rider" in message


@functools.lru_cache(maxsize=None)
def _classify():
    head = _head()
    return head._era_rule(head.READER_PATH, head.READER_NAME).classify


def _hunk_inputs():
    head = _head()
    raw = _bytes(HUNK_RECORD)
    record = json.loads(raw)
    changed = _authority()["changedFiles"]
    afters = {path: _bytes(path) for path in changed}
    context = head._v24_context(head.authority(), record["hunkClassContext"])
    return raw, record, changed, afters, context


def test_v6_record_members_from_section_6():
    """Section 6 V6: outcomeStatements [], and one class per reverse hunk of every changed file (countPairs is the
    head's hunk context, not a record member; MON-287-C3-CLASS)."""
    record = json.loads(_bytes(HUNK_RECORD))
    changed = _authority()["changedFiles"]
    assert record["outcomeStatements"] == []
    assert set(record["classes"]) == set(changed)
    for path, entry in changed.items():
        assert len(record["classes"][path]) == len(entry["reverseHunks"]), path


def test_v6_passes_on_the_live_inputs():
    """Section 6 V6: 287's own hunk-class record under v2.4 passes with its rule digest and context."""
    raw, _, changed, afters, context = _hunk_inputs()
    assert _head().check_hunk_record(raw, changed, afters, _classify(), context, _head().HUNK_RULE_SHA256) is None


def _first_classed_path(classes):
    return next(path for path in sorted(classes) if classes[path])


def _v6_extra_member(record):
    record["unlistedMember"] = True


def _v6_count_pairs(record):
    record["countPairs"] = [[313, 315]]


def _v6_outcome_statement(record):
    record["outcomeStatements"] = ["a demoted layer's outcome changes"]


def _v6_unknown_class(record):
    path = _first_classed_path(record["classes"])
    record["classes"][path] = ["unlisted-class"] + list(record["classes"][path][1:])


def _v6_missing_path(record):
    del record["classes"][_first_classed_path(record["classes"])]


def _v6_extra_class(record):
    path = _first_classed_path(record["classes"])
    record["classes"][path] = list(record["classes"][path]) + [record["classes"][path][0]]


def _v6_context(record):
    value = record["hunkClassContext"]
    if isinstance(value, dict):
        record["hunkClassContext"] = dict(value, unlistedMember=True)
    elif isinstance(value, list):
        record["hunkClassContext"] = list(value) + ["unlisted"]
    else:
        record["hunkClassContext"] = f"{value}-unlisted"


V6_CASES = [
    pytest.param(_v6_extra_member, id="extra-member"),
    pytest.param(_v6_count_pairs, id="count-pairs"),
    pytest.param(_v6_outcome_statement, id="outcome-statements-not-empty"),
    pytest.param(_v6_unknown_class, id="class-outside-the-vocabulary"),
    pytest.param(_v6_missing_path, id="a-changed-file-unclassed"),
    pytest.param(_v6_extra_class, id="more-classes-than-hunks"),
    pytest.param(_v6_context, id="context"),
]


@pytest.mark.parametrize("mutate", V6_CASES)
def test_v6_refuses_a_changed_hunk_record(mutate):
    """Section 6 V6: the hunk-class record's closed members, vocabulary, context, countPairs and empty
    outcomeStatements; any change is refused."""
    raw, record, changed, afters, context = _hunk_inputs()
    mutate(record)
    changed_raw = _dump_like(record, raw)
    assert changed_raw != raw
    _raises_met006(_head().check_hunk_record, changed_raw, changed, afters, _classify(), context, _head().HUNK_RULE_SHA256)


def test_v6_refuses_another_rule_digest():
    """Section 6 V6: the record is held to HUNK_RULE_SHA256; another rule digest is refused."""
    raw, _, changed, afters, context = _hunk_inputs()
    assert _head().HUNK_RULE_SHA256 != "0" * 64
    _raises_met006(_head().check_hunk_record, raw, changed, afters, _classify(), context, "0" * 64)
