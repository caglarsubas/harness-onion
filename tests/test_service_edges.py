"""MET-006 (SERVICE-EDGES-001): the service-edge record beside the catalog.

The live record passes the checker (scripts/validate_service_edges.py, SE-1 to SE-14) and validates against its schema
(architecture/service-edges/schema.json, JSON Schema draft 2020-12, with the repository's pinned jsonschema); then one
in-memory failing case per rule, and the idempotency rule's items (CONTRACT_287 rev 6 section 3.2). Every case mutates a
copy of the live record; no file is written."""
import contextlib
import copy
import importlib.util
import io
from pathlib import Path

import jsonschema
import pytest

ROOT = Path(__file__).resolve().parents[1]


def _load(rel, name):
    spec = importlib.util.spec_from_file_location(name, ROOT / rel)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


SE = _load("scripts/validate_service_edges.py", "validate_service_edges_under_test")
RECORD, CATALOG, GRAPH, SCHEMA = SE.load(ROOT)


def entry(record, consumer, dependency):
    return next(e for e in record["edges"] if (e["consumer"], e["dependency"]) == (consumer, dependency))


def refusals(record):
    return {rule for rule, _ in SE.check_record(record, CATALOG, GRAPH, SCHEMA, root=ROOT)}


def test_live_record_passes():
    assert SE.check(ROOT) == []
    reads = []
    assert SE.check(ROOT, read=lambda path: reads.append(path) or (ROOT / path).read_bytes()) == []
    assert {"architecture/service-edges.yaml", "architecture/services.yaml"} <= set(reads)
    assert len(RECORD["edges"]) == 129 and RECORD["counts"]["edges"] == 129


def test_schema_is_draft_2020_12_and_the_live_record_validates():
    jsonschema.Draft202012Validator.check_schema(SCHEMA)
    assert SCHEMA["$schema"] == "https://json-schema.org/draft/2020-12/schema"
    assert list(jsonschema.Draft202012Validator(SCHEMA).iter_errors(RECORD)) == []
    assert set(SCHEMA["required"]) == set(SE.HEADER) == set(SCHEMA["properties"])


def test_the_record_never_repeats_mode_required_or_failure_mode():
    for e in RECORD["edges"]:
        assert not {"mode", "required", "failureMode"} & set(e)


def _first_none(record):
    return next(e for e in record["edges"] if e["retry"].get("idempotency") == "NONE")


def _first_native(record):
    return next(e for e in record["edges"] if e["retry"].get("idempotency") == "NATIVE")


def _first_fail_open(record):
    return next(e for e in record["edges"] if e["degradation"] is not None)


def _first_service_dns(record):
    return next(f for e in record["edges"] for f in e["transport"] if f["endpoint"]["kind"] == "SERVICE_DNS")


def _set(path_fn, member, value):
    def mutate(record):
        path_fn(record)[member] = value
    return mutate


def _gw(record):
    return entry(record, "ai-gateway", "inference-api")


def _sum_over_ceiling(record):
    e = _gw(record)
    e["timeout"]["attemptSeconds"] = 15
    e["retry"]["backoff"]["maxSeconds"] = 1


def _mesh(record):
    e = _first_fail_open(record)
    e["degradation"] = e["degradation"] + " Retries go through the service mesh."


CASES = [
    ("SE-1", lambda r: r["edges"].pop(0)),
    ("SE-2", _set(lambda r: r["edges"][0], "extra", 1)),
    ("SE-3", _set(lambda r: _first_service_dns(r)["tls"], "minVersion", "1.2")),
    ("SE-4", _set(lambda r: _first_none(r)["retry"], "maxAttempts", 3)),
    ("SE-5", _sum_over_ceiling),
    ("SE-6", _set(lambda r: _gw(r)["timeout"]["basis"], "lineSha256", "0" * 64)),
    ("SE-7", _set(lambda r: entry(r, "experience-gateway", "governance-service"), "lifecyclePhase", "STARTUP")),
    ("SE-8", _set(lambda r: _gw(r)["objectives"], "deadlinePropagation", "UNSPECIFIED")),
    ("SE-9", _set(_first_fail_open, "degradation", None)),
    ("SE-10", _set(lambda r: r["externalProviders"]["external.postgresql"], "value", "TENANT")),
    ("SE-11", lambda r: r["repeatedCalls"].pop(0)),
    ("SE-12", _mesh),
    ("SE-13", lambda r: r["graphMapping"].pop(0)),
    ("SE-14", _set(lambda r: r["counts"], "edges", 128)),
]


@pytest.mark.parametrize("rule,mutate", CASES, ids=[c[0] for c in CASES])
def test_each_rule_refuses_its_case(rule, mutate):
    record = copy.deepcopy(RECORD)
    mutate(record)
    assert rule in refusals(record)


def _receipt_without_field(record):
    r = _first_none(record)["retry"]
    r["idempotency"] = "RECEIPT_KEY"


def _idempotent_only_on_none(record):
    _first_none(record)["retry"]["policy"] = "IDEMPOTENT_ONLY"


def _duplicate_classes(record):
    ops = _gw(record)["retry"]["operations"]
    ops[1]["class"] = ops[0]["class"]


def _field_on_native(record):
    _first_native(record)["retry"]["operationIdField"] = "operationId"


def _entry_level_beside_operations(record):
    _gw(record)["retry"]["idempotency"] = "NATIVE"


def _retried_non_idempotent_class(record):
    _gw(record)["retry"]["operations"][1]["maxAttempts"] = 2


IDEMPOTENCY = [_receipt_without_field, _idempotent_only_on_none, _duplicate_classes, _field_on_native,
               _entry_level_beside_operations, _retried_non_idempotent_class]


@pytest.mark.parametrize("mutate", IDEMPOTENCY, ids=[m.__name__.strip("_") for m in IDEMPOTENCY])
def test_the_idempotency_rule(mutate):
    record = copy.deepcopy(RECORD)
    mutate(record)
    assert "SE-4" in refusals(record)


def test_a_controller_is_never_called():
    record = copy.deepcopy(RECORD)
    e = entry(record, "fleet-sync-agent", "operator")
    e["transport"] = [{"protocol": "HTTP", "endpoint": {"kind": "SERVICE_DNS", "service": "operator", "port": "https"},
                       "tls": {"required": True, "minVersion": "1.3"}}]
    assert "SE-2" in refusals(record)


def test_the_listed_gap_takes_the_controller_sides_protocol():
    record = copy.deepcopy(RECORD)
    entry(record, "control-web", "operator")["transport"][0]["protocol"] = "HTTP"
    assert "SE-2" in refusals(record)
    record = copy.deepcopy(RECORD)
    record["catalogGaps"] = []
    assert {"SE-3", "SE-13"} <= refusals(record)


def test_a_job_handed_an_artifact_is_digest_pinned():
    record = copy.deepcopy(RECORD)
    e = entry(record, "tool-broker", "sandbox-runner")
    assert e["transport"][0]["endpoint"]["kind"] == "ARTIFACT_PATH" and e["objectives"]["integrity"] == "REQUIRED"
    del e["transport"][0]["endpoint"]["digest"]
    assert "SE-2" in refusals(record)


def test_precedence_one_cites_the_externals_own_line():
    record = copy.deepcopy(RECORD)
    record["externalProviders"]["external.kubernetes-api"]["source"] = {
        "ref": "docs/MICROSERVICE_CATALOG.md#L74", "phrase": "operator-supplied Kubernetes"}
    assert "SE-10" in refusals(record)


def test_the_controller_handoffs_via_is_the_store_holding_the_object():
    record = copy.deepcopy(RECORD)
    h = next(h for h in record["handoffs"] if h["kind"] == "CONTROLLER" and h["from"] == "fleet-sync-agent")
    h["via"] = "bundle-verifier"
    assert "SE-13" in refusals(record)


def test_a_stray_justification_is_refused():
    record = copy.deepcopy(RECORD)
    e = next(e for e in record["edges"] if e["repeatedCallJustification"] is None)
    e["repeatedCallJustification"] = "not a repeated call"
    assert "SE-11" in refusals(record)


def test_main_reports_ok():
    out = io.StringIO()
    with contextlib.redirect_stdout(out):
        assert SE.main([str(ROOT)]) == 0
    assert out.getvalue().startswith("SERVICE EDGES OK: 129 entries")
