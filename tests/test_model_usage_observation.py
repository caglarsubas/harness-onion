"""Source-free vectors mutate distilled facts; none are original-source tests."""
from __future__ import annotations

import copy
import hashlib
import json
import os

import pytest
import yaml

from scripts import validate_model_usage_observation as validator


@pytest.fixture(scope="module")
def observed():
    raw = validator.read_report(validator.REPORT_PATH)
    packet = validator.PACKET_PATH.read_bytes()
    index = yaml.safe_load(validator.INDEX_PATH.read_text())
    return json.loads(raw), raw, packet, index


@pytest.fixture
def candidate(observed):
    return copy.deepcopy(observed[0])


def errors(report, observed):
    return validator.validate_report(validator.report_bytes(report), observed[2], observed[3])


def fact(report, kind):
    return next(item for item in report["facts"] if item["kind"] == kind)


def test_real_distilled_report_is_byte_pinned_and_index_bound(observed):
    report, raw, packet, index = observed
    assert hashlib.sha256(raw).hexdigest() == validator.EXPECTED_REPORT_SHA256
    assert validator.report_bytes(report) == raw
    assert validator.validate_report(raw, packet, index) == []


@pytest.mark.parametrize("raw", [b"", b"{", b"{}{}", b"\xff", b"\xef\xbb\xbf{}",
    b'{"x":1,"x":2}', b'{"nested":{"x":1,"x":2}}', b'{"n":NaN}',
    b'{"n":Infinity}', b'{"n":-Infinity}', b" " * (validator.MAX_REPORT_BYTES + 1),
    "not bytes"], ids=["empty", "invalid", "trailing", "encoding", "bom", "duplicate",
                       "nested-duplicate", "nan", "infinity", "negative-infinity", "oversize", "not-bytes"])
def test_strict_json_and_resource_limits(raw, observed):
    assert validator.validate_report(raw, observed[2], observed[3]) == ["report is not bounded strict UTF-8 JSON"]


def test_deep_json_is_rejected_by_parser_or_explicit_depth_guard(observed):
    # pytest/plugin recursion limits can change which of these two guards fires.
    raw = b"[" * 2000 + b"0" + b"]" * 2000
    result = validator.validate_report(raw, observed[2], observed[3])
    assert "report is not bounded strict UTF-8 JSON" in result or "report nesting exceeds the closed grammar" in result


@pytest.mark.parametrize("value", [None, [], True, 0, "report"])
def test_non_object_report_is_rejected(value, observed):
    assert "report must be an object" in errors(value, observed)


def test_packet_whitespace_change_is_not_reauthorized(observed):
    assert validator.validate_report(observed[1], observed[2] + b"\n", observed[3]) == [
        "packet digest differs from merged authority"]


def test_matching_report_and_packet_mutation_does_not_mint_authority(candidate, observed):
    packet = observed[2].replace(b"sourceCodeExecution\":\"DENIED", b"sourceCodeExecution\":\"ALLOWED")
    assert packet != observed[2]
    candidate["authority"]["packetDigest"] = hashlib.sha256(packet).hexdigest()
    candidate["authority"]["packetObservation"]["sourceCodeExecution"] = "ALLOWED"
    assert validator.validate_report(validator.report_bytes(candidate), packet, observed[3]) == [
        "packet digest differs from merged authority"]


@pytest.mark.parametrize("field", ["authorityId", "commit", "extractorSha256", "launcherSha256",
    "observerIdentity", "packetDigest", "packetId", "repository", "schemaVersion", "unknown"])
def test_authority_binding_cannot_be_substituted(field, candidate, observed):
    candidate["authority"][field] = "substituted"
    assert "observer authority differs from approved binding" in errors(candidate, observed)


@pytest.mark.parametrize("field,value", [
    ("sourcePaths", ["tests/test_scheduler.py"]), ("sourcePaths", [validator.SOURCE_PATH, "extra.json"]),
    ("sourceCodeExecution", "ALLOWED"), ("copyAuthority", "COPY_AUTHORIZED"),
    ("ciEvidenceUse", "ALLOWED"), ("implementationIdentityAccess", "ALLOWED"),
    ("networkIsolation", "UNRESTRICTED"), ("outputPath", "raw-source.json"),
    ("allowedFactKinds", ["SOURCE_TEXT"]), ("commit", "0" * 40),
])
def test_observer_scope_cannot_expand(field, value, candidate, observed):
    candidate["authority"]["packetObservation"][field] = value
    assert "observer authority differs from approved binding" in errors(candidate, observed)


@pytest.mark.parametrize("field,value", [
    ("copyAuthority", "COPY_AUTHORIZED"), ("errno", 13), ("errno", True),
    ("outboundDenied", False), ("outboundDenied", 1), ("networkBackend", "UNPROVEN"),
    ("sourceCodeExecution", "ALLOWED"), ("sourceWriteAccess", "ALLOWED"), ("extra", True),
])
def test_isolation_evidence_is_exact_and_type_strict(field, value, candidate, observed):
    candidate["isolationEvidence"][field] = value
    assert "isolation evidence differs from observed boundary" in errors(candidate, observed)


@pytest.mark.parametrize("key", sorted(validator.PROHIBITED_KEYS))
def test_prose_host_metadata_and_behavioral_claims_are_rejected(key, candidate, observed):
    candidate["facts"][0][key] = "PASS or leaked prose"
    assert "report contains prohibited source text or evidence claims" in errors(candidate, observed)


@pytest.mark.parametrize("path", ["/private/tmp/snapshot", "/Users/example/source", "/home/source",
    "/opt/source", "/tmp/source", "/etc/authority", "/var/source", "file:///source",
    "C:\\source", "snapshot/.git/config", "codex-harness-warmstarts.hidden",
    "/opt/planeon/bin/harness-reference-observe"])
def test_filesystem_leaks_are_rejected(path, candidate, observed):
    candidate["facts"][0]["field"] = path
    assert "report leaks a host or source filesystem path" in errors(candidate, observed)


@pytest.mark.parametrize("field,value", [("path", "extra.json"), ("gitObject", "0" * 40),
    ("sha256", "0" * 64), ("unknown", True)])
def test_source_bindings_cannot_be_replaced(field, value, candidate, observed):
    candidate["sources"][0][field] = value
    assert "source path, Git object or schema digest mismatch" in errors(candidate, observed)


def test_matching_source_and_digest_fact_substitution_still_fails(candidate, observed):
    candidate["sources"][0]["sha256"] = "0" * 64
    fact(candidate, "SCHEMA_DIGEST")["sha256"] = "0" * 64
    result = errors(candidate, observed)
    assert "source path, Git object or schema digest mismatch" in result
    assert "schema-digest fact differs from exact source binding" in result


@pytest.mark.parametrize("value", [None, {}, [], [None], "source"])
def test_malformed_sources_are_rejected(value, candidate, observed):
    candidate["sources"] = value
    assert "source path, Git object or schema digest mismatch" in errors(candidate, observed)


@pytest.mark.parametrize("value", [None, {}, "facts", [None], [[]], [True]])
def test_malformed_fact_collections_do_not_crash(value, candidate, observed):
    candidate["facts"] = value
    assert errors(candidate, observed)


@pytest.mark.parametrize("value", ["SOURCE_TEXT", {}, [], None, 1])
def test_unknown_or_unhashable_fact_kind_fails_closed(value, candidate, observed):
    candidate["facts"][0]["kind"] = value
    assert "undeclared fact kind" in errors(candidate, observed)


def test_fact_removal_and_same_kind_duplication_are_rejected(candidate, observed):
    candidate["facts"][0] = copy.deepcopy(candidate["facts"][1])
    candidate["facts"].sort(key=validator.canonical)
    assert "duplicate structural fact" in errors(candidate, observed)
    candidate["facts"].pop()
    assert "observed fact count mismatch" in errors(candidate, observed)


def test_reordering_and_noncanonical_bytes_are_rejected(candidate, observed):
    candidate["facts"].reverse()
    assert "facts are not canonically ordered" in errors(candidate, observed)
    assert "report serialization is not canonical" in validator.validate_report(
        json.dumps(observed[0]).encode(), observed[2], observed[3])


@pytest.mark.parametrize("kind", sorted(validator.FIELDS))
def test_every_fact_kind_rejects_extra_or_missing_members(kind, candidate, observed):
    item = fact(candidate, kind)
    item["unknown"] = "extra"
    assert "fact members are not closed or complete" in errors(candidate, observed)
    del item["unknown"]
    del item["sourcePath"]
    assert "fact members are not closed or complete" in errors(candidate, observed)


@pytest.mark.parametrize("pointer", [None, [], "relative", "/properties/bad~2escape", "/" + "x" * 1025])
def test_pointer_grammar_is_closed(pointer, candidate, observed):
    candidate["facts"][0]["jsonPointer"] = pointer
    assert "invalid structural JSON pointer" in errors(candidate, observed)


def test_property_pointer_must_match_field(candidate, observed):
    fact(candidate, "OBJECT_FIELD")["field"] = "different_field"
    assert "object field pointer and name differ" in errors(candidate, observed)


@pytest.mark.parametrize("value", [["string", "string"], ["unsupported"], [{}], True, {}])
def test_object_field_type_is_strict(value, candidate, observed):
    fact(candidate, "OBJECT_FIELD")["type"] = value
    assert "invalid object-field type" in errors(candidate, observed)


@pytest.mark.parametrize("reference", ["https://example.test/schema", "relative.json", "#/bad~2escape", None, []])
def test_references_are_only_local_data(reference, candidate, observed):
    fact(candidate, "REFERENCE_EDGE")["reference"] = reference
    assert "reference is not a local structural pointer" in errors(candidate, observed)


@pytest.mark.parametrize("keyword,value", [("unknown", 1), ("type", ["bad"]),
    ("additionalProperties", {"description": "prose"}), ("minimum", True),
    ("maximum", 10**400), ("minLength", -1), ("maxLength", 1.5),
    ("pattern", []), ("const", {}), ("format", None)])
def test_constraint_grammar_never_carries_nested_source_text(keyword, value, candidate, observed):
    fact(candidate, "VALUE_CONSTRAINT").update(keyword=keyword, value=value)
    assert "constraint is outside the closed fact grammar" in errors(candidate, observed)


def test_floating_overflow_and_deep_nesting_are_rejected(candidate, observed):
    raw = observed[1].replace(b'"errno": 1', b'"errno": 1e999')
    assert raw != observed[1]
    assert validator.validate_report(raw, observed[2], observed[3])
    nested = []
    for _ in range(validator.MAX_DEPTH + 2):
        nested = [nested]
    candidate["extra"] = nested
    assert "report nesting exceeds the closed grammar" in errors(candidate, observed)


def test_state_identity_and_cross_fact_edges_are_bound(candidate, observed):
    fact(candidate, "STATE_ENUM")["value"].append("success")
    fact(candidate, "SCHEMA_IDENTITY")["schemaId"] = "https://example.test/replaced"
    fact(candidate, "REQUIRED_FIELD")["field"] = "undeclared_field"
    fact(candidate, "OBJECT_FIELD")["$ref"] = "#/$defs/other"
    result = errors(candidate, observed)
    assert "observed state enum mismatch" in result
    assert "schema identity differs from observed identity" in result
    assert "required field lacks a corresponding observed property" in result
    assert "object reference lacks its observed edge" in result


@pytest.mark.parametrize("mutation", ["missing_repository", "duplicate_repository", "missing_path", "duplicate_path",
    "gitObject", "kind", "recordType", "useModes", "reuseDisposition"])
def test_source_index_is_unique_exact_and_reference_only(mutation, observed):
    original = next(record for record in observed[3]["sources"] if record["repository"] == validator.REPOSITORY)
    entry = next(item for item in original["paths"] if item["path"] == validator.SOURCE_PATH)
    record = {"repository": validator.REPOSITORY, "commit": validator.SOURCE_COMMIT, "paths": [copy.deepcopy(entry)]}
    index = {"sources": [record]}
    if mutation == "missing_repository":
        index["sources"] = []
    elif mutation == "duplicate_repository":
        index["sources"].append(copy.deepcopy(record))
    elif mutation == "missing_path":
        record["paths"] = []
    elif mutation == "duplicate_path":
        record["paths"].append(copy.deepcopy(entry))
    else:
        record["paths"][0][mutation] = "COPY_AUTHORIZED"
    result = validator.validate_report(observed[1], observed[2], index)
    assert any("source index" in error for error in result)


@pytest.mark.parametrize("index", [None, [], {}, {"sources": None}, {"sources": [None, []]}])
def test_malformed_index_fails_without_exception(index, observed):
    assert validator.validate_report(observed[1], observed[2], index)


def test_cli_reports_evidence_boundaries_without_source_access(capsys):
    assert validator.main() == 0
    output = capsys.readouterr().out
    for text in ["sources=1 facts=162", "originalSourceTests=NOT_RUN_ENV_UNAVAILABLE",
                 "originalSourceBehavioralParity=NOT_ESTABLISHED", "sourceExecution=DENIED",
                 "copyAuthority=NONE", "liveEvidence=NOT_RUN_ENV_UNAVAILABLE"]:
        assert text in output


def test_cli_missing_report_fails_closed_and_sanitizes_errors(tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(validator, "REPORT_PATH", tmp_path / "private-sensitive-name.json")
    assert validator.main() == 1
    output = capsys.readouterr().out
    assert "FAILED" in output and "private-sensitive-name" not in output


def test_cli_rejects_substituted_report(tmp_path, monkeypatch, capsys):
    path = tmp_path / "report.json"
    path.write_text("{}")
    monkeypatch.setattr(validator, "REPORT_PATH", path)
    assert validator.main() == 1
    assert "report digest differs" in capsys.readouterr().out


def test_report_reader_rejects_links_and_oversize_inputs(tmp_path):
    target = tmp_path / "target.json"
    target.write_text("{}")
    link = tmp_path / "link.json"
    link.symlink_to(target)
    with pytest.raises((OSError, ValueError)):
        validator.read_report(link)
    target.write_bytes(b" " * (validator.MAX_REPORT_BYTES + 1))
    with pytest.raises(ValueError):
        validator.read_report(target)


def test_report_reader_rejects_directories_and_fifo_without_blocking(tmp_path):
    with pytest.raises((OSError, ValueError)):
        validator.read_report(tmp_path)
    fifo = tmp_path / "report.fifo"
    os.mkfifo(fifo)
    with pytest.raises(ValueError):
        validator.read_report(fifo)
