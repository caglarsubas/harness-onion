#!/usr/bin/env python3
"""Validate pinned distilled facts, without loading schemas or executing sources."""
from __future__ import annotations

from collections import Counter
import hashlib
import json
import math
import os
from pathlib import Path
import re
import stat
from typing import Any

import yaml


ROOT = Path(__file__).resolve().parents[1]
REPORT_PATH = ROOT / "architecture/observations/model-usage-v2.json"
PACKET_PATH = ROOT / "task-packets/MET-OBS-MODEL-001.yaml"
INDEX_PATH = ROOT / "architecture/reuse-path-index.yaml"
PACKET_ID = "MET-OBS-MODEL-001"
REPOSITORY = "git@github.com:caglarsubas/llm_inference_engine.git"
SOURCE_COMMIT = "6815c21cb10a4d7dc0b4804f6bb223afb4321e97"
SOURCE_PATH = "contracts/prometa-model-usage-v2.schema.json"
SOURCE_BLOB = "c3ac327e2989ffbbc2452209e2a32f76be911534"
SOURCE_SHA256 = "845f830df424f1626717e60a5dbd05e01187f84e2e96223527cceda521f3d55a"
EXPECTED_REPORT_SHA256 = "aa5488bad4528bd4119dfe9134f517403986b6fd45408f34c508929924e764f9"
EXPECTED_PACKET_SHA256 = "7493f8f788f982df4cd6b32f3647c82f41b8989feee54fea8740fff5e61f1a9b"
EXPECTED_LAUNCHER_SHA256 = "971b534767afd900f00b588cf626b79c029f784f5820608b3803dd27ae967cee"
EXPECTED_EXTRACTOR_SHA256 = "c3ee70583ed0ba85693dcc3da62c40d8039919c1213facdcca3b13e172bc6a04"
EXPECTED_COUNTS = {
    "OBJECT_FIELD": 46, "REQUIRED_FIELD": 43, "SCHEMA_DIGEST": 1,
    "VALUE_CONSTRAINT": 58, "SCHEMA_IDENTITY": 1, "REFERENCE_EDGE": 12,
    "STATE_ENUM": 1,
}
MAX_REPORT_BYTES = 1024 * 1024
MAX_DEPTH = 32
COMMON = {"kind", "sourcePath", "jsonPointer"}
FIELDS = {
    "SCHEMA_IDENTITY": COMMON | {"schemaDialect", "schemaId"},
    "SCHEMA_DIGEST": COMMON | {"gitObject", "sha256"},
    "OBJECT_FIELD": COMMON | {"field", "type", "$ref", "format"},
    "REQUIRED_FIELD": COMMON | {"field"},
    "REFERENCE_EDGE": COMMON | {"reference"},
    "VALUE_CONSTRAINT": COMMON | {"keyword", "value"},
    "STATE_ENUM": COMMON | {"keyword", "value"},
}
PROHIBITED_KEYS = {
    "$comment", "description", "example", "examples", "raw", "sourceRoot",
    "sourceText", "title", "observerUid", "observerGid", "issuedAt",
    "originalSourceTests", "originalSourceBehavioralParity", "tenantAcceptance",
}
JSON_TYPES = {"null", "boolean", "object", "array", "number", "integer", "string"}
NAME = re.compile(r"[A-Za-z_$][A-Za-z0-9_$.-]{0,255}\Z")
KEYWORDS = {"additionalProperties", "type", "maxLength", "minLength", "pattern",
            "minimum", "maximum", "const", "format"}
EXPECTED_ISOLATION = {
    "copyAuthority": "NONE", "errno": 1, "networkBackend": "darwin-sandbox",
    "outboundDenied": True, "sourceCodeExecution": "DENIED", "sourceWriteAccess": "DENIED",
}


def canonical(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False)


def report_bytes(value: Any) -> bytes:
    return (json.dumps(value, indent=2, sort_keys=True, ensure_ascii=False, allow_nan=False) + "\n").encode("utf-8")


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON member")
        result[key] = value
    return result


def _reject_constant(_: str) -> None:
    raise ValueError("non-finite JSON number")


def decode_report(raw: bytes) -> Any:
    if not isinstance(raw, bytes) or not raw or len(raw) > MAX_REPORT_BYTES:
        raise ValueError("report size or byte type is invalid")
    # utf-8 (not utf-8-sig) intentionally rejects a BOM and alternate encodings.
    return json.loads(raw.decode("utf-8"), object_pairs_hook=_unique_object,
                      parse_constant=_reject_constant)


def _pointer(value: Any) -> bool:
    return isinstance(value, str) and len(value) <= 1024 and (
        value == "" or value.startswith("/")
    ) and re.search(r"~(?![01])", value) is None


def _reference(value: Any) -> bool:
    return isinstance(value, str) and value.startswith("#/") and _pointer(value[1:])


def _types(value: Any) -> bool:
    if isinstance(value, str):
        return value in JSON_TYPES
    return isinstance(value, list) and 0 < len(value) <= len(JSON_TYPES) and all(
        isinstance(item, str) and item in JSON_TYPES for item in value
    ) and len(set(value)) == len(value)


def _constraint(keyword: Any, value: Any) -> bool:
    if not isinstance(keyword, str) or keyword not in KEYWORDS:
        return False
    if keyword == "type":
        return _types(value)
    if keyword == "additionalProperties":
        return type(value) is bool
    if keyword in {"minLength", "maxLength"}:
        return type(value) is int and 0 <= value <= 2**31 - 1
    if keyword in {"minimum", "maximum"}:
        return (type(value) is int and -(2**63) <= value < 2**63) or (
            type(value) is float and math.isfinite(value)
        )
    if keyword in {"pattern", "format", "const"}:
        # Patterns and format labels are data only: never evaluate or resolve them.
        return isinstance(value, str) and 0 < len(value) <= 8192
    return False


def validate_report(raw: bytes, packet_bytes: bytes, index: Any) -> list[str]:
    errors: list[str] = []

    def require(condition: bool, message: str) -> None:
        if not condition and message not in errors:
            errors.append(message)

    if not isinstance(packet_bytes, bytes) or hashlib.sha256(packet_bytes).hexdigest() != EXPECTED_PACKET_SHA256:
        return ["packet digest differs from merged authority"]
    packet = yaml.safe_load(packet_bytes)
    observation = packet["referenceObservationExecution"]
    try:
        report = decode_report(raw)
    except (ValueError, UnicodeError, RecursionError):
        return ["report is not bounded strict UTF-8 JSON"]
    require(hashlib.sha256(raw).hexdigest() == EXPECTED_REPORT_SHA256,
            "report digest differs from independently observed authority")

    def inspect(value: Any, depth: int = 0, location: tuple[Any, ...] = ()) -> bool:
        if depth > MAX_DEPTH:
            require(False, "report nesting exceeds the closed grammar")
            return False
        if isinstance(value, dict):
            require(not PROHIBITED_KEYS.intersection(value), "report contains prohibited source text or evidence claims")
            return all([inspect(child, depth + 1, location + (key,)) for key, child in value.items()])
        if isinstance(value, list):
            return all([inspect(child, depth + 1, location + (offset,)) for offset, child in enumerate(value)])
        if isinstance(value, str):
            require(len(value) <= 8192 and not any(ord(c) < 32 for c in value), "report contains an invalid structural string")
            public_launcher = location == ("authority", "packetObservation", "launcherArgv", 0) and value == "/opt/planeon/bin/harness-reference-observe"
            require(public_launcher or (not any(part in value for part in (
                "codex-harness-warmstarts", "/.git/", "file://", "/private/",
                "/Users/", "/home/", "/tmp/", "/opt/", "/etc/", "/var/",
            )) and re.match(r"^[A-Za-z]:[\\/]", value) is None),
                    "report leaks a host or source filesystem path")
        if type(value) is float:
            require(math.isfinite(value), "report contains a non-finite number")
        return True

    if not inspect(report):
        return errors
    try:
        require(raw == report_bytes(report), "report serialization is not canonical")
    except (ValueError, UnicodeError, RecursionError):
        require(False, "report cannot be canonically serialized")
        return errors
    if not isinstance(report, dict):
        return errors + ["report must be an object"]
    require(set(report) == {"schemaVersion", "observationId", "authority", "isolationEvidence", "sources", "facts"},
            "report top-level members are not closed")
    require(report.get("schemaVersion") == "harness.planeon.ai/reference-observation/v1", "report schema version mismatch")
    require(report.get("observationId") == "model-usage-v2-structural-facts", "observation ID mismatch")
    expected_authority = {
        "authorityId": "REF-MODEL-USAGE-V2-001", "commit": SOURCE_COMMIT,
        "extractorSha256": EXPECTED_EXTRACTOR_SHA256, "launcherSha256": EXPECTED_LAUNCHER_SHA256,
        "observerIdentity": "planeon-reference-observer", "packetDigest": EXPECTED_PACKET_SHA256,
        "packetId": PACKET_ID, "packetObservation": observation, "repository": REPOSITORY,
        "schemaVersion": "harness.planeon.ai/reference-source-authority/v1",
    }
    # Canonical JSON equality distinguishes booleans from numbers (True != 1).
    require(canonical(report.get("authority")) == canonical(expected_authority), "observer authority differs from approved binding")
    require(canonical(report.get("isolationEvidence")) == canonical(EXPECTED_ISOLATION), "isolation evidence differs from observed boundary")
    expected_sources = [{"path": SOURCE_PATH, "gitObject": SOURCE_BLOB, "sha256": SOURCE_SHA256}]
    require(report.get("sources") == expected_sources, "source path, Git object or schema digest mismatch")

    records = index.get("sources") if isinstance(index, dict) else None
    matches = [record for record in records if isinstance(record, dict)
               and record.get("repository") == REPOSITORY and record.get("commit") == SOURCE_COMMIT] if isinstance(records, list) else []
    require(len(matches) == 1, "source index must bind one exact repository and commit")
    paths = matches[0].get("paths") if len(matches) == 1 else None
    entries = [entry for entry in paths if isinstance(entry, dict) and entry.get("path") == SOURCE_PATH] if isinstance(paths, list) else []
    require(len(entries) == 1, "source index must bind one exact schema path")
    if len(entries) == 1:
        entry = entries[0]
        require(entry.get("gitObject") == SOURCE_BLOB and entry.get("kind") == "blob"
                and entry.get("recordType") == "BLOB_PENDING"
                and entry.get("useModes") == ["REFERENCE_ONLY"]
                and entry.get("reuseDisposition") == "REFERENCE_ONLY_PENDING_PATH_REVIEW",
                "source index widens or substitutes reference-only blob authority")

    facts = report.get("facts")
    if not isinstance(facts, list):
        return errors + ["facts must be an array"]
    require(len(facts) == sum(EXPECTED_COUNTS.values()), "observed fact count mismatch")
    require(all(isinstance(fact, dict) for fact in facts), "fact must be an object")
    if not all(isinstance(fact, dict) for fact in facts):
        return errors
    keys = [canonical(fact) for fact in facts]
    require(keys == sorted(keys), "facts are not canonically ordered")
    require(len(set(keys)) == len(keys), "duplicate structural fact")
    counts: Counter[str] = Counter()
    fields: set[tuple[str, str]] = set()
    required: set[tuple[str, str]] = set()
    field_refs: set[tuple[str, str]] = set()
    edges: set[tuple[str, str]] = set()
    for fact in facts:
        kind = fact.get("kind")
        if not isinstance(kind, str) or kind not in FIELDS:
            require(False, "undeclared fact kind")
            continue
        counts[kind] += 1
        mandatory = COMMON | {"field"} if kind == "OBJECT_FIELD" else FIELDS[kind]
        require(mandatory <= set(fact) <= FIELDS[kind], "fact members are not closed or complete")
        require(fact.get("sourcePath") == SOURCE_PATH, "fact references undeclared source")
        pointer = fact.get("jsonPointer")
        require(_pointer(pointer), "invalid structural JSON pointer")
        if not _pointer(pointer):
            continue
        if kind in {"OBJECT_FIELD", "REQUIRED_FIELD"}:
            field = fact.get("field")
            require(isinstance(field, str) and NAME.fullmatch(field) is not None, "invalid structural field name")
            if not isinstance(field, str):
                continue
            if kind == "REQUIRED_FIELD":
                required.add((pointer, field))
            else:
                suffix = "/properties/" + field.replace("~", "~0").replace("/", "~1")
                require(pointer.endswith(suffix), "object field pointer and name differ")
                if pointer.endswith(suffix):
                    fields.add((pointer[:-len(suffix)], field))
                require("type" not in fact or _types(fact["type"]), "invalid object-field type")
                require("format" not in fact or isinstance(fact["format"], str), "invalid object-field format")
                if "$ref" in fact:
                    require(_reference(fact["$ref"]), "reference is not a local structural pointer")
                    if _reference(fact["$ref"]):
                        field_refs.add((pointer, fact["$ref"]))
        elif kind == "REFERENCE_EDGE":
            reference = fact.get("reference")
            require(_reference(reference), "reference is not a local structural pointer")
            if _reference(reference):
                edges.add((pointer, reference))
        elif kind == "SCHEMA_DIGEST":
            require(pointer == "" and fact.get("gitObject") == SOURCE_BLOB and fact.get("sha256") == SOURCE_SHA256,
                    "schema-digest fact differs from exact source binding")
        elif kind == "SCHEMA_IDENTITY":
            require(pointer == "" and fact.get("schemaDialect") == "https://json-schema.org/draft/2020-12/schema"
                    and fact.get("schemaId") == "https://prometa.ai/contracts/prometa-model-usage-v2.schema.json",
                    "schema identity differs from observed identity")
        elif kind == "STATE_ENUM":
            require(pointer == "/properties/outcome" and fact.get("keyword") == "enum"
                    and fact.get("value") == ["ok", "error", "timeout", "denied", None], "observed state enum mismatch")
        elif kind == "VALUE_CONSTRAINT":
            require(_constraint(fact.get("keyword"), fact.get("value")), "constraint is outside the closed fact grammar")
    require(dict(counts) == EXPECTED_COUNTS, "observed fact-kind counts mismatch")
    require(required <= fields, "required field lacks a corresponding observed property")
    require(field_refs <= edges, "object reference lacks its observed edge")
    return errors


def read_report(path: Path) -> bytes:
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK)
    with os.fdopen(descriptor, "rb") as stream:
        metadata = os.fstat(stream.fileno())
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_size > MAX_REPORT_BYTES:
            raise ValueError("report must be a bounded regular file, not a link")
        raw = stream.read(MAX_REPORT_BYTES + 1)
        if len(raw) > MAX_REPORT_BYTES:
            raise ValueError("report grew beyond the byte limit")
        return raw


def main() -> int:
    try:
        errors = validate_report(read_report(REPORT_PATH), PACKET_PATH.read_bytes(),
                                 yaml.safe_load(INDEX_PATH.read_text(encoding="utf-8")))
    except (OSError, ValueError, TypeError, RecursionError, yaml.YAMLError):
        print("model observation validation FAILED: required local inputs unavailable or malformed")
        return 1
    for error in errors:
        print("ERROR: " + error)
    if errors:
        return 1
    print(f"model observation validation passed: sources=1 facts=162 sha256={EXPECTED_REPORT_SHA256}")
    print("structuralObservation=PASS originalSourceTests=NOT_RUN_ENV_UNAVAILABLE "
          "originalSourceBehavioralParity=NOT_ESTABLISHED sourceExecution=DENIED "
          "copyAuthority=NONE liveEvidence=NOT_RUN_ENV_UNAVAILABLE")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
