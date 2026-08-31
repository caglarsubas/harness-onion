#!/usr/bin/env python3
"""Validate the deterministic, source-free data.harness/v1 observation report."""

from __future__ import annotations

import hashlib
import json
import re
import sys
from pathlib import Path
from typing import Any

import yaml


ROOT = Path(__file__).resolve().parents[1]
REPORT_PATH = ROOT / "architecture/observations/data-harness-v1.json"
PACKET_PATH = ROOT / "task-packets/MET-002.yaml"
INDEX_PATH = ROOT / "architecture/reuse-path-index.yaml"
EXPECTED_REPORT_SHA256 = "5c559a6ef3d59fa40e74ab2fb36603752751f523249da884f8e0d8daa06cfe10"
EXPECTED_FACT_COUNT = 2030
EXPECTED_FACT_KIND_COUNTS = {
    "OBJECT_FIELD": 523,
    "REFERENCE_EDGE": 46,
    "REQUIRED_FIELD": 429,
    "SCHEMA_DIGEST": 29,
    "SCHEMA_IDENTITY": 29,
    "STATE_ENUM": 12,
    "VALUE_CONSTRAINT": 962,
}
PROHIBITED_KEYS = {
    "$comment",
    "description",
    "example",
    "examples",
    "raw",
    "sourceRoot",
    "sourceText",
    "title",
}
HEX_40 = re.compile(r"^[0-9a-f]{40}$")
HEX_64 = re.compile(r"^[0-9a-f]{64}$")
FACT_FIELDS = {
    "SCHEMA_IDENTITY": {"kind", "sourcePath", "jsonPointer", "schemaDialect", "schemaId"},
    "OBJECT_FIELD": {
        "kind",
        "sourcePath",
        "jsonPointer",
        "field",
        "type",
        "$ref",
        "format",
        "schemaForm",
    },
    "REQUIRED_FIELD": {"kind", "sourcePath", "jsonPointer", "field"},
    "VALUE_CONSTRAINT": {"kind", "sourcePath", "jsonPointer", "keyword", "value"},
    "STATE_ENUM": {"kind", "sourcePath", "jsonPointer", "keyword", "value"},
    "REFERENCE_EDGE": {"kind", "sourcePath", "jsonPointer", "reference"},
    "SCHEMA_DIGEST": {"kind", "sourcePath", "jsonPointer", "gitObject", "sha256"},
}


def canonical_key(value: dict[str, Any]) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def load_packet() -> tuple[dict[str, Any], bytes]:
    packet_bytes = PACKET_PATH.read_bytes()
    packet = yaml.safe_load(packet_bytes)
    if not isinstance(packet, dict):
        raise ValueError("MET-002 packet is not a mapping")
    return packet, packet_bytes


def indexed_blobs(repository: str, commit: str) -> dict[str, dict[str, Any]]:
    index = yaml.safe_load(INDEX_PATH.read_text(encoding="utf-8"))
    records = index.get("sources") if isinstance(index, dict) else index
    if not isinstance(records, list):
        raise ValueError("reuse path index has no repository list")
    matches = [
        record
        for record in records
        if isinstance(record, dict)
        and record.get("repository") == repository
        and record.get("commit") == commit
    ]
    if len(matches) != 1:
        raise ValueError("reuse path index has no unique observed repository record")
    return {
        entry["path"]: entry
        for entry in matches[0].get("paths", [])
        if isinstance(entry, dict) and isinstance(entry.get("path"), str)
    }


def validate_report(
    report: Any,
    raw: bytes,
    packet: dict[str, Any],
    packet_bytes: bytes,
) -> list[str]:
    errors: list[str] = []

    def require(condition: bool, message: str) -> None:
        if not condition:
            errors.append(message)

    require(hashlib.sha256(raw).hexdigest() == EXPECTED_REPORT_SHA256, "report digest differs from observed authority")
    require(isinstance(report, dict), "report must be an object")
    if not isinstance(report, dict):
        return errors
    require(
        raw == (json.dumps(report, indent=2, sort_keys=True, ensure_ascii=False) + "\n").encode("utf-8"),
        "report bytes are not canonical UTF-8 JSON",
    )
    require(
        set(report) == {"schemaVersion", "observationId", "authority", "isolationEvidence", "sources", "facts"},
        "report top-level members are not closed",
    )
    require(report.get("schemaVersion") == "harness.planeon.ai/reference-observation/v1", "report schema version mismatch")
    require(report.get("observationId") == "data-harness-v1-structural-facts", "report observation ID mismatch")

    def reject_prohibited(value: Any, pointer: str = "") -> None:
        if isinstance(value, dict):
            for key, child in value.items():
                require(key not in PROHIBITED_KEYS, f"prohibited source-text key at {pointer}/{key}")
                reject_prohibited(child, f"{pointer}/{key}")
        elif isinstance(value, list):
            for index, child in enumerate(value):
                reject_prohibited(child, f"{pointer}/{index}")
        elif isinstance(value, str):
            require(
                "codex-harness-warmstarts" not in value and "/.git/" not in value,
                f"report leaks a warm-source filesystem path at {pointer}",
            )

    reject_prohibited(report)
    authority = report.get("authority")
    require(isinstance(authority, dict), "report authority must be an object")
    if not isinstance(authority, dict):
        return errors
    require(
        set(authority)
        == {
            "schemaVersion",
            "authorityId",
            "launcherSha256",
            "extractorSha256",
            "packetId",
            "packetDigest",
            "packetObservation",
            "repository",
            "commit",
            "observerIdentity",
        },
        "report authority contains host-dependent or unknown members",
    )
    observation = packet.get("referenceObservationExecution")
    require(packet.get("id") == "MET-002", "observation must be owned by MET-002")
    require(packet.get("warmSourceAccess") == "AUTHORIZED_READ_ONLY_OBSERVATION", "MET-002 observation authority is absent")
    require(authority.get("schemaVersion") == "harness.planeon.ai/reference-source-authority/v1", "source authority version mismatch")
    require(authority.get("authorityId") == "REF-DATA-HARNESS-V1-001", "source authority ID mismatch")
    require(authority.get("packetId") == "MET-002", "source authority packet mismatch")
    require(authority.get("packetDigest") == hashlib.sha256(packet_bytes).hexdigest(), "source authority packet digest mismatch")
    require(authority.get("packetObservation") == observation, "source authority differs from packet observation binding")
    require(authority.get("repository") == observation.get("repository") if isinstance(observation, dict) else False, "source authority repository mismatch")
    require(authority.get("commit") == observation.get("commit") if isinstance(observation, dict) else False, "source authority commit mismatch")
    require(authority.get("observerIdentity") == "planeon-reference-observer", "observer identity mismatch")
    require(HEX_64.fullmatch(str(authority.get("launcherSha256", ""))) is not None, "launcher digest is invalid")
    require(HEX_64.fullmatch(str(authority.get("extractorSha256", ""))) is not None, "extractor digest is invalid")

    expected_isolation = {
        "networkBackend": "darwin-sandbox",
        "outboundDenied": True,
        "errno": 1,
        "sourceWriteAccess": "DENIED",
        "sourceCodeExecution": "DENIED",
        "copyAuthority": "NONE",
    }
    require(report.get("isolationEvidence") == expected_isolation, "observation isolation evidence mismatch")

    expected_paths = observation.get("sourcePaths", []) if isinstance(observation, dict) else []
    require(isinstance(expected_paths, list) and len(expected_paths) == 29 and len(set(expected_paths)) == 29, "packet must bind 29 unique source paths")
    sources = report.get("sources")
    require(isinstance(sources, list), "report sources must be an array")
    if not isinstance(sources, list):
        return errors
    require([source.get("path") for source in sources if isinstance(source, dict)] == sorted(expected_paths), "report source paths differ from packet authority")
    index = indexed_blobs(str(authority.get("repository")), str(authority.get("commit")))
    source_by_path: dict[str, dict[str, Any]] = {}
    for source in sources:
        require(isinstance(source, dict), "report source entry must be an object")
        if not isinstance(source, dict):
            continue
        require(set(source) == {"path", "gitObject", "sha256"}, "report source entry members are not closed")
        path = source.get("path")
        require(isinstance(path, str) and path in expected_paths, "report source path is undeclared")
        if not isinstance(path, str):
            continue
        require(path not in source_by_path, "report repeats a source path")
        source_by_path[path] = source
        indexed = index.get(path, {})
        require(indexed.get("recordType") == "BLOB_PENDING", f"{path} is not an indexed pending blob")
        require(indexed.get("kind") == "blob", f"{path} is not indexed as a blob")
        require(indexed.get("reuseDisposition") == "REFERENCE_ONLY_PENDING_PATH_REVIEW", f"{path} has widened reuse authority")
        require(source.get("gitObject") == indexed.get("gitObject"), f"{path} Git object differs from reuse index")
        require(HEX_40.fullmatch(str(source.get("gitObject", ""))) is not None, f"{path} Git object is malformed")
        require(HEX_64.fullmatch(str(source.get("sha256", ""))) is not None, f"{path} SHA-256 is malformed")

    facts = report.get("facts")
    require(isinstance(facts, list) and len(facts) == EXPECTED_FACT_COUNT, "report fact count mismatch")
    if not isinstance(facts, list):
        return errors
    require(facts == sorted(facts, key=canonical_key), "report facts are not canonically ordered")
    counts = {kind: 0 for kind in FACT_FIELDS}
    schema_digests: dict[str, dict[str, Any]] = {}
    schema_identities: set[str] = set()
    for fact in facts:
        require(isinstance(fact, dict), "report fact must be an object")
        if not isinstance(fact, dict):
            continue
        kind = fact.get("kind")
        require(kind in FACT_FIELDS, "report contains an undeclared fact kind")
        if kind not in FACT_FIELDS:
            continue
        counts[kind] += 1
        require(set(fact) <= FACT_FIELDS[kind], f"{kind} fact contains unknown members")
        require({"kind", "sourcePath", "jsonPointer"} <= set(fact), f"{kind} fact omits common members")
        source_path = fact.get("sourcePath")
        require(source_path in source_by_path, f"{kind} fact references an undeclared source")
        require(isinstance(fact.get("jsonPointer"), str), f"{kind} fact has invalid JSON pointer")
        if kind == "SCHEMA_DIGEST" and isinstance(source_path, str):
            require(source_path not in schema_digests, "report repeats a schema digest fact")
            schema_digests[source_path] = fact
        elif kind == "SCHEMA_IDENTITY" and isinstance(source_path, str):
            require(source_path not in schema_identities, "report repeats a schema identity fact")
            schema_identities.add(source_path)
        elif kind in {"VALUE_CONSTRAINT", "STATE_ENUM"}:
            require("keyword" in fact and "value" in fact, f"{kind} fact is incomplete")
        elif kind == "OBJECT_FIELD":
            require(isinstance(fact.get("field"), str), "object-field fact has no field name")
        elif kind == "REQUIRED_FIELD":
            require(isinstance(fact.get("field"), str), "required-field fact has no field name")
        elif kind == "REFERENCE_EDGE":
            require(isinstance(fact.get("reference"), str), "reference-edge fact has no reference")
    require(counts == EXPECTED_FACT_KIND_COUNTS, "report fact-kind counts mismatch")
    require(set(schema_digests) == set(expected_paths), "report does not contain one digest per schema")
    require(schema_identities == set(expected_paths), "report does not contain one identity per schema")
    for path, source in source_by_path.items():
        digest_fact = schema_digests.get(path, {})
        require(
            digest_fact.get("gitObject") == source.get("gitObject")
            and digest_fact.get("sha256") == source.get("sha256"),
            f"{path} digest fact differs from source binding",
        )
    return errors


def main() -> int:
    packet, packet_bytes = load_packet()
    raw = REPORT_PATH.read_bytes()
    report = json.loads(raw)
    errors = validate_report(report, raw, packet, packet_bytes)
    if errors:
        for error in errors:
            print(f"ERROR: {error}")
        print(f"data.harness/v1 observation validation failed with {len(errors)} error(s)")
        return 1
    print(
        "data.harness/v1 observation validation passed: "
        f"sources=29 facts={EXPECTED_FACT_COUNT} sha256={EXPECTED_REPORT_SHA256}"
    )
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, ValueError, json.JSONDecodeError, yaml.YAMLError) as exc:
        print(f"ERROR: {exc}")
        raise SystemExit(1)
