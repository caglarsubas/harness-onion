#!/usr/bin/env python3
"""Unprivileged, network-denied extractor for approved reference observations."""

from __future__ import annotations

import errno
import hashlib
import json
import os
import socket
import stat
import sys
from pathlib import Path
from typing import Any


MAX_SCHEMA_BYTES = 4 * 1024 * 1024
STATE_NAMES = {
    "action", "decision", "lifecycle", "lifecycleState", "mode", "outcome",
    "phase", "readiness", "result", "state", "status",
}
CONSTRAINT_KEYS = {
    "additionalItems", "additionalProperties", "const", "contains",
    "dependentRequired", "exclusiveMaximum", "exclusiveMinimum", "format",
    "maxContains", "maxItems", "maxLength", "maxProperties", "maximum",
    "minContains", "minItems", "minLength", "minProperties", "minimum",
    "multipleOf", "pattern", "propertyNames", "type", "uniqueItems",
}
PROSE_KEYS = {"$comment", "description", "example", "examples", "title"}


class ObservationError(RuntimeError):
    pass


def _object_no_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ObservationError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def _canonical_key(value: dict[str, Any]) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def _pointer_join(pointer: str, token: str) -> str:
    escaped = token.replace("~", "~0").replace("/", "~1")
    return f"{pointer}/{escaped}" if pointer else f"/{escaped}"


def _type_summary(schema: Any) -> dict[str, Any]:
    if not isinstance(schema, dict):
        return {"schemaForm": type(schema).__name__}
    return {
        key: value
        for key in ("type", "$ref", "format")
        if isinstance((value := schema.get(key)), (str, list))
    }


def _walk_schema(source_path: str, node: Any, pointer: str, facts: list[dict[str, Any]]) -> None:
    if isinstance(node, list):
        for index, child in enumerate(node):
            _walk_schema(source_path, child, _pointer_join(pointer, str(index)), facts)
        return
    if not isinstance(node, dict):
        return
    if pointer == "":
        facts.append({
            "kind": "SCHEMA_IDENTITY", "sourcePath": source_path,
            "jsonPointer": "", "schemaDialect": node.get("$schema"),
            "schemaId": node.get("$id"),
        })
    if isinstance(node.get("$ref"), str):
        facts.append({
            "kind": "REFERENCE_EDGE", "sourcePath": source_path,
            "jsonPointer": pointer, "reference": node["$ref"],
        })
    properties = node.get("properties")
    if isinstance(properties, dict):
        for field_name, field_schema in sorted(properties.items()):
            fact = {
                "kind": "OBJECT_FIELD", "sourcePath": source_path,
                "jsonPointer": _pointer_join(_pointer_join(pointer, "properties"), field_name),
                "field": field_name,
            }
            fact.update(_type_summary(field_schema))
            facts.append(fact)
    required = node.get("required")
    if isinstance(required, list) and all(isinstance(item, str) for item in required):
        for field_name in sorted(required):
            facts.append({
                "kind": "REQUIRED_FIELD", "sourcePath": source_path,
                "jsonPointer": pointer, "field": field_name,
            })
    enum_value = node.get("enum")
    if isinstance(enum_value, list):
        token = pointer.rsplit("/", 1)[-1].replace("~1", "/").replace("~0", "~")
        facts.append({
            "kind": "STATE_ENUM" if token in STATE_NAMES else "VALUE_CONSTRAINT",
            "sourcePath": source_path, "jsonPointer": pointer,
            "keyword": "enum", "value": enum_value,
        })
    for keyword in sorted(CONSTRAINT_KEYS):
        if keyword not in node or keyword in {"contains", "propertyNames"}:
            continue
        value = node[keyword]
        if isinstance(value, (str, int, float, bool, type(None), list, dict)):
            facts.append({
                "kind": "VALUE_CONSTRAINT", "sourcePath": source_path,
                "jsonPointer": pointer, "keyword": keyword, "value": value,
            })
    for key, child in sorted(node.items()):
        if key in PROSE_KEYS:
            continue
        if key in {"enum", "required"} | CONSTRAINT_KEYS and key not in {"contains", "propertyNames"}:
            continue
        _walk_schema(source_path, child, _pointer_join(pointer, key), facts)


def _read_regular_file(path: Path) -> bytes:
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags)
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_size > MAX_SCHEMA_BYTES:
            raise ObservationError("declared schema blob is invalid or exceeds the observation limit")
        chunks: list[bytes] = []
        while chunk := os.read(descriptor, 65536):
            chunks.append(chunk)
        return b"".join(chunks)
    finally:
        os.close(descriptor)


def _git_blob_oid(data: bytes) -> str:
    return hashlib.sha1(f"blob {len(data)}\0".encode("ascii") + data, usedforsecurity=False).hexdigest()


def _prove_network_denial() -> int:
    probe = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    probe.settimeout(1.0)
    try:
        probe.connect(("1.1.1.1", 443))
    except OSError as exc:
        if exc.errno != errno.EPERM:
            raise ObservationError(f"network denial returned non-isolation errno {exc.errno}") from exc
        return exc.errno
    finally:
        probe.close()
    raise ObservationError("network isolation allowed outbound connection")


def _tree_report(authority: dict[str, Any], denial_errno: int) -> dict[str, Any]:
    bindings = authority.pop("sourceBindings")
    if not isinstance(bindings, list) or not bindings:
        raise ObservationError("full-tree authority has no bindings")
    facts = [
        {
            "kind": "TREE_ENTRY",
            "sourcePath": item["path"],
            "gitObject": item["gitObject"],
            "objectType": item["objectType"],
            "mode": item["mode"],
        }
        for item in bindings
    ]
    counts = {
        object_type: sum(item["objectType"] == object_type for item in bindings)
        for object_type in sorted({item["objectType"] for item in bindings})
    }
    facts.append({
        "kind": "REPOSITORY_SUMMARY",
        "sourcePath": ".",
        "trackedEntryCount": len(bindings),
        "objectTypeCounts": counts,
    })
    facts.sort(key=_canonical_key)
    observation = authority["packetObservation"]
    return {
        "schemaVersion": "harness.planeon.ai/reference-observation/v1",
        "observationId": f"{authority['packetId'].casefold()}-full-tracked-tree",
        "authority": authority,
        "isolationEvidence": {
            "networkBackend": "darwin-sandbox", "outboundDenied": True,
            "errno": denial_errno, "sourceContentReadAccess": "DENIED",
            "sourceWriteAccess": "DENIED", "sourceCodeExecution": "DENIED",
            "copyAuthority": observation["copyAuthority"],
        },
        "sources": bindings,
        "facts": facts,
    }


def _schema_observation_id(authority: dict[str, Any]) -> str:
    """Keep the historical data report stable; admit only the exact new model binding."""
    if authority.get("packetId") == "MET-002":
        return "data-harness-v1-structural-facts"
    observation = authority.get("packetObservation", {})
    if (
        authority.get("packetId") == "MET-OBS-MODEL-001"
        and authority.get("repository") == observation.get("repository")
        == "git@github.com:caglarsubas/llm_inference_engine.git"
        and authority.get("commit") == observation.get("commit")
        == "6815c21cb10a4d7dc0b4804f6bb223afb4321e97"
        and observation.get("sourcePaths") == ["contracts/prometa-model-usage-v2.schema.json"]
        and observation.get("outputPath") == "architecture/observations/model-usage-v2.json"
    ):
        return "model-usage-v2-structural-facts"
    raise ObservationError("unrecognized schema observation authority")


def _schema_report(authority: dict[str, Any], source_root: Path, denial_errno: int) -> dict[str, Any]:
    observation_id = _schema_observation_id(authority)
    facts: list[dict[str, Any]] = []
    sources: list[dict[str, str]] = []
    for binding in authority.pop("sourceBindings"):
        source_path = binding["path"]
        path = source_root.joinpath(*source_path.split("/"))
        resolved = path.resolve(strict=True)
        if source_root not in resolved.parents:
            raise ObservationError("declared source path escapes the snapshot root")
        data = _read_regular_file(resolved)
        git_object = _git_blob_oid(data)
        if git_object != binding["gitObject"]:
            raise ObservationError("declared source blob does not match signed Git object")
        document = json.loads(data.decode("utf-8"), object_pairs_hook=_object_no_duplicates)
        if not isinstance(document, dict):
            raise ObservationError("observed JSON Schema must be an object")
        sha256 = hashlib.sha256(data).hexdigest()
        sources.append({"path": source_path, "gitObject": git_object, "sha256": sha256})
        facts.append({
            "kind": "SCHEMA_DIGEST", "sourcePath": source_path,
            "jsonPointer": "", "gitObject": git_object, "sha256": sha256,
        })
        _walk_schema(source_path, document, "", facts)
    facts.sort(key=_canonical_key)
    return {
        "schemaVersion": "harness.planeon.ai/reference-observation/v1",
        "observationId": observation_id,
        "authority": authority,
        "isolationEvidence": {
            "networkBackend": "darwin-sandbox", "outboundDenied": True,
            "errno": denial_errno, "sourceWriteAccess": "DENIED",
            "sourceCodeExecution": "DENIED", "copyAuthority": "NONE",
        },
        "sources": sorted(sources, key=lambda item: item["path"]),
        "facts": facts,
    }


def main() -> int:
    authority = json.load(sys.stdin, object_pairs_hook=_object_no_duplicates)
    source_root = Path(authority.pop("sourceRoot"))
    authority.pop("issuedAt")
    authority.pop("observerUid")
    authority.pop("observerGid")
    denial_errno = _prove_network_denial()
    if authority["packetObservation"].get("observationMode") == "FULL_TRACKED_TREE_METADATA":
        report = _tree_report(authority, denial_errno)
    else:
        report = _schema_report(authority, source_root, denial_errno)
    sys.stdout.write(json.dumps(report, indent=2, sort_keys=True, ensure_ascii=False) + "\n")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (ObservationError, OSError, ValueError, UnicodeError) as exc:
        print(f"reference observation blocked: {exc}", file=sys.stderr)
        raise SystemExit(1)
