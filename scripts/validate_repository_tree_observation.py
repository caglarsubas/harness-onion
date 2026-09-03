#!/usr/bin/env python3
"""Validate a distilled full tracked-tree observation without warm-source access."""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path
from typing import Any

import yaml


ROOT = Path(__file__).resolve().parents[1]
PROHIBITED_KEYS = {"$comment", "description", "example", "examples", "raw", "sourceRoot", "sourceText", "title"}


def _canonical(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def validate(path: Path, packet_id: str) -> list[str]:
    errors: list[str] = []
    try:
        report = json.loads(path.read_text(encoding="utf-8"))
        packet = yaml.safe_load((ROOT / f"task-packets/{packet_id}.yaml").read_text(encoding="utf-8"))
    except (OSError, ValueError, yaml.YAMLError) as exc:
        return [f"cannot load observation authority: {exc}"]

    def require(condition: bool, message: str) -> None:
        if not condition:
            errors.append(message)

    def visit(value: Any) -> None:
        if isinstance(value, dict):
            overlap = PROHIBITED_KEYS & set(value)
            require(not overlap, f"observation contains prohibited key: {sorted(overlap)[0] if overlap else ''}")
            for child in value.values():
                visit(child)
        elif isinstance(value, list):
            for child in value:
                visit(child)

    require(report.get("schemaVersion") == "harness.planeon.ai/reference-observation/v1", "observation schema mismatch")
    require(report.get("observationId") == f"{packet_id.casefold()}-full-tracked-tree", "observation id mismatch")
    visit(report)
    observation = packet.get("referenceObservationExecution", {})
    authority = report.get("authority", {})
    require(authority.get("packetId") == packet_id, "observation packet id mismatch")
    require(authority.get("packetObservation") == observation, "observation packet binding mismatch")
    require(authority.get("repository") == observation.get("repository"), "observation repository mismatch")
    require(authority.get("commit") == observation.get("commit"), "observation commit mismatch")
    require(bool(re.fullmatch(r"[0-9a-f]{64}", str(authority.get("packetDigest", "")))), "observation packet digest invalid")

    isolation = report.get("isolationEvidence", {})
    require(isolation == {
        "networkBackend": "darwin-sandbox", "outboundDenied": True, "errno": 1,
        "sourceContentReadAccess": "DENIED", "sourceWriteAccess": "DENIED",
        "sourceCodeExecution": "DENIED", "copyAuthority": "NONE",
    }, "observation isolation evidence mismatch")
    sources = report.get("sources", [])
    facts = report.get("facts", [])
    require(isinstance(sources, list) and bool(sources), "observation source inventory is empty")
    require(isinstance(facts, list) and bool(facts), "observation facts are empty")
    if not isinstance(sources, list) or not isinstance(facts, list):
        return errors
    require(sources == sorted(sources, key=lambda item: item.get("path", "")), "observation sources are not path-sorted")
    require(facts == sorted(facts, key=_canonical), "observation facts are not canonical")
    paths: list[str] = []
    for item in sources:
        require(set(item) == {"path", "mode", "objectType", "gitObject"}, "tree source entry shape mismatch")
        source_path = str(item.get("path", ""))
        paths.append(source_path)
        require(bool(source_path) and not source_path.startswith("/") and ".." not in Path(source_path).parts, "unsafe tree source path")
        require(item.get("objectType") in {"blob", "tree", "commit"}, "unknown tree object type")
        require(bool(re.fullmatch(r"[0-9a-f]{40}", str(item.get("gitObject", "")))), "tree source object id invalid")
        require(bool(re.fullmatch(r"[0-7]{6}", str(item.get("mode", "")))), "tree source mode invalid")
    require(len(paths) == len(set(paths)), "tree source paths are duplicated")
    entry_facts = [fact for fact in facts if fact.get("kind") == "TREE_ENTRY"]
    summary_facts = [fact for fact in facts if fact.get("kind") == "REPOSITORY_SUMMARY"]
    require(len(entry_facts) == len(sources), "tree fact count differs from source inventory")
    require(len(summary_facts) == 1, "repository summary fact must be unique")
    expected_facts = [{"kind": "TREE_ENTRY", "sourcePath": item["path"], "gitObject": item["gitObject"], "objectType": item["objectType"], "mode": item["mode"]} for item in sources]
    require(sorted(entry_facts, key=_canonical) == sorted(expected_facts, key=_canonical), "tree facts differ from source inventory")
    if summary_facts:
        expected_counts = {kind: sum(item["objectType"] == kind for item in sources) for kind in sorted({item["objectType"] for item in sources})}
        require(summary_facts[0] == {"kind": "REPOSITORY_SUMMARY", "sourcePath": ".", "trackedEntryCount": len(sources), "objectTypeCounts": expected_counts}, "repository summary fact mismatch")
    return errors


def main(argv: list[str]) -> int:
    if len(argv) != 3:
        print("usage: validate_repository_tree_observation.py OUTPUT.json PACKET-ID", file=sys.stderr)
        return 2
    errors = validate((ROOT / argv[1]).resolve(), argv[2])
    if errors:
        for error in errors:
            print(error, file=sys.stderr)
        return 1
    print(f"repository tree observation valid: {argv[2]}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
