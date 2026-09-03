from __future__ import annotations

import copy
import json
from pathlib import Path

from scripts.validate_readiness import load_yaml
from scripts.validate_repository_tree_observation import validate


ROOT = Path(__file__).resolve().parents[1]


def fixture_report() -> dict:
    packet = load_yaml(ROOT / "task-packets/MET-OBS-AH-001.yaml")
    sources = [
        {"path": "README.md", "mode": "100644", "objectType": "blob", "gitObject": "a" * 40},
        {"path": "src", "mode": "040000", "objectType": "tree", "gitObject": "b" * 40},
    ]
    facts = [
        {
            "kind": "TREE_ENTRY", "sourcePath": item["path"],
            "gitObject": item["gitObject"], "objectType": item["objectType"],
            "mode": item["mode"],
        }
        for item in sources
    ]
    facts.append({
        "kind": "REPOSITORY_SUMMARY", "sourcePath": ".",
        "trackedEntryCount": 2, "objectTypeCounts": {"blob": 1, "tree": 1},
    })
    facts.sort(key=lambda value: json.dumps(value, sort_keys=True, separators=(",", ":")))
    return {
        "schemaVersion": "harness.planeon.ai/reference-observation/v1",
        "observationId": "met-obs-ah-001-full-tracked-tree",
        "authority": {
            "packetId": "MET-OBS-AH-001", "packetDigest": "c" * 64,
            "packetObservation": packet["referenceObservationExecution"],
            "repository": packet["referenceObservationExecution"]["repository"],
            "commit": packet["referenceObservationExecution"]["commit"],
        },
        "isolationEvidence": {
            "networkBackend": "darwin-sandbox", "outboundDenied": True,
            "errno": 1, "sourceContentReadAccess": "DENIED",
            "sourceWriteAccess": "DENIED", "sourceCodeExecution": "DENIED",
            "copyAuthority": "NONE",
        },
        "sources": sources,
        "facts": facts,
    }


def write_report(tmp_path: Path, report: dict) -> Path:
    path = tmp_path / "observation.json"
    path.write_text(json.dumps(report), encoding="utf-8")
    return path


def test_tree_observation_accepts_canonical_metadata(tmp_path: Path) -> None:
    assert validate(write_report(tmp_path, fixture_report()), "MET-OBS-AH-001") == []


def test_tree_observation_rejects_content_and_binding_tampering(tmp_path: Path) -> None:
    variants = []
    leaked = copy.deepcopy(fixture_report())
    leaked["sourceText"] = "forbidden"
    variants.append(leaked)
    widened = copy.deepcopy(fixture_report())
    widened["isolationEvidence"]["sourceContentReadAccess"] = "READ_ONLY"
    variants.append(widened)
    changed_commit = copy.deepcopy(fixture_report())
    changed_commit["authority"]["commit"] = "d" * 40
    variants.append(changed_commit)
    missing_entry = copy.deepcopy(fixture_report())
    missing_entry["facts"] = [fact for fact in missing_entry["facts"] if fact.get("sourcePath") != "README.md"]
    variants.append(missing_entry)
    for variant in variants:
        assert validate(write_report(tmp_path, variant), "MET-OBS-AH-001")
