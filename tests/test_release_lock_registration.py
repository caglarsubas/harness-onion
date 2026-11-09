"""MET-REGISTRY-001 (slot 284): R13 mas-harness-research-lab's registration through the successor registry record
(VIS-284-ARGV). The release lock reads R13's releaseSet there (Q-284-3 (a); CONTRACT_284 E6, C1-5, C2-6); the one
composition reader keeps the registry's rows and refuses an override, a duplicate or a widened row; and the chain's
import need stays below the bounded limit less 500 (VIS-284-DEPTH). tests/test_release_lock.py stays as at main."""
from __future__ import annotations

import importlib.util
import json
import os
import subprocess
import sys
from pathlib import Path

import pytest
import yaml
from scripts.repository_registration import Refused, composed_rows, registry_rows
from scripts.safe_yaml import safe_load as safe_yaml_load


ROOT = Path(__file__).resolve().parents[1]
FIXTURE_PATH = ROOT / "release/fixture-release-set.yaml"
INERT_LOCK_PATH = ROOT / "release/repos.lock.json"
REGISTRY_PATH = ROOT / "architecture/repositories.yaml"
SUCCESSOR_PATH = ROOT / "architecture/repository-registration/repositories.json"
SCHEMA_PATH = ROOT / "architecture/repository-registration/repositories.schema.json"
SCHEMA_PIN = {"path": "architecture/repository-registration/repositories.schema.json",
              "sha256": json.loads(SUCCESSOR_PATH.read_text(encoding="utf-8"))["schema"]["sha256"]}
R13_ROW = {"id": "research-lab", "name": "mas-harness-research-lab", "kind": "meta", "dependsOn": [], "releaseSet": "EXCLUDED"}


def _load_module(name: str, path: Path):
    specification = importlib.util.spec_from_file_location(name, path)
    assert specification and specification.loader
    module = importlib.util.module_from_spec(specification)
    sys.modules[name] = module
    specification.loader.exec_module(module)
    return module


CHECKER = _load_module("check_release_lock_registration", ROOT / "scripts/check_release_lock.py")


def fixture_document() -> dict:
    document = safe_yaml_load(FIXTURE_PATH.read_text(encoding="utf-8"))
    assert isinstance(document, dict)
    return document


def validate_mutation(tmp_path: Path, document: dict):
    path = tmp_path / "mutated-release-set.yaml"
    path.write_text(yaml.safe_dump(document, sort_keys=False, width=1000), encoding="utf-8")
    return CHECKER.validate_release_lock(path)


def _copy_into(root: Path, *paths: Path) -> Path:
    for path in paths:
        target = root / path.relative_to(ROOT)
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(path.read_bytes())
    return root


def _successor_copy(monkeypatch, tmp_path: Path, rows: list) -> None:
    root = _copy_into(tmp_path / "registration-root", REGISTRY_PATH, SCHEMA_PATH)
    (root / SUCCESSOR_PATH.relative_to(ROOT)).write_text(
        json.dumps({"schema": SCHEMA_PIN, "repositories": rows}, indent=2) + "\n", encoding="utf-8")
    monkeypatch.setattr(CHECKER, "REGISTRATION_ROOT", root)


def test_excluded_release_set_is_refused_on_a_product_repository(monkeypatch, tmp_path: Path) -> None:
    _successor_copy(monkeypatch, tmp_path, [dict(R13_ROW, kind="product")])
    with pytest.raises(CHECKER.ReleaseLockError, match="releaseSet EXCLUDED on a product repository"):
        validate_mutation(tmp_path, fixture_document())
    with pytest.raises(CHECKER.ReleaseLockError, match="releaseSet EXCLUDED on a product repository"):
        CHECKER.validate_release_lock(INERT_LOCK_PATH)


def test_excluded_release_set_is_admitted_on_the_meta_repository(tmp_path: Path) -> None:
    rows = CHECKER.registry_with_successors()
    assert len(rows) == 14
    assert [(r["id"], r["kind"]) for r in rows if r.get("releaseSet") == "EXCLUDED"] == [("research-lab", "meta")]
    document = fixture_document()
    _, report = validate_mutation(tmp_path, document)
    assert report.repositories == 13
    assert "research-lab" not in {record["repositoryId"] for record in document["repositories"]}


def test_release_lock_covers_exactly_the_release_set_repositories(tmp_path: Path) -> None:
    # Condition 2: an equality, never a subset. The release-set schema holds 13 records, so the excluded repository is
    # swapped in for one release-set repository: the lock has 13 records and the equality's own message refuses it.
    document = fixture_document()
    document["repositories"][-1]["repositoryId"] = "research-lab"
    document["repositories"][-1]["repositoryName"] = "mas-harness-research-lab"
    with pytest.raises(CHECKER.ReleaseLockError, match="release lock does not cover the exact repository registry"):
        validate_mutation(tmp_path, document)


def _record(rows: list) -> bytes:
    return (json.dumps({"schema": SCHEMA_PIN, "repositories": rows}) + "\n").encode()


def test_the_composed_rows_are_the_registry_then_the_successor_rows() -> None:
    base = safe_yaml_load(REGISTRY_PATH.read_bytes())["repositories"]
    rows = composed_rows(REGISTRY_PATH.read_bytes(), SUCCESSOR_PATH.read_bytes(), SCHEMA_PATH.read_bytes(), safe_yaml_load)
    assert len(base) == 13 and list(rows[:13]) == base and list(rows[13:]) == [R13_ROW]
    assert registry_rows(ROOT, safe_yaml_load) == rows


def test_the_record_in_the_root_decides_base_rows_or_composed_and_pinned(tmp_path: Path) -> None:
    # VIS-284-LPORACLE: base rows alone only when no successor record is in the root read; with one, the schema and both
    # pins are required, and an unreadable record or a missing schema refuses, never degrades.
    base = safe_yaml_load(REGISTRY_PATH.read_bytes())["repositories"]
    root = _copy_into(tmp_path / "root", REGISTRY_PATH)
    rows = registry_rows(root, safe_yaml_load)
    assert len(rows) == 13 and [r["id"] for r in rows] == [r["id"] for r in base]
    _copy_into(root, SUCCESSOR_PATH)
    with pytest.raises(Refused, match="repositories.schema.json cannot be read"):
        registry_rows(root, safe_yaml_load)
    _copy_into(root, SCHEMA_PATH)
    assert list(registry_rows(root, safe_yaml_load)[13:]) == [R13_ROW]
    record = root / SUCCESSOR_PATH.relative_to(ROOT)
    record.unlink()
    record.mkdir()
    with pytest.raises(Refused, match="repositories.json cannot be read"):
        registry_rows(root, safe_yaml_load)
    record.rmdir()
    record.symlink_to(root / "no-such-record.json")
    with pytest.raises(Refused, match="repositories.json cannot be read"):
        registry_rows(root, safe_yaml_load)


@pytest.mark.parametrize("row,message", [
    (dict(R13_ROW, id="contracts"), "repeats or overrides"),
    (dict(R13_ROW, name="mas-harness-contracts"), "repeats or overrides"),
    (dict(R13_ROW, extra=1), "row form"),
    (dict(R13_ROW, dependsOn=["unknown"]), "unknown repository"),
    (dict(R13_ROW, releaseSet="INCLUDED"), "members"),
    (dict(R13_ROW, kind="plane"), "members"),
])
def test_a_successor_row_never_overrides_repeats_or_widens(row: dict, message: str) -> None:
    with pytest.raises(Refused, match=message):
        composed_rows(REGISTRY_PATH.read_bytes(), _record([row]), SCHEMA_PATH.read_bytes(), safe_yaml_load)


def test_the_successor_record_holds_rows_only_without_duplicates() -> None:
    base, schema = REGISTRY_PATH.read_bytes(), SCHEMA_PATH.read_bytes()
    with pytest.raises(Refused, match="schema pin and rows only"):
        composed_rows(base, json.dumps({"schema": SCHEMA_PIN, "repositories": [R13_ROW], "note": 1}).encode(), schema,
                      safe_yaml_load)
    with pytest.raises(Refused, match="schema pin and rows only"):
        composed_rows(base, _record([]), schema, safe_yaml_load)
    with pytest.raises(Refused, match="repeats or overrides"):
        composed_rows(base, _record([R13_ROW, R13_ROW]), schema, safe_yaml_load)
    with pytest.raises(Refused, match="repeats a key"):
        composed_rows(base, b'{"repositories": [], "repositories": []}', schema, safe_yaml_load)


def test_the_successor_schema_is_pinned_twice_and_a_tampered_byte_refuses() -> None:
    # MON-284-SCHEMA-LOC: the schema lives beside the record, pinned in the record and in the module.
    base, schema, record = REGISTRY_PATH.read_bytes(), SCHEMA_PATH.read_bytes(), SUCCESSOR_PATH.read_bytes()
    at = len(schema) // 2
    tampered = schema[:at] + bytes([schema[at] ^ 1]) + schema[at + 1:]
    with pytest.raises(Refused, match="schema is not the pinned one"):
        composed_rows(base, record, tampered, safe_yaml_load)
    with pytest.raises(Refused, match="does not pin the successor registry schema"):
        composed_rows(base, json.dumps({"schema": dict(SCHEMA_PIN, sha256="0" * 64), "repositories": [R13_ROW]}).encode(),
                      schema, safe_yaml_load)
    with pytest.raises(Refused, match="schema pin and rows only"):
        composed_rows(base, json.dumps({"repositories": [R13_ROW]}).encode(), schema, safe_yaml_load)


def test_the_protected_module_reads_through_this_layers_projection_and_a_tampered_byte_refuses() -> None:
    # VIS-284-PIN: tests/test_task_packets.py, pinned at its era by test_packet_declaration_consistency, is read through
    # 284's historical_bytes; a live byte that 284's authority does not register is refused.
    from scripts import validate_met_registry_001 as profile
    path = "tests/test_task_packets.py"
    raw = (ROOT / path).read_bytes()
    assert profile.historical_bytes(path, raw).count(b"assert len(files) == EXPECTED_PACKET_COUNT == 293") == 1
    at = len(raw) // 2
    with pytest.raises(ValueError, match="unreviewed current source"):
        profile.historical_bytes(path, raw[:at] + bytes([raw[at] ^ 1]) + raw[at + 1:])


@pytest.mark.parametrize("form", ["package", "bare"])
def test_the_chain_import_need_stays_below_the_bounded_limit_less_500(form: str) -> None:
    # VIS-284-DEPTH condition 4: N = 2000; the chain's oldest entries import, in each module form, at a recursion limit
    # of N - 500 = 1500 in a fresh interpreter, so this fails only when the chain's headroom runs low.
    imports = ("import scripts.validate_credential_lifecycle, scripts.validate_ci_performance" if form == "package"
               else "sys.path.insert(0, 'scripts'); import validate_credential_lifecycle, validate_ci_performance")
    env = dict(os.environ, PYTHONDONTWRITEBYTECODE="1", PYTHONPATH=str(ROOT))
    run = subprocess.run([sys.executable, "-B", "-c", "import sys; sys.setrecursionlimit(1500); " + imports],
                         cwd=ROOT, env=env, capture_output=True, text=True, timeout=120)
    assert run.returncode == 0, run.stderr[-400:]


def test_both_successor_records_meet_their_schemas_and_the_placement_reader_composes() -> None:
    # VIS-284-LPORACLE-2: R13's placement row is the successor placement record's; the data file keeps its thirteen.
    import jsonschema
    from scripts import repository_registration as registration
    for record, schema in ((SUCCESSOR_PATH, SCHEMA_PATH),
                           (ROOT / registration.SUCCESSOR_PLACEMENT_PATH, ROOT / registration.PLACEMENT_SCHEMA_PATH)):
        jsonschema.Draft202012Validator(json.loads(schema.read_bytes())).validate(json.loads(record.read_bytes()))
    base = json.loads((ROOT / registration.BASE_PLACEMENT_PATH).read_bytes())["repositories"]
    rows = registration.placement_rows(ROOT)
    assert len(base) == 13 and list(rows[:13]) == base and [r["id"] for r in rows[13:]] == ["research-lab"]
    assert registration.placement_record_present(ROOT) and registration.record_present(ROOT)


def test_the_placement_record_decides_in_its_own_root_and_refuses_never_degrades(tmp_path: Path) -> None:
    from scripts import repository_registration as registration
    data, record = ROOT / registration.BASE_PLACEMENT_PATH, ROOT / registration.SUCCESSOR_PLACEMENT_PATH
    schema = ROOT / registration.PLACEMENT_SCHEMA_PATH
    root = _copy_into(tmp_path / "root", data)
    assert len(registration.placement_rows(root)) == 13
    _copy_into(root, record)
    with pytest.raises(Refused, match="language-placement.schema.json cannot be read"):
        registration.placement_rows(root)
    _copy_into(root, schema)
    assert len(registration.placement_rows(root)) == 14
    base, raw, schema_raw = json.loads(data.read_bytes())["repositories"], record.read_bytes(), schema.read_bytes()
    at = len(schema_raw) // 2
    with pytest.raises(Refused, match="successor placement schema is not the pinned one"):
        registration.composed_placement_rows(base, raw, schema_raw[:at] + bytes([schema_raw[at] ^ 1]) + schema_raw[at + 1:])
    value = json.loads(raw)
    for change, message in (({"note": 1}, "its decision and its rows only"),
                            ({"schema": dict(value["schema"], sha256="0" * 64)}, "does not pin its schema"),
                            ({"decision": {"packet": "LAB-REPO-001"}}, "names its packet, its policy and its text"),
                            ({"repositories": [dict(value["repositories"][0], extra=1)]}, "placement row form"),
                            ({"repositories": [dict(value["repositories"][0], id="contracts")]}, "repeats or overrides")):
        with pytest.raises(Refused, match=message):
            registration.composed_placement_rows(base, json.dumps(dict(value, **change)).encode(), schema_raw)
