"""D5a oracle tests for MET-REGISTRY-001 (slot 284): R13's registration through the successor records.

Owner decision D5a: a contract packet carries black-box tests written outside the candidate, by someone who is not
its builder. This file was written from three sources only; each test's docstring names the one it checks:

1. CONTRACT_284 rev 5 with errata 1-4 (sha256 e1411781069225a2464bc9229c4978a99ab71cd73d8b8c3cd68ada4f6b47315d):
   section 2 (the product's bytes and plan), section 3 (E1, E2, E2b, E6, E8, E10, E11 and the byte-equal list),
   section 4 (the pins), section 14's general rule (VIS-284-LPORACLE, VIS-284-LPORACLE-2) and section 15a;
2. the packet's meta YAML as the operator exported it (masked): its id, repository, predecessors, prefetch commands,
   allowed paths and its 64 acceptance commands;
3. facts the operator stated in the oracle brief, marked "operator-stated" below: the composition module's names,
   signatures, refusal type and message form, and the command lines, outputs and copied-root file sets of
   scripts/language_placement.py and scripts/check_release_lock.py.

No candidate code, test, validator or authority record was read to write it. Every case is built as files under
pytest's tmp_path; nothing is patched, shimmed or swapped. Exactly two repository modules are loaded by file path
(scripts/repository_registration.py and scripts/safe_yaml.py), each under a new module name of this file's own, and
exactly two repository scripts run as child processes (scripts/language_placement.py and
scripts/check_release_lock.py), with an explicit environment of PATH and PYTHONDONTWRITEBYTECODE only.
"""

from __future__ import annotations

import hashlib
import importlib.util
import json
import os
import re
import shutil
import subprocess
import sys
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[1]

# Repository-relative paths, each as the contract names it.
BASE_REGISTRY = "architecture/repositories.yaml"
SUCCESSOR_REGISTRY = "architecture/repository-registration/repositories.json"
REGISTRY_SCHEMA = "architecture/repository-registration/repositories.schema.json"
BASE_PLACEMENT = "architecture/language-placement.json"
SUCCESSOR_PLACEMENT = "architecture/repository-registration/language-placement.json"
PLACEMENT_SCHEMA = "architecture/repository-registration/language-placement.schema.json"
R8_RECORD = "architecture/repository-registration/rule.json"
V2_RULE = "architecture/chain-product-packets/rule.json"
MODULE = "scripts/repository_registration.py"
SAFE_YAML = "scripts/safe_yaml.py"
LANGUAGE_PLACEMENT = "scripts/language_placement.py"
RELEASE_LOCK = "scripts/check_release_lock.py"
META_YAML = "task-packets/MET-REGISTRY-001.yaml"
PRODUCT_YAML = "task-packets/LAB-REPO-001.yaml"
PLAN_13 = "docs/repositories/13-mas-harness-research-lab.md"
INERT_LOCK = "release/repos.lock.json"
FIXTURE_LOCK = "release/fixture-release-set.yaml"
LOCKS = (INERT_LOCK, FIXTURE_LOCK)

# Section 3: the files that stay byte-equal (so they are outside the meta YAML's change set).
FROZEN = (
    BASE_REGISTRY,
    "schemas/repositories.schema.json",
    "release/evidence-policy.yaml",
    FIXTURE_LOCK,
    INERT_LOCK,
    "tests/test_release_lock.py",
    BASE_PLACEMENT,
    "docs/adr/0010-language-placement.md",
)

# Operator-stated: the copied root that language placement accepts.
LP_FILES = (
    BASE_PLACEMENT,
    "architecture/services.yaml",
    BASE_REGISTRY,
    "architecture/providers.yaml",
    LANGUAGE_PLACEMENT,
    SAFE_YAML,
)
LP_FOLDERS = ("docs/adr", "docs/alpha-2", "docs/harnesses", "docs/repositories")

# Operator-stated: the copied root that the release-lock checker accepts (plus the lock file).
LOCK_FILES = (
    RELEASE_LOCK,
    MODULE,
    "schemas/release-set.schema.json",
    "release/evidence-policy.yaml",
    BASE_REGISTRY,
    SUCCESSOR_REGISTRY,
    REGISTRY_SCHEMA,
)

R13_ID = "research-lab"
R13_NAME = "mas-harness-research-lab"
# E1: R13's one row in the successor registry record.
R13_REGISTRY_ROW = {"id": R13_ID, "name": R13_NAME, "kind": "meta", "dependsOn": [], "releaseSet": "EXCLUDED"}
# E2b: R13's placement row (its two sources are counted apart).
R13_PLACEMENT_FIELDS = {
    "id": R13_ID,
    "name": R13_NAME,
    "rNumber": "R13",
    "languages": ["PYTHON"],
    "toolchain": "Python 3.12.14",
}

DRAFT_2020_12 = "https://json-schema.org/draft/2020-12/schema"
UV_PREFIX = ["uv", "run", "--offline", "--frozen", "--no-sync", "python"]
CHILD_ENV = {"PATH": os.defpath, "PYTHONDONTWRITEBYTECODE": "1"}
CHILD_TIMEOUT = 600

# Refusal texts, verbatim from the contract.
R4_TEXT = "the repositories are exactly the composed registry's ids and names"
REGISTRY_WITHOUT_MODULE = "successor registry record present without its composition module"
PLACEMENT_WITHOUT_MODULE = "successor placement record present without its composition module"
CONDITION_1_TEXT = "releaseSet EXCLUDED on a product repository"


# ---------------------------------------------------------------- helpers


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _live(rel: str) -> bytes:
    return (ROOT / rel).read_bytes()


def _json_bytes(obj: object) -> bytes:
    return (json.dumps(obj, indent=2) + "\n").encode("utf-8")


def _plain(node: object) -> object:
    """Tuples as lists, so a returned row compares with the contract's literal form."""
    if isinstance(node, dict):
        return {key: _plain(value) for key, value in node.items()}
    if isinstance(node, (list, tuple)):
        return [_plain(value) for value in node]
    return node


def _dicts(node: object):
    """Every JSON object inside a parsed document, the document itself first."""
    if isinstance(node, dict):
        yield node
        for value in node.values():
            yield from _dicts(value)
    elif isinstance(node, list):
        for value in node:
            yield from _dicts(value)


def _closed(node: dict) -> bool:
    return node.get("additionalProperties") is False or node.get("unevaluatedProperties") is False


def _tamper(raw: bytes) -> bytes:
    """One byte changed and the JSON still well formed: a trailing newline becomes a space (else a space is added)."""
    if raw.endswith(b"\n"):
        return raw[:-1] + b" "
    return raw + b" "


def _place(root: Path, rel: str, data: bytes) -> None:
    target = root / rel
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_bytes(data)


def _copy(root: Path, *rels: str) -> None:
    for rel in rels:
        _place(root, rel, _live(rel))


def _load_by_path(name: str, rel: str):
    spec = importlib.util.spec_from_file_location(name, ROOT / rel)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


def _run(argv: list, cwd: Path) -> subprocess.CompletedProcess:
    return subprocess.run(
        [str(part) for part in argv],
        cwd=str(cwd),
        env=dict(CHILD_ENV),
        capture_output=True,
        text=True,
        timeout=CHILD_TIMEOUT,
        check=False,
    )


def _tail(proc: subprocess.CompletedProcess, root: Path) -> str:
    """The end of a child's output with the roots replaced by placeholders."""
    text = (proc.stdout or "") + (proc.stderr or "")
    for path, label in ((root.resolve(), "<root>"), (root, "<root>"), (ROOT, "<ROOT>")):
        text = text.replace(str(path), label)
    return text[-1500:]


def _placement_parts(record: dict) -> tuple[str, str]:
    """E2b: besides its schema pin, the record holds one decision object and one row list."""
    decisions = [key for key, value in record.items() if key != "schema" and isinstance(value, dict)]
    rows = [key for key, value in record.items() if isinstance(value, list)]
    assert len(decisions) == 1 and len(rows) == 1, sorted(record)
    return decisions[0], rows[0]


def _message(error: BaseException, root: Path) -> str:
    """A refusal's message for a failure report (diagnostic only), with the roots replaced by placeholders."""
    text = str(error)
    for path, label in ((root.resolve(), "<root>"), (root, "<root>"), (ROOT, "<ROOT>")):
        text = text.replace(str(path), label)
    return text[:300]


def _lp_root(tmp_path: Path, name: str, *, module: bool, registry_record: bool, placement_record: bool) -> Path:
    root = tmp_path / name
    _copy(root, *LP_FILES)
    for folder in LP_FOLDERS:
        shutil.copytree(ROOT / folder, root / folder)
    if module:
        _copy(root, MODULE)
    if registry_record:
        _copy(root, SUCCESSOR_REGISTRY, REGISTRY_SCHEMA)
    if placement_record:
        _copy(root, SUCCESSOR_PLACEMENT, PLACEMENT_SCHEMA)
    return root


def _lp_check(root: Path) -> subprocess.CompletedProcess:
    return _run([sys.executable, "-B", "-E", "-s", root / LANGUAGE_PLACEMENT, "check", "--root", root], root)


def _lp_counts(proc: subprocess.CompletedProcess, root: Path) -> tuple[int, int]:
    lines = proc.stdout.splitlines()
    first = lines[0] if lines else ""
    assert first.startswith("language placement: accepted; "), _tail(proc, root)
    repositories = re.search(r"accepted; (\d+) repositories, ", first)
    spans = re.search(r", (\d+) spans; ", first)
    assert repositories is not None and spans is not None, _tail(proc, root)
    return int(repositories.group(1)), int(spans.group(1))


def _lock_root(tmp_path: Path, name: str, lock: str, record_bytes: bytes | None = None) -> Path:
    root = tmp_path / name
    _copy(root, *LOCK_FILES, lock)
    if record_bytes is not None:
        _place(root, SUCCESSOR_REGISTRY, record_bytes)
    return root


def _lock_check(root: Path, lock: str) -> subprocess.CompletedProcess:
    return _run([sys.executable, "-B", "-E", "-s", root / RELEASE_LOCK, lock], root)


def _lock_repositories(proc: subprocess.CompletedProcess, root: Path) -> int:
    output = (proc.stdout or "") + (proc.stderr or "")
    match = re.search(r"^release lock validation passed: kind=\S+ repositories=(\d+)", output, re.M)
    assert match is not None, _tail(proc, root)
    return int(match.group(1))


# ---------------------------------------------------------------- fixtures


@pytest.fixture(scope="module")
def reg():
    """Operator-stated: the composition module, standard library only, loaded by file path."""
    return _load_by_path("met_registry_001_oracle_repository_registration", MODULE)


@pytest.fixture(scope="module")
def safe_load():
    """Operator-stated: `safe_load` from scripts/safe_yaml.py, which takes bytes."""
    return _load_by_path("met_registry_001_oracle_safe_yaml", SAFE_YAML).safe_load


@pytest.fixture(scope="module")
def live_rows(reg, safe_load):
    return reg.registry_rows(ROOT, safe_load)


@pytest.fixture(scope="module")
def live_placement(reg):
    return reg.placement_rows(ROOT)


# ---------------------------------------------------------------- 1. E1, E2 and section 4


def test_successor_registry_record_holds_its_schema_pin_and_r13_row_only():
    """E1: the record holds "its schema pin and rows only, {"schema": {"path", "sha256"}, "repositories": [...]}; one
    row, R13's ... {id: research-lab, name: mas-harness-research-lab, kind: meta, dependsOn: [], releaseSet: EXCLUDED}";
    E8: "the record's `schema` member must name that path and digest"."""
    record = json.loads(_live(SUCCESSOR_REGISTRY))
    assert set(record) == {"schema", "repositories"}
    assert set(record["schema"]) == {"path", "sha256"}
    assert record["schema"]["path"] == REGISTRY_SCHEMA
    assert record["repositories"] == [R13_REGISTRY_ROW]


def test_registry_schema_is_pinned_twice(reg):
    """E2: "It is pinned twice ...: in the record's `schema` member and as `REGISTRY_SCHEMA_SHA256` in
    `scripts/repository_registration.py`"; both equal the schema file's sha256."""
    digest = _sha256(_live(REGISTRY_SCHEMA))
    assert json.loads(_live(SUCCESSOR_REGISTRY))["schema"]["sha256"] == digest
    assert reg.REGISTRY_SCHEMA_SHA256 == digest


def test_registry_schema_is_a_closed_draft_2020_12_object():
    """E2: "a closed Draft 2020-12 object with `schema` (path const, sha256 pattern) and `repositories` (rows of the
    closed row form, releaseSet {"enum": ["EXCLUDED"]} optional)"."""
    schema = json.loads(_live(REGISTRY_SCHEMA))
    assert schema.get("$schema") == DRAFT_2020_12
    assert schema.get("type") == "object"
    assert _closed(schema)
    assert set(schema.get("properties", {})) == {"schema", "repositories"}
    assert any(node.get("const") == REGISTRY_SCHEMA for node in _dicts(schema))
    forms = [
        node
        for node in _dicts(schema)
        if isinstance(node.get("properties"), dict) and "releaseSet" in node["properties"]
    ]
    assert len(forms) == 1
    form = forms[0]
    assert form["properties"]["releaseSet"] == {"enum": ["EXCLUDED"]}
    assert "releaseSet" not in form.get("required", [])
    assert _closed(form)
    assert {"id", "name", "kind", "dependsOn"} <= set(form["properties"])


def test_the_registry_keeps_section_4s_digest():
    """Section 4: "The registry digest `02190a66...` ... none moves (the registry is byte-equal)"; section 3 lists
    `architecture/repositories.yaml` as byte-equal."""
    assert _sha256(_live(BASE_REGISTRY)).startswith("02190a66")


def test_the_composition_module_names_its_paths_digests_and_refusal(reg):
    """Operator-stated: `Refused` is a `ValueError`; the path constants are repository-relative strings and the
    functions are as listed. The contract gives each path's literal text (E1, E2, E2b, E8) and V2_SHA256 `23fe723a...`
    (E8: "it binds v2 by V2_SHA256")."""
    assert issubclass(reg.Refused, ValueError)
    assert reg.BASE_REGISTRY_PATH == BASE_REGISTRY
    assert reg.SUCCESSOR_REGISTRY_PATH == SUCCESSOR_REGISTRY
    assert reg.REGISTRY_SCHEMA_PATH == REGISTRY_SCHEMA
    assert reg.BASE_PLACEMENT_PATH == BASE_PLACEMENT
    assert reg.SUCCESSOR_PLACEMENT_PATH == SUCCESSOR_PLACEMENT
    assert reg.PLACEMENT_SCHEMA_PATH == PLACEMENT_SCHEMA
    assert reg.RECORD_PATH == R8_RECORD
    assert reg.V2_RULE_PATH == V2_RULE
    assert reg.V2_SHA256.startswith("23fe723a")
    for name in (
        "record_present",
        "placement_record_present",
        "registry_rows",
        "placement_rows",
        "composed_rows",
        "composed_placement_rows",
        "load",
        "allowed_names",
    ):
        assert callable(getattr(reg, name)), name


def test_the_composition_module_has_exactly_one_hard_link():
    """Section 15a, condition (d): "Every new `scripts/*.py` (`scripts/repository_registration.py`, ...) has exactly
    one hard link"."""
    assert os.stat(ROOT / MODULE).st_nlink == 1


# ---------------------------------------------------------------- 2. E8's composition reader and the general rule


def test_registry_rows_at_root_are_the_registrys_then_r13s(reg, safe_load, live_rows, tmp_path):
    """E8: "with one, `composed_rows(...)` ...: then the registry's rows, then the record's"; the vectors: "the composed
    rows are the registry's thirteen then R13's" and "`registry_rows(ROOT)` equals the composition of the live bytes";
    E6 (ii): "14 composed rows, EXCLUDED only on research-lab (meta)"; E10: "fourteen repositories, two of kind meta
    and twelve product". Operator-stated: both readers return a tuple of dicts."""
    bare = tmp_path / "registry-only"
    _copy(bare, BASE_REGISTRY)
    base = reg.registry_rows(bare, safe_load)
    assert isinstance(base, tuple) and isinstance(live_rows, tuple)
    assert all(isinstance(row, dict) for row in live_rows)
    assert len(base) == 13
    assert len(live_rows) == 14
    assert live_rows[:13] == base
    assert _plain(live_rows[13]) == R13_REGISTRY_ROW
    assert R13_ID not in {row["id"] for row in base}
    assert len({row["id"] for row in live_rows}) == 14
    assert len({row["name"] for row in live_rows}) == 14
    kinds = [row["kind"] for row in live_rows]
    assert kinds.count("meta") == 2 and kinds.count("product") == 12
    assert [row["id"] for row in live_rows if row.get("releaseSet") == "EXCLUDED"] == [R13_ID]
    composed = reg.composed_rows(
        _live(BASE_REGISTRY), _live(SUCCESSOR_REGISTRY), _live(REGISTRY_SCHEMA), safe_load
    )
    assert composed == live_rows


def test_registry_rows_without_the_record_are_the_registrys_alone(reg, safe_load, live_rows, tmp_path):
    """General rule (VIS-284-LPORACLE): "a composed reader reads base rows alone only when no successor record exists
    in the root it reads"; E8: "with no entry at the successor record's path under the root ..., the registry's rows
    alone"; the vectors: "a root without the record gives the thirteen"."""
    no_record = tmp_path / "no-record"
    _copy(no_record, BASE_REGISTRY, REGISTRY_SCHEMA)
    assert reg.record_present(no_record) is False
    assert reg.registry_rows(no_record, safe_load) == live_rows[:13]
    with_record = tmp_path / "with-record"
    _copy(with_record, BASE_REGISTRY, SUCCESSOR_REGISTRY, REGISTRY_SCHEMA)
    assert reg.record_present(with_record) is True
    assert reg.registry_rows(with_record, safe_load) == live_rows
    assert reg.record_present(ROOT) is True


@pytest.mark.parametrize("case", ("record-without-its-schema", "record-is-a-directory"))
def test_registry_rows_refuse_an_unreadable_record_or_schema(reg, safe_load, tmp_path, case):
    """E8: "`record_present`: `os.path.lexists`, so a directory ... is present" and "a record or schema that cannot be
    read refuses, never degrades"; the vectors: "a record without its schema, a record that is a directory ...
    refuse". Operator-stated: the refusal is `Refused`, its message `registration registry: <detail>`."""
    root = tmp_path / case
    if case == "record-without-its-schema":
        _copy(root, BASE_REGISTRY, SUCCESSOR_REGISTRY)
    else:
        _copy(root, BASE_REGISTRY, REGISTRY_SCHEMA)
        (root / SUCCESSOR_REGISTRY).mkdir(parents=True)
    assert reg.record_present(root) is True
    with pytest.raises(reg.Refused) as caught:
        reg.registry_rows(root, safe_load)
    assert str(caught.value).startswith("registration registry:")


def test_composed_rows_accepts_the_live_record_reserialised(reg, safe_load, live_rows):
    """Construction control for the refusal vectors below: the live record, parsed and written again by this file,
    composes to the same rows (E8: the record is checked by its schema pin and row form, not by its own digest)."""
    record_raw = _json_bytes(json.loads(_live(SUCCESSOR_REGISTRY)))
    composed = reg.composed_rows(_live(BASE_REGISTRY), record_raw, _live(REGISTRY_SCHEMA), safe_load)
    assert composed == live_rows


REGISTRY_REFUSALS = (
    "another-record-member",
    "missing-schema-pin",
    "wrong-pin-digest",
    "wrong-pin-path",
    "tampered-schema-byte",
    "empty-row-list",
    "repeated-row",
    "repeated-key",
    "override-of-a-base-id",
    "override-of-a-base-name",
    "another-row-member",
    "unknown-dependsOn",
    "another-releaseSet",
    "another-kind",
)


def _registry_variant(case: str, base_row: dict) -> tuple[bytes, bytes]:
    """The record's and the schema's bytes for one refusal case, built from the live bytes."""
    record = json.loads(_live(SUCCESSOR_REGISTRY))
    schema_raw = _live(REGISTRY_SCHEMA)
    row = record["repositories"][0]
    if case == "tampered-schema-byte":
        return _live(SUCCESSOR_REGISTRY), _tamper(schema_raw)
    if case == "repeated-key":
        rows = json.dumps(record["repositories"])
        text = '{"schema": ' + json.dumps(record["schema"]) + ', "repositories": ' + rows
        text += ', "repositories": ' + rows + "}\n"
        return text.encode("utf-8"), schema_raw
    if case == "another-record-member":
        record["note"] = "another member"
    elif case == "missing-schema-pin":
        del record["schema"]
    elif case == "wrong-pin-digest":
        record["schema"]["sha256"] = "0" * 64
    elif case == "wrong-pin-path":
        record["schema"]["path"] = "architecture/repository-registration/another.schema.json"
    elif case == "empty-row-list":
        record["repositories"] = []
    elif case == "repeated-row":
        record["repositories"] = [row, dict(row)]
    elif case == "override-of-a-base-id":
        row["id"] = base_row["id"]
    elif case == "override-of-a-base-name":
        row["name"] = base_row["name"]
    elif case == "another-row-member":
        row["note"] = "another member"
    elif case == "unknown-dependsOn":
        row["dependsOn"] = ["no-such-repository"]
    elif case == "another-releaseSet":
        row["releaseSet"] = "INCLUDED"
    elif case == "another-kind":
        row["kind"] = "not-a-kind"
    else:
        raise AssertionError(f"unknown case {case}")
    return _json_bytes(record), schema_raw


@pytest.mark.parametrize("case", REGISTRY_REFUSALS)
def test_composed_rows_refuses_each_malformed_record(reg, safe_load, live_rows, case):
    """E8: "In `composed_rows` the schema's bytes must hash to `REGISTRY_SCHEMA_SHA256` and the record's `schema`
    member must name that path and digest; then ... each successor row in the closed row form, no override or repeat
    of an id or name, every dependsOn an earlier row, releaseSet only EXCLUDED"; E1: "its schema pin and rows only",
    "no row overrides a base id or name; no duplicate"; the vectors: "an override of a base id or name, an extra
    member, an unknown dependsOn, another releaseSet and another kind refused; the record's other members, an empty
    row list, a repeated row and a repeated key refused; a tampered schema byte, a wrong record pin and a missing pin
    refused". Operator-stated: `Refused`, message `registration registry: <detail>`."""
    record_raw, schema_raw = _registry_variant(case, live_rows[0])
    with pytest.raises(reg.Refused) as caught:
        reg.composed_rows(_live(BASE_REGISTRY), record_raw, schema_raw, safe_load)
    assert str(caught.value).startswith("registration registry:")


# ---------------------------------------------------------------- 3. E2b and placement_rows


def test_successor_placement_record_holds_its_pin_decision_and_r13_row():
    """E2b: the record "holds its schema pin, its decision `{packet: LAB-REPO-001, policy: LANG-D1, text}` ... and R13's
    placement row `{id: research-lab, name: mas-harness-research-lab, rNumber: R13, languages: [PYTHON], toolchain:
    "Python 3.12.14"}` with its two `sources`"; E8: "the record holds its schema pin, its decision (packet, policy,
    text) and its rows only" and "the record's `schema` member names them"."""
    record = json.loads(_live(SUCCESSOR_PLACEMENT))
    assert len(record) == 3 and "schema" in record
    assert record["schema"]["path"] == PLACEMENT_SCHEMA
    decision_key, rows_key = _placement_parts(record)
    decision = record[decision_key]
    assert set(decision) == {"packet", "policy", "text"}
    assert decision["packet"] == "LAB-REPO-001"
    assert decision["policy"] == "LANG-D1"
    assert isinstance(decision["text"], str) and decision["text"].strip()
    rows = record[rows_key]
    assert len(rows) == 1
    row = rows[0]
    assert set(row) == set(R13_PLACEMENT_FIELDS) | {"sources"}
    assert {key: row[key] for key in R13_PLACEMENT_FIELDS} == R13_PLACEMENT_FIELDS
    assert isinstance(row["sources"], list) and len(row["sources"]) == 2


def test_placement_schema_is_pinned_twice(reg):
    """E2b: the schema is "pinned twice: in the record's `schema` member and as `PLACEMENT_SCHEMA_SHA256` in the
    module"; both equal the schema file's sha256."""
    digest = _sha256(_live(PLACEMENT_SCHEMA))
    assert json.loads(_live(SUCCESSOR_PLACEMENT))["schema"]["sha256"] == digest
    assert reg.PLACEMENT_SCHEMA_SHA256 == digest


def test_placement_schema_is_a_closed_draft_2020_12_object():
    """E2b: "a closed Draft 2020-12 object with the checker's row and span forms" (the row form holds R13's row's
    members)."""
    schema = json.loads(_live(PLACEMENT_SCHEMA))
    assert schema.get("$schema") == DRAFT_2020_12
    assert schema.get("type") == "object"
    assert _closed(schema)
    row_members = set(R13_PLACEMENT_FIELDS) | {"sources"}
    assert any(
        isinstance(node.get("properties"), dict) and row_members <= set(node["properties"])
        for node in _dicts(schema)
    )


def test_the_placement_data_keeps_its_pinned_digest():
    """Section 3 and E11: `architecture/language-placement.json` is "byte-equal" and "the data's digest pins stay
    (condition (b): `validate_authority_map` 418 `5e4c76bd...`, `validate_met_gov_004` 406 `ec6df386...`)". Which of
    the two is the file's own sha256 the contract does not say; the file's digest must be one of them."""
    assert _sha256(_live(BASE_PLACEMENT))[:8] in {"5e4c76bd", "ec6df386"}


def test_placement_rows_at_root_are_the_datas_then_r13s(reg, live_rows, live_placement, tmp_path):
    """E8: "with it, `composed_placement_rows(base_rows, successor_raw, schema_raw)`"; the vectors:
    "`placement_rows(ROOT)` is the data's thirteen then R13's"; E11's R4: "the repositories are exactly the composed
    registry's ids and names". Operator-stated: `placement_rows(root)` returns a tuple of dicts and
    `composed_placement_rows` takes the data's row list, bytes, bytes."""
    bare = tmp_path / "data-only"
    _copy(bare, BASE_PLACEMENT)
    base = reg.placement_rows(bare)
    assert isinstance(base, tuple) and isinstance(live_placement, tuple)
    assert len(base) == 13
    assert len(live_placement) == 14
    assert live_placement[:13] == base
    record = json.loads(_live(SUCCESSOR_PLACEMENT))
    _, rows_key = _placement_parts(record)
    assert _plain(live_placement[13]) == record[rows_key][0]
    placed = {(row["id"], row["name"]) for row in live_placement}
    registered = {(row["id"], row["name"]) for row in live_rows}
    assert placed == registered
    composed = reg.composed_placement_rows(list(base), _live(SUCCESSOR_PLACEMENT), _live(PLACEMENT_SCHEMA))
    assert composed == live_placement


def test_placement_rows_without_the_record_are_the_datas_alone(reg, live_placement, tmp_path):
    """E8: "the data's rows alone without the successor placement record" under "its own base file's predicate
    (`placement_record_present`)"; the vectors: "a root without the placement record gives the thirteen"; "on the
    live tree they are present together"."""
    no_record = tmp_path / "no-placement-record"
    _copy(no_record, BASE_PLACEMENT, PLACEMENT_SCHEMA)
    assert reg.placement_record_present(no_record) is False
    assert reg.placement_rows(no_record) == live_placement[:13]
    with_record = tmp_path / "with-placement-record"
    _copy(with_record, BASE_PLACEMENT, SUCCESSOR_PLACEMENT, PLACEMENT_SCHEMA)
    assert reg.placement_record_present(with_record) is True
    assert reg.placement_rows(with_record) == live_placement
    assert reg.placement_record_present(ROOT) is True
    assert reg.record_present(ROOT) is True


@pytest.mark.parametrize("case", ("record-without-its-schema", "record-is-a-directory"))
def test_placement_rows_refuse_an_unreadable_record_or_schema(reg, tmp_path, case):
    """The vectors: "a record without its schema ... refuse" (placement); general rule: "a missing module, a mismatched
    pin or an unreadable record refuses, never degrades". Operator-stated: `Refused`, message
    `registration placement: <detail>`."""
    root = tmp_path / case
    if case == "record-without-its-schema":
        _copy(root, BASE_PLACEMENT, SUCCESSOR_PLACEMENT)
    else:
        _copy(root, BASE_PLACEMENT, PLACEMENT_SCHEMA)
        (root / SUCCESSOR_PLACEMENT).mkdir(parents=True)
    assert reg.placement_record_present(root) is True
    with pytest.raises(reg.Refused) as caught:
        reg.placement_rows(root)
    assert str(caught.value).startswith("registration placement:"), _message(caught.value, root)


def test_composed_placement_rows_accepts_the_live_record_reserialised(reg, live_placement):
    """Construction control for the placement refusal vectors below: the live record, parsed and written again by
    this file, composes to the same rows."""
    record_raw = _json_bytes(json.loads(_live(SUCCESSOR_PLACEMENT)))
    composed = reg.composed_placement_rows(list(live_placement[:13]), record_raw, _live(PLACEMENT_SCHEMA))
    assert composed == live_placement


PLACEMENT_REFUSALS = (
    "another-record-member",
    "missing-schema-pin",
    "wrong-pin-digest",
    "tampered-schema-byte",
    "decision-without-policy-and-text",
    "another-row-member",
    "repeated-row",
    "override-of-a-base-id",
    "override-of-a-base-name",
)


def _placement_variant(case: str, base_row: dict) -> tuple[bytes, bytes]:
    """The placement record's and its schema's bytes for one refusal case, built from the live bytes."""
    record = json.loads(_live(SUCCESSOR_PLACEMENT))
    schema_raw = _live(PLACEMENT_SCHEMA)
    decision_key, rows_key = _placement_parts(record)
    row = record[rows_key][0]
    if case == "tampered-schema-byte":
        return _live(SUCCESSOR_PLACEMENT), _tamper(schema_raw)
    if case == "another-record-member":
        record["note"] = "another member"
    elif case == "missing-schema-pin":
        del record["schema"]
    elif case == "wrong-pin-digest":
        record["schema"]["sha256"] = "0" * 64
    elif case == "decision-without-policy-and-text":
        record[decision_key] = {"packet": record[decision_key]["packet"]}
    elif case == "another-row-member":
        row["note"] = "another member"
    elif case == "repeated-row":
        record[rows_key] = [row, json.loads(json.dumps(row))]
    elif case == "override-of-a-base-id":
        row["id"] = base_row["id"]
    elif case == "override-of-a-base-name":
        row["name"] = base_row["name"]
    else:
        raise AssertionError(f"unknown case {case}")
    return _json_bytes(record), schema_raw


@pytest.mark.parametrize("case", PLACEMENT_REFUSALS)
def test_composed_placement_rows_refuses_each_malformed_record(reg, live_placement, case):
    """E8: "the schema's bytes hash to `PLACEMENT_SCHEMA_SHA256` and the record's `schema` member names them; the record
    holds its schema pin, its decision (packet, policy, text) and its rows only; each row in the placement row form;
    no override or repeat of an id or a name"; the vectors: "a record without its schema, a tampered schema byte, a
    wrong record pin, another member, a decision without its policy and text, another row member and an override
    refuse". Operator-stated: `Refused`, message `registration placement: <detail>`."""
    record_raw, schema_raw = _placement_variant(case, live_placement[0])
    with pytest.raises(reg.Refused) as caught:
        reg.composed_placement_rows(list(live_placement[:13]), record_raw, schema_raw)
    assert str(caught.value).startswith("registration placement:")


# ---------------------------------------------------------------- 4. E11 language placement on copied roots


def test_language_placement_with_both_records_gives_the_head_summary(tmp_path):
    """E11 (VIS-284-LPORACLE-2 (a)): "both records give the head summary" at "14 repositories and 114 spans".
    Operator-stated: the command line, the copied-root set and the first line on exit 0, as brief erratum 1, E1
    corrects it: `language placement: accepted; N repositories, ..., S spans; ...` (a comma before the span count)."""
    root = _lp_root(tmp_path, "both-records", module=True, registry_record=True, placement_record=True)
    proc = _lp_check(root)
    rc = proc.returncode
    assert rc == 0, _tail(proc, root)
    assert _lp_counts(proc, root) == (14, 114)


def test_language_placement_with_neither_record_gives_the_datas_summary(tmp_path):
    """E11: "neither gives 13 repositories and 112 spans"; section 5: "a root copied like the oracle's from the live
    bytes (no record, no module) is accepted with 13". Operator-stated: the command line and the summary line."""
    root = _lp_root(tmp_path, "neither-record", module=False, registry_record=False, placement_record=False)
    proc = _lp_check(root)
    rc = proc.returncode
    assert rc == 0, _tail(proc, root)
    assert _lp_counts(proc, root) == (13, 112)


@pytest.mark.parametrize("which", ("registry-record-alone", "placement-record-alone"))
def test_language_placement_refuses_one_successor_record_alone_at_r4(tmp_path, which):
    """E11: "A registry record without the placement record, and the reverse, are refused at R4 ("the repositories
    are exactly the composed registry's ids and names")". Operator-stated: exit 1 prints
    `refused: <rule>: <message>`."""
    root = _lp_root(
        tmp_path,
        which,
        module=True,
        registry_record=which.startswith("registry"),
        placement_record=which.startswith("placement"),
    )
    proc = _lp_check(root)
    rc = proc.returncode
    output = (proc.stdout or "") + (proc.stderr or "")
    assert rc == 1, _tail(proc, root)
    assert re.search(r"^refused: R4: ", output, re.M) is not None, _tail(proc, root)
    assert R4_TEXT in output, _tail(proc, root)


@pytest.mark.parametrize(
    ("which", "text"),
    (("registry", REGISTRY_WITHOUT_MODULE), ("placement", PLACEMENT_WITHOUT_MODULE)),
)
def test_language_placement_refuses_a_successor_record_without_the_composition_module(tmp_path, which, text):
    """E11 condition 1: a ModuleNotFoundError for the module itself is caught "to refuse ("successor registry record
    present without its composition module")" and, for `_placement`, "("successor placement record present without
    its composition module")"; general rule: "a missing module ... refuses, never degrades". Operator-stated: exit 1
    prints `refused: <rule>: <message>`."""
    root = _lp_root(
        tmp_path,
        which + "-record-without-module",
        module=False,
        registry_record=which == "registry",
        placement_record=which == "placement",
    )
    proc = _lp_check(root)
    rc = proc.returncode
    output = (proc.stdout or "") + (proc.stderr or "")
    assert rc == 1, _tail(proc, root)
    assert re.search(r"^refused: ", output, re.M) is not None, _tail(proc, root)
    assert text in output, _tail(proc, root)


# ---------------------------------------------------------------- 5. E6 the release lock


@pytest.mark.parametrize("lock", LOCKS)
def test_the_release_lock_passes_on_root(lock):
    """E6 and the meta YAML's expected evidence: "both release locks ... pass"; E6 condition 2: "13 release-set
    repositories" (E6 (ii): "the fixture covers 13"). Operator-stated: the command line, exit 0 and
    `release lock validation passed: kind=K repositories=N ...`."""
    proc = _lock_check(ROOT, lock)
    rc = proc.returncode
    assert rc == 0, _tail(proc, ROOT)
    covered = _lock_repositories(proc, ROOT)
    if lock == FIXTURE_LOCK:
        assert covered == 13


@pytest.mark.parametrize("lock", LOCKS)
def test_a_copied_root_with_the_live_record_passes_the_release_lock(tmp_path, lock):
    """Construction control for condition 1 below. Operator-stated: a copied root holding the checker, the module, the
    release-set schema, the evidence policy, the lock, the registry and the successor registry record with its schema
    is accepted; E6 (ii): "the fixture covers 13"."""
    root = _lock_root(tmp_path, "live-record", lock)
    proc = _lock_check(root, lock)
    rc = proc.returncode
    assert rc == 0, _tail(proc, root)
    covered = _lock_repositories(proc, root)
    if lock == FIXTURE_LOCK:
        assert covered == 13


@pytest.mark.parametrize("lock", LOCKS)
def test_condition_1_refuses_excluded_on_a_product_row(tmp_path, lock):
    """E6 condition 1: "before the inert-lock early return ...: over the composed rows, `releaseSet: EXCLUDED` is
    admitted only on a `kind: meta` row; on a `kind: product` row ReleaseLockError ("releaseSet EXCLUDED on a product
    repository")"; case (i): "a record whose R13 row is kind product is refused, on the synthetic fixture and on the
    inert lock". Operator-stated: a refusal prints one line `release lock validation failed: <text>` to stderr and
    exits 2."""
    record = json.loads(_live(SUCCESSOR_REGISTRY))
    record["repositories"][0]["kind"] = "product"
    root = _lock_root(tmp_path, "product-row", lock, record_bytes=_json_bytes(record))
    proc = _lock_check(root, lock)
    rc = proc.returncode
    assert rc == 2, _tail(proc, root)
    lines = (proc.stderr or "").strip().splitlines()
    assert len(lines) == 1, _tail(proc, root)
    assert lines[0].startswith("release lock validation failed: "), _tail(proc, root)
    assert CONDITION_1_TEXT in lines[0], _tail(proc, root)


# ---------------------------------------------------------------- 6. E8 R8 clause 2's successor


def test_r8_successor_record_extends_the_rule_and_names_the_module(reg):
    """E8: the successor record "`extends` `architecture/chain-product-packets/rule.json` by sha256 (`5e6e6821...`)
    and clause (`allowedNames`)" and "Its `extends` block also names the module's sha256"; section 4: rule.json
    `5e6e6821...` is byte-equal. Operator-stated: `load(record_raw, v2_rule_raw, module_raw)` returns the record."""
    record_raw = _live(R8_RECORD)
    v2_raw = _live(V2_RULE)
    module_raw = _live(MODULE)
    assert _sha256(v2_raw).startswith("5e6e6821")
    extends = json.dumps(json.loads(record_raw)["extends"])
    missing = [
        needle
        for needle in (V2_RULE, _sha256(v2_raw), "allowedNames", _sha256(module_raw))
        if needle not in extends
    ]
    assert missing == []
    assert reg.load(record_raw, v2_raw, module_raw) is not None


def test_r8_clause_2_allowed_names_split_at_slot_284(reg):
    """E8: "from slot 284, R8 clause 2's allowed names are rule.json's twelve plus `mas-harness-research-lab`; the
    refused name stays `Harness-Engineering`"; the vectors: "the name refused below slot 284 and admitted from 284".
    Operator-stated: `allowed_names(record, ext, slot)` with `ext` the parsed product-packet rule. Brief erratum 1, E2:
    `productRepository.allowedNames` is an object whose `names` member is the list of the twelve allowed names, and
    `productRepository.refusedName` is the refused name."""
    v2_raw = _live(V2_RULE)
    record = reg.load(_live(R8_RECORD), v2_raw, _live(MODULE))
    ext = json.loads(v2_raw)
    own = ext["productRepository"]["allowedNames"]["names"]
    refused = ext["productRepository"]["refusedName"]
    assert refused == "Harness-Engineering"
    assert len(own) == 12 and len(set(own)) == 12
    assert R13_NAME not in own
    assert refused not in own
    before = set(reg.allowed_names(record, ext, 283))
    assert before == set(own)
    for slot in (284, 285):
        after = set(reg.allowed_names(record, ext, slot))
        assert after == set(own) | {R13_NAME}
        assert refused not in after


@pytest.mark.parametrize("case", ("another-rule-digest", "another-module-digest"))
def test_r8_load_refuses_another_rule_or_module_digest(reg, case):
    """E8: the module "checks the record's `extends` digests"; the vectors: "another rule.json digest, another module
    digest ... refused". Operator-stated: the refusal is `Refused`."""
    v2_raw = _live(V2_RULE)
    module_raw = _live(MODULE)
    if case == "another-rule-digest":
        v2_raw = _tamper(v2_raw)
    else:
        module_raw = _tamper(module_raw)
    with pytest.raises(reg.Refused):
        reg.load(_live(R8_RECORD), v2_raw, module_raw)


# ---------------------------------------------------------------- 7. the meta YAML and the product


def test_the_meta_yaml_states_its_id_repository_product_and_commands():
    """Section 1: "The new meta is `MET-REGISTRY-001` (repository Harness-Engineering)", K = 1, "The 64 acceptance
    argv are inherited unchanged", "argv 63 is the suite itself" (section 5); section 7: "`predecessors:
    [MET-VERIFY-007]`, allowedPaths equal to the change set"; CN's YAML: `prefetchCommands: []`, every command opens
    with the offline `uv run ... python` prefix, and its one product is `task-packets/LAB-REPO-001.yaml`."""
    meta = yaml.safe_load(_live(META_YAML))
    assert meta["id"] == "MET-REGISTRY-001"
    assert meta["repository"] == "Harness-Engineering"
    assert meta["predecessors"] == ["MET-VERIFY-007"]
    assert meta["prefetchCommands"] == []
    commands = meta["offlineAcceptanceCommands"]
    assert len(commands) == 64
    assert all(command[:6] == UV_PREFIX for command in commands)
    assert commands[62][6:9] == ["-m", "pytest", "tests"]
    allowed = meta["allowedPaths"]
    packets = sorted(path for path in allowed if path.startswith("task-packets/") and path.endswith(".yaml"))
    assert packets == [PRODUCT_YAML, META_YAML]
    new_files = (
        SUCCESSOR_REGISTRY,
        REGISTRY_SCHEMA,
        SUCCESSOR_PLACEMENT,
        PLACEMENT_SCHEMA,
        R8_RECORD,
        MODULE,
        PLAN_13,
    )
    missing = [path for path in new_files if path not in allowed]
    assert missing == []


def test_the_meta_yaml_leaves_the_frozen_files_out_of_its_change_set():
    """Section 3: the byte-equal files (the registry, its schema and all of `schemas/`, the three release files, the
    old release-lock test, the placement data and ADR 0010) and "Not edited: `chain_identity_v2.py`,
    `chain_identity_v3.py`, `architecture/chain-product-packets/**`, `architecture/chain-inheritance/**`"; section 7:
    allowedPaths equal the change set."""
    allowed = yaml.safe_load(_live(META_YAML))["allowedPaths"]
    touched = [
        path
        for path in allowed
        if path in FROZEN
        or path.startswith(("schemas/", "architecture/chain-product-packets/", "architecture/chain-inheritance/"))
        or os.path.basename(path) in {"chain_identity_v2.py", "chain_identity_v3.py"}
    ]
    assert touched == []


def test_the_product_packet_is_the_frozen_draft():
    """Section 2: "The lines between section A's fences, byte for byte: sha256
    `8ae5c7fd1efbf8a7b3d38881030184dc13bbc19ec080cd44748d6636740ebf9e`, 20,123 B"."""
    raw = _live(PRODUCT_YAML)
    assert _sha256(raw) == "8ae5c7fd1efbf8a7b3d38881030184dc13bbc19ec080cd44748d6636740ebf9e"
    assert len(raw) == 20123


def test_r13_plan_is_section_bs_fenced_plan():
    """Section 2: "`docs/repositories/13-mas-harness-research-lab.md` = section B's fenced plan, byte for byte (sha256
    `bc19f6a5...`, 92 lines)"."""
    raw = _live(PLAN_13)
    assert _sha256(raw).startswith("bc19f6a5")
    assert len(raw.decode("utf-8").splitlines()) == 92
