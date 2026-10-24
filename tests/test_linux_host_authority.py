"""MET-LINUX-008 (LINUX-HOST-AUTH-001), candidate tests: the Linux host-authority contract's four records and five
schemas against the offline checker, every span re-derived here from the cited bytes independently of the checker, the
restated LAB-RUNPLAN-001 parse rules compared with that checker, and every vector replayed as recorded."""
import ast
import hashlib
import json
import re
import subprocess
import sys
from pathlib import Path

import pytest

from scripts import lab_run_plan as lrp
from scripts import linux_host_authority as lha

ROOT = Path(__file__).resolve().parents[1]
HERE = ROOT / "architecture/linux-host-authority"
RECORDS = {"authority": "host-authority.json", "recipe": "host-recipe.json", "launcher": "launcher-install.json",
           "custody": "custody-model.json"}
SCHEMAS = ["host-authority.schema.json", "host-recipe.schema.json", "launcher-install.schema.json",
           "custody-model.schema.json", "drop-manifest.schema.json"]
CONTRACT_FILES = sorted(["README.md", "vectors.json"] + list(RECORDS.values()) + SCHEMAS)
SPAN_SECTIONS = ("supersedes", "satisfied", "unchanged", "costScope", "reviewedNotBinding")
BUILD_RULES = ["B-LHA-%d" % n for n in (1, 2, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18)]


def _load(name):
    return lha.parse((HERE / name).read_bytes())


def _span_entries(authority):
    entries = [e for section in SPAN_SECTIONS for e in authority[section]]
    entries += [o for reading in authority["readings"] for o in reading["occurrences"]]
    entries += [authority["evidence"]["freshness"], authority["decisions"]["metLinux007"],
                authority["consumers"]["beforeLiveLauncher"]["quote"]]
    return entries


def test_the_contract_directory_holds_exactly_the_candidate_files():
    assert sorted(p.name for p in HERE.iterdir()) == CONTRACT_FILES


def test_the_published_records_are_accepted():
    lha.check_set(lha.load_records(), lha.load_schemas(), lha.Base(ROOT))


def test_every_vector_is_replayed_as_recorded():
    counts = lha.replay(_load("vectors.json"), lha.load_schemas(), lha.load_records(), lha.Base(ROOT))
    assert counts == {"positives": 4, "authority": 32, "recipe": 101, "launcher": 37, "custody": 33, "drop": 9,
                      "signature": 3, "parse": 8}


def test_the_command_line_replays_from_the_repository_root():
    run = subprocess.run([sys.executable, "-I", "-B", "scripts/linux_host_authority.py", "replay"], cwd=ROOT,
                         capture_output=True, text=True, timeout=100)
    assert run.returncode == 0, run.stdout + run.stderr
    assert "each refused as recorded" in run.stdout
    assert subprocess.run([sys.executable, "-I", "-B", "scripts/linux_host_authority.py"], cwd=ROOT,
                          capture_output=True, text=True, timeout=100).returncode == 2


@pytest.mark.parametrize("name", SCHEMAS)
def test_each_schema_is_a_closed_draft_2020_12_schema(name):
    schema = _load(name)
    assert schema["$schema"] == "https://json-schema.org/draft/2020-12/schema"

    def walk(node, where):
        assert set(node) - {"$schema"} <= lha.SCHEMA_KEYWORDS, where
        if node.get("type") == "object":
            assert node["additionalProperties"] is False and set(node["required"]) == set(node["properties"]), where
            for key, sub in node["properties"].items():
                walk(sub, where + "." + key)
        if "items" in node:
            walk(node["items"], where + "[]")

    walk(schema, name)


def test_every_span_is_rederived_here_from_the_cited_bytes():
    """An independent restatement of design section 4's digest rule, not the checker's code path."""
    authority = _load(RECORDS["authority"])
    entries = _span_entries(authority)
    assert len(entries) == len({e["id"] for e in entries}) == 64
    for entry in entries:
        raw = (ROOT / entry["path"]).read_bytes()
        assert hashlib.sha256(raw).hexdigest() == entry["fileSha256"], entry["id"]
        lines = raw.decode("utf-8").split("\n")
        starts, offset = [], 0
        for line in lines:
            starts.append(offset)
            offset += len(line.encode("utf-8")) + 1
        parts = []
        for start_line, start_byte, end_line, end_byte in entry["fragments"]:
            assert entry["lines"][0] <= start_line <= end_line <= entry["lines"][1], entry["id"]
            parts.append(raw[starts[start_line - 1] + start_byte:starts[end_line - 1] + end_byte])
        assert entry["text"] == " … ".join(p.decode("utf-8") for p in parts), entry["id"]
        assert entry["span"] == hashlib.sha256(b"".join(p + b"\x00" for p in parts)).hexdigest(), entry["id"]


def test_the_relaxed_predicates_are_the_capacity_predicates_and_the_independence_clause():
    authority = _load(RECORDS["authority"])
    kinds = {e["id"]: e["kind"] for e in authority["supersedes"]}
    assert set(kinds.values()) == {"CAPACITY", "INDEPENDENCE"}
    assert sorted(k for k, v in kinds.items() if v == "INDEPENDENCE") == [
        "LR-EXISTING-INDEPENDENT", "LR-INDEPENDENT-SIGNERS", "LRJ-INDEPENDENT-SIGNATURES"]
    kept = {e["id"] for e in authority["unchanged"]}
    assert all(set(e["keptIn"]) <= kept for e in authority["supersedes"])


def test_the_restated_parse_and_schema_rules_are_lab_runplan_001s():
    assert lha.SCHEMA_KEYWORDS == lrp.SCHEMA_KEYWORDS and lha.KEYWORD_RULES == lrp.KEYWORD_RULES
    assert lha.TYPES == lrp.TYPES and lha.INTEGER_LIMIT == lrp.INTEGER_LIMIT
    assert [p.pattern for p in lha.FORBIDDEN_TEXT] == [p.pattern for p in lrp.FORBIDDEN_TEXT]
    lab_vectors = lrp.strict((ROOT / "architecture/lab-run-plan/vectors.json").read_bytes())
    for row in lab_vectors["parseNegatives"]:
        raw = row["raw"].encode("utf-8")
        assert lha.explain(lha.strict, raw) == lrp.explain(lrp.strict, raw) == row["refusal"], row["id"]
    value = {"b": [1, "…"], "a": {"c": None}}
    assert lha.canonical(value) == lrp.canonical(value)


def test_every_number_is_an_integer():
    for name in list(RECORDS.values()) + SCHEMAS + ["vectors.json"]:
        lha.integers_only(_load(name))
    with pytest.raises(ValueError, match="a non-integral number is refused"):
        lha.parse(b'{"a": 0.5}')


def test_every_binding_build_rule_has_a_vector():
    vectors = _load("vectors.json")
    rules = " ".join([row["rule"] for row in vectors["negatives"]] + [row["rule"] for row in
                     vectors["dropManifests"]["negatives"] + vectors["dropManifests"]["signatures"]])
    for rule in BUILD_RULES:
        assert re.search(re.escape(rule) + r"(?![0-9])", rules), rule
    assert "B-LHA-3" not in re.findall(r"B-LHA-[0-9]+", rules)


def test_every_negative_is_refused_for_its_recorded_reason_only():
    vectors = _load("vectors.json")
    ids = [row["id"] for row in vectors["negatives"]]
    assert len(ids) == len(set(ids))
    assert all(row["refusal"] and row["intent"] and row["ops"] for row in vectors["negatives"])


def test_role_labels_only_in_every_record():
    recipe = _load(RECORDS["recipe"])
    assert recipe["roleLabels"]["administeringIdentity"] == "OWNER_ADMIN"
    assert recipe["roleLabels"]["loginIdentity"] == "OWNER_LOGIN"
    assert recipe["roleLabels"]["loginBaselineRole"] == "OWNER_LOGIN_BASELINE"
    for name in RECORDS.values():
        document = _load(name)
        lha.free_text(document)
        lha.named_text(document)
    with pytest.raises(ValueError, match="never its full name"):
        lha.named_text({"role": "projects/example-run-0001/roles/ownerLoginBaseline"})


def test_the_carried_notes_are_notes_not_settled_claims():
    for name, note_id in (("authority", "LHA-CN-1"), ("custody", "LHA-CN-2")):
        notes = _load(RECORDS[name])["carriedNotes"]
        assert [n["id"] for n in notes] == [note_id]
        assert notes[0]["status"] == "CARRIED_NOTE_NOT_SETTLED"


def test_a_drop_manifest_signature_never_verifies_as_another_signature():
    raw = b'{"schemaVersion":"planeon.internal.linux-drop-manifest/v1"}'
    payloads = {kind: lha.signature_payload(kind, raw) for kind in ("drop", "manifest", "policy")}
    assert len(set(payloads.values())) == 3
    assert payloads["drop"].startswith(b"planeon.internal.linux-drop-manifest/v1\x00")


@pytest.mark.parametrize("name", CONTRACT_FILES)
def test_no_contract_file_carries_a_local_path_or_an_address(name):
    text = (HERE / name).read_text(encoding="utf-8")
    assert not re.search(r"(?<![A-Za-z0-9_.~-])/(?:Users|home|private|root)/", text)
    assert not re.search(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}", text)


def test_the_checker_imports_only_the_standard_library():
    tree = ast.parse((ROOT / "scripts/linux_host_authority.py").read_text(encoding="utf-8"))
    names = {alias.name.split(".")[0] for node in ast.walk(tree) if isinstance(node, ast.Import) for alias in node.names}
    names |= {node.module.split(".")[0] for node in ast.walk(tree) if isinstance(node, ast.ImportFrom)}
    assert names <= {"__future__", "datetime", "hashlib", "json", "math", "re", "sys", "pathlib", "typing"}


def test_the_pinned_digests_are_bound_to_the_records():
    authority = _load(RECORDS["authority"])
    assert list(lha.PINNED["supersedes"]) == [e["id"] for e in authority["supersedes"]]
    assert list(lha.DECISION_SHA256) == [d["id"] for d in authority["decisions"]["decisionLines"]]
    for decision in authority["decisions"]["decisionLines"]:
        assert hashlib.sha256(decision["text"].encode("utf-8")).hexdigest() == lha.DECISION_SHA256[decision["id"]]


def test_the_base_commit_is_recorded():
    assert _load(RECORDS["authority"])["baseCommit"] == lha.BASE_COMMIT
    assert json.loads((HERE / RECORDS["recipe"]).read_text(encoding="utf-8"))["packet"] == "MET-LINUX-008"
