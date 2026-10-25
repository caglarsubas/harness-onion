"""MET-LINUX-008 (LINUX-HOST-AUTH-001), candidate tests: the Linux host-authority contract's four records and five
schemas against the offline checker, every span re-derived here from the cited bytes independently of the checker, the
restated LAB-RUNPLAN-001 parse rules compared with that checker, every vector replayed as recorded, and candidate c7's
exhaustive leaf audit, closed id-keyed lists and B-LHA-7 statement (MON-LHA-C7-SYSTEMATIC)."""
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
# The candidate's own files, and the contract directory with the D5a oracle's identity (design section 3), which a
# separate agent writes and this test only names.
CANDIDATE_FILES = sorted(["README.md", "vectors.json"] + list(RECORDS.values()) + SCHEMAS)
# Adoption (MON-LHA-C8-ADOPTED) adds the status and the three CONTRACT round records with their identities.
ADOPTION_FILES = ["status.json"] + ["review-round%d.json" % n for n in (1, 2, 3)] + [
    "review-identity-round%d.json" % n for n in (1, 2, 3)]
CONTRACT_FILES = sorted(CANDIDATE_FILES + ["oracle-identity.json"] + ADOPTION_FILES)
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
    assert counts == {"positives": 4, "authority": 37, "recipe": 119, "launcher": 52, "custody": 62, "leaf": 2043,
                      "drop": 11, "signature": 3, "parse": 8}


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
    assert len(entries) == len({e["id"] for e in entries}) == 65
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


def test_each_reading_covers_its_named_forms_in_the_superseded_kept_and_satisfied_texts():
    """Design section 4, B-LHA-11 and MON-LHA-ORC-2-A: a reading covers its named forms in every superseded, kept and
    satisfied text. Restated here over the cited bytes: pre-existing or preexisting in any case and "existing operator"
    are PRE_EXISTING's; EXISTING_ of evidence.signingAuthority and line 147's "existing independent PLATFORM_RELEASE"
    are SIGNING_AUTHORITY's. "Existing ... capacity" is in neither."""
    authority = _load(RECORDS["authority"])
    listed = {}
    for reading in authority["readings"]:
        for o in reading["occurrences"]:
            for start_line, start_byte, end_line, end_byte in o["fragments"]:
                assert start_line == end_line, o["id"]
                listed.setdefault((reading["id"], o["path"], start_line), []).append((start_byte, end_byte, o["id"]))
    forms = [("PRE_EXISTING", rb"(?i)(pre-?existing)"), ("PRE_EXISTING", rb"(?i)(existing)(?=\s+operator\b)"),
             ("SIGNING_AUTHORITY", rb"(EXISTING)(?=_PLATFORM_RELEASE_TENANT_LIVE_EXECUTION_AND_CAPACITY_OPERATOR)"),
             ("SIGNING_AUTHORITY", rb"(?i)(existing)(?=\s+independent\s+PLATFORM_RELEASE\b)")]
    found = []
    for section in ("supersedes", "unchanged", "satisfied"):
        for entry in authority[section]:
            lines = (ROOT / entry["path"]).read_bytes().split(b"\n")
            for start_line, start_byte, end_line, end_byte in entry["fragments"]:
                for number in range(start_line, end_line + 1):
                    start = start_byte if number == start_line else 0
                    end = end_byte if number == end_line else len(lines[number - 1])
                    for reading_id, form in forms:
                        for match in re.finditer(form, lines[number - 1]):
                            at, to = match.span(1)
                            if start <= at and to <= end:
                                hits = [oid for s, e, oid in listed.get((reading_id, entry["path"], number), [])
                                        if s <= at and to <= e]
                                assert hits, (entry["id"], number, reading_id)
                                found.append((reading_id, hits[0]))
    assert sorted(found) == [("PRE_EXISTING", "LRJ-BILLING-CAPACITY-PREEXISTING"), ("SIGNING_AUTHORITY", "LR-147-EXISTING")]
    occurrences = {o["id"] for reading in authority["readings"] for o in reading["occurrences"]}
    assert not occurrences & {"LR-CAPACITY-ZERO-COST-EXISTING", "REP-ZERO-COST-CAPACITY-EXISTING"}


def test_the_drop_manifest_targets_are_exactly_the_fixed_list():
    schema = _load("drop-manifest.schema.json")
    launcher = _load(RECORDS["launcher"])
    paths = [t["path"] for t in launcher["signedDropInstaller"]["fixedTargets"]]
    assert schema["properties"]["files"]["items"]["properties"]["target"] == {"enum": paths}
    assert not any(part in ("", ".", "..") for p in paths for part in p[len("/etc/planeon/"):].split("/"))
    document = _load("vectors.json")["dropManifests"]["positives"][0]["document"]
    document["files"][0]["target"] = "/etc/planeon/credentials/../harness-runner-manifest.json"
    refusal = lha.explain(lha.check_drop, document, lha.load_schemas()["drop"], launcher)
    assert refusal == "schema $.files[0].target enum"


def test_every_schema_pattern_refuses_a_trailing_line_feed_by_search_too():
    """LHA-C1-5: each pattern ends with (?![\\s\\S]), so a validator that applies it by search (Python's jsonschema,
    where $ also matches before a final line feed) refuses a trailing line feed as the model's full match does."""
    patterns = []

    def walk(node):
        if isinstance(node, dict):
            if "pattern" in node:
                patterns.append(node["pattern"])
            for value in node.values():
                walk(value)
        elif isinstance(node, list):
            for value in node:
                walk(value)

    for name in SCHEMAS:
        walk(_load(name))
    assert patterns and all(p.startswith("^") and p.endswith("(?![\\s\\S])") for p in patterns)
    hex64 = _load("drop-manifest.schema.json")["properties"]["planSha256"]["pattern"]
    assert re.search(hex64, "1" * 64) and not re.search(hex64, "1" * 64 + "\n")


def test_the_named_forms_loop_refuses_an_unlisted_occurrence_on_its_own(monkeypatch):
    """LHA-C1-7: with the occurrence removed from both the record and the pinned table, the pin check passes and the
    named-forms coverage loop itself refuses."""
    authority = _load(RECORDS["authority"])
    pre = authority["readings"][1]["occurrences"]
    pre[:] = [o for o in pre if o["id"] != "LRJ-BILLING-CAPACITY-PREEXISTING"]
    pinned = dict(lha.PINNED)
    pinned["occurrences"] = {k: v for k, v in lha.PINNED["occurrences"].items()
                             if k != "LRJ-BILLING-CAPACITY-PREEXISTING"}
    monkeypatch.setattr(lha, "PINNED", pinned)
    refusal = lha.explain(lha.check_authority, authority, lha.load_schemas()["authority"], lha.Base(ROOT))
    assert refusal == ("a reading covers its named forms in every superseded, kept and satisfied text, each listed in "
                       "that reading with its span")


def test_explain_names_an_unexpected_error_as_a_refusal():
    assert lha.explain(lambda: {}["missing"]) == "KeyError"
    assert lha.explain(lambda: None + 1) == "TypeError"
    assert lha.explain(lambda: [][0]) == "IndexError"
    assert lha.explain(lambda: (ROOT / "no-such-file").read_bytes()) == "FileNotFoundError"
    assert lha.explain(lambda: None) is None


def test_the_command_line_refuses_the_same_error_classes_as_explain():
    """LHA-C2-4: main() runs the command through explain() and has no handler of its own, so an IndexError on the
    command line is refused by name, as every class explain() names is."""
    assert lha.REFUSED_ERRORS == (ValueError, OSError, KeyError, TypeError, IndexError, RecursionError)
    tree = ast.parse((ROOT / "scripts/linux_host_authority.py").read_text(encoding="utf-8"))
    main = [node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name == "main"][0]
    calls = [node.func.id for node in ast.walk(main) if isinstance(node, ast.Call) and isinstance(node.func, ast.Name)]
    assert "explain" in calls and not any(isinstance(node, ast.Try) for node in ast.walk(main))
    assert lha.explain(lha._command, ["check"], {}) is None


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


@pytest.mark.parametrize("name", CANDIDATE_FILES)
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


def _generalised_leaves(kind, doc):
    """Restated here: a leaf is a scalar, an empty list or an empty object; its path joins keys with '.' and writes a
    list index as the entry's id where the list is id-keyed, [*] otherwise."""
    out = []

    def walk(value, path, shape):
        if isinstance(value, dict):
            if not value:
                out.append(path)
            for key, item in value.items():
                walk(item, path + "." + key if path else key, shape + "." + key if shape else key)
        elif isinstance(value, list):
            if not value:
                out.append(path)
            key = lha.ID_KEYED[kind].get(shape)
            for item in value:
                walk(item, path + "[%s]" % (item[key] if key else "*"), shape + "[*]")
        else:
            out.append(path)

    walk(doc, "", "")
    return list(dict.fromkeys(out))


def test_every_leaf_is_pinned_left_to_its_sha256_check_or_structure_only():
    """MON-LHA-C7-SYSTEMATIC (ii): the leaf audit is exhaustive. Each generalised leaf of each record is in exactly one
    of the pins, the texts an explicit sha256 check fixes, and the structure-only leaves (image.family alone)."""
    for kind, name in RECORDS.items():
        leaves = _generalised_leaves(kind, _load(name))
        pinned = [path for pins in lha.LEAF_PINS[kind].values() for path, _ in pins]
        listed = pinned + lha.LEAF_EXPLICIT[kind] + lha.LEAF_STRUCTURE_ONLY[kind]
        assert len(listed) == len(set(listed)) and set(listed) == set(leaves), kind
    assert lha.LEAF_STRUCTURE_ONLY == {"authority": [], "recipe": ["image.family"], "launcher": [], "custody": []}


def test_each_decision_carrying_leaf_has_its_refusal_vector():
    vectors = _load("vectors.json")
    covered = [(row["target"], row["leaf"]) for row in vectors["leafVectors"]]
    expected = [(kind, path) for kind in RECORDS for pins in lha.LEAF_PINS[kind].values() for path, _ in pins]
    expected += [(kind, path) for kind in RECORDS for path in lha.LEAF_EXPLICIT[kind]]
    assert len(covered) == len(set(covered)) and set(covered) == set(expected)
    assert all(row["refusal"] and row["rule"] for row in vectors["leafVectors"])


def test_a_repeated_id_is_refused_in_each_record():
    """LHA-C2-2: a wrong entry followed by a correct copy with the same id is refused by a named rule in every record,
    and so is a third trigger unit."""
    vectors = _load("vectors.json")
    assert {row["target"] for row in vectors["negatives"] if row["intent"].startswith("a repeated id")} == set(RECORDS)
    third = [row["refusal"] for row in vectors["negatives"] if row["intent"].startswith("a third trigger unit")]
    assert third == ["an id-keyed list names each entry once: launcher-install.json triggerUnits, by id"]


def test_b_lha_7_is_stated_and_enforced_both_ways():
    custody = _load(RECORDS["custody"])
    proxies = custody["endpointServerIdentities"][:2]
    assert [e["kind"] for e in proxies] == ["KUBERNETES_API_PROXY", "CAMPAIGN_PROXY"]
    assert len({e["identity"] for e in proxies}) == 1 and all(e["servesBothProxyKinds"] for e in proxies)
    assert custody["sharedProxyServerIdentity"] == {"identity": proxies[0]["identity"],
                                                    "servesKinds": ["KUBERNETES_API_PROXY", "CAMPAIGN_PROXY"],
                                                    "rule": "B-LHA-7"}
    schemas, records = lha.load_schemas(), lha.load_records()
    unflagged = json.loads(json.dumps(records))
    unflagged["custody"]["endpointServerIdentities"][1]["servesBothProxyKinds"] = False
    assert lha.explain(lha.check_set, unflagged, schemas, lha.Base(ROOT)).startswith("one server identity serves both")
    unshared = json.loads(json.dumps(records))
    unshared["custody"]["endpointServerIdentities"][0]["identity"] = "CAMPAIGN_PROXY_CLIENT_MTLS"
    assert lha.explain(lha.check_set, unshared, schemas, lha.Base(ROOT)) == ("if one server identity serves both proxy "
                                                                             "kinds, the record says so")


def test_the_status_line_names_the_current_candidate():
    """LHA-C2-3: the README's status line names the adopted candidate (MON-LHA-C8-ADOPTED)."""
    assert "**ADOPTED** (candidate c8," in (HERE / "README.md").read_text(encoding="utf-8").split("\n")[2]
