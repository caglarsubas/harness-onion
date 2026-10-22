"""REVIEW-RECORD-V2, the review record v2 contract candidate: the reference model replays every vector; the four schemas
state the model's closed member sets, with kind and agentIds as plain strings (B-6) and the operator fixed to
LANE_SESSION (B-10); the registry and the frozen list load; `check_tree` judges synthetic trees for every tree code;
the checks take a file's bytes, never a parsed object; and privacy is matched by digest only."""
import hashlib
import json
from pathlib import Path

import pytest

from scripts import evolution_surface as es
from scripts import review_record as rr

ROOT = Path(__file__).resolve().parents[1]
HERE = ROOT / "architecture/review-record"
VECTORS = json.loads((HERE / "vectors.json").read_bytes())
BASES = VECTORS["bases"]
REGISTRY = rr.load_registry(BASES["registry"])
SCHEMAS = {name: json.loads((ROOT / "schemas" / ("%s.schema.json" % name)).read_bytes())
           for name in ("review-record", "review-identity", "oracle-identity", "review-briefs")}


def test_every_vector_replays():
    counts = rr.replay(VECTORS)
    assert counts == {"reviews": 62, "series": 10, "oracles": 10, "prOracles": 5, "merges": 13, "registries": 13,
                      "legacy": 7, "trees": 16, "privacy": 5}


def test_the_tree_vectors_reach_every_tree_code_and_the_tree_rules():
    reached = {row["expect"] for row in VECTORS["trees"]} - {None}
    assert set(rr.TREE_CODES) <= reached
    assert reached == {"LEGACY_CHANGED", "NO_IDENTITY", "ORACLE_MISSING", "ORACLE_DIGEST", "SHAPE", "SERIES_FORK",
                       "PRIVACY"}


def test_the_schemas_accept_each_model_only_shape_case():
    # RR2C1-3: the README lists what the model refuses as SHAPE beyond the schemas; each such row is pinned here.
    jsonschema = pytest.importorskip("jsonschema")
    rows = [row for row in VECTORS["reviews"] if row.get("modelOnly")]
    assert len(rows) == 4
    record_v = jsonschema.Draft202012Validator(SCHEMAS["review-record"])
    identity_v = jsonschema.Draft202012Validator(SCHEMAS["review-identity"])
    for row in rows:
        record = rr.mutate(BASES["record"], row["record"]["mutate"])
        identity = rr.mutate(BASES["identity"], row["identity"]["mutate"])
        identity["record"] = {"path": row["recordPath"], "sha256": rr.file_sha256(rr.serialize(record))}
        assert record_v.is_valid(json.loads(json.dumps(record))), row["id"]
        assert identity_v.is_valid(json.loads(json.dumps(identity))), row["id"]
        assert row["expect"] == "SHAPE"


def test_the_schemas_reject_each_schema_agrees_case_as_the_model_does():
    # RR2C2-2: year 0000 and integers of 2^53 are refused by the schemas and the model alike.
    jsonschema = pytest.importorskip("jsonschema")
    reviews = [row for row in VECTORS["reviews"] if row.get("schemaAgrees")]
    registries = [row for row in VECTORS["registries"] if row.get("schemaAgrees")]
    assert len(reviews) == 2 and len(registries) == 1
    record_v = jsonschema.Draft202012Validator(SCHEMAS["review-record"])
    identity_v = jsonschema.Draft202012Validator(SCHEMAS["review-identity"])
    briefs_v = jsonschema.Draft202012Validator(SCHEMAS["review-briefs"])
    for row in reviews:
        record = rr.mutate(BASES["record"], row["record"]["mutate"])
        identity = rr.mutate(BASES["identity"], row["identity"]["mutate"])
        identity["record"] = {"path": row["recordPath"], "sha256": rr.file_sha256(rr.serialize(record))}
        assert not (record_v.is_valid(record) and identity_v.is_valid(identity)), row["id"]
        assert row["expect"] == "SHAPE"
    for row in registries:
        assert not briefs_v.is_valid(rr.mutate(BASES["registry"], row["mutate"])), row["id"]
        assert row["expect"] == "SHAPE"


def test_the_published_registry_pins_each_current_brief_by_its_file_bytes():
    # RR2C1 NOTE 12: the latest version of each chain matches the file at its path; a superseded version keeps its own.
    registry = rr.load_registry((HERE / "briefs.json").read_bytes())
    latest = [b for b in registry["briefs"] if "supersededAt" not in b]
    assert latest
    for b in latest:
        assert rr.file_sha256((ROOT / b["path"]).read_bytes()) == b["sha256"], b["path"]


def test_the_review_codes_are_in_b6s_order():
    assert rr.REVIEW_CODES == ("NO_IDENTITY", "NO_BRIEF_DIGEST", "SHAPE", "UNKNOWN_KIND", "BINDING", "PLACEHOLDER_ID",
                               "NOT_INDEPENDENT", "IDENTITY_MISMATCH", "SUBJECT_FORM", "SUBJECT_REPOSITORY",
                               "BRIEF_NOT_FOR_SERIES", "BRIEF_SUPERSEDED", "VERDICT", "RULING", "SUBJECT_MISMATCH",
                               "PRIVACY")
    assert rr.SERIES_CODES == ("DUPLICATE_ROUND", "SERIES_GAP", "SERIES_FORK", "DUPLICATE_IDENTITY")
    reached = {row["expect"] for row in VECTORS["reviews"]} - {None}
    assert reached == set(rr.REVIEW_CODES)
    series_codes = {row["expect"] for row in VECTORS["series"]} - {None}
    # Every series code is reached; a series row may also stop at a round's own code (one identity for two records).
    assert set(rr.SERIES_CODES) <= series_codes <= set(rr.SERIES_CODES) | set(rr.REVIEW_CODES)


@pytest.mark.parametrize("name,schema,required,optional", [
    ("review-record", rr.RECORD_SCHEMA, rr.RECORD_REQUIRED, rr.RECORD_OPTIONAL),
    ("review-identity", rr.IDENTITY_SCHEMA, rr.IDENTITY_REQUIRED, rr.IDENTITY_OPTIONAL),
    ("oracle-identity", rr.ORACLE_SCHEMA, rr.ORACLE_REQUIRED, rr.ORACLE_OPTIONAL),
])
def test_each_schema_states_the_models_closed_members(name, schema, required, optional):
    doc = SCHEMAS[name]
    assert doc["$id"] == schema and doc["additionalProperties"] is False
    assert doc["properties"]["schemaVersion"] == {"const": schema}
    assert sorted(doc["required"]) == sorted(required)
    assert set(doc["properties"]) == set(required) | set(optional)


def test_kind_and_agent_ids_are_plain_strings_and_the_operator_is_the_lane_session():
    plain = {"type": "string", "maxLength": 4000}
    record, identity, oracle = SCHEMAS["review-record"], SCHEMAS["review-identity"], SCHEMAS["oracle-identity"]
    assert record["properties"]["kind"] == plain
    assert identity["properties"]["reviewer"]["properties"]["agentId"] == plain
    assert identity["properties"]["author"]["properties"]["agentIds"]["items"] == plain
    assert oracle["properties"]["oracle"]["properties"]["agentId"] == plain
    for doc in (identity, oracle):
        operator = doc["properties"]["operator"]
        assert operator["properties"]["role"] == {"const": "LANE_SESSION"}
        assert operator["properties"]["agentId"] == plain


def test_the_registry_schema_lists_the_four_kinds():
    briefs = SCHEMAS["review-briefs"]
    assert sorted(briefs["properties"]["kinds"]["required"]) == sorted(rr.KINDS)
    assert briefs["properties"]["briefs"]["items"]["properties"]["kind"] == {"enum": list(rr.KINDS)}


def test_the_published_registry_and_frozen_list_load():
    registry = rr.load_registry((HERE / "briefs.json").read_bytes())
    assert set(registry["kinds"]) == set(rr.KINDS)
    legacy = rr.load_legacy((HERE / "legacy-review-records.json").read_bytes())
    assert all(e["path"].endswith(".json") for e in legacy["entries"])
    assert all(rr._is_oracle_test(e["path"]) for e in legacy["oracleTests"])


def test_the_oracle_class_is_the_evolution_surface_records():
    record = es.load((ROOT / "architecture/evolution-surface/evolution-surface.json").read_bytes())
    cls = next(c for c in record["levels"]["programme"]["classes"] if c["id"] == "ORACLE_TESTS")
    assert cls["paths"] == [{"under": rr.ORACLE_TESTS[0], "name": rr.ORACLE_TESTS[1]}]


def test_a_check_takes_bytes_and_a_path_never_a_parsed_object():
    record = rr.serialize(BASES["record"])
    identity = json.loads(json.dumps(BASES["identity"]))
    identity["record"] = {"path": "architecture/x/review-round1.json", "sha256": rr.file_sha256(record)}
    with pytest.raises(rr.Refused) as refused:
        rr.check_review(BASES["record"], "architecture/x/review-round1.json", rr.serialize(identity), None, REGISTRY)
    assert refused.value.code == "SHAPE"
    facts = rr.check_review(record, "architecture/x/review-round1.json", rr.serialize(identity), None, REGISTRY)
    assert facts == {"kind": "CONTRACT", "series": "EXAMPLE-001/contract", "round": 1, "verdict": "PASS_FOR_ADOPTION",
                     "passing": True, "headBound": False, "decision": "NONE_NEEDED", "full": True}


def test_the_binding_is_the_file_byte_sha256():
    record = rr.serialize(BASES["record"])
    reindented = json.dumps(BASES["record"], indent=2).encode("utf-8") + b"\n"
    assert rr.file_sha256(record) != rr.file_sha256(reindented)
    identity = json.loads(json.dumps(BASES["identity"]))
    identity["record"] = {"path": "architecture/x/review-round1.json", "sha256": rr.file_sha256(record)}
    with pytest.raises(rr.Refused) as refused:
        rr.check_review(reindented, "architecture/x/review-round1.json", rr.serialize(identity), None, REGISTRY)
    assert refused.value.code == "BINDING"


def test_privacy_matches_the_legacy_term_by_digest_prefix_only(monkeypatch):
    word = "zyxwvut"
    assert rr.privacy_hits("a " + word + " b")["legacyTerm"] == 0
    monkeypatch.setattr(rr, "LEGACY_TERM_PREFIX", hashlib.sha256(word.encode("ascii")).hexdigest()[:16])
    assert rr.privacy_hits("a " + word + " b")["legacyTerm"] == 1
    assert rr.privacy_hits("a " + word + "s b")["legacyTerm"] == 0  # a run of eight letters is not the term


def test_the_published_name_token_table_is_empty_and_filled_only_by_the_local_loader(tmp_path):
    # Owner Q-RR2-NAMES ("Load hashes locally"): no token digest is published; local scans load them from a file.
    assert rr.NAME_TOKEN_SHA256 == {}
    word = "qzvkwy"
    assert rr.privacy_hits("a " + word + " b")["names"] == 0
    local = tmp_path / "tokens.json"
    local.write_bytes(json.dumps({"6": [hashlib.sha256(word.encode("ascii")).hexdigest()]}).encode("ascii"))
    try:
        assert rr.load_name_tokens(local) == 1
        assert rr.privacy_hits("a " + word.upper() + " b")["names"] == 1
        for bad in (b"[]", b'{"6": []}', b'{"0": ["%s"]}' % (b"0" * 64), b'{"6": ["ABC"]}'):
            local.write_bytes(bad)
            with pytest.raises(rr.Refused):
                rr.load_name_tokens(local)
        assert rr.privacy_hits(word)["names"] == 1  # a refused file leaves the table as it was
    finally:
        rr.NAME_TOKEN_SHA256 = {}


def _string_lists(value):
    if isinstance(value, dict):
        for item in value.values():
            yield from _string_lists(item)
    elif isinstance(value, list):
        if value and all(isinstance(item, str) for item in value):
            yield "".join(value)
        for item in value:
            yield from _string_lists(item)


def test_no_vector_parts_join_into_a_published_privacy_hit():
    # Q-RR2-NAMES: parts that a vector joins at test time hold only the shapes they are meant to show. With the real
    # token digests loaded, the lanes' local scan runs the same walk.
    joined = list(_string_lists(VECTORS))
    assert joined
    hits = [rr.privacy_hits(text) for text in joined]
    assert sum(h["names"] for h in hits) == 0 and sum(h["legacyTerm"] for h in hits) == 0
    assert sum(h["absolutePaths"] for h in hits) == 3 and sum(h["emails"] for h in hits) == 3


def test_every_published_file_of_the_contract_is_private():
    files = [HERE / name for name in ("vectors.json", "briefs.json", "README.md", "REVIEW_BRIEF.md",
                                      "legacy-review-records.json")] + [
        ROOT / "scripts/review_record.py"] + [ROOT / "schemas" / ("%s.schema.json" % n) for n in SCHEMAS]
    for path in files:
        assert rr.privacy_hits(path.read_bytes()) == {"names": 0, "legacyTerm": 0, "absolutePaths": 0, "emails": 0}, path


# ---------------------------------------------------------------- check_tree on synthetic trees

def _write(root: Path, rel: str, raw: bytes) -> None:
    path = root / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(raw)


def _round_files(n: int, record_mutation=(), identity_mutation=(), directory="architecture/example"):
    rec = rr.mutate(BASES["record"], [{"path": ["round"], "value": n}] + list(record_mutation))
    raw = rr.serialize(rec)
    rel = "%s/review-round%d.json" % (directory, n)
    ident = rr.mutate(BASES["identity"], list(identity_mutation))
    ident["record"] = {"path": rel, "sha256": rr.file_sha256(raw)}
    return {rel: raw, "%s/review-identity-round%d.json" % (directory, n): rr.serialize(ident)}


def _legacy(entries=(), oracles=()):
    return rr.load_legacy({"schemaVersion": rr.LEGACY_SCHEMA, "baseCommit": "0" * 40,
                           "entries": sorted(entries, key=lambda e: e["path"]),
                           "oracleTests": sorted(oracles, key=lambda e: e["path"])})


def _tree(tmp_path, files):
    for rel, raw in files.items():
        _write(tmp_path, rel, raw)
    return tmp_path


def _code(fn, *args):
    try:
        fn(*args)
        return None
    except rr.Refused as refused:
        return refused.code


def test_tree_with_one_valid_series_and_a_frozen_record_passes(tmp_path):
    files = _round_files(1, [{"path": ["verdict"], "value": "CHANGES_REQUIRED"}])
    files.update(_round_files(2, [{"path": ["subject", "commit"], "value": "c" * 40},
                                  {"path": ["subject", "tree"], "value": "d" * 40},
                                  {"path": ["base"], "value": BASES["record"]["subject"]}],
                              [{"path": ["subject", "commit"], "value": "c" * 40},
                               {"path": ["subject", "tree"], "value": "d" * 40},
                               {"path": ["base"], "value": BASES["record"]["subject"]}]))
    frozen = b'{"verdict": "PASS_FOR_SOURCE_PUBLICATION"}\n'
    files["legal/old/review-round1.json"] = frozen
    root = _tree(tmp_path, files)
    legacy = _legacy([{"path": "legal/old/review-round1.json", "sha256": rr.file_sha256(frozen)}])
    assert rr.check_tree(root, legacy, REGISTRY, "harness-onion") == {"legacyRecords": 1, "series": 1, "oracleTests": 0,
                                                                     "oracleIdentities": 0}


def test_tree_refuses_a_changed_or_unlisted_legacy_record(tmp_path):
    frozen = b'{"verdict": "CHANGES_REQUIRED"}\n'
    root = _tree(tmp_path, {"legal/old/review-round1.json": frozen + b" "})
    legacy = _legacy([{"path": "legal/old/review-round1.json", "sha256": rr.file_sha256(frozen)}])
    assert _code(rr.check_tree, root, legacy, REGISTRY, "harness-onion") == "LEGACY_CHANGED"
    other = tmp_path / "other"
    _write(other, "architecture/x/review-round-final.json", frozen)
    assert _code(rr.check_tree, other, _legacy(), REGISTRY, "harness-onion") == "LEGACY_CHANGED"


def test_tree_refuses_a_legacy_path_rewritten_into_a_valid_v2_round(tmp_path):
    files = _round_files(1)
    root = _tree(tmp_path, files)
    legacy = _legacy([{"path": "architecture/example/review-round1.json", "sha256": "0" * 64}])
    assert _code(rr.check_tree, root, legacy, REGISTRY, "harness-onion") == "LEGACY_CHANGED"


def test_tree_refuses_a_v2_round_without_its_identity(tmp_path):
    files = _round_files(1)
    del files["architecture/example/review-identity-round1.json"]
    assert _code(rr.check_tree, _tree(tmp_path, files), _legacy(), REGISTRY, "harness-onion") == "NO_IDENTITY"


def test_tree_judges_each_round_and_the_series(tmp_path):
    files = _round_files(1, [{"path": ["subject", "repository"], "value": "mas-harness-operator"}],
                         [{"path": ["subject", "repository"], "value": "mas-harness-operator"}])
    assert _code(rr.check_tree, _tree(tmp_path, files), _legacy(), REGISTRY, "harness-onion") == "SUBJECT_REPOSITORY"
    gap = tmp_path / "gap"
    _tree(gap, dict(_round_files(1), **_round_files(3)))
    assert _code(rr.check_tree, gap, _legacy(), REGISTRY, "harness-onion") == "SERIES_GAP"


def test_tree_requires_a_frozen_oracle_test_or_a_valid_oracle_identity_for_each_oracle_test(tmp_path):
    oracle_file = b"import unittest\n"
    root = _tree(tmp_path, {"tests/test_example_oracle.py": oracle_file})
    assert _code(rr.check_tree, root, _legacy(), REGISTRY, "harness-onion") == "ORACLE_MISSING"
    frozen = _legacy(oracles=[{"path": "tests/test_example_oracle.py", "sha256": rr.file_sha256(oracle_file)}])
    assert rr.check_tree(root, frozen, REGISTRY, "harness-onion")["oracleTests"] == 1
    # Q-RR2-FROZEN (rev 4's stricter rule): a frozen oracle test is frozen with its bytes, so an edit needs an identity.
    _write(root, "tests/test_example_oracle.py", oracle_file + b"# bumped\n")
    assert _code(rr.check_tree, root, frozen, REGISTRY, "harness-onion") == "ORACLE_MISSING"
    _write(root, "tests/test_example_oracle.py", oracle_file)
    identity = rr.mutate(BASES["oracle"], [{"path": ["file"], "value": {"path": "tests/test_example_oracle.py",
                                                                        "sha256": rr.file_sha256(oracle_file)}}])
    _write(root, "architecture/example/oracle-identity.json", rr.serialize(identity))
    assert rr.check_tree(root, _legacy(), REGISTRY, "harness-onion")["oracleIdentities"] == 1
    _write(root, "tests/test_example_oracle.py", oracle_file + b"# edited\n")
    assert _code(rr.check_tree, root, _legacy(), REGISTRY, "harness-onion") == "ORACLE_DIGEST"


def test_tree_refuses_a_malformed_oracle_identity(tmp_path):
    root = _tree(tmp_path, {"architecture/example/oracle-identity.json": b'{"schemaVersion": "x"}\n'})
    assert _code(rr.check_tree, root, _legacy(), REGISTRY, "harness-onion") == "SHAPE"


def test_tree_ignores_records_beneath_git_and_caches(tmp_path):
    root = _tree(tmp_path, {".git/review-round1.json": b"{}", "x/__pycache__/review-round1.json": b"{}"})
    assert rr.check_tree(root, _legacy(), REGISTRY, "harness-onion") == {"legacyRecords": 0, "series": 0,
                                                                        "oracleTests": 0, "oracleIdentities": 0}
