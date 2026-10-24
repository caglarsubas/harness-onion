"""D5a oracle tests for MET-LIVE-003, the neutral Linux probe interface.

Black-box tests written from architecture/linux-probe-interface/README.md by a test author outside the candidate.
The model is used only through its public names: check, valid, R and the upper-case constants.
Every mutation below is the author's own; none is taken from a vector file.
"""
import copy
import hashlib
import importlib.util
import json
import re
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
PACKET = ROOT / "architecture" / "linux-probe-interface"
V1 = PACKET / "v1"
AMENDMENT = ROOT / "architecture" / "probe-kit-scope" / "amendment.json"
MODEL = ROOT / "scripts" / "linux_probe_interface.py"

P_MANIFEST = "architecture/linux-probe-interface/v1/MANIFEST.json"
P_V1_README = "architecture/linux-probe-interface/v1/README.md"
P_INSTANCE = "architecture/linux-probe-interface/v1/probe-interface.json"
P_SCHEMA = "architecture/linux-probe-interface/v1/probe-interface.schema.json"
P_AMENDMENT = "architecture/probe-kit-scope/amendment.json"
DRAFT_2020_12 = "https://json-schema.org/draft/2020-12/schema"


# ---------------------------------------------------------------------------------------------------------------------
# Helpers: the model, the README text, the files.
# ---------------------------------------------------------------------------------------------------------------------

_MODEL = None


def model():
    global _MODEL
    if _MODEL is None:
        spec = importlib.util.spec_from_file_location("linux_probe_interface_oracle_subject", MODEL)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        _MODEL = module
    return _MODEL


def sha256(data):
    return hashlib.sha256(data).hexdigest()


def readme():
    return (PACKET / "README.md").read_text(encoding="utf-8")


def section(title):
    """The body of the README's '## <title>' section, up to the next '## ' heading."""
    text = readme()
    marker = "\n## " + title + "\n"
    start = text.index(marker) + len(marker)
    end = text.find("\n## ", start)
    return text[start:] if end < 0 else text[start:end]


def record():
    return json.loads((PACKET / "binding.json").read_text(encoding="utf-8"))


def manifest():
    return json.loads((V1 / "MANIFEST.json").read_text(encoding="utf-8"))


def amendment():
    return json.loads(AMENDMENT.read_text(encoding="utf-8"))


def schema():
    return json.loads((V1 / "probe-interface.schema.json").read_text(encoding="utf-8"))


def instance():
    return json.loads((V1 / "probe-interface.json").read_text(encoding="utf-8"))


def repo_files():
    """Repository-relative path -> bytes, for the five paths the README's checks cover."""
    return {path: (ROOT / path).read_bytes() for path in (P_MANIFEST, P_V1_README, P_INSTANCE, P_SCHEMA, P_AMENDMENT)}


def reader(files):
    def read(path):
        if path not in files:
            raise FileNotFoundError(path)
        return files[path]
    return read


def readme_key_table():
    rows = re.findall(r"^\| `(architecture/linux-probe-interface/v1/[^`]+)` \| `([0-9a-f]{64})` \|$",
                      section("The contract files (`v1/`), by sha256"), re.M)
    return rows


def readme_source():
    body = section("Source and review chain")
    match = re.search(r"\*\*The source:\*\* `([^`]+)` at commit `([0-9a-f]{40})`, tree `([0-9a-f]{40})`, read at\s+"
                      r"`([0-9a-f]{40})`\.", body)
    assert match, "README source line not found"
    return {"repository": match.group(1), "commit": match.group(2), "tree": match.group(3), "readAt": match.group(4)}


def readme_reviews():
    rows = re.findall(r"^\| (\d+) \| `([0-9a-f]{64})` \| ([A-Z_]+) \|$", section("Source and review chain"), re.M)
    return [{"round": int(r), "recordSha256": s, "verdict": v} for r, s, v in rows]


def readme_non_claims():
    rows = re.findall(r"^- \*\*([A-Z0-9_]+):\*\* (.+)$", section("Non-claims"), re.M)
    return [{"id": i, "text": t} for i, t in rows]


def readme_decisions():
    rows = re.findall(r'^- ([A-Z0-9-]+): "(.+)"[;.]$', section("Owner decisions"), re.M)
    return [{"id": i, "quote": q} for i, q in rows]


def readme_keywords():
    body = section("What the model checks")
    start = body.index("may use only these keywords:")
    end = body.index("Anything else refuses", start)
    return re.findall(r"`([^`]+)`", body[start:end])


# ---------------------------------------------------------------------------------------------------------------------
# An independent walk over schema positions (not keys): only values at schema positions are schemas.
# ---------------------------------------------------------------------------------------------------------------------

_MAP_OF_SCHEMAS = {"$defs", "definitions", "properties", "patternProperties", "dependentSchemas"}
_ONE_SCHEMA = {"items", "additionalProperties", "if", "then", "else", "not", "contains", "propertyNames",
               "unevaluatedItems", "unevaluatedProperties", "additionalItems"}
_LIST_OF_SCHEMAS = {"prefixItems", "allOf", "anyOf", "oneOf"}


def schema_positions(node, pointer="#", out=None):
    """Yield (pointer, keyword, value) for every keyword at every schema position."""
    if out is None:
        out = []
    if isinstance(node, bool):
        return out
    assert isinstance(node, dict), "a schema position holds neither an object nor a boolean at " + pointer
    for key, value in node.items():
        out.append((pointer, key, value))
        here = pointer + "/" + key.replace("~", "~0").replace("/", "~1")
        if key in _MAP_OF_SCHEMAS and isinstance(value, dict):
            for name, sub in value.items():
                schema_positions(sub, here + "/" + name.replace("~", "~0").replace("/", "~1"), out)
        elif key in _ONE_SCHEMA:
            schema_positions(value, here, out)
        elif key in _LIST_OF_SCHEMAS and isinstance(value, list):
            for index, sub in enumerate(value):
                schema_positions(sub, here + "/" + str(index), out)
    return out


def resolve_local(root, ref):
    assert ref.startswith("#/"), ref
    node = root
    for part in ref[2:].split("/"):
        node = node[part.replace("~1", "/").replace("~0", "~")]
    return node


# ---------------------------------------------------------------------------------------------------------------------
# Title section: the packet's identity.
# ---------------------------------------------------------------------------------------------------------------------

def test_packet_identity():
    """README section: '# The neutral Linux probe interface (MET-LIVE-003)' (packet, slot, work item)."""
    text = readme()
    match = re.search(r"This packet is (MET-[A-Z]+-\d+), slot (\d+), (?:after [^,]+, )?work item ([A-Z-]+), and\s+"
                      r"it is data only\.", text)
    assert match
    rec = record()
    assert rec["packet"] == match.group(1) == "MET-LIVE-003"
    assert type(rec["slot"]) is int and rec["slot"] == int(match.group(2)) == 262
    assert rec["workItem"] == match.group(3) == "LINUX-PROBE-INTERFACE"
    assert rec["schemaVersion"] == model().SCHEMA


# ---------------------------------------------------------------------------------------------------------------------
# 1. The four v1/ files' sha256.
# ---------------------------------------------------------------------------------------------------------------------

def test_v1_file_digests_equal_readme_table_and_record():
    """README section: 'The contract files (`v1/`), by sha256'."""
    table = readme_key_table()
    assert len(table) == 4
    assert sorted(p for p, _ in table) == sorted([P_MANIFEST, P_V1_README, P_INSTANCE, P_SCHEMA])
    for path, digest in table:
        assert sha256((ROOT / path).read_bytes()) == digest, path
    assert [{"path": p, "sha256": d} for p, d in table] == record()["files"]
    assert sorted(p.name for p in V1.iterdir()) == sorted(Path(p).name for p, _ in table)


def test_model_pins_the_handoff_digests():
    """README section: 'What the model checks' / The digests (the record's four digests equal the pinned handoff)."""
    m = model()
    table = {Path(p).name: d for p, d in readme_key_table()}
    assert dict(m.HANDOFF) == table
    assert tuple(sorted(m.FILES)) == tuple(sorted(table))
    assert all(p.startswith(m.DIRECTORY) for p, _ in readme_key_table())


# ---------------------------------------------------------------------------------------------------------------------
# 2. Source and review chain.
# ---------------------------------------------------------------------------------------------------------------------

def test_source_equals_readme_record_and_manifest():
    """README section: 'Source and review chain' (the source) and 'What the model checks' / The MANIFEST."""
    expected = readme_source()
    assert expected["repository"] == "mas-harness-conformance-labs"
    assert record()["source"] == expected
    man = manifest()
    assert sorted(man["source"]) == ["commit", "readAt", "repository", "tree"]
    assert man["source"] == expected
    assert sorted(record()["source"]) == sorted(model().SOURCE_MEMBERS)


def test_review_chain_equals_readme_record_and_manifest():
    """README section: 'Source and review chain' (the reviews) and 'What the model checks' / The MANIFEST."""
    table = readme_reviews()
    assert [r["round"] for r in table] == [1, 2, 3]
    assert table[-1]["verdict"] == "PASS_FOR_HANDOFF"
    assert [r["verdict"] for r in table[:-1]] == ["CHANGES_REQUIRED", "CHANGES_REQUIRED"]
    assert record()["reviews"] == table
    man = manifest()
    assert [{"round": r["round"], "recordSha256": r["recordSha256"], "verdict": r["verdict"]}
            for r in man["reviews"]] == table
    assert man["verdict"] == "PASS_FOR_HANDOFF"
    # 'three independent review rounds': three distinct reviewers, none of them the extractor.
    reviewers = [r["reviewer"] for r in man["reviews"]]
    assert len(set(reviewers)) == 3
    assert man["extractor"]["agentId"] not in reviewers


def test_manifest_files_equal_record():
    """README section: 'What the model checks' / The MANIFEST (its files equal the record's)."""
    man_files = manifest()["files"]
    rec_files = {Path(f["path"]).name: f["sha256"] for f in record()["files"]}
    # The MANIFEST cannot hold its own digest; the other three files must equal the record's.
    assert "MANIFEST.json" not in man_files
    assert man_files == {name: digest for name, digest in rec_files.items() if name != "MANIFEST.json"}


# ---------------------------------------------------------------------------------------------------------------------
# 3. The placeholder binding.
# ---------------------------------------------------------------------------------------------------------------------

def test_placeholder_binding():
    """README section: 'The placeholder binding'."""
    body = section("The placeholder binding")
    match = re.search(r"\((MET-[A-Z]+-\d+), `([^`]+)`, sha256\s+`([0-9a-f]{64})`\) names the placeholder `([A-Z_]+)`",
                      body)
    assert match
    lpk0_packet, lpk0_path, lpk0_digest, placeholder = match.groups()
    iface = re.search(r"to (MET-[A-Z]+-\d+) and to `v1/probe-interface.json` \(sha256\s+`([0-9a-f]{64})`\)", body)
    assert iface
    bound_to, interface_digest = iface.groups()

    binding = record()["placeholderBinding"]
    assert sorted(binding) == sorted(model().BINDING_MEMBERS)
    assert binding["record"] == lpk0_path == P_AMENDMENT == model().LPK0_RECORD
    assert binding["recordSha256"] == lpk0_digest == sha256(AMENDMENT.read_bytes())
    assert binding["placeholder"] == placeholder == "NEUTRAL_INTERFACE_CONTRACT" == model().PLACEHOLDER
    assert binding["boundTo"] == bound_to == record()["packet"]
    assert binding["interfaceSha256"] == interface_digest == sha256((V1 / "probe-interface.json").read_bytes())

    lpk0 = amendment()
    assert lpk0["packet"] == lpk0_packet == "MET-LIVE-002"
    assert placeholder in lpk0["effectivePredecessors"]["placeholders"]
    # 'So the amendment's R12_SUCCESSOR and LINUX-PROBE-KIT-001 wait on this packet.'
    edges = {e["item"]: e["after"] for e in lpk0["effectivePredecessors"]["edges"]}
    assert placeholder in edges["R12_SUCCESSOR"]
    assert placeholder in edges["LINUX-PROBE-KIT-001"]


# ---------------------------------------------------------------------------------------------------------------------
# 4. Non-claims and owner decisions.
# ---------------------------------------------------------------------------------------------------------------------

def test_non_claims_exactly_the_four_verbatim():
    """README section: 'Non-claims' (exactly these four, and the model pins each text)."""
    rows = readme_non_claims()
    assert [r["id"] for r in rows] == ["FORM_ONLY", "NOT_ACCEPTANCE", "R12_FILES_AUTHORITATIVE_UNTIL_VENDORED",
                                       "R12_KEEPS_STATUS_AND_COUNT_RULES"]
    assert record()["nonClaims"] == rows
    assert [dict(r) for r in model().NON_CLAIMS] == rows


def test_manifest_non_claims_are_the_two_verbatim():
    """README section: 'Non-claims' (two are the MANIFEST's own nonClaims, verbatim; NOT_ACCEPTANCE; owner's)."""
    body = section("Non-claims")
    match = re.search(r"^([A-Z0-9_]+) and ([A-Z0-9_]+) are `v1/MANIFEST.json`'s own `nonClaims`, verbatim", body, re.M)
    assert match
    texts = {r["id"]: r["text"] for r in readme_non_claims()}
    expected = [texts[match.group(1)], texts[match.group(2)]]
    assert manifest()["nonClaims"] == expected
    assert list(model().MANIFEST_NON_CLAIMS) == expected
    # NOT_ACCEPTANCE follows the MANIFEST's ownerNotes.
    assert "NOT_ACCEPTANCE follows the MANIFEST's `ownerNotes`" in body
    assert any("the interface form, but not acceptance" in note for note in manifest()["ownerNotes"])
    # R12_KEEPS_STATUS_AND_COUNT_RULES is the owner's decision: its text quotes the R12-ACCEPTANCE-RULES row.
    quotes = {d["id"]: d["quote"] for d in readme_decisions()}
    assert '"' + quotes["R12-ACCEPTANCE-RULES"] + '"' in texts["R12_KEEPS_STATUS_AND_COUNT_RULES"]


def test_owner_decisions_exactly_the_two():
    """README section: 'Owner decisions' (exactly these two, and the model pins both rows)."""
    rows = readme_decisions()
    assert rows == [{"id": "Q-PK-6", "quote": "Neutral contract (Recommended)"},
                    {"id": "R12-ACCEPTANCE-RULES", "quote": "Keep them in R12 (Recommended)"}]
    assert record()["ownerDecisions"] == rows
    assert [dict(d) for d in model().DECISIONS] == rows
    # Q-PK-6 set the packet up: the same quote in LPK-0's record and in the MANIFEST's decision line.
    lpk0 = {d["id"]: d["quote"] for d in amendment()["ownerDecisions"]}
    assert lpk0["Q-PK-6"] == rows[0]["quote"]
    assert '"' + rows[0]["quote"] + '"' in manifest()["decision"]
    assert 'Q-PK-6, "Neutral contract (Recommended)", set it up' in readme()


# ---------------------------------------------------------------------------------------------------------------------
# 5. Schema conformance.
# ---------------------------------------------------------------------------------------------------------------------

def test_schema_names_draft_2020_12():
    """README section: 'What the model checks' / Schema conformance (the schema names draft 2020-12)."""
    assert "must name draft 2020-12 in `$schema`" in section("What the model checks")
    assert schema()["$schema"] == DRAFT_2020_12
    assert model().DRAFT == DRAFT_2020_12


def test_schema_position_walker_is_position_aware():
    """README section: 'What the model checks' / Schema conformance (the oracle's own walk, self-test)."""
    toy = {"type": "object", "properties": {"maximum": {"type": "integer"}, "format": True},
           "$defs": {"x": {"const": {"maximum": 1}}}, "allOf": [{"if": {"enum": [1]}, "then": False}]}
    used = {key for _, key, _ in schema_positions(toy)}
    assert used == {"type", "properties", "$defs", "const", "allOf", "if", "then", "enum"}
    assert "maximum" in {key for _, key, _ in schema_positions({"maximum": 3})}
    assert ("#/allOf/0/not", "format") in [(p, k) for p, k, _ in schema_positions({"allOf": [{"not": {"format": "x"}}]})]


def test_schema_uses_only_readme_keywords():
    """README section: 'What the model checks' / Schema conformance (only the listed keywords; local $ref)."""
    listed = readme_keywords()
    assert len(listed) == 21 and len(set(listed)) == 21
    assert frozenset(listed) == frozenset(model().KEYWORDS)
    root = schema()
    positions = schema_positions(root)
    assert len(positions) > 100
    used = {key for _, key, _ in positions}
    assert used <= set(listed), sorted(used - set(listed))
    # A property named 'maximum' exists (a name, not a keyword): the walk must not mistake it for one.
    assert "maximum" in root["$defs"]["field"]["properties"]
    refs = [value for _, key, value in positions if key == "$ref"]
    assert refs
    for ref in refs:
        assert ref.startswith("#/"), ref
        assert isinstance(resolve_local(root, ref), (dict, bool)), ref
    assert all(pointer == "#" for pointer, key, _ in positions if key == "$schema")


def test_instance_conforms_with_jsonschema_draft_2020_12():
    """README section: 'What the model checks' / Schema conformance (independent jsonschema 2020-12 check)."""
    jsonschema = pytest.importorskip("jsonschema")
    root = schema()
    jsonschema.Draft202012Validator.check_schema(root)
    assert jsonschema.validators.validator_for(root) is jsonschema.Draft202012Validator
    errors = list(jsonschema.Draft202012Validator(root).iter_errors(instance()))
    assert errors == [], [e.message for e in errors[:5]]


def test_instance_conforms_with_model_validator():
    """README section: 'What the model checks' / Schema conformance (the standard-library validator)."""
    root = schema()
    assert model().valid(instance(), root, root) is True
    broken = instance()
    del broken["http"]
    assert model().valid(broken, root, root) is False


# ---------------------------------------------------------------------------------------------------------------------
# 6. The model, black-box: check(record, read).
# ---------------------------------------------------------------------------------------------------------------------

def test_check_adopted_record_holds():
    """README section: 'What the model checks' (check returns [] when the record holds)."""
    assert model().check(record(), reader(repo_files())) == []


def _jget(files, path):
    return json.loads(files[path])


def _jput(files, path, obj):
    files[path] = json.dumps(obj, indent=2, ensure_ascii=False).encode("utf-8")


def _deep(depth):
    node = []
    for _ in range(depth):
        node = [node]
    return node


def m_record_file_digest(rec, files):
    rec["files"][0]["sha256"] = "0" * 64


def m_v1_readme_byte(rec, files):
    files[P_V1_README] = files[P_V1_README] + b"\n"


def m_record_source_tree(rec, files):
    rec["source"]["tree"] = "f" * 40


def m_manifest_source_commit(rec, files):
    man = _jget(files, P_MANIFEST)
    man["source"]["commit"] = "a" * 40
    _jput(files, P_MANIFEST, man)


def m_manifest_source_fifth_member(rec, files):
    man = _jget(files, P_MANIFEST)
    man["source"]["branch"] = "main"
    _jput(files, P_MANIFEST, man)


def m_manifest_files_digest(rec, files):
    man = _jget(files, P_MANIFEST)
    man["files"]["probe-interface.json"] = "1" * 64
    _jput(files, P_MANIFEST, man)


def m_manifest_review_digest(rec, files):
    man = _jget(files, P_MANIFEST)
    man["reviews"][1]["recordSha256"] = "2" * 64
    _jput(files, P_MANIFEST, man)


def m_manifest_verdict(rec, files):
    man = _jget(files, P_MANIFEST)
    man["verdict"] = "CHANGES_REQUIRED"
    man["reviews"][-1]["verdict"] = "CHANGES_REQUIRED"
    _jput(files, P_MANIFEST, man)


def m_manifest_non_claim_text(rec, files):
    man = _jget(files, P_MANIFEST)
    man["nonClaims"][1] = man["nonClaims"][1].rstrip(".")
    _jput(files, P_MANIFEST, man)


def m_record_last_verdict(rec, files):
    rec["reviews"][-1]["verdict"] = "CHANGES_REQUIRED"


def m_record_review_digest(rec, files):
    rec["reviews"][0]["recordSha256"] = "3" * 64


def m_non_claim_text(rec, files):
    rec["nonClaims"][1]["text"] = rec["nonClaims"][1]["text"].replace("not acceptance", "and acceptance")


def m_non_claim_dropped(rec, files):
    del rec["nonClaims"][3]


def m_non_claim_id(rec, files):
    rec["nonClaims"][0]["id"] = "FORM_ONLY_DRAFT"


def m_decision_quote(rec, files):
    rec["ownerDecisions"][0]["quote"] = "Neutral contract"


def m_decision_dropped(rec, files):
    del rec["ownerDecisions"][1]


def m_placeholder_name(rec, files):
    rec["placeholderBinding"]["placeholder"] = "R12_SUCCESSOR"


def m_placeholder_record_digest(rec, files):
    rec["placeholderBinding"]["recordSha256"] = "4" * 64


def m_placeholder_interface_digest(rec, files):
    rec["placeholderBinding"]["interfaceSha256"] = rec["files"][3]["sha256"]


def m_placeholder_absent_from_lpk0(rec, files):
    lpk0 = _jget(files, P_AMENDMENT)
    lpk0["effectivePredecessors"]["placeholders"].remove("NEUTRAL_INTERFACE_CONTRACT")
    _jput(files, P_AMENDMENT, lpk0)


def m_slot_float(rec, files):
    rec["slot"] = 262.0


def m_slot_bool(rec, files):
    rec["slot"] = True


def m_slot_string(rec, files):
    rec["slot"] = "262"


def m_packet_wrong_type(rec, files):
    rec["packet"] = ["MET-LIVE-003"]


def m_extra_top_member(rec, files):
    rec["adopted"] = True


def m_extra_binding_member(rec, files):
    rec["placeholderBinding"]["note"] = "extra"


def m_missing_top_member(rec, files):
    del rec["workItem"]


def m_record_not_object(rec, files):
    return [rec]


def m_too_deep(rec, files):
    rec["nonClaims"] = _deep(20000)


def m_schema_format_keyword(rec, files):
    sch = _jget(files, P_SCHEMA)
    sch["properties"]["source"]["properties"]["commit"]["format"] = "hex"
    _jput(files, P_SCHEMA, sch)


def m_schema_maximum_keyword(rec, files):
    sch = _jget(files, P_SCHEMA)
    sch["properties"]["http"]["properties"]["timeouts"]["properties"]["connectSeconds"]["maximum"] = 600
    _jput(files, P_SCHEMA, sch)


def m_schema_any_of_keyword(rec, files):
    sch = _jget(files, P_SCHEMA)
    sch["$defs"]["status"] = {"anyOf": [{"const": "PASS"}, {"const": "FAIL"}, {"const": "NOT_RUN_ENV_UNAVAILABLE"}]}
    _jput(files, P_SCHEMA, sch)


def m_schema_remote_ref(rec, files):
    sch = _jget(files, P_SCHEMA)
    sch["$defs"]["field"]["properties"]["source"]["$ref"] = "other-schema.json#/$defs/source"
    _jput(files, P_SCHEMA, sch)


def m_schema_draft_07(rec, files):
    sch = _jget(files, P_SCHEMA)
    sch["$schema"] = "http://json-schema.org/draft-07/schema#"
    _jput(files, P_SCHEMA, sch)


def m_instance_missing_required(rec, files):
    inst = _jget(files, P_INSTANCE)
    del inst["http"]
    _jput(files, P_INSTANCE, inst)


def m_instance_nested_missing_required(rec, files):
    inst = _jget(files, P_INSTANCE)
    del inst["receipt"]["inventory"]["ordered"]
    _jput(files, P_INSTANCE, inst)


def m_instance_extra_member(rec, files):
    inst = _jget(files, P_INSTANCE)
    inst["status"] = "PASS"
    _jput(files, P_INSTANCE, inst)


def m_instance_final_line_feed(rec, files):
    inst = _jget(files, P_INSTANCE)
    inst["source"]["commit"] = inst["source"]["commit"] + "\n"
    _jput(files, P_INSTANCE, inst)


# (id, what it changes, mutate, requirements). Each requirement is a set of R keys; at least one must refuse.
MUTATIONS = [
    ("record-file-digest", "record files[0].sha256 (MANIFEST.json) set to 64 zeros",
     m_record_file_digest, [{"sha"}, {"handoff"}]),
    ("v1-readme-byte", "v1/README.md gains one trailing line feed", m_v1_readme_byte, [{"sha"}]),
    ("record-source-tree", "record source.tree changed", m_record_source_tree, [{"manifest"}]),
    ("manifest-source-commit", "MANIFEST source.commit changed", m_manifest_source_commit, [{"manifest"}, {"sha"}]),
    ("manifest-source-fifth-member", "MANIFEST source gains a fifth member 'branch'",
     m_manifest_source_fifth_member, [{"manifest"}, {"sha"}]),
    ("manifest-files-digest", "MANIFEST files[probe-interface.json] changed",
     m_manifest_files_digest, [{"manifest"}, {"sha"}]),
    ("manifest-review-digest", "MANIFEST round-2 recordSha256 changed",
     m_manifest_review_digest, [{"manifest"}, {"sha"}]),
    ("manifest-verdict", "MANIFEST verdict and last review verdict set to CHANGES_REQUIRED",
     m_manifest_verdict, [{"manifest", "verdict"}, {"sha"}]),
    ("manifest-non-claim-text", "MANIFEST nonClaims[1] loses its final full stop",
     m_manifest_non_claim_text, [{"manifest", "claims"}, {"sha"}]),
    ("record-last-verdict", "record round-3 verdict set to CHANGES_REQUIRED",
     m_record_last_verdict, [{"verdict"}, {"manifest"}]),
    ("record-review-digest", "record round-1 recordSha256 changed", m_record_review_digest, [{"manifest"}]),
    ("non-claim-text", "NOT_ACCEPTANCE text says 'and acceptance'", m_non_claim_text, [{"claims"}]),
    ("non-claim-dropped", "R12_KEEPS_STATUS_AND_COUNT_RULES row removed", m_non_claim_dropped, [{"claims"}]),
    ("non-claim-id", "FORM_ONLY id renamed", m_non_claim_id, [{"claims"}]),
    ("decision-quote", "Q-PK-6 quote loses ' (Recommended)'", m_decision_quote, [{"decisions"}]),
    ("decision-dropped", "R12-ACCEPTANCE-RULES row removed", m_decision_dropped, [{"decisions"}]),
    ("placeholder-name", "placeholderBinding.placeholder set to R12_SUCCESSOR", m_placeholder_name,
     [{"placeholder"}]),
    ("placeholder-record-digest", "placeholderBinding.recordSha256 changed", m_placeholder_record_digest,
     [{"placeholder"}]),
    ("placeholder-interface-digest", "placeholderBinding.interfaceSha256 set to the schema's digest",
     m_placeholder_interface_digest, [{"placeholder"}]),
    ("placeholder-absent-from-lpk0", "LPK-0 amendment loses NEUTRAL_INTERFACE_CONTRACT from its placeholders",
     m_placeholder_absent_from_lpk0, [{"placeholder"}]),
    ("slot-float", "slot set to 262.0", m_slot_float, [{"shape"}]),
    ("slot-bool", "slot set to true", m_slot_bool, [{"shape"}]),
    ("slot-string", "slot set to \"262\"", m_slot_string, [{"shape"}]),
    ("packet-wrong-type", "packet set to a list", m_packet_wrong_type, [{"shape"}]),
    ("extra-top-member", "record gains member 'adopted'", m_extra_top_member, [{"shape"}]),
    ("extra-binding-member", "placeholderBinding gains member 'note'", m_extra_binding_member, [{"shape"}]),
    ("missing-top-member", "record loses 'workItem'", m_missing_top_member, [{"shape"}]),
    ("record-not-object", "record is a one-item list holding the record", m_record_not_object, [{"shape"}]),
    ("too-deep", "nonClaims replaced by a list nested 20000 deep", m_too_deep, [{"shape"}]),
    ("schema-format-keyword", "schema gains 'format' at /properties/source/properties/commit",
     m_schema_format_keyword, [{"keyword"}]),
    ("schema-maximum-keyword", "schema gains 'maximum' at a schema position (connectSeconds)",
     m_schema_maximum_keyword, [{"keyword"}]),
    ("schema-anyof-keyword", "$defs/status rewritten with 'anyOf'", m_schema_any_of_keyword, [{"keyword"}]),
    ("schema-remote-ref", "a non-local $ref (other-schema.json#/$defs/source)", m_schema_remote_ref,
     [{"keyword", "conformance"}]),
    ("schema-draft-07", "schema $schema names draft-07", m_schema_draft_07, [{"keyword", "conformance"}]),
    ("instance-missing-required", "probe-interface.json loses required member 'http'",
     m_instance_missing_required, [{"conformance"}]),
    ("instance-nested-missing-required", "probe-interface.json loses receipt.inventory.ordered",
     m_instance_nested_missing_required, [{"conformance"}]),
    ("instance-extra-member", "probe-interface.json gains top-level member 'status'",
     m_instance_extra_member, [{"conformance"}]),
    ("instance-final-line-feed", "probe-interface.json source.commit gains a final line feed (pattern ...$)",
     m_instance_final_line_feed, [{"conformance"}]),
]


def run_mutation(mutate):
    rec = record()
    files = repo_files()
    replaced = mutate(rec, files)
    if replaced is not None:
        rec = replaced
    return model().check(rec, reader(files))


def test_mutation_set_covers_the_brief():
    """README section: 'What the model checks' (coverage of the oracle's own mutations)."""
    assert len(MUTATIONS) >= 12
    assert len({m[0] for m in MUTATIONS}) == len(MUTATIONS)
    keys = set(model().R)
    for _, _, _, requirements in MUTATIONS:
        for requirement in requirements:
            assert requirement <= keys


@pytest.mark.parametrize("name, what, mutate, requirements", MUTATIONS, ids=[m[0] for m in MUTATIONS])
def test_check_refuses_mutation(name, what, mutate, requirements):
    """README section: 'What the model checks' (each mutation is refused with texts from R)."""
    R = model().R
    texts = set(R.values())
    result = run_mutation(mutate)
    assert isinstance(result, list) and result, name
    assert all(isinstance(t, str) for t in result)
    assert result == sorted(result), "check must return the sorted refusal texts"
    assert set(result) <= texts, sorted(set(result) - texts)
    for requirement in requirements:
        assert {R[k] for k in requirement} & set(result), (name, sorted(requirement), result)


def test_check_integer_valued_float_in_instance_conforms():
    """README section: 'What the model checks' / Schema conformance (10.0 is an integer; no conformance refusal)."""
    R = model().R

    def mutate(rec, files):
        inst = _jget(files, P_INSTANCE)
        inst["receipt"]["inventory"]["count"] = 10.0
        inst["http"]["timeouts"]["connectSeconds"] = float(inst["http"]["timeouts"]["connectSeconds"])
        _jput(files, P_INSTANCE, inst)

    result = run_mutation(mutate)
    assert R["sha"] in result
    assert R["conformance"] not in result
    assert set(result) <= set(R.values())


def test_check_refusal_texts_are_the_readme_concepts():
    """README section: 'What the model checks' (R holds a refusal text for every check the README lists)."""
    R = model().R
    for key in ("shape", "sha", "handoff", "manifest", "verdict", "keyword", "conformance", "placeholder", "claims",
                "decisions"):
        assert isinstance(R[key], str) and R[key]
    assert "PASS_FOR_HANDOFF" in R["verdict"]
    assert "NEUTRAL_INTERFACE_CONTRACT" in R["placeholder"]
    assert len(set(R.values())) == len(R)


# ---------------------------------------------------------------------------------------------------------------------
# 7. The validator's stated semantics.
# ---------------------------------------------------------------------------------------------------------------------

# (case, value, schema, expected by the README's draft 2020-12 meaning, jsonschema agrees)
BOOLEAN_CASES = [
    ("true-schema-accepts-object", {"any": [1, None]}, True, True, True),
    ("false-schema-refuses-null", None, False, False, True),
    ("false-schema-refuses-empty-object", {}, False, False, True),
    ("property-false-refuses-present", {"a": 1}, {"properties": {"a": False}}, False, True),
    ("property-false-allows-absent", {"b": 1}, {"properties": {"a": False}}, True, True),
    ("property-true-allows-any", {"a": [1, {"x": None}]}, {"properties": {"a": True}}, True, True),
    ("items-false-after-prefix-refuses-third", [1, 2, 3],
     {"type": "array", "prefixItems": [{"type": "integer"}, {"type": "integer"}], "items": False}, False, True),
    ("items-false-after-prefix-allows-two", [1, 2],
     {"type": "array", "prefixItems": [{"type": "integer"}, {"type": "integer"}], "items": False}, True, True),
    ("additional-false-refuses-extra", {"a": 1, "z": 2},
     {"type": "object", "properties": {"a": True}, "additionalProperties": False}, False, True),
    ("then-false-applies", {"form": "x"},
     {"allOf": [{"if": {"properties": {"form": {"const": "x"}}}, "then": False}]}, False, True),
    ("if-false-skips-then", {"form": "y"},
     {"allOf": [{"if": {"properties": {"form": {"const": "x"}}}, "then": False}]}, True, True),
]
NUMBER_CASES = [
    ("float-10.0-is-integer", 10.0, {"type": "integer"}, True, True),
    ("float-10.5-not-integer", 10.5, {"type": "integer"}, False, True),
    ("bool-not-integer", True, {"type": "integer"}, False, True),
    ("const-10-matches-10.0", 10.0, {"const": 10}, True, True),
    ("enum-10.0-matches-10", 10, {"enum": ["10", 10.0]}, True, True),
    ("const-true-not-1", 1, {"const": True}, False, True),
    ("enum-1-not-true", True, {"enum": [1, 0]}, False, True),
    ("unique-1-and-1.0-duplicate", [1, 1.0], {"uniqueItems": True}, False, True),
    ("minimum-10.0-meets-10", 10.0, {"type": "integer", "minimum": 10}, True, True),
    ("minimum-9.0-below-10", 9.0, {"type": "integer", "minimum": 10}, False, True),
]
PATTERN_CASES = [
    ("pattern-end-matches", "ab", {"pattern": "^ab$"}, True, True),
    ("pattern-final-dollar-refuses-final-line-feed", "ab\n", {"pattern": "^ab$"}, False, False),
    ("pattern-hex40-refuses-final-line-feed", "a" * 40 + "\n", {"type": "string", "pattern": "^[0-9a-f]{40}$"},
     False, False),
    ("pattern-final-dollar-refuses-middle-line-feed", "ab\nc", {"pattern": "^ab$"}, False, True),
    ("pattern-unanchored-search", "xaby", {"pattern": "ab"}, True, True),
    ("pattern-escaped-dollar-is-literal", "a$", {"pattern": "^a\\$"}, True, True),
    ("pattern-escaped-dollar-needs-dollar", "a", {"pattern": "^a\\$"}, False, True),
]
VALIDATOR_CASES = BOOLEAN_CASES + NUMBER_CASES + PATTERN_CASES


def _model_valid(value, sch):
    return model().valid(value, sch, sch)


@pytest.mark.parametrize("case, value, sch, expected, agrees", BOOLEAN_CASES, ids=[c[0] for c in BOOLEAN_CASES])
def test_validator_boolean_subschemas(case, value, sch, expected, agrees):
    """README section: 'What the model checks' / Schema conformance (a boolean subschema is true or false)."""
    assert _model_valid(value, sch) is expected


@pytest.mark.parametrize("case, value, sch, expected, agrees", NUMBER_CASES, ids=[c[0] for c in NUMBER_CASES])
def test_validator_integer_valued_numbers(case, value, sch, expected, agrees):
    """README section: 'What the model checks' / Schema conformance (10.0 is an integer; numbers compare by value)."""
    assert _model_valid(value, sch) is expected


@pytest.mark.parametrize("case, value, sch, expected, agrees", PATTERN_CASES, ids=[c[0] for c in PATTERN_CASES])
def test_validator_pattern_final_dollar(case, value, sch, expected, agrees):
    """README section: 'What the model checks' / Schema conformance (a pattern's final $ only at the very end)."""
    assert _model_valid(value, sch) is expected


def test_validator_cases_against_jsonschema():
    """README section: 'What the model checks' / Schema conformance (jsonschema agrees except at a final $)."""
    jsonschema = pytest.importorskip("jsonschema")
    differs = []
    for case, value, sch, expected, agrees in VALIDATOR_CASES:
        got = jsonschema.Draft202012Validator(sch).is_valid(value)
        if agrees:
            assert got is expected, case
        else:
            assert got is (not expected), case
            differs.append(case)
    # The one difference the README names: Python's re matches a final $ before a final line feed.
    assert differs and all("final-line-feed" in case for case in differs)
    assert re.search("^ab$", "ab\n") is not None
