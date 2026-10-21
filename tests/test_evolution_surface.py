"""The evolution surface record v1 (EVOLUTION-SURFACE-001): the record, its schema and its reference model agree; every
vector replays; every invariant has a refusing vector; the derived gate-material list is PA-D5's list plus exactly the
owner-accepted extensions; and every file of this checkout falls in exactly one programme class (invariant 9)."""
import ast
import copy
import json
import os
from pathlib import Path

import jsonschema
import pytest

from scripts import evolution_surface as es

ROOT = Path(__file__).resolve().parents[1]
HERE = ROOT / "architecture/evolution-surface"
RECORD = es.load((HERE / "evolution-surface.json").read_bytes())
VECTORS = json.loads((HERE / "vectors.json").read_bytes())
SCHEMA = json.loads((HERE / "evolution-surface.schema.json").read_bytes())
VALIDATOR = jsonschema.Draft202012Validator(SCHEMA)


def code_of(doc):
    try:
        es.check(doc)
        return None
    except es.Refused as refusal:
        return refusal.code


def test_the_schema_is_a_valid_draft_2020_12_schema():
    jsonschema.Draft202012Validator.check_schema(SCHEMA)
    assert SCHEMA["$id"] == es.SCHEMA == RECORD["schemaVersion"]


def test_the_record_is_valid_and_pinned_by_the_vectors():
    facts = es.check(RECORD)
    assert facts["digest"] == VECTORS["recordDigest"]
    assert VALIDATOR.is_valid(RECORD)


def test_every_vector_replays():
    counts = es.replay(RECORD, VECTORS)
    assert counts["decisions"] == 44 and counts["invariants"] == 31 and counts["requests"] == 10
    assert counts["paths"] == 23 and counts["prs"] == 9
    assert counts["derived"] == 27 and counts["consumerCases"] == 12


def test_a_changed_vector_is_a_mismatch_even_without_asserts():
    # replay raises es.Mismatch explicitly, so `python -O` cannot strip the check (G1R1-10)
    changed = json.loads(json.dumps(VECTORS))
    changed["decisions"][0]["expect"] = {"decision": "ALLOWED", "reasons": []}
    with pytest.raises(es.Mismatch):
        es.replay(RECORD, changed)


def test_every_invariant_code_has_a_refusing_vector():
    expected = {row["expect"] for row in VECTORS["invariants"]}
    assert expected == set(es.CODES) - {"COVERAGE"}


def _shape_probes():
    """Records that differ from the valid record by one shape fault each, plus every invariant vector's record."""
    probes = [("record", RECORD)]
    probes += [(row["id"], es.mutate(RECORD, row["mutation"])) for row in VECTORS["invariants"]]
    probes += [(row["id"], row["record"]) for row in VECTORS["paths"] if "record" in row]
    faults = (("delete", None), ("null", None), ("int", 7), ("text", "x"), ("list", []), ("object", {}),
              ("bool", True), ("newline", "\n"))
    targets = [["schemaVersion"], ["surfaceId"], ["version"], ["operations"], ["levels"], ["levels", "product"],
               ["levels", "programme", "coverageSkip"], ["levels", "programme", "coverageSkip", "rootNames"],
               ["levels", "programme", "coverageSkip", "anyDepthFilePatterns", 0]]
    for level in ("product", "programme"):
        targets += [["levels", level, "roles"], ["levels", level, "roles", 0], ["levels", level, "roles", 0, "id"],
                    ["levels", level, "roles", 0, "kind"], ["levels", level, "roles", 0, "description"],
                    ["levels", level, "classes"]]
        for key in ("id", "description", "neverAutonomous", "appendOnly", "twoPerson", "approvalBinding", "governs",
                    "independentOf", "operations", "grounds"):
            targets.append(["levels", level, "classes", 0, key])
        targets += [["levels", level, "classes", 0, "operations", "approve"],
                    ["levels", level, "classes", 0, "operations", "approve", 0],
                    ["levels", level, "classes", 0, "grounds", 0]]
    targets += [["levels", "product", "roles", 0, "plane"], ["levels", "programme", "classes", 0, "paths"],
                ["levels", "programme", "classes", 0, "paths", 0], ["levels", "programme", "classes", 0, "paths", 0,
                                                                    "prefix"],
                ["levels", "programme", "classes", "#ORACLE_TESTS", "paths", 0, "name"],
                ["levels", "programme", "classes", "#ORACLE_TESTS", "paths", 0, "under"]]
    for target in targets:
        for name, value in faults:
            step = {"path": target, "delete": True} if name == "delete" else {"path": target, "value": value}
            probes.append(("%s:%s" % ("/".join(map(str, target)), name), es.mutate(RECORD, [step])))
    # a valid value with a final newline, for every patterned field (the patterns end with (?![\s\S]), not $)
    patterned = [["surfaceId"], ["levels", "product", "roles", 0, "id"], ["levels", "programme", "classes", 0, "id"],
                 ["levels", "product", "classes", 0, "operations", "approve", 0],
                 ["levels", "programme", "classes", "#ORACLE_TESTS", "independentOf", 0],
                 ["levels", "programme", "classes", 0, "paths", 0, "prefix"],
                 ["levels", "programme", "classes", "#GATE_CI", "paths", 2, "exact"],
                 ["levels", "programme", "classes", "#ORACLE_TESTS", "paths", 0, "under"],
                 ["levels", "programme", "classes", "#ORACLE_TESTS", "paths", 0, "name"],
                 ["levels", "programme", "coverageSkip", "rootNames", 0],
                 ["levels", "programme", "coverageSkip", "anyDepthFilePatterns", 0]]
    for target in patterned:
        node = RECORD
        for key in target:
            node = es._step(node, key) if type(key) is str and key.startswith("#") else node[key]
        probes.append(("%s:newline" % "/".join(map(str, target)), es.mutate(RECORD, [{"path": target,
                                                                                      "value": node + "\n"}])))
    return probes


def test_the_model_refuses_as_shape_exactly_when_the_schema_rejects():
    disagreements = []
    probes = _shape_probes()
    for name, doc in probes:
        schema_rejects = not VALIDATOR.is_valid(doc)
        model_shape = code_of(doc) == "SHAPE"
        if schema_rejects != model_shape:
            disagreements.append(name)
    assert disagreements == [] and len(probes) > 400


def test_beyond_the_schema_only_i_json_faults_are_shape():
    # The schema judges I-JSON values; a value that is not I-JSON (here a lone surrogate built in memory, which load()
    # refuses in text form) passes the schema but the model refuses it as SHAPE: the model is only stricter (G1R1-2).
    lone = es.mutate(RECORD, [{"path": ["levels", "product", "roles", 0, "description"], "value": "x\ud800"}])
    assert VALIDATOR.is_valid(lone) and code_of(lone) == "SHAPE"
    with pytest.raises(es.Refused):
        es.load(json.dumps(lone))


def test_allowed_carries_no_reasons_and_every_denial_starts_with_not_listed():
    for level in es.LEVELS:
        roles = [r["id"] for r in RECORD["levels"][level]["roles"]]
        for c in RECORD["levels"][level]["classes"]:
            for op in es.OPS:
                for role in roles:
                    got = es.decide(RECORD, level, role, c["id"], op)
                    if role in c["operations"][op]:
                        assert got == {"decision": "ALLOWED", "reasons": []}
                        # computed, not assumed: a listed request meets none of the five other reasons (G1R1-7)
                        assert not _reasons_beyond_listing(level, role, c, op)
                    else:
                        assert got["decision"] == "DENIED" and got["reasons"][0] == "NOT_LISTED"
                        assert got["reasons"] == [r for r in es.REASONS if r in got["reasons"]]


def _reasons_beyond_listing(level, role, c, op):
    kinds = {r["id"]: r["kind"] for r in RECORD["levels"][level]["roles"]}
    classes = {k["id"]: k for k in RECORD["levels"][level]["classes"]}
    ops = c["operations"]
    found = []
    if c["neverAutonomous"] and kinds[role] == "AGENT" and op in ("approve", "activate"):
        found.append("NEVER_AUTONOMOUS")
    if op == "approve" and role in c["governs"]:
        found.append("SELF_GOVERNANCE")
    if op == "approve" and kinds[role] != "HUMAN" and role in ops["generate"] + ops["test"]:
        found.append("SEPARATION_OF_DUTIES")
    if c["appendOnly"] and op in ("approve", "activate"):
        found.append("APPEND_ONLY")
    if op == "generate" and any(role in classes[k]["operations"]["generate"] for k in classes
                                if k != c["id"] and (k in c["independentOf"] or c["id"] in classes[k]["independentOf"])):
        found.append("INDEPENDENCE")
    return found


def test_unknown_names_in_a_request_are_refused():
    for args in (("planet", "OWNER", "GATE_CI", "approve"), ("programme", "NOBODY", "GATE_CI", "approve"),
                 ("programme", "OWNER", "NO_CLASS", "approve"), ("programme", "OWNER", "GATE_CI", "merge"),
                 ("product", "OWNER", "GATE_CI", "approve"), ("programme", ["OWNER"], "GATE_CI", "approve"),
                 ("programme", "OWNER", {"c": 1}, "approve"), (None, "OWNER", "GATE_CI", "approve")):
        with pytest.raises(es.Refused) as refusal:
            es.decide(RECORD, *args)
        assert refusal.value.code == "UNKNOWN_REFERENCE"


@pytest.mark.parametrize("path", ["", "/abs", "a//b", "./a", "a/../b", "a/", "a\x00b", None, 3])
def test_a_malformed_path_is_refused(path):
    with pytest.raises(es.Refused) as refusal:
        es.resolve(RECORD, path)
    assert refusal.value.code == "SHAPE"


def test_the_derivation_is_pa_d5_plus_exactly_the_owner_accepted_extensions():
    derivation = VECTORS["derivation"]
    accepted = [e for group in derivation["acceptedExtensions"] for e in group["entries"]]
    assert es.derive_gate_material(RECORD) == sorted(derivation["paD5"] + accepted, key=es.canonical)
    assert len(derivation["paD5"]) == 6 and len(accepted) == 21
    assert [group["id"] for group in derivation["acceptedExtensions"]] == (
        ["D1-i"] + ["C%d" % n for n in range(1, 14)])


def test_every_file_of_this_checkout_falls_in_exactly_one_class():
    report = es.check_coverage(RECORD, ROOT)
    assert report["unclassified"] == [] and report["ambiguous"] == []
    assert report["files"] > 2000 and sum(report["perClass"].values()) == report["files"]


def test_the_tree_listing_skips_by_components_and_never_follows_links(tmp_path):
    for rel in (".git", ".github/workflows/verify.yml", ".venv/lib/x.py", "docs/.venv/y.md", "a/__pycache__/m.pyc",
                "a/m.pyc", "a/.DS_Store", "a/b.py", "dist/z.txt"):
        target = tmp_path / rel
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text("x")
    (tmp_path / "outside").mkdir()
    (tmp_path / "outside" / "hidden.txt").write_text("x")
    os.symlink(tmp_path / "outside", tmp_path / "linked")
    listed = es.tree_paths(RECORD, tmp_path)
    assert listed == sorted([".github/workflows/verify.yml", "docs/.venv/y.md", "a/b.py", "dist/z.txt",
                             "outside/hidden.txt", "linked"])


def test_an_unclassified_file_fails_the_coverage_check(tmp_path):
    for rel in ("README.md", "ci/x.py", "NEWFILE.md"):
        target = tmp_path / rel
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text("x")
    with pytest.raises(es.Refused) as refusal:
        es.check_coverage(RECORD, tmp_path)
    assert refusal.value.code == "COVERAGE"


@pytest.mark.parametrize("make", ["missing", "file", "link"])
def test_the_tree_walk_fails_closed_on_a_bad_root(tmp_path, make):
    root = tmp_path / "root"
    if make == "file":
        root.write_text("x")
    elif make == "link":
        (tmp_path / "real").mkdir()
        os.symlink(tmp_path / "real", root)
    with pytest.raises(es.Refused) as refusal:
        es.check_coverage(RECORD, root)
    assert refusal.value.code == "COVERAGE"


def test_an_unreadable_directory_fails_the_walk(tmp_path):
    (tmp_path / "docs" / "locked").mkdir(parents=True)
    (tmp_path / "docs" / "locked" / "NEW.md").write_text("x")
    (tmp_path / "README.md").write_text("x")
    os.chmod(tmp_path / "docs" / "locked", 0)
    try:
        if os.access(tmp_path / "docs" / "locked", os.R_OK):
            pytest.skip("running with privileges that read any directory")
        with pytest.raises(es.Refused) as refusal:
            es.tree_paths(RECORD, tmp_path)
        assert refusal.value.code == "COVERAGE"
    finally:
        os.chmod(tmp_path / "docs" / "locked", 0o755)


@pytest.mark.parametrize("link,target,refused", [
    ("ci/served.py", "../docs/data.md", True),       # a link at a gate path serving data
    ("docs/view.py", "../ci/real.py", True),          # a data link reaching a gate file
    ("docs/tree", "../ci", True),                     # a data link reaching a gate directory
    ("docs/all", "..", True),                         # a data link reaching the whole tree
    ("docs/other.md", "data.md", False),              # a data link to data
])
def test_a_symbolic_link_may_not_be_or_reach_gate_material(tmp_path, link, target, refused):
    for rel in ("README.md", "docs/data.md", "ci/real.py"):
        (tmp_path / rel).parent.mkdir(parents=True, exist_ok=True)
        (tmp_path / rel).write_text("x")
    os.symlink(target, tmp_path / link)
    if refused:
        with pytest.raises(es.Refused) as refusal:
            es.check_coverage(RECORD, tmp_path)
        assert refusal.value.code == "COVERAGE"
    else:
        assert es.check_coverage(RECORD, tmp_path)["unclassified"] == []


@pytest.mark.parametrize("link,target", [
    ("ci/__pycache__", "../docs/cache"),               # a gate-path link named like a cache directory (G1R2-1)
    ("ci/real.cpython-312.pyc", "../docs/data.pyc"),    # a gate-path link named like bytecode
    ("ci/.DS_Store", "../docs/data.md"),                # a gate-path link named like a skipped file
    ("docs/__pycache__", "../ci"),                      # a data link named like a cache directory reaching a gate dir
    (".venv", "ci"),                                    # a root skip-name link reaching a gate dir
    ("docs/up", "../.."),                               # a data link to an ancestor of the tree (G1R2-2)
    ("docs/gone", "../nowhere"),                        # a dangling link
])
def test_every_link_is_judged_whatever_its_name_and_target(tmp_path, link, target):
    for rel in ("README.md", "docs/data.md", "docs/data.pyc", "docs/cache/x.md", "ci/real.py"):
        (tmp_path / rel).parent.mkdir(parents=True, exist_ok=True)
        (tmp_path / rel).write_text("x")
    os.symlink(target, tmp_path / link)
    with pytest.raises(es.Refused) as refusal:
        es.check_coverage(RECORD, tmp_path)
    assert refusal.value.code == "COVERAGE"


def test_a_link_target_is_judged_by_identity_not_spelling(tmp_path):
    # On a case-insensitive file system ../CI reaches ci/; on a case-sensitive one it dangles. Both are refused (G1R2-2).
    for rel in ("README.md", "docs/data.md", "ci/real.py"):
        (tmp_path / rel).parent.mkdir(parents=True, exist_ok=True)
        (tmp_path / rel).write_text("x")
    os.symlink("../CI", tmp_path / "docs" / "caps")
    with pytest.raises(es.Refused) as refusal:
        es.check_coverage(RECORD, tmp_path)
    assert refusal.value.code == "COVERAGE"


def test_an_entry_that_cannot_be_examined_fails_closed(tmp_path):
    (tmp_path / "docs" / "listed").mkdir(parents=True)
    (tmp_path / "docs" / "listed" / "x.md").write_text("x")
    (tmp_path / "README.md").write_text("x")
    os.chmod(tmp_path / "docs" / "listed", 0o444)  # listable, not searchable (G1R2-4)
    try:
        if os.access(tmp_path / "docs" / "listed" / "x.md", os.F_OK):
            pytest.skip("running with privileges that search any directory")
        with pytest.raises(es.Refused) as refusal:
            es.check_coverage(RECORD, tmp_path)
        assert refusal.value.code == "COVERAGE"
    finally:
        os.chmod(tmp_path / "docs" / "listed", 0o755)


def test_skip_named_links_are_judged_but_not_classified(tmp_path):
    root, outside = tmp_path / "root", tmp_path / "venv"
    outside.mkdir()
    for rel in ("README.md", "docs/data.md"):
        (root / rel).parent.mkdir(parents=True, exist_ok=True)
        (root / rel).write_text("x")
    os.symlink(outside, root / ".venv")   # a sibling outside the tree: allowed, and not classified
    report = es.check_coverage(RECORD, root)
    assert report["files"] == 2 and ".venv" not in es.tree_paths(RECORD, root)
    os.symlink(tmp_path, root / "docs" / "up")   # the tree's parent reaches the whole tree: refused
    with pytest.raises(es.Refused) as refusal:
        es.check_coverage(RECORD, root)
    assert refusal.value.code == "COVERAGE"


@pytest.mark.parametrize("link,target", [
    ("ci/__pycache__/real.cpython-312.pyc", "../../docs/data.pyc"),  # a link inside a skip directory (G1R3-1)
    ("docs/__pycache__/l", "../../ci"),                             # a data link inside a skip directory
    ("docs/.pytest_cache/l", "../../ci"),
    ("docs/harnesses", "../task-packets/p"),                        # a link in place of a gate directory (G1R3-2)
    ("tests/fixtures/zero-bill", "../../docs/cache"),
    ("docs/alpha-2", "../task-packets/p"),                          # holds gate docs (C5, C13 and the verifier doc)
    ("architecture/evolution-surface", "../docs/cache"),
])
def test_links_inside_skip_directories_and_in_place_of_gate_directories_are_refused(tmp_path, link, target):
    for rel in ("README.md", "docs/data.md", "docs/data.pyc", "docs/cache/x.md", "ci/real.py", "task-packets/p/x.yaml",
                "ci/__pycache__/keep.txt", "docs/__pycache__/keep.txt", "docs/.pytest_cache/keep.txt"):
        (tmp_path / rel).parent.mkdir(parents=True, exist_ok=True)
        (tmp_path / rel).write_text("x")
    (tmp_path / link).parent.mkdir(parents=True, exist_ok=True)
    os.symlink(target, tmp_path / link)
    with pytest.raises(es.Refused) as refusal:
        es.check_coverage(RECORD, tmp_path)
    assert refusal.value.code == "COVERAGE"
    assert es._gate_link(RECORD, str(tmp_path), link)


def test_a_root_link_in_place_of_a_gate_directory_is_refused_by_the_link_rule(tmp_path):
    (tmp_path / "docs" / "cache").mkdir(parents=True)
    os.symlink("docs/cache", tmp_path / "ci")
    assert es._gate_link(RECORD, str(tmp_path), "ci")


def test_a_link_is_classified_by_its_own_name_whatever_its_target(tmp_path):
    for rel in ("README.md", "docs/data.md", "docs/cache/x.md"):
        (tmp_path / rel).parent.mkdir(parents=True, exist_ok=True)
        (tmp_path / rel).write_text("x")
    os.symlink("cache", tmp_path / "docs" / "x.pyc")           # a link to a directory, named like bytecode
    os.symlink("data.md", tmp_path / "docs" / "y.pyc")         # a link to a file, named like bytecode
    os.symlink("cache", tmp_path / "docs" / "__pycache__")     # a link to a directory, named like a cache directory
    os.symlink("data.md", tmp_path / "docs" / "z_cache")       # an ordinary name
    listed = es.tree_paths(RECORD, tmp_path)
    assert "docs/x.pyc" not in listed and "docs/y.pyc" not in listed
    assert "docs/__pycache__" in listed and "docs/z_cache" in listed
    assert es.check_coverage(RECORD, tmp_path)["unclassified"] == []


@pytest.mark.parametrize("path", ["Docs/harnesses/x.md", "docs/Harnesses/x.md", "scripts/Evolution_Surface.py",
                                  "Conftest.py", "CI/x.py", "docs/Alpha-2/OWNER_OPERATED_VERIFIER.md",
                                  "architecture/Evolution-Surface-Authority.json"])
def test_a_case_variant_of_gate_material_falls_in_no_class(path):
    # F1 (owner Q-GOV-CAP): files and links alike, refused everywhere
    assert es.resolve(RECORD, path) is None
    assert es.pr_approvers(RECORD, [path]) is None and es.pr_activators(RECORD, [path]) is None
    with pytest.raises(es.Refused) as refusal:
        es.check_paths(RECORD, [path])
    assert refusal.value.code == "COVERAGE"


@pytest.mark.parametrize("link,target", [
    ("docs/Harnesses", "../task-packets/p"),
    ("architecture/Evolution-Surface-Authority.json", "../docs/data.md"),
    ("scripts/Evolution_Surface.py", "../docs/data.md"),
])
def test_a_link_at_a_case_variant_of_gate_material_is_refused(tmp_path, link, target):
    for rel in ("README.md", "docs/data.md", "task-packets/p/x.yaml"):
        (tmp_path / rel).parent.mkdir(parents=True, exist_ok=True)
        (tmp_path / rel).write_text("x")
    (tmp_path / link).parent.mkdir(parents=True, exist_ok=True)
    os.symlink(target, tmp_path / link)
    assert es._gate_link(RECORD, str(tmp_path), link)
    with pytest.raises(es.Refused) as refusal:
        es.check_coverage(RECORD, tmp_path)
    assert refusal.value.code == "COVERAGE"


def test_an_entry_that_vanished_inside_a_skip_directory_is_absent(tmp_path, monkeypatch):
    # F2: a bytecode writer's renamed temporary file is absent; a vanished entry elsewhere still fails closed
    for rel in ("README.md", "ci/x.py", "ci/__pycache__/x.cpython-312.pyc.tmp", "docs/gone.md"):
        (tmp_path / rel).parent.mkdir(parents=True, exist_ok=True)
        (tmp_path / rel).write_text("x")
    real_lstat = os.lstat

    def vanishing(*names):
        def lstat(path, *args, **kwargs):
            if str(path).endswith(names):
                raise FileNotFoundError(2, "vanished", str(path))
            return real_lstat(path, *args, **kwargs)
        return lstat

    monkeypatch.setattr(es.os, "lstat", vanishing(".pyc.tmp", "gone.md"))
    with pytest.raises(es.Refused) as refusal:
        es.check_coverage(RECORD, tmp_path)
    assert refusal.value.code == "COVERAGE"
    monkeypatch.setattr(es.os, "lstat", real_lstat)
    (tmp_path / "docs" / "gone.md").unlink()
    monkeypatch.setattr(es.os, "lstat", vanishing(".pyc.tmp"))
    assert es.check_coverage(RECORD, tmp_path)["unclassified"] == []


@pytest.mark.parametrize("vanished,refused", [
    ("ci/__pycache__/sub", False),   # a directory that vanished inside a skip directory is absent (F2)
    ("ci/__pycache__", True),        # a skip directory that itself vanished is not inside one: fails closed (G1R5-1)
    ("docs/sub", True),              # a directory that vanished elsewhere fails closed
])
def test_the_directory_branch_of_f2(tmp_path, monkeypatch, vanished, refused):
    for rel in ("README.md", "ci/x.py", "ci/__pycache__/sub/x.pyc", "docs/sub/x.md"):
        (tmp_path / rel).parent.mkdir(parents=True, exist_ok=True)
        (tmp_path / rel).write_text("x")
    real_scandir = os.scandir

    def scandir(path="."):
        if str(path).replace(os.sep, "/").endswith(vanished):
            raise FileNotFoundError(2, "vanished", str(path))
        return real_scandir(path)

    monkeypatch.setattr(es.os, "scandir", scandir)
    if refused:
        with pytest.raises(es.Refused) as refusal:
            es.check_coverage(RECORD, tmp_path)
        assert refusal.value.code == "COVERAGE"
    else:
        assert es.check_coverage(RECORD, tmp_path)["unclassified"] == []


def test_an_empty_root_is_refused():
    # G1R5-2: an empty root no longer means the current directory
    for call in (es.check_coverage, es.tree_paths):
        with pytest.raises(es.Refused) as refusal:
            call(RECORD, "")
        assert refusal.value.code == "COVERAGE"


def test_the_root_is_resolved_as_the_file_system_resolves_it(tmp_path):
    # G1R5-2: '..' after a linked component means what the file system means, not what the spelling suggests
    (tmp_path / "x" / "sub").mkdir(parents=True)
    (tmp_path / "x" / "tree").mkdir()
    (tmp_path / "x" / "tree" / "README.md").write_text("x")
    os.symlink(tmp_path / "x" / "sub", tmp_path / "link")
    assert es.check_coverage(RECORD, str(tmp_path / "link") + "/../tree")["files"] == 1


@pytest.mark.parametrize("suffix", ["/", "/."])
def test_a_linked_root_is_refused_however_it_is_written(tmp_path, suffix):
    # F3: the root is normalized before the linked-root check
    (tmp_path / "real").mkdir()
    (tmp_path / "real" / "README.md").write_text("x")
    os.symlink(tmp_path / "real", tmp_path / "root")
    with pytest.raises(es.Refused) as refusal:
        es.check_coverage(RECORD, str(tmp_path / "root") + suffix)
    assert refusal.value.code == "COVERAGE"


def test_every_function_judges_the_record_first():
    broken = es.mutate(RECORD, [{"path": ["version"], "value": 0}])
    calls = (lambda: es.decide(broken, "programme", "OWNER", "GATE_CI", "approve"),
             lambda: es.resolve(broken, "ci/x.py"), lambda: es.pr_approvers(broken, ["ci/x.py"]),
             lambda: es.pr_activators(broken, ["ci/x.py"]), lambda: es.derive_gate_material(broken),
             lambda: es.coverage(broken, ["ci/x.py"]), lambda: es.skipped(broken, "ci/x.py"),
             lambda: es.check_paths(broken, ["ci/x.py"]))
    for call in calls:
        with pytest.raises(es.Refused) as refusal:
            call()
        assert refusal.value.code == "SHAPE"


def test_the_record_is_not_mutated_by_any_question():
    before = copy.deepcopy(RECORD)
    es.replay(RECORD, VECTORS)
    assert RECORD == before


def test_the_model_uses_the_standard_library_only():
    tree = ast.parse((ROOT / "scripts/evolution_surface.py").read_text(encoding="utf-8"))
    imported = {alias.name.split(".")[0] for node in ast.walk(tree) if isinstance(node, ast.Import)
                for alias in node.names}
    imported |= {node.module.split(".")[0] for node in ast.walk(tree) if isinstance(node, ast.ImportFrom)}
    assert imported <= {"__future__", "fnmatch", "hashlib", "json", "math", "os", "re", "stat", "pathlib"}


def test_the_vectors_name_their_grounds_and_keep_the_consumer_cases():
    assert all(row["grounds"] for row in VECTORS["decisions"])
    assert {row["grounds"] for row in VECTORS["consumerCases"]} >= {"E2E-10", "E2E-13", "E2E-14", "E2E-16", "P28"}
