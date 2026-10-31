"""D5a oracle tests for MET-PERF-044 (CHAIN-PRODUCT-PUBLISH-001), the chain product-packet vocabulary.

Owner decision D5a requires a contract packet to carry tests written outside the candidate, by someone who is not
its builder. These are black-box tests: every expected value comes from the contract's own records, never from the
candidate's code:

- ``architecture/chain-product-packets/README.md`` (the contract text): the P-forms F1-F7 and their classes, the
  refusal ids and clauses R1-R12 and R12-L, the vector sections and their counts, the agreement and verifier
  columns, the binding reader's plain spelling, the line rule's refused name and the design digest;
- ``architecture/chain-product-packets/rule.json``: the pins (``extends``, the decisions record, the twelve names),
  the ``productId`` form, the line rule (``productRepository.reader``), the ``allowedPaths`` formula and the
  ``bumpVocabulary`` (i-p)/(ii-p)/(iii-p)/(v-p) with ``nReading``;
- ``architecture/chain-product-packets/vectors.json``: every case's ``expect``, ``refusal``, ``clause`` and
  ``detail``, the classForms bases and the agreement rows;
- ``architecture/repositories.yaml``: the repository ``name`` members, read here with the repository's own
  ``scripts/safe_yaml.safe_load``, from which the twelve allowed names are derived independently.

Outcomes of the vectors and of this file's own variants are model-derived: they come from running the public
evaluators of ``scripts/chain_identity_v2.py`` (``check_step_vector``, ``check_products``, ``check_counts``,
``layer_products``, ``check_allowed_paths``, ``check_class_vector``), loaded by file path. Mutations enter only
through the models' own inputs (records, vectors and layer source text built here). Where the README ties no clause
to a mutation, the test asserts only that it is refused and says so.
"""

from __future__ import annotations

import ast
import hashlib
import importlib.util
import json
import re
import textwrap
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
CPP = ROOT / "architecture" / "chain-product-packets"
README_PATH = CPP / "README.md"
RULE_PATH = CPP / "rule.json"
VECTORS_PATH = CPP / "vectors.json"
DECISIONS_PATH = CPP / "decisions.md"
IDENTITY_RULE_PATH = ROOT / "architecture" / "chain-compaction" / "identity-rule.json"
REPOSITORIES_PATH = ROOT / "architecture" / "repositories.yaml"


def _load(name: str, relative: str):
    spec = importlib.util.spec_from_file_location(name, ROOT / relative)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


V1 = _load("chain_identity", "scripts/chain_identity.py")
SAFE_YAML = _load("safe_yaml", "scripts/safe_yaml.py")
V2 = _load("chain_identity_v2", "scripts/chain_identity_v2.py")

README = README_PATH.read_text(encoding="utf-8")
EXT = json.loads(RULE_PATH.read_text(encoding="utf-8"))
VECTORS = json.loads(VECTORS_PATH.read_text(encoding="utf-8"))
IDENTITY_RULE = json.loads(IDENTITY_RULE_PATH.read_text(encoding="utf-8"))
BASES = VECTORS["classForms"]["bases"]

BINDING = "PRODUCT_PACKETS"
MODEL_SECTIONS = ("steps", "products", "counts", "bindings", "allowedPaths")
EVALUATED = MODEL_SECTIONS + ("classForms",)


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _readme_section(title: str) -> str:
    start = README.index("## " + title + "\n")
    end = README.find("\n## ", start + 1)
    return README[start:] if end == -1 else README[start:end]


# ---- README-derived constants -------------------------------------------------------------------------------------

REFUSALS_TEXT = _readme_section("Refusals")
PFORMS_TEXT = _readme_section("The accepted P-forms")
VECTORS_TEXT = _readme_section("The vectors")
README_REFUSAL_IDS = re.findall(r"^- \*\*(R\d+(?:-L)?)\*\*", REFUSALS_TEXT, re.M)
# The vectors section: a refusing case names `refusal` (the id above, or `P-form`, `D`, `G1`, `G2`).
README_CLASS_IDS = ("P-form", "D", "G1", "G2")
REFUSED_NAME = re.search(r"\*\*R3\*\*, a product whose `repository` \(the line rule\) is `([^`]+)`",
                         REFUSALS_TEXT).group(1)
F_BULLETS = {
    m.group(1): (m.group(2), m.group(3), re.findall(r"`([^`]+)`", m.group(4)))
    for m in re.finditer(r"^- \*\*(F[1-7])\*\*, `(\w+)` \((D|G1|G2)\): (.*?)(?=^- \*\*F|^\s*$)", PFORMS_TEXT,
                         re.M | re.S)
}
F7_BLOCK = re.search(r"```python\n(.*?)\n```", PFORMS_TEXT, re.S).group(1)
DESIGN_SHA = re.search(r"sha256\s+`([0-9a-f]{64})`", README).group(1)
ID_PATH = re.compile(EXT["productList"]["productId"][1])


def _repository_names() -> list[str]:
    document = SAFE_YAML.safe_load(REPOSITORIES_PATH.read_text(encoding="utf-8"))
    return [entry["name"] for entry in document["repositories"]]


ALL_NAMES = _repository_names()
TWELVE = [name for name in ALL_NAMES if name != REFUSED_NAME]


# ---- model drivers ------------------------------------------------------------------------------------------------

def _message(call) -> str | None:
    """Run one evaluator; None when it accepts, else the refusal's message (a ValueError, README Refusals)."""
    try:
        call()
    except ValueError as exc:
        return str(exc)
    return None


def _assert_refused(call, clause=None, clauses=None, detail=None) -> str:
    message = _message(call)
    assert message is not None, "accepted, expected a refusal"
    assert re.match(r"identity [^ ]+: ", message), message
    if clause is not None:
        assert message.startswith("identity " + clause + ": "), message
    if clauses is not None:
        assert any(message.startswith("identity " + c + ": ") for c in clauses), message
    if detail is not None:
        assert detail in message, message
    return message


def _read_packet(files):
    def read(path):
        assert path.startswith("task-packets/") and path.endswith(".yaml"), path
        return files[path[len("task-packets/"):-len(".yaml")]].encode("utf-8")
    return read


def run_products(listed, files, chain=()):
    return V2.check_products(EXT, {int(slot): tuple(ids) for slot, ids in listed.items()}, _read_packet(files),
                             SAFE_YAML.safe_load, tuple(chain))


def run_allowed(c):
    return V2.check_allowed_paths(c["allowed"], c["changed"], c["new"], c["authority"], c["validator"],
                                  c["ownYaml"], c["products"])


def run_class(case):
    return V2.check_class_vector(case, BASES, IDENTITY_RULE, V1)


def evaluate(section, case):
    if section == "steps":
        return lambda: V2.check_step_vector(case, V1)
    if section == "products":
        return lambda: run_products(case["listed"], case["files"], case.get("chainPackets", ()))
    if section == "counts":
        return lambda: V2.check_counts(case["slot"], case["catalog"], case["products"])
    if section == "bindings":
        return lambda: V2.layer_products(ast.parse(case["source"]))
    if section == "allowedPaths":
        return lambda: run_allowed(case)
    if section == "classForms":
        return lambda: run_class(case)
    raise AssertionError(section)


def _cases(section):
    return VECTORS["classForms"]["cases"] if section == "classForms" else VECTORS[section]


ALL_EVALUATED = [(section, case) for section in EVALUATED for case in _cases(section)]


# ---- independent readings of the contract (no model code) ---------------------------------------------------------

def independent_counts(slot, catalog, products) -> bool:
    """rule.json counts: C = S + P, P the sum of K over every layer that binds the list."""
    return catalog == slot + sum(len(layer) for layer in products)


def independent_allowed(c) -> set[str]:
    """rule.json productList.allowedPaths: changedFiles | newFiles | {authority, validator, own YAML} | products."""
    return (set(c["changed"]) | set(c["new"]) | {c["authority"], c["validator"], c["ownYaml"]}
            | {"task-packets/" + p + ".yaml" for p in c["products"]})


def independent_line(text):
    """rule.json productRepository.reader: one 'repository:' line, stripped, JSON-decoded on '"', a string."""
    lines = [line for line in text.splitlines() if line.startswith("repository:")]
    if len(lines) != 1:
        return None
    value = lines[0][len("repository:"):].strip()
    if value.startswith('"'):
        try:
            value = json.loads(value)
        except ValueError:
            return None
    return value if isinstance(value, str) else None


def independent_products(listed, files, chain=()):
    """README R2, R3, R8 clause 2 and R12 applied in the README's order to each listed product; None when valid."""
    for slot in sorted(listed, key=int):
        for pid in listed[slot]:
            if not ID_PATH.fullmatch("task-packets/" + pid + ".yaml") or pid in chain:
                return "R2"
            text = files[pid]
            document = SAFE_YAML.safe_load(text)
            if not isinstance(document, dict) or document.get("id") != pid:
                return "R2"
            value = independent_line(text)
            if value is None:
                return "R12"
            if value == REFUSED_NAME:
                return "R3"
            if value not in TWELVE:
                return "R8"
            if document.get("repository") != value:
                return "R12"
    return None


def independent_binding(source):
    """README R7 (1): only exactly one top-level plain `PRODUCT_PACKETS = (<ids>,)` is read; any other binding of
    the name refuses; the list is a non-empty tuple of distinct productId strings. Returns the tuple or 'refuse'."""
    tree = ast.parse(source)
    plain = [node for node in tree.body
             if isinstance(node, ast.Assign) and len(node.targets) == 1
             and isinstance(node.targets[0], ast.Name) and node.targets[0].id == BINDING]
    plain_targets = {id(node.targets[0]) for node in plain}
    others = 0
    for node in ast.walk(tree):
        if (isinstance(node, ast.Name) and node.id == BINDING and isinstance(node.ctx, (ast.Store, ast.Del))
                and id(node) not in plain_targets):
            others += 1
        elif isinstance(node, (ast.Global, ast.Nonlocal)) and BINDING in node.names:
            others += 1
        elif isinstance(node, ast.alias) and (node.name == "*" or (node.asname or node.name.split(".")[0]) == BINDING):
            others += 1
        elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)) and node.name == BINDING:
            others += 1
        elif isinstance(node, ast.arg) and node.arg == BINDING:
            others += 1
        elif isinstance(node, ast.ExceptHandler) and node.name == BINDING:
            others += 1
        elif isinstance(node, (ast.MatchAs, ast.MatchStar)) and node.name == BINDING:
            others += 1
        elif isinstance(node, ast.MatchMapping) and node.rest == BINDING:
            others += 1
        elif isinstance(node, (ast.TypeVar, ast.ParamSpec, ast.TypeVarTuple)) and node.name == BINDING:
            others += 1
    if others or len(plain) > 1:
        return "refuse"
    if not plain:
        return ()
    value = plain[0].value
    if not isinstance(value, ast.Tuple) or not value.elts:
        return "refuse"
    ids = []
    for element in value.elts:
        if not (isinstance(element, ast.Constant) and type(element.value) is str
                and ID_PATH.fullmatch("task-packets/" + element.value + ".yaml")):
            return "refuse"
        ids.append(element.value)
    return tuple(ids) if len(set(ids)) == len(ids) else "refuse"


# ==== 1. rule.json's pins ==========================================================================================

def test_rule_schema_and_readme_members():
    """rule.json schema (model constant SCHEMA, model-derived) and the members README 'The records' names: counts
    S/C/P with C = S + P, nReading, the (i-p)-(v-p), (ix-p), (x-p) vocabulary, productId, productRepository,
    allowedPaths, the refusals R1-R12; check_ext accepts it (model-derived)."""
    assert EXT["schemaVersion"] == V2.SCHEMA
    assert EXT["packet"] == "MET-PERF-044"
    assert set(EXT["counts"]) >= {"S", "C", "P", "relation"}
    assert "C = S + P" in EXT["counts"]["relation"]
    reading = EXT["nReading"]
    for clause in ("i", "ii", "x"):
        assert reading[clause] == "N := C"
    assert reading["iii"].startswith("N := S") and "d = S - L" in reading["iii"]
    assert reading["v"].startswith("N := S") and "L = S - 2" in reading["v"]
    assert set(EXT["bumpVocabulary"]) == {"i-p", "ii-p", "iii-p", "iv-p", "v-p"}
    assert set(EXT["bridgeVocabulary"]) == {"ix-p", "x-p"}
    assert EXT["productList"]["binding"] == BINDING
    assert EXT["productList"]["authorityField"] == "productPackets"
    assert EXT["productRepository"]["refusedName"] == REFUSED_NAME
    assert EXT["refusals"] == ["R" + str(n) for n in range(1, 13)]
    assert [r for r in README_REFUSAL_IDS if r != "R12-L"] == EXT["refusals"]
    pattern = V2.check_ext(EXT)
    assert pattern.pattern == EXT["productList"]["productId"][1]


def test_rule_extends_identity_rule_by_digest():
    """rule.json `extends` (README 'The records': identity-rule.json cited by digest): sha256 of the file's bytes."""
    extends = EXT["extends"]
    assert extends["path"] == "architecture/chain-compaction/identity-rule.json"
    assert extends["sha256"] == _sha256(IDENTITY_RULE_PATH)


def test_rule_pins_decisions_digest():
    """rule.json evidence.ownerDecision (README 'The records': decisions.md holds Q-SEC3-TWO): file sha256."""
    decision = EXT["evidence"]["ownerDecision"]
    assert decision["id"] == "Q-SEC3-TWO"
    assert decision["record"]["path"] == "architecture/chain-product-packets/decisions.md"
    assert decision["record"]["sha256"] == _sha256(DECISIONS_PATH)
    assert EXT["evidence"]["vectors"] == "architecture/chain-product-packets/vectors.json"


def test_rule_twelve_names_equal_repositories_yaml():
    """rule.json productRepository.allowedNames (README 'The records': the twelve allowed names of
    repositories.yaml at dd000fef, the refused name): derived here from the yaml's `name` members."""
    allowed = EXT["productRepository"]["allowedNames"]
    assert allowed["record"] == "architecture/repositories.yaml"
    assert allowed["member"] == "name"
    assert allowed["revision"].startswith("dd000fef")
    assert allowed["sha256"] == _sha256(REPOSITORIES_PATH)
    assert REFUSED_NAME in ALL_NAMES
    assert len(ALL_NAMES) == len(set(ALL_NAMES)) == 13
    assert len(TWELVE) == 12
    assert allowed["names"] == TWELVE


# ==== 2. vectors.json's shape =======================================================================================

def test_vectors_schema_sections_and_evaluators():
    """vectors.json schema (model constant VECTORS_SCHEMA; check_vectors_record accepts it, model-derived), the
    sections README 'The vectors' lists, the evaluator each names, and the design digest README 'This directory'."""
    assert VECTORS["schemaVersion"] == V2.VECTORS_SCHEMA
    assert VECTORS["rule"] == "architecture/chain-product-packets/rule.json"
    assert VECTORS["design"]["sha256"] == DESIGN_SHA
    V2.check_vectors_record(VECTORS)
    sections = {"steps", "products", "counts", "bindings", "allowedPaths", "classForms", "agreement",
                "bridgeReplay", "headOnly"}
    assert set(VECTORS["evaluators"]) == sections
    assert sections <= set(VECTORS)
    for section in sections:
        assert "`" + section + "`" in VECTORS_TEXT
    named = {"steps": "check_step_vector", "products": "check_products", "counts": "check_counts",
             "bindings": "layer_products", "allowedPaths": "check_allowed_paths", "classForms": "check_class_vector"}
    for section, function in named.items():
        assert "(`" + function + "`)" in VECTORS_TEXT
        assert VECTORS["evaluators"][section] == "chain_identity_v2." + function
        assert callable(getattr(V2, function))


def test_vectors_case_ids_unique():
    """vectors.json: every case id is unique, within each section and across all sections."""
    ids = [case["id"] for section in ("steps", "products", "counts", "bindings", "allowedPaths", "agreement",
                                      "bridgeReplay", "headOnly") for case in VECTORS[section]]
    ids += [case["id"] for case in VECTORS["classForms"]["cases"]]
    assert len(ids) == len(set(ids))


@pytest.mark.parametrize("section", EVALUATED)
def test_vectors_case_fields(section):
    """README 'The vectors': each case has `expect` (OK or refuse); a refusing case names `refusal` (an id of
    README Refusals, or P-form, D, G1, G2), `clause` and `detail`."""
    allowed = set(README_REFUSAL_IDS) | set(README_CLASS_IDS)
    for case in _cases(section):
        assert case["expect"] in ("OK", "refuse"), case["id"]
        if case["expect"] == "OK":
            assert case["refusal"] is None and case["clause"] is None and case["detail"] is None, case["id"]
        else:
            assert case["refusal"] in allowed, case["id"]
            assert isinstance(case["clause"], str) and case["clause"], case["id"]
            assert isinstance(case["detail"], str) and case["detail"], case["id"]


def test_vectors_counts_the_readme_states():
    """README 'The vectors': steps carry K0, K1, K2, K0+ (the 275 step), (iv) at 189 and their refusals (R9/R10,
    clause step); classForms has the two bases and K0, K1, K2, K0+ passing, CF-K0-with-F6 as R7's second clause;
    agreement has 22 rows (11 cases at K = 1 and K = 2); headOnly is R4, R5, R6, R7; bridgeReplay has 5 items."""
    steps = VECTORS["steps"]
    ok = [c for c in steps if c["expect"] == "OK"]
    assert any(c["K"] == 0 and c["S"] == c["C"] for c in ok)
    assert any(c["K"] == 1 and c["L"] != 189 for c in ok)
    assert any(c["K"] == 2 for c in ok)
    assert any(c["K"] == 0 and c["S"] == 275 and c["C"] == 276 for c in ok)
    assert any(c["L"] == 189 for c in ok)
    for case in steps:
        if case["expect"] == "refuse":
            assert case["refusal"] in ("R9", "R10") and case["clause"] == "step", case["id"]
    class_forms = VECTORS["classForms"]
    assert set(class_forms["bases"]) == {"head", "bridged"}
    five = {"authority", "_packet_byte_rules", "historical_bytes", "historical_catalog", "validate_packet_payloads"}
    for base in class_forms["bases"].values():
        assert {node.name for node in ast.parse(base).body if isinstance(node, ast.FunctionDef)} == five
    cf_ok = [c for c in class_forms["cases"] if c["expect"] == "OK"]
    assert any(c["base"] == "head" and not c["products"] for c in cf_ok)
    assert any(c["base"] == "head" and len(c["products"]) == 1 for c in cf_ok)
    assert any(c["base"] == "head" and len(c["products"]) == 2 for c in cf_ok)
    assert any(c["base"] == "bridged" and c["products"] for c in cf_ok)
    for case in class_forms["cases"]:
        if case["expect"] == "refuse":
            assert case["clause"] in README_CLASS_IDS, case["id"]
    f6 = {c["id"]: c for c in class_forms["cases"]}["CF-K0-with-F6"]
    assert (f6["refusal"], f6["clause"], f6["products"]) == ("R7", "P-form", [])
    rows = VECTORS["agreement"]
    assert len(rows) == 22
    assert sorted((int(r["case"]), r["K"]) for r in rows) == sorted((n, k) for n in range(1, 12) for k in (1, 2))
    assert [h["id"] for h in VECTORS["headOnly"]] == ["R4", "R5", "R6", "R7"]
    assert len(VECTORS["bridgeReplay"]) == 5


def test_vectors_products_counts_bindings_allowed_cover_readme():
    """README 'The vectors': products, counts, bindings and allowedPaths carry R1-R3, R7, R8, R11, R12, R12-L and the
    valid K = 1 and K = 2 cases."""
    refusals = {c["refusal"] for s in MODEL_SECTIONS[1:] for c in VECTORS[s] if c["refusal"]}
    assert refusals == {"R1", "R2", "R3", "R7", "R8", "R11", "R12"}
    r12l = {c["id"]: c for c in VECTORS["products"]}["R12-L"]
    assert r12l["refusal"] == "R12" and len(r12l["listed"]) >= 2
    sizes = {"products": lambda c: sum(len(v) for v in c["listed"].values()),
             "counts": lambda c: sum(len(v) for v in c["products"]),
             "allowedPaths": lambda c: len(c["products"])}
    for section, size in sizes.items():
        ks = {size(c) for c in VECTORS[section] if c["expect"] == "OK"}
        assert {1, 2} <= ks, section
    assert any(c["expect"] == "OK" for c in VECTORS["bindings"])


def test_every_readme_refusal_id_appears():
    """README Refusals (R1-R12, R12-L) and the P-form, D, G1, G2 classes each appear in at least one case: as a case's
    `refusal`, as a headOnly id (R4, R5, R6, R7), or as the products case R12-L (refusal R12)."""
    assert README_REFUSAL_IDS == ["R" + str(n) for n in range(1, 13)] + ["R12-L"]
    seen = {c["refusal"] for _, c in ALL_EVALUATED if c["refusal"]}
    seen |= {h["id"] for h in VECTORS["headOnly"]}
    seen |= {c["id"] for c in VECTORS["products"] if c["id"] == "R12-L" and c["refusal"] == "R12"}
    for rid in README_REFUSAL_IDS + list(README_CLASS_IDS):
        assert rid in seen, rid


def test_head_only_and_bridge_replay_name_their_proofs():
    """README 'The vectors': headOnly is R4, R5, R6 and R7's second clause, each with the head check that enforces
    it; bridgeReplay is (ix-p), (x-p), the 275 step's S-based phrases, (v) at layer 274 and the K = 0 era
    equivalence, each with the run that proves it."""
    for item in VECTORS["headOnly"]:
        assert isinstance(item["where"], str) and len(item["where"]) > 20, item["id"]
    r7 = {h["id"]: h for h in VECTORS["headOnly"]}["R7"]
    assert "clause 2" in r7["where"] and "productPackets" in r7["where"]
    replay = VECTORS["bridgeReplay"]
    for item in replay:
        assert isinstance(item["provedBy"], str) and len(item["provedBy"]) > 20, item["id"]
    texts = [item["id"] + " " + item["case"] for item in replay]
    assert any("(ix-p)" in t for t in texts)
    assert any("x-p" in t and "(ix-p)" not in t and "275" in t for t in texts)
    assert any("S-based phrases" in t for t in texts)
    assert any("(v)" in t and "274" in t for t in texts)
    assert any("K = 0" in t for t in texts)


# ==== 3. every model-evaluated vector ===============================================================================

@pytest.mark.parametrize("section,case", ALL_EVALUATED,
                         ids=[s + ":" + c["id"] for s, c in ALL_EVALUATED])
def test_vector_outcome_and_clause(section, case):
    """vectors.json, each model-evaluated case: the outcome it states, and for a refusal a ValueError whose message
    starts `identity <clause>: ` (README Refusals) and holds its detail. Model-derived (the named evaluator)."""
    call = evaluate(section, case)
    if case["expect"] == "OK":
        assert _message(call) is None
    else:
        _assert_refused(call, clause=case["clause"], detail=case["detail"])


@pytest.mark.parametrize("case", VECTORS["counts"], ids=[c["id"] for c in VECTORS["counts"]])
def test_counts_vectors_independently(case):
    """rule.json counts (C = S + P): each counts case's expect, derived without the model."""
    assert independent_counts(case["slot"], case["catalog"], case["products"]) == (case["expect"] == "OK")


@pytest.mark.parametrize("case", VECTORS["allowedPaths"], ids=[c["id"] for c in VECTORS["allowedPaths"]])
def test_allowed_paths_vectors_independently(case):
    """rule.json productList.allowedPaths (equality with the product-aware list): each case's expect, derived without
    the model; expected_allowed_paths gives the same set (model-derived)."""
    expected = independent_allowed(case)
    assert (set(case["allowed"]) == expected) == (case["expect"] == "OK")
    model = V2.expected_allowed_paths(case["changed"], case["new"], case["authority"], case["validator"],
                                      case["ownYaml"], case["products"])
    assert set(model) == expected


@pytest.mark.parametrize("case", VECTORS["products"], ids=[c["id"] for c in VECTORS["products"]])
def test_products_vectors_independently(case):
    """README R2, R3, R8 clause 2 and R12 with rule.json's productId and line rule: each products case's refusal id
    (None when valid), derived without the model."""
    assert independent_products(case["listed"], case["files"], case.get("chainPackets", ())) == case["refusal"]


@pytest.mark.parametrize("case", VECTORS["bindings"], ids=[c["id"] for c in VECTORS["bindings"]])
def test_bindings_vectors_independently(case):
    """README R7 (1) plain-spelling reader: each bindings case's expect, derived without the model."""
    verdict = independent_binding(case["source"])
    assert (verdict != "refuse") == (case["expect"] == "OK")


def _pin_and_message(source):
    pins = re.findall(r"len\(paths\) == (\d+)", source)
    messages = re.findall(r"closed (\d+)-packet catalog", source)
    return [int(x) for x in pins], [int(x) for x in messages]


@pytest.mark.parametrize("case", VECTORS["steps"], ids=[c["id"] for c in VECTORS["steps"]])
def test_step_pins_follow_bump_vocabulary(case):
    """rule.json bumpVocabulary (i-p)/(ii-p) with nReading (i), (ii) N := C: in a valid step the count pin and the
    message move C-1-K -> C; an R10 case moves one of them otherwise. Derived without the model."""
    before, after = _pin_and_message(case["before"]), _pin_and_message(case["after"])
    old, new = case["C"] - 1 - case["K"], case["C"]
    follows = all(b == old for b in before[0] + before[1]) and all(a == new for a in after[0] + after[1])
    if case["expect"] == "OK":
        assert follows, case["id"]
    if case["refusal"] == "R10":
        assert before[0] + before[1], case["id"]
        assert not follows, case["id"]


# ==== 4. the 22 agreement rows ======================================================================================

def _named_case(reference):
    section, cid = reference.split(":", 1)
    pool = _cases(section) if section in EVALUATED else VECTORS[section]
    matches = [c for c in pool if c["id"] == cid]
    assert len(matches) == 1, reference
    return section, matches[0]


@pytest.mark.parametrize("row", VECTORS["agreement"], ids=[r["id"] for r in VECTORS["agreement"]])
def test_agreement_row(row):
    """README 'The vectors' agreement: verify's outcome equals the head's in every row, and the head column names
    vectors (section:id) that exist and prove it (their outcome, model-derived, and refusal id agree)."""
    head = row["head"]
    assert head["expect"] in ("OK", "refuse")
    if head["expect"] == "OK":
        assert row["verify"] == "passes"
    else:
        assert row["verify"] in ("refused", "refused via argv 63")
    assert head["by"]
    for reference in head["by"]:
        section, case = _named_case(reference)
        if section == "headOnly":
            assert head["expect"] == "refuse" and case["id"] == head["refusal"]
            continue
        assert case["expect"] == head["expect"], reference
        if head["refusal"] is not None:
            assert case["refusal"] == head["refusal"], reference
        outcome = _message(evaluate(section, case))
        assert (outcome is None) == (head["expect"] == "OK"), reference


@pytest.mark.parametrize("row", VECTORS["agreement"], ids=[r["id"] for r in VECTORS["agreement"]])
def test_agreement_verifier_column_follows_readme(row):
    """README Refusals, verifier side: R1 part 2 when absent from allowedPaths else via argv 63; R3 part 1; R8 clause 1
    head-only (argv 63), clause 2 part 2; R11 lacking a product part 2, another task-packets/ path via argv 63; R12
    chain-only via argv 63. A verifier that accepts a refused row leaves verify to argv 63."""
    refusal, verifier, verify = row["head"]["refusal"], row["verifier"], row["verify"]
    if row["head"]["expect"] == "OK":
        assert verifier == "accepts"
        return
    assert (verify == "refused via argv 63") == (verifier == "accepts")
    expected = None
    if refusal == "R1":
        expected = "accepts" if "allowedPaths" in row["description"] else "refuses (2)"
    elif refusal == "R3":
        expected = "refuses (1)"
    elif refusal == "R8":
        expected = "accepts" if "clause 1" in (row["head"]["note"] or "") else "refuses (2)"
    elif refusal == "R11":
        expected = "refuses (2)" if "listed product" in row["description"] else "accepts"
    elif refusal == "R12":
        expected = "accepts"
    if expected is not None:
        assert verifier == expected, row["id"]


# ==== 5. the P-form shapes F1-F7 ====================================================================================

ANCHOR_F7 = '    for name, expected in value["baselinePackets"].items():\n'
ALL_F = ("F1", "F2", "F3", "F4", "F5", "F6", "F7")


def f7_statement(block=F7_BLOCK):
    return textwrap.indent(block, "    ") + "\n"


def fragment_edit(f):
    """Each fragment as README 'The accepted P-forms' states it, written over the K = 0 base text."""
    if f in ("F1", "F2", "F3", "F4"):
        _, _, spans = F_BULLETS[f]
        return [spans[1], spans[0]]
    if f == "F5":
        return ['**{NEW_PACKET: record["packetSha256"]})',
                '**{NEW_PACKET: record["packetSha256"]}, **record["productPackets"])']
    if f == "F6":
        return ['"validatorNormalizedSha256",\n    }', '"validatorNormalizedSha256", "productPackets",\n    }']
    if f == "F7":
        return [ANCHOR_F7, f7_statement() + ANCHOR_F7]
    raise AssertionError(f)


def full(without=()):
    return [fragment_edit(f) for f in ALL_F if f not in without]


def class_case(cid, edits, products, base="head"):
    text = BASES[base]
    for old, new in edits:
        assert text.count(old) == 1, (cid, old)
        text = text.replace(old, new)
    return {"id": cid, "base": base, "edits": [list(e) for e in edits], "products": list(products)}


K1 = ["IND-BANK-001"]
K2 = ["IND-BANK-002", "IND-BANK-003"]
K3 = ["IND-BANK-004", "IND-BANK-005", "IND-BANK-006"]


def test_readme_p_forms_match_the_model_constants():
    """README 'The accepted P-forms' F1-F7: each fragment, its undo and its class function agree with the model's
    public constants P_FORMS and AUTHORITY_CHECK (by AST), and p_form_counts() is one of each per function."""
    classes = {"F1": ("historical_catalog", "D"), "F2": ("historical_catalog", "D"),
               "F3": ("validate_packet_payloads", "G1"), "F4": ("validate_packet_payloads", "G1"),
               "F5": ("_packet_byte_rules", "G1"), "F6": ("authority", "G2"), "F7": ("authority", "G2")}
    assert {f: (fn, cls) for f, (fn, cls, _) in F_BULLETS.items()} == classes
    forms = {entry[0]: entry for entry in V2.P_FORMS}
    assert set(forms) == {"F1", "F2", "F3", "F4", "F5", "F6"}

    def same(a, b):
        return ast.dump(ast.parse(a, mode="eval")) == ast.dump(ast.parse(b, mode="eval"))

    for f in ("F1", "F2", "F3", "F4"):
        _, _, spans = F_BULLETS[f]
        assert forms[f][1] == classes[f][0]
        assert same(forms[f][2], spans[0]) and same(forms[f][3], spans[1]), f
    f5 = ast.parse(forms["F5"][2], mode="eval").body
    assert ast.dump(f5.keywords[-1].value) == ast.dump(ast.parse('record["productPackets"]', mode="eval").body)
    assert f5.keywords[-1].arg is None
    assert same(forms["F5"][3], 'dict(record["baselinePackets"], **{NEW_PACKET: record["packetSha256"]})')
    f6, f6_undone = ast.parse(forms["F6"][2], mode="eval").body, ast.parse(forms["F6"][3], mode="eval").body
    assert isinstance(f6.comparators[0].elts[-1], ast.Constant) and f6.comparators[0].elts[-1].value == "productPackets"
    authority = [n for n in ast.parse(BASES["head"]).body if n.name == "authority"][0]
    base_keys = [n.comparators[0] for n in ast.walk(authority)
                 if isinstance(n, ast.Compare) and ast.unparse(n.left) == "set(value)"
                 and isinstance(n.comparators[0], ast.Set)]
    assert len(base_keys) == 1
    base_keys = base_keys[0]
    assert [e.value for e in f6.comparators[0].elts[:-1]] == [e.value for e in base_keys.elts]
    assert [e.value for e in f6_undone.comparators[0].elts] == [e.value for e in base_keys.elts]
    assert V2.AUTHORITY_CHECK[:2] == ("F7", "authority")
    assert ast.dump(ast.parse(V2.AUTHORITY_CHECK[2])) == ast.dump(ast.parse(F7_BLOCK))
    assert V2.p_form_counts() == {"historical_catalog": {"F1": 1, "F2": 1},
                                  "validate_packet_payloads": {"F3": 1, "F4": 1},
                                  "_packet_byte_rules": {"F5": 1}, "authority": {"F6": 1, "F7": 1}}


FULL_FORMS = [
    ("own-K1-head", full(), K1, "head"),
    ("own-K2-head", full(), K2, "head"),
    ("own-K3-head", full(), K3, "head"),
    ("own-K1-bridged", full(), K1, "bridged"),
    ("own-K2-bridged", full(), K2, "bridged"),
]


@pytest.mark.parametrize("cid,edits,products,base", FULL_FORMS, ids=[x[0] for x in FULL_FORMS])
def test_full_p_form_normalizes_to_k0(cid, edits, products, base):
    """README 'The accepted P-forms': a layer that binds the list and writes F1-F7 exactly once each is undone to its
    K = 0 class form (K = 1, 2, 3; head and bridged bases). Model-derived (check_class_vector accepts)."""
    names = run_class(class_case(cid, edits, products, base))
    assert sorted(names) == ["_packet_byte_rules", "authority", "historical_bytes", "historical_catalog",
                             "validate_packet_payloads"]


def _replace_fragment(f, new_text):
    return [fragment_edit(f)[0], new_text]


def _f7_variant(old, new):
    assert F7_BLOCK.count(old) == 1, old
    return f7_statement(F7_BLOCK.replace(old, new))


PFORM_REFUSALS = (
    [("own-only-" + f, [fragment_edit(f)], K1, "head") for f in ALL_F]
    + [("own-missing-" + f, full(without=(f,)), K1, "head") for f in ALL_F]
    + [("own-unbound-" + f, [fragment_edit(f)], [], "head") for f in ALL_F]
    + [("own-unbound-full", full(), [], "head"),
       ("own-unbound-full-bridged", full(), [], "bridged"),
       ("own-F1-repeated", full() + [["    current_ids = set(_PACKET_BYTE_RULES)\n",
                                      "    current_ids = set(_PACKET_BYTE_RULES)\n"
                                      "    require(set(packets) == current_ids | set(PRODUCT_PACKETS), \"again\")\n"]],
        K1, "head"),
       ("own-F5-repeated", full() + [['**record["productPackets"])',
                                      '**record["productPackets"], **record["productPackets"])']], K1, "head"),
       ("own-F7-repeated", full() + [[ANCHOR_F7, f7_statement() + ANCHOR_F7]], K1, "head"),
       ("own-F1-frozenset", full(("F1",)) + [_replace_fragment(
           "F1", "set(packets) == current_ids | frozenset(PRODUCT_PACKETS)")], K1, "head"),
       ("own-F1-successor", full(("F1",)) + [_replace_fragment(
           "F1", "set(packets) == current_ids | set(successor.PRODUCT_PACKETS)")], K1, "head"),
       ("own-F2-reordered", full(("F2",)) + [_replace_fragment(
           "F2", "current_ids - set(PRODUCT_PACKETS) - {NEW_PACKET}")], K1, "head"),
       ("own-F4-concat", full(("F4",)) + [_replace_fragment(
           "F4", "set(rules) == old | {NEW_PACKET} | set(PRODUCT_PACKETS + ())")], K1, "head"),
       ("own-F5-wrapped", full(("F5",)) + [_replace_fragment(
           "F5", '**{NEW_PACKET: record["packetSha256"]}, **dict(record["productPackets"]))')], K1, "head"),
       ("own-F5-not-last", full(("F5",)) + [['dict(record["baselinePackets"],',
                                             'dict(record["baselinePackets"], **record["productPackets"],']],
        K1, "head"),
       ("own-F6-not-last", full(("F6",)) + [['        "schemaVersion", "authorityPacket",',
                                             '        "productPackets", "schemaVersion", "authorityPacket",']],
        K1, "head"),
       ("own-guard-payloads", full() + [['    old = set(record["baselinePackets"])\n',
                                         '    old = set(record["baselinePackets"])\n'
                                         '    if "productPackets" in record:\n        old = set(old)\n']],
        K1, "head"),
       ("own-guard-catalog-attribute", full() + [["    current_ids = set(_PACKET_BYTE_RULES)\n",
                                                  "    current_ids = set(_PACKET_BYTE_RULES)\n"
                                                  "    if successor.PRODUCT_PACKETS:\n"
                                                  "        packets = dict(packets)\n"]], K1, "head"),
       ("own-get-productPackets", full() + [["    record = authority()\n    return MappingProxyType",
                                            '    record = authority()\n    record.get("productPackets")\n'
                                            "    return MappingProxyType"]], K1, "head"),
       ("own-F7-after-first-for", full(("F7",)) + [['    for path, expected in value["newFiles"].items():\n',
                                                    f7_statement()
                                                    + '    for path, expected in value["newFiles"].items():\n']],
        K1, "head"),
       ("own-F7-body-start", full(("F7",)) + [["    value = parse(_checked_authority_raw())\n",
                                               "    value = parse(_checked_authority_raw())\n" + f7_statement()]],
        K1, "head"),
       ("own-F7-in-payloads", full(("F7",)) + [["    for name, (_byte_sha, payload_sha) in rules.items():\n",
                                                f7_statement()
                                                + "    for name, (_byte_sha, payload_sha) in rules.items():\n"]],
        K1, "head"),
       ("own-F7-gap", full(("F7",)) + [[ANCHOR_F7, f7_statement() + "    pass\n" + ANCHOR_F7]], K1, "head"),
       ("own-F7-set-equality", full(("F7",)) + [[ANCHOR_F7, _f7_variant(
           'list(value["productPackets"]) == list(PRODUCT_PACKETS)',
           'set(value["productPackets"]) == set(PRODUCT_PACKETS)') + ANCHOR_F7]], K1, "head"),
       ("own-F7-no-digest-check", full(("F7",)) + [[ANCHOR_F7, _f7_variant(
           '\n        and all(_sha(sha) for sha in value["productPackets"].values())', "") + ANCHOR_F7]],
        K1, "head"),
       ("own-F7-no-disjointness", full(("F7",)) + [[ANCHOR_F7, _f7_variant(
           '\n        and not set(PRODUCT_PACKETS) & (set(value["baselinePackets"]) | {NEW_PACKET}),', ",")
           + ANCHOR_F7]], K1, "head"),
       ("own-F7-isinstance", full(("F7",)) + [[ANCHOR_F7, _f7_variant(
           'type(value["productPackets"]) is dict', 'isinstance(value["productPackets"], dict)') + ANCHOR_F7]],
        K1, "head"),
       ("own-F7-message", full(("F7",)) + [[ANCHOR_F7, _f7_variant('"product packets"', '"products"')
                                            + ANCHOR_F7]], K1, "head")]
)


@pytest.mark.parametrize("cid,edits,products,base", PFORM_REFUSALS, ids=[x[0] for x in PFORM_REFUSALS])
def test_p_form_shape_refuses(cid, edits, products, base):
    """README 'The accepted P-forms': a fragment missing (each alone, each dropped), repeated, present in a layer that
    binds no list, F7 in another place or weakened, and any non-exact or guarded form that still names
    PRODUCT_PACKETS or "productPackets" after the undo refuse under `P-form`. Model-derived outcome."""
    _assert_refused(lambda: run_class(class_case(cid, edits, products, base)), clause="P-form")


CLASS_DIFFERENCES = [
    ("own-D-catalog", full() + [['"packet YAML drift: "', '"packet drift: "']], "head", ("D",)),
    ("own-D-catalog-bridged", full() + [['"packet YAML drift: "', '"packet drift: "']], "bridged", ("D",)),
    ("own-G1-payloads", full() + [['"pinned packet data inventory"', '"pinned inventory"']], "head", ("G1",)),
    ("own-G1-byte-rules", full() + [["    record = authority()\n    return MappingProxyType",
                                     "    record = dict(authority())\n    return MappingProxyType"]], "head", ("G1",)),
    ("own-G2-authority", full() + [['"accepted 270-packet base"', '"accepted 271-packet base"']], "head", ("G2",)),
    # README names no class for historical_bytes: any of D, G1, G2.
    ("own-historical-bytes", full() + [['"bounded source bytes required"', '"bounded bytes"']], "head",
     ("D", "G1", "G2")),
]


@pytest.mark.parametrize("cid,edits,base,clauses", CLASS_DIFFERENCES, ids=[x[0] for x in CLASS_DIFFERENCES])
def test_class_difference_after_undo_refuses(cid, edits, base, clauses):
    """README 'The accepted P-forms': after the undo, a class function that differs from its class refuses under D,
    G1 or G2 (historical_catalog D; validate_packet_payloads and _packet_byte_rules G1; authority G2). Model-derived."""
    _assert_refused(lambda: run_class(class_case(cid, edits, K1, base)), clauses=clauses)


# ==== 6. the binding reader (R7) ====================================================================================

PLAIN = 'PRODUCT_PACKETS = ("IND-BANK-001",)\n'
BINDING_VARIANTS = [
    ("annotated", 'PRODUCT_PACKETS: tuple[str, ...] = ("IND-BANK-001",)\n'),
    ("annotated-with-plain", PLAIN + 'PRODUCT_PACKETS: tuple = ("IND-BANK-001",)\n'),
    ("chained", 'OTHER = PRODUCT_PACKETS = ("IND-BANK-001",)\n'),
    ("augmented", PLAIN + "PRODUCT_PACKETS *= 1\n"),
    ("tuple-target", '(PRODUCT_PACKETS,) = (("IND-BANK-001",),)\n'),
    ("list-target", '[PRODUCT_PACKETS] = [("IND-BANK-001",)]\n'),
    ("starred-target", '*PRODUCT_PACKETS, = ("IND-BANK-001",)\n'),
    ("walrus", PLAIN + "X = [(PRODUCT_PACKETS := ())]\n"),
    ("del", PLAIN + "del PRODUCT_PACKETS\n"),
    ("global", PLAIN + "def f():\n    global PRODUCT_PACKETS\n"),
    ("nonlocal", PLAIN + "def f():\n    def g():\n        nonlocal PRODUCT_PACKETS\n"),
    ("import-as", PLAIN + "import os.path as PRODUCT_PACKETS\n"),
    ("from-import-as", PLAIN + "from os import path as PRODUCT_PACKETS\n"),
    ("import-name", PLAIN + "import PRODUCT_PACKETS\n"),
    ("star-import", PLAIN + "from os.path import *\n"),
    ("for-target", PLAIN + "for PRODUCT_PACKETS in ():\n    pass\n"),
    ("async-for-target", PLAIN + "async def f():\n    async for PRODUCT_PACKETS in x:\n        pass\n"),
    ("with-target", PLAIN + 'with open("x") as PRODUCT_PACKETS:\n    pass\n'),
    ("comprehension-target", PLAIN + "X = [1 for PRODUCT_PACKETS in ()]\n"),
    ("parameter", PLAIN + "def f(PRODUCT_PACKETS=()):\n    return 1\n"),
    ("lambda-parameter", PLAIN + "F = lambda PRODUCT_PACKETS: 1\n"),
    ("def-name", PLAIN + "def PRODUCT_PACKETS():\n    return 1\n"),
    ("class-name", PLAIN + "class PRODUCT_PACKETS:\n    pass\n"),
    ("except-capture", PLAIN + "try:\n    pass\nexcept Exception as PRODUCT_PACKETS:\n    pass\n"),
    ("match-capture", PLAIN + "match 1:\n    case PRODUCT_PACKETS:\n        pass\n"),
    ("match-star", PLAIN + "match ():\n    case [*PRODUCT_PACKETS]:\n        pass\n"),
    ("match-mapping-rest", PLAIN + "match {}:\n    case {**PRODUCT_PACKETS}:\n        pass\n"),
    ("match-as", PLAIN + "match 1:\n    case 1 as PRODUCT_PACKETS:\n        pass\n"),
    ("type-parameter", PLAIN + "def f[PRODUCT_PACKETS]():\n    pass\n"),
    ("class-type-parameter", PLAIN + "class C[*PRODUCT_PACKETS]:\n    pass\n"),
    ("type-alias", PLAIN + "type PRODUCT_PACKETS = tuple\n"),
    ("nested-def", 'def f():\n    PRODUCT_PACKETS = ("IND-BANK-001",)\n'),
    ("nested-class", 'class C:\n    PRODUCT_PACKETS = ("IND-BANK-001",)\n'),
    ("nested-try", 'try:\n    PRODUCT_PACKETS = ("IND-BANK-001",)\nexcept Exception:\n    pass\n'),
    ("plain-empty-k0", "PRODUCT_PACKETS = ()\n"),
    ("plain-repeated", PLAIN + PLAIN),
]


@pytest.mark.parametrize("name,source", BINDING_VARIANTS, ids=[x[0] for x in BINDING_VARIANTS])
def test_binding_variant_refuses(name, source):
    """README R7 (1): only exactly one top-level `PRODUCT_PACKETS = (<ids>,)` is read; any other binding of the name
    (annotated, chained, augmented, tuple/list/starred target, walrus, del, global, nonlocal, import, star import,
    for/with/comprehension target, parameter, def or class name, except or match capture, type parameter, nested
    assignment; README 'Any other binding' also covers the type alias), plain `()` at K = 0 and a repeated binding
    refuse under `binding`. Model-derived outcome; the independent reader agrees."""
    assert independent_binding(source) == "refuse"
    _assert_refused(lambda: V2.layer_products(ast.parse(source)), clause="binding")


BINDING_ACCEPTED = [
    ("plain-k1", PLAIN, ("IND-BANK-001",)),
    ("plain-k2", 'PRODUCT_PACKETS = ("IND-BANK-002", "IND-BANK-003")\n', ("IND-BANK-002", "IND-BANK-003")),
    ("no-binding-k0", "X = 1\n", ()),
    ("plain-and-read", PLAIN + "X = PRODUCT_PACKETS\n", ("IND-BANK-001",)),
]


@pytest.mark.parametrize("name,source,expected", BINDING_ACCEPTED, ids=[x[0] for x in BINDING_ACCEPTED])
def test_plain_binding_is_read(name, source, expected):
    """README R7 (1) and rule.json bindingRule: the plain spelling is read in list order; a K = 0 layer binds none
    (a load of the name is not a binding). Model-derived; the independent reader agrees."""
    assert independent_binding(source) == expected
    assert tuple(V2.layer_products(ast.parse(source))) == expected


# ==== 7. mutations beyond the vectors ===============================================================================

def yaml_text(pid, *repository_lines, id_line=None):
    head = id_line if id_line is not None else "id: " + pid
    return head + "\n" + "".join(line + "\n" for line in repository_lines) + "branch: codex/b\n"


def products_mutation(listed, files, chain=()):
    return lambda: run_products(listed, files, chain)


def step_variant(base_id, edits, **overrides):
    base = {c["id"]: c for c in VECTORS["steps"]}[base_id]
    case = {k: base[k] for k in ("L", "S", "C", "K", "newid", "products", "before", "after")}
    case["id"] = "own-" + base_id
    case.update(overrides)
    for field, old, new in edits:
        assert case[field].count(old) == 1, (base_id, field, old)
        case[field] = case[field].replace(old, new)
    return case


OWN_V_BEFORE = ('def validate():\n    paths = sorted(ROOT.glob("*.yaml"))\n'
                '    require(len(paths) == 273 and {p.stem for p in paths} == old | {NEW_PACKET, successor.NEW_PACKET},'
                ' "closed 273-packet catalog")\n    for path in paths:\n'
                '        if path.stem == successor.NEW_PACKET:\n            continue\n'
                '        packets[path.stem] = path\n')
OWN_V_AFTER = ('def validate():\n    paths = sorted(ROOT.glob("*.yaml"))\n'
               '    require(len(paths) == 275 and {p.stem for p in paths} == old | {NEW_PACKET, successor.NEW_PACKET, '
               'successor.successor.NEW_PACKET, *successor.successor.PRODUCT_PACKETS}, "closed 275-packet catalog")\n'
               '    for path in paths:\n'
               '        if path.stem in (successor.NEW_PACKET, successor.successor.NEW_PACKET, '
               '*successor.successor.PRODUCT_PACKETS):\n            continue\n'
               '        packets[path.stem] = path\n')
OWN_V = {"id": "own-v-p", "L": 272, "S": 274, "C": 275, "K": 1, "newid": "MET-SECTOR-003",
         "products": ["IND-BANK-001"], "before": OWN_V_BEFORE, "after": OWN_V_AFTER}


def own_v(edits):
    case = dict(OWN_V)
    for old, new in edits:
        assert case["after"].count(old) == 1, old
        case["after"] = case["after"].replace(old, new)
    return case


V_SKIP_271 = ("        if path.stem in (successor.NEW_PACKET, successor.successor.NEW_PACKET, "
              "*successor.successor.PRODUCT_PACKETS):\n            continue\n")

AP1 = {c["id"]: c for c in VECTORS["allowedPaths"]}["AP1"]
AP2 = {c["id"]: c for c in VECTORS["allowedPaths"]}["AP2"]


def allowed_mutation(base, allowed):
    case = dict(base, allowed=allowed)
    return lambda: run_allowed(case)


# (id, the mutation, the call, the expected clause(s); None = README ties no clause: refused only)
MUTATIONS = [
    ("M01-counts-two-layers-short", "two publishing layers (K = 1, K = 2) at S = 280 with C = 282, not S + P = 283",
     lambda: V2.check_counts(280, 282, [["IND-BANK-001"], ["IND-BANK-002", "IND-BANK-003"]]), ("counts",)),
    ("M02-counts-k2-over", "K = 2 at S = 290 with C = 293 (an unlisted extra packet, R1)",
     lambda: V2.check_counts(290, 293, [["IND-BANK-002", "IND-BANK-003"]]), ("counts",)),
    ("M03-counts-k3-under", "K = 3 at S = 300 with C = 302 (a listed product not added, R8 clause 1)",
     lambda: V2.check_counts(300, 302, [K3]), ("counts",)),
    ("M04-allowed-own-yaml-missing", "AP1 without the meta packet's own YAML",
     allowed_mutation(AP1, [p for p in AP1["allowed"] if p != AP1["ownYaml"]]), None),
    ("M05-allowed-product-lowercase-path", "AP1 with the product path spelled in lower case",
     allowed_mutation(AP1, [p.replace("IND-BANK-001", "ind-bank-001") for p in AP1["allowed"]]), ("R11",)),
    ("M06-allowed-k2-extra-product", "AP2 holding a third task-packets/ path",
     allowed_mutation(AP2, AP2["allowed"] + ["task-packets/IND-BANK-004.yaml"]), ("R11",)),
    ("M07-allowed-product-outside-task-packets", "AP1 with the product path moved out of task-packets/",
     allowed_mutation(AP1, [p.replace("task-packets/IND-BANK-001", "packets/IND-BANK-001") for p in AP1["allowed"]]),
     ("R11",)),
    ("M08-product-id-trailing-newline", "a product id ending in a newline (productId is a fullmatch)",
     products_mutation({274: ["IND-BANK-001\n"]},
                       {"IND-BANK-001\n": yaml_text("IND-BANK-001", "repository: mas-harness-sdks")}), ("R2",)),
    ("M09-product-id-one-segment", "a product id with no hyphen segment",
     products_mutation({274: ["INDBANK"]}, {"INDBANK": yaml_text("INDBANK", "repository: mas-harness-sdks")}),
     ("R2",)),
    ("M10-product-id-lower-segment", "a product id with a lower-case segment",
     products_mutation({274: ["IND-bank-001"]},
                       {"IND-bank-001": yaml_text("IND-bank-001", "repository: mas-harness-sdks")}), ("R2",)),
    ("M11-product-json-quoted-refused-name", "the refused name written as a JSON string on the line",
     products_mutation({274: K1}, {"IND-BANK-001": yaml_text("IND-BANK-001", 'repository: "' + REFUSED_NAME + '"')}),
     ("R3",)),
    ("M12-product-json-escaped-refused-name", "the refused name with a \\u escape (the line rule JSON-decodes)",
     products_mutation({274: K1}, {"IND-BANK-001": yaml_text(
         "IND-BANK-001", 'repository: "\\u' + format(ord(REFUSED_NAME[0]), "04x") + REFUSED_NAME[1:] + '"')}),
     ("R3",)),
    ("M13-product-case-variant-name", "a repository differing from an allowed name only in case",
     products_mutation({274: K1}, {"IND-BANK-001": yaml_text("IND-BANK-001", "repository: mas-harness-Sdks")}),
     ("R8",)),
    ("M14-product-k2-collision", "the second of two products equal to a chain packet id",
     products_mutation({274: ["IND-BANK-002", "MET-PERF-040"]},
                       {"IND-BANK-002": yaml_text("IND-BANK-002", "repository: mas-harness-sdks"),
                        "MET-PERF-040": yaml_text("MET-PERF-040", "repository: mas-harness-sdks")},
                       ("MET-PERF-040",)), ("R2",)),
    ("M15-product-no-repository-line", "a product YAML with no repository line",
     products_mutation({274: K1}, {"IND-BANK-001": yaml_text("IND-BANK-001")}), ("R12",)),
    ("M16-product-single-quoted-duplicate-key", "a single-quoted duplicate key that safe_load reads last",
     products_mutation({274: K1}, {"IND-BANK-001": yaml_text(
         "IND-BANK-001", "repository: mas-harness-sdks", "'repository': mas-harness-operator")}), ("R12",)),
    ("M17-product-explicit-key-later-layer", "R12-L: a later layer's product with an explicit-key duplicate naming "
     "the refused name",
     products_mutation({274: K1, 285: ["IND-BANK-005"]},
                       {"IND-BANK-001": yaml_text("IND-BANK-001", "repository: mas-harness-sdks"),
                        "IND-BANK-005": yaml_text("IND-BANK-005", "repository: mas-harness-sdks", "? repository",
                                                  ": " + REFUSED_NAME)}), ("R12",)),
    ("M18-product-yaml-id-other", "a quoted YAML id naming another packet",
     products_mutation({274: K1}, {"IND-BANK-001": yaml_text("IND-BANK-001", "repository: mas-harness-sdks",
                                                             id_line='id: "IND-BANK-002"')}), ("R2",)),
    ("M19-product-k2-two-lines", "the second of two products with two repository lines",
     products_mutation({274: K2}, {"IND-BANK-002": yaml_text("IND-BANK-002", "repository: mas-harness-sdks"),
                                   "IND-BANK-003": yaml_text("IND-BANK-003", "repository: mas-harness-sdks",
                                                             "repository: mas-harness-sdks")}), ("R12",)),
    # Two README clauses apply (a non-inline declaration, R12; its line value outside the twelve, R8); the README
    # states no precedence, so either clause is the text's.
    ("M20-product-block-form", "a block-form repository declaration on the next line",
     products_mutation({274: K1}, {"IND-BANK-001": yaml_text("IND-BANK-001", "repository:", "  mas-harness-sdks")}),
     ("R8", "R12")),
    ("M21-product-inline-comment", "a repository line carrying a YAML comment",
     products_mutation({274: K1}, {"IND-BANK-001": yaml_text("IND-BANK-001", "repository: mas-harness-sdks # c")}),
     ("R8", "R12")),
    ("M22-binding-list-value", "PRODUCT_PACKETS bound to a list",
     lambda: V2.layer_products(ast.parse('PRODUCT_PACKETS = ["IND-BANK-001"]\n')), ("binding",)),
    ("M23-binding-int-element", "a non-string element in the tuple",
     lambda: V2.layer_products(ast.parse('PRODUCT_PACKETS = ("IND-BANK-001", 7)\n')), ("binding",)),
    ("M24-binding-concatenated-element", "an element built by string concatenation",
     lambda: V2.layer_products(ast.parse('PRODUCT_PACKETS = ("IND-" + "BANK-001",)\n')), ("binding",)),
    ("M25-step-k1-pin-by-three", "K1 step whose count pin moves 273 -> 276 (R10)",
     lambda: V2.check_step_vector(step_variant("K1", [("after", "len(paths) == 275", "len(paths) == 276")]), V1),
     ("step",)),
    ("M26-step-k2-message-by-two", "K2 step whose message moves 273 -> 275, not 276 (R10)",
     lambda: V2.check_step_vector(step_variant("K2", [("after", "closed 276-packet catalog",
                                                       "closed 275-packet catalog")]), V1), ("step",)),
    ("M27-step-k1-starred-wrong-depth", "K1 display gaining *successor^2.PRODUCT_PACKETS at d = 3 (R9)",
     lambda: V2.check_step_vector(step_variant("K1", [("after", "*successor.successor.successor.PRODUCT_PACKETS",
                                                       "*successor.successor.PRODUCT_PACKETS")]), V1), ("step",)),
    ("M28-step-k1-product-before-meta", "K1 display with the starred list before the meta id ((iii-p) order)",
     lambda: V2.check_step_vector(step_variant("K1", [(
         "after", "successor.successor.successor.NEW_PACKET, *successor.successor.successor.PRODUCT_PACKETS",
         "*successor.successor.successor.PRODUCT_PACKETS, successor.successor.successor.NEW_PACKET")]), V1), None),
    ("M29-step-k1-unstarred-product", "K1 display gaining the list unstarred",
     lambda: V2.check_step_vector(step_variant("K1", [("after", "*successor.successor.successor.PRODUCT_PACKETS",
                                                       "successor.successor.successor.PRODUCT_PACKETS")]), V1), None),
    ("M30-step-k1-v-wrong-layer", "(v-p) rewrite at L = 271 = S - 3 (R9, (v) at the wrong layer)",
     lambda: V2.check_step_vector(step_variant("K1", [
         ("before", "    for path in paths:\n\n",
          "    for path in paths:\n        if path.stem == successor.NEW_PACKET:\n            continue\n"),
         ("after", "    for path in paths:\n\n", "    for path in paths:\n" + V_SKIP_271)]), V1), ("step",)),
    ("M31-step-v-p-starred-wrong-depth", "(v-p) tuple with *successor.PRODUCT_PACKETS at L = S - 2 (R9)",
     lambda: V2.check_step_vector(own_v([("*successor.successor.PRODUCT_PACKETS):", "*successor.PRODUCT_PACKETS):")]),
                                  V1), ("step",)),
    ("M32-step-v-p-no-product", "(v-p) tuple without the starred product list",
     lambda: V2.check_step_vector(own_v([(", *successor.successor.PRODUCT_PACKETS):", "):")]), V1), None),
]


@pytest.mark.parametrize("mid,description,call,clauses", MUTATIONS, ids=[m[0] for m in MUTATIONS])
def test_mutation_refused(mid, description, call, clauses):
    """Mutations of this file's own (beyond vectors.json), entered through the models' own inputs: each is refused
    with the clause README Refusals ties to it (counts for R1/R8 clause 1, R2, R3, R8, R11, R12, binding, step);
    where the README ties no clause the test asserts only that it is refused. Model-derived outcome."""
    _assert_refused(call, clauses=clauses)


def test_product_mutations_agree_with_the_independent_reader():
    """README R2, R3, R8 clause 2, R12 with rule.json's line rule: the single-defect product mutations get the same
    refusal id from the independent reader as the test expects."""
    singles = {
        "R2": [({274: ["IND-bank-001"]}, {"IND-bank-001": yaml_text("IND-bank-001", "repository: mas-harness-sdks")}),
               ({274: K1}, {"IND-BANK-001": yaml_text("IND-BANK-001", "repository: mas-harness-sdks",
                                                      id_line='id: "IND-BANK-002"')})],
        "R3": [({274: K1}, {"IND-BANK-001": yaml_text("IND-BANK-001", 'repository: "' + REFUSED_NAME + '"')})],
        "R8": [({274: K1}, {"IND-BANK-001": yaml_text("IND-BANK-001", "repository: mas-harness-Sdks")})],
        "R12": [({274: K1}, {"IND-BANK-001": yaml_text("IND-BANK-001")}),
                ({274: K1}, {"IND-BANK-001": yaml_text("IND-BANK-001", "repository: mas-harness-sdks",
                                                       "'repository': mas-harness-operator")})],
    }
    for refusal, cases in singles.items():
        for listed, files in cases:
            assert independent_products(listed, files) == refusal


def test_own_valid_inputs_are_accepted():
    """Positive controls built from the contract text: (v-p) at L = S - 2 per rule.json bumpVocabulary; two publishing
    layers with C = S + P; a repository line with trailing spaces (the line rule strips it). Model-derived outcome,
    independently expected."""
    assert V2.check_step_vector(OWN_V, V1)
    assert independent_counts(280, 283, [["IND-BANK-001"], ["IND-BANK-002", "IND-BANK-003"]])
    assert V2.check_counts(280, 283, [["IND-BANK-001"], ["IND-BANK-002", "IND-BANK-003"]])
    files = {"IND-BANK-001": yaml_text("IND-BANK-001", "repository: mas-harness-sdks   ")}
    assert independent_products({274: K1}, files) is None
    assert run_products({274: K1}, files) == 1


def test_at_least_twelve_mutations():
    """Brief item 7: at least 12 mutations of this file's own beyond the vectors."""
    assert len(MUTATIONS) >= 12
    assert len({m[0] for m in MUTATIONS}) == len(MUTATIONS)
