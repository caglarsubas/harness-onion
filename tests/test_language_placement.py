"""MET-GOV-004 (LANG-PLACEMENT-ADR-001): scripts/language_placement.py over ADR 0010's data. The head is accepted, and
one in-memory mutation per rule is refused with its rule id (design section 4), the binding build rule BR-GOV4-1's
constants and rules included: EXPECTED, OUTSIDE_EXPECTED, REPO_LANGUAGES, the PENDING: rule and the verbatim toolchain
rule. Mutations go through the checker's overlay, so no file in the tree is written.

MET-GOV-005 (TECH-TRUTH-001) changes the v1 cases exactly as its design's Appendix C states, and adds one test
per section-5 row of that design (BR-TT-2, BR-TT-3) and the binding rules' self-checks."""
import hashlib
import json
from pathlib import Path

import pytest

from scripts import language_placement as lp

ROOT = Path(__file__).resolve().parents[1]


def _data():
    return json.loads((ROOT / lp.DATA_PATH).read_bytes())


def _adr():
    return (ROOT / lp.ADR_PATH).read_text(encoding="utf-8")


def _dump(data):
    return json.dumps(data, indent=1).encode("utf-8")


def _refused(rule, overlay, fragment=None):
    with pytest.raises(lp.Refusal) as caught:
        lp.check(ROOT, overlay)
    assert caught.value.rule == rule, str(caught.value)
    if fragment is not None:
        assert fragment in str(caught.value), str(caught.value)


def _row(data, key, value, field="id"):
    return next(r for r in data[key] if r[field] == value)


def _with_catalogue(path, old, new):
    raw = (ROOT / path).read_bytes()
    assert raw.count(old) == 1
    raw = raw.replace(old, new)
    data = _data()
    next(c for c in data["catalogues"] if c["path"] == path)["sha256"] = hashlib.sha256(raw).hexdigest()
    return {lp.DATA_PATH: _dump(data), path: raw}


# ---------------------------------------------------------------- the head and the closed constants

def test_head_is_accepted_with_the_designed_counts():
    assert lp.check(ROOT) == {
        "repositories": 13, "deployables": 28,
        "byStatus": {"AS_PLANNED": 15, "PENDING_HOTPATH_DECISION": 4, "CONTROL_LOOP_TO_BE_CONFIRMED": 1,
                     "NO_STATED_DEFAULT": 8},
        "byPlane": {"CONTROL": 2, "DATA": 3, "UNSTATED": 23},
        "outsideCatalogue": 5, "exceptions": 5, "spans": 112,
        "byImplementationStatus": {"PLANNED": 27, "APPROVED": 0, "IMPLEMENTED": 0, "UPSTREAM_MANAGED": 1},
        "nativeRows": 2, "harnesses": 16, "bindings": 31,
        "byKind": {"CATALOG_MODULE": 18, "OPTIONAL_ADAPTER": 2, "PLAN_LIBRARY": 1, "DEFERRED": 10}}


def test_closed_constants_cover_the_catalogues_and_the_design():
    services = lp.safe_load((ROOT / lp.SERVICES_PATH).read_bytes())
    repositories = lp.safe_load((ROOT / lp.REPOSITORIES_PATH).read_bytes())
    assert list(lp.EXPECTED) == [s["id"] for s in services["services"]]
    assert list(lp.REPO_LANGUAGES) == [r["id"] for r in repositories["repositories"]]
    assert set(lp.OUTSIDE_EXPECTED) == {"reference-channel-ui", "model-backends", "native-host-enforcement-roles",
                                        "r12-native-probes", "typescript-sdk"}
    assert lp.LANGUAGES == ("PYTHON", "GO", "RUST", "TYPESCRIPT", "UPSTREAM_OWN")  # CPP is dropped
    assert all(len(v) == 4 for v in lp.EXPECTED.values())  # status, plane, planeSource, plannedLanguage
    pending = sorted(d for d, v in lp.EXPECTED.items() if v[0] == "PENDING_HOTPATH_DECISION")
    assert pending == ["ai-gateway", "experience-gateway", "protocol-gateway", "tool-broker"]


def test_the_rendering_is_deterministic_and_is_the_adr_block():
    data = lp.strict((ROOT / lp.DATA_PATH).read_bytes())
    lines = _adr().split("\n")
    for table in lp.TABLES:
        begin, end = lp._markers(table)
        assert lp.render(data, table) == lp.render(json.loads(json.dumps(data)), table)
        assert lines[lines.index(begin) + 1:lines.index(end)] == lp.render(data, table)
        assert lp.SERVICES_PATH in lp.render(data, table)[0] and lp.REPOSITORIES_PATH in lp.render(data, table)[0]


# ---------------------------------------------------------------- the command line

def test_check_command_exits_zero_on_the_head(capsys):
    assert lp.main(["check"]) == 0
    assert lp.main(["check", "--root", str(ROOT)]) == 0
    assert "accepted" in capsys.readouterr().out


@pytest.mark.parametrize("argv", [[], ["verify"], ["check", "--root"], ["check", "extra"], ["check", "--dir", "."],
                                  ["check", "--root", ".", "extra"]])
def test_usage_exits_two(argv, capsys):
    assert lp.main(argv) == 2
    assert capsys.readouterr().out.startswith("usage:")


def test_a_refused_tree_exits_one(tmp_path, capsys):
    assert lp.main(["check", "--root", str(tmp_path)]) == 1
    assert capsys.readouterr().out.startswith("refused: R1")


# ---------------------------------------------------------------- R1: the parse rules and the shape

@pytest.mark.parametrize("raw", [
    b"\xef\xbb\xbf{}",                      # a byte-order mark
    b"\xff{}",                              # not UTF-8
    b'{"a": 1, "a": 2}',                    # a duplicate key
    b'{"a": NaN}',                          # a non-finite number
    b'{"a": 1.0}',                          # an integral float
    b'{"a": 10000000000000}',               # an oversized integer
    b'{"a": "\\ud800"}',                    # a lone surrogate
    b"not json",
], ids=["bom", "utf8", "duplicate", "nan", "integral-float", "oversized-int", "surrogate", "not-json"])
def test_parse_refusals_are_r1(raw):
    _refused("R1", {lp.DATA_PATH: raw})


def _set(key, value):
    def apply(data):
        data[key] = value
    return apply


R1_MUTATIONS = {
    "extra-top-member": _set("baselineAt", "9184f5b6"),
    "schema-version": _set("schemaVersion", "planeon.internal.language-placement/v3"),
    "adr-path": _set("adr", "docs/adr/0011-language-placement.md"),
    "missing-member": lambda d: d.pop("exceptions"),
    "management-plane": lambda d: _row(d, "deployables", "control-web").update(plane="MANAGEMENT"),
    "cpp-language": lambda d: _row(d, "deployables", "decision-service").update(plannedLanguage="CPP"),
    "unknown-status": lambda d: _row(d, "deployables", "ai-gateway").update(status="PENDING_REQUEST_PATH_EXCEPTION"),
    "unknown-plane-source": lambda d: _row(d, "deployables", "operator").update(planeSource="OWNER"),
    "boolean-line": lambda d: _row(d, "deployables", "operator")["source"].update(lines=[True, 153]),
    "reversed-lines": lambda d: _row(d, "deployables", "operator")["source"].update(lines=[153, 152]),
    "three-spans": lambda d: _row(d, "repositories", "operator")["sources"].append(
        dict(_row(d, "repositories", "operator")["sources"][0])),
    "dot-dot-path": lambda d: _row(d, "deployables", "operator")["source"].update(path="docs/../README.md"),
    "empty-evidence": lambda d: _row(d, "deployables", "operator")["source"].update(evidence=[]),
    "duplicate-language": lambda d: _row(d, "repositories", "operator").update(languages=["GO", "GO"]),
    "bad-r-number": lambda d: _row(d, "repositories", "operator").update(rNumber="R1"),
    "open-span": lambda d: _row(d, "deployables", "operator")["source"].update(note="x"),
    "open-owner": lambda d: d["exceptions"][0]["owner"].update(person="x"),
    "empty-toolchain": lambda d: _row(d, "deployables", "operator").update(toolchain=""),
}


@pytest.mark.parametrize("name", sorted(R1_MUTATIONS))
def test_shape_mutations_are_r1(name):
    data = _data()
    R1_MUTATIONS[name](data)
    _refused("R1", {lp.DATA_PATH: _dump(data)})


# ---------------------------------------------------------------- R2: the catalogues and the policy

def test_a_catalogue_digest_drift_is_r2():
    data = _data()
    data["catalogues"][0]["sha256"] = "0" * 64
    _refused("R2", {lp.DATA_PATH: _dump(data)}, "sha256")


def test_catalogues_out_of_order_are_r2():
    data = _data()
    data["catalogues"].reverse()
    _refused("R2", {lp.DATA_PATH: _dump(data)}, "in that order")


def test_duplicate_service_ids_are_r2():
    overlay = _with_catalogue(lp.SERVICES_PATH, b"  - id: usage-ledger\n    ownerRepository:",
                              b"  - id: policy-decision\n    ownerRepository:")
    _refused("R2", overlay, "unique")


def test_a_service_count_other_than_counts_total_is_r2():
    _refused("R2", _with_catalogue(lp.SERVICES_PATH, b"  total: 28\n", b"  total: 29\n"), "counts.total")


def test_duplicate_repository_ids_are_r2():
    _refused("R2", _with_catalogue(lp.REPOSITORIES_PATH, b"  - id: contracts\n", b"  - id: sdks\n"), "unique")


def test_a_changed_policy_digest_is_r2():
    data = _data()
    data["policySha256"] = hashlib.sha256(b"another policy").hexdigest()
    _refused("R2", {lp.DATA_PATH: _dump(data)}, "policySha256")


def test_a_changed_policy_line_is_r2():
    adr = _adr()
    assert adr.count("merely because it uses Python.") == 1
    _refused("R2", {lp.ADR_PATH: adr.replace("merely because it uses Python.", "merely because it uses Go.").encode()},
             "LANG-D2 (a)")


def test_a_policy_block_of_two_lines_is_r2():
    adr = _adr().replace(lp.POLICY_END, ">\n" + lp.POLICY_END)
    _refused("R2", {lp.ADR_PATH: adr.encode()}, "one line")


def test_a_missing_policy_block_is_r2():
    _refused("R2", {lp.ADR_PATH: _adr().replace(lp.POLICY_BEGIN, "").encode()}, "policy block")


# ---------------------------------------------------------------- R3: the deployables and EXPECTED (BR-GOV4-1)

R3_MUTATIONS = {
    "dropped-row": lambda d: d["deployables"].pop(),
    "duplicated-row": lambda d: d["deployables"].append(dict(d["deployables"][0])),
    "wrong-owner-repository": lambda d: _row(d, "deployables", "tool-broker").update(
        ownerRepository="mas-harness-runtime-plane"),
    "wrong-kind": lambda d: _row(d, "deployables", "tool-broker").update(kind="gateway"),
    # an AS_PLANNED relabel of a pending row, and an UNSTATED relabel of a stated plane
    "as-planned-relabel": lambda d: _row(d, "deployables", "ai-gateway").update(status="AS_PLANNED"),
    "unstated-relabel": lambda d: _row(d, "deployables", "operator").update(plane="UNSTATED", planeSource="NOT_STATED"),
    "invented-data-plane": lambda d: _row(d, "deployables", "inference-api").update(plane="DATA", planeSource="KIND_RULE"),
    "connector-controller-control": lambda d: _row(d, "deployables", "connector-controller").update(
        plane="CONTROL", planeSource="KIND_RULE"),
    "plane-source": lambda d: _row(d, "deployables", "fleet-sync-agent").update(planeSource="OWNER_LANG_D2"),
    # a relabel that the cited span allows: 09-...md:90-100 says "upstream", yet EXPECTED refuses it
    "span-allowed-relabel": lambda d: _row(d, "deployables", "guardrail-service").update(plannedLanguage="UPSTREAM_OWN"),
    # a language that the row's span does not state
    "language-not-in-span": lambda d: _row(d, "deployables", "control-web").update(plannedLanguage="PYTHON"),
    "no-stated-default-as-exception": lambda d: _row(d, "deployables", "ingest-worker").update(
        status="PENDING_HOTPATH_DECISION"),
}


@pytest.mark.parametrize("name", sorted(R3_MUTATIONS))
def test_deployable_mutations_are_r3(name):
    data = _data()
    R3_MUTATIONS[name](data)
    _refused("R3", {lp.DATA_PATH: _dump(data)})


def test_a_catalogue_id_without_a_row_is_r3():
    overlay = _with_catalogue(lp.SERVICES_PATH, b"  - id: usage-ledger\n    ownerRepository:",
                              b"  - id: usage-ledger-v2\n    ownerRepository:")
    _refused("R3", overlay, "exactly services.yaml's")


# ---------------------------------------------------------------- R4: the repositories and REPO_LANGUAGES (BR-GOV4-1)

def _swap_operator_spans(d):
    _row(d, "repositories", "operator")["sources"].reverse()


R4_MUTATIONS = {
    "dropped-row": lambda d: d["repositories"].pop(),
    "duplicated-row": lambda d: d["repositories"].append(dict(d["repositories"][0])),
    "renamed": lambda d: _row(d, "repositories", "sdks").update(name="mas-harness-sdk"),
    "r-number": lambda d: _row(d, "repositories", "operator").update(rNumber="R11"),
    "first-span-not-the-plan": _swap_operator_spans,
    "dropped-language": lambda d: _row(d, "repositories", "operator").update(languages=["GO"]),
    "added-language": lambda d: _row(d, "repositories", "model-plane").update(languages=["PYTHON", "UPSTREAM_OWN"]),
    "r12-node-as-typescript": lambda d: _row(d, "repositories", "conformance-labs").update(
        languages=["PYTHON", "RUST", "TYPESCRIPT"]),
    # v2 (C1-3, design Appendix C): a toolchain string other than its row's constant is R4
    "deployable-toolchain-not-in-span": lambda d: _row(d, "deployables", "ai-gateway").update(toolchain="Python 3.13.0"),
    "repository-toolchain-not-in-span": lambda d: _row(d, "repositories", "conformance-labs").update(
        toolchain="Node 24.20.0 LTS, TypeScript 5"),
}


@pytest.mark.parametrize("name", sorted(R4_MUTATIONS))
def test_repository_mutations_are_r4(name):
    data = _data()
    R4_MUTATIONS[name](data)
    _refused("R4", {lp.DATA_PATH: _dump(data)})


# ---------------------------------------------------------------- R5: the sources, the tokens and the toolchain rule

def _evidence_without(key, rid, token, index=0):
    def apply(d):
        row = _row(d, key, rid)
        span = row["source"] if key == "deployables" else row["sources"][index]
        span["evidence"].remove(token)
    return apply


R5_MUTATIONS = {
    # the content rule: no block of the span's line count anywhere in the file has the recorded digest
    "digest-mismatch": lambda d: _row(d, "deployables", "operator")["source"].update(sha256="0" * 64),
    "line-count-changed": lambda d: _row(d, "deployables", "operator")["source"].update(lines=[152, 152]),
    "line-count-changed-far": lambda d: _row(d, "deployables", "operator")["source"].update(lines=[5000, 5000]),
    "missing-path": lambda d: _row(d, "deployables", "operator")["source"].update(
        path="docs/repositories/99-mas-harness-none.md"),
    "evidence-not-in-span": lambda d: _row(d, "deployables", "operator")["source"]["evidence"].append("Kotlin"),
    "id-token-missing": _evidence_without("deployables", "ai-gateway", "`ai-gateway`"),
    "alias-token-missing": _evidence_without("deployables", "otel-collector", "OTel Collector"),
    "language-token-missing": _evidence_without("deployables", "control-web", "TypeScript"),
    "repository-rust-token-missing": _evidence_without("repositories", "operator", "Rust", index=1),
    "outside-span-digest": lambda d: _row(d, "outsideCatalogue", "typescript-sdk")["sources"][0].update(lines=[93, 94]),
}


@pytest.mark.parametrize("name", sorted(R5_MUTATIONS))
def test_source_mutations_are_r5(name):
    data = _data()
    R5_MUTATIONS[name](data)
    _refused("R5", {lp.DATA_PATH: _dump(data)})


HEAD_SUMMARY = {
    "repositories": 13, "deployables": 28,
    "byStatus": {"AS_PLANNED": 15, "PENDING_HOTPATH_DECISION": 4, "CONTROL_LOOP_TO_BE_CONFIRMED": 1,
                 "NO_STATED_DEFAULT": 8},
    "byPlane": {"CONTROL": 2, "DATA": 3, "UNSTATED": 23},
    "outsideCatalogue": 5, "exceptions": 5, "spans": 112,
    "byImplementationStatus": {"PLANNED": 27, "APPROVED": 0, "IMPLEMENTED": 0, "UPSTREAM_MANAGED": 1},
    "nativeRows": 2, "harnesses": 16, "bindings": 31,
    "byKind": {"CATALOG_MODULE": 18, "OPTIONAL_ADAPTER": 2, "PLAN_LIBRARY": 1, "DEFERRED": 10}}


@pytest.mark.parametrize("plan", ["docs/repositories/00-harness-engineering.md",
                                  "docs/repositories/10-mas-harness-operator.md",
                                  "docs/alpha-2/ENFORCEMENT_TEST_PLAN.md"])
def test_a_shift_above_a_cited_span_is_accepted(plan):
    # errata 2 (B2): the mechanics prepend sections to 00-harness-engineering.md, which moves R00's span
    shifted = b"## A prepended section\n\nThree lines above every cited span.\n" + (ROOT / plan).read_bytes()
    assert lp.check(ROOT, {plan: shifted}) == HEAD_SUMMARY


@pytest.mark.parametrize("plan, old, new", [
    ("docs/repositories/00-harness-engineering.md", b"- Toolchain: Python 3.12.14, `uv` 0.12.7, JSON Schema",
     b"- Toolchain: Python 3.12.15, `uv` 0.12.7, JSON Schema"),
    ("docs/repositories/10-mas-harness-operator.md", b"- `fleet-sync-agent`: optional module",
     b"- `fleet-sync-agent`: optional modules"),
])
def test_a_one_character_change_inside_a_span_is_r5(plan, old, new):
    raw = (ROOT / plan).read_bytes()
    assert raw.count(old) == 1 and len(new) - len(old) in (0, 1)
    _refused("R5", {plan: raw.replace(old, new)}, plan)
    # still refused when the changed span is also shifted
    _refused("R5", {plan: b"\n\n\n" + raw.replace(old, new)}, plan)


def _lines_moved(data):
    for row in data["repositories"] + data["outsideCatalogue"]:
        for span in row["sources"]:
            span["lines"] = [span["lines"][0] + 7, span["lines"][1] + 7]
    for row in data["deployables"]:
        row["source"]["lines"] = [row["source"]["lines"][0] + 7, row["source"]["lines"][1] + 7]


def test_a_change_to_the_data_lines_alone_is_accepted_by_r5():
    data = _data()
    _lines_moved(data)
    assert lp._sources(data, ROOT, {}) == 112


def test_a_change_to_the_data_lines_alone_is_accepted_once_the_tables_show_it():
    # `lines` are for display only: R5 accepts them anywhere, and only R8's rendered Source columns show them
    data = _data()
    _lines_moved(data)
    lines = _adr().split("\n")
    for table in lp.TABLES:
        begin, end = lp._markers(table)
        a, b = lines.index(begin), lines.index(end)
        lines[a + 1:b] = lp.render(data, table)
    overlay = {lp.DATA_PATH: _dump(data), lp.ADR_PATH: "\n".join(lines).encode("utf-8")}
    assert lp.check(ROOT, overlay) == HEAD_SUMMARY
    _refused("R8", {lp.DATA_PATH: _dump(data)})


# ---------------------------------------------------------------- R6: outside the catalogue and OUTSIDE_EXPECTED

def _extra_outside(d):
    row = json.loads(json.dumps(_row(d, "outsideCatalogue", "typescript-sdk")))
    row["id"] = "go-sdk-client"
    d["outsideCatalogue"].append(row)


R6_MUTATIONS = {
    "dropped-row": lambda d: d["outsideCatalogue"].pop(),
    "extra-row": _extra_outside,
    # a relabel that the cited span allows: ENFORCEMENT_TEST_PLAN.md:12-13 also says "Python 3.12"
    "r12-probes-as-python": lambda d: _row(d, "outsideCatalogue", "r12-native-probes").update(plannedLanguage="PYTHON"),
    "owner": lambda d: _row(d, "outsideCatalogue", "native-host-enforcement-roles").update(
        ownerRepository="mas-harness-conformance-labs"),
    "language-token-missing": lambda d: _row(d, "outsideCatalogue", "typescript-sdk")["sources"][0]["evidence"].remove(
        "TypeScript"),
}


@pytest.mark.parametrize("name", sorted(R6_MUTATIONS))
def test_outside_mutations_are_r6(name):
    data = _data()
    R6_MUTATIONS[name](data)
    _refused("R6", {lp.DATA_PATH: _dump(data)})


# ---------------------------------------------------------------- R7: the exceptions and the PENDING: rule

def _exception(d, deployable):
    return _row(d, "exceptions", deployable, field="deployable")


def _extra_exception(d):
    row = json.loads(json.dumps(_exception(d, "ai-gateway")))
    row["deployable"] = "operator"
    d["exceptions"].append(row)


R7_MUTATIONS = {
    "evidence-without-pending": lambda d: _exception(d, "tool-broker").update(
        evidence="LANG-HOTPATH-DECISION-001's measured boundary decision and benchmark against the production SLO"),
    "evidence-names-neither": lambda d: _exception(d, "tool-broker").update(evidence="PENDING: a later decision"),
    "missing-row": lambda d: d["exceptions"].remove(_exception(d, "tool-broker")),
    "duplicated-row": lambda d: d["exceptions"].append(dict(_exception(d, "tool-broker"))),
    "row-for-as-planned": _extra_exception,
    "owner-repository": lambda d: _exception(d, "protocol-gateway")["owner"].update(
        repository="mas-harness-runtime-plane"),
    "owner-packet": lambda d: _exception(d, "experience-gateway")["owner"].update(packet="RUN-001"),
    "planned-language": lambda d: _exception(d, "ai-gateway").update(plannedLanguage="GO"),
    "default-language": lambda d: _exception(d, "ai-gateway").update(defaultLanguage="PYTHON"),
    "status": lambda d: _exception(d, "connector-controller").update(status="PENDING_HOTPATH_DECISION"),
}


@pytest.mark.parametrize("name", sorted(R7_MUTATIONS))
def test_exception_mutations_are_r7(name):
    data = _data()
    R7_MUTATIONS[name](data)
    _refused("R7", {lp.DATA_PATH: _dump(data)})


# ---------------------------------------------------------------- R8: the ADR's tables

def test_a_drifted_table_is_r8():
    adr = _adr()
    old = "| `operator` | `mas-harness-operator` | controller | GO |"
    assert adr.count(old) == 1
    _refused("R8", {lp.ADR_PATH: adr.replace(old, old.replace("| GO |", "| PYTHON |")).encode()}, "deployables")


def test_a_data_change_without_its_table_is_r8():
    data = _data()
    _exception(data, "tool-broker")["reviewTrigger"] = "the first R08 coding packet"
    _refused("R8", {lp.DATA_PATH: _dump(data)}, "exceptions")


def test_a_drifted_caption_digest_is_r8():
    adr = _adr()
    digest = _data()["catalogues"][1]["sha256"]
    assert adr.count(digest) == 4
    _refused("R8", {lp.ADR_PATH: adr.replace(digest, "0" * 64, 1).encode()}, "repositories")


@pytest.mark.parametrize("table", lp.TABLES)
def test_a_missing_table_marker_is_r8(table):
    begin, _ = lp._markers(table)
    _refused("R8", {lp.ADR_PATH: _adr().replace(begin, "").encode()}, table)


# ================================================================ v2, the technology record (MET-GOV-005)

PLAN_06 = "docs/repositories/06-mas-harness-model-plane.md"
PLAN_08 = "docs/repositories/08-mas-harness-execution-plane.md"
H3 = ("runtime.ai-gateway", "BerriAI/litellm")


def _raw(path):
    return (ROOT / path).read_bytes()


def _ov(data):
    return {lp.DATA_PATH: _dump(data)}


def _heading_above(raw, first):
    heads = [line for line in lp._lines(raw)[:first - 1] if lp.HEADING.match(line)]
    return heads[-1].rstrip(b"\n").decode("utf-8")


def _span_at(path, first, last, evidence):
    """A span re-pointed to lines first..last of `path` at the head, its digest and section recomputed."""
    raw = _raw(path)
    block = lp.span_bytes(raw, first, last)
    for item in evidence:
        assert item in block.decode("utf-8")
    return {"path": path, "section": _heading_above(raw, first), "lines": [first, last],
            "sha256": hashlib.sha256(block).hexdigest(), "evidence": list(evidence)}


def _line_containing(path, text):
    found = [n for n, line in enumerate(_raw(path).decode("utf-8").split("\n"), 1) if text in line]
    assert len(found) == 1, found
    return found[0]


def _entry(data, harness):
    return _row(data, "baselineBindings", harness, field="harness")


def _binding(data, harness, baseline):
    return next(r for r in _entry(data, harness)["rows"] if r["baseline"] == baseline)


def _copy(value):
    return json.loads(json.dumps(value))


def _repinned(data, path, raw):
    """A scratch catalog: `path`'s edited bytes, with the data's catalogue pin re-derived for them so that R2 passes."""
    next(c for c in data["catalogues"] if c["path"] == path)["sha256"] = hashlib.sha256(raw).hexdigest()
    return {lp.DATA_PATH: _dump(data), path: raw}


def _edited(path, anchor, old, new):
    """`path`'s head bytes with the first `old` after its one `anchor` replaced by `new`."""
    raw = _raw(path)
    assert raw.count(anchor) == 1
    at = raw.index(old, raw.index(anchor))
    return raw[:at] + new + raw[at + len(old):]


def _replaced(path, old, new):
    raw = _raw(path)
    assert raw.count(old) == 1
    return raw.replace(old, new)


def _rerendered(data):
    """The ADR with all seven table blocks rendered from `data`."""
    lines = _adr().split("\n")
    for table in lp.TABLES + lp.AMENDMENT_TABLES:
        begin, end = lp._markers(table)
        a, b = lines.index(begin), lines.index(end)
        lines[a + 1:b] = lp.render(data, table)
    return "\n".join(lines).encode("utf-8")


def _r08():
    """R08's executor bullet (h10Sources.r08), the line after it, and the plan's bytes."""
    span = _data()["h10Sources"]["r08"]
    raw = _raw(PLAN_08)
    first, last = span["lines"]
    line = lp.span_bytes(raw, first, last)
    assert hashlib.sha256(line).hexdigest() == span["sha256"] and raw.count(line) == 1
    after = lp.span_bytes(raw, last + 1, last + 1)
    assert after.startswith(b"- ") and raw.count(after) == 1
    return line, after, raw


def _next_heading(raw, section):
    """The heading line that follows `section` in `raw`."""
    lines = lp._lines(raw)
    at = lines.index(section.encode("utf-8") + b"\n")
    return next(line for line in lines[at + 1:] if lp.HEADING.match(line))


# ---------------------------------------------------------------- the v2 constants and tables

def test_v2_closed_constants_cover_the_data():
    data = _data()
    ids = [d["id"] for d in data["deployables"]]
    assert list(lp.TECH_EXPECTED) == ids + list(lp.NATIVE_ROWS)
    assert list(lp.FRAMEWORKS_EXPECTED) == ids == list(lp.TOOLCHAIN_EXPECTED["deployables"])
    assert list(lp.TOOLCHAIN_EXPECTED["repositories"]) == [r["id"] for r in data["repositories"]]
    assert len(lp.STEMS) == 16 and len(lp.BINDINGS_EXPECTED) == 31 and lp.PLAN_TOKENS == {"helm/helm": "Helm 4.2.0"}
    kinds = [row[2] for row in lp.BINDINGS_EXPECTED]
    assert {k: kinds.count(k) for k in lp.BINDING_KINDS} == {"CATALOG_MODULE": 18, "OPTIONAL_ADAPTER": 2,
                                                              "PLAN_LIBRARY": 1, "DEFERRED": 10}
    assert len(lp.PACKAGING) == 13 and lp.PACKAGING[-1] == "NATIVE_BINARY"
    assert lp.IMPLEMENTATION_STATUSES == ("PLANNED", "APPROVED", "IMPLEMENTED", "UPSTREAM_MANAGED")
    assert lp.AMENDMENT_TABLES == ("technology", "native", "bindings") and lp.TABLES == (
        "repositories", "deployables", "outsideCatalogue", "exceptions")
    assert lp.DIVERGENCE_ROW == H3 and lp.DIVERGENCE_EXPECTED == {
        "roadmapSelection": "Agent Router", "decisions": ("OW-D3", "H3-D1"), "deferral": "RUN-GATEWAY-ADOPT-001"}


def test_the_amendment_tables_are_rendered_and_pin_providers_yaml_only():
    data = lp.strict(_raw(lp.DATA_PATH))
    lines = _adr().split("\n")
    cats = {c["path"]: c["sha256"] for c in data["catalogues"]}
    for table in lp.AMENDMENT_TABLES:
        begin, end = lp._markers(table)
        block = lp.render(data, table)
        assert block == lp.render(json.loads(json.dumps(data)), table)
        assert lines[lines.index(begin) + 1:lines.index(end)] == block
        assert lp.DATA_PATH in block[0] and lp.SCHEMA_VERSION in block[0] and cats[lp.PROVIDERS_PATH] in block[0]
        assert cats[lp.SERVICES_PATH] not in block[0] and cats[lp.REPOSITORIES_PATH] not in block[0]


def test_every_span_records_its_section_and_r14_accepts_the_head():
    data = _data()
    assert lp._sources(data, ROOT, {}) == 112
    lp._r14(data)
    lp._r14(data["deployables"])


# ---------------------------------------------------------------- the binding rules' self-checks (BR-TT-1 to BR-TT-5)

def test_br_tt_1_binding_spans_are_tied_to_their_own_document():
    data = _data()
    for entry in data["baselineBindings"]:
        assert entry["document"]["path"] == entry["delivery"]["path"] == "docs/harnesses/%s.md" % entry["harness"]
    assert [e["harness"] for e in data["baselineBindings"]] == list(lp.STEMS)
    assert not hasattr(lp, "TOKENS")  # the upstream-to-token table is design-time only


def _plan_span(data):
    return _binding(data, "runtime.infrastructure", "helm/helm")["target"]["span"]


def test_br_tt_1_a_plan_span_s_lines_alone_are_accepted():
    data = _data()
    _plan_span(data)["lines"] = [140, 140]
    assert lp.check(ROOT, _ov(data)) == HEAD_SUMMARY


def test_br_tt_1_a_plan_span_s_changed_digest_is_refused():
    data = _data()
    _plan_span(data)["sha256"] = "0" * 64
    _refused("R5", _ov(data))


def test_br_tt_1_bindings_expected_compares_the_plan_span_s_digest(monkeypatch):
    rows = [list(row) for row in lp.BINDINGS_EXPECTED]
    at = next(i for i, row in enumerate(rows) if row[2] == "PLAN_LIBRARY")
    key = list(rows[at][3])
    key[2] = "0" * 64
    rows[at][3] = tuple(key)
    monkeypatch.setattr(lp, "BINDINGS_EXPECTED", tuple(tuple(row) for row in rows))
    _refused("R12", {}, "BINDINGS_EXPECTED")


def test_br_tt_4_every_module_binding_ends_with_its_deployable():
    providers = lp.safe_load(_raw(lp.PROVIDERS_PATH))
    bound = {b["serviceId"]: b["moduleId"] for b in providers["serviceModuleBindings"]}
    ids = [d["id"] for d in _data()["deployables"]]
    assert len(ids) == 28 and all(bound[d].endswith("." + d) for d in ids)


def test_br_tt_4_native_rows_and_frameworks_sources():
    data = _data()
    natives = [r for r in data["outsideCatalogue"] if r["id"] in lp.NATIVE_ROWS]
    assert len(natives) == 2 and all(r["frameworks"] == [] and "frameworksSources" not in r for r in natives)
    assert all(d["frameworksSources"] for d in data["deployables"] if d["plannedLanguage"] != "UPSTREAM_OWN")
    assert HEAD_SUMMARY["spans"] == 112


def test_br_tt_5_the_v1_cases_change_as_appendix_c_states():
    data = _data()
    R1_MUTATIONS["schema-version"](data)
    assert data["schemaVersion"] == "planeon.internal.language-placement/v3"
    moved = {"deployable-toolchain-not-in-span", "repository-toolchain-not-in-span"}
    assert moved <= set(R4_MUTATIONS) and not moved & set(R5_MUTATIONS)
    assert [len(t) for t in (R1_MUTATIONS, R3_MUTATIONS, R4_MUTATIONS, R5_MUTATIONS, R6_MUTATIONS, R7_MUTATIONS)] == [
        18, 12, 10, 10, 5, 10]


# ---------------------------------------------------------------- section 5: one test per refusal (BR-TT-2, BR-TT-3)
# Each row's builder returns an overlay (or, for the direct rows, a call); the test asserts the design's
# "First broken rule" column under the order R1-R7, R9-R14, then R8.

S5 = {}


def s5(number, slug, expected):
    def register(build):
        S5[number] = (slug, expected, build)
        return build
    return register


@s5(1, "section-not-a-heading", "R1")
def _s5_01(mp):
    data = _data()
    _row(data, "deployables", "operator")["source"]["section"] = "Deployables"
    return _ov(data)


@s5(2, "unknown-packaging", "R1")
def _s5_02(mp):
    data = _data()
    _row(data, "deployables", "operator")["packaging"] = ["RPM"]
    return _ov(data)


@s5(3, "unknown-decision", "R1")
def _s5_03(mp):
    data = _data()
    _row(data, "deployables", "operator")["decision"] = "ADR-9999"
    return _ov(data)


@s5(4, "renamed-divergence-key", "R1")
def _s5_04(mp):
    data = _data()
    divergence = _binding(data, *H3)["divergence"]
    divergence["selected"] = divergence.pop("roadmapSelection")
    return _ov(data)


@s5(5, "catalog-target-without-token", "R1")
def _s5_05(mp):
    data = _data()
    _binding(data, "execution.ml-decision", "scikit-learn/scikit-learn")["target"].pop("token")
    return _ov(data)


@s5(6, "deferred-target-with-span", "R1")
def _s5_06(mp):
    data = _data()
    target = _binding(data, "execution.orchestration", "temporalio/temporal")["target"]
    target["span"] = _copy(_entry(data, "execution.orchestration")["delivery"])
    return _ov(data)


@s5(7, "toolchain-without-name-version", "R4")
def _s5_07(mp):
    mp.setitem(lp.TOOLCHAIN_EXPECTED["deployables"], "control-web", "TypeScript")
    data = _data()
    _row(data, "deployables", "control-web")["toolchain"] = "TypeScript"
    return _ov(data)


@s5(8, "toolchain-not-its-constant", "R4")
def _s5_08(mp):
    data = _data()
    _row(data, "deployables", "operator")["toolchain"] = "Go 1.26.8"
    return _ov(data)


@s5(9, "v1-span-off-its-roots", "R5")
def _s5_09(mp):
    data = _data()
    line = _line_containing(lp.ADR_PATH, "and the Rust of R10's native roles")
    _row(data, "outsideCatalogue", "r12-native-probes")["sources"][0] = _span_at(lp.ADR_PATH, line, line, ["Rust"])
    return _ov(data)


@s5(10, "frameworks-span-off-docs-repositories", "R5")
def _s5_10(mp):
    data = _data()
    native = _row(data, "outsideCatalogue", "native-host-enforcement-roles")["sources"][0]
    first, last = native["lines"]
    _row(data, "deployables", "inference-api")["frameworksSources"][0] = _span_at(native["path"], first, last, ["Rust"])
    return _ov(data)


@s5(11, "binding-span-off-docs-harnesses", "R5")
def _s5_11(mp):
    data = _data()
    first, last = data["h10Sources"]["r08"]["lines"]
    _entry(data, "execution.ml-decision")["document"] = _span_at(PLAN_08, first, last, ["PostgreSQL leases/outbox"])
    return _ov(data)


@s5(12, "duplicated-heading", "R5")
def _s5_12(mp):
    raw = _raw(PLAN_08)
    assert raw.endswith(b"\n")
    return {PLAN_08: raw + b"\n" + lp.TOOLCHAIN_SECTION.encode() + b"\n"}


@s5(13, "renamed-heading", "R5")
def _s5_13(mp):
    heading = lp.TOOLCHAIN_SECTION.encode() + b"\n"
    return {PLAN_08: _replaced(PLAN_08, heading, heading.replace(b"toolchain", b"toolchains"))}


@s5(14, "copied-to-another-section-then-edited", "R5")
def _s5_14(mp):
    line, _, raw = _r08()
    other = _next_heading(raw, lp.TOOLCHAIN_SECTION)
    assert raw.count(other) == 1
    edited = raw.replace(line, line.replace(b"PostgreSQL leases/outbox", b"PostgreSQL leases and outbox"))
    return {PLAN_08: edited.replace(other, other + line)}


@s5(15, "moved-to-another-section", "R5")
def _s5_15(mp):
    line, _, raw = _r08()
    other = _next_heading(raw, lp.TOOLCHAIN_SECTION)
    return {PLAN_08: raw.replace(line, b"").replace(other, other + line)}


@s5(16, "moved-to-the-end", "R5")
def _s5_16(mp):
    line, _, raw = _r08()
    last_heading = [x for x in lp._lines(raw) if lp.HEADING.match(x)][-1]
    assert last_heading != lp.TOOLCHAIN_SECTION.encode() + b"\n" and raw.endswith(b"\n")  # a multi-section plan
    return {PLAN_08: raw.replace(line, b"") + line}


@s5(17, "duplicated-within-the-section", "R5")
def _s5_17(mp):
    line, _, raw = _r08()
    return {PLAN_08: raw.replace(line, line + line)}


@s5(18, "moved-within-the-section", "accepted")
def _s5_18(mp):
    line, after, raw = _r08()
    return {PLAN_08: raw.replace(line + after, after + line)}


@s5(19, "runtime-not-tech-expected", "R9")
def _s5_19(mp):
    data = _data()
    _row(data, "deployables", "operator")["runtime"] = "Go 1.26.8"
    return _ov(data)


@s5(20, "packaging-not-the-module-s", "R10")
def _s5_20(mp):
    chart = (b"      - {name: mas-harness-operator-chart, type: HELM_CHART, artifact: mas-harness-operator/chart, "
             b"digest: null, digestStatus: MISSING_PLANNED}\n")
    return _repinned(_data(), lp.PROVIDERS_PATH, _replaced(lp.PROVIDERS_PATH, chart, b""))


@s5(21, "upstream-not-the-third-party-artifact", "R10")
def _s5_21(mp):
    raw = _replaced(lp.PROVIDERS_PATH, b"artifact: otel/opentelemetry-collector-contrib,",
                    b"artifact: mas-harness-trust-plane/otel-collector,")
    return _repinned(_data(), lp.PROVIDERS_PATH, raw)


def _services_implemented(deployable):
    return _edited(lp.SERVICES_PATH, b"  - id: %s\n    ownerRepository:" % deployable.encode(),
                   b"    implementationStatus: PLANNED\n", b"    implementationStatus: IMPLEMENTED\n")


@s5(22, "status-not-services-yaml-s", "R10")
def _s5_22(mp):
    return _repinned(_data(), lp.SERVICES_PATH, _services_implemented("usage-ledger"))


@s5(23, "implemented-at-the-base", "R10")
def _s5_23(mp):
    expected = list(lp.TECH_EXPECTED["usage-ledger"])
    expected[3] = "IMPLEMENTED"
    mp.setitem(lp.TECH_EXPECTED, "usage-ledger", tuple(expected))
    data = _data()
    _row(data, "deployables", "usage-ledger")["implementationStatus"] = "IMPLEMENTED"
    return _repinned(data, lp.SERVICES_PATH, _services_implemented("usage-ledger"))


@s5(24, "binding-not-ending-in-its-id", "R10")
def _s5_24(mp):
    raw = _replaced(lp.PROVIDERS_PATH, b"- serviceId: operator\n  moduleId: module.runtime.infrastructure.operator\n",
                    b"- serviceId: operator\n  moduleId: module.runtime.infrastructure.bundle-verifier\n")
    return _repinned(_data(), lp.PROVIDERS_PATH, raw)


@s5(25, "framework-not-frameworks-expected", "R11")
def _s5_25(mp):
    data = _data()
    _row(data, "deployables", "inference-api")["frameworks"].append("Django")
    return _ov(data)


def _frameworks_patched(mp, deployable, change):
    items = change(list(lp.FRAMEWORKS_EXPECTED[deployable]))
    mp.setitem(lp.FRAMEWORKS_EXPECTED, deployable, tuple(items))
    data = _data()
    _row(data, "deployables", deployable)["frameworks"] = items
    return _ov(data)


@s5(26, "item-not-a-whole-word", "R11")
def _s5_26(mp):
    return _frameworks_patched(mp, "inference-api", lambda items: ["Py" if i == "Pydantic v2" else i for i in items])


@s5(27, "runtime-in-frameworks", "R11")
def _s5_27(mp):
    return _frameworks_patched(mp, "inference-api",
                               lambda items: items + [_row(_data(), "deployables", "inference-api")["runtime"]])


@s5(28, "duplicate-item", "R11")
def _s5_28(mp):
    return _frameworks_patched(mp, "inference-api", lambda items: items + [items[0]])


@s5(29, "frameworks-span-in-another-section", "R11")
def _s5_29(mp):
    raw = _raw(PLAN_06)
    lines = raw.decode("utf-8").split("\n")
    other = _next_heading(raw, lp.TOOLCHAIN_SECTION).rstrip(b"\n").decode("utf-8")
    number = next(n for n in range(lines.index(other) + 1, len(lines)) if lines[n].startswith("- ")) + 1
    word = lines[number - 1][2:].split(" ")[0]
    data = _data()
    _row(data, "deployables", "inference-api")["frameworksSources"][0] = _span_at(PLAN_06, number, number, [word])
    return _ov(data)


@s5(30, "missing-frameworks-source", "R11")
def _s5_30(mp):
    data = _data()
    _row(data, "deployables", "inference-api")["frameworksSources"] = []
    return _ov(data)


@s5(31, "native-frameworks-not-empty", "R11")
def _s5_31(mp):
    data = _data()
    _row(data, "outsideCatalogue", "r12-native-probes")["frameworks"] = ["musl"]
    return _ov(data)


@s5(32, "dropped-binding-row", "R12")
def _s5_32(mp):
    data = _data()
    _entry(data, "execution.ml-decision")["rows"].pop()
    return _ov(data)


@s5(33, "duplicated-binding-row", "R12")
def _s5_33(mp):
    data = _data()
    rows = _entry(data, "execution.ml-decision")["rows"]
    rows.append(_copy(rows[0]))
    return _ov(data)


@s5(34, "re-kinded-row", "R12")
def _s5_34(mp):
    data = _data()
    row = _binding(data, "runtime.model-inference", "ollama/ollama")
    row.update(kind="DEFERRED", target={"item": "MODEL-ADOPT-001"})
    return _ov(data)


@s5(35, "retargeted-row", "R12")
def _s5_35(mp):
    data = _data()
    _binding(data, "runtime.model-inference", "ollama/ollama")["target"]["record"] = "provider.planeon.vllm"
    return _ov(data)


@s5(36, "token-absent-from-the-record", "R12")
def _s5_36(mp):
    raw = _edited(lp.PROVIDERS_PATH, b"  - id: provider.planeon.ollama\n", b"    providers: [planeon.ollama]\n",
                  b"    providers: []\n")
    return _repinned(_data(), lp.PROVIDERS_PATH, raw)


@s5(37, "selection-contradicting-the-kind", "R12")
def _s5_37(mp):
    raw = _edited(lp.PROVIDERS_PATH, b"  - id: provider.planeon.litellm-local\n", b"    selection: OPTIONAL\n",
                  b"    selection: CONDITIONAL\n")
    return _repinned(_data(), lp.PROVIDERS_PATH, raw)


@s5(38, "plan-token-missing", "R12")
def _s5_38(mp):
    mp.setitem(lp.PLAN_TOKENS, "helm/helm", "Helm 5")
    return {}


@s5(39, "deferred-item-not-on-the-delivery-line", "R12")
def _s5_39(mp):
    rows = [list(row) for row in lp.BINDINGS_EXPECTED]
    at = next(i for i, row in enumerate(rows) if row[1] == "trinodb/trino")
    rows[at][3] = ("KN-DATA-ADOPT-002",)
    mp.setattr(lp, "BINDINGS_EXPECTED", tuple(tuple(row) for row in rows))
    data = _data()
    _binding(data, "knowledge.data-integration", "trinodb/trino")["target"]["item"] = "KN-DATA-ADOPT-002"
    return _ov(data)


@s5(40, "stems-out-of-order", "R12")
def _s5_40(mp):
    data = _data()
    entries = data["baselineBindings"]
    entries[0], entries[1] = entries[1], entries[0]
    return _ov(data)


@s5(41, "document-span-not-holding-the-upstreams", "R12")
def _s5_41(mp):
    data = _data()
    entry = _entry(data, "execution.ml-decision")
    entry["document"] = _copy(entry["delivery"])
    return _ov(data)


@s5(42, "delivery-span-in-another-harness-s-file", "R12")
def _s5_42(mp):
    data = _data()
    _entry(data, "execution.ml-decision")["delivery"] = _copy(_entry(data, "execution.orchestration")["delivery"])
    return _ov(data)


@s5(43, "divergence-altered", "R12")
def _s5_43(mp):
    data = _data()
    _binding(data, *H3)["divergence"]["roadmapSelection"] = "LiteLLM"
    return _ov(data)


@s5(44, "divergence-dropped", "R12")
def _s5_44(mp):
    data = _data()
    _binding(data, *H3).pop("divergence")
    return _ov(data)


@s5(45, "divergence-on-another-row", "R12")
def _s5_45(mp):
    data = _data()
    _binding(data, "runtime.model-inference", "ollama/ollama")["divergence"] = _copy(_binding(data, *H3)["divergence"])
    return _ov(data)


@s5(46, "divergence-deferral-not-on-h3-s-delivery-line", "R12")
def _s5_46(mp):
    mp.setitem(lp.DIVERGENCE_EXPECTED, "deferral", "RUN-UI-ADOPT-001")
    data = _data()
    _binding(data, *H3)["divergence"]["deferral"] = "RUN-UI-ADOPT-001"
    return _ov(data)


def _temporal_record(selection):
    record = (b"  - id: provider.temporal\n    harness: execution.orchestration\n    scope: RUNTIME\n"
              b"    kind: ADAPTER\n    selection: %s\n    providers: [temporal]\n    installUnits:\n"
              b"      - {name: temporal, type: OCI_IMAGE, artifact: temporalio/server, digest: null, "
              b"digestStatus: MISSING_PLANNED}\n" % selection)
    anchor = b"  - id: provider.planeon.ollama\n"
    return _replaced(lp.PROVIDERS_PATH, anchor, record + anchor)


@s5(47, "default-temporal-record", "R13")
def _s5_47(mp):
    return _repinned(_data(), lp.PROVIDERS_PATH, _temporal_record(b"DEFAULT"))


@s5(48, "optional-temporal-record", "accepted")
def _s5_48(mp):
    data = _data()
    overlay = _repinned(data, lp.PROVIDERS_PATH, _temporal_record(b"OPTIONAL"))
    overlay[lp.ADR_PATH] = _rerendered(data)  # the amendment captions pin providers.yaml
    return overlay


@s5(49, "r08-evidence-missing", "R13")
def _s5_49(mp):
    mp.setattr(lp, "H10_R08_EVIDENCE", lp.H10_R08_EVIDENCE + ("Temporal is the default",))
    return {}


@s5(50, "default-in-an-exclusivity-group", "R13")
def _s5_50(mp):
    raw = _edited(lp.PROVIDERS_PATH, b"  - id: provider.planeon.ollama\n", b"    selection: CONDITIONAL\n",
                  b"    selection: DEFAULT\n")
    return _repinned(_data(), lp.PROVIDERS_PATH, raw)


@s5(51, "two-default-bound-records-for-a-capability", "R13")
def _s5_51(mp):
    entry = (b"- capability: planeon.otel\n  resolution: ALL\n  modules:\n"
             b"  - module.trust.observability.otel-collector\n")
    raw = _replaced(lp.PROVIDERS_PATH, entry, entry + b"  - external.otel-backend\n")
    return _repinned(_data(), lp.PROVIDERS_PATH, raw)


@s5(52, "upstream-row-not-upstream-own", "R14")
def _s5_52(mp):
    row = _copy(_row(_data(), "deployables", "otel-collector"))
    row["plannedLanguage"] = "PYTHON"
    return lambda: lp._r14([row])


@s5(53, "upstream-own-row-without-an-upstream", "R14")
def _s5_53(mp):
    row = _copy(_row(_data(), "deployables", "otel-collector"))
    row["upstream"] = None
    return lambda: lp._r14([row])


@s5(54, "amendment-table-drifting", "R8")
def _s5_54(mp):
    cell = b"| otel/opentelemetry-collector-contrib |"
    return {lp.ADR_PATH: _replaced(lp.ADR_PATH, cell, b"| null |")}


@s5(55, "v1-table-drifting", "R8")
def _s5_55(mp):
    cell = b"| `typescript-sdk` | `mas-harness-sdks` | TYPESCRIPT |"
    return {lp.ADR_PATH: _replaced(lp.ADR_PATH, cell, cell.replace(b"TYPESCRIPT", b"PYTHON"))}


# errata E1 (CONTRACT r1, MON-GOV005-CR1): rows 56-59, each span recomputed from the head bytes

@s5(56, "frameworks-source-on-an-upstream-own-row", "R11")
def _s5_56(mp):
    data = _data()
    row = _row(data, "deployables", "otel-collector")
    source = row["source"]
    assert row["plannedLanguage"] == "UPSTREAM_OWN" and row["frameworksSources"] == []
    assert source["path"] == "docs/repositories/09-mas-harness-trust-plane.md" and source["lines"] == [100, 100]
    span = _span_at(source["path"], 100, 100, ["OTel Collector"])
    assert span["section"] == lp.TOOLCHAIN_SECTION
    row["frameworksSources"].append(span)
    return _ov(data)


@s5(57, "delivery-span-off-its-delivery-line", "R12")
def _s5_57(mp):
    data = _data()
    entry = _entry(data, "execution.ml-decision")
    path, number = entry["delivery"]["path"], entry["delivery"]["lines"][0] + 1
    assert number == 20
    word = lp.span_bytes(_raw(path), number, number).decode("utf-8").split(" ")[0]
    span = _span_at(path, number, number, [word])
    assert span["section"] == entry["delivery"]["section"]
    entry["delivery"] = span
    return _ov(data)


@s5(58, "document-span-of-more-than-one-line", "R12")
def _s5_58(mp):
    data = _data()
    entry = _entry(data, "execution.ml-decision")
    document = entry["document"]
    assert document["lines"] == [16, 16]
    span = _span_at(document["path"], 16, 17, document["evidence"])
    assert span["section"] == document["section"]
    entry["document"] = span
    return _ov(data)


@s5(59, "r08-span-of-more-than-one-line", "R13")
def _s5_59(mp):
    data = _data()
    r08 = data["h10Sources"]["r08"]
    assert r08["lines"] == [103, 103]
    span = _span_at(r08["path"], 102, 103, r08["evidence"])
    assert span["section"] == r08["section"]
    data["h10Sources"]["r08"] = span
    return _ov(data)


FIRST_BROKEN_RULE = (["R1"] * 6 + ["R4"] * 2 + ["R5"] * 9 + ["accepted", "R9"] + ["R10"] * 5 + ["R11"] * 7
                     + ["R12"] * 15 + ["R13", "accepted", "R13", "R13", "R13", "R14", "R14", "R8", "R8"]
                     + ["R11", "R12", "R12", "R13"])


def test_section_5_has_one_row_per_refusal_with_its_column():
    assert sorted(S5) == list(range(1, 60))
    assert [S5[n][1] for n in sorted(S5)] == FIRST_BROKEN_RULE


@pytest.mark.parametrize("number", sorted(S5), ids=lambda n: "%02d-%s" % (n, S5[n][0]))
def test_section_5_row_reaches_its_first_broken_rule(number, monkeypatch):
    _, expected, build = S5[number]
    built = build(monkeypatch)
    if callable(built):  # the direct rows (BR-TT-2): R14 on a constructed row
        with pytest.raises(lp.Refusal) as caught:
            built()
        assert caught.value.rule == expected, str(caught.value)
    elif expected == "accepted":
        assert lp.check(ROOT, built) == HEAD_SUMMARY
    else:
        _refused(expected, built)
