"""MET-GOV-004 (LANG-PLACEMENT-ADR-001): scripts/language_placement.py over ADR 0010's data. The head is accepted, and
one in-memory mutation per rule is refused with its rule id (design section 4), the binding build rule BR-GOV4-1's
constants and rules included: EXPECTED, OUTSIDE_EXPECTED, REPO_LANGUAGES, the PENDING: rule and the verbatim toolchain
rule. Mutations go through the checker's overlay, so no file in the tree is written."""
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
        "outsideCatalogue": 5, "exceptions": 5, "spans": 49}


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
    "schema-version": _set("schemaVersion", "planeon.internal.language-placement/v2"),
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
    "deployable-toolchain-not-in-span": lambda d: _row(d, "deployables", "ai-gateway").update(toolchain="Python 3.13.0"),
    "repository-toolchain-not-in-span": lambda d: _row(d, "repositories", "conformance-labs").update(
        toolchain="Node 24.20.0 LTS, TypeScript 5"),
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
    "outsideCatalogue": 5, "exceptions": 5, "spans": 49}


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
    assert lp._sources(data, ROOT, {}) == 49


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
