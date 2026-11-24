"""D5a oracle tests for MET-014 (slot 296): GR-DECISION-RECORD-001, REG-ALIGN-001, EDGE-V13 and the head layer.

Owner decision D5a: these black-box tests are written outside the candidate, by a non-author, one part per
member plus the head layer (V1, E1 per member, E2, E3, V4, V6) and the packet YAML, table and registry.
Every expected value is a literal taken from CONTRACT_296 r2, R12's GR-DECISION-RECORD-001 draft r2 with
its erratum E1, R03's REG-ALIGN-001 draft r4, R10's EDGE-V13 draft r2 or the operator-stated facts of the
oracle brief, and is cited on the assert's own line or the line directly above it. The repository files the
tests read at run time are fixtures to load and mutate, never a source of expectations.

C18 (the era-read rule): every repository file is read through the head's era reader,
head.reviewed_bytes(path), never from the live tree. The head scripts/validate_met_014.py is the one
repository module loaded, by file path, into a fresh module object; the member models and checkers (and
EDGE-V13's bases) reach these tests only as the era objects head._era_checker builds. The one exec is
the v1 transcript function compiled from the v1 model's era bytes (EDGE-V13's bite).
"""

from __future__ import annotations

import ast
import copy
import hashlib
import importlib.util
import json
import re
from collections.abc import Mapping
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
HEAD_PATH = ROOT / "scripts" / "validate_met_014.py"

STEP = "MET-014"
PREV = "MET-013"
ITEMS = ("GR-DECISION-RECORD-001", "REG-ALIGN-001", "EDGE-V13")
BASE_MAIN = "4b1386e0bf22e5d33c052ed27befc014614ac820"
BASE_TREE = "31565845b85467700f5fbe31d69223feed3c04de"
BASE_IDS = 319
TABLE_ENTRIES = 221
REGISTRY_ENTRIES = 43
TABLE_PATH = "ci/parallel_suite_weights.json"
YAML_PATH = "task-packets/MET-014.yaml"
HEAD_TEST = "tests/test_met_014.py"
ORACLE_TEST = "tests/test_met_014_oracle.py"
HEAD_MODULE = "scripts/validate_met_014.py"
MEMBER_TESTS = (
    "tests/test_decision_record.py",
    "tests/test_regulatory_alignment.py",
    "tests/test_edge_record_v13.py",
)
YAML_KEYS = (
    "id",
    "repository",
    "branch",
    "objective",
    "predecessors",
    "allowedPaths",
    "warmSourceAccess",
    "sourceReuse",
    "prefetchCommands",
    "offlineExecution",
    "contracts",
    "deliverables",
    "excluded",
    "offlineAcceptanceCommands",
    "expectedEvidence",
    "rollback",
)
PACKET_FILES_C1 = (
    "architecture/decision-record/README.md",
    "architecture/decision-record/decision-record.schema.json",
    "architecture/decision-record/reason-codes.json",
    "architecture/decision-record/vectors.json",
    "architecture/decision-record/status.json",
    "scripts/decision_record.py",
    "scripts/validate_decision_record.py",
    "tests/test_decision_record.py",
    "architecture/regulatory-alignment.json",
    "architecture/regulatory-alignment-README.md",
    "scripts/validate_regulatory_alignment.py",
    "tests/test_regulatory_alignment.py",
    "architecture/broker-handoff-inputs-v2/channel.schema.json",
    "architecture/broker-handoff-inputs-v2/vectors.json",
    "architecture/artifact-edges/operator-harness-engineering-v13.json",
    "architecture/artifact-edges/README-v13.md",
    "scripts/broker_handoff_transcript_v2.py",
    "scripts/validate_edge_record_v13.py",
    "tests/test_edge_record_v13.py",
)
MEMBER_ROWS = (
    (
        "GR-DECISION-RECORD-001",
        "scripts/decision_record.py",
        "scripts/validate_decision_record.py",
        "architecture/decision-record/reason-codes.json",
        "architecture/decision-record/vectors.json",
        (),
        None,
    ),
    (
        "REG-ALIGN-001",
        None,
        "scripts/validate_regulatory_alignment.py",
        "architecture/regulatory-alignment.json",
        None,
        (),
        None,
    ),
    (
        "EDGE-V13",
        "scripts/broker_handoff_transcript_v2.py",
        "scripts/validate_edge_record_v13.py",
        "architecture/artifact-edges/operator-harness-engineering-v13.json",
        "architecture/broker-handoff-inputs-v2/vectors.json",
        (("safe_yaml", "scripts/safe_yaml.py"), ("validate_proxy_contract", "scripts/validate_proxy_contract.py")),
        "architecture/broker-handoff-inputs-v2/channel.schema.json",
    ),
)
EDGE_V12 = "architecture/artifact-edges/operator-harness-engineering-v12.json"
V1_SCHEMA = "architecture/broker-handoff-inputs/channel.schema.json"
V1_VECTORS = "architecture/broker-handoff-inputs/vectors.json"
V1_MODEL = "scripts/validate_broker_handoff.py"
BASE_READS = (EDGE_V12, V1_SCHEMA, V1_VECTORS, V1_MODEL)
CASCADE_SCRIPTS = (V1_MODEL, "scripts/validate_proxy_contract.py")
RA_README = "architecture/regulatory-alignment-README.md"

# ---------------------------------------------------------------------------------------------- helpers


def _load_head():
    spec = importlib.util.spec_from_file_location("met_014_oracle_head", HEAD_PATH)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.fixture(scope="module")
def head():
    return _load_head()


@pytest.fixture(scope="module")
def catalog(head):
    names = [*head.authority()["baselinePackets"], head.NEW_PACKET]
    return {name: head.safe_load(head.reviewed_bytes("task-packets/" + name + ".yaml")) for name in names}


def _field(row, name):
    if isinstance(row, Mapping):
        return row.get(name)
    return getattr(row, name, None)


def _json(head, path):
    return json.loads(head.reviewed_bytes(path))


def _jcs(value):
    """RFC 8785 form for the integer-only I-JSON of R12 draft r2 section 2."""
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def _record_digest(value):
    """R12 draft r2 section 2: digest(x) is sha256: followed by the hex SHA-256 of x's RFC 8785 form."""
    return "sha256:" + hashlib.sha256(_jcs(value)).hexdigest()


def _compact(value):
    """R10 draft r2 section 2 item 2: the previous frame as compact JSON with sorted keys."""
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _other(value):
    if isinstance(value, bool):
        return not value
    if isinstance(value, int):
        return value + 1
    if isinstance(value, str):
        if value and value[-1] in "0123456789abcdef":
            return value[:-1] + ("1" if value[-1] == "0" else "0")
        return value + "-other"
    raise TypeError("unexpected field type")


def _str_leaves(node):
    if isinstance(node, dict):
        for value in node.values():
            yield from _str_leaves(value)
    elif isinstance(node, list):
        for value in node:
            yield from _str_leaves(value)
    elif isinstance(node, str):
        yield node


def _holder(node, key):
    if isinstance(node, dict):
        if key in node:
            return node
        values = list(node.values())
    elif isinstance(node, list):
        values = node
    else:
        return None
    for value in values:
        found = _holder(value, key)
        if found is not None:
            return found
    return None


def _flip_byte(raw):
    return bytes([raw[0] ^ 1]) + raw[1:]


def _reads(head, path):
    try:
        return isinstance(head.reviewed_bytes(path), bytes)
    except Exception:  # noqa: BLE001 - a refused read counts as not a regular file
        return False


# ------------------------------------------------------------------- part 1: GR-DECISION-RECORD-001 (3a)

GR_POSITIVES = ("GR-P1", "GR-P2", "GR-P3", "GR-P4", "GR-P5", "GR-P6", "GR-P7", "GR-P8a", "GR-P8b")
GR_LIFT_NEGATIVES = ("GR-N7a", "GR-N7b", "GR-N7c", "GR-N7d", "GR-N7e", "GR-N7f")
GR_CODE_NEGATIVES = (
    ("GR-N2", "ERROR_AS_DECISION"),
    ("GR-N3", "RULE_VERSION_MISSING"),
    ("GR-N4", "MODEL_LOWERED"),
    ("GR-N5", "ENVELOPE_MIXED"),
    ("GR-N6", "EFFECTIVE_MISMATCH"),
    ("GR-N11a", "MODEL_APPROVAL"),
    ("GR-N11b", "MODEL_APPROVAL"),
    ("GR-N12", "TRANSFORM_CONFLICT"),
    ("GR-N13a", "TRANSFORM_MISMATCH"),
    ("GR-N13b", "TRANSFORM_MISMATCH"),
    ("GR-N14", "RULE_VERSION_MISSING"),
)
GR_STATED = ("GR-N1", "GR-N8", "GR-N9", "GR-N10")
GR_LIFT_IDS = ("GR-P6",) + GR_LIFT_NEGATIVES
GR_ALL_IDS = GR_POSITIVES + GR_LIFT_NEGATIVES + tuple(case_id for case_id, _ in GR_CODE_NEGATIVES) + GR_STATED
GR_ORDER = {
    "GUARDRAIL": ("DENY", "ESCALATE", "TRANSFORM", "ALLOW"),
    "ADMISSION_SCAN": ("DENY", "ESCALATE", "ALLOW"),
    "GRADE": ("FAIL", "PASS"),
}
GR_DECIDED = {**GR_ORDER, "APPROVAL": ("REJECTED", "EXPIRED", "CANCELLED", "UNAVAILABLE", "APPROVED")}
GR_FAIL_CLOSED = {"GUARDRAIL": "DENY", "ADMISSION_SCAN": "DENY", "GRADE": "UNGRADED", "APPROVAL": "UNAVAILABLE"}
GR_KIND_BASE = {"GUARDRAIL": "GR-P1", "ADMISSION_SCAN": "GR-P3", "GRADE": "GR-P4", "APPROVAL": "GR-P5"}
GR_CODES = (
    "ENVELOPE_MIXED",
    "EFFECTIVE_MISMATCH",
    "ERROR_AS_DECISION",
    "RULE_VERSION_MISSING",
    "MODEL_APPROVAL",
    "MODEL_LOWERED",
    "TRANSFORM_CONFLICT",
    "TRANSFORM_MISMATCH",
)
GR_FAMILIES = ("E1", "E2", "E3", "E4", "E5", "E6", "E7", "L1", "L2", "L3", "L4", "L5")
GR_ORDER_PAIRS = tuple(
    (kind, order[high], order[low])
    for kind, order in GR_ORDER.items()
    for high in range(len(order))
    for low in range(high + 1, len(order))
)
LIFT_MUTATIONS = (
    "L1-REJECTED",
    "L1-EXPIRED",
    "L1-CANCELLED",
    "L1-UNAVAILABLE",
    "L2-expired-at-effect",
    "L3-scopeDigest",
    "L3-subjectDigest",
    "L3-revision",
    "L4-later-escalation",
    "L5-already-lifted",
    "DENY-escalation",
)


def _gr_cases(head):
    vectors = _json(head, _field(head.DECISION, "vectors"))
    return {case["id"]: case for case in vectors["cases"]}


def _ev(model, record):
    return tuple(model.evaluate(record))


def _lift(model, inp):
    return model.lift(inp["escalation"], inp["approval"], inp["lifted"], inp["effect"])


def _earliest(container, key):
    value = container[key]
    if isinstance(value, bool) or value is None:
        return 0
    if isinstance(value, str):
        container[key] = "1970-01-01T00:00:00Z"
        return 1
    if isinstance(value, int):
        container[key] = 0
        return 1
    if isinstance(value, dict):
        keys = list(value)
    elif isinstance(value, list):
        keys = list(range(len(value)))
    else:
        return 0
    return sum(_earliest(value, inner) for inner in keys)


def _expire(node):
    hits = 0
    if isinstance(node, dict):
        for key in list(node):
            if "expir" in key.lower():
                hits += _earliest(node, key)
            else:
                hits += _expire(node[key])
    elif isinstance(node, list):
        for item in node:
            hits += _expire(item)
    return hits


def _mutate_lift(inp, name):
    escalation, approval = inp["escalation"], inp["approval"]
    if name.startswith("L1-"):
        approval["envelope"]["decision"] = name[3:]
        approval["envelope"]["effectiveDecision"] = name[3:]
    elif name == "L2-expired-at-effect":
        hits = _expire(approval)
        assert hits > 0  # R12 draft r2 section 3: the approval carries HR-APPROVAL's expiry (its O3)
    elif name.startswith("L3-"):
        field = name[3:]
        approval["subject"][field] = _other(approval["subject"][field])
    elif name == "L4-later-escalation":
        later = copy.deepcopy(escalation)
        later["decisionId"] = _other(later["decisionId"])
        approval["escalationRef"] = _record_digest(later)
    elif name == "L5-already-lifted":
        inp["lifted"] = [_record_digest(escalation)]
    elif name == "DENY-escalation":
        escalation["envelope"]["decision"] = "DENY"
        escalation["envelope"]["effectiveDecision"] = "DENY"
        approval["escalationRef"] = _record_digest(escalation)
    return inp


def _with_contributions(base, contribution, decision):
    record = copy.deepcopy(base)
    contributions = record["contributions"]
    assert len(contributions) >= 1  # R12 draft r2 section 6 P1/P3/P4: the positives carry contributions
    contributions[0]["source"] = "DETERMINISTIC"
    contributions[0]["model"] = None
    for item in contributions:
        item["decision"] = contribution
    record["envelope"]["decision"] = decision
    record["envelope"]["effectiveDecision"] = decision
    return record


def _code_lists(node):
    if isinstance(node, dict):
        for value in node.values():
            yield from _code_lists(value)
    elif isinstance(node, list):
        projected = []
        for item in node:
            if isinstance(item, str) and item in GR_CODES:
                projected.append(item)
            elif isinstance(item, dict):
                hits = [value for value in item.values() if isinstance(value, str) and value in GR_CODES]
                if hits:
                    projected.append(hits[0])
        yield projected
        for item in node:
            yield from _code_lists(item)


def test_gr_vector_ids_and_kinds(head):
    """CONTRACT_296 section 3a (vectors, L2), R12 draft r2 section 6 and erratum E1: the case set and shapes."""
    cases = _json(head, _field(head.DECISION, "vectors"))["cases"]
    ids = [case["id"] for case in cases]
    # CONTRACT_296 section 3a: P1-P8 (P8 as GR-P8a and GR-P8b, operator-stated), N1-N14, N7a-f, N11a-b, N13a-b
    assert sorted(ids) == sorted(GR_ALL_IDS)
    for case in cases:
        # CONTRACT_296 section 3a (L2): each case is {id, kind, input, expect}
        assert {"id", "kind", "input", "expect"} <= set(case)
        # CONTRACT_296 section 3a (L2): P6 and N7a-f are LIFT cases, every other case a RECORD case
        assert case["kind"] == ("LIFT" if case["id"] in GR_LIFT_IDS else "RECORD")
        if case["kind"] == "LIFT":
            # CONTRACT_296 section 3a (L2): a LIFT input is {escalation, approval, lifted, effect}
            assert set(case["input"]) == {"escalation", "approval", "lifted", "effect"}


@pytest.mark.parametrize("case_id", GR_POSITIVES)
def test_gr_positive_accepted(head, case_id):
    """CONTRACT_296 section 3a (D5a needs): each positive accepted (R12 draft r2 section 6, P1-P8)."""
    model, _ = head._era_checker(head.DECISION)
    case = _gr_cases(head)[case_id]
    if case_id == "GR-P6":
        # R12 draft r2 section 6 P6: an ESCALATE and an APPROVAL meeting L1-L4, the consumer may act
        assert _lift(model, copy.deepcopy(case["input"])) == "ACT"
        # operator-stated: run returns {"result": "ACT"} for an acting LIFT case
        assert model.run(case) == {"result": "ACT"}
    else:
        # CONTRACT_296 section 3a: each positive accepted; operator-stated evaluate shape
        assert _ev(model, copy.deepcopy(case["input"])) == ("ACCEPTED", None)
        # operator-stated: run returns {"result": "ACCEPTED"} for an accepted record
        assert model.run(case) == {"result": "ACCEPTED"}


@pytest.mark.parametrize("case_id,code", GR_CODE_NEGATIVES)
def test_gr_negative_refusal_code(head, case_id, code):
    """CONTRACT_296 section 3a: each negative to its refusal code by the one-vector-per-code line."""
    model, _ = head._era_checker(head.DECISION)
    case = _gr_cases(head)[case_id]
    # CONTRACT_296 section 3a (one vector per refusal code); operator-stated evaluate shape
    assert _ev(model, copy.deepcopy(case["input"])) == ("REFUSED", code)
    # CONTRACT_296 section 3a (one vector per refusal code); operator-stated run shape
    assert model.run(case) == {"result": "REFUSED", "code": code}


@pytest.mark.parametrize("case_id", GR_LIFT_NEGATIVES)
def test_gr_negative_lift_refused(head, case_id):
    """CONTRACT_296 section 3a: LIFT_REFUSED N7a-f, with no effect (R12 draft r2 section 6, erratum E1)."""
    model, _ = head._era_checker(head.DECISION)
    case = _gr_cases(head)[case_id]
    inp = copy.deepcopy(case["input"])
    lifted, effect = copy.deepcopy(inp["lifted"]), copy.deepcopy(inp["effect"])
    # CONTRACT_296 section 3a (one vector per refusal code): LIFT_REFUSED N7a-f
    assert _lift(model, inp) == "LIFT_REFUSED"
    # CONTRACT_296 section 3a (L2): LIFT_REFUSED with no effect
    assert inp["lifted"] == lifted and inp["effect"] == effect
    # operator-stated: {"result": "ACT"} is run's acting result, never a refusal's
    assert model.run(case) != {"result": "ACT"}


@pytest.mark.parametrize("case_id", GR_STATED)
def test_gr_negative_stated_result(head, case_id):
    """CONTRACT_296 section 3a: N1, N8, N9 and N10 keep r2's stated results (E3 via E2, E7, GRADE ERROR, set)."""
    model, _ = head._era_checker(head.DECISION)
    case = _gr_cases(head)[case_id]
    record = copy.deepcopy(case["input"])
    if case_id == "GR-N1":
        # R12 draft r2 section 6 N1 (E3, through E2) and section 4 E2: EFFECTIVE_MISMATCH
        assert _ev(model, record) == ("REFUSED", "EFFECTIVE_MISMATCH")
        # R12 draft r2 section 4 E2; operator-stated run shape
        assert model.run(case) == {"result": "REFUSED", "code": "EFFECTIVE_MISMATCH"}
    elif case_id == "GR-N8":
        expected = GR_FAIL_CLOSED[record["kind"]]
        # R12 draft r2 section 4 E7: an unknown value is read as the kind's fail-closed value
        assert _ev(model, record) == ("READ_FAIL_CLOSED", expected)
        # R12 draft r2 section 4 E7; operator-stated run shape
        assert model.run(case) == {"result": "READ_FAIL_CLOSED", "effectiveDecision": expected}
    elif case_id == "GR-N9":
        result = model.run(case)
        # R12 draft r2 section 3: GRADE's fail-closed value is UNGRADED, never PASS nor FAIL
        assert result["result"] == "UNGRADED"
        leaves = set(_str_leaves(result["replayScore"]))
        # R12 draft r2 section 7 point 4: replay-score BLOCKED with blockerCode EVALUATOR_ERROR, not FAILED
        assert "BLOCKED" in leaves and "EVALUATOR_ERROR" in leaves and "FAILED" not in leaves
        holder = _holder(result["replayScore"], "evidenceDigest")
        # R12 draft r2 section 7 point 4: the record as evidenceDigest (digest(x), section 2)
        assert holder is not None and holder["evidenceDigest"] == _record_digest(record)
    else:
        # R12 draft r2 section 3 (APPROVAL fail-closed UNAVAILABLE) and section 4 E7
        assert _ev(model, record) == ("READ_FAIL_CLOSED", "UNAVAILABLE")
        # R12 draft r2 section 4 E7; operator-stated run shape
        assert model.run(case) == {"result": "READ_FAIL_CLOSED", "effectiveDecision": "UNAVAILABLE"}


def test_gr_every_case_replays(head):
    """CONTRACT_296 section 3 member table (E1 form): every cases entry replays to its expectation."""
    model, _ = head._era_checker(head.DECISION)
    cases = _json(head, _field(head.DECISION, "vectors"))["cases"]
    # CONTRACT_296 section 3a: 30 cases (P1-P7, P8a-b, N1-N14 with N7a-f, N11a-b, N13a-b)
    assert len(cases) == len(GR_ALL_IDS)
    for case in cases:
        # CONTRACT_296 section 3 member table, E1 form: each entry replays to its expectation
        assert model.replay(case)[0] is True


def test_gr_lift_positive_acts(head):
    """R12 draft r2 section 3 (L1-L4), erratum E1 (L5), CONTRACT_296 section 3a: P6's input acts unmutated."""
    model, _ = head._era_checker(head.DECISION)
    case = _gr_cases(head)["GR-P6"]
    inp = copy.deepcopy(case["input"])
    escalation, approval = inp["escalation"], inp["approval"]
    # R12 draft r2 section 3: escalationRef is set only on kind APPROVAL
    assert approval["kind"] == "APPROVAL"
    # R12 draft r2 section 3: ESCALATE is the liftable deny
    assert escalation["envelope"]["decision"] == "ESCALATE"
    # R12 draft r2 section 3 (L1): the approval's decision is APPROVED
    assert approval["envelope"]["decision"] == "APPROVED"
    for field in ("scopeDigest", "subjectDigest", "revision"):
        # R12 draft r2 section 3 (L3): the subject fields equal the ESCALATE record's
        assert approval["subject"][field] == escalation["subject"][field]
    # R12 draft r2 section 3 (L4) with section 2: escalationRef = digest(the ESCALATE record), recomputed
    assert approval["escalationRef"] == _record_digest(escalation)
    # CONTRACT_296 section 3a (L2): P6 carries lifted []
    assert inp["lifted"] == []
    # R12 draft r2 section 6 P6: the consumer may act
    assert _lift(model, inp) == "ACT"
    later = copy.deepcopy(escalation)
    later["decisionId"] = _other(later["decisionId"])
    other = copy.deepcopy(case["input"])
    other["lifted"] = [_record_digest(later)]
    # R12 erratum E1 (L5): only a lift of this escalation itself bars acting
    assert _lift(model, other) == "ACT"


@pytest.mark.parametrize("mutation", LIFT_MUTATIONS)
def test_gr_lift_clause_refused(head, mutation):
    """CONTRACT_296 section 3a (D5a needs, L1): one mutation per clause of L1-L5, and DENY never lifted."""
    model, _ = head._era_checker(head.DECISION)
    inp = _mutate_lift(copy.deepcopy(_gr_cases(head)["GR-P6"]["input"]), mutation)
    lifted, effect = copy.deepcopy(inp["lifted"]), copy.deepcopy(inp["effect"])
    # R12 draft r2 section 3 and erratum E1: otherwise the deny stays, LIFT_REFUSED; DENY is never liftable
    assert _lift(model, inp) == "LIFT_REFUSED"
    # CONTRACT_296 section 3a (L2): LIFT_REFUSED with no effect
    assert inp["lifted"] == lifted and inp["effect"] == effect


def test_gr_n7f_lifted_state(head):
    """CONTRACT_296 section 3a (L2, N7f's lifted state) and R12 erratum E1: N7f holds its own digest."""
    cases = _gr_cases(head)
    inp = cases["GR-N7f"]["input"]
    own = _record_digest(inp["escalation"])
    # CONTRACT_296 section 3a: N7f's lifted holds the escalation's own digest
    assert own in inp["lifted"]
    # CONTRACT_296 section 3a: N7f's approval meets L4 (escalationRef = digest of the escalation)
    assert inp["approval"]["escalationRef"] == own
    # CONTRACT_296 section 3a: N7f's approval meets L1 (APPROVED)
    assert inp["approval"]["envelope"]["decision"] == "APPROVED"
    for case_id in ("GR-N7a", "GR-N7b", "GR-N7c", "GR-N7d", "GR-N7e"):
        # CONTRACT_296 section 3a (L2): N7a-e carry lifted []
        assert cases[case_id]["input"]["lifted"] == []


@pytest.mark.parametrize("kind", tuple(GR_FAIL_CLOSED))
def test_gr_fail_closed_value(head, kind):
    """R12 draft r2 section 3 (fail-closed values) and section 4 E2, through evaluate on mutated P7 records."""
    model, _ = head._era_checker(head.DECISION)
    p7 = _gr_cases(head)["GR-P7"]["input"]
    # R12 draft r2 section 6 P7: GUARDRAIL ERROR, effective DENY
    assert (p7["kind"], p7["envelope"]["status"], p7["envelope"]["effectiveDecision"]) == ("GUARDRAIL", "ERROR", "DENY")
    for value in sorted(set(GR_DECIDED[kind]) | {GR_FAIL_CLOSED[kind]}):
        record = copy.deepcopy(p7)
        record["kind"] = kind
        record["envelope"]["effectiveDecision"] = value
        result = _ev(model, record)
        if value == GR_FAIL_CLOSED[kind]:
            # R12 draft r2 section 3 (fail-closed value on ERROR) and section 4 E2
            assert result != ("REFUSED", "EFFECTIVE_MISMATCH")
            if kind == "GUARDRAIL":
                # R12 draft r2 section 6 P7: accepted
                assert result == ("ACCEPTED", None)
        else:
            # R12 draft r2 section 4 E2: an ERROR record's effective value is only the fail-closed value
            assert result[0] != "ACCEPTED"
            if kind == "GUARDRAIL":
                # R12 draft r2 section 4 E2: EFFECTIVE_MISMATCH
                assert result == ("REFUSED", "EFFECTIVE_MISMATCH")


@pytest.mark.parametrize("kind,higher,lower", GR_ORDER_PAIRS)
def test_gr_kind_order(head, kind, higher, lower):
    """R12 draft r2 section 3 (each kind's order) and section 4 E6b (MODEL_LOWERED), on mutated positives."""
    model, _ = head._era_checker(head.DECISION)
    base = _gr_cases(head)[GR_KIND_BASE[kind]]["input"]
    # R12 draft r2 section 6: P1 is GUARDRAIL, P3 ADMISSION_SCAN, P4 GRADE
    assert base["kind"] == kind
    # R12 draft r2 section 3 order and section 4 E6b: a decision below a deterministic one is MODEL_LOWERED
    assert _ev(model, _with_contributions(base, higher, lower)) == ("REFUSED", "MODEL_LOWERED")
    # R12 draft r2 section 4 E6b: the most restrictive deterministic decision is not lowered
    assert _ev(model, _with_contributions(base, higher, higher)) != ("REFUSED", "MODEL_LOWERED")


@pytest.mark.parametrize("kind", tuple(GR_FAIL_CLOSED))
def test_gr_unknown_value_fails_closed(head, kind):
    """R12 draft r2 section 4 E7: a decision outside the closed set is read as the kind's fail-closed value."""
    model, _ = head._era_checker(head.DECISION)
    record = copy.deepcopy(_gr_cases(head)[GR_KIND_BASE[kind]]["input"])
    # R12 draft r2 section 6: P1 GUARDRAIL, P3 ADMISSION_SCAN, P4 GRADE, P5 APPROVAL
    assert record["kind"] == kind
    record["envelope"]["decision"] = "ORACLE_UNKNOWN"
    record["envelope"]["effectiveDecision"] = "ORACLE_UNKNOWN"
    # R12 draft r2 section 4 E7 with section 3's fail-closed values
    assert _ev(model, record) == ("READ_FAIL_CLOSED", GR_FAIL_CLOSED[kind])


def test_gr_p8_chain(head):
    """R12 draft r2 section 4 E6c and section 6 P8: two chained TRANSFORM records, the second over the first."""
    cases = _gr_cases(head)
    first, second = cases["GR-P8a"]["input"], cases["GR-P8b"]["input"]
    for record in (first, second):
        # R12 draft r2 section 6 P8: GUARDRAIL TRANSFORM records
        assert (record["kind"], record["envelope"]["effectiveDecision"]) == ("GUARDRAIL", "TRANSFORM")
    # R12 draft r2 section 4 E6c: the second rewrite is over the first's after-value
    assert second["transform"]["valueBeforeDigest"] == first["transform"]["valueAfterDigest"]
    # R12 draft r2 section 3 (supersedes) and section 2 (digest): chained through supersedes
    assert second["supersedes"] == _record_digest(first)


def test_gr_record_codes_and_order(head):
    """CONTRACT_296 section 3a: reason-codes.json holds E1-E7 and L1-L5, the refusal codes and the check order."""
    record = _json(head, _field(head.DECISION, "record"))
    text = json.dumps(record, ensure_ascii=False)
    for code in GR_CODES + ("LIFT_REFUSED",):
        # CONTRACT_296 section 3a: the refusal codes, and LIFT_REFUSED
        assert code in text
    for family in GR_FAMILIES:
        # CONTRACT_296 section 3a: E1-E7 and L1-L5 as rule families
        assert family in text
    ordered = [projected for projected in _code_lists(record) if projected == list(GR_CODES)]
    # CONTRACT_296 section 3a: the check order R00 fixes
    assert len(ordered) >= 1


# ------------------------------------------------------------------------------ part 2: REG-ALIGN-001 (3b)

RA_PUBLISHED_KEYS = (
    "id",
    "schemaVersion",
    "status",
    "basis",
    "nonClaims",
    "sources",
    "enums",
    "rows",
    "euDates",
    "rules",
    "gapKindMeaning",
)
RA_MOVED = ("draftedBy", "draftDate", "revision", "revisionNotes", "intendedPath")
RA_COUNTS = {"nonClaims": 6, "sources": 4, "enums": 7, "rows": 35, "euDates": 4, "rules": 8, "gapKindMeaning": 3}
RA_DRAFTED_BY = "R03 (C25 reading: lane drafts the rows; R00 owns the validator, vectors, oracle and publication)"
RA_DRAFT_DATE = "2026-11-22"
RA_INTENDED_PATH = "architecture/regulatory-alignment.json"
RA_REVISION = 4
RA_BASIS = {
    "harnessOnionCommit": "19b176be",
    "harnessModel": "roadmap model.harnesses (H1-H16)",
    "modules": "architecture/release-profile.json modules[] at 19b176be",
    "evidenceColumns": "architecture/release-evidence.json columns[] at 19b176be",
    "claimDomains": "architecture/release-evidence.json claimDomains[] at 19b176be",
}
RA_NON_CLAIMS = (
    "Nothing here says the platform or a tenant complies with any regulator text. The two sources are supervisory "
    "good practice and sound practice, not law.",
    "Each row names a candidate carrier at harness and module level. carrierCheck NOT_CHECKED means no contract "
    "field or schema was read for this draft; R00 confirms or corrects each carrier before publication.",
    "No evidence state is claimed. Every release-evidence cell at 19b176be is BLOCKED, NOT_RUN or NOT_SELECTED "
    "(0 QUALIFIED).",
    "Practices are paraphrased, not quoted. Locators point to the held texts.",
    "Gap kind TENANT_OBLIGATION names who implements a practice, never who bears the legal duty. Article 50(1) "
    "and 50(2) are written as duties on providers.",
    "Whether any EU duty applies to the product today is not settled here: nothing is deployed and no "
    "jurisdiction is named.",
)
RA_SOURCES = (
    ("FSB-SP-2026", "SOUND_PRACTICE", "4e3ea6d2f52439f8aef6a27fc316a20eecacecd50b03dfca4e89f9f1de0ca6de"),
    ("FCA-GP-2026", "GOOD_PRACTICE", "df1e275b9f94bf4ccfb409f54d3f0d54bc9291fb749eec6a17ab6103d4f1cc96"),
    ("BENCH-EU-DATES", "EXTRACTED_CLAIM", None),
    ("EU-AIA-2024-1689", "LAW_AS_ENACTED", "bba630444b3278e881066774002a1d7824308934f49ccfa203e65be43692f55e"),
)
RA_ENUMS = {
    "state": ["MAPPED", "PARTIAL", "GAP"],
    "gapKind": ["PRODUCT_GAP", "TENANT_OBLIGATION", "CARRIER_UNCONFIRMED"],
    "carrierCheck": ["NOT_CHECKED", "CONFIRMED", "CORRECTED"],
    "confirmation": ["HELD_SOURCE", "UNCONFIRMED"],
    "candidateState": ["MAPPED"],
    "noCarryingItem": ["no carrying item (weekly lock decides)"],
    "addressee": ["PROVIDER", "DEPLOYER", "NOT_RECORDED"],
}
RA_RULES = (
    "state MAPPED requires carrierCheck CONFIRMED or CORRECTED.",
    "a row with candidateState MAPPED has state PARTIAL, gap kind CARRIER_UNCONFIRMED and carrierCheck NOT_CHECKED.",
    "every non-MAPPED row carries a gap with a kind from the enum and a note.",
    "every PRODUCT_GAP gap names carryingItems (roadmap ids) or, when the list is empty, noCarryingItem with the "
    "enum's one value.",
    "every EU row carries dateAsEnacted and dateAsAmended; each date object cites a source and a confirmation.",
    "a date object whose source has a held digest carries confirmation HELD_SOURCE and a locator; one whose source "
    "has none carries UNCONFIRMED.",
    "dateAlreadyPassed is computed from dateAsEnacted against draftDate.",
    "an obligationLocator naming two places gives a pdfPage for each place.",
)
RA_GAP_KIND_MEANING = {
    "PRODUCT_GAP": "nothing in the product carries the practice yet",
    "TENANT_OBLIGATION": "the tenant implements it in its own channel or organisation; this says nothing about who "
    "bears a legal duty",
    "CARRIER_UNCONFIRMED": "a carrier is named but not confirmed at field level",
}
RA_REVISION_NOTES = (
    (
        4,
        "Build-R00-Next intake round 1 (ab4c7d00): F1 each obligation locator gives its own page per place (50(5) "
        "pdfPage 83; Art 6(1) and 6(2) pdfPage 53); N3 revision notes split, newest first.",
    ),
    (
        3,
        "The EU AI Act as enacted (Regulation (EU) 2024/1689, OJ L 12.7.2024, held bba63044; the visionary's read "
        "EUAIA-READ-1 4952ac74): every EU row carries dateAsEnacted (held, Art 113) and dateAsAmended (UNCONFIRMED, "
        "secondary note only); the disclosure row is split into 50(1)+50(5) and 50(2); TENANT_OBLIGATION is defined "
        "as who implements, not who bears the legal duty.",
    ),
    (
        2,
        "The roadmap visionary's read (DESIGN-BATCH-READ-2 ed606d55, section 5): F-RA-1 no row is MAPPED before its "
        "carrier is confirmed (candidateState keeps the draft's view); F-RA-2 dated rows without a held source carry "
        "confirmation UNCONFIRMED; F-RA-3 every PRODUCT_GAP names its carrying roadmap items or says none exists.",
    ),
    (1, "First draft of the rows (ORC-DISPATCH-R03-2)."),
)
# R03 draft r4 rows: (id, source, state, carrierCheck, candidateState, gap kind)
RA_ROWS = (
    ("FSB-SP01", "FSB-SP-2026", "GAP", "NOT_CHECKED", None, "TENANT_OBLIGATION"),
    ("FSB-SP02", "FSB-SP-2026", "PARTIAL", "NOT_CHECKED", None, "TENANT_OBLIGATION"),
    ("FSB-SP03", "FSB-SP-2026", "PARTIAL", "NOT_CHECKED", None, "TENANT_OBLIGATION"),
    ("FSB-SP04", "FSB-SP-2026", "GAP", "NOT_CHECKED", None, "TENANT_OBLIGATION"),
    ("FSB-SP05", "FSB-SP-2026", "PARTIAL", "NOT_CHECKED", None, "CARRIER_UNCONFIRMED"),
    ("FSB-SP06", "FSB-SP-2026", "PARTIAL", "NOT_CHECKED", None, "TENANT_OBLIGATION"),
    ("FSB-SP07", "FSB-SP-2026", "PARTIAL", "NOT_CHECKED", None, "CARRIER_UNCONFIRMED"),
    ("FSB-SP08", "FSB-SP-2026", "PARTIAL", "NOT_CHECKED", None, "PRODUCT_GAP"),
    ("FSB-SP09", "FSB-SP-2026", "PARTIAL", "NOT_CHECKED", "MAPPED", "CARRIER_UNCONFIRMED"),
    ("FSB-SP10", "FSB-SP-2026", "PARTIAL", "NOT_CHECKED", None, "CARRIER_UNCONFIRMED"),
    ("FSB-SP11", "FSB-SP-2026", "PARTIAL", "NOT_CHECKED", "MAPPED", "CARRIER_UNCONFIRMED"),
    ("FSB-SP12", "FSB-SP-2026", "PARTIAL", "NOT_CHECKED", None, "TENANT_OBLIGATION"),
    ("FSB-AG01", "FSB-SP-2026", "PARTIAL", "NOT_CHECKED", None, "CARRIER_UNCONFIRMED"),
    ("FSB-AG02", "FSB-SP-2026", "PARTIAL", "NOT_CHECKED", "MAPPED", "CARRIER_UNCONFIRMED"),
    ("FSB-AG03", "FSB-SP-2026", "GAP", "NOT_CHECKED", None, "PRODUCT_GAP"),
    ("FSB-AG04", "FSB-SP-2026", "PARTIAL", "NOT_CHECKED", None, "PRODUCT_GAP"),
    ("FSB-AG05", "FSB-SP-2026", "PARTIAL", "NOT_CHECKED", None, "CARRIER_UNCONFIRMED"),
    ("FSB-AG06", "FSB-SP-2026", "PARTIAL", "NOT_CHECKED", None, "PRODUCT_GAP"),
    ("FSB-AG07", "FSB-SP-2026", "GAP", "NOT_CHECKED", None, "PRODUCT_GAP"),
    ("FSB-AG08", "FSB-SP-2026", "PARTIAL", "NOT_CHECKED", None, "TENANT_OBLIGATION"),
    ("FCA-2-A", "FCA-GP-2026", "GAP", "NOT_CHECKED", None, "TENANT_OBLIGATION"),
    ("FCA-2-B", "FCA-GP-2026", "PARTIAL", "NOT_CHECKED", None, "CARRIER_UNCONFIRMED"),
    ("FCA-2-C", "FCA-GP-2026", "PARTIAL", "NOT_CHECKED", None, "PRODUCT_GAP"),
    ("FCA-2-D", "FCA-GP-2026", "GAP", "NOT_CHECKED", None, "PRODUCT_GAP"),
    ("FCA-2-E", "FCA-GP-2026", "PARTIAL", "NOT_CHECKED", None, "PRODUCT_GAP"),
    ("FCA-3-A", "FCA-GP-2026", "PARTIAL", "NOT_CHECKED", None, "TENANT_OBLIGATION"),
    ("FCA-3-B", "FCA-GP-2026", "PARTIAL", "NOT_CHECKED", None, "CARRIER_UNCONFIRMED"),
    ("FCA-3-C", "FCA-GP-2026", "PARTIAL", "NOT_CHECKED", "MAPPED", "CARRIER_UNCONFIRMED"),
    ("FCA-3-D", "FCA-GP-2026", "GAP", "NOT_CHECKED", None, "TENANT_OBLIGATION"),
    ("FCA-3-E", "FCA-GP-2026", "PARTIAL", "NOT_CHECKED", None, "CARRIER_UNCONFIRMED"),
    ("FCA-3-F", "FCA-GP-2026", "GAP", "NOT_CHECKED", None, "PRODUCT_GAP"),
    ("FCA-4-A", "FCA-GP-2026", "PARTIAL", "NOT_CHECKED", "MAPPED", "CARRIER_UNCONFIRMED"),
    ("FCA-4-B", "FCA-GP-2026", "PARTIAL", "NOT_CHECKED", None, "TENANT_OBLIGATION"),
    ("FCA-4-C", "FCA-GP-2026", "PARTIAL", "NOT_CHECKED", None, "PRODUCT_GAP"),
    ("FCA-4-D", "FCA-GP-2026", "PARTIAL", "NOT_CHECKED", None, "TENANT_OBLIGATION"),
)
# R03 draft r4 euDates: (id, addressee, state, gap kind, enacted, amended, dateAlreadyPassed, obligationLocator)
RA_EU = (
    (
        "EU-AIA-ART50-1-5",
        "PROVIDER",
        "GAP",
        "PRODUCT_GAP",
        "2026-08-02",
        "2026-08-02",
        True,
        "Art 50(1) pdfPage 82; 50(5) pdfPage 83",
    ),
    ("EU-AIA-ART50-2", "PROVIDER", "GAP", "PRODUCT_GAP", "2026-08-02", "2026-08-02", True, "Art 50(2), pdfPage 82"),
    (
        "EU-AIA-HR-STANDALONE",
        "NOT_RECORDED",
        "GAP",
        "CARRIER_UNCONFIRMED",
        "2026-08-02",
        "2027-12-02",
        True,
        "Art 6(2) pdfPage 53; Annex III point 5(b) pdfPage 127",
    ),
    (
        "EU-AIA-HR-EMBEDDED",
        "NOT_RECORDED",
        "GAP",
        "CARRIER_UNCONFIRMED",
        "2027-08-02",
        "2028-08-02",
        False,
        "Art 6(1) pdfPage 53; Art 113(c) pdfPage 123",
    ),
)
ROADMAP_ID = re.compile(r"[A-Z][A-Z0-9-]*-[0-9]{3}")
RA_MUTATIONS = (
    ("control", None),
    ("shape-moved-key-back", "RA_SHAPE"),
    ("enum-carrierCheck", "RA_ENUMS"),
    ("rule0-mapped-unchecked", "RA_RULES"),
    ("rule1-candidate-confirmed", "RA_RULES"),
    ("rule3-product-gap-no-items", "RA_RULES"),
    ("rule5-unheld-source-held", "RA_RULES"),
    ("rule6-date-passed-flipped", "RA_RULES"),
    ("rule7-locator-one-page", "RA_RULES"),
    ("ids-duplicate", "RA_IDS"),
    ("sources-unknown-id", "RA_SOURCES"),
)


def _ra_record(head):
    return _json(head, _field(head.ALIGNMENT, "record"))


def _row(record, row_id):
    return next(row for row in record["rows"] if row["id"] == row_id)


def _section(text):
    lines = text.splitlines()
    starts = [i for i, line in enumerate(lines) if line.lstrip().startswith("#") and "provenance" in line.lower()]
    if not starts:
        return None
    return " ".join(" ".join(lines[starts[0]:]).split())


def _draft_date(text):
    match = re.search(r"draftDate[^0-9]{0,40}?([0-9]{4}-[0-9]{2}-[0-9]{2})", text)
    return None if match is None else match.group(1)


def _ra_mutate(record, name):
    if name == "shape-moved-key-back":
        record["draftDate"] = RA_DRAFT_DATE
    elif name == "enum-carrierCheck":
        record["rows"][0]["carrierCheck"] = "VERIFIED"
    elif name == "rule0-mapped-unchecked":
        _row(record, "FSB-SP02")["state"] = "MAPPED"
    elif name == "rule1-candidate-confirmed":
        _row(record, "FSB-SP09")["carrierCheck"] = "CONFIRMED"
    elif name == "rule3-product-gap-no-items":
        _row(record, "FSB-SP08")["gap"]["carryingItems"] = []
    elif name == "rule5-unheld-source-held":
        record["euDates"][0]["dateAsAmended"]["confirmation"] = "HELD_SOURCE"
    elif name == "rule6-date-passed-flipped":
        record["euDates"][3]["dateAlreadyPassed"] = True
    elif name == "rule7-locator-one-page":
        record["euDates"][0]["obligationLocator"] = "Art 50(1) pdfPage 82; 50(5)"
    elif name == "ids-duplicate":
        record["rows"][1]["id"] = record["rows"][0]["id"]
    elif name == "sources-unknown-id":
        record["rows"][0]["source"] = "FSB-SP-2099"
    return record


def _dict_reader(files):
    def read(path):
        if path not in files:
            raise ValueError("oracle reader: path outside the given inputs")
        return files[path]

    return read


def test_ra_published_key_set(head):
    """CONTRACT_296 section 3b (M2): exactly the 11 published keys, id kept, schemaVersion and status set."""
    record = _ra_record(head)
    # CONTRACT_296 section 3b: r4's 16 top-level keys become 11
    assert sorted(record) == sorted(RA_PUBLISHED_KEYS)
    # CONTRACT_296 section 3b: kept id, set schemaVersion "1.0.0" and status "PUBLISHED"
    assert (record["id"], record["schemaVersion"], record["status"]) == ("REG-ALIGN-001", "1.0.0", "PUBLISHED")
    for key in RA_MOVED:
        # CONTRACT_296 section 3b: the 5 moved keys are not in the record
        assert key not in record
    for key, count in RA_COUNTS.items():
        # CONTRACT_296 section 3b: nonClaims 6, sources 4, enums 7, rows 35, euDates 4, rules 8, gapKindMeaning 3
        assert len(record[key]) == count


def test_ra_verbatim_parts(head):
    """CONTRACT_296 section 3b: basis, nonClaims, sources, enums, rules and gapKindMeaning verbatim from r4."""
    record = _ra_record(head)
    # R03 draft r4 basis
    assert record["basis"] == RA_BASIS
    # R03 draft r4 nonClaims
    assert record["nonClaims"] == list(RA_NON_CLAIMS)
    # R03 draft r4 sources (id, nature, sha256)
    assert [(source["id"], source["nature"], source["sha256"]) for source in record["sources"]] == list(RA_SOURCES)
    # R03 draft r4 enums
    assert record["enums"] == RA_ENUMS
    # R03 draft r4 rules
    assert record["rules"] == list(RA_RULES)
    # R03 draft r4 gapKindMeaning
    assert record["gapKindMeaning"] == RA_GAP_KIND_MEANING


def test_ra_rows_against_r4(head):
    """CONTRACT_296 section 3b (D5a needs): the row count, each row's values and enum fields in r4's enums."""
    record = _ra_record(head)
    observed = [
        (row["id"], row["source"], row["state"], row["carrierCheck"], row.get("candidateState"), row["gap"]["kind"])
        for row in record["rows"]
    ]
    # R03 draft r4 rows (35, in order)
    assert observed == list(RA_ROWS)
    for row in record["rows"]:
        # R03 draft r4 enums.state
        assert row["state"] in RA_ENUMS["state"]
        # R03 draft r4 enums.carrierCheck
        assert row["carrierCheck"] in RA_ENUMS["carrierCheck"]
        # R03 draft r4 enums.gapKind
        assert row["gap"]["kind"] in RA_ENUMS["gapKind"]
        if "candidateState" in row:
            # R03 draft r4 enums.candidateState
            assert row["candidateState"] in RA_ENUMS["candidateState"]
        if "noCarryingItem" in row["gap"]:
            # R03 draft r4 enums.noCarryingItem
            assert row["gap"]["noCarryingItem"] in RA_ENUMS["noCarryingItem"]
    eu = [
        (
            entry["id"],
            entry["addressee"],
            entry["state"],
            entry["gap"]["kind"],
            entry["dateAsEnacted"]["date"],
            entry["dateAsAmended"]["date"],
            entry["dateAlreadyPassed"],
            entry["obligationLocator"],
        )
        for entry in record["euDates"]
    ]
    # R03 draft r4 euDates (4, in order)
    assert eu == list(RA_EU)
    for entry in record["euDates"]:
        # R03 draft r4 enums.addressee
        assert entry["addressee"] in RA_ENUMS["addressee"]
        for key in ("dateAsEnacted", "dateAsAmended"):
            # R03 draft r4 enums.confirmation
            assert entry[key]["confirmation"] in RA_ENUMS["confirmation"]


@pytest.mark.parametrize("rule", range(8))
def test_ra_rule_holds(head, rule):
    """CONTRACT_296 section 3b (D5a needs): each of r4's 8 rules holds over the rows, checked from its text."""
    record = _ra_record(head)
    rows = list(record["rows"]) + list(record["euDates"])
    eu = record["euDates"]
    sources = {source["id"]: source for source in record["sources"]}
    if rule == 0:
        mapped = [row for row in rows if row["state"] == "MAPPED"]
        # R03 draft r4 rows: no row has state MAPPED
        assert len(mapped) == 0
        for row in mapped:
            # R03 draft r4 rules[0]
            assert row.get("carrierCheck") in ("CONFIRMED", "CORRECTED")
    elif rule == 1:
        candidates = [row for row in rows if row.get("candidateState") == "MAPPED"]
        # R03 draft r4 rows: five rows with candidateState MAPPED
        assert len(candidates) == 5
        for row in candidates:
            # R03 draft r4 rules[1]
            assert (row["state"], row["gap"]["kind"], row["carrierCheck"]) == ("PARTIAL", "CARRIER_UNCONFIRMED", "NOT_CHECKED")
    elif rule == 2:
        others = [row for row in rows if row["state"] != "MAPPED"]
        # R03 draft r4 rows and euDates: 39 non-MAPPED rows
        assert len(others) == 39
        for row in others:
            gap = row.get("gap")
            # R03 draft r4 rules[2]: a gap with a kind from the enum and a note
            assert isinstance(gap, dict) and gap.get("kind") in RA_ENUMS["gapKind"]
            # R03 draft r4 rules[2]: a note
            assert isinstance(gap.get("note"), str) and gap["note"].strip() != ""
    elif rule == 3:
        product = [row["gap"] for row in rows if row["gap"]["kind"] == "PRODUCT_GAP"]
        # R03 draft r4 rows and euDates: 12 PRODUCT_GAP gaps
        assert len(product) == 12
        for gap in product:
            items = gap.get("carryingItems")
            # R03 draft r4 rules[3]: carryingItems names roadmap ids
            assert isinstance(items, list) and all(ROADMAP_ID.fullmatch(item) for item in items)
            if not items:
                # R03 draft r4 rules[3]: an empty list goes with noCarryingItem, the enum's one value
                assert gap.get("noCarryingItem") == "no carrying item (weekly lock decides)"
    elif rule == 4:
        # R03 draft r4 euDates: 4 EU rows
        assert len(eu) == 4
        for entry in eu:
            for key in ("dateAsEnacted", "dateAsAmended"):
                # R03 draft r4 rules[4]: each date object cites a source and a confirmation
                assert entry[key]["source"] in sources and entry[key]["confirmation"] in RA_ENUMS["confirmation"]
    elif rule == 5:
        for entry in eu:
            for key in ("dateAsEnacted", "dateAsAmended"):
                date = entry[key]
                if sources[date["source"]]["sha256"] is not None:
                    # R03 draft r4 rules[5]: a held digest carries HELD_SOURCE and a locator
                    assert date["confirmation"] == "HELD_SOURCE" and str(date.get("locator", "")).strip() != ""
                else:
                    # R03 draft r4 rules[5]: no held digest carries UNCONFIRMED
                    assert date["confirmation"] == "UNCONFIRMED"
    elif rule == 6:
        draft_date = _draft_date(head.reviewed_bytes(RA_README).decode("utf-8"))
        # CONTRACT_296 section 3b: draftDate moved verbatim to the README (R03 draft r4 draftDate)
        assert draft_date == RA_DRAFT_DATE
        for entry in eu:
            # R03 draft r4 rules[6]: dateAlreadyPassed from dateAsEnacted against draftDate
            assert entry["dateAlreadyPassed"] is (entry["dateAsEnacted"]["date"] < draft_date)
    else:
        two_place = [entry for entry in eu if ";" in entry["obligationLocator"]]
        # R03 draft r4 euDates: three obligationLocators name two places
        assert len(two_place) == 3
        for entry in two_place:
            for place in entry["obligationLocator"].split(";"):
                # R03 draft r4 rules[7]: a pdfPage for each place
                assert "pdfPage" in place


def test_ra_readme_provenance(head):
    """CONTRACT_296 section 3b (M2): the README's provenance section holds the five moved keys, verbatim."""
    text = head.reviewed_bytes(RA_README).decode("utf-8")
    section = _section(text)
    # CONTRACT_296 section 3b: the README has a provenance section
    assert section is not None
    for key in RA_MOVED:
        # CONTRACT_296 section 3b: draftedBy, draftDate, revision, revisionNotes and intendedPath
        assert key in section
    # R03 draft r4 draftedBy, moved verbatim (CONTRACT_296 section 3b)
    assert RA_DRAFTED_BY in section
    # R03 draft r4 draftDate, moved verbatim (CONTRACT_296 section 3b)
    assert _draft_date(section) == RA_DRAFT_DATE
    # R03 draft r4 intendedPath, moved verbatim (CONTRACT_296 section 3b)
    assert RA_INTENDED_PATH in section
    # R03 draft r4 revision 4, moved verbatim (CONTRACT_296 section 3b)
    assert re.search(r"\brevision\b\W+" + str(RA_REVISION) + r"\b", section) is not None
    # CONTRACT_296 section 3b: revisionNotes (4 notes)
    assert len(RA_REVISION_NOTES) == 4
    for _, note in RA_REVISION_NOTES:
        # R03 draft r4 revisionNotes, moved verbatim (CONTRACT_296 section 3b)
        assert " ".join(note.split()) in section


@pytest.mark.parametrize("name,code", RA_MUTATIONS)
def test_ra_checker_mutation(head, name, code):
    """CONTRACT_296 section 3b: one mutation per checker code (RA_SHAPE to RA_SOURCES), refused with that code."""
    _, checker = head._era_checker(head.ALIGNMENT)
    path = _field(head.ALIGNMENT, "record")
    readme = head.reviewed_bytes(RA_README)
    record = _ra_mutate(json.loads(head.reviewed_bytes(path)), name)
    raw = (json.dumps(record, indent=1, ensure_ascii=False) + "\n").encode("utf-8")
    codes = [pair[0] for pair in checker.check(_dict_reader({path: raw, RA_README: readme}))]
    if code is None:
        # CONTRACT_296 section 3 member table: refusals [] for the published record
        assert codes == []
    else:
        # CONTRACT_296 section 3b: the checker refuses each mutation with its code
        assert code in codes
    order = ["RA_SHAPE", "RA_ENUMS", "RA_RULES", "RA_IDS", "RA_SOURCES"]
    # operator-stated: codes over RA_SHAPE, RA_ENUMS, RA_RULES, RA_IDS, RA_SOURCES, each at most once, in order
    assert codes == [item for item in order if item in codes]


def test_ra_checker_live_record(head):
    """CONTRACT_296 section 3 member table: the era checker passes the published record (refusals [])."""
    model, checker = head._era_checker(head.ALIGNMENT)
    path = _field(head.ALIGNMENT, "record")
    files = {path: head.reviewed_bytes(path), RA_README: head.reviewed_bytes(RA_README)}
    # CONTRACT_296 section 4a difference 1 (i): REG-ALIGN-001 has no model
    assert model is None
    # CONTRACT_296 section 3 member table: refusals []
    assert checker.check(_dict_reader(files)) == []


# ----------------------------------------------------------------------------------- part 3: EDGE-V13 (3c)

EMPTY_DIGEST = "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
FRAME_TYPES = ("STARTED", "RECEIPT_CHUNK", "CLEANUP_RECORDED", "TERMINAL")
SCHEMA_IF = {"required": ["receiptSize"], "properties": {"receiptSize": {"const": 0}}}
SCHEMA_THEN = {"properties": {"status": {"enum": ["FAILED", "UNAVAILABLE"]}, "receiptDigest": {"const": EMPTY_DIGEST}}}
TERMINAL_SHAPES = (
    ("failed-size0-empty", True),
    ("unavailable-size0-empty", True),
    ("failed-size0-nonempty-digest", False),
    ("completed-size0", False),
    ("completed-size1-v1", True),
    ("failed-size-minus1", False),
)


def _frame_type(frame):
    found = sorted({leaf for leaf in _str_leaves(frame) if leaf in FRAME_TYPES})
    assert len(found) == 1  # R10 draft r2 section 2 item 2: frames STARTED, RECEIPT_CHUNK, CLEANUP_RECORDED, TERMINAL
    return found[0]


def _int_paths(node, prefix=()):
    if isinstance(node, dict):
        for key, value in node.items():
            if isinstance(value, dict):
                yield from _int_paths(value, prefix + (key,))
            elif isinstance(value, int) and not isinstance(value, bool):
                yield prefix + (key,)


def _get(node, path):
    for key in path:
        if not isinstance(node, dict) or key not in node:
            return None
        node = node[key]
    return node


def _set(node, path, value):
    for key in path[:-1]:
        node = node[key]
    node[path[-1]] = value


def _sequence_path(frames):
    wanted = list(range(1, len(frames) + 1))
    paths = [path for path in _int_paths(frames[0]) if [_get(frame, path) for frame in frames] == wanted]
    assert len(paths) == 1  # R10 draft r2 section 2 item 2: frames are sequenced from 1
    return paths[0]


def _chain_prefix(frames):
    value = _holder(frames[1], "previousDigest")["previousDigest"]
    hexed = hashlib.sha256(_compact(frames[0])).hexdigest()
    # R10 draft r2 section 2 item 2: previousDigest = sha256 of the previous frame's compact sorted-key JSON
    assert value.endswith(hexed)
    return value[: -len(hexed)]


def _rechain(frames, prefix):
    out = copy.deepcopy(frames)
    for index in range(1, len(out)):
        digest = prefix + hashlib.sha256(_compact(out[index - 1])).hexdigest()
        _holder(out[index], "previousDigest")["previousDigest"] = digest
    return out


def _payload(frame):
    return _holder(frame, "receiptSize")


def _edge_inputs(head):
    schema13 = _json(head, _field(head.EDGE, "schema"))
    vectors13 = _json(head, _field(head.EDGE, "vectors"))
    return schema13, vectors13, _json(head, V1_SCHEMA), _json(head, V1_VECTORS)


def _no_receipt_frames(v1_frames, prefix):
    frames = [copy.deepcopy(frame) for frame in v1_frames if _frame_type(frame) != "RECEIPT_CHUNK"]
    sequence = _sequence_path(v1_frames)
    for index, frame in enumerate(frames):
        _set(frame, sequence, index + 1)
    cleanup = _holder(frames[1], "cleanupDigest")["cleanupDigest"]
    _payload(frames[2]).update(
        status="FAILED", receiptSize=0, receiptDigest=EMPTY_DIGEST, cleanupDigest=cleanup, workerReaped=True
    )
    return _rechain(frames, prefix)


def _refused(function, *args):
    try:
        result = function(*args)
    except Exception:  # noqa: BLE001 - operator-stated: a raise counts as a refusal
        return True
    return result != []


def _frame_refused(model, frame, schema):
    try:
        model._shape(frame, "frame", schema)
    except Exception:  # noqa: BLE001 - operator-stated: _shape raises when the schema refuses the frame
        return True
    return False


def _payload_schema(node):
    if isinstance(node, dict):
        properties = node.get("properties")
        if isinstance(properties, dict) and "receiptSize" in properties:
            return node
        values = list(node.values())
    elif isinstance(node, list):
        values = node
    else:
        return None
    for value in values:
        found = _payload_schema(value)
        if found is not None:
            return found
    return None


def _v1_transcript(head, model):
    tree = ast.parse(head.reviewed_bytes(V1_MODEL))
    nodes = [node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name == "validate_transcript"]
    assert len(nodes) == 1  # operator-stated: the v1 model holds validate_transcript
    namespace = dict(vars(model))
    exec(compile(ast.Module(body=nodes, type_ignores=[]), "v1-validate_transcript", "exec"), namespace)  # noqa: S102
    return namespace["validate_transcript"]


def test_edge_schema_two_hunks(head):
    """CONTRACT_296 section 3c and R10 draft r2 O1: v13's schema is v1's but for two hunks in $defs.frame.oneOf[5]."""
    schema13, _, schema1, _ = _edge_inputs(head)
    stripped = copy.deepcopy(schema13)
    payload13 = _payload_schema(stripped["$defs"]["frame"]["oneOf"][5])
    payload1 = _payload_schema(schema1["$defs"]["frame"]["oneOf"][5])
    # R10 draft r2 section 2 item 1: v1's TERMINAL receiptSize minimum is 1, with no if/then
    assert payload1["properties"]["receiptSize"]["minimum"] == 1 and "if" not in payload1 and "then" not in payload1
    # R10 draft r2 section 2 item 1: receiptSize minimum 1 becomes 0
    assert payload13["properties"]["receiptSize"]["minimum"] == 0
    # R10 draft r2 section 2 item 1: the if (receiptSize const 0)
    assert payload13.get("if") == SCHEMA_IF
    # R10 draft r2 section 2 item 1 and section 1: the then (FAILED or UNAVAILABLE, the empty digest)
    assert payload13.get("then") == SCHEMA_THEN
    payload13["properties"]["receiptSize"]["minimum"] = 1
    del payload13["if"], payload13["then"]
    # CONTRACT_296 section 3c and R10 draft r2 O1: nothing else changes
    assert stripped == schema1


def test_edge_vectors_layout(head):
    """CONTRACT_296 section 3c and R10 draft r2 O2/O3: three positives, one negative, positive[0..1] = v1's."""
    _, vectors13, _, vectors1 = _edge_inputs(head)
    # R10 draft r2 section 2 item 2: v1 holds two positives
    assert len(vectors1["positive"]) == 2
    # CONTRACT_296 section 3c: three positives and one negative
    assert (len(vectors13["positive"]), len(vectors13["negative"])) == (3, 1)
    # CONTRACT_296 section 3c and R10 draft r2 O2: positive[0..1] = v12's two, unchanged and in order
    assert vectors13["positive"][:2] == vectors1["positive"]
    # R10 draft r2 section 2 item 2: negative is the one new key
    assert set(vectors13) == set(vectors1) | {"negative"}
    for key, value in (("evidenceClass", "DATA_CHECK_ONLY"), ("nativeAcceptance", False), ("tenantAcceptance", False)):
        # R10 draft r2 section 2 item 2: carried unchanged
        assert vectors13[key] == value and vectors1[key] == value


def test_edge_positive2_recomputed(head):
    """CONTRACT_296 section 3c and R10 draft r2 O2: positive[2]'s frames and chain recomputed from the recipe."""
    _, vectors13, _, vectors1 = _edge_inputs(head)
    for vector in vectors1["positive"]:
        prefix = _chain_prefix(vector["frames"])
        # R10 draft r2 section 2 item 2: the recipe checked on both v12 vectors
        assert _rechain(vector["frames"], prefix) == vector["frames"]
    base = vectors1["positive"][0]
    prefix = _chain_prefix(base["frames"])
    expected = _no_receipt_frames(base["frames"], prefix)
    actual = vectors13["positive"][2]
    # R10 draft r2 section 2 item 2: STARTED, CLEANUP_RECORDED, TERMINAL
    assert [_frame_type(frame) for frame in actual["frames"]] == ["STARTED", "CLEANUP_RECORDED", "TERMINAL"]
    # R10 draft r2 section 2 item 2 and O2: v12's positive[0] less its RECEIPT_CHUNK, re-sequenced, re-chained
    assert actual["frames"] == expected
    # R10 draft r2 section 2 item 2: the same binding and request as v12's positive[0]
    assert (actual["binding"], actual["request"]) == (base["binding"], base["request"])
    payload = _payload(actual["frames"][2])
    # R10 draft r2 section 2 item 2: TERMINAL {FAILED, 0, empty digest, echoed cleanupDigest, workerReaped true}
    assert (payload["status"], payload["receiptSize"], payload["receiptDigest"], payload["workerReaped"]) == (
        "FAILED",
        0,
        EMPTY_DIGEST,
        True,
    )
    # R10 draft r2 section 5 and O2: cleanupDigest echoed from CLEANUP_RECORDED
    assert payload["cleanupDigest"] == _holder(actual["frames"][1], "cleanupDigest")["cleanupDigest"]


@pytest.mark.parametrize("index", range(3))
def test_edge_v2_model_accepts_positive(head, index):
    """CONTRACT_296 section 3 member table (E1 form) and R10 draft r2 O4: the v2 model accepts the three."""
    model, _ = head._era_checker(head.EDGE)
    schema13, vectors13, _, _ = _edge_inputs(head)
    vector = vectors13["positive"][index]
    # R10 draft r2 O4 and operator-stated: [] on acceptance under the v13 schema
    assert model.validate_transcript(vector["binding"], vector["request"], vector["frames"], schema13) == []


@pytest.mark.parametrize("case", ("K", "L", "M"))
def test_edge_v2_model_refuses_klm(head, case):
    """CONTRACT_296 section 3c and R10 draft r2 O4: the v2 model refuses K, L and M under the v13 schema."""
    model, _ = head._era_checker(head.EDGE)
    schema13, vectors13, _, vectors1 = _edge_inputs(head)
    no_receipt = vectors13["positive"][2]
    base = vectors1["positive"][0]
    if case == "K":
        frames = copy.deepcopy(base["frames"])
        # R10 draft r2 section 3 K: the transcript ends in TERMINAL
        assert _frame_type(frames[-1]) == "TERMINAL"
        _payload(frames[-1]).update(status="FAILED", receiptSize=0, receiptDigest=EMPTY_DIGEST, workerReaped=True)
        frames = _rechain(frames, _chain_prefix(base["frames"]))
        binding, request = base["binding"], base["request"]
    elif case == "L":
        frames = copy.deepcopy(no_receipt["frames"][:-1])
        binding, request = no_receipt["binding"], no_receipt["request"]
    else:
        frames = copy.deepcopy(no_receipt["frames"])
        _payload(frames[-1])["status"] = "COMPLETED"
        binding, request = no_receipt["binding"], no_receipt["request"]
    # R10 draft r2 section 3 (K, L, M) and O4: refused
    assert _refused(model.validate_transcript, binding, request, frames, schema13) is True


def test_edge_v1_function_bite(head):
    """CONTRACT_296 section 3c and R10 draft r2 O4 (the bite): v1's function refuses positive[2], accepts v1's two."""
    model, _ = head._era_checker(head.EDGE)
    schema13, vectors13, _, vectors1 = _edge_inputs(head)
    v1_function = _v1_transcript(head, model)
    bite = vectors13["positive"][2]
    # R10 draft r2 O4 and section 3 case B: the v1 model refuses positive[2] under the v13 schema
    assert _refused(v1_function, bite["binding"], bite["request"], bite["frames"], schema13) is True
    for vector in vectors1["positive"]:
        # R10 draft r2 section 3 case B: the v1 model accepts v12's two under the v13 schema
        assert v1_function(vector["binding"], vector["request"], vector["frames"], schema13) == []


def test_edge_negative_frame(head):
    """CONTRACT_296 section 3c and R10 draft r2 O3: the negative refused by the v13 schema, accepted with FAILED."""
    model, _ = head._era_checker(head.EDGE)
    schema13, vectors13, schema1, _ = _edge_inputs(head)
    negative = vectors13["negative"][0]
    # R10 draft r2 section 2 item 2: frame, refusedBy and rule
    assert set(negative) == {"frame", "refusedBy", "rule"}
    # R10 draft r2 section 2 item 2: refusedBy "channel.schema.json"
    assert negative["refusedBy"] == "channel.schema.json"
    # R10 draft r2 section 2 item 2: the rule's text
    assert negative["rule"] == "receiptSize 0 only with status FAILED or UNAVAILABLE"
    expected = copy.deepcopy(vectors13["positive"][2]["frames"][2])
    _payload(expected)["status"] = "COMPLETED"
    # R10 draft r2 section 2 item 2: the no-receipt TERMINAL with status COMPLETED
    assert negative["frame"] == expected
    # R10 draft r2 O3: refused by the v13 schema
    assert _frame_refused(model, negative["frame"], schema13) is True
    failed = copy.deepcopy(negative["frame"])
    _payload(failed)["status"] = "FAILED"
    # R10 draft r2 O3: only by the size-0 rule, the same frame with FAILED is valid
    assert _frame_refused(model, failed, schema13) is False
    # R10 draft r2 section 3 case D: v1's minimum 1 refuses the size-0 frame
    assert _frame_refused(model, failed, schema1) is True


@pytest.mark.parametrize("shape,valid", TERMINAL_SHAPES)
def test_edge_terminal_shapes(head, shape, valid):
    """R10 draft r2 O1 and section 3 cases F-J: TERMINAL size 0 only with FAILED/UNAVAILABLE and the empty digest."""
    model, _ = head._era_checker(head.EDGE)
    schema13, vectors13, _, vectors1 = _edge_inputs(head)
    frame = copy.deepcopy(vectors13["positive"][2]["frames"][2])
    payload = _payload(frame)
    if shape == "unavailable-size0-empty":
        payload["status"] = "UNAVAILABLE"
    elif shape == "failed-size0-nonempty-digest":
        payload["receiptDigest"] = "sha256:" + "ab" * 32
    elif shape == "completed-size0":
        payload["status"] = "COMPLETED"
    elif shape == "completed-size1-v1":
        frame = copy.deepcopy(vectors1["positive"][0]["frames"][-1])
        # R10 draft r2 section 1: COMPLETED keeps receiptSize >= 1
        assert _payload(frame)["status"] == "COMPLETED" and _payload(frame)["receiptSize"] >= 1
    elif shape == "failed-size-minus1":
        payload["receiptSize"] = -1
    # R10 draft r2 section 3 cases F-J and O1
    assert _frame_refused(model, frame, schema13) is (not valid)


def test_edge_record_rows(head):
    """CONTRACT_296 section 3c and R10 draft r2 O5 (L3): v13 = v12's 81 rows, then two rows bound by sha256 alone."""
    v13 = _json(head, _field(head.EDGE, "record"))
    v12 = _json(head, EDGE_V12)
    old, new = v12["artifacts"], v13["artifacts"]
    # CONTRACT_296 section 3c: v12's 81 rows
    assert len(old) == 81
    # CONTRACT_296 section 3c: 81 + 2 rows
    assert len(new) == 83
    # CONTRACT_296 section 3c and R10 draft r2 O5: v13's first rows equal v12's, in order
    assert new[:81] == old
    # CONTRACT_296 section 3c: supersedes binds v12's digest
    supersedes = _holder({key: value for key, value in v13.items() if key != "artifacts"}, "supersedes")["supersedes"]
    v12_hex = hashlib.sha256(head.reviewed_bytes(EDGE_V12)).hexdigest()
    leaves = [supersedes] if isinstance(supersedes, str) else list(_str_leaves(supersedes))
    # CONTRACT_296 section 3c and R10 draft r2 section 2 item 3: supersedes binds v12's sha256 digest
    assert any(leaf.split(":")[-1] == v12_hex for leaf in leaves)
    old_keys = set().union(*(set(row) for row in old))
    provider_paths = {_field(head.EDGE, "schema"), _field(head.EDGE, "vectors")}
    seen = set()
    for row in new[81:]:
        # CONTRACT_296 section 3c: v12's own row key set, no key added
        assert set(row) <= old_keys and set(row) == set(new[81])
        size_keys = [key for key in row if "size" in key.lower() or key.lower() in ("bytes", "length")]
        # CONTRACT_296 section 3c (L3): no size field
        assert size_keys == []
        paths = sorted({value for value in row.values() if isinstance(value, str) and value in provider_paths})
        # CONTRACT_296 section 3c: one row per new provider path
        assert len(paths) == 1
        path = paths[0]
        seen.add(path)
        digest = hashlib.sha256(head.reviewed_bytes(path)).hexdigest()
        # CONTRACT_296 section 3c (L3): the row binds its file's bytes through sha256
        assert str(row["sha256"]).split(":")[-1] == digest
        # CONTRACT_296 section 3c: mode 100644, BYTE_IDENTICAL, REGISTERED_BEFORE_USE
        assert (str(row["mode"]), row["relation"], row["status"]) == ("100644", "BYTE_IDENTICAL", "REGISTERED_BEFORE_USE")
        # CONTRACT_296 section 3c: consumerPacket HE-005D, providerPacket MET-014, providerCommit null
        assert (row["consumerPacket"], row["providerPacket"], row["providerCommit"]) == ("HE-005D", STEP, None)
        # CONTRACT_296 section 3c and R10 draft r2 section 2 item 3: the consumer path, same basename
        assert row["consumerPath"] == "host-enforcement/contracts/broker-handoff-v2/" + path.rsplit("/", 1)[-1]
    # CONTRACT_296 section 3c: the 2 rows name the two new provider paths
    assert seen == provider_paths


# ------------------------------------------------------------------------- part 4: the head layer (4, 4a)


def test_head_members_table(head):
    """CONTRACT_296 sections 1, 3 and 4a: MEMBERS in section 1's order, each row's paths and bases."""
    rows = list(head.MEMBERS)
    # CONTRACT_296 section 1: three deliverables in SCOPE-296's order; operator-stated DECISION/ALIGNMENT/EDGE
    assert [_field(row, "item") for row in rows] == list(ITEMS)
    # operator-stated: MEMBERS also bound as DECISION, ALIGNMENT and EDGE
    assert (rows[0], rows[1], rows[2]) == (head.DECISION, head.ALIGNMENT, head.EDGE)
    for row, expected in zip(rows, MEMBER_ROWS):
        bases = tuple(tuple(pair) for pair in (_field(row, "bases") or ()))
        observed = (
            _field(row, "item"),
            _field(row, "model"),
            _field(row, "checker"),
            _field(row, "record"),
            _field(row, "vectors"),
            bases,
            _field(row, "schema"),
        )
        # CONTRACT_296 section 3 member table and section 4a difference 1 (bases safe_yaml, then validate_proxy_contract)
        assert observed == expected


def test_head_constants(head):
    """CONTRACT_296 sections 1, 3, 4 and 4a with operator-stated facts: step, authority form and file lists."""
    authority = head.authority()
    # operator-stated: NEW_PACKET is MET-014
    assert head.NEW_PACKET == STEP
    # CONTRACT_296 section 1: base ids 319
    assert len(authority["baselinePackets"]) == BASE_IDS
    # CONTRACT_296 section 4: no productPackets (K 0)
    assert "productPackets" not in authority
    # CONTRACT_296 section 7 (c1) and section 3: PACKET_FILES are the three members' 19 files
    assert sorted(head.PACKET_FILES) == sorted(PACKET_FILES_C1)
    changed, new = authority["changedFiles"], authority["newFiles"]
    named = sum(1 for path in head.BASE_FILES if path in changed or path in new)
    # CONTRACT_296 section 4a (E2): the authority names no base file in changedFiles or newFiles
    assert named == 0
    present = sum(1 for path in (EDGE_V12, V1_SCHEMA, V1_VECTORS, "scripts/safe_yaml.py") if path in head.BASE_FILES)
    # CONTRACT_296 section 1 with ERR-5 (operator-stated): these stay base files
    assert present == 4
    # ERR-5 (operator-stated): E2's base set is section 1's less the two cascade scripts, 35 of 37
    assert len(set(head.BASE_FILES)) == 35
    in_base = sum(1 for path in CASCADE_SCRIPTS if path in head.BASE_FILES)
    # ERR-5 (operator-stated): the two cascade scripts leave E2's base set
    assert in_base == 0
    in_changed = sum(1 for path in CASCADE_SCRIPTS if path in changed)
    # ERR-5 (operator-stated): the chain cascade rewrites both every step, so both are changed files
    assert in_changed == 2
    for path in PACKET_FILES_C1:
        # CONTRACT_296 section 3: the members' files are new files
        assert (path in new) is True


def test_head_cascade_lines(head):
    """ERR-5 (operator-stated) with CONTRACT_296 section 4 (V6): the cascade rewrites two lines of each script."""
    changed = head.authority()["changedFiles"]
    for path in CASCADE_SCRIPTS:
        listed = path in changed
        # ERR-5 (operator-stated): a changed file of this step
        assert listed is True
        raw = head.reviewed_bytes(path)
        after = raw.decode("utf-8").splitlines()
        before = head._undo_this_layer(path, raw).decode("utf-8").splitlines()
        # ERR-5 (operator-stated): every other line is main's, the two lines rewritten in place
        assert len(after) == len(before)
        rewritten = [index for index in range(len(after)) if after[index] != before[index]]
        # ERR-5 (operator-stated): two lines of each script (the packet names and the count)
        assert len(rewritten) == 2
        names = [index for index in rewritten if STEP in after[index] and STEP not in before[index]]
        # ERR-5 (operator-stated): main's names then the appended one, this step's packet
        assert len(names) == 1
        count = [index for index in rewritten if index not in names][0]
        olds = [int(number) for number in re.findall(r"[0-9]+", before[count])]
        news = [int(number) for number in re.findall(r"[0-9]+", after[count])]
        grown = len(olds) == len(news) and any(new == old + 1 for old, new in zip(olds, news))
        # ERR-5 (operator-stated): the count is main's plus the one appended
        assert grown is True


def test_head_v1_packet_files(head):
    """CONTRACT_296 section 4 (V1): validate_packet_files passes; a missing file and a changed byte are refused."""
    head.validate_packet_files()
    readable = {
        _field(head.DECISION, "record"),
        _field(head.DECISION, "vectors"),
        _field(head.ALIGNMENT, "record"),
        RA_README,
        _field(head.EDGE, "record"),
        _field(head.EDGE, "vectors"),
        _field(head.EDGE, "schema"),
    }
    files = {path: (head.reviewed_bytes(path) if path in readable else b"") for path in head.PACKET_FILES}
    missing = dict(files)
    missing.pop(sorted(readable)[0])
    # operator-stated: a refusal raises ValueError naming MET-014
    with pytest.raises(ValueError, match=STEP):
        head.check_packet_files(missing)
    changed = dict(files)
    target = sorted(readable)[0]
    changed[target] = _flip_byte(changed[target])
    # operator-stated: a refusal raises ValueError naming MET-014
    with pytest.raises(ValueError, match=STEP):
        head.check_packet_files(changed)


def test_head_e1_decision(head, catalog):
    """CONTRACT_296 sections 3 and 4a (E1, GR-DECISION-RECORD-001): passes live; refusals and replay refused."""
    head.validate_decision_record(dict(catalog))
    vectors = _json(head, _field(head.DECISION, "vectors"))
    count = len(vectors["cases"])
    # operator-stated: check_* returns None when it passes
    assert head.check_decision_record(vectors, [], [True] * count) is None
    for refusals, replayed in (
        ([("DR_SHAPE", "oracle mutation")], [True] * count),
        ([], [True] * (count - 1) + [False]),
        ([], [True] * (count - 1)),
    ):
        # CONTRACT_296 section 3 member table (E1 form) and operator-stated ValueError naming MET-014
        with pytest.raises(ValueError, match=STEP):
            head.check_decision_record(vectors, refusals, replayed)


def test_head_e1_alignment(head, catalog):
    """CONTRACT_296 sections 3 and 4a (E1, REG-ALIGN-001): passes live; a non-empty refusal list refused."""
    head.validate_regulatory_alignment(dict(catalog))
    # operator-stated: check_* returns None when it passes
    assert head.check_regulatory_alignment([]) is None
    # CONTRACT_296 section 3 member table (refusals []) and operator-stated ValueError naming MET-014
    with pytest.raises(ValueError, match=STEP):
        head.check_regulatory_alignment([("RA_SHAPE", "oracle mutation")])


def test_head_e1_edge(head, catalog):
    """CONTRACT_296 sections 3 and 4a (E1, EDGE-V13): passes live; a non-empty refusal list refused."""
    head.validate_edge_v13(dict(catalog))
    # operator-stated: check_edge_v13(refusals) returns None when it passes
    assert head.check_edge_v13([]) is None
    message = "MET-014 E1 the edge v13 record passes its checker (EV_V1 to EV_HUNKS)"
    # ERR-6 (operator-stated): difference 3's form with EDGE's names and range, its only message
    with pytest.raises(ValueError, match=re.escape(message)):
        head.check_edge_v13([("EV_V1", "oracle mutation")])


def test_head_e2_base_files(head):
    """CONTRACT_296 section 4a (E2): passes live; a changed base byte and a base file in changedFiles refused."""
    head.validate_base_files()
    authority = head.authority()
    changed, new = authority["changedFiles"], authority["newFiles"]
    files = {path: (head.reviewed_bytes(path) if path in BASE_READS else b"") for path in head.BASE_FILES}
    flipped = dict(files)
    flipped[V1_SCHEMA] = _flip_byte(flipped[V1_SCHEMA])
    # operator-stated: a refusal raises ValueError naming MET-014
    with pytest.raises(ValueError, match=STEP):
        head.check_base_files(flipped, changed, new)
    named = dict(changed)
    # ERR-5 (operator-stated): the v1 vectors stay a base file (the v1 model is now a changed cascade file)
    named[V1_VECTORS] = {"beforeSha256": "0" * 64, "afterSha256": "1" * 64, "reverseHunks": []}
    # CONTRACT_296 section 4a (E2): no base file in changedFiles; operator-stated ValueError naming MET-014
    with pytest.raises(ValueError, match=STEP):
        head.check_base_files(files, named, new)


def _class_word(value):
    return re.fullmatch(r"[A-Za-z][A-Za-z0-9_-]*", value) is not None and not re.fullmatch(r"[0-9a-f]{40,64}", value)


def _class_sites(node, changed, context):
    if isinstance(node, dict):
        local = context
        for value in node.values():
            if isinstance(value, str) and value in changed:
                local = value
        for key, value in node.items():
            scope = key if key in changed else local
            if isinstance(value, str):
                if value not in changed and _class_word(value):
                    yield node, key, scope
            else:
                yield from _class_sites(value, changed, scope)
    elif isinstance(node, list):
        for index, value in enumerate(node):
            if isinstance(value, str):
                if value not in changed and _class_word(value):
                    yield node, index, context
            else:
                yield from _class_sites(value, changed, context)


def _other_class(classes, changed, errata):
    mutated = copy.deepcopy(classes)
    for container, key, scope in _class_sites(mutated, changed, None):
        if scope is not None and scope not in errata and container[key] != "other":
            container[key] = "other"
            return mutated
    if isinstance(mutated, dict):
        for name, members in mutated.items():
            if name != "other" and isinstance(members, list):
                for index, member in enumerate(members):
                    if isinstance(member, str) and member in changed and member not in errata:
                        del members[index]
                        mutated.setdefault("other", []).append(member)
                        return mutated
    return None


def _unknown_class(classes, changed):
    mutated = copy.deepcopy(classes)
    for container, key, _ in _class_sites(mutated, changed, None):
        container[key] = "oracle-unknown-class"
        return mutated
    if isinstance(mutated, dict) and mutated:
        first = next(iter(mutated))
        mutated["oracle-unknown-class"] = mutated.pop(first)
        return mutated
    return None


def test_head_e3_errata(head):
    """CONTRACT_296 section 4 (E3): passes live; an other class on a file outside ERRATA_LINES is refused."""
    head.validate_errata()
    changed = head.authority()["changedFiles"]
    errata = set(head.ERRATA_LINES)
    outside = sum(1 for path in errata if path not in changed)
    # operator-stated: befores are _undo_this_layer of changed files
    assert outside == 0
    befores = {path: head._undo_this_layer(path, head.reviewed_bytes(path)) for path in head.ERRATA_LINES}
    classes = json.loads(head.reviewed_bytes(head.HUNK_RECORD_PATH))["classes"]
    # operator-stated: check_* returns None when it passes
    assert head.check_errata(classes, changed, befores) is None
    mutated = _other_class(classes, changed, errata)
    # operator-stated: E3's refusal case is an other class outside ERRATA_LINES
    assert mutated is not None
    # operator-stated: a refusal raises ValueError naming MET-014
    with pytest.raises(ValueError, match=STEP):
        head.check_errata(mutated, changed, befores)


def test_head_v4_registry(head):
    """CONTRACT_296 sections 1 and 5 (V4): passes live; a registry not base plus the one MET-014/packet rider refused."""
    head.validate_registry()
    raw = head.reviewed_bytes(head.REGISTRY_PATH)
    briefs = {head.PACKET_BRIEF: head.reviewed_bytes(head.PACKET_BRIEF)}
    # operator-stated: check_* returns None when it passes
    assert head.check_registry(raw, briefs) is None
    data = json.loads(raw)
    dropped = copy.deepcopy(data)
    if isinstance(dropped, list):
        dropped.pop()
    else:
        listed = [key for key, value in dropped.items() if isinstance(value, list)]
        if len(listed) == 1:
            dropped[listed[0]].pop()
        else:
            dropped.pop(list(dropped)[-1])
    for mutated in (
        (json.dumps(dropped, indent=2) + "\n").encode("utf-8"),
        raw.replace(STEP.encode("utf-8"), b"MET-099"),
    ):
        # CONTRACT_296 sections 1 and 5: the rider 42 -> 43; operator-stated ValueError naming MET-014
        with pytest.raises(ValueError, match=STEP):
            head.check_registry(mutated, briefs)


def _registry_entries(data):
    if isinstance(data, list):
        return data
    listed = [value for value in data.values() if isinstance(value, list)]
    if len(listed) == 1:
        return listed[0]
    return list(data.items())


def test_registry_rider(head):
    """CONTRACT_296 sections 1 and 5: the registry's last entry is the one MET-014/packet rider, 43 entries."""
    entries = _registry_entries(json.loads(head.reviewed_bytes(head.REGISTRY_PATH)))
    # operator-stated: 43 entries (CONTRACT_296 section 5: 42 -> 43)
    assert len(entries) == REGISTRY_ENTRIES
    last = json.dumps(entries[-1], ensure_ascii=False)
    # CONTRACT_296 section 1: the MET-014/packet rider
    assert STEP in last and "packet" in last
    earlier = sum(1 for entry in entries[:-1] if STEP in json.dumps(entry, ensure_ascii=False))
    # CONTRACT_296 section 1: one rider for MET-014
    assert earlier == 0


def test_head_v6_hunk_record(head):
    """CONTRACT_296 sections 4 and 4a (V6): passes live; members, vocabulary, rule digest, steps, countPairs."""
    head.validate_hunk_record()
    authority = head.authority()
    changed = authority["changedFiles"]
    raw = head.reviewed_bytes(head.HUNK_RECORD_PATH)
    record = json.loads(raw)
    context = record["hunkClassContext"]
    # CONTRACT_296 section 4a (steps [1, 1] at K 0) and operator-stated
    assert context["steps"] == [1, 1]
    # operator-stated: countPairs [] at K 0
    assert context["countPairs"] == []
    afters = {path: head.reviewed_bytes(path) for path, entry in changed.items() if entry["reverseHunks"]}
    classify = head._era_rule(head.READER_PATH, head.READER_NAME).classify
    built = head._v24_context(authority, context)
    rule_sha = head.HUNK_RULE_SHA256
    # operator-stated: check_* returns None when it passes
    assert head.check_hunk_record(raw, changed, afters, classify, built, rule_sha) is None
    extra = copy.deepcopy(record)
    extra["oracleExtra"] = 1
    steps = copy.deepcopy(record)
    steps["hunkClassContext"]["steps"] = [1, 2]
    pairs = copy.deepcopy(record)
    pairs["hunkClassContext"]["countPairs"] = [[1, 1]]
    vocabulary = copy.deepcopy(record)
    vocabulary["classes"] = _unknown_class(record["classes"], changed)
    # operator-stated: the record carries classes to mutate
    assert vocabulary["classes"] is not None
    for mutated in (extra, steps, pairs, vocabulary):
        mutated_raw = (json.dumps(mutated, indent=2) + "\n").encode("utf-8")
        # CONTRACT_296 section 4a and operator-stated: refused with a ValueError naming MET-014
        with pytest.raises(ValueError, match=STEP):
            head.check_hunk_record(mutated_raw, changed, afters, classify, built, rule_sha)
    # operator-stated: v2.5's rule digest is compared; a different digest is refused
    with pytest.raises(ValueError, match=STEP):
        head.check_hunk_record(raw, changed, afters, classify, built, _other(rule_sha))


# ------------------------------------------------------------ part 5: the packet YAML, catalog and table


def test_packet_yaml(head):
    """CONTRACT_296 sections 1 and 5: MET-014.yaml's id, predecessor, objective, contracts line and allowedPaths."""
    raw = head.reviewed_bytes(YAML_PATH)
    parsed = head.safe_load(raw)
    lines = raw.decode("utf-8").splitlines()
    # operator-stated: 16 keys, each on one line as key: <JSON value>
    assert [line.split(": ", 1)[0] for line in lines] == list(YAML_KEYS)
    unequal = sum(1 for key, value in (line.split(": ", 1) for line in lines) if json.loads(value) != parsed[key])
    # operator-stated: each line's value is JSON and equals the parsed value
    assert unequal == 0
    # CONTRACT_296 section 1: MET-014, PREV MET-013
    assert (parsed["id"], parsed["predecessors"]) == (STEP, [PREV])
    for text in ITEMS + ("a K = 0 step (320 packets at slot 296)",):
        # CONTRACT_296 section 5: the objective names the three roadmap ids and the K = 0 step
        assert text in parsed["objective"]
    first = parsed["contracts"][0]
    # CONTRACT_296 section 5: the contracts line names the base main and tree, holding 319 packets incl. MET-013
    assert BASE_MAIN in first and BASE_TREE in first and "319 immutable packets including MET-013" in first
    allowed = set(parsed["allowedPaths"])
    authority = head.authority()
    outside = sum(1 for path in authority["changedFiles"] if path not in allowed)
    # CONTRACT_296 section 5: allowedPaths holds the authority's changedFiles
    assert outside == 0
    named = sum(1 for path in (head.AUTHORITY_PATH, HEAD_MODULE, YAML_PATH) + PACKET_FILES_C1 if path in allowed)
    # CONTRACT_296 section 5: plus the authority record, the head and the YAML (and the members' new files)
    assert named == 3 + len(PACKET_FILES_C1)


def test_historical_catalog(head, catalog):
    """CONTRACT_296 section 1 with operator-stated facts: historical_catalog returns exactly the 319 base ids."""
    base = list(head.authority()["baselinePackets"])
    result = head.historical_catalog(dict(catalog))
    same = set(result) == set(base) and head.NEW_PACKET not in result
    # CONTRACT_296 section 1: base ids 319, MET-014 not among them
    assert same is True
    # CONTRACT_296 section 1: 319
    assert len(result) == BASE_IDS
    lacking = dict(catalog)
    lacking.pop(base[0])
    # operator-stated: it refuses a mapping that lacks an id
    with pytest.raises(ValueError):
        head.historical_catalog(lacking)
    adding = dict(catalog)
    adding["MET-999"] = {}
    # operator-stated: it refuses a mapping that adds an id
    with pytest.raises(ValueError):
        head.historical_catalog(adding)


def test_weights_table(head):
    """CONTRACT_296 section 6 (GATE_CI): 221 keys, raw = effective, regular files, head and oracle rows only."""
    objects = []

    def hook(pairs):
        objects.append(pairs)
        return dict(pairs)

    json.loads(head.reviewed_bytes(TABLE_PATH), object_pairs_hook=hook)
    tables = [pairs for pairs in objects if any(key == HEAD_TEST for key, _ in pairs)]
    # CONTRACT_296 section 6: tests/test_met_014.py holds a row
    assert len(tables) == 1
    raw_keys = [key for key, _ in tables[0]]
    effective = list(dict(tables[0]))
    same = raw_keys == effective
    # CONTRACT_296 section 6 and operator-stated: the raw keys equal the effective keys
    assert same is True
    # CONTRACT_296 section 6 (219 + 2) and operator-stated: 221 entries
    assert len(effective) == TABLE_ENTRIES
    has_oracle = ORACLE_TEST in effective
    # CONTRACT_296 section 6: tests/test_met_014_oracle.py holds a row
    assert has_oracle is True
    member_rows = sum(1 for path in MEMBER_TESTS if path in effective)
    # CONTRACT_296 section 6: the member tests take no row
    assert member_rows == 0
    unreadable = sum(1 for key in effective if not _reads(head, key))
    # CONTRACT_296 section 6 and the oracle brief item 5: every key names a regular file
    assert unreadable == 0
