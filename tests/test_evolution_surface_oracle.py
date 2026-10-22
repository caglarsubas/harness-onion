"""Oracle tests for the evolution surface record v1 (EVOLUTION-SURFACE-001).

Owner decision D5a: a contract packet carries tests written outside the candidate.
These tests are black-box. Every expected value is derived from the design note
(revision 4, sections 2 to 7 and 10, with the owner's answers of 2026-10-21) and
from the contract README. None is taken from the candidate's vectors, tests or
output. The model is reached only through its public interface.
"""

# MET-GOV-002: record version 2 (REVIEW-RECORD-V2 design section 8, owner decision Q-RR2-6 (b)) adds the
# programme class GATE_REVIEW_PROCESS. The design tables below are brought to version 2 only where a line is
# marked MET-GOV-002; every version-1 assertion keeps its meaning.

from __future__ import annotations

import fnmatch
import hashlib
import json
import os
import tempfile
from pathlib import Path

import jsonschema
import pytest

from scripts import evolution_surface as es

ROOT = Path(__file__).resolve().parents[1]
CONTRACT_DIR = ROOT / "architecture" / "evolution-surface"
RECORD_FILE = CONTRACT_DIR / "evolution-surface.json"
SCHEMA_FILE = CONTRACT_DIR / "evolution-surface.schema.json"
THIS_FILE = Path(__file__).resolve().relative_to(ROOT).as_posix()

OPS = ("propose", "generate", "test", "approve", "activate")


# --------------------------------------------------------------------------- helpers


def _no_duplicates(pairs):
    out = {}
    for key, value in pairs:
        if key in out:
            raise ValueError("duplicate member name in a fixture file")
        out[key] = value
    return out


def _read_json(path: Path):
    return json.loads(path.read_text(encoding="utf-8"), object_pairs_hook=_no_duplicates)


def clone(value):
    """The oracle's own deep copy."""
    if isinstance(value, dict):
        return {key: clone(item) for key, item in value.items()}
    if isinstance(value, list):
        return [clone(item) for item in value]
    return value


def jcs(value) -> bytes:
    """RFC 8785 bytes for the JSON subset the record uses (no floats)."""
    return _jcs(value).encode("utf-8")


def _jcs(value) -> str:
    if value is None:
        return "null"
    if value is True:
        return "true"
    if value is False:
        return "false"
    if isinstance(value, int):
        return str(value)
    if isinstance(value, str):
        return json.dumps(value, ensure_ascii=False)
    if isinstance(value, list):
        return "[" + ",".join(_jcs(item) for item in value) + "]"
    if isinstance(value, dict):
        keys = sorted(value, key=lambda key: key.encode("utf-16-be"))
        return "{" + ",".join(json.dumps(key, ensure_ascii=False) + ":" + _jcs(value[key]) for key in keys) + "}"
    raise TypeError(f"outside the oracle's JSON subset: {type(value).__name__}")


RECORD = _read_json(RECORD_FILE)
SCHEMA = _read_json(SCHEMA_FILE)
VALIDATOR = jsonschema.Draft202012Validator(SCHEMA)


def record():
    return clone(RECORD)


def klass(rec, level, cid):
    for item in rec["levels"][level]["classes"]:
        if item["id"] == cid:
            return item
    raise KeyError(cid)


def role(rec, level, rid):
    for item in rec["levels"][level]["roles"]:
        if item["id"] == rid:
            return item
    raise KeyError(rid)


def refusal(fn, *args):
    with pytest.raises(es.Refused) as caught:
        fn(*args)
    code = caught.value.code
    assert code in es.CODES
    return code


def make_files(root: Path, rels):
    for rel in rels:
        target = root.joinpath(*rel.split("/"))
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(b"oracle\n")


@pytest.fixture
def scratch():
    with tempfile.TemporaryDirectory(prefix="evos-oracle-") as name:
        yield Path(name).resolve()


def P(prefix):
    return {"prefix": prefix}


def E(exact):
    return {"exact": exact}


def U(under, name):
    return {"under": under, "name": name}


# --------------------------------------------------------------------------- the design's tables (sections 4, 5)

EVO, TASK, CUR = "EVOLUTION_AGENT", "TASK_AGENT", "KNOWLEDGE_CURATOR"
TEV, TAP, RACT, HUM = "TRUST_EVALUATOR", "TRUST_APPROVER", "RUNTIME_ACTIVATOR", "HUMAN_APPROVER"
AGENTS = [EVO, TASK]

PRODUCT_ROLES = {
    EVO: ("AGENT", "Execution"),
    TASK: ("AGENT", "Execution"),
    CUR: ("SERVICE", "Knowledge"),
    TEV: ("SERVICE", "Trust"),
    TAP: ("SERVICE", "Trust"),
    RACT: ("SERVICE", "Runtime"),
    HUM: ("HUMAN", "Trust"),
}

LS, RVW, ORC, VIS, MON, OWN, VER = (
    "LANE_SESSION",
    "REVIEWER_AGENT",
    "ORACLE_AGENT",
    "ROADMAP_VISIONARY",
    "LANE_MONITOR",
    "OWNER",
    "VERIFIER",
)
PROGRAMME_ROLES = {LS: "AGENT", RVW: "AGENT", ORC: "AGENT", VIS: "AGENT", MON: "AGENT", OWN: "HUMAN", VER: "SERVICE"}
LANES = [LS, MON, VIS, OWN]
EVERY_AGENT = [LS, RVW, ORC, VIS, MON]
DATA = ([MON, OWN], [MON, OWN])
GATE = ([OWN], [MON, OWN])


def spec(governs, propose, generate, test, approve, activate, *, never=False, two=False, append=False,
         binding="CONTENT", independent=()):
    return {
        "neverAutonomous": never,
        "twoPerson": two,
        "appendOnly": append,
        "approvalBinding": binding,
        "governs": set(governs),
        "independentOf": set(independent),
        "ops": {
            "propose": set(propose),
            "generate": set(generate),
            "test": set(test),
            "approve": set(approve),
            "activate": set(activate),
        },
    }


def _evolvable():
    return spec([], AGENTS, [EVO], [EVO, TEV], [TAP, HUM], [RACT])


PRODUCT = {
    "PROMPT": _evolvable(),
    "PROCEDURAL_SKILL_GRAPH": _evolvable(),
    "ROUTING_STRATEGY": _evolvable(),
    "TOOL_CONFIGURATION": _evolvable(),
    "MEMORY_KNOWLEDGE": spec([], AGENTS + [CUR], [CUR], [TEV], [TAP], [CUR]),
    "MODEL_ADAPTER": spec([], [EVO], [EVO], [EVO, TEV], [HUM], [RACT]),
    "MODEL_WEIGHTS": spec([], [EVO], [EVO], [EVO, TEV], [HUM], [RACT]),
    "EVALUATOR_RUBRIC": spec(AGENTS + [CUR], AGENTS, [TEV], [TEV, HUM], [HUM], [TAP], never=True, two=True),
    "ACCEPTANCE_THRESHOLD": spec(AGENTS + [CUR], AGENTS, [HUM], [TEV], [HUM], [TAP], never=True, two=True),
    "TRUST_POLICY": spec(AGENTS + [CUR, RACT, TEV, TAP], AGENTS, [HUM], [TEV], [HUM], [TAP], never=True, two=True),
    "CREDENTIAL": spec(AGENTS + [CUR, RACT, TEV, TAP], AGENTS, [HUM], [TEV], [HUM], [HUM], never=True, two=True),
    "APPROVAL_OR_ROLLOUT_GATE": spec(AGENTS + [CUR, RACT], AGENTS, [HUM], [TEV], [HUM], [TAP], never=True, two=True),
    "PROMOTION_AUTHORITY_CODE": spec(
        [r for r in PRODUCT_ROLES if r != HUM], AGENTS, [HUM], [TEV], [HUM], [HUM], never=True, two=True
    ),
}

CANDIDATE_CLASSES = [
    "CONTRACT_AND_SOURCE",
    "REPOSITORY_ROOT",
    "GATE_CI",
    "GATE_SCHEMAS",
    "GATE_POLICIES",
    "GATE_LEGAL",
    "GATE_HARNESS_DOCS",
    "GATE_VERIFIER_DOCS",
    "EVOLUTION_SURFACE",
]

PROGRAMME = {
    "CONTRACT_AND_SOURCE": spec([], LANES, [LS], [RVW, ORC, VER], *DATA),
    "REPOSITORY_ROOT": spec([], LANES, [LS], [RVW, VER], *DATA),
    "GATE_CI": spec([LS, MON, VER], LANES, [LS], [RVW, VER], *GATE),
    "GATE_SCHEMAS": spec([], LANES, [LS], [RVW, VER], *GATE),
    "GATE_POLICIES": spec([LS, MON, RVW, ORC], LANES, [LS], [RVW, VER], *GATE),
    "GATE_LEGAL": spec([], LANES, [LS], [RVW, VER], *GATE),
    "GATE_HARNESS_DOCS": spec([], LANES, [LS], [RVW, VER], *GATE),
    "GATE_VERIFIER_DOCS": spec([LS, MON, VER], LANES, [LS], [RVW, VER], *GATE),
    "EVOLUTION_SURFACE": spec(EVERY_AGENT, LANES, [LS], [RVW, ORC, VER], *GATE),
    # MET-GOV-002: ORACLE_TESTS, REVIEW_RECORD and GATE_REVIEW_RECORD add GATE_REVIEW_PROCESS to independentOf.
    "ORACLE_TESTS": spec([LS], LANES, [ORC], [VER], *DATA, independent=CANDIDATE_CLASSES + ["GATE_REVIEW_PROCESS"]),
    "REVIEW_BRIEF": spec([LS, RVW], LANES, [LS], [VER], *DATA),
    "REVIEW_RECORD": spec([LS], LANES, [RVW], [VER], *DATA, independent=CANDIDATE_CLASSES + ["GATE_REVIEW_PROCESS"]),
    "GATE_REVIEW_BRIEF": spec([LS, RVW], LANES, [LS], [VER], *GATE),
    "GATE_REVIEW_RECORD": spec(
        [LS], LANES, [RVW], [VER], *GATE, independent=CANDIDATE_CLASSES + ["GATE_REVIEW_PROCESS"]
    ),
    # MET-GOV-002: the new class, after GATE_REVIEW_RECORD, as DESIGN section 8's object (gate; governs the lane,
    # the monitor, the reviewer and the oracle; generated by the lane; tested by reviewer, oracle and verifier).
    "GATE_REVIEW_PROCESS": spec([LS, MON, RVW, ORC], LANES, [LS], [RVW, ORC, VER], *GATE),
    "VERIFIER_BUNDLE": spec(EVERY_AGENT, LANES, [LS], [RVW], [OWN], [OWN], never=True),
    "MERGE_DECISION_RECORD": spec([], [], [MON], [], [], [], append=True),
    "OWNER_DECISION_RECORD": spec([], [], [MON, LS], [], [], [], append=True),
    "ROADMAP_STATUS": spec([], [VIS, LS, OWN], [VIS, LS], [VIS, LS], [MON], [VIS, LS], binding="CHANGE"),
    "ROADMAP_SCOPE": spec([], LANES, [VIS, LS], [VIS, LS], [OWN], [VIS, LS], binding="CHANGE"),
}

KINDS = {"product": {rid: kind for rid, (kind, _plane) in PRODUCT_ROLES.items()}, "programme": PROGRAMME_ROLES}
TABLES = {"product": PRODUCT, "programme": PROGRAMME}

GATE_DIRS = [
    "ci/",
    ".github/",
    "schemas/",
    "policies/",
    "legal/",
    "docs/harnesses/",
    "docs/linux-runner/",
    "architecture/evolution-surface/",
    "tests/fixtures/zero-bill/",
    # MET-GOV-002: GATE_REVIEW_PROCESS's prefix is a gate directory (invariant 8), so the review classes gain it.
    "architecture/review-record/",
]

DESIGN_PATHS = {
    "CONTRACT_AND_SOURCE": [
        P("architecture/"),
        P("scripts/"),
        P("tests/"),
        P("docs/"),
        P("task-packets/"),
        P("diagnostics/"),
        P("reference-observer/"),
        P("release/"),
    ],
    "REPOSITORY_ROOT": [
        E(name)
        for name in (
            "README.md",
            "CONTRIBUTING.md",
            "SECURITY.md",
            ".gitignore",
            ".impeccable.md",
            "Makefile",
            "requirements.lock",
            "uv.lock",
        )
    ],
    "GATE_CI": [P("ci/"), P(".github/"), E("pyproject.toml"), E("conftest.py")],
    "GATE_SCHEMAS": [P("schemas/")],
    "GATE_POLICIES": [
        P("policies/"),
        E("BILLING_POLICY.md"),
        E("release/evidence-policy.yaml"),
        E("AGENTS.md"),
        E("scripts/zero_bill_scan.py"),
        P("tests/fixtures/zero-bill/"),
        E("release/repos.lock.json"),
        E("scripts/check_release_lock.py"),
        E("scripts/build_release_lock.py"),
    ],
    "GATE_LEGAL": [P("legal/"), E("LICENSE"), E("NOTICE")],
    "GATE_HARNESS_DOCS": [P("docs/harnesses/")],
    "GATE_VERIFIER_DOCS": [
        E("docs/alpha-2/OWNER_OPERATED_VERIFIER.md"),
        E("docs/TRUSTED_RUNNER_CONTRACT.md"),
        E("docs/alpha-2/CI_CAPACITY_EXCEPTION.md"),
        P("docs/linux-runner/"),
        E("docs/TRUSTED_LIVE_CAMPAIGN_RUNNER_CONTRACT.md"),
        E("docs/alpha-2/CREDENTIAL_ORDERING_REPAIR.md"),
    ],
    "EVOLUTION_SURFACE": [
        P("architecture/evolution-surface/"),
        E("architecture/evolution-surface-authority.json"),
        E("scripts/evolution_surface.py"),
    ],
    "ORACLE_TESTS": [U("tests/", "test_*oracle*.py")],
    "REVIEW_BRIEF": [U("architecture/", "REVIEW_BRIEF*.md")],
    "REVIEW_RECORD": [U("architecture/", "review-round*.json")],
    "GATE_REVIEW_BRIEF": [U(d, "REVIEW_BRIEF*.md") for d in GATE_DIRS],
    "GATE_REVIEW_RECORD": [U(d, "review-round*.json") for d in GATE_DIRS],
    # MET-GOV-002: DESIGN section 8's four path entries of the new class.
    "GATE_REVIEW_PROCESS": [
        P("architecture/review-record/"),
        E("architecture/review-record-authority.json"),
        E("scripts/review_record.py"),
        E("tests/test_review_records_in_tree.py"),
    ],
}

NEVER_SIX = {
    "EVALUATOR_RUBRIC",
    "ACCEPTANCE_THRESHOLD",
    "TRUST_POLICY",
    "CREDENTIAL",
    "APPROVAL_OR_ROLLOUT_GATE",
    "PROMOTION_AUTHORITY_CODE",
}
EVOLVABLE_SEVEN = {
    "PROMPT",
    "PROCEDURAL_SKILL_GRAPH",
    "ROUTING_STRATEGY",
    "TOOL_CONFIGURATION",
    "MEMORY_KNOWLEDGE",
    "MODEL_ADAPTER",
    "MODEL_WEIGHTS",
}
GATE_CLASSES = {
    "GATE_CI",
    "GATE_SCHEMAS",
    "GATE_POLICIES",
    "GATE_LEGAL",
    "GATE_HARNESS_DOCS",
    "GATE_VERIFIER_DOCS",
    "EVOLUTION_SURFACE",
    "GATE_REVIEW_BRIEF",
    "GATE_REVIEW_RECORD",
    "GATE_REVIEW_PROCESS",  # MET-GOV-002: approve {OWNER}, activate {LANE_MONITOR, OWNER} (DESIGN section 8)
}
# MET-GOV-002 r1: the version-2 edit above changed this line by whitespace only ("= {" became "={"); no code change.
DATA_CLASSES ={"CONTRACT_AND_SOURCE", "REPOSITORY_ROOT", "ORACLE_TESTS", "REVIEW_BRIEF", "REVIEW_RECORD"}

# Gate-material derivation (sections 5 and 10; Q-ES-6 (b), Q-ES-D1 (a), Q-ES-D2 (a)).
PA_D5 = [
    P("ci/"),
    P("schemas/"),
    P("policies/"),
    P("legal/"),
    P("docs/harnesses/"),
    E("docs/alpha-2/OWNER_OPERATED_VERIFIER.md"),
]
OWN_THREE = [
    P("architecture/evolution-surface/"),
    E("architecture/evolution-surface-authority.json"),
    E("scripts/evolution_surface.py"),
]
CANDIDATES = {
    "C1": [P(".github/")],
    "C2": [E("BILLING_POLICY.md")],
    "C3": [E("release/evidence-policy.yaml")],
    "C4": [E("LICENSE"), E("NOTICE")],
    "C5": [E("docs/TRUSTED_RUNNER_CONTRACT.md"), E("docs/alpha-2/CI_CAPACITY_EXCEPTION.md"), P("docs/linux-runner/")],
    "C6": [E("AGENTS.md")],
    "C7": [E("scripts/zero_bill_scan.py"), P("tests/fixtures/zero-bill/")],
    "C8": [E("pyproject.toml")],
    "C9": [E("release/repos.lock.json")],
    "C10": [E("conftest.py")],
    "C11": [E("scripts/check_release_lock.py"), E("scripts/build_release_lock.py")],
    "C12": [E("docs/TRUSTED_LIVE_CAMPAIGN_RUNNER_CONTRACT.md")],
    "C13": [E("docs/alpha-2/CREDENTIAL_ORDERING_REPAIR.md")],
}
# MET-GOV-002: record version 2's accepted group RR2 (Q-RR2-6 (b), D-1, D-2): the four GATE_REVIEW_PROCESS entries.
RR2 = [
    P("architecture/review-record/"),
    E("architecture/review-record-authority.json"),
    E("scripts/review_record.py"),
    E("tests/test_review_records_in_tree.py"),
]
# MET-GOV-002: DESIGN section 8's class object, verbatim.
GATE_REVIEW_PROCESS_OBJECT = {
    "id": "GATE_REVIEW_PROCESS",
    "description": (
        "The review-record v2 contract: brief registry, legacy digest list, checker, in-tree pre-check and authority."
    ),
    "paths": [
        {"prefix": "architecture/review-record/"},
        {"exact": "architecture/review-record-authority.json"},
        {"exact": "scripts/review_record.py"},
        {"exact": "tests/test_review_records_in_tree.py"},
    ],
    "neverAutonomous": False,
    "appendOnly": False,
    "twoPerson": False,
    "approvalBinding": "CONTENT",
    "governs": ["LANE_SESSION", "LANE_MONITOR", "REVIEWER_AGENT", "ORACLE_AGENT"],
    "independentOf": [],
    "operations": {
        "propose": ["LANE_SESSION", "LANE_MONITOR", "ROADMAP_VISIONARY", "OWNER"],
        "generate": ["LANE_SESSION"],
        "test": ["REVIEWER_AGENT", "ORACLE_AGENT", "VERIFIER"],
        "approve": ["OWNER"],
        "activate": ["LANE_MONITOR", "OWNER"],
    },
    "grounds": [
        "Q-RR2-6 (owner, 2026-10-21): the brief registry and the checker are gate material",
        "D-1 and D-2 (this design, named in the owner's per-PR ask)",
    ],
}


# --------------------------------------------------------------------------- the oracle's own rules (sections 2, 3)


def related(level, cid):
    table = TABLES[level]
    return {
        other
        for other, entry in table.items()
        if other != cid and (other in table[cid]["independentOf"] or cid in entry["independentOf"])
    }


def design_decision(level, role_id, cid, op):
    entry = TABLES[level][cid]
    if role_id in entry["ops"][op]:
        return {"decision": "ALLOWED", "reasons": []}
    kind = KINDS[level][role_id]
    reasons = ["NOT_LISTED"]
    if kind == "AGENT" and op in ("approve", "activate") and entry["neverAutonomous"]:
        reasons.append("NEVER_AUTONOMOUS")
    if op == "approve" and role_id in entry["governs"]:
        reasons.append("SELF_GOVERNANCE")
    if op == "approve" and kind in ("AGENT", "SERVICE") and (
        role_id in entry["ops"]["generate"] or role_id in entry["ops"]["test"]
    ):
        reasons.append("SEPARATION_OF_DUTIES")
    if op in ("approve", "activate") and entry["appendOnly"]:
        reasons.append("APPEND_ONLY")
    if op == "generate" and any(role_id in TABLES[level][d]["ops"]["generate"] for d in related(level, cid)):
        reasons.append("INDEPENDENCE")
    return {"decision": "DENIED", "reasons": reasons}


def design_resolve(paths_by_class, path):
    exact = [cid for cid, entries in paths_by_class.items() for e in entries if e.get("exact") == path]
    if exact:
        return exact[0] if len(exact) == 1 else None
    name = path.rsplit("/", 1)[-1]
    hits = []
    for cid, entries in paths_by_class.items():
        for e in entries:
            if "prefix" in e and path.startswith(e["prefix"]):
                hits.append(((len(e["prefix"]), 0), cid))
            elif "under" in e and path.startswith(e["under"]) and fnmatch.fnmatchcase(name, e["name"]):
                hits.append(((len(e["under"]), 1), cid))
    if not hits:
        return None
    best = max(rank for rank, _cid in hits)
    winners = [cid for rank, cid in hits if rank == best]
    return winners[0] if len(winners) == 1 else None


# --------------------------------------------------------------------------- public constants


def test_public_tuples_follow_the_readme():
    assert es.CODES == (
        "SHAPE",
        "DUPLICATE_ID",
        "UNKNOWN_REFERENCE",
        "NEVER_AUTONOMOUS",
        "SELF_GOVERNANCE",
        "SEPARATION_OF_DUTIES",
        "TWO_PERSON",
        "ACTIVATION_WITHOUT_APPROVAL",
        "APPEND_ONLY",
        "INDEPENDENCE",
        "PATHS",
        "INDEPENDENT_EVIDENCE",
        "COVERAGE",
    )
    assert es.REASONS == (
        "NOT_LISTED",
        "NEVER_AUTONOMOUS",
        "SELF_GOVERNANCE",
        "SEPARATION_OF_DUTIES",
        "APPEND_ONLY",
        "INDEPENDENCE",
    )
    assert es.OPS == OPS
    assert isinstance(es.LEVELS, tuple)
    assert set(es.LEVELS) == {"product", "programme"}
    assert issubclass(es.Refused, Exception)


# --------------------------------------------------------------------------- 10. the record itself


@pytest.mark.parametrize("level", ["product", "programme"])
def test_record_roles_match_the_design(level):
    roles = RECORD["levels"][level]["roles"]
    assert len(roles) == len({r["id"] for r in roles})
    if level == "product":
        assert {r["id"]: (r["kind"], r["plane"]) for r in roles} == PRODUCT_ROLES
    else:
        assert {r["id"]: r["kind"] for r in roles} == PROGRAMME_ROLES
        assert all("plane" not in r for r in roles)


@pytest.mark.parametrize("level", ["product", "programme"])
def test_record_class_ids_match_the_design(level):
    ids = [c["id"] for c in RECORD["levels"][level]["classes"]]
    assert len(ids) == len(set(ids))
    assert set(ids) == set(TABLES[level])


CLASS_KEYS = [("product", cid) for cid in PRODUCT] + [("programme", cid) for cid in PROGRAMME]


@pytest.mark.parametrize("level,cid", CLASS_KEYS, ids=[f"{lv}-{c}" for lv, c in CLASS_KEYS])
def test_record_class_matches_the_design(level, cid):
    got = klass(RECORD, level, cid)
    want = TABLES[level][cid]
    for flag in ("neverAutonomous", "twoPerson", "appendOnly", "approvalBinding"):
        assert got[flag] == want[flag], flag
    assert set(got["governs"]) == want["governs"]
    assert {op: set(got["operations"][op]) for op in OPS} == want["ops"]
    if cid in DESIGN_PATHS:
        assert sorted(jcs(e) for e in got["paths"]) == sorted(jcs(e) for e in DESIGN_PATHS[cid])
    else:
        assert "paths" not in got
    assert got["grounds"]


def test_record_independence_pairs_match_the_design():
    for level in ("product", "programme"):
        got = {frozenset((c["id"], o)) for c in RECORD["levels"][level]["classes"] for o in c["independentOf"]}
        want = {frozenset((cid, o)) for cid, entry in TABLES[level].items() for o in entry["independentOf"]}
        assert got == want, level


def test_record_coverage_skip_set_matches_section_7():
    skip = RECORD["levels"]["programme"]["coverageSkip"]
    assert sorted(skip["rootNames"]) == [".git", ".venv"]
    assert sorted(skip["anyDepthDirectories"]) == sorted(["__pycache__", ".pytest_cache", ".ruff_cache", ".mypy_cache"])
    assert sorted(skip["anyDepthFilePatterns"]) == sorted(["*.py[cod]", ".DS_Store"])


def test_never_autonomous_six_are_two_person():
    classes = RECORD["levels"]["product"]["classes"]
    assert {c["id"] for c in classes if c["neverAutonomous"]} == NEVER_SIX
    for c in classes:
        assert c["twoPerson"] is (c["id"] in NEVER_SIX), c["id"]
    for c in classes:
        if c["id"] in EVOLVABLE_SEVEN:
            assert not c["neverAutonomous"] and c["governs"] == [], c["id"]
    assert {c["id"] for c in classes if not c["neverAutonomous"]} == EVOLVABLE_SEVEN


def test_task_agent_only_proposes():
    assert role(RECORD, "product", TASK)["kind"] == "AGENT"
    proposes = False
    for c in RECORD["levels"]["product"]["classes"]:
        for op in ("generate", "test", "approve", "activate"):
            assert TASK not in c["operations"][op], (c["id"], op)
        proposes = proposes or TASK in c["operations"]["propose"]
    assert proposes


def test_verifier_bundle_is_the_only_never_autonomous_programme_class():
    classes = RECORD["levels"]["programme"]["classes"]
    assert [c["id"] for c in classes if c["neverAutonomous"]] == ["VERIFIER_BUNDLE"]
    bundle = klass(RECORD, "programme", "VERIFIER_BUNDLE")
    assert "paths" not in bundle
    assert bundle["operations"]["approve"] == [OWN] and bundle["operations"]["activate"] == [OWN]


def test_gate_classes_approve_owner_and_activate_monitor_and_owner():
    repo = [c for c in RECORD["levels"]["programme"]["classes"] if "paths" in c]
    assert {c["id"] for c in repo} == GATE_CLASSES | DATA_CLASSES
    assert {c["id"] for c in repo if set(c["operations"]["approve"]) == {OWN}} == GATE_CLASSES
    for c in repo:
        approve, activate = c["operations"]["approve"], c["operations"]["activate"]
        assert len(approve) == len(set(approve)) and len(activate) == len(set(activate))
        if c["id"] in GATE_CLASSES:
            assert set(approve) == {OWN} and set(activate) == {MON, OWN}, c["id"]
        else:
            assert set(approve) == {MON, OWN} and set(activate) == {MON, OWN}, c["id"]
        assert not c["neverAutonomous"] and c["approvalBinding"] == "CONTENT", c["id"]


def test_roadmap_classes_are_change_bound_and_the_monitor_does_not_propose_status():
    change = {
        c["id"]
        for level in ("product", "programme")
        for c in RECORD["levels"][level]["classes"]
        if c["approvalBinding"] == "CHANGE"
    }
    assert change == {"ROADMAP_STATUS", "ROADMAP_SCOPE"}
    status = klass(RECORD, "programme", "ROADMAP_STATUS")
    scope = klass(RECORD, "programme", "ROADMAP_SCOPE")
    assert "paths" not in status and "paths" not in scope
    assert MON not in status["operations"]["propose"]
    assert status["operations"]["approve"] == [MON]
    assert scope["operations"]["approve"] == [OWN]


# --------------------------------------------------------------------------- 1. decisions (section 6)

PRODUCT_REFUSALS = [
    (EVO, "TRUST_POLICY", "generate", []),
    (EVO, "TRUST_POLICY", "activate", ["NEVER_AUTONOMOUS"]),
    (EVO, "EVALUATOR_RUBRIC", "generate", []),
    (EVO, "EVALUATOR_RUBRIC", "approve", ["NEVER_AUTONOMOUS", "SELF_GOVERNANCE"]),
    (EVO, "ACCEPTANCE_THRESHOLD", "generate", []),
    (EVO, "ACCEPTANCE_THRESHOLD", "approve", ["NEVER_AUTONOMOUS", "SELF_GOVERNANCE"]),
    (EVO, "ACCEPTANCE_THRESHOLD", "activate", ["NEVER_AUTONOMOUS"]),
    (TASK, "CREDENTIAL", "activate", ["NEVER_AUTONOMOUS"]),
    (EVO, "APPROVAL_OR_ROLLOUT_GATE", "activate", ["NEVER_AUTONOMOUS"]),
    (EVO, "PROMOTION_AUTHORITY_CODE", "generate", []),
    (EVO, "PROMOTION_AUTHORITY_CODE", "approve", ["NEVER_AUTONOMOUS", "SELF_GOVERNANCE"]),
    (TAP, "PROMOTION_AUTHORITY_CODE", "approve", ["SELF_GOVERNANCE"]),
    (TAP, "PROMOTION_AUTHORITY_CODE", "activate", []),
    (TAP, "TRUST_POLICY", "approve", ["SELF_GOVERNANCE"]),
    (EVO, "PROMPT", "approve", ["SEPARATION_OF_DUTIES"]),
    (TEV, "PROMPT", "approve", ["SEPARATION_OF_DUTIES"]),
    (EVO, "PROMPT", "activate", []),
    (TASK, "PROMPT", "generate", []),
    (TASK, "PROMPT", "activate", []),
]

PROGRAMME_REFUSALS = [
    (LS, "GATE_CI", "approve", ["SELF_GOVERNANCE", "SEPARATION_OF_DUTIES"]),
    (MON, "GATE_CI", "approve", ["SELF_GOVERNANCE"]),
    (MON, "GATE_SCHEMAS", "approve", []),
    (MON, "GATE_POLICIES", "approve", ["SELF_GOVERNANCE"]),
    (VER, "GATE_CI", "approve", ["SELF_GOVERNANCE", "SEPARATION_OF_DUTIES"]),
    (RVW, "GATE_LEGAL", "generate", ["INDEPENDENCE"]),
    (RVW, "REVIEW_RECORD", "approve", ["SEPARATION_OF_DUTIES"]),
    (RVW, "CONTRACT_AND_SOURCE", "approve", ["SEPARATION_OF_DUTIES"]),
    (LS, "REVIEW_RECORD", "generate", ["INDEPENDENCE"]),
    (LS, "ORACLE_TESTS", "generate", ["INDEPENDENCE"]),
    (ORC, "CONTRACT_AND_SOURCE", "generate", ["INDEPENDENCE"]),
    (MON, "MERGE_DECISION_RECORD", "approve", ["SEPARATION_OF_DUTIES", "APPEND_ONLY"]),
    (MON, "EVOLUTION_SURFACE", "approve", ["SELF_GOVERNANCE"]),
    (MON, "VERIFIER_BUNDLE", "activate", ["NEVER_AUTONOMOUS"]),
    (MON, "ROADMAP_STATUS", "propose", []),
    (MON, "ROADMAP_SCOPE", "approve", []),
    (MON, "ROADMAP_STATUS", "activate", []),
]

REFUSALS = [("product",) + row for row in PRODUCT_REFUSALS] + [("programme",) + row for row in PROGRAMME_REFUSALS]

PERMISSIONS = [
    ("product", TAP, "PROMPT", "approve"),
    ("product", HUM, "EVALUATOR_RUBRIC", "test"),
    ("programme", MON, "CONTRACT_AND_SOURCE", "approve"),
    ("programme", MON, "GATE_CI", "activate"),
    ("programme", OWN, "GATE_CI", "approve"),
    ("programme", MON, "ROADMAP_STATUS", "approve"),
    ("programme", OWN, "ROADMAP_SCOPE", "approve"),
    ("programme", LS, "ROADMAP_STATUS", "activate"),
]


def test_oracle_rules_reproduce_the_design_tables():
    for level, role_id, cid, op, added in REFUSALS:
        assert design_decision(level, role_id, cid, op) == {"decision": "DENIED", "reasons": ["NOT_LISTED"] + added}
    for level, role_id, cid, op in PERMISSIONS:
        assert design_decision(level, role_id, cid, op) == {"decision": "ALLOWED", "reasons": []}


@pytest.mark.parametrize(
    "level,role_id,cid,op,added", REFUSALS, ids=[f"{lv}-{r}-{c}-{o}" for lv, r, c, o, _a in REFUSALS]
)
def test_refusal_vector(level, role_id, cid, op, added):
    expected = {"decision": "DENIED", "reasons": ["NOT_LISTED"] + added}
    assert es.decide(record(), level, role_id, cid, op) == expected


@pytest.mark.parametrize("level,role_id,cid,op", PERMISSIONS, ids=[f"{lv}-{r}-{c}-{o}" for lv, r, c, o in PERMISSIONS])
def test_permission_vector(level, role_id, cid, op):
    assert es.decide(record(), level, role_id, cid, op) == {"decision": "ALLOWED", "reasons": []}


@pytest.mark.parametrize("level", ["product", "programme"])
def test_every_request_follows_the_design_rules(level):
    rec = record()
    mismatches = []
    for role_id in KINDS[level]:
        for cid in TABLES[level]:
            for op in OPS:
                got = es.decide(rec, level, role_id, cid, op)
                want = design_decision(level, role_id, cid, op)
                if got != want:
                    mismatches.append((role_id, cid, op, got, want))
    assert mismatches == []


# --------------------------------------------------------------------------- 2. and 3. invariants, schema agreement


def setc(level, cid, key, value):
    def mutate(rec):
        klass(rec, level, cid)[key] = clone(value)

    return mutate


def popc(level, cid, key):
    def mutate(rec):
        klass(rec, level, cid).pop(key)

    return mutate


def setop(level, cid, op, value):
    def mutate(rec):
        klass(rec, level, cid)["operations"][op] = list(value)

    return mutate


def addop(level, cid, op, rid):
    def mutate(rec):
        klass(rec, level, cid)["operations"][op].append(rid)

    return mutate


def setrole(level, rid, key, value):
    def mutate(rec):
        role(rec, level, rid)[key] = value

    return mutate


def poprole(level, rid, key):
    def mutate(rec):
        role(rec, level, rid).pop(key)

    return mutate


def settop(key, value):
    def mutate(rec):
        rec[key] = value

    return mutate


def addpath(cid, entry):
    def mutate(rec):
        klass(rec, "programme", cid)["paths"].append(clone(entry))

    return mutate


def droppath(cid, entry):
    def mutate(rec):
        klass(rec, "programme", cid)["paths"].remove(entry)

    return mutate


def append_to(level, key, item_fn):
    def mutate(rec):
        rec["levels"][level][key].append(item_fn(rec))

    return mutate


def append_independent(cid, other):
    def mutate(rec):
        klass(rec, "programme", cid)["independentOf"].append(other)

    return mutate


def skipset(fn):
    def mutate(rec):
        fn(rec["levels"]["programme"]["coverageSkip"])

    return mutate


def both(*mutators):
    def mutate(rec):
        for mutator in mutators:
            mutator(rec)

    return mutate


def mutated(mutator):
    rec = record()
    mutator(rec)
    return rec


def no_change(rec):
    return None


def _drop_programme(rec):
    rec["levels"].pop("programme")


def _drop_skip(rec):
    rec["levels"]["programme"].pop("coverageSkip")


def _empty_product_roles(rec):
    rec["levels"]["product"]["roles"] = []


def _drop_op(level, cid, op):
    def mutate(rec):
        klass(rec, level, cid)["operations"].pop(op)

    return mutate


def _extra_op(rec):
    klass(rec, "product", "PROMPT")["operations"]["delete"] = []


NON_SHAPE_BREAKS = [
    (
        "duplicate programme role",
        "DUPLICATE_ID",
        append_to("programme", "roles", lambda rec: clone(role(rec, "programme", OWN))),
    ),
    (
        "duplicate product class",
        "DUPLICATE_ID",
        append_to("product", "classes", lambda rec: clone(klass(rec, "product", "PROMPT"))),
    ),
    (
        "duplicate bridge class",
        "DUPLICATE_ID",
        append_to("programme", "classes", lambda rec: clone(klass(rec, "programme", "VERIFIER_BUNDLE"))),
    ),
    ("unknown role in propose", "UNKNOWN_REFERENCE", addop("product", "PROMPT", "propose", "GHOST_AGENT")),
    ("unknown role in governs", "UNKNOWN_REFERENCE", setc("programme", "GATE_SCHEMAS", "governs", ["GHOST_AGENT"])),
    ("unknown class in independentOf", "UNKNOWN_REFERENCE", append_independent("ORACLE_TESTS", "NO_SUCH_CLASS")),
    ("programme role named at product level", "UNKNOWN_REFERENCE", addop("product", "PROMPT", "propose", MON)),
    ("product class named at programme level", "UNKNOWN_REFERENCE", append_independent("ORACLE_TESTS", "PROMPT")),
    ("model-driven trust approver declared AGENT", "NEVER_AUTONOMOUS", setrole("product", TAP, "kind", "AGENT")),
    ("monitor installs the verifier bundle", "NEVER_AUTONOMOUS", addop("programme", "VERIFIER_BUNDLE", "activate", MON)),
    ("gate class never-autonomous with the monitor activating", "NEVER_AUTONOMOUS",
     setc("programme", "GATE_CI", "neverAutonomous", True)),
    ("trust approver approves its own policy", "SELF_GOVERNANCE", addop("product", "TRUST_POLICY", "approve", TAP)),
    ("data class governs the monitor", "SELF_GOVERNANCE", setc("programme", "CONTRACT_AND_SOURCE", "governs", [MON])),
    ("roadmap scope governs the owner", "SELF_GOVERNANCE", setc("programme", "ROADMAP_SCOPE", "governs", [OWN])),
    ("agent generator approves", "SEPARATION_OF_DUTIES", addop("product", "PROMPT", "approve", EVO)),
    ("service tester approves", "SEPARATION_OF_DUTIES", addop("programme", "CONTRACT_AND_SOURCE", "approve", VER)),
    ("reviewer approves its own review", "SEPARATION_OF_DUTIES", addop("programme", "REVIEW_RECORD", "approve", RVW)),
    ("twoPerson set with no human generator or tester", "TWO_PERSON", setc("product", "PROMPT", "twoPerson", True)),
    ("twoPerson cleared on a human-generated class", "TWO_PERSON", setc("product", "TRUST_POLICY", "twoPerson", False)),
    ("human tester approves without twoPerson", "TWO_PERSON", addop("programme", "CONTRACT_AND_SOURCE", "test", OWN)),
    ("product activation without approval", "ACTIVATION_WITHOUT_APPROVAL", setop("product", "PROMPT", "approve", [])),
    ("programme activation without approval", "ACTIVATION_WITHOUT_APPROVAL",
     setop("programme", "ROADMAP_SCOPE", "approve", [])),
    ("append-only product class with approvers", "APPEND_ONLY", setc("product", "PROMPT", "appendOnly", True)),
    ("append-only programme class with approvers", "APPEND_ONLY",
     setc("programme", "CONTRACT_AND_SOURCE", "appendOnly", True)),
    ("the lane in the oracle's generate", "INDEPENDENCE", addop("programme", "ORACLE_TESTS", "generate", LS)),
    ("the reviewer generates gate material", "INDEPENDENCE", addop("programme", "GATE_LEGAL", "generate", RVW)),
    ("relation declared on the other side", "INDEPENDENCE",
     setc("programme", "CONTRACT_AND_SOURCE", "independentOf", ["REVIEW_BRIEF"])),
    ("gate review records miss a gate prefix", "PATHS", droppath("GATE_REVIEW_RECORD", U("ci/", "review-round*.json"))),
    ("gate review briefs under a data directory", "PATHS", addpath("GATE_REVIEW_BRIEF", U("docs/", "REVIEW_BRIEF*.md"))),
    ("new gate prefix without review directories", "PATHS", addpath("GATE_SCHEMAS", P("templates/"))),
    ("gate prefix dropped with its review directories kept", "PATHS",
     droppath("GATE_VERIFIER_DOCS", P("docs/linux-runner/"))),
    ("entry repeated in one class", "PATHS", addpath("GATE_SCHEMAS", P("schemas/"))),
    ("entry claimed by two classes", "PATHS", addpath("CONTRACT_AND_SOURCE", E("conftest.py"))),
    ("content-bound class tested only by its generator", "INDEPENDENT_EVIDENCE", setop("product", "PROMPT", "test", [EVO])),
    ("programme class tested only by its generator", "INDEPENDENT_EVIDENCE",
     setop("programme", "CONTRACT_AND_SOURCE", "test", [LS])),
    ("approved bridge class with no tester", "INDEPENDENT_EVIDENCE", setop("programme", "VERIFIER_BUNDLE", "test", [])),
    ("roadmap status made content-bound", "INDEPENDENT_EVIDENCE",
     setc("programme", "ROADMAP_STATUS", "approvalBinding", "CONTENT")),
]

SHAPE_FAULTS = [
    ("change-bound class with paths", setc("programme", "ROADMAP_STATUS", "paths", [E("roadmap/roadmap.json")])),
    ("repository class made change-bound", setc("programme", "CONTRACT_AND_SOURCE", "approvalBinding", "CHANGE")),
    ("product class made change-bound", setc("product", "PROMPT", "approvalBinding", "CHANGE")),
    ("product class with paths", setc("product", "PROMPT", "paths", [P("prompts/")])),
    ("approval binding unknown", setc("programme", "GATE_CI", "approvalBinding", "BYTES")),
    ("operation missing", _drop_op("programme", "GATE_CI", "test")),
    ("operation added", _extra_op),
    ("role kind unknown", setrole("programme", VER, "kind", "ROBOT")),
    ("programme role with a plane", setrole("programme", OWN, "plane", "Trust")),
    ("product role without a plane", poprole("product", HUM, "plane")),
    ("product plane unknown", setrole("product", HUM, "plane", "Control")),
    ("role id not upper case", setrole("programme", VER, "id", "verifier")),
    ("role listed twice in one operation", setop("programme", "GATE_CI", "approve", [OWN, OWN])),
    ("role name malformed", setop("programme", "GATE_CI", "propose", ["lane-session"])),
    ("flag not a boolean", setc("product", "PROMPT", "neverAutonomous", "no")),
    ("flag missing", popc("product", "PROMPT", "twoPerson")),
    ("grounds empty", setc("product", "PROMPT", "grounds", [])),
    ("description empty", setc("product", "PROMPT", "description", "")),
    ("description too long", setc("product", "PROMPT", "description", "x" * 2001)),
    ("class member unknown", setc("product", "PROMPT", "owner", "x")),
    ("independentOf not a list", setc("programme", "ORACLE_TESTS", "independentOf", "CONTRACT_AND_SOURCE")),
    ("governs repeats a role", setc("programme", "GATE_CI", "governs", [LS, LS])),
    ("paths empty", setc("programme", "GATE_SCHEMAS", "paths", [])),
    ("prefix without a slash", setc("programme", "GATE_SCHEMAS", "paths", [{"prefix": "schemas"}])),
    ("exact with a trailing slash", setc("programme", "GATE_LEGAL", "paths", [P("legal/"), E("LICENSE/"), E("NOTICE")])),
    ("absolute exact path", setc("programme", "GATE_LEGAL", "paths", [P("legal/"), E("/LICENSE"), E("NOTICE")])),
    ("dot-dot component", setc("programme", "GATE_LEGAL", "paths", [P("legal/../ci/"), E("LICENSE"), E("NOTICE")])),
    ("dot component", setc("programme", "GATE_LEGAL", "paths", [P("legal/"), E("./LICENSE"), E("NOTICE")])),
    ("empty component", setc("programme", "GATE_LEGAL", "paths", [P("legal//x/"), E("LICENSE"), E("NOTICE")])),
    ("space in a path", setc("programme", "GATE_LEGAL", "paths", [P("legal/"), E("LICENSE FILE"), E("NOTICE")])),
    ("entry of two kinds", setc("programme", "GATE_LEGAL", "paths", [{"exact": "LICENSE", "prefix": "legal/"}])),
    ("under entry without a name", setc("programme", "ORACLE_TESTS", "paths", [{"under": "tests/"}])),
    ("name pattern with a slash", setc("programme", "ORACLE_TESTS", "paths", [U("tests/", "sub/test_*oracle*.py")])),
    ("version not an integer", settop("version", 1.5)),
    ("version a boolean", settop("version", True)),
    ("version zero", settop("version", 0)),
    ("version beyond 2^53-1", settop("version", 2**53)),
    ("version a string", settop("version", "1")),
    ("schemaVersion wrong", settop("schemaVersion", "planeon.internal.evolution-surface/v2")),
    ("surfaceId upper case", settop("surfaceId", "Harness-Onion")),
    ("surfaceId with a trailing newline", settop("surfaceId", "harness-onion\n")),
    ("operations reordered", settop("operations", ["generate", "propose", "test", "approve", "activate"])),
    ("top-level member unknown", settop("note", "x")),
    ("programme level missing", _drop_programme),
    ("coverage skip set missing", _drop_skip),
    ("coverage skip names '..'", skipset(lambda skip: skip["rootNames"].append(".."))),
    ("coverage skip member unknown", skipset(lambda skip: skip.__setitem__("followLinks", False))),
    ("product roles empty", _empty_product_roles),
]

VALID_VARIANTS = [
    ("the record as committed", no_change),
    (
        "a human tester approves with twoPerson",
        both(
            addop("programme", "CONTRACT_AND_SOURCE", "test", OWN),
            setc("programme", "CONTRACT_AND_SOURCE", "twoPerson", True),
        ),
    ),
    ("C13 declined", droppath("GATE_VERIFIER_DOCS", E("docs/alpha-2/CREDENTIAL_ORDERING_REPAIR.md"))),
    (
        "C5 declined with its review directories",
        both(
            droppath("GATE_VERIFIER_DOCS", E("docs/TRUSTED_RUNNER_CONTRACT.md")),
            droppath("GATE_VERIFIER_DOCS", E("docs/alpha-2/CI_CAPACITY_EXCEPTION.md")),
            droppath("GATE_VERIFIER_DOCS", P("docs/linux-runner/")),
            droppath("GATE_REVIEW_BRIEF", U("docs/linux-runner/", "REVIEW_BRIEF*.md")),
            droppath("GATE_REVIEW_RECORD", U("docs/linux-runner/", "review-round*.json")),
        ),
    ),
]


@pytest.mark.parametrize("name,code,mutator", NON_SHAPE_BREAKS, ids=[n for n, _c, _m in NON_SHAPE_BREAKS])
def test_invariant_break_is_refused_with_its_code(name, code, mutator):
    assert refusal(es.check, mutated(mutator)) == code


@pytest.mark.parametrize("name,code,mutator", NON_SHAPE_BREAKS, ids=[n for n, _c, _m in NON_SHAPE_BREAKS])
def test_schema_accepts_every_non_shape_break(name, code, mutator):
    assert VALIDATOR.is_valid(mutated(mutator))


def test_every_code_from_shape_to_independent_evidence_is_exercised():
    codes = {code for _n, code, _m in NON_SHAPE_BREAKS} | {"SHAPE"}
    assert codes == set(es.CODES) - {"COVERAGE"}


@pytest.mark.parametrize("name,mutator", SHAPE_FAULTS, ids=[n for n, _m in SHAPE_FAULTS])
def test_shape_fault_is_refused_as_shape(name, mutator):
    assert refusal(es.check, mutated(mutator)) == "SHAPE"


@pytest.mark.parametrize("name,mutator", SHAPE_FAULTS, ids=[n for n, _m in SHAPE_FAULTS])
def test_schema_rejects_every_shape_fault(name, mutator):
    assert not VALIDATOR.is_valid(mutated(mutator))


@pytest.mark.parametrize("value", [[], "record", None, 1], ids=["list", "string", "null", "number"])
def test_a_record_that_is_not_an_object_is_shape(value):
    assert not VALIDATOR.is_valid(value)
    assert refusal(es.check, value) == "SHAPE"


@pytest.mark.parametrize("name,mutator", VALID_VARIANTS, ids=[n for n, _m in VALID_VARIANTS])
def test_valid_variants_pass_check_and_schema(name, mutator):
    rec = mutated(mutator)
    assert VALIDATOR.is_valid(rec)
    out = es.check(rec)
    assert set(out) == {"digest", "gateMaterial"}
    assert out["digest"] == "sha256:" + hashlib.sha256(jcs(rec)).hexdigest()
    assert out["gateMaterial"] == es.derive_gate_material(rec)


ORDER_CASES = [
    (
        "SHAPE before DUPLICATE_ID",
        both(append_to("programme", "roles", lambda rec: clone(role(rec, "programme", OWN))), settop("version", 0)),
        "SHAPE",
    ),
    (
        "DUPLICATE_ID before UNKNOWN_REFERENCE",
        both(
            append_to("programme", "roles", lambda rec: clone(role(rec, "programme", OWN))),
            addop("product", "PROMPT", "propose", "GHOST_AGENT"),
        ),
        "DUPLICATE_ID",
    ),
    (
        "a programme NEVER_AUTONOMOUS before a product INDEPENDENT_EVIDENCE",
        both(setop("product", "PROMPT", "test", [EVO]), addop("programme", "VERIFIER_BUNDLE", "activate", MON)),
        "NEVER_AUTONOMOUS",
    ),
    (
        "a programme SELF_GOVERNANCE before a product TWO_PERSON",
        both(setc("product", "PROMPT", "twoPerson", True), setc("programme", "ROADMAP_SCOPE", "governs", [OWN])),
        "SELF_GOVERNANCE",
    ),
    (
        "APPEND_ONLY before INDEPENDENCE",
        both(
            addop("programme", "ORACLE_TESTS", "generate", LS),
            setc("programme", "CONTRACT_AND_SOURCE", "appendOnly", True),
        ),
        "APPEND_ONLY",
    ),
    (
        "PATHS before a product INDEPENDENT_EVIDENCE",
        both(setop("product", "PROMPT", "test", [EVO]), addpath("GATE_SCHEMAS", P("templates/"))),
        "PATHS",
    ),
]


@pytest.mark.parametrize("name,mutator,code", ORDER_CASES, ids=[n for n, _m, _c in ORDER_CASES])
def test_first_rule_broken_in_code_order_across_the_whole_record(name, mutator, code):
    assert refusal(es.check, mutated(mutator)) == code


# --------------------------------------------------------------------------- 4. I-JSON, canonical bytes, digest

BAD_IJSON = [
    ("duplicate member", '{"a": 1, "a": 2}'),
    ("nested duplicate member", '{"x": {"k": 1, "k": 1}}'),
    ("NaN", '{"a": NaN}'),
    ("Infinity", "[Infinity]"),
    ("minus Infinity", "[-Infinity]"),
    ("lone high surrogate", '["\\ud800"]'),
    ("lone low surrogate", '["\\udc00"]'),
    ("lone surrogate in a key", '{"\\ud83d": 1}'),
    ("high surrogate before a letter", '["\\ud83dA"]'),
    ("reversed surrogate pair", '["\\ude00\\ud83d"]'),
    ("not JSON", '{"a": '),
]


@pytest.mark.parametrize("name,text", BAD_IJSON, ids=[n for n, _t in BAD_IJSON])
def test_load_refuses_non_ijson_as_shape(name, text):
    assert refusal(es.load, text) == "SHAPE"
    assert refusal(es.load, text.encode("utf-8")) == "SHAPE"


def test_load_refuses_invalid_utf8_as_shape():
    assert refusal(es.load, b'["\xff"]') == "SHAPE"


def test_load_accepts_ijson():
    assert es.load('["\\ud83d\\ude00"]') == ["\U0001f600"]
    assert es.load(b'{"a": [1, true, null, "\xc3\xa9"]}') == {"a": [1, True, None, chr(0xE9)]}
    assert es.load(RECORD_FILE.read_bytes()) == RECORD
    assert es.load(RECORD_FILE.read_text(encoding="utf-8")) == RECORD


def test_canonical_bytes_are_rfc8785():
    assert es.canonical({"b": 1, "a": [True, False, None, "x"]}) == b'{"a":[true,false,null,"x"],"b":1}'
    e_acute = chr(0xE9)
    assert es.canonical([chr(0x1F) + '"' + chr(0x5C) + "\n\t" + e_acute]) == (
        b'["\\u001f\\"\\\\\\n\\t' + e_acute.encode("utf-8") + b'"]'
    )
    assert es.canonical({"n": -(2**53 - 1)}) == b'{"n":-9007199254740991}'
    assert es.canonical(RECORD) == jcs(RECORD)


def test_canonical_sorts_member_names_by_utf16_code_units():
    # RFC 8785 section 3.2.3: names are compared as arrays of UTF-16 code units.
    # U+1F600 is the pair D83D DE00, which sorts before the single unit E000.
    private_use, astral = chr(0xE000), chr(0x1F600)
    expected = ("{" + json.dumps(astral, ensure_ascii=False) + ":2," + json.dumps(private_use, ensure_ascii=False)
                + ":1}").encode("utf-8")
    assert jcs({private_use: 1, astral: 2}) == expected
    assert es.canonical({private_use: 1, astral: 2}) == expected


def test_digest_is_sha256_of_the_canonical_bytes():
    assert es.digest({"k": ["v", 1]}) == "sha256:" + hashlib.sha256(b'{"k":["v",1]}').hexdigest()
    expected = "sha256:" + hashlib.sha256(jcs(RECORD)).hexdigest()
    assert es.digest(record()) == expected
    assert es.check(record())["digest"] == expected


# --------------------------------------------------------------------------- 5. paths

HISTORICAL_REVIEW_FILES = [
    "architecture/host-interface-inputs/independent-review.json",
    "architecture/host-interface-inputs/resolution-review-round1.json",
    "architecture/observation-enforcement-inputs/design-review.json",
    "architecture/factory-diagnostics-inputs/c7-review.json",
    "architecture/factory-diagnostics-inputs/c7-review.md",
]

PATH_CASES = [
    # the design's named cases
    ("conftest.py", "GATE_CI"),
    ("tests/conftest.py", "CONTRACT_AND_SOURCE"),
    ("pyproject.toml", "GATE_CI"),
    ("tests/test_evolution_surface_oracle.py", "ORACLE_TESTS"),
    ("architecture/evolution-surface/review-round1.json", "GATE_REVIEW_RECORD"),
    ("legal/license-policy-amendment/review-round1.json", "GATE_REVIEW_RECORD"),
    ("docs/alpha-2/CREDENTIAL_ORDERING_REPAIR.md", "GATE_VERIFIER_DOCS"),
    # an exact entry wins over a matching prefix
    ("docs/alpha-2/OWNER_OPERATED_VERIFIER.md", "GATE_VERIFIER_DOCS"),
    ("docs/TRUSTED_RUNNER_CONTRACT.md", "GATE_VERIFIER_DOCS"),
    ("docs/alpha-2/CI_CAPACITY_EXCEPTION.md", "GATE_VERIFIER_DOCS"),
    ("docs/TRUSTED_LIVE_CAMPAIGN_RUNNER_CONTRACT.md", "GATE_VERIFIER_DOCS"),
    ("scripts/zero_bill_scan.py", "GATE_POLICIES"),
    ("scripts/check_release_lock.py", "GATE_POLICIES"),
    ("scripts/build_release_lock.py", "GATE_POLICIES"),
    ("scripts/evolution_surface.py", "EVOLUTION_SURFACE"),
    ("release/evidence-policy.yaml", "GATE_POLICIES"),
    ("release/repos.lock.json", "GATE_POLICIES"),
    ("architecture/evolution-surface-authority.json", "EVOLUTION_SURFACE"),
    # data neighbours of the gate entries
    ("scripts/validate_evolution_surface.py", "CONTRACT_AND_SOURCE"),
    ("tests/test_evolution_surface.py", "CONTRACT_AND_SOURCE"),
    ("release/other.json", "CONTRACT_AND_SOURCE"),
    ("docs/alpha-2/OTHER.md", "CONTRACT_AND_SOURCE"),
    ("architecture/x-authority.json", "CONTRACT_AND_SOURCE"),
    ("task-packets/x.yaml", "CONTRACT_AND_SOURCE"),
    ("docs/README.md", "CONTRACT_AND_SOURCE"),
    ("scripts/sub/evolution_surface.py", "CONTRACT_AND_SOURCE"),
    # the longest directory wins
    ("docs/harnesses/trust.governance-agentops.md", "GATE_HARNESS_DOCS"),
    ("docs/linux-runner/setup.md", "GATE_VERIFIER_DOCS"),
    ("tests/fixtures/zero-bill/case.json", "GATE_POLICIES"),
    ("tests/fixtures/zero-bill/test_scan_oracle.py", "GATE_POLICIES"),
    ("tests/fixtures/other/case.json", "CONTRACT_AND_SOURCE"),
    ("architecture/evolution-surface/README.md", "EVOLUTION_SURFACE"),
    ("architecture/evolution-surface/vectors.json", "EVOLUTION_SURFACE"),
    # at an equal length an under-plus-name entry beats a prefix
    ("tests/test_x_oracle.py", "ORACLE_TESTS"),
    ("architecture/foo/review-round3.json", "REVIEW_RECORD"),
    ("architecture/foo/REVIEW_BRIEF.md", "REVIEW_BRIEF"),
    ("architecture/foo/REVIEW_BRIEF_round2.md", "REVIEW_BRIEF"),
    ("architecture/evolution-surface/REVIEW_BRIEF.md", "GATE_REVIEW_BRIEF"),
    ("ci/review-round1.json", "GATE_REVIEW_RECORD"),
    ("ci/REVIEW_BRIEF.md", "GATE_REVIEW_BRIEF"),
    (".github/review-round1.json", "GATE_REVIEW_RECORD"),
    ("tests/fixtures/zero-bill/review-round2.json", "GATE_REVIEW_RECORD"),
    ("docs/harnesses/review-round1.json", "GATE_REVIEW_RECORD"),
    ("docs/linux-runner/REVIEW_BRIEF.md", "GATE_REVIEW_BRIEF"),
    # matching is at any depth, on the file name only
    ("tests/a/b/test_deep_oracle_check.py", "ORACLE_TESTS"),
    ("architecture/a/b/c/review-round12.json", "REVIEW_RECORD"),
    ("legal/a/b/review-round1.json", "GATE_REVIEW_RECORD"),
    ("policies/a/b/REVIEW_BRIEF.md", "GATE_REVIEW_BRIEF"),
    ("architecture/evolution-surface/round1/review-round1.json", "GATE_REVIEW_RECORD"),
    ("tests/oracle/test_plain.py", "CONTRACT_AND_SOURCE"),
    ("tests/test_oracle_dir/helper.py", "CONTRACT_AND_SOURCE"),
    # matching is case-sensitive
    ("architecture/foo/review-round1.JSON", "CONTRACT_AND_SOURCE"),
    ("architecture/foo/Review-Round1.json", "CONTRACT_AND_SOURCE"),
    ("tests/test_x_ORACLE.py", "CONTRACT_AND_SOURCE"),
    ("Conftest.py", None),
    ("readme.md", None),
    ("Docs/x.md", None),
    # whole components only
    ("cix/tool.py", None),
    ("docs/harnessesx/a.md", "CONTRACT_AND_SOURCE"),
    ("sub/conftest.py", None),
    # repository root
    ("README.md", "REPOSITORY_ROOT"),
    (".gitignore", "REPOSITORY_ROOT"),
    ("uv.lock", "REPOSITORY_ROOT"),
    ("LICENSE", "GATE_LEGAL"),
    ("NOTICE", "GATE_LEGAL"),
    ("AGENTS.md", "GATE_POLICIES"),
    ("BILLING_POLICY.md", "GATE_POLICIES"),
    (".github/workflows/offline.yml", "GATE_CI"),
    ("ci/parallel_suite.py", "GATE_CI"),
    ("schemas/x.schema.json", "GATE_SCHEMAS"),
    # a new top-level file or directory is no class
    ("NEW_TOP_LEVEL.md", None),
    ("newdir/file.txt", None),
] + [(path, "CONTRACT_AND_SOURCE") for path in HISTORICAL_REVIEW_FILES]


def test_oracle_resolver_reproduces_the_pinned_cases():
    for path, expected in PATH_CASES:
        assert design_resolve(DESIGN_PATHS, path) == expected, path


@pytest.mark.parametrize("path,expected", PATH_CASES, ids=[p for p, _e in PATH_CASES])
def test_resolve(path, expected):
    assert es.resolve(record(), path) == expected


def small_record():
    def cls(cid, paths):
        return {
            "id": cid,
            "description": "Synthetic class for the path rules.",
            "neverAutonomous": False,
            "appendOnly": False,
            "twoPerson": False,
            "approvalBinding": "CONTENT",
            "governs": [],
            "independentOf": [],
            "operations": {
                "propose": ["DEV"],
                "generate": ["DEV"],
                "test": ["CHECKER"],
                "approve": ["MON", "OWNER"],
                "activate": ["MON", "OWNER"],
            },
            "grounds": ["oracle synthetic record"],
            "paths": paths,
        }

    return {
        "schemaVersion": "planeon.internal.evolution-surface/v1",
        "surfaceId": "oracle-synthetic",
        "version": 1,
        "operations": list(OPS),
        "levels": {
            "product": {
                "roles": [
                    {"id": "MAKER", "kind": "AGENT", "plane": "Execution", "description": "Synthetic generator."},
                    {"id": "JUDGE", "kind": "SERVICE", "plane": "Trust", "description": "Synthetic evaluator."},
                    {"id": "PERSON", "kind": "HUMAN", "plane": "Trust", "description": "Synthetic approver."},
                    {"id": "RUNNER", "kind": "SERVICE", "plane": "Runtime", "description": "Synthetic activator."},
                ],
                "classes": [
                    {
                        "id": "ARTIFACT",
                        "description": "Synthetic evolvable artifact.",
                        "neverAutonomous": False,
                        "appendOnly": False,
                        "twoPerson": False,
                        "approvalBinding": "CONTENT",
                        "governs": [],
                        "independentOf": [],
                        "operations": {
                            "propose": ["MAKER"],
                            "generate": ["MAKER"],
                            "test": ["MAKER", "JUDGE"],
                            "approve": ["PERSON"],
                            "activate": ["RUNNER"],
                        },
                        "grounds": ["oracle synthetic record"],
                    }
                ],
            },
            "programme": {
                "roles": [
                    {"id": "DEV", "kind": "AGENT", "description": "Synthetic author."},
                    {"id": "MON", "kind": "AGENT", "description": "Synthetic merger."},
                    {"id": "OWNER", "kind": "HUMAN", "description": "Synthetic owner."},
                    {"id": "CHECKER", "kind": "SERVICE", "description": "Synthetic verifier."},
                ],
                "classes": [
                    cls("WIDE", [P("zz/")]),
                    cls("MD_FILES", [U("zz/", "*.md")]),
                    cls("A_FILES", [U("zz/", "a*")]),
                    cls("PINNED", [E("zz/apex.md")]),
                    cls("DEEP", [P("zz/deep/")]),
                    cls("DEEP_MD", [U("zz/deep/", "*.md")]),
                ],
                "coverageSkip": clone(RECORD["levels"]["programme"]["coverageSkip"]),
            },
        },
    }


SYNTHETIC_CASES = [
    ("zz/abc.md", None),  # two under entries of equal length still match: no class
    ("zz/sub/abc.md", None),
    ("zz/b.md", "MD_FILES"),
    ("zz/abc.txt", "A_FILES"),
    ("zz/b.txt", "WIDE"),
    ("zz/apex.md", "PINNED"),  # an exact entry wins over the otherwise ambiguous pair
    ("zz/deep/abc.md", "DEEP_MD"),  # the longest directory, then under beats prefix
    ("zz/deep/b.txt", "DEEP"),
    ("zz/deep/q/abc.md", "DEEP_MD"),
    ("zz/B.MD", "WIDE"),
    ("zz/Abc.md", "MD_FILES"),
    ("zz/deep/A.MD", "DEEP"),
    ("top.md", None),
    ("zzz/a.md", None),
]


def test_synthetic_record_is_valid():
    rec = small_record()
    assert VALIDATOR.is_valid(rec)
    out = es.check(rec)
    assert out["gateMaterial"] == []
    assert out["digest"] == "sha256:" + hashlib.sha256(jcs(rec)).hexdigest()
    assert es.derive_gate_material(rec) == []
    assert es.decide(rec, "product", "PERSON", "ARTIFACT", "approve") == {"decision": "ALLOWED", "reasons": []}


@pytest.mark.parametrize("path,expected", SYNTHETIC_CASES, ids=[p for p, _e in SYNTHETIC_CASES])
def test_resolve_on_the_synthetic_record(path, expected):
    rec = small_record()
    by_class = {c["id"]: c["paths"] for c in rec["levels"]["programme"]["classes"]}
    assert design_resolve(by_class, path) == expected
    assert es.resolve(rec, path) == expected


def test_ambiguous_path_gives_no_approvers():
    rec = small_record()
    assert es.pr_approvers(rec, ["zz/abc.md"]) is None
    assert es.pr_activators(rec, ["zz/abc.md"]) is None
    assert es.pr_approvers(rec, ["zz/b.md"]) == ["MON", "OWNER"]


# --------------------------------------------------------------------------- 6. PR approvers and activators

LM_OWNER = [MON, OWN]
OWNER_ONLY = [OWN]

PACKET_PATHS = [
    "architecture/evolution-surface/README.md",
    "architecture/evolution-surface/evolution-surface.schema.json",
    "architecture/evolution-surface/evolution-surface.json",
    "architecture/evolution-surface/vectors.json",
    "architecture/evolution-surface/status.json",
    "architecture/evolution-surface/REVIEW_BRIEF.md",
    "architecture/evolution-surface/review-round1.json",
    "architecture/evolution-surface/round1/REVIEW_BRIEF.md",
    "architecture/evolution-surface-authority.json",
    "scripts/evolution_surface.py",
    "scripts/validate_evolution_surface.py",
    "tests/test_evolution_surface.py",
    "tests/test_validate_evolution_surface.py",
    "tests/test_evolution_surface_oracle.py",
    "task-packets/evolution-surface-001.yaml",
    "docs/CURRENT_CHECKPOINT.md",
]

PR_ROWS = [
    (
        "data-only paths",
        ["scripts/tool.py", "docs/notes.md", "README.md", "tests/test_tool.py", "architecture/x-authority.json"],
        LM_OWNER,
        LM_OWNER,
    ),
    ("a ci file with a test", ["ci/parallel_suite.py", "tests/test_parallel_suite.py"], OWNER_ONLY, LM_OWNER),
    ("the root conftest alone", ["conftest.py"], OWNER_ONLY, LM_OWNER),
    ("this packet's own paths", PACKET_PATHS, OWNER_ONLY, LM_OWNER),
    ("the oracle tests alone", ["tests/test_evolution_surface_oracle.py"], LM_OWNER, LM_OWNER),
    ("a rename from data to gate", ["docs/notes/policy.md", "policies/policy.md"], OWNER_ONLY, LM_OWNER),
    ("a rename from gate to data", ["docs/harnesses/old.md", "docs/old.md"], OWNER_ONLY, LM_OWNER),
    ("the tests conftest alone", ["tests/conftest.py"], LM_OWNER, LM_OWNER),
    ("a new top-level file", ["NEW_TOP_LEVEL.md"], None, None),
    ("a new top-level file among data paths", ["README.md", "NEW_TOP_LEVEL.md"], None, None),
    ("a rename into no class", ["docs/notes.md", "newdir/notes.md"], None, None),
    ("no changed paths", [], None, None),
]


@pytest.mark.parametrize("name,paths,approvers,activators", PR_ROWS, ids=[n for n, *_rest in PR_ROWS])
def test_pr_approvers_and_activators(name, paths, approvers, activators):
    rec = record()
    assert es.pr_approvers(rec, list(paths)) == approvers
    assert es.pr_activators(rec, list(paths)) == activators


def test_pr_result_does_not_depend_on_path_order():
    rec = record()
    paths = ["README.md", "conftest.py", "tests/test_evolution_surface_oracle.py"]
    assert es.pr_approvers(rec, paths) == es.pr_approvers(rec, list(reversed(paths))) == OWNER_ONLY
    assert es.pr_activators(rec, paths) == es.pr_activators(rec, list(reversed(paths))) == LM_OWNER


# --------------------------------------------------------------------------- 7. the derivation


def test_candidate_entry_counts_match_the_design():
    counts = {cid: len(entries) for cid, entries in CANDIDATES.items()}
    assert counts == {
        "C1": 1,
        "C2": 1,
        "C3": 1,
        "C4": 2,
        "C5": 3,
        "C6": 1,
        "C7": 2,
        "C8": 1,
        "C9": 1,
        "C10": 1,
        "C11": 2,
        "C12": 1,
        "C13": 1,
    }
    assert sum(counts.values()) == 18
    assert len(PA_D5) == 6 and len(OWN_THREE) == 3


def test_gate_material_is_pa_d5_plus_exactly_the_accepted_21():
    accepted = OWN_THREE + [entry for entries in CANDIDATES.values() for entry in entries]
    # MET-GOV-002: version 1's accepted 21 stay; record version 2 adds the accepted group RR2: 31 entries, 25 more.
    assert len(accepted) == 21
    accepted = accepted + RR2
    expected = sorted(PA_D5 + accepted, key=jcs)
    assert len(expected) == 31 and len({jcs(e) for e in expected}) == 31  # MET-GOV-002: was 27
    got = es.derive_gate_material(record())
    assert got == expected
    assert [jcs(e) for e in got] == sorted(jcs(e) for e in got)
    difference = [e for e in got if e not in PA_D5]
    assert sorted(difference, key=jcs) == sorted(accepted, key=jcs)
    assert len(difference) == 25  # MET-GOV-002: was 21
    assert es.check(record())["gateMaterial"] == expected


def test_a_declined_candidate_returns_to_data():
    rec = mutated(droppath("GATE_VERIFIER_DOCS", E("docs/alpha-2/CREDENTIAL_ORDERING_REPAIR.md")))
    got = es.derive_gate_material(rec)
    assert len(got) == 30  # MET-GOV-002: version 2's 31 less the declined entry (was 26 of 27)
    assert E("docs/alpha-2/CREDENTIAL_ORDERING_REPAIR.md") not in got
    assert es.resolve(rec, "docs/alpha-2/CREDENTIAL_ORDERING_REPAIR.md") == "CONTRACT_AND_SOURCE"


def test_review_directories_follow_the_gate_prefixes():
    rec = mutated(dict(VALID_VARIANTS)["C5 declined with its review directories"])
    got = es.derive_gate_material(rec)
    assert len(got) == 28  # MET-GOV-002: version 2's 31 less C5's three entries (was 24 of 27)
    assert P("docs/linux-runner/") not in got
    assert es.resolve(rec, "docs/linux-runner/review-round1.json") == "CONTRACT_AND_SOURCE"


# MET-GOV-002: record version 2's four entries and their resolutions (DESIGN sections 8 and 12; the amended
# README's class table). The case variant falls in no class by F1 (owner Q-GOV-CAP), a model rule that the
# oracle's design resolver does not restate, so only the model is asked for it.
RR2_RESOLUTIONS = [
    ("architecture/review-record/README.md", "GATE_REVIEW_PROCESS"),
    ("architecture/review-record/review-round1.json", "GATE_REVIEW_RECORD"),
    ("architecture/review-record/REVIEW_BRIEF.md", "GATE_REVIEW_BRIEF"),
    ("tests/test_review_record_oracle.py", "ORACLE_TESTS"),
    ("tests/test_review_record.py", "CONTRACT_AND_SOURCE"),
    ("architecture/review-record-authority.json", "GATE_REVIEW_PROCESS"),
    ("scripts/review_record.py", "GATE_REVIEW_PROCESS"),
    ("tests/test_review_records_in_tree.py", "GATE_REVIEW_PROCESS"),
    ("architecture/review-record/oracle-identity.json", "GATE_REVIEW_PROCESS"),
    ("architecture/review-record/review-identity-round1.json", "GATE_REVIEW_PROCESS"),
    ("architecture/review-record/briefs.json", "GATE_REVIEW_PROCESS"),
]
RR2_CASE_VARIANT = "tests/Test_review_records_in_tree.py"


def test_record_version_2_pins_the_four_gate_review_process_entries():
    rec = record()
    assert klass(rec, "programme", "GATE_REVIEW_PROCESS") == GATE_REVIEW_PROCESS_OBJECT
    assert DESIGN_PATHS["GATE_REVIEW_PROCESS"] == RR2 == GATE_REVIEW_PROCESS_OBJECT["paths"]
    assert [c["id"] for c in rec["levels"]["programme"]["classes"]].count("GATE_REVIEW_PROCESS") == 1
    for cid in ("GATE_REVIEW_BRIEF", "GATE_REVIEW_RECORD"):
        name = "REVIEW_BRIEF*.md" if cid == "GATE_REVIEW_BRIEF" else "review-round*.json"
        assert U("architecture/review-record/", name) in klass(rec, "programme", cid)["paths"]
    for cid in ("ORACLE_TESTS", "REVIEW_RECORD", "GATE_REVIEW_RECORD"):
        assert "GATE_REVIEW_PROCESS" in klass(rec, "programme", cid)["independentOf"]
    for path, expected in RR2_RESOLUTIONS:
        assert design_resolve(DESIGN_PATHS, path) == expected, path
        assert es.resolve(rec, path) == expected, path
    assert es.resolve(rec, RR2_CASE_VARIANT) is None
    entries = [e["prefix"] + "README.md" if "prefix" in e else e["exact"] for e in RR2]
    assert es.pr_approvers(rec, entries) == [OWN]
    assert es.pr_activators(rec, entries) == [MON, OWN]
    assert es.decide(rec, "programme", MON, "GATE_REVIEW_PROCESS", "approve") == {
        "decision": "DENIED",
        "reasons": ["NOT_LISTED", "SELF_GOVERNANCE"],
    }
    assert design_decision("programme", MON, "GATE_REVIEW_PROCESS", "approve") == es.decide(
        rec, "programme", MON, "GATE_REVIEW_PROCESS", "approve"
    )


# --------------------------------------------------------------------------- 8. coverage

SKIP_CASES = [
    (".git", True),
    (".git/HEAD", True),
    (".git/objects/ab/cdef", True),
    (".github/workflows/w.yml", False),
    (".gitignore", False),
    (".gitx/y", False),
    ("sub/.git/HEAD", False),
    ("sub/.git", False),
    (".venv/bin/tool", True),
    ("sub/.venv/cfg", False),
    (".venvx/y", False),
    ("__pycache__/notes.txt", True),
    ("scripts/__pycache__/notes.txt", True),
    ("a/b/__pycache__/c/d.txt", True),
    ("__pycache__x/k.py", False),
    ("x__pycache__/k.py", False),
    (".pytest_cache/v/cache", True),
    ("a/.pytest_cache/x", True),
    ("a/.pytest_cache_old/x", False),
    ("a/.ruff_cache/x", True),
    (".mypy_cache/x", True),
    ("m.pyc", True),
    ("a/m.pyc", True),
    ("a/b/m.pyo", True),
    ("a/m.pyd", True),
    ("a/m.py", False),
    ("a/m.pyx", False),
    ("a/m.pyc.txt", False),
    (".DS_Store", True),
    ("a/.DS_Store", True),
    ("a/.DS_Store.bak", False),
    ("a/x.DS_Store", False),
    ("README.md", False),
]


@pytest.mark.parametrize("path,expected", SKIP_CASES, ids=[p for p, _e in SKIP_CASES])
def test_skipped(path, expected):
    assert es.skipped(record(), path) is expected


TREE_FILES = [
    "a.txt",
    ".git",
    ".gitignore",
    ".gitx/y",
    ".github/workflows/w.yml",
    ".venv/bin/tool",
    ".venvx/y",
    ".DS_Store",
    "x/m.py",
    "x/m.pyc",
    "x/m.pyo",
    "x/m.pyd",
    "x/m.pyx",
    "x/m.pyc.txt",
    "x/.DS_Store",
    "x/.DS_Store.bak",
    "x/__pycache__/m.cpython-312.pyc",
    "x/__pycache__/notes.txt",
    "x/.git/HEAD",
    "x/.venv/cfg",
    "__pycache__/r.txt",
    "__pycache__x/k.py",
    ".pytest_cache/v/cache/nodeids",
    "deep/a/.ruff_cache/z",
    "deep/a/.mypy_cache/z",
    "deep/a/.pytest_cache_old/z",
]
TREE_KEPT = sorted(
    [
        "a.txt",
        ".gitignore",
        ".gitx/y",
        ".github/workflows/w.yml",
        ".venvx/y",
        "x/m.py",
        "x/m.pyx",
        "x/m.pyc.txt",
        "x/.DS_Store.bak",
        "x/.git/HEAD",
        "x/.venv/cfg",
        "__pycache__x/k.py",
        "deep/a/.pytest_cache_old/z",
    ]
)


def test_tree_paths_applies_the_skip_set_by_whole_components(scratch):
    make_files(scratch, TREE_FILES)
    assert es.tree_paths(record(), scratch) == TREE_KEPT


def test_tree_paths_skips_a_git_directory_at_the_root(scratch):
    make_files(scratch, [".git/HEAD", ".git/objects/ab/cdef", "README.md"])
    assert es.tree_paths(record(), scratch) == ["README.md"]


def test_tree_paths_never_follows_links(scratch):
    root, outside = scratch / "root", scratch / "outside"
    make_files(root, ["docs/real.md"])
    make_files(outside, ["stray.txt", "deep/more.txt"])
    os.symlink(outside, root / "docs" / "ext", target_is_directory=True)
    os.symlink(".", root / "docs" / "loop", target_is_directory=True)
    got = es.tree_paths(record(), root)
    assert "docs/real.md" in got
    assert [p for p in got if p.startswith(("docs/ext/", "docs/loop/"))] == []
    assert [p for p in got if p.endswith(("stray.txt", "more.txt"))] == []


CLASSIFIED_TREE = [
    "README.md",
    "ci/tool.py",
    ".github/workflows/offline.yml",
    "docs/a.md",
    "tests/test_x_oracle.py",
    ".git",
    ".venv/bin/tool",
    "scripts/__pycache__/m.cpython-312.pyc",
    "scripts/m.pyc",
    ".DS_Store",
    "docs/.DS_Store",
    ".pytest_cache/v/x",
    "architecture/.mypy_cache/x",
    "architecture/.ruff_cache/x",
]


def test_check_coverage_passes_on_a_classified_tree(scratch):
    make_files(scratch, CLASSIFIED_TREE)
    es.check_coverage(record(), scratch)


# "Legal/x.md": a case variant with no lower-case twin in the tree, so that a
# case-insensitive file system cannot fold it into an existing directory.
@pytest.mark.parametrize("extra", ["stray.txt", "sub/.git/HEAD", "__pycache__x/k.py", ".gitx/y", "Legal/x.md"])
def test_check_coverage_refuses_an_unclassified_file(scratch, extra):
    make_files(scratch, CLASSIFIED_TREE + [extra])
    assert refusal(es.check_coverage, record(), scratch) == "COVERAGE"


def test_check_coverage_refuses_an_ambiguous_file(scratch):
    make_files(scratch, ["zz/b.md", "zz/abc.md"])
    assert refusal(es.check_coverage, small_record(), scratch) == "COVERAGE"


def test_check_coverage_passes_on_the_synthetic_record(scratch):
    make_files(scratch, ["zz/b.md", "zz/deep/x.txt", "zz/apex.md", "zz/abc.txt"])
    es.check_coverage(small_record(), scratch)


def test_coverage_report():
    cov = es.coverage(record(), ["README.md", "ci/x.py", "NEW_TOP_LEVEL.md"])
    assert set(cov) == {"files", "unclassified", "ambiguous", "perClass"}
    assert sorted(cov["unclassified"]) == ["NEW_TOP_LEVEL.md"]
    assert list(cov["ambiguous"]) == []
    synthetic = es.coverage(small_record(), ["zz/abc.md", "zz/b.md", "top.md"])
    assert "zz/abc.md" in synthetic["ambiguous"]
    assert "top.md" in synthetic["unclassified"]
    assert "zz/b.md" not in synthetic["ambiguous"] and "zz/b.md" not in synthetic["unclassified"]


def test_the_worktree_is_covered():
    rec = record()
    es.check_coverage(rec, ROOT)
    paths = es.tree_paths(rec, ROOT)
    assert paths == sorted(paths)
    assert THIS_FILE in paths
    assert ".git" not in paths and not [p for p in paths if p.startswith(".git/")]
    assert [p for p in paths if p.startswith(".github/")]
    assert not [p for p in paths if "__pycache__" in p.split("/")]
    cov = es.coverage(rec, paths)
    assert list(cov["unclassified"]) == [] and list(cov["ambiguous"]) == []
    mismatches = []
    for path in paths:
        got, want = es.resolve(rec, path), design_resolve(DESIGN_PATHS, path)
        if got != want:
            mismatches.append((path, got, want))
    assert mismatches == []


# --------------------------------------------------------------------------- 9. requests

UNKNOWN_REQUESTS = [
    ("unknown role", ("product", "GHOST_AGENT", "PROMPT", "approve")),
    ("unknown class", ("product", EVO, "NO_SUCH_CLASS", "generate")),
    ("unknown operation", ("product", EVO, "PROMPT", "delete")),
    ("unknown level", ("galaxy", EVO, "PROMPT", "generate")),
    ("programme role at product level", ("product", MON, "PROMPT", "approve")),
    ("product class at programme level", ("programme", MON, "PROMPT", "approve")),
    ("product role at programme level", ("programme", EVO, "GATE_CI", "generate")),
]


@pytest.mark.parametrize("name,request_args", UNKNOWN_REQUESTS, ids=[n for n, _r in UNKNOWN_REQUESTS])
def test_unknown_names_in_a_request_are_unknown_reference(name, request_args):
    assert refusal(es.decide, record(), *request_args) == "UNKNOWN_REFERENCE"


MALFORMED_PATHS = ["", "/README.md", "../README.md", "docs/../README.md", "./README.md", "docs/./x.md", "docs//x.md",
                   "docs/", 7, None]
MALFORMED_IDS = [repr(p) for p in MALFORMED_PATHS]


@pytest.mark.parametrize("path", MALFORMED_PATHS, ids=MALFORMED_IDS)
def test_resolve_refuses_a_malformed_path_as_shape(path):
    assert refusal(es.resolve, record(), path) == "SHAPE"


@pytest.mark.parametrize("path", MALFORMED_PATHS, ids=MALFORMED_IDS)
def test_pr_functions_refuse_a_malformed_path_as_shape(path):
    assert refusal(es.pr_approvers, record(), ["README.md", path]) == "SHAPE"
    assert refusal(es.pr_activators, record(), ["README.md", path]) == "SHAPE"


@pytest.mark.parametrize("path", MALFORMED_PATHS, ids=MALFORMED_IDS)
def test_skipped_refuses_a_malformed_path_as_shape(path):
    assert refusal(es.skipped, record(), path) == "SHAPE"


@pytest.mark.parametrize("path", MALFORMED_PATHS, ids=MALFORMED_IDS)
def test_coverage_refuses_a_malformed_path_as_shape(path):
    assert refusal(es.coverage, record(), ["README.md", path]) == "SHAPE"


JUDGED_FIRST = [
    ("check", lambda rec, tmp: es.check(rec)),
    ("decide", lambda rec, tmp: es.decide(rec, "product", "GHOST_AGENT", "PROMPT", "approve")),
    ("resolve", lambda rec, tmp: es.resolve(rec, "/not/relative")),
    ("pr_approvers", lambda rec, tmp: es.pr_approvers(rec, [])),
    ("pr_activators", lambda rec, tmp: es.pr_activators(rec, ["NEW_TOP_LEVEL.md"])),
    ("derive_gate_material", lambda rec, tmp: es.derive_gate_material(rec)),
    ("skipped", lambda rec, tmp: es.skipped(rec, "../x")),
    ("tree_paths", lambda rec, tmp: es.tree_paths(rec, tmp)),
    ("coverage", lambda rec, tmp: es.coverage(rec, ["NEW_TOP_LEVEL.md", ""])),
    ("check_coverage", lambda rec, tmp: es.check_coverage(rec, tmp)),
]


@pytest.mark.parametrize("name,call", JUDGED_FIRST, ids=[n for n, _c in JUDGED_FIRST])
def test_every_function_judges_the_record_first(name, call, scratch):
    make_files(scratch, ["NEW_TOP_LEVEL.md"])
    bad = mutated(setrole("product", TAP, "kind", "AGENT"))
    assert refusal(call, bad, scratch) == "NEVER_AUTONOMOUS"
    shape_bad = mutated(settop("version", 0))
    assert refusal(call, shape_bad, scratch) == "SHAPE"
