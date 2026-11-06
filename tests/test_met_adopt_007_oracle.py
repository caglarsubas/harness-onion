"""D5a oracle tests for MET-ADOPT-007 (AUTHORITY-MAP-001), slot 281: the authority map record and its validator.

Owner decision D5a: a contract packet carries black-box tests written outside the candidate, by someone who is not its
builder. Every expected value below comes from one of these sources, named in each test's docstring:
- README: the contract text, architecture/authority-map/README.md;
- DOCSTRING: the module docstring of scripts/authority_map.py (the refusal codes V0-V9 and what each guards);
- PUBLIC NAMES: the module's def names and upper-case constants (AUTHORITY_PINS, BEHAVIOUR_PINS, FLAGGED, SOURCES,
  RECONCILIATION, RIDER, TECH_BASE_MEMBERS, TECH_LIST_MEMBER, AUTHORITY_VERBS, BRIEFS_BASE_SHA256 and the vocabularies);
  no function body of the module was read;
- DATA: the record architecture/authority-map.json, its vector files budget-vectors.json and r12-vectors.json, the
  technology record architecture/language-placement.json and the registry architecture/review-record/briefs.json;
- SOURCE LINES: the repository lines the record cites, read here by exact path;
- OPERATOR: facts the operator states outside the README: check(read, packets) with packets the set of published
  packet ids (a set or frozenset; frozenset() where no later rider is in play); the result members concerns, pins,
  flagged, budgetVectors and r12Vectors; a refusal is a ValueError whose message starts with the code and a colon; V7
  compares the technology record's top-level member names with TECH_BASE_MEMBERS plus TECH_LIST_MEMBER;
- README V9 (a) and RULING (MON-282-W2-RULED item 1, as relayed): the registry is the base, then MET-ADOPT-007's one
  RIDER, then zero or more later packets' riders (RIDER with series <id>/packet, for an id in packets other than
  MET-ADOPT-007), each series once in the whole registry; anything else in the registry refuses with AM_REGISTRY.
  Tests that are not about later riders run on the base plus RIDER, the registry they were written against; the tree's
  own registry is checked with the packet ids of its later riders. (V9 (a) update, slot 282, by a non-author: R12.)
The budget reference model in this file is written from the budget file's rules B1-B5 and the cited ledger-loss line
(trust.observability-finops.md:177); it shares no code with the module. Mutations reach the module only through this
file's own read(path), which returns changed bytes in memory; nothing is patched.
"""
import copy
import hashlib
import importlib.util
import json
import re
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
MODULE_FILE = ROOT / "scripts" / "authority_map.py"
REC = "architecture/authority-map.json"
BUD = "architecture/authority-map/budget-vectors.json"
R12 = "architecture/authority-map/r12-vectors.json"
TECH = "architecture/language-placement.json"
BRIEFS = "architecture/review-record/briefs.json"
H = "docs/harnesses/"
ORCH = H + "execution.orchestration.md"
SBX = H + "execution.tool-skill-sandbox.md"
MEM = H + "knowledge.memory-state.md"
GW = H + "runtime.ai-gateway.md"
INF = H + "runtime.model-inference.md"
INFRA = H + "runtime.infrastructure.md"
GOV = H + "trust.governance-agentops.md"
FIN = H + "trust.observability-finops.md"
SEC = H + "trust.security-safety.md"
THIRTEEN = (
    "docs/adr/0005-release-evidence.md", "docs/adr/0011-h10-execution-authority.md", ORCH, SBX, MEM, GW,
    H + "runtime.experience.md", INFRA, INF, H + "trust.evaluation-assurance.md", GOV, FIN, SEC,
)
CONCERN_IDS = tuple("AM-%02d" % k for k in range(1, 10))
SLOTS = ("whenUnavailable", "whenRevoked")
ITEM = "AUTHORITY-MAP-001"
# DOCSTRING: "Refusal codes, in the order they run" (lines 10-18 of the module), as read by the oracle author.
EXPECTED_CODES = ("AM_SHAPE", "AM_SOURCES", "AM_CITATIONS", "AM_ONE_AUTHORITY", "AM_ENFORCEMENT", "AM_FAILURE_MODES",
                  "AM_BUDGET", "AM_RECONCILIATION", "AM_RECONCILIATION_UNKNOWN_MEMBER", "AM_R12_VECTORS",
                  "AM_REGISTRY")


def _load_module():
    spec = importlib.util.spec_from_file_location("authority_map_d5a_subject", MODULE_FILE)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


AM = _load_module()
DOC_CODES = tuple(dict.fromkeys(re.findall(r"\bAM_[A-Z0-9_]+\b", AM.__doc__ or "")))


def raw(path):
    return (ROOT / path).read_bytes()


def load(path):
    return json.loads(raw(path).decode("utf-8"))


def line_of(path, number):
    return raw(path).decode("utf-8").split("\n")[number - 1]


def sha(data):
    return hashlib.sha256(data).hexdigest()


def dump(value):
    return (json.dumps(value, indent=1, ensure_ascii=False) + "\n").encode("utf-8")


def replaced(data, old, new):
    assert data.count(old) == 1, (old, data.count(old))
    return data.replace(old, new)


class Stop(BaseException):
    """Raised by the reader to show that a BaseException is never caught."""


class Reader:
    """The injected byte reader: exact repository-relative paths only; overrides and failures in memory."""

    def __init__(self, overrides=None, failures=None):
        self.overrides = dict(overrides or {})
        self.failures = dict(failures or {})
        self.paths = []

    def __call__(self, path):
        if not isinstance(path, str) or path.startswith("/") or ".." in path.split("/") or not path:
            raise LookupError("not an exact repository-relative path")
        self.paths.append(path)
        if path in self.failures:
            raise self.failures[path]
        if path in self.overrides:
            return self.overrides[path]
        return (ROOT / path).read_bytes()


def run(overrides=None, packets=frozenset()):
    merged = base_plus_rider()
    merged.update(overrides or {})
    return AM.check(Reader(merged), packets)


def refusal_code(overrides, packets=frozenset()):
    with pytest.raises(ValueError) as caught:
        run(overrides, packets)
    code, colon, _ = str(caught.value).partition(":")
    assert colon == ":", str(caught.value)
    return code


def concern(rec, cid):
    return next(c for c in rec["concerns"] if c["id"] == cid)


def record_with(edit):
    rec = load(REC)
    edit(rec)
    return {REC: dump(rec)}


def repinned(path, data):
    rec = load(REC)
    hits = [v for v in rec["vectorFiles"] if v["path"] == path]
    assert len(hits) == 1
    hits[0]["sha256"] = sha(data)
    return {REC: dump(rec), path: data}


def vectors_with(path, edit):
    value = load(path)
    edit(value)
    return repinned(path, dump(value))


def tech_with(edit):
    tech = load(TECH)
    edit(tech)
    return {TECH: dump(tech)}


def registry_base():
    """The base registry: the tree's registry up to MET-ADOPT-007's RIDER (README V9 (a): the base comes first, then
    the rider, then later riders); its digest is checked against BRIEFS_BASE_SHA256 in the registry test."""
    reg = load(BRIEFS)
    if AM.RIDER in reg["briefs"]:
        reg["briefs"] = reg["briefs"][:reg["briefs"].index(AM.RIDER)]
    return reg


def registry_with(entries_edit):
    reg = registry_base()
    entries_edit(reg["briefs"])
    return {BRIEFS: dump(reg)}


def base_plus_rider():
    return registry_with(lambda entries: entries.append(copy.deepcopy(AM.RIDER)))


def later_rider(packet_id, **changes):
    """OPERATOR: a later packet's rider is RIDER with only series changed to <id>/packet."""
    return dict(copy.deepcopy(AM.RIDER), series=packet_id + "/packet", **changes)


def tree_later_ids():
    """DATA: the packet ids of the riders after MET-ADOPT-007's RIDER in the tree's registry, in order."""
    entries = load(BRIEFS)["briefs"]
    if AM.RIDER not in entries:
        return []
    rest = entries[entries.index(AM.RIDER) + 1:]
    assert all(e["series"].endswith("/packet") for e in rest)
    return [e["series"][:-len("/packet")] for e in rest]


def pending_entries():
    return [dict(entry) for entry in AM.RECONCILIATION]


def size(value):
    if isinstance(value, int) and not isinstance(value, bool):
        return value
    return len(value)


def as_citation(pin_citation):
    head, second, quote = pin_citation
    if head == "item":
        return {"item": second, "quote": quote}
    return {"path": head, "line": second, "quote": quote}


def repository_citations(rec):
    for c in rec["concerns"]:
        yield c["id"], "authority", c["authority"]["citation"]
        for point in c["enforcementPoints"]:
            yield c["id"], "enforcementPoints", point["citation"]
        for slot in SLOTS:
            yield c["id"], slot, c[slot]["citation"]
        for cited in c["citations"]:
            yield c["id"], "citations", cited


def names_of(rec, cid):
    """The authority's names: its component and every module name its cited quote gives in backticks."""
    authority = concern(rec, cid)["authority"]
    return {authority["component"]} | set(re.findall(r"`([^`]+)`", authority["citation"]["quote"]))


# ---------------------------------------------------------------------------------------------------------------
# The budget reference model (rules B1-B5 of budget-vectors.json, and the ledger-loss line finops.md:177).
# ---------------------------------------------------------------------------------------------------------------

class Unmodelled(AssertionError):
    """A step that B1-B5 and the ledger-loss line do not decide; no published vector may need one."""


def replay(root, steps):
    """Replay one vector: per-step results and each reservation's final {state, committed, returned}."""
    held = 0  # B1: the root's committed-plus-reserved counter
    book = {}
    down = False
    results = []
    for step in steps:
        op = step["op"]
        if op == "ledger_down":
            down = True
            results.append("down")
            continue
        if op == "advisory":
            # finops.md:177: advisory-only callers may proceed if the profile explicitly allows and outbox capacity exists
            if not down:
                raise Unmodelled(step)
            allowed = step["profileAllows"] is True and step["outboxCapacity"] is True
            results.append("proceeds" if allowed else "refused")
            continue
        if down:
            # finops.md:177: ledger loss blocks operations requiring hard budgets
            results.append("refused")
            continue
        key = step["key"]
        entry = book.get(key)
        if op == "reserve":
            amount = step["amount"]
            if entry is not None:
                # B3: an exact retry returns the original result; a conflicting reuse fails closed
                results.append("replayed" if entry["amount"] == amount else "refused")
                continue
            if held + amount > root:  # B1
                results.append("refused")
                continue
            book[key] = {"amount": amount, "consumed": 0, "state": "RESERVED", "committed": 0, "returned": 0,
                         "commit": None}
            held += amount
            results.append("reserved")
            continue
        if entry is None:  # B1: no work without a reservation
            results.append("refused")
            continue
        if op == "consume":
            if entry["state"] != "RESERVED" or entry["consumed"] + step["amount"] > entry["amount"]:
                raise Unmodelled(step)
            entry["consumed"] += step["amount"]
            results.append("consumed")
            continue
        if op == "commit":
            asked = (step["transition"], step["amount"])
            if entry["state"] == "COMMITTED" and entry["commit"] == asked:  # B3: exact retry of the transition
                results.append("replayed")
                continue
            if entry["state"] != "RESERVED" or step["amount"] > entry["amount"]:  # B2, B3
                results.append("refused")
                continue
            entry.update(state="COMMITTED", committed=step["amount"], returned=entry["amount"] - step["amount"],
                         commit=asked)  # B2: closes COMMITTED, returns the unconsumed remainder
            held -= entry["returned"]
            results.append("committed")
            continue
        if op in ("cancel", "expire"):
            if entry["state"] != "RESERVED":
                raise Unmodelled(step)
            used = entry["consumed"]
            if used > 0:  # B4: closes COMMITTED at c and returns the rest
                entry.update(state="COMMITTED", committed=used, returned=entry["amount"] - used)
            else:  # B4: c = 0 closes RELEASED (cancel) or EXPIRED (timeout) and returns all of it
                entry.update(state="RELEASED" if op == "cancel" else "EXPIRED", committed=0,
                             returned=entry["amount"])
            held -= entry["returned"]
            results.append("settled")
            continue
        raise Unmodelled(step)
    final = {k: {"state": e["state"], "committed": e["committed"], "returned": e["returned"]} for k, e in book.items()}
    return results, final


# ---------------------------------------------------------------------------------------------------------------
# 1. The record
# ---------------------------------------------------------------------------------------------------------------

def test_record_schema_and_nine_concerns_in_order():
    """README first paragraph: authority-map.json (planeon.internal.authority-map/v1) records one effective authority
    for each of nine concerns; DATA: concerns[].id; PUBLIC NAMES: SCHEMA, CONCERN_IDS."""
    rec = load(REC)
    assert rec["schemaVersion"] == "planeon.internal.authority-map/v1" == AM.SCHEMA
    assert [c["id"] for c in rec["concerns"]] == list(CONCERN_IDS) == list(AM.CONCERN_IDS)
    assert tuple(rec) == tuple(AM.TOP_MEMBERS)


def test_every_concern_has_one_authority_inputs_others_enforcement_and_both_behaviours():
    """README first paragraph: the boundary whose state or decision determines behaviour, the non-deciding inputs it
    relies on, what others may do, every enforcement point, and the behaviour when the authority is unavailable or
    revoked; DATA: each concern's members; PUBLIC NAMES: CONCERN_MEMBERS, ROLES, WHO_KINDS, ACTIONS, BEHAVIOURS."""
    rec = load(REC)
    for c in rec["concerns"]:
        assert tuple(c) == tuple(AM.CONCERN_MEMBERS), c["id"]
        assert isinstance(c["concern"], str) and c["concern"]
        authority = c["authority"]
        assert isinstance(authority, dict)
        assert set(authority) == {"harness", "component", "boundary", "citation"}, c["id"]
        assert all(isinstance(authority[m], str) and authority[m] for m in ("harness", "component", "boundary"))
        assert isinstance(c["inputs"], list)
        for item in c["inputs"]:
            assert set(item) == {"harness", "component", "role"} and item["role"] in AM.ROLES
        assert isinstance(c["othersMay"], list)
        for other in c["othersMay"]:
            assert set(other) == {"who", "whoKind", "action", "note"}
            assert other["whoKind"] in AM.WHO_KINDS and other["action"] in AM.ACTIONS
        assert isinstance(c["enforcementPoints"], list) and len(c["enforcementPoints"]) >= 1, c["id"]
        for point in c["enforcementPoints"]:
            assert set(point) == {"component", "point", "citation"}
        for slot in SLOTS:
            assert set(c[slot]) == {"behaviour", "note", "citation"}, (c["id"], slot)
            assert c[slot]["behaviour"] in AM.BEHAVIOURS


def test_no_input_and_no_component_row_names_the_authority():
    """DOCSTRING V3: no input and no COMPONENT row names the authority, by its component or by a module name its
    pinned quote gives, whatever the harness label; DATA: inputs and othersMay of each concern."""
    rec = load(REC)
    for cid in CONCERN_IDS:
        c = concern(rec, cid)
        names = names_of(rec, cid)
        assert not [i for i in c["inputs"] if i["component"] in names], cid
        assert not [o for o in c["othersMay"] if o["whoKind"] == "COMPONENT" and o["who"] in names], cid


def test_non_claims_are_in_the_record():
    """README "Reading the design": Non-claims are in the record's nonClaims; README Vectors: write skew, fencing and
    clocks are DATA-CORRECTNESS-001's; DATA: nonClaims of the record and of budget-vectors.json."""
    rec = load(REC)
    assert isinstance(rec["nonClaims"], list) and rec["nonClaims"]
    assert all(isinstance(text, str) and text for text in rec["nonClaims"])
    assert any("DATA-CORRECTNESS-001" in text for text in rec["nonClaims"])
    budget_claims = " ".join(load(BUD)["nonClaims"])
    for word in ("write skew", "fencing", "clock", "DATA-CORRECTNESS-001"):
        assert word in budget_claims, word


# ---------------------------------------------------------------------------------------------------------------
# 2. The 27 pins in three classes
# ---------------------------------------------------------------------------------------------------------------

def test_record_authorities_equal_the_nine_authority_pins():
    """README "The pinned semantics": every row's authority {harness, component} is bound to one citation;
    PUBLIC NAMES: AUTHORITY_PINS (value and citation); DATA: concerns[].authority."""
    rec = load(REC)
    assert set(AM.AUTHORITY_PINS) == set(CONCERN_IDS)
    for cid in CONCERN_IDS:
        harness, component, citation = AM.AUTHORITY_PINS[cid]
        authority = concern(rec, cid)["authority"]
        assert (authority["harness"], authority["component"]) == (harness, component), cid
        assert authority["citation"] == as_citation(citation), cid


def test_record_behaviours_equal_the_eighteen_behaviour_pins():
    """README "The pinned semantics": every row's two behaviours, each bound to one citation; PUBLIC NAMES:
    BEHAVIOUR_PINS (value and citation); DATA: concerns[].whenUnavailable and whenRevoked."""
    rec = load(REC)
    assert set(AM.BEHAVIOUR_PINS) == {(cid, slot) for cid in CONCERN_IDS for slot in SLOTS}
    for (cid, slot), (behaviour, citation) in AM.BEHAVIOUR_PINS.items():
        held = concern(rec, cid)[slot]
        assert held["behaviour"] == behaviour, (cid, slot)
        assert held["citation"] == as_citation(citation), (cid, slot)


def test_twenty_seven_pins_fall_in_three_classes():
    """README "The pinned semantics": 27 constants; 23 stating; 2 item-bound to AUTHORITY-MAP-001 (AM-02's revoked
    behaviour, AM-06's authority); 2 flagged, AM-06 unavailable (execution.tool-skill-sandbox.md:148) and AM-09
    revoked (runtime.infrastructure.md:196); PUBLIC NAMES: AUTHORITY_PINS, BEHAVIOUR_PINS, FLAGGED."""
    pins = {(cid, "authority"): pin[2] for cid, pin in AM.AUTHORITY_PINS.items()}
    pins.update({key: pin[1] for key, pin in AM.BEHAVIOUR_PINS.items()})
    assert len(pins) == 27
    item_bound = {key for key, citation in pins.items() if citation[0] == "item"}
    assert item_bound == {("AM-02", "whenRevoked"), ("AM-06", "authority")}
    assert all(pins[key][1] == ITEM for key in item_bound)
    assert set(AM.FLAGGED) == {("AM-06", "whenUnavailable"), ("AM-09", "whenRevoked")}
    assert pins[("AM-06", "whenUnavailable")][:2] == (SBX, 148)
    assert pins[("AM-09", "whenRevoked")][:2] == (INFRA, 196)
    stating = set(pins) - item_bound - set(AM.FLAGGED)
    assert len(stating) == 23
    assert all(isinstance(pins[key][1], int) and pins[key][0] in THIRTEEN for key in stating)


def test_the_record_alone_shows_the_three_classes():
    """README "The pinned semantics": the 2 item-bound pins cite the roadmap item; the 2 flagged pins are limits of
    the record, listed as such wherever the record is published; DATA: authority and behaviour citations, notes and
    nonClaims of the record."""
    rec = load(REC)
    pinned = {}
    for c in rec["concerns"]:
        pinned[(c["id"], "authority")] = c["authority"]["citation"]
        for slot in SLOTS:
            pinned[(c["id"], slot)] = c[slot]["citation"]
    assert {key for key, cited in pinned.items() if "item" in cited} == {("AM-02", "whenRevoked"),
                                                                           ("AM-06", "authority")}
    flagged = {(c["id"], slot) for c in rec["concerns"] for slot in SLOTS if c[slot]["note"].startswith("flagged")}
    assert flagged == {("AM-06", "whenUnavailable"), ("AM-09", "whenRevoked")}
    assert (pinned[("AM-06", "whenUnavailable")]["path"], pinned[("AM-06", "whenUnavailable")]["line"]) == (SBX, 148)
    assert (pinned[("AM-09", "whenRevoked")]["path"], pinned[("AM-09", "whenRevoked")]["line"]) == (INFRA, 196)
    limits = [text for text in rec["nonClaims"] if "flagged" in text]
    assert len(limits) == 1 and "AM-06 unavailable" in limits[0] and "AM-09 revoked" in limits[0]
    assert "nearest topical line" in limits[0]


def test_every_repository_pin_quote_is_on_its_line():
    """DOCSTRING V2: the same check runs over the pins; SOURCE LINES: each pin's cited line, read here."""
    pins = [pin[2] for pin in AM.AUTHORITY_PINS.values()] + [pin[1] for pin in AM.BEHAVIOUR_PINS.values()]
    for head, number, quote in pins:
        if head == "item":
            continue
        assert quote in line_of(head, number), (head, number)


# ---------------------------------------------------------------------------------------------------------------
# 3. Citations, independently
# ---------------------------------------------------------------------------------------------------------------

def test_every_repository_quote_is_an_exact_substring_of_its_cited_line():
    """DOCSTRING V2: every repository quote is on its cited line of a pinned source; SOURCE LINES: every cited line
    of the authorities, enforcement points, behaviours and each row's citations."""
    rec = load(REC)
    sources = {s["path"] for s in rec["sources"]}
    checked = 0
    for cid, where, cited in repository_citations(rec):
        if "item" in cited:
            assert set(cited) == {"item", "quote"}, (cid, where)
            continue
        assert set(cited) == {"path", "line", "quote"}, (cid, where)
        assert cited["path"] in sources, (cid, where, cited["path"])
        assert type(cited["line"]) is int and cited["line"] >= 1
        assert cited["quote"] and cited["quote"] in line_of(cited["path"], cited["line"]), (cid, where, cited)
        checked += 1
    assert checked > 27


def test_sources_are_the_thirteen_and_their_digests_match_the_bytes():
    """DOCSTRING V1: the thirteen repository sources have their pinned digests; DATA: sources; PUBLIC NAMES:
    SOURCES."""
    rec = load(REC)
    pinned = {s["path"]: s["sha256"] for s in rec["sources"]}
    assert len(rec["sources"]) == 13 and set(pinned) == set(THIRTEEN)
    assert pinned == dict(AM.SOURCES)
    for path, digest in pinned.items():
        assert sha(raw(path)) == digest, path


def test_vector_file_digests_match_the_bytes():
    """DOCSTRING V1: the two vector files have their pinned digests; DATA: vectorFiles."""
    rec = load(REC)
    assert [v["path"] for v in rec["vectorFiles"]] == [BUD, R12]
    for entry in rec["vectorFiles"]:
        assert sha(raw(entry["path"])) == entry["sha256"], entry["path"]


def test_roadmap_citations_name_items_of_the_roadmap_pin_exactly():
    """DOCSTRING V2: every roadmap citation names an item of roadmapPin; README: item-bound pins are checked in-repo
    by item id; DATA: roadmapPin.items and every {item, quote} citation."""
    rec = load(REC)
    cited = {c["item"] for _, _, c in repository_citations(rec) if "item" in c}
    assert sorted(rec["roadmapPin"]["items"]) == sorted(cited)
    assert len(set(rec["roadmapPin"]["items"])) == len(rec["roadmapPin"]["items"])
    assert ITEM in cited


# ---------------------------------------------------------------------------------------------------------------
# 4. FAIL_CLOSED and BLOCK_NEW_OPERATIONS, case by case
# ---------------------------------------------------------------------------------------------------------------

FAIL_CLOSED_CASES = {
    ("AM-02", "whenUnavailable"): (FIN, 177, "hard budgets"),
    ("AM-03", "whenUnavailable"): (INF, 156, None),
    ("AM-04", "whenUnavailable"): (SEC, 158, None),
    ("AM-05", "whenRevoked"): (GOV, 159, None),
}
BLOCK_CASES = {
    ("AM-01", "whenUnavailable"): (ORCH, 155, "rejected"),
    ("AM-05", "whenUnavailable"): (GOV, 157, "paused"),
    ("AM-06", "whenUnavailable"): (SBX, 148, "flagged"),
    ("AM-07", "whenUnavailable"): (MEM, 140, "rejected"),
    ("AM-08", "whenUnavailable"): (GOV, 158, "proven"),
}


@pytest.mark.parametrize("behaviour,cases", [("FAIL_CLOSED", FAIL_CLOSED_CASES),
                                             ("BLOCK_NEW_OPERATIONS", BLOCK_CASES)])
def test_case_by_case_behaviours(behaviour, cases):
    """README "FAIL_CLOSED and BLOCK_NEW_OPERATIONS, case by case": each listed case has that behaviour, cited to the
    line the README names (the pinned line of each case decides), with the README's word in its note; no other case
    in the record carries the behaviour; DATA: whenUnavailable and whenRevoked; PUBLIC NAMES: BEHAVIOUR_PINS."""
    rec = load(REC)
    for (cid, slot), (path, number, word) in cases.items():
        held = concern(rec, cid)[slot]
        assert held["behaviour"] == behaviour, (cid, slot)
        assert (held["citation"]["path"], held["citation"]["line"]) == (path, number), (cid, slot)
        assert AM.BEHAVIOUR_PINS[(cid, slot)][1][:2] == (path, number), (cid, slot)
        if word is not None:
            assert word in held["note"], (cid, slot, word)
    carrying = {(c["id"], slot) for c in rec["concerns"] for slot in SLOTS if c[slot]["behaviour"] == behaviour}
    assert carrying == set(cases)


def test_block_new_operations_cases_are_all_unavailability():
    """README: BLOCK_NEW_OPERATIONS, work held back while the authority's state is unavailable; DATA."""
    assert {slot for _, slot in BLOCK_CASES} == {"whenUnavailable"}


# ---------------------------------------------------------------------------------------------------------------
# 5. The budget model, independently derived
# ---------------------------------------------------------------------------------------------------------------

def test_budget_rules_are_b1_to_b5_with_the_stated_texts():
    """DATA: budget-vectors.json rules; README Vectors: rules B1-B5; whether a refused reserve is kept under its key is
    outside these semantics (B3); SOURCE LINES: finops.md:148 states the reservation states, :177 the ledger loss."""
    budget = load(BUD)
    assert budget["schemaVersion"] == AM.BUDGET_SCHEMA
    rules = {rule["id"]: rule["text"] for rule in budget["rules"]}
    assert list(rules) == ["B1", "B2", "B3", "B4", "B5"]
    assert "committed-plus-reserved" in rules["B1"]
    assert "never exceeds its reservation" in rules["B2"] and "COMMITTED" in rules["B2"]
    assert "Whether a refused reserve is kept under its key is outside these semantics" in rules["B3"]
    assert "RELEASED (cancel)" in rules["B4"] and "EXPIRED (timeout)" in rules["B4"]
    assert "hold no balance" in rules["B5"]
    assert "`RESERVED → COMMITTED | RELEASED | EXPIRED`" in line_of(FIN, 148)
    ledger_loss = line_of(FIN, 177)
    for words in ("Ledger loss blocks operations requiring hard budgets", "advisory usage may proceed",
                  "profile explicitly allows", "local outbox capacity exists"):
        assert words in ledger_loss, words


def test_budget_vectors_replay_in_the_reference_model():
    """README Vectors: VB-01 to VB-10, each with its per-step results and each reservation's state at the end (one
    terminal state once settled, RESERVED while open); DATA: vectors; the model is this file's own (B1-B5)."""
    budget = load(BUD)
    assert [v["id"] for v in budget["vectors"]] == ["VB-%02d" % k for k in range(1, 11)]
    for vector in budget["vectors"]:
        for step in vector["steps"]:
            assert tuple(step) == tuple(AM.STEP_MEMBERS[step["op"]]), (vector["id"], step)
        results, final = replay(vector["root"], vector["steps"])
        assert results == vector["results"], vector["id"]
        assert final == vector["final"], vector["id"]
        for key, state in final.items():
            assert state["state"] in ("RESERVED", "COMMITTED", "RELEASED", "EXPIRED")
            if state["state"] == "RESERVED":
                assert (state["committed"], state["returned"]) == (0, 0), (vector["id"], key)


def test_no_vector_depends_on_keeping_a_refused_reserve():
    """README Vectors and B3: whether a refused reserve is kept under its key is outside these semantics, and no
    vector depends on it: no step after a refused first reserve of a key names that key; DATA: vectors."""
    for vector in load(BUD)["vectors"]:
        results, _ = replay(vector["root"], vector["steps"])
        opened, refused_first = set(), set()
        for step, result in zip(vector["steps"], results):
            key = step.get("key")
            assert key is None or key not in refused_first, (vector["id"], key)
            if step["op"] == "reserve" and result == "reserved":
                opened.add(key)
            elif step["op"] == "reserve" and result == "refused" and key not in opened:
                refused_first.add(key)


def test_b5_estimates_elsewhere_hold_no_balance_in_the_record():
    """DATA: rule B5 (ai-gateway's request, token and concurrency budgets, inference-api's usage, H10's task and
    delegation budgets hold no balance) against AM-02's othersMay; usage-ledger is the one authority."""
    am02 = concern(load(REC), "AM-02")
    assert am02["authority"]["component"] == "usage-ledger"
    estimates = {o["who"]: o for o in am02["othersMay"] if o["action"] == "ESTIMATE_AND_ADMIT"}
    assert {"ai-gateway", "inference-api"} <= set(estimates)
    assert any("task and delegation budgets" in o["note"] for o in estimates.values())
    assert "never a competing balance" in estimates["ai-gateway"]["note"]


# ---------------------------------------------------------------------------------------------------------------
# 6. The R12 vectors
# ---------------------------------------------------------------------------------------------------------------

def authority_verbs():
    rule = [text for text in load(R12)["nonClaims"] if "only a row's authority performs an authority act" in text]
    assert len(rule) == 1
    listed = re.search(r"\(([A-Z, ]+)\)", rule[0]).group(1)
    return {verb.strip() for verb in listed.split(",")}


def test_r12_vectors_are_refused_by_the_maps_rule():
    """README Vectors: R12-V1 to R12-V5, each an actor claiming an authority act on a row it does not hold; every one
    is refused by the map's rule over the vector's declared actor and act; DATA: r12-vectors.json nonClaims (the
    verbs) and the record's authorities."""
    rec, r12 = load(REC), load(R12)
    assert r12["schemaVersion"] == AM.R12_SCHEMA
    assert [v["id"] for v in r12["vectors"]] == ["R12-V%d" % k for k in range(1, 6)]
    verbs = authority_verbs()
    assert verbs == {"DECIDE", "MINT", "GRANT", "COMMIT", "PROMOTE", "ACTIVATE"} == set(AM.AUTHORITY_VERBS)
    for vector in r12["vectors"]:
        assert vector["row"] in CONCERN_IDS, vector["id"]
        assert vector["expected"] == "REFUSED", vector["id"]
        assert vector["claimedAction"] in verbs, vector["id"]
        assert vector["actor"] not in names_of(rec, vector["row"]), vector["id"]


def test_r12_v2_names_am_04_only():
    """README Vectors: R12-V2 names AM-04 only: its approval-expiry half is AM-05's (governance-service), held here
    under AM-04, the row whose cache it is; DATA: R12-V2, AM-04's othersMay, AM-05's authority."""
    rec = load(REC)
    v2 = [v for v in load(R12)["vectors"] if v["id"] == "R12-V2"]
    assert len(v2) == 1 and v2[0]["row"] == "AM-04"
    assert concern(rec, "AM-05")["authority"]["component"] == "governance-service"
    caches = [o for o in concern(rec, "AM-04")["othersMay"] if o["action"] == "CACHE_WITH_FRESHNESS_AND_REVOCATION"]
    assert len(caches) == 1


# ---------------------------------------------------------------------------------------------------------------
# 7. V7 and V9 as the operator states them; 9. the validator accepts the published contract
# ---------------------------------------------------------------------------------------------------------------

def assert_accepted(result):
    assert set(result) == {"concerns", "pins", "flagged", "budgetVectors", "r12Vectors"}
    assert size(result["concerns"]) == 9
    assert size(result["pins"]) == 27
    assert size(result["flagged"]) == 2
    assert size(result["budgetVectors"]) == 10
    assert size(result["r12Vectors"]) == 5


def test_check_accepts_the_published_contract():
    """OPERATOR: check(read, frozenset()) returns concerns, pins, flagged, budgetVectors and r12Vectors; README: 9
    concerns, 27 pins, 2 flagged, VB-01 to VB-10, R12-V1 to R12-V5 (model-derived acceptance)."""
    assert_accepted(run())


def test_check_reads_exact_paths_only():
    """DOCSTRING: an injected byte reader (exact paths only, no listing); V1 reads the thirteen sources and the two
    vector files; OPERATOR: V7 reads the technology record and V9 the registry. The tree's own registry, with the
    packet ids of its later riders (README V9 (a))."""
    reader = Reader()
    assert_accepted(AM.check(reader, frozenset(tree_later_ids())))
    assert set(reader.paths) == {REC, BUD, R12, TECH, BRIEFS} | set(THIRTEEN)


def test_check_accepts_the_reserialized_record_and_repinned_vectors():
    """Control for the mutations: the record re-serialized unchanged, and each vector file re-serialized and
    re-pinned, are accepted (the record carries no digest of itself; DATA: vectorFiles)."""
    assert_accepted(run({REC: dump(load(REC))}))
    assert_accepted(run(repinned(BUD, dump(load(BUD)))))
    assert_accepted(run(repinned(R12, dump(load(R12)))))


def test_registry_base_and_base_plus_one_rider_pass():
    """README V9 (a): the registry is accepted at its base digest, or as the base then MET-ADOPT-007's one rider;
    PUBLIC NAMES: RIDER, BRIEFS_BASE_SHA256 (the base built here, never the file's own digest)."""
    base = dump(registry_base())
    assert sha(base) == AM.BRIEFS_BASE_SHA256
    assert_accepted(run({BRIEFS: base}))
    assert_accepted(run(registry_with(lambda entries: entries.append(copy.deepcopy(AM.RIDER)))))


NEXT_1, NEXT_2 = "MET-NEXT-001", "MET-NEXT-002"


def test_v9a_1_two_later_riders_are_accepted():
    """VECTOR V9A-1 (RULING: two later riders accepted): the base, RIDER, then MET-NEXT-001/packet and
    MET-NEXT-002/packet, with both ids in packets, is accepted."""
    entries = [copy.deepcopy(AM.RIDER), later_rider(NEXT_1), later_rider(NEXT_2)]
    assert_accepted(run(registry_with(lambda e: e.extend(entries)), frozenset({NEXT_1, NEXT_2})))


def test_v9a_2_a_second_281_rider_is_refused():
    """VECTOR V9A-2 (RULING: a second 281 rider still refuses): the base, RIDER, a later rider, then RIDER again,
    with the later id and MET-ADOPT-007 in packets, refuses with AM_REGISTRY."""
    entries = [copy.deepcopy(AM.RIDER), later_rider(NEXT_1), copy.deepcopy(AM.RIDER)]
    packets = frozenset({NEXT_1, "MET-ADOPT-007"})
    assert refusal_code(registry_with(lambda e: e.extend(entries)), packets) == "AM_REGISTRY"


@pytest.mark.parametrize("packets", [frozenset(), frozenset({NEXT_2})], ids=["empty", "other-id"])
def test_v9a_3_an_unknown_id_rider_is_refused(packets):
    """VECTOR V9A-3 (RULING: a rider for an id not in packets refuses): the base, RIDER, then MET-NEXT-001/packet,
    with MET-NEXT-001 not in packets, refuses with AM_REGISTRY."""
    entries = [copy.deepcopy(AM.RIDER), later_rider(NEXT_1)]
    assert refusal_code(registry_with(lambda e: e.extend(entries)), packets) == "AM_REGISTRY"


def test_v9a_4_a_later_rider_before_281s_is_refused():
    """VECTOR V9A-4 (optional; README: a rider before MET-ADOPT-007's is refused, the base's digest refuses it):
    the base, MET-NEXT-001/packet, then RIDER, with MET-NEXT-001 in packets, refuses with AM_REGISTRY."""
    entries = [later_rider(NEXT_1), copy.deepcopy(AM.RIDER)]
    assert refusal_code(registry_with(lambda e: e.extend(entries)), frozenset({NEXT_1})) == "AM_REGISTRY"


def test_v9a_5_a_series_registered_twice_is_refused():
    """VECTOR V9A-5 (optional; README: each series appears once in the whole registry, the base included): a later
    rider twice, and a later rider for a series the base already holds (DATA: MET-PERF-046/packet), each refuse with
    AM_REGISTRY with the id in packets."""
    twice = [copy.deepcopy(AM.RIDER), later_rider(NEXT_1), later_rider(NEXT_1)]
    assert refusal_code(registry_with(lambda e: e.extend(twice)), frozenset({NEXT_1})) == "AM_REGISTRY"
    assert any(e.get("series") == "MET-PERF-046/packet" for e in registry_base()["briefs"])
    held = [copy.deepcopy(AM.RIDER), later_rider("MET-PERF-046")]
    assert refusal_code(registry_with(lambda e: e.extend(held)), frozenset({"MET-PERF-046"})) == "AM_REGISTRY"


GENERIC_BREAKS = [
    ("version-2", {"version": 2}),
    ("other-sha256", {"sha256": "0" * 64}),
    ("other-kind", {"kind": "DESIGN"}),
    ("other-path", {"path": "architecture/review-briefs/OTHER.md"}),
]


@pytest.mark.parametrize("name,change", GENERIC_BREAKS, ids=[g[0] for g in GENERIC_BREAKS])
def test_v9a_a_later_rider_is_the_generic_packet_brief(name, change):
    """README V9 (a): each later rider is the generic packet brief (the rider's kind, path, sha256 and version 1)
    under <id>/packet; OPERATOR: V9's code is AM_REGISTRY. A later rider differing in one of them refuses; the series
    must end in /packet."""
    entries = [copy.deepcopy(AM.RIDER), later_rider(NEXT_1, **change)]
    assert refusal_code(registry_with(lambda e: e.extend(entries)), frozenset({NEXT_1})) == "AM_REGISTRY"
    design = [copy.deepcopy(AM.RIDER), dict(copy.deepcopy(AM.RIDER), series=NEXT_1 + "/design")]
    assert refusal_code(registry_with(lambda e: e.extend(design)), frozenset({NEXT_1})) == "AM_REGISTRY"


def test_v9a_the_trees_registry_with_its_later_riders():
    """README V9 (a) and OPERATOR: the registry on the tree carries later riders from slot 282 on (it holds
    MET-PERF-047/packet after MET-ADOPT-007's rider); it is accepted with their ids in packets, and refused with
    AM_REGISTRY when packets is empty or lacks the last rider's id."""
    ids = tree_later_ids()
    assert "MET-PERF-047" in ids and len(set(ids)) == len(ids)
    tree = {BRIEFS: raw(BRIEFS)}
    assert_accepted(run(tree, frozenset(ids)))
    assert refusal_code(tree, frozenset()) == "AM_REGISTRY"
    assert refusal_code(tree, frozenset(ids[:-1])) == "AM_REGISTRY"


def test_technology_record_with_matching_pending_reconciliation_passes():
    """OPERATOR: V7 accepts TECH_LIST_MEMBER (pendingReconciliation) only when it is a list holding each
    RECONCILIATION entry with the same successor; PUBLIC NAMES: TECH_BASE_MEMBERS, TECH_LIST_MEMBER, RECONCILIATION;
    DATA: the record's reconciliation list."""
    assert load(REC)["reconciliation"] == pending_entries()
    assert AM.TECH_LIST_MEMBER == "pendingReconciliation"
    tech = load(TECH)
    assert set(tech) - {AM.TECH_LIST_MEMBER} == set(AM.TECH_BASE_MEMBERS)
    assert_accepted(run(tech_with(lambda t: t.pop(AM.TECH_LIST_MEMBER, None))))
    assert_accepted(run(tech_with(lambda t: t.__setitem__(AM.TECH_LIST_MEMBER, pending_entries()))))


def test_base_exceptions_from_the_reader_pass_through():
    """DOCSTRING: Exception is caught, never BaseException: a BaseException raised by the reader propagates unchanged.
    (Whether an Exception raised by the reader itself is caught is not stated: the sentence follows the reading
    check's; the Exception half is tested on the reading check, mutation "deeply-nested".)"""
    with pytest.raises(Stop):
        AM.check(Reader(base_plus_rider(), failures={SEC: Stop()}), frozenset())


# ---------------------------------------------------------------------------------------------------------------
# 8. Mutations, each through this file's own read
# ---------------------------------------------------------------------------------------------------------------

def _set(path_fn, member, value):
    def edit(rec):
        path_fn(rec)[member] = value
    return edit


def _c(cid):
    return lambda rec: concern(rec, cid)


def m_extra_top():
    return record_with(lambda rec: rec.__setitem__("owner", "nobody"))


def m_extra_concern_member():
    return record_with(_set(_c("AM-03"), "owner", "nobody"))


def m_bool_line():
    return record_with(_set(lambda rec: concern(rec, "AM-01")["whenUnavailable"]["citation"], "line", True))


def m_missing_member():
    return record_with(lambda rec: concern(rec, "AM-03")["whenRevoked"].pop("note"))


def m_behaviour_outside_vocabulary():
    return record_with(_set(lambda rec: concern(rec, "AM-01")["whenUnavailable"], "behaviour", "RETRY_LATER"))


def m_who_kind_outside_vocabulary():
    return record_with(_set(lambda rec: concern(rec, "AM-01")["othersMay"][0], "whoKind", "SERVICE"))


def m_string_for_list():
    return record_with(lambda rec: rec.__setitem__("nonClaims", "none"))


def m_duplicate_member():
    old = b'"behaviour": "RESUME_FROM_CHECKPOINT",'
    return {REC: replaced(raw(REC), old, old + b'\n    "behaviour": "RESUME_FROM_CHECKPOINT",')}


def m_not_utf8():
    old = b'"note": "requests task transitions"'
    return {REC: replaced(raw(REC), old, b'"note": "requests task transitions \xff"')}


def m_non_finite():
    return {REC: replaced(raw(REC), b'"line": 117,', b'"line": NaN,')}


def m_integer_beyond_limit():
    return {REC: replaced(raw(REC), b'"line": 114,', b'"line": 1' + b"0" * 5000 + b",")}


def m_deeply_nested():
    return {REC: b"[" * 50000 + b"]" * 50000 + b"\n"}


def m_concern_dropped():
    return record_with(lambda rec: rec.__setitem__("concerns", rec["concerns"][:-1]))


def m_concerns_reordered():
    return record_with(lambda rec: rec.__setitem__("concerns", [rec["concerns"][1], rec["concerns"][0]]
                                                   + rec["concerns"][2:]))


def m_source_byte():
    data = raw(SEC)
    return {SEC: data[:-1] + (b"\t" if data[-1:] != b"\t" else b" ")}


def m_budget_byte_unpinned():
    return {BUD: replaced(raw(BUD), b'"timed out unused"', b'"timed out unUsed"')}


def m_r12_byte_unpinned():
    return {R12: replaced(raw(R12), b'"the transport"', b'"the Transport"')}


def m_record_source_digest():
    return record_with(lambda rec: rec["sources"][0].__setitem__("sha256", "0" * 64))


def m_paraphrased_quote():
    def edit(rec):
        row = [x for x in concern(rec, "AM-01")["citations"] if x.get("line") == 59 and x.get("path") == ORCH]
        assert len(row) == 1
        row[0]["quote"] = row[0]["quote"].replace("query,", "queries,")
        assert row[0]["quote"] not in line_of(ORCH, 59)
    return record_with(edit)


def m_wrong_line():
    def edit(rec):
        row = [x for x in concern(rec, "AM-01")["citations"] if x.get("line") == 59 and x.get("path") == ORCH]
        assert len(row) == 1 and row[0]["quote"] not in line_of(ORCH, 60)
        row[0]["line"] = 60
    return record_with(edit)


def m_unknown_roadmap_item():
    def edit(rec):
        row = [x for x in concern(rec, "AM-01")["citations"] if x.get("item") == "DATA-CORRECTNESS-001"]
        assert len(row) == 1
        row[0]["item"] = "DATA-CORRECTNESS-999"
    return record_with(edit)


def m_path_not_a_source():
    def edit(rec):
        assert "{" in line_of(TECH, 1)
        concern(rec, "AM-01")["citations"].append({"path": TECH, "line": 1, "quote": "{"})
    return record_with(edit)


def m_paraphrased_pin_quote():
    def edit(rec):
        cited = concern(rec, "AM-07")["whenRevoked"]["citation"]
        cited["quote"] = "Deletion blocks recall first"
        assert cited["quote"] not in line_of(MEM, 143)
    return record_with(edit)


def m_input_names_authority():
    return record_with(_set(_c("AM-04"), "inputs", [{"harness": "trust.security-safety",
                                                     "component": "policy-decision", "role": "POLICY_LIFECYCLE"}]))


def m_input_other_harness_label():
    return record_with(_set(_c("AM-02"), "inputs", [{"harness": "runtime.ai-gateway", "component": "usage-ledger",
                                                     "role": "EVIDENCE"}]))


def m_second_authority_row():
    return record_with(lambda rec: concern(rec, "AM-07")["othersMay"].append(
        {"who": "memory-service", "whoKind": "COMPONENT", "action": "READ_THROUGH_FILTERS", "note": "a second one"}))


def m_module_name_row():
    return record_with(_set(lambda rec: concern(rec, "AM-04")["othersMay"][0], "who", "planeon.policy-decision"))


def m_authority_component_changed():
    return record_with(_set(lambda rec: concern(rec, "AM-09")["authority"], "component", "operator"))


def m_authority_harness_changed():
    return record_with(_set(lambda rec: concern(rec, "AM-07")["authority"], "harness", "trust.governance-agentops"))


def m_authority_cited_elsewhere():
    quote = "Hard-budget operations reserve atomically before work"
    assert quote in line_of(FIN, 176)
    return record_with(_set(lambda rec: concern(rec, "AM-02")["authority"], "citation",
                            {"path": FIN, "line": 176, "quote": quote}))


def m_enforcement_emptied():
    return record_with(_set(_c("AM-06"), "enforcementPoints", []))


def m_behaviour_changed():
    return record_with(_set(lambda rec: concern(rec, "AM-07")["whenRevoked"], "behaviour", "DEACTIVATE_REVOKED"))


def m_flagged_behaviour_changed():
    return record_with(_set(lambda rec: concern(rec, "AM-06")["whenUnavailable"], "behaviour", "FAIL_CLOSED"))


def m_behaviour_cited_elsewhere():
    quote = "Approval dependency loss pauses the operation"
    assert quote in line_of(GOV, 157)
    return record_with(_set(lambda rec: concern(rec, "AM-05")["whenRevoked"], "citation",
                            {"path": GOV, "line": 157, "quote": quote}))


def m_item_bound_cited_to_a_line():
    quote = "Ledger loss blocks operations requiring hard budgets"
    assert quote in line_of(FIN, 177)
    return record_with(_set(lambda rec: concern(rec, "AM-02")["whenRevoked"], "citation",
                            {"path": FIN, "line": 177, "quote": quote}))


def _vector(value, vid):
    return next(v for v in value["vectors"] if v["id"] == vid)


def m_budget_result_changed():
    return vectors_with(BUD, lambda b: _vector(b, "VB-01")["results"].__setitem__(2, "committed"))


def m_budget_final_state_changed():
    return vectors_with(BUD, lambda b: _vector(b, "VB-09")["final"]["k"].__setitem__("state", "EXPIRED"))


def m_budget_final_amounts_changed():
    return vectors_with(BUD, lambda b: _vector(b, "VB-05")["final"]["k"].update(committed=60, returned=40))


def m_budget_root_changed():
    return vectors_with(BUD, lambda b: _vector(b, "VB-07").__setitem__("root", 250))


def m_tech_successor_changed():
    def edit(tech):
        entries = pending_entries()
        entries[0]["successor"] = "another packet"
        tech[AM.TECH_LIST_MEMBER] = entries
    return tech_with(edit)


def m_tech_entry_missing():
    return tech_with(lambda tech: tech.__setitem__(AM.TECH_LIST_MEMBER, pending_entries()[1:]))


def m_tech_pending_not_a_list():
    return tech_with(lambda tech: tech.__setitem__(AM.TECH_LIST_MEMBER, {"entries": pending_entries()}))


def m_tech_unknown_member():
    return tech_with(lambda tech: tech.__setitem__("zzNewMember", []))


def m_tech_base_member_dropped():
    return tech_with(lambda tech: tech.pop("exceptions"))


def m_record_successor_changed():
    return record_with(lambda rec: rec["reconciliation"][2].__setitem__("successor", "MODEL-AUX-002"))


def m_r12_actor_is_authority():
    return vectors_with(R12, lambda v: _vector(v, "R12-V1").__setitem__("actor", "policy-decision"))


def m_r12_expects_accept():
    return vectors_with(R12, lambda v: _vector(v, "R12-V3").__setitem__("expected", "ACCEPT"))


def m_r12_non_authority_act():
    return vectors_with(R12, lambda v: _vector(v, "R12-V1").__setitem__("claimedAction", "ADVISE"))


def m_r12_unknown_row():
    return vectors_with(R12, lambda v: _vector(v, "R12-V4").__setitem__("row", "AM-10"))


def m_second_rider():
    return registry_with(lambda entries: entries.extend([copy.deepcopy(AM.RIDER), copy.deepcopy(AM.RIDER)]))


def m_base_entry_dropped():
    return registry_with(lambda entries: entries.pop())


def m_rider_other_version():
    rider = dict(AM.RIDER, version=2)
    return registry_with(lambda entries: entries.append(rider))


def m_rider_first():
    return registry_with(lambda entries: entries.insert(0, copy.deepcopy(AM.RIDER)))


def m_registry_duplicate_member():
    old = b'"schemaVersion": "planeon.review-briefs/v1",'
    return {BRIEFS: replaced(dump(registry_base()), old, old + b"\n " + old)}


# (id, builder, expected code or None for "refused with a listed code", source of the expectation)
MUTATIONS = [
    ("extra-top-member", m_extra_top, "AM_SHAPE", "DOCSTRING V0: closed to its exact members"),
    ("extra-concern-member", m_extra_concern_member, "AM_SHAPE", "DOCSTRING V0: closed to its exact members"),
    ("bool-for-line", m_bool_line, "AM_SHAPE", "DOCSTRING V0: exact JSON types"),
    ("member-missing", m_missing_member, "AM_SHAPE", "DOCSTRING V0: closed to its exact members"),
    ("behaviour-outside-vocabulary", m_behaviour_outside_vocabulary, "AM_SHAPE", "DOCSTRING V0: vocabularies closed"),
    ("whokind-outside-vocabulary", m_who_kind_outside_vocabulary, "AM_SHAPE", "DOCSTRING V0: vocabularies closed"),
    ("string-for-list", m_string_for_list, "AM_SHAPE", "DOCSTRING V0: exact JSON types"),
    ("duplicate-member", m_duplicate_member, "AM_SHAPE", "DOCSTRING: the reading check's code (the record: V0)"),
    ("not-utf8", m_not_utf8, "AM_SHAPE", "DOCSTRING: the reading check's code (the record: V0)"),
    ("non-finite-number", m_non_finite, "AM_SHAPE", "DOCSTRING: the reading check's code (the record: V0)"),
    ("integer-beyond-limit", m_integer_beyond_limit, "AM_SHAPE", "DOCSTRING: the reading check's code (V0)"),
    ("deeply-nested", m_deeply_nested, "AM_SHAPE",
     "DOCSTRING: Exception is caught (a parse RecursionError), the reading check's code (V0)"),
    ("concern-dropped", m_concern_dropped, None, "README: nine concerns; the docstring ties no code"),
    ("concerns-reordered", m_concerns_reordered, None, "README: nine concerns; the docstring ties no code"),
    ("source-byte-changed", m_source_byte, "AM_SOURCES", "DOCSTRING V1: sources have their pinned digests"),
    ("budget-byte-not-repinned", m_budget_byte_unpinned, "AM_SOURCES", "DOCSTRING V1: vector files' digests"),
    ("r12-byte-not-repinned", m_r12_byte_unpinned, "AM_SOURCES", "DOCSTRING V1: vector files' digests"),
    ("record-source-digest", m_record_source_digest, "AM_SOURCES", "DOCSTRING V1: pinned digests"),
    ("paraphrased-quote", m_paraphrased_quote, "AM_CITATIONS", "DOCSTRING V2: quote on its cited line"),
    ("wrong-line", m_wrong_line, "AM_CITATIONS", "DOCSTRING V2: quote on its cited line"),
    ("unknown-roadmap-item", m_unknown_roadmap_item, "AM_CITATIONS", "DOCSTRING V2: names an item of roadmapPin"),
    ("path-not-a-source", m_path_not_a_source, "AM_CITATIONS", "DOCSTRING V2: of a pinned source"),
    ("paraphrased-pin-quote", m_paraphrased_pin_quote, "AM_CITATIONS", "DOCSTRING V2: the same check over pins"),
    ("input-names-authority", m_input_names_authority, "AM_ONE_AUTHORITY", "DOCSTRING V3: no input names it"),
    ("input-other-harness-label", m_input_other_harness_label, "AM_ONE_AUTHORITY",
     "DOCSTRING V3: whatever the harness label"),
    ("second-authority-component-row", m_second_authority_row, "AM_ONE_AUTHORITY",
     "DOCSTRING V3: no COMPONENT row names the authority"),
    ("module-name-component-row", m_module_name_row, "AM_ONE_AUTHORITY",
     "DOCSTRING V3: by a module name its pinned quote gives"),
    ("authority-component-changed", m_authority_component_changed, "AM_ONE_AUTHORITY",
     "DOCSTRING V3: a row's authority equals its pin"),
    ("authority-harness-changed", m_authority_harness_changed, "AM_ONE_AUTHORITY",
     "DOCSTRING V3: a row's authority equals its pin"),
    ("authority-cited-to-another-line", m_authority_cited_elsewhere, "AM_ONE_AUTHORITY",
     "DOCSTRING: the right value cited to another line refuses; V3: authority equals its pin"),
    ("enforcement-points-emptied", m_enforcement_emptied, "AM_ENFORCEMENT",
     "README: every enforcement point; DOCSTRING V4 by name"),
    ("behaviour-changed", m_behaviour_changed, "AM_FAILURE_MODES",
     "DOCSTRING: a different value refuses; V5 by name"),
    ("flagged-behaviour-changed", m_flagged_behaviour_changed, "AM_FAILURE_MODES",
     "DOCSTRING: a different value refuses; V5 by name"),
    ("behaviour-cited-to-another-line", m_behaviour_cited_elsewhere, "AM_FAILURE_MODES",
     "DOCSTRING: the right value cited to another line refuses; V5 by name"),
    ("item-bound-cited-to-a-line", m_item_bound_cited_to_a_line, "AM_FAILURE_MODES",
     "DOCSTRING: the right value cited to another line refuses; V5 by name"),
    ("budget-result-changed-repinned", m_budget_result_changed, "AM_BUDGET", "DOCSTRING V6: the model replays"),
    ("budget-final-state-changed-repinned", m_budget_final_state_changed, "AM_BUDGET",
     "DOCSTRING V6: the model replays"),
    ("budget-final-amounts-changed-repinned", m_budget_final_amounts_changed, "AM_BUDGET",
     "DOCSTRING V6: the model replays"),
    ("budget-root-changed-repinned", m_budget_root_changed, "AM_BUDGET", "DOCSTRING V6: the model replays"),
    ("tech-successor-changed", m_tech_successor_changed, "AM_RECONCILIATION",
     "OPERATOR V7: another successor refuses; DOCSTRING V7 code"),
    ("tech-entry-missing", m_tech_entry_missing, "AM_RECONCILIATION",
     "OPERATOR V7: holding each RECONCILIATION entry; DOCSTRING V7 code"),
    ("tech-pending-not-a-list", m_tech_pending_not_a_list, None, "OPERATOR V7: only when it is a list; no code tied"),
    ("tech-unknown-member", m_tech_unknown_member, "AM_RECONCILIATION_UNKNOWN_MEMBER",
     "OPERATOR V7: an unknown new member refuses; DOCSTRING V7 code"),
    ("tech-base-member-dropped", m_tech_base_member_dropped, None, "OPERATOR V7: member names; no code tied"),
    ("record-successor-changed", m_record_successor_changed, None, "README nonClaims: successors; no code tied"),
    ("r12-actor-is-the-authority", m_r12_actor_is_authority, "AM_R12_VECTORS",
     "README: refused by the map's rule over actor and act; DOCSTRING V8"),
    ("r12-expects-accept", m_r12_expects_accept, None, "README: every one is refused; V0 or V8, no code tied"),
    ("r12-non-authority-act", m_r12_non_authority_act, None, "R12 nonClaims verbs; V0 or V8, no code tied"),
    ("r12-unknown-row", m_r12_unknown_row, None, "README: a row it does not hold; no code tied"),
    ("second-rider", m_second_rider, "AM_REGISTRY", "README V9 (a): a second MET-ADOPT-007 rider refuses"),
    ("base-entry-dropped", m_base_entry_dropped, "AM_REGISTRY", "README V9 (a): the base, unchanged, comes first"),
    ("rider-other-version", m_rider_other_version, "AM_REGISTRY",
     "README V9 (a): MET-ADOPT-007's one rider exactly; a later rider is another packet's"),
    ("rider-first", m_rider_first, "AM_REGISTRY", "README V9 (a): a rider before the base's end (the base digest)"),
    ("registry-duplicate-member", m_registry_duplicate_member, "AM_REGISTRY",
     "OPERATOR V9 and DOCSTRING: the reading check's code"),
]


@pytest.mark.parametrize("mid,build,expected,source", MUTATIONS, ids=[m[0] for m in MUTATIONS])
def test_mutation_is_refused(mid, build, expected, source):
    """DOCSTRING "Refusal codes, in the order they run" and OPERATOR (refusal = ValueError "<CODE>: ..."): each
    mutation, given through this file's own read, is refused with the expected code; where the docstring ties no
    code, it is refused with one of the listed codes."""
    code = refusal_code(build())
    if expected is None:
        assert code in DOC_CODES, (mid, code)
    else:
        assert code == expected, (mid, code, source)


def test_mutations_reach_every_listed_code():
    """DOCSTRING: the refusal codes V0-V9 (README: AM_SHAPE to AM_REGISTRY); at least 16 mutations, and every listed
    code is the expected code of at least one mutation."""
    assert DOC_CODES == EXPECTED_CODES
    assert DOC_CODES[0] == "AM_SHAPE" and DOC_CODES[-1] == "AM_REGISTRY"
    assert len(MUTATIONS) >= 16
    assert len({m[0] for m in MUTATIONS}) == len(MUTATIONS)
    assert {m[2] for m in MUTATIONS if m[2] is not None} == set(DOC_CODES)
