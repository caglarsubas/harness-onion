#!/usr/bin/env python3
"""Authority map (architecture/authority-map.json, AUTHORITY-MAP-001, MET-ADOPT-007): one effective authority per concern.

check(read, packets) validates the closed record through an injected byte reader (exact paths only, no listing) and the
set of published packet ids. For each of nine concerns the record names one authoritative boundary, what others may do,
every enforcement point, and the behaviour when the authority is unavailable or revoked. The module pins every row's
authority and both behaviours as constants (27), each bound to one citation: 23 stating lines, 2 roadmap-item quotes
(AM-02 revoked, AM-06's authority) and 2 flagged pins whose documents state no rule for the case, bound to the nearest
topical line (AM-06 unavailable, AM-09 revoked). A different value, or the right value cited to another line, refuses;
a change to a pin is a new module version and a new record version. Refusal codes, in the order they run:
- AM_SHAPE (V0): every object is closed to its exact members, with exact JSON types; vocabularies are closed.
- AM_SOURCES (V1): the thirteen repository sources and the two vector files have their pinned digests.
- AM_CITATIONS (V2): every repository quote is on its cited line of a pinned source; every roadmap citation names an
  item of roadmapPin (its text is checked at authoring and in review, Q-AM-9 (a)); the same check runs over the pins.
- AM_ONE_AUTHORITY (V3: a row's authority equals its pin; no input and no COMPONENT row names the authority, by its
  component or by a module name its pinned quote gives, whatever the harness label), AM_ENFORCEMENT (V4),
  AM_FAILURE_MODES (V5), AM_BUDGET (V6: a standard-library reference model of B1-B5 replays every budget vector),
  AM_RECONCILIATION and AM_RECONCILIATION_UNKNOWN_MEMBER (V7), AM_R12_VECTORS (V8), AM_REGISTRY (V9).
Bytes that are not UTF-8 JSON, duplicate members, non-finite numbers and integers beyond the conversion limit refuse
with the reading check's code. Exception is caught, never BaseException. Data checks only: the map records authority
and its enforcement points; it enforces nothing, and it claims no concurrency or clock property (DATA-CORRECTNESS-001).
"""
from __future__ import annotations

import hashlib
import json

RECORD_PATH = "architecture/authority-map.json"
SCHEMA = "planeon.internal.authority-map/v1"
BUDGET_PATH = "architecture/authority-map/budget-vectors.json"
BUDGET_SCHEMA = "planeon.internal.authority-map-budget/v1"
R12_PATH = "architecture/authority-map/r12-vectors.json"
R12_SCHEMA = "planeon.internal.authority-map-r12/v1"
TECH_PATH = "architecture/language-placement.json"
BRIEFS_PATH = "architecture/review-record/briefs.json"
BRIEFS_BASE_SHA256 = "0eea62f4d4531421191865224832ada9fd8bb5599ebdacb87e1f0adc3609f2cc"
RIDER = {"kind": "PACKET", "series": "MET-ADOPT-007/packet", "path": "architecture/review-briefs/REVIEW_BRIEF_PACKET.md",
         "sha256": "6dcff68d7e6b01823f1740063e94910edcc159a71a6ee803f1b66c62fd06e274", "version": 1}
ROADMAP_PATH = "roadmap/roadmap.json"
H = "docs/harnesses/"
ORCH, FIN, INF, GW = H + "execution.orchestration.md", H + "trust.observability-finops.md", \
    H + "runtime.model-inference.md", H + "runtime.ai-gateway.md"
SEC, GOV, SBX, MEM, INFRA = H + "trust.security-safety.md", H + "trust.governance-agentops.md", \
    H + "execution.tool-skill-sandbox.md", H + "knowledge.memory-state.md", H + "runtime.infrastructure.md"
SOURCES = {
    "docs/adr/0005-release-evidence.md": "e0d9134551f137da84cbb5709b0a6383447995490ac5a01647b211831fc67971",
    "docs/adr/0011-h10-execution-authority.md": "60a8250ecce83e9ee3655726b90db22e526eb69aac163d9e2eb60977a81c5685",
    ORCH: "32b80f130bd4a5d9babf0731ace2b239034c8d07afcfba6742f1ada4335a31f2",
    SBX: "894ef8182df30896ef713d2e46be5601feab234703752eb8243786d419d4556b",
    MEM: "6b89b8fbcd7ba0458817b991fef890cae705958bc16a352db4402d6813a489fb",
    GW: "797b6fd2a10c49a17d9063d7a13654da9c3d2ea2edd665a3cd39c3d5bb18b2ea",
    H + "runtime.experience.md": "66756f3b6f828c2f3d9332dbd92f2799337965aaab1b62e6123aa33337988779",
    INFRA: "eecdfe44672d57778f44943531612a5146cda9d8eb9c21e9abef92999a9f8652",
    INF: "dd79935f62eec36ab0adaf90abcc20a1eed532a579ef49eadd83b066d4749241",
    H + "trust.evaluation-assurance.md": "57b73641ad2362dd31948d57ab810f76f6f5285a254545fe1a7f031b160e860c",
    GOV: "76c717d4d4c419b6d9cd7a29c9d72cfe0484363d60a17d24ea685ec2babe734e",
    FIN: "25e0be5e61350cf1ab00ab3abd654b678d4d48bed8dfad8d3d0e1fe5efe09aee",
    SEC: "736f7184d124cdf7804efbe1d5768830662e649b7588b5e8c2d22c82c617323e",
}
TECH_BASE_MEMBERS = frozenset(("adr", "baselineBindings", "catalogues", "deployables", "exceptions", "h10Sources",
                               "outsideCatalogue", "policySha256", "repositories", "schemaVersion"))
TECH_LIST_MEMBER = "pendingReconciliation"
ROLES = ("CONTRACT_PATH", "EVIDENCE", "POLICY_LIFECYCLE", "READINESS_GATE", "SIGNED_RELEASE", "SIGNED_ROUTE_BUNDLE")
WHO_KINDS = ("COMPONENT", "ROLE")
ACTIONS = ("ADVISE", "BUILD_INPUT", "CACHE_WITH_FRESHNESS_AND_REVOCATION", "ESTIMATE_AND_ADMIT", "MEASURE",
           "PRESENT_AND_SUBMIT", "PROPOSE", "READ_THROUGH_FILTERS", "RENDER", "REQUEST", "SCHEDULE")
BEHAVIOURS = ("BLOCK_NEW_OPERATIONS", "DEACTIVATE_REVOKED", "FAIL_CLOSED", "KEEP_CONSUMED_CHARGE", "KEEP_RUNNING_VERSION",
              "OUTCOME_UNKNOWN_RECONCILE", "RESUME_FROM_CHECKPOINT", "STOP_RECALL")
AUTHORITY_VERBS = ("ACTIVATE", "COMMIT", "DECIDE", "GRANT", "MINT", "PROMOTE")
CONCERN_IDS = tuple("AM-0%d" % k for k in range(1, 10))
SENTINEL = ("EXTERNAL", "TARGET_SYSTEM")
ITEM = "AUTHORITY-MAP-001"
GOV_A = (GOV, 59, "`governance-service`: approval, waiver, autonomy, control requirement, and promotion gate API")
# The 27 pins (design rev 6, section 3): (harness, component, citation) and (behaviour, citation); a citation is
# (path, line, quote) or ("item", item id, quote).
AUTHORITY_PINS = {
    "AM-01": ("execution.orchestration", "planeon.orchestrator.postgres",
              (ORCH, 16, "Planning target: `planeon.orchestrator.postgres` (PostgreSQL leases and outbox) as H10's "
                         "qualified baseline")),
    "AM-02": ("trust.observability-finops", "usage-ledger",
              (FIN, 60, "`usage-ledger`: authoritative request/token/tool/task/resource budget and attribution service")),
    "AM-03": ("runtime.model-inference", "inference-api",
              (INF, 59, "`inference-api`: stable OpenAI-compatible internal API, scheduler, route resolver")),
    "AM-04": ("trust.security-safety", "policy-decision",
              (SEC, 83, "`planeon.policy-decision`: mandatory authorization and admission service")),
    "AM-05": ("trust.governance-agentops", "governance-service", GOV_A),
    "AM-06": (SENTINEL[0], SENTINEL[1],
              ("item", ITEM, "business-system effect (the target plus H11's governed invocation and reconciliation "
                             "contract")),
    "AM-07": ("knowledge.memory-state", "memory-service",
              (MEM, 59, "`memory-service`: policy-gated read/write/search/correct/delete/export API and lifecycle worker")),
    "AM-08": ("trust.governance-agentops", "governance-service", GOV_A),
    "AM-09": ("runtime.infrastructure", "bundle-verifier",
              (INFRA, 61, "`bundle-verifier`: init/container library that verifies bundle lock, signatures, and blob "
                          "digests before apply")),
}
BEHAVIOUR_PINS = {
    ("AM-01", "whenUnavailable"): ("BLOCK_NEW_OPERATIONS", (ORCH, 155, "PostgreSQL loss rejects mutations")),
    ("AM-01", "whenRevoked"): ("RESUME_FROM_CHECKPOINT",
                               (ORCH, 149, "Worker leases expire and are reclaimed; checkpoint version and "
                                           "compare-and-swap prevent double transition")),
    ("AM-02", "whenUnavailable"): ("FAIL_CLOSED", (FIN, 177, "Ledger loss blocks operations requiring hard budgets")),
    ("AM-02", "whenRevoked"): ("KEEP_CONSUMED_CHARGE",
                               ("item", ITEM, "a cancelled or timed-out request keeps its consumed charge")),
    ("AM-03", "whenUnavailable"): ("FAIL_CLOSED",
                                   (INF, 156, "Invalid route signatures, missing blobs, license rejection, or "
                                              "capability mismatch fail route activation closed")),
    ("AM-03", "whenRevoked"): ("DEACTIVATE_REVOKED", (GW, 155, "Revoked routes reject new work immediately")),
    ("AM-04", "whenUnavailable"): ("FAIL_CLOSED",
                                   (SEC, 158, "If no authoritative answer is available, return `ERROR_FAIL_CLOSED`")),
    ("AM-04", "whenRevoked"): ("DEACTIVATE_REVOKED",
                               (SEC, 160, "Critical revocation is applied immediately to new operations")),
    ("AM-05", "whenUnavailable"): ("BLOCK_NEW_OPERATIONS",
                                   (GOV, 157, "Approval dependency loss pauses the operation; it never implies "
                                              "approval")),
    ("AM-05", "whenRevoked"): ("FAIL_CLOSED", (GOV, 159, "expired approval/waiver cannot authorize new operations")),
    ("AM-06", "whenUnavailable"): ("BLOCK_NEW_OPERATIONS",
                                   (SBX, 148, "Validation, policy, approval, artifact, RBAC/network intent, or "
                                              "isolation failure prevents launch")),
    ("AM-06", "whenRevoked"): ("OUTCOME_UNKNOWN_RECONCILE",
                               (SBX, 150, "Loss after a possible side effect is `OUTCOME_UNKNOWN` and requires "
                                          "operator/owner reconciliation")),
    ("AM-07", "whenUnavailable"): ("BLOCK_NEW_OPERATIONS",
                                   (MEM, 140, "Database loss rejects all state-changing operations")),
    ("AM-07", "whenRevoked"): ("STOP_RECALL", (MEM, 143, "Deletion first blocks recall")),
    ("AM-08", "whenUnavailable"): ("BLOCK_NEW_OPERATIONS",
                                   (GOV, 158, "Evidence store loss prevents promotion when current evidence cannot be "
                                              "proven")),
    ("AM-08", "whenRevoked"): ("DEACTIVATE_REVOKED", (GOV, 161, "Revocation is append-only and cannot be rolled back")),
    ("AM-09", "whenUnavailable"): ("KEEP_RUNNING_VERSION",
                                   (INFRA, 159, "Registry loss blocks new installation and upgrade but cannot stop "
                                                "ready workloads")),
    ("AM-09", "whenRevoked"): ("DEACTIVATE_REVOKED",
                               (INFRA, 196, "signature, digest, revocation, and license preflight; must fail before "
                                            "apply")),
}
FLAGGED = frozenset((("AM-06", "whenUnavailable"), ("AM-09", "whenRevoked")))
RECONCILIATION = (
    {"id": "MAS-RA-004-temporal-wording", "conflict": "the retained Temporal wording in MAS-RA-004",
     "successor": "MAS-RA-004 erratum packet"},
    {"id": "PI-DURABLE-PARITY-001-temporal-target", "conflict": "PI-DURABLE-PARITY-001's former Temporal target",
     "successor": "PI-DURABLE-PARITY-001 (retitled)"},
    {"id": "reranker-second-home", "conflict": "the reranker's second home", "successor": "MODEL-AUX-001"},
    {"id": "language-updates", "conflict": "the language updates", "successor": "LANG-HOTPATH-DECISION-001"},
)
TOP_MEMBERS = ("schemaVersion", "sources", "vectorFiles", "roadmapPin", "concerns", "reconciliation", "nonClaims")
CONCERN_MEMBERS = ("id", "concern", "authority", "inputs", "othersMay", "enforcementPoints", "whenUnavailable",
                   "whenRevoked", "citations")
DEFAULT_ROOT = 1000


def require(ok: bool, code: str, message: str) -> None:
    if not ok:
        raise ValueError("%s: %s" % (code, message))


def digest(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _json(raw: bytes, code: str):
    def pairs(items):
        keys = [key for key, _ in items]
        require(len(keys) == len(set(keys)), code, "duplicate JSON member")
        return dict(items)

    def constant(name):
        raise ValueError("%s: nonfinite JSON number %s" % (code, name))

    def integer(text):
        try:
            return int(text)
        except ValueError:
            raise ValueError("%s: JSON integer beyond the conversion limit" % code) from None
    require(type(raw) is bytes, code, "the reader returns bytes")
    try:
        return json.loads(raw.decode("utf-8"), object_pairs_hook=pairs, parse_constant=constant, parse_int=integer)
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError):
        raise ValueError("%s: not UTF-8 JSON" % code) from None


def _canonical(value) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def _eq(left, right) -> bool:
    """Type-strict equality: canonical JSON on both sides, so bool, int and float stay distinct."""
    return _canonical(left) == _canonical(right)


def cite(pin) -> dict:
    """A pinned citation as the record writes it."""
    if pin[0] == "item":
        return {"item": pin[1], "quote": pin[2]}
    return {"path": pin[0], "line": pin[1], "quote": pin[2]}


# V0: shape.
def _closed(value, members, where, code="AM_SHAPE"):
    require(type(value) is dict, code, where + " is an object")
    require(set(value) == set(members), code, "members of %s: %s" % (where, sorted(set(value) ^ set(members))))


def _text(value, where, code="AM_SHAPE"):
    require(type(value) is str and value.strip() != "", code, "non-empty text: " + where)


def _hex64(value) -> bool:
    return type(value) is str and len(value) == 64 and all(c in "0123456789abcdef" for c in value)


def _list(value, where, code="AM_SHAPE", nonempty=False):
    require(type(value) is list and (not nonempty or value), code, ("a non-empty list: " if nonempty else "a list: ")
            + where)


def _citation(value, where):
    require(type(value) is dict, "AM_SHAPE", where + " is an object")
    if "item" in value:
        _closed(value, ("item", "quote"), where)
        _text(value["item"], where + ".item")
    else:
        _closed(value, ("path", "line", "quote"), where)
        _text(value["path"], where + ".path")
        require(type(value["line"]) is int and value["line"] >= 1, "AM_SHAPE", where + ".line: an integer >= 1")
    _text(value["quote"], where + ".quote")


def _shape(rec) -> None:
    _closed(rec, TOP_MEMBERS, "the record")
    require(rec["schemaVersion"] == SCHEMA, "AM_SHAPE", "schemaVersion")
    for name in ("sources", "vectorFiles"):
        _list(rec[name], name, nonempty=True)
        for i, row in enumerate(rec[name]):
            _closed(row, ("path", "sha256"), "%s[%d]" % (name, i))
            _text(row["path"], "%s[%d].path" % (name, i))
            require(_hex64(row["sha256"]), "AM_SHAPE", "%s[%d].sha256" % (name, i))
        require([r["path"] for r in rec[name]] == sorted({r["path"] for r in rec[name]}), "AM_SHAPE",
                name + " sorted by path and unique")
    pin = rec["roadmapPin"]
    _closed(pin, ("path", "sha256", "items"), "roadmapPin")
    require(pin["path"] == ROADMAP_PATH, "AM_SHAPE", "roadmapPin.path")
    require(_hex64(pin["sha256"]), "AM_SHAPE", "roadmapPin.sha256: 64 lowercase hex")
    _list(pin["items"], "roadmapPin.items", nonempty=True)
    require(all(type(x) is str and x for x in pin["items"]) and pin["items"] == sorted(set(pin["items"])), "AM_SHAPE",
            "roadmapPin.items sorted and unique")
    _list(rec["concerns"], "concerns", nonempty=True)
    for c in rec["concerns"]:
        where = "concern %s" % (c.get("id") if type(c) is dict else "?")
        _closed(c, CONCERN_MEMBERS, where)
        _text(c["id"], where + ".id")
        _text(c["concern"], where + ".concern")
        a = c["authority"]
        _closed(a, ("harness", "component", "boundary", "citation"), where + ".authority")
        for k in ("harness", "component", "boundary"):
            _text(a[k], where + ".authority." + k)
        _citation(a["citation"], where + ".authority.citation")
        _list(c["inputs"], where + ".inputs")
        for i, row in enumerate(c["inputs"]):
            _closed(row, ("harness", "component", "role"), "%s.inputs[%d]" % (where, i))
            _text(row["harness"], "%s.inputs[%d].harness" % (where, i))
            _text(row["component"], "%s.inputs[%d].component" % (where, i))
            require(row["role"] in ROLES, "AM_SHAPE", "%s.inputs[%d].role: unknown %r" % (where, i, row["role"]))
        _list(c["othersMay"], where + ".othersMay", nonempty=True)
        for i, row in enumerate(c["othersMay"]):
            _closed(row, ("who", "whoKind", "action", "note"), "%s.othersMay[%d]" % (where, i))
            _text(row["who"], "%s.othersMay[%d].who" % (where, i))
            _text(row["note"], "%s.othersMay[%d].note" % (where, i))
            require(row["whoKind"] in WHO_KINDS, "AM_SHAPE", "%s.othersMay[%d].whoKind" % (where, i))
            require(row["action"] in ACTIONS, "AM_SHAPE", "%s.othersMay[%d].action: unknown %r"
                    % (where, i, row["action"]))
        _list(c["enforcementPoints"], where + ".enforcementPoints")
        for i, row in enumerate(c["enforcementPoints"]):
            _closed(row, ("component", "point", "citation"), "%s.enforcementPoints[%d]" % (where, i))
            _text(row["component"], "%s.enforcementPoints[%d].component" % (where, i))
            _text(row["point"], "%s.enforcementPoints[%d].point" % (where, i))
            _citation(row["citation"], "%s.enforcementPoints[%d].citation" % (where, i))
        for kind in ("whenUnavailable", "whenRevoked"):
            b = c[kind]
            _closed(b, ("behaviour", "note", "citation"), where + "." + kind)
            require(type(b["behaviour"]) is str and b["behaviour"] in BEHAVIOURS, "AM_SHAPE",
                    "%s.%s.behaviour: one known behaviour" % (where, kind))
            _text(b["note"], where + "." + kind + ".note")
            _citation(b["citation"], where + "." + kind + ".citation")
        _list(c["citations"], where + ".citations", nonempty=True)
        for i, row in enumerate(c["citations"]):
            _citation(row, "%s.citations[%d]" % (where, i))
    _list(rec["reconciliation"], "reconciliation")
    for i, row in enumerate(rec["reconciliation"]):
        _closed(row, ("id", "conflict", "successor"), "reconciliation[%d]" % i)
        for k in ("id", "conflict", "successor"):
            _text(row[k], "reconciliation[%d].%s" % (i, k))
    _list(rec["nonClaims"], "nonClaims", nonempty=True)
    for i, text in enumerate(rec["nonClaims"]):
        _text(text, "nonClaims[%d]" % i)


def authority_names(cid) -> frozenset:
    """The names a row's authority goes by: its pinned component and every module name (in backticks) of its pinned
    quote, e.g. AM-04's policy-decision and planeon.policy-decision (trust.security-safety.md:83)."""
    _, component, pin = AUTHORITY_PINS[cid]
    return frozenset({component, *pin[2].split("`")[1::2]})


def _citations_of(c):
    yield c["authority"]["citation"]
    for row in c["enforcementPoints"]:
        yield row["citation"]
    yield c["whenUnavailable"]["citation"]
    yield c["whenRevoked"]["citation"]
    yield from c["citations"]


# V6: the reference model of B1-B5 (semantics only, DATA-CORRECTNESS-001 holds concurrency, fencing and clocks).
class _Ledger:
    def __init__(self, root):
        self.root, self.committed, self.up, self.res, self.transitions = root, 0, True, {}, {}

    def _open(self):
        return sum(r["amount"] for r in self.res.values() if r["state"] == "RESERVED")

    def step(self, s):
        op = s["op"]
        if op == "ledger_down":
            self.up = False
            return "down"
        if op == "advisory":  # :177: advisory-only callers proceed only if the profile allows and outbox capacity exists
            return "proceeds" if (not self.up and s["profileAllows"] is True and s["outboxCapacity"] is True) \
                or self.up else "refused"
        key = s["key"]
        if op == "reserve":
            if not self.up:
                return "refused"
            prior = self.res.get(key)
            if prior is not None:  # B3: an exact retry returns the original result; a conflicting reuse fails closed
                return "reserved" if prior["amount"] == s["amount"] and prior["result"] == "reserved" else "refused"
            if self.committed + self._open() + s["amount"] > self.root:
                return "refused"
            self.res[key] = {"amount": s["amount"], "consumed": 0, "state": "RESERVED", "committed": 0, "returned": 0,
                             "result": "reserved"}
            return "reserved"
        r = self.res.get(key)
        if r is None or r["state"] != "RESERVED":  # B1: no open reservation, so no commit, consume or settlement
            if op == "commit" and r is not None and self.transitions.get((key, s["transition"])) == s["amount"]:
                return "replayed"  # B3: commit has its own transition key; a duplicate commit is idempotent
            return "refused"
        if op == "consume":
            if r["consumed"] + s["amount"] > r["amount"]:
                return "refused"
            r["consumed"] += s["amount"]
            return "consumed"
        if op == "commit":
            if s["amount"] > r["amount"]:  # B2: a commit never exceeds its reservation
                return "refused"
            self._settle(r, "COMMITTED", s["amount"])
            self.transitions[(key, s["transition"])] = s["amount"]
            return "committed"
        if op in ("cancel", "expire"):  # B4: consumed usage stays charged; with none, RELEASED or EXPIRED
            if r["consumed"] > 0:
                self._settle(r, "COMMITTED", r["consumed"])
            else:
                self._settle(r, "RELEASED" if op == "cancel" else "EXPIRED", 0)
            return "settled"
        raise ValueError("AM_BUDGET: unknown step %r" % op)

    def _settle(self, r, state, amount):
        r["state"], r["committed"], r["returned"] = state, amount, r["amount"] - amount
        self.committed += amount


STEP_MEMBERS = {"reserve": ("op", "key", "amount"), "consume": ("op", "key", "amount"),
                "commit": ("op", "key", "transition", "amount"), "cancel": ("op", "key"), "expire": ("op", "key"),
                "ledger_down": ("op",),
                "advisory": ("op", "profileAllows", "outboxCapacity")}


def _budget(raw) -> None:
    doc = _json(raw, "AM_BUDGET")
    _closed(doc, ("schemaVersion", "rules", "vectors", "nonClaims"), "the budget vectors", "AM_BUDGET")
    require(doc["schemaVersion"] == BUDGET_SCHEMA, "AM_BUDGET", "schemaVersion")
    _list(doc["rules"], "rules", "AM_BUDGET", nonempty=True)
    require([r.get("id") if type(r) is dict else None for r in doc["rules"]] == ["B%d" % k for k in range(1, 6)],
            "AM_BUDGET", "rules are B1 to B5")
    _list(doc["nonClaims"], "nonClaims", "AM_BUDGET", nonempty=True)
    require(any(type(t) is str and "DATA-CORRECTNESS-001" in t for t in doc["nonClaims"]), "AM_BUDGET",
            "the nonClaims name DATA-CORRECTNESS-001 (write skew, fencing, clocks)")
    _list(doc["vectors"], "vectors", "AM_BUDGET", nonempty=True)
    require([v.get("id") if type(v) is dict else None for v in doc["vectors"]] == ["VB-%02d" % k for k in range(1, 11)],
            "AM_BUDGET", "vectors are VB-01 to VB-10")
    for v in doc["vectors"]:
        _closed(v, ("id", "name", "root", "steps", "results", "final"), v["id"], "AM_BUDGET")
        require(type(v["root"]) is int and v["root"] > 0, "AM_BUDGET", v["id"] + ".root")
        _list(v["steps"], v["id"] + ".steps", "AM_BUDGET", nonempty=True)
        ledger = _Ledger(v["root"])
        got = []
        for s in v["steps"]:
            require(type(s) is dict and s.get("op") in STEP_MEMBERS, "AM_BUDGET", v["id"] + ": a known step")
            _closed(s, STEP_MEMBERS[s["op"]], "%s step %s" % (v["id"], s["op"]), "AM_BUDGET")
            for k in ("amount",):
                if k in s:
                    require(type(s[k]) is int and s[k] >= 0, "AM_BUDGET", v["id"] + ": an amount")
            got.append(ledger.step(s))
        require(_eq(got, v["results"]), "AM_BUDGET", "%s: the results replay as %s" % (v["id"], got))
        final = {k: {"state": r["state"], "committed": r["committed"], "returned": r["returned"]}
                 for k, r in sorted(ledger.res.items())}
        require(_eq(final, v["final"]), "AM_BUDGET", "%s: the final states replay as %s" % (v["id"], final))


def _r12(raw, concerns) -> None:
    doc = _json(raw, "AM_R12_VECTORS")
    _closed(doc, ("schemaVersion", "vectors", "nonClaims"), "the R12 vectors", "AM_R12_VECTORS")
    require(doc["schemaVersion"] == R12_SCHEMA, "AM_R12_VECTORS", "schemaVersion")
    _list(doc["vectors"], "vectors", "AM_R12_VECTORS", nonempty=True)
    require([v.get("id") if type(v) is dict else None for v in doc["vectors"]] == ["R12-V%d" % k for k in range(1, 6)],
            "AM_R12_VECTORS", "vectors are R12-V1 to R12-V5")
    for v in doc["vectors"]:
        _closed(v, ("id", "row", "actor", "claimedAction", "case", "expected"), v["id"], "AM_R12_VECTORS")
        require(v["row"] in concerns, "AM_R12_VECTORS", v["id"] + " names no concern row")
        require(v["expected"] == "REFUSED", "AM_R12_VECTORS", v["id"] + ": the expected verdict is REFUSED")
        _text(v["case"], v["id"] + ".case", "AM_R12_VECTORS")
        _text(v["actor"], v["id"] + ".actor", "AM_R12_VECTORS")
        _text(v["claimedAction"], v["id"] + ".claimedAction", "AM_R12_VECTORS")
        # The map's rule over the vector's declared actor and act: only the row's authority (by any of its names)
        # performs an authority act; any other actor is refused.
        refused = v["claimedAction"] in AUTHORITY_VERBS and v["actor"] not in authority_names(v["row"])
        require(refused, "AM_R12_VECTORS", v["id"] + ": the map does not refuse it")


def check(read, packets) -> dict:
    """Validate the authority map (V0-V9). `packets` is the set of published packet ids (file stems)."""
    require(isinstance(packets, (set, frozenset)) and all(type(p) is str for p in packets), "AM_SHAPE", "packet set")
    rec = _json(read(RECORD_PATH), "AM_SHAPE")
    _shape(rec)

    # V1: sources and vector files.
    require(_eq(rec["sources"], [{"path": p, "sha256": SOURCES[p]} for p in sorted(SOURCES)]), "AM_SOURCES",
            "the thirteen pinned sources")
    lines = {}
    for path in sorted(SOURCES):
        raw = read(path)
        require(digest(raw) == SOURCES[path], "AM_SOURCES", "bytes of " + path)
        lines[path] = raw.decode("utf-8").splitlines()
    require([r["path"] for r in rec["vectorFiles"]] == sorted((BUDGET_PATH, R12_PATH)), "AM_SOURCES", "vectorFiles")
    vec = {}
    for row in rec["vectorFiles"]:
        vec[row["path"]] = read(row["path"])
        require(digest(vec[row["path"]]) == row["sha256"], "AM_SOURCES", "bytes of " + row["path"])

    # V2: citations, the record's and the pins'.
    items = set(rec["roadmapPin"]["items"])
    cited_items = set()

    def stated(c, where):
        if "item" in c:
            require(c["item"] in items, "AM_CITATIONS", where + ": item not in roadmapPin: " + c["item"])
            cited_items.add(c["item"])
            return
        require(c["path"] in lines, "AM_CITATIONS", where + ": not a pinned source: " + c["path"])
        require(c["line"] <= len(lines[c["path"]]), "AM_CITATIONS", where + ": no such line")
        require(c["quote"] in lines[c["path"]][c["line"] - 1], "AM_CITATIONS",
                "%s: the quote is not on %s:%d" % (where, c["path"], c["line"]))
    for c in rec["concerns"]:
        for i, ct in enumerate(_citations_of(c)):
            stated(ct, "%s citation %d" % (c["id"], i))
    for row, pin in AUTHORITY_PINS.items():
        if pin[2][0] != "item":
            stated(cite(pin[2]), row + " pinned authority")
    for key, pin in BEHAVIOUR_PINS.items():
        if pin[1][0] != "item":
            stated(cite(pin[1]), "%s pinned %s" % key)
    require(cited_items == items, "AM_CITATIONS", "roadmapPin.items are exactly the cited items")

    # V3: one authority per concern, equal to its pin.
    ids = [c["id"] for c in rec["concerns"]]
    require(ids == list(CONCERN_IDS), "AM_ONE_AUTHORITY", "exactly AM-01 to AM-09, sorted: %s" % ids)
    require(not set(ROLES) & set(AUTHORITY_VERBS), "AM_ONE_AUTHORITY", "the role vocabulary holds an authority verb")
    for c in rec["concerns"]:
        a = c["authority"]
        harness, component, pin = AUTHORITY_PINS[c["id"]]
        # The pins hold the external sentinel on AM-06 only, so this comparison also keeps it off every other row.
        require(_eq([a["harness"], a["component"], a["citation"]], [harness, component, cite(pin)]),
                "AM_ONE_AUTHORITY", c["id"] + ": the authority or its citation is not the pinned one")
        names = authority_names(c["id"])
        for row in c["inputs"]:  # compared by component, whatever the harness label
            require(row["component"] not in names, "AM_ONE_AUTHORITY", c["id"] + ": an input repeats the authority")
        for row in c["othersMay"]:
            if row["whoKind"] == "COMPONENT":
                require(row["who"] not in names, "AM_ONE_AUTHORITY", c["id"] + ": a COMPONENT row names the authority")

    # V4: enforcement points.
    for c in rec["concerns"]:
        require(len(c["enforcementPoints"]) >= 1, "AM_ENFORCEMENT", c["id"] + ": no enforcement point")

    # V5: failure modes, equal to their pins.
    for c in rec["concerns"]:
        for kind in ("whenUnavailable", "whenRevoked"):
            behaviour, pin = BEHAVIOUR_PINS[(c["id"], kind)]
            require(_eq([c[kind]["behaviour"], c[kind]["citation"]], [behaviour, cite(pin)]), "AM_FAILURE_MODES",
                    "%s %s: the behaviour or its citation is not the pinned one" % (c["id"], kind))

    # V6: the budget model.
    try:
        _budget(vec[BUDGET_PATH])
    except ValueError:
        raise
    except Exception as error:
        raise ValueError("AM_BUDGET: %s: %s" % (type(error).__name__, error)) from None

    # V7: reconciliation, and agreement with the technology record (fail closed on an unknown member).
    require(_eq(rec["reconciliation"], list(RECONCILIATION)), "AM_RECONCILIATION", "the four entries and successors")
    tech = _json(read(TECH_PATH), "AM_RECONCILIATION")
    require(type(tech) is dict, "AM_RECONCILIATION", "the technology record is an object")
    members = frozenset(tech)
    if members != TECH_BASE_MEMBERS:
        require(members == TECH_BASE_MEMBERS | {TECH_LIST_MEMBER}, "AM_RECONCILIATION_UNKNOWN_MEMBER",
                "the technology record's members: %s" % sorted(members ^ TECH_BASE_MEMBERS))
        listed = tech[TECH_LIST_MEMBER]
        require(type(listed) is list and all(type(e) is dict for e in listed), "AM_RECONCILIATION",
                TECH_LIST_MEMBER + " is a list of objects")
        for entry in RECONCILIATION:
            require(any(e.get("id") == entry["id"] and e.get("successor") == entry["successor"] for e in listed),
                    "AM_RECONCILIATION", "the technology record disagrees on " + entry["id"])

    # V8: the R12 vectors.
    try:
        _r12(vec[R12_PATH], {c["id"]: c for c in rec["concerns"]})
    except ValueError:
        raise
    except Exception as error:
        raise ValueError("AM_R12_VECTORS: %s: %s" % (type(error).__name__, error)) from None

    # V9: the registry: the base plus at most the one MET-ADOPT-007/packet rider, appended last.
    raw = read(BRIEFS_PATH)
    if digest(raw) != BRIEFS_BASE_SHA256:
        reg = _json(raw, "AM_REGISTRY")
        try:
            briefs = reg["briefs"]
            base = dict(reg, briefs=briefs[:-1])
            again = (json.dumps(base, indent=1, ensure_ascii=False) + "\n").encode("utf-8")
        except Exception as error:
            raise ValueError("AM_REGISTRY: %s: %s" % (type(error).__name__, error)) from None
        require(digest(again) == BRIEFS_BASE_SHA256 and _eq(briefs[-1], RIDER), "AM_REGISTRY",
                "the registry is the base plus one MET-ADOPT-007/packet rider, appended last")
        require(json.dumps(reg, indent=1, ensure_ascii=False).encode("utf-8") + b"\n" == raw, "AM_REGISTRY",
                "the registry's serialization")
    return {"concerns": len(rec["concerns"]), "pins": len(AUTHORITY_PINS) + len(BEHAVIOUR_PINS),
            "flagged": sorted("%s %s" % k for k in FLAGGED), "budgetVectors": 10, "r12Vectors": 5}
