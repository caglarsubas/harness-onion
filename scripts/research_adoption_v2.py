#!/usr/bin/env python3
"""Research adoption v2 (architecture/research-adoption-v2/crosswalk.json, MAS-RA-000): the October 2026 corpus.

check(read) validates the closed record through an injected byte reader:
- the predecessor (research-adoption.json, MET-ADOPT-002) and its map stay byte-identical, and v2 carries the
  predecessor's policies unchanged;
- every paper, standard and codebase is cross-referenced to the eight layers, the sixteen harnesses of the predecessor's
  mappings and the MAS-RA items, and the derived per-harness rows equal their recomputation;
- every seed-paper claim carries its kind, status and pages, and every grounded fact and contract implication cites
  pages;
- each codebase's licence-policy outcome is the pinned policy's classification of the GitHub-reported identifier, and
  its reuse mode is consistent with that outcome in both directions;
- the acceptance IDs for MAS-RA-001..010 are proposed, not published: no proposed packet ID names an existing packet;
- the record and README carry no personal data (e-mail addresses, author names in citations, personal handles, local
  paths), and the README is exactly render(record).
Data checks only: no imports beyond the standard library, no network, no execution authority.
"""
from __future__ import annotations

import hashlib
import json
import math
import re

RECORD_PATH = "architecture/research-adoption-v2/crosswalk.json"
README_PATH = "architecture/research-adoption-v2/README.md"
PREDECESSOR_PATH = "architecture/research-adoption.json"
PREDECESSOR_SHA256 = "18dadbbe9aa29b69d18b9ded27e27f6057cf03b437190d14477b2c6908dbc5d5"
MAP_PATH = "docs/alpha-2/HARNESS_PAPER_REPOSITORY_MAP.md"
MAP_SHA256 = "f6a891e8bdbcc579e60800773addd70ca29a2c4021c2dc95af62be93e91f061d"
POLICY_PATH = "legal/third-party-license-policy.yaml"
POLICY_SHA256 = "fa3a4398acafc3960eaaae9f5396d4e96d91e6ff252b83f6c53e1f5f0d8a40d0"
META_BASE = "93d32e1cc5125b5878f51de31c61ada29e1fa6da"
SCHEMA = "planeon.internal.research-adoption/v2"
MAX_BYTES = 4_194_304
MAX_DEPTH = 32

# legal/third-party-license-policy.yaml 0.3.0 (pinned above by digest): every list a single SPDX identifier is
# classified against, in the policy's precedence. GitHub reports one identifier per repository, so the mixed-set rule
# does not arise; an identifier on no list is DENY_UNKNOWN_LICENSE (the policy's unknownExpressionOutcome).
DENIED = frozenset({"SSPL-1.0", "BUSL-1.1", "Elastic-2.0"})
PLANNED_UNRESOLVED = frozenset({"NOASSERTION"})
OPTIONAL_EXPLICIT_REVIEW = frozenset({"GPL-2.0-only", "GPL-3.0-only", "AGPL-3.0-only", "LGPL-3.0-only",
                                      "LGPL-3.0-or-later", "Apache-2.0 AND LGPL-3.0-or-later",
                                      "Apache-2.0 AND LGPL-3.0-or-later AND MIT"})
OPEN_CONTENT = frozenset({"CC0-1.0", "CC-BY-4.0"})
ALLOWED_EXCEPTION_EXPRESSION = frozenset({"Apache-2.0 WITH LLVM-exception", "Apache-2.0 OR BSD-2-Clause",
                                          "Apache-2.0 OR BSD-3-Clause"})
DEFAULT_ALLOWED = frozenset({"Apache-2.0", "0BSD", "MIT", "BSD-2-Clause", "BSD-3-Clause", "ISC", "MPL-2.0",
                             "PostgreSQL", "PSF-2.0", "Unicode-3.0", "W3C-20150513"})
REUSABLE = ("DEFAULT_ALLOWED", "ALLOWED_EXCEPTION_EXPRESSION")

TOP_KEYS = ("schemaVersion", "workItem", "metaPacketId", "metaBase", "evidenceClass", "checkedAt", "predecessor",
            "relation", "policies", "boundaries", "licensePolicy", "definitions", "decisions", "sources", "priorityRule",
            "layers", "principles", "critique", "papers", "standards", "upstreams", "recheck", "mappings", "acceptance",
            "openItems", "nonClaims")
BOUNDARIES = ("publicContractChange", "selectorChange", "catalogChange", "policyChange", "runtimeChange",
              "packetDispatch", "researchInputsCopied", "groundingRecordsVendored", "networkAtValidation")
DECISIONS = ("Q-RA1", "Q-RA2", "HO-D1", "HO-D2", "HO-D3")
# sha256 of each decision's exact text, as recorded (Q-RA1 and Q-RA2 verbatim from the owner via the lane monitor; the
# HO decisions verbatim from the roadmap's research block).
DECISION_SHA256 = {"Q-RA1": "cdeade8e5755d9e7c9f3b56da33b2caaf3a4ae70294f7e8d2545b1279f429200", "Q-RA2": "a3468dfaca7d6859e32a889745f186d9925cd90d7132c45f959ff99b60b8562f", "HO-D1": "8ed140369cffe1a163a7246a8ded7685f4726f9a7f2378a5453806121ddf92bb", "HO-D2": "1d2308a94c69c01647e695d1c801482f981d49a54733ae4c911ed014842ad5bc", "HO-D3": "f737c9007ed26f87819d0c85a0c68afaafec4b62e5c9e57c0a926fd4b9ff651a"}
SOURCES = ("RS-GPT", "RS-GEMINI", "RS-CLAUDE")
LAYERS = tuple("L%d" % n for n in range(1, 9))
PRINCIPLES = tuple("P%d" % n for n in range(1, 14))
ITEMS = tuple("MAS-RA-%03d" % n for n in range(1, 11))
ROADMAP_ITEMS = ("MAS-RA-000",) + ITEMS
STANDARDS = ("MCP", "A2A", "OTEL-GENAI", "SLSA", "SIGSTORE")
REUSE_MODES = ("REFERENCE_DESIGN", "VENDOR_CANDIDATE", "PLANNED_BASELINE", "TEST_ORACLE_CANDIDATE", "LICENSE_BLOCKED",
               "INDEX_ONLY", "NOT_RETRIEVABLE", "NOT_APPLICABLE")
# Policy outcomes each reuse mode admits (the other direction: NOT_APPLICABLE exactly when there is no repository,
# NOT_RETRIEVABLE exactly when a named repository was not found).
REUSE_OUTCOMES = {
    "REFERENCE_DESIGN": {"DEFAULT_ALLOWED", "ALLOWED_EXCEPTION_EXPRESSION", "OPEN_CONTENT"},
    "VENDOR_CANDIDATE": {"DEFAULT_ALLOWED"},
    "PLANNED_BASELINE": {"DEFAULT_ALLOWED", "PLANNED_UNRESOLVED"},
    "TEST_ORACLE_CANDIDATE": {"DEFAULT_ALLOWED", "OPEN_CONTENT"},
    "LICENSE_BLOCKED": {"PLANNED_UNRESOLVED", "DENY_MISSING_LICENSE", "DENIED", "DENY_UNKNOWN_LICENSE",
                        "OPTIONAL_EXPLICIT_REVIEW"},
    "INDEX_ONLY": {"DEFAULT_ALLOWED", "ALLOWED_EXCEPTION_EXPRESSION", "OPEN_CONTENT", "PLANNED_UNRESOLVED",
                   "DENY_MISSING_LICENSE", "DENIED", "DENY_UNKNOWN_LICENSE", "OPTIONAL_EXPLICIT_REVIEW"},
    "NOT_RETRIEVABLE": {"NOT_RETRIEVABLE"},
    "NOT_APPLICABLE": {"NO_REPOSITORY"},
}
POLICY_OUTCOMES = ("DEFAULT_ALLOWED", "ALLOWED_EXCEPTION_EXPRESSION", "OPEN_CONTENT", "OPTIONAL_EXPLICIT_REVIEW",
                   "PLANNED_UNRESOLVED", "DENIED", "DENY_MISSING_LICENSE", "DENY_UNKNOWN_LICENSE", "NOT_RETRIEVABLE",
                   "NO_REPOSITORY")
CEILINGS = ("REUSE_AFTER_GATES", "DESIGN_REFERENCE_ONLY")
ALIGNMENTS = ("ADOPTION_CANDIDATE", "CONCEPTUAL_ALIGNMENT")
CLAIM_KINDS = ("SYNTHESIS_CLAIM", "AVAILABILITY_CHECK", "VENUE_CHECK")
CLAIM_STATUS = ("VERIFIED", "CORRECTED", "NOT_FOUND")
SEED_CLAIMS = {"SYNTHESIS_CLAIM": {"VERIFIED": 45, "CORRECTED": 4, "NOT_FOUND": 0},
               "AVAILABILITY_CHECK": {"VERIFIED": 4, "CORRECTED": 0, "NOT_FOUND": 6},
               "VENUE_CHECK": {"VERIFIED": 1, "CORRECTED": 0, "NOT_FOUND": 0}}
DEFINITION_KEYS = ("reuseModes", "alignment", "licenceCeiling", "policyOutcomes", "claimKinds", "claimStatus",
                   "secondaryNames")
COUNTS = {"SEED": 8, "SECONDARY": 11, "upstreams": 47, "repositories": 41, "openItems": 7}
GATES = {"MAS-RA-002": ["CONF-WG-001"], "MAS-RA-008": ["CONF-A3-001"]}
CRITIQUE = ("CE-1", "CE-2", "CE-3", "CE-4")
HEX40 = re.compile(r"[0-9a-f]{40}\Z")
HEX64 = re.compile(r"[0-9a-f]{64}\Z")
ARXIV = re.compile(r"[0-9]{4}\.[0-9]{4,5}\Z")
REPO = re.compile(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+\Z")
DATE = re.compile(r"20[0-9]{2}-[01][0-9]-[0-3][0-9]\Z")
TIMESTAMP = re.compile(r"20[0-9]{2}-[01][0-9]-[0-3][0-9]T[0-2][0-9]:[0-5][0-9]:[0-5][0-9]Z\Z")
PAGE_REF = re.compile(r"\bpp?\.\s?[0-9]+|\(pp?[0-9]+(?:[-–][0-9]+)?(?:,\s*pp?[0-9]+(?:[-–][0-9]+)?)*\)")
PACKET_ID = re.compile(r"(?:MET|CONF)-MAS-[0-9]{3}\Z")
CLAIM_NUMBERING = re.compile(r"[0-9]+[a-z]?\.\s")
PROMPT_RESIDUE = ("if stated", "give the", "exact list", "exact names", "whatever the paper", "report exact",
                  "name the ", "(Apache-2.0?)", "if any", "if printed", "the paper's own wording")
# Personal data that must not appear anywhere in the public record or README.
HYGIENE = (re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*\.[A-Za-z]{2,}"),
           re.compile(r"\b[A-Za-z0-9._-]+ at [A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*\.[A-Za-z]{2,}\b(?![/\w-]|\.[A-Za-z0-9])", re.I),
           re.compile(r"corresponding author|student researcher|\bet al\b|[(\[{]\s*at\s*[)\]}]|[(\[{]\s*dot\s*[)\]}]",
                      re.I),
           re.compile(r"/Users/|/home/|~/|huggingface\.co/datasets/"))


def require(ok: bool, message: str) -> None:
    if not ok:
        raise ValueError(message)


def digest(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _float(text: str) -> float:
    value = float(text)
    require(math.isfinite(value), "nonfinite number")
    return value


def _json(raw: bytes):
    def pairs(items):
        keys = [key for key, _ in items]
        require(len(keys) == len(set(keys)), "duplicate key")
        return dict(items)

    require(type(raw) is bytes and 0 < len(raw) <= MAX_BYTES, "record size")
    return json.loads(raw.decode("utf-8"), object_pairs_hook=pairs, parse_float=_float,
                      parse_constant=lambda name: (_ for _ in ()).throw(ValueError("nonfinite number")))


def _depth(value, level=0) -> None:
    require(level <= MAX_DEPTH, "record nesting")
    if type(value) is dict:
        for item in value.values():
            _depth(item, level + 1)
    elif type(value) is list:
        for item in value:
            _depth(item, level + 1)


def _strings(value):
    if type(value) is str:
        yield value
    elif type(value) is dict:
        for key, item in value.items():
            yield key
            yield from _strings(item)
    elif type(value) is list:
        for item in value:
            yield from _strings(item)


def _clean(text: str, message: str) -> None:
    require(not any(rule.search(text) for rule in HYGIENE), message)


def _text(value, message):
    require(type(value) is str and value.strip() == value and bool(value), message)


def _texts(value, message):
    require(type(value) is list and value, message)
    for item in value:
        _text(item, message)


def _subset(value, allowed, message, nonempty=False):
    require(type(value) is list and all(type(v) is str for v in value) and len(value) == len(set(value))
            and set(value) <= set(allowed) and (bool(value) or not nonempty), message)


def _closed(value, keys, message, optional=()):
    require(type(value) is dict and set(keys) <= set(value) <= set(keys) | set(optional), message)


def classify(spdx):
    """The pinned policy's outcome for one GitHub-reported SPDX identifier (None: no licence)."""
    if spdx is None:
        return "DENY_MISSING_LICENSE"
    for outcome, members in (("DENIED", DENIED), ("PLANNED_UNRESOLVED", PLANNED_UNRESOLVED),
                             ("OPTIONAL_EXPLICIT_REVIEW", OPTIONAL_EXPLICIT_REVIEW), ("OPEN_CONTENT", OPEN_CONTENT),
                             ("ALLOWED_EXCEPTION_EXPRESSION", ALLOWED_EXCEPTION_EXPRESSION),
                             ("DEFAULT_ALLOWED", DEFAULT_ALLOWED)):
        if spdx in members:
            return outcome
    return "DENY_UNKNOWN_LICENSE"


def ceiling(outcome):
    return "REUSE_AFTER_GATES" if outcome in REUSABLE else "DESIGN_REFERENCE_ONLY"


def _pages(value, message, allow_empty=False):
    require(type(value) is list and (bool(value) or allow_empty)
            and all(type(p) is int and p > 0 for p in value) and value == sorted(set(value)), message)


def check(read) -> dict:
    try:
        return _check(read)
    except (KeyError, TypeError, AttributeError, IndexError, UnicodeDecodeError, json.JSONDecodeError,
            RecursionError, OSError) as exc:
        raise ValueError("malformed research adoption v2 record: %s" % type(exc).__name__) from None


def _check(read) -> dict:
    x = _json(read(RECORD_PATH))
    _depth(x)
    require(type(x) is dict and tuple(x) == TOP_KEYS, "closed top-level keys in order")
    for text in _strings(x):
        _clean(text, "no personal data in the public record")
    require(x["schemaVersion"] == SCHEMA and x["workItem"] == "MAS-RA-000" and x["metaPacketId"] == "MET-ADOPT-003"
            and x["metaBase"] == META_BASE and x["evidenceClass"] == "META_PLANNING_ONLY"
            and x["checkedAt"] == "2026-10-12", "planning boundary")

    pred_raw = read(PREDECESSOR_PATH)
    map_raw = read(MAP_PATH)
    require(digest(pred_raw) == PREDECESSOR_SHA256 and digest(map_raw) == MAP_SHA256,
            "predecessor and map byte-identical")
    pred = _json(pred_raw)
    p = x["predecessor"]
    require(p == {"path": PREDECESSOR_PATH, "sha256": PREDECESSOR_SHA256,
                  "schemaVersion": "planeon.internal.research-adoption/v1", "metaPacketId": "MET-ADOPT-002",
                  "checkedAt": "2026-09-15", "retained": True,
                  "map": {"path": MAP_PATH, "sha256": MAP_SHA256, "retained": True}}, "predecessor record")
    require(pred["schemaVersion"] == p["schemaVersion"] and pred["metaPacketId"] == p["metaPacketId"]
            and pred["checkedAt"] == p["checkedAt"], "predecessor identity")
    _text(x["relation"], "relation")
    require(x["relation"].startswith("SUCCESSOR_OVERLAY: "), "successor overlay")
    require(x["policies"] == pred["policies"], "predecessor policies unchanged")
    require(type(x["boundaries"]) is dict and tuple(x["boundaries"]) == BOUNDARIES
            and all(v is False for v in x["boundaries"].values()), "no contract, runtime or copy change")
    _closed(x["licensePolicy"], ("path", "sha256", "policyVersion", "appliedTo"), "licence policy record")
    require(digest(read(POLICY_PATH)) == POLICY_SHA256 and x["licensePolicy"]["path"] == POLICY_PATH
            and x["licensePolicy"]["sha256"] == POLICY_SHA256 and x["licensePolicy"]["policyVersion"] == "0.3.0",
            "licence policy pinned")
    _text(x["licensePolicy"]["appliedTo"], "licence policy scope")

    d = x["definitions"]
    require(type(d) is dict and tuple(d) == DEFINITION_KEYS, "closed definitions")
    for key, members in (("reuseModes", REUSE_MODES), ("alignment", ALIGNMENTS), ("licenceCeiling", CEILINGS),
                         ("policyOutcomes", POLICY_OUTCOMES), ("claimKinds", CLAIM_KINDS),
                         ("claimStatus", CLAIM_STATUS)):
        require(type(d[key]) is dict and tuple(d[key]) == members, "definitions of " + key)
        for text in d[key].values():
            _text(text, "definition text")
    _text(d["secondaryNames"], "secondary naming rule")

    require([e["id"] for e in x["decisions"]] == list(DECISIONS), "decisions Q-RA1, Q-RA2, HO-D1..HO-D3")
    for e in x["decisions"]:
        _closed(e, ("id", "date", "selected", "by", "text"), "decision record")
        _text(e["text"], "decision text")
        require(digest(e["text"].encode("utf-8")) == DECISION_SHA256[e["id"]], "decision text verbatim: " + e["id"])
        require(e["date"] == "2026-10-12", "decision date")
        if e["id"].startswith("Q-RA"):
            require(e["selected"] == "a" and e["by"] == "owner (via the lane monitor)", "owner decision (a)")
        else:
            require(e["selected"] is None and e["by"] == "roadmap session at the owner's request"
                    and e["text"].startswith(e["id"] + " "), "handover decision")

    require([s["id"] for s in x["sources"]] == list(SOURCES), "three syntheses")
    for s in x["sources"]:
        _closed(s, ("id", "name", "sha256", "role", "includedAs", "copied", "summary"), "source record")
        require(type(s["name"]) is str and "/" not in s["name"] and HEX64.match(s["sha256"])
                and s["role"] == "USER_RESEARCH_INPUT_NOT_EXECUTION_AUTHORITY"
                and s["includedAs"] == "CURATED_CROSSWALK_NOT_EXHAUSTIVE_REPUBLICATION" and s["copied"] is False,
                "research input, digest only, not authority")
        _text(s["summary"], "source summary")
    _text(x["priorityRule"], "priority rule")

    harnesses = [m["harnessId"] for m in pred["mappings"]]
    require(len(harnesses) == 16 and [m["number"] for m in pred["mappings"]] == list(range(1, 17)),
            "the predecessor's sixteen harnesses")
    require([l["key"] for l in x["layers"]] == list(LAYERS), "eight layers")
    for l in x["layers"]:
        _closed(l, ("key", "name", "question", "harnessIds", "items", "evidence"), "layer record")
        _subset(l["harnessIds"], harnesses, "layer harnesses", nonempty=True)
        _subset(l["items"], ROADMAP_ITEMS, "layer items", nonempty=True)
        for key in ("name", "question", "evidence"):
            _text(l[key], "layer text")
    require([q["id"] for q in x["principles"]] == list(PRINCIPLES), "thirteen principles")
    for q in x["principles"]:
        _closed(q, ("id", "principle", "counterEvidence"), "principle record")
        _text(q["principle"], "principle")
        _text(q["counterEvidence"], "principle counter-evidence")

    upstream_ids = [u["id"] for u in x["upstreams"]]
    require(len(upstream_ids) == len(set(upstream_ids)) == COUNTS["upstreams"], "47 codebases")
    reuse = {u["id"]: u["reuseMode"] for u in x["upstreams"]}
    papers = x["papers"]
    paper_ids = [q["id"] for q in papers]
    require(len(paper_ids) == len(set(paper_ids)), "unique papers")
    require([q["corpus"] for q in papers] == ["SEED"] * COUNTS["SEED"] + ["SECONDARY"] * COUNTS["SECONDARY"],
            "eight seed then eleven secondary")
    tally = {kind: {status: 0 for status in CLAIM_STATUS} for kind in CLAIM_KINDS}
    back = {u: [] for u in upstream_ids}
    for q in papers:
        seed = q["corpus"] == "SEED"
        common = ("id", "url", "short", "firstPublicationYear", "corpus", "sourceInputs", "verification", "layers",
                  "harnessIds", "items", "alignment", "upstreams")
        if seed:
            _closed(q, common + ("title", "status", "pdf", "readAt", "claimCounts", "licenceStatedInPaper",
                                 "codeAvailability", "grounding"), "seed paper record")
        else:
            _closed(q, common + ("name", "synthesisMark", "reported"), "secondary paper record", ("synthesisMarkNote",))
        require(ARXIV.match(q["id"]) and q["url"] == "https://arxiv.org/abs/" + q["id"]
                and q["firstPublicationYear"] == 2000 + int(q["id"][:2]), "primary paper identity")
        _text(q["short"], "paper short name")
        _subset(q["sourceInputs"], SOURCES, "paper named by a synthesis", nonempty=True)
        _subset(q["layers"], LAYERS, "paper layers", nonempty=True)
        _subset(q["harnessIds"], harnesses, "paper harness rows", nonempty=True)
        _subset(q["items"], ITEMS, "paper items", nonempty=True)
        _subset(q["upstreams"], upstream_ids, "paper codebases")
        for u in q["upstreams"]:
            back[u].append(q["id"])
        adopt = any(reuse[u] == "VENDOR_CANDIDATE" for u in q["upstreams"])
        require(q["alignment"] == ("ADOPTION_CANDIDATE" if adopt else "CONCEPTUAL_ALIGNMENT"),
                "adoption candidate only through a vendor-candidate codebase")
        if not seed:
            require(q["verification"] == "SECONDARY_AS_REPORTED" and q["synthesisMark"] == "VERIFIED",
                    "secondary figures as reported")
            _text(q["name"], "secondary name")
            _text(q["reported"], "secondary reported figures")
            if "synthesisMarkNote" in q:
                _text(q["synthesisMarkNote"], "synthesis mark note")
            continue
        for key in ("title", "status", "codeAvailability"):
            _text(q[key], "seed text")
        require(q["verification"] == "FULL_TEXT_READ_CLAIMS_CHECKED" and q["readAt"] == "2026-10-12", "read in full")
        _closed(q["pdf"], ("name", "sha256", "copied"), "PDF record")
        require(q["pdf"]["copied"] is False and HEX64.match(q["pdf"]["sha256"]) and type(q["pdf"]["name"]) is str
                and q["pdf"]["name"].startswith(q["id"]) and q["pdf"]["name"].endswith(".pdf"), "PDF by digest only")
        g = q["grounding"]
        _closed(g, ("record", "recordSha256", "vendored", "claims", "facts", "contractImplications"), "grounding record")
        require(g["vendored"] is False and HEX64.match(g["recordSha256"]) and type(g["record"]) is str
                and g["record"].endswith(".json") and "/" not in g["record"], "grounding by digest, embedded as derived data")
        require(type(g["claims"]) is list and g["claims"]
                and [c.get("n") for c in g["claims"]] == list(range(1, len(g["claims"]) + 1)), "claims numbered")
        counts = {kind: {status: 0 for status in CLAIM_STATUS} for kind in CLAIM_KINDS}
        for c in g["claims"]:
            _closed(c, ("n", "kind", "claim", "status", "pages", "finding"), "claim record", ("statusDetail",))
            require(c["kind"] in CLAIM_KINDS and c["status"] in CLAIM_STATUS, "claim kind and status")
            require(c["kind"] != "SYNTHESIS_CLAIM" or c["status"] != "NOT_FOUND",
                    "a synthesis claim the paper lacks is CORRECTED, not NOT_FOUND")
            _pages(c["pages"], "claim pages", allow_empty=c["status"] == "NOT_FOUND")
            _text(c["claim"], "claim text")
            require(not CLAIM_NUMBERING.match(c["claim"]) and not any(r in c["claim"] for r in PROMPT_RESIDUE),
                    "claim text without numbering or prompt wording")
            _text(c["finding"], "claim finding")
            if "statusDetail" in c:
                _text(c["statusDetail"], "status detail")
            counts[c["kind"]][c["status"]] += 1
            tally[c["kind"]][c["status"]] += 1
        require(q["claimCounts"] == counts, "claim counts equal the claims")
        # licenceStatedInPaper follows the licence checks: false exactly when a check naming a licence found none,
        # either as its status or, for a check verified for code, in its status detail.
        licence_checks = [c for c in g["claims"] if c["kind"] == "AVAILABILITY_CHECK" and "licen" in c["claim"].lower()]
        require(licence_checks, "every seed paper has a licence check")
        for c in licence_checks:
            detail = c.get("statusDetail", "")
            require(c["status"] == "NOT_FOUND" or ("NOT_FOUND" in detail and "licen" in detail.lower())
                    or "NOT_FOUND" not in detail, "a licence check's status detail names what was not found")
            if c["status"] == "VERIFIED":
                require("licen" in detail.lower(), "a licence check verified for code states the licence outcome")
        missing = any(c["status"] == "NOT_FOUND" or ("NOT_FOUND" in c.get("statusDetail", "")
                                                    and "licen" in c.get("statusDetail", "").lower())
                      for c in licence_checks)
        require(q["licenceStatedInPaper"] is (not missing), "licence statement follows the licence checks")
        _texts(g["facts"], "grounded facts")
        _texts(g["contractImplications"], "contract implications")
        for text in g["facts"] + g["contractImplications"]:
            require(PAGE_REF.search(text) is not None, "every grounded fact and implication cites pages")
    require(tally == SEED_CLAIMS, "seed claims by kind")

    require([s["id"] for s in x["standards"]] == list(STANDARDS), "five standards")
    pred_repos = {u["repository"] for u in pred["upstreams"]}
    for s in x["standards"]:
        _closed(s, ("id", "name", "url", "layers", "items", "role", "predecessorUpstreams", "harnessIds",
                    "sourceInputs", "verification"), "standard record")
        require(type(s["url"]) is str and s["url"].startswith("https://")
                and s["verification"] == "NAMED_BY_SYNTHESES_NOT_RECHECKED", "standard reference")
        _text(s["name"], "standard name")
        _subset(s["layers"], LAYERS, "standard layers", nonempty=True)
        _subset(s["harnessIds"], harnesses, "standard harnesses", nonempty=True)
        _subset(s["items"], ITEMS, "standard items")
        _subset(s["sourceInputs"], SOURCES, "standard named by a synthesis", nonempty=True)
        _subset(s["predecessorUpstreams"], pred_repos, "standard's predecessor upstreams")
        _text(s["role"], "standard role")

    map_text = map_raw.decode("utf-8")
    found, not_found = [], []
    for u in x["upstreams"]:
        _closed(u, ("id", "repository", "url", "sourceUrl", "reuseMode", "layers", "harnessIds", "items", "papers",
                    "what", "caveat", "roadmapCheck", "packetCheck", "policyOutcome", "licenceCeiling",
                    "inPredecessor", "checkedAt", "evidenceClass", "licenseReview", "qualificationStatus",
                    "releaseVersion", "artifactDigest"), "codebase record", ("licenseNote", "predecessorMapMention"))
        require(u["reuseMode"] in REUSE_MODES and u["policyOutcome"] in POLICY_OUTCOMES, "reuse mode and outcome")
        _subset(u["layers"], LAYERS, "codebase layers", nonempty=True)
        _subset(u["harnessIds"], harnesses, "codebase harnesses", nonempty=True)
        _subset(u["items"], ROADMAP_ITEMS, "codebase items", nonempty=True)
        require(u["papers"] == back[u["id"]], "codebase paper links equal the papers' links")
        _text(u["what"], "codebase text")
        require(type(u["caveat"]) is str and u["caveat"].strip() == u["caveat"], "codebase caveat")
        if "licenseNote" in u:
            _text(u["licenseNote"], "licence note")
        require(u["checkedAt"] == "2026-10-12" and u["evidenceClass"] == "GITHUB_METADATA_NOT_ARTIFACT_QUALIFICATION"
                and u["licenseReview"] == "PINNED_ARTIFACT_REVIEW_REQUIRED" and u["qualificationStatus"] == "NOT_CLAIMED"
                and u["releaseVersion"] is None and u["artifactDigest"] is None, "metadata, not qualification")
        name, pc, rc = u["repository"], u["packetCheck"], u["roadmapCheck"]
        if name is None:
            require(u["url"] is None or (type(u["url"]) is str and u["url"].startswith("https://")), "pattern url")
            require(u["sourceUrl"] is None and rc is None and pc is None and u["policyOutcome"] == "NO_REPOSITORY"
                    and u["inPredecessor"] is False, "no repository: pattern reference only")
        else:
            require(type(name) is str and REPO.match(name) and u["url"] == "https://github.com/" + name
                    and u["sourceUrl"] == "https://api.github.com/repos/" + name, "primary repository source")
            require(u["inPredecessor"] is (name in pred_repos), "predecessor membership")
            _closed(rc, ("license", "stars", "pushedAt", "checkedAt"), "roadmap check")
            require((rc["license"] is None or type(rc["license"]) is str)
                    and (rc["stars"] is None or (type(rc["stars"]) is int and rc["stars"] >= 0))
                    and (rc["pushedAt"] is None or (type(rc["pushedAt"]) is str and DATE.match(rc["pushedAt"])))
                    and rc["checkedAt"] == "2026-10-12", "roadmap check values")
            _closed(pc, ("found", "pinnedCommit", "headRef", "license", "archived", "pushedAt", "stars",
                         "checkedAtUtc"), "packet re-check")
            require(type(pc["checkedAtUtc"]) is str and TIMESTAMP.match(pc["checkedAtUtc"])
                    and pc["checkedAtUtc"].startswith("2026-10-12T"), "re-check date")
            if pc["found"] is True:
                require(type(pc["pinnedCommit"]) is str and HEX40.match(pc["pinnedCommit"])
                        and type(pc["headRef"]) is str and pc["headRef"].startswith("refs/heads/")
                        and pc["archived"] is False and (pc["license"] is None or type(pc["license"]) is str)
                        and type(pc["stars"]) is int and pc["stars"] >= 0
                        and type(pc["pushedAt"]) is str and TIMESTAMP.match(pc["pushedAt"])
                        and u["policyOutcome"] == classify(pc["license"]),
                        "pinned default-branch commit and the policy's classification")
                found.append(name)
            else:
                require(pc["found"] is False and all(pc[k] is None for k in ("pinnedCommit", "headRef", "license",
                                                                             "archived", "pushedAt", "stars"))
                        and u["policyOutcome"] == "NOT_RETRIEVABLE", "not found at the re-check")
                not_found.append(name)
        require(u["policyOutcome"] in REUSE_OUTCOMES[u["reuseMode"]], "reuse mode consistent with the licence outcome")
        require(u["licenceCeiling"] == ceiling(u["policyOutcome"]), "licence ceiling")
        if u["reuseMode"] == "PLANNED_BASELINE":
            mention = u.get("predecessorMapMention")
            require(type(mention) is str and len(mention) >= 8 and mention in map_text
                    and u["id"] in mention.lower(), "planned baseline named by the map under its own name")
        else:
            require("predecessorMapMention" not in u, "map mention only for planned baselines")
    require(len(found) + len(not_found) == COUNTS["repositories"], "41 re-checked repositories")
    r = x["recheck"]
    _closed(r, ("decision", "method", "networkUse", "outputSha256", "count", "found", "notFound"), "re-check summary")
    require(r["decision"] == "Q-RA1" and r["count"] == COUNTS["repositories"] and r["found"] == len(found)
            and r["notFound"] == not_found and type(r["outputSha256"]) is str and HEX64.match(r["outputSha256"]),
            "re-check summary equals the records")
    _text(r["method"], "re-check method")
    _text(r["networkUse"], "re-check network use")
    require("unauthenticated" in r["method"] and "credential helper" in r["method"], "unauthenticated re-check")

    acceptance = x["acceptance"]
    require([a["item"] for a in acceptance] == list(ITEMS), "acceptance for MAS-RA-001..010")
    proposed = []
    for a in acceptance:
        _closed(a, ("item", "title", "phase", "dependsOn", "harnesses", "proposedPacket", "proposedPacketId",
                    "acceptanceIds", "gates", "readyWhenThisMerges", "packetPublished", "dispatchable"),
                "acceptance record")
        _subset(a["dependsOn"], ROADMAP_ITEMS, "item dependencies", nonempty=True)
        require(a["item"] not in a["dependsOn"], "no self-dependency")
        _closed(a["harnesses"], ("primary", "secondary"), "item harnesses")
        _subset(a["harnesses"]["primary"], harnesses, "primary harnesses", nonempty=True)
        _subset(a["harnesses"]["secondary"], harnesses, "secondary harnesses")
        require(not set(a["harnesses"]["primary"]) & set(a["harnesses"]["secondary"]), "primary and secondary disjoint")
        require(type(a["acceptanceIds"]) is list and a["acceptanceIds"]
                and [i.get("id") for i in a["acceptanceIds"]] == ["%s-A%d" % (a["item"], k)
                                                                 for k in range(1, len(a["acceptanceIds"]) + 1)],
                "acceptance IDs numbered")
        for i in a["acceptanceIds"]:
            _closed(i, ("id", "deliverable"), "acceptance ID record")
            _text(i["deliverable"], "deliverable")
        require(a["gates"] == GATES.get(a["item"], []), "HO-D2 gates")
        require(a["readyWhenThisMerges"] is (a["dependsOn"] == ["MAS-RA-000"]), "ready rule")
        require(a["packetPublished"] is False and a["dispatchable"] is False, "proposed, not published")
        for key in ("title", "phase", "proposedPacket"):
            _text(a[key], "acceptance text")
        if a["proposedPacketId"] is not None:
            require(type(a["proposedPacketId"]) is str and PACKET_ID.match(a["proposedPacketId"])
                    and a["proposedPacketId"] in a["proposedPacket"], "proposed packet ID")
            proposed.append(a["proposedPacketId"])
    require(len(proposed) == len(set(proposed)), "unique proposed packet IDs")
    for pid in proposed:
        try:
            read("task-packets/%s.yaml" % pid)
        except OSError:
            continue
        raise ValueError("proposed packet ID names an existing packet: " + pid)

    require([m["harnessId"] for m in x["mappings"]] == harnesses
            and [m["number"] for m in x["mappings"]] == list(range(1, 17)), "the sixteen harnesses in onion order")
    for m, old in zip(x["mappings"], pred["mappings"]):
        hid = m["harnessId"]
        _closed(m, ("number", "harnessId", "layers", "items", "papers", "upstreams", "standards", "predecessor"),
                "mapping record")
        require(m["layers"] == [l["key"] for l in x["layers"] if hid in l["harnessIds"]], "derived layers")
        require(m["items"] == [{"item": a["item"],
                                "role": "PRIMARY" if hid in a["harnesses"]["primary"] else "SECONDARY"}
                               for a in acceptance
                               if hid in a["harnesses"]["primary"] + a["harnesses"]["secondary"]], "derived items")
        require(m["papers"] == [q["id"] for q in papers if hid in q["harnessIds"]], "derived papers")
        require(m["upstreams"] == [u["id"] for u in x["upstreams"] if hid in u["harnessIds"]], "derived codebases")
        require(m["standards"] == [s["id"] for s in x["standards"] if hid in s["harnessIds"]], "derived standards")
        require(m["predecessor"] == {"proposedPacketId": old["proposedPacketId"],
                                     "preferredUpstreams": old["preferredUpstreams"]}, "predecessor mapping reference")

    require([c["id"] for c in x["critique"]] == list(CRITIQUE), "critique evidence")
    corpus_of = {q["id"]: q["corpus"] for q in papers}
    for c in x["critique"]:
        _closed(c, ("id", "paper", "sourceClass", "pages", "figure", "consequence"), "critique record")
        require(c["paper"] in corpus_of, "critique paper")
        if corpus_of[c["paper"]] == "SEED":
            require(c["sourceClass"] == "SEED_FULL_TEXT", "seed critique class")
            _pages(c["pages"], "seed critique pages")
        else:
            require(c["sourceClass"] == "SECONDARY_AS_REPORTED" and c["pages"] == [], "secondary critique class")
        _text(c["figure"], "critique figure")
        _text(c["consequence"], "critique consequence")

    require([o["id"] for o in x["openItems"]] == ["OI-%d" % n for n in range(1, COUNTS["openItems"] + 1)],
            "open items OI-1..OI-7")
    for o in x["openItems"]:
        _closed(o, ("id", "subject", "text", "carriedTo"), "open item record")
        _text(o["subject"], "open item subject")
        _text(o["text"], "open item text")
        _subset(o["carriedTo"], ITEMS, "open item carried to an item", nonempty=True)
    _texts(x["nonClaims"], "non-claims")

    require(read(README_PATH) == render(x).encode("utf-8"), "README is the record's rendering")
    return {"papers": len(papers), "claims": sum(sum(row.values()) for row in tally.values()),
            "codebases": len(x["upstreams"]), "repositoriesFound": len(found),
            "acceptanceIds": sum(len(a["acceptanceIds"]) for a in acceptance)}


def _cell(text) -> str:
    return str(text).replace("|", "/").replace("\n", " ")


def render(x) -> str:
    """The README: a deterministic rendering of the record (the map's successor text)."""
    hnum = {m["harnessId"]: m["number"] for m in x["mappings"]}
    h = lambda hid: "H%d" % hnum[hid]
    short = {q["id"]: q["short"] for q in x["papers"]}
    lines = []
    w = lines.append
    w("# Research adoption v2: the October 2026 MAS-harness corpus (MAS-RA-000)")
    w("")
    w("Alpha 2A; checked %s. Evidence class `%s`: data only, no public contract, selector, catalog, policy or runtime "
      "change." % (x["checkedAt"], x["evidenceClass"]))
    w("")
    w("`crosswalk.json` (`%s`) is the successor overlay of `%s` (`%s`, %s, sha256 `%s`) and of `%s` (sha256 `%s`). "
      "Both stay byte-identical, because later records pin them by digest, and they remain the record of the "
      "2026-09 corpus, the sixteen harness adoption targets, the gates G1-G8 and the policies; the policies are "
      "carried over unchanged. This record adds the October 2026 corpus (three research syntheses, eight seed papers "
      "read in full, eleven secondary papers, five standards and the codebases they name) and maps it onto the same "
      "sixteen harnesses. This README is the map's successor text and is generated from the record; "
      "`scripts/research_adoption_v2.py` checks both." % (x["schemaVersion"], x["predecessor"]["path"],
                                                           x["predecessor"]["schemaVersion"],
                                                           x["predecessor"]["metaPacketId"], x["predecessor"]["sha256"],
                                                           x["predecessor"]["map"]["path"],
                                                           x["predecessor"]["map"]["sha256"]))
    w("")
    w(x["relation"])
    w("")
    w("## Definitions")
    w("")
    for key, title in (("reuseModes", "Reuse mode"), ("alignment", "Alignment"), ("licenceCeiling", "Licence ceiling"),
                       ("policyOutcomes", "Licence-policy outcome"), ("claimKinds", "Claim kind"),
                       ("claimStatus", "Claim status")):
        w("| %s | Meaning |" % title)
        w("|---|---|")
        for name, text in x["definitions"][key].items():
            w("| %s | %s |" % (name, _cell(text)))
        w("")
    w(x["definitions"]["secondaryNames"])
    w("")
    w("## Decisions")
    w("")
    w("| Decision | Selected | By | Text |")
    w("|---|---|---|---|")
    for e in x["decisions"]:
        w("| %s | %s | %s | %s |" % (e["id"], e["selected"] or "-", e["by"], _cell(e["text"])))
    w("")
    w("## Sources")
    w("")
    w("The three syntheses are user research inputs, not execution authority, and are referenced by sha256 only.")
    w("")
    w("| Id | File | sha256 | Summary |")
    w("|---|---|---|---|")
    for s in x["sources"]:
        w("| %s | %s | `%s` | %s |" % (s["id"], s["name"], s["sha256"], _cell(s["summary"])))
    w("")
    w("## Priority rule")
    w("")
    w(x["priorityRule"])
    w("")
    w("## Eight layers to the sixteen harnesses")
    w("")
    w("| Layer | Question | Harnesses | Items | Evidence |")
    w("|---|---|---|---|---|")
    for l in x["layers"]:
        w("| %s %s | %s | %s | %s | %s |" % (l["key"], l["name"], l["question"],
                                           ", ".join("%s `%s`" % (h(i), i) for i in l["harnessIds"]),
                                           ", ".join(l["items"]), _cell(l["evidence"])))
    w("")
    w("| Harness | Layers | MAS-RA items (P primary, S secondary) | Papers | Codebases | Standards |")
    w("|---|---|---|---|---|---|")
    for m in x["mappings"]:
        w("| H%d `%s` | %s | %s | %s | %s | %s |" % (
            m["number"], m["harnessId"], ", ".join(m["layers"]) or "-",
            ", ".join("%s %s" % (i["item"], i["role"][0]) for i in m["items"]) or "-",
            ", ".join(short[q] for q in m["papers"]) or "-", ", ".join(m["upstreams"]) or "-",
            ", ".join(m["standards"]) or "-"))
    w("")
    w("## Design principles and their counter-evidence")
    w("")
    w("| Id | Principle | Counter-evidence or cost |")
    w("|---|---|---|")
    for q in x["principles"]:
        w("| %s | %s | %s |" % (q["id"], _cell(q["principle"]), _cell(q["counterEvidence"])))
    w("")
    w("## Critique evidence that sets the priorities")
    w("")
    w("| Id | Paper | Source class | Figure | Consequence |")
    w("|---|---|---|---|---|")
    for c in x["critique"]:
        w("| %s | %s (%s) | %s | %s | %s |" % (c["id"], short[c["paper"]], c["paper"], c["sourceClass"],
                                             _cell(c["figure"]), _cell(c["consequence"])))
    w("")
    w("## Seed papers (read in full on 2026-10-12)")
    w("")
    w("Each seed paper's checks are of three kinds: the claims the syntheses made about it, whether code, data or a "
      "licence is available, and its venue. `crosswalk.json` carries every check with its kind, status and pages, the "
      "grounded facts and the contract implications (derived data, Q-RA2).")
    w("")
    w("| Paper | Layers | Harnesses | Items | Alignment | Synthesis claims (V / C / NF) | Availability (V / NF) | "
      "Venue | Codebases |")
    w("|---|---|---|---|---|---|---|---|---|")
    for q in x["papers"]:
        if q["corpus"] != "SEED":
            continue
        c = q["claimCounts"]
        w("| %s [%s](%s) | %s | %s | %s | %s | %d / %d / %d | %d / %d | %d | %s |" % (
            q["short"], q["id"], q["url"], ", ".join(q["layers"]), ", ".join(h(i) for i in q["harnessIds"]),
            ", ".join(q["items"]), q["alignment"], c["SYNTHESIS_CLAIM"]["VERIFIED"], c["SYNTHESIS_CLAIM"]["CORRECTED"],
            c["SYNTHESIS_CLAIM"]["NOT_FOUND"], c["AVAILABILITY_CHECK"]["VERIFIED"],
            c["AVAILABILITY_CHECK"]["NOT_FOUND"], c["VENUE_CHECK"]["VERIFIED"], ", ".join(q["upstreams"]) or "-"))
    w("")
    w("| Paper | Status | Licence stated in the paper |")
    w("|---|---|---|")
    for q in x["papers"]:
        if q["corpus"] == "SEED":
            w("| %s | %s | %s |" % (q["short"], _cell(q["status"]), "yes" if q["licenceStatedInPaper"] else "no"))
    w("")
    w("## Secondary corpus (as reported by the syntheses)")
    w("")
    w("| Paper | Name | Layers | Harnesses | Items | Alignment | Reported |")
    w("|---|---|---|---|---|---|---|")
    for q in x["papers"]:
        if q["corpus"] != "SECONDARY":
            continue
        w("| %s [%s](%s) | %s | %s | %s | %s | %s | %s |" % (
            q["short"], q["id"], q["url"], _cell(q["name"]), ", ".join(q["layers"]),
            ", ".join(h(i) for i in q["harnessIds"]), ", ".join(q["items"]), q["alignment"], _cell(q["reported"])))
    w("")
    w("## Standards")
    w("")
    w("| Standard | Layers | Harnesses | Items | Role |")
    w("|---|---|---|---|---|")
    for s in x["standards"]:
        w("| [%s](%s) | %s | %s | %s | %s |" % (s["name"], s["url"], ", ".join(s["layers"]),
                                               ", ".join(h(i) for i in s["harnessIds"]), ", ".join(s["items"]) or "-",
                                               _cell(s["role"])))
    w("")
    w("## Codebases")
    w("")
    r = x["recheck"]
    w("Re-checked on %s under Q-RA1 (%d of %d repositories found; not found: %s; re-check output sha256 `%s`). %s "
      "Each record is dated GitHub metadata and the default-branch commit at the check; the licence-policy outcome "
      "applies the pinned policy's lists to the GitHub-reported identifier. Nothing is qualified, vendored or released."
      % (x["checkedAt"], r["found"], r["count"], ", ".join(r["notFound"]) or "none", r["outputSha256"],
         r["networkUse"]))
    w("")
    w("| Codebase | Reuse mode | Licence (GitHub) | Policy outcome | Licence ceiling | Pinned commit | Items |")
    w("|---|---|---|---|---|---|---|")
    for u in x["upstreams"]:
        pc = u["packetCheck"]
        repo = "[%s](%s)" % (u["repository"], u["url"]) if u["repository"] else u["id"]
        w("| %s | %s | %s | %s | %s | %s | %s |" % (
            repo, u["reuseMode"], (pc["license"] or "none") if pc and pc["found"] else "-", u["policyOutcome"],
            u["licenceCeiling"], ("`%s`" % pc["pinnedCommit"]) if pc and pc["found"] else "-", ", ".join(u["items"])))
    w("")
    w("## Acceptance IDs for MAS-RA-001..010")
    w("")
    w("Proposed, not published or dispatchable. Items whose only predecessor is MAS-RA-000 become READY when this "
      "packet merges.")
    w("")
    w("| Item | Proposed packet | Depends on | Gates | Ready on merge | Acceptance IDs |")
    w("|---|---|---|---|---|---|")
    for a in x["acceptance"]:
        w("| %s | %s | %s | %s | %s | %s |" % (a["item"], _cell(a["proposedPacket"]), ", ".join(a["dependsOn"]),
                                              ", ".join(a["gates"]) or "-", "yes" if a["readyWhenThisMerges"] else "no",
                                              "; ".join("%s %s" % (i["id"], _cell(i["deliverable"]))
                                                        for i in a["acceptanceIds"])))
    w("")
    w("## Open items")
    w("")
    w("| Id | Subject | Text | Carried to |")
    w("|---|---|---|---|")
    for o in x["openItems"]:
        w("| %s | %s | %s | %s |" % (o["id"], o["subject"], _cell(o["text"]), ", ".join(o["carriedTo"])))
    w("")
    w("## Not claimed")
    w("")
    for n in x["nonClaims"]:
        w("- " + n)
    w("")
    return "\n".join(lines)


if __name__ == "__main__":
    from pathlib import Path

    root = Path(__file__).resolve().parents[1]
    summary = check(lambda path: (root / path).read_bytes())
    print("Research adoption v2 valid: %(papers)d papers (%(claims)d seed checks), %(codebases)d codebases "
          "(%(repositoriesFound)d repositories pinned), %(acceptanceIds)d acceptance IDs; predecessor byte-identical."
          % summary)
