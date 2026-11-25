#!/usr/bin/env python3
"""Model weights record (architecture/model-weights/, MODEL-WEIGHTS-POLICY-001, MET-015): the checker.

check(read) validates the weights record, its schema, its vectors and the v3 licence amendment
(legal/license-policy-amendment-v3/, LIC-WEIGHTS-A3) through an injected byte reader (exact paths only, no listing)
and returns its refusals as (code, message) pairs in the codes' order. The rules are R06's step 4 r2 C-1 to C-8:
- MW_POLICY: the amendment pins the base policy (legal/third-party-license-policy.yaml, 0.3.0), A1 and A2 and their
  two amendment scripts by digest, and A1's and A2's validators by source segment (line 1 to the line before their
  one `def validate() -> None:`, the part each slot's cascade leaves alone); its five class outcomes keep the base's
  precedence order, and its `precedence` list is the order of its outcomes (step 3's fragment, class r2);
  the base still requires model licence approval.
- MW_SCHEMA (C-1): the record closed to its exact members, enums and types; duplicate JSON keys refused. The one
  candidate-row null rule (the schema's candidateNullRule): a value no pinned read gives is null, only in
  CANDIDATE_NULL_FIELDS, and the record's nullValues lists each such null by row, field and kind; the three
  SCHEMA_NULLS carry their schema meaning and are not listed.
- MW_IDENTITY (C-2): unique row ids; each commit 40 lowercase hex and each sha256 64 lowercase hex, by full match.
- MW_CLASS (C-3): the outcome agrees with its rule: DEFAULT_ALLOWED under W-1 or W-2a with a pinned text, or under W-3
  with the metadata tag of a defaultAllowed text and the card's statement (Q-W1 option 1), or under W-4 through its
  base; an exception records its duty with no use restriction, revocation or registration; DENIED and UNKNOWN carry
  no decision.
- MW_RESTRICTIONS (C-4): a null restriction field stands only on a DENIED, UNKNOWN or undecided review row (fail
  closed); a review decision stands on all eight fields read, with its authority and digest.
- MW_DISTRIBUTION (C-5): BUNDLE only for DEFAULT_ALLOWED and ALLOWED_EXCEPTION, TENANT_FETCHED only for a review row
  with a decision, each with no null restriction field; NONE otherwise (W-5).
- MW_DERIVED (C-6): derivedFrom and quantization.baseRow name one existing row; a derived row is never more
  permissive than its base, in the base policy's precedence order (W-4).
- MW_SERVED (C-7): each consumer source, read at its exact path, names only rows that exist, have PINNED weights,
  hold no null value (fail closed) and have an allowing release outcome; the empty consumer list serves nothing.
- MW_APPROVAL (C-8): no served row is UNKNOWN or without a licence text (modelLicenseApprovalRequired).
- MW_VECTORS: every vector's in-memory record and sources give exactly its expected refusals; the negatives cover
  C-2 to C-8; and the fail-closed probe holds: nulling any one of the eight restriction fields of any row of a
  positive vector whose release outcome allows gives DENY_RELEASE and a refusal.
Standard library only. main() reads through the checker's own disk_reader and prints counts only.
"""
from __future__ import annotations

import copy
import hashlib
import json
import re
import stat
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
RECORD_PATH = "architecture/model-weights/record.json"
SCHEMA_PATH = "architecture/model-weights/schema.json"
VECTORS_PATH = "architecture/model-weights/vectors.json"
AMENDMENT_PATH = "legal/license-policy-amendment-v3/amendment.json"
BASE_PATH = "legal/third-party-license-policy.yaml"
PREDECESSORS = (("LIC-HOST-A1", "legal/license-policy-amendment/amendment.json",
                 ("scripts/license_amendment.py", "scripts/validate_license_amendment.py")),
                ("LIC-HOST-A2", "legal/license-policy-amendment-v2/amendment.json",
                 ("scripts/license_amendment_v2.py", "scripts/validate_license_amendment_v2.py")))
SEGMENT_PINNED = ("scripts/validate_license_amendment.py", "scripts/validate_license_amendment_v2.py")
SEGMENT_ANCHOR = "def validate() -> None:"
RECORD_VERSION = "planeon.internal.model-weights/v1"
VECTORS_VERSION = "planeon.internal.model-weights-vectors/v1"
CODES = ("MW_POLICY", "MW_SCHEMA", "MW_IDENTITY", "MW_CLASS", "MW_RESTRICTIONS", "MW_DISTRIBUTION", "MW_DERIVED",
         "MW_SERVED", "MW_APPROVAL", "MW_VECTORS")
OUTCOMES = ("DENIED", "UNKNOWN", "OPTIONAL_EXPLICIT_REVIEW", "ALLOWED_EXCEPTION", "DEFAULT_ALLOWED")
ALLOWING = ("DEFAULT_ALLOWED", "ALLOWED_EXCEPTION")
FAMILIES = ("Qwen", "Gemma", "Nemotron", "Mistral", "DeepSeek", "GLM", "Kimi")
RULES = ("W-1", "W-2", "W-2a", "W-3", "W-4")
TIERS = ("CPU", "GPU")
FORMATS = ("SAFETENSORS", "GGUF")
DIGEST_STATUS = ("PINNED", "MISSING_PLANNED")
SOURCES = ("FILE", "PAGE", "DECLARATION")
STATEMENTS = ("STATED", "PARTIAL", "NOT_STATED")
MODES = ("BUNDLE", "TENANT_FETCHED", "NONE")
CONSUMER_KINDS = ("ROUTE_BUNDLE", "SEMANTIC_CONSUMER", "GRADER")
NULL_KINDS = ("UNREAD", "READ_NOT_STATED", "NOT_A_READ")
NO_TERM = ("NONE", "NOT_STATED")
RESTRICTIONS = ("redistribution", "useRestrictions", "attribution", "derivatives", "licensorPowers", "thresholds",
                "acceptance", "governingLaw")
# Each restriction field read: an object of these members (bool, text, or a list of texts), or governingLaw's text.
RESTRICTION_SHAPES = {
    "redistribution": {"allowed": "bool", "conditions": "texts"},
    "useRestrictions": {"list": "texts", "flowDown": "bool"},
    "attribution": {"noticeDuty": "text", "displayOrNamingDuty": "text", "trigger": "text"},
    "derivatives": {"allowed": "bool", "namingOrNoticeDuty": "text"},
    "licensorPowers": {"termination": "text", "revocation": "text", "update": "text", "remoteRestriction": "text"},
    "thresholds": {"users": "text", "revenue": "text", "duty": "text"},
    "acceptance": {"byUse": "bool", "byClick": "bool", "byRegistration": "bool"},
    "governingLaw": "text",
}
TOP = ("schemaVersion", "recordVersion", "policyRef", "consumers", "releases", "nullValues")
ROW = ("id", "family", "release", "tier", "weights", "tokenizer", "quantization", "licence", "modelCard",
       "trainingDataStatement", "languages", "contextTokens", "backends", "distributionMode", "derivedFrom")
LICENCE = ("outcome", "rule", "text", "restrictions", "decisionRef")
CANDIDATE_NULL_FIELDS = ("release.repository", "release.commit", "tier", "weights.format", "tokenizer",
                         "tokenizer.path", "tokenizer.sha256", "quantization.method", "quantization.tool",
                         "quantization.inputDigest", "quantization.outputDigest", "licence.text") \
    + tuple("licence.restrictions." + name for name in RESTRICTIONS) \
    + ("modelCard", "modelCard.sha256", "trainingDataStatement", "languages", "contextTokens")
SCHEMA_NULLS = ("quantization", "derivedFrom", "licence.decisionRef")
ROW_ID = re.compile(r"[a-z0-9][a-z0-9.-]{0,127}")
HEX64, HEX40 = re.compile(r"[0-9a-f]{64}"), re.compile(r"[0-9a-f]{40}")
STAMP = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z")
MAX_BYTES = 16_777_216


class Refused(Exception):
    pass


def need(ok, message):
    if not ok:
        raise Refused(message)


def digest(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def parse_json(raw):
    need(type(raw) is bytes, "a JSON file is present")

    def pairs(items):
        keys = [k for k, _ in items]
        need(len(keys) == len(set(keys)), "a duplicate JSON key")
        return dict(items)

    def constant(name):
        raise Refused("a non-finite number")
    return json.loads(raw.decode("utf-8"), object_pairs_hook=pairs, parse_constant=constant)


def closed(value, members, where):
    need(type(value) is dict and set(value) == set(members), "%s is closed to %s" % (where, ", ".join(members)))


def text(value):
    return type(value) is str and value != "" and len(value) <= 2048


def nullable(value, test):
    return value is None or test(value)


def base_facts(raw: bytes) -> dict:
    """The base policy's evaluation precedence list and modelLicenseApprovalRequired, read from its own lines."""
    lines = raw.decode("utf-8").splitlines()
    need(lines.count("  precedence:") == 1, "the base has one precedence list")
    order = []
    for line in lines[lines.index("  precedence:") + 1:]:
        if not line.startswith("    - "):
            break
        order.append(line[6:].strip())
    approval = [ln.strip() for ln in lines if ln.strip().startswith("modelLicenseApprovalRequired:")]
    return {"precedence": order, "approvalRequired": approval == ["modelLicenseApprovalRequired: true"]}


def null_paths(row) -> list:
    """Every null in the row's objects, as a dotted field path (lists are values, not descended)."""
    out = []

    def walk(value, path):
        if value is None:
            out.append(path)
        elif type(value) is dict:
            for key, item in value.items():
                walk(item, path + "." + key if path else key)
    walk(row, "")
    return out


def unread(row) -> list:
    """The row's null values under the candidate rule (every null but the SCHEMA_NULLS)."""
    return [p for p in null_paths(row) if p not in SCHEMA_NULLS]


def release_outcome(row) -> str:
    """The derived release outcome (never stored). Fail closed: any null value or unpinned weights give DENY_RELEASE,
    whatever the class."""
    lic = row["licence"]
    if unread(row) or row["weights"]["digestStatus"] != "PINNED":
        return "DENY_RELEASE"
    if lic["outcome"] == "DEFAULT_ALLOWED":
        return "ALLOW"
    if lic["outcome"] == "ALLOWED_EXCEPTION":
        return "ALLOW_WITH_DUTY"
    if lic["outcome"] == "OPTIONAL_EXPLICIT_REVIEW" and lic["decisionRef"] is not None:
        return "TENANT_FETCH_APPROVED"
    return "DENY_RELEASE"


# ---------------------------------------------------------------- C-1: the closed shape

def _member(value, kind):
    if kind == "bool":
        return type(value) is bool
    if kind == "texts":
        return type(value) is list and all(text(x) for x in value)
    return text(value)


def _shape_restrictions(rs):
    closed(rs, RESTRICTIONS, "licence.restrictions")
    for name in RESTRICTIONS:
        value, shape = rs[name], RESTRICTION_SHAPES[name]
        if value is None:
            continue
        if shape == "text":
            need(text(value), "restriction %s is text" % name)
        else:
            closed(value, tuple(shape), "restriction " + name)
            need(all(_member(value[k], kind) for k, kind in shape.items()), "restriction %s's members" % name)


def _shape_row(r):
    closed(r, ROW, "a release row")
    need(type(r["id"]) is str and r["family"] in FAMILIES and r["tier"] in TIERS + (None,), "row id, family and tier")
    closed(r["release"], ("repository", "commit"), "release")
    need(nullable(r["release"]["repository"], text) and nullable(r["release"]["commit"], text), "release fields")
    w = r["weights"]
    closed(w, ("format", "files", "digestStatus"), "weights")
    need(w["format"] in FORMATS + (None,) and w["digestStatus"] in DIGEST_STATUS and type(w["files"]) is list,
         "weights fields")
    for f in w["files"]:
        closed(f, ("path", "sha256", "bytes"), "a weights file")
        need(text(f["path"]) and text(f["sha256"]) and type(f["bytes"]) is int and f["bytes"] > 0, "file fields")
    need((w["digestStatus"] == "PINNED") == bool(w["files"]), "PINNED weights list their files; MISSING_PLANNED none")
    t = r["tokenizer"]
    if t is not None:
        closed(t, ("path", "sha256", "embeddedInWeights"), "tokenizer")
        need(nullable(t["path"], text) and nullable(t["sha256"], text) and type(t["embeddedInWeights"]) is bool,
             "tokenizer fields")
    q = r["quantization"]
    if q is not None:
        closed(q, ("method", "baseRow", "tool", "inputDigest", "outputDigest"), "quantization")
        need(nullable(q["method"], text) and text(q["baseRow"]) and nullable(q["inputDigest"], text)
             and nullable(q["outputDigest"], text), "quantization fields")
        if q["tool"] is not None:
            closed(q["tool"], ("name", "release"), "quantization.tool")
            need(text(q["tool"]["name"]) and text(q["tool"]["release"]), "quantization.tool fields")
    lic = r["licence"]
    need(type(lic) is dict and set(lic) in (set(LICENCE), set(LICENCE) | {"declaration"}),
         "licence is closed to %s (and an optional declaration)" % ", ".join(LICENCE))
    need(lic["outcome"] in OUTCOMES and lic["rule"] in RULES, "licence outcome and rule")
    if "declaration" in lic:
        closed(lic["declaration"], ("metadataTag", "cardStatesWeights"), "licence.declaration")
        need(text(lic["declaration"]["metadataTag"]) and type(lic["declaration"]["cardStatesWeights"]) is bool,
             "licence.declaration fields")
    tx = lic["text"]
    if tx is not None:
        need(type(tx) is dict and tx.get("source") in SOURCES, "licence.text.source")
        if tx["source"] == "PAGE":
            closed(tx, ("source", "page", "sha256", "readAt"), "a PAGE licence text")
            need(text(tx["page"]) and text(tx["sha256"]) and type(tx["readAt"]) is str
                 and STAMP.fullmatch(tx["readAt"]) is not None, "PAGE text fields")
        else:
            closed(tx, ("source", "path", "sha256"), "a FILE or DECLARATION licence text")
            need(text(tx["path"]) and text(tx["sha256"]), "FILE or DECLARATION text fields")
    _shape_restrictions(lic["restrictions"])
    if lic["decisionRef"] is not None:
        closed(lic["decisionRef"], ("approvingAuthority", "decisionDigest"), "licence.decisionRef")
        need(text(lic["decisionRef"]["approvingAuthority"]) and text(lic["decisionRef"]["decisionDigest"]),
             "licence.decisionRef fields")
    if r["modelCard"] is not None:
        closed(r["modelCard"], ("path", "sha256"), "modelCard")
        need(text(r["modelCard"]["path"]) and nullable(r["modelCard"]["sha256"], text), "modelCard fields")
    s = r["trainingDataStatement"]
    if s is not None:
        closed(s, ("state", "summary", "sourceSha256"), "trainingDataStatement")
        need(s["state"] in STATEMENTS and text(s["summary"]) and text(s["sourceSha256"]), "trainingDataStatement")
    need(nullable(r["languages"], lambda v: type(v) is list and bool(v) and all(text(x) for x in v)), "languages")
    need(nullable(r["contextTokens"], lambda v: type(v) is int and v > 0), "contextTokens")
    need(type(r["backends"]) is list and all(text(b) for b in r["backends"]), "backends")
    need(r["distributionMode"] in MODES and nullable(r["derivedFrom"], text), "distributionMode and derivedFrom")
    stray = [p for p in null_paths(r) if p not in CANDIDATE_NULL_FIELDS + SCHEMA_NULLS]
    need(not stray, "%s: a null outside the candidate rule: %s" % (r["id"], ", ".join(stray)))


def check_record_shape(record):
    closed(record, TOP, "the record")
    need(record["schemaVersion"] == RECORD_VERSION and type(record["recordVersion"]) is int
         and record["recordVersion"] >= 1, "the record's version")
    need(record["policyRef"] == {"basePolicy": {"path": BASE_PATH, "policyVersion": "0.3.0"},
                                 "amendment": {"path": AMENDMENT_PATH, "key": "weightsLicenseClasses"}}, "policyRef")
    need(type(record["consumers"]) is list and type(record["releases"]) is list, "consumers and releases are lists")
    for c in record["consumers"]:
        closed(c, ("path", "kind", "field"), "a consumer")
        need(text(c["path"]) and c["kind"] in CONSUMER_KINDS and text(c["field"]), "consumer fields")
    for r in record["releases"]:
        _shape_row(r)
    listed = record["nullValues"]
    need(type(listed) is list, "nullValues is a list")
    for entry in listed:
        closed(entry, ("row", "field", "kind"), "a nullValues entry")
        need(entry["kind"] in NULL_KINDS, "a nullValues kind")
    pairs = [(e["row"], e["field"]) for e in listed]
    found = [(r["id"], p) for r in record["releases"] for p in unread(r)]
    need(len(pairs) == len(set(pairs)) and sorted(pairs) == sorted(found),
         "nullValues lists each null by row and field, exactly")


# ---------------------------------------------------------------- C-2 to C-8 over one record

def served_ids(record, read_source) -> list:
    """C-7's served set: each consumer source at its exact path; a route bundle by routes[].<field>."""
    served = []
    for c in record["consumers"]:
        doc = parse_json(read_source(c["path"]))
        need(type(doc) is dict, "%s is an object" % c["path"])
        if c["kind"] == "ROUTE_BUNDLE":
            need(type(doc.get("routes")) is list and all(type(x) is dict for x in doc["routes"]),
                 "%s: routes[]" % c["path"])
            served.extend(route.get(c["field"]) for route in doc["routes"])
        else:
            served.append(doc.get(c["field"]))
    return served


def check_record(record, read_source, policy) -> list:
    """The record's refusals: MW_SCHEMA alone when its shape fails, else C-2 to C-8, each with its first message."""
    try:
        check_record_shape(record)
    except Exception as exc:
        return [("MW_SCHEMA", str(exc))]
    rows = {r["id"]: r for r in record["releases"]}
    order = policy["order"]
    served = []

    def identity():
        need(len(rows) == len(record["releases"]), "a duplicate row id")
        for r in record["releases"]:
            need(ROW_ID.fullmatch(r["id"]) is not None, "row id %r" % r["id"])
            need(r["release"]["commit"] is None or HEX40.fullmatch(r["release"]["commit"]) is not None,
                 "%s's commit is 40 lowercase hex" % r["id"])
            shas = [f["sha256"] for f in r["weights"]["files"]]
            shas += [(r["tokenizer"] or {}).get("sha256"), (r["licence"]["text"] or {}).get("sha256"),
                     (r["modelCard"] or {}).get("sha256"), (r["trainingDataStatement"] or {}).get("sourceSha256"),
                     (r["quantization"] or {}).get("inputDigest"), (r["quantization"] or {}).get("outputDigest"),
                     (r["licence"]["decisionRef"] or {}).get("decisionDigest")]
            need(all(s is None or HEX64.fullmatch(s) is not None for s in shas),
                 "%s's sha256 values are 64 lowercase hex" % r["id"])

    def klass():
        for r in record["releases"]:
            lic, rs = r["licence"], r["licence"]["restrictions"]
            if lic["rule"] == "W-3":
                need("declaration" in lic and (lic["text"] or {}).get("source") == "DECLARATION",
                     "%s: a W-3 row records its declaration" % r["id"])
            if lic["rule"] == "W-4":
                need(r["derivedFrom"] is not None or r["quantization"] is not None,
                     "%s: a W-4 row names its base" % r["id"])
            elif lic["outcome"] == "DEFAULT_ALLOWED":
                need(lic["rule"] in policy["defaultRules"] and lic["text"] is not None,
                     "%s: DEFAULT_ALLOWED needs a pinned text under W-1, W-2a or W-3" % r["id"])
                if lic["rule"] == "W-3":
                    d = lic["declaration"]
                    need(d["metadataTag"].lower() in [t.lower() for t in policy["defaultTexts"]]
                         and (d["cardStatesWeights"] is True or not policy["w3Card"]),
                         "%s: W-3 needs a defaultAllowed metadata tag and the card's statement (Q-W1 option 1)"
                         % r["id"])
                else:
                    need(lic["text"]["source"] in ("FILE", "PAGE"), "%s: a licence text file or page" % r["id"])
            if lic["outcome"] == "ALLOWED_EXCEPTION":
                need(all(rs[k] is not None for k in RESTRICTIONS)
                     and rs["attribution"]["displayOrNamingDuty"] not in NO_TERM
                     and rs["useRestrictions"]["list"] == [] and rs["licensorPowers"]["revocation"] in NO_TERM
                     and rs["acceptance"]["byRegistration"] is False,
                     "%s: an exception records its duty, with no use restriction, revocation or registration"
                     % r["id"])
            if lic["outcome"] in ("DENIED", "UNKNOWN"):
                need(lic["decisionRef"] is None, "%s: DENIED and UNKNOWN carry no decision" % r["id"])

    def restrictions():
        for r in record["releases"]:
            lic = r["licence"]
            if any(lic["restrictions"][k] is None for k in RESTRICTIONS):
                need(lic["outcome"] in ("DENIED", "UNKNOWN") or (lic["outcome"] == "OPTIONAL_EXPLICIT_REVIEW"
                                                                 and lic["decisionRef"] is None),
                     "%s: a null restriction field stands only on a DENIED, UNKNOWN or undecided review row" % r["id"])
            if lic["decisionRef"] is not None:
                need(lic["outcome"] == "OPTIONAL_EXPLICIT_REVIEW", "%s: a decision is a review row's" % r["id"])

    def distribution():
        for r in record["releases"]:
            lic, mode = r["licence"], r["distributionMode"]
            gap = any(lic["restrictions"][k] is None for k in RESTRICTIONS)
            if mode == "BUNDLE":
                need(lic["outcome"] in ALLOWING and not gap,
                     "%s: BUNDLE only for DEFAULT_ALLOWED or ALLOWED_EXCEPTION, all restrictions read" % r["id"])
            if mode == "TENANT_FETCHED":
                need(lic["outcome"] == "OPTIONAL_EXPLICIT_REVIEW" and lic["decisionRef"] is not None and not gap,
                     "%s: TENANT_FETCHED only for a review row with its decision" % r["id"])

    def derived():
        for r in record["releases"]:
            bases = {b for b in (r["derivedFrom"], (r["quantization"] or {}).get("baseRow")) if b is not None}
            need(len(bases) <= 1 and all(b in rows and b != r["id"] for b in bases),
                 "%s: derivedFrom and quantization.baseRow name one existing row" % r["id"])
            for b in bases:
                need(order.index(r["licence"]["outcome"]) <= order.index(rows[b]["licence"]["outcome"]),
                     "%s: a derived row is never more permissive than its base (W-4)" % r["id"])

    def serving():
        served.extend(served_ids(record, read_source))
        for mid in served:
            r = rows.get(mid) if type(mid) is str else None
            need(r is not None, "a served model has no row: %r" % (mid,))
            need(r["weights"]["digestStatus"] == "PINNED", "%s is served without pinned digests" % mid)
            need(not unread(r), "%s is served with a null value (fail closed)" % mid)
            need(r["licence"]["outcome"] == "UNKNOWN" or release_outcome(r) != "DENY_RELEASE",
                 "%s is served with outcome %s" % (mid, r["licence"]["outcome"]))

    def approval():
        need(policy["approvalRequired"], "the base requires model licence approval")
        for mid in served:
            lic = rows[mid]["licence"]
            need(lic["outcome"] != "UNKNOWN" and lic["text"] is not None,
                 "%s is served UNKNOWN or without a licence text" % mid)

    out = []
    for code, run in (("MW_IDENTITY", identity), ("MW_CLASS", klass), ("MW_RESTRICTIONS", restrictions),
                      ("MW_DISTRIBUTION", distribution), ("MW_DERIVED", derived), ("MW_SERVED", serving),
                      ("MW_APPROVAL", approval)):
        try:
            run()
        except Exception as exc:
            out.append((code, str(exc)))
            if code == "MW_SERVED":
                served.clear()
    return out


# ---------------------------------------------------------------- policy, vectors, check

def segment_pin(segment, raw: bytes, path: str) -> None:
    """MW_POLICY for a validator of A1 or A2: its source segment, line 1 to the line before its one
    `def validate() -> None:`, pinned by digest. Each slot's cascade moves the catalog count inside validate() and
    the main block only, so the segment holds across slots while every rule above validate() stays pinned."""
    closed(segment, ("firstLine", "lastLine", "endsBefore", "sha256"), "the segment of " + path)
    lines = raw.splitlines(keepends=True)
    anchors = [i for i, line in enumerate(lines) if line == (SEGMENT_ANCHOR + "\n").encode("utf-8")]
    need(segment["endsBefore"] == SEGMENT_ANCHOR and segment["firstLine"] == 1 and type(segment["lastLine"]) is int
         and anchors == [segment["lastLine"]], "%s: the segment ends before its one anchor line" % path)
    need(segment["sha256"] == digest(b"".join(lines[:segment["lastLine"]])), "%s's segment is pinned by digest" % path)


def policy_facts(read) -> dict:
    """MW_POLICY: the amendment against the base policy, A1 and A2; returns the class facts the record checks use."""
    amendment = parse_json(read(AMENDMENT_PATH))
    base_raw = read(BASE_PATH)
    need(amendment["base"] == {"path": BASE_PATH, "sha256": digest(base_raw), "policyVersion": "0.3.0"},
         "the amendment pins the base policy by digest")
    pins = [(p["amendmentId"], p["path"], tuple(s["path"] for s in p["scripts"])) for p in amendment["predecessors"]]
    need(pins == list(PREDECESSORS), "the amendment names A1 and A2 and their four scripts")
    for p in amendment["predecessors"]:
        need(p["sha256"] == digest(read(p["path"])), "%s is pinned by digest" % p["amendmentId"])
        for s in p["scripts"]:
            if s["path"] in SEGMENT_PINNED:
                closed(s, ("path", "segment"), "the segment pin of " + s["path"])
                segment_pin(s["segment"], read(s["path"]), s["path"])
            else:
                closed(s, ("path", "sha256"), "the pin of " + s["path"])
                need(s["sha256"] == digest(read(s["path"])), "%s is pinned by digest" % s["path"])
    base = base_facts(base_raw)
    cls = amendment["weightsLicenseClasses"]
    pairs = [(o["outcome"], o["baseOutcome"]) for o in cls["outcomes"]]
    need([o for o, _ in pairs] == list(OUTCOMES), "the five class outcomes, most restrictive first")
    need(cls.get("precedence") == [o for o, _ in pairs], "the class's precedence is the order of its outcomes")
    positions = [base["precedence"].index(b) if b in base["precedence"] else -1 for _, b in pairs]
    need(-1 not in positions and positions == sorted(positions), "the class keeps the base's precedence order")
    need(cls["restrictionFields"] == list(RESTRICTIONS) and cls["rules"] == list(RULES), "fields and rules")
    need(cls["distributionMode"]["bundle"] == list(ALLOWING) and text(cls["nullRestrictionRule"]),
         "bundle outcomes and the null-restriction rule")
    return {"order": [o for o, _ in pairs], "defaultTexts": cls["defaultAllowed"]["texts"],
            "defaultRules": cls["defaultAllowed"]["rules"], "w3Card": cls["defaultAllowed"]["w3RequiresCardStatement"],
            "approvalRequired": base["approvalRequired"]}


def _source_reader(sources):
    def read(path):
        need(type(sources) is dict and path in sources, "a vector source at %r" % (path,))
        return json.dumps(sources[path]).encode("utf-8")
    return read


def null_probe(case, policy):
    """Q-C1B-297-1 (a), condition 3: in a positive vector, nulling any one of the eight restriction fields of a row
    whose release outcome allows gives DENY_RELEASE and a refusal (fail closed). Returns the probe count."""
    read = _source_reader(case["sources"])
    probes = 0
    for index, row in enumerate(case["record"]["releases"]):
        if release_outcome(row) == "DENY_RELEASE":
            continue
        for name in RESTRICTIONS:
            record = copy.deepcopy(case["record"])
            record["releases"][index]["licence"]["restrictions"][name] = None
            record["nullValues"].append({"row": row["id"], "field": "licence.restrictions." + name, "kind": "UNREAD"})
            need(release_outcome(record["releases"][index]) == "DENY_RELEASE",
                 "vector %s: a null %s on %s still allows" % (case["id"], name, row["id"]))
            need(check_record(record, read, policy) != [],
                 "vector %s: a null %s on %s passes (fail closed)" % (case["id"], name, row["id"]))
            probes += 1
    return probes


def check_vectors(vectors, policy):
    closed(vectors, ("schemaVersion", "cases"), "the vectors file")
    need(vectors["schemaVersion"] == VECTORS_VERSION and type(vectors["cases"]) is list and vectors["cases"],
         "the vectors' schemaVersion and cases")
    ids, covered, probes = [], set(), 0
    for case in vectors["cases"]:
        closed(case, ("id", "title", "polarity", "record", "sources", "expect"), "a vector")
        closed(case["expect"], ("refusals",), "a vector's expect")
        need(case["polarity"] in ("positive", "negative") and text(case["title"]), "vector %s's polarity" % case["id"])
        got = [code for code, _ in check_record(case["record"], _source_reader(case["sources"]), policy)]
        need(got == case["expect"]["refusals"], "vector %s gives %s" % (case["id"], got))
        need((case["polarity"] == "positive") == (got == []), "vector %s's polarity" % case["id"])
        if case["polarity"] == "positive":
            probes += null_probe(case, policy)
        covered.update(got)
        ids.append(case["id"])
    need(len(ids) == len(set(ids)), "vector ids are unique")
    need(set(CODES[2:9]) <= covered, "the negatives cover C-2 to C-8")
    need(probes > 0, "the fail-closed probe ran over at least one allowing row")
    return probes


def check(read):
    """The refusals of the record, its schema, its vectors and the v3 amendment at read; [] when all pass."""
    try:
        policy = policy_facts(read)
    except Exception as exc:
        return [("MW_POLICY", str(exc))]
    try:
        schema = parse_json(read(SCHEMA_PATH))
        need(type(schema) is dict and schema.get("required") == list(TOP), "the schema requires the record's members")
        rule = schema.get("candidateNullRule")
        need(type(rule) is dict and rule.get("fields") == list(CANDIDATE_NULL_FIELDS)
             and rule.get("schemaNulls") == list(SCHEMA_NULLS) and rule.get("kinds") == list(NULL_KINDS),
             "the schema states the candidate-row null rule")
        record = parse_json(read(RECORD_PATH))
        vectors = parse_json(read(VECTORS_PATH))
    except Exception as exc:
        return [("MW_SCHEMA", str(exc))]
    refusals = check_record(record, read, policy)
    try:
        check_vectors(vectors, policy)
    except Exception as exc:
        refusals.append(("MW_VECTORS", str(exc)))
    return refusals


def _refuse_unless(ok: bool, message: str) -> None:
    if not ok:
        raise ValueError(message)


def disk_reader(root: Path = ROOT):
    """The checker's own repository reader: bounded, regular, single-link files under root, exact relative paths only,
    linked ancestors refused (validate_decision_record's reader form)."""
    def read(path: str) -> bytes:
        _refuse_unless(type(path) is str and path and not path.startswith("/") and "\\" not in path and "\n" not in path
                       and all(part not in ("", ".", "..") for part in path.split("/")),
                       "unsafe repository path: %r" % (path,))
        parent = root
        for part in path.split("/")[:-1]:
            parent /= part
            _refuse_unless(stat.S_ISDIR(parent.lstat().st_mode), "linked or missing ancestor: " + path)
        target = parent / path.split("/")[-1]
        before = target.lstat()
        _refuse_unless(stat.S_ISREG(before.st_mode) and before.st_nlink == 1 and before.st_size <= MAX_BYTES,
                       "bounded regular single-link file: " + path)
        raw = target.read_bytes()
        after = target.lstat()

        def identity(row):
            return row.st_dev, row.st_ino, row.st_mode, row.st_nlink, row.st_size, row.st_mtime_ns, row.st_ctime_ns
        _refuse_unless(identity(before) == identity(after) and len(raw) == before.st_size,
                       "file changed during read: " + path)
        return raw
    return read


def main(argv=None):
    root = Path((argv or sys.argv[1:] or [str(ROOT)])[0])
    read = disk_reader(root)
    refusals = check(read)
    if refusals:
        for code, _ in refusals:
            print("refused: %s" % code)
        print("MODEL WEIGHTS REFUSED: %d" % len(refusals))
        return 1
    record, vectors = parse_json(read(RECORD_PATH)), parse_json(read(VECTORS_PATH))
    outcomes = [r["licence"]["outcome"] for r in record["releases"]]
    print("MODEL WEIGHTS OK: %d rows (%s), %d pinned, %d served ids, %d null values, %d vectors" % (
        len(outcomes), ", ".join("%s %d" % (o, outcomes.count(o)) for o in OUTCOMES if o in outcomes),
        sum(r["weights"]["digestStatus"] == "PINNED" for r in record["releases"]),
        len(served_ids(record, read)), len(record["nullValues"]), len(vectors["cases"])))
    return 0


if __name__ == "__main__":
    sys.exit(main())
