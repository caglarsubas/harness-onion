#!/usr/bin/env python3
"""Review record v2 (architecture/review-record/, REVIEW-RECORD-V2): reference model and checker, DATA_CHECK_ONLY.

A review round is two records, bound by the sha256 of the record file's bytes: the reviewer's record
(`planeon.review-record/v2`) and the operator's identity record (`planeon.review-identity/v2`). A brief registry
(`planeon.review-briefs/v1`) pins the published brief of each series; a frozen list (`planeon.legacy-review-records/v1`)
names the review records that predate v2; an oracle identity (`planeon.oracle-identity/v1`) binds each oracle test file
written outside the candidate (D5a).

Each check raises `Refused(code)` on the first rule broken, in the order the contract gives:
- `check_review(record_bytes, record_path, identity_bytes, identity_path, registry, head=None, repository=None)`, in the
  order of REVIEW_CODES;
- `check_series(records, identities, registry)`, then SERIES_CODES;
- `check_oracle(identity_bytes, identity_path, file_bytes)` and `check_pr_oracles(changed_paths, identities, read)`;
- `check_merge(cited, registry, head)`, NO_HEAD_BOUND_ROUND when no cited head-bound final round passes (a series'
  final round is its highest cited round);
- `check_tree(root, legacy, registry, repository)`, the in-suite pre-check over a checkout (no git).

PRIVACY matches an absolute-path shape, an e-mail shape and the legacy term (by a sha256 prefix), and reports counts
only. Name tokens are matched by sha256 too, but their table ships empty (owner Q-RR2-NAMES, "Load hashes locally"):
local scans fill it with `load_name_tokens(path)` from an unpublished file. Standard library only.
"""
from __future__ import annotations

import datetime
import fnmatch
import hashlib
import json
import os
import posixpath
import re
import tempfile

RECORD_SCHEMA = "planeon.review-record/v2"
IDENTITY_SCHEMA = "planeon.review-identity/v2"
ORACLE_SCHEMA = "planeon.oracle-identity/v1"
BRIEFS_SCHEMA = "planeon.review-briefs/v1"
LEGACY_SCHEMA = "planeon.legacy-review-records/v1"
KINDS = ("DESIGN", "CONTRACT", "PACKET", "PR")
HEAD_BOUND = ("PACKET", "PR")
SEVERITIES = ("MAJOR", "MINOR", "NOTE")
DISPOSITIONS = ("ADDRESSED", "PARTLY", "NOT")
DECISIONS = ("NONE_NEEDED", "PENDING", "KEEP", "VOID")
RULERS = ("LANE_MONITOR", "OWNER")
COUNTING = ("NONE_NEEDED", "KEEP")
REVIEW_CODES = ("NO_IDENTITY", "NO_BRIEF_DIGEST", "SHAPE", "UNKNOWN_KIND", "BINDING", "PLACEHOLDER_ID",
                "NOT_INDEPENDENT", "IDENTITY_MISMATCH", "SUBJECT_FORM", "SUBJECT_REPOSITORY", "BRIEF_NOT_FOR_SERIES",
                "BRIEF_SUPERSEDED", "VERDICT", "RULING", "SUBJECT_MISMATCH", "PRIVACY")
SERIES_CODES = ("DUPLICATE_ROUND", "SERIES_GAP", "SERIES_FORK", "DUPLICATE_IDENTITY")
ORACLE_CODES = ("SHAPE", "PLACEHOLDER_ID", "ORACLE_DIGEST", "NOT_INDEPENDENT", "RULING", "PRIVACY", "ORACLE_MISSING")
TREE_CODES = ("LEGACY_CHANGED", "NO_IDENTITY", "ORACLE_MISSING")
MERGE_CODES = ("NO_HEAD_BOUND_ROUND",)
PLACEHOLDERS = ("stamped_by_operator", "recorded-by-the-launcher", "unknown", "none")
# The closed members of each record (the schemas under schemas/ state the same sets).
RECORD_REQUIRED = ("schemaVersion", "kind", "series", "round", "subject", "reviewDate", "briefSha256", "rulesSha256",
                   "wrapperSha256", "reviewer", "verdict", "findings", "checked", "disclosures")
RECORD_OPTIONAL = ("base", "bindingRules", "dispositions", "notChecked", "questions")
IDENTITY_REQUIRED = ("schemaVersion", "record", "reviewer", "operator", "author", "briefSha256", "rulesSha256",
                     "wrapperSha256", "subject", "launched", "finished", "interruptions", "operatorRelays", "runs",
                     "ruling")
IDENTITY_OPTIONAL = ("base",)
ORACLE_REQUIRED = ("schemaVersion", "file", "oracle", "operator", "author", "briefSha256", "candidateCommit",
                   "launched", "finished", "ruling")
ORACLE_OPTIONAL = ("disclosures",)
# MET-GOV-001's ORACLE_TESTS class, as the evolution surface record states it: {"under": "tests/", "name": ...}.
ORACLE_TESTS = ("tests/", "test_*oracle*.py")
RECORD_NAME = re.compile(r"^review-round([1-9][0-9]{0,3})\.json$")
IDENTITY_NAME = "review-identity-round%d.json"
ORACLE_NAME = "oracle-identity*.json"
# PRIVACY by digest only, so no published file holds a name token or the legacy term. Name tokens: {length: sha256 of
# each token}, matched against every substring of that length in the lowercased text. The table ships empty (owner
# Q-RR2-NAMES): a short token's digest is easily reversed, so the digests stay in an unpublished local file that
# `load_name_tokens` reads for the lanes' and the monitor's local scans. The legacy term's digest prefix is matched
# against every run of exactly seven lowercase letters.
NAME_TOKEN_SHA256: dict = {}
LEGACY_TERM_PREFIX = "3367f5675f6a2486"
END = r"(?![\s\S])"
HEX64 = re.compile(r"^[0-9a-f]{64}" + END)
HEX40 = re.compile(r"^[0-9a-f]{40}" + END)
# The schemas carry the same two patterns (RR2C1-3, RR2C2-2: no year 0000); a day the month lacks (02-30) is SHAPE in
# the model only.
DAY = r"(?!0000)[0-9]{4}-(?:0[1-9]|1[0-2])-(?:0[1-9]|[12][0-9]|3[01])"
DATE = re.compile("^" + DAY + END)
TIME = re.compile("^" + DAY + r"T(?:[01][0-9]|2[0-3]):[0-5][0-9]:[0-5][0-9](?:\.[0-9]{1,9})?"
                  r"(?:Z|[+-](?:[01][0-9]|2[0-3]):[0-5][0-9])" + END)
AGENT_ID = re.compile(r"^[a-z0-9][a-z0-9_-]{7,79}" + END)
SERIES = re.compile(r"^[A-Z][A-Z0-9-]{1,63}/[a-z][a-z0-9-]{0,31}" + END)
SERIES_PREFIX = re.compile(r"^[A-Z][A-Z0-9-]{1,63}/" + END)
REPOSITORY = re.compile(r"^[A-Za-z0-9._-]{1,100}" + END)
FILE_PATH = re.compile(r"^(?!/)(?!(?:.*/)?\.\.?(?:/|" + END + r"))(?:[A-Za-z0-9_.-]+/)*[A-Za-z0-9_.-]+" + END)
ABSOLUTE_PATH = re.compile(r"(?<![A-Za-z0-9_.~-])/(?:Users|home|private|root)/")
EMAIL = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")
SEVEN = re.compile(r"(?<![a-z])[a-z]{7}(?![a-z])")


class Refused(ValueError):
    """A record (or a request about it) breaks a rule; `code` is one of the code tuples above."""

    def __init__(self, code: str):
        super().__init__(code)
        self.code = code


def _refuse(ok: bool, code: str) -> None:
    if not ok:
        raise Refused(code)


def file_sha256(raw: bytes) -> str:
    """The binding digest (owner D-3): the sha256 of the file's bytes, 64 lowercase hex, no prefix."""
    return hashlib.sha256(bytes(raw)).hexdigest()


# ---------------------------------------------------------------- I-JSON reading

def _no_constant(name):
    raise Refused("SHAPE")


def _members(pairs):
    names = [name for name, _ in pairs]
    _refuse(len(names) == len(set(names)), "SHAPE")
    return dict(pairs)


def load(raw):
    """Record bytes as I-JSON (RFC 7493): UTF-8, no duplicate member names, no NaN or infinity, no lone surrogate.
    Anything else is SHAPE. Records need not be canonical; the binding is the file's bytes."""
    try:
        text = bytes(raw).decode("utf-8") if isinstance(raw, (bytes, bytearray)) else raw
        text.encode("utf-8")
        value = json.loads(text, object_pairs_hook=_members, parse_constant=_no_constant)
        stack = [value]
        while stack:
            item = stack.pop()
            if type(item) is str:
                item.encode("utf-8")
            elif type(item) is list:
                stack.extend(item)
            elif type(item) is dict:
                stack.extend(item)
                stack.extend(item.values())
        return value
    except Refused:
        raise
    except (ValueError, TypeError, AttributeError, RecursionError, UnicodeError) as exc:
        raise Refused("SHAPE") from exc  # B-10: a check takes a file's bytes, never a parsed object


# ---------------------------------------------------------------- shape (the schemas' rules, mirrored)

def _str(value, pattern=None) -> bool:
    return type(value) is str and (pattern.search(value) is not None if pattern else 1 <= len(value) <= 4000)


def _closed(value, required, optional=()) -> bool:
    return type(value) is dict and set(required) <= set(value) <= set(required) | set(optional)


def _plain(value) -> bool:
    """B-6: kind and every agentId are plain strings in the schemas (no enum, no pattern, no minimum length), so
    UNKNOWN_KIND and PLACEHOLDER_ID are reached after SHAPE."""
    return type(value) is str and len(value) <= 4000


def _strings(value, low=0) -> bool:
    return type(value) is list and len(value) >= low and all(_str(v) for v in value)


def _unique_strings(value, low=0) -> bool:
    return _strings(value, low) and len(value) == len(set(value))


def _nullable_hex(value) -> bool:
    return value is None or _str(value, HEX64)


def _subject(value) -> bool:
    if _closed(value, ("repository", "commit", "tree")):
        return _str(value["repository"], REPOSITORY) and _str(value["commit"], HEX40) and _str(value["tree"], HEX40)
    return _closed(value, ("path", "sha256")) and _str(value["path"], FILE_PATH) and _str(value["sha256"], HEX64)


def _int(value, low) -> bool:
    return type(value) is int and low <= value <= 2 ** 53 - 1


def _finding(f) -> bool:
    return (_closed(f, ("id", "severity", "location", "finding", "requiredChange", "blocks"))
            and _str(f["id"]) and f["severity"] in SEVERITIES and _str(f["location"]) and _str(f["finding"])
            and _str(f["requiredChange"]) and type(f["blocks"]) is bool)


def _checked(c) -> bool:
    return _str(c) or (_closed(c, ("check", "result")) and _str(c["check"]) and _str(c["result"]))


def _record_shape(r) -> bool:
    if not _closed(r, RECORD_REQUIRED, RECORD_OPTIONAL) or r["schemaVersion"] != RECORD_SCHEMA:
        return False
    ok = (_plain(r["kind"]) and _str(r["series"], SERIES) and _int(r["round"], 1) and _subject(r["subject"])
          and ("base" not in r or _subject(r["base"])) and _str(r["reviewDate"], DATE) and _valid_date(r["reviewDate"])
          and _str(r["briefSha256"], HEX64) and _nullable_hex(r["rulesSha256"]) and _nullable_hex(r["wrapperSha256"])
          and _closed(r["reviewer"], ("model", "role")) and _str(r["reviewer"]["model"])
          and _str(r["reviewer"]["role"]) and _str(r["verdict"])
          and type(r["findings"]) is list and all(_finding(f) for f in r["findings"])
          and type(r["checked"]) is list and len(r["checked"]) >= 1 and all(_checked(c) for c in r["checked"])
          and _strings(r["disclosures"]))
    if not ok:
        return False
    if "bindingRules" in r and not (type(r["bindingRules"]) is list and all(
            _closed(b, ("rule", "met", "note")) and _str(b["rule"]) and type(b["met"]) is bool and _str(b["note"])
            for b in r["bindingRules"])):
        return False
    if "dispositions" in r and not (type(r["dispositions"]) is list and all(
            _closed(d, ("id", "status"), ("note",)) and _str(d["id"]) and d["status"] in DISPOSITIONS
            and ("note" not in d or _str(d["note"])) for d in r["dispositions"])):
        return False
    return all(_strings(r[k]) for k in ("notChecked", "questions") if k in r)


def _valid_date(value: str) -> bool:
    try:
        datetime.date.fromisoformat(value)
        return True
    except ValueError:
        return False


def _instant(value: str) -> tuple:
    """A TIME value as (UTC seconds, nanoseconds), keeping all nine fraction digits the form allows (datetime keeps
    only six)."""
    whole, offset = value[:19], value[19:]
    fraction = ""
    if offset.startswith("."):
        digits = re.match(r"\.([0-9]{1,9})", offset)
        fraction, offset = digits.group(1), offset[digits.end():]
    moment = datetime.datetime.fromisoformat(whole + ("+00:00" if offset == "Z" else offset))
    return int(moment.timestamp()), int(fraction.ljust(9, "0") or "0")


def _time(value) -> bool:
    if not _str(value, TIME):
        return False
    try:
        _instant(value)
        return True
    except ValueError:
        return False


def _ruling(value) -> bool:
    return (_closed(value, ("decision",), ("by", "ref", "date")) and value["decision"] in DECISIONS
            and ("by" not in value or value["by"] in RULERS) and ("ref" not in value or _str(value["ref"]))
            and ("date" not in value or (_str(value["date"], DATE) and _valid_date(value["date"]))))


def _operator(value) -> bool:
    # B-10: a published identity is written only by LANE_SESSION; a monitor-written identity is refused here.
    return (_closed(value, ("role", "agentId"), ("lane",)) and value["role"] == "LANE_SESSION"
            and _plain(value["agentId"]) and ("lane" not in value or _str(value["lane"])))


def _author(value) -> bool:
    ids = value.get("agentIds") if type(value) is dict else None
    return (_closed(value, ("agentIds",)) and type(ids) is list and len(ids) >= 1 and all(_plain(v) for v in ids)
            and len(ids) == len(set(ids)))


def _identity_shape(i) -> bool:
    if not _closed(i, IDENTITY_REQUIRED, IDENTITY_OPTIONAL) or i["schemaVersion"] != IDENTITY_SCHEMA:
        return False
    return (_closed(i["record"], ("path", "sha256")) and _str(i["record"]["path"], FILE_PATH)
            and _str(i["record"]["sha256"], HEX64)
            and _closed(i["reviewer"], ("agentId", "agentType", "model")) and _plain(i["reviewer"]["agentId"])
            and _str(i["reviewer"]["agentType"]) and _str(i["reviewer"]["model"])
            and _operator(i["operator"]) and _author(i["author"])
            and _str(i["briefSha256"], HEX64) and _nullable_hex(i["rulesSha256"]) and _nullable_hex(i["wrapperSha256"])
            and _subject(i["subject"]) and ("base" not in i or _subject(i["base"]))
            and _time(i["launched"]) and _time(i["finished"]) and _instant(i["launched"]) <= _instant(i["finished"])
            and _strings(i["interruptions"]) and _strings(i["operatorRelays"])
            and type(i["runs"]) is list and all(_closed(x, ("limit", "used")) and _str(x["limit"]) and _int(x["used"], 0)
                                                for x in i["runs"])
            and _ruling(i["ruling"]))


def _oracle_shape(o) -> bool:
    if not _closed(o, ORACLE_REQUIRED, ORACLE_OPTIONAL) or o["schemaVersion"] != ORACLE_SCHEMA:
        return False
    return (_closed(o["file"], ("path", "sha256")) and _str(o["file"]["path"], FILE_PATH)
            and _str(o["file"]["sha256"], HEX64)
            and _closed(o["oracle"], ("agentId", "model")) and _plain(o["oracle"]["agentId"])
            and _str(o["oracle"]["model"])
            and _operator(o["operator"]) and _author(o["author"]) and _str(o["briefSha256"], HEX64)
            and _str(o["candidateCommit"], HEX40) and _time(o["launched"]) and _time(o["finished"])
            and _instant(o["launched"]) <= _instant(o["finished"]) and _ruling(o["ruling"])
            and ("disclosures" not in o or _strings(o["disclosures"])))


# ---------------------------------------------------------------- the brief registry and the legacy list

def _series_matches(entry_series: str, series: str) -> bool:
    if entry_series.endswith("/"):
        return series.startswith(entry_series)
    return series == entry_series


def _overlap(a: str, b: str) -> bool:
    """Two registry series patterns that can match one series id."""
    if a.endswith("/") and b.endswith("/"):
        return a.startswith(b) or b.startswith(a)
    if a.endswith("/"):
        return b.startswith(a)
    if b.endswith("/"):
        return a.startswith(b)
    return a == b


def load_registry(raw) -> dict:
    """The brief registry, checked when loaded (B-3): closed shape; every kind's passing verdicts within its list; a
    brief's kind among the kinds; a superseded version names its successor; and no series matched by two entries that
    are not one brief's versions (an exact id and a prefix, or two prefixes, over one series). Anything else is SHAPE."""
    reg = load(raw) if isinstance(raw, (bytes, bytearray, str)) else raw
    _refuse(_closed(reg, ("schemaVersion", "kinds", "briefs")) and reg["schemaVersion"] == BRIEFS_SCHEMA, "SHAPE")
    kinds = reg["kinds"]
    _refuse(type(kinds) is dict and set(kinds) == set(KINDS), "SHAPE")
    for spec in kinds.values():
        _refuse(_closed(spec, ("verdicts", "passing")) and _unique_strings(spec["verdicts"], 1)
                and _unique_strings(spec["passing"], 1) and set(spec["passing"]) <= set(spec["verdicts"]), "SHAPE")
    briefs = reg["briefs"]
    _refuse(type(briefs) is list, "SHAPE")
    for b in briefs:
        _refuse(_closed(b, ("kind", "series", "path", "sha256", "version"), ("supersedes", "supersededAt"))
                and b["kind"] in KINDS and (_str(b["series"], SERIES) or _str(b["series"], SERIES_PREFIX))
                and _str(b["path"], FILE_PATH) and _str(b["sha256"], HEX64) and _int(b["version"], 1)
                and ("supersedes" not in b or _str(b["supersedes"], HEX64))
                and ("supersededAt" not in b or _time(b["supersededAt"])), "SHAPE")
    # One kind per series pattern, and versions of one brief chained by `supersedes`.
    by_series: dict = {}
    for b in briefs:
        by_series.setdefault(b["series"], []).append(b)
    for series, entries in by_series.items():
        _refuse(len({b["kind"] for b in entries}) == 1, "SHAPE")
        _refuse(len({b["version"] for b in entries}) == len(entries), "SHAPE")
        _refuse(len({b["sha256"] for b in entries}) == len(entries), "SHAPE")
        ordered = sorted(entries, key=lambda b: b["version"])
        # A chain starts at version 1 with no `supersedes` (RR2C1-15); each successor is the next version, names its
        # predecessor, and is superseded, if at all, later than its predecessor; the latest is current.
        _refuse(ordered[0]["version"] == 1 and "supersedes" not in ordered[0], "SHAPE")
        for older, newer in zip(ordered, ordered[1:]):
            _refuse("supersededAt" in older and newer.get("supersedes") == older["sha256"]
                    and newer["version"] == older["version"] + 1, "SHAPE")
            _refuse("supersededAt" not in newer or _instant(older["supersededAt"]) < _instant(newer["supersededAt"]),
                    "SHAPE")
        _refuse("supersededAt" not in ordered[-1], "SHAPE")
    patterns = sorted(by_series)
    for i, a in enumerate(patterns):
        for b in patterns[i + 1:]:
            _refuse(not _overlap(a, b), "SHAPE")  # overlapping entries (B-3)
    return reg


def load_legacy(raw) -> dict:
    """The frozen list `planeon.legacy-review-records/v1`: {baseCommit, entries: [{path, sha256}], oracleTests: [{path,
    sha256}]}, each list sorted by path and unique. Review records and oracle test files alike are frozen by path and
    file digest (design rev 4 B-9; the monitor's Q-RR2-FROZEN keeps that stricter rule)."""
    doc = load(raw) if isinstance(raw, (bytes, bytearray, str)) else raw
    _refuse(_closed(doc, ("schemaVersion", "baseCommit", "entries", "oracleTests"))
            and doc["schemaVersion"] == LEGACY_SCHEMA and _str(doc["baseCommit"], HEX40)
            and type(doc["entries"]) is list and type(doc["oracleTests"]) is list, "SHAPE")
    for frozen in (doc["entries"], doc["oracleTests"]):
        paths = [e.get("path") if type(e) is dict else None for e in frozen]
        _refuse(all(_closed(e, ("path", "sha256")) and _str(e["path"], FILE_PATH) and _str(e["sha256"], HEX64)
                    for e in frozen) and paths == sorted(set(paths)), "SHAPE")
    return doc


def load_name_tokens(path) -> int:
    """Fill NAME_TOKEN_SHA256 from an unpublished local file (owner Q-RR2-NAMES): a JSON object {"<length>": [sha256 of
    each lowercase token of that length]}. For the lanes' and the monitor's local scans only; the suite never calls it.
    Returns the number of digests loaded; anything malformed is SHAPE and leaves the table unchanged."""
    global NAME_TOKEN_SHA256
    with open(path, "rb") as handle:
        doc = load(handle.read())
    _refuse(type(doc) is dict and all(type(n) is str and re.fullmatch(r"[1-9][0-9]?", n) and type(d) is list and d
                                      and all(_str(x, HEX64) for x in d) for n, d in doc.items()), "SHAPE")
    NAME_TOKEN_SHA256 = {int(n): tuple(d) for n, d in doc.items()}
    return sum(len(d) for d in doc.values())


# ---------------------------------------------------------------- privacy (by digest only)

def privacy_hits(raw) -> dict:
    """Counts only: name tokens (by sha256 of every substring of a token's length), seven-letter runs whose sha256 has
    the legacy term's prefix, absolute home-path shapes and e-mail shapes."""
    text = bytes(raw).decode("utf-8", "replace") if isinstance(raw, (bytes, bytearray)) else str(raw)
    low = text.lower()
    names = 0
    for n, digests in NAME_TOKEN_SHA256.items():
        for i in range(len(low) - n + 1):
            if hashlib.sha256(low[i:i + n].encode("utf-8")).hexdigest() in digests:
                names += 1
    term = sum(1 for m in SEVEN.finditer(low)
               if hashlib.sha256(m.group(0).encode("utf-8")).hexdigest().startswith(LEGACY_TERM_PREFIX))
    return {"names": names, "legacyTerm": term, "absolutePaths": len(ABSOLUTE_PATH.findall(text)),
            "emails": len(EMAIL.findall(text))}


def _string_values(value):
    if isinstance(value, str):
        yield value
    elif isinstance(value, dict):
        for key, item in value.items():
            yield key
            yield from _string_values(item)
    elif isinstance(value, list):
        for item in value:
            yield from _string_values(item)


def _private(*raws) -> bool:
    """A hit in the raw text, or in any parsed string value, so a JSON escape cannot hide one (RR2C1-10)."""
    for raw in raws:
        if any(privacy_hits(raw).values()):
            return True
        try:
            value = load(raw)
        except Refused:
            continue
        if any(any(privacy_hits(s).values()) for s in _string_values(value)):
            return True
    return False


# ---------------------------------------------------------------- one round

def _agent_ids(identity) -> list:
    return [identity["reviewer"]["agentId"], identity["operator"]["agentId"]] + list(identity["author"]["agentIds"])


def _placeholder(agent_id: str) -> bool:
    return not _str(agent_id, AGENT_ID) or agent_id in PLACEHOLDERS


def _brief_entry(registry, record):
    """The registered entry the record's brief resolves to for its series and kind, or None."""
    for b in registry["briefs"]:
        if b["sha256"] == record["briefSha256"] and b["kind"] == record["kind"] and _series_matches(b["series"],
                                                                                                    record["series"]):
            return b
    return None


def _ruling_ok(ruling, empty: bool) -> bool:
    decision = ruling["decision"]
    if decision in ("PENDING", "VOID"):
        return False
    if decision == "NONE_NEEDED":
        return empty
    return all(k in ruling for k in ("by", "ref", "date"))


def check_review(record_bytes, record_path: str, identity_bytes, identity_path, registry, head=None,
                 repository=None) -> dict:
    """One round, in the order of REVIEW_CODES. `registry` is a loaded registry; `head` is {commit, tree} of a PR head
    (SUBJECT_MISMATCH is judged only when it is given); `repository` is the repository whose tree holds the record
    (SUBJECT_REPOSITORY is judged only when it is given). Returns the round's facts."""
    _refuse(identity_bytes is not None, "NO_IDENTITY")
    record = load(record_bytes)
    _refuse(type(record) is not dict or _str(record.get("briefSha256"), HEX64), "NO_BRIEF_DIGEST")
    identity = load(identity_bytes)
    _refuse(_record_shape(record) and _identity_shape(identity) and _str(record_path, FILE_PATH)
            and (identity_path is None or _str(identity_path, FILE_PATH)), "SHAPE")
    _refuse(record["kind"] in registry["kinds"], "UNKNOWN_KIND")
    _refuse(identity["record"] == {"path": record_path, "sha256": file_sha256(record_bytes)}, "BINDING")
    _refuse(not any(_placeholder(a) for a in _agent_ids(identity)), "PLACEHOLDER_ID")
    reviewer = identity["reviewer"]["agentId"]
    _refuse(reviewer != identity["operator"]["agentId"] and reviewer not in identity["author"]["agentIds"],
            "NOT_INDEPENDENT")
    same = (identity["reviewer"]["model"] == record["reviewer"]["model"]
            and all(identity[k] == record[k] for k in ("briefSha256", "rulesSha256", "wrapperSha256", "subject"))
            and identity.get("base") == record.get("base") and ("base" in identity) == ("base" in record))
    _refuse(same, "IDENTITY_MISMATCH")
    head_bound = record["kind"] in HEAD_BOUND
    _refuse(not head_bound or "repository" in record["subject"], "SUBJECT_FORM")
    _refuse(repository is None or "repository" not in record["subject"]
            or record["subject"]["repository"] == repository, "SUBJECT_REPOSITORY")
    entry = _brief_entry(registry, record)
    _refuse(entry is not None, "BRIEF_NOT_FOR_SERIES")
    if "supersededAt" in entry:
        cut = _instant(entry["supersededAt"])
        _refuse(_instant(identity["launched"]) < cut and record["reviewDate"] < entry["supersededAt"][:10],
                "BRIEF_SUPERSEDED")
    spec = registry["kinds"][record["kind"]]
    _refuse(record["verdict"] in spec["verdicts"], "VERDICT")
    empty = not record["disclosures"] and not identity["interruptions"] and not identity["operatorRelays"]
    _refuse(_ruling_ok(identity["ruling"], empty), "RULING")
    if head is not None and head_bound:
        _refuse(record["subject"]["tree"] == head["tree"], "SUBJECT_MISMATCH")
    _refuse(not _private(record_bytes, identity_bytes), "PRIVACY")
    return {"kind": record["kind"], "series": record["series"], "round": record["round"],
            "verdict": record["verdict"], "passing": record["verdict"] in spec["passing"],
            "headBound": head_bound, "decision": identity["ruling"]["decision"], "full": "base" not in record}


# ---------------------------------------------------------------- a series

def check_series(records, identities, registry, head=None, repository=None) -> dict:
    """Every round of one series: `records` and `identities` are lists of (path, bytes). Each round passes
    `check_review` with its identity (the one naming its path); then DUPLICATE_ROUND, SERIES_GAP, SERIES_FORK and
    DUPLICATE_IDENTITY. A full round (no base) may follow any round; a delta's base is the previous round's subject."""
    parsed_ids = [(path, raw, load(raw)) for path, raw in identities]
    for _path, _raw, ident in parsed_ids:
        _refuse(_identity_shape(ident), "SHAPE")
    named: dict = {}
    for path, raw, ident in parsed_ids:
        named.setdefault(ident["record"]["path"], []).append((path, raw))
    rounds = []
    for path, raw in records:
        found = named.get(path, [])
        facts = check_review(raw, path, found[0][1] if found else None, found[0][0] if found else None, registry,
                             head=head, repository=repository)
        rounds.append((facts, load(raw)))
    series = {facts["series"] for facts, _ in rounds}
    _refuse(len(series) <= 1, "SHAPE")
    numbers = [facts["round"] for facts, _ in rounds]
    _refuse(len(numbers) == len(set(numbers)), "DUPLICATE_ROUND")
    _refuse(sorted(numbers) == list(range(1, len(numbers) + 1)), "SERIES_GAP")
    by_round = {facts["round"]: rec for facts, rec in rounds}
    bases = [json.dumps(rec["base"], sort_keys=True) for rec in by_round.values() if "base" in rec]
    _refuse(len(bases) == len(set(bases)), "SERIES_FORK")
    for n in sorted(by_round):
        rec = by_round[n]
        if "base" in rec:
            _refuse(n > 1 and rec["base"] == by_round[n - 1]["subject"], "SERIES_FORK")
    record_paths = {path for path, _ in records}
    raws = [raw for _path, raw, _ident in parsed_ids]
    _refuse(all(len(v) == 1 for k, v in named.items() if k in record_paths) and len(raws) == len(set(raws)),
            "DUPLICATE_IDENTITY")
    last = by_round[max(by_round)] if by_round else None
    return {"series": next(iter(series)) if series else None, "rounds": len(numbers),
            "final": rounds[[f["round"] for f, _ in rounds].index(max(numbers))][0] if rounds else None,
            "lastSubject": last["subject"] if last else None}


# ---------------------------------------------------------------- oracle identities (D5a)

def _is_oracle_test(path: str) -> bool:
    under, name = ORACLE_TESTS
    return path.startswith(under) and fnmatch.fnmatchcase(posixpath.basename(path), name)


def check_oracle(identity_bytes, identity_path, file_bytes) -> dict:
    """One oracle identity against the oracle file's bytes (at the head, or in the tree)."""
    oracle = load(identity_bytes)
    _refuse(_oracle_shape(oracle) and (identity_path is None or _str(identity_path, FILE_PATH)), "SHAPE")
    ids = [oracle["oracle"]["agentId"], oracle["operator"]["agentId"]] + list(oracle["author"]["agentIds"])
    _refuse(not any(_placeholder(a) for a in ids), "PLACEHOLDER_ID")
    _refuse(file_bytes is not None and file_sha256(file_bytes) == oracle["file"]["sha256"], "ORACLE_DIGEST")
    agent = oracle["oracle"]["agentId"]
    _refuse(agent != oracle["operator"]["agentId"] and agent not in oracle["author"]["agentIds"], "NOT_INDEPENDENT")
    _refuse(_ruling_ok(oracle["ruling"], not oracle.get("disclosures")), "RULING")
    _refuse(not _private(identity_bytes), "PRIVACY")
    return {"file": oracle["file"]["path"], "decision": oracle["ruling"]["decision"]}


def check_pr_oracles(changed_paths, identities, read_bytes_at_head, contract_series: bool = False) -> list:
    """B-5: every changed ORACLE_TESTS file has an oracle identity whose file digest matches at the head; a PR with a
    CONTRACT series has at least one. `identities` is a list of (path, bytes); `read_bytes_at_head(path)` returns the
    file's bytes at the head, or None."""
    parsed = [(path, raw, load(raw)) for path, raw in identities]
    for _path, _raw, o in parsed:
        _refuse(_oracle_shape(o), "SHAPE")
    changed = sorted(p for p in changed_paths if _is_oracle_test(p))
    _refuse(not contract_series or parsed, "ORACLE_MISSING")
    out = []
    for path in changed:
        mine = [(p, raw) for p, raw, o in parsed if o["file"]["path"] == path]
        _refuse(bool(mine), "ORACLE_MISSING")
        for p, raw in mine:
            out.append(check_oracle(raw, p, read_bytes_at_head(path)))
    for p, raw, o in parsed:
        if o["file"]["path"] not in changed:
            out.append(check_oracle(raw, p, read_bytes_at_head(o["file"]["path"])))
    return out


# ---------------------------------------------------------------- the merge (the monitor's check)

def _voided_sibling(registry, series: str, voided) -> bool:
    """Q-RR2-VOID-PREFIX (b), as corrected by contract r4 (RR2C4-1): a series under a prefix entry, while another series
    under that prefix holds a VOID round. Every series under that prefix then counts for nothing until the registry
    changes; the rerun needs an entry with another packet-id part (an owner-approved registry change), since B-3 refuses
    an exact id beneath a prefix. A series with an exact entry is under no prefix (B-3), so it is never stopped here."""
    if any(b["series"] == series for b in registry["briefs"]):
        return False
    prefixes = {b["series"] for b in registry["briefs"] if b["series"].endswith("/") and series.startswith(b["series"])}
    return any(v != series and any(v.startswith(p) for p in prefixes) for v in voided)


def check_merge(cited, registry, head, voided=()) -> list:
    """`cited` is a list of {record, recordPath, identity, identityPath} (bytes and paths) for the head-bound final
    rounds a merge cites, with every round of each such series from round 1 (B-4, RR2C1-1); `head` is {commit, tree}.
    `voided` is a list of the series ids that hold a VOID round, from the monitor's and the owner's rulings; a cited
    series under a prefix entry counts for nothing while another series under that prefix is listed (Q-RR2-VOID-PREFIX,
    RR2C4-1). Anything but a list or tuple of strings refuses the merge (RR2C4-3).
    Each cited series must pass `check_series` (head-less: earlier rounds reviewed earlier trees), and its final round,
    the highest, must pass `check_review` against the head with a passing verdict and a counting ruling (NONE_NEEDED
    or KEEP). A cited record that cannot be read as a round (a string series and an integer round) refuses the whole
    merge (RR2C1-7, RR2C2-3); a series that fails counts for nothing. Without one counting series: NO_HEAD_BOUND_ROUND.
    Returns the facts of the counting final rounds."""
    groups: dict = {}
    for c in cited:
        try:
            r = load(c["record"])
        except Refused:
            r = None
        _refuse(type(r) is dict and type(r.get("series")) is str and _int(r.get("round"), 1), "NO_HEAD_BOUND_ROUND")
        groups.setdefault(r["series"], []).append((r["round"], c))
    passing = []
    _refuse(type(voided) in (list, tuple) and all(type(v) is str for v in voided), "NO_HEAD_BOUND_ROUND")
    for series, items in sorted(groups.items()):
        if _voided_sibling(registry, series, voided):
            continue
        try:
            check_series([(c["recordPath"], c["record"]) for _n, c in items],
                         [(c["identityPath"], c["identity"]) for _n, c in items if c["identity"] is not None],
                         registry)
            final = max(items, key=lambda item: item[0])[1]
            facts = check_review(final["record"], final["recordPath"], final["identity"], final["identityPath"],
                                 registry, head=head)
        except Refused:
            continue
        if facts["headBound"] and facts["passing"] and facts["decision"] in COUNTING:
            passing.append(facts)
    _refuse(bool(passing), "NO_HEAD_BOUND_ROUND")
    return passing


# ---------------------------------------------------------------- the tree (the in-suite pre-check; no git)

def _walk(root: str):
    for top, dirs, files in os.walk(root, followlinks=False):
        dirs[:] = sorted(d for d in dirs if d not in (".git", "__pycache__", ".pytest_cache"))
        rel = os.path.relpath(top, root)
        rel = "" if rel == "." else rel.replace(os.sep, "/") + "/"
        for name in sorted(files):
            yield rel + name


def check_tree(root, legacy, registry, repository: str) -> dict:
    """The in-suite pre-check over a clean checkout; reads files only and needs no git.
    - The registry (bytes, or a loaded registry) holds no privacy hit (B-8, RR2C1-2).
    - Every `review-round*.json` is on the frozen list with its digest, or is a v2 round `review-round<n>.json` whose
      `round` is n, bound by the `review-identity-round<n>.json` beside it (RR2C1-6); every frozen record is present
      (RR2C1-8). Else LEGACY_CHANGED, SHAPE or NO_IDENTITY.
    - Every directory's v2 rounds form one valid series, and no series spans two directories (SERIES_FORK).
    - Every `oracle-identity*.json` passes `check_oracle` with its file's bytes, ORACLE_DIGEST when the file is absent.
    - Every ORACLE_TESTS file is frozen with its current bytes' digest or bound by an oracle identity, and every frozen
      oracle test is present (ORACLE_MISSING)."""
    raw_registry = registry if isinstance(registry, (bytes, bytearray, str)) else None
    registry = load_registry(registry) if raw_registry is not None else registry
    _refuse(not _private(raw_registry if raw_registry is not None else b"",
                         json.dumps(registry, ensure_ascii=False).encode("utf-8")), "PRIVACY")
    frozen = {e["path"]: e["sha256"] for e in legacy["entries"]}
    frozen_oracles = {e["path"]: e["sha256"] for e in legacy["oracleTests"]}
    paths = list(_walk(str(root)))
    present = set(paths)

    def read(rel):
        with open(os.path.join(str(root), *rel.split("/")), "rb") as handle:
            return handle.read()

    _refuse(all(p in present for p in frozen), "LEGACY_CHANGED")
    series: dict = {}
    legacy_seen = 0
    for rel in paths:
        name = posixpath.basename(rel)
        if not fnmatch.fnmatchcase(name, "review-round*.json"):
            continue
        if rel in frozen:
            _refuse(file_sha256(read(rel)) == frozen[rel], "LEGACY_CHANGED")
            legacy_seen += 1
            continue
        m = RECORD_NAME.match(name)
        _refuse(m is not None, "LEGACY_CHANGED")
        record = load(read(rel))
        _refuse(type(record) is dict and record.get("round") == int(m.group(1))
                and type(record.get("round")) is int, "SHAPE")
        ident = posixpath.join(posixpath.dirname(rel), IDENTITY_NAME % int(m.group(1)))
        _refuse(ident in present, "NO_IDENTITY")
        named = load(read(ident))
        _refuse(type(named) is dict and type(named.get("record")) is dict and named["record"].get("path") == rel,
                "NO_IDENTITY")
        series.setdefault(posixpath.dirname(rel), []).append(rel)
    ids_seen: dict = {}
    for directory in sorted(series):
        records = [(rel, read(rel)) for rel in sorted(series[directory])]
        identities = [(rel, read(rel)) for rel in paths
                      if posixpath.dirname(rel) == directory
                      and fnmatch.fnmatchcase(posixpath.basename(rel), "review-identity-round*.json")]
        facts = check_series(records, identities, registry, repository=repository)
        _refuse(facts["series"] not in ids_seen, "SERIES_FORK")
        ids_seen[facts["series"]] = directory
    oracle_ids = [rel for rel in paths if fnmatch.fnmatchcase(posixpath.basename(rel), ORACLE_NAME)]
    bound: dict = {}
    for rel in oracle_ids:
        raw = read(rel)
        o = load(raw)
        _refuse(_oracle_shape(o), "SHAPE")
        target = o["file"]["path"]
        check_oracle(raw, rel, read(target) if target in present else None)
        bound.setdefault(target, []).append(rel)
    _refuse(all(p in present for p in frozen_oracles), "ORACLE_MISSING")
    oracles = 0
    for rel in paths:
        if not _is_oracle_test(rel):
            continue
        oracles += 1
        if rel in bound:
            continue
        # A legacy oracle file counts as frozen only with its frozen bytes; a changed one needs an oracle identity.
        _refuse(rel in frozen_oracles and file_sha256(read(rel)) == frozen_oracles[rel], "ORACLE_MISSING")
    return {"legacyRecords": legacy_seen, "series": len(series), "oracleTests": oracles,
            "oracleIdentities": len(oracle_ids)}


# ---------------------------------------------------------------- the vector runner

class Mismatch(AssertionError):
    """A vector the model does not reach; raised explicitly, so `python -O` cannot skip the check."""


def _expect(ok: bool, what) -> None:
    if not ok:
        raise Mismatch(what)


def mutate(doc, mutation: list):
    """A copy of `doc` with each step applied: {"path": [...], "value": v} sets, {"path": [...], "parts": [...]} sets
    the parts joined (privacy vectors: no published file holds a home path, an address or a name token whole),
    {"path": [...], "delete": true} removes. A path step is a key or a list index; an index equal to the list's length
    appends."""
    out = json.loads(json.dumps(doc))
    for step in mutation:
        node = out
        for key in step["path"][:-1]:
            node = node[key]
        last = step["path"][-1]
        value = "".join(step["parts"]) if "parts" in step else step.get("value")
        if step.get("delete"):
            del node[last]
        elif type(node) is list and last == len(node):
            node.append(value)
        else:
            node[last] = value
    return out


def serialize(value) -> bytes:
    """How a vector's record is written as a file: indent 1, a trailing newline, UTF-8."""
    return (json.dumps(value, indent=1, ensure_ascii=False) + "\n").encode("utf-8")


def _file(spec, base):
    """A vector's file: absent (None), raw text ({"text": ...}), or the base value with mutations ({"mutate": [...]})."""
    if spec is None:
        return None
    if set(spec) == {"text"}:
        return spec["text"].encode("utf-8")
    return mutate(base, spec["mutate"])


def _round(row, bases):
    """A round's (record bytes, identity bytes). The identity's record path and digest are filled from the record
    unless the row's own mutations set them (a "@record" digest is replaced after the mutations)."""
    record = _file(row.get("record", {"mutate": []}), bases["record"])
    record = record if isinstance(record, bytes) or record is None else serialize(record)
    ident = _file(row.get("identity", {"mutate": []}), bases["identity"])
    if ident is None or isinstance(ident, bytes):
        return record, ident
    if ident["record"]["path"] == "@path":
        ident["record"]["path"] = row["recordPath"]
    if ident["record"]["sha256"] == "@record":
        # An identity with no record of its own (a second identity for one record) binds the base record's bytes.
        base_record = record if record is not None else serialize(mutate(bases["record"], []))
        ident["record"]["sha256"] = file_sha256(base_record)
    return record, serialize(ident)


def _outcome(fn, *args):
    try:
        fn(*args)
        return None
    except Refused as refusal:
        return refusal.code


def _with_tokens(row, fn, *args):
    """Run fn with the row's made-up name-token digests (`tokenSha256`, {"<length>": [sha256]}) in the table, if it
    gives any; the published table stays empty (owner Q-RR2-NAMES)."""
    global NAME_TOKEN_SHA256
    saved = NAME_TOKEN_SHA256
    if "tokenSha256" in row:
        NAME_TOKEN_SHA256 = {int(n): tuple(d) for n, d in row["tokenSha256"].items()}
    try:
        return fn(*args)
    finally:
        NAME_TOKEN_SHA256 = saved


def replay(vectors) -> dict:
    """Replay every vector; raise Mismatch on any difference."""
    _expect(vectors["codes"] == {"review": list(REVIEW_CODES), "series": list(SERIES_CODES),
                                 "oracle": list(ORACLE_CODES), "tree": list(TREE_CODES),
                                 "merge": list(MERGE_CODES)}, "codes")
    bases = vectors["bases"]
    registry = load_registry(bases["registry"])
    counts = {}
    for row in vectors["reviews"]:
        record, ident = _round(row, bases)
        got = _with_tokens(row, _outcome, check_review, record, row["recordPath"], ident, row.get("identityPath"),
                           registry, row.get("head"), row.get("repository"))
        _expect(got == row["expect"], (row["id"], got))
    for row in vectors["series"]:
        records, identities = [], []
        for r in row["rounds"]:
            record, ident = _round(r, bases)
            if record is not None:
                records.append((r["recordPath"], record))
            if ident is not None:
                identities.append((r["identityPath"], ident))
        got = _outcome(check_series, records, identities, registry)
        _expect(got == row["expect"], (row["id"], got))
    for row in vectors["oracles"]:
        oracle = _file(row.get("identity", {"mutate": []}), bases["oracle"])
        oracle = oracle if isinstance(oracle, bytes) else serialize(oracle)
        file_bytes = None if row.get("file") is None else row["file"].encode("utf-8")
        got = _outcome(check_oracle, oracle, row.get("identityPath"), file_bytes)
        _expect(got == row["expect"], (row["id"], got))
    for row in vectors["prOracles"]:
        files = {path: text.encode("utf-8") for path, text in row["files"].items()}
        identities = []
        for x in row["identities"]:
            o = _file(x, bases["oracle"])
            identities.append((x["path"], o if isinstance(o, bytes) else serialize(o)))
        got = _outcome(check_pr_oracles, row["changed"], identities, files.get, row.get("contractSeries", False))
        _expect(got == row["expect"], (row["id"], got))
    for row in vectors["merges"]:
        cited = []
        for c in row["cited"]:
            record, ident = _round(c, bases)
            cited.append({"record": record, "recordPath": c["recordPath"], "identity": ident,
                          "identityPath": c.get("identityPath")})
        got = _outcome(check_merge, cited, registry, row["head"], row.get("voided", []))
        _expect(got == row["expect"], (row["id"], got))
    for row in vectors["registries"]:
        got = _outcome(load_registry, mutate(bases["registry"], row["mutate"]))
        _expect(got == row["expect"], (row["id"], got))
    for row in vectors["legacy"]:
        got = _outcome(load_legacy, mutate(bases["legacy"], row["mutate"]))
        _expect(got == row["expect"], (row["id"], got))
    for row in vectors["trees"]:
        registry_raw = serialize(mutate(bases["registry"], row["registry"]["mutate"]))
        frozen = load_legacy(dict({"schemaVersion": LEGACY_SCHEMA, "baseCommit": "0" * 40}, **row["legacy"]))
        with tempfile.TemporaryDirectory() as root:
            for rel, text in row["files"].items():
                path = os.path.join(root, *rel.split("/"))
                os.makedirs(os.path.dirname(path), exist_ok=True)
                with open(path, "wb") as handle:
                    handle.write(("".join(text) if isinstance(text, list) else text).encode("utf-8"))
            got = _outcome(check_tree, root, frozen, registry_raw, "harness-onion")
        _expect(got == row["expect"], (row["id"], got))
    for row in vectors["privacy"]:
        hits = _with_tokens(row, privacy_hits, "".join(row["parts"]))
        _expect(hits == row["expect"], (row["id"], hits))
    for key in ("reviews", "series", "oracles", "prOracles", "merges", "registries", "legacy", "trees", "privacy"):
        counts[key] = len(vectors[key])
    return counts


if __name__ == "__main__":
    from pathlib import Path

    here = Path(__file__).resolve().parents[1] / "architecture/review-record"
    counts = replay(json.loads((here / "vectors.json").read_bytes()))
    print("review record vectors replay: " + ", ".join("%d %s" % (n, k) for k, n in counts.items()))
