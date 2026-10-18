#!/usr/bin/env python3
"""HS53: owner-decided changes to the W01 host-interface specification, applied on top of amendment HS43.

Amendment HS43's effective specification (architecture/host-interface-amendment-hs43/HOST_INTERFACE_SPEC.md) and its
record stay byte-identical: this module pins both digests. The HS53 record
(architecture/host-interface-amendment-hs53/amendment.json) lists exact, counted substring replacements of that effective
text, each citing the owner decisions it carries out; every owner decision is cited, and its disposition names every item
that cites it and the obligations that answer it. Adopted text elsewhere that HS53 overrides is listed, quoted exactly,
under `supersedes` with its pinned file; those files stay byte-identical. effective_spec() applies the replacements to
the pinned HS43 bytes and must give exactly the pinned HS53 bytes, which are published beside the record.

Nothing in the amended text is free-standing: a DECIDED item must sit inside the section and lines it names (H1 only in
the §5.3 OBSERVER row, H2 the fixed pointer, H3 its fixed bullet after the §4.3 one), the head extension is fixed, section 13
is rendered from the record, and the title rename is fixed. This is HS43's v2 model with HS53's constants and those
item places; the record schema is unchanged.

check(read) validates the record, the HS43 base and its record, every superseded file and quote, and the published HS53
specification through an injected byte reader, so a history-chain layer can pass its reviewed_bytes.
"""
from __future__ import annotations

import hashlib
import json
import re
from typing import Any, Callable

SCHEMA = "planeon.internal.host-interface-amendment/v2"
RECORD_PATH = "architecture/host-interface-amendment-hs53/amendment.json"
EFFECTIVE_PATH = "architecture/host-interface-amendment-hs53/HOST_INTERFACE_SPEC.md"
DESIGN_LABEL = "HOST-INTERFACE-DRAFT-002-HS53"
BASE_PATH = "architecture/host-interface-amendment-hs43/HOST_INTERFACE_SPEC.md"
BASE_SHA256 = "b4f46b3a79c45691d7029a79849a555aca5ca7a6e6c600958147935f806888e9"
BASE_LABEL = "HOST-INTERFACE-DRAFT-002-HS43"
BASE_RECORD_PATH = "architecture/host-interface-amendment-hs43/amendment.json"
BASE_RECORD_SHA256 = "6a3719cdc659d7ccfde3598bdec06a31896fa82de810cf73ccc1f7ca3dc7f24c"
DECIDED = "OWNER_DECIDED"
KINDS = ("DECIDED", "EDITORIAL")
RECORD_KEYS = {"schemaVersion", "designLabel", "base", "effective", "ownerDecisions", "items", "dispositions",
               "obligations", "supersedes", "residuals", "notAmended"}
ITEM_KEYS = {"id", "kind", "section", "baseLines", "current", "proposed", "occurrences", "decisions", "why"}
DECISION_KEYS = {"id", "date", "state", "decision", "source"}
OBLIGATION_KEYS = {"id", "owner", "label", "text"}
SUPERSEDES_KEYS = {"path", "sha256", "quote", "replacement", "items"}
RESIDUAL_KEYS = {"id", "text", "followUp", "decisions"}
MAX_BYTES = 16_777_216
OBLIGATION_REF = re.compile(r"\bO-[A-Z0-9]+(?:-[A-Z0-9]+)*\b")
SECTION = re.compile(r"(\d+(?:\.\d+)?)(?: .+)?")
HEADING = re.compile(r"#{2,3} (\d+(?:\.\d+)?)[. ]")
TITLE = ("# W01 host interfaces — gate resolutions, candidate v2 with amendments W02D and HS43\n",
         "# W01 host interfaces — gate resolutions, candidate v2 with amendments W02D, HS43 and HS53\n")
HEAD_LINE = "`architecture/host-interface-amendment-hs43/amendment.json` lists its changes.\n"
HEAD_EXTENSION = ("Amendment HS53 (`HOST-INTERFACE-DRAFT-002-HS53`, section 13) is applied on top of the HS43 effective text,\n"
                  "which also stays byte-identical (`architecture/host-interface-amendment-hs43/HOST_INTERFACE_SPEC.md`);\n"
                  "`architecture/host-interface-amendment-hs53/amendment.json` lists its changes.\n")
END_LINE = "O-T04-HS43 (native confirmation). Every E01-E12 obligation stays OPEN_UNPROVEN.\n"
# The closed list of adopted clauses HS53 overrides: a record must quote exactly these, in this order, so nothing else is
# superseded silently. Each file stays byte-identical.
_SUMMARY = ("The observer is a separately\ninstalled open-source operator prerequisite, not an available or deployed "
            "product.")
SUPERSEDED = (
    ("architecture/host-interface-inputs/corrected/HOST_INTERFACE_SPEC.md",
     "Existing fixed native observer, read-only to policy"),
    ("docs/alpha-2/POLICY_OBSERVATION_READINESS.md", "Pre-existing protected observation service"),
    ("docs/alpha-2/POLICY_OBSERVATION_READINESS.md",
     "Documents the observer as a separately installed prerequisite, not an included or provisioned service"),
    ("docs/alpha-2/POLICY_OBSERVATION_READINESS.md",
     "The producer is an external operator prerequisite, like the pre-existing API\nproxy and admission controls, not an "
     "unimplemented product packet disguised as\nDONE. An operator must supply an open-source, reviewed implementation "
     "meeting\nthis protocol and the native tests below."),
    ("architecture/policy-observation-amendment.json", "PREEXISTING_INDEPENDENTLY_INSTALLED_OPEN_SOURCE_PRODUCER"),
    ("architecture/policy-observation-amendment.json",
     "An absent independently installed observer remains an explicit external prerequisite, not product/native PASS."),
    ("docs/alpha-2/BROKER_HANDOFF_READINESS.md",
     "The broker and observer are separately installed, reviewed open-source operator\nprerequisites, not product "
     "implementations represented as DONE."),
) + tuple((path, _SUMMARY) for path in (
    "docs/alpha-2/LIVE_BACKEND_READINESS.md", "docs/READINESS_INDEX.md", "docs/TRUSTED_LIVE_CAMPAIGN_RUNNER_CONTRACT.md",
    "docs/adr/0004-sol-high-packet-boundary.md", "docs/repositories/00-harness-engineering.md",
    "docs/repositories/12-mas-harness-conformance-labs.md", "task-packets/README.md")) + (
    ("architecture/seccomp-allowlists/README.md", "as SERVER without the listener; the I06 read connection (connect)"),
)
# Q-SOL-2 (a): the stated residual and the obligations that follow it up must stay in the record.
REQUIRED_RESIDUALS = ("R-OBSERVER-TCP-LISTEN",)
REQUIRED_OBLIGATIONS = ("O-SECCOMP-V5-OBSERVER-LISTENER", "O-W03-OBSERVER-UNIT", "O-W03-OBSERVER-PRESTART",
                        "O-W03-OBSERVER-TCP", "O-T04-HS53",
                        "O-MATRIX-OBSERVER-TCP", "O-MATRIX-OBSERVER-SOCK-CLEAR", "O-PROGRAMS-V3-OBSERVER",
                        "O-R10-HE004-I01")
# The DECIDED items, in order; none may be dropped or added without changing this module.
REQUIRED_DECIDED = ("H1", "H2", "H3")
# Where each DECIDED item may change: its section and, in the §5.3 table, only the OBSERVER row.
DECIDED_PLACES = {"H1": ("5.3", "| OBSERVER |"), "H2": ("5.3", None), "H3": ("4.3", None)}
# H2 is fixed: the stale pointer to the W02d data names the current successor (Q-SOL-1 (a)).
POINTER = ("are W02 data (W02d, `architecture/seccomp-allowlists-v2/`), generated",
           "are W02 data (W02d; the current successor is `architecture/seccomp-allowlists-v5/`, HS53), generated")
# H3 appends exactly this bullet after the one it names (the v1 peer duties stay as they are, Q-SOL-4 (a)). The text is
# fixed here, as H2's pointer is, so no other markup can be appended (review SOL3-1).
APPEND_ONLY = {"H3": "- I01's producer is R10's HE-004-I01: obligation I01-1 of W03-PLAN-AMEND-2 (MET-ENFORCE-032, harness-onion main\n  c69e55f; owner decision Q-HE4-1 (a)), which supersedes for I01 the earlier statements that the producer is a\n  pre-existing, independently installed operator prerequisite (§13). The observer listens on I01 (§5.3, HS53); both\n  ends keep the v1 peer duties, the server's checks of the observer and the observer's of the server\n  (`docs/alpha-2/POLICY_OBSERVATION_READINESS.md`), unchanged. HE-004-I01's design decides whether the race-free\n  start-time reference above also applies to I01, and records the choice; it re-vendors the republished OBSERVER\n  programs (O-PROGRAMS-V3-OBSERVER) and serves I01 (Q-SOL-4 (a), O-R10-HE004-I01).\n"}
SECTION13_INTRO = (
    "HS53 lets the observer hold the one listener I01 needs (§5.3 OBSERVER row) and records who produces I01 (§4.3); the\n"
    "observer's filter admits the listener only once O-SECCOMP-V5-OBSERVER-LISTENER lands. It is applied to the HS43\n"
    "effective text, which stays byte-identical; `architecture/host-interface-amendment-hs53/amendment.json` gives every\n"
    "change and its reason.")
SECTION13_ORDER = (
    "The data follow in order (Q-SOL-1 (a)): the W02d allowlist successor (`architecture/seccomp-allowlists-v5/`) gains\n"
    "the OBSERVER I01 listener rule in the same packet as this amendment, then the OBSERVER programs and the edge record\n"
    "are republished, then R10's HE-004-I01 re-vendors them and serves I01.")


def require(ok: bool, message: str) -> None:
    if not ok:
        raise ValueError(message)


def digest(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def parse(raw: bytes) -> Any:
    def unique(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            require(key not in result, "duplicate amendment member: " + key)
            result[key] = value
        return result

    def no_constant(_value: str) -> Any:
        raise ValueError("nonfinite amendment number")

    require(type(raw) is bytes and len(raw) <= MAX_BYTES, "bounded amendment bytes")
    return json.loads(raw, object_pairs_hook=unique, parse_constant=no_constant)


def _text(value: Any) -> bool:
    return type(value) is str and bool(value.strip())


def _texts(value: Any) -> bool:
    return type(value) is list and bool(value) and all(_text(entry) for entry in value) and len(set(value)) == len(value)


def _ids(value: Any) -> bool:
    """A possibly empty list of distinct non-empty strings."""
    return type(value) is list and all(_text(entry) for entry in value) and len(set(value)) == len(value)


def _closed(value: Any, keys: set, message: str) -> None:
    require(type(value) is dict and set(value) == keys, message)


def _cell(text: str) -> str:
    return text.replace("|", "\\|").replace("\n", " ")


def _cells(text: str) -> int:
    """The unescaped column separators in a table row."""
    return len(re.findall(r"(?<!\\)\|", text))


def render_section13(record: dict) -> str:
    """Section 13, rendered only from the record and this module's fixed sentences."""
    out = ["", "## 13. Amendment HS53 (2026-10-17)", "", SECTION13_INTRO, "",
           "| Item | Where | Decisions |", "|---|---|---|"]
    out += ["| %s | %s | %s |" % (item["id"], item["section"], ", ".join(item["decisions"]))
            for item in record["items"] if item["kind"] == "DECIDED"]
    if record["supersedes"]:
        out += ["", "Adopted text HS53 overrides (each file stays byte-identical; HS53 governs, and a successor of that"
                " contract adopts it):", "", "| Superseded clause | In | Replaced by |", "|---|---|---|"]
        out += ["| \"%s\" | `%s` | %s (%s) |" % (_cell(row["quote"]), row["path"], _cell(row["replacement"]),
                                               ", ".join(row["items"])) for row in record["supersedes"]]
    if record["residuals"]:
        out += ["", "Stated residuals:", ""]
        out += ["- %s: %s Follow-up: %s (%s)." % (row["id"], row["text"], row["followUp"], ", ".join(row["decisions"]))
                for row in record["residuals"]]
    out += ["", SECTION13_ORDER, ""]
    labels = ", ".join("%s (%s)" % (row["id"], row["label"]) for row in record["obligations"])
    out += ["Obligations: %s. Every E01-E12 obligation stays OPEN_UNPROVEN." % labels]
    return "\n".join(out) + "\n"


def _editorial(item: dict, record: dict) -> bool:
    pair = (item["current"], item["proposed"])
    return ((pair == TITLE and item["section"] == "title")
            or (pair == (HEAD_LINE, HEAD_LINE + HEAD_EXTENSION) and item["section"] == "head")
            or (pair == (END_LINE, END_LINE + render_section13(record)) and item["section"] == "13 (new)"))


def _base_lines(base: str, current: str) -> str:
    start = base.count("\n", 0, base.index(current)) + 1
    end = start + current.rstrip("\n").count("\n")
    return str(start) if end == start else "%d-%d" % (start, end)


def _section_of(base: str, current: str) -> str | None:
    """The number of the last numbered heading before the current text (None before the first one)."""
    found = None
    for line in base[:base.index(current)].split("\n"):
        match = HEADING.match(line)
        if match:
            found = match.group(1)
    return found


def check_record(record: Any, base: bytes) -> None:
    """A closed record: pinned paths, decided owner decisions, exact items in their sections, full dispositions."""
    _closed(record, RECORD_KEYS, "closed amendment record")
    require(record["schemaVersion"] == SCHEMA and record["designLabel"] == DESIGN_LABEL, "amendment schema and label")
    require(record["base"] == {"path": BASE_PATH, "sha256": BASE_SHA256, "designLabel": BASE_LABEL,
                               "record": {"path": BASE_RECORD_PATH, "sha256": BASE_RECORD_SHA256}},
            "pinned HS43 base and record")
    require(type(base) is bytes and digest(base) == BASE_SHA256, "pinned HS43 effective bytes")
    text = base.decode("utf-8")
    _closed(record["effective"], {"path", "sha256"}, "closed effective pin")
    require(record["effective"]["path"] == EFFECTIVE_PATH and type(record["effective"]["sha256"]) is str
            and re.fullmatch("[0-9a-f]{64}", record["effective"]["sha256"]) is not None, "effective path and digest")
    decisions = record["ownerDecisions"]
    require(type(decisions) is list and bool(decisions), "owner decisions")
    for row in decisions:
        _closed(row, DECISION_KEYS, "closed owner decision")
        require(_text(row["id"]) and type(row["date"]) is str and re.fullmatch(r"\d{4}-\d{2}-\d{2}", row["date"]) is not None
                and row["state"] == DECIDED and _text(row["decision"]) and _text(row["source"]),
                "every owner decision is decided: %r" % (row.get("id"),))
    ids = [row["id"] for row in decisions]
    require(len(ids) == len(set(ids)), "unique owner decisions")
    obligations = record["obligations"]
    require(type(obligations) is list and bool(obligations), "obligations")
    obligation_ids = []
    for row in obligations:
        _closed(row, OBLIGATION_KEYS, "closed obligation")
        require(_text(row["id"]) and OBLIGATION_REF.fullmatch(row["id"]) is not None and row["id"] not in obligation_ids
                and _text(row["owner"]) and _text(row["label"]) and _text(row["text"]), "described obligation")
        obligation_ids.append(row["id"])
    items = record["items"]
    require(type(items) is list and bool(items), "amendment items")
    item_ids = [item.get("id") if type(item) is dict else None for item in items]
    require(len(item_ids) == len(set(item_ids)), "unique amendment items")
    require(type(record["supersedes"]) is list and type(record["residuals"]) is list, "superseded clauses and residuals")
    require([(row.get("path"), row.get("quote")) if type(row) is dict else None for row in record["supersedes"]]
            == list(SUPERSEDED), "the closed list of superseded clauses, in order")
    for row in record["supersedes"]:
        _closed(row, SUPERSEDES_KEYS, "closed superseded clause")
        require(_text(row["path"]) and type(row["sha256"]) is str and re.fullmatch("[0-9a-f]{64}", row["sha256"]) is not None
                and _text(row["quote"]) and _text(row["replacement"]) and _texts(row["items"])
                and set(row["items"]) <= set(item_ids), "described superseded clause in %r" % (row.get("path"),))
    for row in record["residuals"]:
        _closed(row, RESIDUAL_KEYS, "closed residual")
        require(_text(row["id"]) and _text(row["text"]) and _text(row["followUp"]) and _texts(row["decisions"])
                and set(row["decisions"]) <= set(ids), "described residual %r" % (row.get("id"),))
    for item in items:
        _closed(item, ITEM_KEYS, "closed amendment item")
        require(_text(item["id"]) and item["kind"] in KINDS and _text(item["section"]) and _text(item["baseLines"])
                and _text(item["why"]), "described amendment item %r" % (item["id"],))
        require(_text(item["current"]) and type(item["proposed"]) is str and item["current"] != item["proposed"]
                and item["occurrences"] == 1 and text.count(item["current"]) == 1, "effective amendment item " + item["id"])
        require(_ids(item["decisions"]) and set(item["decisions"]) <= set(ids)
                and (item["kind"] == "EDITORIAL") == (not item["decisions"]),
                "item %s cites decided owner decisions" % item["id"])
        if item["kind"] == "EDITORIAL":
            lines = "end" if item["section"] == "13 (new)" else _base_lines(text, item["current"])
            require(item["baseLines"] == lines and _editorial(item, record),
                    "editorial item %s is a fixed or rendered edge" % item["id"])
        else:
            match = SECTION.fullmatch(item["section"])
            place = DECIDED_PLACES.get(item["id"])
            require(match is not None and place is not None and match.group(1) == place[0]
                    and _section_of(text, item["current"]) == place[0] and item["baseLines"] == _base_lines(text, item["current"]),
                    "decided item %s sits in the section and lines it names" % item["id"])
            row_prefix = place[1]
            line_start = text.rfind("\n", 0, text.index(item["current"])) + 1
            require(row_prefix is None or ("\n" not in item["current"].rstrip("\n")
                                           and text[line_start:].startswith(row_prefix)),
                    "decided item %s changes only its table's permitted row" % item["id"])
            require(item["id"] != "H2" or (item["current"], item["proposed"]) == POINTER,
                    "decided item H2 is the fixed pointer to the current W02d successor")
            # A row item keeps its line and its cells: no new row, heading or column.
            require(row_prefix is None or ("\n" not in item["current"] and "\n" not in item["proposed"]
                                           and _cells(item["proposed"]) == _cells(item["current"])),
                    "decided item %s keeps its row's line and cells" % item["id"])
            require(item["id"] not in APPEND_ONLY or (item["current"].endswith("\n")
                                                      and item["proposed"] == item["current"] + APPEND_ONLY[item["id"]]),
                    "decided item %s appends exactly its fixed text after the text it names" % item["id"])
    require(all(any(decision in item["decisions"] for item in items) for decision in ids), "every owner decision is cited")
    dispositions = record["dispositions"]
    require(type(dispositions) is list and [row.get("decision") for row in dispositions if type(row) is dict] == ids,
            "one disposition per owner decision, in record order")
    used = set()
    for row in dispositions:
        _closed(row, {"decision", "items", "obligations", "summary"}, "closed disposition")
        citing = [item["id"] for item in items if row["decision"] in item["decisions"]]
        require(row["items"] == citing and _ids(row["obligations"]) and set(row["obligations"]) <= set(obligation_ids)
                and _text(row["summary"]), "disposition of %r names every citing item and known obligations" % row["decision"])
        used |= set(row["obligations"])
    require(used == set(obligation_ids), "every obligation answers an owner decision")
    require([item["id"] for item in items if item["kind"] == "DECIDED"] == list(REQUIRED_DECIDED), "the required items")
    require(obligation_ids == list(REQUIRED_OBLIGATIONS)
            and [row["id"] for row in record["residuals"]] == list(REQUIRED_RESIDUALS),
            "the required obligations and residuals, in order")
    # Obligations the base text already names (W02D's and HS43's) are not HS53's. The DECIDED items must name exactly the
    # record's obligations (section 13 lists them all, so it cannot show that one is missing), and no item names another.
    def new_refs(item: dict) -> set:
        return set(OBLIGATION_REF.findall(item["proposed"])) - set(OBLIGATION_REF.findall(item["current"]))
    named = {ref for item in items if item["kind"] == "DECIDED" for ref in new_refs(item)}
    require(named == set(obligation_ids) and all(new_refs(item) <= named for item in items),
            "the DECIDED items name exactly the record's obligations")
    require(_texts(record["notAmended"]), "stated non-amendments")


def check_superseded(record: dict, read: Callable[[str], bytes]) -> None:
    """Every superseded file is the pinned one and holds its quoted clause exactly once."""
    for row in record["supersedes"]:
        raw = read(row["path"])
        require(digest(raw) == row["sha256"], "pinned superseded file " + row["path"])
        require(raw.decode("utf-8").count(row["quote"]) == 1, "superseded clause quoted exactly once in " + row["path"])


def effective_spec(record: dict, base: bytes) -> bytes:
    """Apply every item in order. Each current text occurs exactly once when applied, and every proposed text still
    occurs at the end, so no later item rewrites an earlier one."""
    require(type(base) is bytes and digest(base) == BASE_SHA256, "pinned HS43 effective bytes")
    text = base.decode("utf-8")
    for item in record["items"]:
        require(text.count(item["current"]) == 1, "item %s current text count" % item["id"])
        before = text.count(item["proposed"])
        text = text.replace(item["current"], item["proposed"])
        require(text.count(item["proposed"]) == before + 1, "item %s proposed text count" % item["id"])
    for item in record["items"]:
        require(text.count(item["proposed"]) >= 1, "item %s survives every later item" % item["id"])
    raw = text.encode("utf-8")
    require(digest(raw) == record["effective"]["sha256"], "pinned effective HS53 bytes")
    return raw


def check(read: Callable[[str], bytes]) -> dict:
    """The HS43 record is the pinned one, the HS53 record is closed, every superseded clause is exact, and the published
    HS53 specification is exact."""
    require(digest(read(BASE_RECORD_PATH)) == BASE_RECORD_SHA256, "pinned HS43 amendment record")
    record = parse(read(RECORD_PATH))
    base = read(BASE_PATH)
    check_record(record, base)
    check_superseded(record, read)
    effective = effective_spec(record, base)
    require(read(EFFECTIVE_PATH) == effective, "published effective specification")
    return record
