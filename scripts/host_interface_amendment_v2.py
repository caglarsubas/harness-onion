#!/usr/bin/env python3
"""HS43: owner-decided changes to the W01 host-interface specification, applied on top of amendment W02D.

Amendment W02D's effective specification (architecture/host-interface-amendment-w02d/HOST_INTERFACE_SPEC.md) and its
record stay byte-identical: this module pins both digests. The HS43 record
(architecture/host-interface-amendment-hs43/amendment.json) lists exact, counted substring replacements of that effective
text, each citing the owner decisions it carries out; every owner decision is cited, and its disposition names every item
that cites it and the obligations that answer it. Adopted text elsewhere that HS43 overrides is listed, quoted exactly,
under `supersedes` with its pinned file; those files stay byte-identical. effective_spec() applies the replacements to
the pinned W02D bytes and must give exactly the pinned HS43 bytes, which are published beside the record.

Nothing in the amended text is free-standing: a DECIDED item must sit inside the section and lines it names, the head
extension is fixed, section 12 is rendered from the record, and the title rename is fixed.

check(read) validates the record, the W02D base and its record, every superseded file and quote, and the published HS43
specification through an injected byte reader, so a history-chain layer can pass its reviewed_bytes.
"""
from __future__ import annotations

import hashlib
import json
import re
from typing import Any, Callable

SCHEMA = "planeon.internal.host-interface-amendment/v2"
RECORD_PATH = "architecture/host-interface-amendment-hs43/amendment.json"
EFFECTIVE_PATH = "architecture/host-interface-amendment-hs43/HOST_INTERFACE_SPEC.md"
DESIGN_LABEL = "HOST-INTERFACE-DRAFT-002-HS43"
BASE_PATH = "architecture/host-interface-amendment-w02d/HOST_INTERFACE_SPEC.md"
BASE_SHA256 = "2ac2751cbddd7fae20ee92a93a8fc18c7988dd0c96853d1ccb2d08cb3753f83b"
BASE_LABEL = "HOST-INTERFACE-DRAFT-002-W02D"
BASE_RECORD_PATH = "architecture/host-interface-amendment-w02d/amendment.json"
BASE_RECORD_SHA256 = "8c20ccc25ae504073d89d052b1618c21ab53108dcc44af26f747024709e8f6f9"
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
TITLE = ("# W01 host interfaces — gate resolutions, candidate v2 with amendment W02D\n",
         "# W01 host interfaces — gate resolutions, candidate v2 with amendments W02D and HS43\n")
HEAD_LINE = "`architecture/host-interface-amendment-w02d/amendment.json` lists every change.\n"
HEAD_EXTENSION = ("Amendment HS43 (`HOST-INTERFACE-DRAFT-002-HS43`, section 12) is applied on top of that effective text, which also\n"
                  "stays byte-identical (`architecture/host-interface-amendment-w02d/HOST_INTERFACE_SPEC.md`);\n"
                  "`architecture/host-interface-amendment-hs43/amendment.json` lists its changes.\n")
END_LINE = "O-T04-AMEND (native confirmation). Every E01-E12 obligation stays OPEN_UNPROVEN.\n"
# The closed list of adopted clauses HS43 overrides (owner decision Q-HS43-2 (a)): a record must quote exactly these, in
# this order, so nothing else is superseded silently. Each file stays byte-identical.
_I05_CLAUSE = "PID/start identity, executable, label and cgroup"
_I05_BROKER = "The broker verifies the gate's frames the same way"
_MATRIX_CLAUSES = ("Captures and peer checks therefore use SO_PEERCRED, SO_PEERSEC, pidfds and ungated entries",
                   "Executable identity follows from the peer's label",
                   "Peer qualification and captures use SO_PEERCRED, SO_PEERSEC, pidfds and ungated `/proc` entries; "
                   "executable identity")
SUPERSEDED = (
    ("architecture/host-interface-inputs/corrected/HOST_INTERFACE_SPEC.md",
     "authenticate exact installed peer artifacts, manifest/trust custody, PID/start,"),
    ("architecture/i05-gate-channel/README.md", _I05_CLAUSE),
    ("architecture/i05-gate-channel/README.md", _I05_BROKER),
    ("architecture/i05-gate-channel-v2/README.md", _I05_CLAUSE),
    ("architecture/i05-gate-channel-v2/README.md", _I05_BROKER),
    ("architecture/i05-gate-channel-v3/README.md", _I05_CLAUSE),
    ("architecture/i05-gate-channel-v3/README.md", _I05_BROKER),
    ("architecture/i07-policy-write/README.md", "qualifies the writer peer the way it qualifies the broker"),
    ("architecture/i07-policy-write/README.md",
     "writer artifact `/opt/planeon/bin/harness-policy-write` (fs-verity digest under its signed manifest, §4.2)"),
    (BASE_PATH, "and the broker peer qualification digest (§4.3)"),
    ("architecture/native-profile-v2/README.md", "CAP_NET_BIND_SERVICE only with a signed port below 1024"),
) + tuple(("architecture/selinux-matrix/README.md", clause) for clause in _MATRIX_CLAUSES) \
  + tuple(("architecture/selinux-matrix-v2/README.md", clause) for clause in _MATRIX_CLAUSES)
# Q-HS43-3 (a): the stated residuals and the obligations that follow them up must stay in the record.
REQUIRED_RESIDUALS = ("R-WRITER-PROC", "R-GATE-PROC")
REQUIRED_OBLIGATIONS = ("O-SECCOMP-V3-READLINKAT", "O-W03-WRITER-EXE", "O-W03-PEER-EXE", "O-MATRIX-WRITER-PROCACCESS",
                        "O-MATRIX-GATE-PROCACCESS", "O-MATRIX-GATE-NETBIND", "O-NATIVE-GATE-NOCAP", "O-T04-HS43")
# The DECIDED items, in order; none may be dropped or added without changing this module.
REQUIRED_DECIDED = ("H1", "H2", "H3", "H5", "H4")
# A DECIDED item may change only these sections: who qualifies whom, the per-role policy table and the I05 table; in the
# two tables only the EFFECT_GATE row and the BIND_EXECUTION row.
DECIDED_SECTIONS = ("4.3", "5.3", "7")
DECIDED_ROWS = {"5.3": "| EFFECT_GATE |", "7": "| BIND_EXECUTION |"}
SECTION12_INTRO = (
    "HS43 changes how the effect gate qualifies its two local peers (§4.3) and states the one system call the writer's\n"
    "executable check needs (§5.3); the gate's filter admits that call only once O-SECCOMP-V3-READLINKAT lands. It is\n"
    "applied to the W02D effective text, which stays byte-identical; `architecture/host-interface-amendment-hs43/amendment.json`\n"
    "gives every change and its reason.")
SECTION12_ORDER = (
    "The data follow in order (Q-HE3A-1b): the W02d v3 allowlist (`architecture/seccomp-allowlists-v3/`) gains the\n"
    "EFFECT_GATE `readlinkat` rule in its own packet, then the EFFECT_GATE programs and the edge record are republished,\n"
    "then R10 re-vendors them and adds the check.")


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


def render_section12(record: dict) -> str:
    """Section 12, rendered only from the record and this module's fixed sentences."""
    out = ["", "## 12. Amendment HS43 (2026-10-15)", "", SECTION12_INTRO, "",
           "| Item | Where | Decisions |", "|---|---|---|"]
    out += ["| %s | %s | %s |" % (item["id"], item["section"], ", ".join(item["decisions"]))
            for item in record["items"] if item["kind"] == "DECIDED"]
    if record["supersedes"]:
        out += ["", "Adopted text HS43 overrides (each file stays byte-identical; HS43 governs, and a successor of that"
                " contract adopts it):", "", "| Superseded clause | In | Replaced by |", "|---|---|---|"]
        out += ["| \"%s\" | `%s` | %s (%s) |" % (_cell(row["quote"]), row["path"], _cell(row["replacement"]),
                                               ", ".join(row["items"])) for row in record["supersedes"]]
    if record["residuals"]:
        out += ["", "Stated residuals:", ""]
        out += ["- %s: %s Follow-up: %s (%s)." % (row["id"], row["text"], row["followUp"], ", ".join(row["decisions"]))
                for row in record["residuals"]]
    out += ["", SECTION12_ORDER, ""]
    labels = ", ".join("%s (%s)" % (row["id"], row["label"]) for row in record["obligations"])
    out += ["Obligations: %s. Every E01-E12 obligation stays OPEN_UNPROVEN." % labels]
    return "\n".join(out) + "\n"


def _editorial(item: dict, record: dict) -> bool:
    pair = (item["current"], item["proposed"])
    return ((pair == TITLE and item["section"] == "title")
            or (pair == (HEAD_LINE, HEAD_LINE + HEAD_EXTENSION) and item["section"] == "head")
            or (pair == (END_LINE, END_LINE + render_section12(record)) and item["section"] == "12 (new)"))


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
            "pinned W02D base and record")
    require(type(base) is bytes and digest(base) == BASE_SHA256, "pinned W02D effective bytes")
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
            lines = "end" if item["section"] == "12 (new)" else _base_lines(text, item["current"])
            require(item["baseLines"] == lines and _editorial(item, record),
                    "editorial item %s is a fixed or rendered edge" % item["id"])
        else:
            match = SECTION.fullmatch(item["section"])
            require(match is not None and match.group(1) in DECIDED_SECTIONS and _section_of(text, item["current"]) == match.group(1)
                    and item["baseLines"] == _base_lines(text, item["current"]),
                    "decided item %s sits in the section and lines it names" % item["id"])
            row_prefix = DECIDED_ROWS.get(match.group(1))
            line_start = text.rfind("\n", 0, text.index(item["current"])) + 1
            require(row_prefix is None or ("\n" not in item["current"].rstrip("\n")
                                           and text[line_start:].startswith(row_prefix)),
                    "decided item %s changes only its table's permitted row" % item["id"])
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
    # Obligations the base text already names (W02D's) are not HS43's; the new text names exactly the record's.
    named = {ref for item in items
             for ref in set(OBLIGATION_REF.findall(item["proposed"])) - set(OBLIGATION_REF.findall(item["current"]))}
    require(named == set(obligation_ids), "the amended text names exactly the record's obligations")
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
    require(type(base) is bytes and digest(base) == BASE_SHA256, "pinned W02D effective bytes")
    text = base.decode("utf-8")
    for item in record["items"]:
        require(text.count(item["current"]) == 1, "item %s current text count" % item["id"])
        before = text.count(item["proposed"])
        text = text.replace(item["current"], item["proposed"])
        require(text.count(item["proposed"]) == before + 1, "item %s proposed text count" % item["id"])
    for item in record["items"]:
        require(text.count(item["proposed"]) >= 1, "item %s survives every later item" % item["id"])
    raw = text.encode("utf-8")
    require(digest(raw) == record["effective"]["sha256"], "pinned effective HS43 bytes")
    return raw


def check(read: Callable[[str], bytes]) -> dict:
    """The W02D record is the pinned one, the HS43 record is closed, every superseded clause is exact, and the published
    HS43 specification is exact."""
    require(digest(read(BASE_RECORD_PATH)) == BASE_RECORD_SHA256, "pinned W02D amendment record")
    record = parse(read(RECORD_PATH))
    base = read(BASE_PATH)
    check_record(record, base)
    check_superseded(record, read)
    effective = effective_spec(record, base)
    require(read(EFFECTIVE_PATH) == effective, "published effective specification")
    return record
