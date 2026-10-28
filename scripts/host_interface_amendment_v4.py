#!/usr/bin/env python3
"""HE5: owner-decided changes to the W01 host-interface specification, applied on top of amendment HS53.

Amendment HS53's effective specification (architecture/host-interface-amendment-hs53/HOST_INTERFACE_SPEC.md) and its
record stay byte-identical: this module pins both digests. The HE5 record
(architecture/host-interface-amendment-he5/amendment.json) lists exact, counted substring replacements of that effective
text, each citing the owner decisions it carries out; every owner decision is cited, and its disposition names every item
that cites it and the obligations that answer it. Adopted text elsewhere that HE5 overrides is listed, quoted exactly,
under `supersedes` with its pinned file; those files stay byte-identical. effective_spec() applies the replacements to
the pinned HS53 bytes and must give exactly the pinned HE5 bytes, which are published beside the record.

Nothing in the amended text is free-standing: a DECIDED item must sit inside §5.4 and the lines of its own step (H1 only
in W3, H2 only in W4, H3 only in W5) and keep that step's plain lines, the head extension is fixed, section 14 is
rendered from the record, and the title rename is fixed. This is HS53's v3 model with HE5's constants and those item
places; the record schema is unchanged.

check(read) validates the record, the HS53 base and its record, every superseded file and quote, and the published HE5
specification through an injected byte reader, so a history-chain layer can pass its reviewed_bytes.
"""
from __future__ import annotations

import hashlib
import json
import re
from typing import Any, Callable

SCHEMA = "planeon.internal.host-interface-amendment/v2"
RECORD_PATH = "architecture/host-interface-amendment-he5/amendment.json"
EFFECTIVE_PATH = "architecture/host-interface-amendment-he5/HOST_INTERFACE_SPEC.md"
DESIGN_LABEL = "HOST-INTERFACE-DRAFT-002-HE5"
BASE_PATH = "architecture/host-interface-amendment-hs53/HOST_INTERFACE_SPEC.md"
BASE_SHA256 = "fa7f36fb7d291ab5ffccfc51f9bae7b99ad1a2ef466fc0793dbe6e4182af1e75"
BASE_LABEL = "HOST-INTERFACE-DRAFT-002-HS53"
BASE_RECORD_PATH = "architecture/host-interface-amendment-hs53/amendment.json"
BASE_RECORD_SHA256 = "e4255685a38f183d9cd5e5411ee83cc3dee6442e578831296d9789109824d763"
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
TITLE = ("# W01 host interfaces — gate resolutions, candidate v2 with amendments W02D, HS43 and HS53\n",
         "# W01 host interfaces — gate resolutions, candidate v2 with amendments W02D, HS43, HS53 and HE5\n")
HEAD_LINE = "`architecture/host-interface-amendment-hs53/amendment.json` lists its changes.\n"
HEAD_EXTENSION = ("Amendment HE5 (`HOST-INTERFACE-DRAFT-002-HE5`, section 14) is applied on top of the HS53 effective text,\n"
                  "which also stays byte-identical (`architecture/host-interface-amendment-hs53/HOST_INTERFACE_SPEC.md`);\n"
                  "`architecture/host-interface-amendment-he5/amendment.json` lists its changes.\n")
END_LINE = ("Obligations: O-SECCOMP-V5-OBSERVER-LISTENER (the allowlist rule), O-W03-OBSERVER-UNIT (the socket's directory, "
            "mode and freshness), O-W03-OBSERVER-PRESTART (the pre-start removal runs as init_t), O-W03-OBSERVER-TCP (no "
            "TCP listener for the observer), O-T04-HS53 (native confirmation), O-MATRIX-OBSERVER-TCP (the observer's TCP "
            "listen closed in data), O-MATRIX-OBSERVER-SOCK-CLEAR (systemd's grant to clear a stale I01 path (met once "
            "matrix v6 is adopted)), O-PROGRAMS-V3-OBSERVER (the OBSERVER programs and the edge record), O-R10-HE004-I01 "
            "(the observer serves I01). Every E01-E12 obligation stays OPEN_UNPROVEN.\n")
# The closed list of adopted clauses HE5 overrides: a record must quote exactly these, in this order, so nothing else is
# superseded silently. Each file stays byte-identical. The readiness guide is frozen by
# scripts/validate_seccomp_observer_listener.py's FROZEN_PATHS (:390-391, its entry :397) and ERA_SHA256 pin (:493), as
# HS53 carried its broker sentence (scripts/host_interface_amendment_v3.py's SUPERSEDED); native-profile v4's README
# by the sha256 pins in scripts/validate_native_profile_v4.py (:402, :679) and five other validators.
SUPERSEDED = (
    ("docs/alpha-2/BROKER_HANDOFF_READINESS.md", "FD3 is the sole inherited non-stdio\ndescriptor"),
    ("architecture/native-profile-v4/README.md", "on an O_PATH descriptor of the worker executable"),
)
# No string in the record may hold a line separator other than the line feed (CommonMark also ends a line at a carriage
# return), so no item, quote or rendered cell can start a new line or row unseen (review SOL5-1).
LINE_SEPARATORS = ("\r", "\x0b", "\x0c", "\x85", "\u2028", "\u2029")
# Q-HE5-12 (b): the stated residual and the obligations that follow it up must stay in the record.
REQUIRED_RESIDUALS = ("R-HE5-POSTEXEC",)
REQUIRED_OBLIGATIONS = ("O-R10-HE005", "O-T04-HE5")
# The DECIDED items, in order; none may be dropped or added without changing this module.
REQUIRED_DECIDED = ("H1", "H2", "H3")
# Where each DECIDED item may change: §5.4, and only the lines of its own step, so no item touches another step, W1, W2
# or W6. A step runs from its "Wn. " line to the next step line or the blank line that ends the list.
DECIDED_PLACES = {"H1": ("5.4", "W3"), "H2": ("5.4", "W4"), "H3": ("5.4", "W5")}
STEP = re.compile(r"W\d+\. ")
# A line that would open a new step, heading, list item or quote; a DECIDED item's later lines may start none.
BLOCK_START = re.compile(r"(?:W\d+\.|#{1,6}|[-*+>]|\d+[.)])(?: |$)")
SECTION14_INTRO = (
    "HE5 makes fd 4, the verity-checked O_RDONLY worker script, the one more descriptor the worker inherits beside FD3\n"
    "(§5.4 W3-W5), and the broker reads nothing of the worker's `/proc` after exec. It is applied to the HS53 effective\n"
    "text, which stays byte-identical; `architecture/host-interface-amendment-he5/amendment.json` gives every change and\n"
    "its reason.")
SECTION14_ORDER = (
    "Edge record v12 registers the I02/I03 inputs beside this amendment (Q-EV12-1 (a)): R10's HE-005B vendors them\n"
    "byte-identical, HE-005C and HE-005D implement W3-W5 as amended, and T04 confirms them on the enrolled kernel.")


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


def _strings(value: Any):
    """Every string in a parsed record, keys included."""
    if type(value) is str:
        yield value
    elif type(value) is dict:
        for key, entry in value.items():
            yield key
            yield from _strings(entry)
    elif type(value) is list:
        for entry in value:
            yield from _strings(entry)


def render_section14(record: dict) -> str:
    """Section 14, rendered only from the record and this module's fixed sentences."""
    out = ["", "## 14. Amendment HE5 (2026-10-26)", "", SECTION14_INTRO, "",
           "| Item | Where | Decisions |", "|---|---|---|"]
    out += ["| %s | %s | %s |" % (item["id"], item["section"], ", ".join(item["decisions"]))
            for item in record["items"] if item["kind"] == "DECIDED"]
    if record["supersedes"]:
        out += ["", "Adopted text HE5 overrides (each file stays byte-identical; HE5 governs, and a successor of that"
                " contract adopts it):", "", "| Superseded clause | In | Replaced by |", "|---|---|---|"]
        out += ["| \"%s\" | `%s` | %s (%s) |" % (_cell(row["quote"]), row["path"], _cell(row["replacement"]),
                                               ", ".join(row["items"])) for row in record["supersedes"]]
    if record["residuals"]:
        out += ["", "Stated residuals:", ""]
        out += ["- %s: %s Follow-up: %s (%s)." % (row["id"], row["text"], row["followUp"], ", ".join(row["decisions"]))
                for row in record["residuals"]]
    out += ["", SECTION14_ORDER, ""]
    labels = ", ".join("%s (%s)" % (row["id"], row["label"]) for row in record["obligations"])
    out += ["Obligations: %s. Every E01-E12 obligation stays OPEN_UNPROVEN." % labels]
    return "\n".join(out) + "\n"


def _editorial(item: dict, record: dict) -> bool:
    pair = (item["current"], item["proposed"])
    return ((pair == TITLE and item["section"] == "title")
            or (pair == (HEAD_LINE, HEAD_LINE + HEAD_EXTENSION) and item["section"] == "head")
            or (pair == (END_LINE, END_LINE + render_section14(record)) and item["section"] == "14 (new)"))


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


def _step_of(base: str, current: str) -> str | None:
    """The step ("W1" to "W6") whose lines hold the whole current text: from its "Wn. " line up to the next step line or
    the blank line that ends the list. None when the text starts outside a step or reaches into the next one."""
    lines = base.split("\n")
    start = base.index(current)
    first = base.count("\n", 0, start)
    last = base.count("\n", 0, start + len(current.rstrip("\n")))
    head = first
    while head >= 0 and lines[head] and STEP.match(lines[head]) is None:
        head -= 1
    if head < 0 or not lines[head]:
        return None
    tail = head + 1
    while tail < len(lines) and lines[tail] and STEP.match(lines[tail]) is None:
        tail += 1
    return lines[head].split(".", 1)[0] if last < tail else None


def _keeps_step(current: str, proposed: str) -> bool:
    """The proposed text stays plain lines of its step: no blank line, no later line that opens a step, heading, list
    item or quote, and its first line keeps the current's step label, or opens none where the current opens none."""
    label = STEP.match(current)
    first = STEP.match(proposed) is None if label is None else proposed.startswith(label.group(0))
    return "\n\n" not in proposed and first and not any(BLOCK_START.match(line) for line in proposed.split("\n")[1:])


def check_record(record: Any, base: bytes) -> None:
    """A closed record: pinned paths, decided owner decisions, exact items in their sections, full dispositions."""
    _closed(record, RECORD_KEYS, "closed amendment record")
    require(not any(sep in s for s in _strings(record) for sep in LINE_SEPARATORS),
            "no line separator but the line feed in the record")
    require(record["schemaVersion"] == SCHEMA and record["designLabel"] == DESIGN_LABEL, "amendment schema and label")
    require(record["base"] == {"path": BASE_PATH, "sha256": BASE_SHA256, "designLabel": BASE_LABEL,
                               "record": {"path": BASE_RECORD_PATH, "sha256": BASE_RECORD_SHA256}},
            "pinned HS53 base and record")
    require(type(base) is bytes and digest(base) == BASE_SHA256, "pinned HS53 effective bytes")
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
    listed = [(row.get("path"), row.get("quote")) if type(row) is dict else None for row in record["supersedes"]]
    require(len(listed) == len(SUPERSEDED), "exactly %d superseded clauses" % len(SUPERSEDED))
    require(listed == list(SUPERSEDED), "the closed list of superseded clauses, in order")
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
            lines = "end" if item["section"] == "14 (new)" else _base_lines(text, item["current"])
            require(item["baseLines"] == lines and _editorial(item, record),
                    "editorial item %s is a fixed or rendered edge" % item["id"])
        else:
            match = SECTION.fullmatch(item["section"])
            place = DECIDED_PLACES.get(item["id"])
            require(match is not None and place is not None and match.group(1) == place[0]
                    and _section_of(text, item["current"]) == place[0] and item["baseLines"] == _base_lines(text, item["current"]),
                    "decided item %s sits in the section and lines it names" % item["id"])
            require(_step_of(text, item["current"]) == place[1],
                    "decided item %s sits in the lines of its own step, %s" % (item["id"], place[1]))
            # A step item keeps its step's plain lines: no new step, paragraph, heading, list item or quote.
            require(_keeps_step(item["current"], item["proposed"]),
                    "decided item %s keeps its step's plain lines" % item["id"])
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
    # Obligations the base text already names (W02D's, HS43's and HS53's) are not HE5's. The DECIDED items must name exactly
    # the record's obligations (section 14 lists them all, so it cannot show that one is missing), and no item names another.
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
    require(type(base) is bytes and digest(base) == BASE_SHA256, "pinned HS53 effective bytes")
    text = base.decode("utf-8")
    for item in record["items"]:
        require(text.count(item["current"]) == 1, "item %s current text count" % item["id"])
        before = text.count(item["proposed"])
        text = text.replace(item["current"], item["proposed"])
        require(text.count(item["proposed"]) == before + 1, "item %s proposed text count" % item["id"])
    for item in record["items"]:
        require(text.count(item["proposed"]) >= 1, "item %s survives every later item" % item["id"])
    raw = text.encode("utf-8")
    require(digest(raw) == record["effective"]["sha256"], "pinned effective HE5 bytes")
    return raw


def check(read: Callable[[str], bytes]) -> dict:
    """The HS53 record is the pinned one, the HE5 record is closed, every superseded clause is exact, and the published
    HE5 specification is exact."""
    require(digest(read(BASE_RECORD_PATH)) == BASE_RECORD_SHA256, "pinned HS53 amendment record")
    record = parse(read(RECORD_PATH))
    base = read(BASE_PATH)
    check_record(record, base)
    check_superseded(record, read)
    effective = effective_spec(record, base)
    require(read(EFFECTIVE_PATH) == effective, "published effective specification")
    return record
