#!/usr/bin/env python3
"""HS43: owner-decided changes to the W01 host-interface specification, applied on top of amendment W02D.

Amendment W02D's effective specification (architecture/host-interface-amendment-w02d/HOST_INTERFACE_SPEC.md) and its
record stay byte-identical: this module pins both digests. The HS43 record
(architecture/host-interface-amendment-hs43/amendment.json) lists exact, counted substring replacements of that effective
text, each citing the owner decisions it carries out; every cited decision has a disposition naming the items and
obligations that answer it. effective_spec() applies the replacements to the pinned W02D bytes and must give exactly the
pinned HS43 bytes, which are published beside the record.

check(read) validates the record, the W02D base and its record, and the published HS43 specification through an
injected byte reader, so a history-chain layer can pass its reviewed_bytes.
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
               "obligations", "notAmended"}
ITEM_KEYS = {"id", "kind", "section", "baseLines", "current", "proposed", "occurrences", "decisions", "why"}
DECISION_KEYS = {"id", "date", "state", "decision", "source"}
MAX_BYTES = 16_777_216
OBLIGATION_REF = re.compile(r"\bO-[A-Z0-9]+(?:-[A-Z0-9]+)*\b")
# An editorial item only renames the amendment list in the title line, or extends the head paragraph's last line or
# the document's last line; it never changes what the specification says.
TITLE = ("# W01 host interfaces — gate resolutions, candidate v2 with amendment W02D\n",
         "# W01 host interfaces — gate resolutions, candidate v2 with amendments W02D and HS43\n")
EXTENDED_LINES = ("`architecture/host-interface-amendment-w02d/amendment.json` lists every change.\n",
                  "O-T04-AMEND (native confirmation). Every E01-E12 obligation stays OPEN_UNPROVEN.\n")


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


def _editorial(item: dict) -> bool:
    if (item["current"], item["proposed"]) == TITLE:
        return True
    return item["current"] in EXTENDED_LINES and item["proposed"].startswith(item["current"].rstrip("\n") + "\n")


def check_record(record: Any) -> None:
    """A closed record: pinned paths, decided owner decisions, exact items, and a disposition for every cited decision."""
    _closed(record, RECORD_KEYS, "closed amendment record")
    require(record["schemaVersion"] == SCHEMA and record["designLabel"] == DESIGN_LABEL, "amendment schema and label")
    require(record["base"] == {"path": BASE_PATH, "sha256": BASE_SHA256, "designLabel": BASE_LABEL,
                               "record": {"path": BASE_RECORD_PATH, "sha256": BASE_RECORD_SHA256}},
            "pinned W02D base and record")
    _closed(record["effective"], {"path", "sha256"}, "closed effective pin")
    require(record["effective"]["path"] == EFFECTIVE_PATH and type(record["effective"]["sha256"]) is str
            and re.fullmatch("[0-9a-f]{64}", record["effective"]["sha256"]) is not None, "effective path and digest")
    decisions = record["ownerDecisions"]
    require(type(decisions) is list and bool(decisions), "owner decisions")
    for row in decisions:
        _closed(row, DECISION_KEYS, "closed owner decision")
        require(_text(row["id"]) and re.fullmatch(r"\d{4}-\d{2}-\d{2}", row["date"] if type(row["date"]) is str else "")
                and row["state"] == DECIDED and _text(row["decision"]) and _text(row["source"]),
                "every owner decision is decided: %r" % (row.get("id"),))
    ids = [row["id"] for row in decisions]
    require(len(ids) == len(set(ids)), "unique owner decisions")
    items = record["items"]
    require(type(items) is list and bool(items), "amendment items")
    item_ids = []
    for item in items:
        _closed(item, ITEM_KEYS, "closed amendment item")
        require(_text(item["id"]) and item["id"] not in item_ids and item["kind"] in KINDS and _text(item["section"])
                and _text(item["baseLines"]) and _text(item["why"]),
                "described amendment item %r" % (item["id"],))
        require(_text(item["current"]) and type(item["proposed"]) is str and item["current"] != item["proposed"]
                and type(item["occurrences"]) is int and item["occurrences"] >= 1, "effective amendment item " + item["id"])
        require(_ids(item["decisions"]) and set(item["decisions"]) <= set(ids)
                and (item["kind"] == "EDITORIAL") == (not item["decisions"]),
                "item %s cites decided owner decisions" % item["id"])
        if item["kind"] == "EDITORIAL":
            require(item["occurrences"] == 1 and _editorial(item),
                    "editorial item %s only renames the title or extends a fixed line" % item["id"])
        item_ids.append(item["id"])
    obligations = record["obligations"]
    require(type(obligations) is list, "obligations")
    obligation_ids = []
    for row in obligations:
        _closed(row, {"id", "owner", "text"}, "closed obligation")
        require(_text(row["id"]) and OBLIGATION_REF.fullmatch(row["id"]) is not None and row["id"] not in obligation_ids
                and _text(row["owner"]) and _text(row["text"]), "described obligation")
        obligation_ids.append(row["id"])
    cited = [decision for decision in ids if any(decision in item["decisions"] for item in items)]
    dispositions = record["dispositions"]
    require(type(dispositions) is list and [row.get("decision") for row in dispositions if type(row) is dict] == cited,
            "one disposition per cited owner decision, in record order")
    answered, used = set(), set()
    for row in dispositions:
        _closed(row, {"decision", "items", "obligations", "summary"}, "closed disposition")
        require(_texts(row["items"]) and set(row["items"]) <= set(item_ids)
                and all(row["decision"] in next(item for item in items if item["id"] == ident)["decisions"]
                        for ident in row["items"])
                and _ids(row["obligations"]) and set(row["obligations"]) <= set(obligation_ids)
                and _text(row["summary"]), "disposition of %r names its own items and known obligations" % row["decision"])
        answered |= set(row["items"])
        used |= set(row["obligations"])
    require({item["id"] for item in items if item["kind"] == "DECIDED"} <= answered, "every decided item is disposed")
    require(used == set(obligation_ids), "every obligation answers an owner decision")
    # Obligations the base text already names (W02D's) are not HS43's; the new text names exactly the record's.
    named = {ref for item in items
             for ref in set(OBLIGATION_REF.findall(item["proposed"])) - set(OBLIGATION_REF.findall(item["current"]))}
    require(named == set(obligation_ids), "the amended text names exactly the record's obligations")
    require(_texts(record["notAmended"]), "stated non-amendments")


def effective_spec(record: dict, base: bytes) -> bytes:
    """Apply every item in order. Each current text occurs exactly its stated number of times when applied, and every
    proposed text still occurs exactly that often at the end, so no later item rewrites an earlier one."""
    require(type(base) is bytes and digest(base) == BASE_SHA256, "pinned W02D effective bytes")
    text = base.decode("utf-8")
    for item in record["items"]:
        require(text.count(item["current"]) == item["occurrences"], "item %s current text count" % item["id"])
        before = text.count(item["proposed"])
        text = text.replace(item["current"], item["proposed"])
        require(text.count(item["proposed"]) == before + item["occurrences"], "item %s proposed text count" % item["id"])
    for item in record["items"]:
        require(text.count(item["proposed"]) >= item["occurrences"], "item %s survives every later item" % item["id"])
    raw = text.encode("utf-8")
    require(digest(raw) == record["effective"]["sha256"], "pinned effective HS43 bytes")
    return raw


def check(read: Callable[[str], bytes]) -> dict:
    """The W02D record is the pinned one, the HS43 record is closed, and the published HS43 specification is exact."""
    require(digest(read(BASE_RECORD_PATH)) == BASE_RECORD_SHA256, "pinned W02D amendment record")
    record = parse(read(RECORD_PATH))
    check_record(record)
    effective = effective_spec(record, read(BASE_PATH))
    require(read(EFFECTIVE_PATH) == effective, "published effective specification")
    return record
