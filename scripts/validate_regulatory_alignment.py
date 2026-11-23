#!/usr/bin/env python3
"""Regulatory alignment (architecture/regulatory-alignment.json, REG-ALIGN-001, MET-014): the checker.

check(read) validates the published record and its README's provenance through an injected byte reader (exact paths
only, no listing) and returns its refusals as (code, message) pairs, in the order the codes run:
- RA_SHAPE: the record's top-level keys are exactly the 11 published keys (id REG-ALIGN-001, schemaVersion 1.0.0,
  status PUBLISHED, and the eight content sections); rows, EU date rows and sources are closed to their keys; the
  README's provenance block holds exactly the five moved keys (draftedBy, draftDate, revision, revisionNotes,
  intendedPath), and intendedPath is this record's path.
- RA_ENUMS: every row's and EU date row's enum fields are in their enum (state, gapKind, carrierCheck, candidateState,
  confirmation, addressee, noCarryingItem); gapKindMeaning names exactly the gap kinds.
- RA_RULES: the record's eight `rules`, each checked as stated (the draft date for dateAlreadyPassed is the
  provenance block's draftDate).
- RA_IDS: row ids, EU date row ids and source ids are each unique, and no id is both a row's and an EU date row's.
- RA_SOURCES: every row, EU date row and date object cites a source by its id, and every source is cited.
Standard library only. main() reads through the checker's own disk_reader. Data checks only; it claims no compliance.
"""
from __future__ import annotations

import json
import re
import stat
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
RECORD_PATH = "architecture/regulatory-alignment.json"
README_PATH = "architecture/regulatory-alignment-README.md"
CODES = ("RA_SHAPE", "RA_ENUMS", "RA_RULES", "RA_IDS", "RA_SOURCES")
TOP = ("schemaVersion", "id", "status", "basis", "nonClaims", "sources", "enums", "rows", "euDates", "rules",
       "gapKindMeaning")
MOVED = ("draftedBy", "draftDate", "intendedPath", "revision", "revisionNotes")
ENUMS = ("state", "gapKind", "carrierCheck", "confirmation", "candidateState", "noCarryingItem", "addressee")
ROW = ("id", "source", "locator", "practice", "carriedBy", "evidence", "state", "gap", "carrierCheck")
ROW_OPTIONAL = ("candidateState",)
EU_ROW = ("id", "obligation", "addressee", "obligationLocator", "source", "dateAsEnacted", "dateAsAmended",
          "dateAlreadyPassed", "carriedBy", "state", "gap")
SOURCE = ("id", "title", "nature", "sha256", "heldAs")
SOURCE_OPTIONAL = ("note", "bytes", "date", "locatorForm")
GAP = ("kind", "note")
GAP_OPTIONAL = ("carryingItems", "itemState", "noCarryingItem", "relatedItems")
DATE = ("date", "source", "confirmation")
DATE_OPTIONAL = ("locator", "note")
RULES = (
    "state MAPPED requires carrierCheck CONFIRMED or CORRECTED.",
    "a row with candidateState MAPPED has state PARTIAL, gap kind CARRIER_UNCONFIRMED and carrierCheck NOT_CHECKED.",
    "every non-MAPPED row carries a gap with a kind from the enum and a note.",
    "every PRODUCT_GAP gap names carryingItems (roadmap ids) or, when the list is empty, noCarryingItem with the enum's "
    "one value.",
    "every EU row carries dateAsEnacted and dateAsAmended; each date object cites a source and a confirmation.",
    "a date object whose source has a held digest carries confirmation HELD_SOURCE and a locator; one whose source has "
    "none carries UNCONFIRMED.",
    "dateAlreadyPassed is computed from dateAsEnacted against draftDate.",
    "an obligationLocator naming two places gives a pdfPage for each place.",
)
PROVENANCE = re.compile(r"## Provenance\n(?:[^\n]*\n)*?```json\n(.*?)\n```\n", re.S)
DAY = re.compile(r"\d{4}-\d{2}-\d{2}\Z")
PDF_PAGE = re.compile(r"pdfPage \d+")
MAX_BYTES = 16_777_216


class Refused(Exception):
    pass


def need(ok, message):
    if not ok:
        raise Refused(message)


def parse_json(raw):
    need(type(raw) is bytes, "a JSON file is present")

    def pairs(items):
        keys = [k for k, _ in items]
        need(len(keys) == len(set(keys)), "a duplicate member")
        return dict(items)
    return json.loads(raw.decode("utf-8"), object_pairs_hook=pairs,
                      parse_constant=lambda c: (_ for _ in ()).throw(Refused("a non-finite number")))


def closed(value, required, optional, where):
    need(type(value) is dict and set(required) <= set(value) <= set(required) | set(optional),
         "%s is closed to %s" % (where, ", ".join(tuple(required) + tuple(optional))))


def text(value, where):
    need(type(value) is str and value != "", "%s is a non-empty string" % where)


def provenance(read):
    match = PROVENANCE.search(read(README_PATH).decode("utf-8"))
    need(match is not None, "the README has a Provenance section with one JSON block")
    return parse_json(match.group(1).encode("utf-8"))


def check_shape(record, moved):
    closed(record, TOP, (), "the record")
    need(list(record) == list(TOP), "the record's keys are in the published order")
    need(record["id"] == "REG-ALIGN-001" and record["schemaVersion"] == "1.0.0" and record["status"] == "PUBLISHED",
         "id REG-ALIGN-001, schemaVersion 1.0.0, status PUBLISHED")
    closed(moved, MOVED, (), "the README's provenance block")
    need(moved["intendedPath"] == RECORD_PATH, "the provenance's intendedPath is this record's path")
    need(type(moved["draftDate"]) is str and DAY.match(moved["draftDate"]), "the provenance's draftDate is a day")
    need(type(record["basis"]) is dict and record["basis"], "basis is an object")
    for key in ("nonClaims", "rules"):
        need(type(record[key]) is list and record[key] and all(type(x) is str and x for x in record[key]),
             key + " is a list of non-empty strings")
    need(type(record["enums"]) is dict and sorted(record["enums"]) == sorted(ENUMS), "enums are the seven")
    for name, values in record["enums"].items():
        need(type(values) is list and values and all(type(v) is str and v for v in values), "enum %s" % name)
    need(type(record["gapKindMeaning"]) is dict, "gapKindMeaning is an object")
    for key, shape, optional in (("sources", SOURCE, SOURCE_OPTIONAL), ("rows", ROW, ROW_OPTIONAL),
                                 ("euDates", EU_ROW, ())):
        need(type(record[key]) is list and record[key], key + " is a non-empty list")
        for row in record[key]:
            closed(row, shape, optional, "a %s entry" % key)
            text(row["id"], "a %s id" % key)
    for row in record["rows"] + record["euDates"]:
        if row["gap"] is not None:
            closed(row["gap"], GAP, GAP_OPTIONAL, "row %s's gap" % row["id"])
        closed(row["carriedBy"], ("harness", "modules"), (), "row %s's carriedBy" % row["id"])
    for row in record["euDates"]:
        for key in ("dateAsEnacted", "dateAsAmended"):
            if type(row[key]) is dict:
                closed(row[key], DATE, DATE_OPTIONAL, "EU row %s's %s" % (row["id"], key))


def check(read):
    """The refusals of the record at read, as (code, message) pairs in the codes' order; [] when it passes."""
    try:
        record = parse_json(read(RECORD_PATH))
        moved = provenance(read)
        check_shape(record, moved)
    except Exception as exc:  # a malformed record stops at its shape
        return [("RA_SHAPE", str(exc))]
    enums, rows, eu = record["enums"], record["rows"], record["euDates"]
    sources = {s["id"]: s for s in record["sources"]}

    def enum_fields():
        for row in rows + eu:
            need(row["state"] in enums["state"], "row %s's state" % row["id"])
            if row["gap"] is not None:
                need(row["gap"]["kind"] in enums["gapKind"], "row %s's gap kind" % row["id"])
                if "noCarryingItem" in row["gap"]:
                    need(row["gap"]["noCarryingItem"] in enums["noCarryingItem"], "row %s's noCarryingItem" % row["id"])
        for row in rows:
            need(row["carrierCheck"] in enums["carrierCheck"], "row %s's carrierCheck" % row["id"])
            if "candidateState" in row:
                need(row["candidateState"] in enums["candidateState"], "row %s's candidateState" % row["id"])
        for row in eu:
            need(row["addressee"] in enums["addressee"], "EU row %s's addressee" % row["id"])
            for key in ("dateAsEnacted", "dateAsAmended"):
                if type(row[key]) is dict:
                    need(row[key]["confirmation"] in enums["confirmation"], "EU row %s's confirmation" % row["id"])
        need(sorted(record["gapKindMeaning"]) == sorted(enums["gapKind"]), "gapKindMeaning names the gap kinds")

    def rules():
        need(record["rules"] == list(RULES), "the record's rules are the eight this checker checks")
        for row in rows + eu:
            if row["state"] == "MAPPED" and "carrierCheck" in row:
                need(row["carrierCheck"] in ("CONFIRMED", "CORRECTED"), "rule 1: row %s" % row["id"])
        for row in rows:
            if row.get("candidateState") == "MAPPED":
                need(row["state"] == "PARTIAL" and row["gap"] is not None and row["gap"]["kind"] == "CARRIER_UNCONFIRMED"
                     and row["carrierCheck"] == "NOT_CHECKED", "rule 2: row %s" % row["id"])
        for row in rows + eu:
            if row["state"] != "MAPPED":
                need(row["gap"] is not None and row["gap"]["kind"] in enums["gapKind"]
                     and type(row["gap"]["note"]) is str and row["gap"]["note"] != "", "rule 3: row %s" % row["id"])
            gap = row["gap"]
            if gap is not None and gap["kind"] == "PRODUCT_GAP":
                items = gap.get("carryingItems")
                need(type(items) is list and (items and all(type(i) is str and i for i in items)
                                              or (items == [] and gap.get("noCarryingItem") == enums["noCarryingItem"][0]
                                                  and len(enums["noCarryingItem"]) == 1)), "rule 4: row %s" % row["id"])
        for row in eu:
            for key in ("dateAsEnacted", "dateAsAmended"):
                date = row[key]
                need(type(date) is dict and date.get("source") in sources and date.get("confirmation"),
                     "rule 5: EU row %s's %s" % (row["id"], key))
                held = sources[date["source"]]["sha256"] is not None
                need((date["confirmation"] == "HELD_SOURCE" and type(date.get("locator")) is str and date["locator"])
                     if held else date["confirmation"] == "UNCONFIRMED", "rule 6: EU row %s's %s" % (row["id"], key))
            need(type(row["dateAlreadyPassed"]) is bool
                 and row["dateAlreadyPassed"] == (row["dateAsEnacted"]["date"] < moved["draftDate"]),
                 "rule 7: EU row %s" % row["id"])
            places = [p for p in row["obligationLocator"].split(";") if p.strip()]
            need(places and all(PDF_PAGE.search(p) for p in places), "rule 8: EU row %s" % row["id"])

    def ids():
        for key, values in (("rows", rows), ("euDates", eu), ("sources", record["sources"])):
            seen = [r["id"] for r in values]
            need(len(seen) == len(set(seen)), "the %s ids are unique" % key)
        need(not {r["id"] for r in rows} & {r["id"] for r in eu}, "no id is both a row's and an EU row's")

    def cited():
        used = set()
        for row in rows + eu:
            need(row["source"] in sources, "row %s cites a source by id" % row["id"])
            used.add(row["source"])
        for row in eu:
            for key in ("dateAsEnacted", "dateAsAmended"):
                need(row[key]["source"] in sources, "EU row %s's %s cites a source by id" % (row["id"], key))
                used.add(row[key]["source"])
        need(used == set(sources), "every source is cited")

    refusals = []
    for code, run in (("RA_ENUMS", enum_fields), ("RA_RULES", rules), ("RA_IDS", ids), ("RA_SOURCES", cited)):
        try:
            run()
        except Exception as exc:
            refusals.append((code, str(exc)))
    return refusals


def _refuse_unless(ok: bool, message: str) -> None:
    if not ok:
        raise ValueError(message)


def disk_reader(root: Path = ROOT):
    """The checker's own repository reader: bounded, regular, single-link files under root, exact relative paths only,
    linked ancestors refused (validate_approval_outcome's reader form)."""
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
        identity = lambda row: (row.st_dev, row.st_ino, row.st_mode, row.st_nlink, row.st_size, row.st_mtime_ns,
                                row.st_ctime_ns)
        _refuse_unless(identity(before) == identity(after) and len(raw) == before.st_size,
                       "file changed during read: " + path)
        return raw
    return read


def main(argv=None):
    root = Path((argv or sys.argv[1:] or [str(ROOT)])[0])
    read = disk_reader(root)
    refusals = check(read)
    if refusals:
        for code, message in refusals:
            print("%s: %s" % (code, message))
        print("REGULATORY ALIGNMENT REFUSED: %d" % len(refusals))
        return 1
    record = parse_json(read(RECORD_PATH))
    print("REGULATORY ALIGNMENT OK: %d rows, %d EU date rows, %d sources, %d rules, %d published keys" % (
        len(record["rows"]), len(record["euDates"]), len(record["sources"]), len(record["rules"]), len(record)))
    return 0


if __name__ == "__main__":
    sys.exit(main())
