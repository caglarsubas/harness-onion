#!/usr/bin/env python3
"""Approval outcome (architecture/approval-outcome/record.json, HR-APPROVAL-OUTCOME-001, MET-013): the checker.

check(read) validates the record and its vectors through an injected byte reader (exact paths only, no listing) and
returns its refusals as (code, message) pairs, in the order the codes run:
- AO_RECORD: the record and the vectors file, every object closed to its exact members with exact JSON types; the open
  state, the outcomes, the event names, the kinds, the port answers, the UNAVAILABLE reasons, the row fields, the sweep
  bounds and the statement layers are the model's; every clause the contract names is present once, in its family; the
  rule families are O, A, S, H and N in order, each listing its own clauses and refusal codes.
- AO_BASIS: the schema's, the vectors file's and the model's digests; the model imports the standard library only
  (`__future__`, `re`).
- AO_VECTOR: every vector is listed by exactly one family, its own; every family has a positive and a negative vector;
  every vector replays through the model (scripts/approval_outcome.py) to its expectation, and a negative vector's code
  is one of its family's; every model code and every check is reached; every clause but Q-TLA-1 is named by a positive
  and by a negative vector, and Q-TLA-1 by none;
  the note's in-scope negatives (N-1 to N-6, N-8 to N-12) are each named by a refused vector and N-7 and N-13 by none;
  the three UNAVAILABLE reasons are each a lifecycle vector's result.
Standard library plus the reference model. main() reads through the checker's own disk_reader. Data checks only; it
enforces nothing.
"""
from __future__ import annotations

import hashlib
import json
import re
import stat
import sys
from pathlib import Path

try:
    import approval_outcome as model
except ImportError:
    from scripts import approval_outcome as model

ROOT = Path(__file__).resolve().parents[1]
RECORD_PATH = "architecture/approval-outcome/record.json"
SCHEMA_PATH = "architecture/approval-outcome/schema.json"
VECTORS_PATH = "architecture/approval-outcome/vectors.json"
MODEL_PATH = "scripts/approval_outcome.py"
SCHEMA_VERSION = "harness.planeon.ai/approval-outcome/v1"
VECTORS_VERSION = "harness.planeon.ai/approval-outcome-vectors/v1"
CODES = ("AO_RECORD", "AO_BASIS", "AO_VECTOR")
TOP = ("schemaVersion", "item", "packet", "status", "schema", "vectors", "model", "sources", "openState", "outcomes",
       "events", "kinds", "askAnswers", "decideAnswers", "unavailableReasons", "rowFields", "sweep", "statementLayers",
       "clauses", "ruleFamilies", "settlements", "outOfScope")
FAMILY = ("id", "name", "codes", "clauses", "vectors")
CASE = ("id", "family", "check", "polarity", "title", "refs", "input", "expect")
FAMILIES = ("O", "A", "S", "H", "N")
CLAUSE_IDS = {"O": ("O1", "O2", "O3", "O4", "O5", "Q-TLA-1", "Q-TLA-2", "UNAVAILABLE-SOURCES"),
              "A": ("A1", "A2", "A3", "A4", "A5"),
              "S": ("S1", "S2", "S3", "S4", "S5"),
              "H": ("H1a", "R2-N1", "N1", "H1b", "H2", "H3", "H4"),
              "N": ("N1-SCOPE",)}
NO_VECTOR = ("Q-TLA-1",)                               # CONTRACT_295 section 3c: no vector
NEGATIVES_IN = tuple("N-%d" % n for n in (1, 2, 3, 4, 5, 6, 8, 9, 10, 11, 12))
NEGATIVES_OUT = ("N-7", "N-13")                        # ORC-295-READ-OK (1): the trigger packet's
MODEL_IMPORTS = {"__future__", "re"}
DIGEST = re.compile(r"[0-9a-f]{64}\Z")
PREFIX = re.compile(r"[0-9a-f]{8}\Z")
NEGATIVE_REF = re.compile(r"N-[0-9]{1,2}\Z")
IMPORT_LINE = re.compile(rb"^\s*(?:from\s+([A-Za-z_][\w.]*)\s+import\b|import\s+([A-Za-z_][\w.]*))", re.M)
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
        need(len(keys) == len(set(keys)), "a duplicate member")
        return dict(items)
    return json.loads(raw.decode("utf-8"), object_pairs_hook=pairs,
                      parse_constant=lambda c: (_ for _ in ()).throw(Refused("a non-finite number")))


def closed(value, members, where):
    need(type(value) is dict and set(value) == set(members), "%s is closed to %s" % (where, ", ".join(members)))


def text(value, where):
    need(type(value) is str and value != "", "%s is a non-empty string" % where)


def text_list(value, where):
    need(type(value) is list and value and all(type(v) is str and v for v in value), where + " is a list of non-empty strings")


def pinned(value, path, where):
    closed(value, ("path", "sha256"), where)
    need(value["path"] == path, "%s.path is %s" % (where, path))
    need(type(value["sha256"]) is str and DIGEST.match(value["sha256"]), where + ".sha256 is a hex digest")


def check_shape(record, vectors):
    closed(record, TOP, "the record")
    need(record["schemaVersion"] == SCHEMA_VERSION, "schemaVersion is " + SCHEMA_VERSION)
    need(record["item"] == "HR-APPROVAL-OUTCOME-001" and record["packet"] == "MET-013", "item and packet")
    text(record["status"], "status")
    pinned(record["schema"], SCHEMA_PATH, "schema")
    pinned(record["vectors"], VECTORS_PATH, "vectors")
    pinned(record["model"], MODEL_PATH, "model")
    need(type(record["sources"]) is list and record["sources"], "sources is a non-empty list")
    for row in record["sources"]:
        closed(row, ("name", "sha256Prefix"), "a source")
        text(row["name"], "a source's name")
        need(type(row["sha256Prefix"]) is str and PREFIX.match(row["sha256Prefix"]), "a source's sha256Prefix")
    need(record["openState"] == model.OPEN, "openState is the model's " + model.OPEN)
    for key, value in (("outcomes", model.OUTCOMES), ("kinds", model.KINDS), ("askAnswers", model.ASK_ANSWERS),
                       ("decideAnswers", model.DECIDE_ANSWERS), ("unavailableReasons", model.UNAVAILABLE_REASONS),
                       ("statementLayers", model.LAYERS)):
        need(record[key] == list(value), key + " is the model's")
    need(record["events"] == {"asked": model.ASKED_EVENT, "decided": model.DECIDED_EVENT}, "events are the model's")
    need(record["rowFields"] == {"required": list(model.ROW_KEYS), "optional": list(model.ROW_OPTIONAL)},
         "rowFields are the model's")
    need(record["sweep"] == {"owners": list(model.SWEEP_OWNERS), "minSeconds": model.SWEEP_MIN,
                             "maxSeconds": model.SWEEP_MAX, "defaultSeconds": model.SWEEP_DEFAULT}, "sweep is the model's")
    clauses = record["clauses"]
    need(type(clauses) is list, "clauses is a list")
    for row in clauses:
        closed(row, ("id", "family", "text"), "a clause")
        text(row["text"], "clause %s's text" % row["id"])
    ids = [row["id"] for row in clauses]
    need(sorted(ids) == sorted(i for f in FAMILIES for i in CLAUSE_IDS[f]), "the clauses are the contract's, each once")
    need(all(row["id"] in CLAUSE_IDS.get(row["family"], ()) for row in clauses), "each clause is in its family")
    families = record["ruleFamilies"]
    need(type(families) is list and [f.get("id") if type(f) is dict else None for f in families] == list(FAMILIES),
         "the rule families are O, A, S, H, N in order")
    for family in families:
        where = "ruleFamily " + family["id"]
        closed(family, FAMILY, where)
        text(family["name"], where + ".name")
        text_list(family["codes"], where + ".codes")
        need(set(family["codes"]) <= set(model.CODES), where + ".codes are model codes")
        need(family["clauses"] == [row["id"] for row in clauses if row["family"] == family["id"]],
             where + ".clauses are its own")
        text_list(family["vectors"], where + ".vectors")
    for key in ("settlements",):
        need(type(record[key]) is list and record[key], key + " is a non-empty list")
        for row in record[key]:
            closed(row, ("id", "text"), "a settlement")
            text(row["id"], "a settlement's id")
            text(row["text"], "a settlement's text")
    text_list(record["outOfScope"], "outOfScope")
    closed(vectors, ("schemaVersion", "cases"), "the vectors file")
    need(vectors["schemaVersion"] == VECTORS_VERSION, "the vectors' schemaVersion is " + VECTORS_VERSION)
    need(type(vectors["cases"]) is list and vectors["cases"], "cases is a non-empty list")
    for case in vectors["cases"]:
        closed(case, CASE, "a vector")
        text(case["id"], "a vector's id")
        where = "vector " + case["id"]
        need(case["family"] in FAMILIES, where + ".family is O, A, S, H or N")
        need(case["check"] in model.CHECKS, where + ".check is a model check")
        need(case["polarity"] in ("POSITIVE", "NEGATIVE"), where + ".polarity")
        text(case["title"], where + ".title")
        text_list(case["refs"], where + ".refs")
        need(all(r in ids or NEGATIVE_REF.match(r) for r in case["refs"]), where + ".refs name clauses or negatives")
        need(type(case["input"]) is dict, where + ".input is an object")
        expect = case["expect"]
        if case["polarity"] == "POSITIVE":
            need(type(expect) is dict and expect.get("accept") is True and set(expect) <= {"accept", "result"}
                 and type(expect.get("result", {})) is dict, where + ".expect is an acceptance")
        else:
            closed(expect, ("refuse",), where + ".expect")
            need(expect["refuse"] in model.CODES, where + ".expect.refuse is a model code")


def check(read):
    """The refusals of the record at read, as (code, message) pairs in the codes' order; [] when it passes."""
    try:
        record = parse_json(read(RECORD_PATH))
        vectors = parse_json(read(VECTORS_PATH))
        check_shape(record, vectors)
    except Exception as exc:  # a malformed record or vectors file stops at its shape
        return [("AO_RECORD", str(exc))]

    def basis():
        for key, path in (("schema", SCHEMA_PATH), ("vectors", VECTORS_PATH), ("model", MODEL_PATH)):
            need(record[key]["sha256"] == digest(read(path)), "the %s's digest" % key)
        found = {(a or b).decode("ascii").split(".")[0] for a, b in IMPORT_LINE.findall(read(MODEL_PATH))}
        need(found == MODEL_IMPORTS, "the model imports %s only" % ", ".join(sorted(MODEL_IMPORTS)))

    def vector():
        cases = {c["id"]: c for c in vectors["cases"]}
        need(len(cases) == len(vectors["cases"]), "a vector id twice")
        listed = [(f["id"], v) for f in record["ruleFamilies"] for v in f["vectors"]]
        need(sorted(v for _, v in listed) == sorted(cases), "every vector is listed by exactly one family")
        for family, vid in listed:
            need(cases[vid]["family"] == family, "vector %s is listed by %s, not its family" % (vid, family))
        codes = {f["id"]: f["codes"] for f in record["ruleFamilies"]}
        for family in record["ruleFamilies"]:
            polarities = {cases[v]["polarity"] for v in family["vectors"]}
            need(polarities == {"POSITIVE", "NEGATIVE"}, family["id"] + " has a positive and a negative vector")
        refused = set()
        for case in vectors["cases"]:
            if case["polarity"] == "NEGATIVE":
                need(case["expect"]["refuse"] in codes[case["family"]], "vector %s refuses by one of its family's codes"
                     % case["id"])
                refused.add(case["expect"]["refuse"])
            ok, got = model.replay(case)
            need(ok, "vector %s replays to %r" % (case["id"], got))
        need(refused == set(model.CODES), "every model code is reached")
        need({c["check"] for c in vectors["cases"]} == set(model.CHECKS), "every check is reached")
        named = {r for c in vectors["cases"] for r in c["refs"]}
        for polarity in ("POSITIVE", "NEGATIVE"):
            have = {r for c in vectors["cases"] if c["polarity"] == polarity for r in c["refs"]}
            bare = [row["id"] for row in record["clauses"] if row["id"] not in have and row["id"] not in NO_VECTOR]
            need(not bare, "clauses without a %s vector: %s" % (polarity.lower(), ", ".join(bare)))
        need(not named & set(NO_VECTOR), "Q-TLA-1 has no vector")
        negatives = {r for c in vectors["cases"] if c["polarity"] == "NEGATIVE" for r in c["refs"]}
        need(set(NEGATIVES_IN) <= negatives, "each in-scope negative is named by a refused vector")
        need(not named & set(NEGATIVES_OUT), "N-7 and N-13 are out")
        reasons = {c["expect"]["result"].get("reason") for c in vectors["cases"] if c["check"] == "LIFECYCLE"
                   and c["polarity"] == "POSITIVE" and c["expect"].get("result", {}).get("state") == "UNAVAILABLE"}
        need(reasons == set(model.UNAVAILABLE_REASONS), "each UNAVAILABLE reason is a lifecycle vector's result")

    refusals = []
    for code, run in (("AO_BASIS", basis), ("AO_VECTOR", vector)):
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
    linked ancestors refused (validate_data_correctness's reader form)."""
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
        print("APPROVAL OUTCOME REFUSED: %d" % len(refusals))
        return 1
    record, vectors = parse_json(read(RECORD_PATH)), parse_json(read(VECTORS_PATH))
    polarity = [c["polarity"] for c in vectors["cases"]]
    print("APPROVAL OUTCOME OK: %d rule families, %d clauses, %d vectors (%d positive, %d negative)" % (
        len(record["ruleFamilies"]), len(record["clauses"]), len(polarity), polarity.count("POSITIVE"),
        polarity.count("NEGATIVE")))
    return 0


if __name__ == "__main__":
    sys.exit(main())
