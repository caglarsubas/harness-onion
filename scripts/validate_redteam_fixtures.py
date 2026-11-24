#!/usr/bin/env python3
"""Red-team and safety fixture pack (architecture/redteam-fixtures/, GR-REDTEAM-FIXTURES-001, MET-015): the checker.

check(read) validates the contract's record, its closed schema and its vectors through an injected byte reader (exact
paths only, no listing) and returns its refusals as (code, message) pairs, in the order the codes run:
- GRRT_SHAPE: record.json, schema.json and vectors.json, every object closed to its exact members; the schema's three
  $defs (manifestRow, case, runBinding); each vector `{id, family, check, expect, input, polarity, title}` in
  HR-REPLAY's entry form, a negative's expect `{refuse: <code>}`.
- GRRT_ORDER: the refusalOrder, the six rule families and their codes, the classes, expected values, licences,
  placement, the authored set, the N2 pair sets, the weights paths, the empty tree, the caseId pattern and RT-2's outcome
  table are the model's; the N1 table holds N1-01 to N1-09, each with a decision-record kind or none (N1-06).
- GRRT_BASES: the base files are their pinned digests; HR-REPLAY's PLACEMENT family has the one code the pack reuses;
  MAS-RA-002's era schema gives the partitions (so the closed partition is its second split.partition value, never a
  typed string) and the id pattern; the empty tree {entries: []} passes HR-REPLAY's TREE family (D1); GR-DEC's era
  record has the fail-closed values the model reads.
- GRRT_CODES: one negative vector per refusal code, each refusing with its code; every vector in one family.
- GRRT_VECTOR: the pins (schema, vectors, model) are the files' digests; the model imports the standard library and its
  two base models only; the vectors are RT-P1 to RT-P3, RT-E01 to RT-E09 but RT-E06 (N1-06 is RT-N12) and RT-N0 to
  RT-N16; every vector replays through the model (scripts/redteam_fixtures.py) to its expectation; each N1 case's
  contentSha256 is its table row's.
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
    import redteam_fixtures as model
except ImportError:
    from scripts import redteam_fixtures as model

ROOT = Path(__file__).resolve().parents[1]
RECORD_PATH = "architecture/redteam-fixtures/record.json"
SCHEMA_PATH = "architecture/redteam-fixtures/schema.json"
VECTORS_PATH = "architecture/redteam-fixtures/vectors.json"
MODEL_PATH = "scripts/redteam_fixtures.py"
RECORD_VERSION = "harness.planeon.ai/redteam-fixtures/v1"
VECTORS_VERSION = "harness.planeon.ai/redteam-fixtures-vectors/v1"
CODES = ("GRRT_SHAPE", "GRRT_ORDER", "GRRT_BASES", "GRRT_CODES", "GRRT_VECTOR")
TOP = ("schemaVersion", "item", "packet", "status", "recordSchema", "schema", "vectors", "model", "basis",
       "caseIdPattern", "classes", "expectedValues", "allowedLicences", "placement", "authoredSet", "pairSets",
       "weightsPaths", "emptyTree", "refusalOrder", "ruleFamilies", "vectorPerCode", "outcomeTable", "n1Cases",
       "settlements", "sources", "outOfScope")
BASIS = (("runManifestReadme", "architecture/run-manifest/README.md"),
         ("runManifestSchema", "architecture/run-manifest/run-manifest.schema.json"),
         ("splitDeclarationSchema", "architecture/run-manifest/split-declaration.schema.json"),
         ("replayRecord", "architecture/replay-fixtures/record.json"),
         ("replayModel", "scripts/replay_fixtures.py"),
         ("replayChecker", "scripts/validate_replay_fixtures.py"),
         ("decisionRecordCodes", "architecture/decision-record/reason-codes.json"),
         ("decisionRecordModel", "scripts/decision_record.py"),
         ("researchAdoptionV2Readme", "architecture/research-adoption-v2/README.md"))
FAMILY = ("id", "name", "property", "source", "codes", "vectors")
CASE = ("id", "family", "check", "expect", "input", "polarity", "title")
N1_ROW = ("caseId", "tool", "residue", "recordKind", "expected")
DEFS = ("manifestRow", "case", "runBinding")
N1_IDS = tuple("N1-%02d" % n for n in range(1, 10))
POSITIVES = ("RT-P1", "RT-P2", "RT-P3") + tuple("RT-E%02d" % n for n in range(1, 10) if n != 6)
NEGATIVES = tuple("RT-N%d" % n for n in range(17))
MODEL_IMPORTS = {"__future__", "hashlib", "re", "decision_record", "replay_fixtures", "scripts"}
DIGEST = re.compile(r"[0-9a-f]{64}\Z")
PREFIX = re.compile(r"[0-9a-f]{8}\Z")
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


def pinned(value, path, where):
    closed(value, ("path", "sha256"), where)
    need(value["path"] == path, "%s.path is %s" % (where, path))
    need(type(value["sha256"]) is str and DIGEST.match(value["sha256"]) is not None, where + ".sha256 is a hex digest")


def check_shape(record, schema, vectors):
    closed(record, TOP, "the record")
    need(record["schemaVersion"] == RECORD_VERSION, "schemaVersion is " + RECORD_VERSION)
    need(record["item"] == "GR-REDTEAM-FIXTURES-001" and record["packet"] == "MET-015", "item and packet")
    need(record["status"] == "CONTRACT_CANDIDATE" and record["recordSchema"] == model.SCHEMA_NAME,
         "status and recordSchema")
    for key, path in (("schema", SCHEMA_PATH), ("vectors", VECTORS_PATH), ("model", MODEL_PATH)):
        pinned(record[key], path, key)
    closed(record["basis"], [k for k, _ in BASIS], "basis")
    for key, path in BASIS:
        pinned(record["basis"][key], path, "basis." + key)
    for family in record["ruleFamilies"]:
        closed(family, FAMILY, "a rule family")
        text(family["property"], "a family's property")
    for row in record["n1Cases"]:
        closed(row, N1_ROW, "an N1 row")
    for row in record["outcomeTable"]:
        closed(row, ("expected", "outcome"), "an outcome row")
    for row in record["settlements"]:
        closed(row, ("id", "text"), "a settlement")
    for row in record["sources"]:
        closed(row, ("name", "sha256Prefix"), "a source")
        need(type(row["sha256Prefix"]) is str and PREFIX.match(row["sha256Prefix"]) is not None, "a source's prefix")
    need(type(record["outOfScope"]) is list and record["outOfScope"] and all(
        type(s) is str and s for s in record["outOfScope"]), "outOfScope is a list of non-empty strings")
    need(type(schema) is dict and schema.get("$id") == model.SCHEMA_NAME and schema.get("additionalProperties") is False
         and type(schema.get("$defs")) is dict and sorted(schema["$defs"]) == sorted(DEFS), "the closed schema's $defs")
    for name in DEFS:
        d = schema["$defs"][name]
        need(d.get("additionalProperties") is False and sorted(d.get("required", [])) == sorted(d.get("properties", {})),
             "$defs.%s is closed" % name)
    need(sorted(schema["$defs"]["manifestRow"]["properties"]) == sorted(model.ROW_KEYS)
         and sorted(schema["$defs"]["case"]["properties"]) == sorted(model.CASE_KEYS)
         and sorted(schema["$defs"]["runBinding"]["properties"]) == sorted(model.BINDING_KEYS),
         "the $defs' members are the model's")
    closed(vectors, ("schemaVersion", "cases"), "the vectors file")
    need(vectors["schemaVersion"] == VECTORS_VERSION, "the vectors' schemaVersion is " + VECTORS_VERSION)
    need(type(vectors["cases"]) is list and vectors["cases"], "cases is a non-empty list")
    for case in vectors["cases"]:
        closed(case, CASE, "a vector")
        text(case["id"], "a vector's id")
        text(case["title"], "a vector's title")
        need(case["check"] in model.CHECKS and type(case["input"]) is dict, "vector %s's check and input" % case["id"])
        if case["polarity"] == "negative":
            closed(case["expect"], ("refuse",), "vector %s's expect" % case["id"])
        else:
            need(case["polarity"] == "positive", "vector %s's polarity" % case["id"])
            closed(case["expect"], ("result",), "vector %s's expect" % case["id"])
            need(type(case["expect"]["result"]) is dict, "vector %s's expected result" % case["id"])


def check(read):
    """The refusals of the contract at read, as (code, message) pairs in the codes' order; [] when it passes."""
    try:
        record = parse_json(read(RECORD_PATH))
        schema = parse_json(read(SCHEMA_PATH))
        vectors = parse_json(read(VECTORS_PATH))
        check_shape(record, schema, vectors)
    except Exception as exc:  # a malformed file stops at its shape
        return [("GRRT_SHAPE", str(exc))]
    cases = {c["id"]: c for c in vectors["cases"]}

    def order():
        need(record["refusalOrder"] == list(model.REFUSAL_ORDER) and record["refusalOrder"][0] == "SHAPE",
             "the refusalOrder is the model's, SHAPE first")
        need([f["id"] for f in record["ruleFamilies"]] == [f for f, _ in model.FAMILIES], "the six rule families")
        need([f["codes"] for f in record["ruleFamilies"]] == [list(c) for _, c in model.FAMILIES], "the families' codes")
        coded = [c for _, codes in model.FAMILIES for c in codes]
        need(sorted(coded) == sorted(model.CODES[1:]) and len(coded) == len(set(coded)), "each code but SHAPE in one family")
        for key, value in (("classes", list(model.CLASSES)), ("expectedValues", list(model.EXPECTED)),
                           ("allowedLicences", list(model.ALLOWED_LICENCES)), ("placement", model.PLACEMENT),
                           ("authoredSet", {"setId": model.AUTHORED_SET, "licenceRef": model.AUTHORED_LICENCE}),
                           ("pairSets", {"source": model.PAIR_SOURCE_SET, "paired": model.PAIR_SET}),
                           ("weightsPaths", {"segments": list(model.WEIGHT_SEGMENTS),
                                             "suffixes": list(model.WEIGHT_SUFFIXES)}),
                           ("emptyTree", model.EMPTY_TREE), ("caseIdPattern", model.TASK_ID_PATTERN)):
            need(record[key] == value, "the record's %s is the model's" % key)
        need(record["outcomeTable"] == [{"expected": e, "outcome": o} for e, o in model.OUTCOMES],
             "RT-2's outcome table is the model's")
        need([row["caseId"] for row in record["n1Cases"]] == list(N1_IDS), "the N1 table is N1-01 to N1-09")
        need(all(row["recordKind"] in model.dr.KINDS or (row["caseId"] == "N1-06" and row["recordKind"] is None)
                 for row in record["n1Cases"]), "each N1 row names its record kind (N1-06 none)")

    def bases():
        for key, path in BASIS:
            need(record["basis"][key]["sha256"] == digest(read(path)), "the base file %s's digest" % path)
        replay = parse_json(read("architecture/replay-fixtures/record.json"))
        placement = [f for f in replay["ruleFamilies"] if f["id"] == "PLACEMENT"]
        need(len(placement) == 1 and placement[0]["codes"] == [model.PLACEMENT_CODE],
             "HR-REPLAY's PLACEMENT family has the one code the pack reuses")
        manifest = parse_json(read("architecture/run-manifest/run-manifest.schema.json"))
        enum = manifest["properties"]["split"]["properties"]["partition"]["enum"]
        need(enum == list(model.rf.PARTITIONS) and len(enum) == 2,
             "MAS-RA-002's era schema gives the partitions; the closed one is its second value")
        need(manifest["properties"]["runId"]["pattern"] == model.TASK_ID_PATTERN == record["caseIdPattern"],
             "the caseId pattern is MAS-RA-002's id pattern as main has it")
        empty = {"entries": []}
        need(model.EMPTY_TREE == empty and model.rf._tree_shape(empty), "D1: the empty tree is HR-REPLAY's TREE shape")
        model.rf.check_tree_paths(empty, {})
        model.rf.check_tree_order(empty)
        codes = parse_json(read("architecture/decision-record/reason-codes.json"))
        need(codes["failClosed"] == dict(model.dr.FAIL_CLOSED) and not set(model.dr.FAIL_CLOSED.values())
             & set(model.dr.PERMITTING), "GR-DEC's era fail-closed values, none permitting")

    def codes():
        per = record["vectorPerCode"]
        need(set(per) == set(model.CODES) and len(per) == len(model.CODES), "one entry per refusal code")
        for code, vids in per.items():
            need(type(vids) is list and len(vids) == 1, "one vector for %s" % code)
            case = cases.get(vids[0])
            need(case is not None and case["polarity"] == "negative" and case["expect"] == {"refuse": code},
                 "%s's vector refuses with %s" % (vids[0], code))
        listed = [v for f in record["ruleFamilies"] for v in f["vectors"]]
        need(sorted(listed) == sorted(cases) and len(listed) == len(set(listed)), "every vector in one family")
        for family in record["ruleFamilies"]:
            for vid in family["vectors"]:
                expect = cases[vid]["expect"]
                need(cases[vid]["family"] == family["id"], "%s's family is %s" % (vid, family["id"]))
                need("refuse" not in expect or expect["refuse"] in family["codes"] + ["SHAPE"],
                     "%s refuses with one of %s's codes" % (vid, family["id"]))
        refused = {c["expect"]["refuse"] for c in vectors["cases"] if c["polarity"] == "negative"}
        need(refused == set(model.CODES), "every refusal code is reached")

    def vector():
        for key, path in (("schema", SCHEMA_PATH), ("vectors", VECTORS_PATH), ("model", MODEL_PATH)):
            need(record[key]["sha256"] == digest(read(path)), "the %s's digest" % key)
        found = {(a or b).decode("ascii").split(".")[0] for a, b in IMPORT_LINE.findall(read(MODEL_PATH))}
        need(found == MODEL_IMPORTS, "the model imports %s only" % ", ".join(sorted(MODEL_IMPORTS)))
        need(len(cases) == len(vectors["cases"]), "a vector id twice")
        need(sorted(cases) == sorted(POSITIVES + NEGATIVES), "the vectors are RT-P1-P3, RT-E01-E09 but E06, RT-N0-N16")
        need(all(cases[v]["polarity"] == "positive" for v in POSITIVES), "the positives")
        for case in vectors["cases"]:
            ok, got = model.replay(case)
            need(ok, "vector %s replays to %r" % (case["id"], got))
        need(cases["RT-P1"]["expect"]["result"].get("classes") == list(model.CLASSES), "RT-P1 covers every class")
        rows = {row["caseId"]: row for row in record["n1Cases"]}
        for vid in POSITIVES[3:]:
            case = cases[vid]["input"]["case"]
            need(case["caseId"] == "N1-" + vid[4:] and case["setId"] == model.AUTHORED_SET, "%s is its N1 case" % vid)
            row = rows[case["caseId"]]
            need(case["contentSha256"] == digest(model.rf.canonical(row)), "%s's contentSha256 is its row's" % vid)
            need(cases[vid]["expect"]["result"]["kind"] == row["recordKind"]
                 and cases[vid]["expect"]["result"]["errorCode"] in row["expected"], "%s follows the N1 table" % vid)

    refusals = []
    for code, run in (("GRRT_ORDER", order), ("GRRT_BASES", bases), ("GRRT_CODES", codes), ("GRRT_VECTOR", vector)):
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
        print("RED-TEAM FIXTURES REFUSED: %d" % len(refusals))
        return 1
    record, vectors = parse_json(read(RECORD_PATH)), parse_json(read(VECTORS_PATH))
    polarity = [c["polarity"] for c in vectors["cases"]]
    print("RED-TEAM FIXTURES OK: %d rule families, %d vectors (%d positive, %d negative), %d refusal codes, %d N1 cases" % (
        len(record["ruleFamilies"]), len(polarity), polarity.count("positive"), polarity.count("negative"),
        len(record["vectorPerCode"]), len(record["n1Cases"])))
    return 0


if __name__ == "__main__":
    sys.exit(main())
