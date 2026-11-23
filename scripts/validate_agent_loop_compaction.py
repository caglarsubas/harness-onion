#!/usr/bin/env python3
"""Agent-loop compaction (architecture/agent-loop-compaction/record.json, HR-COMPACTION-GOV-001, MET-013): the checker.

check(read) validates the record and its vectors through an injected byte reader (exact paths only, no listing) and
returns its refusals as (code, message) pairs, in the order the codes run:
- CG_SHAPE: the record and the vectors file, every object closed to its exact members with exact JSON types; the rule
  families are C1 to C9 in order, each with its model refusal code; the step-kind set is the base's plus COMPACT; the
  COMPACT detail and the profile's cooldown defaults are the model's.
- CG_BASIS: the schema's, the vectors file's and the model's digests; MAS-RA-008's README, two schemas, status record and
  scripts/agent_loop.py by digest; the status record names MAS-RA-008 and the status the record states; each base
  vocabulary list is an enum of the base trace schema, and the base step kinds lack COMPACT; the model imports nothing
  from scripts/agent_loop.py.
- CG_VECTOR: every vector is listed by exactly one family, its own; every family has a positive and a negative vector;
  every vector replays through the model (scripts/agent_loop_compaction.py) to its expectation, and a negative vector's
  code is its family's.
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
    import agent_loop_compaction as model
except ImportError:
    from scripts import agent_loop_compaction as model

ROOT = Path(__file__).resolve().parents[1]
RECORD_PATH = "architecture/agent-loop-compaction/record.json"
SCHEMA_PATH = "architecture/agent-loop-compaction/schema.json"
VECTORS_PATH = "architecture/agent-loop-compaction/vectors.json"
MODEL_PATH = "scripts/agent_loop_compaction.py"
SCHEMA_VERSION = "harness.planeon.ai/agent-loop-compaction/v1"
VECTORS_VERSION = "harness.planeon.ai/agent-loop-compaction-vectors/v1"
BASIS = {"readme": "architecture/agent-loop/README.md",
         "profileSchema": "architecture/agent-loop/loop-profile.schema.json",
         "traceSchema": "architecture/agent-loop/loop-trace.schema.json",
         "status": "architecture/agent-loop/status.json",
         "model": "scripts/agent_loop.py"}
BASE_ITEM = "MAS-RA-008"
CODES = ("CG_SHAPE", "CG_BASIS", "CG_VECTOR")
TOP = ("schemaVersion", "item", "packet", "status", "successorOf", "schema", "vectors", "model", "basis",
       "baseVocabulary", "stepKinds", "compactDetail", "profileDefaults", "ruleFamilies", "settlements", "outOfScope")
VOCABULARY = ("stepKinds", "hookEvents", "trustLabels", "terminalStatuses")
FAMILY = ("id", "name", "property", "source", "refusal", "vectors")
CASE = ("id", "family", "polarity", "title", "input", "expect")
DIGEST = re.compile(r"[0-9a-f]{64}\Z")
IMPORTS_BASE = re.compile(rb"^\s*(from|import)\s+(scripts\.)?agent_loop\b(?!_)|^\s*from\s+scripts\s+import\s+agent_loop\b(?!_)",
                          re.M)
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
    need(record["item"] == "HR-COMPACTION-GOV-001" and record["packet"] == "MET-013", "item and packet")
    text(record["status"], "status")
    closed(record["successorOf"], ("item", "status"), "successorOf")
    need(record["successorOf"]["item"] == BASE_ITEM, "successorOf.item is " + BASE_ITEM)
    text(record["successorOf"]["status"], "successorOf.status")
    pinned(record["schema"], SCHEMA_PATH, "schema")
    pinned(record["vectors"], VECTORS_PATH, "vectors")
    pinned(record["model"], MODEL_PATH, "model")
    closed(record["basis"], tuple(BASIS), "basis")
    for key, path in BASIS.items():
        pinned(record["basis"][key], path, "basis." + key)
    closed(record["baseVocabulary"], VOCABULARY, "baseVocabulary")
    for key in VOCABULARY:
        text_list(record["baseVocabulary"][key], "baseVocabulary." + key)
    need(record["stepKinds"] == record["baseVocabulary"]["stepKinds"] + ["COMPACT"]
         and tuple(record["stepKinds"]) == model.STEP_KINDS, "stepKinds is the base's plus COMPACT, as the model's")
    need(record["compactDetail"] == list(model.COMPACT_DETAIL), "compactDetail is the model's")
    closed(record["profileDefaults"], ("cooldownSeconds",), "profileDefaults")
    need(record["profileDefaults"]["cooldownSeconds"] == list(model.PROFILE_COOLDOWNS), "the cooldown defaults")
    families = record["ruleFamilies"]
    need(type(families) is list and [f.get("id") if type(f) is dict else None for f in families] == list(model.CODES),
         "the rule families are %s in order" % ", ".join(model.CODES))
    for family in families:
        where = "ruleFamily " + family["id"]
        closed(family, FAMILY, where)
        for key in ("name", "property", "source"):
            text(family[key], "%s.%s" % (where, key))
        need(family["refusal"] == model.CODES[family["id"]], where + ".refusal is the model's code")
        text_list(family["vectors"], where + ".vectors")
    need(type(record["settlements"]) is list and record["settlements"], "settlements is a non-empty list")
    for row in record["settlements"]:
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
        need(case["family"] in model.CODES, where + ".family is C1 to C9")
        need(case["polarity"] in ("POSITIVE", "NEGATIVE"), where + ".polarity")
        text(case["title"], where + ".title")
        need(type(case["input"]) is dict, where + ".input is an object")
        expect = case["expect"]
        if case["polarity"] == "POSITIVE":
            need(type(expect) is dict and expect.get("accept") is True and set(expect) <= {"accept", "result"}
                 and type(expect.get("result", {})) is dict, where + ".expect is an acceptance")
        else:
            closed(expect, ("refuse",), where + ".expect")
            need(expect["refuse"] in model.CODES.values(), where + ".expect.refuse is a model code")


def enums(node):
    """Every enum list in a parsed JSON schema."""
    if type(node) is dict:
        if type(node.get("enum")) is list:
            yield node["enum"]
        for value in node.values():
            yield from enums(value)
    elif type(node) is list:
        for value in node:
            yield from enums(value)


def check(read):
    """The refusals of the record at read, as (code, message) pairs in the codes' order; [] when it passes."""
    try:
        record = parse_json(read(RECORD_PATH))
        vectors = parse_json(read(VECTORS_PATH))
        check_shape(record, vectors)
    except Exception as exc:  # a malformed record or vectors file stops at its shape
        return [("CG_SHAPE", str(exc))]

    def basis():
        for key, path in (("schema", SCHEMA_PATH), ("vectors", VECTORS_PATH), ("model", MODEL_PATH)):
            need(record[key]["sha256"] == digest(read(path)), "the %s's digest" % key)
        for key, path in BASIS.items():
            need(record["basis"][key]["sha256"] == digest(read(path)), "the base %s's digest" % key)
        status = parse_json(read(BASIS["status"]))
        need(status.get("workItem") == BASE_ITEM and status.get("status") == record["successorOf"]["status"],
             "the base status record names %s and the stated status" % BASE_ITEM)
        found = list(enums(parse_json(read(BASIS["traceSchema"]))))
        for key in VOCABULARY:
            need(record["baseVocabulary"][key] in found, "baseVocabulary.%s is an enum of the base trace schema" % key)
        need("COMPACT" not in record["baseVocabulary"]["stepKinds"], "the base step kinds lack COMPACT")
        need(not IMPORTS_BASE.search(read(MODEL_PATH)), "the model imports from scripts/agent_loop.py")

    def vector():
        cases = {c["id"]: c for c in vectors["cases"]}
        need(len(cases) == len(vectors["cases"]), "a vector id twice")
        listed = [(f["id"], v) for f in record["ruleFamilies"] for v in f["vectors"]]
        need(sorted(v for _, v in listed) == sorted(cases), "every vector is listed by exactly one family")
        for family, vid in listed:
            need(cases[vid]["family"] == family, "vector %s is listed by %s, not its family" % (vid, family))
        for family in record["ruleFamilies"]:
            polarities = {cases[v]["polarity"] for v in family["vectors"]}
            need(polarities == {"POSITIVE", "NEGATIVE"}, family["id"] + " has a positive and a negative vector")
        for case in vectors["cases"]:
            if case["polarity"] == "NEGATIVE":
                need(case["expect"]["refuse"] == model.CODES[case["family"]], "vector %s refuses by its family's code"
                     % case["id"])
            ok, got = model.replay(case)
            need(ok, "vector %s replays to %r" % (case["id"], got))

    refusals = []
    for code, run in (("CG_BASIS", basis), ("CG_VECTOR", vector)):
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
        print("AGENT LOOP COMPACTION REFUSED: %d" % len(refusals))
        return 1
    record, vectors = parse_json(read(RECORD_PATH)), parse_json(read(VECTORS_PATH))
    polarity = [c["polarity"] for c in vectors["cases"]]
    print("AGENT LOOP COMPACTION OK: %d rule families, %d vectors (%d positive, %d negative)" % (
        len(record["ruleFamilies"]), len(polarity), polarity.count("POSITIVE"), polarity.count("NEGATIVE")))
    return 0


if __name__ == "__main__":
    sys.exit(main())
