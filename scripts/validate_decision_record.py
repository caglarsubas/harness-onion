#!/usr/bin/env python3
"""Decision record (architecture/decision-record/, GR-DECISION-RECORD-001, MET-014): the checker.

check(read) validates the contract's record (reason-codes.json), its vectors and its status record through an injected
byte reader (exact paths only, no listing) and returns its refusals as (code, message) pairs, in the order the codes
run:
- DR_SHAPE: reason-codes.json, vectors.json and status.json, every object closed to its exact members; each case is
  `{id, kind, input, expect}` with kind RECORD or LIFT, a LIFT input `{escalation, approval, lifted, effect}`.
- DR_ENVELOPE: the kinds, decision sets, unordered kinds, fail-closed values, reserved error codes in their two groups,
  per-kind reason codes and the check order are the model's; the APPROVAL set and row fields are
  HR-APPROVAL-OUTCOME-001's (its record, read through the reader and pinned by digest).
- DR_LIFT: the clauses are E1-E7, X3 and L1-L5, each once, in the families E and L, and L5 carries E1's two sentences;
  the families' codes are the model's check order and LIFT_REFUSED.
- DR_CODES: one vector per refusal code: each code's vectors exist and refuse with that code, every code is reached;
  N1, N8, N9 and N10 keep r2's results; the C30 tests are the seven named cases.
- DR_VECTOR: the pins (schema, vectors, status, model, HR-APPROVAL's record) are the files' digests; the model imports
  the standard library only; the cases are P1-P8 (P8 as P8a and P8b) and N1-N14 with N7a-f, N11a-b and N13a-b; every
  case replays through the model (scripts/decision_record.py) to its expectation; P8b chains on P8a.
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
    import decision_record as model
except ImportError:
    from scripts import decision_record as model

ROOT = Path(__file__).resolve().parents[1]
RECORD_PATH = "architecture/decision-record/reason-codes.json"
SCHEMA_PATH = "architecture/decision-record/decision-record.schema.json"
VECTORS_PATH = "architecture/decision-record/vectors.json"
STATUS_PATH = "architecture/decision-record/status.json"
MODEL_PATH = "scripts/decision_record.py"
APPROVAL_PATH = "architecture/approval-outcome/record.json"
RECORD_VERSION = "harness.planeon.ai/decision-record-reason-codes/v1"
VECTORS_VERSION = "harness.planeon.ai/decision-record-vectors/v1"
STATUS_VERSION = "harness.planeon.ai/decision-record-status/v1"
CODES = ("DR_SHAPE", "DR_ENVELOPE", "DR_LIFT", "DR_CODES", "DR_VECTOR")
TOP = ("schemaVersion", "item", "packet", "status", "recordSchema", "schema", "vectors", "statusRecord", "model",
       "approvalOutcome", "sources", "kinds", "decisions", "unorderedKinds", "failClosed", "errorCodes", "reasonCodes",
       "approvalFields", "checkOrder", "consumerRule", "clauses", "ruleFamilies", "vectorPerCode", "r2Results",
       "chainedPair", "c30Tests", "settlements", "outOfScope")
STATUS_TOP = ("schemaVersion", "item", "packet", "status", "recordSchema", "consumers", "producers")
FAMILY = ("id", "name", "codes", "clauses", "vectors")
CASE = ("id", "kind", "input", "expect")
LIFT_INPUT = ("escalation", "approval", "lifted", "effect")
CLAUSE_IDS = {"E": ("E1", "E2", "E3", "E4", "E5", "E6", "E7", "X3"), "L": ("L1", "L2", "L3", "L4", "L5")}
L5_SENTENCES = ("The ESCALATE record has not been lifted before", "an ESCALATE record is lifted at most once")
POSITIVES = ("GR-P1", "GR-P2", "GR-P3", "GR-P4", "GR-P5", "GR-P6", "GR-P7", "GR-P8a", "GR-P8b")
NEGATIVES = ("GR-N1", "GR-N2", "GR-N3", "GR-N4", "GR-N5", "GR-N6", "GR-N7a", "GR-N7b", "GR-N7c", "GR-N7d", "GR-N7e",
             "GR-N7f", "GR-N8", "GR-N9", "GR-N10", "GR-N11a", "GR-N11b", "GR-N12", "GR-N13a", "GR-N13b", "GR-N14")
R2_RESULT_IDS = ("GR-N1", "GR-N8", "GR-N9", "GR-N10")
C30_TESTS = ("case_escalate_between_check_and_act", "case_crash_before_act", "case_approval_for_superseded_escalation",
             "case_effect_repeated_delivery", "case_new_revision_after_approval", "case_approval_expires_before_effect",
             "case_second_approval_after_lift")
MODEL_IMPORTS = {"__future__", "hashlib", "json"}
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


def text_list(value, where):
    need(type(value) is list and value and all(type(v) is str and v for v in value), where + " is a list of non-empty strings")


def pinned(value, path, where):
    closed(value, ("path", "sha256"), where)
    need(value["path"] == path, "%s.path is %s" % (where, path))
    need(type(value["sha256"]) is str and DIGEST.match(value["sha256"]), where + ".sha256 is a hex digest")


def check_shape(record, vectors, status):
    closed(record, TOP, "the record")
    need(record["schemaVersion"] == RECORD_VERSION, "schemaVersion is " + RECORD_VERSION)
    need(record["item"] == "GR-DECISION-RECORD-001" and record["packet"] == "MET-014", "item and packet")
    need(record["status"] == "PUBLISHED" and record["recordSchema"] == model.SCHEMA_NAME, "status and recordSchema")
    for key, path in (("schema", SCHEMA_PATH), ("vectors", VECTORS_PATH), ("statusRecord", STATUS_PATH),
                      ("model", MODEL_PATH), ("approvalOutcome", APPROVAL_PATH)):
        pinned(record[key], path, key)
    need(type(record["sources"]) is list and record["sources"], "sources is a non-empty list")
    for row in record["sources"]:
        closed(row, ("name", "sha256Prefix"), "a source")
        text(row["name"], "a source's name")
        need(type(row["sha256Prefix"]) is str and PREFIX.match(row["sha256Prefix"]), "a source's sha256Prefix")
    for row in record["clauses"]:
        closed(row, ("id", "family", "text"), "a clause")
        text(row["text"], "a clause's text")
    for family in record["ruleFamilies"]:
        closed(family, FAMILY, "a rule family")
    closed(record["c30Tests"], ("file", "cases", "listedWithoutCase"), "c30Tests")
    for row in record["settlements"]:
        closed(row, ("id", "text"), "a settlement")
    text_list(record["outOfScope"], "outOfScope")
    closed(status, STATUS_TOP, "the status record")
    need(status["schemaVersion"] == STATUS_VERSION and status["item"] == record["item"]
         and status["packet"] == record["packet"] and status["status"] == "PUBLISHED"
         and status["recordSchema"] == model.SCHEMA_NAME, "the status record names this item")
    text_list(status["consumers"], "consumers")
    text_list(status["producers"], "producers")
    closed(vectors, ("schemaVersion", "cases"), "the vectors file")
    need(vectors["schemaVersion"] == VECTORS_VERSION, "the vectors' schemaVersion is " + VECTORS_VERSION)
    need(type(vectors["cases"]) is list and vectors["cases"], "cases is a non-empty list")
    for case in vectors["cases"]:
        closed(case, CASE, "a vector")
        text(case["id"], "a vector's id")
        need(case["kind"] in ("RECORD", "LIFT"), "vector %s's kind is RECORD or LIFT" % case["id"])
        need(type(case["input"]) is dict and type(case["expect"]) is dict, "vector %s's input and expect" % case["id"])
        if case["kind"] == "LIFT":
            closed(case["input"], LIFT_INPUT, "vector %s's input" % case["id"])
        need(case["expect"].get("result") in model.RESULTS, "vector %s's expected result" % case["id"])


def check(read):
    """The refusals of the contract at read, as (code, message) pairs in the codes' order; [] when it passes."""
    try:
        record = parse_json(read(RECORD_PATH))
        vectors = parse_json(read(VECTORS_PATH))
        status = parse_json(read(STATUS_PATH))
        check_shape(record, vectors, status)
    except Exception as exc:  # a malformed file stops at its shape
        return [("DR_SHAPE", str(exc))]
    cases = {c["id"]: c for c in vectors["cases"]}

    def envelope():
        need(record["kinds"] == list(model.KINDS), "the kinds are the model's")
        need(record["decisions"] == {k: list(model.DECISIONS[k]) for k in model.KINDS}, "the decision sets")
        need(record["unorderedKinds"] == list(model.UNORDERED), "APPROVAL has no order")
        need(record["failClosed"] == dict(model.FAIL_CLOSED), "the fail-closed values")
        need(all(record["failClosed"][k] not in model.PERMITTING for k in model.KINDS), "no fail-closed value permits")
        need(record["errorCodes"] == {"beforeSelection": list(model.ERRORS_BEFORE_SELECTION),
                                      "duringEvaluation": list(model.ERRORS_DURING_EVALUATION)}, "the error codes")
        need(record["reasonCodes"] == {k: list(model.REASON_CODES[k]) for k in model.KINDS}, "the reason codes")
        need(not [c for k in model.KINDS for c in model.REASON_CODES[k] if c.startswith("ERR_")], "ERR_ is reserved")
        need(record["checkOrder"] == list(model.CHECK_ORDER) and record["consumerRule"] == model.LIFT_REFUSED,
             "the check order and the consumer rule")
        approval = parse_json(read(APPROVAL_PATH))
        need(record["approvalOutcome"]["sha256"] == digest(read(APPROVAL_PATH)), "HR-APPROVAL's record digest")
        need(set(approval["outcomes"]) == set(model.DECISIONS["APPROVAL"]), "the APPROVAL set is HR-APPROVAL's")
        need(record["approvalFields"] == approval["rowFields"], "the approval fields are HR-APPROVAL's row fields")

    def lift_rule():
        ids = [row["id"] for row in record["clauses"]]
        need(sorted(ids) == sorted(i for f in CLAUSE_IDS for i in CLAUSE_IDS[f]), "the clauses, each once")
        need(all(row["id"] in CLAUSE_IDS.get(row["family"], ()) for row in record["clauses"]), "each in its family")
        l5 = [row["text"] for row in record["clauses"] if row["id"] == "L5"][0]
        need(all(s in l5 for s in L5_SENTENCES), "L5 carries E1's two sentences")
        families = record["ruleFamilies"]
        need([f["id"] for f in families] == ["E", "L"], "the rule families are E and L")
        need(families[0]["codes"] == list(model.CHECK_ORDER) and families[1]["codes"] == [model.LIFT_REFUSED],
             "the families' codes")
        for family in families:
            need(family["clauses"] == [row["id"] for row in record["clauses"] if row["family"] == family["id"]],
                 family["id"] + "'s clauses are its own")
        need(sorted(v for f in families for v in f["vectors"]) == sorted(cases), "every vector in one family")
        need(all(cases[v]["kind"] == ("RECORD" if f["id"] == "E" else "LIFT") for f in families for v in f["vectors"]),
             "E lists the RECORD cases, L the LIFT cases")

    def codes():
        per = record["vectorPerCode"]
        need(set(per) == set(model.CODES), "one entry per refusal code")
        for code, vids in per.items():
            need(vids and all(v in cases and cases[v]["expect"] == {"result": "REFUSED", "code": code} for v in vids),
                 "the vectors of %s refuse with it" % code)
        need(sorted(record["r2Results"]) == sorted(R2_RESULT_IDS), "N1, N8, N9 and N10 keep r2's results")
        need(not set(R2_RESULT_IDS) & {v for vids in per.values() for v in vids}, "r2's four are not per-code vectors")
        need(record["c30Tests"]["cases"] == list(C30_TESTS) and record["c30Tests"]["listedWithoutCase"] == ["Revoke"],
             "the seven C30 test cases")

    def vector():
        for key, path in (("schema", SCHEMA_PATH), ("vectors", VECTORS_PATH), ("statusRecord", STATUS_PATH),
                          ("model", MODEL_PATH)):
            need(record[key]["sha256"] == digest(read(path)), "the %s's digest" % key)
        found = {(a or b).decode("ascii").split(".")[0] for a, b in IMPORT_LINE.findall(read(MODEL_PATH))}
        need(found == MODEL_IMPORTS, "the model imports %s only" % ", ".join(sorted(MODEL_IMPORTS)))
        need(len(cases) == len(vectors["cases"]), "a vector id twice")
        need(sorted(cases) == sorted(POSITIVES + NEGATIVES), "the vectors are P1-P8 and N1-N14 with their sub-cases")
        for case in vectors["cases"]:
            ok, got = model.replay(case)
            need(ok, "vector %s replays to %r" % (case["id"], got))
        first, second = (cases[v]["input"] for v in record["chainedPair"])
        need(second["supersedes"] == model.digest(first)
             and second["transform"]["valueBeforeDigest"] == first["transform"]["valueAfterDigest"], "P8b chains on P8a")
        refused = {c["expect"].get("code") for c in vectors["cases"] if c["expect"]["result"] == "REFUSED"}
        need(refused == set(model.CODES), "every refusal code is reached")

    refusals = []
    for code, run in (("DR_ENVELOPE", envelope), ("DR_LIFT", lift_rule), ("DR_CODES", codes), ("DR_VECTOR", vector)):
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
        print("DECISION RECORD REFUSED: %d" % len(refusals))
        return 1
    record, vectors = parse_json(read(RECORD_PATH)), parse_json(read(VECTORS_PATH))
    kinds = [c["kind"] for c in vectors["cases"]]
    print("DECISION RECORD OK: %d rule families, %d clauses, %d vectors (%d RECORD, %d LIFT), %d refusal codes" % (
        len(record["ruleFamilies"]), len(record["clauses"]), len(kinds), kinds.count("RECORD"), kinds.count("LIFT"),
        len(record["vectorPerCode"])))
    return 0


if __name__ == "__main__":
    sys.exit(main())
