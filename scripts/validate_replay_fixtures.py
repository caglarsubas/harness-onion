#!/usr/bin/env python3
"""Replay fixtures (architecture/replay-fixtures/record.json, HR-REPLAY-FIXTURES-001, MET-013): the checker.

check(read) validates the record, the stored worked example and the vectors through an injected byte reader (exact
paths only, no listing: the record names every stored file) and returns its refusals as (code, message) pairs, in the
order the codes run:
- RF_SHAPE: the record and the vectors file, closed to their exact members; the shapes, the refusal order, the verdicts,
  the exit-code and blocker-code lists equal the model's; the rule families in their fixed order; every store path
  under the record's folder, and every blob named by its own sha256.
- RF_BASIS: the schema's, the vectors file's, the model's and every stored file's digests; MAS-RA-002's README, two
  schemas, status record (workItem MAS-RA-002) and scripts/run_manifest.py by digest; the model's lock names,
  partitions and score bound equal MAS-RA-002's.
- RF_STORE: the split passes MAS-RA-002's check_split; each stored fixture passes the model as a public DEVELOPMENT
  fixture, names a stored recorded trajectory that passes the model (its manifest through MAS-RA-002's model), and is
  byte-equal in canonical form to its pinned generator's rebuild (the model's build_fixture, its digest the model
  file's); the recording run's fixture lock follows the record's rule; the vectors' stores hold the stored documents.
- RF_VECTOR: every vector is listed by exactly one family, its own; each family's refusals are its codes, and it has a
  positive and a negative vector; every vector replays through the model to its expectation; every record refusal code and every verdict is reached by a vector.
Standard library plus the reference model (scripts/replay_fixtures.py) and MAS-RA-002's model (scripts/run_manifest.py).
main() reads through the checker's own disk_reader. Data checks only; it enforces nothing.
"""
from __future__ import annotations

import hashlib
import json
import re
import stat
import sys
from pathlib import Path

try:
    import replay_fixtures as model
    import run_manifest as rm
except ImportError:
    from scripts import replay_fixtures as model
    from scripts import run_manifest as rm

ROOT = Path(__file__).resolve().parents[1]
DIR = "architecture/replay-fixtures/"
RECORD_PATH = DIR + "record.json"
SCHEMA_PATH = DIR + "schema.json"
VECTORS_PATH = DIR + "vectors.json"
MODEL_PATH = "scripts/replay_fixtures.py"
SCHEMA_VERSION = "harness.planeon.ai/replay-fixtures/v1"
VECTORS_VERSION = "harness.planeon.ai/replay-fixtures-vectors/v1"
BASIS = {"readme": "architecture/run-manifest/README.md",
         "manifestSchema": "architecture/run-manifest/run-manifest.schema.json",
         "recordSchema": "architecture/run-manifest/evaluation-record.schema.json",
         "status": "architecture/run-manifest/status.json",
         "model": "scripts/run_manifest.py"}
CODES = ("RF_SHAPE", "RF_BASIS", "RF_STORE", "RF_VECTOR")
TOP = ("schemaVersion", "item", "packet", "status", "schema", "vectors", "model", "basis", "shapes", "refusalOrder",
       "verdicts", "exitCodes", "blockerCodes", "outcomeMap", "fixtureLockRule", "store", "ruleFamilies", "settlements",
       "outOfScope")
FAMILIES = ("TREE", "FIXTURE", "PLACEMENT", "TRAJECTORY", "REPLAY", "VERDICT", "SCORE", "BINDING", "BLOCKED",
            "REGENERATION", "ARMS", "DENOM")
CHECKS = ("FIXTURE", "TRAJECTORY", "SCORE", "REGENERATION", "REPLAY", "VERDICT", "ARM_PAIR", "EVALUATION")
STORES = ("blobs", "splits", "manifests", "fixtures", "trajectories")
CASE = ("id", "family", "check", "polarity", "title", "input", "expect")
HEX = re.compile(r"[0-9a-f]{64}\Z")
MAX_BYTES = 16_777_216


class Refused(Exception):
    pass


def need(ok, message):
    if not ok:
        raise Refused(message)


def sha(raw: bytes) -> str:
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


def text_list(value, where, empty=False):
    need(type(value) is list and (empty or value) and all(type(v) is str and v for v in value),
         where + " is a list of non-empty strings")


def pinned(value, where, path=None, prefix=None):
    closed(value, ("path", "sha256"), where)
    need(type(value["sha256"]) is str and HEX.match(value["sha256"]), where + ".sha256 is a hex digest")
    need(type(value["path"]) is str and (value["path"] == path if path else value["path"].startswith(prefix)),
         "%s.path is %s" % (where, path or prefix + "..."))


def store_paths(record):
    store = record["store"]
    return [store["split"]] + store["fixtures"] + store["trajectories"] + store["blobs"]


def check_shape(record, vectors):
    closed(record, TOP, "the record")
    need(record["schemaVersion"] == SCHEMA_VERSION, "schemaVersion is " + SCHEMA_VERSION)
    need(record["item"] == "HR-REPLAY-FIXTURES-001" and record["packet"] == "MET-013", "item and packet")
    text(record["status"], "status")
    pinned(record["schema"], "schema", SCHEMA_PATH)
    pinned(record["vectors"], "vectors", VECTORS_PATH)
    pinned(record["model"], "model", MODEL_PATH)
    closed(record["basis"], tuple(BASIS), "basis")
    for key, path in BASIS.items():
        pinned(record["basis"][key], "basis." + key, path)
    need(record["shapes"] == list(model.SHAPES), "the shapes are the model's five")
    need(record["refusalOrder"] == ["MAS-RA-002"] + list(model.RECORD_CODES), "the refusal order is the model's")
    need(record["verdicts"] == list(model.VERDICTS), "the verdicts are the model's")
    need(record["exitCodes"] == {s: list(c) for s, c in model.EXIT_CODES.items()}, "the exit-code lists are the model's")
    need(record["blockerCodes"] == list(model.BLOCKER_CODES), "the blocker codes are the model's")
    need(type(record["outcomeMap"]) is list and record["outcomeMap"], "outcomeMap is a non-empty list")
    for row in record["outcomeMap"]:
        closed(row, ("exitStatus", "condition", "outcome", "score"), "an outcome row")
        need(row["exitStatus"] in model.EXIT_CODES and row["outcome"] in model.OUTCOMES, "an outcome row's vocabulary")
        text(row["condition"], "an outcome row's condition")
        text(row["score"], "an outcome row's score")
    text(record["fixtureLockRule"], "fixtureLockRule")
    closed(record["store"], ("split", "fixtures", "trajectories", "blobs"), "store")
    pinned(record["store"]["split"], "store.split", prefix=DIR + "fixtures/")
    for key, prefix in (("fixtures", DIR + "fixtures/"), ("trajectories", DIR + "fixtures/"), ("blobs", DIR + "blobs/")):
        need(type(record["store"][key]) is list and record["store"][key], "store.%s is a non-empty list" % key)
        for row in record["store"][key]:
            pinned(row, "store." + key, prefix=prefix)
    for row in record["store"]["blobs"]:
        need(row["path"] == DIR + "blobs/" + row["sha256"], "a blob is named by its own sha256: " + row["path"])
    paths = [p["path"] for p in store_paths(record)]
    need(len(paths) == len(set(paths)), "a store path twice")
    families = record["ruleFamilies"]
    need(type(families) is list and [f.get("id") if type(f) is dict else None for f in families] == list(FAMILIES),
         "the rule families are %s in order" % ", ".join(FAMILIES))
    for family in families:
        where = "ruleFamily " + family["id"]
        closed(family, ("id", "name", "property", "source", "codes", "vectors"), where)
        for key in ("name", "property", "source"):
            text(family[key], "%s.%s" % (where, key))
        text_list(family["codes"], where + ".codes", empty=True)
        text_list(family["vectors"], where + ".vectors")
    need(type(record["settlements"]) is list and record["settlements"], "settlements is a non-empty list")
    for row in record["settlements"]:
        closed(row, ("id", "text"), "a settlement")
        text(row["id"], "a settlement's id")
        text(row["text"], "a settlement's text")
    text_list(record["outOfScope"], "outOfScope")
    closed(vectors, ("schemaVersion", "stores", "cases"), "the vectors file")
    need(vectors["schemaVersion"] == VECTORS_VERSION, "the vectors' schemaVersion is " + VECTORS_VERSION)
    closed(vectors["stores"], STORES, "the vectors' stores")
    need(all(type(vectors["stores"][k]) is dict for k in STORES), "every store is an object")
    need(type(vectors["cases"]) is list and vectors["cases"], "cases is a non-empty list")
    for case in vectors["cases"]:
        closed(case, CASE, "a vector")
        text(case["id"], "a vector's id")
        where = "vector " + case["id"]
        need(case["family"] in FAMILIES and case["check"] in CHECKS, where + "'s family and check")
        need(case["polarity"] in ("POSITIVE", "NEGATIVE"), where + ".polarity")
        text(case["title"], where + ".title")
        need(type(case["input"]) is dict, where + ".input is an object")
        expect = case["expect"]
        if case["polarity"] == "POSITIVE":
            need(type(expect) is dict and expect.get("accept") is True and set(expect) <= {"accept", "result"}
                 and type(expect.get("result", {})) is dict, where + ".expect is an acceptance")
        else:
            closed(expect, ("refuse",), where + ".expect")
            text(expect["refuse"], where + ".expect.refuse")


def check(read):
    """The refusals of the record at read, as (code, message) pairs in the codes' order; [] when it passes."""
    try:
        record = parse_json(read(RECORD_PATH))
        vectors = parse_json(read(VECTORS_PATH))
        check_shape(record, vectors)
    except Exception as exc:  # a malformed record or vectors file stops at its shape
        return [("RF_SHAPE", str(exc))]

    def basis():
        for key, path in (("schema", SCHEMA_PATH), ("vectors", VECTORS_PATH), ("model", MODEL_PATH)):
            need(record[key]["sha256"] == sha(read(path)), "the %s's digest" % key)
        for key, path in BASIS.items():
            need(record["basis"][key]["sha256"] == sha(read(path)), "the base %s's digest" % key)
        for row in store_paths(record):
            need(row["sha256"] == sha(read(row["path"])), "the stored file's digest: " + row["path"])
        need(parse_json(read(BASIS["status"])).get("workItem") == "MAS-RA-002", "the base status record is MAS-RA-002's")
        need(model.LOCK_NAMES == rm.LOCK_KEYS and model.PARTITIONS == rm.PARTITIONS and model.MAX_SCORE == rm.MAX_SCORE,
             "the model's lock names, partitions and score bound are MAS-RA-002's")

    def store():
        blobs = {"sha256:" + row["sha256"]: read(row["path"]) for row in record["store"]["blobs"]}
        split = parse_json(read(record["store"]["split"]["path"]))
        facts = rm.check_split(split)
        splits = {facts["digest"]: split}
        trajectories = [parse_json(read(row["path"])) for row in record["store"]["trajectories"]]
        by_digest = {model.digest(t): t for t in trajectories}
        fixtures = [parse_json(read(row["path"])) for row in record["store"]["fixtures"]]
        generator = {"id": model.GENERATOR_ID, "version": model.GENERATOR_VERSION,
                     "digest": model.bytes_digest(read(MODEL_PATH))}
        for t in trajectories:
            model.check_trajectory(t, blobs, splits, rm)
        for fx in fixtures:
            model.check_fixture(fx, blobs, public=True)
            need(fx["split"]["partition"] == "DEVELOPMENT", "a stored fixture is DEVELOPMENT: " + fx["fixtureId"])
            t = by_digest.get(fx["trajectoryDigest"])
            need(t is not None and t["taskId"] == fx["taskId"], "a fixture names its stored recorded trajectory")
            need(fx["generator"] == generator, "a fixture's generator is the model's build_fixture: " + fx["fixtureId"])
            task = {k: fx[k] for k in ("suiteDigest", "taskId", "taskDigest", "split")}
            rebuilt = model.build_fixture(fx["fixtureId"], task, fx["workspaceBefore"], t, blobs, generator["digest"],
                                          fx["requestMatch"], fx.get("requestMatchReason"))
            need(model.canonical(rebuilt) == model.canonical(fx), "the stored fixture is its generator's rebuild: "
                 + fx["fixtureId"])
        befores = {fx["taskId"]: model.digest(fx["workspaceBefore"]) for fx in fixtures}
        for t in trajectories:
            tasks = [x["taskId"] for x in split["partitions"][t["manifest"]["split"]["partition"]]]
            need(all(x in befores for x in tasks)
                 and t["manifest"]["locks"]["fixtureDigest"] == model.digest(sorted(befores[x] for x in tasks)),
                 "the recording run's fixture lock follows fixtureLockRule")
        need(len({model.digest(t["manifest"]) for t in trajectories}) == 1, "the recorded trajectories embed one manifest")
        st = vectors["stores"]
        need(st["splits"].get(facts["digest"]) == split, "the vectors' stores hold the stored split")
        need(all(st["fixtures"].get(model.digest(fx)) == fx for fx in fixtures), "the vectors' stores hold the fixtures")
        need(all(st["trajectories"].get(d) == t for d, t in by_digest.items()), "the vectors' stores hold the trajectories")
        need(all(st["blobs"].get(d, "").encode("utf-8") == raw for d, raw in blobs.items()), "the vectors' stores hold "
             "the blobs")
        need(all(type(v) is str and model.bytes_digest(v.encode("utf-8")) == k for k, v in st["blobs"].items()),
             "every vector blob is named by its bytesDigest")

    def vector():
        cases = {c["id"]: c for c in vectors["cases"]}
        need(len(cases) == len(vectors["cases"]), "a vector id twice")
        listed = [(f["id"], v) for f in record["ruleFamilies"] for v in f["vectors"]]
        need(sorted(v for _, v in listed) == sorted(cases), "every vector is listed by exactly one family")
        for family, vid in listed:
            need(cases[vid]["family"] == family, "vector %s is listed by %s, not its family" % (vid, family))
        reached, verdicts = set(), set()
        for family in record["ruleFamilies"]:
            refused = {cases[v]["expect"]["refuse"] for v in family["vectors"] if cases[v]["polarity"] == "NEGATIVE"}
            need(refused == set(family["codes"]), "%s's refusals are its codes" % family["id"])
            need({cases[v]["polarity"] for v in family["vectors"]} == {"POSITIVE", "NEGATIVE"},
                 family["id"] + " has a positive and a negative vector")
            reached |= refused
        for case in vectors["cases"]:
            ok, got = model.replay_case(case, vectors["stores"], rm)
            need(ok, "vector %s replays to %r" % (case["id"], got))
            if case["check"] == "REPLAY" and type(got) is dict:
                verdicts.add(got["verdict"])
        need(set(model.RECORD_CODES) <= reached, "every record refusal code is reached by a vector")
        need(verdicts == set(model.VERDICTS), "every verdict is reached by a vector")

    refusals = []
    for code, run in (("RF_BASIS", basis), ("RF_STORE", store), ("RF_VECTOR", vector)):
        try:
            run()
        except Exception as exc:
            refusals.append((code, "%s: %s" % (type(exc).__name__, exc)))
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
        print("REPLAY FIXTURES REFUSED: %d" % len(refusals))
        return 1
    record, vectors = parse_json(read(RECORD_PATH)), parse_json(read(VECTORS_PATH))
    polarity = [c["polarity"] for c in vectors["cases"]]
    print("REPLAY FIXTURES OK: %d rule families, %d stored files, %d vectors (%d positive, %d negative)" % (
        len(record["ruleFamilies"]), len(store_paths(record)), len(polarity), polarity.count("POSITIVE"),
        polarity.count("NEGATIVE")))
    return 0


if __name__ == "__main__":
    sys.exit(main())
