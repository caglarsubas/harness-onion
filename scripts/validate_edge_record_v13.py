#!/usr/bin/env python3
"""Operator edge record v13 (EDGE-V13, MET-014): the member checker for the no-receipt TERMINAL amendment.

check(read) checks edge record v13 (architecture/artifact-edges/operator-harness-engineering-v13.json), its README, the
broker handoff v2 inputs (architecture/broker-handoff-inputs-v2/) and the transcript model v2
(scripts/broker_handoff_transcript_v2.py) through an injected byte reader (exact paths only, no listing), and returns its
refusals as (code, message) pairs, in the order the codes run: edge record v12's V1-V5 pattern for a member, then the
row check and the hunk checks.
- EV_V1: the files: each file below reads through the reader and parses; the base files are the pinned ones (edge
  record v12, the v1 schema and vectors, each by the sha256 of its bytes at main); every JSON file is in the
  repository's form (indent 2, a final newline). ERR-5 (ORC-296-Q-C2-1 (a)): the chain cascade rewrites two lines of
  each of the v1 model scripts/validate_broker_handoff.py and scripts/validate_proxy_contract.py every step, so they
  are pinned by the source segments the models execute (v1's validate_transcript, ZERO, COMMON, require and _shape;
  the proxy contract's canonical, digest, parse and _bounded), each by its sha256 at main; and their hunks are
  cascade-only: every other line is main's, the cascade lines hold main's packet names then the appended ones and
  the count main's plus the appended, the same packets appended in both.
- EV_V2: the model accepts the contract: under the v13 schema the v2 model accepts the three positives and refuses K (a
  receipt chunk, then a size-0 FAILED TERMINAL, the chain redone), L (the no-receipt vector without its TERMINAL) and M
  (the no-receipt vector with TERMINAL COMPLETED); it accepts M under the v13 schema less its if/then (N: the refusal is
  the schema's, README-v13's X3); and v1's validate_transcript, executed from v1's bytes over the same helpers, accepts
  v1's two positives and refuses positive[2] (the bite).
- EV_V3: the vectors: v1's other keys carried unchanged; positive[0..1] equal v1's two; positive[2] is v1's positive[0]
  without its RECEIPT_CHUNK, re-sequenced, a complete chain from ZERO (each previousDigest the digest of the previous
  frame's canonical bytes), its TERMINAL FAILED with size 0, the empty-bytes digest and the cleanup echo; negative is one
  entry, that TERMINAL with COMPLETED, refused by the v13 schema and only by the size-0 rule (the same frame with FAILED
  or UNAVAILABLE is valid, with a non-empty digest it is refused, size 1 COMPLETED is valid and size -1 is refused).
- EV_V4: the record's carried fields: schemaVersion, graph, consumer, provider, ownerDecision, rules, notArtifacts,
  statuses and ownerDecisions equal v12's; artifact is broker-handoff-v2; the notes; README-v13 carries X3's two
  statements and the design's obligation.
- EV_V5: the open items: supersedes binds v12 by its packet, path and sha256, and v12 is the record that supersedes v11;
  the first note states v12's parsed row count.
- EV_ROWS: v13's first rows are v12's, unchanged and in order, and exactly two follow, one per new provider file, in v12's
  row key set with providerPacket (no key added), each binding its file's bytes by sha256 alone.
- EV_HUNKS: the v13 schema is v1's with exactly the two hunks in $defs.frame.oneOf[5] (TERMINAL); the model's
  validate_transcript is v1's function source with one clause changed (`payload and` dropped from "cleanup order"), by
  AST; require, _shape, ZERO and COMMON equal v1's by AST; the model's top level is exactly these and its imports are
  base64, jsonschema, and canonical, digest, parse and _bounded from validate_proxy_contract (bare, then scripts.).
Needs the repository's pinned jsonschema and the v2 model. main() reads through the checker's own disk_reader. Data
checks only; it enforces nothing.
"""
from __future__ import annotations

import ast
import copy
import hashlib
import json
import re
import stat
import sys
from pathlib import Path

import jsonschema

try:
    import broker_handoff_transcript_v2 as model
except ImportError:
    from scripts import broker_handoff_transcript_v2 as model

ROOT = Path(__file__).resolve().parents[1]
RECORD_PATH = "architecture/artifact-edges/operator-harness-engineering-v13.json"
README_PATH = "architecture/artifact-edges/README-v13.md"
V12_PATH = "architecture/artifact-edges/operator-harness-engineering-v12.json"
V11_PATH = "architecture/artifact-edges/operator-harness-engineering-v11.json"
SCHEMA_PATH = "architecture/broker-handoff-inputs-v2/channel.schema.json"
VECTORS_PATH = "architecture/broker-handoff-inputs-v2/vectors.json"
MODEL_PATH = "scripts/broker_handoff_transcript_v2.py"
SCHEMA_V1_PATH = "architecture/broker-handoff-inputs/channel.schema.json"
VECTORS_V1_PATH = "architecture/broker-handoff-inputs/vectors.json"
MODEL_V1_PATH = "scripts/validate_broker_handoff.py"
PROXY_PATH = "scripts/validate_proxy_contract.py"
PINS = {
    V12_PATH: "3587488b040f1c23f95f847dd3f1e15b97fa6ca705b6dca429d1cc6d64f3a5c7",
    SCHEMA_V1_PATH: "e7e9558fb50b7ba804222065734d1d4fb4694327bb2427a34ef8dffc945d56f9",
    VECTORS_V1_PATH: "80d8da953c41ef544ecf0cd4a0f62b98316b018bfbdc39c550c320f68ab603c4",
}
SEGMENT_PINS = {   # ERR-5 (ORC-296-Q-C2-1 (a)): the source segments the models execute, by sha256 at main 4b1386e0
    MODEL_V1_PATH: {
        "ZERO": "dad1e3856fbb3ee00bf0b3da4d5f8668d3049b7386fbb44e23dc2a51cc0c0d51",
        "COMMON": "27be8495de62c7f129535c75da9dc7f4c0f0bcab25cc593e2ee9d76bce34ce58",
        "require": "570ace48effbcffbb325b4bdc4424b575500114187d28c59c86b8870081e9f76",
        "_shape": "f6f7bf31029a1e75b91a59867e3f66b13695dcbf11b8a58536171a69b5679c48",
        "validate_transcript": "47a5e09f1f8efcfee19bfc6aa7b6763f9c4e553cf90c5c6418e729ef5ef54ccc",
    },
    PROXY_PATH: {
        "canonical": "4f3300703d43af01bca3800a439ddd4a5caa70ebb88eb50909af5690ea3403b2",
        "digest": "aa0210ace4fdb541410909814713738e8261645d1f9f4e166eecc1083c4c42ed",
        "parse": "e43729d8a4875fb836793d87da15d1a89c5d23868790e899b947744e4591a272",
        "_bounded": "308ab2135b84ca0a32cd85633199f905cb21a6b0c1c53a4dc9e6fcca321cab21",
    },
}
CASCADE = {   # ERR-5: the chain cascade's two lines per base script, by form (the catalog's packet names,
    # then the count); every other line is main's (the rest's sha256), main's names lead (their number and
    # sha256), and the count is main's plus the appended names
    MODEL_V1_PATH: (
        (
            r'        require\(len\(old\) == 142 and len\(packets\) == (?P<count>\d+) and set\(packets'
            r'\) == old \| \{(?P<names>"[^"]+"(?:, "[^"]+")*)\}, "exact catalog"\)',
            r'        print\("Broker handoff valid: (?P<count>\d+) packets; 127/327 checkpoint; DATA_C'
            r'HECK_ONLY; product/native NOT_RUN\."\)',
        ),
        "ab3bdae20093d9f25bae5fa2e755016977dd5ec77768691810bc47e2d2b4e7cd",
        319, 177, "807000f512bb4ce1b427fb0d82c75adf36d6d1ac7f4110086bfd2770a07defc8",
    ),
    PROXY_PATH: (
        (
            r'        if len\(old_ids\) != 134 or len\(record\["protectedFiles"\]\) != 176 or set\(pac'
            r'kets\) != old_ids \| set\(ADDITIONS\) \| \{(?P<names>"[^"]+"(?:, "[^"]+")*)\}:',
            r'        print\("Proxy prerequisite valid: (?P<count>\d+) packets; 176 immutable authorit'
            r'y files; 127-file/279-ID source checkpoint; product/native NOT_RUN\."\)',
        ),
        "a69344299a9b8e6ec4d70f4c3262c4d829d65b7aa98b13e487b464f78dca2db8",
        319, 131, "fbe03a80406d855d98712c1ea102d83af028fc8ce90f48abbc97659ff60e19b6",
    ),
}
V12_PACKET = "MET-ENFORCE-043"
PACKET = "MET-014"
ARTIFACT = "broker-handoff-v2"
CONSUMER_PACKET = "HE-005D"
CONSUMER_DIR = "host-enforcement/contracts/broker-handoff-v2/"
NEW_FILES = (SCHEMA_PATH, VECTORS_PATH)
ROW_KEYS = ("providerPath", "providerCommit", "sha256", "mode", "consumerPath", "consumerPacket", "relation", "status",
            "providerPacket")
CARRIED = ("schemaVersion", "graph", "consumer", "provider", "ownerDecision", "rules", "notArtifacts", "statuses",
           "ownerDecisions")
EMPTY = "sha256:" + hashlib.sha256(b"").hexdigest()
TERMINAL_INDEX = 5
IF = {"required": ["receiptSize"], "properties": {"receiptSize": {"const": 0}}}
THEN = {"properties": {"status": {"enum": ["FAILED", "UNAVAILABLE"]}, "receiptDigest": {"const": EMPTY}}}
NEGATIVE_RULE = "receiptSize 0 only with status FAILED or UNAVAILABLE"
OLD_CLAUSE = 'require(pending is None and payload and cleanup is None, "cleanup order")'
NEW_CLAUSE = 'require(pending is None and cleanup is None, "cleanup order")'
COPIED = ("ZERO", "COMMON", "require", "_shape")
MODEL_TOP = COPIED + ("validate_transcript",)
HELPERS = ["canonical", "digest", "parse", "_bounded"]
MODEL_IMPORTS = {"__future__", "base64", "jsonschema", "validate_proxy_contract", "scripts.validate_proxy_contract"}
FIRST_NOTE = "Edge record v12's %d rows are carried unchanged and in order."
README_STATEMENTS = (
    "The `/v1` frame label now covers two schema revisions, v12's and v13's. They are told apart by the digests in the "
    "v12 and v13 rows, not by the label.",
    "The v2 model is valid only with the v13 schema. The model does not refuse a COMPLETED size-0 transcript; the "
    "schema's if/then does.",
    "The DATA model fixes order, not the trigger: the design must not record cleanup on a channel that may still carry "
    "a receipt.",
)
RECORD_INDENT = 1
MAX_BYTES = 16_777_216


class Refused(Exception):
    pass


def need(ok, message):
    if not ok:
        raise Refused(message)


def sha(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def dump(value, indent=2) -> bytes:
    """The repository's JSON form: the inputs' indent 2; the edge records' indent 1 (v12's own form)."""
    return (json.dumps(value, indent=indent, ensure_ascii=False) + "\n").encode("utf-8")


def parse_json(raw):
    need(type(raw) is bytes, "a JSON file is present")

    def pairs(items):
        keys = [k for k, _ in items]
        need(len(keys) == len(set(keys)), "a duplicate member")
        return dict(items)
    return json.loads(raw.decode("utf-8"), object_pairs_hook=pairs,
                      parse_constant=lambda c: (_ for _ in ()).throw(Refused("a non-finite number")))


def chained(frames):
    """frames re-sequenced 1.. and re-chained from ZERO: each previousDigest the digest of the previous frame's
    canonical bytes (validate_proxy_contract's canonical, through the model)."""
    out, previous = [], model.ZERO
    for sequence, frame in enumerate(copy.deepcopy(frames), 1):
        frame["sequence"], frame["previousDigest"] = sequence, previous
        previous = "sha256:" + model.digest(model.canonical(frame))
        out.append(frame)
    return out


def accepted(validate, vector, schema) -> bool:
    """A vector's transcript through a validate_transcript; a raise counts as not accepted (ERR-1)."""
    try:
        return validate(vector["binding"], vector["request"], vector["frames"], schema) == []
    except (ValueError, TypeError, KeyError, RecursionError, jsonschema.ValidationError):
        return False


def frame_valid(frame, schema) -> bool:
    try:
        model._shape(frame, "frame", schema)
        return True
    except jsonschema.ValidationError:
        return False


def no_receipt(v1_first):
    """v1's positive[0] without its RECEIPT_CHUNK, re-chained, its TERMINAL FAILED with size 0 and the empty digest."""
    vector = copy.deepcopy(v1_first)
    frames = [f for f in vector["frames"] if f["kind"] != "RECEIPT_CHUNK"]
    frames[-1]["payload"].update({"status": "FAILED", "receiptSize": 0, "receiptDigest": EMPTY})
    vector["frames"] = chained(frames)
    return vector


def expected_rows(read):
    return [{"providerPath": path, "providerCommit": None, "sha256": sha(read(path)), "mode": "100644",
             "consumerPath": CONSUMER_DIR + path.rsplit("/", 1)[1], "consumerPacket": CONSUMER_PACKET,
             "relation": "BYTE_IDENTICAL", "status": "REGISTERED_BEFORE_USE", "providerPacket": PACKET}
            for path in NEW_FILES]


def amended(schema_v1):
    """v1's schema with the two hunks applied in $defs.frame.oneOf[5] (TERMINAL)."""
    schema = copy.deepcopy(schema_v1)
    terminal = schema["$defs"]["frame"]["oneOf"][TERMINAL_INDEX]
    need(terminal["properties"]["kind"].get("const") == "TERMINAL", "oneOf[5] is TERMINAL in v1")
    payload = terminal["properties"]["payload"]
    need(payload["properties"]["receiptSize"]["minimum"] == 1 and "if" not in payload and "then" not in payload,
         "v1's TERMINAL payload has minimum 1 and no if/then")
    payload["properties"]["receiptSize"]["minimum"] = 0
    payload["if"], payload["then"] = copy.deepcopy(IF), copy.deepcopy(THEN)
    return schema


def top_level(tree):
    """The module's top-level defs and single-name assignments, by name."""
    out = {}
    for node in tree.body:
        if isinstance(node, ast.FunctionDef):
            out[node.name] = node
        elif isinstance(node, ast.Assign) and len(node.targets) == 1 and isinstance(node.targets[0], ast.Name):
            out[node.targets[0].id] = node
    return out


def check(read):
    """The refusals of the member at read, as (code, message) pairs in the codes' order; [] when it passes."""
    refusals = []
    try:
        raw = {path: read(path) for path in (RECORD_PATH, README_PATH, SCHEMA_PATH, VECTORS_PATH, MODEL_PATH, V12_PATH,
                                             SCHEMA_V1_PATH, VECTORS_V1_PATH, MODEL_V1_PATH, PROXY_PATH)}
        record, v12 = parse_json(raw[RECORD_PATH]), parse_json(raw[V12_PATH])
        schema, schema_v1 = parse_json(raw[SCHEMA_PATH]), parse_json(raw[SCHEMA_V1_PATH])
        vectors, vectors_v1 = parse_json(raw[VECTORS_PATH]), parse_json(raw[VECTORS_V1_PATH])
        readme = raw[README_PATH].decode("utf-8")
        source, source_v1 = raw[MODEL_PATH].decode("utf-8"), raw[MODEL_V1_PATH].decode("utf-8")
        tree, tree_v1 = ast.parse(source), ast.parse(source_v1)
        need(type(record) is dict and type(v12) is dict and type(vectors) is dict and type(vectors_v1) is dict
             and type(schema) is dict and type(schema_v1) is dict, "every JSON file is an object")
    except Exception as exc:  # a missing or malformed file stops at its read
        return [("EV_V1", str(exc))]
    positives_v1 = vectors_v1.get("positive")

    def v1_files():
        for path, pin in PINS.items():
            need(sha(raw[path]) == pin, "%s is the pinned base file" % path)
        for path, pins in SEGMENT_PINS.items():   # ERR-5: the executed helpers are main's, by source segment
            text = raw[path].decode("utf-8")
            nodes = top_level(ast.parse(text))
            for name, pin in pins.items():
                need(name in nodes and sha(ast.get_source_segment(text, nodes[name]).encode("utf-8")) == pin,
                     "%s: %s is main's source segment" % (path, name))
        appended = []
        for path, (forms, rest_pin, count, names_n, names_pin) in CASCADE.items():   # ERR-5: cascade-only hunks
            lines = raw[path].decode("utf-8").splitlines(keepends=True)
            hits = [[m for m in (re.fullmatch(form, line.rstrip("\n")) for line in lines) if m] for form in forms]
            need(all(len(h) == 1 for h in hits), "%s: each cascade line once" % path)
            rest = "".join(line for line in lines if not any(re.fullmatch(f, line.rstrip("\n")) for f in forms))
            need(sha(rest.encode("utf-8")) == rest_pin, "%s: every line but the cascade's is main's" % path)
            names = re.findall(r'"([^"]+)"', hits[0][0]["names"])
            counts = {int(h[0]["count"]) for h in hits if "count" in h[0].groupdict()}
            need(len(names) >= names_n and sha(json.dumps(names[:names_n]).encode("utf-8")) == names_pin
                 and counts == {count + len(names) - names_n},
                 "%s: the cascade lines hold main's packets, then the appended ones, and their count" % path)
            appended.append(names[names_n:])
        need(appended[0] == appended[1], "the two base scripts append the same packets")
        for path, indent in ((RECORD_PATH, RECORD_INDENT), (V12_PATH, RECORD_INDENT), (SCHEMA_PATH, 2),
                             (VECTORS_PATH, 2)):
            need(raw[path] == dump(parse_json(raw[path]), indent), "%s is in the repository's JSON form" % path)

    def v2_model():
        positives = vectors["positive"]
        need(type(positives) is list and len(positives) == 3, "three positives")
        need(all(accepted(model.validate_transcript, v, schema) for v in positives),
             "the v2 model accepts every positive under the v13 schema")
        k = copy.deepcopy(positives_v1[0])
        k["frames"][-1]["payload"].update({"status": "FAILED", "receiptSize": 0, "receiptDigest": EMPTY})
        k["frames"] = chained(k["frames"])
        l_case = copy.deepcopy(positives[2])
        l_case["frames"] = l_case["frames"][:-1]
        m = copy.deepcopy(positives[2])
        m["frames"][-1]["payload"]["status"] = "COMPLETED"
        for name, case in (("K", k), ("L", l_case), ("M", m)):
            need(not accepted(model.validate_transcript, case, schema), "the v2 model refuses case %s" % name)
        bare = copy.deepcopy(schema)
        payload = bare["$defs"]["frame"]["oneOf"][TERMINAL_INDEX]["properties"]["payload"]
        payload.pop("if"), payload.pop("then")
        need(accepted(model.validate_transcript, m, bare), "case N: M is accepted without the if/then")
        node = top_level(tree_v1)["validate_transcript"]
        namespace = dict(vars(model))
        exec(compile(ast.Module(body=[node], type_ignores=[]), MODEL_V1_PATH, "exec", dont_inherit=True), namespace)
        v1_validate = namespace["validate_transcript"]
        need(all(accepted(v1_validate, v, schema) for v in positives[:2]), "v1's model accepts v1's two positives")
        need(not accepted(v1_validate, positives[2], schema), "v1's model refuses positive[2] (the bite)")

    def v3_vectors():
        need(list(vectors) == list(vectors_v1) + ["negative"], "v1's keys, then negative")
        need(all(vectors[k] == vectors_v1[k] for k in vectors_v1 if k != "positive"), "v1's other keys unchanged")
        need(type(positives_v1) is list and len(positives_v1) == 2 and vectors["positive"][:2] == positives_v1,
             "positive[0..1] are v1's two")
        for vector in positives_v1:
            need(vector["frames"] == chained(vector["frames"]), "v1's positives follow the chain recipe")
        third = vectors["positive"][2]
        need(third == no_receipt(positives_v1[0]), "positive[2] is the no-receipt vector")
        kinds = [f["kind"] for f in third["frames"]]
        need(kinds == ["STARTED", "CLEANUP_RECORDED", "TERMINAL"], "positive[2]'s frames")
        need(third["frames"][-1]["payload"]["cleanupDigest"] == third["frames"][1]["payload"]["cleanupDigest"],
             "the cleanup echo")
        bad = copy.deepcopy(third["frames"][-1])
        bad["payload"]["status"] = "COMPLETED"
        need(vectors["negative"] == [{"frame": bad, "refusedBy": "channel.schema.json", "rule": NEGATIVE_RULE}],
             "one negative: the no-receipt TERMINAL with COMPLETED")
        need(not frame_valid(bad, schema), "the negative is refused by the v13 schema")
        for status in ("FAILED", "UNAVAILABLE"):
            ok = copy.deepcopy(bad)
            ok["payload"]["status"] = status
            need(frame_valid(ok, schema), "size 0 with %s is valid" % status)
            digest_set = copy.deepcopy(ok)
            digest_set["payload"]["receiptDigest"] = "sha256:" + sha(b"x")
            need(not frame_valid(digest_set, schema), "size 0 with %s and a non-empty digest is refused" % status)
        one = copy.deepcopy(bad)
        one["payload"].update({"receiptSize": 1, "receiptDigest": "sha256:" + sha(b"x")})
        need(frame_valid(one, schema), "size 1 COMPLETED is valid")
        minus = copy.deepcopy(ok)
        minus["payload"]["receiptSize"] = -1
        need(not frame_valid(minus, schema), "size -1 is refused")

    def v4_record():
        need(list(record) == list(v12), "v12's top-level keys, in order (no key added)")
        need(all(record[k] == v12[k] for k in CARRIED), "the carried fields are v12's")
        need(record["artifact"] == ARTIFACT, "artifact is " + ARTIFACT)
        need(type(record["notes"]) is list and len(record["notes"]) == 4
             and all(type(n) is str and n for n in record["notes"]), "four notes")
        for statement in README_STATEMENTS:
            need(statement in " ".join(readme.split()), "README-v13 states: " + statement[:60])

    def v5_open_items():
        need(record["supersedes"] == {"path": V12_PATH, "sha256": "sha256:" + PINS[V12_PATH], "packet": V12_PACKET},
             "supersedes binds v12")
        need(v12["supersedes"]["path"] == V11_PATH, "v12 supersedes v11")
        need(record["notes"][0] == FIRST_NOTE % len(v12["artifacts"]), "the first note states v12's row count")

    def rows():
        old = v12["artifacts"]
        need(type(old) is list and old and record["artifacts"][:len(old)] == old, "v13's first rows are v12's, in order")
        new = record["artifacts"][len(old):]
        need(len(new) == len(NEW_FILES), "one new row per new provider file")
        need(all(list(row) == list(ROW_KEYS) for row in new), "the new rows have v12's key set with providerPacket")
        need(new == expected_rows(read), "each new row binds its file's bytes by sha256")

    def hunks():
        need(raw[SCHEMA_PATH] == dump(amended(schema_v1)), "the v13 schema is v1's with exactly the two hunks")
        mine, v1 = top_level(tree), top_level(tree_v1)
        need(set(mine) == set(MODEL_TOP), "the model's top level is " + ", ".join(MODEL_TOP))
        for name in COPIED:
            need(ast.dump(mine[name]) == ast.dump(v1[name]), name + " is v1's, by AST")
        text = ast.get_source_segment(source_v1, v1["validate_transcript"])
        need(text.count(OLD_CLAUSE) == 1, "v1's cleanup-order clause, once")
        relaxed = ast.parse(text.replace(OLD_CLAUSE, NEW_CLAUSE)).body[0]
        need(ast.dump(mine["validate_transcript"]) == ast.dump(relaxed), "validate_transcript is v1's less one clause")
        found = {}
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    found.setdefault(alias.name, []).append(None)
            elif isinstance(node, ast.ImportFrom):
                need(node.level == 0, "no relative import")
                found.setdefault(node.module, []).append([a.name for a in node.names])
        need(set(found) == MODEL_IMPORTS, "the model imports " + ", ".join(sorted(MODEL_IMPORTS)))
        need(found["validate_proxy_contract"] == [HELPERS] and found["scripts.validate_proxy_contract"] == [HELPERS],
             "the helpers come from validate_proxy_contract")
        for node in tree.body:
            need(isinstance(node, (ast.Import, ast.ImportFrom, ast.Try, ast.FunctionDef, ast.Assign))
                 or (isinstance(node, ast.Expr) and isinstance(node.value, ast.Constant)), "a plain module body")

    for code, run in (("EV_V1", v1_files), ("EV_V2", v2_model), ("EV_V3", v3_vectors), ("EV_V4", v4_record),
                      ("EV_V5", v5_open_items), ("EV_ROWS", rows), ("EV_HUNKS", hunks)):
        try:
            run()
        except Exception as exc:
            refusals.append((code, str(exc) or type(exc).__name__))
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
        print("EDGE RECORD V13 REFUSED: %d" % len(refusals))
        return 1
    record, vectors = parse_json(read(RECORD_PATH)), parse_json(read(VECTORS_PATH))
    print("EDGE RECORD V13 OK: %d rows (%d carried, %d new), %d positives, %d negative; the hunks hold" % (
        len(record["artifacts"]), len(record["artifacts"]) - len(NEW_FILES), len(NEW_FILES), len(vectors["positive"]),
        len(vectors["negative"])))
    return 0


if __name__ == "__main__":
    sys.exit(main())
