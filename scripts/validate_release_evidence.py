#!/usr/bin/env python3
"""Release evidence (architecture/release-evidence.json, RELEASE-EVIDENCE-001, MET-008): the checker.

validate(record, read) returns the ordered list of every refusal code that applies, each at most once, in CODES order;
[] accepts. When RE_SHAPE applies, the list is ["RE_SHAPE"] alone, because the later checks need the shape. Otherwise
every other code that applies is listed; RE_CELLS, RE_DOMAINS and RE_EXCLUSIONS run on the record itself, independent
of RE_PROJECTION. Each form is checked by exactly one code:
- RE_SHAPE: the JSON types, the closed member sets and their order at every level (each row's cells and claimDomains
  included), schemaVersion, the states, columns and claimDomains constants, the closed enums of a row's nodeClass and a
  cell's state, a closure row owner's rNumber pattern, counts' three members, and producerStatus's members, the
  source's constants and hex forms, asOf's date form and the statuses keys and values; nothing else.
- RE_PROFILE: RELEASE-PROFILE-001's registered checker accepts (any refusal or exception from it refuses).
- RE_BASIS: exactly the three pins at the three named paths, in order, each sha256 the digest of the bytes the reader
  gives; the profile pin's id is the profile's profile.id.
- RE_CLOSURE: the row ids are the profile's closure.nodes, in order; each module row's nodeClass is the module's class;
  each closure.external id is a TENANT_FACT row.
- RE_PROJECTION: the record's bytes equal serialize(project(read)); an exception from project refuses.
- RE_CELLS: the reference grammar and its resolution, producer and requiredSource null exactly when NOT_SELECTED, the
  owner pattern, the date form and its equality with producerStatus.asOf, a non-empty nextAction ("none: " first when
  NOT_SELECTED), no QUALIFIED or FAILED cell, and each state equal to the three-branch rule applied to the class table,
  the lock's documentKind, the profile and producerStatus.statuses, with the producer the cell table consults. A
  closure row's class comes from the profile, never from the record's nodeClass (RE_CLOSURE's form): a tenant fact
  when its id is in closure.external, else a module.
- RE_DOMAINS: on module rows (the class from the profile, as in RE_CELLS), tenantAcceptance and customerAcceptance
  share neither a non-null producer nor a non-null reference.
- RE_EXCLUSIONS: the nine rider ids in order; each id's grammar and registry part; the repository's id, name and
  rNumber; no duplicate id and no id equal to a closure node; side, rider, and the source's registryRow and mainPin.
Data checks only; it enforces nothing.
"""
from __future__ import annotations

import hashlib
import json
import re
import stat
import sys
from pathlib import Path

from scripts import release_evidence as projection
from scripts import validate_release_profile

ROOT = Path(__file__).resolve().parents[1]
MAX_BYTES = 8 * 1024 * 1024
CODES = ("RE_SHAPE", "RE_PROFILE", "RE_BASIS", "RE_CLOSURE", "RE_PROJECTION", "RE_CELLS", "RE_DOMAINS", "RE_EXCLUSIONS")
TOP = ("schemaVersion", "basis", "producerStatus", "states", "columns", "claimDomains", "rows", "exclusionRows", "counts")
ROW = ("id", "nodeClass", "kind", "owningService", "owner", "implementation", "deployables", "cells", "claimDomains")
XROW = ("id", "repository", "artifact", "side", "rider", "source", "cells", "claimDomains")
CELL = ("state", "reference", "producer", "requiredSource", "owner", "date", "nextAction")
DEPLOYABLE = ("name", "type", "deployableRecord", "plannedLanguage", "status")
PACKET_ID = re.compile(r"[A-Z][A-Z0-9]*(-[A-Z0-9]+)+")
R_NUMBER = re.compile(r"R[0-9]{2}")
OWNER = re.compile(r"R[0-9]{2}|TENANT")
DATE = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}")
HEX40, HEX64 = re.compile(r"[0-9a-f]{40}"), re.compile(r"[0-9a-f]{64}")
MAIN_PIN = re.compile(r"[0-9a-f]{8,40}")
EXCLUSION_ID = re.compile(r"([a-z0-9]+(?:-[a-z0-9]+)*)\.([a-z0-9]+(?:-[a-z0-9]+)*)")
PROFILE_REF = projection.PROFILE_PATH + "#"


def digest(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _str(value) -> bool:
    return type(value) is str


def _opt_str(value) -> bool:
    return value is None or type(value) is str


def _int(value) -> bool:
    return type(value) is int


def _keys(value, members) -> bool:
    return type(value) is dict and tuple(value) == tuple(members)


def _cells(row):
    return list(row["cells"].values()) + list(row["claimDomains"].values())


def _named_cells(row):
    return list(row["cells"].items()) + list(row["claimDomains"].items())


def _shape_cell(cell) -> bool:
    return (_keys(cell, CELL) and cell["state"] in projection.STATES and _opt_str(cell["reference"])
            and _opt_str(cell["producer"]) and _opt_str(cell["requiredSource"]) and _str(cell["owner"])
            and _str(cell["date"]) and _str(cell["nextAction"]))


def _shape_cell_sets(row) -> bool:
    return (_keys(row["cells"], projection.COLUMNS) and _keys(row["claimDomains"], projection.DOMAINS)
            and all(_shape_cell(c) for c in _cells(row)))


def _shape_row(row) -> bool:
    if not (_keys(row, ROW) and _str(row["id"]) and row["nodeClass"] in projection.NODE_CLASSES and _str(row["kind"])
            and _opt_str(row["owningService"])):
        return False
    owner, implementation = row["owner"], row["implementation"]
    if not (_keys(owner, ("type", "name", "rNumber")) and _str(owner["type"]) and _str(owner["name"])
            and (owner["rNumber"] is None or (_str(owner["rNumber"]) and R_NUMBER.fullmatch(owner["rNumber"])))):
        return False
    if implementation is not None and not (_keys(implementation, ("packetId", "deliverableIndex"))
                                           and _str(implementation["packetId"])
                                           and _int(implementation["deliverableIndex"])):
        return False
    if type(row["deployables"]) is not list or not all(
            _keys(d, DEPLOYABLE) and _str(d["name"]) and _str(d["type"]) and _str(d["deployableRecord"])
            and _opt_str(d["plannedLanguage"]) and _opt_str(d["status"]) for d in row["deployables"]):
        return False
    return _shape_cell_sets(row)


def _shape_exclusion(row) -> bool:
    return (_keys(row, XROW) and _str(row["id"]) and _keys(row["repository"], ("id", "name", "rNumber"))
            and all(_str(v) for v in row["repository"].values()) and _str(row["artifact"]) and _str(row["side"])
            and _str(row["rider"]) and _keys(row["source"], ("registryRow", "mainPin", "note", "path"))
            and _str(row["source"]["registryRow"]) and _opt_str(row["source"]["mainPin"])
            and _str(row["source"]["note"]) and _str(row["source"]["path"]) and _shape_cell_sets(row))


def _shape(record) -> bool:
    if not (_keys(record, TOP) and record["schemaVersion"] == projection.SCHEMA_VERSION
            and record["states"] == list(projection.STATES) and record["columns"] == list(projection.COLUMNS)
            and record["claimDomains"] == list(projection.DOMAINS)):
        return False
    basis = record["basis"]
    if not (_keys(basis, ("profile", "deployableRecord", "releaseLock"))
            and _keys(basis["profile"], ("path", "id", "sha256")) and all(_str(v) for v in basis["profile"].values())
            and all(_keys(basis[k], ("path", "sha256")) and all(_str(v) for v in basis[k].values())
                    for k in ("deployableRecord", "releaseLock"))):
        return False
    status = record["producerStatus"]
    if not (_keys(status, ("source", "asOf", "statuses")) and _keys(status["source"], ("repository", "path", "commit", "sha256"))):
        return False
    source = status["source"]
    if not (source["repository"] == projection.PRODUCER_STATUS["source"]["repository"]
            and source["path"] == projection.PRODUCER_STATUS["source"]["path"]
            and _str(source["commit"]) and HEX40.fullmatch(source["commit"])
            and _str(source["sha256"]) and HEX64.fullmatch(source["sha256"])
            and _str(status["asOf"]) and DATE.fullmatch(status["asOf"])
            and type(status["statuses"]) is dict
            and all(_str(k) and (k == projection.HUMAN_PROBES or PACKET_ID.fullmatch(k))
                    and v in projection.ROADMAP_STATUSES for k, v in status["statuses"].items())):
        return False
    counts = record["counts"]
    if not (_keys(counts, ("rows", "exclusionRows", "cellsByState")) and _int(counts["rows"])
            and _int(counts["exclusionRows"]) and _keys(counts["cellsByState"], projection.STATES)
            and all(_int(v) for v in counts["cellsByState"].values())):
        return False
    return (type(record["rows"]) is list and all(_shape_row(r) for r in record["rows"])
            and type(record["exclusionRows"]) is list and all(_shape_exclusion(r) for r in record["exclusionRows"]))


def _profile(read):
    validate_release_profile.validate_release_profile()


def _basis(record, read) -> bool:
    basis = record["basis"]
    pins = (("profile", projection.PROFILE_PATH), ("deployableRecord", projection.DEPLOYABLE_RECORD_PATH),
            ("releaseLock", projection.LOCK_PATH))
    if tuple(basis) != tuple(k for k, _ in pins):
        return False
    if not all(basis[k]["path"] == path and basis[k]["sha256"] == digest(read(path)) for k, path in pins):
        return False
    return basis["profile"]["id"] == json.loads(read(projection.PROFILE_PATH))["profile"]["id"]


def _closure(record, read) -> bool:
    profile = json.loads(read(projection.PROFILE_PATH))
    rows = record["rows"]
    if [r["id"] for r in rows] != profile["closure"]["nodes"]:
        return False
    classes = {m["id"]: m["class"] for m in profile["modules"]}
    by_id = {r["id"]: r for r in rows}
    return (all(r["nodeClass"] == classes[r["id"]] for r in rows if r["id"] in classes)
            and all(by_id[x]["nodeClass"] == "TENANT_FACT" for x in profile["closure"]["external"]))


def _projection(record, read) -> bool:
    return projection.serialize(record) == projection.serialize(projection.project(read))


def _resolves(reference, row_id, closure_ids, read) -> bool:
    if reference is None or reference == projection.LOCK_PATH:
        return True
    if reference.startswith(PROFILE_REF):
        return reference[len(PROFILE_REF):] == row_id and row_id in closure_ids
    if reference.startswith("packet:") and PACKET_ID.fullmatch(reference[7:]):
        try:
            read("task-packets/%s.yaml" % reference[7:])
        except Exception:  # noqa: BLE001 - a read that raises, for any reason, leaves it unresolved
            return False
        return True
    return False


def _expected(kind, name, row, profile, inert, statuses):
    """The three-branch rule: the state a cell must hold, from the class table and the consulted producer."""
    if kind == "module":
        module = next(m for m in profile["modules"] if m["id"] == row["id"])
        if name == "retrievalQuality" and projection.GROUNDING not in module["exitEvidence"]["evidenceKinds"]:
            return "NOT_SELECTED"
        if name in projection.LOCK_COLUMNS:
            return "BLOCKED" if inert else projection.rule(projection.STATUS_KEY["R11's release set"], statuses)
        key = projection.MODULE_CONSULTS[name]
        return projection.rule(module["exitEvidence"]["at"] if key == "e" else key, statuses)
    if kind == "tenant":
        if name in projection.TENANT_NOT_SELECTED:
            return "NOT_SELECTED"
        fact = next(f for f in profile["tenantFacts"] if f["id"] == row["id"])
        if fact["attestation"]["requirement"] != projection.UNATTESTED:
            raise ValueError("no rule for an attested tenant fact")
        return "BLOCKED"
    if row["id"] in projection.NOT_SELECTED_ROWS or name in projection.ARTIFACT_NOT_SELECTED_COLUMNS or (
            name in projection.DOMAINS and name != projection.ARTIFACT_DOMAIN):
        return "NOT_SELECTED"
    registry = row["id"].split(".", 1)[0]
    return "BLOCKED" if inert else projection.rule(projection.STATUS_KEY[projection.CLOSURE_PROOF[registry][1]], statuses)


def _cells_ok(record, read) -> bool:
    profile = json.loads(read(projection.PROFILE_PATH))
    inert = json.loads(read(projection.LOCK_PATH)).get("documentKind") == projection.INERT_LOCK
    statuses = record["producerStatus"]["statuses"]
    as_of = record["producerStatus"]["asOf"]
    closure_ids = {r["id"] for r in record["rows"]}
    external = set(profile["closure"]["external"])
    rows = [("tenant" if r["id"] in external else "module", r) for r in record["rows"]]
    rows += [("exclusion", r) for r in record["exclusionRows"]]
    for kind, row in rows:
        for name, cell in _named_cells(row):
            empty = cell["state"] == "NOT_SELECTED"
            if cell["state"] in ("QUALIFIED", "FAILED"):
                return False
            if not _resolves(cell["reference"], row["id"], closure_ids, read):
                return False
            if (cell["producer"] is None) != empty or (cell["requiredSource"] is None) != empty:
                return False
            if not (OWNER.fullmatch(cell["owner"]) and DATE.fullmatch(cell["date"]) and cell["date"] == as_of):
                return False
            if not cell["nextAction"] or (empty and not cell["nextAction"].startswith("none: ")):
                return False
            if cell["state"] != _expected(kind, name, row, profile, inert, statuses):
                return False
    return True


def _domains_ok(record, read) -> bool:
    external = set(json.loads(read(projection.PROFILE_PATH))["closure"]["external"])
    for row in record["rows"]:
        if row["id"] in external:
            continue
        a, c = row["cells"]["tenantAcceptance"], row["claimDomains"]["customerAcceptance"]
        if (a["producer"] is not None and a["producer"] == c["producer"]) or (
                a["reference"] is not None and a["reference"] == c["reference"]):
            return False
    return True


def _exclusions_ok(record, read) -> bool:
    placement = json.loads(read(projection.DEPLOYABLE_RECORD_PATH))
    profile = json.loads(read(projection.PROFILE_PATH))
    repositories = {r["id"]: r for r in placement["repositories"]}
    nodes = set(profile["closure"]["nodes"]) | {f["id"] for f in profile["tenantFacts"]}
    rows = record["exclusionRows"]
    ids = [r["id"] for r in rows]
    if ids != [x for x, _, _ in projection.EXCLUSIONS] or len(set(ids)) != len(ids):
        return False
    for row in rows:
        match = EXCLUSION_ID.fullmatch(row["id"])
        if not match or match.group(1) not in repositories or row["id"] in nodes:
            return False
        registry, entry = match.group(1), repositories[match.group(1)]
        repository, source = row["repository"], row["source"]
        if (repository["id"] != registry or repository["name"] != entry["name"]
                or repository["rNumber"] != entry["rNumber"]):
            return False
        if row["side"] != "PRODUCER" or row["rider"] != projection.RIDER.get(registry):
            return False
        if source["registryRow"] != registry or not (source["mainPin"] is None or MAIN_PIN.fullmatch(source["mainPin"])):
            return False
    return True


CHECKS = (("RE_PROFILE", lambda record, read: _profile(read) is None), ("RE_BASIS", _basis), ("RE_CLOSURE", _closure),
          ("RE_PROJECTION", _projection), ("RE_CELLS", _cells_ok), ("RE_DOMAINS", _domains_ok),
          ("RE_EXCLUSIONS", _exclusions_ok))


def validate(record, read) -> list:
    try:
        shaped = _shape(record)
    except Exception:  # noqa: BLE001 - any failure to read the shape is a shape refusal
        shaped = False
    if not shaped:
        return ["RE_SHAPE"]
    codes = []
    for code, check in CHECKS:
        try:
            ok = check(record, read)
        except Exception:  # noqa: BLE001 - an exception inside a check refuses that check's code
            ok = False
        if not ok:
            codes.append(code)
    return codes


def disk_reader(root: Path = ROOT):
    def read(path: str) -> bytes:
        if path.startswith("/") or ".." in Path(path).parts:
            raise ValueError("unsafe repository path: %r" % (path,))
        target = root / path
        mode = target.lstat().st_mode
        if not stat.S_ISREG(mode) or target.stat().st_size > MAX_BYTES:
            raise ValueError("unsafe repository path: %r" % (path,))
        return target.read_bytes()
    return read


def main(argv=None):
    root = Path((argv if argv is not None else sys.argv[1:] or [str(ROOT)])[0])
    read = disk_reader(root)
    try:
        record = json.loads(read(projection.RECORD_PATH))
    except Exception as error:  # noqa: BLE001
        print("RE_SHAPE: the record does not read as JSON (%s)" % type(error).__name__)
        print("RELEASE EVIDENCE REFUSED: 1")
        return 1
    codes = validate(record, read)
    for code in codes:
        print("%s: refused" % code)
    print("RELEASE EVIDENCE %s" % ("REFUSED: %d" % len(codes) if codes else "OK"))
    return 1 if codes else 0


if __name__ == "__main__":
    sys.exit(main())
