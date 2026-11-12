#!/usr/bin/env python3
"""Data correctness (architecture/data-correctness/record.json, DATA-CORRECTNESS-001, MET-007): the checker.

check(read, packets) validates the record through an injected byte reader (exact paths only, no listing) and the set of
published packet ids, and returns its refusals as (code, message) pairs, in the order the codes run:
- DC_SHAPE: every object closed to its exact members with exact JSON types; closed vocabularies; a valued member is
  {value, source} with source null exactly when value is UNSPECIFIED; no string contains a catalog path or equals a
  catalog basename (the record names no catalog, Q-288-A1).
- DC_BASIS: the schema's, the effective catalog's, the service-edge record's and the authority map's digests; the
  effective catalog through sector_catalog.effective_bytes_from(read, packets, path), its counts, and its parity with
  the raw catalog (equal service names and dependency entries, in order).
- DC_ROWS: the durable writers derived from the effective catalog (STATEFUL, or STATELESS with durableState true; 24 at
  the base), in its order, each stores equal to the catalog's {name, ownership} projection (the model's durable_writers).
- DC_SOURCES: each phrase stands on its cited line (the c1 content review judges whether it states the member's value).
- DC_FENCING: a lease implies RF-2 in the obligations, and RF-2 a lease.
- DC_VERSIONS: every record kind has its version member; a valued window implies a valued version.
- DC_DERIVED_STORES: every derived store has its feed and deletion members; RF-6 is in the obligations exactly when a
  derived store is.
- DC_OPIDS: per operation class, the counts equal the service-edge record's (130 classes; NATIVE 73, NONE 57,
  RECEIPT_KEY 0; per edge 72, 56 and 1 split), and native, receiptKey and none each name the tool effect classes they
  bind; no operation class is classified from its lifecyclePhase or its idempotency.
- DC_BUDGET: the authority map's budget row AM-02 exists and is cited by the map's digest.
- DC_COUNTS: the counts, and every row's obligations against the rule families' predicates.
- DC_VECTORS: the model replays every vector, read by the exact paths the rule families list, to its expected outcome,
  and every model code is refused by at least one vector.
Standard library plus the repository's safe YAML loader, sector_catalog and the reference model
(scripts/data_correctness.py). Data checks only; it enforces nothing.
"""
from __future__ import annotations

import hashlib
import json
import sys
from collections import Counter
from pathlib import Path

try:
    import data_correctness as model
    from safe_yaml import safe_load
    from sector_catalog import disk_reader, effective_bytes_from, published_packets
except ImportError:
    from scripts import data_correctness as model
    from scripts.safe_yaml import safe_load
    from scripts.sector_catalog import disk_reader, effective_bytes_from, published_packets

ROOT = Path(__file__).resolve().parents[1]
RECORD_PATH = "architecture/data-correctness/record.json"
SCHEMA_PATH = "architecture/data-correctness/schema.json"
SERVICES_CATALOG = "architecture/services.yaml"
EDGES_PATH = "architecture/service-edges.yaml"
AUTHORITY_MAP_PATH = "architecture/authority-map.json"
VECTOR_DIR = "architecture/data-correctness/vectors/"
SCHEMA_VERSION = "harness.planeon.ai/data-correctness/v1"
CATALOG_PATHS = ("architecture/providers.yaml", "architecture/services.yaml", "docs/PROVIDER_MODULE_CATALOG.md")
CATALOG_BASENAMES = tuple(p.rsplit("/", 1)[-1] for p in CATALOG_PATHS)
CODES = ("DC_SHAPE", "DC_BASIS", "DC_ROWS", "DC_SOURCES", "DC_FENCING", "DC_VERSIONS", "DC_DERIVED_STORES", "DC_OPIDS",
         "DC_BUDGET", "DC_COUNTS", "DC_VECTORS")
U = "UNSPECIFIED"
FAMILIES = ("RF-1", "RF-2", "RF-3", "RF-4", "RF-5", "RF-6", "RF-7")
NAMES = ("WRITE_SKEW", "FENCING", "CLOCKS", "OPERATION_IDS", "COMPATIBILITY", "DERIVED_DATA", "REPLAY_STATE")
GUARDS = ("SERIALIZABLE", "ROW_LOCK", "ADVISORY_LOCK", "SINGLE_WRITER", "APPEND_ONLY", U)
FENCINGS = ("STORE_CHECKED_TOKEN", "TARGET_CHECKED_GENERATION", U)
CLOCK_USES = ("NONE", "DURATION", "WALL_COMPARISON", U)
WINDOWS = ("N_MINUS_1_BOTH_DIRECTIONS", U)
FEEDS = ("CHANGE_LOG", "REBUILD", U)
DELETIONS = ("PROPAGATED", U)
TOOL_CLASSES = ("READ", "IDEMPOTENT_WRITE", "NON_IDEMPOTENT", "IRREVERSIBLE")
BINDS = {"native": ["IDEMPOTENT_WRITE"], "receiptKey": ["NON_IDEMPOTENT", "IRREVERSIBLE"], "none": ["NON_IDEMPOTENT", "IRREVERSIBLE"]}
TOP = ("schemaVersion", "schema", "basis", "ruleFamilies", "operationIds", "deployables", "counts")
ROW = ("id", "stateMode", "stores", "writePaths", "lease", "clock", "recordKinds", "derivedStores", "outbox",
       "transactionBoundary", "obligations")
OPERATION_IDS = ("origin", "shape", "propagation", "receiptKey", "native", "none", "outcomes", "toolEffectClasses", "edges")
COUNTS = ("deployables", "byStateMode", "withLease", "withOutbox", "withDerivedStores", "withTransactionBoundary", "guards",
          "unspecifiedByMember", "obligationsByFamily", "vectorsByFamily")


class Refused(ValueError):
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


def source(value, where):
    closed(value, ("basis", "line", "phrase"), where)
    text(value["basis"], where + ".basis")
    need(type(value["line"]) is int and value["line"] >= 1, where + ".line is a positive integer")
    text(value["phrase"], where + ".phrase")


def valued(value, vocabulary, where):
    closed(value, ("value", "source"), where)
    v = value["value"]
    if vocabulary is int:
        need(v == U or (type(v) is int and v >= 0), where + ".value is an integer or UNSPECIFIED")
    elif vocabulary is str:
        text(v, where + ".value")
    else:
        need(v in vocabulary, "%s.value is one of %s" % (where, ", ".join(vocabulary)))
    if v == U:
        need(value["source"] is None, where + ": an UNSPECIFIED value has a null source")
    else:
        source(value["source"], where + ".source")


def strings(value):
    if isinstance(value, str):
        yield value
    elif isinstance(value, dict):
        for k, v in value.items():
            yield k
            yield from strings(v)
    elif isinstance(value, list):
        for v in value:
            yield from strings(v)


def check_shape(record):
    closed(record, TOP, "the record")
    need(record["schemaVersion"] == SCHEMA_VERSION, "schemaVersion")
    closed(record["schema"], ("path", "sha256"), "schema")
    need(record["schema"]["path"] == SCHEMA_PATH, "schema.path")
    closed(record["basis"], ("catalog", "serviceEdges", "authorityMap"), "basis")
    closed(record["basis"]["catalog"], ("view", "sha256", "services", "dependencyEntries", "parity"), "basis.catalog")
    need(record["basis"]["catalog"]["view"] == "EFFECTIVE" and record["basis"]["catalog"]["parity"] == "RAW_EQUALS_EFFECTIVE",
         "basis.catalog's view and parity")
    closed(record["basis"]["serviceEdges"], ("path", "sha256"), "basis.serviceEdges")
    closed(record["basis"]["authorityMap"], ("path", "sha256", "budgetRow"), "basis.authorityMap")
    need(record["basis"]["serviceEdges"]["path"] == EDGES_PATH and record["basis"]["authorityMap"]["path"] == AUTHORITY_MAP_PATH,
         "basis paths")
    families = record["ruleFamilies"]
    need(type(families) is list and [f.get("id") for f in families if type(f) is dict] == list(FAMILIES), "seven rule families in order")
    for f, name in zip(families, NAMES):
        closed(f, ("id", "name", "property", "appliesWhen", "staticChecks", "vectors"), "rule family " + f["id"])
        need(f["name"] == name, f["id"] + "'s name")
        text(f["property"], f["id"] + ".property")
        text(f["appliesWhen"], f["id"] + ".appliesWhen")
        need(type(f["staticChecks"]) is list and f["staticChecks"] and set(f["staticChecks"]) <= set(CODES), f["id"] + ".staticChecks")
        need(type(f["vectors"]) is list and f["vectors"] and all(type(v) is str and v.startswith(VECTOR_DIR) and v.endswith(".json")
                                                               and "/" not in v[len(VECTOR_DIR):] for v in f["vectors"]),
             f["id"] + ".vectors are exact vector paths")
    ops = record["operationIds"]
    closed(ops, OPERATION_IDS, "operationIds")
    for k in ("origin", "shape", "propagation"):
        text(ops[k], "operationIds." + k)
    for k in BINDS:
        closed(ops[k], ("binds", "rule"), "operationIds." + k)
        need(type(ops[k]["binds"]) is list and set(ops[k]["binds"]) <= set(TOOL_CLASSES), "operationIds.%s.binds" % k)
        text(ops[k]["rule"], "operationIds.%s.rule" % k)
    closed(ops["outcomes"], ("terms", "citedFrom", "owner", "unknown", "separations"), "operationIds.outcomes")
    need(type(ops["toolEffectClasses"]) is list and [c.get("class") for c in ops["toolEffectClasses"]] == list(TOOL_CLASSES),
         "the four tool effect classes in order")
    for c in ops["toolEffectClasses"]:
        closed(c, ("class", "retry", "approval"), "a tool effect class")
    closed(ops["edges"], ("edges", "operationClasses", "byIdempotency", "perEdge", "splitEdges"), "operationIds.edges")
    rows = record["deployables"]
    need(type(rows) is list and rows, "deployables is a non-empty list")
    for r in rows:
        closed(r, ROW, "a deployable")
        where = "deployable " + str(r.get("id"))
        text(r["id"], where + ".id")
        need(r["stateMode"] in ("STATEFUL", "STATELESS_DURABLE"), where + ".stateMode")
        need(type(r["stores"]) is list, where + ".stores")
        for s in r["stores"]:
            closed(s, ("name", "ownership"), where + " store")
        for w in r["writePaths"]:
            closed(w, ("store", "guard"), where + " write path")
            valued(w["guard"], GUARDS, where + " guard")
        if r["lease"] is not None:
            closed(r["lease"], ("resource", "source", "fencing"), where + ".lease")
            text(r["lease"]["resource"], where + ".lease.resource")
            source(r["lease"]["source"], where + ".lease.source")
            valued(r["lease"]["fencing"], FENCINGS, where + ".lease.fencing")
        closed(r["clock"], ("use", "skewMarginMs"), where + ".clock")
        valued(r["clock"]["use"], CLOCK_USES, where + ".clock.use")
        valued(r["clock"]["skewMarginMs"], int, where + ".clock.skewMarginMs")
        for k in r["recordKinds"]:
            closed(k, ("kind", "source", "version", "window"), where + " record kind")
            source(k["source"], where + " record kind source")
            valued(k["version"], str, where + " record kind version")
            valued(k["window"], WINDOWS, where + " record kind window")
        for d in r["derivedStores"]:
            closed(d, ("store", "source", "feed", "deletion"), where + " derived store")
            source(d["source"], where + " derived store source")
            valued(d["feed"], FEEDS, where + " derived store feed")
            valued(d["deletion"], DELETIONS, where + " derived store deletion")
        if r["outbox"] is not None:
            closed(r["outbox"], ("source",), where + ".outbox")
            source(r["outbox"]["source"], where + ".outbox.source")
        valued(r["transactionBoundary"], str, where + ".transactionBoundary")
        need(type(r["obligations"]) is list and len(set(r["obligations"])) == len(r["obligations"])
             and [f for f in FAMILIES if f in r["obligations"]] == r["obligations"], where + ".obligations in family order")
    closed(record["counts"], COUNTS, "counts")
    for s in strings(record):
        need(not any(p in s for p in CATALOG_PATHS) and s not in CATALOG_BASENAMES, "the record names a catalog")


def all_sources(record):
    for r in record["deployables"]:
        if r["lease"]:
            yield r["lease"]["source"]
            yield r["lease"]["fencing"]["source"]
        yield from (w["guard"]["source"] for w in r["writePaths"])
        yield r["clock"]["use"]["source"]
        yield r["clock"]["skewMarginMs"]["source"]
        for k in r["recordKinds"]:
            yield from (k["source"], k["version"]["source"], k["window"]["source"])
        for d in r["derivedStores"]:
            yield from (d["source"], d["feed"]["source"], d["deletion"]["source"])
        if r["outbox"]:
            yield r["outbox"]["source"]
        yield r["transactionBoundary"]["source"]


def deps(services):
    return [(s["id"], [d["id"] if isinstance(d, dict) else d for d in s.get("dependencies", [])]) for s in services]


def operation_classes(edges):
    return [(e["consumer"], e["dependency"], op["idempotency"]) for e in edges["edges"]
            for op in (e["retry"]["operations"] if "operations" in e["retry"] else [e["retry"]])]


def obligations(row):
    applies = {"RF-1": bool(row["writePaths"]), "RF-2": row["lease"] is not None,
               "RF-3": row["lease"] is not None or row["clock"]["use"]["value"] != "NONE", "RF-4": row["outbox"] is not None,
               "RF-5": bool(row["recordKinds"]), "RF-6": bool(row["derivedStores"]), "RF-7": row["outbox"] is not None}
    return [f for f in FAMILIES if applies[f]]


def valued_members(row):
    out = [("guard", w["guard"]) for w in row["writePaths"]]
    if row["lease"]:
        out.append(("fencing", row["lease"]["fencing"]))
    out += [("clockUse", row["clock"]["use"]), ("skewMarginMs", row["clock"]["skewMarginMs"])]
    out += [(m, k[m]) for k in row["recordKinds"] for m in ("version", "window")]
    out += [(m, d[m]) for d in row["derivedStores"] for m in ("feed", "deletion")]
    out.append(("transactionBoundary", row["transactionBoundary"]))
    return out


def recount(record):
    rows = record["deployables"]
    unspec = Counter(m for r in rows for m, v in valued_members(r) if v["value"] == U)
    vectors = {f["id"]: len(f["vectors"]) for f in record["ruleFamilies"]}
    return {"deployables": len(rows), "byStateMode": dict(Counter(r["stateMode"] for r in rows)),
            "withLease": sum(1 for r in rows if r["lease"]), "withOutbox": sum(1 for r in rows if r["outbox"]),
            "withDerivedStores": sum(1 for r in rows if r["derivedStores"]),
            "withTransactionBoundary": sum(1 for r in rows if r["transactionBoundary"]["value"] != U),
            "guards": dict(sorted(Counter(w["guard"]["value"] for r in rows for w in r["writePaths"]).items())),
            "unspecifiedByMember": dict(sorted(unspec.items())),
            "obligationsByFamily": {f: sum(1 for r in rows if f in r["obligations"]) for f in FAMILIES},
            "vectorsByFamily": {f: vectors[f] for f in FAMILIES}}


def check(read, packets):
    """The refusals of the record at read, as (code, message) pairs in the codes' order; [] when it passes."""
    refusals = []
    try:
        record = parse_json(read(RECORD_PATH))
        check_shape(record)
    except Exception as exc:  # a malformed record stops at its shape
        return [("DC_SHAPE", str(exc))]
    state = {}

    def basis():
        need(record["schema"]["sha256"] == digest(read(SCHEMA_PATH)), "the schema's digest")
        eff = effective_bytes_from(read, packets, SERVICES_CATALOG)
        state["eff_lines"] = eff.decode("utf-8").split("\n")
        eff_services = safe_load(eff.decode("utf-8"))["services"]
        raw_services = safe_load(read(SERVICES_CATALOG).decode("utf-8"))["services"]
        cat = record["basis"]["catalog"]
        need(cat["sha256"] == digest(eff), "the effective catalog's digest")
        need(cat["services"] == len(eff_services) and cat["dependencyEntries"] == sum(len(d) for _, d in deps(eff_services)),
             "the effective catalog's counts")
        need(deps(raw_services) == deps(eff_services), "raw and effective catalogs differ in names or entries")
        need(record["basis"]["serviceEdges"]["sha256"] == digest(read(EDGES_PATH)), "the service-edge record's digest")
        need(record["basis"]["authorityMap"]["sha256"] == digest(read(AUTHORITY_MAP_PATH)), "the authority map's digest")

    def rows():
        got = [{"id": r["id"], "stateMode": r["stateMode"], "stores": r["stores"]} for r in record["deployables"]]
        want = model.durable_writers(read, packets)
        need(got == want, "the rows differ from the effective catalog's durable writers: %s" % sorted(
            {r["id"] for r in got} ^ {r["id"] for r in want} or {"order or stores"}))

    def sources():
        lines = state.get("eff_lines") or effective_bytes_from(read, packets, SERVICES_CATALOG).decode("utf-8").split("\n")
        for s in all_sources(record):
            if s is None:
                continue
            if s["basis"] == "catalog":
                body = lines
            else:
                need(s["basis"] not in CATALOG_PATHS, "a source names a catalog path")
                body = read(s["basis"]).decode("utf-8").split("\n")
            need(s["line"] <= len(body) and s["phrase"] in body[s["line"] - 1],
                 "the phrase %r is not on %s line %d" % (s["phrase"][:40], s["basis"], s["line"]))

    def fencing():
        for r in record["deployables"]:
            need((r["lease"] is not None) == ("RF-2" in r["obligations"]), r["id"] + ": a lease and RF-2 go together")

    def versions():
        for r in record["deployables"]:
            for k in r["recordKinds"]:
                need(k["window"]["value"] == U or k["version"]["value"] != U, r["id"] + ": a valued window needs a valued version")

    def derived():
        for r in record["deployables"]:
            need(bool(r["derivedStores"]) == ("RF-6" in r["obligations"]), r["id"] + ": derived stores and RF-6 go together")

    def opids():
        edges = safe_load(read(EDGES_PATH).decode("utf-8"))
        classes = operation_classes(edges)
        by = Counter(c[2] for c in classes)
        per = Counter("SPLIT" if "operations" in e["retry"] else e["retry"]["idempotency"] for e in edges["edges"])
        e = record["operationIds"]["edges"]
        need(e["edges"] == len(edges["edges"]) and e["operationClasses"] == len(classes), "the edge and class counts")
        need(e["byIdempotency"] == {"NATIVE": by["NATIVE"], "NONE": by["NONE"], "RECEIPT_KEY": by.get("RECEIPT_KEY", 0)},
             "the classes by idempotency")
        need(e["perEdge"] == {"NATIVE": per["NATIVE"], "NONE": per["NONE"], "SPLIT": per["SPLIT"]}, "the edges by idempotency")
        need(e["splitEdges"] == [{"consumer": x["consumer"], "dependency": x["dependency"]} for x in edges["edges"]
                                 if "operations" in x["retry"]], "the split edges")
        for k, want in BINDS.items():
            need(record["operationIds"][k]["binds"] == want, "operationIds.%s binds %s" % (k, ", ".join(want)))

    def budget():
        am = parse_json(read(AUTHORITY_MAP_PATH))
        need(record["basis"]["authorityMap"]["budgetRow"] == "AM-02"
             and any(c.get("id") == "AM-02" for c in am["concerns"]), "the authority map's budget row AM-02")

    def counts():
        for r in record["deployables"]:
            need(r["obligations"] == obligations(r), r["id"] + ": the obligations differ from the rule families' predicates")
        want = recount(record)
        need(record["counts"] == want, "counts differ: %s" % sorted(k for k in want if record["counts"].get(k) != want[k]))

    def vectors():
        seen, refused = set(), set()
        for f in record["ruleFamilies"]:
            for path in f["vectors"]:
                need(path not in seen, "a vector listed twice")
                seen.add(path)
                vector = parse_json(read(path))
                need(vector.get("id") == path[len(VECTOR_DIR):-5] and vector.get("family") == f["id"],
                     path + ": its id and family")
                got = model.replay(vector)
                need(got == vector["expect"], "%s replays to %s, not %s" % (vector["id"], got, vector["expect"]))
                if got != "ACCEPT":
                    refused.add(got["refuse"])
        need(refused == set(model.MODEL_CODES), "a model code no vector refuses: %s" % sorted(set(model.MODEL_CODES) - refused))

    for code, run in zip(CODES[1:], (basis, rows, sources, fencing, versions, derived, opids, budget, counts, vectors)):
        try:
            run()
        except Exception as exc:
            refusals.append((code, str(exc)))
    return refusals


def main(argv=None):
    root = Path((argv or sys.argv[1:] or [str(ROOT)])[0])
    refusals = check(disk_reader(root), published_packets(root))
    if refusals:
        for code, message in refusals:
            print("%s: %s" % (code, message))
        print("DATA CORRECTNESS REFUSED: %d" % len(refusals))
        return 1
    record = parse_json(disk_reader(root)(RECORD_PATH))
    print("DATA CORRECTNESS OK: %d deployables, %d rule families, %d vectors; counts %s" % (
        len(record["deployables"]), len(record["ruleFamilies"]), sum(len(f["vectors"]) for f in record["ruleFamilies"]),
        json.dumps({k: record["counts"][k] for k in ("withLease", "withOutbox", "withDerivedStores")}, sort_keys=True)))
    return 0


if __name__ == "__main__":
    sys.exit(main())
