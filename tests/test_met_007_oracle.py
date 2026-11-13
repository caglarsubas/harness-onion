"""D5a oracle tests for slot 288, MET-007: DATA-CORRECTNESS-001's contract record, its reference model and its checker,
and the head layer's checks V1, E1, E2, E3, E4, V4, V5 and V6.

Owner decision D5a requires a contract packet to carry tests written outside the candidate, by someone who is not its
builder. These tests are black-box. They load by file path, each into a fresh module object, exactly three repository
modules (the checker scripts/validate_data_correctness.py, the model scripts/data_correctness.py and the head layer
scripts/validate_met_007.py), read repository files by exact path as bytes, parse JSON with json and YAML only through
the head's own safe_load, and build every case from plain data (deep copies, bytes and readers written here).

Source of every expected value: CONTRACT_288 rev 4, cited next to each assert as "CONTRACT_288 section N" (sections 1,
3 to 9, 11 and 13). The facts the operator stated from the candidate c2 give call shapes only: check, disk_reader,
published_packets, RECORD_PATH, CODES, replay, MODEL_CODES, durable_writers and the head's constants and check_*
functions (each raises a ValueError whose message names MET-007). The record, its schema and the vectors are fixtures
that the tests load and mutate; their member names give a mutation its shape, never an expected count, code, class, row
or field.
"""

import base64
import copy
import hashlib
import importlib.util
import json
from collections import Counter
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]


def _load(relative, name):
    """Load one repository module by its file path into a fresh module object."""
    spec = importlib.util.spec_from_file_location(name, ROOT / relative)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


CHECKER = _load("scripts/validate_data_correctness.py", "oracle_met_007_checker")
MODEL = _load("scripts/data_correctness.py", "oracle_met_007_model")
HEAD = _load("scripts/validate_met_007.py", "oracle_met_007_head")

# Paths named by CONTRACT_288 sections 3, 4, 5, 6, 7, 8, 8.1, 9 and 11.
RECORD = "architecture/data-correctness/record.json"
SCHEMA = "architecture/data-correctness/schema.json"
VECTOR_PREFIX = "architecture/data-correctness/vectors/"
CATALOG = "architecture/services.yaml"
SERVICE_EDGES = "architecture/service-edges.yaml"
AUTHORITY_MAP = "architecture/authority-map.json"
HEAD_AUTHORITY = "architecture/data-correctness-authority.json"
HUNK_RECORD = "architecture/chain-checkpoint/hunk-classes/288.json"
REGISTRY = "architecture/review-record/briefs.json"
READER = "ci/chain_checkpoint.py"
RULE_288 = "architecture/repository-registration/rule-288.json"
REGISTRATION_288 = "scripts/repository_registration_288.py"
MODEL_FILE = "scripts/data_correctness.py"
CHECKER_FILE = "scripts/validate_data_correctness.py"
MODEL_TESTS = "tests/test_data_correctness.py"
PRODUCT = "LAB-SYNC-001"
COMPARATOR = "LAB-REPO-001"
ACCEPT = "ACCEPT"
UNSPECIFIED = "UNSPECIFIED"

# CONTRACT_288 section 5: the checker's codes in order and the model's codes in run order.
CONTRACT_CHECKER_CODES = (
    "DC_SHAPE", "DC_BASIS", "DC_ROWS", "DC_SOURCES", "DC_FENCING", "DC_VERSIONS", "DC_DERIVED_STORES", "DC_OPIDS",
    "DC_BUDGET", "DC_COUNTS", "DC_VECTORS",
)
CONTRACT_MODEL_CODES = ("DC_WRITE_SKEW", "DC_FENCE", "DC_CLOCK", "DC_OPID", "DC_VERSION", "DC_DERIVED", "DC_REPLAY_STATE")

# CONTRACT_288 sections 3.1, 3.3 and 3.4: closed members, the seven families in order, the vocabularies.
TOP_MEMBERS = {"schemaVersion", "schema", "basis", "ruleFamilies", "operationIds", "deployables", "counts"}
FAMILIES = (
    ("RF-1", "WRITE_SKEW"), ("RF-2", "FENCING"), ("RF-3", "CLOCKS"), ("RF-4", "OPERATION_IDS"),
    ("RF-5", "COMPATIBILITY"), ("RF-6", "DERIVED_DATA"), ("RF-7", "REPLAY_STATE"),
)
FAMILY_MEMBERS = {"id", "name", "property", "appliesWhen", "staticChecks", "vectors"}
FAMILY_PHRASES = {
    "RF-1": "SERIALIZABLE isolation",
    "RF-2": "monotonic fencing token",
    "RF-3": "monotonic source",
    "RF-4": "deduplicated at the effect's own store",
    "RF-5": "reader-writer pairs",
    "RF-6": "rebuild-and-compare",
    "RF-7": "a log-only replay vector is expected to diverge",
}
ROW_MEMBERS = {
    "id", "stateMode", "stores", "writePaths", "lease", "clock", "recordKinds", "derivedStores", "outbox",
    "transactionBoundary", "obligations",
}
GUARDS = {"SERIALIZABLE", "ROW_LOCK", "ADVISORY_LOCK", "SINGLE_WRITER", "APPEND_ONLY", UNSPECIFIED}
FENCINGS = {"STORE_CHECKED_TOKEN", "TARGET_CHECKED_GENERATION", UNSPECIFIED}
CLOCK_USES = {"NONE", "DURATION", "WALL_COMPARISON", UNSPECIFIED}
WINDOWS = {"N_MINUS_1_BOTH_DIRECTIONS", UNSPECIFIED}
FEEDS = {"CHANGE_LOG", "REBUILD", UNSPECIFIED}
DELETIONS = {"PROPAGATED", UNSPECIFIED}

# CONTRACT_288 section 3.4: what the catalog states today.
STATELESS_DURABLE_IDS = {"operator", "fleet-sync-agent", "profile-compiler-worker"}
LEASE_IDS = {
    "operator", "connector-controller", "ingest-worker", "profile-compiler-worker", "assurance-worker",
    "orchestration-worker",
}
OUTBOX_IDS = {
    "connector-controller", "control-web", "protocol-gateway", "profile-compiler-worker", "orchestration-api",
    "assurance-worker", "orchestration-worker", "ai-gateway", "experience-gateway",
}
DERIVED_IDS = {"memory-service", "control-web", "retrieval-service", "protocol-gateway", "index-worker"}
BOUNDARY_LINES = {963, 1208, 1312, 1422, 1554}


def _refuse(code):
    return {"refuse": code}


# CONTRACT_288 section 4: the thirteen vectors, their families and their expectations.
VECTOR_TABLE = (
    ("rf1-concurrent-reservations", "RF-1", _refuse("DC_WRITE_SKEW")),
    ("rf2-paused-holder", "RF-2", _refuse("DC_FENCE")),
    ("rf3-skew-and-jump", "RF-3", _refuse("DC_CLOCK")),
    ("rf4-replay-per-class", "RF-4", ACCEPT),
    ("rf4-retry-after-unknown", "RF-4", _refuse("DC_OPID")),
    ("rf4-receipt-key-restart", "RF-4", ACCEPT),
    ("rf4-receipt-key-per-attempt", "RF-4", _refuse("DC_OPID")),
    ("rf5-mixed-versions", "RF-5", ACCEPT),
    ("rf5-reader-drops-previous-version", "RF-5", _refuse("DC_VERSION")),
    ("rf6-deletion-through-derived", "RF-6", _refuse("DC_DERIVED")),
    ("rf7-log-only-replay-diverges", "RF-7", _refuse("DC_REPLAY_STATE")),
    ("neg-bounded-not-exactly-once", "RF-4", _refuse("DC_OPID")),
    ("neg-exception-path-dedup", "RF-4", _refuse("DC_OPID")),
)

# CONTRACT_288 section 7: LAB-REPO-001's 16-key form.
PRODUCT_KEYS = {
    "id", "repository", "branch", "objective", "predecessors", "allowedPaths", "warmSourceAccess", "sourceReuse",
    "contracts", "deliverables", "excluded", "prefetchCommands", "offlineAcceptanceCommands", "offlineExecution",
    "expectedEvidence", "rollback",
}

# CONTRACT_288 section 9: the authored files (each named in E3's ERRATA_LINES) and the v2.5 reader's files.
SECTION9_REQUIRED = (
    "tests/test_sector_catalog.py",
    "architecture/repository-registration/repositories.json",
    "architecture/repository-registration/language-placement.json",
    "scripts/language_placement.py",
    "tests/test_language_placement.py",
    "scripts/validate_architecture.py",
    "scripts/validate_readiness.py",
    "tests/test_packet_declaration_consistency.py",
    "docs/repositories/13-mas-harness-research-lab.md",
    "task-packets/README.md",
    "tests/test_release_lock_registration.py",
    "tests/test_task_packets.py",
    "docs/adr/0001-repository-boundaries.md",
    "docs/MASTER_DEVELOPMENT_PLAN.md",
)
SECTION9_READER_FILES = ("ci/chain_checkpoint.py", "architecture/chain-checkpoint/README.md", "tests/test_chain_checkpoint.py")
# CONTRACT_288 section 9 [PC-3]: 287's re-bound oracle identity and its corrected oracle join section 9's files.
SECTION9_PC3_FILES = ("architecture/oracle-identity-met-006.json", "tests/test_met_006_oracle.py")
SECTION9_READER_FILES = SECTION9_READER_FILES + SECTION9_PC3_FILES
# CONTRACT_288 section 9 [PC-4]: three older oracles' non-author corrections and two re-bound oracle identities.
SECTION9_PC4_FILES = (
    "tests/test_met_registry_001_oracle.py",
    "tests/test_met_perf_049_oracle.py",
    "tests/test_met_perf_047_oracle.py",
    "architecture/oracle-identity-met-registry-001.json",
    "architecture/oracle-identity-met-perf-049.json",
    "architecture/chain-checkpoint/oracle-identity.json",
)
SECTION9_READER_FILES = SECTION9_READER_FILES + SECTION9_PC4_FILES
# CONTRACT_288 section 9 [PC-5]: the runner's process-spawn fix, an authored edit in three hunks.
SECTION9_PC5_FILES = ("ci/run_packet_argv.py",)
SECTION9_READER_FILES = SECTION9_READER_FILES + SECTION9_PC5_FILES

# CONTRACT_288 section 9: the base lines each authored edit replaces, as the contract names them.
NAMED_LINES = (
    ("scripts/language_placement.py", (104,)),
    ("tests/test_language_placement.py", (59, 63, 315, 319, 652, 1203, 1242, 1245)),
    ("scripts/validate_architecture.py", (403, 413, 416)),
    ("scripts/validate_readiness.py", (694, 695)),
    ("docs/repositories/13-mas-harness-research-lab.md", (69, 70)),
    ("tests/test_release_lock_registration.py", (80, 81, 105, 120, 205, 219)),
    ("docs/adr/0001-repository-boundaries.md", (29, 33, 34, 35, 65)),
    ("docs/MASTER_DEVELOPMENT_PLAN.md", (3136,)),
)

# CONTRACT_288 section 9: authored files whose named lines lie well inside the file (for the out-of-span hunk).
OUT_OF_SPAN_CANDIDATES = (
    "docs/adr/0001-repository-boundaries.md",
    "scripts/validate_architecture.py",
    "tests/test_release_lock_registration.py",
    "tests/test_language_placement.py",
)

# CONTRACT_288 section 9: a mechanics file (the YAML corpus count, 97 layers).
MECHANICS_FILE = "tests/test_ci_performance.py"


# ---------------------------------------------------------------------------------------------------------------------
# Plain helpers.

_MEMO = {}


def _memo(key, make):
    if key not in _MEMO:
        _MEMO[key] = make()
    return _MEMO[key]


def _bytes(relative):
    return (ROOT / relative).read_bytes()


def _sha(data):
    return hashlib.sha256(data).hexdigest()


def _vector_path(vector_id):
    return VECTOR_PREFIX + vector_id + ".json"


def _dumper(raw):
    """Return a JSON writer that reproduces the layout of raw (falling back to two-space indent)."""
    data = json.loads(raw)
    for indent in (2, 1, 4, None):
        for ascii_only in (False, True):
            for tail in ("\n", ""):
                if (json.dumps(data, indent=indent, ensure_ascii=ascii_only) + tail).encode("utf-8") == raw:
                    return lambda obj, i=indent, a=ascii_only, t=tail: (
                        json.dumps(obj, indent=i, ensure_ascii=a) + t
                    ).encode("utf-8")
    return lambda obj: (json.dumps(obj, indent=2, ensure_ascii=False) + "\n").encode("utf-8")


def _record_raw():
    return _memo("record_raw", lambda: _bytes(RECORD))


def _record():
    return copy.deepcopy(_memo("record", lambda: json.loads(_record_raw())))


def _record_bytes(record):
    return _memo("record_dumper", lambda: _dumper(_record_raw()))(record)


def _packets():
    return _memo("packets", lambda: CHECKER.published_packets(ROOT))


def _disk():
    return _memo("disk", lambda: CHECKER.disk_reader(ROOT))


def _reader(overrides):
    """A plain reader: the bytes in overrides for their paths, the disk's bytes otherwise."""
    base = _disk()

    def read(path):
        if path in overrides:
            return overrides[path]
        return base(path)

    return read


def _check(record, extra=None):
    overrides = {CHECKER.RECORD_PATH: _record_bytes(record)}
    overrides.update(extra or {})
    return CHECKER.check(_reader(overrides), _packets())


def _codes(refusals):
    return [pair[0] for pair in refusals]


def _live_refusals():
    return _memo("live_refusals", lambda: CHECKER.check(CHECKER.disk_reader(ROOT), CHECKER.published_packets(ROOT)))


def _rows(record):
    return record["deployables"]


def _first_row(record):
    return record["deployables"][0]


def _row(record, predicate):
    for row in record["deployables"]:
        if predicate(row):
            return row
    pytest.fail("construction: no row of the live record matches this mutation")


def _has_lease(row):
    return row["lease"] is not None


def _has_outbox(row):
    return row["outbox"] is not None


def _has_derived(row):
    return bool(row["derivedStores"])


def _entry_source(record):
    return copy.deepcopy(_first_row(record)["recordKinds"][0]["source"])


def _valued(record):
    """Every valued member of section 3.4 as (member, {value, source})."""
    out = []
    for row in record["deployables"]:
        for path in row["writePaths"]:
            out.append(("guard", path["guard"]))
        if row["lease"] is not None:
            out.append(("fencing", row["lease"]["fencing"]))
        out.append(("clockUse", row["clock"]["use"]))
        out.append(("skewMarginMs", row["clock"]["skewMarginMs"]))
        for kind in row["recordKinds"]:
            out.append(("version", kind["version"]))
            out.append(("window", kind["window"]))
        for store in row["derivedStores"]:
            out.append(("feed", store["feed"]))
            out.append(("deletion", store["deletion"]))
        out.append(("transactionBoundary", row["transactionBoundary"]))
    return out


def _entry_sources(record):
    """The entry sources of section 3.4 [C2-7]: lease, record kinds, derived stores and outbox."""
    out = []
    for row in record["deployables"]:
        if row["lease"] is not None:
            out.append(row["lease"]["source"])
        for kind in row["recordKinds"]:
            out.append(kind["source"])
        for store in row["derivedStores"]:
            out.append(store["source"])
        if row["outbox"] is not None:
            out.append(row["outbox"]["source"])
    return out


def _source_ok(source):
    if not isinstance(source, dict) or set(source) != {"basis", "line", "phrase"}:
        return False
    basis, line, phrase = source["basis"], source["line"], source["phrase"]
    if not isinstance(basis, str) or not basis or basis.startswith("/") or CATALOG in basis:
        return False
    if not isinstance(line, int) or isinstance(line, bool) or line < 1:
        return False
    return isinstance(phrase, str) and bool(phrase)


def _same(stated, computed):
    keys = set(stated) | set(computed)
    return {key: stated.get(key, 0) for key in keys} == {key: computed.get(key, 0) for key in keys}


def _strings(obj):
    if isinstance(obj, str):
        yield obj
    elif isinstance(obj, dict):
        for key, value in obj.items():
            yield from _strings(key)
            yield from _strings(value)
    elif isinstance(obj, list):
        for value in obj:
            yield from _strings(value)


def _locations(obj, matches, trail=()):
    found = []
    if isinstance(obj, dict):
        for key, value in obj.items():
            if matches(key):
                found.append(trail + (key,))
            found.extend(_locations(value, matches, trail + (key,)))
    elif isinstance(obj, list):
        for index, value in enumerate(obj):
            found.extend(_locations(value, matches, trail + (index,)))
    return found


def _at(obj, trail):
    for step in trail:
        obj = obj[step]
    return obj


def _put(obj, trail, value):
    _at(obj, trail[:-1])[trail[-1]] = value


def _is_steps(key):
    return isinstance(key, str) and key.lower().endswith("steps")


def _catalog():
    return _memo("catalog", lambda: HEAD.safe_load(_bytes(CATALOG).decode("utf-8")))


def _catalog_writers():
    """Durable writers of the catalog (STATEFUL, or STATELESS with durableState true), in order (section 3.4)."""
    writers = []
    for service in _catalog()["services"]:
        behavior = service.get("stateBehavior") or {}
        if behavior.get("mode") == "STATEFUL":
            state = "STATEFUL"
        elif behavior.get("mode") == "STATELESS" and behavior.get("durableState") is True:
            state = "STATELESS_DURABLE"
        else:
            continue
        stores = [{"name": store["name"], "ownership": store["ownership"]} for store in service.get("stores") or []]
        writers.append({"id": service["id"], "stateMode": state, "stores": stores})
    return writers


def _authority():
    return HEAD.authority()


def _changed():
    return _authority()["changedFiles"]


def _hunk_raw():
    return _memo("hunk_raw", lambda: _bytes(HEAD.HUNK_RECORD_PATH))


def _hunk_record():
    return copy.deepcopy(_memo("hunk_record", lambda: json.loads(_hunk_raw())))


def _befores():
    return _memo("befores", lambda: {path: HEAD._undo_this_layer(path, _bytes(path)) for path in HEAD.ERRATA_LINES})


def _afters():
    return _memo(
        "afters", lambda: {path: _bytes(path) for path, entry in _changed().items() if entry.get("reverseHunks")}
    )


def _v6(raw):
    context = _memo(
        "v6_context", lambda: HEAD._v24_context(HEAD.authority(), json.loads(_hunk_raw())["hunkClassContext"])
    )
    classify = _memo("v6_classify", lambda: HEAD._era_rule(HEAD.READER_PATH, HEAD.READER_NAME).classify)
    return HEAD.check_hunk_record(raw, _changed(), _afters(), classify, context, HEAD.HUNK_RULE_SHA256)


def _replays():
    out = {}
    for path in HEAD.VECTORS:
        vector = json.loads(_bytes(path))
        try:
            out[path] = MODEL.replay(vector)
        except ValueError:
            out[path] = None
    return out


def _packet_files():
    return {path: _bytes(path) for path in HEAD.PACKET_FILES}


def _base_files():
    return {path: _bytes(path) for path in HEAD.BASE_FILES}


def _yaml(relative):
    return HEAD.safe_load(_bytes(relative).decode("utf-8"))


def _product_raws():
    return {pid: _bytes("task-packets/" + pid + ".yaml") for pid in HEAD.PRODUCT_PACKETS}


def _comparators():
    return {pid: _bytes("task-packets/" + COMPARATOR + ".yaml") for pid in HEAD.PRODUCT_PACKETS}


def _swap_commands(raw):
    """The product YAML with its first two offlineAcceptanceCommands swapped (one line, else the whole file as JSON)."""
    text = raw.decode("utf-8")
    product = HEAD.safe_load(text)
    commands = list(product["offlineAcceptanceCommands"])
    swapped = [commands[1], commands[0]] + commands[2:]
    lines = text.split("\n")
    for index, line in enumerate(lines):
        if line.startswith("offlineAcceptanceCommands:"):
            candidate = list(lines)
            candidate[index] = "offlineAcceptanceCommands: " + json.dumps(swapped, ensure_ascii=False)
            joined = "\n".join(candidate)
            try:
                parsed = HEAD.safe_load(joined)
            except Exception:
                parsed = None
            if isinstance(parsed, dict) and parsed == dict(product, offlineAcceptanceCommands=swapped):
                return joined.encode("utf-8"), commands, swapped
    product["offlineAcceptanceCommands"] = swapped
    return (json.dumps(product, indent=2, ensure_ascii=False) + "\n").encode("utf-8"), commands, swapped


# ---------------------------------------------------------------------------------------------------------------------
# Checker mutations (section 5): each mutates a deep copy of the live record and returns extra reader overrides.


def _shape_extra_member(record):
    record["zzOracleExtra"] = 1


def _shape_schema_version(record):
    record["schemaVersion"] = "harness.planeon.ai/data-correctness/v0"


def _shape_guard_vocabulary(record):
    _first_row(record)["writePaths"][0]["guard"] = {"value": "OPTIMISTIC", "source": _entry_source(record)}


def _shape_catalog_path(record):
    family = record["ruleFamilies"][0]
    family["appliesWhen"] = family["appliesWhen"] + " (" + CATALOG + ")"


def _shape_catalog_basename(record):
    record["operationIds"]["origin"] = CATALOG.rsplit("/", 1)[1]


def _shape_state_mode(record):
    _first_row(record)["stateMode"] = "EPHEMERAL"


def _basis_catalog_digest(record):
    record["basis"]["catalog"]["sha256"] = "0" * 64


def _basis_edges_digest(record):
    record["basis"]["serviceEdges"]["sha256"] = "0" * 64


def _basis_services(record):
    record["basis"]["catalog"]["services"] = 27


def _basis_dependency_entries(record):
    record["basis"]["catalog"]["dependencyEntries"] = 128


def _rows_swapped(record):
    rows = record["deployables"]
    rows[0], rows[1] = rows[1], rows[0]


def _rows_dropped(record):
    record["deployables"].pop()


def _rows_store_order(record):
    _row(record, lambda row: len(row["stores"]) >= 2)["stores"].reverse()


def _rows_state_mode(record):
    _row(record, lambda row: row["stateMode"] == "STATELESS_DURABLE")["stateMode"] = "STATEFUL"


def _sources_phrase(record):
    _first_row(record)["recordKinds"][0]["source"]["phrase"] = "zz oracle phrase that stands on no catalog line"


def _sources_other_row(record):
    rows = record["deployables"]
    rows[0]["recordKinds"][0]["source"] = copy.deepcopy(rows[1]["recordKinds"][0]["source"])


def _sources_past_end(record):
    _first_row(record)["recordKinds"][0]["source"]["line"] = 999999


def _fencing_obligation(record):
    row = _row(record, _has_lease)
    row["obligations"] = [item for item in row["obligations"] if item != "RF-2"]


def _versions_window_alone(record):
    kind = _first_row(record)["recordKinds"][0]
    kind["window"] = {"value": "N_MINUS_1_BOTH_DIRECTIONS", "source": copy.deepcopy(kind["source"])}


def _versions_missing(record):
    del _first_row(record)["recordKinds"][0]["version"]


def _derived_obligation(record):
    row = _row(record, _has_derived)
    row["obligations"] = [item for item in row["obligations"] if item != "RF-6"]


def _derived_feed(record):
    del _row(record, _has_derived)["derivedStores"][0]["feed"]


def _derived_deletion(record):
    del _row(record, _has_derived)["derivedStores"][0]["deletion"]


def _opids_native(record):
    record["operationIds"]["edges"]["byIdempotency"]["NATIVE"] = 72


def _opids_classes(record):
    record["operationIds"]["edges"]["operationClasses"] = 131


def _opids_split(record):
    record["operationIds"]["edges"]["perEdge"]["SPLIT"] = 2


def _opids_native_binds(record):
    record["operationIds"]["native"]["binds"] = ["READ"]


def _opids_receipt_binds(record):
    record["operationIds"]["receiptKey"]["binds"] = ["IDEMPOTENT_WRITE"]


def _budget_row_missing(record):
    raw = _bytes(AUTHORITY_MAP)
    token = b'"id": "AM-02"'
    occurrences = raw.count(token)
    # CONTRACT_288 section 3.2 (construction: the authority map holds the one AM-02 row the basis cites)
    assert occurrences == 1
    changed = raw.replace(token, b'"id": "AM-92"')
    record["basis"]["authorityMap"]["sha256"] = _sha(changed)
    return {AUTHORITY_MAP: changed}


def _counts_deployables(record):
    record["counts"]["deployables"] = record["counts"]["deployables"] + 1


def _counts_state_mode(record):
    record["counts"]["byStateMode"]["STATEFUL"] = record["counts"]["byStateMode"]["STATEFUL"] - 1


def _counts_vectors(record):
    record["counts"]["vectorsByFamily"]["RF-4"] = record["counts"]["vectorsByFamily"]["RF-4"] - 1


def _vector_expect(vector_id, expect):
    def mutate(record):
        path = _vector_path(vector_id)
        raw = _bytes(path)
        vector = json.loads(raw)
        vector["expect"] = expect
        return {path: _dumper(raw)(vector)}

    return mutate


# (id, codes of which the refusals must name one, mutation); a one-code tuple names that code alone (section 5).
CHECKER_MUTATIONS = [
    ("DC_SHAPE-extra-member", ("DC_SHAPE",), _shape_extra_member),
    ("DC_SHAPE-schema-version", ("DC_SHAPE",), _shape_schema_version),
    ("DC_SHAPE-guard-vocabulary", ("DC_SHAPE",), _shape_guard_vocabulary),
    ("DC_SHAPE-catalog-path", ("DC_SHAPE",), _shape_catalog_path),
    ("DC_SHAPE-catalog-basename", ("DC_SHAPE",), _shape_catalog_basename),
    ("DC_SHAPE-state-mode-vocabulary", ("DC_SHAPE",), _shape_state_mode),
    ("DC_BASIS-catalog-digest", ("DC_BASIS",), _basis_catalog_digest),
    ("DC_BASIS-service-edges-digest", ("DC_BASIS",), _basis_edges_digest),
    ("DC_BASIS-services", ("DC_BASIS",), _basis_services),
    ("DC_BASIS-dependency-entries", ("DC_BASIS",), _basis_dependency_entries),
    ("DC_ROWS-order", ("DC_ROWS",), _rows_swapped),
    ("DC_ROWS-missing-writer", ("DC_ROWS",), _rows_dropped),
    ("DC_ROWS-store-projection", ("DC_ROWS",), _rows_store_order),
    ("DC_ROWS-state-mode", ("DC_ROWS",), _rows_state_mode),
    ("DC_SOURCES-phrase", ("DC_SOURCES",), _sources_phrase),
    ("DC_SOURCES-line-outside-own-entry", ("DC_SOURCES",), _sources_other_row),
    ("DC_SOURCES-line-past-end", ("DC_SOURCES",), _sources_past_end),
    ("DC_FENCING-lease-without-rf2", ("DC_FENCING",), _fencing_obligation),
    ("DC_VERSIONS-window-without-version", ("DC_VERSIONS",), _versions_window_alone),
    ("DC_VERSIONS-missing-version", ("DC_VERSIONS", "DC_SHAPE"), _versions_missing),
    ("DC_DERIVED_STORES-without-rf6", ("DC_DERIVED_STORES",), _derived_obligation),
    ("DC_DERIVED_STORES-missing-feed", ("DC_DERIVED_STORES", "DC_SHAPE"), _derived_feed),
    ("DC_DERIVED_STORES-missing-deletion", ("DC_DERIVED_STORES", "DC_SHAPE"), _derived_deletion),
    ("DC_OPIDS-native-count", ("DC_OPIDS",), _opids_native),
    ("DC_OPIDS-class-count", ("DC_OPIDS",), _opids_classes),
    ("DC_OPIDS-split-count", ("DC_OPIDS",), _opids_split),
    ("DC_OPIDS-native-binds", ("DC_OPIDS",), _opids_native_binds),
    ("DC_OPIDS-receipt-key-binds", ("DC_OPIDS",), _opids_receipt_binds),
    ("DC_BUDGET-row-missing", ("DC_BUDGET",), _budget_row_missing),
    ("DC_COUNTS-deployables", ("DC_COUNTS",), _counts_deployables),
    ("DC_COUNTS-state-mode", ("DC_COUNTS",), _counts_state_mode),
    ("DC_COUNTS-vectors-by-family", ("DC_COUNTS",), _counts_vectors),
    ("DC_VECTORS-expect-accept", ("DC_VECTORS",), _vector_expect("rf1-concurrent-reservations", ACCEPT)),
    ("DC_VECTORS-expect-refuse", ("DC_VECTORS",), _vector_expect("rf4-replay-per-class", _refuse("DC_OPID"))),
]


# Valued-form mutations (sections 3.1 and 3.4).


def _vf_guard_null_source(record):
    _first_row(record)["writePaths"][0]["guard"] = {"value": "SINGLE_WRITER", "source": None}


def _vf_boundary_null_source(record):
    _first_row(record)["transactionBoundary"] = {"value": "commits atomically with its outbox", "source": None}


def _vf_skew_null_source(record):
    _first_row(record)["clock"]["skewMarginMs"] = {"value": 250, "source": None}


def _vf_guard_unspecified_with_source(record):
    _first_row(record)["writePaths"][0]["guard"] = {"value": UNSPECIFIED, "source": _entry_source(record)}


def _vf_clock_unspecified_with_source(record):
    _first_row(record)["clock"]["use"] = {"value": UNSPECIFIED, "source": _entry_source(record)}


def _vf_kind_source_null(record):
    _first_row(record)["recordKinds"][0]["source"] = None


def _vf_lease_source_null(record):
    _row(record, _has_lease)["lease"]["source"] = None


def _vf_outbox_source_null(record):
    _row(record, _has_outbox)["outbox"]["source"] = None


def _vf_derived_source_null(record):
    _row(record, _has_derived)["derivedStores"][0]["source"] = None


VALUED_MUTATIONS = [
    ("value-with-null-source-guard", ("DC_SHAPE",), _vf_guard_null_source),
    ("value-with-null-source-transaction-boundary", ("DC_SHAPE",), _vf_boundary_null_source),
    ("value-with-null-source-skew-margin", ("DC_SHAPE",), _vf_skew_null_source),
    ("unspecified-with-source-guard", ("DC_SHAPE",), _vf_guard_unspecified_with_source),
    ("unspecified-with-source-clock-use", ("DC_SHAPE",), _vf_clock_unspecified_with_source),
    ("null-entry-source-record-kind", ("DC_SHAPE", "DC_SOURCES"), _vf_kind_source_null),
    ("null-entry-source-lease", ("DC_SHAPE", "DC_SOURCES"), _vf_lease_source_null),
    ("null-entry-source-outbox", ("DC_SHAPE", "DC_SOURCES"), _vf_outbox_source_null),
    ("null-entry-source-derived-store", ("DC_SHAPE", "DC_SOURCES"), _vf_derived_source_null),
]


# Vectors built from each family's words (sections 3.3 and 4), in the vectors' step form.


def _begin(tx):
    return {"op": "begin", "tx": tx}


def _reserve(tx, units):
    return {"op": "reserve", "tx": tx, "units": units}


def _commit(tx):
    return {"op": "commit", "tx": tx}


def _acquire(holder, token):
    return {"op": "acquire", "holder": holder, "token": token}


def _expire(holder):
    return {"op": "expire", "holder": holder}


def _write(holder, token, accepted):
    return {"op": "write", "holder": holder, "token": token, "accepted": accepted}


def _read(record_version, reader, accepted):
    return {"op": "read_record", "recordVersion": record_version, "reader": reader, "rollout": True, "accepted": accepted}


def _call(operation, edge, effect_class, attempt, applied, **extra):
    step = {"op": "call", "operation": operation, "edge": edge, "class": effect_class, "attempt": attempt}
    step.update(extra)
    step["applied"] = applied
    return step


def _delete(propagated, receipt):
    return {"op": "delete", "id": "doc-9", "propagatedTo": propagated, "receipt": receipt}


BUILT_VECTORS = [
    # RF-1: two reservations of the last unit without a covering guard; one reservation alone decides on nothing shared.
    ("rf1-built-reordered-commits", "RF-1", {"units": 1, "guard": "NONE"},
     [_begin("p"), _begin("q"), _reserve("p", 1), _reserve("q", 1), _commit("q"), _commit("p")],
     _refuse("DC_WRITE_SKEW")),
    ("rf1-built-single-reservation", "RF-1", {"units": 1, "guard": "NONE"},
     [_begin("a"), _reserve("a", 1), _commit("a")], ACCEPT),
    # RF-2: a holder that resumes after its lease expired is refused by the store-checked token.
    ("rf2-built-resumed-holder-writes", "RF-2", {"fencing": "STORE_CHECKED_TOKEN"},
     [_acquire("a", 1), _expire("a"), _acquire("b", 2), _write("a", 1, True)], _refuse("DC_FENCE")),
    ("rf2-built-store-refuses-old-token", "RF-2", {"fencing": "STORE_CHECKED_TOKEN"},
     [_acquire("a", 1), _expire("a"), _acquire("b", 2), _write("b", 2, True), _write("a", 1, False)], ACCEPT),
    # RF-3: a clock jump never extends a lease; durations use the monotonic source.
    ("rf3-built-backward-jump", "RF-3", {},
     [{"op": "lease_start", "monotonicMs": 0, "wallMs": 50000, "leaseMs": 2000},
      {"op": "wall_jump", "deltaMs": -10000},
      {"op": "lease_check", "monotonicMs": 3000, "wallMs": 43000, "held": True}],
     _refuse("DC_CLOCK")),
    # RF-4: section 3.5.
    ("rf4-built-none-retried-after-unknown", "RF-4", {},
     [_call("op-21", "caller->callee", "NONE", 1, True, outcome="unknown"),
      _call("op-21", "caller->callee", "NONE", 2, True, outcome="committed")],
     _refuse("DC_OPID")),
    ("rf4-built-fresh-key-per-attempt", "RF-4", {},
     [_call("op-22", "caller->callee", "RECEIPT_KEY", 1, True, key="fresh-a", outcome="unknown"),
      _call("op-22", "caller->callee", "RECEIPT_KEY", 2, True, key="fresh-b", outcome="committed")],
     _refuse("DC_OPID")),
    ("rf4-built-exactly-once-claim", "RF-4", {},
     [{"op": "claim", "exactlyOnce": True, "maxAttempts": 5}], _refuse("DC_OPID")),
    ("rf4-built-exception-path-skips-dedup", "RF-4", {},
     [_call("op-25", "caller->callee", "NATIVE", 1, True, outcome="unknown"),
      _call("op-25", "caller->callee", "NATIVE", 2, True, path="exception", dedup=False)],
     _refuse("DC_OPID")),
    ("rf4-built-key-from-operation-and-edge", "RF-4", {},
     [_call("op-23", "caller->callee", "RECEIPT_KEY", 1, True, key="op-23/caller->callee", outcome="unknown"),
      _call("op-23", "caller->callee", "RECEIPT_KEY", 2, False, key="op-23/caller->callee", outcome="final",
            afterRestart=True)],
     ACCEPT),
    ("rf4-built-replay-applies-once", "RF-4", {},
     [_call("op-24", "ai-gateway->inference-api", "NATIVE", 1, True, outcome="committed"),
      _call("op-24", "ai-gateway->inference-api", "NATIVE", 2, False, outcome="committed")],
     ACCEPT),
    # RF-5: readers accept the previous and the current version in both directions during a rollout.
    ("rf5-built-previous-reader-refuses-current", "RF-5", {}, [_read("N", "N-1", False)], _refuse("DC_VERSION")),
    ("rf5-built-current-reader-refuses-previous", "RF-5", {}, [_read("N-1", "N", False)], _refuse("DC_VERSION")),
    ("rf5-built-both-directions-accepted", "RF-5", {}, [_read("N-1", "N", True), _read("N", "N-1", True)], ACCEPT),
    # RF-6: a deletion reaches every derived store, with a receipt.
    ("rf6-built-deletion-misses-embedding", "RF-6", {"derived": ["index", "embedding"]},
     [{"op": "insert", "id": "doc-9"}, _delete(["index"], True)], _refuse("DC_DERIVED")),
    ("rf6-built-deletion-without-receipt", "RF-6", {"derived": ["index", "embedding"]},
     [{"op": "insert", "id": "doc-9"}, _delete(["index", "embedding"], False)], _refuse("DC_DERIVED")),
    ("rf6-built-deletion-reaches-every-store", "RF-6", {"derived": ["index", "embedding"]},
     [{"op": "insert", "id": "doc-9"}, _delete(["index", "embedding"], True)], ACCEPT),
    # RF-7: the durable state a replay consults is an input beside the log.
    ("rf7-built-log-only-replay", "RF-7", {},
     [{"op": "replay", "inputs": ["log"], "consulted": ["checkpoint-state", "log"]}], _refuse("DC_REPLAY_STATE")),
    ("rf7-built-state-beside-the-log", "RF-7", {},
     [{"op": "replay", "inputs": ["log", "checkpoint-state"], "consulted": ["log", "checkpoint-state"]}], ACCEPT),
]


def _malformed_unknown_op():
    vector = json.loads(_bytes(_vector_path("rf1-concurrent-reservations")))
    vector["steps"][0]["op"] = "zz-oracle-unknown-op"
    return vector


def _malformed_missing_steps():
    vector = json.loads(_bytes(_vector_path("rf1-concurrent-reservations")))
    del vector["steps"]
    return vector


NEW_ARCHITECTURE_FILES = (
    [RECORD, SCHEMA] + [_vector_path(vector_id) for vector_id, _, _ in VECTOR_TABLE] + [HEAD_AUTHORITY, HUNK_RECORD, RULE_288]
)


# ---------------------------------------------------------------------------------------------------------------------
# 1. The live record (sections 3 and 5).


def test_live_record_passes_the_checker():
    """CONTRACT_288 section 5: check(disk_reader(ROOT), published_packets(ROOT)) returns no refusal."""
    packets = CHECKER.published_packets(ROOT)
    # CONTRACT_288 section 5 (operator-stated: published_packets returns a frozenset)
    assert isinstance(packets, frozenset)
    refusals = CHECKER.check(CHECKER.disk_reader(ROOT), packets)
    # CONTRACT_288 section 5 (an empty list passes)
    assert refusals == []


def test_record_path_and_code_sets():
    """CONTRACT_288 sections 3 and 5: RECORD_PATH, the checker's codes DC_SHAPE to DC_VECTORS, the model's codes."""
    # CONTRACT_288 section 3 (the record's path)
    assert CHECKER.RECORD_PATH == RECORD
    # CONTRACT_288 section 5 (DC_SHAPE to DC_VECTORS)
    assert set(CHECKER.CODES) == set(CONTRACT_CHECKER_CODES)
    if isinstance(CHECKER.CODES, (list, tuple)):
        # CONTRACT_288 section 5 (refusal codes in order)
        assert tuple(CHECKER.CODES) == CONTRACT_CHECKER_CODES
    # CONTRACT_288 section 5 (the model's seven codes)
    assert set(MODEL.MODEL_CODES) == set(CONTRACT_MODEL_CODES)
    if isinstance(MODEL.MODEL_CODES, (list, tuple)):
        # CONTRACT_288 section 5 (in run order)
        assert tuple(MODEL.MODEL_CODES) == CONTRACT_MODEL_CODES
    # CONTRACT_288 section 5 [C1-8] (the two code sets are disjoint)
    assert not set(CHECKER.CODES) & set(MODEL.MODEL_CODES)


def test_reader_with_unchanged_record_passes():
    """CONTRACT_288 section 5 (check through an injected byte reader): the live record served by this reader passes."""
    refusals = _check(_record())
    # CONTRACT_288 section 5
    assert refusals == []


def test_rows_are_the_catalog_durable_writers_in_order():
    """CONTRACT_288 section 3.4 and DC_ROWS (section 5): one row per durable writer, in the catalog's order."""
    rows = _rows(_record())
    writers = _catalog_writers()
    # CONTRACT_288 section 3.4 (24 rows)
    assert len(writers) == 24
    # CONTRACT_288 section 3.4 (21 STATEFUL and 3 STATELESS with durableState true)
    assert Counter(writer["stateMode"] for writer in writers) == Counter({"STATEFUL": 21, "STATELESS_DURABLE": 3})
    # CONTRACT_288 section 3.4 (operator, fleet-sync-agent, profile-compiler-worker)
    assert {w["id"] for w in writers if w["stateMode"] == "STATELESS_DURABLE"} == STATELESS_DURABLE_IDS
    # CONTRACT_288 section 3.4 (in the catalog's order)
    assert [row["id"] for row in rows] == [writer["id"] for writer in writers]
    # CONTRACT_288 section 3.4 (stateMode STATEFUL or STATELESS_DURABLE)
    assert [row["stateMode"] for row in rows] == [writer["stateMode"] for writer in writers]
    # CONTRACT_288 section 3.4 (stores, the catalog's {name, ownership} projection, in order)
    assert [row["stores"] for row in rows] == [writer["stores"] for writer in writers]


def test_model_durable_writers_match_the_rows():
    """CONTRACT_288 section 5 (the model's catalog read, durable_writers): ids and state modes, in catalog order."""
    writers = MODEL.durable_writers(CHECKER.disk_reader(ROOT), CHECKER.published_packets(ROOT))
    rows = _rows(_record())
    # CONTRACT_288 section 5 (24 at the base)
    assert len(writers) == 24
    # CONTRACT_288 section 5 (DC_ROWS compares the record against it)
    assert [(w["id"], w["stateMode"]) for w in writers] == [(row["id"], row["stateMode"]) for row in rows]


def test_rule_families_in_section_order():
    """CONTRACT_288 section 3.3: seven rows RF-1 to RF-7 in order; section 4: each row's vectors by exact path."""
    families = _record()["ruleFamilies"]
    # CONTRACT_288 section 3.3 (the item's six families and DC-D2's row, in this order)
    assert [(family["id"], family["name"]) for family in families] == list(FAMILIES)
    member_faults = sum(1 for family in families if set(family) != FAMILY_MEMBERS)
    # CONTRACT_288 section 3.3 ({id, name, property, appliesWhen, staticChecks, vectors})
    assert member_faults == 0
    for family in families:
        # CONTRACT_288 section 3.3 (the property in the contract's words)
        assert FAMILY_PHRASES[family["id"]] in family["property"]
        # CONTRACT_288 section 5 (static checks are checker codes)
        assert family["staticChecks"] and set(family["staticChecks"]) <= set(CONTRACT_CHECKER_CODES)
        expected = {_vector_path(vector_id) for vector_id, owner, _ in VECTOR_TABLE if owner == family["id"]}
        # CONTRACT_288 section 4 (the table's vectors of this family, by exact path)
        assert set(family["vectors"]) == expected


def test_counts_agree_with_the_rows():
    """CONTRACT_288 section 3.6 (the checker recomputes each count) with sections 3.4 and 4."""
    record = _record()
    rows = _rows(record)
    counts = record["counts"]
    by_mode = Counter(row["stateMode"] for row in rows)
    leases = sum(1 for row in rows if row["lease"] is not None)
    outboxes = sum(1 for row in rows if row["outbox"] is not None)
    derived = sum(1 for row in rows if row["derivedStores"])
    boundaries = sum(1 for row in rows if row["transactionBoundary"]["value"] != UNSPECIFIED)
    guards = Counter(path["guard"]["value"] for row in rows for path in row["writePaths"])
    unspecified = Counter(member for member, valued in _valued(record) if valued["value"] == UNSPECIFIED)
    obligations = Counter(item for row in rows for item in row["obligations"])
    vectors = {family["id"]: len(family["vectors"]) for family in record["ruleFamilies"]}
    # CONTRACT_288 section 3.6 (the deployables: 24)
    assert counts["deployables"] == len(rows) == 24
    # CONTRACT_288 section 3.6 (STATEFUL 21, STATELESS_DURABLE 3)
    assert dict(by_mode) == {"STATEFUL": 21, "STATELESS_DURABLE": 3}
    # CONTRACT_288 section 3.6 (by state mode, as stated)
    assert _same(counts["byStateMode"], by_mode)
    # CONTRACT_288 section 3.6 (rows with a lease; section 3.4: 6)
    assert counts["withLease"] == leases == 6
    # CONTRACT_288 section 3.6 (rows with an outbox; section 3.4: 9)
    assert counts["withOutbox"] == outboxes == 9
    # CONTRACT_288 section 3.6 (rows with derived stores; section 3.4: 5)
    assert counts["withDerivedStores"] == derived == 5
    # CONTRACT_288 section 3.4 (four outbox lines and ingest-worker's line 963 state a transaction boundary)
    assert counts["withTransactionBoundary"] == boundaries == 5
    # CONTRACT_288 section 3.6 (the guards by value)
    assert _same(counts["guards"], guards)
    # CONTRACT_288 section 3.6 (the UNSPECIFIED values by member)
    assert _same(counts["unspecifiedByMember"], unspecified)
    # CONTRACT_288 section 3.6 (the checker recomputes each count)
    assert _same(counts["obligationsByFamily"], obligations)
    # CONTRACT_288 section 4 (the table: six RF-4 vectors, two RF-5, one for every other family)
    assert vectors == {"RF-1": 1, "RF-2": 1, "RF-3": 1, "RF-4": 6, "RF-5": 2, "RF-6": 1, "RF-7": 1}
    # CONTRACT_288 section 3.6 (the vectors by family)
    assert _same(counts["vectorsByFamily"], vectors)


def test_rows_with_lease_outbox_derived_stores_and_boundary():
    """CONTRACT_288 section 3.4 (what the catalog states today): the named lease, outbox, derived and boundary rows."""
    rows = _rows(_record())
    # CONTRACT_288 section 3.4 (a lease for six durable writers)
    assert {row["id"] for row in rows if row["lease"] is not None} == LEASE_IDS
    # CONTRACT_288 section 3.4 (an outbox for nine)
    assert {row["id"] for row in rows if row["outbox"] is not None} == OUTBOX_IDS
    # CONTRACT_288 section 3.4 (derived stores for five)
    assert {row["id"] for row in rows if row["derivedStores"]} == DERIVED_IDS
    bounded = [row for row in rows if row["transactionBoundary"]["value"] != UNSPECIFIED]
    lines = {row["transactionBoundary"]["source"]["line"] for row in bounded}
    # CONTRACT_288 section 3.4 (the effective catalog's lines 963, 1208, 1312, 1422 and 1554)
    assert lines == BOUNDARY_LINES
    catalog_based = all(row["transactionBoundary"]["source"]["basis"] == "catalog" for row in bounded)
    # CONTRACT_288 section 3.4 (catalog lines)
    assert catalog_based
    ingest = [row["transactionBoundary"]["source"]["line"] for row in bounded if row["id"] == "ingest-worker"]
    # CONTRACT_288 section 3.4 (ingest-worker's line 963)
    assert ingest == [963]
    # CONTRACT_288 section 3.4 (the other four are outbox lines)
    assert {row["id"] for row in bounded} - {"ingest-worker"} <= OUTBOX_IDS


def test_valued_members_vocabularies_and_entry_sources():
    """CONTRACT_288 section 3.4 (valued members, vocabularies, entry sources [C2-7], row members)."""
    record = _record()
    rows = _rows(record)
    member_faults = sum(1 for row in rows if set(row) != ROW_MEMBERS)
    # CONTRACT_288 section 3.4 (the row members)
    assert member_faults == 0
    sub_faults = 0
    for row in rows:
        sub_faults += sum(1 for store in row["stores"] if set(store) != {"name", "ownership"})
        sub_faults += sum(1 for path in row["writePaths"] if set(path) != {"store", "guard"})
        sub_faults += int(row["lease"] is not None and set(row["lease"]) != {"resource", "source", "fencing"})
        sub_faults += int(set(row["clock"]) != {"use", "skewMarginMs"})
        sub_faults += sum(1 for kind in row["recordKinds"] if set(kind) != {"kind", "source", "version", "window"})
        sub_faults += sum(1 for store in row["derivedStores"] if set(store) != {"store", "source", "feed", "deletion"})
        sub_faults += int(row["outbox"] is not None and set(row["outbox"]) != {"source"})
    # CONTRACT_288 section 3.4 (stores, writePaths, lease, clock, recordKinds, derivedStores and outbox members)
    assert sub_faults == 0
    mode_faults = sum(1 for row in rows if row["stateMode"] not in ("STATEFUL", "STATELESS_DURABLE"))
    # CONTRACT_288 section 3.4 (stateMode STATEFUL or STATELESS_DURABLE)
    assert mode_faults == 0
    valued = _valued(record)
    shape_faults = sum(1 for _, item in valued if not (isinstance(item, dict) and set(item) == {"value", "source"}))
    # CONTRACT_288 section 3.4 (a valued member is {value, source})
    assert shape_faults == 0
    rule_faults = sum(1 for _, item in valued if (item["value"] == UNSPECIFIED) != (item["source"] is None))
    # CONTRACT_288 section 3.4 (source null exactly when value is UNSPECIFIED)
    assert rule_faults == 0
    source_faults = sum(1 for _, item in valued if item["source"] is not None and not _source_ok(item["source"]))
    # CONTRACT_288 section 3.4 (a source is {basis, line, phrase}, the basis catalog or a repository path)
    assert source_faults == 0
    vocabulary = {
        "guard": GUARDS, "fencing": FENCINGS, "clockUse": CLOCK_USES, "window": WINDOWS, "feed": FEEDS,
        "deletion": DELETIONS,
    }
    vocabulary_faults = sum(1 for member, item in valued if member in vocabulary and item["value"] not in vocabulary[member])
    # CONTRACT_288 section 3.4 (the vocabularies)
    assert vocabulary_faults == 0
    skew_faults = sum(
        1 for member, item in valued
        if member == "skewMarginMs" and item["value"] != UNSPECIFIED
        and (not isinstance(item["value"], int) or isinstance(item["value"], bool))
    )
    # CONTRACT_288 section 3.4 (skewMarginMs an integer or UNSPECIFIED)
    assert skew_faults == 0
    text_faults = sum(
        1 for member, item in valued if member in ("version", "transactionBoundary") and not isinstance(item["value"], str)
    )
    # CONTRACT_288 section 3.4 (version and transactionBoundary: a string or UNSPECIFIED)
    assert text_faults == 0
    stated = sum(
        1 for member, item in valued
        if member in ("fencing", "skewMarginMs", "version", "window") and item["value"] != UNSPECIFIED
    )
    # CONTRACT_288 section 3.4 (no line states a fencing, skew, version or window value)
    assert stated == 0
    isolation = sum(1 for member, item in valued if member == "guard" and item["value"] == "SERIALIZABLE")
    # CONTRACT_288 section 3.4 (no line states an isolation value)
    assert isolation == 0
    entry_faults = sum(1 for source in _entry_sources(record) if not _source_ok(source))
    # CONTRACT_288 section 3.4 [C2-7] (entry sources are never null)
    assert entry_faults == 0


def test_obligations_follow_the_families():
    """CONTRACT_288 section 3.4 (obligations) and section 5 (DC_FENCING, DC_DERIVED_STORES)."""
    rows = _rows(_record())
    ids = {family_id for family_id, _ in FAMILIES}
    foreign = sum(1 for row in rows if not set(row["obligations"]) <= ids)
    # CONTRACT_288 section 3.4 (the rule-family ids that apply)
    assert foreign == 0
    unfenced = sum(1 for row in rows if row["lease"] is not None and "RF-2" not in row["obligations"])
    # CONTRACT_288 section 5 (DC_FENCING: a lease implies RF-2 in the obligations)
    assert unfenced == 0
    underived = sum(1 for row in rows if row["derivedStores"] and "RF-6" not in row["obligations"])
    # CONTRACT_288 section 5 (DC_DERIVED_STORES: RF-6 in the obligations)
    assert underived == 0


def test_members_schema_pin_and_basis():
    """CONTRACT_288 sections 3.1 (closed members, schemaVersion, the schema pin) and 3.2 (the basis)."""
    record = _record()
    raw_digest = _sha(_bytes(CATALOG))
    # CONTRACT_288 section 3.1 (no other member)
    assert set(record) == TOP_MEMBERS
    # CONTRACT_288 section 3.1
    assert record["schemaVersion"] == "harness.planeon.ai/data-correctness/v1"
    # CONTRACT_288 section 3.1 ({path, sha256} of the schema beside it)
    assert record["schema"] == {"path": SCHEMA, "sha256": _sha(_bytes(SCHEMA))}
    basis = record["basis"]
    # CONTRACT_288 section 3.2
    assert set(basis) == {"catalog", "serviceEdges", "authorityMap"}
    catalog = basis["catalog"]
    # CONTRACT_288 section 3.2
    assert set(catalog) == {"view", "sha256", "services", "dependencyEntries", "parity"}
    # CONTRACT_288 section 3.2 (EFFECTIVE, 28 services, 129 dependency entries, RAW_EQUALS_EFFECTIVE)
    assert (catalog["view"], catalog["services"], catalog["dependencyEntries"], catalog["parity"]) == (
        "EFFECTIVE", 28, 129, "RAW_EQUALS_EFFECTIVE"
    )
    hex_digest = isinstance(catalog["sha256"], str) and len(catalog["sha256"]) == 64 and set(catalog["sha256"]) <= set(
        "0123456789abcdef"
    )
    # CONTRACT_288 section 3.2 (the effective catalog bytes' digest)
    assert hex_digest
    # CONTRACT_288 section 3.2 (the basis pins the effective digest, never a raw catalog digest)
    assert catalog["sha256"] != raw_digest
    # CONTRACT_288 section 3.2 (287's service-edge record)
    assert basis["serviceEdges"] == {"path": SERVICE_EDGES, "sha256": _sha(_bytes(SERVICE_EDGES))}
    # CONTRACT_288 section 3.2 (the authority map and its AM-02 budget row)
    assert basis["authorityMap"] == {"path": AUTHORITY_MAP, "sha256": _sha(_bytes(AUTHORITY_MAP)), "budgetRow": "AM-02"}


def test_operation_ids():
    """CONTRACT_288 section 3.5 (RF-4): members, binds, outcome terms, tool effect classes, 287's counts."""
    ops = _record()["operationIds"]
    # CONTRACT_288 section 3.5 (the operationIds members)
    assert set(ops) == {
        "origin", "shape", "propagation", "receiptKey", "native", "none", "outcomes", "toolEffectClasses", "edges"
    }
    # CONTRACT_288 section 3.5 (receiptKey binds NON_IDEMPOTENT, IRREVERSIBLE)
    assert set(ops["receiptKey"]["binds"]) == {"NON_IDEMPOTENT", "IRREVERSIBLE"}
    # CONTRACT_288 section 3.5 (native binds IDEMPOTENT_WRITE)
    assert set(ops["native"]["binds"]) == {"IDEMPOTENT_WRITE"}
    # CONTRACT_288 section 3.5 (none binds NON_IDEMPOTENT, IRREVERSIBLE)
    assert set(ops["none"]["binds"]) == {"NON_IDEMPOTENT", "IRREVERSIBLE"}
    # CONTRACT_288 section 3.5 (READ, IDEMPOTENT_WRITE, NON_IDEMPOTENT, IRREVERSIBLE)
    assert [item["class"] for item in ops["toolEffectClasses"]] == ["READ", "IDEMPOTENT_WRITE", "NON_IDEMPOTENT", "IRREVERSIBLE"]
    consequences = all(item.get("retry") and item.get("approval") for item in ops["toolEffectClasses"])
    # CONTRACT_288 section 3.5 (each with its retry and approval consequence)
    assert consequences
    outcomes = ops["outcomes"]
    # CONTRACT_288 section 3.5 (the five terms accepted, committed, final, unknown and rejected)
    assert ["accepted", "committed", "final", "unknown", "rejected"] in list(outcomes.values())
    text = json.dumps(outcomes)
    # CONTRACT_288 section 3.5 (cited from BNK-UC-1 rule 10, owner EFFECT-ADAPTER-001)
    assert "BNK-UC-1 rule 10" in text and "EFFECT-ADAPTER-001" in text
    edges = ops["edges"]
    # CONTRACT_288 section 3.5 (129 edges carrying 130 operation classes)
    assert (edges["edges"], edges["operationClasses"]) == (129, 130)
    # CONTRACT_288 section 3.5 (NATIVE 73, NONE 57, RECEIPT_KEY 0)
    assert edges["byIdempotency"] == {"NATIVE": 73, "NONE": 57, "RECEIPT_KEY": 0}
    # CONTRACT_288 section 3.5 (per edge 72 NATIVE, 56 NONE and 1 split)
    assert edges["perEdge"] == {"NATIVE": 72, "NONE": 56, "SPLIT": 1}
    split = json.dumps(edges.get("splitEdges"))
    # CONTRACT_288 section 3.5 (ai-gateway to inference-api splits NATIVE and NONE)
    assert "ai-gateway" in split and "inference-api" in split


def test_record_strings_name_no_catalog():
    """CONTRACT_288 section 3.1 (DC_SHAPE): no record string contains the catalog path or equals its basename."""
    basename = CATALOG.rsplit("/", 1)[1]
    hits = sum(1 for text in _strings(_record()) if CATALOG in text or text == basename)
    # CONTRACT_288 section 3.1
    assert hits == 0


def test_no_catalog_path_or_raw_digest(relative):
    """CONTRACT_288 sections 3.1, 8 (E2) and 13: no non-.py file 288 adds under architecture/ names the catalog or its digest."""
    data = _bytes(relative)
    names_catalog = CATALOG.encode("ascii") in data
    # CONTRACT_288 section 13 (no catalog path; section 3.1 for the record)
    assert not names_catalog
    holds_digest = _sha(_bytes(CATALOG)).encode("ascii") in data
    # CONTRACT_288 section 8 (E2: the base digests live in scripts/validate_met_007.py, never in a non-.py record)
    assert not holds_digest


test_no_catalog_path_or_raw_digest = pytest.mark.parametrize(
    "relative", NEW_ARCHITECTURE_FILES, ids=[path.rsplit("/", 1)[1] for path in NEW_ARCHITECTURE_FILES]
)(test_no_catalog_path_or_raw_digest)


# ---------------------------------------------------------------------------------------------------------------------
# 2. The valued form (section 3.1 and 3.4) and 3. the checker's codes (section 5).


def test_valued_form_refused(case):
    """CONTRACT_288 sections 3.1 and 3.4 (the valued form; entry sources never null) and section 5 (DC_SHAPE)."""
    _, accepted, mutate = case
    record = _record()
    mutate(record)
    codes = _codes(_check(record))
    # CONTRACT_288 section 5 (each code one of DC_SHAPE to DC_VECTORS)
    assert set(codes) <= set(CONTRACT_CHECKER_CODES)
    # CONTRACT_288 section 5 (DC_SHAPE: the valued-member rule)
    assert set(codes) & set(accepted)


test_valued_form_refused = pytest.mark.parametrize(
    "case", VALUED_MUTATIONS, ids=[case[0] for case in VALUED_MUTATIONS]
)(test_valued_form_refused)


def test_checker_refuses_each_code(case):
    """CONTRACT_288 section 5: for each checker code, a mutation the contract refuses, the refusals naming that code."""
    _, accepted, mutate = case
    record = _record()
    extra = mutate(record)
    codes = _codes(_check(record, extra))
    # CONTRACT_288 section 5 (each code one of DC_SHAPE to DC_VECTORS)
    assert set(codes) <= set(CONTRACT_CHECKER_CODES)
    # CONTRACT_288 section 5 (the refusals name the mutated rule's code)
    assert set(codes) & set(accepted)


test_checker_refuses_each_code = pytest.mark.parametrize(
    "case", CHECKER_MUTATIONS, ids=[case[0] for case in CHECKER_MUTATIONS]
)(test_checker_refuses_each_code)


def test_every_checker_code_has_its_own_mutation():
    """CONTRACT_288 section 5: the mutation table names every checker code, DC_SHAPE to DC_VECTORS, by itself."""
    named = {accepted[0] for _, accepted, _ in CHECKER_MUTATIONS if len(accepted) == 1}
    # CONTRACT_288 section 5
    assert named == set(CONTRACT_CHECKER_CODES)


# ---------------------------------------------------------------------------------------------------------------------
# 4. The model (sections 3.3, 4 and 5).


def test_vector_replays_to_the_table(case):
    """CONTRACT_288 section 4 (the thirteen vectors) and section 5 (replay): each file and its replay match the table."""
    vector_id, family, expected = case
    vector = json.loads(_bytes(_vector_path(vector_id)))
    # CONTRACT_288 section 4 ({id, family, setup, steps, expect})
    assert set(vector) == {"id", "family", "setup", "steps", "expect"}
    # CONTRACT_288 section 4 (the table's family and expectation)
    assert (vector["id"], vector["family"], vector["expect"]) == (vector_id, family, expected)
    # CONTRACT_288 section 4 (the model replays the vector to the table's outcome)
    assert MODEL.replay(vector) == expected


test_vector_replays_to_the_table = pytest.mark.parametrize(
    "case", VECTOR_TABLE, ids=[case[0] for case in VECTOR_TABLE]
)(test_vector_replays_to_the_table)


def test_every_model_code_is_refused_by_a_vector():
    """CONTRACT_288 sections 4 and 5: the thirteen vectors' replays refuse with every model code."""
    seen = set()
    for vector_id, _, _ in VECTOR_TABLE:
        outcome = MODEL.replay(json.loads(_bytes(_vector_path(vector_id))))
        if isinstance(outcome, dict):
            seen.add(outcome.get("refuse"))
    # CONTRACT_288 section 5 (DC_WRITE_SKEW to DC_REPLAY_STATE)
    assert seen == set(CONTRACT_MODEL_CODES)


def test_malformed_vector_raises(make):
    """CONTRACT_288 section 4 (the vector form; operator-stated: a malformed vector raises ValueError)."""
    vector = make()
    # CONTRACT_288 section 4
    with pytest.raises(ValueError):
        MODEL.replay(vector)


test_malformed_vector_raises = pytest.mark.parametrize(
    "make", [_malformed_unknown_op, _malformed_missing_steps], ids=["unknown-op", "missing-steps"]
)(test_malformed_vector_raises)


def test_built_vector_outcome(case):
    """CONTRACT_288 sections 3.3 and 4: a vector built from each family's words replays to the outcome the contract fixes."""
    vector_id, family, setup, steps, expected = case
    vector = {"id": vector_id, "family": family, "setup": copy.deepcopy(setup), "steps": copy.deepcopy(steps),
              "expect": copy.deepcopy(expected)}
    # CONTRACT_288 section 3.3 (the family's rule; section 4: ACCEPT or the family's model code)
    assert MODEL.replay(vector) == expected


test_built_vector_outcome = pytest.mark.parametrize(
    "case", BUILT_VECTORS, ids=[case[0] for case in BUILT_VECTORS]
)(test_built_vector_outcome)


def test_built_vectors_cover_every_family():
    """CONTRACT_288 section 3.3: at least one built vector per rule family, RF-1 to RF-7."""
    # CONTRACT_288 section 3.3
    assert {case[1] for case in BUILT_VECTORS} == {family_id for family_id, _ in FAMILIES}


# ---------------------------------------------------------------------------------------------------------------------
# 5. The head layer (section 8): V1, E1, E2, E3, E4, V4, V5 and V6.


def test_v1_packet_files_live_and_pinned():
    """CONTRACT_288 section 8 (V1) and section 8.1: the packet's files by digest, the new reader digest among them."""
    required = {RECORD, SCHEMA, MODEL_FILE, CHECKER_FILE, MODEL_TESTS, RULE_288, REGISTRATION_288, READER}
    required |= {_vector_path(vector_id) for vector_id, _, _ in VECTOR_TABLE}
    missing = sorted(required - set(HEAD.PACKET_FILES))
    # CONTRACT_288 section 8 (V1's files; section 8.1: 288's head pins the new reader digest among its packet files)
    assert missing == []
    old_reader = _sha(_bytes(READER)).startswith("9d5d2a36")
    # CONTRACT_288 section 8.1 (286's and 287's heads keep 9d5d2a36 at their era; 288's reader is new)
    assert not old_reader
    # CONTRACT_288 section 8 (V1 passes on the live bytes)
    assert HEAD.check_packet_files(_packet_files()) is None


def test_v1_refuses_a_changed_file(relative):
    """CONTRACT_288 section 8 (V1): a packet file whose bytes leave their pinned digest is refused."""
    files = _packet_files()
    files[relative] = files[relative] + b"\n"
    # CONTRACT_288 section 8 (V1)
    with pytest.raises(ValueError, match="MET-007"):
        HEAD.check_packet_files(files)


test_v1_refuses_a_changed_file = pytest.mark.parametrize(
    "relative", [RECORD, _vector_path("rf1-concurrent-reservations"), CHECKER_FILE, READER],
    ids=["record", "vector", "checker", "reader"],
)(test_v1_refuses_a_changed_file)


def test_e1_live():
    """CONTRACT_288 section 8 (E1): every vector replays to its expectation and the record passes the checker."""
    # CONTRACT_288 section 4 (the thirteen vectors by exact path)
    assert sorted(HEAD.VECTORS) == sorted(_vector_path(vector_id) for vector_id, _, _ in VECTOR_TABLE)
    # CONTRACT_288 section 8 (E1)
    assert HEAD.check_correctness(_replays(), _live_refusals()) is None


def test_e1_refuses(name):
    """CONTRACT_288 section 8 (E1): a wrong replay outcome, a vector the model refuses, or a checker refusal is refused."""
    replays = _replays()
    refusals = list(_live_refusals())
    first = list(HEAD.VECTORS)[0]
    if name == "outcome-flipped":
        replays[first] = _refuse("DC_OPID") if replays[first] == ACCEPT else ACCEPT
    elif name == "model-refuses-vector":
        replays[first] = None
    else:
        refusals = refusals + [("DC_COUNTS", "oracle mutation")]
    # CONTRACT_288 section 8 (E1)
    with pytest.raises(ValueError, match="MET-007"):
        HEAD.check_correctness(replays, refusals)


test_e1_refuses = pytest.mark.parametrize(
    "name", ["outcome-flipped", "model-refuses-vector", "checker-refusal"]
)(test_e1_refuses)


def test_e2_live_and_base_set():
    """CONTRACT_288 section 8 (E2) and section 1: the seven base files equal their base bytes; none is changed or new."""
    base = set(HEAD.BASE_FILES)
    # CONTRACT_288 section 8 (E2: catalog, graph, two catalog schemas, service-edge record, repositories.yaml, its schema)
    assert len(base) == 7
    # CONTRACT_288 section 8 (E2)
    assert {CATALOG, SERVICE_EDGES, "architecture/repositories.yaml", "schemas/repositories.schema.json"} <= base
    authority = _authority()
    claimed = sum(1 for path in base if path in authority["changedFiles"] or path in authority["newFiles"])
    # CONTRACT_288 section 1 (no edit of these files in 288)
    assert claimed == 0
    # CONTRACT_288 section 8 (E2 passes on the live bytes)
    assert HEAD.check_base_files(_base_files(), authority["changedFiles"], authority["newFiles"]) is None


def test_e2_refuses_a_changed_base_file(relative):
    """CONTRACT_288 section 8 (E2): a base file whose bytes differ from the base is refused."""
    files = _base_files()
    files[relative] = files[relative] + b"\n"
    authority = _authority()
    # CONTRACT_288 section 8 (E2)
    with pytest.raises(ValueError, match="MET-007"):
        HEAD.check_base_files(files, authority["changedFiles"], authority["newFiles"])


test_e2_refuses_a_changed_base_file = pytest.mark.parametrize(
    "relative", [CATALOG, SERVICE_EDGES, "architecture/repositories.yaml"],
    ids=["catalog", "service-edges", "repositories-yaml"],
)(test_e2_refuses_a_changed_base_file)


def _spans_ok(spans):
    try:
        items = list(spans)
    except TypeError:
        return False
    if not items:
        return False
    for span in items:
        if len(span) != 2:
            return False
        first, last = span
        if not (isinstance(first, int) and isinstance(last, int) and 1 <= first <= last):
            return False
    return True


def test_e3_live_and_errata_files():
    """CONTRACT_288 section 8 (E3) and section 9: class other only on section 9's files; E3 passes on the live inputs."""
    errata = HEAD.ERRATA_LINES
    classes = _hunk_record()["classes"]
    changed = _changed()
    allowed = set(SECTION9_REQUIRED) | set(SECTION9_READER_FILES)
    # CONTRACT_288 section 9 (each authored edit is named in E3's ERRATA_LINES)
    assert sorted(set(SECTION9_REQUIRED) - set(errata)) == []
    outside = sum(1 for path in errata if path not in allowed)
    # CONTRACT_288 section 9 (ERRATA_LINES names only section 9's authored files)
    assert outside == 0
    bad_spans = sum(1 for path in errata if not _spans_ok(errata[path]))
    # CONTRACT_288 section 8 (E3 [R4-D8]: one or more (first, last) base-line spans per file)
    assert bad_spans == 0
    stray = sum(1 for path, items in classes.items() if "other" in items and path not in errata)
    # CONTRACT_288 section 8 (E3: class-other hunks fall only on the files of section 9)
    assert stray == 0
    uneven = sum(
        1 for path, items in classes.items()
        if path not in changed or len(items) != len(changed[path].get("reverseHunks") or [])
    )
    # CONTRACT_288 section 8 (E3; operator-stated: one class per reverse hunk)
    assert uneven == 0
    # CONTRACT_288 section 8 (E3 passes on the live inputs)
    assert HEAD.check_errata(classes, changed, _befores()) is None


def test_e3_named_lines_covered(entry):
    """CONTRACT_288 section 9: each authored edit's named base lines lie inside its ERRATA_LINES spans."""
    relative, lines = entry
    spans = HEAD.ERRATA_LINES.get(relative, ())
    uncovered = [line for line in lines if not any(first <= line <= last for first, last in spans)]
    # CONTRACT_288 section 9 (the authored edits at their named lines)
    assert uncovered == []


test_e3_named_lines_covered = pytest.mark.parametrize(
    "entry", NAMED_LINES, ids=[entry[0].rsplit("/", 1)[1] for entry in NAMED_LINES]
)(test_e3_named_lines_covered)


def test_e3_refuses_other_on_a_mechanics_file():
    """CONTRACT_288 section 8 (E3) and section 9: an "other" hunk on a mechanics file is refused."""
    classes = _hunk_record()["classes"]
    eligible = (
        MECHANICS_FILE in classes and MECHANICS_FILE not in HEAD.ERRATA_LINES and bool(classes[MECHANICS_FILE])
        and "other" not in classes[MECHANICS_FILE]
    )
    # CONTRACT_288 section 9 (construction: the YAML corpus count's file is mechanics, never authored)
    assert eligible
    classes[MECHANICS_FILE][0] = "other"
    # CONTRACT_288 section 8 (E3: class other only on section 9's authored files)
    with pytest.raises(ValueError, match="MET-007"):
        HEAD.check_errata(classes, _changed(), _befores())


def test_e3_refuses_other_hunk_outside_named_lines():
    """CONTRACT_288 section 8 (E3) and section 9: an "other" hunk on an authored file, outside its named lines, is refused."""
    errata = HEAD.ERRATA_LINES
    befores = dict(_befores())
    classes = _hunk_record()["classes"]
    changed = copy.deepcopy(_changed())
    target = None
    for candidate in OUT_OF_SPAN_CANDIDATES:
        if candidate in errata and candidate in classes and candidate in changed and candidate in befores:
            last_named = max(span[1] for span in errata[candidate])
            if befores[candidate].count(b"\n") > last_named + 1:
                target = candidate
                break
    # CONTRACT_288 section 9 (construction: an authored file whose named lines end before its last line)
    assert target is not None
    inserted = b"# oracle line outside every named span\n"
    hunk = {"at": len(_bytes(target)), "removeBase64": "", "insertBase64": base64.b64encode(inserted).decode("ascii")}
    hunks = changed[target]["reverseHunks"]
    if len(hunks) < 2 or hunks[0]["at"] <= hunks[-1]["at"]:
        hunks.append(hunk)
        classes[target].append("other")
    else:
        hunks.insert(0, hunk)
        classes[target].insert(0, "other")
    befores[target] = befores[target] + inserted
    changed[target]["beforeSha256"] = _sha(befores[target])
    # CONTRACT_288 section 8 (E3: class-other hunks fall only at the named lines)
    with pytest.raises(ValueError, match="MET-007"):
        HEAD.check_errata(classes, changed, befores)


def test_e4_raw_counts_and_live():
    """CONTRACT_288 section 8 (E4) and sections 3.2 and 13: raw == effective, 28 services and 129 entries, in order."""
    catalog = _catalog()
    services = catalog["services"]
    # CONTRACT_288 section 13 (raw == effective: 28 services)
    assert len(services) == 28
    entries = sum(len(service.get("dependencies") or []) for service in services)
    # CONTRACT_288 section 13 (raw == effective: 129 dependency entries)
    assert entries == 129
    # CONTRACT_288 section 8 (E4 passes on the live inputs)
    assert HEAD.check_parity(copy.deepcopy(catalog), _record()["basis"]["catalog"], _live_refusals()) is None


def test_e4_refuses(name):
    """CONTRACT_288 section 8 (E4): a raw catalog that leaves the effective names or entries, in order, is refused."""
    catalog = copy.deepcopy(_catalog())
    basis = copy.deepcopy(_record()["basis"]["catalog"])
    refusals = list(_live_refusals())
    services = catalog["services"]
    if name == "drop-last-service":
        services.pop()
    elif name == "swap-first-services":
        raw = _bytes(CATALOG)
        marker = b"\nservices:\n"
        # CONTRACT_288 section 8 (E4 row; construction: the catalog holds one top-level services list)
        assert raw.count(marker) == 1
        first = raw.index(marker) + len(marker)
        second = raw.index(b"\n  - id: ", first) + 1
        third = raw.index(b"\n  - id: ", second) + 1
        swapped = raw[:first] + raw[second:third] + raw[first:second] + raw[third:]
        catalog = HEAD.safe_load(swapped.decode("utf-8"))
        expected_order = [service["id"] for service in services]
        expected_order[0], expected_order[1] = expected_order[1], expected_order[0]
        # CONTRACT_288 section 8 (E4 row; construction: the served bytes swap exactly the first two services)
        assert [service["id"] for service in catalog["services"]] == expected_order
        refusals = list(CHECKER.check(_reader({CATALOG: swapped}), _packets()))
        # CONTRACT_288 section 8 (E4 row: the era checker's DC_BASIS over the swapped bytes establishes the order)
        assert "DC_BASIS" in _codes(refusals)
    elif name == "drop-a-dependency":
        for service in services:
            if service.get("dependencies"):
                service["dependencies"].pop(0)
                break
    elif name == "basis-services":
        basis["services"] = 27
    else:
        refusals = refusals + [("DC_BASIS", "oracle mutation")]
    # CONTRACT_288 section 8 (E4)
    with pytest.raises(ValueError, match="MET-007"):
        HEAD.check_parity(catalog, basis, refusals)


test_e4_refuses = pytest.mark.parametrize(
    "name", ["drop-last-service", "swap-first-services", "drop-a-dependency", "basis-services", "checker-refusal"]
)(test_e4_refuses)


def test_v4_live():
    """CONTRACT_288 section 8 (V4) and sections 9 and 11: the registry briefs.json differs from the base by one rider."""
    # CONTRACT_288 section 11 (GATE_REVIEW_PROCESS: architecture/review-record/briefs.json)
    assert HEAD.REGISTRY_PATH == REGISTRY
    attested = bool((_changed().get(REGISTRY) or {}).get("reverseHunks"))
    # CONTRACT_288 section 9 (the rider in briefs.json, an attested file)
    assert attested
    # CONTRACT_288 section 8 (V4 passes on the live bytes)
    assert HEAD.check_registry(_bytes(REGISTRY), {HEAD.PACKET_BRIEF: _bytes(HEAD.PACKET_BRIEF)}) is None


def test_v4_refuses(name):
    """CONTRACT_288 section 8 (V4): a registry without the rider, or with a second difference, is refused."""
    raw = _bytes(REGISTRY)
    briefs = {HEAD.PACKET_BRIEF: _bytes(HEAD.PACKET_BRIEF)}
    if name == "registry-without-rider":
        raw = HEAD._undo_this_layer(REGISTRY, raw)
    else:
        data = json.loads(raw)
        if isinstance(data, dict):
            data["zzOracleExtra"] = "a second difference"
        else:
            data.append({"zzOracleExtra": "a second difference"})
        raw = _dumper(_bytes(REGISTRY))(data)
    # CONTRACT_288 section 8 (V4)
    with pytest.raises(ValueError, match="MET-007") as caught:
        HEAD.check_registry(raw, briefs)
    names_rider = "the MET-007 packet rider" in str(caught.value)
    # CONTRACT_288 section 8 (V4; operator-stated: its message names the MET-007 packet rider)
    assert names_rider


test_v4_refuses = pytest.mark.parametrize(
    "name", ["registry-without-rider", "registry-with-second-difference"]
)(test_v4_refuses)


def test_v5_product_form():
    """CONTRACT_288 section 7: LAB-SYNC-001 in LAB-REPO-001's 16-key form, its six commands inherited in order."""
    # CONTRACT_288 section 8 (V5: the product LAB-SYNC-001)
    assert set(HEAD.PRODUCT_PACKETS) == {PRODUCT}
    product = _yaml("task-packets/" + PRODUCT + ".yaml")
    comparator = _yaml("task-packets/" + COMPARATOR + ".yaml")
    # CONTRACT_288 section 7 (the 16-key form)
    assert set(product) == PRODUCT_KEYS
    # CONTRACT_288 section 7 (R00 writes id LAB-SYNC-001)
    assert product["id"] == PRODUCT
    # CONTRACT_288 section 7 (predecessors LAB-REPO-001)
    assert product["predecessors"] == [COMPARATOR]
    # CONTRACT_288 section 7 (allowedPaths research/)
    assert product["allowedPaths"] == ["research/"]
    excluded = product["excluded"]
    one_item = isinstance(excluded, list) and len(excluded) == 1 and isinstance(excluded[0], str)
    # CONTRACT_288 section 7 (excluded is a one-item list whose item is a string)
    assert one_item
    # CONTRACT_288 section 7 (the nine expectedEvidence lines)
    assert len(product["expectedEvidence"]) == 9
    branch = str(product["branch"])
    # CONTRACT_288 section 7 [R4-OQ4] (codex/lab-sync- and a short hash, not codex/lab-sync-001)
    assert branch.startswith("codex/lab-sync-") and not branch.startswith("codex/lab-sync-001")
    is_r13 = str(product["repository"]).split("/")[-1] == "mas-harness-research-lab"
    # CONTRACT_288 section 1 (part C names R13's PR as a LAB packet)
    assert is_r13
    commands = product["offlineAcceptanceCommands"]
    # CONTRACT_288 section 7 (the six commands)
    assert len(commands) == 6
    inherited = commands == comparator["offlineAcceptanceCommands"]
    # CONTRACT_288 section 7 (inherited from LAB-REPO-001 byte-exact and in order, under R13)
    assert inherited


def test_v5_allowed_names():
    """CONTRACT_288 section 6: R8 clause 2's names at slot 288 (the twelve, R13 from 284, R14 from 288)."""
    allowed = set(HEAD._allowed_names())
    # CONTRACT_288 section 6 (the twelve before 284, R13 from 284, R14 from 288)
    assert len(allowed) == 14
    # CONTRACT_288 section 6 (allowedNames from slot 288 add mas-harness-reference-lab; R13 since 284)
    assert {"mas-harness-research-lab", "mas-harness-reference-lab"} <= allowed


def test_v5_live():
    """CONTRACT_288 section 8 (V5): the product's YAML by digest, its comparator's pin with R13 inheritance, R8 clause 2."""
    # CONTRACT_288 section 8 (V5 passes on the live bytes)
    assert HEAD.check_products(_product_raws(), _comparators(), _authority(), HEAD._allowed_names()) is None


def test_v5_refuses(name):
    """CONTRACT_288 section 8 (V5): swapped commands, changed product or comparator bytes, or a missing name is refused."""
    raws = _product_raws()
    comparators = _comparators()
    allowed = HEAD._allowed_names()
    if name == "commands-swapped":
        swapped_bytes, commands, swapped = _swap_commands(raws[PRODUCT])
        distinct = commands[0] != commands[1]
        # CONTRACT_288 section 7 (construction: the six commands differ, so a swap changes their order)
        assert distinct
        parsed = HEAD.safe_load(swapped_bytes.decode("utf-8"))["offlineAcceptanceCommands"] == swapped
        # CONTRACT_288 section 7 (construction: the swapped product still parses with the swapped order)
        assert parsed
        raws = {PRODUCT: swapped_bytes}
    elif name == "product-bytes":
        raws = {PRODUCT: raws[PRODUCT] + b"\n"}
    elif name == "comparator-bytes":
        comparators = {PRODUCT: comparators[PRODUCT] + b"\n"}
    else:
        repository = str(_yaml("task-packets/" + PRODUCT + ".yaml")["repository"]).split("/")[-1]
        kept = [item for item in allowed if item != repository]
        removed = len(kept) == len(list(allowed)) - 1
        # CONTRACT_288 section 7 (construction: R8 clause 2 admits the product's repository through the allowed names)
        assert removed
        if isinstance(allowed, frozenset):
            allowed = frozenset(kept)
        elif isinstance(allowed, set):
            allowed = set(kept)
        else:
            allowed = type(allowed)(kept)
    # CONTRACT_288 section 8 (V5)
    with pytest.raises(ValueError, match="MET-007"):
        HEAD.check_products(raws, comparators, _authority(), allowed)


test_v5_refuses = pytest.mark.parametrize(
    "name", ["commands-swapped", "product-bytes", "comparator-bytes", "allowed-without-repository"]
)(test_v5_refuses)


def test_v6_live_record_facts():
    """CONTRACT_288 section 8 (V6), 8.1 and 9: v2.5's rule digest, steps [1, 2], countPairs [[315, 317]], no outcome."""
    record = _hunk_record()
    # CONTRACT_288 section 8 (the hunk-class record architecture/chain-checkpoint/hunk-classes/288.json)
    assert HEAD.HUNK_RECORD_PATH == HUNK_RECORD
    # CONTRACT_288 section 8 (V6: hunkClassRuleSha256 = RULE_V25_SHA256)
    assert record["hunkClassRuleSha256"] == HEAD.HUNK_RULE_SHA256
    pinned = str(HEAD.HUNK_RULE_SHA256).encode("ascii") in _bytes(READER)
    # CONTRACT_288 section 8.1 (RULE_V25_SHA256 in ci/chain_checkpoint.py pins the rule)
    assert pinned
    reader_path = str(HEAD.READER_PATH).replace("\\", "/").endswith(READER)
    # CONTRACT_288 section 8.1 (the classes are read under the reader ci/chain_checkpoint.py)
    assert reader_path
    steps = [_at(record, trail) for trail in _locations(record, _is_steps)]
    # CONTRACT_288 section 1 (the v2.5 reader's steps are [1, 2])
    assert steps and all(value == [1, 2] for value in steps)
    pairs = [_at(record, trail) for trail in _locations(record, lambda key: key == "countPairs")]
    # CONTRACT_288 section 9 (countPairs [[315, 317]])
    assert pairs and all(value == [[315, 317]] for value in pairs)
    outcomes = [_at(record, trail) for trail in _locations(record, lambda key: key == "outcomeStatements")]
    # CONTRACT_288 section 8 (V6: outcomeStatements [])
    assert outcomes and all(value == [] for value in outcomes)
    # CONTRACT_288 section 8 (V6 passes on the live inputs)
    assert _v6(_hunk_raw()) is None


def test_v6_refuses(name):
    """CONTRACT_288 section 8 (V6): an extra member, an unknown class, another rule digest, steps, pairs or outcomes."""
    record = _hunk_record()
    if name == "extra-member":
        record["zzOracleExtra"] = 1
    elif name == "unknown-class":
        path = sorted(path for path, items in record["classes"].items() if items)[0]
        record["classes"][path][0] = "zz-oracle-class"
    elif name == "rule-digest":
        record["hunkClassRuleSha256"] = "0" * 64
    elif name == "steps":
        _put(record, _locations(record, _is_steps)[0], [1])
    elif name == "count-pairs":
        _put(record, _locations(record, lambda key: key == "countPairs")[0], [[315, 316]])
    else:
        _put(record, _locations(record, lambda key: key == "outcomeStatements")[0], ["zz oracle outcome statement"])
    raw = _memo("hunk_dumper", lambda: _dumper(_hunk_raw()))(record)
    # CONTRACT_288 section 8 (V6)
    with pytest.raises(ValueError, match="MET-007"):
        _v6(raw)


test_v6_refuses = pytest.mark.parametrize(
    "name", ["extra-member", "unknown-class", "rule-digest", "steps", "count-pairs", "outcome-statement"]
)(test_v6_refuses)


def test_authority_form_and_product_pins():
    """CONTRACT_288 sections 7 and 8: the ten-member K = 1 authority naming the product and LAB-REPO-001's pin."""
    authority = _authority()
    # CONTRACT_288 section 8 (284's ten-member K = 1 form)
    assert len(authority) == 10
    # CONTRACT_288 section 8 (operator-stated members)
    assert {"changedFiles", "newFiles", "productPackets", "productComparators"} <= set(authority)
    products = json.dumps(authority["productPackets"], sort_keys=True)
    names_product = PRODUCT in products and _sha(_bytes("task-packets/" + PRODUCT + ".yaml")) in products
    # CONTRACT_288 section 7 (productPackets names LAB-SYNC-001 by its YAML digest)
    assert names_product
    comparator_digest = _sha(_bytes("task-packets/" + COMPARATOR + ".yaml"))
    # CONTRACT_288 section 7 (LAB-REPO-001.yaml's sha256 8ae5c7fd)
    assert comparator_digest.startswith("8ae5c7fd")
    comparators = json.dumps(authority["productComparators"], sort_keys=True)
    maps_pin = PRODUCT in comparators and comparator_digest in comparators
    # CONTRACT_288 section 7 (productComparators maps LAB-SYNC-001 to LAB-REPO-001's pin)
    assert maps_pin


def test_authority_digests_match_the_tree():
    """CONTRACT_288 section 8 (the authority; operator-stated changedFiles and newFiles): digests match the tree."""
    authority = _authority()
    after_faults = 0
    before_faults = 0
    for path, entry in authority["changedFiles"].items():
        raw = _bytes(path)
        after_faults += int(_sha(raw) != entry["afterSha256"])
        if entry.get("reverseHunks"):
            before_faults += int(_sha(HEAD._undo_this_layer(path, raw)) != entry["beforeSha256"])
    # CONTRACT_288 section 8 (each changed file's after digest)
    assert after_faults == 0
    # CONTRACT_288 section 8 (each changed file's before digest, from its reverse hunks)
    assert before_faults == 0
    new_faults = 0
    for path, digest in authority["newFiles"].items():
        target = ROOT / path
        new_faults += int(not target.is_file() or _sha(target.read_bytes()) != digest)
    # CONTRACT_288 section 8 (each new file by its sha256)
    assert new_faults == 0
