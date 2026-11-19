"""D5a oracle tests for slot 291, MET-009: the three plane health-shell bootstraps, the four transport successors,
the plane-shell ordering annex and the head layer's checks (V1, E3, V4, V6), at K = 7.

Owner decision D5a: a contract packet carries tests written outside the candidate, by someone who is not its
builder. These tests are black-box. Every expected value (a count, member, order, string, wording, digest prefix or
field) comes from CONTRACT_291 rev 3 (sha256 8837aa6a7381b8cbffbdb0bca648fc37f6fcec55433ff8d18d03f497b31b0333),
cited beside its assert as "CONTRACT_291 section N", or from the facts the operator states in ORACLE_BRIEF_291
about the candidate's interfaces, cited as "operator-stated". The repository files read at run time (the seven
product YAMLs, the three registered bootstraps, task-packets/MET-009.yaml, the weights table, the authority, the
hunk-class record, the registry and its packet brief, and the current bytes of the authority's changedFiles keys)
are fixtures: they are loaded and mutated as plain data and are never the source of an expected value. No digest of
the table, the head, the authority or the hunk-class record, and no head-test row value, is pinned here.
"""

import copy
import datetime
import hashlib
import importlib.util
import json
import re
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]

# Fixture locations (the brief's read list; CONTRACT_291 sections 4 to 6).
HEAD_FILE = "scripts/validate_met_009.py"
ANNEX_FILE = "scripts/validate_packet_ownership.py"
ANNEX_TEST_FILE = "tests/test_plane_shell_order.py"
HEAD_TEST_FILE = "tests/test_met_009.py"
WEIGHTS_FILE = "ci/parallel_suite_weights.json"
AUTHORITY_FILE = "architecture/plane-bootstraps-authority.json"
HUNK_RECORD_FILE = "architecture/chain-checkpoint/hunk-classes/291.json"
REGISTRY_FILE = "architecture/review-record/briefs.json"
PACKET_YAML_FILE = "task-packets/MET-009.yaml"
README_FILE = "task-packets/README.md"

# CONTRACT_291 section 1: the meta packet, its predecessor and the seven products, in order.
NEW_PACKET = "MET-009"
PREDECESSOR = "MET-PERF-050"
PRODUCTS = (
    "PLANE-BOOTSTRAP-R05",
    "PLANE-BOOTSTRAP-R06",
    "PLANE-BOOTSTRAP-R08",
    "DIST-TRANSPORT-002A",
    "CTRL-TRANSPORT-002A",
    "IND-TRANSPORT-001A",
    "LAB-TRANSPORT-001",
)
SHELLS = PRODUCTS[:3]
SUCCESSORS = PRODUCTS[3:]
PRODUCT_FILES = tuple(f"task-packets/{packet}.yaml" for packet in PRODUCTS)

# CONTRACT_291 section 3: the frozen sha256 prefixes.
PREFIXES = {
    "PLANE-BOOTSTRAP-R05": "bc3ebb3b",
    "PLANE-BOOTSTRAP-R06": "880c30f2",
    "PLANE-BOOTSTRAP-R08": "f8689716",
    "DIST-TRANSPORT-002A": "6ea7de7f",
    "CTRL-TRANSPORT-002A": "b189824c",
    "IND-TRANSPORT-001A": "d1c27e92",
    "LAB-TRANSPORT-001": "b4120531",
}

# CONTRACT_291 sections 3 and 4: each registered bootstrap and its plane's health shell
# (runtime plane R05 / RUN-001, model plane R06 / MODEL-001, execution plane R08 / EXEC-001).
PAIRS = {
    "RUN-001": "PLANE-BOOTSTRAP-R05",
    "MODEL-001": "PLANE-BOOTSTRAP-R06",
    "EXEC-001": "PLANE-BOOTSTRAP-R08",
}
REGISTERED = tuple(PAIRS)
SIDES = ("registered", "shell")
ROW_SIDES = tuple((registered, side) for registered in REGISTERED for side in SIDES)
ROW_SIDE_IDS = tuple(f"{registered}-{side}" for registered, side in ROW_SIDES)

# CONTRACT_291 section 4: the annex's wordings.
TABLE_MESSAGE = "plane shell order table must hold exactly the three closed rows"
REPOSITORY_MISMATCH = "repository mismatch"

# CONTRACT_291 sections 5, 7 and 10: the weights table with the head-test row.
WEIGHT_ENTRIES = 212

# Operator-stated: the registry rider, V6's steps at K = 7 and E3's free class.
RIDER = "MET-009/packet"
STEPS = [1, 8]
OTHER_CLASS = "other"

# Paths used as mutation targets when they are eligible (names visible in the packet's own allowedPaths).
PREFERRED_PICKS = (
    "tests/test_met_007.py",
    "tests/test_met_008.py",
    "scripts/validate_met_perf_050.py",
    "scripts/validate_met_008.py",
    "tests/test_task_packets.py",
    "scripts/validate_readiness.py",
)

FILE_COUNT = re.compile(r"(?<![\w.,])(\d[\d,]*) files\b")

_FIXED_READS = frozenset(
    {WEIGHTS_FILE, AUTHORITY_FILE, HUNK_RECORD_FILE, REGISTRY_FILE, PACKET_YAML_FILE}
    | set(PRODUCT_FILES)
    | {f"task-packets/{packet}.yaml" for packet in REGISTERED}
)
_BYTES = {}
_CURRENT = {}
_PARSED = {}


# ---------------------------------------------------------------------------------------------------------------
# Helpers (plain data only)
# ---------------------------------------------------------------------------------------------------------------


def _sha(data):
    return hashlib.sha256(data).hexdigest()


def _era_read(rel):
    """Era read ([PC-1] form, MON-292-D1-ERA, Lane-Monitor as a non-author): the head's reviewed_bytes, which projects
    a bridged successor's newer bytes back first."""
    if "_met_009_oracle_era_head" not in sys.modules:
        _load("_met_009_oracle_era_head", HEAD_FILE)
    return sys.modules["_met_009_oracle_era_head"].reviewed_bytes(rel)


def _read(rel):
    """Bytes of one fixture on the brief's fixed read list, by exact path."""
    if rel not in _FIXED_READS:
        raise RuntimeError("path outside the oracle's fixed read list")
    if rel not in _BYTES:
        _BYTES[rel] = _era_read(rel)
    return _BYTES[rel]


def _current(changed, rel):
    """Current bytes of one of the authority's changedFiles keys (V6 afters, E3 befores)."""
    if rel not in changed:
        raise RuntimeError("path is not one of the authority's changedFiles keys")
    if rel not in _CURRENT:
        _CURRENT[rel] = _era_read(rel)
    return _CURRENT[rel]


def _read_brief(head):
    """Bytes of the packet brief the registry pairs with (the head's PACKET_BRIEF)."""
    return _era_read(head.PACKET_BRIEF)


def _load(name, rel):
    """Load one repository module by file path into a fresh module object under a new, unique name."""
    spec = importlib.util.spec_from_file_location(name, ROOT / rel)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


def _safe_load(head):
    """The head's own safe_load (the chain's YAML parser)."""
    load = getattr(head, "safe_load", None)
    if not callable(load):
        load = head.safe_yaml.safe_load
    return load


def _packet(head, packet_id):
    """A deep copy of one task-packet YAML parsed through the head's safe_load."""
    if packet_id not in _PARSED:
        text = _read(f"task-packets/{packet_id}.yaml").decode("utf-8")
        _PARSED[packet_id] = _safe_load(head)(text)
    return copy.deepcopy(_PARSED[packet_id])


def _same_path(value, rel):
    return Path(value) in (Path(rel), ROOT / rel)


def _flip_hex(value):
    return value[:-1] + ("1" if value[-1] == "0" else "0")


def _altered(value):
    if isinstance(value, dict):
        altered = dict(value)
        altered["oracleNote"] = "changed"
        return altered
    if isinstance(value, list):
        return [*value, "oracle"]
    if isinstance(value, str):
        return value + "-oracle"
    return "oracle"


def _replace_string(node, old, new):
    if isinstance(node, dict):
        return {(new if key == old else key): _replace_string(value, old, new) for key, value in node.items()}
    if isinstance(node, list):
        return [_replace_string(value, old, new) for value in node]
    if isinstance(node, str) and node == old:
        return new
    return node


def _find_values(node, predicate, trail=()):
    found = [trail] if predicate(node) else []
    if isinstance(node, dict):
        for key, value in node.items():
            found.extend(_find_values(value, predicate, trail + (key,)))
    elif isinstance(node, list):
        for index, value in enumerate(node):
            found.extend(_find_values(value, predicate, trail + (index,)))
    return found


def _find_keys(node, predicate, trail=()):
    found = []
    if isinstance(node, dict):
        for key, value in node.items():
            if predicate(key):
                found.append(trail + (key,))
            found.extend(_find_keys(value, predicate, trail + (key,)))
    elif isinstance(node, list):
        for index, value in enumerate(node):
            found.extend(_find_keys(value, predicate, trail + (index,)))
    return found


def _outside_classes(trails):
    return [trail for trail in trails if trail and trail[0] != "classes"]


def _get(node, trail):
    for step in trail:
        node = node[step]
    return node


def _set(node, trail, value):
    _get(node, trail[:-1])[trail[-1]] = value


def _dumps_like(raw, original, mutant):
    """Serialise a mutant in the fixture's own JSON layout when one of the usual layouts reproduces it."""
    text = raw.decode("utf-8")
    for indent in (2, 4, 1, None):
        for separators in ((None,) if indent is not None else (None, (",", ":"))):
            for sort_keys in (False, True):
                for ensure_ascii in (True, False):
                    options = {
                        "indent": indent,
                        "separators": separators,
                        "sort_keys": sort_keys,
                        "ensure_ascii": ensure_ascii,
                    }
                    rendered = json.dumps(original, **options)
                    for tail in ("\n", ""):
                        if rendered + tail == text:
                            return (json.dumps(mutant, **options) + tail).encode("utf-8")
    return (json.dumps(mutant, indent=2) + "\n").encode("utf-8")


def _picks(changed, classes, exclude=frozenset()):
    """Mutation targets: changed files with reverse hunks and a class list, outside `exclude`."""

    def eligible(path):
        return (
            path in changed
            and bool(changed[path].get("reverseHunks"))
            and path not in exclude
            and isinstance(classes.get(path), list)
            and bool(classes[path])
        )

    preferred = [path for path in PREFERRED_PICKS if eligible(path)]
    if preferred:
        return preferred[:2]
    return [path for path in sorted(classes) if eligible(path)][:1]


def _canonical_digests(packet):
    """sha256 of the sorted-key compact JSON, with and without ASCII escaping (the contract fixes neither)."""
    digests = set()
    for ensure_ascii in (True, False):
        text = json.dumps(packet, sort_keys=True, separators=(",", ":"), ensure_ascii=ensure_ascii)
        digests.add(_sha(text.encode("utf-8")))
    return digests


def _row_packets(head):
    return {packet: _packet(head, packet) for packet in (*REGISTERED, *SHELLS)}


def _expected_extra(skip=()):
    return {registered: (shell,) for registered, shell in PAIRS.items() if registered not in skip}


def _side(registered, side):
    return registered if side == "registered" else PAIRS[registered]


def _other_side(registered, side):
    return PAIRS[registered] if side == "registered" else registered


def _table_with_digest(table, registered, side, digest):
    rows = []
    for row in table:
        row = tuple(row)
        if row[1] == registered:
            cell = 2 if side == "registered" else 4
            row = row[:cell] + (digest,) + row[cell + 1:]
        rows.append(row)
    return type(table)(rows)


def _assert_row_refused(result, registered, wording):
    extra, errors = result
    errors = list(errors)
    # CONTRACT_291 section 4 (a refused row is not applied; the other rows still apply)
    assert dict(extra) == _expected_extra(skip={registered})
    # CONTRACT_291 section 4 (a row refuses at its first failing condition, with that condition's wording)
    assert len(errors) == 1
    # CONTRACT_291 section 4
    assert wording in str(errors[0])
    return str(errors[0])


def _unencodable(vector):
    """Content that sorted-key compact JSON cannot encode (CONTRACT_291 section 4, T6 wording)."""
    if vector == "date":
        return datetime.date(2026, 11, 16)
    if vector == "binary":
        return b"\x00oracle"
    if vector == "set":
        return {"oracle"}
    if vector == "mixed_keys":
        return {"oracle": 1, 7: "oracle"}
    if vector == "lone_surrogate":
        return "oracle \ud800"
    loop = {}
    loop["self"] = loop
    return loop


TABLE_VECTORS = (
    "fourth_row_duplicate",
    "fourth_row_new",
    "short",
    "empty",
    "non_string_cell",
    "list_row",
    "four_cell_row",
    "non_plane_shell",
    "swapped_shells",
    "swapped_registered",
    "non_plane_repository",
)


def _bad_table(table, vector):
    """A table that is not the three closed rows (CONTRACT_291 section 4, T5)."""
    rows = [tuple(row) for row in table]
    first, second = rows[0], rows[1]
    if vector == "fourth_row_duplicate":
        rows.append(first)
    elif vector == "fourth_row_new":
        rows.append(("oracle-plane", "ORACLE-001", "0" * 64, "PLANE-BOOTSTRAP-R99", "0" * 64))
    elif vector == "short":
        rows = rows[:2]
    elif vector == "empty":
        rows = []
    elif vector == "non_string_cell":
        rows[0] = first[:2] + (7,) + first[3:]
    elif vector == "list_row":
        rows[0] = list(first)
    elif vector == "four_cell_row":
        rows[0] = first[:4]
    elif vector == "non_plane_shell":
        rows[0] = first[:3] + ("PLANE-BOOTSTRAP-R99",) + first[4:]
    elif vector == "swapped_shells":
        rows[0] = first[:3] + second[3:]
        rows[1] = second[:3] + first[3:]
    elif vector == "swapped_registered":
        rows[0] = first[:1] + second[1:3] + first[3:]
        rows[1] = second[:1] + first[1:3] + second[3:]
    elif vector == "non_plane_repository":
        rows[0] = ("oracle-plane",) + first[1:]
    return type(table)(rows)


def _v1_files(head, changed):
    """PACKET_FILES -> bytes from the fixtures; a file outside the read list gets an empty placeholder."""
    files = {}
    placeholders = []
    for path in head.PACKET_FILES:
        if path in PRODUCT_FILES:
            files[path] = _read(path)
        elif path in changed:
            files[path] = _current(changed, path)
        else:
            files[path] = b""
            placeholders.append(path)
    return files, placeholders


def _rider_entry(registry):
    """(parent trail, step) of the registry entry that carries the rider id, or None."""
    for trail in _find_keys(registry, lambda key: key == RIDER):
        return trail[:-1], trail[-1]
    for trail in _find_values(registry, lambda value: isinstance(value, str) and value == RIDER):
        container_trail = trail[:-1]
        container = _get(registry, container_trail)
        if isinstance(container, list):
            return container_trail, trail[-1]
        if container_trail:
            return container_trail[:-1], container_trail[-1]
    return None


V4_CASES = ("rider_removed", "rider_renamed", "second_rider", "base_entry_changed")


def _v4_mutant(registry, case):
    """A registry that is not the base plus the one rider."""
    mutant = copy.deepcopy(registry)
    if case == "rider_renamed":
        return _replace_string(mutant, RIDER, RIDER + "-oracle")
    parent_trail, step = _rider_entry(registry)
    parent = _get(mutant, parent_trail)
    if case == "rider_removed":
        del parent[step]
    elif case == "second_rider":
        twin = _replace_string(copy.deepcopy(parent[step]), RIDER, "MET-009/oracle-extra")
        if isinstance(parent, list):
            parent.append(twin)
        else:
            parent["MET-009/oracle-extra" if step == RIDER else f"{step}-oracle-extra"] = twin
    else:
        steps = range(len(parent)) if isinstance(parent, list) else list(parent)
        siblings = [other for other in steps if other != step]
        if siblings:
            parent[siblings[0]] = _altered(parent[siblings[0]])
        elif isinstance(mutant, dict):
            mutant["oracleNote"] = "added"
        else:
            mutant.append("oracle")
    return mutant


V6_CASES = (
    "member_added",
    "members_dropped",
    "class_outside_vocabulary",
    "rule_digest",
    "steps",
    "count_pairs",
    "outcome_statement",
    "context_changed",
)


def _steps_trails(record):
    named = _outside_classes(_find_keys(record, lambda key: key == "steps"))
    if named:
        return named
    return _outside_classes(_find_values(record, lambda value: isinstance(value, list) and value == STEPS))


def _v6_mutants(record, changed, rule_sha, case):
    """Plain-data mutants of the hunk-class record that break one V6 condition each."""
    mutants = []
    if case == "member_added":
        mutant = copy.deepcopy(record)
        mutant["oracleExtra"] = "added"
        mutants.append(mutant)
    elif case == "members_dropped":
        for key in record:
            mutant = copy.deepcopy(record)
            del mutant[key]
            mutants.append(mutant)
    elif case == "class_outside_vocabulary":
        for path in _picks(changed, record["classes"]):
            mutant = copy.deepcopy(record)
            mutant["classes"][path] = ["oracle-unknown-class", *mutant["classes"][path][1:]]
            mutants.append(mutant)
        for trail in _outside_classes(_find_keys(record, lambda key: key == "vocabulary")):
            mutant = copy.deepcopy(record)
            _set(mutant, trail, _altered(_get(mutant, trail)))
            mutants.append(mutant)
    elif case == "rule_digest":
        for trail in _find_values(record, lambda value: isinstance(value, str) and value == rule_sha):
            mutant = copy.deepcopy(record)
            _set(mutant, trail, _flip_hex(rule_sha))
            mutants.append(mutant)
    elif case == "steps":
        for trail in _steps_trails(record):
            mutant = copy.deepcopy(record)
            _set(mutant, trail, [1, 9])
            mutants.append(mutant)
    elif case == "count_pairs":
        for trail in _outside_classes(_find_keys(record, lambda key: key == "countPairs")):
            mutant = copy.deepcopy(record)
            _set(mutant, trail, [[1, 2]])
            mutants.append(mutant)
    elif case == "outcome_statement":
        statement = "oracle outcome statement"
        trails = _outside_classes(_find_keys(record, lambda key: "outcome" in key.lower()))
        for trail in trails:
            mutant = copy.deepcopy(record)
            current = _get(mutant, trail)
            _set(mutant, trail, [statement] if isinstance(current, list) else statement)
            mutants.append(mutant)
        if not trails:
            mutant = copy.deepcopy(record)
            context_node = mutant.get("hunkClassContext")
            target = context_node if isinstance(context_node, dict) else mutant
            target["outcomeStatement"] = statement
            mutants.append(mutant)
    elif case == "context_changed":
        mutant = copy.deepcopy(record)
        mutant["hunkClassContext"] = _altered(mutant["hunkClassContext"])
        mutants.append(mutant)
    return mutants


def _weight_pairs():
    """The weights mapping's raw (key, value) pairs: the largest JSON object in the table."""
    collected = []

    def hook(pairs):
        collected.append(pairs)
        return dict(pairs)

    json.loads(_read(WEIGHTS_FILE).decode("utf-8"), object_pairs_hook=hook)
    return max(collected, key=len)


# ---------------------------------------------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------------------------------------------


@pytest.fixture(scope="module")
def head():
    return _load("_met_009_oracle_head", HEAD_FILE)


@pytest.fixture(scope="module")
def annex():
    return _load("_met_009_oracle_annex", ANNEX_FILE)


@pytest.fixture(scope="module")
def changed(head):
    return head.authority()["changedFiles"]


@pytest.fixture(scope="module")
def record():
    return json.loads(_read(HUNK_RECORD_FILE).decode("utf-8"))


@pytest.fixture(scope="module")
def v6_inputs(head, changed, record):
    raw = _read(HUNK_RECORD_FILE)
    afters = {path: _current(changed, path) for path, entry in changed.items() if entry["reverseHunks"]}
    classify = head._era_rule(head.READER_PATH, head.READER_NAME).classify
    context = head._v24_context(head.authority(), record["hunkClassContext"])
    return raw, afters, classify, context, head.HUNK_RULE_SHA256


# ---------------------------------------------------------------------------------------------------------------
# 1. The seven product YAMLs (CONTRACT_291 sections 1, 3 and 5)
# ---------------------------------------------------------------------------------------------------------------


@pytest.mark.parametrize("packet", PRODUCTS)
def test_product_yaml_frozen_prefix(packet):
    """CONTRACT_291 section 3: each product YAML's sha256 starts with its frozen prefix."""
    digest = _sha(_read(f"task-packets/{packet}.yaml"))
    # CONTRACT_291 section 3
    assert digest.startswith(PREFIXES[packet])


def test_head_product_packets_and_new_packet(head):
    """CONTRACT_291 sections 1 and 5: PRODUCT_PACKETS is section 1's seven ids in order; NEW_PACKET is MET-009."""
    # CONTRACT_291 section 1
    assert tuple(head.PRODUCT_PACKETS) == PRODUCTS
    # CONTRACT_291 section 1
    assert head.NEW_PACKET == NEW_PACKET


def test_authority_product_packets(head):
    """CONTRACT_291 sections 1, 3 and 5: the authority's productPackets names the seven, in order, each with the
    sha256 of its YAML's bytes."""
    sources = (head.authority(), json.loads(_read(AUTHORITY_FILE).decode("utf-8")))
    for source in sources:
        product_packets = source["productPackets"]
        # CONTRACT_291 section 1
        assert list(product_packets) == list(PRODUCTS)
        for packet, rel in zip(PRODUCTS, PRODUCT_FILES):
            # operator-stated (productPackets: the sha256 of each product YAML's bytes; CONTRACT_291 section 5)
            assert product_packets[packet] == _sha(_read(rel))
            # CONTRACT_291 section 3
            assert product_packets[packet].startswith(PREFIXES[packet])


def test_authority_product_comparators(head):
    """CONTRACT_291 sections 1 and 5: productComparators per product row: the four successors, in order, each
    bound to its one predecessor; the three shells have none (their predecessors are [])."""
    comparators = head.authority()["productComparators"]
    # operator-stated (the four successors, in order; CONTRACT_291 section 1)
    assert list(comparators) == list(SUCCESSORS)
    for packet in SHELLS:
        # operator-stated (the shells' predecessors are [])
        assert _packet(head, packet)["predecessors"] == []
    for packet in SUCCESSORS:
        predecessors = _packet(head, packet)["predecessors"]
        # operator-stated (each successor has one predecessor)
        assert len(predecessors) == 1
        # operator-stated (packet: its one predecessor)
        assert comparators[packet]["packet"] == predecessors[0]
        # operator-stated (sha256: that predecessor's baseline digest)
        assert re.fullmatch(r"[0-9a-f]{64}", comparators[packet]["sha256"]) is not None


def test_historical_catalog_drops_new_packet_and_products(head):
    """CONTRACT_291 sections 1 and 5, MON-291-B1C-CLASS and MON-291-R2-RULE: on the complete catalog of the tree's
    task-packets YAMLs, historical_catalog returns it minus NEW_PACKET and the seven products and leaves its input
    unchanged.

    This is the file's one listing call, under MON-291-R2-RULE's allowance for this test only: a sorted glob of
    task-packets/*.yaml, file stems as ids, each file parsed with scripts/safe_yaml.safe_load (reached through the
    head's own import). Every failure below prints only a count or a boolean, never an id or a packet.
    """
    safe_yaml = getattr(head, "safe_yaml", None)
    load = safe_yaml.safe_load if safe_yaml is not None else _safe_load(head)
    paths = sorted((ROOT / "task-packets").glob("*.yaml"))
    catalog = {path.stem: load(path.read_bytes().decode("utf-8")) for path in paths}
    # Era catalog ([PC-1] form, MON-292-D1-ERA): a bridged successor's historical_catalog drops its newer packets.
    era = head.successor.historical_catalog(catalog) if hasattr(head, "successor") else catalog
    count = len(era)
    # MON-291-R2-RULE (operator-stated fact; CONTRACT_291 section 5's 310 packets)
    assert count == 310
    absent = sum(1 for packet in (NEW_PACKET, *PRODUCTS) if packet not in era)
    # MON-291-R2-RULE (operator-stated fact; CONTRACT_291 section 5's 310 packets)
    assert absent == 0
    expected = set(era) - {NEW_PACKET, *PRODUCTS}
    snapshot = copy.deepcopy(catalog)
    result = head.historical_catalog(catalog)
    differing = len(set(result) ^ expected)
    # MON-291-R2-RULE (operator-stated fact; CONTRACT_291 section 5's 310 packets)
    assert differing == 0
    unchanged = catalog == snapshot
    # MON-291-R2-RULE (operator-stated fact; CONTRACT_291 section 5's 310 packets)
    assert unchanged


def test_historical_catalog_refuses_a_partial_mapping(head):
    """CONTRACT_291 section 5 and MON-291-B1C-CLASS: a partial mapping (NEW_PACKET, the seven products, the three
    registered bootstraps and one predecessor) is refused with ValueError."""
    packets = {packet: _packet(head, packet) for packet in (NEW_PACKET, *PRODUCTS, *REGISTERED)}
    packets[PREDECESSOR] = {"id": PREDECESSOR, "predecessors": []}
    # MON-291-B1C-CLASS (contract behaviour, CONTRACT_291 section 5)
    with pytest.raises(ValueError) as caught:
        head.historical_catalog(packets)
    # MON-291-B1C-CLASS (contract behaviour, CONTRACT_291 section 5)
    assert "unexpected packet addition or loss" in str(caught.value)


@pytest.mark.parametrize("packet", SHELLS)
def test_shell_tree_contract(head, packet):
    """CONTRACT_291 sections 2 and 3: each shell carries exactly one "Tree:" contract stating its count as
    "N files", states "exactly 11 files" and no other file count."""
    text = _read(f"task-packets/{packet}.yaml").decode("utf-8")
    trees = [item for item in _packet(head, packet)["contracts"] if "Tree:" in item]
    # CONTRACT_291 section 2 (exactly one "Tree:" contract)
    assert len(trees) == 1
    # CONTRACT_291 sections 2 and 3 (the count as "N files": 11)
    assert "11 files" in trees[0]
    # CONTRACT_291 section 3
    assert "exactly 11 files" in text
    # CONTRACT_291 section 3 (no other file count)
    assert set(FILE_COUNT.findall(text)) == {"11"}


def test_packet_yaml(head):
    """CONTRACT_291 sections 1 and 6: MET-009.yaml (16 one-line JSON keys, operator-stated), its predecessor and
    the allowedPaths sections 3 to 7 name."""
    text = _read(PACKET_YAML_FILE).decode("utf-8")
    lines = text.splitlines()
    packet = _safe_load(head)(text)
    # operator-stated (16 keys, each on one line as key: <JSON value>)
    assert len(lines) == 16
    # operator-stated
    assert len(packet) == 16
    unmatched = 0
    for line in lines:
        key, separator, value = line.partition(": ")
        if separator != ": " or key not in packet or json.loads(value) != packet[key]:
            unmatched += 1
    # operator-stated
    assert unmatched == 0
    # CONTRACT_291 section 1
    assert packet["id"] == NEW_PACKET
    # CONTRACT_291 sections 1 and 6 (PREV MET-PERF-050; predecessors ["MET-PERF-050"])
    assert packet["predecessors"] == [PREDECESSOR]
    allowed = set(packet["allowedPaths"])
    required = set(PRODUCT_FILES) | {
        ANNEX_FILE,
        ANNEX_TEST_FILE,
        HEAD_FILE,
        HEAD_TEST_FILE,
        WEIGHTS_FILE,
        REGISTRY_FILE,
        HUNK_RECORD_FILE,
        PACKET_YAML_FILE,
        README_FILE,
    }
    # CONTRACT_291 sections 3 to 7 (the files section 6 lists for allowedPaths)
    assert sorted(required - allowed) == []
    # operator-stated (the authority file)
    assert AUTHORITY_FILE in allowed
    yaml_paths = {path for path in allowed if path.startswith("task-packets/") and path.endswith(".yaml")}
    # CONTRACT_291 sections 1 and 6 (no predecessor YAML edit: the seven products and MET-009.yaml only)
    assert yaml_paths == set(PRODUCT_FILES) | {PACKET_YAML_FILE}
    # CONTRACT_291 section 1 (no schemas/ edit)
    assert sum(1 for path in allowed if path.startswith("schemas/")) == 0
    # CONTRACT_291 section 1 (no runner or planner edit)
    assert "ci/run_packet_argv.py" not in allowed
    # CONTRACT_291 section 1
    assert "ci/parallel_suite.py" not in allowed


# ---------------------------------------------------------------------------------------------------------------
# 2. The plane-shell ordering annex (CONTRACT_291 section 4)
# ---------------------------------------------------------------------------------------------------------------


def test_annex_closed_table(head, annex):
    """CONTRACT_291 section 4: the closed three-row table keyed by the registered bootstrap, each row five strings
    binding both packets' repository and canonical content digests (D-ANNEX-1)."""
    table = annex.PLANE_SHELL_ORDER
    packets = _row_packets(head)
    # CONTRACT_291 section 4 (three rows)
    assert len(table) == 3
    for row in table:
        # CONTRACT_291 section 4 (each row a tuple of five strings)
        assert isinstance(row, tuple) and len(row) == 5
        # CONTRACT_291 section 4
        assert all(isinstance(cell, str) for cell in row)
    rows = {row[1]: row for row in table}
    # CONTRACT_291 sections 3 and 4 (RUN-001, MODEL-001, EXEC-001 and their planes' shells)
    assert {registered: row[3] for registered, row in rows.items()} == PAIRS
    # CONTRACT_291 section 4 (six distinct ids)
    assert len({row[1] for row in table} | {row[3] for row in table}) == 6
    # CONTRACT_291 section 4 (over the three plane repositories)
    assert len({row[0] for row in table}) == 3
    for registered, row in rows.items():
        repository, _, registered_digest, shell, shell_digest = row
        # CONTRACT_291 section 4 (the registered id is the repository's PRODUCT_BOOTSTRAP_PACKETS entry)
        assert annex.PRODUCT_BOOTSTRAP_PACKETS[repository] == registered
        # CONTRACT_291 section 4 (both packets name the plane's repository)
        assert packets[registered]["repository"] == repository
        # CONTRACT_291 section 4
        assert packets[shell]["repository"] == repository
        # CONTRACT_291 section 4 (D-ANNEX-1: the row binds canonical content digests)
        assert registered_digest == annex.packet_content_sha256(packets[registered])
        # CONTRACT_291 section 4
        assert shell_digest == annex.packet_content_sha256(packets[shell])


def test_annex_content_digest_definition(head, annex):
    """CONTRACT_291 section 4 (D-ANNEX-1): packet_content_sha256 is the sha256 of the parsed packet as sorted-key
    compact JSON."""
    sample = {"b": [1, "x", None, True], "a": {"d": 2.5, "c": "y"}}
    reordered = {"a": {"c": "y", "d": 2.5}, "b": [1, "x", None, True]}
    compact = '{"a":{"c":"y","d":2.5},"b":[1,"x",null,true]}'
    # CONTRACT_291 section 4
    assert annex.packet_content_sha256(sample) == _sha(compact.encode("utf-8"))
    # CONTRACT_291 section 4 (sorted keys: insertion order does not matter)
    assert annex.packet_content_sha256(reordered) == annex.packet_content_sha256(sample)
    for packet in _row_packets(head).values():
        # CONTRACT_291 section 4
        assert annex.packet_content_sha256(packet) in _canonical_digests(packet)


def test_annex_formatting_only_change_keeps_digest(head, annex):
    """CONTRACT_291 section 4 (D-ANNEX-1): a formatting-only YAML change does not move a content digest."""
    load = _safe_load(head)
    for packet_id in (*REGISTERED, *SHELLS):
        packet = _packet(head, packet_id)
        text = "".join(
            f"{key}: {json.dumps(value, ensure_ascii=False)}\n" for key, value in reversed(list(packet.items()))
        )
        reparsed = load(text)
        # CONTRACT_291 section 4 (the same parsed content)
        assert reparsed == packet
        # CONTRACT_291 section 4
        assert annex.packet_content_sha256(reparsed) == annex.packet_content_sha256(packet)


def test_annex_applies_the_three_rows(head, annex):
    """CONTRACT_291 section 4: over the six row packets the three rows apply with no error (P3), with the default
    table and with an equal copy of it."""
    table = annex.PLANE_SHELL_ORDER
    for result in (
        annex.plane_shell_order(_row_packets(head)),
        annex.plane_shell_order(_row_packets(head), type(table)(tuple(row) for row in table)),
    ):
        extra, errors = result
        # CONTRACT_291 section 4 (each shell precedes its registered bootstrap)
        assert dict(extra) == _expected_extra()
        # CONTRACT_291 section 4 (0 order errors)
        assert list(errors) == []


def test_annex_orders_nothing_else(head, annex):
    """CONTRACT_291 section 4 (T7 isolation): other packets in the mapping gain nothing and change nothing."""
    packets = _row_packets(head)
    for packet_id in (NEW_PACKET, *SUCCESSORS):
        packets[packet_id] = _packet(head, packet_id)
    extra, errors = annex.plane_shell_order(packets)
    # CONTRACT_291 section 4
    assert dict(extra) == _expected_extra()
    # CONTRACT_291 section 4
    assert list(errors) == []


@pytest.mark.parametrize("vector", TABLE_VECTORS)
def test_annex_refuses_a_table_that_is_not_the_closed_rows(head, annex, vector):
    """CONTRACT_291 section 4 (T5): a table that is not the closed three rows is refused whole and no row
    applies."""
    table = _bad_table(annex.PLANE_SHELL_ORDER, vector)
    extra, errors = annex.plane_shell_order(_row_packets(head), table)
    # CONTRACT_291 section 4 (no row applies)
    assert dict(extra) == {}
    # CONTRACT_291 section 4
    assert any(TABLE_MESSAGE in str(error) for error in errors)


@pytest.mark.parametrize("registered", REGISTERED)
def test_annex_shell_absent_skips_row_silently(head, annex, registered):
    """CONTRACT_291 section 4: a row whose shell is absent from the mapping is skipped silently."""
    packets = _row_packets(head)
    del packets[PAIRS[registered]]
    extra, errors = annex.plane_shell_order(packets)
    # CONTRACT_291 section 4
    assert dict(extra) == _expected_extra(skip={registered})
    # CONTRACT_291 section 4 (silently)
    assert list(errors) == []


@pytest.mark.parametrize("registered", REGISTERED)
def test_annex_shell_check_comes_first(head, annex, registered):
    """CONTRACT_291 section 4 (a row, in order): with both the shell and its registered bootstrap absent, the row
    is skipped silently."""
    packets = _row_packets(head)
    del packets[PAIRS[registered]]
    del packets[registered]
    extra, errors = annex.plane_shell_order(packets)
    # CONTRACT_291 section 4
    assert dict(extra) == _expected_extra(skip={registered})
    # CONTRACT_291 section 4
    assert list(errors) == []


@pytest.mark.parametrize("registered", REGISTERED)
def test_annex_registered_absent_refuses_row(head, annex, registered):
    """CONTRACT_291 section 4 (T9; CR1 C1-2): a present shell whose registered bootstrap is absent refuses that
    row with "plane shell order row <shell>: <registered> absent"."""
    packets = _row_packets(head)
    del packets[registered]
    result = annex.plane_shell_order(packets)
    # CONTRACT_291 section 4
    wording = f"plane shell order row {PAIRS[registered]}: {registered} absent"
    _assert_row_refused(result, registered, wording)


@pytest.mark.parametrize(("registered", "side"), ROW_SIDES, ids=ROW_SIDE_IDS)
def test_annex_repository_change_refuses_row(head, annex, registered, side):
    """CONTRACT_291 section 4 (T8, T6 wording): a repository change on either side refuses that row with
    "repository mismatch"."""
    packets = _row_packets(head)
    target = _side(registered, side)
    packets[target]["repository"] = packets[target]["repository"] + "-oracle"
    message = _assert_row_refused(annex.plane_shell_order(packets), registered, REPOSITORY_MISMATCH)
    # CONTRACT_291 section 4 ("repository mismatch" when the repository value changes, else "content digest")
    assert "content digest" not in message


@pytest.mark.parametrize(("registered", "side"), ROW_SIDES, ids=ROW_SIDE_IDS)
def test_annex_content_change_refuses_row(head, annex, registered, side):
    """CONTRACT_291 section 4 (T6): a content change on either side refuses that row with
    "<id> content digest mismatch"."""
    packets = _row_packets(head)
    target = _side(registered, side)
    packets[target]["oracleNote"] = "content changed"
    # CONTRACT_291 section 4
    wording = f"{target} content digest mismatch"
    _assert_row_refused(annex.plane_shell_order(packets), registered, wording)


@pytest.mark.parametrize(("registered", "side"), ROW_SIDES, ids=ROW_SIDE_IDS)
def test_annex_table_digest_differs_refuses_row(head, annex, registered, side):
    """CONTRACT_291 section 4 (T6): a row digest that differs from the packet's content digest, on either side,
    refuses that row with "<id> content digest mismatch"."""
    packets = _row_packets(head)
    target = _side(registered, side)
    digest = _flip_hex(annex.packet_content_sha256(packets[target]))
    table = _table_with_digest(annex.PLANE_SHELL_ORDER, registered, side, digest)
    # CONTRACT_291 section 4
    wording = f"{target} content digest mismatch"
    _assert_row_refused(annex.plane_shell_order(packets, table), registered, wording)


@pytest.mark.parametrize("vector", ("date", "binary", "set", "mixed_keys", "lone_surrogate", "recursive"))
@pytest.mark.parametrize(("registered", "side"), ROW_SIDES, ids=ROW_SIDE_IDS)
def test_annex_unencodable_content_refuses_row(head, annex, registered, side, vector):
    """CONTRACT_291 section 4 (T6 wording; CR1 C1-1): content that sorted-key compact JSON cannot encode refuses
    that row with "<id> content digest unavailable" instead of raising."""
    packets = _row_packets(head)
    target = _side(registered, side)
    packets[target]["oracleValue"] = _unencodable(vector)
    # CONTRACT_291 section 4
    wording = f"{target} content digest unavailable"
    _assert_row_refused(annex.plane_shell_order(packets), registered, wording)


@pytest.mark.parametrize("variant", ("same_side_unencodable", "other_side_changed"))
@pytest.mark.parametrize(("registered", "side"), ROW_SIDES, ids=ROW_SIDE_IDS)
def test_annex_repository_check_precedes_digest(head, annex, registered, side, variant):
    """CONTRACT_291 section 4 (a row, in order): a repository change is reported as "repository mismatch" even
    when a content digest would also fail."""
    packets = _row_packets(head)
    target = _side(registered, side)
    packets[target]["repository"] = packets[target]["repository"] + "-oracle"
    if variant == "same_side_unencodable":
        packets[target]["oracleValue"] = datetime.date(2026, 11, 16)
    else:
        packets[_other_side(registered, side)]["oracleNote"] = "content changed"
    message = _assert_row_refused(annex.plane_shell_order(packets), registered, REPOSITORY_MISMATCH)
    # CONTRACT_291 section 4
    assert "content digest" not in message


# ---------------------------------------------------------------------------------------------------------------
# 3. The head layer: V1, E3, V4 and V6 (CONTRACT_291 section 5)
# ---------------------------------------------------------------------------------------------------------------


@pytest.mark.parametrize(
    "name", ("validate_packet_files", "validate_errata", "validate_registry", "validate_hunk_record")
)
def test_head_check_passes_on_live_tree(head, name):
    """CONTRACT_291 section 5 (V1, E3, V4, V6): each validate_* passes over the live tree."""
    getattr(head, name)()


def test_head_paths(head):
    """CONTRACT_291 section 6: the head reads the registry rider's file and 291's hunk-class record."""
    # CONTRACT_291 section 6
    assert _same_path(head.REGISTRY_PATH, REGISTRY_FILE)
    # CONTRACT_291 section 6
    assert _same_path(head.HUNK_RECORD_PATH, HUNK_RECORD_FILE)
    # operator-stated
    assert _same_path(head.AUTHORITY_PATH, AUTHORITY_FILE)


def test_v1_packet_files_and_era_pins(head):
    """CONTRACT_291 sections 3, 4 and 5 (V1): PACKET_FILES is the seven product YAMLs and the annex's two files;
    ERA_SHA256 pins each product YAML at its frozen digest."""
    # CONTRACT_291 sections 3 and 4
    assert set(head.PACKET_FILES) == set(PRODUCT_FILES) | {ANNEX_FILE, ANNEX_TEST_FILE}
    # CONTRACT_291 sections 3 and 4
    assert len(head.PACKET_FILES) == 9
    for packet, rel in zip(PRODUCTS, PRODUCT_FILES):
        # CONTRACT_291 section 3
        assert head.ERA_SHA256[rel].startswith(PREFIXES[packet])
        # CONTRACT_291 section 3 (copied byte for byte)
        assert head.ERA_SHA256[rel] == _sha(_read(rel))


def test_v1_refuses_changed_byte_and_missing_file(head, changed):
    """CONTRACT_291 sections 3 and 5 (V1): a packet file with one byte changed, and a packet file missing, are
    refused."""
    files, placeholders = _v1_files(head, changed)
    target = PRODUCT_FILES[0]
    baseline = None
    if placeholders:
        # operator-stated (ERA_SHA256 pins every packet file)
        with pytest.raises(ValueError) as caught:
            head.check_packet_files(dict(files))
        baseline = str(caught.value)
    else:
        head.check_packet_files(dict(files))
    flipped = dict(files)
    data = bytearray(files[target])
    data[0] ^= 0x01
    flipped[target] = bytes(data)
    missing = dict(files)
    del missing[target]
    attribute = placeholders == [ANNEX_TEST_FILE] and baseline is not None and ANNEX_TEST_FILE in baseline
    for case in (flipped, missing):
        # operator-stated (check_packet_files raises ValueError)
        with pytest.raises(ValueError) as caught:
            head.check_packet_files(case)
        message = str(caught.value)
        # operator-stated (the message contains MET-009)
        assert "MET-009" in message
        if attribute:
            # operator-stated (a check refuses at the first condition that fails)
            assert message != baseline


def test_e3_refuses_other_class_outside_errata_lines(head, changed, record):
    """CONTRACT_291 section 5 (E3, operator-stated): class `other` on a file outside ERRATA_LINES is refused."""
    classes = record["classes"]
    befores = {path: head._undo_this_layer(path, _current(changed, path)) for path in head.ERRATA_LINES}
    head.check_errata(copy.deepcopy(classes), changed, befores)
    picks = _picks(changed, classes, exclude=frozenset(head.ERRATA_LINES))
    # CONTRACT_291 section 5 (the mechanics change files with reverse hunks outside the errata rows)
    assert picks
    for path in picks:
        mutated = copy.deepcopy(classes)
        mutated[path] = [OTHER_CLASS, *mutated[path][1:]]
        # operator-stated
        with pytest.raises(ValueError) as caught:
            head.check_errata(mutated, changed, befores)
        # operator-stated
        assert "MET-009" in str(caught.value)


def test_v4_check_passes_on_live_inputs(head):
    """CONTRACT_291 section 6 (V4): the live registry and its packet brief pass check_registry."""
    head.check_registry(_read(REGISTRY_FILE), {head.PACKET_BRIEF: _read_brief(head)})


@pytest.mark.parametrize("case", V4_CASES)
def test_v4_refuses_registry_mutation(head, case):
    """CONTRACT_291 section 6 (V4): a registry that is not the base plus the one MET-009/packet rider is
    refused."""
    raw = _read(REGISTRY_FILE)
    briefs = {head.PACKET_BRIEF: _read_brief(head)}
    registry = json.loads(raw.decode("utf-8"))
    # operator-stated (the one MET-009/packet rider; CONTRACT_291 section 6)
    assert _rider_entry(registry) is not None
    data = _dumps_like(raw, registry, _v4_mutant(registry, case))
    # operator-stated
    with pytest.raises(ValueError) as caught:
        head.check_registry(data, briefs)
    # operator-stated
    assert "MET-009" in str(caught.value)


def test_v6_check_passes_on_live_inputs(head, changed, v6_inputs):
    """CONTRACT_291 section 5 (V6, v2.5): the live hunk-class record passes check_hunk_record."""
    raw, afters, classify, context, rule_sha = v6_inputs
    head.check_hunk_record(raw, changed, afters, classify, context, rule_sha)


@pytest.mark.parametrize("case", V6_CASES)
def test_v6_refuses_record_mutation(head, changed, record, v6_inputs, case):
    """CONTRACT_291 sections 1 and 5 (V6, v2.5): breaking the record's closed members, its vocabulary, v2.5's rule
    digest, steps [1, 8] (K = 7), countPairs [], its context, or adding an outcome statement, is refused."""
    raw, afters, classify, context, rule_sha = v6_inputs
    if case == "rule_digest":
        found = _find_values(record, lambda value: isinstance(value, str) and value == rule_sha)
        # operator-stated (the record carries v2.5's rule digest; CONTRACT_291 section 5)
        assert found
    if case == "steps":
        trails = _steps_trails(record)
        # operator-stated (steps [1, 8] for K = 7; CONTRACT_291 section 1)
        assert trails
        # operator-stated (steps [1, 8]; CONTRACT_291 section 1)
        assert all(_get(record, trail) == STEPS for trail in trails)
    if case == "count_pairs":
        trails = _outside_classes(_find_keys(record, lambda key: key == "countPairs"))
        # operator-stated (countPairs [])
        assert trails
        # operator-stated (countPairs [])
        assert all(_get(record, trail) == [] for trail in trails)
    mutants = _v6_mutants(record, changed, rule_sha, case)
    # operator-stated (each V6 condition has a target in the record)
    assert mutants
    for mutant in mutants:
        data = _dumps_like(raw, record, mutant)
        # operator-stated
        with pytest.raises(ValueError) as caught:
            head.check_hunk_record(data, changed, afters, classify, context, rule_sha)
        # operator-stated
        assert "MET-009" in str(caught.value)


def test_v6_refuses_a_different_rule_digest(head, changed, v6_inputs):
    """CONTRACT_291 section 5 (V6, v2.5): the live record checked against a rule digest other than v2.5's is
    refused."""
    raw, afters, classify, context, rule_sha = v6_inputs
    # operator-stated
    with pytest.raises(ValueError) as caught:
        head.check_hunk_record(raw, changed, afters, classify, context, _flip_hex(rule_sha))
    # operator-stated
    assert "MET-009" in str(caught.value)


# ---------------------------------------------------------------------------------------------------------------
# 4. The weights table (CONTRACT_291 sections 5, 7 and 10)
# ---------------------------------------------------------------------------------------------------------------


def test_weights_table():
    """CONTRACT_291 sections 5, 7 and 10 (P2): raw keys equal effective keys (no duplicate), every key names a
    regular file, the head test holds a row, 212 entries."""
    keys = [key for key, _ in _weight_pairs()]
    # CONTRACT_291 sections 5 and 7 (211 -> 212 with the head-test row)
    assert len(keys) == WEIGHT_ENTRIES
    # CONTRACT_291 section 10 (raw = effective: 0 duplicates)
    assert len(keys) - len(set(keys)) == 0
    # CONTRACT_291 section 5 (the head test's row)
    assert HEAD_TEST_FILE in keys
    # CONTRACT_291 section 10 (0 keys naming no file)
    assert sum(1 for key in keys if not (ROOT / key).is_file()) == 0
