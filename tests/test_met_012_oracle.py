"""D5a oracle tests for MET-012 (slot 294, K = 3): the three product packets and the head's V1, E3, V4 and V6.

D5a (owner decision): a contract packet carries tests written outside the candidate by someone who is not its builder.
This file was written by a non-author from CONTRACT_294 r2 (sha256
aab3512c91816a168a6d9d24bf186999bb21be905c90d4cc1bcff45e364057fc), its r2 errata E1 and E2 (sha256
5d6346ff8187db78a6fb7d2d3f2da50e91d9b3abb07c7c0e6e9383ee5ab20fe6) and the facts the operator stated in the oracle
brief. The masked packet YAML that came with them is a fixture only, never the source of an expectation.

Sources of the expected values: every expected value cites its source in a comment on the assert's own line or the
line directly above it, as "# CONTRACT_294 section N" (sections 1, 3, 3a, 4, 4a, 5, 6, 8 and 11), as
"# CONTRACT_294 erratum E1", or as "# operator-stated" (the three frozen product digests of the freeze record that
section 3 names, the head layer's interface and refusal form, the authority's members, the table's 217 entries, the
registry's 41 entries and the packet YAML's 16 one-line keys).

C18 (the era-read rule, CONTRACT_294 section 2): every repository file is read through the head's era reader
reviewed_bytes, never from the live tree; the catalog's names come from the authority, never from a listing. The head
is the one repository module loaded, by file path, into a fresh module object.

The repository files are fixtures: they are loaded and mutated as plain data (deep copies, bytes and mappings) and
nothing is patched. No digest of the table, the head, the authority or the hunk-class record is pinned, nor either new
row's value, so the file holds on the c3 candidate and after the measured step (CONTRACT_294 section 7, step 3).
"""

import copy
import hashlib
import importlib.util
import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

# Expected values; each cites its source.
# CONTRACT_294 section 1 (the new meta packet and its PREV)
NEW_PACKET = "MET-012"
PREV_PACKET = "MET-011"
# CONTRACT_294 section 1 (the three products, in the hub's order)
PRODUCTS = ("MODEL-ADOPT-PINS-001", "IND-BANK-003A", "EXEC-TEMPORAL-PINS-001")
# operator-stated (the freeze record that CONTRACT_294 section 3 names; equal to section 3's table)
FROZEN_SHA256 = {
    "MODEL-ADOPT-PINS-001": "f99afe08d9bc6daf02407ea6247de59c5cf4a73ce2d9b7912e40eb86b661cb58",
    "IND-BANK-003A": "ad10b6622b8bd3ab9aa79ef47b2855c489930ba457df66826323cc50ac9859c4",
    "EXEC-TEMPORAL-PINS-001": "3015206b52c26128331794bf96796ec7fcbfc283455c58b1510f6ce0232fcba7",
}
# CONTRACT_294 section 3 (the Bytes column)
FROZEN_SIZE = {"MODEL-ADOPT-PINS-001": 10798, "IND-BANK-003A": 8597, "EXEC-TEMPORAL-PINS-001": 7904}
# CONTRACT_294 sections 1 and 3 (the Repository column)
REPOSITORY = {
    "MODEL-ADOPT-PINS-001": "mas-harness-model-plane",
    "IND-BANK-003A": "mas-harness-industry-packs",
    "EXEC-TEMPORAL-PINS-001": "mas-harness-execution-plane",
}
# CONTRACT_294 section 3 (the Branch column)
BRANCH = {
    "MODEL-ADOPT-PINS-001": "codex/model-adopt-pins-001-llama-cpp-dossier",
    "IND-BANK-003A": "codex/ind-bank-003a-governance-integrations",
    "EXEC-TEMPORAL-PINS-001": "codex/exec-temporal-pins-001-provider-dossier",
}
# CONTRACT_294 sections 3 and 4 (the Predecessors column; productComparators per product row)
PREDECESSORS = {
    "MODEL-ADOPT-PINS-001": ["PLANE-BOOTSTRAP-R06"],
    "IND-BANK-003A": ["IND-BANK-003"],
    "EXEC-TEMPORAL-PINS-001": ["PLANE-BOOTSTRAP-R08"],
}
# CONTRACT_294 section 3 (the allowedPaths column)
ALLOWED_COUNT = {"MODEL-ADOPT-PINS-001": 2, "IND-BANK-003A": 30, "EXEC-TEMPORAL-PINS-001": 4}
# CONTRACT_294 section 3a (the replay's member roots for 06, 03 and 08)
MEMBER_ROOTS = {
    "MODEL-ADOPT-PINS-001": {"adoption", "tests"},
    "IND-BANK-003A": {"ci", "docs", "packs", "src", "tests"},
    "EXEC-TEMPORAL-PINS-001": {"adoption", "tests"},
}
# CONTRACT_294 section 1 (314 packets at the base; the catalog pair (314, 318))
BASE_COUNT = 314
CATALOG_COUNT = 318
# CONTRACT_294 section 4 (the head, the authority record and its schema)
HEAD_SCRIPT = "scripts/validate_met_012.py"
AUTHORITY_PATH = "architecture/three-ready-packets-authority.json"
AUTHORITY_SCHEMA = "harness.planeon.ai/three-ready-packets-authority/v1"
# operator-stated (the authority's members)
AUTHORITY_MEMBERS = {"baselinePackets", "changedFiles", "newFiles", "productPackets", "productComparators"}
# CONTRACT_294 sections 4 and 5 (the hunk-class record)
HUNK_RECORD = "architecture/chain-checkpoint/hunk-classes/294.json"
# CONTRACT_294 sections 1 and 5 (the registry and its one rider)
REGISTRY = "architecture/review-record/briefs.json"
RIDER = "MET-012/packet"
# operator-stated (41 entries; CONTRACT_294 section 1: the rider 40 -> 41)
REGISTRY_COUNT = 41
# CONTRACT_294 section 6 (GATE_CI: the table and its two new rows)
TABLE = "ci/parallel_suite_weights.json"
HEAD_TEST = "tests/test_met_012.py"
ORACLE_TEST = "tests/test_met_012_oracle.py"
# operator-stated (217 entries in both runs; CONTRACT_294 section 6: 215 -> 217)
TABLE_COUNT = 217
# CONTRACT_294 section 5 (the packet YAML and its contracts line naming the accepted base)
PACKET_YAML = "task-packets/MET-012.yaml"
BASE_SENTENCE = (
    "Accepted base is main 50785a12403a31d8bc466da8c61207d27d92cf52, tree "
    "4f589c102fd5365298359b88f5ecbfe587476cc6, holding 314 immutable packets including MET-011."
)
# CONTRACT_294 section 5 (the index docs and the three lanes' plans)
INDEX_DOCS = (
    "docs/MASTER_DEVELOPMENT_PLAN.md",
    "docs/repositories/00-harness-engineering.md",
    "task-packets/README.md",
    "docs/repositories/03-mas-harness-industry-packs.md",
    "docs/repositories/06-mas-harness-model-plane.md",
    "docs/repositories/08-mas-harness-execution-plane.md",
)
# CONTRACT_294 sections 3a and 11 (the 06 and 08 exact-tree lines are E3 spans)
TREE_DOCS = (
    "docs/repositories/06-mas-harness-model-plane.md",
    "docs/repositories/08-mas-harness-execution-plane.md",
)
# CONTRACT_294 section 11 (the branch name)
PACKET_BRANCH = "codex/met-012-three-ready-packets"
# operator-stated (16 keys, each on one line as key: <JSON value>)
PACKET_KEYS = 16
# CONTRACT_294 section 4a (check_hunk_record's context steps [1, 4] at K 3; 292's [1, 3] at K 2)
STEPS = [1, 4]
STEPS_K2 = [1, 3]
# operator-stated (the record's context holds countPairs [] at K = 3)
COUNT_PAIRS = []
# CONTRACT_294 section 4a (E3 refuses an unnamed "other" hunk)
OTHER = "other"

# Construction values only (never an expectation).
HEAD_MODULE = "met_012_oracle_head"
UNKNOWN_CLASS = "oracle-unknown-class"
EXTRA_ID = "ORACLE-EXTRA-001"
DUMP_FORMS = (
    {"indent": 2},
    {"indent": 2, "sort_keys": True},
    {"indent": 2, "ensure_ascii": False},
    {"indent": 2, "sort_keys": True, "ensure_ascii": False},
    {"indent": 1},
    {"indent": 4},
    {"separators": (",", ":")},
    {"separators": (",", ":"), "sort_keys": True},
    {},
    {"sort_keys": True},
)
V1_CASES = (
    *(("byte-changed", packet) for packet in PRODUCTS),
    *(("missing", packet) for packet in PRODUCTS),
    ("extra", NEW_PACKET),
)
CATALOG_CASES = (
    *(("lacks", packet) for packet in PRODUCTS),
    ("lacks", NEW_PACKET),
    ("lacks-base", "first-base-id"),
    ("adds", EXTRA_ID),
)
V4_CASES = ("rider-renamed", "rider-dropped", "base-entry-dropped")
V6_CASES = (
    "extra-member",
    "missing-member",
    "class-outside-vocabulary",
    "rule-digest",
    "steps-k2",
    "count-pairs",
    "no-outcome-statement",
)


def _packet_path(name):
    return "task-packets/" + name + ".yaml"


def _sha(data):
    return hashlib.sha256(data).hexdigest()


def _load_head():
    """Load the head by file path into a fresh module object (the one repository module this file loads)."""
    spec = importlib.util.spec_from_file_location(HEAD_MODULE, ROOT / HEAD_SCRIPT)
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def _dump_like(raw, value):
    """Serialise value in the first json.dumps form that reproduces raw from its own parse (construction only)."""
    original = json.loads(raw)
    for options in DUMP_FORMS:
        for tail in ("\n", ""):
            if (json.dumps(original, **options) + tail).encode("utf-8") == raw:
                return (json.dumps(value, **options) + tail).encode("utf-8")
    return (json.dumps(value, indent=2) + "\n").encode("utf-8")


def _containers(node, path=()):
    """Yield (path, node) for every JSON object and array under node, node included."""
    if isinstance(node, dict):
        yield path, node
        for key, child in node.items():
            yield from _containers(child, path + (key,))
    elif isinstance(node, list):
        yield path, node
        for index, child in enumerate(node):
            yield from _containers(child, path + (index,))


def _entries(node):
    return list(node.items()) if isinstance(node, dict) else list(enumerate(node))


def _mentions_rider(node):
    if isinstance(node, str):
        return node == RIDER
    if isinstance(node, dict):
        return any(key == RIDER or _mentions_rider(value) for key, value in node.items())
    if isinstance(node, list):
        return any(_mentions_rider(value) for value in node)
    return False


def _names_rider(node, key, value):
    return (isinstance(node, dict) and key == RIDER) or _mentions_rider(value)


def _registry_entries(registry):
    """The registry's entry container: the largest object or array of which exactly one entry names the rider."""
    found = []
    for path, node in _containers(registry):
        entries = _entries(node)
        hits = [key for key, value in entries if _names_rider(node, key, value)]
        if len(entries) >= 2 and len(hits) == 1:
            found.append((len(entries), path, node))
    if not found:
        pytest.fail("construction: no container of the registry has exactly one entry naming the rider")
    size, path, node = max(found, key=lambda item: item[0])
    return path, node


def _without(node, drop):
    if isinstance(node, dict):
        return {key: value for key, value in node.items() if not drop(key, value)}
    return [value for index, value in enumerate(node) if not drop(index, value)]


def _replace_at(root, path, new):
    if not path:
        return new
    root = copy.deepcopy(root)
    parent = root
    for key in path[:-1]:
        parent = parent[key]
    parent[path[-1]] = new
    return root


def _table_pairs(raw):
    """The raw (key, value) pairs of the table's largest JSON object, duplicates kept."""
    objects = []

    def keep(pairs):
        objects.append(pairs)
        return dict(pairs)

    json.loads(raw, object_pairs_hook=keep)
    if not objects:
        pytest.fail("construction: the table holds no JSON object")
    return max(objects, key=len)


def _first_hunk_path(classes, excluded):
    for path in sorted(classes):
        if path not in excluded and classes[path]:
            return path
    pytest.fail("construction: no classed path with a hunk outside the excluded set")


def _outcome_paths(node, path=()):
    found = []
    if isinstance(node, dict):
        for key, value in node.items():
            lowered = str(key).lower()
            if not path and key == "classes":
                continue
            if "outcome" in lowered or "statement" in lowered:
                found.append(path + (key,))
            else:
                found.extend(_outcome_paths(value, path + (key,)))
    elif isinstance(node, list):
        for index, value in enumerate(node):
            found.extend(_outcome_paths(value, path + (index,)))
    return found


def _blank_at(root, path):
    parent = root
    for key in path[:-1]:
        parent = parent[key]
    value = parent[path[-1]]
    if isinstance(value, str):
        parent[path[-1]] = ""
    elif isinstance(value, list):
        parent[path[-1]] = []
    elif isinstance(value, dict):
        parent[path[-1]] = {}
    else:
        parent[path[-1]] = None


def _v6_mutated(record, case):
    """A deep copy of the hunk-class record broken in one way (construction only)."""
    mutated = copy.deepcopy(record)
    context = mutated["hunkClassContext"]
    if case == "extra-member":
        mutated["oracleExtraMember"] = True
    elif case == "missing-member":
        del mutated["classes"]
    elif case == "class-outside-vocabulary":
        mutated["classes"][_first_hunk_path(mutated["classes"], ())][0] = UNKNOWN_CLASS
    elif case == "steps-k2":
        context["steps"] = list(STEPS_K2)
    elif case == "count-pairs":
        context["countPairs"] = [[BASE_COUNT, CATALOG_COUNT]]
    elif case == "no-outcome-statement":
        paths = _outcome_paths(mutated)
        if not paths:
            pytest.fail("construction: no member of the hunk-class record names an outcome statement")
        for path in paths:
            parent = mutated
            for key in path[:-1]:
                parent = parent[key]
            statement = "oracle outcome statement"
            held = parent[path[-1]]
            if isinstance(held, list):
                parent[path[-1]] = [statement]
            elif isinstance(held, dict):
                parent[path[-1]] = {"oracle": statement}
            else:
                parent[path[-1]] = statement
    else:
        pytest.fail("construction: unknown case " + case)
    return mutated


@pytest.fixture(scope="module")
def head():
    return _load_head()


@pytest.fixture(scope="module")
def auth(head):
    return copy.deepcopy(head.authority())


@pytest.fixture(scope="module")
def catalog(head, auth):
    """The catalog's names from the authority (C18), each YAML read through the era reader."""
    names = [*auth["baselinePackets"], head.NEW_PACKET, *auth["productPackets"]]
    return names, {name: head.reviewed_bytes(_packet_path(name)) for name in names}


@pytest.fixture(scope="module")
def parsed_catalog(head, catalog):
    names, raws = catalog
    return {name: head.safe_load(raws[name]) for name in names}


@pytest.fixture(scope="module")
def changed(auth):
    return auth["changedFiles"]


@pytest.fixture(scope="module")
def hunk_raw(head):
    return head.reviewed_bytes(HUNK_RECORD)


@pytest.fixture(scope="module")
def afters(head, changed):
    return {path: head.reviewed_bytes(path) for path, row in changed.items() if row["reverseHunks"]}


@pytest.fixture(scope="module")
def befores(head, changed):
    return {
        path: head._undo_this_layer(path, head.reviewed_bytes(path))
        for path in head.ERRATA_LINES
        if path in changed
    }


@pytest.fixture(scope="module")
def classify(head):
    return head._era_rule(head.READER_PATH, head.READER_NAME).classify


def test_head_constants(head):
    """CONTRACT_294 sections 1 and 4: the head's NEW_PACKET, PRODUCT_PACKETS in the hub's order, its authority."""
    # CONTRACT_294 section 1 (MET-012)
    assert head.NEW_PACKET == NEW_PACKET
    # CONTRACT_294 sections 1 and 4 (PRODUCT_PACKETS in section 1's order)
    assert list(head.PRODUCT_PACKETS) == list(PRODUCTS)
    # CONTRACT_294 section 4 (the authority record)
    assert str(head.AUTHORITY_PATH) == AUTHORITY_PATH


@pytest.mark.parametrize("packet", PRODUCTS)
def test_product_frozen_bytes(head, packet):
    """CONTRACT_294 section 3: each product YAML is the lanes' frozen bytes (digest, size, LF, UTF-8, no BOM)."""
    raw = head.reviewed_bytes(_packet_path(packet))
    # operator-stated (the freeze digest; CONTRACT_294 section 3's table)
    assert _sha(raw) == FROZEN_SHA256[packet]
    # CONTRACT_294 section 3 (the Bytes column)
    assert len(raw) == FROZEN_SIZE[packet]
    # CONTRACT_294 section 3 (LF only, no BOM)
    assert b"\r" not in raw and not raw.startswith(b"\xef\xbb\xbf")
    # CONTRACT_294 section 3 (strict UTF-8)
    assert isinstance(raw.decode("utf-8", "strict"), str)


@pytest.mark.parametrize("packet", PRODUCTS)
def test_product_fields(head, packet):
    """CONTRACT_294 sections 1, 3 and 3a: each product's id, repository, branch, predecessors and allowedPaths."""
    parsed = head.safe_load(head.reviewed_bytes(_packet_path(packet)))
    # CONTRACT_294 section 3 (the target task-packets/<id>.yaml)
    assert parsed["id"] == packet
    # CONTRACT_294 sections 1 and 3 (the repository)
    assert parsed["repository"] == REPOSITORY[packet]
    # CONTRACT_294 section 3 (the branch)
    assert parsed["branch"] == BRANCH[packet]
    # CONTRACT_294 section 3 (the predecessors)
    assert parsed["predecessors"] == PREDECESSORS[packet]
    # CONTRACT_294 section 3 (the allowedPaths count)
    assert len(parsed["allowedPaths"]) == ALLOWED_COUNT[packet]
    # CONTRACT_294 section 3a (the member roots)
    assert {path.split("/", 1)[0] for path in parsed["allowedPaths"]} == MEMBER_ROOTS[packet]


def test_authority_record(head, auth):
    """CONTRACT_294 section 4: the authority record, its schema and its members."""
    raw = head.reviewed_bytes(AUTHORITY_PATH)
    # operator-stated (importing the head checks AUTHORITY_PATH against AUTHORITY_SHA256)
    assert _sha(raw) == head.AUTHORITY_SHA256
    # CONTRACT_294 section 4 (the schema)
    assert AUTHORITY_SCHEMA in [value for value in json.loads(raw).values() if isinstance(value, str)]
    # operator-stated (the authority's members)
    assert AUTHORITY_MEMBERS <= set(auth)


def test_authority_product_packets(head, auth):
    """CONTRACT_294 sections 1, 3 and 4: productPackets names the three in order, each with its file's sha256."""
    # CONTRACT_294 sections 1 and 4 (the authority's productPackets in the hub's order)
    assert list(auth["productPackets"]) == list(PRODUCTS)
    for packet in PRODUCTS:
        raw = head.reviewed_bytes(_packet_path(packet))
        # operator-stated (productPackets maps each to its YAML's sha256; the freeze digests)
        assert auth["productPackets"][packet] == _sha(raw) == FROZEN_SHA256[packet]
    # CONTRACT_294 section 4 (productComparators per product row)
    assert sorted(auth["productComparators"]) == sorted(PRODUCTS)


@pytest.mark.parametrize("packet", PRODUCTS)
def test_product_comparator(head, auth, packet):
    """CONTRACT_294 sections 3 and 4: productComparators pins each product's one predecessor by its base digest."""
    row = auth["productComparators"][packet]
    predecessor = PREDECESSORS[packet][0]
    # CONTRACT_294 section 4 (the member's one predecessor)
    assert row["packet"] == predecessor
    # operator-stated (that predecessor's baselinePackets digest)
    assert row["sha256"] == auth["baselinePackets"][predecessor]
    raw = head.reviewed_bytes(_packet_path(predecessor))
    # operator-stated (the digest is the sha256 of the predecessor's YAML bytes)
    assert _sha(raw) == row["sha256"]


def test_authority_baseline(auth):
    """CONTRACT_294 sections 1, 3 and 5: the base's 314 ids, without the four new names, with the predecessors."""
    base = auth["baselinePackets"]
    # CONTRACT_294 section 1 (314 packets at the base)
    assert len(base) == BASE_COUNT
    # CONTRACT_294 section 1 (none of the four names is present at the base)
    assert not ({NEW_PACKET, *PRODUCTS} & set(base))
    # CONTRACT_294 sections 3 and 5 (MET-011 and each predecessor in the base catalog)
    assert {PREV_PACKET, *(name for names in PREDECESSORS.values() for name in names)} <= set(base)


def test_catalog_names_and_base_bytes(auth, catalog):
    """CONTRACT_294 sections 1 and 5: 318 catalog names (C18), the 314 base YAMLs at their base digests."""
    names, raws = catalog
    # CONTRACT_294 section 1 (the catalog pair (314, 318))
    assert len(names) == len(set(names)) == CATALOG_COUNT
    for name in auth["baselinePackets"]:
        # operator-stated (baselinePackets maps each base id to its YAML's sha256); CONTRACT_294 section 5
        assert _sha(raws[name]) == auth["baselinePackets"][name]


def test_historical_catalog_returns_base(head, auth, parsed_catalog):
    """CONTRACT_294 sections 1 and 4: historical_catalog over the whole catalog returns exactly the 314 base ids."""
    result = dict(head.historical_catalog(dict(parsed_catalog)))
    # CONTRACT_294 sections 1 and 4 (without NEW_PACKET and the three: the 314 base ids)
    assert sorted(result) == sorted(auth["baselinePackets"]) and len(result) == BASE_COUNT
    # operator-stated (the mapping without NEW_PACKET and the three)
    assert all(result[name] == parsed_catalog[name] for name in result)


@pytest.mark.parametrize(("case", "name"), CATALOG_CASES, ids=[case + "-" + name for case, name in CATALOG_CASES])
def test_historical_catalog_refuses(head, auth, parsed_catalog, case, name):
    """CONTRACT_294 section 4: historical_catalog refuses a mapping that lacks a product (or any id) or adds one."""
    packets = dict(parsed_catalog)
    if case == "lacks":
        del packets[name]
    elif case == "lacks-base":
        del packets[next(iter(auth["baselinePackets"]))]
    else:
        extra = copy.deepcopy(parsed_catalog[NEW_PACKET])
        extra["id"] = name
        packets[name] = extra
    # operator-stated (historical_catalog refuses a mapping that lacks or adds an id)
    with pytest.raises(ValueError):
        head.historical_catalog(packets)


def test_v1_live(head):
    """CONTRACT_294 sections 3 and 4, erratum E1 (V1): the three packet files pass on the live inputs."""
    head.validate_packet_files()
    # CONTRACT_294 section 3 (task-packets/<id>.yaml) and erratum E1 (exactly the three)
    assert sorted(head.PACKET_FILES) == sorted(_packet_path(packet) for packet in PRODUCTS)
    files = {_packet_path(packet): head.reviewed_bytes(_packet_path(packet)) for packet in PRODUCTS}
    # operator-stated (check_packet_files returns None on the live files)
    assert head.check_packet_files(files) is None


@pytest.mark.parametrize(("case", "packet"), V1_CASES, ids=[case + "-" + packet for case, packet in V1_CASES])
def test_v1_refuses(head, case, packet):
    """CONTRACT_294 sections 3 and 4, erratum E1 (V1): a changed byte, a missing file or a fourth file is refused."""
    files = {_packet_path(name): head.reviewed_bytes(_packet_path(name)) for name in PRODUCTS}
    path = _packet_path(packet)
    if case == "byte-changed":
        data = files[path]
        files[path] = data[:-1] + bytes([data[-1] ^ 0x01])
    elif case == "missing":
        del files[path]
    else:
        files[path] = head.reviewed_bytes(path)
    # operator-stated (each check_* refuses with a ValueError naming MET-012); CONTRACT_294 erratum E1
    with pytest.raises(ValueError, match=NEW_PACKET):
        head.check_packet_files(files)


def test_e3_live(head, hunk_raw, changed, befores):
    """CONTRACT_294 sections 3a, 4 and 11 (E3): the errata spans hold on the live inputs; 06 and 08 are E3 paths."""
    head.validate_errata()
    # operator-stated (befores are read for ERRATA_LINES paths, each a changedFiles key)
    assert set(head.ERRATA_LINES) <= set(changed)
    # CONTRACT_294 sections 3a and 11 (the 06 and 08 exact-tree lines are E3 spans)
    assert set(TREE_DOCS) <= set(head.ERRATA_LINES)
    for path, spans in head.ERRATA_LINES.items():
        for first, last in spans:
            # operator-stated ((first, last) base-line spans)
            assert isinstance(first, int) and isinstance(last, int) and first <= last
    for path, data in befores.items():
        # operator-stated (_undo_this_layer returns a changed file's before bytes)
        assert _sha(data) == changed[path]["beforeSha256"]
    classes = json.loads(hunk_raw)["classes"]
    # operator-stated (check_errata returns None on the live inputs)
    assert head.check_errata(classes, changed, befores) is None


def test_e3_refuses_other_outside_errata(head, hunk_raw, changed, befores):
    """CONTRACT_294 section 4a (E3): an "other" hunk on a file outside ERRATA_LINES is refused."""
    classes = copy.deepcopy(json.loads(hunk_raw)["classes"])
    classes[_first_hunk_path(classes, head.ERRATA_LINES)][0] = OTHER
    # CONTRACT_294 section 4a; operator-stated (refused with a ValueError naming MET-012)
    with pytest.raises(ValueError, match=NEW_PACKET):
        head.check_errata(classes, changed, befores)


def test_v4_live(head):
    """CONTRACT_294 sections 1 and 5 (V4): the registry rider passes on the live inputs."""
    # CONTRACT_294 section 5 (the rider's registry)
    assert str(head.REGISTRY_PATH) == REGISTRY
    head.validate_registry()
    briefs = {head.PACKET_BRIEF: head.reviewed_bytes(head.PACKET_BRIEF)}
    # operator-stated (check_registry returns None on the live registry and brief)
    assert head.check_registry(head.reviewed_bytes(REGISTRY), briefs) is None


@pytest.mark.parametrize("case", V4_CASES)
def test_v4_refuses(head, case):
    """CONTRACT_294 sections 1 and 5 (V4): a registry that is not the base plus the one MET-012/packet rider."""
    raw = head.reviewed_bytes(REGISTRY)
    briefs = {head.PACKET_BRIEF: head.reviewed_bytes(head.PACKET_BRIEF)}
    if case == "rider-renamed":
        token = RIDER.encode("utf-8")
        # CONTRACT_294 sections 1 and 5 (the registry names the MET-012/packet rider)
        assert token in raw
        mutated = raw.replace(token, (NEW_PACKET + "/oracle").encode("utf-8"))
    else:
        registry = json.loads(raw)
        path, node = _registry_entries(registry)
        if case == "rider-dropped":
            new = _without(node, lambda key, value: _names_rider(node, key, value))
        else:
            first = next(key for key, value in _entries(node) if not _names_rider(node, key, value))
            new = _without(node, lambda key, value: key == first)
        mutated = _dump_like(raw, _replace_at(registry, path, new))
    # CONTRACT_294 sections 1 and 5; operator-stated (refused with a ValueError naming MET-012)
    with pytest.raises(ValueError, match=NEW_PACKET):
        head.check_registry(mutated, briefs)


def test_v6_live(head, auth, hunk_raw, changed, afters, classify):
    """CONTRACT_294 sections 4 and 4a (V6): the hunk-class record passes on the live inputs; steps [1, 4] at K 3."""
    # CONTRACT_294 sections 4 and 5 (the hunk-class record)
    assert str(head.HUNK_RECORD_PATH) == HUNK_RECORD
    head.validate_hunk_record()
    record = json.loads(hunk_raw)
    # CONTRACT_294 section 4a (context steps [1, 4] at K 3)
    assert record["hunkClassContext"]["steps"] == STEPS
    # operator-stated (countPairs [] at K = 3)
    assert record["hunkClassContext"]["countPairs"] == COUNT_PAIRS
    for path, data in afters.items():
        # operator-stated (a changedFiles row's afterSha256 is its reviewed bytes' sha256)
        assert _sha(data) == changed[path]["afterSha256"]
    context = head._v24_context(copy.deepcopy(auth), record["hunkClassContext"])
    # operator-stated (check_hunk_record returns None on the live record)
    assert head.check_hunk_record(hunk_raw, changed, afters, classify, context, head.HUNK_RULE_SHA256) is None


@pytest.mark.parametrize("case", V6_CASES)
def test_v6_refuses(head, auth, hunk_raw, changed, afters, classify, case):
    """CONTRACT_294 sections 4 and 4a (V6): closed members, vocabulary, rule digest, steps, countPairs, outcome.

    The context is derived from the record passed, as V6 derives it; a refusal there is V6's refusal.
    """
    rule_sha = head.HUNK_RULE_SHA256
    if case == "rule-digest":
        # operator-stated (the record carries v2.5's rule digest, HUNK_RULE_SHA256)
        assert rule_sha.encode("ascii") in hunk_raw
        other_sha = ("1" if rule_sha[0] != "1" else "2") + rule_sha[1:]
        raw = hunk_raw.replace(rule_sha.encode("ascii"), other_sha.encode("ascii"))
    else:
        raw = _dump_like(hunk_raw, _v6_mutated(json.loads(hunk_raw), case))
    try:
        context = head._v24_context(copy.deepcopy(auth), json.loads(raw)["hunkClassContext"])
    except ValueError:
        return
    # CONTRACT_294 section 4a; operator-stated (refused with a ValueError naming MET-012)
    with pytest.raises(ValueError, match=NEW_PACKET):
        head.check_hunk_record(raw, changed, afters, classify, context, rule_sha)


def test_packet_yaml(head):
    """CONTRACT_294 sections 1, 5 and 11: MET-012.yaml's form, id, predecessors, branch and contracts line."""
    raw = head.reviewed_bytes(PACKET_YAML)
    lines = raw.decode("utf-8").splitlines()
    pairs = [line.split(": ", 1) for line in lines]
    # operator-stated (16 keys, each on one line as key: <JSON value>)
    assert len(lines) == PACKET_KEYS and all(len(pair) == 2 for pair in pairs)
    one_line = {key: json.loads(value) for key, value in pairs}
    parsed = head.safe_load(raw)
    # operator-stated (16 distinct keys, each line's JSON value equal to the parsed value)
    assert len(one_line) == PACKET_KEYS and one_line == parsed
    # CONTRACT_294 section 1 (MET-012)
    assert parsed["id"] == NEW_PACKET
    # CONTRACT_294 section 5 (predecessors ["MET-011"])
    assert parsed["predecessors"] == [PREV_PACKET]
    # CONTRACT_294 section 11 (the branch)
    assert parsed["branch"] == PACKET_BRANCH
    # CONTRACT_294 section 5 (the contracts line naming the accepted base)
    assert sum(BASE_SENTENCE in line for line in parsed["contracts"]) == 1


def test_packet_allowed_paths(head, auth):
    """CONTRACT_294 sections 5 and 6: allowedPaths are the authority's files plus the fixed paths of section 5."""
    allowed = set(head.safe_load(head.reviewed_bytes(PACKET_YAML))["allowedPaths"])
    products = {_packet_path(packet) for packet in PRODUCTS}
    fixed = {AUTHORITY_PATH, HEAD_SCRIPT, PACKET_YAML, *products}
    authority_files = set(auth["changedFiles"]) | set(auth["newFiles"])
    # CONTRACT_294 section 5 (the authority record, the head, the packet YAML and the three product YAMLs)
    assert fixed <= allowed
    # CONTRACT_294 sections 5 and 6 (the index docs, the rider, 294.json, the table and the head test)
    assert {*INDEX_DOCS, REGISTRY, HUNK_RECORD, TABLE, HEAD_TEST} <= allowed
    # CONTRACT_294 section 5 (exactly the authority's changedFiles and newFiles plus the fixed paths)
    assert allowed <= authority_files | fixed
    # CONTRACT_294 section 5 (the product YAMLs are listed beside the authority's files, not among them)
    assert not (products & authority_files)


def test_weights_table(head):
    """CONTRACT_294 sections 6 and 8: raw keys equal effective keys, 217 rows, both new rows, every key a file."""
    pairs = _table_pairs(head.reviewed_bytes(TABLE))
    raw_keys = [key for key, _ in pairs]
    effective = list(dict(pairs))
    # CONTRACT_294 section 8 (P2: raw = effective); operator-stated (no duplicate key)
    assert raw_keys == effective
    # operator-stated (217 entries); CONTRACT_294 section 6 (215 -> 217)
    assert len(effective) == TABLE_COUNT
    # CONTRACT_294 section 6 (the head test's row and the oracle's row)
    assert HEAD_TEST in effective and ORACLE_TEST in effective
    for key in effective:
        # operator-stated (every key names a regular file, read through reviewed_bytes)
        assert isinstance(head.reviewed_bytes(key), bytes)


def test_registry_rider(head):
    """CONTRACT_294 sections 1 and 5: the registry's last entry is the one MET-012/packet rider, 41 entries."""
    _, node = _registry_entries(json.loads(head.reviewed_bytes(REGISTRY)))
    entries = _entries(node)
    # operator-stated (41 entries); CONTRACT_294 section 1 (the rider 40 -> 41)
    assert len(entries) == REGISTRY_COUNT
    # CONTRACT_294 sections 1 and 5 (the last entry is the MET-012/packet rider)
    assert _names_rider(node, *entries[-1])
