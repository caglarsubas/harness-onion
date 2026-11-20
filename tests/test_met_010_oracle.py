"""D5a oracle for slot 292: MET-010 (IND-BANK-003 and LAB-SYNC-002, K = 2).

D5a: owner decision D5a requires a contract packet to carry black-box tests written
outside the candidate by a non-author. This file is MET-010's D5a oracle (gate
ORACLE_TESTS), written from CONTRACT_292 rev 4 and the operator-stated facts only.

C18 (the era-read rule, CONTRACT_292 sections 2 and 8): every repository file this
oracle reads goes through the head layer's era reader, head.reviewed_bytes(path),
never the live tree. The one repository module loaded is the head layer
scripts/validate_met_010.py, by file path into a fresh module object. YAML is parsed
only through head.safe_load and JSON only with the json module. The catalog's names
come from the authority record (baselinePackets, NEW_PACKET, productPackets), never
from a listing.

Sources of expected values: CONTRACT_292 rev 4, section 1 (the step, the counts, the
two products in order and their repositories), section 2 (B1's predecessors, C18),
section 3 (the two frozen product YAMLs), section 4 (the head, its product part, the
authority record, the head-test row), section 5 (the packet YAML and the rider),
section 6 (the gate set) and section 8 (the light checks); and the facts the operator
stated in the oracle brief (the two frozen product digests, the head layer's
interface and its record context at K = 2). Each expected value carries its cite on
the assert's line or the line directly above it.

The weights table, the authority record, the hunk-class record, the registry and the
YAMLs are fixtures: read at run time and mutated only as deep-copied plain data. No
digest of the table, the head, the authority or the hunk-class record, and no value
of the head-test row, is pinned here, so the file holds on the c3 candidate and after
the measured step (CONTRACT_292 section 7, step 3).
"""

import copy
import hashlib
import importlib.util
import json
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
HEAD_FILE = ROOT / "scripts" / "validate_met_010.py"

# CONTRACT_292 section 1: the meta packet and the two products, in the read's order.
NEW_ID = "MET-010"
PRODUCTS = ("IND-BANK-003", "LAB-SYNC-002")
# CONTRACT_292 section 1: each product's repository.
REPOSITORIES = {
    "IND-BANK-003": "mas-harness-industry-packs",
    "LAB-SYNC-002": "mas-harness-research-lab",
}
# CONTRACT_292 section 2: B1's predecessors.
PREDECESSORS = {
    "IND-BANK-003": ["IND-TRANSPORT-001A"],
    "LAB-SYNC-002": ["LAB-TRANSPORT-001"],
    "MET-010": ["MET-009"],
}
# operator-stated: the freeze record's digests of the two product YAMLs.
FROZEN_SHA256 = {
    "IND-BANK-003": "d07059d67bf0180a9e7c0e97845a547823b38cb668d026ea878628f94984bf6f",
    "LAB-SYNC-002": "467b12aff2c1815d12a1ebf9dc4a5a15c4af43bde5aabffa3368c1d89d20be6a",
}
# CONTRACT_292 section 1: the catalog pair (310, 313).
BASE_COUNT = 310
CATALOG_COUNT = 313
# CONTRACT_292 section 4: the authority record and its schema; the head and its test.
AUTHORITY_REL = "architecture/first-rider-pair-authority.json"
AUTHORITY_SCHEMA = "harness.planeon.ai/first-rider-pair-authority/v1"
HEAD_REL = "scripts/validate_met_010.py"
HEAD_TEST_REL = "tests/test_met_010.py"
# CONTRACT_292 section 5: the packet YAML, the rider registry and the hunk-class record.
PACKET_REL = "task-packets/MET-010.yaml"
REGISTRY_REL = "architecture/review-record/briefs.json"
HUNK_RECORD_REL = "architecture/chain-checkpoint/hunk-classes/292.json"
RIDER = "MET-010/packet"
ACCEPTED_BASE = (
    "Accepted base is main d144e3fcdefbc55053e01db982bbd990c7f552b5, tree "
    "31c1ae78341db693a5a9cdea03ba4cc74e5a181c, holding 310 immutable packets "
    "including MET-009."
)
# CONTRACT_292 section 1: briefs.json 38 -> 39 entries.
REGISTRY_ENTRIES = 39
# CONTRACT_292 sections 4, 6 and 8: the weights table, 212 -> 213 entries.
TABLE_REL = "ci/parallel_suite_weights.json"
TABLE_ENTRIES = 213
# CONTRACT_292 section 3: LAB-SYNC-002's allowedPaths and the five quoted OK lines.
LAB_ALLOWED_PATHS = [
    "research/",
    "design/tokens/pages.css",
    "design/pages/glossary-families.md",
]
LAB_OK_LINES = (
    "MANIFEST OK: 371 files",
    "PRIVACY OK: 368 files, 0 hits, 0 name digests loaded",
    "PREREG OK: 24 folders (1 pending), 10 reviewed, 3 records",
    "RERUN OK: 23 entries (1 pending); LEDGER_REDERIVED 10, RAW_REPRODUCED 0, "
    "INDEPENDENT_REPLICATION 0, RECORDED 13",
    "PAGE OK: 24 experiments, 50 tools, 30 reads, 7 record keys",
)
# CONTRACT_292 section 3: IND-BANK-003's three replacements.
R03_OLD_BASE = "b9aed8eff38277479aae400f1edbb80320e7368c"
IB3_COMMANDS_TEXT = "IND-TRANSPORT-001A's 12 commands (equal to IND-TRANSPORT-001's)"
IB3_VERIFIER_TEXT = "the installed verifier accepts the head."
IB3_DROPPED_VERSION = "(bundle v7)"


# ---------------------------------------------------------------- helpers


def _sha256(data):
    return hashlib.sha256(data).hexdigest()


def _packet_rel(packet_id):
    return "task-packets/" + packet_id + ".yaml"


def _names(value, rel):
    text = str(value).replace("\\", "/")
    return text == rel or text.endswith("/" + rel)


def _catalog_names(head, authority):
    return [
        *authority["baselinePackets"],
        head.NEW_PACKET,
        *authority["productPackets"],
    ]


def _json_style(raw, value):
    """Find the json.dumps arguments that reproduce raw, for re-serialising mutations."""
    for indent in (2, None, 4, 1):
        for separators in ((",", ": "), (", ", ": "), (",", ":")):
            for sort_keys in (False, True):
                for ensure_ascii in (True, False):
                    text = json.dumps(
                        value,
                        indent=indent,
                        separators=separators,
                        sort_keys=sort_keys,
                        ensure_ascii=ensure_ascii,
                    )
                    for tail in ("\n", ""):
                        if (text + tail).encode("utf-8") == raw:
                            return (indent, separators, sort_keys, ensure_ascii, tail)
    return (2, (",", ": "), False, True, "\n")


def _dump(value, style):
    indent, separators, sort_keys, ensure_ascii, tail = style
    text = json.dumps(
        value,
        indent=indent,
        separators=separators,
        sort_keys=sort_keys,
        ensure_ascii=ensure_ascii,
    )
    return (text + tail).encode("utf-8")


def _pairs_of(container):
    if isinstance(container, dict):
        return list(container.items())
    return list(enumerate(container))


def _mentions(key, value, token):
    if isinstance(key, str) and token in key:
        return True
    return token in json.dumps(value, ensure_ascii=False)


def _containers(node):
    if isinstance(node, (dict, list)):
        yield node
        for _, child in _pairs_of(node):
            yield from _containers(child)


def _entries(registry, token):
    """The largest container in the registry with an element that mentions token."""
    best = None
    for container in _containers(registry):
        hit = any(_mentions(key, child, token) for key, child in _pairs_of(container))
        if hit and (best is None or len(container) > len(best)):
            best = container
    return best


def _rider_keys(entries, token):
    return [key for key, child in _pairs_of(entries) if _mentions(key, child, token)]


def _remove(entries, key):
    if isinstance(entries, dict):
        del entries[key]
    else:
        entries.pop(key)


def _registry_case(registry, case):
    mutated = copy.deepcopy(registry)
    entries = _entries(mutated, NEW_ID)
    riders = _rider_keys(entries, NEW_ID)
    rider = riders[0]
    if case == "drop-rider":
        _remove(entries, rider)
    elif case == "second-rider":
        second = NEW_ID + "/contract"
        twin = json.loads(json.dumps(entries[rider]).replace(RIDER, second))
        if isinstance(entries, dict):
            twin_key = rider.replace(RIDER, second)
            if twin_key == rider:
                twin_key = rider + "/second"
            entries[twin_key] = twin
        else:
            entries.append(twin)
    else:
        base_key = next(key for key, _ in _pairs_of(entries) if key not in riders)
        _remove(entries, base_key)
    return mutated


def _replace_strings(node, old, new):
    count = 0
    for key, value in _pairs_of(node):
        if isinstance(value, str):
            if old in value:
                node[key] = value.replace(old, new)
                count += 1
        elif isinstance(value, (dict, list)):
            count += _replace_strings(value, old, new)
    return count


def _empty_outcomes(node):
    count = 0
    for key, value in _pairs_of(node):
        if isinstance(key, str) and (
            "outcome" in key.casefold() or "statement" in key.casefold()
        ):
            if value:
                node[key] = type(value)() if isinstance(value, (str, list, dict)) else None
                count += 1
        elif isinstance(value, (dict, list)):
            count += _empty_outcomes(value)
    return count


def _table_row_pairs(head):
    """The key/value pairs, as written, of the table object that holds the head-test row."""
    seen = []

    def hook(pairs):
        seen.append(pairs)
        return dict(pairs)

    json.loads(head.reviewed_bytes(TABLE_REL), object_pairs_hook=hook)
    return [pairs for pairs in seen if any(key == HEAD_TEST_REL for key, _ in pairs)]


def _packet_files(head):
    return {path: head.reviewed_bytes(path) for path in head.PACKET_FILES}


def _errata_inputs(head, authority, hunk_record):
    changed = copy.deepcopy(authority["changedFiles"])
    befores = {
        path: head._undo_this_layer(path, head.reviewed_bytes(path))
        for path in changed
        if path in head.ERRATA_LINES
    }
    classes = copy.deepcopy(hunk_record["classes"])
    return classes, changed, befores


def _registry_inputs(head):
    raw = head.reviewed_bytes(REGISTRY_REL)
    briefs = {head.PACKET_BRIEF: head.reviewed_bytes(head.PACKET_BRIEF)}
    return raw, briefs


# ---------------------------------------------------------------- fixtures


@pytest.fixture(scope="module")
def head():
    spec = importlib.util.spec_from_file_location("met_010_head_for_oracle", HEAD_FILE)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.fixture(scope="module")
def authority(head):
    return json.loads(head.reviewed_bytes(AUTHORITY_REL))


@pytest.fixture(scope="module")
def catalog_bytes(head, authority):
    return {
        name: head.reviewed_bytes(_packet_rel(name))
        for name in _catalog_names(head, authority)
    }


@pytest.fixture(scope="module")
def catalog(head, catalog_bytes):
    return {name: head.safe_load(data) for name, data in catalog_bytes.items()}


@pytest.fixture(scope="module")
def hunk_raw(head):
    return head.reviewed_bytes(HUNK_RECORD_REL)


@pytest.fixture(scope="module")
def hunk_record(hunk_raw):
    return json.loads(hunk_raw)


@pytest.fixture(scope="module")
def hunk_inputs(head, authority, hunk_record):
    changed = authority["changedFiles"]
    afters = {
        path: head.reviewed_bytes(path)
        for path, entry in changed.items()
        if entry["reverseHunks"]
    }
    classify = head._era_rule(head.READER_PATH, head.READER_NAME).classify
    context = head._v24_context(
        head.authority(), copy.deepcopy(hunk_record["hunkClassContext"])
    )
    return changed, afters, classify, context


# ------------------------------------------- 1. the two product YAMLs (sections 1-4)


@pytest.mark.parametrize("pid", PRODUCTS)
def test_product_yaml_is_the_frozen_file(head, pid):
    """CONTRACT_292 section 3: each product YAML is the lane's frozen bytes (the freeze digest)."""
    data = head.reviewed_bytes(_packet_rel(pid))
    # operator-stated
    assert _sha256(data) == FROZEN_SHA256[pid]
    # operator-stated
    assert b"@@R" not in data


def test_head_new_packet_and_product_order(head):
    """CONTRACT_292 section 1 (and section 4): NEW_PACKET and PRODUCT_PACKETS in the read's order."""
    # CONTRACT_292 section 1
    assert head.NEW_PACKET == NEW_ID
    # CONTRACT_292 section 1
    assert tuple(head.PRODUCT_PACKETS) == PRODUCTS


@pytest.mark.parametrize("pid", PRODUCTS)
def test_product_yaml_repository_and_predecessors(head, pid):
    """CONTRACT_292 sections 1 and 2: each product's id, repository and B1 predecessors."""
    packet = head.safe_load(head.reviewed_bytes(_packet_rel(pid)))
    # CONTRACT_292 section 1
    assert packet["id"] == pid
    # CONTRACT_292 section 1
    assert str(packet["repository"]).casefold() == REPOSITORIES[pid]
    # CONTRACT_292 section 2
    assert packet["predecessors"] == PREDECESSORS[pid]


def test_authority_record_identity(head, authority):
    """CONTRACT_292 section 4: the authority record's path and schema, as the head reads it."""
    # CONTRACT_292 section 4
    assert _names(head.AUTHORITY_PATH, AUTHORITY_REL)
    # operator-stated
    assert _sha256(head.reviewed_bytes(AUTHORITY_REL)) == head.AUTHORITY_SHA256
    has_schema = any(value == AUTHORITY_SCHEMA for value in authority.values())
    # CONTRACT_292 section 4
    assert has_schema
    same = head.authority() == authority
    # operator-stated
    assert same


def test_authority_product_packets(head, authority):
    """CONTRACT_292 sections 1 and 4: productPackets names the two in order with each file's sha256."""
    product_packets = authority["productPackets"]
    # CONTRACT_292 section 1
    assert list(product_packets) == list(PRODUCTS)
    # CONTRACT_292 section 4
    assert sorted(authority["productComparators"]) == sorted(PRODUCTS)
    for pid in PRODUCTS:
        # operator-stated
        assert product_packets[pid] == FROZEN_SHA256[pid]
        # CONTRACT_292 section 4
        assert product_packets[pid] == _sha256(head.reviewed_bytes(_packet_rel(pid)))


@pytest.mark.parametrize("pid", PRODUCTS)
def test_authority_product_comparator(head, authority, pid):
    """CONTRACT_292 section 4: productComparators pins each product's one predecessor and its digest."""
    entry = authority["productComparators"][pid]
    predecessor = PREDECESSORS[pid][0]
    # operator-stated
    assert sorted(entry) == ["packet", "sha256"]
    # CONTRACT_292 section 4
    assert entry["packet"] == predecessor
    # CONTRACT_292 section 4
    assert entry["sha256"] == authority["baselinePackets"][predecessor]
    # CONTRACT_292 section 4
    assert entry["sha256"] == _sha256(head.reviewed_bytes(_packet_rel(predecessor)))


def test_catalog_names_and_base_digests(head, authority, catalog_bytes):
    """CONTRACT_292 section 1: 310 base packets, 313 in the catalog, no predecessor YAML edited."""
    names = _catalog_names(head, authority)
    # CONTRACT_292 section 1
    assert len(authority["baselinePackets"]) == BASE_COUNT
    # CONTRACT_292 section 1
    assert len(names) == CATALOG_COUNT
    # CONTRACT_292 section 1
    assert len(set(names)) == CATALOG_COUNT
    mismatched = sum(
        1
        for pid, digest in authority["baselinePackets"].items()
        if _sha256(catalog_bytes[pid]) != digest
    )
    # operator-stated
    assert mismatched == 0


def test_historical_catalog_is_the_base(head, authority, catalog):
    """CONTRACT_292 sections 1 and 4: historical_catalog over the whole catalog returns the 310 base ids."""
    # CONTRACT_293 section 5 (erratum E4): the catalog stays strict, so 292's era catalog
    # alone (313 names) is refused; the whole catalog at 293 is those 313 plus MET-011,
    # read through the head's era reader (C18).
    mapping = dict(catalog)
    # CONTRACT_292 section 1 (after 293, MET-011 alone); CONTRACT_293 section 5
    later = "MET-011"
    mapping[later] = head.safe_load(head.reviewed_bytes(_packet_rel(later)))
    # CONTRACT_292 section 1 (314 after 293); CONTRACT_293 section 5 (erratum E4)
    assert len(mapping) == CATALOG_COUNT + 1
    result = head.historical_catalog(mapping)
    # CONTRACT_292 section 1
    assert len(result) == BASE_COUNT
    differing = len(set(result) ^ set(authority["baselinePackets"]))
    # CONTRACT_292 section 4
    assert differing == 0


@pytest.mark.parametrize(
    "case", ["lacks-IND-BANK-003", "lacks-LAB-SYNC-002", "adds-an-id"]
)
def test_historical_catalog_refuses(head, catalog, case):
    """CONTRACT_292 section 4: historical_catalog refuses a mapping that lacks or adds an id."""
    mapping = dict(catalog)
    if case == "adds-an-id":
        mapping["MET-011"] = copy.deepcopy(catalog[NEW_ID])
    else:
        del mapping[case.split("-", 1)[1]]
    # operator-stated
    with pytest.raises(ValueError):
        head.historical_catalog(mapping)


def test_lab_sync_002_paths_and_six_commands(catalog):
    """CONTRACT_292 section 3: LAB-SYNC-002's allowedPaths and LAB-SYNC-001's six argv, byte-exact."""
    packet = catalog["LAB-SYNC-002"]
    # CONTRACT_292 section 3
    assert packet["allowedPaths"] == LAB_ALLOWED_PATHS
    commands = packet["offlineAcceptanceCommands"]
    # CONTRACT_292 section 3
    assert len(commands) == 6
    # CONTRACT_292 section 3
    assert commands == catalog["LAB-SYNC-001"]["offlineAcceptanceCommands"]
    # CONTRACT_292 section 3
    assert commands == catalog["LAB-TRANSPORT-001"]["offlineAcceptanceCommands"]


def test_ind_bank_003_keeps_the_twelve_commands(catalog):
    """CONTRACT_292 section 3 (IB3-C1-11): argv items 1-6 and 11-16 are IND-TRANSPORT-001A's 12."""
    commands = catalog["IND-BANK-003"]["offlineAcceptanceCommands"]
    kept = commands[0:6] + commands[10:16]
    # CONTRACT_292 section 3
    assert len(kept) == 12
    # CONTRACT_292 section 3
    assert kept == catalog["IND-TRANSPORT-001A"]["offlineAcceptanceCommands"]
    # CONTRACT_292 section 3
    assert kept == catalog["IND-TRANSPORT-001"]["offlineAcceptanceCommands"]


def test_ind_bank_003_evidence_replacements(catalog):
    """CONTRACT_292 section 3 (C1-5): the three replacements in expectedEvidence[0], [1] and [3]."""
    evidence = catalog["IND-BANK-003"]["expectedEvidence"]
    # CONTRACT_292 section 3
    assert R03_OLD_BASE not in evidence[0]
    # CONTRACT_292 section 3
    assert IB3_COMMANDS_TEXT in evidence[1]
    # CONTRACT_292 section 3
    assert IB3_VERIFIER_TEXT in evidence[3]
    # CONTRACT_292 section 3
    assert IB3_DROPPED_VERSION not in evidence[3]


@pytest.mark.parametrize(
    "line", LAB_OK_LINES, ids=["manifest", "privacy", "prereg", "rerun", "page"]
)
def test_lab_sync_002_evidence_ok_lines(catalog, line):
    """CONTRACT_292 section 3: LAB-SYNC-002's expectedEvidence carries the six commands' OK lines."""
    text = "\n".join(catalog["LAB-SYNC-002"]["expectedEvidence"])
    # CONTRACT_292 section 3
    assert line in text


# ------------------------------------------- 2. the head layer (section 4): V1, E3, V4, V6


def test_v1_passes_on_live_inputs(head):
    """CONTRACT_292 section 4: V1 checks this packet's files (the two product YAMLs) by digest."""
    head.validate_packet_files()
    files = _packet_files(head)
    # operator-stated
    assert sorted(str(path) for path in files) == sorted(_packet_rel(pid) for pid in PRODUCTS)
    # operator-stated
    assert head.check_packet_files(files) is None


@pytest.mark.parametrize("pid", PRODUCTS)
def test_v1_refuses_a_changed_byte(head, pid):
    """CONTRACT_292 section 4: V1 refuses a product YAML with one byte changed."""
    files = _packet_files(head)
    rel = _packet_rel(pid)
    data = files[rel]
    files[rel] = data[:-1] + bytes([data[-1] ^ 0x01])
    # operator-stated
    with pytest.raises(ValueError, match=NEW_ID):
        head.check_packet_files(files)


@pytest.mark.parametrize("pid", PRODUCTS)
def test_v1_refuses_a_missing_file(head, pid):
    """CONTRACT_292 section 4: V1 refuses a mapping that lacks one product YAML."""
    files = _packet_files(head)
    del files[_packet_rel(pid)]
    # operator-stated
    with pytest.raises(ValueError, match=NEW_ID):
        head.check_packet_files(files)


def test_e3_passes_on_live_inputs(head, authority, hunk_record):
    """CONTRACT_292 section 4: E3 (the errata spans) holds on the era inputs."""
    head.validate_errata()
    classes, changed, befores = _errata_inputs(head, authority, hunk_record)
    uncovered = len(set(head.ERRATA_LINES) - set(befores))
    # operator-stated
    assert uncovered == 0
    # operator-stated
    assert head.check_errata(classes, changed, befores) is None


def test_e3_refuses_other_outside_errata_lines(head, authority, hunk_record):
    """CONTRACT_292 section 4: E3 refuses class other on a file outside ERRATA_LINES."""
    classes, changed, befores = _errata_inputs(head, authority, hunk_record)
    candidates = sorted(
        path
        for path, hunk_classes in classes.items()
        if path not in head.ERRATA_LINES and hunk_classes and hunk_classes[0] != "other"
    )
    found = len(candidates)
    assert found >= 1
    classes[candidates[0]][0] = "other"
    # operator-stated
    with pytest.raises(ValueError, match=NEW_ID):
        head.check_errata(classes, changed, befores)


def test_v4_passes_on_live_inputs(head):
    """CONTRACT_292 sections 1 and 5: V4, the registry is the base plus the one MET-010/packet rider."""
    head.validate_registry()
    raw, briefs = _registry_inputs(head)
    # CONTRACT_292 section 5
    assert _names(head.REGISTRY_PATH, REGISTRY_REL)
    # operator-stated
    assert head.check_registry(raw, briefs) is None
    entries = _entries(json.loads(raw), NEW_ID)
    # CONTRACT_292 section 1
    assert len(entries) == REGISTRY_ENTRIES
    riders = _rider_keys(entries, NEW_ID)
    # CONTRACT_292 section 5
    assert len(riders) == 1
    named = _mentions(riders[0], entries[riders[0]], RIDER)
    # CONTRACT_292 section 1
    assert named


@pytest.mark.parametrize("case", ["drop-rider", "second-rider", "drop-base-entry"])
def test_v4_refuses_a_registry_other_than_base_plus_rider(head, case):
    """CONTRACT_292 sections 1 and 5: V4 refuses a registry that is not the base plus the one rider."""
    raw, briefs = _registry_inputs(head)
    registry = json.loads(raw)
    mutated = _registry_case(registry, case)
    # operator-stated
    with pytest.raises(ValueError, match=NEW_ID):
        head.check_registry(_dump(mutated, _json_style(raw, registry)), briefs)


def test_v6_passes_on_live_inputs(head, hunk_raw, hunk_record, hunk_inputs):
    """CONTRACT_292 sections 4 and 5: V6, the hunk-class record 292.json, at K = 2."""
    head.validate_hunk_record()
    changed, afters, classify, context = hunk_inputs
    # CONTRACT_292 section 5
    assert _names(head.HUNK_RECORD_PATH, HUNK_RECORD_REL)
    # operator-stated
    assert hunk_record["hunkClassContext"]["steps"] == [1, 3]
    # operator-stated
    assert hunk_record["hunkClassContext"]["countPairs"] == []
    result = head.check_hunk_record(
        hunk_raw, copy.deepcopy(changed), afters, classify, context, head.HUNK_RULE_SHA256
    )
    # operator-stated
    assert result is None


V6_CASES = [
    "extra-member",
    "missing-member",
    "vocabulary",
    "record-rule-digest",
    "rule-digest-argument",
    "steps",
    "count-pairs",
    "outcome-statement",
]


@pytest.mark.parametrize("case", V6_CASES)
def test_v6_refuses_a_broken_record(head, hunk_raw, hunk_record, hunk_inputs, case):
    """CONTRACT_292 section 4: V6 refuses broken members, vocabulary, rule digest, context or outcome."""
    changed, afters, classify, context = hunk_inputs
    record = copy.deepcopy(hunk_record)
    rule_sha = head.HUNK_RULE_SHA256
    other_sha = "1" * 64 if rule_sha == "0" * 64 else "0" * 64
    touched = 1
    if case == "extra-member":
        record["oracleExtraMember"] = True
    elif case == "missing-member":
        del record["classes"]
    elif case == "vocabulary":
        path = sorted(p for p, hunk_classes in record["classes"].items() if hunk_classes)[0]
        record["classes"][path][0] = "not-a-hunk-class"
    elif case == "record-rule-digest":
        touched = _replace_strings(record, rule_sha, other_sha)
    elif case == "rule-digest-argument":
        rule_sha = other_sha
    elif case == "steps":
        record["hunkClassContext"]["steps"] = [1, 2]
    elif case == "count-pairs":
        record["hunkClassContext"]["countPairs"] = [[310, 313]]
    else:
        record["outcomeStatements"] = ["An outcome statement added by the oracle."]
        # operator-stated
        assert len(record["outcomeStatements"]) >= 1
    # operator-stated
    assert touched >= 1
    raw = hunk_raw if case == "rule-digest-argument" else _dump(
        record, _json_style(hunk_raw, hunk_record)
    )
    # operator-stated
    with pytest.raises(ValueError, match=NEW_ID):
        head.check_hunk_record(raw, copy.deepcopy(changed), afters, classify, context, rule_sha)


# ------------------------------------------- 3. the packet YAML (sections 1, 2 and 5)


def test_packet_yaml_identity_predecessors_and_base(head):
    """CONTRACT_292 sections 1, 2 and 5: MET-010's id, B1 predecessors and accepted-base line."""
    packet = head.safe_load(head.reviewed_bytes(PACKET_REL))
    # CONTRACT_292 section 1
    assert packet["id"] == NEW_ID
    # CONTRACT_292 section 2
    assert packet["predecessors"] == PREDECESSORS[NEW_ID]
    has_base = any(
        isinstance(line, str) and ACCEPTED_BASE in line for line in packet["contracts"]
    )
    # CONTRACT_292 section 5
    assert has_base


def test_packet_yaml_form(head):
    """CONTRACT_292 section 5: MET-010.yaml in MET-009's form, 16 keys, one per line."""
    raw = head.reviewed_bytes(PACKET_REL)
    packet = head.safe_load(raw)
    lines = raw.decode("utf-8").splitlines()
    # operator-stated
    assert len(packet) == 16
    # operator-stated
    assert len(lines) == 16
    mismatches = 0
    for line in lines:
        key, sep, value = line.partition(": ")
        try:
            same = bool(sep) and key in packet and json.loads(value) == packet[key]
        except ValueError:
            same = False
        if not same:
            mismatches += 1
    # operator-stated
    assert mismatches == 0


def test_packet_yaml_allowed_paths(head, authority):
    """CONTRACT_292 section 5: allowedPaths is the authority's changed and new files plus five named files."""
    packet = head.safe_load(head.reviewed_bytes(PACKET_REL))
    named = [AUTHORITY_REL, HEAD_REL, PACKET_REL] + [_packet_rel(pid) for pid in PRODUCTS]
    missing = sum(1 for path in named if path not in packet["allowedPaths"])
    # CONTRACT_292 section 5
    assert missing == 0
    expected = set(authority["changedFiles"]) | set(authority["newFiles"]) | set(named)
    differing = len(set(packet["allowedPaths"]) ^ expected)
    # CONTRACT_292 section 5
    assert differing == 0


# ------------------------------------------- 4. the weights table (sections 4, 6 and 8)


def test_weights_table_raw_keys_equal_effective_keys(head):
    """CONTRACT_292 sections 4, 6 and 8 (P2): raw = effective = 213, with the one head-test row."""
    rows = _table_row_pairs(head)
    # CONTRACT_292 section 6
    assert len(rows) == 1
    raw_keys = [key for key, _ in rows[0]]
    effective_keys = list(dict(rows[0]))
    same = raw_keys == effective_keys
    # CONTRACT_292 section 8
    assert same
    # CONTRACT_292 section 8
    assert len(raw_keys) == TABLE_ENTRIES
    # CONTRACT_292 section 4
    assert HEAD_TEST_REL in effective_keys


def test_weights_table_keys_name_regular_files(head):
    """CONTRACT_292 sections 6 and 8: every weights key names a regular file (read through reviewed_bytes)."""
    rows = _table_row_pairs(head)
    keys = list(dict(rows[0]))
    # CONTRACT_292 section 8
    assert len(keys) == TABLE_ENTRIES
    failures = 0
    for key in keys:
        try:
            data = head.reviewed_bytes(key)
        except Exception:
            failures += 1
            continue
        if not isinstance(data, bytes):
            failures += 1
    # operator-stated
    assert failures == 0
