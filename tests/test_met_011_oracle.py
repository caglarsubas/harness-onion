"""D5a oracle tests for MET-011 (slot 293): CHAIN-COMPACTION-002's ledger rewrite, the third checkpoint, at K = 0.

Owner decision D5a: black-box tests written outside the candidate by a fresh non-author, who saw neither the candidate's
code nor any test. Every expected value comes from CONTRACT_293 r2 with errata E1-E3 (sections 1, 4, 4.1, 5, 6, 7, 11
and 17) or from a fact the operator stated from the candidate (marked "operator-stated"); each assert cites its source
on its own line or the line above. The repository files read at run time are fixtures, never expectations.

C18 (the era-read rule, CONTRACT_293 section 2): every repository file is read only through the head's era reader,
head.reviewed_bytes(path); JSON is parsed with json and YAML only through head.safe_load. The catalog's names come
from the head's authority (its baselinePackets plus head.NEW_PACKET), never from a listing. The only repository module
loaded is the head, scripts/validate_met_011.py, by file path into a fresh module object.

Tests that drive a head check over the live tree pass from F on (section 8: before F they are in the red set by
design). The mutation tests build every case from plain data (copies, bytes and mappings passed to a check_*), and
their refusal does not depend on which ledger is on disk.
"""

import copy
import hashlib
import importlib.util
import json
import re
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

HEAD_FILE = ROOT / "scripts" / "validate_met_011.py"
HEAD_PATH = "scripts/validate_met_011.py"
PACKET_YAML = "task-packets/MET-011.yaml"
PREDECESSOR_YAML = "task-packets/MET-010.yaml"
TABLE_PATH = "ci/parallel_suite_weights.json"
HUNK_RECORD = "architecture/chain-checkpoint/hunk-classes/293.json"
LEDGER = "architecture/chain-checkpoint/record.json"
REGISTRY = "architecture/review-record/briefs.json"
AUTHORITY_FILE = "architecture/ledger-rewrite-293-authority.json"
RIDER = "MET-011/packet"
# CONTRACT_293 section 4, E-9 and E-11: the base ledger (286's) that verifyReference and beforeSha256 name.
BASE_LEDGER_SHA256 = "993b4618bf4ad9b6440a3e41bdbeb238cc50455f7f151584cbd6e394277e5084"
# CONTRACT_293 section 4: the base ledger's 97 layers, one per slot, 189-285.
BASE_SLOTS = list(range(189, 286))
# CONTRACT_293 section 4, E-2 and E-12: the third ledger's layers 189-292, 104 entries, one per slot.
NEW_SLOTS = list(range(189, 293))
# CONTRACT_293 section 4, E-7: the exclusion's three files, sorted and unique.
EXCLUDED_FILES = [
    "architecture/chain-checkpoint/hunk-classes/293.json",
    "architecture/chain-checkpoint/record.json",
    "architecture/ledger-rewrite-293-authority.json",
]
# CONTRACT_293 section 4 (E-2 to E-13): the top-level members a rewrite changes; the rest equal the base's.
CHANGING_MEMBERS = {
    "checkpointSlot",
    "checkpointBaseline",
    "exclusion",
    "fullRunProof",
    "sizeBytes",
    "sizeBound",
    "writingCommit",
    "writingTree",
    "writingRun",
}
SIXTEEN_MIB = 16 * 1024 * 1024


# ---------------------------------------------------------------------------------------------------------------------
# Loading the head and its era inputs (fixtures, never expectations)
# ---------------------------------------------------------------------------------------------------------------------


def _load_head():
    spec = importlib.util.spec_from_file_location("met_011_head_under_d5a_oracle", HEAD_FILE)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.fixture(scope="module")
def head():
    return _load_head()


@pytest.fixture(scope="module")
def authority(head):
    return copy.deepcopy(head.authority())


@pytest.fixture(scope="module")
def catalog(head, authority):
    names = [*authority["baselinePackets"], head.NEW_PACKET]
    return {name: head.safe_load(head.reviewed_bytes("task-packets/" + name + ".yaml")) for name in names}


@pytest.fixture(scope="module")
def packet(head):
    raw = head.reviewed_bytes(PACKET_YAML)
    return raw, head.safe_load(raw)


@pytest.fixture(scope="module")
def predecessor(head):
    return head.safe_load(head.reviewed_bytes(PREDECESSOR_YAML))


@pytest.fixture(scope="module")
def ledger(head):
    raw = head.reviewed_bytes(head.LEDGER_PATH)
    return raw, json.loads(raw)


@pytest.fixture(scope="module")
def base_ledger(head, ledger):
    base_raw = head._undo_this_layer(head.LEDGER_PATH, ledger[0])
    return base_raw, json.loads(base_raw)


@pytest.fixture(scope="module")
def hunk_record(head):
    raw = head.reviewed_bytes(head.HUNK_RECORD_PATH)
    return raw, json.loads(raw)


@pytest.fixture(scope="module")
def registry(head):
    raw = head.reviewed_bytes(head.REGISTRY_PATH)
    return raw, json.loads(raw)


@pytest.fixture(scope="module")
def layer_validators(head, ledger):
    obj = ledger[1]
    member = _layers_member(obj)
    paths = [entry["validatorPath"] for entry in _entries(obj, member)]
    return {path: head.reviewed_bytes(path) for path in paths}


@pytest.fixture(scope="module")
def errata_befores(head, authority):
    changed = authority["changedFiles"]
    paths = list(head.ERRATA_LINES)
    # CONTRACT_293 section 11 (1): E3's named files are files the built authority changes (class-other hunks)
    assert set(paths) <= set(changed)
    return {path: head._undo_this_layer(path, head.reviewed_bytes(path)) for path in paths}


@pytest.fixture(scope="module")
def v6_inputs(head, authority, hunk_record):
    changed = authority["changedFiles"]
    afters = {path: head.reviewed_bytes(path) for path, entry in changed.items() if entry.get("reverseHunks")}
    classify = head._era_rule(head.READER_PATH, head.READER_NAME).classify
    context = head._v24_context(head.authority(), hunk_record[1]["hunkClassContext"])
    return afters, classify, context


# ---------------------------------------------------------------------------------------------------------------------
# Plain-data helpers
# ---------------------------------------------------------------------------------------------------------------------


def _sha256(data):
    return hashlib.sha256(data).hexdigest()


def _layers_member(obj):
    found = []
    for key, value in obj.items():
        entries = list(value.values()) if isinstance(value, dict) else value
        if isinstance(entries, list) and entries and all(
            isinstance(entry, dict) and "validatorPath" in entry for entry in entries
        ):
            found.append(key)
    # operator-stated: each ledger layer names its validatorPath; one member holds the layers
    assert len(found) == 1, "one layers member"
    return found[0]


def _entries(obj, member):
    value = obj[member]
    return list(value.values()) if isinstance(value, dict) else list(value)


def _as_slot(value):
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    if isinstance(value, str) and value.isdigit():
        return int(value)
    return None


def _slot_key(base_obj, member):
    value = base_obj[member]
    if isinstance(value, dict):
        return None
    keys = sorted({key for entry in value for key in entry})
    matches = [key for key in keys if [_as_slot(entry.get(key)) for entry in value] == BASE_SLOTS]
    # CONTRACT_293 section 4: the base ledger's layers are slots 189-285, one per slot, no gap
    assert matches, "a layer field carries the slot"
    return matches[0]


def _slots(obj, member, slot_key):
    value = obj[member]
    if isinstance(value, dict):
        return [_as_slot(key) for key in value]
    return [_as_slot(entry.get(slot_key)) for entry in value]


def _strings(node, out):
    if isinstance(node, dict):
        for key, value in node.items():
            out.add(key)
            _strings(value, out)
    elif isinstance(node, list):
        for value in node:
            _strings(value, out)
    elif isinstance(node, str):
        out.add(node)
    return out


def _dump_like(raw, original, mutated):
    """Serialise `mutated` in the form that reproduces `raw` from `original`, so a refusal is the mutation's."""
    match = re.match(rb"[\[{]\n( +)\S", raw)
    indent = len(match.group(1)) if match else None
    forms = []
    for sort_keys in (True, False):
        for ensure_ascii in (True, False):
            if indent is None:
                forms.append({"separators": (",", ":"), "sort_keys": sort_keys, "ensure_ascii": ensure_ascii})
                forms.append({"sort_keys": sort_keys, "ensure_ascii": ensure_ascii})
            else:
                forms.append({"indent": indent, "sort_keys": sort_keys, "ensure_ascii": ensure_ascii})
    for form in forms:
        text = json.dumps(original, **form)
        for tail in ("\n", ""):
            if (text + tail).encode("utf-8") == raw:
                return (json.dumps(mutated, **form) + tail).encode("utf-8")
    return (json.dumps(mutated, indent=2, sort_keys=True) + "\n").encode("utf-8")


def _class_of(item):
    if isinstance(item, str):
        return item
    if isinstance(item, dict):
        return item.get("class")
    return None


def _with_class(item, value):
    if isinstance(item, dict):
        changed = dict(item)
        changed["class"] = value
        return changed
    return value


def _handles(container):
    if isinstance(container, dict):
        return list(container)
    if isinstance(container, list):
        return list(range(len(container)))
    return []


def _rider_site(obj):
    """The path to the registry container holding the rider, and the rider's handle in it."""
    trail = []
    node = obj
    while True:
        if isinstance(node, dict):
            hits = [key for key in node if RIDER in key or RIDER in json.dumps(node[key])]
        elif isinstance(node, list):
            hits = [index for index, value in enumerate(node) if RIDER in json.dumps(value)]
        else:
            hits = []
        # CONTRACT_293 section 6: the rider MET-011/packet is one entry of the registry
        assert len(hits) == 1, "the rider is one entry"
        handle = hits[0]
        child = node[handle]
        direct = (
            (isinstance(node, dict) and RIDER in handle)
            or (isinstance(child, str) and RIDER in child)
            or (isinstance(child, dict) and any(isinstance(v, str) and RIDER in v for v in child.values()))
        )
        if direct:
            return trail, handle
        trail.append(handle)
        node = child


def _navigate(obj, trail):
    node = obj
    for handle in trail:
        node = node[handle]
    return node


def _vocabulary(node):
    if isinstance(node, dict):
        for key, value in node.items():
            if key == "classes":
                continue
            if isinstance(value, list) and value and all(isinstance(x, str) for x in value) and "other" in value:
                return value
            if isinstance(value, dict) and "other" in value:
                return value
            found = _vocabulary(value)
            if found is not None:
                return found
    elif isinstance(node, list):
        for value in node:
            found = _vocabulary(value)
            if found is not None:
                return found
    return None


def _replace_string(node, old, new):
    count = 0
    if isinstance(node, dict):
        for key in list(node):
            if key == "classes":
                continue
            if node[key] == old:
                node[key] = new
                count += 1
            else:
                count += _replace_string(node[key], old, new)
    elif isinstance(node, list):
        for index, value in enumerate(node):
            if value == old:
                node[index] = new
                count += 1
            else:
                count += _replace_string(value, old, new)
    return count


def _flip_hex(digest):
    return ("1" if digest[0] == "0" else "0") + digest[1:]


def _json_objects(node, out):
    """Every JSON object of a tree parsed with object_pairs_hook=list, as its raw (key, value) pairs."""
    if isinstance(node, list):
        if node and all(isinstance(item, tuple) for item in node):
            out.append(node)
            for _, value in node:
                _json_objects(value, out)
        else:
            for value in node:
                _json_objects(value, out)
    return out


def _table_rows(head):
    raw = head.reviewed_bytes(TABLE_PATH)
    objects = _json_objects(json.loads(raw, object_pairs_hook=list), [])
    rows = [pairs for pairs in objects if any(key == "tests/test_met_011.py" for key, _ in pairs)]
    return objects, rows


# ---------------------------------------------------------------------------------------------------------------------
# 1. The packet YAML (sections 1 and 6; erratum E2)
# ---------------------------------------------------------------------------------------------------------------------


def test_packet_paths_and_ids(head):
    """CONTRACT_293 section 1: the packet id and its files (head, authority, hunk-class record, ledger)."""
    # CONTRACT_293 section 1: MET-011 is the new packet id
    assert head.NEW_PACKET == "MET-011"
    # CONTRACT_293 section 1: AUTHORITY_PATH
    assert head.AUTHORITY_PATH == AUTHORITY_FILE
    # CONTRACT_293 section 1: the hunk-class record
    assert head.HUNK_RECORD_PATH == HUNK_RECORD
    # CONTRACT_293 section 1: record.json is the ledger, replaced in place at F
    assert head.LEDGER_PATH == LEDGER
    # CONTRACT_293 section 6: the rider lives in the review-record briefs registry
    assert head.REGISTRY_PATH == REGISTRY
    # CONTRACT_293 section 1: K = 0, one meta packet, so no product packets
    assert len(head.PRODUCT_PACKETS) == 0


def test_packet_id_and_predecessors(packet):
    """CONTRACT_293 sections 1 and 6: MET-011's id and predecessors ["MET-010"]."""
    data = packet[1]
    # CONTRACT_293 section 1: the packet id MET-011
    assert data["id"] == "MET-011"
    # CONTRACT_293 section 6: predecessors ["MET-010"]
    assert data["predecessors"] == ["MET-010"]


def test_packet_sixteen_members(packet, predecessor):
    """CONTRACT_293 section 6: the 16-member form of MET-PERF-049 and MET-010, no scope key."""
    data = packet[1]
    # CONTRACT_293 section 6: 16 members
    assert len(data) == 16
    # CONTRACT_293 section 6: no scope key ("scope = programme" is the roadmap item's label)
    assert "scope" not in data
    # CONTRACT_293 section 6: the 16-member form of MET-010
    assert set(data) == set(predecessor)


def test_packet_lines_form(packet):
    """CONTRACT_293 section 6 (the YAML), in the form the operator states: 16 keys, one line each, key: <JSON value>."""
    raw, data = packet
    lines = raw.decode("utf-8").splitlines()
    # operator-stated: 16 keys, each on one line
    assert len(lines) == 16
    for line in lines:
        key, sep, value = line.partition(": ")
        # operator-stated: each line is `key: <JSON value>`
        assert sep == ": "
        # operator-stated: the JSON value is the member's value
        assert json.loads(value) == data[key]


def test_packet_commands_and_offline_execution(packet, predecessor):
    """CONTRACT_293 section 6: the 64 commands and offlineExecution equal to MET-010's."""
    data = packet[1]
    # CONTRACT_293 section 6: the 64 commands
    assert len(data["offlineAcceptanceCommands"]) == 64
    # CONTRACT_293 section 6: the 64 commands equal to MET-010's
    assert data["offlineAcceptanceCommands"] == predecessor["offlineAcceptanceCommands"]
    # CONTRACT_293 section 6: offlineExecution equal to MET-010's
    assert data["offlineExecution"] == predecessor["offlineExecution"]


def test_packet_allowed_paths(packet):
    """CONTRACT_293 erratum E2 (section 17) and section 4.1 condition 1: 307 allowedPaths naming the exclusion files."""
    allowed = packet[1]["allowedPaths"]
    # CONTRACT_293 section 17 (erratum E2): allowedPaths are the dry set's 307 paths
    assert len(allowed) == 307
    # CONTRACT_293 section 17 (erratum E2): a set of 307 paths
    assert len(set(allowed)) == 307
    for path in EXCLUDED_FILES:
        # CONTRACT_293 section 4.1 condition 1: allowedPaths already name the three exclusion files
        assert path in allowed
    # CONTRACT_293 section 1: the head is one of the packet's files
    assert HEAD_PATH in allowed


# ---------------------------------------------------------------------------------------------------------------------
# 2. The era rule (section 5; erratum E1-15)
# ---------------------------------------------------------------------------------------------------------------------


def test_catalog_counts(head, authority, catalog):
    """CONTRACT_293 section 1 and E-2: 313 base packets in the authority, 314 in the catalog."""
    # CONTRACT_293 section 1 and section 4 E-2: the authority's baselinePackets are the 313 packets at 292's merge
    assert len(authority["baselinePackets"]) == 313
    # CONTRACT_293 section 1: the packet count moves from 313 to 314
    assert len(catalog) == 314
    # CONTRACT_293 section 1: MET-011 is new, not among the base packets
    assert head.NEW_PACKET not in authority["baselinePackets"]


def test_era_vector_1_full_set_peeled(head, authority, catalog):
    """CONTRACT_293 section 5, era vector 1: the full set is accepted with MET-011 peeled."""
    result = head.historical_catalog(copy.deepcopy(catalog))
    # CONTRACT_293 section 5 vector 1: MET-011 peeled
    assert head.NEW_PACKET not in result
    # CONTRACT_293 section 5 vector 1: the peeled catalog is the 313 base packets
    assert set(result) == set(authority["baselinePackets"])


def test_era_vector_2_pass_on_unchanged(head, catalog):
    """CONTRACT_293 section 5, era vector 2: 292's era catalog (313 names, no MET-011) is passed on unchanged."""
    era = {name: value for name, value in catalog.items() if name != head.NEW_PACKET}
    expected = copy.deepcopy(era)
    result = head.historical_catalog(copy.deepcopy(era))
    # CONTRACT_293 section 5 vector 2: 313 names
    assert len(expected) == 313
    # CONTRACT_293 section 5 vector 2: passed on unchanged
    assert result == expected


@pytest.mark.parametrize("vector", ["3a-minus-MET-010", "3a-minus-first", "3b-plus-unknown"])
def test_era_vector_3_refused(head, authority, catalog, vector):
    """CONTRACT_293 section 5, era vectors 3a (the full set minus one older packet) and 3b (plus one unknown name)."""
    packets = copy.deepcopy(catalog)
    if vector == "3a-minus-MET-010":
        del packets["MET-010"]
    elif vector == "3a-minus-first":
        del packets[sorted(authority["baselinePackets"])[0]]
    else:
        extra = copy.deepcopy(catalog["MET-010"])
        extra["id"] = "UNLISTED-293"
        packets["UNLISTED-293"] = extra
    # CONTRACT_293 section 5 vector 3: refused with the existing text
    with pytest.raises(ValueError, match="unexpected packet addition or loss"):
        head.historical_catalog(packets)


def test_era_non_mapping_refused(head, catalog):
    """CONTRACT_293 section 5 (erratum E1-15): a non-mapping is refused with "packet mapping" before the pass-on test."""
    names = sorted(name for name in catalog if name != head.NEW_PACKET)
    # CONTRACT_293 section 5 (E1-15): type(packets) is dict, else "packet mapping"
    with pytest.raises(ValueError, match="packet mapping"):
        head.historical_catalog(names)


# ---------------------------------------------------------------------------------------------------------------------
# 3. The head's checks (section 5): each passes on the live inputs and refuses a plain-data mutation
# ---------------------------------------------------------------------------------------------------------------------

LIVE_CHECKS = [
    "validate_packet_files",
    "validate_errata",
    "validate_ledger",
    "validate_inline",
    "validate_ledger_classes",
    "validate_registry",
    "validate_hunk_record",
    "validate_canonical_hunks",
]


@pytest.mark.parametrize("name", LIVE_CHECKS)
def test_live_check_passes(head, name):
    """CONTRACT_293 section 5: V1, E3, C1, C2, V6a, V4, V6 and the canonical check pass on the live tree (from F)."""
    getattr(head, name)()


def test_live_head_runs_in_order(head, catalog):
    """CONTRACT_293 section 5: validate_met_011 runs the head's checks in order over the catalog (from F)."""
    head.validate_met_011(copy.deepcopy(catalog))


@pytest.mark.parametrize("mutation", ["byte_changed", "file_missing"])
def test_v1_refuses_mutation(head, mutation):
    """CONTRACT_293 section 5 (V1, this packet's files by digest): a changed byte or a missing file is refused."""
    files = {path: head.reviewed_bytes(path) for path in head.PACKET_FILES}
    # operator-stated: check_* returns None on its live inputs (V1 passes at c4, erratum E3)
    assert head.check_packet_files(dict(files)) is None
    path = sorted(files)[0]
    if mutation == "byte_changed":
        data = files[path]
        files[path] = data[:-1] + bytes([data[-1] ^ 0x01]) if data else b"\x00"
    else:
        del files[path]
    # operator-stated: a check_* refusal is a ValueError whose message contains MET-011
    with pytest.raises(ValueError, match="MET-011"):
        head.check_packet_files(files)


def test_e3_refuses_other_class_outside_errata_lines(head, authority, hunk_record, errata_befores):
    """CONTRACT_293 section 5 (E3) and section 11 (1): an `other` class outside ERRATA_LINES is refused."""
    classes = copy.deepcopy(hunk_record[1]["classes"])
    # operator-stated: check_* returns None on its live inputs (E3 passes at c4, erratum E3)
    assert head.check_errata(copy.deepcopy(classes), copy.deepcopy(authority["changedFiles"]), errata_befores) is None
    target = None
    for path in sorted(classes):
        if path in head.ERRATA_LINES or path == head.LEDGER_PATH:
            continue
        container = classes[path]
        for handle in _handles(container):
            if _class_of(container[handle]) not in (None, "other"):
                target = (path, handle)
                break
        if target is not None:
            break
    # CONTRACT_293 section 6: the index appends are record-class hunks, outside E3's named files
    assert target is not None, "a non-other hunk outside ERRATA_LINES"
    path, handle = target
    classes[path][handle] = _with_class(classes[path][handle], "other")
    # operator-stated: a check_* refusal is a ValueError whose message contains MET-011
    with pytest.raises(ValueError, match="MET-011"):
        head.check_errata(classes, copy.deepcopy(authority["changedFiles"]), errata_befores)


@pytest.mark.parametrize("mutation", ["member_removed", "slot_changed"])
def test_c1_refuses_mutation(head, authority, ledger, layer_validators, mutation):
    """CONTRACT_293 section 5 (C1) and section 4 (E-1, E-2): a removed ledger member or a changed checkpointSlot."""
    raw, obj = ledger
    mutated = dict(obj)
    if mutation == "member_removed":
        # CONTRACT_293 section 4 E-9: writingRun is a member of the ledger
        assert "writingRun" in mutated
        del mutated["writingRun"]
    else:
        mutated["checkpointSlot"] = mutated["checkpointSlot"] + 1
    data = _dump_like(raw, obj, mutated)
    real = authority["changedFiles"].get(head.LEDGER_PATH)
    entry = {
        "beforeSha256": BASE_LEDGER_SHA256,
        "afterSha256": _sha256(data),
        "reverseHunks": copy.deepcopy(real["reverseHunks"]) if real else [],
    }
    # operator-stated: a check_* refusal is a ValueError whose message contains MET-011
    with pytest.raises(ValueError, match="MET-011"):
        head.check_ledger(data, dict(layer_validators), len(authority["baselinePackets"]), entry, True)


def test_c2_refuses_altered_reverse_hunk(head, authority, ledger):
    """CONTRACT_293 section 5 (C2) and E-11: an altered reverse hunk does not replay to the base record."""
    raw = ledger[0]
    real = authority["changedFiles"].get(head.LEDGER_PATH)
    if real is None:
        # before F there is no entry: the identity entry (no hunks) is outside E-11's 1 to 4,096
        entry = {"beforeSha256": BASE_LEDGER_SHA256, "afterSha256": _sha256(raw), "reverseHunks": []}
    else:
        entry = copy.deepcopy(real)
        hunks = entry["reverseHunks"]
        index = next(i for i, hunk in enumerate(hunks) if hunk["removeBase64"] != hunk["insertBase64"])
        hunks[index]["insertBase64"] = hunks[index]["removeBase64"]
    # operator-stated: a check_* refusal is a ValueError whose message contains MET-011
    with pytest.raises(ValueError, match="MET-011"):
        head.check_inline(entry, raw)


def test_v6a_refuses_non_other_class(head, authority, hunk_record):
    """CONTRACT_293 section 5 (V6a): a record.json class that is not `other` is refused."""
    classes = copy.deepcopy(hunk_record[1]["classes"])
    current = classes.get(head.LEDGER_PATH)
    if current is None or not _handles(current):
        classes[head.LEDGER_PATH] = ["record"]
    else:
        handle = _handles(current)[0]
        current[handle] = _with_class(current[handle], "record")
    # operator-stated: a check_* refusal is a ValueError whose message contains MET-011
    with pytest.raises(ValueError, match="MET-011"):
        head.check_ledger_classes(classes, copy.deepcopy(authority["changedFiles"]))


def test_v4_refuses_registry_without_rider(head, registry):
    """CONTRACT_293 section 5 (V4) and section 6: a registry without the one MET-011/packet rider is refused."""
    raw, obj = registry
    briefs = {head.PACKET_BRIEF: head.reviewed_bytes(head.PACKET_BRIEF)}
    # operator-stated: check_* returns None on its live inputs (V4 passes at c4, erratum E3)
    assert head.check_registry(raw, dict(briefs)) is None
    trail, handle = _rider_site(obj)
    mutated = copy.deepcopy(obj)
    del _navigate(mutated, trail)[handle]
    data = _dump_like(raw, obj, mutated)
    # operator-stated: check_registry's refusal message contains "MET-011 packet rider"
    with pytest.raises(ValueError, match="MET-011 packet rider"):
        head.check_registry(data, dict(briefs))


@pytest.mark.parametrize("mutation", ["vocabulary", "rule_digest"])
def test_v6_refuses_mutation(head, authority, hunk_record, v6_inputs, mutation):
    """CONTRACT_293 section 5 (V6, its own hunk-class record under v2.5): a changed vocabulary or rule digest."""
    raw, obj = hunk_record
    afters, classify, context = v6_inputs
    rule_sha = head.HUNK_RULE_SHA256
    changed = authority["changedFiles"]
    # operator-stated: check_* returns None on its live inputs (V6 passes at c4, erratum E3)
    assert head.check_hunk_record(raw, copy.deepcopy(changed), dict(afters), classify, context, rule_sha) is None
    mutated = copy.deepcopy(obj)
    if mutation == "vocabulary":
        vocabulary = _vocabulary(mutated)
        # CONTRACT_293 section 5 (V6): the record names its class vocabulary, `other` among it (V6a)
        assert vocabulary is not None, "the record's vocabulary"
        if isinstance(vocabulary, list):
            vocabulary.append("unreviewed-class-293")
        else:
            vocabulary["unreviewed-class-293"] = copy.deepcopy(vocabulary["other"])
    elif _replace_string(mutated, rule_sha, _flip_hex(rule_sha)) == 0:
        rule_sha = _flip_hex(rule_sha)
    data = _dump_like(raw, obj, mutated)
    # operator-stated: a check_* refusal is a ValueError whose message contains MET-011
    with pytest.raises(ValueError, match="MET-011"):
        head.check_hunk_record(data, copy.deepcopy(changed), dict(afters), classify, context, rule_sha)


# ---------------------------------------------------------------------------------------------------------------------
# 4. The ledger (section 4, the expected set), read through the era reader
# ---------------------------------------------------------------------------------------------------------------------


def test_ledger_e1_members(ledger, base_ledger):
    """CONTRACT_293 section 4, E-1: schema v1 with exactly the base's 14 members; every layer entry with 11 keys."""
    obj = ledger[1]
    base_raw, base = base_ledger
    # CONTRACT_293 section 4: the base ledger is 993b4618 (E-9, E-11)
    assert _sha256(base_raw) == BASE_LEDGER_SHA256
    # CONTRACT_293 section 4 E-1: exactly the base's top-level members
    assert set(obj) == set(base)
    # CONTRACT_293 section 4 E-1: 14 top-level members
    assert len(obj) == 14
    member = _layers_member(obj)
    base_keys = set(_entries(base, member)[0])
    # CONTRACT_293 section 4: 11 keys in every base layer entry
    assert len(base_keys) == 11
    for entry in _entries(obj, member):
        # CONTRACT_293 section 4 E-1: every layer entry with 11 keys
        assert set(entry) == base_keys


def test_ledger_e2_slot_and_baseline(authority, ledger):
    """CONTRACT_293 section 4, E-2: checkpointSlot 293; checkpointBaseline 313; 104 layer entries."""
    obj = ledger[1]
    # CONTRACT_293 section 4 E-2: checkpointSlot 293
    assert obj["checkpointSlot"] == 293
    # CONTRACT_293 section 4 E-2: checkpointBaseline 313
    assert obj["checkpointBaseline"] == 313
    # CONTRACT_293 section 4 E-2: the size of 293's authority's baselinePackets
    assert obj["checkpointBaseline"] == len(authority["baselinePackets"])
    # CONTRACT_293 section 4 E-2: 104 entries
    assert len(_entries(obj, _layers_member(obj))) == 104


def test_ledger_e3_unchanged_members(ledger, base_ledger):
    """CONTRACT_293 section 4, E-3 and E-1: parameters and checkPairs (and the schema) equal to the base's."""
    obj = ledger[1]
    base = base_ledger[1]
    member = _layers_member(obj)
    unchanged = set(base) - CHANGING_MEMBERS - {member}
    # CONTRACT_293 section 4: 14 members less the 10 a rewrite changes: schema, parameters, checkPairs, normalisedRecordClass
    assert len(unchanged) == 4
    for name in sorted(unchanged):
        # CONTRACT_293 section 4 E-1, E-3 and E-14: equal to the base's
        assert obj[name] == base[name]
    # CONTRACT_293 section 4 E-3: checkPairs equal to the base's
    assert obj["checkPairs"] == base["checkPairs"]
    # CONTRACT_293 section 4: two checkPairs
    assert len(obj["checkPairs"]) == 2


def test_ledger_e7_exclusion(ledger):
    """CONTRACT_293 section 4, E-7: the three-file exclusion, its pinLine, and no layer attesting an excluded file."""
    obj = ledger[1]
    # CONTRACT_293 section 4 E-7: exclusion == {files: three sorted entries, pinLine: the head}
    assert obj["exclusion"] == {"files": EXCLUDED_FILES, "pinLine": HEAD_PATH}
    excluded = set(EXCLUDED_FILES)
    for entry in _entries(obj, _layers_member(obj)):
        # CONTRACT_293 section 4 E-7: no layer attests an excluded file
        assert not (_strings(entry, set()) & excluded)


def test_ledger_e8_full_run_proof(ledger):
    """CONTRACT_293 section 4, E-8: fullRunProof == {collected: N > 0, executed: N, deselected: 0, attested: 0}."""
    proof = ledger[1]["fullRunProof"]
    # CONTRACT_293 section 4 E-8: exactly four members
    assert set(proof) == {"collected", "executed", "deselected", "attested"}
    # CONTRACT_293 section 4 E-8: N an int
    assert type(proof["collected"]) is int
    # CONTRACT_293 section 4 E-8: N > 0
    assert proof["collected"] > 0
    # CONTRACT_293 section 4 E-8: executed N
    assert proof["executed"] == proof["collected"]
    # CONTRACT_293 section 4 E-8: deselected 0
    assert proof["deselected"] == 0
    # CONTRACT_293 section 4 E-8: attested 0
    assert proof["attested"] == 0


def test_ledger_e9_writing_run(ledger):
    """CONTRACT_293 section 4, E-9: writingRun's six members; verifyReference names slot 286 and 993b4618."""
    run = ledger[1]["writingRun"]
    # CONTRACT_293 section 4 E-9: exactly its six members
    assert set(run) == {
        "statedDifferences",
        "captureEnv",
        "captureObservesOnly",
        "outsideReads",
        "argvRunSummarySha256",
        "verifyReference",
    }
    # CONTRACT_293 section 4 E-9: the two stated differences
    assert isinstance(run["statedDifferences"], (list, dict)) and len(run["statedDifferences"]) == 2
    # CONTRACT_293 section 4 E-9: captureEnv, the capture variables
    assert isinstance(run["captureEnv"], (list, dict)) and len(run["captureEnv"]) > 0
    # CONTRACT_293 section 4 E-9: captureObservesOnly true
    assert run["captureObservesOnly"] is True
    # CONTRACT_293 section 4 E-9: outsideReads an int
    assert type(run["outsideReads"]) is int
    # CONTRACT_293 section 4 E-9: argvRunSummarySha256 a sha256 digest
    assert re.fullmatch(r"[0-9a-f]{64}", run["argvRunSummarySha256"])
    reference = run["verifyReference"]
    # CONTRACT_293 section 4 (base form) and E-9: verifyReference is a string
    assert isinstance(reference, str)
    # CONTRACT_293 section 4 E-9: verifyReference names slot 286
    assert re.search(r"(?<![0-9a-f])286(?![0-9a-f])", reference)
    # CONTRACT_293 section 4 E-9: verifyReference names 286's record 993b4618...
    assert BASE_LEDGER_SHA256 in reference


def test_ledger_e10_size_relations(ledger):
    """CONTRACT_293 section 4, E-10 (the size relations): sizeBytes == the file's length <= sizeBound <= 16 MiB."""
    raw, obj = ledger
    # CONTRACT_293 section 4 E-10: sizeBytes == the file's length
    assert obj["sizeBytes"] == len(raw)
    # CONTRACT_293 section 4 E-10: sizeBytes <= sizeBound
    assert obj["sizeBytes"] <= obj["sizeBound"]
    # CONTRACT_293 section 4 E-10: sizeBound <= 16 MiB
    assert obj["sizeBound"] <= SIXTEEN_MIB


def test_ledger_e11_inline_entry(head, authority, ledger):
    """CONTRACT_293 section 4, E-11: record.json's three-key changedFiles entry, 1 to 4,096 reverse hunks."""
    raw = ledger[0]
    entry = authority["changedFiles"][head.LEDGER_PATH]
    # CONTRACT_293 section 4 E-11: exactly {beforeSha256, afterSha256, reverseHunks}
    assert set(entry) == {"beforeSha256", "afterSha256", "reverseHunks"}
    # CONTRACT_293 section 4 E-11: beforeSha256 993b4618...
    assert entry["beforeSha256"] == BASE_LEDGER_SHA256
    # CONTRACT_293 section 4 E-11: afterSha256 is the third ledger's digest
    assert entry["afterSha256"] == _sha256(raw)
    # CONTRACT_293 section 4 E-11: 1 to 4,096 line-run reverse hunks
    assert 1 <= len(entry["reverseHunks"]) <= 4096


def test_ledger_e12_layer_slots(ledger, base_ledger):
    """CONTRACT_293 section 4, E-12 and E-2: the layers are the chain walk 189-292, one per slot, no gap."""
    obj = ledger[1]
    base = base_ledger[1]
    member = _layers_member(obj)
    slot_key = _slot_key(base, member)
    # CONTRACT_293 section 4: the base's layers 189-285
    assert _slots(base, member, slot_key) == BASE_SLOTS
    # CONTRACT_293 section 4 E-2 and E-12: layers 189-292, one per slot, in walk order
    assert _slots(obj, member, slot_key) == NEW_SLOTS


def test_ledger_e14_normalised_record_class(ledger, base_ledger):
    """CONTRACT_293 section 4, E-14: normalisedRecordClass true, as at the base."""
    # CONTRACT_293 section 4 E-14: normalisedRecordClass true
    assert ledger[1]["normalisedRecordClass"] is True
    # CONTRACT_293 section 4 E-14: as at the base
    assert base_ledger[1]["normalisedRecordClass"] is True


# ---------------------------------------------------------------------------------------------------------------------
# 5. The registry and the weights table (section 6; operator-stated)
# ---------------------------------------------------------------------------------------------------------------------


def test_registry_last_entry_is_the_rider(registry):
    """CONTRACT_293 section 6: the MET-011/packet rider appended last, the 40th entry (operator-stated: 40 entries)."""
    obj = registry[1]
    trail, handle = _rider_site(obj)
    container = _navigate(obj, trail)
    # operator-stated: the registry at c4 holds 40 entries; CONTRACT_293 section 6: the 40th entry
    assert len(container) == 40
    last = list(container)[-1] if isinstance(container, dict) else len(container) - 1
    # CONTRACT_293 section 6: the rider is appended last
    assert handle == last
    mentions = [h for h in _handles(container) if "MET-011/" in json.dumps(container[h]) or "MET-011/" in str(h)]
    # CONTRACT_293 section 6 and section 5 (V4): this packet's one rider
    assert mentions == [handle]


def test_table_keys_and_rows(head):
    """CONTRACT_293 section 6 (the weights): raw keys equal effective keys; the two rows; 215 entries."""
    objects, rows = _table_rows(head)
    for pairs in objects:
        keys = [key for key, _ in pairs]
        # CONTRACT_293 section 6 (the append form): no key repeated, raw keys equal effective keys
        assert keys == list(dict(pairs))
    # CONTRACT_293 section 6: one weights mapping holds the head test's row
    assert len(rows) == 1
    keys = [key for key, _ in rows[0]]
    # operator-stated: the table at c5 holds 215 entries
    assert len(keys) == 215
    # CONTRACT_293 section 6: an entry for tests/test_met_011.py
    assert "tests/test_met_011.py" in keys
    # CONTRACT_293 section 6: an entry for 293's D5a oracle
    assert "tests/test_met_011_oracle.py" in keys


def test_table_keys_are_regular_files(head):
    """CONTRACT_293 section 6 (the weights; operator-stated): every key names a regular file, read via the era reader."""
    _, rows = _table_rows(head)
    # CONTRACT_293 section 6: one weights mapping
    assert len(rows) == 1
    for key, _ in rows[0]:
        # operator-stated: every key names a regular file (reviewed_bytes reads only regular files)
        assert isinstance(head.reviewed_bytes(key), bytes)
