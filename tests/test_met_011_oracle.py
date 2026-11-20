"""D5a oracle tests for MET-011, the third checkpoint's head layer (slot 293, K = 0).

Owner decision D5a: these black-box tests are written outside the candidate by a non-author. Every expected
value comes from CONTRACT_293 (r2 with errata E1-E4 and E4's revision b, the export CONTRACT_293_e4b.md) or from
the facts the operator states about the c6 head; each assert cites its source on its own line or the line above.

C18 (the era-read rule): every repository file is read only through the head's era reader
`head.reviewed_bytes(path)`; the catalog's names come from the head's authority (`baselinePackets`) plus
`head.NEW_PACKET`, never from a directory listing. JSON is parsed with `json`, YAML only through `head.safe_load`.
The head is the one repository module loaded, by file path, into a fresh module object. Nothing is patched;
every negative case is built from plain data (copies, bytes, mappings passed to the head's `check_*`).

Before F every test that drives a head check over the live tree fails by design (CONTRACT_293 section 8, the red
set); the mutation tests do not depend on which ledger is on disk. No digest of the weights table, the head, the
authority, the hunk-class record or the ledger is pinned here.
"""

from __future__ import annotations

import base64
import copy
import hashlib
import importlib.util
import json
import sys
from functools import lru_cache
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

# CONTRACT_293 section 1: the packet id and its predecessor.
NEW_ID = "MET-011"
PREV_ID = "MET-010"
# CONTRACT_293 section 6: the one rider appended to the registry.
RIDER = "MET-011/packet"
# CONTRACT_293 section 4 (E-9, E-11): the base record's digest (286's ledger).
BASE_LEDGER_SHA256 = "993b4618bf4ad9b6440a3e41bdbeb238cc50455f7f151584cbd6e394277e5084"
# CONTRACT_293 section 4 (E-7): the exclusion of the third ledger.
EXCLUSION_FILES = [
    "architecture/chain-checkpoint/hunk-classes/293.json",
    "architecture/chain-checkpoint/record.json",
    "architecture/ledger-rewrite-293-authority.json",
]
PIN_LINE = "scripts/validate_met_011.py"
# CONTRACT_293 section 5 (vectors 2, 3a, 3b) and erratum E4: the strict check's existing text.
STRICT_TEXT = "unexpected packet addition or loss"
# CONTRACT_293 section 5 (vector 6): the non-mapping refusal.
MAPPING_TEXT = "packet mapping"
# operator-stated: the weights table's own rows for this packet's two test files.
HEAD_TEST = "tests/test_met_011.py"
ORACLE_TEST = "tests/test_met_011_oracle.py"
SIXTEEN_MIB = 16 * 1024 * 1024


@lru_cache(maxsize=None)
def head():
    """The head `scripts/validate_met_011.py`, loaded once by file path into a fresh module object."""
    spec = importlib.util.spec_from_file_location(
        "met_011_d5a_oracle_head", str(ROOT / "scripts" / "validate_met_011.py")
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def rb(path):
    """A repository file's bytes through the head's era reader (C18)."""
    return head().reviewed_bytes(path)


def sha256(data):
    return hashlib.sha256(data).hexdigest()


@lru_cache(maxsize=None)
def authority():
    return head().authority()


def changed_files():
    return copy.deepcopy(authority()["changedFiles"])


@lru_cache(maxsize=None)
def catalog_names():
    """The catalog's names: the authority's baselinePackets plus the head's NEW_PACKET (C18)."""
    return tuple([*authority()["baselinePackets"], head().NEW_PACKET])


@lru_cache(maxsize=None)
def catalog_bytes():
    return {name: rb("task-packets/" + name + ".yaml") for name in catalog_names()}


@lru_cache(maxsize=None)
def catalog_parsed():
    return {name: head().safe_load(raw) for name, raw in catalog_bytes().items()}


def catalog(form):
    """A fresh mapping of the catalog in one form ("parsed" or "bytes")."""
    return dict(catalog_parsed() if form == "parsed" else catalog_bytes())


@lru_cache(maxsize=None)
def accepted_catalog():
    """Vector 1: the full catalog, in the parsed form first, then as bytes; returns (form, result)."""
    try:
        return "parsed", head().historical_catalog(catalog("parsed"))
    except ValueError as first:
        try:
            return "bytes", head().historical_catalog(catalog("bytes"))
        except ValueError:
            raise first


def redump(raw, mutated):
    """Serialise `mutated` in the first json.dumps form that reproduces `raw` byte for byte."""
    original = json.loads(raw)
    text = raw.decode("utf-8")
    newline = "\n" if text.endswith("\n") else ""
    forms = []
    for indent in (2, 1, 4, None):
        for sort_keys in (False, True):
            for ensure_ascii in (True, False):
                separators = (",", ": ") if indent is not None else None
                forms.append(
                    {"indent": indent, "sort_keys": sort_keys, "ensure_ascii": ensure_ascii, "separators": separators}
                )
    for sort_keys in (False, True):
        forms.append({"indent": None, "sort_keys": sort_keys, "ensure_ascii": True, "separators": (",", ":")})
    for form in forms:
        if json.dumps(original, **form) + newline == text:
            return (json.dumps(mutated, **form) + newline).encode("utf-8")
    return (json.dumps(mutated, indent=2) + newline).encode("utf-8")


def class_slots(value):
    """The (container, key) places of class names in one path's hunk-class value."""
    slots = []
    if isinstance(value, list):
        for index, item in enumerate(value):
            if isinstance(item, str):
                slots.append((value, index))
            elif isinstance(item, dict) and isinstance(item.get("class"), str):
                slots.append((item, "class"))
    elif isinstance(value, dict):
        for key, item in value.items():
            if isinstance(item, str):
                slots.append((value, key))
    return slots


def class_names(value):
    return [container[key] for container, key in class_slots(value)]


@lru_cache(maxsize=None)
def ledger_raw():
    return rb(head().LEDGER_PATH)


def ledger():
    return json.loads(ledger_raw())


@lru_cache(maxsize=None)
def base_ledger_raw():
    """The base record (286's ledger): one ascending replay of the authority's inline hunks."""
    return head()._undo_this_layer(head().LEDGER_PATH, ledger_raw())


def layer_entries(document):
    layers = document["layers"]
    return list(layers.values()) if isinstance(layers, dict) else list(layers)


def layer_slots(document):
    layers = document["layers"]
    if isinstance(layers, dict):
        return [int(key) for key in layers]
    keys = None
    for entry in layers:
        found = {
            key
            for key, value in entry.items()
            if "slot" in key.lower() and isinstance(value, int) and not isinstance(value, bool)
        }
        keys = found if keys is None else keys & found
    if not keys or len(keys) != 1:
        pytest.fail("no single slot member in the ledger's layer entries")
    (key,) = tuple(keys)
    return [entry[key] for entry in layers]


def ledger_check_args(document):
    walk = {entry["validatorPath"]: rb(entry["validatorPath"]) for entry in layer_entries(document)}
    baseline = len(authority()["baselinePackets"])
    entry = copy.deepcopy(authority()["changedFiles"].get(head().LEDGER_PATH))
    return walk, baseline, entry


def hunk_record_raw():
    return rb(head().HUNK_RECORD_PATH)


def befores():
    return {path: head()._undo_this_layer(path, rb(path)) for path in head().ERRATA_LINES}


def hunk_check_args(raw):
    record = json.loads(hunk_record_raw())
    changed = changed_files()
    afters = {path: rb(path) for path, entry in changed.items() if entry.get("reverseHunks")}
    classify = head()._era_rule(head().READER_PATH, head().READER_NAME).classify
    context = head()._v24_context(head().authority(), record["hunkClassContext"])
    return raw, changed, afters, classify, context, head().HUNK_RULE_SHA256


def names_rider(entry):
    if entry == RIDER:
        return True
    if isinstance(entry, tuple):
        return entry[0] == RIDER or (isinstance(entry[1], dict) and names_rider(entry[1]))
    if isinstance(entry, dict):
        strings = [value for value in entry.values() if isinstance(value, str)]
        return RIDER in strings or (NEW_ID in strings and "packet" in strings)
    return False


def registry_entries(document):
    if isinstance(document, list):
        return list(document)
    lists = [key for key, value in document.items() if isinstance(value, list)]
    if len(lists) == 1:
        return list(document[lists[0]])
    return list(document.items())


def registry_without_rider(document):
    if isinstance(document, list):
        return [entry for entry in document if not names_rider(entry)]
    lists = [key for key, value in document.items() if isinstance(value, list)]
    if len(lists) == 1:
        trimmed = copy.deepcopy(document)
        trimmed[lists[0]] = [entry for entry in document[lists[0]] if not names_rider(entry)]
        return trimmed
    return {key: value for key, value in document.items() if not names_rider((key, value))}


def table_pairs():
    objects = []

    def hook(pairs):
        objects.append(pairs)
        return dict(pairs)

    json.loads(rb("ci/parallel_suite_weights.json"), object_pairs_hook=hook)
    return max(objects, key=len)


# ---------------------------------------------------------------------------------------------------------------
# 1. The packet YAML (sections 1 and 6; errata E2 and E4)
# ---------------------------------------------------------------------------------------------------------------


def test_packet_yaml_lines_are_sixteen_json_keys():
    """CONTRACT_293 section 6 (the 16-member form); operator-stated: each key on one line as `key: <JSON value>`."""
    text = rb("task-packets/" + head().NEW_PACKET + ".yaml").decode("utf-8")
    lines = text.splitlines()
    # operator-stated: 16 keys, each on one line
    assert len(lines) == 16
    parsed = head().safe_load(text)
    bad = 0
    for line in lines:
        key, separator, rest = line.partition(": ")
        try:
            value = json.loads(rest)
        except ValueError:
            bad += 1
            continue
        if not separator or key not in parsed or parsed[key] != value:
            bad += 1
    # operator-stated: every line is `key: <JSON value>` and parses to the same value
    assert bad == 0


def test_packet_yaml_members_and_predecessor_commands():
    """CONTRACT_293 sections 1 and 6: id, the 16 members of MET-010's form, predecessors, 64 commands, offlineExecution."""
    packet = head().safe_load(rb("task-packets/" + head().NEW_PACKET + ".yaml"))
    # CONTRACT_293 section 1: the packet id
    assert head().NEW_PACKET == NEW_ID
    # CONTRACT_293 section 1: the packet id
    assert packet["id"] == NEW_ID
    # CONTRACT_293 section 6: the 16-member form
    assert len(packet) == 16
    # CONTRACT_293 section 6: no scope key
    assert "scope" not in packet
    # CONTRACT_293 section 6: predecessors ["MET-010"]
    assert packet["predecessors"] == [PREV_ID]
    # CONTRACT_293 section 1: PREV MET-010 is in the base catalog
    assert PREV_ID in authority()["baselinePackets"]
    previous = head().safe_load(rb("task-packets/" + packet["predecessors"][0] + ".yaml"))
    # CONTRACT_293 section 6: the 16-member form of MET-PERF-049 and MET-010
    assert set(packet) == set(previous)
    # CONTRACT_293 section 6: the 64 commands
    assert len(packet["offlineAcceptanceCommands"]) == 64
    # CONTRACT_293 section 6: the 64 commands equal to MET-010's
    assert packet["offlineAcceptanceCommands"] == previous["offlineAcceptanceCommands"]
    # CONTRACT_293 section 6: offlineExecution equal to MET-010's
    assert packet["offlineExecution"] == previous["offlineExecution"]


def test_packet_yaml_allowed_paths():
    """CONTRACT_293 section 4.1 condition 1, section 6 and errata E2/E4: 309 allowedPaths, sorted, with the exclusion."""
    packet = head().safe_load(rb("task-packets/" + head().NEW_PACKET + ".yaml"))
    allowed = packet["allowedPaths"]
    # CONTRACT_293 section 19 (erratum E4, R1): allowedPaths 307 -> 309
    assert len(allowed) == 309
    # CONTRACT_293 section 19 (erratum E4, R1): O1's two paths in sorted place
    assert allowed == sorted(allowed)
    # CONTRACT_293 section 19 (erratum E4, R1): one place per path
    assert len(set(allowed)) == 309
    missing_exclusion = sum(1 for path in EXCLUSION_FILES if path not in allowed)
    # CONTRACT_293 section 4.1 condition 1: allowedPaths name the three exclusion files
    assert missing_exclusion == 0
    missing_changed = sum(1 for path in authority()["changedFiles"] if path not in allowed)
    # CONTRACT_293 section 4.1 condition 1: allowedPaths == changedFiles plus the named files
    assert missing_changed == 0


# ---------------------------------------------------------------------------------------------------------------
# 2. The strict catalog (section 5, erratum E4)
# ---------------------------------------------------------------------------------------------------------------


def test_catalog_names_are_the_pair_313_314():
    """CONTRACT_293 section 1: the catalog pair (313, 314); section 4 E-2: the baseline is 313."""
    # CONTRACT_293 section 1 and section 4 E-2: 313 baseline packets
    assert len(authority()["baselinePackets"]) == 313
    # CONTRACT_293 section 1: 314 packets with MET-011
    assert len(set(catalog_names())) == 314


def test_strict_catalog_vector_1_full_set_peels_met_011():
    """CONTRACT_293 section 5, vector 1: the full set is accepted and MET-011 is peeled."""
    _form, result = accepted_catalog()
    # CONTRACT_293 section 5 vector 1: accepted, returning the peeled catalog
    assert isinstance(result, dict)
    # CONTRACT_293 section 5 vector 1: MET-011 peeled
    assert NEW_ID not in result
    # CONTRACT_293 section 5 vector 1: what is left is 292's era catalog (the 313 baseline names)
    assert set(result) == set(authority()["baselinePackets"])


def strict_vector(name):
    packets = catalog("parsed")
    if name == "2-without-met-011":
        packets.pop(head().NEW_PACKET)
    elif name == "3a-minus-one-older":
        packets.pop(sorted(authority()["baselinePackets"])[0])
    elif name == "3b-plus-unknown":
        packets["ORACLE-UNKNOWN-" + "293"] = packets[head().NEW_PACKET]
    return packets


@pytest.mark.parametrize("vector", ["2-without-met-011", "3a-minus-one-older", "3b-plus-unknown"])
def test_strict_catalog_refusals(vector):
    """CONTRACT_293 section 5 (erratum E4), vectors 2, 3a and 3b: refused with the strict check's existing text."""
    packets = strict_vector(vector)
    with pytest.raises(ValueError) as caught:
        head().historical_catalog(packets)
    # CONTRACT_293 section 5: "unexpected packet addition or loss" (vector 2 inverts; 3a and 3b the existing text)
    assert STRICT_TEXT in str(caught.value)


def test_strict_catalog_vector_6_non_mapping():
    """CONTRACT_293 section 5, vector 6 (C2-7): a non-mapping is refused with "packet mapping"."""
    with pytest.raises(ValueError) as caught:
        head().historical_catalog(list(catalog("parsed").items()))
    # CONTRACT_293 section 5 vector 6: refused with "packet mapping"
    assert MAPPING_TEXT in str(caught.value)


# ---------------------------------------------------------------------------------------------------------------
# 3. The head's checks on the live inputs (section 5; at F)
# ---------------------------------------------------------------------------------------------------------------


@pytest.mark.parametrize(
    "name",
    [
        "validate_packet_files",
        "validate_errata",
        "validate_ledger",
        "validate_inline",
        "validate_ledger_classes",
        "validate_registry",
        "validate_hunk_record",
        "validate_canonical_hunks",
    ],
)
def test_head_check_passes_on_live_inputs(name):
    """CONTRACT_293 section 5: V1, E3, C1, C2, V6a, V4, V6 and the canonical check pass on the live tree at F."""
    getattr(head(), name)()


def test_validate_met_011_runs_every_check_in_order():
    """CONTRACT_293 section 5: validate_met_011(packets) runs the checks in section 5's order and passes at F."""
    form, _result = accepted_catalog()
    head().validate_met_011(catalog(form))


# ---------------------------------------------------------------------------------------------------------------
# 3. The head's checks refuse plain-data mutations (section 5)
# ---------------------------------------------------------------------------------------------------------------


def packet_files():
    return {path: rb(path) for path in head().PACKET_FILES}


@pytest.mark.parametrize("mutation", ["byte-changed", "file-missing"])
def test_v1_refuses_mutated_packet_files(mutation):
    """CONTRACT_293 section 5 item 2 (V1): this packet's files by digest; a changed byte or a missing file refuses."""
    files = packet_files()
    # CONTRACT_293 section 18 (erratum E3): V1 passes on its unmutated inputs before and after F
    assert head().check_packet_files(dict(files)) is None
    first = sorted(files)[0]
    if mutation == "byte-changed":
        data = bytearray(files[first])
        if data:
            data[0] ^= 0x01
        else:
            data.extend(b"x")
        files[first] = bytes(data)
    else:
        files.pop(first)
    with pytest.raises(ValueError) as caught:
        head().check_packet_files(files)
    # operator-stated: each check's message contains MET-011
    assert NEW_ID in str(caught.value)


def test_e3_refuses_other_class_outside_errata_lines():
    """CONTRACT_293 section 5 item 3 and section 11 (1) (E3): an `other` class outside ERRATA_LINES refuses."""
    record = json.loads(hunk_record_raw())
    changed = changed_files()
    before_map = befores()
    # CONTRACT_293 section 18 (erratum E3): E3 passes on its unmutated inputs (record.json is outside E3 by path)
    assert head().check_errata(copy.deepcopy(record["classes"]), changed, before_map) is None
    classes = copy.deepcopy(record["classes"])
    target = None
    for path in sorted(changed):
        if path in head().ERRATA_LINES or path == head().LEDGER_PATH or path not in classes:
            continue
        slots = [slot for slot in class_slots(classes[path]) if slot[0][slot[1]] != "other"]
        if slots:
            target = slots[0]
            break
    if target is None:
        pytest.fail("no changed file with a non-other hunk class outside ERRATA_LINES")
    container, key = target
    container[key] = "other"
    with pytest.raises(ValueError) as caught:
        head().check_errata(classes, changed, before_map)
    # operator-stated: each check's message contains MET-011
    assert NEW_ID in str(caught.value)


@pytest.mark.parametrize("mutation", ["member-removed", "checkpoint-slot-changed"])
def test_c1_refuses_mutated_ledger(mutation):
    """CONTRACT_293 section 5 item 4 (C1) and section 4 (E-1, E-2): a removed member or another checkpointSlot refuses."""
    raw = ledger_raw()
    document = json.loads(raw)
    walk, baseline, entry = ledger_check_args(document)
    mutated = json.loads(raw)
    if mutation == "member-removed":
        member = "fullRunProof" if "fullRunProof" in mutated else list(mutated)[-1]
        mutated.pop(member)
    else:
        # CONTRACT_293 section 4 E-2: checkpointSlot 293; any other slot is refused
        mutated["checkpointSlot"] = 292
    new_raw = redump(raw, mutated)
    if isinstance(entry, dict):
        entry["afterSha256"] = sha256(new_raw)
    with pytest.raises(ValueError) as caught:
        # CONTRACT_293 section 4 E-7: no ledger-hunks path exists
        head().check_ledger(new_raw, walk, baseline, entry, True)
    # operator-stated: each check's message contains MET-011
    assert NEW_ID in str(caught.value)


def test_c2_refuses_altered_reverse_hunk():
    """CONTRACT_293 section 5 item 5 (C2): one ascending replay reproduces the base record; an altered hunk refuses."""
    live = ledger_raw()
    entry = copy.deepcopy(authority()["changedFiles"].get(head().LEDGER_PATH))
    if not isinstance(entry, dict) or not entry.get("reverseHunks"):
        entry = {
            "beforeSha256": BASE_LEDGER_SHA256,
            "afterSha256": sha256(live),
            "reverseHunks": [{"at": 1, "removeBase64": "", "insertBase64": ""}],
        }
    hunk = entry["reverseHunks"][0]
    inserted = head()._base64(hunk["insertBase64"])
    hunk["insertBase64"] = base64.b64encode(inserted + b"\n").decode("ascii")
    with pytest.raises(ValueError) as caught:
        head().check_inline(entry, live)
    # operator-stated: each check's message contains MET-011
    assert NEW_ID in str(caught.value)


def test_v6a_refuses_record_class_that_is_not_other():
    """CONTRACT_293 section 5 item 6 (V6a): record.json's classes are pinned to "other"; another class refuses."""
    record = json.loads(hunk_record_raw())
    classes = copy.deepcopy(record["classes"])
    ledger_path = head().LEDGER_PATH
    slots = class_slots(classes.get(ledger_path))
    if slots:
        container, key = slots[0]
        # CONTRACT_293 section 3: "bridge" is a normalised class, not "other"
        container[key] = "bridge"
    else:
        classes[ledger_path] = ["bridge"]
    with pytest.raises(ValueError) as caught:
        head().check_ledger_classes(classes, changed_files())
    # operator-stated: each check's message contains MET-011
    assert NEW_ID in str(caught.value)


def test_v4_refuses_registry_without_the_rider():
    """CONTRACT_293 section 5 item 7 and section 6 (V4): the registry differs from the base by the one rider."""
    raw = rb(head().REGISTRY_PATH)
    briefs = {head().PACKET_BRIEF: rb(head().PACKET_BRIEF)}
    # CONTRACT_293 section 18 (erratum E3): V4 passes on its unmutated inputs before and after F
    assert head().check_registry(raw, dict(briefs)) is None
    new_raw = redump(raw, registry_without_rider(json.loads(raw)))
    with pytest.raises(ValueError) as caught:
        head().check_registry(new_raw, briefs)
    # operator-stated: check_registry's message contains "MET-011 packet rider"
    assert "MET-011 packet rider" in str(caught.value)


@pytest.mark.parametrize("mutation", ["rule-digest-argument", "record-vocabulary-or-digest"])
def test_v6_refuses_changed_vocabulary_or_rule_digest(mutation):
    """CONTRACT_293 section 5 item 8 (V6): the hunk-class record under v2.5; a changed vocabulary or digest refuses."""
    raw = hunk_record_raw()
    args = list(hunk_check_args(raw))
    # CONTRACT_293 section 18 (erratum E3): V6 passes on its unmutated inputs before and after F
    assert head().check_hunk_record(*args) is None
    rule_sha = args[5]
    other_sha = ("0" if rule_sha[:1] != "0" else "1") + rule_sha[1:]
    if mutation == "rule-digest-argument":
        args[5] = other_sha
    else:
        record = json.loads(raw)
        vocabulary = [key for key in record if "vocab" in key.lower()]
        digests = [key for key, value in record.items() if value == rule_sha]
        if vocabulary:
            value = record[vocabulary[0]]
            if isinstance(value, list):
                value.append("oracle-unknown-class")
            elif isinstance(value, dict):
                value["oracle-unknown-class"] = "oracle-unknown-class"
            else:
                record[vocabulary[0]] = str(value) + "-changed"
        elif digests:
            record[digests[0]] = other_sha
        else:
            pytest.fail("the hunk-class record holds no vocabulary or rule digest member")
        args[0] = redump(raw, record)
    with pytest.raises(ValueError) as caught:
        head().check_hunk_record(*args)
    # operator-stated: each check's message contains MET-011
    assert NEW_ID in str(caught.value)


# ---------------------------------------------------------------------------------------------------------------
# 4. The ledger: the expected set (section 4), read through reviewed_bytes (at F)
# ---------------------------------------------------------------------------------------------------------------


def test_ledger_e1_schema_v1_members():
    """CONTRACT_293 section 4, E-1: schema v1, exactly the base's 14 top-level members, 11 keys in every layer."""
    document = ledger()
    base = json.loads(base_ledger_raw())
    # CONTRACT_293 section 4 E-1: exactly 14 top-level members
    assert len(document) == 14
    # CONTRACT_293 section 4 E-1: exactly the base's members
    assert set(document) == set(base)
    schema_keys = [key for key in base if "schema" in key.lower()]
    differing = sum(1 for key in schema_keys if document.get(key) != base[key])
    # CONTRACT_293 section 4 E-1: schema v1, as the base
    assert differing == 0
    wrong = sum(1 for entry in layer_entries(document) if len(entry) != 11)
    # CONTRACT_293 section 4 E-1: every layer entry with 11 keys
    assert wrong == 0


def test_ledger_e2_e12_slot_baseline_and_layers():
    """CONTRACT_293 section 4, E-2 and E-12: checkpointSlot 293, checkpointBaseline 313, layers 189-292."""
    document = ledger()
    # CONTRACT_293 section 4 E-2: checkpointSlot 293
    assert document["checkpointSlot"] == 293
    # CONTRACT_293 section 4 E-2: checkpointBaseline 313
    assert document["checkpointBaseline"] == 313
    # CONTRACT_293 section 4 E-2: the size of 293's authority's baselinePackets
    assert document["checkpointBaseline"] == len(authority()["baselinePackets"])
    slots = layer_slots(document)
    # CONTRACT_293 section 4 E-2: 104 entries
    assert len(slots) == 104
    # CONTRACT_293 section 4 E-2 and E-12: one per slot, 189-292, no gap
    assert sorted(slots) == list(range(189, 293))
    last = layer_entries(document)[slots.index(292)]
    # CONTRACT_293 section 4 E-12: the last layer binds scripts/validate_met_011.py
    assert PIN_LINE in json.dumps(last)


def test_ledger_e3_parameters_and_check_pairs():
    """CONTRACT_293 section 4, E-3: parameters and checkPairs equal to the base's."""
    document = ledger()
    base = json.loads(base_ledger_raw())
    # CONTRACT_293 section 4 E-3: parameters equal to the base's
    assert document["parameters"] == base["parameters"]
    # CONTRACT_293 section 4 E-3: checkPairs equal to the base's
    assert document["checkPairs"] == base["checkPairs"]


def test_ledger_e7_exclusion():
    """CONTRACT_293 section 4, E-7: the three-file exclusion and the pin line; no layer attests an excluded file."""
    document = ledger()
    # CONTRACT_293 section 4 E-7: exclusion == {files: three sorted entries, pinLine: the head}
    assert document["exclusion"] == {"files": EXCLUSION_FILES, "pinLine": PIN_LINE}
    # CONTRACT_293 section 4 E-7: sorted, unique, three entries
    assert EXCLUSION_FILES == sorted(set(EXCLUSION_FILES))
    attesting = sum(
        1 for entry in layer_entries(document) if any(path in json.dumps(entry) for path in EXCLUSION_FILES)
    )
    # CONTRACT_293 section 4 E-7: no layer attests an excluded file
    assert attesting == 0


def test_ledger_e8_full_run_proof():
    """CONTRACT_293 section 4, E-8: fullRunProof == {collected: N > 0, executed: N, deselected: 0, attested: 0}."""
    proof = ledger()["fullRunProof"]
    # CONTRACT_293 section 4 E-8: exactly the four members
    assert set(proof) == {"collected", "executed", "deselected", "attested"}
    # CONTRACT_293 section 4 E-8: collected N > 0
    assert isinstance(proof["collected"], int) and proof["collected"] > 0
    # CONTRACT_293 section 4 E-8: executed N
    assert proof["executed"] == proof["collected"]
    # CONTRACT_293 section 4 E-8: deselected 0
    assert proof["deselected"] == 0
    # CONTRACT_293 section 4 E-8: attested 0
    assert proof["attested"] == 0


def test_ledger_e9_writing_run():
    """CONTRACT_293 section 4, E-9: writingRun's six members; verifyReference names slot 286 and 993b4618."""
    run = ledger()["writingRun"]
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
    assert len(run["statedDifferences"]) == 2
    # CONTRACT_293 section 4 E-9: captureObservesOnly true
    assert run["captureObservesOnly"] is True
    # CONTRACT_293 section 4 E-9: outsideReads an int
    assert isinstance(run["outsideReads"], int) and not isinstance(run["outsideReads"], bool)
    digest = run["argvRunSummarySha256"]
    # CONTRACT_293 section 4 E-9: argvRunSummarySha256 a sha256 digest
    assert isinstance(digest, str) and len(digest) == 64 and set(digest) <= set("0123456789abcdef")
    reference = run["verifyReference"]
    # CONTRACT_293 section 4 E-9 (and section 4: a string): verifyReference names slot 286
    assert isinstance(reference, str) and "286" in reference
    # CONTRACT_293 section 4 E-9: verifyReference names the record 993b4618...5084
    assert BASE_LEDGER_SHA256 in reference


def test_ledger_e10_size_relations():
    """CONTRACT_293 section 4, E-10 (the size relations only): sizeBytes == length <= sizeBound <= 16 MiB."""
    raw = ledger_raw()
    document = json.loads(raw)
    # CONTRACT_293 section 4 E-10: sizeBytes == the file's length
    assert document["sizeBytes"] == len(raw)
    # CONTRACT_293 section 4 E-10: length <= sizeBound
    assert len(raw) <= document["sizeBound"]
    # CONTRACT_293 section 4 E-10: sizeBound <= 16 MiB
    assert document["sizeBound"] <= SIXTEEN_MIB


def test_ledger_e14_normalised_record_class():
    """CONTRACT_293 section 4, E-14: normalisedRecordClass true, as at the base."""
    document = ledger()
    # CONTRACT_293 section 4 E-14: normalisedRecordClass true
    assert document["normalisedRecordClass"] is True
    # CONTRACT_293 section 4 E-14: as at the base
    assert json.loads(base_ledger_raw())["normalisedRecordClass"] is True


def test_ledger_e11_inline_entry_and_record_classes():
    """CONTRACT_293 section 4, E-11, and section 4.1 (F): record.json's inline entry and its "other" classes."""
    live = ledger_raw()
    entry = authority()["changedFiles"][head().LEDGER_PATH]
    # CONTRACT_293 section 4 E-11: exactly {beforeSha256, afterSha256, reverseHunks}
    assert set(entry) == {"beforeSha256", "afterSha256", "reverseHunks"}
    # CONTRACT_293 section 4 E-11: beforeSha256 is the base record's digest
    assert entry["beforeSha256"] == BASE_LEDGER_SHA256
    # CONTRACT_293 section 4 E-11: afterSha256 is the rewritten record's digest
    assert entry["afterSha256"] == sha256(live)
    hunks = entry["reverseHunks"]
    # CONTRACT_293 section 4 E-11: 1 to 4,096 line-run reverse hunks
    assert 1 <= len(hunks) <= 4096
    # CONTRACT_293 section 4 E-11 and section 5 item 5: one ascending replay to the base record
    assert sha256(base_ledger_raw()) == BASE_LEDGER_SHA256
    record = json.loads(hunk_record_raw())
    names = class_names(record["classes"].get(head().LEDGER_PATH))
    # CONTRACT_293 section 4.1 (F) and section 5 item 6: the class "other" for every hunk
    assert len(names) == len(hunks)
    # CONTRACT_293 section 4.1 (F) and section 5 item 6: the class "other" for every hunk
    assert set(names) == {"other"}


# ---------------------------------------------------------------------------------------------------------------
# 5. The registry and the weights table (section 6; operator-stated)
# ---------------------------------------------------------------------------------------------------------------


def test_registry_last_entry_is_the_one_rider():
    """CONTRACT_293 section 6: the rider MET-011/packet appended last (the 40th entry); operator-stated: 40 entries."""
    entries = registry_entries(json.loads(rb(head().REGISTRY_PATH)))
    # operator-stated: the registry at c6 holds 40 entries; CONTRACT_293 section 6: the 40th entry
    assert len(entries) == 40
    # CONTRACT_293 section 6: the one MET-011/packet rider
    assert sum(1 for entry in entries if names_rider(entry)) == 1
    # CONTRACT_293 section 6: appended last
    assert names_rider(entries[-1])


def test_weights_table_keys_rows_and_regular_files():
    """CONTRACT_293 section 6 (the weights' append form); operator-stated: 215 entries, both MET-011 test rows."""
    pairs = table_pairs()
    raw_keys = [key for key, _value in pairs]
    effective = list(dict(pairs))
    # operator-stated: the table's raw keys equal its effective keys
    assert raw_keys == effective
    # operator-stated: 215 entries at c6
    assert len(effective) == 215
    # CONTRACT_293 section 6: an entry for tests/test_met_011.py
    assert HEAD_TEST in effective
    # CONTRACT_293 section 6: an entry for 293's D5a oracle
    assert ORACLE_TEST in effective
    not_regular = sum(1 for key in effective if not isinstance(rb(key), bytes))
    # operator-stated: every key names a regular file (read through reviewed_bytes)
    assert not_regular == 0
