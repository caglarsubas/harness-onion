"""D5a oracle tests for MET-PERF-050 (slot 290, PERF-WEIGHTS-REFRESH).

Owner decision D5a: a contract packet carries black-box tests written outside the candidate by someone who is not
its builder.  This file was written from two era inputs only: CONTRACT_290 rev 2 (the whole contract) and the packet
YAML at c2 with its closed-path strings masked.  None of the table, the inputs record, the head, the authority or the
hunk-class record is among its era inputs.

Source of every expected value: CONTRACT_290 rev 2, cited next to each assert as "# CONTRACT_290 section N"
(section 1 the step, 3 the weights table and its rule, 4 the inputs record, 5 the head's checks V1, E1, E2, E3, V4
and V6, 6 the packet YAML and the rider, 7 the attested files and E3's named lines, 9 the c3 steps, 10 C13's text,
11 the light checks and the final-head block).  The call shapes of the head's checks (their arguments, and the
ValueError whose message carries MET-PERF-050) are the operator-stated facts of the oracle brief; the one assert
that rests on such a fact alone says "operator-stated".

The repository files read at run time are fixtures, loaded and mutated, never expectations.  No digest of the table,
the inputs record, the head, the authority or the hunk-class record is pinned, nor any head-test row's value: each is
checked against the contract's rule, so the file holds at the c3 commit (provisional rows) and after the measured
step (measured rows).
"""
from __future__ import annotations

import copy
import hashlib
import importlib.util
import json
import re
import sys
from collections.abc import Mapping
from pathlib import Path, PurePath, PurePosixPath

import pytest

ROOT = Path(__file__).resolve().parents[1]

# Paths named by CONTRACT_290 sections 1, 3, 4, 5, 6 and 7.
TABLE = "ci/parallel_suite_weights.json"
INPUTS = "architecture/perf-weights-refresh-inputs.json"
AUTHORITY = "architecture/perf-weights-refresh-authority.json"
HUNK_RECORD = "architecture/chain-checkpoint/hunk-classes/290.json"
REGISTRY = "architecture/review-record/briefs.json"
PACKET_YAML = "task-packets/MET-PERF-050.yaml"
PLANNER = "ci/parallel_suite.py"
HEAD = "scripts/validate_met_perf_050.py"
HEAD_TEST = "tests/test_met_perf_050.py"
ORACLE = "tests/test_met_perf_050_oracle.py"
ORACLE_IDENTITY = "architecture/oracle-identity-met-perf-050.json"
# CONTRACT_290 section 7: the YAML corpus count lines, by file.
COUNT_FILES = {"tests/test_ci_performance.py": 169, "tests/test_credential_lifecycle.py": 362}
# CONTRACT_290 section 11: the two worker files outside tests/.
CI_WORKER_FILES = ("ci/test_offline_runner.py", "ci/test_warm_snapshot.py")
# A test-file key that no packet adds (negative cases only).
EXTRA_TEST = "tests/test_met_perf_050_extra.py"

# CONTRACT_290 section 4: the eight members, in sorted order.
INPUT_MEMBERS = (
    "dryRunSource",
    "dryRunUs",
    "headTests",
    "headTestsSource",
    "kappa",
    "kappaSource",
    "rule",
    "schemaVersion",
)
# CONTRACT_290 section 4.
SCHEMA_VERSION = "harness.planeon.ai/perf-weights-refresh-inputs/v1"
# CONTRACT_290 section 3: the record's rule string, verbatim.
RULE = (
    "table[f] = round((dryRunUs[f][0] + dryRunUs[f][1]) / 2 / 1000000 * kappa, 1) for every dryRunUs key, and "
    "table[k] = headTests[k] for every headTests key (disjoint from the dryRunUs keys); the table holds exactly "
    "these keys, written as json.dumps(table, indent=1, sort_keys=True) + newline; round and json.dumps are "
    "Python 3's (round half to even on the binary float; json.dumps' default float form)"
)
# CONTRACT_290 section 3: the record's kappaSource string, verbatim.
KAPPA_SOURCE = (
    "the median, over the keys in both main cf253506's table and the parse with a positive main weight and a "
    "positive mean, of main weight / mean"
)
# CONTRACT_290 section 10: C13's text, quoted exactly (whitespace collapsed).
C13_TEXT = (
    "C13 TIMING TRIALS ONLY NEAR THE CAP (owner 2026-11-15, \"apply 4\"; the Mac stays loaded with Docker/llama). "
    "A full timing trial run (dry run) before the push is required only when the timing model's forecast upper "
    "bound on the final head is within 180 s of the verify cap (today: at or above 1,320 s against 1,500 s). "
    "Otherwise no trial: the verify's own time, with its start and window load recorded, is the measurement and "
    "feeds the timing model. A trial still runs when the head changes the runner, the planner or the weights in a "
    "way the model cannot price (the monitor names it)."
)
# CONTRACT_290 section 5: the hunk-class record's classes.
VOCABULARY = frozenset({"bridge", "cascade", "other", "record", "register"})
# CONTRACT_290 section 1: the packet id every refusal names.
TAG = "MET-PERF-050"


# ----------------------------------------------------------------------------------------------------------------
# Plain helpers (no patching: every case is built from plain data).
# ----------------------------------------------------------------------------------------------------------------


def _load(relative: str, name: str):
    """Load one repository module by its file path into a fresh module object."""
    spec = importlib.util.spec_from_file_location(name, ROOT / relative)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


def _read(relative: str) -> bytes:
    return (ROOT / relative).read_bytes()


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _rel(path) -> str:
    candidate = Path(path)
    if candidate.is_absolute():
        candidate = candidate.resolve().relative_to(ROOT)
    return candidate.as_posix()


def _top_pairs(raw: bytes) -> list:
    """The top-level (key, value) pairs of a JSON object, duplicates kept."""
    seen = []

    def hook(pairs):
        seen.append(pairs)
        return dict(pairs)

    json.loads(raw, object_pairs_hook=hook)
    return seen[-1]


def _strings(value):
    if isinstance(value, str):
        yield value
    elif isinstance(value, bytes):
        yield value.decode("utf-8", "replace")
    elif isinstance(value, PurePath):
        yield str(value)
    elif isinstance(value, Mapping):
        for key, item in value.items():
            yield from _strings(key)
            yield from _strings(item)
    elif isinstance(value, (list, tuple, set, frozenset)):
        for item in value:
            yield from _strings(item)


def _key_paths(value, predicate, trail=()):
    found = []
    if isinstance(value, dict):
        items = list(value.items())
    elif isinstance(value, list):
        items = list(enumerate(value))
    else:
        return found
    for key, item in items:
        here = trail + (key,)
        if predicate(key, item):
            found.append(here)
        found.extend(_key_paths(item, predicate, here))
    return found


def _get(value, trail):
    for step in trail:
        value = value[step]
    return value


def _set(value, trail, new):
    _get(value, trail[:-1])[trail[-1]] = new


def _dumps(table: dict) -> bytes:
    return (json.dumps(table, indent=1, sort_keys=True) + "\n").encode("utf-8")


def _recompute(record: dict) -> bytes:
    """CONTRACT_290 section 3's rule, applied to a parsed inputs record."""
    kappa = record["kappa"]
    table = {}
    for key, (first, second) in record["dryRunUs"].items():
        table[key] = round((first + second) / 2 / 1000000 * kappa, 1)
    for key, value in record["headTests"].items():
        table[key] = value
    return _dumps(table)


def _dump_like(original: bytes, value) -> bytes:
    """Serialize ``value`` in the json.dumps form that reproduces ``original``, if one does."""
    parsed = json.loads(original)
    for indent in (1, 2, 4, None):
        for sort_keys in (True, False):
            for ensure_ascii in (True, False):
                for tail in ("\n", ""):
                    options = {"indent": indent, "sort_keys": sort_keys, "ensure_ascii": ensure_ascii}
                    if (json.dumps(parsed, **options) + tail).encode("utf-8") == original:
                        return (json.dumps(value, **options) + tail).encode("utf-8")
    return _dumps(value)


def _worker_test(path: str) -> bool:
    """CONTRACT_290 section 11's name rule: test_*.py or *_test.py under tests/."""
    pure = PurePosixPath(path)
    return (
        len(pure.parts) > 1
        and pure.parts[0] == "tests"
        and pure.suffix == ".py"
        and (pure.name.startswith("test_") or pure.name.endswith("_test.py"))
    )


def _packet_files(head) -> dict:
    files = {}
    for path in head.PACKET_FILES:
        relative = _rel(path)
        # CONTRACT_290 section 5 (V1: this packet's two files, the inputs record and the table)
        assert relative in (INPUTS, TABLE)
        files[path] = _read(relative)
    return files


def _base_files(head) -> dict:
    files = {}
    for path in head.BASE_FILES:
        # CONTRACT_290 section 5 (E2: BASE_FILES is the planner ci/parallel_suite.py)
        assert _rel(path) == PLANNER
        files[path] = _read(PLANNER)
    return files


def _befores(head, authority: dict) -> dict:
    befores = {}
    for path in head.ERRATA_LINES:
        relative = _rel(path)
        # CONTRACT_290 section 7 (E3's named files are files this step changes)
        assert relative in authority["changedFiles"]
        befores[path] = head._undo_this_layer(relative, _read(relative))
    return befores


def _briefs(head) -> dict:
    return {head.PACKET_BRIEF: _read(_rel(head.PACKET_BRIEF))}


def _entries(registry):
    """The container of the registry's 37 entries (CONTRACT_290 section 6), or None."""
    if isinstance(registry, list):
        return registry
    if isinstance(registry, dict):
        inner = [value for value in registry.values() if isinstance(value, (list, dict)) and len(value) == 37]
        if len(inner) == 1:
            return inner[0]
        if len(registry) == 37:
            return registry
    return None


def _v6_context(head, record: dict):
    return head._v24_context(head.authority(), record["hunkClassContext"])


# ----------------------------------------------------------------------------------------------------------------
# Fixtures (the repository's files, read at run time; they are fixtures, not expectations).
# ----------------------------------------------------------------------------------------------------------------


@pytest.fixture(scope="module")
def head():
    return _load(HEAD, "met_perf_050_oracle_head_layer")


@pytest.fixture(scope="module")
def planner():
    return _load(PLANNER, "met_perf_050_oracle_planner")


@pytest.fixture(scope="module")
def table_raw() -> bytes:
    return _read(TABLE)


@pytest.fixture(scope="module")
def inputs_raw() -> bytes:
    return _read(INPUTS)


@pytest.fixture(scope="module")
def authority() -> dict:
    return json.loads(_read(AUTHORITY))


@pytest.fixture(scope="module")
def record_raw() -> bytes:
    return _read(HUNK_RECORD)


@pytest.fixture(scope="module")
def registry_raw() -> bytes:
    return _read(REGISTRY)


@pytest.fixture(scope="module")
def yaml_raw() -> bytes:
    return _read(PACKET_YAML)


@pytest.fixture(scope="module")
def e1_live(table_raw, inputs_raw, authority):
    new_tests = tuple(path for path in authority["newFiles"] if _worker_test(path))
    present = frozenset(key for key in json.loads(table_raw) if (ROOT / key).is_file())
    return table_raw, inputs_raw, new_tests, present


@pytest.fixture(scope="module")
def afters(authority) -> dict:
    return {
        path: _read(path)
        for path, entry in authority["changedFiles"].items()
        if entry.get("reverseHunks")
    }


@pytest.fixture(scope="module")
def classify(head):
    return head._era_rule(head.READER_PATH, head.READER_NAME).classify


@pytest.fixture(scope="module")
def live_context(head, record_raw):
    return _v6_context(head, json.loads(record_raw))


# ----------------------------------------------------------------------------------------------------------------
# Section 3 (the table) and section 4 (the inputs record).
# ----------------------------------------------------------------------------------------------------------------


def test_table_equals_its_recomputation_byte_for_byte(table_raw, inputs_raw):
    """CONTRACT_290 section 3: the table's bytes equal section 3's rule applied to the inputs record (section 4)."""
    record = json.loads(inputs_raw)
    # CONTRACT_290 section 3 (byte for byte)
    assert table_raw == _recompute(record)
    # CONTRACT_290 section 3 (json.dumps(table, indent=1, sort_keys=True) plus one newline)
    assert table_raw.endswith(b"}\n") and not table_raw.endswith(b"\n\n")


def test_table_raw_keys_equal_effective_keys_and_their_union(table_raw, inputs_raw):
    """CONTRACT_290 sections 3 and 11: raw keys = key lines = effective = 211; keys = dryRunUs + headTests, disjoint."""
    raw_keys = [key for key, _ in _top_pairs(table_raw)]
    table = json.loads(table_raw)
    key_lines = [line for line in table_raw.decode("utf-8").split("\n") if line.startswith(' "')]
    record = json.loads(inputs_raw)
    measured = set(record["dryRunUs"])
    head_keys = set(record["headTests"])
    # CONTRACT_290 section 3 (raw keys = effective keys, 0 duplicates)
    assert len(raw_keys) == len(set(raw_keys)) == len(table)
    # CONTRACT_290 section 11 (raw keys = key lines = effective)
    assert len(key_lines) == len(raw_keys)
    # CONTRACT_290 section 3 and section 11 (the table then holds 211 entries)
    assert len(table) == 211
    # CONTRACT_290 section 3 (the headTests keys are disjoint from the measured files')
    assert measured.isdisjoint(head_keys)
    # CONTRACT_290 section 3 (the table holds exactly these keys)
    assert set(table) == measured | head_keys
    # CONTRACT_290 section 11 (209 dryRunUs + 2 headTests)
    assert (len(measured), len(head_keys)) == (209, 2)


def test_table_values_are_one_decimal_floats_and_no_key_is_stale(table_raw):
    """CONTRACT_290 sections 3 and 11: every value a float >= 0 with one decimal; 0 stale keys."""
    table = json.loads(table_raw)
    odd = sorted(
        key
        for key, value in table.items()
        if type(value) is not float or value < 0 or round(value, 1) != value
    )
    # CONTRACT_290 section 3 (round(..., 1)) and section 4 (headTests: float with one decimal, >= 0)
    assert odd == []
    stale = sorted(key for key in table if not (ROOT / key).is_file())
    # CONTRACT_290 section 3 (0 stale) and section 11 (every table key names a file of the era tree)
    assert stale == []


def test_measured_keys_are_worker_files(inputs_raw):
    """CONTRACT_290 sections 3 and 11: every dryRunUs key is a worker file by section 11's definition."""
    record = json.loads(inputs_raw)
    outside = sorted(key for key in record["dryRunUs"] if not (_worker_test(key) or key in CI_WORKER_FILES))
    # CONTRACT_290 section 11 (the worker files) and section 3 (every key a worker file of the base tree)
    assert outside == []


def test_inputs_record_has_eight_closed_typed_members(inputs_raw):
    """CONTRACT_290 sections 3 and 4: eight closed members in sorted order, each typed; section 3's strings."""
    names = [key for key, _ in _top_pairs(inputs_raw)]
    record = json.loads(inputs_raw)
    # CONTRACT_290 section 4 (members closed, in sorted order)
    assert names == list(INPUT_MEMBERS)
    types = {name: type(record[name]).__name__ for name in INPUT_MEMBERS}
    # CONTRACT_290 section 4 (each typed)
    assert types == {
        "dryRunSource": "dict",
        "dryRunUs": "dict",
        "headTests": "dict",
        "headTestsSource": "dict",
        "kappa": "float",
        "kappaSource": "str",
        "rule": "str",
        "schemaVersion": "str",
    }
    # CONTRACT_290 section 4 (schemaVersion)
    assert record["schemaVersion"] == SCHEMA_VERSION
    # CONTRACT_290 section 3 (the rule string, verbatim from c1)
    assert record["rule"] == RULE
    # CONTRACT_290 section 3 (the kappaSource string, verbatim from c1)
    assert record["kappaSource"] == KAPPA_SOURCE
    # CONTRACT_290 section 3 (kappa = 0.5772) and section 4 (at most 4 decimals)
    assert record["kappa"] == 0.5772 and round(record["kappa"], 4) == record["kappa"]


def test_dry_run_source_is_closed_and_names_both_logs(inputs_raw):
    """CONTRACT_290 sections 3 and 4: dryRunSource closed {d1, d2, run, selection}; both logs' sizes and digests."""
    source = json.loads(inputs_raw)["dryRunSource"]
    # CONTRACT_290 section 4 (closed)
    assert set(source) == {"d1", "d2", "run", "selection"}
    for run, size, prefix in (("d1", 25318530, "15f21a66"), ("d2", 25316048, "0ecbce05")):
        entry = source[run]
        # CONTRACT_290 section 4 ({bytes: int, logSha256: 64 lowercase hex})
        assert set(entry) == {"bytes", "logSha256"}
        # CONTRACT_290 section 4 (bytes an int) and section 3 (d1 25,318,530 bytes; d2 25,316,048 bytes)
        assert type(entry["bytes"]) is int and entry["bytes"] == size
        # CONTRACT_290 section 4 (64 lowercase hex)
        assert re.fullmatch(r"[0-9a-f]{64}", entry["logSha256"])
        # CONTRACT_290 section 3 (d1's 63.log 15f21a66, d2's 0ecbce05)
        assert entry["logSha256"].startswith(prefix)
    # CONTRACT_290 section 4 (run: str, selection: str)
    assert isinstance(source["run"], str) and isinstance(source["selection"], str)


def test_dry_run_rows_are_millisecond_quantized_pairs(inputs_raw):
    """CONTRACT_290 sections 3 and 4: 209 rows of two millisecond-quantized ints; per-run sums 7,034.1 s and 6,650.5 s."""
    rows = json.loads(inputs_raw)["dryRunUs"]
    # CONTRACT_290 section 4 (209 rows)
    assert len(rows) == 209
    bad = sorted(
        key
        for key, row in rows.items()
        if not (
            isinstance(row, list)
            and len(row) == 2
            and all(type(value) is int and value >= 0 and value % 1000 == 0 for value in row)
        )
    )
    # CONTRACT_290 section 4 (each row [int, int], every value a multiple of 1,000)
    assert bad == []
    sums = sorted(sum(row[index] for row in rows.values()) / 1000000 for index in (0, 1))
    for got, want in zip(sums, (6650.5, 7034.1)):
        # CONTRACT_290 section 3 (the per-run sums 7,034.1 s and 6,650.5 s; section 4's millisecond quantization)
        assert abs(got - want) <= 0.2


def test_head_test_rows_agree_with_their_sources(inputs_raw):
    """CONTRACT_290 sections 4 and 9: headTests is this packet's two test files; each source row agrees with its value."""
    record = json.loads(inputs_raw)
    head_tests = record["headTests"]
    sources = record["headTestsSource"]
    # CONTRACT_290 section 4 (from c3: the head test and the oracle)
    assert set(head_tests) == {HEAD_TEST, ORACLE}
    # CONTRACT_290 section 4 (headTestsSource has exactly headTests's keys)
    assert set(sources) == set(head_tests)
    modes = set()
    for key, value in head_tests.items():
        row = sources[key]
        modes.add(row.get("mode"))
        # CONTRACT_290 section 4 (a float with one decimal, >= 0)
        assert type(value) is float and value >= 0 and round(value, 1) == value
        if row.get("mode") == "provisional":
            # CONTRACT_290 section 4 ({mode: "provisional"}, closed)
            assert set(row) == {"mode"}
            # CONTRACT_290 section 4 (a provisional row's value is 1.0)
            assert value == 1.0
            continue
        # CONTRACT_290 section 4 (the row is provisional or measured)
        assert row.get("mode") == "measured"
        # CONTRACT_290 section 4 (the measured row, closed)
        assert set(row) == {"mode", "rawSeconds", "overheadSeconds", "summarySha256"}
        # CONTRACT_290 section 4 (rawSeconds and overheadSeconds floats)
        assert type(row["rawSeconds"]) is float and type(row["overheadSeconds"]) is float
        # CONTRACT_290 section 4 (summarySha256: 64 lowercase hex)
        assert re.fullmatch(r"[0-9a-f]{64}", row["summarySha256"])
        # CONTRACT_290 section 4 (value = round(rawSeconds - overheadSeconds, 1))
        assert value == round(row["rawSeconds"] - row["overheadSeconds"], 1)
        # CONTRACT_290 section 4 (the head test's overheadSeconds 0.0; the oracle's 1.26)
        assert row["overheadSeconds"] == (0.0 if key == HEAD_TEST else 1.26)
    # CONTRACT_290 section 4 and section 9 (both provisional at the c3 commit, both measured after the measured step)
    assert len(modes) == 1


def test_table_against_main_by_commit(head, table_raw, inputs_raw, authority):
    """CONTRACT_290 sections 3 and 7: against main's table (da58f123, 198): 174 changed, 24 unchanged, 0 removed."""
    before = head._undo_this_layer(TABLE, table_raw)
    # CONTRACT_290 section 7 (main's table digest da58f123)
    assert _sha(before).startswith("da58f123")
    # CONTRACT_290 section 7 (the step's authority's beforeSha256 for the table)
    assert authority["changedFiles"][TABLE]["beforeSha256"] == _sha(before)
    main = json.loads(before)
    table = json.loads(table_raw)
    measured = json.loads(inputs_raw)["dryRunUs"]
    changed = sorted(key for key in main if key in table and table[key] != main[key])
    # CONTRACT_290 section 3 (main's 198 entries)
    assert len(main) == 198
    # CONTRACT_290 section 3 (0 removed: every main key is a measured key)
    assert set(main) <= set(measured)
    # CONTRACT_290 section 3 (11 added at c1: the worker files main's table leaves unkeyed)
    assert len(set(measured) - set(main)) == 11
    # CONTRACT_290 section 3 (174 changed, 24 unchanged)
    assert (len(changed), len(main) - len(changed)) == (174, 24)
    # CONTRACT_290 section 3 (the summed weight 3,629.7 s at main)
    assert abs(sum(main.values()) - 3629.7) <= 0.05
    # CONTRACT_290 section 3 (the A2 rows sum to 3,949.0 s)
    assert abs(sum(table[key] for key in measured) - 3949.0) <= 0.05


def test_new_table_digest_in_the_authority_and_one_era_row(head, table_raw, inputs_raw, authority):
    """CONTRACT_290 section 5 (OQ-290-D2): the new digest is the authority's afterSha256 and one ERA_SHA256 row."""
    digest = _sha(table_raw)
    # CONTRACT_290 section 5 (the authority's changedFiles entry, afterSha256)
    assert authority["changedFiles"][TABLE]["afterSha256"] == digest
    # CONTRACT_290 section 5 (once in the authority)
    assert sum(1 for text in _strings(authority) if digest in text) == 1
    # CONTRACT_290 section 5 (the head's one ERA_SHA256 row)
    assert sum(1 for text in _strings(head.ERA_SHA256) if digest in text) == 1
    # CONTRACT_290 section 5 (V1 pins the inputs record by its era digest; OQ-290-D2)
    assert any(_sha(inputs_raw) in text for text in _strings(head.ERA_SHA256))


def test_planner_is_unchanged(head, planner, authority):
    """CONTRACT_290 sections 1, 3 and 5 (E2): the planner keeps its base bytes and the authority never names it."""
    digest = _sha(_read(PLANNER))
    # CONTRACT_290 section 5 (E2: the planner equals its base bytes, 33f6b82d)
    assert digest.startswith("33f6b82d")
    # CONTRACT_290 section 5 (E2: BASE_SHA256 pins the base bytes)
    assert any(digest in text for text in _strings(head.BASE_SHA256))
    # CONTRACT_290 section 5 (E2: the authority names it nowhere)
    assert PLANNER not in set(_strings(authority))
    # CONTRACT_290 section 3 (the planner reads ci/parallel_suite_weights.json)
    assert _rel(planner.WEIGHTS_PATH) == TABLE


def test_packet_yaml_at_c3(yaml_raw):
    """CONTRACT_290 sections 1, 6, 9, 10 and 11: the packet YAML's form and its allowedPaths at c3."""
    lines = [line for line in yaml_raw.decode("utf-8").split("\n") if line]
    data = {}
    for line in lines:
        key, _, rest = line.partition(": ")
        data[key] = json.loads(rest)
    # CONTRACT_290 section 6 (MET-008.yaml's 16-key form)
    assert len(lines) == len(data) == 16
    # CONTRACT_290 section 1 (the packet MET-PERF-050)
    assert data["id"] == TAG
    # CONTRACT_290 section 6 (predecessors 1, MET-008)
    assert data["predecessors"] == ["MET-008"]
    # CONTRACT_290 section 6 (the 64 offlineAcceptanceCommands)
    assert len(data["offlineAcceptanceCommands"]) == 64
    # CONTRACT_290 section 6 (contracts go from 4 to 5)
    assert len(data["contracts"]) == 5
    # CONTRACT_290 section 6 (a "Forward notes" entry carrying FN-290-1)
    assert any(item.startswith("Forward notes") and "FN-290-1" in item for item in data["contracts"])
    evidence = data["expectedEvidence"]
    # CONTRACT_290 section 6 (two items, the first C13's text) and section 10 (quoted exactly, whitespace collapsed)
    assert len(evidence) == 2 and " ".join(evidence[0].split()) == " ".join(C13_TEXT.split())
    allowed = data["allowedPaths"]
    # CONTRACT_290 section 11 (allowedPaths 297) and section 9 (c3 step 2: allowedPaths + 2)
    assert len(allowed) == 297
    # CONTRACT_290 section 6 and section 11 (the oracle and its identity join at c3)
    assert ORACLE in allowed and ORACLE_IDENTITY in allowed
    # CONTRACT_290 sections 3, 4 and 5 (the table, the record, the head, its test, the authority, 290.json)
    assert {TABLE, INPUTS, HEAD, HEAD_TEST, AUTHORITY, HUNK_RECORD} <= set(allowed)
    # CONTRACT_290 section 1 (no edit of ci/parallel_suite.py)
    assert PLANNER not in allowed


# ----------------------------------------------------------------------------------------------------------------
# Section 5: the head layer (V1, E1, E2, E3, V4, V6).
# ----------------------------------------------------------------------------------------------------------------


def test_head_names_the_contract_paths_and_file_sets(head):
    """CONTRACT_290 sections 3, 4, 5, 6 and 7: the head's paths, PACKET_FILES, BASE_FILES and ERRATA_LINES files."""
    # CONTRACT_290 section 3 (the table) and section 4 (the inputs record)
    assert (_rel(head.WEIGHTS_PATH), _rel(head.INPUTS_PATH)) == (TABLE, INPUTS)
    # CONTRACT_290 section 5 (the authority and the hunk-class record)
    assert (_rel(head.AUTHORITY_PATH), _rel(head.HUNK_RECORD_PATH)) == (AUTHORITY, HUNK_RECORD)
    # CONTRACT_290 section 6 (the registry architecture/review-record/briefs.json)
    assert _rel(head.REGISTRY_PATH) == REGISTRY
    # CONTRACT_290 section 5 (PACKET_FILES 2: the inputs record and the table)
    assert sorted(_rel(path) for path in head.PACKET_FILES) == sorted([INPUTS, TABLE])
    # CONTRACT_290 section 5 (BASE_FILES 1: ci/parallel_suite.py)
    assert [_rel(path) for path in head.BASE_FILES] == [PLANNER]
    # CONTRACT_290 section 5 (ERRATA_LINES 3 files) and section 7 (the three named files)
    assert sorted(_rel(path) for path in head.ERRATA_LINES) == sorted([TABLE, *COUNT_FILES])
    # CONTRACT_290 section 4 (the record's eight members)
    assert sorted(head.INPUTS_MEMBERS) == list(INPUT_MEMBERS)


@pytest.mark.parametrize(
    "name",
    [
        "validate_packet_files",
        "validate_weights",
        "validate_base_files",
        "validate_errata",
        "validate_registry",
        "validate_hunk_record",
    ],
)
def test_head_validators_pass_on_the_live_tree(head, name):
    """CONTRACT_290 section 5: V1, E1, E2, E3, V4 and V6 each pass over the live tree."""
    getattr(head, name)()


def test_v1_accepts_the_live_files(head):
    """CONTRACT_290 section 5 (V1): the inputs record and the table at their era digests pass."""
    head.check_packet_files(_packet_files(head))


@pytest.mark.parametrize("index", [0, 1])
@pytest.mark.parametrize("change", ["append", "flip"])
def test_v1_refuses_changed_bytes(head, index, change):
    """CONTRACT_290 section 5 (V1): either pinned file with changed bytes is refused."""
    files = _packet_files(head)
    path = list(head.PACKET_FILES)[index]
    data = files[path]
    files[path] = data + b"\n" if change == "append" else data[:-1] + (b" " if data.endswith(b"\n") else b"\n")
    # CONTRACT_290 section 5 (V1 pins PACKET_FILES by their era digests)
    with pytest.raises(ValueError, match=TAG):
        head.check_packet_files(files)


def test_e1_accepts_the_live_inputs(head, e1_live):
    """CONTRACT_290 section 5 (E1): the live table, record, new test files and present keys pass."""
    head.check_weights(*e1_live)


def test_e1_new_test_files_are_the_head_tests(e1_live):
    """CONTRACT_290 sections 4 and 11: the authority's new test files are the headTests keys; every key present."""
    table_raw, inputs_raw, new_tests, present = e1_live
    record = json.loads(inputs_raw)
    # CONTRACT_290 section 4 (headTests keys equal the authority's new test files: the head test and the oracle)
    assert set(new_tests) == set(record["headTests"]) == {HEAD_TEST, ORACLE}
    # CONTRACT_290 section 3 (0 stale) and section 11 (every table key names a file of the era tree)
    assert present == frozenset(json.loads(table_raw))


@pytest.mark.parametrize("change", ["live", "rows-doubled", "rows-plus-ms"])
def test_e1_head_recomputation_follows_the_rule(head, inputs_raw, change):
    """CONTRACT_290 section 3: the head's recomputed(inputs) equals section 3's rule, live and on moved rows."""
    record = json.loads(inputs_raw)
    if change == "rows-doubled":
        record["dryRunUs"] = {key: [2 * first, 2 * second] for key, (first, second) in record["dryRunUs"].items()}
    elif change == "rows-plus-ms":
        record["dryRunUs"] = {
            key: [first + 1000, second + 3000] for key, (first, second) in record["dryRunUs"].items()
        }
    # CONTRACT_290 section 3 (the rule, Python 3's round and json.dumps)
    assert head.recomputed(record) == _recompute(record)


E1_CASES = [
    "overlap:head",
    "overlap:oracle",
    "outside:extra",
    "outside:new-files",
    "source-value:head",
    "source-value:oracle",
    "source-row:head",
    "source-row:oracle",
    "source-keys:missing",
    "source-keys:extra",
    "stale:measured",
    "stale:head",
    "bytes:value",
    "bytes:newline",
    "bytes:indent",
    "bytes:unsorted",
    "bytes:duplicate",
    "bytes:dropped",
    "bytes:extra",
]


def _e1_case(case, table_raw, inputs_raw, new_tests, present):
    record = json.loads(inputs_raw)
    table = json.loads(table_raw)
    kind, _, target = case.partition(":")
    key = HEAD_TEST if target == "head" else ORACLE
    first = sorted(record["dryRunUs"])[0]
    raw, tests, keys, touched = table_raw, new_tests, present, False
    if kind == "overlap":
        micro = int(round(record["headTests"][key] / record["kappa"] * 1000)) * 1000
        record["dryRunUs"][key] = [micro, micro]
        raw, touched = _recompute(record), True
    elif case == "outside:extra":
        record["headTests"][EXTRA_TEST] = 1.0
        record["headTestsSource"][EXTRA_TEST] = {"mode": "provisional"}
        raw, keys, touched = _recompute(record), present | {EXTRA_TEST}, True
    elif case == "outside:new-files":
        tests = tuple(path for path in new_tests if path != ORACLE)
    elif kind == "source-value":
        record["headTests"][key] = round(record["headTests"][key] + 0.5, 1)
        raw, touched = _recompute(record), True
    elif kind == "source-row":
        row = record["headTestsSource"][key]
        if row.get("mode") == "measured":
            row["rawSeconds"] = row["rawSeconds"] + 0.5
        else:
            record["headTestsSource"][key] = {
                "mode": "measured",
                "rawSeconds": record["headTests"][key] + 0.5,
                "overheadSeconds": 0.0,
                "summarySha256": "a" * 64,
            }
        touched = True
    elif case == "source-keys:missing":
        del record["headTestsSource"][ORACLE]
        touched = True
    elif case == "source-keys:extra":
        record["headTestsSource"][EXTRA_TEST] = {"mode": "provisional"}
        touched = True
    elif kind == "stale":
        keys = present - {first if target == "measured" else HEAD_TEST}
    elif case == "bytes:value":
        table[first] = round(table[first] + 0.1, 1)
        raw = _dumps(table)
    elif case == "bytes:newline":
        raw = table_raw[:-1] if table_raw.endswith(b"\n") else table_raw + b"\n"
    elif case == "bytes:indent":
        raw = (json.dumps(table, indent=2, sort_keys=True) + "\n").encode("utf-8")
    elif case == "bytes:unsorted":
        raw = (json.dumps(dict(reversed(list(table.items()))), indent=1) + "\n").encode("utf-8")
    elif case == "bytes:duplicate":
        lines = table_raw.split(b"\n")
        lines.insert(2, lines[1])
        raw = b"\n".join(lines)
    elif case == "bytes:dropped":
        del table[first]
        raw, keys = _dumps(table), present - {first}
    elif case == "bytes:extra":
        table[EXTRA_TEST] = 0.0
        raw, keys = _dumps(table), present | {EXTRA_TEST}
    else:
        raise AssertionError(case)
    inputs_bytes = _dump_like(inputs_raw, record) if touched else inputs_raw
    return raw, inputs_bytes, tests, keys


@pytest.mark.parametrize("case", E1_CASES)
def test_e1_refuses(head, e1_live, case):
    """CONTRACT_290 section 5 (E1): an overlap, a key outside the new test files, a disagreeing or missing source row,
    a stale key, and a table whose bytes differ from the recomputation are each refused."""
    arguments = _e1_case(case, *e1_live)
    assert arguments != e1_live
    # CONTRACT_290 section 5 (E1 refuses each of these)
    with pytest.raises(ValueError, match=TAG):
        head.check_weights(*arguments)


def test_e2_accepts_the_live_planner(head, authority):
    """CONTRACT_290 section 5 (E2): the planner at its base bytes, unnamed by the authority, passes."""
    head.check_base_files(_base_files(head), authority["changedFiles"], authority["newFiles"])


@pytest.mark.parametrize(
    "change", ["planner-appended", "planner-flipped", "changed-names-planner", "new-names-planner"]
)
def test_e2_refuses(head, authority, change):
    """CONTRACT_290 section 5 (E2): a planner off its base bytes, or an authority that names it, is refused."""
    files = _base_files(head)
    changed = copy.deepcopy(authority["changedFiles"])
    new = dict(authority["newFiles"])
    path = next(iter(files))
    data = files[path]
    if change == "planner-appended":
        files[path] = data + b"\n"
    elif change == "planner-flipped":
        files[path] = bytes([data[0] ^ 0x01]) + data[1:]
    elif change == "changed-names-planner":
        changed[PLANNER] = copy.deepcopy(changed[TABLE])
    else:
        new[PLANNER] = _sha(data)
    # CONTRACT_290 section 5 (E2: base bytes 33f6b82d, and the authority names it nowhere)
    with pytest.raises(ValueError, match=TAG):
        head.check_base_files(files, changed, new)


def test_e3_named_files_spans_and_classes(head, record_raw):
    """CONTRACT_290 sections 5 and 7 (E3): class other only on the three named files; the count lines are named."""
    classes = json.loads(record_raw)["classes"]
    named = sorted([TABLE, *COUNT_FILES])
    # CONTRACT_290 section 5 (E3: class-other hunks only on the 3 named files) and section 7
    assert sorted(path for path, kinds in classes.items() if "other" in kinds) == named
    # CONTRACT_290 section 7 (the table's hunks, all class other under rule W)
    assert classes[TABLE] and set(classes[TABLE]) == {"other"}
    spans = {_rel(path): value for path, value in head.ERRATA_LINES.items()}
    for path, line in COUNT_FILES.items():
        # CONTRACT_290 section 7 (test_ci_performance.py line 169, test_credential_lifecycle.py line 362)
        assert any(first <= line <= last for first, last in spans[path])


def test_e3_accepts_the_live_record(head, authority, record_raw):
    """CONTRACT_290 section 5 (E3): the live classes, with the named files' before bytes, pass."""
    head.check_errata(json.loads(record_raw)["classes"], authority["changedFiles"], _befores(head, authority))


@pytest.mark.parametrize("position", ["first", "middle", "last"])
def test_e3_refuses_other_on_any_other_file(head, authority, record_raw, position):
    """CONTRACT_290 sections 5 and 7 (E3): class other on a file outside the three named files is refused."""
    classes = copy.deepcopy(json.loads(record_raw)["classes"])
    named = {_rel(path) for path in head.ERRATA_LINES}
    eligible = sorted(
        path
        for path, kinds in classes.items()
        if path not in named and kinds and any(kind != "other" for kind in kinds)
    )
    assert eligible
    path = {"first": eligible[0], "middle": eligible[len(eligible) // 2], "last": eligible[-1]}[position]
    index = next(number for number, kind in enumerate(classes[path]) if kind != "other")
    classes[path][index] = "other"
    befores = _befores(head, authority)
    # CONTRACT_290 section 5 (E3: class other only on the 3 named files at their named spans)
    with pytest.raises(ValueError, match=TAG):
        head.check_errata(classes, authority["changedFiles"], befores)


def test_v4_registry_holds_the_rider_last(registry_raw):
    """CONTRACT_290 section 6 (V4's rider): briefs.json holds 37 entries, the MET-PERF-050/packet rider last."""
    entries = _entries(json.loads(registry_raw))
    # CONTRACT_290 section 6 (36 to 37 entries)
    assert entries is not None and len(entries) == 37
    if isinstance(entries, list):
        last = entries[-1]
    else:
        last_key = list(entries)[-1]
        last = {last_key: entries[last_key]}
    # CONTRACT_290 section 6 (the MET-PERF-050/packet rider is appended last)
    assert TAG in json.dumps(last)


def test_v4_accepts_the_live_registry(head, registry_raw):
    """CONTRACT_290 section 5 (V4): the live registry and its packet brief pass."""
    head.check_registry(registry_raw, _briefs(head))


@pytest.mark.parametrize("change", ["drop-rider", "duplicate-rider"])
def test_v4_refuses(head, registry_raw, change):
    """CONTRACT_290 sections 5 and 6 (V4): a registry without the rider, or with it twice, is refused."""
    registry = json.loads(registry_raw)
    entries = _entries(registry)
    # CONTRACT_290 section 6 (the 37 entries)
    assert entries is not None
    if isinstance(entries, list):
        if change == "drop-rider":
            entries.pop()
        else:
            entries.append(copy.deepcopy(entries[-1]))
    else:
        last_key = list(entries)[-1]
        if change == "drop-rider":
            del entries[last_key]
        else:
            entries[last_key + "-copy"] = copy.deepcopy(entries[last_key])
    raw = _dump_like(registry_raw, registry)
    briefs = _briefs(head)
    # CONTRACT_290 section 5 (V4: the registry differs from the base by this packet's one rider)
    with pytest.raises(ValueError, match=TAG):
        head.check_registry(raw, briefs)


def _is_steps(key, value) -> bool:
    return isinstance(key, str) and "step" in key.lower() and value == [1, 1]


def _is_count_pairs(key, value) -> bool:
    return isinstance(key, str) and key.lower().replace("_", "") == "countpairs" and value == []


def test_v6_record_terms(head, authority, record_raw):
    """CONTRACT_290 sections 1 and 5 (V6): rule 106e5771, steps [1, 1], countPairs [], the v2.5 classes."""
    record = json.loads(record_raw)
    rule = head.HUNK_RULE_SHA256
    # CONTRACT_290 section 5 (V6: rule 106e5771)
    assert isinstance(rule, str) and rule.startswith("106e5771")
    # CONTRACT_290 section 5 (V6: the record is under the v2.5 rule, by its digest)
    assert any(rule in text for text in _strings(record))
    # CONTRACT_290 section 1 and section 5 (the v2.5 reader's steps are [1, 1])
    assert _key_paths(record, _is_steps)
    # CONTRACT_290 section 1 and section 5 (countPairs [])
    assert _key_paths(record, _is_count_pairs)
    used = {kind for kinds in record["classes"].values() for kind in kinds}
    # CONTRACT_290 section 5 (the hunk-class record's classes: bridge, cascade, other, record, register)
    assert used <= VOCABULARY
    changed = authority["changedFiles"]
    # operator-stated: classes maps a changed file to one class per reverse hunk
    assert all(path in changed and len(kinds) == len(changed[path]["reverseHunks"]) for path, kinds in record["classes"].items())


def test_v6_accepts_the_live_record(head, authority, record_raw, afters, classify, live_context):
    """CONTRACT_290 section 5 (V6): the live record, under the era rule and context, passes."""
    head.check_hunk_record(
        record_raw, authority["changedFiles"], afters, classify, live_context, head.HUNK_RULE_SHA256
    )


V6_CASES = [
    "extra-member",
    "vocab-class",
    "vocab-list",
    "rule-param",
    "rule-record",
    "steps",
    "count-pairs",
    "outcome",
    "class-swap",
    "classes-drop-path",
]


def _v6_case(head, record_raw, case):
    record = json.loads(record_raw)
    rule = head.HUNK_RULE_SHA256
    rule_sha = rule
    raw = None
    first = sorted(path for path, kinds in record["classes"].items() if kinds)[0]
    if case == "extra-member":
        record["oracleExtraMember"] = True
    elif case == "vocab-class":
        record["classes"][first][0] = "bogus-class"
    elif case == "vocab-list":
        trails = _key_paths(
            record, lambda key, value: isinstance(key, str) and "vocab" in key.lower() and isinstance(value, list)
        )
        for trail in trails:
            _get(record, trail).append("bogus-class")
        if not trails:
            record["classes"][first][-1] = record["classes"][first][-1].upper()
    elif case == "rule-param":
        rule_sha = "0" * 64
        raw = record_raw
    elif case == "rule-record":
        trails = _key_paths(record, lambda key, value: isinstance(value, str) and rule in value)
        # CONTRACT_290 section 5 (V6: the record carries the v2.5 rule's digest)
        assert trails
        for trail in trails:
            _set(record, trail, _get(record, trail).replace(rule, "0" * 64))
    elif case == "steps":
        trails = _key_paths(record, _is_steps)
        # CONTRACT_290 section 1 and section 5 (steps [1, 1])
        assert trails
        for trail in trails:
            _set(record, trail, [1, 2])
    elif case == "count-pairs":
        trails = _key_paths(record, _is_count_pairs)
        # CONTRACT_290 section 1 and section 5 (countPairs [])
        assert trails
        for trail in trails:
            _set(record, trail, [[301, 302]])
    elif case == "outcome":
        statement = "the verify passed under the bar"
        trails = _key_paths(record, lambda key, value: isinstance(key, str) and "outcome" in key.lower())
        for trail in trails:
            current = _get(record, trail)
            if isinstance(current, list):
                _set(record, trail, current + [statement])
            elif isinstance(current, dict):
                _set(record, trail, dict(current, statement=statement))
            else:
                _set(record, trail, statement)
        if not trails:
            record["outcomeStatements"] = [statement]
    elif case == "class-swap":
        path = next(name for name in sorted(record["classes"]) if any(k != "other" for k in record["classes"][name]))
        index = next(number for number, kind in enumerate(record["classes"][path]) if kind != "other")
        current = record["classes"][path][index]
        record["classes"][path][index] = "bridge" if current != "bridge" else "cascade"
    elif case == "classes-drop-path":
        del record["classes"][first]
    else:
        raise AssertionError(case)
    if raw is None:
        raw = _dump_like(record_raw, record)
    return raw, rule_sha


@pytest.mark.parametrize("case", V6_CASES)
def test_v6_refuses(head, authority, record_raw, afters, classify, live_context, case):
    """CONTRACT_290 sections 1 and 5 (V6): a record off its closed members, vocabulary, v2.5 rule digest, steps
    [1, 1], countPairs [] or classes, or carrying an outcome statement, is refused."""
    raw, rule_sha = _v6_case(head, record_raw, case)
    assert (raw, rule_sha) != (record_raw, head.HUNK_RULE_SHA256)
    # CONTRACT_290 section 5 (V6: its own hunk-class record under the v2.5 classes; rule 106e5771, steps [1, 1])
    with pytest.raises(ValueError, match=TAG):
        head.check_hunk_record(raw, authority["changedFiles"], afters, classify, live_context, rule_sha)


def test_v6_refuses_each_dropped_member(head, authority, record_raw, afters, classify, live_context):
    """CONTRACT_290 section 5 (V6): the record's members are closed; dropping any one is refused."""
    record = json.loads(record_raw)
    for name in list(record):
        broken = copy.deepcopy(record)
        del broken[name]
        raw = _dump_like(record_raw, broken)
        # CONTRACT_290 section 5 (V6: the record's closed members)
        with pytest.raises(ValueError, match=TAG):
            head.check_hunk_record(
                raw, authority["changedFiles"], afters, classify, live_context, head.HUNK_RULE_SHA256
            )
