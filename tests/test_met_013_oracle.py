"""D5a oracle for MET-013 (slot 295, CONTRACT_295 r5): one part per member contract, and the head layer.

D5a (owner decision): a contract packet carries tests written outside the candidate by someone who is not its
builder. These tests are black-box. They load exactly one repository module, the head layer
scripts/validate_met_013.py, by file path into a fresh module object, and reach the three members' era models and
checkers (and MAS-RA-002's model) only as the era objects the head builds.

C18 (CONTRACT_295 section 2): every repository file is read through the head's era reader,
head.reviewed_bytes(path); the era checkers read through head._era_read. Nothing here reads the live tree or
tests a path on it.

Sources of every expected value, cited on the assert's own line or the line directly above it:
- CONTRACT_295 r5, sections 1, 3a, 3b, 3c, 4, 4a, 5, 6 and 8 ("CONTRACT_295 section ...");
- R08's design note r3 of HR-COMPACTION-GOV-001 ("R08 note r3 ...");
- R12's contract draft r4 of HR-REPLAY-FIXTURES-001 ("R12 draft r4 section ...");
- R12's erratum D1 to draft r4, which CONTRACT_295 section 3b (r5) names: it replaces draft r4 section 6's
  "Binding (3.4)" example by two runs ("R12 erratum D1 section ...");
- R04's design note r3 of HR-APPROVAL-OUTCOME-001 ("R04 note r3 ...");
- the facts the operator states about the head layer and the era models ("operator-stated").
Records, vector sets, blobs, the weights table, the authority, the hunk-class record, the registry and the packet
YAML are fixtures: read at run time, mutated only in deep copies, never the source of an expected value. Nothing
here pins a digest of the table, the head, the authority, the hunk-class record or a record file, nor either new
row's value, so the file holds on the c3 candidate and after the measured step (CONTRACT_295 section 7, step 3).
"""

from __future__ import annotations

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

HEAD_MODULE = "_met_013_d5a_oracle_head"

# ----------------------------------------------------------------------------------------------------------------
# Expected values, each with its source.
# ----------------------------------------------------------------------------------------------------------------

# CONTRACT_295 section 1: the three members, in the hub's drafting order.
MEMBER_ITEMS = ("HR-COMPACTION-GOV-001", "HR-REPLAY-FIXTURES-001", "HR-APPROVAL-OUTCOME-001")
# CONTRACT_295 sections 3a, 3b and 3c: each member's record and vector set.
MEMBER_PATHS = {
    "HR-COMPACTION-GOV-001": (
        "architecture/agent-loop-compaction/record.json",
        "architecture/agent-loop-compaction/vectors.json",
    ),
    "HR-REPLAY-FIXTURES-001": (
        "architecture/replay-fixtures/record.json",
        "architecture/replay-fixtures/vectors.json",
    ),
    "HR-APPROVAL-OUTCOME-001": (
        "architecture/approval-outcome/record.json",
        "architecture/approval-outcome/vectors.json",
    ),
}
# operator-stated: each member's E1 check and validate pair; the third value names this file's fixture.
E1_FUNCTIONS = {
    "HR-COMPACTION-GOV-001": ("check_compaction", "validate_compaction", "compaction"),
    "HR-REPLAY-FIXTURES-001": ("check_replay_fixtures", "validate_replay_fixtures", "replay"),
    "HR-APPROVAL-OUTCOME-001": ("check_approval_outcome", "validate_approval_outcome", "approval"),
}
# CONTRACT_295 section 4a (N2): REPLAY's one injected base model.
REPLAY_BASES = [("run_manifest", "scripts/run_manifest.py")]
# CONTRACT_295 section 1: MAS-RA-008's and MAS-RA-002's files are base files (E2).
BASE_PREFIXES = ("architecture/agent-loop/", "architecture/run-manifest/")
BASE_SCRIPTS = ("scripts/agent_loop.py", "scripts/run_manifest.py")

# operator-stated (CODES) and CONTRACT_295 section 3a: nine rule families, one refusal code each.
COMPACTION_CODES = {
    "C1": "CG_LOCK",
    "C2": "CG_RANGE",
    "C3": "CG_CHECKPOINT",
    "C4": "CG_LADDER",
    "C5": "CG_EPOCH",
    "C6": "CG_PROMPT",
    "C7": "CG_TRUST",
    "C8": "CG_RETENTION",
    "C9": "CG_GATE",
}
POSITIVE = "POSITIVE"  # operator-stated ("every POSITIVE vector accepted")
# CONTRACT_295 section 3a (COMPACT's detail): fields only the COMPACT step carries, used to find it in a case.
_COMPACT_ONLY = ("lockId", "summaryDigest", "summaryKind", "summaryTrust", "summaryRoute", "systemPromptDigest")

# R12 draft r4 section 6: the worked fixtures, their tasks and their real content digests.
FIXTURE_IDS = ("fx-dev-0001.v1", "fx-dev-0002.v1")
TASK_IDS = ("fx-dev-0001", "fx-dev-0002")
HELLO = "5891b5b522d5df086d0ff0b110fbd9d21bb4fc7163af34d08286a2e846f6be03"
HELLO_WORLD = "853ff93762a06ddbf722c4ebe9ddd66d8f63ddaea97f521c3ecc20da7c976020"
CHECK_SH = "b4d644d4279594903f1a9911956432d9473041f2984fc6014c14d7402c7d126c"
# R12 draft r4 section 6: greeting.txt "hello" then "hello, world" (each a line), and bin/check.sh's exact bytes.
SECTION6_CONTENT = (
    pytest.param(b"hello\n", HELLO, id="greeting-before"),
    pytest.param(b"hello, world\n", HELLO_WORLD, id="greeting-after"),
    pytest.param(b"#!/bin/sh\necho ok\n", CHECK_SH, id="check-sh"),
)
BLOB_PREFIX = "architecture/replay-fixtures/blobs/"  # CONTRACT_295 section 3b; operator-stated
DIGEST_FORM = re.compile(r"sha256:[0-9a-f]{64}")  # R12 draft r4 section 2 (sha256: and the hex SHA-256)
FULL_SCORE = 1_000_000  # R12 draft r4 section 3.3
# CONTRACT_295 section 3b: the record refusal codes beside MAS-RA-002's shape codes.
RECORD_CODES = (
    "TREE_PATH",
    "TREE_ORDER",
    "HELD_OUT_PUBLIC",
    "FIXTURE_BINDING",
    "SELF_REPORTED_SCORE",
    "OUTCOME_MISMATCH",
    "BLOCKER_UNEVIDENCED",
    "REGENERATION_MISMATCH",
    "ARMS_IDENTICAL",
    "ARMS_NOT_ONE_VARIABLE",
)
VERDICTS = ("REPLAY_MATCH", "REPLAY_DIVERGED", "TREE_MISMATCH")  # R12 draft r4 section 3.6; CONTRACT_295 section 3b
# CONTRACT_295 section 3b: the blockerCode closed list (four environment causes plus the evaluator cause).
ENVIRONMENT_CAUSES = ("PROVIDER_UNAVAILABLE", "SANDBOX_UNAVAILABLE", "RESOURCE_UNAVAILABLE", "FIXTURE_UNAVAILABLE")
EVALUATOR_CAUSE = "EVALUATOR_ERROR"
# CONTRACT_295 section 3b: the trajectory exit.code closed list per exit status.
EXIT_CODES = {
    "COMPLETED": ("DONE",),
    "ERRORED": ("AGENT_ERROR", "TOOL_ERROR", "HARNESS_ERROR"),
    "BUDGET_EXCEEDED": ("BUDGET_TOKENS", "BUDGET_COST", "BUDGET_WALL_CLOCK", "BUDGET_ITERATIONS"),
    "BLOCKED": ENVIRONMENT_CAUSES,
}
# operator-stated: the replay model's checks.
REPLAY_CHECKS = frozenset(
    {"FIXTURE", "TRAJECTORY", "SCORE", "REGENERATION", "REPLAY", "VERDICT", "ARM_PAIR", "EVALUATION"}
)
# R12 draft r4 section 3.1 (path grammar): up to 4,096 UTF-8 bytes is allowed; this path has exactly 4,096.
LONG_PATH = "d" * 64 + ("/" + "d" * 63) * 63
# R12 draft r4 section 3.1: each path below is refused as TREE_PATH.
BAD_PATHS = (
    pytest.param("/greeting.txt", id="absolute"),
    pytest.param("bin/", id="ends-with-slash"),
    pytest.param("bin//check.sh", id="empty-segment"),
    pytest.param("", id="empty-path"),
    pytest.param(".", id="dot"),
    pytest.param("./greeting.txt", id="dot-segment-first"),
    pytest.param("bin/./check.sh", id="dot-segment-inner"),
    pytest.param("..", id="dot-dot"),
    pytest.param("../escape.sh", id="path-mutant"),
    pytest.param("bin/../greeting.txt", id="dot-dot-inner"),
    pytest.param("bin\\check.sh", id="backslash"),
    pytest.param("greeting\x00.txt", id="nul"),
    pytest.param("greeting\x01.txt", id="control-01"),
    pytest.param("greeting\x1f.txt", id="control-1f"),
    pytest.param("greeting\n.txt", id="control-newline"),
    pytest.param("greeting\t.txt", id="control-tab"),
    pytest.param(LONG_PATH + "d", id="4097-bytes"),
    pytest.param("é" * 2049, id="4098-utf8-bytes"),
)
# R12 draft r4 sections 3.1 and 6: valid paths.
GOOD_PATHS = (
    pytest.param("greeting.txt", id="greeting"),
    pytest.param("bin/check.sh", id="check-sh"),
    pytest.param(LONG_PATH, id="4096-bytes"),
)

# R04 note r3 section 1 and CONTRACT_295 section 3c: the five terminal outcomes and the open state's spelling.
TERMINAL_OUTCOMES = frozenset({"APPROVED", "REJECTED", "EXPIRED", "CANCELLED", "UNAVAILABLE"})
REQUESTED_STATE = "REQUESTED"
APPROVAL_CHECKS = frozenset({"HISTORY", "LIFECYCLE", "PROFILE", "READ", "STATEMENTS"})  # operator-stated
# CONTRACT_295 section 3c and R04 note r3 section 5: the in-scope negatives, and those named out.
IN_SCOPE_NEGATIVES = ("N-1", "N-2", "N-3", "N-4", "N-5", "N-6", "N-8", "N-9", "N-10", "N-11", "N-12", "R2-N1")
OUT_OF_SCOPE = ("N-7", "N-13", "R2-N2")
# R04 note r3 O1 and N-5: values outside the six (R04's stored PENDING is not the published spelling).
OUTSIDE_VALUES = (
    "PENDING",
    "approved",
    "Approved",
    " APPROVED",
    "APPROVED ",
    "APPROVED\n",
    "APPROVED\x00",
    "ADMITTED",
    "ALLOW",
    "ALLOWED",
    "GRANTED",
    "YES",
    "TRUE",
    "OK",
    "",
    "UNKNOWN",
    "DEFAULT",
    "APPROVE",
    "APPROVED_ONCE",
    "APPROVED,REJECTED",
)

# CONTRACT_295 section 5: the contracts line names the accepted base.
BASE_SENTENCE = (
    "Accepted base is main 6437de35186c458e671a4b659390d2b5f3909c8d, tree "
    "4c28317966879df7b813b0af10913dbf51d0172a, holding 318 immutable packets including MET-012."
)
OBJECTIVE_STEP = "a K = 0 step (319 packets at slot 295)"  # CONTRACT_295 section 5
BASE_PACKETS = 318  # CONTRACT_295 section 1
CATALOG_PACKETS = 319  # CONTRACT_295 section 1 (318 + 1 + K, K = 0)
YAML_PATH = "task-packets/MET-013.yaml"  # CONTRACT_295 section 5
YAML_KEYS = 16  # operator-stated
HEAD_REPO_PATH = "scripts/validate_met_013.py"  # CONTRACT_295 sections 4 and 5
TABLE_PATH = "ci/parallel_suite_weights.json"  # CONTRACT_295 section 6
TABLE_ENTRIES = 219  # CONTRACT_295 section 6 (217 + 2); operator-stated
NEW_ROWS = ("tests/test_met_013.py", "tests/test_met_013_oracle.py")  # CONTRACT_295 section 6
REGISTRY_PATH = "architecture/review-record/briefs.json"  # CONTRACT_295 section 5
REGISTRY_ENTRIES = 42  # CONTRACT_295 sections 1 and 5 (41 -> 42); operator-stated
RIDER = "MET-013/packet"  # CONTRACT_295 sections 1 and 5
HUNK_CLASS_PATH = "architecture/chain-checkpoint/hunk-classes/295.json"  # CONTRACT_295 section 4
K0_STEPS = [1, 1]  # CONTRACT_295 section 4a (check_hunk_record's steps [1, 1] at K 0); operator-stated
K3_STEPS = [1, 4]  # CONTRACT_295 section 4a (294's value at K 3): used only as a mutation
V6_KINDS = ("closed-members", "vocabulary", "rule-digest", "k0-steps", "k0-count-pairs", "no-outcome-statement")

# ----------------------------------------------------------------------------------------------------------------
# Plain-data helpers (no repository access).
# ----------------------------------------------------------------------------------------------------------------


def _positions(value, position=()):
    """Every (position, node) pair of a JSON value, the value itself first, in document order."""
    yield position, value
    if isinstance(value, dict):
        for key, item in value.items():
            yield from _positions(item, position + (key,))
    elif isinstance(value, list):
        for index, item in enumerate(value):
            yield from _positions(item, position + (index,))


def _at(value, position):
    for step in position:
        value = value[step]
    return value


def _dicts(value):
    return [node for _, node in _positions(value) if isinstance(node, dict)]


def _strings(value):
    """Every string of a JSON value, keys included."""
    found = []
    for _, node in _positions(value):
        if isinstance(node, str):
            found.append(node)
        elif isinstance(node, dict):
            found.extend(key for key in node if isinstance(key, str))
    return found


def _direct_strings(node):
    if isinstance(node, str):
        return [node]
    if isinstance(node, dict):
        return [value for value in node.values() if isinstance(value, str)]
    return []


def _is_int(value):
    return isinstance(value, int) and not isinstance(value, bool)


def _sha(raw):
    return hashlib.sha256(raw).hexdigest()


def _flip_byte(raw):
    return bytes([raw[0] ^ 0x01]) + raw[1:]


def _flip_last(text):
    return text[:-1] + ("1" if text[-1] != "1" else "2")


def _other_digest(value):
    """A digest of the same form that names nothing the case holds."""
    match = re.fullmatch(r"(sha256:)?([0-9a-f]{64})", value)
    if match is None:
        return value + "-absent"
    replacement = "0" * 64 if match.group(2) != "0" * 64 else "f" * 64
    return (match.group(1) or "") + replacement


_JCS_ESCAPES = {'"': '\\"', "\\": "\\\\", "\b": "\\b", "\f": "\\f", "\n": "\\n", "\r": "\\r", "\t": "\\t"}


def _jcs_string(text):
    out = ['"']
    for char in text:
        if char in _JCS_ESCAPES:
            out.append(_JCS_ESCAPES[char])
        elif ord(char) < 0x20:
            out.append("\\u%04x" % ord(char))
        else:
            out.append(char)
    out.append('"')
    return "".join(out)


def _jcs(value):
    """RFC 8785 canonical form of an I-JSON value with integers only (R12 draft r4 section 2), written here."""
    if value is None:
        return "null"
    if value is True:
        return "true"
    if value is False:
        return "false"
    if _is_int(value):
        return str(value)
    if isinstance(value, str):
        return _jcs_string(value)
    if isinstance(value, list):
        return "[" + ",".join(_jcs(item) for item in value) + "]"
    if isinstance(value, dict):
        keys = sorted(value, key=lambda key: key.encode("utf-16-be"))
        return "{" + ",".join(_jcs_string(key) + ":" + _jcs(value[key]) for key in keys) + "}"
    raise TypeError("not an integer-only I-JSON value: " + type(value).__name__)


def _digest(value):
    """R12 draft r4 section 2: digest(x) = sha256: and the hex SHA-256 of x's RFC 8785 form."""
    return "sha256:" + _sha(_jcs(value).encode("utf-8"))


def _dump_like(original, raw):
    """A JSON writer in the form that reproduces raw from original (indent 2 and a newline when none does)."""
    forms = []
    for indent in (2, None, 4, 1):
        for separators in ((",", ": "), (", ", ": "), (",", ":")):
            for sort_keys in (False, True):
                for ensure_ascii in (False, True):
                    for tail in ("\n", ""):
                        forms.append((indent, separators, sort_keys, ensure_ascii, tail))

    def dump(document, form):
        indent, separators, sort_keys, ensure_ascii, tail = form
        text = json.dumps(
            document, indent=indent, separators=separators, sort_keys=sort_keys, ensure_ascii=ensure_ascii
        )
        return (text + tail).encode("utf-8")

    chosen = next((form for form in forms if dump(original, form) == raw), forms[0])
    return lambda document: dump(document, chosen)


class _Pairs(dict):
    """A JSON object that keeps its raw key list, duplicates included."""

    def __init__(self, pairs):
        super().__init__(pairs)
        self.raw = [key for key, _ in pairs]


# ----------------------------------------------------------------------------------------------------------------
# The head and the era objects it builds.
# ----------------------------------------------------------------------------------------------------------------


def _load_head():
    spec = importlib.util.spec_from_file_location(HEAD_MODULE, ROOT / "scripts" / "validate_met_013.py")
    module = importlib.util.module_from_spec(spec)
    # The import system's recipe for a module loaded by path: a new name, nothing replaced.
    sys.modules[HEAD_MODULE] = module
    spec.loader.exec_module(module)
    return module


class _Era:
    """One member's era model and checker (as the head builds them), its parsed record and its vector set."""

    def __init__(self, head, row):
        self.row = row
        self.model, self.checker = head._era_checker(row)
        self.record = json.loads(head.reviewed_bytes(row["record"]))
        self.vectors = json.loads(head.reviewed_bytes(row["vectors"]))
        self.cases = self.vectors["cases"]
        self.positives = [case for case in self.cases if case["polarity"] == POSITIVE]
        self.others = [case for case in self.cases if case["polarity"] != POSITIVE]

    def of(self, key, name, cases=None):
        return [case for case in (self.positives if cases is None else cases) if case.get(key) == name]


@pytest.fixture(scope="module")
def head():
    return _load_head()


@pytest.fixture(scope="module")
def authority(head):
    return head.authority()


@pytest.fixture(scope="module")
def compaction(head):
    return _Era(head, head.COMPACTION)


@pytest.fixture(scope="module")
def replay(head):
    era = _Era(head, head.REPLAY)
    name, path = head.REPLAY["bases"][0]
    era.rm = head._era_model(path, "_met_013_" + name)
    era.stores = era.vectors["stores"]
    era.documents = _dicts(era.stores) + [node for case in era.positives for node in _dicts(case["input"])]
    return era


@pytest.fixture(scope="module")
def approval(head):
    return _Era(head, head.APPROVAL)


@pytest.fixture(scope="module")
def catalog(head, authority):
    """The whole catalog's YAML bytes: every base id of the authority, and the new packet."""
    names = [*authority["baselinePackets"], head.NEW_PACKET]
    return {name: head.reviewed_bytes("task-packets/" + name + ".yaml") for name in names}


@pytest.fixture(scope="module")
def packets(head, catalog):
    return {name: head.safe_load(raw) for name, raw in catalog.items()}


def _compaction_eval(era, family, data):
    return tuple(era.model.evaluate(family, copy.deepcopy(data)))


def _replay_eval(era, check, data):
    return tuple(era.model.evaluate(check, copy.deepcopy(data), copy.deepcopy(era.stores), era.rm))


def _approval_eval(era, check, data):
    return tuple(era.model.evaluate(check, copy.deepcopy(data)))


# ----------------------------------------------------------------------------------------------------------------
# Part 1: the head's member rows (CONTRACT_295 sections 1, 3 and 4a).
# ----------------------------------------------------------------------------------------------------------------


def test_member_rows_in_drafting_order(head):
    """CONTRACT_295 sections 1, 3a to 3c and 4a (N2): MEMBERS holds the three contracts in the hub's drafting order
    with their record and vector paths; REPLAY alone injects MAS-RA-002's run_manifest."""
    assert [row["item"] for row in head.MEMBERS] == list(MEMBER_ITEMS)  # CONTRACT_295 section 1 (drafting order)
    # operator-stated (COMPACTION, REPLAY, APPROVAL bound to the rows); CONTRACT_295 section 1
    assert [head.COMPACTION["item"], head.REPLAY["item"], head.APPROVAL["item"]] == list(MEMBER_ITEMS)
    for row in head.MEMBERS:
        assert (row["record"], row["vectors"]) == MEMBER_PATHS[row["item"]]  # CONTRACT_295 sections 3a, 3b, 3c
    assert [tuple(pair) for pair in head.REPLAY["bases"]] == REPLAY_BASES  # CONTRACT_295 section 4a (N2); operator-stated
    # operator-stated (the other rows have no bases); CONTRACT_295 section 4a (N2)
    assert list(head.COMPACTION["bases"]) == [] and list(head.APPROVAL["bases"]) == []
    assert head.NEW_PACKET == "MET-013"  # operator-stated; CONTRACT_295 section 1


# ----------------------------------------------------------------------------------------------------------------
# Part 2: HR-COMPACTION-GOV-001 (CONTRACT_295 section 3a, R08 note r3).
# ----------------------------------------------------------------------------------------------------------------


def _drift_mutants(data):
    """R08 note r3 C6: a MODEL step's prompt changed with no COMPACT step since the MODEL step before it."""
    steps = data["steps"]
    kinds = [step.get("kind") for step in steps]
    model_at = [index for index, kind in enumerate(kinds) if kind == "MODEL"]
    mutants = []
    for before, after in zip(model_at, model_at[1:]):
        if "COMPACT" in kinds[before + 1:after]:
            continue
        mutant = copy.deepcopy(data)
        mutant["steps"][after]["prompt"] = mutant["steps"][after]["prompt"] + " [drift]"
        mutants.append(mutant)
    return mutants


def _consumes_names(consumes, step):
    names = {node for _, node in _positions(consumes) if isinstance(node, (str, int)) and not isinstance(node, bool)}
    return step.get("seq") in names or step.get("id") in names


def _range_mutants(data):
    """R08 note r3 C2: the dropped range made to end, or start, between a MODEL request and its TOOL result."""
    ranges = sorted(
        {
            (node["rangeFirstSeq"], node["rangeLastSeq"])
            for node in _dicts(data)
            if _is_int(node.get("rangeFirstSeq")) and _is_int(node.get("rangeLastSeq"))
        }
    )
    step_lists = [
        node
        for _, node in _positions(data)
        if isinstance(node, list) and node and all(isinstance(item, dict) and "kind" in item for item in node)
    ]
    mutants = []
    for steps in step_lists:
        by_seq = {step["seq"]: step for step in steps if _is_int(step.get("seq"))}
        for first, last in ranges:
            for seq in sorted(by_seq):
                model, tool = by_seq[seq], by_seq.get(seq + 1)
                if model.get("kind") != "MODEL" or tool is None or tool.get("kind") != "TOOL":
                    continue
                if not first <= seq < last:
                    continue
                if "consumes" in tool and not _consumes_names(tool["consumes"], model):
                    continue
                for field, value in (("rangeLastSeq", seq), ("rangeFirstSeq", seq + 1)):
                    mutant = copy.deepcopy(data)
                    targets = [
                        node
                        for node in _dicts(mutant)
                        if node.get("rangeFirstSeq") == first and node.get("rangeLastSeq") == last
                    ]
                    for node in targets:
                        node[field] = value
                    mutants.append(mutant)
    return mutants


def _checkpoint_mutants(data):
    """R08 note r3 C3: the COMPACT step names no archive of its range (and, where the case lists archives, none)."""
    if not any(isinstance(node.get("checkpointDigest"), str) for node in _dicts(data)):
        return []
    renamed = copy.deepcopy(data)
    holders = [node for node in _dicts(renamed) if isinstance(node.get("checkpointDigest"), str)]
    # CONTRACT_295 section 3a (COMPACT's detail): rename where the COMPACT step names its archive, if found apart.
    compact = [node for node in holders if node.get("kind") == "COMPACT" or any(key in node for key in _COMPACT_ONLY)]
    for node in compact or holders:
        node["checkpointDigest"] = _other_digest(node["checkpointDigest"])
    mutants = [renamed]
    emptied = copy.deepcopy(data)
    holders = [
        (node, key)
        for node in _dicts(emptied)
        for key, value in node.items()
        if "archive" in key.lower() and isinstance(value, list) and value
    ]
    for node, key in holders:
        node[key] = []
    if holders:
        mutants.append(emptied)
    return mutants


_WORD = re.compile(r"[A-Z]?[a-z]+|[A-Z]+(?![a-z])|[0-9]+")
_END_WORDS = frozenset({"close", "closed", "release", "released", "unlock", "unlocked", "end", "ended"})
_LATER_KINDS = frozenset({"MODEL", "TOOL", "DELEGATE", "HANDOFF"})


def _words(text):
    return {word.lower() for word in _WORD.findall(text)}


def _names_orphan(node):
    keys = list(node) if isinstance(node, dict) else []
    return any("orphan" in text.lower() for text in keys + _direct_strings(node))


def _is_lock_end(node):
    values = _direct_strings(node)
    keys = list(node) if isinstance(node, dict) else []
    lock = any({"lock", "unlock"} & _words(text) for text in keys + values)
    end = any(_END_WORDS & _words(text) for text in values)
    return lock and end


def _orphan_mutants(data):
    """R08 note r3 C1: an orphan lock left unhandled (its orphan report or restore removed), or a lock never
    closed while later MODEL, TOOL, DELEGATE or HANDOFF steps start."""
    mutants = []
    for position, node in list(_positions(data)):
        if isinstance(node, list):
            named = [index for index, item in enumerate(node) if _names_orphan(item)]
            if named:
                mutant = copy.deepcopy(data)
                target = _at(mutant, position)
                for index in reversed(named):
                    del target[index]
                mutants.append(mutant)
            for index, item in enumerate(node):
                later = node[index + 1:]
                if _is_lock_end(item) and any(isinstance(x, dict) and x.get("kind") in _LATER_KINDS for x in later):
                    mutant = copy.deepcopy(data)
                    del _at(mutant, position)[index]
                    mutants.append(mutant)
        elif isinstance(node, dict):
            for key, value in node.items():
                lowered = key.lower()
                replacement = None
                if "orphan" in lowered and _is_int(value) and value >= 1:
                    replacement = 0
                elif "orphan" in lowered and isinstance(value, list) and value:
                    replacement = []
                elif value is True and (
                    "restor" in lowered
                    or ("orphan" in lowered and any(word in lowered for word in ("detect", "report", "event")))
                ):
                    replacement = False
                if replacement is not None:
                    mutant = copy.deepcopy(data)
                    _at(mutant, position)[key] = replacement
                    mutants.append(mutant)
    return mutants


COMPACTION_NEGATIVES = (
    pytest.param("C3", _checkpoint_mutants, id="no-checkpoint"),  # R08 note r3 C3
    pytest.param("C1", _orphan_mutants, id="orphan-lock"),  # R08 note r3 C1
    pytest.param("C2", _range_mutants, id="unbalanced-range"),  # R08 note r3 C2
    pytest.param("C6", _drift_mutants, id="prompt-drift"),  # R08 note r3 C6
)


def test_compaction_codes_and_clause_vectors(compaction):
    """CONTRACT_295 section 3a (R08 note r3 section 3): nine rule families C1 to C9, one refusal code each, and at
    least one positive and one negative vector per clause (CONTRACT_295 section 3)."""
    assert dict(compaction.model.CODES) == COMPACTION_CODES  # operator-stated (CODES); CONTRACT_295 section 3a
    for case in compaction.cases:
        expect = case["expect"]
        if case["polarity"] == POSITIVE:
            # operator-stated A (an accepted case's expect is {"accept": true}, with "result" where the case states one)
            assert expect.get("accept") is True and set(expect) <= {"accept", "result"}, case["id"]
        else:
            assert set(expect) == {"refuse"}, case["id"]  # operator-stated A (a refused case's expect is {"refuse": code})
    assert {case["family"] for case in compaction.cases} == set(COMPACTION_CODES)  # CONTRACT_295 section 3a (C1 to C9)
    for family in COMPACTION_CODES:
        assert compaction.of("family", family), family  # CONTRACT_295 section 3 (a positive vector per clause)
        assert compaction.of("family", family, compaction.others), family  # CONTRACT_295 section 3 (a negative per clause)


def test_compaction_every_positive_accepted(compaction):
    """CONTRACT_295 section 3a, its oracle part: every positive vector is accepted by the era model."""
    assert compaction.positives  # CONTRACT_295 section 3a (positive vectors)
    for case in compaction.positives:
        code, _ = _compaction_eval(compaction, case["family"], case["input"])
        assert code is None, case["id"]  # CONTRACT_295 section 3a (every positive accepted); operator-stated (None)


def test_compaction_every_negative_refused_with_its_family_code(compaction):
    """CONTRACT_295 section 3a: each clause is one rule family with one refusal code, so each negative vector is
    refused with its family's code."""
    assert compaction.others  # CONTRACT_295 section 3a (negative vectors)
    for case in compaction.others:
        got = _compaction_eval(compaction, case["family"], case["input"])
        assert got == (COMPACTION_CODES[case["family"]], {}), case["id"]  # CONTRACT_295 section 3a; operator-stated


def test_compaction_c6_prompt_digest_recomputed(compaction):
    """CONTRACT_295 section 3a and R08 note r3 C6: for each MODEL step of the C6 positives, the prompt digest is
    recomputed here (sha256: and the hex SHA-256 of the prompt's UTF-8 bytes) and equals the model's digests."""
    recomputed = 0
    for case in compaction.of("family", "C6"):
        steps = case["input"]["steps"]
        mine = ["sha256:" + _sha(step["prompt"].encode("utf-8")) for step in steps if step["kind"] == "MODEL"]
        code, result = _compaction_eval(compaction, "C6", case["input"])
        assert code is None, case["id"]  # CONTRACT_295 section 3a (positive accepted)
        assert list(result["digests"]) == mine, case["id"]  # operator-stated (C6 result); CONTRACT_295 section 3a
        # operator-stated A (an accepted case's expect carries "result" only where the case states one)
        stated = (case["expect"].get("result") or {}).get("digests")
        if stated is not None:
            assert list(stated) == mine, case["id"]  # CONTRACT_295 section 3a (the digest is recomputed, not copied)
        recomputed += len(mine)
    assert recomputed >= 2  # R08 note r3 C6 (+ equal digests across MODEL steps: two MODEL steps at least)


@pytest.mark.parametrize(("family", "build"), COMPACTION_NEGATIVES)
def test_compaction_scope_negative_refused(compaction, family, build):
    """CONTRACT_295 section 3a, its oracle part (R08 note r3 C1, C2, C3 and C6): the scope's four negatives (no
    checkpoint, orphan lock, unbalanced range, prompt drift), each built here as a mutation of a deep copy of an
    accepted case of its family, are refused with that family's code."""
    built = 0
    for case in compaction.of("family", family):
        base, _ = _compaction_eval(compaction, family, case["input"])
        assert base is None, case["id"]  # CONTRACT_295 section 3a (the base is an accepted case)
        for mutant in build(case["input"]):
            got = tuple(compaction.model.evaluate(family, mutant))
            assert got == (COMPACTION_CODES[family], {}), case["id"]  # R08 note r3 C1/C2/C3/C6; operator-stated (code)
            built += 1
    assert built >= 1, family  # CONTRACT_295 section 3a (the scope's negative, built from an accepted case)


# ----------------------------------------------------------------------------------------------------------------
# Part 3: HR-REPLAY-FIXTURES-001 (CONTRACT_295 section 3b, R12 draft r4).
# ----------------------------------------------------------------------------------------------------------------


def _section6_after(task_id):
    """R12 draft r4 section 6: each task's expected after-tree."""
    if task_id == TASK_IDS[0]:
        return [{"path": "greeting.txt", "kind": "FILE", "digest": "sha256:" + HELLO_WORLD}]
    return [
        {"path": "bin/check.sh", "kind": "EXECUTABLE", "digest": "sha256:" + CHECK_SH},
        {"path": "greeting.txt", "kind": "FILE", "digest": "sha256:" + HELLO},
    ]


def _section6_mismatches(node, task_id):
    """The fields R12 draft r4 section 6 fixes for its fixture of task_id (fx-dev-0002 follows fx-dev-0001)."""
    wanted = {
        "schemaVersion": "planeon.internal.replay-fixture/v1",
        "taskId": task_id,
        "workspaceBefore": {"entries": [{"path": "greeting.txt", "kind": "FILE", "digest": "sha256:" + HELLO}]},
        "expectedAfter": {"entries": _section6_after(task_id)},
        "ignoredPaths": [],
        "requestMatch": "DIGEST",
    }
    bad = [key for key, value in wanted.items() if node.get(key) != value]
    split = node.get("split") if isinstance(node.get("split"), dict) else {}
    if split.get("partition") != "DEVELOPMENT":
        bad.append("split.partition")
    generator = node.get("generator") if isinstance(node.get("generator"), dict) else {}
    if (generator.get("id"), generator.get("version")) != ("fixture-builder", "1"):
        bad.append("generator")
    return bad


def _section6_fixtures(era):
    """Section 6's two fixtures, as the vector set's stores and accepted inputs carry them."""
    found = {}
    for fixture_id, task_id in zip(FIXTURE_IDS, TASK_IDS):
        candidates = [node for node in era.documents if node.get("fixtureId") == fixture_id]
        matching = {_jcs(node): node for node in candidates if not _section6_mismatches(node, task_id)}
        detail = [_section6_mismatches(node, task_id) for node in candidates[:3]]
        # R12 draft r4 section 6 (the fixture as drafted) and section 4.4 (one document per fixture id)
        assert len(matching) == 1, (fixture_id, len(candidates), detail)
        found[fixture_id] = next(iter(matching.values()))
    return found


def _blob_keys(era, authority):
    files = {"sha256:" + path[len(BLOB_PREFIX):] for path in authority["newFiles"] if path.startswith(BLOB_PREFIX)}
    return set(era.stores["blobs"]) | files


@pytest.mark.parametrize(("content", "hexdigest"), SECTION6_CONTENT)
def test_replay_section6_content_digest(head, authority, replay, content, hexdigest):
    """R12 draft r4 sections 2 and 6, CONTRACT_295 section 3b: each content bytesDigest is the SHA-256 of the
    content's raw bytes; a blob carrying it (a blob file, or the stores' blobs under its key) holds exactly those
    bytes; and the candidate's section-6 fixtures carry the draft's value."""
    assert _sha(content) == hexdigest  # R12 draft r4 section 6 (content digests are real bytesDigest values)
    path = BLOB_PREFIX + hexdigest
    if path in authority["newFiles"]:
        raw = head.reviewed_bytes(path)
        assert _sha(raw) == hexdigest and raw == content  # R12 draft r4 sections 2 and 6
    stored = replay.stores["blobs"].get("sha256:" + hexdigest)
    if stored is not None:
        assert stored.encode("utf-8") == content  # R12 draft r4 sections 2 and 6 (key = bytesDigest of the bytes)
    fixtures = _section6_fixtures(replay)
    carried = {
        entry["digest"]
        for fixture in fixtures.values()
        for tree in ("workspaceBefore", "expectedAfter")
        for entry in fixture[tree]["entries"]
    }
    assert "sha256:" + hexdigest in carried  # CONTRACT_295 section 3b (the content bytesDigest values stay the draft's)


def test_replay_blob_files_named_by_bytes_digest(head, authority, replay):
    """CONTRACT_295 section 3b and R12 draft r4 section 2: each blob file is named by the bytesDigest hex of its
    bytes and the stores hold it under that key; every stored blob's key is the bytesDigest of its bytes."""
    paths = [path for path in authority["newFiles"] if path.startswith(BLOB_PREFIX)]
    assert paths  # CONTRACT_295 section 3b (blobs/)
    for path in paths:
        name = path[len(BLOB_PREFIX):]
        raw = head.reviewed_bytes(path)
        assert _sha(raw) == name, path  # CONTRACT_295 section 3b (each file named by its bytesDigest hex)
        # operator-stated (the stores' blobs map sha256:<hex> to text); R12 draft r4 section 3.2 (blobs by bytesDigest)
        assert replay.stores["blobs"]["sha256:" + name].encode("utf-8") == raw, path
    for key, text in replay.stores["blobs"].items():
        assert key == "sha256:" + _sha(text.encode("utf-8")), key  # R12 draft r4 section 2 (bytesDigest, raw bytes)


def test_replay_section6_fixtures_as_drafted(replay):
    """R12 draft r4 section 6 and CONTRACT_295 section 3b: the two worked fixtures, DEVELOPMENT and keyless, with
    the draft's trees, ignoredPaths, requestMatch and generator; fx-dev-0002 starts from fx-dev-0001's before-tree."""
    fixtures = _section6_fixtures(replay)
    first, second = fixtures[FIXTURE_IDS[0]], fixtures[FIXTURE_IDS[1]]
    assert first["workspaceBefore"] == second["workspaceBefore"]  # R12 draft r4 section 6
    # R12 draft r4 section 6 (two entries, in byte order)
    assert [entry["path"] for entry in second["expectedAfter"]["entries"]] == ["bin/check.sh", "greeting.txt"]


def test_replay_section6_structural_digests_recomputed(authority, replay):
    """CONTRACT_295 section 3b (r5), R12 draft r4 sections 2, 3.1, 3.2, 3.4 and 6, and R12 erratum D1 section 2:
    section 6's structural digests, recomputed here with RFC 8785 from the fixtures' values: each t1 trajectory
    digest, the recording run M0's before-tree lock, the fixture set in the scored run M1's lock, and every JSON
    value the stores key by digest; the task, split and generator digests are computed digests shared as the
    draft's pattern says."""
    fixtures = _section6_fixtures(replay)
    first, second = fixtures[FIXTURE_IDS[0]], fixtures[FIXTURE_IDS[1]]
    for fixture in (first, second):
        named = (
            fixture["suiteDigest"],
            fixture["taskDigest"],
            fixture["split"]["declarationDigest"],
            fixture["trajectoryDigest"],
            fixture["generator"]["digest"],
        )
        for value in named:
            assert DIGEST_FORM.fullmatch(value), value  # R12 draft r4 section 2; CONTRACT_295 section 3b (computed at c1)
    assert first["suiteDigest"] == second["suiteDigest"]  # R12 draft r4 section 6 (fx-dev-0002 follows the pattern)
    assert first["split"] == second["split"]  # R12 draft r4 section 6 (one split fx-dev)
    assert first["generator"] == second["generator"]  # R12 draft r4 section 6 (one fixture builder)
    assert first["taskDigest"] != second["taskDigest"]  # R12 draft r4 section 6 (two tasks)
    blobs = _blob_keys(replay, authority)
    trajectories = []
    for fixture in (first, second):
        named = [
            node
            for node in replay.documents
            if "trajectoryId" in node and "manifest" in node and _digest(node) == fixture["trajectoryDigest"]
        ]
        assert named, fixture["fixtureId"]  # R12 draft r4 sections 3.1 and 6 (trajectoryDigest = digest(trajectory))
        trajectory = named[0]
        assert trajectory["taskId"] == fixture["taskId"]  # R12 draft r4 section 3.2 (one task per trajectory, F3)
        assert trajectory["trajectoryId"] == fixture["taskId"] + ".t1"  # R12 draft r4 section 6
        indexes = [step["index"] for step in trajectory["steps"]]
        assert indexes == list(range(1, len(indexes) + 1))  # R12 draft r4 section 3.2 (1..n with no gaps)
        assert {step["actor"] for step in trajectory["steps"]} <= {"MODEL", "TOOL"}  # R12 draft r4 section 3.2
        for step in trajectory["steps"]:
            if step["actor"] == "MODEL":
                assert step["responseDigest"] in blobs, step["index"]  # R12 draft r4 section 3.2 (answered from the blob)
        trajectories.append(trajectory)
    # R12 erratum D1 section 2: the recording run M0 writes both t1 trajectories, each embedding M0
    assert trajectories[0]["manifest"] == trajectories[1]["manifest"]  # R12 erratum D1 section 2 (one manifest per run)
    before_lock = _digest(sorted([_digest(first["workspaceBefore"]), _digest(second["workspaceBefore"])]))
    for trajectory in trajectories:
        assert trajectory["exit"]["status"] == "COMPLETED", trajectory["trajectoryId"]  # R12 erratum D1 section 2
        # R12 erratum D1 section 2 (M0's lock: digest of the sorted array of the two tasks' before-tree digests);
        # CONTRACT_295 section 3b (r5: the t1 trajectories carry M0's before-tree lock)
        assert trajectory["manifest"]["locks"]["fixtureDigest"] == before_lock, trajectory["trajectoryId"]
    fixture_set = _digest(sorted({_digest(first), _digest(second)}))
    scored = {}
    for task_id, status in ((TASK_IDS[0], "COMPLETED"), (TASK_IDS[1], "BUDGET_EXCEEDED")):
        scored[task_id] = [
            node
            for node in replay.documents
            if node.get("trajectoryId") == task_id + ".r1"
            and isinstance(node.get("manifest"), dict)
            and isinstance(node.get("exit"), dict)
            and node["exit"].get("status") == status
        ]
        assert scored[task_id], task_id  # R12 erratum D1 section 2 (fx-dev-0001.r1 COMPLETED, fx-dev-0002.r1 BUDGET_EXCEEDED)
    # both r1 trajectories embed the scored run's manifest M1, whose lock is digest(F) over the two fixtures:
    # R12 erratum D1 section 2 and draft r4 section 3.4; CONTRACT_295 section 3b (r5)
    assert any(
        left["manifest"] == right["manifest"] and left["manifest"]["locks"]["fixtureDigest"] == fixture_set
        for left in scored[TASK_IDS[0]]
        for right in scored[TASK_IDS[1]]
    )
    tasks = {_digest(first): first["taskId"], _digest(second): second["taskId"]}
    for node in replay.documents:
        for result in node.get("results") or []:
            if isinstance(result, dict) and result.get("fixtureDigest") in tasks:
                assert result.get("taskId") == tasks[result["fixtureDigest"]]  # R12 draft r4 sections 3.3 and 3.4
    for position, node in _positions(replay.stores):
        if position == ("blobs",) or not isinstance(node, dict) or not node:
            continue
        if all(isinstance(key, str) and DIGEST_FORM.fullmatch(key) for key in node):
            for key, value in node.items():
                if isinstance(value, (dict, list)):
                    assert key == _digest(value), key  # R12 draft r4 section 2 (digest(x) of a JSON value)


def _path_accepted(verdict):
    if isinstance(verdict, tuple):
        verdict = verdict[0]
    return bool(verdict)


@pytest.mark.parametrize("path", BAD_PATHS)
def test_replay_path_grammar_refuses(replay, path):
    """R12 draft r4 section 3.1 (path grammar, F1 (b)) and CONTRACT_295 section 3b: each named form is refused."""
    assert not _path_accepted(replay.model.path_ok(path))  # R12 draft r4 section 3.1


@pytest.mark.parametrize("path", GOOD_PATHS)
def test_replay_path_grammar_accepts_a_valid_path(replay, path):
    """R12 draft r4 sections 3.1 and 6: a valid path (up to 4,096 UTF-8 bytes) is accepted."""
    assert _path_accepted(replay.model.path_ok(path))  # R12 draft r4 sections 3.1 and 6


def _fixture_positions(data):
    return [
        position
        for position, node in _positions(data)
        if isinstance(node, dict) and "fixtureId" in node and isinstance(node.get("expectedAfter"), dict)
    ]


def _with_entry(fixture, entry):
    entries = fixture["expectedAfter"]["entries"] + [entry]
    fixture["expectedAfter"]["entries"] = sorted(entries, key=lambda item: item["path"].encode("utf-8"))


def _tree_escape(fixture):
    _with_entry(fixture, {"path": "../escape.sh", "kind": "EXECUTABLE", "digest": "sha256:" + CHECK_SH})


def _tree_prefix(fixture):
    head_entry = fixture["expectedAfter"]["entries"][0]
    _with_entry(fixture, {"path": head_entry["path"] + "/inner.txt", "kind": "FILE", "digest": "sha256:" + HELLO})


def _tree_case_fold(fixture):
    head_entry = fixture["expectedAfter"]["entries"][0]
    folded = dict(head_entry, path=head_entry["path"].upper())
    _with_entry(fixture, folded)


def _tree_ignored(fixture):
    fixture["ignoredPaths"] = [{"path": "../escape.sh", "reason": "oracle"}]


def _tree_order(fixture):
    fixture["expectedAfter"]["entries"] = fixture["expectedAfter"]["entries"] + [
        {"path": "aaa-first.txt", "kind": "FILE", "digest": "sha256:" + HELLO}
    ]


def _tree_held_out(fixture):
    fixture["split"]["partition"] = "HELD_OUT"


TREE_MUTATIONS = (
    pytest.param(_tree_escape, "TREE_PATH", id="path-mutant-escape"),  # R12 draft r4 sections 3.1 and 6
    pytest.param(_tree_prefix, "TREE_PATH", id="directory-prefix"),  # R12 draft r4 section 3.1
    pytest.param(_tree_case_fold, "TREE_PATH", id="case-fold-collision"),  # R12 draft r4 section 3.1
    pytest.param(_tree_ignored, "TREE_PATH", id="ignored-path-escape"),  # R12 draft r4 section 3.1
    pytest.param(_tree_order, "TREE_ORDER", id="unsorted-entries"),  # R12 draft r4 section 3.1
    pytest.param(_tree_held_out, "HELD_OUT_PUBLIC", id="held-out-public"),  # R12 draft r4 section 4.5
)


@pytest.mark.parametrize(("mutate", "code"), TREE_MUTATIONS)
def test_replay_tree_refusals_through_fixture_check(replay, mutate, code):
    """R12 draft r4 sections 3.1, 4.5 and 6 and CONTRACT_295 section 3b (record refusals first met first: shape,
    TREE_PATH, TREE_ORDER, HELD_OUT_PUBLIC): a mutation of a deep copy of an accepted FIXTURE case is refused
    with its code before anything is materialised."""
    built = 0
    for case in replay.of("check", "FIXTURE"):
        positions = _fixture_positions(case["input"])
        if not positions or not _at(case["input"], positions[0])["expectedAfter"].get("entries"):
            continue
        base, _ = _replay_eval(replay, "FIXTURE", case["input"])
        assert base is None, case["id"]  # CONTRACT_295 section 3b (an accepted base)
        mutant = copy.deepcopy(case["input"])
        mutate(_at(mutant, positions[0]))
        # R12 draft r4 sections 3.1 and 4.5; CONTRACT_295 section 3b (refusal codes, first met first)
        assert _replay_eval(replay, "FIXTURE", mutant) == (code, {}), case["id"]
        built += 1
    assert built >= 1  # CONTRACT_295 section 3b (accepted FIXTURE vectors)


def _score_results(data):
    return [
        position
        for position, node in _positions(data)
        if isinstance(node, dict) and {"exitStatus", "outcome", "score"} <= set(node)
    ]


def test_replay_accepted_results_follow_the_exit_map(replay):
    """R12 draft r4 section 3.3 and CONTRACT_295 section 3b (F2): every accepted scoring result follows the
    exit-to-outcome map, with the grader-error row, and its accepted positive vector is there."""
    results = [_at(case["input"], position) for case in replay.positives for position in _score_results(case["input"])]
    assert results  # CONTRACT_295 section 3b (scoring vectors)
    for result in results:
        status, outcome, score = result["exitStatus"], result["outcome"], result["score"]
        blocker = result.get("blockerCode")
        if status in ("ERRORED", "BUDGET_EXCEEDED"):
            assert (outcome, score) == ("ERRORED", 0)  # R12 draft r4 section 3.3 (ERRORED 0; BUDGET_EXCEEDED -> ERRORED 0)
        elif status == "BLOCKED":
            assert (outcome, score) == ("BLOCKED", 0)  # R12 draft r4 section 3.3
            assert blocker in ENVIRONMENT_CAUSES  # CONTRACT_295 section 3b (BLOCKED exit -> an environment cause)
        else:
            assert status == "COMPLETED"  # R12 draft r4 section 3.2 (four exit statuses)
            assert outcome in ("PASSED", "FAILED", "BLOCKED")  # R12 draft r4 section 3.3; CONTRACT_295 section 3b (F2)
            if outcome == "PASSED":
                assert score == FULL_SCORE  # R12 draft r4 section 3.3 (PASSED 1,000,000)
            elif outcome == "FAILED":
                assert 0 <= score <= FULL_SCORE - 1  # R12 draft r4 section 3.3 (FAILED 0 to 999,999)
            else:
                assert (score, blocker) == (0, EVALUATOR_CAUSE)  # CONTRACT_295 section 3b (F2's grader-error row)
        assert (blocker is not None) == (outcome == "BLOCKED")  # R12 draft r4 section 3.3 (when, and only when)
    grader = [
        result
        for result in results
        if (result["exitStatus"], result["outcome"], result["score"], result.get("blockerCode"))
        == ("COMPLETED", "BLOCKED", 0, EVALUATOR_CAUSE)
    ]
    assert grader  # CONTRACT_295 section 3b (F2: the grader-error row's positive vector)


SCORE_MUTATIONS = (
    # R12 draft r4 section 3.3: ERRORED (and BUDGET_EXCEEDED) score 0
    pytest.param(lambda r: r["outcome"] == "ERRORED", {"score": 1}, id="errored-scores-0"),
    # R12 draft r4 section 3.3: FAILED is 0 to 999,999, so it never reaches 1,000,000
    pytest.param(
        lambda r: r["outcome"] in ("PASSED", "FAILED"), {"outcome": "FAILED", "score": FULL_SCORE}, id="failed-below-full"
    ),
    # R12 draft r4 section 3.3: PASSED is 1,000,000
    pytest.param(lambda r: r["outcome"] == "PASSED", {"score": FULL_SCORE - 1}, id="passed-at-full-only"),
    # R12 draft r4 section 3.3: PASSED only on a matching tree (a COMPLETED run whose trees match)
    pytest.param(
        lambda r: r["outcome"] in ("ERRORED", "FAILED"),
        {"outcome": "PASSED", "score": FULL_SCORE},
        id="passed-on-matching-tree-only",
    ),
    # CONTRACT_295 section 3b (F2): the grader-error row is BLOCKED with score 0
    pytest.param(lambda r: r.get("blockerCode") == EVALUATOR_CAUSE, {"score": 1}, id="grader-error-row-blocked-0"),
)


@pytest.mark.parametrize(("select", "change"), SCORE_MUTATIONS)
def test_replay_score_map_mutation_refused(replay, select, change):
    """R12 draft r4 section 3.3 and CONTRACT_295 section 3b (F2): ERRORED 0; FAILED 0 to 999,999; PASSED only on
    a matching tree, at 1,000,000; the grader-error row BLOCKED, 0. A result moved off the map in a deep copy of
    an accepted SCORE case is OUTCOME_MISMATCH."""
    built = 0
    for case in replay.of("check", "SCORE"):
        for position in _score_results(case["input"]):
            if not select(_at(case["input"], position)):
                continue
            mutant = copy.deepcopy(case["input"])
            _at(mutant, position).update(change)
            # R12 draft r4 section 3.3 (a result off the map is OUTCOME_MISMATCH); operator-stated ((code, {}))
            assert _replay_eval(replay, "SCORE", mutant) == ("OUTCOME_MISMATCH", {}), case["id"]
            built += 1
    assert built >= 1  # CONTRACT_295 section 3b (accepted SCORE vectors carry the row)


def _cited_trajectory(stores, data):
    """operator-stated D: (stores key, position of the map that holds it) of the trajectory a case cites by key."""
    cited = [text for text in _strings(data) if DIGEST_FORM.fullmatch(text)]
    maps = [(position, node) for position, node in _positions(stores) if isinstance(node, dict)]
    for key in cited:
        for position, node in maps:
            value = node.get(key)
            if isinstance(value, dict) and "trajectoryId" in value and isinstance(value.get("exit"), dict):
                return key, position
    return None


def _recite(data, old, new):
    """A deep copy of data citing the stores key new wherever it cited old (operator-stated D)."""
    return json.loads(json.dumps(data).replace(json.dumps(old), json.dumps(new)))


def test_replay_trajectory_exit_codes_closed(replay):
    """CONTRACT_295 section 3b: the trajectory exit.code closed list per status holds for every accepted
    trajectory; EVALUATOR_ERROR as an exit code (F2), and codes off their status's list, are refused."""
    exits = [node["exit"] for node in replay.documents if "trajectoryId" in node and isinstance(node.get("exit"), dict)]
    assert exits  # CONTRACT_295 section 3b (trajectories in the vectors)
    for exit_record in exits:
        assert exit_record["code"] in EXIT_CODES[exit_record["status"]], exit_record  # CONTRACT_295 section 3b
    built = 0
    for case in replay.of("check", "TRAJECTORY"):
        cited = _cited_trajectory(replay.stores, case["input"])
        assert cited is not None, case["id"]  # operator-stated D (an accepted TRAJECTORY case cites a stores key)
        key, holder = cited
        for status, code in (("BLOCKED", EVALUATOR_CAUSE), ("COMPLETED", "AGENT_ERROR"), ("ERRORED", "DONE")):
            # operator-stated D: the mutated trajectory goes into a copy of the stores under its own digest
            # (R12 draft r4 section 2), and the case cites that key in place of the old one
            stores = copy.deepcopy(replay.stores)
            trajectory = copy.deepcopy(_at(replay.stores, holder)[key])
            trajectory["exit"] = {"status": status, "code": code}
            new_key = _digest(trajectory)
            _at(stores, holder)[new_key] = trajectory
            data = _recite(case["input"], key, new_key)
            got, result = tuple(replay.model.evaluate("TRAJECTORY", data, stores, replay.rm))
            assert got is not None and result == {}, (case["id"], status, code)  # CONTRACT_295 section 3b (F2)
            built += 1
    assert built >= 1  # CONTRACT_295 section 3b (F2: a trajectory whose exit.code is EVALUATOR_ERROR is refused)


def test_replay_vectors_cover_codes_and_verdicts(replay):
    """CONTRACT_295 section 3b: one vector per record refusal code and per verdict; REPLAY_DIVERGED and
    TREE_MISMATCH are replay verdicts, never record refusals (N1)."""
    assert {case["check"] for case in replay.cases} <= REPLAY_CHECKS  # operator-stated (the model's checks)
    refused = {case["expect"]["refuse"] for case in replay.others}
    assert set(RECORD_CODES) <= refused, sorted(set(RECORD_CODES) - refused)  # CONTRACT_295 section 3b
    assert not refused & set(VERDICTS)  # CONTRACT_295 section 3b (N1: verdicts are not record refusals)
    named = {text for case in replay.positives for text in _strings([case["input"], case["expect"]])}
    for verdict in VERDICTS:
        assert verdict in named, verdict  # CONTRACT_295 section 3b (one vector per verdict); R12 draft r4 section 3.6


def test_replay_vectors_accepted_and_refused(replay):
    """CONTRACT_295 section 3b: every positive vector is accepted by the era model and every negative refused."""
    assert replay.positives and replay.others  # CONTRACT_295 section 3b (vectors of both kinds)
    for case in replay.positives:
        assert _replay_eval(replay, case["check"], case["input"])[0] is None, case["id"]  # CONTRACT_295 section 3b
    for case in replay.others:
        code, result = _replay_eval(replay, case["check"], case["input"])
        assert code is not None and result == {}, case["id"]  # CONTRACT_295 section 3b; operator-stated ((code, {}))


# ----------------------------------------------------------------------------------------------------------------
# Part 4: HR-APPROVAL-OUTCOME-001 (CONTRACT_295 section 3c, R04 note r3).
# ----------------------------------------------------------------------------------------------------------------


def test_approval_outcome_set_closed(approval):
    """CONTRACT_295 section 3c and R04 note r3 O1 and O2: the outcome set is the five terminal outcomes (beside the
    open state REQUESTED), and of the five only APPROVED permits the effect."""
    # CONTRACT_295 section 3c (O1's closed set: the five terminal outcomes and REQUESTED); R04 note r3 section 1
    assert set(approval.model.OUTCOMES) - {REQUESTED_STATE} == TERMINAL_OUTCOMES
    assert approval.model.permits("APPROVED")  # R04 note r3 O2 (only APPROVED permits the effect)
    for outcome in sorted(TERMINAL_OUTCOMES - {"APPROVED"}) + [REQUESTED_STATE]:
        assert not approval.model.permits(outcome), outcome  # R04 note r3 O2; CONTRACT_295 section 3c


@pytest.mark.parametrize("value", OUTSIDE_VALUES, ids=[f"outside-{i:02d}" for i in range(len(OUTSIDE_VALUES))])
def test_approval_value_outside_the_set_never_permits(approval, value):
    """CONTRACT_295 section 3c (no value outside the set maps to APPROVED) and R04 note r3 O1 and N-5."""
    assert value not in set(approval.model.OUTCOMES)  # R04 note r3 O1 (a closed set of six)
    assert not approval.model.permits(value)  # R04 note r3 O1 and N-5; CONTRACT_295 section 3c


def _statement_bases(era):
    bases = []
    for case in era.of("check", "STATEMENTS"):
        for node in _dicts(case["input"]):
            if {"statements", "layers", "action"} <= set(node):
                bases.append((case["id"], node))
                break
    return bases


def _flat_statements(statements):
    """(holder list, index) of every statement, in evaluation order."""
    if isinstance(statements, list):
        return [(statements, index) for index, item in enumerate(statements) if isinstance(item, dict)]
    if isinstance(statements, dict):
        return [pair for value in statements.values() for pair in _flat_statements(value)]
    return []


def _deny_key(statement):
    keys = [key for key, value in statement.items() if isinstance(value, str) and value.upper() in ("DENY", "DENIED")]
    return keys[0] if keys else None


def _is_deny(decision):
    text = json.dumps(decision, sort_keys=True, default=str).upper()
    return "DENY" in text or "DENIED" in text


def _is_tool_statement(statement):
    keyed = any("tool" in key.lower() and value not in (None, "", [], {}) for key, value in statement.items())
    return keyed or any("tool" in text.lower() for text in _direct_strings(statement))


def _effect_token(bases, key, word):
    """The vectors' own spelling of an effect word (ALLOW or ASK) under the statements' effect field."""
    seen = set()
    for _, node in bases:
        for holder, index in _flat_statements(node["statements"]):
            value = holder[index].get(key)
            if isinstance(value, str):
                seen.add(value)
    exact = sorted(value for value in seen if value.upper() == word)
    if exact:
        return exact[0]
    return word.lower() if seen and all(value == value.lower() for value in seen) else word


def test_approval_later_statement_never_lifts_a_deny(approval):
    """CONTRACT_295 section 3c (the statement order holds) and R04 note r3 S2 and S4 (N-8): through
    evaluate_statements, a later statement allowing the same action never lifts an earlier deny; the deny still
    decides, and the same statement is named."""
    bases = _statement_bases(approval)
    assert bases  # operator-stated (evaluate_statements(statements, layers, action)); CONTRACT_295 section 3c
    built = 0
    for case_id, node in bases:
        before = approval.model.evaluate_statements(
            copy.deepcopy(node["statements"]), copy.deepcopy(node["layers"]), copy.deepcopy(node["action"])
        )
        if not _is_deny(before["decision"]):
            continue
        statements = copy.deepcopy(node["statements"])
        flat = _flat_statements(statements)
        denies = sorted(
            ((holder, index) for holder, index in flat if _deny_key(holder[index])),
            key=lambda pair: _is_tool_statement(pair[0][pair[1]]),
        )
        if not denies:
            continue
        holder, index = denies[0]
        key = _deny_key(holder[index])
        later = copy.deepcopy(holder[index])
        # R04 note r3 S1 and S3: a later statement may allow (a tool-use statement may only ask), never lift a deny.
        later[key] = _effect_token(bases, key, "ASK" if _is_tool_statement(later) else "ALLOW")
        for field in ("id", "statementId"):
            if isinstance(later.get(field), str):
                later[field] = later[field] + "-later-allow"
        layers = node["layers"]
        if isinstance(layers, list) and layers and all(isinstance(layer, str) for layer in layers):
            for field, value in list(later.items()):
                if isinstance(value, str) and value in layers:
                    later[field] = layers[-1]
        flat[-1][0].append(later)
        after = approval.model.evaluate_statements(statements, copy.deepcopy(layers), copy.deepcopy(node["action"]))
        assert after["decision"] == before["decision"], case_id  # R04 note r3 S2 (any DENY is final)
        assert after["statement"] == before["statement"], case_id  # R04 note r3 S2 and S4 (the deny decides, named)
        built += 1
    assert built >= 1  # CONTRACT_295 section 3c (the statement order deciding); R04 note r3 S2


def _refs(case):
    return _strings(case.get("refs", case.get("ref", [])))


def _names_ref(texts, ref):
    pattern = re.compile(r"(?<![A-Za-z0-9])" + re.escape(ref) + r"(?![0-9])")
    return any(pattern.search(text) for text in texts)


@pytest.mark.parametrize("ref", IN_SCOPE_NEGATIVES)
def test_approval_in_scope_negative_refused(approval, ref):
    """CONTRACT_295 section 3c and R04 note r3 section 5 (and R2-N1): each in-scope negative is named by a vector's
    refs, and every negative vector naming it is refused by the era model."""
    named = [case for case in approval.cases if _names_ref(_refs(case), ref)]
    negatives = [case for case in named if case["polarity"] != POSITIVE]
    assert negatives, ref  # CONTRACT_295 section 3c (N-1 to N-6 and N-8 to N-12 each refused; R2-N1's vector)
    for case in negatives:
        code, result = _approval_eval(approval, case["check"], case["input"])
        assert code is not None and result == {}, case["id"]  # R04 note r3 section 5; operator-stated ((code, {}))


def test_approval_out_of_scope_negatives_have_no_vector(approval):
    """CONTRACT_295 sections 1 and 3c: N-7, N-13 and R2-N2's vector wait for the trigger packet's gate."""
    for ref in OUT_OF_SCOPE:
        named = [case["id"] for case in approval.cases if _names_ref(_refs(case), ref)]
        assert named == [], ref  # CONTRACT_295 section 3c (Out: N-7 and N-13; R2-N2's vector out)


def test_approval_vectors_accepted_and_refused(approval):
    """CONTRACT_295 section 3c: every positive vector is accepted by the era model and every negative refused."""
    assert {case["check"] for case in approval.cases} <= APPROVAL_CHECKS  # operator-stated (the model's checks)
    assert approval.positives and approval.others  # CONTRACT_295 section 3c (positives per family; N-k refused)
    for case in approval.positives:
        assert _approval_eval(approval, case["check"], case["input"])[0] is None, case["id"]  # CONTRACT_295 section 3c
    for case in approval.others:
        code, result = _approval_eval(approval, case["check"], case["input"])
        assert code is not None and result == {}, case["id"]  # CONTRACT_295 section 3c; operator-stated ((code, {}))


# ----------------------------------------------------------------------------------------------------------------
# Part 5: the head layer (CONTRACT_295 sections 4 and 4a): V1, E1, E2, E3, V4, V6 and the entry.
# ----------------------------------------------------------------------------------------------------------------


def test_v1_packet_files(head):
    """CONTRACT_295 section 4a (V1) and section 7 (c1's added files): the packet files pass on the live inputs;
    the check refuses a changed byte and a missing file."""
    head.validate_packet_files()  # operator-stated: passes on the live inputs
    files = {path: head.reviewed_bytes(path) for path in head.PACKET_FILES}
    assert YAML_PATH not in files  # operator-stated (c1's added files but the packet YAML)
    for record, vectors in MEMBER_PATHS.values():
        assert record in files and vectors in files  # CONTRACT_295 section 7 (c1 adds the three members' files)
    assert head.check_packet_files(dict(files)) is None  # operator-stated
    path = next(name for name in sorted(files) if files[name])
    with pytest.raises(ValueError, match="MET-013"):  # operator-stated (V1: a packet file's byte changed)
        head.check_packet_files({**files, path: _flip_byte(files[path])})
    missing = dict(files)
    del missing[path]
    with pytest.raises(ValueError, match="MET-013"):  # operator-stated (V1: a file missing)
        head.check_packet_files(missing)


def _replayed(era, item):
    if item == "HR-REPLAY-FIXTURES-001":
        return list(era.model.replay_vectors(copy.deepcopy(era.cases), copy.deepcopy(era.stores), era.rm))
    return [era.model.replay(copy.deepcopy(case))[0] for case in era.cases]


@pytest.mark.parametrize("item", MEMBER_ITEMS)
def test_e1_member(request, head, packets, item):
    """CONTRACT_295 section 4a (E1, one per member): the member passes on the live inputs (its record passes its
    era checker with no refusal and every vector replays to its expected result); its check refuses a non-empty
    refusal list, one False in replayed and a replayed shorter than the cases."""
    check_name, validate_name, fixture_name = E1_FUNCTIONS[item]
    era = request.getfixturevalue(fixture_name)
    getattr(head, validate_name)(copy.deepcopy(packets))  # operator-stated: passes on the live inputs
    assert list(era.checker.check(head._era_read)) == []  # CONTRACT_295 section 4a (no refusal); operator-stated
    replayed = _replayed(era, item)
    assert len(replayed) == len(era.cases) and all(replayed)  # CONTRACT_295 section 4a (each its expected result)
    check = getattr(head, check_name)
    assert check(copy.deepcopy(era.vectors), [], list(replayed)) is None  # operator-stated
    with pytest.raises(ValueError, match="MET-013"):  # operator-stated (E1: a non-empty refusal list)
        check(copy.deepcopy(era.vectors), [("ORACLE_REFUSAL", "an injected refusal")], list(replayed))
    with pytest.raises(ValueError, match="MET-013"):  # operator-stated (E1: one False in replayed)
        check(copy.deepcopy(era.vectors), [], [False] + list(replayed[1:]))
    with pytest.raises(ValueError, match="MET-013"):  # operator-stated (E1: a replayed shorter than the cases)
        check(copy.deepcopy(era.vectors), [], list(replayed[:-1]))


def _is_base_path(path):
    return path.startswith(BASE_PREFIXES) or path in BASE_SCRIPTS


def test_e2_base_files(head, authority):
    """CONTRACT_295 sections 1 and 4a (E2): MAS-RA-008's and MAS-RA-002's files equal their base bytes and the
    authority names none of them; the check refuses a changed byte and a base file named in changedFiles or
    newFiles."""
    head.validate_base_files()  # operator-stated: passes on the live inputs
    base = list(head.BASE_FILES)
    assert set(BASE_SCRIPTS) <= set(base)  # CONTRACT_295 section 1 (scripts/agent_loop.py, scripts/run_manifest.py)
    assert all(_is_base_path(path) for path in base)  # CONTRACT_295 sections 1 and 4a (only those two contracts' files)
    for prefix in BASE_PREFIXES:
        assert any(path.startswith(prefix) for path in base), prefix  # CONTRACT_295 section 1 (both folders)
    changed, new = authority["changedFiles"], authority["newFiles"]
    assert not [path for path in [*changed, *new] if _is_base_path(path)]  # CONTRACT_295 section 1 (no byte of either)
    files = {path: head.reviewed_bytes(path) for path in base}
    assert head.check_base_files(dict(files), copy.deepcopy(changed), copy.deepcopy(new)) is None  # operator-stated
    path = next(name for name in sorted(files) if files[name])
    with pytest.raises(ValueError, match="MET-013"):  # operator-stated (E2: a base file's byte changed)
        head.check_base_files({**files, path: _flip_byte(files[path])}, copy.deepcopy(changed), copy.deepcopy(new))
    named = copy.deepcopy(changed)
    named[path] = copy.deepcopy(next(iter(changed.values()), {"beforeSha256": "0" * 64, "afterSha256": "1" * 64}))
    with pytest.raises(ValueError, match="MET-013"):  # operator-stated (E2: a base file named in changed)
        head.check_base_files(dict(files), named, copy.deepcopy(new))
    listed = copy.deepcopy(new)
    listed[path] = next(iter(new.values()), "0" * 64)
    with pytest.raises(ValueError, match="MET-013"):  # CONTRACT_295 section 4a (E2: named in newFiles)
        head.check_base_files(dict(files), copy.deepcopy(changed), listed)


def _class_place(inner):
    """True where a per-file value holds a class word: the value itself, a list item, or a field named for it."""
    keys = [step for step in inner if isinstance(step, str)]
    return not keys or "class" in keys[-1].lower()


def _class_slots(classes, changed):
    """(position in classes, file) of each class word the hunk-class record gives a changed file."""
    slots = {}
    for position, node in _positions(classes):
        if not isinstance(node, dict):
            continue
        if any(key in changed for key in node):
            for file, value in node.items():
                if file not in changed:
                    continue
                for inner, leaf in _positions(value):
                    if isinstance(leaf, str) and _class_place(inner):
                        slots[position + (file,) + inner] = file
            continue
        files = [value for value in node.values() if isinstance(value, str) and value in changed]
        if not files:
            continue
        for key, value in node.items():
            if "class" not in key.lower():
                continue
            if isinstance(value, str):
                slots[position + (key,)] = files[0]
            elif isinstance(value, list):
                for index, item in enumerate(value):
                    if isinstance(item, str):
                        slots[position + (key, index)] = files[0]
    return list(slots.items())


def _class_word(classes, word):
    return next((leaf for _, leaf in _positions(classes) if isinstance(leaf, str) and leaf.lower() == word), word)


def _set_at(document, position, value):
    _at(document, position[:-1])[position[-1]] = value


def test_e3_errata(head, authority):
    """CONTRACT_295 section 4a (E3, ledger-free form): the errata pass on the live inputs; the check refuses an
    `other` class on a file outside ERRATA_LINES."""
    head.validate_errata()  # operator-stated: passes on the live inputs
    assert head.HUNK_RECORD_PATH == HUNK_CLASS_PATH  # CONTRACT_295 section 4 (the ledger's hunk-class record)
    record = json.loads(head.reviewed_bytes(head.HUNK_RECORD_PATH))
    changed = authority["changedFiles"]
    befores = {path: head._undo_this_layer(path, head.reviewed_bytes(path)) for path in head.ERRATA_LINES}
    # operator-stated (check_errata returns None on the live inputs)
    assert head.check_errata(copy.deepcopy(record["classes"]), copy.deepcopy(changed), dict(befores)) is None
    slots = _class_slots(record["classes"], changed)
    outside = [(position, file) for position, file in slots if file not in head.ERRATA_LINES]
    assert outside  # operator-stated (E3's mutation: a class on a file outside ERRATA_LINES)
    classes = copy.deepcopy(record["classes"])
    _set_at(classes, outside[0][0], _class_word(record["classes"], "other"))
    with pytest.raises(ValueError, match="MET-013"):  # operator-stated (E3: an other class outside ERRATA_LINES)
        head.check_errata(classes, copy.deepcopy(changed), dict(befores))


def _registry_entries(document):
    if isinstance(document, list):
        return document
    lists = [
        value
        for value in document.values()
        if isinstance(value, list) and value and all(isinstance(item, dict) for item in value)
    ]
    assert len(lists) == 1  # operator-stated (the registry holds one list of entries)
    return lists[0]


def _names_rider(entry):
    texts = _strings(entry)
    return RIDER in texts or any(RIDER in text for text in texts) or ("MET-013" in texts and "packet" in texts)


def test_v4_registry(head):
    """CONTRACT_295 sections 1, 4a and 5 (V4): the registry is the base plus the one MET-013/packet rider, 42
    entries with the rider last; the check refuses a registry without the rider, with it twice, or renamed."""
    head.validate_registry()  # operator-stated: passes on the live inputs
    assert head.REGISTRY_PATH == REGISTRY_PATH  # CONTRACT_295 section 5 (the rider's registry)
    raw = head.reviewed_bytes(head.REGISTRY_PATH)
    briefs = {head.PACKET_BRIEF: head.reviewed_bytes(head.PACKET_BRIEF)}
    assert head.check_registry(raw, dict(briefs)) is None  # operator-stated
    document = json.loads(raw)
    entries = _registry_entries(document)
    assert len(entries) == REGISTRY_ENTRIES  # CONTRACT_295 sections 1 and 5 (41 -> 42); operator-stated
    assert _names_rider(entries[-1])  # CONTRACT_295 sections 1 and 5 (the MET-013/packet rider, last)
    mentions = [entry for entry in entries if any("MET-013" in text for text in _strings(entry))]
    assert len(mentions) == 1  # CONTRACT_295 section 1 (one in-tree review series)
    dump = _dump_like(document, raw)
    dropped = copy.deepcopy(document)
    _registry_entries(dropped).pop()
    doubled = copy.deepcopy(document)
    _registry_entries(doubled).append(copy.deepcopy(_registry_entries(doubled)[-1]))
    renamed = copy.deepcopy(document)
    renamed_entries = _registry_entries(renamed)
    renamed_entries[-1] = json.loads(json.dumps(renamed_entries[-1]).replace("MET-013", "MET-014"))
    for mutant in (dropped, doubled, renamed):
        with pytest.raises(ValueError, match="MET-013"):  # operator-stated (V4: not the base plus the one rider)
            head.check_registry(dump(mutant), dict(briefs))


def _field(context, name):
    return context[name] if isinstance(context, dict) else getattr(context, name)


def _with_field(context, name, value):
    if isinstance(context, dict):
        mutated = copy.deepcopy(context)
        mutated[name] = value
        return mutated
    return context._replace(**{name: value})


def _v6_inputs(head, authority):
    raw = head.reviewed_bytes(head.HUNK_RECORD_PATH)
    record = json.loads(raw)
    changed = copy.deepcopy(authority["changedFiles"])
    afters = {path: head.reviewed_bytes(path) for path, entry in changed.items() if entry["reverseHunks"]}
    classify = head._era_rule(head.READER_PATH, head.READER_NAME).classify
    context = head._v24_context(copy.deepcopy(authority), record["hunkClassContext"])
    return raw, record, changed, afters, classify, context


def _v6_variants(kind, raw, record, context, rule_sha, changed):
    """Plain-data mutations of V6's inputs, one kind at a time: (raw, context, rule_sha) triples."""
    dump = _dump_like(record, raw)
    if kind == "closed-members":
        mutated = copy.deepcopy(record)
        mutated["oracleExtraMember"] = 1
        return [(dump(mutated), context, rule_sha)]
    if kind == "no-outcome-statement":
        mutated = copy.deepcopy(record)
        mutated["outcome"] = "PASS"
        return [(dump(mutated), context, rule_sha)]
    if kind == "vocabulary":
        slots = _class_slots(record["classes"], changed)
        if not slots:
            return []
        mutated = copy.deepcopy(record)
        _set_at(mutated, ("classes",) + slots[0][0], "oracle-unknown-class")
        return [(dump(mutated), context, rule_sha)]
    if kind == "rule-digest":
        variants = [(raw, context, _flip_last(rule_sha))]
        hexpart = rule_sha.split(":")[-1]
        for position, leaf in _positions(record):
            if position and isinstance(leaf, str) and hexpart in leaf:
                mutated = copy.deepcopy(record)
                _set_at(mutated, position, leaf.replace(hexpart, _flip_last(hexpart)))
                variants.append((dump(mutated), context, rule_sha))
                break
        return variants
    # operator-stated E: check_hunk_record compares the record's hunkClassContext (steps [1, 1], countPairs []);
    # the mutation goes into the record's bytes, and the context stays the one built from the live record
    mutated = copy.deepcopy(record)
    if kind == "k0-steps":
        mutated["hunkClassContext"]["steps"] = list(K3_STEPS)
    else:
        mutated["hunkClassContext"]["countPairs"] = [[BASE_PACKETS, CATALOG_PACKETS]]
    return [(dump(mutated), context, rule_sha)]


def test_v6_hunk_record(head, authority):
    """CONTRACT_295 section 4a (V6, MET-012's form): the hunk-class record passes on the live inputs; at K = 0
    the record's hunkClassContext holds steps [1, 1] and countPairs [] (operator-stated E)."""
    head.validate_hunk_record()  # operator-stated: passes on the live inputs
    raw, record, changed, afters, classify, context = _v6_inputs(head, authority)
    # operator-stated (check_hunk_record returns None on the live inputs)
    assert head.check_hunk_record(raw, changed, afters, classify, context, head.HUNK_RULE_SHA256) is None
    hunk_context = record["hunkClassContext"]
    assert list(hunk_context["steps"]) == K0_STEPS  # operator-stated E; CONTRACT_295 section 4a (steps [1, 1] at K 0)
    assert list(hunk_context["countPairs"]) == []  # operator-stated E (K = 0: countPairs [] in the hunkClassContext)


@pytest.mark.parametrize("kind", V6_KINDS)
def test_v6_hunk_record_mutation_refused(head, authority, kind):
    """CONTRACT_295 section 4a (V6, MET-012's form): the check refuses a record outside its closed members, a class
    outside its vocabulary, another rule digest than v2.5's, steps other than [1, 1] (K = 0), countPairs other
    than [] and an outcome statement."""
    raw, record, changed, afters, classify, context = _v6_inputs(head, authority)
    variants = _v6_variants(kind, raw, record, context, head.HUNK_RULE_SHA256, changed)
    assert variants, kind  # operator-stated (V6 checks this part of its inputs)
    for mutated_raw, mutated_context, rule_sha in variants:
        with pytest.raises(ValueError, match="MET-013"):  # operator-stated (V6's checks); CONTRACT_295 section 4a
            head.check_hunk_record(mutated_raw, copy.deepcopy(changed), dict(afters), classify, mutated_context, rule_sha)


def test_entry_passes(head, packets):
    """CONTRACT_295 section 4a (the entry: era files, V1, E1 per member in section 1's order, E2, E3, V4, V6,
    canonical hunks): it passes on the live inputs, as do the canonical hunks alone."""
    head.validate_canonical_hunks()  # operator-stated: passes on the live inputs
    head.validate_met_013(copy.deepcopy(packets))  # operator-stated: passes on the live inputs


# ----------------------------------------------------------------------------------------------------------------
# Part 6: the packet YAML, the catalog, the table and the registry (CONTRACT_295 sections 1, 4, 5 and 6).
# ----------------------------------------------------------------------------------------------------------------


def test_packet_yaml(head):
    """CONTRACT_295 sections 1 and 5: MET-013.yaml's id, its predecessor MET-012, the objective's three roadmap ids
    and step words, and the contracts line naming the accepted base; 16 keys, each on one line."""
    raw = head.reviewed_bytes(YAML_PATH)
    document = head.safe_load(raw)
    lines = raw.decode("utf-8").splitlines()
    assert len(document) == YAML_KEYS and len(lines) == YAML_KEYS  # operator-stated (16 keys, each on one line)
    for line in lines:
        key, separator, value = line.partition(": ")
        assert separator and json.loads(value) == document[key], key  # operator-stated (key: <JSON value>)
    assert document["id"] == "MET-013"  # CONTRACT_295 section 1
    assert document["predecessors"] == ["MET-012"]  # CONTRACT_295 section 5
    assert document["contracts"][0].startswith(BASE_SENTENCE)  # CONTRACT_295 section 5 (the contracts line)
    for item in MEMBER_ITEMS:
        assert item in document["objective"], item  # CONTRACT_295 section 5 (the objective names the three ids)
    assert OBJECTIVE_STEP in document["objective"]  # CONTRACT_295 section 5


def test_packet_yaml_allowed_paths(head, authority):
    """CONTRACT_295 section 5: allowedPaths are exactly the authority's changedFiles and newFiles plus the
    authority record, scripts/validate_met_013.py and task-packets/MET-013.yaml."""
    document = head.safe_load(head.reviewed_bytes(YAML_PATH))
    allowed = document["allowedPaths"]
    wanted = set(authority["changedFiles"]) | set(authority["newFiles"]) | {head.AUTHORITY_PATH, HEAD_REPO_PATH, YAML_PATH}
    assert set(allowed) == wanted  # CONTRACT_295 section 5 (allowedPaths)
    assert len(allowed) == len(set(allowed))  # CONTRACT_295 section 5 (exactly)


def test_authority_k0_form(authority):
    """CONTRACT_295 section 4: the authority record has no productPackets or productComparators member (K 0)."""
    assert "productPackets" not in authority  # CONTRACT_295 section 4; operator-stated
    assert "productComparators" not in authority  # CONTRACT_295 section 4; operator-stated


def test_historical_catalog(head, authority, catalog, packets):
    """CONTRACT_295 section 1 (318 -> 319 at K 0): the whole catalog less MET-013 is exactly the 318 base ids,
    each base YAML equal to the bytes the authority pins; a mapping that lacks or adds an id is refused."""
    base = set(authority["baselinePackets"])
    assert len(base) == BASE_PACKETS  # CONTRACT_295 section 1 (318 packets)
    assert head.NEW_PACKET not in base and "MET-012" in base  # CONTRACT_295 sections 1 and 5
    assert len(packets) == CATALOG_PACKETS  # CONTRACT_295 section 1 (318 + 1 + K, K 0)
    result = head.historical_catalog(dict(packets))
    assert set(result) == base and len(result) == BASE_PACKETS  # operator-stated; CONTRACT_295 section 1
    for name, pin in authority["baselinePackets"].items():
        # operator-stated (baselinePackets: the sha256 of each YAML's bytes); CONTRACT_295 section 1 (no YAML edit)
        assert _sha(catalog[name]) == pin.split(":")[-1], name
    lacking = dict(packets)
    lacking.pop(sorted(base)[0])
    with pytest.raises(ValueError):  # operator-stated (refuses a mapping that lacks an id)
        head.historical_catalog(lacking)
    adding = dict(packets)
    adding[head.NEW_PACKET + "-EXTRA"] = copy.deepcopy(packets[head.NEW_PACKET])
    with pytest.raises(ValueError):  # operator-stated (refuses a mapping that adds an id)
        head.historical_catalog(adding)


def _weights_tables(document):
    candidates = [document] + [value for value in document.values() if isinstance(value, _Pairs)]
    return [table for table in candidates if table and all(isinstance(key, str) and "/" in key for key in table)]


def test_weights_table(head):
    """CONTRACT_295 sections 6 and 8 (P2): the table's raw keys equal its effective keys, every key names a
    regular file, the head test and the oracle hold rows, 219 entries."""
    document = json.loads(head.reviewed_bytes(TABLE_PATH), object_pairs_hook=_Pairs)
    tables = _weights_tables(document)
    assert len(tables) == 1  # CONTRACT_295 section 6 (one weights table)
    table = tables[0]
    assert len(table.raw) == len(set(table.raw)) and set(table.raw) == set(table)  # CONTRACT_295 section 8 (P2)
    assert len(table) == TABLE_ENTRIES  # CONTRACT_295 section 6 (217 + 2); operator-stated
    for key in NEW_ROWS:
        assert key in table, key  # CONTRACT_295 section 6 (the head test's and the oracle's rows)
    for key in table:
        assert isinstance(head.reviewed_bytes(key), bytes), key  # CONTRACT_295 section 6 (a regular file per key)
