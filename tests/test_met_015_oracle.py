"""D5a oracle for MET-015 (slot 297, K = 1): one part per item, and the head layer's checks.

Owner decision D5a: black-box tests written outside the candidate by a non-author. C18 (CONTRACT_297 section 2):
every repository file is read through the head's era reader, `head.reviewed_bytes(path)`; the current catalog's
names come from the one names-only helper below, and each packet's bytes come through the era reader.

Sources of every expected value (each assert cites its own): CONTRACT_297 r5 (sections 1 to 6) and its erratum r8
(the hub's rulings R1 to R4 in section 3; where r8 and r5 differ, r8 rules), R08's r8 YAML of
EXEC-ML-ADOPT-PINS-001, the GR-REDTEAM-FIXTURES-001 draft r3, R06's MODEL-WEIGHTS-POLICY-001 step 4 r2 (rules
C-1 to C-8 and the vectors) and step 3 r2 (the class), and the operator-stated facts of the oracle brief
(revision 3, B1 and B2 among them). Mutation sites follow the hub's construction relay (A1 to A7). The
records, vector sets, schemas, table, authority, hunk-class record, registry and YAMLs are fixtures: the tests load
them and mutate deep copies; no expected value is taken from them except where a disclosure says so.
"""

from __future__ import annotations

import base64
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

_HEAD_NAME = "met_015_oracle_head_module"
_HEAD_SPEC = importlib.util.spec_from_file_location(_HEAD_NAME, ROOT / "scripts" / "validate_met_015.py")
head = importlib.util.module_from_spec(_HEAD_SPEC)
sys.modules[_HEAD_NAME] = head
_HEAD_SPEC.loader.exec_module(head)


def current_catalog_names():
    """The current catalog's names: the sorted *.yaml stems in task-packets/ under the head's ROOT (names only)."""
    return sorted(path.stem for path in (head.ROOT / "task-packets").glob("*.yaml"))


# ---------------------------------------------------------------------------------------------------------------
# Literals, each with its source.
# ---------------------------------------------------------------------------------------------------------------

NEW_PACKET = "MET-015"  # CONTRACT_297 section 1
PREV_PACKET = "MET-014"  # CONTRACT_297 section 1
PRODUCT = "EXEC-ML-ADOPT-PINS-001"  # CONTRACT_297 section 1
PRODUCT_YAML = "task-packets/EXEC-ML-ADOPT-PINS-001.yaml"  # CONTRACT_297 section 3
PRODUCT_SHA256 = "05b84bf42325995eb928c310623fa109aba2e99fc0765701e23569565d89734f"  # operator-stated
COMPARATOR = "EXEC-TEMPORAL-PINS-001"  # CONTRACT_297 section 3 (R13's pin)
COMPARATOR_YAML = "task-packets/EXEC-TEMPORAL-PINS-001.yaml"  # CONTRACT_297 section 1
COMPARATOR_SHA256 = "3015206b52c26128331794bf96796ec7fcbfc283455c58b1510f6ce0232fcba7"  # operator-stated
NEW_PACKET_YAML = "task-packets/MET-015.yaml"  # CONTRACT_297 section 5
BASE_MAIN = "12ecc897dece54c7332eaad18e4c4b92243a0f08"  # CONTRACT_297 Inputs (the base main)
BASE_TREE_SHORT = "9c562119"  # CONTRACT_297 Inputs (the base tree)
BASE_IDS = 320  # CONTRACT_297 section 1 (C - 1 - K = 322 - 1 - 1)

AUTHORITY_PATH = "architecture/execml-grrt-weights-authority.json"  # CONTRACT_297 section 4
HUNK_RECORD_PATH = "architecture/chain-checkpoint/hunk-classes/297.json"  # CONTRACT_297 section 4
REGISTRY_PATH = "architecture/review-record/briefs.json"  # CONTRACT_297 section 5
TABLE_PATH = "ci/parallel_suite_weights.json"  # CONTRACT_297 section 6
HEAD_PATH = "scripts/validate_met_015.py"  # CONTRACT_297 section 4
HEAD_TEST = "tests/test_met_015.py"  # CONTRACT_297 section 4
OWN_ROW = "tests/" + Path(__file__).name  # CONTRACT_297 section 6 (297's D5a file, placed at c3)
MEMBER_TESTS = ("tests/test_redteam_fixtures.py", "tests/test_model_weights.py")  # CONTRACT_297 sections 6 and 9
TABLE_ENTRIES = 223  # operator-stated; CONTRACT_297 section 6 (221 -> 223)
REGISTRY_ENTRIES = 44  # operator-stated; CONTRACT_297 section 1 (43 -> 44)
RIDER = "MET-015/packet"  # CONTRACT_297 section 1
PEEL_MESSAGE = "unexpected packet addition or loss"  # operator-stated
HEAD_MESSAGE = "MET-015"  # operator-stated (every check_* refusal names MET-015)

BASE_POLICY = "legal/third-party-license-policy.yaml"  # R06 step 4 r2 section 2
A1_AMENDMENT = "legal/license-policy-amendment/amendment.json"  # R06 step 4 r2 section 2; operator-stated
A2_AMENDMENT = "legal/license-policy-amendment-v2/amendment.json"  # R06 step 4 r2 section 2; operator-stated
V3_AMENDMENT = "legal/license-policy-amendment-v3/amendment.json"  # CONTRACT_297 section 3
V3_README = "legal/license-policy-amendment-v3/README.md"  # CONTRACT_297 section 3
BASE_POLICY_SHA256 = "fa3a4398acafc3960eaaae9f5396d4e96d91e6ff252b83f6c53e1f5f0d8a40d0"  # operator-stated
A1_SHA256 = "f6a8c0796857cf40906df3e6bc483122988b91271cc77b3aaed4d4e213d864c2"  # operator-stated
A2_SHA256 = "05984db7339c60cf0d4b9acc1179bd0b5fbb16c6f2f4dd554889388133e8f3a7"  # operator-stated
WHOLE_FILE_SCRIPTS = ("scripts/license_amendment.py", "scripts/license_amendment_v2.py")  # CONTRACT_297 section 3 (fix 1)
SEGMENT_VALIDATORS = (
    "scripts/validate_license_amendment.py",
    "scripts/validate_license_amendment_v2.py",
)  # CONTRACT_297 section 3 (fix 1: cascade-only hunks, era files)

REDTEAM_ITEM = "GR-REDTEAM-FIXTURES-001"  # CONTRACT_297 section 1
WEIGHTS_ITEM = "MODEL-WEIGHTS-POLICY-001"  # CONTRACT_297 section 1
REDTEAM_PATHS = {
    "record": "architecture/redteam-fixtures/record.json",
    "schema": "architecture/redteam-fixtures/schema.json",
    "vectors": "architecture/redteam-fixtures/vectors.json",
    "model": "scripts/redteam_fixtures.py",
    "checker": "scripts/validate_redteam_fixtures.py",
}  # CONTRACT_297 section 3 (the member table)
WEIGHTS_PATHS = {
    "record": "architecture/model-weights/record.json",
    "schema": "architecture/model-weights/schema.json",
    "vectors": "architecture/model-weights/vectors.json",
    "checker": "scripts/validate_model_weights.py",
}  # CONTRACT_297 section 3 (the member table)
PACKET_FILES_EXPECTED = {
    PRODUCT_YAML,
    REDTEAM_PATHS["record"],
    REDTEAM_PATHS["schema"],
    REDTEAM_PATHS["vectors"],
    REDTEAM_PATHS["model"],
    REDTEAM_PATHS["checker"],
    MEMBER_TESTS[0],
    WEIGHTS_PATHS["record"],
    WEIGHTS_PATHS["schema"],
    WEIGHTS_PATHS["vectors"],
    V3_AMENDMENT,
    V3_README,
    WEIGHTS_PATHS["checker"],
    MEMBER_TESTS[1],
}  # CONTRACT_297 section 3 (the product and the two members' files); operator-stated (c1's 14 files)

R8_REPOSITORY = "mas-harness-execution-plane"  # R08 r8; CONTRACT_297 Inputs
R8_PREDECESSORS = ["PLANE-BOOTSTRAP-R08", "EXEC-TEMPORAL-PINS-001"]  # R08 r8; CONTRACT_297 Inputs
R8_ADDED = [
    "adoption/scikit-learn/PROVIDER.json",
    "adoption/scikit-learn/SBOM.cdx.json",
    "adoption/scikit-learn/NOTICE.md",
    "adoption/scikit-learn/SAFE-FORMAT.md",
    "adoption/onnxruntime/PROVIDER.json",
    "adoption/onnxruntime/SBOM.cdx.json",
    "adoption/onnxruntime/NOTICE.md",
    "tests/adoption/test_ml_dossiers.py",
]  # R08 r8 (the Tree contract's 8 A entries)
R8_MODIFIED = "tests/adoption/test_temporal_dossier.py"  # R08 r8 (the Tree contract's 1 M entry)
R8_EVIDENCE = [
    "The head's name-status against 8939c5cd542dcd0b748b87a8065d2e1f348c60db is exactly the Tree contract's 8 A "
    "entries and 1 M entry.",
    "The dossier unittest passes under the hash-pinned offline runner with all outbound network denied.",
    "Every sha256 in both PROVIDER.json files equals the part-2 report's computed digest and the mirror object's name.",
    "Source, offline unit, PR check and merge are the only evidence this packet can prove (G1, G2 records); adapters, "
    "Linux profile, artifact, deployment, runtime, assurance and tenant acceptance stay not run (G8).",
]  # R08 r8 (expectedEvidence)

# GR-REDTEAM-FIXTURES-001 draft r3 section 3: refusalOrder, with the PLACEMENT code between these two parts.
GRRT_ORDER_BEFORE_PLACEMENT = [
    "SHAPE",
    "CASE_ID",
    "CASE_DUPLICATE",
    "COMMIT_NOT_PINNED",
    "LICENCE_MISSING",
    "LICENCE_NOT_ALLOWED",
    "WEIGHTS_PATH",
    "GENERATED_NOT_ALLOWED",
    "SERVES_EMPTY",
    "DIGEST_MISMATCH",
    "SELECTION_DIGEST",
    "SELECTION_COUNT",
    "N2_PAIR",
    "EXPECTED_FAIL_OPEN",
]  # GRRT draft r3 section 3 (refusalOrder 1-6)
GRRT_ORDER_AFTER_PLACEMENT = ["MIXED_RUN", "DATASET_DIGEST"]  # GRRT draft r3 section 3 (refusalOrder 8)
GRRT_NAMED_CODES = GRRT_ORDER_BEFORE_PLACEMENT + GRRT_ORDER_AFTER_PLACEMENT  # GRRT draft r3 section 3
GRRT_FAMILIES = {
    "MANIFEST": {
        "LICENCE_MISSING",
        "LICENCE_NOT_ALLOWED",
        "COMMIT_NOT_PINNED",
        "DIGEST_MISMATCH",
        "WEIGHTS_PATH",
        "SERVES_EMPTY",
        "GENERATED_NOT_ALLOWED",
    },
    "CASE": {"CASE_ID", "CASE_DUPLICATE", "N2_PAIR"},
    "SELECTION": {"SELECTION_DIGEST", "SELECTION_COUNT"},
    "EXPECTED": {"EXPECTED_FAIL_OPEN"},
    "BINDING": {"MIXED_RUN", "DATASET_DIGEST"},
}  # GRRT draft r3 section 3 (the negative table's Family column; PLACEMENT holds its one reused code)
GRRT_CASE_ID_PATTERN = r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}(?![\s\S])"  # GRRT draft r3 section 3 (RT-1, R12's N1)
GRRT_WEIGHTS_PATH = "models/weights/model.safetensors"  # GRRT draft r3 section 3 (RT-N5: a model-weight directory)
GRRT_NON_PACK_TASK = "oracle-other-task-0001"  # GRRT draft r3 section 3 (RT-N15: a task that is no pack case)

# GRRT draft r3 section 3, N1 table: record kind, effective decision and error code of each decision-record row.
N1_DECISIONS = {
    "N1-01": ("GUARDRAIL", "DENY", "ERR_EVALUATOR_UNAVAILABLE"),
    "N1-02": ("GUARDRAIL", "DENY", "ERR_INTERNAL"),
    "N1-03": ("GUARDRAIL", "DENY", "ERR_RULE_NOT_SELECTED"),
    "N1-04": ("GUARDRAIL", "DENY", "ERR_MALFORMED_INPUT"),
    "N1-05": ("GRADE", "UNGRADED", "ERR_EVALUATOR_UNAVAILABLE"),
    "N1-07": ("GUARDRAIL", "DENY", "ERR_TIMEOUT"),
    "N1-08": ("GUARDRAIL", "DENY", "ERR_RULE_NOT_SELECTED"),
    "N1-09": ("ADMISSION_SCAN", "DENY", "ERR_EVALUATOR_UNAVAILABLE"),
}  # GRRT draft r3 section 3 (N1 rows; N1-06 is run level, not a decision record)
N1_TAGS = sorted(list(N1_DECISIONS) + ["N1-06"])  # GRRT draft r3 section 3 (nine N1 cases)

# MODEL-WEIGHTS-POLICY-001: R06 step 4 r2 section 4 names the rules; the operator states the codes run MW_IDENTITY
# to MW_APPROVAL, that is "MW_" and the rule's name.
MW_RULE_NAMES = {
    "C-2": "identity",
    "C-3": "class",
    "C-4": "restrictions",
    "C-5": "distribution",
    "C-6": "derived",
    "C-7": "served",
    "C-8": "approval",
}  # R06 step 4 r2 section 4 (C-2 to C-8); operator-stated (MW_IDENTITY to MW_APPROVAL)
RESTRICTION_FIELDS = [
    "redistribution",
    "useRestrictions",
    "attribution",
    "derivatives",
    "licensorPowers",
    "thresholds",
    "acceptance",
    "governingLaw",
]  # R06 step 3 r2 section 3 (the eight restriction fields)
MW_NEGATIVES = [
    ("n01-route-names-model-with-no-row", "C-7"),
    ("n02-served-row-denied", "C-7"),
    ("n03-served-row-missing-planned", "C-7"),
    ("n04-served-row-unknown", "C-8"),
    ("n05-served-review-row-no-decision", "C-7"),
    ("n06-review-row-bundle", "C-5"),
    ("n07-w3-row-metadata-tag-only", "C-3"),
    ("n08-derived-row-more-permissive", "C-6"),
    ("n09a-digest-trailing-newline", "C-2"),
    ("n09b-digest-63-hex", "C-2"),
    ("n10-duplicate-row-id", "C-2"),
    ("n11-review-row-missing-restriction-field", "C-4"),
]  # R06 step 4 r2 section 5 (negatives 1 to 11, each with the rule it breaks)
WEIGHTS_PRECEDENCE = [
    "DENIED",
    "UNKNOWN",
    "OPTIONAL_EXPLICIT_REVIEW",
    "ALLOWED_EXCEPTION",
    "DEFAULT_ALLOWED",
]  # R06 step 3 r2 sections 2 and 5
REQUIRED_DECISION_FIELDS = RESTRICTION_FIELDS + [
    "distributionMode",
    "approvingAuthority",
    "decisionDigest",
]  # R06 step 3 r2 section 5 (requiredDecisionFields)

HEX64 = re.compile(r"[0-9a-f]{64}")  # R06 step 4 r2 C-2 (64 lowercase hex, full match)

# Revision 3 of the brief (B1, B2) and CONTRACT_297 r8 (R1 to R4).
RUN_MANIFEST_SCHEMA = "architecture/run-manifest/run-manifest.schema.json"  # operator-stated (B1)
SPLIT_DECLARATION_SCHEMA = "architecture/run-manifest/split-declaration.schema.json"  # operator-stated (B1)
A1_A2_SCRIPTS = WHOLE_FILE_SCRIPTS + SEGMENT_VALIDATORS  # operator-stated (B2: A1's and A2's four scripts)
GRRT_NOT_ALLOWED_SPDX = "GPL-3.0-only"  # GRRT draft r3 section 3 (RT-N2: an SPDX outside MIT or Apache-2.0)
GRRT_ALLOWED_SPDX = ("MIT", "Apache-2.0")  # GRRT draft r3 section 3 (RT-N2)
ALLOWING_OUTCOMES = ("DEFAULT_ALLOWED", "ALLOWED_EXCEPTION")  # R06 step 3 r2 section 2 (outcomes that allow release)
MW_DRAFT_NEGATIVES = [
    ("negative-1", "C-7"),
    ("negative-2", "C-7"),
    ("negative-3", "C-7"),
    ("negative-4", "C-8"),
    ("negative-5", "C-7"),
    ("negative-6", "C-5"),
    ("negative-7", "C-3"),
    ("negative-8", "C-6"),
    ("negative-9", "C-2"),
    ("negative-10", "C-2"),
    ("negative-11", "C-4"),
]  # R06 step 4 r2 section 5 (the draft's eleven negatives, each with its rule); CONTRACT_297 r8 R3 and R4


# ---------------------------------------------------------------------------------------------------------------
# Plain-data helpers (no repository read here except through head.reviewed_bytes).
# ---------------------------------------------------------------------------------------------------------------


def _read(path):
    return head.reviewed_bytes(_rel(path))


def _json(path):
    return json.loads(_read(path))


def _rel(path):
    candidate = Path(path)
    if candidate.is_absolute():
        candidate = candidate.relative_to(head.ROOT)
    return candidate.as_posix()


def _field(row, name):
    try:
        return row[name]
    except (TypeError, KeyError, IndexError):
        return getattr(row, name)


def _sha256(data):
    return hashlib.sha256(data).hexdigest()


def _hex(value):
    text = str(value)
    return text[len("sha256:"):] if text.startswith("sha256:") else text


def _other_hex(value):
    prefix = "sha256:" if value.startswith("sha256:") else ""
    body = value[len(prefix):]
    return prefix + ("0" * 64 if body != "0" * 64 else "1" * 64)


def _walk(value):
    stack = [value]
    while stack:
        item = stack.pop()
        yield item
        if isinstance(item, dict):
            stack.extend(reversed(list(item.values())))
        elif isinstance(item, list):
            stack.extend(reversed(item))


def _dicts_with(value, *keys):
    return [item for item in _walk(value) if isinstance(item, dict) and all(key in item for key in keys)]


def _lists(value):
    return [item for item in _walk(value) if isinstance(item, list)]


def _strings(value):
    return {item for item in _walk(value) if isinstance(item, str)}


def _find_key(value, key):
    for item in _walk(value):
        if isinstance(item, dict) and key in item:
            return item
    return None


def _jcs(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def _dump_forms():
    forms = []
    for indent in (2, 1, 4, None):
        separators = [(",", ": ")] if indent is not None else [(", ", ": "), (",", ":")]
        for sep in separators:
            for sort_keys in (False, True):
                for ensure_ascii in (False, True):
                    forms.append({"indent": indent, "separators": sep, "sort_keys": sort_keys, "ensure_ascii": ensure_ascii})
    return forms


def _dump_like(raw, original, new):
    """Serialise `new` in the form that reproduces `raw` from `original`, so only the mutation differs."""
    text = raw.decode("utf-8")
    for form in _dump_forms():
        for tail in ("\n", ""):
            if json.dumps(original, **form) + tail == text:
                return (json.dumps(new, **form) + tail).encode("utf-8")
    return (json.dumps(new, indent=2, ensure_ascii=False) + "\n").encode("utf-8")


def _flip_byte(data):
    return data[:-1] + bytes([data[-1] ^ 0x01]) if data else b"x"


def _refuses(function, *args):
    with pytest.raises(ValueError) as info:
        function(*args)
    return str(info.value)


def _codes(refusals):
    codes = []
    for item in refusals:
        if isinstance(item, (tuple, list)):
            codes.append(item[0])
        elif isinstance(item, dict):
            codes.append(item.get("code"))
        else:
            codes.append(getattr(item, "code", item))
    return codes


def _reader_over(files):
    def read(path):
        key = _rel(path)
        if key not in files:
            raise FileNotFoundError(key)
        return files[key]

    return read


class _PairsDict(dict):
    raw_keys: list


def _pairs_hook(pairs):
    result = _PairsDict(pairs)
    result.raw_keys = [key for key, _value in pairs]
    return result


@pytest.fixture(scope="module")
def catalog():
    """The current catalog mapping: names from the helper, bytes through the era reader, parsed by safe_load."""
    return {name: head.safe_load(head.reviewed_bytes(f"task-packets/{name}.yaml")) for name in current_catalog_names()}


# ---- GR-REDTEAM-FIXTURES-001 helpers ---------------------------------------------------------------------------


def _polarity(case):
    value = str(case.get("polarity", "")).lower()
    if value.startswith("pos"):
        return "positive"
    if value.startswith("neg"):
        return "negative"
    return value


def _grrt_cases():
    return _json(_field(head.REDTEAM, "vectors"))["cases"]


def _grrt_record():
    return _json(_field(head.REDTEAM, "record"))


def _positive_packs(cases):
    packs = [case for case in cases if _polarity(case) == "positive" and case.get("check") == "PACK"]
    return sorted(
        packs,
        key=lambda case: (
            not _dicts_with(case.get("input"), "datasetDigest"),
            -len(json.dumps(case.get("input"), sort_keys=True)),
        ),
    )


def _rows(pack):
    return _dicts_with(pack, "setId", "upstream", "licence")


def _pack_cases(pack):
    return _dicts_with(pack, "caseId", "class")


def _refusal(model, pack):
    try:
        model.check_pack(pack)
    except model.Refused as exc:
        return exc.code
    return None


def _replay_meets(model, case):
    try:
        return model.replay(case)[0] is True
    except (model.Refused, ValueError):
        return False


def _resolve_ref(schema, ref):
    if not isinstance(ref, str) or not ref.startswith("#/"):
        return {}
    node = schema
    for part in ref[2:].split("/"):
        part = part.replace("~1", "/").replace("~0", "~")
        if not isinstance(node, dict) or part not in node:
            return {}
        node = node[part]
    return node


def _closed_partition():
    """B1: the second value of MAS-RA-002's split.partition enum in the run-manifest schema (era bytes)."""
    schema = _json(RUN_MANIFEST_SCHEMA)
    scopes = []
    for site in _dicts_with(schema, "split"):
        node = site["split"]
        if isinstance(node, dict) and "$ref" in node:
            node = _resolve_ref(schema, node["$ref"])
        scopes.append(node)
    scopes.append(schema)
    for scope in scopes:
        for item in _walk(scope):
            if isinstance(item, dict) and isinstance(item.get("partition"), dict):
                node = item["partition"]
                if "$ref" in node:
                    node = _resolve_ref(schema, node["$ref"])
                values = node.get("enum")
                if isinstance(values, list) and len(values) >= 2:
                    return values[1]
    return None


def _sample_string(node):
    pattern = node.get("pattern")
    minimum = node.get("minLength", 0)
    for candidate in ("generated-by-a-tool", "0" * 64, "sha256:" + "0" * 64, "A"):
        if len(candidate) >= minimum and (not pattern or re.search(pattern, candidate)):
            return candidate
    return "generated-by-a-tool"


def _schema_value(node, schema, depth=0):
    """A non-null value of a type the schema node allows (relay A3), or None when it allows only null."""
    if not isinstance(node, dict) or depth > 8:
        return None
    if "$ref" in node:
        return _schema_value(_resolve_ref(schema, node["$ref"]), schema, depth + 1)
    if "const" in node:
        return node["const"]
    if isinstance(node.get("enum"), list):
        values = [value for value in node["enum"] if value is not None]
        return values[0] if values else None
    for key in ("anyOf", "oneOf"):
        if isinstance(node.get(key), list):
            for branch in node[key]:
                value = _schema_value(branch, schema, depth + 1)
                if value is not None:
                    return value
            return None
    kinds = node.get("type")
    kinds = [kinds] if isinstance(kinds, str) else list(kinds or [])
    if "string" in kinds:
        return _sample_string(node)
    if "object" in kinds:
        properties = node.get("properties") or {}
        return {key: _schema_value(properties.get(key, {}), schema, depth + 1) for key in node.get("required") or []}
    if "array" in kinds:
        count = node.get("minItems", 0)
        return [_schema_value(node.get("items") or {}, schema, depth + 1)] * count
    if "integer" in kinds or "number" in kinds:
        return node.get("minimum", 1)
    if "boolean" in kinds:
        return True
    return None


def _generated_value():
    """A non-null generationProvenance of a type the era schema's manifestRow allows (relay A3)."""
    schema = _json(_field(head.REDTEAM, "schema"))
    definitions = schema.get("$defs") or schema.get("definitions") or {}
    row = definitions.get("manifestRow") or {}
    node = (row.get("properties") or {}).get("generationProvenance")
    return _schema_value(node, schema) if isinstance(node, dict) else None


def _placement_code():
    order = list(_grrt_record()["refusalOrder"])
    rest = [code for code in order if code not in GRRT_NAMED_CODES]
    return rest[0] if len(rest) == 1 else None


def _m_shape(pack):
    rows = _rows(pack)
    if not rows:
        return False
    rows[0]["oracleKeyOutsideDef"] = "x"
    return True


def _m_licence_missing(pack):
    rows = _rows(pack)
    if not rows:
        return False
    rows[0]["licence"] = None
    return True


def _m_licence_not_allowed(pack):
    """RT-N2 under R1: the row's SPDX changes together with the licenceRef of every case of that set."""
    for row in _rows(pack):
        if isinstance(row["licence"], dict) and "spdx" in row["licence"]:
            row["licence"]["spdx"] = GRRT_NOT_ALLOWED_SPDX
            for case in _pack_cases(pack):
                if case.get("setId") == row["setId"] and "licenceRef" in case:
                    case["licenceRef"] = GRRT_NOT_ALLOWED_SPDX
            return True
    return False


def _m_licence_ref_mismatch(pack):
    """R1: one case's licenceRef no longer equals its set's row SPDX (both SPDX allowed)."""
    for row in _rows(pack):
        licence = row.get("licence")
        spdx = licence.get("spdx") if isinstance(licence, dict) else None
        if spdx is None:
            continue
        for case in _pack_cases(pack):
            if case.get("setId") == row["setId"] and case.get("licenceRef") == spdx:
                case["licenceRef"] = GRRT_ALLOWED_SPDX[1] if spdx == GRRT_ALLOWED_SPDX[0] else GRRT_ALLOWED_SPDX[0]
                return True
    return False


def _m_commit_not_pinned(pack):
    for row in _rows(pack):
        if isinstance(row["upstream"], dict) and "commit" in row["upstream"]:
            row["upstream"]["commit"] = "main"
            return True
    return False


def _carried_digests(pack):
    """The sha256 of every byte string the input carries (as UTF-8 text or as base64)."""
    digests = set()
    for text in _strings(pack):
        digests.add(_sha256(text.encode("utf-8")))
        try:
            digests.add(_sha256(base64.b64decode(text, validate=True)))
        except ValueError:
            pass
    return digests


def _m_digest_mismatch(pack):
    """RT-N4 (relay A2): only a row whose fetch.sha256 is the digest of bytes carried in the same input."""
    carried = _carried_digests(pack)
    for row in _rows(pack):
        fetch = row.get("fetch")
        if isinstance(fetch, dict) and isinstance(fetch.get("sha256"), str) and _hex(fetch["sha256"]) in carried:
            fetch["sha256"] = _other_hex(fetch["sha256"])
            return True
    return False


def _m_weights_path(pack):
    for row in _rows(pack):
        if isinstance(row["upstream"], dict) and isinstance(row["upstream"].get("paths"), list):
            row["upstream"]["paths"].append(GRRT_WEIGHTS_PATH)
            return True
    return False


def _m_serves_empty(pack):
    for row in _rows(pack):
        if "servesItems" in row:
            row["servesItems"] = []
            return True
    return False


def _m_generated(pack):
    """RT-N7 (relay A3): a non-null value of a type the era schema's manifestRow allows."""
    value = _generated_value()
    if value is None:
        return False
    for row in _rows(pack):
        if "generationProvenance" in row:
            row["generationProvenance"] = copy.deepcopy(value)
            return True
    return False


def _m_case_id(pack):
    cases = _pack_cases(pack)
    if not cases:
        return False
    cases[0]["caseId"] = "-" + str(cases[0]["caseId"])
    return True


def _m_case_duplicate(pack):
    for items in _lists(pack):
        if items and all(isinstance(item, dict) and "caseId" in item and "class" in item for item in items):
            items.append(copy.deepcopy(items[0]))
            return True
    return False


def _m_n2_pair(pack):
    for case in _pack_cases(pack):
        if case.get("pairedCaseId") is not None:
            case["pairedCaseId"] = None
            return True
    return False


def _m_selection_digest(pack):
    sites = _dicts_with(pack, "selectedIdsSha256")
    if not sites:
        return False
    sites[0]["selectedIdsSha256"] = None
    return True


def _m_selection_count(pack):
    for site in _dicts_with(pack, "selectedIdsSha256", "count"):
        if isinstance(site["count"], int) and not isinstance(site["count"], bool):
            site["count"] = site["count"] + 1
            return True
    return False


def _m_expected_fail_open(pack):
    for case in _pack_cases(pack):
        if case.get("class") == "FAIL_OPEN" and "expected" in case:
            case["expected"] = "ALLOW"
            return True
    return False


def _split_partitions(pack):
    """B1: the split declaration's `partitions` map, a partition name to a list of {taskId} entries."""
    for site in _dicts_with(pack, "partitions"):
        if isinstance(site["partitions"], dict):
            return site["partitions"]
    return None


def _pack_ids(pack):
    return {case["caseId"] for case in _pack_cases(pack) if isinstance(case.get("caseId"), str)}


def _m_placement(pack):
    """RT-N14 (relay A5): move one pack case's task entry into the closed partition's list."""
    closed = _closed_partition()
    partitions = _split_partitions(pack)
    ids = _pack_ids(pack)
    if closed is None or not partitions or not ids:
        return False
    if closed in partitions and not isinstance(partitions[closed], list):
        return False
    for minimum in (2, 1):
        for name, entries in partitions.items():
            if name == closed or not isinstance(entries, list) or len(entries) < minimum:
                continue
            for index, entry in enumerate(entries):
                if isinstance(entry, dict) and entry.get("taskId") in ids:
                    moved = entries.pop(index)
                    partitions.setdefault(closed, []).append(moved)
                    return True
    return False


def _m_mixed_run(pack):
    """RT-N15 (relay A4): add a non-pack {taskId} entry to the split declaration's pack task list only."""
    partitions = _split_partitions(pack)
    ids = _pack_ids(pack)
    if not partitions or not ids:
        return False
    for entries in partitions.values():
        if isinstance(entries, list) and entries and all(isinstance(entry, dict) for entry in entries):
            if {entry.get("taskId") for entry in entries} <= ids:
                extra = copy.deepcopy(entries[0])
                extra["taskId"] = GRRT_NON_PACK_TASK
                entries.append(extra)
                return True
    return False


def _m_dataset_digest(pack):
    sites = _dicts_with(pack, "datasetDigest")
    if not sites or not isinstance(sites[0]["datasetDigest"], str):
        return False
    sites[0]["datasetDigest"] = _other_hex(sites[0]["datasetDigest"])
    return True


GRRT_NEGATIVES = [
    ("RT-N0", "SHAPE", _m_shape),
    ("RT-N1", "LICENCE_MISSING", _m_licence_missing),
    ("RT-N2", "LICENCE_NOT_ALLOWED", _m_licence_not_allowed),
    ("RT-N3", "COMMIT_NOT_PINNED", _m_commit_not_pinned),
    ("RT-N4", "DIGEST_MISMATCH", _m_digest_mismatch),
    ("RT-N5", "WEIGHTS_PATH", _m_weights_path),
    ("RT-N6", "SERVES_EMPTY", _m_serves_empty),
    ("RT-N7", "GENERATED_NOT_ALLOWED", _m_generated),
    ("RT-N8", "CASE_ID", _m_case_id),
    ("RT-N9", "CASE_DUPLICATE", _m_case_duplicate),
    ("RT-N10", "N2_PAIR", _m_n2_pair),
    ("RT-N11", "SELECTION_DIGEST", _m_selection_digest),
    ("RT-N12", "SELECTION_COUNT", _m_selection_count),
    ("RT-N13", "EXPECTED_FAIL_OPEN", _m_expected_fail_open),
    ("RT-N14", "PLACEMENT", _m_placement),
    ("RT-N15", "MIXED_RUN", _m_mixed_run),
    ("RT-N16", "DATASET_DIGEST", _m_dataset_digest),
]  # GRRT draft r3 section 3 (the negative table: one mutation and one code per vector)


def _built_case(mutate, unbound_first=False):
    """Return (original input, mutated input) from the first positive PACK case the mutation applies to."""
    packs = _positive_packs(_grrt_cases())
    if unbound_first:
        packs = sorted(packs, key=lambda case: bool(_dicts_with(case.get("input"), "datasetDigest")))
    for case in packs:
        pack = copy.deepcopy(case["input"])
        if mutate(pack):
            return copy.deepcopy(case["input"]), pack
    return None, None


def _manifest_of(pack):
    if isinstance(pack, dict) and "manifest" in pack:
        return pack["manifest"]
    holders = [value for value in pack.values() if _rows(value)] if isinstance(pack, dict) else []
    return holders[0] if len(holders) == 1 else None


def _dataset_digest(pack):
    """GRRT draft r3 section 3 (I1): sha256: + the RFC 8785 digest of {manifest, sets sorted by setId}."""
    manifest = _manifest_of(pack)
    sets = sorted([row["setId"], row["selection"]["selectedIdsSha256"]] for row in _dicts_with(manifest, "setId", "selection"))
    return "sha256:" + _sha256(_jcs({"manifest": _sha256(_jcs(manifest)), "sets": sets}))


def _n1_hits(cases, tag):
    wanted = tag.lower()
    hits = []
    for case in cases:
        if _polarity(case) != "positive":
            continue
        label = (str(case.get("id", "")) + " " + str(case.get("title", ""))).lower().replace("_", "-")
        if wanted in label:
            hits.append(case)
    return hits


def _grrt_families(record):
    """Relay A1: each family's entry is found by a member (id, family or name) equal to its upper-case name."""
    wanted = set(GRRT_FAMILIES) | {"PLACEMENT"}
    families = record["ruleFamilies"]
    entries = list(families.items()) if isinstance(families, dict) else [(None, body) for body in families]
    result = {}
    for key, body in entries:
        if not isinstance(body, dict):
            continue
        names = [body.get(member) for member in ("id", "family", "name")]
        if key is not None:
            names.append(key)
        hits = [name for name in names if isinstance(name, str) and name in wanted]
        if hits:
            result[hits[0]] = set(body["codes"])
    return result


# ---- MODEL-WEIGHTS-POLICY-001 helpers ---------------------------------------------------------------------------


def _mw_code(rule):
    return "MW_" + MW_RULE_NAMES[rule].upper()


def _mw_files():
    paths = [_rel(_field(head.WEIGHTS, key)) for key in ("record", "schema", "vectors")]
    paths += [V3_AMENDMENT, V3_README, BASE_POLICY, A1_AMENDMENT, A2_AMENDMENT]
    paths += list(A1_A2_SCRIPTS)  # relay A7; operator-stated (B2: the checker reads A1's and A2's four scripts)
    return {path: head.reviewed_bytes(path) for path in paths}


def _mw_cases():
    return _json(_field(head.WEIGHTS, "vectors"))["cases"]


def _mw_committed():
    return _json(_field(head.WEIGHTS, "record"))


def _mw_outcome(row):
    return (row.get("licence") or {}).get("outcome")


def _mw_served(positives, outcome):
    for case in positives:
        record = case.get("record")
        if not isinstance(record, dict) or not record.get("consumers"):
            continue
        for row in record.get("releases") or []:
            licence = row.get("licence") or {}
            weights = row.get("weights") or {}
            if licence.get("outcome") != outcome or weights.get("digestStatus") != "PINNED":
                continue
            if outcome == "OPTIONAL_EXPLICIT_REVIEW" and not licence.get("decisionRef"):
                continue
            return copy.deepcopy(case), row["id"]
    return None, None


def _mw_row(record, row_id):
    return [row for row in record["releases"] if row.get("id") == row_id][0]


def _mw_restrictions(row):
    licence = row.get("licence") or {}
    if isinstance(licence.get("restrictions"), dict):
        return licence["restrictions"]
    return _find_key(row, "redistribution")


def _record_lists(value, path=()):
    """Every list in the record reached through mappings only, outside its releases, with its key path."""
    found = []
    if isinstance(value, dict):
        for key, item in value.items():
            if not path and key == "releases":
                continue
            if isinstance(item, list):
                found.append((path + (key,), item))
            elif isinstance(item, dict):
                found.extend(_record_lists(item, path + (key,)))
    return found


def _resolve_dotted(row, dotted):
    node = row
    for part in dotted.split("."):
        if not isinstance(node, dict) or part not in node:
            return False, None
        node = node[part]
    return True, node


def _deref(schema, node):
    for _step in range(8):
        if not (isinstance(node, dict) and "$ref" in node):
            break
        node = _resolve_ref(schema, node["$ref"])
    return node


def _listing_item_schema(list_path):
    """The era schema's form for one entry of the record's listing at `list_path` (relay A9), or None."""
    schema = _json(_field(head.WEIGHTS, "schema"))
    node = schema
    for key in list_path:
        node = _deref(schema, node)
        node = (node.get("properties") or {}).get(key) if isinstance(node, dict) else None
        if node is None:
            return None
    node = _deref(schema, node)
    item = _deref(schema, node.get("items")) if isinstance(node, dict) else None
    return item if isinstance(item, dict) else None


def _null_entry_keys(entry, rows):
    """(row key, path key, dotted path) when the entry names a row id and a dotted path to a null in that row."""
    if not isinstance(entry, dict):
        return None
    for row_key, row_id in entry.items():
        if not isinstance(row_id, str) or row_id not in rows:
            continue
        for path_key, dotted in entry.items():
            if path_key == row_key or not isinstance(dotted, str):
                continue
            resolved, value = _resolve_dotted(rows[row_id], dotted)
            if resolved and value is None:
                return row_key, path_key, dotted
    return None


def _restriction_null_form(committed):
    """Relay A9: the committed record's own listing of restriction-field nulls, whose kind must agree."""
    rows = {row.get("id"): row for row in committed.get("releases") or [] if isinstance(row, dict)}
    found = []
    for list_path, items in _record_lists(committed):
        for entry in items:
            keys = _null_entry_keys(entry, rows)
            if keys and keys[2].rsplit(".", 1)[-1] in RESTRICTION_FIELDS:
                found.append((list_path, entry) + keys)
    if not found:
        pytest.fail("the committed record lists no restriction-field null (relay A9)")
    item = _listing_item_schema(found[0][0])
    if item is None:
        pytest.fail("the era schema gives no form for the record's null listing (relay A9)")
    properties = item.get("properties") or {}
    shapes = set()
    for list_path, entry, row_key, path_key, dotted in found:
        kind_keys = [
            key
            for key, spec in properties.items()
            if key not in (row_key, path_key) and isinstance(spec, dict) and ("enum" in spec or "const" in spec)
        ]
        if not kind_keys:
            kind_keys = [key for key in entry if key not in (row_key, path_key)]
        kind = json.dumps({key: entry.get(key) for key in kind_keys}, sort_keys=True)
        prefix = dotted.rsplit(".", 1)[0] if "." in dotted else ""
        shapes.add((list_path, row_key, path_key, prefix, kind))
    if len(shapes) != 1:
        pytest.fail("the committed record's restriction-field null listings disagree (relay A9)")
    list_path, entry, row_key, path_key, dotted = found[0]
    prefix = dotted.rsplit(".", 1)[0] if "." in dotted else ""
    return list_path, row_key, path_key, prefix, entry, item


def _list_null(record, row_id, field, committed):
    """Relay A9 and A10: list one restriction-field null by row id and dotted path, in the era schema's form."""
    list_path, row_key, path_key, prefix, template, item = _restriction_null_form(committed)
    entry = copy.deepcopy(template)
    entry[row_key] = row_id
    entry[path_key] = prefix + "." + field if prefix else field
    properties = item.get("properties") or {}
    required = item.get("required") or []
    # relay A9 (the entry takes the form the era schema gives for the listing)
    assert set(required) <= set(entry), "the listing entry lacks a member the era schema requires"
    # relay A9 (the entry takes the form the era schema gives for the listing)
    assert not properties or set(entry) <= set(properties), "the listing entry holds a member outside the schema"
    node = record
    for key in list_path[:-1]:
        node = node.setdefault(key, {})
    listing = node.setdefault(list_path[-1], [])
    if entry not in listing:
        listing.append(entry)
    return entry


def _mw_build(name, committed, positives, checker, policy):
    number = name[1:3]
    if number in ("01", "02", "03", "04"):
        case, row_id = _mw_served(positives, "DEFAULT_ALLOWED")
        # R06 step 4 r2 section 5 (positive: one served, pinned DEFAULT_ALLOWED row)
        assert case is not None, "no served DEFAULT_ALLOWED positive vector"
        record = case["record"]
        row = _mw_row(record, row_id)
        if number == "01":
            record["releases"] = [item for item in record["releases"] if item.get("id") != row_id]
        elif number == "02":
            row["licence"]["outcome"] = "DENIED"
        elif number == "03":
            # relay A8 (R06 step 4 r2 section 3 and section 6: MISSING_PLANNED reads never made, no digest guessed)
            row["weights"]["digestStatus"] = "MISSING_PLANNED"
            row["weights"]["files"] = []
        else:
            row["licence"]["outcome"] = "UNKNOWN"
        return record, case.get("sources", {})
    if number in ("05", "06", "11"):
        case, row_id = _mw_served(positives, "OPTIONAL_EXPLICIT_REVIEW")
        # R06 step 4 r2 section 5 (positive: one served review row with an approved decisionRef)
        assert case is not None, "no served review positive vector"
        record = case["record"]
        row = _mw_row(record, row_id)
        if number == "05":
            row["licence"]["decisionRef"] = None
        elif number == "06":
            row["distributionMode"] = "BUNDLE"
        else:
            restrictions = _mw_restrictions(row)
            present = [field for field in RESTRICTION_FIELDS if field in (restrictions or {})]
            # R06 step 4 r2 C-4 (a review row has all eight restriction fields); CONTRACT_297 r8 R4
            assert present, "the served review row carries no restriction field"
            restrictions[present[0]] = None
            _list_null(record, row_id, present[0], committed)  # relay A9 (CONTRACT_297 r8 section 3: nulls listed)
        return record, case.get("sources", {})
    record = copy.deepcopy(committed)
    releases = record["releases"]
    if number == "07":
        for row in releases:
            for site in _dicts_with(row, "cardStatesWeights"):
                if site["cardStatesWeights"] is True:
                    site["cardStatesWeights"] = False
                    return record, {}
        pytest.fail("no row with cardStatesWeights true in the committed record (R06 step 4 r2 C-3)")
    if number == "08":
        bases = [row for row in releases if _mw_outcome(row) in ("DENIED", "UNKNOWN")]
        derived = [row for row in releases if _mw_outcome(row) == "DEFAULT_ALLOWED" and not row.get("derivedFrom")]
        # R06 step 3 r2 section 4 (DENIED, UNKNOWN and DEFAULT_ALLOWED rows exist among the 11 releases)
        assert bases and derived, "no restrictive and permissive row pair in the committed record"
        derived[0]["derivedFrom"] = bases[0]["id"]
        return record, {}
    if number == "09":
        for row in releases:
            for site in _dicts_with(row, "sha256"):
                if isinstance(site["sha256"], str) and HEX64.fullmatch(site["sha256"]):
                    site["sha256"] = site["sha256"] + "\n" if name[3] == "a" else site["sha256"][:63]
                    return record, {}
        pytest.fail("no 64-hex sha256 in the committed record (R06 step 4 r2 C-2)")
    record, sources, row_id = _mw_lone_passing_row(checker, policy, committed, positives)
    # relay A6 (R06 step 4 r2 section 5, negative 10: the duplicate satisfies every other rule on its own)
    assert record is not None, "no row passes check_record alone"
    record["releases"].append(copy.deepcopy(_mw_row(record, row_id)))
    return record, sources


def _mw_lone_passing_row(checker, policy, committed, positives):
    """Relay A6: a row that passes alone, i.e. its record with only that row passes check_record."""
    pairs = [(committed, {})]
    pairs += [(case["record"], case.get("sources", {})) for case in positives if isinstance(case.get("record"), dict)]
    for record, sources in pairs:
        for row in record.get("releases") or []:
            single = copy.deepcopy(record)
            single["releases"] = [copy.deepcopy(row)]
            if _codes(checker.check_record(single, checker._source_reader(sources), policy)) == []:
                return copy.deepcopy(record), copy.deepcopy(sources), row["id"]
    return None, None, None


# ---------------------------------------------------------------------------------------------------------------
# Part 1: EXEC-ML-ADOPT-PINS-001, the product packet (CONTRACT_297 sections 1 and 3; R08 r8).
# ---------------------------------------------------------------------------------------------------------------


def test_product_yaml_is_r8_published_form():
    """CONTRACT_297 sections 1 and 3: the product YAML is r8's published form (tail -n +12), its id and lineage."""
    raw = head.reviewed_bytes(PRODUCT_YAML)
    assert _sha256(raw) == PRODUCT_SHA256  # operator-stated; CONTRACT_297 section 3 (05b84bf4)
    assert _sha256(raw).startswith("05b84bf4")  # CONTRACT_297 section 1
    packet = head.safe_load(raw)
    assert packet["id"] == PRODUCT  # CONTRACT_297 section 1; R08 r8
    assert packet["repository"] == R8_REPOSITORY  # CONTRACT_297 Inputs; R08 r8
    assert packet["predecessors"] == R8_PREDECESSORS  # CONTRACT_297 Inputs; R08 r8


def test_product_expected_evidence_and_tree():
    """CONTRACT_297 section 3 (D5a needs): expectedEvidence holds r8's 8 A entries and 1 M entry."""
    packet = head.safe_load(head.reviewed_bytes(PRODUCT_YAML))
    evidence = packet["expectedEvidence"]
    assert evidence == R8_EVIDENCE  # R08 r8 (expectedEvidence)
    assert "exactly the Tree contract's 8 A entries and 1 M entry" in evidence[0]  # CONTRACT_297 section 3; R08 r8
    assert len(R8_ADDED) == 8  # R08 r8 (8 A entries)
    assert sorted(packet["allowedPaths"]) == sorted(R8_ADDED + [R8_MODIFIED])  # R08 r8 (allowedPaths)
    tree = packet["contracts"][0]
    assert "adds exactly 8 files, each with status A, modifies exactly 1 file" in tree  # R08 r8 (Tree contract)
    for path in R8_ADDED + [R8_MODIFIED]:
        assert "`" + path + "`" in tree  # R08 r8 (Tree contract names each file)


def test_product_authority_pins():
    """CONTRACT_297 section 3: the authority's productPackets names the product alone, with its digest."""
    authority = head.authority()
    products = {name: _hex(value) for name, value in authority["productPackets"].items()}
    assert products == {PRODUCT: PRODUCT_SHA256}  # CONTRACT_297 section 3; operator-stated
    assert tuple(head.PRODUCT_PACKETS) == (PRODUCT,)  # operator-stated
    assert PRODUCT not in authority["baselinePackets"]  # CONTRACT_297 section 1 (absent at main)


def test_product_comparator_pin():
    """CONTRACT_297 section 3 (R13): the comparator EXEC-TEMPORAL-PINS-001 is pinned at 3015206b, a base file."""
    authority = head.authority()
    comparators = authority["productComparators"]
    assert list(comparators) == [PRODUCT]  # CONTRACT_297 section 3
    assert comparators[PRODUCT]["packet"] == COMPARATOR  # CONTRACT_297 section 3 (R13)
    assert _hex(comparators[PRODUCT]["sha256"]) == COMPARATOR_SHA256  # operator-stated; CONTRACT_297 section 3
    assert _hex(authority["baselinePackets"][COMPARATOR]) == COMPARATOR_SHA256  # operator-stated
    assert _sha256(head.reviewed_bytes(COMPARATOR_YAML)) == COMPARATOR_SHA256  # operator-stated; CONTRACT_297 section 3
    assert COMPARATOR_SHA256.startswith("3015206b")  # CONTRACT_297 section 3


# ---------------------------------------------------------------------------------------------------------------
# Part 2: GR-REDTEAM-FIXTURES-001 (CONTRACT_297 section 3; GRRT draft r3 section 3).
# ---------------------------------------------------------------------------------------------------------------


def test_grrt_refusal_order_and_families():
    """CONTRACT_297 section 3: 17 codes in one refusalOrder; GRRT draft r3 section 3's order and families."""
    model, _checker = head._era_checker(head.REDTEAM)
    record = _grrt_record()
    order = list(record["refusalOrder"])
    assert len(order) == 17  # CONTRACT_297 section 3; GRRT draft r3 section 3 (17 codes)
    assert order[:14] == GRRT_ORDER_BEFORE_PLACEMENT  # GRRT draft r3 section 3 (refusalOrder 1-6)
    assert order[15:] == GRRT_ORDER_AFTER_PLACEMENT  # GRRT draft r3 section 3 (refusalOrder 8)
    placement = order[14]
    assert placement not in GRRT_NAMED_CODES  # GRRT draft r3 section 3 (refusalOrder 7: the PLACEMENT code)
    assert list(model.REFUSAL_ORDER) == order  # operator-stated (Refused codes are REFUSAL_ORDER's)
    families = _grrt_families(record)
    for name, codes in GRRT_FAMILIES.items():
        assert families[name] == codes  # GRRT draft r3 section 3 (the negative table's families)
    assert families["PLACEMENT"] == {placement}  # GRRT draft r3 section 3 (PLACEMENT's one code, reused)


def test_grrt_negative_vectors_carry_the_17_codes():
    """CONTRACT_297 section 3: 17 negatives with 17 codes; GRRT draft r3 section 3: one refusal code each."""
    negatives = [case for case in _grrt_cases() if _polarity(case) == "negative"]
    assert len(negatives) == 17  # CONTRACT_297 section 3 (17 negatives)
    codes = [case["expect"]["refuse"] for case in negatives]
    assert len(set(codes)) == 17  # CONTRACT_297 section 3 (17 codes)
    assert set(GRRT_NAMED_CODES) <= set(codes)  # GRRT draft r3 section 3 (the negative table)
    assert set(codes) - set(GRRT_NAMED_CODES) == {_placement_code()}  # GRRT draft r3 section 3 (RT-N14)


@pytest.mark.parametrize("vector, code, mutate", GRRT_NEGATIVES, ids=[row[0] for row in GRRT_NEGATIVES])
def test_grrt_each_code_refused_on_built_case(vector, code, mutate):
    """GRRT draft r3 section 3: each negative breaks one rule, so its code is the first in refusalOrder."""
    model, _checker = head._era_checker(head.REDTEAM)
    original, pack = _built_case(mutate, unbound_first=(code == "DIGEST_MISMATCH"))
    if code == "DIGEST_MISMATCH":
        reason = "no positive carries a manifest row whose synthetic bytes are in the same input"  # relay A2
    else:
        reason = "no positive PACK case carries the site this mutation needs"
    # GRRT draft r3 section 3 (the positives carry manifest rows, cases, selections and a run binding); relay A2-A5
    assert pack is not None, f"{vector}: {reason}"
    assert _refusal(model, original) is None  # GRRT draft r3 section 3 (a positive passes)
    expected = _placement_code() if code == "PLACEMENT" else code  # GRRT draft r3 section 3 (RT-N14 reuses one code)
    assert expected is not None  # GRRT draft r3 section 3 (one PLACEMENT code)
    assert _refusal(model, pack) == expected  # GRRT draft r3 section 3 (the vector's refusal code)


def test_grrt_case_id_pattern_rejects_trailing_newline():
    """GRRT draft r3 section 3 (RT-1, R12's N1): the caseId pattern refuses a trailing newline."""
    assert re.match(GRRT_CASE_ID_PATTERN, "ab\n") is None  # GRRT draft r3 section 3 (N1 note)
    model, _checker = head._era_checker(head.REDTEAM)

    def newline(pack):
        cases = _pack_cases(pack)
        if not cases:
            return False
        cases[0]["caseId"] = str(cases[0]["caseId"]) + "\n"
        return True

    original, pack = _built_case(newline)
    assert pack is not None, "no positive PACK case with a case"  # GRRT draft r3 section 3
    assert _refusal(model, original) is None  # GRRT draft r3 section 3 (a positive passes)
    assert _refusal(model, pack) == "CASE_ID"  # GRRT draft r3 section 3 (RT-N8, pattern with (?![\s\S]))


def test_grrt_dataset_digest_rule():
    """GRRT draft r3 section 3 (I1): datasetDigest is sha256: + the RFC 8785 digest of {manifest, sets}."""
    model, _checker = head._era_checker(head.REDTEAM)
    found = None
    for case in _positive_packs(_grrt_cases()):
        if _dicts_with(case["input"], "datasetDigest"):
            found = copy.deepcopy(case["input"])
            break
    assert found is not None, "no pack-backed run binding positive"  # GRRT draft r3 section 3 (positive 3)
    assert _manifest_of(found) is not None, "the run binding positive holds no manifest"  # GRRT draft r3 section 3
    binding = _dicts_with(found, "datasetDigest")[0]
    assert binding["datasetDigest"] == _dataset_digest(found)  # GRRT draft r3 section 3 (I1 recomputation)
    assert _refusal(model, copy.deepcopy(found)) is None  # GRRT draft r3 section 3 (the positive binding passes)
    changed = copy.deepcopy(found)
    rows = _dicts_with(_manifest_of(changed), "setId", "selection")
    rows[0]["title"] = str(rows[0].get("title", "")) + " (renamed)"
    assert _refusal(model, copy.deepcopy(changed)) == "DATASET_DIGEST"  # GRRT draft r3 section 3 (RT-N16)
    _dicts_with(changed, "datasetDigest")[0]["datasetDigest"] = _dataset_digest(changed)
    assert _refusal(model, changed) is None  # GRRT draft r3 section 3 (I1: the recomputation binds)


def test_grrt_mixed_run_refusal():
    """GRRT draft r3 section 3 (RT-1, I1): a split declaration mixing pack cases and other tasks is MIXED_RUN."""
    model, _checker = head._era_checker(head.REDTEAM)
    original, pack = _built_case(_m_mixed_run)
    assert pack is not None, "no positive split declaration with pack tasks"  # GRRT draft r3 section 3
    assert _refusal(model, original) is None  # GRRT draft r3 section 3 (all pack cases: passes)
    assert _refusal(model, pack) == "MIXED_RUN"  # GRRT draft r3 section 3 (RT-N15)


def test_grrt_closed_partition_refusal():
    """CONTRACT_297 section 3 and B1: the closed partition is the second value of MAS-RA-002's split.partition enum."""
    model, _checker = head._era_checker(head.REDTEAM)
    closed = _closed_partition()
    # operator-stated (B1: run-manifest.schema.json's split.partition enum); CONTRACT_297 section 3
    assert isinstance(closed, str) and closed, "no split.partition enum in the run-manifest schema"
    assert closed != "DEVELOPMENT"  # GRRT draft r3 section 3 (pack cases sit in DEVELOPMENT only)
    assert _find_key(_json(SPLIT_DECLARATION_SCHEMA), "partitions") is not None  # operator-stated (B1)
    original, pack = _built_case(_m_placement)
    assert pack is not None, "no positive split declaration with pack tasks"  # operator-stated (B1); relay A5
    assert _refusal(model, original) is None  # GRRT draft r3 section 3 (DEVELOPMENT passes)
    assert _refusal(model, pack) == _placement_code()  # GRRT draft r3 section 3 (RT-N14)


def test_grrt_n1_nine_cases_present():
    """CONTRACT_297 section 3: N1's nine authored cases are positive cases entries (GRRT draft r3 section 3)."""
    model, _checker = head._era_checker(head.REDTEAM)
    cases = _grrt_cases()
    found = []
    for tag in N1_TAGS:
        hits = _n1_hits(cases, tag)
        assert len(hits) == 1, f"{tag}: {len(hits)} positive cases"  # GRRT draft r3 section 3 (one case per row)
        assert _replay_meets(model, hits[0])  # CONTRACT_297 section 3 (E1 form: replays to its expectation)
        found.append(json.dumps(hits[0], sort_keys=True))
    assert len(set(found)) == 9  # CONTRACT_297 section 3; GRRT draft r3 section 3 (nine N1 cases)


def test_grrt_n1_06_is_a_run_level_pack_positive():
    """CONTRACT_297 r8 section 3 (R2): N1-06 is a PACK positive at run level; RT-N12 is its run-level negative."""
    model, _checker = head._era_checker(head.REDTEAM)
    hits = _n1_hits(_grrt_cases(), "N1-06")
    assert len(hits) == 1  # CONTRACT_297 r8 R2 (its title names N1-06)
    case = hits[0]
    assert case.get("check") == "PACK"  # CONTRACT_297 r8 R2 (a PACK positive at run level)
    assert _polarity(case) == "positive"  # CONTRACT_297 r8 R2
    pack = copy.deepcopy(case["input"])
    assert _refusal(model, copy.deepcopy(pack)) is None  # CONTRACT_297 r8 R2 (selected count equals the manifest's)
    assert _m_selection_count(pack), "N1-06's input carries no selection count"  # CONTRACT_297 r8 R2
    assert _refusal(model, pack) == "SELECTION_COUNT"  # CONTRACT_297 r8 R2 (RT-N12 stays N1-06's negative)


def test_grrt_licence_ref_mismatch_is_licence_missing():
    """CONTRACT_297 r8 section 3 (R1): a case's licenceRef unequal to its set's row SPDX refuses LICENCE_MISSING."""
    model, _checker = head._era_checker(head.REDTEAM)
    original, pack = _built_case(_m_licence_ref_mismatch)
    assert pack is not None, "no positive case whose licenceRef equals its row SPDX"  # CONTRACT_297 r8 R1
    assert _refusal(model, original) is None  # GRRT draft r3 section 3 (a positive passes)
    assert _refusal(model, pack) == "LICENCE_MISSING"  # CONTRACT_297 r8 R1


@pytest.mark.parametrize("tag", sorted(N1_DECISIONS))
def test_grrt_n1_case_against_table(tag):
    """GRRT draft r3 section 3 (N1 table, RT-5): kind, ERROR, the fail-closed value and the error code."""
    model, _checker = head._era_checker(head.REDTEAM)
    hits = _n1_hits(_grrt_cases(), tag)
    assert len(hits) == 1  # GRRT draft r3 section 3 (one case per N1 row)
    case = hits[0]
    kind, effective, code = N1_DECISIONS[tag]
    strings = _strings(case)
    assert case.get("family") == "EXPECTED"  # GRRT draft r3 section 3 (the EXPECTED family)
    assert case.get("check") == "EXPECTED"  # operator-stated (EXPECTED runs check_expected)
    assert {"ERROR", kind, effective, code} <= strings  # GRRT draft r3 section 3 (N1 table row)
    assert "FAIL_CLOSED" in strings  # GRRT draft r3 section 3 (each case expects FAIL_CLOSED)
    assert model.replay(case)[0] is True  # CONTRACT_297 section 3 (E1 form)


@pytest.mark.parametrize("tag", sorted(N1_DECISIONS))
def test_grrt_n1_never_allow_pass_or_approved(tag):
    """GRRT draft r3 section 3 (RT-5): a FAIL_CLOSED row is never ALLOW, PASS or APPROVED."""
    model, _checker = head._era_checker(head.REDTEAM)
    case = copy.deepcopy(_n1_hits(_grrt_cases(), tag)[0])
    kind = N1_DECISIONS[tag][0]
    sites = _dicts_with(case.get("input"), "effectiveDecision")
    assert sites, f"{tag}: no effectiveDecision in the case input"  # GRRT draft r3 section 3 (RT-2 records)
    for site in sites:
        site["effectiveDecision"] = "PASS" if kind == "GRADE" else "ALLOW"
    assert not _replay_meets(model, case)  # GRRT draft r3 section 3 (never ALLOW, PASS or APPROVED)


def test_grrt_every_case_replays():
    """CONTRACT_297 section 3 (E1 form): every cases entry replays to its expectation; every positive passes."""
    model, _checker = head._era_checker(head.REDTEAM)
    cases = _grrt_cases()
    positives = [case for case in cases if _polarity(case) == "positive"]
    assert positives  # GRRT draft r3 section 3 (positives exist)
    for case in cases:
        assert model.replay(case)[0] is True, case.get("id")  # CONTRACT_297 section 3 (E1 form)
    for case in _positive_packs(cases):
        assert _refusal(model, copy.deepcopy(case["input"])) is None  # GRRT draft r3 section 3 (positive)


# ---------------------------------------------------------------------------------------------------------------
# Part 3: MODEL-WEIGHTS-POLICY-001 (CONTRACT_297 section 3; R06 step 4 r2 and step 3 r2).
# ---------------------------------------------------------------------------------------------------------------


def _mw_fail_closed(case):
    """The rows-file rule's vector: an allowing row with a null in one of the eight restriction fields."""
    record = case.get("record")
    if not isinstance(record, dict):
        return False
    for row in record.get("releases") or []:
        if not isinstance(row, dict) or _mw_outcome(row) not in ALLOWING_OUTCOMES:
            continue
        restrictions = _mw_restrictions(row)
        if isinstance(restrictions, dict):
            if any(field in restrictions and restrictions[field] is None for field in RESTRICTION_FIELDS):
                return True
    return False


def _matched(slot_count, item_count, fits):
    """True when every slot takes a distinct item it fits (a bipartite matching)."""
    owner = [None] * item_count

    def assign(slot, seen):
        for item in range(item_count):
            if item not in seen and fits(slot, item):
                seen.add(item)
                if owner[item] is None or assign(owner[item], seen):
                    owner[item] = slot
                    return True
        return False

    return all(assign(slot, set()) for slot in range(slot_count))


def test_mw_vectors_hold_the_draft_negatives_and_the_fail_closed_vector():
    """CONTRACT_297 r8 section 3 (R3): 3 positives; each of the draft's eleven negatives and the fail-closed vector."""
    _model, checker = head._era_checker(head.WEIGHTS)
    cases = _mw_cases()
    assert len([case for case in cases if _polarity(case) == "positive"]) == 3  # CONTRACT_297 r8 section 3
    negatives = [case for case in cases if _polarity(case) == "negative"]
    policy = checker.policy_facts(_reader_over(_mw_files()))
    codes = []
    for case in negatives:
        record = case.get("record")
        reader = checker._source_reader(case.get("sources") or {})
        codes.append(set(_codes(checker.check_record(record, reader, policy))) if isinstance(record, dict) else set())
    wanted = [_mw_code(rule) for _name, rule in MW_DRAFT_NEGATIVES]
    for name, rule in MW_DRAFT_NEGATIVES:
        assert any(_mw_code(rule) in found for found in codes), name  # CONTRACT_297 r8 R3; R06 step 4 r2 section 5
    assert any(_mw_fail_closed(case) for case in negatives)  # CONTRACT_297 r8 R3 (the fail-closed vector)

    def fits(slot, item):
        if slot < len(wanted):
            return wanted[slot] in codes[item]
        return _mw_fail_closed(negatives[item])

    assert _matched(len(wanted) + 1, len(negatives), fits)  # CONTRACT_297 r8 R3 (each present, distinct vectors)


def test_mw_committed_record_and_c7_literal_zero():
    """CONTRACT_297 section 3: C-7's literal 0 over the parsed empty consumers; the record passes."""
    _model, checker = head._era_checker(head.WEIGHTS)
    record = _mw_committed()
    assert "consumers" in record  # R06 step 4 r2 section 3 (top-level consumers)
    consumers = record["consumers"]
    assert isinstance(consumers, list)  # R06 step 4 r2 C-7
    assert len(consumers) == 0  # CONTRACT_297 section 3; R06 step 4 r2 C-7 (literal 0)
    policy = checker.policy_facts(_reader_over(_mw_files()))
    assert _codes(checker.check_record(record, checker._source_reader({}), policy)) == []  # R06 step 4 r2 section 5
    assert _codes(checker.check(_reader_over(_mw_files()))) == []  # CONTRACT_297 section 3 (E1: refusals [])


@pytest.mark.parametrize("name, rule", MW_NEGATIVES, ids=[row[0] for row in MW_NEGATIVES])
def test_mw_negative_refused_with_rule_code(name, rule):
    """CONTRACT_297 section 3: each of the 11 negatives against its rule (R06 step 4 r2 section 5)."""
    _model, checker = head._era_checker(head.WEIGHTS)
    positives = [case for case in _mw_cases() if _polarity(case) == "positive"]
    policy = checker.policy_facts(_reader_over(_mw_files()))
    record, sources = _mw_build(name, _mw_committed(), positives, checker, policy)
    codes = _codes(checker.check_record(record, checker._source_reader(sources), policy))
    assert _mw_code(rule) in codes, codes  # R06 step 4 r2 section 5 (the rule each negative breaks)


def test_mw_served_positives_pass():
    """R06 step 4 r2 section 5: the two served positives pass check_record (controls for the negatives)."""
    _model, checker = head._era_checker(head.WEIGHTS)
    positives = [case for case in _mw_cases() if _polarity(case) == "positive"]
    policy = checker.policy_facts(_reader_over(_mw_files()))
    for outcome in ("DEFAULT_ALLOWED", "OPTIONAL_EXPLICIT_REVIEW"):
        case, _row_id = _mw_served(positives, outcome)
        assert case is not None, outcome  # R06 step 4 r2 section 5 (positives 2 and 3)
        reader = checker._source_reader(case.get("sources", {}))
        assert _codes(checker.check_record(case["record"], reader, policy)) == []  # R06 step 4 r2 section 5


@pytest.mark.parametrize("field", RESTRICTION_FIELDS)
def test_mw_null_restriction_never_yields_allow(field):
    """CONTRACT_297 section 3 (the rows file): a null in any restriction field never yields ALLOW."""
    _model, checker = head._era_checker(head.WEIGHTS)
    files = _mw_files()
    record_path = _rel(_field(head.WEIGHTS, "record"))
    raw = files[record_path]
    original = json.loads(raw)
    mutated = copy.deepcopy(original)
    allowing = [row for row in mutated["releases"] if _mw_outcome(row) == "DEFAULT_ALLOWED"]
    assert allowing, "no DEFAULT_ALLOWED row"  # R06 step 3 r2 section 4 (Qwen3-8B, DeepSeek-R1, GLM-4.5)
    restrictions = _mw_restrictions(allowing[0])
    assert isinstance(restrictions, dict), "no restriction fields on the allowing row"  # R06 step 4 r2 section 3
    assert _codes(checker.check(_reader_over(files))) == []  # CONTRACT_297 section 3 (E1: refusals [])
    restrictions[field] = None
    _list_null(mutated, allowing[0]["id"], field, original)  # relay A10 (CONTRACT_297 r8 section 3: nulls listed)
    files[record_path] = _dump_like(raw, original, mutated)
    assert _codes(checker.check(_reader_over(files))) != []  # CONTRACT_297 section 3 (never ALLOW with a null)


def test_mw_class_from_v3_amendment():
    """CONTRACT_297 section 3: C-3's class from the v3 amendment (R06 step 3 r2 section 5's fragment)."""
    amendment = _json(V3_AMENDMENT)
    holder = _find_key(amendment, "weightsLicenseClasses")
    assert holder is not None  # R06 step 4 r2 section 2 (amendment.json holds weightsLicenseClasses)
    classes = holder["weightsLicenseClasses"]
    assert classes["scope"] == "MODEL_WEIGHTS"  # R06 step 3 r2 section 5
    assert classes["matching"] == "PINNED_LICENSE_TEXT"  # R06 step 3 r2 section 5 (W-1)
    assert classes["precedence"] == WEIGHTS_PRECEDENCE  # R06 step 3 r2 sections 2 and 5
    assert classes["defaultAllowed"]["texts"] == ["Apache-2.0", "MIT"]  # R06 step 3 r2 section 5
    assert classes["denied"]["overrideAllowed"] is False  # R06 step 3 r2 section 5
    assert classes["unknown"]["releaseOutcome"] == "DENY_RELEASE"  # R06 step 3 r2 section 5
    review = classes["optionalExplicitReview"]
    assert review["releaseOutcomeWithoutApprovedDecision"] == "DENY_RELEASE"  # R06 step 3 r2 section 5
    assert review["requiredDecisionFields"] == REQUIRED_DECISION_FIELDS  # R06 step 3 r2 section 5
    mode = classes["distributionMode"]
    assert mode["bundle"] == ["DEFAULT_ALLOWED", "ALLOWED_EXCEPTION"]  # R06 step 3 r2 section 5 (W-5)
    assert mode["tenantFetched"] == ["OPTIONAL_EXPLICIT_REVIEW_APPROVED"]  # R06 step 3 r2 section 5 (W-5)


def test_mw_class_is_read_from_v3_amendment():
    """CONTRACT_297 section 3: C-3 applies the class read from the v3 amendment (M2 (a))."""
    _model, checker = head._era_checker(head.WEIGHTS)
    files = _mw_files()
    record = _mw_committed()
    assert _codes(checker.check_record(record, checker._source_reader({}), checker.policy_facts(_reader_over(files)))) == []  # R06 step 4 r2 section 5
    original = json.loads(files[V3_AMENDMENT])
    mutated = copy.deepcopy(original)
    _find_key(mutated, "weightsLicenseClasses")["weightsLicenseClasses"]["defaultAllowed"]["texts"] = []
    files[V3_AMENDMENT] = _dump_like(head.reviewed_bytes(V3_AMENDMENT), original, mutated)
    policy = checker.policy_facts(_reader_over(files))
    codes = _codes(checker.check_record(record, checker._source_reader({}), policy))
    assert _mw_code("C-3") in codes  # R06 step 4 r2 C-3 (DEFAULT_ALLOWED needs a defaultAllowed text)


def test_mw_base_policy_and_amendments_byte_identical():
    """CONTRACT_297 section 3: the base policy and A1/A2 byte-identical, at their operator-stated digests."""
    assert _sha256(head.reviewed_bytes(BASE_POLICY)) == BASE_POLICY_SHA256  # operator-stated
    assert _sha256(head.reviewed_bytes(A1_AMENDMENT)) == A1_SHA256  # operator-stated
    assert _sha256(head.reviewed_bytes(A2_AMENDMENT)) == A2_SHA256  # operator-stated
    assert BASE_POLICY_SHA256.startswith("fa3a4398")  # R06 step 4 r2 section 1 (the policy's full sha256)


MW_CHECK_MUTATIONS = ["duplicate-json-key", "key-outside-closed-schema", "vector-expectation-changed"]  # R06 step 4 r2 C-1, section 5


@pytest.mark.parametrize("mutation", MW_CHECK_MUTATIONS)
def test_mw_checker_refuses_stated_mutation(mutation):
    """R06 step 4 r2 C-1 and section 5: the checker's check(read) refuses each mutation r2 states."""
    _model, checker = head._era_checker(head.WEIGHTS)
    files = _mw_files()
    assert _codes(checker.check(_reader_over(files))) == []  # CONTRACT_297 section 3 (E1: refusals [])
    record_path = _rel(_field(head.WEIGHTS, "record"))
    vectors_path = _rel(_field(head.WEIGHTS, "vectors"))
    if mutation == "duplicate-json-key":
        raw = files[record_path]
        original = json.loads(raw)
        first = next(iter(original))
        body = raw.decode("utf-8").lstrip()
        assert body.startswith("{")  # R06 step 4 r2 section 3 (the record is one JSON object)
        duplicate = "{" + json.dumps(first) + ": " + json.dumps(original[first]) + ", " + body[1:]
        files[record_path] = duplicate.encode("utf-8")
    elif mutation == "key-outside-closed-schema":
        raw = files[record_path]
        original = json.loads(raw)
        mutated = copy.deepcopy(original)
        mutated["oracleKeyOutsideSchema"] = True
        files[record_path] = _dump_like(raw, original, mutated)
    else:
        raw = files[vectors_path]
        original = json.loads(raw)
        mutated = copy.deepcopy(original)
        negatives = [case for case in mutated["cases"] if _polarity(case) == "negative"]
        assert negatives  # R06 step 4 r2 section 5 (11 negatives)
        negatives[0]["expect"] = {"refusals": []}
        files[vectors_path] = _dump_like(raw, original, mutated)
    assert _codes(checker.check(_reader_over(files))) != []  # R06 step 4 r2 C-1 and section 5


# ---------------------------------------------------------------------------------------------------------------
# Part 4: the head layer (CONTRACT_297 sections 3 and 4): V1, E1, E2, E3, V4, V6.
# ---------------------------------------------------------------------------------------------------------------


def test_head_constants_and_members_table():
    """CONTRACT_297 sections 1, 3 and 4: the head's names, paths and its MEMBERS rows in section 1's order."""
    assert head.NEW_PACKET == NEW_PACKET  # operator-stated; CONTRACT_297 section 1
    assert tuple(head.PRODUCT_PACKETS) == (PRODUCT,)  # operator-stated; CONTRACT_297 section 1
    assert _rel(head.AUTHORITY_PATH) == AUTHORITY_PATH  # CONTRACT_297 section 4
    assert _rel(head.REGISTRY_PATH) == REGISTRY_PATH  # CONTRACT_297 section 5
    rows = list(head.MEMBERS)
    assert [_field(row, "item") for row in rows] == [REDTEAM_ITEM, WEIGHTS_ITEM]  # CONTRACT_297 section 1 (order)
    assert _field(head.REDTEAM, "item") == REDTEAM_ITEM  # operator-stated (REDTEAM row)
    assert _field(head.WEIGHTS, "item") == WEIGHTS_ITEM  # operator-stated (WEIGHTS row)
    for key, path in REDTEAM_PATHS.items():
        assert _rel(_field(head.REDTEAM, key)) == path  # CONTRACT_297 section 3 (member table)
    for key, path in WEIGHTS_PATHS.items():
        assert _rel(_field(head.WEIGHTS, key)) == path  # CONTRACT_297 section 3 (member table)
    assert _field(head.WEIGHTS, "model") is None  # CONTRACT_297 section 3 (model: none); operator-stated
    assert list(_field(head.REDTEAM, "bases")) == []  # operator-stated
    assert list(_field(head.WEIGHTS, "bases")) == []  # operator-stated


def test_v1_packet_files():
    """CONTRACT_297 section 4 (V1): the packet files pass at their era pins and a changed or missing file is refused."""
    assert head.validate_packet_files() is None  # operator-stated (validate_* passes on the live inputs)
    rels = [_rel(path) for path in head.PACKET_FILES]
    assert len(rels) == 14  # operator-stated (c1's 14 files)
    assert set(rels) == PACKET_FILES_EXPECTED  # CONTRACT_297 section 3; operator-stated
    readable = {
        PRODUCT_YAML,
        REDTEAM_PATHS["record"],
        REDTEAM_PATHS["schema"],
        REDTEAM_PATHS["vectors"],
        WEIGHTS_PATHS["record"],
        WEIGHTS_PATHS["schema"],
        WEIGHTS_PATHS["vectors"],
        V3_AMENDMENT,
        V3_README,
    }
    files = {path: head.reviewed_bytes(_rel(path)) for path in head.PACKET_FILES if _rel(path) in readable}
    changed = dict(files)
    target = [path for path in changed if _rel(path) == REDTEAM_PATHS["record"]][0]
    changed[target] = _flip_byte(changed[target])
    assert HEAD_MESSAGE in _refuses(head.check_packet_files, changed)  # operator-stated
    missing = dict(files)
    del missing[[path for path in missing if _rel(path) == PRODUCT_YAML][0]]
    assert HEAD_MESSAGE in _refuses(head.check_packet_files, missing)  # operator-stated


def test_e1_redteam(catalog):
    """CONTRACT_297 section 3 (E1, GR-REDTEAM-FIXTURES-001): refusals [] and every case replays."""
    assert head.validate_redteam_fixtures(dict(catalog)) is None  # operator-stated (passes on live inputs)
    vectors = _json(_field(head.REDTEAM, "vectors"))
    count = len(vectors["cases"])
    assert head.check_redteam_fixtures(vectors, [], [True] * count) is None  # CONTRACT_297 section 3 (E1 form)
    refusal = [("SHAPE", "a refusal")]
    assert HEAD_MESSAGE in _refuses(head.check_redteam_fixtures, vectors, refusal, [True] * count)  # operator-stated
    one_false = [True] * count
    one_false[-1] = False
    assert HEAD_MESSAGE in _refuses(head.check_redteam_fixtures, vectors, [], one_false)  # operator-stated
    shorter = [True] * (count - 1)
    assert HEAD_MESSAGE in _refuses(head.check_redteam_fixtures, vectors, [], shorter)  # operator-stated


def test_e1_weights(catalog):
    """CONTRACT_297 section 3 (E1, MODEL-WEIGHTS-POLICY-001): refusals [], with no replay half."""
    assert head.validate_model_weights(dict(catalog)) is None  # operator-stated (passes on live inputs)
    assert head.check_model_weights([]) is None  # CONTRACT_297 section 3 (E1: refusals [])
    refusal = [(_mw_code("C-7"), "a refusal")]
    assert HEAD_MESSAGE in _refuses(head.check_model_weights, refusal)  # operator-stated


def test_e2_base_files():
    """CONTRACT_297 sections 1 and 3 (E2): the base files keep their bytes and no base file is changed."""
    assert head.validate_base_files() is None  # operator-stated (passes on live inputs)
    rels = {_rel(path) for path in head.BASE_FILES}
    for path in (COMPARATOR_YAML, BASE_POLICY, A1_AMENDMENT, A2_AMENDMENT) + WHOLE_FILE_SCRIPTS:
        assert path in rels, path  # CONTRACT_297 sections 1 and 3 (base files; fix 1's whole-file pins)
    for path in SEGMENT_VALIDATORS:
        assert path not in rels, path  # CONTRACT_297 section 3 (fix 1: the validators leave E2's named set)
    authority = head.authority()
    changed = authority["changedFiles"]
    new = authority["newFiles"]
    for path in SEGMENT_VALIDATORS:
        assert path in {_rel(key) for key in changed}, path  # CONTRACT_297 section 3 (fix 1: cascade-only hunks)
    readable = {COMPARATOR_YAML, BASE_POLICY, A1_AMENDMENT, A2_AMENDMENT}
    files = {path: head.reviewed_bytes(_rel(path)) for path in head.BASE_FILES if _rel(path) in readable}
    flipped = dict(files)
    target = [path for path in flipped if _rel(path) == BASE_POLICY][0]
    flipped[target] = _flip_byte(flipped[target])
    assert HEAD_MESSAGE in _refuses(head.check_base_files, flipped, changed, new)  # operator-stated
    named = dict(changed)
    named[BASE_POLICY] = copy.deepcopy(next(iter(changed.values())))
    assert HEAD_MESSAGE in _refuses(head.check_base_files, files, named, new)  # operator-stated


def _reclass(value, word):
    if isinstance(value, str):
        return word
    if isinstance(value, list):
        return [_reclass(item, word) for item in value]
    if isinstance(value, dict):
        result = dict(value)
        hit = False
        for key in ("class", "classes", "kind"):
            if key in result:
                result[key] = _reclass(result[key], word)
                hit = True
        if not hit:
            result = {key: _reclass(item, word) for key, item in result.items()}
        return result
    return word


def _class_mutation(classes, avoid, word, candidates):
    mutated = copy.deepcopy(classes)
    if isinstance(mutated, dict):
        for key in list(mutated):
            if _rel(key) not in avoid:
                mutated[key] = _reclass(mutated[key], word)
                return mutated
        spare = [path for path in candidates if _rel(path) not in avoid]
        if mutated and spare:
            mutated[spare[0]] = _reclass(copy.deepcopy(next(iter(mutated.values()))), word)
            return mutated
        return None
    if isinstance(mutated, list):
        for entry in mutated:
            if isinstance(entry, dict) and "path" in entry and _rel(entry["path"]) not in avoid:
                for key in ("class", "classes", "kind"):
                    if key in entry:
                        entry[key] = _reclass(entry[key], word)
                        return mutated
    return None


def test_e3_errata():
    """CONTRACT_297 section 4 (E3): the errata pass; an `other` class outside ERRATA_LINES is refused."""
    assert head.validate_errata() is None  # operator-stated (passes on live inputs)
    record = _json(HUNK_RECORD_PATH)
    classes = record["classes"]
    changed = head.authority()["changedFiles"]
    changed_rels = {_rel(key) for key in changed}
    errata = list(head.ERRATA_LINES)
    for path in errata:
        assert _rel(path) in changed_rels, "an ERRATA_LINES path outside changedFiles"  # operator-stated (E3 befores)
    befores = {path: head._undo_this_layer(path, head.reviewed_bytes(_rel(path))) for path in errata}
    assert head.check_errata(classes, changed, befores) is None  # operator-stated (E3 on live inputs)
    mutated = _class_mutation(classes, {_rel(path) for path in errata}, "other", list(changed))
    assert mutated is not None, "no class entry outside ERRATA_LINES to mark other"  # CONTRACT_297 section 4
    assert HEAD_MESSAGE in _refuses(head.check_errata, mutated, changed, befores)  # operator-stated


def _registry_entries(registry):
    if isinstance(registry, list):
        return registry
    for items in _lists(registry):
        if items and "MET-015" in json.dumps(items[-1]):
            return items
    return []


def _is_rider(entry):
    strings = _strings(entry)
    return any(RIDER in text for text in strings) or ({"MET-015", "packet"} <= strings)


def test_v4_registry():
    """CONTRACT_297 sections 1 and 5 (V4): the registry is the base plus the one MET-015/packet rider, 44 entries."""
    assert head.validate_registry() is None  # operator-stated (passes on live inputs)
    raw = head.reviewed_bytes(REGISTRY_PATH)
    briefs = {head.PACKET_BRIEF: head.reviewed_bytes(_rel(head.PACKET_BRIEF))}
    assert head.check_registry(raw, briefs) is None  # operator-stated (V4 on live inputs)
    registry = json.loads(raw)
    entries = _registry_entries(registry)
    assert len(entries) == REGISTRY_ENTRIES  # operator-stated; CONTRACT_297 section 1 (43 -> 44)
    assert _is_rider(entries[-1])  # CONTRACT_297 section 1 (the one MET-015/packet rider, last)
    assert not any("MET-015" in json.dumps(entry) for entry in entries[:-1])  # CONTRACT_297 section 1 (one rider)
    base_only = copy.deepcopy(registry)
    del _registry_entries(base_only)[-1]
    assert HEAD_MESSAGE in _refuses(head.check_registry, _dump_like(raw, registry, base_only), briefs)  # operator-stated
    twice = copy.deepcopy(registry)
    twice_entries = _registry_entries(twice)
    twice_entries.append(copy.deepcopy(twice_entries[-1]))
    assert HEAD_MESSAGE in _refuses(head.check_registry, _dump_like(raw, registry, twice), briefs)  # operator-stated


def _v6_inputs():
    raw = head.reviewed_bytes(HUNK_RECORD_PATH)
    record = json.loads(raw)
    authority = head.authority()
    changed = authority["changedFiles"]
    afters = {path: head.reviewed_bytes(_rel(path)) for path in changed}
    classify = head._era_rule(head.READER_PATH, head.READER_NAME).classify
    context = head._v24_context(authority, record["hunkClassContext"])
    return raw, record, changed, afters, classify, context


V6_MUTATIONS = ["closed-members", "vocabulary", "rule-digest", "steps", "count-pairs"]  # operator-stated (V6, 296's form)


def test_v6_hunk_record_live():
    """CONTRACT_297 section 4 (V6): the hunk-class record passes; K = 1 gives steps [1, 2] and countPairs []."""
    assert head.validate_hunk_record() is None  # operator-stated (passes on live inputs)
    raw, record, changed, afters, classify, context = _v6_inputs()
    assert head.check_hunk_record(raw, changed, afters, classify, context, head.HUNK_RULE_SHA256) is None  # operator-stated
    steps = _find_key(record, "steps")
    pairs = _find_key(record, "countPairs")
    assert steps is not None and steps["steps"] == [1, 2]  # operator-stated (K = 1); CONTRACT_297 section 1
    assert pairs is not None and pairs["countPairs"] == []  # operator-stated (K = 1)


@pytest.mark.parametrize("mutation", V6_MUTATIONS)
def test_v6_hunk_record_refusals(mutation):
    """CONTRACT_297 section 4 (V6): closed members, vocabulary, v2.5's rule digest, steps and countPairs."""
    raw, record, changed, afters, classify, context = _v6_inputs()
    mutated = copy.deepcopy(record)
    rule_sha = head.HUNK_RULE_SHA256
    if mutation == "closed-members":
        mutated["oracleMemberOutsideSet"] = True
    elif mutation == "vocabulary":
        mutated["classes"] = _class_mutation(mutated["classes"], set(), "oracle-word-outside-vocabulary", list(changed))
        assert mutated["classes"] is not None  # operator-stated (the record carries classes)
    elif mutation == "rule-digest":
        rule_sha = _other_hex(str(rule_sha))
    elif mutation == "steps":
        _find_key(mutated, "steps")["steps"] = [1, 2, 3]
    else:
        _find_key(mutated, "countPairs")["countPairs"] = [[1, 2]]
    new_raw = raw if mutation == "rule-digest" else _dump_like(raw, record, mutated)
    message = _refuses(head.check_hunk_record, new_raw, changed, afters, classify, context, rule_sha)
    assert HEAD_MESSAGE in message  # operator-stated


def test_validate_met_015_whole_and_canonical_hunks(catalog):
    """CONTRACT_297 section 4: the head's entry runs every check in order on the live inputs."""
    assert head.validate_canonical_hunks() is None  # operator-stated
    assert head.validate_met_015(dict(catalog)) is None  # operator-stated


# ---------------------------------------------------------------------------------------------------------------
# Part 5: the packet YAML, the catalog, the table and the registry (CONTRACT_297 sections 1, 5 and 6).
# ---------------------------------------------------------------------------------------------------------------


def test_met_015_yaml():
    """CONTRACT_297 section 5: MET-015.yaml's id, its predecessor MET-014 and its contracts line."""
    raw = head.reviewed_bytes(NEW_PACKET_YAML)
    packet = head.safe_load(raw)
    assert len(packet) == 16  # operator-stated (16 keys)
    assert len(raw.decode("utf-8").splitlines()) == 16  # operator-stated (each key on one line)
    assert packet["id"] == NEW_PACKET  # CONTRACT_297 section 1
    assert packet["predecessors"] == [PREV_PACKET]  # CONTRACT_297 section 5
    contracts = packet["contracts"]
    line = contracts[0] if isinstance(contracts, list) else contracts
    assert BASE_MAIN in line  # CONTRACT_297 section 5 (names the merge commit)
    assert BASE_TREE_SHORT in line  # CONTRACT_297 section 5 (and its tree)
    assert "322 packets at slot 297" in packet["objective"]  # CONTRACT_297 section 5
    allowed = set(packet["allowedPaths"])
    for path in (AUTHORITY_PATH, HEAD_PATH, NEW_PACKET_YAML, PRODUCT_YAML, HUNK_RECORD_PATH, REGISTRY_PATH, TABLE_PATH):
        assert path in allowed, path  # CONTRACT_297 sections 4, 5 and 6
    for path in PACKET_FILES_EXPECTED:
        assert path in allowed, path  # CONTRACT_297 section 5 (the product and the members' files)


def test_historical_catalog_peels_to_the_era_catalog(catalog):
    """CONTRACT_297 section 4b: the current catalog (the helper) peels to the authority's baselinePackets ids."""
    baseline = head.authority()["baselinePackets"]
    era = head.historical_catalog(dict(catalog))
    assert set(era) == set(baseline)  # operator-stated; CONTRACT_297 section 4b (peel on the era catalog)
    assert len(baseline) == BASE_IDS  # CONTRACT_297 section 1 (base ids 320)
    assert PREV_PACKET in baseline  # CONTRACT_297 section 5 (320 packets including MET-014)
    assert NEW_PACKET not in baseline and PRODUCT not in baseline  # CONTRACT_297 section 1 (absent at main)


@pytest.mark.parametrize("change", ["less-product", "plus-one-id"])
def test_historical_catalog_refusals(catalog, change):
    """CONTRACT_297 section 4b (N1): the current catalog less the product, or plus one id, is refused."""
    packets = dict(catalog)
    if change == "less-product":
        del packets[PRODUCT]
    else:
        extra = copy.deepcopy(packets[NEW_PACKET])
        extra["id"] = "ORACLE-EXTRA-PACKET-001"
        packets["ORACLE-EXTRA-PACKET-001"] = extra
    message = _refuses(head.historical_catalog, packets)
    assert PEEL_MESSAGE in message  # operator-stated


def test_weights_table():
    """CONTRACT_297 section 6 (GATE_CI): 223 entries, the two new rows, no member-test row, regular files."""
    raw = head.reviewed_bytes(TABLE_PATH)
    parsed = json.loads(raw, object_pairs_hook=_pairs_hook)
    tables = [item for item in _walk(parsed) if isinstance(item, dict) and HEAD_TEST in item]
    assert len(tables) == 1  # CONTRACT_297 section 6 (tests/test_met_015.py holds a row)
    table = tables[0]
    assert table.raw_keys == list(table.keys())  # CONTRACT_297 section 6 (raw keys equal effective keys)
    assert len(table) == TABLE_ENTRIES  # operator-stated; CONTRACT_297 section 6 (221 -> 223)
    assert HEAD_TEST in table  # CONTRACT_297 section 6 (c2 row)
    assert OWN_ROW in table  # CONTRACT_297 section 6 (297's D5a file, c3)
    for path in MEMBER_TESTS:
        assert path not in table, path  # CONTRACT_297 section 6 (member tests take no row)
    for key in table:
        assert isinstance(head.reviewed_bytes(key), bytes), key  # CONTRACT_297 section 6 (each key a regular file)
