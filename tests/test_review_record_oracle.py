"""Oracle tests for review record v2 (REVIEW-RECORD-V2, packet MET-GOV-002).

Owner decision D5a: a contract packet carries tests written outside the candidate, so
that the candidate cannot snapshot its own output. These tests are black-box. Every
expected value is derived from the design dossier (revision 4: the records, the brief
registry, the checks and their ordered codes, the oracle identity, the merge rules and
the refusal vectors of sections 3 to 9, and the binding rules B-1 to B-10 of section 14,
which win where they refine an earlier section) and from the contract README. None is
taken from the candidate's vectors, tests or code; the model is reached only through its
public interface.

Every round, registry, oracle identity and frozen list here is the oracle's own, built
from the design's tables with made-up agentIds and digests computed with hashlib. Where
the design leaves a code open between named codes, the row accepts exactly those codes
and says why. Privacy shapes are built from parts at test time; name tokens and the
legacy term are exercised only through digests of made-up words.
"""

from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path

import jsonschema
import pytest

from scripts import review_record as rr

ROOT = Path(__file__).resolve().parents[1]
CONTRACT_DIR = ROOT / "architecture" / "review-record"
SCHEMA_DIR = ROOT / "schemas"

MISSING = object()


# --------------------------------------------------------------------------- helpers


def clone(value):
    """The oracle's own deep copy."""
    if isinstance(value, dict):
        return {key: clone(item) for key, item in value.items()}
    if isinstance(value, list):
        return [clone(item) for item in value]
    return value


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha_text(text: str) -> str:
    return sha(text.encode("utf-8"))


def hex40(seed: str) -> str:
    return hashlib.sha1(seed.encode("utf-8")).hexdigest()


def dump(value) -> bytes:
    """One non-canonical serialization of the oracle's own (the binding is the file's bytes, D-3)."""
    return json.dumps(value, indent=1, ensure_ascii=False).encode("utf-8") + b"\n"


def set_in(target, path, value):
    for key in path[:-1]:
        target = target[key]
    target[path[-1]] = value


def del_in(target, path):
    for key in path[:-1]:
        target = target[key]
    del target[path[-1]]


def node(doc, *path):
    for key in path:
        doc = doc[key]
    return doc


def _all_codes():
    out = set()
    for name in ("REVIEW_CODES", "SERIES_CODES", "ORACLE_CODES", "TREE_CODES", "MERGE_CODES"):
        out |= set(getattr(rr, name))
    return out


ALL_CODES = _all_codes()


def refusal(fn, *args):
    with pytest.raises(rr.Refused) as caught:
        fn(*args)
    code = caught.value.code
    assert code in ALL_CODES, code
    return code


def _schema(name):
    return json.loads((SCHEMA_DIR / name).read_text(encoding="utf-8"))


RECORD_SCHEMA_DOC = _schema("review-record.schema.json")
IDENTITY_SCHEMA_DOC = _schema("review-identity.schema.json")
ORACLE_SCHEMA_DOC = _schema("oracle-identity.schema.json")
BRIEFS_SCHEMA_DOC = _schema("review-briefs.schema.json")
RECORD_V = jsonschema.Draft202012Validator(RECORD_SCHEMA_DOC)
IDENTITY_V = jsonschema.Draft202012Validator(IDENTITY_SCHEMA_DOC)
ORACLE_V = jsonschema.Draft202012Validator(ORACLE_SCHEMA_DOC)
BRIEFS_V = jsonschema.Draft202012Validator(BRIEFS_SCHEMA_DOC)


# --------------------------------------------------------------------------- the design's tables

# B-6: the order of check_review.
B6_ORDER = (
    "NO_IDENTITY",
    "NO_BRIEF_DIGEST",
    "SHAPE",
    "UNKNOWN_KIND",
    "BINDING",
    "PLACEHOLDER_ID",
    "NOT_INDEPENDENT",
    "IDENTITY_MISMATCH",
    "SUBJECT_FORM",
    "SUBJECT_REPOSITORY",
    "BRIEF_NOT_FOR_SERIES",
    "BRIEF_SUPERSEDED",
    "VERDICT",
    "RULING",
    "SUBJECT_MISMATCH",
    "PRIVACY",
)
SERIES_CODE_SET = {"DUPLICATE_ROUND", "SERIES_GAP", "SERIES_FORK", "DUPLICATE_IDENTITY"}
# README: check_oracle checks SHAPE, PLACEHOLDER_ID, then ORACLE_DIGEST, NOT_INDEPENDENT, RULING and PRIVACY.
ORACLE_ORDER = ("SHAPE", "PLACEHOLDER_ID", "ORACLE_DIGEST", "NOT_INDEPENDENT", "RULING", "PRIVACY")

# Section 4 and the README's registry table: kind -> (verdicts, passing).
KIND_VERDICTS = {
    "DESIGN": (["PASS_FOR_BUILD", "CHANGES_REQUIRED"], ["PASS_FOR_BUILD"]),
    "CONTRACT": (
        ["PASS_FOR_ADOPTION", "PASS_FOR_SOURCE_PUBLICATION", "CHANGES_REQUIRED"],
        ["PASS_FOR_ADOPTION", "PASS_FOR_SOURCE_PUBLICATION"],
    ),
    # MET-GOV-002 r1: RR2C1-9 (the monitor's first option): PACKET passes with PASS_FOR_PUSH only.
    "PACKET": (["PASS_FOR_PRECHECK", "PASS_FOR_PUSH", "CHANGES_REQUIRED"], ["PASS_FOR_PUSH"]),
    "PR": (["PASS_FOR_PUSH", "CHANGES_REQUIRED"], ["PASS_FOR_PUSH"]),
}

# Section 3: the named placeholders, and the v1 placeholder the pattern refuses.
PLACEHOLDER_VALUES = ["stamped_by_operator", "recorded-by-the-launcher", "unknown", "none"]
V1_PLACEHOLDER = "STAMPED_BY_OPERATOR"

RECORD_REQUIRED = [
    "schemaVersion",
    "kind",
    "series",
    "round",
    "subject",
    "reviewDate",
    "briefSha256",
    "rulesSha256",
    "wrapperSha256",
    "reviewer",
    "verdict",
    "findings",
    "checked",
    "disclosures",
]
RECORD_OPTIONAL = ["base", "bindingRules", "dispositions", "notChecked", "questions"]
IDENTITY_REQUIRED = [
    "schemaVersion",
    "record",
    "reviewer",
    "operator",
    "author",
    "briefSha256",
    "rulesSha256",
    "wrapperSha256",
    "subject",
    "launched",
    "finished",
    "interruptions",
    "operatorRelays",
    "runs",
    "ruling",
]
ORACLE_REQUIRED = [
    "schemaVersion",
    "file",
    "oracle",
    "operator",
    "author",
    "briefSha256",
    "candidateCommit",
    "launched",
    "finished",
    "ruling",
]

# The oracle's own identities: made-up ids matching ^[a-z0-9][a-z0-9_-]{7,79}$.
MODEL = "model-alpha"
REVIEWER_ID = "agent-review-0001"
OPERATOR_ID = "session-lane-0001"
AUTHOR_IDS = ["session-author-0001", "session-author-0002"]
ORACLE_ID = "agent-oracle-0001"


def brief_bytes(tag):
    return ("# Oracle synthetic brief " + tag + "\n\nPlaceholders only.\n").encode("utf-8")


BRIEF_TAGS = ("DSN", "CTR", "PKT", "PR1", "PR2", "OTHER", "PFX", "PFX2", "SH", "OLD", "NEW", "ORACLE")
BRIEF = {tag: sha(brief_bytes(tag)) for tag in BRIEF_TAGS}
UNREGISTERED_BRIEF = sha(b"an unregistered brief\n")
RULES = sha(b"oracle synthetic round rules\n")
WRAPPER = sha(b"oracle synthetic wait wrapper\n")
CUTOVER = "2026-10-20T12:00:00+00:00"
PR_BRIEF_PATH = "architecture/orc-pr/REVIEW_BRIEF.md"
UPPER40 = "ABCDEF0123" * 4


def brief_entry(kind, series, tag, version=1, path=None, **extra):
    out = {
        "kind": kind,
        "series": series,
        "path": path or "architecture/orc-" + tag.lower() + "/REVIEW_BRIEF.md",
        "sha256": BRIEF[tag],
        "version": version,
    }
    out.update(extra)
    return out


def registry_value():
    return {
        "schemaVersion": "planeon.review-briefs/v1",
        "kinds": {kind: {"verdicts": list(v), "passing": list(p)} for kind, (v, p) in KIND_VERDICTS.items()},
        "briefs": [
            brief_entry("DESIGN", "ORC-DSN/design", "DSN"),
            brief_entry("CONTRACT", "ORC-CTR/contract", "CTR"),
            brief_entry("PACKET", "ORC-PKT/packet", "PKT"),
            brief_entry("PR", "ORC-PR/pr", "PR1", 1, PR_BRIEF_PATH, supersededAt=CUTOVER),
            brief_entry("PR", "ORC-PR/pr", "PR2", 2, PR_BRIEF_PATH, supersedes=BRIEF["PR1"]),
            brief_entry("PR", "ORC-OTHER/pr", "OTHER"),
            brief_entry("PR", "ORC-PFX/", "PFX"),
            brief_entry("PR", "ORC-SH/", "SH"),
        ],
    }


def load_registry(value=None):
    return rr.load_registry(dump(registry_value() if value is None else value))


def repo_subject(seed, repository="harness-onion"):
    return {"repository": repository, "commit": hex40("commit " + seed), "tree": hex40("tree " + seed)}


S = {n: repo_subject("s" + str(n)) for n in range(1, 6)}
NOTE_SUBJECT = {"path": "notes/orc-design-note.md", "sha256": sha(b"oracle design note\n")}
HEAD = {"commit": S[1]["commit"], "tree": S[1]["tree"]}
SQUASH_HEAD = {"commit": hex40("squash of s1"), "tree": S[1]["tree"]}
OTHER_HEAD = {"commit": hex40("another head"), "tree": hex40("another tree")}

# Privacy shapes, built from parts so that no file holds them (RR1-13).
EMAIL_SHAPE = "orc.user" + chr(64) + "example.org"
HOME_SHAPES = ["/" + "Us" + "ers/" + "orcuser/work", "/" + "ho" + "me/" + "orcuser/work"]

KEEP = {"decision": "KEEP", "by": "LANE_MONITOR", "ref": "MON-ORC-1", "date": "2026-10-21"}
VOID = {"decision": "VOID", "by": "OWNER", "ref": "OWN-ORC-1", "date": "2026-10-21"}
FINDING = {
    "id": "ORC-1",
    "severity": "MINOR",
    "location": "README.md",
    "finding": "a synthetic finding",
    "requiredChange": "a synthetic change",
    "blocks": False,
}


# --------------------------------------------------------------------------- the oracle's builders

KIND_DEFAULTS = {
    "DESIGN": ("ORC-DSN/design", "DSN", "PASS_FOR_BUILD", "orc-dsn"),
    "CONTRACT": ("ORC-CTR/contract", "CTR", "PASS_FOR_ADOPTION", "orc-ctr"),
    "PACKET": ("ORC-PKT/packet", "PKT", "PASS_FOR_PUSH", "orc-pkt"),
    "PR": ("ORC-PR/pr", "PR2", "PASS_FOR_PUSH", "orc-pr"),
}


class Round:
    """A valid v2 round of the oracle's own (DESIGN section 3), with its check context."""

    def __init__(self, kind="PR", n=1, *, subject=None, base=None, directory=None, series=None, tag=None,
                 verdict=None):
        d_series, d_tag, d_verdict, d_dir = KIND_DEFAULTS[kind]
        series = series or d_series
        tag = tag or d_tag
        verdict = verdict or d_verdict
        directory = directory or d_dir
        if subject is None:
            subject = NOTE_SUBJECT if kind == "DESIGN" else S[n]
        self.record_path = "architecture/" + directory + "/review-round" + str(n) + ".json"
        self.identity_path = "architecture/" + directory + "/review-identity-round" + str(n) + ".json"
        self.record = {
            "schemaVersion": "planeon.review-record/v2",
            "kind": kind,
            "series": series,
            "round": n,
            "subject": clone(subject),
            "reviewDate": "2026-10-21",
            "briefSha256": BRIEF[tag],
            "rulesSha256": RULES,
            "wrapperSha256": WRAPPER,
            "reviewer": {"model": MODEL, "role": "REVIEWER_AGENT"},
            "verdict": verdict,
            "findings": [],
            "checked": ["synthetic round checked"],
            "disclosures": [],
        }
        self.identity = {
            "schemaVersion": "planeon.review-identity/v2",
            "record": {"path": self.record_path, "sha256": ""},
            "reviewer": {"agentId": REVIEWER_ID, "agentType": "general-purpose", "model": MODEL},
            "operator": {"role": "LANE_SESSION", "agentId": OPERATOR_ID, "lane": "PARALLEL"},
            "author": {"agentIds": list(AUTHOR_IDS)},
            "briefSha256": BRIEF[tag],
            "rulesSha256": RULES,
            "wrapperSha256": WRAPPER,
            "subject": clone(subject),
            "launched": "2026-10-21T09:00:00+00:00",
            "finished": "2026-10-21T10:30:00+00:00",
            "interruptions": [],
            "operatorRelays": [],
            "runs": [{"limit": "test runs", "used": 2}],
            "ruling": {"decision": "NONE_NEEDED"},
        }
        if base is not None:
            self.record["base"] = clone(base)
            self.identity["base"] = clone(base)
        self.registry = registry_value()
        self.head = None
        self.repository = None
        self.rebind = True
        self.no_identity = False
        self.raw_record = None
        self.raw_identity = None

    def both(self, key, value):
        self.record[key] = clone(value)
        self.identity[key] = clone(value)
        return self

    def record_bytes(self):
        return self.raw_record if self.raw_record is not None else dump(self.record)

    def identity_value(self):
        value = clone(self.identity)
        bound = value.get("record")
        if self.rebind and isinstance(bound, dict) and "sha256" in bound:
            bound["sha256"] = sha(self.record_bytes())
        return value

    def identity_bytes(self):
        if self.no_identity:
            return None
        if self.raw_identity is not None:
            return self.raw_identity
        return dump(self.identity_value())

    def check(self):
        return rr.check_review(
            self.record_bytes(),
            self.record_path,
            self.identity_bytes(),
            self.identity_path,
            rr.load_registry(dump(self.registry)),
            self.head,
            self.repository,
        )

    def code(self):
        return refusal(self.check)

    def pair(self):
        return (self.record_path, self.record_bytes()), (self.identity_path, self.identity_bytes())

    def cited(self):
        return {
            "record": self.record_bytes(),
            "recordPath": self.record_path,
            "identity": self.identity_bytes(),
            "identityPath": self.identity_path,
        }


def expected_facts(case, passing=True, decision="NONE_NEEDED"):
    kind = case.record["kind"]
    return {
        "kind": kind,
        "series": case.record["series"],
        "round": case.record["round"],
        "verdict": case.record["verdict"],
        "passing": passing,
        "headBound": kind in ("PACKET", "PR"),
        "decision": decision,
        "full": "base" not in case.record,
    }


ORACLE_FILE_PATH = "tests/test_orc_sample_oracle.py"
ORACLE_FILE_BYTES = b"def test_sample():\n    assert True\n"


class Oracle:
    """A valid oracle identity of the oracle's own (DESIGN section 6, B-5)."""

    def __init__(self, path=ORACLE_FILE_PATH, data=ORACLE_FILE_BYTES,
                 identity_path="architecture/orc-ctr/oracle-identity.json"):
        self.identity_path = identity_path
        self.file_bytes = data
        self.value = {
            "schemaVersion": "planeon.oracle-identity/v1",
            "file": {"path": path, "sha256": sha(data)},
            "oracle": {"agentId": ORACLE_ID, "model": MODEL},
            "operator": {"role": "LANE_SESSION", "agentId": OPERATOR_ID, "lane": "PARALLEL"},
            "author": {"agentIds": list(AUTHOR_IDS)},
            "briefSha256": BRIEF["ORACLE"],
            "candidateCommit": hex40("candidate"),
            "launched": "2026-10-21T09:00:00+00:00",
            "finished": "2026-10-21T11:00:00+00:00",
            "ruling": {"decision": "NONE_NEEDED"},
        }

    def bytes(self):
        return dump(self.value)

    def entry(self):
        return (self.identity_path, self.bytes())

    def check(self):
        return rr.check_oracle(self.bytes(), self.identity_path, self.file_bytes)

    def code(self):
        return refusal(self.check)


def rec(*path, value=MISSING):
    def mutate(case):
        if value is MISSING:
            del_in(case.record, path)
        else:
            set_in(case.record, path, clone(value))

    return mutate


def ident(*path, value=MISSING):
    def mutate(case):
        if value is MISSING:
            del_in(case.identity, path)
        else:
            set_in(case.identity, path, clone(value))

    return mutate


def both(key, value):
    def mutate(case):
        case.both(key, value)

    return mutate


def seq(*mutators):
    def mutate(case):
        for mutator in mutators:
            mutator(case)

    return mutate


def ova(*path, value=MISSING):
    def mutate(oracle):
        if value is MISSING:
            del_in(oracle.value, path)
        else:
            set_in(oracle.value, path, clone(value))

    return mutate


DIGEST_FORMS = [
    ("63 hex", lambda h: h[:63]),
    ("65 hex", lambda h: h + "a"),
    ("upper case", lambda h: h.upper()),
    ("sha256-prefixed", lambda h: "sha256:" + h),
    ("16 hex", lambda h: h[:16]),
]


# --------------------------------------------------------------------------- public constants


def test_review_codes_are_b6_order():
    assert isinstance(rr.REVIEW_CODES, tuple)
    assert rr.REVIEW_CODES == B6_ORDER


def test_code_tuples_name_the_readme_codes():
    for name in ("SERIES_CODES", "ORACLE_CODES", "TREE_CODES", "MERGE_CODES"):
        assert isinstance(getattr(rr, name), tuple), name
    assert set(rr.SERIES_CODES) == SERIES_CODE_SET
    assert {"ORACLE_DIGEST", "NOT_INDEPENDENT", "RULING"} <= set(rr.ORACLE_CODES)
    assert "ORACLE_MISSING" in set(rr.ORACLE_CODES) | set(rr.TREE_CODES)
    assert {"LEGACY_CHANGED", "NO_IDENTITY"} <= set(rr.TREE_CODES)
    assert "NO_HEAD_BOUND_ROUND" in rr.MERGE_CODES
    assert issubclass(rr.Refused, Exception)


def test_constants_follow_the_design():
    assert set(rr.KINDS) == set(KIND_VERDICTS)
    assert set(rr.HEAD_BOUND) == {"PACKET", "PR"}
    assert set(PLACEHOLDER_VALUES) <= set(rr.PLACEHOLDERS)
    assert set(rr.DECISIONS) == {"NONE_NEEDED", "PENDING", "KEEP", "VOID"}
    assert tuple(rr.ORACLE_TESTS) == ("tests/", "test_*oracle*.py")


def test_schema_ids_follow_the_design():
    pairs = [
        (rr.RECORD_SCHEMA, "planeon.review-record/v2", RECORD_SCHEMA_DOC),
        (rr.IDENTITY_SCHEMA, "planeon.review-identity/v2", IDENTITY_SCHEMA_DOC),
        (rr.ORACLE_SCHEMA, "planeon.oracle-identity/v1", ORACLE_SCHEMA_DOC),
        (rr.BRIEFS_SCHEMA, "planeon.review-briefs/v1", BRIEFS_SCHEMA_DOC),
    ]
    for constant, expected, doc in pairs:
        assert constant == expected
        assert doc["$id"] == expected
        assert doc["properties"]["schemaVersion"]["const"] == expected
        assert doc["$schema"] == "https://json-schema.org/draft/2020-12/schema"
    assert rr.LEGACY_SCHEMA == "planeon.legacy-review-records/v1"


def test_privacy_constants_hold_digests_only():
    # Q-RR2-NAMES (owner, relayed): the published table may be empty; only its form is checked here.
    assert isinstance(rr.NAME_TOKEN_SHA256, dict)
    for length, digests in rr.NAME_TOKEN_SHA256.items():
        assert isinstance(length, int) and length > 0
        assert isinstance(digests, tuple)
        assert all(isinstance(d, str) and re.fullmatch("[0-9a-f]{64}", d) for d in digests)
    assert isinstance(rr.LEGACY_TERM_PREFIX, str) and re.fullmatch("[0-9a-f]{16}", rr.LEGACY_TERM_PREFIX)


def test_name_tokens_have_a_local_loader():
    # Q-RR2-NAMES (owner, relayed): the checker fills the table from an unpublished local file.
    assert callable(getattr(rr, "load_name_tokens", None))


@pytest.mark.parametrize("data", [b"", b"abc", b"{}\n", "é".encode("utf-8")], ids=["empty", "abc", "json", "utf8"])
def test_file_sha256_is_64_lowercase_hex_of_the_bytes(data):
    assert rr.file_sha256(data) == hashlib.sha256(data).hexdigest()
    assert re.fullmatch("[0-9a-f]{64}", rr.file_sha256(data))


# --------------------------------------------------------------------------- I-JSON loading

BAD_IJSON = [
    ("duplicate member", b'{"a": 1, "a": 1}'),
    ("nested duplicate member", b'{"x": {"k": 1, "k": 2}}'),
    ("NaN", b'{"a": NaN}'),
    ("Infinity", b"[Infinity]"),
    ("minus Infinity", b"[-Infinity]"),
    ("lone high surrogate", b'["\\ud800"]'),
    ("lone low surrogate", b'["\\udc00"]'),
    ("lone surrogate in a key", b'{"\\ud83d": 1}'),
    ("reversed surrogate pair", b'["\\ude00\\ud83d"]'),
    ("invalid UTF-8", b'["\xff"]'),
    ("truncated", b'{"a": '),
    ("trailing data", b'{"a": 1} x'),
]


@pytest.mark.parametrize("name,raw", BAD_IJSON, ids=[n for n, _r in BAD_IJSON])
def test_load_refuses_non_ijson_as_shape(name, raw):
    assert refusal(rr.load, raw) == "SHAPE"
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        return
    assert refusal(rr.load, text) == "SHAPE"


def test_load_accepts_ijson():
    assert rr.load('["\\ud83d\\ude00"]') == ["\U0001f600"]
    assert rr.load(b'{"a": [1, true, null, "\\u00e9"]}') == {"a": [1, True, None, "é"]}
    assert rr.load(dump(registry_value())) == registry_value()


@pytest.mark.parametrize("name,raw", BAD_IJSON[:3], ids=[n for n, _r in BAD_IJSON[:3]])
def test_registry_and_frozen_list_refuse_non_ijson_as_shape(name, raw):
    assert refusal(rr.load_registry, raw) == "SHAPE"
    assert refusal(rr.load_legacy, raw) == "SHAPE"


# --------------------------------------------------------------------------- 1. shapes and schema agreement


def test_schema_members_follow_the_design():
    assert set(RECORD_SCHEMA_DOC["required"]) == set(RECORD_REQUIRED)
    assert set(RECORD_SCHEMA_DOC["properties"]) == set(RECORD_REQUIRED) | set(RECORD_OPTIONAL)
    assert set(IDENTITY_SCHEMA_DOC["required"]) == set(IDENTITY_REQUIRED)
    assert set(IDENTITY_SCHEMA_DOC["properties"]) == set(IDENTITY_REQUIRED) | {"base"}
    assert set(ORACLE_SCHEMA_DOC["required"]) == set(ORACLE_REQUIRED)
    for doc in (RECORD_SCHEMA_DOC, IDENTITY_SCHEMA_DOC, ORACLE_SCHEMA_DOC, BRIEFS_SCHEMA_DOC):
        assert doc["additionalProperties"] is False
    # The reviewer cannot attest its own agentId (section 3.1).
    assert "agentId" not in node(RECORD_SCHEMA_DOC, "properties", "reviewer", "properties")


def test_kind_and_every_agent_id_are_plain_strings_in_the_schemas():
    # B-6: no enum and no pattern, so UNKNOWN_KIND and PLACEHOLDER_ID stay reachable after SHAPE;
    # section 9 lists the empty agentId as a PLACEHOLDER_ID vector, so no minimum length either.
    kind = node(RECORD_SCHEMA_DOC, "properties", "kind")
    agent_ids = [
        node(IDENTITY_SCHEMA_DOC, "properties", "reviewer", "properties", "agentId"),
        node(IDENTITY_SCHEMA_DOC, "properties", "operator", "properties", "agentId"),
        node(IDENTITY_SCHEMA_DOC, "properties", "author", "properties", "agentIds", "items"),
        node(ORACLE_SCHEMA_DOC, "properties", "oracle", "properties", "agentId"),
        node(ORACLE_SCHEMA_DOC, "properties", "operator", "properties", "agentId"),
        node(ORACLE_SCHEMA_DOC, "properties", "author", "properties", "agentIds", "items"),
    ]
    for item in [kind] + agent_ids:
        assert item.get("type") == "string"
        assert not {"enum", "const", "pattern", "format"} & set(item)
    for item in agent_ids:
        assert item.get("minLength", 0) == 0


@pytest.mark.parametrize("kind", list(KIND_VERDICTS))
def test_a_valid_round_of_each_kind_passes(kind):
    case = Round(kind)
    assert RECORD_V.is_valid(case.record)
    assert IDENTITY_V.is_valid(case.identity_value())
    assert case.check() == expected_facts(case)


@pytest.mark.parametrize(
    "kind,verdict",
    [(k, v) for k, (verdicts, _p) in KIND_VERDICTS.items() for v in verdicts],
    ids=[k + "-" + v for k, (verdicts, _p) in KIND_VERDICTS.items() for v in verdicts],
)
def test_every_listed_verdict_passes_with_its_passing_fact(kind, verdict):
    case = Round(kind, verdict=verdict)
    assert case.check() == expected_facts(case, passing=verdict in KIND_VERDICTS[kind][1])


def test_a_delta_round_is_not_full():
    case = Round("CONTRACT", 2, base=S[1])
    assert RECORD_V.is_valid(case.record) and IDENTITY_V.is_valid(case.identity_value())
    facts = case.check()
    assert facts == expected_facts(case)
    assert facts["full"] is False


def _subject_mixed(case):
    case.record["subject"] = dict(clone(S[1]), path="notes/orc.md", sha256=NOTE_SUBJECT["sha256"])


RECORD_SHAPE_FAULTS = [("record without " + m, rec(m)) for m in RECORD_REQUIRED if m != "briefSha256"] + [
    ("record unknown member", rec("note", value="x")),
    ("record schemaVersion v1", rec("schemaVersion", value="planeon.review-record/v1")),
    ("record kind not a string", rec("kind", value=7)),
    ("record series lower case", rec("series", value="orc-pr/pr")),
    ("record series without a slash", rec("series", value="ORC-PR")),
    ("record series a prefix", rec("series", value="ORC-PR/")),
    ("record round a string", rec("round", value="1")),
    ("record round zero", rec("round", value=0)),
    ("record round negative", rec("round", value=-1)),
    ("record round a boolean", rec("round", value=True)),
    ("record round beyond 2^53-1", rec("round", value=2**53)),
    ("record subject unknown member", rec("subject", "branch", value="main")),
    ("record subject commit 7 hex", rec("subject", "commit", value="abc1234")),
    ("record subject commit upper case", rec("subject", "commit", value=UPPER40)),
    ("record subject tree 41 hex", rec("subject", "tree", value=S[1]["tree"] + "a")),
    ("record subject without repository", rec("subject", "repository")),
    ("record subject of both forms", _subject_mixed),
    ("record subject empty", rec("subject", value={})),
    ("record subject path absolute", rec("subject", value={"path": "/notes/orc.md", "sha256": NOTE_SUBJECT["sha256"]})),
    ("record subject path with dot-dot", rec("subject", value={"path": "notes/../orc.md", "sha256": NOTE_SUBJECT["sha256"]})),
    ("record subject sha256 63 hex", rec("subject", value={"path": "notes/orc.md", "sha256": NOTE_SUBJECT["sha256"][:63]})),
    ("record reviewDate with a time", rec("reviewDate", value="2026-10-21T09:00:00+00:00")),
    ("record reviewDate not RFC 3339", rec("reviewDate", value="21.10.2026")),
    ("record rulesSha256 not a string", rec("rulesSha256", value=5)),
    ("record reviewer with an agentId", rec("reviewer", "agentId", value=REVIEWER_ID)),
    ("record reviewer without role", rec("reviewer", "role")),
    ("record reviewer model empty", rec("reviewer", "model", value="")),
    ("record verdict empty", rec("verdict", value="")),
    ("record verdict not a string", rec("verdict", value=1)),
    ("record findings not a list", rec("findings", value="none")),
    ("record finding severity unknown", rec("findings", value=[dict(FINDING, severity="BLOCKER")])),
    ("record finding without blocks", rec("findings", value=[{k: v for k, v in FINDING.items() if k != "blocks"}])),
    ("record finding blocks not a boolean", rec("findings", value=[dict(FINDING, blocks="no")])),
    ("record finding unknown member", rec("findings", value=[dict(FINDING, note="x")])),
    ("record checked empty", rec("checked", value=[])),
    ("record checked empty string", rec("checked", value=[""])),
    ("record checked object without result", rec("checked", value=[{"check": "x"}])),
    ("record disclosures not a list", rec("disclosures", value="none")),
    ("record disclosures empty string", rec("disclosures", value=[""])),
    ("record bindingRules without note", rec("bindingRules", value=[{"rule": "B-1", "met": True}])),
    ("record dispositions status unknown", rec("dispositions", value=[{"id": "ORC-1", "status": "DONE"}])),
    ("record notChecked not strings", rec("notChecked", value=[1])),
    ("record questions not a list", rec("questions", value="why")),
    ("record base commit 7 hex", rec("base", value=dict(clone(S[1]), commit="abc1234"))),
] + [("record rulesSha256 " + n, rec("rulesSha256", value=f(RULES))) for n, f in DIGEST_FORMS] + [
    ("record wrapperSha256 " + n, rec("wrapperSha256", value=f(WRAPPER))) for n, f in DIGEST_FORMS
]


def record_digest(form):
    def mutate(case):
        case.rebind = False
        case.identity["record"]["sha256"] = form(sha(case.record_bytes()))

    return mutate


def ident_record_path(form):
    def mutate(case):
        case.identity["record"]["path"] = form(case.record_path)

    return mutate


IDENTITY_SHAPE_FAULTS = [("identity without " + m, ident(m)) for m in IDENTITY_REQUIRED if m != "briefSha256"] + [
    ("identity unknown member", ident("note", value="x")),
    ("identity schemaVersion v1", ident("schemaVersion", value="masra010.review-identity/v1")),
    ("identity record unknown member", ident("record", "size", value=1)),
    ("identity record without path", ident("record", "path")),
    ("identity record without sha256", ident("record", "sha256")),
    ("identity record path absolute", ident_record_path(lambda p: "/" + p)),
    ("identity record path with dot-dot", ident_record_path(lambda p: "architecture/../" + p)),
    ("identity reviewer unknown member", ident("reviewer", "lane", value="x")),
    ("identity reviewer without agentType", ident("reviewer", "agentType")),
    ("identity reviewer agentType empty", ident("reviewer", "agentType", value="")),
    ("identity reviewer agentId not a string", ident("reviewer", "agentId", value=5)),
    ("identity reviewer model empty", ident("reviewer", "model", value="")),
    ("identity operator role LANE_MONITOR", ident("operator", "role", value="LANE_MONITOR")),
    ("identity operator role OWNER", ident("operator", "role", value="OWNER")),
    ("identity operator without role", ident("operator", "role")),
    ("identity operator without agentId", ident("operator", "agentId")),
    ("identity operator unknown member", ident("operator", "model", value=MODEL)),
    ("identity operator lane empty", ident("operator", "lane", value="")),
    ("identity author empty", ident("author", "agentIds", value=[])),
    ("identity author repeated", ident("author", "agentIds", value=[AUTHOR_IDS[0], AUTHOR_IDS[0]])),
    ("identity author not a list", ident("author", "agentIds", value=AUTHOR_IDS[0])),
    ("identity author unknown member", ident("author", "lane", value="x")),
    ("identity rulesSha256 upper case", ident("rulesSha256", value=RULES.upper())),
    ("identity wrapperSha256 sha256-prefixed", ident("wrapperSha256", value="sha256:" + WRAPPER)),
    ("identity subject commit 7 hex", ident("subject", "commit", value="abc1234")),
    ("identity base commit 7 hex", ident("base", value=dict(clone(S[1]), commit="abc1234"))),
    ("identity launched without an offset", ident("launched", value="2026-10-21T09:00:00")),
    ("identity launched a date", ident("launched", value="2026-10-21")),
    ("identity finished with a space", ident("finished", value="2026-10-21 10:30:00+00:00")),
    ("identity interruptions not a list", ident("interruptions", value="none")),
    ("identity interruptions empty string", ident("interruptions", value=[""])),
    ("identity operatorRelays not strings", ident("operatorRelays", value=[1])),
    ("identity runs not a list", ident("runs", value={"limit": "test runs", "used": 1})),
    ("identity runs entry without used", ident("runs", value=[{"limit": "test runs"}])),
    ("identity runs used negative", ident("runs", value=[{"limit": "test runs", "used": -1}])),
    ("identity runs used a string", ident("runs", value=[{"limit": "test runs", "used": "2"}])),
    ("identity runs limit empty", ident("runs", value=[{"limit": "", "used": 1}])),
    ("identity runs entry unknown member", ident("runs", value=[{"limit": "x", "used": 1, "max": 3}])),
    ("identity ruling decision unknown", ident("ruling", value={"decision": "MAYBE"})),
    ("identity ruling without decision", ident("ruling", value={})),
    ("identity ruling by unknown", ident("ruling", value=dict(KEEP, by="SOMEONE"))),
    ("identity ruling date with a time", ident("ruling", value=dict(KEEP, date="2026-10-21T00:00:00Z"))),
    ("identity ruling ref empty", ident("ruling", value=dict(KEEP, ref=""))),
    ("identity ruling unknown member", ident("ruling", value={"decision": "NONE_NEEDED", "note": "x"})),
] + [("identity record sha256 " + n, record_digest(f)) for n, f in DIGEST_FORMS]

SHAPE_FAULTS = RECORD_SHAPE_FAULTS + IDENTITY_SHAPE_FAULTS


@pytest.mark.parametrize("name,mutator", SHAPE_FAULTS, ids=[n for n, _m in SHAPE_FAULTS])
def test_a_shape_fault_is_refused_as_shape(name, mutator):
    case = Round("PR")
    mutator(case)
    assert case.code() == "SHAPE"


@pytest.mark.parametrize("name,mutator", SHAPE_FAULTS, ids=[n for n, _m in SHAPE_FAULTS])
def test_the_matching_schema_rejects_each_shape_fault(name, mutator):
    case = Round("PR")
    mutator(case)
    if name.startswith("record "):
        assert not RECORD_V.is_valid(case.record)
        assert IDENTITY_V.is_valid(case.identity_value())
    else:
        assert RECORD_V.is_valid(case.record)
        assert not IDENTITY_V.is_valid(case.identity_value())


# Rules of SHAPE that no closed schema can state (README: "launched after finished").
@pytest.mark.parametrize(
    "launched",
    ["2026-10-21T11:00:00+00:00", "2026-10-21T10:00:00-01:00", "2026-10-21T10:30:00.000000001+00:00"],
    ids=["later", "later by offset", "later by a nanosecond"],
)
def test_launched_after_finished_is_shape(launched):
    case = Round("PR")
    case.identity["launched"] = launched
    assert case.code() == "SHAPE"


BRIEF_DIGEST_FAULTS = [("absent", MISSING)] + [(n, f(BRIEF["PR2"])) for n, f in DIGEST_FORMS] + [
    ("not a string", 5)
]


@pytest.mark.parametrize("name,value", BRIEF_DIGEST_FAULTS, ids=[n for n, _v in BRIEF_DIGEST_FAULTS])
def test_a_record_brief_digest_fault_is_no_brief_digest(name, value):
    case = Round("PR")
    if value is MISSING:
        del case.record["briefSha256"]
    else:
        case.record["briefSha256"] = value
    assert not RECORD_V.is_valid(case.record)
    assert case.code() == "NO_BRIEF_DIGEST"


@pytest.mark.parametrize("name,value", BRIEF_DIGEST_FAULTS, ids=[n for n, _v in BRIEF_DIGEST_FAULTS])
def test_an_identity_brief_digest_fault_is_refused_before_the_bindings(name, value):
    # Sections 5 and B-6 name "briefSha256" without saying which record; either presence-or-shape code fits.
    case = Round("PR")
    if value is MISSING:
        del case.identity["briefSha256"]
    else:
        case.identity["briefSha256"] = value
    assert not IDENTITY_V.is_valid(case.identity_value())
    assert case.code() in {"NO_BRIEF_DIGEST", "SHAPE"}


AFTER_SHAPE = [
    ("kind DELTA", "UNKNOWN_KIND", rec("kind", value="DELTA")),
    ("kind lower case", "UNKNOWN_KIND", rec("kind", value="pr")),
    ("kind empty", "UNKNOWN_KIND", rec("kind", value="")),
    ("reviewer placeholder", "PLACEHOLDER_ID", ident("reviewer", "agentId", value="stamped_by_operator")),
    ("reviewer v1 placeholder", "PLACEHOLDER_ID", ident("reviewer", "agentId", value=V1_PLACEHOLDER)),
    ("operator empty", "PLACEHOLDER_ID", ident("operator", "agentId", value="")),
    ("author unknown", "PLACEHOLDER_ID", ident("author", "agentIds", value=["unknown"])),
    ("verdict of another kind", "VERDICT", rec("verdict", value="PASS_FOR_BUILD")),
    ("brief unregistered", "BRIEF_NOT_FOR_SERIES", both("briefSha256", UNREGISTERED_BRIEF)),
]


@pytest.mark.parametrize("name,code,mutator", AFTER_SHAPE, ids=[n for n, _c, _m in AFTER_SHAPE])
def test_the_schemas_accept_what_a_later_code_refuses(name, code, mutator):
    case = Round("PR")
    mutator(case)
    assert RECORD_V.is_valid(case.record)
    assert IDENTITY_V.is_valid(case.identity_value())
    assert case.code() == code


def _keep_with_disclosure(case):
    case.record["disclosures"] = ["a benign slip"]
    case.identity["ruling"] = clone(KEEP)


VALID_VARIANTS = [
    ("rules and wrapper null in both", seq(both("rulesSha256", None), both("wrapperSha256", None))),
    (
        "optional record members",
        seq(
            rec("bindingRules", value=[{"rule": "B-1", "met": True, "note": "met"}]),
            rec("dispositions", value=[{"id": "ORC-0", "status": "ADDRESSED"}, {"id": "ORC-9", "status": "NOT", "note": "n"}]),
            rec("notChecked", value=["nothing else"]),
            rec("questions", value=["none"]),
        ),
    ),
    ("checked objects and strings", rec("checked", value=[{"check": "x", "result": "y"}, "plain"])),
    ("findings with changes required", seq(rec("findings", value=[FINDING]), rec("verdict", value="CHANGES_REQUIRED"))),
    ("operator without a lane", ident("operator", "lane")),
    ("operator is an author", ident("operator", "agentId", value=AUTHOR_IDS[0])),
    ("one author", ident("author", "agentIds", value=[AUTHOR_IDS[1]])),
    ("agentId of 8 characters", ident("reviewer", "agentId", value="abcdefgh")),
    ("agentId of 80 characters", ident("reviewer", "agentId", value="a" * 80)),
    ("agentId of digits, underscores and hyphens", ident("reviewer", "agentId", value="0_1-2_3-4")),
    ("times in Z with fractions", seq(ident("launched", value="2026-10-21T09:00:00.5Z"),
                                      ident("finished", value="2026-10-21T10:30:00.123456789Z"))),
    ("launched equal to finished", ident("launched", value="2026-10-21T10:30:00+00:00")),
    ("launched earlier by offset", ident("launched", value="2026-10-21T11:00:00+02:00")),
    ("no runs", ident("runs", value=[])),
    ("several runs", ident("runs", value=[{"limit": "test runs", "used": 0}, {"limit": "probes", "used": 3}])),
    ("kept ruling with a disclosure", _keep_with_disclosure),
]


@pytest.mark.parametrize("name,mutator", VALID_VARIANTS, ids=[n for n, _m in VALID_VARIANTS])
def test_valid_variants_pass_the_schemas_and_the_model(name, mutator):
    case = Round("PR")
    mutator(case)
    assert RECORD_V.is_valid(case.record)
    assert IDENTITY_V.is_valid(case.identity_value())
    facts = case.check()
    assert facts == expected_facts(
        case,
        passing=case.record["verdict"] in KIND_VERDICTS["PR"][1],
        decision=case.identity["ruling"]["decision"],
    )


def _replace_once(raw, old, new):
    assert raw.count(old) == 1
    return raw.replace(old, new)


NON_IJSON_ROUND = [
    ("record duplicate member", "record", lambda raw: b'{"kind": "PR",' + raw[1:]),
    ("record lone surrogate", "record", lambda raw: _replace_once(raw, b'"synthetic round checked"', b'"\\ud800"')),
    ("record NaN", "record", lambda raw: _replace_once(raw, b'"round": 1', b'"round": NaN')),
    ("record invalid UTF-8", "record", lambda raw: _replace_once(raw, b'"synthetic round checked"', b'"\xff"')),
    ("identity duplicate member", "identity",
     lambda raw: b'{"launched": "2026-10-21T09:00:00+00:00",' + raw[1:]),
    ("identity lone surrogate", "identity", lambda raw: _replace_once(raw, b'"test runs"', b'"\\udc00"')),
    ("identity NaN", "identity", lambda raw: _replace_once(raw, b'"used": 2', b'"used": NaN')),
    ("identity not JSON", "identity", lambda raw: raw[:-3]),
]


@pytest.mark.parametrize("name,which,edit", NON_IJSON_ROUND, ids=[n for n, _w, _e in NON_IJSON_ROUND])
def test_non_ijson_round_files_are_shape(name, which, edit):
    case = Round("PR")
    if which == "record":
        case.raw_record = edit(dump(case.record))
    else:
        case.raw_identity = edit(dump(case.identity_value()))
    assert case.code() == "SHAPE"


# --------------------------------------------------------------------------- 2. the check order (B-6)


def _no_identity(case):
    case.no_identity = True


def _binding(case):
    case.rebind = False
    case.identity["record"]["sha256"] = sha(b"the bytes of another record\n")


def _not_independent(case):
    case.identity["reviewer"]["agentId"] = case.identity["operator"]["agentId"]


def _another_repository(case):
    case.repository = "orc-elsewhere"


def _another_tree(case):
    case.head = clone(OTHER_HEAD)


def _privacy(case):
    case.record["checked"].append("contact " + EMAIL_SHAPE)


# One fault per code, on the oracle's PR round; each leaves every earlier rule intact.
ORDER_FAULTS = {
    "NO_IDENTITY": _no_identity,
    "NO_BRIEF_DIGEST": rec("briefSha256"),
    "SHAPE": rec("note", value="x"),
    "UNKNOWN_KIND": rec("kind", value="DELTA"),
    "BINDING": _binding,
    "PLACEHOLDER_ID": ident("author", "agentIds", value=["stamped_by_operator"]),
    "NOT_INDEPENDENT": _not_independent,
    "IDENTITY_MISMATCH": ident("reviewer", "model", value="model-other"),
    "SUBJECT_FORM": both("subject", {"path": "notes/orc-pr-note.md", "sha256": sha(b"pr note\n")}),
    "SUBJECT_REPOSITORY": _another_repository,
    "BRIEF_NOT_FOR_SERIES": rec("series", value="ORC-OTHER/pr"),
    "BRIEF_SUPERSEDED": both("briefSha256", BRIEF["PR1"]),
    "VERDICT": rec("verdict", value="PASS_FOR_BUILD"),
    "RULING": ident("ruling", value={"decision": "PENDING"}),
    "SUBJECT_MISMATCH": _another_tree,
    "PRIVACY": _privacy,
}


def test_every_review_code_has_an_order_fault():
    assert tuple(ORDER_FAULTS) == B6_ORDER


@pytest.mark.parametrize("code", B6_ORDER)
def test_each_review_code_is_reachable(code):
    case = Round("PR")
    ORDER_FAULTS[code](case)
    assert case.code() == code


ORDER_PAIRS = [(a, b) for i, a in enumerate(B6_ORDER) for b in B6_ORDER[i + 1:]]


@pytest.mark.parametrize("first,second", ORDER_PAIRS, ids=[a + "-over-" + b for a, b in ORDER_PAIRS])
def test_the_earlier_code_wins(first, second):
    case = Round("PR")
    ORDER_FAULTS[second](case)
    ORDER_FAULTS[first](case)
    assert case.code() == first


# --------------------------------------------------------------------------- 3. the binding (D-3, B-1)


def test_the_identity_binds_the_record_path_and_its_file_bytes():
    case = Round("PR")
    raw = case.record_bytes()
    bound = case.identity_value()["record"]
    assert bound == {"path": case.record_path, "sha256": hashlib.sha256(raw).hexdigest()}
    assert rr.file_sha256(raw) == bound["sha256"]
    assert case.check() == expected_facts(case)


def test_an_identity_naming_another_path_is_binding():
    case = Round("PR")
    case.identity["record"]["path"] = "architecture/orc-pr/review-round2.json"
    assert case.code() == "BINDING"


def test_a_record_checked_at_another_path_is_binding():
    case = Round("PR")
    case.record_path = "architecture/orc-pr-copy/review-round1.json"
    assert case.code() == "BINDING"


def test_an_identity_digest_of_other_bytes_is_binding():
    case = Round("PR")
    _binding(case)
    assert case.code() == "BINDING"


def test_the_same_value_with_other_whitespace_is_binding():
    case = Round("PR")
    indented = dump(case.record)
    compact = json.dumps(case.record, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    assert json.loads(compact) == json.loads(indented) and compact != indented
    case.rebind = False
    case.identity["record"]["sha256"] = sha(indented)
    case.raw_record = compact
    assert case.code() == "BINDING"
    case.raw_record = indented
    assert case.check() == expected_facts(case)


def test_a_record_need_not_be_canonical():
    case = Round("PR")
    case.record["checked"] = ["synthetic round checked é"]
    reordered = dict(reversed(list(case.record.items())))
    case.raw_record = json.dumps(reordered, indent=4, ensure_ascii=True).encode("utf-8") + b"\n\n"
    assert b"\\u00e9" in case.raw_record
    assert case.check() == expected_facts(case)


# --------------------------------------------------------------------------- 4. identity rules

AGENT_FIELDS = {
    "reviewer": lambda case, value: set_in(case.identity, ("reviewer", "agentId"), value),
    "operator": lambda case, value: set_in(case.identity, ("operator", "agentId"), value),
    "first author": lambda case, value: set_in(case.identity, ("author", "agentIds"), [value, AUTHOR_IDS[1]]),
    "second author": lambda case, value: set_in(case.identity, ("author", "agentIds"), [AUTHOR_IDS[0], value]),
}
PLACEHOLDER_IDS = PLACEHOLDER_VALUES + [V1_PLACEHOLDER, ""]
PATTERN_BREAKS = [
    "Agent-review-0001",
    "agent07",
    "-agent-review-01",
    "_agent-review-01",
    "a" * 81,
    "agent review 01",
    "agent.review.01",
    "agent-review-01\n",
]
PLACEHOLDER_ROWS = [(f, v) for f in AGENT_FIELDS for v in PLACEHOLDER_IDS + PATTERN_BREAKS]


@pytest.mark.parametrize("field,value", PLACEHOLDER_ROWS, ids=[f + "-" + repr(v) for f, v in PLACEHOLDER_ROWS])
def test_a_placeholder_or_malformed_agent_id_is_placeholder_id(field, value):
    case = Round("PR")
    AGENT_FIELDS[field](case, value)
    assert IDENTITY_V.is_valid(case.identity_value())
    assert case.code() == "PLACEHOLDER_ID"


@pytest.mark.parametrize("who", ["operator", "first author", "second author"])
def test_a_reviewer_equal_to_the_operator_or_an_author_is_not_independent(who):
    case = Round("PR")
    other = {"operator": OPERATOR_ID, "first author": AUTHOR_IDS[0], "second author": AUTHOR_IDS[1]}[who]
    case.identity["reviewer"]["agentId"] = other
    assert case.code() == "NOT_INDEPENDENT"


def _identity_base_differs(case):
    case.identity["base"]["tree"] = hex40("another base tree")


MISMATCHES = [
    ("model", ident("reviewer", "model", value="model-other")),
    ("brief", ident("briefSha256", value=BRIEF["OTHER"])),
    ("rules", ident("rulesSha256", value=sha(b"other rules\n"))),
    ("rules null in the identity", ident("rulesSha256", value=None)),
    ("wrapper", ident("wrapperSha256", value=sha(b"other wrapper\n"))),
    ("wrapper null in the record", rec("wrapperSha256", value=None)),
    ("subject tree", ident("subject", "tree", value=hex40("another subject tree"))),
    ("subject commit", ident("subject", "commit", value=hex40("another subject commit"))),
    ("subject repository", ident("subject", "repository", value="orc-elsewhere")),
    ("base tree", _identity_base_differs),
    ("base only in the record", ident("base")),
    ("base only in the identity", rec("base")),
]


@pytest.mark.parametrize("name,mutator", MISMATCHES, ids=[n for n, _m in MISMATCHES])
def test_each_restated_member_that_differs_is_identity_mismatch(name, mutator):
    case = Round("PR", 2, base=S[1])
    assert case.check() == expected_facts(case)
    mutator(case)
    assert RECORD_V.is_valid(case.record) and IDENTITY_V.is_valid(case.identity_value())
    assert case.code() == "IDENTITY_MISMATCH"


def test_a_base_only_in_the_identity_of_a_full_round_is_identity_mismatch():
    case = Round("PR")
    case.identity["base"] = clone(S[2])
    assert case.code() == "IDENTITY_MISMATCH"


# --------------------------------------------------------------------------- 5. subjects (Q-RR2-3 (a), B-6)


@pytest.mark.parametrize("kind", ["PACKET", "PR"])
def test_a_head_bound_round_on_a_design_note_is_subject_form(kind):
    case = Round(kind)
    case.both("subject", NOTE_SUBJECT)
    assert RECORD_V.is_valid(case.record) and IDENTITY_V.is_valid(case.identity_value())
    assert case.code() == "SUBJECT_FORM"


def test_a_design_round_may_review_a_design_note():
    case = Round("DESIGN")
    assert case.record["subject"] == NOTE_SUBJECT
    assert case.check() == expected_facts(case)


@pytest.mark.parametrize("kind", list(KIND_VERDICTS))
def test_a_subject_naming_another_repository_is_subject_repository(kind):
    case = Round(kind, subject=repo_subject("s1", "orc-elsewhere"))
    assert case.check() == expected_facts(case)
    case.repository = "harness-onion"
    assert case.code() == "SUBJECT_REPOSITORY"


@pytest.mark.parametrize("kind", list(KIND_VERDICTS))
def test_a_subject_in_the_named_repository_passes(kind):
    case = Round(kind, subject=S[1])
    case.repository = "harness-onion"
    assert case.check() == expected_facts(case)


def test_a_design_note_names_no_repository():
    case = Round("DESIGN")
    case.repository = "harness-onion"
    assert case.check() == expected_facts(case)


@pytest.mark.parametrize("kind", ["PACKET", "PR"])
def test_a_head_bound_round_passes_on_a_squash_and_not_on_another_tree(kind):
    case = Round(kind)
    case.head = clone(HEAD)
    assert case.check() == expected_facts(case)
    case.head = clone(SQUASH_HEAD)
    assert case.check() == expected_facts(case)
    case.head = clone(OTHER_HEAD)
    assert case.code() == "SUBJECT_MISMATCH"
    case.head = {"commit": S[1]["commit"], "tree": hex40("another tree for the same commit")}
    assert case.code() == "SUBJECT_MISMATCH"


@pytest.mark.parametrize("kind", ["DESIGN", "CONTRACT"])
def test_design_and_contract_rounds_are_not_judged_against_a_head(kind):
    case = Round(kind)
    case.head = clone(OTHER_HEAD)
    assert case.check() == expected_facts(case)


# --------------------------------------------------------------------------- 6. the registry (section 4, B-3)


def test_the_oracle_registry_is_valid():
    value = registry_value()
    assert BRIEFS_V.is_valid(value)
    loaded = load_registry(value)
    assert isinstance(loaded, dict)


def _entry(value, series, version=1):
    for item in value["briefs"]:
        if item["series"] == series and item["version"] == version:
            return item
    raise KeyError(series)


def reg_mutation(fn):
    def build():
        value = registry_value()
        fn(value)
        return value

    return build


# B-3 rules checked when the registry is loaded; a break is SHAPE beyond any schema.
REGISTRY_RULE_BREAKS = [
    ("an exact id and a prefix over one series",
     reg_mutation(lambda v: v["briefs"].append(brief_entry("PR", "ORC-PR/", "PFX2")))),
    ("one prefix registered twice",
     reg_mutation(lambda v: v["briefs"].append(brief_entry("PR", "ORC-PFX/", "PFX2")))),
    ("one exact id registered twice, not chained",
     reg_mutation(lambda v: v["briefs"].append(brief_entry("PR", "ORC-OTHER/pr", "PFX2")))),
    ("a series pattern with two kinds",
     reg_mutation(lambda v: _entry(v, "ORC-PR/pr", 2).__setitem__("kind", "PACKET"))),
    ("a successor superseding another digest",
     reg_mutation(lambda v: _entry(v, "ORC-PR/pr", 2).__setitem__("supersedes", BRIEF["OTHER"]))),
    ("a superseded version without supersededAt",
     reg_mutation(lambda v: _entry(v, "ORC-PR/pr", 1).pop("supersededAt"))),
    ("the latest version with supersededAt",
     reg_mutation(lambda v: _entry(v, "ORC-PR/pr", 2).__setitem__("supersededAt", "2026-10-22T00:00:00+00:00"))),
    ("a single version with supersededAt",
     reg_mutation(lambda v: _entry(v, "ORC-OTHER/pr").__setitem__("supersededAt", CUTOVER))),
    ("a version number skipped",
     reg_mutation(lambda v: _entry(v, "ORC-PR/pr", 2).__setitem__("version", 3))),
    ("a passing verdict outside the kind's list",
     reg_mutation(lambda v: v["kinds"]["PR"]["passing"].append("PASS_FOR_BUILD"))),
]


@pytest.mark.parametrize("name,build", REGISTRY_RULE_BREAKS, ids=[n for n, _b in REGISTRY_RULE_BREAKS])
def test_a_registry_rule_break_is_shape_at_load(name, build):
    assert refusal(rr.load_registry, dump(build())) == "SHAPE"


REGISTRY_SHAPE_FAULTS = [
    ("schemaVersion wrong", reg_mutation(lambda v: v.__setitem__("schemaVersion", "planeon.review-briefs/v2"))),
    ("unknown top-level member", reg_mutation(lambda v: v.__setitem__("note", "x"))),
    ("kinds without PR", reg_mutation(lambda v: v["kinds"].pop("PR"))),
    ("kinds with DELTA", reg_mutation(lambda v: v["kinds"].__setitem__("DELTA", clone(v["kinds"]["PR"])))),
    ("verdicts empty", reg_mutation(lambda v: v["kinds"]["PR"].__setitem__("verdicts", []))),
    ("passing empty", reg_mutation(lambda v: v["kinds"]["PR"].__setitem__("passing", []))),
    ("verdict repeated", reg_mutation(lambda v: v["kinds"]["PR"]["verdicts"].append("PASS_FOR_PUSH"))),
    ("briefs not a list", reg_mutation(lambda v: v.__setitem__("briefs", {}))),
    ("brief kind DELTA", reg_mutation(lambda v: _entry(v, "ORC-OTHER/pr").__setitem__("kind", "DELTA"))),
    ("brief sha256 upper case",
     reg_mutation(lambda v: _entry(v, "ORC-OTHER/pr").__setitem__("sha256", BRIEF["OTHER"].upper()))),
    ("brief sha256 prefixed",
     reg_mutation(lambda v: _entry(v, "ORC-OTHER/pr").__setitem__("sha256", "sha256:" + BRIEF["OTHER"]))),
    ("brief sha256 16 hex",
     reg_mutation(lambda v: _entry(v, "ORC-OTHER/pr").__setitem__("sha256", BRIEF["OTHER"][:16]))),
    ("brief series lower case", reg_mutation(lambda v: _entry(v, "ORC-OTHER/pr").__setitem__("series", "orc-other/pr"))),
    ("brief series without a slash", reg_mutation(lambda v: _entry(v, "ORC-OTHER/pr").__setitem__("series", "ORC-OTHER"))),
    ("brief version zero", reg_mutation(lambda v: _entry(v, "ORC-OTHER/pr").__setitem__("version", 0))),
    ("brief version a string", reg_mutation(lambda v: _entry(v, "ORC-OTHER/pr").__setitem__("version", "1"))),
    ("brief path absolute",
     reg_mutation(lambda v: _entry(v, "ORC-OTHER/pr").__setitem__("path", "/architecture/x/REVIEW_BRIEF.md"))),
    ("brief path with dot-dot",
     reg_mutation(lambda v: _entry(v, "ORC-OTHER/pr").__setitem__("path", "architecture/../x/REVIEW_BRIEF.md"))),
    ("brief without path", reg_mutation(lambda v: _entry(v, "ORC-OTHER/pr").pop("path"))),
    ("brief unknown member", reg_mutation(lambda v: _entry(v, "ORC-OTHER/pr").__setitem__("note", "x"))),
    ("supersededAt without an offset",
     reg_mutation(lambda v: _entry(v, "ORC-PR/pr", 1).__setitem__("supersededAt", "2026-10-20T12:00:00"))),
    ("supersedes upper case",
     reg_mutation(lambda v: _entry(v, "ORC-PR/pr", 2).__setitem__("supersedes", BRIEF["PR1"].upper()))),
]


@pytest.mark.parametrize("name,build", REGISTRY_SHAPE_FAULTS, ids=[n for n, _b in REGISTRY_SHAPE_FAULTS])
def test_a_registry_shape_fault_is_shape_and_the_schema_rejects_it(name, build):
    value = build()
    assert not BRIEFS_V.is_valid(value)
    assert refusal(rr.load_registry, dump(value)) == "SHAPE"


def test_a_three_version_chain_loads():
    value = registry_value()
    _entry(value, "ORC-PR/pr", 2)["supersededAt"] = "2026-10-21T00:00:00+00:00"
    value["briefs"].append(brief_entry("PR", "ORC-PR/pr", "PFX2", 3, PR_BRIEF_PATH, supersedes=BRIEF["PR2"]))
    assert BRIEFS_V.is_valid(value)
    assert isinstance(load_registry(value), dict)


def test_a_brief_of_another_series_of_the_same_kind_is_brief_not_for_series():
    case = Round("PR")
    case.both("briefSha256", BRIEF["OTHER"])
    assert case.code() == "BRIEF_NOT_FOR_SERIES"


def test_a_brief_of_another_kind_under_a_shared_prefix_is_brief_not_for_series():
    case = Round("PACKET", series="ORC-SH/packet", tag="SH")
    assert case.code() == "BRIEF_NOT_FOR_SERIES"


def test_an_unregistered_series_is_brief_not_for_series():
    case = Round("PR", series="ORC-NONE/pr")
    assert case.code() == "BRIEF_NOT_FOR_SERIES"


@pytest.mark.parametrize("series,tag", [("ORC-PFX/pr", "PFX"), ("ORC-SH/pr", "SH"), ("ORC-SH/second", "SH")])
def test_a_prefix_registered_brief_serves_its_series(series, tag):
    case = Round("PR", series=series, tag=tag)
    assert case.check() == expected_facts(case)


def superseded(launched, review_date, finished="2026-10-20T23:00:00+00:00"):
    case = Round("PR")
    case.both("briefSha256", BRIEF["PR1"])
    case.identity["launched"] = launched
    case.identity["finished"] = finished
    case.record["reviewDate"] = review_date
    return case


def test_a_superseded_brief_launched_at_the_cutover_is_superseded():
    assert superseded(CUTOVER, "2026-10-19").code() == "BRIEF_SUPERSEDED"


def test_a_superseded_brief_reviewed_on_the_cutover_date_is_superseded():
    assert superseded("2026-10-20T11:59:59+00:00", "2026-10-20").code() == "BRIEF_SUPERSEDED"


def test_a_superseded_brief_after_the_cutover_is_superseded():
    assert superseded("2026-10-21T09:00:00+00:00", "2026-10-21", "2026-10-21T10:00:00+00:00").code() == (
        "BRIEF_SUPERSEDED"
    )


def test_a_superseded_brief_one_second_before_on_an_earlier_date_passes():
    case = superseded("2026-10-20T11:59:59+00:00", "2026-10-19")
    assert case.check() == expected_facts(case)


def test_supersession_compares_instants_not_spellings():
    before = superseded("2026-10-20T13:59:59+02:00", "2026-10-19")
    assert before.check() == expected_facts(before)
    at = superseded("2026-10-20T14:00:00+02:00", "2026-10-19")
    assert at.code() == "BRIEF_SUPERSEDED"


def test_the_current_brief_passes_after_the_cutover():
    case = Round("PR")
    assert case.record["briefSha256"] == BRIEF["PR2"]
    assert case.check() == expected_facts(case)


# --------------------------------------------------------------------------- 7. verdicts and rulings

VERDICT_FAULTS = [
    ("DESIGN", "PASS_FOR_PUSH"),
    ("DESIGN", "PASS_FOR_ADOPTION"),
    ("CONTRACT", "PASS_FOR_BUILD"),
    ("CONTRACT", "PASS"),
    ("PACKET", "PASS_FOR_ADOPTION"),
    ("PR", "PASS_FOR_PRECHECK"),
    ("PR", "PASS_FOR_BUILD"),
    ("PR", "pass_for_push"),
]


@pytest.mark.parametrize("kind,verdict", VERDICT_FAULTS, ids=[k + "-" + v for k, v in VERDICT_FAULTS])
def test_a_verdict_outside_the_kinds_list_is_verdict(kind, verdict):
    case = Round(kind, verdict=verdict)
    assert RECORD_V.is_valid(case.record)
    assert case.code() == "VERDICT"


RULINGS = {
    "NONE_NEEDED": {"decision": "NONE_NEEDED"},
    "PENDING": {"decision": "PENDING"},
    "KEEP": KEEP,
    "VOID": VOID,
}
RULING_ROWS = [
    (d, dis, intr, rel)
    for d in RULINGS
    for dis in (False, True)
    for intr in (False, True)
    for rel in (False, True)
]


def ruling_expected(decision, disclosure, interruption, relay):
    if decision == "KEEP":
        return None
    if decision == "NONE_NEEDED" and not (disclosure or interruption or relay):
        return None
    return "RULING"


@pytest.mark.parametrize(
    "decision,disclosure,interruption,relay",
    RULING_ROWS,
    ids=[f"{d}-disc{int(a)}-intr{int(b)}-relay{int(c)}" for d, a, b, c in RULING_ROWS],
)
def test_the_ruling_rule(decision, disclosure, interruption, relay):
    case = Round("PR")
    if disclosure:
        case.record["disclosures"] = ["a benign slip"]
    if interruption:
        case.identity["interruptions"] = ["resumed once after a stop"]
    if relay:
        case.identity["operatorRelays"] = ["relayed a monitor note"]
    case.identity["ruling"] = clone(RULINGS[decision])
    assert RECORD_V.is_valid(case.record) and IDENTITY_V.is_valid(case.identity_value())
    expected = ruling_expected(decision, disclosure, interruption, relay)
    if expected is None:
        assert case.check() == expected_facts(case, decision=decision)
    else:
        assert case.code() == expected


RULING_GAPS = [(d, m) for d in ("KEEP", "VOID") for m in ("by", "ref", "date")]


@pytest.mark.parametrize("decision,missing", RULING_GAPS, ids=[d + "-without-" + m for d, m in RULING_GAPS])
def test_a_keep_or_void_without_by_ref_or_date_is_ruling(decision, missing):
    case = Round("PR")
    case.record["disclosures"] = ["a benign slip"]
    ruling = clone(RULINGS[decision])
    del ruling[missing]
    case.identity["ruling"] = ruling
    assert IDENTITY_V.is_valid(case.identity_value())
    assert case.code() == "RULING"


def test_a_keep_by_the_owner_counts():
    case = Round("PR")
    case.identity["interruptions"] = ["resumed once after a stop"]
    case.identity["ruling"] = dict(KEEP, by="OWNER")
    assert case.check() == expected_facts(case, decision="KEEP")


# --------------------------------------------------------------------------- 8. series (full and delta rounds)


def ctr(n, *, base=None, subject=None, directory=None):
    return Round("CONTRACT", n, subject=subject or S[n], base=base, directory=directory)


def run_series(rounds, extra_identities=(), identities=None):
    records = [r.pair()[0] for r in rounds]
    if identities is None:
        identities = [r.pair()[1] for r in rounds]
    return rr.check_series(records, list(identities) + list(extra_identities), load_registry())


SERIES_VALID = [
    ("one full round", lambda: [ctr(1)]),
    ("three full rounds", lambda: [ctr(1), ctr(2), ctr(3)]),
    ("a full round and two deltas", lambda: [ctr(1), ctr(2, base=S[1]), ctr(3, base=S[2])]),
    ("a full round after a delta", lambda: [ctr(1), ctr(2, base=S[1]), ctr(3)]),
    ("a delta after a full round after a delta", lambda: [ctr(1), ctr(2, base=S[1]), ctr(3), ctr(4, base=S[3])]),
]


@pytest.mark.parametrize("name,build", SERIES_VALID, ids=[n for n, _b in SERIES_VALID])
def test_a_valid_series_passes(name, build):
    rounds = build()
    out = rr.check_series([r.pair()[0] for r in rounds], [r.pair()[1] for r in rounds], load_registry())
    assert set(out) == {"series", "rounds", "final", "lastSubject"}
    assert out["series"] == "ORC-CTR/contract"
    assert out["lastSubject"] == rounds[-1].record["subject"]


def _two_identities_for_one_record():
    first, second = ctr(1), ctr(2)
    other = first.identity_value()
    other["runs"] = [{"limit": "test runs", "used": 5}]
    extra = [("architecture/orc-ctr/review-identity-round1-b.json", dump(other))]
    return [first, second], extra


def _one_identity_listed_twice():
    first, second = ctr(1), ctr(2)
    return [first, second], [first.pair()[1]]


def _one_identity_copied():
    first, second = ctr(1), ctr(2)
    return [first, second], [("architecture/orc-ctr/review-identity-round1-copy.json", first.identity_bytes())]


SERIES_REFUSALS = [
    ("two round-2 records", {"DUPLICATE_ROUND"},
     lambda: ([ctr(1), ctr(2), ctr(2, subject=S[3], directory="orc-ctr-b")], [])),
    ("rounds 1 and 3 only", {"SERIES_GAP"}, lambda: ([ctr(1), ctr(3)], [])),
    ("a delta whose earlier round is missing", {"SERIES_GAP"}, lambda: ([ctr(2, base=S[1])], [])),
    ("a delta whose earlier rounds are missing", {"SERIES_GAP"}, lambda: ([ctr(3, base=S[2])], [])),
    ("two rounds with one base", {"SERIES_FORK"},
     lambda: ([ctr(1), ctr(2, base=S[1]), ctr(3, base=S[1])], [])),
    ("a delta whose base is not the previous subject", {"SERIES_FORK"},
     lambda: ([ctr(1), ctr(2, base=S[4])], [])),
    ("a delta after a full round naming an older base", {"SERIES_FORK"},
     lambda: ([ctr(1), ctr(2), ctr(3, base=S[1])], [])),
    # Section 5 and the brief: a delta that is round 1 has no previous round; GAP and FORK both describe it.
    ("a delta round 1", {"SERIES_GAP", "SERIES_FORK"}, lambda: ([ctr(1, base=S[4])], [])),
    ("two identities for one record", {"DUPLICATE_IDENTITY"}, _two_identities_for_one_record),
    ("one identity file listed twice", {"DUPLICATE_IDENTITY"}, _one_identity_listed_twice),
    ("one identity file copied to a second path", {"DUPLICATE_IDENTITY"}, _one_identity_copied),
]


@pytest.mark.parametrize("name,codes,build", SERIES_REFUSALS, ids=[n for n, _c, _b in SERIES_REFUSALS])
def test_a_broken_series_is_refused(name, codes, build):
    rounds, extra = build()
    for item in rounds:
        if item.record["round"] > 1 or "base" not in item.record:
            assert item.check() == expected_facts(item)
    assert refusal(run_series, rounds, extra) in codes


def test_a_series_round_without_its_identity_is_no_identity():
    rounds = [ctr(1), ctr(2)]
    assert refusal(run_series, rounds, (), [rounds[0].pair()[1]]) == "NO_IDENTITY"


def test_a_series_checks_every_round_with_its_identity():
    rounds = [ctr(1), ctr(2)]
    rounds[1].identity["ruling"] = {"decision": "PENDING"}
    assert refusal(run_series, rounds) == "RULING"


# --------------------------------------------------------------------------- 9. oracle identities (B-5, D5a)


def test_a_valid_oracle_identity_passes():
    oracle = Oracle()
    assert ORACLE_V.is_valid(oracle.value)
    out = oracle.check()
    assert set(out) == {"file", "decision"}
    assert out["decision"] == "NONE_NEEDED"
    assert out["file"] in (ORACLE_FILE_PATH, {"path": ORACLE_FILE_PATH, "sha256": sha(ORACLE_FILE_BYTES)})


def _oracle_edited(oracle):
    oracle.file_bytes = oracle.file_bytes + b"# edited after the identity\n"


def _oracle_is_operator(oracle):
    oracle.value["oracle"]["agentId"] = oracle.value["operator"]["agentId"]


ORACLE_FAULTS = {
    "SHAPE": ova("note", value="x"),
    "PLACEHOLDER_ID": ova("author", "agentIds", value=["recorded-by-the-launcher"]),
    "ORACLE_DIGEST": _oracle_edited,
    "NOT_INDEPENDENT": _oracle_is_operator,
    "RULING": ova("ruling", value={"decision": "PENDING"}),
    "PRIVACY": ova("operator", "lane", value="lane " + EMAIL_SHAPE),
}


@pytest.mark.parametrize("code", ORACLE_ORDER)
def test_each_oracle_code_is_reachable(code):
    oracle = Oracle()
    ORACLE_FAULTS[code](oracle)
    assert oracle.code() == code


ORACLE_PAIRS = [(a, b) for i, a in enumerate(ORACLE_ORDER) for b in ORACLE_ORDER[i + 1:]]


@pytest.mark.parametrize("first,second", ORACLE_PAIRS, ids=[a + "-over-" + b for a, b in ORACLE_PAIRS])
def test_the_earlier_oracle_code_wins(first, second):
    oracle = Oracle()
    ORACLE_FAULTS[second](oracle)
    ORACLE_FAULTS[first](oracle)
    assert oracle.code() == first


ORACLE_SHAPE_FAULTS = [("oracle identity without " + m, ova(m)) for m in ORACLE_REQUIRED] + [
    ("unknown member", ova("note", value="x")),
    ("schemaVersion wrong", ova("schemaVersion", value="planeon.oracle-identity/v2")),
    ("file unknown member", ova("file", "size", value=1)),
    ("file path absolute", ova("file", "path", value="/" + ORACLE_FILE_PATH)),
    ("file path with dot-dot", ova("file", "path", value="tests/../" + ORACLE_FILE_PATH)),
    ("oracle model empty", ova("oracle", "model", value="")),
    ("oracle unknown member", ova("oracle", "role", value="ORACLE_AGENT")),
    ("operator role LANE_MONITOR", ova("operator", "role", value="LANE_MONITOR")),
    ("operator unknown member", ova("operator", "model", value=MODEL)),
    ("author empty", ova("author", "agentIds", value=[])),
    ("author repeated", ova("author", "agentIds", value=[AUTHOR_IDS[0], AUTHOR_IDS[0]])),
    ("candidateCommit 7 hex", ova("candidateCommit", value="abc1234")),
    ("candidateCommit upper case", ova("candidateCommit", value=UPPER40)),
    ("launched without an offset", ova("launched", value="2026-10-21T09:00:00")),
    ("finished a date", ova("finished", value="2026-10-21")),
    ("briefSha256 upper case", ova("briefSha256", value=BRIEF["ORACLE"].upper())),
    ("briefSha256 prefixed", ova("briefSha256", value="sha256:" + BRIEF["ORACLE"])),
    ("ruling decision unknown", ova("ruling", value={"decision": "MAYBE"})),
    ("ruling by unknown", ova("ruling", value=dict(KEEP, by="SOMEONE"))),
    ("disclosures empty string", ova("disclosures", value=[""])),
] + [("file sha256 " + n, ova("file", "sha256", value=f(sha(ORACLE_FILE_BYTES)))) for n, f in DIGEST_FORMS]


@pytest.mark.parametrize("name,mutator", ORACLE_SHAPE_FAULTS, ids=[n for n, _m in ORACLE_SHAPE_FAULTS])
def test_an_oracle_shape_fault_is_shape_and_the_schema_rejects_it(name, mutator):
    oracle = Oracle()
    mutator(oracle)
    assert not ORACLE_V.is_valid(oracle.value)
    assert oracle.code() == "SHAPE"


def test_an_oracle_launched_after_finished_is_shape():
    oracle = Oracle()
    oracle.value["launched"] = "2026-10-21T12:00:00+00:00"
    assert oracle.code() == "SHAPE"


@pytest.mark.parametrize("value", PLACEHOLDER_IDS + PATTERN_BREAKS, ids=[repr(v) for v in PLACEHOLDER_IDS + PATTERN_BREAKS])
def test_an_oracle_placeholder_is_placeholder_id(value):
    oracle = Oracle()
    oracle.value["oracle"]["agentId"] = value
    assert ORACLE_V.is_valid(oracle.value)
    assert oracle.code() == "PLACEHOLDER_ID"


@pytest.mark.parametrize("who", ["operator", "first author", "second author"])
def test_an_oracle_equal_to_the_operator_or_an_author_is_not_independent(who):
    oracle = Oracle()
    oracle.value["oracle"]["agentId"] = {"operator": OPERATOR_ID, "first author": AUTHOR_IDS[0],
                                        "second author": AUTHOR_IDS[1]}[who]
    assert oracle.code() == "NOT_INDEPENDENT"


def test_an_absent_oracle_file_is_oracle_digest():
    oracle = Oracle()
    oracle.file_bytes = None
    assert oracle.code() == "ORACLE_DIGEST"


ORACLE_RULINGS = [
    ("pending", None, {"decision": "PENDING"}, "RULING"),
    ("void", None, VOID, "RULING"),
    ("none needed with a disclosure", ["a benign slip"], {"decision": "NONE_NEEDED"}, "RULING"),
    ("keep without ref", ["a benign slip"], {k: v for k, v in KEEP.items() if k != "ref"}, "RULING"),
    ("keep without by", ["a benign slip"], {k: v for k, v in KEEP.items() if k != "by"}, "RULING"),
    ("keep without date", ["a benign slip"], {k: v for k, v in KEEP.items() if k != "date"}, "RULING"),
    ("keep with a disclosure", ["a benign slip"], KEEP, None),
]


@pytest.mark.parametrize("name,disclosures,ruling,code", ORACLE_RULINGS, ids=[r[0] for r in ORACLE_RULINGS])
def test_the_oracle_ruling_rule(name, disclosures, ruling, code):
    oracle = Oracle()
    if disclosures is not None:
        oracle.value["disclosures"] = list(disclosures)
    oracle.value["ruling"] = clone(ruling)
    assert ORACLE_V.is_valid(oracle.value)
    if code is None:
        assert oracle.check()["decision"] == ruling["decision"]
    else:
        assert oracle.code() == code


def heads(files):
    return lambda path: files.get(path)


ORACLE_PATHS = [
    "tests/test_orc_new_oracle.py",
    "tests/test_oracle.py",
    "tests/test_x_oracle_y.py",
    "tests/sub/dir/test_deep_oracle_case.py",
]
NOT_ORACLE_PATHS = [
    "scripts/test_x_oracle.py",
    "docs/tests/test_x_oracle.py",
    "test_x_oracle.py",
    "tests/test_plain.py",
    "tests/oracle/test_plain.py",
    "tests/oracle_test.py",
    "tests/test_x_oracle.txt",
    "tests/test_x_ORACLE.py",
]


def test_pr_oracles_pass_with_a_matching_identity():
    oracle = Oracle()
    read = heads({ORACLE_FILE_PATH: ORACLE_FILE_BYTES})
    out = rr.check_pr_oracles([ORACLE_FILE_PATH, "scripts/tool.py"], [oracle.entry()], read)
    assert isinstance(out, list)
    out = rr.check_pr_oracles([ORACLE_FILE_PATH], [oracle.entry()], read, True)
    assert isinstance(out, list)


@pytest.mark.parametrize("path", ORACLE_PATHS)
def test_a_changed_oracle_test_without_an_identity_is_oracle_missing(path):
    assert refusal(rr.check_pr_oracles, [path], [], heads({path: b"x = 1\n"})) == "ORACLE_MISSING"


def test_an_identity_for_another_oracle_file_leaves_the_changed_one_missing():
    oracle = Oracle()
    changed = "tests/test_orc_new_oracle.py"
    read = heads({ORACLE_FILE_PATH: ORACLE_FILE_BYTES, changed: b"x = 1\n"})
    assert refusal(rr.check_pr_oracles, [changed], [oracle.entry()], read) == "ORACLE_MISSING"


def test_files_outside_tests_or_with_other_names_are_not_oracle_tests():
    out = rr.check_pr_oracles(list(NOT_ORACLE_PATHS), [], heads({p: b"x = 1\n" for p in NOT_ORACLE_PATHS}))
    assert isinstance(out, list)


def test_an_oracle_file_that_differs_at_the_head_is_oracle_digest():
    oracle = Oracle()
    read = heads({ORACLE_FILE_PATH: ORACLE_FILE_BYTES + b"# edited\n"})
    assert refusal(rr.check_pr_oracles, [ORACLE_FILE_PATH], [oracle.entry()], read) == "ORACLE_DIGEST"


def test_an_oracle_file_absent_at_the_head_is_oracle_digest():
    oracle = Oracle()
    assert refusal(rr.check_pr_oracles, [ORACLE_FILE_PATH], [oracle.entry()], heads({})) == "ORACLE_DIGEST"


def test_a_contract_series_without_an_oracle_identity_is_oracle_missing():
    assert refusal(rr.check_pr_oracles, ["scripts/tool.py"], [], heads({}), True) == "ORACLE_MISSING"


def test_pr_oracles_refuse_a_dependent_oracle_and_an_open_ruling():
    read = heads({ORACLE_FILE_PATH: ORACLE_FILE_BYTES})
    dependent = Oracle()
    dependent.value["oracle"]["agentId"] = AUTHOR_IDS[0]
    assert refusal(rr.check_pr_oracles, [ORACLE_FILE_PATH], [dependent.entry()], read) == "NOT_INDEPENDENT"
    pending = Oracle()
    pending.value["ruling"] = {"decision": "PENDING"}
    assert refusal(rr.check_pr_oracles, [ORACLE_FILE_PATH], [pending.entry()], read) == "RULING"


# --------------------------------------------------------------------------- 10. the merge (B-4, Q-RR2-3 (a))


def pr(n=1, verdict=None):
    return Round("PR", n, subject=S[1], verdict=verdict)


def kept(case):
    case.record["disclosures"] = ["a benign slip"]
    case.identity["ruling"] = clone(KEEP)
    return case


def pending(case):
    case.record["disclosures"] = ["a benign slip"]
    case.identity["ruling"] = {"decision": "PENDING"}
    return case


def voided(case):
    case.record["disclosures"] = ["a benign slip"]
    case.identity["ruling"] = clone(VOID)
    return case


MERGE_PASSES = [
    ("a passing PR round on the head", lambda: [pr()], HEAD, [("PR", 1)]),
    ("a squash of the reviewed commit", lambda: [pr()], SQUASH_HEAD, [("PR", 1)]),
    # MET-GOV-002 r1: a PACKET round counts with PASS_FOR_PUSH (RR2C1-9).
    ("a passing PACKET round", lambda: [Round("PACKET", 1, verdict="PASS_FOR_PUSH")], HEAD, [("PACKET", 1)]),
    ("a kept ruling", lambda: [kept(pr())], HEAD, [("PR", 1)]),
    ("design and contract rounds beside a PR round", lambda: [Round("DESIGN"), Round("CONTRACT"), pr()], HEAD,
     [("PR", 1)]),
    ("a passing final round after changes required", lambda: [pr(1, "CHANGES_REQUIRED"), pr(2)], HEAD, [("PR", 2)]),
]


@pytest.mark.parametrize("name,build,head,expected", MERGE_PASSES, ids=[r[0] for r in MERGE_PASSES])
def test_the_merge_returns_only_passing_head_bound_final_rounds(name, build, head, expected):
    out = rr.check_merge([r.cited() for r in build()], load_registry(), clone(head))
    assert isinstance(out, list)
    assert [(f["kind"], f["round"]) for f in out] == expected
    for facts in out:
        assert facts["headBound"] is True and facts["passing"] is True
        assert facts["decision"] in ("NONE_NEEDED", "KEEP")


MERGE_REFUSALS = [
    ("no cited round", lambda: [], HEAD),
    ("a DESIGN round only", lambda: [Round("DESIGN")], HEAD),
    ("a CONTRACT round only", lambda: [Round("CONTRACT")], HEAD),
    ("DESIGN and CONTRACT rounds only", lambda: [Round("DESIGN"), Round("CONTRACT")], HEAD),
    ("a CHANGES_REQUIRED PR round", lambda: [pr(1, "CHANGES_REQUIRED")], HEAD),
    # MET-GOV-002 r1: a PACKET round that only cleared the pre-check is no merge authority (RR2C1-9).
    ("a PACKET round with PASS_FOR_PRECHECK alone", lambda: [Round("PACKET", 1, verdict="PASS_FOR_PRECHECK")], HEAD),
    ("a pending ruling", lambda: [pending(pr())], HEAD),
    ("a void ruling", lambda: [voided(pr())], HEAD),
    ("a PR round on another tree", lambda: [pr()], OTHER_HEAD),
    ("a passing round that is not final", lambda: [pr(1), pr(2, "CHANGES_REQUIRED")], HEAD),
]


@pytest.mark.parametrize("name,build,head", MERGE_REFUSALS, ids=[r[0] for r in MERGE_REFUSALS])
def test_the_merge_refuses_without_a_counting_head_bound_round(name, build, head):
    cited = [r.cited() for r in build()]
    assert refusal(rr.check_merge, cited, load_registry(), clone(head)) == "NO_HEAD_BOUND_ROUND"


# --------------------------------------------------------------------------- 11. the tree (B-9), temporary directories only

LEGACY_RECORD_PATH = "architecture/orc-old/review-round1.json"
LEGACY_RECORD_BYTES = dump({"schema": "orc-legacy/v0", "round": 1, "verdict": "PASS_FOR_ADOPTION"})
NEW_ORACLE_PATH = "tests/test_orc_new_oracle.py"
NEW_ORACLE_BYTES = b"def test_new():\n    assert True\n"
OLD_ORACLE_PATH = "tests/test_orc_old_oracle.py"
OLD_ORACLE_BYTES = b"def test_old():\n    assert True\n"
TREE_BRIEFS = [("CONTRACT", "ORC-CTR/contract", "CTR"), ("DESIGN", "ORC-OLD/design", "OLD"),
               ("DESIGN", "ORC-NEW/design", "NEW")]


def tree_registry_value():
    value = registry_value()
    value["briefs"] = [brief_entry(kind, series, tag) for kind, series, tag in TREE_BRIEFS]
    return value


def legacy_value(entries=None, oracle_tests=None):
    # Q-RR2-FROZEN (monitor, relayed): legacy oracle tests are frozen by path and file digest, like entries.
    return {
        "schemaVersion": "planeon.legacy-review-records/v1",
        "baseCommit": hex40("oracle base"),
        "entries": entries if entries is not None else [
            {"path": LEGACY_RECORD_PATH, "sha256": sha(LEGACY_RECORD_BYTES)}
        ],
        "oracleTests": oracle_tests if oracle_tests is not None else [
            {"path": OLD_ORACLE_PATH, "sha256": sha(OLD_ORACLE_BYTES)}
        ],
    }


def tree_round(kind, directory, series, tag, subject=None):
    case = Round(kind, 1, directory=directory, series=series, tag=tag, subject=subject)
    case.registry = tree_registry_value()
    return case


def tree_files(contract=None):
    contract = contract or tree_round("CONTRACT", "orc-ctr", "ORC-CTR/contract", "CTR")
    oracle = Oracle(NEW_ORACLE_PATH, NEW_ORACLE_BYTES, "architecture/orc-ctr/oracle-identity.json")
    (record_path, record_bytes), (identity_path, identity_bytes) = contract.pair()
    files = {
        LEGACY_RECORD_PATH: LEGACY_RECORD_BYTES,
        record_path: record_bytes,
        identity_path: identity_bytes,
        oracle.identity_path: oracle.bytes(),
        NEW_ORACLE_PATH: NEW_ORACLE_BYTES,
        OLD_ORACLE_PATH: OLD_ORACLE_BYTES,
        "README.md": b"Oracle synthetic tree.\n",
        "scripts/tool.py": b"VALUE = 1\n",
    }
    for _kind, _series, tag in TREE_BRIEFS:
        files["architecture/orc-" + tag.lower() + "/REVIEW_BRIEF.md"] = brief_bytes(tag)
    return files


def run_tree(tmp_path, files, legacy=None):
    root = tmp_path / "tree"
    for rel, data in files.items():
        target = root.joinpath(*rel.split("/"))
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(data)
    legacy_loaded = rr.load_legacy(dump(legacy if legacy is not None else legacy_value()))
    return rr.check_tree(root, legacy_loaded, rr.load_registry(dump(tree_registry_value())), "harness-onion")


def test_a_valid_tree_passes(tmp_path):
    out = run_tree(tmp_path, tree_files())
    assert set(out) == {"legacyRecords", "series", "oracleTests", "oracleIdentities"}


def test_a_frozen_record_with_one_byte_changed_is_legacy_changed(tmp_path):
    files = tree_files()
    changed = files[LEGACY_RECORD_PATH].replace(b'"round": 1', b'"round": 2')
    assert len(changed) == len(LEGACY_RECORD_BYTES) and changed != LEGACY_RECORD_BYTES
    files[LEGACY_RECORD_PATH] = changed
    assert refusal(run_tree, tmp_path, files) == "LEGACY_CHANGED"


def test_a_frozen_record_rewritten_into_a_valid_v2_set_is_legacy_changed(tmp_path):
    rewritten = tree_round("DESIGN", "orc-old", "ORC-OLD/design", "OLD")
    assert rewritten.record_path == LEGACY_RECORD_PATH
    assert rewritten.check() == expected_facts(rewritten)
    files = tree_files()
    (record_path, record_bytes), (identity_path, identity_bytes) = rewritten.pair()
    files[record_path] = record_bytes
    files[identity_path] = identity_bytes
    assert refusal(run_tree, tmp_path, files) == "LEGACY_CHANGED"


def test_an_unlisted_review_round_file_is_legacy_changed(tmp_path):
    files = tree_files()
    files["architecture/orc-misc/review-round-x.json"] = LEGACY_RECORD_BYTES
    assert refusal(run_tree, tmp_path, files) == "LEGACY_CHANGED"


def test_a_v2_round_without_its_identity_is_no_identity(tmp_path):
    lonely = tree_round("DESIGN", "orc-new", "ORC-NEW/design", "NEW")
    files = tree_files()
    files[lonely.record_path] = lonely.record_bytes()
    assert refusal(run_tree, tmp_path, files) == "NO_IDENTITY"


def test_a_v2_round_naming_another_repository_is_subject_repository(tmp_path):
    contract = tree_round("CONTRACT", "orc-ctr", "ORC-CTR/contract", "CTR", subject=repo_subject("s1", "orc-elsewhere"))
    assert refusal(run_tree, tmp_path, tree_files(contract)) == "SUBJECT_REPOSITORY"


@pytest.mark.parametrize("path", ["tests/test_orc_extra_oracle.py", "tests/sub/test_orc_deep_oracle.py"])
def test_an_unlisted_oracle_test_without_an_identity_is_oracle_missing(tmp_path, path):
    files = tree_files()
    files[path] = b"def test_extra():\n    assert True\n"
    assert refusal(run_tree, tmp_path, files) == "ORACLE_MISSING"


def test_a_frozen_oracle_test_with_changed_bytes_is_oracle_missing(tmp_path):
    # Q-RR2-FROZEN (monitor, relayed): frozen by path and digest, so changed bytes need an identity.
    files = tree_files()
    files[OLD_ORACLE_PATH] = OLD_ORACLE_BYTES + b"# a mechanical edit\n"
    assert refusal(run_tree, tmp_path, files) == "ORACLE_MISSING"


def test_an_oracle_test_edited_after_its_identity_is_refused(tmp_path):
    # B-5 names ORACLE_MISSING for a file no valid identity covers; check_oracle names ORACLE_DIGEST.
    files = tree_files()
    files[NEW_ORACLE_PATH] = NEW_ORACLE_BYTES + b"# edited after the identity\n"
    assert refusal(run_tree, tmp_path, files) in {"ORACLE_MISSING", "ORACLE_DIGEST"}


@pytest.mark.parametrize(
    "data",
    [b"{", dump(dict(Oracle(NEW_ORACLE_PATH, NEW_ORACLE_BYTES).value, note="x"))],
    ids=["not JSON", "unknown member"],
)
def test_a_malformed_oracle_identity_is_shape(tmp_path, data):
    files = tree_files()
    files["architecture/orc-ctr/oracle-identity-2.json"] = data
    assert refusal(run_tree, tmp_path, files) == "SHAPE"


def test_git_and_cache_directories_are_not_walked(tmp_path):
    junk = LEGACY_RECORD_BYTES.replace(b'"round": 1', b'"round": 7')
    files = tree_files()
    files[".git/review-round7.json"] = junk
    files[".git/tests/test_git_oracle.py"] = b"x = 1\n"
    files["architecture/orc-ctr/__pycache__/review-round7.json"] = junk
    files["tests/__pycache__/test_cached_oracle.py"] = b"x = 1\n"
    files[".pytest_cache/review-round7.json"] = junk
    files[".pytest_cache/tests/test_cached_oracle.py"] = b"x = 1\n"
    out = run_tree(tmp_path, files)
    assert set(out) == {"legacyRecords", "series", "oracleTests", "oracleIdentities"}


# --------------------------------------------------------------------------- the frozen list (B-6, Q-RR2-FROZEN)

SECOND_RECORD = {"path": "architecture/orc-zzz/review-round1.json", "sha256": sha(b"second legacy record\n")}
SECOND_ORACLE = {"path": "tests/test_orc_zzz_oracle.py", "sha256": sha(b"second legacy oracle\n")}


def legacy_mutation(fn):
    def build():
        value = legacy_value()
        fn(value)
        return value

    return build


def test_a_valid_frozen_list_loads():
    value = legacy_value(
        entries=[{"path": LEGACY_RECORD_PATH, "sha256": sha(LEGACY_RECORD_BYTES)}, clone(SECOND_RECORD)],
        oracle_tests=[{"path": OLD_ORACLE_PATH, "sha256": sha(OLD_ORACLE_BYTES)}, clone(SECOND_ORACLE)],
    )
    assert isinstance(rr.load_legacy(dump(value)), dict)
    assert isinstance(rr.load_legacy(dump(legacy_value(entries=[], oracle_tests=[]))), dict)


LEGACY_FAULTS = [
    ("schemaVersion wrong", legacy_mutation(lambda v: v.__setitem__("schemaVersion", "planeon.legacy-review-records/v2"))),
    ("unknown top-level member", legacy_mutation(lambda v: v.__setitem__("note", "x"))),
    ("without schemaVersion", legacy_mutation(lambda v: v.pop("schemaVersion"))),
    ("without baseCommit", legacy_mutation(lambda v: v.pop("baseCommit"))),
    ("without entries", legacy_mutation(lambda v: v.pop("entries"))),
    ("entries unsorted", legacy_mutation(lambda v: v["entries"].insert(0, clone(SECOND_RECORD)))),
    ("entries repeated", legacy_mutation(lambda v: v["entries"].append(clone(v["entries"][0])))),
    ("entry sha256 upper case", legacy_mutation(lambda v: v["entries"][0].__setitem__("sha256", sha(LEGACY_RECORD_BYTES).upper()))),
    ("entry sha256 prefixed", legacy_mutation(lambda v: v["entries"][0].__setitem__("sha256", "sha256:" + sha(LEGACY_RECORD_BYTES)))),
    ("entry sha256 63 hex", legacy_mutation(lambda v: v["entries"][0].__setitem__("sha256", sha(LEGACY_RECORD_BYTES)[:63]))),
    ("entry unknown member", legacy_mutation(lambda v: v["entries"][0].__setitem__("note", "x"))),
    ("entry path absolute", legacy_mutation(lambda v: v["entries"][0].__setitem__("path", "/" + LEGACY_RECORD_PATH))),
    ("entry path with dot-dot", legacy_mutation(lambda v: v["entries"][0].__setitem__("path", "architecture/../" + LEGACY_RECORD_PATH))),
    ("oracleTests as path strings", legacy_mutation(lambda v: v.__setitem__("oracleTests", [OLD_ORACLE_PATH]))),
    ("oracleTests unsorted", legacy_mutation(lambda v: v["oracleTests"].insert(0, clone(SECOND_ORACLE)))),
    ("oracleTests repeated", legacy_mutation(lambda v: v["oracleTests"].append(clone(v["oracleTests"][0])))),
    ("oracleTests sha256 upper case",
     legacy_mutation(lambda v: v["oracleTests"][0].__setitem__("sha256", sha(OLD_ORACLE_BYTES).upper()))),
    ("oracleTests without sha256", legacy_mutation(lambda v: v["oracleTests"][0].pop("sha256"))),
    ("oracleTests path absolute", legacy_mutation(lambda v: v["oracleTests"][0].__setitem__("path", "/" + OLD_ORACLE_PATH))),
]


@pytest.mark.parametrize("name,build", LEGACY_FAULTS, ids=[n for n, _b in LEGACY_FAULTS])
def test_a_malformed_frozen_list_is_shape(name, build):
    assert refusal(rr.load_legacy, dump(build())) == "SHAPE"


# --------------------------------------------------------------------------- 12. privacy (RR1-13, B-8)

HIT_KEYS = {"names", "legacyTerm", "absolutePaths", "emails"}


def test_privacy_hits_counts_only():
    hits = rr.privacy_hits(b"a clean synthetic text\n")
    assert set(hits) == HIT_KEYS
    assert hits == {key: 0 for key in HIT_KEYS}


@pytest.mark.parametrize("shape", HOME_SHAPES, ids=["home-a", "home-b"])
def test_a_home_path_shape_is_counted(shape):
    hits = rr.privacy_hits(("see " + shape + " for it\n").encode("utf-8"))
    assert all(isinstance(v, int) for v in hits.values())
    assert hits["absolutePaths"] >= 1


def test_an_email_shape_is_counted():
    hits = rr.privacy_hits(("write to " + EMAIL_SHAPE + " today\n").encode("utf-8"))
    assert hits["emails"] >= 1


PRIVACY_PLACES = [
    ("record checked", lambda case, text: case.record["checked"].append(text)),
    ("record finding", lambda case, text: (case.record.__setitem__("findings", [dict(FINDING, finding=text)]),
                                           case.record.__setitem__("verdict", "CHANGES_REQUIRED"))),
    ("identity lane", lambda case, text: set_in(case.identity, ("operator", "lane"), text)),
    ("identity runs", lambda case, text: set_in(case.identity, ("runs",), [{"limit": text, "used": 1}])),
]
PRIVACY_ROWS = [(place, i) for place, _f in PRIVACY_PLACES for i in range(len(HOME_SHAPES) + 1)]


@pytest.mark.parametrize("place,index", PRIVACY_ROWS, ids=[p + "-" + str(i) for p, i in PRIVACY_ROWS])
def test_a_round_holding_a_privacy_shape_is_privacy(place, index):
    text = "see " + (HOME_SHAPES + [EMAIL_SHAPE])[index]
    case = Round("PR")
    dict(PRIVACY_PLACES)[place](case, text)
    assert RECORD_V.is_valid(case.record) and IDENTITY_V.is_valid(case.identity_value())
    assert case.code() == "PRIVACY"


MADE_UP_NAME = "zu" + "vekt"
MADE_UP_TERM = "plom" + "var"


def test_a_name_token_is_matched_by_digest(monkeypatch):
    # Q-RR2-NAMES (owner, relayed): exercised only through the digest of a made-up word.
    assert rr.privacy_hits(("met " + MADE_UP_NAME + " today").encode("utf-8"))["names"] == 0
    monkeypatch.setattr(rr, "NAME_TOKEN_SHA256", {len(MADE_UP_NAME): (sha_text(MADE_UP_NAME),)})
    assert rr.privacy_hits(("met " + MADE_UP_NAME + " today").encode("utf-8"))["names"] >= 1
    assert rr.privacy_hits(b"met nobody today")["names"] == 0
    case = Round("PR")
    case.record["checked"].append("met " + MADE_UP_NAME)
    assert case.code() == "PRIVACY"
    oracle = Oracle()
    oracle.value["operator"]["lane"] = "lane " + MADE_UP_NAME
    assert oracle.code() == "PRIVACY"


def test_the_legacy_term_is_matched_by_digest_prefix(monkeypatch):
    assert len(MADE_UP_TERM) == 7
    assert rr.privacy_hits(("an old " + MADE_UP_TERM + " name").encode("utf-8"))["legacyTerm"] == 0
    monkeypatch.setattr(rr, "LEGACY_TERM_PREFIX", sha_text(MADE_UP_TERM)[:16])
    assert rr.privacy_hits(("an old " + MADE_UP_TERM + " name").encode("utf-8"))["legacyTerm"] >= 1
    assert rr.privacy_hits(b"an old common name")["legacyTerm"] == 0
    case = Round("PR")
    case.identity["operator"]["lane"] = "lane " + MADE_UP_TERM
    assert case.code() == "PRIVACY"


PUBLISHED = [
    CONTRACT_DIR / "README.md",
    CONTRACT_DIR / "briefs.json",
    CONTRACT_DIR / "REVIEW_BRIEF.md",
    SCHEMA_DIR / "review-record.schema.json",
    SCHEMA_DIR / "review-identity.schema.json",
    SCHEMA_DIR / "oracle-identity.schema.json",
    SCHEMA_DIR / "review-briefs.schema.json",
]


@pytest.mark.parametrize("path", PUBLISHED, ids=[p.name for p in PUBLISHED])
def test_the_published_files_have_no_privacy_hits(path):
    hits = rr.privacy_hits(path.read_bytes())
    assert set(hits) == HIT_KEYS
    assert hits == {key: 0 for key in HIT_KEYS}


# --------------------------------------------------------------------------- 13. the published registry


def test_the_published_registry_holds_the_four_kinds():
    raw = (CONTRACT_DIR / "briefs.json").read_bytes()
    value = json.loads(raw)
    assert BRIEFS_V.is_valid(value)
    assert isinstance(rr.load_registry(raw), dict)
    got = {kind: (set(item["verdicts"]), set(item["passing"])) for kind, item in value["kinds"].items()}
    assert got == {kind: (set(v), set(p)) for kind, (v, p) in KIND_VERDICTS.items()}


def test_the_published_registry_pins_each_brief_by_its_file_bytes():
    value = json.loads((CONTRACT_DIR / "briefs.json").read_bytes())
    assert value["briefs"]
    for item in value["briefs"]:
        assert item["sha256"] == sha((ROOT / item["path"]).read_bytes()), item["path"]
    assert [(b["kind"], b["series"]) for b in value["briefs"] if b["series"] == "MET-GOV-002/contract"] == [
        ("CONTRACT", "MET-GOV-002/contract")
    ]
