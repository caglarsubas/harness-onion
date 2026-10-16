#!/usr/bin/env python3
"""LIC-HOST license-policy amendment A2: Zlib default-allowed, on top of the adopted amendment A1.

The base policy (legal/third-party-license-policy.yaml, 0.3.0) and A1 (legal/license-policy-amendment/,
scripts/license_amendment.py) stay byte-identical, because later records pin them. A2 adds one overlay list,
`additionalDefaultAllowedSpdx` = ["Zlib"]:
- the decision is the lane monitor's (owner-delegated), 2026-10-15;
- L2-1 (a): Zlib is default-allowed globally, like the base's own default-allowed list.

The classifier is A1's. A2 builds A1's Policy from the base categories with Zlib added to DEFAULT_ALLOWED, so every A1 rule
applies unchanged: the class, the decisions and elections, OR-choice, AND-term, legacy slash and precedence.

check(read) validates:
- A1, through A1's own check;
- the A2 record and its pins of the base and A1;
- the A2 vectors. Every A1 vector replays under A2 to its A1 result, and A2 changes none of them: the one A1 vector with
  a Zlib leaf elects Apache-2.0 either way. Every new case classifies as expected under A2, and as it did under A1.
"""
from __future__ import annotations

from pathlib import Path

try:
    import license_amendment as a1
except ImportError:
    from scripts import license_amendment as a1

RECORD_PATH = "legal/license-policy-amendment-v2/amendment.json"
VECTORS_PATH = "legal/license-policy-amendment-v2/vectors.json"
A1_MODEL_PATH = "scripts/license_amendment.py"
SCHEMA = "planeon.internal.license-policy-amendment/v2"
VECTORS_SCHEMA = "planeon.internal.license-policy-amendment-vectors/v3"
AMENDMENT_ID = "LIC-HOST-A2"
ADDED_DEFAULT_ALLOWED = ("Zlib",)
OWNER_DECISIONS = (("LIC-ZLIB", "2026-10-15"), ("L2-1", "2026-10-16"), ("L2-2", "2026-10-16"))
MIN_CASES = 30
# Zlib alone must be shown default-allowed in every component kind and every base custody (L2-1 (a): globally).
CUSTODIES = ("REPOSITORY_BUILT", "UPSTREAM_PINNED", "COMPOSITE_REVIEW_REQUIRED", "TENANT_ATTESTED_PINNED")
# The outcomes the new cases must reach under A2 (Zlib alone, in each compound and election, blocked, refused and
# exactly matched only).
REQUIRED_A2_OUTCOMES = ("DEFAULT_ALLOWED", "ACCEPTED_OR", "ACCEPTED_AND", "DENIED", "UNKNOWN",
                        "OPTIONAL_EXPLICIT_REVIEW", "OUT_OF_SCOPE", "REFUSED")

require = a1.require
classify = a1.classify


def _sha(raw: bytes) -> str:
    return a1.digest(raw)


def _result(policy, case: dict) -> dict:
    try:
        got = classify(policy, case["expression"], case["component"])
    except ValueError:
        return {"outcome": "REFUSED", "elections": []}
    return {"outcome": got["outcome"], "elections": got["elections"]}


def _leaves(expression: str, crate_field: bool) -> set:
    """Every exact term of the expression (after legacy normalisation), a WITH term whole; empty when it does not
    parse. So "Zlib WITH LLVM-exception" is not the term Zlib."""
    try:
        node = a1.parse(a1.normalise_legacy(expression) if crate_field else expression)
    except ValueError:
        return set()
    found, stack = set(), [node]
    while stack:
        item = stack.pop()
        if type(item) is str:
            found.add(item)
        else:
            stack.extend(item[1])
    return found


def record(raw: bytes, pins: dict) -> dict:
    """The closed A2 record. `pins` maps each pinned path to the SHA-256 of the bytes the reader returned."""
    value = a1._json(raw)
    a1._closed(value, ("schemaVersion", "amendmentId", "base", "predecessor", "ownerDecisions",
                       "additionalDefaultAllowedSpdx", "rule", "effects", "carriedFindings", "notClaimed"),
               "closed A2 record")
    require(value["schemaVersion"] == SCHEMA and value["amendmentId"] == AMENDMENT_ID, "A2 schema and id")
    require(value["base"] == {"path": a1.BASE_PATH, "sha256": a1.BASE_SHA256, "policyVersion": "0.3.0"}, "the base pin")
    require(value["predecessor"] == {"amendmentId": a1.AMENDMENT_ID,
                                     "record": {"path": a1.RECORD_PATH, "sha256": pins[a1.RECORD_PATH]},
                                     "vectors": {"path": a1.VECTORS_PATH, "sha256": pins[a1.VECTORS_PATH]},
                                     "model": {"path": A1_MODEL_PATH, "sha256": pins[A1_MODEL_PATH]}},
            "the A1 pins")
    decisions = value["ownerDecisions"]
    require(type(decisions) is list and [(row.get("id"), row.get("date")) for row in decisions if type(row) is dict]
            == list(OWNER_DECISIONS), "owner decisions LIC-ZLIB, L2-1, L2-2")
    for row in decisions:
        a1._closed(row, ("id", "date", "via", "selected", "text"), "closed owner decision")
        a1._text(row["via"], "decision route")
        a1._text(row["text"], "verbatim decision text")
        require(row["selected"] == (None if row["id"] == "LIC-ZLIB" else "a"), "the selected option")
    require(value["additionalDefaultAllowedSpdx"] == list(ADDED_DEFAULT_ALLOWED), "Zlib, and only Zlib, is added")
    a1._text(value["rule"], "the overlay rule")
    effects = value["effects"]
    require(type(effects) is list and len(effects) == 1, "one stated effect (L2-2)")
    a1._closed(effects[0], ("record", "subject", "expression", "recorded", "underA2", "recordChanged", "decidedBy"),
               "closed effect")
    require(effects[0]["expression"] == "Zlib" and effects[0]["recorded"] == "DENY_UNKNOWN_LICENSE"
            and effects[0]["underA2"] == "DEFAULT_ALLOWED" and effects[0]["recordChanged"] is False
            and effects[0]["decidedBy"] == "L2-2", "the phoenix-sqlean effect is stated, and its record is unchanged")
    a1._text(effects[0]["record"], "effect record")
    a1._text(effects[0]["subject"], "effect subject")
    carried = value["carriedFindings"]
    require(type(carried) is list and [row.get("id") for row in carried if type(row) is dict] == ["P2-F1", "P2-F2"],
            "the two carried LIC-HOST-F findings")
    for row in carried:
        a1._closed(row, ("id", "source", "severity", "location", "finding", "requiredChange", "disposition"),
                   "closed carried finding")
        for key in ("source", "location", "finding", "requiredChange", "disposition"):
            a1._text(row[key], "carried finding " + key)
        require(row["severity"] == "NOTE", "the carried findings are NOTEs")
    require(type(value["notClaimed"]) is list and value["notClaimed"]
            and all(type(text) is str and text for text in value["notClaimed"]), "non-claims")
    return value


def effective_policy(read) -> "a1.Policy":
    """The base categories under A1 and A2, built from the same verified bytes check() read."""
    try:
        return _check(read)[1]
    except (TypeError, KeyError, AttributeError, IndexError, RecursionError) as error:
        raise ValueError("malformed A2 record: %s" % error) from None


def check(read) -> dict:
    try:
        return _check(read)[0]
    except (TypeError, KeyError, AttributeError, IndexError, RecursionError) as error:
        raise ValueError("malformed A2 record: %s" % error) from None


def _once(read):
    """The reader, memoised per path: A1's check and A2's pins and replay see the same bytes of each path."""
    seen = {}

    def memo(path: str) -> bytes:
        if path not in seen:
            seen[path] = read(path)
        return seen[path]
    return memo


def _check(read) -> tuple:
    read = _once(read)
    _, policy1 = a1._check(read)                     # A1 as adopted, its 88 vectors included
    raws = {path: read(path) for path in (a1.RECORD_PATH, a1.VECTORS_PATH, A1_MODEL_PATH)}   # the bytes A1's check used
    pins = {path: _sha(raw) for path, raw in raws.items()}
    # The A1 classifier that runs is the pinned one. This reads the imported module's own file, outside the reader; the
    # packet layer pins the import closure (safe_yaml included) and routes this identity check (carried, review LR2-4).
    require(_sha(Path(a1.__file__).read_bytes()) == pins[A1_MODEL_PATH], "the running A1 classifier is the pinned one")
    value = record(read(RECORD_PATH), pins)
    base = read(a1.BASE_PATH)
    require(_sha(base) == a1.BASE_SHA256, "the base policy changed")
    categories = a1.base_categories(base)
    exact = frozenset().union(*categories.values())
    added = frozenset(ADDED_DEFAULT_ALLOWED)
    require(not added & exact, "an added term is on no base list")
    require(not added & set(a1.CLASS_EXPRESSIONS) and not added & set(a1.DECISIONS)
            and not any(term in group for group in a1.OWNER_ELECTIONS for term in added),
            "an added term is not an A1 class term, decision or election")
    policy = a1.Policy(dict(categories, DEFAULT_ALLOWED=categories["DEFAULT_ALLOWED"] | added))
    vectors = a1._json(read(VECTORS_PATH))
    a1._closed(vectors, ("schemaVersion", "a1Replay", "cases"), "closed A2 vectors")
    require(vectors["schemaVersion"] == VECTORS_SCHEMA, "A2 vector schema")
    replay = vectors["a1Replay"]
    a1._closed(replay, ("vectors", "changed"), "closed A1 replay")
    require(replay["vectors"] == {"path": a1.VECTORS_PATH, "sha256": pins[a1.VECTORS_PATH]}, "the replayed A1 vectors")
    changed = []
    for case in a1._json(raws[a1.VECTORS_PATH])["cases"]:
        before, after = _result(policy1, case), _result(policy, case)
        if before != after:
            require(added & _leaves(case["expression"], case["component"]["crateField"]),
                    "an A1 result changes only through an added term: %r" % case["expression"])
            changed.append({"expression": case["expression"], "component": case["component"], "a1": before, "a2": after})
    require(replay["changed"] == changed, "the A1 results A2 changes, exactly")
    cases = vectors["cases"]
    require(type(cases) is list and len(cases) >= MIN_CASES, "A2 cases")
    keys = set()
    for case in cases:
        a1._closed(case, ("expression", "component", "a1", "a2", "note"), "closed A2 vector")
        key = a1.canonical_json([case["expression"], case["component"]])
        require(key not in keys, "duplicate A2 vector")
        keys.add(key)
        a1.validate_component(case["component"])
        for name, which in (("a1", policy1), ("a2", policy)):
            a1._closed(case[name], ("outcome", "elections"), "closed expected result")
            require(case[name]["outcome"] in a1.OUTCOMES, "vector outcome")
            got = _result(which, case)
            require(got == case[name], "vector %r for %s under %s: expected %s, got %s"
                    % (case["expression"], case["component"]["name"], name.upper(), case[name], got))
        a1._text(case["note"], "vector note")
    require(set(REQUIRED_A2_OUTCOMES) <= {case["a2"]["outcome"] for case in cases}, "the A2 cases reach every required outcome")
    require(any(case["a1"] != case["a2"] for case in cases) and any(case["a1"] == case["a2"] for case in cases),
            "the A2 cases include changed results and unchanged controls")
    require(all(added & _leaves(case["expression"], case["component"]["crateField"]) or case["a1"] == case["a2"]
                for case in cases), "a result changes only through an added term")
    alone = [case["component"] for case in cases if case["expression"] in added
             and case["a2"] == {"outcome": "DEFAULT_ALLOWED", "elections": []}]
    require({c["kind"] for c in alone} == set(a1.KINDS) and set(CUSTODIES) <= {c["custody"] for c in alone},
            "an added term alone is shown default-allowed in every kind and every base custody")
    return value, policy


if __name__ == "__main__":
    from pathlib import Path

    root = Path(__file__).resolve().parents[1]
    check(lambda path: (root / path).read_bytes())
    print("LIC-HOST amendment A2 valid: base policy and A1 unchanged; Zlib default-allowed; A1 and A2 vectors hold.")
