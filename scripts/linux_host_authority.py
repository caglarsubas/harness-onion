#!/usr/bin/env python3
"""Linux host-authority contract v1 (architecture/linux-host-authority/, MET-LINUX-008): offline checker.

Roadmap item LINUX-HOST-AUTH-001 (owner decisions LX-D1 and LX-D2; design revision 7 with the binding build rules
B-LHA-1, B-LHA-2 and B-LHA-4 to B-LHA-18). Four closed records, each with a schema in the contract directory:

- host-authority.json: the superseding authority. It relaxes, member by member and bound by span, only the capacity
  predicates and the independence clause (with its replacement predicate), and lists every kept, satisfied, cost-scope
  and reviewed-not-binding text, and every occurrence of the two readings, with its span;
- host-recipe.json: the two hosts per run, their access, egress, inventories and runtime writes, and the runbook steps;
- launcher-install.json: the operator install steps, the signed-drop installer and the trigger units;
- custody-model.json: the signing authorities, the per-run credentials and the live custody duties.

A fifth schema, drop-manifest.schema.json, closes the per-run drop manifest the signed-drop installer verifies.

Candidate c7's systematic pass (MON-LHA-C7-SYSTEMATIC): every id-keyed list is closed before anything reads it by id
(each id once, so a wrong entry can never hide behind a correct copy; the design's ids, in order where it fixes one),
and every decision-carrying leaf of the four records is pinned to its published value in the generated LEAF_PINS
block, each pin under the source it cites (a decision, a B-LHA rule or a DESIGN.r7.md line). image.family alone is
structure only: the family is data, not code.

DATA_CHECK_ONLY: nothing here touches a cloud, holds a credential or installs anything. Standard library only. The
parse rules, the canonical form, the closed schema subset and the string rule are LAB-RUNPLAN-001's
(scripts/lab_run_plan.py), restated here; on top of them every number is an integer, and the role-label rule refuses a
project id, a custom role's full name, a price, a POSIX name or a UID. Every cited file is read from the checkout and
must still be its bytes at the packet's base (each entry's file sha256); spans are re-derived from those bytes.

Usage (repository root):
  python3 -I -B scripts/linux_host_authority.py check     check the schemas and the four records
  python3 -I -B scripts/linux_host_authority.py replay    the same, then replay every vector
"""
from __future__ import annotations

import datetime
import hashlib
import json
import math
import re
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
CONTRACT_DIR = "architecture/linux-host-authority/"
KINDS = ("authority", "recipe", "launcher", "custody")
RECORD_PATHS = {"authority": CONTRACT_DIR + "host-authority.json", "recipe": CONTRACT_DIR + "host-recipe.json",
                "launcher": CONTRACT_DIR + "launcher-install.json", "custody": CONTRACT_DIR + "custody-model.json"}
SCHEMA_PATHS = {"authority": CONTRACT_DIR + "host-authority.schema.json",
                "recipe": CONTRACT_DIR + "host-recipe.schema.json",
                "launcher": CONTRACT_DIR + "launcher-install.schema.json",
                "custody": CONTRACT_DIR + "custody-model.schema.json",
                "drop": CONTRACT_DIR + "drop-manifest.schema.json"}
VECTORS_PATH = CONTRACT_DIR + "vectors.json"
VERSIONS = {"authority": "planeon.internal.linux-host-authority/v1", "recipe": "planeon.internal.linux-host-recipe/v1",
            "launcher": "planeon.internal.linux-launcher-install/v1", "custody": "planeon.internal.linux-key-custody/v1",
            "drop": "planeon.internal.linux-drop-manifest/v1",
            "vectors": "planeon.internal.linux-host-authority-vectors/v1"}
DIALECT = "https://json-schema.org/draft/2020-12/schema"
# The packet's base: every file sha256, line, fragment and span in the records is taken there.
BASE_COMMIT = "a88276171453760e46b28e8f6f0c0bb4bbfade5d"

# ---------------------------------------------------------------------------------------------------------------------
# Restated from LAB-RUNPLAN-001 (scripts/lab_run_plan.py): the closed schema subset, the strict parse, the canonical
# form and the string rule. The candidate's tests compare these with that checker.

SCHEMA_KEYWORDS = {"$id", "title", "description", "type", "properties", "required", "additionalProperties", "items",
                   "minItems", "maxItems", "uniqueItems", "enum", "const", "pattern", "minLength", "maxLength", "minimum",
                   "maximum", "exclusiveMinimum"}
TYPES = {"object": dict, "array": list, "string": str, "boolean": bool, "null": type(None)}
TYPE_NAMES = set(TYPES) | {"integer", "number"}
KEYWORD_RULES = {"pattern": ("string", str), "minLength": ("string", int), "maxLength": ("string", int),
                 "minimum": ("numeric", (int, float)), "maximum": ("numeric", (int, float)),
                 "exclusiveMinimum": ("numeric", (int, float)), "minItems": ("array", int), "maxItems": ("array", int),
                 "uniqueItems": ("array", bool)}
INTEGER_LIMIT = 10 ** 12
FORBIDDEN_TEXT = (re.compile(r"@"), re.compile(r"-----BEGIN"), re.compile(r"PRIVATE KEY"), re.compile(r"AKIA[0-9A-Z]{4}"),
                  re.compile(r"ASIA[0-9A-Z]{4}"), re.compile(r"AIza[0-9A-Za-z_-]{4}"), re.compile(r"gh[pousr]_[0-9A-Za-z]{4}"),
                  re.compile(r"github_pat_"), re.compile(r"xox[abpr]-"), re.compile(r"ya29\.[0-9A-Za-z_-]{4}"),
                  re.compile(r"1//[0-9A-Za-z_-]{4}"), re.compile(r"(?i)gserviceaccount"), re.compile(r"private_key_id"),
                  re.compile(r"GOCSPX-"), re.compile(r"[0-9A-Fa-f]{6}-[0-9A-Fa-f]{6}-[0-9A-Fa-f]{6}"))


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(message)


def canonical(value: Any) -> bytes:
    """Sorted keys, no whitespace, UTF-8 (LAB-RUNPLAN-001's canonical form)."""
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False).encode("utf-8")


def strict(raw: bytes) -> Any:
    """UTF-8 JSON without a byte-order mark; duplicate keys, non-finite numbers, integral floats, oversized integers and
    lone surrogates refused (LAB-RUNPLAN-001's parse rules)."""
    def pairs(items: list) -> dict:
        value: dict = {}
        for key, item in items:
            require(key not in value, "duplicate key " + key)
            value[key] = item
        return value

    def constant(name: str) -> Any:
        raise ValueError("non-finite number " + name)

    def number(text: str) -> float:
        value = float(text)
        require(math.isfinite(value), "non-finite number " + text)
        require(not value.is_integer(), "an integral number is written without a decimal point or exponent: " + text)
        return value

    def integer(text: str) -> int:
        require(len(text.lstrip("-")) <= 13 and abs(int(text)) <= INTEGER_LIMIT, "integer out of range")
        return int(text)

    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        raise ValueError("a document is UTF-8 without a byte-order mark") from None
    require(not text.startswith("﻿"), "a document is UTF-8 without a byte-order mark")
    value = json.loads(text, object_pairs_hook=pairs, parse_constant=constant, parse_float=number, parse_int=integer)
    try:
        canonical(value)
    except UnicodeEncodeError:
        raise ValueError("a string is not valid Unicode (a lone surrogate)") from None
    return value


def check_schema(schema: Any, where: str = "$") -> None:
    """Only the closed keywords, each where it applies and with a value of its type; every schema has a type, a const or
    an enum; a schema with properties is exactly an object schema and closed; items only on arrays."""
    require(type(schema) is dict and set(schema) <= SCHEMA_KEYWORDS, "schema keyword outside the subset at " + where)
    require("type" in schema or "const" in schema or "enum" in schema, "schema without type, const or enum at " + where)
    kind = schema.get("type")
    kinds = kind if type(kind) is list else [kind]
    require(kind is None or (kinds != [] and all(type(name) is str and name in TYPE_NAMES for name in kinds)
                             and len(set(kinds)) == len(kinds)), "schema type names at " + where)
    require(all(type(schema[key]) is str for key in ("$id", "title", "description") if key in schema)
            and ("enum" not in schema or (type(schema["enum"]) is list and schema["enum"] != [])),
            "schema annotation or enum value type at " + where)
    for key, (needs, value_type) in KEYWORD_RULES.items():
        if key in schema:
            value = schema[key]
            applies = ("integer" in kinds or "number" in kinds) if needs == "numeric" else needs in kinds
            typed = (type(value) is bool if value_type is bool
                     else isinstance(value, value_type) and type(value) is not bool and (value_type is not int or value >= 0))
            require(applies and typed, "schema keyword %s misplaced or mistyped at %s" % (key, where))
    if "pattern" in schema:
        try:
            re.compile(schema["pattern"])
        except re.error:
            raise ValueError("schema keyword pattern misplaced or mistyped at " + where) from None
    if "properties" in schema or "object" in kinds or "required" in schema or "additionalProperties" in schema:
        require(kind == "object" and schema.get("additionalProperties") is False and type(schema.get("properties")) is dict
                and type(schema.get("required")) is list and set(schema["required"]) == set(schema["properties"])
                and len(schema["required"]) == len(set(schema["required"])), "closed object schema at " + where)
        for name, sub in schema["properties"].items():
            check_schema(sub, where + "." + name)
    if "items" in schema or "array" in kinds:
        require(kind == "array" and "items" in schema, "array schema with items at " + where)
        check_schema(schema["items"], where + "[]")


def _type_ok(value: Any, kind: Any) -> bool:
    kinds = kind if type(kind) is list else [kind]
    for name in kinds:
        if name == "integer" and type(value) is int:
            return True
        if name == "number" and type(value) in (int, float):
            return True
        if name in TYPES and type(value) is TYPES[name]:
            return True
    return False


def shape(value: Any, schema: dict, where: str = "$") -> None:
    """The value against the closed schema subset; the first difference raises naming its JSON path."""
    if type(value) is float:
        require(math.isfinite(value) and not value.is_integer(), "schema %s integral or non-finite float" % where)
    if "type" in schema:
        require(_type_ok(value, schema["type"]), "schema %s type" % where)
    if "const" in schema:
        require(value == schema["const"] and type(value) is type(schema["const"]), "schema %s const" % where)
    if "enum" in schema:
        require(any(value == item and type(value) is type(item) for item in schema["enum"]), "schema %s enum" % where)
    if type(value) is str:
        if "pattern" in schema:
            require(re.fullmatch(schema["pattern"], value) is not None, "schema %s pattern" % where)
        if "minLength" in schema:
            require(len(value) >= schema["minLength"], "schema %s minLength" % where)
        if "maxLength" in schema:
            require(len(value) <= schema["maxLength"], "schema %s maxLength" % where)
    if type(value) in (int, float):
        if "minimum" in schema:
            require(value >= schema["minimum"], "schema %s minimum" % where)
        if "exclusiveMinimum" in schema:
            require(value > schema["exclusiveMinimum"], "schema %s exclusiveMinimum" % where)
        if "maximum" in schema:
            require(value <= schema["maximum"], "schema %s maximum" % where)
    if type(value) is dict and schema.get("type") == "object":
        require(set(value) == set(schema["properties"]), "schema %s closed object" % where)
        for name, sub in schema["properties"].items():
            shape(value[name], sub, where + "." + name)
    if type(value) is list and schema.get("type") == "array":
        if "minItems" in schema:
            require(len(value) >= schema["minItems"], "schema %s minItems" % where)
        if "maxItems" in schema:
            require(len(value) <= schema["maxItems"], "schema %s maxItems" % where)
        if schema.get("uniqueItems"):
            require(len({canonical(item) for item in value}) == len(value), "schema %s uniqueItems" % where)
        for index, item in enumerate(value):
            shape(item, schema["items"], "%s[%d]" % (where, index))


# The strings each rule below has already passed: both rules are pure functions of the string, so a string that passed
# once passes again, and only a failing string's message needs its path (c7: the replay runs every rule per vector).
_PASSED_FREE_TEXT: set = set()
_PASSED_NAMED_TEXT: set = set()


def free_text(value: Any, where: str = "$") -> None:
    """No string anywhere in a document carries a credential, an account identity or a billing account."""
    if type(value) is str:
        if value not in _PASSED_FREE_TEXT:
            require(not any(pattern.search(value) for pattern in FORBIDDEN_TEXT),
                    "no credential, account identity or billing account in %s" % where)
            _PASSED_FREE_TEXT.add(value)
    elif type(value) is dict:
        for name, item in value.items():
            free_text(item, where + "." + name)
    elif type(value) is list:
        for index, item in enumerate(value):
            free_text(item, "%s[%d]" % (where, index))


# ---------------------------------------------------------------------------------------------------------------------
# This contract's own parse and string rules.

# Role labels only (B-LHA-13): no member names a project id, an account, a key, a price, a POSIX name or a UID. The
# string rule above refuses an account (an address shape) and key material; these refuse the rest, in this order.
NAMED_TEXT = ((re.compile(r"(?:projects|organizations|folders)/[^/\s]+/roles/"),
               "role labels only: a custom role by its role label, never its full name, in %s"),
              (re.compile(r"(?:projects|organizations|folders)/[A-Za-z0-9]"),
               "role labels only: no project, folder or organization id in %s"),
              (re.compile(r"ssh-(?:ed25519|rsa|dss) |ecdsa-sha2-"), "role labels only: no key in %s"),
              (re.compile(r"(?i)\$\s?[0-9]|\b(?:usd|eur|gbp)\b|€"), "role labels only: no price in %s"),
              (re.compile(r"(?i)[ug]id[ =:]+[0-9]"), "role labels only: no POSIX name or UID in %s"),
              (re.compile(r"\b[a-z0-9][a-z0-9.-]*_[a-z0-9-]+_(?:com|net|org|io|ai|dev|co|uk|de)\b"),
               "role labels only: no POSIX name or UID in %s"))


def named_text(value: Any, where: str = "$") -> None:
    if type(value) is str:
        if value not in _PASSED_NAMED_TEXT:
            for pattern, message in NAMED_TEXT:
                require(pattern.search(value) is None, message % where)
            _PASSED_NAMED_TEXT.add(value)
    elif type(value) is dict:
        for name, item in value.items():
            named_text(item, where + "." + name)
    elif type(value) is list:
        for index, item in enumerate(value):
            named_text(item, "%s[%d]" % (where, index))


def integers_only(value: Any, where: str = "$") -> None:
    """Every number in these records is an integer; a non-integral number is refused (the design's parse rule, on top
    of LAB-RUNPLAN-001's refusal of integral floats)."""
    if type(value) is float:
        raise ValueError("a number is an integer; a non-integral number is refused at " + where)
    if type(value) is dict:
        for name, item in value.items():
            integers_only(item, where + "." + name)
    elif type(value) is list:
        for index, item in enumerate(value):
            integers_only(item, "%s[%d]" % (where, index))


def parse(raw: bytes) -> Any:
    value = strict(raw)
    integers_only(value)
    return value


def check_root_schema(schema: Any, kind: str) -> None:
    """A record schema declares draft 2020-12 at its root, names its record's version as its $id, and otherwise uses only
    the restated closed subset."""
    require(type(schema) is dict and schema.get("$schema") == DIALECT,
            "a schema declares JSON Schema draft 2020-12 at its root")
    rest = {key: value for key, value in schema.items() if key != "$schema"}
    require(rest.get("$id") == VERSIONS[kind], "a schema's $id is its record's schema version")
    check_schema(rest)
    require(rest["properties"].get("schemaVersion") == {"const": VERSIONS[kind]}, "a schema fixes its record's version")


def _sha(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _instant(text: str) -> datetime.datetime:
    return datetime.datetime.fromisoformat(text[:-1] + "+00:00")


def _closed(items: list, key: str, expected: list, message: str, where: str, ordered: bool = True) -> dict:
    """(i) An id-keyed list, compared before anything reads it by id (MON-LHA-C7-SYSTEMATIC; LHA-C2-2): each id once, so
    a wrong entry can never hide behind a correct copy with the same id, then the design's ids, in order where the
    design fixes one and otherwise as an exact set. Returns the entries by id."""
    ids = [item[key] for item in items]
    require(len(set(ids)) == len(ids), "an id-keyed list names each entry once: %s, by %s" % (where, key))
    require(ids == expected if ordered else sorted(ids) == sorted(expected), message)
    return {item[key]: item for item in items}


# ---------------------------------------------------------------------------------------------------------------------
# Pinned facts. The spans and digests below are computed from the base bytes by the build script; never edited by hand.

# BEGIN PINNED
PINNED: dict = {'supersedes': {'LR-CAPACITY-ZERO-COST': {'path': 'docs/alpha-2/LINUX_READINESS.md',
                                          'member': None,
                                          'lines': [63, 66],
                                          'span': '1cebce04ccbe84683f6fd4d41b70e8ee09cf042b69e85fd971bf294afa71bb22',
                                          'kind': 'CAPACITY',
                                          'scope': 'ALL',
                                          'keptIn': []},
                'LR-NO-CLOUD-INSTANCE': {'path': 'docs/alpha-2/LINUX_READINESS.md',
                                         'member': None,
                                         'lines': [63, 66],
                                         'span': 'e9c1317d8562c9fc12dac151bf8c23f567c81f5001c74d0f9e9dfa0e946df64f',
                                         'kind': 'CAPACITY',
                                         'scope': 'ALL',
                                         'keptIn': ['LR-KEPT-HOSTED-RUNNER',
                                                    'LR-KEPT-NEW-BROKER',
                                                    'LR-KEPT-PAID-KEY',
                                                    'LR-KEPT-REGISTRY-EGRESS',
                                                    'LR-KEPT-AUTOMATIC-PULL']},
                'LRJ-BILLING-CAPACITY': {'path': 'architecture/linux-readiness.json',
                                         'member': 'billing.capacity',
                                         'lines': [117, 117],
                                         'span': '78cf251144949d7521fa01f2d7ec55f74c49de8070f6e81e30887ee7b824edd6',
                                         'kind': 'CAPACITY',
                                         'scope': 'ALL',
                                         'keptIn': []},
                'LRJ-BILLING-NEW-PROVISIONING': {'path': 'architecture/linux-readiness.json',
                                                 'member': 'billing.newProvisioning',
                                                 'lines': [112, 112],
                                                 'span': '43e126ed0c900c78e03bc6fbf92572c549119830d372984c9b5ee846efca5ee3',
                                                 'kind': 'CAPACITY',
                                                 'scope': 'ALL',
                                                 'keptIn': ['LRJ-KEPT-HOSTED-RUNNERS',
                                                            'LRJ-KEPT-PAID-APIS',
                                                            'LRJ-KEPT-THIRD-PARTY-KEYS',
                                                            'LRJ-KEPT-RAW-SOCKETS']},
                'REP-ZERO-COST-CAPACITY': {'path': 'docs/alpha-2/LINUX_READINESS_REPAIRS.md',
                                           'member': None,
                                           'lines': [147, 149],
                                           'span': 'fd947b85a9fc5e76d362ffd2db49a78ad51a467ab9340291b96fab218766ae83',
                                           'kind': 'CAPACITY',
                                           'scope': 'ALL',
                                           'keptIn': ['REP-KEPT-UNTIL']},
                'REP-CREATE-CAPACITY': {'path': 'docs/alpha-2/LINUX_READINESS_REPAIRS.md',
                                        'member': None,
                                        'lines': [155, 155],
                                        'span': '2bb2c97556fc0c27e35dd6e87ccac298a599ae0f43b3f160bed6c582f7e93ec5',
                                        'kind': 'CAPACITY',
                                        'scope': 'ALL',
                                        'keptIn': ['REP-KEPT-NEVER']},
                'CI-LIVE-CAMPAIGNS': {'path': 'docs/alpha-2/CI_CAPACITY_EXCEPTION.md',
                                      'member': None,
                                      'lines': [7, 7],
                                      'span': '6b4fb3d39000e8376b1cb99b6c529bc97cdcfe67544f57d3573f614462bdb1a0',
                                      'kind': 'CAPACITY',
                                      'scope': 'LIVE_CAMPAIGNS_ONLY',
                                      'keptIn': ['CI-KEPT-OTHER-SCOPES', 'CI-KEPT-NO-PAID-API']},
                'LR-INDEPENDENT-SIGNERS': {'path': 'docs/alpha-2/LINUX_READINESS.md',
                                           'member': None,
                                           'lines': [66, 68],
                                           'span': 'ef16bfe6fe5f6f33c67893398a1cf0f571e0ece11d06f48e2c36b9daac26806e',
                                           'kind': 'INDEPENDENCE',
                                           'scope': 'ALL',
                                           'keptIn': ['LR-KEPT-MISSING']},
                'LR-EXISTING-INDEPENDENT': {'path': 'docs/alpha-2/LINUX_READINESS.md',
                                            'member': None,
                                            'lines': [146, 148],
                                            'span': 'aeefa2d754419cbd7f1d8e0c395308d77db62d254bd477242e7b396354e5664a',
                                            'kind': 'INDEPENDENCE',
                                            'scope': 'ALL',
                                            'keptIn': ['LR-KEPT-LIVE-ENTRY']},
                'LRJ-INDEPENDENT-SIGNATURES': {'path': 'architecture/linux-readiness.json',
                                               'member': 'evidence.requiredBindings[11]',
                                               'lines': [106, 106],
                                               'span': 'f506fb8c3445271a77c0303d1f9c558251d5404af9882c584045a89c256bdaf9',
                                               'kind': 'INDEPENDENCE',
                                               'scope': 'ALL',
                                               'keptIn': []}},
 'satisfied': {'LR-INDEPENDENT-SIGNATURES-138': {'path': 'docs/alpha-2/LINUX_READINESS.md',
                                                 'member': None,
                                                 'lines': [138, 138],
                                                 'span': '98679cdee990625b1b8f9098bd356a3a4141eb07ac6f09d421d47c57e712eea2'},
               'TL-FRESH-INDEPENDENTLY-SIGNED': {'path': 'docs/TRUSTED_LIVE_CAMPAIGN_RUNNER_CONTRACT.md',
                                                 'member': None,
                                                 'lines': [456, 457],
                                                 'span': 'f947d6f219f24e3504f4cf9c553940172a45d23049e19aa1dab03eb3de5ec945'},
               'TL-AFTER-INDEPENDENT-SIGNATURES': {'path': 'docs/TRUSTED_LIVE_CAMPAIGN_RUNNER_CONTRACT.md',
                                                   'member': None,
                                                   'lines': [532, 532],
                                                   'span': '53a6bbe8ebfce79b05ff25c0342f9d1f52cb48bb926d4dc6fbc143637ee99189'},
               'COR-THREE-INDEPENDENT-ROLES': {'path': 'docs/alpha-2/CREDENTIAL_ORDERING_REPAIR.md',
                                               'member': None,
                                               'lines': [37, 37],
                                               'span': 'e35323d6428c8aa2ad734af1fd92c86e5fb9f61230b2a19c51f01505c55febb2'}},
 'unchanged': {'LR-KEPT-HOSTED-RUNNER': {'path': 'docs/alpha-2/LINUX_READINESS.md',
                                         'member': None,
                                         'lines': [63, 69],
                                         'span': '0221500d8719640d516388bab21859ecad8ab9dd89ad55d7ef1d0cea92fb405b'},
               'LR-KEPT-NEW-BROKER': {'path': 'docs/alpha-2/LINUX_READINESS.md',
                                      'member': None,
                                      'lines': [63, 69],
                                      'span': '733efdd538e8942ab9b30a0c0353888a5c7fa71a3d6f5c97bfba97f41d45320d'},
               'LR-KEPT-PAID-KEY': {'path': 'docs/alpha-2/LINUX_READINESS.md',
                                    'member': None,
                                    'lines': [63, 69],
                                    'span': '940d6504cfe68ad2123ed2029d7a8e476d23bc89225ba816e7417886c19f53a7'},
               'LR-KEPT-REGISTRY-EGRESS': {'path': 'docs/alpha-2/LINUX_READINESS.md',
                                           'member': None,
                                           'lines': [63, 69],
                                           'span': '9bb571fa2845a3aefd62bb43f3a3c1f38d76181b77884f0eb0de4ef9e56859cb'},
               'LR-KEPT-AUTOMATIC-PULL': {'path': 'docs/alpha-2/LINUX_READINESS.md',
                                          'member': None,
                                          'lines': [63, 69],
                                          'span': '824cdb999d1cba99c2035394c91b455371a7e3eaf5b58d0cf05898563e4931b3'},
               'LR-KEPT-MISSING': {'path': 'docs/alpha-2/LINUX_READINESS.md',
                                   'member': None,
                                   'lines': [66, 68],
                                   'span': '7e6782e177aae0c672f3c150728e14ad5197777a97a816e9a1fd329310e4d9bd'},
               'LR-KEPT-NO-ADMIN-PASSWORD': {'path': 'docs/alpha-2/LINUX_READINESS.md',
                                             'member': None,
                                             'lines': [101, 102],
                                             'span': '2d729ddee88073070fab80fb27d2d1ffd5ec4bcde9ffe620af9cd5535340a271'},
               'LR-KEPT-LIVE-ENTRY': {'path': 'docs/alpha-2/LINUX_READINESS.md',
                                      'member': None,
                                      'lines': [146, 148],
                                      'span': '9aa000981f196977160e24cf0bcccba1799cb6e8a06d95797dc3a6f8e956d510'},
               'LRJ-KEPT-HOSTED-RUNNERS': {'path': 'architecture/linux-readiness.json',
                                           'member': 'billing.hostedRunners',
                                           'lines': [113, 113],
                                           'span': '711c3a0fa39fe9b3b21d55ff92b76dc64a3fe12dca20b3bdb9d58aedbcfcbaa1'},
               'LRJ-KEPT-PAID-APIS': {'path': 'architecture/linux-readiness.json',
                                      'member': 'billing.paidApis',
                                      'lines': [114, 114],
                                      'span': '86f2fa6c6fb39e82b5e5b97d8adcf86d2bcfc43c7df203eea95ea2489c108346'},
               'LRJ-KEPT-THIRD-PARTY-KEYS': {'path': 'architecture/linux-readiness.json',
                                             'member': 'billing.thirdPartyKeys',
                                             'lines': [115, 115],
                                             'span': 'fef51243d1e67e7bedbd3fbdfb9feb12aee9e8c9ae5c154049bc2bd1a854c7b9'},
               'LRJ-KEPT-RAW-SOCKETS': {'path': 'architecture/linux-readiness.json',
                                        'member': 'billing.rawContainerSockets',
                                        'lines': [116, 116],
                                        'span': 'a21a459408c091b6004562ba8d3d69bd98a21ef06260391beb8b5280ec02e232'},
               'REP-KEPT-UNTIL': {'path': 'docs/alpha-2/LINUX_READINESS_REPAIRS.md',
                                  'member': None,
                                  'lines': [147, 149],
                                  'span': '418a2dc3c9270d9b138912db2d0cfb1fee0a426f554cfb6b3614cb806147e3af'},
               'REP-KEPT-NEVER': {'path': 'docs/alpha-2/LINUX_READINESS_REPAIRS.md',
                                  'member': None,
                                  'lines': [154, 156],
                                  'span': '22126786d7816739ff90fb48a9d99420ba4d4b6a7e3aee9db5e50de8ebdd3ddc'},
               'CI-KEPT-OTHER-SCOPES': {'path': 'docs/alpha-2/CI_CAPACITY_EXCEPTION.md',
                                        'member': None,
                                        'lines': [7, 7],
                                        'span': 'be1372f8e169a60ff8aad929c37496f822f44814850a572685b7ab212b3ab4f8'},
               'CI-KEPT-NO-PAID-API': {'path': 'docs/alpha-2/CI_CAPACITY_EXCEPTION.md',
                                       'member': None,
                                       'lines': [7, 7],
                                       'span': '2fe6cf48bf973c3384d55755dc3e5e1a975d9ab102d3cfb5032bc44c15c4a694'}},
 'costScope': {'TL-NO-NEW-RESOURCE-CAPACITY': {'path': 'docs/TRUSTED_LIVE_CAMPAIGN_RUNNER_CONTRACT.md',
                                               'member': None,
                                               'lines': [442, 443],
                                               'span': '0f38b0120ccd7b0e8195e5bf8a4e0df868221f0b65b098c89acacb8c990159c2',
                                               'level': 'CAMPAIGN'},
               'COR-NEVER-CREATE-CAPACITY': {'path': 'docs/alpha-2/CREDENTIAL_ORDERING_REPAIR.md',
                                             'member': None,
                                             'lines': [94, 94],
                                             'span': '2bb2c97556fc0c27e35dd6e87ccac298a599ae0f43b3f160bed6c582f7e93ec5',
                                             'level': 'SERVER'},
               'NQR-NO-NEW-CGROUP': {'path': 'docs/alpha-2/NATIVE_QUALIFICATION_READINESS.md',
                                     'member': None,
                                     'lines': [110, 110],
                                     'span': '2b770c6e5b17106ac168a3a1b68f6d30a4308f478a78e98d56e7acd447d41324',
                                     'level': 'READER'},
               'LR-DO-NOT-DESTROY-CAPACITY': {'path': 'docs/alpha-2/LINUX_READINESS.md',
                                              'member': None,
                                              'lines': [163, 163],
                                              'span': '8a56c95e1856418bbb644a560d451b858c643447093a01c85b0ffbb942a7bb8a',
                                              'level': 'EXISTING_CAPACITY'},
               'TL-ENDPOINT-COST-DISPOSITION': {'path': 'docs/TRUSTED_LIVE_CAMPAIGN_RUNNER_CONTRACT.md',
                                                'member': None,
                                                'lines': [241, 244],
                                                'span': 'b59c3756e52ebff03f06bbb7f5404cb7d7a7ca60bd11819d44be51fad135602b',
                                                'level': 'ENDPOINT'},
               'TL-MUTATION-PROFILE': {'path': 'docs/TRUSTED_LIVE_CAMPAIGN_RUNNER_CONTRACT.md',
                                       'member': None,
                                       'lines': [339, 339],
                                       'span': '9843ae5bc0a201ecbc4e9c4d0e62a0bd11fff2b153b3e25ebd9919ccca370297',
                                       'level': 'CLUSTER'}},
 'reviewedNotBinding': {'NQR-NO-NEW-SERVICE': {'path': 'docs/alpha-2/NATIVE_QUALIFICATION_READINESS.md',
                                               'member': None,
                                               'lines': [22, 23],
                                               'span': 'a22af603b83e93b60cc05eda1b927d9e330f07183787cdc6fa288ebb92867b7f'},
                        'NQR-CLOSING-SENTENCE': {'path': 'docs/alpha-2/NATIVE_QUALIFICATION_READINESS.md',
                                                 'member': None,
                                                 'lines': [281, 282],
                                                 'span': '38243b08115f11c346953302d14ce0fa08b7e1595e484ba287cf6cdb84045852'},
                        'TL-PUBLICATION-460': {'path': 'docs/TRUSTED_LIVE_CAMPAIGN_RUNNER_CONTRACT.md',
                                               'member': None,
                                               'lines': [460, 461],
                                               'span': 'dcf40f8dac5184fa29304ab5e96abc89f9c29c30d3083de39a05b8ac05fbb51b'},
                        'TL-PUBLICATION-484': {'path': 'docs/TRUSTED_LIVE_CAMPAIGN_RUNNER_CONTRACT.md',
                                               'member': None,
                                               'lines': [484, 485],
                                               'span': 'dc1ad5a4f54146c00068fb704d7f6734c0dd4ab0ee36a32ee190780e738e8fa7'},
                        'TL-PUBLICATION-524': {'path': 'docs/TRUSTED_LIVE_CAMPAIGN_RUNNER_CONTRACT.md',
                                               'member': None,
                                               'lines': [523, 525],
                                               'span': 'cc9ee4e1b01939e88e50929bdef80a71bcfce9e17fe74012b7dbc493232e5383'},
                        'TL-PUBLICATION-540': {'path': 'docs/TRUSTED_LIVE_CAMPAIGN_RUNNER_CONTRACT.md',
                                               'member': None,
                                               'lines': [540, 541],
                                               'span': 'e394ff7727d5b3daf422f6c171e7fb5ab60104ee1c9bcbd79850d4bc2a98b6f0'},
                        'TL-PUBLICATION-560': {'path': 'docs/TRUSTED_LIVE_CAMPAIGN_RUNNER_CONTRACT.md',
                                               'member': None,
                                               'lines': [560, 561],
                                               'span': 'cf4493b647ddfd72f9f3fbe5d3d709d21807af369e88d7d59c94a7af4b08a427'}},
 'occurrences': {'LRJ-SIGNING-AUTHORITY': {'path': 'architecture/linux-readiness.json',
                                           'member': 'evidence.signingAuthority',
                                           'lines': [108, 108],
                                           'span': 'd3f8a1866728a93794b9c8f6e99c99c352fd117b6fbc379df0a942a319e63559'},
                 'OP-STEP-4-EXISTING': {'path': 'docs/linux-runner/OPERATOR.md',
                                        'member': None,
                                        'lines': [93, 93],
                                        'span': '11602555873496bfcae331907dcdce1dabd0066aa0b6e99da79dc173262604af'},
                 'OP-STEP-5-EXISTING': {'path': 'docs/linux-runner/OPERATOR.md',
                                        'member': None,
                                        'lines': [99, 99],
                                        'span': '11602555873496bfcae331907dcdce1dabd0066aa0b6e99da79dc173262604af'},
                 'OP-STEP-8-EXISTING-KEY': {'path': 'docs/linux-runner/OPERATOR.md',
                                            'member': None,
                                            'lines': [115, 115],
                                            'span': '11602555873496bfcae331907dcdce1dabd0066aa0b6e99da79dc173262604af'},
                 'OP-STEP-8-EXISTING-PATHS': {'path': 'docs/linux-runner/OPERATOR.md',
                                              'member': None,
                                              'lines': [116, 116],
                                              'span': '11602555873496bfcae331907dcdce1dabd0066aa0b6e99da79dc173262604af'},
                 'LR-147-EXISTING': {'path': 'docs/alpha-2/LINUX_READINESS.md',
                                     'member': None,
                                     'lines': [147, 147],
                                     'span': '11602555873496bfcae331907dcdce1dabd0066aa0b6e99da79dc173262604af'},
                 'NQR-28-PRE-EXISTING': {'path': 'docs/alpha-2/NATIVE_QUALIFICATION_READINESS.md',
                                         'member': None,
                                         'lines': [28, 29],
                                         'span': 'a0a8f55b200bafaba71cb93be2d0b1514c0a1f332359cb658ca8b6bf2ae5683a'},
                 'NQR-37-EXISTING': {'path': 'docs/alpha-2/NATIVE_QUALIFICATION_READINESS.md',
                                     'member': None,
                                     'lines': [37, 37],
                                     'span': '3e7b8566ba4b6227175af11b1af05d70e199b7291d04f4008b3acbce3953a4ea'},
                 'LRJ-RUNTIME-TRANSPORT': {'path': 'architecture/linux-readiness.json',
                                           'member': 'evidence.runtimeTransport',
                                           'lines': [109, 109],
                                           'span': 'bdb731fe061da254e298f5ea72909bd12d988d0f36b526b2b732b909f1ab4ea3'},
                 'TL-241-LOCAL-PREEXISTING': {'path': 'docs/TRUSTED_LIVE_CAMPAIGN_RUNNER_CONTRACT.md',
                                              'member': None,
                                              'lines': [240, 241],
                                              'span': 'bdb731fe061da254e298f5ea72909bd12d988d0f36b526b2b732b909f1ab4ea3'},
                 'TL-254-PRE-EXISTING': {'path': 'docs/TRUSTED_LIVE_CAMPAIGN_RUNNER_CONTRACT.md',
                                         'member': None,
                                         'lines': [254, 257],
                                         'span': 'a0a8f55b200bafaba71cb93be2d0b1514c0a1f332359cb658ca8b6bf2ae5683a'},
                 'TL-257-PRE-EXISTING': {'path': 'docs/TRUSTED_LIVE_CAMPAIGN_RUNNER_CONTRACT.md',
                                         'member': None,
                                         'lines': [254, 257],
                                         'span': 'a0a8f55b200bafaba71cb93be2d0b1514c0a1f332359cb658ca8b6bf2ae5683a'},
                 'TL-260-PRE-EXISTING': {'path': 'docs/TRUSTED_LIVE_CAMPAIGN_RUNNER_CONTRACT.md',
                                         'member': None,
                                         'lines': [260, 260],
                                         'span': 'a0a8f55b200bafaba71cb93be2d0b1514c0a1f332359cb658ca8b6bf2ae5683a'},
                 'TL-281-PRE-EXISTING': {'path': 'docs/TRUSTED_LIVE_CAMPAIGN_RUNNER_CONTRACT.md',
                                         'member': None,
                                         'lines': [281, 281],
                                         'span': 'a0a8f55b200bafaba71cb93be2d0b1514c0a1f332359cb658ca8b6bf2ae5683a'},
                 'TL-302-PREEXISTING': {'path': 'docs/TRUSTED_LIVE_CAMPAIGN_RUNNER_CONTRACT.md',
                                        'member': None,
                                        'lines': [302, 302],
                                        'span': '3688890505618f49875d3dbff452104b424cbffcfcb2134795419ee45fcc5dbd'},
                 'TL-321-PRE-EXISTING': {'path': 'docs/TRUSTED_LIVE_CAMPAIGN_RUNNER_CONTRACT.md',
                                         'member': None,
                                         'lines': [321, 321],
                                         'span': '3400e528e43074bb6df0691b678c4293e10d7c77c58b2509241c984e66382fba'},
                 'TL-442-PRE-EXISTING': {'path': 'docs/TRUSTED_LIVE_CAMPAIGN_RUNNER_CONTRACT.md',
                                         'member': None,
                                         'lines': [442, 443],
                                         'span': 'a0a8f55b200bafaba71cb93be2d0b1514c0a1f332359cb658ca8b6bf2ae5683a'},
                 'COR-87-PREEXISTING': {'path': 'docs/alpha-2/CREDENTIAL_ORDERING_REPAIR.md',
                                        'member': None,
                                        'lines': [87, 87],
                                        'span': '3688890505618f49875d3dbff452104b424cbffcfcb2134795419ee45fcc5dbd'},
                 'LRJ-BILLING-CAPACITY-PREEXISTING': {'path': 'architecture/linux-readiness.json',
                                                      'member': 'billing.capacity',
                                                      'lines': [117, 117],
                                                      'span': 'bdb731fe061da254e298f5ea72909bd12d988d0f36b526b2b732b909f1ab4ea3'}},
 'freshness': {'LRJ-MAXIMUM-EVIDENCE-AGE': {'path': 'architecture/linux-readiness.json',
                                            'member': 'gate.maximumEvidenceAgeHours',
                                            'lines': [28, 28],
                                            'span': '650e450743b4a5b605333a331f4bcb06e11a894f3c9bb3645eb1e4665395f639'}},
 'metLinux007': {'LRP-LINUX-CAPACITY': {'path': 'architecture/lab-run-plan/status.json',
                                        'member': 'ownerDecisions[2].decision',
                                        'lines': [146, 146],
                                        'span': '52b930eccf524385e0259511f51e5fdb0bc0a37db4a970b970badd58d0f0b44c'}},
 'beforeLiveLauncher': {'OP-HOST-ISOLATION-ONLY': {'path': 'docs/linux-runner/OPERATOR.md',
                                                   'member': None,
                                                   'lines': [224, 225],
                                                   'span': '73e175d3d715a0d274068b9e07abf8129d0fd4876408c808ce7901f335a4c2e8'}}}
DECISION_SHA256: dict = {'LX-D1': '9fe455c0eee0256b2334e3900595d734b397e368b52660792ac29106d156638c',
 'LX-D2': '89e44c46ae4a4ff9e6933e75cd010cc4a33d1de93e87f9acada865679e62f79d',
 'Q-LHA-ID': 'd9c8f2c007ef0f668c708da35daa4072ec223a041023e8b59c7f9d7d5266fb31',
 'Q-LHA-SERIES': '6b0a6841b5c441cfd5a759ea39de137614bc03eca22b46116b8fdb0dd27048f2',
 'Q-LHA-1': '135ea927dde66137df764329cf15b8e57a8ac20ed03921ae70cc90015ad82749',
 'Q-LHA-2': '313270819d9ce830aa7dc51ba3d876df724b7753ff77ac78948495ffbfd531dc',
 'Q-LHA-3': '235df63bf3315060d19bfdeff7fa7c0ee9ddeb809a381e8284c2a613382ee162',
 'Q-LHA-4': '1e20ea495738914863d003f477727eb2579d59eabff29a2460a549bd921b455e',
 'Q-LHA-5': '4cbe2726e585173757cd72a9ddd0654e9866eae5af77a24a17bc95f401bd360a',
 'Q-LHA-6': 'fa6f8a1e737c77014bc255e0fba9a7bd4e4f1fb2b71e5e8884d6dab847374247',
 'Q-LHA-4-5-6-STAND': 'c841e1b6e7f3810c96c52af22222b1b2a4ec6ca6214cdd9b0017c5eec449bed7',
 'Q-LHA-7': '497013bcbcd57ee755bd8ec84de4dc27f7f00ea6e94557bb5f9a75af3260938f',
 'Q-LHA-8': '31e14c573fe5dc91c046b14f3ab116269a1e3c0efe25101dfc9cb4ded18c74fc',
 'Q-LHA-9': 'f39bdb5ebb273df63d7a6a4843975da35b79331ea1593daff8b8d43368490795',
 'Q-LHA-10': '4be43a8f6e913f2d32b574162ee1ec1bf4c30b0e1d3ed3d6184267a83f6335f0',
 'Q-LHA-11': 'd942441e71f8932ecc69431aebbbaf6e5bf8650e392dcb025e80fb0e048c6bb6',
 'Q-LHA-12': '8d26106914aa2d574be23bea870ea8aabaf0bcb4ec228a7b98dd38dc745aa5fe',
 'Q-LHA-13': 'bc0c4e462f4f8c072041c7d755b369ab53ef716ce442de6e4ad6dd011648f4c7',
 'Q-LHA-14': '95ec23037b40f6ecc0c17e0cb99dc75823acd25a04d51ba5a2e37014fd99f0f4',
 'Q-LHA-15': '0e4deb9367968a5fc1d1ba60717199cb6c6dff032dff3da420b22d90da40c8da',
 'Q-LHA-16-2': '381ce4115e29d9043d23c8db036dbe38a080bdd88f5378f4b8f19db054218ab7',
 'MON-LHA-16-1': 'f2115be4f335cb3cf2431e7f01d878468573f53b77ce2a60ace8af15b06b92d8',
 'MON-LHA-SPLIT': '36ebea94f647736cb7f50b1341222d1c3e21c7f69ffb80705d9d66904d5fce87',
 'MON-LHA-12R': '741e59c59faf0ac126cb6c6f49cb55b8b9a21b31322818163b4f6f114c387a19',
 'MON-LHA-17': '22261e8b76dca583a98e7d9905224603f614a70a315f651bf77bfaf69a79c255',
 'LHA2-11': '4833b43a0d1c3313d859fbce6eed1d29030d23f4543bf7095c04a4fd521ceb04',
 'LHA-CAP': '0f6c6ee142847d12acecefaf573fa2fa538dfe84d407908097379fda1a9709dd',
 'LHA3-8': '04f960a0397a239235dfe5eefc1c8e40d0f2c728a31cc0c0ca34455abc37f8b1',
 'MON-LHA3-1-2': 'e753e576c8bb07545877f051544a399dadde0d1e53b462016023dd3c3732321e',
 'MON-LHA-B1': '87f3ba83a2be0928e84fe3ce2f599a8668e1c6898c32778ae80d702d99a82d8b',
 'MON-LHA-B2': 'dee136b653ed947a515788ee5110d9d288aab87c020f8f4eb2a84e7865b3454d',
 'B-LHA-3': '5dd784b814b00eff0a439fdeb8bffe2935f0dde236a20780a24aa97cea2d58c6',
 'B-LHA-4-12': 'c4b1f73ab3ad90e94bc1b4ef49d2d161813404401eb1f001307f049c17b529ab',
 'OWNER-CUSTOM-ROLE': '52824fdc7ecf5389ae4aebd460f8fb03d557cfcff65835ae33317b1c222602d4',
 'Q-LHA5-1': 'c75c193c335dcbfab871a94dd248b1ce0e25e06ebd508379b057a37fc45e7496',
 'Q-LHA6-3': 'ad47a812966021b28f4f5b8a4279cad0ea78adfba24baae430417725508d9875',
 'MON-LHA-NO-LOCAL-BRIEF': '67e01a7678a17cab0c00fa82b2eed76bd9111d84311698879996956e701a04b6'}
STATEMENT_SHA256: dict = {'replacementPredicate': '5578e0a745c6f67540de949b19ce5d9c7161d47bd9d1506afdfd098b6ac4a4c4',
 'LHA-CN-1': '8861d9442295e59a0893581ad0c0dda9863a86e22e07e938ec61522e15b86422',
 'LHA-CN-2': '9e74371ff3ac386e03d6353fb2a095a992d7d5d6358be25d370fa63da36e8eed'}
# END PINNED

# ---------------------------------------------------------------------------------------------------------------------
# The leaf pins (MON-LHA-C7-SYSTEMATIC (ii)). A generalised leaf path joins keys with '.' and writes a list index as the
# entry's id where the list is id-keyed, [*] otherwise. ID_KEYED names each id-keyed list by its shape path (every list
# written [*]) and its key member; each is closed, by _closed or by the ordered id comparison its record's check makes.

ID_KEYED = {
    "authority": {"supersedes": "id", "satisfied": "id", "unchanged": "id", "costScope": "id",
                  "reviewedNotBinding": "id", "readings": "id", "readings[*].occurrences": "id",
                  "decisions.decisionLines": "id", "consumers.list": "id", "preconditions": "id", "carriedNotes": "id"},
    "recipe": {"hosts": "role", "internalFlows": "id", "firewall.ingress": "id", "machine.metadata": "key",
               "hostInventory.records": "host", "hostInventory.leftOut": "what", "profile": "prerequisite",
               "access.identities": "label", "access.leaseBindings": "role", "access.auditLogCheck.expected": "entry",
               "packages.sources": "what", "runtimeRootWrites": "id", "costScope": "item", "runbook": "id"},
    "launcher": {"signedDropInstaller.fixedTargets": "id", "triggerUnits": "id", "privilegedActions": "action",
                 "exportSet": "host", "liveLauncher.trustMounts": "path", "steps": "id"},
    "custody": {"authorities": "id", "tokenSessions": "id", "perRunCredentials": "id",
                "endpointServerIdentities": "kind", "independence.carriers": "packet", "carriedNotes": "id"},
}
LEAF_PART = re.compile(r"(?:^|\.)([A-Za-z_][A-Za-z0-9_]*)|\[([^\]]+)\]")
_LEAF_TOKENS: dict = {}


def _leaf_tokens(kind: str, path: str) -> list:
    """A leaf path's steps: ("key", name), ("all",) for [*], or ("id", key member, id, the list's shape path)."""
    if (kind, path) not in _LEAF_TOKENS:
        tokens, at, shape = [], 0, ""
        for match in LEAF_PART.finditer(path):
            require(match.start() == at, "a leaf path is dotted keys with [id] or [*] selectors: " + path)
            if match.group(1) is not None:
                tokens.append(("key", match.group(1)))
                shape = shape + "." + match.group(1) if shape else match.group(1)
            elif match.group(2) == "*":
                tokens.append(("all",))
                shape += "[*]"
            else:
                require(shape in ID_KEYED[kind], "a leaf path selects by id only in an id-keyed list: " + path)
                tokens.append(("id", ID_KEYED[kind][shape], match.group(2), shape))
                shape += "[*]"
            at = match.end()
        require(at == len(path) and tokens != [], "a leaf path is dotted keys with [id] or [*] selectors: " + path)
        _LEAF_TOKENS[(kind, path)] = tokens
    return _LEAF_TOKENS[(kind, path)]


def leaf(kind: str, doc: Any, path: str, first: bool = False) -> Any:
    """The value at a generalised leaf path: [*] maps over every entry, nested, so a value moved from one entry to
    another still differs, and [id] selects the one entry with that id. With first, the concrete path (keys and
    indexes) of the leaf's first occurrence instead, which a leaf vector sets."""
    tokens = _leaf_tokens(kind, path)
    where = RECORD_PATHS[kind][len(CONTRACT_DIR):]

    def walk(node: Any, at: int, concrete: list) -> Any:
        while at < len(tokens):
            token = tokens[at]
            if token[0] == "key":
                require(type(node) is dict and token[1] in node, "a pinned leaf is present: %s %s" % (where, path))
                node = node[token[1]]
                concrete = concrete + [token[1]] if first else concrete
            else:
                require(type(node) is list, "a pinned leaf is present: %s %s" % (where, path))
                if token[0] == "all":
                    if not first:
                        return [walk(item, at + 1, concrete) for item in node]
                    require(node != [], "a pinned leaf is present: %s %s" % (where, path))
                    found = [0]
                else:
                    found = [i for i, item in enumerate(node) if type(item) is dict and item.get(token[1]) == token[2]]
                    require(len(found) == 1, "an id-keyed list names each entry once: %s %s, by %s"
                            % (where, token[3], token[1]))
                node = node[found[0]]
                concrete = concrete + [found[0]] if first else concrete
            at += 1
        return concrete if first else node

    return walk(doc, 0, [])


def _same(a: Any, b: Any) -> bool:
    """Equal JSON values, type for type (so true is never 1)."""
    if type(a) is not type(b):
        return False
    if type(a) is list:
        return len(a) == len(b) and all(_same(x, y) for x, y in zip(a, b))
    if type(a) is dict:
        return a.keys() == b.keys() and all(_same(a[key], b[key]) for key in a)
    return a == b


def check_pins(docs: dict) -> None:
    """(ii) Every decision-carrying leaf at its published value, each pin under the source it cites. LEAF_EXPLICIT's few
    long texts are left to the explicit sha256 check that fixes each exactly, and LEAF_STRUCTURE_ONLY is shape only."""
    for kind in KINDS:
        where = RECORD_PATHS[kind][len(CONTRACT_DIR):]
        for source, pins in LEAF_PINS[kind].items():
            for path, value in pins:
                require(_same(leaf(kind, docs[kind], path), value),
                        "%s %s is pinned to its published value (%s)" % (where, path, source))


# The generated block: the pins by record and source, the explicit texts and the structure-only leaves. Computed from
# the published records by the build script; never edited by hand.
# BEGIN LEAF PINS
LEAF_PINS: dict = {
    'authority': {
        "DESIGN.r7.md 128 (the record's schema version)": [
            ('schemaVersion', 'planeon.internal.linux-host-authority/v1'),
        ],
        'DESIGN.r7.md 1 (MET-LINUX-008, LINUX-HOST-AUTH-001)': [
            ('packet', 'MET-LINUX-008'),
            ('item', 'LINUX-HOST-AUTH-001'),
        ],
        'DESIGN.r7.md 835 (no GCP project, VM, key or spend exists or is created by this packet: data checks only)': [
            ('evidenceClass', 'DATA_CHECK_ONLY'),
        ],
        "DESIGN.r7.md 157 (every file sha256 is taken at the packet's base commit, a8827617)": [
            ('baseCommit', 'a88276171453760e46b28e8f6f0c0bb4bbfade5d'),
        ],
        'DESIGN.r7.md 157-168 (the one digest rule)': [
            ('digestRule.fileDigest', 'SHA256_OF_THE_CITED_FILE_AT_THE_BASE'),
            ('digestRule.lineNumbers', 'ONE_BASED_INCLUSIVE'),
            ('digestRule.fragmentForm', 'START_LINE_START_BYTE_END_LINE_END_BYTE_UTF8_BYTE_OFFSETS_END_EXCLUSIVE'),
            ('digestRule.textForm', 'FRAGMENTS_DECODED_JOINED_BY_SPACE_ELLIPSIS_SPACE_LINE_FEEDS_KEPT'),
            ('digestRule.spanForm', 'SHA256_OF_EACH_FRAGMENT_FOLLOWED_BY_ONE_ZERO_BYTE'),
            ('digestRule.wholeSentenceDigest', False),
        ],
        'DESIGN.r7.md 153 (the precedence, Q-LHA-5), 287-288': [
            ('precedence',
             'This record supersedes, member by member and bound by span at the base, only the listed predicates. The '
             "superseded texts stay byte-identical as historical text; for runs under MET-LINUX-007's plans this "
             'record governs where they differ (Q-LHA-5 (a)).'),
        ],
        ('DESIGN.r7.md 170-188 (the relaxed predicates, member by member) and 157-168 (their digests); Q-LHA-13 (a); '
         'Q-LHA-1 (a)'): [
            ('supersedes[LR-CAPACITY-ZERO-COST].id', 'LR-CAPACITY-ZERO-COST'),
            ('supersedes[LR-CAPACITY-ZERO-COST].path', 'docs/alpha-2/LINUX_READINESS.md'),
            ('supersedes[LR-CAPACITY-ZERO-COST].fileSha256',
             'ce9c3dfbc7265735b5f41874c82d18b64260f6e3f8f44e623c6b623dbf9bf171'),
            ('supersedes[LR-CAPACITY-ZERO-COST].member', None),
            ('supersedes[LR-CAPACITY-ZERO-COST].lines[*]', [63, 66]),
            ('supersedes[LR-CAPACITY-ZERO-COST].fragments[*][*]', [[63, 0, 63, 59]]),
            ('supersedes[LR-CAPACITY-ZERO-COST].text', 'Use only existing authorized zero-incremental-cost capacity'),
            ('supersedes[LR-CAPACITY-ZERO-COST].span',
             '1cebce04ccbe84683f6fd4d41b70e8ee09cf042b69e85fd971bf294afa71bb22'),
            ('supersedes[LR-CAPACITY-ZERO-COST].note',
             'Relaxed: capacity is the owner-approved per-run GCP capacity of `capacity`.'),
            ('supersedes[LR-CAPACITY-ZERO-COST].kind', 'CAPACITY'),
            ('supersedes[LR-CAPACITY-ZERO-COST].scope', 'ALL'),
            ('supersedes[LR-CAPACITY-ZERO-COST].keptIn', []),
            ('supersedes[LR-NO-CLOUD-INSTANCE].id', 'LR-NO-CLOUD-INSTANCE'),
            ('supersedes[LR-NO-CLOUD-INSTANCE].path', 'docs/alpha-2/LINUX_READINESS.md'),
            ('supersedes[LR-NO-CLOUD-INSTANCE].fileSha256',
             'ce9c3dfbc7265735b5f41874c82d18b64260f6e3f8f44e623c6b623dbf9bf171'),
            ('supersedes[LR-NO-CLOUD-INSTANCE].member', None),
            ('supersedes[LR-NO-CLOUD-INSTANCE].lines[*]', [63, 66]),
            ('supersedes[LR-NO-CLOUD-INSTANCE].fragments[*][*]', [[65, 24, 65, 41], [66, 55, 66, 68]]),
            ('supersedes[LR-NO-CLOUD-INSTANCE].text', 'No cloud instance … is authorized'),
            ('supersedes[LR-NO-CLOUD-INSTANCE].span',
             'e9c1317d8562c9fc12dac151bf8c23f567c81f5001c74d0f9e9dfa0e946df64f'),
            ('supersedes[LR-NO-CLOUD-INSTANCE].note',
             "Relaxed: the cloud-instance fragments only; the sentence's other predicates are kept."),
            ('supersedes[LR-NO-CLOUD-INSTANCE].kind', 'CAPACITY'),
            ('supersedes[LR-NO-CLOUD-INSTANCE].scope', 'ALL'),
            ('supersedes[LR-NO-CLOUD-INSTANCE].keptIn[*]',
             ['LR-KEPT-HOSTED-RUNNER',
              'LR-KEPT-NEW-BROKER',
              'LR-KEPT-PAID-KEY',
              'LR-KEPT-REGISTRY-EGRESS',
              'LR-KEPT-AUTOMATIC-PULL']),
            ('supersedes[LRJ-BILLING-CAPACITY].id', 'LRJ-BILLING-CAPACITY'),
            ('supersedes[LRJ-BILLING-CAPACITY].path', 'architecture/linux-readiness.json'),
            ('supersedes[LRJ-BILLING-CAPACITY].fileSha256',
             '2ac76f01df10f3267b23340dd2af7c466647f5bd9f3645d6203c4de93c0a8762'),
            ('supersedes[LRJ-BILLING-CAPACITY].member', 'billing.capacity'),
            ('supersedes[LRJ-BILLING-CAPACITY].lines[*]', [117, 117]),
            ('supersedes[LRJ-BILLING-CAPACITY].fragments[*][*]', [[117, 4, 117, 78]]),
            ('supersedes[LRJ-BILLING-CAPACITY].text',
             '"capacity": "LOCAL_OR_PREEXISTING_TENANT_AUTHORIZED_ZERO_INCREMENTAL_COST"'),
            ('supersedes[LRJ-BILLING-CAPACITY].span',
             '78cf251144949d7521fa01f2d7ec55f74c49de8070f6e81e30887ee7b824edd6'),
            ('supersedes[LRJ-BILLING-CAPACITY].note', 'Relaxed member billing.capacity.'),
            ('supersedes[LRJ-BILLING-CAPACITY].kind', 'CAPACITY'),
            ('supersedes[LRJ-BILLING-CAPACITY].scope', 'ALL'),
            ('supersedes[LRJ-BILLING-CAPACITY].keptIn', []),
            ('supersedes[LRJ-BILLING-NEW-PROVISIONING].id', 'LRJ-BILLING-NEW-PROVISIONING'),
            ('supersedes[LRJ-BILLING-NEW-PROVISIONING].path', 'architecture/linux-readiness.json'),
            ('supersedes[LRJ-BILLING-NEW-PROVISIONING].fileSha256',
             '2ac76f01df10f3267b23340dd2af7c466647f5bd9f3645d6203c4de93c0a8762'),
            ('supersedes[LRJ-BILLING-NEW-PROVISIONING].member', 'billing.newProvisioning'),
            ('supersedes[LRJ-BILLING-NEW-PROVISIONING].lines[*]', [112, 112]),
            ('supersedes[LRJ-BILLING-NEW-PROVISIONING].fragments[*][*]', [[112, 4, 112, 28]]),
            ('supersedes[LRJ-BILLING-NEW-PROVISIONING].text', '"newProvisioning": false'),
            ('supersedes[LRJ-BILLING-NEW-PROVISIONING].span',
             '43e126ed0c900c78e03bc6fbf92572c549119830d372984c9b5ee846efca5ee3'),
            ('supersedes[LRJ-BILLING-NEW-PROVISIONING].note',
             "Relaxed member billing.newProvisioning; the billing object's other members are kept."),
            ('supersedes[LRJ-BILLING-NEW-PROVISIONING].kind', 'CAPACITY'),
            ('supersedes[LRJ-BILLING-NEW-PROVISIONING].scope', 'ALL'),
            ('supersedes[LRJ-BILLING-NEW-PROVISIONING].keptIn[*]',
             ['LRJ-KEPT-HOSTED-RUNNERS', 'LRJ-KEPT-PAID-APIS', 'LRJ-KEPT-THIRD-PARTY-KEYS', 'LRJ-KEPT-RAW-SOCKETS']),
            ('supersedes[REP-ZERO-COST-CAPACITY].id', 'REP-ZERO-COST-CAPACITY'),
            ('supersedes[REP-ZERO-COST-CAPACITY].path', 'docs/alpha-2/LINUX_READINESS_REPAIRS.md'),
            ('supersedes[REP-ZERO-COST-CAPACITY].fileSha256',
             'ae1c9284eba881730bf4959587616e701c4c3d09f5d8209d156a3798e6cb4f24'),
            ('supersedes[REP-ZERO-COST-CAPACITY].member', None),
            ('supersedes[REP-ZERO-COST-CAPACITY].lines[*]', [147, 149]),
            ('supersedes[REP-ZERO-COST-CAPACITY].fragments[*][*]', [[147, 51, 148, 8]]),
            ('supersedes[REP-ZERO-COST-CAPACITY].text', 'existing zero-incremental-cost\ncapacity'),
            ('supersedes[REP-ZERO-COST-CAPACITY].span',
             'fd947b85a9fc5e76d362ffd2db49a78ad51a467ab9340291b96fab218766ae83'),
            ('supersedes[REP-ZERO-COST-CAPACITY].note',
             'Relaxed (Q-LHA-13 (a)): the existing zero-incremental-cost capacity condition.'),
            ('supersedes[REP-ZERO-COST-CAPACITY].kind', 'CAPACITY'),
            ('supersedes[REP-ZERO-COST-CAPACITY].scope', 'ALL'),
            ('supersedes[REP-ZERO-COST-CAPACITY].keptIn[*]', ['REP-KEPT-UNTIL']),
            ('supersedes[REP-CREATE-CAPACITY].id', 'REP-CREATE-CAPACITY'),
            ('supersedes[REP-CREATE-CAPACITY].path', 'docs/alpha-2/LINUX_READINESS_REPAIRS.md'),
            ('supersedes[REP-CREATE-CAPACITY].fileSha256',
             'ae1c9284eba881730bf4959587616e701c4c3d09f5d8209d156a3798e6cb4f24'),
            ('supersedes[REP-CREATE-CAPACITY].member', None),
            ('supersedes[REP-CREATE-CAPACITY].lines[*]', [155, 155]),
            ('supersedes[REP-CREATE-CAPACITY].fragments[*][*]', [[155, 51, 155, 66]]),
            ('supersedes[REP-CREATE-CAPACITY].text', 'create capacity'),
            ('supersedes[REP-CREATE-CAPACITY].span',
             '2bb2c97556fc0c27e35dd6e87ccac298a599ae0f43b3f160bed6c582f7e93ec5'),
            ('supersedes[REP-CREATE-CAPACITY].note',
             "Relaxed (Q-LHA-13 (a)): create capacity, for the plan's per-run capacity under its lease."),
            ('supersedes[REP-CREATE-CAPACITY].kind', 'CAPACITY'),
            ('supersedes[REP-CREATE-CAPACITY].scope', 'ALL'),
            ('supersedes[REP-CREATE-CAPACITY].keptIn[*]', ['REP-KEPT-NEVER']),
            ('supersedes[CI-LIVE-CAMPAIGNS].id', 'CI-LIVE-CAMPAIGNS'),
            ('supersedes[CI-LIVE-CAMPAIGNS].path', 'docs/alpha-2/CI_CAPACITY_EXCEPTION.md'),
            ('supersedes[CI-LIVE-CAMPAIGNS].fileSha256',
             '9a7e6613684d504494ace5380593ce198e679f779d236463e39c58df3ecb28cf'),
            ('supersedes[CI-LIVE-CAMPAIGNS].member', None),
            ('supersedes[CI-LIVE-CAMPAIGNS].lines[*]', [7, 7]),
            ('supersedes[CI-LIVE-CAMPAIGNS].fragments[*][*]', [[7, 251, 7, 265], [7, 305, 7, 314], [7, 332, 7, 353]]),
            ('supersedes[CI-LIVE-CAMPAIGNS].text', 'live campaigns … zero-bill … no-cloud-provisioning'),
            ('supersedes[CI-LIVE-CAMPAIGNS].span', '6b4fb3d39000e8376b1cb99b6c529bc97cdcfe67544f57d3573f614462bdb1a0'),
            ('supersedes[CI-LIVE-CAMPAIGNS].note',
             "Relaxed (Q-LHA-13 (a)) for live campaigns only: the host's per-run compute is a bill."),
            ('supersedes[CI-LIVE-CAMPAIGNS].kind', 'CAPACITY'),
            ('supersedes[CI-LIVE-CAMPAIGNS].scope', 'LIVE_CAMPAIGNS_ONLY'),
            ('supersedes[CI-LIVE-CAMPAIGNS].keptIn[*]', ['CI-KEPT-OTHER-SCOPES', 'CI-KEPT-NO-PAID-API']),
            ('supersedes[LR-INDEPENDENT-SIGNERS].id', 'LR-INDEPENDENT-SIGNERS'),
            ('supersedes[LR-INDEPENDENT-SIGNERS].path', 'docs/alpha-2/LINUX_READINESS.md'),
            ('supersedes[LR-INDEPENDENT-SIGNERS].fileSha256',
             'ce9c3dfbc7265735b5f41874c82d18b64260f6e3f8f44e623c6b623dbf9bf171'),
            ('supersedes[LR-INDEPENDENT-SIGNERS].member', None),
            ('supersedes[LR-INDEPENDENT-SIGNERS].lines[*]', [66, 68]),
            ('supersedes[LR-INDEPENDENT-SIGNERS].fragments[*][*]', [[66, 70, 66, 77], [67, 45, 68, 23]]),
            ('supersedes[LR-INDEPENDENT-SIGNERS].text',
             'Missing … independent signers remains\nNOT_RUN_ENV_UNAVAILABLE'),
            ('supersedes[LR-INDEPENDENT-SIGNERS].span',
             'ef16bfe6fe5f6f33c67893398a1cf0f571e0ece11d06f48e2c36b9daac26806e'),
            ('supersedes[LR-INDEPENDENT-SIGNERS].note',
             "Superseded with the replacement predicate (the owner's Q-LHA-1 (a)); the predicate begins at Missing."),
            ('supersedes[LR-INDEPENDENT-SIGNERS].kind', 'INDEPENDENCE'),
            ('supersedes[LR-INDEPENDENT-SIGNERS].scope', 'ALL'),
            ('supersedes[LR-INDEPENDENT-SIGNERS].keptIn[*]', ['LR-KEPT-MISSING']),
            ('supersedes[LR-EXISTING-INDEPENDENT].id', 'LR-EXISTING-INDEPENDENT'),
            ('supersedes[LR-EXISTING-INDEPENDENT].path', 'docs/alpha-2/LINUX_READINESS.md'),
            ('supersedes[LR-EXISTING-INDEPENDENT].fileSha256',
             'ce9c3dfbc7265735b5f41874c82d18b64260f6e3f8f44e623c6b623dbf9bf171'),
            ('supersedes[LR-EXISTING-INDEPENDENT].member', None),
            ('supersedes[LR-EXISTING-INDEPENDENT].lines[*]', [146, 148]),
            ('supersedes[LR-EXISTING-INDEPENDENT].fragments[*][*]', [[147, 9, 147, 20]]),
            ('supersedes[LR-EXISTING-INDEPENDENT].text', 'independent'),
            ('supersedes[LR-EXISTING-INDEPENDENT].span',
             'aeefa2d754419cbd7f1d8e0c395308d77db62d254bd477242e7b396354e5664a'),
            ('supersedes[LR-EXISTING-INDEPENDENT].note',
             'Superseded with the replacement predicate: the independent of existing independent authorities.'),
            ('supersedes[LR-EXISTING-INDEPENDENT].kind', 'INDEPENDENCE'),
            ('supersedes[LR-EXISTING-INDEPENDENT].scope', 'ALL'),
            ('supersedes[LR-EXISTING-INDEPENDENT].keptIn[*]', ['LR-KEPT-LIVE-ENTRY']),
            ('supersedes[LRJ-INDEPENDENT-SIGNATURES].id', 'LRJ-INDEPENDENT-SIGNATURES'),
            ('supersedes[LRJ-INDEPENDENT-SIGNATURES].path', 'architecture/linux-readiness.json'),
            ('supersedes[LRJ-INDEPENDENT-SIGNATURES].fileSha256',
             '2ac76f01df10f3267b23340dd2af7c466647f5bd9f3645d6203c4de93c0a8762'),
            ('supersedes[LRJ-INDEPENDENT-SIGNATURES].member', 'evidence.requiredBindings[11]'),
            ('supersedes[LRJ-INDEPENDENT-SIGNATURES].lines[*]', [106, 106]),
            ('supersedes[LRJ-INDEPENDENT-SIGNATURES].fragments[*][*]', [[106, 6, 106, 30]]),
            ('supersedes[LRJ-INDEPENDENT-SIGNATURES].text', '"INDEPENDENT_SIGNATURES"'),
            ('supersedes[LRJ-INDEPENDENT-SIGNATURES].span',
             'f506fb8c3445271a77c0303d1f9c558251d5404af9882c584045a89c256bdaf9'),
            ('supersedes[LRJ-INDEPENDENT-SIGNATURES].note',
             'Stays a required binding, read with the replacement predicate.'),
            ('supersedes[LRJ-INDEPENDENT-SIGNATURES].kind', 'INDEPENDENCE'),
            ('supersedes[LRJ-INDEPENDENT-SIGNATURES].scope', 'ALL'),
            ('supersedes[LRJ-INDEPENDENT-SIGNATURES].keptIn', []),
        ],
        'DESIGN.r7.md 181-184 (the replacement predicate); Q-LHA-1 (a)': [
            ('replacementPredicate.binding', 'INDEPENDENT_SIGNATURES'),
            ('replacementPredicate.required', True),
            ('replacementPredicate.authorities[*]', ['PLATFORM_RELEASE', 'TENANT_LIVE_EXECUTION', 'CAPACITY_OPERATOR']),
            ('replacementPredicate.distinctPerAuthority[*]', ['KEY_ID', 'PURPOSE', 'TOKEN', 'SEALED_BACKUP']),
            ('replacementPredicate.principal', 'SINGLE_OWNER'),
            ('replacementPredicate.disclosure.signers', 'SINGLE_PRINCIPAL_SEPARATED_KEYS'),
            ('replacementPredicate.decision', 'Q-LHA-1'),
        ],
        'DESIGN.r7.md 189-193 (satisfied by the replacement predicate) and 157-168': [
            ('satisfied[LR-INDEPENDENT-SIGNATURES-138].id', 'LR-INDEPENDENT-SIGNATURES-138'),
            ('satisfied[LR-INDEPENDENT-SIGNATURES-138].path', 'docs/alpha-2/LINUX_READINESS.md'),
            ('satisfied[LR-INDEPENDENT-SIGNATURES-138].fileSha256',
             'ce9c3dfbc7265735b5f41874c82d18b64260f6e3f8f44e623c6b623dbf9bf171'),
            ('satisfied[LR-INDEPENDENT-SIGNATURES-138].member', None),
            ('satisfied[LR-INDEPENDENT-SIGNATURES-138].lines[*]', [138, 138]),
            ('satisfied[LR-INDEPENDENT-SIGNATURES-138].fragments[*][*]', [[138, 46, 138, 68]]),
            ('satisfied[LR-INDEPENDENT-SIGNATURES-138].text', 'independent signatures'),
            ('satisfied[LR-INDEPENDENT-SIGNATURES-138].span',
             '98679cdee990625b1b8f9098bd356a3a4141eb07ac6f09d421d47c57e712eea2'),
            ('satisfied[LR-INDEPENDENT-SIGNATURES-138].note',
             'Satisfied by the replacement predicate, not relaxed further.'),
            ('satisfied[TL-FRESH-INDEPENDENTLY-SIGNED].id', 'TL-FRESH-INDEPENDENTLY-SIGNED'),
            ('satisfied[TL-FRESH-INDEPENDENTLY-SIGNED].path', 'docs/TRUSTED_LIVE_CAMPAIGN_RUNNER_CONTRACT.md'),
            ('satisfied[TL-FRESH-INDEPENDENTLY-SIGNED].fileSha256',
             '3f1bf16f6ec5d1e265946765fd82a1a1c05773dcd99a15a1c68f43b122937052'),
            ('satisfied[TL-FRESH-INDEPENDENTLY-SIGNED].member', None),
            ('satisfied[TL-FRESH-INDEPENDENTLY-SIGNED].lines[*]', [456, 457]),
            ('satisfied[TL-FRESH-INDEPENDENTLY-SIGNED].fragments[*][*]', [[456, 63, 457, 47]]),
            ('satisfied[TL-FRESH-INDEPENDENTLY-SIGNED].text',
             'a fresh\nindependently signed native AMD64 qualification'),
            ('satisfied[TL-FRESH-INDEPENDENTLY-SIGNED].span',
             'f947d6f219f24e3504f4cf9c553940172a45d23049e19aa1dab03eb3de5ec945'),
            ('satisfied[TL-FRESH-INDEPENDENTLY-SIGNED].note',
             'Satisfied by the replacement predicate, not relaxed further.'),
            ('satisfied[TL-AFTER-INDEPENDENT-SIGNATURES].id', 'TL-AFTER-INDEPENDENT-SIGNATURES'),
            ('satisfied[TL-AFTER-INDEPENDENT-SIGNATURES].path', 'docs/TRUSTED_LIVE_CAMPAIGN_RUNNER_CONTRACT.md'),
            ('satisfied[TL-AFTER-INDEPENDENT-SIGNATURES].fileSha256',
             '3f1bf16f6ec5d1e265946765fd82a1a1c05773dcd99a15a1c68f43b122937052'),
            ('satisfied[TL-AFTER-INDEPENDENT-SIGNATURES].member', None),
            ('satisfied[TL-AFTER-INDEPENDENT-SIGNATURES].lines[*]', [532, 532]),
            ('satisfied[TL-AFTER-INDEPENDENT-SIGNATURES].fragments[*][*]', [[532, 22, 532, 50]]),
            ('satisfied[TL-AFTER-INDEPENDENT-SIGNATURES].text', 'After independent signatures'),
            ('satisfied[TL-AFTER-INDEPENDENT-SIGNATURES].span',
             '53a6bbe8ebfce79b05ff25c0342f9d1f52cb48bb926d4dc6fbc143637ee99189'),
            ('satisfied[TL-AFTER-INDEPENDENT-SIGNATURES].note',
             'Satisfied by the replacement predicate, not relaxed further.'),
            ('satisfied[COR-THREE-INDEPENDENT-ROLES].id', 'COR-THREE-INDEPENDENT-ROLES'),
            ('satisfied[COR-THREE-INDEPENDENT-ROLES].path', 'docs/alpha-2/CREDENTIAL_ORDERING_REPAIR.md'),
            ('satisfied[COR-THREE-INDEPENDENT-ROLES].fileSha256',
             'b2ed7fe5be1a8b23ec31483c94f77a79094972acde5b726b33a660d729a3bb2d'),
            ('satisfied[COR-THREE-INDEPENDENT-ROLES].member', None),
            ('satisfied[COR-THREE-INDEPENDENT-ROLES].lines[*]', [37, 37]),
            ('satisfied[COR-THREE-INDEPENDENT-ROLES].fragments[*][*]', [[37, 0, 37, 55]]),
            ('satisfied[COR-THREE-INDEPENDENT-ROLES].text', 'all three independent valid and nonrevoked signer roles'),
            ('satisfied[COR-THREE-INDEPENDENT-ROLES].span',
             'e35323d6428c8aa2ad734af1fd92c86e5fb9f61230b2a19c51f01505c55febb2'),
            ('satisfied[COR-THREE-INDEPENDENT-ROLES].note',
             'Satisfied by the replacement predicate, not relaxed further.'),
        ],
        'DESIGN.r7.md 195-214 (the kept predicates) and 157-168': [
            ('unchanged[LR-KEPT-HOSTED-RUNNER].id', 'LR-KEPT-HOSTED-RUNNER'),
            ('unchanged[LR-KEPT-HOSTED-RUNNER].path', 'docs/alpha-2/LINUX_READINESS.md'),
            ('unchanged[LR-KEPT-HOSTED-RUNNER].fileSha256',
             'ce9c3dfbc7265735b5f41874c82d18b64260f6e3f8f44e623c6b623dbf9bf171'),
            ('unchanged[LR-KEPT-HOSTED-RUNNER].member', None),
            ('unchanged[LR-KEPT-HOSTED-RUNNER].lines[*]', [63, 69]),
            ('unchanged[LR-KEPT-HOSTED-RUNNER].fragments[*][*]',
             [[65, 24, 65, 26], [65, 43, 65, 56], [66, 55, 66, 68]]),
            ('unchanged[LR-KEPT-HOSTED-RUNNER].text', 'No … hosted runner … is authorized'),
            ('unchanged[LR-KEPT-HOSTED-RUNNER].span',
             '0221500d8719640d516388bab21859ecad8ab9dd89ad55d7ef1d0cea92fb405b'),
            ('unchanged[LR-KEPT-HOSTED-RUNNER].note', 'Kept: no hosted runner.'),
            ('unchanged[LR-KEPT-NEW-BROKER].id', 'LR-KEPT-NEW-BROKER'),
            ('unchanged[LR-KEPT-NEW-BROKER].path', 'docs/alpha-2/LINUX_READINESS.md'),
            ('unchanged[LR-KEPT-NEW-BROKER].fileSha256',
             'ce9c3dfbc7265735b5f41874c82d18b64260f6e3f8f44e623c6b623dbf9bf171'),
            ('unchanged[LR-KEPT-NEW-BROKER].member', None),
            ('unchanged[LR-KEPT-NEW-BROKER].lines[*]', [63, 69]),
            ('unchanged[LR-KEPT-NEW-BROKER].fragments[*][*]', [[65, 24, 65, 26], [65, 58, 65, 68], [66, 55, 66, 68]]),
            ('unchanged[LR-KEPT-NEW-BROKER].text', 'No … new broker … is authorized'),
            ('unchanged[LR-KEPT-NEW-BROKER].span', '733efdd538e8942ab9b30a0c0353888a5c7fa71a3d6f5c97bfba97f41d45320d'),
            ('unchanged[LR-KEPT-NEW-BROKER].note',
             'Kept, read with PRE_EXISTING: no broker beyond the one reviewed capacity broker that the operator '
             'installs and verifies before the envelope is signed (Q-LHA-14, the owner).'),
            ('unchanged[LR-KEPT-PAID-KEY].id', 'LR-KEPT-PAID-KEY'),
            ('unchanged[LR-KEPT-PAID-KEY].path', 'docs/alpha-2/LINUX_READINESS.md'),
            ('unchanged[LR-KEPT-PAID-KEY].fileSha256',
             'ce9c3dfbc7265735b5f41874c82d18b64260f6e3f8f44e623c6b623dbf9bf171'),
            ('unchanged[LR-KEPT-PAID-KEY].member', None),
            ('unchanged[LR-KEPT-PAID-KEY].lines[*]', [63, 69]),
            ('unchanged[LR-KEPT-PAID-KEY].fragments[*][*]', [[65, 24, 65, 26], [65, 70, 65, 78], [66, 55, 66, 68]]),
            ('unchanged[LR-KEPT-PAID-KEY].text', 'No … paid key … is authorized'),
            ('unchanged[LR-KEPT-PAID-KEY].span', '940d6504cfe68ad2123ed2029d7a8e476d23bc89225ba816e7417886c19f53a7'),
            ('unchanged[LR-KEPT-PAID-KEY].note', 'Kept: no paid key.'),
            ('unchanged[LR-KEPT-REGISTRY-EGRESS].id', 'LR-KEPT-REGISTRY-EGRESS'),
            ('unchanged[LR-KEPT-REGISTRY-EGRESS].path', 'docs/alpha-2/LINUX_READINESS.md'),
            ('unchanged[LR-KEPT-REGISTRY-EGRESS].fileSha256',
             'ce9c3dfbc7265735b5f41874c82d18b64260f6e3f8f44e623c6b623dbf9bf171'),
            ('unchanged[LR-KEPT-REGISTRY-EGRESS].member', None),
            ('unchanged[LR-KEPT-REGISTRY-EGRESS].lines[*]', [63, 69]),
            ('unchanged[LR-KEPT-REGISTRY-EGRESS].fragments[*][*]',
             [[65, 24, 65, 26], [66, 0, 66, 22], [66, 55, 66, 68]]),
            ('unchanged[LR-KEPT-REGISTRY-EGRESS].text', 'No … registry egress charge … is authorized'),
            ('unchanged[LR-KEPT-REGISTRY-EGRESS].span',
             '9bb571fa2845a3aefd62bb43f3a3c1f38d76181b77884f0eb0de4ef9e56859cb'),
            ('unchanged[LR-KEPT-REGISTRY-EGRESS].note', 'Kept: no registry egress charge.'),
            ('unchanged[LR-KEPT-AUTOMATIC-PULL].id', 'LR-KEPT-AUTOMATIC-PULL'),
            ('unchanged[LR-KEPT-AUTOMATIC-PULL].path', 'docs/alpha-2/LINUX_READINESS.md'),
            ('unchanged[LR-KEPT-AUTOMATIC-PULL].fileSha256',
             'ce9c3dfbc7265735b5f41874c82d18b64260f6e3f8f44e623c6b623dbf9bf171'),
            ('unchanged[LR-KEPT-AUTOMATIC-PULL].member', None),
            ('unchanged[LR-KEPT-AUTOMATIC-PULL].lines[*]', [63, 69]),
            ('unchanged[LR-KEPT-AUTOMATIC-PULL].fragments[*][*]', [[65, 24, 65, 26], [66, 26, 66, 68]]),
            ('unchanged[LR-KEPT-AUTOMATIC-PULL].text', 'No … automatic package/image pull is authorized'),
            ('unchanged[LR-KEPT-AUTOMATIC-PULL].span',
             '824cdb999d1cba99c2035394c91b455371a7e3eaf5b58d0cf05898563e4931b3'),
            ('unchanged[LR-KEPT-AUTOMATIC-PULL].note',
             'Kept: no automatic package or image pull at any time; only operator-initiated, digest-pinned fetches '
             'inside the setup window.'),
            ('unchanged[LR-KEPT-MISSING].id', 'LR-KEPT-MISSING'),
            ('unchanged[LR-KEPT-MISSING].path', 'docs/alpha-2/LINUX_READINESS.md'),
            ('unchanged[LR-KEPT-MISSING].fileSha256',
             'ce9c3dfbc7265735b5f41874c82d18b64260f6e3f8f44e623c6b623dbf9bf171'),
            ('unchanged[LR-KEPT-MISSING].member', None),
            ('unchanged[LR-KEPT-MISSING].lines[*]', [66, 68]),
            ('unchanged[LR-KEPT-MISSING].fragments[*][*]', [[66, 70, 67, 41], [67, 65, 68, 23]]),
            ('unchanged[LR-KEPT-MISSING].text',
             'Missing\nhardware, preloaded tooling, OS isolation … remains\nNOT_RUN_ENV_UNAVAILABLE'),
            ('unchanged[LR-KEPT-MISSING].span', '7e6782e177aae0c672f3c150728e14ad5197777a97a816e9a1fd329310e4d9bd'),
            ('unchanged[LR-KEPT-MISSING].note',
             'Kept: missing hardware, preloaded tooling or OS isolation remains NOT_RUN_ENV_UNAVAILABLE.'),
            ('unchanged[LR-KEPT-NO-ADMIN-PASSWORD].id', 'LR-KEPT-NO-ADMIN-PASSWORD'),
            ('unchanged[LR-KEPT-NO-ADMIN-PASSWORD].path', 'docs/alpha-2/LINUX_READINESS.md'),
            ('unchanged[LR-KEPT-NO-ADMIN-PASSWORD].fileSha256',
             'ce9c3dfbc7265735b5f41874c82d18b64260f6e3f8f44e623c6b623dbf9bf171'),
            ('unchanged[LR-KEPT-NO-ADMIN-PASSWORD].member', None),
            ('unchanged[LR-KEPT-NO-ADMIN-PASSWORD].lines[*]', [101, 102]),
            ('unchanged[LR-KEPT-NO-ADMIN-PASSWORD].fragments[*][*]', [[101, 41, 102, 76]]),
            ('unchanged[LR-KEPT-NO-ADMIN-PASSWORD].text',
             'No stored administrator password,\n'
             'interactive prompt automation or broad passwordless sudo grant is introduced'),
            ('unchanged[LR-KEPT-NO-ADMIN-PASSWORD].span',
             '2d729ddee88073070fab80fb27d2d1ffd5ec4bcde9ffe620af9cd5535340a271'),
            ('unchanged[LR-KEPT-NO-ADMIN-PASSWORD].note',
             'Kept, read with Q-LHA-12: no administrator login is bound at preflight or after.'),
            ('unchanged[LR-KEPT-LIVE-ENTRY].id', 'LR-KEPT-LIVE-ENTRY'),
            ('unchanged[LR-KEPT-LIVE-ENTRY].path', 'docs/alpha-2/LINUX_READINESS.md'),
            ('unchanged[LR-KEPT-LIVE-ENTRY].fileSha256',
             'ce9c3dfbc7265735b5f41874c82d18b64260f6e3f8f44e623c6b623dbf9bf171'),
            ('unchanged[LR-KEPT-LIVE-ENTRY].member', None),
            ('unchanged[LR-KEPT-LIVE-ENTRY].lines[*]', [146, 148]),
            ('unchanged[LR-KEPT-LIVE-ENTRY].fragments[*][*]', [[146, 0, 147, 8], [147, 21, 148, 29]]),
            ('unchanged[LR-KEPT-LIVE-ENTRY].text',
             'The only live entry point remains the external root-owned launcher with the\n'
             'existing … PLATFORM_RELEASE, TENANT_LIVE_EXECUTION and\n'
             'CAPACITY_OPERATOR authorities'),
            ('unchanged[LR-KEPT-LIVE-ENTRY].span', '9aa000981f196977160e24cf0bcccba1799cb6e8a06d95797dc3a6f8e956d510'),
            ('unchanged[LR-KEPT-LIVE-ENTRY].note',
             'Kept: the only live entry point is the external root-owned launcher, and the three authorities '
             'themselves; existing is read with SIGNING_AUTHORITY.'),
            ('unchanged[LRJ-KEPT-HOSTED-RUNNERS].id', 'LRJ-KEPT-HOSTED-RUNNERS'),
            ('unchanged[LRJ-KEPT-HOSTED-RUNNERS].path', 'architecture/linux-readiness.json'),
            ('unchanged[LRJ-KEPT-HOSTED-RUNNERS].fileSha256',
             '2ac76f01df10f3267b23340dd2af7c466647f5bd9f3645d6203c4de93c0a8762'),
            ('unchanged[LRJ-KEPT-HOSTED-RUNNERS].member', 'billing.hostedRunners'),
            ('unchanged[LRJ-KEPT-HOSTED-RUNNERS].lines[*]', [113, 113]),
            ('unchanged[LRJ-KEPT-HOSTED-RUNNERS].fragments[*][*]', [[113, 4, 113, 26]]),
            ('unchanged[LRJ-KEPT-HOSTED-RUNNERS].text', '"hostedRunners": false'),
            ('unchanged[LRJ-KEPT-HOSTED-RUNNERS].span',
             '711c3a0fa39fe9b3b21d55ff92b76dc64a3fe12dca20b3bdb9d58aedbcfcbaa1'),
            ('unchanged[LRJ-KEPT-HOSTED-RUNNERS].note', 'Kept member: no hosted runner.'),
            ('unchanged[LRJ-KEPT-PAID-APIS].id', 'LRJ-KEPT-PAID-APIS'),
            ('unchanged[LRJ-KEPT-PAID-APIS].path', 'architecture/linux-readiness.json'),
            ('unchanged[LRJ-KEPT-PAID-APIS].fileSha256',
             '2ac76f01df10f3267b23340dd2af7c466647f5bd9f3645d6203c4de93c0a8762'),
            ('unchanged[LRJ-KEPT-PAID-APIS].member', 'billing.paidApis'),
            ('unchanged[LRJ-KEPT-PAID-APIS].lines[*]', [114, 114]),
            ('unchanged[LRJ-KEPT-PAID-APIS].fragments[*][*]', [[114, 4, 114, 21]]),
            ('unchanged[LRJ-KEPT-PAID-APIS].text', '"paidApis": false'),
            ('unchanged[LRJ-KEPT-PAID-APIS].span', '86f2fa6c6fb39e82b5e5b97d8adcf86d2bcfc43c7df203eea95ea2489c108346'),
            ('unchanged[LRJ-KEPT-PAID-APIS].note', 'Kept member: no paid API.'),
            ('unchanged[LRJ-KEPT-THIRD-PARTY-KEYS].id', 'LRJ-KEPT-THIRD-PARTY-KEYS'),
            ('unchanged[LRJ-KEPT-THIRD-PARTY-KEYS].path', 'architecture/linux-readiness.json'),
            ('unchanged[LRJ-KEPT-THIRD-PARTY-KEYS].fileSha256',
             '2ac76f01df10f3267b23340dd2af7c466647f5bd9f3645d6203c4de93c0a8762'),
            ('unchanged[LRJ-KEPT-THIRD-PARTY-KEYS].member', 'billing.thirdPartyKeys'),
            ('unchanged[LRJ-KEPT-THIRD-PARTY-KEYS].lines[*]', [115, 115]),
            ('unchanged[LRJ-KEPT-THIRD-PARTY-KEYS].fragments[*][*]', [[115, 4, 115, 27]]),
            ('unchanged[LRJ-KEPT-THIRD-PARTY-KEYS].text', '"thirdPartyKeys": false'),
            ('unchanged[LRJ-KEPT-THIRD-PARTY-KEYS].span',
             'fef51243d1e67e7bedbd3fbdfb9feb12aee9e8c9ae5c154049bc2bd1a854c7b9'),
            ('unchanged[LRJ-KEPT-THIRD-PARTY-KEYS].note', 'Kept member: third-party keys stay refused.'),
            ('unchanged[LRJ-KEPT-RAW-SOCKETS].id', 'LRJ-KEPT-RAW-SOCKETS'),
            ('unchanged[LRJ-KEPT-RAW-SOCKETS].path', 'architecture/linux-readiness.json'),
            ('unchanged[LRJ-KEPT-RAW-SOCKETS].fileSha256',
             '2ac76f01df10f3267b23340dd2af7c466647f5bd9f3645d6203c4de93c0a8762'),
            ('unchanged[LRJ-KEPT-RAW-SOCKETS].member', 'billing.rawContainerSockets'),
            ('unchanged[LRJ-KEPT-RAW-SOCKETS].lines[*]', [116, 116]),
            ('unchanged[LRJ-KEPT-RAW-SOCKETS].fragments[*][*]', [[116, 4, 116, 32]]),
            ('unchanged[LRJ-KEPT-RAW-SOCKETS].text', '"rawContainerSockets": false'),
            ('unchanged[LRJ-KEPT-RAW-SOCKETS].span',
             'a21a459408c091b6004562ba8d3d69bd98a21ef06260391beb8b5280ec02e232'),
            ('unchanged[LRJ-KEPT-RAW-SOCKETS].note', 'Kept member: raw container sockets stay refused.'),
            ('unchanged[REP-KEPT-UNTIL].id', 'REP-KEPT-UNTIL'),
            ('unchanged[REP-KEPT-UNTIL].path', 'docs/alpha-2/LINUX_READINESS_REPAIRS.md'),
            ('unchanged[REP-KEPT-UNTIL].fileSha256',
             'ae1c9284eba881730bf4959587616e701c4c3d09f5d8209d156a3798e6cb4f24'),
            ('unchanged[REP-KEPT-UNTIL].member', None),
            ('unchanged[REP-KEPT-UNTIL].lines[*]', [147, 149]),
            ('unchanged[REP-KEPT-UNTIL].fragments[*][*]', [[147, 0, 147, 50], [148, 10, 149, 58]]),
            ('unchanged[REP-KEPT-UNTIL].text',
             'Native Linux remains NOT_RUN_ENV_UNAVAILABLE until … pinned native tools/caches, reviewed installation, '
             'actual isolation\n'
             'negatives and signed build/runtime/campaign evidence exist'),
            ('unchanged[REP-KEPT-UNTIL].span', '418a2dc3c9270d9b138912db2d0cfb1fee0a426f554cfb6b3614cb806147e3af'),
            ('unchanged[REP-KEPT-UNTIL].note',
             'Kept: pinned native tools and caches, reviewed installation, actual isolation negatives and signed '
             'build, runtime and campaign evidence.'),
            ('unchanged[REP-KEPT-NEVER].id', 'REP-KEPT-NEVER'),
            ('unchanged[REP-KEPT-NEVER].path', 'docs/alpha-2/LINUX_READINESS_REPAIRS.md'),
            ('unchanged[REP-KEPT-NEVER].fileSha256',
             'ae1c9284eba881730bf4959587616e701c4c3d09f5d8209d156a3798e6cb4f24'),
            ('unchanged[REP-KEPT-NEVER].member', None),
            ('unchanged[REP-KEPT-NEVER].lines[*]', [154, 156]),
            ('unchanged[REP-KEPT-NEVER].fragments[*][*]', [[154, 29, 155, 50], [155, 67, 156, 11]]),
            ('unchanged[REP-KEPT-NEVER].text',
             'Never operationally restore the unsafe live path,\n'
             'erase failed runs, relax packet or source custody, … or reverse\n'
             'tenant data'),
            ('unchanged[REP-KEPT-NEVER].span', '22126786d7816739ff90fb48a9d99420ba4d4b6a7e3aee9db5e50de8ebdd3ddc'),
            ('unchanged[REP-KEPT-NEVER].note', 'Kept; create capacity (line 155) is the relaxed fragment.'),
            ('unchanged[CI-KEPT-OTHER-SCOPES].id', 'CI-KEPT-OTHER-SCOPES'),
            ('unchanged[CI-KEPT-OTHER-SCOPES].path', 'docs/alpha-2/CI_CAPACITY_EXCEPTION.md'),
            ('unchanged[CI-KEPT-OTHER-SCOPES].fileSha256',
             '9a7e6613684d504494ace5380593ce198e679f779d236463e39c58df3ecb28cf'),
            ('unchanged[CI-KEPT-OTHER-SCOPES].member', None),
            ('unchanged[CI-KEPT-OTHER-SCOPES].lines[*]', [7, 7]),
            ('unchanged[CI-KEPT-OTHER-SCOPES].fragments[*][*]', [[7, 186, 7, 250], [7, 267, 7, 362]]),
            ('unchanged[CI-KEPT-OTHER-SCOPES].text',
             'The platform, tenant workflows, provider integrations, releases, … and production deployments retain '
             'the zero-bill, no-paid-API and no-cloud-provisioning defaults'),
            ('unchanged[CI-KEPT-OTHER-SCOPES].span',
             'be1372f8e169a60ff8aad929c37496f822f44814850a572685b7ab212b3ab4f8'),
            ('unchanged[CI-KEPT-OTHER-SCOPES].note',
             'Kept: the zero-bill, no-paid-API and no-cloud-provisioning defaults for the platform, tenant workflows, '
             'provider integrations, releases and production deployments.'),
            ('unchanged[CI-KEPT-NO-PAID-API].id', 'CI-KEPT-NO-PAID-API'),
            ('unchanged[CI-KEPT-NO-PAID-API].path', 'docs/alpha-2/CI_CAPACITY_EXCEPTION.md'),
            ('unchanged[CI-KEPT-NO-PAID-API].fileSha256',
             '9a7e6613684d504494ace5380593ce198e679f779d236463e39c58df3ecb28cf'),
            ('unchanged[CI-KEPT-NO-PAID-API].member', None),
            ('unchanged[CI-KEPT-NO-PAID-API].lines[*]', [7, 7]),
            ('unchanged[CI-KEPT-NO-PAID-API].fragments[*][*]', [[7, 251, 7, 265], [7, 316, 7, 327]]),
            ('unchanged[CI-KEPT-NO-PAID-API].text', 'live campaigns … no-paid-API'),
            ('unchanged[CI-KEPT-NO-PAID-API].span', '2fe6cf48bf973c3384d55755dc3e5e1a975d9ab102d3cfb5032bc44c15c4a694'),
            ('unchanged[CI-KEPT-NO-PAID-API].note', 'Kept for live campaigns too: no paid API.'),
        ],
        'DESIGN.r7.md 216-228 (kept at campaign, cluster or reader level) and 157-168': [
            ('costScope[TL-NO-NEW-RESOURCE-CAPACITY].id', 'TL-NO-NEW-RESOURCE-CAPACITY'),
            ('costScope[TL-NO-NEW-RESOURCE-CAPACITY].path', 'docs/TRUSTED_LIVE_CAMPAIGN_RUNNER_CONTRACT.md'),
            ('costScope[TL-NO-NEW-RESOURCE-CAPACITY].fileSha256',
             '3f1bf16f6ec5d1e265946765fd82a1a1c05773dcd99a15a1c68f43b122937052'),
            ('costScope[TL-NO-NEW-RESOURCE-CAPACITY].member', None),
            ('costScope[TL-NO-NEW-RESOURCE-CAPACITY].lines[*]', [442, 443]),
            ('costScope[TL-NO-NEW-RESOURCE-CAPACITY].fragments[*][*]', [[443, 14, 443, 76]]),
            ('costScope[TL-NO-NEW-RESOURCE-CAPACITY].text',
             'no raw container socket or new resource capacity is authorized'),
            ('costScope[TL-NO-NEW-RESOURCE-CAPACITY].span',
             '0f38b0120ccd7b0e8195e5bf8a4e0df868221f0b65b098c89acacb8c990159c2'),
            ('costScope[TL-NO-NEW-RESOURCE-CAPACITY].note', 'Kept at campaign level.'),
            ('costScope[TL-NO-NEW-RESOURCE-CAPACITY].level', 'CAMPAIGN'),
            ('costScope[COR-NEVER-CREATE-CAPACITY].id', 'COR-NEVER-CREATE-CAPACITY'),
            ('costScope[COR-NEVER-CREATE-CAPACITY].path', 'docs/alpha-2/CREDENTIAL_ORDERING_REPAIR.md'),
            ('costScope[COR-NEVER-CREATE-CAPACITY].fileSha256',
             'b2ed7fe5be1a8b23ec31483c94f77a79094972acde5b726b33a660d729a3bb2d'),
            ('costScope[COR-NEVER-CREATE-CAPACITY].member', None),
            ('costScope[COR-NEVER-CREATE-CAPACITY].lines[*]', [94, 94]),
            ('costScope[COR-NEVER-CREATE-CAPACITY].fragments[*][*]', [[94, 0, 94, 15]]),
            ('costScope[COR-NEVER-CREATE-CAPACITY].text', 'create capacity'),
            ('costScope[COR-NEVER-CREATE-CAPACITY].span',
             '2bb2c97556fc0c27e35dd6e87ccac298a599ae0f43b3f160bed6c582f7e93ec5'),
            ('costScope[COR-NEVER-CREATE-CAPACITY].note',
             'Kept at server level: the server must never create capacity.'),
            ('costScope[COR-NEVER-CREATE-CAPACITY].level', 'SERVER'),
            ('costScope[NQR-NO-NEW-CGROUP].id', 'NQR-NO-NEW-CGROUP'),
            ('costScope[NQR-NO-NEW-CGROUP].path', 'docs/alpha-2/NATIVE_QUALIFICATION_READINESS.md'),
            ('costScope[NQR-NO-NEW-CGROUP].fileSha256',
             '60bed4c5358527dabfba15bf4e7a7f584872715ef2ca4f9b4350303b656bf595'),
            ('costScope[NQR-NO-NEW-CGROUP].member', None),
            ('costScope[NQR-NO-NEW-CGROUP].lines[*]', [110, 110]),
            ('costScope[NQR-NO-NEW-CGROUP].fragments[*][*]', [[110, 49, 110, 80]]),
            ('costScope[NQR-NO-NEW-CGROUP].text', 'No new cgroup/capacity creation'),
            ('costScope[NQR-NO-NEW-CGROUP].span', '2b770c6e5b17106ac168a3a1b68f6d30a4308f478a78e98d56e7acd447d41324'),
            ('costScope[NQR-NO-NEW-CGROUP].note', 'Kept at reader level.'),
            ('costScope[NQR-NO-NEW-CGROUP].level', 'READER'),
            ('costScope[LR-DO-NOT-DESTROY-CAPACITY].id', 'LR-DO-NOT-DESTROY-CAPACITY'),
            ('costScope[LR-DO-NOT-DESTROY-CAPACITY].path', 'docs/alpha-2/LINUX_READINESS.md'),
            ('costScope[LR-DO-NOT-DESTROY-CAPACITY].fileSha256',
             'ce9c3dfbc7265735b5f41874c82d18b64260f6e3f8f44e623c6b623dbf9bf171'),
            ('costScope[LR-DO-NOT-DESTROY-CAPACITY].member', None),
            ('costScope[LR-DO-NOT-DESTROY-CAPACITY].lines[*]', [163, 163]),
            ('costScope[LR-DO-NOT-DESTROY-CAPACITY].fragments[*][*]', [[163, 0, 163, 6], [163, 58, 163, 74]]),
            ('costScope[LR-DO-NOT-DESTROY-CAPACITY].text', 'Do not … destroy capacity'),
            ('costScope[LR-DO-NOT-DESTROY-CAPACITY].span',
             '8a56c95e1856418bbb644a560d451b858c643447093a01c85b0ffbb942a7bb8a'),
            ('costScope[LR-DO-NOT-DESTROY-CAPACITY].note',
             "Kept. The plan's teardown releases per-run capacity that the plan itself created, under its lease; that "
             'is not the destruction of existing capacity the line forbids.'),
            ('costScope[LR-DO-NOT-DESTROY-CAPACITY].level', 'EXISTING_CAPACITY'),
            ('costScope[TL-ENDPOINT-COST-DISPOSITION].id', 'TL-ENDPOINT-COST-DISPOSITION'),
            ('costScope[TL-ENDPOINT-COST-DISPOSITION].path', 'docs/TRUSTED_LIVE_CAMPAIGN_RUNNER_CONTRACT.md'),
            ('costScope[TL-ENDPOINT-COST-DISPOSITION].fileSha256',
             '3f1bf16f6ec5d1e265946765fd82a1a1c05773dcd99a15a1c68f43b122937052'),
            ('costScope[TL-ENDPOINT-COST-DISPOSITION].member', None),
            ('costScope[TL-ENDPOINT-COST-DISPOSITION].lines[*]', [241, 244]),
            ('costScope[TL-ENDPOINT-COST-DISPOSITION].fragments[*][*]', [[242, 65, 244, 41]]),
            ('costScope[TL-ENDPOINT-COST-DISPOSITION].text',
             'cost disposition\n`SELF_HOSTED_OPEN_SOURCE_NON_METERED` or\n`TENANT_SUPPLIED_OPEN_SOURCE_NON_METERED`'),
            ('costScope[TL-ENDPOINT-COST-DISPOSITION].span',
             'b59c3756e52ebff03f06bbb7f5404cb7d7a7ca60bd11819d44be51fad135602b'),
            ('costScope[TL-ENDPOINT-COST-DISPOSITION].note',
             'Unchanged endpoint cost disposition; see the carried note LHA-CN-1.'),
            ('costScope[TL-ENDPOINT-COST-DISPOSITION].level', 'ENDPOINT'),
            ('costScope[TL-MUTATION-PROFILE].id', 'TL-MUTATION-PROFILE'),
            ('costScope[TL-MUTATION-PROFILE].path', 'docs/TRUSTED_LIVE_CAMPAIGN_RUNNER_CONTRACT.md'),
            ('costScope[TL-MUTATION-PROFILE].fileSha256',
             '3f1bf16f6ec5d1e265946765fd82a1a1c05773dcd99a15a1c68f43b122937052'),
            ('costScope[TL-MUTATION-PROFILE].member', None),
            ('costScope[TL-MUTATION-PROFILE].lines[*]', [339, 339]),
            ('costScope[TL-MUTATION-PROFILE].fragments[*][*]', [[339, 0, 339, 66]]),
            ('costScope[TL-MUTATION-PROFILE].text',
             '`mutationProfile` is exactly `ZERO_INCREMENTAL_COST_KUBERNETES_V1`'),
            ('costScope[TL-MUTATION-PROFILE].span', '9843ae5bc0a201ecbc4e9c4d0e62a0bd11fff2b153b3e25ebd9919ccca370297'),
            ('costScope[TL-MUTATION-PROFILE].note',
             'Unchanged Kubernetes mutation profile; see the carried note LHA-CN-1.'),
            ('costScope[TL-MUTATION-PROFILE].level', 'CLUSTER'),
        ],
        'DESIGN.r7.md 230-237 (reviewed, not binding, with the reason) and 157-168; Q-LHA-13 (a)': [
            ('reviewedNotBinding[NQR-NO-NEW-SERVICE].id', 'NQR-NO-NEW-SERVICE'),
            ('reviewedNotBinding[NQR-NO-NEW-SERVICE].path', 'docs/alpha-2/NATIVE_QUALIFICATION_READINESS.md'),
            ('reviewedNotBinding[NQR-NO-NEW-SERVICE].fileSha256',
             '60bed4c5358527dabfba15bf4e7a7f584872715ef2ca4f9b4350303b656bf595'),
            ('reviewedNotBinding[NQR-NO-NEW-SERVICE].member', None),
            ('reviewedNotBinding[NQR-NO-NEW-SERVICE].lines[*]', [22, 23]),
            ('reviewedNotBinding[NQR-NO-NEW-SERVICE].fragments[*][*]', [[22, 0, 23, 44]]),
            ('reviewedNotBinding[NQR-NO-NEW-SERVICE].text',
             'No new service, network endpoint, local socket, root key, signing role, public\n'
             'campaign field or Kubernetes grant is added.'),
            ('reviewedNotBinding[NQR-NO-NEW-SERVICE].span',
             'a22af603b83e93b60cc05eda1b927d9e330f07183787cdc6fa288ebb92867b7f'),
            ('reviewedNotBinding[NQR-NO-NEW-SERVICE].note',
             "States that packet's own publication scope, not a standing rule."),
            ('reviewedNotBinding[NQR-CLOSING-SENTENCE].id', 'NQR-CLOSING-SENTENCE'),
            ('reviewedNotBinding[NQR-CLOSING-SENTENCE].path', 'docs/alpha-2/NATIVE_QUALIFICATION_READINESS.md'),
            ('reviewedNotBinding[NQR-CLOSING-SENTENCE].fileSha256',
             '60bed4c5358527dabfba15bf4e7a7f584872715ef2ca4f9b4350303b656bf595'),
            ('reviewedNotBinding[NQR-CLOSING-SENTENCE].member', None),
            ('reviewedNotBinding[NQR-CLOSING-SENTENCE].lines[*]', [281, 282]),
            ('reviewedNotBinding[NQR-CLOSING-SENTENCE].fragments[*][*]', [[281, 54, 282, 58]]),
            ('reviewedNotBinding[NQR-CLOSING-SENTENCE].text',
             'No new key, admin prompt,\ndownload, hosted runner, cloud bill or API-key dependency.'),
            ('reviewedNotBinding[NQR-CLOSING-SENTENCE].span',
             '38243b08115f11c346953302d14ce0fa08b7e1595e484ba287cf6cdb84045852'),
            ('reviewedNotBinding[NQR-CLOSING-SENTENCE].note',
             "States that packet's own publication scope, not a standing rule."),
            ('reviewedNotBinding[TL-PUBLICATION-460].id', 'TL-PUBLICATION-460'),
            ('reviewedNotBinding[TL-PUBLICATION-460].path', 'docs/TRUSTED_LIVE_CAMPAIGN_RUNNER_CONTRACT.md'),
            ('reviewedNotBinding[TL-PUBLICATION-460].fileSha256',
             '3f1bf16f6ec5d1e265946765fd82a1a1c05773dcd99a15a1c68f43b122937052'),
            ('reviewedNotBinding[TL-PUBLICATION-460].member', None),
            ('reviewedNotBinding[TL-PUBLICATION-460].lines[*]', [460, 461]),
            ('reviewedNotBinding[TL-PUBLICATION-460].fragments[*][*]', [[460, 34, 461, 32]]),
            ('reviewedNotBinding[TL-PUBLICATION-460].text',
             'it grants no installation, target access,\nprovisioning or paid capability.'),
            ('reviewedNotBinding[TL-PUBLICATION-460].span',
             'dcf40f8dac5184fa29304ab5e96abc89f9c29c30d3083de39a05b8ac05fbb51b'),
            ('reviewedNotBinding[TL-PUBLICATION-460].note',
             "States that packet's own publication scope, not a standing rule."),
            ('reviewedNotBinding[TL-PUBLICATION-484].id', 'TL-PUBLICATION-484'),
            ('reviewedNotBinding[TL-PUBLICATION-484].path', 'docs/TRUSTED_LIVE_CAMPAIGN_RUNNER_CONTRACT.md'),
            ('reviewedNotBinding[TL-PUBLICATION-484].fileSha256',
             '3f1bf16f6ec5d1e265946765fd82a1a1c05773dcd99a15a1c68f43b122937052'),
            ('reviewedNotBinding[TL-PUBLICATION-484].member', None),
            ('reviewedNotBinding[TL-PUBLICATION-484].lines[*]', [484, 485]),
            ('reviewedNotBinding[TL-PUBLICATION-484].fragments[*][*]', [[484, 0, 485, 25]]),
            ('reviewedNotBinding[TL-PUBLICATION-484].text',
             'No installation, key issuance, root-policy change, hosted runner or paid API is\n'
             'part of this publication.'),
            ('reviewedNotBinding[TL-PUBLICATION-484].span',
             'dc1ad5a4f54146c00068fb704d7f6734c0dd4ab0ee36a32ee190780e738e8fa7'),
            ('reviewedNotBinding[TL-PUBLICATION-484].note',
             "States that packet's own publication scope, not a standing rule."),
            ('reviewedNotBinding[TL-PUBLICATION-524].id', 'TL-PUBLICATION-524'),
            ('reviewedNotBinding[TL-PUBLICATION-524].path', 'docs/TRUSTED_LIVE_CAMPAIGN_RUNNER_CONTRACT.md'),
            ('reviewedNotBinding[TL-PUBLICATION-524].fileSha256',
             '3f1bf16f6ec5d1e265946765fd82a1a1c05773dcd99a15a1c68f43b122937052'),
            ('reviewedNotBinding[TL-PUBLICATION-524].member', None),
            ('reviewedNotBinding[TL-PUBLICATION-524].lines[*]', [523, 525]),
            ('reviewedNotBinding[TL-PUBLICATION-524].fragments[*][*]', [[523, 63, 525, 12]]),
            ('reviewedNotBinding[TL-PUBLICATION-524].text',
             'No product/native\n'
             'execution, new installation, key, dependency, cloud action or bill in this meta\n'
             'publication.'),
            ('reviewedNotBinding[TL-PUBLICATION-524].span',
             'cc9ee4e1b01939e88e50929bdef80a71bcfce9e17fe74012b7dbc493232e5383'),
            ('reviewedNotBinding[TL-PUBLICATION-524].note',
             "States that packet's own publication scope, not a standing rule."),
            ('reviewedNotBinding[TL-PUBLICATION-540].id', 'TL-PUBLICATION-540'),
            ('reviewedNotBinding[TL-PUBLICATION-540].path', 'docs/TRUSTED_LIVE_CAMPAIGN_RUNNER_CONTRACT.md'),
            ('reviewedNotBinding[TL-PUBLICATION-540].fileSha256',
             '3f1bf16f6ec5d1e265946765fd82a1a1c05773dcd99a15a1c68f43b122937052'),
            ('reviewedNotBinding[TL-PUBLICATION-540].member', None),
            ('reviewedNotBinding[TL-PUBLICATION-540].lines[*]', [540, 541]),
            ('reviewedNotBinding[TL-PUBLICATION-540].fragments[*][*]', [[540, 50, 541, 77]]),
            ('reviewedNotBinding[TL-PUBLICATION-540].text',
             'no additional product repair\n'
             'packet, signature role, endpoint, installed capability or billing permission.'),
            ('reviewedNotBinding[TL-PUBLICATION-540].span',
             'e394ff7727d5b3daf422f6c171e7fb5ab60104ee1c9bcbd79850d4bc2a98b6f0'),
            ('reviewedNotBinding[TL-PUBLICATION-540].note',
             "States that packet's own publication scope, not a standing rule."),
            ('reviewedNotBinding[TL-PUBLICATION-560].id', 'TL-PUBLICATION-560'),
            ('reviewedNotBinding[TL-PUBLICATION-560].path', 'docs/TRUSTED_LIVE_CAMPAIGN_RUNNER_CONTRACT.md'),
            ('reviewedNotBinding[TL-PUBLICATION-560].fileSha256',
             '3f1bf16f6ec5d1e265946765fd82a1a1c05773dcd99a15a1c68f43b122937052'),
            ('reviewedNotBinding[TL-PUBLICATION-560].member', None),
            ('reviewedNotBinding[TL-PUBLICATION-560].lines[*]', [560, 561]),
            ('reviewedNotBinding[TL-PUBLICATION-560].fragments[*][*]', [[560, 18, 561, 22]]),
            ('reviewedNotBinding[TL-PUBLICATION-560].text',
             'No installation, new broker availability, paid service or live\nacceptance is claimed.'),
            ('reviewedNotBinding[TL-PUBLICATION-560].span',
             'cf4493b647ddfd72f9f3fbe5d3d709d21807af369e88d7d59c94a7af4b08a427'),
            ('reviewedNotBinding[TL-PUBLICATION-560].note',
             "States that packet's own publication scope, not a standing rule."),
        ],
        ('DESIGN.r7.md 250-264 (the readings) and 157-168; MON-LHA-16-1; Q-LHA-14; MON-LHA-ORC-1-A; MON-LHA-ORC-2-A; '
         'B-LHA-11'): [
            ('readings[SIGNING_AUTHORITY].id', 'SIGNING_AUTHORITY'),
            ('readings[SIGNING_AUTHORITY].words[*]', ['existing']),
            ('readings[SIGNING_AUTHORITY].decision', 'MON-LHA-16-1'),
            ('readings[SIGNING_AUTHORITY].reading',
             'Existing signing authority is established by the post-merge key ceremony and recorded in '
             'custody-model.json before any run, never introduced during a run.'),
            ('readings[SIGNING_AUTHORITY].occurrences[LRJ-SIGNING-AUTHORITY].id', 'LRJ-SIGNING-AUTHORITY'),
            ('readings[SIGNING_AUTHORITY].occurrences[LRJ-SIGNING-AUTHORITY].path',
             'architecture/linux-readiness.json'),
            ('readings[SIGNING_AUTHORITY].occurrences[LRJ-SIGNING-AUTHORITY].fileSha256',
             '2ac76f01df10f3267b23340dd2af7c466647f5bd9f3645d6203c4de93c0a8762'),
            ('readings[SIGNING_AUTHORITY].occurrences[LRJ-SIGNING-AUTHORITY].member', 'evidence.signingAuthority'),
            ('readings[SIGNING_AUTHORITY].occurrences[LRJ-SIGNING-AUTHORITY].lines[*]', [108, 108]),
            ('readings[SIGNING_AUTHORITY].occurrences[LRJ-SIGNING-AUTHORITY].fragments[*][*]', [[108, 25, 108, 33]]),
            ('readings[SIGNING_AUTHORITY].occurrences[LRJ-SIGNING-AUTHORITY].text', 'EXISTING'),
            ('readings[SIGNING_AUTHORITY].occurrences[LRJ-SIGNING-AUTHORITY].span',
             'd3f8a1866728a93794b9c8f6e99c99c352fd117b6fbc379df0a942a319e63559'),
            ('readings[SIGNING_AUTHORITY].occurrences[LRJ-SIGNING-AUTHORITY].note',
             'evidence.signingAuthority EXISTING_PLATFORM_RELEASE_TENANT_LIVE_EXECUTION_AND_CAPACITY_OPERATOR.'),
            ('readings[SIGNING_AUTHORITY].occurrences[OP-STEP-4-EXISTING].id', 'OP-STEP-4-EXISTING'),
            ('readings[SIGNING_AUTHORITY].occurrences[OP-STEP-4-EXISTING].path', 'docs/linux-runner/OPERATOR.md'),
            ('readings[SIGNING_AUTHORITY].occurrences[OP-STEP-4-EXISTING].fileSha256',
             '30a59f557ea1a3129fe0d11f86801ed282cffba3f580359b550a8335924fec28'),
            ('readings[SIGNING_AUTHORITY].occurrences[OP-STEP-4-EXISTING].member', None),
            ('readings[SIGNING_AUTHORITY].occurrences[OP-STEP-4-EXISTING].lines[*]', [93, 93]),
            ('readings[SIGNING_AUTHORITY].occurrences[OP-STEP-4-EXISTING].fragments[*][*]', [[93, 7, 93, 15]]),
            ('readings[SIGNING_AUTHORITY].occurrences[OP-STEP-4-EXISTING].text', 'existing'),
            ('readings[SIGNING_AUTHORITY].occurrences[OP-STEP-4-EXISTING].span',
             '11602555873496bfcae331907dcdce1dabd0066aa0b6e99da79dc173262604af'),
            ('readings[SIGNING_AUTHORITY].occurrences[OP-STEP-4-EXISTING].note', 'OPERATOR.md step 4.'),
            ('readings[SIGNING_AUTHORITY].occurrences[OP-STEP-5-EXISTING].id', 'OP-STEP-5-EXISTING'),
            ('readings[SIGNING_AUTHORITY].occurrences[OP-STEP-5-EXISTING].path', 'docs/linux-runner/OPERATOR.md'),
            ('readings[SIGNING_AUTHORITY].occurrences[OP-STEP-5-EXISTING].fileSha256',
             '30a59f557ea1a3129fe0d11f86801ed282cffba3f580359b550a8335924fec28'),
            ('readings[SIGNING_AUTHORITY].occurrences[OP-STEP-5-EXISTING].member', None),
            ('readings[SIGNING_AUTHORITY].occurrences[OP-STEP-5-EXISTING].lines[*]', [99, 99]),
            ('readings[SIGNING_AUTHORITY].occurrences[OP-STEP-5-EXISTING].fragments[*][*]', [[99, 44, 99, 52]]),
            ('readings[SIGNING_AUTHORITY].occurrences[OP-STEP-5-EXISTING].text', 'existing'),
            ('readings[SIGNING_AUTHORITY].occurrences[OP-STEP-5-EXISTING].span',
             '11602555873496bfcae331907dcdce1dabd0066aa0b6e99da79dc173262604af'),
            ('readings[SIGNING_AUTHORITY].occurrences[OP-STEP-5-EXISTING].note', 'OPERATOR.md step 5.'),
            ('readings[SIGNING_AUTHORITY].occurrences[OP-STEP-8-EXISTING-KEY].id', 'OP-STEP-8-EXISTING-KEY'),
            ('readings[SIGNING_AUTHORITY].occurrences[OP-STEP-8-EXISTING-KEY].path', 'docs/linux-runner/OPERATOR.md'),
            ('readings[SIGNING_AUTHORITY].occurrences[OP-STEP-8-EXISTING-KEY].fileSha256',
             '30a59f557ea1a3129fe0d11f86801ed282cffba3f580359b550a8335924fec28'),
            ('readings[SIGNING_AUTHORITY].occurrences[OP-STEP-8-EXISTING-KEY].member', None),
            ('readings[SIGNING_AUTHORITY].occurrences[OP-STEP-8-EXISTING-KEY].lines[*]', [115, 115]),
            ('readings[SIGNING_AUTHORITY].occurrences[OP-STEP-8-EXISTING-KEY].fragments[*][*]', [[115, 64, 115, 72]]),
            ('readings[SIGNING_AUTHORITY].occurrences[OP-STEP-8-EXISTING-KEY].text', 'existing'),
            ('readings[SIGNING_AUTHORITY].occurrences[OP-STEP-8-EXISTING-KEY].span',
             '11602555873496bfcae331907dcdce1dabd0066aa0b6e99da79dc173262604af'),
            ('readings[SIGNING_AUTHORITY].occurrences[OP-STEP-8-EXISTING-KEY].note', 'OPERATOR.md step 8.'),
            ('readings[SIGNING_AUTHORITY].occurrences[OP-STEP-8-EXISTING-PATHS].id', 'OP-STEP-8-EXISTING-PATHS'),
            ('readings[SIGNING_AUTHORITY].occurrences[OP-STEP-8-EXISTING-PATHS].path', 'docs/linux-runner/OPERATOR.md'),
            ('readings[SIGNING_AUTHORITY].occurrences[OP-STEP-8-EXISTING-PATHS].fileSha256',
             '30a59f557ea1a3129fe0d11f86801ed282cffba3f580359b550a8335924fec28'),
            ('readings[SIGNING_AUTHORITY].occurrences[OP-STEP-8-EXISTING-PATHS].member', None),
            ('readings[SIGNING_AUTHORITY].occurrences[OP-STEP-8-EXISTING-PATHS].lines[*]', [116, 116]),
            ('readings[SIGNING_AUTHORITY].occurrences[OP-STEP-8-EXISTING-PATHS].fragments[*][*]', [[116, 51, 116, 59]]),
            ('readings[SIGNING_AUTHORITY].occurrences[OP-STEP-8-EXISTING-PATHS].text', 'existing'),
            ('readings[SIGNING_AUTHORITY].occurrences[OP-STEP-8-EXISTING-PATHS].span',
             '11602555873496bfcae331907dcdce1dabd0066aa0b6e99da79dc173262604af'),
            ('readings[SIGNING_AUTHORITY].occurrences[OP-STEP-8-EXISTING-PATHS].note', 'OPERATOR.md step 8.'),
            ('readings[SIGNING_AUTHORITY].occurrences[LR-147-EXISTING].id', 'LR-147-EXISTING'),
            ('readings[SIGNING_AUTHORITY].occurrences[LR-147-EXISTING].path', 'docs/alpha-2/LINUX_READINESS.md'),
            ('readings[SIGNING_AUTHORITY].occurrences[LR-147-EXISTING].fileSha256',
             'ce9c3dfbc7265735b5f41874c82d18b64260f6e3f8f44e623c6b623dbf9bf171'),
            ('readings[SIGNING_AUTHORITY].occurrences[LR-147-EXISTING].member', None),
            ('readings[SIGNING_AUTHORITY].occurrences[LR-147-EXISTING].lines[*]', [147, 147]),
            ('readings[SIGNING_AUTHORITY].occurrences[LR-147-EXISTING].fragments[*][*]', [[147, 0, 147, 8]]),
            ('readings[SIGNING_AUTHORITY].occurrences[LR-147-EXISTING].text', 'existing'),
            ('readings[SIGNING_AUTHORITY].occurrences[LR-147-EXISTING].span',
             '11602555873496bfcae331907dcdce1dabd0066aa0b6e99da79dc173262604af'),
            ('readings[SIGNING_AUTHORITY].occurrences[LR-147-EXISTING].note',
             'Line 147 cited for the word only (B-LHA-11); the sentence is kept in unchanged.'),
            ('readings[PRE_EXISTING].id', 'PRE_EXISTING'),
            ('readings[PRE_EXISTING].words[*]', ['pre-existing', 'preexisting', 'existing']),
            ('readings[PRE_EXISTING].decision', 'Q-LHA-14'),
            ('readings[PRE_EXISTING].reading',
             'Pre-existing, preexisting and existing operator resources are installed, reviewed and verified by the '
             'operator before the envelope is signed, never by the campaign. For the per-run cluster the operator '
             'makes these resources at step 7, which this reading admits.'),
            ('readings[PRE_EXISTING].occurrences[NQR-28-PRE-EXISTING].id', 'NQR-28-PRE-EXISTING'),
            ('readings[PRE_EXISTING].occurrences[NQR-28-PRE-EXISTING].path',
             'docs/alpha-2/NATIVE_QUALIFICATION_READINESS.md'),
            ('readings[PRE_EXISTING].occurrences[NQR-28-PRE-EXISTING].fileSha256',
             '60bed4c5358527dabfba15bf4e7a7f584872715ef2ca4f9b4350303b656bf595'),
            ('readings[PRE_EXISTING].occurrences[NQR-28-PRE-EXISTING].member', None),
            ('readings[PRE_EXISTING].occurrences[NQR-28-PRE-EXISTING].lines[*]', [28, 29]),
            ('readings[PRE_EXISTING].occurrences[NQR-28-PRE-EXISTING].fragments[*][*]', [[28, 67, 28, 79]]),
            ('readings[PRE_EXISTING].occurrences[NQR-28-PRE-EXISTING].text', 'pre-existing'),
            ('readings[PRE_EXISTING].occurrences[NQR-28-PRE-EXISTING].span',
             'a0a8f55b200bafaba71cb93be2d0b1514c0a1f332359cb658ca8b6bf2ae5683a'),
            ('readings[PRE_EXISTING].occurrences[NQR-28-PRE-EXISTING].note', 'MET-REPAIR-015 lines 28-29.'),
            ('readings[PRE_EXISTING].occurrences[NQR-37-EXISTING].id', 'NQR-37-EXISTING'),
            ('readings[PRE_EXISTING].occurrences[NQR-37-EXISTING].path',
             'docs/alpha-2/NATIVE_QUALIFICATION_READINESS.md'),
            ('readings[PRE_EXISTING].occurrences[NQR-37-EXISTING].fileSha256',
             '60bed4c5358527dabfba15bf4e7a7f584872715ef2ca4f9b4350303b656bf595'),
            ('readings[PRE_EXISTING].occurrences[NQR-37-EXISTING].member', None),
            ('readings[PRE_EXISTING].occurrences[NQR-37-EXISTING].lines[*]', [37, 37]),
            ('readings[PRE_EXISTING].occurrences[NQR-37-EXISTING].fragments[*][*]', [[37, 2, 37, 10]]),
            ('readings[PRE_EXISTING].occurrences[NQR-37-EXISTING].text', 'Existing'),
            ('readings[PRE_EXISTING].occurrences[NQR-37-EXISTING].span',
             '3e7b8566ba4b6227175af11b1af05d70e199b7291d04f4008b3acbce3953a4ea'),
            ('readings[PRE_EXISTING].occurrences[NQR-37-EXISTING].note', 'MET-REPAIR-015 line 37.'),
            ('readings[PRE_EXISTING].occurrences[LRJ-RUNTIME-TRANSPORT].id', 'LRJ-RUNTIME-TRANSPORT'),
            ('readings[PRE_EXISTING].occurrences[LRJ-RUNTIME-TRANSPORT].path', 'architecture/linux-readiness.json'),
            ('readings[PRE_EXISTING].occurrences[LRJ-RUNTIME-TRANSPORT].fileSha256',
             '2ac76f01df10f3267b23340dd2af7c466647f5bd9f3645d6203c4de93c0a8762'),
            ('readings[PRE_EXISTING].occurrences[LRJ-RUNTIME-TRANSPORT].member', 'evidence.runtimeTransport'),
            ('readings[PRE_EXISTING].occurrences[LRJ-RUNTIME-TRANSPORT].lines[*]', [109, 109]),
            ('readings[PRE_EXISTING].occurrences[LRJ-RUNTIME-TRANSPORT].fragments[*][*]', [[109, 32, 109, 43]]),
            ('readings[PRE_EXISTING].occurrences[LRJ-RUNTIME-TRANSPORT].text', 'PREEXISTING'),
            ('readings[PRE_EXISTING].occurrences[LRJ-RUNTIME-TRANSPORT].span',
             'bdb731fe061da254e298f5ea72909bd12d988d0f36b526b2b732b909f1ab4ea3'),
            ('readings[PRE_EXISTING].occurrences[LRJ-RUNTIME-TRANSPORT].note',
             'evidence.runtimeTransport SIGNED_PREEXISTING_PROXY_ONLY.'),
            ('readings[PRE_EXISTING].occurrences[TL-241-LOCAL-PREEXISTING].id', 'TL-241-LOCAL-PREEXISTING'),
            ('readings[PRE_EXISTING].occurrences[TL-241-LOCAL-PREEXISTING].path',
             'docs/TRUSTED_LIVE_CAMPAIGN_RUNNER_CONTRACT.md'),
            ('readings[PRE_EXISTING].occurrences[TL-241-LOCAL-PREEXISTING].fileSha256',
             '3f1bf16f6ec5d1e265946765fd82a1a1c05773dcd99a15a1c68f43b122937052'),
            ('readings[PRE_EXISTING].occurrences[TL-241-LOCAL-PREEXISTING].member', None),
            ('readings[PRE_EXISTING].occurrences[TL-241-LOCAL-PREEXISTING].lines[*]', [240, 241]),
            ('readings[PRE_EXISTING].occurrences[TL-241-LOCAL-PREEXISTING].fragments[*][*]', [[241, 47, 241, 58]]),
            ('readings[PRE_EXISTING].occurrences[TL-241-LOCAL-PREEXISTING].text', 'PREEXISTING'),
            ('readings[PRE_EXISTING].occurrences[TL-241-LOCAL-PREEXISTING].span',
             'bdb731fe061da254e298f5ea72909bd12d988d0f36b526b2b732b909f1ab4ea3'),
            ('readings[PRE_EXISTING].occurrences[TL-241-LOCAL-PREEXISTING].note', 'TRUSTED_LIVE lines 240-241.'),
            ('readings[PRE_EXISTING].occurrences[TL-254-PRE-EXISTING].id', 'TL-254-PRE-EXISTING'),
            ('readings[PRE_EXISTING].occurrences[TL-254-PRE-EXISTING].path',
             'docs/TRUSTED_LIVE_CAMPAIGN_RUNNER_CONTRACT.md'),
            ('readings[PRE_EXISTING].occurrences[TL-254-PRE-EXISTING].fileSha256',
             '3f1bf16f6ec5d1e265946765fd82a1a1c05773dcd99a15a1c68f43b122937052'),
            ('readings[PRE_EXISTING].occurrences[TL-254-PRE-EXISTING].member', None),
            ('readings[PRE_EXISTING].occurrences[TL-254-PRE-EXISTING].lines[*]', [254, 257]),
            ('readings[PRE_EXISTING].occurrences[TL-254-PRE-EXISTING].fragments[*][*]', [[254, 6, 254, 18]]),
            ('readings[PRE_EXISTING].occurrences[TL-254-PRE-EXISTING].text', 'pre-existing'),
            ('readings[PRE_EXISTING].occurrences[TL-254-PRE-EXISTING].span',
             'a0a8f55b200bafaba71cb93be2d0b1514c0a1f332359cb658ca8b6bf2ae5683a'),
            ('readings[PRE_EXISTING].occurrences[TL-254-PRE-EXISTING].note', 'TRUSTED_LIVE lines 254-257.'),
            ('readings[PRE_EXISTING].occurrences[TL-257-PRE-EXISTING].id', 'TL-257-PRE-EXISTING'),
            ('readings[PRE_EXISTING].occurrences[TL-257-PRE-EXISTING].path',
             'docs/TRUSTED_LIVE_CAMPAIGN_RUNNER_CONTRACT.md'),
            ('readings[PRE_EXISTING].occurrences[TL-257-PRE-EXISTING].fileSha256',
             '3f1bf16f6ec5d1e265946765fd82a1a1c05773dcd99a15a1c68f43b122937052'),
            ('readings[PRE_EXISTING].occurrences[TL-257-PRE-EXISTING].member', None),
            ('readings[PRE_EXISTING].occurrences[TL-257-PRE-EXISTING].lines[*]', [254, 257]),
            ('readings[PRE_EXISTING].occurrences[TL-257-PRE-EXISTING].fragments[*][*]', [[257, 6, 257, 18]]),
            ('readings[PRE_EXISTING].occurrences[TL-257-PRE-EXISTING].text', 'pre-existing'),
            ('readings[PRE_EXISTING].occurrences[TL-257-PRE-EXISTING].span',
             'a0a8f55b200bafaba71cb93be2d0b1514c0a1f332359cb658ca8b6bf2ae5683a'),
            ('readings[PRE_EXISTING].occurrences[TL-257-PRE-EXISTING].note', 'TRUSTED_LIVE lines 254-257.'),
            ('readings[PRE_EXISTING].occurrences[TL-260-PRE-EXISTING].id', 'TL-260-PRE-EXISTING'),
            ('readings[PRE_EXISTING].occurrences[TL-260-PRE-EXISTING].path',
             'docs/TRUSTED_LIVE_CAMPAIGN_RUNNER_CONTRACT.md'),
            ('readings[PRE_EXISTING].occurrences[TL-260-PRE-EXISTING].fileSha256',
             '3f1bf16f6ec5d1e265946765fd82a1a1c05773dcd99a15a1c68f43b122937052'),
            ('readings[PRE_EXISTING].occurrences[TL-260-PRE-EXISTING].member', None),
            ('readings[PRE_EXISTING].occurrences[TL-260-PRE-EXISTING].lines[*]', [260, 260]),
            ('readings[PRE_EXISTING].occurrences[TL-260-PRE-EXISTING].fragments[*][*]', [[260, 32, 260, 44]]),
            ('readings[PRE_EXISTING].occurrences[TL-260-PRE-EXISTING].text', 'pre-existing'),
            ('readings[PRE_EXISTING].occurrences[TL-260-PRE-EXISTING].span',
             'a0a8f55b200bafaba71cb93be2d0b1514c0a1f332359cb658ca8b6bf2ae5683a'),
            ('readings[PRE_EXISTING].occurrences[TL-260-PRE-EXISTING].note', 'TRUSTED_LIVE line 260.'),
            ('readings[PRE_EXISTING].occurrences[TL-281-PRE-EXISTING].id', 'TL-281-PRE-EXISTING'),
            ('readings[PRE_EXISTING].occurrences[TL-281-PRE-EXISTING].path',
             'docs/TRUSTED_LIVE_CAMPAIGN_RUNNER_CONTRACT.md'),
            ('readings[PRE_EXISTING].occurrences[TL-281-PRE-EXISTING].fileSha256',
             '3f1bf16f6ec5d1e265946765fd82a1a1c05773dcd99a15a1c68f43b122937052'),
            ('readings[PRE_EXISTING].occurrences[TL-281-PRE-EXISTING].member', None),
            ('readings[PRE_EXISTING].occurrences[TL-281-PRE-EXISTING].lines[*]', [281, 281]),
            ('readings[PRE_EXISTING].occurrences[TL-281-PRE-EXISTING].fragments[*][*]', [[281, 18, 281, 30]]),
            ('readings[PRE_EXISTING].occurrences[TL-281-PRE-EXISTING].text', 'pre-existing'),
            ('readings[PRE_EXISTING].occurrences[TL-281-PRE-EXISTING].span',
             'a0a8f55b200bafaba71cb93be2d0b1514c0a1f332359cb658ca8b6bf2ae5683a'),
            ('readings[PRE_EXISTING].occurrences[TL-281-PRE-EXISTING].note', 'TRUSTED_LIVE line 281.'),
            ('readings[PRE_EXISTING].occurrences[TL-302-PREEXISTING].id', 'TL-302-PREEXISTING'),
            ('readings[PRE_EXISTING].occurrences[TL-302-PREEXISTING].path',
             'docs/TRUSTED_LIVE_CAMPAIGN_RUNNER_CONTRACT.md'),
            ('readings[PRE_EXISTING].occurrences[TL-302-PREEXISTING].fileSha256',
             '3f1bf16f6ec5d1e265946765fd82a1a1c05773dcd99a15a1c68f43b122937052'),
            ('readings[PRE_EXISTING].occurrences[TL-302-PREEXISTING].member', None),
            ('readings[PRE_EXISTING].occurrences[TL-302-PREEXISTING].lines[*]', [302, 302]),
            ('readings[PRE_EXISTING].occurrences[TL-302-PREEXISTING].fragments[*][*]', [[302, 0, 302, 11]]),
            ('readings[PRE_EXISTING].occurrences[TL-302-PREEXISTING].text', 'preexisting'),
            ('readings[PRE_EXISTING].occurrences[TL-302-PREEXISTING].span',
             '3688890505618f49875d3dbff452104b424cbffcfcb2134795419ee45fcc5dbd'),
            ('readings[PRE_EXISTING].occurrences[TL-302-PREEXISTING].note', 'The preexistingResourceRefs member.'),
            ('readings[PRE_EXISTING].occurrences[TL-321-PRE-EXISTING].id', 'TL-321-PRE-EXISTING'),
            ('readings[PRE_EXISTING].occurrences[TL-321-PRE-EXISTING].path',
             'docs/TRUSTED_LIVE_CAMPAIGN_RUNNER_CONTRACT.md'),
            ('readings[PRE_EXISTING].occurrences[TL-321-PRE-EXISTING].fileSha256',
             '3f1bf16f6ec5d1e265946765fd82a1a1c05773dcd99a15a1c68f43b122937052'),
            ('readings[PRE_EXISTING].occurrences[TL-321-PRE-EXISTING].member', None),
            ('readings[PRE_EXISTING].occurrences[TL-321-PRE-EXISTING].lines[*]', [321, 321]),
            ('readings[PRE_EXISTING].occurrences[TL-321-PRE-EXISTING].fragments[*][*]', [[321, 59, 321, 71]]),
            ('readings[PRE_EXISTING].occurrences[TL-321-PRE-EXISTING].text', 'Pre-existing'),
            ('readings[PRE_EXISTING].occurrences[TL-321-PRE-EXISTING].span',
             '3400e528e43074bb6df0691b678c4293e10d7c77c58b2509241c984e66382fba'),
            ('readings[PRE_EXISTING].occurrences[TL-321-PRE-EXISTING].note',
             'Line 321 cited for the word (B-LHA-11); lines 321-322 read Pre-existing, storage, and accelerator '
             'references.'),
            ('readings[PRE_EXISTING].occurrences[TL-442-PRE-EXISTING].id', 'TL-442-PRE-EXISTING'),
            ('readings[PRE_EXISTING].occurrences[TL-442-PRE-EXISTING].path',
             'docs/TRUSTED_LIVE_CAMPAIGN_RUNNER_CONTRACT.md'),
            ('readings[PRE_EXISTING].occurrences[TL-442-PRE-EXISTING].fileSha256',
             '3f1bf16f6ec5d1e265946765fd82a1a1c05773dcd99a15a1c68f43b122937052'),
            ('readings[PRE_EXISTING].occurrences[TL-442-PRE-EXISTING].member', None),
            ('readings[PRE_EXISTING].occurrences[TL-442-PRE-EXISTING].lines[*]', [442, 443]),
            ('readings[PRE_EXISTING].occurrences[TL-442-PRE-EXISTING].fragments[*][*]', [[442, 26, 442, 38]]),
            ('readings[PRE_EXISTING].occurrences[TL-442-PRE-EXISTING].text', 'pre-existing'),
            ('readings[PRE_EXISTING].occurrences[TL-442-PRE-EXISTING].span',
             'a0a8f55b200bafaba71cb93be2d0b1514c0a1f332359cb658ca8b6bf2ae5683a'),
            ('readings[PRE_EXISTING].occurrences[TL-442-PRE-EXISTING].note', 'TRUSTED_LIVE lines 442-443.'),
            ('readings[PRE_EXISTING].occurrences[COR-87-PREEXISTING].id', 'COR-87-PREEXISTING'),
            ('readings[PRE_EXISTING].occurrences[COR-87-PREEXISTING].path',
             'docs/alpha-2/CREDENTIAL_ORDERING_REPAIR.md'),
            ('readings[PRE_EXISTING].occurrences[COR-87-PREEXISTING].fileSha256',
             'b2ed7fe5be1a8b23ec31483c94f77a79094972acde5b726b33a660d729a3bb2d'),
            ('readings[PRE_EXISTING].occurrences[COR-87-PREEXISTING].member', None),
            ('readings[PRE_EXISTING].occurrences[COR-87-PREEXISTING].lines[*]', [87, 87]),
            ('readings[PRE_EXISTING].occurrences[COR-87-PREEXISTING].fragments[*][*]', [[87, 46, 87, 57]]),
            ('readings[PRE_EXISTING].occurrences[COR-87-PREEXISTING].text', 'preexisting'),
            ('readings[PRE_EXISTING].occurrences[COR-87-PREEXISTING].span',
             '3688890505618f49875d3dbff452104b424cbffcfcb2134795419ee45fcc5dbd'),
            ('readings[PRE_EXISTING].occurrences[COR-87-PREEXISTING].note', 'CREDENTIAL_ORDERING_REPAIR.md line 87.'),
            ('readings[PRE_EXISTING].occurrences[LRJ-BILLING-CAPACITY-PREEXISTING].id',
             'LRJ-BILLING-CAPACITY-PREEXISTING'),
            ('readings[PRE_EXISTING].occurrences[LRJ-BILLING-CAPACITY-PREEXISTING].path',
             'architecture/linux-readiness.json'),
            ('readings[PRE_EXISTING].occurrences[LRJ-BILLING-CAPACITY-PREEXISTING].fileSha256',
             '2ac76f01df10f3267b23340dd2af7c466647f5bd9f3645d6203c4de93c0a8762'),
            ('readings[PRE_EXISTING].occurrences[LRJ-BILLING-CAPACITY-PREEXISTING].member', 'billing.capacity'),
            ('readings[PRE_EXISTING].occurrences[LRJ-BILLING-CAPACITY-PREEXISTING].lines[*]', [117, 117]),
            ('readings[PRE_EXISTING].occurrences[LRJ-BILLING-CAPACITY-PREEXISTING].fragments[*][*]',
             [[117, 26, 117, 37]]),
            ('readings[PRE_EXISTING].occurrences[LRJ-BILLING-CAPACITY-PREEXISTING].text', 'PREEXISTING'),
            ('readings[PRE_EXISTING].occurrences[LRJ-BILLING-CAPACITY-PREEXISTING].span',
             'bdb731fe061da254e298f5ea72909bd12d988d0f36b526b2b732b909f1ab4ea3'),
            ('readings[PRE_EXISTING].occurrences[LRJ-BILLING-CAPACITY-PREEXISTING].note',
             'The named form PREEXISTING in the superseded entry LRJ-BILLING-CAPACITY (design section 4; '
             'MON-LHA-ORC-1-A and MON-LHA-ORC-2-A).'),
        ],
        'DESIGN.r7.md 239-244 (capacity, closed); MET-LINUX-007': [
            ('capacity.rule', 'OWNER_APPROVED_GCP_PER_RUN'),
            ('capacity.contract', 'MET-LINUX-007'),
            ('capacity.binding[*]', ['PLAN_SHA256', 'LEASE', 'COST_CEILING', 'TEARDOWN_REPORT']),
            ('capacity.runProject.separateFromLabFoundation', True),
            ('capacity.runProject.defaultNetwork', False),
            ('capacity.hostRecipe', 'architecture/linux-host-authority/host-recipe.json'),
            ('capacity.paidScope', 'HOST_RECIPE_COST_SCOPE'),
            ('capacity.licenceCharge', 'NONE'),
        ],
        'DESIGN.r7.md 76-78 (ownerDecisions LINUX-CAPACITY)': [
            ('capacity.ownerDecision', 'LINUX-CAPACITY'),
        ],
        'DESIGN.r7.md 226-228 (inside the paid scope nothing creates capacity)': [
            ('capacity.insideThePaidScope', 'THE_CAMPAIGN_THE_SERVER_AND_THE_QUALIFICATION_READER_CREATE_NO_CAPACITY'),
        ],
        'DESIGN.r7.md 246-248 (the evidence states do not move)': [
            ('evidence.nativeAmd64', 'NOT_RUN_ENV_UNAVAILABLE'),
            ('evidence.arm64', 'NOT_RUN_ENV_UNAVAILABLE'),
            ('evidence.approvingCapacityIsQualification', False),
        ],
        'DESIGN.r7.md 109 (freshness, 168 hours, G14), 498 (runbook step 14) and 157-168': [
            ('evidence.freshness.id', 'LRJ-MAXIMUM-EVIDENCE-AGE'),
            ('evidence.freshness.path', 'architecture/linux-readiness.json'),
            ('evidence.freshness.fileSha256', '2ac76f01df10f3267b23340dd2af7c466647f5bd9f3645d6203c4de93c0a8762'),
            ('evidence.freshness.member', 'gate.maximumEvidenceAgeHours'),
            ('evidence.freshness.lines[*]', [28, 28]),
            ('evidence.freshness.fragments[*][*]', [[28, 4, 28, 34]]),
            ('evidence.freshness.text', '"maximumEvidenceAgeHours": 168'),
            ('evidence.freshness.span', '650e450743b4a5b605333a331f4bcb06e11a894f3c9bb3645eb1e4665395f639'),
            ('evidence.freshness.note', 'Unchanged: runbook step 14 places the campaign inside the 168-hour window.'),
        ],
        "DESIGN.r7.md 76-78 (MET-LINUX-007 records the owner's decision), 267, and 157-168": [
            ('decisions.metLinux007.id', 'LRP-LINUX-CAPACITY'),
            ('decisions.metLinux007.path', 'architecture/lab-run-plan/status.json'),
            ('decisions.metLinux007.fileSha256', '81c4e9988cb29b93d8abbef7b4bf5d5330cb2e7c1af4429a9b78fe5c6f26e039'),
            ('decisions.metLinux007.member', 'ownerDecisions[2].decision'),
            ('decisions.metLinux007.lines[*]', [146, 146]),
            ('decisions.metLinux007.fragments[*][*]', [[146, 16, 146, 127]]),
            ('decisions.metLinux007.text',
             "Linux capacity for CONF-LINUX-001 and W06 is the owner's GCP compute, and each run plan goes to the "
             'owner first'),
            ('decisions.metLinux007.span', '52b930eccf524385e0259511f51e5fdb0bc0a37db4a970b970badd58d0f0b44c'),
            ('decisions.metLinux007.note', "The owner's decision as MET-LINUX-007 records it, verbatim."),
        ],
        'LX-D1 (owner_decisions.json, carried verbatim); DESIGN.r7.md 266-272': [
            ('decisions.decisionLines[LX-D1].id', 'LX-D1'),
            ('decisions.decisionLines[LX-D1].by', 'OWNER'),
            ('decisions.decisionLines[LX-D1].entry', 'LX-D1'),
            ('decisions.decisionLines[LX-D1].state', 'IN_FORCE'),
            ('decisions.decisionLines[LX-D1].supersededBy', None),
        ],
        'LX-D2 (owner_decisions.json, carried verbatim); DESIGN.r7.md 266-272': [
            ('decisions.decisionLines[LX-D2].id', 'LX-D2'),
            ('decisions.decisionLines[LX-D2].by', 'OWNER'),
            ('decisions.decisionLines[LX-D2].entry', 'LX-D2'),
            ('decisions.decisionLines[LX-D2].state', 'IN_FORCE'),
            ('decisions.decisionLines[LX-D2].supersededBy', None),
        ],
        'Q-LHA-ID (owner_decisions.json, carried verbatim); DESIGN.r7.md 266-272': [
            ('decisions.decisionLines[Q-LHA-ID].id', 'Q-LHA-ID'),
            ('decisions.decisionLines[Q-LHA-ID].by', 'LANE_MONITOR'),
            ('decisions.decisionLines[Q-LHA-ID].entry', 'Q-LHA-ID + Q-LHA-SERIES + GO design'),
            ('decisions.decisionLines[Q-LHA-ID].state', 'IN_FORCE'),
            ('decisions.decisionLines[Q-LHA-ID].supersededBy', None),
        ],
        'Q-LHA-SERIES (owner_decisions.json, carried verbatim); DESIGN.r7.md 266-272': [
            ('decisions.decisionLines[Q-LHA-SERIES].id', 'Q-LHA-SERIES'),
            ('decisions.decisionLines[Q-LHA-SERIES].by', 'LANE_MONITOR'),
            ('decisions.decisionLines[Q-LHA-SERIES].entry', 'Q-LHA-ID + Q-LHA-SERIES + GO design'),
            ('decisions.decisionLines[Q-LHA-SERIES].state', 'IN_FORCE'),
            ('decisions.decisionLines[Q-LHA-SERIES].supersededBy', None),
        ],
        'Q-LHA-1 (owner_decisions.json, carried verbatim); DESIGN.r7.md 266-272': [
            ('decisions.decisionLines[Q-LHA-1].id', 'Q-LHA-1'),
            ('decisions.decisionLines[Q-LHA-1].by', 'OWNER'),
            ('decisions.decisionLines[Q-LHA-1].entry',
             'Q-LHA-1 + Q-LHA-2 (owner) + MON-LHA-3-8-R2 + MON-LHA-9-13 + GO r2'),
            ('decisions.decisionLines[Q-LHA-1].state', 'IN_FORCE'),
            ('decisions.decisionLines[Q-LHA-1].supersededBy', None),
        ],
        'Q-LHA-2 (owner_decisions.json, carried verbatim); DESIGN.r7.md 266-272': [
            ('decisions.decisionLines[Q-LHA-2].id', 'Q-LHA-2'),
            ('decisions.decisionLines[Q-LHA-2].by', 'OWNER'),
            ('decisions.decisionLines[Q-LHA-2].entry',
             'Q-LHA-1 + Q-LHA-2 (owner) + MON-LHA-3-8-R2 + MON-LHA-9-13 + GO r2'),
            ('decisions.decisionLines[Q-LHA-2].state', 'IN_FORCE'),
            ('decisions.decisionLines[Q-LHA-2].supersededBy', None),
        ],
        'Q-LHA-3 (owner_decisions.json, carried verbatim); DESIGN.r7.md 266-272': [
            ('decisions.decisionLines[Q-LHA-3].id', 'Q-LHA-3'),
            ('decisions.decisionLines[Q-LHA-3].by', 'LANE_MONITOR'),
            ('decisions.decisionLines[Q-LHA-3].entry',
             'Q-LHA-1 + Q-LHA-2 (owner) + MON-LHA-3-8-R2 + MON-LHA-9-13 + GO r2'),
            ('decisions.decisionLines[Q-LHA-3].state', 'IN_FORCE'),
            ('decisions.decisionLines[Q-LHA-3].supersededBy', None),
        ],
        'Q-LHA-4 (owner_decisions.json, carried verbatim); DESIGN.r7.md 266-272': [
            ('decisions.decisionLines[Q-LHA-4].id', 'Q-LHA-4'),
            ('decisions.decisionLines[Q-LHA-4].by', 'LANE_MONITOR'),
            ('decisions.decisionLines[Q-LHA-4].entry', 'MON-LHA-3-8'),
            ('decisions.decisionLines[Q-LHA-4].state', 'IN_FORCE'),
            ('decisions.decisionLines[Q-LHA-4].supersededBy', None),
        ],
        'Q-LHA-5 (owner_decisions.json, carried verbatim); DESIGN.r7.md 266-272': [
            ('decisions.decisionLines[Q-LHA-5].id', 'Q-LHA-5'),
            ('decisions.decisionLines[Q-LHA-5].by', 'LANE_MONITOR'),
            ('decisions.decisionLines[Q-LHA-5].entry', 'MON-LHA-3-8'),
            ('decisions.decisionLines[Q-LHA-5].state', 'IN_FORCE'),
            ('decisions.decisionLines[Q-LHA-5].supersededBy', None),
        ],
        'Q-LHA-6 (owner_decisions.json, carried verbatim); DESIGN.r7.md 266-272': [
            ('decisions.decisionLines[Q-LHA-6].id', 'Q-LHA-6'),
            ('decisions.decisionLines[Q-LHA-6].by', 'LANE_MONITOR'),
            ('decisions.decisionLines[Q-LHA-6].entry', 'MON-LHA-3-8'),
            ('decisions.decisionLines[Q-LHA-6].state', 'IN_FORCE'),
            ('decisions.decisionLines[Q-LHA-6].supersededBy', None),
        ],
        'Q-LHA-4-5-6-STAND (owner_decisions.json, carried verbatim); DESIGN.r7.md 266-272': [
            ('decisions.decisionLines[Q-LHA-4-5-6-STAND].id', 'Q-LHA-4-5-6-STAND'),
            ('decisions.decisionLines[Q-LHA-4-5-6-STAND].by', 'LANE_MONITOR'),
            ('decisions.decisionLines[Q-LHA-4-5-6-STAND].entry',
             'Q-LHA-1 + Q-LHA-2 (owner) + MON-LHA-3-8-R2 + MON-LHA-9-13 + GO r2'),
            ('decisions.decisionLines[Q-LHA-4-5-6-STAND].state', 'IN_FORCE'),
            ('decisions.decisionLines[Q-LHA-4-5-6-STAND].supersededBy', None),
        ],
        'Q-LHA-7 (owner_decisions.json, carried verbatim); DESIGN.r7.md 266-272': [
            ('decisions.decisionLines[Q-LHA-7].id', 'Q-LHA-7'),
            ('decisions.decisionLines[Q-LHA-7].by', 'LANE_MONITOR'),
            ('decisions.decisionLines[Q-LHA-7].entry',
             'Q-LHA-1 + Q-LHA-2 (owner) + MON-LHA-3-8-R2 + MON-LHA-9-13 + GO r2'),
            ('decisions.decisionLines[Q-LHA-7].state', 'IN_FORCE'),
            ('decisions.decisionLines[Q-LHA-7].supersededBy', None),
        ],
        'Q-LHA-8 (owner_decisions.json, carried verbatim); DESIGN.r7.md 266-272': [
            ('decisions.decisionLines[Q-LHA-8].id', 'Q-LHA-8'),
            ('decisions.decisionLines[Q-LHA-8].by', 'LANE_MONITOR'),
            ('decisions.decisionLines[Q-LHA-8].entry',
             'Q-LHA-1 + Q-LHA-2 (owner) + MON-LHA-3-8-R2 + MON-LHA-9-13 + GO r2'),
            ('decisions.decisionLines[Q-LHA-8].state', 'IN_FORCE'),
            ('decisions.decisionLines[Q-LHA-8].supersededBy', None),
        ],
        'Q-LHA-9 (owner_decisions.json, carried verbatim); DESIGN.r7.md 266-272': [
            ('decisions.decisionLines[Q-LHA-9].id', 'Q-LHA-9'),
            ('decisions.decisionLines[Q-LHA-9].by', 'LANE_MONITOR'),
            ('decisions.decisionLines[Q-LHA-9].entry',
             'Q-LHA-1 + Q-LHA-2 (owner) + MON-LHA-3-8-R2 + MON-LHA-9-13 + GO r2'),
            ('decisions.decisionLines[Q-LHA-9].state', 'IN_FORCE'),
            ('decisions.decisionLines[Q-LHA-9].supersededBy', None),
        ],
        'Q-LHA-10 (owner_decisions.json, carried verbatim); DESIGN.r7.md 266-272': [
            ('decisions.decisionLines[Q-LHA-10].id', 'Q-LHA-10'),
            ('decisions.decisionLines[Q-LHA-10].by', 'LANE_MONITOR'),
            ('decisions.decisionLines[Q-LHA-10].entry',
             'Q-LHA-1 + Q-LHA-2 (owner) + MON-LHA-3-8-R2 + MON-LHA-9-13 + GO r2'),
            ('decisions.decisionLines[Q-LHA-10].state', 'IN_FORCE'),
            ('decisions.decisionLines[Q-LHA-10].supersededBy', None),
        ],
        'Q-LHA-11 (owner_decisions.json, carried verbatim); DESIGN.r7.md 266-272': [
            ('decisions.decisionLines[Q-LHA-11].id', 'Q-LHA-11'),
            ('decisions.decisionLines[Q-LHA-11].by', 'LANE_MONITOR'),
            ('decisions.decisionLines[Q-LHA-11].entry',
             'Q-LHA-1 + Q-LHA-2 (owner) + MON-LHA-3-8-R2 + MON-LHA-9-13 + GO r2'),
            ('decisions.decisionLines[Q-LHA-11].state', 'IN_FORCE'),
            ('decisions.decisionLines[Q-LHA-11].supersededBy', None),
        ],
        'Q-LHA-12 (owner_decisions.json, carried verbatim); DESIGN.r7.md 266-272': [
            ('decisions.decisionLines[Q-LHA-12].id', 'Q-LHA-12'),
            ('decisions.decisionLines[Q-LHA-12].by', 'LANE_MONITOR'),
            ('decisions.decisionLines[Q-LHA-12].entry',
             'Q-LHA-1 + Q-LHA-2 (owner) + MON-LHA-3-8-R2 + MON-LHA-9-13 + GO r2'),
            ('decisions.decisionLines[Q-LHA-12].state', 'IN_FORCE'),
            ('decisions.decisionLines[Q-LHA-12].supersededBy', None),
        ],
        'Q-LHA-13 (owner_decisions.json, carried verbatim); DESIGN.r7.md 266-272': [
            ('decisions.decisionLines[Q-LHA-13].id', 'Q-LHA-13'),
            ('decisions.decisionLines[Q-LHA-13].by', 'LANE_MONITOR'),
            ('decisions.decisionLines[Q-LHA-13].entry',
             'Q-LHA-1 + Q-LHA-2 (owner) + MON-LHA-3-8-R2 + MON-LHA-9-13 + GO r2'),
            ('decisions.decisionLines[Q-LHA-13].state', 'IN_FORCE'),
            ('decisions.decisionLines[Q-LHA-13].supersededBy', None),
        ],
        'Q-LHA-14 (owner_decisions.json, carried verbatim); DESIGN.r7.md 266-272': [
            ('decisions.decisionLines[Q-LHA-14].id', 'Q-LHA-14'),
            ('decisions.decisionLines[Q-LHA-14].by', 'OWNER'),
            ('decisions.decisionLines[Q-LHA-14].entry',
             'Q-LHA-14 + Q-LHA-15 + Q-LHA-16(2) (owner) + MON-LHA-16-1 + MON-LHA-SPLIT + MON-LHA-12R + MON-LHA-17 + '
             'GO r3'),
            ('decisions.decisionLines[Q-LHA-14].state', 'IN_FORCE'),
            ('decisions.decisionLines[Q-LHA-14].supersededBy', None),
        ],
        'Q-LHA-15 (owner_decisions.json, carried verbatim); DESIGN.r7.md 266-272': [
            ('decisions.decisionLines[Q-LHA-15].id', 'Q-LHA-15'),
            ('decisions.decisionLines[Q-LHA-15].by', 'OWNER'),
            ('decisions.decisionLines[Q-LHA-15].entry',
             'Q-LHA-14 + Q-LHA-15 + Q-LHA-16(2) (owner) + MON-LHA-16-1 + MON-LHA-SPLIT + MON-LHA-12R + MON-LHA-17 + '
             'GO r3'),
            ('decisions.decisionLines[Q-LHA-15].state', 'IN_FORCE'),
            ('decisions.decisionLines[Q-LHA-15].supersededBy', None),
        ],
        'Q-LHA-16-2 (owner_decisions.json, carried verbatim); DESIGN.r7.md 266-272': [
            ('decisions.decisionLines[Q-LHA-16-2].id', 'Q-LHA-16-2'),
            ('decisions.decisionLines[Q-LHA-16-2].by', 'OWNER'),
            ('decisions.decisionLines[Q-LHA-16-2].entry',
             'Q-LHA-14 + Q-LHA-15 + Q-LHA-16(2) (owner) + MON-LHA-16-1 + MON-LHA-SPLIT + MON-LHA-12R + MON-LHA-17 + '
             'GO r3'),
            ('decisions.decisionLines[Q-LHA-16-2].state', 'IN_FORCE'),
            ('decisions.decisionLines[Q-LHA-16-2].supersededBy', None),
        ],
        'MON-LHA-16-1 (owner_decisions.json, carried verbatim); DESIGN.r7.md 266-272': [
            ('decisions.decisionLines[MON-LHA-16-1].id', 'MON-LHA-16-1'),
            ('decisions.decisionLines[MON-LHA-16-1].by', 'LANE_MONITOR'),
            ('decisions.decisionLines[MON-LHA-16-1].entry',
             'Q-LHA-14 + Q-LHA-15 + Q-LHA-16(2) (owner) + MON-LHA-16-1 + MON-LHA-SPLIT + MON-LHA-12R + MON-LHA-17 + '
             'GO r3'),
            ('decisions.decisionLines[MON-LHA-16-1].state', 'IN_FORCE'),
            ('decisions.decisionLines[MON-LHA-16-1].supersededBy', None),
        ],
        'MON-LHA-SPLIT (owner_decisions.json, carried verbatim); DESIGN.r7.md 266-272': [
            ('decisions.decisionLines[MON-LHA-SPLIT].id', 'MON-LHA-SPLIT'),
            ('decisions.decisionLines[MON-LHA-SPLIT].by', 'LANE_MONITOR'),
            ('decisions.decisionLines[MON-LHA-SPLIT].entry',
             'Q-LHA-14 + Q-LHA-15 + Q-LHA-16(2) (owner) + MON-LHA-16-1 + MON-LHA-SPLIT + MON-LHA-12R + MON-LHA-17 + '
             'GO r3'),
            ('decisions.decisionLines[MON-LHA-SPLIT].state', 'IN_FORCE'),
            ('decisions.decisionLines[MON-LHA-SPLIT].supersededBy', None),
        ],
        'MON-LHA-12R (owner_decisions.json, carried verbatim); DESIGN.r7.md 266-272': [
            ('decisions.decisionLines[MON-LHA-12R].id', 'MON-LHA-12R'),
            ('decisions.decisionLines[MON-LHA-12R].by', 'LANE_MONITOR'),
            ('decisions.decisionLines[MON-LHA-12R].entry',
             'Q-LHA-14 + Q-LHA-15 + Q-LHA-16(2) (owner) + MON-LHA-16-1 + MON-LHA-SPLIT + MON-LHA-12R + MON-LHA-17 + '
             'GO r3'),
            ('decisions.decisionLines[MON-LHA-12R].state', 'IN_FORCE'),
            ('decisions.decisionLines[MON-LHA-12R].supersededBy', None),
        ],
        'MON-LHA-17 (owner_decisions.json, carried verbatim); DESIGN.r7.md 266-272': [
            ('decisions.decisionLines[MON-LHA-17].id', 'MON-LHA-17'),
            ('decisions.decisionLines[MON-LHA-17].by', 'LANE_MONITOR'),
            ('decisions.decisionLines[MON-LHA-17].entry',
             'Q-LHA-14 + Q-LHA-15 + Q-LHA-16(2) (owner) + MON-LHA-16-1 + MON-LHA-SPLIT + MON-LHA-12R + MON-LHA-17 + '
             'GO r3'),
            ('decisions.decisionLines[MON-LHA-17].state', 'IN_FORCE'),
            ('decisions.decisionLines[MON-LHA-17].supersededBy', None),
        ],
        'LHA2-11 (owner_decisions.json, carried verbatim); DESIGN.r7.md 266-272': [
            ('decisions.decisionLines[LHA2-11].id', 'LHA2-11'),
            ('decisions.decisionLines[LHA2-11].by', 'LANE_MONITOR'),
            ('decisions.decisionLines[LHA2-11].entry',
             'Q-LHA-14 + Q-LHA-15 + Q-LHA-16(2) (owner) + MON-LHA-16-1 + MON-LHA-SPLIT + MON-LHA-12R + MON-LHA-17 + '
             'GO r3'),
            ('decisions.decisionLines[LHA2-11].state', 'IN_FORCE'),
            ('decisions.decisionLines[LHA2-11].supersededBy', None),
        ],
        'LHA-CAP (owner_decisions.json, carried verbatim); DESIGN.r7.md 266-272': [
            ('decisions.decisionLines[LHA-CAP].id', 'LHA-CAP'),
            ('decisions.decisionLines[LHA-CAP].by', 'OWNER'),
            ('decisions.decisionLines[LHA-CAP].entry',
             'MON-LHA-DR3-KEEP + LHA cap (owner) + LHA3-8 (owner) + MON-LHA3-1-2'),
            ('decisions.decisionLines[LHA-CAP].state', 'IN_FORCE'),
            ('decisions.decisionLines[LHA-CAP].supersededBy', None),
        ],
        'LHA3-8 (owner_decisions.json, carried verbatim); DESIGN.r7.md 266-272': [
            ('decisions.decisionLines[LHA3-8].id', 'LHA3-8'),
            ('decisions.decisionLines[LHA3-8].by', 'OWNER'),
            ('decisions.decisionLines[LHA3-8].entry',
             'MON-LHA-DR3-KEEP + LHA cap (owner) + LHA3-8 (owner) + MON-LHA3-1-2'),
            ('decisions.decisionLines[LHA3-8].state', 'SUPERSEDED'),
            ('decisions.decisionLines[LHA3-8].supersededBy', 'OWNER-CUSTOM-ROLE'),
        ],
        'MON-LHA3-1-2 (owner_decisions.json, carried verbatim); DESIGN.r7.md 266-272': [
            ('decisions.decisionLines[MON-LHA3-1-2].id', 'MON-LHA3-1-2'),
            ('decisions.decisionLines[MON-LHA3-1-2].by', 'LANE_MONITOR'),
            ('decisions.decisionLines[MON-LHA3-1-2].entry',
             'MON-LHA-DR3-KEEP + LHA cap (owner) + LHA3-8 (owner) + MON-LHA3-1-2'),
            ('decisions.decisionLines[MON-LHA3-1-2].state', 'IN_FORCE'),
            ('decisions.decisionLines[MON-LHA3-1-2].supersededBy', None),
        ],
        'MON-LHA-B1 (owner_decisions.json, carried verbatim); DESIGN.r7.md 266-272': [
            ('decisions.decisionLines[MON-LHA-B1].id', 'MON-LHA-B1'),
            ('decisions.decisionLines[MON-LHA-B1].by', 'LANE_MONITOR'),
            ('decisions.decisionLines[MON-LHA-B1].entry',
             'MON-LHA-DR4-KEEP + MON-LHA-B1 + MON-LHA-B2 + B-LHA-3 (owner) + design close'),
            ('decisions.decisionLines[MON-LHA-B1].state', 'IN_FORCE'),
            ('decisions.decisionLines[MON-LHA-B1].supersededBy', None),
        ],
        'MON-LHA-B2 (owner_decisions.json, carried verbatim); DESIGN.r7.md 266-272': [
            ('decisions.decisionLines[MON-LHA-B2].id', 'MON-LHA-B2'),
            ('decisions.decisionLines[MON-LHA-B2].by', 'LANE_MONITOR'),
            ('decisions.decisionLines[MON-LHA-B2].entry',
             'MON-LHA-DR4-KEEP + MON-LHA-B1 + MON-LHA-B2 + B-LHA-3 (owner) + design close'),
            ('decisions.decisionLines[MON-LHA-B2].state', 'IN_FORCE'),
            ('decisions.decisionLines[MON-LHA-B2].supersededBy', None),
        ],
        'B-LHA-3 (owner_decisions.json, carried verbatim); DESIGN.r7.md 266-272': [
            ('decisions.decisionLines[B-LHA-3].id', 'B-LHA-3'),
            ('decisions.decisionLines[B-LHA-3].by', 'OWNER'),
            ('decisions.decisionLines[B-LHA-3].entry',
             'MON-LHA-DR4-KEEP + MON-LHA-B1 + MON-LHA-B2 + B-LHA-3 (owner) + design close'),
            ('decisions.decisionLines[B-LHA-3].state', 'SUPERSEDED'),
            ('decisions.decisionLines[B-LHA-3].supersededBy', 'OWNER-CUSTOM-ROLE'),
        ],
        'B-LHA-4-12 (owner_decisions.json, carried verbatim); DESIGN.r7.md 266-272': [
            ('decisions.decisionLines[B-LHA-4-12].id', 'B-LHA-4-12'),
            ('decisions.decisionLines[B-LHA-4-12].by', 'LANE_MONITOR'),
            ('decisions.decisionLines[B-LHA-4-12].entry',
             'MON-LHA-DR4-KEEP + MON-LHA-B1 + MON-LHA-B2 + B-LHA-3 (owner) + design close'),
            ('decisions.decisionLines[B-LHA-4-12].state', 'IN_FORCE'),
            ('decisions.decisionLines[B-LHA-4-12].supersededBy', None),
        ],
        'OWNER-CUSTOM-ROLE (owner_decisions.json, carried verbatim); DESIGN.r7.md 266-272': [
            ('decisions.decisionLines[OWNER-CUSTOM-ROLE].id', 'OWNER-CUSTOM-ROLE'),
            ('decisions.decisionLines[OWNER-CUSTOM-ROLE].by', 'OWNER'),
            ('decisions.decisionLines[OWNER-CUSTOM-ROLE].entry',
             'MON-DC-EVID-RESULT + owner custom-role decision (replaces LHA3-8, B-LHA-3; MET-LINUX-010 withdrawn) + '
             'MON-LHA-REV6 + Q-SLOT-263'),
            ('decisions.decisionLines[OWNER-CUSTOM-ROLE].state', 'IN_FORCE'),
            ('decisions.decisionLines[OWNER-CUSTOM-ROLE].supersededBy', None),
        ],
        'Q-LHA5-1 (owner_decisions.json, carried verbatim); DESIGN.r7.md 266-272': [
            ('decisions.decisionLines[Q-LHA5-1].id', 'Q-LHA5-1'),
            ('decisions.decisionLines[Q-LHA5-1].by', 'OWNER'),
            ('decisions.decisionLines[Q-LHA5-1].entry', 'MON-LHA-DR5-KEEP + Q-LHA5-1 (owner) + MON-LHA-REV7'),
            ('decisions.decisionLines[Q-LHA5-1].state', 'IN_FORCE'),
            ('decisions.decisionLines[Q-LHA5-1].supersededBy', None),
        ],
        'Q-LHA6-3 (owner_decisions.json, carried verbatim); DESIGN.r7.md 266-272': [
            ('decisions.decisionLines[Q-LHA6-3].id', 'Q-LHA6-3'),
            ('decisions.decisionLines[Q-LHA6-3].by', 'OWNER'),
            ('decisions.decisionLines[Q-LHA6-3].entry',
             'MON-LHA-DR6-KEEP + Q-LHA6-3 (owner) + B-LHA-14..18 under the cap'),
            ('decisions.decisionLines[Q-LHA6-3].state', 'IN_FORCE'),
            ('decisions.decisionLines[Q-LHA6-3].supersededBy', None),
        ],
        'MON-LHA-NO-LOCAL-BRIEF (owner_decisions.json, carried verbatim); DESIGN.r7.md 266-272': [
            ('decisions.decisionLines[MON-LHA-NO-LOCAL-BRIEF].id', 'MON-LHA-NO-LOCAL-BRIEF'),
            ('decisions.decisionLines[MON-LHA-NO-LOCAL-BRIEF].by', 'LANE_MONITOR'),
            ('decisions.decisionLines[MON-LHA-NO-LOCAL-BRIEF].entry', 'MON-LHA-AUTHOR-GO'),
            ('decisions.decisionLines[MON-LHA-NO-LOCAL-BRIEF].state', 'IN_FORCE'),
            ('decisions.decisionLines[MON-LHA-NO-LOCAL-BRIEF].supersededBy', None),
        ],
        'DESIGN.r7.md 274-281 (the consumers); LHA2-11': [
            ('consumers.list[CONF-LINUX-001].id', 'CONF-LINUX-001'),
            ('consumers.list[CONF-LINUX-001].through', 'EXTERNAL_ROOT_OWNED_LIVE_LAUNCHER'),
            ('consumers.list[CONF-LINUX-001].earliestFullRun', 'AFTER_CONF_LIVE_005_006_SOURCE_CLOSURE'),
            ('consumers.list[CONF-LINUX-001].readsThroughThePublishedDigest', True),
            ('consumers.list[CONF-LINUX-001].note', 'R12; LINUX_READINESS.md line 146 and TRUSTED_LIVE line 440.'),
            ('consumers.list[NATIVE_AMD64_QUALIFICATION].id', 'NATIVE_AMD64_QUALIFICATION'),
            ('consumers.list[NATIVE_AMD64_QUALIFICATION].through',
             'CONF_LIVE_006_CAMPAIGN_DECLARATION_AND_ITS_AUTHORITY_AND_EVIDENCE_ADAPTER'),
            ('consumers.list[NATIVE_AMD64_QUALIFICATION].earliestFullRun', 'AFTER_CONF_LIVE_001_TO_006'),
            ('consumers.list[NATIVE_AMD64_QUALIFICATION].readsThroughThePublishedDigest', True),
            ('consumers.list[NATIVE_AMD64_QUALIFICATION].note',
             "MET-LIVE-001's fresh, independently signed native AMD64 qualification."),
            ('consumers.beforeLiveLauncher.mode', 'OFFLINE_LAUNCHER_PREFLIGHT_ONLY'),
            ('consumers.beforeLiveLauncher.evidence', 'HOST_ISOLATION_ONLY'),
        ],
        "DESIGN.r7.md 279-281 (OPERATOR.md's HOST_ISOLATION_ONLY sentence) and 157-168": [
            ('consumers.beforeLiveLauncher.quote.id', 'OP-HOST-ISOLATION-ONLY'),
            ('consumers.beforeLiveLauncher.quote.path', 'docs/linux-runner/OPERATOR.md'),
            ('consumers.beforeLiveLauncher.quote.fileSha256',
             '30a59f557ea1a3129fe0d11f86801ed282cffba3f580359b550a8335924fec28'),
            ('consumers.beforeLiveLauncher.quote.member', None),
            ('consumers.beforeLiveLauncher.quote.lines[*]', [224, 225]),
            ('consumers.beforeLiveLauncher.quote.fragments[*][*]', [[224, 23, 225, 35]]),
            ('consumers.beforeLiveLauncher.quote.text',
             'This is not a product image build, live runtime test or\n  full native release qualification'),
            ('consumers.beforeLiveLauncher.quote.span',
             '73e175d3d715a0d274068b9e07abf8129d0fd4876408c808ce7901f335a4c2e8'),
            ('consumers.beforeLiveLauncher.quote.note',
             'Before CONF-LIVE-005/006 close, a lease yields only this preflight-only evidence.'),
        ],
        'DESIGN.r7.md 826-831 (the preconditions outside this packet); MON-LHA-17; B-LHA-1 (MON-LHA-B1)': [
            ('preconditions[MET-LINUX-009].id', 'MET-LINUX-009'),
            ('preconditions[MET-LINUX-009].what',
             "The root-alias contract, MET-LINUX-005's excluded policy (MON-LHA-17)."),
            ('preconditions[MET-LINUX-009].before', 'THE_FIRST_PLAN_IS_APPROVED'),
            ('preconditions[MET-LINUX-009].state', 'MERGED_AT_BASE'),
            ('preconditions[CONF-LINUX-002].id', 'CONF-LINUX-002'),
            ('preconditions[CONF-LINUX-002].what',
             "R12's signers evidence change for SINGLE_PRINCIPAL_SEPARATED_KEYS (Q-LHA-1)."),
            ('preconditions[CONF-LINUX-002].before', 'THE_FIRST_CONF_LINUX_001_RUN'),
            ('preconditions[CONF-LINUX-002].state', 'OPEN'),
            ('preconditions[CONF-LIVE-006-ADAPTER].id', 'CONF-LIVE-006-ADAPTER'),
            ('preconditions[CONF-LIVE-006-ADAPTER].what', "CONF-LIVE-006's adapter carrying the disclosure."),
            ('preconditions[CONF-LIVE-006-ADAPTER].before', 'THE_LIVE_PATH_QUALIFICATION'),
            ('preconditions[CONF-LIVE-006-ADAPTER].state', 'OPEN'),
            ('preconditions[CONF-LIVE-005-006-NON-ADMIN-ENTRY].id', 'CONF-LIVE-005-006-NON-ADMIN-ENTRY'),
            ('preconditions[CONF-LIVE-005-006-NON-ADMIN-ENTRY].what',
             "The live launcher's entry path for a login without admin (MON-LHA-B1)."),
            ('preconditions[CONF-LIVE-005-006-NON-ADMIN-ENTRY].before', 'ANY_LIVE_RUN'),
            ('preconditions[CONF-LIVE-005-006-NON-ADMIN-ENTRY].state', 'OPEN'),
            ('preconditions[CONF-LIVE-003-006-AND-MET-REPAIR-015-SOURCE-CLOSURE].id',
             'CONF-LIVE-003-006-AND-MET-REPAIR-015-SOURCE-CLOSURE'),
            ('preconditions[CONF-LIVE-003-006-AND-MET-REPAIR-015-SOURCE-CLOSURE].what',
             'CONF-LIVE-003 to CONF-LIVE-006 and MET-REPAIR-015 closed at source.'),
            ('preconditions[CONF-LIVE-003-006-AND-MET-REPAIR-015-SOURCE-CLOSURE].before', 'ANY_LIVE_RUN'),
            ('preconditions[CONF-LIVE-003-006-AND-MET-REPAIR-015-SOURCE-CLOSURE].state', 'OPEN'),
            ('preconditions[KERNEL-INDEPENDENT-QUALIFICATION].id', 'KERNEL-INDEPENDENT-QUALIFICATION'),
            ('preconditions[KERNEL-INDEPENDENT-QUALIFICATION].what',
             "The kernel's independent qualification against MET-REPAIR-015's interface and record."),
            ('preconditions[KERNEL-INDEPENDENT-QUALIFICATION].before', 'QUALIFICATION_ON_THE_PINNED_KERNEL'),
            ('preconditions[KERNEL-INDEPENDENT-QUALIFICATION].state', 'OPEN'),
        ],
        ('MON-LHA-CR1-KEEP (OPEN-1 (ii), MON-LHA-OPEN-1-A); LHA-C1-4; DESIGN.r7.md 102 (G10 defines the local '
         'endpoints)'): [
            ('preconditions[G10-LOCAL-ENDPOINT-IDENTITIES].id', 'G10-LOCAL-ENDPOINT-IDENTITIES'),
            ('preconditions[G10-LOCAL-ENDPOINT-IDENTITIES].what',
             'The campaign release (G10) names the LOCAL_REGISTRY and LOCAL_EVIDENCE_SINK server identities with '
             "their issuer, the issuer certificate's digest, the private half's custody on the proxy/operator host "
             "and the lifetime, and supplies the content of the node's LOCAL_REGISTRY trust file."),
            ('preconditions[G10-LOCAL-ENDPOINT-IDENTITIES].before', 'RUNBOOK_STEP_7'),
            ('preconditions[G10-LOCAL-ENDPOINT-IDENTITIES].state', 'OPEN'),
        ],
        'LHA-CN-1 (design-status.json, carried verbatim as a note); DESIGN.r7.md 223-224, 967-968': [
            ('carriedNotes[LHA-CN-1].id', 'LHA-CN-1'),
            ('carriedNotes[LHA-CN-1].date', '2026-10-24'),
            ('carriedNotes[LHA-CN-1].status', 'CARRIED_NOTE_NOT_SETTLED'),
            ('carriedNotes[LHA-CN-1].appliesTo[*]', ['TL-ENDPOINT-COST-DISPOSITION', 'TL-MUTATION-PROFILE']),
            ('carriedNotes[LHA-CN-1].checkedIn', 'THE_LHA_CONTRACT_ROUND'),
        ],
    },
    'recipe': {
        "DESIGN.r7.md 129 (the record's schema version)": [
            ('schemaVersion', 'planeon.internal.linux-host-recipe/v1'),
        ],
        'DESIGN.r7.md 1 (MET-LINUX-008, LINUX-HOST-AUTH-001)': [
            ('packet', 'MET-LINUX-008'),
            ('item', 'LINUX-HOST-AUTH-001'),
        ],
        'DESIGN.r7.md 835 (no GCP project, VM, key or spend exists or is created by this packet: data checks only)': [
            ('evidenceClass', 'DATA_CHECK_ONLY'),
        ],
        'B-LHA-13; DESIGN.r7.md 432-434; B-LHA-1 (operatorUid by role label); B-LHA-17 (the observer)': [
            ('roleLabels.administeringIdentity', 'OWNER_ADMIN'),
            ('roleLabels.loginIdentity', 'OWNER_LOGIN'),
            ('roleLabels.loginBaselineRole', 'OWNER_LOGIN_BASELINE'),
            ('roleLabels.observer', 'OBSERVER'),
            ('roleLabels.operatorUid', 'OPERATOR_UID'),
            ('roleLabels.loginTriggerGroup', 'PLANEON_LOGIN_TRIGGER'),
        ],
        'DESIGN.r7.md 295-299 (the run project); runbook step 2 (DESIGN.r7.md 486)': [
            ('project.contract', 'LAB-RUNPLAN-001'),
            ('project.separateFromLabFoundation', True),
            ('project.preparedOnce', True),
            ('project.confirmedPerRun', True),
            ('project.runsAtATime', 1),
            ('project.computeBetweenRuns', False),
            ('project.defaultNetwork', False),
            ('project.cloudNat', False),
            ('project.privateGoogleAccess', False),
            ('project.vpcAndFirewallCreatedAtStep', 2),
            ('project.osLoginPolicy', 'ENFORCED'),
        ],
        'DESIGN.r7.md 300-308 (two AMD64 hosts per run); Q-LHA-14': [
            ('hosts[PROXY_OPERATOR_HOST].role', 'PROXY_OPERATOR_HOST'),
            ('hosts[PROXY_OPERATOR_HOST].architecture', 'AMD64'),
            ('hosts[PROXY_OPERATOR_HOST].sizing', 'PER_PLAN'),
            ('hosts[PROXY_OPERATOR_HOST].boots', 'CUSTOM_IMAGE'),
            ('hosts[PROXY_OPERATOR_HOST].carries[*]',
             ['CAMPAIGN_PROXY',
              'POLICY_OBSERVER',
              'CAPACITY_BROKER',
              'LOCAL_REGISTRY',
              'LOCAL_EVIDENCE_SINK',
              'OFFLINE_LAUNCHER',
              'LIVE_LAUNCHER',
              'SIGNED_DROP_INSTALLER',
              'TRIGGER_UNITS',
              'MET_REPAIR_015_PROFILE',
              'LOCKED_PYTHON_3_12_14',
              'NODE',
              'FIREJAIL',
              'GIT']),
            ('hosts[CLUSTER_NODE].role', 'CLUSTER_NODE'),
            ('hosts[CLUSTER_NODE].architecture', 'AMD64'),
            ('hosts[CLUSTER_NODE].sizing', 'PER_PLAN'),
            ('hosts[CLUSTER_NODE].boots', 'PINNED_FAMILY_IMAGE'),
            ('hosts[CLUSTER_NODE].carries[*]',
             ['SINGLE_NODE_CLUSTER',
              'CLUSTER_PRELOAD_IMAGES',
              'FIXTURE_DATABASE',
              'CONTROL_CONTAINER',
              'CLUSTER_DISTRIBUTION_PACKAGES',
              'EXPORT_UNIT']),
        ],
        'DESIGN.r7.md 111-112 (the line at Kubernetes)': [
            ('hosts[PROXY_OPERATOR_HOST].rootKubeconfig', False),
            ('hosts[PROXY_OPERATOR_HOST].containerRuntimeSocket', False),
            ('hosts[CLUSTER_NODE].rootKubeconfig', True),
            ('hosts[CLUSTER_NODE].containerRuntimeSocket', True),
        ],
        'DESIGN.r7.md 112-113 (the proxy/operator host holds only that client credential); B-LHA-2': [
            ('hosts[PROXY_OPERATOR_HOST].holdsKubernetesClientCredential', True),
            ('hosts[CLUSTER_NODE].holdsKubernetesClientCredential', False),
        ],
        'DESIGN.r7.md 428-429; MON-LHA3-1-2': [
            ('hosts[PROXY_OPERATOR_HOST].filesAfterRevocation', 'SIGNED_DROP_INSTALLER_ONLY'),
            ('hosts[CLUSTER_NODE].filesAfterRevocation', 'NONE'),
        ],
        'DESIGN.r7.md 309-318 (F1 and F2 only); MON-LHA3-1-2; B-LHA-6 (F1 carries the proxy upstream)': [
            ('internalFlows[F1].id', 'F1'),
            ('internalFlows[F1].from', 'PROXY_OPERATOR_HOST'),
            ('internalFlows[F1].to', 'CLUSTER_NODE'),
            ('internalFlows[F1].protocol', 'tcp'),
            ('internalFlows[F1].port', 'CLUSTER_API_PORT_THE_KIT_FIXES_PER_PLAN'),
            ('internalFlows[F1].direction', 'PROXY_OPERATOR_HOST_TO_CLUSTER_NODE'),
            ('internalFlows[F1].purposes[*]',
             ['KUBERNETES_API_PROXY', 'POLICY_OBSERVER', 'CAPACITY_BROKER', 'CAMPAIGN_PROXY_UPSTREAM']),
            ('internalFlows[F2].id', 'F2'),
            ('internalFlows[F2].from', 'CLUSTER_NODE'),
            ('internalFlows[F2].to', 'PROXY_OPERATOR_HOST'),
            ('internalFlows[F2].protocol', 'tcp'),
            ('internalFlows[F2].port', 'LOCAL_REGISTRY_PORT_PER_PLAN'),
            ('internalFlows[F2].direction', 'CLUSTER_NODE_TO_PROXY_OPERATOR_HOST'),
            ('internalFlows[F2].purposes[*]', ['NODE_RUNTIME_PULLS_PRELOADED_IMAGES']),
        ],
        'B-LHA-6 (every proxy upstream through the API server on F1)': [
            ('campaignProxyUpstream.flow', 'F1'),
            ('campaignProxyUpstream.targets[*]', ['KUBERNETES_API_SERVER']),
            ('campaignProxyUpstream.via[*]', ['SERVICE_PROXY_SUBRESOURCE', 'PORT_FORWARD_SUBRESOURCE']),
            ('campaignProxyUpstream.asAllowedBy', 'THE_CAPACITY_AUTHORIZATION_RULES'),
            ('campaignProxyUpstream.refusedTargets[*]', ['NODE_PORT', 'SERVICE_ADDRESS', 'POD_ADDRESS']),
            ('campaignProxyUpstream.anyOtherFlow', 'A_NEW_LISTED_FLOW_FOR_THE_MONITOR'),
        ],
        "B-LHA-6 (the node's LOCAL_REGISTRY trust file at step 7 or 8); runbook step 7 (DESIGN.r7.md 491)": [
            ('localRegistryTrust.host', 'CLUSTER_NODE'),
            ('localRegistryTrust.file', '/etc/planeon/node/local-registry-trust.pem'),
            ('localRegistryTrust.owner', 'ROOT'),
            ('localRegistryTrust.mode', '0444'),
            ('localRegistryTrust.installedAtStep', 7),
            ('localRegistryTrust.beforeRevocation', True),
            ('localRegistryTrust.readBy', 'THE_NODE_CONTAINER_RUNTIME'),
            ('localRegistryTrust.trustsTheIssuerOf', 'LOCAL_REGISTRY'),
        ],
        'runbook step 2 (DESIGN.r7.md 486); DESIGN.r7.md 390, 442-443; Q-LHA-11 (a)': [
            ('firewall.ingress[IAP_SSH].id', 'IAP_SSH'),
            ('firewall.ingress[IAP_SSH].sourceRange', '35.235.240.0/20'),
            ('firewall.ingress[IAP_SSH].protocol', 'tcp'),
            ('firewall.ingress[IAP_SSH].port', 22),
            ('firewall.ingress[IAP_SSH].targets', 'BOTH_HOSTS'),
            ('firewall.internal[*]', ['F1', 'F2']),
            ('firewall.egressDenyAll.createdAtStep', 2),
            ('firewall.egressDenyAll.belowSetupWindowAllow', True),
            ('firewall.setupWindowAllow.createdAtStep', 2),
            ('firewall.setupWindowAllow.removedAtStep', 6),
            ('firewall.setupWindowAllow.destinations', 'IP_RANGES_PER_PLAN'),
            ('firewall.setupWindowAllow.byteCeiling', 'FETCH_TOOL_CEILING_PER_PLAN'),
            ('firewall.setupWindowAllow.paidFirewallFeature', False),
        ],
        'DESIGN.r7.md 319-330 (machine, both hosts); Q-LHA-8 (a)': [
            ('machine.appliesTo[*]', ['PROXY_OPERATOR_HOST', 'CLUSTER_NODE']),
            ('machine.shieldedVm.secureBoot', True),
            ('machine.shieldedVm.vtpm', True),
            ('machine.shieldedVm.integrityMonitoring', True),
            ('machine.serialPortAccess', False),
            ('machine.serviceAccount', False),
            ('machine.scopes', []),
            ('machine.metadata[enable-oslogin].key', 'enable-oslogin'),
            ('machine.metadata[enable-oslogin].value', 'TRUE'),
            ('machine.metadata[enable-oslogin-2fa].key', 'enable-oslogin-2fa'),
            ('machine.metadata[enable-oslogin-2fa].value', 'TRUE'),
            ('machine.metadata[block-project-ssh-keys].key', 'block-project-ssh-keys'),
            ('machine.metadata[block-project-ssh-keys].value', 'TRUE'),
            ('machine.refusedMetadata[*]',
             ['ssh-keys', 'startup-script*', 'shutdown-script*', 'enable-guest-attributes']),
            ('machine.maintenance.onHostMaintenance', 'MIGRATE'),
            ('machine.maintenance.automaticRestartInLease', False),
            ('machine.maintenance.bootIdRecordedAtStep', 11),
            ('machine.maintenance.rebootAfterQualification', 'INVALIDATES_QUALIFICATION'),
            ('machine.maxRunDuration.set', True),
            ('machine.maxRunDuration.action', 'DELETE'),
            ('machine.maxRunDuration.endsNoLaterThan', 'LEASE_END'),
            ('machine.maxRunDuration.onPaper', True),
        ],
        'DESIGN.r7.md 324-327 (the guest agent, checked at preflight); Q-LHA-8 (a)': [
            ('guestAgent.on[*]', ['OS_LOGIN_NSS_PAM', 'CLOCK_SYNC']),
            ('guestAgent.off[*]',
             ['METADATA_ACCOUNT_MANAGEMENT',
              'METADATA_SSH_KEY_MANAGEMENT',
              'METADATA_SCRIPT_EXECUTION',
              'NETWORK_INTERFACE_MANAGEMENT',
              'DIAGNOSTICS',
              'SNAPSHOT_HOOKS']),
            ('guestAgent.checkedAtStep', 11),
        ],
        'DESIGN.r7.md 331-347 (the image); Q-LHA-9 (a); Q-LHA-15; B-LHA-8': [
            ('image.allowedFamilies[*]', ['ALMALINUX_10', 'ROCKY_LINUX_10', 'CENTOS_STREAM_10']),
            ('image.familyKind', 'RHEL_10_COMPATIBLE_NO_LICENCE_FEE'),
            ('image.selinux', 'ENFORCING'),
            ('image.onPaper', True),
            ('image.architecture', 'AMD64'),
            ('image.pinnedPerPlan', True),
            ('image.licenceCharge', 'NONE'),
            ('image.clusterNodeBoots', 'PINNED_FAMILY_IMAGE'),
            ('image.customImage.for', 'PROXY_OPERATOR_HOST'),
            ('image.customImage.builtPerPlan', True),
            ('image.customImage.builtOn', 'THE_CLUSTER_NODE_ONTO_THE_TEMPORARY_BUILD_DISK'),
            ('image.customImage.startsFrom', 'PINNED_FAMILY_IMAGE_OWN_FILES'),
            ('image.customImage.verifiedAgainst', 'PINNED_IMAGE_INVENTORY_TAKEN_BEFORE_ANY_INSTALL_ON_THE_NODE'),
            ('image.customImage.plus', 'THE_LISTED_PACKAGES'),
            ('image.customImage.rootFilesystem', 'EXT4_WITH_VERITY'),
            ('image.customImage.usrOnRoot', True),
            ('image.customImage.guestFeatures', 'UEFI_FOR_SHIELDED_SECURE_BOOT'),
            ('image.customImage.selinuxLabels', 'FROM_OWN_POLICY_FILE_CONTEXTS_AT_STEP_4'),
            ('image.customImage.firstBootRelabel', False),
            ('image.customImage.buildDiskDeletedAtStep', 5),
            ('image.customImage.proxyOperatorHostBootsRecordedImage', True),
            ('image.customImage.deletedAtTeardown', True),
            ('image.imageDigest.is', 'SHA256_OF_THE_CUSTOM_IMAGE_INVENTORY'),
            ('image.imageDigest.inventoryFields[*]',
             ['path', 'type', 'mode', 'owner', 'size', 'sha256', 'selinuxLabel']),
            ('image.imageDigest.takenAtStep', 5),
            ('image.imageDigest.from', 'THE_BUILD_DISK_MOUNTED_READ_ONLY'),
            ('image.imageDigest.recomputedOffHost', True),
            ('image.imageDigest.coversLaterSteps', False),
            ('image.kernel.release', 'PINNED_IN_PLAN'),
            ('image.kernel.checkedInBuiltRootAtStep', 5),
            ('image.kernel.qualification', 'PRECONDITION_KERNEL_INDEPENDENT_QUALIFICATION'),
            ('image.kernel.recordedAtStep', 11),
            ('image.kernel.notesDigestRecorded', True),
            ('image.kernel.lockdownKeepsBpfProgramInformation', True),
            ('image.preflightComparesLabels', True),
        ],
        'DESIGN.r7.md 348-369 (the host inventory); LHA3-3; B-LHA-9': [
            ('hostInventory.records[PROXY_OPERATOR_HOST].host', 'PROXY_OPERATOR_HOST'),
            ('hostInventory.records[PROXY_OPERATOR_HOST].scope[*]',
             ['SYSTEM_TREES',
              '/opt/planeon/tools',
              '/opt/planeon/cache',
              '/opt/planeon/python',
              '/opt/planeon/bin',
              '/opt/planeon/work',
              '/etc',
              'BOOT_CHAIN']),
            ('hostInventory.records[CLUSTER_NODE].host', 'CLUSTER_NODE'),
            ('hostInventory.records[CLUSTER_NODE].scope[*]',
             ['SYSTEM_TREES',
              '/opt/planeon/tools',
              '/opt/planeon/cache',
              '/opt/planeon/python',
              '/opt/planeon/bin',
              '/opt/planeon/work',
              '/etc',
              'BOOT_CHAIN']),
            ('hostInventory.leftOut[CLUSTER_STATE].what', 'CLUSTER_STATE'),
            ('hostInventory.leftOut[CLUSTER_STATE].ownRecord', 'RUNTIME_STATE_LISTING'),
            ('hostInventory.leftOut[HOST_NONCE_LEDGER].what', 'HOST_NONCE_LEDGER'),
            ('hostInventory.leftOut[HOST_NONCE_LEDGER].ownRecord', 'EXPORTED_AT_STEP_15'),
            ('hostInventory.leftOut[LOGS].what', 'LOGS'),
            ('hostInventory.leftOut[LOGS].ownRecord', 'EXPORTED_AT_STEP_15'),
            ('hostInventory.leftOut[STEP_10_FILES].what', 'STEP_10_FILES'),
            ('hostInventory.leftOut[STEP_10_FILES].ownRecord', 'DIGEST_AND_SIGNATURE'),
            ('hostInventory.leftOut[SIGNED_DROP_TARGETS].what', 'SIGNED_DROP_TARGETS'),
            ('hostInventory.leftOut[SIGNED_DROP_TARGETS].ownRecord', 'DIGEST_AND_DROP_MANIFEST_SIGNATURE'),
            ('hostInventory.leftOut[PER_RUN_PRIVATE_HALVES].what', 'PER_RUN_PRIVATE_HALVES'),
            ('hostInventory.leftOut[PER_RUN_PRIVATE_HALVES].ownRecord', 'SPKI_DIGEST_ONLY'),
            ('hostInventory.leftOut[PER_RUN_CERTIFICATE_REQUESTS].what', 'PER_RUN_CERTIFICATE_REQUESTS'),
            ('hostInventory.leftOut[PER_RUN_CERTIFICATE_REQUESTS].ownRecord', 'SPKI_DIGEST_ONLY'),
            ('hostInventory.frozenAtStep', 9),
            ('hostInventory.coveredInstallSteps[*]', [4, 7, 8]),
            ('hostInventory.invalidateOn', 'HOST_OR_ISOLATION_CHANGE'),
            ('hostInventory.measuredBoot.readThrough', 'THE_PROVIDER_SHIELDED_VM_INTEGRITY_RECORD'),
            ('hostInventory.measuredBoot.notThroughTheVm', True),
            ('hostInventory.measuredBoot.pcrValues[*]', ['EARLY_BOOT', 'LATE_BOOT']),
            ('hostInventory.measuredBoot.baseline', 'LEARNED_AT_FIRST_BOOT'),
            ('hostInventory.measuredBoot.eventLogReplayed', True),
            ('hostInventory.measuredBoot.efiDigest', 'AUTHENTICODE_AND_FILE_SHA256'),
            ('hostInventory.measuredBoot.onPaper', True),
            ('hostInventory.bootEventLogsExportedAtStep', 9),
            ('hostInventory.imageReverification.where', 'OFF_HOST_IN_T1'),
            ('hostInventory.imageReverification.compares', 'UNCHANGED_HOST_INVENTORY_ENTRIES_WITH_THE_IMAGE_INVENTORY'),
            ('hostInventory.buildInputsReading.cites',
             'docs/linux-runner/BUILD_INPUTS.md lines 95-103 (lines 101 and 103 quoted)'),
            ('hostInventory.buildInputsReading.reading',
             "The owner's off-host verification (the custom image's inventory recomputed outside the VM, plus the "
             "provider-read measured-boot record) is the external operator's independent verification of the image "
             'identity; the remainder beyond the boot chain is operator-attested.'),
            ('hostInventory.buildInputsReading.ifRejected', 'QUALIFICATION_BLOCKED'),
        ],
        'DESIGN.r7.md 370-374 (root aliases); MON-LHA-17': [
            ('rootAliases.contract', 'MET-LINUX-009'),
            ('rootAliases.ruling', 'MON-LHA-17'),
            ('rootAliases.precondition', 'BEFORE_THE_FIRST_PLAN'),
            ('rootAliases.stateAtBase', 'MERGED_AT_BASE'),
            ('rootAliases.inputs', 'BUILD_INPUTS_V4'),
            ('rootAliases.rootLink', '/lib64'),
            ('rootAliases.loader', '/lib64/ld-linux-x86-64.so.2'),
            ('rootAliases.checkAtStep', 9),
            ('rootAliases.uncoveredUsedPath', 'STOP_NOT_RUN_ENV_UNAVAILABLE'),
            ('rootAliases.onPaper', True),
        ],
        "DESIGN.r7.md 375-386 (MET-REPAIR-015's prerequisites); MON-LHA-SPLIT": [
            ('profile[SELINUX_ENFORCING].prerequisite', 'SELINUX_ENFORCING'),
            ('profile[SELINUX_ENFORCING].owner', 'THIS_RECIPE'),
            ('profile[SELINUX_ENFORCING].steps[*]', [4, 5]),
            ('profile[SELINUX_ENFORCING].check', 'PREFLIGHT_READS_SYS_FS_SELINUX'),
            ('profile[SELINUX_ENFORCING].value', 'ENFORCING'),
            ('profile[REVIEWED_EXACT_BINARY_POLICY].prerequisite', 'REVIEWED_EXACT_BINARY_POLICY'),
            ('profile[REVIEWED_EXACT_BINARY_POLICY].owner', 'THE_EXISTING_INDEPENDENT_OPERATOR'),
            ('profile[REVIEWED_EXACT_BINARY_POLICY].steps[*]', [7]),
            ('profile[REVIEWED_EXACT_BINARY_POLICY].check', 'MET_REPAIR_015_READER'),
            ('profile[REVIEWED_EXACT_BINARY_POLICY].value', 'DENY_UNKNOWN_1'),
            ('profile[EXT4_VERITY_ROOT_AND_MEASUREMENTS].prerequisite', 'EXT4_VERITY_ROOT_AND_MEASUREMENTS'),
            ('profile[EXT4_VERITY_ROOT_AND_MEASUREMENTS].owner', 'RECIPE_FILESYSTEM_OPERATOR_MEASUREMENTS'),
            ('profile[EXT4_VERITY_ROOT_AND_MEASUREMENTS].steps[*]', [4, 5, 7]),
            ('profile[EXT4_VERITY_ROOT_AND_MEASUREMENTS].check', 'MET_REPAIR_015_READER'),
            ('profile[EXT4_VERITY_ROOT_AND_MEASUREMENTS].value', 'EVERY_CLOSED_LIST_FILE_MEASURED'),
            ('profile[CGROUP_V2_AND_PLANEON_LIVE_CGROUPS].prerequisite', 'CGROUP_V2_AND_PLANEON_LIVE_CGROUPS'),
            ('profile[CGROUP_V2_AND_PLANEON_LIVE_CGROUPS].owner', 'RECIPE_V2_OPERATOR_CGROUPS'),
            ('profile[CGROUP_V2_AND_PLANEON_LIVE_CGROUPS].steps[*]', [4, 5, 7]),
            ('profile[CGROUP_V2_AND_PLANEON_LIVE_CGROUPS].check', 'MET_REPAIR_015_READER'),
            ('profile[CGROUP_V2_AND_PLANEON_LIVE_CGROUPS].value', 'FINITE_LIMITS'),
            ('profile[ONE_ENROLLED_BPF_PROGRAM_PER_HOOK_PER_ROLE].prerequisite',
             'ONE_ENROLLED_BPF_PROGRAM_PER_HOOK_PER_ROLE'),
            ('profile[ONE_ENROLLED_BPF_PROGRAM_PER_HOOK_PER_ROLE].owner', 'THE_EXISTING_INDEPENDENT_OPERATOR'),
            ('profile[ONE_ENROLLED_BPF_PROGRAM_PER_HOOK_PER_ROLE].steps[*]', [7]),
            ('profile[ONE_ENROLLED_BPF_PROGRAM_PER_HOOK_PER_ROLE].check', 'MET_REPAIR_015_READER'),
            ('profile[ONE_ENROLLED_BPF_PROGRAM_PER_HOOK_PER_ROLE].value', 'ENROLLED'),
            ('profile[KERNEL_RELEASE_NOTES_DIGEST_AND_BOOT_ID].prerequisite',
             'KERNEL_RELEASE_NOTES_DIGEST_AND_BOOT_ID'),
            ('profile[KERNEL_RELEASE_NOTES_DIGEST_AND_BOOT_ID].owner', 'THIS_RECIPE_RECORDS'),
            ('profile[KERNEL_RELEASE_NOTES_DIGEST_AND_BOOT_ID].steps[*]', [11]),
            ('profile[KERNEL_RELEASE_NOTES_DIGEST_AND_BOOT_ID].check', 'PREFLIGHT'),
            ('profile[KERNEL_RELEASE_NOTES_DIGEST_AND_BOOT_ID].value', 'RECORDED'),
            ('profile[SERIALISED_POLICY_FILTER_CGROUP_LABEL_AND_EXECUTABLE_CHANGES].prerequisite',
             'SERIALISED_POLICY_FILTER_CGROUP_LABEL_AND_EXECUTABLE_CHANGES'),
            ('profile[SERIALISED_POLICY_FILTER_CGROUP_LABEL_AND_EXECUTABLE_CHANGES].owner',
             'THE_EXISTING_INDEPENDENT_OPERATOR'),
            ('profile[SERIALISED_POLICY_FILTER_CGROUP_LABEL_AND_EXECUTABLE_CHANGES].steps[*]', [7]),
            ('profile[SERIALISED_POLICY_FILTER_CGROUP_LABEL_AND_EXECUTABLE_CHANGES].check', 'THE_OPERATOR_OWN_RECORD'),
            ('profile[SERIALISED_POLICY_FILTER_CGROUP_LABEL_AND_EXECUTABLE_CHANGES].value', 'SERIALISED_FROM_STEP_7'),
        ],
        'DESIGN.r7.md 390 (SSH only through IAP); Q-LHA-12 (a)': [
            ('access.ssh.only', 'IAP'),
            ('access.ssh.sourceRange', '35.235.240.0/20'),
            ('access.ssh.protocol', 'tcp'),
            ('access.ssh.port', 22),
            ('access.ssh.onPaper', True),
        ],
        'DESIGN.r7.md 391-394 (two identities); Q-LHA5-1; B-LHA-18 (no login for OWNER_ADMIN, Q-LHA6-3)': [
            ('access.identities[OWNER_LOGIN].label', 'OWNER_LOGIN'),
            ('access.identities[OWNER_LOGIN].of', 'OWNER'),
            ('access.identities[OWNER_LOGIN].use', 'SSH_ONLY'),
            ('access.identities[OWNER_LOGIN].osLogin', True),
            ('access.identities[OWNER_LOGIN].twoStepVerification', True),
            ('access.identities[OWNER_LOGIN].administersIam', False),
            ('access.identities[OWNER_ADMIN].label', 'OWNER_ADMIN'),
            ('access.identities[OWNER_ADMIN].of', 'OWNER'),
            ('access.identities[OWNER_ADMIN].use', 'IAM_ADMINISTRATION_AND_CLOUD_ACTIONS'),
            ('access.identities[OWNER_ADMIN].osLogin', False),
            ('access.identities[OWNER_ADMIN].twoStepVerification', True),
            ('access.identities[OWNER_ADMIN].administersIam', True),
        ],
        'DESIGN.r7.md 395-407 (the login baseline custom role); B-LHA-14; B-LHA-15; OWNER-CUSTOM-ROLE': [
            ('access.loginBaseline.label', 'OWNER_LOGIN_BASELINE'),
            ('access.loginBaseline.kind', 'CUSTOM_ROLE'),
            ('access.loginBaseline.boundOn', 'RUN_PROJECT'),
            ('access.loginBaseline.basicRole', 'NONE'),
            ('access.loginBaseline.inPlaceOf[*]', ['OWNER', 'EDITOR', 'VIEWER']),
            ('access.loginBaseline.permittedPurpose', 'SSH_THROUGH_IAP_AND_OS_LOGIN_ONLY'),
            ('access.loginBaseline.excludes[*]',
             ['compute.instances.osAdminLogin',
              'resourcemanager.projects.setIamPolicy',
              'compute.instances.setIamPolicy',
              'iam.serviceAccounts.setIamPolicy',
              'iam.roles.create',
              'iam.roles.update',
              'resourcemanager.folders.setIamPolicy',
              'resourcemanager.organizations.setIamPolicy',
              'iam.serviceAccounts.actAs',
              'iam.serviceAccounts.getAccessToken',
              'iam.serviceAccounts.signBlob',
              'iam.serviceAccounts.signJwt',
              'iam.serviceAccounts.implicitDelegation',
              'iam.serviceAccounts.getOpenIdToken',
              'iam.serviceAccountKeys.create',
              'resourcemanager.tagValueBindings.create',
              'resourcemanager.tagValueBindings.delete']),
            ('access.loginBaseline.noOtherGrant[*]',
             ['DIRECT', 'GROUP', 'DOMAIN', 'PRINCIPAL_SET', 'FOLDER_INHERITED', 'ORGANIZATION_INHERITED']),
            ('access.loginBaseline.onPaper', True),
        ],
        'DESIGN.r7.md 401-402 (recorded in the plan at approval, LHA5-2); B-LHA-17': [
            ('access.loginBaseline.recordedInPlan.roleId', 'REAL_ID_IN_THE_OWNER_HELD_PLAN_ROLE_LABEL_WHEN_PUBLISHED'),
            ('access.loginBaseline.recordedInPlan.exactPermissionList', True),
        ],
        "DESIGN.r7.md 399-400 (the custom role's lifecycle, LHA5-8)": [
            ('access.loginBaseline.lifecycle.createdBy', 'OWNER_ADMIN'),
            ('access.loginBaseline.lifecycle.boundBy', 'OWNER_ADMIN'),
            ('access.loginBaseline.lifecycle.when', 'OUTSIDE_THE_RUN_BEFORE_APPROVAL'),
            ('access.loginBaseline.lifecycle.keptBetweenRuns', True),
            ('access.loginBaseline.lifecycle.deletedAtTeardown', False),
        ],
        'B-LHA-18 (OWNER_ADMIN holds no login permission; Q-LHA6-3)': [
            ('access.adminBaseline.label', 'OWNER_ADMIN'),
            ('access.adminBaseline.holdsNoLoginPermission[*]',
             ['compute.instances.osLogin', 'compute.instances.osAdminLogin', 'iap.tunnelInstances.accessViaIAP']),
            ('access.adminBaseline.on', 'RUN_PROJECT_AND_EVERY_ANCESTOR'),
            ('access.adminBaseline.countsAmongBaselineBindings', True),
            ('access.adminBaseline.decision', 'Q-LHA6-3'),
        ],
        'DESIGN.r7.md 408-410 (between runs, LHA5-6); B-LHA-18': [
            ('access.betweenRuns.bindings[*]',
             ['OWNER_LOGIN_BASELINE_BINDING', 'OWNER_ADMIN_BINDING', 'OBSERVER_VIEWER_BINDINGS']),
            ('access.betweenRuns.isLabRunPlanOwnerBaseline', True),
            ('access.betweenRuns.confirmedAtStep', 1),
        ],
        'DESIGN.r7.md 411-416 (the lease bindings, LHA5-7), 430-431; runbook steps 10 and 16 (DESIGN.r7.md 494, 500)': [
            ('access.leaseBindings[IAP_TUNNEL].role', 'IAP_TUNNEL'),
            ('access.leaseBindings[IAP_TUNNEL].grantee', 'OWNER_LOGIN'),
            ('access.leaseBindings[IAP_TUNNEL].grantedBy', 'OWNER_ADMIN'),
            ('access.leaseBindings[IAP_TUNNEL].counted', 'IAM_BINDINGS_ADDED'),
            ('access.leaseBindings[IAP_TUNNEL].window', 'THE_LEASE'),
            ('access.leaseBindings[IAP_TUNNEL].revokedBy', 'OWNER_ADMIN'),
            ('access.leaseBindings[IAP_TUNNEL].revokedAtStep', 16),
            ('access.leaseBindings[OS_LOGIN_ADMIN].role', 'OS_LOGIN_ADMIN'),
            ('access.leaseBindings[OS_LOGIN_ADMIN].grantee', 'OWNER_LOGIN'),
            ('access.leaseBindings[OS_LOGIN_ADMIN].grantedBy', 'OWNER_ADMIN'),
            ('access.leaseBindings[OS_LOGIN_ADMIN].counted', 'IAM_BINDINGS_ADDED'),
            ('access.leaseBindings[OS_LOGIN_ADMIN].window', 'SETUP_AND_INSTALL'),
            ('access.leaseBindings[OS_LOGIN_ADMIN].revokedBy', 'OWNER_ADMIN'),
            ('access.leaseBindings[OS_LOGIN_ADMIN].revokedAtStep', 10),
            ('access.leaseBindings[OS_LOGIN].role', 'OS_LOGIN'),
            ('access.leaseBindings[OS_LOGIN].grantee', 'OWNER_LOGIN'),
            ('access.leaseBindings[OS_LOGIN].grantedBy', 'OWNER_ADMIN'),
            ('access.leaseBindings[OS_LOGIN].counted', 'IAM_BINDINGS_ADDED'),
            ('access.leaseBindings[OS_LOGIN].window', 'AFTER_THE_REVOCATION'),
            ('access.leaseBindings[OS_LOGIN].revokedBy', 'OWNER_ADMIN'),
            ('access.leaseBindings[OS_LOGIN].revokedAtStep', 16),
        ],
        'DESIGN.r7.md 417-418 (the revocation at step 10); B-LHA-10': [
            ('access.revocation.atStep', 10),
            ('access.revocation.by', 'OWNER_ADMIN'),
            ('access.revocation.removes', 'OS_LOGIN_ADMIN'),
            ('access.revocation.denyPolicy', False),
            ('access.revocation.folderOrOrganizationGrant', False),
            ('access.revocation.thenWaitsForPropagation', True),
            ('access.revocation.endsAdminSessionsOn[*]', ['PROXY_OPERATOR_HOST', 'CLUSTER_NODE']),
        ],
        ('DESIGN.r7.md 419-427 (the checks); runbook steps 1, 10 and 15 (DESIGN.r7.md 485, 494, 499); B-LHA-14; '
         'B-LHA-15; B-LHA-17; B-LHA-18'): [
            ('access.effectiveChecks[*].step', [1, 10, 15, 1, 10, 15]),
            ('access.effectiveChecks[*].identity',
             ['OWNER_LOGIN', 'OWNER_LOGIN', 'OWNER_LOGIN', 'OWNER_ADMIN', 'OWNER_ADMIN', 'OWNER_ADMIN']),
            ('access.effectiveChecks[*].runBy',
             ['OWNER_ADMIN',
              'OBSERVER_AND_OWNER_ADMIN',
              'OBSERVER_AND_OWNER_ADMIN',
              'OWNER_ADMIN',
              'OBSERVER_AND_OWNER_ADMIN',
              'OBSERVER_AND_OWNER_ADMIN']),
            ('access.effectiveChecks[*].kind',
             ['CONFIRMATION_AT_APPROVAL',
              'EFFECTIVE_CHECK',
              'EFFECTIVE_CHECK',
              'CONFIRMATION_AT_APPROVAL',
              'EFFECTIVE_CHECK',
              'EFFECTIVE_CHECK']),
            ('access.effectiveChecks[*].propagationWait',
             ['NOT_APPLICABLE', 'BEFORE_CHECK', 'BEFORE_CHECK', 'NOT_APPLICABLE', 'BEFORE_CHECK', 'BEFORE_CHECK']),
            ('access.effectiveChecks[*].absent[*]',
             [['compute.instances.osAdminLogin',
               'resourcemanager.projects.setIamPolicy',
               'compute.instances.setIamPolicy',
               'iam.serviceAccounts.setIamPolicy',
               'iam.roles.create',
               'iam.roles.update',
               'resourcemanager.folders.setIamPolicy',
               'resourcemanager.organizations.setIamPolicy',
               'iam.serviceAccounts.actAs',
               'iam.serviceAccounts.getAccessToken',
               'iam.serviceAccounts.signBlob',
               'iam.serviceAccounts.signJwt',
               'iam.serviceAccounts.implicitDelegation',
               'iam.serviceAccounts.getOpenIdToken',
               'iam.serviceAccountKeys.create',
               'resourcemanager.tagValueBindings.create',
               'resourcemanager.tagValueBindings.delete'],
              ['compute.instances.osAdminLogin',
               'resourcemanager.projects.setIamPolicy',
               'compute.instances.setIamPolicy',
               'iam.serviceAccounts.setIamPolicy',
               'iam.roles.create',
               'iam.roles.update',
               'resourcemanager.folders.setIamPolicy',
               'resourcemanager.organizations.setIamPolicy',
               'iam.serviceAccounts.actAs',
               'iam.serviceAccounts.getAccessToken',
               'iam.serviceAccounts.signBlob',
               'iam.serviceAccounts.signJwt',
               'iam.serviceAccounts.implicitDelegation',
               'iam.serviceAccounts.getOpenIdToken',
               'iam.serviceAccountKeys.create',
               'resourcemanager.tagValueBindings.create',
               'resourcemanager.tagValueBindings.delete'],
              ['compute.instances.osAdminLogin',
               'resourcemanager.projects.setIamPolicy',
               'compute.instances.setIamPolicy',
               'iam.serviceAccounts.setIamPolicy',
               'iam.roles.create',
               'iam.roles.update',
               'resourcemanager.folders.setIamPolicy',
               'resourcemanager.organizations.setIamPolicy',
               'iam.serviceAccounts.actAs',
               'iam.serviceAccounts.getAccessToken',
               'iam.serviceAccounts.signBlob',
               'iam.serviceAccounts.signJwt',
               'iam.serviceAccounts.implicitDelegation',
               'iam.serviceAccounts.getOpenIdToken',
               'iam.serviceAccountKeys.create',
               'resourcemanager.tagValueBindings.create',
               'resourcemanager.tagValueBindings.delete'],
              ['compute.instances.osLogin', 'compute.instances.osAdminLogin', 'iap.tunnelInstances.accessViaIAP'],
              ['compute.instances.osLogin', 'compute.instances.osAdminLogin', 'iap.tunnelInstances.accessViaIAP'],
              ['compute.instances.osLogin', 'compute.instances.osAdminLogin', 'iap.tunnelInstances.accessViaIAP']]),
            ('access.effectiveChecks[*].resources[*]',
             [['RUN_PROJECT', 'EACH_INSTANCE', 'EACH_SERVICE_ACCOUNT', 'EVERY_ANCESTOR_FOLDER', 'ORGANIZATION'],
              ['RUN_PROJECT', 'EACH_INSTANCE', 'EACH_SERVICE_ACCOUNT', 'EVERY_ANCESTOR_FOLDER', 'ORGANIZATION'],
              ['RUN_PROJECT', 'EACH_INSTANCE', 'EACH_SERVICE_ACCOUNT', 'EVERY_ANCESTOR_FOLDER', 'ORGANIZATION'],
              ['RUN_PROJECT', 'EVERY_ANCESTOR_FOLDER', 'ORGANIZATION'],
              ['RUN_PROJECT', 'EVERY_ANCESTOR_FOLDER', 'ORGANIZATION'],
              ['RUN_PROJECT', 'EVERY_ANCESTOR_FOLDER', 'ORGANIZATION']]),
            ('access.effectiveChecks[*].grantPaths[*]',
             [['DIRECT', 'BASIC_ROLE', 'CUSTOM_ROLE', 'INHERITED', 'GROUP', 'DOMAIN', 'PRINCIPAL_SET', 'CONDITIONAL'],
              ['DIRECT', 'BASIC_ROLE', 'CUSTOM_ROLE', 'INHERITED', 'GROUP', 'DOMAIN', 'PRINCIPAL_SET', 'CONDITIONAL'],
              ['DIRECT', 'BASIC_ROLE', 'CUSTOM_ROLE', 'INHERITED', 'GROUP', 'DOMAIN', 'PRINCIPAL_SET', 'CONDITIONAL'],
              ['DIRECT', 'BASIC_ROLE', 'CUSTOM_ROLE', 'INHERITED', 'GROUP', 'DOMAIN', 'PRINCIPAL_SET', 'CONDITIONAL'],
              ['DIRECT', 'BASIC_ROLE', 'CUSTOM_ROLE', 'INHERITED', 'GROUP', 'DOMAIN', 'PRINCIPAL_SET', 'CONDITIONAL'],
              ['DIRECT', 'BASIC_ROLE', 'CUSTOM_ROLE', 'INHERITED', 'GROUP', 'DOMAIN', 'PRINCIPAL_SET', 'CONDITIONAL']]),
            ('access.effectiveChecks[*].conditionalBindingIsGrant', [True, True, True, True, True, True]),
            ('access.effectiveChecks[*].checksNoBasicRole', [True, True, True, False, False, False]),
            ('access.effectiveChecks[*].checksPermissionListAgainstPlan', [True, True, True, False, False, False]),
            ('access.effectiveChecks[*].onFinding',
             ['REFUSE_RUN_EVIDENCE',
              'REFUSE_RUN_EVIDENCE',
              'REFUSE_RUN_EVIDENCE',
              'REFUSE_RUN_EVIDENCE',
              'REFUSE_RUN_EVIDENCE',
              'REFUSE_RUN_EVIDENCE']),
        ],
        'B-LHA-17 (who runs the checks, and the on-paper mechanism)': [
            ('access.permissionMechanism.onPaper', True),
            ('access.permissionMechanism.projectAndInstances.runBy', 'OBSERVER'),
            ('access.permissionMechanism.projectAndInstances.reads',
             'THE_IAM_POLICIES_OF_THE_RUN_PROJECT_ITS_INSTANCES_AND_SERVICE_ACCOUNTS'),
            ('access.permissionMechanism.projectAndInstances.with', 'ITS_RUN_PROJECT_VIEWER_ROLES'),
            ('access.permissionMechanism.ancestors.runBy', 'OWNER_ADMIN'),
            ('access.permissionMechanism.ancestors.reads',
             'THE_IAM_POLICIES_OF_EVERY_ANCESTOR_FOLDER_AND_THE_ORGANIZATION'),
            ('access.permissionMechanism.membership.runBy', 'OWNER_ADMIN'),
            ('access.permissionMechanism.membership.groups',
             'THE_LOGIN_IDENTITY_TRANSITIVE_GROUP_MEMBERSHIP_RESOLVED_THROUGH_THE_DIRECTORY'),
            ('access.permissionMechanism.membership.domain',
             'A_DOMAIN_BINDING_COVERING_THE_LOGIN_IDENTITY_COUNTS_AS_A_GRANT'),
            ('access.permissionMechanism.membership.principalSets',
             'ANY_PRINCIPAL_SET_THAT_CAN_INCLUDE_THE_LOGIN_IDENTITY_COUNTS_AS_A_GRANT'),
            ('access.permissionMechanism.roles',
             'EVERY_MATCHED_ROLE_EXPANDED_TO_ITS_PERMISSIONS_BASIC_PREDEFINED_AND_CUSTOM'),
            ('access.permissionMechanism.conditions', 'A_CONDITIONAL_BINDING_COUNTS_AS_A_GRANT'),
            ('access.permissionMechanism.cannotRead', 'THE_CHECK_FAILS_AND_THE_RUN_EVIDENCE_IS_REFUSED'),
            ('access.permissionMechanism.neverRunBy', 'OWNER_LOGIN'),
        ],
        'B-LHA-10 (admin sessions)': [
            ('access.sessionChecks.atStep', 10),
            ('access.sessionChecks.after', 'IAM_PROPAGATION'),
            ('access.sessionChecks.endsEverySessionOpenedWithAdminOn[*]', ['PROXY_OPERATOR_HOST', 'CLUSTER_NODE']),
            ('access.sessionChecks.identities[*]', ['OWNER_LOGIN', 'OWNER_ADMIN']),
            ('access.sessionChecks.confirms[*]',
             ['NO_PROCESS_OR_SESSION_STARTED_BEFORE_REVOCATION',
              'NO_OS_LOGIN_SUDOERS_ENTRY',
              'FRESH_LOGIN_CANNOT_USE_SUDO']),
            ('access.sessionChecks.preRevocationAdminSessionAliveAtPreflight', 'REFUSES_RUN_EVIDENCE'),
        ],
        'B-LHA-16 (the exact audit expectation); DESIGN.r7.md 424-425': [
            ('access.auditLogCheck.log', 'ADMIN_ACTIVITY'),
            ('access.auditLogCheck.from', 'STEP_10_REVOCATION_ENTRY'),
            ('access.auditLogCheck.to', 'END_OF_TEARDOWN'),
            ('access.auditLogCheck.runBy', 'OBSERVER_AND_OWNER_ADMIN'),
            ('access.auditLogCheck.lists[*]',
             ['IAM_POLICY_CHANGE_RUN_PROJECT',
              'IAM_POLICY_CHANGE_INSTANCE',
              'CUSTOM_ROLE_CREATE',
              'CUSTOM_ROLE_UPDATE',
              'CUSTOM_ROLE_DELETE',
              'CUSTOM_ROLE_UNDELETE']),
            ('access.auditLogCheck.expected[STEP_10_ADMIN_LOGIN_BINDING_REMOVAL].entry',
             'STEP_10_ADMIN_LOGIN_BINDING_REMOVAL'),
            ('access.auditLogCheck.expected[STEP_10_ADMIN_LOGIN_BINDING_REMOVAL].by', 'OWNER_ADMIN'),
            ('access.auditLogCheck.expected[NON_ADMIN_LOGIN_GRANT_IF_IN_WINDOW].entry',
             'NON_ADMIN_LOGIN_GRANT_IF_IN_WINDOW'),
            ('access.auditLogCheck.expected[NON_ADMIN_LOGIN_GRANT_IF_IN_WINDOW].by', 'OWNER_ADMIN'),
            ('access.auditLogCheck.expected[TEARDOWN_REVOCATIONS].entry', 'TEARDOWN_REVOCATIONS'),
            ('access.auditLogCheck.expected[TEARDOWN_REVOCATIONS].by', 'OWNER_ADMIN'),
            ('access.auditLogCheck.anyOtherEntry', 'REFUSES_RUN_EVIDENCE_WHATEVER_ITS_PRINCIPAL'),
            ('access.auditLogCheck.anyCustomRoleChange', 'REFUSES_RUN_EVIDENCE'),
            ('access.auditLogCheck.finalSpanCheckedAfterTeardownCompletes', True),
            ('access.auditLogCheck.evidenceAcceptedOnlyAfterThisCheck', True),
        ],
        'B-LHA-14; B-LHA-16; Q-LHA5-1 (detected by the effective check, not blocked); DESIGN.r7.md 426': [
            ('access.acceptedLimit.decision', 'Q-LHA5-1'),
            ('access.acceptedLimit.words', 'detected by the effective check, not blocked'),
            ('access.acceptedLimit.grantKinds[*]',
             ['GROUP_MEMBERSHIP_CHANGE',
              'DOMAIN_MEMBERSHIP_CHANGE',
              'PRINCIPAL_SET_MEMBERSHIP_CHANGE',
              'FOLDER_BINDING',
              'ORGANIZATION_BINDING']),
            ('access.acceptedLimit.detectedOnlyBy[*]', ['EFFECTIVE_CHECK_STEP_10', 'EFFECTIVE_CHECK_STEP_15']),
            ('access.acceptedLimit.notDetected[*]',
             ['A_GRANT_MADE_AND_REMOVED_BETWEEN_STEPS_10_AND_15', 'A_GRANT_MADE_AFTER_STEP_15']),
            ('access.acceptedLimit.auditLogDetectsThem', False),
            ('access.acceptedLimit.caughtByTheAuditLogCheck',
             'A_RUN_PROJECT_OR_INSTANCE_BINDING_TO_ANY_PRINCIPAL_GROUPS_INCLUDED_THROUGH_TEARDOWN'),
        ],
        'DESIGN.r7.md 428-429 (only the signed-drop installer after the revocation)': [
            ('access.afterRevocationRootFiles', 'SIGNED_DROP_INSTALLER_ONLY'),
        ],
        ("DESIGN.r7.md 430-431 (teardown revokes the lease's bindings; the baseline stays, LHA5-8); runbook step 16 "
         '(DESIGN.r7.md 500)'): [
            ('access.teardown.by', 'OWNER_ADMIN'),
            ('access.teardown.revokes', 'EVERY_BINDING_GRANTED_SINCE_THE_LEASE_STARTED'),
            ('access.teardown.keeps[*]',
             ['OWNER_LOGIN_BASELINE_ROLE', 'OWNER_LOGIN_BASELINE_BINDING', 'OWNER_ADMIN_BINDING']),
        ],
        'DESIGN.r7.md 435-447 (egress); Q-LHA-11 (a)': [
            ('egress.window', 'THE_SETUP_WINDOW_ONLY'),
            ('egress.fetches', 'OPERATOR_INITIATED_AND_DIGEST_PINNED'),
            ('egress.fetchTool', 'ONE_OPERATOR_FETCH_TOOL'),
            ('egress.matching', 'IP_RANGES_LISTED_PER_PLAN'),
            ('egress.paidFirewallFeature', False),
            ('egress.byteCeiling', 'THE_FETCH_TOOL_STOPS_AT_THE_CEILING'),
            ('egress.providerFigures', 'COMPARED_AFTER_THE_WINDOW_DETECTS_NOT_PREVENTS'),
            ('egress.closure.denyAllCreatedAtStep', 2),
            ('egress.closure.closedAtStep', 6),
            ('egress.closure.removes[*]', ['THE_SETUP_WINDOW_ALLOW_RULE', 'BOTH_EXTERNAL_ADDRESSES']),
            ('egress.check[*]', ['REFUSAL_PROBE_ON_EACH_HOST', 'THE_OBSERVER_LISTING']),
            ('egress.expectedExceptions[*]', ['METADATA_ADDRESS', 'F1', 'F2']),
            ('egress.atCampaign.externalAddress', False),
            ('egress.atCampaign.allowEgressRule', False),
            ('egress.atCampaign.launcherIsolation', 'DENY_ALL'),
        ],
        'DESIGN.r7.md 448-450 (time)': [
            ('time.source', 'THE_PROVIDER_INTERNAL_TIME_SERVICE'),
            ('time.daemon', 'CHRONY'),
            ('time.otherMetadataUses[*]', ['OS_LOGIN_NSS_PAM', 'THE_GUEST_AGENT_KEPT_FEATURES', 'DNS']),
            ('time.capturedAtPreflight[*]', ['CLOCK_SOURCE', 'OFFSET']),
            ('time.podsDeniedTheMetadataServerBy', 'THE_KIT'),
        ],
        'DESIGN.r7.md 451-465 (packages)': [
            ('packages.proxyOperatorHost[*]',
             ['GIT',
              'FIREJAIL_AT_/usr/bin/firejail',
              'LOCKED_PYTHON_3_12_14_AT_/opt/planeon/python/3.12.14',
              'NODE_FOR_THE_STANDALONE_CONTROL_BUILD',
              'GO_ONLY_IF_NEEDED']),
            ('packages.clusterNode[*]', ['THE_CLUSTER_DISTRIBUTION', 'ITS_PINNED_DISTRIBUTION_PACKAGES']),
            ('packages.sources[DISTRIBUTION_PACKAGES].what', 'DISTRIBUTION_PACKAGES'),
            ('packages.sources[DISTRIBUTION_PACKAGES].from', 'THE_FAMILY_DATED_SNAPSHOT'),
            ('packages.sources[DISTRIBUTION_PACKAGES].pin', 'VERSION_AND_FILE_SHA256'),
            ('packages.sources[DISTRIBUTION_PACKAGES].onPaper', True),
            ('packages.sources[FIREJAIL].what', 'FIREJAIL'),
            ('packages.sources[FIREJAIL].from', 'EPEL_EXACT_RPM_FILES'),
            ('packages.sources[FIREJAIL].pin', 'FILE_SHA256'),
            ('packages.sources[FIREJAIL].onPaper', True),
            ('packages.sources[LOCKED_PYTHON_AND_NODE].what', 'LOCKED_PYTHON_AND_NODE'),
            ('packages.sources[LOCKED_PYTHON_AND_NODE].from', 'OUTSIDE_THE_SNAPSHOT_WITH_SOURCE_AND_DIGEST_CLOSURE'),
            ('packages.sources[LOCKED_PYTHON_AND_NODE].pin', 'FILE_SHA256'),
            ('packages.sources[LOCKED_PYTHON_AND_NODE].onPaper', False),
            ('packages.mirrorRule', 'EVERY_PACKAGE_PINNED_BY_EXACT_FILE_DIGEST_FROM_A_DATED_SNAPSHOT_WHERE_OFFERED'),
            ('packages.relaxes', 'REVISION_3_NO_UNDATED_MIRROR_REFUSAL'),
            ('packages.toolRoot', '/opt/planeon/tools'),
            ('packages.cacheRoot', '/opt/planeon/cache'),
            ('packages.automaticUpdaters', 'OFF'),
            ('packages.updaters[*]', ['DISTRIBUTION_UPDATER', 'SNAP_REFRESH', 'UPDATE_TIMERS']),
        ],
        ('DESIGN.r7.md 466-468 (the source transfer), 97 (no repository credential on the host); runbook step 4 '
         '(DESIGN.r7.md 488)'): [
            ('source.what', 'THE_OWNED_PRODUCT_CHECKOUT_AND_THE_WORKLOAD_COMMIT'),
            ('source.withGit', True),
            ('source.treeSha256', True),
            ('source.transfer', 'BY_DIGEST_OVER_THE_IAP_TUNNEL'),
            ('source.into', 'THE_PROXY_OPERATOR_HOST_BUILT_ROOT'),
            ('source.repositoryCredentialOnHost', False),
        ],
        'B-LHA-5 (the closed list of runtime state paths, each with its one writer)': [
            ('runtimeRootWrites[HOST_LEDGER_LAUNCHER].id', 'HOST_LEDGER_LAUNCHER'),
            ('runtimeRootWrites[HOST_LEDGER_LAUNCHER].host', 'PROXY_OPERATOR_HOST'),
            ('runtimeRootWrites[HOST_LEDGER_LAUNCHER].path', '/var/lib/planeon/host-ledger/launcher/'),
            ('runtimeRootWrites[HOST_LEDGER_LAUNCHER].writer', 'LIVE_LAUNCHER'),
            ('runtimeRootWrites[HOST_LEDGER_PROXY_CLIENT].id', 'HOST_LEDGER_PROXY_CLIENT'),
            ('runtimeRootWrites[HOST_LEDGER_PROXY_CLIENT].host', 'PROXY_OPERATOR_HOST'),
            ('runtimeRootWrites[HOST_LEDGER_PROXY_CLIENT].path', '/var/lib/planeon/host-ledger/proxy-client/'),
            ('runtimeRootWrites[HOST_LEDGER_PROXY_CLIENT].writer', 'CAMPAIGN_PROXY_CLIENT'),
            ('runtimeRootWrites[HOST_LEDGER_PROXY_SERVER].id', 'HOST_LEDGER_PROXY_SERVER'),
            ('runtimeRootWrites[HOST_LEDGER_PROXY_SERVER].host', 'PROXY_OPERATOR_HOST'),
            ('runtimeRootWrites[HOST_LEDGER_PROXY_SERVER].path', '/var/lib/planeon/host-ledger/proxy-server/'),
            ('runtimeRootWrites[HOST_LEDGER_PROXY_SERVER].writer', 'CAMPAIGN_PROXY_SERVER'),
            ('runtimeRootWrites[PREFLIGHT_RECORDS].id', 'PREFLIGHT_RECORDS'),
            ('runtimeRootWrites[PREFLIGHT_RECORDS].host', 'PROXY_OPERATOR_HOST'),
            ('runtimeRootWrites[PREFLIGHT_RECORDS].path', '/var/lib/planeon/preflight/'),
            ('runtimeRootWrites[PREFLIGHT_RECORDS].writer', 'PREFLIGHT_UNIT'),
            ('runtimeRootWrites[INSTALLER_LOG].id', 'INSTALLER_LOG'),
            ('runtimeRootWrites[INSTALLER_LOG].host', 'PROXY_OPERATOR_HOST'),
            ('runtimeRootWrites[INSTALLER_LOG].path', '/var/log/planeon/signed-drop-installer.log'),
            ('runtimeRootWrites[INSTALLER_LOG].writer', 'SIGNED_DROP_INSTALLER'),
            ('runtimeRootWrites[EVIDENCE_SINK].id', 'EVIDENCE_SINK'),
            ('runtimeRootWrites[EVIDENCE_SINK].host', 'PROXY_OPERATOR_HOST'),
            ('runtimeRootWrites[EVIDENCE_SINK].path', '/var/lib/planeon/evidence-sink/'),
            ('runtimeRootWrites[EVIDENCE_SINK].writer', 'LOCAL_EVIDENCE_SINK'),
            ('runtimeRootWrites[JOURNAL].id', 'JOURNAL'),
            ('runtimeRootWrites[JOURNAL].host', 'BOTH_HOSTS'),
            ('runtimeRootWrites[JOURNAL].path', '/var/log/journal/'),
            ('runtimeRootWrites[JOURNAL].writer', 'SYSTEMD_JOURNALD'),
            ('runtimeRootWrites[CLUSTER_STATE].id', 'CLUSTER_STATE'),
            ('runtimeRootWrites[CLUSTER_STATE].host', 'CLUSTER_NODE'),
            ('runtimeRootWrites[CLUSTER_STATE].path', 'THE_CLUSTER_DISTRIBUTION_STATE_DIRECTORY'),
            ('runtimeRootWrites[CLUSTER_STATE].writer', 'THE_CLUSTER_DISTRIBUTION'),
        ],
        'DESIGN.r7.md 469-472 (the paid items, each a plan line item); LHA3-5': [
            ('costScope[PROXY_OPERATOR_HOST_MACHINE_HOURS].item', 'PROXY_OPERATOR_HOST_MACHINE_HOURS'),
            ('costScope[PROXY_OPERATOR_HOST_MACHINE_HOURS].planLineItem', True),
            ('costScope[PROXY_OPERATOR_HOST_MACHINE_HOURS].requiredBy', 'LAB-RUNPLAN-001'),
            ('costScope[PROXY_OPERATOR_HOST_BOOT_DISK].item', 'PROXY_OPERATOR_HOST_BOOT_DISK'),
            ('costScope[PROXY_OPERATOR_HOST_BOOT_DISK].planLineItem', True),
            ('costScope[PROXY_OPERATOR_HOST_BOOT_DISK].requiredBy', 'LAB-RUNPLAN-001'),
            ('costScope[CLUSTER_NODE_MACHINE_HOURS].item', 'CLUSTER_NODE_MACHINE_HOURS'),
            ('costScope[CLUSTER_NODE_MACHINE_HOURS].planLineItem', True),
            ('costScope[CLUSTER_NODE_MACHINE_HOURS].requiredBy', 'LAB-RUNPLAN-001'),
            ('costScope[CLUSTER_NODE_BOOT_DISK].item', 'CLUSTER_NODE_BOOT_DISK'),
            ('costScope[CLUSTER_NODE_BOOT_DISK].planLineItem', True),
            ('costScope[CLUSTER_NODE_BOOT_DISK].requiredBy', 'LAB-RUNPLAN-001'),
            ('costScope[TEMPORARY_BUILD_DISK].item', 'TEMPORARY_BUILD_DISK'),
            ('costScope[TEMPORARY_BUILD_DISK].planLineItem', True),
            ('costScope[TEMPORARY_BUILD_DISK].requiredBy', 'THIS_RECIPE'),
            ('costScope[STORED_CUSTOM_IMAGE].item', 'STORED_CUSTOM_IMAGE'),
            ('costScope[STORED_CUSTOM_IMAGE].planLineItem', True),
            ('costScope[STORED_CUSTOM_IMAGE].requiredBy', 'THIS_RECIPE'),
        ],
        'DESIGN.r7.md 473-479 (teardown); B-LHA-1 (step 16 reworded); runbook step 16 (DESIGN.r7.md 500)': [
            ('teardown.governedBy', 'THE_PLAN'),
            ('teardown.first', 'THE_EXPORT_AT_RUNBOOK_STEP_15'),
            ('teardown.deletes[*]', ['BOTH_INSTANCES_AND_THEIR_DISKS', 'CUSTOM_IMAGE', 'ANY_BUILD_DISK_LEFT']),
            ('teardown.privateHalvesEndWith', 'INSTANCE_AND_DISK_DELETION'),
            ('teardown.check', 'TEARDOWN_REPORT_ZERO_COUNTS'),
            ('teardown.bindingsRevokedBy', 'OWNER_ADMIN'),
        ],
        'runbook step 1 (DESIGN.r7.md 485)': [
            ('runbook[PREPARE_OR_CONFIRM_THE_RUN_PROJECT].step', 1),
            ('runbook[PREPARE_OR_CONFIRM_THE_RUN_PROJECT].id', 'PREPARE_OR_CONFIRM_THE_RUN_PROJECT'),
            ('runbook[PREPARE_OR_CONFIRM_THE_RUN_PROJECT].cloudActionsBy', 'OWNER_ADMIN'),
            ('runbook[PREPARE_OR_CONFIRM_THE_RUN_PROJECT].onHost', 'NONE'),
            ('runbook[PREPARE_OR_CONFIRM_THE_RUN_PROJECT].check',
             "The plan's sha256 approved with every costScope line item; the lease active; no compute present; the "
             "custom role's id (the real id in the owner-held plan, the role label in every published rendering) and "
             'its exact permission list recorded in the plan; the owner confirms the baseline holds no basic role and '
             'that no binding grants OWNER_LOGIN compute.instances.osAdminLogin or an IAM-changing permission, and '
             'OWNER_ADMIN no login permission.'),
        ],
        'runbook step 2 (DESIGN.r7.md 486); B-LHA-15 (OWNER_ADMIN performs its cloud actions)': [
            ('runbook[VPC_AND_FIREWALL].step', 2),
            ('runbook[VPC_AND_FIREWALL].id', 'VPC_AND_FIREWALL'),
            ('runbook[VPC_AND_FIREWALL].cloudActionsBy', 'OWNER_ADMIN'),
            ('runbook[VPC_AND_FIREWALL].onHost', 'NONE'),
            ('runbook[VPC_AND_FIREWALL].check',
             'Firewall and route listing: ingress IAP tcp 22 only, F1 and F2 only, the deny-all egress rule and the '
             "window's allow rule above it; no NAT; Private Google Access off."),
        ],
        'runbook step 3 (DESIGN.r7.md 487); B-LHA-15 (OWNER_ADMIN performs its cloud actions)': [
            ('runbook[CREATE_THE_CLUSTER_NODE].step', 3),
            ('runbook[CREATE_THE_CLUSTER_NODE].id', 'CREATE_THE_CLUSTER_NODE'),
            ('runbook[CREATE_THE_CLUSTER_NODE].cloudActionsBy', 'OWNER_ADMIN'),
            ('runbook[CREATE_THE_CLUSTER_NODE].onHost', 'NONE'),
            ('runbook[CREATE_THE_CLUSTER_NODE].check',
             "The node's metadata keys and refusals; no service account; Shielded VM; serial off; guest-agent "
             'features; maximum run duration.'),
        ],
        'runbook step 4 (DESIGN.r7.md 488)': [
            ('runbook[SETUP_WINDOW_BUILD].step', 4),
            ('runbook[SETUP_WINDOW_BUILD].id', 'SETUP_WINDOW_BUILD'),
            ('runbook[SETUP_WINDOW_BUILD].cloudActionsBy', 'NONE'),
            ('runbook[SETUP_WINDOW_BUILD].onHost', 'OWNER_LOGIN_WITH_ADMIN'),
            ('runbook[SETUP_WINDOW_BUILD].check',
             "Every digest matches; the built root verified against the pinned image's inventory; bytes under the "
             'ceiling.'),
        ],
        'runbook step 5 (DESIGN.r7.md 489); B-LHA-15 (OWNER_ADMIN performs its cloud actions)': [
            ('runbook[IMAGE_INVENTORY_CUSTOM_IMAGE_AND_PROXY_HOST].step', 5),
            ('runbook[IMAGE_INVENTORY_CUSTOM_IMAGE_AND_PROXY_HOST].id', 'IMAGE_INVENTORY_CUSTOM_IMAGE_AND_PROXY_HOST'),
            ('runbook[IMAGE_INVENTORY_CUSTOM_IMAGE_AND_PROXY_HOST].cloudActionsBy', 'OWNER_ADMIN'),
            ('runbook[IMAGE_INVENTORY_CUSTOM_IMAGE_AND_PROXY_HOST].onHost', 'OWNER_LOGIN_WITH_ADMIN'),
            ('runbook[IMAGE_INVENTORY_CUSTOM_IMAGE_AND_PROXY_HOST].check',
             'imageDigest recorded and recomputed off host; the kernel release checked in the built root; the build '
             "disk gone; the proxy/operator host booted from the recorded image; step 3's checks repeated on it."),
        ],
        'runbook step 6 (DESIGN.r7.md 490); B-LHA-15 (OWNER_ADMIN performs its cloud actions)': [
            ('runbook[CLOSE_EGRESS].step', 6),
            ('runbook[CLOSE_EGRESS].id', 'CLOSE_EGRESS'),
            ('runbook[CLOSE_EGRESS].cloudActionsBy', 'OWNER_ADMIN'),
            ('runbook[CLOSE_EGRESS].onHost', 'NONE'),
            ('runbook[CLOSE_EGRESS].check',
             "Refusal probes (expected exceptions: the metadata address, F1, F2); the observer's listing."),
        ],
        'runbook step 7 (DESIGN.r7.md 491)': [
            ('runbook[EXTERNAL_OPERATOR_INSTALLATION].step', 7),
            ('runbook[EXTERNAL_OPERATOR_INSTALLATION].id', 'EXTERNAL_OPERATOR_INSTALLATION'),
            ('runbook[EXTERNAL_OPERATOR_INSTALLATION].cloudActionsBy', 'NONE'),
            ('runbook[EXTERNAL_OPERATOR_INSTALLATION].onHost', 'OWNER_LOGIN_WITH_ADMIN'),
            ('runbook[EXTERNAL_OPERATOR_INSTALLATION].check',
             "Each component's own install check (elsewhere); the node's LOCAL_REGISTRY trust file installed."),
        ],
        'runbook step 8 (DESIGN.r7.md 492)': [
            ('runbook[LAUNCHERS_UNITS_KEYS_AND_REQUESTS].step', 8),
            ('runbook[LAUNCHERS_UNITS_KEYS_AND_REQUESTS].id', 'LAUNCHERS_UNITS_KEYS_AND_REQUESTS'),
            ('runbook[LAUNCHERS_UNITS_KEYS_AND_REQUESTS].cloudActionsBy', 'NONE'),
            ('runbook[LAUNCHERS_UNITS_KEYS_AND_REQUESTS].onHost', 'OWNER_LOGIN_WITH_ADMIN'),
            ('runbook[LAUNCHERS_UNITS_KEYS_AND_REQUESTS].check',
             "Modes, owners and digests as launcher-install.json lists; the requests exported; the cluster CA's "
             'KUBERNETES_PROXY_SERVER_MTLS leaf installed and RBAC bound to its exact subject.'),
        ],
        'runbook step 9 (DESIGN.r7.md 493)': [
            ('runbook[FREEZE_INVENTORIES_AND_ROOT_ALIAS_CHECK].step', 9),
            ('runbook[FREEZE_INVENTORIES_AND_ROOT_ALIAS_CHECK].id', 'FREEZE_INVENTORIES_AND_ROOT_ALIAS_CHECK'),
            ('runbook[FREEZE_INVENTORIES_AND_ROOT_ALIAS_CHECK].cloudActionsBy', 'NONE'),
            ('runbook[FREEZE_INVENTORIES_AND_ROOT_ALIAS_CHECK].onHost', 'OWNER_LOGIN_WITH_ADMIN'),
            ('runbook[FREEZE_INVENTORIES_AND_ROOT_ALIAS_CHECK].check',
             'The inventories and both boot event logs exported; the root-alias check PASS, or stop.'),
        ],
        'runbook step 10 (DESIGN.r7.md 494)': [
            ('runbook[T1_INSTALL_AND_REVOKE].step', 10),
            ('runbook[T1_INSTALL_AND_REVOKE].id', 'T1_INSTALL_AND_REVOKE'),
            ('runbook[T1_INSTALL_AND_REVOKE].cloudActionsBy', 'OWNER_ADMIN'),
            ('runbook[T1_INSTALL_AND_REVOKE].onHost', 'OWNER_LOGIN_WITH_ADMIN'),
            ('runbook[T1_INSTALL_AND_REVOKE].check',
             'The signatures verify; the bundle digests recorded; after propagation the effective checks pass and the '
             "custom role's permission list equals the plan's; every admin session on both hosts ended."),
        ],
        'runbook step 11 (DESIGN.r7.md 495)': [
            ('runbook[PREFLIGHT].step', 11),
            ('runbook[PREFLIGHT].id', 'PREFLIGHT'),
            ('runbook[PREFLIGHT].cloudActionsBy', 'NONE'),
            ('runbook[PREFLIGHT].onHost', 'OWNER_LOGIN_WITHOUT_ADMIN'),
            ('runbook[PREFLIGHT].check',
             'HOST_ISOLATION_NEGATIVES records; boot_id, kernel and notes digest recorded; the labels compared.'),
        ],
        'runbook step 12 (DESIGN.r7.md 496)': [
            ('runbook[T2].step', 12),
            ('runbook[T2].id', 'T2'),
            ('runbook[T2].cloudActionsBy', 'NONE'),
            ('runbook[T2].onHost', 'OWNER_OFF_HOST'),
            ('runbook[T2].check',
             "Every signature verifies; T2 ends within the hour; the envelope's bundle digests equal the installed "
             'bytes.'),
        ],
        'runbook step 13 (DESIGN.r7.md 497)': [
            ('runbook[DROP].step', 13),
            ('runbook[DROP].id', 'DROP'),
            ('runbook[DROP].cloudActionsBy', 'NONE'),
            ('runbook[DROP].onHost', 'OWNER_LOGIN_WITHOUT_ADMIN'),
            ('runbook[DROP].check', "The installer's log; the launchers' own verification."),
        ],
        'runbook step 14 (DESIGN.r7.md 498)': [
            ('runbook[CAMPAIGN].step', 14),
            ('runbook[CAMPAIGN].id', 'CAMPAIGN'),
            ('runbook[CAMPAIGN].cloudActionsBy', 'NONE'),
            ('runbook[CAMPAIGN].onHost', 'OUT_OF_THIS_PACKET'),
            ('runbook[CAMPAIGN].check', 'Out of this packet: inside the lease and the 168-hour window.'),
        ],
        'runbook step 15 (DESIGN.r7.md 499)': [
            ('runbook[RECHECK_AND_EXPORT].step', 15),
            ('runbook[RECHECK_AND_EXPORT].id', 'RECHECK_AND_EXPORT'),
            ('runbook[RECHECK_AND_EXPORT].cloudActionsBy', 'NONE'),
            ('runbook[RECHECK_AND_EXPORT].onHost', 'OWNER_LOGIN_WITHOUT_ADMIN'),
            ('runbook[RECHECK_AND_EXPORT].check',
             "The effective re-check and the audit-log check pass, or the run's evidence is refused; export digests "
             "in the owner's custody."),
        ],
        'runbook step 16 (DESIGN.r7.md 500); B-LHA-15 (OWNER_ADMIN performs its cloud actions)': [
            ('runbook[TEARDOWN].step', 16),
            ('runbook[TEARDOWN].id', 'TEARDOWN'),
            ('runbook[TEARDOWN].cloudActionsBy', 'OWNER_ADMIN'),
            ('runbook[TEARDOWN].onHost', 'NONE'),
            ('runbook[TEARDOWN].check',
             "The plan's teardown report with zero counts; the audit-log check closes after teardown completes."),
        ],
    },
    'launcher': {
        "DESIGN.r7.md 130 (the record's schema version)": [
            ('schemaVersion', 'planeon.internal.linux-launcher-install/v1'),
        ],
        'DESIGN.r7.md 1 (MET-LINUX-008, LINUX-HOST-AUTH-001)': [
            ('packet', 'MET-LINUX-008'),
            ('item', 'LINUX-HOST-AUTH-001'),
        ],
        'DESIGN.r7.md 835 (no GCP project, VM, key or spend exists or is created by this packet: data checks only)': [
            ('evidenceClass', 'DATA_CHECK_ONLY'),
        ],
        'DESIGN.r7.md 504 (each step is an operator duty; the repository never installs anything)': [
            ('repositoryInstalls', False),
        ],
        ("B-LHA-1 (the policy's operatorUid named, its POSIX name and UID unpublished); runbook step 8 (DESIGN.r7.md "
         '492)'): [
            ('operatorUid.label', 'OPERATOR_UID'),
            ('operatorUid.kind', 'DEDICATED_NON_ROOT_LOCAL_ACCOUNT'),
            ('operatorUid.createdAtStep', 8),
            ('operatorUid.createdBy', 'OWNER_LOGIN_WITH_ADMIN'),
            ('operatorUid.isTheLoginIdentityAccount', False),
            ('operatorUid.nameAndUidPublished', False),
            ('operatorUid.boundIn', 'THE_OFFLINE_POLICY_OPERATOR_UID_AND_OPERATOR_NAME'),
        ],
        'B-LHA-1 (trigger units a login without admin starts); DESIGN.r7.md 514': [
            ('loginTriggerGroup.label', 'PLANEON_LOGIN_TRIGGER'),
            ('loginTriggerGroup.members[*]', ['OWNER_LOGIN']),
            ('loginTriggerGroup.setAtStep', 8),
            ('loginTriggerGroup.excludes[*]', ['OPERATOR_UID']),
            ('loginTriggerGroup.nameAndGidPublished', False),
        ],
        'DESIGN.r7.md 506-522 (the signed-drop installer); MON-LHA-12R; MON-LHA3-1-2': [
            ('signedDropInstaller.component', 'A_REVIEWED_ROOT_COMPONENT_OF_THIS_PACKET'),
            ('signedDropInstaller.units[*]', ['planeon-drop-installer.path', 'planeon-drop-installer.service']),
            ('signedDropInstaller.helper', '/opt/planeon/bin/planeon-signed-drop-install'),
            ('signedDropInstaller.unitDirectory', '/etc/systemd/system'),
            ('signedDropInstaller.installedAtStep', 8),
            ('signedDropInstaller.inHostInventory', True),
            ('signedDropInstaller.runsAs', 'ROOT'),
            ('signedDropInstaller.operatorArguments', False),
            ('signedDropInstaller.startedBy', 'A_WRITE_BY_OWNER_LOGIN_INTO_THE_DROP_DIRECTORY'),
            ('signedDropInstaller.verifier', 'KIT_ED25519_VERIFY_ONLY'),
            ('signedDropInstaller.newCryptography', False),
            ('signedDropInstaller.certificateChainMode', False),
            ('signedDropInstaller.verifies', 'THE_DROP_MANIFEST_DETACHED_SIGNATURE'),
            ('signedDropInstaller.publicKey', '/etc/planeon/harness-runner-manifest.pub'),
            ('signedDropInstaller.signer', 'LINUX_RUNNER_MANIFEST'),
            ('signedDropInstaller.refusesEverythingElse', True),
            ('signedDropInstaller.logsEveryAttempt', '/var/log/planeon/signed-drop-installer.log'),
            ('signedDropInstaller.certificateValidityCheckedBy', 'THE_CONSUMING_COMPONENTS'),
            ('signedDropInstaller.consumersReadTheirTargets',
             'AT_THE_LISTED_PATHS_THEIR_START_ON_PICKUP_IS_THEIR_OWNERS'),
        ],
        'B-LHA-4 (a drop directory or parent chain not as specified is refused); DESIGN.r7.md 514': [
            ('signedDropInstaller.dropDirectory.path', '/var/lib/planeon/drop'),
            ('signedDropInstaller.dropDirectory.owner', 'ROOT'),
            ('signedDropInstaller.dropDirectory.group', 'PLANEON_LOGIN_TRIGGER'),
            ('signedDropInstaller.dropDirectory.mode', '1730'),
            ('signedDropInstaller.dropDirectory.parentChain', 'ROOT_OWNED_NOT_GROUP_OR_WORLD_WRITABLE'),
            ('signedDropInstaller.dropDirectory.otherwiseRefused', True),
        ],
        'B-LHA-4 (a copy into a root-owned staging directory)': [
            ('signedDropInstaller.stagingDirectory.path', '/var/lib/planeon/drop-staging'),
            ('signedDropInstaller.stagingDirectory.owner', 'ROOT'),
            ('signedDropInstaller.stagingDirectory.group', 'ROOT'),
            ('signedDropInstaller.stagingDirectory.mode', '0700'),
        ],
        'B-LHA-4 (the drop manifest)': [
            ('signedDropInstaller.dropManifest.schemaId', 'planeon.internal.linux-drop-manifest/v1'),
            ('signedDropInstaller.dropManifest.schema', 'architecture/linux-host-authority/drop-manifest.schema.json'),
            ('signedDropInstaller.dropManifest.signaturePayload', 'UTF8_SCHEMA_ID_THEN_0x00_THEN_EXACT_BYTES'),
            ('signedDropInstaller.dropManifest.formedAs', 'THE_POLICY_SIGNATURE'),
            ('signedDropInstaller.dropManifest.binds[*]',
             ['PLAN_SHA256', 'INSTANCE_IDENTITY', 'STEP_11_BOOT_ID', 'VALIDITY_WINDOW_ENDING_NO_LATER_THAN_THE_LEASE']),
            ('signedDropInstaller.dropManifest.refuses[*]',
             ['harness.planeon.ai/trusted-runner-manifest/v1alpha1', 'planeon.linux-runner-policy/v3']),
            ('signedDropInstaller.dropManifest.authorizes', 'PLACEMENT_ONLY'),
        ],
        'DESIGN.r7.md 514-518 (the install rule); B-LHA-4': [
            ('signedDropInstaller.installsOnlyIf[*]',
             ['DROP_MANIFEST_VERIFIES',
              'MANIFEST_LISTS_EXACT_TARGET_AND_SHA256',
              'TARGET_AND_MODE_ON_THE_FIXED_LIST',
              'BINDINGS_MATCH_THIS_HOST_BOOT_AND_WINDOW']),
        ],
        "B-LHA-4 (the installer's file handling)": [
            ('signedDropInstaller.fileHandling[*]',
             ['REGULAR_FILES_ONLY',
              'NO_FOLLOW_OPENS',
              'NO_HARDLINKS',
              'COPY_INTO_ROOT_OWNED_STAGING',
              'SHA256_OVER_THE_STAGED_COPY',
              'ATOMIC_RENAME_INTO_THE_TARGET',
              'OWNER_AND_MODE_FROM_THE_FIXED_LIST']),
        ],
        "DESIGN.r7.md 519-520 (the fixed list); B-LHA-5 (each target's exact path and mode)": [
            ('signedDropInstaller.fixedTargets[CAMPAIGN_PROXY_SERVER_TLS_CERTIFICATE].id',
             'CAMPAIGN_PROXY_SERVER_TLS_CERTIFICATE'),
            ('signedDropInstaller.fixedTargets[CAMPAIGN_PROXY_SERVER_TLS_CERTIFICATE].path',
             '/etc/planeon/credentials/campaign-proxy-server-tls.crt.pem'),
            ('signedDropInstaller.fixedTargets[CAMPAIGN_PROXY_SERVER_TLS_CERTIFICATE].owner', 'ROOT'),
            ('signedDropInstaller.fixedTargets[CAMPAIGN_PROXY_SERVER_TLS_CERTIFICATE].mode', '0444'),
            ('signedDropInstaller.fixedTargets[CAMPAIGN_PROXY_SERVER_TLS_CERTIFICATE].identity',
             'CAMPAIGN_PROXY_SERVER_TLS'),
            ('signedDropInstaller.fixedTargets[CAMPAIGN_PROXY_SERVER_TLS_CERTIFICATE].readBy', 'THE_PROXY_SERVER'),
            ('signedDropInstaller.fixedTargets[CAMPAIGN_PROXY_SERVER_TLS_CERTIFICATE].state', 'ACTIVE'),
            ('signedDropInstaller.fixedTargets[CAMPAIGN_PROXY_CLIENT_MTLS_CERTIFICATE].id',
             'CAMPAIGN_PROXY_CLIENT_MTLS_CERTIFICATE'),
            ('signedDropInstaller.fixedTargets[CAMPAIGN_PROXY_CLIENT_MTLS_CERTIFICATE].path',
             '/etc/planeon/credentials/campaign-proxy-client-mtls.crt.pem'),
            ('signedDropInstaller.fixedTargets[CAMPAIGN_PROXY_CLIENT_MTLS_CERTIFICATE].owner', 'ROOT'),
            ('signedDropInstaller.fixedTargets[CAMPAIGN_PROXY_CLIENT_MTLS_CERTIFICATE].mode', '0444'),
            ('signedDropInstaller.fixedTargets[CAMPAIGN_PROXY_CLIENT_MTLS_CERTIFICATE].identity',
             'CAMPAIGN_PROXY_CLIENT_MTLS'),
            ('signedDropInstaller.fixedTargets[CAMPAIGN_PROXY_CLIENT_MTLS_CERTIFICATE].readBy', 'THE_PROXY_CLIENT'),
            ('signedDropInstaller.fixedTargets[CAMPAIGN_PROXY_CLIENT_MTLS_CERTIFICATE].state', 'ACTIVE'),
            ('signedDropInstaller.fixedTargets[OFFLINE_MANIFEST].id', 'OFFLINE_MANIFEST'),
            ('signedDropInstaller.fixedTargets[OFFLINE_MANIFEST].path', '/etc/planeon/harness-runner-manifest.json'),
            ('signedDropInstaller.fixedTargets[OFFLINE_MANIFEST].owner', 'ROOT'),
            ('signedDropInstaller.fixedTargets[OFFLINE_MANIFEST].mode', '0444'),
            ('signedDropInstaller.fixedTargets[OFFLINE_MANIFEST].identity', 'NONE'),
            ('signedDropInstaller.fixedTargets[OFFLINE_MANIFEST].readBy', 'THE_OFFLINE_LAUNCHER'),
            ('signedDropInstaller.fixedTargets[OFFLINE_MANIFEST].state', 'ACTIVE'),
            ('signedDropInstaller.fixedTargets[OFFLINE_MANIFEST_SIGNATURE].id', 'OFFLINE_MANIFEST_SIGNATURE'),
            ('signedDropInstaller.fixedTargets[OFFLINE_MANIFEST_SIGNATURE].path',
             '/etc/planeon/harness-runner-manifest.json.sig'),
            ('signedDropInstaller.fixedTargets[OFFLINE_MANIFEST_SIGNATURE].owner', 'ROOT'),
            ('signedDropInstaller.fixedTargets[OFFLINE_MANIFEST_SIGNATURE].mode', '0444'),
            ('signedDropInstaller.fixedTargets[OFFLINE_MANIFEST_SIGNATURE].identity', 'NONE'),
            ('signedDropInstaller.fixedTargets[OFFLINE_MANIFEST_SIGNATURE].readBy', 'THE_OFFLINE_LAUNCHER'),
            ('signedDropInstaller.fixedTargets[OFFLINE_MANIFEST_SIGNATURE].state', 'ACTIVE'),
            ('signedDropInstaller.fixedTargets[LIVE_MANIFEST].id', 'LIVE_MANIFEST'),
            ('signedDropInstaller.fixedTargets[LIVE_MANIFEST].path', '/etc/planeon/harness-live-runner-manifest.json'),
            ('signedDropInstaller.fixedTargets[LIVE_MANIFEST].owner', 'ROOT'),
            ('signedDropInstaller.fixedTargets[LIVE_MANIFEST].mode', '0444'),
            ('signedDropInstaller.fixedTargets[LIVE_MANIFEST].identity', 'NONE'),
            ('signedDropInstaller.fixedTargets[LIVE_MANIFEST].readBy', 'THE_LIVE_LAUNCHER'),
            ('signedDropInstaller.fixedTargets[LIVE_MANIFEST].state', 'AFTER_CONF_LIVE_005_006_CLOSE'),
            ('signedDropInstaller.fixedTargets[LIVE_MANIFEST_SIGNATURE].id', 'LIVE_MANIFEST_SIGNATURE'),
            ('signedDropInstaller.fixedTargets[LIVE_MANIFEST_SIGNATURE].path',
             '/etc/planeon/harness-live-runner-manifest.json.sig'),
            ('signedDropInstaller.fixedTargets[LIVE_MANIFEST_SIGNATURE].owner', 'ROOT'),
            ('signedDropInstaller.fixedTargets[LIVE_MANIFEST_SIGNATURE].mode', '0444'),
            ('signedDropInstaller.fixedTargets[LIVE_MANIFEST_SIGNATURE].identity', 'NONE'),
            ('signedDropInstaller.fixedTargets[LIVE_MANIFEST_SIGNATURE].readBy', 'THE_LIVE_LAUNCHER'),
            ('signedDropInstaller.fixedTargets[LIVE_MANIFEST_SIGNATURE].state', 'AFTER_CONF_LIVE_005_006_CLOSE'),
        ],
        'B-LHA-1 (one reviewed family of trigger units; MON-LHA-B1)': [
            ('triggerUnits[PREFLIGHT_UNIT].id', 'PREFLIGHT_UNIT'),
            ('triggerUnits[PREFLIGHT_UNIT].hosts[*]', ['PROXY_OPERATOR_HOST']),
            ('triggerUnits[PREFLIGHT_UNIT].units[*]', ['planeon-preflight.path', 'planeon-preflight.service']),
            ('triggerUnits[PREFLIGHT_UNIT].trigger.kind', 'PATH_UNIT'),
            ('triggerUnits[PREFLIGHT_UNIT].trigger.path', '/var/lib/planeon/trigger/preflight'),
            ('triggerUnits[PREFLIGHT_UNIT].trigger.directory', '/var/lib/planeon/trigger'),
            ('triggerUnits[PREFLIGHT_UNIT].trigger.owner', 'ROOT'),
            ('triggerUnits[PREFLIGHT_UNIT].trigger.group', 'PLANEON_LOGIN_TRIGGER'),
            ('triggerUnits[PREFLIGHT_UNIT].trigger.mode', '1730'),
            ('triggerUnits[PREFLIGHT_UNIT].command', '/opt/planeon/bin/harness-offline-launch --operator-preflight'),
            ('triggerUnits[PREFLIGHT_UNIT].runsAs', 'OPERATOR_UID'),
            ('triggerUnits[PREFLIGHT_UNIT].startedBy', 'OWNER_LOGIN_WRITES_THE_TRIGGER_FILE'),
            ('triggerUnits[PREFLIGHT_UNIT].writes[*]', ['PREFLIGHT_RECORDS', 'JOURNAL']),
            ('triggerUnits[PREFLIGHT_UNIT].deliversToTheLogin', 'THROUGH_THE_EXPORT_UNIT'),
            ('triggerUnits[PREFLIGHT_UNIT].operatorArguments', False),
            ('triggerUnits[PREFLIGHT_UNIT].readsTriggerContent', False),
            ('triggerUnits[PREFLIGHT_UNIT].installedAtStep', 8),
            ('triggerUnits[PREFLIGHT_UNIT].inHostInventory', True),
            ('triggerUnits[PREFLIGHT_UNIT].unitDirectory', '/etc/systemd/system'),
            ('triggerUnits[EXPORT_UNIT].id', 'EXPORT_UNIT'),
            ('triggerUnits[EXPORT_UNIT].hosts[*]', ['PROXY_OPERATOR_HOST', 'CLUSTER_NODE']),
            ('triggerUnits[EXPORT_UNIT].units[*]', ['planeon-export.socket', 'planeon-export.service']),
            ('triggerUnits[EXPORT_UNIT].trigger.kind', 'SOCKET_UNIT'),
            ('triggerUnits[EXPORT_UNIT].trigger.path', '/run/planeon/export.sock'),
            ('triggerUnits[EXPORT_UNIT].trigger.directory', '/run/planeon'),
            ('triggerUnits[EXPORT_UNIT].trigger.owner', 'ROOT'),
            ('triggerUnits[EXPORT_UNIT].trigger.group', 'PLANEON_LOGIN_TRIGGER'),
            ('triggerUnits[EXPORT_UNIT].trigger.mode', '0660'),
            ('triggerUnits[EXPORT_UNIT].command', '/opt/planeon/bin/planeon-export'),
            ('triggerUnits[EXPORT_UNIT].runsAs', 'ROOT'),
            ('triggerUnits[EXPORT_UNIT].startedBy', 'OWNER_LOGIN_CONNECTS_TO_THE_SOCKET'),
            ('triggerUnits[EXPORT_UNIT].writes[*]', ['JOURNAL']),
            ('triggerUnits[EXPORT_UNIT].deliversToTheLogin', 'THE_FIXED_EXPORT_SET_STREAMED_OVER_THE_ONE_CONNECTION'),
            ('triggerUnits[EXPORT_UNIT].operatorArguments', False),
            ('triggerUnits[EXPORT_UNIT].readsTriggerContent', False),
            ('triggerUnits[EXPORT_UNIT].installedAtStep', 8),
            ('triggerUnits[EXPORT_UNIT].inHostInventory', True),
            ('triggerUnits[EXPORT_UNIT].unitDirectory', '/etc/systemd/system'),
        ],
        "B-LHA-1 (each privileged action's UID and how a login without admin starts it)": [
            ('privilegedActions[STEP_11_PREFLIGHT].action', 'STEP_11_PREFLIGHT'),
            ('privilegedActions[STEP_11_PREFLIGHT].runsAs', 'OPERATOR_UID'),
            ('privilegedActions[STEP_11_PREFLIGHT].startedBy', 'PREFLIGHT_UNIT'),
            ('privilegedActions[STEP_11_PREFLIGHT].loginNeedsAdmin', False),
            ('privilegedActions[STEP_13_PICKUP].action', 'STEP_13_PICKUP'),
            ('privilegedActions[STEP_13_PICKUP].runsAs', 'ROOT'),
            ('privilegedActions[STEP_13_PICKUP].startedBy', 'SIGNED_DROP_INSTALLER'),
            ('privilegedActions[STEP_13_PICKUP].loginNeedsAdmin', False),
            ('privilegedActions[STEP_14_LAUNCH].action', 'STEP_14_LAUNCH'),
            ('privilegedActions[STEP_14_LAUNCH].runsAs', 'PER_CONF_LIVE_005_006'),
            ('privilegedActions[STEP_14_LAUNCH].startedBy', 'CONF_LIVE_005_006_NON_ADMIN_ENTRY_PATH_PRECONDITION'),
            ('privilegedActions[STEP_14_LAUNCH].loginNeedsAdmin', False),
            ('privilegedActions[STEP_15_EXPORT].action', 'STEP_15_EXPORT'),
            ('privilegedActions[STEP_15_EXPORT].runsAs', 'ROOT'),
            ('privilegedActions[STEP_15_EXPORT].startedBy', 'EXPORT_UNIT'),
            ('privilegedActions[STEP_15_EXPORT].loginNeedsAdmin', False),
        ],
        'B-LHA-1 (every root-only record has a read path at step 15); runbook step 15 (DESIGN.r7.md 499)': [
            ('exportSet[PROXY_OPERATOR_HOST].host', 'PROXY_OPERATOR_HOST'),
            ('exportSet[PROXY_OPERATOR_HOST].records[*]',
             ['HOST_NONCE_LEDGER',
              'PREFLIGHT_RECORDS',
              'HOST_INVENTORY',
              'INSTALLER_LOG',
              'JOURNAL',
              'EVIDENCE_SINK_RECORDS']),
            ('exportSet[CLUSTER_NODE].host', 'CLUSTER_NODE'),
            ('exportSet[CLUSTER_NODE].records[*]', ['HOST_INVENTORY', 'JOURNAL', 'CLUSTER_STATE_LISTING']),
        ],
        'DESIGN.r7.md 524-543 (the offline launcher); Q-LHA-10 (a)': [
            ('offlineLauncher.path', '/opt/planeon/bin/harness-offline-launch'),
            ('offlineLauncher.kit', 'MET-LINUX-005'),
            ('offlineLauncher.owner', 'ROOT'),
            ('offlineLauncher.fileMode', '0555'),
            ('offlineLauncher.mode', 'OPERATOR_PREFLIGHT_ONLY'),
            ('offlineLauncher.evidence', 'HOST_ISOLATION_ONLY'),
            ('offlineLauncher.githubRunnerRegistered', False),
            ('offlineLauncher.ciCapacityExceptionApplies', False),
            ('offlineLauncher.trustAnchor', 'THE_NEW_LINUX_RUNNER_KEY'),
            ('offlineLauncher.publicKey', '/etc/planeon/harness-runner-manifest.pub'),
            ('offlineLauncher.rootAliasRecord', '/etc/planeon/linux-runner/root-aliases.json'),
            ('offlineLauncher.policySigner', 'LINUX_RUNNER_MANIFEST'),
            ('offlineLauncher.manifestSigner', 'LINUX_RUNNER_MANIFEST'),
            ('offlineLauncher.manifestSignedAt', 'T2_AFTER_STEP_11_PREFLIGHT'),
            ('offlineLauncher.operatorMdApplies[*]', ['LAYOUT_CHECKS', 'WORK_SIBLINGS_AND_SENTINEL']),
            ('offlineLauncher.operatorMdDoesNotApply[*]', ['RUNNER_SETTINGS', 'RUNNER_BINARY_CHECK']),
            ('offlineLauncher.operatorSteps', 'OPERATOR_MD_STEPS_1_TO_6_WITH_THE_NEW_LINUX_RUNNER_KEY'),
            ('offlineLauncher.rollback', 'TEARDOWN'),
        ],
        'DESIGN.r7.md 536-537 (custody.json, written at step 10); runbook step 10 (DESIGN.r7.md 494)': [
            ('offlineLauncher.custody', '/etc/planeon/linux-runner/custody.json'),
        ],
        ('DESIGN.r7.md 536-537 (custody.json binds the public key and the launcher and policy digests); runbook step '
         '10 (DESIGN.r7.md 494)'): [
            ('offlineLauncher.custodyBinds[*]', ['PUBLIC_KEY', 'LAUNCHER_DIGEST', 'POLICY_DIGEST']),
        ],
        'DESIGN.r7.md 536-537; runbook step 10 (DESIGN.r7.md 494)': [
            ('offlineLauncher.custodyWrittenAtStep', 10),
        ],
        'DESIGN.r7.md 527-528 (it serves no normal invocation on this host); B-LHA-11': [
            ('offlineLauncher.manifestServesANormalInvocation', False),
        ],
        "DESIGN.r7.md 113-117 (the negative probes' scope), 495 (runbook step 11)": [
            ('offlineLauncher.preflightProbeScope[*]',
             ['PROXY_OPERATOR_HOST_CREDENTIALS',
              'PROXY_OPERATOR_HOST_SOCKETS',
              'TRIGGER_UNIT_ENDPOINTS',
              'NO_KUBECONFIG_OR_RUNTIME_SOCKET',
              'CLUSTER_NODE_REACHABLE_ONLY_ON_F1',
              'GUEST_AGENT_LOCAL_SOCKETS',
              'OS_LOGIN_LOCAL_SOCKETS',
              'METADATA_ADDRESS']),
        ],
        'DESIGN.r7.md 545-560 (the live launcher, design only); Q-LHA-7 (a); MON-LHA-B1': [
            ('liveLauncher.path', '/opt/planeon/bin/harness-live-campaign-launch'),
            ('liveLauncher.source', 'CONF_LIVE_005_PACKAGING_WITH_THE_CONF_LIVE_006_FINAL_HOOK'),
            ('liveLauncher.state', 'WAITING'),
            ('liveLauncher.designOnly', True),
            ('liveLauncher.owner', 'ROOT'),
            ('liveLauncher.mode', '0555'),
            ('liveLauncher.manifest', '/etc/planeon/harness-live-runner-manifest.json'),
            ('liveLauncher.signature', '/etc/planeon/harness-live-runner-manifest.json.sig'),
            ('liveLauncher.publicKey', '/etc/planeon/harness-live-runner-manifest.pub'),
            ('liveLauncher.manifestSigner', 'LIVE_RUNNER_MANIFEST'),
            ('liveLauncher.manifestSignedAfter', 'CONF_LIVE_005_006_OWN_PREFLIGHT'),
            ('liveLauncher.pinCheck', 'THE_INSTALLED_PIN_EQUALS_CUSTODY_MODEL'),
            ('liveLauncher.ifThePinIsEmbedded', 'THE_KEY_CEREMONY_COMES_BEFORE_THEIR_REPRODUCIBLE_BUILD'),
            ('liveLauncher.trustMounts[/etc/planeon/trust/release-trust-bundle.json].path',
             '/etc/planeon/trust/release-trust-bundle.json'),
            ('liveLauncher.trustMounts[/etc/planeon/trust/release-trust-bundle.json].readOnly', True),
            ('liveLauncher.trustMounts[/etc/planeon/trust/release-trust-bundle.json].owner', 'ROOT'),
            ('liveLauncher.trustMounts[/etc/planeon/trust/release-trust-bundle.json].mode', '0444'),
            ('liveLauncher.trustMounts[/etc/planeon/trust/release-trust-bundle.json].installedAtStep', 10),
            ('liveLauncher.trustMounts[/etc/planeon/trust/tenant-trust-bundle.json].path',
             '/etc/planeon/trust/tenant-trust-bundle.json'),
            ('liveLauncher.trustMounts[/etc/planeon/trust/tenant-trust-bundle.json].readOnly', True),
            ('liveLauncher.trustMounts[/etc/planeon/trust/tenant-trust-bundle.json].owner', 'ROOT'),
            ('liveLauncher.trustMounts[/etc/planeon/trust/tenant-trust-bundle.json].mode', '0444'),
            ('liveLauncher.trustMounts[/etc/planeon/trust/tenant-trust-bundle.json].installedAtStep', 10),
            ('liveLauncher.nonAdminEntryPath', 'PRECONDITION_ON_CONF_LIVE_005_006'),
        ],
        'DESIGN.r7.md 538-542 (which time limit binds each signed object); Q-LHA-2; B-LHA-11': [
            ('timeLimits.policyMaxHours', 24),
            ('timeLimits.policyFrom', 'T1'),
            ('timeLimits.manifestsSignedWithinHoursOfPreflight', 1),
            ('timeLimits.t2EndsWithinHoursOfPreflight', 1),
            ('timeLimits.operatorMdOneHourAge',
             'THE_LAUNCHER_CHECK_AT_A_NORMAL_INVOCATION_WHICH_THIS_HOST_DOES_NOT_MAKE'),
            ('timeLimits.envelopeAndCapacityAuthorization', 'THEIR_OWN_VALIDITY_WINDOWS'),
        ],
        ('DESIGN.r7.md 562-564 (each step names its input digests and its rollback), 543 (rollback means teardown); '
         'runbook steps 8 and 10 (DESIGN.r7.md 492, 494)'): [
            ('steps[INSTALL_OFFLINE_LAUNCHER_BYTES].id', 'INSTALL_OFFLINE_LAUNCHER_BYTES'),
            ('steps[INSTALL_OFFLINE_LAUNCHER_BYTES].runbookStep', 8),
            ('steps[INSTALL_OFFLINE_LAUNCHER_BYTES].duty', 'OPERATOR'),
            ('steps[INSTALL_OFFLINE_LAUNCHER_BYTES].inputDigests[*]', ['CANDIDATE_SHA256', 'KIT_INVENTORY_SHA256']),
            ('steps[INSTALL_OFFLINE_LAUNCHER_BYTES].rollback', 'TEARDOWN'),
            ('steps[INSTALL_OFFLINE_LAUNCHER_BYTES].movesTrustDigest', False),
            ('steps[INSTALL_OFFLINE_LAUNCHER_BYTES].state', 'ACTIVE'),
            ('steps[INSTALL_OPERATOR_MD_LAYOUT].id', 'INSTALL_OPERATOR_MD_LAYOUT'),
            ('steps[INSTALL_OPERATOR_MD_LAYOUT].runbookStep', 8),
            ('steps[INSTALL_OPERATOR_MD_LAYOUT].duty', 'OPERATOR'),
            ('steps[INSTALL_OPERATOR_MD_LAYOUT].inputDigests[*]', ['LAYOUT_LISTING_SHA256']),
            ('steps[INSTALL_OPERATOR_MD_LAYOUT].rollback', 'TEARDOWN'),
            ('steps[INSTALL_OPERATOR_MD_LAYOUT].movesTrustDigest', False),
            ('steps[INSTALL_OPERATOR_MD_LAYOUT].state', 'ACTIVE'),
            ('steps[CREATE_OPERATOR_UID_AND_TRIGGER_GROUP].id', 'CREATE_OPERATOR_UID_AND_TRIGGER_GROUP'),
            ('steps[CREATE_OPERATOR_UID_AND_TRIGGER_GROUP].runbookStep', 8),
            ('steps[CREATE_OPERATOR_UID_AND_TRIGGER_GROUP].duty', 'OPERATOR'),
            ('steps[CREATE_OPERATOR_UID_AND_TRIGGER_GROUP].inputDigests[*]', ['ACCOUNT_LISTING_SHA256']),
            ('steps[CREATE_OPERATOR_UID_AND_TRIGGER_GROUP].rollback', 'TEARDOWN'),
            ('steps[CREATE_OPERATOR_UID_AND_TRIGGER_GROUP].movesTrustDigest', False),
            ('steps[CREATE_OPERATOR_UID_AND_TRIGGER_GROUP].state', 'ACTIVE'),
            ('steps[INSTALL_SIGNED_DROP_INSTALLER].id', 'INSTALL_SIGNED_DROP_INSTALLER'),
            ('steps[INSTALL_SIGNED_DROP_INSTALLER].runbookStep', 8),
            ('steps[INSTALL_SIGNED_DROP_INSTALLER].duty', 'OPERATOR'),
            ('steps[INSTALL_SIGNED_DROP_INSTALLER].inputDigests[*]',
             ['INSTALLER_HELPER_SHA256', 'INSTALLER_UNITS_SHA256']),
            ('steps[INSTALL_SIGNED_DROP_INSTALLER].rollback', 'TEARDOWN'),
            ('steps[INSTALL_SIGNED_DROP_INSTALLER].movesTrustDigest', False),
            ('steps[INSTALL_SIGNED_DROP_INSTALLER].state', 'ACTIVE'),
            ('steps[INSTALL_TRIGGER_UNITS].id', 'INSTALL_TRIGGER_UNITS'),
            ('steps[INSTALL_TRIGGER_UNITS].runbookStep', 8),
            ('steps[INSTALL_TRIGGER_UNITS].duty', 'OPERATOR'),
            ('steps[INSTALL_TRIGGER_UNITS].inputDigests[*]', ['TRIGGER_UNITS_SHA256', 'EXPORT_HELPER_SHA256']),
            ('steps[INSTALL_TRIGGER_UNITS].rollback', 'TEARDOWN'),
            ('steps[INSTALL_TRIGGER_UNITS].movesTrustDigest', False),
            ('steps[INSTALL_TRIGGER_UNITS].state', 'ACTIVE'),
            ('steps[GENERATE_PRIVATE_HALVES_AND_REQUESTS].id', 'GENERATE_PRIVATE_HALVES_AND_REQUESTS'),
            ('steps[GENERATE_PRIVATE_HALVES_AND_REQUESTS].runbookStep', 8),
            ('steps[GENERATE_PRIVATE_HALVES_AND_REQUESTS].duty', 'OPERATOR'),
            ('steps[GENERATE_PRIVATE_HALVES_AND_REQUESTS].inputDigests[*]', ['REQUEST_SPKI_SHA256']),
            ('steps[GENERATE_PRIVATE_HALVES_AND_REQUESTS].rollback', 'TEARDOWN'),
            ('steps[GENERATE_PRIVATE_HALVES_AND_REQUESTS].movesTrustDigest', False),
            ('steps[GENERATE_PRIVATE_HALVES_AND_REQUESTS].state', 'ACTIVE'),
            ('steps[ISSUE_KUBERNETES_PROXY_SERVER_MTLS_FROM_THE_CLUSTER_CA].id',
             'ISSUE_KUBERNETES_PROXY_SERVER_MTLS_FROM_THE_CLUSTER_CA'),
            ('steps[ISSUE_KUBERNETES_PROXY_SERVER_MTLS_FROM_THE_CLUSTER_CA].runbookStep', 8),
            ('steps[ISSUE_KUBERNETES_PROXY_SERVER_MTLS_FROM_THE_CLUSTER_CA].duty', 'OPERATOR'),
            ('steps[ISSUE_KUBERNETES_PROXY_SERVER_MTLS_FROM_THE_CLUSTER_CA].inputDigests[*]',
             ['REQUEST_SPKI_SHA256', 'CLUSTER_CA_CERTIFICATE_SHA256']),
            ('steps[ISSUE_KUBERNETES_PROXY_SERVER_MTLS_FROM_THE_CLUSTER_CA].rollback', 'TEARDOWN'),
            ('steps[ISSUE_KUBERNETES_PROXY_SERVER_MTLS_FROM_THE_CLUSTER_CA].movesTrustDigest', False),
            ('steps[ISSUE_KUBERNETES_PROXY_SERVER_MTLS_FROM_THE_CLUSTER_CA].state', 'ACTIVE'),
            ('steps[INSTALL_POLICY_CUSTODY_BUNDLES_AND_REVOCATION].id',
             'INSTALL_POLICY_CUSTODY_BUNDLES_AND_REVOCATION'),
            ('steps[INSTALL_POLICY_CUSTODY_BUNDLES_AND_REVOCATION].runbookStep', 10),
            ('steps[INSTALL_POLICY_CUSTODY_BUNDLES_AND_REVOCATION].duty', 'OPERATOR'),
            ('steps[INSTALL_POLICY_CUSTODY_BUNDLES_AND_REVOCATION].inputDigests[*]',
             ['POLICY_SHA256', 'CUSTODY_SHA256', 'BUNDLE_SHA256', 'ROOT_ALIAS_RECORD_SHA256']),
            ('steps[INSTALL_POLICY_CUSTODY_BUNDLES_AND_REVOCATION].rollback', 'TEARDOWN'),
            ('steps[INSTALL_POLICY_CUSTODY_BUNDLES_AND_REVOCATION].movesTrustDigest', False),
            ('steps[INSTALL_POLICY_CUSTODY_BUNDLES_AND_REVOCATION].state', 'ACTIVE'),
            ('steps[DROP_CERTIFICATES_MANIFESTS_AND_SIGNATURES].id', 'DROP_CERTIFICATES_MANIFESTS_AND_SIGNATURES'),
            ('steps[DROP_CERTIFICATES_MANIFESTS_AND_SIGNATURES].runbookStep', 13),
            ('steps[DROP_CERTIFICATES_MANIFESTS_AND_SIGNATURES].duty', 'OPERATOR'),
            ('steps[DROP_CERTIFICATES_MANIFESTS_AND_SIGNATURES].inputDigests[*]', ['DROP_MANIFEST_SHA256']),
            ('steps[DROP_CERTIFICATES_MANIFESTS_AND_SIGNATURES].rollback', 'TEARDOWN'),
            ('steps[DROP_CERTIFICATES_MANIFESTS_AND_SIGNATURES].movesTrustDigest', False),
            ('steps[DROP_CERTIFICATES_MANIFESTS_AND_SIGNATURES].state', 'ACTIVE'),
            ('steps[INSTALL_LIVE_LAUNCHER].id', 'INSTALL_LIVE_LAUNCHER'),
            ('steps[INSTALL_LIVE_LAUNCHER].runbookStep', 8),
            ('steps[INSTALL_LIVE_LAUNCHER].duty', 'OPERATOR'),
            ('steps[INSTALL_LIVE_LAUNCHER].inputDigests[*]', ['CONF_LIVE_005_REPRODUCIBLE_BYTES_SHA256']),
            ('steps[INSTALL_LIVE_LAUNCHER].rollback', 'TEARDOWN'),
            ('steps[INSTALL_LIVE_LAUNCHER].movesTrustDigest', False),
            ('steps[INSTALL_LIVE_LAUNCHER].state', 'WAITING_FOR_CONF_LIVE_005_006'),
        ],
        'DESIGN.r7.md 562-568 (the launcher rules); B-LHA-5 (the preflight record retained and exported only)': [
            ('rules.newPolicyNeedsNewProbeEvidence', True),
            ('rules.noManifestBeforeItsPreflight', True),
            ('rules.noManifestByTheOtherLaunchersKey', True),
            ('rules.afterRevocationEtcPlaneonChangesOnlyThrough',
             'SIGNED_DROP_INSTALLER_UNDER_A_VERIFIED_DROP_MANIFEST'),
            ('rules.loginStartedWritesAfterRevocation', 'SIGNED_DROP_INSTALLER_ONLY'),
            ('rules.preflightRecord', 'RETAINED_AND_EXPORTED_ONLY'),
            ('rules.preflightRecordReason', 'NO_NORMAL_INVOCATION_READS_IT_WITHIN_MON_LHA3_1_2'),
        ],
    },
    'custody': {
        "DESIGN.r7.md 131 (the record's schema version)": [
            ('schemaVersion', 'planeon.internal.linux-key-custody/v1'),
        ],
        'DESIGN.r7.md 1 (MET-LINUX-008, LINUX-HOST-AUTH-001)': [
            ('packet', 'MET-LINUX-008'),
            ('item', 'LINUX-HOST-AUTH-001'),
        ],
        'DESIGN.r7.md 835 (no GCP project, VM, key or spend exists or is created by this packet: data checks only)': [
            ('evidenceClass', 'DATA_CHECK_ONLY'),
        ],
        "DESIGN.r7.md 631-638, 648-649 (one principal, with the disclosure and the owner's answer); Q-LHA-1 (a)": [
            ('principal.holder', 'OWNER'),
            ('principal.disclosure.signers', 'SINGLE_PRINCIPAL_SEPARATED_KEYS'),
            ('principal.decision', 'Q-LHA-1'),
        ],
        'DESIGN.r7.md 635, 648 (one owner principal); Q-LHA-1 (a)': [
            ('principal.count', 1),
        ],
        'DESIGN.r7.md 572-575, 578, 609-612 (LINUX_RUNNER_MANIFEST); Q-LHA-2 (a)': [
            ('authorities[LINUX_RUNNER_MANIFEST].id', 'LINUX_RUNNER_MANIFEST'),
            ('authorities[LINUX_RUNNER_MANIFEST].keyId', 'KEYID-LINUX-RUNNER-MANIFEST'),
            ('authorities[LINUX_RUNNER_MANIFEST].purpose', 'LINUX_RUNNER_MANIFEST'),
            ('authorities[LINUX_RUNNER_MANIFEST].algorithm', 'ED25519'),
            ('authorities[LINUX_RUNNER_MANIFEST].signs[*]', ['OFFLINE_POLICY', 'OFFLINE_MANIFEST', 'DROP_MANIFEST']),
            ('authorities[LINUX_RUNNER_MANIFEST].sessions[*]', ['T1', 'T2']),
            ('authorities[LINUX_RUNNER_MANIFEST].publicHalf', '/etc/planeon/harness-runner-manifest.pub'),
            ('authorities[LINUX_RUNNER_MANIFEST].cadence', 'PER_RUN_ONCE_IN_T1_TWICE_IN_T2'),
            ('authorities[LINUX_RUNNER_MANIFEST].holder', 'OWNER'),
            ('authorities[LINUX_RUNNER_MANIFEST].token', 'TOKEN-LINUX-RUNNER-MANIFEST'),
            ('authorities[LINUX_RUNNER_MANIFEST].sealedBackup', 'BACKUP-LINUX-RUNNER-MANIFEST'),
            ('authorities[LINUX_RUNNER_MANIFEST].generation', 'OFFLINE_ON_A_MACHINE_THAT_NEVER_CONNECTS'),
            ('authorities[LINUX_RUNNER_MANIFEST].storage', 'HARDWARE_TOKEN_WITH_ONE_SEALED_OFFLINE_BACKUP'),
            ('authorities[LINUX_RUNNER_MANIFEST].rotation', 'PER_RELEASE_OR_ON_COMPROMISE'),
            ('authorities[LINUX_RUNNER_MANIFEST].revocation', 'REVOKED_IN_THE_TRUST_BUNDLE_BY_LOCAL_CUSTODY_TRANSFER'),
            ('authorities[LINUX_RUNNER_MANIFEST].importCheckedAtCeremony', True),
            ('authorities[LINUX_RUNNER_MANIFEST].ceremony.state', 'PENDING_THE_POST_MERGE_KEY_CEREMONY'),
            ('authorities[LINUX_RUNNER_MANIFEST].ceremony.records[*]', ['PUBLIC_KEY_DIGEST', 'PURPOSE']),
            ('authorities[LINUX_RUNNER_MANIFEST].ceremony.privateBytes', False),
        ],
        'DESIGN.r7.md 572-575, 579, 609-612 (LIVE_RUNNER_MANIFEST); Q-LHA-2 (a)': [
            ('authorities[LIVE_RUNNER_MANIFEST].id', 'LIVE_RUNNER_MANIFEST'),
            ('authorities[LIVE_RUNNER_MANIFEST].keyId', 'KEYID-LIVE-RUNNER-MANIFEST'),
            ('authorities[LIVE_RUNNER_MANIFEST].purpose', 'LIVE_RUNNER_MANIFEST'),
            ('authorities[LIVE_RUNNER_MANIFEST].algorithm', 'ED25519'),
            ('authorities[LIVE_RUNNER_MANIFEST].signs[*]', ['LIVE_RUNNER_MANIFEST']),
            ('authorities[LIVE_RUNNER_MANIFEST].sessions[*]', ['T2']),
            ('authorities[LIVE_RUNNER_MANIFEST].publicHalf', '/etc/planeon/harness-live-runner-manifest.pub'),
            ('authorities[LIVE_RUNNER_MANIFEST].cadence', 'PER_RUN_IN_T2_ONLY_AFTER_CONF_LIVE_005_006_OWN_PREFLIGHT'),
            ('authorities[LIVE_RUNNER_MANIFEST].holder', 'OWNER'),
            ('authorities[LIVE_RUNNER_MANIFEST].token', 'TOKEN-LIVE-RUNNER-MANIFEST'),
            ('authorities[LIVE_RUNNER_MANIFEST].sealedBackup', 'BACKUP-LIVE-RUNNER-MANIFEST'),
            ('authorities[LIVE_RUNNER_MANIFEST].generation', 'OFFLINE_ON_A_MACHINE_THAT_NEVER_CONNECTS'),
            ('authorities[LIVE_RUNNER_MANIFEST].storage', 'HARDWARE_TOKEN_WITH_ONE_SEALED_OFFLINE_BACKUP'),
            ('authorities[LIVE_RUNNER_MANIFEST].rotation', 'PER_RELEASE_OR_ON_COMPROMISE'),
            ('authorities[LIVE_RUNNER_MANIFEST].revocation', 'REVOKED_IN_THE_TRUST_BUNDLE_BY_LOCAL_CUSTODY_TRANSFER'),
            ('authorities[LIVE_RUNNER_MANIFEST].importCheckedAtCeremony', True),
            ('authorities[LIVE_RUNNER_MANIFEST].ceremony.state', 'PENDING_THE_POST_MERGE_KEY_CEREMONY'),
            ('authorities[LIVE_RUNNER_MANIFEST].ceremony.records[*]', ['PUBLIC_KEY_DIGEST', 'PURPOSE']),
            ('authorities[LIVE_RUNNER_MANIFEST].ceremony.privateBytes', False),
        ],
        'DESIGN.r7.md 572-575, 580, 609-612 (PLATFORM_RELEASE); Q-LHA-2 (a)': [
            ('authorities[PLATFORM_RELEASE].id', 'PLATFORM_RELEASE'),
            ('authorities[PLATFORM_RELEASE].keyId', 'KEYID-PLATFORM-RELEASE'),
            ('authorities[PLATFORM_RELEASE].purpose', 'PLATFORM_RELEASE'),
            ('authorities[PLATFORM_RELEASE].algorithm', 'ED25519'),
            ('authorities[PLATFORM_RELEASE].signs[*]',
             ['ENVELOPE_PLATFORM_SIGNATURE', 'RELEASE_MATERIAL', 'RELEASE_TRUST_BUNDLE_REVOCATION_MATERIAL']),
            ('authorities[PLATFORM_RELEASE].sessions[*]', ['T1', 'T2']),
            ('authorities[PLATFORM_RELEASE].publicHalf', 'THE_RELEASE_TRUST_BUNDLE'),
            ('authorities[PLATFORM_RELEASE].cadence', 'THE_ENVELOPE_PER_RUN_RELEASE_MATERIAL_PER_RELEASE'),
            ('authorities[PLATFORM_RELEASE].holder', 'OWNER'),
            ('authorities[PLATFORM_RELEASE].token', 'TOKEN-PLATFORM-RELEASE'),
            ('authorities[PLATFORM_RELEASE].sealedBackup', 'BACKUP-PLATFORM-RELEASE'),
            ('authorities[PLATFORM_RELEASE].generation', 'OFFLINE_ON_A_MACHINE_THAT_NEVER_CONNECTS'),
            ('authorities[PLATFORM_RELEASE].storage', 'HARDWARE_TOKEN_WITH_ONE_SEALED_OFFLINE_BACKUP'),
            ('authorities[PLATFORM_RELEASE].rotation', 'PER_RELEASE_OR_ON_COMPROMISE'),
            ('authorities[PLATFORM_RELEASE].revocation', 'REVOKED_IN_THE_TRUST_BUNDLE_BY_LOCAL_CUSTODY_TRANSFER'),
            ('authorities[PLATFORM_RELEASE].importCheckedAtCeremony', True),
            ('authorities[PLATFORM_RELEASE].ceremony.state', 'PENDING_THE_POST_MERGE_KEY_CEREMONY'),
            ('authorities[PLATFORM_RELEASE].ceremony.records[*]', ['PUBLIC_KEY_DIGEST', 'PURPOSE']),
            ('authorities[PLATFORM_RELEASE].ceremony.privateBytes', False),
        ],
        'DESIGN.r7.md 572-575, 581, 609-612 (TENANT_LIVE_EXECUTION); Q-LHA-2 (a)': [
            ('authorities[TENANT_LIVE_EXECUTION].id', 'TENANT_LIVE_EXECUTION'),
            ('authorities[TENANT_LIVE_EXECUTION].keyId', 'KEYID-TENANT-LIVE-EXECUTION'),
            ('authorities[TENANT_LIVE_EXECUTION].purpose', 'TENANT_LIVE_EXECUTION'),
            ('authorities[TENANT_LIVE_EXECUTION].algorithm', 'ED25519'),
            ('authorities[TENANT_LIVE_EXECUTION].signs[*]',
             ['ENVELOPE_TENANT_SIGNATURE', 'TENANT_TRUST_BUNDLE_REVOCATION_MATERIAL']),
            ('authorities[TENANT_LIVE_EXECUTION].sessions[*]', ['T1', 'T2']),
            ('authorities[TENANT_LIVE_EXECUTION].publicHalf', 'THE_TENANT_TRUST_BUNDLE'),
            ('authorities[TENANT_LIVE_EXECUTION].cadence', 'PER_RUN'),
            ('authorities[TENANT_LIVE_EXECUTION].holder', 'OWNER'),
            ('authorities[TENANT_LIVE_EXECUTION].token', 'TOKEN-TENANT-LIVE-EXECUTION'),
            ('authorities[TENANT_LIVE_EXECUTION].sealedBackup', 'BACKUP-TENANT-LIVE-EXECUTION'),
            ('authorities[TENANT_LIVE_EXECUTION].generation', 'OFFLINE_ON_A_MACHINE_THAT_NEVER_CONNECTS'),
            ('authorities[TENANT_LIVE_EXECUTION].storage', 'HARDWARE_TOKEN_WITH_ONE_SEALED_OFFLINE_BACKUP'),
            ('authorities[TENANT_LIVE_EXECUTION].rotation', 'PER_RELEASE_OR_ON_COMPROMISE'),
            ('authorities[TENANT_LIVE_EXECUTION].revocation', 'REVOKED_IN_THE_TRUST_BUNDLE_BY_LOCAL_CUSTODY_TRANSFER'),
            ('authorities[TENANT_LIVE_EXECUTION].importCheckedAtCeremony', True),
            ('authorities[TENANT_LIVE_EXECUTION].ceremony.state', 'PENDING_THE_POST_MERGE_KEY_CEREMONY'),
            ('authorities[TENANT_LIVE_EXECUTION].ceremony.records[*]', ['PUBLIC_KEY_DIGEST', 'PURPOSE']),
            ('authorities[TENANT_LIVE_EXECUTION].ceremony.privateBytes', False),
        ],
        'DESIGN.r7.md 572-575, 582, 609-612 (CAPACITY_OPERATOR); Q-LHA-2 (a)': [
            ('authorities[CAPACITY_OPERATOR].id', 'CAPACITY_OPERATOR'),
            ('authorities[CAPACITY_OPERATOR].keyId', 'KEYID-CAPACITY-OPERATOR'),
            ('authorities[CAPACITY_OPERATOR].purpose', 'CAPACITY_OPERATOR'),
            ('authorities[CAPACITY_OPERATOR].algorithm', 'ED25519'),
            ('authorities[CAPACITY_OPERATOR].signs[*]', ['CAPACITY_AUTHORIZATION']),
            ('authorities[CAPACITY_OPERATOR].sessions[*]', ['T2']),
            ('authorities[CAPACITY_OPERATOR].publicHalf', 'THE_TENANT_TRUST_BUNDLE'),
            ('authorities[CAPACITY_OPERATOR].cadence', 'PER_RUN'),
            ('authorities[CAPACITY_OPERATOR].holder', 'OWNER'),
            ('authorities[CAPACITY_OPERATOR].token', 'TOKEN-CAPACITY-OPERATOR'),
            ('authorities[CAPACITY_OPERATOR].sealedBackup', 'BACKUP-CAPACITY-OPERATOR'),
            ('authorities[CAPACITY_OPERATOR].generation', 'OFFLINE_ON_A_MACHINE_THAT_NEVER_CONNECTS'),
            ('authorities[CAPACITY_OPERATOR].storage', 'HARDWARE_TOKEN_WITH_ONE_SEALED_OFFLINE_BACKUP'),
            ('authorities[CAPACITY_OPERATOR].rotation', 'PER_RELEASE_OR_ON_COMPROMISE'),
            ('authorities[CAPACITY_OPERATOR].revocation', 'REVOKED_IN_THE_TRUST_BUNDLE_BY_LOCAL_CUSTODY_TRANSFER'),
            ('authorities[CAPACITY_OPERATOR].importCheckedAtCeremony', True),
            ('authorities[CAPACITY_OPERATOR].ceremony.state', 'PENDING_THE_POST_MERGE_KEY_CEREMONY'),
            ('authorities[CAPACITY_OPERATOR].ceremony.records[*]', ['PUBLIC_KEY_DIGEST', 'PURPOSE']),
            ('authorities[CAPACITY_OPERATOR].ceremony.privateBytes', False),
        ],
        'B-LHA-4 (custody: LINUX_RUNNER_MANIFEST signs the drop manifest, placement only)': [
            ('dropManifest.signer', 'LINUX_RUNNER_MANIFEST'),
            ('dropManifest.authorizes', 'PLACEMENT_ONLY'),
            ('dropManifest.liveManifestStillVerifiedUnder', 'LIVE_RUNNER_MANIFEST'),
        ],
        'DESIGN.r7.md 584-589 (T1 and T2); runbook steps 10 and 12 (DESIGN.r7.md 494, 496); Q-LHA-2': [
            ('tokenSessions[T1].id', 'T1'),
            ('tokenSessions[T1].runbookStep', 10),
            ('tokenSessions[T1].after', 'THE_STEP_9_INVENTORY_FREEZE'),
            ('tokenSessions[T1].offHost', True),
            ('tokenSessions[T1].withinOneHourOfPreflight', False),
            ('tokenSessions[T1].everyTokenPresent', False),
            ('tokenSessions[T1].order[*]',
             ['MEASURED_BOOT_COMPARISON',
              'LINUX_RUNNER_MANIFEST_SIGNS_THE_OFFLINE_POLICY',
              'BUNDLES_AND_REVOCATION_MATERIAL_REFRESHED']),
            ('tokenSessions[T2].id', 'T2'),
            ('tokenSessions[T2].runbookStep', 12),
            ('tokenSessions[T2].after', 'THE_STEP_11_PREFLIGHT'),
            ('tokenSessions[T2].offHost', True),
            ('tokenSessions[T2].withinOneHourOfPreflight', True),
            ('tokenSessions[T2].everyTokenPresent', True),
            ('tokenSessions[T2].order[*]',
             ['LOCAL_CA_ISSUES_CAMPAIGN_PROXY_SERVER_TLS_AND_CAMPAIGN_PROXY_CLIENT_MTLS',
              'CAPACITY_OPERATOR_SIGNS_THE_CAPACITY_AUTHORIZATION',
              'PLATFORM_RELEASE_AND_TENANT_LIVE_EXECUTION_SIGN_THE_ENVELOPE',
              'LINUX_RUNNER_MANIFEST_SIGNS_THE_OFFLINE_MANIFEST',
              'LINUX_RUNNER_MANIFEST_SIGNS_THE_DROP_MANIFEST']),
        ],
        'DESIGN.r7.md 496 (runbook step 12: until they close, T2 signs no live manifest), 556-558': [
            ('liveManifestInT2', 'NOT_SIGNED_UNTIL_CONF_LIVE_005_006_CLOSE_AND_THEIR_OWN_PREFLIGHT'),
        ],
        'DESIGN.r7.md 591-596 (bundles); MON-LHA3-1-2': [
            ('bundles.release.path', '/etc/planeon/trust/release-trust-bundle.json'),
            ('bundles.release.authoredUnder', 'PLATFORM_RELEASE'),
            ('bundles.tenant.path', '/etc/planeon/trust/tenant-trust-bundle.json'),
            ('bundles.tenant.authoredUnder', 'TENANT_LIVE_EXECUTION'),
            ('bundles.digestsInTheSignedEnvelope', True),
            ('bundles.refreshedIn', 'T1'),
            ('bundles.installedAtStep', 10),
            ('bundles.beforeTheRevocation', True),
            ('bundles.t2EnvelopeBindsTheInstalledBytes', True),
            ('bundles.route', 'LOCAL_CUSTODY_TRANSFER_ONLY'),
            ('bundles.networkLookup', False),
        ],
        'DESIGN.r7.md 602 (the release-pinned local CA); Q-LHA-16 (2); B-LHA-2': [
            ('localCa.id', 'RELEASE_PINNED_LOCAL_CA'),
            ('localCa.issuer', 'THE_OWNER_AT_THE_CEREMONY'),
            ('localCa.pinnedIn', 'THE_RELEASE'),
            ('localCa.holder', 'OWNER'),
            ('localCa.generation', 'OFFLINE_ON_A_MACHINE_THAT_NEVER_CONNECTS'),
            ('localCa.storage', 'A_TOKEN_SUPPORTING_ITS_ALGORITHM_WITH_A_SEALED_BACKUP_CHECKED_AT_THE_CEREMONY'),
            ('localCa.secondTokenModel', 'THE_OWNER_PURCHASE_IF_NEEDED'),
            ('localCa.rotation', 'PER_RELEASE'),
            ('localCa.issues[*]', ['CAMPAIGN_PROXY_SERVER_TLS', 'CAMPAIGN_PROXY_CLIENT_MTLS']),
            ('localCa.neverInTheApiServerClientTrust', True),
            ('localCa.decision', 'Q-LHA-16-2'),
        ],
        'B-LHA-2 (the per-run cluster CA; MON-LHA-B2)': [
            ('clusterCa.id', 'PER_RUN_CLUSTER_CA'),
            ('clusterCa.madeAtStep', 7),
            ('clusterCa.on', 'CLUSTER_NODE'),
            ('clusterCa.by', 'THE_CLUSTER_DISTRIBUTION'),
            ('clusterCa.issues[*]', ['KUBERNETES_PROXY_SERVER_MTLS']),
            ('clusterCa.issuesAtStep', 8),
            ('clusterCa.withAdmin', True),
            ('clusterCa.newKeyOrToken', False),
            ('clusterCa.trustedByTheProxyOperatorHostAt', '/etc/planeon/credentials/cluster-ca.crt.pem'),
            ('clusterCa.privateHalfEnds', 'CLUSTER_NODE_INSTANCE_AND_DISK_DELETION'),
            ('clusterCa.decision', 'MON-LHA-B2'),
        ],
        'DESIGN.r7.md 603, 607, 650 (the CAMPAIGN_PROXY server TLS identity)': [
            ('perRunCredentials[CAMPAIGN_PROXY_SERVER_TLS].id', 'CAMPAIGN_PROXY_SERVER_TLS'),
            ('perRunCredentials[CAMPAIGN_PROXY_SERVER_TLS].issuer', 'RELEASE_PINNED_LOCAL_CA'),
            ('perRunCredentials[CAMPAIGN_PROXY_SERVER_TLS].issuedAt', 'T2'),
            ('perRunCredentials[CAMPAIGN_PROXY_SERVER_TLS].fromRequestAtStep', 8),
            ('perRunCredentials[CAMPAIGN_PROXY_SERVER_TLS].madeOn', 'PROXY_OPERATOR_HOST'),
            ('perRunCredentials[CAMPAIGN_PROXY_SERVER_TLS].privateHalf',
             '/etc/planeon/credentials/campaign-proxy-server-tls.key.pem'),
            ('perRunCredentials[CAMPAIGN_PROXY_SERVER_TLS].privateHalfOwner', 'ROOT'),
            ('perRunCredentials[CAMPAIGN_PROXY_SERVER_TLS].privateHalfMode', '0400'),
            ('perRunCredentials[CAMPAIGN_PROXY_SERVER_TLS].certificate',
             '/etc/planeon/credentials/campaign-proxy-server-tls.crt.pem'),
            ('perRunCredentials[CAMPAIGN_PROXY_SERVER_TLS].certificateArrives', 'SIGNED_DROP_AT_STEP_13'),
            ('perRunCredentials[CAMPAIGN_PROXY_SERVER_TLS].trustedBy',
             'THE_CAMPAIGN_PROXY_CLIENT_THROUGH_THE_LOCAL_CA'),
            ('perRunCredentials[CAMPAIGN_PROXY_SERVER_TLS].inCredentialIdentities', True),
            ('perRunCredentials[CAMPAIGN_PROXY_SERVER_TLS].reusedAcrossRuns', False),
            ('perRunCredentials[CAMPAIGN_PROXY_SERVER_TLS].ends', 'INSTANCE_AND_DISK_DELETION_AT_TEARDOWN'),
            ('perRunCredentials[CAMPAIGN_PROXY_SERVER_TLS].grantsKubernetesAccess', False),
        ],
        'DESIGN.r7.md 604, 607, 650 (CAMPAIGN_PROXY_CLIENT_MTLS)': [
            ('perRunCredentials[CAMPAIGN_PROXY_CLIENT_MTLS].id', 'CAMPAIGN_PROXY_CLIENT_MTLS'),
            ('perRunCredentials[CAMPAIGN_PROXY_CLIENT_MTLS].issuer', 'RELEASE_PINNED_LOCAL_CA'),
            ('perRunCredentials[CAMPAIGN_PROXY_CLIENT_MTLS].issuedAt', 'T2'),
            ('perRunCredentials[CAMPAIGN_PROXY_CLIENT_MTLS].fromRequestAtStep', 8),
            ('perRunCredentials[CAMPAIGN_PROXY_CLIENT_MTLS].madeOn', 'PROXY_OPERATOR_HOST'),
            ('perRunCredentials[CAMPAIGN_PROXY_CLIENT_MTLS].privateHalf',
             '/etc/planeon/credentials/campaign-proxy-client-mtls.key.pem'),
            ('perRunCredentials[CAMPAIGN_PROXY_CLIENT_MTLS].privateHalfOwner', 'ROOT'),
            ('perRunCredentials[CAMPAIGN_PROXY_CLIENT_MTLS].privateHalfMode', '0400'),
            ('perRunCredentials[CAMPAIGN_PROXY_CLIENT_MTLS].certificate',
             '/etc/planeon/credentials/campaign-proxy-client-mtls.crt.pem'),
            ('perRunCredentials[CAMPAIGN_PROXY_CLIENT_MTLS].certificateArrives', 'SIGNED_DROP_AT_STEP_13'),
            ('perRunCredentials[CAMPAIGN_PROXY_CLIENT_MTLS].trustedBy', 'THE_PROXY_SERVER_THROUGH_THE_LOCAL_CA'),
            ('perRunCredentials[CAMPAIGN_PROXY_CLIENT_MTLS].inCredentialIdentities', True),
            ('perRunCredentials[CAMPAIGN_PROXY_CLIENT_MTLS].reusedAcrossRuns', False),
            ('perRunCredentials[CAMPAIGN_PROXY_CLIENT_MTLS].ends', 'INSTANCE_AND_DISK_DELETION_AT_TEARDOWN'),
            ('perRunCredentials[CAMPAIGN_PROXY_CLIENT_MTLS].grantsKubernetesAccess', False),
        ],
        'B-LHA-2 (issued by the per-run cluster CA at step 8; MON-LHA-B2); DESIGN.r7.md 605, 607, 650': [
            ('perRunCredentials[KUBERNETES_PROXY_SERVER_MTLS].id', 'KUBERNETES_PROXY_SERVER_MTLS'),
            ('perRunCredentials[KUBERNETES_PROXY_SERVER_MTLS].issuer', 'PER_RUN_CLUSTER_CA'),
            ('perRunCredentials[KUBERNETES_PROXY_SERVER_MTLS].issuedAt', 'STEP_8'),
            ('perRunCredentials[KUBERNETES_PROXY_SERVER_MTLS].fromRequestAtStep', 8),
            ('perRunCredentials[KUBERNETES_PROXY_SERVER_MTLS].madeOn', 'PROXY_OPERATOR_HOST'),
            ('perRunCredentials[KUBERNETES_PROXY_SERVER_MTLS].privateHalf',
             '/etc/planeon/credentials/kubernetes-proxy-server-mtls.key.pem'),
            ('perRunCredentials[KUBERNETES_PROXY_SERVER_MTLS].privateHalfOwner', 'ROOT'),
            ('perRunCredentials[KUBERNETES_PROXY_SERVER_MTLS].privateHalfMode', '0400'),
            ('perRunCredentials[KUBERNETES_PROXY_SERVER_MTLS].certificate',
             '/etc/planeon/credentials/kubernetes-proxy-server-mtls.crt.pem'),
            ('perRunCredentials[KUBERNETES_PROXY_SERVER_MTLS].certificateArrives', 'INSTALLED_AT_STEP_8_WITH_ADMIN'),
            ('perRunCredentials[KUBERNETES_PROXY_SERVER_MTLS].trustedBy',
             'THE_API_SERVER_WHOSE_CLIENT_TRUST_HOLDS_ONLY_THE_CLUSTER_CA'),
            ('perRunCredentials[KUBERNETES_PROXY_SERVER_MTLS].inCredentialIdentities', True),
            ('perRunCredentials[KUBERNETES_PROXY_SERVER_MTLS].reusedAcrossRuns', False),
            ('perRunCredentials[KUBERNETES_PROXY_SERVER_MTLS].ends', 'INSTANCE_AND_DISK_DELETION_AT_TEARDOWN'),
            ('perRunCredentials[KUBERNETES_PROXY_SERVER_MTLS].grantsKubernetesAccess', True),
        ],
        "B-LHA-7 (each endpoint kind's server TLS identity)": [
            ('endpointServerIdentities[KUBERNETES_API_PROXY].owner', 'THIS_CUSTODY_MODEL'),
            ('endpointServerIdentities[KUBERNETES_API_PROXY].identity', 'CAMPAIGN_PROXY_SERVER_TLS'),
            ('endpointServerIdentities[KUBERNETES_API_PROXY].issuer', 'RELEASE_PINNED_LOCAL_CA'),
            ('endpointServerIdentities[KUBERNETES_API_PROXY].host', 'PROXY_OPERATOR_HOST'),
            ('endpointServerIdentities[KUBERNETES_API_PROXY].privateHalfCustody',
             'GENERATED_AT_STEP_8_ROOT_OWNED_0400'),
            ('endpointServerIdentities[KUBERNETES_API_PROXY].lifetime', 'PER_RUN_ENDS_WITH_INSTANCE_AND_DISK_DELETION'),
            ('endpointServerIdentities[KUBERNETES_API_PROXY].perRun', True),
            ('endpointServerIdentities[KUBERNETES_API_PROXY].servesBothProxyKinds', True),
            ('endpointServerIdentities[KUBERNETES_API_PROXY].kind', 'KUBERNETES_API_PROXY'),
            ('endpointServerIdentities[CAMPAIGN_PROXY].owner', 'THIS_CUSTODY_MODEL'),
            ('endpointServerIdentities[CAMPAIGN_PROXY].identity', 'CAMPAIGN_PROXY_SERVER_TLS'),
            ('endpointServerIdentities[CAMPAIGN_PROXY].issuer', 'RELEASE_PINNED_LOCAL_CA'),
            ('endpointServerIdentities[CAMPAIGN_PROXY].host', 'PROXY_OPERATOR_HOST'),
            ('endpointServerIdentities[CAMPAIGN_PROXY].privateHalfCustody', 'GENERATED_AT_STEP_8_ROOT_OWNED_0400'),
            ('endpointServerIdentities[CAMPAIGN_PROXY].lifetime', 'PER_RUN_ENDS_WITH_INSTANCE_AND_DISK_DELETION'),
            ('endpointServerIdentities[CAMPAIGN_PROXY].perRun', True),
            ('endpointServerIdentities[CAMPAIGN_PROXY].servesBothProxyKinds', True),
            ('endpointServerIdentities[CAMPAIGN_PROXY].kind', 'CAMPAIGN_PROXY'),
            ('endpointServerIdentities[LOCAL_REGISTRY].owner', 'CAMPAIGN_RELEASE'),
            ('endpointServerIdentities[LOCAL_REGISTRY].identity', 'DEFINED_BY_THE_CAMPAIGN_RELEASE'),
            ('endpointServerIdentities[LOCAL_REGISTRY].issuer', 'PER_THE_CAMPAIGN_RELEASE_G10'),
            ('endpointServerIdentities[LOCAL_REGISTRY].host', 'PROXY_OPERATOR_HOST'),
            ('endpointServerIdentities[LOCAL_REGISTRY].privateHalfCustody', 'PER_THE_CAMPAIGN_RELEASE_G10'),
            ('endpointServerIdentities[LOCAL_REGISTRY].lifetime', 'PER_THE_CAMPAIGN_RELEASE_G10'),
            ('endpointServerIdentities[LOCAL_REGISTRY].perRun', False),
            ('endpointServerIdentities[LOCAL_REGISTRY].servesBothProxyKinds', False),
            ('endpointServerIdentities[LOCAL_REGISTRY].kind', 'LOCAL_REGISTRY'),
            ('endpointServerIdentities[LOCAL_EVIDENCE_SINK].owner', 'CAMPAIGN_RELEASE'),
            ('endpointServerIdentities[LOCAL_EVIDENCE_SINK].identity', 'DEFINED_BY_THE_CAMPAIGN_RELEASE'),
            ('endpointServerIdentities[LOCAL_EVIDENCE_SINK].issuer', 'PER_THE_CAMPAIGN_RELEASE_G10'),
            ('endpointServerIdentities[LOCAL_EVIDENCE_SINK].host', 'PROXY_OPERATOR_HOST'),
            ('endpointServerIdentities[LOCAL_EVIDENCE_SINK].privateHalfCustody', 'PER_THE_CAMPAIGN_RELEASE_G10'),
            ('endpointServerIdentities[LOCAL_EVIDENCE_SINK].lifetime', 'PER_THE_CAMPAIGN_RELEASE_G10'),
            ('endpointServerIdentities[LOCAL_EVIDENCE_SINK].perRun', False),
            ('endpointServerIdentities[LOCAL_EVIDENCE_SINK].servesBothProxyKinds', False),
            ('endpointServerIdentities[LOCAL_EVIDENCE_SINK].kind', 'LOCAL_EVIDENCE_SINK'),
        ],
        'B-LHA-7 (if one server identity serves both proxy kinds, the record says so)': [
            ('sharedProxyServerIdentity.identity', 'CAMPAIGN_PROXY_SERVER_TLS'),
            ('sharedProxyServerIdentity.servesKinds[*]', ['KUBERNETES_API_PROXY', 'CAMPAIGN_PROXY']),
            ('sharedProxyServerIdentity.rule', 'B-LHA-7'),
        ],
        "B-LHA-2 (the API server's client trust and RBAC; MON-LHA-B2)": [
            ('kubernetes.apiServerClientTrust[*]', ['PER_RUN_CLUSTER_CA']),
            ('kubernetes.refusedInClientTrust[*]', ['RELEASE_PINNED_LOCAL_CA']),
            ('kubernetes.rbacSubject', 'KUBERNETES_PROXY_SERVER_MTLS_EXACT_SUBJECT'),
            ('kubernetes.privilegedGroups', False),
            ('kubernetes.proxyOperatorHostTrustsClusterCa', True),
            ('kubernetes.proxyOperatorHostClusterCaTrust', '/etc/planeon/credentials/cluster-ca.crt.pem'),
        ],
        'MON-LHA-CR1-KEEP (OPEN-1 (ii), MON-LHA-OPEN-1-A); LHA-C1-4; DESIGN.r7.md 102': [
            ('localEndpointIdentities.kinds[*]', ['LOCAL_REGISTRY', 'LOCAL_EVIDENCE_SINK']),
            ('localEndpointIdentities.suppliedBy', 'CAMPAIGN_RELEASE_G10'),
            ('localEndpointIdentities.before', 'RUNBOOK_STEP_7'),
            ('localEndpointIdentities.precondition', 'G10-LOCAL-ENDPOINT-IDENTITIES'),
            ('localEndpointIdentities.issuedInT1OrT2', False),
            ('localEndpointIdentities.ifTheCampaignReleaseChoosesTheLocalCa',
             'A_TOKEN_SESSION_BEFORE_STEP_7_A_CUSTODY_SCOPE_CHANGE_FOR_THE_MONITOR'),
        ],
        'DESIGN.r7.md 615-620 (the nonce stores); Q-LHA-3 (a)': [
            ('nonce.signingRegistry.custody', 'OWNER'),
            ('nonce.signingRegistry.location', 'OUTSIDE_GCP'),
            ('nonce.signingRegistry.neverSignsSameNonceTwice', True),
            ('nonce.signingRegistry.covers[*]', ['ENVELOPE_NONCE', 'CAPACITY_AUTHORIZATION_NONCE']),
            ('nonce.hostLedger.host', 'PROXY_OPERATOR_HOST'),
            ('nonce.hostLedger.owner', 'ROOT'),
            ('nonce.hostLedger.durable', True),
            ('nonce.hostLedger.reservations[*]', ['LAUNCHER', 'PROXY_CLIENT', 'PROXY_SERVER']),
            ('nonce.hostLedger.runtimeWrites[*]',
             ['HOST_LEDGER_LAUNCHER', 'HOST_LEDGER_PROXY_CLIENT', 'HOST_LEDGER_PROXY_SERVER']),
            ('nonce.hostLedger.exportedAtStep', 15),
            ('nonce.hostLedger.retained', True),
        ],
        'DESIGN.r7.md 621-624 (cross-host replay is closed)': [
            ('crossHostReplay.envelopeBinds[*]', ['ENDPOINT_ADDRESS', 'SERVER_SPKI_FRESH_PER_RUN', 'VALIDITY_WINDOW']),
            ('crossHostReplay.serverKeyReused', False),
            ('crossHostReplay.signingRegistryNeverResigns', True),
        ],
        'DESIGN.r7.md 625-626 (the trusted clock)': [
            ('trustedClock.host', 'CHRONY'),
            ('trustedClock.launchers', 'VALIDITY_WINDOW_CHECKS'),
            ('trustedClock.capturedAtPreflight[*]', ['CLOCK_SOURCE', 'OFFSET']),
        ],
        'DESIGN.r7.md 627, 594-596 (revocation by local transfer in T1, installed at step 10)': [
            ('revocation.refreshedBy', 'LOCAL_TRANSFER'),
            ('revocation.in', 'T1'),
            ('revocation.beforeEachRun', True),
            ('revocation.installedAtStep', 10),
            ('revocation.route', 'LOCAL_CUSTODY_TRANSFER'),
            ('revocation.network', False),
        ],
        'DESIGN.r7.md 628-629 (the evidence store)': [
            ('evidenceStore.custody', 'OWNER'),
            ('evidenceStore.fromRunbookStep', 15),
            ('evidenceStore.location', 'OUTSIDE_THE_RUN_PROJECT'),
            ('evidenceStore.inRunProjectBeyondPlan', False),
        ],
        'DESIGN.r7.md 631-644 (independence); Q-LHA-1 (a)': [
            ('independence.decision', 'Q-LHA-1'),
            ('independence.trustedLiveRequires', 'DISTINCT_KEYS_AND_IDENTITIES'),
            ('independence.keysDistinct', True),
            ('independence.heldApart', True),
            ('independence.independentPeople', False),
            ('independence.clauseSupersededIn', 'architecture/linux-host-authority/host-authority.json'),
            ('independence.disclosure.signers', 'SINGLE_PRINCIPAL_SEPARATED_KEYS'),
            ('independence.carriers[CONF-LINUX-002].carrier', 'R12_CLOSED_EVIDENCE_RECORD'),
            ('independence.carriers[CONF-LINUX-002].for', 'CONF-LINUX-001'),
            ('independence.carriers[CONF-LINUX-002].packet', 'CONF-LINUX-002'),
            ('independence.carriers[CONF-LINUX-002].state', 'PRECONDITION'),
            ('independence.carriers[CONF-LIVE-006].carrier', 'CONF_LIVE_006_AUTHORITY_AND_EVIDENCE_ADAPTER'),
            ('independence.carriers[CONF-LIVE-006].for', 'THE_LIVE_PATH_QUALIFICATION'),
            ('independence.carriers[CONF-LIVE-006].packet', 'CONF-LIVE-006'),
            ('independence.carriers[CONF-LIVE-006].state', 'PRECONDITION'),
        ],
        'LHA-CN-2 (design-status.json, carried verbatim as a note); DESIGN.r7.md 967-968': [
            ('carriedNotes[LHA-CN-2].id', 'LHA-CN-2'),
            ('carriedNotes[LHA-CN-2].date', '2026-10-24'),
            ('carriedNotes[LHA-CN-2].status', 'CARRIED_NOTE_NOT_SETTLED'),
            ('carriedNotes[LHA-CN-2].appliesTo[*]', ['principal', 'independence']),
            ('carriedNotes[LHA-CN-2].checkedIn', 'THE_LHA_CONTRACT_ROUND'),
        ],
    },
}
LEAF_EXPLICIT: dict = {
    'authority': ['replacementPredicate.ownerAnswer',
                  'replacementPredicate.text',
                  'decisions.decisionLines[LX-D1].text',
                  'decisions.decisionLines[LX-D2].text',
                  'decisions.decisionLines[Q-LHA-ID].text',
                  'decisions.decisionLines[Q-LHA-SERIES].text',
                  'decisions.decisionLines[Q-LHA-1].text',
                  'decisions.decisionLines[Q-LHA-2].text',
                  'decisions.decisionLines[Q-LHA-3].text',
                  'decisions.decisionLines[Q-LHA-4].text',
                  'decisions.decisionLines[Q-LHA-5].text',
                  'decisions.decisionLines[Q-LHA-6].text',
                  'decisions.decisionLines[Q-LHA-4-5-6-STAND].text',
                  'decisions.decisionLines[Q-LHA-7].text',
                  'decisions.decisionLines[Q-LHA-8].text',
                  'decisions.decisionLines[Q-LHA-9].text',
                  'decisions.decisionLines[Q-LHA-10].text',
                  'decisions.decisionLines[Q-LHA-11].text',
                  'decisions.decisionLines[Q-LHA-12].text',
                  'decisions.decisionLines[Q-LHA-13].text',
                  'decisions.decisionLines[Q-LHA-14].text',
                  'decisions.decisionLines[Q-LHA-15].text',
                  'decisions.decisionLines[Q-LHA-16-2].text',
                  'decisions.decisionLines[MON-LHA-16-1].text',
                  'decisions.decisionLines[MON-LHA-SPLIT].text',
                  'decisions.decisionLines[MON-LHA-12R].text',
                  'decisions.decisionLines[MON-LHA-17].text',
                  'decisions.decisionLines[LHA2-11].text',
                  'decisions.decisionLines[LHA-CAP].text',
                  'decisions.decisionLines[LHA3-8].text',
                  'decisions.decisionLines[MON-LHA3-1-2].text',
                  'decisions.decisionLines[MON-LHA-B1].text',
                  'decisions.decisionLines[MON-LHA-B2].text',
                  'decisions.decisionLines[B-LHA-3].text',
                  'decisions.decisionLines[B-LHA-4-12].text',
                  'decisions.decisionLines[OWNER-CUSTOM-ROLE].text',
                  'decisions.decisionLines[Q-LHA5-1].text',
                  'decisions.decisionLines[Q-LHA6-3].text',
                  'decisions.decisionLines[MON-LHA-NO-LOCAL-BRIEF].text',
                  'carriedNotes[LHA-CN-1].note'],
    'recipe': [],
    'launcher': [],
    'custody': ['principal.ownerAnswer', 'carriedNotes[LHA-CN-2].note'],
}
LEAF_STRUCTURE_ONLY: dict = {
    'authority': [],
    'recipe': ['image.family'],
    'launcher': [],
    'custody': [],
}
# END LEAF PINS

# ---------------------------------------------------------------------------------------------------------------------
# Span entries (design section 4, "One digest rule").

CITED_FILES = ("architecture/lab-run-plan/status.json", "architecture/linux-readiness.json",
               "docs/TRUSTED_LIVE_CAMPAIGN_RUNNER_CONTRACT.md", "docs/alpha-2/CI_CAPACITY_EXCEPTION.md",
               "docs/alpha-2/CREDENTIAL_ORDERING_REPAIR.md", "docs/alpha-2/LINUX_READINESS.md",
               "docs/alpha-2/LINUX_READINESS_REPAIRS.md", "docs/alpha-2/NATIVE_QUALIFICATION_READINESS.md",
               "docs/linux-runner/OPERATOR.md")
JOINER = " … "
MEMBER_PART = re.compile(r"([A-Za-z_][A-Za-z0-9_]*)((?:\[[0-9]+\])*)")
# A reading covers its named forms in every superseded, kept and satisfied text (design section 4; B-LHA-11;
# MON-LHA-ORC-2-A). PRE_EXISTING: pre-existing and preexisting in any case, and "existing operator". SIGNING_AUTHORITY:
# evidence.signingAuthority's EXISTING_..., and line 147's "existing" of the existing independent PLATFORM_RELEASE,
# TENANT_LIVE_EXECUTION and CAPACITY_OPERATOR authorities. Group 1 is the word; a lookahead may read past the fragment.
NAMED_FORMS = (("PRE_EXISTING", re.compile(rb"(?i)(pre-?existing)")),
               ("PRE_EXISTING", re.compile(rb"(?i)(existing)(?=\s+operator\b)")),
               ("SIGNING_AUTHORITY",
                re.compile(rb"(EXISTING)(?=_PLATFORM_RELEASE_TENANT_LIVE_EXECUTION_AND_CAPACITY_OPERATOR)")),
               ("SIGNING_AUTHORITY", re.compile(rb"(?i)(existing)(?=\s+independent\s+PLATFORM_RELEASE\b)")))


class Base:
    """The cited files, read once from the checkout."""

    def __init__(self, root: Path) -> None:
        self.root = root
        self.cache: dict = {}
        self.derived: dict = {}

    def read(self, path: str) -> bytes:
        require(path in CITED_FILES, "a cited file is one of the contract's cited files: " + path)
        if path not in self.cache:
            self.cache[path] = (self.root / path).read_bytes()
        return self.cache[path]

    def _derive(self, what: str, path: str, make: Any) -> Any:
        # The bytes never change once read, so what is derived from them is derived once (read only by the checks).
        if (what, path) not in self.derived:
            self.derived[(what, path)] = make(self.read(path))
        return self.derived[(what, path)]

    def lines(self, path: str) -> list:
        return self._derive("lines", path, lambda raw: raw.split(b"\n"))

    def sha256(self, path: str) -> str:
        return self._derive("sha256", path, lambda raw: hashlib.sha256(raw).hexdigest())

    def json(self, path: str) -> Any:
        return self._derive("json", path, strict)


def _member(value: Any, member: str) -> tuple:
    """The value at a full member path such as `evidence.requiredBindings[11]`, and the path's last token."""
    tokens: list = []
    for part in member.split("."):
        match = MEMBER_PART.fullmatch(part)
        require(match is not None, "a member path is dotted keys with list indexes: " + member)
        tokens.append(match.group(1))
        tokens.extend(int(index) for index in re.findall(r"\[([0-9]+)\]", match.group(2)))
    node = value
    for token in tokens:
        if type(token) is int:
            require(type(node) is list and token < len(node), "missing")
        else:
            require(type(node) is dict and token in node, "missing")
        node = node[token]
    return node, tokens[-1]


def check_entry(entry: dict, base: Base) -> list:
    """One span entry against the base bytes: file sha256, lines, fragments, text, span and (for JSON) the full member
    path. Returns the fragments' (line, start, end) pieces, one per line they touch."""
    name = entry["id"]
    base.read(entry["path"])
    require(base.sha256(entry["path"]) == entry["fileSha256"], name + ": the file sha256 is the base's")
    lines = base.lines(entry["path"])
    count = len(lines) - 1 if lines[-1] == b"" else len(lines)
    first, last = entry["lines"]
    require(1 <= first <= last <= count, name + ": the lines lie in the file")
    parts, pieces, previous = [], [], (first, 0)
    for start_line, start_byte, end_line, end_byte in entry["fragments"]:
        require(first <= start_line <= end_line <= last, name + ": a fragment lies within its lines")
        require((start_line, start_byte) >= previous and (start_line, start_byte) < (end_line, end_byte),
                name + ": the fragments are non-empty and in order")
        require(start_byte <= len(lines[start_line - 1]) and end_byte <= len(lines[end_line - 1]),
                name + ": a fragment's bytes lie within its lines")
        if start_line == end_line:
            parts.append(lines[start_line - 1][start_byte:end_byte])
        else:
            parts.append(b"\n".join([lines[start_line - 1][start_byte:]] + lines[start_line:end_line - 1]
                                    + [lines[end_line - 1][:end_byte]]))
        for number in range(start_line, end_line + 1):
            pieces.append((number, start_byte if number == start_line else 0,
                           end_byte if number == end_line else len(lines[number - 1])))
        previous = (end_line, end_byte)
    try:
        decoded = [part.decode("utf-8") for part in parts]
    except UnicodeDecodeError:
        raise ValueError(name + ": a fragment is UTF-8 text") from None
    require(entry["text"] == JOINER.join(decoded), name + ": the text is the fragments' bytes")
    require(entry["span"] == hashlib.sha256(b"".join(part + b"\x00" for part in parts)).hexdigest(),
            name + ": the span is the fragments' digest")
    if entry["path"].endswith(".json"):
        require(type(entry["member"]) is str, name + ": a JSON citation names its full member path")
        try:
            found, token = _member(base.json(entry["path"]), entry["member"])
        except ValueError:
            raise ValueError(name + ": the member path exists at the base, in its full form") from None
        rendered = json.dumps(found, ensure_ascii=False)
        expected = rendered if type(token) is int else '"%s": %s' % (token, rendered)
        line_number = entry["fragments"][0][0]
        line = lines[line_number - 1].decode("utf-8").strip()
        require(line in (expected, expected + ",") and all(f[0] == f[2] == line_number for f in entry["fragments"]),
                name + ": the fragments lie on the member's line")
    else:
        require(entry["member"] is None, name + ": a text citation names no member path")
    return pieces


def _pinned_section(entries: list, section: str, extra: str, missing: str) -> None:
    pinned = PINNED[section]
    ids = [entry["id"] for entry in entries]
    require(set(ids) <= set(pinned), extra)
    require(set(pinned) <= set(ids), missing)
    require(ids == list(pinned), section + " lists its entries in the contract's order")
    for entry in entries:
        want = pinned[entry["id"]]
        got = {"path": entry["path"], "member": entry["member"], "lines": entry["lines"], "span": entry["span"]}
        got.update({key: entry[key] for key in want if key not in got})
        require(got == want, entry["id"] + ": the entry is its listed text, bound by its span")


# ---------------------------------------------------------------------------------------------------------------------
# host-authority.json (design section 4)

SECTION_MESSAGES = {
    "supersedes": ("only the listed capacity predicates and the independence clause are relaxed",
                   "supersedes lists every relaxed predicate, member by member"),
    "satisfied": ("satisfied holds only the listed restatements of the independence clause",
                  "every restatement the replacement predicate satisfies is listed with its span"),
    "unchanged": ("unchanged holds only the listed kept predicates",
                  "every kept predicate of a partly relaxed sentence is in unchanged"),
    "costScope": ("costScope holds only the listed campaign, server, reader, cluster and endpoint rules",
                  "every rule kept at campaign, cluster or reader level is in costScope"),
    "reviewedNotBinding": ("reviewedNotBinding holds only the listed publication-scope texts",
                           "every reviewed publication-scope text is in reviewedNotBinding"),
}
SIGNING_TRIO = ["PLATFORM_RELEASE", "TENANT_LIVE_EXECUTION", "CAPACITY_OPERATOR"]
DISTINCT_PER_AUTHORITY = ["KEY_ID", "PURPOSE", "TOKEN", "SEALED_BACKUP"]
DISCLOSURE = {"signers": "SINGLE_PRINCIPAL_SEPARATED_KEYS"}
READINGS = {"SIGNING_AUTHORITY": ["existing"], "PRE_EXISTING": ["pre-existing", "preexisting", "existing"]}
NOT_SETTLED = "CARRIED_NOTE_NOT_SETTLED"
# The preconditions outside this packet (design section 10; MON-LHA-17; MON-LHA-B1). MET-LINUX-009 merged as the base.
PRECONDITIONS = ["MET-LINUX-009", "CONF-LINUX-002", "CONF-LIVE-006-ADAPTER", "CONF-LIVE-005-006-NON-ADMIN-ENTRY",
                 "CONF-LIVE-003-006-AND-MET-REPAIR-015-SOURCE-CLOSURE", "KERNEL-INDEPENDENT-QUALIFICATION",
                 "G10-LOCAL-ENDPOINT-IDENTITIES"]


def check_authority(doc: Any, schema: dict, base: Base) -> None:
    shape(doc, schema)
    free_text(doc)
    named_text(doc)
    sections = ("supersedes", "satisfied", "unchanged", "costScope", "reviewedNotBinding")
    occurrences = [o for reading in doc["readings"] for o in reading["occurrences"]]
    entries = [e for section in sections for e in doc[section]] + occurrences + [
        doc["evidence"]["freshness"], doc["decisions"]["metLinux007"], doc["consumers"]["beforeLiveLauncher"]["quote"]]
    ids = [entry["id"] for entry in entries]
    require(len(ids) == len(set(ids)), "every span entry has its own id")
    pieces = {entry["id"]: check_entry(entry, base) for entry in entries}
    for section in sections:
        _pinned_section(doc[section], section, *SECTION_MESSAGES[section])
    kept = {e["id"]: e for e in doc["unchanged"]}
    for entry in doc["supersedes"]:
        require(all(k in kept and kept[k]["path"] == entry["path"] for k in entry["keptIn"]),
                entry["id"] + ": a partly relaxed sentence names its kept predicates in unchanged")
    # The independence clause and its replacement predicate (the owner's Q-LHA-1 (a)).
    replacement = doc["replacementPredicate"]
    if any(entry["kind"] == "INDEPENDENCE" for entry in doc["supersedes"]):
        require(replacement["binding"] == "INDEPENDENT_SIGNATURES" and replacement["required"] is True
                and replacement["authorities"] == SIGNING_TRIO
                and replacement["distinctPerAuthority"] == DISTINCT_PER_AUTHORITY
                and replacement["principal"] == "SINGLE_OWNER"
                and _sha(replacement["text"]) == STATEMENT_SHA256["replacementPredicate"],
                "the independence clause is superseded only together with its replacement predicate")
        require(replacement["decision"] == "Q-LHA-1" and _sha(replacement["ownerAnswer"]) == DECISION_SHA256["Q-LHA-1"],
                "the independence clause is superseded only with the owner's Q-LHA-1 (a) answer, verbatim")
        require(replacement["disclosure"] == DISCLOSURE,
                "the independence clause is superseded only with the disclosure signers: SINGLE_PRINCIPAL_SEPARATED_KEYS")
    # The readings (MON-LHA-16-1; Q-LHA-14): each occurrence holds one of its words, and each reading covers its named
    # forms in every superseded, kept and satisfied text (design section 4; MON-LHA-ORC-1-A, MON-LHA-ORC-2-A).
    require([r["id"] for r in doc["readings"]] == list(READINGS)
            and all(r["words"] == READINGS[r["id"]] for r in doc["readings"]),
            "the readings are SIGNING_AUTHORITY and PRE_EXISTING, each with its words")
    for reading in doc["readings"]:
        for occurrence in reading["occurrences"]:
            require(occurrence["text"].lower() in reading["words"],
                    occurrence["id"] + ": a reading occurrence holds one of its words")
    _pinned_section(occurrences, "occurrences", "the readings list only their listed occurrences",
                    "every listed occurrence of a reading's words is in its reading")
    covered = [(reading["id"], o["path"], piece) for reading in doc["readings"] for o in reading["occurrences"]
               for piece in pieces[o["id"]]]
    lines_of = {}
    for section in ("supersedes", "unchanged", "satisfied"):
        for entry in doc[section]:
            line_list = lines_of.setdefault(entry["path"], base.lines(entry["path"]))
            for number, start, end in pieces[entry["id"]]:
                for reading_id, pattern in NAMED_FORMS:
                    for match in pattern.finditer(line_list[number - 1]):
                        at, to = match.span(1)
                        if start <= at and to <= end:
                            require(any(rid == reading_id and path == entry["path"] and n == number and s <= at
                                        and to <= e for rid, path, (n, s, e) in covered),
                                    "a reading covers its named forms in every superseded, kept and satisfied text, "
                                    "each listed in that reading with its span")
    # Capacity, evidence and decisions.
    capacity = doc["capacity"]
    require(capacity["rule"] == "OWNER_APPROVED_GCP_PER_RUN" and capacity["contract"] == "MET-LINUX-007"
            and capacity["binding"] == ["PLAN_SHA256", "LEASE", "COST_CEILING", "TEARDOWN_REPORT"],
            "the capacity rule is the owner's per-run GCP approval under MET-LINUX-007, bound to the plan sha256, the "
            "lease, the cost ceiling and the teardown report")
    require(capacity["runProject"] == {"separateFromLabFoundation": True, "defaultNetwork": False},
            "the run project is separate from the lab foundation, with no default network")
    require(capacity["hostRecipe"] == RECORD_PATHS["recipe"] and capacity["paidScope"] == "HOST_RECIPE_COST_SCOPE",
            "the host follows host-recipe.json, and its paid scope is the recipe's costScope")
    require(capacity["licenceCharge"] == "NONE", "licenceCharge is NONE; an owner-approved licence charge needs a "
            "contract amendment")
    evidence = doc["evidence"]
    readiness = base.json("architecture/linux-readiness.json")
    states = {t["architecture"]: t["status"] for t in readiness["targets"]}
    require(evidence["nativeAmd64"] == states.get("amd64") == "NOT_RUN_ENV_UNAVAILABLE"
            and evidence["arm64"] == states.get("arm64") == "NOT_RUN_ENV_UNAVAILABLE",
            "the evidence states do not move: native AMD64 and ARM64 stay NOT_RUN_ENV_UNAVAILABLE")
    require(evidence["approvingCapacityIsQualification"] is False, "approving capacity is not qualification")
    single = {"freshness": evidence["freshness"], "metLinux007": doc["decisions"]["metLinux007"],
              "beforeLiveLauncher": doc["consumers"]["beforeLiveLauncher"]["quote"]}
    for key, entry in single.items():
        _pinned_section([entry], key, key + " is its listed citation", key + " is its listed citation")
    lines = doc["decisions"]["decisionLines"]
    require([d["id"] for d in lines] == list(DECISION_SHA256), "the decisions are the listed decision lines")
    for decision in lines:
        require(_sha(decision["text"]) == DECISION_SHA256[decision["id"]],
                "the decisions are the decision lines, verbatim: " + decision["id"])
    consumers = doc["consumers"]
    require([c["id"] for c in consumers["list"]] == ["CONF-LINUX-001", "NATIVE_AMD64_QUALIFICATION"]
            and consumers["beforeLiveLauncher"]["evidence"] == "HOST_ISOLATION_ONLY"
            and consumers["beforeLiveLauncher"]["mode"] == "OFFLINE_LAUNCHER_PREFLIGHT_ONLY",
            "the consumers are CONF-LINUX-001 and the native AMD64 qualification, and before the live launcher a lease "
            "yields only HOST_ISOLATION_ONLY preflight evidence")
    require([p["id"] for p in doc["preconditions"]] == PRECONDITIONS
            and all(p["state"] == ("MERGED_AT_BASE" if p["id"] == "MET-LINUX-009" else "OPEN") for p in doc["preconditions"]),
            "the preconditions outside this packet are listed, each with its state at the base")
    _check_notes(doc["carriedNotes"], ["LHA-CN-1"])


def _check_notes(notes: list, ids: list) -> None:
    require([n["id"] for n in notes] == ids and all(n["status"] == NOT_SETTLED and _sha(n["note"]) == STATEMENT_SHA256[n["id"]]
                                                   for n in notes),
            "a carried note is carried verbatim and stated as a note, never as a settled claim")


# ---------------------------------------------------------------------------------------------------------------------
# host-recipe.json (design section 5; B-LHA-5, 6, 8, 9, 10, 13 to 18)

LABELS = {"administeringIdentity": "OWNER_ADMIN", "loginIdentity": "OWNER_LOGIN", "loginBaselineRole": "OWNER_LOGIN_BASELINE",
          "observer": "OBSERVER", "operatorUid": "OPERATOR_UID", "loginTriggerGroup": "PLANEON_LOGIN_TRIGGER"}
IAP_RANGE = "35.235.240.0/20"
OS_LOGIN_METADATA = [{"key": "enable-oslogin", "value": "TRUE"}, {"key": "enable-oslogin-2fa", "value": "TRUE"},
                     {"key": "block-project-ssh-keys", "value": "TRUE"}]
REFUSED_METADATA = ("ssh-keys", "sshKeys", "startup-script", "shutdown-script", "enable-guest-attributes")
AGENT_ON = ["OS_LOGIN_NSS_PAM", "CLOCK_SYNC"]
AGENT_OFF = ["METADATA_ACCOUNT_MANAGEMENT", "METADATA_SSH_KEY_MANAGEMENT", "METADATA_SCRIPT_EXECUTION",
             "NETWORK_INTERFACE_MANAGEMENT", "DIAGNOSTICS", "SNAPSHOT_HOOKS"]
INVENTORY_SCOPE = ["SYSTEM_TREES", "/opt/planeon/tools", "/opt/planeon/cache", "/opt/planeon/python", "/opt/planeon/bin",
                   "/opt/planeon/work", "/etc", "BOOT_CHAIN"]
LOGIN_FORBIDDEN = (
    (("compute.instances.osAdminLogin",),
     "the login identity's effective compute.instances.osAdminLogin is checked absent at steps 1, 10 and 15"),
    (("resourcemanager.projects.setIamPolicy", "compute.instances.setIamPolicy", "iam.serviceAccounts.setIamPolicy",
      "iam.roles.create", "iam.roles.update"),
     "the login identity's IAM-changing permissions are checked absent at steps 1, 10 and 15"),
    (("resourcemanager.folders.setIamPolicy", "resourcemanager.organizations.setIamPolicy"),
     "the login identity's folder and organization IAM-changing permissions are checked absent at steps 1, 10 and 15"),
    (("iam.serviceAccounts.actAs", "iam.serviceAccounts.getAccessToken", "iam.serviceAccounts.signBlob",
      "iam.serviceAccounts.signJwt", "iam.serviceAccounts.implicitDelegation", "iam.serviceAccounts.getOpenIdToken",
      "iam.serviceAccountKeys.create"),
     "the login identity's service-account impersonation and key permissions are checked absent at steps 1, 10 and 15"),
    (("resourcemanager.tagValueBindings.create", "resourcemanager.tagValueBindings.delete"),
     "the login identity's tag-binding permissions are checked absent at steps 1, 10 and 15"))
ADMIN_FORBIDDEN = ["compute.instances.osLogin", "compute.instances.osAdminLogin", "iap.tunnelInstances.accessViaIAP"]
LOGIN_RESOURCES = ["RUN_PROJECT", "EACH_INSTANCE", "EACH_SERVICE_ACCOUNT", "EVERY_ANCESTOR_FOLDER", "ORGANIZATION"]
ADMIN_RESOURCES = ["RUN_PROJECT", "EVERY_ANCESTOR_FOLDER", "ORGANIZATION"]
GRANT_PATHS = ["DIRECT", "BASIC_ROLE", "CUSTOM_ROLE", "INHERITED", "GROUP", "DOMAIN", "PRINCIPAL_SET", "CONDITIONAL"]
CHECK_ROWS = [(1, "OWNER_LOGIN"), (10, "OWNER_LOGIN"), (15, "OWNER_LOGIN"), (1, "OWNER_ADMIN"), (10, "OWNER_ADMIN"),
              (15, "OWNER_ADMIN")]
AUDIT_LISTS = ["IAM_POLICY_CHANGE_RUN_PROJECT", "IAM_POLICY_CHANGE_INSTANCE", "CUSTOM_ROLE_CREATE", "CUSTOM_ROLE_UPDATE",
               "CUSTOM_ROLE_DELETE", "CUSTOM_ROLE_UNDELETE"]
AUDIT_EXPECTED = [{"entry": "STEP_10_ADMIN_LOGIN_BINDING_REMOVAL", "by": "OWNER_ADMIN"},
                  {"entry": "NON_ADMIN_LOGIN_GRANT_IF_IN_WINDOW", "by": "OWNER_ADMIN"},
                  {"entry": "TEARDOWN_REVOCATIONS", "by": "OWNER_ADMIN"}]
RUNTIME_WRITES = ["HOST_LEDGER_LAUNCHER", "HOST_LEDGER_PROXY_CLIENT", "HOST_LEDGER_PROXY_SERVER", "PREFLIGHT_RECORDS",
                  "INSTALLER_LOG", "EVIDENCE_SINK", "JOURNAL", "CLUSTER_STATE"]
COST_ITEMS = ["PROXY_OPERATOR_HOST_MACHINE_HOURS", "PROXY_OPERATOR_HOST_BOOT_DISK", "CLUSTER_NODE_MACHINE_HOURS",
              "CLUSTER_NODE_BOOT_DISK", "TEMPORARY_BUILD_DISK", "STORED_CUSTOM_IMAGE"]
ADMIN_CLOUD_STEPS = (2, 3, 5, 6, 16)
PROFILE_ROWS = ["SELINUX_ENFORCING", "REVIEWED_EXACT_BINARY_POLICY", "EXT4_VERITY_ROOT_AND_MEASUREMENTS",
                "CGROUP_V2_AND_PLANEON_LIVE_CGROUPS", "ONE_ENROLLED_BPF_PROGRAM_PER_HOOK_PER_ROLE",
                "KERNEL_RELEASE_NOTES_DIGEST_AND_BOOT_ID", "SERIALISED_POLICY_FILTER_CGROUP_LABEL_AND_EXECUTABLE_CHANGES"]
LIMIT_KINDS = ["GROUP_MEMBERSHIP_CHANGE", "DOMAIN_MEMBERSHIP_CHANGE", "PRINCIPAL_SET_MEMBERSHIP_CHANGE", "FOLDER_BINDING",
               "ORGANIZATION_BINDING"]
# The id-keyed lists c7 closes here (MON-LHA-C7-SYSTEMATIC (i)): what the host inventory leaves out (design section 5
# hostInventory, lines 351-356; B-LHA-9), the package sources (lines 455-459), the lease bindings (lines 411-416,
# LHA5-7), the runbook's steps (lines 485-500) and what teardown keeps (lines 430-431, LHA5-8; B-LHA-18).
LEFT_OUT = ["CLUSTER_STATE", "HOST_NONCE_LEDGER", "LOGS", "STEP_10_FILES", "SIGNED_DROP_TARGETS", "PER_RUN_PRIVATE_HALVES",
            "PER_RUN_CERTIFICATE_REQUESTS"]
PACKAGE_SOURCES = ["DISTRIBUTION_PACKAGES", "FIREJAIL", "LOCKED_PYTHON_AND_NODE"]
LEASE_ROLES = ["IAP_TUNNEL", "OS_LOGIN_ADMIN", "OS_LOGIN"]
RUNBOOK_IDS = ["PREPARE_OR_CONFIRM_THE_RUN_PROJECT", "VPC_AND_FIREWALL", "CREATE_THE_CLUSTER_NODE", "SETUP_WINDOW_BUILD",
               "IMAGE_INVENTORY_CUSTOM_IMAGE_AND_PROXY_HOST", "CLOSE_EGRESS", "EXTERNAL_OPERATOR_INSTALLATION",
               "LAUNCHERS_UNITS_KEYS_AND_REQUESTS", "FREEZE_INVENTORIES_AND_ROOT_ALIAS_CHECK", "T1_INSTALL_AND_REVOKE",
               "PREFLIGHT", "T2", "DROP", "CAMPAIGN", "RECHECK_AND_EXPORT", "TEARDOWN"]
TEARDOWN_KEEPS = ["OWNER_LOGIN_BASELINE_ROLE", "OWNER_LOGIN_BASELINE_BINDING", "OWNER_ADMIN_BINDING"]


def check_recipe(doc: Any, schema: dict) -> None:
    shape(doc, schema)
    free_text(doc)
    named_text(doc)
    require(doc["roleLabels"] == LABELS, "role labels only: OWNER_ADMIN, OWNER_LOGIN and OWNER_LOGIN_BASELINE name the "
            "two identities and the custom role")
    project = doc["project"]
    require(project["separateFromLabFoundation"] and project["runsAtATime"] == 1 and not project["computeBetweenRuns"]
            and not project["defaultNetwork"], "the run project is LAB-RUNPLAN-001's: separate, one run at a time, no "
            "compute between runs, no default network")
    require(not project["cloudNat"], "no Cloud NAT in the run project")
    require(not project["privateGoogleAccess"], "Private Google Access is off")
    hosts = {h["role"]: h for h in doc["hosts"]}
    require([h["role"] for h in doc["hosts"]] == ["PROXY_OPERATOR_HOST", "CLUSTER_NODE"]
            and all(h["architecture"] == "AMD64" for h in doc["hosts"]),
            "two AMD64 hosts per run: the proxy/operator host and the cluster node (Q-LHA-14)")
    proxy = hosts["PROXY_OPERATOR_HOST"]
    require(not proxy["rootKubeconfig"] and not proxy["containerRuntimeSocket"],
            "no kubeconfig or container-runtime socket on the proxy/operator host")
    require(proxy["boots"] == "CUSTOM_IMAGE" and hosts["CLUSTER_NODE"]["boots"] == "PINNED_FAMILY_IMAGE",
            "the proxy/operator host boots the custom image and the cluster node the pinned family image")
    require(proxy["filesAfterRevocation"] == "SIGNED_DROP_INSTALLER_ONLY"
            and hosts["CLUSTER_NODE"]["filesAfterRevocation"] == "NONE",
            "after the revocation only the signed-drop installer changes root-owned files, and the node needs none")
    flows = doc["internalFlows"]
    require([(f["id"], f["from"], f["to"], f["protocol"]) for f in flows]
            == [("F1", "PROXY_OPERATOR_HOST", "CLUSTER_NODE", "tcp"), ("F2", "CLUSTER_NODE", "PROXY_OPERATOR_HOST", "tcp")],
            "the only internal paths are F1 and F2")
    upstream = doc["campaignProxyUpstream"]
    require("CAMPAIGN_PROXY_UPSTREAM" in flows[0]["purposes"] and upstream["flow"] == "F1"
            and upstream["targets"] == ["KUBERNETES_API_SERVER"]
            and set(upstream["refusedTargets"]) >= {"NODE_PORT", "SERVICE_ADDRESS", "POD_ADDRESS"},
            "every campaign-proxy upstream goes through the API server on F1; a NodePort, Service or Pod address "
            "target is refused")
    trust = doc["localRegistryTrust"]
    require(trust["host"] == "CLUSTER_NODE" and trust["installedAtStep"] in (7, 8) and trust["beforeRevocation"],
            "the node's LOCAL_REGISTRY trust file is installed at step 7 or 8, before the revocation")
    firewall = doc["firewall"]
    require(firewall["ingress"] == [{"id": "IAP_SSH", "sourceRange": IAP_RANGE, "protocol": "tcp", "port": 22,
                                     "targets": "BOTH_HOSTS"}] and firewall["internal"] == ["F1", "F2"],
            "ingress is IAP tcp 22 and the listed internal flows only")
    allow = firewall["setupWindowAllow"]
    require(allow["byteCeiling"] != "NONE" and not allow["paidFirewallFeature"],
            "the setup window's allow rule has a byte ceiling and uses no paid firewall feature")
    require(allow["removedAtStep"] == 6 and firewall["egressDenyAll"]["createdAtStep"] == 2
            and firewall["egressDenyAll"]["belowSetupWindowAllow"],
            "the deny-all egress rule is made at step 2 below the window's allow rule, which step 6 removes")
    machine = doc["machine"]
    require(not machine["serviceAccount"] and machine["scopes"] == [], "a host has no service account and no scopes")
    keys = [item["key"] for item in machine["metadata"]]
    require(not any(key.startswith(REFUSED_METADATA) for key in keys),
            "metadata carries no SSH keys, startup or shutdown script or guest attributes")
    require(machine["metadata"] == OS_LOGIN_METADATA, "OS Login and its 2-step verification are on, and project SSH keys "
            "are blocked")
    require(all(machine["shieldedVm"].values()), "Shielded VM is on: secure boot, vTPM and integrity monitoring")
    require(not machine["serialPortAccess"], "serial-port access is off")
    duration = machine["maxRunDuration"]
    require(duration["set"] and duration["action"] == "DELETE" and duration["endsNoLaterThan"] == "LEASE_END",
            "a maximum run duration with a delete action is set, ending no later than the lease")
    maintenance = machine["maintenance"]
    require(maintenance["onHostMaintenance"] == "MIGRATE" and not maintenance["automaticRestartInLease"]
            and maintenance["rebootAfterQualification"] == "INVALIDATES_QUALIFICATION",
            "no automatic restart inside the lease: live migration, and a reboot after qualification invalidates it")
    agent = doc["guestAgent"]
    require(agent["on"] == AGENT_ON and agent["off"] == AGENT_OFF,
            "only OS Login and clock sync stay on in the guest agent")
    image = doc["image"]
    require(image["architecture"] == "AMD64", "an image is AMD64")
    require(image["licenceCharge"] == "NONE", "an image has licenceCharge NONE")
    require(image["family"] in image["allowedFamilies"] and image["selinux"] == "ENFORCING",
            "the image is a listed SELinux-enforcing, no-licence-fee RHEL-10-compatible family")
    custom = image["customImage"]
    require(custom["startsFrom"] == "PINNED_FAMILY_IMAGE_OWN_FILES"
            and custom["verifiedAgainst"] == "PINNED_IMAGE_INVENTORY_TAKEN_BEFORE_ANY_INSTALL_ON_THE_NODE",
            "the built root starts from the pinned family image's own files, verified against its inventory")
    require(custom["selinuxLabels"] == "FROM_OWN_POLICY_FILE_CONTEXTS_AT_STEP_4" and not custom["firstBootRelabel"]
            and "selinuxLabel" in image["imageDigest"]["inventoryFields"] and image["preflightComparesLabels"],
            "the built root is labelled at step 4 from its own file contexts, the inventory records each label, a "
            "first-boot relabel is refused and preflight compares the labels")
    require(image["kernel"]["release"] == "PINNED_IN_PLAN" and image["kernel"]["checkedInBuiltRootAtStep"] == 5,
            "the plan pins the kernel release and step 5 checks it in the built root")
    require(custom["proxyOperatorHostBootsRecordedImage"] and custom["buildDiskDeletedAtStep"] == 5,
            "the proxy/operator host boots the recorded custom image, and no build disk is left after step 5")
    require(custom["rootFilesystem"] == "EXT4_WITH_VERITY" and custom["usrOnRoot"],
            "the custom image's root, /usr included, is ext4 with verity (Q-LHA-15)")
    digest = image["imageDigest"]
    require(digest["is"] == "SHA256_OF_THE_CUSTOM_IMAGE_INVENTORY" and digest["takenAtStep"] == 5
            and digest["from"] == "THE_BUILD_DISK_MOUNTED_READ_ONLY" and digest["recomputedOffHost"],
            "imageDigest is the custom image inventory's sha256, taken at step 5 from the read-only build disk and "
            "recomputed off host")
    inventory = doc["hostInventory"]
    require([r["host"] for r in inventory["records"]] == ["PROXY_OPERATOR_HOST", "CLUSTER_NODE"]
            and all(r["scope"] == INVENTORY_SCOPE for r in inventory["records"]),
            "each host has its own inventory, with its scope")
    require(inventory["frozenAtStep"] == 9 and inventory["frozenAtStep"] > max(inventory["coveredInstallSteps"]),
            "the inventories are frozen at step 9, after the last install that changes a covered path")
    left = _closed(inventory["leftOut"], "what", LEFT_OUT, "everything the host inventory leaves out is listed, each "
                   "with its own record (design section 5 hostInventory; B-LHA-9)", "host-recipe.json hostInventory.leftOut",
                   ordered=False)
    require(left["PER_RUN_PRIVATE_HALVES"]["ownRecord"] == "SPKI_DIGEST_ONLY"
            and left["PER_RUN_CERTIFICATE_REQUESTS"]["ownRecord"] == "SPKI_DIGEST_ONLY",
            "the private halves and requests are left out of the inventory, each with a record of its SPKI digest only")
    require(inventory["bootEventLogsExportedAtStep"] == 9, "both hosts' boot event logs are exported at step 9")
    require(inventory["imageReverification"]["where"] == "OFF_HOST_IN_T1",
            "the image re-verification runs off host in T1, not at preflight")
    profile = {row["prerequisite"]: row for row in doc["profile"]}
    require([row["prerequisite"] for row in doc["profile"]] == PROFILE_ROWS,
            "MET-REPAIR-015's profile lists its seven prerequisites, each once, in order")
    require(profile["SELINUX_ENFORCING"]["value"] == "ENFORCING", "SELinux is enforcing")
    require(profile["REVIEWED_EXACT_BINARY_POLICY"]["value"] == "DENY_UNKNOWN_1",
            "the active policy's deny_unknown is 1")
    _check_access(doc["access"])
    egress = doc["egress"]
    require(not egress["atCampaign"]["externalAddress"] and not egress["atCampaign"]["allowEgressRule"],
            "no external address or allow-egress rule at campaign time")
    require(egress["expectedExceptions"] == ["METADATA_ADDRESS", "F1", "F2"],
            "the closure probe's expected exceptions are the metadata address, F1 and F2")
    # LHA-C2-1 (i): Q-LHA-11 (a), no paid firewall feature; one would be spend for the monitor (design section 5).
    require(not egress["paidFirewallFeature"], "egress uses no paid firewall feature; one would be spend for the monitor "
            "(Q-LHA-11 (a))")
    packages = doc["packages"]
    require(packages["automaticUpdaters"] == "OFF", "every automatic updater is off")
    _closed(packages["sources"], "what", PACKAGE_SOURCES, "the package sources are the dated distribution snapshot, "
            "Firejail from EPEL and the locked Python and Node (design section 5 packages)",
            "host-recipe.json packages.sources", ordered=False)
    require(all("FILE_SHA256" in source["pin"] for source in packages["sources"]), "every package is pinned by its file "
            "digest")
    require(doc["source"]["withGit"] and doc["source"]["treeSha256"], "the source transfer carries .git and treeSha256")
    # LHA-C2-1 (j): no repository credential on the host (DESIGN.r7.md line 97; runbook step 4).
    require(not doc["source"]["repositoryCredentialOnHost"], "no repository credential is on the host: the checkout is "
            "transferred by digest over the IAP tunnel (design section 2; runbook step 4)")
    writes = doc["runtimeRootWrites"]
    require([w["id"] for w in writes] == RUNTIME_WRITES,
            "the root writes after the revocation are the closed list of runtime state paths and the listed drop "
            "targets")
    require(len({w["path"] for w in writes}) == len(writes) and all(type(w["writer"]) is str for w in writes),
            "each runtime state path is listed once, with its one writer")
    cost = doc["costScope"]
    require([c["item"] for c in cost] == COST_ITEMS and all(c["planLineItem"] for c in cost),
            "every paid costScope item is a plan line item")
    teardown = doc["teardown"]
    require("CUSTOM_IMAGE" in teardown["deletes"] and "ANY_BUILD_DISK_LEFT" in teardown["deletes"],
            "teardown deletes the custom image and any build disk left")
    require(teardown["privateHalvesEndWith"] == "INSTANCE_AND_DISK_DELETION" and teardown["check"] ==
            "TEARDOWN_REPORT_ZERO_COUNTS", "the private halves end when the instances and their disks are deleted, and "
            "the teardown report's zero counts are the check")
    runbook = doc["runbook"]
    require([s["step"] for s in runbook] == list(range(1, 17)) and all(s["check"] for s in runbook),
            "the runbook has steps 1 to 16, each with its check")
    _closed(runbook, "id", RUNBOOK_IDS, "the runbook's sixteen steps are the design's, in order (design section 5 "
            "runbook)", "host-recipe.json runbook")
    require(all(s["cloudActionsBy"] == "OWNER_ADMIN" for s in runbook if s["step"] in ADMIN_CLOUD_STEPS)
            and all(s["cloudActionsBy"] in ("OWNER_ADMIN", "NONE") for s in runbook),
            "the administering identity, OWNER_ADMIN, performs the cloud actions of runbook steps 2, 3, 5, 6 and 16")


def _check_access(access: dict) -> None:
    require(access["ssh"] == {"only": "IAP", "sourceRange": IAP_RANGE, "protocol": "tcp", "port": 22, "onPaper": True},
            "SSH only through IAP: 35.235.240.0/20, tcp 22")
    two = "two identities: the login identity for SSH only, and the administering identity, which alone administers IAM"
    identities = _closed(access["identities"], "label", ["OWNER_LOGIN", "OWNER_ADMIN"], two,
                         "host-recipe.json access.identities")
    require(identities["OWNER_LOGIN"]["use"] == "SSH_ONLY" and not identities["OWNER_LOGIN"]["administersIam"]
            and identities["OWNER_ADMIN"]["administersIam"], two)
    require(identities["OWNER_LOGIN"]["osLogin"] and identities["OWNER_LOGIN"]["twoStepVerification"],
            "OS Login and its 2-step verification are on")
    # LHA-C2-1 (g): B-LHA-18, the owner's "No login for admin id (Recommended)" (Q-LHA6-3).
    require(not identities["OWNER_ADMIN"]["osLogin"], "the administering identity, OWNER_ADMIN, has no OS Login: no "
            "login for the admin id (B-LHA-18; Q-LHA6-3)")
    baseline = access["loginBaseline"]
    require(baseline["basicRole"] == "NONE", "a basic role in the login identity's baseline is refused")
    everything = [p for group, _ in LOGIN_FORBIDDEN for p in group]
    require(baseline["kind"] == "CUSTOM_ROLE" and set(baseline["excludes"]) >= set(everything)
            and baseline["permittedPurpose"] == "SSH_THROUGH_IAP_AND_OS_LOGIN_ONLY",
            "the login baseline custom role is for SSH only and excludes admin login, IAM-changing, service-account, key "
            "and tag-binding permissions")
    require(baseline["recordedInPlan"]["exactPermissionList"], "the custom role's exact permission list is recorded in "
            "the plan")
    life = baseline["lifecycle"]
    require(life["createdBy"] == life["boundBy"] == "OWNER_ADMIN" and life["keptBetweenRuns"] and not life["deletedAtTeardown"],
            "the administering identity makes and binds the custom role before approval; it is kept between runs")
    admin = access["adminBaseline"]
    require(set(admin["holdsNoLoginPermission"]) >= set(ADMIN_FORBIDDEN) and admin["on"] == "RUN_PROJECT_AND_EVERY_ANCESTOR"
            and admin["countsAmongBaselineBindings"],
            "OWNER_ADMIN holds no login permission on the run project or any ancestor, and its binding is a baseline "
            "binding")
    require(access["betweenRuns"]["confirmedAtStep"] == 1 and "OWNER_ADMIN_BINDING" in access["betweenRuns"]["bindings"],
            "between runs the IAM policy holds only the baseline bindings, confirmed at step 1")
    for binding in access["leaseBindings"]:
        require(binding["grantedBy"] == binding["revokedBy"] == "OWNER_ADMIN",
                "only OWNER_ADMIN grants and revokes the run's bindings")
        require(binding["counted"] == "IAM_BINDINGS_ADDED", "every lease-time binding is counted under IAM_BINDINGS_ADDED")
    admin_login = [b for b in access["leaseBindings"] if b["role"] == "OS_LOGIN_ADMIN"]
    require(len(admin_login) == 1 and admin_login[0]["revokedAtStep"] == 10,
            "the OS Login admin binding is a separate project binding, revoked at step 10")
    bindings = _closed(access["leaseBindings"], "role", LEASE_ROLES, "the lease bindings are the IAP tunnel role, the OS "
                       "Login admin role and the non-admin OS Login role (design section 5 access; LHA5-7)",
                       "host-recipe.json access.leaseBindings", ordered=False)
    # LHA-C2-1 (k): every lease binding but the admin-login one ends at the step-16 teardown, which keeps the baseline
    # custom role and its binding, and OWNER_ADMIN's (LHA5-8; B-LHA-18; runbook step 16).
    require(all(b["revokedAtStep"] == 16 for role, b in bindings.items() if role != "OS_LOGIN_ADMIN")
            and access["teardown"]["keeps"] == TEARDOWN_KEEPS,
            "the administering identity revokes every other lease binding at the step-16 teardown, which keeps the "
            "baseline custom role, its binding and OWNER_ADMIN's binding (LHA5-8; runbook step 16)")
    revocation = access["revocation"]
    require(revocation["atStep"] == 10 and revocation["by"] == "OWNER_ADMIN" and not revocation["denyPolicy"]
            and not revocation["folderOrOrganizationGrant"],
            "OWNER_ADMIN removes the admin-login binding at step 10; no deny policy and no folder or organization grant")
    require(revocation["thenWaitsForPropagation"], "the step-10 and step-15 checks wait for IAM propagation first")
    # LHA-C2-1 (h): B-LHA-10, every session opened with admin on both hosts ends at step 10.
    require(revocation["endsAdminSessionsOn"] == ["PROXY_OPERATOR_HOST", "CLUSTER_NODE"],
            "the step-10 revocation ends every admin session on both hosts (B-LHA-10)")
    checks = access["effectiveChecks"]
    require([(c["step"], c["identity"]) for c in checks] == CHECK_ROWS,
            "the effective checks run at steps 1, 10 and 15, for the login and the administering identity")
    for check in checks:
        require(check["runBy"] != "OWNER_LOGIN" and access["permissionMechanism"]["neverRunBy"] == "OWNER_LOGIN",
                "the effective and audit-log checks are run by the observer or OWNER_ADMIN, never the login identity")
        require(check["onFinding"] == "REFUSE_RUN_EVIDENCE", "any finding refuses the run's evidence")
        require(check["step"] == 1 or check["propagationWait"] == "BEFORE_CHECK",
                "the step-10 and step-15 checks wait for IAM propagation first")
        require(set(check["grantPaths"]) >= set(GRANT_PATHS) and check["conditionalBindingIsGrant"],
                "the effective checks count basic, custom, inherited, group, domain, principal-set and conditional grants")
        if check["identity"] == "OWNER_LOGIN":
            for group, message in LOGIN_FORBIDDEN:
                require(set(check["absent"]) >= set(group), message)
            require(set(check["resources"]) >= set(LOGIN_RESOURCES),
                    "the login identity is checked on the project, each instance, each service account, every ancestor "
                    "folder and the organization")
            require(check["checksNoBasicRole"], "a basic role in the login identity's baseline is refused")
            require(check["checksPermissionListAgainstPlan"], "the custom role's permission list equals the plan's at "
                    "steps 1, 10 and 15")
        else:
            require(set(check["absent"]) >= set(ADMIN_FORBIDDEN) and set(check["resources"]) >= set(ADMIN_RESOURCES),
                    "OWNER_ADMIN holds no login permission on the run project or any ancestor, confirmed at step 1 and "
                    "tested at steps 10 and 15")
    mechanism = access["permissionMechanism"]
    require(mechanism["ancestors"]["runBy"] == "OWNER_ADMIN" and mechanism["membership"]["runBy"] == "OWNER_ADMIN"
            and mechanism["projectAndInstances"]["runBy"] == "OBSERVER",
            "the effective and audit-log checks are run by the observer or OWNER_ADMIN, never the login identity")
    sessions = access["sessionChecks"]
    require(sessions["atStep"] == 10 and sessions["after"] == "IAM_PROPAGATION"
            and sessions["endsEverySessionOpenedWithAdminOn"] == ["PROXY_OPERATOR_HOST", "CLUSTER_NODE"]
            and sessions["identities"] == ["OWNER_LOGIN", "OWNER_ADMIN"]
            and sessions["confirms"] == ["NO_PROCESS_OR_SESSION_STARTED_BEFORE_REVOCATION", "NO_OS_LOGIN_SUDOERS_ENTRY",
                                         "FRESH_LOGIN_CANNOT_USE_SUDO"],
            "at step 10 every admin session on both hosts ends, and no earlier session, sudoers entry or sudo use remains "
            "for either identity")
    require(sessions["preRevocationAdminSessionAliveAtPreflight"] == "REFUSES_RUN_EVIDENCE",
            "an admin session from before the revocation alive at preflight refuses the run's evidence")
    audit = access["auditLogCheck"]
    require(audit["log"] == "ADMIN_ACTIVITY" and audit["from"] == "STEP_10_REVOCATION_ENTRY"
            and audit["to"] == "END_OF_TEARDOWN" and set(audit["lists"]) >= set(AUDIT_LISTS),
            "the audit-log check lists every IAM policy change and custom-role change from the step-10 revocation entry "
            "to the end of teardown")
    require(audit["runBy"] != "OWNER_LOGIN", "the effective and audit-log checks are run by the observer or OWNER_ADMIN, "
            "never the login identity")
    require(audit["expected"] == AUDIT_EXPECTED, "each expected audit entry is the plan's, made by OWNER_ADMIN")
    require(audit["anyOtherEntry"] == "REFUSES_RUN_EVIDENCE_WHATEVER_ITS_PRINCIPAL"
            and audit["anyCustomRoleChange"] == "REFUSES_RUN_EVIDENCE",
            "any other audit entry, and any custom-role change, refuses the run's evidence")
    require(audit["finalSpanCheckedAfterTeardownCompletes"] and audit["evidenceAcceptedOnlyAfterThisCheck"],
            "the final span is checked after teardown completes, and the evidence counts only after it passes")
    limit = access["acceptedLimit"]
    require(limit["decision"] == "Q-LHA5-1" and not limit["auditLogDetectsThem"] and limit["grantKinds"] == LIMIT_KINDS
            and limit["detectedOnlyBy"] == ["EFFECTIVE_CHECK_STEP_10", "EFFECTIVE_CHECK_STEP_15"]
            and limit["notDetected"] == ["A_GRANT_MADE_AND_REMOVED_BETWEEN_STEPS_10_AND_15", "A_GRANT_MADE_AFTER_STEP_15"]
            and limit["caughtByTheAuditLogCheck"]
            == "A_RUN_PROJECT_OR_INSTANCE_BINDING_TO_ANY_PRINCIPAL_GROUPS_INCLUDED_THROUGH_TEARDOWN",
            "group, domain and principal-set membership changes and folder and organization bindings are detected only "
            "by the step-10 and step-15 effective checks, not blocked (the owner's accepted limit); a run-project or "
            "instance binding to any principal, groups included, is caught by the audit-log check through teardown")
    # LHA-C2-1 (f): the owner's Q-LHA5-1 words, as B-LHA-14 quotes them.
    require(limit["words"] == "detected by the effective check, not blocked",
            "the accepted limit carries the owner's Q-LHA5-1 words verbatim: \"detected by the effective check, not "
            "blocked\" (B-LHA-14)")
    require(access["afterRevocationRootFiles"] == "SIGNED_DROP_INSTALLER_ONLY",
            "after the revocation only the signed-drop installer changes root-owned files")


# ---------------------------------------------------------------------------------------------------------------------
# launcher-install.json (design section 6; B-LHA-1, 4, 5, 11)

PRIVILEGED_ACTIONS = ["STEP_11_PREFLIGHT", "STEP_13_PICKUP", "STEP_14_LAUNCH", "STEP_15_EXPORT"]
PROBE_SCOPE = ["PROXY_OPERATOR_HOST_CREDENTIALS", "PROXY_OPERATOR_HOST_SOCKETS", "TRIGGER_UNIT_ENDPOINTS",
               "NO_KUBECONFIG_OR_RUNTIME_SOCKET", "CLUSTER_NODE_REACHABLE_ONLY_ON_F1", "GUEST_AGENT_LOCAL_SOCKETS",
               "OS_LOGIN_LOCAL_SOCKETS", "METADATA_ADDRESS"]
FILE_HANDLING = ["REGULAR_FILES_ONLY", "NO_FOLLOW_OPENS", "NO_HARDLINKS", "COPY_INTO_ROOT_OWNED_STAGING",
                 "SHA256_OVER_THE_STAGED_COPY", "ATOMIC_RENAME_INTO_THE_TARGET", "OWNER_AND_MODE_FROM_THE_FIXED_LIST"]
DROP_BINDS = ["PLAN_SHA256", "INSTANCE_IDENTITY", "STEP_11_BOOT_ID", "VALIDITY_WINDOW_ENDING_NO_LATER_THAN_THE_LEASE"]
INSTALLS_ONLY_IF = ["DROP_MANIFEST_VERIFIES", "MANIFEST_LISTS_EXACT_TARGET_AND_SHA256", "TARGET_AND_MODE_ON_THE_FIXED_LIST",
                    "BINDINGS_MATCH_THIS_HOST_BOOT_AND_WINDOW"]
OTHER_SIGNED = ["harness.planeon.ai/trusted-runner-manifest/v1alpha1", "planeon.linux-runner-policy/v3"]
FIXED_TARGETS = ["CAMPAIGN_PROXY_SERVER_TLS_CERTIFICATE", "CAMPAIGN_PROXY_CLIENT_MTLS_CERTIFICATE", "OFFLINE_MANIFEST",
                 "OFFLINE_MANIFEST_SIGNATURE", "LIVE_MANIFEST", "LIVE_MANIFEST_SIGNATURE"]
# The id-keyed lists c7 closes here (MON-LHA-C7-SYSTEMATIC (i)): the trust mounts (design section 6, lines 559-560) and
# the operator install steps (lines 504, 524-560; runbook steps 8, 10 and 13).
TRUST_MOUNTS = ["/etc/planeon/trust/release-trust-bundle.json", "/etc/planeon/trust/tenant-trust-bundle.json"]
LAUNCHER_STEPS = ["INSTALL_OFFLINE_LAUNCHER_BYTES", "INSTALL_OPERATOR_MD_LAYOUT", "CREATE_OPERATOR_UID_AND_TRIGGER_GROUP",
                  "INSTALL_SIGNED_DROP_INSTALLER", "INSTALL_TRIGGER_UNITS", "GENERATE_PRIVATE_HALVES_AND_REQUESTS",
                  "ISSUE_KUBERNETES_PROXY_SERVER_MTLS_FROM_THE_CLUSTER_CA",
                  "INSTALL_POLICY_CUSTODY_BUNDLES_AND_REVOCATION", "DROP_CERTIFICATES_MANIFESTS_AND_SIGNATURES",
                  "INSTALL_LIVE_LAUNCHER"]


def check_launcher(doc: Any, schema: dict, recipe: dict) -> None:
    shape(doc, schema)
    free_text(doc)
    named_text(doc)
    require(not doc["repositoryInstalls"], "the repository never installs anything; each step is an operator duty")
    uid = doc["operatorUid"]
    require(uid["label"] == "OPERATOR_UID" and not uid["nameAndUidPublished"] and uid["createdAtStep"] == 8,
            "the policy's operatorUid is named by its role label only")
    installer = doc["signedDropInstaller"]
    require(installer["installedAtStep"] == 8 and installer["inHostInventory"] and installer["runsAs"] == "ROOT"
            and not installer["operatorArguments"],
            "the signed-drop installer is a reviewed root component, installed at step 8 and inventoried")
    require(installer["verifier"] == "KIT_ED25519_VERIFY_ONLY" and not installer["newCryptography"]
            and not installer["certificateChainMode"] and installer["signer"] == "LINUX_RUNNER_MANIFEST",
            "the installer verifies Ed25519 only, with the kit's verifier and the pinned LINUX_RUNNER_MANIFEST key")
    drop = installer["dropManifest"]
    require(drop["schemaId"] == VERSIONS["drop"] and drop["schema"] == SCHEMA_PATHS["drop"]
            and set(drop["refuses"]) >= set(OTHER_SIGNED),
            "the drop manifest has its own closed schema; a runner manifest or policy offered as one is refused")
    require(drop["signaturePayload"] == "UTF8_SCHEMA_ID_THEN_0x00_THEN_EXACT_BYTES",
            "the drop manifest's signature covers its schema id, one 0x00 byte and its exact bytes")
    require(drop["binds"] == DROP_BINDS, "the drop manifest binds the plan sha256, the instance, the step-11 boot_id and "
            "a validity window ending no later than the lease")
    require(drop["authorizes"] == "PLACEMENT_ONLY", "the drop manifest authorizes placement only")
    require(installer["installsOnlyIf"] == INSTALLS_ONLY_IF,
            "a drop is installed only with a verified drop manifest listing its exact target and sha256 on the fixed list")
    require(installer["fileHandling"] == FILE_HANDLING,
            "the installer's file handling: regular files, no-follow, no hardlinks, staged copy, sha256 over it, atomic "
            "rename, fixed owner and mode")
    directory = installer["dropDirectory"]
    require(directory["owner"] == "ROOT" and directory["parentChain"] == "ROOT_OWNED_NOT_GROUP_OR_WORLD_WRITABLE"
            and directory["otherwiseRefused"], "a drop directory or parent chain not as specified is refused")
    staging = installer["stagingDirectory"]
    require(directory["group"] == "PLANEON_LOGIN_TRIGGER" and directory["mode"] == "1730"
            and staging["owner"] == staging["group"] == "ROOT" and staging["mode"] == "0700",
            "the drop directory is root-owned, group PLANEON_LOGIN_TRIGGER, mode 1730, and the staging directory "
            "root-owned 0700")
    targets = installer["fixedTargets"]
    require([t["id"] for t in targets] == FIXED_TARGETS, "the fixed target list is closed; a drop to an unlisted target "
            "is refused")
    require(all(t["path"].startswith("/etc/planeon/") and t["owner"] == "ROOT" and t["mode"] == "0444"
                and not any(part in ("", ".", "..") for part in t["path"][len("/etc/planeon/"):].split("/"))
                for t in targets) and len({t["path"] for t in targets}) == len(targets),
            "each drop target has its exact /etc/planeon path, root owner and mode")
    require(installer["refusesEverythingElse"] and installer["logsEveryAttempt"] == "/var/log/planeon/signed-drop-installer.log",
            "the installer refuses everything else and logs every attempt")
    waiting = doc["liveLauncher"]["state"] == "WAITING"
    require(all(t["state"] == ("AFTER_CONF_LIVE_005_006_CLOSE" if waiting and t["id"].startswith("LIVE_MANIFEST")
                               else "ACTIVE") for t in targets),
            "the live-manifest drop targets stay closed while the live launcher is WAITING; every other target is active")
    units = _closed(doc["triggerUnits"], "id", ["PREFLIGHT_UNIT", "EXPORT_UNIT"],
                    "one reviewed family of trigger units: one for the preflight and one for the export",
                    "launcher-install.json triggerUnits")
    for unit in units.values():
        require(not unit["operatorArguments"] and not unit["readsTriggerContent"],
                "a trigger unit runs one fixed command and takes no operator arguments")
        require(unit["installedAtStep"] == 8 and unit["inHostInventory"],
                "a trigger unit is installed at step 8 and covered by the host inventory")
        trigger = unit["trigger"]
        require(trigger["owner"] == "ROOT" and trigger["group"] == "PLANEON_LOGIN_TRIGGER"
                and trigger["mode"] in ("1730", "0660"),
                "a trigger unit's trigger is root-owned and open to the login identity's group only")
    require(units["PREFLIGHT_UNIT"]["command"] == "/opt/planeon/bin/harness-offline-launch --operator-preflight"
            and units["PREFLIGHT_UNIT"]["runsAs"] == "OPERATOR_UID",
            "the preflight unit runs the installed offline launcher's --operator-preflight as the policy's operatorUid")
    written = {w["id"] for w in recipe["runtimeRootWrites"]}
    require(all(set(u["writes"]) <= written for u in units.values()),
            "the root writes after the revocation are the closed list of runtime state paths and the listed drop "
            "targets")
    group = doc["loginTriggerGroup"]
    require(group["members"] == ["OWNER_LOGIN"] and "OPERATOR_UID" in group["excludes"],
            "the trigger group holds the login identity's account only, never the operatorUid")
    actions = doc["privilegedActions"]
    require([a["action"] for a in actions] == PRIVILEGED_ACTIONS and not any(a["loginNeedsAdmin"] for a in actions),
            "each privileged action after step 10 names its UID and how a login without admin starts it")
    require({a["action"]: (a["runsAs"], a["startedBy"]) for a in actions}
            == {"STEP_11_PREFLIGHT": ("OPERATOR_UID", "PREFLIGHT_UNIT"), "STEP_13_PICKUP": ("ROOT", "SIGNED_DROP_INSTALLER"),
                "STEP_14_LAUNCH": ("PER_CONF_LIVE_005_006", "CONF_LIVE_005_006_NON_ADMIN_ENTRY_PATH_PRECONDITION"),
                "STEP_15_EXPORT": ("ROOT", "EXPORT_UNIT")},
            "each privileged action after step 10 names its UID and how a login without admin starts it")
    runs_as = {a["startedBy"]: a["runsAs"] for a in actions}
    require(all(unit["runsAs"] == runs_as[unit["id"]] for unit in units.values())
            and units["EXPORT_UNIT"]["command"] == "/opt/planeon/bin/planeon-export",
            "each trigger unit runs as its privileged action's UID, with its fixed command")
    read_path = "every root-only record has a read path at step 15: the export unit on both hosts"
    exports = {host: e["records"] for host, e in _closed(doc["exportSet"], "host", ["PROXY_OPERATOR_HOST", "CLUSTER_NODE"],
                                                         read_path, "launcher-install.json exportSet").items()}
    require({"HOST_NONCE_LEDGER", "PREFLIGHT_RECORDS", "INSTALLER_LOG", "JOURNAL"} <= set(exports["PROXY_OPERATOR_HOST"]),
            read_path)
    # LHA-C2-1 (n): B-LHA-1, each root-only record's read path at step 15 is the export unit on every host of the export
    # set, the node (which carries EXPORT_UNIT) included.
    require(units["EXPORT_UNIT"]["hosts"] == list(exports)
            and all(h["role"] in exports for h in recipe["hosts"] if "EXPORT_UNIT" in h["carries"]),
            "the export unit runs on every host of the export set and on every host that carries it (B-LHA-1)")
    offline = doc["offlineLauncher"]
    require(offline["mode"] == "OPERATOR_PREFLIGHT_ONLY" and not offline["githubRunnerRegistered"],
            "the offline launcher runs --operator-preflight only; no runner is registered")
    require(offline["manifestSignedAt"] == "T2_AFTER_STEP_11_PREFLIGHT", "no manifest is signed before its preflight")
    require(offline["policySigner"] == offline["manifestSigner"] == "LINUX_RUNNER_MANIFEST",
            "no manifest is signed by the other launcher's key")
    require(offline["preflightProbeScope"] == PROBE_SCOPE,
            "the preflight probe scope covers the host's credentials and sockets, the agent sockets and the metadata "
            "address")
    require(offline["custodyWrittenAtStep"] == 10, "custody.json is written at step 10, before the revocation")
    # LHA-C2-1 (m): custody.json binds the public key and the launcher and policy digests (design section 6; runbook
    # step 10, OPERATOR.md step 6).
    require(offline["custodyBinds"] == ["PUBLIC_KEY", "LAUNCHER_DIGEST", "POLICY_DIGEST"],
            "custody.json binds the public key and the launcher and policy digests (design section 6; runbook step 10)")
    live = doc["liveLauncher"]
    require(live["manifestSigner"] == "LIVE_RUNNER_MANIFEST", "no manifest is signed by the other launcher's key")
    require(live["manifestSignedAfter"] == "CONF_LIVE_005_006_OWN_PREFLIGHT" and live["state"] == "WAITING",
            "no live manifest is signed before CONF-LIVE-005/006's own preflight")
    # LHA-C2-1, a self-contradiction: the live launcher's install is design only while it is WAITING (design section 6;
    # Q-LHA-7 (a)).
    require(live["designOnly"] == (live["state"] == "WAITING"),
            "the live launcher is a design-only slot while it is WAITING (design section 6; Q-LHA-7 (a))")
    require(all(m["readOnly"] and m["owner"] == "ROOT" and m["mode"] == "0444" and m["installedAtStep"] == 10
                for m in live["trustMounts"]), "the trust bundles are mounted read-only, root-owned, 0444")
    _closed(live["trustMounts"], "path", TRUST_MOUNTS, "the trust bundles are mounted at the release and tenant "
            "trust-bundle paths (design section 6)", "launcher-install.json liveLauncher.trustMounts", ordered=False)
    limits = doc["timeLimits"]
    require(limits["policyMaxHours"] == 24, "the policy lives at most 24 hours")
    require(limits["t2EndsWithinHoursOfPreflight"] == 1 and limits["manifestsSignedWithinHoursOfPreflight"] == 1,
            "T2 ends within one hour of the step-11 preflight")
    # LHA-C2-1 (l): B-LHA-11's third bullet. The offline manifest serves no normal invocation on this host, and
    # OPERATOR.md lines 110-111's one-hour age is the launcher's check at a normal invocation, which this host does not
    # make.
    require(not offline["manifestServesANormalInvocation"]
            and limits["operatorMdOneHourAge"] == "THE_LAUNCHER_CHECK_AT_A_NORMAL_INVOCATION_WHICH_THIS_HOST_DOES_NOT_MAKE",
            "the offline manifest serves no normal invocation on this host, and OPERATOR.md's one-hour age is the "
            "launcher's check at a normal invocation, which this host does not make (B-LHA-11)")
    for step in doc["steps"]:
        require(step["rollback"] not in ("", "NONE"), "each step names its rollback")
        require(step["inputDigests"] != [], "each step names its input digests")
        require(not step["movesTrustDigest"], "no step signs an unknown candidate by moving a trust digest")
    _closed(doc["steps"], "id", LAUNCHER_STEPS, "the operator install steps are the listed ones (design section 6)",
            "launcher-install.json steps", ordered=False)
    rules = doc["rules"]
    require(rules["newPolicyNeedsNewProbeEvidence"], "a new policy needs new probe evidence")
    require(rules["noManifestBeforeItsPreflight"] and rules["noManifestByTheOtherLaunchersKey"],
            "no manifest is signed before its preflight, and none by the other launcher's key")
    require(rules["afterRevocationEtcPlaneonChangesOnlyThrough"] == "SIGNED_DROP_INSTALLER_UNDER_A_VERIFIED_DROP_MANIFEST"
            and rules["loginStartedWritesAfterRevocation"] == "SIGNED_DROP_INSTALLER_ONLY",
            "after the revocation nothing under /etc/planeon changes except through the signed-drop installer")
    require(rules["preflightRecord"] == "RETAINED_AND_EXPORTED_ONLY", "the preflight record is retained and exported only")


# ---------------------------------------------------------------------------------------------------------------------
# custody-model.json (design section 7; B-LHA-2, 4, 7; LHA-CN-2)

AUTHORITIES = ["LINUX_RUNNER_MANIFEST", "LIVE_RUNNER_MANIFEST", "PLATFORM_RELEASE", "TENANT_LIVE_EXECUTION",
               "CAPACITY_OPERATOR"]
PER_RUN = ["CAMPAIGN_PROXY_SERVER_TLS", "CAMPAIGN_PROXY_CLIENT_MTLS", "KUBERNETES_PROXY_SERVER_MTLS"]
# The token sessions' order (runbook steps 10 and 12; Q-LHA-2; MON-LHA3-1-2).
T1_ORDER = ["MEASURED_BOOT_COMPARISON", "LINUX_RUNNER_MANIFEST_SIGNS_THE_OFFLINE_POLICY",
            "BUNDLES_AND_REVOCATION_MATERIAL_REFRESHED"]
T2_ORDER = ["LOCAL_CA_ISSUES_CAMPAIGN_PROXY_SERVER_TLS_AND_CAMPAIGN_PROXY_CLIENT_MTLS",
            "CAPACITY_OPERATOR_SIGNS_THE_CAPACITY_AUTHORIZATION",
            "PLATFORM_RELEASE_AND_TENANT_LIVE_EXECUTION_SIGN_THE_ENVELOPE",
            "LINUX_RUNNER_MANIFEST_SIGNS_THE_OFFLINE_MANIFEST", "LINUX_RUNNER_MANIFEST_SIGNS_THE_DROP_MANIFEST"]
ENDPOINT_KINDS = ["KUBERNETES_API_PROXY", "CAMPAIGN_PROXY", "LOCAL_REGISTRY", "LOCAL_EVIDENCE_SINK"]
PROXY_KINDS = ["KUBERNETES_API_PROXY", "CAMPAIGN_PROXY"]
ROLE_LABEL = re.compile(r"[A-Z][A-Z0-9_]{1,63}")


def check_custody(doc: Any, schema: dict, recipe: dict, launcher: dict) -> None:
    shape(doc, schema)
    free_text(doc)
    named_text(doc)
    authorities = doc["authorities"]
    require(all(ROLE_LABEL.fullmatch(a["holder"]) for a in authorities) and ROLE_LABEL.fullmatch(doc["principal"]["holder"]),
            "a holder is a role label, never a name")
    require([a["id"] for a in authorities] == AUTHORITIES, "every signing authority is listed")
    require(len({a["keyId"] for a in authorities}) == len(authorities), "no two authorities share a key id")
    require(len({a["purpose"] for a in authorities}) == len(authorities), "no two authorities share a purpose")
    require(len({a["token"] for a in authorities}) == len({a["sealedBackup"] for a in authorities}) == len(authorities),
            "each authority has its own token and sealed backup")
    for authority in authorities:
        require(authority["algorithm"] == "ED25519" and authority["generation"] == "OFFLINE_ON_A_MACHINE_THAT_NEVER_CONNECTS"
                and authority["storage"] == "HARDWARE_TOKEN_WITH_ONE_SEALED_OFFLINE_BACKUP"
                and authority["importCheckedAtCeremony"],
                "each authority is one Ed25519 key, made offline, on a hardware token with one sealed backup")
        require(not authority["ceremony"]["privateBytes"], "the ceremony records public-key digests and purposes only")
    principal = doc["principal"]
    require(principal["disclosure"] == DISCLOSURE and principal["decision"] == "Q-LHA-1"
            and _sha(principal["ownerAnswer"]) == DECISION_SHA256["Q-LHA-1"],
            "authorities share the single owner principal only with the disclosure and the owner's Q-LHA-1 (a) answer")
    # LHA-C2-1, a self-contradiction: one principal beside the single-principal disclosure (Q-LHA-1 (a)).
    require(principal["count"] == 1, "one owner principal holds every authority, as the disclosure "
            "SINGLE_PRINCIPAL_SEPARATED_KEYS states (Q-LHA-1 (a))")
    linux = authorities[0]
    require(linux["signs"] == ["OFFLINE_POLICY", "OFFLINE_MANIFEST", "DROP_MANIFEST"],
            "LINUX_RUNNER_MANIFEST signs the policy, the offline manifest and the drop manifest")
    require(doc["dropManifest"] == {"signer": "LINUX_RUNNER_MANIFEST", "authorizes": "PLACEMENT_ONLY",
                                    "liveManifestStillVerifiedUnder": "LIVE_RUNNER_MANIFEST"},
            "the drop manifest authorizes placement only; the live launcher still verifies the live manifest under "
            "LIVE_RUNNER_MANIFEST")
    per_run = "two token sessions per run; T2 ends within one hour of the preflight, with every token present"
    sessions = _closed(doc["tokenSessions"], "id", ["T1", "T2"], per_run, "custody-model.json tokenSessions")
    require(sessions["T2"]["withinOneHourOfPreflight"] and sessions["T2"]["everyTokenPresent"], per_run)
    require((sessions["T1"]["runbookStep"], sessions["T1"]["after"], sessions["T1"]["order"])
            == (10, "THE_STEP_9_INVENTORY_FREEZE", T1_ORDER)
            and (sessions["T2"]["runbookStep"], sessions["T2"]["after"], sessions["T2"]["order"])
            == (12, "THE_STEP_11_PREFLIGHT", T2_ORDER),
            "T1 runs at step 10 after the inventory freeze and T2 at step 12 after the preflight, each in the runbook's "
            "order")
    # LHA-C2-1 (b) and (c): runbook steps 10 and 12, "T1, off host" and "T2, off host"; until CONF-LIVE-005/006 close,
    # T2 signs no live manifest (step 12; design section 6).
    require(sessions["T1"]["offHost"] and sessions["T2"]["offHost"],
            "T1 and T2 are off-host token sessions (runbook steps 10 and 12: T1, off host; T2, off host)")
    require(launcher["liveLauncher"]["state"] != "WAITING"
            or doc["liveManifestInT2"] == "NOT_SIGNED_UNTIL_CONF_LIVE_005_006_CLOSE_AND_THEIR_OWN_PREFLIGHT",
            "until CONF-LIVE-005/006 close, T2 signs no live manifest (runbook step 12)")
    bundles = doc["bundles"]
    require(bundles["route"] == "LOCAL_CUSTODY_TRANSFER_ONLY" and not bundles["networkLookup"]
            and doc["revocation"]["route"] == "LOCAL_CUSTODY_TRANSFER" and not doc["revocation"]["network"],
            "revocation and bundles travel by local custody transfer only, never over the network")
    revocation = doc["revocation"]
    require(bundles["refreshedIn"] == revocation["in"] == "T1" and bundles["installedAtStep"] == 10
            and revocation["installedAtStep"] == 10 and bundles["beforeTheRevocation"] and revocation["beforeEachRun"]
            and bundles["digestsInTheSignedEnvelope"] and bundles["t2EnvelopeBindsTheInstalledBytes"],
            "the bundles and revocation material are refreshed in T1 and installed at step 10, before the revocation, "
            "with the bundle digests in the signed envelope")
    kube = doc["kubernetes"]
    require(kube["apiServerClientTrust"] == ["PER_RUN_CLUSTER_CA"] and "RELEASE_PINNED_LOCAL_CA" in kube["refusedInClientTrust"],
            "the API server's client trust never holds the release-pinned local CA")
    require(kube["rbacSubject"] == "KUBERNETES_PROXY_SERVER_MTLS_EXACT_SUBJECT" and not kube["privilegedGroups"],
            "RBAC is bound to the cluster-CA leaf's exact subject only, with no privileged group")
    require(kube["proxyOperatorHostTrustsClusterCa"], "the proxy/operator host trusts the per-run cluster CA")
    local_ca = doc["localCa"]
    require(local_ca["id"] == "RELEASE_PINNED_LOCAL_CA" and local_ca["holder"] == "OWNER"
            and local_ca["generation"] == "OFFLINE_ON_A_MACHINE_THAT_NEVER_CONNECTS"
            and local_ca["storage"] == "A_TOKEN_SUPPORTING_ITS_ALGORITHM_WITH_A_SEALED_BACKUP_CHECKED_AT_THE_CEREMONY"
            and local_ca["rotation"] == "PER_RELEASE" and local_ca["pinnedIn"] == "THE_RELEASE",
            "the release-pinned local CA is the owner's, made offline on a token with a sealed backup checked at the "
            "ceremony, pinned in the release and rotated per release (Q-LHA-16 (2))")
    require(local_ca["neverInTheApiServerClientTrust"],
            "the API server's client trust never holds the release-pinned local CA")
    cluster_ca = doc["clusterCa"]
    require(cluster_ca["madeAtStep"] == 7 and cluster_ca["on"] == "CLUSTER_NODE"
            and cluster_ca["issues"] == ["KUBERNETES_PROXY_SERVER_MTLS"] and cluster_ca["issuesAtStep"] == 8
            and cluster_ca["withAdmin"],
            "the per-run cluster CA is made at step 7 on the node and issues only KUBERNETES_PROXY_SERVER_MTLS at step "
            "8, with admin")
    require(not cluster_ca["newKeyOrToken"], "the per-run cluster CA needs no new key or token")
    require(cluster_ca["trustedByTheProxyOperatorHostAt"] == kube["proxyOperatorHostClusterCaTrust"],
            "the proxy/operator host trusts the per-run cluster CA at its listed path")
    credentials = _closed(doc["perRunCredentials"], "id", PER_RUN, "every per-run credential is listed",
                          "custody-model.json perRunCredentials")
    for credential in credentials.values():
        require(not credential["reusedAcrossRuns"], "a per-run credential is never reused across runs")
        require(credential["madeOn"] == "PROXY_OPERATOR_HOST" and credential["fromRequestAtStep"] == 8,
                "a per-run credential is made on its named host, from the step-8 request")
        require(credential["ends"] == "INSTANCE_AND_DISK_DELETION_AT_TEARDOWN",
                "a per-run credential's private half ends when the instances and their disks are deleted")
        require(credential["privateHalfOwner"] == "ROOT" and credential["privateHalfMode"] == "0400",
                "a per-run private half is root-owned 0400")
        require(credential["inCredentialIdentities"], "every per-run identity is in the capacity authorization's "
                "credentialIdentities")
        if credential["issuer"] == "RELEASE_PINNED_LOCAL_CA":
            require(not credential["grantsKubernetesAccess"], "no local-CA leaf authenticates to the API server")
    local_leaves = [c["id"] for c in credentials.values() if c["issuer"] == "RELEASE_PINNED_LOCAL_CA"]
    require(local_ca["issues"] == ["CAMPAIGN_PROXY_SERVER_TLS", "CAMPAIGN_PROXY_CLIENT_MTLS"] == local_leaves
            and all(credentials[c]["issuedAt"] == "T2" for c in local_leaves),
            "the release-pinned local CA issues exactly CAMPAIGN_PROXY_SERVER_TLS and CAMPAIGN_PROXY_CLIENT_MTLS, both "
            "in T2")
    k8s = credentials["KUBERNETES_PROXY_SERVER_MTLS"]
    require(k8s["issuer"] == "PER_RUN_CLUSTER_CA" and k8s["issuedAt"] == "STEP_8",
            "the per-run cluster CA issues KUBERNETES_PROXY_SERVER_MTLS at step 8")
    # LHA-C2-1, a self-contradiction: only the host the Kubernetes client credential is made on holds it (B-LHA-2;
    # design section 2, "the proxy/operator host holds only the KUBERNETES_PROXY_SERVER_MTLS client credential").
    require(all(h["holdsKubernetesClientCredential"] == (h["role"] == k8s["madeOn"]) for h in recipe["hosts"]),
            "only the host the Kubernetes client credential is made on holds it: the proxy/operator host (B-LHA-2)")
    for credential in credentials.values():
        if credential["issuedAt"] == "T2":
            drops = [t for t in launcher["signedDropInstaller"]["fixedTargets"] if t["identity"] == credential["id"]]
            require(credential["issuer"] == "RELEASE_PINNED_LOCAL_CA" and len(drops) == 1
                    and drops[0]["path"] == credential["certificate"]
                    and credential["certificateArrives"] == "SIGNED_DROP_AT_STEP_13",
                    "every per-run identity issued in T2 has its drop target")
    endpoints = _closed(doc["endpointServerIdentities"], "kind", ENDPOINT_KINDS,
                        "each endpoint kind's server TLS identity is listed",
                        "custody-model.json endpointServerIdentities")
    for endpoint in endpoints.values():
        require(endpoint["owner"] in ("THIS_CUSTODY_MODEL", "THE_KIT", "CONF-LIVE-003", "CAMPAIGN_RELEASE")
                and all(endpoint[key] for key in ("issuer", "host", "privateHalfCustody", "lifetime")),
                "each endpoint kind's server TLS identity names its owner, issuer, host, private-half custody and lifetime")
        if endpoint["perRun"]:
            require(endpoint["identity"] in credentials and credentials[endpoint["identity"]]["issuedAt"] == "T2",
                    "every per-run endpoint identity is in step 8's requests, T2's issuance, the drop list and "
                    "credentialIdentities")
    # LHA-C2-1 (a): B-LHA-7, "If one server identity serves both proxy kinds, the record says so", enforced both ways.
    # The two proxy entries carry servesBothProxyKinds exactly when they name one identity, no other entry carries it,
    # and sharedProxyServerIdentity states that identity (NONE, with no kinds, when the proxy kinds share none).
    api, campaign = endpoints["KUBERNETES_API_PROXY"], endpoints["CAMPAIGN_PROXY"]
    one = api["identity"] == campaign["identity"]
    for endpoint in endpoints.values():
        if endpoint["servesBothProxyKinds"]:
            require(one and endpoint["kind"] in PROXY_KINDS,
                    "if one server identity serves both proxy kinds, the record says so")
    require(not one or (api["servesBothProxyKinds"] and campaign["servesBothProxyKinds"]),
            "one server identity serves both proxy kinds, so both proxy entries say so with servesBothProxyKinds "
            "(B-LHA-7)")
    stated = ({"identity": api["identity"], "servesKinds": PROXY_KINDS, "rule": "B-LHA-7"} if one
              else {"identity": "NONE", "servesKinds": [], "rule": "B-LHA-7"})
    require(doc["sharedProxyServerIdentity"] == stated,
            "the record states the one server identity both proxy kinds share, or NONE (B-LHA-7)")
    local_endpoints = doc["localEndpointIdentities"]
    require(local_endpoints["kinds"] == ["LOCAL_REGISTRY", "LOCAL_EVIDENCE_SINK"]
            and local_endpoints["suppliedBy"] == "CAMPAIGN_RELEASE_G10" and local_endpoints["before"] == "RUNBOOK_STEP_7"
            and local_endpoints["precondition"] == "G10-LOCAL-ENDPOINT-IDENTITIES"
            and not local_endpoints["issuedInT1OrT2"]
            and all(endpoints[k]["owner"] == "CAMPAIGN_RELEASE" and not endpoints[k]["perRun"]
                    for k in local_endpoints["kinds"]),
            "T1 and T2 issue neither the LOCAL_REGISTRY nor the LOCAL_EVIDENCE_SINK identity; the campaign release "
            "supplies both before runbook step 7")
    # LHA-C2-1 (e): MON-LHA-CR1-KEEP, OPEN-1 read as (ii): if G10 later asks this packet's local CA to issue either
    # identity, that would be a custody-scope change for the monitor.
    require(local_endpoints["ifTheCampaignReleaseChoosesTheLocalCa"]
            == "A_TOKEN_SESSION_BEFORE_STEP_7_A_CUSTODY_SCOPE_CHANGE_FOR_THE_MONITOR",
            "the local CA as the issuer of either local endpoint identity would be a token session before step 7 and a "
            "custody-scope change for the monitor (MON-LHA-CR1-KEEP, OPEN-1 (ii))")
    nonce = doc["nonce"]
    require(nonce["signingRegistry"]["location"] == "OUTSIDE_GCP" and nonce["signingRegistry"]["custody"] == "OWNER",
            "the signing registry is in the owner's custody outside GCP, never in the run project")
    require(nonce["signingRegistry"]["neverSignsSameNonceTwice"]
            and nonce["signingRegistry"]["covers"] == ["ENVELOPE_NONCE", "CAPACITY_AUTHORIZATION_NONCE"],
            "the signing registry never signs an envelope or capacity nonce twice")
    ledger = nonce["hostLedger"]
    require(ledger["exportedAtStep"] == 15 and ledger["retained"], "the host ledger is exported at step 15 and retained")
    # LHA-C2-1 (d): Q-LHA-3 (a), a root-owned, durable host ledger on the proxy/operator host (design section 7).
    require(ledger["host"] == "PROXY_OPERATOR_HOST" and ledger["owner"] == "ROOT" and ledger["durable"],
            "the host ledger is root-owned and durable, on the proxy/operator host (Q-LHA-3 (a))")
    require(set(ledger["runtimeWrites"]) <= {w["id"] for w in recipe["runtimeRootWrites"]},
            "the root writes after the revocation are the closed list of runtime state paths and the listed drop "
            "targets")
    replay_ = doc["crossHostReplay"]
    require("SERVER_SPKI_FRESH_PER_RUN" in replay_["envelopeBinds"] and not replay_["serverKeyReused"],
            "the envelope binds the run's fresh server SPKI, so a cross-host replay fails")
    store = doc["evidenceStore"]
    require(store["custody"] == "OWNER" and store["location"] == "OUTSIDE_THE_RUN_PROJECT"
            and not store["inRunProjectBeyondPlan"], "the evidence store is the owner's and does not outlive teardown in "
            "the run project")
    independence = doc["independence"]
    require(independence["disclosure"] == DISCLOSURE and not independence["independentPeople"]
            and [c["packet"] for c in independence["carriers"]] == ["CONF-LINUX-002", "CONF-LIVE-006"],
            "the disclosure is carried here, and both evidence carriers need it before their runs")
    _check_notes(doc["carriedNotes"], ["LHA-CN-2"])


# ---------------------------------------------------------------------------------------------------------------------
# The drop manifest (B-LHA-4)

SIGNATURE_DOMAINS = {"drop": VERSIONS["drop"].encode("utf-8") + b"\x00", "policy": b"planeon.linux-runner-policy/v3\x00",
                     "manifest": b""}


def signature_payload(kind: str, raw: bytes) -> bytes:
    """The bytes an Ed25519 signature covers: a domain prefix and the exact document bytes (the runner manifest keeps
    its unchanged form: the exact bytes alone)."""
    return SIGNATURE_DOMAINS[kind] + raw


def check_offered_signature(signed_as: str, offered_as: str, raw: bytes) -> None:
    require(signature_payload(signed_as, raw) == signature_payload(offered_as, raw),
            "a signature verifies only over its own payload: a %s signature offered as a %s signature is refused"
            % (signed_as, offered_as))


def check_drop(doc: Any, schema: dict, launcher: dict) -> None:
    require(type(doc) is dict and doc.get("schemaVersion") == VERSIONS["drop"],
            "a drop manifest is planeon.internal.linux-drop-manifest/v1; a runner manifest or policy offered as one is "
            "refused")
    shape(doc, schema)
    free_text(doc)
    named_text(doc)
    targets = {t["path"]: t for t in launcher["signedDropInstaller"]["fixedTargets"]}
    files = [item["target"] for item in doc["files"]]
    require(len(set(files)) == len(files) and all(p in targets and targets[p]["state"] == "ACTIVE" for p in files),
            "a drop manifest lists only active fixed targets, each once")
    start, until, lease = _instant(doc["validFrom"]), _instant(doc["validUntil"]), _instant(doc["leaseExpiresAt"])
    require(start < until <= lease, "a drop manifest's validity window ends no later than the lease")
    require(doc["signer"] == "LINUX_RUNNER_MANIFEST", "LINUX_RUNNER_MANIFEST signs the drop manifest")


# ---------------------------------------------------------------------------------------------------------------------
# The set, the vectors and the command line

def check_set(docs: dict, schemas_: dict, base: Base) -> None:
    check_authority(docs["authority"], schemas_["authority"], base)
    check_recipe(docs["recipe"], schemas_["recipe"])
    check_launcher(docs["launcher"], schemas_["launcher"], docs["recipe"])
    check_custody(docs["custody"], schemas_["custody"], docs["recipe"], docs["launcher"])
    # LHA-C2-1 (e): host-authority.json's G10 precondition against custody-model.json's step-7 ordering: it falls due
    # before runbook step 7, where the custody model has the campaign release supply both local endpoint identities, and
    # it names both (MON-LHA-CR1-KEEP, OPEN-1 (ii); LHA-C1-4).
    g10 = [p for p in docs["authority"]["preconditions"] if p["id"] == "G10-LOCAL-ENDPOINT-IDENTITIES"][0]
    local = docs["custody"]["localEndpointIdentities"]
    require(g10["before"] == local["before"] and local["precondition"] == g10["id"]
            and all(kind in g10["what"] for kind in local["kinds"]),
            "the G10 precondition falls due before runbook step 7, where custody-model.json has the campaign release "
            "supply both local endpoint identities, and names both (MON-LHA-CR1-KEEP, OPEN-1 (ii))")
    # The drop manifest's targets are exactly the fixed list's paths (design section 6; B-LHA-5), so the schema itself
    # refuses any other target, a path with a .. segment included.
    target = schemas_["drop"]["properties"]["files"]["items"]["properties"]["target"]
    require(target == {"enum": [t["path"] for t in docs["launcher"]["signedDropInstaller"]["fixedTargets"]]},
            "the drop-manifest schema's targets are exactly the fixed list's paths")
    # (ii) Last, so that every rule above keeps its own refusal: each decision-carrying leaf at its published value.
    check_pins(docs)


# The error classes a check can raise and that refuse: its own refusal (ValueError, by its message), and every other
# one (an unreadable file, a missing member, a wrong type, a short list, a too-deep document) by its class name, so none
# can pass or print a traceback. The command line runs through explain() too, so the two refuse alike (LHA-C2-4).
REFUSED_ERRORS = (ValueError, OSError, KeyError, TypeError, IndexError, RecursionError)


def explain(check: Any, *args: Any) -> str | None:
    """None when the check accepts; otherwise the refusal: a ValueError by its message, any other REFUSED_ERRORS class
    by its name. main() runs the command line through this function, so it refuses the same classes alike."""
    try:
        check(*args)
    except REFUSED_ERRORS as exc:
        return str(exc) if isinstance(exc, ValueError) else type(exc).__name__
    return None


def apply_ops(value: Any, ops: list) -> Any:
    """Closed set/delete/append operations on a copy (plain keys and list indexes; append adds to the list at path)."""
    value = json.loads(json.dumps(value))
    for op in ops:
        require(type(op) is dict and op.get("op") in ("set", "delete", "append") and type(op.get("path")) is list
                and op["path"], "closed vector operation")
        *parents, last = op["path"]
        node = value
        for key in parents:
            node = node[key]
        if op["op"] == "set":
            node[last] = op["value"]
        elif op["op"] == "delete":
            del node[last]
        else:
            node[last].append(op["value"])
    return value


def load_schemas(root: Path = ROOT) -> dict:
    loaded = {kind: parse((root / path).read_bytes()) for kind, path in SCHEMA_PATHS.items()}
    for kind, schema in loaded.items():
        check_root_schema(schema, kind)
    return {kind: {k: v for k, v in schema.items() if k != "$schema"} for kind, schema in loaded.items()}


def load_records(root: Path = ROOT) -> dict:
    return {kind: parse((root / path).read_bytes()) for kind, path in RECORD_PATHS.items()}


def replay(vectors: Any, schemas_: dict, records: dict, base: Base) -> dict:
    """Every vector to its recorded result; returns the counts per kind."""
    require(type(vectors) is dict and set(vectors) == {"schemaVersion", "evidenceClass", "positives", "negatives",
                                                         "leafVectors", "dropManifests", "parseNegatives"}
            and vectors["schemaVersion"] == VERSIONS["vectors"] and vectors["evidenceClass"] == "DATA_CHECK_ONLY",
            "closed vectors file")
    counts = {"positives": 0, "authority": 0, "recipe": 0, "launcher": 0, "custody": 0, "leaf": 0, "drop": 0,
              "signature": 0, "parse": 0}
    ids: list = []
    sets = []
    for p in vectors["positives"]:
        require(set(p) == {"id", "intent", "ops"} and set(p["ops"]) == set(KINDS), "closed positive " + str(p.get("id")))
        docs = {kind: apply_ops(records[kind], p["ops"][kind]) for kind in KINDS}
        require(explain(check_set, docs, schemas_, base) is None, "positive set accepted: " + p["id"])
        sets.append(docs)
        counts["positives"] += 1
        ids.append(p["id"])
    for row in vectors["negatives"]:
        require(set(row) == {"id", "intent", "rule", "positive", "target", "ops", "refusal"} and row["target"] in KINDS,
                "closed negative " + str(row.get("id")))
        docs = dict(sets[row["positive"]])
        docs[row["target"]] = apply_ops(docs[row["target"]], row["ops"])
        result = explain(check_set, docs, schemas_, base)
        require(result is not None and result == row["refusal"], "negative vector %s: got %r" % (row["id"], result))
        counts[row["target"]] += 1
        ids.append(row["id"])
    # (ii) One generated refusal vector per decision-carrying leaf: the published set with that leaf's first occurrence
    # set to another value of its type, refused as recorded.
    for row in vectors["leafVectors"]:
        require(set(row) == {"id", "rule", "target", "leaf", "value", "refusal"} and row["target"] in KINDS,
                "closed leaf vector " + str(row.get("id")))
        docs = dict(sets[0])
        path = leaf(row["target"], docs[row["target"]], row["leaf"], first=True)
        docs[row["target"]] = apply_ops(docs[row["target"]], [{"op": "set", "path": path, "value": row["value"]}])
        result = explain(check_set, docs, schemas_, base)
        require(result is not None and result == row["refusal"], "leaf vector %s: got %r" % (row["id"], result))
        counts["leaf"] += 1
        ids.append(row["id"])
    drops = vectors["dropManifests"]
    require(type(drops) is dict and set(drops) == {"positives", "negatives", "signatures"}, "closed drop-manifest vectors")
    for p in drops["positives"]:
        require(set(p) == {"id", "intent", "document"}, "closed drop-manifest positive " + str(p.get("id")))
        require(explain(check_drop, p["document"], schemas_["drop"], records["launcher"]) is None,
                "positive drop manifest accepted: " + p["id"])
        counts["positives"] += 1
        ids.append(p["id"])
    for row in drops["negatives"]:
        require(set(row) == {"id", "intent", "rule", "positive", "ops", "refusal"}, "closed drop-manifest negative")
        document = apply_ops(drops["positives"][row["positive"]]["document"], row["ops"])
        result = explain(check_drop, document, schemas_["drop"], records["launcher"])
        require(result is not None and result == row["refusal"], "drop vector %s: got %r" % (row["id"], result))
        counts["drop"] += 1
        ids.append(row["id"])
    for row in drops["signatures"]:
        require(set(row) == {"id", "intent", "rule", "positive", "signedAs", "offeredAs", "refusal"},
                "closed signature vector")
        raw = canonical(drops["positives"][row["positive"]]["document"])
        result = explain(check_offered_signature, row["signedAs"], row["offeredAs"], raw)
        require(result == row["refusal"], "signature vector %s: got %r" % (row["id"], result))
        counts["signature" if row["refusal"] is not None else "positives"] += 1
        ids.append(row["id"])
    for row in vectors["parseNegatives"]:
        require(set(row) == {"id", "intent", "raw", "refusal"} and type(row["raw"]) is str,
                "closed parse negative " + str(row.get("id")))
        result = explain(parse, row["raw"].encode("utf-8"))
        require(result is not None and result == row["refusal"], "parse vector %s: got %r" % (row["id"], result))
        counts["parse"] += 1
        ids.append(row["id"])
    require(len(ids) == len(set(ids)), "unique vector identifiers")
    return counts


USAGE = "usage: linux_host_authority.py check | replay"


def _command(argv: list, out: dict) -> None:
    schemas_ = load_schemas()
    records = load_records()
    base = Base(ROOT)
    check_set(records, schemas_, base)
    spans = sum(len(records["authority"][s]) for s in ("supersedes", "satisfied", "unchanged", "costScope",
                                                        "reviewedNotBinding"))
    out["spans"] = spans + sum(len(r["occurrences"]) for r in records["authority"]["readings"]) + 3
    out["pins"] = sum(len(pins) for kind in KINDS for pins in LEAF_PINS[kind].values())
    if argv[0] == "replay":
        out["counts"] = replay(parse((ROOT / VECTORS_PATH).read_bytes()), schemas_, records, base)


def main(argv: list[str]) -> int:
    if argv not in (["check"], ["replay"]):
        print(USAGE)
        return 2
    out: dict = {}
    refusal = explain(_command, argv, out)
    if refusal is not None:
        print("refused: %s" % refusal)
        return 1
    print("linux host-authority contract: schemas closed; the four records accepted, %d span entries matching the base "
          "and %d leaves at their pinned values" % (out["spans"], out["pins"]))
    if argv[0] == "replay":
        counts = out["counts"]
        print("vectors: %d positives accepted; negatives: %d authority, %d recipe, %d launcher, %d custody, %d leaf, %d "
              "drop manifest, %d signature and %d parse, each refused as recorded"
              % (counts["positives"], counts["authority"], counts["recipe"], counts["launcher"], counts["custody"],
                 counts["leaf"], counts["drop"], counts["signature"], counts["parse"]))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
