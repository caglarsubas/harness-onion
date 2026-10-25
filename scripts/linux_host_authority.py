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


def free_text(value: Any, where: str = "$") -> None:
    """No string anywhere in a document carries a credential, an account identity or a billing account."""
    if type(value) is str:
        require(not any(pattern.search(value) for pattern in FORBIDDEN_TEXT),
                "no credential, account identity or billing account in %s" % where)
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
        for pattern, message in NAMED_TEXT:
            require(pattern.search(value) is None, message % where)
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

    def read(self, path: str) -> bytes:
        require(path in CITED_FILES, "a cited file is one of the contract's cited files: " + path)
        if path not in self.cache:
            self.cache[path] = (self.root / path).read_bytes()
        return self.cache[path]

    def lines(self, path: str) -> list:
        return self.read(path).split(b"\n")


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
    raw = base.read(entry["path"])
    require(hashlib.sha256(raw).hexdigest() == entry["fileSha256"], name + ": the file sha256 is the base's")
    lines = raw.split(b"\n")
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
            found, token = _member(strict(raw), entry["member"])
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
    readiness = strict(base.read("architecture/linux-readiness.json"))
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
    left = {item["what"]: item["ownRecord"] for item in inventory["leftOut"]}
    require(left.get("PER_RUN_PRIVATE_HALVES") == "SPKI_DIGEST_ONLY"
            and left.get("PER_RUN_CERTIFICATE_REQUESTS") == "SPKI_DIGEST_ONLY",
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
    packages = doc["packages"]
    require(packages["automaticUpdaters"] == "OFF", "every automatic updater is off")
    require(all("FILE_SHA256" in source["pin"] for source in packages["sources"]), "every package is pinned by its file "
            "digest")
    require(doc["source"]["withGit"] and doc["source"]["treeSha256"], "the source transfer carries .git and treeSha256")
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
    require(all(s["cloudActionsBy"] == "OWNER_ADMIN" for s in runbook if s["step"] in ADMIN_CLOUD_STEPS)
            and all(s["cloudActionsBy"] in ("OWNER_ADMIN", "NONE") for s in runbook),
            "the administering identity, OWNER_ADMIN, performs the cloud actions of runbook steps 2, 3, 5, 6 and 16")


def _check_access(access: dict) -> None:
    require(access["ssh"] == {"only": "IAP", "sourceRange": IAP_RANGE, "protocol": "tcp", "port": 22, "onPaper": True},
            "SSH only through IAP: 35.235.240.0/20, tcp 22")
    identities = {i["label"]: i for i in access["identities"]}
    require(list(identities) == ["OWNER_LOGIN", "OWNER_ADMIN"] and identities["OWNER_LOGIN"]["use"] == "SSH_ONLY"
            and not identities["OWNER_LOGIN"]["administersIam"] and identities["OWNER_ADMIN"]["administersIam"],
            "two identities: the login identity for SSH only, and the administering identity, which alone administers IAM")
    require(identities["OWNER_LOGIN"]["osLogin"] and identities["OWNER_LOGIN"]["twoStepVerification"],
            "OS Login and its 2-step verification are on")
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
    revocation = access["revocation"]
    require(revocation["atStep"] == 10 and revocation["by"] == "OWNER_ADMIN" and not revocation["denyPolicy"]
            and not revocation["folderOrOrganizationGrant"],
            "OWNER_ADMIN removes the admin-login binding at step 10; no deny policy and no folder or organization grant")
    require(revocation["thenWaitsForPropagation"], "the step-10 and step-15 checks wait for IAM propagation first")
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
    units = {u["id"]: u for u in doc["triggerUnits"]}
    require(list(units) == ["PREFLIGHT_UNIT", "EXPORT_UNIT"],
            "one reviewed family of trigger units: one for the preflight and one for the export")
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
    exports = {e["host"]: e["records"] for e in doc["exportSet"]}
    require(list(exports) == ["PROXY_OPERATOR_HOST", "CLUSTER_NODE"]
            and {"HOST_NONCE_LEDGER", "PREFLIGHT_RECORDS", "INSTALLER_LOG", "JOURNAL"} <= set(exports["PROXY_OPERATOR_HOST"]),
            "every root-only record has a read path at step 15: the export unit on both hosts")
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
    live = doc["liveLauncher"]
    require(live["manifestSigner"] == "LIVE_RUNNER_MANIFEST", "no manifest is signed by the other launcher's key")
    require(live["manifestSignedAfter"] == "CONF_LIVE_005_006_OWN_PREFLIGHT" and live["state"] == "WAITING",
            "no live manifest is signed before CONF-LIVE-005/006's own preflight")
    require(all(m["readOnly"] and m["owner"] == "ROOT" and m["mode"] == "0444" and m["installedAtStep"] == 10
                for m in live["trustMounts"]), "the trust bundles are mounted read-only, root-owned, 0444")
    limits = doc["timeLimits"]
    require(limits["policyMaxHours"] == 24, "the policy lives at most 24 hours")
    require(limits["t2EndsWithinHoursOfPreflight"] == 1 and limits["manifestsSignedWithinHoursOfPreflight"] == 1,
            "T2 ends within one hour of the step-11 preflight")
    for step in doc["steps"]:
        require(step["rollback"] not in ("", "NONE"), "each step names its rollback")
        require(step["inputDigests"] != [], "each step names its input digests")
        require(not step["movesTrustDigest"], "no step signs an unknown candidate by moving a trust digest")
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
    linux = authorities[0]
    require(linux["signs"] == ["OFFLINE_POLICY", "OFFLINE_MANIFEST", "DROP_MANIFEST"],
            "LINUX_RUNNER_MANIFEST signs the policy, the offline manifest and the drop manifest")
    require(doc["dropManifest"] == {"signer": "LINUX_RUNNER_MANIFEST", "authorizes": "PLACEMENT_ONLY",
                                    "liveManifestStillVerifiedUnder": "LIVE_RUNNER_MANIFEST"},
            "the drop manifest authorizes placement only; the live launcher still verifies the live manifest under "
            "LIVE_RUNNER_MANIFEST")
    sessions = {s["id"]: s for s in doc["tokenSessions"]}
    require(list(sessions) == ["T1", "T2"] and sessions["T2"]["withinOneHourOfPreflight"] and sessions["T2"]["everyTokenPresent"],
            "two token sessions per run; T2 ends within one hour of the preflight, with every token present")
    require((sessions["T1"]["runbookStep"], sessions["T1"]["after"], sessions["T1"]["order"])
            == (10, "THE_STEP_9_INVENTORY_FREEZE", T1_ORDER)
            and (sessions["T2"]["runbookStep"], sessions["T2"]["after"], sessions["T2"]["order"])
            == (12, "THE_STEP_11_PREFLIGHT", T2_ORDER),
            "T1 runs at step 10 after the inventory freeze and T2 at step 12 after the preflight, each in the runbook's "
            "order")
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
    credentials = {c["id"]: c for c in doc["perRunCredentials"]}
    require(list(credentials) == PER_RUN, "every per-run credential is listed")
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
    targets = {t["identity"]: t for t in launcher["signedDropInstaller"]["fixedTargets"]}
    for credential in credentials.values():
        if credential["issuedAt"] == "T2":
            require(credential["issuer"] == "RELEASE_PINNED_LOCAL_CA" and credential["id"] in targets
                    and targets[credential["id"]]["path"] == credential["certificate"]
                    and credential["certificateArrives"] == "SIGNED_DROP_AT_STEP_13",
                    "every per-run identity issued in T2 has its drop target")
    endpoints = {e["kind"]: e for e in doc["endpointServerIdentities"]}
    require(list(endpoints) == ENDPOINT_KINDS, "each endpoint kind's server TLS identity is listed")
    for endpoint in endpoints.values():
        require(endpoint["owner"] in ("THIS_CUSTODY_MODEL", "THE_KIT", "CONF-LIVE-003", "CAMPAIGN_RELEASE")
                and all(endpoint[key] for key in ("issuer", "host", "privateHalfCustody", "lifetime")),
                "each endpoint kind's server TLS identity names its owner, issuer, host, private-half custody and lifetime")
        if endpoint["perRun"]:
            require(endpoint["identity"] in credentials and credentials[endpoint["identity"]]["issuedAt"] == "T2",
                    "every per-run endpoint identity is in step 8's requests, T2's issuance, the drop list and "
                    "credentialIdentities")
    shared = [e for e in endpoints.values() if e["servesBothProxyKinds"]]
    require(len({e["identity"] for e in shared}) <= 1
            and all(e["kind"] in ("KUBERNETES_API_PROXY", "CAMPAIGN_PROXY") for e in shared),
            "if one server identity serves both proxy kinds, the record says so")
    local_endpoints = doc["localEndpointIdentities"]
    require(local_endpoints["kinds"] == ["LOCAL_REGISTRY", "LOCAL_EVIDENCE_SINK"]
            and local_endpoints["suppliedBy"] == "CAMPAIGN_RELEASE_G10" and local_endpoints["before"] == "RUNBOOK_STEP_7"
            and local_endpoints["precondition"] == "G10-LOCAL-ENDPOINT-IDENTITIES"
            and not local_endpoints["issuedInT1OrT2"]
            and all(endpoints[k]["owner"] == "CAMPAIGN_RELEASE" and not endpoints[k]["perRun"]
                    for k in local_endpoints["kinds"]),
            "T1 and T2 issue neither the LOCAL_REGISTRY nor the LOCAL_EVIDENCE_SINK identity; the campaign release "
            "supplies both before runbook step 7")
    nonce = doc["nonce"]
    require(nonce["signingRegistry"]["location"] == "OUTSIDE_GCP" and nonce["signingRegistry"]["custody"] == "OWNER",
            "the signing registry is in the owner's custody outside GCP, never in the run project")
    require(nonce["signingRegistry"]["neverSignsSameNonceTwice"]
            and nonce["signingRegistry"]["covers"] == ["ENVELOPE_NONCE", "CAPACITY_AUTHORIZATION_NONCE"],
            "the signing registry never signs an envelope or capacity nonce twice")
    ledger = nonce["hostLedger"]
    require(ledger["exportedAtStep"] == 15 and ledger["retained"], "the host ledger is exported at step 15 and retained")
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
    # The drop manifest's targets are exactly the fixed list's paths (design section 6; B-LHA-5), so the schema itself
    # refuses any other target, a path with a .. segment included.
    target = schemas_["drop"]["properties"]["files"]["items"]["properties"]["target"]
    require(target == {"enum": [t["path"] for t in docs["launcher"]["signedDropInstaller"]["fixedTargets"]]},
            "the drop-manifest schema's targets are exactly the fixed list's paths")


def explain(check: Any, *args: Any) -> str | None:
    """None when the check accepts; otherwise the refusal. As on the command line, an error a check raises other than
    its own refusal (a missing member, a wrong type) is a refusal named by its class, so it can never pass."""
    try:
        check(*args)
    except ValueError as exc:
        return str(exc)
    except (KeyError, TypeError, IndexError) as exc:
        return type(exc).__name__
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
                                                         "dropManifests", "parseNegatives"}
            and vectors["schemaVersion"] == VERSIONS["vectors"] and vectors["evidenceClass"] == "DATA_CHECK_ONLY",
            "closed vectors file")
    counts = {"positives": 0, "authority": 0, "recipe": 0, "launcher": 0, "custody": 0, "drop": 0, "signature": 0,
              "parse": 0}
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


def main(argv: list[str]) -> int:
    if argv not in (["check"], ["replay"]):
        print(USAGE)
        return 2
    try:
        schemas_ = load_schemas()
        records = load_records()
        base = Base(ROOT)
        check_set(records, schemas_, base)
        spans = sum(len(records["authority"][s]) for s in ("supersedes", "satisfied", "unchanged", "costScope",
                                                            "reviewedNotBinding"))
        spans += sum(len(r["occurrences"]) for r in records["authority"]["readings"]) + 3
        if argv[0] == "replay":
            counts = replay(parse((ROOT / VECTORS_PATH).read_bytes()), schemas_, records, base)
    except (ValueError, OSError, KeyError, TypeError, RecursionError) as exc:
        print("refused: %s" % (exc if type(exc) is ValueError else type(exc).__name__))
        return 1
    print("linux host-authority contract: schemas closed; the four records accepted, %d span entries matching the base"
          % spans)
    if argv[0] == "replay":
        print("vectors: %d positives accepted; negatives: %d authority, %d recipe, %d launcher, %d custody, %d drop "
              "manifest, %d signature and %d parse, each refused as recorded"
              % (counts["positives"], counts["authority"], counts["recipe"], counts["launcher"], counts["custody"],
                 counts["drop"], counts["signature"], counts["parse"]))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
