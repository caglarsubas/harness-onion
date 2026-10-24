"""D5a oracle tests for MET-LINUX-008 (LINUX-HOST-AUTH-001), the Linux host-authority contract.

Every expected value comes from the closed design (revision 7), its binding build rules (B-LHA-1, B-LHA-2 and B-LHA-4 to
B-LHA-18; B-LHA-3 is superseded), the decisions they cite and the base bytes (harness-onion
a88276171453760e46b28e8f6f0c0bb4bbfade5d), never from the candidate's checker, tests or vectors. The candidate is reached
only through its published command line. The mutation checks below are this oracle's own, independent checks of the
records: the published README documents no way to point the checker at a modified copy. Standard library, pytest and
jsonschema only.
"""
from __future__ import annotations

import copy
import hashlib
import json
import re
import subprocess
import sys
import unittest
from functools import lru_cache
from pathlib import Path

import jsonschema

CONTRACT = "architecture/linux-host-authority"


def _root() -> Path:
    # In the candidate's tree this file sits in tests/; run from elsewhere, the working directory is the repository root
    # (the published command line runs from the repository root).
    here = Path(__file__).resolve().parent.parent
    if (here / CONTRACT / "host-authority.json").is_file():
        return here
    return Path.cwd()


ROOT = _root()
BASE_COMMIT = "a88276171453760e46b28e8f6f0c0bb4bbfade5d"

# Design section 3: the four records, their schema ids, one closed Draft 2020-12 schema each; B-LHA-4: the drop manifest's
# own closed schema.
RECORDS = {"authority": "host-authority.json", "recipe": "host-recipe.json", "launcher": "launcher-install.json",
           "custody": "custody-model.json"}
SCHEMA_IDS = {"authority": "planeon.internal.linux-host-authority/v1", "recipe": "planeon.internal.linux-host-recipe/v1",
              "launcher": "planeon.internal.linux-launcher-install/v1", "custody": "planeon.internal.linux-key-custody/v1"}
SCHEMAS = {kind: name[:-len(".json")] + ".schema.json" for kind, name in RECORDS.items()}
SCHEMAS["drop"] = "drop-manifest.schema.json"
DRAFT_2020_12 = "https://json-schema.org/draft/2020-12/schema"

# Section 4: the base documents the superseding record cites, with their sha256 at the base (taken by the oracle author
# from the base's git objects, not from the record).
LR = "docs/alpha-2/LINUX_READINESS.md"
LRJ = "architecture/linux-readiness.json"
REP = "docs/alpha-2/LINUX_READINESS_REPAIRS.md"
CIX = "docs/alpha-2/CI_CAPACITY_EXCEPTION.md"
TL = "docs/TRUSTED_LIVE_CAMPAIGN_RUNNER_CONTRACT.md"
COR = "docs/alpha-2/CREDENTIAL_ORDERING_REPAIR.md"
NQR = "docs/alpha-2/NATIVE_QUALIFICATION_READINESS.md"
OPR = "docs/linux-runner/OPERATOR.md"
LRP = "architecture/lab-run-plan/status.json"
BASE_SHA256 = {
    LR: "ce9c3dfbc7265735b5f41874c82d18b64260f6e3f8f44e623c6b623dbf9bf171",
    LRJ: "2ac76f01df10f3267b23340dd2af7c466647f5bd9f3645d6203c4de93c0a8762",
    REP: "ae1c9284eba881730bf4959587616e701c4c3d09f5d8209d156a3798e6cb4f24",
    CIX: "9a7e6613684d504494ace5380593ce198e679f779d236463e39c58df3ecb28cf",
    TL: "3f1bf16f6ec5d1e265946765fd82a1a1c05773dcd99a15a1c68f43b122937052",
    COR: "b2ed7fe5be1a8b23ec31483c94f77a79094972acde5b726b33a660d729a3bb2d",
    NQR: "60bed4c5358527dabfba15bf4e7a7f584872715ef2ca4f9b4350303b656bf595",
    OPR: "30a59f557ea1a3129fe0d11f86801ed282cffba3f580359b550a8335924fec28",
    LRP: "81c4e9988cb29b93d8abbef7b4bf5d5330cb2e7c1af4429a9b78fe5c6f26e039",
}
# OPERATOR.md at the base: the line ranges of its steps 4, 5 and 8 (section 4 `readings`, "existing").
OPERATOR_STEPS = {4: (93, 95), 5: (96, 103), 8: (113, 118)}
# B-LHA-4: what a drop manifest must never be taken for, at the base: the runner manifest's schema id
# (schemas/trusted-runner-manifest.schema.json line 10) and the offline policy's (docs/linux-runner/BUILD_INPUTS.md lines
# 138 and 158, whose signature covers UTF8(schema id, 0x00) and the exact bytes).
RUNNER_MANIFEST_SCHEMA_ID = "harness.planeon.ai/trusted-runner-manifest/v1alpha1"
POLICY_SCHEMA_ID = "planeon.linux-runner-policy/v3"
# B-LHA-5: the offline manifest's fixed contract paths (docs/TRUSTED_RUNNER_CONTRACT.md lines 5 and 8 at the base).
OFFLINE_MANIFEST_PATH = "/etc/planeon/harness-runner-manifest.json"
OFFLINE_MANIFEST_SIG_PATH = "/etc/planeon/harness-runner-manifest.json.sig"
# Section 4 `decisions`: the decision lines, verbatim. Each digest is the sha256 of the line(s) the oracle author took from
# owner_decisions.json, in the entries the design and the rules cite.
DECISION_PINS = {
    "LX-D1": "9fe455c0eee0256b2334e3900595d734b397e368b52660792ac29106d156638c",
    "LX-D2": "89e44c46ae4a4ff9e6933e75cd010cc4a33d1de93e87f9acada865679e62f79d",
    "Q-LHA-ID": "d9c8f2c007ef0f668c708da35daa4072ec223a041023e8b59c7f9d7d5266fb31",
    "Q-LHA-SERIES": "6b0a6841b5c441cfd5a759ea39de137614bc03eca22b46116b8fdb0dd27048f2",
    "Q-LHA-1": "135ea927dde66137df764329cf15b8e57a8ac20ed03921ae70cc90015ad82749",
    "Q-LHA-2": "313270819d9ce830aa7dc51ba3d876df724b7753ff77ac78948495ffbfd531dc",
    "Q-LHA-3": "235df63bf3315060d19bfdeff7fa7c0ee9ddeb809a381e8284c2a613382ee162",
    "Q-LHA-4": "1e20ea495738914863d003f477727eb2579d59eabff29a2460a549bd921b455e",
    "Q-LHA-5": "4cbe2726e585173757cd72a9ddd0654e9866eae5af77a24a17bc95f401bd360a",
    "Q-LHA-6": "fa6f8a1e737c77014bc255e0fba9a7bd4e4f1fb2b71e5e8884d6dab847374247",
    "Q-LHA-4-5-6": "c841e1b6e7f3810c96c52af22222b1b2a4ec6ca6214cdd9b0017c5eec449bed7",
    "Q-LHA-7": "497013bcbcd57ee755bd8ec84de4dc27f7f00ea6e94557bb5f9a75af3260938f",
    "Q-LHA-8": "31e14c573fe5dc91c046b14f3ab116269a1e3c0efe25101dfc9cb4ded18c74fc",
    "Q-LHA-9": "f39bdb5ebb273df63d7a6a4843975da35b79331ea1593daff8b8d43368490795",
    "Q-LHA-10": "4be43a8f6e913f2d32b574162ee1ec1bf4c30b0e1d3ed3d6184267a83f6335f0",
    "Q-LHA-11": "d942441e71f8932ecc69431aebbbaf6e5bf8650e392dcb025e80fb0e048c6bb6",
    "Q-LHA-12": "8d26106914aa2d574be23bea870ea8aabaf0bcb4ec228a7b98dd38dc745aa5fe",
    "Q-LHA-13": "bc0c4e462f4f8c072041c7d755b369ab53ef716ce442de6e4ad6dd011648f4c7",
    "Q-LHA-14": "95ec23037b40f6ecc0c17e0cb99dc75823acd25a04d51ba5a2e37014fd99f0f4",
    "Q-LHA-15": "0e4deb9367968a5fc1d1ba60717199cb6c6dff032dff3da420b22d90da40c8da",
    "Q-LHA-16(2)": "381ce4115e29d9043d23c8db036dbe38a080bdd88f5378f4b8f19db054218ab7",
    "MON-LHA-16-1": "f2115be4f335cb3cf2431e7f01d878468573f53b77ce2a60ace8af15b06b92d8",
    "MON-LHA-SPLIT": "36ebea94f647736cb7f50b1341222d1c3e21c7f69ffb80705d9d66904d5fce87",
    "MON-LHA-12R": "741e59c59faf0ac126cb6c6f49cb55b8b9a21b31322818163b4f6f114c387a19",
    "MON-LHA-17": "22261e8b76dca583a98e7d9905224603f614a70a315f651bf77bfaf69a79c255",
    "LHA2-11": "4833b43a0d1c3313d859fbce6eed1d29030d23f4543bf7095c04a4fd521ceb04",
    "CAP": "0f6c6ee142847d12acecefaf573fa2fa538dfe84d407908097379fda1a9709dd",
    "LHA3-8": "04f960a0397a239235dfe5eefc1c8e40d0f2c728a31cc0c0ca34455abc37f8b1",
    "MON-LHA3-1-2": "e753e576c8bb07545877f051544a399dadde0d1e53b462016023dd3c3732321e",
    "MON-LHA-B1": "87f3ba83a2be0928e84fe3ce2f599a8668e1c6898c32778ae80d702d99a82d8b",
    "MON-LHA-B2": "dee136b653ed947a515788ee5110d9d288aab87c020f8f4eb2a84e7865b3454d",
    "B-LHA-3": "5dd784b814b00eff0a439fdeb8bffe2935f0dde236a20780a24aa97cea2d58c6",
    "B-LHA-4..12": "c4b1f73ab3ad90e94bc1b4ef49d2d161813404401eb1f001307f049c17b529ab",
    "CUSTOM-ROLE": "52824fdc7ecf5389ae4aebd460f8fb03d557cfcff65835ae33317b1c222602d4",
    "Q-LHA5-1": "c75c193c335dcbfab871a94dd248b1ce0e25e06ebd508379b057a37fc45e7496",
    "Q-LHA6-3": "ad47a812966021b28f4f5b8a4279cad0ea78adfba24baae430417725508d9875",
}
# design-status.json `carriedNotes`: the sha256 of each note's text (LHA-CN-1 into the authority, LHA-CN-2 into custody).
CARRIED_NOTE_PINS = {"LHA-CN-1": "8861d9442295e59a0893581ad0c0dda9863a86e22e07e938ec61522e15b86422",
                     "LHA-CN-2": "9e74371ff3ac386e03d6353fb2a095a992d7d5d6358be25d370fa63da36e8eed"}
# The owners' answers as the design quotes them (sections 9 and 16; BUILD_RULES).
OWNER_WORDS = ["Separated keys, disclosed (Recommended)", "Offline + token + sealed backup (Recommended)",
               "Two VMs per run (Recommended)", "Custom ext4-verity image (Recommended)",
               "Offline + token + backup (Recommended)", "Rev 5 + one last round (Recommended)",
               "Custom role on run project (Recommended)", "Two identities + audit check (Recommended)",
               "No login for admin id (Recommended)"]
# LHA2-20: the monitor's spend-condition wording, carried verbatim.
SPEND_WORDING = "Any image with a licence charge, and any other spend, comes to me for the owner."
LABEL = re.compile(r"[A-Z][A-Z0-9_]*")
JOIN = " \u2026 "
INTEGER_LIMIT = 10 ** 12


# ----------------------------------------------------------------------------------------------- parse rules (section 3)

def strict(raw: bytes, integers_only: bool = True):
    """LAB-RUNPLAN-001's parse rules (scripts/lab_run_plan.py `strict` at the base): UTF-8 without a byte-order mark, no
    duplicate keys, no non-finite number, no integral float, no oversized integer, no lone surrogate. The design adds the
    refusal of non-integral numbers for these records (section 3), so with integers_only every float is refused."""
    def pairs(items):
        value = {}
        for key, item in items:
            if key in value:
                raise ValueError("duplicate key " + key)
            value[key] = item
        return value

    def constant(name):
        raise ValueError("non-finite number " + name)

    def number(text):
        value = float(text)
        if integers_only:
            raise ValueError("non-integral number " + text)
        if value != value or value in (float("inf"), float("-inf")) or value.is_integer():
            raise ValueError("integral or non-finite float " + text)
        return value

    def integer(text):
        if len(text.lstrip("-")) > 13 or abs(int(text)) > INTEGER_LIMIT:
            raise ValueError("integer out of range")
        return int(text)

    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        raise ValueError("not UTF-8") from None
    if text.startswith("\ufeff"):
        raise ValueError("byte-order mark")
    value = json.loads(text, object_pairs_hook=pairs, parse_constant=constant, parse_float=number, parse_int=integer)
    try:
        json.dumps(value, ensure_ascii=False).encode("utf-8")
    except UnicodeEncodeError:
        raise ValueError("lone surrogate") from None
    return value


@lru_cache(maxsize=None)
def contract_bytes(name: str) -> bytes:
    return (ROOT / CONTRACT / name).read_bytes()


@lru_cache(maxsize=None)
def _record(kind: str):
    return strict(contract_bytes(RECORDS[kind]))


def record(kind: str):
    return copy.deepcopy(_record(kind))


@lru_cache(maxsize=None)
def _schema(kind: str):
    return strict(contract_bytes(SCHEMAS[kind]), integers_only=False)


def schema(kind: str):
    return copy.deepcopy(_schema(kind))


@lru_cache(maxsize=None)
def base_bytes(path: str) -> bytes:
    return (ROOT / path).read_bytes()


@lru_cache(maxsize=None)
def readme() -> str:
    return contract_bytes("README.md").decode("utf-8")


def render(text: str) -> str:
    return " ".join(str(text).split())


def strings(value, keys: bool = True):
    """Every string value (and, with keys, every key) in a document, with its JSON path."""
    out = []
    if isinstance(value, str):
        out.append(("$", value))
    elif isinstance(value, dict):
        for key, item in value.items():
            if keys:
                out.append(("key " + key, key))
            out.extend((key + "." + where, text) for where, text in strings(item, keys))
    elif isinstance(value, list):
        for index, item in enumerate(value):
            out.extend(("[%d]." % index + where, text) for where, text in strings(item, keys))
    return out


# ------------------------------------------------------------------------------- the closed schema subset (section 3)

SCHEMA_KEYWORDS = {"$id", "title", "description", "type", "properties", "required", "additionalProperties", "items",
                   "minItems", "maxItems", "uniqueItems", "enum", "const", "pattern", "minLength", "maxLength", "minimum",
                   "maximum", "exclusiveMinimum"}
TYPE_NAMES = {"object", "array", "string", "boolean", "null", "integer", "number"}
KEYWORD_RULES = {"pattern": ("string", str), "minLength": ("string", int), "maxLength": ("string", int),
                 "minimum": ("numeric", (int, float)), "maximum": ("numeric", (int, float)),
                 "exclusiveMinimum": ("numeric", (int, float)), "minItems": ("array", int), "maxItems": ("array", int),
                 "uniqueItems": ("array", bool)}


def closed_schema_findings(node, where: str = "$", root: bool = True) -> list:
    """LAB-RUNPLAN-001's closed subset, restated: only its keywords (plus the root's Draft 2020-12 declaration), each
    where it applies; every object schema closed with every key required; items only on arrays."""
    out = []
    if not isinstance(node, dict):
        return [where + ": not a schema object"]
    allowed = SCHEMA_KEYWORDS | ({"$schema"} if root else set())
    if not set(node) <= allowed:
        out.append("%s: keywords outside the closed subset %s" % (where, sorted(set(node) - allowed)))
    if not ("type" in node or "const" in node or "enum" in node):
        out.append(where + ": no type, const or enum")
    kind = node.get("type")
    kinds = kind if isinstance(kind, list) else [kind]
    if kind is not None and not all(isinstance(name, str) and name in TYPE_NAMES for name in kinds):
        out.append(where + ": type names")
    for key, (needs, value_type) in KEYWORD_RULES.items():
        if key in node:
            value = node[key]
            applies = ("integer" in kinds or "number" in kinds) if needs == "numeric" else needs in kinds
            typed = (type(value) is bool if value_type is bool
                     else isinstance(value, value_type) and type(value) is not bool and (value_type is not int or value >= 0))
            if not (applies and typed):
                out.append("%s: %s misplaced or mistyped" % (where, key))
    if "pattern" in node:
        try:
            re.compile(node["pattern"])
        except (re.error, TypeError):
            out.append(where + ": pattern does not compile")
    if "properties" in node or "object" in kinds or "required" in node or "additionalProperties" in node:
        props = node.get("properties")
        required = node.get("required")
        if not (kind == "object" and node.get("additionalProperties") is False and isinstance(props, dict)
                and isinstance(required, list) and set(required) == set(props) and len(required) == len(set(required))):
            out.append(where + ": object schema not closed (additionalProperties false, every key required)")
        if isinstance(props, dict):
            for name, sub in props.items():
                out.extend(closed_schema_findings(sub, where + "." + name, False))
    if "items" in node or "array" in kinds:
        if not (kind == "array" and isinstance(node.get("items"), dict)):
            out.append(where + ": array schema without items")
        else:
            out.extend(closed_schema_findings(node["items"], where + "[]", False))
    return out


def shape_findings(value, node, where: str = "$") -> list:
    """A document against the closed subset with LAB-RUNPLAN-001's semantics (full-match patterns, closed objects)."""
    out = []
    kind = node.get("type")
    if kind is not None:
        kinds = kind if isinstance(kind, list) else [kind]
        ok = any((name == "integer" and type(value) is int) or (name == "number" and type(value) in (int, float))
                 or (name == "object" and type(value) is dict) or (name == "array" and type(value) is list)
                 or (name == "string" and type(value) is str) or (name == "boolean" and type(value) is bool)
                 or (name == "null" and value is None) for name in kinds)
        if not ok:
            return [where + ": type"]
    if "const" in node and not (value == node["const"] and type(value) is type(node["const"])):
        out.append(where + ": const")
    if "enum" in node and not any(value == item and type(value) is type(item) for item in node["enum"]):
        out.append(where + ": enum")
    if type(value) is str:
        if "pattern" in node and re.fullmatch(node["pattern"], value) is None:
            out.append(where + ": pattern")
        if "minLength" in node and len(value) < node["minLength"]:
            out.append(where + ": minLength")
        if "maxLength" in node and len(value) > node["maxLength"]:
            out.append(where + ": maxLength")
    if type(value) in (int, float):
        if "minimum" in node and value < node["minimum"]:
            out.append(where + ": minimum")
        if "exclusiveMinimum" in node and not value > node["exclusiveMinimum"]:
            out.append(where + ": exclusiveMinimum")
        if "maximum" in node and value > node["maximum"]:
            out.append(where + ": maximum")
    if type(value) is dict and node.get("type") == "object":
        if set(value) != set(node["properties"]):
            out.append(where + ": closed object keys")
        for name, sub in node["properties"].items():
            if name in value:
                out.extend(shape_findings(value[name], sub, where + "." + name))
    if type(value) is list and node.get("type") == "array":
        if "minItems" in node and len(value) < node["minItems"]:
            out.append(where + ": minItems")
        if "maxItems" in node and len(value) > node["maxItems"]:
            out.append(where + ": maxItems")
        if node.get("uniqueItems") and len({json.dumps(item, sort_keys=True) for item in value}) != len(value):
            out.append(where + ": uniqueItems")
        for index, item in enumerate(value):
            out.extend(shape_findings(item, node["items"], "%s[%d]" % (where, index)))
    return out


def schema_findings(doc, kind: str) -> list:
    validator = jsonschema.Draft202012Validator(_schema(kind))
    out = ["jsonschema: %s at %s" % (error.message[:160], "/".join(map(str, error.absolute_path)))
           for error in validator.iter_errors(doc)]
    return out + shape_findings(doc, _schema(kind))


# ------------------------------------------------------------------- B-LHA-13 role labels and the string rule (§3, §8)

def identity_probes():
    """Shapes of an identity, account, POSIX name or UID, custom role's full name, key or price. Built from parts at test
    time so that this module names none of them."""
    at = chr(64)
    principals = "|".join(["us" + "er", "gro" + "up", "service" + "Account", "dom" + "ain", "dele" + "ted"])
    resources = "|".join(["pro" + "jects", "fold" + "ers", "organi" + "zations", "billing" + "Accounts"])
    tlds = "|".join(["com", "net", "org", "io", "ai", "dev", "co", "edu", "gov", "cloud"])
    return [
        ("an address with the at sign", re.compile(re.escape(at))),
        ("an IAM principal", re.compile(r"\b(?:" + principals + r"):[A-Za-z0-9]")),
        ("a principal URI", re.compile(r"\bprincipal(?:Set)?:" + "//")),
        ("a service-account domain", re.compile("(?i)gservice" + "account")),
        ("a resource path with an id", re.compile(r"\b(?:" + resources + r")/[A-Za-z0-9]")),
        ("a custom role's full name", re.compile("/" + "ro" + "les/[A-Za-z]")),
        ("an OS Login POSIX name", re.compile(r"\b[a-z][a-z0-9.-]*_[a-z0-9-]+_(?:" + tlds + r")\b")),
        ("a service-account POSIX name", re.compile(r"\bsa_[0-9]{6,}\b")),
        ("a numeric UID or GID", re.compile(r"(?i)\b(?:uid|gid)\s*[:=]\s*[0-9]+")),
        ("an SSH public key", re.compile(r"(?:ssh-(?:rsa|ed25519|dss)|ecdsa-sha2-nistp[0-9]+)\s+AAAA")),
        ("a price", re.compile(r"[$\u20ac\u00a3]\s?[0-9]|(?i:\b[0-9]+(?:\.[0-9]+)?\s?(?:usd|eur|gbp)\b)")),
    ]


def string_rule():
    """LAB-RUNPLAN-001's string rule (FORBIDDEN_TEXT at the base), restated and built from parts."""
    return [re.compile(re.escape(chr(64))), re.compile("-" * 5 + "BEG" + "IN"), re.compile("PRIV" + "ATE KEY"),
            re.compile("AK" + "IA[0-9A-Z]{4}"), re.compile("AS" + "IA[0-9A-Z]{4}"),
            re.compile("AI" + "za[0-9A-Za-z_-]{4}"), re.compile("g" + "h[pousr]_[0-9A-Za-z]{4}"),
            re.compile("git" + "hub_pat_"), re.compile("xo" + "x[abpr]-"), re.compile("ya" + r"29\.[0-9A-Za-z_-]{4}"),
            re.compile("1" + "//[0-9A-Za-z_-]{4}"), re.compile("(?i)gservice" + "account"),
            re.compile("private" + "_key_id"), re.compile("GOC" + "SPX-"),
            re.compile("[0-9A-Fa-f]{6}-[0-9A-Fa-f]{6}-[0-9A-Fa-f]{6}")]


def identity_findings(doc) -> list:
    out = []
    probes = identity_probes()
    for where, text in (strings(doc) if not isinstance(doc, str) else [("$", doc)]):
        for name, probe in probes:
            if probe.search(text):
                out.append("%s: %s" % (where, name))

    def walk(value, where):
        if isinstance(value, dict):
            for key, item in value.items():
                if key.lower() in ("uid", "gid", "uidnumber", "gidnumber") and type(item) is int:
                    out.append("%s.%s: a numeric UID or GID" % (where, key))
                walk(item, where + "." + key)
        elif isinstance(value, list):
            for index, item in enumerate(value):
                walk(item, "%s[%d]" % (where, index))
    if not isinstance(doc, str):
        walk(doc, "$")
    return out


def string_rule_findings(doc) -> list:
    rules = string_rule()
    return ["%s: credential-like string" % where for where, text in strings(doc) if any(r.search(text) for r in rules)]


# --------------------------------------------------------------------------------------- the digest rule (section 4)

CITE_KEYS = {"path", "fileSha256", "lines", "fragments", "text", "span"}
MEMBER = re.compile(r"[A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*|\[[0-9]+\])*")


def cited(doc, where: str = "$") -> list:
    """Every cited entry (a dict carrying path, file sha256, lines, fragments, text and span), wherever it sits."""
    out = []
    if isinstance(doc, dict):
        if CITE_KEYS <= set(doc):
            out.append((where, doc))
        for key, item in doc.items():
            out.extend(cited(item, where + "." + key))
    elif isinstance(doc, list):
        for index, item in enumerate(doc):
            out.extend(cited(item, "%s[%d]" % (where, index)))
    return out


def fragment(data: bytes, frag):
    """Section 4: [startLine, startByte, endLine, endByte]; lines 1-based, bytes 0-based within their line, end exclusive;
    a fragment across lines holds the line feeds between them. Returns (bytes, absolute begin, absolute end)."""
    if not (isinstance(frag, list) and len(frag) == 4 and all(type(x) is int for x in frag)):
        raise ValueError("fragment form")
    start_line, start_byte, end_line, end_byte = frag
    lines = data.split(b"\n")
    if not 1 <= start_line <= end_line <= len(lines):
        raise ValueError("fragment lines")
    if not (0 <= start_byte <= len(lines[start_line - 1]) and 0 <= end_byte <= len(lines[end_line - 1])):
        raise ValueError("fragment bytes")
    starts = [0]
    for line in lines:
        starts.append(starts[-1] + len(line) + 1)
    begin = starts[start_line - 1] + start_byte
    end = starts[end_line - 1] + end_byte
    if begin >= end:
        raise ValueError("empty fragment")
    return data[begin:end], begin, end


def digest_findings(doc) -> list:
    """Section 4 and B-LHA-12: each cited entry's file sha256, text and span recomputed from the base bytes."""
    out = []
    if doc.get("baseCommit") != BASE_COMMIT:
        out.append("baseCommit is not the packet's base")
    entries = cited(doc)
    if not entries:
        out.append("no cited entry")
    for where, entry in entries:
        tag = "%s %s" % (where, entry.get("id"))
        path = entry.get("path")
        if path not in BASE_SHA256:
            out.append(tag + ": not a base document the design cites")
            continue
        data = base_bytes(path)
        if hashlib.sha256(data).hexdigest() != BASE_SHA256[path]:
            out.append(tag + ": the checkout's bytes are not the base's")
            continue
        if entry.get("fileSha256") != BASE_SHA256[path]:
            out.append(tag + ": file sha256")
        frags = entry.get("fragments")
        try:
            if not isinstance(frags, list) or not frags:
                raise ValueError("no fragment")
            parts = [fragment(data, frag) for frag in frags]
            text = JOIN.join(part.decode("utf-8") for part, _, _ in parts)
        except (ValueError, UnicodeDecodeError) as exc:
            out.append("%s: fragment %s" % (tag, exc))
            continue
        if any(parts[i][1] < parts[i - 1][2] for i in range(1, len(parts))):
            out.append(tag + ": fragments not in order")
        lines = entry.get("lines")
        if not (isinstance(lines, list) and len(lines) == 2 and all(type(x) is int for x in lines)
                and 1 <= lines[0] <= lines[1] and all(lines[0] <= f[0] and f[2] <= lines[1] for f in frags)):
            out.append(tag + ": lines do not hold the fragments")
        if entry.get("text") != text:
            out.append(tag + ": text is not the fragments' bytes joined by ' \u2026 '")
        span = hashlib.sha256(b"".join(part + b"\x00" for part, _, _ in parts)).hexdigest()
        if entry.get("span") != span:
            out.append(tag + ": span")
    return out


def resolve(doc, member: str):
    value = doc
    last = None
    for name, index in re.findall(r"([A-Za-z_][A-Za-z0-9_]*)|\[([0-9]+)\]", member):
        if name:
            if not isinstance(value, dict) or name not in value:
                raise KeyError(member)
            value, last = value[name], name
        else:
            if not isinstance(value, list) or int(index) >= len(value):
                raise KeyError(member)
            value, last = value[int(index)], int(index)
    return value, last


def member_findings(doc) -> list:
    """Section 4 rules: for JSON, the full member path, which exists at the base and is the cited bytes' member."""
    out = []
    for where, entry in cited(doc):
        tag = "%s %s" % (where, entry.get("id"))
        path = str(entry.get("path"))
        member = entry.get("member")
        if not path.endswith(".json"):
            if member is not None:
                out.append(tag + ": a member on a non-JSON citation")
            continue
        if not isinstance(member, str) or not MEMBER.fullmatch(member):
            out.append(tag + ": no full member path")
            continue
        if path not in BASE_SHA256:
            continue
        try:
            value, last = resolve(json.loads(base_bytes(path).decode("utf-8")), member)
        except (KeyError, ValueError):
            out.append(tag + ": member does not exist at the base in this full form")
            continue
        frags = entry.get("fragments") or [[1, 0, 1, 0]]
        lines = base_bytes(path).decode("utf-8").split("\n")
        segment = "\n".join(lines[frags[0][0] - 1:frags[-1][2]])
        scalar = None if isinstance(value, (dict, list)) else json.dumps(value, ensure_ascii=False)
        if isinstance(last, str) and '"%s"' % last not in segment:
            out.append(tag + ": the member's key is not on the cited lines")
        if scalar is not None:
            text = str(entry.get("text"))
            if scalar not in segment or not (text in scalar or scalar in text):
                out.append(tag + ": the cited bytes are not the member's value")
    return out


def _r(entry) -> str:
    return render(entry.get("text", ""))


def _parts(entry) -> list:
    return [render(part) for part in str(entry.get("text", "")).split(JOIN)]


def _first_line(entry):
    frags = entry.get("fragments")
    return frags[0][0] if isinstance(frags, list) and frags and isinstance(frags[0], list) else None


def _lines_cover(entry, start: int, end: int) -> bool:
    lines = entry.get("lines")
    return isinstance(lines, list) and len(lines) == 2 and lines[0] <= start and end <= lines[1]


def _group(doc, name: str) -> list:
    value = doc.get(name)
    return [entry for entry in value if isinstance(entry, dict)] if isinstance(value, list) else []


# Section 4 `supersedes`: the only relaxed predicates, member by member.
RELAXED = [
    ("LINUX_READINESS.md lines 63-66: Use only existing authorized zero-incremental-cost capacity",
     lambda e: e.get("path") == LR and _r(e) == "Use only existing authorized zero-incremental-cost capacity"),
    ("LINUX_READINESS.md lines 63-66: No cloud instance \u2026 is authorized, the cloud-instance fragments only",
     lambda e: e.get("path") == LR and _r(e) == "No cloud instance \u2026 is authorized"),
    ("linux-readiness.json billing.capacity", lambda e: e.get("path") == LRJ and e.get("member") == "billing.capacity"),
    ("linux-readiness.json billing.newProvisioning",
     lambda e: e.get("path") == LRJ and e.get("member") == "billing.newProvisioning"),
    ("LINUX_READINESS_REPAIRS.md lines 147-149: the existing zero-incremental-cost capacity condition",
     lambda e: e.get("path") == REP and _r(e) == "existing zero-incremental-cost capacity"),
    ("LINUX_READINESS_REPAIRS.md line 155: create capacity",
     lambda e: e.get("path") == REP and _r(e) == "create capacity" and _first_line(e) == 155),
    ("CI_CAPACITY_EXCEPTION.md line 7: zero-bill and no-cloud-provisioning, for live campaigns only",
     lambda e: e.get("path") == CIX and _first_line(e) == 7
     and set(_parts(e)) - {"live campaigns"} == {"zero-bill", "no-cloud-provisioning"}
     and ("live campaigns" in _parts(e) or any("LIVE_CAMPAIGN" in str(v) for v in e.values()))),
    ("LINUX_READINESS.md lines 66-68: independent signers, the predicate beginning at Missing",
     lambda e: e.get("path") == LR and _first_line(e) == 66 and _r(e).startswith("Missing")
     and "independent signers" in _r(e) and "hardware" not in _r(e)),
    ("LINUX_READINESS.md lines 146-148: the independent of the three authorities",
     lambda e: e.get("path") == LR and e.get("text") == "independent" and _first_line(e) == 147),
    ("linux-readiness.json evidence.requiredBindings INDEPENDENT_SIGNATURES",
     lambda e: e.get("path") == LRJ and str(e.get("member", "")).startswith("evidence.requiredBindings[")
     and e.get("text") == '"INDEPENDENT_SIGNATURES"'),
]


def _kept_no(phrase: str):
    return lambda e: (e.get("path") == LR and _r(e).startswith("No") and _r(e).endswith("is authorized")
                      and phrase in _r(e) and "cloud instance" not in _r(e))


def _member_is(path: str, member: str):
    return lambda e: e.get("path") == path and e.get("member") == member


# Section 4 `unchanged`: the kept predicates of every partly relaxed sentence, each its own entry.
KEPT = [
    ("LINUX_READINESS.md lines 63-69: no hosted runner", _kept_no("hosted runner")),
    ("LINUX_READINESS.md lines 63-69: no new broker", _kept_no("new broker")),
    ("LINUX_READINESS.md lines 63-69: no paid key", _kept_no("paid key")),
    ("LINUX_READINESS.md lines 63-69: no registry egress charge", _kept_no("registry egress charge")),
    ("LINUX_READINESS.md lines 63-69: no automatic package or image pull", _kept_no("automatic package/image pull")),
    ("LINUX_READINESS.md lines 66-68: missing hardware, preloaded tooling or OS isolation remains NOT_RUN_ENV_UNAVAILABLE",
     lambda e: e.get("path") == LR and _r(e).startswith("Missing") and "independent" not in _r(e)
     and all(w in _r(e) for w in ("hardware", "preloaded tooling", "OS isolation", "NOT_RUN_ENV_UNAVAILABLE"))),
    ("LINUX_READINESS.md lines 101-102",
     lambda e: e.get("path") == LR and _r(e) == "No stored administrator password, interactive prompt automation or "
     "broad passwordless sudo grant is introduced"),
    ("LINUX_READINESS.md lines 146-148: the only live entry point and the three authorities",
     lambda e: e.get("path") == LR and "independent" not in _r(e)
     and "The only live entry point remains the external root-owned launcher" in _r(e)
     and "PLATFORM_RELEASE, TENANT_LIVE_EXECUTION and CAPACITY_OPERATOR authorities" in _r(e)),
    ("linux-readiness.json billing.hostedRunners", _member_is(LRJ, "billing.hostedRunners")),
    ("linux-readiness.json billing.paidApis", _member_is(LRJ, "billing.paidApis")),
    ("linux-readiness.json billing.thirdPartyKeys (third-party keys stay refused)", _member_is(LRJ, "billing.thirdPartyKeys")),
    ("linux-readiness.json billing.rawContainerSockets (raw container sockets stay refused)",
     _member_is(LRJ, "billing.rawContainerSockets")),
    ("LINUX_READINESS_REPAIRS.md lines 147-149: tools, installation, isolation negatives and signed evidence",
     lambda e: e.get("path") == REP and _r(e).startswith("Native Linux remains NOT_RUN_ENV_UNAVAILABLE until")
     and "zero-incremental-cost" not in _r(e)
     and all(w in _r(e) for w in ("pinned native tools/caches", "reviewed installation", "actual isolation negatives",
                                  "signed build/runtime/campaign evidence"))),
    ("LINUX_READINESS_REPAIRS.md lines 154-156",
     lambda e: e.get("path") == REP and _r(e) == "Never operationally restore the unsafe live path, erase failed runs, "
     "relax packet or source custody, \u2026 or reverse tenant data"),
    ("CI_CAPACITY_EXCEPTION.md line 7: the defaults for the platform, tenant workflows, integrations, releases, production",
     lambda e: e.get("path") == CIX and "live campaigns" not in _r(e)
     and all(w in _r(e) for w in ("The platform, tenant workflows, provider integrations, releases",
                                  "production deployments", "zero-bill", "no-paid-API", "no-cloud-provisioning"))),
    ("CI_CAPACITY_EXCEPTION.md line 7: no paid API for live campaigns too",
     lambda e: e.get("path") == CIX and "no-paid-API" in _parts(e) and "zero-bill" not in _r(e)
     and "no-cloud-provisioning" not in _r(e)),
]

# Section 4: satisfied by the replacement predicate, none relaxed further.
SATISFIED = [
    ("LINUX_READINESS.md line 138: independent signatures",
     lambda e: e.get("path") == LR and _first_line(e) == 138 and _r(e) == "independent signatures"),
    ("TRUSTED_LIVE lines 456-457: a fresh independently signed native AMD64 qualification",
     lambda e: e.get("path") == TL and _lines_cover(e, 456, 457)
     and _r(e) == "a fresh independently signed native AMD64 qualification"),
    ("TRUSTED_LIVE line 532: After independent signatures",
     lambda e: e.get("path") == TL and _first_line(e) == 532 and _r(e) == "After independent signatures"),
    ("CREDENTIAL_ORDERING_REPAIR.md line 37",
     lambda e: e.get("path") == COR and _first_line(e) == 37
     and _r(e) == "all three independent valid and nonrevoked signer roles"),
]

# Section 4: kept at campaign, server, reader, cluster or endpoint level (`costScope`).
COST_SCOPE = [
    ("TRUSTED_LIVE lines 442-443", lambda e: e.get("path") == TL and _lines_cover(e, 442, 443)
     and _r(e) == "no raw container socket or new resource capacity is authorized"),
    ("CREDENTIAL_ORDERING_REPAIR.md line 94: create capacity",
     lambda e: e.get("path") == COR and _first_line(e) == 94 and _r(e) == "create capacity"),
    ("NATIVE_QUALIFICATION_READINESS.md line 110",
     lambda e: e.get("path") == NQR and _first_line(e) == 110 and _r(e) == "No new cgroup/capacity creation"),
    ("LINUX_READINESS.md line 163: Do not \u2026 destroy capacity",
     lambda e: e.get("path") == LR and _first_line(e) == 163 and _r(e) == "Do not \u2026 destroy capacity"),
    ("TRUSTED_LIVE lines 241-244: the endpoint cost disposition",
     lambda e: e.get("path") == TL and _lines_cover(e, 241, 244) and "_NON_METERED" in _r(e)),
    ("TRUSTED_LIVE line 339: the Kubernetes mutationProfile",
     lambda e: e.get("path") == TL and _first_line(e) == 339 and "ZERO_INCREMENTAL_COST_KUBERNETES_V1" in _r(e)),
]

# Section 4 `reviewedNotBinding` (Q-LHA-13 (a)).
REVIEWED = [
    ("NATIVE_QUALIFICATION_READINESS.md lines 22-23",
     lambda e: e.get("path") == NQR and _lines_cover(e, 22, 23)
     and _r(e).startswith("No new service, network endpoint, local socket, root key, signing role")),
    ("NATIVE_QUALIFICATION_READINESS.md closing sentence",
     lambda e: e.get("path") == NQR
     and _r(e).rstrip(".") == "No new key, admin prompt, download, hosted runner, cloud bill or API-key dependency"),
] + [("TRUSTED_LIVE publication-scope line %d" % n, (lambda n: lambda e: e.get("path") == TL and _lines_cover(e, n, n))(n))
     for n in (460, 484, 524, 540, 560)]
REVIEW_REASON = "states that packet's own publication scope, not a standing rule"


def match_findings(entries: list, expected: list, what: str, exact: bool) -> list:
    out = []
    for label, match in expected:
        count = sum(1 for entry in entries if match(entry))
        if count < 1 or (exact and count != 1):
            out.append("%s: %s matched %d entries" % (what, label, count))
    if exact:
        for entry in entries:
            if not any(match(entry) for _, match in expected):
                out.append("%s %s: not one the design lists" % (what, entry.get("id")))
    return out


def relaxed_findings(a) -> list:
    return match_findings(_group(a, "supersedes"), RELAXED, "supersedes", exact=True)


def kept_findings(a) -> list:
    unchanged = _group(a, "unchanged")
    out = match_findings(unchanged, KEPT, "unchanged", exact=False)
    ids = {entry.get("id") for entry in unchanged}
    for entry in _group(a, "supersedes"):
        for kept in entry.get("keptIn", []) or []:
            if kept not in ids:
                out.append("supersedes %s: kept predicate %s is not in unchanged" % (entry.get("id"), kept))
    return out


DESIGN_REPLACEMENT = ("INDEPENDENT_SIGNATURES stays a required binding. It is satisfied by signatures of the three "
                      "distinct authorities (PLATFORM_RELEASE, TENANT_LIVE_EXECUTION, CAPACITY_OPERATOR), each with its "
                      "own key id, purpose, token and sealed backup, under one principal, with the disclosure signers: "
                      "SINGLE_PRINCIPAL_SEPARATED_KEYS.")
DISCLOSURE = {"signers": "SINGLE_PRINCIPAL_SEPARATED_KEYS"}


def _sha(text) -> str:
    return hashlib.sha256(str(text).encode("utf-8")).hexdigest()


def replacement_findings(a) -> list:
    """Section 4: the independence clause is admitted only together with its replacement predicate and the owner's
    Q-LHA-1 (a) answer, carried verbatim."""
    out = []
    rp = a.get("replacementPredicate")
    if not isinstance(rp, dict):
        return ["no replacement predicate"]
    if rp.get("binding") != "INDEPENDENT_SIGNATURES" or rp.get("required") is not True:
        out.append("INDEPENDENT_SIGNATURES is not a required binding")
    if sorted(rp.get("authorities") or []) != sorted(["PLATFORM_RELEASE", "TENANT_LIVE_EXECUTION", "CAPACITY_OPERATOR"]):
        out.append("the three distinct authorities")
    distinct = " ".join(map(str, rp.get("distinctPerAuthority") or []))
    for word in ("KEY_ID", "PURPOSE", "TOKEN", "SEALED_BACKUP"):
        if word not in distinct:
            out.append("distinct per authority: " + word)
    if rp.get("disclosure") != DISCLOSURE:
        out.append("the disclosure signers: SINGLE_PRINCIPAL_SEPARATED_KEYS")
    if _sha(rp.get("ownerAnswer")) != DECISION_PINS["Q-LHA-1"]:
        out.append("the owner's Q-LHA-1 (a) answer is not carried verbatim")
    if render(str(rp.get("text", "")).replace("`", "")) != DESIGN_REPLACEMENT:
        out.append("the replacement predicate's text is not the design's")
    independence = [e for e in _group(a, "supersedes") if RELAXED[7][1](e) or RELAXED[8][1](e) or RELAXED[9][1](e)]
    if len(independence) != 3:
        out.append("the independence clause's three superseded texts")
    return out


def capacity_findings(a) -> list:
    """Section 4 `capacity`, closed, exactly as the design writes it; licenceCharge NONE."""
    out = []
    c = a.get("capacity") or {}
    if c.get("rule") != "OWNER_APPROVED_GCP_PER_RUN":
        out.append("capacity rule")
    if c.get("contract") != "MET-LINUX-007":
        out.append("capacity contract")
    if c.get("binding") != ["PLAN_SHA256", "LEASE", "COST_CEILING", "TEARDOWN_REPORT"]:
        out.append("capacity binding")
    if c.get("licenceCharge") != "NONE":
        out.append("licenceCharge is not NONE")
    run = c.get("runProject") or {}
    if run.get("separateFromLabFoundation") is not True or run.get("defaultNetwork") is not False:
        out.append("the run project separate from the lab foundation, with no default network")
    if not str(c.get("hostRecipe", "")).endswith("host-recipe.json"):
        out.append("the host follows host-recipe.json")
    return out


def evidence_findings(a) -> list:
    """Section 4 `evidence`: unchanged; approving capacity is not qualification."""
    out = []
    e = a.get("evidence") or {}
    if e.get("nativeAmd64") != "NOT_RUN_ENV_UNAVAILABLE" or e.get("arm64") != "NOT_RUN_ENV_UNAVAILABLE":
        out.append("an evidence state moved")
    if [k for k, v in e.items() if "qualification" in k.lower() and v is not False] or \
            not any("qualification" in k.lower() and v is False for k, v in e.items()):
        out.append("approving capacity is not qualification")
    members = {entry.get("member") for _, entry in cited(a)}
    for member in ("gate.maximumEvidenceAgeHours", "evidence.signingAuthority"):
        if member not in members:
            out.append("the design's full member path %s is not cited" % member)
    return out


def decision_findings(a) -> list:
    """Section 4 `decisions`: the owner's decision as MET-LINUX-007 records it; the decision lines only, verbatim."""
    out = []
    lrp = [entry for _, entry in cited(a) if entry.get("path") == LRP]
    if len(lrp) != 1 or _r(lrp[0]) != ("Linux capacity for CONF-LINUX-001 and W06 is the owner's GCP compute, and each "
                                       "run plan goes to the owner first"):
        out.append("the owner's decision as MET-LINUX-007 records it")
    lines = (a.get("decisions") or {}).get("decisionLines") or []
    digests = {}
    for line in lines:
        digests.setdefault(_sha(line.get("text")), []).append(line)
    for label, digest in DECISION_PINS.items():
        if digest not in digests:
            out.append("decision line %s missing or not verbatim" % label)
    for label in ("LHA3-8", "B-LHA-3"):
        for line in digests.get(DECISION_PINS[label], []):
            if "SUPERSEDED" not in [v for v in line.values() if isinstance(v, str)]:
                out.append("decision %s is not marked superseded" % label)
    for line in digests.get(DECISION_PINS["CUSTOM-ROLE"], []):
        if "SUPERSEDED" in [v for v in line.values() if isinstance(v, str)]:
            out.append("the custom-role decision is marked superseded")
    texts = "\n".join(str(line.get("text")) for line in lines)
    for words in OWNER_WORDS:
        if words not in texts:
            out.append("owner words missing: " + words)
    if SPEND_WORDING not in texts:
        out.append("the monitor's spend-condition wording (LHA2-20)")
    return out


def _reading(a, test):
    found = [r for r in _group(a, "readings") if test(r)]
    return found[0] if len(found) == 1 else None


def signing_reading(a):
    return _reading(a, lambda r: any(o.get("member") == "evidence.signingAuthority" for o in _group(r, "occurrences")))


def pre_reading(a):
    return _reading(a, lambda r: "pre-existing" in [str(w).lower() for w in r.get("words", [])])


# Section 4 `readings`: the occurrences the design names. Ranges are base lines.
SIGNING_OCCURRENCES = [
    ("evidence.signingAuthority", lambda o: o.get("path") == LRJ and o.get("member") == "evidence.signingAuthority"),
    ("OPERATOR.md step 4", lambda o: o.get("path") == OPR and 93 <= (_first_line(o) or 0) <= 95),
    ("OPERATOR.md step 5", lambda o: o.get("path") == OPR and 96 <= (_first_line(o) or 0) <= 103),
    ("OPERATOR.md step 8", lambda o: o.get("path") == OPR and 113 <= (_first_line(o) or 0) <= 118),
    ("LINUX_READINESS.md line 147, existing", lambda o: o.get("path") == LR and _first_line(o) == 147),
]
PRE_RANGES = [(NQR, 28, 29), (NQR, 37, 37), (TL, 240, 241), (TL, 254, 257), (TL, 260, 260), (TL, 281, 281),
              (TL, 302, 302), (TL, 321, 322), (TL, 442, 443), (COR, 87, 87)]
PRE_WORD = re.compile(rb"(?i)pre-?existing")
EXISTING_WORD = re.compile(rb"(?i)\bexisting\b")


def _occurrence_spans(reading) -> list:
    spans = []
    for o in _group(reading or {}, "occurrences"):
        path = o.get("path")
        if path not in BASE_SHA256:
            continue
        try:
            for frag in o.get("fragments") or []:
                _, begin, end = fragment(base_bytes(path), frag)
                spans.append((path, begin, end))
        except ValueError:
            continue
    return spans


def _covered(spans, path, begin, end) -> bool:
    return any(p == path and b <= begin and end <= e for p, b, e in spans)


def _line_span(path, start, end):
    """Absolute byte offsets of base lines start..end (1-based, inclusive), without the final line feed."""
    lines = base_bytes(path).split(b"\n")
    begin = sum(len(line) + 1 for line in lines[:start - 1])
    stop = sum(len(line) + 1 for line in lines[:end]) - 1
    return begin, stop


def reading_findings(a) -> list:
    """Section 4 `readings` (MON-LHA-16-1; Q-LHA-14) and B-LHA-11."""
    out = []
    sa, pre = signing_reading(a), pre_reading(a)
    if sa is None or pre is None:
        return ["the signing-authority and pre-existing readings"]
    for label, match in SIGNING_OCCURRENCES:
        if not any(match(o) for o in _group(sa, "occurrences")):
            out.append("signing-authority reading: occurrence " + label)
    for o in _group(sa, "occurrences"):
        if str(o.get("text")).lower() != "existing" and o.get("member") != "evidence.signingAuthority":
            out.append("signing-authority occurrence %s is not the word existing" % o.get("id"))
    text = render(sa.get("reading", ""))
    for words in ("post-merge key ceremony", "custody-model.json", "never introduced during a run"):
        if words not in text:
            out.append("signing-authority reading text: " + words)
    for path, start, end in PRE_RANGES:
        if not any(o.get("path") == path and start <= (_first_line(o) or 0) <= end for o in _group(pre, "occurrences")):
            out.append("pre-existing reading: occurrence %s lines %d-%d" % (path, start, end))
    if not any(o.get("member") == "evidence.runtimeTransport" for o in _group(pre, "occurrences")):
        out.append("pre-existing reading: evidence.runtimeTransport")
    words = {str(w).lower() for w in pre.get("words", [])}
    for o in _group(pre, "occurrences"):
        if str(o.get("text")).lower() not in words:
            out.append("pre-existing occurrence %s is not one of the reading's words" % o.get("id"))
    text = render(pre.get("reading", ""))
    for words_ in ("verified by the operator before the envelope is signed", "never by the campaign", "step 7"):
        if words_ not in text:
            out.append("pre-existing reading text: " + words_)
    # every occurrence of the words inside the design's cited ranges is listed with its span
    pre_spans, sa_spans = _occurrence_spans(pre), _occurrence_spans(sa)
    for path, start, end in PRE_RANGES:
        begin, stop = _line_span(path, start, end)
        data = base_bytes(path)
        for m in PRE_WORD.finditer(data, begin, stop):
            if not _covered(pre_spans, path, m.start(), m.end()):
                out.append("pre-existing at %s offset %d (lines %d-%d) is not listed" % (path, m.start(), start, end))
    begin, stop = _line_span(NQR, 37, 37)
    for m in EXISTING_WORD.finditer(base_bytes(NQR), begin, stop):
        if not _covered(pre_spans, NQR, m.start(), m.end()):
            out.append("existing operator at NATIVE_QUALIFICATION_READINESS.md line 37 is not listed")
    for step, (start, end) in OPERATOR_STEPS.items():
        begin, stop = _line_span(OPR, start, end)
        for m in EXISTING_WORD.finditer(base_bytes(OPR), begin, stop):
            if not _covered(sa_spans, OPR, m.start(), m.end()):
                out.append("existing in OPERATOR.md step %d is not listed" % step)
    return out


def reading_coverage_findings(a) -> list:
    """Section 4 `readings`: "Each reading applies to every occurrence of its words in the superseded, kept and
    satisfied texts, each listed with its span." Every pre-existing/preexisting inside those texts' fragments, and the
    existing of LINUX_READINESS.md line 147 (kept), must be covered by a listed occurrence."""
    out = []
    pre_spans = _occurrence_spans(pre_reading(a))
    sa_spans = _occurrence_spans(signing_reading(a))
    for group in ("supersedes", "unchanged", "satisfied"):
        for entry in _group(a, group):
            path = entry.get("path")
            if path not in BASE_SHA256:
                continue
            data = base_bytes(path)
            for frag in entry.get("fragments") or []:
                try:
                    _, begin, end = fragment(data, frag)
                except ValueError:
                    continue
                for m in PRE_WORD.finditer(data, begin, end):
                    if not _covered(pre_spans, path, m.start(), m.end()):
                        out.append("%s %s: %r at %s line %d is not listed in the pre-existing reading"
                                   % (group, entry.get("id"), m.group().decode(), path,
                                      data.count(b"\n", 0, m.start()) + 1))
                if path == LR:
                    for m in EXISTING_WORD.finditer(data, begin, end):
                        line = data.count(b"\n", 0, m.start()) + 1
                        if line == 147 and not _covered(sa_spans, path, m.start(), m.end()):
                            out.append("%s %s: existing at line 147 is not under the signing-authority reading"
                                       % (group, entry.get("id")))
    return out


# ----------------------------------------------------------------------------- record predicates (sections 5, 6 and 7)

def _by(items, key, value):
    return [item for item in items if isinstance(item, dict) and item.get(key) == value]


def _has_all(values, words) -> list:
    joined = " ".join(map(str, values or []))
    return [w for w in words if w not in joined]


LOGIN_ABSENT = ["compute.instances.osAdminLogin", "iam.roles.create", "iam.roles.update",
                "resourcemanager.folders.setIamPolicy", "resourcemanager.organizations.setIamPolicy",
                "iam.serviceAccounts.actAs", "iam.serviceAccounts.getAccessToken", "iam.serviceAccounts.signBlob",
                "iam.serviceAccounts.signJwt", "iam.serviceAccounts.implicitDelegation",
                "iam.serviceAccounts.getOpenIdToken", "iam.serviceAccountKeys.create"]
ADMIN_ABSENT = ["compute.instances.osLogin", "compute.instances.osAdminLogin"]


def _login_absent_findings(absent, where) -> list:
    out = ["%s: %s not tested" % (where, p) for p in LOGIN_ABSENT if p not in (absent or [])]
    absent = [str(p) for p in absent or []]
    if not any(p.endswith("projects.setIamPolicy") for p in absent):
        out.append(where + ": project setIamPolicy not tested")
    if not any(p.endswith("instances.setIamPolicy") for p in absent):
        out.append(where + ": instance setIamPolicy not tested")
    if not any("tag" in p.lower() and "binding" in p.lower() for p in absent):
        out.append(where + ": no tag-binding permission tested")
    return out


def recipe_findings(r) -> list:
    """Section 5 (`host-recipe.json`) and its section 8 refusals, as this oracle's own checks."""
    out = []
    p = r.get("project") or {}
    if p.get("defaultNetwork") is not False:
        out.append("project: a default network")
    if p.get("cloudNat") is not False:
        out.append("project: NAT present")
    if p.get("privateGoogleAccess") is not False:
        out.append("project: Private Google Access on")
    if p.get("osLoginPolicy") != "ENFORCED":
        out.append("project: OS Login policy not enforced")
    if p.get("computeBetweenRuns") is not False or p.get("runsAtATime") != 1:
        out.append("project: one run at a time, no compute between runs")
    hosts = {h.get("role"): h for h in r.get("hosts") or []}
    if set(hosts) != {"PROXY_OPERATOR_HOST", "CLUSTER_NODE"}:
        out.append("hosts: not the proxy/operator host and the cluster node")
    if any(h.get("architecture") != "AMD64" for h in hosts.values()):
        out.append("hosts: not AMD64")
    proxy = hosts.get("PROXY_OPERATOR_HOST") or {}
    node = hosts.get("CLUSTER_NODE") or {}
    if proxy.get("rootKubeconfig") is not False or proxy.get("containerRuntimeSocket") is not False:
        out.append("hosts: a kubeconfig or container-runtime socket on the proxy/operator host")
    if proxy.get("boots") != "CUSTOM_IMAGE" or node.get("boots") != "PINNED_FAMILY_IMAGE":
        out.append("hosts: boot images")
    if node.get("filesAfterRevocation") != "NONE":
        out.append("hosts: the cluster node needs a file after the revocation")
    flows = {f.get("id"): f for f in r.get("internalFlows") or []}
    if set(flows) != {"F1", "F2"}:
        out.append("internalFlows: an internal path other than F1 and F2")
    else:
        if (flows["F1"].get("from"), flows["F1"].get("to")) != ("PROXY_OPERATOR_HOST", "CLUSTER_NODE") or \
                (flows["F2"].get("from"), flows["F2"].get("to")) != ("CLUSTER_NODE", "PROXY_OPERATOR_HOST") or \
                any(f.get("protocol") != "tcp" for f in flows.values()):
            out.append("internalFlows: F1 and F2 directions or protocol")
    fw = r.get("firewall") or {}
    ingress = fw.get("ingress") or []
    if len(ingress) != 1 or ingress[0].get("sourceRange") != "35.235.240.0/20" or ingress[0].get("protocol") != "tcp" \
            or ingress[0].get("port") != 22:
        out.append("firewall: ingress other than IAP tcp 22")
    if sorted(fw.get("internal") or []) != ["F1", "F2"]:
        out.append("firewall: internal rules other than F1 and F2")
    allow = fw.get("setupWindowAllow") or {}
    if not allow.get("byteCeiling") or allow.get("paidFirewallFeature") is not False or allow.get("removedAtStep") != 6:
        out.append("firewall: an allow rule without a byte ceiling, or not removed at step 6")
    deny = fw.get("egressDenyAll") or {}
    if deny.get("createdAtStep") != 2 or deny.get("belowSetupWindowAllow") is not True:
        out.append("firewall: the deny-all egress rule at step 2 below the window's allow rule")
    m = r.get("machine") or {}
    if sorted(m.get("appliesTo") or []) != ["CLUSTER_NODE", "PROXY_OPERATOR_HOST"]:
        out.append("machine: not both hosts")
    if m.get("shieldedVm") != {"secureBoot": True, "vtpm": True, "integrityMonitoring": True}:
        out.append("machine: Shielded VM off")
    if m.get("serialPortAccess") is not False:
        out.append("machine: serial port on")
    if m.get("serviceAccount") is not False or m.get("scopes") != []:
        out.append("machine: a service account or scopes")
    meta = {x.get("key"): x.get("value") for x in m.get("metadata") or []}
    if meta != {"enable-oslogin": "TRUE", "enable-oslogin-2fa": "TRUE", "block-project-ssh-keys": "TRUE"}:
        out.append("machine: OS Login or its 2FA off, or other metadata")
    refused = " ".join(m.get("refusedMetadata") or [])
    for word in ("ssh-keys", "startup-script", "shutdown-script", "guest-attributes"):
        if word not in refused:
            out.append("machine: metadata refusal " + word)
    maint = m.get("maintenance") or {}
    if maint.get("onHostMaintenance") != "MIGRATE" or maint.get("automaticRestartInLease") is not False \
            or maint.get("bootIdRecordedAtStep") != 11:
        out.append("machine: maintenance")
    mrd = m.get("maxRunDuration") or {}
    if mrd.get("set") is not True or mrd.get("action") != "DELETE" or mrd.get("endsNoLaterThan") != "LEASE_END":
        out.append("machine: a maximum run duration missing, or later than the lease's end")
    ga = r.get("guestAgent") or {}
    if sorted(ga.get("on") or []) != sorted(["OS_LOGIN_NSS_PAM", "CLOCK_SYNC"]):
        out.append("guestAgent: an unlisted feature left on")
    missing = _has_all(ga.get("off"), ["ACCOUNT", "SSH_KEY", "SCRIPT", "NETWORK_INTERFACE", "DIAGNOSTIC", "SNAPSHOT"])
    if missing or ga.get("checkedAtStep") != 11:
        out.append("guestAgent: off list or check step %s" % missing)
    img = r.get("image") or {}
    if img.get("architecture") != "AMD64":
        out.append("image: wrong architecture")
    if img.get("licenceCharge") != "NONE":
        out.append("image: licenceCharge other than NONE")
    if img.get("selinux") != "ENFORCING":
        out.append("image: SELinux not enforcing")
    if "RHEL_10" not in str(img.get("familyKind")) or "NO_LICENCE_FEE" not in str(img.get("familyKind")) \
            or img.get("family") not in (img.get("allowedFamilies") or []):
        out.append("image: not a no-licence-fee RHEL-10-compatible family")
    ci = img.get("customImage") or {}
    if ci.get("for") != "PROXY_OPERATOR_HOST" or ci.get("rootFilesystem") != "EXT4_WITH_VERITY" \
            or ci.get("usrOnRoot") is not True or "UEFI" not in str(ci.get("guestFeatures")):
        out.append("image: the custom ext4-verity image with /usr on the root and UEFI")
    if ci.get("buildDiskDeletedAtStep") != 5:
        out.append("image: a build disk left after step 5")
    if ci.get("proxyOperatorHostBootsRecordedImage") is not True:
        out.append("image: the proxy/operator host not booted from the recorded custom image")
    if ci.get("deletedAtTeardown") is not True:
        out.append("image: a custom image not deleted at teardown")
    dig = img.get("imageDigest") or {}
    if "INVENTORY" not in str(dig.get("is")) or dig.get("takenAtStep") != 5 or "READ_ONLY" not in str(dig.get("from")) \
            or dig.get("recomputedOffHost") is not True or dig.get("coversLaterSteps") is not False:
        out.append("image: imageDigest is the custom image's own inventory, at step 5, read-only, recomputed off host")
    if _has_all(dig.get("inventoryFields"), ["path", "type", "mode", "owner", "size", "sha256"]):
        out.append("image: inventory fields")
    inv = r.get("hostInventory") or {}
    recs = {x.get("host"): x for x in inv.get("records") or []}
    if set(recs) != {"PROXY_OPERATOR_HOST", "CLUSTER_NODE"}:
        out.append("hostInventory: an inventory without its host")
    for host, rec in recs.items():
        if _has_all(rec.get("scope"), ["SYSTEM_TREES", "/opt/planeon/tools", "/opt/planeon/cache", "/opt/planeon/python",
                                       "/opt/planeon/bin", "/opt/planeon/work", "/etc", "BOOT_CHAIN"]):
            out.append("hostInventory: an inventory without its scope (%s)" % host)
    covered = inv.get("coveredInstallSteps") or []
    if inv.get("frozenAtStep") != 9 or (covered and max(covered) >= 9) or 8 not in covered:
        out.append("hostInventory: frozen before an install that changes a covered path")
    if inv.get("invalidateOn") != "HOST_OR_ISOLATION_CHANGE":
        out.append("hostInventory: gate.invalidateOn HOST_OR_ISOLATION_CHANGE")
    left = _has_all([x.get("what") for x in inv.get("leftOut") or []],
                    ["CLUSTER_STATE", "NONCE_LEDGER", "LOGS", "STEP_10", "DROP"])
    if left:
        out.append("hostInventory: left-out records %s" % left)
    ra = r.get("rootAliases") or {}
    if ra.get("rootLink") != "/lib64" or ra.get("loader") != "/lib64/ld-linux-x86-64.so.2" or ra.get("checkAtStep") != 9 \
            or "NOT_RUN_ENV_UNAVAILABLE" not in str(ra.get("uncoveredUsedPath")):
        out.append("rootAliases")
    out.extend(profile_findings(r.get("profile") or []))
    out.extend(access_findings(r.get("access") or {}, r))
    eg = r.get("egress") or {}
    if "SETUP_WINDOW" not in str(eg.get("window")) or "DIGEST_PINNED" not in str(eg.get("fetches")) \
            or "IP_RANGES" not in str(eg.get("matching")) or eg.get("paidFirewallFeature") is not False \
            or "CEILING" not in str(eg.get("byteCeiling")):
        out.append("egress: the setup window, digest-pinned fetches, IP ranges, byte ceiling")
    closure = eg.get("closure") or {}
    if closure.get("denyAllCreatedAtStep") != 2 or closure.get("closedAtStep") != 6 \
            or _has_all(closure.get("removes"), ["ALLOW_RULE", "EXTERNAL_ADDRESSES"]):
        out.append("egress: closure")
    if sorted(eg.get("expectedExceptions") or []) != ["F1", "F2", "METADATA_ADDRESS"]:
        out.append("egress: expected exceptions are the metadata address, F1 and F2")
    camp = eg.get("atCampaign") or {}
    if camp.get("externalAddress") is not False or camp.get("allowEgressRule") is not False:
        out.append("egress: an external address or an allow-egress rule at campaign time")
    t = r.get("time") or {}
    if t.get("daemon") != "CHRONY" or _has_all(t.get("capturedAtPreflight"), ["CLOCK_SOURCE", "OFFSET"]):
        out.append("time: chrony; clock source and offset at preflight")
    pk = r.get("packages") or {}
    if pk.get("automaticUpdaters") != "OFF":
        out.append("packages: an automatic updater on")
    if any("SHA256" not in str(s.get("pin")) for s in pk.get("sources") or []) or not pk.get("sources"):
        out.append("packages: a package without a file digest")
    if _has_all(pk.get("proxyOperatorHost"), ["GIT", "/usr/bin/firejail", "/opt/planeon/python/3.12.14", "NODE"]):
        out.append("packages: the proxy/operator host's packages")
    if pk.get("toolRoot") != "/opt/planeon/tools" or pk.get("cacheRoot") != "/opt/planeon/cache":
        out.append("packages: tool and cache roots")
    src = r.get("source") or {}
    if src.get("withGit") is not True or src.get("treeSha256") is not True:
        out.append("source: a transfer without .git or treeSha256")
    if src.get("repositoryCredentialOnHost") is not False or "IAP" not in str(src.get("transfer")):
        out.append("source: by digest over the IAP tunnel, no repository credential")
    cost = {x.get("item"): x for x in r.get("costScope") or []}
    if any(x.get("planLineItem") is not True for x in cost.values()):
        out.append("costScope: a paid item without its plan line item")
    missing = _has_all(list(cost), ["PROXY_OPERATOR_HOST_MACHINE_HOURS", "PROXY_OPERATOR_HOST_BOOT_DISK",
                                    "CLUSTER_NODE_MACHINE_HOURS", "CLUSTER_NODE_BOOT_DISK", "BUILD_DISK",
                                    "CUSTOM_IMAGE"])
    if missing:
        out.append("costScope: items %s" % missing)
    td = r.get("teardown") or {}
    if "CUSTOM_IMAGE" not in " ".join(td.get("deletes") or []):
        out.append("teardown: a custom image not deleted at teardown")
    if "STEP_15" not in str(td.get("first")):
        out.append("teardown: the export first")
    rb = r.get("runbook") or []
    if [s.get("step") for s in rb] != list(range(1, 17)):
        out.append("runbook: steps 1 to 16 in order")
    for s in rb:
        if isinstance(s.get("step"), int) and s["step"] >= 11 and str(s.get("onHost")).endswith("_WITH_ADMIN"):
            out.append("runbook: step %d runs with admin after the revocation" % s["step"])
    return out


def profile_findings(rows) -> list:
    """Section 5 `profile` (MON-LHA-SPLIT): owner, step and check per MET-REPAIR-015 prerequisite."""
    expected = [("SELINUX", "RECIPE", [4, 5]), ("BINARY_POLICY", "OPERATOR", [7]), ("VERITY", "RECIPE", [4, 5, 7]),
                ("CGROUP_V2", "RECIPE", [4, 5, 7]), ("BPF", "OPERATOR", [7]), ("KERNEL", "RECIPE", [11]),
                ("SERIALIS", "OPERATOR", [7])]
    out = []
    if len(rows) != 7:
        out.append("profile: seven prerequisites")
    for word, owner, steps in expected:
        found = [row for row in rows if word in str(row.get("prerequisite"))]
        if len(found) != 1 or owner not in str(found[0].get("owner")) or found[0].get("steps") != steps:
            out.append("profile: %s owner or steps" % word)
    selinux = [row for row in rows if "SELINUX" in str(row.get("prerequisite"))]
    if not selinux or selinux[0].get("value") != "ENFORCING":
        out.append("profile: SELinux not enforcing")
    policy = [row for row in rows if "BINARY_POLICY" in str(row.get("prerequisite"))]
    if not policy or "DENY_UNKNOWN_1" not in str(policy[0].get("value")):
        out.append("profile: the active policy's deny_unknown not 1")
    return out


def access_findings(acc, r) -> list:
    """Section 5 `access` (Q-LHA-12 (a), MON-LHA-12R, the custom-role decision, Q-LHA5-1) and B-LHA-14 to B-LHA-18."""
    out = []
    ssh = acc.get("ssh") or {}
    if ssh.get("only") != "IAP" or ssh.get("sourceRange") != "35.235.240.0/20" or ssh.get("port") != 22:
        out.append("access: SSH only through IAP")
    ids = {i.get("label"): i for i in acc.get("identities") or []}
    if set(ids) != {"OWNER_LOGIN", "OWNER_ADMIN"}:
        out.append("access: the two identities by role label")
    login, admin = ids.get("OWNER_LOGIN") or {}, ids.get("OWNER_ADMIN") or {}
    if login.get("administersIam") is not False or admin.get("administersIam") is not True:
        out.append("access: only the administering identity administers IAM")
    if login.get("osLogin") is not True or login.get("twoStepVerification") is not True or admin.get("osLogin") is not False:
        out.append("access: OS Login with 2-step verification for the login identity only")
    base = acc.get("loginBaseline") or {}
    if base.get("label") != "OWNER_LOGIN_BASELINE" or base.get("kind") != "CUSTOM_ROLE" or base.get("basicRole") != "NONE":
        out.append("access: a basic role in the login identity's baseline")
    if sorted(base.get("inPlaceOf") or []) != ["EDITOR", "OWNER", "VIEWER"]:
        out.append("access: the custom role in place of Owner, Editor or Viewer")
    out.extend(_login_absent_findings(base.get("excludes"), "access: the baseline excludes"))
    life = base.get("lifecycle") or {}
    if life.get("createdBy") != "OWNER_ADMIN" or life.get("boundBy") != "OWNER_ADMIN" \
            or life.get("keptBetweenRuns") is not True or life.get("deletedAtTeardown") is not False:
        out.append("access: the custom role's lifecycle (LHA5-8)")
    if _has_all(base.get("noOtherGrant"), ["DIRECT", "GROUP", "DOMAIN", "PRINCIPAL_SET", "FOLDER", "ORGANIZATION"]):
        out.append("access: no other grant through direct, group, domain, principal-set, folder or organization")
    lease = acc.get("leaseBindings") or []
    for b in lease:
        if b.get("grantedBy") != "OWNER_ADMIN" or b.get("revokedBy") != "OWNER_ADMIN":
            out.append("access: a run binding granted or revoked by the login identity")
        if b.get("counted") != "IAM_BINDINGS_ADDED":
            out.append("access: a lease binding not counted in IAM_BINDINGS_ADDED")
    roles = [str(b.get("role")) for b in lease]
    admin_bindings = [b for b in lease if "ADMIN" in str(b.get("role"))]
    if not any("IAP" in x for x in roles) or len(admin_bindings) != 1 or admin_bindings[0].get("revokedAtStep") != 10 \
            or not any("OS_LOGIN" in x and "ADMIN" not in x for x in roles):
        out.append("access: the IAP, OS Login admin (revoked at step 10) and non-admin login bindings")
    rev = acc.get("revocation") or {}
    if rev.get("atStep") != 10 or rev.get("by") != "OWNER_ADMIN" or rev.get("denyPolicy") is not False \
            or rev.get("folderOrOrganizationGrant") is not False:
        out.append("access: the revocation at step 10 by OWNER_ADMIN, no deny policy, no folder or organization grant")
    checks = acc.get("effectiveChecks") or []
    login_checks = {c.get("step"): c for c in checks if c.get("identity") == "OWNER_LOGIN"}
    for step in (1, 10, 15):
        c = login_checks.get(step)
        if c is None:
            out.append("access: no effective check of the login identity at step %d" % step)
            continue
        out.extend(_login_absent_findings(c.get("absent"), "access: step %d" % step))
        if _has_all(c.get("resources"), ["PROJECT", "INSTANCE", "SERVICE_ACCOUNT", "FOLDER", "ORGANIZATION"]):
            out.append("access: step %d resources" % step)
        if _has_all(c.get("grantPaths"), ["BASIC", "CUSTOM", "INHERITED", "GROUP", "DOMAIN", "PRINCIPAL_SET",
                                          "CONDITIONAL"]):
            out.append("access: step %d grant paths" % step)
        if "REFUSE" not in str(c.get("onFinding")):
            out.append("access: step %d finding does not refuse the run's evidence" % step)
        if step in (10, 15) and c.get("checksPermissionListAgainstPlan") is not True:
            out.append("access: the custom role's permission list not compared with the plan's at step %d" % step)
        if "OWNER_LOGIN" in str(c.get("runBy")):
            out.append("access: step %d check run by the login identity" % step)
    admin_checks = {c.get("step"): c for c in checks if c.get("identity") == "OWNER_ADMIN"}
    for step in (1, 10, 15):
        c = admin_checks.get(step)
        if c is None or _has_all(c.get("absent"), ADMIN_ABSENT) or \
                not any("iap" in str(x).lower() and "tunnel" in str(x).lower() for x in c.get("absent") or []) or \
                "REFUSE" not in str(c.get("onFinding")):
            out.append("access: OWNER_ADMIN holds a login permission (step %d)" % step)
    audit = acc.get("auditLogCheck") or {}
    if audit.get("log") != "ADMIN_ACTIVITY" or "STEP_10" not in str(audit.get("from")) \
            or "TEARDOWN" not in str(audit.get("to")):
        out.append("access: the Admin Activity audit log from step 10 to teardown")
    if "REFUSE" not in str(audit.get("anyCustomRoleChange")) or "REFUSE" not in str(audit.get("anyOtherEntry")):
        out.append("access: an audit-log entry from step 10 to teardown not refused")
    if acc.get("afterRevocationRootFiles") != "SIGNED_DROP_INSTALLER_ONLY":
        out.append("access: root-owned files after the revocation only through the signed-drop installer")
    td = acc.get("teardown") or {}
    if td.get("by") != "OWNER_ADMIN" or "EVERY_BINDING_GRANTED_SINCE_THE_LEASE_STARTED" != td.get("revokes") \
            or _has_all(td.get("keeps"), ["OWNER_LOGIN_BASELINE"]):
        out.append("access: teardown revokes every lease binding and keeps the baseline custom role")
    for s in r.get("runbook") or []:
        if s.get("cloudActionsBy") == "OWNER_LOGIN":
            out.append("runbook: step %s cloud actions by the login identity" % s.get("step"))
    return out


def launcher_findings(li) -> list:
    """Section 6 (`launcher-install.json`) and its section 8 refusals, as this oracle's own checks."""
    out = []
    if li.get("repositoryInstalls") is not False:
        out.append("the repository installs something")
    for s in li.get("steps") or []:
        if not s.get("inputDigests"):
            out.append("step %s without its input digests" % s.get("id"))
        if not s.get("rollback"):
            out.append("step %s without rollback" % s.get("id"))
        if s.get("movesTrustDigest") is not False:
            out.append("step %s moves a trust digest" % s.get("id"))
    rules = li.get("rules") or {}
    if rules.get("newPolicyNeedsNewProbeEvidence") is not True:
        out.append("rules: a new policy without new probe evidence")
    if rules.get("noManifestBeforeItsPreflight") is not True:
        out.append("rules: a manifest signed before its preflight")
    if rules.get("noManifestByTheOtherLaunchersKey") is not True:
        out.append("rules: a manifest signed by the other launcher's key")
    after = str(rules.get("afterRevocationEtcPlaneonChangesOnlyThrough"))
    if "SIGNED_DROP_INSTALLER" not in after or "VERIFIED_DROP_MANIFEST" not in after:
        out.append("rules: a change under /etc/planeon after the revocation not through the signed-drop installer")
    tl = li.get("timeLimits") or {}
    if tl.get("policyMaxHours") != 24 or tl.get("policyFrom") != "T1":
        out.append("timeLimits: the policy at most 24 hours from T1")
    if tl.get("t2EndsWithinHoursOfPreflight") != 1 or tl.get("manifestsSignedWithinHoursOfPreflight") != 1:
        out.append("timeLimits: T2 ending more than one hour after the preflight")
    off = li.get("offlineLauncher") or {}
    if off.get("path") != "/opt/planeon/bin/harness-offline-launch" or off.get("mode") != "OPERATOR_PREFLIGHT_ONLY" \
            or off.get("evidence") != "HOST_ISOLATION_ONLY" or off.get("githubRunnerRegistered") is not False \
            or off.get("ciCapacityExceptionApplies") is not False:
        out.append("offlineLauncher: --operator-preflight only, no runner, CI_CAPACITY_EXCEPTION.md does not apply")
    if off.get("publicKey") != "/etc/planeon/harness-runner-manifest.pub" \
            or off.get("policySigner") != "LINUX_RUNNER_MANIFEST" or off.get("manifestSigner") != "LINUX_RUNNER_MANIFEST":
        out.append("offlineLauncher: a manifest or policy signed by another key than the new Linux runner key")
    if off.get("custody") != "/etc/planeon/linux-runner/custody.json" or off.get("custodyWrittenAtStep") != 10 \
            or _has_all(off.get("custodyBinds"), ["PUBLIC_KEY", "LAUNCHER", "POLICY"]):
        out.append("offlineLauncher: custody.json binds the public key, the launcher and policy digests, at step 10")
    if "T2" not in str(off.get("manifestSignedAt")) or "PREFLIGHT" not in str(off.get("manifestSignedAt")):
        out.append("offlineLauncher: the manifest signed in T2 after the preflight")
    if _has_all(off.get("operatorMdApplies"), ["LAYOUT", "SENTINEL"]) or \
            _has_all(off.get("operatorMdDoesNotApply"), ["RUNNER_SETTINGS", "RUNNER_BINARY"]):
        out.append("offlineLauncher: what applies from OPERATOR.md")
    if off.get("rollback") != "TEARDOWN":
        out.append("offlineLauncher: rollback means teardown")
    scope = off.get("preflightProbeScope") or []
    if _has_all(scope, ["GUEST_AGENT", "OS_LOGIN", "METADATA_ADDRESS", "KUBECONFIG", "F1"]):
        out.append("offlineLauncher: an agent socket or the metadata address outside the preflight probe scope")
    live = li.get("liveLauncher") or {}
    if live.get("path") != "/opt/planeon/bin/harness-live-campaign-launch" or live.get("designOnly") is not True \
            or live.get("owner") != "ROOT" or live.get("mode") != "0555":
        out.append("liveLauncher: design only, root-owned 0555")
    if (live.get("manifest"), live.get("signature"), live.get("publicKey")) != (
            "/etc/planeon/harness-live-runner-manifest.json", "/etc/planeon/harness-live-runner-manifest.json.sig",
            "/etc/planeon/harness-live-runner-manifest.pub"):
        out.append("liveLauncher: TRUSTED_LIVE lines 34-38 paths")
    if live.get("manifestSigner") != "LIVE_RUNNER_MANIFEST":
        out.append("liveLauncher: a manifest signed by the other launcher's key")
    if "CONF_LIVE_005_006" not in str(live.get("manifestSignedAfter")) or \
            "PREFLIGHT" not in str(live.get("manifestSignedAfter")):
        out.append("liveLauncher: a live manifest signed before CONF-LIVE-005/006's own preflight")
    mounts = {m.get("path"): m for m in live.get("trustMounts") or []}
    if set(mounts) != {"/etc/planeon/trust/release-trust-bundle.json", "/etc/planeon/trust/tenant-trust-bundle.json"}:
        out.append("liveLauncher: the trust bundle mounts")
    for m in mounts.values():
        if m.get("readOnly") is not True or m.get("mode") not in ("0444", "0440", "0400") or m.get("owner") != "ROOT" \
                or m.get("installedAtStep") != 10:
            out.append("liveLauncher: a writable trust mount or a wrong mode")
    inst = li.get("signedDropInstaller") or {}
    if _has_all(inst.get("installsOnlyIf"), ["VERIFIES", "EXACT_TARGET_AND_SHA256", "FIXED_LIST"]):
        out.append("signedDropInstaller: a drop accepted without a verified drop manifest, an unlisted file or target")
    if inst.get("refusesEverythingElse") is not True or not str(inst.get("logsEveryAttempt", "")).startswith("/"):
        out.append("signedDropInstaller: refuses everything else and logs every attempt")
    for t in inst.get("fixedTargets") or []:
        path = str(t.get("path"))
        if not path.startswith("/etc/planeon/") or ".." in path.split("/") or t.get("owner") != "ROOT" \
                or t.get("mode") not in ("0444", "0440", "0400"):
            out.append("signedDropInstaller: an unlisted target or a wrong mode (%s)" % path)
    ids = " ".join(str(t.get("id")) for t in inst.get("fixedTargets") or [])
    if _has_all([ids], ["CAMPAIGN_PROXY_SERVER_TLS", "CAMPAIGN_PROXY_CLIENT_MTLS", "OFFLINE_MANIFEST", "LIVE_MANIFEST"]):
        out.append("signedDropInstaller: the fixed list")
    for t in inst.get("fixedTargets") or []:
        if "LIVE_MANIFEST" in str(t.get("id")) and "CONF_LIVE_005_006" not in str(t.get("state")):
            out.append("signedDropInstaller: the live manifest before CONF-LIVE-005/006 close")
    for u in li.get("triggerUnits") or []:
        if u.get("operatorArguments") is not False:
            out.append("triggerUnits: %s takes operator arguments" % u.get("id"))
    return out


AUTHORITIES = ["LINUX_RUNNER_MANIFEST", "LIVE_RUNNER_MANIFEST", "PLATFORM_RELEASE", "TENANT_LIVE_EXECUTION",
               "CAPACITY_OPERATOR"]


def custody_findings(c) -> list:
    """Section 7 (`custody-model.json`) and its section 8 refusals, as this oracle's own checks."""
    out = []
    auth = {a.get("id"): a for a in c.get("authorities") or []}
    if sorted(auth) != sorted(AUTHORITIES):
        out.append("authorities: a missing authority")
    for field in ("keyId", "purpose", "token", "sealedBackup"):
        values = [a.get(field) for a in auth.values()]
        if len(set(values)) != len(values) or None in values:
            out.append("authorities: two authorities sharing one %s" % field)
    for name, a in auth.items():
        if a.get("algorithm") != "ED25519" or "OFFLINE" not in str(a.get("generation")) \
                or "NEVER_CONNECTS" not in str(a.get("generation")) or "TOKEN" not in str(a.get("storage")) \
                or "SEALED" not in str(a.get("storage")) or "PER_RELEASE" not in str(a.get("rotation")) \
                or a.get("importCheckedAtCeremony") is not True:
            out.append("authorities: %s generation, token, sealed backup, rotation or import check" % name)
        if not LABEL.fullmatch(str(a.get("holder"))):
            out.append("authorities: %s holder written as a name" % name)
        cer = a.get("ceremony") or {}
        if cer.get("privateBytes") is not False or _has_all(cer.get("records"), ["PUBLIC_KEY_DIGEST", "PURPOSE"]):
            out.append("authorities: %s ceremony records public-key digests and purposes only" % name)
    halves = {"LINUX_RUNNER_MANIFEST": "/etc/planeon/harness-runner-manifest.pub",
              "LIVE_RUNNER_MANIFEST": "/etc/planeon/harness-live-runner-manifest.pub"}
    for name, half in halves.items():
        if (auth.get(name) or {}).get("publicHalf") != half:
            out.append("authorities: %s public half" % name)
    for name, bundle in (("PLATFORM_RELEASE", "RELEASE_TRUST_BUNDLE"), ("TENANT_LIVE_EXECUTION", "TENANT_TRUST_BUNDLE"),
                         ("CAPACITY_OPERATOR", "TENANT_TRUST_BUNDLE")):
        if bundle not in str((auth.get(name) or {}).get("publicHalf")):
            out.append("authorities: %s public half" % name)
    if _has_all((auth.get("LINUX_RUNNER_MANIFEST") or {}).get("signs"), ["POLICY", "OFFLINE_MANIFEST", "DROP_MANIFEST"]):
        out.append("authorities: LINUX_RUNNER_MANIFEST signs the policy, the offline manifest and the drop manifest")
    sessions = {s.get("id"): s for s in c.get("tokenSessions") or []}
    t1, t2 = sessions.get("T1") or {}, sessions.get("T2") or {}
    if t1.get("runbookStep") != 10 or t1.get("offHost") is not True:
        out.append("tokenSessions: T1 off host at step 10")
    if t2.get("runbookStep") != 12 or t2.get("offHost") is not True or t2.get("withinOneHourOfPreflight") is not True \
            or t2.get("everyTokenPresent") is not True:
        out.append("tokenSessions: T2 off host within one hour of the preflight, every token present")
    order = [str(x) for x in t2.get("order") or []]
    marks = ["LOCAL_CA", "CAPACITY_AUTHORIZATION", "ENVELOPE", "OFFLINE_MANIFEST", "DROP_MANIFEST"]
    positions = [next((i for i, x in enumerate(order) if mark in x), -1) for mark in marks]
    if -1 in positions or positions != sorted(positions):
        out.append("tokenSessions: T2's order")
    bundles = c.get("bundles") or {}
    if (bundles.get("release") or {}).get("authoredUnder") != "PLATFORM_RELEASE" or \
            (bundles.get("tenant") or {}).get("authoredUnder") != "TENANT_LIVE_EXECUTION" or \
            bundles.get("digestsInTheSignedEnvelope") is not True or bundles.get("refreshedIn") != "T1" or \
            bundles.get("installedAtStep") != 10 or bundles.get("beforeTheRevocation") is not True:
        out.append("bundles: authorship, envelope digests, refreshed in T1, installed at step 10")
    if bundles.get("networkLookup") is not False or "LOCAL_CUSTODY_TRANSFER" not in str(bundles.get("route")):
        out.append("bundles: a revocation route over the network")
    creds = {x.get("id"): x for x in c.get("perRunCredentials") or []}
    if sorted(creds) != ["CAMPAIGN_PROXY_CLIENT_MTLS", "CAMPAIGN_PROXY_SERVER_TLS", "KUBERNETES_PROXY_SERVER_MTLS"]:
        out.append("perRunCredentials: a missing per-run credential")
    for name, x in creds.items():
        if not x.get("issuer"):
            out.append("perRunCredentials: %s without its issuer" % name)
        if x.get("madeOn") != "PROXY_OPERATOR_HOST" or x.get("fromRequestAtStep") != 8:
            out.append("perRunCredentials: %s made off its named host" % name)
        if x.get("privateHalfOwner") != "ROOT" or x.get("privateHalfMode") != "0400":
            out.append("perRunCredentials: %s private half root-owned 0400" % name)
        if x.get("reusedAcrossRuns") is not False:
            out.append("perRunCredentials: %s reused across runs" % name)
        if "INSTANCE_AND_DISK_DELETION" not in str(x.get("ends")):
            out.append("perRunCredentials: %s not destroyed at teardown" % name)
        if x.get("inCredentialIdentities") is not True:
            out.append("perRunCredentials: %s not in credentialIdentities" % name)
    nonce = c.get("nonce") or {}
    reg = nonce.get("signingRegistry") or {}
    if reg.get("custody") != "OWNER" or reg.get("location") != "OUTSIDE_GCP":
        out.append("nonce: a signing registry inside the run project")
    if reg.get("neverSignsSameNonceTwice") is not True or \
            _has_all(reg.get("covers"), ["ENVELOPE_NONCE", "CAPACITY_AUTHORIZATION_NONCE"]):
        out.append("nonce: a reused envelope or capacity nonce")
    ledger = nonce.get("hostLedger") or {}
    if ledger.get("exportedAtStep") != 15 or ledger.get("retained") is not True:
        out.append("nonce: a host ledger not exported")
    if ledger.get("host") != "PROXY_OPERATOR_HOST" or ledger.get("owner") != "ROOT" or ledger.get("durable") is not True \
            or _has_all(ledger.get("reservations"), ["LAUNCHER", "PROXY_CLIENT", "PROXY_SERVER"]):
        out.append("nonce: the host ledger's holder and reservations")
    replay = c.get("crossHostReplay") or {}
    if _has_all(replay.get("envelopeBinds"), ["ENDPOINT_ADDRESS", "SERVER_SPKI_FRESH_PER_RUN", "VALIDITY_WINDOW"]) \
            or replay.get("serverKeyReused") is not False:
        out.append("crossHostReplay: an envelope whose server SPKI is not the run's fresh key")
    clock = c.get("trustedClock") or {}
    if clock.get("host") != "CHRONY" or _has_all(clock.get("capturedAtPreflight"), ["CLOCK_SOURCE", "OFFSET"]):
        out.append("trustedClock")
    rev = c.get("revocation") or {}
    if rev.get("network") is not False or rev.get("in") != "T1" or rev.get("installedAtStep") != 10:
        out.append("revocation: a revocation route over the network")
    store = c.get("evidenceStore") or {}
    if store.get("custody") != "OWNER" or store.get("inRunProjectBeyondPlan") is not False \
            or store.get("fromRunbookStep") != 15:
        out.append("evidenceStore: an evidence store that outlives teardown in the run project")
    ind = c.get("independence") or {}
    if ind.get("disclosure") != DISCLOSURE or ind.get("keysDistinct") is not True or ind.get("heldApart") is not True \
            or ind.get("independentPeople") is not False:
        out.append("independence: the disclosure and its facts")
    carriers = " ".join(json.dumps(x) for x in ind.get("carriers") or [])
    if _has_all([carriers], ["CONF-LINUX-002", "CONF-LIVE-006"]):
        out.append("independence: the two evidence carriers")
    pr = c.get("principal") or {}
    if pr.get("disclosure") != DISCLOSURE or _sha(pr.get("ownerAnswer")) != DECISION_PINS["Q-LHA-1"] \
            or pr.get("count") != 1:
        out.append("principal: the disclosure with the owner's answer verbatim")
    k = c.get("kubernetes") or {}
    local = (c.get("localCa") or {}).get("id")
    if local is None or local in (k.get("apiServerClientTrust") or []):
        out.append("kubernetes: a client trust that holds the local CA")
    for name, x in creds.items():
        if x.get("issuer") == local and x.get("grantsKubernetesAccess") is not False:
            out.append("kubernetes: a local-CA leaf that authenticates to the API server (%s)" % name)
    return out


# ------------------------------------------------------------------------------------------------------- the module

def _cli(*args):
    return subprocess.run([sys.executable, "-I", "-B", "scripts/linux_host_authority.py", *args], cwd=str(ROOT),
                          capture_output=True, text=True, timeout=100)


def _set(doc, path, value):
    target = doc
    for key in path[:-1]:
        target = target[key]
    target[path[-1]] = value
    return doc


def _then(doc, *_effects):
    """Returns the document after the side effects passed as arguments (already evaluated)."""
    return doc


def _find_index(items, key, value):
    for index, item in enumerate(items):
        if isinstance(item, dict) and item.get(key) == value:
            return index
    raise KeyError(value)


class ORACLE_TESTS(unittest.TestCase):
    maxDiff = None

    def assertNone(self, findings, what=""):
        self.assertEqual(findings, [], what)

    # --- item 7: the parse rules LAB-RUNPLAN-001 states (section 3), on the records and schemas as published

    def test_01_parse_rules_on_the_published_records_and_schemas(self):
        for kind, name in RECORDS.items():
            data = contract_bytes(name)
            self.assertFalse(data.startswith(b"\xef\xbb\xbf"), name + ": byte-order mark")
            strict(data)  # duplicate keys, non-finite, every number an integer within range, lone surrogates
            self.assertEqual(record(kind).get("schemaVersion"), SCHEMA_IDS[kind], name)
        for kind, name in SCHEMAS.items():
            strict(contract_bytes(name), integers_only=False)

    def test_02_parse_probe_refuses_what_the_rules_refuse(self):
        # this oracle's own probe, checked on hand-made bytes (duplicate key, byte-order mark, non-integral numbers)
        for raw in (b'{"a": 1, "a": 2}', b"\xef\xbb\xbf{}", b'{"a": 1.5}', b'{"a": 1.0}', b'{"a": NaN}',
                    b'{"a": 10000000000000}', b'{"a": "\\ud800"}', b'{"a": 1e3}'):
            with self.assertRaises(ValueError, msg=raw):
                strict(raw)
        self.assertEqual(strict(b'{"a": [1, "b", true, null]}'), {"a": [1, "b", True, None]})

    # --- item 5: the schemas (section 3; LAB-RUNPLAN-001's closed subset)

    def test_03_schemas_declare_draft_2020_12_and_are_closed(self):
        for kind, name in SCHEMAS.items():
            node = schema(kind)
            self.assertEqual(node.get("$schema"), DRAFT_2020_12, name)
            jsonschema.Draft202012Validator.check_schema(node)
            self.assertNone(closed_schema_findings(node), name)
            if kind in SCHEMA_IDS:
                self.assertEqual(node.get("$id"), SCHEMA_IDS[kind], name)
                self.assertEqual(node["properties"]["schemaVersion"].get("const"), SCHEMA_IDS[kind], name)

    def test_04_each_record_validates_against_its_schema(self):
        for kind in RECORDS:
            self.assertNone(schema_findings(record(kind), kind), RECORDS[kind])

    # --- item 1: the digest rule (section 4, B-LHA-12)

    def test_05_digest_rule_recomputed_from_the_base_bytes(self):
        a = record("authority")
        for name in ("supersedes", "unchanged", "costScope", "reviewedNotBinding", "satisfied", "readings"):
            self.assertTrue(_group(a, name), "section 4 group %s" % name)
        self.assertNone(digest_findings(a))

    def test_06_member_paths_exist_in_full_form(self):
        # section 4 rules: every member path exists, in its full form
        self.assertNone(member_findings(record("authority")))

    # --- item 2: the authority record's closed parts (section 4)

    def test_07_capacity_exactly_as_the_design_writes_it(self):
        self.assertNone(capacity_findings(record("authority")))

    def test_08_evidence_unchanged(self):
        self.assertNone(evidence_findings(record("authority")))

    def test_09_relaxed_predicates_only_the_listed_ones(self):
        self.assertNone(relaxed_findings(record("authority")))

    def test_10_independence_clause_with_its_replacement_predicate(self):
        self.assertNone(replacement_findings(record("authority")))

    def test_11_unchanged_carries_every_kept_predicate(self):
        self.assertNone(kept_findings(record("authority")))

    def test_12_satisfied_by_the_replacement_predicate(self):
        self.assertNone(match_findings(_group(record("authority"), "satisfied"), SATISFIED, "satisfied", exact=True))

    def test_13_cost_scope_kept_at_campaign_server_reader_cluster_endpoint(self):
        a = record("authority")
        self.assertNone(match_findings(_group(a, "costScope"), COST_SCOPE, "costScope", exact=True))

    def test_14_reviewed_not_binding_with_the_reason(self):
        entries = _group(record("authority"), "reviewedNotBinding")
        self.assertNone(match_findings(entries, REVIEWED, "reviewedNotBinding", exact=True))
        for entry in entries:
            self.assertIn(REVIEW_REASON, render(entry.get("note", "")).lower(), entry.get("id"))

    def test_15_readings_list_the_designed_occurrences(self):
        self.assertNone(reading_findings(record("authority")))

    def test_16_readings_cover_every_occurrence_in_superseded_kept_satisfied_texts(self):
        self.assertNone(reading_coverage_findings(record("authority")))

    def test_17_decisions_verbatim(self):
        self.assertNone(decision_findings(record("authority")))

    def test_18_consumers_preconditions_and_carried_notes(self):
        a, c = record("authority"), record("custody")
        consumers = a.get("consumers") or {}
        listed = {x.get("id"): x for x in consumers.get("list") or []}
        conf = listed.get("CONF-LINUX-001") or {}
        self.assertIn("EXTERNAL_ROOT_OWNED", str(conf.get("through")))
        self.assertIn("LIVE_LAUNCHER", str(conf.get("through")))
        self.assertIn("CONF_LIVE_005_006", str(conf.get("earliestFullRun")))
        qual = [x for k, x in listed.items() if "QUALIFICATION" in str(k)]
        self.assertEqual(len(qual), 1)
        self.assertIn("CONF_LIVE_006", str(qual[0].get("through")))
        self.assertIn("CONF_LIVE_001", str(qual[0].get("earliestFullRun")))
        self.assertTrue(all(x.get("readsThroughThePublishedDigest") is True for x in listed.values()))
        before = consumers.get("beforeLiveLauncher") or {}
        self.assertEqual(before.get("evidence"), "HOST_ISOLATION_ONLY")
        self.assertIn("PREFLIGHT_ONLY", str(before.get("mode")))
        self.assertEqual(_r(before.get("quote") or {}), "This is not a product image build, live runtime test or full "
                                                        "native release qualification")
        pre = " ".join(json.dumps(x) for x in a.get("preconditions") or [])
        for words in (["MET-LINUX-009"], ["CONF-LINUX-002"], ["CONF-LIVE-006", "adapter"], ["MET-REPAIR-015"],
                      ["kernel"], ["without admin"]):
            self.assertTrue(all(w in pre for w in words), "section 10 precondition %s" % words)
        self.assertNotIn("MET-LINUX-010", pre)  # withdrawn (revision 6)
        notes = {n.get("id"): n for n in a.get("carriedNotes") or []}
        self.assertEqual(_sha(notes.get("LHA-CN-1", {}).get("note")), CARRIED_NOTE_PINS["LHA-CN-1"])
        notes = {n.get("id"): n for n in c.get("carriedNotes") or []}
        self.assertEqual(_sha(notes.get("LHA-CN-2", {}).get("note")), CARRIED_NOTE_PINS["LHA-CN-2"])

    # --- item 3: role labels only (B-LHA-13); the string rule (section 8)

    def test_19_no_identity_account_posix_name_uid_role_name_key_or_price(self):
        for kind, name in RECORDS.items():
            self.assertNone(identity_findings(record(kind)), name)
            self.assertNone(string_rule_findings(record(kind)), name)
        for kind, name in SCHEMAS.items():
            self.assertNone(identity_findings(schema(kind)), name)
            self.assertNone(string_rule_findings(schema(kind)), name)
        self.assertNone(identity_findings(readme()), "README.md")

    # --- item 4: the build rules in checkFirst order: B-LHA-1, B-LHA-2, B-LHA-13 to B-LHA-18, then B-LHA-4 to B-LHA-12

    def test_20_b_lha_01_trigger_units_operator_uid_read_paths(self):
        li, r, a, c = record("launcher"), record("recipe"), record("authority"), record("custody")
        units = li.get("triggerUnits") or []
        pre = [u for u in units if "PREFLIGHT" in str(u.get("id"))]
        exp = [u for u in units if "EXPORT" in str(u.get("id"))]
        self.assertEqual((len(pre), len(exp)), (1, 1), "one unit for the preflight and one for the export")
        for u in units:
            self.assertIs(u.get("operatorArguments"), False, u.get("id"))
            self.assertEqual(u.get("installedAtStep"), 8, u.get("id"))
            self.assertIs(u.get("inHostInventory"), True, u.get("id"))
            self.assertTrue(isinstance(u.get("command"), str) and u["command"].startswith("/"), u.get("id"))
            self.assertFalse(re.search(r"[$%{}<>]", u["command"]), "one fixed command")
        self.assertEqual(pre[0]["command"], "/opt/planeon/bin/harness-offline-launch --operator-preflight")
        uid = li.get("operatorUid") or {}
        self.assertTrue(LABEL.fullmatch(str(uid.get("label"))), "operatorUid by role label")
        self.assertIs(uid.get("nameAndUidPublished"), False)
        self.assertEqual(pre[0].get("runsAs"), uid.get("label"))
        actions = " ".join(json.dumps(x) for x in li.get("privilegedActions") or [])
        for step in ("STEP_11", "STEP_13", "STEP_14", "STEP_15"):
            self.assertIn(step, actions)
        for x in li.get("privilegedActions") or []:
            self.assertTrue(x.get("runsAs") and x.get("startedBy"), x)
            self.assertIs(x.get("loginNeedsAdmin"), False, x)
        pre_conditions = " ".join(json.dumps(x) for x in a.get("preconditions") or [])
        self.assertIn("without admin", pre_conditions)  # the live launcher's entry path, a precondition on 005/006
        self.assertEqual(li["liveLauncher"].get("nonAdminEntryPath"), "PRECONDITION_ON_CONF_LIVE_005_006")
        export = {x.get("host"): x.get("records") or [] for x in li.get("exportSet") or []}
        self.assertNone(_has_all(export.get("PROXY_OPERATOR_HOST"),
                                 ["HOST_NONCE_LEDGER", "PREFLIGHT_RECORDS", "HOST_INVENTORY", "JOURNAL"]))
        self.assertNone(_has_all(export.get("CLUSTER_NODE"), ["HOST_INVENTORY", "JOURNAL"]))
        td = r.get("teardown") or {}
        self.assertIn("INSTANCE_AND_DISK_DELETION", str(td.get("privateHalvesEndWith")))
        self.assertIn("ZERO_COUNTS", str(td.get("check")))
        for x in c.get("perRunCredentials") or []:
            self.assertIn("INSTANCE_AND_DISK_DELETION", str(x.get("ends")), x.get("id"))

    def test_21_b_lha_02_cluster_ca_issues_the_kubernetes_client_credential(self):
        c, r = record("custody"), record("recipe")
        local, cluster, k = c.get("localCa") or {}, c.get("clusterCa") or {}, c.get("kubernetes") or {}
        self.assertNotIn(local.get("id"), k.get("apiServerClientTrust") or [])
        self.assertIn(cluster.get("id"), k.get("apiServerClientTrust") or [])
        self.assertIs(local.get("neverInTheApiServerClientTrust"), True)
        self.assertEqual((cluster.get("madeAtStep"), cluster.get("on"), cluster.get("issuesAtStep")), (7, "CLUSTER_NODE", 8))
        self.assertIs(cluster.get("withAdmin"), True)
        self.assertIs(cluster.get("newKeyOrToken"), False)
        self.assertIn("KUBERNETES_PROXY_SERVER_MTLS", cluster.get("issues") or [])
        self.assertNotIn("KUBERNETES_PROXY_SERVER_MTLS", local.get("issues") or [])
        creds = {x.get("id"): x for x in c.get("perRunCredentials") or []}
        self.assertEqual(creds["KUBERNETES_PROXY_SERVER_MTLS"].get("issuer"), cluster.get("id"))
        self.assertEqual(creds["KUBERNETES_PROXY_SERVER_MTLS"].get("fromRequestAtStep"), 8)
        self.assertIn("EXACT_SUBJECT", str(k.get("rbacSubject")))
        self.assertIn("KUBERNETES_PROXY_SERVER_MTLS", str(k.get("rbacSubject")))
        self.assertIs(k.get("privilegedGroups"), False)
        self.assertIs(k.get("proxyOperatorHostTrustsClusterCa"), True)
        self.assertTrue(str(cluster.get("trustedByTheProxyOperatorHostAt", "")).startswith("/etc/planeon/"))
        for name, x in creds.items():  # CREDENTIAL_ORDERING_REPAIR.md line 62: "purpose grants no Kubernetes access"
            if x.get("issuer") == local.get("id"):
                self.assertIs(x.get("grantsKubernetesAccess"), False, name)
        proxy = [h for h in r.get("hosts") or [] if h.get("role") == "PROXY_OPERATOR_HOST"][0]
        self.assertIs(proxy.get("holdsKubernetesClientCredential"), True)

    def test_22_b_lha_13_role_labels_only(self):
        r = record("recipe")
        labels = r.get("roleLabels") or {}
        self.assertEqual(labels.get("administeringIdentity"), "OWNER_ADMIN")
        self.assertEqual(labels.get("loginIdentity"), "OWNER_LOGIN")
        self.assertEqual(labels.get("loginBaselineRole"), "OWNER_LOGIN_BASELINE")
        for kind in RECORDS:
            doc = record(kind)
            for where, text in strings(doc, keys=False):
                field = where.split(".")[-2] if "." in where else where
                if field.split("[")[0] in ("holder", "grantee", "grantedBy", "revokedBy", "runBy", "by", "createdBy",
                                           "boundBy", "identity", "label", "neverRunBy", "runsAs"):
                    self.assertTrue(LABEL.fullmatch(text), "%s %s: %r is not a role label" % (kind, where, text))
            self.assertNone(identity_findings(doc), kind)

    def test_23_b_lha_14_folder_and_organization_reach_and_the_accepted_limit(self):
        acc = record("recipe").get("access") or {}
        for c in acc.get("effectiveChecks") or []:
            if c.get("identity") == "OWNER_LOGIN":
                self.assertNone(_has_all(c.get("absent"), ["resourcemanager.folders.setIamPolicy",
                                                           "resourcemanager.organizations.setIamPolicy",
                                                           "iam.roles.create", "iam.roles.update"]), c.get("step"))
                self.assertNone(_has_all(c.get("resources"), ["FOLDER", "ORGANIZATION"]), c.get("step"))
                self.assertIn("REFUSE", str(c.get("onFinding")))
        self.assertEqual(sorted(c.get("step") for c in acc.get("effectiveChecks") or []
                                if c.get("identity") == "OWNER_LOGIN"), [1, 10, 15])
        limit = acc.get("acceptedLimit") or {}
        self.assertEqual(limit.get("words"), "detected by the effective check, not blocked")  # Q-LHA5-1, the owner
        self.assertNone(_has_all(limit.get("grantKinds"), ["GROUP", "DOMAIN", "PRINCIPAL_SET", "FOLDER", "ORGANIZATION"]))
        self.assertNone(_has_all(limit.get("detectedOnlyBy"), ["STEP_10", "STEP_15"]))
        self.assertNone(_has_all(limit.get("notDetected"), ["BETWEEN_STEPS_10_AND_15", "AFTER_STEP_15"]))
        self.assertIs(limit.get("auditLogDetectsThem"), False)

    def test_24_b_lha_15_ssh_only_made_binding(self):
        r = record("recipe")
        acc = r.get("access") or {}
        base = acc.get("loginBaseline") or {}
        self.assertNone(_login_absent_findings(base.get("excludes"), "baseline"))
        self.assertIn("SSH", str(base.get("permittedPurpose")))
        self.assertIn("ONLY", str(base.get("permittedPurpose")))
        for c in acc.get("effectiveChecks") or []:
            if c.get("identity") == "OWNER_LOGIN":
                self.assertNone(_login_absent_findings(c.get("absent"), "step %s" % c.get("step")))
                self.assertNone(_has_all(c.get("resources"), ["RUN_PROJECT", "SERVICE_ACCOUNT"]))
                self.assertIn("CONDITIONAL", c.get("grantPaths") or [])
                if c.get("step") == 1:
                    self.assertIs(c.get("conditionalBindingIsGrant"), True)
        steps = {s.get("step"): s for s in r.get("runbook") or []}
        for step in (2, 3, 5, 6, 16):
            self.assertEqual(steps[step].get("cloudActionsBy"), "OWNER_ADMIN", step)
        self.assertFalse([s for s in steps.values() if s.get("cloudActionsBy") == "OWNER_LOGIN"])

    def test_25_b_lha_16_the_exact_audit_expectation(self):
        audit = (record("recipe").get("access") or {}).get("auditLogCheck") or {}
        self.assertEqual(audit.get("log"), "ADMIN_ACTIVITY")
        self.assertIn("STEP_10", str(audit.get("from")))
        self.assertIn("REVOCATION", str(audit.get("from")))
        self.assertIn("TEARDOWN", str(audit.get("to")))
        lists = " ".join(audit.get("lists") or [])
        for word in ("IAM_POLICY_CHANGE_RUN_PROJECT", "IAM_POLICY_CHANGE_INSTANCE", "CUSTOM_ROLE_CREATE",
                     "CUSTOM_ROLE_UPDATE", "CUSTOM_ROLE_DELETE", "CUSTOM_ROLE_UNDELETE"):
            self.assertIn(word, lists)
        expected = audit.get("expected") or []
        self.assertEqual(len(expected), 3)
        self.assertTrue(all(x.get("by") == "OWNER_ADMIN" for x in expected))
        self.assertNone(_has_all([x.get("entry") for x in expected], ["STEP_10", "NON_ADMIN_LOGIN_GRANT", "TEARDOWN"]))
        self.assertIn("WHATEVER_ITS_PRINCIPAL", str(audit.get("anyOtherEntry")))
        self.assertIn("REFUSE", str(audit.get("anyOtherEntry")))
        self.assertIn("REFUSE", str(audit.get("anyCustomRoleChange")))
        self.assertIs(audit.get("finalSpanCheckedAfterTeardownCompletes"), True)
        self.assertIs(audit.get("evidenceAcceptedOnlyAfterThisCheck"), True)

    def test_26_b_lha_17_who_runs_the_checks_and_the_step_1_wording(self):
        r = record("recipe")
        acc = r.get("access") or {}
        step1 = render([s for s in r.get("runbook") or [] if s.get("step") == 1][0].get("check"))
        self.assertIn("the real id in the owner-held plan, the role label in every published rendering", step1)
        self.assertIn("exact permission list recorded in the plan", step1)
        for c in acc.get("effectiveChecks") or []:
            if c.get("step") in (10, 15):
                self.assertNotIn("LOGIN", str(c.get("runBy")))
                self.assertIn("BEFORE", str(c.get("propagationWait")))
        self.assertNotIn("LOGIN", str((acc.get("auditLogCheck") or {}).get("runBy")))
        mech = acc.get("permissionMechanism") or {}
        self.assertEqual(mech.get("neverRunBy"), "OWNER_LOGIN")
        self.assertIs(mech.get("onPaper"), True)
        membership = mech.get("membership") or {}
        self.assertTrue(membership.get("groups") and membership.get("principalSets") and membership.get("domain"))
        self.assertEqual((acc.get("sessionChecks") or {}).get("after"), "IAM_PROPAGATION")
        self.assertIn("Q-LHA5-1 (owner) and MON-LHA-REV7", readme())

    def test_27_b_lha_18_no_login_for_the_administering_identity(self):
        acc = record("recipe").get("access") or {}
        admin = acc.get("adminBaseline") or {}
        self.assertEqual(admin.get("label"), "OWNER_ADMIN")
        self.assertNone(_has_all(admin.get("holdsNoLoginPermission"), ADMIN_ABSENT))
        self.assertTrue(any("iap" in x.lower() and "tunnel" in x.lower() for x in admin.get("holdsNoLoginPermission")))
        self.assertIn("ANCESTOR", str(admin.get("on")))
        self.assertIs(admin.get("countsAmongBaselineBindings"), True)
        steps = sorted(c.get("step") for c in acc.get("effectiveChecks") or [] if c.get("identity") == "OWNER_ADMIN")
        self.assertEqual(steps, [1, 10, 15])
        self.assertIn("OWNER_ADMIN_BINDING", (acc.get("betweenRuns") or {}).get("bindings") or [])
        self.assertIn("OWNER_ADMIN", (acc.get("sessionChecks") or {}).get("identities") or [])
        self.assertNone([f for f in access_findings(acc, record("recipe")) if "OWNER_ADMIN holds" in f])

    def test_28_b_lha_04_the_drop_manifest(self):
        li, c = record("launcher"), record("custody")
        inst = li.get("signedDropInstaller") or {}
        dm = inst.get("dropManifest") or {}
        drop_schema = schema("drop")
        self.assertEqual(dm.get("schemaId"), drop_schema.get("$id"))
        self.assertEqual(drop_schema["properties"]["schemaVersion"].get("const"), dm.get("schemaId"))
        self.assertNotIn(dm.get("schemaId"), (RUNNER_MANIFEST_SCHEMA_ID, POLICY_SCHEMA_ID))
        payload = str(dm.get("signaturePayload"))
        self.assertTrue(payload.index("SCHEMA_ID") < payload.index("0x00") < payload.index("EXACT_BYTES"), payload)
        self.assertIn("POLICY", str(dm.get("formedAs")))
        self.assertNone(_has_all(dm.get("refuses"), [RUNNER_MANIFEST_SCHEMA_ID, POLICY_SCHEMA_ID]))
        self.assertEqual(dm.get("authorizes"), "PLACEMENT_ONLY")
        self.assertNone(_has_all(dm.get("binds"), ["PLAN_SHA256", "INSTANCE", "BOOT_ID", "VALIDITY_WINDOW", "LEASE"]))
        required = " ".join(drop_schema.get("required") or []).lower()
        self.assertNone(_has_all([required], ["plan", "instance", "boot", "valid", "lease"]))
        auth = {x.get("id"): x for x in c.get("authorities") or []}
        self.assertNone(_has_all(auth["LINUX_RUNNER_MANIFEST"].get("signs"), ["POLICY", "OFFLINE_MANIFEST",
                                                                              "DROP_MANIFEST"]))
        cdm = c.get("dropManifest") or {}
        self.assertEqual((cdm.get("signer"), cdm.get("authorizes"), cdm.get("liveManifestStillVerifiedUnder")),
                         ("LINUX_RUNNER_MANIFEST", "PLACEMENT_ONLY", "LIVE_RUNNER_MANIFEST"))
        handling = " ".join(inst.get("fileHandling") or [])
        for word in ("REGULAR_FILES_ONLY", "NO_FOLLOW", "NO_HARDLINKS", "STAGING", "SHA256_OVER_THE_STAGED_COPY",
                     "ATOMIC_RENAME", "OWNER_AND_MODE_FROM_THE_FIXED_LIST"):
            self.assertIn(word, handling)
        drop_dir = inst.get("dropDirectory") or {}
        self.assertIs(drop_dir.get("otherwiseRefused"), True)
        self.assertIn("ROOT_OWNED", str(drop_dir.get("parentChain")))
        self.assertIn("NOT_GROUP_OR_WORLD_WRITABLE", str(drop_dir.get("parentChain")))
        self.assertEqual((inst.get("stagingDirectory") or {}).get("owner"), "ROOT")
        self.assertIn("ED25519", str(inst.get("verifier")))
        self.assertIs(inst.get("newCryptography"), False)
        self.assertIs(inst.get("certificateChainMode"), False)
        self.assertEqual(inst.get("publicKey"), "/etc/planeon/harness-runner-manifest.pub")
        self.assertEqual(inst.get("signer"), "LINUX_RUNNER_MANIFEST")
        self.assertIs(inst.get("inHostInventory"), True)
        self.assertEqual(inst.get("installedAtStep"), 8)

    def test_29_b_lha_05_root_writes_after_the_revocation(self):
        r, li, c = record("recipe"), record("launcher"), record("custody")
        categories = {"LEDGER": 0, "PREFLIGHT": 0, "INSTALLER_LOG": 0, "EVIDENCE": 0, "JOURNAL": 0, "CLUSTER": 0}
        for w in r.get("runtimeRootWrites") or []:
            hits = [k for k in categories if k in str(w.get("id"))]
            self.assertEqual(len(hits), 1, "one listed kind per runtime write: %s" % w.get("id"))
            categories[hits[0]] += 1
            self.assertTrue(isinstance(w.get("writer"), str) and w["writer"], "its one writer: %s" % w.get("id"))
        self.assertTrue(all(categories.values()), categories)
        inst = li.get("signedDropInstaller") or {}
        logs = [w for w in r["runtimeRootWrites"] if "INSTALLER_LOG" in w.get("id")]
        self.assertEqual(logs[0].get("path"), inst.get("logsEveryAttempt"))
        targets = {t.get("id"): t for t in inst.get("fixedTargets") or []}
        paths = {t.get("path") for t in targets.values()}
        self.assertIn(OFFLINE_MANIFEST_PATH, paths)
        self.assertIn(OFFLINE_MANIFEST_SIG_PATH, paths)
        for x in c.get("perRunCredentials") or []:
            if "DROP" in str(x.get("certificateArrives")):
                self.assertIn(x.get("certificate"), paths, x.get("id"))
        rules = li.get("rules") or {}
        self.assertEqual(rules.get("loginStartedWritesAfterRevocation"), "SIGNED_DROP_INSTALLER_ONLY")
        self.assertEqual(rules.get("preflightRecord"), "RETAINED_AND_EXPORTED_ONLY")

    def test_30_b_lha_06_the_proxy_route_to_the_workloads(self):
        r = record("recipe")
        flows = {f.get("id"): f for f in r.get("internalFlows") or []}
        self.assertTrue(any("CAMPAIGN_PROXY" in p for p in flows["F1"].get("purposes") or []))
        up = r.get("campaignProxyUpstream") or {}
        self.assertEqual(up.get("flow"), "F1")
        self.assertEqual(up.get("targets"), ["KUBERNETES_API_SERVER"])
        self.assertNone(_has_all(up.get("via"), ["SERVICE_PROXY", "PORT_FORWARD"]))
        self.assertNone(_has_all(up.get("refusedTargets"), ["NODE_PORT", "SERVICE_ADDRESS", "POD_ADDRESS"]))
        trust = r.get("localRegistryTrust") or {}
        self.assertTrue(str(trust.get("file", "")).startswith("/etc/planeon/"))
        self.assertIn(trust.get("installedAtStep"), (7, 8))
        self.assertIs(trust.get("beforeRevocation"), True)

    def test_31_b_lha_07_endpoint_server_identities(self):
        c, li = record("custody"), record("launcher")
        esi = c.get("endpointServerIdentities") or []
        # TRUSTED_LIVE lines 238-239: the endpoint kinds are exactly these four
        self.assertEqual(sorted(e.get("kind") for e in esi),
                         sorted(["KUBERNETES_API_PROXY", "CAMPAIGN_PROXY", "LOCAL_REGISTRY", "LOCAL_EVIDENCE_SINK"]))
        creds = {x.get("id"): x for x in c.get("perRunCredentials") or []}
        drop_ids = {t.get("identity") for t in (li.get("signedDropInstaller") or {}).get("fixedTargets") or []}
        t2 = " ".join(str(x) for s in c.get("tokenSessions") or [] if s.get("id") == "T2" for x in s.get("order") or [])
        for e in esi:
            for field in ("owner", "issuer", "host", "privateHalfCustody", "lifetime"):
                self.assertTrue(e.get(field), "%s %s" % (e.get("kind"), field))
            if e.get("perRun"):
                x = creds.get(e.get("identity")) or {}
                self.assertEqual(x.get("fromRequestAtStep"), 8, e.get("identity"))
                self.assertEqual(x.get("issuedAt"), "T2", e.get("identity"))
                self.assertIs(x.get("inCredentialIdentities"), True, e.get("identity"))
                self.assertIn(e.get("identity"), drop_ids)
                self.assertIn(e.get("identity"), t2)
        proxies = [e for e in esi if e.get("kind") in ("KUBERNETES_API_PROXY", "CAMPAIGN_PROXY")]
        if len({e.get("identity") for e in proxies}) == 1:
            self.assertTrue(all(e.get("servesBothProxyKinds") is True for e in proxies))

    def test_32_b_lha_08_the_built_root(self):
        img = record("recipe").get("image") or {}
        ci = img.get("customImage") or {}
        self.assertIn("PINNED_FAMILY_IMAGE", str(ci.get("startsFrom")))
        self.assertIn("INVENTORY", str(ci.get("verifiedAgainst")))
        self.assertIn("BEFORE_ANY_INSTALL", str(ci.get("verifiedAgainst")))
        self.assertIn("LISTED_PACKAGES", str(ci.get("plus")))
        self.assertIn("OWN_POLICY_FILE_CONTEXTS", str(ci.get("selinuxLabels")))
        self.assertIn("STEP_4", str(ci.get("selinuxLabels")))
        self.assertIs(ci.get("firstBootRelabel"), False)
        self.assertIn("selinuxLabel", (img.get("imageDigest") or {}).get("inventoryFields") or [])
        self.assertIs(img.get("preflightComparesLabels"), True)
        kernel = img.get("kernel") or {}
        self.assertEqual(kernel.get("release"), "PINNED_IN_PLAN")
        self.assertEqual(kernel.get("checkedInBuiltRootAtStep"), 5)

    def test_33_b_lha_09_inventory_loose_ends(self):
        inv = record("recipe").get("hostInventory") or {}
        left = {x.get("what"): x.get("ownRecord") for x in inv.get("leftOut") or []}
        halves = [v for k, v in left.items() if "PRIVATE_HALVES" in str(k)]
        requests = [v for k, v in left.items() if "REQUEST" in str(k)]
        self.assertEqual(halves, ["SPKI_DIGEST_ONLY"])
        self.assertEqual(requests, ["SPKI_DIGEST_ONLY"])
        self.assertEqual(inv.get("bootEventLogsExportedAtStep"), 9)
        again = inv.get("imageReverification") or {}
        self.assertEqual(again.get("where"), "OFF_HOST_IN_T1")
        self.assertIn("UNCHANGED", str(again.get("compares")))
        self.assertIn("IMAGE_INVENTORY", str(again.get("compares")))

    def test_34_b_lha_10_admin_sessions(self):
        acc = record("recipe").get("access") or {}
        rev = acc.get("revocation") or {}
        self.assertIs(rev.get("thenWaitsForPropagation"), True)
        self.assertEqual(sorted(rev.get("endsAdminSessionsOn") or []), ["CLUSTER_NODE", "PROXY_OPERATOR_HOST"])
        sess = acc.get("sessionChecks") or {}
        self.assertEqual(sess.get("atStep"), 10)
        self.assertNone(_has_all(sess.get("confirms"), ["STARTED_BEFORE_REVOCATION", "SUDOERS", "CANNOT_USE_SUDO"]))
        self.assertIn("REFUSES", str(sess.get("preRevocationAdminSessionAliveAtPreflight")))

    def test_35_b_lha_11_three_citations(self):
        a, li = record("authority"), record("launcher")
        sa = signing_reading(a)
        lr147 = [o for o in _group(sa, "occurrences") if o.get("path") == LR]
        self.assertEqual([(o.get("text"), o.get("fragments")[0][0], o.get("fragments")[-1][2]) for o in lr147],
                         [("existing", 147, 147)])
        independent = [e for e in _group(a, "supersedes") if RELAXED[8][1](e)]
        self.assertEqual(independent[0].get("lines"), [146, 148])
        tl321 = [o for o in _group(pre_reading(a), "occurrences") if o.get("path") == TL and _first_line(o) == 321]
        self.assertEqual(len(tl321), 1)
        self.assertTrue(tl321[0].get("text") == "Pre-existing" or _lines_cover(tl321[0], 321, 322))
        limits = li.get("timeLimits") or {}
        self.assertEqual(limits.get("manifestsSignedWithinHoursOfPreflight"), 1)
        self.assertIn("NORMAL_INVOCATION", str(limits.get("operatorMdOneHourAge")))
        self.assertIn("DOES_NOT", str(limits.get("operatorMdOneHourAge")))

    def test_36_b_lha_12_record_text_is_the_exact_bytes(self):
        a = record("authority")
        multi = [entry for _, entry in cited(a)
                 if any(f[0] != f[2] for f in entry.get("fragments") or [])]
        self.assertTrue(multi)
        for entry in multi:
            self.assertIn("\n", entry.get("text"), entry.get("id"))
        quote = (a.get("consumers") or {}).get("beforeLiveLauncher", {}).get("quote") or {}
        self.assertIn("\n  full native", quote.get("text", ""))  # indentation kept, no normalisation
        self.assertIs((a.get("digestRule") or {}).get("wholeSentenceDigest"), False)

    # --- sections 5 to 7 as this oracle's own record checks (the design's section 8 refusal list)

    def test_40_recipe_section_5(self):
        self.assertNone(recipe_findings(record("recipe")))

    def test_41_launcher_install_section_6(self):
        self.assertNone(launcher_findings(record("launcher")))

    def test_42_custody_model_section_7(self):
        self.assertNone(custody_findings(record("custody")))

    def test_43_readme_states_what_the_design_asks(self):
        text = render(readme().replace("`", "")).lower()
        for words in ("python3 -i -b scripts/linux_host_authority.py check", "precedence",
                      "licence charge would need a contract amendment", "teardown releases per-run capacity",
                      "no undated mirror", "approving capacity is not qualification",
                      "no gcp project, vm, key or spend exists or is created by this packet",
                      "a grant made and removed between them, or made after step 15, is not detected",
                      "owner_admin", "owner_login", "owner_login_baseline"):
            self.assertIn(words, text)
        for step in range(1, 17):
            self.assertIn("| %d |" % step, readme())

    # --- item 6: design-derived mutations, refused by this oracle's own checks (the README documents no way to check a
    #     modified copy with the published command line)

    def test_50_own_mutations_authority(self):
        a = record("authority")
        sup = a["supersedes"]
        unchanged = a["unchanged"]
        lines = a["decisions"]["decisionLines"]
        q1 = [i for i, x in enumerate(lines) if _sha(x.get("text")) == DECISION_PINS["Q-LHA-1"]][0]
        paid = _find_index(unchanged, "text", [e for e in unchanged if KEPT[2][1](e)][0]["text"])
        provisioning = [i for i, e in enumerate(sup) if e.get("member") == "billing.newProvisioning"][0]
        cases = [
            ("a span that does not match", digest_findings, lambda d: _set(d, ["supersedes", 0, "span"], "0" * 64)),
            ("a text that does not match", digest_findings,
             lambda d: _set(d, ["unchanged", 0, "text"], d["unchanged"][0]["text"] + " ")),
            ("a file digest that does not match", digest_findings,
             lambda d: _set(d, ["costScope", 0, "fileSha256"], "f" * 64)),
            ("a reviewed entry off its digest", digest_findings,
             lambda d: _set(d, ["reviewedNotBinding", 0, "fragments"], [[22, 1, 23, 44]])),
            ("a member path in short form", member_findings,
             lambda d: _set(d, ["supersedes", provisioning, "member"], "newProvisioning")),
            ("a relaxed predicate other than the listed ones", relaxed_findings,
             lambda d: d["supersedes"].append(copy.deepcopy(d["unchanged"][paid])) or d),
            ("an unchanged list missing a kept predicate", kept_findings,
             lambda d: d["unchanged"].pop(paid) and d),
            ("the independence clause without the disclosure", replacement_findings,
             lambda d: _set(d, ["replacementPredicate", "disclosure"], {})),
            ("the independence clause without the owner's answer", replacement_findings,
             lambda d: _set(d, ["replacementPredicate", "ownerAnswer"], "answer")),
            ("an evidence state moved", evidence_findings, lambda d: _set(d, ["evidence", "nativeAmd64"], "PASS")),
            ("a licence charge", capacity_findings, lambda d: _set(d, ["capacity", "licenceCharge"], "PER_HOUR")),
            ("a capacity binding missing the teardown report", capacity_findings,
             lambda d: _set(d, ["capacity", "binding"], ["PLAN_SHA256", "LEASE", "COST_CEILING"])),
            ("decisions not verbatim", decision_findings,
             lambda d: _set(d, ["decisions", "decisionLines", q1, "text"], lines[q1]["text"].replace("keys", "key"))),
            ("an identity named", identity_findings,
             lambda d: _set(d, ["supersedes", 0, "note"], "approved by someone" + chr(64) + "example.test")),
            ("a credential-like string", string_rule_findings,
             lambda d: _set(d, ["supersedes", 0, "note"], "-" * 5 + "BEG" + "IN key")),
        ]
        for label, check, mutation in cases:
            self.assertNone(check(record("authority")), label + " (published)")
            self.assertTrue(check(mutation(record("authority"))), label)

    def test_51_own_mutations_recipe(self):
        def check(d, identity, step):
            return [c for c in d["access"]["effectiveChecks"] if c["identity"] == identity and c["step"] == step][0]

        cases = [
            ("a host with a service account", lambda d: _set(d, ["machine", "serviceAccount"], True)),
            ("a host with scopes", lambda d: _set(d, ["machine", "scopes"], ["cloud-platform"])),
            ("ingress other than IAP tcp 22", lambda d: _set(d, ["firewall", "ingress", 0, "port"], 2222)),
            ("an internal path other than F1 and F2", lambda d: _then(d, d["internalFlows"].append(
                dict(d["internalFlows"][0], id="F3")))),
            ("a kubeconfig on the proxy/operator host", lambda d: _set(d, ["hosts", 0, "rootKubeconfig"], True)),
            ("SSH keys in metadata", lambda d: _then(d, d["machine"]["metadata"].append({"key": "ssh-keys", "value": "x"}))),
            ("an unlisted guest-agent feature on", lambda d: _then(d, d["guestAgent"]["on"].append("DIAGNOSTICS"))),
            ("Shielded VM off", lambda d: _set(d, ["machine", "shieldedVm", "secureBoot"], False)),
            ("serial port on", lambda d: _set(d, ["machine", "serialPortAccess"], True)),
            ("OS Login 2FA off", lambda d: _set(d, ["machine", "metadata", 1, "value"], "FALSE")),
            ("osAdminLogin present at step 10", lambda d: _then(d, check(d, "OWNER_LOGIN", 10)["absent"].remove(
                "compute.instances.osAdminLogin"))),
            ("an IAM-changing permission at step 15", lambda d: _then(d, check(d, "OWNER_LOGIN", 15)["absent"].remove(
                "iam.roles.update"))),
            ("a basic role in the login baseline", lambda d: _set(d, ["access", "loginBaseline", "basicRole"], "EDITOR")),
            ("the permission list not compared at step 15", lambda d: _then(d, check(d, "OWNER_LOGIN", 15).update(
                checksPermissionListAgainstPlan=False))),
            ("an audit-log custom-role update not refused", lambda d: _set(
                d, ["access", "auditLogCheck", "anyCustomRoleChange"], "ACCEPTED")),
            ("a run binding granted by the login identity", lambda d: _set(
                d, ["access", "leaseBindings", 0, "grantedBy"], "OWNER_LOGIN")),
            ("OWNER_ADMIN holding a login permission", lambda d: _then(d, check(d, "OWNER_ADMIN", 10)["absent"].remove(
                "compute.instances.osLogin"))),
            ("an external address at campaign time", lambda d: _set(d, ["egress", "atCampaign", "externalAddress"], True)),
            ("an allow rule without a byte ceiling", lambda d: _set(d, ["firewall", "setupWindowAllow", "byteCeiling"], "")),
            ("NAT present", lambda d: _set(d, ["project", "cloudNat"], True)),
            ("Private Google Access on", lambda d: _set(d, ["project", "privateGoogleAccess"], True)),
            ("a maximum run duration later than the lease", lambda d: _set(
                d, ["machine", "maxRunDuration", "endsNoLaterThan"], "LEASE_END_PLUS_ONE_DAY")),
            ("an image of the wrong architecture", lambda d: _set(d, ["image", "architecture"], "ARM64")),
            ("a licence charge", lambda d: _set(d, ["image", "licenceCharge"], "PER_HOUR")),
            ("a build disk left after step 5", lambda d: _set(d, ["image", "customImage", "buildDiskDeletedAtStep"], 16)),
            ("a paid item without its plan line item", lambda d: _set(d, ["costScope", 4, "planLineItem"], False)),
            ("a custom image not deleted at teardown", lambda d: _set(
                d, ["image", "customImage", "deletedAtTeardown"], False)),
            ("SELinux not enforcing", lambda d: _set(d, ["image", "selinux"], "PERMISSIVE")),
            ("deny_unknown not 1", lambda d: _set(d, ["profile", 1, "value"], "DENY_UNKNOWN_0")),
            ("an inventory frozen before an install", lambda d: _set(d, ["hostInventory", "frozenAtStep"], 7)),
            ("an inventory without its scope", lambda d: _set(d, ["hostInventory", "records", 1, "scope"], ["/etc"])),
            ("an automatic updater on", lambda d: _set(d, ["packages", "automaticUpdaters"], "ON")),
            ("a package without a file digest", lambda d: _set(d, ["packages", "sources", 0, "pin"], "VERSION_ONLY")),
            ("a source transfer without .git", lambda d: _set(d, ["source", "withGit"], False)),
            ("a source transfer without treeSha256", lambda d: _set(d, ["source", "treeSha256"], False)),
            ("a deny policy", lambda d: _set(d, ["access", "revocation", "denyPolicy"], True)),
            ("an onHost step with admin after the revocation", lambda d: _set(
                d, ["runbook", 10, "onHost"], "OWNER_LOGIN_WITH_ADMIN")),
        ]
        self.assertNone(recipe_findings(record("recipe")))
        for label, mutation in cases:
            self.assertTrue(recipe_findings(mutation(record("recipe"))), label)
        named = _set(record("recipe"), ["roleLabels", "loginIdentity"], "someone" + chr(64) + "example.test")
        self.assertTrue(identity_findings(named), "an exported or published record naming an identity")
        full_name = "pro" + "jects/run-project-1/" + "ro" + "les/loginBaseline"
        self.assertTrue(identity_findings(_set(record("recipe"), ["roleLabels", "loginBaselineRole"], full_name)),
                        "the custom role by its full name")

    def test_52_own_mutations_launcher(self):
        cases = [
            ("a step without rollback", lambda d: _set(d, ["steps", 0, "rollback"], "")),
            ("a step that moves a trust digest", lambda d: _set(d, ["steps", 1, "movesTrustDigest"], True)),
            ("a new policy without new probe evidence", lambda d: _set(
                d, ["rules", "newPolicyNeedsNewProbeEvidence"], False)),
            ("a manifest signed before its preflight", lambda d: _set(d, ["rules", "noManifestBeforeItsPreflight"], False)),
            ("a live manifest signed by the other launcher's key", lambda d: _set(
                d, ["liveLauncher", "manifestSigner"], "LINUX_RUNNER_MANIFEST")),
            ("T2 ending more than one hour after the preflight", lambda d: _set(
                d, ["timeLimits", "t2EndsWithinHoursOfPreflight"], 2)),
            ("a live manifest signed before CONF-LIVE-005/006's own preflight", lambda d: _set(
                d, ["liveLauncher", "manifestSignedAfter"], "T2")),
            ("a writable trust mount", lambda d: _set(d, ["liveLauncher", "trustMounts", 0, "readOnly"], False)),
            ("a wrong mode", lambda d: _set(d, ["liveLauncher", "trustMounts", 1, "mode"], "0644")),
            ("a change under /etc/planeon not through the installer", lambda d: _set(
                d, ["rules", "afterRevocationEtcPlaneonChangesOnlyThrough"], "ANY_ROOT_WRITE")),
            ("a drop accepted without a verified drop manifest", lambda d: d["signedDropInstaller"][
                "installsOnlyIf"].remove("DROP_MANIFEST_VERIFIES") or d),
            ("an unlisted target", lambda d: d["signedDropInstaller"]["fixedTargets"].append(
                {"id": "X", "path": "/etc/planeon/../shadow", "owner": "ROOT", "mode": "0444"}) or d),
            ("the metadata address outside the probe scope", lambda d: d["offlineLauncher"][
                "preflightProbeScope"].remove("METADATA_ADDRESS") or d),
            ("a trigger unit with operator arguments", lambda d: _set(d, ["triggerUnits", 0, "operatorArguments"], True)),
        ]
        self.assertNone(launcher_findings(record("launcher")))
        for label, mutation in cases:
            self.assertTrue(launcher_findings(mutation(record("launcher"))), label)

    def test_53_own_mutations_custody(self):
        cases = [
            ("two authorities sharing one key id", lambda d: _set(d, ["authorities", 1, "keyId"],
                                                                 d["authorities"][0]["keyId"])),
            ("two authorities sharing one purpose", lambda d: _set(d, ["authorities", 3, "purpose"],
                                                                  d["authorities"][2]["purpose"])),
            ("a missing authority", lambda d: d["authorities"].pop() and d),
            ("a missing per-run credential", lambda d: d["perRunCredentials"].pop() and d),
            ("a per-run credential reused across runs", lambda d: _set(d, ["perRunCredentials", 0, "reusedAcrossRuns"], True)),
            ("a per-run credential made off its named host", lambda d: _set(
                d, ["perRunCredentials", 1, "madeOn"], "CLUSTER_NODE")),
            ("a per-run credential not destroyed at teardown", lambda d: _set(d, ["perRunCredentials", 0, "ends"], "KEPT")),
            ("an envelope whose server SPKI is not the run's fresh key", lambda d: d["crossHostReplay"][
                "envelopeBinds"].remove("SERVER_SPKI_FRESH_PER_RUN") or d),
            ("a holder written as a name", lambda d: _set(d, ["authorities", 0, "holder"], "Key Holder")),
            ("a revocation route over the network", lambda d: _set(d, ["revocation", "network"], True)),
            ("a signing registry inside the run project", lambda d: _set(
                d, ["nonce", "signingRegistry", "location"], "INSIDE_THE_RUN_PROJECT")),
            ("a reused envelope or capacity nonce", lambda d: _set(
                d, ["nonce", "signingRegistry", "neverSignsSameNonceTwice"], False)),
            ("a host ledger not exported", lambda d: _set(d, ["nonce", "hostLedger", "exportedAtStep"], 16)),
            ("an evidence store that outlives teardown", lambda d: _set(d, ["evidenceStore", "inRunProjectBeyondPlan"], True)),
            ("a client trust that holds the local CA (B-LHA-2)", lambda d: d["kubernetes"]["apiServerClientTrust"].append(
                d["localCa"]["id"]) or d),
            ("a local-CA leaf that authenticates to the API server (B-LHA-2)", lambda d: _set(
                d, ["perRunCredentials", 0, "grantsKubernetesAccess"], True)),
            ("T2 outside the hour", lambda d: _set(d, ["tokenSessions", 1, "withinOneHourOfPreflight"], False)),
            ("the disclosure missing", lambda d: _set(d, ["independence", "disclosure"], {})),
        ]
        self.assertNone(custody_findings(record("custody")))
        for label, mutation in cases:
            self.assertTrue(custody_findings(mutation(record("custody"))), label)

    def test_54_own_mutations_drop_manifest_schema(self):
        node = schema("drop")
        sample = {"schemaVersion": node.get("$id"), "planSha256": "a" * 64, "instance": "1234567890",
                  "bootId": "0123abcd-0123-4abc-8def-0123456789ab", "validFrom": "2026-10-25T10:00:00Z",
                  "validUntil": "2026-10-25T11:00:00Z", "leaseExpiresAt": "2026-10-25T12:00:00Z",
                  "signer": "LINUX_RUNNER_MANIFEST", "files": [{"target": OFFLINE_MANIFEST_PATH, "sha256": "b" * 64}]}
        validator = jsonschema.Draft202012Validator(node)
        self.assertEqual(list(validator.iter_errors(sample)), [])
        self.assertNone(shape_findings(sample, node))
        mutations = [
            ("an extra key", lambda d: _set(d, ["extra"], 1)),
            ("a runner manifest offered as a drop manifest", lambda d: _set(d, ["schemaVersion"], RUNNER_MANIFEST_SCHEMA_ID)),
            ("a policy offered as a drop manifest", lambda d: _set(d, ["schemaVersion"], POLICY_SCHEMA_ID)),
            ("no boot_id binding", lambda d: d.pop("bootId") and d),
            ("no plan binding", lambda d: d.pop("planSha256") and d),
            ("no lease binding", lambda d: d.pop("leaseExpiresAt") and d),
            ("a target outside /etc/planeon", lambda d: _set(d, ["files", 0, "target"], "/usr/bin/x")),
            ("a file without its sha256", lambda d: _then(d, d["files"][0].pop("sha256"))),
            ("no file", lambda d: _set(d, ["files"], [])),
        ]
        for label, mutation in mutations:
            doc = mutation(copy.deepcopy(sample))
            self.assertTrue(list(validator.iter_errors(doc)), label)
            self.assertTrue(shape_findings(doc, node), label)

    # --- item 6: the checker's published command line, as the README documents it

    def test_60_published_check_exits_0(self):
        result = _cli("check")
        self.assertEqual(result.returncode, 0, (result.stdout[-2000:], result.stderr[-2000:]))

    def test_61_published_usage_error_exits_2(self):
        result = _cli("no-such-command")
        self.assertEqual(result.returncode, 2, (result.stdout[-2000:], result.stderr[-2000:]))


if __name__ == "__main__":
    unittest.main()
