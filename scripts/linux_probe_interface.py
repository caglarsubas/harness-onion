"""The neutral Linux probe interface's binding model (MET-LIVE-003, slot 262). Standard library only.

`check(record, read)` returns the sorted refusal texts, empty when the record holds. `read(path)` returns a file's bytes or
None. The model checks the four `v1/` files' digests, the MANIFEST against the record, the interface's conformance to its
own schema (a validator for exactly the schema's keyword set: any other keyword refuses), and the binding of LPK-0's
`NEUTRAL_INTERFACE_CONTRACT` placeholder.
"""

import hashlib
import json
import re

SCHEMA = "planeon.internal.linux-probe-interface-binding/v1"
DIRECTORY = "architecture/linux-probe-interface/v1/"
FILES = ("MANIFEST.json", "README.md", "probe-interface.json", "probe-interface.schema.json")
LPK0_RECORD = "architecture/probe-kit-scope/amendment.json"
PLACEHOLDER = "NEUTRAL_INTERFACE_CONTRACT"
MEMBERS = ("files", "nonClaims", "ownerDecisions", "packet", "placeholderBinding", "reviews", "schemaVersion", "slot",
           "source", "workItem")
SOURCE_MEMBERS = ("commit", "readAt", "repository", "tree")
BINDING_MEMBERS = ("boundTo", "interfaceSha256", "placeholder", "record", "recordSha256")
# Pinned (review round 1, L1-1..L1-3 and L1-8): the monitor-verified handoff digests, the owner decisions and the
# non-claims, two of them the MANIFEST's own texts.
HANDOFF = {"MANIFEST.json": "67cedd0cc251c61bfd42bc0f100d90923d3bafebb8b38c4e2ae7da891973a9a8",
           "README.md": "049773616005f017bda9a79f22448fc16258ea61d5351ea108a5050213819da3",
           "probe-interface.json": "8c630b41bed90cd10781edc66ba122d2c4caf06fbf5adfaa2be996e3d90233be",
           "probe-interface.schema.json": "2ae672a9912061810f00436e4939c0d4a45074e345b01e3fb04387fed8a5ab69"}
DECISIONS = [{"id": "Q-PK-6", "quote": "Neutral contract (Recommended)"},
             {"id": "R12-ACCEPTANCE-RULES", "quote": "Keep them in R12 (Recommended)"}]
MANIFEST_NON_CLAIMS = ["This draft records the interface form only; it does not state or imply that any probe output will be accepted by R12.",
                       "R12 vendors this contract back later; until then R12's own files remain authoritative."]
NON_CLAIMS = [
    {"id": "FORM_ONLY", "text": MANIFEST_NON_CLAIMS[0]},
    {"id": "NOT_ACCEPTANCE", "text": "A probe kit built from this contract alone shows the interface form, not acceptance."},
    {"id": "R12_FILES_AUTHORITATIVE_UNTIL_VENDORED", "text": MANIFEST_NON_CLAIMS[1]},
    {"id": "R12_KEEPS_STATUS_AND_COUNT_RULES", "text": "R12's acceptance rules, the status and count thresholds, stay in R12 (owner, \"Keep them in R12 (Recommended)\"); the kit's author never learns them."},
]
DRAFT = "https://json-schema.org/draft/2020-12/schema"
KEYWORDS = frozenset(("$defs", "$ref", "$schema", "title", "type", "properties", "required", "additionalProperties",
                      "items", "prefixItems", "minItems", "maxItems", "uniqueItems", "const", "enum", "pattern",
                      "minLength", "minimum", "allOf", "if", "then"))

R = {
    "shape": "the record's shape is not the closed shape",
    "order": "a list is not sorted or holds a duplicate row",
    "sha": "a file's sha256 does not equal the record",
    "manifest": "the MANIFEST disagrees with the record",
    "verdict": "the last review's verdict is not PASS_FOR_HANDOFF",
    "keyword": "the schema uses a keyword outside the supported set",
    "conformance": "probe-interface.json does not conform to its schema",
    "placeholder": "the NEUTRAL_INTERFACE_CONTRACT binding is not as stated",
    "claims": "the non-claims are not exactly as stated",
    "handoff": "a v1 file's digest is not the monitor-verified handoff digest",
    "decisions": "the owner decisions are not exactly as stated",
}


def sha(data):
    return hashlib.sha256(data).hexdigest()


def number(value):
    return isinstance(value, (int, float)) and not isinstance(value, bool)


def same(a, b):
    """JSON equality as draft 2020-12 defines it: booleans apart from numbers, numbers by value (10 equals 10.0)."""
    if isinstance(a, bool) or isinstance(b, bool):
        return type(a) is type(b) and a == b
    if number(a) and number(b):
        return a == b
    if isinstance(a, dict) and isinstance(b, dict):
        return a.keys() == b.keys() and all(same(a[k], b[k]) for k in a)
    if isinstance(a, list) and isinstance(b, list):
        return len(a) == len(b) and all(same(x, y) for x, y in zip(a, b))
    return type(a) is type(b) and a == b


def is_type(value, name):
    return {"object": isinstance(value, dict), "array": isinstance(value, list), "string": isinstance(value, str),
            "boolean": isinstance(value, bool),
            "integer": (isinstance(value, int) and not isinstance(value, bool))
                       or (isinstance(value, float) and value.is_integer())}.get(name, False)


def keywords(schema, out):
    """Every keyword the schema uses, walking only schema positions."""
    if not isinstance(schema, dict):
        return
    for key, value in schema.items():
        out.add(key)
        if key in ("properties", "$defs"):
            for sub in value.values():
                keywords(sub, out)
        elif key in ("items", "additionalProperties", "if", "then"):
            keywords(value, out)
        elif key in ("allOf", "prefixItems"):
            for sub in value:
                keywords(sub, out)


def ecma(pattern):
    """A pattern's final unescaped `$` matches only at the very end, as in ECMA-262 (Python's `$` also matches before a
    final line feed; review round 1, L1-7)."""
    if pattern.endswith("$"):
        slashes = len(pattern[:-1]) - len(pattern[:-1].rstrip("\\"))
        if slashes % 2 == 0:
            return pattern[:-1] + r"\Z"
    return pattern


def valid(value, schema, root, depth=0):
    """Whether `value` conforms to `schema` under the supported keyword set (draft 2020-12 meaning; a boolean schema
    is true or false, review round 1, L1-5)."""
    if isinstance(schema, bool):
        return schema
    if depth > 64 or not isinstance(schema, dict):
        return False
    if "$ref" in schema:
        ref = schema["$ref"]
        if not ref.startswith("#/$defs/") or ref[8:] not in root.get("$defs", {}):
            return False
        if not valid(value, root["$defs"][ref[8:]], root, depth + 1):
            return False
    if "type" in schema and not is_type(value, schema["type"]):
        return False
    if "const" in schema and not same(value, schema["const"]):
        return False
    if "enum" in schema and not any(same(value, option) for option in schema["enum"]):
        return False
    if isinstance(value, str):
        if "minLength" in schema and len(value) < schema["minLength"]:
            return False
        if "pattern" in schema and not re.search(ecma(schema["pattern"]), value):
            return False
    if number(value) and "minimum" in schema and value < schema["minimum"]:
        return False
    if isinstance(value, dict):
        if any(name not in value for name in schema.get("required", [])):
            return False
        properties = schema.get("properties", {})
        for name, member in value.items():
            if name in properties:
                if not valid(member, properties[name], root, depth + 1):
                    return False
            elif schema.get("additionalProperties") is False:
                return False
            elif "additionalProperties" in schema and \
                    not valid(member, schema["additionalProperties"], root, depth + 1):
                return False
    if isinstance(value, list):
        if "minItems" in schema and len(value) < schema["minItems"]:
            return False
        if "maxItems" in schema and len(value) > schema["maxItems"]:
            return False
        if schema.get("uniqueItems") and any(same(value[i], value[j]) for i in range(len(value))
                                             for j in range(i + 1, len(value))):
            return False
        prefix = schema.get("prefixItems", [])
        for index, item in enumerate(value):
            if index < len(prefix):
                if not valid(item, prefix[index], root, depth + 1):
                    return False
            elif "items" in schema and not valid(item, schema["items"], root, depth + 1):
                return False
    for sub in schema.get("allOf", []):
        if not valid(value, sub, root, depth + 1):
            return False
    if "if" in schema and valid(value, schema["if"], root, depth + 1) and "then" in schema \
            and not valid(value, schema["then"], root, depth + 1):
        return False
    return True


def check(record, read):
    try:
        return _check(record, read)
    except (TypeError, AttributeError, KeyError, ValueError, IndexError, UnicodeDecodeError, re.error, RecursionError):
        return [R["shape"]]


def _check(record, read):
    refusals = set()
    if not isinstance(record, dict) or tuple(sorted(record)) != MEMBERS:
        return [R["shape"]]
    types = {"files": list, "nonClaims": list, "ownerDecisions": list, "packet": str, "placeholderBinding": dict,
             "reviews": list, "schemaVersion": str, "slot": int, "source": dict, "workItem": str}
    if any(type(record[name]) is not kind for name, kind in types.items()):
        return [R["shape"]]
    if record["schemaVersion"] != SCHEMA or record["packet"] != "MET-LIVE-003" or record["slot"] != 262 \
            or record["workItem"] != "LINUX-PROBE-INTERFACE":
        refusals.add(R["shape"])
    files = record["files"]
    if not isinstance(files, list) or [row.get("path") for row in files] != [DIRECTORY + name for name in FILES] or \
            any(tuple(sorted(row)) != ("path", "sha256") for row in files):
        return sorted(refusals | {R["shape"]})
    data = {}
    for row in files:
        data[row["path"][len(DIRECTORY):]] = read(row["path"])
        if data[row["path"][len(DIRECTORY):]] is None or sha(data[row["path"][len(DIRECTORY):]]) != row["sha256"]:
            refusals.add(R["sha"])
    if any(value is None for value in data.values()):
        return sorted(refusals)
    digests = {row["path"][len(DIRECTORY):]: row["sha256"] for row in files}
    if digests != HANDOFF:
        refusals.add(R["handoff"])

    # The MANIFEST against the record.
    manifest = json.loads(data["MANIFEST.json"].decode("utf-8"))
    if manifest.get("files") != {name: digests[name] for name in FILES if name != "MANIFEST.json"}:
        refusals.add(R["manifest"])
    source = record["source"]
    if tuple(sorted(source)) != SOURCE_MEMBERS or not isinstance(manifest.get("source"), dict) or \
            tuple(sorted(manifest["source"])) != SOURCE_MEMBERS or not same(source, manifest["source"]):
        refusals.add(R["manifest"])
    if manifest.get("nonClaims") != MANIFEST_NON_CLAIMS:
        refusals.add(R["manifest"])
    reviews = record["reviews"]
    if not isinstance(reviews, list) or any(tuple(sorted(row)) != ("recordSha256", "round", "verdict") for row in reviews):
        refusals.add(R["shape"])
    else:
        if [row["round"] for row in reviews] != list(range(1, len(reviews) + 1)):
            refusals.add(R["order"])
        stated = [{"round": row.get("round"), "recordSha256": row.get("recordSha256"), "verdict": row.get("verdict")}
                  for row in manifest.get("reviews", [])]
        if not same(reviews, stated):
            refusals.add(R["manifest"])
        if not reviews or reviews[-1]["verdict"] != "PASS_FOR_HANDOFF" or manifest.get("verdict") != "PASS_FOR_HANDOFF":
            refusals.add(R["verdict"])

    # The interface's conformance to its own schema.
    schema = json.loads(data["probe-interface.schema.json"].decode("utf-8"))
    used = set()
    keywords(schema, used)
    if not isinstance(schema, dict) or not used <= KEYWORDS or schema.get("$schema") != DRAFT:
        refusals.add(R["keyword"])
    elif not valid(json.loads(data["probe-interface.json"].decode("utf-8")), schema, schema):
        refusals.add(R["conformance"])

    # LPK-0's placeholder.
    binding = record["placeholderBinding"]
    if not isinstance(binding, dict) or tuple(sorted(binding)) != BINDING_MEMBERS:
        refusals.add(R["shape"])
    else:
        lpk0 = read(LPK0_RECORD)
        try:
            placeholders = json.loads(lpk0.decode("utf-8"))["effectivePredecessors"]["placeholders"] if lpk0 else []
        except (ValueError, KeyError, TypeError):
            placeholders = []
        if binding["record"] != LPK0_RECORD or lpk0 is None or sha(lpk0) != binding["recordSha256"] or \
                binding["placeholder"] != PLACEHOLDER or PLACEHOLDER not in placeholders or \
                binding["boundTo"] != record["packet"] or binding["interfaceSha256"] != digests["probe-interface.json"]:
            refusals.add(R["placeholder"])

    # Owner decisions (shape only; their text is checked at the contract build) and the non-claims.
    decisions = record["ownerDecisions"]
    if not all(type(row) is dict for row in decisions):
        return [R["shape"]]
    if decisions != DECISIONS:
        refusals.add(R["decisions"])
    claims = record["nonClaims"]
    if not all(type(row) is dict for row in claims):
        return [R["shape"]]
    if claims != NON_CLAIMS:
        refusals.add(R["claims"])
    return sorted(refusals)
