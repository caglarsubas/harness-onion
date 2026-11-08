"""R8 clause 2's successor for the repository registration, and the registry's one composition reader
(MET-REGISTRY-001, slot 284; Q-284-4 (b), VIS-284-CR1, VIS-284-ARGV).

`scripts/chain_identity_v2.py` admits a listed product only when its `repository` line names one of
`architecture/chain-product-packets/rule.json`'s twelve allowed names (R8 clause 2), and its `check_ext` requires
exactly those twelve. v2, `chain_identity_v3.py` and that rule stay byte-equal. This module sits beside its record,
`architecture/repository-registration/rule.json`:

- it binds v2 by V2_SHA256, as `chain_identity_v3.pin_v2` does;
- it reads the slot split of the allowed names from its record only (one source);
- it checks the record's `extends` block, which names rule.json's sha256 and this module's sha256, so a later edit to
  either refuses;
- `check_products` applies R8 clause 2 per product by its layer's slot: rule.json's twelve names before the record's
  `fromSlot`, the twelve plus the record's additions from it on. Every other clause (R2's form, R3, R12) is v2's own,
  called as v2 calls it.

R13 `mas-harness-research-lab` is kind meta in its registry row, while its first packet LAB-REPO-001 is a product packet
in the chain vocabulary; allowedNames reads only the name, so there is no conflict (VIS-284).

The registry `architecture/repositories.yaml` keeps its thirteen rows (VIS-284-ARGV): the 64 inherited acceptance argv
run older validators that read it live. R13's row lives in the successor registry record
`architecture/repository-registration/repositories.json` (its schema pin and rows only, append-only, no override of a
base id or name, no duplicate). Its schema `architecture/repository-registration/repositories.schema.json` lives
beside it and is pinned twice: in the record's `schema` member and in REGISTRY_SCHEMA_SHA256 here, checked before any
row is read (MON-284-SCHEMA-LOC).

`registry_rows(root, safe_load)` is the one composition reader and the one place the record decides (VIS-284-LPORACLE):
with no successor record in the root it reads, the registry's rows alone, as before 284; with one, the module and both
schema pins are required, and a mismatched pin or an unreadable record refuses, never degrades. Every reader that must
see the registry with its successor rows calls it; none of them parses the registry alone or branches on the record.
`scripts/language_placement.py`, the one script that runs alone from a copied root, tests the same predicate
(`record_present`) before it imports this module, and then calls `composed_rows` over its own reads.

`architecture/language-placement.json` and ADR 0010 keep their thirteen rows too (VIS-284-LPORACLE-2: the
language-placement oracle copies them live). R13's placement row lives in the successor placement record
`architecture/repository-registration/language-placement.json` (its schema pin, its decision and its rows only), with
its schema `architecture/repository-registration/language-placement.schema.json` beside it, pinned twice: in the
record and in PLACEMENT_SCHEMA_SHA256 here. `placement_rows(root)` is the placement's reader beside `registry_rows`,
under its own base file's predicate (`placement_record_present`); language placement tests that predicate before its
lazy import and calls `composed_placement_rows`. On the live tree both records are present together.
"""
import hashlib
import json
import os
import re
from pathlib import Path

V2_NAME = "chain_identity_v2.py"
V2_SHA256 = "23fe723ae060b13727118b5808541d0b40bfee22ac5e803955e324f4dd6d9a55"
RECORD_PATH = "architecture/repository-registration/rule.json"
V2_RULE_PATH = "architecture/chain-product-packets/rule.json"
MODULE_PATH = "scripts/repository_registration.py"
SCHEMA = "harness.planeon.ai/repository-registration-rule/v1"
BASE_REGISTRY_PATH = "architecture/repositories.yaml"
SUCCESSOR_REGISTRY_PATH = "architecture/repository-registration/repositories.json"
REGISTRY_SCHEMA_PATH = "architecture/repository-registration/repositories.schema.json"
REGISTRY_SCHEMA_SHA256 = "b2d0723862553ef864d41bc9bed8a907c2124c2e19f4b52c5774ffa4e851075c"
BASE_PLACEMENT_PATH = "architecture/language-placement.json"
SUCCESSOR_PLACEMENT_PATH = "architecture/repository-registration/language-placement.json"
PLACEMENT_SCHEMA_PATH = "architecture/repository-registration/language-placement.schema.json"
PLACEMENT_SCHEMA_SHA256 = "26c4e8746effcdab309da74e1bf864bab2932d9e796a31bedc66a4186282bf26"
PLACEMENT_ROW = frozenset({"id", "name", "rNumber", "languages", "toolchain", "sources"})
DECISION = frozenset({"packet", "policy", "text"})
ROW_REQUIRED = frozenset({"id", "name", "kind", "dependsOn"})
ROW_OPTIONAL = frozenset({"releaseSet"})
ROW_ID = re.compile(r"[a-z][a-z0-9-]*")
ROW_NAME = re.compile(r"mas-harness-[a-z0-9-]+")


class Refused(ValueError):
    """A refusal of the successor rule, in v2's message form."""


def need(ok, clause, detail):
    if not ok:
        raise Refused("registration %s: %s" % (clause, detail))


def _sha(raw):
    return hashlib.sha256(raw).hexdigest()


def pin_v2(v2, raw):
    """Bind v2: the caller's bytes must hash to V2_SHA256 and the module must be chain_identity_v2.py."""
    need(type(raw) is bytes and _sha(raw) == V2_SHA256, "model", "chain_identity_v2.py is not the pinned v2 (%s)"
         % V2_SHA256[:8])
    need(str(getattr(v2, "__file__", "")).replace("\\", "/").rsplit("/", 1)[-1] == V2_NAME, "model",
         "the module is not chain_identity_v2.py")
    return v2


def load(record_raw, v2_rule_raw, module_raw):
    """The record, checked: its schema, its `extends` digests (rule.json's and this module's) and its one slot split."""
    try:
        record = json.loads(record_raw.decode("utf-8"))
    except (UnicodeDecodeError, ValueError):
        record = None
    need(type(record) is dict and record.get("schemaVersion") == SCHEMA, "record", "the repository-registration record")
    need(record.get("extends") == [
        {"path": V2_RULE_PATH, "sha256": _sha(v2_rule_raw), "clause": "productRepository.allowedNames"},
        {"path": MODULE_PATH, "sha256": _sha(module_raw), "clause": "R8 clause 2"},
    ], "extends", "the record does not extend this rule.json and this module by their sha256")
    split = record.get("allowedNames")
    need(type(split) is list and len(split) == 1 and type(split[0]) is dict
         and set(split[0]) == {"fromSlot", "add"} and type(split[0]["fromSlot"]) is int
         and type(split[0]["add"]) is list and split[0]["add"]
         and all(type(n) is str and n for n in split[0]["add"]), "record", "one slot split of added names")
    return record


def allowed_names(record, ext, slot):
    """rule.json's twelve names, plus the record's additions from its fromSlot on."""
    names = list(ext["productRepository"]["allowedNames"]["names"])
    entry = record["allowedNames"][0]
    if slot >= entry["fromSlot"]:
        names += [n for n in entry["add"] if n not in names]
    need(ext["productRepository"]["refusedName"] not in names, "record", "the refused name is not allowed")
    return names


def check_products(ext, products, read_packet, safe_load, chain_packets, v2, record):
    """v2's check_products, with R8 clause 2 read from the record by each product's slot. Returns the count."""
    before = {s: ids for s, ids in products.items() if s < record["allowedNames"][0]["fromSlot"]}
    count = v2.check_products(ext, before, read_packet, safe_load, chain_packets) if before else 0
    path_form = v2.check_ext(ext)
    refused = ext["productRepository"]["refusedName"]
    for slot in sorted(s for s in products if s not in before):
        names = set(allowed_names(record, ext, slot))
        for pid in products[slot]:
            path = "task-packets/%s.yaml" % pid
            v2.need(path_form.fullmatch(path) is not None, "R2", "product id outside the PACKET_PATH form: %s" % pid)
            v2.need(pid not in chain_packets, "R2", "product id equal to a chain packet id: %s" % pid)
            raw = read_packet(path)
            value = v2.line_repository(raw)
            v2.need(value != refused, "R3", "%s names this repository" % pid)
            v2.need(value in names, "R8", "%s names a repository outside the allowed names at slot %d: %s"
                    % (pid, slot, value))
            doc = safe_load(raw)
            v2.need(type(doc) is dict and doc.get("id") == pid, "R2", "%s: the YAML's id is not its file stem" % pid)
            v2.need(doc.get("repository") == value, "R12", "%s: safe_load reads another repository than the line" % pid)
            count += 1
    return count


def _strict_json(raw, what):
    """JSON with no repeated key and no NaN or infinity, from UTF-8 bytes."""
    def pairs(items):
        keys = [key for key, _ in items]
        need(len(keys) == len(set(keys)), "registry", "%s repeats a key" % what)
        return dict(items)

    def constant(token):
        raise Refused("registration registry: %s holds %s" % (what, token))
    need(type(raw) is bytes, "registry", "%s: bytes required" % what)
    try:
        return json.loads(raw.decode("utf-8"), object_pairs_hook=pairs, parse_constant=constant)
    except Refused:
        raise
    except (UnicodeDecodeError, ValueError, RecursionError):
        raise Refused("registration registry: %s does not parse" % what) from None


def base_rows(base_raw, safe_load):
    """The registry's own rows, as a tuple of new dicts: it parses with the caller's YAML loader, every row is a mapping,
    and no id or name repeats."""
    need(type(base_raw) is bytes, "registry", "the registry: bytes required")
    try:
        base = safe_load(base_raw)
    except Refused:
        raise
    except Exception:  # every parse error of the registry, whatever its class, is the composition's refusal
        raise Refused("registration registry: the registry does not parse") from None
    need(type(base) is dict and type(base.get("repositories")) is list and base["repositories"]
         and all(type(row) is dict for row in base["repositories"]), "registry", "the registry's rows")
    rows = tuple(dict(row) for row in base["repositories"])
    ids, names = [row.get("id") for row in rows], [row.get("name") for row in rows]
    need(len(set(ids)) == len(ids) and len(set(names)) == len(names), "registry", "the registry repeats an id or a name")
    return rows


def composed_rows(base_raw, successor_raw, schema_raw, safe_load):
    """The composition, pinned (VIS-284-ARGV): the registry's rows, then the successor record's rows, as a tuple of new
    dicts. First the successor schema's bytes must hash to REGISTRY_SCHEMA_SHA256 and the record's `schema` member must
    name that path and digest (MON-284-SCHEMA-LOC). The successor record holds its schema pin and rows only; each row has
    the registry's row members (id, name, kind, dependsOn) and may add releaseSet EXCLUDED; no row repeats or overrides a
    base id or name, no two rows share an id or a name, and every dependsOn entry names an earlier row. safe_load is the
    caller's YAML loader for the registry."""
    need(type(schema_raw) is bytes and _sha(schema_raw) == REGISTRY_SCHEMA_SHA256, "registry",
         "the successor registry schema is not the pinned one (%s)" % REGISTRY_SCHEMA_SHA256[:8])
    rows = list(base_rows(base_raw, safe_load))
    ids, names = [row.get("id") for row in rows], [row.get("name") for row in rows]
    successor = _strict_json(successor_raw, "the successor registry record")
    need(type(successor) is dict and set(successor) == {"schema", "repositories"}
         and type(successor["repositories"]) is list and successor["repositories"], "registry",
         "the successor registry record holds its schema pin and rows only")
    need(successor["schema"] == {"path": REGISTRY_SCHEMA_PATH, "sha256": REGISTRY_SCHEMA_SHA256}, "registry",
         "the successor registry record does not pin the successor registry schema")
    for row in successor["repositories"]:
        need(type(row) is dict and ROW_REQUIRED <= set(row) <= ROW_REQUIRED | ROW_OPTIONAL, "registry",
             "a successor row is not in the registry's row form")
        need(type(row["id"]) is str and ROW_ID.fullmatch(row["id"]) is not None
             and type(row["name"]) is str and ROW_NAME.fullmatch(row["name"]) is not None
             and row["kind"] in ("meta", "product") and type(row["dependsOn"]) is list
             and all(type(d) is str for d in row["dependsOn"]) and len(set(row["dependsOn"])) == len(row["dependsOn"])
             and row.get("releaseSet", "EXCLUDED") == "EXCLUDED", "registry", "a successor row's members")
        need(row["id"] not in ids and row["name"] not in names, "registry",
             "a successor row repeats or overrides an id or a name: %s" % row["id"])
        need(all(d in ids for d in row["dependsOn"]), "registry", "a successor row depends on an unknown repository")
        ids.append(row["id"])
        names.append(row["name"])
        rows.append(dict(row))
    return tuple(rows)


def record_present(root):
    """The one predicate (VIS-284-LPORACLE): an entry of any kind at SUCCESSOR_REGISTRY_PATH under `root` (a file, a
    directory, a link even when it dangles) is a present record."""
    return os.path.lexists(os.path.join(os.fspath(root), *SUCCESSOR_REGISTRY_PATH.split("/")))


def _root_bytes(root, rel):
    try:
        return Path(root).joinpath(*rel.split("/")).read_bytes()
    except OSError:
        raise Refused("registration registry: %s cannot be read" % rel) from None


def registry_rows(root, safe_load):
    """The one composition reader, and the one place the record decides (VIS-284-LPORACLE): with no successor record
    under `root`, the registry's rows alone, as before 284; with one, composed_rows over the registry, the record and
    the schema, pinned twice. A record present but unreadable, a schema absent or a pin mismatched refuses; nothing
    degrades to the base rows."""
    base_raw = _root_bytes(root, BASE_REGISTRY_PATH)
    if not record_present(root):
        return base_rows(base_raw, safe_load)
    return composed_rows(base_raw, _root_bytes(root, SUCCESSOR_REGISTRY_PATH), _root_bytes(root, REGISTRY_SCHEMA_PATH),
                         safe_load)


def placement_record_present(root):
    """The placement data's predicate (VIS-284-LPORACLE-2 (a), one predicate per base file): an entry of any kind at
    SUCCESSOR_PLACEMENT_PATH under `root` is a present record."""
    return os.path.lexists(os.path.join(os.fspath(root), *SUCCESSOR_PLACEMENT_PATH.split("/")))


def composed_placement_rows(base_rows, successor_raw, schema_raw):
    """The placement data's rows, then the successor placement record's, as a tuple of new dicts (VIS-284-LPORACLE-2).
    First the schema's bytes must hash to PLACEMENT_SCHEMA_SHA256 and the record's `schema` member must name that path
    and digest. The record holds its schema pin, its decision (its packet, its policy and its text) and its rows only;
    each row has the placement row's members (id, name, rNumber, languages, toolchain, sources), whose form is the
    checker's R1; no row repeats or overrides an id or a name."""
    need(type(schema_raw) is bytes and _sha(schema_raw) == PLACEMENT_SCHEMA_SHA256, "placement",
         "the successor placement schema is not the pinned one (%s)" % PLACEMENT_SCHEMA_SHA256[:8])
    need(type(base_rows) in (list, tuple) and base_rows and all(type(row) is dict for row in base_rows), "placement",
         "the placement data's rows")
    rows = [dict(row) for row in base_rows]
    ids, names = [row.get("id") for row in rows], [row.get("name") for row in rows]
    need(len(set(ids)) == len(ids) and len(set(names)) == len(names), "placement",
         "the placement data repeats an id or a name")
    record = _strict_json(successor_raw, "the successor placement record")
    need(type(record) is dict and set(record) == {"schema", "decision", "repositories"}
         and type(record["repositories"]) is list and record["repositories"], "placement",
         "the successor placement record holds its schema pin, its decision and its rows only")
    need(record["schema"] == {"path": PLACEMENT_SCHEMA_PATH, "sha256": PLACEMENT_SCHEMA_SHA256}, "placement",
         "the successor placement record does not pin its schema")
    decision = record["decision"]
    need(type(decision) is dict and set(decision) == DECISION and all(type(v) is str and v for v in decision.values()),
         "placement", "the decision names its packet, its policy and its text")
    for row in record["repositories"]:
        need(type(row) is dict and set(row) == PLACEMENT_ROW, "placement",
             "a successor placement row is not in the placement row form")
        need(row["id"] not in ids and row["name"] not in names, "placement",
             "a successor placement row repeats or overrides an id or a name: %s" % row["id"])
        ids.append(row["id"])
        names.append(row["name"])
        rows.append(dict(row))
    return tuple(rows)


def placement_rows(root):
    """The placement's reader beside registry_rows (VIS-284-LPORACLE-2): with no successor placement record under
    `root`, the placement data's rows alone, as before 284; with one, composed_placement_rows over the data, the record
    and the schema, pinned twice. A record present but unreadable, a schema absent or a pin mismatched refuses."""
    data = _strict_json(_root_bytes(root, BASE_PLACEMENT_PATH), "the placement data")
    need(type(data) is dict and type(data.get("repositories")) is list, "placement", "the placement data's rows")
    if not placement_record_present(root):
        return tuple(dict(row) for row in data["repositories"])
    return composed_placement_rows(data["repositories"], _root_bytes(root, SUCCESSOR_PLACEMENT_PATH),
                                   _root_bytes(root, PLACEMENT_SCHEMA_PATH))
