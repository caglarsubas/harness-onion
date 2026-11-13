"""R8 clause 2's successor from slot 288 (MET-007; CONTRACT_288 rev 3 section 6, Q-288-B2 (a)), beside its record
`architecture/repository-registration/rule-288.json`.

The 284 module `scripts/repository_registration.py` and its record `architecture/repository-registration/rule.json` stay
byte-equal. This module pins the 284 module by REGISTRATION_284_SHA256 (`pin_284`, as the 284 module pins v2), checks
that rule-288.json's `extends` names rule.json's, the 284 module's and this module's own bytes by sha256 (as the 284
module checks rule.json), and answers, by delegation to the 284 module:
- `allowed_names(base, record, base_record, ext, slot)`: the 284 answer (rule.json's twelve names before 284, R13 from
  284) plus this record's additions from its fromSlot on (R14 from 288);
- `check_products(base, ext, products, read_packet, safe_load, chain_packets, v2, record, base_record)`: R8 clause 2 by
  each product's slot, the 284 module's check_products over slots before 288 with rule.json alone and over slots from
  288 with both records' additions;
- `check(base, record_raw, base_record_raw, base_module_raw, module_raw, ext, slot)`: a head's one call (pin_284, load,
  then allowed_names), so a chain layer reaches R8 clause 2 through one name.

R14 mas-harness-reference-lab is kind meta in its row of the successor registry record, while its first packet will be a
product packet in the chain vocabulary; allowedNames reads only the name, so there is no conflict (VIS-284). Standard
library only: the caller passes the 284 module and the bytes this module pins.
"""
import hashlib
import json

REGISTRATION_284_NAME = "repository_registration.py"
REGISTRATION_284_SHA256 = "e8635f23dbf10572da331237483c8245ee590f9f423f54d6c8ce28b11c01736c"
RECORD_PATH = "architecture/repository-registration/rule-288.json"
BASE_RECORD_PATH = "architecture/repository-registration/rule.json"
BASE_MODULE_PATH = "scripts/repository_registration.py"
MODULE_PATH = "scripts/repository_registration_288.py"
SCHEMA = "harness.planeon.ai/repository-registration-rule/v1"
PACKET = "MET-007"
FROM_SLOT = 288


class Refused(ValueError):
    """A refusal of the successor rule, in the 284 module's message form."""


def need(ok, clause, detail):
    if not ok:
        raise Refused("registration %s: %s" % (clause, detail))


def _sha(raw):
    return hashlib.sha256(raw).hexdigest()


def pin_284(base, raw):
    """Bind the 284 module: the caller's bytes must hash to REGISTRATION_284_SHA256 and the module be its file."""
    need(type(raw) is bytes and _sha(raw) == REGISTRATION_284_SHA256, "model",
         "repository_registration.py is not the pinned 284 module (%s)" % REGISTRATION_284_SHA256[:8])
    need(str(getattr(base, "__file__", "")).replace("\\", "/").rsplit("/", 1)[-1] == REGISTRATION_284_NAME, "model",
         "the module is not repository_registration.py")
    return base


def load(record_raw, base_record_raw, base_module_raw, module_raw):
    """The record, checked: its schema, its `extends` digests (rule.json's, the 284 module's and this module's) and its
    one slot split from 288."""
    try:
        record = json.loads(record_raw.decode("utf-8"))
    except (AttributeError, UnicodeDecodeError, ValueError):
        record = None
    need(type(record) is dict and record.get("schemaVersion") == SCHEMA and record.get("packet") == PACKET, "record",
         "the slot-288 repository-registration record")
    need(type(base_module_raw) is bytes and _sha(base_module_raw) == REGISTRATION_284_SHA256, "extends",
         "the 284 module is not the pinned one")
    need(record.get("extends") == [
        {"path": BASE_RECORD_PATH, "sha256": _sha(base_record_raw), "clause": "allowedNames"},
        {"path": BASE_MODULE_PATH, "sha256": REGISTRATION_284_SHA256, "clause": "R8 clause 2"},
        {"path": MODULE_PATH, "sha256": _sha(module_raw), "clause": "R8 clause 2 from slot 288"},
    ], "extends", "the record does not extend rule.json, the 284 module and this module by their sha256")
    split = record.get("allowedNames")
    need(type(split) is list and len(split) == 1 and type(split[0]) is dict
         and set(split[0]) == {"fromSlot", "add"} and split[0]["fromSlot"] == FROM_SLOT
         and type(split[0]["add"]) is list and split[0]["add"]
         and all(type(n) is str and n for n in split[0]["add"]), "record", "one slot split of added names from 288")
    return record


def allowed_names(base, record, base_record, ext, slot):
    """The 284 module's names at slot, plus this record's additions from its fromSlot on."""
    names = list(base.allowed_names(base_record, ext, slot))
    entry = record["allowedNames"][0]
    if slot >= entry["fromSlot"]:
        names += [n for n in entry["add"] if n not in names]
    need(ext["productRepository"]["refusedName"] not in names, "record", "the refused name is not allowed")
    return names


def check(base, record_raw, base_record_raw, base_module_raw, module_raw, ext, slot):
    """The allowed names at slot through both records, the head's one call: pin_284, load, then allowed_names."""
    pin_284(base, base_module_raw)
    record = load(record_raw, base_record_raw, base_module_raw, module_raw)
    return allowed_names(base, record, json.loads(base_record_raw.decode("utf-8")), ext, slot)


def check_products(base, ext, products, read_packet, safe_load, chain_packets, v2, record, base_record):
    """The 284 module's check_products, by slot: before 288 with rule.json, from 288 with both records' additions."""
    cut = record["allowedNames"][0]["fromSlot"]
    before = {s: ids for s, ids in products.items() if s < cut}
    later = {s: ids for s, ids in products.items() if s >= cut}
    count = base.check_products(ext, before, read_packet, safe_load, chain_packets, v2, base_record) if before else 0
    if later:
        entry = base_record["allowedNames"][0]
        merged = dict(base_record, allowedNames=[{"fromSlot": entry["fromSlot"], "add": list(entry["add"]) + [
            n for n in record["allowedNames"][0]["add"] if n not in entry["add"]]}])
        count += base.check_products(ext, later, read_packet, safe_load, chain_packets, v2, merged)
    return count
