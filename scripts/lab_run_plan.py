#!/usr/bin/env python3
"""Lab run-plan contract v1 (architecture/lab-run-plan/, MET-LINUX-007): offline checker for the owner's GCP qualification
runs.

Roadmap item LAB-RUNPLAN-001 (owner VR-D1, 2026-10-17; owner decision 2026-10-15: Linux capacity for CONF-LINUX-001 and
W06 is the owner's GCP compute, and each run plan goes to the owner first; owner decisions Q-RP-0..9 (a), 2026-10-19).
Three closed documents, each with a JSON Schema in the contract directory:

- a run plan: what runs and where, the dated cost estimate under the owner's ceiling, alert-only budgets, no exposure
  unless listed, a dedicated read-only observer, owner-held credentials, and the teardown with its expected residual;
- a lease: it binds the plan's canonical sha256 and the owner's approval reference, and expires within the plan's
  maximum duration;
- a teardown-residual report: what the observer saw after teardown in each of eighteen resource classes, which must be
  nothing beyond the plan's residual, with the teardown completed before the lease expired.

DATA_CHECK_ONLY: nothing here touches a cloud, holds a credential, or applies anything; the owner approves each plan by
its sha256. Real plans, leases and reports stay with the owner, outside every repository. The schemas use only the closed
JSON Schema subset this file implements (`SCHEMA_KEYWORDS`, with this file's semantics); any other keyword, and any
object schema that is not closed, is refused, so the schema files and this checker cannot drift apart silently. Standard
library only.

Usage (repository root):
  python3 -I -B scripts/lab_run_plan.py                         check the schemas and replay every vector
  python3 -I -B scripts/lab_run_plan.py plan PLAN               check one plan and print the sha256 the owner approves
  python3 -I -B scripts/lab_run_plan.py lease PLAN LEASE        check a lease against its plan
  python3 -I -B scripts/lab_run_plan.py teardown PLAN LEASE REPORT  check a teardown report (the lease is re-checked)
"""
from __future__ import annotations

import datetime
import hashlib
import ipaddress
import json
import math
import re
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
CONTRACT_DIR = "architecture/lab-run-plan/"
SCHEMA_PATHS = {"plan": CONTRACT_DIR + "run-plan.schema.json", "lease": CONTRACT_DIR + "lease.schema.json",
                "teardown": CONTRACT_DIR + "teardown-report.schema.json"}
VECTORS_PATH = CONTRACT_DIR + "vectors.json"
# The closed JSON Schema subset the schemas may use, with this checker's semantics (not a full JSON Schema dialect).
SCHEMA_KEYWORDS = {"$id", "title", "description", "type", "properties", "required", "additionalProperties", "items",
                   "minItems", "maxItems", "uniqueItems", "enum", "const", "pattern", "minLength", "maxLength", "minimum",
                   "maximum", "exclusiveMinimum"}
TYPES = {"object": dict, "array": list, "string": str, "boolean": bool, "null": type(None)}
TYPE_NAMES = set(TYPES) | {"integer", "number"}
# Where each value keyword applies: (the type it needs, the type of its value).
KEYWORD_RULES = {"pattern": ("string", str), "minLength": ("string", int), "maxLength": ("string", int),
                 "minimum": ("numeric", (int, float)), "maximum": ("numeric", (int, float)),
                 "exclusiveMinimum": ("numeric", (int, float)), "minItems": ("array", int), "maxItems": ("array", int),
                 "uniqueItems": ("array", bool)}
# Integers beyond this magnitude are refused when parsed.
INTEGER_LIMIT = 10 ** 12
# Rate-card freshness, in days, at preparation and at the lease's start; the price tolerance of an amount (half a cent).
RATE_CARD_MAX_AGE_DAYS = 31
CENT = 0.005
HOURS_PER_MONTH = 730
# Exposure: in every plan the ingress sources together cover at most this many addresses (a /16); without an external
# address, every source is also an RFC 1918 private network.
MAX_INGRESS_ADDRESSES = 2 ** 16
PRIVATE_NETWORKS = tuple(ipaddress.ip_network(net) for net in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"))
# The resource classes a teardown report lists, every one, in this order. The fourteen compute and network classes count
# every such resource in the run project, named with the prefix or not (a default network counts); BUCKETS and
# SERVICE_ACCOUNTS count those named with the plan's prefix; SERVICE_ACCOUNT_KEYS counts every user-managed key in the
# run project, the observer's own included; IAM_BINDINGS_ADDED counts the bindings granted on the run project since the
# lease started (the Admin Activity audit log shows each grant), other than the observer's own viewer bindings.
RESOURCE_CLASSES = ("INSTANCES", "INSTANCE_GROUPS", "INSTANCE_TEMPLATES", "DISKS", "SNAPSHOTS", "IMAGES", "ADDRESSES",
                    "NETWORKS", "SUBNETWORKS", "FIREWALL_RULES", "ROUTES", "ROUTERS", "NAT_GATEWAYS", "FORWARDING_RULES",
                    "BUCKETS", "SERVICE_ACCOUNTS", "SERVICE_ACCOUNT_KEYS", "IAM_BINDINGS_ADDED")
# What a plan's residual and a report's kept list must always include: the run project, and the observer identity that
# makes the report (the owner revokes it after accepting the report).
ALWAYS_KEPT = {"PROJECT", "OBSERVER_IDENTITY"}
# The viewer roles the observer needs to list each class, as the provider defines those roles (not checked here):
# compute.viewer the compute and network classes; iam.securityReviewer buckets, service accounts, their keys and the
# project's IAM policy; logging.viewer the audit log that shows which bindings were granted since the lease started.
CLASS_ROLES = {**{name: ("roles/compute.viewer",) for name in RESOURCE_CLASSES[:14]},
               "BUCKETS": ("roles/iam.securityReviewer",), "SERVICE_ACCOUNTS": ("roles/iam.securityReviewer",),
               "SERVICE_ACCOUNT_KEYS": ("roles/iam.securityReviewer",),
               "IAM_BINDINGS_ADDED": ("roles/iam.securityReviewer", "roles/logging.viewer")}
# Free text must not carry a credential, an account identity or a billing account (design review RP1-12).
# Each shape has a negative vector of its own (review rounds 2 and 3). Every shape matches anywhere in a string; six token
# prefixes need a tail of at least four token characters.
FORBIDDEN_TEXT = (re.compile(r"@"), re.compile(r"-----BEGIN"), re.compile(r"PRIVATE KEY"), re.compile(r"AKIA[0-9A-Z]{4}"),
                  re.compile(r"ASIA[0-9A-Z]{4}"), re.compile(r"AIza[0-9A-Za-z_-]{4}"), re.compile(r"gh[pousr]_[0-9A-Za-z]{4}"),
                  re.compile(r"github_pat_"), re.compile(r"xox[abpr]-"), re.compile(r"ya29\.[0-9A-Za-z_-]{4}"),
                  re.compile(r"1//[0-9A-Za-z_-]{4}"), re.compile(r"(?i)gserviceaccount"), re.compile(r"private_key_id"),
                  re.compile(r"GOCSPX-"), re.compile(r"[0-9A-Fa-f]{6}-[0-9A-Fa-f]{6}-[0-9A-Fa-f]{6}"))


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(message)


def canonical(value: Any) -> bytes:
    """The canonical JSON bytes a plan's sha256 is taken over: sorted keys, no whitespace, UTF-8. Integral numbers are
    integers (a float with an integral value is refused), so each plan has one canonical form."""
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False).encode("utf-8")


def plan_sha256(plan: Any) -> str:
    return hashlib.sha256(canonical(plan)).hexdigest()


def strict(raw: bytes) -> Any:
    """UTF-8 JSON without a byte-order mark; duplicate keys, non-finite numbers, integral floats, oversized integers and
    lone surrogates refused."""
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
    require(not text.startswith("\ufeff"), "a document is UTF-8 without a byte-order mark")
    value = json.loads(text, object_pairs_hook=pairs, parse_constant=constant, parse_float=number, parse_int=integer)
    try:
        canonical(value)
    except UnicodeEncodeError:
        raise ValueError("a string is not valid Unicode (a lone surrogate)") from None
    return value


# The closed schema subset -------------------------------------------------------------------------------------------

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


def texts(value: Any) -> list[str]:
    """Every string value in a document."""
    if type(value) is str:
        return [value]
    if type(value) is dict:
        return [text for item in value.values() for text in texts(item)]
    if type(value) is list:
        return [text for item in value for text in texts(item)]
    return []


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


def schemas() -> dict:
    loaded = {kind: strict((ROOT / path).read_bytes()) for kind, path in SCHEMA_PATHS.items()}
    for schema in loaded.values():
        check_schema(schema)
    return loaded


def _date(text: str) -> datetime.date:
    return datetime.date.fromisoformat(text)


def _instant(text: str) -> datetime.datetime:
    return datetime.datetime.fromisoformat(text[:-1] + "+00:00")


# The run plan ------------------------------------------------------------------------------------------------------

def check_plan(plan: Any, schema: dict) -> None:
    """A run plan the owner can approve by its sha256: its shape, then the rules a schema cannot state."""
    shape(plan, schema)
    free_text(plan)
    project = plan["project"]["id"]
    require(sum(text.count(project) for text in texts(plan)) == 1, "the run project's id appears in the plan only as project.id")
    require(plan["location"]["zone"].startswith(plan["location"]["region"] + "-"), "the zone lies in the plan's region")
    prepared = _date(plan["preparedAt"])
    rate_date = _date(plan["cost"]["rateCard"]["date"])
    require(rate_date <= prepared and (prepared - rate_date).days <= RATE_CARD_MAX_AGE_DAYS,
            "the rate card is dated at most %d days before the plan" % RATE_CARD_MAX_AGE_DAYS)
    require((plan["purpose"]["packetId"] is None) == (plan["purpose"]["gate"] != "PACKET"),
            "a packet id is named exactly for a PACKET run")
    _check_cost(plan)
    _check_exposure(plan["exposure"])
    require(set(plan["observer"]["roles"]) >= {role for roles in CLASS_ROLES.values() for role in roles},
            "the observer's roles list every class the report counts")
    require(ALWAYS_KEPT <= set(plan["teardown"]["keep"]), "the residual always keeps the run project and the observer identity")


def _check_cost(plan: dict) -> None:
    """The estimate is the rate card applied to the line items; it covers every machine's hours and boot disk for the
    whole maximum duration, and it stays under the owner's ceiling (Q-RP-2)."""
    cost = plan["cost"]
    rates = {row["sku"]: row for row in cost["rateCard"]["rates"]}
    require(len(rates) == len(cost["rateCard"]["rates"]), "each rate card SKU once")
    items: dict = {}
    for item in cost["lineItems"]:
        require(item["sku"] in rates and item["unit"] == rates[item["sku"]]["unit"], "a line item uses a rate card SKU and unit")
        require(abs(item["amount"] - item["quantity"] * rates[item["sku"]]["price"]) <= CENT, "a line item's amount is its quantity at its rate")
        require(item["sku"] not in items, "each line item SKU once")
        items[item["sku"]] = item
    hours = plan["maxDurationHours"]
    needed: dict = {}
    for machine in plan["machines"]:
        needed[(machine["machineType"], "hour")] = needed.get((machine["machineType"], "hour"), 0) + machine["count"] * hours
        disk = (machine["bootDiskSku"], "gb-month")
        needed[disk] = needed.get(disk, 0) + machine["count"] * machine["bootDiskGb"] * hours / HOURS_PER_MONTH
    for (sku, unit), quantity in needed.items():
        item = items.get(sku)
        require(item is not None and item["unit"] == unit and item["quantity"] >= quantity - CENT,
                "the estimate covers every machine's hours and boot disk for the whole maximum duration")
    require(abs(cost["total"] - sum(item["amount"] for item in cost["lineItems"])) <= CENT, "the total is the sum of the line items")
    require(cost["total"] <= cost["ceiling"], "the estimate stays under the owner's ceiling")


def _check_exposure(exposure: dict) -> None:
    """No external address or ingress unless listed with its reason (Q-RP-5): in every plan the sources together cover
    at most a /16, so never the whole internet; without an external address every source is also a private network."""
    require(exposure["externalIp"] is (exposure["externalIpReason"] is not None), "an external address names its reason")
    networks = []
    for rule in exposure["ingress"]:
        try:
            networks.append(ipaddress.ip_network(rule["sourceRange"], strict=True))
        except ValueError:
            raise ValueError("an ingress source range is a network address with its prefix") from None
    if not exposure["externalIp"]:
        require(all(any(net.subnet_of(private) for private in PRIVATE_NETWORKS) for net in networks),
                "without an external address every ingress source is a private network")
    union = list(ipaddress.collapse_addresses(networks))
    require(sum(net.num_addresses for net in union) <= MAX_INGRESS_ADDRESSES,
            "the ingress sources together cover at most %d addresses" % MAX_INGRESS_ADDRESSES)


# The lease ---------------------------------------------------------------------------------------------------------

def check_lease(lease: Any, plan: dict, schema: dict) -> None:
    """The lease binds the plan's sha256 and the owner's approval, expires within the plan's maximum duration, and starts
    while the plan's rate card is still fresh (Q-RP-6)."""
    shape(lease, schema)
    free_text(lease)
    require(not any(plan["project"]["id"] in text for text in texts(lease)), "the lease does not carry the run project's id")
    require(lease["planId"] == plan["planId"] and lease["planSha256"] == plan_sha256(plan), "the lease binds this plan's sha256")
    start, expiry = _instant(lease["startsAt"]), _instant(lease["expiresAt"])
    require(start < expiry, "the lease expires after it starts")
    require((expiry - start).total_seconds() <= plan["maxDurationHours"] * 3600, "the lease lasts at most the plan's maximum duration")
    require(start.date() >= _date(plan["preparedAt"]), "the lease starts on or after the plan's preparation date")
    require((start.date() - _date(plan["cost"]["rateCard"]["date"])).days <= RATE_CARD_MAX_AGE_DAYS,
            "the lease starts at most %d days after the rate card's date" % RATE_CARD_MAX_AGE_DAYS)


# The teardown-residual report ----------------------------------------------------------------------------------------

def check_teardown(report: Any, plan: dict, lease: dict, schemas_: dict) -> None:
    """The lease is checked again; then nothing remains beyond the plan's residual in any class, the run's own observer
    saw it, the teardown finished within the lease, and the residual was observed after the lease expired, within a day."""
    check_lease(lease, plan, schemas_["lease"])
    shape(report, schemas_["teardown"])
    free_text(report)
    require(report["leaseId"] == lease["leaseId"] and report["planSha256"] == lease["planSha256"],
            "the report binds this lease and plan")
    require(report["observer"] == plan["observer"]["identity"], "the run's own observer reports")
    require(report["namePrefix"] == plan["teardown"]["namePrefix"], "the report counts the plan's run-name prefix")
    require(list(report["resources"]) == list(RESOURCE_CLASSES), "the report lists every resource class, in order")
    for name in RESOURCE_CLASSES:
        require(report["resources"][name] == 0, "no %s remains after teardown" % name)
    kept = set(report["kept"])
    require(ALWAYS_KEPT <= kept <= set(plan["teardown"]["keep"]),
            "only the plan's residual is kept, always with the run project and the observer identity")
    start, expiry = _instant(lease["startsAt"]), _instant(lease["expiresAt"])
    completed, observed = _instant(report["teardownCompletedAt"]), _instant(report["observedAt"])
    require(start <= completed <= observed, "the teardown completes within the run and before it is observed")
    require(completed <= expiry, "lease overrun: the teardown completed after the lease expired")
    require(expiry <= observed <= expiry + datetime.timedelta(days=1),
            "the residual is observed after the lease expires and within a day of it")


def explain(check: Any, *args: Any) -> str | None:
    """None when the check accepts; otherwise the refusal."""
    try:
        check(*args)
    except ValueError as exc:
        return str(exc)
    return None


# Vectors -----------------------------------------------------------------------------------------------------------

def apply_ops(value: Any, ops: list) -> Any:
    """Closed set/delete/append operations on a copy (plain keys and list indexes; append adds to the list at path)."""
    value = json.loads(json.dumps(value))
    for op in ops:
        require(type(op) is dict and op.get("op") in ("set", "delete", "append") and type(op.get("path")) is list and op["path"],
                "closed vector operation")
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


def replay(vectors: dict, loaded: dict) -> dict:
    """Every vector to its recorded result; returns the counts per kind."""
    require(set(vectors) == {"schemaVersion", "evidenceClass", "positives", "negatives", "parseNegatives"}
            and vectors["schemaVersion"] == "planeon.internal.lab-run-plan-vectors/v1"
            and vectors["evidenceClass"] == "DATA_CHECK_ONLY", "closed vectors file")
    positives = vectors["positives"]
    for index, p in enumerate(positives):
        require(set(p) == {"id", "intent", "plan", "lease", "teardown"}, "closed positive " + str(index))
        require(explain(check_plan, p["plan"], loaded["plan"]) is None, "positive plan accepted: " + p["id"])
        require(explain(check_lease, p["lease"], p["plan"], loaded["lease"]) is None, "positive lease accepted: " + p["id"])
        require(explain(check_teardown, p["teardown"], p["plan"], p["lease"], loaded) is None, "positive teardown accepted: " + p["id"])
    counts = {"positives": len(positives), "plan": 0, "lease": 0, "teardown": 0, "parse": 0}
    ids = [p["id"] for p in positives]
    for row in vectors["negatives"]:
        require(set(row) == {"id", "intent", "positive", "target", "ops", "refusal"}
                and row["target"] in ("plan", "lease", "teardown", "lease-at-teardown"), "closed negative " + str(row.get("id")))
        p = positives[row["positive"]]
        documents = {key: p[key] for key in ("plan", "lease", "teardown")}
        # A lease-at-teardown vector changes the lease and checks the report, so the teardown's re-check must refuse it.
        changed = "lease" if row["target"] == "lease-at-teardown" else row["target"]
        documents[changed] = apply_ops(documents[changed], row["ops"])
        if row["target"] == "plan":
            result = explain(check_plan, documents["plan"], loaded["plan"])
        elif row["target"] == "lease":
            result = explain(check_lease, documents["lease"], documents["plan"], loaded["lease"])
        else:
            result = explain(check_teardown, documents["teardown"], documents["plan"], documents["lease"], loaded)
        require(result is not None and result == row["refusal"], "negative vector %s: got %r" % (row["id"], result))
        counts["teardown" if row["target"] == "lease-at-teardown" else row["target"]] += 1
        ids.append(row["id"])
    for row in vectors["parseNegatives"]:
        require(set(row) == {"id", "intent", "raw", "refusal"} and type(row["raw"]) is str, "closed parse negative " + str(row.get("id")))
        result = explain(strict, row["raw"].encode("utf-8"))
        require(result is not None and result == row["refusal"], "parse vector %s: got %r" % (row["id"], result))
        counts["parse"] += 1
        ids.append(row["id"])
    require(len(ids) == len(set(ids)), "unique vector identifiers")
    return counts


def _load(path: str) -> Any:
    return strict(Path(path).read_bytes())


USAGE = "usage: lab_run_plan.py [plan PLAN | lease PLAN LEASE | teardown PLAN LEASE REPORT]"


def main(argv: list[str]) -> int:
    modes = {"plan": 2, "lease": 3, "teardown": 4}
    if argv and (argv[0] not in modes or len(argv) != modes[argv[0]]):
        print(USAGE)
        return 2
    loaded = schemas()
    if argv:
        try:
            documents = [_load(path) for path in argv[1:]]
            if argv[0] == "plan":
                check_plan(documents[0], loaded["plan"])
            elif argv[0] == "lease":
                check_plan(documents[0], loaded["plan"])
                check_lease(documents[1], documents[0], loaded["lease"])
            else:
                check_plan(documents[0], loaded["plan"])
                check_teardown(documents[2], documents[0], documents[1], loaded)
            sha = plan_sha256(documents[0])
        except (ValueError, OverflowError, RecursionError, KeyError, TypeError, OSError) as exc:
            print("refused: %s" % (exc if type(exc) is ValueError else type(exc).__name__))
            return 1
        print("accepted; plan sha256 " + sha)
        return 0
    counts = replay(strict((ROOT / VECTORS_PATH).read_bytes()), loaded)
    print("lab run-plan contract: schemas closed; %d positives (plan, lease and teardown each accepted); negatives: "
          "%d plan, %d lease, %d teardown and %d parse, each refused as recorded"
          % (counts["positives"], counts["plan"], counts["lease"], counts["teardown"], counts["parse"]))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
