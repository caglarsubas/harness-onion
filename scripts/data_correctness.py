#!/usr/bin/env python3
"""Data correctness (architecture/data-correctness/record.json, DATA-CORRECTNESS-001, MET-007): the reference model.

replay(vector) judges one vector, a recorded trace {id, family, setup, steps, expect}, against the seven rule families
of the record and returns "ACCEPT" or {"refuse": <code>}. The trace states what an implementation did (each step with
its observed outcome); the model checks the families' properties over it. Refusal codes, in the order they run, each
with its family:
- DC_WRITE_SKEW (RF-1): reservations committed beyond the units, because no covering guard (SERIALIZABLE, ROW_LOCK,
  ADVISORY_LOCK or SINGLE_WRITER) aborted a transaction whose read set changed; or a serialization-failure retry that
  reissues an external effect.
- DC_FENCE (RF-2): a fencing token that does not increase, a write accepted with a token older than the newest issued, or
  a write accepted from a holder whose lease expired.
- DC_CLOCK (RF-3): a lease still held after its monotonic duration, a wall-clock comparison without a skew margin, or an
  ordering by wall-clock time.
- DC_OPID (RF-4): a NONE effect retried, a receipt key that changes between attempts of one operation on one edge, an
  effect applied twice for one operation, edge and class, deduplication skipped on an exception path, or a claim of
  exactly-once delivery.
- DC_VERSION (RF-5): a reader that refuses the previous or the current version during a rollout, a stored envelope that
  drops opaque extension data, or a migration without its reader-writer pairs and rollback.
- DC_DERIVED (RF-6): a deletion that misses a derived store or has no receipt, or a rebuild-and-compare audit that finds
  drift and does not report it.
- DC_REPLAY_STATE (RF-7): a replay that consults durable state it did not take as an input beside the log.
A vector's first failing family, in that order, names its code. A malformed vector raises ValueError (it is not a code).

durable_writers(read, packets) is the model's one catalog read: the effective services catalog through
sector_catalog.effective_bytes_from(read, packets, "architecture/services.yaml"), giving each durable writer's id, state
mode and {name, ownership} stores in the catalog's order (STATEFUL, or STATELESS with durableState true); the checker's
DC_ROWS compares the record against it. That function imports sector_catalog (and through it the repository's safe
loader) inside its body; replay uses the standard library only. The model records and models; it enforces nothing.
"""
from __future__ import annotations

import json

SERVICES_CATALOG = "architecture/services.yaml"
MODEL_CODES = ("DC_WRITE_SKEW", "DC_FENCE", "DC_CLOCK", "DC_OPID", "DC_VERSION", "DC_DERIVED", "DC_REPLAY_STATE")
FAMILIES = ("RF-1", "RF-2", "RF-3", "RF-4", "RF-5", "RF-6", "RF-7")
FAMILY_OF_CODE = dict(zip(MODEL_CODES, FAMILIES))
COVERING_GUARDS = ("SERIALIZABLE", "ROW_LOCK", "ADVISORY_LOCK", "SINGLE_WRITER")
OTHER_GUARDS = ("NONE", "APPEND_ONLY")
OPS = {
    "RF-1": ("begin", "reserve", "commit", "effect"),
    "RF-2": ("acquire", "expire", "write"),
    "RF-3": ("lease_start", "wall_jump", "lease_check", "wall_compare", "order"),
    "RF-4": ("call", "claim"),
    "RF-5": ("read_record", "store_envelope", "migrate", "public_input"),
    "RF-6": ("insert", "delete", "rebuild_compare"),
    "RF-7": ("replay",),
}
FAMILY_OF_OP = {op: fam for fam, ops in OPS.items() for op in ops}
VECTOR_MEMBERS = ("id", "family", "setup", "steps", "expect")


def _need(ok, message):
    if not ok:
        raise ValueError(message)


def _int(value, message):
    _need(type(value) is int, message)
    return value


def _check_shape(vector):
    _need(type(vector) is dict and set(vector) == set(VECTOR_MEMBERS), "a vector is exactly {id, family, setup, steps, expect}")
    _need(type(vector["id"]) is str and vector["id"], "a vector id is a non-empty string")
    _need(vector["family"] in FAMILIES, "a vector's family is RF-1 to RF-7")
    _need(type(vector["setup"]) is dict and type(vector["steps"]) is list and vector["steps"], "setup is an object, steps a list")
    expect = vector["expect"]
    _need(expect == "ACCEPT" or (type(expect) is dict and tuple(expect) == ("refuse",) and expect["refuse"] in MODEL_CODES),
          "expect is ACCEPT or {refuse: <model code>}")
    for step in vector["steps"]:
        _need(type(step) is dict and step.get("op") in FAMILY_OF_OP, "every step names a known op")
        _need(FAMILY_OF_OP[step["op"]] == vector["family"], "a step's op belongs to the vector's family")


def _steps(vector, family):
    return [s for s in vector["steps"] if FAMILY_OF_OP[s["op"]] == family]


def _write_skew(setup, steps):
    if not steps:
        return False
    units = _int(setup.get("units"), "RF-1 setup names its units")
    guard = setup.get("guard")
    _need(guard in COVERING_GUARDS + OTHER_GUARDS, "RF-1 setup names a guard")
    committed, commits, tx, effects = 0, 0, {}, []
    for s in steps:
        name = s.get("tx")
        _need(type(name) is str and (s["op"] == "begin" or name in tx), "a step names a begun transaction")
        if s["op"] == "begin":
            tx[name] = {"snapshot": units - committed, "seen": commits, "reserved": 0, "aborted": False}
        elif s["op"] == "reserve":
            t = tx[name]
            n = _int(s.get("units"), "a reservation names its units")
            _need(0 < n <= t["snapshot"] - t["reserved"], "a reservation within the transaction's snapshot")
            t["reserved"] += n
        elif s["op"] == "commit":
            t = tx[name]
            if guard in COVERING_GUARDS and t["reserved"] and commits != t["seen"]:
                t["aborted"] = True  # a serialization failure: the read set changed under the guard
            else:
                committed += t["reserved"]
                commits += 1
        else:
            effects.append((name, s.get("key")))
    for key in {k for _, k in effects}:
        issuers = [n for n, k in effects if k == key]
        if len(issuers) > 1 and any(tx[n]["aborted"] for n in issuers[:-1]):
            return True  # a serialization-failure retry reissued an external effect
    return committed > units


def _fence(setup, steps):
    newest, expired, violated = None, set(), False
    for s in steps:
        holder = s.get("holder")
        _need(type(holder) is str and holder != "", "an RF-2 step names its holder")
        if s["op"] == "acquire":
            token = _int(s.get("token"), "a lease grant names its token")
            if newest is not None and token <= newest:
                return True
            newest = token
            expired.discard(holder)
        elif s["op"] == "expire":
            expired.add(holder)
        elif s["op"] == "write" and s.get("accepted") is True:
            token = _int(s.get("token"), "a write names its token")
            if holder in expired or (newest is not None and token < newest):
                violated = True
    return violated


def _clock(setup, steps):
    start = None
    for s in steps:
        if s["op"] == "lease_start":
            start = (_int(s.get("monotonicMs"), "a lease start names its monotonic time"),
                     _int(s.get("leaseMs"), "a lease start names its duration"))
        elif s["op"] == "lease_check":
            _need(start is not None, "a lease check after its start")
            if s.get("held") is True and _int(s.get("monotonicMs"), "a check names its monotonic time") - start[0] > start[1]:
                return True
        elif s["op"] == "wall_compare":
            if s.get("skewMarginMs") is None:
                return True
        elif s["op"] == "order":
            _need(s.get("by") in ("sequence", "fencing_token", "wall"), "an ordering names its key")
            if s["by"] == "wall":
                return True
    return False


def _opid(setup, steps):
    keys, applied = {}, {}
    for s in steps:
        if s["op"] == "claim":
            if s.get("exactlyOnce") is True:
                return True
            continue
        cls = s.get("class")
        _need(cls in ("NATIVE", "NONE", "RECEIPT_KEY"), "a call names its idempotency class")
        op, edge = s.get("operation"), s.get("edge")
        _need(type(op) is str and type(edge) is str, "a call names its operation ID and its edge")
        attempt = _int(s.get("attempt"), "a call names its attempt")
        if s.get("path") == "exception" and s.get("dedup") is False:
            return True
        if cls == "NONE" and attempt > 1:
            return True
        if cls == "RECEIPT_KEY":
            _need(type(s.get("key")) is str, "a RECEIPT_KEY call names its key")
            if keys.setdefault((op, edge), s["key"]) != s["key"]:
                return True
        if s.get("applied") is True:
            applied[(op, edge, cls)] = applied.get((op, edge, cls), 0) + 1
            if applied[(op, edge, cls)] > 1:
                return True
    return False


def _version(setup, steps):
    for s in steps:
        if s["op"] == "read_record":
            _need(s.get("recordVersion") in ("N-1", "N") and s.get("reader") in ("N-1", "N"), "a read names both versions")
            if s.get("rollout") is True and s.get("accepted") is not True:
                return True
        elif s["op"] == "store_envelope":
            if s.get("extensionKept") is not True:
                return True
        elif s["op"] == "migrate":
            if s.get("readerWriterPairs") is not True or s.get("rollback") is not True:
                return True
    return False  # public_input may reject unknown fields and versions


def _derived(setup, steps):
    derived = setup.get("derived")
    for s in steps:
        if s["op"] == "delete":
            _need(type(derived) is list and derived, "RF-6 setup names its derived stores")
            if sorted(s.get("propagatedTo") or []) != sorted(derived) or s.get("receipt") is not True:
                return True
        elif s["op"] == "rebuild_compare":
            if s.get("driftFound") is True and s.get("reported") is not True:
                return True
    return False


def _replay_state(setup, steps):
    for s in steps:
        inputs, consulted = s.get("inputs"), s.get("consulted")
        _need(type(inputs) is list and type(consulted) is list, "a replay names its inputs and the state it consults")
        if set(consulted) - set(inputs):
            return True
    return False


RULES = (_write_skew, _fence, _clock, _opid, _version, _derived, _replay_state)


def replay(vector):
    """The vector's outcome: "ACCEPT", or {"refuse": code} for the first failing family in run order."""
    _check_shape(vector)
    for code, family, rule in zip(MODEL_CODES, FAMILIES, RULES):
        if rule(vector["setup"], _steps(vector, family)):
            return {"refuse": code}
    return "ACCEPT"


def replay_bytes(raw: bytes):
    """replay over a vector file's bytes (UTF-8 JSON, duplicate members refused)."""
    def pairs(items):
        keys = [k for k, _ in items]
        _need(len(keys) == len(set(keys)), "duplicate member in a vector")
        return dict(items)
    return replay(json.loads(raw.decode("utf-8"), object_pairs_hook=pairs))


def durable_writers(read, packets):
    """The durable writers of the effective services catalog, in its order: [{id, stateMode, stores}]."""
    try:
        from sector_catalog import effective_bytes_from
        from safe_yaml import safe_load
    except ImportError:
        from scripts.sector_catalog import effective_bytes_from
        from scripts.safe_yaml import safe_load
    catalog = safe_load(effective_bytes_from(read, packets, SERVICES_CATALOG).decode("utf-8"))
    rows = []
    for service in catalog["services"]:
        behaviour = service["stateBehavior"]
        if behaviour["mode"] == "STATEFUL" or behaviour.get("durableState") is True:
            rows.append({"id": service["id"],
                         "stateMode": "STATEFUL" if behaviour["mode"] == "STATEFUL" else "STATELESS_DURABLE",
                         "stores": [{"name": s["name"], "ownership": s["ownership"]} for s in service["stores"]]})
    return rows
