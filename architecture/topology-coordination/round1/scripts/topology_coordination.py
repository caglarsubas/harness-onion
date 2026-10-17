#!/usr/bin/env python3
"""Topology and coordination v1 (architecture/topology-coordination/, MAS-RA-004): reference model, DATA_CHECK_ONLY.

Two closed, content-addressed record kinds, each checked by one function that raises `Refused(code)` on the first rule it
breaks (whole-record passes in the order of TOPOLOGY_CODES / TRANSCRIPT_CODES) and otherwise returns derived facts:
- a TopologySpec: the agents of one task as a closed graph of nodes (each with a role) and DELEGATE / MESSAGE edges, one
  AgentSpec per role (objective, model reference, budgets), the coordination mode, its lease and deadline, the agent
  budget and the declared selection. The model derives the MASS-style role-block vector [#COORDINATOR, #WORKER,
  #VERIFIER] (owner decision Q-M4-2 (a)); the budget and the selection rule apply to it;
- a board transcript: the operations a coordinator board answered for one topology (acquire, assign, renew, release,
  verify, merge, message), each with the answer recorded. The model replays them on exclusive leased claims (Q-M4-3 (a):
  compare-and-swap on one record per item, conflicting acquires refused, an expired lease reclaimable, deterministic
  arbitration) and must reach every recorded answer; a merge needs a PASS verdict from a different agent context,
  recorded as a MAS-RA-001 verdict ledger (Q-M4-9 (a)). It also derives the run-events v1 points of the transcript and
  the steps v1 cannot represent (Q-M4-4 (a)).

The selection rule (Q-M4-5 (a)): the topology declares the task shape and cites a MAS-RA-002 evaluation record of a
single-agent configuration; its exact score is the baseline. A SEQUENTIAL or TOOL_HEAVY task, or a baseline at or above
SELECTION_THRESHOLD, may only be SINGLE_AGENT or ORCHESTRATOR_WORKER (a central coordinator with at most 4 workers);
otherwise SELF_ORGANIZING (the decentralized board) is also allowed. SELECTION_THRESHOLD is a named parameter, 45/100: the
only published figure is the abstract of Kim et al.'s first version (the later version drops the number), so it is a
secondary source, replaceable by MAS-RA-010's measurements.

Standard library only. The checks take the MAS-RA-002 model (`scripts/run_manifest.py`, argument `runs`) and the MAS-RA-001
model (`scripts/verdict_ledger.py`, argument `ledgers`, with its check-kinds record `kinds`), so a caller decides which
bytes of them run (the layer runs its era's).
"""
from __future__ import annotations

import hashlib
import json
import math
import re

TOPOLOGY_SCHEMA = "planeon.internal.topology-spec/v1"
TRANSCRIPT_SCHEMA = "planeon.internal.board-transcript/v1"
MAX_ITEMS = 65536
MAX_INT = 2 ** 53 - 1
ROLES = ("COORDINATOR", "WORKER", "VERIFIER")  # the fixed block order of the role-block vector
MODES = ("SINGLE_AGENT", "CENTRAL", "DECENTRALIZED")
EDGE_KINDS = ("DELEGATE", "MESSAGE")
ASSIGNMENT = {"SINGLE_AGENT": "NONE", "CENTRAL": "COORDINATOR_ASSIGNS", "DECENTRALIZED": "CLAIM_FROM_BOARD"}
ARBITRATION = "EARLIEST_THEN_NODE_ID"
TASK_SHAPES = ("SEQUENTIAL", "TOOL_HEAVY", "DECOMPOSABLE")
OUTCOMES = ("SINGLE_AGENT", "ORCHESTRATOR_WORKER", "SELF_ORGANIZING")
OUTCOME_MODE = {"SINGLE_AGENT": "SINGLE_AGENT", "ORCHESTRATOR_WORKER": "CENTRAL", "SELF_ORGANIZING": "DECENTRALIZED"}
SELECTION_THRESHOLD = (45, 100)  # named parameter (Q-M4-5 (a)); Kim et al. v1 abstract, secondary; see the README
MAX_ORCHESTRATED_WORKERS = 4
OPS = ("ACQUIRE", "ASSIGN", "RENEW", "RELEASE", "VERIFY", "MERGE", "MESSAGE")
MESSAGE_TYPES = ("INTERFACE", "DEPENDENCY", "BEHAVIOR", "TEST", "CONFIGURATION")
REQUIRED_ACTIONS = ("NONE", "ACKNOWLEDGE", "CHANGE")
RESULTS = ("ACCEPTED", "DEADLINE", "NOT_PERMITTED", "MERGED", "HELD", "NOT_HELD", "NOT_HOLDER", "STALE_VERSION",
           "CONCURRENCY_LIMIT", "SELF_VERIFICATION", "LEDGER_MISMATCH", "NO_VERDICT", "VERDICT_NOT_PASS", "OFF_EDGE")
TOPOLOGY_CODES = ("SHAPE", "DUPLICATE_ID", "UNKNOWN_REFERENCE", "CONFLICTING_OBJECTIVE", "MODE_STRUCTURE", "BUDGET",
                  "SELECTION")
TRANSCRIPT_CODES = ("SHAPE", "DUPLICATE_ID", "UNKNOWN_REFERENCE", "MODE", "RETRY", "REPLAY")
DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")
IDENT = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}\Z")


class Refused(ValueError):
    """A record breaks a rule; `code` is one of TOPOLOGY_CODES or TRANSCRIPT_CODES."""

    def __init__(self, code: str):
        super().__init__(code)
        self.code = code


def _refuse(ok: bool, code: str) -> None:
    if not ok:
        raise Refused(code)


# ---------------------------------------------------------------- canonical form and text (as MAS-RA-001, -002, -003)

def _integral(value) -> bool:
    if type(value) is int:
        return abs(value) <= MAX_INT
    return type(value) is float and math.isfinite(value) and value.is_integer() and abs(value) <= MAX_INT


def _normal(value):
    if type(value) is float:
        _refuse(_integral(value), "SHAPE")
        return int(value)
    if type(value) is list:
        return [_normal(v) for v in value]
    if type(value) is dict:
        return {k: _normal(v) for k, v in value.items()}
    return value


def canonical(value) -> bytes:
    """RFC 8785 (JCS) bytes of a record: keys sorted, no whitespace, UTF-8, integers without a fraction."""
    return json.dumps(_normal(value), sort_keys=True, ensure_ascii=False, separators=(",", ":"),
                      allow_nan=False).encode("utf-8")


def digest(value) -> str:
    return "sha256:" + hashlib.sha256(canonical(value)).hexdigest()


def _no_constant(name):
    raise Refused("SHAPE")


def _members(pairs):
    names = [name for name, _ in pairs]
    _refuse(len(names) == len(set(names)), "SHAPE")
    return dict(pairs)


def _encodable(value) -> None:
    stack = [value]
    while stack:
        item = stack.pop()
        if type(item) is str:
            item.encode("utf-8")
        elif type(item) is list:
            stack.extend(item)
        elif type(item) is dict:
            stack.extend(item)
            stack.extend(item.values())


def parse(text):
    """Record text as I-JSON (RFC 7493): UTF-8, no duplicate member names, no NaN or infinity, no lone surrogate (also not
    escaped); anything else is SHAPE."""
    try:
        if isinstance(text, (bytes, bytearray)):
            text = bytes(text).decode("utf-8")
        text.encode("utf-8")
        value = json.loads(text, object_pairs_hook=_members, parse_constant=_no_constant)
        _encodable(value)
        return value
    except Refused:
        raise
    except (ValueError, TypeError, RecursionError) as exc:
        raise Refused("SHAPE") from exc


# ---------------------------------------------------------------- shape helpers

def _ident(value) -> bool:
    return type(value) is str and IDENT.match(value) is not None


def _digest_str(value) -> bool:
    return type(value) is str and DIGEST.match(value) is not None


def _int(value, low: int, high: int) -> bool:
    return _integral(value) and low <= value <= high


def _closed(value, keys, optional=()) -> bool:
    return type(value) is dict and set(keys) <= set(value) <= set(keys) | set(optional)


def _list(value, low: int = 0, high: int = MAX_ITEMS) -> bool:
    return type(value) is list and low <= len(value) <= high


def _guarded(check):
    """Run one record check; anything malformed that slipped past the shape rules is SHAPE, never another exception."""
    try:
        return check()
    except Refused:
        raise
    except (KeyError, TypeError, AttributeError, IndexError, ValueError, UnicodeError, RecursionError) as exc:
        raise Refused("SHAPE") from exc


def _stored(stores, store: str, key):
    """The record stored under `key` in `stores[store]`, only if it hashes to `key` (content addressing); else None."""
    records = stores.get(store) if type(stores) is dict else None
    if type(records) is not dict or key not in records:
        return None
    try:
        return records[key] if digest(records[key]) == key else None
    except (Refused, TypeError, ValueError, RecursionError):
        return None


# ---------------------------------------------------------------- the selection rule (Q-M4-5 (a))

def at_or_above(score, threshold=SELECTION_THRESHOLD) -> bool:
    """score >= threshold for exact non-negative rationals (numerator, denominator > 0)."""
    return score[0] * threshold[1] >= threshold[0] * score[1]


def allowed_outcomes(task_shape: str, score) -> tuple:
    """The outcomes the declared task shape and the single-agent baseline allow."""
    restricted = task_shape in ("SEQUENTIAL", "TOOL_HEAVY") or at_or_above(score)
    return ("SINGLE_AGENT", "ORCHESTRATOR_WORKER") if restricted else OUTCOMES


# ---------------------------------------------------------------- TopologySpec

TOPOLOGY_KEYS = ("schemaVersion", "topologyId", "objectiveId", "mode", "agents", "nodes", "edges", "assignmentPolicy",
                 "arbitrationPolicy", "concurrency", "leaseSeconds", "deadlineSeconds", "agentBudget", "selection")
AGENT_KEYS = ("role", "objectiveId", "modelRef", "budgets")
BUDGET_KEYS = ("tokens", "iterations", "wallClockSeconds", "recursionDepth")


def _topology_shape(doc) -> None:
    _refuse(_closed(doc, TOPOLOGY_KEYS) and doc["schemaVersion"] == TOPOLOGY_SCHEMA and _ident(doc["topologyId"])
            and _ident(doc["objectiveId"]) and doc["mode"] in MODES and _list(doc["agents"], 1, len(ROLES))
            and _list(doc["nodes"], 1, 1024) and _list(doc["edges"]) and doc["assignmentPolicy"] in set(ASSIGNMENT.values())
            and doc["arbitrationPolicy"] == ARBITRATION and _int(doc["concurrency"], 1, 1024)
            and _int(doc["leaseSeconds"], 1, 86400) and _int(doc["deadlineSeconds"], 1, 2592000)
            and _int(doc["agentBudget"], 1, 1024)
            and _closed(doc["selection"], ("taskShape", "baselineRecordDigest", "outcome"))
            and doc["selection"]["taskShape"] in TASK_SHAPES and _digest_str(doc["selection"]["baselineRecordDigest"])
            and doc["selection"]["outcome"] in OUTCOMES, "SHAPE")
    for a in doc["agents"]:
        _refuse(_closed(a, AGENT_KEYS) and a["role"] in ROLES and _ident(a["objectiveId"])
                and _closed(a["modelRef"], ("backboneId", "configurationDigest")) and _ident(a["modelRef"]["backboneId"])
                and _digest_str(a["modelRef"]["configurationDigest"]) and _closed(a["budgets"], BUDGET_KEYS)
                and _int(a["budgets"]["tokens"], 1, MAX_INT) and _int(a["budgets"]["iterations"], 1, 1000000)
                and _int(a["budgets"]["wallClockSeconds"], 1, 2592000) and _int(a["budgets"]["recursionDepth"], 0, 1),
                "SHAPE")
    for n in doc["nodes"]:
        _refuse(_closed(n, ("nodeId", "role")) and _ident(n["nodeId"]) and n["role"] in ROLES, "SHAPE")
    for e in doc["edges"]:
        _refuse(_closed(e, ("from", "to", "kind")) and _ident(e["from"]) and _ident(e["to"]) and e["kind"] in EDGE_KINDS,
                "SHAPE")


def block_vector(doc) -> list:
    """The MASS-style role-block vector: how many nodes hold each role, in the fixed order of ROLES."""
    return [sum(1 for n in doc["nodes"] if n["role"] == role) for role in ROLES]


def baseline_score(record_digest: str, stores: dict, runs) -> tuple:
    """The single-agent baseline of a MAS-RA-002 evaluation record, as an exact rational: the sum of every score over
    tasks x runs x MAX_SCORE, in lowest terms. None if the record is missing, does not hash to its digest or is refused by MAS-RA-002's
    model; refusal-free records that are incomplete or not single-agent return (None, reason)."""
    record = _stored(stores, "records", record_digest)
    if record is None:
        return None
    try:
        facts = runs.check_record(record, stores.get("manifests", {}), stores.get("splits", {}))
    except runs.Refused:
        return None
    if facts["digest"] != record_digest:
        return None
    if not facts["complete"] or record["configuration"]["agentCount"] != 1:
        return ("NOT_SINGLE_AGENT_COMPLETE", None)
    total, scale = sum(facts["sums"].values()), len(facts["tasks"]) * facts["runs"] * runs.MAX_SCORE
    common = math.gcd(total, scale)
    return ("OK", (total // common, scale // common))


def check_topology(doc: dict, stores: dict, runs) -> dict:
    """Refuse a TopologySpec that breaks a rule (first failing code in TOPOLOGY_CODES); otherwise return its derived facts:
    its digest, the role-block vector, the baseline score, the allowed outcomes and the worker count."""
    def run():
        _topology_shape(doc)
        nodes = {n["nodeId"]: n["role"] for n in doc["nodes"]}
        _refuse(len(nodes) == len(doc["nodes"]) and len({a["role"] for a in doc["agents"]}) == len(doc["agents"])
                and len({(e["from"], e["to"], e["kind"]) for e in doc["edges"]}) == len(doc["edges"]), "DUPLICATE_ID")
        roles = {a["role"]: a for a in doc["agents"]}
        baseline = baseline_score(doc["selection"]["baselineRecordDigest"], stores, runs)
        _refuse(set(nodes.values()) == set(roles) and all(e["from"] in nodes and e["to"] in nodes for e in doc["edges"])
                and baseline is not None, "UNKNOWN_REFERENCE")
        _refuse(all(a["objectiveId"] == doc["objectiveId"] for a in doc["agents"]), "CONFLICTING_OBJECTIVE")
        vector = block_vector(doc)
        coordinators, workers, verifiers = vector
        mode = doc["mode"]
        delegate = {(e["from"], e["to"]) for e in doc["edges"] if e["kind"] == "DELEGATE"}
        structure = (all(e["from"] != e["to"] for e in doc["edges"]) and doc["assignmentPolicy"] == ASSIGNMENT[mode]
                     and all(a["budgets"]["recursionDepth"] == (1 if a["role"] == "COORDINATOR" else 0)
                             for a in doc["agents"]))
        if mode == "SINGLE_AGENT":
            structure = structure and vector == [0, 1, 0] and not doc["edges"] and doc["concurrency"] == 1
        elif mode == "CENTRAL":
            coordinator = [n for n, r in nodes.items() if r == "COORDINATOR"]
            structure = (structure and coordinators == 1 and workers >= 1
                         and delegate == {(coordinator[0], n) for n, r in nodes.items() if r != "COORDINATOR"})
        else:
            structure = structure and coordinators == 0 and workers >= 2 and not delegate
        _refuse(structure, "MODE_STRUCTURE")
        _refuse(sum(vector) <= doc["agentBudget"] and doc["concurrency"] <= workers, "BUDGET")
        status, score = baseline
        outcome = doc["selection"]["outcome"]
        allowed = allowed_outcomes(doc["selection"]["taskShape"], score) if status == "OK" else ()
        _refuse(status == "OK" and outcome in allowed and OUTCOME_MODE[outcome] == mode
                and (outcome != "ORCHESTRATOR_WORKER" or workers <= MAX_ORCHESTRATED_WORKERS), "SELECTION")
        return {"digest": digest(doc), "blockVector": vector, "baselineScore": list(score),
                "allowedOutcomes": list(allowed), "workers": workers, "verifiers": verifiers}
    return _guarded(run)


def check_run_binding(topology: dict, manifest: dict, stores: dict, runs) -> dict:
    """A MAS-RA-002 run manifest that reports a run of this topology: the topology is valid, the manifest is valid under
    MAS-RA-002's model, and its agentCount does not exceed the topology's agentBudget (Q-M4-6 (a)); else BUDGET."""
    facts = check_topology(topology, stores, runs)
    try:
        runs.check_manifest(manifest, stores.get("splits", {}))
    except runs.Refused as exc:
        raise Refused("UNKNOWN_REFERENCE") from exc
    _refuse(manifest["configuration"]["agentCount"] <= topology["agentBudget"], "BUDGET")
    return {"topologyDigest": facts["digest"], "agentCount": manifest["configuration"]["agentCount"]}


# ---------------------------------------------------------------- board transcript

TRANSCRIPT_KEYS = ("schemaVersion", "transcriptId", "topologyDigest", "items", "operations")
OP_KEYS = {"ACQUIRE": ("item", "expectedVersion"), "ASSIGN": ("item", "worker", "expectedVersion"),
           "RENEW": ("item", "expectedVersion"), "RELEASE": ("item", "expectedVersion"), "VERIFY": ("item", "verdict"),
           "MERGE": ("item", "expectedVersion"), "MESSAGE": ("message",)}
COMMON_KEYS = ("opId", "t", "agent", "op", "result")


def _op_shape(o) -> bool:
    if type(o) is not dict or o.get("op") not in OPS:
        return False
    extra = OP_KEYS[o["op"]]
    ok = (_closed(o, COMMON_KEYS + extra, ("retryOf",)) and _ident(o["opId"]) and _int(o["t"], 0, MAX_INT)
          and _ident(o["agent"]) and o["result"] in RESULTS and ("retryOf" not in o or _ident(o["retryOf"])))
    if "item" in extra:
        ok = ok and _ident(o["item"])
    if "worker" in extra:
        ok = ok and _ident(o["worker"])
    if "expectedVersion" in extra:
        ok = ok and _int(o["expectedVersion"], 0, MAX_INT)
    if "verdict" in extra:
        ok = ok and _closed(o["verdict"], ("ledgerDigest",)) and _digest_str(o["verdict"]["ledgerDigest"])
    if "message" in extra:
        m = o["message"]
        ok = ok and _closed(m, ("to", "messageType", "requiredAction")) and _ident(m["to"]) \
            and m["messageType"] in MESSAGE_TYPES and m["requiredAction"] in REQUIRED_ACTIONS
    return ok


def _body(o) -> dict:
    """What an operation asks for: everything but its own id, time, recorded answer and retry link."""
    return {k: v for k, v in o.items() if k not in ("opId", "t", "result", "retryOf")}


def _ledger_contexts(ledger: dict) -> dict:
    return {c["contextId"]: c["role"] for c in ledger["contexts"]}


class _Board:
    """One record per item: state OPEN | HELD | MERGED, holder, leaseUntil, version, the accepted claim that holds it and
    the verdicts bound to that claim."""

    def __init__(self, topology: dict, items: list):
        self.topology = topology
        self.roles = {n["nodeId"]: n["role"] for n in topology["nodes"]}
        self.edges = {(e["from"], e["to"], e["kind"]) for e in topology["edges"]}
        self.records = {i: {"state": "OPEN", "holder": None, "leaseUntil": None, "version": 0, "claim": None,
                            "verdicts": []} for i in items}
        self.expiries = []

    def expire(self, t: int) -> None:
        due = sorted((r["leaseUntil"], item) for item, r in self.records.items()
                     if r["state"] == "HELD" and r["leaseUntil"] <= t)
        for at, item in due:
            r = self.records[item]
            self.expiries.append({"item": item, "at": at, "holder": r["holder"], "claim": r["claim"]})
            r.update(state="OPEN", holder=None, leaseUntil=None, version=r["version"] + 1, claim=None, verdicts=[])

    def held(self) -> int:
        return sum(1 for r in self.records.values() if r["state"] == "HELD")

    def apply(self, o: dict, ledger_facts) -> str:
        """The board's answer to one operation, applying it when ACCEPTED (leases due by its time have already expired).
        Refusal precedence: DEADLINE, permission, state, version, then the operation's own conditions."""
        topo, t, agent, op = self.topology, o["t"], o["agent"], o["op"]
        if t > topo["deadlineSeconds"]:
            return "DEADLINE"
        if op == "MESSAGE":
            return "ACCEPTED" if (agent, o["message"]["to"], "MESSAGE") in self.edges else "OFF_EDGE"
        r = self.records[o["item"]]
        if op in ("ACQUIRE", "ASSIGN"):
            if op == "ACQUIRE":
                if topo["mode"] != "DECENTRALIZED" or self.roles[agent] != "WORKER":
                    return "NOT_PERMITTED"
                holder = agent
            else:
                holder = o["worker"]
                if (topo["mode"] != "CENTRAL" or self.roles[agent] != "COORDINATOR" or self.roles[holder] != "WORKER"
                        or (agent, holder, "DELEGATE") not in self.edges):
                    return "NOT_PERMITTED"
            if r["state"] != "OPEN":
                return r["state"]  # MERGED or HELD
            if o["expectedVersion"] != r["version"]:
                return "STALE_VERSION"
            if self.held() >= topo["concurrency"]:
                return "CONCURRENCY_LIMIT"
            r.update(state="HELD", holder=holder, leaseUntil=t + topo["leaseSeconds"], version=r["version"] + 1,
                     claim=o["opId"], verdicts=[])
            return "ACCEPTED"
        if op in ("RENEW", "RELEASE", "MERGE"):
            coordinator_release = op == "RELEASE" and topo["mode"] == "CENTRAL" and self.roles[agent] == "COORDINATOR"
            if r["state"] != "HELD" or (r["holder"] != agent and not coordinator_release):
                return "NOT_HOLDER"
            if o["expectedVersion"] != r["version"]:
                return "STALE_VERSION"
            if op == "RENEW":
                r.update(leaseUntil=t + topo["leaseSeconds"], version=r["version"] + 1)
            elif op == "RELEASE":
                r.update(state="OPEN", holder=None, leaseUntil=None, version=r["version"] + 1, claim=None, verdicts=[])
            else:
                if not r["verdicts"]:
                    return "NO_VERDICT"
                if r["verdicts"][-1]["status"] != "PASS":
                    return "VERDICT_NOT_PASS"
                r.update(state="MERGED", leaseUntil=None, version=r["version"] + 1)
            return "ACCEPTED"
        # VERIFY: any node but the holder; the ledger must name this node as its VERIFIER and the holder as its GENERATOR.
        if r["state"] != "HELD":
            return "NOT_HELD"
        if agent == r["holder"]:
            return "SELF_VERIFICATION"
        contexts, status = ledger_facts
        if contexts.get(agent) != "VERIFIER" or contexts.get(r["holder"]) != "GENERATOR":
            return "LEDGER_MISMATCH"
        r["verdicts"].append({"verifier": agent, "ledgerDigest": o["verdict"]["ledgerDigest"], "status": status})
        return "ACCEPTED"


def check_transcript(doc: dict, stores: dict, runs, ledgers, kinds: dict) -> dict:
    """Refuse a board transcript that breaks a rule (first failing code in TRANSCRIPT_CODES); otherwise return its derived
    facts: the digest, each operation's answer, the final board, the run-events v1 points and the steps v1 cannot
    represent. Operations are applied in (t, agent, opId) order (deterministic arbitration), whatever their order in the
    transcript; an operation with `retryOf` repeats an earlier operation's body, gets its answer and changes nothing."""
    def run():
        _refuse(_closed(doc, TRANSCRIPT_KEYS) and doc["schemaVersion"] == TRANSCRIPT_SCHEMA
                and _ident(doc["transcriptId"]) and _digest_str(doc["topologyDigest"]) and _list(doc["items"], 1)
                and all(_ident(i) for i in doc["items"]) and _list(doc["operations"])
                and all(_op_shape(o) for o in doc["operations"]), "SHAPE")
        ops = doc["operations"]
        _refuse(len({o["opId"] for o in ops}) == len(ops) and len(set(doc["items"])) == len(doc["items"]), "DUPLICATE_ID")
        topology = _stored(stores, "topologies", doc["topologyDigest"])
        _refuse(topology is not None, "UNKNOWN_REFERENCE")
        try:
            check_topology(topology, stores, runs)
        except Refused as exc:
            raise Refused("UNKNOWN_REFERENCE") from exc
        nodes = {n["nodeId"] for n in topology["nodes"]}
        by_id = {o["opId"]: o for o in ops}
        verdicts = {}
        for o in ops:
            _refuse(o["agent"] in nodes and ("item" not in o or o["item"] in doc["items"])
                    and ("worker" not in o or o["worker"] in nodes)
                    and ("message" not in o or o["message"]["to"] in nodes)
                    and ("retryOf" not in o or o["retryOf"] in by_id), "UNKNOWN_REFERENCE")
            if "verdict" in o:
                key = o["verdict"]["ledgerDigest"]
                ledger = _stored(stores, "ledgers", key)
                _refuse(ledger is not None, "UNKNOWN_REFERENCE")
                try:
                    facts = ledgers.check_ledger(ledger, kinds)
                except ledgers.Refused as exc:
                    raise Refused("UNKNOWN_REFERENCE") from exc
                _refuse(facts["ledgerDigest"] == key, "UNKNOWN_REFERENCE")
                verdicts[key] = (_ledger_contexts(ledger), facts["status"])
        _refuse(topology["mode"] != "SINGLE_AGENT", "MODE")
        order = sorted(ops, key=lambda o: (o["t"], o["agent"], o["opId"]))
        rank = {o["opId"]: i for i, o in enumerate(order)}
        for o in ops:
            if "retryOf" in o:
                first = by_id[o["retryOf"]]
                _refuse(rank[first["opId"]] < rank[o["opId"]] and "retryOf" not in first and _body(first) == _body(o),
                        "RETRY")
        board = _Board(topology, doc["items"])
        answers, mapping, gaps, claims = {}, [], [], {}
        for o in order:
            expired = len(board.expiries)
            if o["t"] <= topology["deadlineSeconds"]:
                board.expire(o["t"])  # leases end with time, whatever the operation
            if "retryOf" in o:
                answer = answers[o["retryOf"]]
            else:
                answer = board.apply(o, verdicts.get(o.get("verdict", {}).get("ledgerDigest")))
            for x in board.expiries[expired:]:
                gaps.append({"step": "EXPIRY", "item": x["item"], "at": x["at"], "claim": x["claim"]})
            _refuse(answer == o["result"], "REPLAY")
            answers[o["opId"]] = answer
            if "retryOf" in o:
                gaps.append({"step": "RETRY", "opId": o["opId"], "retryOf": o["retryOf"]})
            elif answer != "ACCEPTED":
                gaps.append({"step": "REFUSED", "opId": o["opId"], "op": o["op"], "result": answer})
            elif o["op"] in ("ACQUIRE", "ASSIGN"):
                holder = o["agent"] if o["op"] == "ACQUIRE" else o["worker"]
                earlier = [c for c in claims.get(o["item"], []) if c["agent"] != holder]
                mapping.append({"operation": "CLAIM", "agentId": holder,
                                "attributes": {"claimId": o["opId"], "taskDigest": digest({"item": o["item"]}),
                                               "conflictsWith": earlier[-1]["claimId"] if earlier else None}})
                claims.setdefault(o["item"], []).append({"claimId": o["opId"], "agent": holder})
            elif o["op"] == "MERGE":
                mapping.append({"operation": "MERGE", "agentId": o["agent"],
                                "attributes": {"mergeId": o["opId"], "conflict": False}})
            elif o["op"] == "MESSAGE":
                for direction, agent in (("SEND", o["agent"]), ("RECEIVE", o["message"]["to"])):
                    mapping.append({"operation": "MESSAGE", "agentId": agent,
                                    "attributes": {"messageId": o["opId"], "direction": direction,
                                                   "fromAgent": o["agent"], "toAgent": o["message"]["to"]}})
                if o["message"]["messageType"] != "INTERFACE" or o["message"]["requiredAction"] != "NONE":
                    gaps.append({"step": "MESSAGE_TYPE", "opId": o["opId"]})
            elif o["op"] == "VERIFY":
                mapping.append({"operation": "VERIFICATION", "agentId": o["agent"],
                                "attributes": {"ledgerDigest": o["verdict"]["ledgerDigest"]}})
            else:
                gaps.append({"step": o["op"], "opId": o["opId"]})
        final = {i: {k: r[k] for k in ("state", "holder", "version")} for i, r in board.records.items()}
        return {"digest": digest(doc), "topologyDigest": doc["topologyDigest"], "answers": answers, "board": final,
                "mapping": mapping, "gaps": gaps}
    return _guarded(run)


if __name__ == "__main__":
    from pathlib import Path

    import importlib.util

    root = Path(__file__).resolve().parents[1]

    def load(name, path):
        spec = importlib.util.spec_from_file_location(name, root / path)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        return module

    runs_model = load("_run_manifest", "scripts/run_manifest.py")
    ledger_model = load("_verdict_ledger", "scripts/verdict_ledger.py")
    kinds = json.loads((root / "architecture/verdict-ledger/check-kinds.json").read_bytes())
    vectors = json.loads((root / "architecture/topology-coordination/vectors.json").read_bytes())
    stores = vectors["stores"]
    checks = {"topology": lambda d: check_topology(d, stores, runs_model),
              "transcript": lambda d: check_transcript(d, stores, runs_model, ledger_model, kinds),
              "binding": lambda d: check_run_binding(stores["topologies"][d["topologyDigest"]],
                                                     stores["manifests"][d["manifestDigest"]], stores, runs_model)}
    for row in vectors["cases"]:
        try:
            facts = checks[row["kind"]](row["document"])
            got = None
        except Refused as refusal:
            got, facts = refusal.code, None
        assert got == row["expect"], (row["id"], got, row["expect"])
        if facts is not None and "facts" in row:
            assert {k: facts[k] for k in row["facts"]} == row["facts"], row["id"]
    for row in vectors["texts"]:
        try:
            checks[row["kind"]](parse(row["text"]))
            got = None
        except Refused as refusal:
            got = refusal.code
        assert got == row["expect"], row["id"]
    for row in vectors["selection"]:
        assert list(allowed_outcomes(row["taskShape"], tuple(row["score"]))) == row["allowed"], row
    print("topology and coordination vectors replay: %d cases, %d texts, %d selection rows"
          % (len(vectors["cases"]), len(vectors["texts"]), len(vectors["selection"])))
