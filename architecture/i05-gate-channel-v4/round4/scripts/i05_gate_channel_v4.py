#!/usr/bin/env python3
"""I05 broker-gate channel v4 (I05-OBSERVED-WORKERS): the v3 model with the gate's own worker observation.

DATA_CHECK_ONLY reference model for the private interface between the capacity broker and
the effect gate (HOST-INTERFACE-DRAFT-002 sections 3.2, 4.3, 6 and 7). It is the successor of
`i05_gate_channel_v3` (adopted and frozen). The wire is unchanged: frames keep the v3 schema and
version (`planeon.internal.effect-gate-frame/v3`). v4 changes only how the gate knows the worker named
in BIND_EXECUTION (owner decisions Q-HE3D-2 (a), Q-I5-1..4 (a), 2026-10-16): v3 took a static
configuration list; v4 observes the kernel at every BIND (Q-I5-1) through the reads the SELinux
matrix v5 and the seccomp allowlists v4 allow:
  1. CGROUP_PROCS: read `cgroup.procs` of the broker's probe-worker cgroup; the BIND's PID must be
     listed (thread-group leaders; other members do not refuse, Q-I5-4);
  2. PIDFD_OPEN: `pidfd_open` the PID;
  3. STAT: `/proc/<pid>/stat` starttime (field 22) must equal the BIND's workerStartTicks;
  4. CGROUP_RECHECK: read `cgroup.procs` again; the PID must still be listed;
  5. PIDFD_ALIVE: the pidfd has not exited, so the PID named the process the pidfd holds throughout steps 3 and 4
     (Q-I5-3: no window for PID reuse).
The gate reads only `cgroup.procs` of the leaf and the worker's ungated `/proc/<pid>/stat` (the reachable set the
lane monitor relayed: cgroup.procs, stat and status), plus pidfd_open and a zero-timeout poll of the pidfd.
Every failure, a kernel read error included, refuses the BIND with the existing WORKER_NOT_OBSERVED:
non-fatal, retryable, nothing durable recorded (Q-I5-2); its cause goes to a local diagnostic log
(`Gate.observations`), outside the durable journal and the snapshot. A v3 configuration converts by
listing its observedWorkers as live members of the probe-worker cgroup (`convert_v3_config`), and every
v3 transcript then replays to the same outputs and final snapshot.

- `decode_frame` and `check_frame` check one frame: canonical duplicate-free bytes, exact
  builtins, the closed schema and the envelope bounds.
- `render_request` derives the one I04 request an armed action permits (method, path,
  query, headers and body).
- `Gate` replays a transcript of broker frames, I04 connection events, upstream events and
  failures, and returns every gate decision: response payloads, fatal channel closures,
  forwarding decisions with the refusal reason, the I07 drain answer, and the resulting
  generation state. Every state change the gate relies on after a restart is a durable journal
  record; a failed record also writes a failure marker on a separate failure domain, and a
  restart rebuilds the gate's actions from the journal and the marker alone.
- `check_agreement` applies the ACTION_OUTCOME to RESOURCE_RESULT mapping table.

None of it opens a socket, forwards a request or grants authority. A gate response is an
observation of gate-owned state, never a capability.
"""
from __future__ import annotations

import base64
import copy
import hashlib
import json
from typing import Any

FRAME_VERSION = "planeon.internal.effect-gate-frame/v3"
TEMPLATE_VERSION = "planeon.internal.effect-gate-template/v1"   # the action template is unchanged from v1
MODEL_VERSION = "planeon.internal.effect-gate-model/v4"            # the gate model; the wire stays v3
# The broker's probe-worker cgroup (resolved W01 4.2; SELinux matrix v5 planeon_cgroup_worker_t), relative to the
# cgroup2 root.
PROBE_WORKER_CGROUP = "/planeon.slice/planeon-capacity-broker.service/probe-worker"
OBSERVATION_STEPS = ("CGROUP_PROCS", "PIDFD_OPEN", "STAT", "CGROUP_RECHECK", "PIDFD_ALIVE")
# The local diagnostic causes of a refused observation; the frame answer is always WORKER_NOT_OBSERVED (Q-I5-2).
READ_FAILURES = {"CGROUP_PROCS": "CGROUP_PROCS_UNREADABLE", "PIDFD_OPEN": "PIDFD_OPEN_FAILED", "STAT": "STAT_UNREADABLE",
                 "CGROUP_RECHECK": "CGROUP_RECHECK_UNREADABLE", "PIDFD_ALIVE": "PIDFD_POLL_FAILED"}
OBSERVATION_CAUSES = tuple(READ_FAILURES.values()) + ("NOT_A_MEMBER", "PROCESS_GONE", "START_MISMATCH",
                                                      "NOT_IN_PROBE_WORKER_CGROUP", "PIDFD_EXITED")
# Every (failing step, local cause) the observation can give.
OBSERVATION_OUTCOMES = (("CGROUP_PROCS", "CGROUP_PROCS_UNREADABLE"), ("CGROUP_PROCS", "NOT_A_MEMBER"),
                        ("PIDFD_OPEN", "PIDFD_OPEN_FAILED"), ("PIDFD_OPEN", "PROCESS_GONE"),
                        ("STAT", "STAT_UNREADABLE"), ("STAT", "PROCESS_GONE"), ("STAT", "START_MISMATCH"),
                        ("CGROUP_RECHECK", "CGROUP_RECHECK_UNREADABLE"), ("CGROUP_RECHECK", "NOT_IN_PROBE_WORKER_CGROUP"),
                        ("PIDFD_ALIVE", "PIDFD_POLL_FAILED"), ("PIDFD_ALIVE", "PIDFD_EXITED"))
# Test inputs only: the kernel changes between the gate's reads (closed shapes).
KERNEL_EVENTS = {"KERNEL_SPAWN": {"type", "pid", "startTicks", "cgroup"}, "KERNEL_EXIT": {"type", "pid"},
                 "KERNEL_MOVE": {"type", "pid", "cgroup"}}
OPERATIONS = ("GENERATION_STATUS", "BIND_EXECUTION", "ARM_ACTION", "ACTION_OUTCOME", "CLOSE_GENERATION")
STATES = ("INSPECTING", "ACTIVE", "DRAINING", "CLOSED", "INVALIDATED", "HELD")
CLOSE_REASONS = ("NORMAL_DRAIN", "REVOCATION", "EXPIRY", "PEER_FAILURE", "STORAGE_FAILURE", "OBSERVATION_FAILURE",
                 "RECONCILIATION_REQUIRED")
CLASSIFICATIONS = ("NOT_FORWARDED", "DELIVERED_RESULT", "IO_AMBIGUOUS")
# The I07 drain answer: PENDING (wait), OPEN (the A3 fence holds; a policy write may begin), HELD (no write).
DRAIN_ANSWERS = ("PENDING", "OPEN", "HELD")
# Refusals no reachable interleaving produces in this model; the gate still checks them (defence in depth).
UNREACHABLE_REFUSALS = ("STAMP_MISMATCH", "ALREADY_CONSUMED")
CORRELATION_REFUSALS = ("STAMP_NONE", "CERTIFICATE_MISMATCH", "REQUEST_MISMATCH") + UNREACHABLE_REFUSALS
PLURALS = {"Pod": "pods", "ConfigMap": "configmaps", "Service": "services"}
MAX_FRAME_BYTES = 16384
MAX_DEPTH = 16
MAX_SEQUENCE = 2147483647
ZERO_DIGEST = "sha256:" + "0" * 64


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(message)


def canonical(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, ensure_ascii=False, separators=(",", ":"), allow_nan=False).encode("utf-8")


def sha(raw: bytes) -> str:
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def frame_digest(frame: dict) -> str:
    return sha(canonical(frame))


def identity_of(manifest: dict) -> str:
    """A manifest's object identity: kind, namespace and name (the API server's uniqueness key)."""
    return "%s/%s/%s" % (manifest["kind"], manifest["namespace"], manifest["name"])


def template_digest(verb: str, api_version: str, kind: str, namespace: str, name: str, uid: str | None,
                    manifest_digest: str) -> str:
    """The ARM_ACTION request template: the canonical identity of one permitted action."""
    return sha(canonical({"schemaVersion": TEMPLATE_VERSION, "verb": verb, "apiVersion": api_version, "kind": kind,
                          "namespace": namespace, "name": name, "uid": uid, "manifestDigest": manifest_digest}))


def delete_options(uid: str) -> bytes:
    """The only DeleteOptions body a DELETE may carry: the recorded-UID precondition."""
    return canonical({"apiVersion": "v1", "kind": "DeleteOptions", "preconditions": {"uid": uid}})


def render_request(verb: str, manifest: dict, uid: str | None, endpoint: str) -> dict:
    """The exact I04 request an armed action permits: the request-head bytes and the body digest. A1
    requires the received head bytes and body to equal them byte for byte, and the gate forwards these
    rendered bytes. Any other method, target, query parameter (dryRun, watch, gracePeriodSeconds, ...),
    version, header field, name case, order, duplicate, folding, transfer-coding or body is refused."""
    base = "/api/v1/namespaces/%s/%s" % (manifest["namespace"], PLURALS[manifest["kind"]])
    if verb == "CREATE":
        body_digest, body_length, method, target = manifest["digest"], manifest["size"], "POST", base
    elif verb == "DELETE":
        body = delete_options(uid)
        body_digest, body_length, method, target = sha(body), len(body), "DELETE", base + "/" + manifest["name"]
    else:
        body_digest, body_length, method, target = None, 0, "GET", base + "/" + manifest["name"]
    head = "%s %s HTTP/1.1\r\nHost: %s\r\nAccept: application/json\r\n" % (method, target, endpoint)
    if body_digest is not None:
        head += "Content-Type: application/json\r\nContent-Length: %d\r\n" % body_length
    return {"head": head + "\r\n", "bodyDigest": body_digest}


def outcome_is_final(verb: str, status: int) -> bool:
    """Whether a delivered response settles a mutation. GET never mutates. A CREATE is settled by 201 or a
    rejection (4xx other than 408); a DELETE by 200, 202, 404 or a rejection. Any other status (5xx, 408,
    1xx, 3xx, another 2xx) leaves the outcome unknown: the gate classifies it IO_AMBIGUOUS (Kubernetes API
    conventions: 500 means the outcome is unknown, and a timed-out request may still persist)."""
    if verb == "GET":
        return True
    rejected = 400 <= status <= 499 and status != 408
    return rejected or (status == 201 if verb == "CREATE" else status in (200, 202, 404))


# ---------------------------------------------------------------- frames

def _strict_pairs(pairs: list) -> dict:
    result = {}
    for key, value in pairs:
        require(key not in result, "F05 duplicate key")
        result[key] = value
    return result


def _reject_constant(token: str) -> Any:
    raise ValueError("F03 frame contains a non-integer number")


def _depth(value: Any) -> int:
    """Nesting depth, computed without recursion (a scalar is 0, an empty object or array 1)."""
    deepest, stack = 0, [(value, 0)]
    while stack:
        node, level = stack.pop()
        if isinstance(node, dict):
            children = list(node.values())
        elif isinstance(node, list):
            children = list(node)
        else:
            continue
        deepest = max(deepest, level + 1)
        stack.extend((child, level + 1) for child in children)
    return deepest


def _walk(value: Any):
    """Every value and object key, without recursion."""
    stack = [value]
    while stack:
        node = stack.pop()
        yield node
        if isinstance(node, dict):
            for key, child in node.items():
                yield key
                stack.append(child)
        elif isinstance(node, list):
            stack.extend(node)


def check_frame(frame: Any, schema: dict) -> None:
    """Depth first (so no later check recurses into an unbounded value), then exact builtins,
    newline-safe strings, the closed schema and the canonical size."""
    import jsonschema
    require(_depth(frame) <= MAX_DEPTH, "F01 frame deeper than 16")
    require(not any(type(v) is float for v in _walk(frame)), "F03 frame contains a non-integer number")
    # jsonschema's Python patterns let '$' match before a trailing newline; ECMA-262 does not.
    require(not any(type(v) is str and any(ord(c) < 32 or ord(c) == 127 for c in v) for v in _walk(frame)),
            "F04 frame string contains a control character")
    require(not list(jsonschema.Draft202012Validator(schema).iter_errors(frame)), "F00 frame outside the closed schema")
    require(len(canonical(frame)) <= MAX_FRAME_BYTES, "F02 frame larger than 16 KiB")


def decode_frame(raw: Any, schema: dict) -> dict:
    """Bytes as received: a byte string of at most 16 KiB, UTF-8, duplicate-free, no NaN or Infinity, and
    exactly the canonical encoding, so the next frame's previousDigest is the digest of these very bytes."""
    require(type(raw) is bytes, "F07 frame is not a byte string")
    require(len(raw) <= MAX_FRAME_BYTES, "F02 frame larger than 16 KiB")
    try:
        frame = json.loads(raw.decode("utf-8"), object_pairs_hook=_strict_pairs, parse_constant=_reject_constant)
        encoded = canonical(frame)
    except RecursionError as exc:   # nesting beyond the decoder's recursion limit is far deeper than 16
        raise ValueError("F01 frame deeper than 16") from exc
    except ValueError as exc:       # also JSONDecodeError, UnicodeDecodeError and over-long integers
        if str(exc).startswith(("F03 ", "F05 ")):
            raise
        raise ValueError("F06 frame is not canonical JSON") from exc
    except UnicodeEncodeError as exc:  # a lone surrogate escape
        raise ValueError("F06 frame is not canonical JSON") from exc
    # Canonical form: sorted keys, no whitespace, UTF-8; for this schema (ASCII strings, integers only) it
    # coincides with RFC 8785.
    require(encoded == raw, "F06 frame is not canonical JSON")
    check_frame(frame, schema)
    return frame


# ---------------------------------------------------------------- outcome mapping

def _row_status(row: dict, status: int | None, exact: bool) -> bool:
    rule = row["httpStatus"]
    if status is None or rule is None:
        return status is None and rule is None
    if exact:
        return type(rule) is int and rule == status
    low, high = {"4xx": (400, 499), "5xx": (500, 599)}.get(rule, (0, -1))
    return type(rule) is str and low <= status <= high and status not in row["excludeStatus"]


def _decode_object(data: Any) -> dict | None:
    """Strict decode of RESOURCE_RESULT objectBase64: valid base64, duplicate-free JSON, no NaN or
    Infinity, depth at most 16, an object. None when any of that fails."""
    try:
        raw = base64.b64decode(data, validate=True)
        value = json.loads(raw.decode("utf-8"), object_pairs_hook=_strict_pairs, parse_constant=_reject_constant)
    except (ValueError, TypeError, RecursionError, UnicodeDecodeError):
        return None
    if not isinstance(value, dict) or _depth(value) > MAX_DEPTH:
        return None
    return value


def check_agreement(mapping: dict, verb: str, identity: dict, outcome: Any, result: Any) -> str | None:
    """None when the gate's ACTION_OUTCOME and the server's RESOURCE_RESULT agree; otherwise the refusal.
    `identity` is the armed template's apiVersion, kind, namespace and name. The broker treats any
    refusal as sticky disagreement and holds the generation HELD."""
    if type(outcome) is not dict or outcome.get("result") != "OK":
        return "M00 no usable ACTION_OUTCOME"
    if type(result) is not dict or result.get("actionId") != outcome.get("actionId"):
        return "M01 action identifiers differ"
    status = outcome.get("httpStatus")
    rows = [row for row in mapping["rows"] if row["verb"] in (verb, "*") and row["classification"] == outcome.get("classification")]
    exact = [row for row in rows if _row_status(row, status, True)]
    matched = exact or [row for row in rows if _row_status(row, status, False)]
    if len(matched) != 1:
        return "M02 no mapping row for this outcome"
    row = matched[0]
    if result.get("outcome") not in row["resourceResults"]:
        return "M03 resource result outside the mapped outcomes"
    data = result.get("objectBase64")
    if row["object"] == "NULL" and data is not None:
        return "M04 object reported where the mapping requires none"
    if row["object"] == "DELETE_BODY_IF_PRESENT" and data is not None and mapping["deleteResponseBody"][identity["kind"]] == "STATUS":
        # Registries that do not return the deleted object answer with a v1 Status (details.kind is the resource).
        # A deletion that is not immediate (finalizers) returns the object instead: refused here, so HELD.
        value = _decode_object(data)
        details = value.get("details") if value is not None and isinstance(value.get("details"), dict) else None
        if value is None or details is None or (value.get("kind"), value.get("status")) != ("Status", "Success"):
            return "M05 reported object missing or not strictly decodable"
        if (details.get("name"), details.get("kind")) != (identity["name"], PLURALS[identity["kind"]]):
            return "M06 reported object identity differs from the armed action"
        if details.get("uid") != outcome.get("observedUid") or outcome.get("observedResourceVersion") is not None:
            return "M07 reported object UID or resourceVersion differs from the gate's observation"
        return None
    if row["object"] in ("IDENTITY_MATCH", "DELETE_BODY_IF_PRESENT") and (row["object"] == "IDENTITY_MATCH" or data is not None):
        value = _decode_object(data) if data is not None else None
        if value is None:
            return "M05 reported object missing or not strictly decodable"
        meta = value.get("metadata") if isinstance(value.get("metadata"), dict) else {}
        if (value.get("apiVersion"), value.get("kind"), meta.get("namespace"), meta.get("name")) != (
                identity["apiVersion"], identity["kind"], identity["namespace"], identity["name"]):
            return "M06 reported object identity differs from the armed action"
        if meta.get("uid") != outcome.get("observedUid") or meta.get("resourceVersion") != outcome.get("observedResourceVersion"):
            return "M07 reported object UID or resourceVersion differs from the gate's observation"
    return None


# ---------------------------------------------------------------- gate model

class Gate:
    """Deterministic model of the gate's decisions for one generation and its single I05 channel."""

    def __init__(self, config: dict):
        self.generation = config["generation"]
        self.state = config["state"]
        self.peer = config["peerQualificationDigest"]
        self.endpoint = config["endpoint"]
        self.manifests = config["manifests"]
        self.runs = config["runs"]
        # v4: the kernel's process table as the gate can observe it (pid -> start ticks, cgroup, a serial standing for
        # the process itself, so that a reused PID is a different process). There is no static worker list.
        require("observedWorkers" not in config,
                "v4 observes the kernel; a static observedWorkers list is refused (convert_v3_config)")
        kernel = config.get("kernel")
        require(type(kernel) is dict and set(kernel) == {"processes"} and type(kernel["processes"]) is list,
                "a closed kernel process table")
        self.kernel: dict[int, dict] = {}
        self._serial = 0
        for proc in kernel["processes"]:
            require(type(proc) is dict and set(proc) == {"pid", "startTicks", "cgroup"}, "a closed kernel process")
            self._spawn(proc["pid"], proc["startTicks"], proc["cgroup"])
        self.observation_fails: list[str] = []   # test injection: the next observation's read at that step fails
        self.observation_races: list[dict] = []  # test injection: a kernel event right after a step of the next observation
        self.observations: list[dict] = []       # local diagnostic log (not durable, not in the snapshot)
        # The gate refuses inputs in which a manifest digest or a manifest identity (kind, namespace, name)
        # belongs to more than one run (I02: a digest belongs to one case only; signed names are never reused).
        manifests = [d for run in self.runs.values() for d in run["manifests"]]
        require(all(d in self.manifests for d in manifests), "a run manifest is not in the signed profile")
        require(len(manifests) == len(set(manifests)), "a manifest digest resolves to more than one run")
        identities = [identity_of(self.manifests[d]) for d in manifests]
        require(len(identities) == len(set(identities)), "a manifest identity resolves to more than one manifest")
        # Bindings of earlier generations stay in the durable journal: their executionIds and run nonces are
        # never bound again, and their manifest digests and identities never belong to a later run.
        prior = config["priorBindings"]
        require(type(prior) is dict and set(prior) == {"executionIds", "runNonces", "manifestDigests", "manifestIdentities"}
                and all(type(prior[key]) is list for key in prior), "an incomplete priorBindings record")
        self.prior_ids, self.prior_nonces = set(prior["executionIds"]), set(prior["runNonces"])
        self.prior_digests, self.prior_identities = set(prior["manifestDigests"]), set(prior["manifestIdentities"])
        self._failing = False
        self.drain_pending = False
        self.channel = "UNOPENED"          # UNOPENED, OPEN, CLOSED
        self.challenge = None
        self.next_sequence = 1
        self.last_digest = ZERO_DIGEST
        self.bound = None                  # {"executionId", "runNonce"}
        self.bound_ids: list[str] = []
        self.bound_nonces: list[str] = []
        self.expired = False
        self.actions: dict[int, dict] = {}
        self.mutation_keys: set[tuple] = set()
        self.created_uids: dict[str, set] = {}
        self.backlog: list[str] = []
        self.connections: dict[str, dict] = {}
        self.storage_fails: list[bool] = []   # pending journal write failures; True leaves a torn record
        self._fail_after: int | None = None    # test injection: the record attempt after this many attempts fails
        self.marker_fails = 0
        self.counters = {"stampsIssued": 0, "consumptions": 0, "correlationRefusals": 0, "flushClosures": 0}
        self.journal: list[list] = []
        self.marker: list[list] = []          # the failure marker store (separate failure domain)

    # -- the kernel as the gate observes it (v4)
    def _spawn(self, pid: Any, start: Any, cgroup: Any) -> None:
        require(type(pid) is int and pid > 0 and type(start) is int and start >= 0 and type(cgroup) is str
                and cgroup.startswith("/") and pid not in self.kernel, "a closed kernel process")
        self._serial += 1
        self.kernel[pid] = {"startTicks": start, "cgroup": cgroup, "serial": self._serial}

    def _kernel_event(self, event: Any) -> None:
        """A kernel change the gate does not see directly (test input: the kernel moves on between reads)."""
        require(type(event) is dict and set(event) == KERNEL_EVENTS.get(event.get("type")), "a closed kernel event")
        kind = event["type"]
        if kind == "KERNEL_SPAWN":
            self._spawn(event["pid"], event["startTicks"], event["cgroup"])
        elif kind == "KERNEL_EXIT":
            require(event["pid"] in self.kernel, "exit of an unknown process")
            del self.kernel[event["pid"]]
        else:
            require(event["pid"] in self.kernel and type(event["cgroup"]) is str and event["cgroup"].startswith("/"),
                    "a move of an unknown process or to a malformed cgroup")
            self.kernel[event["pid"]]["cgroup"] = event["cgroup"]

    def _after(self, step: str) -> None:
        """Apply the pending race injections for this step: kernel events between this read and the next."""
        pending = [race for race in self.observation_races if race["after"] == step]
        self.observation_races = [race for race in self.observation_races if race["after"] != step]
        for race in pending:
            self._kernel_event(race["event"])

    def _read_fails(self, step: str) -> bool:
        if step in self.observation_fails:
            self.observation_fails.remove(step)
            return True
        return False

    def _observe_worker(self, pid: Any, start: Any) -> tuple | None:
        """The gate's observation of the worker a BIND names (Q-I5-1 and Q-I5-3): None when observed, else the failing
        step and its cause. KERNEL_EXIT stands for exit and reap together: a zombie stays visible to pidfd_open and
        /proc/<pid>/stat on a real kernel, so the local cause can differ there (README rule 1); the wire answer does not."""
        if self._read_fails("CGROUP_PROCS"):
            return "CGROUP_PROCS", READ_FAILURES["CGROUP_PROCS"]
        members = sorted(p for p, proc in self.kernel.items() if proc["cgroup"] == PROBE_WORKER_CGROUP)
        self._after("CGROUP_PROCS")
        if pid not in members:
            return "CGROUP_PROCS", "NOT_A_MEMBER"
        if self._read_fails("PIDFD_OPEN"):
            return "PIDFD_OPEN", READ_FAILURES["PIDFD_OPEN"]
        if pid not in self.kernel:
            return "PIDFD_OPEN", "PROCESS_GONE"  # pidfd_open: ESRCH
        held = self.kernel[pid]["serial"]
        self._after("PIDFD_OPEN")
        if self._read_fails("STAT"):
            return "STAT", READ_FAILURES["STAT"]
        if pid not in self.kernel:
            return "STAT", "PROCESS_GONE"
        if self.kernel[pid]["startTicks"] != start:
            return "STAT", "START_MISMATCH"
        self._after("STAT")
        if self._read_fails("CGROUP_RECHECK"):
            return "CGROUP_RECHECK", READ_FAILURES["CGROUP_RECHECK"]
        if pid not in [p for p, proc in self.kernel.items() if proc["cgroup"] == PROBE_WORKER_CGROUP]:
            # No longer listed: moved out, or exited and not reused there.
            return "CGROUP_RECHECK", "NOT_IN_PROBE_WORKER_CGROUP"
        self._after("CGROUP_RECHECK")
        if self._read_fails("PIDFD_ALIVE"):
            return "PIDFD_ALIVE", READ_FAILURES["PIDFD_ALIVE"]
        if self.kernel.get(pid, {}).get("serial") != held:
            return "PIDFD_ALIVE", "PIDFD_EXITED"  # the held process exited; a later reuse of the PID does not count
        return None

    # -- durable journal and failure marker
    def _record(self, *entry: Any) -> bool:
        """fsync and read back one journal record. A failed write is an urgent STORAGE_FAILURE: the failure
        marker is written, A1 closes, the generation is HELD, an armed action is denied and an in-flight one
        is marked admitted before invalidation; the caller then refuses or reports what it was doing. A
        write that fails may leave a torn record, which fails its own digest at restart."""
        if self._fail_after is not None:
            if self._fail_after == 0:
                self._fail_after = None
                self.storage_fails.append(False)
            else:
                self._fail_after -= 1
        if self.storage_fails:
            if self.storage_fails.pop(0):
                self.journal.append(["TORN"])
            self._storage_failure()
            return False
        self.journal.append(list(entry))
        return True

    def _mark(self, reason: str) -> bool:
        """The failure marker: one record for this generation in a store on a failure domain separate from
        the journal's (another device and file system), written with fsync and read back. Once present it
        is never removed for this generation, and a restart reads it before the journal."""
        if self.marker:
            return True
        if self.marker_fails:
            self.marker_fails -= 1
            return False
        self.marker.append([self.generation, reason])
        return True

    def _storage_failure(self) -> None:
        if self._failing:
            return
        self._failing = True
        self.state = "HELD"
        in_flight = self._in_flight()
        if in_flight is not None:
            in_flight["afterInvalidation"] = True
        self._mark("STORAGE_FAILURE")
        self._record("INVALIDATED", "STORAGE_FAILURE", "HELD")
        self._deny_armed()
        self._failing = False

    def _rebuild(self) -> str:
        """Restart: the gate's actions are what the durable journal says, nothing more. Returns the state the
        gate restarts in: HELD when the failure marker is present or any journal record is torn; otherwise
        the last recorded CLOSED or INVALIDATED state when every action is sealed and terminal and none is
        ambiguous, and HELD in every other case."""
        actions: dict[int, dict] = {}
        state, torn = "HELD", False
        for entry in self.journal:
            kind = entry[0]
            if kind == "TORN":
                torn = True
            elif kind in ("INVALIDATED", "CLOSED"):
                state = entry[2]
            elif kind in ("DRAINED", "RESTARTED"):
                state = entry[1]
            if kind == "BIND":
                actions = {}
            elif kind == "ARM":
                actions[entry[1]] = {"actionId": entry[1], "status": "ARMED", "sealed": False}
            elif kind == "CONSUMED":
                actions[entry[1]].update(status="CONSUMED", afterInvalidation=False)
            elif kind in ("INVALIDATED", "EXPIRED"):
                for action in actions.values():
                    if action["status"] == "CONSUMED":
                        action["afterInvalidation"] = True
            elif kind == "TERMINAL":
                actions[entry[1]].update(status="TERMINAL", classification=entry[2], afterInvalidation=entry[3])
            elif kind == "DENIED":
                actions[entry[1]].update(status="TERMINAL", classification="NOT_FORWARDED")
            elif kind == "SEALED":
                actions[entry[1]].update(status="TERMINAL", classification=entry[2], sealed=True,
                                         afterInvalidation=entry[3] and entry[2] != "NOT_FORWARDED")
        clean = all(a["status"] == "TERMINAL" and a["sealed"] and a.get("classification") != "IO_AMBIGUOUS"
                    for a in actions.values())
        for action in actions.values():
            # Admitted without a terminal record: ambiguous, and admitted before the restart (C6, base 5).
            if action["status"] == "CONSUMED":
                action.update(status="TERMINAL", classification="IO_AMBIGUOUS", afterInvalidation=True)
            elif action["status"] == "ARMED":
                action.update(status="TERMINAL", classification="NOT_FORWARDED")
        self.actions = actions
        if self.marker or torn:
            return "HELD"
        return state if clean and state in ("CLOSED", "INVALIDATED") else "HELD"

    # -- helpers
    def _armed(self) -> dict | None:
        return next((a for a in self.actions.values() if a["status"] == "ARMED"), None)

    def _in_flight(self) -> dict | None:
        return next((a for a in self.actions.values() if a["status"] == "CONSUMED"), None)

    def _armed_ids(self) -> list[int]:
        return [a["actionId"] for a in self.actions.values() if a["status"] == "ARMED"]

    def _denied_since(self, armed: list[int]) -> list[int]:
        """The actions armed when an operation began that it denied, by whichever path: the operation's
        own deny or the storage-failure path of a record that failed during it."""
        return [action_id for action_id in armed if self.actions[action_id]["status"] == "TERMINAL"]

    def _stamp_of(self, action: dict) -> dict:
        return {"executionId": self.bound["executionId"], "actionId": action["actionId"]}

    def _close_connections(self, predicate) -> int:
        closed = 0
        for conn in self.connections.values():
            if conn["state"] == "OPEN" and predicate(conn):
                conn["state"] = "CLOSED"
                closed += 1
        self.counters["flushClosures"] += closed
        return closed

    def _deny_armed(self) -> list[int]:
        """Deny every armed, unconsumed action: its stamped connections close, then NOT_FORWARDED is
        recorded. The deny holds in memory even if the record fails (the generation is then HELD)."""
        denied = []
        for action in self.actions.values():
            if action["status"] == "ARMED":
                stamp = self._stamp_of(action)
                self._close_connections(lambda c, s=stamp: c["stamp"] == s and not c["consumed"])
                action.update(status="TERMINAL", classification="NOT_FORWARDED")
                self._record("DENIED", action["actionId"])
                denied.append(action["actionId"])
        return denied

    def _urgent(self, state: str, reason: str) -> list[int]:
        """A4: close A1 first (in memory, independent of storage), record the invalidation, deny
        unconsumed actions, keep consumed actions recorded."""
        if self.state != "HELD":
            self.state = state
        in_flight = self._in_flight()
        if in_flight is not None:
            in_flight["afterInvalidation"] = True
        self._record("INVALIDATED", reason, self.state)
        return self._deny_armed()

    def _fatal(self, reason: str) -> dict:
        self.channel = "CLOSED"
        self._urgent("HELD", reason)
        self.state = "HELD"
        return {"fatal": reason}

    def _orderly(self) -> bool:
        return (self.state in ("CLOSED", "INVALIDATED") and self._in_flight() is None
                and all(a["status"] == "TERMINAL" and a["sealed"] for a in self.actions.values()))

    def fence(self) -> str:
        """The A3 fence for an I07 write, from gate state only: HELD when the generation is HELD; OPEN when it
        is CLOSED or INVALIDATED and no consumed action lacks a terminal record; otherwise PENDING."""
        if self.state == "HELD":
            return "HELD"
        if self.state not in ("CLOSED", "INVALIDATED") or self._in_flight() is not None:
            return "PENDING"
        return "OPEN"

    def snapshot(self) -> dict:
        return {"state": self.state, "drainPending": self.drain_pending, "channel": self.channel,
                "boundExecutionId": self.bound["executionId"] if self.bound else None,
                "actions": {str(k): {"status": v["status"], "classification": v.get("classification"),
                                     "admittedBeforeInvalidation": v.get("afterInvalidation", False),
                                     "sealed": v["sealed"]}
                            for k, v in sorted(self.actions.items())},
                "connections": {k: v["state"] for k, v in sorted(self.connections.items())},
                "counters": dict(self.counters), "journal": copy.deepcopy(self.journal),
                "failureMarker": copy.deepcopy(self.marker)}

    # -- events
    def handle(self, event: dict, schema: dict) -> dict:
        """One event. A pending I07 drain is settled after every event; the event that settles it carries
        the answer (`drain`: OPEN or HELD)."""
        out = self._dispatch(event, schema)
        answer = self._settle_drain()
        if answer is not None:
            out = dict(out, drain=answer)
        return out

    def _dispatch(self, event: dict, schema: dict) -> dict:
        kind = event["type"]
        if kind == "FRAME":
            return self._frame(event["frame"], schema)
        if kind == "BACKLOG":
            self.backlog.append(event["conn"])
            return {}
        if kind == "ACCEPT":
            return self._accept(event["conn"])
        if kind == "REQUEST":
            return self._request(event)
        if kind == "UPSTREAM_RESPONSE":
            return self._upstream(event, lost=False)
        if kind == "UPSTREAM_LOST":
            return self._upstream(event, lost=True)
        if kind == "UPSTREAM_TIMEOUT":
            return self._timeout(event)
        if kind == "STORAGE_FAIL_NEXT":
            self.storage_fails.append(event.get("torn", False) is True)
            return {}
        if kind == "MARKER_FAIL_NEXT":
            self.marker_fails += 1
            return {}
        if kind == "STORAGE_FAIL_AFTER":
            # Test injection only (v2 review V1): the (after+1)-th record attempted from now fails. Attempts are counted,
            # failed ones and those inside the storage-failure path included; one injection is pending at a time.
            self._fail_after = event["after"]
            return {}
        if kind == "DRAIN_REQUEST":
            return self._drain()
        if kind == "EXPIRE":
            return self._expire()
        if kind == "CHANNEL_LOST":
            if self.channel == "UNOPENED":      # a connection that ends before its first frame uses the channel
                self.channel = "CLOSED"
                self._record("CHANNEL_ENDED", "BEFORE_FIRST_FRAME")
                return {"channelEnd": "UNUSED"}
            if self.channel != "OPEN":
                return {}
            if self._orderly():
                self.channel = "CLOSED"
                self._record("CHANNEL_ENDED", "ORDERLY")
                return {"channelEnd": "ORDERLY"}
            return self._fatal("PEER_LOST")
        if kind == "SECOND_CHANNEL":
            require(self.channel != "UNOPENED", "second channel before the first")
            return {"refusedChannel": "CHANNEL_EXISTS" if self.channel == "OPEN" else "GENERATION_CHANNEL_USED"}
        if kind == "PEER_CHANGED":
            return self._fatal("PEER_CHANGED") if self.channel == "OPEN" else {}
        if kind in KERNEL_EVENTS:
            self._kernel_event(event)
            return {}
        if kind == "OBSERVATION_FAIL_NEXT":
            # Test injection (v4): the next observation that reaches this step fails its read there (EACCES, EIO or
            # malformed content).
            require(set(event) == {"type", "step"} and event["step"] in OBSERVATION_STEPS, "unknown observation step")
            self.observation_fails.append(event["step"])
            return {}
        if kind == "OBSERVATION_RACE_NEXT":
            # Test injection (v4): a kernel event lands right after this step of the next observation that completes it.
            require(set(event) == {"type", "after", "event"} and event["after"] in OBSERVATION_STEPS[:-1]
                    and type(event["event"]) is dict and set(event["event"]) == KERNEL_EVENTS.get(event["event"].get("type")),
                    "unknown observation race")
            self.observation_races.append({"after": event["after"], "event": event["event"]})
            return {}
        require(kind == "GATE_RESTART", "unknown event")
        # Deny-first restart: no channel, no stamps, no connections, no pending drain (the I07 session does
        # not survive a restart either); actions and state come from the failure marker and the journal.
        self.state = self._rebuild()
        for conn in self.connections.values():
            conn["state"] = "CLOSED"
        self.backlog = []
        self.channel = "CLOSED"
        self.drain_pending = False
        # The restart's own record: a store that still fails makes the restart HELD (and writes the marker).
        self._record("RESTARTED", self.state)
        return {"restartState": self.state}

    def _expire(self) -> dict:
        """The bound execution's signed lifetime ended: as with the EXPIRY close for that execution, an
        in-flight action is reported admitted before invalidation and an armed one is denied."""
        if self.bound is None or self.expired:
            return {"denied": []}
        armed = self._armed_ids()
        self.expired = True
        in_flight = self._in_flight()
        if in_flight is not None:
            in_flight["afterInvalidation"] = True
        self._record("EXPIRED", self.bound["executionId"])
        self._deny_armed()
        return {"denied": self._denied_since(armed)}

    def _accept(self, conn: str) -> dict:
        require(conn in self.backlog, "accept outside the backlog")
        self.backlog.remove(conn)
        armed = self._armed()
        stamp = self._stamp_of(armed) if armed is not None else None  # C3: gate state, never client data
        self.connections[conn] = {"stamp": stamp, "state": "OPEN", "requests": 0, "consumed": False}
        if stamp is not None:
            self.counters["stampsIssued"] += 1
        return {"stamp": stamp}

    def _request(self, event: dict) -> dict:
        conn = self.connections.get(event["conn"])
        require(conn is not None, "request on an unaccepted connection")

        def refuse(reason: str) -> dict:
            if conn["state"] == "OPEN":
                conn["state"] = "CLOSED"
            if reason in CORRELATION_REFUSALS:
                self.counters["correlationRefusals"] += 1
            return {"decision": "CLOSE", "reason": reason}

        conn["requests"] += 1
        if conn["state"] != "OPEN":
            return refuse("CONNECTION_CLOSED")
        if conn["requests"] > 1:
            return refuse("PROTOCOL_VIOLATION")          # C1: one request per connection
        # The observed policy generation is current exactly while the generation is ACTIVE with no
        # pending drain: I07 is the only policy writer, and any write first drains the generation.
        if self.state != "ACTIVE" or self.drain_pending or self.channel != "OPEN" or self.bound is None:
            return refuse("NOT_ACTIVE")
        if self.expired:
            return refuse("EXECUTION_EXPIRED")
        if conn["stamp"] is None:
            return refuse("STAMP_NONE")                   # C5: a 'none' stamp never forwards
        if conn["stamp"]["executionId"] != self.bound["executionId"]:
            return refuse("STAMP_MISMATCH")
        action = self.actions.get(conn["stamp"]["actionId"])
        if action is None or action["status"] != "ARMED":
            return refuse("ALREADY_CONSUMED" if action is not None else "STAMP_MISMATCH")
        run = self.runs[self.bound["runNonce"]]
        if event["certificateDigest"] != run["serverCertificateDigest"]:
            return refuse("CERTIFICATE_MISMATCH")
        manifest = self.manifests[action["manifestDigest"]]
        if {"head": event["head"], "bodyDigest": event["bodyDigest"]} != render_request(
                action["verb"], manifest, action["uid"], self.endpoint):
            return refuse("REQUEST_MISMATCH")             # C4: exact bytes, not a reduction
        # A1: consume exactly once, fsync and read back, then the first byte goes upstream.
        if not self._record("CONSUMED", action["actionId"]):
            return refuse("STORAGE_FAILURE")
        action.update(status="CONSUMED", conn=event["conn"], afterInvalidation=False)
        conn["consumed"] = True
        self.counters["consumptions"] += 1
        stamp = self._stamp_of(action)
        self._close_connections(lambda c: c["stamp"] == stamp and not c["consumed"])   # C5
        return {"decision": "FORWARD", "actionId": action["actionId"]}

    def _upstream(self, event: dict, lost: bool) -> dict:
        action = next((a for a in self.actions.values() if a.get("conn") == event["conn"] and a["status"] != "ARMED"), None)
        require(action is not None, "upstream event without a forwarded action")
        if action["status"] == "TERMINAL":
            # The seal aborted this exchange: a late response is never relayed and never changes the seal.
            self._record("LATE_UPSTREAM", action["actionId"])
            return {"lateUpstream": "NOT_RELAYED"}
        reconciliation = {}
        if lost:
            classification, details = "IO_AMBIGUOUS", {}
        elif not outcome_is_final(action["verb"], event["httpStatus"]):
            # Unknown mutation outcome: ambiguous; status and digest are kept for reconciliation only.
            classification, details = "IO_AMBIGUOUS", {}
            reconciliation = {"httpStatus": event["httpStatus"], "resultDigest": event["bodyDigest"]}
        else:
            classification = "DELIVERED_RESULT"
            details = {"httpStatus": event["httpStatus"], "resultDigest": event["bodyDigest"], "observedUid": event["uid"],
                       "observedResourceVersion": event["resourceVersion"]}
        after = action.get("afterInvalidation", False)
        # The terminal record, qualifier included, is durable before any response byte is relayed.
        recorded = self._record("TERMINAL", action["actionId"], classification, after, details or reconciliation)
        if not recorded:
            classification, details = "IO_AMBIGUOUS", {}
        action.update(status="TERMINAL", classification=classification, **details)
        if classification == "IO_AMBIGUOUS":
            self.state = "HELD"
        elif action["verb"] == "CREATE" and details["httpStatus"] == 201 and details["observedUid"] is not None:
            # Only this execution's own created objects may be deleted (I02: server-recorded created UIDs).
            self.created_uids.setdefault(action["manifestDigest"], set()).add(details["observedUid"])
        self.connections[event["conn"]]["state"] = "CLOSED"  # one response per connection, then close
        # A response is relayed only after its terminal record is durable; a lost exchange relays nothing.
        return {"classification": classification, "relayed": recorded and not lost}

    def _timeout(self, event: dict) -> dict:
        """The gate bounds a forwarded exchange by the 900-second limit, counted from its consumption (v2 review V4);
        the end of the signed lifetime does not abort it (EXPIRE, Decision 9). On expiry the gate aborts the
        exchange and closes the server connection: the action is
        TERMINAL IO_AMBIGUOUS {aborted: UPSTREAM_TIMEOUT} and the generation is HELD; nothing is relayed, and a
        later upstream response is a late response. A pending drain then settles HELD."""
        action = next((a for a in self.actions.values() if a.get("conn") == event["conn"] and a["status"] == "CONSUMED"), None)
        require(action is not None, "timeout without an outstanding exchange")
        after = action.get("afterInvalidation", False)
        self._record("TERMINAL", action["actionId"], "IO_AMBIGUOUS", after, {"aborted": "UPSTREAM_TIMEOUT"})
        action.update(status="TERMINAL", classification="IO_AMBIGUOUS")
        self.state = "HELD"
        self.connections[event["conn"]]["state"] = "CLOSED"
        return {"classification": "IO_AMBIGUOUS", "relayed": False, "aborted": "UPSTREAM_TIMEOUT"}

    def _drain(self) -> dict:
        """I07 WRITE_BEGIN, in any state. From ACTIVE or INSPECTING it is the gate's own normal drain
        (DRAINING); in every state it denies an armed action and waits for the A3 fence. The answer is
        PENDING until the fence is decided, then OPEN or HELD (see `_settle_drain`)."""
        armed = self._armed_ids()
        if self.state in ("ACTIVE", "INSPECTING"):
            self.state = "DRAINING"
        if not self.drain_pending:
            self.drain_pending = True
            self._record("DRAIN_STARTED")
        self._deny_armed()
        answer = self._settle_drain()
        return {"denied": self._denied_since(armed), "drain": answer or "PENDING"}

    def _settle_drain(self) -> str | None:
        """A pending drain settles once its fence is decided: a DRAINING generation with nothing in flight
        becomes CLOSED (HELD if an action is ambiguous); then the fence is OPEN or HELD. The DRAINED record
        is written, drainPending clears and the answer goes to I07. A failed DRAINED record holds the
        generation, so the answer is then HELD."""
        if not self.drain_pending:
            return None
        if self.state == "DRAINING" and self._in_flight() is None:
            ambiguous = any(a.get("classification") == "IO_AMBIGUOUS" for a in self.actions.values())
            self.state = "HELD" if ambiguous else "CLOSED"
        if self.fence() == "PENDING":
            return None
        self.drain_pending = False
        self._record("DRAINED", self.state)
        return self.fence()

    # -- I05 frames
    def _frame(self, frame: Any, schema: dict) -> dict:
        if self.channel == "CLOSED":
            return {"refusedChannel": "GENERATION_CHANNEL_USED"}
        try:
            check_frame(frame, schema)
        except ValueError as exc:
            return self._fatal(str(exc).split(" ", 1)[0] + "_INVALID_FRAME")
        if frame["direction"] != "BROKER_TO_GATE" or frame["sequence"] % 2 != 1:
            return self._fatal("DIRECTION")
        if frame["sequence"] != self.next_sequence or frame["previousDigest"] != self.last_digest:
            return self._fatal("CHAIN_BROKEN")
        if frame["generation"] != self.generation:
            return self._fatal("GENERATION_MISMATCH")
        if self.channel == "UNOPENED":
            if frame["operation"] != "GENERATION_STATUS":
                return self._fatal("OPENING_FRAME_REQUIRED")
            self.channel, self.challenge = "OPEN", frame["challenge"]
        elif frame["challenge"] != self.challenge:
            return self._fatal("CHALLENGE_MISMATCH")
        payload = getattr(self, "_op_" + frame["operation"].lower())(frame["payload"])
        if payload.get("fatal"):
            return payload
        response = {"schemaVersion": FRAME_VERSION, "generation": self.generation, "challenge": self.challenge,
                    "sequence": frame["sequence"] + 1, "previousDigest": frame_digest(frame),
                    "direction": "GATE_TO_BROKER", "operation": frame["operation"], "payload": payload}
        check_frame(response, schema)
        self.next_sequence = frame["sequence"] + 2
        self.last_digest = frame_digest(response)
        return {"response": payload}

    def _refused(self, reason: str) -> dict:
        return {"result": "REFUSED", "reason": reason}

    def _op_generation_status(self, payload: dict) -> dict:
        armed, in_flight = self._armed(), self._in_flight()
        return {"result": "OK", "state": self.state, "drainPending": self.drain_pending,
                "boundExecutionId": self.bound["executionId"] if self.bound else None,
                "armedActionId": armed["actionId"] if armed else None,
                "inFlightActionId": in_flight["actionId"] if in_flight else None,
                "counters": dict(self.counters), "journalDigest": sha(canonical(self.journal))}

    def _op_bind_execution(self, p: dict) -> dict:
        if p["peerQualificationDigest"] != self.peer:
            return self._fatal("PEER_QUALIFICATION_MISMATCH")
        if self.state != "ACTIVE":
            return self._refused("NOT_ACTIVE")
        if any(a["status"] != "TERMINAL" or not a["sealed"] for a in self.actions.values()):
            return self._refused("ACTION_OUTSTANDING")
        if p["executionId"] in self.bound_ids or p["runNonce"] in self.bound_nonces \
                or p["executionId"] in self.prior_ids or p["runNonce"] in self.prior_nonces:
            return self._refused("EXECUTION_REPLAY")     # durable across generations
        if p["dispatchGeneration"] != self.generation:
            return self._refused("GENERATION_MISMATCH")
        run = self.runs.get(p["runNonce"])
        if run is None or any(run[k] != p[k] for k in ("bindingDigest", "caseId", "requestDigest")):
            return self._refused("UNKNOWN_BINDING")
        if p["serverCertificateDigest"] != run["serverCertificateDigest"]:
            return self._refused("CERTIFICATE_MISMATCH")
        digests = sorted(run["manifests"])
        identities = sorted(identity_of(self.manifests[d]) for d in digests)
        if any(d in self.prior_digests for d in digests) or any(i in self.prior_identities for i in identities):
            return self._refused("MANIFEST_REUSED")      # a run never re-uses an earlier generation's manifest
        failed = self._observe_worker(p["workerPid"], p["workerStartTicks"])
        self.observations.append({"workerPid": p["workerPid"], "workerStartTicks": p["workerStartTicks"],
                                  "result": "OBSERVED" if failed is None else failed[1],
                                  "step": None if failed is None else failed[0]})
        if failed is not None:
            return self._refused("WORKER_NOT_OBSERVED")   # Q-I5-2: one wire answer; the cause stays local
        if not self._record("BIND", p["executionId"], p["runNonce"], p["reservationDigest"], digests, identities):
            return self._refused("STORAGE_FAILURE")
        self.bound = {"executionId": p["executionId"], "runNonce": p["runNonce"]}
        self.expired, self.actions, self.mutation_keys, self.created_uids = False, {}, set(), {}
        self.bound_ids.append(p["executionId"])
        self.bound_nonces.append(p["runNonce"])
        return {"result": "OK", "executionId": p["executionId"], "caseManifestSetDigest": sha(canonical(digests))}

    def _op_arm_action(self, p: dict) -> dict:
        if self.state != "ACTIVE":
            return self._refused("DRAIN_PENDING" if self.state == "DRAINING" else "NOT_ACTIVE")
        if self.bound is None or p["executionId"] != self.bound["executionId"]:
            return self._refused("EXECUTION_NOT_BOUND")
        if self.expired:
            return self._refused("EXECUTION_EXPIRED")
        if any(a["status"] != "TERMINAL" or not a["sealed"] for a in self.actions.values()):
            return self._refused("ACTION_OUTSTANDING")
        if p["actionId"] != len(self.actions) + 1:
            return self._refused("ACTION_ID_OUT_OF_ORDER")
        run = self.runs[self.bound["runNonce"]]
        manifest = self.manifests.get(p["manifestDigest"])
        if manifest is None or p["manifestDigest"] not in run["manifests"]:
            return self._refused("MANIFEST_OUTSIDE_CASE")
        if (p["verb"] == "DELETE") != (p["recordedUid"] is not None):
            return self._refused("UID_RULE")              # only DELETE carries the recorded-UID precondition
        if p["verb"] == "DELETE" and p["recordedUid"] not in self.created_uids.get(p["manifestDigest"], set()):
            return self._refused("UID_NOT_CREATED")       # the UID must come from this execution's own CREATE 201
        expected = template_digest(p["verb"], manifest["apiVersion"], manifest["kind"], manifest["namespace"],
                                   manifest["name"], p["recordedUid"], p["manifestDigest"])
        if p["requestTemplateDigest"] != expected:
            return self._refused("TEMPLATE_MISMATCH")
        key = ("CREATE", p["manifestDigest"]) if p["verb"] == "CREATE" else ("DELETE", p["recordedUid"]) \
            if p["verb"] == "DELETE" else None
        if key is not None and key in self.mutation_keys:
            return self._refused("MUTATION_KEY_REUSED")   # C7
        # C2: close every unconsumed connection and drain the listen backlog before recording ARM.
        flushed = self._close_connections(lambda c: not c["consumed"])
        for conn in self.backlog:
            self.connections[conn] = {"stamp": None, "state": "CLOSED", "requests": 0, "consumed": False}
        flushed += len(self.backlog)
        self.counters["flushClosures"] += len(self.backlog)
        self.backlog = []
        if not self._record("ARM", p["actionId"], p["verb"], p["manifestDigest"], p["recordedUid"], expected):
            return self._refused("STORAGE_FAILURE")
        if key is not None:
            self.mutation_keys.add(key)
        self.actions[p["actionId"]] = {"actionId": p["actionId"], "verb": p["verb"], "manifestDigest": p["manifestDigest"],
                                       "uid": p["recordedUid"], "templateDigest": expected, "status": "ARMED",
                                       "sealed": False}
        return {"result": "OK", "actionId": p["actionId"], "flushedConnections": flushed}

    def _op_action_outcome(self, p: dict) -> dict:
        if self.bound is None or p["executionId"] != self.bound["executionId"]:
            return self._refused("EXECUTION_NOT_BOUND")
        action = self.actions.get(p["actionId"])
        if action is None:
            return self._refused("UNKNOWN_ACTION")
        if not action["sealed"]:
            # Sealing: from here on the action can never be consumed, and its classification never changes.
            if action["status"] == "ARMED":
                stamp = self._stamp_of(action)
                self._close_connections(lambda c: c["stamp"] == stamp and not c["consumed"])
                action.update(status="TERMINAL", classification="NOT_FORWARDED")
            elif action["status"] == "CONSUMED":
                # Still in flight: the gate aborts the upstream exchange and closes the server connection.
                self.connections[action["conn"]]["state"] = "CLOSED"
                action.update(status="TERMINAL", classification="IO_AMBIGUOUS")
                self.state = "HELD"
            if not self._record("SEALED", action["actionId"], action["classification"], action.get("afterInvalidation", False)):
                return self._refused("STORAGE_FAILURE")
            action["sealed"] = True
        delivered = action["classification"] == "DELIVERED_RESULT"
        return {"result": "OK", "actionId": action["actionId"], "classification": action["classification"],
                "admittedBeforeInvalidation": action.get("afterInvalidation", False) and action["classification"] != "NOT_FORWARDED",
                "httpStatus": action.get("httpStatus") if delivered else None,
                "resultDigest": action.get("resultDigest") if delivered else None,
                "observedUid": action.get("observedUid") if delivered else None,
                "observedResourceVersion": action.get("observedResourceVersion") if delivered else None}

    def _op_close_generation(self, p: dict) -> dict:
        reason = p["reason"]
        armed = self._armed_ids()
        if self.state in ("CLOSED", "INVALIDATED", "HELD"):
            if reason == "RECONCILIATION_REQUIRED" and self.state != "HELD":
                self.state = "HELD"
                self._record("INVALIDATED", reason, "HELD")
            self._deny_armed()
            return {"result": "OK", "state": self.state, "deniedActionIds": self._denied_since(armed)}
        if reason == "NORMAL_DRAIN":
            if self._in_flight() is not None:
                return self._refused("ACTION_IN_FLIGHT")
            ambiguous = any(a.get("classification") == "IO_AMBIGUOUS" for a in self.actions.values())
            self.state = "HELD" if ambiguous else "CLOSED"
            self._record("CLOSED", reason, self.state)
            self._deny_armed()
            return {"result": "OK", "state": self.state, "deniedActionIds": self._denied_since(armed)}
        # The broker's own disagreement or missing outcome ends the gate's generation HELD as well.
        self._urgent("HELD" if reason == "RECONCILIATION_REQUIRED" else "INVALIDATED", reason)
        return {"result": "OK", "state": self.state, "deniedActionIds": self._denied_since(armed)}


def _apply(value: Any, ops: list) -> Any:
    value = copy.deepcopy(value)
    for op in ops:
        *parents, last = op["path"]
        node = value
        for key in parents:
            node = node[key]
        if op["op"] == "set":
            node[last] = copy.deepcopy(op["value"])
        else:
            require(op["op"] == "delete", "closed mutation operation")
            del node[last]
    return value


def convert_v3_config(config: dict) -> dict:
    """A v3 configuration as v4 sees it: each observedWorkers entry becomes a live member of the probe-worker cgroup."""
    converted = copy.deepcopy(config)
    workers = converted.pop("observedWorkers")
    converted["kernel"] = {"processes": [{"pid": pid, "startTicks": start, "cgroup": PROBE_WORKER_CGROUP}
                                         for pid, start in workers]}
    return converted


def replay_observed(config: dict, events: list, schema: dict) -> tuple[list, dict, list]:
    """`replay`, also returning the local observation log."""
    gate, outputs = _run(config, events, schema)
    return outputs, gate.snapshot(), copy.deepcopy(gate.observations)


def replay(config: dict, events: list, schema: dict) -> tuple[list, dict]:
    """Replay one transcript; returns every event's output and the final snapshot. A FRAME event
    names the broker's operation and payload; the replay builds the envelope a correct broker
    would send next (sequence, previous digest, generation and channel challenge) and then
    applies the event's mutations, so invalid frames are exact deviations from a valid one."""
    gate, outputs = _run(config, events, schema)
    return outputs, gate.snapshot()


def _run(config: dict, events: list, schema: dict) -> tuple[Gate, list]:
    gate = Gate(copy.deepcopy(config))
    outputs = []
    for event in events:
        event = copy.deepcopy(event)
        if event["type"] == "FRAME":
            frame = {"schemaVersion": FRAME_VERSION, "generation": config["generation"],
                     "challenge": config["brokerChallenge"], "sequence": gate.next_sequence,
                     "previousDigest": gate.last_digest, "direction": "BROKER_TO_GATE",
                     "operation": event["operation"], "payload": event["payload"]}
            event = {"type": "FRAME", "frame": _apply(frame, event.get("mutate", []))}
        outputs.append(gate.handle(event, schema))
    return gate, outputs


# -- data check of the v4 vectors
VECTORS_VERSION = "planeon.internal.effect-gate-model-vectors/v4"
V3_FILES = {"schema": "architecture/i05-gate-channel-v3/channel.schema.json",
            "outcomeMapping": "architecture/i05-gate-channel-v3/outcome-mapping.json",
            "vectors": "architecture/i05-gate-channel-v3/vectors.json",
            "supplement": "architecture/i05-gate-channel-v3-supplement/vectors.json"}
V3_FLOORS = {"transcripts": 120, "agreement": 42, "frames": 34, "byteFrames": 14, "configRefusals": 5}
SUPPLEMENT_FLOOR = 6
V4_FLOORS = {"transcripts": 20, "orderTranscripts": 9, "configRefusals": 9, "eventRefusals": 9}
REFUSAL_PREFIX = {"configRefusals": "C", "eventRefusals": "M"}      # M: malformed model events (not the E01-E12 claims)
# Every BIND answer that comes before the observation (README "The observation"): a BIND refused this way is never
# observed, whatever its worker. A fatal answer is named "FATAL:" plus its reason.
BEFORE_OBSERVATION = ("FATAL:OPENING_FRAME_REQUIRED", "FATAL:PEER_QUALIFICATION_MISMATCH", "NOT_ACTIVE", "ACTION_OUTSTANDING", "EXECUTION_REPLAY",
                      "GENERATION_MISMATCH", "UNKNOWN_BINDING", "CERTIFICATE_MISMATCH", "MANIFEST_REUSED")
# The BIND answers that follow an observation: bound, refused by it, or refused by the BIND record's storage failure.
AFTER_OBSERVATION = ("OK", "WORKER_NOT_OBSERVED", "STORAGE_FAILURE")
INPUT_TYPES = {"bytes": bytes, "bytearray": bytearray, "str": lambda raw: raw.decode("ascii")}
# OBSERVING = v3's ACTIVE converted (4100 and 4200 in the leaf), plus these two processes, exactly.
OUTSIDER = {"pid": 5100, "startTicks": 800001, "cgroup": "/planeon.slice/planeon-proxy-server.service"}
OBSERVING_EXTRA = ({"pid": 4300, "startTicks": 900003, "cgroup": PROBE_WORKER_CGROUP}, OUTSIDER)
# The v4 configurations: each is a v3 configuration converted, plus exactly these processes (the order transcripts' two
# other configurations add only the process outside the leaf; v3's LATER already lists 4300).
V4_CONFIGS = {"OBSERVING": ("ACTIVE", OBSERVING_EXTRA), "OBSERVING_INSPECTING": ("INSPECTING", (OUTSIDER,)),
              "OBSERVING_LATER": ("LATER", (OUTSIDER,))}


def _refusal(call) -> str | None:
    try:
        call()
    except ValueError as exc:
        return str(exc)
    return None


def _strict_base64(value: Any) -> bytes:
    require(type(value) is str, "byte vector encoding")
    try:
        raw = base64.b64decode(value, validate=True)
    except ValueError as exc:          # binascii.Error is a ValueError
        raise ValueError("byte vector encoding") from exc
    require(base64.b64encode(raw).decode("ascii") == value, "noncanonical byte vector")
    return raw


def _without(value: dict, key: str) -> dict:
    return {k: v for k, v in value.items() if k != key}


def bind_answer(output: dict) -> str:
    """A BIND event's answer as one name: OK, a refusal reason, or FATAL: plus the fatal reason."""
    if "response" in output:
        response = output["response"]
        return "OK" if response.get("result") == "OK" else response["reason"]
    require(set(output) >= {"fatal"}, "a BIND answer")
    return "FATAL:" + output["fatal"]


def _paired(events: list, outputs: list, observations: list, label: str) -> list:
    """Pair the observation log with the BINDs that reach the observation, in order; a BIND answered before it has none."""
    reached = []
    for event, output in zip(events, outputs):
        if event.get("type") == "FRAME" and event.get("operation") == "BIND_EXECUTION":
            answer = bind_answer(output)
            require(answer in AFTER_OBSERVATION or answer in BEFORE_OBSERVATION, "a known BIND answer in " + label)
            if answer in AFTER_OBSERVATION:
                reached.append(answer)
    require(len(reached) == len(observations), "one observation per BIND that reaches it in " + label)
    for answer, seen in zip(reached, observations):
        require((seen["result"] == "OBSERVED") == (answer != "WORKER_NOT_OBSERVED")
                and (seen["result"] == "OBSERVED") == (seen["step"] is None),
                "the observation decides the BIND in " + label)
    return reached


def check_vectors(vectors: Any, files: dict) -> int:
    """DATA_CHECK_ONLY: replay every v4 vector, and every v3 and supplement vector under v4.

    `files` maps each v3 path the vectors pin (V3_FILES) to its bytes, which must match the pinned SHA-256.
    Returns the number of checks; any mismatch raises ValueError."""
    require(type(vectors) is dict and set(vectors) == {"schemaVersion", "evidenceClass", "modelVersion", "frameVersion", "v3",
                                                       "v3Replay", "configs", "configRefusals", "eventRefusals",
                                                       "transcripts", "orderTranscripts"}
            and vectors["schemaVersion"] == VECTORS_VERSION and vectors["evidenceClass"] == "DATA_CHECK_ONLY"
            and vectors["modelVersion"] == MODEL_VERSION and vectors["frameVersion"] == FRAME_VERSION
            and type(vectors["v3Replay"]) is str
            and all(type(vectors[key]) is list and len(vectors[key]) >= floor for key, floor in V4_FLOORS.items()),
            "closed I05 v4 vectors")
    require(type(vectors["v3"]) is dict and set(vectors["v3"]) == set(V3_FILES), "the pinned v3 inputs")
    pinned = {}
    for key, path in V3_FILES.items():
        require(type(files.get(path)) is bytes
                and vectors["v3"][key] == {"path": path, "sha256": hashlib.sha256(files[path]).hexdigest()},
                "the pinned v3 input " + path)
        pinned[key] = json.loads(files[path].decode("utf-8"), object_pairs_hook=_strict_pairs)
    schema, mapping, v3, supplement = pinned["schema"], pinned["outcomeMapping"], pinned["vectors"], pinned["supplement"]
    require(schema.get("$id") == "urn:planeon:internal:effect-gate-frame:v3", "the wire stays the v3 frame schema")
    require(set(v3["configs"]) == {"ACTIVE", "INSPECTING", "LATER"}
            and all(len(v3[key]) >= floor for key, floor in V3_FLOORS.items())
            and len(supplement["transcripts"]) >= SUPPLEMENT_FLOOR, "the v3 vectors and supplement")
    checks = 0
    # 1. v3 and its supplement replay unchanged under v4, each configuration converted (no wire change).
    # The supplement names its configuration by reference into the v3 vectors file.
    require(set(supplement["configs"]) == {"ACTIVE"} and supplement["configs"]["ACTIVE"]
            == {"vectorsPath": V3_FILES["vectors"], "key": ["configs", "ACTIVE"]}, "the supplement uses v3's ACTIVE")
    for source, configs in ((v3, v3["configs"]), (supplement, {"ACTIVE": v3["configs"]["ACTIVE"]})):
        for row in source["transcripts"]:
            outputs, final = replay(convert_v3_config(configs[row["config"]]), row["events"], schema)
            require(outputs == row["outputs"] and final == row["final"], "v3 transcript under v4 " + row["id"])
            checks += 1
    for row in v3["configRefusals"]:
        got = _refusal(lambda: Gate(convert_v3_config(dict(v3["configs"]["ACTIVE"], **row["override"]))))
        require(got is not None and got == row["expect"], "v3 configuration refusal under v4 " + row["id"])
        checks += 1
    for row in v3["agreement"]:
        require(check_agreement(mapping, row["verb"], row["identity"], row["outcome"], row["resourceResult"]) == row["expect"],
                "v3 agreement under v4 " + row["id"])
        checks += 1
    for row in v3["frames"]:
        require(_refusal(lambda: check_frame(row["frame"], schema)) == row["expect"], "v3 frame under v4 " + row["id"])
        checks += 1
    for row in v3["byteFrames"]:
        raw = INPUT_TYPES[row["inputType"]](_strict_base64(row["base64"]))
        require(_refusal(lambda: decode_frame(raw, schema)) == row["expect"], "v3 byte frame under v4 " + row["id"])
        checks += 1
    # 2. The v4 configurations: each a v3 configuration with its static list replaced by the kernel's process table.
    configs = vectors["configs"]
    require(type(configs) is dict and set(configs) == set(V4_CONFIGS), "the v4 configurations")
    for name, (source, extra) in V4_CONFIGS.items():
        Gate(copy.deepcopy(configs[name]))
        converted = convert_v3_config(v3["configs"][source])
        require(_without(configs[name], "kernel") == _without(converted, "kernel")
                and configs[name]["kernel"]["processes"] == converted["kernel"]["processes"] + list(extra),
                name + " is v3's " + source + " converted, plus exactly its listed processes")
    observing = configs["OBSERVING"]
    for key, call in (("configRefusals", lambda row: Gate(dict(copy.deepcopy(observing), **copy.deepcopy(row["override"])))),
                      ("eventRefusals", lambda row: _run(observing, row["events"], schema))):
        ids = [row.get("id") for row in vectors[key]]
        require(ids == [REFUSAL_PREFIX[key] + "%02d" % n for n in range(1, len(ids) + 1)], key + " in order")
        for row in vectors[key]:
            require(type(row) is dict and set(row) == {"id", "intent", "override" if key == "configRefusals" else "events",
                                                       "expect"}, "closed " + key + " row")
            got = _refusal(lambda: call(row))
            require(got is not None and got == row["expect"], key + " " + row["id"])
            checks += 1
    # 3. The gate's observation at each BIND (Q-I5-1..4).
    ids = [row.get("id") for row in vectors["transcripts"]]
    require(ids == ["O%02d" % n for n in range(1, len(ids) + 1)], "observation transcripts in order")
    outcomes, recached, stored = set(), False, False
    for row in vectors["transcripts"]:
        require(type(row) is dict and set(row) == {"id", "intent", "config", "events", "outputs", "final", "observations"}
                and row["config"] == "OBSERVING", "closed transcript " + row["id"])
        require(not any(event.get("mutate") for event in row["events"]), "observation transcripts send unmutated frames")
        gate, outputs = _run(observing, row["events"], schema)
        require(outputs == row["outputs"] and gate.snapshot() == row["final"] and gate.observations == row["observations"],
                "I05 v4 transcript " + row["id"])
        require(not gate.observation_fails and not gate.observation_races, "every injection is consumed in " + row["id"])
        binds = [n for n, event in enumerate(row["events"]) if event.get("operation") == "BIND_EXECUTION"]
        require(len(_paired(row["events"], outputs, gate.observations, row["id"])) == len(binds),
                "every BIND of an observation transcript reaches the observation: " + row["id"])
        for n, seen in zip(binds, gate.observations):
            answer = outputs[n].get("response", {})
            if seen["result"] == "OBSERVED":
                # Observed: it binds, or its BIND record fails after the observation (STORAGE_FAILURE, v3's rule).
                require(seen["step"] is None and bind_answer(outputs[n]) in ("OK", "STORAGE_FAILURE"),
                        "an observed worker binds, or its record fails, in " + row["id"])
                stored |= bind_answer(outputs[n]) == "STORAGE_FAILURE"
            else:
                # Q-I5-2: one wire answer, non-fatal, and nothing durable: the gate's snapshot is unchanged.
                before = _run(observing, row["events"][:n], schema)[0].snapshot()
                require((seen["step"], seen["result"]) in OBSERVATION_OUTCOMES
                        and outputs[n] == {"response": {"result": "REFUSED", "reason": "WORKER_NOT_OBSERVED"}}
                        and _run(observing, row["events"][:n + 1], schema)[0].snapshot() == before,
                        "a refused observation is WORKER_NOT_OBSERVED and records nothing in " + row["id"])
            outcomes.add((seen["step"], seen["result"]))
        # Q-I5-1: no cached answer: the same worker observed at one BIND is refused at a later one once the kernel moved on.
        seen = [(o["workerPid"], o["workerStartTicks"], o["result"]) for o in gate.observations]
        recached |= any(a[:2] == b[:2] and a[2] == "OBSERVED" and b[2] != "OBSERVED"
                        for i, a in enumerate(seen) for b in seen[i + 1:])
        checks += 1
    require(outcomes == set(OBSERVATION_OUTCOMES) | {(None, "OBSERVED")}, "every step's every outcome is exercised")
    require(recached, "a later BIND re-observes a worker observed earlier (Q-I5-1)")
    require(stored, "an observed BIND whose record then fails keeps its log entry")
    # 4. The order: a BIND answered before the observation is never observed, even when it names a non-member.
    ids = [row.get("id") for row in vectors["orderTranscripts"]]
    require(ids == ["OB%02d" % n for n in range(1, len(ids) + 1)], "order transcripts in order")
    covered, v3_rows = set(), {row["id"]: row for row in v3["transcripts"]}
    for row in vectors["orderTranscripts"]:
        require(type(row) is dict and set(row) == {"id", "intent", "from", "config", "events", "outputs", "final",
                                                   "observations", "answer"} and row["config"] in V4_CONFIGS,
                "closed order transcript")
        # Exactly a v3 transcript's prefix in that v3 configuration, its last BIND naming the process outside the leaf.
        source = v3_rows[row["from"]["transcript"]]
        index = row["from"]["event"]
        expected = copy.deepcopy(source["events"][:index + 1])
        require(type(index) is int and set(row["from"]) == {"transcript", "event"} and 0 <= index < len(source["events"])
                and expected[-1].get("operation") == "BIND_EXECUTION"
                and V4_CONFIGS[row["config"]][0] == source["config"], "an order transcript names its v3 source")
        expected[-1]["payload"]["workerPid"], expected[-1]["payload"]["workerStartTicks"] = OUTSIDER["pid"], OUTSIDER["startTicks"]
        require(row["events"] == expected, "an order transcript is its v3 prefix with only the worker replaced: " + row["id"])
        gate, outputs = _run(configs[row["config"]], row["events"], schema)
        require(outputs == row["outputs"] and gate.snapshot() == row["final"] and gate.observations == row["observations"],
                "I05 v4 order transcript " + row["id"])
        require(not gate.observation_fails and not gate.observation_races, "every injection is consumed in " + row["id"])
        require(bind_answer(outputs[-1]) == row["answer"] and row["answer"] in BEFORE_OBSERVATION
                and bind_answer(source["outputs"][index]) == row["answer"],
                "an order transcript ends in v3's answer, given before the observation: " + row["id"])
        # The worker it names is not a member of the leaf in the kernel at that BIND.
        before = _run(configs[row["config"]], row["events"][:-1], schema)[0]
        require(OUTSIDER["pid"] not in [p for p, proc in before.kernel.items() if proc["cgroup"] == PROBE_WORKER_CGROUP],
                "its worker is not a member at the BIND: " + row["id"])
        _paired(row["events"], outputs, gate.observations, row["id"])
        covered.add(row["answer"])
        checks += 1
    require(covered == set(BEFORE_OBSERVATION), "every answer before the observation is pinned with a non-member")
    return checks
