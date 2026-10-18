#!/usr/bin/env python3
"""v4 native qualification record: expected/native-capture DATA consistency only.

Reference model for `planeon.internal.native-qualification/v4` (profile
SELINUX_FSVERITY_CGROUP_BPF_V4), the successor of the adopted v3 contract: v3 plus
O-NATIVE-GATE-NOCAP, the capture routes (the observer as capturer, evidence classes per role
and recorded capability set, entrypoint label constants and closures) and the inspector
obligation restated. It never inspects a kernel, never mints a native handle and never grants
authority; every result is DATA_CHECK_ONLY. The v1, v2 and v3 schemas, vectors and models are
unchanged.

`check_*` functions raise with the first refused rule. A single check is NOT an
acceptance decision: only `check_qualification` combines the record, one capture per
resident role, the lifecycle capture (containment absence, planeon-slice census and own
members, host-wide planeon process counts), one observation per backend component and the
earlier-version (v1, v2 and v3) migration rules for one boot and validity window. A record whose implementation
profile is test-only qualifies only when the caller asks for a test fixture.

Caller obligations (not checked here):
- `profile` is already valid under the pinned proxy profile contract
  (`scripts/validate_proxy_contract.py`, `validate_profile`); this model only adds the
  binding-nonce label rule and the earlier-version nonce scan;
- `v1_records`, `v2_records` and `v3_records` are the host's complete retained v1, v2 and v3
  enrollment histories, or `no_earlier_history` is set because all three are attested empty;
- the inspector is the observer, which never freezes and never writes any cgroup.freeze. It
  reports a per-process field only when it holds for every thread (`threadsUniform`), reads
  the (pid, start) member set and each member's (tid, start) thread set before and after the
  process reads, through pidfds or a held /proc/<pid> directory descriptor, and reads the
  probe-worker leaf only inside a frozen bracket the broker holds (cgroup.events frozen 1
  before and after). The declared premises and their T04 proofs are in the README.
"""
from __future__ import annotations

import copy
import hashlib
import ipaddress
import json
import re
from datetime import datetime
from typing import Any

import jsonschema

SCHEMA_SHA256 = "3bf244b21f91e30062ad56a7a21f3f0b4554daa71a0c3b624bcac058fee58d80"
V1_SCHEMA_SHA256 = "8e184d60df63863bc627c1655887c32012490e3c7211f8f9a38baee67f64d4cf"
V2_SCHEMA_SHA256 = "fd1657c9a9ea437df2d48f03c69a1de62013a47a9fc62ad7776db2fc7029c0c5"
V3_SCHEMA_SHA256 = "1c7930351e58a12cdf8bf8ef0df1f971eddceb8d17268f73541425258e9657d2"
V4_RECORD = ("planeon.internal.native-qualification/v4", "SELINUX_FSVERITY_CGROUP_BPF_V4")
V4_CAPTURE = "planeon.internal.native-qualification-capture/v4"
V4_LIFECYCLE = "planeon.internal.native-qualification-lifecycle/v4"
V4_BACKEND = "planeon.internal.native-qualification-backend/v4"
SEAL_VERSION = "planeon.internal.containment-seal/v1"
ROLES = ("SERVER", "OBSERVER", "BROKER", "WORKER", "EFFECT_GATE")
SINGLE_PROCESS_ROLES = ("SERVER", "OBSERVER", "BROKER", "EFFECT_GATE")
LIFECYCLE = ("HOST_CONTAINMENT", "POLICY_WRITER")
HOOKS = ("INET_SOCK_CREATE", "INET4_BIND", "INET6_BIND", "INET4_CONNECT", "INET6_CONNECT",
         "UDP4_SENDMSG", "UDP6_SENDMSG")
HOOK_DIRS = {hook: hook.lower().replace("_", "-") for hook in HOOKS}
ROLE_DIRS = {"SERVER": "proxy-server", "OBSERVER": "policy-observer", "BROKER": "capacity-broker",
             "WORKER": "probe-worker", "EFFECT_GATE": "effect-gate"}
DELEGATED_CHILDREN = ["broker", "probe-worker"]
BROKER_SERVICE = "/sys/fs/cgroup/planeon.slice/planeon-capacity-broker.service"
# Native-only roles may list nothing from the enrolled interpreter's installation tree (round 2, W4).
INTERPRETER_TREE = "/opt/planeon/python/"
# Closed kernel command-line grammar (rounds 5-6, R4-1, R5-1; W02 notes errata R6-1). Every word of the enrolled
# entry is one of these kernel parameters: none names a unit or carries a unit-bearing value, root=, ro and rw only
# drive systemd's fixed root-mount units, and none reaches init's arguments. "--" and every later word, systemd.*,
# rd.* and SYSTEMD_* words, runlevel words, root mount options (rootflags= carries x-systemd.* dependencies),
# console= (getty-generator adds a serial getty) and every other word are refused. The maintenance entry is the
# enrolled entry plus MAINTENANCE_UNIT once, so both name the same initrd= files and root= device; the kernel
# image or UKI an entry loads is not on its command line. The grammar is widened only through a reviewed revision
# of this contract.
KERNEL_PARAMETERS = tuple(re.compile(pattern) for pattern in (
    r"initrd=[A-Za-z0-9_./\\+-]+", r"root=(UUID|PARTUUID|LABEL)=[A-Za-z0-9_.-]+", r"root=/dev/[A-Za-z0-9_/.-]+",
    r"ro", r"rw", r"security=selinux", r"selinux=1", r"enforcing=1", r"lockdown=integrity", r"quiet",
    r"loglevel=[0-7]"))
MAINTENANCE_UNIT = "systemd.unit=planeon-maintenance.target"
PIN_ROOT = "/sys/fs/bpf/planeon"
CGROUP_ROOT = "/sys/fs/cgroup"
SLICE = CGROUP_ROOT + "/planeon.slice"
REQUIRED_BACKEND = ("APISERVER", "DATASTORE", "CONTROLLER_MANAGER", "SCHEDULER", "KUBELET", "CONTAINER_RUNTIME")
NO_API_CLIENT = ("DATASTORE", "CONTAINER_RUNTIME")
ROLE_DOMAINS = {"SERVER": "planeon_server_t", "OBSERVER": "planeon_observer_t", "BROKER": "planeon_broker_t",
                "WORKER": "planeon_worker_t", "EFFECT_GATE": "planeon_gate_t"}
# Evidence classes of the P1 captures (README "Evidence classes"): BROKER and WORKER are LABEL_BOUND for every
# capability set, SERVER only with CAP_NET_BIND_SERVICE recorded, EFFECT_GATE is OBSERVED, and the observer's own
# capture holds cgroup-level facts only (DECLARED_T04, T04-OBSERVER-IDENTITY).
LABEL_BOUND_ROLES = ("BROKER", "WORKER")
# Seccomp_filters in /proc/<pid>/status corroborates the declared filter (T04-SECCOMP-INSTALLED): the worker keeps the
# broker's inherited filter and adds its own (HS43 HOST_INTERFACE_SPEC.md BROKER row, W02d-QD); every other role runs
# under exactly one.
SECCOMP_FILTERS = {"SERVER": 1, "OBSERVER": 1, "BROKER": 1, "WORKER": 2, "EFFECT_GATE": 1}
# Static native roles load a single-file closure, their executable (T04-MAPS-STATIC).
STATIC_ROLES = ("OBSERVER", "BROKER")
# Every cgroup BPF attach type of Linux v6.12 (to_cgroup_bpf_attach_type plus BPF_LSM_CGROUP); the seven containment
# hooks are observed per hook, and the effective census covers the rest.
HOOK_ATTACH_TYPES = tuple("BPF_CGROUP_" + hook for hook in HOOKS)
CENSUS_ATTACH_TYPES = ("BPF_CGROUP_INET_INGRESS", "BPF_CGROUP_INET_EGRESS", "BPF_CGROUP_SOCK_OPS", "BPF_CGROUP_DEVICE",
                       "BPF_CGROUP_UNIX_CONNECT", "BPF_CGROUP_INET4_POST_BIND", "BPF_CGROUP_INET6_POST_BIND",
                       "BPF_CGROUP_UNIX_SENDMSG", "BPF_CGROUP_SYSCTL", "BPF_CGROUP_UDP4_RECVMSG",
                       "BPF_CGROUP_UDP6_RECVMSG", "BPF_CGROUP_UNIX_RECVMSG", "BPF_CGROUP_GETSOCKOPT",
                       "BPF_CGROUP_SETSOCKOPT", "BPF_CGROUP_INET4_GETPEERNAME", "BPF_CGROUP_INET6_GETPEERNAME",
                       "BPF_CGROUP_UNIX_GETPEERNAME", "BPF_CGROUP_INET4_GETSOCKNAME", "BPF_CGROUP_INET6_GETSOCKNAME",
                       "BPF_CGROUP_UNIX_GETSOCKNAME", "BPF_CGROUP_INET_SOCK_RELEASE", "BPF_LSM_CGROUP")
MAX_BYTES = 262144
PLANEON_CODE_BYTES = 536870912
BACKEND_CODE_BYTES = 4294967296
TIME = "%Y-%m-%dT%H:%M:%SZ"


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(message)


def canonical(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, ensure_ascii=False, separators=(",", ":"),
                      allow_nan=False).encode("utf-8")


def digest(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def parse(raw: bytes) -> Any:
    def unique(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            require(key not in result, "duplicate member")
            result[key] = value
        return result

    def no_constant(_value: str) -> Any:
        raise ValueError("nonfinite number")

    return json.loads(raw, object_pairs_hook=unique, parse_constant=no_constant)


def _bounded(value: Any, depth: int = 0, budget: list[int] | None = None) -> None:
    budget = [MAX_BYTES] if budget is None else budget
    require(depth <= 16, "depth exceeded")
    kind = type(value)
    require(kind in (dict, list, str, int, bool, type(None)), "non-data value")
    budget[0] -= len(value) if kind is str else 1
    require(budget[0] >= 0, "size exceeded")
    if kind is int:
        require(abs(value) <= 9007199254740991, "integer overflow")
    elif kind is str:
        require(all(32 <= ord(char) <= 126 for char in value), "ASCII data required")
    elif kind is dict:
        for key, item in value.items():
            require(type(key) is str, "string key required")
            _bounded(key, depth + 1, budget)
            _bounded(item, depth + 1, budget)
    elif kind is list:
        for item in value:
            _bounded(item, depth + 1, budget)


def schema_errors(value: Any, schema: dict, variant: str) -> list:
    validator = jsonschema.Draft202012Validator({"$ref": "#/$defs/" + variant, "$defs": schema["$defs"]})
    return list(validator.iter_errors(value))


def _shape(value: Any, variant: str, schema: dict) -> None:
    require(digest(canonical(schema)) == SCHEMA_SHA256, "unreviewed v4 qualification schema")
    _bounded(value)
    require(len(canonical(value)) <= MAX_BYTES, "bounded qualification data")
    error = jsonschema.exceptions.best_match(schema_errors(value, schema, variant))
    if error is not None:
        raise error


def _path(path: str) -> None:
    require(type(path) is str and path.startswith("/")
            and all(part not in ("", ".", "..") for part in path[1:].split("/")), "canonical installed path")


def _moment(value: str) -> datetime:
    moment = datetime.strptime(value, TIME)
    require(moment.strftime(TIME) == value, "canonical UTC time")
    return moment


def _within(record: dict, observed: str, message: str) -> None:
    now = _moment(observed)
    start, end = _moment(record["scope"]["validFrom"]), _moment(record["scope"]["expiresAt"])
    require(start <= now < end, message)


def _strings(value: Any) -> list[str]:
    if type(value) is str:
        return [value]
    if type(value) is dict:
        return [s for key, item in value.items() for s in [key] + _strings(item)]
    if type(value) is list:
        return [s for item in value for s in _strings(item)]
    return []


def _same_set(observed: list, enrolled: list) -> bool:
    return len(set(observed)) == len(observed) and sorted(observed) == sorted(enrolled)


def _endpoint_rows(rows: list) -> dict:
    require(type(rows) is list and 1 <= len(rows) <= 16, "bounded signed endpoints")
    by_id, tuples = {}, set()
    for row in rows:
        require(type(row) is dict and set(row) == {"endpointId", "kind", "addressFamily", "ipAddress", "port"}
                and row["endpointId"] not in by_id, "unique closed endpoint tuples")
        ip = ipaddress.ip_address(row["ipAddress"])
        require(str(ip) == row["ipAddress"] and not ip.is_unspecified and not ip.is_multicast
                and not (ip.version == 6 and (ip.ipv4_mapped is not None or ip.scope_id is not None)),
                "fixed canonical numeric endpoint")
        require(row["addressFamily"] == ("IPV4" if ip.version == 4 else "IPV6")
                and row["kind"] in ("CAMPAIGN_PROXY", "KUBERNETES_API_PROXY")
                and type(row["port"]) is int and 1 <= row["port"] <= 65535, "endpoint family/type")
        require((row["ipAddress"], row["port"]) not in tuples, "duplicate signed endpoint tuple")
        tuples.add((row["ipAddress"], row["port"]))
        by_id[row["endpointId"]] = row
    return by_id


def _type(label: str) -> str:
    """The type field of an SELinux context (user:role:type:level): SELinux grants entry and execution by type."""
    parts = label.split(":")
    require(len(parts) >= 4 and all(parts[:3]), "malformed SELinux context")
    return parts[2]


def expected_seal_digest(record: dict) -> str:
    """Marker content: boot, active policy, containment artifact and every (role, hook, program) assignment."""
    programs = sorted([role, hook, record["roles"][role]["bpfPrograms"][hook]["programId"],
                       record["roles"][role]["bpfPrograms"][hook]["translatedSha256"]] for role in ROLES for hook in HOOKS)
    content = {"schemaVersion": SEAL_VERSION, "bootId": record["host"]["bootId"],
               "policyDigest": record["selinux"]["policyDigest"],
               "containmentArtifactDigest": record["lifecycleSubjects"]["HOST_CONTAINMENT"]["artifactDigest"],
               "programs": programs}
    return "sha256:" + digest(canonical(content))


class _Owners:
    """Code ownership by path and by content digest; one owner class per byte string."""

    def __init__(self) -> None:
        self.by_path: dict[str, str] = {}
        self.by_sha256: dict[str, str] = {}
        self.by_verity: dict[str, str] = {}

    def own(self, paths: list, rows: dict, owner: str, executable: str, artifact: str, interpreter: str | None) -> None:
        require(set(paths) <= set(rows) and executable in paths and rows[executable]["sha256"] == artifact,
                "artifact custody")
        if interpreter is not None:
            require(interpreter in paths, "interpreter not enrolled")
        loaded = interpreter or executable
        require(rows[loaded]["mode"] == "0555" and rows[loaded]["executableSegments"], "actual executable missing")
        for path in paths:
            for table, key in ((self.by_path, path), (self.by_sha256, rows[path]["sha256"]),
                               (self.by_verity, rows[path]["verityDigest"])):
                previous = table.setdefault(key, owner)
                if previous != owner:
                    require(not {previous, owner} <= set(LIFECYCLE), "lifecycle subjects share code")
                    require(False, "code shared across owner classes")


def check_record(record: Any, profile: Any, endpoints: Any, schema: dict) -> None:
    """Expected-data consistency of one v4 record; raises with the first refused rule."""
    require(type(record) is dict and (record.get("schemaVersion"), record.get("qualificationProfile")) == V4_RECORD,
            "not a v4 record")
    _shape(record, "record", schema)
    require(record["profileDigest"] == "sha256:" + digest(canonical(profile)), "profile substitution")
    entries = record["bootEntries"]
    require(entries["ENROLLED"]["entryId"] != entries["MAINTENANCE"]["entryId"]
            and entries["ENROLLED"]["kernelCmdline"] != entries["MAINTENANCE"]["kernelCmdline"],
            "enrolled and maintenance boot entries indistinguishable")
    enrolled, maintenance = (entries[name]["kernelCmdline"].split(" ") for name in ("ENROLLED", "MAINTENANCE"))
    require(all(_kernel_parameter(word) for word in enrolled), "enrolled boot entry outside the closed kernel parameters")
    require("lockdown=integrity" in enrolled, "enrolled boot entry without lockdown=integrity")
    require(all(_kernel_parameter(word) or word == MAINTENANCE_UNIT for word in maintenance),
            "maintenance boot entry outside the closed kernel parameters")
    require(MAINTENANCE_UNIT in maintenance, "maintenance boot entry does not select the maintenance target")
    require(maintenance.count(MAINTENANCE_UNIT) == 1, "maintenance boot entry names the maintenance target twice")
    require([word for word in maintenance if word != MAINTENANCE_UNIT] == enrolled,
            "maintenance boot entry differs from the enrolled entry beyond the maintenance unit")
    binding = profile["binding"]
    require(record["scope"] == {key: binding[key] for key in record["scope"]}, "scope substitution")
    start, end = _moment(record["scope"]["validFrom"]), _moment(record["scope"]["expiresAt"])
    require(0 < (end - start).total_seconds() <= 900, "canonical half-open window")
    labels = {"planeon.ai/run-nonce": binding["runNonce"], "planeon.ai/tenant-id": binding["tenantId"]}
    require(all(row["manifest"]["metadata"]["labels"] == labels for row in profile["resources"]),
            "profile resource labels differ from the binding")
    signed = _endpoint_rows(endpoints)
    require(record["endpointTuples"] == endpoints, "endpoint tuple substitution")
    proxy = signed.get(binding["endpointId"])
    api = signed.get(binding["apiEndpointId"]) if binding["apiEndpointId"] is not None else None
    resources = bool(profile["resources"])
    require(proxy is not None and proxy["kind"] == "CAMPAIGN_PROXY"
            and ((api is not None and api["kind"] == "KUBERNETES_API_PROXY") if resources
                 else binding["apiEndpointId"] is None), "profile endpoint kinds")
    internal = record["internalEndpoints"][0]
    ip = ipaddress.ip_address(internal["ipAddress"])
    require(ip.is_loopback and internal["addressFamily"] == ("IPV4" if ip.version == 4 else "IPV6")
            and internal["endpointId"] not in signed
            and all((row["ipAddress"], row["port"]) != (internal["ipAddress"], internal["port"])
                    for row in signed.values()), "loopback apiserver endpoint must stay internal")
    require(record["selinux"]["status"]["sequence"] % 2 == 0, "unstable policy epoch")

    def inventory(rows: list, bound: int) -> dict:
        files = {}
        for row in rows:
            _path(row["path"])
            require(row["path"] not in files and row["sha256"] != row["verityDigest"],
                    "duplicate file or conflated digest")
            files[row["path"]] = row
            occupied = set()
            for segment in row["executableSegments"]:
                key = (segment["offset"], segment["length"], segment["permissions"])
                require(key not in occupied and segment["offset"] + segment["length"]
                        <= ((row["size"] + 4095) // 4096) * 4096, "executable segment outside artifact")
                occupied.add(key)
        require(sum(row["size"] for row in files.values()) <= bound, "code inventory bound")
        return files

    files = inventory(record["files"], PLANEON_CODE_BYTES)
    backend_files = inventory(record["backendFiles"], BACKEND_CODE_BYTES)
    require(not set(files) & set(backend_files), "planeon and backend inventories overlap")
    owners = _Owners()

    program_ids: set[int] = set()
    inodes: set[int] = set()
    for role in ROLES:
        row = record["roles"][role]
        owners.own(row["filePaths"], files, "role", row["executable"], row["artifactDigest"], row["interpreterPath"])
        require(row["cgroup"]["inode"] not in inodes, "duplicate cgroup inode")
        inodes.add(row["cgroup"]["inode"])
        listen, outbound = row["listenEndpointIds"], row["outboundEndpointIds"]
        if role == "SERVER":
            require(listen == [binding["endpointId"]]
                    and outbound == ([binding["apiEndpointId"]] if resources else []), "server endpoints differ")
            bound_ports = [proxy["port"]]
        elif role == "EFFECT_GATE":
            require(listen == ([binding["apiEndpointId"]] if resources else [])
                    and outbound == [internal["endpointId"]], "gate endpoints differ")
            bound_ports = [api["port"]] if resources else []
        elif role == "OBSERVER":
            require(listen == [] and outbound == [internal["endpointId"]], "observer endpoints differ")
            bound_ports = []
        else:
            require(listen == [] and outbound == [], role.lower() + " network grant")
            bound_ports = []
        if role == "SERVER":
            require(("CAP_NET_BIND_SERVICE" in row["capabilities"]) == any(port < 1024 for port in bound_ports),
                    "CAP_NET_BIND_SERVICE only for a signed port below 1024")
        if role == "EFFECT_GATE":
            # O-NATIVE-GATE-NOCAP (HS43, H5): W01 section 5.3 gives the gate no capability.
            require(row["capabilities"] == [] and all(port >= 1024 for port in bound_ports),
                    "EFFECT_GATE holds no capability and its signed I04 port is 1024 or above")
        for hook in HOOKS:
            program = row["bpfPrograms"][hook]
            require(program["programType"] == (9 if hook == "INET_SOCK_CREATE" else 18)
                    and program["instructionBytes"] % 8 == 0, "wrong kernel program type/length")
            require(program["pinPath"] == "%s/%s/%s" % (PIN_ROOT, ROLE_DIRS[role], HOOK_DIRS[hook]),
                    "program pin outside the sealed layout")
            require(program["programId"] not in program_ids, "program shared between hooks or roles")
            program_ids.add(program["programId"])

    executables: dict[tuple[str, str], str] = {}
    for role in ROLES:
        row = files[record["roles"][role]["executable"]]
        for key in (("sha256", row["sha256"]), ("verity", row["verityDigest"])):
            require(key not in executables, "role executables share content")
            executables[key] = role
    interpreters = {record["roles"][role]["interpreterPath"] for role in ROLES} - {None}
    for path in interpreters:
        require(("sha256", files[path]["sha256"]) not in executables
                and ("verity", files[path]["verityDigest"]) not in executables, "role executable equal to an interpreter")
    interpreter_content = {(key, files[path][field]) for path in interpreters
                           for key, field in (("sha256", "sha256"), ("verity", "verityDigest"))}
    tree_content = {(key, row[field]) for path, row in files.items() if path.startswith(INTERPRETER_TREE)
                    for key, field in (("sha256", "sha256"), ("verity", "verityDigest"))}
    for role in ROLES:
        row = record["roles"][role]
        for path in row["filePaths"]:
            content = {("sha256", files[path]["sha256"]), ("verity", files[path]["verityDigest"])}
            if path != row["executable"]:
                require(not any(executables.get(key) not in (None, role) for key in content)
                        and all(path != record["roles"][other]["executable"] for other in ROLES),
                        "role closure lists another role's executable")
            if row["interpreterPath"] is None:
                require(path not in interpreters and not content & interpreter_content
                        and not path.startswith(INTERPRETER_TREE) and not content & tree_content,
                        "native-only role closure lists an interpreter")

    lifecycle = record["lifecycleSubjects"]
    for name in LIFECYCLE:
        row = lifecycle[name]
        owners.own(row["filePaths"], files, name, row["executable"], row["artifactDigest"], None)
    require(set(owners.by_path) == set(files), "unowned planeon code")
    require(record["hardening"]["sealMarker"]["digest"] == expected_seal_digest(record),
            "seal marker does not bind this boot")
    # Closures (README "Entrypoints and labels"): a static native role loads its executable alone, and every
    # executable-segment file of an interpreted role's closure but its script carries the dedicated interpreter type.
    for role in ROLES:
        row = record["roles"][role]
        if role in STATIC_ROLES:
            require(row["filePaths"] == [row["executable"]], "static native role closure is its executable alone")
        if row["interpreterPath"] is not None:
            require(all(_type(files[path]["selinuxLabel"]) == _type(row["interpreterLabel"]) for path in row["filePaths"]
                        if path != row["executable"] and files[path]["executableSegments"]),
                    "interpreter closure file outside the dedicated interpreter type")
    # Each entrypoint file carries its domain's matrix v5 entrypoint type, a schema constant (T04-ENTRYPOINT). Labels
    # are compared by type, as SELinux grants entry and execution (the schema admits only the canonical context).
    entry_labels: dict[str, str] = {}
    for name, row in [(role, record["roles"][role]) for role in ROLES] + [(name, lifecycle[name]) for name in LIFECYCLE]:
        require(entry_labels.setdefault(_type(row["executableLabel"]), name) == name, "two roles share an entrypoint label")
        require(_type(files[row["executable"]]["selinuxLabel"]) == _type(row["executableLabel"]),
                "entrypoint file label differs from the role's entrypoint type")

    components = record["backendComponents"]
    require(sorted(components) == sorted(record["backendProfile"]["componentKeys"])
            and set(REQUIRED_BACKEND) <= set(components), "backend components differ from the implementation profile")
    planeon_labels = {record["roles"][role]["processLabel"] for role in ROLES}
    planeon_labels |= {row["processLabel"] for row in lifecycle.values()}
    labels_seen, cgroups_seen, identities_seen = set(), set(), set()
    for name in sorted(components):
        row = components[name]
        owners.own(row["filePaths"], backend_files, "backend", row["executable"], row["artifactDigest"], None)
        domain = row["processLabel"].split(":")[2]
        require(row["processLabel"] not in planeon_labels and not domain.startswith("planeon_"),
                "backend component in a planeon domain")
        require(row["processLabel"] not in labels_seen, "backend components share a domain")
        labels_seen.add(row["processLabel"])
        _path(row["cgroupPath"])
        require(row["cgroupPath"].startswith(CGROUP_ROOT + "/"), "backend cgroup outside cgroupfs")
        require(row["cgroupPath"] != SLICE and not row["cgroupPath"].startswith(SLICE + "/"),
                "backend component inside the planeon slice")
        require(row["cgroupPath"] not in cgroups_seen, "backend components share a cgroup")
        require(not any(row["cgroupPath"].startswith(seen + "/") or seen.startswith(row["cgroupPath"] + "/")
                        for seen in cgroups_seen), "backend cgroup nested in another backend cgroup")
        require(sum(identity.startswith("system:node:") for identity in row["apiIdentities"]) <= 1,
                "more than one node identity")
        cgroups_seen.add(row["cgroupPath"])
        if name in NO_API_CLIENT:
            require(row["apiIdentities"] == [], "backend API identity")
        elif name != "APISERVER":
            require(row["apiIdentities"] != [], "backend API identity")
        require(not set(row["apiIdentities"]) & identities_seen, "backend components share an API identity")
        identities_seen |= set(row["apiIdentities"])
    require(set(owners.by_path) - set(files) == set(backend_files), "unowned backend code")
    # ENTRY_BOUND backends: one executable file per component (no multi-call executable), carrying the component's
    # matrix v5 exec type; content distinctness stays I06's SC08.
    executables = [components[name]["executable"] for name in sorted(components)]
    require(len(set(executables)) == len(executables), "backend components share an executable")
    for name in sorted(components):
        require(_type(backend_files[components[name]["executable"]]["selinuxLabel"]) == _type(components[name]["executableLabel"]),
                "backend executable label differs from the component's exec type")
    # The in-set half of the entrypoint census (T04-ENTRYPOINT-CENSUS keeps the out-of-set half), by type: each
    # entrypoint or exec type labels only its own subject's executable, and the interpreter type labels only files of
    # the interpreted roles' closures, never an executable or a file that a native, lifecycle or backend closure lists.
    # Every backend exec type of the schema's component constants is covered, so a type whose component the record
    # does not list labels no file at all.
    subjects = [record["roles"][role] for role in ROLES] + [lifecycle[name] for name in LIFECYCLE] + list(components.values())
    entry_files: dict[str, str | None] = {_type(rule["allOf"][1]["properties"]["executableLabel"]["const"]): None
                                          for rule in schema["$defs"]["backendComponents"]["properties"].values()}
    entry_files.update({_type(row["executableLabel"]): row["executable"] for row in subjects})
    inventory = record["files"] + record["backendFiles"]
    for row in inventory:
        require(entry_files.get(_type(row["selinuxLabel"]), row["path"]) == row["path"],
                "entrypoint type labels a file other than its subject's executable")
    interpreted = {path for role in ROLES if record["roles"][role]["interpreterPath"] is not None
                   for path in record["roles"][role]["filePaths"]}
    others = [record["roles"][role] for role in ROLES if record["roles"][role]["interpreterPath"] is None]
    others += [lifecycle[name] for name in LIFECYCLE] + list(components.values())
    elsewhere = {row["executable"] for row in subjects} | {path for row in others for path in row["filePaths"]}
    interpreter_types = {_type(record["roles"][role]["interpreterLabel"]) for role in ROLES
                         if record["roles"][role]["interpreterLabel"] is not None}
    for row in inventory:
        require(_type(row["selinuxLabel"]) not in interpreter_types or (row["path"] in interpreted and row["path"] not in elsewhere),
                "interpreter type outside the interpreted closures")


def capture_class(record: dict, role: str) -> str:
    """The evidence class of one role's P1 capture: a function of the role and its recorded capability set."""
    if role == "OBSERVER":
        return "DECLARED_T04"
    if role in LABEL_BOUND_ROLES or "CAP_NET_BIND_SERVICE" in record["roles"][role]["capabilities"]:
        return "LABEL_BOUND"
    return "OBSERVED"


def _member_sets(capture: dict, members: list) -> None:
    """Inspector obligation: the (pid, start) member set and each member's (tid, start) thread set, read before and
    after the process reads, list each key once, are equal, and are exactly the reported members' keys and their
    thread counts."""
    def keyed(rows: list) -> dict:
        processes = {(row["pid"], row["startTicks"]): row["threads"] for row in rows}
        require(len(processes) == len(rows)
                and all(len({(t["tid"], t["startTicks"]) for t in threads}) == len({t["tid"] for t in threads}) == len(threads)
                        for threads in processes.values()), "member set lists a process or thread twice")
        return {key: sorted((t["tid"], t["startTicks"]) for t in threads) for key, threads in processes.items()}

    before, after = keyed(capture["memberSetBefore"]), keyed(capture["memberSetAfter"])
    require(before == after, "member or thread set changed during the inspection")
    reported = {(m["pid"], m["startTicks"]): m["threadCount"] for m in members}
    require(len(reported) == len(members) and set(before) == set(reported)
            and all(len(threads) == reported[key] for key, threads in before.items()),
            "member set differs from the cgroup members")


def check_capture(record: Any, capture: Any, role: str, schema: dict, previous: Any = None) -> None:
    """Detached model capture of one resident role, taken by the observer. Production inspects the kernel through
    its own owner."""
    require(type(capture) is dict and capture.get("schemaVersion") == V4_CAPTURE, "not a v4 capture")
    _shape(record, "record", schema)
    _shape(capture, "capture", schema)
    require(type(role) is str and role in ROLES and capture["role"] == role
            and capture["qualificationDigest"] == "sha256:" + digest(canonical(record)), "capture binding")
    require(capture["host"] == record["host"], "wrong boot/kernel")
    status = record["selinux"]["status"]
    require(status["sequence"] % 2 == 0 and capture["selinuxBefore"] == status == capture["selinuxAfter"]
            and capture["kernelPolicyDigest"] == record["selinux"]["policyDigest"], "active policy changed")
    seal = {key: value for key, value in record["hardening"]["sealMarker"].items() if key != "selinuxLabel"}
    require(capture["booleansObserved"] == record["selinux"]["booleans"]
            and capture["hardeningObserved"] == dict(record["hardening"], sealMarker=seal), "host lock state differs")
    _boot_entry(record, capture["bootEntryObserved"])
    _within(record, capture["observedAt"], "expired capture")
    a, b, d = (capture[k] for k in ("inspectionStartedMs", "inspectionFinishedMs", "deadlineMs"))
    require(a <= b < d and b - a <= 2000 and d - a <= 900000, "inspection deadline")
    expected, actual = record["roles"][role], capture["process"]
    members = capture["cgroupMembers"]
    route = capture_class(record, role)
    own = route == "DECLARED_T04"   # the observer's own leaf: cgroup facts only (T04-OBSERVER-IDENTITY)
    if not own:
        present = ["exe" in actual, "namespaceInodes" in actual, "executableMaps" in capture] + ["exe" in m for m in members]
        if route == "OBSERVED":
            require(any(present), "LABEL_BOUND capture where OBSERVED is required")
            require(all(present), "OBSERVED field missing from the capture")
        else:
            require(not any(present), "field forbidden in a LABEL_BOUND capture")
    # Labels, the seccomp filter digest and default action and rlimitCore are declared (DECLARED_T04), never captured.
    for field in () if own else ("uid", "gid", "processLabel", "seccompMode", "noNewPrivs") + (
            ("namespaceInodes",) if route == "OBSERVED" else ()):
        require(actual[field] == expected[field], "process/kernel custody differs")
    hidden = ("selinuxLabel", "path") if own else ("selinuxLabel",)
    require(actual["cgroup"] == {key: value for key, value in expected["cgroup"].items() if key not in hidden},
            "process/kernel custody differs")
    require(own or actual["threadsUniform"] is True, "per-thread state not uniform")
    if role == "WORKER":
        # Owner decision D5 (2026-10-06): the bounding set may be any subset of the broker's
        # enrolled set (the broker cannot drop it without CAP_SETPCAP); every other set is empty
        # and no_new_privs keeps a leftover bounding set from granting anything.
        bounding = actual["capBounding"]
        require(actual["capPermitted"] == [] and actual["capEffective"] == [] and actual["capAmbient"] == []
                and actual["capInheritable"] == [] and len(set(bounding)) == len(bounding)
                and set(bounding) <= set(record["roles"]["BROKER"]["capabilities"]),
                "capability sets differ from the enrolled set")
    elif not own:
        require(_same_set(actual["capPermitted"], expected["capabilities"])
                and _same_set(actual["capEffective"], expected["capabilities"])
                and _same_set(actual["capBounding"], expected["capabilities"])
                and actual["capAmbient"] == [] and actual["capInheritable"] == [],
                "capability sets differ from the enrolled set")
    me = {key: actual[key] for key in ("pid", "startTicks", "ppid", "uid", "processLabel", "noNewPrivs", "seccompMode",
                                       "seccompFilters", "threadCount", "exe") if key in actual}
    if own:
        require(len(members) == 1, "unenrolled cgroup member")
    elif role in SINGLE_PROCESS_ROLES:
        require(members == [me], "unenrolled cgroup member")
    else:
        pids = {m["pid"]: m for m in members}
        require(me in members and len(pids) == len(members) <= expected["cgroup"]["pidsMax"]
                and all(m["processLabel"] == expected["processLabel"] and m["uid"] == expected["uid"]
                        and m["noNewPrivs"] == 1 and m["seccompMode"] == 2 for m in members), "unenrolled cgroup member")
        for member in members:
            seen, cursor = set(), member
            while cursor["pid"] != me["pid"]:
                require(cursor["pid"] not in seen and cursor["ppid"] in pids, "worker member not descended from the inspected worker")
                seen.add(cursor["pid"])
                cursor = pids[cursor["ppid"]]
    # pids.current counts tasks (threads) of the whole cgroup; a role cgroup has no descendants. The observer's own
    # thread counts are declared, so only its bound is checked.
    tasks = capture["pidsCurrent"] if own else sum(m["threadCount"] for m in members)
    require(capture["pidsCurrent"] == tasks <= expected["cgroup"]["pidsMax"],
            "task count differs from pids.current or exceeds pids.max")
    if not own:
        require(actual["seccompFilters"] == SECCOMP_FILTERS[role]
                and all(m["seccompFilters"] == SECCOMP_FILTERS[role] for m in members),
                "Seccomp_filters count differs from the role's filters")
        if role == "WORKER":
            # Frozen bracket only (owner Q-NP4D-10 (a)): the broker holds the probe-worker leaf frozen.
            require(capture["cgroupFrozenBefore"] == 1 == capture["cgroupFrozenAfter"],
                    "worker capture outside a frozen bracket")
        _member_sets(capture, members)
    require(capture["childCgroups"] == [] and capture["descendantCount"] == 0, "role cgroup has descendants")
    children, service = capture["delegatedChildren"], capture["delegatedServiceMembers"]
    if role == "BROKER":
        require(type(children) is list and sorted(children) == DELEGATED_CHILDREN and service == [],
                "delegated broker subtree differs")
    else:
        require(children is None and service is None, "delegated broker subtree differs")
    rows = {row["path"]: row for row in record["files"]}
    observed = {}
    for item in capture["files"]:
        path = item["entry"]["path"]
        entry = {key: value for key, value in rows[path].items() if key != "selinuxLabel"} if path in rows else None
        require(path not in observed and path in expected["filePaths"] and item["entry"] == entry
                and item["contentDigest"] == rows[path]["sha256"]
                and item["measuredVerity"] == rows[path]["verityDigest"], "file measurement differs")
        observed[path] = item
    require(set(observed) == set(expected["filePaths"]), "incomplete loaded-code closure")
    if route == "OBSERVED":
        image = expected["interpreterPath"] or expected["executable"]
        require(actual["exe"] == {"path": image, "device": observed[image]["device"], "inode": observed[image]["inode"]}
                and all(m["exe"] == actual["exe"] for m in members),
                "running image is not the role's executable or interpreter")
        mappings = [dict(path=path, **segment, device=observed[path]["device"], inode=observed[path]["inode"])
                    for path in expected["filePaths"] for segment in rows[path]["executableSegments"]]
        key = lambda m: (m["path"], m["offset"], m["length"], m["permissions"], m["device"], m["inode"])
        require(sorted(capture["executableMaps"], key=key) == sorted(mappings, key=key),
                "missing or injected executable map")
    for hook in HOOKS:
        item, pinned = capture["bpfPrograms"][hook], expected["bpfPrograms"][hook]
        require(item["program"] == {key: value for key, value in pinned.items() if key != "pinLabel"}
                and item["pinPath"] == pinned["pinPath"]
                and item["localIds"] == [pinned["programId"]] and item["effectiveIds"] == item["localIds"],
                "effective kernel filter differs")
    require(all(capture["effectiveCensus"][name] == [] for name in CENSUS_ATTACH_TYPES),
            "program effective on a role cgroup outside the containment hooks")
    if previous is not None:
        require(explain(check_capture, record, previous, role, schema) is None, "invalid retained capture")
        for field in ("host", "process", "files", "executableMaps", "bpfPrograms", "selinuxBefore", "selinuxAfter",
                      "kernelPolicyDigest", "booleansObserved", "hardeningObserved", "cgroupMembers",
                      "memberSetBefore", "memberSetAfter", "cgroupFrozenBefore", "cgroupFrozenAfter",
                      "childCgroups", "descendantCount", "delegatedChildren", "delegatedServiceMembers",
                      "pidsCurrent", "effectiveCensus", "bootEntryObserved"):
            require(capture.get(field) == previous.get(field), "retained native identity changed")
        require(capture["inspectionStartedMs"] >= previous["inspectionFinishedMs"]
                and capture["observedAt"] >= previous["observedAt"]
                and capture["deadlineMs"] == previous["deadlineMs"], "rollback or renewed lifetime")


def _kernel_parameter(word: str) -> bool:
    """One word of the closed kernel command-line grammar."""
    return any(pattern.fullmatch(word) for pattern in KERNEL_PARAMETERS)


def _boot_entry(record: dict, observed: dict) -> None:
    """The observation was taken on the enrolled boot entry, never the maintenance entry."""
    enrolled = record["bootEntries"]["ENROLLED"]
    require(observed == {"entryId": enrolled["entryId"],
                         "cmdlineSha256": "sha256:" + digest(enrolled["kernelCmdline"].encode("ascii"))},
            "observed on a boot entry other than the enrolled one")


def check_lifecycle_capture(record: Any, capture: Any, schema: dict) -> None:
    """Absence of the one-shot containment subject after its seal; data only."""
    require(type(capture) is dict and capture.get("schemaVersion") == V4_LIFECYCLE, "not a v4 lifecycle capture")
    _shape(record, "record", schema)
    _shape(capture, "lifecycleCapture", schema)
    require(capture["qualificationDigest"] == "sha256:" + digest(canonical(record))
            and capture["host"] == record["host"], "lifecycle capture binding")
    _within(record, capture["observedAt"], "expired lifecycle capture")
    # The marker's label is declared (T04-LABELS); its path, digest, uid and mode are observed.
    require(capture["sealMarker"] == {key: value for key, value in record["hardening"]["sealMarker"].items()
                                      if key != "selinuxLabel"}, "seal marker differs")
    require(capture["runFsType"] == record["hardening"]["runFsType"], "seal marker not on a per-boot filesystem")
    containment = record["lifecycleSubjects"]["HOST_CONTAINMENT"]["cgroupPath"]
    require(capture["cgroup"]["path"] == containment and capture["cgroup"]["state"] in ("ABSENT", "EMPTY")
            and capture["domainProcessCounts"]["planeon_contain_t"] == 0, "containment subject still resident")
    require(capture["booleansObserved"] == record["selinux"]["booleans"], "host lock state differs")
    _boot_entry(record, capture["bootEntryObserved"])
    # The slice root holds no process of its own (observed, not inferred from the no-internal-process rule).
    require(capture["sliceMembers"] == [], "process directly in the planeon slice")
    census = {row["path"]: row["populated"] for row in capture["sliceCgroups"]}
    for path in census:
        _path(path)
    require(len(census) == len(capture["sliceCgroups"])
            and all(path == SLICE or path.startswith(SLICE + "/") for path in census), "planeon slice census malformed")
    require(all(path == SLICE or path.rsplit("/", 1)[0] in census for path in census),
            "planeon slice census omits a parent cgroup")
    enrolled = {record["roles"][role]["cgroup"]["path"] for role in ROLES} | {SLICE, SLICE + "/planeon-capacity-broker.service"}
    require(enrolled <= set(census), "planeon slice census incomplete")
    require((containment in census) == (capture["cgroup"]["state"] == "EMPTY")
            and census.get(containment, 0) == 0, "containment subject still resident")
    require(all(populated == 0 for path, populated in census.items() if path not in enrolled),
            "unenrolled populated cgroup in the planeon slice")
    # cgroup.stat nr_descendants of the slice: the census lists every live descendant (round 2, W7).
    require(capture["sliceDescendants"] == len(census) - 1, "slice descendants differ from the census")


def check_backend_capture(record: Any, capture: Any, schema: dict) -> None:
    """ENTRY_BOUND observation of one backend component (domain entry plus measured file, not the running image)
    against its record entry; data only."""
    require(type(capture) is dict and capture.get("schemaVersion") == V4_BACKEND, "not a v4 backend capture")
    _shape(record, "record", schema)
    _shape(capture, "backendCapture", schema)
    require(capture["qualificationDigest"] == "sha256:" + digest(canonical(record))
            and capture["host"] == record["host"], "backend capture binding")
    _within(record, capture["observedAt"], "expired backend capture")
    entry = record["backendComponents"].get(capture["component"])
    require(entry is not None, "backend capture for an unrecorded component")
    executable = {row["path"]: row for row in record["backendFiles"]}[entry["executable"]]
    require(capture["process"]["processLabel"] == entry["processLabel"]
            and capture["process"]["cgroupPath"] == entry["cgroupPath"]
            and capture["executable"] == {"path": entry["executable"], "contentDigest": executable["sha256"],
                                          "measuredVerity": executable["verityDigest"]}, "backend observation differs")


def check_migration(v1_records: Any, v2_records: Any, v3_records: Any, v4_record: Any, v4_profile: Any, v1_schema: dict,
                    v2_schema: dict, v3_schema: dict, schema: dict, no_earlier_history: bool = False) -> None:
    """A v4 enrollment needs a maintenance reboot and fresh nonces against every earlier version.

    `v1_records`, `v2_records` and `v3_records` must be the complete retained v1, v2 and v3 histories (a
    caller obligation); a host whose histories are all attested empty passes `no_earlier_history=True`
    with three empty lists. Earlier data is never reinterpreted."""
    _shape(v4_record, "record", schema)
    require(v4_record["profileDigest"] == "sha256:" + digest(canonical(v4_profile)), "profile substitution")
    require(digest(canonical(v1_schema)) == V1_SCHEMA_SHA256, "unreviewed v1 schema")
    require(digest(canonical(v2_schema)) == V2_SCHEMA_SHA256, "unreviewed v2 schema")
    require(digest(canonical(v3_schema)) == V3_SCHEMA_SHA256, "unreviewed v3 schema")
    require(type(v1_records) is list and type(v2_records) is list and type(v3_records) is list
            and type(no_earlier_history) is bool, "migration inputs")
    if no_earlier_history:
        require(v1_records == [] and v2_records == [] and v3_records == [], "attested empty history with earlier records")
    require(no_earlier_history or v1_records or v2_records or v3_records, "retained earlier records required")
    old_nonces: set[str] = set()
    for version, records, old_schema in (("v1", v1_records, v1_schema), ("v2", v2_records, v2_schema),
                                         ("v3", v3_records, v3_schema)):
        for old in records:
            require(type(old) is dict and old.get("schemaVersion") == "planeon.internal.native-qualification/" + version
                    and not schema_errors(old, old_schema, "record"), "predecessor is not a valid %s record" % version)
            require(old["host"]["bootId"] != v4_record["host"]["bootId"], "v4 enrollment without a maintenance reboot")
            old_nonces |= {old["scope"]["runNonce"], old["scope"]["capacityNonce"]}
    new_nonces = {v4_record["scope"]["runNonce"], v4_record["scope"]["capacityNonce"]}
    require(not new_nonces & old_nonces, "nonce reused across versions")
    require(not set(_strings(v4_profile)) & old_nonces and not set(_strings(v4_record)) & old_nonces,
            "earlier nonce carried into v4 data")


def check_qualification(record: Any, profile: Any, endpoints: Any, captures: Any, lifecycle: Any,
                        backend_captures: Any, v1_records: Any, v2_records: Any, v3_records: Any, v1_schema: dict,
                        v2_schema: dict, v3_schema: dict, schema: dict, no_earlier_history: bool = False,
                        test_fixture: bool = False) -> None:
    """The only acceptance-shaped check: everything for one boot and window, still DATA_CHECK_ONLY.

    Caller obligations: the profile passed the pinned proxy profile contract, and `v1_records`,
    `v2_records` and `v3_records` are the complete retained earlier histories (see the module
    docstring). A test-only implementation profile qualifies only with `test_fixture=True`; a WORKER
    capture qualifies only from inside a frozen bracket (check_capture)."""
    check_record(record, profile, endpoints, schema)
    require(type(test_fixture) is bool and (test_fixture or not record["backendProfile"]["testOnly"]),
            "test-only implementation profile")
    require(type(captures) is list and sorted(c.get("role") for c in captures) == sorted(ROLES),
            "one capture per resident role")
    for capture in captures:
        check_capture(record, capture, capture["role"], schema)
    check_lifecycle_capture(record, lifecycle, schema)
    require(type(backend_captures) is list
            and sorted(c.get("component") for c in backend_captures) == sorted(record["backendComponents"]),
            "one observation per backend component")
    for capture in backend_captures:
        check_backend_capture(record, capture, schema)
    # The observer's own start time is declared (T04-OBSERVER-IDENTITY), so its member is outside this rule.
    processes = [(m["pid"], m["startTicks"]) for c in captures if c["role"] != "OBSERVER" for m in c["cgroupMembers"]]
    processes += [(c["process"]["pid"], c["process"]["startTicks"]) for c in backend_captures]
    require(len(set(processes)) == len(processes), "one process reported twice")
    # One observed file per (device, inode) and one inode per path, across every role capture (round 2, W1).
    by_inode: dict[tuple, tuple] = {}
    by_path: dict[str, tuple] = {}
    for capture in captures:
        for item in capture["files"]:
            node = (item["device"], item["inode"])
            seen = (item["entry"]["path"], item["contentDigest"], item["measuredVerity"])
            require(by_inode.setdefault(node, seen) == seen, "one inode reported for two files")
            require(by_path.setdefault(seen[0], node) == node, "one file reported at two inodes")
    by_role = {c["role"]: c for c in captures}
    require(by_role["WORKER"]["process"]["ppid"] == by_role["BROKER"]["process"]["pid"],
            "worker is not a child of the original broker")
    counts = lifecycle["domainProcessCounts"]
    require(all(counts[ROLE_DOMAINS[role]] == len(by_role[role]["cgroupMembers"]) for role in ROLES),
            "role-domain process outside its role cgroup")
    # The slice census agrees with the role captures: role cgroups have no child cgroup, the delegated broker
    # service has exactly its two leaves, and every enrolled cgroup that holds a captured process is populated.
    census = {row["path"]: row["populated"] for row in lifecycle["sliceCgroups"]}
    role_cgroups = {record["roles"][role]["cgroup"]["path"] for role in ROLES}
    require(not any(path.startswith(cgroup + "/") for path in census for cgroup in role_cgroups),
            "census lists a cgroup below a role cgroup")
    require(sorted(path[len(BROKER_SERVICE) + 1:] for path in census if path.startswith(BROKER_SERVICE + "/")
                   and "/" not in path[len(BROKER_SERVICE) + 1:]) == DELEGATED_CHILDREN,
            "census children of the delegated broker service differ")
    require(all(census[path] == 1 for path in role_cgroups | {SLICE, BROKER_SERVICE}),
            "census reports a cgroup with captured processes as unpopulated")
    check_migration(v1_records, v2_records, v3_records, record, profile, v1_schema, v2_schema, v3_schema, schema,
                    no_earlier_history)


ERRORS = (ValueError, TypeError, KeyError, AttributeError, RecursionError, jsonschema.ValidationError)


def explain(check: Any, *args: Any) -> str | None:
    """None when `check` accepts; otherwise the refused rule (schema refusals name the JSON path)."""
    try:
        check(*args)
    except jsonschema.ValidationError as exc:
        return "schema %s %s" % (exc.json_path, exc.validator)
    except ERRORS as exc:
        return str(exc) if type(exc) is ValueError else type(exc).__name__
    return None


def refusal_under(value: Any, schema: dict, variant: str) -> str | None:
    """Best-match schema refusal of `value` as `variant` of `schema` (any version), or None."""
    error = jsonschema.exceptions.best_match(schema_errors(value, schema, variant))
    return None if error is None else "schema %s %s" % (error.json_path, error.validator)


def _result(check: Any, message: str, *args: Any) -> list[str]:
    return [] if explain(check, *args) is None else [message]


def validate_record(record: Any, profile: Any, endpoints: Any, schema: dict) -> list[str]:
    return _result(check_record, "invalid DATA_CHECK_ONLY v4 qualification record; no native authority",
                   record, profile, endpoints, schema)


def validate_capture(record: Any, capture: Any, role: str, schema: dict, previous: Any = None) -> list[str]:
    return _result(check_capture, "invalid DATA_CHECK_ONLY v4 capture; no native authority",
                   record, capture, role, schema, previous)


def validate_qualification(*args: Any) -> list[str]:
    """Empty list = accepted as data, given the caller obligations in the module docstring."""
    return _result(check_qualification, "invalid DATA_CHECK_ONLY v4 qualification; no native authority "
                   "(caller must also have validated the profile with the pinned proxy contract)", *args)


# -- data check of the v4 vectors: every v4 case, every v3 case and the W02 notes errata R6-3 cases replayed under v4
SCHEMA_PATH = "architecture/native-profile-v4/qualification.schema.json"
V4_INPUTS = {"v1Schema": "architecture/native-qualification-inputs/qualification.schema.json",
             "v1Vectors": "architecture/native-qualification-inputs/vectors.json",
             "v2Schema": "architecture/native-profile-v2/qualification.schema.json",
             "v2Vectors": "architecture/native-profile-v2/vectors.json",
             "v3Schema": "architecture/native-profile-v3/qualification.schema.json",
             "v3Vectors": "architecture/native-profile-v3/vectors.json",
             "erratumVectors": "architecture/w02-notes-errata/native-profile-v3-r6-3-vectors.json"}
VECTOR_FLOORS = {"positive": 5, "negative": 444, "accepted": 18, "crossVersion": 15, "migration": 22}
# v3 refusals and cross-version results that change only by the version they name.
MECHANICAL = {"not a v3 record": "not a v4 record", "not a v3 capture": "not a v4 capture",
              "not a v3 lifecycle capture": "not a v4 lifecycle capture",
              "not a v3 backend capture": "not a v4 backend capture",
              "v3 enrollment without a maintenance reboot": "v4 enrollment without a maintenance reboot",
              "earlier nonce carried into v3 data": "earlier nonce carried into v4 data"}
# v3 accepted cases that v4 refuses (README "Replayed v3 cases"): A01 (O-NATIVE-GATE-NOCAP), A05 (static closures).
MOVED_TO_NEGATIVE = ("A01", "A05")
# v3 cases whose refusal changes for a reason, and v3 cases whose operations are re-derived for the v4 shapes; each
# row records its v3 refusal or the reason (README "Replayed v3 cases").
CHANGED_V3_REFUSALS = ("C13", "C27", "C28", "C29", "L05", "R28", "R29", "V08", "V22", "V45")
REDERIVED_V3_OPS = ("C14", "C15", "C16", "C17", "C18", "Q03", "V08", "V18", "V56")
CASE_KEYS = ("positive", "target", "role", "component", "testFixture", "profileOps", "endpointOps", "rebindProfile")
MIGRATION_KEYS = ("positive", "v1Positives", "v2Positives", "profileOps", "ops", "rebindProfile", "v1Ops", "v2Ops",
                  "noEarlierHistory")


def _apply(value: Any, ops: list) -> Any:
    value = copy.deepcopy(value)
    for op in ops:
        require(type(op) is dict and op.get("op") in ("set", "delete", "append") and type(op.get("path")) is list
                and op["path"], "closed vector operation")
        *parents, last = op["path"]
        node = value
        for key in parents:
            node = node[key]
        if op["op"] == "set":
            node[last] = copy.deepcopy(op["value"])
        elif op["op"] == "delete":
            del node[last]
        else:
            node[last].append(copy.deepcopy(op["value"]))
    return value


def _shift(kind: str) -> str:
    """A v3 cross-version kind moved one version up (V2_RECORD_UNDER_V3 -> V3_RECORD_UNDER_V4)."""
    return kind.replace("V3", "V4").replace("V2", "V3")


def check_vectors(vectors: Any, files: dict) -> int:
    """DATA_CHECK_ONLY: replay every v4 vector, every v3 case and the W02 notes errata R6-3 cases under v4.

    `files` maps the v4 schema path and each pinned input path (V4_INPUTS) to its bytes; the inputs must match the
    SHA-256 the vectors pin. Returns the number of checks; any mismatch raises ValueError."""
    require(type(vectors) is dict and set(vectors) == {
        "evidenceClass", "nativeAcceptance", "tenantAcceptance", "schemaSha256", "v1SchemaSha256", "v2SchemaSha256",
        "v3SchemaSha256", "derivedFrom", "inputs", "positive", "negative", "accepted", "crossVersion", "migration"}
            and vectors["evidenceClass"] == "DATA_CHECK_ONLY" and vectors["nativeAcceptance"] is False
            and vectors["tenantAcceptance"] is False and vectors["derivedFrom"] == V4_INPUTS["v3Vectors"]
            and all(type(vectors[key]) is list and len(vectors[key]) >= floor for key, floor in VECTOR_FLOORS.items()),
            "closed v4 vectors")
    require(type(vectors["inputs"]) is dict and set(vectors["inputs"]) == set(V4_INPUTS), "the pinned inputs")
    pinned = {}
    for key, path in V4_INPUTS.items():
        require(type(files.get(path)) is bytes and vectors["inputs"][key] == {"path": path, "sha256": digest(files[path])},
                "the pinned input " + path)
        pinned[key] = parse(files[path])
    require(type(files.get(SCHEMA_PATH)) is bytes, "the v4 schema")
    schema = parse(files[SCHEMA_PATH])
    s1, s2, s3 = pinned["v1Schema"], pinned["v2Schema"], pinned["v3Schema"]
    require(vectors["schemaSha256"] == SCHEMA_SHA256 == digest(canonical(schema))
            and vectors["v1SchemaSha256"] == V1_SCHEMA_SHA256 == digest(canonical(s1))
            and vectors["v2SchemaSha256"] == V2_SCHEMA_SHA256 == digest(canonical(s2))
            and vectors["v3SchemaSha256"] == V3_SCHEMA_SHA256 == digest(canonical(s3)), "v4 vectors bound to the pinned schemas")
    histories = [[row["record"] for row in pinned[key]["positive"]] for key in ("v1Vectors", "v2Vectors", "v3Vectors")]
    positives = vectors["positive"]

    def qualify(p: dict, bundle: dict, test_fixture: bool = True) -> Any:
        return explain(check_qualification, p["record"], p["profile"], p["endpoints"], bundle["captures"],
                       bundle["lifecycle"], bundle["backendCaptures"], *histories, s1, s2, s3, schema, False, test_fixture)

    def case(row: dict) -> Any:
        p = positives[row["positive"]]
        profile = _apply(p["profile"], row.get("profileOps", []))
        endpoints = _apply(p["endpoints"], row.get("endpointOps", []))
        target = row["target"]
        if target == "record":
            record = _apply(p["record"], row["ops"])
            if row.get("rebindProfile"):
                record["profileDigest"] = "sha256:" + digest(canonical(profile))
            return explain(check_record, record, profile, endpoints, schema)
        if target == "capture":
            capture = _apply(next(c for c in p["captures"] if c["role"] == row["role"]), row["ops"])
            return explain(check_capture, p["record"], capture, row["role"], schema)
        if target == "lifecycle":
            return explain(check_lifecycle_capture, p["record"], _apply(p["lifecycle"], row["ops"]), schema)
        if target == "backend":
            capture = _apply(next(c for c in p["backendCaptures"] if c["component"] == row["component"]), row["ops"])
            return explain(check_backend_capture, p["record"], capture, schema)
        require(target == "qualification", "closed vector target")
        bundle = _apply({key: p[key] for key in ("captures", "lifecycle", "backendCaptures")}, row["ops"])
        return qualify(p, bundle, row.get("testFixture", True))

    for p in positives:
        require(qualify(p, p) is None, "v4 positive refused")
    checks = len(positives)
    for kind in ("negative", "accepted"):
        for row in vectors[kind]:
            result = case(row)
            require(result == row["refusal"] and result is not None if kind == "negative" else result is None,
                    "%s vector %s" % (kind, row["id"]))
            checks += 1
    ids = [row["id"] for key in ("negative", "accepted", "crossVersion", "migration") for row in vectors[key]]
    require(len(ids) == len(set(ids)), "unique vector identifiers")
    # Every v3 negative and accepted case is replayed under v4 with its v3 operations, unless re-derived for the v4
    # shapes; its refusal is v3's (version names moved) unless the change is recorded.
    v3 = pinned["v3Vectors"]
    rows = {row["id"]: (kind, row) for kind in ("negative", "accepted") for row in vectors[kind]}
    replayed = set()
    for kind in ("negative", "accepted"):
        for old in v3[kind]:
            name = old["id"]
            new_kind, row = rows.get(name, (None, {}))
            rederived = name in REDERIVED_V3_OPS
            require(new_kind is not None and ("rederived" in row) == rederived
                    and (rederived or (row["ops"] == old["ops"]
                                       and all(row.get(key) == old.get(key) for key in CASE_KEYS))),
                    "v3 case replayed with its operations: " + name)
            if kind == "accepted":
                moved = name in MOVED_TO_NEGATIVE
                require(new_kind == ("negative" if moved else "accepted")
                        and (row.get("v3Refusal", "absent") is None) == moved and ("v3Refusal" in row) == moved,
                        "v3 accepted case replayed: " + name)
            else:
                mapped = MECHANICAL.get(old["refusal"], old["refusal"])
                changed = name in CHANGED_V3_REFUSALS
                require(new_kind == "negative" and ("v3Refusal" in row) == changed
                        and (row["refusal"] == mapped) != changed and (not changed or row["v3Refusal"] == old["refusal"]),
                        "v3 negative replayed: " + name)
            replayed.add(name)
    require(replayed >= set(CHANGED_V3_REFUSALS) | set(REDERIVED_V3_OPS) | set(MOVED_TO_NEGATIVE),
            "recorded replay changes name v3 cases")
    # The errata's R6-3 cases are replayed under v4 unchanged.
    erratum = pinned["erratumVectors"]
    for kind in ("negative", "accepted"):
        for old in erratum[kind]:
            new_kind, row = rows.get(old["id"], (None, {}))
            require(new_kind == kind and all(row.get(key) == old.get(key) for key in ("positive", "target", "ops", "refusal"))
                    and "v3Refusal" not in row and "rederived" not in row, "errata case replayed under v4: " + old["id"])
    # Cross-version: v3 data under the v4 model and v4 data under the v3 schema (every v3 kind moved one version up).
    kinds = {}
    for row in vectors["crossVersion"]:
        kinds[row["id"]] = row
        p = positives[row["index"]]
        if row["kind"] == "V3_RECORD_UNDER_V4":
            result = explain(check_record, histories[2][row["index"]], p["profile"], p["endpoints"], schema)
            require(result == row["expect"] == "not a v4 record", "cross-version " + row["id"])
        elif row["kind"] in ("V3_CAPTURE_UNDER_V4", "V3_LIFECYCLE_UNDER_V4", "V3_BACKEND_CAPTURE_UNDER_V4"):
            old = v3["positive"][row["index"]]
            value, check, args = {"V3_CAPTURE_UNDER_V4": (old["captures"][0], check_capture, ("SERVER",)),
                                  "V3_LIFECYCLE_UNDER_V4": (old["lifecycle"], check_lifecycle_capture, ()),
                                  "V3_BACKEND_CAPTURE_UNDER_V4": (old["backendCaptures"][0], check_backend_capture, ())}[row["kind"]]
            require(explain(check, p["record"], value, *args, schema) == row["expect"], "cross-version " + row["id"])
        else:
            value, variant = {"V4_RECORD_UNDER_V3": (p["record"], "record"),
                              "V4_CAPTURE_UNDER_V3": (p["captures"][0], "capture"),
                              "V4_LIFECYCLE_UNDER_V3": (p["lifecycle"], "lifecycleCapture"),
                              "V4_BACKEND_CAPTURE_UNDER_V3": (p["backendCaptures"][0], "backendCapture")}[row["kind"]]
            errors = {(error.json_path, error.validator) for error in schema_errors(value, s3, variant)}
            require(row["mustInclude"] and all(tuple(pair) in errors for pair in row["mustInclude"]), "cross-version " + row["id"])
        checks += 1
    for old in v3["crossVersion"]:
        row = kinds.get(old["id"], {})
        require(row.get("kind") == _shift(old["kind"]) and row.get("index") == old["index"]
                and row.get("mustInclude") == old.get("mustInclude")
                and row.get("expect") == MECHANICAL.get(old.get("expect"), old.get("expect")),
                "v3 cross-version case moved one version up: " + old["id"])
    # Migration over the v1, v2 and v3 histories; v3's cases replay with an empty v3 history.
    cases = {}
    for row in vectors["migration"]:
        cases[row["id"]] = row
        p = positives[row["positive"]]
        profile = _apply(p["profile"], row.get("profileOps", []))
        record = _apply(p["record"], row.get("ops", []))
        if row.get("rebindProfile"):
            record["profileDigest"] = "sha256:" + digest(canonical(profile))
        olds = [[copy.deepcopy(history[index]) for index in row[key]]
                for history, key in zip(histories, ("v1Positives", "v2Positives", "v3Positives"))]
        for history, key in zip(olds, ("v1Ops", "v2Ops", "v3Ops")):
            for change in row.get(key, []):
                history[change["index"]] = _apply(history[change["index"]], change["ops"])
        result = explain(check_migration, *olds, record, profile, s1, s2, s3, schema, row.get("noEarlierHistory", False))
        require(result == row["expect"], "migration vector " + row["id"])
        checks += 1
    for old in v3["migration"]:
        row = cases.get(old["id"], {})
        require(row.get("v3Positives") == [] and "v3Ops" not in row
                and all(row.get(key) == old.get(key) for key in MIGRATION_KEYS)
                and row.get("expect", "absent") == MECHANICAL.get(old["expect"], old["expect"]),
                "v3 migration case replayed: " + old["id"])
    return checks
