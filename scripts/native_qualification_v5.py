#!/usr/bin/env python3
"""v5 native qualification captures: native-profile v4's captures without the host, policy and boot fields.

Reference model for the capture variants of native-profile v5 (`planeon.internal.native-qualification-capture/v5`,
`planeon.internal.native-qualification-lifecycle/v5` and `planeon.internal.native-qualification-backend/v5`), the
capture-only successor of the adopted native-profile v4 (owner decision Q-NPE-1 (c)). The record contract stays
native-profile v4's: the record `planeon.internal.native-qualification/v4`, its schema (passed as `record_schema` and
pinned by v4's digest), `check_record` and `check_migration`, all used unchanged from
`scripts/native_qualification_v4.py`. v5 drops the seven OUT_OF_SCOPE_HOST fields (`host`, `selinuxBefore`,
`selinuxAfter`, `kernelPolicyDigest`, `booleansObserved`, `hardeningObserved` and `bootEntryObserved`) from every
capture that carried them, and with them v4's capture equalities on them; the record keeps their declared values and
its own rules, and four named T04 proofs cover them (README "The host facts"). It never inspects a kernel, never mints
a native handle and never grants authority; every result is DATA_CHECK_ONLY. Native-profile v1 to v4 are unchanged.

`check_*` functions raise with the first refused rule. A single check is NOT an acceptance decision: only
`check_qualification` combines v4's `check_record`, one v5 capture per resident role, the v5 lifecycle capture, one v5
observation per backend component, v4's cross-capture rules and v4's `check_migration`, for one boot and validity
window. Every function here that v4 also has is v4's with the changes the README lists, so the v4-to-v5 diff of each
function is the review surface; every other helper and constant is v4's, bound by name below.

Caller obligations: native-profile v4's (its module docstring and README "Files"), unchanged. That `record_schema` is
native-profile v4's schema is checked, not a caller obligation: v4's `_shape` refuses any other.
"""
from __future__ import annotations

import copy
from typing import Any

import jsonschema

try:
    import native_qualification_v4 as v4
except ImportError:
    from scripts import native_qualification_v4 as v4

SCHEMA_SHA256 = "5f6703ca38d0919f6446772e8edd75e92609a9a3971b8cb052b53a7e9ab50393"
V5_CAPTURE = "planeon.internal.native-qualification-capture/v5"
V5_LIFECYCLE = "planeon.internal.native-qualification-lifecycle/v5"
V5_BACKEND = "planeon.internal.native-qualification-backend/v5"
# The fields v5 drops from each capture variant (README "The host facts"): OUT_OF_SCOPE_HOST, absent and record-only.
HOST_FIELDS = {"capture": ("host", "selinuxBefore", "selinuxAfter", "kernelPolicyDigest", "booleansObserved",
                           "hardeningObserved", "bootEntryObserved"),
               "lifecycleCapture": ("host", "booleansObserved", "bootEntryObserved"),
               "backendCapture": ("host",)}

# v4's helpers and constants, bound by name and unchanged.
require, digest, canonical, parse, explain = v4.require, v4.digest, v4.canonical, v4.parse, v4.explain
schema_errors, _bounded, _path, _within, _same_set = v4.schema_errors, v4._bounded, v4._path, v4._within, v4._same_set
_result, _apply, capture_class, _member_sets = v4._result, v4._apply, v4.capture_class, v4._member_sets
ROLES, SINGLE_PROCESS_ROLES, SECCOMP_FILTERS, HOOKS = v4.ROLES, v4.SINGLE_PROCESS_ROLES, v4.SECCOMP_FILTERS, v4.HOOKS
CENSUS_ATTACH_TYPES, DELEGATED_CHILDREN, SLICE = v4.CENSUS_ATTACH_TYPES, v4.DELEGATED_CHILDREN, v4.SLICE
BROKER_SERVICE, ROLE_DOMAINS, MAX_BYTES = v4.BROKER_SERVICE, v4.ROLE_DOMAINS, v4.MAX_BYTES


def _shape(value: Any, variant: str, schema: dict) -> None:
    require(digest(canonical(schema)) == SCHEMA_SHA256, "unreviewed v5 capture schema")
    _bounded(value)
    require(len(canonical(value)) <= MAX_BYTES, "bounded qualification data")
    error = jsonschema.exceptions.best_match(schema_errors(value, schema, variant))
    if error is not None:
        raise error


def check_capture(record: Any, capture: Any, role: str, record_schema: dict, schema: dict,
                  previous: Any = None) -> None:
    """Detached model capture of one resident role, taken by the observer. Production inspects the kernel through
    its own owner. The record is native-profile v4's, shaped by v4's schema (record_schema)."""
    require(type(capture) is dict and capture.get("schemaVersion") == V5_CAPTURE, "not a v5 capture")
    v4._shape(record, "record", record_schema)
    _shape(capture, "capture", schema)
    require(type(role) is str and role in ROLES and capture["role"] == role
            and capture["qualificationDigest"] == "sha256:" + digest(canonical(record)), "capture binding")
    # v5: the host, policy and boot fields are record-only (OUT_OF_SCOPE_HOST, absent; T04-HOST-BOOT,
    # T04-POLICY-STABLE, T04-HOST-LOCKS, T04-BOOT-ENTRY), so no capture equality runs on them. The record's even policy
    # sequence stays check_record's rule ("unstable policy epoch").
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
        require(explain(check_capture, record, previous, role, record_schema, schema) is None,
                "invalid retained capture")
        for field in ("process", "files", "executableMaps", "bpfPrograms", "cgroupMembers",
                      "memberSetBefore", "memberSetAfter", "cgroupFrozenBefore", "cgroupFrozenAfter",
                      "childCgroups", "descendantCount", "delegatedChildren", "delegatedServiceMembers",
                      "pidsCurrent", "effectiveCensus"):
            require(capture.get(field) == previous.get(field), "retained native identity changed")
        require(capture["inspectionStartedMs"] >= previous["inspectionFinishedMs"]
                and capture["observedAt"] >= previous["observedAt"]
                and capture["deadlineMs"] == previous["deadlineMs"], "rollback or renewed lifetime")


def check_lifecycle_capture(record: Any, capture: Any, record_schema: dict, schema: dict) -> None:
    """Absence of the one-shot containment subject after its seal; data only."""
    require(type(capture) is dict and capture.get("schemaVersion") == V5_LIFECYCLE, "not a v5 lifecycle capture")
    v4._shape(record, "record", record_schema)
    _shape(capture, "lifecycleCapture", schema)
    require(capture["qualificationDigest"] == "sha256:" + digest(canonical(record)), "lifecycle capture binding")
    _within(record, capture["observedAt"], "expired lifecycle capture")
    # The marker's label is declared (T04-LABELS); its path, digest, uid and mode are observed.
    require(capture["sealMarker"] == {key: value for key, value in record["hardening"]["sealMarker"].items()
                                      if key != "selinuxLabel"}, "seal marker differs")
    require(capture["runFsType"] == record["hardening"]["runFsType"], "seal marker not on a per-boot filesystem")
    containment = record["lifecycleSubjects"]["HOST_CONTAINMENT"]["cgroupPath"]
    require(capture["cgroup"]["path"] == containment and capture["cgroup"]["state"] in ("ABSENT", "EMPTY")
            and capture["domainProcessCounts"]["planeon_contain_t"] == 0, "containment subject still resident")
    # v5: the booleans and the boot entry are record-only (T04-HOST-LOCKS, T04-BOOT-ENTRY).
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


def check_backend_capture(record: Any, capture: Any, record_schema: dict, schema: dict) -> None:
    """ENTRY_BOUND observation of one backend component (domain entry plus measured file, not the running image)
    against its record entry; data only."""
    require(type(capture) is dict and capture.get("schemaVersion") == V5_BACKEND, "not a v5 backend capture")
    v4._shape(record, "record", record_schema)
    _shape(capture, "backendCapture", schema)
    require(capture["qualificationDigest"] == "sha256:" + digest(canonical(record)), "backend capture binding")
    _within(record, capture["observedAt"], "expired backend capture")
    entry = record["backendComponents"].get(capture["component"])
    require(entry is not None, "backend capture for an unrecorded component")
    executable = {row["path"]: row for row in record["backendFiles"]}[entry["executable"]]
    require(capture["process"]["processLabel"] == entry["processLabel"]
            and capture["process"]["cgroupPath"] == entry["cgroupPath"]
            and capture["executable"] == {"path": entry["executable"], "contentDigest": executable["sha256"],
                                          "measuredVerity": executable["verityDigest"]}, "backend observation differs")


def check_qualification(record: Any, profile: Any, endpoints: Any, captures: Any, lifecycle: Any,
                        backend_captures: Any, v1_records: Any, v2_records: Any, v3_records: Any, v1_schema: dict,
                        v2_schema: dict, v3_schema: dict, record_schema: dict, schema: dict,
                        no_earlier_history: bool = False, test_fixture: bool = False) -> None:
    """The only acceptance-shaped check: everything for one boot and window, still DATA_CHECK_ONLY.

    Caller obligations: the profile passed the pinned proxy profile contract, and `v1_records`,
    `v2_records` and `v3_records` are the complete retained earlier histories (see the module
    docstring). A test-only implementation profile qualifies only with `test_fixture=True`; a WORKER
    capture qualifies only from inside a frozen bracket (check_capture). The record, its migration and the
    cross-capture rules are native-profile v4's (record_schema is v4's schema); the captures are v5's."""
    v4.check_record(record, profile, endpoints, record_schema)
    require(type(test_fixture) is bool and (test_fixture or not record["backendProfile"]["testOnly"]),
            "test-only implementation profile")
    require(type(captures) is list and sorted(c.get("role") for c in captures) == sorted(ROLES),
            "one capture per resident role")
    for capture in captures:
        check_capture(record, capture, capture["role"], record_schema, schema)
    check_lifecycle_capture(record, lifecycle, record_schema, schema)
    require(type(backend_captures) is list
            and sorted(c.get("component") for c in backend_captures) == sorted(record["backendComponents"]),
            "one observation per backend component")
    for capture in backend_captures:
        check_backend_capture(record, capture, record_schema, schema)
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
    v4.check_migration(v1_records, v2_records, v3_records, record, profile, v1_schema, v2_schema, v3_schema,
                       record_schema, no_earlier_history)


def validate_capture(record: Any, capture: Any, role: str, record_schema: dict, schema: dict,
                     previous: Any = None) -> list[str]:
    return _result(check_capture, "invalid DATA_CHECK_ONLY v5 capture; no native authority",
                   record, capture, role, record_schema, schema, previous)


def validate_qualification(*args: Any) -> list[str]:
    """Empty list = accepted as data, given the caller obligations in the module docstring."""
    return _result(check_qualification, "invalid DATA_CHECK_ONLY v5 qualification; no native authority "
                   "(caller must also have validated the profile with the pinned proxy contract)", *args)


# -- data check of the v5 vectors: v4's capture-family and qualification cases replayed under v5, plus the v5 cases
SCHEMA_PATH = "architecture/native-profile-v5/qualification.schema.json"
V5_INPUTS = {"v1Schema": "architecture/native-qualification-inputs/qualification.schema.json",
             "v1Vectors": "architecture/native-qualification-inputs/vectors.json",
             "v2Schema": "architecture/native-profile-v2/qualification.schema.json",
             "v2Vectors": "architecture/native-profile-v2/vectors.json",
             "v3Schema": "architecture/native-profile-v3/qualification.schema.json",
             "v3Vectors": "architecture/native-profile-v3/vectors.json",
             "v4Schema": "architecture/native-profile-v4/qualification.schema.json",
             "v4Vectors": "architecture/native-profile-v4/vectors.json"}
VECTOR_COUNTS = {"positive": 5, "negative": 266, "accepted": 7, "crossVersion": 6}
# v4's targets that v5 replays. v4's record and migration cases stay pinned by v4's vectors: v4's check_record and
# check_migration are unchanged.
REPLAYED_TARGETS = ("capture", "lifecycle", "backend", "qualification")
VARIANTS = {"capture": "capture", "lifecycle": "lifecycleCapture", "backend": "backendCapture"}
VERSIONS = {"capture": V5_CAPTURE, "lifecycle": V5_LIFECYCLE, "backend": V5_BACKEND}
MECHANICAL = {"not a v4 capture": "not a v5 capture", "not a v4 lifecycle capture": "not a v5 lifecycle capture",
              "not a v4 backend capture": "not a v5 backend capture"}
# The v4 cases whose operation edits a dropped field, re-derived to set the whole field (README "Replayed v4 cases"),
# and the texts each such row carries, by dropped field.
REDERIVED_V4_CASES = ("C10", "C11", "L08", "N134", "N135", "V39", "V40")
REDERIVED_WHY = ("v4's operation edits a member of %s, which v5 captures do not carry; the case sets the whole field "
                 "to the v4 positive's value with the same edit")
REDERIVED_REASONS = {
    "hardeningObserved": "the hardening settings are record-only in v5 (OUT_OF_SCOPE_HOST, absent; T04-HOST-LOCKS): a "
                         "capture that carries hardeningObserved is refused by the schema, whatever its value",
    "booleansObserved": "the SELinux booleans are record-only in v5 (OUT_OF_SCOPE_HOST, absent; T04-HOST-LOCKS): a "
                        "capture that carries booleansObserved is refused by the schema, whatever its value",
    "bootEntryObserved": "the boot entry is record-only in v5 (OUT_OF_SCOPE_HOST, absent; T04-BOOT-ENTRY): a capture "
                         "that carries bootEntryObserved is refused by the schema, whatever its value"}
# Q03 (decision Q-NPE-9 (a)): v4's operation sets a whole v4 capture; re-derived to the v5 positive's same
# capture, with its refusal unchanged.
REDERIVED_SAME_REFUSAL = {
    "Q03": "the duplicated server capture is the v5 positive's (v4's row duplicated the v4 positive's)"}
# The v5 cases, in order, each setting one dropped field (README "v5 cases"): id, target, role or component,
# field, and whether the value is the v4 positive's (the record's declared value) or another.
NEW_CASES = (("H01", "capture", "SERVER", "host", True),
             ("H02", "capture", "SERVER", "host", False),
             ("H03", "capture", "OBSERVER", "selinuxBefore", True),
             ("H04", "capture", "OBSERVER", "selinuxBefore", False),
             ("H05", "capture", "BROKER", "selinuxAfter", True),
             ("H06", "capture", "BROKER", "selinuxAfter", False),
             ("H07", "capture", "WORKER", "kernelPolicyDigest", True),
             ("H08", "capture", "WORKER", "kernelPolicyDigest", False),
             ("H09", "capture", "EFFECT_GATE", "booleansObserved", True),
             ("H10", "capture", "EFFECT_GATE", "booleansObserved", False),
             ("H11", "capture", "SERVER", "hardeningObserved", True),
             ("H12", "capture", "OBSERVER", "bootEntryObserved", True),
             ("H13", "lifecycle", None, "host", True),
             ("H14", "lifecycle", None, "host", False),
             ("H15", "lifecycle", None, "booleansObserved", True),
             ("H16", "lifecycle", None, "bootEntryObserved", True),
             ("H17", "backend", "APISERVER", "host", True),
             ("H18", "backend", "KUBELET", "host", False))
DROPPED_FIELD = "schema $ additionalProperties"
NEW_CASE_KEYS = {"capture": ["id", "positive", "target", "role", "intent", "ops", "refusal"],
                 "lifecycle": ["id", "positive", "target", "intent", "ops", "refusal"],
                 "backend": ["id", "positive", "target", "component", "intent", "ops", "refusal"]}


def derive_capture(capture: dict, target: str) -> dict:
    """A v4 capture moved to v5: the dropped host fields removed and the version discriminator moved."""
    out = {key: copy.deepcopy(value) for key, value in capture.items() if key not in HOST_FIELDS[VARIANTS[target]]}
    out["schemaVersion"] = VERSIONS[target]
    return out


def derive_positive(positive: dict) -> dict:
    """A v4 positive under v5: its record, profile and endpoints unchanged, its captures moved to v5."""
    return {"record": copy.deepcopy(positive["record"]), "profile": copy.deepcopy(positive["profile"]),
            "endpoints": copy.deepcopy(positive["endpoints"]),
            "captures": [derive_capture(capture, "capture") for capture in positive["captures"]],
            "lifecycle": derive_capture(positive["lifecycle"], "lifecycle"),
            "backendCaptures": [derive_capture(capture, "backend") for capture in positive["backendCaptures"]]}


def _subject(positive: dict, row: dict) -> dict:
    """The capture a capture-family case edits."""
    if row["target"] == "capture":
        return next(capture for capture in positive["captures"] if capture["role"] == row["role"])
    if row["target"] == "lifecycle":
        return positive["lifecycle"]
    return next(capture for capture in positive["backendCaptures"] if capture["component"] == row["component"])


def check_vectors(vectors: Any, files: dict) -> int:
    """DATA_CHECK_ONLY: replay every v5 vector and check every replayed v4 case against its v4 form.

    `files` maps the v5 schema path and each pinned input path (V5_INPUTS) to its bytes; the inputs must match the
    SHA-256 the vectors pin. Returns the number of checks; any mismatch raises ValueError."""
    require(type(vectors) is dict and set(vectors) == {
        "evidenceClass", "nativeAcceptance", "tenantAcceptance", "schemaSha256", "recordSchemaSha256", "v1SchemaSha256",
        "v2SchemaSha256", "v3SchemaSha256", "derivedFrom", "inputs", "positive", "negative", "accepted", "crossVersion"}
            and vectors["evidenceClass"] == "DATA_CHECK_ONLY" and vectors["nativeAcceptance"] is False
            and vectors["tenantAcceptance"] is False and vectors["derivedFrom"] == V5_INPUTS["v4Vectors"]
            and all(type(vectors[key]) is list and len(vectors[key]) == count for key, count in VECTOR_COUNTS.items()),
            "closed v5 vectors")
    require(type(vectors["inputs"]) is dict and set(vectors["inputs"]) == set(V5_INPUTS), "the pinned inputs")
    pinned = {}
    for key, path in V5_INPUTS.items():
        require(type(files.get(path)) is bytes and vectors["inputs"][key] == {"path": path, "sha256": digest(files[path])},
                "the pinned input " + path)
        pinned[key] = parse(files[path])
    require(type(files.get(SCHEMA_PATH)) is bytes, "the v5 schema")
    schema = parse(files[SCHEMA_PATH])
    s1, s2, s3, s4 = pinned["v1Schema"], pinned["v2Schema"], pinned["v3Schema"], pinned["v4Schema"]
    require(vectors["schemaSha256"] == SCHEMA_SHA256 == digest(canonical(schema))
            and vectors["recordSchemaSha256"] == v4.SCHEMA_SHA256 == digest(canonical(s4))
            and vectors["v1SchemaSha256"] == v4.V1_SCHEMA_SHA256 == digest(canonical(s1))
            and vectors["v2SchemaSha256"] == v4.V2_SCHEMA_SHA256 == digest(canonical(s2))
            and vectors["v3SchemaSha256"] == v4.V3_SCHEMA_SHA256 == digest(canonical(s3)),
            "v5 vectors bound to the pinned schemas")
    old = pinned["v4Vectors"]
    histories = [[row["record"] for row in pinned[key]["positive"]] for key in ("v1Vectors", "v2Vectors", "v3Vectors")]
    positives = vectors["positive"]
    require(len(positives) == len(old["positive"])
            and all(p == derive_positive(o) for p, o in zip(positives, old["positive"])),
            "v5 positives derived from v4's")

    def qualify(p: dict, bundle: dict, test_fixture: bool = True) -> Any:
        return explain(check_qualification, p["record"], p["profile"], p["endpoints"], bundle["captures"],
                       bundle["lifecycle"], bundle["backendCaptures"], *histories, s1, s2, s3, s4, schema, False,
                       test_fixture)

    def case(row: dict) -> Any:
        p = positives[row["positive"]]
        target = row["target"]
        if target == "capture":
            return explain(check_capture, p["record"], _apply(_subject(p, row), row["ops"]), row["role"], s4, schema)
        if target == "lifecycle":
            return explain(check_lifecycle_capture, p["record"], _apply(p["lifecycle"], row["ops"]), s4, schema)
        if target == "backend":
            return explain(check_backend_capture, p["record"], _apply(_subject(p, row), row["ops"]), s4, schema)
        require(target == "qualification", "closed vector target")
        bundle = _apply({key: p[key] for key in ("captures", "lifecycle", "backendCaptures")}, row["ops"])
        return qualify(p, bundle, row.get("testFixture", True))

    for p in positives:
        require(qualify(p, p) is None, "v5 positive refused")
    checks = len(positives)
    for kind in ("negative", "accepted"):
        for row in vectors[kind]:
            result = case(row)
            require(result == row["refusal"] and result is not None if kind == "negative" else result is None,
                    "%s vector %s" % (kind, row["id"]))
            checks += 1
    rows = {row["id"]: (kind, row) for kind in ("negative", "accepted") for row in vectors[kind]}
    require(len(rows) == len(vectors["negative"]) + len(vectors["accepted"]), "unique vector identifiers")
    # Every v4 case of a replayed target is replayed under v5 as v4's row (refusals renamed only by MECHANICAL), unless
    # re-derived: then only its operations and refusal change, and the row records why, its v4 refusal and the reason.
    replayed = set()
    for kind in ("negative", "accepted"):
        for o in old[kind]:
            if o["target"] not in REPLAYED_TARGETS:
                continue
            new_kind, row = rows.get(o["id"], (None, {}))
            replayed.add(o["id"])
            if o["id"] in REDERIVED_V4_CASES:
                # v4's operation is one 'set' inside the dropped field; the v5 operation sets the whole field to the v4
                # positive's value with that edit applied, and the row's texts are the field's pinned texts.
                field = row["ops"][0]["path"][0] if row.get("ops") and row["ops"][0].get("path") else None
                require(kind == new_kind == "negative" and list(row) == list(o) + ["rederived", "v4Refusal", "reason"]
                        and all(row[key] == o[key] for key in o if key not in ("ops", "refusal"))
                        and row["v4Refusal"] == o["refusal"] and row["refusal"] == DROPPED_FIELD
                        and len(o["ops"]) == 1 and o["ops"][0]["op"] == "set" and o["ops"][0]["path"][0] == field
                        and row["ops"] == [{"op": "set", "path": [field], "value": _apply(
                            _subject(old["positive"][o["positive"]], o), o["ops"])[field]}]
                        and row["rederived"] == REDERIVED_WHY % field and row["reason"] == REDERIVED_REASONS[field],
                        "v4 case re-derived: " + o["id"])
            elif o["id"] in REDERIVED_SAME_REFUSAL:
                # v4's operation sets a whole v4 positive capture; the v5 operation sets the v5 positive's same capture.
                op = o["ops"][0] if len(o["ops"]) == 1 else {}
                same = [j for j, capture in enumerate(old["positive"][o["positive"]]["captures"])
                        if op.get("op") == "set" and op.get("value") == capture]
                require(kind == new_kind == "negative" and list(row) == list(o) and len(same) == 1
                        and all(row[key] == o[key] for key in o if key not in ("ops", "rederived"))
                        and row["ops"] == [dict(op, value=positives[o["positive"]]["captures"][same[0]])]
                        and row["rederived"] == REDERIVED_SAME_REFUSAL[o["id"]], "v4 case re-derived: " + o["id"])
            else:
                expected = dict(o, refusal=MECHANICAL.get(o["refusal"], o["refusal"])) if kind == "negative" else o
                require(new_kind == kind and row == expected, "v4 case replayed with its operations: " + o["id"])
    require(set(REDERIVED_V4_CASES) <= replayed, "the re-derived cases are v4's")
    added = [row for row in vectors["negative"] if row["id"] not in replayed]
    v4_ids = {row["id"] for key in ("negative", "accepted", "crossVersion", "migration") for row in old[key]}
    new_ids = [case[0] for case in NEW_CASES]
    require([row["id"] for row in added] == new_ids and not set(new_ids) & v4_ids
            and all(row["target"] in VARIANTS and list(row) == NEW_CASE_KEYS[row["target"]]
                    and row["refusal"] == DROPPED_FIELD for row in added),
            "the v5 cases H01-H18 refuse a dropped field")
    # The closed set: every dropped (variant, field) pair is refused at least once with the v4 positive's value (the
    # record's declared value) and at least once with another value, by a v5 case or a re-derived v4 case setting that
    # field alone.
    halves = set()
    for row in added + [rows[name][1] for name in REDERIVED_V4_CASES]:
        op = row["ops"][0]
        require(len(row["ops"]) == 1 and op["op"] == "set" and len(op["path"]) == 1
                and op["path"][0] in HOST_FIELDS[VARIANTS[row["target"]]], "one dropped field set: " + row["id"])
        source = _subject(old["positive"][row["positive"]], row)
        halves.add((row["target"], op["path"][0], op["value"] == source[op["path"][0]]))
    require(halves == {(target, field, same) for target, variant in VARIANTS.items() for field in HOST_FIELDS[variant]
                       for same in (True, False)},
            "every dropped field refused with its v4 value and with another value")
    # Each v5 case is the one NEW_CASES declares: its target, role or component, field and kind of value.
    for row, (name, target, subject, field, same) in zip(added, NEW_CASES):
        require(row["target"] == target and row.get("role", row.get("component")) == subject
                and row["ops"][0]["path"] == [field]
                and (row["ops"][0]["value"] == _subject(old["positive"][row["positive"]], row)[field]) == same,
                "v5 case as declared: " + name)
    # Cross-version: v4's capture-family cases moved one version up (v4 captures under the v5 model, v5 captures under
    # the v4 schema, which also refuses them for the dropped required fields).
    kinds = ("V3_CAPTURE_UNDER_V4", "V3_LIFECYCLE_UNDER_V4", "V3_BACKEND_CAPTURE_UNDER_V4", "V4_CAPTURE_UNDER_V3",
             "V4_LIFECYCLE_UNDER_V3", "V4_BACKEND_CAPTURE_UNDER_V3")
    moved = [o for o in old["crossVersion"] if o["kind"] in kinds]
    require([row["id"] for row in vectors["crossVersion"]] == [o["id"] for o in moved],
            "v4's capture cross-version cases")
    for row, o in zip(vectors["crossVersion"], moved):
        shifted = o["kind"].replace("V4", "V5").replace("V3", "V4")
        p, q = positives[row["index"]], old["positive"][row["index"]]
        if shifted.startswith("V4_"):
            require(list(row) == ["id", "kind", "index", "expect"] and row["kind"] == shifted
                    and row["index"] == o["index"] and row["expect"] == MECHANICAL[o["expect"]],
                    "cross-version case moved one version up: " + row["id"])
            value, check, args = {
                "V4_CAPTURE_UNDER_V5": (q["captures"][0], check_capture, ("SERVER",)),
                "V4_LIFECYCLE_UNDER_V5": (q["lifecycle"], check_lifecycle_capture, ()),
                "V4_BACKEND_CAPTURE_UNDER_V5": (q["backendCaptures"][0], check_backend_capture, ())}[shifted]
            require(explain(check, p["record"], value, *args, s4, schema) == row["expect"],
                    "cross-version " + row["id"])
        else:
            require(list(row) == ["id", "kind", "index", "mustInclude"] and row["kind"] == shifted
                    and row["index"] == o["index"] and row["mustInclude"] == o["mustInclude"] + [["$", "required"]],
                    "cross-version case moved one version up: " + row["id"])
            value, variant = {"V5_CAPTURE_UNDER_V4": (p["captures"][0], "capture"),
                              "V5_LIFECYCLE_UNDER_V4": (p["lifecycle"], "lifecycleCapture"),
                              "V5_BACKEND_CAPTURE_UNDER_V4": (p["backendCaptures"][0], "backendCapture")}[shifted]
            errors = {(error.json_path, error.validator) for error in schema_errors(value, s4, variant)}
            require(all(tuple(pair) in errors for pair in row["mustInclude"]), "cross-version " + row["id"])
        checks += 1
    return checks
