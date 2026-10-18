#!/usr/bin/env python3
"""I06 backend profile v3: I06 v2's distribution evidence bound to an accepted native-profile v4 (W02a v4) record.

Successor of the adopted I06 backend profile v2 (architecture/i06-backend-profile-v2/, MET-ENFORCE-012, as corrected by
the W02 notes errata). v3 moves the W02a binding from native-profile v3 to native-profile v4 (W02A_VERSION, the v4
schema digest that v4's check_record pins, and v4's check_record) and changes nothing else: the evidence record format,
SC00-SC15, the snapshot check IC00-IC05 and the v1 inputs are v2's. The writer inventory, identity closure, upstream
facts, upstream bootstrap RBAC and the v1 model (scripts/i06_backend_profile.py) stay unchanged and are read from there.
v2's answers to the W02g round-2 findings, with the binding moved:

- N1: an evidence record names one W02a v4 record by schema version and qualification digest, and that record must be
  one that W02a v4's `check_record` accepts. A test-only backend qualifies only in an explicit fixture call, as in
  W02a v4's `check_qualification`. W02a v4 admits only the test-only unit-distribution backend, and this model is
  bound to W02a v4's pinned schema, so no production call is accepted. Production evidence needs both a reviewed W02a
  revision with a production backend profile and an I06 successor bound to it (W03).
- N2: the apiserver's loopback user system:apiserver holds no resource rule at all, not only no policy-relevant one;
  an observer that finds a non-resource-URL rule on it refuses to produce the snapshot (W03).
- N3: shared and nested backend cgroups are refused by W02a v4's `check_record`, which N1 applies.

- `check_evidence` checks one distribution evidence record (SC00-SC15) against its W02a v4 record.
- `check_rbac_snapshot` checks an effective-RBAC snapshot against a checked closure (IC00-IC05).
- `check_inventory` and `check_closure` are the v1 checks; their inputs are unchanged.

DATA_CHECK_ONLY: none of them inspects a cluster, a distribution or a kernel, grants authority or selects a
distribution. Every refusal names the criterion or closure rule it breaks.
"""
from __future__ import annotations

import copy
from typing import Any

try:
    import i06_backend_profile as v1
    import native_qualification_v4 as w02a
except ImportError:
    from scripts import i06_backend_profile as v1
    from scripts import native_qualification_v4 as w02a

EVIDENCE_VERSION = "planeon.internal.i06-distribution-evidence/v2"
SNAPSHOT_VERSION = v1.SNAPSHOT_VERSION
W02A_VERSION = "planeon.internal.native-qualification/v4"
LOOPBACK_USER = ("User", "system:apiserver")
EVIDENCE_KEYS = {"schemaVersion", "w02aRecord", "implementationId", "testOnly", "kubernetesVersion", "distribution",
                 "artifacts", "components", "datastore", "apiserver", "controllerManager", "kubelet", "versioning",
                 "credentialsOnHost", "apiClients", "runtimeSocket", "sealedConfiguration"}
V1_PROFILE_KEYS = ("profile", "implementationId", "componentKeys")

require = v1.require
check_inventory = v1.check_inventory
check_closure = v1.check_closure


def record_digest(record: Any) -> str:
    """W02a's qualification digest of a record: "sha256:" and the lowercase hex SHA-256 of W02a's canonical JSON form
    (sorted keys, no whitespace, UTF-8), as W02a v4 captures spell `qualificationDigest`."""
    return "sha256:" + w02a.digest(w02a.canonical(record))


def check_evidence(record: Any, inventory: dict, w02a_record: Any, w02a_profile: Any, w02a_endpoints: Any,
                   w02a_schema: dict, test_fixture: bool = False) -> None:
    """Check one evidence record against SC00-SC15, bound by digest to one W02a v4 record that check_record accepts.

    The evidence binds to that one record (one boot, nonce set and validity window) and is re-issued for each record.
    `check_record` is not W02a's acceptance decision: combining this check with `check_qualification`'s acceptance of
    the same record is the caller's composition (W03). Callers inherit W02a v4's caller obligations 1 (the profile is
    valid under the pinned proxy profile contract) and 4 (`test_fixture=True` only when qualifying a test fixture).
    `test_fixture` must be True to accept a test-only backend; it is the only way to accept one (N1)."""
    require(type(test_fixture) is bool, "SC00 fixture flag must be a boolean")
    v1._keys(record, EVIDENCE_KEYS, "SC00 closed evidence record")
    require(record["schemaVersion"] == EVIDENCE_VERSION, "SC00 evidence version")
    reference = record["w02aRecord"]
    v1._keys(reference, {"schemaVersion", "qualificationDigest"}, "SC00 closed W02a record reference")
    require(reference["schemaVersion"] == W02A_VERSION, "SC00 evidence names a W02a record of another version")
    refusal = w02a.explain(w02a.check_record, w02a_record, w02a_profile, w02a_endpoints, w02a_schema)
    require(refusal is None, "SC00 W02a v4 refuses the backend record: %s" % refusal)
    require(type(reference["qualificationDigest"]) is str and reference["qualificationDigest"] == record_digest(w02a_record),
            "SC00 evidence names a different W02a record")
    backend = w02a_record["backendProfile"]
    require(type(record["testOnly"]) is bool and record["testOnly"] is backend["testOnly"],
            "SC00 evidence and its W02a backend disagree on test-only")
    require(test_fixture or backend["testOnly"] is False,
            "SC00 a test-only W02a backend qualifies only in an explicit fixture call")
    projection = {key: value for key, value in record.items() if key != "w02aRecord"}
    projection["schemaVersion"] = v1.EVIDENCE_VERSION
    v1.check_evidence(projection, inventory,
                      {"backendProfile": {key: backend[key] for key in V1_PROFILE_KEYS},
                       "backendComponents": w02a_record["backendComponents"]},
                      production=not test_fixture)


def check_rbac_snapshot(snapshot: Any, closure: dict, inventory: dict, bootstrap: Any, namespace: str) -> None:
    """IC00-IC05 as in v1; in addition the loopback user system:apiserver holds no resource rule at all (N2).

    The v1 snapshot shape carries resource rules only. Observer obligation: a non-resource-URL rule bound to
    system:apiserver is not dropped; the observer refuses to produce the snapshot (carried to W03)."""
    v1.check_rbac_snapshot(snapshot, closure, inventory, bootstrap, namespace)
    for subject in snapshot["subjects"]:
        if (subject["kind"], subject["name"]) == LOOPBACK_USER:
            require(subject["effectiveRules"] == [], "IC03 the loopback user system:apiserver holds an RBAC rule")


ERRORS = v1.ERRORS
explain = v1.explain


# -- data check of the I06 v3 vectors: v2's evidence cases re-derived against native-profile v4's positives, v2's
# snapshot cases carried, and the cross-version cases
V3_INPUTS = {"v1Vectors": "architecture/i06-backend-profile/vectors.json",
             "v2Vectors": "architecture/i06-backend-profile-v2/vectors.json",
             "w02aVectors": "architecture/native-profile-v4/vectors.json",
             "w02aSchema": "architecture/native-profile-v4/qualification.schema.json",
             "w02aV2Vectors": "architecture/native-profile-v2/vectors.json",
             "inventory": "architecture/i06-backend-profile/writer-inventory.json",
             "closure": "architecture/i06-backend-profile/identity-closure.json",
             "bootstrap": "architecture/i06-backend-profile/upstream-bootstrap-rbac-v1.37.1.json"}
VECTOR_FLOORS = {"evidenceAccepted": 7, "snapshotAccepted": 5, "evidenceNegative": 91, "snapshotNegative": 38, "crossVersion": 7}
# W02a refusals reported by SC00 name the bound W02a version; v2's refusals move with the binding.
BOUND_REFUSAL = ("SC00 W02a v3 refuses the backend record: ", "SC00 W02a v4 refuses the backend record: ")
# G19 (one multi-call executable for every component) is refused by W02a v4's check_record (DESIGN D2-11 (e)).
CHANGED_V2_REFUSALS = ("G19",)
DISTINCTNESS = "SC08 components must use distinct executables with distinct content (one entry type per confined domain)"


def _locate(node: Any, key: Any) -> Any:
    if type(key) is dict:
        found = [index for index, item in enumerate(node) if all(item.get(k) == v for k, v in key.items())]
        require(len(found) == 1, "vector selector must match exactly one element")
        return found[0]
    return key


def _apply(value: Any, ops: list) -> Any:
    value = copy.deepcopy(value)
    for op in ops:
        require(type(op) is dict and op.get("op") in ("set", "delete", "append") and type(op.get("path")) is list
                and op["path"], "closed vector operation")
        *parents, last = op["path"]
        node = value
        for key in parents:
            node = node[_locate(node, key)]
        if op["op"] == "set":
            node[_locate(node, last)] = copy.deepcopy(op["value"])
        elif op["op"] == "delete":
            del node[_locate(node, last)]
        else:
            node[_locate(node, last)].append(copy.deepcopy(op["value"]))
    return value


def _moved(refusal: Any) -> Any:
    """A v2 refusal with the binding moved: the SC00 prefix and the W02a rule's own version name (w02a.MECHANICAL)."""
    if not str(refusal).startswith(BOUND_REFUSAL[0]):
        return refusal
    rule = refusal[len(BOUND_REFUSAL[0]):]
    return BOUND_REFUSAL[1] + w02a.MECHANICAL.get(rule, rule)


def check_vectors(vectors: Any, files: dict) -> int:
    """DATA_CHECK_ONLY: replay every I06 v3 vector, and check it against I06 v2's.

    `files` maps each input path (V3_INPUTS) to its bytes; the v1 and v2 vectors must match the SHA-256 the vectors pin.
    Returns the number of checks; any mismatch raises ValueError."""
    require(type(vectors) is dict and set(vectors) == {
        "evidenceClass", "kubernetesBaseline", "qualificationNamespace", "v1Vectors", "v2Vectors", "w02aBackend",
        "evidencePositive", "snapshotPositive", "evidenceAccepted", "snapshotAccepted", "evidenceNegative",
        "snapshotNegative", "crossVersion"}
            and vectors["evidenceClass"] == "DATA_CHECK_ONLY" and vectors["kubernetesBaseline"] == "v1.37.1"
            and all(type(files.get(path)) is bytes for path in V3_INPUTS.values())
            and vectors["v1Vectors"] == {"path": V3_INPUTS["v1Vectors"], "sha256": w02a.digest(files[V3_INPUTS["v1Vectors"]])}
            and vectors["v2Vectors"] == {"path": V3_INPUTS["v2Vectors"], "sha256": w02a.digest(files[V3_INPUTS["v2Vectors"]])}
            and vectors["w02aBackend"] == {"vectors": V3_INPUTS["w02aVectors"], "schema": V3_INPUTS["w02aSchema"],
                                           "positive": 0}
            and all(type(vectors[key]) is list and len(vectors[key]) >= floor for key, floor in VECTOR_FLOORS.items()),
            "closed I06 v3 vectors")
    data = {key: w02a.parse(files[path]) for key, path in V3_INPUTS.items()}
    v1_vectors, v2_vectors, w02a_schema = data["v1Vectors"], data["v2Vectors"], data["w02aSchema"]
    inventory, closure, bootstrap = data["inventory"], data["closure"], data["bootstrap"]
    positives = data["w02aVectors"]["positive"]
    namespace = vectors["qualificationNamespace"]
    evidence, snapshot = vectors["evidencePositive"], vectors["snapshotPositive"]
    require(namespace == v2_vectors["qualificationNamespace"] and snapshot == v2_vectors["snapshotPositive"]
            and {key: value for key, value in evidence.items() if key != "w02aRecord"}
            == {key: value for key, value in v2_vectors["evidencePositive"].items() if key != "w02aRecord"}
            and evidence["w02aRecord"] == {"schemaVersion": W02A_VERSION,
                                           "qualificationDigest": record_digest(positives[0]["record"])},
            "v3 positives are v2's, bound to native-profile v4 positive 0")

    def bound(row: dict) -> tuple:
        p = positives[row.get("w02aPositive", 0)]
        return _apply(p["record"], row["backendOps"]), p["profile"], p["endpoints"]

    def evidence_result(row: dict) -> Any:
        record, profile, endpoints = bound(row)
        base = copy.deepcopy(evidence)
        base["w02aRecord"]["qualificationDigest"] = record_digest(record)
        return explain(check_evidence, _apply(base, row["ops"]), inventory, record, profile, endpoints, w02a_schema,
                       row["testFixture"])

    def snapshot_result(row: dict) -> Any:
        return explain(check_rbac_snapshot, _apply(snapshot, row["ops"]), closure, inventory, bootstrap,
                       row.get("namespace", namespace))

    record, profile, endpoints = positives[0]["record"], positives[0]["profile"], positives[0]["endpoints"]
    require(explain(check_evidence, evidence, inventory, record, profile, endpoints, w02a_schema, True) is None
            and explain(check_evidence, evidence, inventory, record, profile, endpoints, w02a_schema, False)
            == "SC00 a test-only W02a backend qualifies only in an explicit fixture call"
            and explain(check_rbac_snapshot, snapshot, closure, inventory, bootstrap, namespace) is None,
            "v3 positives: accepted as a fixture, refused in production")
    checks = 3
    for row in vectors["evidenceAccepted"]:
        require(row["testFixture"] is True and evidence_result(row) is None, "accepted evidence variant " + row["id"])
        checks += 1
    for row in vectors["snapshotAccepted"]:
        require(snapshot_result(row) is None, "accepted snapshot variant " + row["id"])
        checks += 1
    for key, replay in (("evidenceNegative", evidence_result), ("snapshotNegative", snapshot_result)):
        for row in vectors[key]:
            result = replay(row)
            require(result is not None and result == row["refusal"], key + " " + row["id"] + " refusal")
            checks += 1
    # Every v2 evidence case is replayed with its operations and flags; its refusal moves with the binding, and only
    # the pinned set changes for a reason. Snapshot cases are carried unchanged.
    new_evidence = {row["id"]: row for row in vectors["evidenceNegative"]}
    for old in v2_vectors["evidenceNegative"]:
        row = new_evidence.get(old["id"], {})
        changed = old["id"] in CHANGED_V2_REFUSALS
        require(all(row.get(key) == old.get(key) for key in ("ops", "backendOps", "testFixture", "w02aPositive"))
                and "v1Refusal" not in row and ("v2Refusal" in row) == changed
                and (row.get("refusal") == _moved(old["refusal"])) != changed
                and (not changed or row["v2Refusal"] == old["refusal"]), "v2 evidence negative replayed: " + old["id"])
    accepted = {row["id"]: row for row in vectors["evidenceAccepted"]}
    for old in v2_vectors["evidenceAccepted"]:
        require({key: accepted.get(old["id"], {}).get(key) for key in old} == old, "v2 accepted variant replayed: " + old["id"])
    require(vectors["snapshotNegative"][:len(v2_vectors["snapshotNegative"])] == v2_vectors["snapshotNegative"]
            and vectors["snapshotAccepted"][:len(v2_vectors["snapshotAccepted"])] == v2_vectors["snapshotAccepted"],
            "v2 snapshot cases carried")
    # Code distinctness: G20 stays an SC08 refusal with a backend W02a v4 accepts; G19 is W02a v4's refusal.
    require(w02a.explain(w02a.check_record, *bound(new_evidence["G20"]), w02a_schema) is None
            and new_evidence["G20"]["refusal"] == DISTINCTNESS
            and new_evidence["G19"]["refusal"] == BOUND_REFUSAL[1] + "backend components share an executable",
            "code distinctness: G20 by SC08, G19 by W02a v4")
    # Cross-version: the v1 model with the W02a v2 backend against the v3 model with the W02a v4 record.
    old_record = data["w02aV2Vectors"]["positive"][0]["record"]
    old_backend = {"backendProfile": old_record["backendProfile"], "backendComponents": old_record["backendComponents"]}
    v2_cross = {row["id"]: row for row in v2_vectors["crossVersion"]}
    ids = []
    for row in vectors["crossVersion"]:
        ids.append(row["id"])
        if row["id"] in v2_cross:
            old = v2_cross[row["id"]]
            require(all(row.get(key) == old.get(key) for key in ("subject", "ops", "backendOps", "production", "namespace",
                                                                  "v1Result")), "v2 cross-version case replayed: " + row["id"])
        if row["subject"] == "snapshot":
            value = _apply(snapshot, row["ops"])
            require(row["v1Result"] == v1.explain(v1.check_rbac_snapshot, value, closure, inventory, bootstrap,
                                                  row["namespace"]) is None
                    and row["v3Result"] == snapshot_result({"ops": row["ops"], "namespace": row["namespace"]}) is not None,
                    "cross-version " + row["id"])
        else:
            require(row["subject"] == "evidence" and row["v1Subject"] in ("v1", "v2", "v3")
                    and row["v3Subject"] in ("v1", "v2", "v3"), "closed cross-version case")
            current, current_profile, current_endpoints = bound(row)
            mine = copy.deepcopy(evidence)
            mine["w02aRecord"]["qualificationDigest"] = record_digest(current)
            bases = {"v1": v1_vectors["evidencePositive"], "v2": v2_vectors["evidencePositive"], "v3": mine}
            require(row["v1Result"] == v1.explain(v1.check_evidence, _apply(bases[row["v1Subject"]], row["ops"]),
                                                  inventory, _apply(old_backend, row["backendOps"]), row["production"])
                    and row["v3Result"] == explain(check_evidence, _apply(bases[row["v3Subject"]], row["ops"]), inventory,
                                                   current, current_profile, current_endpoints, w02a_schema,
                                                   not row["production"]),
                    "cross-version " + row["id"])
        checks += 1
    require(set(v2_cross) <= set(ids), "every v2 cross-version case is replayed")
    all_ids = ids + [row["id"] for key in ("evidenceAccepted", "snapshotAccepted", "evidenceNegative", "snapshotNegative")
                     for row in vectors[key]]
    require(len(all_ids) == len(set(all_ids)), "unique vector identifiers")
    return checks
