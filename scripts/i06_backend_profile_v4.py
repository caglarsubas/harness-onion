#!/usr/bin/env python3
"""I06 backend profile v4: I06 v3 plus the policy observer's closed ClusterRole and binding, pinned exactly.

Successor of I06 backend profile v3 (architecture/i06-backend-profile-v3/, MET-ENFORCE-033), under owner decisions
Q-HE4-6 (a) (2026-10-18) and Q-RBAC-1..8 (a), and monitor decisions Q-RBAC-9 (a), Q-RBAC-10 and Q-RBAC-11 (a)
(2026-10-19). v4 imports v3 and changes no evidence rule: `check_evidence`
is v3's function object, bound to native-profile v4 (W02a v4) as before; the evidence record stays
planeon.internal.i06-distribution-evidence/v2 and the snapshot record planeon.internal.i06-rbac-snapshot/v1. The writer
inventory, identity closure, upstream facts and upstream bootstrap RBAC are v1's, unchanged. v4 adds:

- the observer RBAC document (architecture/i06-backend-profile-v4/observer-rbac.json): one ClusterRole and one
  ClusterRoleBinding, both named planeon:policy-observer, whose rules are OBSERVER_RULES, fixed by this model: list and
  watch on the 19 (group, resource) pairs of HE-004C's 20 request specs, and get on its five non-resource URLs;
- `check_observer_document` (RB00): the document equals the model's;
- `check_observer_rbac` (RB01-RB04, RB06, RB07): RBAC objects (HE-008's manifest, or the observer's live lists) hold
  exactly the contract's ClusterRole and binding, no other binding names the observer (RB06; this covers non-resource
  rules, which the snapshot cannot carry), and nothing else reaches the role: no other binding references it and no
  aggregated ClusterRole selects it (RB07, monitor decision Q-RBAC-9 (a));
- `check_rbac_snapshot`: v3's IC00-IC05 first, unchanged, then RB05: the observer holds exactly the role's resource
  rules, at cluster scope;
- `check_observer_snapshot`: the two composed. Caller obligation (Q-RBAC-3 (a)): the observer accepts its snapshot only
  if `check_observer_snapshot` accepts it, given the ClusterRoles, ClusterRoleBindings and RoleBindings of the same
  read, at the snapshot's one resourceVersion, from which the snapshot was produced.

Limit (Q-RBAC-7 (a), Q-RBAC-11 (a)): only bindings naming User planeon:policy-observer are pinned, with RB07's
references to the role. Grants that reach the observer through its implicit group system:authenticated beyond the stock
bootstrap ones are neither pinned here nor seen by I06 when they are reads (carried to T04 and HE-004-I01).

The observer's grants are reads, which I06's policy-relevant categories do not classify, so v3's IC03 accepts any read
on the observer; RB05, RB06 and RB07 are exact instead. DATA_CHECK_ONLY: nothing here inspects a cluster, grants
authority or selects a distribution. Every refusal names its criterion.
"""
from __future__ import annotations

import copy
from typing import Any

try:
    import i06_backend_profile as v1
    import i06_backend_profile_v3 as v3
except ModuleNotFoundError:
    from scripts import i06_backend_profile as v1
    from scripts import i06_backend_profile_v3 as v3

RBAC_VERSION = "planeon.internal.i06-observer-rbac/v1"
KUBERNETES_VERSION = v1.KUBERNETES_VERSION
EVIDENCE_VERSION = v3.EVIDENCE_VERSION
SNAPSHOT_VERSION = v3.SNAPSHOT_VERSION
W02A_VERSION = v3.W02A_VERSION
RBAC_GROUP = "rbac.authorization.k8s.io"
RBAC_API_VERSION = RBAC_GROUP + "/v1"
OBSERVER_NAME = "planeon:policy-observer"
OBSERVER = ("User", OBSERVER_NAME)
# Q-RBAC-2 (a): the ClusterRole and the ClusterRoleBinding are both named after the user.
ROLE_NAME = OBSERVER_NAME
BINDING_NAME = OBSERVER_NAME
# HE-004C's requests (R10 1a0c529, MODEL_DEFINED R116): list and watch on the 19 pairs of the 20 request specs (OR05's
# two Secret specs share core secrets), and get on the five fixed non-resource targets, in their own rule.
OBSERVER_RULES = [
    {"apiGroups": [""], "resources": ["limitranges", "namespaces", "resourcequotas", "serviceaccounts", "secrets"],
     "verbs": ["list", "watch"]},
    {"apiGroups": ["networking.k8s.io"], "resources": ["networkpolicies"], "verbs": ["list", "watch"]},
    {"apiGroups": ["rbac.authorization.k8s.io"], "resources": ["roles", "rolebindings", "clusterroles", "clusterrolebindings"],
     "verbs": ["list", "watch"]},
    {"apiGroups": ["admissionregistration.k8s.io"],
     "resources": ["validatingwebhookconfigurations", "mutatingwebhookconfigurations", "mutatingadmissionpolicies",
                   "mutatingadmissionpolicybindings", "validatingadmissionpolicies", "validatingadmissionpolicybindings"],
     "verbs": ["list", "watch"]},
    {"apiGroups": ["apiregistration.k8s.io"], "resources": ["apiservices"], "verbs": ["list", "watch"]},
    {"apiGroups": ["apiextensions.k8s.io"], "resources": ["customresourcedefinitions"], "verbs": ["list", "watch"]},
    {"apiGroups": ["certificates.k8s.io"], "resources": ["certificatesigningrequests"], "verbs": ["list", "watch"]},
    {"nonResourceURLs": ["/metrics", "/readyz/poststarthook/rbac/bootstrap-roles", "/version",
                         "/apis/admissionregistration.k8s.io", "/apis/admissionregistration.k8s.io/*"],
     "verbs": ["get"]},
]
RULE_KEYS = ("apiGroups", "resources", "nonResourceURLs", "verbs", "resourceNames")
# Fields the apiserver sets on a stored object; the contract's objects carry none of them, and they grant nothing.
SERVER_METADATA = ("uid", "resourceVersion", "generation", "creationTimestamp", "managedFields")
SECRET_RESIDUAL = {
    "id": "SECRET-READS",
    "object": "ClusterRole/planeon:policy-observer",
    "ruleIndex": 0,
    "resource": "secrets",
    "verbs": ["list", "watch"],
    "text": ("RBAC has no metadata-only verb and no field-selector rule, so list and watch on secrets at cluster scope "
             "permit full Secret reads in every namespace, although HE-004C requests only the two field-selected, "
             "metadata-only lists and watches of OR05. The owner accepted this residual (Q-HE4-6 (a), 2026-10-18); it is "
             "re-assessed at HE-004-I01, where the optional audit check is decided (Q-RBAC-5 (a))."),
}

require = v1.require
check_evidence = v3.check_evidence
check_inventory = v3.check_inventory
check_closure = v3.check_closure
ERRORS = v1.ERRORS
explain = v1.explain


def observer_role() -> dict:
    return {"apiVersion": RBAC_API_VERSION, "kind": "ClusterRole", "metadata": {"name": ROLE_NAME},
            "rules": copy.deepcopy(OBSERVER_RULES)}


def observer_binding() -> dict:
    return {"apiVersion": RBAC_API_VERSION, "kind": "ClusterRoleBinding", "metadata": {"name": BINDING_NAME},
            "roleRef": {"apiGroup": RBAC_GROUP, "kind": "ClusterRole", "name": ROLE_NAME},
            "subjects": [{"apiGroup": RBAC_GROUP, "kind": "User", "name": OBSERVER_NAME}]}


def observer_document() -> dict:
    """The observer RBAC document: the identity, the two objects HE-008 applies as they are, and the marked residual."""
    return {"schemaVersion": RBAC_VERSION, "kubernetesBaseline": KUBERNETES_VERSION,
            "identity": {"kind": "User", "name": OBSERVER_NAME, "certificateSubject": "CN=" + OBSERVER_NAME,
                         "certificateOrganizations": [], "extendedKeyUsage": ["clientAuth"]},
            "objects": [observer_role(), observer_binding()],
            "residuals": [copy.deepcopy(SECRET_RESIDUAL)]}


def observer_snapshot_rules() -> list[dict]:
    """The role's resource rules as the RBAC snapshot carries them through a ClusterRoleBinding, in role order."""
    return [{"apiGroups": list(rule["apiGroups"]), "resources": list(rule["resources"]), "verbs": list(rule["verbs"]),
             "resourceNames": [], "scope": v1.CLUSTER} for rule in OBSERVER_RULES if "resources" in rule]


def _same(a: Any, b: Any) -> bool:
    return v1.canonical(a) == v1.canonical(b)


def check_observer_document(document: Any) -> None:
    """RB00: the closed observer RBAC document equals the model's."""
    expected = observer_document()
    v1._keys(document, set(expected), "RB00 closed observer RBAC document")
    require(document["schemaVersion"] == RBAC_VERSION and document["kubernetesBaseline"] == KUBERNETES_VERSION,
            "RB00 observer RBAC document version")
    require(_same(document["identity"], expected["identity"]),
            "RB00 the observer RBAC document's identity differs from the model's")
    require(_same(document["objects"], expected["objects"]),
            "RB00 the observer RBAC document's objects differ from the model's ClusterRole and binding")
    require(_same(document["residuals"], expected["residuals"]),
            "RB00 the observer RBAC document's residuals differ from the model's")


def _items(objects: dict, key: str) -> list:
    items = objects[key]
    require(type(items) is list and all(type(item) is dict and type(item.get("metadata")) is dict
                                        and v1._text(item["metadata"].get("name")) for item in items),
            "RB01 closed RBAC object lists")
    return items


def _shape(obj: dict, kind: str, members: set[str], where: str) -> None:
    unknown = sorted(set(obj) - members)
    require(not unknown, where + " holds an unknown member: " + ",".join(unknown))
    for key, value in (("kind", kind), ("apiVersion", RBAC_API_VERSION)):
        require(key not in obj or obj[key] == value, where + "'s kind or apiVersion differs")
    extra = sorted(set(obj["metadata"]) - {"name"} - set(SERVER_METADATA))
    require(not extra, where + "'s metadata holds " + ",".join(extra))


def _rule(rule: Any, index: int) -> dict:
    """A rule's five lists; an absent or null list is empty (as R10's producer reads them, R99)."""
    require(type(rule) is dict, "RB02 the observer ClusterRole's rule %d is malformed" % index)
    unknown = sorted(set(rule) - set(RULE_KEYS))
    require(not unknown, "RB02 the observer ClusterRole's rule %d holds an unknown member: %s" % (index, ",".join(unknown)))
    out = {}
    for key in RULE_KEYS:
        value = [] if rule.get(key) is None else rule[key]
        require(type(value) is list and all(type(item) is str for item in value),
                "RB02 the observer ClusterRole's rule %d is malformed" % index)
        out[key] = value
    return out


def _selects_unlabeled(selector: Any, where: str) -> bool:
    """Whether a label selector matches an object with no labels (the contract's ClusterRole carries none, RB01): no
    matchLabels, and every expression NotIn or DoesNotExist. An empty selector matches every object. A selector this
    cannot read refuses (fail closed)."""
    require(type(selector) is dict and set(selector) <= {"matchLabels", "matchExpressions"},
            "RB07 an aggregationRule selector is malformed: " + where)
    labels = {} if selector.get("matchLabels") is None else selector["matchLabels"]
    expressions = [] if selector.get("matchExpressions") is None else selector["matchExpressions"]
    require(type(labels) is dict and type(expressions) is list and all(
        type(e) is dict and v1._text(e.get("key")) and e.get("operator") in ("In", "NotIn", "Exists", "DoesNotExist")
        for e in expressions), "RB07 an aggregationRule selector is malformed: " + where)
    return not labels and all(e["operator"] in ("NotIn", "DoesNotExist") for e in expressions)


def check_observer_rbac(objects: Any) -> None:
    """RB01-RB04, RB06 and RB07 over {clusterRoles, clusterRoleBindings, roleBindings}: HE-008's manifest (the
    document's two objects, no RoleBindings) or the observer's live lists. Server-set metadata is ignored; anything else
    is exact."""
    v1._keys(objects, {"clusterRoles", "clusterRoleBindings", "roleBindings"}, "RB01 closed RBAC object lists")
    roles, cluster_bindings, role_bindings = (_items(objects, key) for key in ("clusterRoles", "clusterRoleBindings",
                                                                                 "roleBindings"))
    found = [item for item in roles if item["metadata"]["name"] == ROLE_NAME]
    require(len(found) == 1, "RB01 the observer ClusterRole is missing or repeated")
    role = found[0]
    require("aggregationRule" not in role, "RB01 the observer ClusterRole has an aggregationRule")
    _shape(role, "ClusterRole", {"apiVersion", "kind", "metadata", "rules"}, "RB01 the observer ClusterRole")
    rules = [] if role.get("rules") is None else role["rules"]
    require(type(rules) is list, "RB02 the observer ClusterRole's rules are not a list")
    require(len(rules) == len(OBSERVER_RULES),
            "RB02 the observer ClusterRole holds %d rules, the contract %d" % (len(rules), len(OBSERVER_RULES)))
    for index, (got, want) in enumerate(zip(rules, OBSERVER_RULES), 1):
        got, want = _rule(got, index), _rule(want, index)
        for key in RULE_KEYS:
            require(_same(got[key], want[key]),
                    "RB02 the observer ClusterRole's rule %d differs from the contract: %s" % (index, key))
    found = [item for item in cluster_bindings if item["metadata"]["name"] == BINDING_NAME]
    require(len(found) == 1, "RB03 the observer ClusterRoleBinding is missing or repeated")
    binding = found[0]
    _shape(binding, "ClusterRoleBinding", {"apiVersion", "kind", "metadata", "roleRef", "subjects"},
           "RB03 the observer ClusterRoleBinding")
    require(_same(binding.get("roleRef"), observer_binding()["roleRef"]),
            "RB03 the observer ClusterRoleBinding's roleRef is not the observer ClusterRole")
    require(_same(binding.get("subjects"), observer_binding()["subjects"]),
            "RB04 the observer ClusterRoleBinding's subjects are not exactly User planeon:policy-observer")
    for kind, items in (("ClusterRoleBinding", cluster_bindings), ("RoleBinding", role_bindings)):
        for item in items:
            if item is binding:
                continue
            namespace = item["metadata"].get("namespace")
            where = "%s/%s%s" % (kind, namespace + "/" if kind == "RoleBinding" and type(namespace) is str else "",
                                 item["metadata"]["name"])
            subjects = [] if item.get("subjects") is None else item["subjects"]
            require(type(subjects) is list and all(type(subject) is dict for subject in subjects),
                    "RB06 a binding's subjects are malformed: " + where)
            require(not any(subject.get("kind") == "User" and subject.get("name") == OBSERVER_NAME for subject in subjects),
                    "RB06 a binding other than the contract's names the observer: " + where)
            # RB07 (Q-RBAC-9 (a)): only the contract's binding references the role, whatever the subject.
            role_ref = item.get("roleRef")
            require(type(role_ref) is dict, "RB07 a binding's roleRef is malformed: " + where)
            require(not (role_ref.get("kind") == "ClusterRole" and role_ref.get("name") == ROLE_NAME),
                    "RB07 a binding other than the contract's references the observer ClusterRole: " + where)
    # RB07: no other ClusterRole aggregates the role (an aggregationRule selector that matches its empty labels).
    for item in roles:
        if item is role or "aggregationRule" not in item:
            continue
        where = "ClusterRole/" + item["metadata"]["name"]
        rule = item["aggregationRule"]
        selectors = [] if rule is None else (rule.get("clusterRoleSelectors") if type(rule) is dict else None)
        selectors = [] if type(rule) is dict and selectors is None else selectors
        require(type(selectors) is list, "RB07 an aggregationRule selector is malformed: " + where)
        require(not any(_selects_unlabeled(selector, where) for selector in selectors),
                "RB07 an aggregated ClusterRole selects the observer ClusterRole: " + where)


def check_rbac_snapshot(snapshot: Any, closure: dict, inventory: dict, bootstrap: Any, namespace: str) -> None:
    """IC00-IC05 as in v3 (every v3 refusal first), then RB05: the observer is present and holds exactly the role's
    resource rules at cluster scope, nothing else at any scope (the snapshot carries resource rules only; RB06 covers
    the rest)."""
    v3.check_rbac_snapshot(snapshot, closure, inventory, bootstrap, namespace)
    found = [subject for subject in snapshot["subjects"] if (subject["kind"], subject["name"]) == OBSERVER]
    require(len(found) == 1, "RB05 the observer is absent from the RBAC snapshot")
    require(_same(found[0]["effectiveRules"], observer_snapshot_rules()),
            "RB05 the observer's effective rules are not exactly the observer ClusterRole's resource rules")


def check_observer_snapshot(snapshot: Any, objects: Any, closure: dict, inventory: dict, bootstrap: Any,
                            namespace: str) -> None:
    """The observer's acceptance of one snapshot (Q-RBAC-3 (a)). Caller obligation: `objects` are the ClusterRoles,
    ClusterRoleBindings and RoleBindings of the same read, at the snapshot's one resourceVersion, from which `snapshot`
    was produced. The observer accepts its snapshot only if this accepts: check_rbac_snapshot (IC00-IC05, RB05) on the
    snapshot first, then check_observer_rbac (RB01-RB04, RB06, RB07) on those lists. HE-008's manifest check is
    check_observer_document and check_observer_rbac alone."""
    check_rbac_snapshot(snapshot, closure, inventory, bootstrap, namespace)
    check_observer_rbac(objects)


# -- data check of the I06 v4 vectors: the document, the object cases, v3's snapshot cases replayed on the v4 positive,
# the new snapshot cases and the cross-version cases
V4_DIR = "architecture/i06-backend-profile-v4/"
V4_INPUTS = {"v3Vectors": "architecture/i06-backend-profile-v3/vectors.json",
             "v3Criteria": "architecture/i06-backend-profile-v3/criteria.json",
             "criteria": V4_DIR + "criteria.json",
             "observerRbac": V4_DIR + "observer-rbac.json",
             "i07Vectors": "architecture/i07-policy-write-v3/vectors.json",
             "inventory": v3.V3_INPUTS["inventory"], "closure": v3.V3_INPUTS["closure"],
             "bootstrap": v3.V3_INPUTS["bootstrap"]}
# The case set, each section's ids in order (contract review round 1, R1-1); the counts follow from it.
CASE_IDS = {
    "documentNegative": [
        "D01", "D02", "D03", "D04", "D05", "D06", "D07"
    ],
    "objectsAccepted": [
        "OA01", "OA02", "OA03", "OA04", "OA05", "OA06"
    ],
    "objectsNegative": [
        "ON01", "ON02", "ON03", "ON04", "ON05", "ON06", "ON07", "ON08", "ON09", "ON10", "ON11", "ON12", "ON13",
        "ON14", "ON15", "ON16", "ON17", "ON18", "ON19", "ON20", "ON21", "ON22", "ON23", "ON24", "ON25", "ON26",
        "ON27", "ON28", "ON29", "ON30", "ON31", "ON32", "ON33", "ON34", "ON35", "ON36", "ON37", "ON38", "ON39",
        "ON40", "ON41", "ON42", "ON43", "ON44", "ON45", "ON46", "ON47", "ON48", "ON49", "ON50", "ON51", "ON52",
        "ON53", "ON54", "ON55", "ON56", "ON57", "ON58", "ON59", "ON60", "ON61"
    ],
    "snapshotAccepted": [
        "SA01", "SA02"
    ],
    "snapshotNegative": [
        "SN01", "SN02", "SN03", "SN04", "SN05", "SN06", "SN07", "SN08", "SN09", "SN10", "SN11", "SN12", "SN13",
        "SN14"
    ],
    "crossVersion": [
        "XR01", "XR02", "XR03", "XR04", "XR05", "XR06"
    ],
    "composed": [
        "CO01", "CO02", "CO03", "CO04", "CO05", "CO06", "CO07"
    ],
}
VECTOR_COUNTS = {key: len(ids) for key, ids in CASE_IDS.items()}
ANCHORS = {"XR01": {"base": "v3", "ops": []}, "XR02": {"base": "v4", "ops": []}}
# The frozen inputs' SHA-256 and the RB rows' digest, fixed by the model (R1-4), so that an edit which also updates
# vectors.json's own pins is still refused.
FROZEN_INPUTS = {
    "v3Vectors": "4752b648abdd82d21ea622a1b26c721143577478c0a2491204e0d584c1d6f081",
    "v3Criteria": "752533c57b5f93e4c4158a9c17b52eb88d236a3632ab0b66b669e8f8041f57c7",
    "i07Vectors": "c4c24c5ff15618aa2f0fe0f016011359bc4316220c6e40d5168f9ee24b6f736d",
    "inventory": "8e6b3b7565cfc93a61162b84d740cffb2871eb66ab85e8c4e80ac813f1af3077",
    "closure": "0a9b82ffa2d63bf48a8850574cdf3ece02bf1913f33a72cbb96ed30a40f1f3bb",
    "bootstrap": "7529c2a713af2fb90163175924c264d95f4242d7e0c26b1452c77febb13ed50e",
}
RB_ROWS_SHA256 = "c7a07c9d93e8a8d77242ba10d6dfef29a98209252e26efefec81e67298d6fe8a"
V3_SNAPSHOT_CASES = {"accepted": 5, "negative": 38}
RB_CHECKED_BY = {"RB00": "check_observer_document", "RB01": "check_observer_rbac", "RB02": "check_observer_rbac",
                 "RB03": "check_observer_rbac", "RB04": "check_observer_rbac", "RB05": "check_rbac_snapshot",
                 "RB06": "check_observer_rbac", "RB07": "check_observer_rbac"}
I07_BINDINGS = ("K22", "K23")


def check_vectors(vectors: Any, files: dict) -> int:
    """DATA_CHECK_ONLY: replay every I06 v4 vector. `files` maps each input path (V4_INPUTS) to its bytes; the vectors pin
    each input's SHA-256. Returns the number of checks; any mismatch raises ValueError."""
    require(type(vectors) is dict and set(vectors) == {
        "evidenceClass", "kubernetesBaseline", "qualificationNamespace", "inputs", "evidence", "v3SnapshotCases",
        "snapshotPositive", "objectsPositive", "documentNegative", "objectsAccepted", "objectsNegative",
        "snapshotAccepted", "snapshotNegative", "crossVersion", "composed"}
            and vectors["evidenceClass"] == "DATA_CHECK_ONLY" and vectors["kubernetesBaseline"] == KUBERNETES_VERSION
            and all(type(files.get(path)) is bytes for path in V4_INPUTS.values())
            and vectors["inputs"] == {key: {"path": path, "sha256": v3.w02a.digest(files[path])}
                                      for key, path in V4_INPUTS.items()}
            and vectors["evidence"] == {"model": "scripts/i06_backend_profile_v3.py", "function": "check_evidence",
                                        "replayed": False}
            and vectors["v3SnapshotCases"] == V3_SNAPSHOT_CASES
            and {key: len(vectors[key]) for key in VECTOR_COUNTS} == VECTOR_COUNTS,
            "closed I06 v4 vectors")
    require({key: [row.get("id") for row in vectors[key]] for key in CASE_IDS} == CASE_IDS, "the I06 v4 case set")
    anchors = {row["id"]: {"base": row["base"], "ops": row["ops"]}
               for row in vectors["crossVersion"] if row["id"] in ANCHORS}
    require(anchors == ANCHORS, "the cross-version anchors XR01 (v3's positive) and XR02 (v4's positive)")
    for key, digest in FROZEN_INPUTS.items():
        require(v3.w02a.digest(files[V4_INPUTS[key]]) == digest, "a frozen input differs from the model's pin: " + key)
    data = {key: v3.w02a.parse(files[path]) for key, path in V4_INPUTS.items()}
    v3_vectors, closure, inventory, bootstrap = data["v3Vectors"], data["closure"], data["inventory"], data["bootstrap"]
    namespace = vectors["qualificationNamespace"]
    require(namespace == v3_vectors["qualificationNamespace"], "the v3 qualification namespace")
    v3_ids = {row["id"] for key in ("snapshotAccepted", "snapshotNegative") for row in v3_vectors[key]}
    require(not v3_ids & {i for ids in CASE_IDS.values() for i in ids},
            "v4 case ids are disjoint from v3's replayed snapshot ids")
    # Evidence: v3's function object, unchanged; no evidence case is replayed (v3's own check_vectors replays them).
    require(check_evidence is v3.check_evidence and v3.v1 is v1, "v4's check_evidence is v3's function object")
    checks = 1
    # Criteria: v3's 30 rows as they are, then RB00-RB07.
    criteria, old = data["criteria"], data["v3Criteria"]
    require(type(criteria) is dict and set(criteria) == {"schemaVersion", "kubernetesBaseline", "criteria"}
            and criteria["schemaVersion"] == "planeon.internal.i06-selection-criteria/v4"
            and criteria["kubernetesBaseline"] == KUBERNETES_VERSION
            and _same(criteria["criteria"][:len(old["criteria"])], old["criteria"])
            and [row.get("id") for row in criteria["criteria"][len(old["criteria"]):]] == list(RB_CHECKED_BY)
            and all(type(row) is dict and set(row) == {"id", "requirement", "source", "checkedBy"}
                    and row["checkedBy"] == RB_CHECKED_BY[row["id"]]
                    for row in criteria["criteria"][len(old["criteria"]):]),
            "v4 criteria are v3's rows and RB00-RB07")
    require(v3.w02a.digest(v1.canonical(criteria["criteria"][len(old["criteria"]):])) == RB_ROWS_SHA256,
            "the RB criteria rows differ from the model's pin")
    checks += 1
    # The document and its negatives.
    document = data["observerRbac"]
    require(explain(check_observer_document, document) is None, "the observer RBAC document is the model's")
    checks += 1
    for row in vectors["documentNegative"]:
        require(explain(check_observer_document, v3._apply(document, row["ops"])) == row["refusal"] is not None,
                "document negative " + row["id"])
        checks += 1
    # The objects: the positive is the document's two objects with no RoleBindings (HE-008's manifest form).
    objects = vectors["objectsPositive"]
    require(_same(objects, {"clusterRoles": [document["objects"][0]], "clusterRoleBindings": [document["objects"][1]],
                            "roleBindings": []}) and explain(check_observer_rbac, objects) is None,
            "the objects positive is the document's manifest")
    checks += 1
    i07 = {row["id"]: row for row in data["i07Vectors"]["kindChecks"] if row.get("id") in I07_BINDINGS}
    require(sorted(row["fromI07"] for row in vectors["objectsNegative"] if "fromI07" in row) == list(I07_BINDINGS)
            and not any("fromI07" in row for row in vectors["objectsAccepted"]),
            "I07 v3's K22 and K23 are each pinned by one object negative")
    for key in ("objectsAccepted", "objectsNegative"):
        for row in vectors[key]:
            if "fromI07" in row:
                # The writer's RoleBinding to Role planeon-policy-observer, exactly as I07 v3's vector writes it.
                require(row["fromI07"] in I07_BINDINGS and row["ops"] == [{"op": "append", "path": ["roleBindings"],
                                                                          "value": i07[row["fromI07"]]["payload"]["object"]}],
                        "the case is I07 v3's binding " + row["id"])
            result = explain(check_observer_rbac, v3._apply(objects, row["ops"]))
            require(result is None if key == "objectsAccepted" else result == row["refusal"] is not None,
                    key + " " + row["id"])
            checks += 1
    # The snapshot positive: v3's, with only the observer's effective rules replaced by the role's resource rules.
    v3_positive, snapshot = v3_vectors["snapshotPositive"], vectors["snapshotPositive"]
    expected = copy.deepcopy(v3_positive)
    for subject in expected["subjects"]:
        if (subject["kind"], subject["name"]) == OBSERVER:
            subject["effectiveRules"] = observer_snapshot_rules()
    require(_same(snapshot, expected), "the v4 snapshot positive is v3's with the observer's rules replaced")
    require(explain(check_rbac_snapshot, snapshot, closure, inventory, bootstrap, namespace) is None
            and v3.explain(v3.check_rbac_snapshot, snapshot, closure, inventory, bootstrap, namespace) is None,
            "the v4 snapshot positive is accepted by v4 and v3")
    checks += 1

    def v4_result(base: dict, row: dict) -> Any:
        return explain(check_rbac_snapshot, v3._apply(base, row["ops"]), closure, inventory, bootstrap,
                       row.get("namespace", namespace))

    def v3_result(base: dict, row: dict) -> Any:
        return v3.explain(v3.check_rbac_snapshot, v3._apply(base, row["ops"]), closure, inventory, bootstrap,
                          row.get("namespace", namespace))

    # v3's snapshot cases, replayed on the v4 positive with their v3 results.
    require(len(v3_vectors["snapshotAccepted"]) == V3_SNAPSHOT_CASES["accepted"]
            and len(v3_vectors["snapshotNegative"]) == V3_SNAPSHOT_CASES["negative"], "v3's snapshot case counts")
    for row in v3_vectors["snapshotAccepted"]:
        require(v4_result(snapshot, row) is None, "v3 accepted snapshot case replayed: " + row["id"])
        checks += 1
    for row in v3_vectors["snapshotNegative"]:
        require(v4_result(snapshot, row) == row["refusal"], "v3 snapshot negative replayed: " + row["id"])
        checks += 1
    # The new snapshot cases: each states v3's result on the same snapshot, so the cases the pin adds are visible.
    for key in ("snapshotAccepted", "snapshotNegative"):
        for row in vectors[key]:
            require(v3_result(snapshot, row) == row["v3Result"], key + " " + row["id"] + " v3 result")
            result = v4_result(snapshot, row)
            require(result is None if key == "snapshotAccepted" else result == row["refusal"] is not None,
                    key + " " + row["id"])
            checks += 1
    # Cross-version: each case on v3's or v4's positive, judged by v3 and by v4.
    for row in vectors["crossVersion"]:
        base = {"v3": v3_positive, "v4": snapshot}[row["base"]]
        require(v3_result(base, row) == row["v3Result"] and v4_result(base, row) == row["v4Result"],
                "cross-version " + row["id"])
        checks += 1
    # Coverage: every RB criterion has a pinned refusal; RB07's cover the three routes Q-RBAC-9 (a) names.
    refusals = [row["refusal"] for key in ("documentNegative", "objectsNegative", "snapshotNegative")
                for row in vectors[key]]
    require(all(any(text.startswith(rid + " ") for text in refusals) for rid in RB_CHECKED_BY),
            "every criterion RB00-RB07 has a negative")
    routes = {op["path"][0] for row in vectors["objectsNegative"] if row["refusal"].startswith("RB07 ")
              for op in row["ops"] if op["op"] == "append"}
    require({"clusterRoleBindings", "roleBindings", "clusterRoles"} <= routes,
            "RB07's negatives cover a second ClusterRoleBinding, a RoleBinding and an aggregated ClusterRole")
    # The composed acceptance (R1-2): a snapshot case and an object case of this file, judged together.
    snapshot_cases = {row["id"]: row for key in ("snapshotAccepted", "snapshotNegative") for row in vectors[key]}
    object_cases = {row["id"]: row for key in ("objectsAccepted", "objectsNegative") for row in vectors[key]}
    for row in vectors["composed"]:
        require(type(row) is dict and set(row) == {"id", "intent", "snapshotCase", "objectsCase", "refusal"}
                and (row["snapshotCase"] is None or row["snapshotCase"] in snapshot_cases)
                and (row["objectsCase"] is None or row["objectsCase"] in object_cases), "composed case " + row["id"])
        snapshot_ops = [] if row["snapshotCase"] is None else snapshot_cases[row["snapshotCase"]]["ops"]
        object_ops = [] if row["objectsCase"] is None else object_cases[row["objectsCase"]]["ops"]
        require(explain(check_observer_snapshot, v3._apply(snapshot, snapshot_ops), v3._apply(objects, object_ops),
                        closure, inventory, bootstrap, namespace) == row["refusal"], "composed " + row["id"])
        checks += 1
    ids = [row["id"] for key in VECTOR_COUNTS for row in vectors[key]]
    require(len(ids) == len(set(ids)), "unique vector identifiers")
    return checks
