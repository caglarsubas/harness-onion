#!/usr/bin/env python3
"""The I01 digest contract (DIGEST-CONTRACT): reference model, DATA_CHECK_ONLY.

It fixes how the policy observer derives the I01 v1 answer's seven projection objects and four enforcement digests
(architecture/policy-observation-digests/README.md, definitions.json and vectors.json). HE-008 computes every expected
value with it at enrollment; the release author and the capacity signer render and reference the projection files with
it; R10's HE-004-I01B ports it and replays its vectors.

- `projection_document(key, snapshot, binding)`: one of the seven projection documents, or a refusal.
- `projection_digest(document)`: "sha256:" and the lowercase hex sha256 of the document's canonical bytes.
- `enforcement_digests(snapshot, i06)`: the four enforcement digests at the snapshot (the capture gates are separate).
- `capture_gate(key, capture, record)`: whether a capture-gated value may be in an answer, over capture verdicts given
  as data.
- `check_observation_digests(snapshot, binding, capture, i06)`: every value derived, gated and compared with the signed
  binding: an empty list, or the refusal texts.
- `check_vectors(vectors, files)`: replays vectors.json; `main` checks definitions.json and the vectors.

Shared helpers: `canonical`, `digest` and `_bounded` are imported by name from scripts/validate_proxy_contract.py, as
the other validators import them. Their behaviour is pinned by the helper vectors (canonical bytes, digests and bounds),
not by that file's sha256, because its packet list changes with every packet. The frozen models imported here (admission
v3's renderers and hash; I06 v1 and v4's closure check and role pin, with what v4 imports) are pinned by file sha256 in
FROZEN_MODELS and are never edited.

A refusal is `Refused(text)`; every text is pinned in definitions.json and in at least one vector. Nothing here contacts
an apiserver or a host, grants authority or returns a protected handle.
"""
from __future__ import annotations

import copy
import hashlib
import json
import sys
from pathlib import Path
from typing import Any

try:
    from validate_proxy_contract import canonical, digest, _bounded
except ImportError:
    try:
        from scripts.validate_proxy_contract import canonical, digest, _bounded
    except ImportError:
        # Run as a file in isolated mode (python3 -I puts neither the script's directory nor the working directory on
        # sys.path): use the script's own directory, as `python3 scripts/policy_observation_digests.py` does.
        sys.path.insert(0, str(Path(__file__).resolve().parent))
        from validate_proxy_contract import canonical, digest, _bounded
try:
    import admission_semantics_v3 as adm
    import i06_backend_profile as i06v1
    import i06_backend_profile_v4 as i06v4
except ImportError:
    from scripts import admission_semantics_v3 as adm
    from scripts import i06_backend_profile as i06v1
    from scripts import i06_backend_profile_v4 as i06v4

SCHEMA_VERSION = "planeon.internal.policy-observation-digests/v1"
VECTORS_VERSION = "planeon.internal.policy-observation-digests-vectors/v1"
CLOSURE_VERSION = "planeon.internal.policy-observation-rbac-closure/v1"
CONTRACT_DIR = "architecture/policy-observation-digests/"
MODEL_PATH = "scripts/policy_observation_digests.py"
POLICIES = ("admissionPolicy", "resourceQuota", "limitRange", "serviceAccount", "rbac", "networkPolicy",
            "mutationBroker")
DIGESTS = ("admissionFenceDigest", "rbacClosureDigest", "networkEnforcementDigest", "hostPreflightDigest")
GATED = ("mutationBroker", "networkEnforcementDigest", "hostPreflightDigest")
MAX_INT = 9007199254740991
CLUSTER = "CLUSTER"
# The capture gate's bound: R10's 60 s cycle, plus the 5 s start bound, plus the 25 s set budget.
CYCLE_MS, SCRAPE_TO_SET_MS, SET_BUDGET_MS = 60000, 5000, 25000
GATE_BOUND_MS = CYCLE_MS + SCRAPE_TO_SET_MS + SET_BUDGET_MS
ROLES = ("SERVER", "OBSERVER", "BROKER", "WORKER", "EFFECT_GATE")
TAKEN = "TAKEN"

# The fixed identities (apiVersion, kind, name, namespace). A name, namespace or uid of None is the live object's;
# the namespace "QUALIFICATION_NAMESPACE" is the configured qualification namespace; "CLUSTER_SCOPED" is null.
IDENTITY = {
    "admissionPolicy": ("admissionregistration.k8s.io/v1", "ValidatingAdmissionPolicy", "admissionpolicy", "CLUSTER_SCOPED"),
    "resourceQuota": ("v1", "ResourceQuota", None, None),
    "limitRange": ("v1", "LimitRange", None, None),
    "serviceAccount": ("v1", "ServiceAccount", None, None),
    "rbac": ("planeon.internal/v1", "EffectiveRbac", "rbac", "QUALIFICATION_NAMESPACE"),
    "networkPolicy": ("networking.k8s.io/v1", "NetworkPolicy", None, None),
    "mutationBroker": ("planeon.internal/v1", "MutationBroker", "mutationbroker", "QUALIFICATION_NAMESPACE"),
}
SYNTHETIC = ("admissionPolicy", "rbac", "mutationBroker")
LIST_OF = {"resourceQuota": "resourceQuotas", "limitRange": "limitRanges", "serviceAccount": "serviceAccounts",
           "networkPolicy": "networkPolicies"}
LISTS = ("namespaces", "resourceQuotas", "limitRanges", "serviceAccounts", "networkPolicies", "roles", "roleBindings",
         "clusterRoles", "clusterRoleBindings", "validatingAdmissionPolicies", "validatingAdmissionPolicyBindings")
SA_KEYS = ("automountServiceAccountToken", "imagePullSecrets", "secrets")
SA_ANNOTATION = "kubernetes.io/enforce-mountable-secrets"
PSA_PREFIX = "pod-security.kubernetes.io/"
SEALED_VALUES = ("ipFamily", "serviceCIDR", "defaultTolerationSeconds")
VAP, VAPB = "ValidatingAdmissionPolicy", "ValidatingAdmissionPolicyBinding"
BROKER_MEMBERS = ("executable", "executableLabel", "artifactDigest", "interpreterPath", "interpreterLabel", "uid", "gid",
                  "processLabel", "namespaceInodes", "cgroup", "seccompMode", "seccompDefaultAction",
                  "seccompFilterDigest", "noNewPrivs", "rlimitCore", "capabilities", "filePaths", "bpfPrograms",
                  "listenEndpointIds", "outboundEndpointIds")
CGROUP_MEMBERS = ("path", "inode", "memoryMaxBytes", "pidsMax", "cpuQuotaMicros", "cpuPeriodMicros", "selinuxLabel")
BROKER_DOCUMENT = ("executable", "executableLabel", "artifactDigest", "uid", "gid", "processLabel", "cgroup",
                   "seccompMode", "seccompDefaultAction", "seccompFilterDigest", "noNewPrivs", "capabilities",
                   "listenEndpointIds", "outboundEndpointIds")
AGENT = "NETWORK_POLICY_AGENT"
AGENT_MEMBERS = ("executable", "executableLabel", "artifactDigest", "processLabel", "apiIdentities")
RBAC_GROUP = "rbac.authorization.k8s.io"
LOOPBACK_USER = "system:apiserver"
SA_PREFIX = "system:serviceaccount:"
B1_FIELDS = ("metadata", "rules", "rule", "rule list", "rule (non-resource URLs beside resources)", "subjects", "subject",
             "subject name", "subject kind", "subject namespace", "roleRef", "roleRef apiGroup", "roleRef kind",
             "roleRef name")

# The wire's pinned files, cited by sha256 and never changed.
WIRE_PINS = {
    "CS": ("architecture/policy-observation-inputs/channel.schema.json",
           "fb69b77201d9b6275a19667a5f5770537f382ddb11309095733628c8430bdc0e"),
    "PV": ("architecture/policy-observation-inputs/vectors.json",
           "1bfb46776636f800e38ab6a8f94a0989aa38513fb4a28ef18e61e732a115c124"),
    "RD": ("docs/alpha-2/POLICY_OBSERVATION_READINESS.md",
           "65778040919c5eb7335f2c104d983ca920b877b1b123f961556a6bcae36d232c"),
}
# Frozen models imported here (directly or through I06 v4), by file sha256 and last-change commit at harness-onion
# 30f41e6f.
FROZEN_MODELS = {
    "scripts/admission_semantics_v3.py": ("3db8f51ab55f49dc33cf6f028306bfb6d7aa1c5d7d96f264cfe709dae925ad22",
                                          "4196dae972f2a2636a5176e2cef440c01bf03a98"),
    "scripts/i06_backend_profile.py": ("bea3c953573478be5b03ab81b4ebd859da62d1eaa2a1be8f361b9dd39a98555e",
                                       "fe50b57c0e6b6d5e5732b1b346bbad8727959a6f"),
    "scripts/i06_backend_profile_v3.py": ("dfb00e90199d436ae63b79261f2e04870d7861cb0f7a424971657a4d777754de",
                                          "887cbe7a005f6c7c813623dce5072e1c75f1fe58"),
    "scripts/i06_backend_profile_v4.py": ("7f97acfe9060e79c101f264f5bf61610bf421326c689216cbaf41df7e38e6d2a",
                                          "29c84b36dad2f6f9822b71cd959064f0202d9868"),
    "scripts/native_qualification_v4.py": ("f7c718072d1ffbb9b8bbc310e6141d476ea5f25296f70ff8c1bc9ada3db02387",
                                           "887cbe7a005f6c7c813623dce5072e1c75f1fe58"),
}
# I06 v1's frozen closure inputs (the same bytes R10 embeds and I06 v4 pins).
FROZEN_INPUTS = {
    "closure": ("architecture/i06-backend-profile/identity-closure.json",
                "0a9b82ffa2d63bf48a8850574cdf3ece02bf1913f33a72cbb96ed30a40f1f3bb"),
    "inventory": ("architecture/i06-backend-profile/writer-inventory.json",
                  "8e6b3b7565cfc93a61162b84d740cffb2871eb66ab85e8c4e80ac813f1af3077"),
    "bootstrap": ("architecture/i06-backend-profile/upstream-bootstrap-rbac-v1.37.1.json",
                  "7529c2a713af2fb90163175924c264d95f4242d7e0c26b1452c77febb13ed50e"),
}

GATE_TEXT = {"mutationBroker": "mutationBroker: broker capture not passed",
             "networkEnforcementDigest": "networkEnforcementDigest: agent capture not passed",
             "hostPreflightDigest": "hostPreflightDigest: capture set not passed"}
T_RENDERED = "admissionPolicy: rendered hash differs"
T_UNKNOWN = "admissionPolicy: unknown admission object"
T_NAMESPACE = "admissionPolicy: qualification namespace not listed"
T_ANNOTATION = "serviceAccount: enforce-mountable-secrets annotation"
T_SELECTOR = "networkPolicy: selector form outside v1"
T_AGGREGATED = "rbac: aggregated role reaches the namespace"
T_DANGLING = "rbac: role does not exist"
T_LOOPBACK = "rbac: loopback user bound to a non-resource rule"
T_CLOSURE = "rbacClosureDigest: I06 closure check not passed"
T_BROKER_ROW = "mutationBroker: broker row incomplete"
T_NO_AGENT = "networkEnforcementDigest: no network policy agent"
KEY_TEXTS = ("float refused", "integer out of range", "document bound exceeded", "malformed input",
             "differs from the signed value")
ONE_OBJECT_TEXTS = ("count is not one", "name differs from the binding")


class Refused(ValueError):
    """A refusal; `text` is one of the contract's pinned refusal texts."""

    def __init__(self, text: str):
        super().__init__(text)
        self.text = text


def _refuse(ok: Any, text: str) -> None:
    if not ok:
        raise Refused(text)


def _text(value: Any) -> bool:
    return type(value) is str and value != ""


def _member(value: Any, name: str, key: str) -> Any:
    _refuse(type(value) is dict and name in value, key + ": malformed input")
    return value[name]


# ---------------------------------------------------------------------------------------------------- common rules

def document_bound(key: str, value: Any) -> None:
    """The exactness rule over a document or an input. A float refuses. Then VPC's `_bounded` (exact builtins, depth
    at most 16, its size budget, and its magnitude rule |integer| <= 2^53 - 1): its integer refusal is the contract's
    integer text, and any other refusal of it is the document bound."""
    stack = [value]
    while stack:
        item = stack.pop()
        if type(item) is float:
            raise Refused(key + ": float refused")
        if type(item) is dict:
            stack.extend(item.values())
        elif type(item) is list:
            stack.extend(item)
    try:
        _bounded(value)
    except ValueError as exc:
        raise Refused(key + (": integer out of range" if str(exc) == "integer overflow"
                             else ": document bound exceeded")) from None
    except RecursionError:
        raise Refused(key + ": document bound exceeded") from None


def projection_digest(document: Any) -> str:
    """"sha256:" and the lowercase hex sha256 of the document's canonical bytes."""
    return "sha256:" + digest(canonical(document))


def synthetic_uid(api_version: str, kind: str, name: str, namespace: str | None) -> str:
    """A synthetic projection's uid: the lowercase hex sha256 of the canonical fixed identity (64 characters)."""
    return digest(canonical({"apiVersion": api_version, "kind": kind, "name": name, "namespace": namespace}))


def _namespace(snapshot: Any, key: str) -> str:
    space = _member(_member(snapshot, "configuration", key), "qualificationNamespace", key)
    _refuse(_text(space), key + ": malformed input")
    return space


def _list(snapshot: Any, name: str, key: str) -> list:
    items = _member(_member(snapshot, "lists", key), name, key)
    _refuse(type(items) is list and all(type(item) is dict and type(item.get("metadata")) is dict for item in items),
            key + ": malformed input")
    return items


def _bound_name(binding: Any, key: str) -> str:
    name = _member(_member(_member(binding, "projections", key), key, key), "name", key)
    _refuse(type(name) is str, key + ": malformed input")
    return name


def _in_namespace(snapshot: Any, key: str) -> tuple[str, list]:
    space = _namespace(snapshot, key)
    items = _list(snapshot, LIST_OF[key], key)
    for item in items:
        _refuse(_text(item["metadata"].get("name")) and _text(item["metadata"].get("namespace")),
                key + ": malformed input")
    return space, [item for item in items if item["metadata"]["namespace"] == space]


def _real_document(key: str, item: dict, spec: Any) -> dict:
    api_version, kind = IDENTITY[key][:2]
    meta = item["metadata"]
    _refuse(_text(meta.get("uid")), key + ": malformed input")
    return {"apiVersion": api_version, "kind": kind,
            "metadata": {"name": meta["name"], "namespace": meta["namespace"], "uid": meta["uid"]}, "spec": spec}


def _synthetic_document(key: str, space: str, spec: dict) -> dict:
    api_version, kind, name, scope = IDENTITY[key]
    namespace = None if scope == "CLUSTER_SCOPED" else space
    return {"apiVersion": api_version, "kind": kind,
            "metadata": {"name": name, "namespace": namespace,
                         "uid": synthetic_uid(api_version, kind, name, namespace)}, "spec": spec}


# ---------------------------------------------------------------------------------------------------- admission

def _rendered(snapshot: Any, key: str) -> tuple[list, str]:
    """The eight rendered objects and the directory hash, after the sealed values' exactness and the two equalities:
    the hash equals the signed pinnedManifestHash and ADM-4's loaded hash."""
    configuration = _member(snapshot, "configuration", key)
    space = _namespace(snapshot, key)
    sealed = _member(configuration, "sealedAdmission", key)
    _refuse(type(sealed) is dict and set(sealed) == set(SEALED_VALUES), key + ": malformed input")
    document_bound(key, sealed)
    _refuse(_text(sealed["ipFamily"]) and _text(sealed["serviceCIDR"])
            and type(sealed["defaultTolerationSeconds"]) is int, key + ": malformed input")
    values = dict(sealed, namespace=space)
    objects = adm.a2_objects(values)
    loaded = adm.manifest_directory_hash({adm.MANIFEST_FILE: adm.manifest_file_bytes(values)})
    pin = _member(configuration, "pinnedManifestHash", key)
    seen = _member(snapshot, "adm4LoadedHash", key)
    _refuse(loaded == pin and loaded == seen, T_RENDERED)
    return objects, loaded


def _admission_spec(snapshot: Any) -> dict:
    key = "admissionPolicy"
    objects, _ = _rendered(snapshot, key)
    names = {kind: {obj["metadata"]["name"] for obj in objects if obj["kind"] == kind} for kind in (VAP, VAPB)}
    for list_name, kind in (("validatingAdmissionPolicies", VAP), ("validatingAdmissionPolicyBindings", VAPB)):
        for item in _list(snapshot, list_name, key):
            name = item["metadata"].get("name")
            _refuse(_text(name), key + ": malformed input")
            _refuse(name in names[kind], T_UNKNOWN)
    space = _namespace(snapshot, key)
    found = [item for item in _list(snapshot, "namespaces", key) if item["metadata"].get("name") == space]
    _refuse(len(found) == 1, T_NAMESPACE)
    labels = found[0]["metadata"].get("labels")
    labels = {} if labels is None else labels
    _refuse(type(labels) is dict and all(type(k) is str and type(v) is str for k, v in labels.items()),
            key + ": malformed input")
    return {"sealedObjects": sorted(copy.deepcopy(objects), key=lambda obj: (obj["kind"], obj["metadata"]["name"])),
            "podSecurityLabels": {k: v for k, v in labels.items() if k.startswith(PSA_PREFIX)}}


# ---------------------------------------------------------------------------------------------------- RBAC (B1's rules)

def _b1_malformed(field: str) -> Refused:
    return Refused("rbac: malformed " + field)


def _object_member(item: Any, member: str) -> str | None:
    meta = item.get("metadata") if type(item) is dict else None
    value = meta.get(member) if type(meta) is dict else None
    return value if _text(value) else None


def _strings(holder: dict, name: str) -> list:
    value = holder.get(name)
    if value is None:
        return []
    if type(value) is list and all(type(item) is str for item in value):
        return list(value)
    raise _b1_malformed("rule list")


def _role_rules(role: Any) -> tuple[list, bool]:
    """A role's rules (absent or null: none) and whether it has an aggregationRule key (any value)."""
    aggregated = type(role) is dict and "aggregationRule" in role
    items = role.get("rules") if type(role) is dict else None
    if items is None:
        items = []
    elif type(items) is not list:
        raise _b1_malformed("rules")
    rules = []
    for item in items:
        if type(item) is not dict:
            raise _b1_malformed("rule")
        urls = _strings(item, "nonResourceURLs")
        rule = {"apiGroups": _strings(item, "apiGroups"), "resources": _strings(item, "resources"),
                "verbs": _strings(item, "verbs"), "resourceNames": _strings(item, "resourceNames"),
                "nonResourceURLs": urls}
        if urls and rule["resources"]:
            raise _b1_malformed("rule (non-resource URLs beside resources)")
        rules.append(rule)
    return rules, aggregated


def _role_ref(value: dict, space: str | None) -> tuple[str, str]:
    ref = value.get("roleRef")
    if type(ref) is not dict:
        raise _b1_malformed("roleRef")
    if ref.get("apiGroup") != RBAC_GROUP:
        raise _b1_malformed("roleRef apiGroup")
    kind = ref.get("kind")
    if not (kind == "ClusterRole" or (kind == "Role" and space is not None)):
        raise _b1_malformed("roleRef kind")
    if not _text(ref.get("name")):
        raise _b1_malformed("roleRef name")
    return kind, ref["name"]


def _subjects(value: dict, space: str | None) -> list:
    items = value.get("subjects")
    if items is None:
        items = []
    elif type(items) is not list:
        raise _b1_malformed("subjects")
    out = []
    for item in items:
        if type(item) is not dict:
            raise _b1_malformed("subject")
        name = item.get("name")
        if not _text(name):
            raise _b1_malformed("subject name")
        kind = item.get("kind")
        if type(kind) is not str or kind not in ("User", "Group", "ServiceAccount"):
            raise _b1_malformed("subject kind")
        if kind != "ServiceAccount":
            out.append((kind, name, None))
            continue
        # The authorizer's rule: a RoleBinding's service account without a namespace is in the binding's namespace;
        # a ClusterRoleBinding's must name one; an empty namespace is absent.
        namespace = item.get("namespace")
        if namespace is not None and type(namespace) is not str:
            raise _b1_malformed("subject namespace")
        namespace = namespace or space
        if not namespace:
            raise _b1_malformed("subject namespace")
        out.append((kind, SA_PREFIX + namespace + ":" + name, (namespace, name)))
    return out


def _rbac(snapshot: Any, space: str) -> tuple[dict, dict]:
    """B1's producer (R10:obs/rbac.rs:251-353): its refusals in its order, then B1's snapshot value (for I06's checks)
    and the contract's entries: (kind, name) -> {exists, snapshot, rules, local}. `local`: named by a RoleBinding in the
    qualification namespace or by a ClusterRoleBinding (the rbac subject set)."""
    lists = _member(snapshot, "lists", "rbac")

    def items(name: str) -> list:
        value = _member(lists, name, "rbac")
        _refuse(type(value) is list, "rbac: malformed input")
        return value

    cluster_roles, cluster_bindings, roles, role_bindings, accounts = (
        items(name) for name in ("clusterRoles", "clusterRoleBindings", "roles", "roleBindings", "serviceAccounts"))
    cluster_role_rules = {}
    for role in cluster_roles:
        name = _object_member(role, "name")
        if name is None:
            raise _b1_malformed("metadata")
        cluster_role_rules[name] = _role_rules(role)
    role_rule_sets = {}
    for role in roles:
        namespace, name = _object_member(role, "namespace"), _object_member(role, "name")
        if namespace is None or name is None:
            raise _b1_malformed("metadata")
        role_rule_sets[(namespace, name)] = _role_rules(role)
    existing = set()
    for account in accounts:
        namespace, name = _object_member(account, "namespace"), _object_member(account, "name")
        if namespace is None or name is None:
            raise _b1_malformed("metadata")
        existing.add((namespace, name))
    bindings = []
    for value in cluster_bindings:
        name = _object_member(value, "name")
        if name is None:
            raise _b1_malformed("metadata")
        bindings.append((None, name, value))
    for value in role_bindings:
        namespace, name = _object_member(value, "namespace"), _object_member(value, "name")
        if namespace is None or name is None:
            raise _b1_malformed("metadata")
        bindings.append((namespace, name, value))
    # ClusterRoleBindings sort before RoleBindings, each by its namespace and name.
    bindings.sort(key=lambda row: (row[0] is not None, row[0] or "", row[1]))
    entries: dict = {}
    for namespace, _, value in bindings:
        kind, role_name = _role_ref(value, namespace)
        named = _subjects(value, namespace)
        rules = role_rule_sets.get((namespace, role_name)) if kind == "Role" else cluster_role_rules.get(role_name)
        _refuse(rules is not None, T_DANGLING)
        role_rules, aggregated = rules
        _refuse(not (aggregated and (namespace is None or namespace == space)), T_AGGREGATED)
        loopback = any(kind_ == "User" and name_ == LOOPBACK_USER for kind_, name_, _ in named)
        _refuse(not (loopback and any(rule["nonResourceURLs"] for rule in role_rules)), T_LOOPBACK)
        scope = CLUSTER if namespace is None else namespace
        for subject_kind, subject_name, account in named:
            entry = entries.setdefault((subject_kind, subject_name), {
                "exists": account in existing if account is not None else True,
                "snapshot": [], "rules": [], "local": False})
            entry["local"] = entry["local"] or namespace is None or namespace == space
            for rule in role_rules:
                if rule["nonResourceURLs"]:
                    entry["rules"].append({"nonResourceURLs": list(rule["nonResourceURLs"]), "verbs": list(rule["verbs"]),
                                           "scope": scope})
                else:
                    shaped = {"apiGroups": list(rule["apiGroups"]), "resources": list(rule["resources"]),
                              "verbs": list(rule["verbs"]), "resourceNames": list(rule["resourceNames"]),
                              "scope": scope}
                    entry["snapshot"].append(shaped)
                    entry["rules"].append(copy.deepcopy(shaped))
    snapshot_value = {"schemaVersion": i06v1.SNAPSHOT_VERSION, "subjects": [
        {"kind": kind, "name": name, "exists": entry["exists"], "effectiveRules": entry["snapshot"]}
        for (kind, name), entry in sorted(entries.items())]}
    return snapshot_value, entries


def _entry(subject: tuple, entry: dict, scopes: tuple | None = None) -> dict:
    rules = [rule for rule in entry["rules"] if scopes is None or rule["scope"] in scopes]
    unique = {canonical(rule): rule for rule in rules}
    return {"kind": subject[0], "name": subject[1], "exists": entry["exists"],
            "effectiveRules": [unique[raw] for raw in sorted(unique)]}


# ---------------------------------------------------------------------------------------------------- network policy

def _selector_free(spec: dict) -> None:
    """v1's selector-free form: podSelector exactly {}, peers by ipBlock alone, integer ports and endPorts (an entry
    without a port is admitted); the closed members of the NetworkPolicy v1 API, nothing else."""
    _refuse(set(spec) <= {"podSelector", "policyTypes", "ingress", "egress"}, T_SELECTOR)
    _refuse(type(spec.get("podSelector")) is dict and spec["podSelector"] == {}, T_SELECTOR)
    for direction, peers_key in (("ingress", "from"), ("egress", "to")):
        rules = spec.get(direction, [])
        _refuse(type(rules) is list, T_SELECTOR)
        for rule in rules:
            _refuse(type(rule) is dict and set(rule) <= {peers_key, "ports"}, T_SELECTOR)
            peers, ports = rule.get(peers_key, []), rule.get("ports", [])
            _refuse(type(peers) is list and all(type(peer) is dict and set(peer) == {"ipBlock"} for peer in peers),
                    T_SELECTOR)
            _refuse(type(ports) is list, T_SELECTOR)
            for port in ports:
                _refuse(type(port) is dict and set(port) <= {"protocol", "port", "endPort"}, T_SELECTOR)
                for member in ("port", "endPort"):
                    _refuse(member not in port or type(port[member]) is int, T_SELECTOR)


def _network_documents(snapshot: Any) -> list:
    """The qualification namespace's NetworkPolicy documents (v1: exactly one, selector-free)."""
    key = "networkPolicy"
    _, items = _in_namespace(snapshot, key)
    _refuse(len(items) == 1, key + ": count is not one")
    documents = []
    for item in items:
        spec = item.get("spec")
        _refuse(type(spec) is dict, key + ": malformed input")
        _selector_free(spec)
        document = _real_document(key, item, copy.deepcopy(spec))
        document_bound(key, document)
        documents.append(document)
    return documents


# ---------------------------------------------------------------------------------------------------- the projections

def _broker_row(snapshot: Any) -> dict:
    record = _member(snapshot, "record", "mutationBroker")
    roles = record.get("roles") if type(record) is dict else None
    row = roles.get("BROKER") if type(roles) is dict else None
    _refuse(type(row) is dict and set(row) == set(BROKER_MEMBERS) and type(row["cgroup"]) is dict
            and set(row["cgroup"]) == set(CGROUP_MEMBERS), T_BROKER_ROW)
    return row


def projection(key: str, snapshot: Any, binding: Any) -> dict:
    """{"document", "identity", "resourceVersion"}: the projection document, the identity the binding must hold
    ({apiVersion, kind, name, namespace, uid, projectionDigest}) and the observed resourceVersion. The binding is read
    only for the bound names (one-object kinds) and the profile's service-account subject; nothing else comes from it."""
    try:
        return _projection(key, snapshot, binding)
    except Refused:
        raise
    except (TypeError, KeyError, AttributeError, IndexError, ValueError, RecursionError):
        raise Refused(key + ": malformed input") from None


def _projection(key: str, snapshot: Any, binding: Any) -> dict:
    _refuse(key in POLICIES, "unknown projection key")
    if key in SYNTHETIC:
        space = _namespace(snapshot, key)
        if key == "admissionPolicy":
            spec = _admission_spec(snapshot)
        elif key == "rbac":
            _, entries = _rbac(snapshot, space)
            spec = {"subjects": [_entry(subject, entry, (space, CLUSTER))
                                 for subject, entry in sorted(entries.items()) if entry["local"]]}
        else:
            row = _broker_row(snapshot)
            spec = {member: copy.deepcopy(row[member]) for member in BROKER_DOCUMENT}
            spec["cgroup"] = {k: v for k, v in spec["cgroup"].items() if k != "inode"}
        document = _synthetic_document(key, space, spec)
        version = _member(snapshot, "resourceVersion", key)
    else:
        if key == "serviceAccount":
            space, items = _in_namespace(snapshot, key)
            subject = _member(_member(binding, "scope", key), "serviceAccountSubject", key)
            _refuse(type(subject) is str, key + ": malformed input")
            prefix = SA_PREFIX + space + ":"
            name = subject[len(prefix):] if subject.startswith(prefix) else None
            matches = [item for item in items if name is not None and item["metadata"]["name"] == name]
            _refuse(len(matches) == 1, key + ": count is not one")
            item = matches[0]
            _refuse(item["metadata"]["name"] == _bound_name(binding, key), key + ": name differs from the binding")
            annotations = item["metadata"].get("annotations")
            _refuse(annotations is None or type(annotations) is dict, key + ": malformed input")
            _refuse(not annotations or SA_ANNOTATION not in annotations, T_ANNOTATION)
            spec = {member: copy.deepcopy(item[member]) for member in SA_KEYS if member in item}
        else:
            _, items = _in_namespace(snapshot, key)
            _refuse(len(items) == 1, key + ": count is not one")
            item = items[0]
            _refuse(item["metadata"]["name"] == _bound_name(binding, key), key + ": name differs from the binding")
            spec = item.get("spec")
            _refuse(type(spec) is dict, key + ": malformed input")
            if key == "networkPolicy":
                _selector_free(spec)
            spec = copy.deepcopy(spec)
        document = _real_document(key, item, spec)
        version = item["metadata"].get("resourceVersion")
    _refuse(_text(version), key + ": malformed input")
    document_bound(key, document)
    meta = document["metadata"]
    identity = {"apiVersion": document["apiVersion"], "kind": document["kind"], "name": meta["name"],
                "namespace": meta["namespace"], "uid": meta["uid"], "projectionDigest": projection_digest(document)}
    return {"document": document, "identity": identity, "resourceVersion": version}


def projection_document(key: str, snapshot: Any, binding: Any) -> dict:
    """One of the seven projection documents, {apiVersion, kind, metadata: {name, namespace, uid}, spec}."""
    return projection(key, snapshot, binding)["document"]


# ---------------------------------------------------------------------------------------------------- the digests

def _frozen_i06(i06: Any, key: str) -> tuple:
    _refuse(type(i06) is dict and set(i06) == set(FROZEN_INPUTS), key + ": malformed input")
    return i06["closure"], i06["inventory"], i06["bootstrap"]


def enforcement(key: str, snapshot: Any, i06: Any = None) -> dict:
    """{"digest"} and, for the RBAC closure and the network document, {"document"}: one enforcement digest at the
    snapshot. The capture gates (`capture_gate`) are separate: they hold at every answer."""
    try:
        return _enforcement(key, snapshot, i06)
    except Refused:
        raise
    except (TypeError, KeyError, AttributeError, IndexError, ValueError, RecursionError):
        raise Refused(key + ": malformed input") from None


def _enforcement(key: str, snapshot: Any, i06: Any) -> dict:
    _refuse(key in DIGESTS, "unknown digest key")
    if key == "admissionFenceDigest":
        return {"digest": _rendered(snapshot, key)[1]}
    if key == "rbacClosureDigest":
        space = _namespace(snapshot, key)
        snapshot_value, entries = _rbac(snapshot, space)
        closure, inventory, bootstrap = _frozen_i06(i06, key)
        lists = snapshot["lists"]
        objects = {"clusterRoles": lists["clusterRoles"], "clusterRoleBindings": lists["clusterRoleBindings"],
                   "roleBindings": lists["roleBindings"]}
        verdict = i06v4.explain(i06v4.check_observer_snapshot, snapshot_value, objects, closure, inventory, bootstrap,
                                space)
        _refuse(verdict is None, T_CLOSURE)
        document = {"schemaVersion": CLOSURE_VERSION,
                    "subjects": [_entry(subject, entry) for subject, entry in sorted(entries.items())]}
    elif key == "networkEnforcementDigest":
        policies = _network_documents(snapshot)
        record = _member(snapshot, "record", key)
        components = record.get("backendComponents") if type(record) is dict else None
        profile = record.get("backendProfile") if type(record) is dict else None
        keys = profile.get("componentKeys") if type(profile) is dict else None
        _refuse(type(components) is dict and AGENT in components and type(keys) is list and AGENT in keys, T_NO_AGENT)
        agent = components[AGENT]
        _refuse(type(agent) is dict and all(member in agent for member in AGENT_MEMBERS), key + ": malformed input")
        document = {"networkPolicies": sorted(policies, key=canonical),
                    "agent": {member: copy.deepcopy(agent[member]) for member in AGENT_MEMBERS}}
    else:
        record = _member(snapshot, "record", key)
        _refuse(type(record) is dict, key + ": malformed input")
        document_bound(key, record)
        return {"digest": "sha256:" + digest(canonical(record))}
    document_bound(key, document)
    return {"document": document, "digest": projection_digest(document)}


def enforcement_digests(snapshot: Any, i06: Any = None) -> dict:
    """The four enforcement digests at the snapshot, in DIGESTS order; the first refusal is raised."""
    return {key: enforcement(key, snapshot, i06)["digest"] for key in DIGESTS}


# ---------------------------------------------------------------------------------------------------- the capture gate

def _capture(capture: Any, key: str) -> tuple[list, dict]:
    def count(value: Any) -> bool:
        return type(value) is int and 0 <= value <= MAX_INT

    text = key + ": malformed input"
    _refuse(type(capture) is dict and set(capture) == {"sets", "answer"} and type(capture["sets"]) is list, text)
    for row in capture["sets"]:
        _refuse(type(row) is dict and set(row) == {"scheduledMonotonicMs", "startedWallMs", "completed", "slots"}
                and count(row["scheduledMonotonicMs"]) and count(row["startedWallMs"])
                and type(row["completed"]) is bool and type(row["slots"]) is dict
                and all(type(k) is str and type(v) is str for k, v in row["slots"].items()), text)
    answer = capture["answer"]
    _refuse(type(answer) is dict and set(answer) == {"monotonicMs", "wallMs"} and count(answer["monotonicMs"])
            and count(answer["wallMs"]), text)
    return capture["sets"], answer


def required_slots(key: str, record: Any) -> list:
    """The capture slots a gated value needs: role/<ROLE>, lifecycle and backend/<COMPONENT>."""
    if key == "mutationBroker":
        return ["role/BROKER"]
    if key == "networkEnforcementDigest":
        return ["backend/" + AGENT]
    components = record.get("backendComponents") if type(record) is dict else None
    _refuse(type(components) is dict and components, key + ": malformed input")
    return ["role/" + role for role in ROLES] + ["lifecycle"] + ["backend/" + name for name in sorted(components)]


def capture_gate(key: str, capture: Any, record: Any) -> None:
    """At an answer: the latest completed set (the last completed entry of `sets`) has every required slot TAKEN, and
    both its age on the monotonic clock (answer.monotonicMs - scheduledMonotonicMs, the set's own scheduled start) and
    its wall age (answer.wallMs - startedWallMs) are within 0..90 s. Otherwise the value's own text, or the age text."""
    _refuse(key in GATED, "unknown gated key")
    sets, answer = _capture(capture, key)
    done = [row for row in sets if row["completed"]]
    _refuse(done, GATE_TEXT[key])
    latest = done[-1]
    _refuse(all(latest["slots"].get(slot) == TAKEN for slot in required_slots(key, record)), GATE_TEXT[key])
    monotonic_age = answer["monotonicMs"] - latest["scheduledMonotonicMs"]
    wall_age = answer["wallMs"] - latest["startedWallMs"]
    _refuse(0 <= monotonic_age <= GATE_BOUND_MS and 0 <= wall_age <= GATE_BOUND_MS, key + ": capture set too old")


# ---------------------------------------------------------------------------------------------------- the answer

def observed(snapshot: Any, binding: Any, capture: Any, i06: Any) -> dict:
    """Every value of one answer: {"projections": {key: identity + resourceVersion}, "enforcement": {key: digest}},
    each derived at the snapshot and gated at the answer, or {"refusal": text}. Nothing is compared here."""
    out: dict = {"projections": {}, "enforcement": {}}
    record = snapshot.get("record") if type(snapshot) is dict else None
    for key in POLICIES:
        try:
            value = projection(key, snapshot, binding)
            if key in GATED:
                capture_gate(key, capture, record)
            out["projections"][key] = dict(value["identity"], resourceVersion=value["resourceVersion"])
        except Refused as exc:
            out["projections"][key] = {"refusal": exc.text}
    for key in DIGESTS:
        try:
            value = enforcement(key, snapshot, i06)
            if key in GATED:
                capture_gate(key, capture, record)
            out["enforcement"][key] = value["digest"]
        except Refused as exc:
            out["enforcement"][key] = {"refusal": exc.text}
    return out


def check_observation_digests(snapshot: Any, binding: Any, capture: Any, i06: Any) -> list:
    """DATA_CHECK_ONLY: every projection identity and digest and every enforcement digest derived from the snapshot,
    gated at the answer and compared with the signed binding (the HE-008-signed copy). Returns [] or the refusal texts,
    each once, in key order. Nothing is echoed from the binding."""
    values = observed(snapshot, binding, capture, i06)
    errors: list = []

    def add(text: str) -> None:
        if text not in errors:
            errors.append(text)

    projections = binding.get("projections") if type(binding) is dict else None
    pins = binding.get("enforcementPins") if type(binding) is dict else None
    for key in POLICIES:
        value = values["projections"][key]
        if "refusal" in value:
            add(value["refusal"])
            continue
        expected = projections.get(key) if type(projections) is dict else None
        identity = {k: v for k, v in value.items() if k != "resourceVersion"}
        if identity != expected:
            add(key + ": differs from the signed value")
    for key in DIGESTS:
        value = values["enforcement"][key]
        if type(value) is dict:
            add(value["refusal"])
            continue
        if type(pins) is not dict or pins.get(key) != value:
            add(key + ": differs from the signed value")
    return errors


# ---------------------------------------------------------------------------------------------------- definitions

def refusal_texts() -> list:
    """Every refusal text the contract pins, sorted."""
    texts = {T_RENDERED, T_UNKNOWN, T_NAMESPACE, T_ANNOTATION, T_SELECTOR, T_AGGREGATED, T_DANGLING, T_LOOPBACK,
             T_CLOSURE, T_BROKER_ROW, T_NO_AGENT, *GATE_TEXT.values()}
    texts |= {"rbac: malformed " + field for field in B1_FIELDS}
    texts |= {key + ": " + text for key in POLICIES + DIGESTS for text in KEY_TEXTS}
    texts |= {key + ": " + text for key in LIST_OF for text in ONE_OBJECT_TEXTS}
    texts |= {key + ": capture set too old" for key in GATED}
    return sorted(texts - UNREACHABLE)


# Both RBAC documents hold only B1-validated strings and booleans, so their float and integer texts cannot occur; they
# are not pinned.
UNREACHABLE = frozenset(key + ": " + text for key in ("rbac", "rbacClosureDigest")
                        for text in ("float refused", "integer out of range"))


def _projection_definitions() -> dict:
    live = "LIVE"

    def identity(key: str) -> dict:
        api_version, kind, name, scope = IDENTITY[key]
        return {"apiVersion": api_version, "kind": kind, "name": name or live,
                "namespace": None if scope == "CLUSTER_SCOPED" else (scope or live),
                "uid": "DERIVED" if key in SYNTHETIC else live}

    def malformed(key: str) -> list:
        return [key + ": " + text for text in ("malformed input", "float refused", "integer out of range",
                                               "document bound exceeded") if key + ": " + text not in UNREACHABLE]

    one = {key: [key + ": count is not one", key + ": name differs from the binding"] for key in LIST_OF}
    return {
        "admissionPolicy": {
            "identity": identity("admissionPolicy"),
            "source": "synthetic: the four sealed values rendered by admission v3 (a2_objects, manifest_file_bytes under "
                      "the file name planeon-a2.json, manifest_directory_hash), and the qualification Namespace's Pod "
                      "Security labels",
            "spec": {"sealedObjects": "the eight rendered objects (four ValidatingAdmissionPolicies, four bindings), "
                                      "sorted by (kind, metadata.name)",
                     "podSecurityLabels": "the qualification Namespace's labels whose key starts with "
                                          "pod-security.kubernetes.io/, as an object; {} when there are none"},
            "inputs": {"requestSpecs": ["v1 namespaces", "admissionregistration.k8s.io/v1 validatingadmissionpolicies",
                                        "admissionregistration.k8s.io/v1 validatingadmissionpolicybindings"],
                       "configurationValues": ["qualificationNamespace", "pinnedManifestHash",
                                               "sealedAdmission.ipFamily", "sealedAdmission.serviceCIDR",
                                               "sealedAdmission.defaultTolerationSeconds"],
                       "observedValues": ["ADM-4's loaded hash (adm4LoadedHash)"],
                       "bindingValues": [], "recordFields": [], "captureSlots": []},
            "gates": ["the rendered directory hash equals the signed pinnedManifestHash and ADM-4's loaded hash",
                      "every listed ValidatingAdmissionPolicy is one of the four rendered policy names and every listed "
                      "binding one of the four rendered binding names, over (kind, name)"],
            "order": ["sealed values: exactness and shape", "rendered hash", "unknown admission objects",
                      "qualification Namespace listed", "document exactness"],
            "refusals": malformed("admissionPolicy") + [T_RENDERED, T_UNKNOWN, T_NAMESPACE],
            "residuals": ["R-ADM-LIST", "R-PSA-CONFIG"]},
        "resourceQuota": {
            "identity": identity("resourceQuota"), "source": "the ResourceQuotas list (R10:obs/inputs.rs:104)",
            "spec": {"spec": "the served spec"},
            "inputs": {"requestSpecs": ["v1 resourcequotas"], "configurationValues": ["qualificationNamespace"],
                       "observedValues": [], "bindingValues": ["projections.resourceQuota.name"], "recordFields": [],
                       "captureSlots": []},
            "gates": ["exactly one ResourceQuota in the qualification namespace", "its name is the binding's"],
            "order": ["shape", "count", "name", "document exactness"],
            "refusals": malformed("resourceQuota") + one["resourceQuota"], "residuals": ["R-DEFAULTS"]},
        "limitRange": {
            "identity": identity("limitRange"), "source": "the LimitRanges list (R10:obs/inputs.rs:102)",
            "spec": {"spec": "the served spec"},
            "inputs": {"requestSpecs": ["v1 limitranges"], "configurationValues": ["qualificationNamespace"],
                       "observedValues": [], "bindingValues": ["projections.limitRange.name"], "recordFields": [],
                       "captureSlots": []},
            "gates": ["exactly one LimitRange in the qualification namespace", "its name is the binding's"],
            "order": ["shape", "count", "name", "document exactness"],
            "refusals": malformed("limitRange") + one["limitRange"], "residuals": ["R-DEFAULTS"]},
        "serviceAccount": {
            "identity": identity("serviceAccount"), "source": "the ServiceAccounts list (R10:obs/inputs.rs:105)",
            "spec": {member: "the served top-level member, when present (never null for an absent one)"
                     for member in SA_KEYS},
            "inputs": {"requestSpecs": ["v1 serviceaccounts"], "configurationValues": ["qualificationNamespace"],
                       "observedValues": [],
                       "bindingValues": ["scope.serviceAccountSubject", "projections.serviceAccount.name"],
                       "recordFields": [], "captureSlots": []},
            "gates": ["exactly one ServiceAccount by the subject's name in the qualification namespace",
                      "its name is the binding's", "no kubernetes.io/enforce-mountable-secrets annotation"],
            "order": ["shape", "count by name", "name", "annotation", "document exactness"],
            "refusals": malformed("serviceAccount") + one["serviceAccount"] + [T_ANNOTATION],
            "residuals": ["R-DEFAULTS"]},
        "rbac": {
            "identity": identity("rbac"),
            "source": "synthetic: the four RBAC lists and the ServiceAccounts list, under B1's rules",
            "spec": {"subjects": "one entry {kind, name, exists, effectiveRules} per subject named by a RoleBinding in "
                                 "the qualification namespace or by any ClusterRoleBinding, sorted by (kind, name); "
                                 "the subject's rules whose scope is the qualification namespace or CLUSTER, sorted "
                                 "and deduplicated by canonical bytes"},
            "inputs": {"requestSpecs": ["rbac.authorization.k8s.io/v1 clusterroles",
                                        "rbac.authorization.k8s.io/v1 clusterrolebindings",
                                        "rbac.authorization.k8s.io/v1 roles", "rbac.authorization.k8s.io/v1 rolebindings",
                                        "v1 serviceaccounts"],
                       "configurationValues": ["qualificationNamespace"], "observedValues": [], "bindingValues": [],
                       "recordFields": [], "captureSlots": []},
            "gates": ["B1's refusals, in B1's order, before either RBAC document"],
            "order": ["B1's refusals", "document exactness"],
            "refusals": malformed("rbac") + [T_AGGREGATED, T_DANGLING, T_LOOPBACK]
                        + ["rbac: malformed " + field for field in B1_FIELDS if field != "input"],
            "residuals": ["R-RBAC-COMPLETE"]},
        "networkPolicy": {
            "identity": identity("networkPolicy"), "source": "the NetworkPolicies list (R10:obs/inputs.rs:106)",
            "spec": {"spec": "the served spec, in v1's selector-free form"},
            "inputs": {"requestSpecs": ["networking.k8s.io/v1 networkpolicies"],
                       "configurationValues": ["qualificationNamespace"], "observedValues": [],
                       "bindingValues": ["projections.networkPolicy.name"], "recordFields": [], "captureSlots": []},
            "gates": ["exactly one NetworkPolicy in the qualification namespace", "its name is the binding's",
                      "selector-free: podSelector {}, peers by ipBlock alone, integer port and endPort (an entry with "
                      "no port is admitted), only the NetworkPolicy v1 API's members"],
            "order": ["shape", "count", "name", "selector-free form", "document exactness"],
            "refusals": malformed("networkPolicy") + one["networkPolicy"] + [T_SELECTOR],
            "residuals": ["R-DEFAULTS", "R-NET-DATAPATH"]},
        "mutationBroker": {
            "identity": identity("mutationBroker"),
            "source": "synthetic: the enrolled native-qualification/v4 record's BROKER row (never the broker binding)",
            "spec": {member: ("the row's cgroup without its inode" if member == "cgroup" else "the row's member")
                     for member in BROKER_DOCUMENT},
            "inputs": {"requestSpecs": [], "configurationValues": ["qualificationNamespace"], "observedValues": [],
                       "bindingValues": [], "recordFields": ["roles.BROKER." + member for member in BROKER_MEMBERS],
                       "captureSlots": ["role/BROKER"]},
            "gates": ["the BROKER row carries its 20 members and its cgroup its 7",
                      "at every answer, the capture gate over role/BROKER"],
            "order": ["broker row", "document exactness", "capture gate (at the answer)"],
            "refusals": malformed("mutationBroker") + [T_BROKER_ROW, GATE_TEXT["mutationBroker"],
                                                      "mutationBroker: capture set too old"],
            "residuals": ["R-BROKER-LIVE"]},
    }


def _digest_definitions() -> dict:
    def bound(key: str) -> list:
        return [key + ": " + text for text in ("malformed input", "float refused", "integer out of range",
                                               "document bound exceeded") if key + ": " + text not in UNREACHABLE]

    return {
        "admissionFenceDigest": {
            "source": "manifest_directory_hash over the rendered sealed directory (admission v3), already in "
                      "sha256:<hex> form",
            "document": None,
            "inputs": {"requestSpecs": [], "configurationValues": ["qualificationNamespace", "pinnedManifestHash",
                                                                   "sealedAdmission"],
                       "observedValues": ["ADM-4's loaded hash (adm4LoadedHash)"], "recordFields": [],
                       "captureSlots": []},
            "gates": ["the rendered hash equals the signed pinnedManifestHash and ADM-4's loaded hash"],
            "refusals": bound("admissionFenceDigest") + [T_RENDERED], "residuals": []},
        "rbacClosureDigest": {
            "source": "the cluster-wide closure value of every subject named by any RoleBinding or ClusterRoleBinding",
            "document": {"schemaVersion": CLOSURE_VERSION,
                         "subjects": "entries {kind, name, exists, effectiveRules} with every rule at every scope, "
                                     "non-resource entries with their binding's scope, sorted and deduplicated; "
                                     "subjects sorted by (kind, name)"},
            "inputs": {"requestSpecs": ["rbac.authorization.k8s.io/v1 clusterroles",
                                        "rbac.authorization.k8s.io/v1 clusterrolebindings",
                                        "rbac.authorization.k8s.io/v1 roles", "rbac.authorization.k8s.io/v1 rolebindings",
                                        "v1 serviceaccounts"],
                       "configurationValues": ["qualificationNamespace"], "observedValues": [],
                       "recordFields": [], "captureSlots": [],
                       "frozenInputs": sorted(FROZEN_INPUTS),
                       "callerSupplied": {"i06": "{closure, inventory, bootstrap}: each the parsed JSON of its "
                                                 "frozenInputs file, pinned by path and sha256; a missing i06, or one "
                                                 "without exactly those three members, refuses rbacClosureDigest: "
                                                 "malformed input"}},
            "gates": ["B1's refusals", "I06's closure check and I06 v4's role pin "
                                       "(i06_backend_profile_v4.check_observer_snapshot) over B1's snapshot and the "
                                       "same read's ClusterRoles, ClusterRoleBindings and RoleBindings"],
            "refusals": bound("rbacClosureDigest") + [T_CLOSURE, T_AGGREGATED, T_DANGLING, T_LOOPBACK]
                        + ["rbac: malformed input"] + ["rbac: malformed " + field for field in B1_FIELDS],
            "residuals": ["R-RBAC-COMPLETE"]},
        "networkEnforcementDigest": {
            "source": "the qualification namespace's NetworkPolicy documents and the enrolled record's network policy "
                      "agent",
            "document": {"networkPolicies": "the NetworkPolicy documents in the projection form, selector-free, sorted "
                                            "by canonical bytes (v1: exactly one)",
                         "agent": {member: "backendComponents.NETWORK_POLICY_AGENT." + member
                                   for member in AGENT_MEMBERS}},
            "inputs": {"requestSpecs": ["networking.k8s.io/v1 networkpolicies"],
                       "configurationValues": ["qualificationNamespace"], "observedValues": [],
                       "recordFields": ["backendComponents.NETWORK_POLICY_AGENT." + member for member in AGENT_MEMBERS]
                       + ["backendProfile.componentKeys"],
                       "captureSlots": ["backend/" + AGENT]},
            "gates": ["the networkPolicy rules (count, selector-free form)",
                      "NETWORK_POLICY_AGENT in backendComponents and in backendProfile.componentKeys",
                      "at every answer, the capture gate over backend/NETWORK_POLICY_AGENT"],
            "refusals": bound("networkEnforcementDigest") + bound("networkPolicy")
                        + ["networkPolicy: count is not one", T_SELECTOR, T_NO_AGENT,
                           GATE_TEXT["networkEnforcementDigest"], "networkEnforcementDigest: capture set too old"],
            "residuals": ["R-NET-AGENT", "R-NET-DATAPATH", "R-DEFAULTS"]},
        "hostPreflightDigest": {
            "source": "\"sha256:\" and the sha256 of the enrolled native-qualification/v4 record's canonical bytes (the "
                      "value of configuration v2's qualificationRecord.sha256)",
            "document": None,
            "inputs": {"requestSpecs": [], "configurationValues": [], "observedValues": [],
                       "recordFields": ["the whole record"],
                       "captureSlots": ["role/" + role for role in ROLES] + ["lifecycle",
                                                                             "backend/<every backendComponents key>"]},
            "gates": ["at every answer, the capture gate over every role, the lifecycle and every backend component of "
                      "the record"],
            "refusals": bound("hostPreflightDigest") + [GATE_TEXT["hostPreflightDigest"],
                                                        "hostPreflightDigest: capture set too old"],
            "residuals": []},
    }


RESIDUALS = {
    "R-ADM-LIST": {
        "cannotSee": "Whether the static admission objects appear in API lists, and with what uid and content; whether "
                     "the apiserver refuses an API object named with the .static.k8s.io suffix. A listed object with a "
                     "rendered (kind, name) is admitted by the unknown-object rule and rests on this check.",
        "check": "T04 (owner)"},
    "R-PSA-CONFIG": {
        "cannotSee": "PodSecurity's configured defaults and exemptions (usernames, runtimeClasses, namespaces) in the "
                     "sealed admission configuration file (SC05, --admission-control-config-file)",
        "check": "T04: the running PodSecurity configuration equals the enrolled file's, the record's APISERVER "
                 "backendFiles row for the SC05 file"},
    "R-NET-DATAPATH": {
        "cannotSee": "The live network datapath, including pod-IP behaviour for an ipBlock that overlaps the pod or "
                     "Service ranges, and the running agent's flags against the sealed --fail-open=false and "
                     "--disable-nri",
        "check": "T04 (owner): the agent's programmed nftables ruleset enforces the namespace's NetworkPolicy; the "
                 "flags are the sealed ones"},
    "R-NET-AGENT": {
        "cannotSee": "The network agent's executableLabel, artifactDigest and apiIdentities, which its backend capture "
                     "does not compare, and its running image (ENTRY_BOUND: domain entry plus the measured file, not "
                     "the running image). Custody link: check_record requires artifactDigest to equal the sha256 of the "
                     "executable's backendFiles row (R10:obs/record_check.rs:915, :592-594), and each set compares the "
                     "live file's contentDigest and verity with that row (R10:obs/capture_check.rs:630-634), so the "
                     "artifactDigest check concerns only the running image.",
        "check": "T04-LABELS for executableLabel; T04: the running agent's executable content equals the record's "
                 "artifactDigest; T04: the running agent's apiserver identities equal the record's apiIdentities; "
                 "T04-ENTRYPOINT, T04-ENTRYPOINT-CENSUS and the matrix successor's execute_no_trans closure for the "
                 "running image"},
    "R-DEFAULTS": {
        "cannotSee": "Server defaulting of the real kinds' spec",
        "check": "T04, per kind (ResourceQuota, LimitRange, ServiceAccount, NetworkPolicy): the spec HE-008 captured at "
                 "enrollment equals the spec served after an apiserver restart on v1.37.1"},
    "R-RBAC-COMPLETE": {
        "cannotSee": "Completeness by refusal, not expansion (aggregations, impersonation paths, indirect grants); the "
                     "system:authenticated limit",
        "check": "T04 (carried)"},
    "R-BROKER-LIVE": {
        "cannotSee": "The BROKER document members its capture does not observe: the process image (LABEL_BOUND: bound "
                     "by processLabel and the enrolled file's measurement); executableLabel (DECLARED_T04); "
                     "seccompFilterDigest and seccompDefaultAction (DECLARED_T04, corroborated by the OBSERVED filter "
                     "count); the cgroup's selinuxLabel (DECLARED_T04); listenEndpointIds and outboundEndpointIds (no "
                     "class row; not compared by check_capture)",
        "check": "T04-SECCOMP-INSTALLED for the seccomp members; T04-LABELS for executableLabel and the cgroup's "
                 "selinuxLabel; T04-ENTRYPOINT and T04-ENTRYPOINT-CENSUS for the image's binding; HE-005 and T04 for "
                 "the endpoints: the broker's bound and connected endpoints equal the record's listenEndpointIds and "
                 "outboundEndpointIds, resolved through the record's endpointTuples; HE-005 for the broker's behaviour"},
}


def definitions() -> dict:
    """The closed definitions document (definitions.json must equal it)."""
    return {
        "schemaVersion": SCHEMA_VERSION,
        "contract": "DIGEST-CONTRACT",
        "evidenceClass": "DATA_CHECK_ONLY",
        "nativeAcceptance": False,
        "wirePins": {key: {"path": path, "sha256": sha} for key, (path, sha) in WIRE_PINS.items()},
        "model": {"path": MODEL_PATH,
                  "functions": ["projection_document", "projection_digest", "enforcement_digests", "capture_gate",
                                "check_observation_digests", "check_vectors", "main"]},
        "sharedHelpers": {"path": "scripts/validate_proxy_contract.py", "functions": ["canonical", "digest", "_bounded"],
                          "import": "by name, as the other validators import them",
                          "pinnedBy": "the helper vectors in vectors.json (canonical bytes, digests and bounds), not "
                                      "the file's sha256: its packet list changes with every packet"},
        "frozenModels": [{"path": path, "sha256": sha, "lastChange": commit}
                         for path, (sha, commit) in FROZEN_MODELS.items()],
        "frozenInputs": [{"name": name, "path": path, "sha256": sha} for name, (path, sha) in FROZEN_INPUTS.items()],
        "projectionForm": {"members": ["apiVersion", "kind", "metadata", "spec"],
                           "metadata": ["name", "namespace", "uid"],
                           "identity": "apiVersion and kind are the contract's for each key, never a served item's; "
                                       "no identity member is read from the binding"},
        "canonical": {"bytes": "json.dumps(value, sort_keys=True, separators=(\",\", \":\"), ensure_ascii=False, "
                               "allow_nan=False), UTF-8 (VPC's canonical)",
                      "values": "the apiserver's exact JSON values; a float refuses; VPC's _bounded: exact builtins, "
                                "depth at most 16, its size budget, |integer| at most 2^53 - 1 (a negative integer "
                                "within the bound is accepted)",
                      "sortedSets": ["sealedObjects by (kind, metadata.name)",
                                     "RBAC subjects by (kind, name), one entry each",
                                     "each RBAC subject's rules by canonical bytes, deduplicated",
                                     "networkPolicies by canonical bytes"],
                      "otherLists": "served order"},
        "digest": {"form": "sha256:<64 lowercase hex>", "rule": "\"sha256:\" + digest(canonical(document))"},
        "syntheticUid": "digest(canonical({apiVersion, kind, name, namespace})) over the fixed identity: 64 lowercase "
                        "hex characters",
        "snapshot": {"members": ["resourceVersion", "lists", "configuration", "adm4LoadedHash", "record"],
                     "lists": list(LISTS),
                     "configuration": ["qualificationNamespace", "pinnedManifestHash",
                                       "sealedAdmission: {ipFamily, serviceCIDR, defaultTolerationSeconds}"],
                     "rule": "every projection and digest from one read at one resourceVersion, computed before the "
                             "lists are dropped; a real projection's resourceVersion is the object's own, a synthetic "
                             "one's the read's"},
        "projections": _projection_definitions(),
        "enforcementDigests": _digest_definitions(),
        "captureGate": {
            "gated": list(GATED),
            "boundMs": GATE_BOUND_MS,
            "bound": {"cycleMs": CYCLE_MS, "scrapeToSetMs": SCRAPE_TO_SET_MS, "setBudgetMs": SET_BUDGET_MS,
                      "anchors": ["R10:obs/observe.rs:99 CYCLE", "R10:obs/capture.rs:55 SCRAPE_TO_SET",
                                  "R10:obs/capture.rs:53 SET_BUDGET"]},
            "dataShape": {"sets": [{"scheduledMonotonicMs": "integer 0..2^53-1: the set's own scheduled start on the "
                                                            "monotonic clock, recorded with the set",
                                    "startedWallMs": "integer 0..2^53-1: the wall clock at the set's start "
                                                     "(set_started_ms)",
                                    "completed": "boolean",
                                    "slots": {"<slot>": "TAKEN | <any other state>"}}],
                          "answer": {"monotonicMs": "integer 0..2^53-1: the answer's reading of the monotonic clock of "
                                                    "the scheduled starts",
                                     "wallMs": "integer 0..2^53-1: a millisecond reading of the same wall clock as "
                                               "set_started_ms, handed to the I01 service with the view"}},
            "slots": {"roles": ["role/" + role for role in ROLES], "lifecycle": "lifecycle",
                      "backends": "backend/<backendComponents key>"},
            "requiredSlots": {"mutationBroker": ["role/BROKER"], "networkEnforcementDigest": ["backend/" + AGENT],
                              "hostPreflightDigest": ["role/" + role for role in ROLES]
                              + ["lifecycle", "backend/<every backendComponents key of the record>"]},
            "rule": ["the latest completed set is the last entry of sets whose completed is true; none: the value's own "
                     "text", "every required slot of that set is TAKEN, else the value's own text",
                     "monotonic age = answer.monotonicMs - scheduledMonotonicMs and wall age = answer.wallMs - "
                     "startedWallMs are both within 0..90000 ms, else <key>: capture set too old",
                     "the start is the set's own, never the epoch's current cycle; an Expired view is a set whose "
                     "slots are EXPIRED"],
            "refusals": [GATE_TEXT[key] for key in GATED] + [key + ": capture set too old" for key in GATED]
                        + [key + ": malformed input" for key in GATED]},
        "b1Refusals": {
            "anchor": "R10:obs/rbac.rs",
            "rows": [{"refusal": "rbac: malformed subject namespace",
                      "rule": "a ClusterRoleBinding ServiceAccount subject without a namespace (an empty namespace is "
                              "absent)", "lines": ":207, :212-214"},
                     {"refusal": "rbac: malformed subject kind", "rule": "a subject kind other than User, Group or "
                                                                         "ServiceAccount", "lines": ":192-197"},
                     {"refusal": "rbac: malformed subject name", "rule": "a missing or empty subject name",
                      "lines": ":189-191"},
                     {"refusal": "rbac: malformed roleRef apiGroup", "rule": "a roleRef outside the RBAC group",
                      "lines": ":229-231"},
                     {"refusal": "rbac: malformed roleRef kind", "rule": "a ClusterRoleBinding naming a Role, or another "
                                                                         "kind", "lines": ":232-236"},
                     {"refusal": "rbac: malformed roleRef name", "rule": "a missing or empty roleRef name",
                      "lines": ":237-239"},
                     {"refusal": T_DANGLING, "rule": "a binding whose roleRef names no listed role",
                      "lines": ":313-315"},
                     {"refusal": "rbac: malformed rule (non-resource URLs beside resources)",
                      "rule": "a rule with nonResourceURLs beside resources", "lines": ":141-143"},
                     {"refusal": T_LOOPBACK, "rule": "a role holding a non-resource rule bound directly to User "
                                                     "system:apiserver", "lines": ":319-322"},
                     {"refusal": T_AGGREGATED, "rule": "a ClusterRole with an aggregationRule key bound by a RoleBinding "
                                                       "in the qualification namespace or by any ClusterRoleBinding",
                      "lines": ":316-318"},
                     {"refusal": "rbac: malformed <field>", "rule": "any other malformed RBAC or ServiceAccount object "
                                                                    "(metadata, rules, rule, rule list, subjects, "
                                                                    "subject, roleRef)",
                      "lines": ":109-147, :178-241, :258-292"}],
            "nonResourceRule": "a rule with a non-empty nonResourceURLs list (R10:obs/rbac.rs:133, :139); its entry is "
                               "{nonResourceURLs, verbs, scope}, scope CLUSTER through a ClusterRoleBinding and the "
                               "binding's namespace through a RoleBinding",
            "exists": "true for User and Group; for a ServiceAccount, whether that ServiceAccount is listed "
                      "(R10:obs/rbac.rs:272-278, :325-328)",
            "subjectKey": "system:serviceaccount:<namespace>:<name> for a ServiceAccount, a RoleBinding's subject without "
                          "a namespace taking the binding's (R10:obs/rbac.rs:202-219)",
            "order": "ClusterRoles, Roles, ServiceAccounts, binding metadata, then bindings sorted (ClusterRoleBindings "
                     "by name, then RoleBindings by namespace and name), each: roleRef, subjects, role resolution, "
                     "aggregation, loopback"},
        "comparison": {"text": "<key>: differs from the signed value",
                       "rule": "each projection's identity and digest, and each enforcement digest, equals the "
                               "HE-008-signed binding's; nothing is echoed"},
        "refusalTexts": refusal_texts(),
        "residuals": RESIDUALS,
        "scopeLimits": ["one NetworkPolicy in the qualification namespace (v1); several take a List form for "
                        "networkPolicy alone, through a contract revision",
                        "selector-free NetworkPolicies only (v1)",
                        "direct RBAC grants only: an aggregated ClusterRole that reaches the namespace refuses"],
    }


# ---------------------------------------------------------------------------------------------------- vectors

def _pairs(items: list) -> dict:
    out = {}
    for key, value in items:
        if key in out:
            raise ValueError("duplicate JSON member")
        out[key] = value
    return out


def _parse(raw: bytes) -> Any:
    def constant(_: str) -> Any:
        raise ValueError("nonfinite JSON")

    return json.loads(raw, object_pairs_hook=_pairs, parse_constant=constant)


def _locate(node: Any, key: Any) -> Any:
    if type(node) is list:
        if type(key) is int:
            return key
        raise ValueError("closed vector operation")
    if type(node) is dict and type(key) is str:
        return key
    raise ValueError("closed vector operation")


def apply_ops(value: Any, ops: list) -> Any:
    """A copy of `value` with each operation {op: set|delete|append, path, value?} applied in order."""
    value = copy.deepcopy(value)
    for op in ops:
        if not (type(op) is dict and op.get("op") in ("set", "delete", "append") and type(op.get("path")) is list
                and op["path"] and set(op) == ({"op", "path"} if op["op"] == "delete" else {"op", "path", "value"})):
            raise ValueError("closed vector operation")
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


def _expand(value: Any) -> Any:
    """A helper vector's input: {"$fill": n} stands for a string of n "a" characters."""
    if type(value) is dict:
        if set(value) == {"$fill"} and type(value["$fill"]) is int:
            return "a" * value["$fill"]
        return {k: _expand(v) for k, v in value.items()}
    if type(value) is list:
        return [_expand(v) for v in value]
    return value


def _check(ok: Any, what: str) -> None:
    if not ok:
        raise ValueError(what)


def _outcome(function: Any, *args: Any) -> dict:
    try:
        return {"value": function(*args)}
    except Refused as exc:
        return {"refusal": exc.text}


def _frozen(files: dict) -> dict:
    out = {}
    for name, (path, sha) in FROZEN_INPUTS.items():
        raw = files.get(path)
        _check(type(raw) is bytes and hashlib.sha256(raw).hexdigest() == sha, "frozen input differs: " + path)
        out[name] = _parse(raw)
    for path, (sha, _) in FROZEN_MODELS.items():
        raw = files.get(path)
        _check(type(raw) is bytes and hashlib.sha256(raw).hexdigest() == sha, "frozen model differs: " + path)
    _check(i06v4.v1 is i06v1, "I06 v4 imports I06 v1")
    return out


VECTOR_MEMBERS = {"schemaVersion", "evidenceClass", "nativeAcceptance", "contract", "sources", "fixtures", "helpers",
                  "vectors", "complete"}
ROW_MEMBERS = {"id", "case", "snapshot", "binding", "capture", "ops", "expect"}
EXPECT_MEMBERS = {"projections", "enforcement", "gates", "observation", "same", "differs"}


def _inputs(fixtures: dict, row: dict) -> tuple:
    snapshot = dict(fixtures["snapshots"][row["snapshot"]], record=fixtures["record"])
    combined = {"snapshot": snapshot, "binding": fixtures["bindings"][row["binding"]],
                "capture": fixtures["captures"][row["capture"]]}
    combined = apply_ops(combined, row["ops"])
    return combined["snapshot"], combined["binding"], combined["capture"]


def check_vectors(vectors: Any, files: dict) -> int:
    """DATA_CHECK_ONLY: replay every vector. `files` maps the frozen inputs' and the frozen models' paths to their bytes.
    Returns the number of checks; a mismatch raises ValueError naming the vector."""
    _check(type(vectors) is dict and set(vectors) == VECTOR_MEMBERS and vectors["schemaVersion"] == VECTORS_VERSION
           and vectors["evidenceClass"] == "UNIT_VERIFICATION_ONLY" and vectors["nativeAcceptance"] is False
           and type(vectors["helpers"]) is list and type(vectors["vectors"]) is list, "closed vectors document")
    i06 = _frozen(files)
    fixtures = vectors["fixtures"]
    _check(type(fixtures) is dict and set(fixtures) == {"record", "snapshots", "bindings", "captures"},
           "closed fixtures")
    checks = 0
    seen_texts: set = set()
    ids: list = []
    # Helper vectors: VPC's canonical, digest and _bounded, as this contract uses them.
    for row in vectors["helpers"]:
        _check(type(row) is dict and set(row) == {"id", "case", "function", "input", "expect"}, "closed helper vector")
        ids.append(row["id"])
        value = _expand(row["input"])
        if row["function"] == "canonical":
            got = canonical(value).hex()
        elif row["function"] == "digest":
            got = digest(bytes.fromhex(value))
        elif row["function"] == "projection_digest":
            got = projection_digest(value)
        elif row["function"] == "bound":
            outcome = _outcome(document_bound, "resourceQuota", value)
            got = outcome.get("refusal")
            if got:
                seen_texts.add(got)
        else:
            raise ValueError("helper function: " + str(row["id"]))
        _check(got == row["expect"], "helper vector " + str(row["id"]))
        checks += 1
    # After the helpers, so that a changed helper is named by its helper vector first.
    _check(vectors["contract"] == {"path": CONTRACT_DIR + "definitions.json",
                                   "canonicalSha256": digest(canonical(definitions()))},
           "the vectors' definitions pin")
    checks += 1
    digests: dict = {}
    for row in vectors["vectors"]:
        _check(type(row) is dict and set(row) == ROW_MEMBERS and type(row["expect"]) is dict
               and set(row["expect"]) <= EXPECT_MEMBERS and row["expect"], "closed vector " + str(row.get("id")))
        ids.append(row["id"])
        snapshot, binding, capture = _inputs(fixtures, row)
        expect, where = row["expect"], "vector " + row["id"]
        digests[row["id"]] = {}
        for key, want in expect.get("projections", {}).items():
            outcome = _outcome(projection, key, snapshot, binding)
            if "refusal" in outcome:
                _check(want == {"refusal": outcome["refusal"]}, where + " " + key + " refusal " + outcome["refusal"])
                seen_texts.add(outcome["refusal"])
            else:
                value = outcome["value"]
                _check("refusal" not in want and want["digest"] == value["identity"]["projectionDigest"],
                       where + " " + key + " digest")
                _check(want.get("identity", value["identity"]) == value["identity"], where + " " + key + " identity")
                _check(want.get("document", value["document"]) == value["document"], where + " " + key + " document")
                _check(want.get("canonical", canonical(value["document"]).decode()) == canonical(value["document"]).decode(),
                       where + " " + key + " canonical")
                _check(want.get("resourceVersion", value["resourceVersion"]) == value["resourceVersion"],
                       where + " " + key + " resourceVersion")
                digests[row["id"]][key] = value["identity"]["projectionDigest"]
            checks += 1
        for key, want in expect.get("enforcement", {}).items():
            outcome = _outcome(enforcement, key, snapshot, i06)
            if "refusal" in outcome:
                _check(want == {"refusal": outcome["refusal"]}, where + " " + key + " refusal " + outcome["refusal"])
                seen_texts.add(outcome["refusal"])
            else:
                value = outcome["value"]
                _check("refusal" not in want and want["digest"] == value["digest"], where + " " + key + " digest")
                _check(want.get("document", value.get("document")) == value.get("document"),
                       where + " " + key + " document")
                digests[row["id"]][key] = value["digest"]
            checks += 1
        for key, want in expect.get("gates", {}).items():
            outcome = _outcome(capture_gate, key, capture, snapshot.get("record"))
            got = outcome.get("refusal")
            _check(got == want, where + " gate " + key)
            if got:
                seen_texts.add(got)
            checks += 1
        if "observation" in expect:
            got = check_observation_digests(snapshot, binding, capture, i06)
            _check(got == expect["observation"], where + " observation " + json.dumps(got))
            seen_texts.update(got)
            checks += 1
        for relation in ("same", "differs"):
            for key, other in expect.get(relation, {}).items():
                _check(other in digests and key in digests[other] and key in digests[row["id"]]
                       and (digests[other][key] == digests[row["id"]][key]) == (relation == "same"),
                       where + " " + relation + " " + key + " as " + str(other))
                checks += 1
    checks += _check_complete(vectors["complete"], fixtures, i06)
    _check(len(ids) == len(set(ids)), "unique vector ids")
    missing = [text for text in DESIGN_TEXTS if text not in seen_texts]
    _check(not missing, "a named refusal text has no vector: " + ", ".join(missing))
    return checks


# The refusal texts the design names (each <key> template instantiated for at least one key); each must occur in a
# vector's pinned outcome.
DESIGN_TEXTS = (T_RENDERED, T_UNKNOWN, T_ANNOTATION, T_SELECTOR, T_AGGREGATED, T_NO_AGENT,
                GATE_TEXT["mutationBroker"], GATE_TEXT["networkEnforcementDigest"], GATE_TEXT["hostPreflightDigest"],
                "resourceQuota: float refused", "resourceQuota: integer out of range",
                "resourceQuota: count is not one", "resourceQuota: name differs from the binding",
                "mutationBroker: capture set too old")


def _check_complete(complete: Any, fixtures: dict, i06: dict) -> int:
    """The complete I01 positive: the derived binding, request, observation and profile hold together, and the model's
    answer over the fixture equals the observation. VPO's validate_messages and VPC's validate_profile are not imported
    here: the packet's layer test, tests/test_policy_observation_digests.py, which the pre-check and verify run, asserts
    with no skip, expected-failure mark or import guard that validate_messages and validate_profile return [] on the
    complete positive and each refuses when one preexisting reference's observedDigest is changed (README section
    10)."""
    _check(type(complete) is dict and set(complete) == {"case", "snapshot", "capture", "binding", "request",
                                                        "observation", "profile", "now", "previous", "replaced"},
           "closed complete positive")
    snapshot = dict(fixtures["snapshots"][complete["snapshot"]], record=fixtures["record"])
    capture = fixtures["captures"][complete["capture"]]
    binding, request, observation, profile = (complete[k] for k in ("binding", "request", "observation", "profile"))
    _check(check_observation_digests(snapshot, binding, capture, i06) == [], "complete positive: the answer refuses")
    values = observed(snapshot, binding, capture, i06)
    _check(observation["projections"] == values["projections"], "complete positive: observed projections")
    _check(observation["enforcement"] == dict(values["enforcement"], policyGeneration=observation["generation"]),
           "complete positive: observed enforcement")
    _check(binding["profileDigest"] == "sha256:" + digest(canonical(profile)), "complete positive: profileDigest")
    bound = "sha256:" + digest(canonical(binding))
    _check(request["bindingDigest"] == bound and observation["bindingDigest"] == bound,
           "complete positive: bindingDigest")
    policy = profile["policy"]
    for key in POLICIES:
        _check(policy[key + "Digest"] == binding["projections"][key]["projectionDigest"],
               "complete positive: profile digest " + key)
    kinds = {"resourceQuota": "ResourceQuota", "limitRange": "LimitRange", "serviceAccount": "ServiceAccount"}
    for key, kind in kinds.items():
        refs = [r for r in profile["capacityEntries"]["preexistingResourceRefs"] if r["kind"] == kind]
        _check(len(refs) == 1 and refs[0]["observedDigest"] == binding["projections"][key]["projectionDigest"]
               and refs[0]["uid"] == binding["projections"][key]["uid"], "complete positive: reference " + key)
    return 5


def main() -> int:
    root = Path(__file__).resolve().parents[1]
    try:
        for module, path in ((adm, "scripts/admission_semantics_v3.py"), (i06v1, "scripts/i06_backend_profile.py"),
                             (i06v4, "scripts/i06_backend_profile_v4.py")):
            _check(Path(module.__file__).resolve() == (root / path).resolve(), "imported model path: " + path)
        _check(_parse((root / CONTRACT_DIR / "definitions.json").read_bytes()) == definitions(),
               "definitions.json differs from the model's definitions")
        vectors = _parse((root / CONTRACT_DIR / "vectors.json").read_bytes())
        files = {path: (root / path).read_bytes()
                 for path in [p for p, _ in FROZEN_INPUTS.values()] + list(FROZEN_MODELS)}
        count = check_vectors(vectors, files)
    except (OSError, ValueError, TypeError, KeyError, AttributeError, IndexError, RecursionError) as exc:
        print("ERROR: policy observation digests: " + str(exc))
        return 1
    print("Policy observation digests valid: %d checks (%d helper, %d vectors, 1 complete I01 positive); "
          "DATA_CHECK_ONLY, product/native NOT_RUN." % (count, len(vectors["helpers"]), len(vectors["vectors"])))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
