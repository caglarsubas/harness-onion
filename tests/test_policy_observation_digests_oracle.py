"""Oracle tests for the I01 digest contract (DIGEST-CONTRACT), slot 258.

Owner decision D5a: a contract packet carries tests written outside the candidate.
These tests are black-box. Every expected value is derived from the contract text
(architecture/policy-observation-digests/README.md, sections 0 to 5 and 9), from
definitions.json, from the design note (revision 3) and from the recorded owner and
monitor decisions (Q-DIG-3/7 "Accept, check at T04", Q-DIG-1..18, R1-A..R1-C,
R2-A..R2-C, R3-A, R3-B), or computed here with hashlib.sha256 over canonical bytes
that this module builds itself, as README section 3.2 states. Every fixture (the
snapshot, the binding, the enrolled record and the capture verdicts) is the oracle's
own. None is taken from the candidate's vectors, tests, reviews or output, and no
model function body was read. The model is reached only through its public
functions: projection_document, projection_digest, projection, enforcement,
enforcement_digests, capture_gate, synthetic_uid, refusal_texts and definitions.
admissionPolicy's rendered objects and directory hash are computed with the three
admission v3 renderers that README section 4.1 names (a2_objects,
manifest_file_bytes, manifest_directory_hash; frozen, pinned by sha256 in
definitions.json), imported by the oracle under the slot author's ruling of
2026-10-22. Every refusal text asserted here is checked, verbatim, against
definitions.json's refusalTexts. Each test's docstring names the README section or
decision it checks.
"""

from __future__ import annotations

import copy
import hashlib
import json
import re
from pathlib import Path

import pytest

from scripts import policy_observation_digests as pod
from scripts.admission_semantics_v3 import a2_objects, manifest_directory_hash, manifest_file_bytes

ROOT = Path(__file__).resolve().parents[1]
CONTRACT_DIR = ROOT / "architecture" / "policy-observation-digests"


# --------------------------------------------------------------------------- helpers


def _no_duplicates(pairs):
    out = {}
    for key, value in pairs:
        if key in out:
            raise ValueError("duplicate member name in a contract file")
        out[key] = value
    return out


DEFINITIONS = json.loads(
    (CONTRACT_DIR / "definitions.json").read_text(encoding="utf-8"), object_pairs_hook=_no_duplicates
)
PINNED = frozenset(DEFINITIONS["refusalTexts"])


def canonical_bytes(value) -> bytes:
    """README 3.2: json.dumps(sort_keys, (",", ":") separators, ensure_ascii=False, allow_nan=False), UTF-8."""
    text = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False)
    return text.encode("utf-8")


def sha256_digest(value) -> str:
    """README 3.2: "sha256:" + hex(sha256(canonical(document)))."""
    return "sha256:" + hashlib.sha256(canonical_bytes(value)).hexdigest()


def synthetic(api_version, kind, name, namespace) -> str:
    """README 3.1 (uids): the lowercase hex sha256 of canonical({apiVersion, kind, name, namespace})."""
    identity = {"apiVersion": api_version, "kind": kind, "name": name, "namespace": namespace}
    return hashlib.sha256(canonical_bytes(identity)).hexdigest()


def refusal(fn, *args) -> str:
    with pytest.raises(pod.Refused) as caught:
        fn(*args)
    text = getattr(caught.value, "text", None)
    return str(caught.value) if text is None else text


def assert_refuses(expected, fn, *args):
    assert expected in PINNED, f"oracle error: {expected!r} is not in definitions.json refusalTexts"
    assert refusal(fn, *args) == expected


def refuses_doc(expected, key, snap, bound=None):
    assert_refuses(expected, pod.projection_document, key, snap, binding() if bound is None else bound)


def refuses_enf(expected, key, snap):
    assert_refuses(expected, pod.enforcement, key, snap)


def refuses_gate(expected, key, capture, record):
    assert_refuses(expected, pod.capture_gate, key, capture, record)


# --------------------------------------------------------------------------- constants (README 3, 4, 5, 9)

NS = "oracle-qual"
OTHER = "oracle-other"
RBAC_GROUP = "rbac.authorization.k8s.io"
CLUSTER = "CLUSTER"
MAX = 2**53 - 1
BOUND_MS = 90_000
DIGEST_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
UID_RE = re.compile(r"^[A-Za-z0-9-]{1,128}$")
BOGUS_A = "sha256:" + "0" * 64
BOGUS_B = "sha256:" + "f" * 64

T_RENDERED = "admissionPolicy: rendered hash differs"
T_ANNOTATION = "serviceAccount: enforce-mountable-secrets annotation"
T_SA_NAME = "serviceAccount: name differs from the binding"
T_SELECTOR = "networkPolicy: selector form outside v1"
T_AGGREGATED = "rbac: aggregated role reaches the namespace"
T_ROW = "mutationBroker: broker row incomplete"
T_NO_AGENT = "networkEnforcementDigest: no network policy agent"
T_HOST = "hostPreflightDigest: capture set not passed"

REAL = {
    "resourceQuota": ("v1", "ResourceQuota", "resourceQuotas"),
    "limitRange": ("v1", "LimitRange", "limitRanges"),
    "serviceAccount": ("v1", "ServiceAccount", "serviceAccounts"),
    "networkPolicy": ("networking.k8s.io/v1", "NetworkPolicy", "networkPolicies"),
}
SYNTHETIC = {
    "admissionPolicy": ("admissionregistration.k8s.io/v1", "ValidatingAdmissionPolicy", "admissionpolicy"),
    "rbac": ("planeon.internal/v1", "EffectiveRbac", "rbac"),
    "mutationBroker": ("planeon.internal/v1", "MutationBroker", "mutationbroker"),
}
SEVEN = ("admissionPolicy", "resourceQuota", "limitRange", "serviceAccount", "rbac", "networkPolicy", "mutationBroker")
BASE_NAMES = {
    "resourceQuota": "oracle-quota",
    "limitRange": "oracle-limits",
    "serviceAccount": "oracle-campaign",
    "networkPolicy": "oracle-default-deny",
}
COMPUTABLE = ("resourceQuota", "limitRange", "serviceAccount", "rbac", "networkPolicy", "mutationBroker")
SA_KEYS = ("automountServiceAccountToken", "imagePullSecrets", "secrets")
BROKER_MEMBERS = (
    "executable",
    "executableLabel",
    "artifactDigest",
    "interpreterPath",
    "interpreterLabel",
    "uid",
    "gid",
    "processLabel",
    "namespaceInodes",
    "cgroup",
    "seccompMode",
    "seccompDefaultAction",
    "seccompFilterDigest",
    "noNewPrivs",
    "rlimitCore",
    "capabilities",
    "filePaths",
    "bpfPrograms",
    "listenEndpointIds",
    "outboundEndpointIds",
)
CGROUP_MEMBERS = ("path", "inode", "memoryMaxBytes", "pidsMax", "cpuQuotaMicros", "cpuPeriodMicros", "selinuxLabel")
BROKER_DOCUMENT = (
    "executable",
    "executableLabel",
    "artifactDigest",
    "uid",
    "gid",
    "processLabel",
    "cgroup",
    "seccompMode",
    "seccompDefaultAction",
    "seccompFilterDigest",
    "noNewPrivs",
    "capabilities",
    "listenEndpointIds",
    "outboundEndpointIds",
)
AGENT = "NETWORK_POLICY_AGENT"
AGENT_MEMBERS = ("executable", "executableLabel", "artifactDigest", "processLabel", "apiIdentities")
ROLES = ("SERVER", "OBSERVER", "BROKER", "WORKER", "EFFECT_GATE")
BACKENDS = ("APISERVER", "DATASTORE", "CONTROLLER_MANAGER", "SCHEDULER", "KUBELET", "CONTAINER_RUNTIME", AGENT)
GATED = ("mutationBroker", "networkEnforcementDigest", "hostPreflightDigest")
OWN_TEXT = {
    "mutationBroker": "mutationBroker: broker capture not passed",
    "networkEnforcementDigest": "networkEnforcementDigest: agent capture not passed",
    "hostPreflightDigest": T_HOST,
}
REQUIRED = {
    "mutationBroker": ["role/BROKER"],
    "networkEnforcementDigest": ["backend/" + AGENT],
    "hostPreflightDigest": (
        ["role/" + name for name in ROLES] + ["lifecycle"] + ["backend/" + name for name in BACKENDS]
    ),
}


# --------------------------------------------------------------------------- the oracle's own fixtures


def U(n):
    return "0e0c0a1e-0000-4000-8000-%012d" % n


def md(name, namespace, n, rv, **extra):
    metadata = {"name": name, "uid": U(n), "resourceVersion": rv}
    if namespace is not None:
        metadata["namespace"] = namespace
    metadata.update(extra)
    return metadata


def quota(name="oracle-quota", namespace=NS, n=10, rv="201"):
    return {
        "metadata": md(name, namespace, n, rv),
        "spec": {"hard": {"pods": "10", "requests.cpu": "2", "requests.memory": "4Gi"}},
        "status": {"hard": {"pods": "10"}, "used": {"pods": "1"}},
    }


def limits(name="oracle-limits", namespace=NS, n=20, rv="301"):
    limit = {"type": "Container", "default": {"cpu": "500m", "memory": "256Mi"}, "max": {"cpu": "2", "memory": "1Gi"}}
    return {"metadata": md(name, namespace, n, rv), "spec": {"limits": [limit]}}


def account(name="oracle-campaign", namespace=NS, n=30, rv="401", **top):
    item = {"metadata": md(name, namespace, n, rv)}
    item.update(top)
    return item


def campaign_account():
    return account(automountServiceAccountToken=False, imagePullSecrets=[{"name": "oracle-pull"}])


def helper_account():
    return account("oracle-helper", n=31, rv="402", secrets=[{"name": "oracle-helper-token"}])


def default_deny():
    return {"podSelector": {}, "policyTypes": ["Ingress", "Egress"]}


def netpol(name="oracle-default-deny", namespace=NS, n=40, rv="501", spec=None):
    return {"metadata": md(name, namespace, n, rv), "spec": default_deny() if spec is None else spec}


def rule(groups, resources, verbs, names=()):
    return {"apiGroups": list(groups), "resources": list(resources), "verbs": list(verbs), "resourceNames": list(names)}


def nonresource(urls, verbs):
    return {"nonResourceURLs": list(urls), "verbs": list(verbs)}


def ref(kind, name):
    return {"apiGroup": RBAC_GROUP, "kind": kind, "name": name}


def sa_subject(name, namespace=None):
    subject = {"kind": "ServiceAccount", "name": name}
    if namespace is not None:
        subject["namespace"] = namespace
    return subject


def user(name):
    return {"kind": "User", "apiGroup": RBAC_GROUP, "name": name}


def group(name):
    return {"kind": "Group", "apiGroup": RBAC_GROUP, "name": name}


def role(name, namespace, n, rules):
    return {"metadata": md(name, namespace, n, str(600 + n)), "rules": copy.deepcopy(rules)}


def cluster_role(name, n, rules, **extra):
    item = {"metadata": md(name, None, n, str(700 + n)), "rules": copy.deepcopy(rules)}
    item.update(extra)
    return item


def role_binding(name, namespace, n, role_ref, subjects):
    return {"metadata": md(name, namespace, n, str(800 + n)), "roleRef": role_ref, "subjects": subjects}


def cluster_role_binding(name, n, role_ref, subjects):
    return {"metadata": md(name, None, n, str(900 + n)), "roleRef": role_ref, "subjects": subjects}


READER_RULE = rule([""], ["configmaps"], ["get", "list"])
WRITER_RULE = rule([""], ["secrets"], ["create"])
VIEW_RULE = rule(["apps"], ["deployments"], ["get", "watch"])
HEALTH_RULE = nonresource(["/healthz"], ["get"])
AGGREGATION = {"clusterRoleSelectors": [{"matchLabels": {"oracle/aggregate": "true"}}]}


def rbac_lists():
    campaign = sa_subject("oracle-campaign")
    return {
        "roles": [role("oracle-reader", NS, 50, [READER_RULE]), role("other-writer", OTHER, 51, [WRITER_RULE])],
        "roleBindings": [
            role_binding("oracle-reader-binding", NS, 70, ref("Role", "oracle-reader"), [campaign]),
            role_binding("oracle-view-binding", NS, 71, ref("ClusterRole", "oracle-view"), [group("oracle-auditors")]),
            role_binding(
                "other-writer-binding", OTHER, 72, ref("Role", "other-writer"), [sa_subject("oracle-campaign", NS)]
            ),
        ],
        "clusterRoles": [
            cluster_role("oracle-view", 60, [VIEW_RULE]),
            cluster_role("oracle-health", 61, [HEALTH_RULE]),
        ],
        "clusterRoleBindings": [
            cluster_role_binding(
                "oracle-health-binding", 80, ref("ClusterRole", "oracle-health"), [user("oracle-operator")]
            )
        ],
    }


def _slug(name):
    return name.lower().replace("_", "-")


def _sha(text):
    return "sha256:" + hashlib.sha256(text.encode("utf-8")).hexdigest()


def role_row(name, n):
    slug = _slug(name)
    return {
        "executable": "/oracle/bin/" + slug,
        "executableLabel": "system_u:object_r:oracle_%s_exec_t:s0" % name.lower(),
        "artifactDigest": _sha("artifact " + name),
        "interpreterPath": None,
        "interpreterLabel": None,
        "uid": 2000 + n,
        "gid": 2000 + n,
        "processLabel": "system_u:system_r:oracle_%s_t:s0" % name.lower(),
        "namespaceInodes": {"mnt": 4026532000 + 10 * n, "net": 4026532001 + 10 * n, "pid": 4026532002 + 10 * n},
        "cgroup": {
            "path": "/oracle.slice/%s.service" % slug,
            "inode": 7000 + n,
            "memoryMaxBytes": 268435456,
            "pidsMax": 64,
            "cpuQuotaMicros": 50000,
            "cpuPeriodMicros": 100000,
            "selinuxLabel": "system_u:object_r:oracle_cgroup_t:s0",
        },
        "seccompMode": "FILTER",
        "seccompDefaultAction": "KILL_PROCESS",
        "seccompFilterDigest": _sha("filter " + name),
        "noNewPrivs": True,
        "rlimitCore": 0,
        "capabilities": {"bounding": [], "effective": [], "permitted": []},
        "filePaths": ["/oracle/bin/" + slug],
        "bpfPrograms": [],
        "listenEndpointIds": [slug + "-listen"],
        "outboundEndpointIds": [slug + "-out"],
    }


def backend(name):
    slug = _slug(name)
    return {
        "executable": "/oracle/bin/" + slug,
        "executableLabel": "system_u:object_r:oracle_%s_exec_t:s0" % name.lower(),
        "artifactDigest": _sha("artifact " + name),
        "processLabel": "system_u:system_r:oracle_%s_t:s0" % name.lower(),
        "apiIdentities": ["system:serviceaccount:kube-system:oracle-" + slug],
        "cgroupPath": "/oracle.slice/%s.service" % slug,
        "filePaths": ["/oracle/bin/" + slug],
    }


def enrolled_record():
    return {
        "schemaVersion": "planeon.internal.native-qualification/v4",
        "roles": {name: role_row(name, n) for n, name in enumerate(ROLES, start=1)},
        "backendComponents": {name: backend(name) for name in BACKENDS},
        "backendProfile": {"componentKeys": list(BACKENDS)},
    }


def snapshot():
    psa = {"pod-security.kubernetes.io/enforce": "restricted", "team": "oracle"}
    lists = {
        "namespaces": [{"metadata": md(NS, None, 1, "11", labels=psa)}, {"metadata": md(OTHER, None, 2, "12")}],
        "resourceQuotas": [quota()],
        "limitRanges": [limits()],
        "serviceAccounts": [campaign_account(), helper_account()],
        "networkPolicies": [netpol()],
        "validatingAdmissionPolicies": [],
        "validatingAdmissionPolicyBindings": [],
    }
    lists.update(rbac_lists())
    sealed = {"ipFamily": "IPv4", "serviceCIDR": "10.96.0.0/12", "defaultTolerationSeconds": 300}
    return copy.deepcopy(
        {
            "resourceVersion": "4242",
            "lists": lists,
            "configuration": {"qualificationNamespace": NS, "pinnedManifestHash": BOGUS_A, "sealedAdmission": sealed},
            "adm4LoadedHash": BOGUS_A,
            "record": enrolled_record(),
        }
    )


def binding():
    return {
        "scope": {"serviceAccountSubject": "system:serviceaccount:%s:oracle-campaign" % NS},
        "projections": {
            "resourceQuota": {"name": "oracle-quota"},
            "limitRange": {"name": "oracle-limits"},
            "serviceAccount": {"name": "oracle-campaign"},
            "networkPolicy": {"name": "oracle-default-deny"},
        },
    }


def junk_binding():
    """A binding whose identity members are all wrong; the model must not read them (README 3.1, 3.5, 4.6)."""
    value = binding()
    wrong = {
        "apiVersion": "oracle.example/v0",
        "kind": "OracleWrong",
        "namespace": "oracle-wrong",
        "uid": "oracle-wrong-uid",
        "projectionDigest": BOGUS_B,
    }
    for key in SEVEN:
        value["projections"].setdefault(key, {}).update(copy.deepcopy(wrong))
    for key in SYNTHETIC:
        value["projections"][key]["name"] = "oracle-wrong"
    value["enforcementPins"] = {"mutationBrokerDigest": BOGUS_B, "hostPreflightDigest": BOGUS_B}
    return value


def base_item(snap, key):
    for item in snap["lists"][REAL[key][2]]:
        metadata = item["metadata"]
        if metadata.get("name") == BASE_NAMES[key] and metadata.get("namespace") == NS:
            return item
    raise KeyError(key)


def _named(snap, list_name, name):
    for item in snap["lists"][list_name]:
        if item["metadata"]["name"] == name:
            return item
    raise KeyError(name)


# --------------------------------------------------------------------------- the oracle's expected documents


def real_document(key, item):
    api_version, kind, _list = REAL[key]
    if key == "serviceAccount":
        spec = {name: copy.deepcopy(item[name]) for name in SA_KEYS if name in item}
    else:
        spec = copy.deepcopy(item["spec"])
    metadata = item["metadata"]
    return {
        "apiVersion": api_version,
        "kind": kind,
        "metadata": {"name": metadata["name"], "namespace": metadata["namespace"], "uid": metadata["uid"]},
        "spec": spec,
    }


def synthetic_document(key, namespace, spec):
    api_version, kind, name = SYNTHETIC[key]
    return {
        "apiVersion": api_version,
        "kind": kind,
        "metadata": {"name": name, "namespace": namespace, "uid": synthetic(api_version, kind, name, namespace)},
        "spec": spec,
    }


def scoped(value, scope):
    out = copy.deepcopy(value)
    out["scope"] = scope
    return out


def entry(kind, name, exists, rules):
    """README 4.5: {kind, name, exists, effectiveRules}, the rules sorted and deduplicated by canonical bytes."""
    unique = {canonical_bytes(item): item for item in rules}
    return {"kind": kind, "name": name, "exists": exists, "effectiveRules": [unique[key] for key in sorted(unique)]}


def sa_name(namespace, name):
    return "system:serviceaccount:%s:%s" % (namespace, name)


def base_subjects():
    return [
        entry("Group", "oracle-auditors", True, [scoped(VIEW_RULE, NS)]),
        entry("ServiceAccount", sa_name(NS, "oracle-campaign"), True, [scoped(READER_RULE, NS)]),
        entry("User", "oracle-operator", True, [scoped(HEALTH_RULE, CLUSTER)]),
    ]


def rbac_document(subjects):
    ordered = sorted(subjects, key=lambda item: (item["kind"], item["name"]))
    return synthetic_document("rbac", NS, {"subjects": ordered})


def broker_spec(row):
    spec = {name: copy.deepcopy(row[name]) for name in BROKER_DOCUMENT}
    spec["cgroup"] = {name: copy.deepcopy(value) for name, value in row["cgroup"].items() if name != "inode"}
    return spec


def expected_document(key, snap):
    if key in REAL:
        return real_document(key, base_item(snap, key))
    if key == "rbac":
        return rbac_document(base_subjects())
    if key == "mutationBroker":
        return synthetic_document("mutationBroker", NS, broker_spec(snap["record"]["roles"]["BROKER"]))
    raise KeyError(key)


def network_document(snap):
    agent = snap["record"]["backendComponents"][AGENT]
    return {
        "networkPolicies": [real_document("networkPolicy", base_item(snap, "networkPolicy"))],
        "agent": {name: copy.deepcopy(agent[name]) for name in AGENT_MEMBERS},
    }


def document(key, snap, bound=None):
    return pod.projection_document(key, snap, binding() if bound is None else bound)


def doc_digest(key, snap):
    return pod.projection_digest(document(key, snap))


def enf_digest(key, snap):
    return pod.enforcement(key, snap)["digest"]


# =========================================================================== 1. canonical bytes and digests


def test_projection_digest_hashes_the_readme_canonical_bytes():
    """README 3.2 (canonical bytes, the digest): sorted keys, (",", ":") separators, raw UTF-8, "sha256:" + hex."""
    value = {
        "spec": {"b": [1, True, None], "a": "ç\U0001F600"},
        "kind": "K",
        "apiVersion": "v1",
        "metadata": {"uid": "u", "namespace": None, "name": "n"},
    }
    literal = (
        '{"apiVersion":"v1","kind":"K","metadata":{"name":"n","namespace":null,"uid":"u"},'
        '"spec":{"a":"ç\U0001F600","b":[1,true,null]}}'
    ).encode("utf-8")
    assert canonical_bytes(value) == literal
    assert pod.projection_digest(value) == "sha256:" + hashlib.sha256(literal).hexdigest()


def test_projection_digest_keeps_json_escapes():
    """README 3.2: json.dumps with ensure_ascii=False escapes quotes, backslashes and control characters only."""
    value = {"q": 'say "hi"\n\t\\ \u0001 ü'}
    literal = b'{"q":"say \\"hi\\"\\n\\t\\\\ \\u0001 \xc3\xbc"}'
    assert pod.projection_digest(value) == "sha256:" + hashlib.sha256(literal).hexdigest()


def test_key_order_does_not_change_the_digest():
    """README 3.2: canonical bytes sort keys, so insertion order never changes a digest."""
    first = {"a": 1, "b": {"c": 2, "d": [3, {"e": 4, "f": 5}]}}
    second = {"b": {"d": [3, {"f": 5, "e": 4}], "c": 2}, "a": 1}
    assert pod.projection_digest(first) == pod.projection_digest(second) == sha256_digest(first)


def test_served_key_order_does_not_change_a_projection_digest():
    """README 3.2: a served object whose members arrive in another order gives the same projection digest."""
    reordered = snapshot()
    item = base_item(reordered, "resourceQuota")
    item["spec"]["hard"] = dict(reversed(list(item["spec"]["hard"].items())))
    item["metadata"] = dict(reversed(list(item["metadata"].items())))
    assert doc_digest("resourceQuota", reordered) == doc_digest("resourceQuota", snapshot())


def test_list_order_is_served_order():
    """README 3.2 (sorted sets): lists outside the named sets keep served order, so reordering one changes it."""
    reordered = snapshot()
    base_item(reordered, "networkPolicy")["spec"]["policyTypes"] = ["Egress", "Ingress"]
    assert document("networkPolicy", reordered)["spec"]["policyTypes"] == ["Egress", "Ingress"]
    assert doc_digest("networkPolicy", reordered) != doc_digest("networkPolicy", snapshot())


@pytest.mark.parametrize("key", COMPUTABLE)
def test_every_projection_digest_has_the_wire_form(key):
    """README 3.2: the digest matches ^sha256:[0-9a-f]{64}$ and equals the oracle's own computation."""
    digest = doc_digest(key, snapshot())
    assert DIGEST_RE.match(digest)
    assert digest == sha256_digest(expected_document(key, snapshot()))


@pytest.mark.parametrize("key", ["resourceQuota", "limitRange"])
def test_a_float_refuses(key):
    """README 3.2 (exact values): a float refuses with "<key>: float refused"."""
    snap = snapshot()
    base_item(snap, key)["spec"]["oracleFloat"] = 1.5
    refuses_doc(key + ": float refused", key, snap)


@pytest.mark.parametrize("value", [MAX + 1, -(MAX + 1), 2**64], ids=["2^53", "-2^53", "2^64"])
@pytest.mark.parametrize("key", ["resourceQuota", "limitRange"])
def test_an_integer_beyond_the_bound_refuses(key, value):
    """README 3.2: VPC's magnitude rule abs(value) <= 2^53 - 1; beyond it, "<key>: integer out of range"."""
    snap = snapshot()
    base_item(snap, key)["spec"]["oracleInteger"] = value
    refuses_doc(key + ": integer out of range", key, snap)


@pytest.mark.parametrize("value", [MAX, -MAX, -1, 0], ids=["2^53-1", "-(2^53-1)", "-1", "0"])
@pytest.mark.parametrize("key", ["resourceQuota", "limitRange"])
def test_an_integer_within_the_bound_is_accepted(key, value):
    """README 3.2 and decision D2-7 (design rev 3): a negative integer within the bound is accepted."""
    snap = snapshot()
    base_item(snap, key)["spec"]["oracleInteger"] = value
    got = document(key, snap)
    assert got["spec"]["oracleInteger"] == value
    assert got == real_document(key, base_item(snap, key))


@pytest.mark.parametrize("key", ["resourceQuota", "limitRange"])
def test_a_document_deeper_than_the_bound_refuses(key):
    """README 3.2: any other refusal of VPC's _bounded (depth at most 16) is "<key>: document bound exceeded"."""
    snap = snapshot()
    deep = "leaf"
    for _ in range(40):
        deep = {"n": deep}
    base_item(snap, key)["spec"]["oracleDeep"] = deep
    refuses_doc(key + ": document bound exceeded", key, snap)


# =========================================================================== 2. the seven projections


@pytest.mark.parametrize("key", list(REAL))
def test_real_projection_document(key):
    """README 3.1 and 4 (table): {apiVersion, kind, metadata: {name, namespace, uid}, spec}; the contract's
    apiVersion and kind, the live object's name, namespace and uid."""
    got = document(key, snapshot())
    assert got == real_document(key, base_item(snapshot(), key))
    assert sorted(got) == ["apiVersion", "kind", "metadata", "spec"]
    assert sorted(got["metadata"]) == ["name", "namespace", "uid"]
    assert (got["apiVersion"], got["kind"]) == REAL[key][:2]


@pytest.mark.parametrize("key", list(REAL))
def test_served_apiversion_and_kind_are_never_used(key):
    """README 3.1 (the identity is the contract's): apiVersion and kind are never taken from a served item."""
    snap = snapshot()
    item = base_item(snap, key)
    item["apiVersion"] = "oracle.example/v9"
    item["kind"] = "OracleKind"
    assert document(key, snap) == real_document(key, base_item(snapshot(), key))


def _set_meta(member, value):
    def mutate(item):
        item["metadata"][member] = copy.deepcopy(value)

    return mutate


def _set_top(member, value):
    def mutate(item):
        item[member] = copy.deepcopy(value)

    return mutate


OWNER = [{"apiVersion": "v1", "kind": "ConfigMap", "name": "oracle-owner", "uid": U(99)}]
VOLATILE = [
    ("resourceVersion", _set_meta("resourceVersion", "987654")),
    ("managedFields", _set_meta("managedFields", [{"manager": "oracle", "operation": "Update", "apiVersion": "v1"}])),
    ("generation", _set_meta("generation", 9)),
    ("creationTimestamp", _set_meta("creationTimestamp", "2026-10-22T00:00:00Z")),
    ("labels", _set_meta("labels", {"oracle/relabelled": "yes"})),
    ("annotations", _set_meta("annotations", {"oracle/note": "changed"})),
    ("ownerReferences", _set_meta("ownerReferences", OWNER)),
    ("status", _set_top("status", {"oracle": "changed"})),
]
VOLATILE_IDS = [name for name, _ in VOLATILE]


@pytest.mark.parametrize("name,mutate", VOLATILE, ids=VOLATILE_IDS)
@pytest.mark.parametrize("key", list(REAL))
def test_volatile_fields_do_not_change_a_real_digest(key, name, mutate):
    """README 3.1: no status, resourceVersion, managedFields, generation, creationTimestamp, labels, annotations or
    ownerReferences enters a document."""
    snap = snapshot()
    mutate(base_item(snap, key))
    assert document(key, snap) == expected_document(key, snapshot())


@pytest.mark.parametrize("name,mutate", VOLATILE, ids=VOLATILE_IDS)
def test_volatile_fields_of_rbac_objects_do_not_change_rbac(name, mutate):
    """README 3.1 and 4.5: the EffectiveRbac document holds only subjects and rules, never object metadata."""
    snap = snapshot()
    for list_name in ("roles", "roleBindings", "clusterRoles", "clusterRoleBindings", "serviceAccounts"):
        for item in snap["lists"][list_name]:
            mutate(item)
    assert document("rbac", snap) == rbac_document(base_subjects())


@pytest.mark.parametrize("key", COMPUTABLE)
def test_the_read_resource_version_does_not_change_a_digest(key):
    """README 3.1 and 3.3: the read's resourceVersion never enters a document."""
    snap = snapshot()
    snap["resourceVersion"] = "999999"
    assert doc_digest(key, snap) == doc_digest(key, snapshot())


def change_spec(key, snap):
    if key == "resourceQuota":
        base_item(snap, key)["spec"]["hard"]["pods"] = "11"
    elif key == "limitRange":
        base_item(snap, key)["spec"]["limits"][0]["max"]["cpu"] = "3"
    elif key == "serviceAccount":
        base_item(snap, key)["automountServiceAccountToken"] = True
    elif key == "networkPolicy":
        base_item(snap, key)["spec"]["policyTypes"] = ["Ingress"]
    elif key == "rbac":
        _named(snap, "roles", "oracle-reader")["rules"][0]["verbs"].append("watch")
    elif key == "mutationBroker":
        snap["record"]["roles"]["BROKER"]["executable"] = "/oracle/bin/broker-v2"


@pytest.mark.parametrize("key", COMPUTABLE)
def test_a_spec_change_changes_the_digest(key):
    """README 3.1 and 4: the document's spec is enforcement content, so a change to it changes the digest."""
    snap = snapshot()
    change_spec(key, snap)
    assert doc_digest(key, snap) != doc_digest(key, snapshot())


@pytest.mark.parametrize("key", COMPUTABLE)
def test_no_identity_member_is_read_from_the_binding(key):
    """README 3.1 ("No identity member is ever read from the binding"), 3.5 and 4.6 (never the broker binding)."""
    assert document(key, snapshot(), junk_binding()) == expected_document(key, snapshot())


RESOURCE_VERSIONS = [
    ("resourceQuota", "201"),
    ("limitRange", "301"),
    ("serviceAccount", "401"),
    ("networkPolicy", "501"),
    ("rbac", "4242"),
    ("mutationBroker", "4242"),
]


@pytest.mark.parametrize("key,rv", RESOURCE_VERSIONS)
def test_projection_resource_version_and_identity(key, rv):
    """README 3.1 (resourceVersion) and 3.5: a real projection's resourceVersion is the object's own and a synthetic
    one's is the read's; the identity is {apiVersion, kind, name, namespace, uid, projectionDigest}."""
    result = pod.projection(key, snapshot(), binding())
    got = result["document"]
    assert got == expected_document(key, snapshot())
    assert result["resourceVersion"] == rv
    assert result["identity"] == {
        "apiVersion": got["apiVersion"],
        "kind": got["kind"],
        "name": got["metadata"]["name"],
        "namespace": got["metadata"]["namespace"],
        "uid": got["metadata"]["uid"],
        "projectionDigest": sha256_digest(got),
    }


@pytest.mark.parametrize("key", list(SYNTHETIC))
def test_synthetic_uid(key):
    """README 3.1 (uids): the lowercase hex sha256 of canonical({apiVersion, kind, name, namespace}), 64 characters
    fitting ^[A-Za-z0-9-]{1,128}$; namespace null for admissionPolicy, the qualification namespace otherwise."""
    api_version, kind, name = SYNTHETIC[key]
    namespace = None if key == "admissionPolicy" else NS
    uid = pod.synthetic_uid(api_version, kind, name, namespace)
    assert uid == synthetic(api_version, kind, name, namespace)
    assert len(uid) == 64 and UID_RE.match(uid) and uid == uid.lower()


@pytest.mark.parametrize("key", ["rbac", "mutationBroker"])
def test_synthetic_projection_identity(key):
    """README 3.1 and 4 (table): the synthetic keys' fixed identities and derived uids."""
    got = document(key, snapshot())
    api_version, kind, name = SYNTHETIC[key]
    assert sorted(got) == ["apiVersion", "kind", "metadata", "spec"]
    assert got["apiVersion"] == api_version and got["kind"] == kind
    assert got["metadata"] == {"name": name, "namespace": NS, "uid": synthetic(api_version, kind, name, NS)}


@pytest.mark.parametrize("key", SEVEN)
def test_a_missing_qualification_namespace_is_malformed(key):
    """README 3.4: a missing configuration value refuses "<key>: malformed input"."""
    snap = snapshot()
    del snap["configuration"]["qualificationNamespace"]
    refuses_doc(key + ": malformed input", key, snap)


@pytest.mark.parametrize("member", ["name", "namespace", "uid"])
@pytest.mark.parametrize("key", list(REAL))
def test_a_served_object_without_its_metadata_members_is_malformed(key, member):
    """README 3.4: a served object without its metadata members refuses "<key>: malformed input"."""
    snap = snapshot()
    del base_item(snap, key)["metadata"][member]
    refuses_doc(key + ": malformed input", key, snap)


ONE_OBJECT = {
    "resourceQuota": ("resourceQuotas", quota),
    "limitRange": ("limitRanges", limits),
    "networkPolicy": ("networkPolicies", netpol),
}


@pytest.mark.parametrize("key", list(ONE_OBJECT))
def test_no_object_refuses_count(key):
    """README 4.2: the count of the kind's objects in the qualification namespace is exactly 1."""
    snap = snapshot()
    snap["lists"][ONE_OBJECT[key][0]] = []
    refuses_doc(key + ": count is not one", key, snap)


@pytest.mark.parametrize("key", list(ONE_OBJECT))
def test_two_objects_refuse_count(key):
    """README 4.2 and decision Q-CB-15: two objects of a one-object kind in the namespace refuse."""
    snap = snapshot()
    list_name, make = ONE_OBJECT[key]
    snap["lists"][list_name].append(make(name="oracle-second", n=98, rv="998"))
    refuses_doc(key + ": count is not one", key, snap)


@pytest.mark.parametrize("key", list(ONE_OBJECT))
def test_another_name_refuses_name(key):
    """README 4.2: that object's name equals the name the binding gives."""
    snap = snapshot()
    base_item(snap, key)["metadata"]["name"] = "oracle-renamed"
    refuses_doc(key + ": name differs from the binding", key, snap)


@pytest.mark.parametrize("key", list(ONE_OBJECT))
def test_count_is_checked_before_name(key):
    """README 4.2 and definitions.json order (count, then name)."""
    snap = snapshot()
    list_name, make = ONE_OBJECT[key]
    snap["lists"][list_name] = [make(name="oracle-a", n=95, rv="995"), make(name="oracle-b", n=96, rv="996")]
    bound = binding()
    bound["projections"][key]["name"] = "oracle-nobody"
    refuses_doc(key + ": count is not one", key, snap, bound)
    snap["lists"][list_name] = []
    refuses_doc(key + ": count is not one", key, snap, bound)


@pytest.mark.parametrize("key", list(ONE_OBJECT))
def test_objects_in_other_namespaces_do_not_count(key):
    """README 4.2: only objects in the qualification namespace count."""
    snap = snapshot()
    list_name, make = ONE_OBJECT[key]
    snap["lists"][list_name].append(make(name="oracle-elsewhere", namespace=OTHER, n=97, rv="997"))
    assert document(key, snap) == expected_document(key, snapshot())


def test_service_account_spec_holds_only_the_three_top_level_keys():
    """README 3.1 (kinds without spec) and 4.3: automountServiceAccountToken, imagePullSecrets and secrets; an absent
    key is absent, never null; no other top-level member enters."""
    snap = snapshot()
    item = base_item(snap, "serviceAccount")
    item["apiVersion"] = "v1"
    item["kind"] = "ServiceAccount"
    item["oracleExtra"] = {"x": 1}
    got = document("serviceAccount", snap)
    assert got["spec"] == {"automountServiceAccountToken": False, "imagePullSecrets": [{"name": "oracle-pull"}]}
    assert "secrets" not in got["spec"]


def test_service_account_spec_carries_secrets_when_served():
    """README 3.1: each of the three keys is the served top-level member when present."""
    snap = snapshot()
    base_item(snap, "serviceAccount")["secrets"] = [{"name": "oracle-token"}]
    assert document("serviceAccount", snap)["spec"] == {
        "automountServiceAccountToken": False,
        "imagePullSecrets": [{"name": "oracle-pull"}],
        "secrets": [{"name": "oracle-token"}],
    }


def test_service_account_count_is_by_the_subject_name():
    """README 4.3: the count of objects by the subject's name in the qualification namespace is exactly 1."""
    snap = snapshot()
    snap["lists"]["serviceAccounts"] = [helper_account()]
    refuses_doc("serviceAccount: count is not one", "serviceAccount", snap)
    snap = snapshot()
    snap["lists"]["serviceAccounts"].append(account(n=94, rv="994"))
    refuses_doc("serviceAccount: count is not one", "serviceAccount", snap)


def test_a_same_named_service_account_elsewhere_does_not_count():
    """README 4.3: the subject names one object in the qualification namespace."""
    snap = snapshot()
    snap["lists"]["serviceAccounts"].append(account(namespace=OTHER, n=93, rv="993"))
    assert document("serviceAccount", snap) == expected_document("serviceAccount", snapshot())


def test_service_account_name_must_be_the_binding_name():
    """README 4.3: the name equals the binding's, else "serviceAccount: name differs from the binding"."""
    bound = binding()
    bound["projections"]["serviceAccount"]["name"] = "oracle-helper"
    refuses_doc(T_SA_NAME, "serviceAccount", snapshot(), bound)


def test_enforce_mountable_secrets_annotation_refuses():
    """README 3.1 and 4.3 (decision D1-13): the kubernetes.io/enforce-mountable-secrets annotation refuses."""
    snap = snapshot()
    base_item(snap, "serviceAccount")["metadata"]["annotations"] = {"kubernetes.io/enforce-mountable-secrets": "true"}
    refuses_doc(T_ANNOTATION, "serviceAccount", snap)


def test_the_annotation_on_another_account_does_not_refuse():
    """README 4.3: only the subject's ServiceAccount is the projection."""
    snap = snapshot()
    helper = _named(snap, "serviceAccounts", "oracle-helper")
    helper["metadata"]["annotations"] = {"kubernetes.io/enforce-mountable-secrets": "true"}
    assert document("serviceAccount", snap) == expected_document("serviceAccount", snapshot())


def test_service_account_name_is_checked_before_the_annotation():
    """definitions.json serviceAccount order: shape, count by name, name, annotation, document exactness."""
    snap = snapshot()
    base_item(snap, "serviceAccount")["metadata"]["annotations"] = {"kubernetes.io/enforce-mountable-secrets": "true"}
    bound = binding()
    bound["projections"]["serviceAccount"]["name"] = "oracle-helper"
    refuses_doc(T_SA_NAME, "serviceAccount", snap, bound)


# =========================================================================== 3. admissionPolicy, admissionFenceDigest


def test_definitions_fix_the_admission_policy_identity():
    """README 4 (table) and 4.1: admissionregistration.k8s.io/v1 ValidatingAdmissionPolicy admissionpolicy, namespace
    null, uid derived."""
    assert DEFINITIONS["projections"]["admissionPolicy"]["identity"] == {
        "apiVersion": "admissionregistration.k8s.io/v1",
        "kind": "ValidatingAdmissionPolicy",
        "name": "admissionpolicy",
        "namespace": None,
        "uid": "DERIVED",
    }


def test_a_pin_that_is_not_the_rendered_hash_refuses():
    """README 4.1: the recomputed hash must equal the signed pinnedManifestHash and ADM-4's loaded hash; a pin and a
    loaded hash that agree with each other but not with the rendering refuse."""
    refuses_doc(T_RENDERED, "admissionPolicy", snapshot())


def test_a_pin_and_loaded_hash_that_differ_refuse():
    """README 4.1: the rendered hash must equal both values; two different values cannot both equal it."""
    snap = snapshot()
    snap["adm4LoadedHash"] = BOGUS_B
    refuses_doc(T_RENDERED, "admissionPolicy", snap)


@pytest.mark.parametrize(
    "value,text",
    [(300.0, "float refused"), (MAX + 1, "integer out of range"), (-(MAX + 1), "integer out of range")],
    ids=["float", "2^53", "-2^53"],
)
def test_sealed_value_exactness_comes_before_the_rendered_hash(value, text):
    """README 4.1 (exact values) and definitions.json order (sealed values: exactness and shape, then rendered hash)."""
    snap = snapshot()
    snap["configuration"]["sealedAdmission"]["defaultTolerationSeconds"] = value
    refuses_doc("admissionPolicy: " + text, "admissionPolicy", snap)


def test_a_negative_sealed_integer_within_the_bound_passes_exactness():
    """README 3.2 and 4.1: a negative integer within the bound is accepted, so the next step (the hash) decides."""
    snap = snapshot()
    snap["configuration"]["sealedAdmission"]["defaultTolerationSeconds"] = -MAX
    refuses_doc(T_RENDERED, "admissionPolicy", snap)


@pytest.mark.parametrize("member", ["ipFamily", "serviceCIDR", "defaultTolerationSeconds"])
def test_a_missing_sealed_value_is_malformed(member):
    """README 3.4 and 4.1: a missing configuration value refuses "admissionPolicy: malformed input"."""
    snap = snapshot()
    del snap["configuration"]["sealedAdmission"][member]
    refuses_doc("admissionPolicy: malformed input", "admissionPolicy", snap)


def test_a_missing_pinned_manifest_hash_is_malformed():
    """README 3.4: a missing configuration value refuses "admissionPolicy: malformed input"."""
    snap = snapshot()
    del snap["configuration"]["pinnedManifestHash"]
    refuses_doc("admissionPolicy: malformed input", "admissionPolicy", snap)


def test_the_rendered_hash_is_checked_before_objects_and_namespace():
    """definitions.json admissionPolicy order: rendered hash, then unknown admission objects, then the Namespace."""
    snap = snapshot()
    unknown = {"metadata": md("oracle-unknown-policy", None, 90, "1001"), "spec": {}}
    snap["lists"]["validatingAdmissionPolicies"] = [unknown]
    snap["lists"]["namespaces"] = []
    refuses_doc(T_RENDERED, "admissionPolicy", snap)


def test_admission_fence_digest_needs_the_rendered_hash():
    """README 5.1: it exists only after section 4.1's two equalities hold, else "admissionPolicy: rendered hash
    differs"."""
    refuses_enf(T_RENDERED, "admissionFenceDigest", snapshot())


def test_admission_fence_digest_exactness():
    """README 3.2 and definitions.json admissionFenceDigest refusals: a float sealed value refuses with its own key."""
    snap = snapshot()
    snap["configuration"]["sealedAdmission"]["defaultTolerationSeconds"] = 300.5
    refuses_enf("admissionFenceDigest: float refused", "admissionFenceDigest", snap)


@pytest.mark.parametrize("member", ["qualificationNamespace", "pinnedManifestHash"])
def test_admission_fence_digest_malformed(member):
    """README 3.4 and definitions.json admissionFenceDigest refusals: a missing configuration value is malformed."""
    snap = snapshot()
    del snap["configuration"][member]
    refuses_enf("admissionFenceDigest: malformed input", "admissionFenceDigest", snap)


def test_enforcement_digests_raise_the_first_refusal_in_order():
    """README 5 and the model's docstring: the four digests in order (admissionFenceDigest first); the first refusal
    is raised."""
    assert_refuses(T_RENDERED, pod.enforcement_digests, snapshot())


T_UNKNOWN = "admissionPolicy: unknown admission object"
T_NOT_LISTED = "admissionPolicy: qualification namespace not listed"
PSA_BASE = {"pod-security.kubernetes.io/enforce": "restricted"}
VAP = "ValidatingAdmissionPolicy"
VAPB = "ValidatingAdmissionPolicyBinding"


def sealed_values(snap):
    """README 4.1: the four sealed values a2_objects reads; namespace is the configured qualification namespace."""
    configuration = snap["configuration"]
    sealed = configuration["sealedAdmission"]
    return {
        "namespace": configuration["qualificationNamespace"],
        "ipFamily": sealed["ipFamily"],
        "serviceCIDR": sealed["serviceCIDR"],
        "defaultTolerationSeconds": sealed["defaultTolerationSeconds"],
    }


def rendered_objects(snap):
    return copy.deepcopy(a2_objects(sealed_values(snap)))


def rendered_hash(snap):
    """README 4.1: manifest_directory_hash({"planeon-a2.json": manifest_file_bytes(...)})."""
    return manifest_directory_hash({"planeon-a2.json": manifest_file_bytes(sealed_values(snap))})


def sealed_snapshot(**changes):
    """A snapshot whose signed pin and ADM-4 loaded hash both equal the rendered hash (README 4.1)."""
    snap = snapshot()
    snap["configuration"]["sealedAdmission"].update(changes)
    rendered = rendered_hash(snap)
    snap["configuration"]["pinnedManifestHash"] = rendered
    snap["adm4LoadedHash"] = rendered
    return snap


def expected_admission(snap, labels):
    """README 4.1 (the document): sealedObjects sorted by (kind, metadata.name), and podSecurityLabels."""
    objects = sorted(rendered_objects(snap), key=lambda item: (item["kind"], item["metadata"]["name"]))
    return synthetic_document("admissionPolicy", None, {"sealedObjects": objects, "podSecurityLabels": labels})


def rendered_names(snap, kind):
    return [item["metadata"]["name"] for item in rendered_objects(snap) if item["kind"] == kind]


def listed(name, n, spec=None):
    return {"metadata": md(name, None, n, str(1100 + n)), "spec": {} if spec is None else spec}


def _qualification_namespace(snap):
    return [item for item in snap["lists"]["namespaces"] if item["metadata"]["name"] == NS][0]


def test_the_rendering_has_eight_objects_and_a_digest_hash():
    """README 4.1 and 5.1: eight rendered objects, four policies and four bindings; the directory hash is already in
    sha256:<hex> form."""
    snap = sealed_snapshot()
    kinds = [item["kind"] for item in rendered_objects(snap)]
    assert sorted(kinds) == [VAP] * 4 + [VAPB] * 4
    assert DIGEST_RE.match(rendered_hash(snap))


def test_admission_policy_document():
    """README 3.1, 4 (table) and 4.1: {apiVersion, kind, metadata: {name: admissionpolicy, namespace: null, uid},
    spec: {sealedObjects, podSecurityLabels}}, the eight rendered objects sorted by (kind, metadata.name) and the
    qualification Namespace's pod-security.kubernetes.io/ labels only."""
    snap = sealed_snapshot()
    got = document("admissionPolicy", snap)
    assert got == expected_admission(snap, PSA_BASE)
    assert sorted(got) == ["apiVersion", "kind", "metadata", "spec"]
    assert sorted(got["spec"]) == ["podSecurityLabels", "sealedObjects"]
    assert got["metadata"]["namespace"] is None
    assert got["metadata"]["uid"] == synthetic(*SYNTHETIC["admissionPolicy"], None)
    order = [(item["kind"], item["metadata"]["name"]) for item in got["spec"]["sealedObjects"]]
    assert order == sorted(order) and len(order) == 8


def test_admission_policy_resource_version_and_identity():
    """README 3.1 (resourceVersion) and 3.5: a synthetic projection's resourceVersion is the read's; the identity is
    {apiVersion, kind, name, namespace, uid, projectionDigest}."""
    snap = sealed_snapshot()
    result = pod.projection("admissionPolicy", snap, binding())
    got = result["document"]
    assert got == expected_admission(snap, PSA_BASE)
    assert result["resourceVersion"] == "4242"
    assert result["identity"] == {
        "apiVersion": "admissionregistration.k8s.io/v1",
        "kind": VAP,
        "name": "admissionpolicy",
        "namespace": None,
        "uid": got["metadata"]["uid"],
        "projectionDigest": sha256_digest(got),
    }


def test_admission_policy_identity_is_not_read_from_the_binding():
    """README 3.1 and 3.5: no identity member is read from the binding."""
    snap = sealed_snapshot()
    assert document("admissionPolicy", snap, junk_binding()) == expected_admission(snap, PSA_BASE)


def test_admission_fence_digest_is_the_rendered_hash():
    """README 5.1: the manifest_directory_hash of section 4.1 over the rendered bytes, in sha256:<hex> form."""
    snap = sealed_snapshot()
    assert enf_digest("admissionFenceDigest", snap) == rendered_hash(snap)


@pytest.mark.parametrize("member", ["pinnedManifestHash", "adm4LoadedHash"])
def test_the_rendered_hash_must_equal_both_values(member):
    """README 4.1 and 5.1: the recomputed hash must equal both the signed pin and ADM-4's loaded hash; one of them
    differing refuses both admissionPolicy and admissionFenceDigest."""
    snap = sealed_snapshot()
    if member == "pinnedManifestHash":
        snap["configuration"]["pinnedManifestHash"] = BOGUS_A
    else:
        snap["adm4LoadedHash"] = BOGUS_A
    refuses_doc(T_RENDERED, "admissionPolicy", snap)
    refuses_enf(T_RENDERED, "admissionFenceDigest", snap)


def test_a_sealed_value_change_needs_new_pins_and_changes_the_document():
    """README 4.1 and 6: the document is the rendering of the signed sealed values; the old pins refuse the new
    values, and new pins give the new rendering."""
    base = sealed_snapshot()
    changed = sealed_snapshot(serviceCIDR="10.100.0.0/16")
    assert rendered_hash(changed) != rendered_hash(base)
    stale = copy.deepcopy(changed)
    stale["configuration"]["pinnedManifestHash"] = rendered_hash(base)
    stale["adm4LoadedHash"] = rendered_hash(base)
    refuses_doc(T_RENDERED, "admissionPolicy", stale)
    assert document("admissionPolicy", changed) == expected_admission(changed, PSA_BASE)
    assert doc_digest("admissionPolicy", changed) != doc_digest("admissionPolicy", base)


def test_pod_security_labels_are_empty_when_there_are_none():
    """README 4.1 (decision R1-C): {} when the qualification Namespace has no pod-security.kubernetes.io/ label."""
    snap = sealed_snapshot()
    _qualification_namespace(snap)["metadata"]["labels"] = {"team": "oracle"}
    assert document("admissionPolicy", snap) == expected_admission(snap, {})
    del _qualification_namespace(snap)["metadata"]["labels"]
    assert document("admissionPolicy", snap) == expected_admission(snap, {})


def test_pod_security_labels_carry_every_prefixed_label():
    """README 4.1: the labels whose key starts with pod-security.kubernetes.io/, as an object; others stay out."""
    snap = sealed_snapshot()
    _qualification_namespace(snap)["metadata"]["labels"] = {
        "pod-security.kubernetes.io/enforce": "baseline",
        "pod-security.kubernetes.io/warn": "restricted",
        "oracle.pod-security.kubernetes.io/enforce": "privileged",
        "pod-security.kubernetes.io": "restricted",
        "team": "oracle",
    }
    expected = {"pod-security.kubernetes.io/enforce": "baseline", "pod-security.kubernetes.io/warn": "restricted"}
    assert document("admissionPolicy", snap) == expected_admission(snap, expected)


def test_a_pod_security_label_change_changes_the_digest():
    """README 4.1 (decision R1-C) and design rev 3 section 9: a changed pod-security.kubernetes.io/enforce label
    changes admissionPolicy's digest."""
    snap = sealed_snapshot()
    _qualification_namespace(snap)["metadata"]["labels"]["pod-security.kubernetes.io/enforce"] = "privileged"
    assert doc_digest("admissionPolicy", snap) != doc_digest("admissionPolicy", sealed_snapshot())


def test_other_labels_and_namespaces_do_not_change_the_digest():
    """README 3.1 and 4.1: other labels, the Namespace's metadata and other namespaces' Pod Security labels are
    outside the document."""
    snap = sealed_snapshot()
    qualification = _qualification_namespace(snap)
    qualification["metadata"]["labels"]["team"] = "changed"
    qualification["metadata"]["resourceVersion"] = "987654"
    qualification["metadata"]["annotations"] = {"oracle/note": "changed"}
    other = [item for item in snap["lists"]["namespaces"] if item["metadata"]["name"] == OTHER][0]
    other["metadata"]["labels"] = {"pod-security.kubernetes.io/enforce": "privileged"}
    snap["resourceVersion"] = "999999"
    assert doc_digest("admissionPolicy", snap) == doc_digest("admissionPolicy", sealed_snapshot())


def test_listed_objects_with_rendered_kind_and_name_are_admitted():
    """README 4.1 (unknown admission objects, R-ADM-LIST): every listed policy carrying a rendered policy name and
    every listed binding a rendered binding name is admitted, and is not compared with the rendered object."""
    snap = sealed_snapshot()
    other_spec = {"oracle": "not the rendered spec"}
    snap["lists"]["validatingAdmissionPolicies"] = [
        listed(name, 120 + n, spec=other_spec) for n, name in enumerate(rendered_names(snap, VAP))
    ]
    snap["lists"]["validatingAdmissionPolicyBindings"] = [
        listed(name, 130 + n) for n, name in enumerate(rendered_names(snap, VAPB))
    ]
    assert document("admissionPolicy", snap) == expected_admission(snap, PSA_BASE)
    assert enf_digest("admissionFenceDigest", snap) == rendered_hash(snap)


def _unknown_policy(snap):
    snap["lists"]["validatingAdmissionPolicies"] = [listed("oracle-unknown-policy", 140)]


def _unknown_binding(snap):
    snap["lists"]["validatingAdmissionPolicyBindings"] = [listed("oracle-unknown-binding", 141)]


def _policy_with_a_binding_name(snap):
    snap["lists"]["validatingAdmissionPolicies"] = [listed(rendered_names(snap, VAPB)[0], 142)]


def _binding_with_a_policy_name(snap):
    snap["lists"]["validatingAdmissionPolicyBindings"] = [listed(rendered_names(snap, VAP)[0], 143)]


def _static_suffix_not_rendered(snap):
    snap["lists"]["validatingAdmissionPolicies"] = [listed("oracle-extra.static.k8s.io", 144)]


def _one_unknown_among_rendered(snap):
    names = rendered_names(snap, VAP)
    snap["lists"]["validatingAdmissionPolicies"] = [listed(name, 150 + n) for n, name in enumerate(names)] + [
        listed("oracle-unknown-policy", 159)
    ]


UNKNOWN_OBJECTS = [
    ("a policy with an unknown name", _unknown_policy),
    ("a binding with an unknown name", _unknown_binding),
    ("a policy carrying a rendered binding name", _policy_with_a_binding_name),
    ("a binding carrying a rendered policy name", _binding_with_a_policy_name),
    ("a .static.k8s.io name that is not rendered", _static_suffix_not_rendered),
    ("one unknown policy among the rendered ones", _one_unknown_among_rendered),
]


@pytest.mark.parametrize("name,mutate", UNKNOWN_OBJECTS, ids=[name for name, _ in UNKNOWN_OBJECTS])
def test_an_unknown_admission_object_refuses(name, mutate):
    """README 4.1 (decisions D1-12, D2-5): over (kind, name), a listed policy must carry one of the four rendered
    policy names and a listed binding one of the four rendered binding names; nothing rests on the .static.k8s.io
    suffix."""
    snap = sealed_snapshot()
    mutate(snap)
    refuses_doc(T_UNKNOWN, "admissionPolicy", snap)


def test_the_qualification_namespace_must_be_listed():
    """README 4.1: the qualification Namespace must be listed exactly once, else "admissionPolicy: qualification
    namespace not listed"."""
    snap = sealed_snapshot()
    snap["lists"]["namespaces"] = [item for item in snap["lists"]["namespaces"] if item["metadata"]["name"] != NS]
    refuses_doc(T_NOT_LISTED, "admissionPolicy", snap)


def test_the_qualification_namespace_listed_twice_refuses():
    """README 4.1: listed exactly once."""
    snap = sealed_snapshot()
    twin = copy.deepcopy(_qualification_namespace(snap))
    twin["metadata"]["uid"] = U(3)
    snap["lists"]["namespaces"].append(twin)
    refuses_doc(T_NOT_LISTED, "admissionPolicy", snap)


def test_unknown_objects_are_checked_before_the_namespace():
    """definitions.json admissionPolicy order: rendered hash, unknown admission objects, qualification Namespace."""
    snap = sealed_snapshot()
    _unknown_policy(snap)
    snap["lists"]["namespaces"] = []
    refuses_doc(T_UNKNOWN, "admissionPolicy", snap)


# =========================================================================== 4. networkPolicy's selector-free form

IP_PEER = {"ipBlock": {"cidr": "10.20.0.0/16", "except": ["10.20.1.0/24"]}}


def _np_spec(**members):
    spec = default_deny()
    spec.update(members)
    return spec


def _ingress(*ports, peer=None):
    return [{"from": [IP_PEER if peer is None else peer], "ports": list(ports)}]


ADMITTED_SPECS = {
    "default deny": default_deny(),
    "ipBlock peers, integer port and endPort": _np_spec(
        ingress=_ingress({"protocol": "TCP", "port": 443}),
        egress=[
            {
                "to": [{"ipBlock": {"cidr": "192.0.2.0/24"}}],
                "ports": [{"protocol": "TCP", "port": 8000, "endPort": 8080}],
            }
        ],
    ),
    "a ports entry without port": {
        "podSelector": {},
        "policyTypes": ["Egress"],
        "egress": [{"to": [{"ipBlock": {"cidr": "198.51.100.0/24"}}], "ports": [{"protocol": "UDP"}]}],
    },
}

REFUSED_SPECS = {
    "non-empty podSelector": {"podSelector": {"matchLabels": {"app": "oracle"}}, "policyTypes": ["Ingress"]},
    "podSelector not exactly empty": {"podSelector": {"matchExpressions": []}, "policyTypes": ["Ingress"]},
    "namespaceSelector peer": _np_spec(ingress=[{"from": [{"namespaceSelector": {}}]}]),
    "podSelector peer": _np_spec(egress=[{"to": [{"podSelector": {}}]}]),
    "ipBlock beside namespaceSelector": _np_spec(
        ingress=_ingress(peer=dict(IP_PEER, namespaceSelector={"matchLabels": {"team": "oracle"}}))
    ),
    "named port": _np_spec(ingress=_ingress({"protocol": "TCP", "port": "https"})),
    "port as a string of digits": _np_spec(ingress=_ingress({"protocol": "TCP", "port": "443"})),
    "endPort as a string": _np_spec(ingress=_ingress({"protocol": "TCP", "port": 8000, "endPort": "8080"})),
    "boolean port": _np_spec(ingress=_ingress({"protocol": "TCP", "port": True})),
    "extra spec member": _np_spec(oracleExtra={}),
    "extra rule member": _np_spec(ingress=[{"from": [IP_PEER], "ports": [], "oracleExtra": []}]),
    "extra port member": _np_spec(ingress=_ingress({"protocol": "TCP", "port": 443, "oracleExtra": 1})),
}


@pytest.mark.parametrize("name", list(ADMITTED_SPECS))
def test_selector_free_forms_are_admitted(name):
    """README 4.4 (decisions R1-A, D2-6): podSelector {}, ipBlock-only peers, integer port and endPort, and a ports
    entry without port are admitted; the document's spec is the served spec."""
    snap = snapshot()
    base_item(snap, "networkPolicy")["spec"] = copy.deepcopy(ADMITTED_SPECS[name])
    got = document("networkPolicy", snap)
    assert got["spec"] == ADMITTED_SPECS[name]
    assert got == real_document("networkPolicy", base_item(snap, "networkPolicy"))


@pytest.mark.parametrize("name", list(REFUSED_SPECS))
def test_forms_outside_v1_refuse(name):
    """README 4.4 (decisions R1-A, D2-6): a non-empty podSelector, a namespaceSelector or podSelector peer, a named or
    non-integer port, or a member outside the NetworkPolicy v1 API refuses "networkPolicy: selector form outside
    v1"."""
    snap = snapshot()
    base_item(snap, "networkPolicy")["spec"] = copy.deepcopy(REFUSED_SPECS[name])
    refuses_doc(T_SELECTOR, "networkPolicy", snap)


# =========================================================================== 5. rbac and rbacClosureDigest


def _campaign_entry(got):
    return [item for item in got["spec"]["subjects"] if item["name"] == sa_name(NS, "oracle-campaign")][0]


def test_rbac_document():
    """README 4.5: the subject set (qualification-namespace RoleBindings plus every ClusterRoleBinding), B1's subject
    key, exists, rules in B1's shape plus non-resource entries, each with its binding's scope, the namespace filter,
    sorting by (kind, name) and by canonical bytes; spec {subjects} with no schemaVersion."""
    got = document("rbac", snapshot())
    assert got == rbac_document(base_subjects())
    assert sorted(got["spec"]) == ["subjects"]
    assert [(item["kind"], item["name"]) for item in got["spec"]["subjects"]] == [
        ("Group", "oracle-auditors"),
        ("ServiceAccount", sa_name(NS, "oracle-campaign")),
        ("User", "oracle-operator"),
    ]


def test_rbac_keeps_only_namespace_and_cluster_scopes():
    """README 4.5 (decision D1-8): rbac keeps the rules whose scope is the qualification namespace or CLUSTER; the
    subject's RoleBinding in another namespace does not enter."""
    got = document("rbac", snapshot())
    scopes = {item_rule["scope"] for item in got["spec"]["subjects"] for item_rule in item["effectiveRules"]}
    assert scopes <= {NS, CLUSTER}
    assert scoped(WRITER_RULE, OTHER) not in _campaign_entry(got)["effectiveRules"]


def test_a_role_binding_subject_without_namespace_takes_the_binding_namespace():
    """README 4.5 (subject key, decision D2-3): system:serviceaccount:<namespace>:<name>, a RoleBinding's namespace
    by default."""
    snap = snapshot()
    snap["lists"]["serviceAccounts"].append(account("oracle-late", n=33, rv="405"))
    snap["lists"]["roleBindings"].append(
        role_binding("oracle-late-binding", NS, 74, ref("Role", "oracle-reader"), [sa_subject("oracle-late")])
    )
    late = entry("ServiceAccount", sa_name(NS, "oracle-late"), True, [scoped(READER_RULE, NS)])
    assert document("rbac", snap) == rbac_document(base_subjects() + [late])


def test_same_named_accounts_in_two_namespaces_stay_two_subjects():
    """README 4.5 (decision D2-3): same-named ServiceAccounts in two namespaces stay two subjects."""
    snap = snapshot()
    snap["lists"]["serviceAccounts"].append(account(namespace=OTHER, n=32, rv="403"))
    twins = [sa_subject("oracle-campaign", NS), sa_subject("oracle-campaign", OTHER)]
    snap["lists"]["clusterRoleBindings"].append(
        cluster_role_binding("oracle-twins-binding", 81, ref("ClusterRole", "oracle-view"), twins)
    )
    here = [scoped(READER_RULE, NS), scoped(VIEW_RULE, CLUSTER)]
    expected = [
        entry("Group", "oracle-auditors", True, [scoped(VIEW_RULE, NS)]),
        entry("ServiceAccount", sa_name(NS, "oracle-campaign"), True, here),
        entry("ServiceAccount", sa_name(OTHER, "oracle-campaign"), True, [scoped(VIEW_RULE, CLUSTER)]),
        entry("User", "oracle-operator", True, [scoped(HEALTH_RULE, CLUSTER)]),
    ]
    assert document("rbac", snap) == rbac_document(expected)


def test_a_grant_moved_between_same_named_accounts_changes_rbac():
    """Design rev 3 section 9 (decision D2-3): a grant moved between same-named ServiceAccounts changes the digest."""
    digests = []
    for namespace in (NS, OTHER):
        snap = snapshot()
        snap["lists"]["serviceAccounts"].append(account(namespace=OTHER, n=32, rv="403"))
        subjects = [sa_subject("oracle-campaign", namespace)]
        snap["lists"]["clusterRoleBindings"].append(
            cluster_role_binding("oracle-twins-binding", 81, ref("ClusterRole", "oracle-view"), subjects)
        )
        digests.append(doc_digest("rbac", snap))
    assert digests[0] != digests[1]


def test_exists_is_false_for_an_unlisted_service_account():
    """README 4.5 (the entry): exists is true for User and Group; for a ServiceAccount, whether it is listed."""
    snap = snapshot()
    snap["lists"]["roleBindings"].append(
        role_binding("oracle-ghost-binding", NS, 75, ref("Role", "oracle-reader"), [sa_subject("oracle-ghost")])
    )
    ghost = entry("ServiceAccount", sa_name(NS, "oracle-ghost"), False, [scoped(READER_RULE, NS)])
    assert document("rbac", snap) == rbac_document(base_subjects() + [ghost])


def test_a_subject_bound_only_in_another_namespace_is_not_in_rbac():
    """README 4.5 (the subject set): only RoleBindings in the qualification namespace and ClusterRoleBindings."""
    snap = snapshot()
    snap["lists"]["roleBindings"].append(
        role_binding("elsewhere-view-binding", OTHER, 76, ref("ClusterRole", "oracle-view"), [user("oracle-elsewhere")])
    )
    assert document("rbac", snap) == rbac_document(base_subjects())


def test_a_non_resource_rule_through_a_cluster_binding_is_cluster_scoped():
    """README 4.5 (decisions D1-1, R2-B): a ClusterRoleBinding granting nonResourceURLs ["*"] enters rbac with scope
    CLUSTER and changes the digest."""
    snap = snapshot()
    everything = nonresource(["*"], ["get"])
    snap["lists"]["clusterRoles"].append(cluster_role("oracle-everything", 62, [everything]))
    snap["lists"]["clusterRoleBindings"].append(
        cluster_role_binding(
            "oracle-everything-binding", 82, ref("ClusterRole", "oracle-everything"), [group("oracle-auditors")]
        )
    )
    expected = base_subjects()
    expected[0] = entry("Group", "oracle-auditors", True, [scoped(VIEW_RULE, NS), scoped(everything, CLUSTER)])
    assert document("rbac", snap) == rbac_document(expected)
    assert doc_digest("rbac", snap) != doc_digest("rbac", snapshot())


def test_a_non_resource_rule_through_a_role_binding_takes_its_namespace():
    """README 4.5 (decision R2-B): a non-resource rule through a RoleBinding takes the binding's namespace; in the
    qualification namespace it enters rbac."""
    snap = snapshot()
    snap["lists"]["roleBindings"].append(
        role_binding("oracle-health-here", NS, 77, ref("ClusterRole", "oracle-health"), [sa_subject("oracle-campaign")])
    )
    expected = base_subjects()
    rules = [scoped(READER_RULE, NS), scoped(HEALTH_RULE, NS)]
    expected[1] = entry("ServiceAccount", sa_name(NS, "oracle-campaign"), True, rules)
    assert document("rbac", snap) == rbac_document(expected)


def test_a_non_resource_rule_through_another_namespace_stays_out_of_rbac():
    """README 4.5 (decisions D2-3, R2-B): through a RoleBinding in another namespace the entry carries that
    namespace, so it does not enter rbac."""
    snap = snapshot()
    subjects = [sa_subject("oracle-campaign", NS)]
    snap["lists"]["roleBindings"].append(
        role_binding("elsewhere-health-binding", OTHER, 78, ref("ClusterRole", "oracle-health"), subjects)
    )
    assert document("rbac", snap) == rbac_document(base_subjects())


def test_rules_are_sorted_and_deduplicated_by_canonical_bytes():
    """README 3.2 and 4.5: each subject's rules are sorted and deduplicated by canonical bytes."""
    snap = snapshot()
    pods = rule([""], ["pods"], ["get"])
    maps = rule([""], ["configmaps"], ["get"])
    _named(snap, "roles", "oracle-reader")["rules"] = [pods, maps, copy.deepcopy(pods)]
    got = document("rbac", snap)
    assert _campaign_entry(got)["effectiveRules"] == [scoped(maps, NS), scoped(pods, NS)]


def test_a_rule_granted_twice_is_one_entry():
    """README 4.5: rules deduplicated; subjects one entry each."""
    snap = snapshot()
    snap["lists"]["roleBindings"].append(
        role_binding("oracle-view-binding-2", NS, 79, ref("ClusterRole", "oracle-view"), [group("oracle-auditors")])
    )
    assert document("rbac", snap) == rbac_document(base_subjects())


def _aggregate(snap, name):
    _named(snap, "clusterRoles", name)["aggregationRule"] = copy.deepcopy(AGGREGATION)


def _b1_aggregated_namespace(snap):
    _aggregate(snap, "oracle-view")


def _b1_aggregated_cluster(snap):
    _aggregate(snap, "oracle-health")


def _b1_dangling(snap):
    _named(snap, "roleBindings", "oracle-reader-binding")["roleRef"]["name"] = "oracle-missing"


def _b1_cluster_sa_no_namespace(snap):
    _named(snap, "clusterRoleBindings", "oracle-health-binding")["subjects"] = [sa_subject("oracle-campaign")]


def _b1_cluster_sa_empty_namespace(snap):
    _named(snap, "clusterRoleBindings", "oracle-health-binding")["subjects"] = [sa_subject("oracle-campaign", "")]


def _b1_subject_kind(snap):
    _named(snap, "roleBindings", "oracle-view-binding")["subjects"] = [{"kind": "Robot", "name": "oracle-robot"}]


def _b1_subject_name(snap):
    _named(snap, "roleBindings", "oracle-view-binding")["subjects"] = [group("")]


def _b1_roleref_group(snap):
    _named(snap, "roleBindings", "oracle-view-binding")["roleRef"]["apiGroup"] = "oracle.example"


def _b1_roleref_kind(snap):
    _named(snap, "clusterRoleBindings", "oracle-health-binding")["roleRef"] = ref("Role", "oracle-reader")


def _b1_roleref_name(snap):
    _named(snap, "roleBindings", "oracle-view-binding")["roleRef"]["name"] = ""


def _b1_nonresource_beside_resources(snap):
    _named(snap, "clusterRoles", "oracle-view")["rules"] = [dict(VIEW_RULE, nonResourceURLs=["/metrics"])]


def _b1_loopback(snap):
    _named(snap, "clusterRoleBindings", "oracle-health-binding")["subjects"] = [user("system:apiserver")]


B1_CASES = [
    ("aggregated role by a namespace RoleBinding", _b1_aggregated_namespace, T_AGGREGATED),
    ("aggregated role by a ClusterRoleBinding", _b1_aggregated_cluster, T_AGGREGATED),
    ("dangling roleRef", _b1_dangling, "rbac: role does not exist"),
    ("cluster account subject without namespace", _b1_cluster_sa_no_namespace, "rbac: malformed subject namespace"),
    ("cluster account subject, empty namespace", _b1_cluster_sa_empty_namespace, "rbac: malformed subject namespace"),
    ("subject kind outside User, Group, ServiceAccount", _b1_subject_kind, "rbac: malformed subject kind"),
    ("empty subject name", _b1_subject_name, "rbac: malformed subject name"),
    ("roleRef outside the RBAC group", _b1_roleref_group, "rbac: malformed roleRef apiGroup"),
    ("ClusterRoleBinding naming a Role", _b1_roleref_kind, "rbac: malformed roleRef kind"),
    ("empty roleRef name", _b1_roleref_name, "rbac: malformed roleRef name"),
    (
        "nonResourceURLs beside resources",
        _b1_nonresource_beside_resources,
        "rbac: malformed rule (non-resource URLs beside resources)",
    ),
    ("loopback user bound to a non-resource rule", _b1_loopback, "rbac: loopback user bound to a non-resource rule"),
]
B1_IDS = [name for name, _, _ in B1_CASES]


@pytest.mark.parametrize("name,mutate,text", B1_CASES, ids=B1_IDS)
def test_b1_refusals_withhold_rbac(name, mutate, text):
    """README 4.5 (B1's refusals table) and definitions.json b1Refusals."""
    snap = snapshot()
    mutate(snap)
    refuses_doc(text, "rbac", snap)


@pytest.mark.parametrize("name,mutate,text", B1_CASES, ids=B1_IDS)
def test_b1_refusals_withhold_the_closure(name, mutate, text):
    """README 4.5 ("These refusals withhold both RBAC values") and 5.2 (the closure refuses with rbac's texts
    first)."""
    snap = snapshot()
    mutate(snap)
    refuses_enf(text, "rbacClosureDigest", snap)


def _order_cluster_roles_first(snap):
    _b1_nonresource_beside_resources(snap)
    _b1_subject_kind(snap)


def _order_cluster_bindings_first(snap):
    _named(snap, "clusterRoleBindings", "oracle-health-binding")["roleRef"]["name"] = "oracle-missing"
    _b1_subject_kind(snap)


def _order_subjects_before_resolution(snap):
    item = _named(snap, "roleBindings", "oracle-view-binding")
    item["roleRef"]["name"] = "oracle-missing"
    item["subjects"] = [{"kind": "Robot", "name": "oracle-robot"}]


def _order_roleref_before_subjects(snap):
    item = _named(snap, "roleBindings", "oracle-view-binding")
    item["roleRef"]["apiGroup"] = "oracle.example"
    item["subjects"] = [{"kind": "Robot", "name": "oracle-robot"}]


B1_ORDER = [
    (
        "ClusterRoles before bindings",
        _order_cluster_roles_first,
        "rbac: malformed rule (non-resource URLs beside resources)",
    ),
    ("ClusterRoleBindings before RoleBindings", _order_cluster_bindings_first, "rbac: role does not exist"),
    ("subjects before role resolution", _order_subjects_before_resolution, "rbac: malformed subject kind"),
    ("roleRef before subjects", _order_roleref_before_subjects, "rbac: malformed roleRef apiGroup"),
]


@pytest.mark.parametrize("name,mutate,text", B1_ORDER, ids=[name for name, _, _ in B1_ORDER])
def test_b1_refusals_follow_b1_order(name, mutate, text):
    """README 4.5 and definitions.json b1Refusals.order: ClusterRoles, Roles, ServiceAccounts, binding metadata, then
    the bindings sorted (ClusterRoleBindings first), each: roleRef, subjects, role resolution, aggregation,
    loopback."""
    snap = snapshot()
    mutate(snap)
    refuses_doc(text, "rbac", snap)


def test_an_aggregated_role_bound_only_elsewhere_does_not_refuse():
    """definitions.json b1Refusals: the aggregation refusal is for a RoleBinding in the qualification namespace or
    any ClusterRoleBinding; a RoleBinding elsewhere, or no binding, does not refuse."""
    snap = snapshot()
    roles = snap["lists"]["clusterRoles"]
    roles.append(cluster_role("oracle-aggregate", 63, [], aggregationRule=copy.deepcopy(AGGREGATION)))
    roles.append(cluster_role("oracle-unbound", 64, [], aggregationRule=copy.deepcopy(AGGREGATION)))
    snap["lists"]["roleBindings"].append(
        role_binding(
            "elsewhere-aggregate-binding", OTHER, 83, ref("ClusterRole", "oracle-aggregate"), [user("oracle-elsewhere")]
        )
    )
    assert document("rbac", snap) == rbac_document(base_subjects())


def frozen_i06():
    """README 5.2 (the i06 input) and definitions.json frozenInputs: {closure, inventory, bootstrap}, each the parsed
    JSON of its file, read by its exact path and checked against its pinned sha256."""
    out = {}
    for item in DEFINITIONS["frozenInputs"]:
        raw = (ROOT / item["path"]).read_bytes()
        assert hashlib.sha256(raw).hexdigest() == item["sha256"], item["path"]
        out[item["name"]] = json.loads(raw.decode("utf-8"))
    assert sorted(out) == ["bootstrap", "closure", "inventory"]
    return out


T_CLOSURE_MALFORMED = "rbacClosureDigest: malformed input"


def test_rbac_closure_needs_the_i06_checks():
    """README 5.2: the closure exists only after I06's closure check and I06 v4's role pin pass, with the
    caller-supplied i06 = {closure, inventory, bootstrap}; a snapshot without the observer's ClusterRole and binding
    refuses "rbacClosureDigest: I06 closure check not passed". A missing i06, or one without exactly those three
    members, refuses "rbacClosureDigest: malformed input"."""
    i06 = frozen_i06()
    expected = "rbacClosureDigest: I06 closure check not passed"
    assert_refuses(expected, pod.enforcement, "rbacClosureDigest", snapshot(), i06)
    assert_refuses(T_CLOSURE_MALFORMED, pod.enforcement, "rbacClosureDigest", snapshot())
    missing = {name: value for name, value in i06.items() if name != "inventory"}
    assert_refuses(T_CLOSURE_MALFORMED, pod.enforcement, "rbacClosureDigest", snapshot(), missing)
    extra = dict(i06, oracleExtra={})
    assert_refuses(T_CLOSURE_MALFORMED, pod.enforcement, "rbacClosureDigest", snapshot(), extra)


def test_rbac_closure_refuses_a_missing_namespace_with_its_own_text():
    """README 5.2 (the order): the closure first refuses a missing or ill-shaped qualification namespace with its own
    text, "rbacClosureDigest: malformed input"; then rbac's texts and B1's; then the i06 input and the I06 checks."""
    i06 = frozen_i06()
    snap = snapshot()
    del snap["configuration"]["qualificationNamespace"]
    assert_refuses(T_CLOSURE_MALFORMED, pod.enforcement, "rbacClosureDigest", snap, i06)
    snap = snapshot()
    snap["configuration"]["qualificationNamespace"] = 42
    assert_refuses(T_CLOSURE_MALFORMED, pod.enforcement, "rbacClosureDigest", snap, i06)
    snap = snapshot()
    del snap["configuration"]["qualificationNamespace"]
    _b1_aggregated_namespace(snap)
    assert_refuses(T_CLOSURE_MALFORMED, pod.enforcement, "rbacClosureDigest", snap, i06)
    snap = snapshot()
    _b1_aggregated_namespace(snap)
    assert_refuses(T_AGGREGATED, pod.enforcement, "rbacClosureDigest", snap, i06)
    assert_refuses(T_AGGREGATED, pod.enforcement, "rbacClosureDigest", snap)


# =========================================================================== 6. mutationBroker


def test_mutation_broker_document():
    """README 4.6: the 14 members of the BROKER row, cgroup without its inode; the fixed identity and derived uid."""
    got = document("mutationBroker", snapshot())
    row = snapshot()["record"]["roles"]["BROKER"]
    assert got == synthetic_document("mutationBroker", NS, broker_spec(row))
    assert sorted(got["spec"]) == sorted(BROKER_DOCUMENT)
    assert sorted(got["spec"]["cgroup"]) == sorted(set(CGROUP_MEMBERS) - {"inode"})
    left_out = ("namespaceInodes", "rlimitCore", "filePaths", "bpfPrograms", "interpreterPath", "interpreterLabel")
    assert not set(left_out) & set(got["spec"])


def _set_row(path, value):
    def mutate(row):
        target = row
        for part in path[:-1]:
            target = target[part]
        target[path[-1]] = copy.deepcopy(value)

    return mutate


LEFT_OUT_CHANGES = [
    ("namespaceInodes", _set_row(("namespaceInodes",), {"mnt": 1, "net": 2, "pid": 3})),
    ("cgroup.inode", _set_row(("cgroup", "inode"), 8888)),
    ("rlimitCore", _set_row(("rlimitCore",), 4096)),
    ("filePaths", _set_row(("filePaths",), ["/oracle/bin/broker", "/oracle/etc/broker.conf"])),
    ("bpfPrograms", _set_row(("bpfPrograms",), [{"id": 1, "tag": "oracle"}])),
]


@pytest.mark.parametrize("name,mutate", LEFT_OUT_CHANGES, ids=[name for name, _ in LEFT_OUT_CHANGES])
def test_left_out_broker_members_do_not_change_the_digest(name, mutate):
    """README 4.6: namespaceInodes and cgroup.inode change on recreation; rlimitCore, filePaths and bpfPrograms are
    covered by section 5.4's record digest; none enters the document."""
    snap = snapshot()
    mutate(snap["record"]["roles"]["BROKER"])
    assert doc_digest("mutationBroker", snap) == doc_digest("mutationBroker", snapshot())


CAPABILITIES = {"bounding": ["CAP_NET_BIND_SERVICE"], "effective": [], "permitted": []}
KEPT_CHANGES = [
    ("executable", _set_row(("executable",), "/oracle/bin/broker-v2")),
    ("executableLabel", _set_row(("executableLabel",), "system_u:object_r:oracle_other_exec_t:s0")),
    ("artifactDigest", _set_row(("artifactDigest",), "sha256:" + "a" * 64)),
    ("uid", _set_row(("uid",), 2999)),
    ("gid", _set_row(("gid",), 2999)),
    ("processLabel", _set_row(("processLabel",), "system_u:system_r:oracle_other_t:s0")),
    ("cgroup.path", _set_row(("cgroup", "path"), "/oracle.slice/other.service")),
    ("cgroup.memoryMaxBytes", _set_row(("cgroup", "memoryMaxBytes"), 536870912)),
    ("cgroup.pidsMax", _set_row(("cgroup", "pidsMax"), 128)),
    ("cgroup.cpuQuotaMicros", _set_row(("cgroup", "cpuQuotaMicros"), 60000)),
    ("cgroup.cpuPeriodMicros", _set_row(("cgroup", "cpuPeriodMicros"), 200000)),
    ("cgroup.selinuxLabel", _set_row(("cgroup", "selinuxLabel"), "system_u:object_r:oracle_other_t:s0")),
    ("seccompMode", _set_row(("seccompMode",), "STRICT")),
    ("seccompDefaultAction", _set_row(("seccompDefaultAction",), "ERRNO")),
    ("seccompFilterDigest", _set_row(("seccompFilterDigest",), "sha256:" + "b" * 64)),
    ("noNewPrivs", _set_row(("noNewPrivs",), False)),
    ("capabilities", _set_row(("capabilities",), CAPABILITIES)),
    ("listenEndpointIds", _set_row(("listenEndpointIds",), ["broker-listen-2"])),
    ("outboundEndpointIds", _set_row(("outboundEndpointIds",), [])),
]


@pytest.mark.parametrize("name,mutate", KEPT_CHANGES, ids=[name for name, _ in KEPT_CHANGES])
def test_kept_broker_members_change_the_digest(name, mutate):
    """README 4.6: each of the 14 members (and cgroup's six kept members) is in the document."""
    snap = snapshot()
    mutate(snap["record"]["roles"]["BROKER"])
    expected = synthetic_document("mutationBroker", NS, broker_spec(snap["record"]["roles"]["BROKER"]))
    assert document("mutationBroker", snap) == expected
    assert doc_digest("mutationBroker", snap) != doc_digest("mutationBroker", snapshot())


def test_other_role_rows_do_not_enter_the_broker_document():
    """README 4 (table) and 4.6: the source is the BROKER row alone."""
    snap = snapshot()
    snap["record"]["roles"]["SERVER"]["executable"] = "/oracle/bin/server-v2"
    assert document("mutationBroker", snap) == expected_document("mutationBroker", snapshot())


@pytest.mark.parametrize("member", BROKER_MEMBERS)
def test_a_broker_row_without_a_member_is_incomplete(member):
    """README 4.6: the row must carry exactly the 20 required members, else "mutationBroker: broker row
    incomplete"."""
    snap = snapshot()
    del snap["record"]["roles"]["BROKER"][member]
    refuses_doc(T_ROW, "mutationBroker", snap)


def test_a_broker_row_with_an_extra_member_is_incomplete():
    """README 4.6: a row without exactly those members refuses."""
    snap = snapshot()
    snap["record"]["roles"]["BROKER"]["oracleExtra"] = "x"
    refuses_doc(T_ROW, "mutationBroker", snap)


@pytest.mark.parametrize("member", CGROUP_MEMBERS)
def test_a_cgroup_without_a_member_is_incomplete(member):
    """README 4.6: cgroup requires 7 members."""
    snap = snapshot()
    del snap["record"]["roles"]["BROKER"]["cgroup"][member]
    refuses_doc(T_ROW, "mutationBroker", snap)


def test_a_cgroup_with_an_extra_member_is_incomplete():
    """README 4.6: cgroup requires exactly its 7 members."""
    snap = snapshot()
    snap["record"]["roles"]["BROKER"]["cgroup"]["oracleExtra"] = 1
    refuses_doc(T_ROW, "mutationBroker", snap)


def test_mutation_broker_exactness():
    """README 3.2: a float in the document refuses "mutationBroker: float refused"; an integer beyond 2^53 - 1
    refuses "mutationBroker: integer out of range"."""
    snap = snapshot()
    snap["record"]["roles"]["BROKER"]["cgroup"]["memoryMaxBytes"] = 268435456.5
    refuses_doc("mutationBroker: float refused", "mutationBroker", snap)
    snap = snapshot()
    snap["record"]["roles"]["BROKER"]["uid"] = MAX + 1
    refuses_doc("mutationBroker: integer out of range", "mutationBroker", snap)


# =========================================================================== 7. the capture gate

T0 = 7_200_000
W0 = 1_760_000_000_000
FRESH = (T0 + 30_000, W0 + 30_000)


def all_slots(record, state="TAKEN"):
    backends = ["backend/" + name for name in record["backendComponents"]]
    return {name: state for name in ["role/" + name for name in ROLES] + ["lifecycle"] + backends}


def capture_set(record, scheduled=T0, started=W0, completed=True, slots=None):
    return {
        "scheduledMonotonicMs": scheduled,
        "startedWallMs": started,
        "completed": completed,
        "slots": all_slots(record) if slots is None else slots,
    }


def verdicts(sets, monotonic, wall):
    return {"sets": sets, "answer": {"monotonicMs": monotonic, "wallMs": wall}}


def failing_slots(record, key):
    slots = all_slots(record)
    for name in REQUIRED[key]:
        slots[name] = "FAILED"
    return slots


@pytest.mark.parametrize("key", GATED)
def test_gate_passes_a_fresh_passing_set(key):
    """README 3.3 (the gate): the latest completed set has every required slot TAKEN and both ages within 0..90 s."""
    record = enrolled_record()
    pod.capture_gate(key, verdicts([capture_set(record)], *FRESH), record)


INCLUSIVE = [(0, 0), (BOUND_MS, BOUND_MS), (BOUND_MS, 0), (0, BOUND_MS)]


@pytest.mark.parametrize("mono_age,wall_age", INCLUSIVE, ids=["0-0", "90-90", "90-0", "0-90"])
@pytest.mark.parametrize("key", GATED)
def test_gate_bound_is_inclusive(key, mono_age, wall_age):
    """README 3.3 and decision R2-A: a set whose scheduled start is 90 s before the answer passes; ages
    0..90000 ms."""
    record = enrolled_record()
    pod.capture_gate(key, verdicts([capture_set(record)], T0 + mono_age, W0 + wall_age), record)


OUTSIDE = [(BOUND_MS + 1, 0), (0, BOUND_MS + 1), (-1, 0), (0, -1), (BOUND_MS + 1, BOUND_MS + 1)]
OUTSIDE_IDS = ["mono-90001", "wall-90001", "mono-negative", "wall-negative", "both-90001"]


@pytest.mark.parametrize("mono_age,wall_age", OUTSIDE, ids=OUTSIDE_IDS)
@pytest.mark.parametrize("key", GATED)
def test_gate_refuses_an_age_outside_the_bound(key, mono_age, wall_age):
    """README 3.3 (items 2 and 3) and decisions R2-A, D3-1: monotonic age over 90 s or negative, or wall age
    negative or over 90 s, refuses "<key>: capture set too old"."""
    record = enrolled_record()
    capture = verdicts([capture_set(record)], T0 + mono_age, W0 + wall_age)
    refuses_gate(key + ": capture set too old", key, capture, record)


@pytest.mark.parametrize("key,slot", [(key, slot) for key in GATED for slot in REQUIRED[key]])
def test_gate_refuses_a_required_slot_not_taken(key, slot):
    """README 3.3 (item 1), 4.6, 5.3, 5.4 and definitions.json captureGate.requiredSlots: every required slot must
    be TAKEN, else the value's own text."""
    record = enrolled_record()
    slots = all_slots(record)
    slots[slot] = "FAILED"
    refuses_gate(OWN_TEXT[key], key, verdicts([capture_set(record, slots=slots)], *FRESH), record)


@pytest.mark.parametrize("key", ["mutationBroker", "networkEnforcementDigest"])
def test_gate_needs_only_its_own_slots(key):
    """definitions.json captureGate.requiredSlots: mutationBroker needs role/BROKER and the network digest
    backend/NETWORK_POLICY_AGENT only."""
    record = enrolled_record()
    slots = all_slots(record, "FAILED")
    for name in REQUIRED[key]:
        slots[name] = "TAKEN"
    pod.capture_gate(key, verdicts([capture_set(record, slots=slots)], *FRESH), record)


@pytest.mark.parametrize("key", GATED)
def test_gate_refuses_without_any_set(key):
    """README 3.3 (item 1) and definitions.json captureGate.rule: no completed set, the value's own text."""
    refuses_gate(OWN_TEXT[key], key, verdicts([], T0, W0), enrolled_record())


@pytest.mark.parametrize("key", GATED)
def test_gate_refuses_when_no_set_is_completed(key):
    """README 3.3: the latest completed set is the last entry whose completed is true; an incomplete set never
    counts."""
    record = enrolled_record()
    refuses_gate(OWN_TEXT[key], key, verdicts([capture_set(record, completed=False)], *FRESH), record)


@pytest.mark.parametrize("key", GATED)
def test_gate_refuses_an_expired_view(key):
    """README 3.3: an Expired view is presented as a set whose slots are EXPIRED."""
    record = enrolled_record()
    capture = verdicts([capture_set(record, slots=all_slots(record, "EXPIRED"))], *FRESH)
    refuses_gate(OWN_TEXT[key], key, capture, record)


@pytest.mark.parametrize("key", GATED)
def test_a_later_failing_set_withdraws_the_value(key):
    """README 3.3 and decision D2-1: a later set without the required slots withdraws the values at once."""
    record = enrolled_record()
    first = capture_set(record, T0, W0)
    pod.capture_gate(key, verdicts([first], T0 + 70_000, W0 + 70_000), record)
    second = capture_set(record, T0 + 60_000, W0 + 60_000, slots=failing_slots(record, key))
    refuses_gate(OWN_TEXT[key], key, verdicts([first, second], T0 + 70_000, W0 + 70_000), record)


@pytest.mark.parametrize("key", GATED)
def test_a_later_passing_set_restores_the_value(key):
    """README 3.3: the values are withdrawn until a set passes again."""
    record = enrolled_record()
    first = capture_set(record, T0, W0, slots=failing_slots(record, key))
    second = capture_set(record, T0 + 60_000, W0 + 60_000)
    pod.capture_gate(key, verdicts([first, second], T0 + 70_000, W0 + 70_000), record)


@pytest.mark.parametrize("key", GATED)
def test_a_later_incomplete_set_is_ignored(key):
    """README 3.3: the latest completed set decides; an incomplete set after it is ignored."""
    record = enrolled_record()
    first = capture_set(record, T0, W0)
    second = capture_set(record, T0 + 60_000, W0 + 60_000, completed=False, slots=all_slots(record, "FAILED"))
    pod.capture_gate(key, verdicts([first, second], T0 + 70_000, W0 + 70_000), record)


@pytest.mark.parametrize("key", GATED)
def test_the_age_is_the_latest_completed_set_own_scheduled_start(key):
    """README 3.3 (item 2) and decision D3-1: the start is the set's own on the monotonic clock, never a later
    cycle's; a skipped or escalated cycle takes no set, so the values refuse once the latest set is older than the
    bound."""
    record = enrolled_record()
    first = capture_set(record, T0, W0)
    escalated = capture_set(record, T0 + 60_000, W0 + 60_000, completed=False)
    capture = verdicts([first, escalated], T0 + BOUND_MS + 5_000, W0 + 30_000)
    refuses_gate(key + ": capture set too old", key, capture, record)


def test_a_slot_from_an_earlier_set_never_counts():
    """README 3.3: each set resets every slot and the view is replaced wholesale; slots never combine across sets."""
    record = enrolled_record()
    first = all_slots(record)
    first["lifecycle"] = "FAILED"
    second = all_slots(record)
    second["role/BROKER"] = "FAILED"
    sets = [capture_set(record, T0, W0, slots=first), capture_set(record, T0 + 60_000, W0 + 60_000, slots=second)]
    refuses_gate(T_HOST, "hostPreflightDigest", verdicts(sets, T0 + 70_000, W0 + 70_000), record)


def test_host_preflight_needs_every_backend_of_the_record():
    """README 3.3 and 5.4: the slots are backend/<component> for each of the record's backendComponents."""
    record = enrolled_record()
    record["backendComponents"]["SERVICE_PROXY"] = backend("SERVICE_PROXY")
    record["backendProfile"]["componentKeys"].append("SERVICE_PROXY")
    slots = all_slots(record)
    slots["backend/SERVICE_PROXY"] = "FAILED"
    capture = verdicts([capture_set(record, slots=slots)], *FRESH)
    refuses_gate(T_HOST, "hostPreflightDigest", capture, record)
    pod.capture_gate("mutationBroker", capture, record)
    slots["backend/SERVICE_PROXY"] = "TAKEN"
    pod.capture_gate("hostPreflightDigest", verdicts([capture_set(record, slots=slots)], *FRESH), record)


def _negative_start(capture):
    capture["sets"][0]["scheduledMonotonicMs"] = -1


def _start_beyond_bound(capture):
    capture["sets"][0]["scheduledMonotonicMs"] = MAX + 1


def _float_wall_start(capture):
    capture["sets"][0]["startedWallMs"] = W0 + 0.5


def _completed_not_boolean(capture):
    capture["sets"][0]["completed"] = "true"


def _answer_missing(capture):
    del capture["answer"]


def _answer_wall_beyond_bound(capture):
    capture["answer"]["wallMs"] = MAX + 1


def _sets_not_a_list(capture):
    capture["sets"] = {"0": capture["sets"][0]}


MALFORMED_CAPTURE = [
    ("negative scheduled start", _negative_start),
    ("scheduled start beyond 2^53 - 1", _start_beyond_bound),
    ("float wall start", _float_wall_start),
    ("completed not a boolean", _completed_not_boolean),
    ("answer missing", _answer_missing),
    ("answer wall time beyond 2^53 - 1", _answer_wall_beyond_bound),
    ("sets not a list", _sets_not_a_list),
]


@pytest.mark.parametrize("name,mutate", MALFORMED_CAPTURE, ids=[name for name, _ in MALFORMED_CAPTURE])
@pytest.mark.parametrize("key", GATED)
def test_malformed_capture_data_refuses(key, name, mutate):
    """README 3.3 (every number an integer in 0..2^53 - 1; completed boolean) and 3.4 (malformed capture data
    refuses "<key>: malformed input")."""
    record = enrolled_record()
    capture = verdicts([capture_set(record)], *FRESH)
    mutate(capture)
    refuses_gate(key + ": malformed input", key, capture, record)


# =========================================================================== 8. network and host digests


def test_network_enforcement_digest_document():
    """README 5.3: canonical({networkPolicies: [...], agent: {executable, executableLabel, artifactDigest,
    processLabel, apiIdentities}}), the NetworkPolicy in section 3.1's form."""
    result = pod.enforcement("networkEnforcementDigest", snapshot())
    expected = network_document(snapshot())
    assert result["document"] == expected
    assert result["digest"] == sha256_digest(expected)
    assert DIGEST_RE.match(result["digest"])


@pytest.mark.parametrize("member", ["cgroupPath", "filePaths"])
def test_agent_members_outside_the_document_do_not_change_it(member):
    """README 5.3: the agent object carries cgroupPath and filePaths, which are not document members."""
    snap = snapshot()
    value = ["/oracle/changed"] if member == "filePaths" else "/oracle/changed"
    snap["record"]["backendComponents"][AGENT][member] = value
    assert pod.enforcement("networkEnforcementDigest", snap) == pod.enforcement("networkEnforcementDigest", snapshot())


@pytest.mark.parametrize("member", AGENT_MEMBERS)
def test_agent_members_change_the_digest(member):
    """README 5.3 and decision R2-C: executableLabel, artifactDigest and apiIdentities stay in the document with the
    executable and processLabel."""
    snap = snapshot()
    agent = snap["record"]["backendComponents"][AGENT]
    if member == "apiIdentities":
        agent[member] = ["system:serviceaccount:kube-system:oracle-changed"]
    else:
        agent[member] = agent[member] + "-changed"
    result = pod.enforcement("networkEnforcementDigest", snap)
    assert result["document"] == network_document(snap)
    assert result["digest"] != enf_digest("networkEnforcementDigest", snapshot())


def test_network_document_follows_the_network_policy():
    """README 5.3: the NetworkPolicy documents in section 3.1's form; volatile fields stay out, a spec change
    counts."""
    snap = snapshot()
    base_item(snap, "networkPolicy")["metadata"]["labels"] = {"oracle/relabelled": "yes"}
    base = enf_digest("networkEnforcementDigest", snapshot())
    assert enf_digest("networkEnforcementDigest", snap) == base
    change_spec("networkPolicy", snap)
    assert enf_digest("networkEnforcementDigest", snap) != base


def test_no_network_policy_agent_in_backend_components_refuses():
    """README 5.3 (decision D1-4): without backendComponents.NETWORK_POLICY_AGENT, "networkEnforcementDigest: no
    network policy agent"."""
    snap = snapshot()
    del snap["record"]["backendComponents"][AGENT]
    refuses_enf(T_NO_AGENT, "networkEnforcementDigest", snap)


def test_no_network_policy_agent_in_component_keys_refuses():
    """README 5.3 (decision D1-4): its member of backendProfile.componentKeys absent refuses the same way."""
    snap = snapshot()
    snap["record"]["backendProfile"]["componentKeys"].remove(AGENT)
    refuses_enf(T_NO_AGENT, "networkEnforcementDigest", snap)


def _np_none(snap):
    snap["lists"]["networkPolicies"] = []


def _np_two(snap):
    snap["lists"]["networkPolicies"].append(netpol(name="oracle-second", n=98, rv="998"))


def _np_selector(snap):
    base_item(snap, "networkPolicy")["spec"] = copy.deepcopy(REFUSED_SPECS["namespaceSelector peer"])


def _np_malformed(snap):
    del base_item(snap, "networkPolicy")["metadata"]["uid"]


NETWORK_PART = [
    ("no NetworkPolicy", _np_none, "networkPolicy: count is not one"),
    ("two NetworkPolicies", _np_two, "networkPolicy: count is not one"),
    ("a selector form", _np_selector, T_SELECTOR),
    ("a served object without uid", _np_malformed, "networkPolicy: malformed input"),
]


@pytest.mark.parametrize("name,mutate,text", NETWORK_PART, ids=[name for name, _, _ in NETWORK_PART])
def test_the_network_part_refuses_with_network_policy_texts(name, mutate, text):
    """README 5.3 (decision Q-CB-15): this part refuses with networkPolicy's texts, in v1 exactly one selector-free
    NetworkPolicy."""
    snap = snapshot()
    mutate(snap)
    refuses_enf(text, "networkEnforcementDigest", snap)


def test_network_enforcement_exactness():
    """README 3.2 and definitions.json: a float in the agent document refuses "networkEnforcementDigest: float
    refused"."""
    snap = snapshot()
    snap["record"]["backendComponents"][AGENT]["apiIdentities"].append(2.5)
    refuses_enf("networkEnforcementDigest: float refused", "networkEnforcementDigest", snap)


def test_host_preflight_digest_is_the_record_digest():
    """README 5.4: "sha256:" and the sha256 of the enrolled v4 record's canonical bytes."""
    digest = enf_digest("hostPreflightDigest", snapshot())
    assert digest == sha256_digest(enrolled_record())
    assert DIGEST_RE.match(digest)


def test_record_members_left_out_of_the_broker_document_are_in_the_record_digest():
    """README 4.6 and 5.4: rlimitCore, filePaths and bpfPrograms are covered by the record digest, not
    mutationBroker."""
    snap = snapshot()
    snap["record"]["roles"]["BROKER"]["rlimitCore"] = 4096
    assert enf_digest("hostPreflightDigest", snap) == sha256_digest(snap["record"])
    assert enf_digest("hostPreflightDigest", snap) != enf_digest("hostPreflightDigest", snapshot())
    assert doc_digest("mutationBroker", snap) == doc_digest("mutationBroker", snapshot())


@pytest.mark.parametrize(
    "value,text",
    [(0.5, "float refused"), (MAX + 1, "integer out of range"), (-(MAX + 1), "integer out of range")],
    ids=["float", "2^53", "-2^53"],
)
def test_host_preflight_record_exactness(value, text):
    """README 3.2 and 5.4: the record is an exact value."""
    snap = snapshot()
    snap["record"]["roles"]["WORKER"]["rlimitCore"] = value
    refuses_enf("hostPreflightDigest: " + text, "hostPreflightDigest", snap)


def test_host_preflight_accepts_a_negative_integer_within_the_bound():
    """README 3.2 and 5.4: a negative integer within the bound is accepted."""
    snap = snapshot()
    snap["record"]["roles"]["WORKER"]["rlimitCore"] = -MAX
    assert enf_digest("hostPreflightDigest", snap) == sha256_digest(snap["record"])


def test_gated_digests_are_checked_under_the_gate():
    """README 3.3, 5.3 and 5.4: the digests are computed at the snapshot and gated at the answer; a passing set
    admits them and a set with one backend slot failed withdraws hostPreflightDigest only."""
    snap = snapshot()
    record = snap["record"]
    assert enf_digest("hostPreflightDigest", snap) == sha256_digest(record)
    passing = verdicts([capture_set(record)], *FRESH)
    for key in GATED:
        pod.capture_gate(key, passing, record)
    slots = all_slots(record)
    slots["backend/KUBELET"] = "FAILED"
    one_failed = verdicts([capture_set(record, slots=slots)], *FRESH)
    pod.capture_gate("mutationBroker", one_failed, record)
    pod.capture_gate("networkEnforcementDigest", one_failed, record)
    refuses_gate(T_HOST, "hostPreflightDigest", one_failed, record)


# =========================================================================== 9. refusal texts and definitions

ALL_KEYS = SEVEN + ("admissionFenceDigest", "rbacClosureDigest", "networkEnforcementDigest", "hostPreflightDigest")
B1_FIELDS = (
    "metadata",
    "rules",
    "rule",
    "rule list",
    "rule (non-resource URLs beside resources)",
    "subjects",
    "subject",
    "subject name",
    "subject kind",
    "subject namespace",
    "roleRef",
    "roleRef apiGroup",
    "roleRef kind",
    "roleRef name",
)


def readme_texts():
    """README section 9's table, expanded over <key>, with section 9's note on the four unpinned RBAC texts."""
    texts = set()
    for key in ALL_KEYS:
        for text in ("document bound exceeded", "malformed input", "differs from the signed value"):
            texts.add(key + ": " + text)
        if key not in ("rbac", "rbacClosureDigest"):
            texts.add(key + ": float refused")
            texts.add(key + ": integer out of range")
    for key in GATED:
        texts.add(key + ": capture set too old")
    for key in ("resourceQuota", "limitRange", "serviceAccount", "networkPolicy"):
        texts.add(key + ": count is not one")
        texts.add(key + ": name differs from the binding")
    texts |= {
        T_RENDERED,
        "admissionPolicy: unknown admission object",
        "admissionPolicy: qualification namespace not listed",
        T_ANNOTATION,
        T_SELECTOR,
        T_AGGREGATED,
        "rbac: role does not exist",
        "rbac: loopback user bound to a non-resource rule",
        "rbacClosureDigest: I06 closure check not passed",
        T_ROW,
        "mutationBroker: broker capture not passed",
        T_NO_AGENT,
        "networkEnforcementDigest: agent capture not passed",
        T_HOST,
    }
    texts |= {"rbac: malformed " + field for field in B1_FIELDS}
    return texts


def test_refusal_texts_are_the_readme_table():
    """README 9: every refusal text is pinned in definitions.json refusalTexts; the table, expanded over <key>, is
    exactly that list, sorted, and equals the model's refusal_texts()."""
    pinned = DEFINITIONS["refusalTexts"]
    assert set(pinned) == readme_texts()
    assert len(pinned) == len(set(pinned)) == 90
    assert pinned == sorted(pinned)
    assert pod.refusal_texts() == pinned


def test_per_key_refusals_are_pinned():
    """README 9 and definitions.json: every per-key and capture-gate refusal is one of refusalTexts."""
    for group_name in ("projections", "enforcementDigests"):
        for key, value in DEFINITIONS[group_name].items():
            assert set(value["refusals"]) <= PINNED, key
    assert set(DEFINITIONS["captureGate"]["refusals"]) <= PINNED
    assert {row["refusal"] for row in DEFINITIONS["b1Refusals"]["rows"] if "<" not in row["refusal"]} <= PINNED


def test_definitions_are_the_model_definitions():
    """README 0: definitions.json equals the model's definitions()."""
    assert pod.definitions() == DEFINITIONS


def test_definitions_carry_the_readme_pins_and_bounds():
    """README header table (CS, PV, RD pins), 3.3 (the 90 s bound) and 4 (fixed identities)."""
    assert DEFINITIONS["wirePins"] == {
        "CS": {
            "path": "architecture/policy-observation-inputs/channel.schema.json",
            "sha256": "fb69b77201d9b6275a19667a5f5770537f382ddb11309095733628c8430bdc0e",
        },
        "PV": {
            "path": "architecture/policy-observation-inputs/vectors.json",
            "sha256": "1bfb46776636f800e38ab6a8f94a0989aa38513fb4a28ef18e61e732a115c124",
        },
        "RD": {
            "path": "docs/alpha-2/POLICY_OBSERVATION_READINESS.md",
            "sha256": "65778040919c5eb7335f2c104d983ca920b877b1b123f961556a6bcae36d232c",
        },
    }
    gate = DEFINITIONS["captureGate"]
    bound = gate["bound"]
    assert (bound["cycleMs"], bound["scrapeToSetMs"], bound["setBudgetMs"]) == (60_000, 5_000, 25_000)
    assert gate["boundMs"] == BOUND_MS == bound["cycleMs"] + bound["scrapeToSetMs"] + bound["setBudgetMs"]
    assert gate["gated"] == list(GATED)
    for key, (api_version, kind, name) in SYNTHETIC.items():
        identity = DEFINITIONS["projections"][key]["identity"]
        assert (identity["apiVersion"], identity["kind"], identity["name"]) == (api_version, kind, name)
        assert identity["uid"] == "DERIVED"
    for key, (api_version, kind, _list) in REAL.items():
        identity = DEFINITIONS["projections"][key]["identity"]
        assert (identity["apiVersion"], identity["kind"], identity["uid"]) == (api_version, kind, "LIVE")
