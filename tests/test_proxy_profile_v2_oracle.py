"""D5a oracle tests for workload profile v2 (CAMPAIGN_PROXY_MTLS_ZERO_COST_V2; LPK-1, packet MET-LIVE-004).

Black-box tests written outside the candidate (owner decision D5a). Every expectation comes from
architecture/proxy-profile-v2/README.md. The positive document is built here from the README and the closed
schema; it is not taken from any vector file. The model is used only through its public names: validate,
precondition, schema_error and the upper-case constants (TEXT, SCHEMA_ID, SCHEMA_SHA256, KEYWORDS).

The README does not list the ten proxy paths; they are written below from the case names of the model's public
CASES constant, as the path pattern `^/v1/linux-baseline/[a-z-]+$` reads them.
"""
from __future__ import annotations

import copy
import hashlib
import importlib.util
import json
import re
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
CONTRACT_DIR = ROOT / "architecture" / "proxy-profile-v2"
README_PATH = CONTRACT_DIR / "README.md"
SCHEMA_PATH = CONTRACT_DIR / "profile.schema.json"
STATUS_PATH = CONTRACT_DIR / "status.json"
MODEL_PATH = ROOT / "scripts" / "proxy_profile_v2.py"
MODEL_NAME = "proxy_profile_v2_under_oracle"


def _load_model():
    before = set(sys.modules)
    spec = importlib.util.spec_from_file_location(MODEL_NAME, MODEL_PATH)
    module = importlib.util.module_from_spec(spec)
    sys.modules[MODEL_NAME] = module
    spec.loader.exec_module(module)
    added = sorted({name.split(".")[0] for name in set(sys.modules) - before} - {MODEL_NAME})
    return module, added


MODEL, MODEL_ADDED_MODULES = _load_model()

try:  # jsonschema is optional: without it only the schema tests skip
    import jsonschema
    from jsonschema import Draft202012Validator
except ImportError:  # pragma: no cover
    jsonschema = None
    Draft202012Validator = None

needs_jsonschema = pytest.mark.skipif(jsonschema is None, reason="jsonschema absent: schema tests skip")

README = README_PATH.read_text(encoding="utf-8")
SCHEMA = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
STATUS = json.loads(STATUS_PATH.read_text(encoding="utf-8"))


# ---------------------------------------------------------------------------------------------------------------
# What the README states: refusal texts, rule codes, evaluation order
# ---------------------------------------------------------------------------------------------------------------

def _readme_table_texts():
    texts = {}
    for line in README.splitlines():
        match = re.match(r"^\| (P\d\d) \|.*\| `(P\d\d [^`]+)` \|\s*$", line)
        if match:
            texts[match.group(1)] = match.group(2)
    return texts


README_TABLE_TEXT = _readme_table_texts()
README_TEXT = dict(README_TABLE_TEXT)
README_TEXT["P40"] = re.search(r"`(P40 [^`]+)`", README).group(1)
README_TEXT["P99"] = re.search(r"`(P99 [^`]+)`", README).group(1)
README_P01_VERBATIM = re.search(r"\*\*P01's refusal text, verbatim\.\*\*.*?\n\n`(P01 [^`]+)`", README, re.S).group(1)

README_RULE_CODES = ["P00", "P01"] + ["P%02d" % n for n in range(2, 23)] + ["P30", "P32", "P33", "P34", "P35"]
# "The evaluation order": P01; P00; P02..P12; per resource P13, P14, P15, then for a Pod P16, P17, P35, P30, P32,
# P33, P34, for a Service P18; then P19..P22.
EVALUATION_ORDER = (["P01", "P00"] + ["P%02d" % n for n in range(2, 13)]
                    + ["P13", "P14", "P15", "P16", "P17", "P35", "P30", "P32", "P33", "P34", "P18"]
                    + ["P19", "P20", "P21", "P22"])


def refusal(code):
    """The exact refusal list for `code`: the model's TEXT entry, which must equal the README's text."""
    assert MODEL.TEXT[code] == README_TEXT[code]
    return [MODEL.TEXT[code]]


SECTION = {
    "files": "Files",
    "schema": "The schema: what changes, what is kept",
    "patterns": "The schema: what changes, what is kept (Patterns)",
    "kept": "The schema: what changes, what is kept (KEPT)",
    "model": "The model (scripts/proxy_profile_v2.py)",
    "table": "The model: the rule table",
    "p01": "The model: P01's full content",
    "p01text": "The model: P01's refusal text, verbatim",
    "order": "The model: The evaluation order",
    "p33": "The model: P33's reading",
    "p40": "The model: P40, the cross-contract precondition",
    "p99": "The model: P99, a defensive code with two uses",
    "validation": "The model: Schema validation",
    "cross": "The cross-contract statement",
    "vectors": "Vectors (vectors.json): the crossContract table, profile v2 and P40 columns",
    "v4table": "The rule table: what implies each v4 rule",
    "iface": "The interface's check names",
    "carried": "Carried steps and non-claims",
}


# ---------------------------------------------------------------------------------------------------------------
# The positive document, built from the README and the closed schema
# ---------------------------------------------------------------------------------------------------------------

SEALED_NAMESPACE = "planeon-qual"  # README, Vectors: "the sealed namespace `planeon-qual`"
OTHER_NAMESPACE = "lab-other"
PROFILE_ID_V2 = "CAMPAIGN_PROXY_MTLS_ZERO_COST_V2"
PROFILE_ID_V1 = "CAMPAIGN_PROXY_MTLS_ZERO_COST_V1"
SA_NAME = "probe-runner"
POD_NAME = "kit-probe"
CM_NAME = "kit-fixture"
SVC_NAME = "linux-baseline-probes"
EPHEMERAL = "805306368"
CACHE_SIZE = "402653184"
OUTPUT_SIZE = "134217728"
CLIENT = "CAMPAIGN_PROXY_CLIENT_MTLS"
SERVER = "KUBERNETES_PROXY_SERVER_MTLS"
VALID_FROM = "2026-10-24T10:00:00Z"
EXPIRES_AT = "2026-10-24T10:10:00Z"
ECHO_CONTAINERS = "planeon.ai/a2-containers"
ECHO_INIT = "planeon.ai/a2-init-containers"
ECHO_VOLUMES = "planeon.ai/a2-volumes"


def sha(label):
    return "sha256:" + hashlib.sha256(("lpk1-oracle-p2/" + label).encode("ascii")).hexdigest()


IMAGE = "registry.local/linux-probe@" + sha("probe-image")
OTHER_IMAGE = "registry.local/linux-probe-alt@" + sha("other-image")
CASE_NAMES = ["HOST_ISOLATION_NEGATIVES", "LINUX_TARGET_BUILD", "FULL_PREDECESSOR_REGRESSION",
              "CONTROL_CONTAINER_STARTUP", "POSTGRES_MIGRATION_AND_RLS", "DURABLE_RESTART", "ARBITRARY_NON_ROOT_UID",
              "READ_ONLY_ROOT_FILESYSTEM", "KUBERNETES_SMOKE", "DEFAULT_DENY_NETWORK"]
PROXY_PATHS = ["/v1/linux-baseline/" + name.lower().replace("_", "-") for name in CASE_NAMES]
PLURAL = {"Pod": "pods", "ConfigMap": "configmaps", "Service": "services"}
GRANT_VERBS = ["create", "get", "delete"]


def canonical_bytes(value):
    """The README's canonical JSON: sorted keys, no spaces, UTF-8, no NaN."""
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False,
                      allow_nan=False).encode("utf-8")


def manifest_digest(manifest):
    return "sha256:" + hashlib.sha256(canonical_bytes(manifest)).hexdigest()


def rehash(doc):
    """`rehash: true` as the README states it: every resource's manifestDigest recomputed."""
    for resource in doc["resources"]:
        resource["manifestDigest"] = manifest_digest(resource["manifest"])
    return doc


def binding_labels(binding):
    return {"planeon.ai/run-nonce": binding["runNonce"], "planeon.ai/tenant-id": binding["tenantId"]}


def build_pod(namespace, labels):
    quantities = {"cpu": "250m", "memory": "134217728", "ephemeral-storage": EPHEMERAL}
    return {
        "apiVersion": "v1",
        "kind": "Pod",
        "metadata": {
            "name": POD_NAME,
            "namespace": namespace,
            "labels": dict(labels),
            "annotations": {ECHO_CONTAINERS: "probe=" + IMAGE, ECHO_INIT: "", ECHO_VOLUMES: "cache,output"},
        },
        "spec": {
            "restartPolicy": "Never",
            "serviceAccountName": SA_NAME,
            "automountServiceAccountToken": False,
            "enableServiceLinks": False,
            "containers": [{
                "name": "probe",
                "image": IMAGE,
                "imagePullPolicy": "Never",
                "resources": {"requests": dict(quantities), "limits": dict(quantities)},
                "securityContext": {
                    "allowPrivilegeEscalation": False,
                    "readOnlyRootFilesystem": True,
                    "runAsNonRoot": True,
                    "runAsUser": 10001,
                    "seccompProfile": {"type": "RuntimeDefault"},
                    "capabilities": {"drop": ["ALL"]},
                },
                "volumeMounts": [{"name": "cache", "mountPath": "/work/cache"},
                                 {"name": "output", "mountPath": "/work/output"}],
            }],
            "volumes": [{"name": "cache", "emptyDir": {"sizeLimit": CACHE_SIZE}},
                        {"name": "output", "emptyDir": {"sizeLimit": OUTPUT_SIZE}}],
        },
    }


def build_configmap(namespace, labels):
    return {"apiVersion": "v1", "kind": "ConfigMap",
            "metadata": {"name": CM_NAME, "namespace": namespace, "labels": dict(labels)},
            "immutable": True, "data": {"fixture.json": "{\"cases\":10}"}}


def build_service(namespace, labels):
    return {"apiVersion": "v1", "kind": "Service",
            "metadata": {"name": SVC_NAME, "namespace": namespace, "labels": dict(labels)},
            "spec": {"type": "ClusterIP", "selector": dict(labels),
                     "ports": [{"name": "probe", "protocol": "TCP", "port": 9443, "targetPort": 9443}]}}


def derive_grants(doc):
    """P19, P20 and P21 as the README states them: the GVK and name grants, the API rules and localImages equal
    what the resources need."""
    binding = doc["binding"]
    gvks, rules, images = [], [], []
    for resource in doc["resources"]:
        manifest = resource["manifest"]
        kind, name = manifest["kind"], manifest["metadata"]["name"]
        entry = next((g for g in gvks if g["kind"] == kind), None)
        if entry is None:
            entry = {"apiGroup": "", "apiVersion": "v1", "kind": kind, "verbs": list(GRANT_VERBS), "names": []}
            gvks.append(entry)
        entry["names"].append(name)
        for verb in GRANT_VERBS:
            rules.append({"endpointId": binding["apiEndpointId"], "verb": verb, "apiGroup": "", "apiVersion": "v1",
                          "resource": PLURAL[kind], "namespace": binding["namespace"], "name": name,
                          "subresource": "", "requestMediaType": "application/json",
                          "responseMediaType": "application/json", "requestMaxBytes": 16384,
                          "responseMaxBytes": 4194304})
        if kind == "Pod":
            for container_entry in manifest["spec"]["containers"]:
                if container_entry["image"] not in images:
                    images.append(container_entry["image"])
    doc["capacityEntries"]["permittedGvksAndVerbs"] = gvks
    doc["capacityEntries"]["kubernetesApiRules"] = rules
    doc["localImages"] = images
    return doc


def new_ref(kind, name, uid, namespace=SEALED_NAMESPACE):
    return {"apiVersion": "v1", "kind": kind, "namespace": namespace, "name": name, "uid": uid,
            "observedDigest": sha("observed/" + uid)}


def build_positive(namespace=SEALED_NAMESPACE):
    binding = {
        "tenantId": "tenant-a",
        "environmentId": "env-qual",
        "runNonce": "run-0001",
        "capacityNonce": "cap-0001",
        "endpointId": "probe-proxy",
        "namespace": namespace,
        "serviceAccountSubject": "system:serviceaccount:%s:%s" % (namespace, SA_NAME),
        "validFrom": VALID_FROM,
        "expiresAt": EXPIRES_AT,
        "apiEndpointId": "kube-api",
    }
    labels = binding_labels(binding)
    credentials = [
        {"endpointId": binding["endpointId"], "purpose": CLIENT, "subject": binding["serviceAccountSubject"],
         "expiresAt": EXPIRES_AT, "certificateDigest": sha("client-cert"), "clientSpkiDigest": sha("client-spki")},
        {"endpointId": binding["apiEndpointId"], "purpose": SERVER, "subject": binding["serviceAccountSubject"],
         "expiresAt": EXPIRES_AT, "certificateDigest": sha("server-cert"), "clientSpkiDigest": sha("server-spki")},
    ]
    proxy_rule = {"endpointId": binding["endpointId"], "namespace": namespace, "service": "linux-baseline-probes",
                  "port": 9443, "protocol": "HTTPS", "methods": ["POST"], "paths": list(PROXY_PATHS),
                  "requestMediaType": "application/json", "responseMediaType": "application/json",
                  "requestMaxBytes": 16384, "responseMaxBytes": 4194304, "timeoutSeconds": 900}
    rq = new_ref("ResourceQuota", "probe-quota", "rq-uid-0001", namespace)
    lr = new_ref("LimitRange", "probe-limits", "lr-uid-0001", namespace)
    sa = new_ref("ServiceAccount", SA_NAME, "sa-uid-0001", namespace)
    policy = {
        "admissionPolicyDigest": sha("admission-policy"),
        "resourceQuotaDigest": rq["observedDigest"],
        "limitRangeDigest": lr["observedDigest"],
        "namespaceUid": "ns-uid-0001",
        "resourceQuotaUid": rq["uid"],
        "limitRangeUid": lr["uid"],
        "serviceAccountUid": sa["uid"],
        "rbacDigest": sha("rbac"),
        "networkPolicyDigest": sha("network-policy"),
        "mutationBrokerDigest": sha("mutation-broker"),
        "maxConcurrentOperations": 1,
        "serviceAccountDigest": sa["observedDigest"],
    }
    doc = {
        "profileId": PROFILE_ID_V2,
        "binding": binding,
        "capacityEntries": {
            "kubernetesApiRules": [],
            "campaignProxyRules": [proxy_rule],
            "permittedGvksAndVerbs": [],
            "preexistingResourceRefs": [rq, lr, sa],
            "preallocatedStorageRefs": [],
            "preallocatedAcceleratorRefs": [],
            "credentialIdentities": credentials,
        },
        "policy": policy,
        "quota": {"pods": 2, "configMaps": 2, "services": 2, "cpuMillis": 1000, "memoryBytes": 1073741824,
                  "ephemeralStorageBytes": 2147483648},
        "resources": [{"manifest": build_pod(namespace, labels), "manifestDigest": ""},
                      {"manifest": build_configmap(namespace, labels), "manifestDigest": ""},
                      {"manifest": build_service(namespace, labels), "manifestDigest": ""}],
        "localImages": [],
    }
    derive_grants(doc)
    return rehash(doc)


POSITIVE = build_positive()


def fresh():
    return copy.deepcopy(POSITIVE)


# accessors ------------------------------------------------------------------------------------------------------

def resource_of(doc, kind, nth=0):
    return [r for r in doc["resources"] if r["manifest"].get("kind") == kind][nth]


def manifest_of(doc, kind, nth=0):
    return resource_of(doc, kind, nth)["manifest"]


def pod(doc):
    return manifest_of(doc, "Pod")


def cm(doc):
    return manifest_of(doc, "ConfigMap")


def svc(doc):
    return manifest_of(doc, "Service")


def container(doc):
    return pod(doc)["spec"]["containers"][0]


def annotations(doc):
    return pod(doc)["metadata"]["annotations"]


def volumes(doc):
    return pod(doc)["spec"]["volumes"]


def mounts(doc):
    return container(doc)["volumeMounts"]


def volume(doc, name):
    return next(v for v in volumes(doc) if v["name"] == name)


def mount(doc, name):
    return next(m for m in mounts(doc) if m["name"] == name)


def quantities(doc, which):
    return container(doc)["resources"][which]


def refs(doc):
    return doc["capacityEntries"]["preexistingResourceRefs"]


def ref_of(doc, kind):
    return next(r for r in refs(doc) if r["kind"] == kind)


def creds(doc):
    return doc["capacityEntries"]["credentialIdentities"]


def cred_of(doc, purpose):
    return next(c for c in creds(doc) if c["purpose"] == purpose)


def proxy(doc):
    return doc["capacityEntries"]["campaignProxyRules"][0]


def gvks(doc):
    return doc["capacityEntries"]["permittedGvksAndVerbs"]


def api_rules(doc):
    return doc["capacityEntries"]["kubernetesApiRules"]


def _set(obj, key, value):
    obj[key] = value


def _del(obj, key):
    del obj[key]


def _nest(levels):
    value = 0
    for _ in range(levels):
        value = [value]
    return value


class _Str(str):
    """A str subclass: a string, but not an exact JSON builtin."""


LONE_SURROGATE = json.loads('"\\ud800"')


# ---------------------------------------------------------------------------------------------------------------
# Mutations of my own positive
# ---------------------------------------------------------------------------------------------------------------

class Mutation:
    def __init__(self, mid, code, section, intent, pre, *, rehash_after=True, post=None, base=None):
        self.mid, self.code, self.section, self.intent = mid, code, section, intent
        self.pre, self.rehash_after, self.post, self.base = pre, rehash_after, post, base

    def build(self):
        doc = self.base() if self.base is not None else fresh()
        self.pre(doc)
        if self.rehash_after:
            rehash(doc)
        if self.post is not None:
            self.post(doc)
        return doc


def build_no_resources():
    """P04 'none otherwise': a profile with no resources, so no API endpoint, server credential or grants."""
    doc = fresh()
    doc["resources"] = []
    doc["binding"]["apiEndpointId"] = None
    doc["capacityEntries"]["credentialIdentities"] = [cred_of(doc, CLIENT)]
    return derive_grants(doc)


def _no_volumes(doc):
    del pod(doc)["spec"]["volumes"]
    del container(doc)["volumeMounts"]
    annotations(doc)[ECHO_VOLUMES] = ""


def _volumes_empty_no_mounts(doc):
    pod(doc)["spec"]["volumes"] = []
    del container(doc)["volumeMounts"]
    annotations(doc)[ECHO_VOLUMES] = ""


def _add_volumes(doc, names, size="1048576"):
    for name in names:
        volumes(doc).append({"name": name, "emptyDir": {"sizeLimit": size}})


def _add_mounts(doc, names):
    for name in names:
        mounts(doc).append({"name": name, "mountPath": "/work/" + name})


def _kube_api_access_volume(doc):
    volume(doc, "output")["name"] = "kube-api-access-x1"
    mount(doc, "output").update(name="kube-api-access-x1", mountPath="/work/kube-api-access-x1")
    annotations(doc)[ECHO_VOLUMES] = "cache,kube-api-access-x1"


def _both_quantities(doc, key, value):
    quantities(doc, "requests")[key] = value
    quantities(doc, "limits")[key] = value


def _six_large_configmaps(doc):
    template = copy.deepcopy(cm(doc))
    kept = [r for r in doc["resources"] if r["manifest"]["kind"] != "ConfigMap"]
    for index in range(6):
        manifest = copy.deepcopy(template)
        manifest["metadata"]["name"] = "kit-fixture-%d" % index
        manifest["data"]["fixture.json"] = "\u0001" * 8192
        kept.insert(1 + index, {"manifest": manifest, "manifestDigest": ""})
    doc["resources"] = kept


def _swap_credentials(doc):
    creds(doc).reverse()


def _server_reuses_client(doc):
    client, server = cred_of(doc, CLIENT), cred_of(doc, SERVER)
    server["certificateDigest"] = client["certificateDigest"]
    server["clientSpkiDigest"] = client["clientSpkiDigest"]


def _duplicate_configmap(doc):
    twin = copy.deepcopy(cm(doc))
    twin["data"]["fixture.json"] = "{\"cases\":11}"
    doc["resources"].append({"manifest": twin, "manifestDigest": ""})


def _duplicate_volume_names(doc):
    volume(doc, "output")["name"] = "cache"
    annotations(doc)[ECHO_VOLUMES] = "cache,cache"


def _dup_names_one_mount(doc):
    _duplicate_volume_names(doc)
    container(doc)["volumeMounts"] = [{"name": "cache", "mountPath": "/work/cache"}]


def _dup_names_two_mounts(doc):
    _duplicate_volume_names(doc)
    container(doc)["volumeMounts"] = [{"name": "cache", "mountPath": "/work/cache"},
                                      {"name": "cache", "mountPath": "/work/cache"}]


def _single_volume_mounted_twice(doc):
    pod(doc)["spec"]["volumes"] = [{"name": "cache", "emptyDir": {"sizeLimit": CACHE_SIZE}}]
    annotations(doc)[ECHO_VOLUMES] = "cache"
    container(doc)["volumeMounts"] = [{"name": "cache", "mountPath": "/work/cache"},
                                      {"name": "cache", "mountPath": "/work/cache"}]


def _mounts_without_volumes(doc):
    del pod(doc)["spec"]["volumes"]
    annotations(doc)[ECHO_VOLUMES] = ""


def _one_volume(doc, size=CACHE_SIZE):
    pod(doc)["spec"]["volumes"] = [{"name": "cache", "emptyDir": {"sizeLimit": size}}]
    container(doc)["volumeMounts"] = [{"name": "cache", "mountPath": "/work/cache"}]
    annotations(doc)[ECHO_VOLUMES] = "cache"


def _four_volumes(doc):
    _add_volumes(doc, ["logs", "tmp"], OUTPUT_SIZE)  # 402653184 + 3 x 134217728 = 805306368, the limit
    _add_mounts(doc, ["logs", "tmp"])
    annotations(doc)[ECHO_VOLUMES] = "cache,output,logs,tmp"


def _pod_name_trailing_lf(doc):
    pod(doc)["metadata"]["name"] = "probe-pod\n"
    derive_grants(doc)


M = Mutation
S = SECTION
MUTATIONS = [
    # ---- the closed v2 schema (P00) -----------------------------------------------------------------------------
    M("P00-v1-profile-id", "P00", S["schema"], "change 0: a v1 profileId",
      lambda d: _set(d, "profileId", PROFILE_ID_V1)),
    M("P00-foreign-annotation", "P00", S["schema"], "change 1: annotations closed",
      lambda d: _set(annotations(d), "example.org/extra", "x")),
    M("P00-missing-volumes-echo", "P00", S["schema"], "change 1: a2-volumes required",
      lambda d: _del(annotations(d), ECHO_VOLUMES)),
    M("P00-missing-containers-echo", "P00", S["schema"], "change 1: a2-containers required",
      lambda d: _del(annotations(d), ECHO_CONTAINERS)),
    M("P00-annotations-absent", "P00", S["schema"], "change 1: annotations required",
      lambda d: _del(pod(d)["metadata"], "annotations")),
    M("P00-init-echo-nonempty", "P00", S["schema"], "change 1: a2-init-containers const empty",
      lambda d: _set(annotations(d), ECHO_INIT, "probe=" + IMAGE)),
    M("P00-containers-echo-pattern", "P00", S["schema"], "change 1: a2-containers pattern probe=<image>",
      lambda d: _set(annotations(d), ECHO_CONTAINERS, "main=" + IMAGE)),
    M("P00-volumes-echo-five-names", "P00", S["schema"], "change 1: a2-volumes at most four names",
      lambda d: _set(annotations(d), ECHO_VOLUMES, "a,b,c,d,e")),
    M("P00-configmap-annotations", "P00", S["schema"], "change 1: ConfigMap metadata closed, no annotations",
      lambda d: _set(cm(d)["metadata"], "annotations", {})),
    M("P00-service-annotations", "P00", S["schema"], "change 1: Service metadata closed, no annotations",
      lambda d: _set(svc(d)["metadata"], "annotations", {ECHO_VOLUMES: ""})),
    M("P00-pod-name-dot", "P00", S["schema"], "change 2: DNS label (X03)",
      lambda d: _set(pod(d)["metadata"], "name", "kit.probe")),
    M("P00-pod-name-trailing-dash", "P00", S["schema"], "change 2: DNS label (X04)",
      lambda d: _set(pod(d)["metadata"], "name", "kit-probe-")),
    M("P00-pod-name-64", "P00", S["schema"], "change 2: maxLength 63",
      lambda d: _set(pod(d)["metadata"], "name", "p" * 64)),
    M("P00-pod-name-uppercase", "P00", S["schema"], "change 2: DNS label",
      lambda d: _set(pod(d)["metadata"], "name", "Kit-probe")),
    M("P00-configmap-kube-root-ca", "P00", S["schema"], "change 2: a ConfigMap cannot be kube-root-ca.crt",
      lambda d: _set(cm(d)["metadata"], "name", "kube-root-ca.crt")),
    M("P00-configmap-name-dot", "P00", S["schema"], "change 2: DNS label for ConfigMaps (X15)",
      lambda d: _set(cm(d)["metadata"], "name", "kit.fixture")),
    M("P00-service-name-dot", "P00", S["schema"], "change 2: DNS label for Services",
      lambda d: _set(svc(d)["metadata"], "name", "linux.baseline")),
    M("P00-host-network-false", "P00", S["schema"], "change 3: hostNetwork forbidden even as false (X02)",
      lambda d: _set(pod(d)["spec"], "hostNetwork", False)),
    M("P00-host-pid-false", "P00", S["schema"], "change 3: hostPID forbidden",
      lambda d: _set(pod(d)["spec"], "hostPID", False)),
    M("P00-host-ipc-false", "P00", S["schema"], "change 3: hostIPC forbidden",
      lambda d: _set(pod(d)["spec"], "hostIPC", False)),
    M("P00-volumes-empty", "P00", S["schema"], "change 4: volumes minItems 1",
      lambda d: _set(pod(d)["spec"], "volumes", [])),
    M("P00-volumes-empty-no-mounts", "P00", S["schema"], "change 4: volumes minItems 1, nothing else wrong",
      _volumes_empty_no_mounts),
    M("P00-volumes-five", "P00", S["schema"], "change 4: volumes maxItems 4",
      lambda d: _add_volumes(d, ["logs", "tmp", "spool"])),
    M("P00-volume-medium-memory", "P00", S["schema"], "change 4: medium forbidden (X11)",
      lambda d: _set(volume(d, "cache")["emptyDir"], "medium", "Memory")),
    M("P00-volume-no-sizelimit", "P00", S["schema"], "change 4: sizeLimit required (X09)",
      lambda d: _set(volume(d, "cache"), "emptyDir", {})),
    M("P00-volume-hostpath", "P00", S["schema"], "change 4: every other source forbidden",
      lambda d: _set(volumes(d), 0, {"name": "cache", "hostPath": {"path": "/var/tmp"}})),
    M("P00-volume-pvc", "P00", S["schema"], "change 4: every other source forbidden",
      lambda d: _set(volumes(d), 0, {"name": "cache", "persistentVolumeClaim": {"claimName": "data"}})),
    M("P00-volume-emptydir-plus-hostpath", "P00", S["schema"], "change 4: entry closed to {name, emptyDir}",
      lambda d: _set(volume(d, "cache"), "hostPath", {"path": "/var/tmp"})),
    M("P00-volume-kube-api-access", "P00", S["schema"], "change 4: never kube-api-access-* (X06)",
      _kube_api_access_volume),
    M("P00-sizelimit-suffix", "P00", S["schema"], "change 4: decimal byte form",
      lambda d: _set(volume(d, "cache")["emptyDir"], "sizeLimit", "512Mi")),
    M("P00-sizelimit-zero", "P00", S["schema"], "change 4: ^[1-9][0-9]{0,14}$",
      lambda d: _set(volume(d, "cache")["emptyDir"], "sizeLimit", "0")),
    M("P00-sizelimit-leading-zero", "P00", S["schema"], "change 4: ^[1-9][0-9]{0,14}$",
      lambda d: _set(volume(d, "cache")["emptyDir"], "sizeLimit", "0402653184")),
    M("P00-sizelimit-16-digits", "P00", S["schema"], "change 4: at most 15 digits",
      lambda d: _set(volume(d, "cache")["emptyDir"], "sizeLimit", "1" + "0" * 15)),
    M("P00-sizelimit-integer", "P00", S["schema"], "change 4: sizeLimit is a string",
      lambda d: _set(volume(d, "cache")["emptyDir"], "sizeLimit", 402653184)),
    M("P00-mounts-empty", "P00", S["schema"], "change 5: volumeMounts minItems 1",
      lambda d: _set(container(d), "volumeMounts", [])),
    M("P00-mounts-five", "P00", S["schema"], "change 5: volumeMounts maxItems 4",
      lambda d: _add_mounts(d, ["logs", "tmp", "spool"])),
    M("P00-mount-outside-work", "P00", S["schema"], "change 5: mountPath pattern /work/<name>",
      lambda d: _set(mount(d, "cache"), "mountPath", "/data/cache")),
    M("P00-mount-work-root", "P00", S["schema"], "change 5: mountPath pattern /work/<name>",
      lambda d: _set(mount(d, "cache"), "mountPath", "/work/")),
    M("P00-mount-subpath", "P00", S["schema"], "change 5: mountPath pattern /work/<name>",
      lambda d: _set(mount(d, "cache"), "mountPath", "/work/cache/sub")),
    M("P00-mount-readonly-member", "P00", S["schema"], "change 5: entry closed to {name, mountPath}",
      lambda d: _set(mount(d, "cache"), "readOnly", True)),
    M("P00-rootfs-false", "P00", S["schema"], "change 5: readOnlyRootFilesystem stays required true",
      lambda d: _set(container(d)["securityContext"], "readOnlyRootFilesystem", False)),
    M("P00-rootfs-missing", "P00", S["schema"], "change 5: readOnlyRootFilesystem stays required",
      lambda d: _del(container(d)["securityContext"], "readOnlyRootFilesystem")),
    M("P00-pull-always", "P00", S["schema"], "change 7: imagePullPolicy const Never (X08)",
      lambda d: _set(container(d), "imagePullPolicy", "Always")),
    M("P00-pull-ifnotpresent", "P00", S["schema"], "change 7: imagePullPolicy const Never",
      lambda d: _set(container(d), "imagePullPolicy", "IfNotPresent")),
    M("P00-pull-missing", "P00", S["schema"], "change 7: imagePullPolicy required",
      lambda d: _del(container(d), "imagePullPolicy")),
    M("P00-init-containers", "P00", S["schema"], "change 1: initContainers stays forbidden",
      lambda d: _set(pod(d)["spec"], "initContainers", [copy.deepcopy(container(d))])),
    M("P00-port-boolean", "P00", S["schema"], "integer type: a boolean is not an integer",
      lambda d: _set(svc(d)["spec"]["ports"][0], "port", True)),
    M("P00-port-negative-in-range", "P00", S["p01"], "-(2^53-1) is inside P01's integer range, so P00 refuses",
      lambda d: _set(svc(d)["spec"]["ports"][0], "port", -(2 ** 53 - 1))),
    M("P00-automount-true", "P00", S["kept"], "KEPT: automountServiceAccountToken const false",
      lambda d: _set(pod(d)["spec"], "automountServiceAccountToken", True)),
    M("P00-restart-always", "P00", S["kept"], "KEPT: restartPolicy",
      lambda d: _set(pod(d)["spec"], "restartPolicy", "Always")),
    M("P00-containers-two", "P00", S["kept"], "KEPT: one probe container",
      lambda d: pod(d)["spec"]["containers"].append(copy.deepcopy(container(d)))),
    M("P00-image-underscore", "P00", S["v4table"], "MC33: the image pattern has no _",
      lambda d: _set(container(d), "image", "registry.local/linux_probe@" + sha("probe-image"))),
    M("P00-ephemeral-limit-missing", "P00", S["v4table"], "MC34/MC42: ephemeral-storage limit required",
      lambda d: _del(quantities(d, "limits"), "ephemeral-storage")),
    M("P00-service-nodeport", "P00", S["v4table"], "MC20: type const ClusterIP",
      lambda d: _set(svc(d)["spec"], "type", "NodePort")),
    M("P00-service-clusterip-member", "P00", S["v4table"], "MC21: spec closed to {type, selector, ports}",
      lambda d: _set(svc(d)["spec"], "clusterIP", "10.0.0.10")),
    M("P00-service-port-nodeport", "P00", S["v4table"], "MC22: ports closed",
      lambda d: _set(svc(d)["spec"]["ports"][0], "nodePort", 30000)),
    M("P00-pod-status", "P00", S["v4table"], "MC03/MC05: closed manifests, no status",
      lambda d: _set(pod(d), "status", {})),
    M("P00-tolerations", "P00", S["v4table"], "MC30: no tolerations",
      lambda d: _set(pod(d)["spec"], "tolerations", [])),
    M("P00-node-name", "P00", S["v4table"], "MC30: no node",
      lambda d: _set(pod(d)["spec"], "nodeName", "node-1")),
    M("P00-image-pull-secrets", "P00", S["v4table"], "A2-POD-PULL-SECRETS: no imagePullSecrets",
      lambda d: _set(pod(d)["spec"], "imagePullSecrets", [])),
    M("P00-affinity", "P00", S["v4table"], "MC38-MC41: no affinity",
      lambda d: _set(pod(d)["spec"], "affinity", {})),
    M("P00-configmap-mutable", "P00", S["v4table"], "MC10: immutable const true",
      lambda d: _set(cm(d), "immutable", False)),
    M("P00-run-as-user-low", "P00", S["iface"], "runAsUser >= 10000 (KEPT)",
      lambda d: _set(container(d)["securityContext"], "runAsUser", 9999)),
    M("P00-privilege-escalation", "P00", S["iface"], "allowPrivilegeEscalation const false (KEPT)",
      lambda d: _set(container(d)["securityContext"], "allowPrivilegeEscalation", True)),
    M("P00-run-as-root-allowed", "P00", S["iface"], "runAsNonRoot (KEPT)",
      lambda d: _set(container(d)["securityContext"], "runAsNonRoot", False)),
    M("P00-capabilities-kept", "P00", S["iface"], "drop: [ALL] (KEPT)",
      lambda d: _set(container(d)["securityContext"]["capabilities"], "drop", [])),
    M("P00-seccomp-unconfined", "P00", S["iface"], "RuntimeDefault (KEPT)",
      lambda d: _set(container(d)["securityContext"]["seccompProfile"], "type", "Unconfined")),
    M("P00-sizelimit-two-line-feeds", "P00", S["patterns"], "re.search: $ matches before ONE trailing line feed only",
      lambda d: _set(volume(d, "cache")["emptyDir"], "sizeLimit", "536870912\n\n")),
    M("P00-sizelimit-leading-line-feed", "P00", S["patterns"], "re.search with ^: a leading line feed fails",
      lambda d: _set(volume(d, "cache")["emptyDir"], "sizeLimit", "\n536870912")),
    M("P00-sizelimit-crlf", "P00", S["patterns"], "$ does not match before a trailing CR LF",
      lambda d: _set(volume(d, "cache")["emptyDir"], "sizeLimit", "536870912\r\n")),

    # ---- P01 -----------------------------------------------------------------------------------------------------
    M("P01-integral-float-port", "P01", S["p01"], "9443.0: an integral float, schema-valid, P01 alone refuses",
      lambda d: _set(svc(d)["spec"]["ports"][0], "port", 9443.0)),
    M("P01-noninteger-float", "P01", S["p01"], "0.5: fails P00 as well, P01 runs first",
      lambda d: _set(d["quota"], "cpuMillis", 0.5)),
    M("P01-nan", "P01", S["p01"], "NaN is a float",
      lambda d: _set(d["quota"], "memoryBytes", float("nan"))),
    M("P01-infinity", "P01", S["p01"], "an infinity is a float",
      lambda d: _set(d["quota"], "memoryBytes", float("inf"))),
    M("P01-depth", "P01", S["p01"], "depth well over 16 (and outside the schema): P01 before P00",
      lambda d: _set(d, "deep", _nest(20))),
    M("P01-budget-string", "P01", S["p01"], "one string over the 262144 size budget",
      lambda d: _set(d, "big", "x" * 262145)),
    M("P01-budget-key", "P01", S["p01"], "keys included: one key over the size budget",
      lambda d: _set(d, "k" * 262145, 1)),
    M("P01-canonical-size", "P01", S["p01"], "within the budget, canonical form over 262144 bytes",
      lambda d: _set(d, "many", ["a"] * 70000)),
    M("P01-canonical-size-schema-valid", "P01", S["p01"], "schema-valid, canonical form over 262144 bytes",
      _six_large_configmaps),
    M("P01-integer-above-range", "P01", S["p01"], "2^53 is outside +-(2^53-1)",
      lambda d: _set(d["quota"], "pods", 2 ** 53)),
    M("P01-integer-below-range", "P01", S["p01"], "-(2^53) is outside +-(2^53-1)",
      lambda d: _set(svc(d)["spec"]["ports"][0], "port", -(2 ** 53))),
    M("P01-lone-surrogate", "P01", S["p01"], "a lone surrogate cannot be encoded as UTF-8",
      lambda d: _set(cm(d)["data"], "fixture.json", LONE_SURROGATE), rehash_after=False),
    M("P01-non-string-key", "P01", S["p01"], "an object with a non-string key",
      lambda d: _set(d["binding"], 7, "x")),
    M("P01-tuple", "P01", S["p01"], "a tuple is not an exact JSON builtin",
      lambda d: _set(d, "localImages", tuple(d["localImages"]))),
    M("P01-str-subclass", "P01", S["p01"], "a str subclass is not an exact JSON builtin",
      lambda d: _set(d["binding"], "tenantId", _Str(d["binding"]["tenantId"]))),

    # ---- the rule table, P02-P22 ------------------------------------------------------------------------------------
    M("P02-window-901", "P02", S["table"], "expiresAt - validFrom = 901 s",
      lambda d: _set(d["binding"], "validFrom", "2026-10-24T09:54:59Z")),
    M("P02-window-zero", "P02", S["table"], "expiresAt - validFrom = 0",
      lambda d: _set(d["binding"], "validFrom", EXPIRES_AT)),
    M("P02-window-negative", "P02", S["table"], "expiresAt before validFrom",
      lambda d: _set(d["binding"], "validFrom", "2026-10-24T10:20:00Z")),
    M("P02-not-a-date", "P02", S["table"], "not a canonical UTC time (30 February)",
      lambda d: _set(d["binding"], "validFrom", "2026-02-30T10:00:00Z")),
    M("P03-subject-other-namespace", "P03", S["table"], "the subject's namespace is not the binding's",
      lambda d: _set(d["binding"], "serviceAccountSubject", "system:serviceaccount:%s:%s" % (OTHER_NAMESPACE, SA_NAME))),
    M("P04-api-endpoint-null", "P04", S["table"], "resources but no API endpoint",
      lambda d: _set(d["binding"], "apiEndpointId", None)),
    M("P04-api-endpoint-reused", "P04", S["table"], "the API endpoint reuses the proxy endpoint",
      lambda d: _set(d["binding"], "apiEndpointId", d["binding"]["endpointId"])),
    M("P04-api-endpoint-unused", "P04", S["table"], "no resources but an API endpoint",
      lambda d: _set(d["binding"], "apiEndpointId", "kube-api"), base=build_no_resources),
    M("P05-server-credential-missing", "P05", S["table"], "the server credential is missing",
      lambda d: creds(d).remove(cred_of(d, SERVER))),
    M("P05-server-before-client", "P05", S["table"], "the inventory order is client, then server",
      _swap_credentials),
    M("P06-client-expiry", "P06", S["table"], "a credential's expiry differs from the binding",
      lambda d: _set(cred_of(d, CLIENT), "expiresAt", "2026-10-24T10:09:59Z")),
    M("P06-server-subject", "P06", S["table"], "a credential's subject differs from the binding",
      lambda d: _set(cred_of(d, SERVER), "subject", "system:serviceaccount:%s:other-sa" % SEALED_NAMESPACE)),
    M("P07-server-reuses-client", "P07", S["table"], "client and server credentials reused",
      _server_reuses_client),
    M("P08-path-replaced", "P08", S["table"], "one of the ten paths replaced",
      lambda d: _set(proxy(d)["paths"], 0, "/v1/linux-baseline/other-case")),
    M("P08-namespace", "P08", S["table"], "the proxy rule's namespace differs",
      lambda d: _set(proxy(d), "namespace", OTHER_NAMESPACE)),
    M("P08-endpoint", "P08", S["table"], "the proxy rule's endpoint differs",
      lambda d: _set(proxy(d), "endpointId", "other-proxy")),
    M("P09-foreign-reference", "P09", S["table"], "a preexisting reference outside the binding namespace",
      lambda d: refs(d).append(new_ref("ConfigMap", "foreign-cm", "foreign-uid-1", OTHER_NAMESPACE))),
    M("P09-duplicate-reference", "P09", S["table"], "the same ServiceAccount referenced twice",
      lambda d: refs(d).append(new_ref("ServiceAccount", SA_NAME, "sa-uid-0002"))),
    M("P10-limit-range-digest", "P10", S["table"], "the policy's limit range digest differs from the reference",
      lambda d: _set(d["policy"], "limitRangeDigest", sha("another-limit-range"))),
    M("P10-service-account-uid", "P10", S["table"], "the policy's service account uid differs",
      lambda d: _set(d["policy"], "serviceAccountUid", "sa-uid-9999")),
    M("P10-quota-reference-missing", "P10", S["table"], "the quota reference is missing",
      lambda d: refs(d).remove(ref_of(d, "ResourceQuota"))),
    M("P11-service-account-ref-name", "P11", S["table"], "the ServiceAccount reference names another account",
      lambda d: _set(ref_of(d, "ServiceAccount"), "name", "other-sa")),
    M("P12-duplicate-uid", "P12", S["table"], "two references share one uid",
      lambda d: refs(d).extend([new_ref("ConfigMap", "seed-a", "seed-uid-1"),
                                new_ref("ConfigMap", "seed-b", "seed-uid-1")])),
    M("P13-pod-digest", "P13", S["table"], "the Pod's manifestDigest is wrong",
      lambda d: None, post=lambda d: _set(resource_of(d, "Pod"), "manifestDigest", sha("not-the-pod"))),
    M("P13-service-digest-stale", "P13", S["table"], "the Service changed after hashing",
      lambda d: None, post=lambda d: svc(d)["spec"]["ports"][0].update(port=9444, targetPort=9444)),
    M("P13-configmap-over-16384", "P13", S["table"], "a schema-valid ConfigMap over 16384 canonical bytes",
      lambda d: _set(cm(d)["data"], "fixture.json", "\u0001" * 8192)),
    M("P14-configmap-namespace", "P14", S["table"], "a resource outside the binding namespace",
      lambda d: _set(cm(d)["metadata"], "namespace", OTHER_NAMESPACE)),
    M("P14-service-label", "P14", S["table"], "a resource label differs from the binding",
      lambda d: _set(svc(d)["metadata"]["labels"], "planeon.ai/tenant-id", "tenant-b")),
    M("P14-pod-label", "P14", S["table"], "the Pod's run-nonce label differs from the binding",
      lambda d: _set(pod(d)["metadata"]["labels"], "planeon.ai/run-nonce", "run-0002")),
    M("P14-duplicate-logical-identity", "P14", S["table"], "two ConfigMaps with one name",
      _duplicate_configmap),
    M("P15-configmap-takeover", "P15", S["table"], "the ConfigMap takes over a preexisting ConfigMap",
      lambda d: refs(d).append(new_ref("ConfigMap", CM_NAME, "cm-pre-uid-1"))),
    M("P15-service-takeover", "P15", S["table"], "the Service takes over a preexisting Service",
      lambda d: refs(d).append(new_ref("Service", SVC_NAME, "svc-pre-uid-1"))),
    M("P16-pod-service-account", "P16", S["table"], "the Pod's service account is not the subject's",
      lambda d: _set(pod(d)["spec"], "serviceAccountName", "other-sa")),
    M("P17-memory-request", "P17", S["table"], "memory request below the limit",
      lambda d: _set(quantities(d, "requests"), "memory", "67108864")),
    M("P17-cpu-request", "P17", S["table"], "cpu request below the limit (X07)",
      lambda d: _set(quantities(d, "requests"), "cpu", "200m")),
    M("P17-ephemeral-request", "P17", S["table"], "ephemeral-storage request below the limit",
      lambda d: _set(quantities(d, "requests"), "ephemeral-storage", "536870912")),
    M("P18-selector-nonce", "P18", S["table"], "the selector's run-nonce differs",
      lambda d: _set(svc(d)["spec"]["selector"], "planeon.ai/run-nonce", "run-0002")),
    M("P18-selector-tenant", "P18", S["table"], "the selector's tenant differs",
      lambda d: _set(svc(d)["spec"]["selector"], "planeon.ai/tenant-id", "tenant-b")),
    M("P19-pod-names", "P19", S["table"], "the Pod grant names another Pod",
      lambda d: _set(gvks(d)[0], "names", ["other-pod"])),
    M("P19-service-grant-missing", "P19", S["table"], "no grant for the Service",
      lambda d: gvks(d).pop()),
    M("P20-rule-missing", "P20", S["table"], "an API rule is missing",
      lambda d: api_rules(d).pop()),
    M("P20-rule-name", "P20", S["table"], "an API rule names another object",
      lambda d: _set(api_rules(d)[3], "name", "other-cm")),
    M("P20-rule-endpoint", "P20", S["table"], "an API rule on the proxy endpoint",
      lambda d: _set(api_rules(d)[0], "endpointId", "probe-proxy")),
    M("P21-other-image", "P21", S["table"], "localImages names another image",
      lambda d: _set(d, "localImages", [OTHER_IMAGE])),
    M("P21-extra-image", "P21", S["table"], "localImages has an image no Pod uses",
      lambda d: _set(d, "localImages", [IMAGE, OTHER_IMAGE])),
    M("P21-no-images", "P21", S["table"], "localImages empty with a Pod",
      lambda d: _set(d, "localImages", [])),
    M("P22-pods-zero", "P22", S["table"], "quota of zero Pods",
      lambda d: _set(d["quota"], "pods", 0)),
    M("P22-configmaps-zero", "P22", S["table"], "quota of zero ConfigMaps",
      lambda d: _set(d["quota"], "configMaps", 0)),
    M("P22-services-zero", "P22", S["table"], "quota of zero Services",
      lambda d: _set(d["quota"], "services", 0)),

    # ---- the new Pod rules, P30-P35 -------------------------------------------------------------------------------
    M("P30-containers-echo-other-image", "P30", S["table"], "the containers echo names another image (X12)",
      lambda d: _set(annotations(d), ECHO_CONTAINERS, "probe=" + OTHER_IMAGE)),
    M("P30-containers-echo-trailing-lf", "P30", S["patterns"], "schema-valid echo + LF is not probe=<image>",
      lambda d: _set(annotations(d), ECHO_CONTAINERS, "probe=" + IMAGE + "\n")),
    M("P32-volumes-echo-reversed", "P32", S["table"], "the volumes echo in another order (X13)",
      lambda d: _set(annotations(d), ECHO_VOLUMES, "output,cache")),
    M("P32-volumes-echo-empty", "P32", S["table"], "an empty volumes echo with two volumes",
      lambda d: _set(annotations(d), ECHO_VOLUMES, "")),
    M("P32-volumes-echo-missing-name", "P32", S["table"], "the volumes echo misses a volume",
      lambda d: _set(annotations(d), ECHO_VOLUMES, "cache")),
    M("P32-volumes-echo-without-volumes", "P32", S["table"], "a volumes echo with no volumes",
      lambda d: (_no_volumes(d), _set(annotations(d), ECHO_VOLUMES, "cache"))),
    M("P32-volumes-echo-trailing-lf", "P32", S["patterns"], "schema-valid echo + LF is not the joined names",
      lambda d: _set(annotations(d), ECHO_VOLUMES, "cache,output\n")),
    M("P33-undeclared-extra-mount", "P33", S["p33"], "a mount naming an undeclared volume",
      lambda d: _add_mounts(d, ["extra"])),
    M("P33-undeclared-replacing-mount", "P33", S["p33"], "a mount names an undeclared volume instead of output",
      lambda d: mount(d, "output").update(name="extra", mountPath="/work/extra")),
    M("P33-mounts-without-volumes", "P33", S["p33"], "mounts with no volumes",
      _mounts_without_volumes),
    M("P33-volume-mounted-twice", "P33", S["p33"], "one volume mounted twice",
      lambda d: _set(container(d), "volumeMounts", [{"name": "cache", "mountPath": "/work/cache"},
                                                     {"name": "cache", "mountPath": "/work/cache"},
                                                     {"name": "output", "mountPath": "/work/output"}])),
    M("P33-single-volume-mounted-twice", "P33", S["p33"], "the only volume mounted twice",
      _single_volume_mounted_twice),
    M("P33-mount-path-other-name", "P33", S["p33"], "a mountPath at /work/<another name>",
      lambda d: _set(mount(d, "cache"), "mountPath", "/work/output")),
    M("P33-mount-path-suffix", "P33", S["p33"], "a mountPath other than /work/<name>",
      lambda d: _set(mount(d, "cache"), "mountPath", "/work/cache-2")),
    M("P33-mount-path-trailing-lf", "P33", S["patterns"], "schema-valid mountPath + LF is not /work/<name>",
      lambda d: _set(mount(d, "cache"), "mountPath", "/work/cache\n")),
    M("P33-unmounted-volume", "P33", S["p33"], "a volume not mounted",
      lambda d: _set(container(d), "volumeMounts", [{"name": "cache", "mountPath": "/work/cache"}])),
    M("P33-no-mounts-member", "P33", S["p33"], "volumes but no volumeMounts member",
      lambda d: _del(container(d), "volumeMounts")),
    M("P34-sum-over-by-one", "P34", S["table"], "sizeLimits one byte over the limit (X10)",
      lambda d: _set(volume(d, "cache")["emptyDir"], "sizeLimit", str(int(EPHEMERAL) - int(OUTPUT_SIZE) + 1))),
    M("P34-limit-below-sum", "P34", S["table"], "the ephemeral-storage limit one byte under the sum",
      lambda d: _both_quantities(d, "ephemeral-storage", str(int(CACHE_SIZE) + int(OUTPUT_SIZE) - 1))),
    M("P34-single-volume-over", "P34", S["table"], "one volume over the limit",
      lambda d: _one_volume(d, str(int(EPHEMERAL) + 1))),
    M("P35-duplicate-volume-names", "P35", S["table"], "two volumes named cache",
      _duplicate_volume_names),
    M("P35-before-P33-one-mount", "P35", S["p33"], "duplicate names and one mount: P35, never P33",
      _dup_names_one_mount),
    M("P35-before-P33-two-mounts", "P35", S["p33"], "duplicate names each mounted: P35, never P33",
      _dup_names_two_mounts),

    # ---- P99 ---------------------------------------------------------------------------------------------------
    M("P99-cpu-trailing-lf", "P99", S["p99"], "cpu request and limit equal and ending in one line feed",
      lambda d: _both_quantities(d, "cpu", "250m\n")),
]
BY_ID = {m.mid: m for m in MUTATIONS}
assert len(BY_ID) == len(MUTATIONS)


def _variant(fn, base=None):
    def build():
        doc = base() if base is not None else fresh()
        fn(doc)
        return rehash(doc)
    return build


VALID = [
    ("valid-positive", S["schema"], fresh),
    ("valid-window-900", S["table"], _variant(lambda d: _set(d["binding"], "validFrom", "2026-10-24T09:55:00Z"))),
    ("valid-sizelimits-equal-limit", S["table"],
     _variant(lambda d: _set(volume(d, "cache")["emptyDir"], "sizeLimit", str(int(EPHEMERAL) - int(OUTPUT_SIZE))))),
    ("valid-mounts-reordered", S["p33"], _variant(lambda d: mounts(d).reverse())),
    ("valid-no-volumes-no-mounts", S["vectors"], _variant(_no_volumes)),
    ("valid-one-volume", S["schema"], _variant(_one_volume)),
    ("valid-four-volumes", S["schema"], _variant(_four_volumes)),
    ("valid-integer-max", S["p01"], _variant(lambda d: _set(d["quota"], "pods", 2 ** 53 - 1))),
    ("valid-configmap-8192-ascii", S["table"], _variant(lambda d: _set(cm(d)["data"], "fixture.json", "x" * 8192))),
    ("valid-run-as-user-10000", S["iface"],
     _variant(lambda d: _set(container(d)["securityContext"], "runAsUser", 10000))),
    ("valid-other-namespace", S["p40"], lambda: build_positive(OTHER_NAMESPACE)),
    ("valid-no-resources", S["table"], build_no_resources),
]

PATTERN_ACCEPTED = [
    ("pattern-sizelimit-trailing-lf", _variant(lambda d: _set(volume(d, "cache")["emptyDir"], "sizeLimit",
                                                               "536870912\n"))),
    ("pattern-ephemeral-trailing-lf", _variant(lambda d: _both_quantities(d, "ephemeral-storage", "536870912\n"))),
    ("pattern-pod-name-trailing-lf", _variant(_pod_name_trailing_lf)),
]

ORDER_PAIRS = [
    ("P01-integral-float-port", "P00-v1-profile-id", "P01"),
    ("P00-v1-profile-id", "P02-window-901", "P00"),
    ("P02-window-901", "P03-subject-other-namespace", "P02"),
    ("P03-subject-other-namespace", "P04-api-endpoint-null", "P03"),
    ("P04-api-endpoint-null", "P05-server-credential-missing", "P04"),
    ("P05-server-credential-missing", "P06-client-expiry", "P05"),
    ("P06-client-expiry", "P07-server-reuses-client", "P06"),
    ("P07-server-reuses-client", "P08-path-replaced", "P07"),
    ("P08-path-replaced", "P09-foreign-reference", "P08"),
    ("P09-foreign-reference", "P10-limit-range-digest", "P09"),
    ("P10-limit-range-digest", "P11-service-account-ref-name", "P10"),
    ("P11-service-account-ref-name", "P12-duplicate-uid", "P11"),
    ("P12-duplicate-uid", "P13-pod-digest", "P12"),
    ("P13-pod-digest", "P14-pod-label", "P13"),
    ("P14-pod-label", "P16-pod-service-account", "P14"),
    ("P16-pod-service-account", "P17-memory-request", "P16"),
    ("P17-memory-request", "P35-duplicate-volume-names", "P17"),
    ("P35-duplicate-volume-names", "P30-containers-echo-other-image", "P35"),
    ("P30-containers-echo-other-image", "P32-volumes-echo-reversed", "P30"),
    ("P32-volumes-echo-reversed", "P33-mount-path-suffix", "P32"),
    ("P33-mount-path-suffix", "P34-sum-over-by-one", "P33"),
    ("P34-sum-over-by-one", "P13-service-digest-stale", "P34"),
    ("P34-sum-over-by-one", "P14-configmap-namespace", "P34"),
    ("P14-configmap-namespace", "P15-configmap-takeover", "P14"),
    ("P15-configmap-takeover", "P18-selector-nonce", "P15"),
    ("P18-selector-nonce", "P19-pod-names", "P18"),
    ("P19-pod-names", "P20-rule-missing", "P19"),
    ("P20-rule-missing", "P21-other-image", "P20"),
    ("P21-other-image", "P22-pods-zero", "P21"),
    # the table's row order is not the evaluation order: P35 runs before P30, P32, P33 and P34
    ("P35-duplicate-volume-names", "P34-sum-over-by-one", "P35"),
    ("P35-duplicate-volume-names", "P32-volumes-echo-reversed", "P35"),
    ("P17-cpu-request", "P34-sum-over-by-one", "P17"),
    ("P16-pod-service-account", "P30-containers-echo-other-image", "P16"),
    # every rule of one resource before any rule of the next; P19-P22 after every resource
    ("P33-unmounted-volume", "P13-service-digest-stale", "P33"),
    ("P18-selector-nonce", "P22-pods-zero", "P18"),
    ("P12-duplicate-uid", "P35-duplicate-volume-names", "P12"),
    ("P02-window-901", "P34-sum-over-by-one", "P02"),
]


def compose(*mids, reorder=None):
    doc = fresh()
    for mid in mids:
        mutation = BY_ID[mid]
        assert mutation.base is None
        mutation.pre(doc)
    if reorder is not None:
        reorder(doc)
    if all(BY_ID[mid].rehash_after for mid in mids):
        rehash(doc)
    for mid in mids:
        if BY_ID[mid].post is not None:
            BY_ID[mid].post(doc)
    return doc


def _configmap_first(doc):
    doc["resources"].sort(key=lambda r: {"ConfigMap": 0, "Pod": 1, "Service": 2}[r["manifest"]["kind"]])


CROSS_CONTRACT = [  # (case, builder, profile v2 code or None for "valid", P40 met)
    ("X01", fresh, None, True),
    ("X02", BY_ID["P00-host-network-false"].build, "P00", True),
    ("X03", BY_ID["P00-pod-name-dot"].build, "P00", True),
    ("X04", BY_ID["P00-pod-name-trailing-dash"].build, "P00", True),
    ("X05", lambda: build_positive(OTHER_NAMESPACE), None, False),
    ("X06", BY_ID["P00-volume-kube-api-access"].build, "P00", True),
    ("X07", BY_ID["P17-cpu-request"].build, "P17", True),
    ("X08", BY_ID["P00-pull-always"].build, "P00", True),
    ("X09", BY_ID["P00-volume-no-sizelimit"].build, "P00", True),
    ("X10", BY_ID["P34-sum-over-by-one"].build, "P34", True),
    ("X11", BY_ID["P00-volume-medium-memory"].build, "P00", True),
    ("X12", BY_ID["P30-containers-echo-other-image"].build, "P30", True),
    ("X13", BY_ID["P32-volumes-echo-reversed"].build, "P32", True),
    ("X14", fresh, None, True),
    ("X15", BY_ID["P00-configmap-name-dot"].build, "P00", True),
    ("X16", _variant(_no_volumes), None, True),
]


def validate(doc):
    return MODEL.validate(doc, SCHEMA)


# ---------------------------------------------------------------------------------------------------------------
# 9. Files and status
# ---------------------------------------------------------------------------------------------------------------

def test_files_table_lists_the_contract_files():
    """Files: the table lists README.md, profile.schema.json, vectors.json, status.json and the model, and the
    files of this tree exist (vectors.json is outside the oracle's tree and is not read)."""
    files_section = README.split("## Files", 1)[1].split("\n## ", 1)[0]
    listed = re.findall(r"^\| `([^`]+)` \|", files_section, re.M)
    assert listed == ["README.md", "profile.schema.json", "vectors.json", "status.json",
                      "../../scripts/proxy_profile_v2.py"]
    for name in ("README.md", "profile.schema.json", "status.json", "../../scripts/proxy_profile_v2.py"):
        assert (CONTRACT_DIR / name).resolve().is_file(), name


def test_model_public_interface():
    """Files: the reference model offers validate(profile, schema), precondition(profile, namespace) and
    schema_error(instance, schema)."""
    for name in ("validate", "precondition", "schema_error"):
        assert callable(getattr(MODEL, name))


def test_model_uses_the_standard_library_only():
    """The model (scripts/proxy_profile_v2.py): standard library only (modules newly loaded by importing it)."""
    assert all(name in sys.stdlib_module_names for name in MODEL_ADDED_MODULES), MODEL_ADDED_MODULES
    assert "jsonschema" not in MODEL_ADDED_MODULES


def test_status_contract_state_matches_readme_status_line():
    """Header status line and Files (status.json governs): contractState equals the README's status line."""
    match = re.search(r"Status: \*\*([A-Z0-9_]+)\*\*", README)
    assert match and STATUS["contractState"] == match.group(1)
    candidate = re.search(r"\(candidate (c\d+);", README)
    assert candidate and STATUS["candidate"] == candidate.group(1)


def test_status_readme_status_note_agrees():
    """Header: 'This status line is the candidate line the README is reviewed with; status.json governs.'"""
    readme_sentence = " ".join(re.search(r"(This status line is .*?governs\.)", README, re.S).group(1).split())
    readme_sentence = readme_sentence.replace("`", "")
    note = STATUS["readmeStatusNote"]
    for text in (readme_sentence, note):
        assert "status line is the candidate line" in text
        assert text.endswith("status.json governs.")


def _tokens(text):
    return {token.lower() for token in re.findall(r"[A-Za-z0-9'\-]+", text)}


def test_status_non_claims_agree_with_readme():
    """Carried steps and non-claims: status.json nonClaims state the README's five non-claims, in order."""
    sentence = " ".join(re.search(r"Non-claims: (.+?land)\.", README, re.S).group(1).split())
    clauses = sentence.split("; ")
    assert len(clauses) == 5 == len(STATUS["nonClaims"])
    for clause, claim in zip(clauses, STATUS["nonClaims"]):
        missing = _tokens(clause) - _tokens(claim)
        assert not missing, (clause, claim, missing)


def test_status_records_what_the_readme_names():
    """Files (status.json row), header and Carried steps: state, review rounds, non-claims, the carried steps
    S1-S3, W1-W4, C1-C2 and the predecessor record (LPK-0's amendment.json, MET-LIVE-002)."""
    for key in ("contractState", "reviewRounds", "nonClaims", "carried", "predecessorRecord", "readmeStatusNote"):
        assert key in STATUS
    assert STATUS["profileId"] == PROFILE_ID_V2
    assert STATUS["packet"] == "MET-LIVE-004"
    assert STATUS["workItem"] == "LINUX-PROBE-KIT-ADMISSION"
    assert STATUS["reviewSeries"] == "MET-LIVE-004/contract"
    assert STATUS["evidenceClass"] == "UNIT_VERIFICATION_ONLY"
    assert {s["id"] for s in STATUS["carried"]["steps"]} == {"S1", "S2", "S3", "W1", "W2", "W3", "W4", "C1", "C2"}
    assert STATUS["predecessorRecord"]["record"] == "architecture/probe-kit-scope/amendment.json"
    assert STATUS["predecessorRecord"]["packet"] == "MET-LIVE-002"
    assert STATUS["installed"] is False  # "nothing is installed or compiled"
    assert STATUS["wireProfile"] is False  # "profile v1 remains the wire's profile"
    assert set(STATUS["combinedReview"]) == {"architecture/admission-semantics-v4/", "architecture/proxy-profile-v2/"}


# ---------------------------------------------------------------------------------------------------------------
# 1. The schema
# ---------------------------------------------------------------------------------------------------------------

@needs_jsonschema
def test_positive_is_valid_under_the_pinned_schema():
    """The model: Schema validation (the pinned G-JSONSCHEMA bundle, jsonschema 4.24.0, draft 2020-12)."""
    from importlib.metadata import version
    assert version("jsonschema") == "4.24.0"
    assert SCHEMA["$schema"] == "https://json-schema.org/draft/2020-12/schema"
    Draft202012Validator.check_schema(SCHEMA)
    errors = [e.message for e in Draft202012Validator(SCHEMA).iter_errors(POSITIVE)]
    assert errors == []


def test_validate_returns_empty_for_the_positive():
    """The model: validate returns no refusal for a document that passes every rule; precondition is met."""
    assert validate(fresh()) == []
    assert MODEL.schema_error(fresh(), SCHEMA) is None
    assert MODEL.precondition(fresh(), SEALED_NAMESPACE) == []


def test_schema_id_and_canonical_digest():
    """Files and The model: the schema's $id is the README's and SCHEMA_ID; its canonical sha256 is SCHEMA_SHA256."""
    readme_id = re.search(r"`\$id` `([^`]+)`", README).group(1)
    assert SCHEMA["$id"] == readme_id == MODEL.SCHEMA_ID
    assert hashlib.sha256(canonical_bytes(SCHEMA)).hexdigest() == MODEL.SCHEMA_SHA256


def test_profile_id_const_and_echo_keys():
    """The schema, changes 0 and 1: profileId const and the three required echo keys."""
    assert SCHEMA["properties"]["profileId"] == {"const": PROFILE_ID_V2}
    title_id = re.search(r"^# Workload profile v2 \(`([A-Z0-9_]+)`\)", README).group(1)
    assert title_id == PROFILE_ID_V2
    pod_branch = SCHEMA["$defs"]["manifest"]["oneOf"][0]
    required = pod_branch["properties"]["metadata"]["properties"]["annotations"]["required"]
    assert sorted(required) == sorted([ECHO_CONTAINERS, ECHO_INIT, ECHO_VOLUMES])


def _schema_keywords(node, found):
    if isinstance(node, dict):
        for key, value in node.items():
            found.add(key)
            if key in ("properties", "$defs"):
                for sub in value.values():
                    _schema_keywords(sub, found)
            elif key in ("items", "not", "additionalProperties"):
                _schema_keywords(value, found)
            elif key == "oneOf":
                for sub in value:
                    _schema_keywords(sub, found)
    return found


def test_model_walker_keywords_are_the_schema_keywords():
    """The model: P00 uses its own walker over exactly the keywords the schema uses."""
    assert _schema_keywords(SCHEMA, set()) == set(MODEL.KEYWORDS)


def test_another_schema_raises_and_an_equal_copy_does_not():
    """The model: schema must be the reviewed v2 schema; another raises an error and has no P code."""
    other = copy.deepcopy(SCHEMA)
    other["$id"] = "https://schemas.planeon.ai/internal/proxy-execution-profile/v9.json"
    with pytest.raises(Exception):
        MODEL.validate(fresh(), other)
    with pytest.raises(Exception):
        MODEL.validate(BY_ID["P01-depth"].build(), other)
    assert MODEL.validate(fresh(), copy.deepcopy(SCHEMA)) == []


# ---------------------------------------------------------------------------------------------------------------
# 2. The rule table and texts
# ---------------------------------------------------------------------------------------------------------------

def test_refusal_texts_equal_the_readme():
    """The model: the rule table's refusal texts, P40's and P99's texts, equal the model's TEXT table."""
    assert sorted(README_TABLE_TEXT) == sorted(README_RULE_CODES)
    assert set(MODEL.TEXT) == set(README_RULE_CODES) | {"P40", "P99"}
    for code, text in README_TEXT.items():
        assert MODEL.TEXT[code] == text, code


def test_P01_text_verbatim():
    """The model: P01's refusal text, verbatim (B-L1-1's text), equals the table's and the model's."""
    assert README_P01_VERBATIM == README_TABLE_TEXT["P01"] == MODEL.TEXT["P01"]


def test_every_readme_rule_has_mutations():
    """The model: the rule table: every P rule has at least one mutation of my own; at least 20 in all."""
    covered = {m.code for m in MUTATIONS}
    assert set(README_RULE_CODES) <= covered
    assert len(MUTATIONS) >= 20
    assert set(EVALUATION_ORDER) == set(README_RULE_CODES)


@pytest.mark.parametrize("mutation", MUTATIONS, ids=[m.mid for m in MUTATIONS])
def test_mutation_refused_with_exact_text(mutation):
    """The model: the rule table (each mutation also names its own README section): one refusal, exact text."""
    assert validate(mutation.build()) == refusal(mutation.code)


@pytest.mark.parametrize("vid,section,build", VALID, ids=[v[0] for v in VALID])
def test_valid_variants(vid, section, build):
    """The schema and The model (bounds stated as at most / at least): boundary documents are valid."""
    assert validate(build()) == []


@pytest.mark.parametrize("first,second,code", ORDER_PAIRS, ids=["%s+%s" % (a, b) for a, b, _ in ORDER_PAIRS])
def test_evaluation_order(first, second, code):
    """The model: The evaluation order: a document failing two rules refuses with the earlier one."""
    assert code in (BY_ID[first].code, BY_ID[second].code)
    assert validate(BY_ID[first].build()) == refusal(BY_ID[first].code)
    assert validate(BY_ID[second].build()) == refusal(BY_ID[second].code)
    assert validate(compose(first, second)) == refusal(code)


def test_evaluation_order_follows_the_resources_list():
    """The model: The evaluation order, step 4: per resource in the order of `resources`."""
    pod_first = compose("P34-sum-over-by-one", "P14-configmap-namespace")
    assert validate(pod_first) == refusal("P34")
    configmap_first = compose("P34-sum-over-by-one", "P14-configmap-namespace", reorder=_configmap_first)
    assert validate(configmap_first) == refusal("P14")


# ---------------------------------------------------------------------------------------------------------------
# 3. P33 and 4. volumes: []
# ---------------------------------------------------------------------------------------------------------------

@pytest.mark.parametrize("mid", ["P33-undeclared-extra-mount", "P33-undeclared-replacing-mount",
                                 "P33-mounts-without-volumes", "P33-volume-mounted-twice",
                                 "P33-single-volume-mounted-twice", "P33-mount-path-other-name",
                                 "P33-mount-path-suffix", "P33-unmounted-volume", "P33-no-mounts-member"])
@needs_jsonschema
def test_P33_cases_are_schema_valid_and_refused_P33(mid):
    """The schema, change 5, and The model: P33's reading: schema-valid documents only the model's P33 refuses."""
    doc = BY_ID[mid].build()
    assert Draft202012Validator(SCHEMA).is_valid(doc)
    assert validate(doc) == refusal("P33")


def test_P33_judged_over_names_after_P35():
    """The model: P33's reading: over volume names (mount order free), after P35 (duplicates refuse P35)."""
    assert validate(_variant(lambda d: mounts(d).reverse())()) == []
    assert validate(BY_ID["P35-before-P33-one-mount"].build()) == refusal("P35")
    assert validate(BY_ID["P35-before-P33-two-mounts"].build()) == refusal("P35")


@needs_jsonschema
def test_volumes_empty_refused_P00_by_min_items():
    """The schema, change 4: volumes optional, minItems 1 when present; `volumes: []` refuses P00."""
    def keywords_failed(errors, found):
        for error in errors:
            found.add(error.validator)
            keywords_failed(error.context or [], found)
        return found

    for mid in ("P00-volumes-empty", "P00-volumes-empty-no-mounts"):
        doc = BY_ID[mid].build()
        failed = keywords_failed(Draft202012Validator(SCHEMA).iter_errors(doc), set())
        assert "minItems" in failed, (mid, failed)
        assert validate(doc) == refusal("P00")
    no_mounts = BY_ID["P00-volumes-empty-no-mounts"].build()
    no_mounts_ok = copy.deepcopy(no_mounts)
    del pod(no_mounts_ok)["spec"]["volumes"]
    rehash(no_mounts_ok)
    assert validate(no_mounts_ok) == []  # the same Pod without the empty list is valid: minItems alone refuses


# ---------------------------------------------------------------------------------------------------------------
# 5. P01
# ---------------------------------------------------------------------------------------------------------------

@needs_jsonschema
def test_P01_integral_float_passes_the_schema_and_P01_refuses():
    """The model: P01's full content: 9443.0 passes P00 (the schema reads it as an integer) and P01 refuses."""
    doc = BY_ID["P01-integral-float-port"].build()
    assert isinstance(svc(doc)["spec"]["ports"][0]["port"], float)
    assert Draft202012Validator(SCHEMA).is_valid(doc)
    assert MODEL.schema_error(doc, SCHEMA) is None
    assert validate(doc) == [README_P01_VERBATIM]
    text = json.dumps(doc)
    assert '"port": 9443.0' in text  # the op value spelled 9443.0, which a JSON reader parses as a float
    parsed = json.loads(text)
    assert isinstance(svc(parsed)["spec"]["ports"][0]["port"], float)
    assert validate(parsed) == [README_P01_VERBATIM]


@needs_jsonschema
def test_P01_non_integral_float_fails_the_schema_and_P01_refuses_first():
    """The model: P01's full content: 0.5 fails P00 as well, but P01 runs first."""
    doc = BY_ID["P01-noninteger-float"].build()
    assert not Draft202012Validator(SCHEMA).is_valid(doc)
    assert validate(doc) == [README_P01_VERBATIM]


def test_P01_bounds():
    """The model: P01's full content: depth at most 16, the 262144 size budget (keys included), integers within
    +-(2^53-1), canonical size at most 262144; each refuses with B-L1-1's one text."""
    for mid in ("P01-depth", "P01-budget-string", "P01-budget-key", "P01-canonical-size",
                "P01-canonical-size-schema-valid", "P01-integer-above-range", "P01-integer-below-range"):
        assert validate(BY_ID[mid].build()) == [README_P01_VERBATIM], mid
    shallow = fresh()
    shallow["deep"] = _nest(12)
    assert validate(shallow) == refusal("P00")  # within the depth bound, outside the schema


@needs_jsonschema
def test_P01_canonical_size_on_a_schema_valid_document():
    """The model: P01's full content: the canonical-size step refuses even a schema-valid document."""
    doc = BY_ID["P01-canonical-size-schema-valid"].build()
    assert Draft202012Validator(SCHEMA).is_valid(doc)
    assert len(canonical_bytes(doc)) > 262144
    assert validate(doc) == [README_P01_VERBATIM]


def test_P01_lone_surrogate_validate_and_precondition():
    """The model: P01's full content and P40: a lone surrogate refuses P01 from validate and precondition."""
    doc = BY_ID["P01-lone-surrogate"].build()
    assert "\ud800" in cm(doc)["data"]["fixture.json"]
    with pytest.raises(UnicodeEncodeError):
        json.dumps(doc, ensure_ascii=False).encode("utf-8")
    assert validate(doc) == [README_P01_VERBATIM]
    assert MODEL.precondition(doc, SEALED_NAMESPACE) == [README_P01_VERBATIM]
    assert MODEL.precondition(doc, OTHER_NAMESPACE) == [README_P01_VERBATIM]


# ---------------------------------------------------------------------------------------------------------------
# 6. P99 and P40
# ---------------------------------------------------------------------------------------------------------------

@needs_jsonschema
def test_P99_cpu_with_trailing_line_feed_is_schema_valid():
    """The model: P99, use (1): equal cpu request and limit ending in one line feed: schema-valid, P99."""
    doc = BY_ID["P99-cpu-trailing-lf"].build()
    assert quantities(doc, "requests")["cpu"] == quantities(doc, "limits")["cpu"] == "250m\n"
    assert Draft202012Validator(SCHEMA).is_valid(doc)
    assert MODEL.schema_error(doc, SCHEMA) is None
    assert validate(doc) == refusal("P99")


NON_PROFILES = [("string", "not a profile"), ("list", []), ("none", None), ("integer", 7), ("empty-object", {}),
                ("binding-without-namespace", {"binding": {}}), ("binding-not-object", {"binding": "x"})]


@pytest.mark.parametrize("label,argument", NON_PROFILES, ids=[n[0] for n in NON_PROFILES])
def test_P99_precondition_non_profile(label, argument):
    """The model: P40 and P99, use (2): precondition returns P99 for a non-profile argument."""
    assert MODEL.precondition(argument, SEALED_NAMESPACE) == refusal("P99")


def test_P40_precondition():
    """The model: P40, the cross-contract precondition: met for the sealed namespace, P40 otherwise; P40 is not
    a profile rule (validate accepts the other-namespace profile)."""
    other = build_positive(OTHER_NAMESPACE)
    assert validate(other) == []
    assert MODEL.precondition(other, SEALED_NAMESPACE) == refusal("P40")
    assert MODEL.precondition(fresh(), OTHER_NAMESPACE) == refusal("P40")
    assert MODEL.precondition(fresh(), SEALED_NAMESPACE) == []


# ---------------------------------------------------------------------------------------------------------------
# 7. The pattern reading
# ---------------------------------------------------------------------------------------------------------------

def test_pattern_reading_is_re_search():
    """The schema: Patterns: Python re.search, where $ also matches before one trailing line feed."""
    pod_branch = SCHEMA["$defs"]["manifest"]["oneOf"][0]
    size_pattern = (pod_branch["properties"]["spec"]["properties"]["volumes"]["items"]["properties"]["emptyDir"]
                    ["properties"]["sizeLimit"]["pattern"])
    name_pattern = pod_branch["properties"]["metadata"]["properties"]["name"]["pattern"]
    assert re.search(size_pattern, "536870912\n") and not re.fullmatch(size_pattern, "536870912\n")
    assert re.search(name_pattern, "probe-pod\n") and not re.fullmatch(name_pattern, "probe-pod\n")
    assert not re.search(size_pattern, "536870912\n\n")


@pytest.mark.parametrize("pid,build", PATTERN_ACCEPTED, ids=[p[0] for p in PATTERN_ACCEPTED])
@needs_jsonschema
def test_pattern_trailing_line_feed_accepted_by_schema_and_model(pid, build):
    """The schema: Patterns: `536870912` + LF as a sizeLimit or ephemeral-storage quantity and `probe-pod` + LF as
    a name match; the pinned schema and the model's P00 agree."""
    doc = build()
    assert Draft202012Validator(SCHEMA).is_valid(doc)
    assert MODEL.schema_error(doc, SCHEMA) is None
    assert validate(doc) != refusal("P00")


@pytest.mark.parametrize("mid", ["P30-containers-echo-trailing-lf", "P32-volumes-echo-trailing-lf",
                                 "P33-mount-path-trailing-lf"])
@needs_jsonschema
def test_pattern_admits_line_feed_but_model_equality_refuses(mid):
    """The schema: Patterns, with changes 1 and 5: the pattern admits the trailing LF, the model's equality
    rule (P30, P32, P33) refuses."""
    doc = BY_ID[mid].build()
    assert Draft202012Validator(SCHEMA).is_valid(doc)
    assert validate(doc) == refusal(BY_ID[mid].code)


@pytest.mark.parametrize("mid", ["P00-sizelimit-two-line-feeds", "P00-sizelimit-leading-line-feed",
                                 "P00-sizelimit-crlf"])
@needs_jsonschema
def test_pattern_rejects_other_line_feeds(mid):
    """The schema: Patterns: only ONE trailing line feed matches; the schema and the model both refuse others."""
    doc = BY_ID[mid].build()
    assert not Draft202012Validator(SCHEMA).is_valid(doc)
    assert validate(doc) == refusal("P00")


# ---------------------------------------------------------------------------------------------------------------
# Cross-contract table: the profile v2 and P40 columns
# ---------------------------------------------------------------------------------------------------------------

@pytest.mark.parametrize("case,build,code,met", CROSS_CONTRACT, ids=[c[0] for c in CROSS_CONTRACT])
def test_cross_contract_profile_columns(case, build, code, met):
    """Vectors (vectors.json): the crossContract table's Profile v2 and P40 columns, on my own documents."""
    doc = build()
    assert validate(doc) == ([] if code is None else refusal(code))
    assert MODEL.precondition(doc, SEALED_NAMESPACE) == ([] if met else refusal("P40"))


# ---------------------------------------------------------------------------------------------------------------
# 8. Schema and model agree
# ---------------------------------------------------------------------------------------------------------------

def agreement_corpus():
    corpus = [("positive", fresh())]
    corpus += [(m.mid, m.build()) for m in MUTATIONS]
    corpus += [(vid, build()) for vid, _, build in VALID]
    corpus += [("pair:%s+%s" % (a, b), compose(a, b)) for a, b, _ in ORDER_PAIRS]
    corpus += [(pid, build()) for pid, build in PATTERN_ACCEPTED]
    corpus.append(("configmap-first", compose("P34-sum-over-by-one", "P14-configmap-namespace",
                                              reorder=_configmap_first)))
    return corpus


@needs_jsonschema
def test_schema_and_model_agree():
    """The model: Schema validation and The evaluation order: over the positive and every mutation, the model
    refuses P00 exactly where the pinned schema rejects, unless P01 (an earlier rule) refuses first; the model's
    walker (schema_error) agrees with the pinned schema."""
    validator = Draft202012Validator(SCHEMA)
    p00, p01 = refusal("P00"), refusal("P01")
    mismatches, checked, p01_first = [], 0, 0
    for cid, doc in agreement_corpus():
        result = validate(doc)
        if result == p01:
            p01_first += 1
            continue
        schema_valid = validator.is_valid(doc)
        walker_valid = MODEL.schema_error(doc, SCHEMA) is None
        if (result == p00) == schema_valid or walker_valid != schema_valid:
            mismatches.append((cid, result, schema_valid, walker_valid))
        checked += 1
    assert mismatches == []
    assert checked >= 150 and p01_first >= 10
