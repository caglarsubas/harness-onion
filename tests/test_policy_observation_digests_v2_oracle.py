"""D5a oracle tests for the I01 digest contract v2 (MET-ENFORCE-042, adopted candidate c4).

Owner decision D5a: a contract packet carries black-box tests written outside the candidate, by someone who is not its
builder. The expectations here come from the contract text, `architecture/policy-observation-digests-v2/README.md`
("README section n" below), never from the model's code. Sources of the expected values:

- canonical bytes and digests: README section 3.2 (json.dumps(sort_keys=True, separators=(",", ":"), ensure_ascii=False,
  allow_nan=False) as UTF-8; "sha256:" + lowercase hex); synthetic uids: README section 3.1;
- literal hashes, sizes, counts, namespaces, quota values, refusal texts, packet ids and edge members: quoted from the
  README where it states them;
- the A2 rendering: admission v4's renderers `a2_objects`, `manifest_file_bytes` and `manifest_directory_hash`, which
  README sections 4.1 and 5.1 name as the rendering, applied to the sealed values;
- every projection document and enforcement digest of the complete positive: rebuilt here from the README's rules
  (sections 3.1, 4.1-4.6, 5.1-5.4) over the `qual` fixture and the record (README_DERIVED below); the v2 model's
  public functions are used only as the system under test (cross-checks and the refusal mutations), and for the
  values listed in MODEL_DERIVED (none: the README states enough for every `replaced` member);
- inputs read: vectors.json `fixtures`, `complete` and the rows' `ops` only (never any row's `expect`); admission v4's
  vectors.json `sealed` and `admission-manifests/planeon-a2.json`; profile v2's vectors.json `positive` and
  `profile.schema.json`; I01 v1's vectors.json `complete.profile` and `fixtures.bindings.complete`; edge record v11's
  rows for this contract's files; `definitions.json` and `status.json` as contract data. I06 v1's three frozen inputs
  are only hashed and handed, parsed, to the model as its `i06` argument (README section 5.2).

The test never imports scripts/validate_policy_observation.py or scripts/validate_readiness.py, and patches nothing.
"""
from __future__ import annotations

import copy
import hashlib
import json
import re
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import admission_semantics_v4 as adm  # noqa: E402
import policy_observation_digests_v2 as model  # noqa: E402
import proxy_profile_v2 as pp2  # noqa: E402

CONTRACT = "architecture/policy-observation-digests-v2/"


def _bytes(relative: str) -> bytes:
    return (ROOT / relative).read_bytes()


def _json(relative: str):
    return json.loads(_bytes(relative))


def _allowed_vectors():
    """Only `fixtures`, `complete` and each row's `ops` leave this function; no `expect` is touched."""
    data = _json(CONTRACT + "vectors.json")
    return data["fixtures"], data["complete"], [row["ops"] for row in data["vectors"]]


FIXTURES, COMPLETE, OPS = _allowed_vectors()
SEALED_V4 = _json("architecture/admission-semantics-v4/vectors.json")["sealed"]
PROFILE_V2_POSITIVE = _json("architecture/proxy-profile-v2/vectors.json")["positive"]
PROFILE_SCHEMA_BYTES = _bytes("architecture/proxy-profile-v2/profile.schema.json")
PROFILE_SCHEMA = json.loads(PROFILE_SCHEMA_BYTES)
_V1 = _json("architecture/policy-observation-digests/vectors.json")
V1_COMPLETE_PROFILE = _V1["complete"]["profile"]
V1_COMPLETE_BINDING = _V1["fixtures"]["bindings"]["complete"]
del _V1
DEFINITIONS = _json(CONTRACT + "definitions.json")
STATUS = _json(CONTRACT + "status.json")
I06_PATHS = {"closure": "architecture/i06-backend-profile/identity-closure.json",
             "inventory": "architecture/i06-backend-profile/writer-inventory.json",
             "bootstrap": "architecture/i06-backend-profile/upstream-bootstrap-rbac-v1.37.1.json"}
I06 = {key: json.loads(_bytes(path)) for key, path in I06_PATHS.items()}

# ---- values quoted from the README -----------------------------------------------------------------------------
QUAL = "planeon-qual"                                                     # sections 10, 12
UNIT = "unit-namespace"                                                   # section 10
HASH_UNIT = "sha256:8004085f93b447942e2aeffd00856e7dc485a063445a40c3518c60d6bd3c503f"  # section 10
HASH_QUAL = "sha256:9b1ddc1096ff0d35fb4cd5a9e5e6b4248fefc5b75b5a06f862c59d85e028ca60"  # section 10
A2_FILE = "planeon-a2.json"                                               # section 4.1
A2_SIZE = 8322                                                            # section 12
A2_SHA256 = "92c21612304cb704d13b506c1ae885d62a47c01f0ed0d284affe563aa1868e32"  # section 12
SEALED_QUAL = {"namespace": QUAL, "ipFamily": "IPv4", "serviceCIDR": "10.96.0.0/12",
               "defaultTolerationSeconds": 300}                           # section 12
V1_PROFILE_DIGEST = "sha256:cdf3f7337ae938da6998d4084cca76300f31e72ecaac27a6d968b8dba4fa167b"  # section 10
QUOTA_QUANTITIES = {"pods": "1", "configmaps": "1", "services": "1", "limits.cpu": "500m", "limits.memory": "256Mi",
                    "limits.ephemeral-storage": "1Gi"}                    # section 10
QUOTA = {"pods": 1, "configMaps": 1, "services": 1, "cpuMillis": 500, "memoryBytes": 268435456,
         "ephemeralStorageBytes": 1073741824}                             # section 10
CLOSURE_VERSION = "planeon.internal.policy-observation-rbac-closure/v1"   # sections 0, 5.2
GATE_BOUND_MS = (60 + 5 + 25) * 1000                                      # section 3.3
IDENTITY = {                                                              # section 4 table
    "admissionPolicy": ("admissionregistration.k8s.io/v1", "ValidatingAdmissionPolicy"),
    "resourceQuota": ("v1", "ResourceQuota"),
    "limitRange": ("v1", "LimitRange"),
    "serviceAccount": ("v1", "ServiceAccount"),
    "rbac": ("planeon.internal/v1", "EffectiveRbac"),
    "networkPolicy": ("networking.k8s.io/v1", "NetworkPolicy"),
    "mutationBroker": ("planeon.internal/v1", "MutationBroker"),
}
KEYS = tuple(IDENTITY)
DIGEST_KEYS = ("admissionFenceDigest", "rbacClosureDigest", "networkEnforcementDigest", "hostPreflightDigest")
SYNTHETIC_NAMES = {"admissionPolicy": "admissionpolicy", "rbac": "rbac", "mutationBroker": "mutationbroker"}
REAL_LISTS = {"resourceQuota": "resourceQuotas", "limitRange": "limitRanges", "serviceAccount": "serviceAccounts",
              "networkPolicy": "networkPolicies"}
KIND_KEY = {"ResourceQuota": "resourceQuota", "LimitRange": "limitRange", "ServiceAccount": "serviceAccount"}
SA_KEYS = ("automountServiceAccountToken", "imagePullSecrets", "secrets")              # section 3.1
PSA_PREFIX = "pod-security.kubernetes.io/"                                             # section 4.1
BROKER_ROW = ("executable", "executableLabel", "artifactDigest", "interpreterPath", "interpreterLabel", "uid", "gid",
              "processLabel", "namespaceInodes", "cgroup", "seccompMode", "seccompDefaultAction",
              "seccompFilterDigest", "noNewPrivs", "rlimitCore", "capabilities", "filePaths", "bpfPrograms",
              "listenEndpointIds", "outboundEndpointIds")                              # section 4.6 (20)
BROKER_DOCUMENT = ("executable", "executableLabel", "artifactDigest", "uid", "gid", "processLabel", "cgroup",
                   "seccompMode", "seccompDefaultAction", "seccompFilterDigest", "noNewPrivs", "capabilities",
                   "listenEndpointIds", "outboundEndpointIds")                         # section 4.6 (14)
CGROUP_DOCUMENT = ("path", "memoryMaxBytes", "pidsMax", "cpuQuotaMicros", "cpuPeriodMicros", "selinuxLabel")
AGENT = "NETWORK_POLICY_AGENT"                                                         # section 5.3
AGENT_MEMBERS = ("executable", "executableLabel", "artifactDigest", "processLabel", "apiIdentities")
ROLE_SLOTS = ("role/SERVER", "role/OBSERVER", "role/BROKER", "role/WORKER", "role/EFFECT_GATE")  # section 3.3

# Values of the complete positive's `replaced` members derived by the v2 model's public functions rather than by the
# README's rules. Empty: every member is rebuilt from the README below.
MODEL_DERIVED: frozenset = frozenset()


# ---- README section 3.2 / 3.1 helpers ----------------------------------------------------------------------------
def canonical(value) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False).encode("utf-8")


def digest_of(value) -> str:
    return "sha256:" + hashlib.sha256(canonical(value)).hexdigest()


def synthetic_uid(api_version: str, kind: str, name: str, namespace) -> str:
    return hashlib.sha256(canonical({"apiVersion": api_version, "kind": kind, "name": name,
                                     "namespace": namespace})).hexdigest()


def snapshot_of(name: str) -> dict:
    """README section 2: snapshot = {resourceVersion, lists, configuration, adm4LoadedHash, record}."""
    snapshot = copy.deepcopy(FIXTURES["snapshots"][name])
    snapshot["record"] = copy.deepcopy(FIXTURES["record"])
    return snapshot


def sealed_of(snapshot: dict) -> dict:
    """README section 4.1: the four sealed values a2_objects reads."""
    configuration = snapshot["configuration"]
    sealed = {"namespace": configuration["qualificationNamespace"]}
    sealed.update(configuration["sealedAdmission"])
    return sealed


def rendered_hash(sealed: dict) -> str:
    return adm.manifest_directory_hash({A2_FILE: adm.manifest_file_bytes(sealed)})


def live_item(key: str, snapshot: dict, binding: dict) -> dict:
    """README sections 4.2 and 4.3: the one object of the kind in the qualification namespace."""
    space = snapshot["configuration"]["qualificationNamespace"]
    items = [item for item in snapshot["lists"][REAL_LISTS[key]] if item["metadata"].get("namespace") == space]
    if key == "serviceAccount":
        subject = binding["scope"]["serviceAccountSubject"]
        prefix = "system:serviceaccount:" + space + ":"
        assert subject.startswith(prefix)
        items = [item for item in items if item["metadata"]["name"] == subject[len(prefix):]]
    assert len(items) == 1, key
    assert items[0]["metadata"]["name"] == binding["projections"][key]["name"], key
    return items[0]


def rbac_entries(snapshot: dict) -> tuple[list, list]:
    """README sections 4.5 and 5.2: rbac's subjects (qualification-namespace RoleBindings plus every
    ClusterRoleBinding, rules at the namespace or CLUSTER scope) and the closure's (every bound subject, all rules)."""
    lists = snapshot["lists"]
    space = snapshot["configuration"]["qualificationNamespace"]
    roles = {(item["metadata"]["namespace"], item["metadata"]["name"]): item for item in lists["roles"]}
    cluster_roles = {item["metadata"]["name"]: item for item in lists["clusterRoles"]}
    accounts = {(item["metadata"]["namespace"], item["metadata"]["name"]) for item in lists["serviceAccounts"]}
    grants: dict = {}
    reach: set = set()

    def subject_key(subject: dict, binding_namespace):
        if subject["kind"] == "ServiceAccount":
            namespace = subject.get("namespace") or binding_namespace
            return ("ServiceAccount", "system:serviceaccount:%s:%s" % (namespace, subject["name"]))
        return (subject["kind"], subject["name"])

    def rules_of(role: dict, scope: str) -> list:
        out = []
        for rule in role.get("rules") or []:
            if rule.get("nonResourceURLs"):
                out.append({"nonResourceURLs": rule["nonResourceURLs"], "verbs": rule["verbs"], "scope": scope})
            else:
                out.append({"apiGroups": rule.get("apiGroups", []), "resources": rule.get("resources", []),
                            "verbs": rule["verbs"], "resourceNames": rule.get("resourceNames", []), "scope": scope})
        return out

    for binding in lists["roleBindings"]:
        namespace = binding["metadata"]["namespace"]
        ref = binding["roleRef"]
        role = roles[(namespace, ref["name"])] if ref["kind"] == "Role" else cluster_roles[ref["name"]]
        for subject in binding.get("subjects") or []:
            key = subject_key(subject, namespace)
            grants.setdefault(key, []).extend(rules_of(role, namespace))
            if namespace == space:
                reach.add(key)
    for binding in lists["clusterRoleBindings"]:
        role = cluster_roles[binding["roleRef"]["name"]]
        for subject in binding.get("subjects") or []:
            key = subject_key(subject, None)
            grants.setdefault(key, []).extend(rules_of(role, "CLUSTER"))
            reach.add(key)

    def entry(key: tuple, scopes) -> dict:
        unique = {canonical(rule): rule for rule in grants[key] if scopes is None or rule["scope"] in scopes}
        if key[0] == "ServiceAccount":
            _system, _account, namespace, name = key[1].split(":", 3)
            exists = (namespace, name) in accounts
        else:
            exists = True
        return {"kind": key[0], "name": key[1], "exists": exists,
                "effectiveRules": [unique[raw] for raw in sorted(unique)]}

    return ([entry(key, (space, "CLUSTER")) for key in sorted(reach)],
            [entry(key, None) for key in sorted(grants)])


def readme_document(key: str, snapshot: dict, binding: dict) -> dict:
    """The projection document of README section 3.1 for `key`, built from sections 4.1-4.6."""
    space = snapshot["configuration"]["qualificationNamespace"]
    api_version, kind = IDENTITY[key]
    if key in REAL_LISTS:
        item = live_item(key, snapshot, binding)
        if key == "serviceAccount":
            spec = {member: item[member] for member in SA_KEYS if member in item}
        else:
            spec = item["spec"]
        metadata = item["metadata"]
        return {"apiVersion": api_version, "kind": kind,
                "metadata": {"name": metadata["name"], "namespace": metadata["namespace"], "uid": metadata["uid"]},
                "spec": copy.deepcopy(spec)}
    name = SYNTHETIC_NAMES[key]
    namespace = None if key == "admissionPolicy" else space
    if key == "admissionPolicy":
        objects = sorted(adm.a2_objects(sealed_of(snapshot)), key=lambda obj: (obj["kind"], obj["metadata"]["name"]))
        listed = [item for item in snapshot["lists"]["namespaces"] if item["metadata"]["name"] == space]
        assert len(listed) == 1
        labels = listed[0]["metadata"].get("labels") or {}
        spec = {"sealedObjects": objects,
                "podSecurityLabels": {label: value for label, value in labels.items() if label.startswith(PSA_PREFIX)}}
    elif key == "rbac":
        spec = {"subjects": rbac_entries(snapshot)[0]}
    else:
        row = snapshot["record"]["roles"]["BROKER"]
        spec = {member: copy.deepcopy(row[member]) for member in BROKER_DOCUMENT}
        spec["cgroup"] = {member: row["cgroup"][member] for member in CGROUP_DOCUMENT}
    return {"apiVersion": api_version, "kind": kind,
            "metadata": {"name": name, "namespace": namespace, "uid": synthetic_uid(api_version, kind, name, namespace)},
            "spec": spec}


def readme_enforcement(snapshot: dict, binding: dict) -> dict:
    """README sections 5.1-5.4."""
    sealed_hash = rendered_hash(sealed_of(snapshot))
    assert sealed_hash == snapshot["configuration"]["pinnedManifestHash"] == snapshot["adm4LoadedHash"]
    record = snapshot["record"]
    agent = record["backendComponents"][AGENT]
    network = {"networkPolicies": sorted([readme_document("networkPolicy", snapshot, binding)], key=canonical),
               "agent": {member: agent[member] for member in AGENT_MEMBERS}}
    return {"admissionFenceDigest": sealed_hash,
            "rbacClosureDigest": digest_of({"schemaVersion": CLOSURE_VERSION, "subjects": rbac_entries(snapshot)[1]}),
            "networkEnforcementDigest": digest_of(network),
            "hostPreflightDigest": digest_of(record)}


def readme_gate_passes(capture: dict, record: dict) -> dict:
    """README section 3.3: per gated value, whether the latest completed set passes."""
    completed = [entry for entry in capture["sets"] if entry["completed"] is True]
    answer = capture["answer"]
    if not completed:
        return {"mutationBroker": False, "networkEnforcementDigest": False, "hostPreflightDigest": False}
    latest = completed[-1]
    young = (0 <= answer["monotonicMs"] - latest["scheduledMonotonicMs"] <= GATE_BOUND_MS
             and 0 <= answer["wallMs"] - latest["startedWallMs"] <= GATE_BOUND_MS)
    every = list(ROLE_SLOTS) + ["lifecycle"] + ["backend/" + name for name in record["backendComponents"]]
    taken = latest["slots"]
    return {"mutationBroker": young and taken.get("role/BROKER") == "TAKEN",
            "networkEnforcementDigest": young and taken.get("backend/" + AGENT) == "TAKEN",
            "hostPreflightDigest": young and all(taken.get(slot) == "TAKEN" for slot in every)}


def flat(value, prefix: str):
    if isinstance(value, dict) and value:
        for member, item in value.items():
            yield from flat(item, prefix + "." + member)
    elif isinstance(value, list) and value:
        for index, item in enumerate(value):
            yield from flat(item, "%s[%d]" % (prefix, index))
    else:
        yield prefix, value


def leaf_diff(left, right, path=()) -> set:
    if isinstance(left, dict) and isinstance(right, dict):
        out = set()
        for member in set(left) | set(right):
            if member not in left or member not in right:
                out.add(path + (member,))
            else:
                out |= leaf_diff(left[member], right[member], path + (member,))
        return out
    if isinstance(left, list) and isinstance(right, list) and len(left) == len(right):
        out = set()
        for index, (one, two) in enumerate(zip(left, right)):
            out |= leaf_diff(one, two, path + (index,))
        return out
    return set() if type(left) is type(right) and left == right else {path}


def replaced_regex(pattern: str):
    out, index = "", 0
    while index < len(pattern):
        if pattern.startswith("[*]", index):
            out, index = out + r"\[\d+\]", index + 3
        elif pattern[index] == "*":
            out, index = out + r"[^.\[\]]*", index + 1
        elif pattern[index] == "{":
            end = pattern.index("}", index)
            out += "(?:" + "|".join(re.escape(part) for part in pattern[index + 1:end].split(",")) + ")"
            index = end + 1
        else:
            out, index = out + re.escape(pattern[index]), index + 1
    return re.compile(out + r"(?:$|[.\[])")


def readme_derived() -> dict:
    """Every value of the complete positive that README section 10 lists as replaced, from the README's rules."""
    snapshot = snapshot_of("qual")
    binding, profile = COMPLETE["binding"], COMPLETE["profile"]
    space = snapshot["configuration"]["qualificationNamespace"]
    out: dict = {}
    documents = {key: readme_document(key, snapshot, binding) for key in KEYS}
    for key, document in documents.items():
        version = (live_item(key, snapshot, binding)["metadata"]["resourceVersion"] if key in REAL_LISTS
                   else snapshot["resourceVersion"])
        for side in ("binding", "observation"):
            base = "%s.projections.%s." % (side, key)
            out[base + "uid"] = document["metadata"]["uid"]
            out[base + "projectionDigest"] = digest_of(document)
            out[base + "namespace"] = document["metadata"]["namespace"]
        out["observation.projections.%s.resourceVersion" % key] = version
    for key, value in readme_enforcement(snapshot, binding).items():
        out["binding.enforcementPins." + key] = value
        out["observation.enforcement." + key] = value
    out["binding.profileDigest"] = digest_of(profile)
    out["request.bindingDigest"] = out["observation.bindingDigest"] = digest_of(binding)
    for member in profile["policy"]:
        if member.endswith("Digest"):
            out["profile.policy." + member] = digest_of(documents[member[:-len("Digest")]])
    for index, ref in enumerate(profile["capacityEntries"]["preexistingResourceRefs"]):
        out["profile.capacityEntries.preexistingResourceRefs[%d].observedDigest" % index] = digest_of(
            documents[KIND_KEY[ref["kind"]]])
    for member, value in QUOTA.items():
        out["observation.quota.hard." + member] = value
        out["observation.quota.used." + member] = 0
    account = FIXTURES["bindings"]["unit"]["scope"]["serviceAccountSubject"].rsplit(":", 1)[1]
    out["binding.scope.namespace"] = space
    out["binding.scope.serviceAccountSubject"] = "system:serviceaccount:%s:%s" % (space, account)
    out["binding.namespace.name"] = space
    out["observation.namespace.name"] = space
    return out


def run_check(state: dict) -> list:
    return model.check_observation_digests(state["snapshot"], state["binding"], state["capture"], state["i06"])


def base_state() -> dict:
    return {"snapshot": snapshot_of("qual"), "binding": copy.deepcopy(COMPLETE["binding"]),
            "capture": copy.deepcopy(FIXTURES["captures"]["passing"]), "i06": I06}


def find(state: dict, list_name: str, name: str, namespace=QUAL) -> dict:
    items = [item for item in state["snapshot"]["lists"][list_name]
             if item["metadata"]["name"] == name and item["metadata"].get("namespace") == namespace]
    assert len(items) == 1
    return items[0]


# ---- 1. the rendering --------------------------------------------------------------------------------------------
def test_rendering_hashes_and_file_bytes():
    """README sections 0, 1, 4.1, 10 and 12: v4's renderers give the stated directory hashes at unit-namespace and
    planeon-qual, and the planeon-qual file bytes are planeon-a2.json (8322 bytes, the stated sha256)."""
    assert rendered_hash(dict(SEALED_QUAL)) == HASH_QUAL
    assert rendered_hash(dict(SEALED_QUAL, namespace=UNIT)) == HASH_UNIT
    raw = adm.manifest_file_bytes(dict(SEALED_QUAL))
    published = _bytes("architecture/admission-semantics-v4/admission-manifests/planeon-a2.json")
    assert raw == published
    assert len(published) == A2_SIZE
    assert hashlib.sha256(published).hexdigest() == A2_SHA256
    objects = adm.a2_objects(dict(SEALED_QUAL))
    assert len(objects) == 8
    kinds = sorted(obj["kind"] for obj in objects)
    assert kinds == ["ValidatingAdmissionPolicy"] * 4 + ["ValidatingAdmissionPolicyBinding"] * 4
    assert len({(obj["kind"], obj["metadata"]["name"]) for obj in objects}) == 8


def test_frozen_model_table_names_admission_v4():
    """README section 0 (change (4)) and section 0's imports: FROZEN_MODELS replaces v3's row with admission v4, adds
    proxy_profile_v2, keeps the I06 rows and native_qualification_v4, each at its file sha256; definitions.json's
    frozenModels carries the same rows; the I06 inputs and profile v2's schema are pinned by sha256."""
    expected = {"scripts/admission_semantics_v4.py", "scripts/proxy_profile_v2.py", "scripts/i06_backend_profile.py",
                "scripts/i06_backend_profile_v3.py", "scripts/i06_backend_profile_v4.py",
                "scripts/native_qualification_v4.py"}
    assert set(model.FROZEN_MODELS) == expected
    assert "scripts/admission_semantics_v3.py" not in model.FROZEN_MODELS
    for path, (sha, _commit) in model.FROZEN_MODELS.items():
        assert hashlib.sha256(_bytes(path)).hexdigest() == sha, path
    rows = {row["path"]: (row["sha256"], row["lastChange"]) for row in DEFINITIONS["frozenModels"]}
    assert rows == {path: tuple(pin) for path, pin in model.FROZEN_MODELS.items()}
    for key, (path, sha) in model.FROZEN_INPUTS.items():
        assert path == I06_PATHS[key]
        assert hashlib.sha256(_bytes(path)).hexdigest() == sha
    assert model.PROFILE_SCHEMA[0] == "architecture/proxy-profile-v2/profile.schema.json"
    assert hashlib.sha256(PROFILE_SCHEMA_BYTES).hexdigest() == model.PROFILE_SCHEMA[1]


def test_model_names_v2_and_keeps_closure_version():
    """README header and section 0 (change (3), (6)): the schema, vectors, contract folder and model path name v2;
    CLOSURE_VERSION stays v1's; SEALED_NAMESPACE is planeon-qual; definitions.json equals the model's definitions()."""
    assert model.SCHEMA_VERSION == "planeon.internal.policy-observation-digests/v2"
    assert model.VECTORS_VERSION == "planeon.internal.policy-observation-digests-vectors/v2"
    assert model.CONTRACT_DIR == CONTRACT
    assert model.MODEL_PATH == "scripts/policy_observation_digests_v2.py"
    assert model.CLOSURE_VERSION == CLOSURE_VERSION
    assert model.SEALED_NAMESPACE == QUAL
    assert DEFINITIONS["schemaVersion"] == "planeon.internal.policy-observation-digests/v2"
    assert DEFINITIONS["evidenceClass"] == "DATA_CHECK_ONLY" and DEFINITIONS["nativeAcceptance"] is False
    assert json.loads(json.dumps(model.definitions())) == DEFINITIONS


def test_canonical_digest_and_synthetic_uid_rules():
    """README sections 3.1 and 3.2: projection_digest is "sha256:" + sha256 of the canonical bytes (non-ASCII kept);
    a synthetic uid is the 64-hex sha256 of canonical({apiVersion, kind, name, namespace}) and fits the CS pattern."""
    documents = [{"b": 1, "a": "ü€日", "c": [None, True, -5, {"z": "\"\\\n"}]}, {}, {"k": []}]
    for document in documents:
        assert model.projection_digest(document) == digest_of(document)
        assert re.fullmatch(r"sha256:[0-9a-f]{64}", digest_of(document))
    assert canonical({"b": 1, "a": "ü"}) == '{"a":"ü","b":1}'.encode("utf-8")
    for key in SYNTHETIC_NAMES:
        api_version, kind = IDENTITY[key]
        namespace = None if key == "admissionPolicy" else QUAL
        uid = synthetic_uid(api_version, kind, SYNTHETIC_NAMES[key], namespace)
        assert model.synthetic_uid(api_version, kind, SYNTHETIC_NAMES[key], namespace) == uid
        assert re.fullmatch(r"[0-9a-f]{64}", uid) and re.fullmatch(r"^[A-Za-z0-9-]{1,128}$", uid)


# ---- 2. the fixtures ---------------------------------------------------------------------------------------------
def test_unit_and_closure_stay_at_unit_namespace():
    """README section 10: unit and closure stay at unit-namespace; their pinnedManifestHash and adm4LoadedHash are v4's
    directory hash at unit-namespace."""
    for name in ("unit", "closure"):
        snapshot = FIXTURES["snapshots"][name]
        assert snapshot["configuration"]["qualificationNamespace"] == UNIT
        assert snapshot["configuration"]["pinnedManifestHash"] == HASH_UNIT
        assert snapshot["adm4LoadedHash"] == HASH_UNIT
        assert rendered_hash(sealed_of(snapshot)) == HASH_UNIT


def test_qual_differs_from_closure_exactly_where_listed():
    """README section 10: qual is closure with the namespace moved to planeon-qual in its 12 places, the two hash members
    at v4's pinned hash, and the ResourceQuota's spec.hard carrying profile v2's quota in quantity form; names, uids,
    the other namespace, its quota, the cluster-scoped objects and the ResourceQuota's status unchanged."""
    closure, qual = FIXTURES["snapshots"]["closure"], FIXTURES["snapshots"]["qual"]
    diff = leaf_diff(closure, qual)
    expected = {("configuration", "qualificationNamespace"), ("configuration", "pinnedManifestHash"),
                ("adm4LoadedHash",)}
    namespace_index = [index for index, item in enumerate(closure["lists"]["namespaces"])
                       if item["metadata"]["name"] == UNIT]
    assert len(namespace_index) == 1
    expected |= {("lists", "namespaces", namespace_index[0], "metadata", "name"),
                 ("lists", "namespaces", namespace_index[0], "metadata", "labels", "kubernetes.io/metadata.name")}
    counts = {}
    for list_name in ("resourceQuotas", "limitRanges", "serviceAccounts", "networkPolicies", "roles", "roleBindings"):
        for index, item in enumerate(closure["lists"][list_name]):
            if item["metadata"].get("namespace") == UNIT:
                expected.add(("lists", list_name, index, "metadata", "namespace"))
                counts[list_name] = counts.get(list_name, 0) + 1
    assert counts == {"resourceQuotas": 1, "limitRanges": 1, "serviceAccounts": 2, "networkPolicies": 1, "roles": 1,
                      "roleBindings": 3}
    namespace_places = [path for path in expected if path not in {("configuration", "pinnedManifestHash"),
                                                                  ("adm4LoadedHash",)}]
    assert len(namespace_places) == 12
    quota_index = [index for index, item in enumerate(closure["lists"]["resourceQuotas"])
                   if item["metadata"].get("namespace") == UNIT][0]
    hard = {path for path in diff if path[:5] == ("lists", "resourceQuotas", quota_index, "spec", "hard")}
    assert hard, "the ResourceQuota's spec.hard must change"
    assert diff - hard == expected
    for path in expected:
        node = qual
        for part in path:
            node = node[part]
        assert node in (QUAL, HASH_QUAL), path
    assert qual["lists"]["resourceQuotas"][quota_index]["spec"]["hard"] == QUOTA_QUANTITIES
    assert qual["lists"]["namespaces"][namespace_index[0]]["metadata"]["uid"] == "unit-namespace-uid"


# ---- 3. the `complete` binding fixture -----------------------------------------------------------------------------
def test_complete_binding_fixture_against_v1():
    """README section 10: the complete binding is v1's with exactly enforcementPins.admissionFenceDigest (the
    unit-namespace hash) and projections.admissionPolicy.projectionDigest (v4's admissionPolicy digest over closure)
    changed, its uid kept; its profileDigest is the canonical sha256 of v1's complete.profile; no op sets it."""
    v2 = FIXTURES["bindings"]["complete"]
    assert leaf_diff(V1_COMPLETE_BINDING, v2) == {("enforcementPins", "admissionFenceDigest"),
                                                  ("projections", "admissionPolicy", "projectionDigest")}
    assert v2["enforcementPins"]["admissionFenceDigest"] == HASH_UNIT
    closure = snapshot_of("closure")
    document = readme_document("admissionPolicy", closure, v2)
    assert v2["projections"]["admissionPolicy"]["projectionDigest"] == digest_of(document)
    assert v2["projections"]["admissionPolicy"]["uid"] == document["metadata"]["uid"]
    assert v2["profileDigest"] == V1_PROFILE_DIGEST == digest_of(V1_COMPLETE_PROFILE)
    for ops in OPS:
        for op in ops:
            path = op["path"]
            assert not (path[0] == "binding" and (len(path) == 1 or path[1] == "profileDigest")), op


def test_rows_and_af01_op_values():
    """README section 10: 152 vectors (P-UNIT, AP-01..14, AF-01, MI-01, OB-01..12 and 123 others); AF-01's ops[1] and
    ops[2] carry v4's pinned hash (checked over the rows' ops only: some row has that pair)."""
    assert len(OPS) == 1 + 14 + 1 + 1 + 12 + 123
    pairs = [ops for ops in OPS if len(ops) >= 3 and ops[1].get("value") == HASH_QUAL == ops[2].get("value")]
    assert pairs


# ---- 4. the complete positive --------------------------------------------------------------------------------------
def test_replaced_list_matches_readme():
    """README section 10: replaced = v1's ten members plus observation.quota and the six namespace members."""
    replaced = COMPLETE["replaced"]
    added = ["observation.quota", "binding.scope.namespace", "binding.scope.serviceAccountSubject",
             "binding.namespace.name", "binding.projections.*.namespace", "observation.namespace.name",
             "observation.projections.*.namespace"]
    assert all(member in replaced for member in added)
    assert len(replaced) == 10 + len(added)
    assert COMPLETE["snapshot"] == "qual" and COMPLETE["capture"] == "passing"


def test_every_replaced_member_rederived_from_readme():
    """README sections 3.1-5.4 and 10: every leaf under every replaced member equals the value rebuilt here from the
    README's rules (synthetic uids, projection documents and digests, resourceVersions, enforcement digests,
    profileDigest, bindingDigests, the profile's policy digests and references, observation.quota, namespaces)."""
    derived = readme_derived()
    leaves = {}
    for member in ("binding", "request", "observation", "profile"):
        leaves.update(dict(flat(COMPLETE[member], member)))
    matched = {pattern: [] for pattern in COMPLETE["replaced"]}
    for pattern in COMPLETE["replaced"]:
        regex = replaced_regex(pattern)
        for path, value in leaves.items():
            if regex.match(path):
                matched[pattern].append(path)
                assert path in derived, path
                assert path not in MODEL_DERIVED
                assert value == derived[path], path
    assert all(matched.values()), [pattern for pattern, paths in matched.items() if not paths]
    assert "namespace" not in json.dumps(sorted(dict(flat(COMPLETE["request"], "request"))))


def test_admission_policy_projection_and_fence_from_readme():
    """README sections 4.1 and 5.1: the admissionPolicy projection (v4's eight objects sorted by (kind, name) and the
    planeon-qual Pod Security labels) and the admission fence (v4's directory hash at the sealed values)."""
    snapshot, binding = snapshot_of("qual"), COMPLETE["binding"]
    document = readme_document("admissionPolicy", snapshot, binding)
    assert binding["projections"]["admissionPolicy"]["projectionDigest"] == digest_of(document)
    assert COMPLETE["profile"]["policy"]["admissionPolicyDigest"] == digest_of(document)
    assert document["spec"]["podSecurityLabels"] == {"pod-security.kubernetes.io/enforce": "restricted",
                                                     "pod-security.kubernetes.io/enforce-version": "v1.37"}
    assert binding["enforcementPins"]["admissionFenceDigest"] == HASH_QUAL
    assert COMPLETE["observation"]["enforcement"]["admissionFenceDigest"] == HASH_QUAL


def test_profile_references_equal_binding_projections():
    """README section 6 (the capacity signer) and section 10: each preexisting reference's observedDigest and uid, and
    each profile.policy digest and uid, equal the binding's projection; the profile digest and both bindingDigests are
    canonical sha256s."""
    binding, profile = COMPLETE["binding"], COMPLETE["profile"]
    for ref in profile["capacityEntries"]["preexistingResourceRefs"]:
        projection = binding["projections"][KIND_KEY[ref["kind"]]]
        assert (ref["observedDigest"], ref["uid"], ref["name"], ref["namespace"]) == (
            projection["projectionDigest"], projection["uid"], projection["name"], projection["namespace"])
    for member, value in profile["policy"].items():
        if member.endswith("Digest"):
            assert value == binding["projections"][member[:-6]]["projectionDigest"]
    for member in ("resourceQuota", "limitRange", "serviceAccount"):
        assert profile["policy"][member + "Uid"] == binding["projections"][member]["uid"]
    assert profile["policy"]["namespaceUid"] == binding["namespace"]["uid"]
    assert binding["profileDigest"] == digest_of(profile)
    assert COMPLETE["request"]["bindingDigest"] == COMPLETE["observation"]["bindingDigest"] == digest_of(binding)


def test_complete_outside_replaced_is_pv_and_profile_v2():
    """README section 10: the binding is PV's (the unit binding) and the profile is profile v2's positive, with only the
    replaced members changed; profile v2's positive is already at planeon-qual."""
    patterns = [replaced_regex(pattern) for pattern in COMPLETE["replaced"]]

    def text(path, member):
        out = member
        for part in path:
            out += "[%d]" % part if isinstance(part, int) else "." + part
        return out

    for member, original in (("binding", FIXTURES["bindings"]["unit"]), ("profile", PROFILE_V2_POSITIVE)):
        for path in leaf_diff(original, COMPLETE[member]):
            assert any(regex.match(text(path, member)) for regex in patterns), text(path, member)
    assert PROFILE_V2_POSITIVE["binding"]["namespace"] == QUAL


def test_capture_gate_passes_by_readme_rules():
    """README section 3.3: on the passing capture the latest completed set holds every required slot TAKEN and both
    ages are within 0..90 s, so all three gated values are present."""
    assert readme_gate_passes(FIXTURES["captures"]["passing"], FIXTURES["record"]) == {
        "mutationBroker": True, "networkEnforcementDigest": True, "hostPreflightDigest": True}


def test_model_agrees_with_readme_documents():
    """README sections 3.1-5.4 against the model: projection_document and enforcement_digests over qual equal the
    README-built documents and digests, and check_observation_digests on the complete positive is []."""
    snapshot, binding = snapshot_of("qual"), COMPLETE["binding"]
    for key in KEYS:
        document = model.projection_document(key, snapshot, binding)
        assert set(document) == {"apiVersion", "kind", "metadata", "spec"}
        assert set(document["metadata"]) == {"name", "namespace", "uid"}
        assert document == readme_document(key, snapshot, binding), key
    assert model.enforcement_digests(snapshot, I06) == readme_enforcement(snapshot, binding)
    assert run_check(base_state()) == []


# ---- 5. W1, profile v2's part -------------------------------------------------------------------------------------
def test_w1_profile_v2_validate_and_precondition():
    """README sections 10 and 12 (W1): profile v2's validate and precondition on complete.profile are [] with qual's
    qualificationNamespace, which equals SEALED_NAMESPACE and admission v4's sealed.namespace."""
    namespace = FIXTURES["snapshots"]["qual"]["configuration"]["qualificationNamespace"]
    assert namespace == model.SEALED_NAMESPACE == SEALED_V4["namespace"] == QUAL
    assert pp2.validate(COMPLETE["profile"], PROFILE_SCHEMA) == []
    assert pp2.precondition(COMPLETE["profile"], namespace) == []
    assert {key: SEALED_V4[key] for key in SEALED_QUAL} == SEALED_QUAL


@pytest.mark.parametrize("kind", ["ResourceQuota", "LimitRange", "ServiceAccount"])
def test_w1_changed_observed_digest_gives_p10(kind):
    """README section 10 (W1 (3)): a changed observedDigest of the kind's reference gives profile v2's P10 text."""
    profile = copy.deepcopy(COMPLETE["profile"])
    refs = [ref for ref in profile["capacityEntries"]["preexistingResourceRefs"] if ref["kind"] == kind]
    assert len(refs) == 1
    refs[0]["observedDigest"] = "sha256:" + "0" * 64
    assert pp2.TEXT["P10"] in pp2.validate(profile, PROFILE_SCHEMA)


# ---- 6. the counts -------------------------------------------------------------------------------------------------
def test_replay_and_check_counts():
    """README sections 10 and 11: the replay prints one line with 323 checks (16 helpers, the vectors, 1 complete
    positive); _check_complete counts 8 (v1's 5 plus 3); 323 = 16 + 1 + 298 + 8 and R10's 321 = 16 + 1 + 298 + 6
    (v1's five plus the sealed-namespace equality)."""
    result = subprocess.run([sys.executable, "-I", "-B", str(ROOT / "scripts/policy_observation_digests_v2.py")],
                            cwd=str(ROOT), capture_output=True, text=True, timeout=100, check=False)
    assert result.returncode == 0, result.stderr[-2000:]
    lines = [line for line in result.stdout.splitlines() if line.strip()]
    assert len(lines) == 1
    found = re.search(r"\b(\d+) checks \((\d+) helper, (\d+) vectors, (\d+) complete", lines[0])
    assert found and tuple(int(part) for part in found.groups()) == (323, 16, 152, 1), lines[0]
    count = model._check_complete(copy.deepcopy(COMPLETE), copy.deepcopy(FIXTURES), I06, PROFILE_SCHEMA)
    assert count == 8 == 5 + 3
    assert 323 == 16 + 1 + 298 + count
    assert 321 == 16 + 1 + 298 + (5 + 1)


# ---- 7. refusal texts ----------------------------------------------------------------------------------------------
def readme_refusal_texts() -> set:
    keys = KEYS + DIGEST_KEYS
    texts = set()
    for key in keys:
        for text in ("document bound exceeded", "malformed input", "differs from the signed value"):
            texts.add(key + ": " + text)
        if key not in ("rbac", "rbacClosureDigest"):
            texts.add(key + ": float refused")
            texts.add(key + ": integer out of range")
    for key in ("mutationBroker", "networkEnforcementDigest", "hostPreflightDigest"):
        texts.add(key + ": capture set too old")
    for key in ("resourceQuota", "limitRange", "networkPolicy", "serviceAccount"):
        texts.add(key + ": count is not one")
        texts.add(key + ": name differs from the binding")
    texts |= {"admissionPolicy: rendered hash differs", "admissionPolicy: unknown admission object",
              "admissionPolicy: qualification namespace not listed",
              "serviceAccount: enforce-mountable-secrets annotation", "networkPolicy: selector form outside v1",
              "rbac: aggregated role reaches the namespace", "rbac: role does not exist",
              "rbac: loopback user bound to a non-resource rule", "rbac: malformed subject namespace",
              "rbac: malformed subject kind", "rbac: malformed roleRef apiGroup", "rbac: malformed roleRef kind",
              "rbac: malformed rule (non-resource URLs beside resources)",
              "rbacClosureDigest: I06 closure check not passed", "mutationBroker: broker row incomplete",
              "mutationBroker: broker capture not passed", "networkEnforcementDigest: no network policy agent",
              "networkEnforcementDigest: agent capture not passed", "hostPreflightDigest: capture set not passed"}
    for field in ("metadata", "rules", "rule", "rule list", "subjects", "subject", "subject name", "roleRef",
                  "roleRef name"):
        texts.add("rbac: malformed " + field)
    return texts


def test_every_readme_refusal_text_is_pinned():
    """README section 9 (with sections 3.2-5.4 and 4.5's table): every refusal text the README lists is in
    definitions.json refusalTexts, verbatim; rbac's and rbacClosureDigest's float and integer texts are not pinned."""
    pinned = set(DEFINITIONS["refusalTexts"])
    texts = readme_refusal_texts()
    assert texts - pinned == set()
    unreachable = {key + ": " + text for key in ("rbac", "rbacClosureDigest")
                   for text in ("float refused", "integer out of range")}
    assert not unreachable & pinned
    assert model.UNREACHABLE == unreachable


def test_pinned_refusal_texts_are_the_readmes():
    """README section 9: the table is the contract's list of refusal texts; definitions.json pins no other text."""
    assert set(DEFINITIONS["refusalTexts"]) - readme_refusal_texts() == set()
    assert set(model.refusal_texts()) == set(DEFINITIONS["refusalTexts"])


def test_residual_ids():
    """README section 8: the seven residual ids."""
    ids = {"R-ADM-LIST", "R-PSA-CONFIG", "R-NET-DATAPATH", "R-NET-AGENT", "R-DEFAULTS", "R-RBAC-COMPLETE",
           "R-BROKER-LIVE"}
    assert set(DEFINITIONS["residuals"]) == ids == set(model.RESIDUALS)


# ---- 8. status -----------------------------------------------------------------------------------------------------
def test_status_agrees_with_readme():
    """README header and section 12: status.json governs the status line, the review series is
    MET-ENFORCE-042/contract, v1 (MET-ENFORCE-041) is superseded beside it, the non-claims are carried verbatim and
    every carried item the README names is in status.json `carried` with the stated destination."""
    assert "status.json governs" in STATUS["readmeStatusNote"]
    assert STATUS["packet"] == "MET-ENFORCE-042"
    assert STATUS["reviewSeries"] == "MET-ENFORCE-042/contract"
    assert STATUS["supersedes"]["packet"] == "MET-ENFORCE-041"
    assert "scripts/policy_observation_digests.py" in STATUS["supersedes"]["files"]
    assert STATUS["installed"] is False and STATUS["nativeAcceptance"] is False
    for claim in ("Nothing is installed or compiled.",
                  "The I01 v1 wire, I01 v1's files and R10's HE-004-I01B1 are unchanged.",
                  "Profile v1 remains the wire's profile until W3 and W4 land.",
                  "Admission v4's A2 claims stay unproven until C1 and C2.",
                  "DATA_CHECK_ONLY: the model returns errors or derived values, never a protected handle or native "
                  "acceptance."):
        assert claim in STATUS["nonClaims"], claim
    carried = STATUS["carried"]

    def one(item_part: str) -> dict:
        rows = [row for row in carried if item_part in row["item"]]
        assert len(rows) == 1, item_part
        return rows[0]

    assert "HE-004-I01B4" in one("S3")["to"] and "W3" in one("S3")["item"]
    assert one("W4")["to"] == "its own step"
    assert "LPK-1" in one("C1 and C2")["item"] + one("C1 and C2")["to"]
    assert "HE-004-I01B4" in one("D3-1 and C1-7")["to"]
    assert "HE-004-I01B" in one("Q-CB-11 (a)")["to"]
    section6 = one("Section 6")
    assert "HE-004-I01B" in section6["to"] and "HE-008" in section6["to"]
    residuals = one("residuals")
    for rid in ("R-ADM-LIST", "R-PSA-CONFIG", "R-NET-DATAPATH", "R-NET-AGENT", "R-DEFAULTS", "R-RBAC-COMPLETE",
                "R-BROKER-LIVE"):
        assert rid in residuals["item"]
    assert "T04" in residuals["to"] and "HE-005" in residuals["to"]
    assert "List-form revision" in one("Q-CB-15 (a)")["to"]
    for item in ("C3-1", "C4-1", "C4-2"):
        assert one(item)["to"] == "a later contract revision"
    assert "layer test" in one("C1-1")["to"]
    assert "I01 v1" in one("C3-2")["to"]


# ---- 9. edge record v11 --------------------------------------------------------------------------------------------
def test_edge_v11_rows_for_this_contract():
    """README section 12: edge v11 registers this contract's definitions.json, vectors.json and README.md at
    host-enforcement/contracts/i01-digests-v2/, BYTE_IDENTICAL and REGISTERED_BEFORE_USE for HE-004-I01B4, published by
    this packet (providerCommit null, providerPacket MET-ENFORCE-042), each at the sha256 of the file's bytes."""
    edge = _json("architecture/artifact-edges/operator-harness-engineering-v11.json")
    rows = [row for row in edge["artifacts"] if str(row.get("providerPath", "")).startswith(CONTRACT)]
    assert sorted(row["providerPath"] for row in rows) == sorted(CONTRACT + name for name in
                                                                 ("definitions.json", "vectors.json", "README.md"))
    for row in rows:
        name = row["providerPath"][len(CONTRACT):]
        assert row["sha256"] == hashlib.sha256(_bytes(row["providerPath"])).hexdigest(), name
        assert row["consumerPath"] == "host-enforcement/contracts/i01-digests-v2/" + name
        assert row["consumerPacket"] == "HE-004-I01B4"
        assert row["providerPacket"] == "MET-ENFORCE-042"
        assert row["providerCommit"] is None
        assert row["relation"] == "BYTE_IDENTICAL" and row["status"] == "REGISTERED_BEFORE_USE"


# ---- 10. mutations of my own ---------------------------------------------------------------------------------------
def _set_pin(state):
    state["snapshot"]["configuration"]["pinnedManifestHash"] = "sha256:" + "2" * 64


def _set_loaded(state):
    state["snapshot"]["adm4LoadedHash"] = "sha256:" + "3" * 64


def _set_toleration(state):
    state["snapshot"]["configuration"]["sealedAdmission"]["defaultTolerationSeconds"] = 301


def _binding_rq_namespace(state):
    state["binding"]["projections"]["resourceQuota"]["namespace"] = UNIT


def _binding_rbac_namespace(state):
    state["binding"]["projections"]["rbac"]["namespace"] = UNIT


def _quota_lowered(state):
    find(state, "resourceQuotas", "unit-quota")["spec"]["hard"]["pods"] = "0"


def _ref_digest(state):
    state["binding"]["projections"]["limitRange"]["projectionDigest"] = "sha256:" + "0" * 64


def _pin_changed(state):
    state["binding"]["enforcementPins"]["networkEnforcementDigest"] = "sha256:" + "0" * 64


def _binding_uid(state):
    state["binding"]["projections"]["serviceAccount"]["uid"] = "another-uid"


def _netpol(state):
    return find(state, "networkPolicies", "networkpolicy")["spec"]


def _pod_selector(state):
    _netpol(state)["podSelector"] = {"matchLabels": {"app": "probe"}}


def _namespace_peer(state):
    _netpol(state)["ingress"] = [{"from": [{"namespaceSelector": {}}]}]


def _named_port(state):
    _netpol(state)["egress"] = [{"to": [{"ipBlock": {"cidr": "10.0.0.0/8"}}], "ports": [{"protocol": "TCP",
                                                                                         "port": "https"}]}]


def _digit_string_port(state):
    _netpol(state)["egress"] = [{"ports": [{"protocol": "TCP", "port": "443"}]}]


def _extra_spec_member(state):
    _netpol(state)["serviceSelector"] = {}


def _admitted_netpol(state):
    _netpol(state)["ingress"] = [{"from": [{"ipBlock": {"cidr": "10.0.0.0/8"}}],
                                  "ports": [{"protocol": "TCP", "port": 443, "endPort": 450}, {"protocol": "UDP"}]}]


def _float(state):
    find(state, "limitRanges", "unit-limits")["spec"]["limits"][0]["default"]["cpu"] = 0.5


def _too_big(state):
    find(state, "resourceQuotas", "unit-quota")["spec"]["hard"]["requests.storage"] = 2 ** 53


def _too_small(state):
    find(state, "resourceQuotas", "unit-quota")["spec"]["hard"]["requests.storage"] = -(2 ** 53)


def _negative_in_bound(state):
    find(state, "resourceQuotas", "unit-quota")["spec"]["hard"]["requests.storage"] = -(2 ** 53 - 1)


def _too_deep(state):
    node: dict = {}
    top = node
    for _ in range(40):
        node["a"] = {}
        node = node["a"]
    find(state, "resourceQuotas", "unit-quota")["spec"]["deep"] = top


def _annotation(state):
    find(state, "serviceAccounts", "campaign")["metadata"]["annotations"] = {
        "kubernetes.io/enforce-mountable-secrets": "true"}


def _second_quota(state):
    extra = copy.deepcopy(find(state, "resourceQuotas", "unit-quota"))
    extra["metadata"].update({"name": "second-quota", "uid": "second-quota-uid"})
    state["snapshot"]["lists"]["resourceQuotas"].append(extra)


def _quota_name(state):
    state["binding"]["projections"]["resourceQuota"]["name"] = "renamed-quota"


def _no_netpol(state):
    state["snapshot"]["lists"]["networkPolicies"] = []


def _unknown_policy(state):
    state["snapshot"]["lists"]["validatingAdmissionPolicies"].append(
        {"metadata": {"name": "rogue-policy", "uid": "rogue-uid", "resourceVersion": "9"}, "spec": {}})


def _rendered_names(kind):
    return sorted(obj["metadata"]["name"] for obj in adm.a2_objects(dict(SEALED_QUAL)) if obj["kind"] == kind)


def _binding_name_as_policy(state):
    state["snapshot"]["lists"]["validatingAdmissionPolicies"].append(
        {"metadata": {"name": _rendered_names("ValidatingAdmissionPolicyBinding")[0], "uid": "x", "resourceVersion": "9"},
         "spec": {}})


def _rendered_policy_listed(state):
    state["snapshot"]["lists"]["validatingAdmissionPolicies"].append(
        {"metadata": {"name": _rendered_names("ValidatingAdmissionPolicy")[0], "uid": "x", "resourceVersion": "9"},
         "spec": {}})


def _namespace_missing(state):
    state["snapshot"]["lists"]["namespaces"] = [item for item in state["snapshot"]["lists"]["namespaces"]
                                                if item["metadata"]["name"] != QUAL]


def _namespace_twice(state):
    namespaces = state["snapshot"]["lists"]["namespaces"]
    namespaces.append(copy.deepcopy([item for item in namespaces if item["metadata"]["name"] == QUAL][0]))


def _psa_label(state):
    find(state, "namespaces", QUAL, None)["metadata"]["labels"]["pod-security.kubernetes.io/enforce"] = "baseline"


def _other_psa_label(state):
    find(state, "namespaces", "other-namespace", None)["metadata"]["labels"][
        "pod-security.kubernetes.io/enforce"] = "baseline"


def _labels_and_versions(state):
    for list_name, name in (("resourceQuotas", "unit-quota"), ("limitRanges", "unit-limits"),
                            ("networkPolicies", "networkpolicy")):
        item = find(state, list_name, name)
        item["metadata"]["labels"] = {"team": "x"}
        item["metadata"]["annotations"] = {"note": "y"}
        item["metadata"]["resourceVersion"] = "999"
    find(state, "resourceQuotas", "unit-quota")["status"] = {"used": {"pods": "1"}}


def _latest(state):
    return [entry for entry in state["capture"]["sets"] if entry["completed"] is True][-1]


def _answer_at(state, monotonic, wall):
    latest = _latest(state)
    state["capture"]["answer"] = {"monotonicMs": latest["scheduledMonotonicMs"] + monotonic,
                                  "wallMs": latest["startedWallMs"] + wall}


def _at_bound(state):
    _answer_at(state, GATE_BOUND_MS, GATE_BOUND_MS)


def _monotonic_old(state):
    _answer_at(state, GATE_BOUND_MS + 1, 0)


def _wall_old(state):
    _answer_at(state, 0, GATE_BOUND_MS + 1)


def _wall_negative(state):
    _answer_at(state, 0, -1)


def _scheduled_after(state):
    _answer_at(state, -1, 0)


def _slot(name, value="FAILED"):
    def mutate(state):
        _latest(state)["slots"][name] = value
    return mutate


def _later_incomplete(state):
    extra = copy.deepcopy(_latest(state))
    extra["completed"] = False
    extra["slots"] = {slot: "FAILED" for slot in extra["slots"]}
    state["capture"]["sets"].append(extra)


def _later_without_slots(state):
    extra = copy.deepcopy(_latest(state))
    extra["slots"] = {}
    state["capture"]["sets"].append(extra)


def _no_sets(state):
    state["capture"]["sets"] = []


def _malformed_capture(state):
    state["capture"]["answer"]["monotonicMs"] = str(state["capture"]["answer"]["monotonicMs"])


def _broker(state):
    return state["snapshot"]["record"]["roles"]["BROKER"]


def _broker_missing(state):
    del _broker(state)["noNewPrivs"]


def _cgroup_missing(state):
    del _broker(state)["cgroup"]["pidsMax"]


def _broker_extra(state):
    _broker(state)["extraMember"] = 1


def _broker_left_out(state):
    row = _broker(state)
    row["rlimitCore"] = 1 if row["rlimitCore"] != 1 else 2
    row["cgroup"]["inode"] = row["cgroup"]["inode"] + 1 if isinstance(row["cgroup"]["inode"], int) else 12345


def _no_agent(state):
    del state["snapshot"]["record"]["backendComponents"][AGENT]


def _cluster_binding(name, role, subject):
    return {"metadata": {"name": name, "uid": name + "-uid", "resourceVersion": "9"},
            "roleRef": {"apiGroup": "rbac.authorization.k8s.io", "kind": "ClusterRole", "name": role},
            "subjects": [subject]}


def _aggregated(state):
    lists = state["snapshot"]["lists"]
    lists["clusterRoles"].append({"metadata": {"name": "oracle-aggregate", "uid": "oracle-aggregate-uid",
                                               "resourceVersion": "9"},
                                  "aggregationRule": {"clusterRoleSelectors": [{"matchLabels": {"x": "y"}}]},
                                  "rules": []})
    lists["clusterRoleBindings"].append(_cluster_binding("oracle-aggregate", "oracle-aggregate",
                                                         {"apiGroup": "rbac.authorization.k8s.io", "kind": "User",
                                                          "name": "oracle-user"}))


def _dangling(state):
    state["snapshot"]["lists"]["roleBindings"].append(
        {"metadata": {"name": "oracle-dangling", "uid": "oracle-dangling-uid", "resourceVersion": "9",
                      "namespace": QUAL},
         "roleRef": {"apiGroup": "rbac.authorization.k8s.io", "kind": "Role", "name": "oracle-missing"},
         "subjects": [{"kind": "ServiceAccount", "name": "campaign"}]})


def _loopback(state):
    lists = state["snapshot"]["lists"]
    lists["clusterRoles"].append({"metadata": {"name": "oracle-health", "uid": "oracle-health-uid",
                                               "resourceVersion": "9"},
                                  "rules": [{"nonResourceURLs": ["/healthz"], "verbs": ["get"]}]})
    lists["clusterRoleBindings"].append(_cluster_binding("oracle-health", "oracle-health",
                                                         {"apiGroup": "rbac.authorization.k8s.io", "kind": "User",
                                                          "name": "system:apiserver"}))


def _bad_subject_kind(state):
    find(state, "roleBindings", "campaign-reader")["subjects"][0]["kind"] = "Robot"


def _cluster_sa_without_namespace(state):
    state["snapshot"]["lists"]["clusterRoleBindings"].append(
        _cluster_binding("oracle-sa", "closure-54-0", {"kind": "ServiceAccount", "name": "campaign"}))


def _mixed_rule(state):
    find(state, "roles", "campaign-reader")["rules"].append(
        {"apiGroups": [""], "resources": ["pods"], "nonResourceURLs": ["/metrics"], "verbs": ["get"]})


def _new_cluster_grant(state):
    state["snapshot"]["lists"]["clusterRoleBindings"].append(
        _cluster_binding("oracle-grant", "closure-54-0", {"apiGroup": "rbac.authorization.k8s.io", "kind": "User",
                                                          "name": "oracle-new-user"}))


def _other_namespace_grant(state):
    state["snapshot"]["lists"]["roleBindings"].append(
        {"metadata": {"name": "oracle-other", "uid": "oracle-other-uid", "resourceVersion": "9",
                      "namespace": "other-namespace"},
         "roleRef": {"apiGroup": "rbac.authorization.k8s.io", "kind": "ClusterRole", "name": "closure-54-0"},
         "subjects": [{"apiGroup": "rbac.authorization.k8s.io", "kind": "User", "name": "oracle-elsewhere"}]})


def _no_i06(state):
    state["i06"] = None


def _i06_short(state):
    state["i06"] = {key: value for key, value in I06.items() if key != "bootstrap"}


def _no_i06_and_dangling(state):
    _no_i06(state)
    _dangling(state)


def _no_namespace_and_dangling(state):
    del state["snapshot"]["configuration"]["qualificationNamespace"]
    _dangling(state)


GATE_OLD = ["mutationBroker: capture set too old", "networkEnforcementDigest: capture set too old",
            "hostPreflightDigest: capture set too old"]
GATE_NOT = ["mutationBroker: broker capture not passed", "networkEnforcementDigest: agent capture not passed",
            "hostPreflightDigest: capture set not passed"]

# (id, README section, mutation, texts that must appear, texts that must not appear, exact expected list or None)
MUTATIONS = [
    ("M01 qual pinnedManifestHash changed", "4.1", _set_pin, ["admissionPolicy: rendered hash differs"], [], None),
    ("M02 adm4LoadedHash changed", "4.1", _set_loaded, ["admissionPolicy: rendered hash differs"], [], None),
    ("M03 sealed defaultTolerationSeconds changed", "4.1", _set_toleration,
     ["admissionPolicy: rendered hash differs"], [], None),
    ("M04 binding resourceQuota namespace changed", "3.5", _binding_rq_namespace,
     ["resourceQuota: differs from the signed value"], [], None),
    ("M05 binding rbac namespace changed", "3.5", _binding_rbac_namespace,
     ["rbac: differs from the signed value"], [], None),
    ("M06 quota lowered (spec.hard.pods 0)", "3.5", _quota_lowered,
     ["resourceQuota: differs from the signed value"], [], None),
    ("M07 limitRange reference digest changed", "3.5", _ref_digest,
     ["limitRange: differs from the signed value"], [], ["limitRange: differs from the signed value"]),
    ("M08 networkEnforcementDigest pin changed", "3.5", _pin_changed,
     ["networkEnforcementDigest: differs from the signed value"], [],
     ["networkEnforcementDigest: differs from the signed value"]),
    ("M09 binding serviceAccount uid changed", "3.1, 3.5", _binding_uid,
     ["serviceAccount: differs from the signed value"], [], None),
    ("M10 non-empty podSelector", "4.4, 5.3", _pod_selector, ["networkPolicy: selector form outside v1"], [], None),
    ("M11 namespaceSelector peer", "4.4", _namespace_peer, ["networkPolicy: selector form outside v1"], [], None),
    ("M12 named port", "4.4", _named_port, ["networkPolicy: selector form outside v1"], [], None),
    ("M13 port as a string of digits", "4.4", _digit_string_port, ["networkPolicy: selector form outside v1"], [],
     None),
    ("M14 spec member outside the v1 API", "4.4", _extra_spec_member, ["networkPolicy: selector form outside v1"],
     [], None),
    ("M15 ipBlock peer, integer port and endPort, all-ports entry admitted", "4.4", _admitted_netpol,
     ["networkPolicy: differs from the signed value"], ["networkPolicy: selector form outside v1"], None),
    ("M16 float in a projected spec", "3.2", _float, ["limitRange: float refused"], [], None),
    ("M17 integer 2^53 in a projected spec", "3.2", _too_big, ["resourceQuota: integer out of range"], [], None),
    ("M18 integer -(2^53) in a projected spec", "3.2", _too_small, ["resourceQuota: integer out of range"], [], None),
    ("M19 integer -(2^53 - 1) accepted", "3.2", _negative_in_bound, ["resourceQuota: differs from the signed value"],
     ["resourceQuota: integer out of range"], None),
    ("M20 projected spec nested 41 deep", "3.2", _too_deep, ["resourceQuota: document bound exceeded"], [], None),
    ("M21 enforce-mountable-secrets annotation", "4.3", _annotation,
     ["serviceAccount: enforce-mountable-secrets annotation"], [], None),
    ("M22 second ResourceQuota in the namespace", "4.2", _second_quota, ["resourceQuota: count is not one"], [],
     None),
    ("M23 binding's ResourceQuota name changed", "4.2", _quota_name, ["resourceQuota: name differs from the binding"],
     [], None),
    ("M24 no NetworkPolicy", "4.2, 5.3", _no_netpol, ["networkPolicy: count is not one"], [], None),
    ("M25 unknown ValidatingAdmissionPolicy listed", "4.1", _unknown_policy,
     ["admissionPolicy: unknown admission object"], [], None),
    ("M26 policy listed under a rendered binding name", "4.1", _binding_name_as_policy,
     ["admissionPolicy: unknown admission object"], [], None),
    ("M27 policy listed under a rendered policy name admitted", "4.1, 8", _rendered_policy_listed, [], [], []),
    ("M28 qualification Namespace not listed", "4.1", _namespace_missing,
     ["admissionPolicy: qualification namespace not listed"], [], None),
    ("M29 qualification Namespace listed twice", "4.1", _namespace_twice,
     ["admissionPolicy: qualification namespace not listed"], [], None),
    ("M30 qualification Namespace Pod Security label changed", "4.1", _psa_label,
     ["admissionPolicy: differs from the signed value"], [], None),
    ("M31 other namespace's Pod Security label changed", "4.1", _other_psa_label, [], [], []),
    ("M32 labels, annotations, resourceVersions and status of real objects changed", "3.1", _labels_and_versions,
     [], [], []),
    ("M33 both ages exactly 90 s", "3.3", _at_bound, [], [], []),
    ("M34 monotonic age 90 s + 1 ms", "3.3", _monotonic_old, GATE_OLD, [], None),
    ("M35 wall age 90 s + 1 ms", "3.3", _wall_old, GATE_OLD, [], None),
    ("M36 wall age negative", "3.3", _wall_negative, GATE_OLD, [], None),
    ("M37 scheduled start after the answer", "3.3", _scheduled_after, GATE_OLD, [], None),
    ("M38 role/BROKER not TAKEN", "3.3, 4.6, 5.4", _slot("role/BROKER"),
     [GATE_NOT[0], GATE_NOT[2]], [GATE_NOT[1]], None),
    ("M39 backend/NETWORK_POLICY_AGENT not TAKEN", "3.3, 5.3, 5.4", _slot("backend/" + AGENT, "EXPIRED"),
     [GATE_NOT[1], GATE_NOT[2]], [GATE_NOT[0]], None),
    ("M40 lifecycle not TAKEN", "5.4", _slot("lifecycle"), [GATE_NOT[2]], [GATE_NOT[0], GATE_NOT[1]], None),
    ("M41 a later incomplete set is ignored", "3.3", _later_incomplete, [], [], []),
    ("M42 a later completed set without the slots withdraws", "3.3", _later_without_slots, GATE_NOT, [], None),
    ("M43 no capture set", "3.3", _no_sets, GATE_NOT, [], None),
    ("M44 malformed capture data", "3.4", _malformed_capture,
     ["mutationBroker: malformed input", "networkEnforcementDigest: malformed input",
      "hostPreflightDigest: malformed input"], [], None),
    ("M45 BROKER row without noNewPrivs", "4.6", _broker_missing, ["mutationBroker: broker row incomplete"], [], None),
    ("M46 BROKER cgroup without pidsMax", "4.6", _cgroup_missing, ["mutationBroker: broker row incomplete"], [], None),
    ("M47 BROKER row with an extra member", "4.6", _broker_extra, ["mutationBroker: broker row incomplete"], [], None),
    ("M48 BROKER rlimitCore and cgroup.inode changed (outside the document)", "4.6, 5.4", _broker_left_out,
     ["hostPreflightDigest: differs from the signed value"], ["mutationBroker: differs from the signed value"], None),
    ("M49 no NETWORK_POLICY_AGENT", "5.3", _no_agent, ["networkEnforcementDigest: no network policy agent"], [], None),
    ("M50 aggregated ClusterRole bound by a ClusterRoleBinding", "4.5", _aggregated,
     ["rbac: aggregated role reaches the namespace"], [], None),
    ("M51 dangling roleRef", "4.5", _dangling, ["rbac: role does not exist"], [], None),
    ("M52 loopback user bound to a non-resource rule", "4.5", _loopback,
     ["rbac: loopback user bound to a non-resource rule"], [], None),
    ("M53 subject kind outside User, Group, ServiceAccount", "4.5", _bad_subject_kind,
     ["rbac: malformed subject kind"], [], None),
    ("M54 ClusterRoleBinding ServiceAccount subject without a namespace", "4.5", _cluster_sa_without_namespace,
     ["rbac: malformed subject namespace"], [], None),
    ("M55 rule with nonResourceURLs beside resources", "4.5", _mixed_rule,
     ["rbac: malformed rule (non-resource URLs beside resources)"], [], None),
    ("M56 new cluster-wide grant", "4.5", _new_cluster_grant, ["rbac: differs from the signed value"], [], None),
    ("M57 grant in another namespace only", "4.5, 5.2", _other_namespace_grant, [],
     ["rbac: differs from the signed value"], None),
    ("M58 no i06 input", "5.2", _no_i06, ["rbacClosureDigest: malformed input"], [], None),
    ("M59 i06 without bootstrap", "5.2", _i06_short, ["rbacClosureDigest: malformed input"], [], None),
    ("M60 no i06 and a B1 refusal: B1 first", "5.2", _no_i06_and_dangling, ["rbac: role does not exist"],
     ["rbacClosureDigest: malformed input"], None),
    ("M61 no qualification namespace and a B1 refusal: namespace first", "5.2", _no_namespace_and_dangling,
     ["rbacClosureDigest: malformed input"], [], None),
]


@pytest.mark.parametrize("name, section, mutate, present, absent, exact", MUTATIONS, ids=[row[0][:3] for row in MUTATIONS])
def test_mutation(name, section, mutate, present, absent, exact):
    """README sections 3.1-5.4 (the section named per mutation): each mutation of the complete positive is refused
    with the README's text (or, where the README says so, admitted)."""
    state = base_state()
    mutate(state)
    refusals = run_check(state)
    assert isinstance(refusals, list)
    for text in present:
        assert text in refusals, (name, refusals)
    for text in absent:
        assert text not in refusals, (name, refusals)
    if exact is not None:
        assert refusals == exact, (name, refusals)
    if present or exact is None:
        assert refusals, name


def test_mutation_other_namespace_grant_touches_only_the_closure():
    """README sections 4.5 and 5.2: a grant in another namespace is outside rbac's subject set but inside the closure,
    so only the closure's value is refused (the README does not state which closure text; asserted: a
    rbacClosureDigest refusal)."""
    state = base_state()
    _other_namespace_grant(state)
    refusals = run_check(state)
    assert refusals and all(text.startswith("rbacClosureDigest: ") for text in refusals), refusals


def test_mutation_profile_namespace_p40():
    """README sections 10 and 12: precondition runs with the sealed namespace; a profile whose namespace is not
    planeon-qual is refused (the README states no text; profile v2's P40 text asserted from its TEXT constant)."""
    profile = copy.deepcopy(COMPLETE["profile"])
    profile["binding"]["namespace"] = UNIT
    assert pp2.TEXT["P40"] in pp2.precondition(profile, model.SEALED_NAMESPACE)
    assert pp2.TEXT["P40"] in pp2.precondition(COMPLETE["profile"], UNIT)


def test_mutation_profile_schema_digest():
    """README section 0: proxy_profile_v2.validate refuses unless the schema's canonical digest is the reviewed one.
    The README states neither a text nor the refusal's form, so either form is a refusal: an exception, or a
    non-empty list. (First run on c4 asserted the list form only and failed: the model raises. Recorded in the
    oracle report; this is the README's statement, not a loosening below it.)"""
    schema = copy.deepcopy(PROFILE_SCHEMA)
    schema["description"] = str(schema.get("description", "")) + " (oracle mutation)"
    try:
        result = pp2.validate(COMPLETE["profile"], schema)
    except Exception:  # noqa: BLE001 - a raised refusal is a refusal
        return
    assert result != []
