"""D5a oracle tests for POLICY-ADMISSION-SEMANTICS/v4 (LPK-1, MET-LIVE-004).

Black-box tests. Every expectation comes from architecture/admission-semantics-v4/README.md (and, where the README
points at them, the contract data files allowlists.json, status.json and admission-manifests/planeon-a2.json). The
model is called only through its public names. No vector file is read. Each test's docstring names the README
section it checks.

Model exceptions are caught by `run` and returned as "RAISED <type>", so a failing test never prints model source.
"""
from __future__ import annotations

import copy
import hashlib
import importlib.util
import json
import re
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
CONTRACT = ROOT / "architecture" / "admission-semantics-v4"
MODEL_PATH = ROOT / "scripts" / "admission_semantics_v4.py"
README = (CONTRACT / "README.md").read_text(encoding="utf-8")
FLAT = " ".join(README.split())  # the README with its line wrapping undone
SEALED_PATH = CONTRACT / "admission-manifests" / "planeon-a2.json"
SEALED_RAW = SEALED_PATH.read_bytes()
ALLOW = json.loads((CONTRACT / "allowlists.json").read_text(encoding="utf-8"))
STATUS = json.loads((CONTRACT / "status.json").read_text(encoding="utf-8"))
HEADINGS = re.findall(r"^## (.+)$", README, re.M)


def _load_model():
    spec = importlib.util.spec_from_file_location("admission_semantics_v4_oracle_subject", MODEL_PATH)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


M = _load_model()


def run(fn, *args, **kwargs):
    """Call a public model function; an exception becomes the string "RAISED <type>"."""
    try:
        return fn(*args, **kwargs)
    except Exception as exc:  # the model's exception, reported by type only
        return "RAISED " + type(exc).__name__


# --------------------------------------------------------------------------------------------------------------------
# README literals (each one is checked to occur in the README by test_readme_literals_are_quoted_from_the_readme)
# --------------------------------------------------------------------------------------------------------------------
NS = "planeon-qual"
MC42_PREFIX = "MC42 every emptyDir is bounded: "
R1 = "a sizeLimit in decimal bytes"
R2 = "no medium"
R3 = "an ephemeral-storage limit in decimal bytes on every container and init container"
R4 = "the sizeLimits sum to at most the containers' ephemeral-storage limits"
MC33_TEXT = "MC33 every image is pinned by digest and pulled Never"
PULL_REFUSAL = "A2-POD-PULL-POLICY an image pull policy other than Never"
EMPTYDIR_READING = "an emptyDir without a sizeLimit or with a medium"
EMPTYDIR_CEL = ("!has(object.spec.volumes) || object.spec.volumes.all(v, !has(v.emptyDir) || "
                "(has(v.emptyDir.sizeLimit) && !has(v.emptyDir.medium)))")
POD_ORDER = ["A2-RESERVED", "A2-POD-ECHO", "A2-POD-TOKEN", "A2-POD-PULL-SECRETS", "A2-POD-IMAGE-VOLUME",
             "A2-POD-TOLERATIONS", "A2-POD-PRIORITY", "A2-POD-PLACEMENT", "A2-POD-PULL-POLICY", "A2-POD-EMPTYDIR"]
CM_ORDER = ["A2-CM-PUBLISHER", "A2-RESERVED", "A2-CM-IMMUTABLE"]
C01_TEXT = "cite POLICY-ADMISSION-SEMANTICS/v4 checks"
C03_TEXT = "cite v4"
C04_TEXT = ("a v3 claim lacks the AlwaysPullImages evidence and pins the superseded sealed directory; cite v4")
C28_TEXT = "A2's pull-policy argument needs AlwaysPullImages disabled on the apiserver (pinned off)"
SEALED_SIZE = 8322
SEALED_SHA256 = "92c21612304cb704d13b506c1ae885d62a47c01f0ed0d284affe563aa1868e32"
DIR_HASH_V4 = "sha256:9b1ddc1096ff0d35fb4cd5a9e5e6b4248fefc5b75b5a06f862c59d85e028ca60"
DIR_HASH_V3 = "sha256:5aa2cdec0b8dc08c008b887e30b9954ffc46e7d779365f64db1adfd80656f189"
MC38_TEXT_PART = "(AlwaysPullImages rewrites its pull policy)"
TOKEN_PATH = "/var/run/secrets/kubernetes.io/serviceaccount"

KEPT_MC = ["MC00", "MC01", "MC02", "MC03", "MC04", "MC05", "MC06", "MC10", "MC11", "MC20", "MC21", "MC22", "MC30",
           "MC31", "MC32", "MC34", "MC35", "MC36", "MC37", "MC38", "MC39", "MC40", "MC41"]
KEPT_A2 = ["A2-RESERVED", "A2-CM-PUBLISHER", "A2-CM-IMMUTABLE", "A2-SVC-TYPE", "A2-SVC-ALLOCATION", "A2-SVC-DEFAULTS",
           "A2-POD-ECHO", "A2-POD-TOKEN", "A2-POD-PULL-SECRETS", "A2-POD-IMAGE-VOLUME", "A2-POD-TOLERATIONS",
           "A2-POD-PRIORITY", "A2-POD-PLACEMENT", "A2-GUARD"]
KEPT_C = ["C00", "C02", "C10", "C11", "C12", "C20", "C21", "C22", "C23", "C24", "C25", "C26", "C27", "C30", "C31",
          "C40", "C41"]
ALL_C = KEPT_C + ["C01", "C03", "C04", "C28"]

# The README's four sealed values ("the vectors use planeon-qual, IPv4, 10.96.0.0/12 and 300"). The key names are the
# model's (learned from the KeyError names it raised for an empty dict; disclosed in the oracle report).
SEALED = {"namespace": NS, "ipFamily": "IPv4", "serviceCIDR": "10.96.0.0/12", "defaultTolerationSeconds": 300}
# The server block: "alwaysPullImages" is the README's key; the other key names are the model's (KeyError names).
SERVER = {"namespace": NS, "uid": "3f1c2a64-0d5e-4b7a-9c11-6a0e5d2b8f40", "creationTimestamp": "2026-10-24T00:00:00Z",
          "fieldManager": "oracle-gate", "defaultTolerationSeconds": 300, "alwaysPullImages": False}

IMG = "registry.invalid/oracle/probe@sha256:" + "1" * 64
IMG_SETUP = "registry.invalid/oracle/setup@sha256:" + "2" * 64
IMG_SIDE = "registry.invalid/oracle/side@sha256:" + "3" * 64


# --------------------------------------------------------------------------------------------------------------------
# Manifest builders (my own; not taken from any vector file)
# --------------------------------------------------------------------------------------------------------------------
_DEFAULT = object()


def container(name="probe", image=IMG, eph="1073741824", pull="Never", resources=_DEFAULT):
    c = {"name": name, "image": image}
    if pull is not None:
        c["imagePullPolicy"] = pull
    if resources is not _DEFAULT:
        c["resources"] = resources  # may be any value, None included
    else:
        limits = {"cpu": "100m", "memory": "67108864"}
        if eph is not None:
            limits["ephemeral-storage"] = eph
        c["resources"] = {"limits": dict(limits), "requests": dict(limits)}
    return c


def scratch(size="536870912", name="scratch", **extra):
    ed = {} if size is None else {"sizeLimit": size}
    ed.update(extra)
    return {"name": name, "emptyDir": ed}


def pod(containers=None, init=None, volumes="default", name="probe-pod", echo=True):
    containers = [container()] if containers is None else containers
    volumes = [scratch()] if volumes == "default" else volumes
    spec = {"automountServiceAccountToken": False, "containers": containers}
    if init is not None:
        spec["initContainers"] = init
    if volumes:
        spec["volumes"] = volumes
    meta = {"name": name, "namespace": NS}
    if echo:
        meta["annotations"] = {
            "planeon.ai/a2-containers": ",".join(c["name"] + "=" + c["image"] for c in containers),
            "planeon.ai/a2-init-containers": ",".join(c["name"] + "=" + c["image"] for c in (init or [])),
            "planeon.ai/a2-volumes": ",".join(v["name"] for v in (volumes or [])),
        }
    return {"apiVersion": "v1", "kind": "Pod", "metadata": meta, "spec": spec}


def pod_init():
    """The README's PodInit values: probe 1073741824, setup init 268435456, scratch sizeLimit 536870912."""
    return pod(containers=[container(eph="1073741824")], init=[container("setup", IMG_SETUP, eph="268435456")],
               volumes=[scratch("536870912")])


FOUR_SOURCES = [
    {"name": "cfg", "configMap": {"name": "probe-config"}},
    {"name": "sec", "secret": {"secretName": "probe-secret"}},
    {"name": "info", "downwardAPI": {"items": [{"path": "labels", "fieldRef": {"fieldPath": "metadata.labels"}}]}},
    {"name": "proj", "projected": {"sources": [{"configMap": {"name": "probe-config"}},
                                               {"secret": {"name": "probe-secret"}}]}},
]


def configmap():
    return {"apiVersion": "v1", "kind": "ConfigMap", "metadata": {"name": "probe-config", "namespace": NS},
            "immutable": True, "data": {"k": "v"}}


def service():
    return {"apiVersion": "v1", "kind": "Service", "metadata": {"name": "probe-svc", "namespace": NS},
            "spec": {"type": "ClusterIP", "selector": {"app": "probe"}, "ports": [{"port": 8080}]}}


def check(manifest, kind=None):
    return run(M.check_manifest, kind or manifest["kind"], manifest, NS)


def final(manifest, always=False):
    server = dict(SERVER, alwaysPullImages=always)
    return run(M.final_object, manifest["kind"], copy.deepcopy(manifest), server)


def a2(obj, kind="Pod"):
    return run(M.check_final, kind, obj, SEALED)


def mc42(reason):
    return MC42_PREFIX + reason


def code_of(result):
    return result.split(" ", 1)[0] if isinstance(result, str) else result


def sealed_doc():
    return json.loads(SEALED_RAW)


def policy(doc, name):
    return next(i for i in doc["items"] if i["metadata"]["name"] == name)


POD_POLICY = "planeon-a2-pod.static.k8s.io"


# ====================================================================================================================
# Self-checks: the literals above are the README's words; each docstring cites a README section
# ====================================================================================================================
def test_readme_literals_are_quoted_from_the_readme():
    """README §MC42, every emptyDir is bounded; §A2-POD-EMPTYDIR; §AlwaysPullImages, pinned off; §What v4 changes:
    every refusal text, expression and digest this oracle expects occurs verbatim in the README."""
    for literal in (MC42_PREFIX, R1, R2, R3, R4, MC33_TEXT, PULL_REFUSAL, EMPTYDIR_READING, EMPTYDIR_CEL, C01_TEXT,
                    C03_TEXT, C04_TEXT, C28_TEXT, str(SEALED_SIZE), SEALED_SHA256, DIR_HASH_V4, DIR_HASH_V3,
                    MC38_TEXT_PART, ", ".join(POD_ORDER), "`^[1-9][0-9]{0,14}$`", "planeon-qual", "`10.96.0.0/12`"):
        assert literal in FLAT, literal
    for code in KEPT_MC + KEPT_A2 + KEPT_C + ["MC33", "MC42", "A2-POD-PULL-POLICY", "A2-POD-EMPTYDIR", "C01", "C03",
                                              "C04", "C28"]:
        assert code in README, code


def test_every_test_docstring_names_a_readme_section():
    """README §(all sections): each test's docstring starts with README and names at least one README heading."""
    names = [n for n, f in globals().items() if n.startswith("test_") and callable(f)]
    assert len(names) >= 40
    for n in names:
        doc = globals()[n].__doc__ or ""
        assert doc.startswith("README"), n
        sections = re.findall(r"§([^;:\n]+?)(?=[;:]|\n|$)", doc)
        assert sections, n
        for s in sections:
            s = s.strip()
            assert s == "(all sections)" or any(h.startswith(s) or s.startswith(h) for h in HEADINGS) \
                or s.startswith("status line"), (n, s)


# ====================================================================================================================
# 1. MC42, every emptyDir is bounded
# ====================================================================================================================
def test_mc42_bounded_pod_is_admitted():
    """README §MC42, every emptyDir is bounded: a bounded emptyDir Pod (decimal bytes, no medium, limits, sum in
    budget) passes check_manifest."""
    assert check(pod()) is None


def test_mc42_readme_podinit_values_are_admitted_and_reemitted_unchanged():
    """README §MC42, every emptyDir is bounded: PodInit's probe 1073741824, setup 268435456 and scratch sizeLimit
    536870912 are admitted, and final_object keeps the strings (powers of two, no new re-emission rule)."""
    m = pod_init()
    assert check(m) is None
    obj = final(m)
    assert isinstance(obj, dict), obj
    assert obj["spec"]["volumes"][0]["emptyDir"] == {"sizeLimit": "536870912"}
    assert obj["spec"]["containers"][0]["resources"]["limits"]["ephemeral-storage"] == "1073741824"
    assert obj["spec"]["containers"][0]["resources"]["requests"]["ephemeral-storage"] == "1073741824"
    assert obj["spec"]["initContainers"][0]["resources"]["limits"]["ephemeral-storage"] == "268435456"
    assert a2(obj) is None


@pytest.mark.parametrize("value", ["bounded", [], [{"sizeLimit": "536870912"}], 536870912, None, True])
def test_mc42_check1_emptydir_not_an_object(value):
    """README §MC42, every emptyDir is bounded: check 1, "an emptyDir that is not an object fails here too"."""
    assert check(pod(volumes=[{"name": "scratch", "emptyDir": value}])) == mc42(R1)


@pytest.mark.parametrize("size", [
    "0",                      # zero
    "00",                     # zero, two digits
    "0536870912",             # leading zero
    "000000001",              # leading zeros
    "5e8", "5E8", "1e3",      # exponent
    "5.36870912e8",           # exponent with a fraction
    "536870912000m",          # milli
    "1000m",                  # milli
    "512Mi", "1Gi", "524288Ki",  # binary suffixes
    "512M", "1G", "1k",       # decimal suffixes
    "536870912.0", "-536870912", "+536870912", "", " 536870912", "536870912 ",
    "1000000000000000",       # 16 digits: over {0,14}
])
def test_mc42_check1_refused_sizelimit_forms(size):
    """README §MC42, every emptyDir is bounded: binary or decimal suffixes, exponents, milli units, zero and leading
    zeros are refused, with check 1's reason."""
    m = pod(containers=[container(eph="999999999999999")], volumes=[scratch(size)])
    assert check(m) == mc42(R1)


@pytest.mark.parametrize("size", ["1", "536870912", "1073741824", "999999999999999"])
def test_mc42_accepted_decimal_bytes_form(size):
    """README §MC42, every emptyDir is bounded: the decimal byte form ^[1-9][0-9]{0,14}$ is accepted."""
    m = pod(containers=[container(eph="999999999999999")], volumes=[scratch(size)])
    assert check(m) is None


def test_mc42_check1_missing_or_null_sizelimit():
    """README §MC42, every emptyDir is bounded: check 1 needs a sizeLimit (emptyDir: {} and a null sizeLimit fail)."""
    assert check(pod(volumes=[scratch(None)])) == mc42(R1)
    assert check(pod(volumes=[{"name": "scratch", "emptyDir": {"sizeLimit": None}}])) == mc42(R1)


@pytest.mark.parametrize("medium", ["", "Memory", "HugePages", None])
def test_mc42_check2_no_medium_member_not_even_empty(medium):
    """README §MC42, every emptyDir is bounded: check 2, "no medium" member, not even "" (a present member of any
    value fails)."""
    assert check(pod(volumes=[scratch("536870912", medium=medium)])) == mc42(R2)


def test_mc42_check3_container_without_ephemeral_storage_limit():
    """README §MC42, every emptyDir is bounded: check 3, a container without an ephemeral-storage limit."""
    assert check(pod(containers=[container(eph=None)])) == mc42(R3)


def test_mc42_check3_init_container_without_ephemeral_storage_limit():
    """README §MC42, every emptyDir is bounded: check 3, init containers must carry a limit."""
    m = pod(init=[container("setup", IMG_SETUP, eph=None)])
    assert check(m) == mc42(R3)


@pytest.mark.parametrize("eph", ["1Gi", "1G", "0", "01073741824", "1e9", "1073741824000m", "1000000000000000"])
@pytest.mark.parametrize("where", ["container", "init"])
def test_mc42_check3_limit_not_in_decimal_bytes(eph, where):
    """README §MC42, every emptyDir is bounded: in a Pod with an emptyDir, every ephemeral-storage limit is in the
    decimal byte form (check 3)."""
    if where == "container":
        m = pod(containers=[container(eph=eph)])
    else:
        m = pod(init=[container("setup", IMG_SETUP, eph=eph)])
    assert check(m) == mc42(R3)


@pytest.mark.parametrize("limits", ["1073741824", ["ephemeral-storage"], 1073741824, True])
@pytest.mark.parametrize("where", ["container", "init"])
def test_mc42_check3_limits_not_an_object(limits, where):
    """README §MC42, every emptyDir is bounded: a container or init container whose `limits` is not an object has no
    such limit and fails check 3 (an emptyDir is present)."""
    res = {"limits": copy.deepcopy(limits), "requests": copy.deepcopy(limits)}
    if where == "container":
        m = pod(containers=[container(resources=res)])
    else:
        m = pod(init=[container("setup", IMG_SETUP, resources=res)])
    assert check(m) == mc42(R3)


@pytest.mark.parametrize("resources", [{}, None])
def test_mc42_empty_or_null_resources_refused_earlier_by_mc34(resources):
    """README §MC42, every emptyDir is bounded: a `resources` that is empty or null is refused earlier by MC34."""
    assert code_of(check(pod(containers=[container(resources=resources)]))) == "MC34"


@pytest.mark.parametrize("resources", ["requests-and-limits", 7])
def test_mc42_non_object_resources_raises_in_carried_mc34(resources):
    """README §MC42, every emptyDir is bounded: any other `resources` that is not an object makes the carried MC34
    check raise an error instead of refusing, so it never reaches check 3."""
    result = check(pod(containers=[container(resources=resources)]))
    assert isinstance(result, str) and result.startswith("RAISED "), result


def test_mc42_mc34_runs_earlier_requests_must_equal_limits():
    """README §MC42, every emptyDir is bounded: MC34 (requests equal limits) runs earlier than check 3."""
    res = {"limits": {"ephemeral-storage": "1073741824"}, "requests": {"ephemeral-storage": "536870912"}}
    assert code_of(check(pod(containers=[container(resources=res)]))) == "MC34"


def test_mc42_check4_sum_at_the_limit_is_admitted():
    """README §MC42, every emptyDir is bounded: check 4, a sum exactly equal to the containers' limits is admitted."""
    assert check(pod(volumes=[scratch("1073741824")])) is None


def test_mc42_check4_sum_over_by_one_byte():
    """README §MC42, every emptyDir is bounded: check 4, the sum over the limit by one byte is refused."""
    assert check(pod(volumes=[scratch("1073741825")])) == mc42(R4)


def test_mc42_check4_sum_under_the_limit_is_admitted():
    """README §MC42, every emptyDir is bounded: check 4, a sum under the limit is admitted."""
    assert check(pod(volumes=[scratch("1073741823")])) is None
    assert check(pod(volumes=[scratch("1")])) is None


def test_mc42_check4_init_container_larger_limit_not_counted():
    """README §MC42, every emptyDir is bounded: init containers' limits do not count toward the sum (check 4)."""
    init = [container("setup", IMG_SETUP, eph="4294967296")]
    assert check(pod(init=init, volumes=[scratch("2147483648")])) == mc42(R4)
    assert check(pod(init=init, volumes=[scratch("1073741825")])) == mc42(R4)
    assert check(pod(init=init, volumes=[scratch("1073741824")])) is None


def test_mc42_check4_sums_every_container_and_every_emptydir():
    """README §MC42, every emptyDir is bounded: check 4 compares the sum of the sizeLimits with the sum of the
    spec.containers limits."""
    two = [container(eph="536870912"), container("side", IMG_SIDE, eph="536870912")]
    assert check(pod(containers=two, volumes=[scratch("1073741824")])) is None
    assert check(pod(containers=two, volumes=[scratch("1073741825")])) == mc42(R4)
    vols = [scratch("536870912", name="a"), scratch("536870912", name="b")]
    assert check(pod(volumes=vols)) is None
    vols = [scratch("536870912", name="a"), scratch("536870913", name="b")]
    assert check(pod(volumes=vols)) == mc42(R4)


def test_mc42_order_first_emptydir_check2_before_second_emptydir_check1():
    """README §MC42, every emptyDir is bounded: checks 1 and 2 run per emptyDir in volume order (the first with a
    medium, the second without a sizeLimit, refuses with "no medium")."""
    vols = [scratch("268435456", name="a", medium="Memory"), scratch(None, name="b")]
    assert check(pod(volumes=vols)) == mc42(R2)


def test_mc42_order_first_emptydir_check1_before_second_emptydir_check2():
    """README §MC42, every emptyDir is bounded: the first emptyDir takes check 1 before the next emptyDir."""
    vols = [scratch(None, name="a"), scratch("268435456", name="b", medium="Memory")]
    assert check(pod(volumes=vols)) == mc42(R1)


def test_mc42_order_check1_before_check2_on_one_emptydir():
    """README §MC42, every emptyDir is bounded: one emptyDir takes check 1 and then check 2."""
    assert check(pod(volumes=[scratch(None, medium="Memory")])) == mc42(R1)
    assert check(pod(volumes=[scratch("512Mi", medium="Memory")])) == mc42(R1)


def test_mc42_order_checks_1_and_2_before_check_3():
    """README §MC42, every emptyDir is bounded: checks 3 and 4 run once, after every emptyDir has passed checks 1 and
    2."""
    no_limit = [container(eph=None)]
    vols = [scratch("268435456", name="a"), scratch("1Gi", name="b")]
    assert check(pod(containers=no_limit, volumes=vols)) == mc42(R1)
    vols = [scratch("268435456", name="a"), scratch("268435456", name="b", medium="")]
    assert check(pod(containers=no_limit, volumes=vols)) == mc42(R2)


def test_mc42_order_check3_before_check4():
    """README §MC42, every emptyDir is bounded: check 3 comes before check 4."""
    init = [container("setup", IMG_SETUP, eph=None)]
    assert check(pod(init=init, volumes=[scratch("2147483648")])) == mc42(R3)


def test_mc42_pod_without_emptydir_is_not_touched():
    """README §MC42, every emptyDir is bounded: a Pod without an emptyDir is not touched, and neither is its quantity
    form."""
    assert check(pod(containers=[container(eph=None)], volumes=[])) is None
    assert check(pod(containers=[container(eph="1Gi")], volumes=[])) is None
    assert check(pod(containers=[container(eph=None)], init=[container("setup", IMG_SETUP, eph="512Mi")],
                     volumes=copy.deepcopy(FOUR_SOURCES))) is None


def test_mc42_comes_after_mc41():
    """README §MC42, every emptyDir is bounded: MC42 comes after MC41."""
    vols = [{"name": "host", "hostPath": {"path": "/srv"}}, scratch(None)]
    assert code_of(check(pod(volumes=vols))) == "MC41"


def test_mc42_comes_before_mc37():
    """README §MC42, every emptyDir is bounded: MC42 comes before MC37, so MC37 stays last."""
    m = pod(volumes=[scratch(None)])
    m["metadata"]["annotations"]["planeon.ai/a2-volumes"] = "not-the-volumes"
    assert check(m) == mc42(R1)
    m = pod()
    m["metadata"]["annotations"]["planeon.ai/a2-volumes"] = "not-the-volumes"
    assert code_of(check(m)) == "MC37"


def test_mc42_mc36_precedes_mc42():
    """README §The v3 re-derivation table: N19 (token-like name, `emptyDir: {}`) stays MC36, which precedes MC42."""
    assert code_of(check(pod(volumes=[scratch(None, name="kube-api-access-oracle")]))) == "MC36"


def test_mc42_constraint_coverage():
    """README §MC42, every emptyDir is bounded: constraintCoverage.MC42 is RECHECKED_BY_A2 A2-POD-EMPTYDIR for
    sizeLimit present and medium absent, SIGNER_GUARANTEED for the decimal forms, the limits and the sum."""
    text = ALLOW["constraintCoverage"]["MC42"]
    assert text.startswith("RECHECKED_BY_A2 A2-POD-EMPTYDIR")
    assert "sizeLimit present" in text and "medium absent" in text
    assert "SIGNER_GUARANTEED" in text and "ephemeral-storage limits" in text and "sum" in text


# ====================================================================================================================
# 2. The pattern reading (re.match with ^...$: "$" also matches before one trailing line feed)
# ====================================================================================================================
def test_pattern_reading_sizelimit_with_one_trailing_line_feed_passes():
    """README §MC42, every emptyDir is bounded: `536870912` followed by one line feed passes the pattern as a
    sizeLimit."""
    assert check(pod(volumes=[scratch("536870912\n")])) is None


def test_pattern_reading_limit_with_one_trailing_line_feed_passes():
    """README §MC42, every emptyDir is bounded: a decimal-bytes value followed by one line feed passes as a limit."""
    assert check(pod(containers=[container(eph="1073741824\n")])) is None
    assert check(pod(init=[container("setup", IMG_SETUP, eph="268435456\n")])) is None


@pytest.mark.parametrize("size", ["536870912\n\n", "\n536870912", "536870912\r\n", "536870912\r", "536870912 \n"])
def test_pattern_reading_other_line_ends_are_refused(size):
    """README §MC42, every emptyDir is bounded: only one trailing line feed matches before `$`; anything else fails
    check 1."""
    assert check(pod(volumes=[scratch(size)])) == mc42(R1)


def test_pattern_reading_limit_with_two_line_feeds_is_refused():
    """README §MC42, every emptyDir is bounded: a limit with two trailing line feeds fails check 3."""
    assert check(pod(containers=[container(eph="1073741824\n\n")])) == mc42(R3)


def test_pattern_reading_name_with_one_trailing_line_feed_passes():
    """README §MC42, every emptyDir is bounded: a name such as `probe-pod` followed by one line feed passes the
    pattern, and with two it does not."""
    assert check(pod(name="probe-pod\n")) is None
    assert check(pod(name="probe-pod\n\n")) is not None


def test_pattern_reading_applies_to_carried_digest_pattern():
    """README §MC42, every emptyDir is bounded: every pattern v4 applies, those carried from v3 included, is read the
    same way (the digest pattern accepts one trailing line feed and refuses two)."""
    one = check(pod(containers=[container(image=IMG + "\n")]))
    assert not (isinstance(one, str) and one.startswith("MC33")), one
    assert check(pod(containers=[container(image=IMG + "\n\n")])) == MC33_TEXT


# ====================================================================================================================
# 3. A2-POD-EMPTYDIR and its guard
# ====================================================================================================================
def test_a2_emptydir_rendered_expression_is_exact_and_last():
    """README §A2-POD-EMPTYDIR: the rendered expression is exactly the README's, its message is A2-POD-EMPTYDIR, and
    it is last in the Pod policy, in the stated order."""
    for doc_items in (sealed_doc()["items"], run(M.a2_objects, dict(SEALED))):
        pol = next(i for i in doc_items if i["metadata"]["name"] == POD_POLICY)
        vals = pol["spec"]["validations"]
        assert [v["message"] for v in vals] == POD_ORDER
        assert vals[-1]["expression"] == EMPTYDIR_CEL
        assert vals[-1]["message"] == "A2-POD-EMPTYDIR"


def test_a2_emptydir_guard_pod_without_volumes():
    """README §A2-POD-EMPTYDIR: guarded, no runtime error (no refusal) on a Pod without volumes."""
    m = pod(containers=[container(eph=None)], volumes=[])
    assert check(m) is None
    obj = final(m)
    assert isinstance(obj, dict), obj
    assert "volumes" not in obj["spec"]
    assert a2(obj) is None


def test_a2_emptydir_guard_four_other_sources():
    """README §A2-POD-EMPTYDIR: guarded, no refusal on configMap, secret, downwardAPI or projected volumes."""
    m = pod(containers=[container(eph=None)], volumes=copy.deepcopy(FOUR_SOURCES))
    assert check(m) is None
    obj = final(m)
    assert isinstance(obj, dict), obj
    assert a2(obj) is None


def test_a2_emptydir_refuses_missing_sizelimit():
    """README §A2-POD-EMPTYDIR: its reference reading refuses "an emptyDir without a sizeLimit"."""
    obj = final(pod())
    obj["spec"]["volumes"][0]["emptyDir"] = {}
    assert a2(obj) == "A2-POD-EMPTYDIR " + EMPTYDIR_READING


def test_a2_emptydir_refuses_medium():
    """README §A2-POD-EMPTYDIR: its reference reading refuses an emptyDir "with a medium"."""
    obj = final(pod())
    obj["spec"]["volumes"][0]["emptyDir"]["medium"] = "Memory"
    assert a2(obj) == "A2-POD-EMPTYDIR " + EMPTYDIR_READING


@pytest.mark.parametrize("size", ["512Mi", "1G", "536870912"])
def test_a2_emptydir_checks_presence_only(size):
    """README §Allowed differences per kind: A2-POD-EMPTYDIR checks presence only (A2 compares no quantities)."""
    obj = final(pod())
    obj["spec"]["volumes"][0]["emptyDir"]["sizeLimit"] = size
    assert a2(obj) is None


def test_a2_emptydir_injected_emptydir_still_refused_by_echo():
    """README §A2-POD-EMPTYDIR: it comes after A2-POD-ECHO, so an injected `emptyDir: {}` refuses with A2-POD-ECHO."""
    obj = final(pod())
    obj["spec"]["volumes"].append({"name": "injected", "emptyDir": {}})
    assert code_of(a2(obj)) == "A2-POD-ECHO"


def test_a2_emptydir_after_pull_policy():
    """README §A2-POD-EMPTYDIR: last in the Pod policy, after A2-POD-PULL-POLICY."""
    obj = final(pod())
    obj["spec"]["volumes"][0]["emptyDir"] = {}
    obj["spec"]["containers"][0]["imagePullPolicy"] = "Always"
    assert a2(obj) == PULL_REFUSAL


def test_a2_emptydir_after_reserved():
    """README §The sealed directory (`admission-manifests/planeon-a2.json`): check_final starts with A2-RESERVED."""
    obj = final(pod())
    obj["spec"]["volumes"][0]["emptyDir"] = {}
    obj["metadata"].setdefault("labels", {})["app.kubernetes.io/name"] = "x"
    assert code_of(a2(obj)) == "A2-RESERVED"


def _rendered():
    return run(M.a2_objects, dict(SEALED))


def _set_pod_validations(objs, fn):
    objs = copy.deepcopy(objs)
    pol = next(i for i in objs if i["metadata"]["name"] == POD_POLICY)
    pol["spec"]["validations"] = fn(pol["spec"]["validations"])
    return objs


def test_a2_emptydir_check_a2_objects_accepts_the_rendering():
    """README §The sealed directory (`admission-manifests/planeon-a2.json`): check_a2_objects accepts v4's rendering
    and the sealed file's items."""
    assert run(M.check_a2_objects, _rendered(), dict(SEALED)) is None
    assert run(M.check_a2_objects, sealed_doc()["items"], dict(SEALED)) is None


def test_a2_emptydir_removed_is_s06():
    """README §Vectors: A2-POD-EMPTYDIR removed refuses with S06 (S06 compares with v4's rendering)."""
    objs = _set_pod_validations(_rendered(), lambda vs: vs[:-1])
    assert code_of(run(M.check_a2_objects, objs, dict(SEALED))) == "S06"


def test_a2_emptydir_unguarded_is_s06():
    """README §A2-POD-EMPTYDIR: the unguarded rendering is kept out (S06)."""
    def unguard(vs):
        vs[-1]["expression"] = "object.spec.volumes.all(v, has(v.emptyDir.sizeLimit) && !has(v.emptyDir.medium))"
        return vs
    objs = _set_pod_validations(_rendered(), unguard)
    assert code_of(run(M.check_a2_objects, objs, dict(SEALED))) == "S06"


def test_a2_v3_pull_policy_rendering_is_s06():
    """README §Every rule, KEPT, CHANGED or NEW: A2-POD-PULL-POLICY CHANGED to 'Never'; a rendering that still
    requires 'Always' is a change to a rendered validation (S06)."""
    def to_always(vs):
        vs[-2]["expression"] = vs[-2]["expression"].replace("'Never'", "'Always'")
        return vs
    objs = _set_pod_validations(_rendered(), to_always)
    assert code_of(run(M.check_a2_objects, objs, dict(SEALED))) == "S06"


def test_a2_emptydir_reordered_is_refused():
    """README §The sealed directory (`admission-manifests/planeon-a2.json`): check_a2_objects refuses any other
    structure (S01-S06), including a reordered Pod policy."""
    def swap(vs):
        vs[-1], vs[-2] = vs[-2], vs[-1]
        return vs
    objs = _set_pod_validations(_rendered(), swap)
    assert code_of(run(M.check_a2_objects, objs, dict(SEALED))) in {"S01", "S02", "S03", "S04", "S05", "S06"}


# ====================================================================================================================
# 4. AlwaysPullImages, pinned off; MC33 and A2-POD-PULL-POLICY
# ====================================================================================================================
@pytest.mark.parametrize("pull", ["Always", "IfNotPresent", "never", "", None])
def test_mc33_container_pull_policy_other_than_never(pull):
    """README §What v4 changes: MC33 "every image is pinned by digest and pulled Never"; an omitted policy is
    refused."""
    assert check(pod(containers=[container(pull=pull)])) == MC33_TEXT


@pytest.mark.parametrize("pull", ["Always", "IfNotPresent", None])
def test_mc33_init_container_pull_policy_other_than_never(pull):
    """README §What v4 changes: MC33 covers every image, init containers included."""
    assert check(pod(init=[container("setup", IMG_SETUP, eph="268435456", pull=pull)])) == MC33_TEXT


@pytest.mark.parametrize("image", ["registry.invalid/oracle/probe:1.0", "registry.invalid/oracle/probe",
                                   "registry.invalid/oracle/probe@sha256:" + "1" * 63])
def test_mc33_digest_pin_still_required(image):
    """README §Manifest constraints (signed qualification manifests): every image pinned by digest with
    `imagePullPolicy: Never`."""
    assert check(pod(containers=[container(image=image)])) == MC33_TEXT


def test_a2_pull_policy_rendering_requires_never():
    """README §What v4 changes: the rendered A2-POD-PULL-POLICY requires 'Never' on every container and init
    container."""
    pol = policy(sealed_doc(), POD_POLICY)
    expr = next(v for v in pol["spec"]["validations"] if v["message"] == "A2-POD-PULL-POLICY")["expression"]
    assert "object.spec.containers.all(" in expr and "object.spec.initContainers.all(" in expr
    assert expr.count("== 'Never'") == 2 and "Always" not in expr


@pytest.mark.parametrize("where,pull", [("containers", "Always"), ("containers", "IfNotPresent"),
                                        ("initContainers", "Always"), ("initContainers", "IfNotPresent")])
def test_a2_pull_policy_reference_reading(where, pull):
    """README §AlwaysPullImages, pinned off: the reference reading refuses "an image pull policy other than Never"."""
    obj = final(pod_init())
    obj["spec"][where][0]["imagePullPolicy"] = pull
    assert a2(obj) == PULL_REFUSAL


def test_a2_pull_policy_missing_field_is_refused():
    """README §The sealed directory (`admission-manifests/planeon-a2.json`): a field dereferenced without has() is
    required; its absence is a runtime error that failurePolicy Fail denies."""
    obj = final(pod())
    del obj["spec"]["containers"][0]["imagePullPolicy"]
    assert code_of(a2(obj)) == "A2-POD-PULL-POLICY"


def test_always_pull_images_pin_holds_end_to_end():
    """README §AlwaysPullImages, pinned off: with the pinned value `alwaysPullImages: false` the Never Pod is admitted
    and keeps Never."""
    m = pod_init()
    assert check(m) is None
    obj = final(m, always=False)
    assert obj["spec"]["containers"][0]["imagePullPolicy"] == "Never"
    assert obj["spec"]["initContainers"][0]["imagePullPolicy"] == "Never"
    assert a2(obj) is None


def test_always_pull_images_final_object_models_the_rewrite():
    """README §AlwaysPullImages, pinned off: final_object keeps modelling the plugin's rewrite to Always for
    containers and init containers."""
    obj = final(pod_init(), always=True)
    assert isinstance(obj, dict), obj
    assert obj["spec"]["containers"][0]["imagePullPolicy"] == "Always"
    assert obj["spec"]["initContainers"][0]["imagePullPolicy"] == "Always"


def test_always_pull_images_final_object_rewrites_image_volumes():
    """README §AlwaysPullImages, pinned off: final_object models the rewrite to Always for image volumes too."""
    vols = [scratch(), {"name": "img", "image": {"reference": IMG_SIDE, "pullPolicy": "Never"}}]
    obj = final(pod(volumes=vols), always=True)
    assert isinstance(obj, dict), obj
    img = next(v for v in obj["spec"]["volumes"] if v["name"] == "img")
    assert img["image"]["pullPolicy"] == "Always"


def test_always_pull_images_enabled_despite_pin_fails_closed():
    """README §AlwaysPullImages, pinned off: an enabled plugin rewrites Never to Always, and A2 fails closed with
    `A2-POD-PULL-POLICY an image pull policy other than Never`."""
    m = pod_init()
    assert check(m) is None
    assert a2(final(m, always=True)) == PULL_REFUSAL
    m = pod()
    assert check(m) is None
    assert a2(final(m, always=True)) == PULL_REFUSAL


def test_always_pull_images_image_volume_refused_by_image_volume_first():
    """README §AlwaysPullImages, pinned off: U05 keeps its expectation A2-POD-IMAGE-VOLUME (it precedes
    A2-POD-PULL-POLICY in the Pod policy)."""
    vols = [scratch(), {"name": "img", "image": {"reference": IMG_SIDE, "pullPolicy": "Never"}}]
    m = pod(volumes=vols)
    assert code_of(check(m)) == "MC38"
    assert code_of(a2(final(m, always=True))) == "A2-POD-IMAGE-VOLUME"


def test_mc38_text_kept_with_always_pull_images_clause():
    """README §Every rule, KEPT, CHANGED or NEW: MC38's text "(AlwaysPullImages rewrites its pull policy)" is kept."""
    vols = [scratch(), {"name": "img", "image": {"reference": IMG_SIDE, "pullPolicy": "Never"}}]
    result = check(pod(volumes=vols))
    assert code_of(result) == "MC38" and MC38_TEXT_PART in result


def test_always_pull_images_pinned_off_in_allowlists():
    """README §Files: allowlists.json carries ALWAYS_PULL_IMAGES_PINNED_OFF (a non-MC key), the AlwaysPullImages
    mutator row, RULED_OUT_BY_MANIFEST (pinned off, C28) and MC33 (Never)."""
    cov = ALLOW["constraintCoverage"]
    assert "alwaysPullImagesDisabled" in cov["ALWAYS_PULL_IMAGES_PINNED_OFF"]
    assert "C28" in cov["ALWAYS_PULL_IMAGES_PINNED_OFF"]
    assert "Never" in cov["MC33"]
    rows = [r for r in ALLOW["mutatorsByKind"] if "AlwaysPullImages" in r.get("plugin", "")]
    assert len(rows) == 1 and "pinned off" in rows[0]["plugin"]
    ruled = ALLOW["kinds"]["Pod"]["RULED_OUT_BY_MANIFEST"]
    hits = [v for k, v in ruled.items() if "imagePullPolicy" in k and "AlwaysPullImages" in k]
    assert len(hits) == 1 and "C28" in hits[0] and "pinned off" in hits[0]


@pytest.mark.parametrize("check_name", ["A1", "A2", "A3", "A4"])
def test_claim_v3_is_refused_with_c04(check_name):
    """README §Every rule, KEPT, CHANGED or NEW: C04, "a v3 claim lacks the AlwaysPullImages evidence and pins the
    superseded sealed directory; cite v4", for every check."""
    result = run(M.check_claim, {"semantics": "POLICY-ADMISSION-SEMANTICS/v3", "check": check_name,
                                 "alwaysPullImagesDisabled": True}, {})
    assert code_of(result) == "C04" and C04_TEXT in result


@pytest.mark.parametrize("check_name", ["A1", "A2", "A3", "A4"])
def test_claim_v2_is_refused_with_c03(check_name):
    """README §POLICY-ADMISSION-SEMANTICS/v1 (pinned, not met): a claim citing v2 is refused (C03, "cite v4")."""
    result = run(M.check_claim, {"semantics": "POLICY-ADMISSION-SEMANTICS/v2", "check": check_name}, {})
    assert code_of(result) == "C03" and C03_TEXT in result


@pytest.mark.parametrize("check_name", ["A1", "A2", "A3", "A4"])
def test_claim_v1_is_refused_with_c01(check_name):
    """README §POLICY-ADMISSION-SEMANTICS/v1 (pinned, not met): a claim citing v1 is refused (C01, "cite
    POLICY-ADMISSION-SEMANTICS/v4 checks")."""
    result = run(M.check_claim, {"semantics": "POLICY-ADMISSION-SEMANTICS/v1", "check": check_name}, {})
    assert code_of(result) == "C01" and C01_TEXT in result


@pytest.mark.parametrize("check_name", ["A1", "A2", "A3", "A4"])
def test_claim_v5_is_unknown(check_name):
    """README §Vectors: Q16 uses `.../v5` as the unknown version (v4 is now known): a v5 claim is refused, not as a
    v1, v2 or v3 claim, and not as a v4 claim is."""
    v5 = run(M.check_claim, {"semantics": "POLICY-ADMISSION-SEMANTICS/v5", "check": check_name}, {})
    v4 = run(M.check_claim, {"semantics": "POLICY-ADMISSION-SEMANTICS/v4", "check": check_name}, {})
    assert isinstance(v5, str) and code_of(v5) in ALL_C
    assert code_of(v5) not in {"C01", "C03", "C04"}
    assert code_of(v5) != code_of(v4)


@pytest.mark.parametrize("check_name", ["A1", "A2", "A3", "A4"])
def test_claim_v4_without_evidence_is_refused_with_a_readme_code(check_name):
    """README §POLICY-ADMISSION-SEMANTICS/v4: a v4 claim with no evidence is refused, with a code from the README's
    rule table."""
    result = run(M.check_claim, {"semantics": M.SEMANTICS_V4, "check": check_name}, {})
    assert isinstance(result, str) and code_of(result) in ALL_C


# ====================================================================================================================
# 5. The sealed directory
# ====================================================================================================================
def test_sealed_file_size_and_sha256():
    """README §The sealed directory (`admission-manifests/planeon-a2.json`): 8322 bytes, sha256 92c216...8e32."""
    assert len(SEALED_RAW) == SEALED_SIZE
    assert hashlib.sha256(SEALED_RAW).hexdigest() == SEALED_SHA256


def test_sealed_directory_hash_independent_recomputation():
    """README §The sealed directory (`admission-manifests/planeon-a2.json`): the loader's directory hash (file-name
    order, each non-empty .yaml/.yml/.json file followed by a NUL byte) is the stated v4 hash, not v3's."""
    mine = "sha256:" + hashlib.sha256(SEALED_RAW + b"\0").hexdigest()
    assert mine == DIR_HASH_V4
    assert mine != DIR_HASH_V3


def test_sealed_directory_hash_by_the_model():
    """README §The sealed directory (`admission-manifests/planeon-a2.json`): manifest_directory_hash reproduces the
    stated hash for the one-file directory."""
    assert run(M.manifest_directory_hash, {"planeon-a2.json": SEALED_RAW}) == DIR_HASH_V4


def test_manifest_directory_hash_rules():
    """README §The sealed directory (`admission-manifests/planeon-a2.json`): file-name order, only non-empty .yaml,
    .yml or .json files, each followed by a NUL byte."""
    a, b, c = b'{"a":1}', b"b: 2\n", b"c: 3\n"
    expected = "sha256:" + hashlib.sha256(a + b"\0" + b + b"\0" + c + b"\0").hexdigest()
    files = {"c.yml": c, "notes.txt": b"ignored", "a.json": a, "empty.json": b"", "b.yaml": b}
    assert run(M.manifest_directory_hash, files) == expected
    reordered = dict(reversed(list(files.items())))
    assert run(M.manifest_directory_hash, reordered) == expected


def test_model_rendering_equals_sealed_file():
    """README §The sealed directory (`admission-manifests/planeon-a2.json`): v4's model renders the sealed file from
    the four sealed values (planeon-qual, IPv4, 10.96.0.0/12, 300)."""
    assert run(M.manifest_file_bytes, dict(SEALED)) == SEALED_RAW
    assert sealed_doc() == {"apiVersion": "v1", "kind": "List", "items": run(M.a2_objects, dict(SEALED))}


def test_sealed_file_is_canonical_json_list_of_four_policies_and_four_bindings():
    """README §Files: a v1 List of four static ValidatingAdmissionPolicy objects and their four bindings, canonical
    JSON."""
    doc = sealed_doc()
    assert SEALED_RAW == json.dumps(doc, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    assert doc["apiVersion"] == "v1" and doc["kind"] == "List"
    kinds = [i["kind"] for i in doc["items"]]
    assert kinds.count("ValidatingAdmissionPolicy") == 4 and kinds.count("ValidatingAdmissionPolicyBinding") == 4
    assert len(kinds) == 8


def test_sealed_per_kind_policies():
    """README §The sealed directory (`admission-manifests/planeon-a2.json`): one policy per kind, CREATE of its v1
    resource in the qualification namespace, matchPolicy Exact, no objectSelector, matchConditions or paramKind,
    failurePolicy Fail, each validation's message its A2 code."""
    doc = sealed_doc()
    for name, resource in (("planeon-a2-pod.static.k8s.io", "pods"),
                           ("planeon-a2-configmap.static.k8s.io", "configmaps"),
                           ("planeon-a2-service.static.k8s.io", "services")):
        pol = policy(doc, name)
        assert pol["apiVersion"] == "admissionregistration.k8s.io/v1"
        spec = pol["spec"]
        assert spec["failurePolicy"] == "Fail"
        assert "paramKind" not in spec and "matchConditions" not in spec
        mc = spec["matchConstraints"]
        assert mc["matchPolicy"] == "Exact" and "objectSelector" not in mc
        assert mc["namespaceSelector"] == {"matchExpressions": [
            {"key": "kubernetes.io/metadata.name", "operator": "In", "values": [NS]}]}
        assert mc["resourceRules"] == [{"apiGroups": [""], "apiVersions": ["v1"], "operations": ["CREATE"],
                                        "resources": [resource]}]
        for v in spec["validations"]:
            assert re.fullmatch(r"A2-[A-Z0-9-]+", v["message"]), v["message"]


def test_sealed_guard_policy():
    """README §The sealed directory (`admission-manifests/planeon-a2.json`): the guard denies every API CREATE, UPDATE
    and DELETE of the six admission resources; the status subresource is not matched."""
    pol = policy(sealed_doc(), "planeon-a2-admission-objects.static.k8s.io")
    rules = pol["spec"]["matchConstraints"]["resourceRules"]
    resources = sorted(r for rule in rules for r in rule["resources"])
    assert resources == sorted(["validatingadmissionpolicies", "validatingadmissionpolicybindings",
                                "mutatingadmissionpolicies", "mutatingadmissionpolicybindings",
                                "validatingwebhookconfigurations", "mutatingwebhookconfigurations"])
    for rule in rules:
        assert sorted(rule["operations"]) == ["CREATE", "DELETE", "UPDATE"]
    assert not any("/" in r for r in resources)
    assert pol["spec"]["failurePolicy"] == "Fail"
    assert [v["message"].split(" ")[0] for v in pol["spec"]["validations"]] == ["A2-GUARD"]


def test_sealed_bindings():
    """README §The sealed directory (`admission-manifests/planeon-a2.json`): one binding per policy, named
    `<policy>-binding.static.k8s.io`, `validationActions: [Deny]`, no paramRef or matchResources."""
    doc = sealed_doc()
    policies = [i["metadata"]["name"] for i in doc["items"] if i["kind"] == "ValidatingAdmissionPolicy"]
    bindings = [i for i in doc["items"] if i["kind"] == "ValidatingAdmissionPolicyBinding"]
    assert sorted(b["spec"]["policyName"] for b in bindings) == sorted(policies)
    for b in bindings:
        base = b["spec"]["policyName"][: -len(".static.k8s.io")]
        assert b["metadata"]["name"] == base + "-binding.static.k8s.io"
        assert b["spec"]["validationActions"] == ["Deny"]
        assert "paramRef" not in b["spec"] and "matchResources" not in b["spec"]


def test_sealed_rendering_follows_the_sealed_values():
    """README §The sealed directory (`admission-manifests/planeon-a2.json`): a2_objects renders from the sealed values
    (another namespace changes the namespaceSelector and the bytes, so the pinned hash no longer matches)."""
    other = dict(SEALED, namespace="oracle-other")
    objs = run(M.a2_objects, other)
    pol = next(i for i in objs if i["metadata"]["name"] == POD_POLICY)
    assert pol["spec"]["matchConstraints"]["namespaceSelector"]["matchExpressions"][0]["values"] == ["oracle-other"]
    raw = run(M.manifest_file_bytes, other)
    assert run(M.manifest_directory_hash, {"planeon-a2.json": raw}) != DIR_HASH_V4


# ====================================================================================================================
# 6. The rule table, and my own mutations (none from any vector file)
# ====================================================================================================================
def test_rule_table_a2_codes_exist_in_the_rendering():
    """README §Every rule, KEPT, CHANGED or NEW: every KEPT, CHANGED and NEW A2 rule exists in the rendering, and no
    other."""
    codes = set()
    for item in sealed_doc()["items"]:
        for v in item["spec"].get("validations", []):
            codes.add(v["message"].split(" ")[0])
    assert codes == set(KEPT_A2) | {"A2-POD-PULL-POLICY", "A2-POD-EMPTYDIR"}


def test_rule_table_configmap_and_service_orders():
    """README §The sealed directory (`admission-manifests/planeon-a2.json`): A2-RESERVED first, except ConfigMap:
    A2-CM-PUBLISHER, A2-RESERVED, A2-CM-IMMUTABLE."""
    doc = sealed_doc()
    cm = [v["message"] for v in policy(doc, "planeon-a2-configmap.static.k8s.io")["spec"]["validations"]]
    assert cm == CM_ORDER
    svc = [v["message"] for v in policy(doc, "planeon-a2-service.static.k8s.io")["spec"]["validations"]]
    assert svc[0] == "A2-RESERVED"
    assert sorted(svc[1:]) == sorted(["A2-SVC-TYPE", "A2-SVC-ALLOCATION", "A2-SVC-DEFAULTS"])


def test_rule_table_model_names():
    """README §Files: the reference model exposes check_manifest, final_object, check_final, a2_objects,
    check_a2_objects, manifest_file_bytes, manifest_directory_hash and check_claim."""
    for name in ("check_manifest", "final_object", "check_final", "a2_objects", "check_a2_objects",
                 "manifest_file_bytes", "manifest_directory_hash", "check_claim"):
        assert callable(getattr(M, name, None)), name
    assert M.SEMANTICS_V4 == "POLICY-ADMISSION-SEMANTICS/v4"


def _mut(fn, base=pod):
    m = base()
    fn(m)
    return m


def _set(path, value):
    def apply(m):
        node = m
        for key in path[:-1]:
            node = node.setdefault(key, {}) if isinstance(key, str) else node[key]
        node[path[-1]] = value
    return apply


def _delete(path):
    def apply(m):
        node = m
        for key in path[:-1]:
            node = node[key]
        del node[path[-1]]
    return apply


# (id, manifest factory, expected code, expected exact text or None)
MANIFEST_MUTATIONS = [
    ("pod kind Deployment", lambda: _mut(_set(["kind"], "Deployment")), "MC00", None),
    ("pod name replaced by generateName", lambda: _mut(lambda m: (m["metadata"].pop("name"),
                                                                  m["metadata"].update(generateName="probe-"))),
     "MC01", None),
    ("pod namespace omitted", lambda: _mut(_delete(["metadata", "namespace"])), "MC02", None),
    ("pod namespace other", lambda: _mut(_set(["metadata", "namespace"], "default")), "MC02", None),
    ("pod metadata.uid", lambda: _mut(_set(["metadata", "uid"], "3f1c2a64-0d5e-4b7a-9c11-6a0e5d2b8f41")), "MC03",
     None),
    ("pod metadata.finalizers", lambda: _mut(_set(["metadata", "finalizers"], ["oracle/hold"])), "MC03", None),
    ("pod metadata.resourceVersion", lambda: _mut(_set(["metadata", "resourceVersion"], "1")), "MC03", None),
    ("pod label under kubernetes.io/", lambda: _mut(_set(["metadata", "labels"], {"app.kubernetes.io/name": "x"})),
     "MC04", None),
    ("pod annotation under a k8s.io subdomain",
     lambda: _mut(lambda m: m["metadata"]["annotations"].update({"oracle.k8s.io/x": "y"})), "MC04", None),
    ("pod status", lambda: _mut(_set(["status"], {"phase": "Pending"})), "MC05", None),
    ("configmap immutable false", lambda: _mut(_set(["immutable"], False), configmap), "MC10", None),
    ("configmap immutable omitted", lambda: _mut(_delete(["immutable"]), configmap), "MC10", None),
    ("configmap named kube-root-ca.crt", lambda: _mut(_set(["metadata", "name"], "kube-root-ca.crt"), configmap),
     "MC11", None),
    ("service type omitted", lambda: _mut(_delete(["spec", "type"]), service), "MC20", None),
    ("service clusterIP", lambda: _mut(_set(["spec", "clusterIP"], "10.96.0.10"), service), "MC21", None),
    ("service externalIPs", lambda: _mut(_set(["spec", "externalIPs"], ["192.0.2.1"]), service), "MC21", None),
    ("service sessionAffinity ClientIP", lambda: _mut(_set(["spec", "sessionAffinity"], "ClientIP"), service),
     "MC22", None),
    ("service internalTrafficPolicy Local", lambda: _mut(_set(["spec", "internalTrafficPolicy"], "Local"), service),
     "MC22", None),
    ("pod nodeName", lambda: _mut(_set(["spec", "nodeName"], "node-a")), "MC30", None),
    ("pod priorityClassName", lambda: _mut(_set(["spec", "priorityClassName"], "high")), "MC30", None),
    ("pod tolerations", lambda: _mut(_set(["spec", "tolerations"], [{"operator": "Exists"}])), "MC30", None),
    ("pod imagePullSecrets", lambda: _mut(_set(["spec", "imagePullSecrets"], [{"name": "pull"}])), "MC30", None),
    ("pod hostNetwork", lambda: _mut(_set(["spec", "hostNetwork"], True)), "MC30", None),
    ("pod automountServiceAccountToken true", lambda: _mut(_set(["spec", "automountServiceAccountToken"], True)),
     "MC31", None),
    ("pod automountServiceAccountToken omitted", lambda: _mut(_delete(["spec", "automountServiceAccountToken"])),
     "MC31", None),
    ("pod imagePullPolicy Always", lambda: _mut(_set(["spec", "containers", 0, "imagePullPolicy"], "Always")),
     "MC33", MC33_TEXT),
    ("pod imagePullPolicy omitted", lambda: _mut(_delete(["spec", "containers", 0, "imagePullPolicy"])), "MC33",
     MC33_TEXT),
    ("pod requests differ from limits",
     lambda: _mut(_set(["spec", "containers", 0, "resources", "requests", "cpu"], "200m")), "MC34", None),
    ("pod token-like emptyDir volume name", lambda: pod(volumes=[scratch(name="kube-api-access-oracle")]), "MC36",
     None),
    ("pod echo of containers changed",
     lambda: _mut(lambda m: m["metadata"]["annotations"].update({"planeon.ai/a2-containers": "probe=" + IMG_SIDE})),
     "MC37", None),
    ("pod echo annotation missing",
     lambda: _mut(lambda m: m["metadata"]["annotations"].pop("planeon.ai/a2-init-containers")), "MC37", None),
    ("pod image volume", lambda: pod(volumes=[scratch(), {"name": "img", "image": {"reference": IMG_SIDE,
                                                                                    "pullPolicy": "Never"}}]),
     "MC38", None),
    ("pod pod-level resources", lambda: _mut(_set(["spec", "resources"], {"limits": {"cpu": "1"}})), "MC39", None),
    ("pod affinity", lambda: _mut(_set(["spec", "affinity"], {"nodeAffinity": {}})), "MC40", None),
    ("pod topologySpreadConstraints",
     lambda: _mut(_set(["spec", "topologySpreadConstraints"], [{"maxSkew": 1, "topologyKey": "zone",
                                                               "whenUnsatisfiable": "DoNotSchedule"}])), "MC40", None),
    ("pod hostPath volume", lambda: pod(volumes=[{"name": "host", "hostPath": {"path": "/srv"}}]), "MC41", None),
    ("pod projected serviceAccountToken source",
     lambda: pod(volumes=[{"name": "proj", "projected": {"sources": [{"serviceAccountToken": {"path": "t"}}]}}]),
     "MC41", None),
    ("pod emptyDir {}", lambda: pod(volumes=[scratch(None)]), "MC42", mc42(R1)),
    ("pod emptyDir sizeLimit 512Mi", lambda: pod(volumes=[scratch("512Mi")]), "MC42", mc42(R1)),
    ("pod emptyDir medium Memory", lambda: pod(volumes=[scratch(medium="Memory")]), "MC42", mc42(R2)),
    ("pod container without ephemeral-storage limit", lambda: pod(containers=[container(eph=None)]), "MC42",
     mc42(R3)),
    ("pod sizeLimit over the containers' sum by one", lambda: pod(volumes=[scratch("1073741825")]), "MC42",
     mc42(R4)),
]


@pytest.mark.parametrize("label,factory,code,text", MANIFEST_MUTATIONS, ids=[m[0] for m in MANIFEST_MUTATIONS])
def test_rule_table_manifest_mutations(label, factory, code, text):
    """README §Manifest constraints (signed qualification manifests); §Every rule, KEPT, CHANGED or NEW: each of my
    mutations of a valid manifest is refused with the code (and, where the README states it, the text)."""
    m = factory()
    result = check(m)
    assert code_of(result) == code, (label, result)
    if text is not None:
        assert result == text


def test_rule_table_mutation_bases_are_valid():
    """README §Manifest constraints (signed qualification manifests): the unmutated Pod, ConfigMap and Service bases
    pass check_manifest (defaults sessionAffinity None and internalTrafficPolicy Cluster are allowed)."""
    assert check(pod()) is None and check(configmap()) is None and check(service()) is None
    svc = service()
    svc["spec"]["sessionAffinity"] = "None"
    svc["spec"]["internalTrafficPolicy"] = "Cluster"
    assert check(svc) is None


def test_rule_table_mc_codes_covered_by_mutations():
    """README §Every rule, KEPT, CHANGED or NEW: every KEPT, CHANGED or NEW MC rule with a README-stated constraint is
    reached by at least one mutation (MC06, MC32 and MC35 have no README-stated constraint; see notChecked)."""
    covered = {m[2] for m in MANIFEST_MUTATIONS}
    assert covered == (set(KEPT_MC) | {"MC33", "MC42"}) - {"MC06", "MC32", "MC35"}


def test_rule_table_token_mount_refused():
    """README §Manifest constraints (signed qualification manifests): no mount at the token path."""
    m = pod()
    m["spec"]["containers"][0]["volumeMounts"] = [{"name": "scratch", "mountPath": TOKEN_PATH}]
    assert check(m) is not None


# ====================================================================================================================
# 7. Files and status
# ====================================================================================================================
def test_files_listed_exist():
    """README §Files: README.md, allowlists.json, admission-manifests/planeon-a2.json, status.json and
    ../../scripts/admission_semantics_v4.py exist (vectors.json is not in the oracle's tree; see notChecked)."""
    for rel in ("README.md", "allowlists.json", "admission-manifests/planeon-a2.json", "status.json"):
        assert (CONTRACT / rel).is_file(), rel
        assert "`" + rel.split("/")[-1] in README or rel in README
    assert (CONTRACT / "../../scripts/admission_semantics_v4.py").resolve().is_file()


def test_allowlists_v4_values():
    """README §Files: allowlists.json keeps v3's schema with the v4 semantics, the sizeLimit fixed entry, the
    A2-POD-EMPTYDIR check, the new sizeLimit upstream row, four new unverified entries and v3's 95 citations."""
    assert ALLOW["schemaVersion"] == "planeon.internal.admission-allowlists/v2"
    assert ALLOW["semantics"] == "POLICY-ADMISSION-SEMANTICS/v4"
    assert ALLOW["kubernetes"]["tag"] == "v1.37.1"
    assert ALLOW["kubernetes"]["commit"] == "f78e722310e50bcaca9276be22276d9e91d91308"
    files = ALLOW["kubernetes"]["files"]
    assert len(files) == 95 and all(re.fullmatch(r"[0-9a-f]{64}", f["sha256"]) for f in files)
    pod_kind = ALLOW["kinds"]["Pod"]
    assert any("emptyDir.sizeLimit" in e and "canonical" in e for e in pod_kind["ALLOWED_FIXED"])
    assert pod_kind["CHECKED_BY_A2"] == POD_ORDER
    rows = [r for r in pod_kind["upstreamFields"] if r["path"] == "spec.volumes[*].emptyDir.sizeLimit"]
    assert len(rows) == 1
    assert sum(1 for u in ALLOW["unverified"] if u.startswith("LPK-1")) == 4
    changed = [r for r in pod_kind["upstreamFields"] if "imagePullPolicy" in r["path"]]
    assert len(changed) == 2 and all("v4" in r["condition"] for r in changed)


def test_allowlists_unverified_readings_named_in_readme():
    """README §What stays open: the four new unverified readings (sizeLimit re-emission, kubelet eviction accounting,
    runtime writable paths and sandbox image, AlwaysPullImages' Validate path)."""
    new = [u for u in ALLOW["unverified"] if u.startswith("LPK-1")]
    joined = " ".join(new)
    for phrase in ("sizeLimit", "eviction", "sandbox", "Validate path"):
        assert phrase in joined, phrase


def test_status_governs_and_readme_status_line_is_the_reviewed_candidate_line():
    """README §status line (top of the README); §Files: the README's status line is the candidate line the README is
    reviewed with, and status.json, which holds the contract state, governs it. The README states no equality between
    them, so none is asserted."""
    found = re.search(r"Status: \*\*([A-Z0-9_]+)\*\* \(candidate (c\d+);", README)
    assert found and "CANDIDATE" in found.group(1)
    assert "This status line is the candidate line the README is reviewed with; `status.json` governs" in FLAT
    assert "The contract state, review rounds" in FLAT and "it governs this README's status line" in FLAT
    assert isinstance(STATUS.get("contractState"), str) and STATUS["contractState"]
    note = STATUS["readmeStatusNote"]
    assert "candidate line" in note and "status.json governs" in note


def test_status_readme_status_note_agrees():
    """README §status line (top of the README): readmeStatusNote says what the README says about its status line and
    the v3 README."""
    note = STATUS["readmeStatusNote"]
    assert "status.json governs" in note
    assert "candidate line" in note and "candidate line" in README
    flat = " ".join(README.split())
    for phrase in ("still reads CONTRACT_CANDIDATE_ROUND2_AWAITING_INDEPENDENT_REVIEW",
                   "governs v3 (ADOPTED_DATA_CONTRACT)", "the v3 README is not edited"):
        assert phrase in note, phrase
        assert phrase in flat, phrase


def test_status_non_claims_agree_with_readme():
    """README §What stays open: status.json nonClaims are the README's five non-claims."""
    flat = " ".join(README.split())
    section = flat.split("**Non-claims:**", 1)[1].split("The W02f", 1)[0]
    pairs = [
        ("Nothing is installed or compiled.", "nothing is installed or compiled"),
        ("No apiserver is contacted.", "no apiserver is contacted"),
        ("Admission semantics v3 and v2, workload profile v1, I06, I01 and edge records v1-v10 are byte-identical.",
         "admission v3 and v2, profile v1, I06, I01 and edge records v1-v10 are byte-identical"),
        ("\"Pinned off\" binds the contract only until I06's successor and HE-008 carry it.",
         "\"pinned off\" binds this contract only until I06's successor and HE-008 carry it"),
        ("Profile v1 remains the wire's profile until the wire steps (W1-W4) land.",
         "profile v1 remains the wire's profile until the wire steps W1-W4 land"),
    ]
    assert STATUS["nonClaims"] == [p[0] for p in pairs]
    for _, readme_phrase in pairs:
        assert readme_phrase in section, readme_phrase
    assert len([p for p in section.split(";") if p.strip()]) == 5


def test_status_record_agrees_with_readme():
    """README §What stays open: E01-E12 stay OPEN_UNPROVEN; the sealed block, the carried steps S1-S3, W1-W4, C1 and
    C2, and the --disable-admission-plugins=AlwaysPullImages obligation."""
    assert STATUS["semantics"] == "POLICY-ADMISSION-SEMANTICS/v4"
    assert STATUS["supersedes"] == "POLICY-ADMISSION-SEMANTICS/v3"
    assert STATUS["packet"] == "MET-LIVE-004" and STATUS["workItem"] == "LINUX-PROBE-KIT-ADMISSION"
    assert STATUS["base"] in README
    assert STATUS["obligations"] == {"E%02d" % i: "OPEN_UNPROVEN" for i in range(1, 13)}
    sealed = STATUS["sealed"]
    assert sealed["supersedesManifestDirectoryHash"] == DIR_HASH_V3
    assert sealed["installed"] is False
    assert "M1" in sealed["activation"] and "M3" in sealed["activation"] and "maintenance boot" in sealed["activation"]
    assert [p["id"] for p in sealed["preconditions"]] == ["S1", "S2", "S3"]
    steps = [s["id"] for s in STATUS["carried"]["steps"]]
    assert steps == ["S1", "S2", "S3", "W1", "W2", "W3", "W4", "C1", "C2"]
    c2 = next(s for s in STATUS["carried"]["steps"] if s["id"] == "C2")
    assert "--disable-admission-plugins=AlwaysPullImages" in c2["content"]
    ob = STATUS["carried"]["obligationsOfC1C2"]
    assert "ALLOWED_ADMISSION" in ob["I06 SC05 successor"] and "FORBIDDEN_ADMISSION" in ob["I06 SC05 successor"]
    assert "--disable-admission-plugins=AlwaysPullImages" in ob["HE-008"]
    assert STATUS["admissionConfigurationInstalled"] is False
