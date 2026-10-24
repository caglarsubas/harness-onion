#!/usr/bin/env python3
"""Workload profile v2 (CAMPAIGN_PROXY_MTLS_ZERO_COST_V2): the LPK-1 (MET-LIVE-004) successor beside profile v1.

DATA_CHECK_ONLY reference model, standard library only. Profile v1 (`architecture/proxy-contract-inputs/`, checked by
`scripts/validate_proxy_contract.py`) stays byte-identical and remains the wire's profile until the carried wire steps
W1-W4 land. A v1 document is refused here (P00, the profileId const).

- `validate(profile, schema)` returns [] for a valid profile v2 document, otherwise exactly one refusal, "P<nn> <text>":
  the first rule that fails in VPC's evaluation order (README, "The evaluation order"). It carries every rule and bound
  of VPC's `validate_profile` unchanged (P01-P22), checks the closed v2 schema with the standard-library walker below
  (P00), and adds P30-P35. `schema` must be the reviewed v2 schema (SCHEMA_SHA256, over its canonical JSON); any other
  schema raises ValueError, because that check concerns the caller, not the document.
- `precondition(profile, namespace)` returns P40 when the binding namespace is not the sealed qualification namespace.
  P40 is the cross-contract precondition, not a profile rule: the sealed namespace is not profile data.
- `schema_error(instance, schema)` is the walker behind P00: None when the instance matches, otherwise the JSON path of
  the first mismatch. It implements, with draft 2020-12 meaning, exactly the keywords the v2 schema uses, and refuses a
  schema with any other keyword.

Nothing here contacts an apiserver, verifies a certificate, grants authority or reads a file.
"""
from __future__ import annotations

import hashlib
import json
import re
from datetime import datetime
from typing import Any

PROFILE_ID = "CAMPAIGN_PROXY_MTLS_ZERO_COST_V2"
SCHEMA_ID = "https://schemas.planeon.ai/internal/proxy-execution-profile/v2.json"
SCHEMA_SHA256 = "85d13533ab56d4da023ab9267077e69ab24918fd9ab740568daf11b172dedec6"
ECHO = {"containers": "planeon.ai/a2-containers", "initContainers": "planeon.ai/a2-init-containers",
        "volumes": "planeon.ai/a2-volumes"}
CASES = ["HOST_ISOLATION_NEGATIVES", "LINUX_TARGET_BUILD", "FULL_PREDECESSOR_REGRESSION", "CONTROL_CONTAINER_STARTUP",
         "POSTGRES_MIGRATION_AND_RLS", "DURABLE_RESTART", "ARBITRARY_NON_ROOT_UID", "READ_ONLY_ROOT_FILESYSTEM",
         "KUBERNETES_SMOKE", "DEFAULT_DENY_NETWORK"]
PATHS = ["/v1/linux-baseline/" + item.lower().replace("_", "-") for item in CASES]
TEXT = {
    "P00": "P00 the document does not match the closed profile v2 schema",
    "P01": "P01 the profile holds a non-data value (any number parsed as a float, integral or not) or exceeds the depth, size-budget, integer-range or canonical-size bounds",
    "P02": "P02 the binding window is not a canonical UTC window of at most 900 s",
    "P03": "P03 the service-account subject is outside the binding namespace",
    "P04": "P04 the API endpoint is missing, reused or unused",
    "P05": "P05 the credential inventory differs from the binding",
    "P06": "P06 a credential's subject or expiry differs from the binding",
    "P07": "P07 the client and server credentials are reused",
    "P08": "P08 the fixed proxy rule differs",
    "P09": "P09 a duplicate or foreign preexisting reference",
    "P10": "P10 the three policy references differ from the policy",
    "P11": "P11 the service-account reference name differs from the subject",
    "P12": "P12 a duplicate preexisting resource uid",
    "P13": "P13 a manifest digest or 16384-byte size mismatch",
    "P14": "P14 a resource outside the binding scope or a duplicate logical identity",
    "P15": "P15 a resource takes over a preexisting resource",
    "P16": "P16 the Pod service account differs from the subject",
    "P17": "P17 unequal requests and limits",
    "P18": "P18 a Service selector other than the binding labels",
    "P19": "P19 the GVK and name grants differ from the resources",
    "P20": "P20 the API rules differ from the resources",
    "P21": "P21 the Pod images differ from localImages",
    "P22": "P22 the quota is exceeded",
    "P30": "P30 the containers echo differs from probe=<image>",
    "P32": "P32 the volumes echo differs from the volume names",
    "P33": "P33 a volume not mounted exactly once at /work/<name>, or a mount of an undeclared volume",
    "P34": "P34 the emptyDir sizeLimits exceed the container's ephemeral-storage limit",
    "P35": "P35 duplicate volume names",
    "P40": "P40 the binding namespace is not the sealed qualification namespace",
    "P99": "P99 malformed profile data"
}


def canonical(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False).encode()


def digest(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


# ---------------------------------------------------------------- P00: the closed v2 schema, standard library only

KEYWORDS = frozenset(("$schema", "$id", "$defs", "$ref", "type", "properties", "required", "additionalProperties",
                      "const", "enum", "items", "minItems", "maxItems", "uniqueItems", "minLength", "maxLength",
                      "pattern", "minimum", "maximum", "oneOf", "not"))


def _is_type(value: Any, name: str) -> bool:
    if name == "object":
        return type(value) is dict
    if name == "array":
        return type(value) is list
    if name == "string":
        return type(value) is str
    if name == "boolean":
        return type(value) is bool
    if name == "null":
        return value is None
    if name == "number":
        return type(value) in (int, float)
    if name == "integer":                     # draft 2020-12: a number with a zero fractional part
        return type(value) is int or (type(value) is float and value.is_integer())
    raise ValueError("unsupported schema type " + repr(name))


def _equal(a: Any, b: Any) -> bool:
    """JSON equality: booleans never equal numbers, 1 equals 1.0, arrays in order, objects by members."""
    if type(a) is bool or type(b) is bool:
        return type(a) is bool and type(b) is bool and a == b
    if type(a) in (int, float) and type(b) in (int, float):
        return a == b
    if type(a) is list and type(b) is list:
        return len(a) == len(b) and all(_equal(x, y) for x, y in zip(a, b))
    if type(a) is dict and type(b) is dict:
        return a.keys() == b.keys() and all(_equal(a[k], b[k]) for k in a)
    return type(a) is type(b) and a == b


def schema_error(instance: Any, schema: Any, root: Any = None, path: str = "$") -> str | None:
    root = schema if root is None else root
    if type(schema) is not dict or not set(schema) <= KEYWORDS:
        raise ValueError("unsupported schema at " + path)
    if "$ref" in schema:
        ref = schema["$ref"]
        if type(ref) is not str or not ref.startswith("#/$defs/"):
            raise ValueError("unsupported reference at " + path)
        found = schema_error(instance, root["$defs"][ref[len("#/$defs/"):]], root, path)
        if found:
            return found
    if "type" in schema and not _is_type(instance, schema["type"]):
        return path
    if "const" in schema and not _equal(instance, schema["const"]):
        return path
    if "enum" in schema and not any(_equal(instance, option) for option in schema["enum"]):
        return path
    if type(instance) is dict:
        properties = schema.get("properties", {})
        if any(key not in instance for key in schema.get("required", [])):
            return path
        if schema.get("additionalProperties") is False and any(key not in properties for key in instance):
            return path
        for key, sub in properties.items():
            if key in instance:
                found = schema_error(instance[key], sub, root, path + "." + key)
                if found:
                    return found
    if type(instance) is list:
        if len(instance) < schema.get("minItems", 0) or ("maxItems" in schema and len(instance) > schema["maxItems"]):
            return path
        if schema.get("uniqueItems") is True and any(_equal(instance[i], instance[j]) for i in range(len(instance))
                                                     for j in range(i + 1, len(instance))):
            return path
        if "items" in schema:
            for index, item in enumerate(instance):
                found = schema_error(item, schema["items"], root, "%s[%d]" % (path, index))
                if found:
                    return found
    if type(instance) is str:
        if len(instance) < schema.get("minLength", 0) or ("maxLength" in schema and len(instance) > schema["maxLength"]):
            return path
        if "pattern" in schema and not re.search(schema["pattern"], instance):
            return path
    if type(instance) in (int, float):
        if ("minimum" in schema and instance < schema["minimum"]) or ("maximum" in schema and instance > schema["maximum"]):
            return path
    if "oneOf" in schema and sum(schema_error(instance, sub, root, path) is None for sub in schema["oneOf"]) != 1:
        return path
    if "not" in schema and schema_error(instance, schema["not"], root, path) is None:
        return path
    return None


# ---------------------------------------------------------------- the profile rules (VPC's, then P30-P35)

class Refused(Exception):
    pass


def _r(ok: bool, code: str) -> None:
    if not ok:
        raise Refused(TEXT[code])


def _time(value: str) -> datetime:
    try:
        result = datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ")
    except ValueError:
        raise Refused(TEXT["P02"]) from None
    _r(result.strftime("%Y-%m-%dT%H:%M:%SZ") == value, "P02")
    return result


def _bounded(value: Any, depth: int = 0, budget: list | None = None) -> None:
    """VPC's _bounded, unchanged in meaning: exact JSON builtins only (a float, integral or not, is refused), depth at
    most 16, a size budget of 262144 (a string costs its length, every other value 1), integers within 2^53-1."""
    if budget is None:
        budget = [262144]
    _r(depth <= 16, "P01")
    kind = type(value)
    _r(kind in (dict, list, str, int, bool, type(None)), "P01")
    budget[0] -= len(value) if kind is str else 1
    _r(budget[0] >= 0, "P01")
    if kind is int:
        _r(abs(value) <= 9007199254740991, "P01")
    if kind is dict:
        for key, item in value.items():
            _r(type(key) is str, "P01")
            _bounded(key, depth + 1, budget)
            _bounded(item, depth + 1, budget)
    elif kind is list:
        for item in value:
            _bounded(item, depth + 1, budget)


def _echo(entries: list, field: str) -> str:
    if not entries:
        return ""
    if field == "volumes":
        return ",".join(v["name"] for v in entries)
    return ",".join("%s=%s" % (c["name"], c["image"]) for c in entries)


def mounts_exact(volume_names: list, mounts: list) -> bool:
    """P33, as the README states it: judged over volume names after P35 has made them unique, the probe container's
    mount names are exactly the Pod's volume names, each mounted once, and each mountPath is /work/<name>."""
    names = [m["name"] for m in mounts]
    return (len(set(names)) == len(names) and set(names) == set(volume_names)
            and all(m["mountPath"] == "/work/" + m["name"] for m in mounts))


def validate(profile: Any, schema: Any) -> list[str]:
    if digest(canonical(schema)) != SCHEMA_SHA256:
        raise ValueError("the reviewed profile v2 schema is required")
    try:
        _bounded(profile)
        _r(len(canonical(profile)) <= 262144, "P01")
        _r(schema_error(profile, schema) is None, "P00")
        binding, entries, policy = profile["binding"], profile["capacityEntries"], profile["policy"]
        start, end = _time(binding["validFrom"]), _time(binding["expiresAt"])
        _r(0 < (end - start).total_seconds() <= 900, "P02")
        subject = binding["serviceAccountSubject"]
        _r(subject.startswith("system:serviceaccount:" + binding["namespace"] + ":"), "P03")
        credentials = entries["credentialIdentities"]
        expected = [(binding["endpointId"], "CAMPAIGN_PROXY_CLIENT_MTLS")]
        if profile["resources"]:
            _r(binding["apiEndpointId"] is not None and binding["apiEndpointId"] != binding["endpointId"], "P04")
            expected.append((binding["apiEndpointId"], "KUBERNETES_PROXY_SERVER_MTLS"))
        else:
            _r(binding["apiEndpointId"] is None, "P04")
        _r([(c["endpointId"], c["purpose"]) for c in credentials] == expected, "P05")
        for item in credentials:
            _r(item["subject"] == subject and item["expiresAt"] == binding["expiresAt"], "P06")
        for field in ("certificateDigest", "clientSpkiDigest"):
            _r(len({c[field] for c in credentials}) == len(credentials), "P07")
        rule = entries["campaignProxyRules"][0]
        _r(rule["endpointId"] == binding["endpointId"] and rule["namespace"] == binding["namespace"]
           and rule["paths"] == PATHS, "P08")
        reference_ids = set()
        references = entries["preexistingResourceRefs"]
        for item in references:
            key = (item["apiVersion"], item["kind"], item["namespace"], item["name"])
            _r(item["namespace"] == binding["namespace"] and key not in reference_ids, "P09")
            reference_ids.add(key)
        for kind, uid_key, digest_key in (("ResourceQuota", "resourceQuotaUid", "resourceQuotaDigest"),
                                          ("LimitRange", "limitRangeUid", "limitRangeDigest"),
                                          ("ServiceAccount", "serviceAccountUid", "serviceAccountDigest")):
            matches = [r for r in references if r["kind"] == kind]
            _r(len(matches) == 1 and matches[0]["uid"] == policy[uid_key]
               and matches[0]["observedDigest"] == policy[digest_key], "P10")
            if kind == "ServiceAccount":
                _r(matches[0]["name"] == subject.rsplit(":", 1)[1], "P11")
        _r(len({r["uid"] for r in references}) == len(references), "P12")
        labels = {"planeon.ai/run-nonce": binding["runNonce"], "planeon.ai/tenant-id": binding["tenantId"]}
        names, units, required_gvk, required_api = set(), dict.fromkeys(profile["quota"], 0), {}, set()
        kinds = {"Pod": ("pods", "pods"), "ConfigMap": ("configmaps", "configMaps"), "Service": ("services", "services")}
        images = set()
        for row in profile["resources"]:
            manifest = row["manifest"]
            raw = canonical(manifest)
            _r(len(raw) <= 16384 and row["manifestDigest"] == "sha256:" + digest(raw), "P13")
            meta, kind = manifest["metadata"], manifest["kind"]
            key = (kind, meta["name"])
            _r(key not in names and meta["namespace"] == binding["namespace"] and meta["labels"] == labels, "P14")
            _r(("v1", kind, meta["namespace"], meta["name"]) not in reference_ids, "P15")
            names.add(key)
            required_gvk.setdefault(kind, set()).add(meta["name"])
            api_resource, unit = kinds[kind]
            units[unit] += 1
            required_api.update((binding["apiEndpointId"], verb, api_resource, meta["name"])
                                for verb in ("create", "get", "delete"))
            if kind == "Pod":
                spec = manifest["spec"]
                _r(spec["serviceAccountName"] == subject.rsplit(":", 1)[1], "P16")
                container = spec["containers"][0]
                quantities = container["resources"]
                _r(quantities["requests"] == quantities["limits"], "P17")
                units["cpuMillis"] += int(quantities["limits"]["cpu"][:-1])
                units["memoryBytes"] += int(quantities["limits"]["memory"])
                units["ephemeralStorageBytes"] += int(quantities["limits"]["ephemeral-storage"])
                images.add(container["image"])
                volumes = spec.get("volumes") or []
                volume_names = [v["name"] for v in volumes]
                _r(len(set(volume_names)) == len(volume_names), "P35")
                annotations = meta["annotations"]
                _r(annotations[ECHO["containers"]] == _echo(spec["containers"], "containers"), "P30")
                _r(annotations[ECHO["volumes"]] == _echo(volumes, "volumes"), "P32")
                _r(mounts_exact(volume_names, container.get("volumeMounts") or []), "P33")
                _r(sum(int(v["emptyDir"]["sizeLimit"]) for v in volumes)
                   <= int(quantities["limits"]["ephemeral-storage"]), "P34")
            elif kind == "Service":
                _r(manifest["spec"]["selector"] == labels, "P18")
        observed_gvk = {}
        for rule in entries["permittedGvksAndVerbs"]:
            _r(rule["kind"] not in observed_gvk, "P19")
            observed_gvk[rule["kind"]] = set(rule["names"])
        _r(observed_gvk == required_gvk, "P19")
        api = set()
        for rule in entries["kubernetesApiRules"]:
            key = (rule["endpointId"], rule["verb"], rule["resource"], rule["name"])
            _r(rule["namespace"] == binding["namespace"] and key not in api, "P20")
            api.add(key)
        _r(api == required_api, "P20")
        _r(images == set(profile["localImages"]), "P21")
        _r(all(units[k] <= profile["quota"][k] for k in units), "P22")
        return []
    except Refused as exc:
        return [str(exc)]
    except (ValueError, TypeError, KeyError, AttributeError, OverflowError, RecursionError):
        return [TEXT["P99"]]


def precondition(profile: Any, namespace: str) -> list[str]:
    """P40, the cross-contract precondition the kit's signer calls with the sealed qualification namespace."""
    try:
        return [] if profile["binding"]["namespace"] == namespace else [TEXT["P40"]]
    except (TypeError, KeyError):
        return [TEXT["P99"]]
