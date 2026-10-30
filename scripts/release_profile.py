#!/usr/bin/env python3
"""Release profile (architecture/release-profile.json, RELEASE-PROFILE-001, MET-ADOPT-006): the first release profile.

check(read, packets) validates the closed record of profile.banking-readonly-amd64 through an injected byte reader and
the set of published packet ids. The catalogs are read only through the overlay module's public effective bytes; the
record, the overlay record, the sector record, the H-key map, provider-adoption, the registry and the non-operator packet
YAMLs are read through `read`. Refusal codes, in the order they run (V0, V6, V1, V8, V2, V3, V4, V5, V7, V9):
- RP_SHAPE (V0): every object is closed to its exact members; string lists are sorted and unique; free-text members
  are non-empty; state, version and host members are refused. Row lists are ordered by the check that owns them.
- RP_CATALOG_BYTES (V6): the catalogs, the overlay, the sector record and the H-key map are the pinned era's bytes, and
  the record's profile member pins exactly them.
- RP_CLOSURE (V1): the closure recomputed from the effective catalog, the profile's selection, and the module rows as
  a sorted list of the 30 non-external nodes.
- RP_PACK_BINDING (V8): the pack row and nonClaims.industryPack equal their derivation from the overlay's deferred entry.
- RP_OWNER_PACKET (V2): row class, owner, kind, harness, H key, deployables and packet, for both row classes.
  Operator rows are decided from the catalog's packet id (prefix OP-) before any task-packets read, and an operator
  packet YAML is never opened.
- RP_EXIT (V3), RP_PROVIDER_SET (V4), RP_EXCLUSION (V5), RP_TENANT_FACTS (V7), RP_REGISTRY (V9).
Types are exact (c2, RP-C1-1, RP-C1-2): V0 checks the JSON type of every member before any use, so bool, int and float
stay distinct and a wrongly typed identifier refuses RP_SHAPE; derived objects are compared as canonical JSON. V9
(RP-C1-4) requires exactly one MET-ADOPT-006/packet rider, equal to the generic packet rider, appended last, and the
registry's bytes equal to the base's serialization with that rider.
Data checks only: no network, no execution authority, no evidence state.
"""
from __future__ import annotations

import hashlib
import json
import re

from scripts import sector_catalog

RECORD_PATH = "architecture/release-profile.json"
SCHEMA = "planeon.internal.release-profile/v1"
PROFILE_ID = "profile.banking-readonly-amd64"
PROVIDERS_PATH = "architecture/providers.yaml"
SERVICES_PATH = "architecture/services.yaml"
CATALOG_DOC_PATH = "docs/PROVIDER_MODULE_CATALOG.md"
CATALOG_PATHS = (PROVIDERS_PATH, SERVICES_PATH, CATALOG_DOC_PATH)
OVERLAY_PATH = "architecture/sector-catalog/overlay.json"
SECTOR_PATH = "architecture/sector-direction.json"
HKEY_MAP_PATH = "docs/alpha-2/HARNESS_PAPER_REPOSITORY_MAP.md"
ADOPTION_PATH = "architecture/provider-adoption.json"
BRIEFS_PATH = "architecture/review-record/briefs.json"
BASE_SHA256 = {
    PROVIDERS_PATH: "9e2b43dac1ca4531dcdeb3a1b6ead8002d7384e2a0d0e6b57e972accb8631c02",
    SERVICES_PATH: "857376b5e2b10a2a2542124a7d36b770eca531d15e463d68415416b887dd90a6",
    CATALOG_DOC_PATH: "1723f1ea35ecc87529c2d680f7e51fda61923a368f1e241b7a82982b10935b1d",
}
EFFECTIVE_SHA256 = {
    PROVIDERS_PATH: "c5fffe8776ce7f280ac8d3d763b8f70a2cc8071475750f0aed0c2f395d1ce60a",
    SERVICES_PATH: "f1ccfecd3fd0d716d45d0c0cd423f9de1425ed3a91f9ec4e0b64f96a836aac35",
    CATALOG_DOC_PATH: "db95629a43b67b55e17206cc1d4659b6724644ab38d9dff2003a805917a0aad8",
}
OVERLAY_SHA256 = "296c973e8902a822da2bdc0ad3603170deb6a91cffc2d37ca9332ddf1834c4e4"
SECTOR_SHA256 = "cfc39b4adbfb2771e27cc5498d94530d5691130736a8791288ce296253fc2efe"
HKEY_MAP_SHA256 = "f6a891e8bdbcc579e60800773addd70ca29a2c4021c2dc95af62be93e91f061d"
BRIEFS_BASE_SHA256 = "14022229ea689a81879cc7c6a327051777176dec3e90348ecdca48a30f82b0e0"
RIDER_SERIES = "MET-ADOPT-006/packet"
RIDER_TEMPLATE_SERIES = "MET-ENFORCE-043/packet"
OPERATOR_PREFIX = "OP-"
NAMED_IN_ROADMAP = frozenset({"external.oidc-provider", "external.otel-backend", "external.postgresql",
                              "external.tenant-object-store"})
ROADMAP_EXCLUSIONS = frozenset({"clickhouse", "decision-service", "memory-service", "sandbox-runner", "temporal",
                                "tool-broker", "valkey"})
NOT_IN_CATALOG_DECISIONS = {
    "clickhouse": {"items": ["OBS-ANALYTICS-001"], "decision": "STORE-D1"},
    "temporal": {"items": ["TECH-ORCHESTRATION-001", "TECH-TRUTH-001"], "decision": "TECH-D1"},
    "valkey": {"items": ["EPHEMERAL-STORE-001"], "decision": "STORE-D1"},
}
KIND_WITH_SERVICE = "CATALOG_MODULE_WITH_SERVICE"
KIND_WITHOUT_SERVICE = "CATALOG_MODULE_WITHOUT_SERVICE"
KIND_NOT_IN_CATALOG = "NOT_IN_CATALOG"
SOURCES_ORDER = ("PROFILE", "ROADMAP")
EVIDENCE_AT = "CONF-A2-001"
EVIDENCE_RECORD = "RELEASE-EVIDENCE-001"
QUALIFICATION = "QUALIFICATION_EVIDENCE"
GROUNDING = "GROUNDING_EVALUATION"
CITED_IMPLICATION = "imply.cited-retrieval"
REQUIREMENT = "SIGNED_ENVIRONMENT_FACT"
RELEASE_SET_ENTRY = (
    "the banking pack enters the release set when, after CHAIN-PRODUCT-PUBLISH-001 (273), one MET-SECTOR packet "
    "publishes IND-BANK-005 and, in the same slot, carries the reviewed sector_catalog/overlay-schema revision and the "
    "record's new version, so sector_catalog.check never sees the publication and the revision apart")
RELEASE_SET_SOURCE = "the visionary's Q-RPD1-2 erratum, 2026-10-30"
STATE_MEMBERS = frozenset({"state", "status", "NOT_RUN"})
VERSION_MEMBERS = frozenset({"version", "versionFloor", "minVersion", "host"})
HKEY_ROW = re.compile(r"^\|\s*(H\d+)\s*\|\s*`([a-z]+\.[a-z-]+)`")

RECORD_MEMBERS = ("schemaVersion", "profile", "closure", "modules", "tenantFacts", "providerSet", "exclusions",
                  "dependencyAmendments", "nonClaims")
PROFILE_MEMBERS = ("id", "overlaySha256", "sectorRecordSha256", "catalogs", "hKeyMap")
CATALOG_ROW_MEMBERS = ("path", "baseSha256", "effectiveSha256")
MAP_MEMBERS = ("path", "sha256")
CLOSURE_MEMBERS = ("selected", "external", "nodes")
ROW_BASE = ("id", "class", "harness", "hKey", "kind", "owner", "deployables", "rowClass", "readiness", "exitEvidence")
REPOSITORY_ROW_MEMBERS = ROW_BASE + ("implementation",)
TENANT_ROW_MEMBERS = ROW_BASE + ("attestationRef",)
OWNER_MEMBERS = ("type", "name")
DEPLOYABLE_MEMBERS = ("name", "type", "artifact")
IMPLEMENTATION_MEMBERS = ("packetId", "deliverableIndex")
EXIT_MEMBERS = ("at", "obligation", "evidenceKinds", "evidenceRecord")
FACT_MEMBERS = ("id", "supplier", "namedInRoadmap", "attestation")
ATTESTATION_MEMBERS = ("requirement", "installUnitDigestStatus", "envelope")
ENVELOPE_MEMBERS = ("digest", "digestStatus", "signatureStatus")
PROVIDER_SET_MEMBERS = ("in", "deferred", "platformNonHarness")
IN_ROW_MEMBERS = ("key", "harness", "nodes")
DEFERRED_ROW_MEMBERS = ("key", "harness", "reason")
EXCLUSION_MEMBERS = ("component", "kind", "sources", "reason")
DECISION_MEMBERS = ("items", "decision")
NON_CLAIMS_MEMBERS = ("prose", "industryPack")
INDUSTRY_PACK_MEMBERS = ("subject", "effectiveBinding", "successor", "successorPublished", "inReleaseSet",
                         "releaseSetEntry", "source")


def require(ok: bool, code: str, message: str) -> None:
    if not ok:
        raise ValueError("%s: %s" % (code, message))


def digest(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _json(raw: bytes, code: str):
    def pairs(items):
        keys = [key for key, _ in items]
        require(len(keys) == len(set(keys)), code, "duplicate JSON member")
        return dict(items)

    def constant(name):
        raise ValueError("%s: nonfinite JSON number %s" % (code, name))
    return json.loads(raw.decode("utf-8"), object_pairs_hook=pairs, parse_constant=constant)


def _canonical(value) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def _serialize(registry) -> bytes:
    """The registry's own serialization: one-space indentation and a final newline."""
    return (json.dumps(registry, indent=1, ensure_ascii=False) + "\n").encode("utf-8")


# V0: shape.
def _closed(value, members, where):
    require(type(value) is dict, "RP_SHAPE", where + " is an object")
    keys = set(value)
    require(not keys & STATE_MEMBERS, "RP_SHAPE", "state member in " + where)
    require(not keys & VERSION_MEMBERS, "RP_SHAPE", "version or host member in " + where)
    require(keys == set(members), "RP_SHAPE", "members of %s: %s" % (where, sorted(keys ^ set(members))))


def _str(value, where, empty=False):
    require(type(value) is str and (empty or value != ""), "RP_SHAPE", "a string: " + where)


def _text(value, where):
    require(type(value) is str and value.strip() != "", "RP_SHAPE", "non-empty text: " + where)


def _bool(value, where):
    require(type(value) is bool, "RP_SHAPE", "a boolean: " + where)


def _count(value, where):
    require(type(value) is int and value >= 0, "RP_SHAPE", "a non-negative integer (not a boolean): " + where)


def _list(value, where):
    require(type(value) is list, "RP_SHAPE", "a list: " + where)


def _strings(value, where, sort=True):
    _list(value, where)
    require(all(type(item) is str and item for item in value), "RP_SHAPE", where + " strings")
    if sort:
        require(value == sorted(set(value)), "RP_SHAPE", where + " sorted and unique")


def _eq(left, right) -> bool:
    """Type-strict equality: canonical JSON on both sides, so bool, int and float stay distinct."""
    return _canonical(left) == _canonical(right)


def _shape(rec) -> None:
    _closed(rec, RECORD_MEMBERS, "the record")
    require(rec["schemaVersion"] == SCHEMA and type(rec["schemaVersion"]) is str, "RP_SHAPE", "schemaVersion")
    profile = rec["profile"]
    _closed(profile, PROFILE_MEMBERS, "profile")
    for name in ("id", "overlaySha256", "sectorRecordSha256"):
        _str(profile[name], "profile." + name)
    _list(profile["catalogs"], "profile.catalogs")
    for row in profile["catalogs"]:
        _closed(row, CATALOG_ROW_MEMBERS, "a profile.catalogs row")
        for name in CATALOG_ROW_MEMBERS:
            _str(row[name], "profile.catalogs " + name)
    require([row["path"] for row in profile["catalogs"]] == sorted({row["path"] for row in profile["catalogs"]}),
            "RP_SHAPE", "profile.catalogs sorted by path and unique")
    _closed(profile["hKeyMap"], MAP_MEMBERS, "profile.hKeyMap")
    for name in MAP_MEMBERS:
        _str(profile["hKeyMap"][name], "profile.hKeyMap " + name)
    _closed(rec["closure"], CLOSURE_MEMBERS, "closure")
    for name in CLOSURE_MEMBERS:
        _strings(rec["closure"][name], "closure." + name)
    _list(rec["modules"], "modules")
    require(rec["modules"] != [], "RP_SHAPE", "modules is non-empty")
    for row in rec["modules"]:
        require(type(row) is dict, "RP_SHAPE", "a module row is an object")
        _str(row.get("id"), "a module row id")
        where = "module row " + row["id"]
        members = TENANT_ROW_MEMBERS if row.get("rowClass") == "TENANT_PLATFORM" else REPOSITORY_ROW_MEMBERS
        if "attestationRef" in row and "implementation" not in row:
            members = TENANT_ROW_MEMBERS
        if "implementation" in row and "attestationRef" not in row:
            members = REPOSITORY_ROW_MEMBERS
        _closed(row, members, where)
        for name in ("class", "harness", "kind", "rowClass"):
            _str(row[name], "%s of %s" % (name, where))
        require(row["hKey"] is None or (type(row["hKey"]) is str and row["hKey"] != ""), "RP_SHAPE",
                "hKey of %s is a string or null" % where)
        _closed(row["owner"], OWNER_MEMBERS, "owner of " + where)
        for name in OWNER_MEMBERS:
            _str(row["owner"][name], "owner %s of %s" % (name, where))
        _list(row["deployables"], "deployables of " + where)
        require(row["deployables"] != [], "RP_SHAPE", "deployables of %s is non-empty" % where)
        for unit in row["deployables"]:
            _closed(unit, DEPLOYABLE_MEMBERS, "a deployable of " + where)
            for name in DEPLOYABLE_MEMBERS:
                _str(unit[name], "deployable %s of %s" % (name, where))
        if "implementation" in row:
            _closed(row["implementation"], IMPLEMENTATION_MEMBERS, "implementation of " + where)
            _str(row["implementation"]["packetId"], "packetId of " + where, empty=True)
            index = row["implementation"]["deliverableIndex"]
            require(index is None or (type(index) is int and index >= 0), "RP_SHAPE", "deliverableIndex of " + where)
        else:
            _str(row["attestationRef"], "attestationRef of " + where)
        readiness = row["readiness"]
        require(type(readiness) is dict and readiness.get("source") in ("SERVICES", "MODULE_HEALTH")
                and type(readiness.get("source")) is str, "RP_SHAPE", "readiness.source of " + where)
        _closed(readiness, ("source", "serviceId", "criteriaCount") if readiness["source"] == "SERVICES"
                else ("source",), "readiness of " + where)
        if readiness["source"] == "SERVICES":
            _str(readiness["serviceId"], "readiness.serviceId of " + where)
            _count(readiness["criteriaCount"], "readiness.criteriaCount of " + where)
        _closed(row["exitEvidence"], EXIT_MEMBERS, "exitEvidence of " + where)
        for name in ("at", "obligation", "evidenceRecord"):
            _str(row["exitEvidence"][name], "exitEvidence.%s of %s" % (name, where))
        _strings(row["exitEvidence"]["evidenceKinds"], "evidenceKinds of " + where, sort=False)
    _list(rec["tenantFacts"], "tenantFacts")
    for fact in rec["tenantFacts"]:
        require(type(fact) is dict, "RP_SHAPE", "a tenant fact is an object")
        _str(fact.get("id"), "a tenant fact id")
        where = "tenant fact " + fact["id"]
        _closed(fact, FACT_MEMBERS, where)
        _closed(fact["supplier"], OWNER_MEMBERS, "supplier of " + where)
        for name in OWNER_MEMBERS:
            _str(fact["supplier"][name], "supplier %s of %s" % (name, where))
        _bool(fact["namedInRoadmap"], "namedInRoadmap of " + where)
        _closed(fact["attestation"], ATTESTATION_MEMBERS, "attestation of " + where)
        _str(fact["attestation"]["requirement"], "requirement of " + where)
        _str(fact["attestation"]["installUnitDigestStatus"], "installUnitDigestStatus of " + where)
        envelope = fact["attestation"]["envelope"]
        _closed(envelope, ENVELOPE_MEMBERS, "envelope of " + where)
        require(envelope["digest"] is None or type(envelope["digest"]) is str, "RP_SHAPE", "envelope.digest of " + where)
        _str(envelope["digestStatus"], "envelope.digestStatus of " + where)
        _str(envelope["signatureStatus"], "envelope.signatureStatus of " + where)
    provider_set = rec["providerSet"]
    _closed(provider_set, PROVIDER_SET_MEMBERS, "providerSet")
    _list(provider_set["in"], "providerSet.in")
    for row in provider_set["in"]:
        _closed(row, IN_ROW_MEMBERS, "a providerSet.in row")
        _str(row["key"], "a providerSet.in key")
        _str(row["harness"], "a providerSet.in harness")
        _strings(row["nodes"], "providerSet.in nodes")
    _list(provider_set["deferred"], "providerSet.deferred")
    for row in provider_set["deferred"]:
        _closed(row, DEFERRED_ROW_MEMBERS, "a providerSet.deferred row")
        _str(row["key"], "a providerSet.deferred key")
        _str(row["harness"], "a providerSet.deferred harness")
        _text(row["reason"], "a providerSet.deferred reason")
    _strings(provider_set["platformNonHarness"], "providerSet.platformNonHarness")
    _list(rec["exclusions"], "exclusions")
    for row in rec["exclusions"]:
        require(type(row) is dict, "RP_SHAPE", "an exclusions row is an object")
        _str(row.get("component"), "an exclusion component")
        where = "exclusion " + row["component"]
        _closed(row, EXCLUSION_MEMBERS + (("roadmapDecision",) if "roadmapDecision" in row else ()), where)
        _str(row["kind"], "kind of " + where)
        _text(row["reason"], "the reason of " + where)
        _strings(row["sources"], "sources of " + where, sort=False)
        require(row["sources"] == [s for s in SOURCES_ORDER if s in row["sources"]] and row["sources"], "RP_SHAPE",
                "sources of %s in the order PROFILE, ROADMAP" % where)
        if "roadmapDecision" in row:
            _closed(row["roadmapDecision"], DECISION_MEMBERS, "roadmapDecision of " + where)
            _strings(row["roadmapDecision"]["items"], "roadmapDecision items of " + where)
            _str(row["roadmapDecision"]["decision"], "roadmapDecision decision of " + where)
    require(rec["dependencyAmendments"] == [] and type(rec["dependencyAmendments"]) is list, "RP_SHAPE",
            "dependencyAmendments is an empty list")
    _closed(rec["nonClaims"], NON_CLAIMS_MEMBERS, "nonClaims")
    _list(rec["nonClaims"]["prose"], "nonClaims.prose")
    require(rec["nonClaims"]["prose"] != [], "RP_SHAPE", "nonClaims.prose is non-empty")
    for item in rec["nonClaims"]["prose"]:
        _text(item, "a nonClaims.prose entry")
    pack = rec["nonClaims"]["industryPack"]
    _closed(pack, INDUSTRY_PACK_MEMBERS, "nonClaims.industryPack")
    for name in ("subject", "effectiveBinding", "successor", "releaseSetEntry", "source"):
        _str(pack[name], "nonClaims.industryPack." + name)
    _bool(pack["successorPublished"], "nonClaims.industryPack.successorPublished")
    _bool(pack["inReleaseSet"], "nonClaims.industryPack.inReleaseSet")


# The closure: a standard-library port of validate_readiness.dependency_closure and selection_predicate_active.
def _active(predicate, harnesses, capabilities):
    if not isinstance(predicate, dict):
        return False
    return bool(harnesses & set(predicate.get("anyOfSubjectHarnesses", []))
                or capabilities & set(predicate.get("anyOfSubjectCapabilities", [])))


def _closure(modules, roots, harnesses, capabilities):
    seen, pending = set(), list(roots)
    while pending:
        node = pending.pop()
        if node in seen or node not in modules:
            continue
        seen.add(node)
        pending.extend(modules[node].get("dependencies", []))
        for conditional in modules[node].get("conditionalDependencies", []):
            if _active(conditional.get("selectedWhen", {}), harnesses, capabilities):
                pending.append(conditional.get("moduleId"))
    return seen


def _hkey_map(raw: bytes) -> dict:
    mapping = {}
    for line in raw.decode("utf-8").splitlines():
        match = HKEY_ROW.match(line)
        if match:
            mapping.setdefault(match.group(2), match.group(1))
    return mapping


def _key_number(key):
    return int(key[1:])


def operator_rows(ownership, internal) -> frozenset:
    """The operator rows, decided from the catalog's packet ids alone, before any task-packets read."""
    return frozenset(node for node in internal
                     if str((ownership.get(node) or {}).get("packetId", "")).startswith(OPERATOR_PREFIX))


def packet_repository(read, packet_id: str) -> str:
    """The `repository` of a published non-operator packet YAML. An operator packet YAML is never opened."""
    require(type(packet_id) is str and not packet_id.startswith(OPERATOR_PREFIX), "RP_OWNER_PACKET",
            "an operator packet YAML is never opened: %s" % packet_id)
    for line in read("task-packets/%s.yaml" % packet_id).decode("utf-8").splitlines():
        if line.startswith("repository:"):
            return line.split(":", 1)[1].strip().strip('"')
    raise ValueError("RP_OWNER_PACKET: no repository line in packet %s" % packet_id)


def check(read, packets) -> dict:
    """Validate the release profile record (V0-V9). `packets` is the set of published packet ids (file stems)."""
    require(isinstance(packets, (set, frozenset)) and all(type(p) is str for p in packets), "RP_SHAPE", "packet set")
    rec = _json(read(RECORD_PATH), "RP_SHAPE")
    _shape(rec)

    # V6: the era's bytes.
    profile_member = rec["profile"]
    overlay_raw, sector_raw, map_raw = read(OVERLAY_PATH), read(SECTOR_PATH), read(HKEY_MAP_PATH)
    require(digest(overlay_raw) == OVERLAY_SHA256 == profile_member["overlaySha256"], "RP_CATALOG_BYTES", "overlay")
    require(digest(sector_raw) == SECTOR_SHA256 == profile_member["sectorRecordSha256"], "RP_CATALOG_BYTES",
            "sector record")
    require(digest(map_raw) == HKEY_MAP_SHA256 and _eq(profile_member["hKeyMap"], {"path": HKEY_MAP_PATH,
                                                                                   "sha256": HKEY_MAP_SHA256}),
            "RP_CATALOG_BYTES", "H-key map")
    effective = {}
    for path in CATALOG_PATHS:
        require(digest(read(path)) == BASE_SHA256[path], "RP_CATALOG_BYTES", "base bytes of " + path)
        effective[path] = sector_catalog.effective_bytes(path)
        require(digest(effective[path]) == EFFECTIVE_SHA256[path], "RP_CATALOG_BYTES", "effective bytes of " + path)
    require(_eq(profile_member["catalogs"], [{"path": p, "baseSha256": BASE_SHA256[p], "effectiveSha256":
                                              EFFECTIVE_SHA256[p]} for p in sorted(CATALOG_PATHS)]),
            "RP_CATALOG_BYTES", "profile.catalogs")

    providers = sector_catalog.effective_catalog(PROVIDERS_PATH)
    services = sector_catalog.effective_catalog(SERVICES_PATH)
    modules = {m["id"]: m for m in providers["modules"]}
    profiles = [p for p in providers["profileExamples"] if p.get("id") == PROFILE_ID]

    # V1: the closure.
    require(profile_member["id"] == PROFILE_ID and len(profiles) == 1, "RP_CLOSURE", "profile id")
    profile = profiles[0]
    subjects = profile.get("assuranceSubjects", {})
    computed = _closure(modules, profile["selectedModules"], set(subjects.get("harnesses", [])),
                        set(subjects.get("capabilities", [])))
    require(computed == set(profile["expectedClosure"]), "RP_CLOSURE", "the closure is the catalog's expectedClosure")
    require(rec["closure"]["nodes"] == sorted(computed), "RP_CLOSURE", "closure.nodes")
    require(rec["closure"]["selected"] == sorted(profile["selectedModules"]), "RP_CLOSURE", "closure.selected")
    require(rec["closure"]["external"] == sorted(profile["externalPrerequisites"]), "RP_CLOSURE", "closure.external")
    external = sorted(n for n in computed if n.startswith("external."))
    require(external == rec["closure"]["external"], "RP_CLOSURE", "external nodes")
    internal = sorted(computed - set(external))
    rows = rec["modules"]
    require([row["id"] for row in rows] == internal, "RP_CLOSURE", "module rows equal the non-external nodes, sorted")
    selected = set(profile["selectedModules"])
    for row in rows:
        require(row["class"] == ("SELECTED" if row["id"] in selected else "CLOSURE"), "RP_CLOSURE",
                "class of " + row["id"])
    by_id = {row["id"]: row for row in rows}

    # V8: the pack binding (before V2, so the pack row's packet is judged here).
    overlay = _json(overlay_raw, "RP_PACK_BINDING")
    deferred_entries = overlay["deferred"]
    require(len(deferred_entries) == 1, "RP_PACK_BINDING", "one deferred overlay entry")
    entry = deferred_entries[0]
    subject = entry["binding"]["catalogKey"]
    require(subject in by_id and "implementation" in by_id[subject]
            and by_id[subject]["implementation"]["packetId"] == entry["binding"]["packetId"], "RP_PACK_BINDING",
            "the pack row's packet is the overlay's effective binding")
    expected_pack = {"subject": subject, "effectiveBinding": entry["binding"]["packetId"],
                     "successor": entry["blockedBy"], "successorPublished": entry["blockedBy"] in packets,
                     "inReleaseSet": False, "releaseSetEntry": RELEASE_SET_ENTRY, "source": RELEASE_SET_SOURCE}
    require(expected_pack["successorPublished"] is False, "RP_PACK_BINDING", "the successor is unpublished")
    require(_eq(rec["nonClaims"]["industryPack"], expected_pack), "RP_PACK_BINDING", "nonClaims.industryPack")

    # V2: owner and packet, for both row classes; operator rows decided before any task-packets read.
    hkeys = _hkey_map(map_raw)
    ownership = providers.get("implementationOwnership", {})
    operators = operator_rows(ownership, internal)
    for node in internal:
        row, module = by_id[node], modules[node]
        own = ownership.get(node) if isinstance(ownership.get(node), dict) else {}
        owner = module.get("owner") or {}
        derived = ("REPOSITORY" if own.get("disposition") == "REPOSITORY_PACKET" and owner.get("type") == "REPOSITORY"
                   else "TENANT_PLATFORM" if own.get("disposition") == "EXTERNAL_PREREQUISITE"
                   and owner.get("type") == "TENANT_SUPPLIED_EXTERNAL" else None)
        require(derived is not None, "RP_OWNER_PACKET", "no row class for the catalog's pairing of " + node)
        require(not (derived == "REPOSITORY" and "attestationRef" in row), "RP_OWNER_PACKET",
                "attestationRef on a catalog REPOSITORY row: " + node)
        require(row["rowClass"] == derived, "RP_OWNER_PACKET", "rowClass of %s is the catalog's %s" % (node, derived))
        require(_eq(row["owner"], {"type": owner.get("type"), "name": owner.get("name")}), "RP_OWNER_PACKET",
                "owner of " + node)
        require(row["kind"] == module.get("kind") and row["harness"] == module.get("harness"), "RP_OWNER_PACKET",
                "kind and harness of " + node)
        require(row["hKey"] == hkeys.get(module.get("harness")), "RP_OWNER_PACKET", "hKey of " + node)
        units = [{"name": u.get("name"), "type": u.get("type"), "artifact": u.get("artifact")}
                 for u in module.get("installUnits", [])]
        require(_eq(row["deployables"], units), "RP_OWNER_PACKET", "deployables of " + node)
        if derived == "REPOSITORY":
            packet_id = own.get("packetId")
            require(_eq(row["implementation"], {"packetId": packet_id, "deliverableIndex": own.get("deliverableIndex")}),
                    "RP_OWNER_PACKET", "implementation of %s is the catalog's" % node)
            require(packet_id in packets, "RP_OWNER_PACKET", "packet %s is published" % packet_id)
            if node not in operators:
                require(packet_repository(read, packet_id) == owner.get("name"), "RP_OWNER_PACKET",
                        "packet %s names the owner" % packet_id)
        else:
            dependencies = module.get("dependencies", [])
            require("attestationRef" in row and len(dependencies) == 1 and row["attestationRef"] == dependencies[0],
                    "RP_OWNER_PACKET",
                    "attestationRef of %s is its one catalog dependency" % node)

    # V3: exit obligations and evidence kinds.
    binding = {b["moduleId"]: b["serviceId"] for b in providers.get("serviceModuleBindings", [])}
    service_rows = {s["id"]: s for s in services.get("services", []) if isinstance(s, dict)}
    implications = [i for i in providers.get("capabilityImplications", []) if i.get("id") == CITED_IMPLICATION]
    require(len(implications) == 1, "RP_EXIT", "the cited-retrieval implication")
    cited_caps = set(implications[0]["whenAll"]) | set(implications[0]["addCapabilities"])
    cited = set()
    for row in providers.get("capabilityProviders", []):
        if row.get("capability") in cited_caps:
            cited.update(row.get("modules", []))
    for node in internal:
        row, readiness = by_id[node], by_id[node]["readiness"]
        if node in binding:
            service = service_rows.get(binding[node])
            require(service is not None and _eq(readiness, {"source": "SERVICES", "serviceId": binding[node],
                                                            "criteriaCount": len(service.get("readinessCriteria", []))})
                    and readiness["criteriaCount"] >= 1, "RP_EXIT", "SERVICES readiness of " + node)
        else:
            health = modules[node].get("health")
            require(_eq(readiness, {"source": "MODULE_HEALTH"}) and isinstance(health, dict) and "readiness" in health,
                    "RP_EXIT", "MODULE_HEALTH readiness of " + node)
        kinds = [QUALIFICATION, GROUNDING] if node in cited else [QUALIFICATION]
        require(_eq(row["exitEvidence"], {"at": EVIDENCE_AT, "obligation": readiness["source"], "evidenceKinds": kinds,
                                          "evidenceRecord": EVIDENCE_RECORD}), "RP_EXIT", "exitEvidence of " + node)

    # V4: the provider set over all closure nodes.
    by_key = {}
    for node in sorted(computed):
        key = hkeys.get(modules[node].get("harness"))
        if key:
            by_key.setdefault(key, {"key": key, "harness": modules[node]["harness"], "nodes": []})["nodes"].append(node)
    expected_in = [by_key[k] for k in sorted(by_key, key=_key_number)]
    require(_eq(rec["providerSet"]["in"], expected_in), "RP_PROVIDER_SET", "providerSet.in")
    adoption = _json(read(ADOPTION_PATH), "RP_PROVIDER_SET")
    candidates = {row["harnessId"]: set(row.get("catalogCandidateIds", [])) for row in adoption["harnessCoverage"]}
    keyed = {key: harness for harness, key in hkeys.items()}
    deferred_keys = sorted(set(keyed) - set(by_key), key=_key_number)
    require([(row["key"], row["harness"]) for row in rec["providerSet"]["deferred"]]
            == [(key, keyed[key]) for key in deferred_keys], "RP_PROVIDER_SET", "providerSet.deferred")
    require(all(not (candidates.get(keyed[key], set()) & computed) for key in deferred_keys), "RP_PROVIDER_SET",
            "a deferred key has no closure candidate")
    no_key = sorted({modules[node].get("harness") for node in computed} - set(hkeys))
    require(_eq(rec["providerSet"]["platformNonHarness"], no_key), "RP_PROVIDER_SET", "providerSet.platformNonHarness")

    # V5: exclusions.
    excluded_modules = {m.rsplit(".", 1)[1]: m for m in profile.get("excludedModules", [])}
    components = sorted(ROADMAP_EXCLUSIONS | set(excluded_modules))
    require([row["component"] for row in rec["exclusions"]] == components, "RP_EXCLUSION",
            "the exclusions are the roadmap seven and the profile's excludedModules, sorted")
    catalog_text = b"\n".join(effective[p] for p in CATALOG_PATHS).decode("utf-8").lower()
    for row in rec["exclusions"]:
        name = row["component"]
        sources = [s for s in SOURCES_ORDER if (s == "PROFILE" and name in excluded_modules)
                   or (s == "ROADMAP" and name in ROADMAP_EXCLUSIONS)]
        require(row["sources"] == sources, "RP_EXCLUSION", "sources of " + name)
        matches = sorted(m for m in modules if m.rsplit(".", 1)[-1] == name)
        if matches:
            require(not set(matches) & computed, "RP_EXCLUSION", "excluded module in the closure: " + name)
            kind = KIND_WITH_SERVICE if any(m in binding for m in matches) else KIND_WITHOUT_SERVICE
            require(row["kind"] == kind and "roadmapDecision" not in row, "RP_EXCLUSION", "kind of " + name)
        else:
            require(name.lower() not in catalog_text, "RP_EXCLUSION", "no catalog mention of " + name)
            require(row["kind"] == KIND_NOT_IN_CATALOG and _eq(row.get("roadmapDecision"), NOT_IN_CATALOG_DECISIONS.get(name)),
                    "RP_EXCLUSION", "NOT_IN_CATALOG row and its roadmap decision: " + name)

    # V7: tenant facts.
    envelope_source = profile["environmentFacts"]["attestation"]
    envelope = {"digest": envelope_source.get("digest"), "digestStatus": envelope_source.get("digestStatus"),
                "signatureStatus": envelope_source.get("signatureStatus")}
    facts = rec["tenantFacts"]
    require([fact["id"] for fact in facts] == external, "RP_TENANT_FACTS", "the tenant facts are the external nodes")
    for fact in facts:
        module = modules[fact["id"]]
        owner = module.get("owner") or {}
        require(_eq(fact["supplier"], {"type": owner.get("type"), "name": owner.get("name")}), "RP_TENANT_FACTS",
                "supplier of " + fact["id"])
        require(fact["namedInRoadmap"] is (fact["id"] in NAMED_IN_ROADMAP), "RP_TENANT_FACTS",
                "namedInRoadmap of " + fact["id"])
        statuses = {u.get("digestStatus") for u in module.get("installUnits", [])}
        require(len(statuses) == 1, "RP_TENANT_FACTS", "the install units of %s share one digestStatus" % fact["id"])
        require(_eq(fact["attestation"], {"requirement": REQUIREMENT, "installUnitDigestStatus": statuses.pop(),
                                          "envelope": envelope}), "RP_TENANT_FACTS", "attestation of " + fact["id"])

    # V9: the registry is the base plus exactly this packet's one rider, appended last, byte for byte (RP-C1-4).
    briefs_raw = read(BRIEFS_PATH)
    briefs = _json(briefs_raw, "RP_REGISTRY")
    entries = briefs.get("briefs") if type(briefs) is dict else None
    require(type(entries) is list and entries, "RP_REGISTRY", "the registry's briefs list")
    riders = [i for i, b in enumerate(entries) if type(b) is dict and b.get("series") == RIDER_SERIES]
    require(len(riders) == 1, "RP_REGISTRY", "exactly one MET-ADOPT-006/packet rider (found %d)" % len(riders))
    require(riders[0] == len(entries) - 1, "RP_REGISTRY", "the rider is appended last")
    base = dict(briefs, briefs=entries[:-1])
    require(digest(_serialize(base)) == BRIEFS_BASE_SHA256, "RP_REGISTRY", "the registry less the rider is the base")
    template = [b for b in entries[:-1] if b.get("series") == RIDER_TEMPLATE_SERIES]
    require(len(template) == 1 and _eq(entries[-1], dict(template[0], series=RIDER_SERIES)), "RP_REGISTRY",
            "the rider equals the generic packet rider with this packet's series")
    require(briefs_raw == _serialize(briefs), "RP_REGISTRY", "the registry bytes are the base serialization plus the rider")
    return {"modules": len(rows), "tenantFacts": len(facts), "closure": len(computed), "in": len(expected_in),
            "exclusions": len(rec["exclusions"]), "operatorRows": sorted(operators), "citedRows": sorted(cited & set(internal)),
            "rider": len(riders)}
