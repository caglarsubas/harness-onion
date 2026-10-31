"""D5a oracle tests for MET-ADOPT-006 (RELEASE-PROFILE-001): the release profile record.

Owner decision D5a: a contract packet carries black-box tests written outside the candidate, by someone who is not
its builder. These tests take their expectations from:

* README  - ``architecture/release-profile/README.md``, the contract text (record path, schema, profile id, the
  41/30/11 counts, the ten refusal codes, the pack-row and release-set wording, the one-overlay-era rule, the
  obligations-only rule, the tenant-fact marks and the Kubernetes row);
* catalog data, read as data - the overlay-effective ``architecture/providers.yaml`` (profile fixture, module
  entries, implementationOwnership, serviceModuleBindings), the effective ``docs/PROVIDER_MODULE_CATALOG.md``
  (fixture table and closure sentence), ``architecture/sector-catalog/overlay.json`` (base/effective pins and the
  deferred pack binding), ``architecture/sector-direction.json`` (bytes only),
  ``docs/alpha-2/HARNESS_PAPER_REPOSITORY_MAP.md`` (H-key table) and the published packet YAMLs (``repository``);
  overlay-effective values come from ``sector_catalog.effective_bytes`` / ``effective_catalog`` and are named
  catalog-derived;
* operator-stated facts - the entry point ``check(read, packets)``, a refusal is a ``ValueError`` whose message
  starts with the code and a colon, ``packets`` is the frozenset of ``task-packets/*.yaml`` stems, and the
  registry rider (``MET-ADOPT-006/packet``, a copy of ``MET-ENFORCE-043/packet`` appended last, serialised with
  ``json.dumps(indent=1, ensure_ascii=False)`` plus a line feed) that this file's ``read`` supplies only when absent;
* model-derived - only the acceptance run (``check`` returns without a refusal) and the refusal codes the model
  raises for this file's own mutations.

Mutations go in only through this file's own ``read``; it refuses every ``task-packets/OP-`` path.
"""

from __future__ import annotations

import copy
import functools
import hashlib
import json
import re
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from scripts import release_profile, sector_catalog  # noqa: E402

README_PATH = "architecture/release-profile/README.md"
RECORD_PATH = "architecture/release-profile.json"
RECORD_V2_PATH = "architecture/release-profile-v2.json"
PROVIDERS = "architecture/providers.yaml"
SERVICES = "architecture/services.yaml"
CATALOG_DOC = "docs/PROVIDER_MODULE_CATALOG.md"
CATALOGS = (PROVIDERS, SERVICES, CATALOG_DOC)
OVERLAY = "architecture/sector-catalog/overlay.json"
SECTOR = "architecture/sector-direction.json"
HMAP = "docs/alpha-2/HARNESS_PAPER_REPOSITORY_MAP.md"
BRIEFS = "architecture/review-record/briefs.json"
RIDER = "MET-ADOPT-006/packet"
RIDER_TEMPLATE = "MET-ENFORCE-043/packet"
OP_PREFIX = "task-packets/" + "OP-"
EVIDENCE_RECORD = "RELEASE-EVIDENCE-001"

README = (ROOT / README_PATH).read_text(encoding="utf-8")
README_FLAT = " ".join(README.split())
PACKETS = frozenset(p.stem for p in (ROOT / "task-packets").glob("*.yaml"))


def sha(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def load_record() -> dict:
    return json.loads((ROOT / RECORD_PATH).read_bytes())


def dump_record(rec) -> bytes:
    return (json.dumps(rec, indent=2, ensure_ascii=False) + "\n").encode("utf-8")


def dump_registry(reg, indent=1) -> bytes:
    return (json.dumps(reg, indent=indent, ensure_ascii=False) + "\n").encode("utf-8")


def registry_with_rider(raw: bytes) -> bytes:
    """Operator-stated rider: supplied only when absent."""
    reg = json.loads(raw)
    if any(entry.get("series") == RIDER for entry in reg["briefs"]):
        return raw
    template = [entry for entry in reg["briefs"] if entry.get("series") == RIDER_TEMPLATE]
    assert len(template) == 1
    rider = copy.deepcopy(template[0])
    rider["series"] = RIDER
    reg["briefs"].append(rider)
    return dump_registry(reg)


class Reader:
    """The model's input: repository bytes by relative path, with this file's mutations only."""

    def __init__(self, mutations=None):
        self.mutations = dict(mutations or {})
        self.log = []

    def __call__(self, path):
        rel = str(path)
        self.log.append(rel)
        if rel.startswith(OP_PREFIX) or ("/" + OP_PREFIX) in rel:
            raise PermissionError("the oracle read refuses operator packet paths")
        if rel.startswith("/") or ".." in Path(rel).parts:
            raise PermissionError("the oracle read takes repository-relative paths only")
        raw = (ROOT / rel).read_bytes()
        if rel == BRIEFS:
            raw = registry_with_rider(raw)
        if rel in self.mutations:
            raw = self.mutations[rel](raw)
        return raw


def op_paths(log):
    return [p for p in log if p.startswith(OP_PREFIX) or ("/" + OP_PREFIX) in p]


@functools.lru_cache(maxsize=None)
def effective_providers():
    """Catalog-derived: the overlay-effective providers catalog."""
    return sector_catalog.effective_catalog(PROVIDERS)


def effective_profile():
    profiles = [p for p in effective_providers()["profileExamples"] if p["id"] == "profile.banking-readonly-amd64"]
    assert len(profiles) == 1
    return profiles[0]


def catalog_modules():
    return {m["id"]: m for m in effective_providers()["modules"]}


def readme_codes():
    codes = []
    for code in re.findall(r"\bRP_[A-Z_]+\b", README):
        if code not in codes:
            codes.append(code)
    return codes


def readme_bullets():
    bullets, cur = [], None
    for line in README.splitlines():
        if line.startswith("- "):
            if cur is not None:
                bullets.append(cur)
            cur = line[2:]
        elif cur is not None and line.startswith("  "):
            cur += " " + line.strip()
        elif cur is not None:
            bullets.append(cur)
            cur = None
    if cur is not None:
        bullets.append(cur)
    return [" ".join(b.split()) for b in bullets]


def hkey_map():
    """H-key table of the harness map, parsed here: | Hn | `harness` / ... |."""
    out = {}
    for line in (ROOT / HMAP).read_text(encoding="utf-8").splitlines():
        cells = [c.strip() for c in line.split("|")]
        if len(cells) > 3 and re.fullmatch(r"H\d+", cells[1]):
            harness = re.match(r"`([^`]+)`", cells[2])
            assert harness is not None
            assert cells[1] not in out
            out[cells[1]] = harness.group(1)
    return out


def walk(value):
    """Yield (key, value) for every member and every scalar in the record."""
    if isinstance(value, dict):
        for key, item in value.items():
            yield key, item
            yield from walk(item)
    elif isinstance(value, list):
        for item in value:
            yield None, item
            yield from walk(item)


# ---------------------------------------------------------------------------------------------------------------
# 1. The record and its schema
# ---------------------------------------------------------------------------------------------------------------


def test_record_path_schema_and_profile():
    """README: "`architecture/release-profile.json` (`planeon.internal.release-profile/v1`) records the first
    release profile: the overlay-effective closure of `profile.banking-readonly-amd64`"."""
    schema = re.search(r"`architecture/release-profile\.json` \(`([^`]+)`\)", README)
    title = re.search(r"^# Release profile: (\S+) \(RELEASE-PROFILE-001\)$", README, re.M)
    assert schema and title
    assert schema.group(1) == "planeon.internal.release-profile/v1"
    assert title.group(1) == "profile.banking-readonly-amd64"
    assert (ROOT / RECORD_PATH).is_file()
    rec = load_record()
    assert rec["schemaVersion"] == schema.group(1)
    assert rec["profile"]["id"] == title.group(1)


# ---------------------------------------------------------------------------------------------------------------
# 2. 41 nodes, 30 module rows and 11 tenant facts
# ---------------------------------------------------------------------------------------------------------------


def test_counts_and_rows_partition_the_closure():
    """README: "(41 nodes: 30 module rows and 11 tenant facts)"."""
    counts = re.search(r"\((\d+) nodes: (\d+) module rows and (\d+) tenant facts\)", README_FLAT)
    assert counts
    nodes_n, rows_n, facts_n = (int(x) for x in counts.groups())
    assert (nodes_n, rows_n, facts_n) == (41, 30, 11)
    rec = load_record()
    nodes = rec["closure"]["nodes"]
    rows = [row["id"] for row in rec["modules"]]
    facts = [fact["id"] for fact in rec["tenantFacts"]]
    assert len(nodes) == nodes_n and len(set(nodes)) == nodes_n
    assert len(rows) == rows_n and len(facts) == facts_n
    together = rows + facts
    assert len(together) == len(set(together)) == nodes_n
    assert set(together) == set(nodes)


# ---------------------------------------------------------------------------------------------------------------
# 3. The overlay-effective closure
# ---------------------------------------------------------------------------------------------------------------


def test_closure_equals_the_effective_catalog_profile():
    """README: "the overlay-effective closure of `profile.banking-readonly-amd64`" (catalog-derived: the
    effective profile fixture's expectedClosure, selectedModules and externalPrerequisites)."""
    prof = effective_profile()
    closure = load_record()["closure"]
    assert sorted(closure["nodes"]) == sorted(prof["expectedClosure"])
    assert sorted(closure["selected"]) == sorted(prof["selectedModules"])
    assert sorted(closure["external"]) == sorted(prof["externalPrerequisites"])
    for name in ("nodes", "selected", "external"):
        assert len(set(closure[name])) == len(closure[name])


def test_closure_rederived_as_dependency_fixed_point():
    """README: "the overlay-effective closure" - re-derived here from the catalog rule closure.transitive-fixed-point
    (add required module dependencies and external prerequisites until a fixed point) over the effective modules'
    `dependencies`, starting from the effective selectedModules."""
    mods = catalog_modules()
    prof = effective_profile()
    seen, stack = set(), list(prof["selectedModules"])
    while stack:
        node = stack.pop()
        if node in seen:
            continue
        assert node in mods, node
        seen.add(node)
        stack.extend(mods[node]["dependencies"])
    closure = load_record()["closure"]
    assert seen == set(prof["expectedClosure"]) == set(closure["nodes"])


def test_closure_matches_what_the_catalog_doc_states():
    """README: "the overlay-effective closure"; the effective catalog doc states "`expectedClosure` is the exact
    dependency closure, and `externalPrerequisites` is exactly the `external.*` subset" and its fixture table row
    gives 20 directly selected, 41 exact closure, 11 external facts (catalog-derived)."""
    doc = sector_catalog.effective_bytes(CATALOG_DOC).decode("utf-8")
    flat = " ".join(doc.split())
    assert ("`expectedClosure` is the exact dependency closure, and `externalPrerequisites` is exactly the "
            "`external.*` subset") in flat
    rows = [line for line in doc.splitlines() if line.startswith("| `profile.banking-readonly-amd64` |")]
    assert len(rows) == 1
    cells = [c.strip() for c in rows[0].split("|")]
    selected_n, closure_n, external_n = int(cells[2]), int(cells[3]), int(cells[4])
    closure = load_record()["closure"]
    assert len(closure["selected"]) == selected_n
    assert len(closure["nodes"]) == closure_n
    assert len(closure["external"]) == external_n
    assert sorted(closure["external"]) == sorted(n for n in closure["nodes"] if n.startswith("external."))
    assert set(closure["selected"]) <= set(closure["nodes"])


# ---------------------------------------------------------------------------------------------------------------
# 4. Each module row
# ---------------------------------------------------------------------------------------------------------------


def test_each_module_row_carries_the_named_parts():
    """README: "each module's deployables, owner, implementation packet or tenant attestation reference, readiness
    obligation and exit evidence kinds"."""
    rec = load_record()
    facts = {fact["id"] for fact in rec["tenantFacts"]}
    for row in rec["modules"]:
        assert isinstance(row["deployables"], list) and row["deployables"], row["id"]
        for dep in row["deployables"]:
            assert all(isinstance(dep[k], str) and dep[k] for k in ("name", "type", "artifact")), row["id"]
        assert isinstance(row["owner"]["type"], str) and row["owner"]["type"]
        assert isinstance(row["owner"]["name"], str) and row["owner"]["name"]
        has_impl, has_att = "implementation" in row, "attestationRef" in row
        assert has_impl != has_att, row["id"]
        if has_impl:
            assert row["implementation"]["packetId"] in PACKETS, row["id"]
            index = row["implementation"]["deliverableIndex"]
            assert type(index) is int and index >= 0
        else:
            assert row["attestationRef"] in facts, row["id"]
        assert isinstance(row["readiness"], dict) and row["readiness"], row["id"]
        assert isinstance(row["exitEvidence"]["obligation"], str) and row["exitEvidence"]["obligation"]
        kinds = row["exitEvidence"]["evidenceKinds"]
        assert isinstance(kinds, list) and kinds and all(isinstance(k, str) and k for k in kinds), row["id"]


def test_module_rows_match_the_effective_catalog():
    """README: "each module's deployables, owner, implementation packet or tenant attestation reference, readiness
    obligation" (catalog-derived: owner, harness, kind and installUnits of the effective module entry,
    implementationOwnership, serviceModuleBindings; H keys from the harness map)."""
    mods = catalog_modules()
    cat = effective_providers()
    ownership = cat["implementationOwnership"]
    bindings = {b["moduleId"]: b["serviceId"] for b in cat["serviceModuleBindings"]}
    hkeys = {harness: key for key, harness in hkey_map().items()}
    for row in load_record()["modules"]:
        mod = mods[row["id"]]
        assert row["owner"] == {"type": mod["owner"]["type"], "name": mod["owner"]["name"]}, row["id"]
        assert row["harness"] == mod["harness"] and row["kind"] == mod["kind"], row["id"]
        assert row["hKey"] == hkeys.get(mod["harness"]), row["id"]
        assert row["deployables"] == [{"name": u["name"], "type": u["type"], "artifact": u["artifact"]}
                                      for u in mod["installUnits"]], row["id"]
        own = ownership[row["id"]]
        if own["disposition"] == "REPOSITORY_PACKET":
            assert row["implementation"] == {"packetId": own["packetId"],
                                             "deliverableIndex": own["deliverableIndex"]}, row["id"]
            assert row["rowClass"] == "REPOSITORY"
        else:
            assert own["disposition"] == "EXTERNAL_PREREQUISITE", row["id"]
            assert "implementation" not in row and row["rowClass"] == "TENANT_PLATFORM", row["id"]
        if row["id"] in bindings:
            assert row["readiness"]["source"] == "SERVICES", row["id"]
            assert row["readiness"]["serviceId"] == bindings[row["id"]], row["id"]
        else:
            assert row["readiness"] == {"source": "MODULE_HEALTH"}, row["id"]


def test_implementation_packets_name_the_row_owner():
    """README: "each module's ... owner, implementation packet" (packet data: each published non-operator
    implementation packet's `repository` is the row's owner; operator packets are never opened)."""
    for row in load_record()["modules"]:
        if "implementation" not in row:
            continue
        packet_id = row["implementation"]["packetId"]
        if packet_id.startswith("OP-"):
            continue
        rel = "task-packets/" + packet_id + ".yaml"
        assert not rel.startswith(OP_PREFIX)
        text = (ROOT / rel).read_text(encoding="utf-8")
        repo = re.findall(r"^repository: (\S+)$", text, re.M)
        assert repo == [row["owner"]["name"]], row["id"]


# ---------------------------------------------------------------------------------------------------------------
# 5. The pack row and the release set
# ---------------------------------------------------------------------------------------------------------------


def test_pack_row_is_the_white_goods_pack():
    """README: "the pack row of `profile.banking-readonly-amd64` is the white-goods pack (`IND-WG-005`) in this first
    record, and the banking pack is not in the release set" (pack row identified from the overlay's deferred
    binding, catalog data)."""
    overlay = json.loads((ROOT / OVERLAY).read_bytes())
    keys = {d["binding"]["catalogKey"] for d in overlay["deferred"]}
    assert len(keys) == 1
    pack_key = keys.pop()
    rec = load_record()
    rows = [row for row in rec["modules"] if row["id"] == pack_key]
    assert len(rows) == 1
    assert rows[0]["implementation"]["packetId"] == "IND-WG-005"
    pack = rec["nonClaims"]["industryPack"]
    assert pack["subject"] == pack_key
    assert pack["effectiveBinding"] == "IND-WG-005"
    assert pack["successor"] == "IND-BANK-005"
    assert pack["successorPublished"] is False
    assert pack["inReleaseSet"] is False
    assert "IND-BANK-005" not in PACKETS
    assert "IND-WG-005" in PACKETS


def test_release_set_entry_says_what_the_readme_says():
    """README: "the banking pack enters the release set when, after CHAIN-PRODUCT-PUBLISH-001 (273), one MET-SECTOR
    packet publishes IND-BANK-005 and, in the same slot, carries the reviewed sector_catalog/overlay-schema revision
    and the record's new version, ... (the visionary's Q-RPD1-2 erratum, 2026-10-30)"."""
    first = readme_bullets()[0]
    start = first.index("the banking pack enters the release set when")
    end = first.index(" (the visionary's")
    expected_entry = first[start:end]
    expected_source = first[end + 2:first.index(")", end + 2)]
    pack = load_record()["nonClaims"]["industryPack"]
    assert pack["releaseSetEntry"] == expected_entry
    assert pack["source"] == expected_source == "the visionary's Q-RPD1-2 erratum, 2026-10-30"
    for phrase in ("after CHAIN-PRODUCT-PUBLISH-001 (273)", "one MET-SECTOR packet publishes IND-BANK-005",
                   "in the same slot", "sector_catalog/overlay-schema revision", "the record's new version"):
        assert phrase in pack["releaseSetEntry"], phrase


# ---------------------------------------------------------------------------------------------------------------
# 6. One overlay era
# ---------------------------------------------------------------------------------------------------------------


def test_record_pins_one_overlay_era():
    """README: "the record is bound to one overlay era and is never edited in place" (sha256 of the overlay and
    sector-record bytes computed here; effective bytes catalog-derived through effective_bytes)."""
    profile = load_record()["profile"]
    assert profile["overlaySha256"] == sha((ROOT / OVERLAY).read_bytes())
    assert profile["sectorRecordSha256"] == sha((ROOT / SECTOR).read_bytes())
    overlay = json.loads((ROOT / OVERLAY).read_bytes())
    assert overlay["sectorDirection"]["sha256"] == profile["sectorRecordSha256"]
    rows = {row["path"]: row for row in profile["catalogs"]}
    assert [row["path"] for row in profile["catalogs"]] == list(CATALOGS)
    for path in CATALOGS:
        base = sha((ROOT / path).read_bytes())
        effective = sha(sector_catalog.effective_bytes(path))
        assert rows[path]["baseSha256"] == base == overlay["base"][path]
        assert rows[path]["effectiveSha256"] == effective == overlay["effective"][path]
    assert profile["hKeyMap"] == {"path": HMAP, "sha256": sha((ROOT / HMAP).read_bytes())}


def test_new_version_is_not_issued_at_this_candidate():
    """README: "its new version, `architecture/release-profile-v2.json`, is issued beside it in that same MET-SECTOR
    packet" - so it does not exist yet."""
    assert "`architecture/release-profile-v2.json`" in README
    assert not (ROOT / RECORD_V2_PATH).exists()


# ---------------------------------------------------------------------------------------------------------------
# 7. Obligations and evidence kinds only
# ---------------------------------------------------------------------------------------------------------------


def test_record_names_obligations_and_evidence_kinds_only():
    """README: "it names obligations and evidence kinds only; RELEASE-EVIDENCE-001 holds every state"."""
    rec = load_record()
    for key, value in walk(rec):
        assert key not in ("state", "status"), key
        assert value != "NOT_RUN"
    for row in rec["modules"]:
        assert row["exitEvidence"]["evidenceRecord"] == EVIDENCE_RECORD, row["id"]
    assert EVIDENCE_RECORD in README


# ---------------------------------------------------------------------------------------------------------------
# 8. Tenant facts
# ---------------------------------------------------------------------------------------------------------------


def test_tenant_fact_statuses_are_the_catalog_marks():
    """README: "the tenant facts' digest and signature statuses are the catalog's MISSING_PLANNED marks as projected,
    not evidence states" (catalog-derived: each fact's installUnits digest marks and the profile fixture's
    environment-fact envelope)."""
    mods = catalog_modules()
    envelope_marks = effective_profile()["environmentFacts"]["attestation"]
    assert envelope_marks["digest"] is None
    assert envelope_marks["digestStatus"] == "MISSING_PLANNED"
    assert envelope_marks["signatureStatus"] == "MISSING_PLANNED"
    for fact in load_record()["tenantFacts"]:
        mod = mods[fact["id"]]
        assert fact["supplier"] == {"type": mod["owner"]["type"], "name": mod["owner"]["name"]}, fact["id"]
        unit_marks = {unit["digestStatus"] for unit in mod["installUnits"]}
        assert unit_marks == {"MISSING_PLANNED"}, fact["id"]
        assert all(unit["digest"] is None for unit in mod["installUnits"]), fact["id"]
        att = fact["attestation"]
        assert att["installUnitDigestStatus"] == "MISSING_PLANNED"
        assert att["envelope"]["digest"] is None
        assert att["envelope"]["digestStatus"] == "MISSING_PLANNED" == envelope_marks["digestStatus"]
        assert att["envelope"]["signatureStatus"] == "MISSING_PLANNED" == envelope_marks["signatureStatus"]


# ---------------------------------------------------------------------------------------------------------------
# 9. Kubernetes
# ---------------------------------------------------------------------------------------------------------------


def test_kubernetes_provider_is_a_tenant_platform_row():
    """README: "the Kubernetes provider is a tenant platform row whose attestation is the tenant fact
    `external.kubernetes-api`"."""
    rec = load_record()
    facts = [fact["id"] for fact in rec["tenantFacts"]]
    assert "external.kubernetes-api" in facts
    rows = [row for row in rec["modules"] if row["id"] == "provider.runtime.infrastructure.kubernetes-upstream"]
    assert len(rows) == 1
    row = rows[0]
    assert row["rowClass"] == "TENANT_PLATFORM"
    assert row["attestationRef"] == "external.kubernetes-api"
    assert "implementation" not in row
    tenant_rows = [r["id"] for r in rec["modules"] if "attestationRef" in r]
    assert tenant_rows == ["provider.runtime.infrastructure.kubernetes-upstream"]


# ---------------------------------------------------------------------------------------------------------------
# Provider set and exclusions (catalog-derived)
# ---------------------------------------------------------------------------------------------------------------


def test_provider_set_groups_the_closure_by_harness():
    """README: "the provider set" (catalog-derived: closure nodes grouped by their effective catalog harness, keyed by
    the harness map; harnesses outside the map are platform non-harness rows)."""
    mods = catalog_modules()
    hmap = hkey_map()
    by_harness = {harness: key for key, harness in hmap.items()}
    rec = load_record()
    derived, platform = {}, set()
    for node in rec["closure"]["nodes"]:
        harness = mods[node]["harness"]
        if harness in by_harness:
            derived.setdefault(by_harness[harness], (harness, []))[1].append(node)
        else:
            platform.add(harness)
    got = {row["key"]: (row["harness"], sorted(row["nodes"])) for row in rec["providerSet"]["in"]}
    assert got == {key: (h, sorted(n)) for key, (h, n) in derived.items()}
    deferred = {row["key"]: row["harness"] for row in rec["providerSet"]["deferred"]}
    assert deferred == {key: hmap[key] for key in hmap if key not in derived}
    assert sorted(rec["providerSet"]["platformNonHarness"]) == sorted(platform)


def test_exclusions_cover_the_profile_exclusions_and_stay_out_of_the_closure():
    """README: "the exclusions" (catalog-derived: the effective profile's excludedModules are the PROFILE-sourced
    exclusions; each kind follows the catalog's module entries and serviceModuleBindings)."""
    cat = effective_providers()
    mods = catalog_modules()
    bound = {b["moduleId"] for b in cat["serviceModuleBindings"]}
    rec = load_record()
    nodes = set(rec["closure"]["nodes"])
    profile_excluded = {mid.rsplit(".", 1)[-1] for mid in effective_profile()["excludedModules"]}
    from_profile = {ex["component"] for ex in rec["exclusions"] if "PROFILE" in ex["sources"]}
    assert from_profile == profile_excluded
    for ex in rec["exclusions"]:
        matches = [mid for mid in mods if mid.rsplit(".", 1)[-1] == ex["component"]]
        assert not (set(matches) & nodes), ex["component"]
        if not matches:
            assert ex["kind"] == "NOT_IN_CATALOG", ex["component"]
        else:
            assert len(matches) == 1, ex["component"]
            want = "CATALOG_MODULE_WITH_SERVICE" if matches[0] in bound else "CATALOG_MODULE_WITHOUT_SERVICE"
            assert ex["kind"] == want, ex["component"]


# ---------------------------------------------------------------------------------------------------------------
# 10. Refusal codes and mutations
# ---------------------------------------------------------------------------------------------------------------


def test_readme_lists_exactly_ten_refusal_codes():
    """README: "refusal codes RP_SHAPE, RP_CLOSURE, RP_OWNER_PACKET, RP_EXIT, RP_PROVIDER_SET, RP_EXCLUSION,
    RP_CATALOG_BYTES, RP_TENANT_FACTS, RP_PACK_BINDING, RP_REGISTRY"."""
    assert readme_codes() == ["RP_SHAPE", "RP_CLOSURE", "RP_OWNER_PACKET", "RP_EXIT", "RP_PROVIDER_SET",
                              "RP_EXCLUSION", "RP_CATALOG_BYTES", "RP_TENANT_FACTS", "RP_PACK_BINDING",
                              "RP_REGISTRY"]


def rec_mut(fn):
    def transform(raw):
        rec = json.loads(raw)
        fn(rec)
        out = dump_record(rec)
        assert out != raw
        return out
    return transform


def row(rec, row_id):
    rows = [r for r in rec["modules"] if r["id"] == row_id]
    assert len(rows) == 1
    return rows[0]


def fact(rec, fact_id):
    facts = [f for f in rec["tenantFacts"] if f["id"] == fact_id]
    assert len(facts) == 1
    return facts[0]


def _remove_row(rec):
    rec["modules"] = [r for r in rec["modules"] if r["id"] != "module.trust.observability.usage-ledger"]


def _swap_rows(rec):
    rec["modules"][0], rec["modules"][1] = rec["modules"][1], rec["modules"][0]


def _extra_member(rec):
    row(rec, "module.knowledge.retrieval-context.retrieval-service")["note"] = "extra"


def _bool_count(rec):
    readiness = row(rec, "module.execution.orchestration.orchestration-api")["readiness"]
    assert readiness["criteriaCount"] == 1
    readiness["criteriaCount"] = True


def _schema(rec):
    rec["schemaVersion"] = "planeon.internal.release-profile/v2"


def _drop_selected(rec):
    rec["closure"]["selected"].remove("provider.planeon.llamacpp")


def _extra_closure_member(rec):
    rec["closure"]["external"] = sorted(rec["closure"]["external"] + ["external.pgvector"])
    rec["closure"]["nodes"] = sorted(rec["closure"]["nodes"] + ["external.pgvector"])


def _pin_changed(rec):
    rec["profile"]["catalogs"][0]["effectiveSha256"] = "0" * 64


def _wrong_attestation(rec):
    row(rec, "provider.runtime.infrastructure.kubernetes-upstream")["attestationRef"] = "external.postgresql"


def _signature_status(rec):
    fact(rec, "external.postgresql")["attestation"]["envelope"]["signatureStatus"] = "SIGNED"


def _install_digest_status(rec):
    fact(rec, "external.opa-engine")["attestation"]["installUnitDigestStatus"] = "PINNED"


def _pack_rebound(rec):
    row(rec, "artifact.platform.industry-pack")["implementation"]["packetId"] = "IND-BANK-005"


def _in_release_set(rec):
    rec["nonClaims"]["industryPack"]["inReleaseSet"] = True


def _release_entry_text(rec):
    pack = rec["nonClaims"]["industryPack"]
    pack["releaseSetEntry"] = pack["releaseSetEntry"].replace(" (273)", "")


def _evidence_record(rec):
    row(rec, "module.runtime.ai-gateway.ai-gateway")["exitEvidence"]["evidenceRecord"] = "RELEASE-EVIDENCE-002"


def _evidence_kind_dropped(rec):
    kinds = row(rec, "module.knowledge.retrieval-context.retrieval-service")["exitEvidence"]["evidenceKinds"]
    kinds.remove("GROUNDING_EVALUATION")


def _exclusion_dropped(rec):
    rec["exclusions"] = [ex for ex in rec["exclusions"] if ex["component"] != "ollama"]


def _provider_node_moved(rec):
    rows = {r["key"]: r for r in rec["providerSet"]["in"]}
    rows["H2"]["nodes"].remove("provider.planeon.llamacpp")
    rows["H3"]["nodes"] = sorted(rows["H3"]["nodes"] + ["provider.planeon.llamacpp"])


def _provider_rows_swapped(rec):
    rows = rec["providerSet"]["in"]
    rows[1], rows[2] = rows[2], rows[1]


def _owner_changed(rec):
    row(rec, "module.knowledge.retrieval-context.index-worker")["owner"]["name"] = "mas-harness-trust-plane"


def _packet_unpublished(rec):
    row(rec, "module.knowledge.retrieval-context.index-worker")["implementation"]["packetId"] = "KN-RET-999"


def _state_member(rec):
    row(rec, "module.runtime.model-inference.inference-api")["exitEvidence"]["status"] = "PLANNED"


def _not_run_value(rec):
    fact(rec, "external.signed-catalog")["attestation"]["envelope"]["signatureStatus"] = "NOT_RUN"


def _deployable_changed(rec):
    row(rec, "module.trust.governance.registry-service")["deployables"][0]["artifact"] = "elsewhere/registry"


def _overlay_byte(raw):
    out = raw.replace(b'"decision": "SECTOR-D1"', b'"decision":  "SECTOR-D1"', 1)
    assert out != raw and json.loads(out) == json.loads(raw)
    return out


def _sector_byte(raw):
    out = raw.rstrip(b"\n") + b" \n"
    assert out != raw and json.loads(out) == json.loads(raw)
    return out


def _catalog_byte(raw):
    out = raw + b"# oracle\n"
    assert out != raw
    return out


def _rider_missing(raw):
    reg = json.loads(raw)
    reg["briefs"] = [e for e in reg["briefs"] if e.get("series") != RIDER]
    return dump_registry(reg)


def _rider_duplicated(raw):
    reg = json.loads(raw)
    riders = [e for e in reg["briefs"] if e.get("series") == RIDER]
    assert len(riders) == 1
    reg["briefs"].append(copy.deepcopy(riders[0]))
    return dump_registry(reg)


def _registry_reserialised(raw):
    out = dump_registry(json.loads(raw), indent=2)
    assert out != raw
    return out


# (name, path, transform, expected code or None where the README does not tie the case to one code)
MUTATIONS = [
    ("row removed", RECORD_PATH, rec_mut(_remove_row), None),
    ("rows reordered", RECORD_PATH, rec_mut(_swap_rows), None),
    ("extra member in a row", RECORD_PATH, rec_mut(_extra_member), "RP_SHAPE"),
    ("bool where a count is", RECORD_PATH, rec_mut(_bool_count), "RP_SHAPE"),
    ("schema version changed", RECORD_PATH, rec_mut(_schema), "RP_SHAPE"),
    ("selected member dropped from the closure", RECORD_PATH, rec_mut(_drop_selected), "RP_CLOSURE"),
    ("extra closure member", RECORD_PATH, rec_mut(_extra_closure_member), None),
    ("record's effective catalog pin changed", RECORD_PATH, rec_mut(_pin_changed), "RP_CATALOG_BYTES"),
    ("overlay byte changed", OVERLAY, _overlay_byte, "RP_CATALOG_BYTES"),
    ("sector record byte changed", SECTOR, _sector_byte, None),
    ("catalog byte changed", PROVIDERS, _catalog_byte, None),
    ("wrong attestation reference", RECORD_PATH, rec_mut(_wrong_attestation), None),
    ("fact signature status changed", RECORD_PATH, rec_mut(_signature_status), "RP_TENANT_FACTS"),
    ("fact install-unit digest status changed", RECORD_PATH, rec_mut(_install_digest_status), "RP_TENANT_FACTS"),
    ("pack row rebound", RECORD_PATH, rec_mut(_pack_rebound), None),
    ("banking pack put in the release set", RECORD_PATH, rec_mut(_in_release_set), "RP_PACK_BINDING"),
    ("release-set entry text changed", RECORD_PATH, rec_mut(_release_entry_text), "RP_PACK_BINDING"),
    ("exit evidence record renamed", RECORD_PATH, rec_mut(_evidence_record), "RP_EXIT"),
    ("exit evidence kind dropped", RECORD_PATH, rec_mut(_evidence_kind_dropped), "RP_EXIT"),
    ("exclusion dropped", RECORD_PATH, rec_mut(_exclusion_dropped), "RP_EXCLUSION"),
    ("provider-set node moved to another row", RECORD_PATH, rec_mut(_provider_node_moved), "RP_PROVIDER_SET"),
    ("provider-set rows reordered", RECORD_PATH, rec_mut(_provider_rows_swapped), None),
    ("owner changed", RECORD_PATH, rec_mut(_owner_changed), "RP_OWNER_PACKET"),
    ("implementation packet unpublished", RECORD_PATH, rec_mut(_packet_unpublished), "RP_OWNER_PACKET"),
    ("state member added", RECORD_PATH, rec_mut(_state_member), None),
    ("NOT_RUN value", RECORD_PATH, rec_mut(_not_run_value), None),
    ("deployable artifact changed", RECORD_PATH, rec_mut(_deployable_changed), None),
    ("rider missing", BRIEFS, _rider_missing, "RP_REGISTRY"),
    ("rider duplicated", BRIEFS, _rider_duplicated, "RP_REGISTRY"),
    ("registry re-serialised", BRIEFS, _registry_reserialised, "RP_REGISTRY"),
]
BY_NAME = {m[0]: m for m in MUTATIONS}


@functools.lru_cache(maxsize=None)
def refusal_of(name):
    _, path, transform, _ = BY_NAME[name]
    reader = Reader({path: transform})
    with pytest.raises(ValueError) as exc:
        release_profile.check(reader, PACKETS)
    assert not op_paths(reader.log)
    assert path in reader.log
    message = str(exc.value)
    assert ":" in message
    return message.split(":", 1)[0]


@pytest.mark.parametrize("name", [m[0] for m in MUTATIONS])
def test_mutation_is_refused(name):
    """README: "`scripts/release_profile.py` checks it (refusal codes RP_SHAPE, ..., RP_REGISTRY)" - each mutation
    is refused with a README code; the expected code is asserted where the code's name in the README names the
    mutated part, otherwise only refusal with one of the ten."""
    code = refusal_of(name)
    assert code in readme_codes()
    expected = BY_NAME[name][3]
    if expected is not None:
        assert code == expected


def test_every_refusal_code_is_reached():
    """README: the ten refusal codes - every one is reached by at least one of this file's mutations."""
    assert len(MUTATIONS) >= 14
    reached = {refusal_of(name) for name in BY_NAME}
    assert reached == set(readme_codes())


# ---------------------------------------------------------------------------------------------------------------
# 11. The model accepts the published contract
# ---------------------------------------------------------------------------------------------------------------


def test_model_accepts_the_published_contract():
    """README: "`scripts/release_profile.py` checks it" - the published record passes (model-derived), and the model
    never asks for an operator packet."""
    reader = Reader()
    result = release_profile.check(reader, PACKETS)
    assert isinstance(result, dict)
    assert not op_paths(reader.log)
    assert RECORD_PATH in reader.log
    assert BRIEFS in reader.log
