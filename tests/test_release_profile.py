"""The release profile record (RELEASE-PROFILE-001, MET-ADOPT-006): the real record passes check(read, packets), and
every failing case of design E1 fails for its named refusal code. Operator packet YAMLs are never opened: the reader
used here refuses any task-packets/OP-* path (its own literal prefix, not the module's), and two tests show the guard is
live: the module's own guard stops an emptied operator set before any read, and with the module's guard bypassed the
reader's guard fires. Until the 272 mechanics add the MET-ADOPT-006/packet rider to the registry, the reader supplies
the registry with that rider appended (RP-C1-4)."""
import copy
import json
import os
from pathlib import Path

import pytest

from scripts import release_profile as rp

ROOT = Path(__file__).resolve().parents[1]


class OperatorRead(Exception):
    """Raised by the guarded reader if anything tries to open an operator packet YAML."""


FIXTURE_OPERATOR_PATH = "task-packets/OP-"


def _serialize(registry):
    return (json.dumps(registry, indent=1, ensure_ascii=False) + "\n").encode("utf-8")


def _registry(mutate=None, serialize=_serialize):
    registry = json.loads((ROOT / rp.BRIEFS_PATH).read_bytes())
    template = next(b for b in registry["briefs"] if b["series"] == rp.RIDER_TEMPLATE_SERIES)
    registry["briefs"].append(dict(template, series=rp.RIDER_SERIES))
    if mutate:
        mutate(registry["briefs"], template)
    return serialize(registry)


def _packets():
    return frozenset(name[:-5] for name in os.listdir(ROOT / "task-packets") if name.endswith(".yaml"))


def _reader(record=None, files=None, log=None):
    files = dict({rp.BRIEFS_PATH: _registry()}, **(files or {}))
    if record is not None:
        files[rp.RECORD_PATH] = (json.dumps(record, indent=2, ensure_ascii=False) + "\n").encode("utf-8")

    def read(path):
        if log is not None:
            log.append(path)
        if path.startswith(FIXTURE_OPERATOR_PATH):
            raise OperatorRead(path)
        if path in files:
            return files[path]
        assert not path.startswith("/") and ".." not in path.split("/")
        return (ROOT / path).read_bytes()
    return read


def _record():
    return json.loads((ROOT / rp.RECORD_PATH).read_bytes())


def _row(rec, node):
    return next(row for row in rec["modules"] if row["id"] == node)


def _fact(rec, node):
    return next(fact for fact in rec["tenantFacts"] if fact["id"] == node)


def _exclusion(rec, name):
    return next(row for row in rec["exclusions"] if row["component"] == name)


TENANT = "provider.runtime.infrastructure.kubernetes-upstream"
RETRIEVAL = "module.knowledge.retrieval-context.retrieval-service"
OPERATOR = "module.runtime.infrastructure.operator"
CONTRACTS = "module.platform.contracts"
POLICY = "module.trust.security.policy-decision"
PACK = "artifact.platform.industry-pack"


def test_the_real_record_passes_without_opening_an_operator_packet():
    summary = rp.check(_reader(), _packets())
    assert summary["modules"] == 30 and summary["tenantFacts"] == 11 and summary["closure"] == 41
    assert summary["in"] == 13 and summary["exclusions"] == 10 and summary["rider"] == 1
    assert summary["operatorRows"] == ["module.runtime.infrastructure.bundle-verifier",
                                       "module.runtime.infrastructure.namespace-baseline", OPERATOR]
    assert len(summary["citedRows"]) == 6


def test_the_registry_with_exactly_this_packets_rider_passes():
    assert rp.check(_reader(files={rp.BRIEFS_PATH: _registry()}), _packets())["rider"] == 1


def test_an_operator_packet_yaml_is_never_opened():
    with pytest.raises(ValueError, match=r"^RP_OWNER_PACKET: an operator packet YAML is never opened"):
        rp.packet_repository(_reader(), "OP-001")


def _set(path, value):
    def mutate(rec):
        target = rec
        for key in path[:-1]:
            target = target[key]
        target[path[-1]] = value
    return mutate


def _edit_row(node, fn):
    return lambda rec: fn(_row(rec, node))


def _edit_fact(node, fn):
    return lambda rec: fn(_fact(rec, node))


def _edit_exclusion(name, fn):
    return lambda rec: fn(_exclusion(rec, name))


def _swap_class(row):
    row["class"] = "CLOSURE" if row["class"] == "SELECTED" else "SELECTED"


def _relabel(row):
    row["rowClass"] = "TENANT_PLATFORM"
    del row["implementation"]
    row["attestationRef"] = "external.kubernetes-api"
    row.update({k: row.pop(k) for k in ("readiness", "exitEvidence")})


def _attestation_on_repository(row):
    del row["implementation"]
    row["attestationRef"] = "external.kubernetes-api"


def _drop_node(rec):
    rec["closure"]["nodes"].remove(RETRIEVAL)


def _add_excluded(rec):
    rec["closure"]["nodes"] = sorted(rec["closure"]["nodes"] + ["provider.planeon.ollama"])


def _drop_module_row(rec):
    rec["modules"] = [row for row in rec["modules"] if row["id"] != RETRIEVAL]


def _extra_module_row(rec):
    extra = copy.deepcopy(_row(rec, RETRIEVAL))
    extra["id"] = "provider.planeon.ollama"
    rec["modules"] = sorted(rec["modules"] + [extra], key=lambda row: row["id"])


def _duplicate_module_row(rec):
    index = next(i for i, row in enumerate(rec["modules"]) if row["id"] == RETRIEVAL)
    rec["modules"].insert(index, copy.deepcopy(rec["modules"][index]))


def _h10_to_deferred(rec):
    row = next(r for r in rec["providerSet"]["in"] if r["key"] == "H10")
    rec["providerSet"]["in"].remove(row)
    rec["providerSet"]["deferred"].append({"key": "H10", "harness": row["harness"], "reason": "moved"})


def _drop_platform(name):
    def mutate(rec):
        rec["providerSet"]["platformNonHarness"].remove(name)
    return mutate


def _excluded_in_closure(rec):
    rec["exclusions"] = sorted(rec["exclusions"] + [{"component": "retrieval-service",
                                                     "kind": "CATALOG_MODULE_WITH_SERVICE", "sources": ["ROADMAP"],
                                                     "reason": "test"}], key=lambda row: row["component"])


def _drop_exclusion(name):
    def mutate(rec):
        rec["exclusions"] = [row for row in rec["exclusions"] if row["component"] != name]
    return mutate


def _drop_fact(rec):
    rec["tenantFacts"].pop()


def _swap_facts(rec):
    rec["tenantFacts"][0], rec["tenantFacts"][1] = rec["tenantFacts"][1], rec["tenantFacts"][0]


def _bound_as_module_health(row):
    row["readiness"] = {"source": "MODULE_HEALTH"}
    row["exitEvidence"]["obligation"] = "MODULE_HEALTH"


CASES = [
    # V0 RP_SHAPE
    ("extra member", "RP_SHAPE", _set(["extra"], 1)),
    ("missing hKey", "RP_SHAPE", _edit_row(RETRIEVAL, lambda row: row.pop("hKey"))),
    ("state member in a module row", "RP_SHAPE", _edit_row(RETRIEVAL, lambda row: row.update(state="DONE"))),
    ("NOT_RUN member", "RP_SHAPE", _edit_row(RETRIEVAL, lambda row: row["exitEvidence"].update(NOT_RUN=True))),
    ("version floor on the tenant platform row", "RP_SHAPE", _edit_row(TENANT, lambda row: row.update(versionFloor="1"))),
    ("implementation on the tenant platform row", "RP_SHAPE",
     _edit_row(TENANT, lambda row: row.update(implementation={"packetId": "OP-001", "deliverableIndex": None}))),
    ("empty free-text reason", "RP_SHAPE", _edit_exclusion("valkey", lambda row: row.update(reason=""))),
    # V1 RP_CLOSURE
    ("dropped node", "RP_CLOSURE", _drop_node),
    ("added excluded module", "RP_CLOSURE", _add_excluded),
    ("white-goods profile id", "RP_CLOSURE", _set(["profile", "id"], "profile.white-goods-readonly-amd64")),
    ("dropped module row", "RP_CLOSURE", _drop_module_row),
    ("extra module row", "RP_CLOSURE", _extra_module_row),
    ("exact duplicate module row", "RP_CLOSURE", _duplicate_module_row),
    ("SELECTED/CLOSURE swap", "RP_CLOSURE", _edit_row(RETRIEVAL, _swap_class)),
    # V8 RP_PACK_BINDING
    ("pack row naming IND-BANK-005", "RP_PACK_BINDING",
     _edit_row(PACK, lambda row: row["implementation"].update(packetId="IND-BANK-005"))),
    ("inReleaseSet true", "RP_PACK_BINDING", _set(["nonClaims", "industryPack", "inReleaseSet"], True)),
    ("changed releaseSetEntry", "RP_PACK_BINDING", _set(["nonClaims", "industryPack", "releaseSetEntry"], "changed")),
    ("successor IND-BANK-004", "RP_PACK_BINDING", _set(["nonClaims", "industryPack", "successor"], "IND-BANK-004")),
    ("effectiveBinding IND-BANK-005", "RP_PACK_BINDING",
     _set(["nonClaims", "industryPack", "effectiveBinding"], "IND-BANK-005")),
    # V2 RP_OWNER_PACKET
    ("blank packet", "RP_OWNER_PACKET", _edit_row(RETRIEVAL, lambda row: row["implementation"].update(packetId=""))),
    ("unpublished packet id IND-BANK-005", "RP_OWNER_PACKET",
     _edit_row(RETRIEVAL, lambda row: row["implementation"].update(packetId="IND-BANK-005"))),
    ("same-repository packet swap", "RP_OWNER_PACKET",
     _edit_row(RETRIEVAL, lambda row: row["implementation"].update(packetId="KN-DOM-001"))),
    ("changed deployable artifact", "RP_OWNER_PACKET",
     _edit_row(RETRIEVAL, lambda row: row["deployables"][0].update(artifact="other/retrieval-service"))),
    ("REPOSITORY_PACKET module relabelled TENANT_PLATFORM", "RP_OWNER_PACKET", _edit_row(POLICY, _relabel)),
    ("attestationRef external.postgresql", "RP_OWNER_PACKET",
     _edit_row(TENANT, lambda row: row.update(attestationRef="external.postgresql"))),
    ("attestationRef on a REPOSITORY row", "RP_OWNER_PACKET", _edit_row(CONTRACTS, _attestation_on_repository)),
    ("tenant row with a changed owner", "RP_OWNER_PACKET",
     _edit_row(TENANT, lambda row: row["owner"].update(name="another distribution"))),
    ("tenant row with a changed deployable artifact", "RP_OWNER_PACKET",
     _edit_row(TENANT, lambda row: row["deployables"][0].update(artifact="other-kubernetes-api"))),
    ("tenant row with a changed kind", "RP_OWNER_PACKET", _edit_row(TENANT, lambda row: row.update(kind="ADAPTER"))),
    ("retrieval-service hKey H7 to H9", "RP_OWNER_PACKET", _edit_row(RETRIEVAL, lambda row: row.update(hKey="H9"))),
    ("kubernetes-upstream hKey to null", "RP_OWNER_PACKET", _edit_row(TENANT, lambda row: row.update(hKey=None))),
    ("tampered operator row", "RP_OWNER_PACKET",
     _edit_row(OPERATOR, lambda row: row["owner"].update(name="mas-harness-trust-plane"))),
    # V3 RP_EXIT
    ("removed binding", "RP_EXIT", _edit_row(RETRIEVAL, lambda row: row["readiness"].update(serviceId="index-worker"))),
    ("bound module recorded as MODULE_HEALTH", "RP_EXIT", _edit_row(OPERATOR, _bound_as_module_health)),
    ("wrong criteria count", "RP_EXIT", _edit_row(OPERATOR, lambda row: row["readiness"].update(criteriaCount=3))),
    ("another evidence record", "RP_EXIT",
     _edit_row(RETRIEVAL, lambda row: row["exitEvidence"].update(evidenceRecord="CONF-A2-001"))),
    ("at changed", "RP_EXIT", _edit_row(RETRIEVAL, lambda row: row["exitEvidence"].update(at="CONF-A3-001"))),
    ("grounding evaluation dropped from a cited row", "RP_EXIT",
     _edit_row(RETRIEVAL, lambda row: row["exitEvidence"].update(evidenceKinds=["QUALIFICATION_EVIDENCE"]))),
    ("grounding evaluation added to a non-cited row", "RP_EXIT",
     _edit_row(CONTRACTS, lambda row: row["exitEvidence"].update(
         evidenceKinds=["QUALIFICATION_EVIDENCE", "GROUNDING_EVALUATION"]))),
    # V4 RP_PROVIDER_SET
    ("H10 moved to deferred", "RP_PROVIDER_SET", _h10_to_deferred),
    ("wrong harness id for a key", "RP_PROVIDER_SET",
     lambda rec: rec["providerSet"]["in"][0].update(harness="runtime.model-inference")),
    ("dropped platformNonHarness entry", "RP_PROVIDER_SET", _drop_platform("platform.sdk")),
    ("platform.external-prerequisite removed", "RP_PROVIDER_SET", _drop_platform("platform.external-prerequisite")),
    # V5 RP_EXCLUSION
    ("an excluded module in the closure", "RP_EXCLUSION", _excluded_in_closure),
    ("dropped profile exclusion", "RP_EXCLUSION", _drop_exclusion("vllm")),
    ("NOT_IN_CATALOG row without its decision", "RP_EXCLUSION",
     _edit_exclusion("valkey", lambda row: row.pop("roadmapDecision"))),
    ("wrong kind (ollama with a service)", "RP_EXCLUSION",
     _edit_exclusion("ollama", lambda row: row.update(kind="CATALOG_MODULE_WITH_SERVICE"))),
    ("wrong source", "RP_EXCLUSION", _edit_exclusion("tool-broker", lambda row: row.update(sources=["ROADMAP"]))),
    # V6 RP_CATALOG_BYTES (the record part; the byte parts are below)
    ("digest of another era", "RP_CATALOG_BYTES", _set(["profile", "overlaySha256"], "0" * 64)),
    # V7 RP_TENANT_FACTS
    ("ten-row set", "RP_TENANT_FACTS", _drop_fact),
    ("unsorted pair", "RP_TENANT_FACTS", _swap_facts),
    ("fifth namedInRoadmap", "RP_TENANT_FACTS", _edit_fact("external.kubernetes-api",
                                                           lambda fact: fact.update(namedInRoadmap=True))),
    ("wrong supplier", "RP_TENANT_FACTS", _edit_fact("external.postgresql",
                                                     lambda fact: fact["supplier"].update(name="someone else"))),
    ("status other than the catalog's", "RP_TENANT_FACTS",
     _edit_fact("external.postgresql", lambda fact: fact["attestation"].update(installUnitDigestStatus="PINNED"))),
    ("requirement NONE", "RP_TENANT_FACTS",
     _edit_fact("external.postgresql", lambda fact: fact["attestation"].update(requirement="NONE"))),
    ("non-null envelope digest", "RP_TENANT_FACTS",
     _edit_fact("external.postgresql", lambda fact: fact["attestation"]["envelope"].update(digest="sha256:" + "a" * 64))),
]


@pytest.mark.parametrize("name,code,mutate", CASES, ids=[case[0] for case in CASES])
def test_each_record_fault_fails_for_its_code(name, code, mutate):
    rec = _record()
    mutate(rec)
    with pytest.raises(ValueError, match=r"^%s: " % code):
        rp.check(_reader(rec), _packets())


def test_an_unpublished_catalog_packet_fails_for_owner_packet():
    with pytest.raises(ValueError, match=r"^RP_OWNER_PACKET: packet KN-RET-001 is published"):
        rp.check(_reader(), _packets() - {"KN-RET-001"})


def test_a_packet_yaml_naming_another_repository_fails_for_owner_packet():
    path = "task-packets/KN-RET-001.yaml"
    raw = (ROOT / path).read_bytes().replace(b"repository: mas-harness-knowledge-plane",
                                             b"repository: mas-harness-trust-plane", 1)
    assert raw != (ROOT / path).read_bytes()
    with pytest.raises(ValueError, match=r"^RP_OWNER_PACKET: packet KN-RET-001 names the owner"):
        rp.check(_reader(files={path: raw}), _packets())


def test_a_tampered_operator_row_never_reaches_an_operator_packet_read():
    rec = _record()
    _row(rec, OPERATOR)["owner"]["name"] = "mas-harness-trust-plane"
    with pytest.raises(ValueError, match=r"^RP_OWNER_PACKET: owner of " + OPERATOR):
        rp.check(_reader(rec), _packets())


def test_one_changed_catalog_byte_fails_for_catalog_bytes():
    raw = bytearray((ROOT / rp.PROVIDERS_PATH).read_bytes())
    raw[0] ^= 1
    with pytest.raises(ValueError, match=r"^RP_CATALOG_BYTES: base bytes of "):
        rp.check(_reader(files={rp.PROVIDERS_PATH: bytes(raw)}), _packets())


def test_a_changed_hkey_map_fails_for_catalog_bytes():
    raw = (ROOT / rp.HKEY_MAP_PATH).read_bytes() + b"\n"
    with pytest.raises(ValueError, match=r"^RP_CATALOG_BYTES: H-key map"):
        rp.check(_reader(files={rp.HKEY_MAP_PATH: raw}), _packets())


REGISTRY_FAULTS = [
    ("a second rider", _registry(lambda briefs, template: briefs.append(dict(template, series=rp.RIDER_SERIES)))),
    ("no rider", (ROOT / rp.BRIEFS_PATH).read_bytes()),
    ("a re-serialised registry", _registry(serialize=lambda r: (json.dumps(r, separators=(",", ":")) + "\n").encode())),
    ("the rider in a wrong position", _registry(lambda briefs, template: briefs.insert(0, briefs.pop()))),
    ("another packet's rider appended", _registry(lambda briefs, template: briefs.append(
        dict(template, series="MET-ADOPT-007/packet")))),
]


@pytest.mark.parametrize("name,raw", REGISTRY_FAULTS, ids=[case[0] for case in REGISTRY_FAULTS])
def test_each_registry_fault_fails_for_registry(name, raw):
    with pytest.raises(ValueError, match=r"^RP_REGISTRY: "):
        rp.check(_reader(files={rp.BRIEFS_PATH: raw}), _packets())


TYPE_CASES = [
    # RP-C1-1: bool, int and float are distinct.
    ("criteriaCount true on a 1-criterion row",
     _edit_row(RETRIEVAL, lambda row: row["readiness"].update(criteriaCount=True))),
    ("criteriaCount 2.0 on a 2-criterion row", _edit_row(OPERATOR, lambda row: row["readiness"].update(criteriaCount=2.0))),
    ("successorPublished 0", _set(["nonClaims", "industryPack", "successorPublished"], 0)),
    ("inReleaseSet 0", _set(["nonClaims", "industryPack", "inReleaseSet"], 0)),
    # RP-C1-2: identifier members are type-checked before any use.
    ("integer module-row id", _edit_row(RETRIEVAL, lambda row: row.update(id=7))),
    ("integer tenant-fact id", _edit_fact("external.postgresql", lambda fact: fact.update(id=7))),
    ("integer exclusion component", _edit_exclusion("valkey", lambda row: row.update(component=7))),
    ("integer providerSet.in", _set(["providerSet", "in"], 7)),
    ("integer providerSet.in key", lambda rec: rec["providerSet"]["in"][0].update(key=1)),
    ("integer owner name", _edit_row(TENANT, lambda row: row["owner"].update(name=7))),
]


@pytest.mark.parametrize("name,mutate", TYPE_CASES, ids=[case[0] for case in TYPE_CASES])
def test_each_type_fault_fails_for_shape_without_a_type_error(name, mutate):
    rec = _record()
    mutate(rec)
    with pytest.raises(ValueError, match=r"^RP_SHAPE: "):
        rp.check(_reader(rec), _packets())


def test_an_emptied_operator_set_is_stopped_by_the_module_guard_before_any_read(monkeypatch):
    log = []
    monkeypatch.setattr(rp, "operator_rows", lambda ownership, internal: frozenset())
    with pytest.raises(ValueError, match=r"^RP_OWNER_PACKET: an operator packet YAML is never opened"):
        rp.check(_reader(log=log), _packets())
    assert not any(path.startswith(FIXTURE_OPERATOR_PATH) for path in log)


def test_with_the_module_guard_bypassed_the_readers_guard_fires(monkeypatch):
    monkeypatch.setattr(rp, "OPERATOR_PREFIX", "\x00")
    with pytest.raises(OperatorRead, match=r"^task-packets/OP-"):
        rp.check(_reader(), _packets())
