"""The release profile record (RELEASE-PROFILE-001, MET-ADOPT-006): the real record passes check(read, packets), and
every failing case of design E1 fails for its named refusal code. Operator packet YAMLs are never opened: the reader
used here refuses any task-packets/OP-* path (its own literal prefix, not the module's), and two tests show the guard is
live: the module's own guard stops an emptied operator set before any read, and with the module's guard bypassed the
reader's guard fires. The reader supplies the registry with the MET-ADOPT-006/packet rider appended only when it is
absent (RP-C1-4, MON-RP-MECH-i), so the same tests hold before and after the 272 mechanics add the rider. The catalogs
reach the model only through this reader and packet set (Q-RP-PROJ (a1), design E2)."""
import copy
import json
import os
from pathlib import Path

import pytest

from scripts import release_profile as rp
from scripts import sector_catalog
from scripts.safe_yaml import safe_load

ROOT = Path(__file__).resolve().parents[1]


class OperatorRead(Exception):
    """Raised by the guarded reader if anything tries to open an operator packet YAML."""


FIXTURE_OPERATOR_PATH = "task-packets/OP-"


def _serialize(registry):
    return (json.dumps(registry, indent=1, ensure_ascii=False) + "\n").encode("utf-8")


def _registry(mutate=None, serialize=_serialize):
    registry = json.loads((ROOT / rp.BRIEFS_PATH).read_bytes())
    template = next(b for b in registry["briefs"] if b["series"] == rp.RIDER_TEMPLATE_SERIES)
    if not any(b["series"] == rp.RIDER_SERIES for b in registry["briefs"]):
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
    ("no rider", _registry(lambda briefs, template: briefs.pop())),
    ("a re-serialised registry", _registry(serialize=lambda r: (json.dumps(r, separators=(",", ":")) + "\n").encode())),
    ("the rider in a wrong position", _registry(lambda briefs, template: briefs.insert(0, briefs.pop()))),
    ("another packet's rider appended", _registry(lambda briefs, template: briefs.append(
        dict(template, series="MET-ADOPT-007/packet")))),
    # RP-C2-1: the same content with the rider's members in another order.
    ("the rider's members permuted", _registry(lambda briefs, template: briefs.append(
        dict(reversed(list(briefs.pop().items())))))),
]


@pytest.mark.parametrize("name,raw", REGISTRY_FAULTS, ids=[case[0] for case in REGISTRY_FAULTS])
def test_each_registry_fault_fails_for_registry(name, raw):
    with pytest.raises(ValueError, match=r"^RP_REGISTRY: "):
        rp.check(_reader(files={rp.BRIEFS_PATH: raw}), _packets())


# RP-C2-2: bytes that are not UTF-8 JSON refuse with the reading check's code, never an uncoded error.
ENCODING_CASES = [
    ("record: invalid UTF-8", rp.RECORD_PATH, b"\xff\xfe", "RP_SHAPE"),
    ("record: a UTF-8 byte-order mark", rp.RECORD_PATH, b"\xef\xbb\xbf" + (ROOT / rp.RECORD_PATH).read_bytes(), "RP_SHAPE"),
    ("record: not JSON", rp.RECORD_PATH, b"not json\n", "RP_SHAPE"),
    ("registry: invalid UTF-8", rp.BRIEFS_PATH, b"\xff\xfe", "RP_REGISTRY"),
    ("registry: a UTF-8 byte-order mark", rp.BRIEFS_PATH, b"\xef\xbb\xbf" + _registry(), "RP_REGISTRY"),
    ("registry: not JSON", rp.BRIEFS_PATH, b"not json\n", "RP_REGISTRY"),
    # RP-C3-1: text nested beyond the decoder's recursion depth.
    ("record: nested beyond the decoder's depth", rp.RECORD_PATH, b"[" * 200000, "RP_SHAPE"),
    ("registry: nested beyond the decoder's depth", rp.BRIEFS_PATH, b"[" * 200000, "RP_REGISTRY"),
]


@pytest.mark.parametrize("name,path,raw,code", ENCODING_CASES, ids=[case[0] for case in ENCODING_CASES])
def test_bytes_that_are_not_utf8_json_fail_for_the_reading_checks_code(name, path, raw, code):
    with pytest.raises(ValueError, match=r"^%s: not UTF-8 JSON$" % code):
        rp.check(_reader(files={path: raw}), _packets())


# RP-C3-3: valid JSON holding an integer beyond Python's integer-conversion limit refuses with the reading check's code.
@pytest.mark.parametrize("path,code", [(rp.RECORD_PATH, "RP_SHAPE"), (rp.BRIEFS_PATH, "RP_REGISTRY")])
def test_a_json_integer_beyond_the_conversion_limit_fails_for_the_reading_checks_code(path, code):
    raw = b'{"a": ' + b"1" * 5000 + b"}\n"
    with pytest.raises(ValueError, match=r"^%s: JSON integer beyond the conversion limit$" % code):
        rp.check(_reader(files={path: raw}), _packets())


def test_a_non_operator_packet_yaml_that_is_not_utf8_fails_for_owner_packet():
    with pytest.raises(ValueError, match=r"^RP_OWNER_PACKET: packet KN-RET-001 is not UTF-8$"):
        rp.check(_reader(files={"task-packets/KN-RET-001.yaml": b"\xff\xfe"}), _packets())


def test_an_unparseable_published_successor_packet_fails_for_catalog_bytes():
    # RP-C3-2: a published SECTOR-D1 successor (neither the blocker IND-BANK-005 nor the notice proposal) whose packet
    # YAML, read through this reader, does not parse.
    files = {"task-packets/IND-BANK-001.yaml": b"a: [\n"}
    with pytest.raises(ValueError, match=r"^RP_CATALOG_BYTES: the overlay era does not check: "):
        rp.check(_reader(files=files), _packets() | {"IND-BANK-001"})


# Q-RP-PROJ (a1), design E2: the catalogs reach the model only through the injected reader and packet set. The c2
# model read them from the disk: it passed the R11 case below, and refused the IND-BANK-005 case with RP_PACK_BINDING
# (the record's successor is unpublished), where c3 refuses it with RP_CATALOG_BYTES (RP-C3-6).
R11_PLAN = "docs/repositories/11-mas-harness-distribution.md"


def test_a_changed_r11_notice_through_the_reader_fails_for_catalog_bytes():
    raw = (ROOT / R11_PLAN).read_bytes()
    line = b"7. `DIST-004-helm-profiles`:"
    assert raw.count(b"\n" + line) == 1
    changed = raw.replace(b"\n" + line, b"\n" + line.replace(b"`:", b"` :"), 1)
    with pytest.raises(ValueError, match=r"^RP_CATALOG_BYTES: the overlay era does not check: the DIST-004 list item"):
        rp.check(_reader(files={R11_PLAN: changed}), _packets())


def test_the_injected_packet_set_decides_the_overlay_era():
    with pytest.raises(ValueError, match=r"^RP_CATALOG_BYTES: the overlay era does not check: IND-BANK-005 is published"):
        rp.check(_reader(), _packets() | {"IND-BANK-005"})


def test_the_yaml_catalogs_parse_as_effective_catalog_parses_them():
    for path in (rp.PROVIDERS_PATH, rp.SERVICES_PATH):
        assert safe_load(sector_catalog.effective_bytes(path)) == sector_catalog.effective_catalog(path)


# RP-C4-1..3 (c5): any other exception of the era check, of V9's serialization and of provider-adoption's use refuses
# with the check's code and names the original exception type.
SUCCESSOR = "task-packets/IND-BANK-001.yaml"
SUCCESSOR_ID = "IND-BANK-001"


def _nested_flow_mappings(depth):
    return b"a: " + b"{a: " * depth + b"b" + b"}" * depth + b"\n"


def _nested_block_mappings(depth):
    return b"".join(b"  " * level + b"a:\n" for level in range(depth)) + b"  " * depth + b"b\n"


NESTED_SUCCESSORS = [("flow mappings 500 deep", _nested_flow_mappings(500)),
                     ("flow mappings 600 deep", _nested_flow_mappings(600)),
                     ("block mappings 500 deep", _nested_block_mappings(500)),
                     ("block mappings 600 deep", _nested_block_mappings(600))]
UNHASHABLE_SUCCESSORS = [("block", b"? [a]\n: b\n"), ("flow", b"{[a]: b}\n")]


@pytest.mark.parametrize("name,raw", NESTED_SUCCESSORS, ids=[case[0] for case in NESTED_SUCCESSORS])
def test_a_published_successor_nesting_mappings_past_the_recursion_limit_fails_for_catalog_bytes(name, raw):
    with pytest.raises(ValueError, match=r"^RP_CATALOG_BYTES: the overlay era does not check: RecursionError: "):
        rp.check(_reader(files={SUCCESSOR: raw}), _packets() | {SUCCESSOR_ID})


@pytest.mark.parametrize("name,raw", UNHASHABLE_SUCCESSORS, ids=[case[0] for case in UNHASHABLE_SUCCESSORS])
def test_a_published_successor_with_an_unhashable_mapping_key_fails_for_catalog_bytes(name, raw):
    with pytest.raises(ValueError, match=r"^RP_CATALOG_BYTES: the overlay era does not check: TypeError: "):
        rp.check(_reader(files={SUCCESSOR: raw}), _packets() | {SUCCESSOR_ID})


def _overlay_changed_after_the_pinned_read():
    """A reader that serves the overlay's pinned bytes on the model's own read and 200000 '[' on the later reads."""
    base, reads = _reader(), []

    def read(path):
        if path == rp.OVERLAY_PATH:
            reads.append(path)
            if len(reads) > 1:
                return b"[" * 200000
        return base(path)
    return read


def test_an_overlay_changed_after_the_models_pinned_read_fails_for_catalog_bytes():
    with pytest.raises(ValueError, match=r"^RP_CATALOG_BYTES: the overlay era does not check: RecursionError: "):
        rp.check(_overlay_changed_after_the_pinned_read(), _packets())


def _registry_with_a_member_nested(depth):
    raw = _registry()
    end = raw.rindex(b"}")
    return raw[:end].rstrip() + b',\n "x": ' + b"[" * depth + b"]" * depth + b"\n}\n"


def test_a_registry_nested_past_the_recursion_limit_within_the_decoders_depth_fails_for_registry():
    # RP-C4-2: valid JSON the decoder reads, nested past the interpreter's recursion limit for V9's serialization.
    with pytest.raises(ValueError, match=r"^RP_REGISTRY: the registry does not serialize: RecursionError: "):
        rp.check(_reader(files={rp.BRIEFS_PATH: _registry_with_a_member_nested(5000)}), _packets())


ADOPTION_SHAPES = [("an empty object", b"{}\n", "KeyError"), ("a list", b"[]\n", "TypeError"),
                   ("an integer row", b'{"harnessCoverage": [1]}\n', "TypeError"),
                   ("a list harnessId", b'{"harnessCoverage": [{"harnessId": ["x"]}]}\n', "TypeError")]


@pytest.mark.parametrize("name,raw,kind", ADOPTION_SHAPES, ids=[case[0] for case in ADOPTION_SHAPES])
def test_provider_adoption_of_another_valid_shape_fails_for_provider_set(name, raw, kind):
    # RP-C4-3: provider-adoption is valid JSON of another shape.
    with pytest.raises(ValueError, match=r"^RP_PROVIDER_SET: provider-adoption is not of the read shape: %s: " % kind):
        rp.check(_reader(files={rp.ADOPTION_PATH: raw}), _packets())


CODES = ("RP_SHAPE", "RP_CLOSURE", "RP_OWNER_PACKET", "RP_EXIT", "RP_PROVIDER_SET", "RP_EXCLUSION", "RP_CATALOG_BYTES",
         "RP_TENANT_FACTS", "RP_PACK_BINDING", "RP_REGISTRY")
PROBE_FORMS = (("invalid UTF-8", b"\xff\xfe\x00"), ("nested [", b"[" * 200000), ("nested YAML", b"a: " + b"[" * 100000),
               ("5000-digit integer", b'{"a": ' + b"1" * 5000 + b"}"), ("open flow sequence", b"a: ["), ("empty", b""))
# The YAML loader under the era check exits by SIGSEGV on the two deeply nested forms in a published successor's
# packet YAML (RP-C4-4, recorded, not codeable in-process), so the successor runs only the other four.
SUCCESSOR_FORMS = ("invalid UTF-8", "5000-digit integer", "open flow sequence", "empty")


@pytest.fixture(scope="module")
def probe_cases():
    """The class probe, generated deterministically: every path check() reads on the real record, sorted, with each
    malformed form (172 cases with the published successor's four), then c5's new cases. Each case is (label, a reader
    factory, the packet set)."""
    log = []
    rp.check(_reader(log=log), _packets())
    forms = dict(PROBE_FORMS)
    files_case = lambda files: (lambda: _reader(files=files))
    cases = [("%s / %s" % (path, name), files_case({path: raw}), _packets())
             for path in sorted(set(log)) for name, raw in PROBE_FORMS]
    cases += [("%s / %s" % (SUCCESSOR, name), files_case({SUCCESSOR: forms[name]}), _packets() | {SUCCESSOR_ID})
              for name in SUCCESSOR_FORMS]
    assert len(cases) == 172
    cases += [("%s / %s" % (SUCCESSOR, name), files_case({SUCCESSOR: raw}), _packets() | {SUCCESSOR_ID})
              for name, raw in NESTED_SUCCESSORS + UNHASHABLE_SUCCESSORS]
    cases += [("overlay changed after the pinned read", _overlay_changed_after_the_pinned_read, _packets()),
              ("registry nested 5000 deep", files_case({rp.BRIEFS_PATH: _registry_with_a_member_nested(5000)}),
               _packets())]
    cases += [("provider-adoption / " + name, files_case({rp.ADOPTION_PATH: raw}), _packets())
              for name, raw, _ in ADOPTION_SHAPES]
    return cases


def test_no_uncoded_exception_escapes_check_over_the_class_probe(probe_cases):
    escaped = []
    for label, make_reader, packets in probe_cases:
        try:
            rp.check(make_reader(), packets)
            escaped.append((label, "accepted"))
        except ValueError as error:
            if str(error).split(":", 1)[0] not in CODES:
                escaped.append((label, "uncoded ValueError"))
        except Exception as error:
            escaped.append((label, type(error).__name__))
    assert len(probe_cases) == 172 + 12 and escaped == []


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
