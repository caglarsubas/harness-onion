"""D5a oracle for MET-008 (slot 289; CONTRACT_289 rev 3 with errata [E-1] and [E-2]).

Owner decision D5a: a contract packet carries tests written outside the candidate, by someone who is not its
builder. This file checks RELEASE-EVIDENCE-001's record architecture/release-evidence.json (sections 3 and 4), its
projection and checker (section 5: RE_SHAPE to RE_EXCLUSIONS), the head layer's checks V1, E1, E2, E3, V4 and V6
(section 6) and c-B's environment reader (section 7).

Source of every expected value: CONTRACT_289, cited next to each assert in the form "# CONTRACT_289 section N".
The names, signatures and return forms of the four loaded modules are the operator-stated facts of the oracle brief
(read from the candidate c2). The record, its schema, the three basis files, the authority, the hunk-class record and
the registry are fixtures: they are loaded and mutated (deep copies, served bytes, plain mappings), and never the
source of an expected value. Where a value is computed here (the state rule, the join, the counts), it is section
3's rule applied to the basis files' data. Where the contract's table prints a cell text with a parenthetical note
that may or may not belong to the text, both readings are accepted (_Either).
"""
from __future__ import annotations

import base64
import collections
import copy
import functools
import hashlib
import importlib.util
import json
import re
from pathlib import Path, PurePosixPath

import pytest

ROOT = Path(__file__).resolve().parents[1]

# --------------------------------------------------------------------------------------------------------------
# Contract constants (CONTRACT_289 sections 3 to 8)
# --------------------------------------------------------------------------------------------------------------
RECORD = "architecture/release-evidence.json"  # section 3
SCHEMA = "architecture/release-evidence/schema.json"  # section 4
PROFILE = "architecture/release-profile.json"  # section 3.1
PLACEMENT = "architecture/language-placement.json"  # section 3.1
LOCK = "release/repos.lock.json"  # section 3.1
BASIS_PATHS = (PROFILE, PLACEMENT, LOCK)  # section 3.1
HUNK_RECORD = "architecture/chain-checkpoint/hunk-classes/289.json"  # section 6
PACKET_YAMLS = (
    "task-packets/CONF-A2-001.yaml",
    "task-packets/CONF-LINUX-001.yaml",
    "task-packets/CONF-WG-001.yaml",
)  # section 6 (the era reader binds them)
SCHEMA_VERSION = "harness.planeon.ai/release-evidence/v1"  # section 3.1
AUTHORITY_SCHEMA = "harness.planeon.ai/release-evidence-authority/v1"  # section 6
PROFILE_ID = "profile.banking-readonly-amd64"  # section 3.1
DATE = "2026-11-14"  # sections 3.1 and 3.3
MEMBERS = [
    "schemaVersion", "basis", "producerStatus", "states", "columns", "claimDomains", "rows", "exclusionRows",
    "counts",
]  # section 3.1
STATES = ["NOT_RUN", "NOT_SELECTED", "BLOCKED", "FAILED", "QUALIFIED"]  # section 3.1
COLUMNS = [
    "sourceCommit", "artifactDigest", "deploymentProfile", "runtimeCampaign", "independentAssurance",
    "tenantAcceptance", "executionMode", "qualificationBundle",
]  # section 3.1
DOMAINS = [
    "containment", "applicationAuthorization", "effectSemantics", "retrievalQuality", "deploymentRecovery",
    "customerAcceptance",
]  # section 3.1
CELL_NAMES = COLUMNS + DOMAINS
ROW_MEMBERS = [
    "id", "nodeClass", "kind", "owningService", "owner", "implementation", "deployables", "cells", "claimDomains",
]  # section 3.2
DEPLOYABLE_MEMBERS = ["name", "type", "deployableRecord", "plannedLanguage", "status"]  # section 3.2
CELL_MEMBERS = ["state", "reference", "producer", "requiredSource", "owner", "date", "nextAction"]  # section 3.3
EXCLUSION_MEMBERS = [
    "id", "repository", "artifact", "side", "rider", "source", "cells", "claimDomains",
]  # section 3.4
ORDER = [
    "RE_SHAPE", "RE_PROFILE", "RE_BASIS", "RE_CLOSURE", "RE_PROJECTION", "RE_CELLS", "RE_DOMAINS", "RE_EXCLUSIONS",
]  # section 5
STATUSES = {
    "CAP-CATALOG-001": "READY",
    "CONF-A2-001": "BLOCKED",
    "CONF-LINUX-001": "BLOCKED",
    "CONF-WG-001": "BLOCKED",
    "RO-IMPL-R04": "BLOCKED",
    "RO-IMPL-R11": "BLOCKED",
    "UAT-CAMPAIGN-001": "READY",
    "human-probes item": "WAITING_OWNER",
}  # section 3.1
ROADMAP_STATUSES = ["BLOCKED", "WAITING_OWNER", "READY", "IN_PROGRESS", "DONE"]  # section 4
PROFILE_REF = "architecture/release-profile.json#"  # section 3.3
PACKET_REF = r"packet:[A-Z][A-Z0-9]*(-[A-Z0-9]+)+"  # section 3.3
EXCLUSION_ID = r"(distribution|control-plane)\.[a-z0-9]+(-[a-z0-9]+)*"  # section 3.4
MODULE_CLASSES = ("SELECTED", "CLOSURE")  # section 3.2
TENANT_SUPPLIED = "TENANT_SUPPLIED_EXTERNAL"  # section 3.2
KUBERNETES_UPSTREAM = "provider.runtime.infrastructure.kubernetes-upstream"  # section 3.2
# A catalog path, built from parts at run time (section 5, the catalog-bytes rule, D5).
CATALOG_PATH = "architecture/" + "provid" + "ers" + ".yaml"

# The class table (section 3.3, branch 1).
TENANT_NOT_SELECTED = ("sourceCommit", "artifactDigest", "executionMode", "qualificationBundle")
ARTIFACT_DECIDED = (
    "sourceCommit", "artifactDigest", "deploymentProfile", "runtimeCampaign", "independentAssurance",
    "tenantAcceptance", "deploymentRecovery",
)
# The consulted producer per module cell (section 3.3's module table; "e" is the module's exitEvidence.at; clause 2d
# fixes CONF-A2-001 for independentAssurance).
MODULE_CONSULTS = {
    "sourceCommit": "lock",
    "artifactDigest": "lock",
    "deploymentProfile": "e",
    "runtimeCampaign": "e",
    "independentAssurance": "CONF-A2-001",
    "tenantAcceptance": "CONF-WG-001",
    "executionMode": "CAP-CATALOG-001",
    "qualificationBundle": "CAP-CATALOG-001",
    "containment": "CONF-LINUX-001",
    "applicationAuthorization": "e",
    "effectSemantics": "e",
    "retrievalQuality": "e",
    "deploymentRecovery": "e",
    "customerAcceptance": "UAT-CAMPAIGN-001",
}
BLOCKING_STATUSES = ("BLOCKED", "WAITING_OWNER")  # section 3.3, clause 2c


class _Either(tuple):
    """A cell text the contract's table prints with a parenthetical note: either reading is accepted."""


CONTAINMENT_ACTION = (
    "unblock CONF-LINUX-001 (it needs existing Linux capacity or owner-approved cloud spend); the human-authored "
    "probe input is BLOCKED on a human author named by the owner"
)  # section 3.3
TENANT_ACCEPTANCE_PRODUCER = _Either(("CONF-WG-001 (the candidate)", "CONF-WG-001"))  # section 3.3
TENANT_ACCEPTANCE_SOURCE = _Either((
    "a tenant's own acceptance record from an independent producer (ADR 0005, TENANT_ACCEPTANCE after the candidate)",
    "a tenant's own acceptance record from an independent producer",
))  # section 3.3
TENANT_NONE = (
    "none: a tenant fact has no source commit, artifact digest, execution mode or qualification bundle"
)  # section 3.3
RETRIEVAL_NONE = "none: the module's exit evidence holds no GROUNDING_EVALUATION"  # section 3.3

# The exclusion rows (section 3.4).
EXCLUSIONS = [
    ("distribution.bundle", "the signed OCI bundle"),
    ("distribution.bundle-lock", "bundle.lock.json"),
    ("distribution.helm-profile", "the profile's Helm chart set"),
    ("distribution.sbom-licence", "SPDX SBOM and licence closure"),
    ("distribution.vulnerability-custody", "vulnerability evidence and model custody"),
    ("distribution.signatures-trust", "signatures, trust bundle, promotion record"),
    ("distribution.airgap-archive", "the air-gap export archive"),
    ("control-plane.control-web", "control-web"),
    ("control-plane.profile-compiler-worker", "profile-compiler-worker"),
]
SCOPE_ROW = "distribution.airgap-archive"
EXCLUSION_REPOSITORIES = {
    "distribution": {"id": "distribution", "name": "mas-harness-distribution", "rNumber": "R11"},
    "control-plane": {"id": "control-plane", "name": "mas-harness-control-plane", "rNumber": "R04"},
}
RIDERS = {
    "distribution": "RELEASE-PROFILE-001 errata (2026-10-31): R11 finding 2, Q-R11-FIRST",
    "control-plane": "RELEASE-PROFILE-001 errata (2026-10-31): F-R04-2",
}
SOURCES = {
    "distribution": {
        "registryRow": "distribution",
        "mainPin": "fe49981e",
        "note": "R11 main a60de413 since 2026-11-08 (DIST-TRANSPORT-002); the named artifacts are unchanged there",
        "path": ".",
    },
    "control-plane": {
        "registryRow": "control-plane",
        "mainPin": None,
        "note": "no verified pin: no record names R04's artifacts at a pin; Build-R04's closure-proof packet records it",
        "path": ".",
    },
}
ARTIFACT_BLOCKED = {
    "distribution": (
        "Build-R11's closure-proof packet (Q-R11-FIRST)",
        "an artifact record for repositoryId distribution in a non-inert release-set lock",
        "R11",
        "the closure-proof packet, after bundle v9 and R11's adoption of v9's hosted-runner digest",
    ),
    "control-plane": (
        "Build-R04's closure-proof packet (F-R04-2)",
        "an artifact record for repositoryId control-plane in a non-inert release-set lock",
        "R04",
        "the closure-proof packet",
    ),
}
ARTIFACT_STATUS_KEYS = {"distribution": "RO-IMPL-R11", "control-plane": "RO-IMPL-R04"}  # section 3.1
ARTIFACT_COLUMN_NONE = "none: an artifact row has no execution mode or qualification bundle"  # section 3.4
ARTIFACT_DOMAIN_NONE = "none: an artifact row answers deployment and recovery only"  # section 3.4
SCOPE_NONE = "none: enterprise-release scope, not selected for profile.banking-readonly-amd64"  # section 3.4

# E3's spans (section 6): 20 spans over 7 files.
ERRATA_SPANS = {
    "ci/parallel_suite.py": [(67, 68), (83, 84), (123, 124), (126, 128), (273, 273), (343, 343), (357, 357),
                             (364, 364)],
    "docs/alpha-2/PARALLEL_SUITE_PERF035.md": [(21, 22)],
    "tests/test_ci_performance.py": [(169, 169)],
    "tests/test_credential_lifecycle.py": [(362, 362)],
    "tests/test_parallel_suite.py": [(990, 990), (992, 993), (1072, 1073)],
    "tests/test_met_007_oracle.py": [(212, 212), (1776, 1776)],
    "architecture/oracle-identity-met-007.json": [(5, 5), (8, 8), (28, 29), (42, 42)],
}
PC1_ORACLE = "tests/test_met_007_oracle.py"  # section 8.1
PC1_IDENTITY = "architecture/oracle-identity-met-007.json"  # section 8.1
CASCADE_FILE = "tests/test_load_deadlines.py"  # section 16, [E-1]
SYNTHETIC_FILE = "tests/test_credential_lifecycle.py"  # one span, (362, 362), section 6
SYNTHETIC_LINE = 362

# c-B (section 7).
WORKERS_NAME = "PLANEON_PARALLEL_SUITE_WORKERS"
DEADLINE_NAME = "PLANEON_PARALLEL_SUITE_DEADLINE"

# --------------------------------------------------------------------------------------------------------------
# Loaders, readers and helpers (plain data only)
# --------------------------------------------------------------------------------------------------------------


def _load(relative, tag):
    """Load one of the four repository modules by file path into a fresh module object (operator-stated)."""
    spec = importlib.util.spec_from_file_location("met008_oracle_" + tag, ROOT / relative)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@functools.lru_cache(maxsize=None)
def projection():
    return _load("scripts/release_evidence.py", "projection")


@functools.lru_cache(maxsize=None)
def checker():
    return _load("scripts/validate_release_evidence.py", "checker")


@functools.lru_cache(maxsize=None)
def head():
    return _load("scripts/validate_met_008.py", "head")


@functools.lru_cache(maxsize=None)
def suite():
    return _load("ci/parallel_suite.py", "suite")


@functools.lru_cache(maxsize=None)
def _disk(relative):
    """The bytes of one repository file, by exact path (a regular file under ROOT)."""
    text = str(relative)
    pure = PurePosixPath(text)
    if not text or pure.is_absolute() or ".." in pure.parts:
        raise ValueError("not a repository path: %r" % text)
    target = ROOT / text
    if not target.is_file():
        raise FileNotFoundError(text)
    # Era read ([PC-1]): the head's reviewed_bytes, which projects a bridged successor's newer bytes back first.
    return head().reviewed_bytes(text)


def _reader(served=None):
    """A plain reader: the served bytes for the paths in `served`, the disk's bytes otherwise."""
    table = dict(served or {})

    def read(path):
        key = str(path)
        if key in table:
            return table[key]
        return _disk(key)

    return read


def _json(relative):
    return json.loads(_disk(relative))


def _record():
    """A fresh parsed copy of the live record."""
    return json.loads(_disk(RECORD))


def _sha(raw):
    return hashlib.sha256(raw).hexdigest()


def _hex(value):
    return str(value).split(":")[-1].lower()


def _b64(raw):
    return base64.b64encode(raw).decode("ascii")


def _format_of(raw):
    """The json.dumps options that reproduce `raw`, so a mutated copy changes only what the case changes."""
    original = json.loads(raw)
    for indent in (2, 4, 1, None):
        for ensure_ascii in (False, True):
            for sort_keys in (False, True):
                for tail in ("\n", ""):
                    options = {"indent": indent, "ensure_ascii": ensure_ascii, "sort_keys": sort_keys}
                    if (json.dumps(original, **options) + tail).encode("utf-8") == raw:
                        return options, tail
    return {"indent": 2, "ensure_ascii": False, "sort_keys": False}, "\n"


def _dump_like(raw, data):
    options, tail = _format_of(raw)
    return (json.dumps(data, **options) + tail).encode("utf-8")


def _served(path, mutate):
    """{path: the bytes of a mutated copy of that JSON file}."""
    raw = _disk(path)
    data = json.loads(raw)
    mutate(data)
    return {path: _dump_like(raw, data)}


def _cell(row, name):
    return row["cells"][name] if name in COLUMNS else row["claimDomains"][name]


def _c(state, reference, producer, required, owner, action):
    """A cell in section 3.3's member order."""
    return {
        "state": state,
        "reference": reference,
        "producer": producer,
        "requiredSource": required,
        "owner": owner,
        "date": DATE,
        "nextAction": action,
    }


_MISSING = object()


def _mismatches(actual, expected):
    wrong = []
    for member, want in expected.items():
        got = actual.get(member, _MISSING)
        good = got in want if isinstance(want, _Either) else got == want
        if not good:
            wrong.append((member, got))
    return wrong


def _walk(node):
    yield node
    if isinstance(node, dict):
        for value in node.values():
            yield from _walk(value)
    elif isinstance(node, list):
        for value in node:
            yield from _walk(value)


def _find_holder(node, key):
    """The first mapping (depth first, a mapping's own keys before its children) that holds `key`."""
    if isinstance(node, dict):
        if key in node:
            return node
        children = list(node.values())
    elif isinstance(node, list):
        children = node
    else:
        return None
    for child in children:
        found = _find_holder(child, key)
        if found is not None:
            return found
    return None


@functools.lru_cache(maxsize=None)
def _grounded_ids():
    profile = _json(PROFILE)
    return frozenset(
        module["id"] for module in profile["modules"]
        if "GROUNDING_EVALUATION" in module["exitEvidence"]["evidenceKinds"]
    )


def _modules():
    return {module["id"]: module for module in _json(PROFILE)["modules"]}


def _facts():
    return {fact["id"]: fact for fact in _json(PROFILE)["tenantFacts"]}


def _module_rows(record):
    return [row for row in record["rows"] if row["nodeClass"] in MODULE_CLASSES]


def _fact_rows(record):
    return [row for row in record["rows"] if row["nodeClass"] == "TENANT_FACT"]


def _first_module(record):
    return _module_rows(record)[0]


def _last_module(record):
    return _module_rows(record)[-1]


def _first_fact(record):
    return _fact_rows(record)[0]


def _ungrounded_module(record):
    grounded = _grounded_ids()
    return next(row for row in _module_rows(record) if row["id"] not in grounded)


def _module_with_deployables(record):
    return next(row for row in _module_rows(record) if row["deployables"])


def _row_by_id(record, ident):
    return next(row for row in record["rows"] if row["id"] == ident)


def _module_cells(row_id, module):
    """Section 3.3's module table for one module row (e = the module's exitEvidence.at, p = the profile id)."""
    e = module["exitEvidence"]["at"]
    packet_e = "packet:" + e
    run_e = "unblock and run " + e
    release = "publish the first product release"
    grounded = "GROUNDING_EVALUATION" in module["exitEvidence"]["evidenceKinds"]
    if grounded:
        retrieval = _c("BLOCKED", packet_e, e, "a grounding evaluation record", "R12", run_e)
    else:
        retrieval = _c("NOT_SELECTED", PROFILE_REF + row_id, None, None, "R00", RETRIEVAL_NONE)
    return {
        "sourceCommit": _c("BLOCKED", LOCK, "R11's release set", "a release-lock repository entry", "R11", release),
        "artifactDigest": _c("BLOCKED", LOCK, "R11's release set", "a release-lock artifact digest", "R11", release),
        "deploymentProfile": _c("BLOCKED", packet_e, e, "a deployment record of " + PROFILE_ID, "R12", run_e),
        "runtimeCampaign": _c("BLOCKED", packet_e, e, "a campaign record of " + e, "R12", run_e),
        "independentAssurance": _c(
            "BLOCKED", packet_e, e, "an assurance record bound to the artifact digest", "R12", run_e),
        "tenantAcceptance": _c(
            "BLOCKED", "packet:CONF-WG-001", TENANT_ACCEPTANCE_PRODUCER, TENANT_ACCEPTANCE_SOURCE, "R12",
            "unblock and run CONF-WG-001; the tenant accepts after the candidate"),
        "executionMode": _c(
            "NOT_RUN", None, "CAP-CATALOG-001", "a capability catalogue row with its execution mode", "R00",
            "publish CAP-CATALOG-001"),
        "qualificationBundle": _c(
            "NOT_RUN", None, "CAP-CATALOG-001", "a qualification bundle reference", "R00", "publish CAP-CATALOG-001"),
        "containment": _c(
            "BLOCKED", "packet:CONF-LINUX-001", "CONF-LINUX-001", "a containment campaign record", "R12",
            CONTAINMENT_ACTION),
        "applicationAuthorization": _c("BLOCKED", packet_e, e, "an authorization campaign record", "R12", run_e),
        "effectSemantics": _c("BLOCKED", packet_e, e, "an effect-semantics campaign record", "R12", run_e),
        "retrievalQuality": retrieval,
        "deploymentRecovery": _c("BLOCKED", packet_e, e, "a deployment and recovery record", "R12", run_e),
        "customerAcceptance": _c(
            "NOT_RUN", None, "UAT-CAMPAIGN-001", "a customer workflow acceptance record", "R12",
            "run UAT-CAMPAIGN-001"),
    }


def _fact_cell(row_id, fact, name):
    """Section 3.3's TENANT_FACT rows."""
    if name in TENANT_NOT_SELECTED:
        return _c("NOT_SELECTED", None, None, None, "R00", TENANT_NONE)
    return _c(
        "BLOCKED", PROFILE_REF + row_id, fact["supplier"]["name"], fact["attestation"]["requirement"], "TENANT",
        "obtain the signed environment fact")


def _exclusion_cell(ident, name):
    """Section 3.4's exclusion-row cells."""
    if ident == SCOPE_ROW:
        return _c("NOT_SELECTED", None, None, None, "R00", SCOPE_NONE)
    if name in ARTIFACT_DECIDED:
        producer, required, owner, action = ARTIFACT_BLOCKED[ident.split(".", 1)[0]]
        return _c("BLOCKED", LOCK, producer, required, owner, action)
    if name in COLUMNS:
        return _c("NOT_SELECTED", None, None, None, "R00", ARTIFACT_COLUMN_NONE)
    return _c("NOT_SELECTED", None, None, None, "R00", ARTIFACT_DOMAIN_NONE)


def _rule(kind, name, facts, lock_kind, statuses):
    """Section 3.3's three branches, in order, for one cell, with the consulted producer the tables fix."""
    # Branch 1: NOT_SELECTED by the class table.
    if kind == "module" and name == "retrievalQuality" and not facts["grounded"]:
        return "NOT_SELECTED"
    if kind == "tenant" and name in TENANT_NOT_SELECTED:
        return "NOT_SELECTED"
    if kind == "artifact" and name not in ARTIFACT_DECIDED:
        return "NOT_SELECTED"
    if kind == "scope":
        return "NOT_SELECTED"
    # Branch 2: BLOCKED where the producer cannot run.
    if kind == "tenant":
        return "BLOCKED" if facts["requirement"] == "SIGNED_ENVIRONMENT_FACT" else "NOT_RUN"  # clause 2b
    if kind == "artifact":
        consulted, status_key = "lock", facts["statusKey"]
    else:
        consulted = MODULE_CONSULTS[name]
        status_key = {"lock": "RO-IMPL-R11", "e": facts["exitAt"]}.get(consulted, consulted)
    if consulted == "lock" and lock_kind == "INERT_LOCK":  # clause 2a
        return "BLOCKED"
    if statuses.get(status_key) in BLOCKING_STATUSES:  # clause 2c (and 2d for independentAssurance)
        return "BLOCKED"
    # Branch 3.
    return "NOT_RUN"


def _assert_well_formed(result):
    # CONTRACT_289 section 5 (validate returns a list of codes)
    assert isinstance(result, list), result
    # CONTRACT_289 section 5 (known codes, in section 5's order, each at most once)
    assert result == [code for code in ORDER if code in result], result
    # CONTRACT_289 section 5 (RE_PROFILE runs the registered checker over the live tree, which passes)
    assert "RE_PROFILE" not in result, result


def _validate(record, served=None):
    result = checker().validate(record, _reader(served))
    _assert_well_formed(result)
    return result


def _refusal(call, *args):
    """The message of the ValueError a head check raises (operator-stated: it contains MET-008)."""
    with pytest.raises(ValueError) as info:
        call(*args)
    return str(info.value)


# --------------------------------------------------------------------------------------------------------------
# Mutators (each takes a fresh parsed record and changes it in place)
# --------------------------------------------------------------------------------------------------------------


def _navigate(record, keys):
    target = record
    for key in keys:
        target = target[key]
    return target


def _set_path(keys, value):
    def mutate(record):
        _navigate(record, keys[:-1])[keys[-1]] = copy.deepcopy(value)
    return mutate


def _drop_path(keys):
    def mutate(record):
        del _navigate(record, keys[:-1])[keys[-1]]
    return mutate


def _set_cell(pick, name, member, value):
    def mutate(record):
        _cell(pick(record), name)[member] = copy.deepcopy(value)
    return mutate


def _set_row(pick, member, value):
    def mutate(record):
        pick(record)[member] = copy.deepcopy(value)
    return mutate


def _swap_in(pick, first, second):
    def mutate(record):
        target = pick(record)
        order = list(target)
        i, j = order.index(first), order.index(second)
        order[i], order[j] = order[j], order[i]
        items = [(key, target[key]) for key in order]
        target.clear()
        target.update(items)
    return mutate


def _swap_list(key, i, j):
    def mutate(record):
        items = record[key]
        items[i], items[j] = items[j], items[i]
    return mutate


def _reverse_list(key):
    def mutate(record):
        record[key].reverse()
    return mutate


def _pop_list(key, index):
    def mutate(record):
        record[key].pop(index)
    return mutate


def _drop_cell(pick, name):
    def mutate(record):
        row = pick(record)
        del (row["cells"] if name in COLUMNS else row["claimDomains"])[name]
    return mutate


def _extra_domain_cell(record):
    row = _first_module(record)
    row["claimDomains"]["auditTrail"] = copy.deepcopy(row["claimDomains"]["containment"])


def _extra_deployable_member(record):
    _module_with_deployables(record)["deployables"][0]["oracle"] = "an extra member"


def _rows_as_object(record):
    record["rows"] = {"rows": record["rows"]}


def _owner_rnumber(record):
    _first_module(record)["owner"]["rNumber"] = "R1"


def _duplicate_last_row(record):
    record["rows"].append(copy.deepcopy(record["rows"][-1]))


def _flip_module_class(record):
    row = _first_module(record)
    row["nodeClass"] = "CLOSURE" if row["nodeClass"] == "SELECTED" else "SELECTED"


def _fact_as_closure(record):
    _first_fact(record)["nodeClass"] = "CLOSURE"


def _rename_module(record):
    _first_module(record)["id"] = "module.oracle.renamed"


def _other_row_fragment(record):
    row = _ungrounded_module(record)
    _cell(row, "retrievalQuality")["reference"] = PROFILE_REF + _first_fact(record)["id"]


def _qualified_exclusion_cell(record):
    _cell(record["exclusionRows"][0], "sourceCommit")["state"] = "QUALIFIED"


def _scope_row_not_run(record):
    row = next(row for row in record["exclusionRows"] if row["id"] == SCOPE_ROW)
    _cell(row, "deploymentRecovery")["state"] = "NOT_RUN"


def _duplicate_exclusion_id(record):
    record["exclusionRows"][1]["id"] = record["exclusionRows"][0]["id"]


def _exclusion_names_a_fact(record):
    record["exclusionRows"][0]["id"] = _json(PROFILE)["closure"]["external"][0]


def _share_reference(pick):
    def mutate(record):
        row = pick(record)
        _cell(row, "customerAcceptance")["reference"] = _cell(row, "tenantAcceptance")["reference"]
    return mutate


def _share_producer(pick):
    def mutate(record):
        row = pick(record)
        _cell(row, "customerAcceptance")["producer"] = _cell(row, "tenantAcceptance")["producer"]
    return mutate


def _noop(record):
    return None


# Basis premises the projection guards (section 3.3 and section 5; MET008-C2-8).
def _lock_not_inert(data):
    data["documentKind"] = "RELEASE_SET"


def _exit_first_module(data):
    data["modules"][0]["exitEvidence"]["at"] = "CONF-WG-001"


def _exit_last_module(data):
    data["modules"][-1]["exitEvidence"]["at"] = "CONF-LINUX-001"


def _attestation_first_fact(data):
    data["tenantFacts"][0]["attestation"]["requirement"] = "ATTESTATION_RECORD"


def _attestation_last_fact(data):
    data["tenantFacts"][-1]["attestation"]["requirement"] = "UNATTESTED"


GUARD_CASES = [
    pytest.param(LOCK, _lock_not_inert, id="lock-not-inert"),
    pytest.param(PROFILE, _exit_first_module, id="exit-evidence-first-module"),
    pytest.param(PROFILE, _exit_last_module, id="exit-evidence-last-module"),
    pytest.param(PROFILE, _attestation_first_fact, id="attestation-first-fact"),
    pytest.param(PROFILE, _attestation_last_fact, id="attestation-last-fact"),
]


# ==============================================================================================================
# 1. The live record (sections 3 and 4)
# ==============================================================================================================


def test_live_record_passes_the_checker():
    """Sections 3 to 5: validate(<the record parsed from RECORD_PATH>, disk_reader(ROOT)) returns []."""
    result = checker().validate(_record(), checker().disk_reader(ROOT))
    # CONTRACT_289 section 5 ([] accepts)
    assert result == []


def test_projection_paths_name_the_record_and_its_basis():
    """Sections 3 and 3.1: RECORD_PATH, PROFILE_PATH, DEPLOYABLE_RECORD_PATH and LOCK_PATH."""
    module = projection()
    # CONTRACT_289 section 3
    assert str(module.RECORD_PATH) == RECORD
    # CONTRACT_289 section 3.1
    assert str(module.PROFILE_PATH) == PROFILE
    # CONTRACT_289 section 3.1
    assert str(module.DEPLOYABLE_RECORD_PATH) == PLACEMENT
    # CONTRACT_289 section 3.1
    assert str(module.LOCK_PATH) == LOCK


def test_members_and_constants():
    """Section 3.1: the nine members in order, schemaVersion and the states, columns and claimDomains constants."""
    record = _record()
    # CONTRACT_289 section 3.1
    assert list(record) == MEMBERS
    # CONTRACT_289 section 3.1
    assert record["schemaVersion"] == SCHEMA_VERSION
    # CONTRACT_289 section 3.1
    assert record["states"] == STATES
    # CONTRACT_289 section 3.1
    assert record["columns"] == COLUMNS
    # CONTRACT_289 section 3.1
    assert record["claimDomains"] == DOMAINS


def test_basis_pins_the_three_files():
    """Section 3.1 (basis): three pins in order, their members and paths, each sha256 the digest of the bytes."""
    basis = _record()["basis"]
    # CONTRACT_289 section 3.1
    assert list(basis) == ["profile", "deployableRecord", "releaseLock"]
    # CONTRACT_289 section 3.1
    assert list(basis["profile"]) == ["path", "id", "sha256"]
    # CONTRACT_289 section 3.1
    assert list(basis["deployableRecord"]) == ["path", "sha256"]
    # CONTRACT_289 section 3.1
    assert list(basis["releaseLock"]) == ["path", "sha256"]
    for key, path in zip(("profile", "deployableRecord", "releaseLock"), BASIS_PATHS):
        # CONTRACT_289 section 3.1
        assert basis[key]["path"] == path
        # CONTRACT_289 section 3.1 (the digest of the bytes the reader gives for that path)
        assert basis[key]["sha256"] == _sha(_disk(path))
    # CONTRACT_289 section 3.1 (the profile's profile.id)
    assert basis["profile"]["id"] == PROFILE_ID == _json(PROFILE)["profile"]["id"]
    # CONTRACT_289 section 3.1 (no catalog file is named, D5)
    assert CATALOG_PATH not in json.dumps(basis)


def test_producer_status():
    """Section 3.1 (producerStatus): source, asOf and the statuses at 289, keys sorted."""
    status = _record()["producerStatus"]
    # CONTRACT_289 section 3.1
    assert list(status) == ["source", "asOf", "statuses"]
    source = status["source"]
    # CONTRACT_289 section 3.1
    assert list(source) == ["repository", "path", "commit", "sha256"]
    # CONTRACT_289 section 3.1
    assert source["repository"] == "harness-onion-roadmap"
    # CONTRACT_289 section 3.1
    assert source["path"] == "roadmap/roadmap.json"
    # CONTRACT_289 section 3.1 (a 40-hex commit)
    assert re.fullmatch(r"[0-9a-f]{40}", source["commit"])
    # CONTRACT_289 section 3.3 (bridge roadmap 1cc8073d)
    assert source["commit"].startswith("1cc8073d")
    # CONTRACT_289 section 3.1 (a 64-hex sha256)
    assert re.fullmatch(r"[0-9a-f]{64}", source["sha256"])
    # CONTRACT_289 section 3.3 (roadmap.json bf78bd61)
    assert source["sha256"].startswith("bf78bd61")
    # CONTRACT_289 section 3.1
    assert status["asOf"] == DATE
    # CONTRACT_289 section 3.1 (the statuses at 289)
    assert status["statuses"] == STATUSES
    # CONTRACT_289 section 3.1 (keys sorted)
    assert list(status["statuses"]) == sorted(STATUSES)


def test_rows_follow_closure_nodes():
    """Section 3.2 (Q-289-A1): 41 rows in closure.nodes order, 20 SELECTED + 10 CLOSURE + 11 TENANT_FACT."""
    record = _record()
    profile = _json(PROFILE)
    ids = [row["id"] for row in record["rows"]]
    # CONTRACT_289 section 3.2 (in closure.nodes order)
    assert ids == profile["closure"]["nodes"]
    # CONTRACT_289 section 3.2
    assert len(ids) == 41
    classes = collections.Counter(row["nodeClass"] for row in record["rows"])
    # CONTRACT_289 section 3.2 (composition)
    assert dict(classes) == {"SELECTED": 20, "CLOSURE": 10, "TENANT_FACT": 11}
    facts = [row["id"] for row in _fact_rows(record)]
    # CONTRACT_289 section 3.2 (the tenant-fact ids equal closure.external)
    assert sorted(facts) == sorted(profile["closure"]["external"]) and len(facts) == len(set(facts))
    modules = _modules()
    for row in _module_rows(record):
        # CONTRACT_289 section 5 (RE_CLOSURE: each module row's nodeClass equals the module's class)
        assert row["nodeClass"] == modules[row["id"]]["class"], row["id"]


def test_row_and_cell_members():
    """Sections 3.2 to 3.4 (MET008-C2-2): row, deployable, exclusion-row and cell members, in order."""
    record = _record()
    for row in record["rows"]:
        # CONTRACT_289 section 3.2
        assert list(row) == ROW_MEMBERS, row["id"]
        # CONTRACT_289 section 3.2 (cells keyed by the eight columns, in order)
        assert list(row["cells"]) == COLUMNS, row["id"]
        # CONTRACT_289 section 3.2 (claimDomains keyed by the six domains, in order)
        assert list(row["claimDomains"]) == DOMAINS, row["id"]
        for deployable in row["deployables"]:
            # CONTRACT_289 section 3.2
            assert list(deployable) == DEPLOYABLE_MEMBERS, row["id"]
    for row in record["exclusionRows"]:
        # CONTRACT_289 section 3.4
        assert list(row) == EXCLUSION_MEMBERS, row["id"]
        # CONTRACT_289 section 3.4 (the same form as a closure row's)
        assert list(row["cells"]) == COLUMNS and list(row["claimDomains"]) == DOMAINS, row["id"]
    for row in record["rows"] + record["exclusionRows"]:
        for name in CELL_NAMES:
            # CONTRACT_289 section 3.3 (every cell is exactly these seven members)
            assert list(_cell(row, name)) == CELL_MEMBERS, (row["id"], name)


def test_row_members_from_the_profile_and_the_deployable_record():
    """Section 3.2: kind, owningService (21 strings, 9 nulls), owner with rNumber (12 nulls), implementation."""
    record = _record()
    modules = _modules()
    facts = _facts()
    placement = _json(PLACEMENT)
    numbers = {entry["name"]: entry["rNumber"] for entry in placement["repositories"]}
    services = []
    for row in record["rows"]:
        if row["id"] in modules:
            module = modules[row["id"]]
            readiness = module["readiness"]
            service = readiness["serviceId"] if readiness["source"] == "SERVICES" else None
            services.append(service)
            implementation = module.get("implementation")
            if implementation is not None:
                implementation = {
                    "packetId": implementation["packetId"],
                    "deliverableIndex": implementation["deliverableIndex"],
                }
            owner = {
                "type": module["owner"]["type"],
                "name": module["owner"]["name"],
                "rNumber": numbers.get(module["owner"]["name"]),
            }
            # CONTRACT_289 section 3.2 (the module's kind)
            assert row["kind"] == module["kind"], row["id"]
            # CONTRACT_289 section 3.2 (readiness.serviceId when readiness.source is SERVICES, else null)
            assert row["owningService"] == service, row["id"]
            # CONTRACT_289 section 3.2 (the profile's owner; rNumber from the deployable record by name)
            assert row["owner"] == owner, row["id"]
            # CONTRACT_289 section 3.2 (the profile's {packetId, deliverableIndex} or null)
            assert row["implementation"] == implementation, row["id"]
        else:
            fact = facts[row["id"]]
            # CONTRACT_289 section 3.2 (EXTERNAL for a tenant fact)
            assert row["kind"] == "EXTERNAL", row["id"]
            # CONTRACT_289 section 3.2 (null on tenant facts)
            assert row["owningService"] is None, row["id"]
            # CONTRACT_289 section 3.2 (the fact's supplier.type and supplier.name)
            assert row["owner"] == {
                "type": fact["supplier"]["type"], "name": fact["supplier"]["name"], "rNumber": None,
            }, row["id"]
            # CONTRACT_289 section 3.2 (tenant facts have no implementation and no deployables)
            assert row["implementation"] is None and row["deployables"] == [], row["id"]
        if row["owner"]["rNumber"] is not None:
            # CONTRACT_289 section 3.2 (pattern R[0-9]{2})
            assert re.fullmatch(r"R[0-9]{2}", row["owner"]["rNumber"]), row["id"]
    strings = sum(1 for service in services if isinstance(service, str))
    # CONTRACT_289 section 3.2 (21 strings, 9 nulls on module rows)
    assert (strings, services.count(None)) == (21, 9)
    nulls = {row["id"] for row in record["rows"] if row["owner"]["rNumber"] is None}
    # CONTRACT_289 section 3.2 (rNumber null exactly when type is TENANT_SUPPLIED_EXTERNAL)
    assert nulls == {row["id"] for row in record["rows"] if row["owner"]["type"] == TENANT_SUPPLIED}
    # CONTRACT_289 section 3.2 (the 11 tenant facts and the one module)
    assert len(nulls) == 12 and KUBERNETES_UPSTREAM in nulls


def test_deployables_join():
    """Section 3.2 (MET008-C1-5): ENTRY, OUTSIDE_CATALOGUE or ABSENT; 20, 1 and 11 over 32 deployables."""
    record = _record()
    modules = _modules()
    placement = _json(PLACEMENT)
    entries = {entry["id"]: entry for entry in placement["deployables"]}
    outside = {entry["id"]: entry for entry in placement["outsideCatalogue"]}
    # CONTRACT_289 section 3.2 (28 entries and 5 outside-catalogue entries)
    assert (len(entries), len(outside)) == (28, 5)
    # CONTRACT_289 section 3.2 (two disjoint lists)
    assert not set(entries) & set(outside)
    kinds = collections.Counter()
    outside_seen = []
    for row in _module_rows(record):
        expected = []
        for deployable in modules[row["id"]]["deployables"]:
            name = deployable["name"]
            if name in entries:
                joined = ("ENTRY", entries[name]["plannedLanguage"], entries[name]["status"])
            elif name in outside:
                joined = ("OUTSIDE_CATALOGUE", outside[name]["plannedLanguage"], None)
                outside_seen.append((name, outside[name]["plannedLanguage"]))
            else:
                joined = ("ABSENT", None, None)
            kinds[joined[0]] += 1
            expected.append({
                "name": name,
                "type": deployable["type"],
                "deployableRecord": joined[0],
                "plannedLanguage": joined[1],
                "status": joined[2],
            })
        # CONTRACT_289 section 3.2 (one entry per profile deployable, in order)
        assert row["deployables"] == expected, row["id"]
    # CONTRACT_289 section 3.2 (20 ENTRY, 11 ABSENT, 1 OUTSIDE_CATALOGUE)
    assert dict(kinds) == {"ENTRY": 20, "ABSENT": 11, "OUTSIDE_CATALOGUE": 1}
    # CONTRACT_289 section 3.2 (reference-channel-ui, TYPESCRIPT)
    assert outside_seen == [("reference-channel-ui", "TYPESCRIPT")]


def test_premises_of_the_state_rule_hold_at_289():
    """Section 3.3: the lock is inert, every exitEvidence.at is CONF-A2-001, all 11 facts SIGNED_ENVIRONMENT_FACT."""
    profile = _json(PROFILE)
    # CONTRACT_289 section 3.3 (clause 2a: the lock's documentKind)
    assert _json(LOCK)["documentKind"] == "INERT_LOCK"
    # CONTRACT_289 section 3.3 (CONF-A2-001 is every module's exitEvidence.at)
    assert {module["exitEvidence"]["at"] for module in profile["modules"]} == {"CONF-A2-001"}
    # CONTRACT_289 section 3.3 (clause 2b: all 11 at 289)
    assert [fact["attestation"]["requirement"] for fact in profile["tenantFacts"]] == ["SIGNED_ENVIRONMENT_FACT"] * 11
    # CONTRACT_289 section 3.3 (6 GROUNDING_EVALUATION rows of 30 modules; 24 without)
    assert (len(_grounded_ids()), len(profile["modules"])) == (6, 30)


@pytest.mark.parametrize("name", CELL_NAMES)
def test_module_row_cells(name):
    """Section 3.3's module table: each module row's cell for one column or domain."""
    record = _record()
    modules = _modules()
    rows = _module_rows(record)
    # CONTRACT_289 section 3.2 (30 module rows)
    assert len(rows) == 30
    for row in rows:
        expected = _module_cells(row["id"], modules[row["id"]])[name]
        # CONTRACT_289 section 3.3 (the module rows' table)
        assert _mismatches(_cell(row, name), expected) == [], (row["id"], name)


@pytest.mark.parametrize("name", CELL_NAMES)
def test_tenant_fact_cells(name):
    """Section 3.3's TENANT_FACT rows: 10 BLOCKED cells (clause 2b) and 4 NOT_SELECTED cells (branch 1)."""
    record = _record()
    facts = _facts()
    rows = _fact_rows(record)
    # CONTRACT_289 section 3.2 (11 tenant-fact rows)
    assert len(rows) == 11
    for row in rows:
        expected = _fact_cell(row["id"], facts[row["id"]], name)
        # CONTRACT_289 section 3.3 (TENANT_FACT rows)
        assert _mismatches(_cell(row, name), expected) == [], (row["id"], name)


def test_exclusion_rows():
    """Section 3.4: the nine rows in order, repository from the deployable record, artifact, side, rider, source."""
    record = _record()
    placement = _json(PLACEMENT)
    repositories = {entry["id"]: entry for entry in placement["repositories"]}
    rows = record["exclusionRows"]
    # CONTRACT_289 section 3.4 (the deployable record's 13 repository ids)
    assert len(placement["repositories"]) == 13
    # CONTRACT_289 section 3.4 (the nine ids in order)
    assert [row["id"] for row in rows] == [ident for ident, _artifact in EXCLUSIONS]
    for row, (ident, artifact) in zip(rows, EXCLUSIONS):
        registry = ident.split(".", 1)[0]
        entry = repositories[registry]
        # CONTRACT_289 section 3.4 (the id grammar)
        assert re.fullmatch(EXCLUSION_ID, row["id"]), ident
        # CONTRACT_289 section 3.4 (the repository)
        assert row["repository"] == EXCLUSION_REPOSITORIES[registry], ident
        # CONTRACT_289 section 3.4 (copied from basis.deployableRecord's repositories[] entry)
        assert row["repository"] == {"id": entry["id"], "name": entry["name"], "rNumber": entry["rNumber"]}, ident
        # CONTRACT_289 section 3.4 (the artifact)
        assert row["artifact"] == artifact, ident
        # CONTRACT_289 section 3.4 (side PRODUCER)
        assert row["side"] == "PRODUCER", ident
        # CONTRACT_289 section 3.4 (the rider constant)
        assert row["rider"] == RIDERS[registry], ident
        # CONTRACT_289 section 3.4 (the source, in member order)
        assert row["source"] == SOURCES[registry] and list(row["source"]) == list(SOURCES[registry]), ident
    node_ids = set(_json(PROFILE)["closure"]["nodes"])
    # CONTRACT_289 section 3.4 (the rows name artifacts, never a closure node)
    assert not node_ids & {row["id"] for row in rows}


@pytest.mark.parametrize("index", range(9))
def test_exclusion_row_cells(index):
    """Section 3.4's cells: 7 BLOCKED and 7 NOT_SELECTED per producer row; row 7 has 14 NOT_SELECTED."""
    row = _record()["exclusionRows"][index]
    ident = EXCLUSIONS[index][0]
    # CONTRACT_289 section 3.4 (the row at this position)
    assert row["id"] == ident
    for name in CELL_NAMES:
        # CONTRACT_289 section 3.4 (the exclusion rows' cells)
        assert _mismatches(_cell(row, name), _exclusion_cell(ident, name)) == [], (ident, name)
    states = collections.Counter(_cell(row, name)["state"] for name in CELL_NAMES)
    expected = {"NOT_SELECTED": 14} if ident == SCOPE_ROW else {"BLOCKED": 7, "NOT_SELECTED": 7}
    # CONTRACT_289 section 3.4
    assert dict(states) == expected


def test_states_follow_the_three_branch_rule():
    """Section 3.3: every cell's state equals the three-branch rule over the class table, lock, profile, statuses."""
    record = _record()
    modules = _modules()
    facts = _facts()
    lock_kind = _json(LOCK)["documentKind"]
    statuses = record["producerStatus"]["statuses"]
    wrong = []
    for row in record["rows"]:
        if row["id"] in modules:
            module = modules[row["id"]]
            kind = "module"
            row_facts = {"grounded": row["id"] in _grounded_ids(), "exitAt": module["exitEvidence"]["at"]}
        else:
            kind = "tenant"
            row_facts = {"requirement": facts[row["id"]]["attestation"]["requirement"]}
        for name in CELL_NAMES:
            if _cell(row, name)["state"] != _rule(kind, name, row_facts, lock_kind, statuses):
                wrong.append((row["id"], name))
    for row in record["exclusionRows"]:
        kind = "scope" if row["id"] == SCOPE_ROW else "artifact"
        row_facts = {"statusKey": ARTIFACT_STATUS_KEYS[row["id"].split(".", 1)[0]]}
        for name in CELL_NAMES:
            if _cell(row, name)["state"] != _rule(kind, name, row_facts, lock_kind, statuses):
                wrong.append((row["id"], name))
    # CONTRACT_289 section 3.3 (the state rule, the class table and the consulted producers)
    assert wrong == []


def test_counts():
    """Sections 3.1 and 3.3: counts' members, 41 and 9 rows, cellsByState as recounted, per row class."""
    record = _record()
    counts = record["counts"]

    def tally(rows):
        found = collections.Counter()
        for row in rows:
            for name in CELL_NAMES:
                found[_cell(row, name)["state"]] += 1
        return found

    every = tally(record["rows"] + record["exclusionRows"])
    # CONTRACT_289 section 3.1
    assert list(counts) == ["rows", "exclusionRows", "cellsByState"]
    # CONTRACT_289 section 3.1 (41 closure rows)
    assert counts["rows"] == len(record["rows"]) == 41
    # CONTRACT_289 section 3.1 (9 exclusion rows)
    assert counts["exclusionRows"] == len(record["exclusionRows"]) == 9
    # CONTRACT_289 section 3.1 (the five states in states order)
    assert list(counts["cellsByState"]) == STATES
    # CONTRACT_289 section 3.1 (each the number of cells in that state)
    assert counts["cellsByState"] == {state: every.get(state, 0) for state in STATES}
    # CONTRACT_289 section 3.3 (90 NOT_RUN, 138 NOT_SELECTED, 472 BLOCKED, 0 FAILED, 0 QUALIFIED)
    assert counts["cellsByState"] == {"NOT_RUN": 90, "NOT_SELECTED": 138, "BLOCKED": 472, "FAILED": 0, "QUALIFIED": 0}
    # CONTRACT_289 section 3.1 (50 rows x 14 cells = 700)
    assert sum(every.values()) == 700
    # CONTRACT_289 section 3.3 (module rows: 90 NOT_RUN, 24 NOT_SELECTED, 306 BLOCKED)
    assert dict(tally(_module_rows(record))) == {"NOT_RUN": 90, "NOT_SELECTED": 24, "BLOCKED": 306}
    # CONTRACT_289 section 3.3 (tenant-fact rows: 44 NOT_SELECTED, 110 BLOCKED)
    assert dict(tally(_fact_rows(record))) == {"NOT_SELECTED": 44, "BLOCKED": 110}
    # CONTRACT_289 section 3.3 (exclusion rows: 70 NOT_SELECTED, 56 BLOCKED)
    assert dict(tally(record["exclusionRows"])) == {"NOT_SELECTED": 70, "BLOCKED": 56}


def test_references_resolve_and_count():
    """Section 3.3 (MET008-C1-2): the reference grammar, own-row fragments, and the reference counts."""
    record = _record()
    tally = collections.Counter()
    for row in record["rows"] + record["exclusionRows"]:
        for name in CELL_NAMES:
            reference = _cell(row, name)["reference"]
            if reference is None:
                tally["null"] += 1
            elif reference == LOCK:
                tally["lock"] += 1
            elif reference.startswith(PROFILE_REF):
                # CONTRACT_289 section 3.3 (a fragment names only the cell's own row)
                assert reference == PROFILE_REF + row["id"], (row["id"], name)
                tally["profile"] += 1
            else:
                # CONTRACT_289 section 3.3 (the packet form)
                assert re.fullmatch(PACKET_REF, reference), (row["id"], name)
                tally[reference] += 1
    # CONTRACT_289 section 3.3 (116 lock, 134 profile, 186 / 30 / 30 packet references, 204 null)
    assert dict(tally) == {
        "lock": 116,
        "profile": 134,
        "packet:CONF-A2-001": 186,
        "packet:CONF-LINUX-001": 30,
        "packet:CONF-WG-001": 30,
        "null": 204,
    }
    for path in PACKET_YAMLS:
        # CONTRACT_289 section 3.3 (at 289 three packet references resolve)
        assert (ROOT / path).is_file(), path


def test_cell_forms():
    """Section 3.3: no QUALIFIED or FAILED cell, the NOT_SELECTED pairing, owner, date, nextAction forms."""
    record = _record()
    as_of = record["producerStatus"]["asOf"]
    for row in record["rows"] + record["exclusionRows"]:
        for name in CELL_NAMES:
            cell = _cell(row, name)
            where = (row["id"], name)
            not_selected = cell["state"] == "NOT_SELECTED"
            # CONTRACT_289 section 3.3 (the grammar has no evidence-record form: no QUALIFIED or FAILED at 289)
            assert cell["state"] in ("NOT_RUN", "NOT_SELECTED", "BLOCKED"), where
            # CONTRACT_289 section 3.3 (producer null exactly when NOT_SELECTED)
            assert (cell["producer"] is None) == not_selected, where
            # CONTRACT_289 section 3.3 (requiredSource null exactly when NOT_SELECTED)
            assert (cell["requiredSource"] is None) == not_selected, where
            # CONTRACT_289 section 3.3 (owner: R[0-9]{2} or TENANT)
            assert re.fullmatch(r"R[0-9]{2}|TENANT", cell["owner"]), where
            # CONTRACT_289 section 3.3 (the same date in every cell, equal to asOf)
            assert cell["date"] == as_of == DATE, where
            # CONTRACT_289 section 3.3 (a non-empty nextAction)
            assert isinstance(cell["nextAction"], str) and cell["nextAction"], where
            if not_selected:
                # CONTRACT_289 section 3.3 (for NOT_SELECTED it starts "none: ")
                assert cell["nextAction"].startswith("none: "), where


def test_tenant_and_customer_acceptance():
    """Section 3.3 (Q2 (a), MET008-C2-6): module rows share no producer or reference; tenant facts share both."""
    record = _record()
    for row in _module_rows(record):
        tenant = _cell(row, "tenantAcceptance")
        customer = _cell(row, "customerAcceptance")
        # CONTRACT_289 section 3.3 (module rows: no shared non-null producer)
        assert tenant["producer"] is None or tenant["producer"] != customer["producer"], row["id"]
        # CONTRACT_289 section 3.3 (module rows: no shared non-null reference)
        assert tenant["reference"] is None or tenant["reference"] != customer["reference"], row["id"]
    for row in _fact_rows(record):
        tenant = _cell(row, "tenantAcceptance")
        customer = _cell(row, "customerAcceptance")
        # CONTRACT_289 section 3.3 (TENANT_FACT rows share the tenant producer and the own-row reference)
        assert (tenant["producer"], tenant["reference"]) == (customer["producer"], customer["reference"]), row["id"]


def _is_type(value, name):
    return {
        "object": isinstance(value, dict),
        "array": isinstance(value, list),
        "string": isinstance(value, str),
        "null": value is None,
        "boolean": isinstance(value, bool),
        "integer": isinstance(value, int) and not isinstance(value, bool),
        "number": isinstance(value, (int, float)) and not isinstance(value, bool),
    }[name]


def _schema_errors(instance, node, root, where="$"):
    """A small JSON Schema reader for the keywords this schema uses (standard library only)."""
    errors = []
    if node is True or node == {}:
        return errors
    if "$ref" in node:
        target = root
        for part in node["$ref"].lstrip("#/").split("/"):
            target = target[part]
        errors.extend(_schema_errors(instance, target, root, where))
    if "type" in node:
        names = node["type"] if isinstance(node["type"], list) else [node["type"]]
        if not any(_is_type(instance, name) for name in names):
            return errors + [where + ": type"]
    if "const" in node and instance != node["const"]:
        errors.append(where + ": const")
    if "enum" in node and instance not in node["enum"]:
        errors.append(where + ": enum")
    if isinstance(instance, str) and "pattern" in node and not re.search(node["pattern"], instance):
        errors.append(where + ": pattern")
    if isinstance(instance, str) and "minLength" in node and len(instance) < node["minLength"]:
        errors.append(where + ": minLength")
    if _is_type(instance, "number") and "minimum" in node and instance < node["minimum"]:
        errors.append(where + ": minimum")
    if "oneOf" in node:
        passing = sum(1 for sub in node["oneOf"] if not _schema_errors(instance, sub, root, where))
        if passing != 1:
            errors.append(where + ": oneOf")
    if isinstance(instance, dict):
        properties = node.get("properties", {})
        for key in node.get("required", []):
            if key not in instance:
                errors.append("%s: required %s" % (where, key))
        for key, value in instance.items():
            if "propertyNames" in node:
                errors.extend(_schema_errors(key, node["propertyNames"], root, where + ": name"))
            if key in properties:
                errors.extend(_schema_errors(value, properties[key], root, where + "." + key))
            else:
                extra = node.get("additionalProperties", True)
                if extra is False:
                    errors.append("%s: additional %s" % (where, key))
                elif isinstance(extra, dict):
                    errors.extend(_schema_errors(value, extra, root, where + "." + key))
    if isinstance(instance, list) and "items" in node:
        for index, item in enumerate(instance):
            errors.extend(_schema_errors(item, node["items"], root, "%s[%d]" % (where, index)))
    return errors


def test_schema_is_closed_and_holds_the_constants():
    """Section 4: Draft 2020-12, closed at every level, the const arrays, the enums and the reference patterns."""
    schema = _json(SCHEMA)
    nodes = [node for node in _walk(schema) if isinstance(node, dict)]
    # CONTRACT_289 section 4 (Draft 2020-12)
    assert "2020-12" in schema["$schema"]
    for node in nodes:
        if "properties" in node:
            # CONTRACT_289 section 4 (additionalProperties false, every member required)
            assert node.get("additionalProperties") is False, sorted(node["properties"])
            # CONTRACT_289 section 4 (every member required)
            assert sorted(node.get("required", [])) == sorted(node["properties"])
    consts = [node["const"] for node in nodes if isinstance(node.get("const"), list)]
    enums = [sorted(node["enum"]) for node in nodes if isinstance(node.get("enum"), list)]
    patterns = [node["pattern"] for node in nodes if isinstance(node.get("pattern"), str)]
    required = [sorted(node["required"]) for node in nodes if isinstance(node.get("required"), list)]
    # CONTRACT_289 section 4 (the states, columns and claimDomains as const arrays)
    assert STATES in consts and COLUMNS in consts and DOMAINS in consts
    # CONTRACT_289 section 4 (the state enum)
    assert sorted(STATES) in enums
    # CONTRACT_289 section 4 (statuses values are roadmap statuses)
    assert sorted(ROADMAP_STATUSES) in enums
    # CONTRACT_289 section 4 (cells: exactly the eight column names; claimDomains: exactly the six)
    assert sorted(COLUMNS) in required and sorted(DOMAINS) in required
    # CONTRACT_289 section 4 (the profile pattern)
    assert any("architecture/release-profile\\.json#[a-z0-9][a-z0-9.-]*" in pattern for pattern in patterns)
    # CONTRACT_289 section 4 (the packet pattern)
    assert any("packet:" in pattern and "[A-Z][A-Z0-9]*(-[A-Z0-9]+)+" in pattern for pattern in patterns)
    # CONTRACT_289 section 4 (statuses keys: a packet id or the one constant human-probes item)
    assert any("human-probes item" in pattern for pattern in patterns)
    # CONTRACT_289 section 4 (the reference: null or a oneOf with the lock constant)
    assert any(
        {"const": LOCK} in node["oneOf"] for node in nodes if isinstance(node.get("oneOf"), list)
    )


def test_record_conforms_to_its_schema():
    """Section 4: the live record meets its closed schema."""
    schema = _json(SCHEMA)
    # CONTRACT_289 section 4
    assert _schema_errors(_record(), schema, schema) == []


SCHEMA_REJECTS = [
    pytest.param(_set_path(["notes"], "extra"), id="extra-member"),
    pytest.param(_set_cell(_first_module, "deploymentProfile", "state", "DONE"), id="state-enum"),
    pytest.param(_set_cell(_first_module, "deploymentProfile", "owner", "R1"), id="cell-owner-pattern"),
    pytest.param(_set_cell(_first_module, "sourceCommit", "reference", LOCK + "#sourceCommit"), id="lock-fragment"),
    pytest.param(_set_path(["exclusionRows", 0, "side"], "CONSUMER"), id="exclusion-side"),
    pytest.param(_set_path(["exclusionRows", 0, "id"], "distribution.Bundle"), id="exclusion-id"),
]


@pytest.mark.parametrize("mutate", SCHEMA_REJECTS)
def test_schema_rejects_a_changed_record(mutate):
    """Section 4: closed members, the state enum and the patterns of the reference, owner, side and exclusion id."""
    schema = _json(SCHEMA)
    record = _record()
    mutate(record)
    # CONTRACT_289 section 4
    assert _schema_errors(record, schema, schema) != []


# ==============================================================================================================
# 2. The projection (section 5)
# ==============================================================================================================


def test_projection_reproduces_the_record():
    """Section 5: serialize(project(disk_reader(ROOT))) equals the record's bytes."""
    raw = _disk(RECORD)
    projected = projection().project(checker().disk_reader(ROOT))
    # CONTRACT_289 section 5 (project returns the record)
    assert projected == json.loads(raw)
    # CONTRACT_289 section 5 (canonical bytes)
    assert projection().serialize(projected) == raw


def test_the_record_is_in_canonical_form():
    """Section 5: json.dumps(..., indent=2, ensure_ascii=False) plus a newline, UTF-8."""
    raw = _disk(RECORD)
    record = json.loads(raw)
    # CONTRACT_289 section 5 (the canonical form)
    assert raw == (json.dumps(record, indent=2, ensure_ascii=False) + "\n").encode("utf-8")
    # CONTRACT_289 section 5 (serialize returns the canonical bytes)
    assert projection().serialize(record) == raw
    record["counts"]["rows"] = 40
    # CONTRACT_289 section 5 (serialize of any record is its canonical form)
    assert projection().serialize(record) == (json.dumps(record, indent=2, ensure_ascii=False) + "\n").encode("utf-8")


def test_projection_reads_only_the_three_basis_files():
    """Section 5: project reads only the three basis files through its injected reader; it never probes."""
    served = {path: _disk(path) for path in BASIS_PATHS}
    asked = []

    def read(path):
        asked.append(str(path))
        if str(path) not in served:
            raise FileNotFoundError(str(path))
        return served[str(path)]

    record = projection().project(read)
    # CONTRACT_289 section 5 (only the three basis files)
    assert set(asked) <= set(BASIS_PATHS)
    # CONTRACT_289 section 5 (the record, from those bytes alone)
    assert projection().serialize(record) == _disk(RECORD)


def test_projection_derives_from_the_served_profile():
    """Sections 3.1 to 3.3: a served profile's supplier name reaches the row and its BLOCKED cells; basis follows."""
    served = _served(PROFILE, lambda data: data["tenantFacts"][0]["supplier"].__setitem__("name", "an oracle supplier"))
    record = projection().project(_reader(served))
    row = _row_by_id(record, _json(PROFILE)["tenantFacts"][0]["id"])
    # CONTRACT_289 section 3.1 (the digest of the bytes the reader gives)
    assert record["basis"]["profile"]["sha256"] == _sha(served[PROFILE])
    # CONTRACT_289 section 3.2 (a tenant fact's owner name is its supplier.name)
    assert row["owner"]["name"] == "an oracle supplier"
    blocked = [_cell(row, name) for name in CELL_NAMES if _cell(row, name)["state"] == "BLOCKED"]
    # CONTRACT_289 section 3.3 (10 BLOCKED cells, producer the fact's supplier.name)
    assert len(blocked) == 10 and all(cell["producer"] == "an oracle supplier" for cell in blocked)


@pytest.mark.parametrize("path, mutate", GUARD_CASES)
def test_projection_raises_on_a_broken_premise(path, mutate):
    """Section 5 (MET008-C2-8): project raises ValueError on a non-inert lock, an exitEvidence.at other than
    CONF-A2-001, or an attestation.requirement other than SIGNED_ENVIRONMENT_FACT."""
    read = _reader(_served(path, mutate))
    # CONTRACT_289 section 5 (project raises ValueError)
    with pytest.raises(ValueError):
        projection().project(read)


# ==============================================================================================================
# 3. The checker's codes (section 5)
# ==============================================================================================================


def test_codes_constant():
    """Section 5: CODES holds the eight codes, in section 5's order when it is ordered."""
    codes = checker().CODES
    # CONTRACT_289 section 5 (the eight codes)
    assert set(codes) == set(ORDER) and len(list(codes)) == 8
    if isinstance(codes, (list, tuple, dict)):
        # CONTRACT_289 section 5 (in this order)
        assert list(codes) == ORDER


def test_re_profile_passes_on_the_live_tree():
    """Section 5 (RE_PROFILE): the registered checker runs over the live tree, which passes."""
    result = checker().validate(_record(), checker().disk_reader(ROOT))
    # CONTRACT_289 section 5 (RE_PROFILE)
    assert "RE_PROFILE" not in result


SHAPE_CASES = [
    pytest.param(_set_path(["producerStatus", "statuses", "oracle key"], "READY"), id="statuses-key-other"),
    pytest.param(_set_path(["producerStatus", "statuses", "cap-catalog-002"], "READY"), id="statuses-key-lowercase"),
    pytest.param(_set_path(["producerStatus", "statuses", "CAP-CATALOG-001"], "UNKNOWN"), id="statuses-value"),
    pytest.param(_drop_path(["counts"]), id="member-missing"),
    pytest.param(_set_path(["notes"], "extra"), id="member-extra"),
    pytest.param(_swap_in(lambda record: record, "basis", "producerStatus"), id="member-order"),
    pytest.param(_set_path(["schemaVersion"], "harness.planeon.ai/release-evidence/v2"), id="schema-version"),
    pytest.param(_set_path(["states"], [STATES[1], STATES[0]] + STATES[2:]), id="states-order"),
    pytest.param(_set_path(["columns"], COLUMNS[:-1]), id="columns-short"),
    pytest.param(_set_path(["claimDomains"], DOMAINS + ["auditTrail"]), id="claim-domains-extra"),
    pytest.param(_drop_cell(_first_module, "executionMode"), id="cells-missing-column"),
    pytest.param(_extra_domain_cell, id="claim-domains-extra-cell"),
    pytest.param(_set_cell(_first_module, "deploymentProfile", "evidence", "x"), id="cell-extra-member"),
    pytest.param(_set_cell(_first_module, "deploymentProfile", "state", "DONE"), id="cell-state-enum"),
    pytest.param(_set_cell(_first_module, "deploymentProfile", "producer", 7), id="cell-producer-type"),
    pytest.param(_set_row(_first_module, "nodeClass", "MODULE"), id="node-class-enum"),
    pytest.param(_owner_rnumber, id="owner-rnumber-pattern"),
    pytest.param(_set_path(["producerStatus", "source", "commit"], "1cc8073d"), id="source-commit-form"),
    pytest.param(_set_path(["producerStatus", "source", "repository"], "another-roadmap"), id="source-repository"),
    pytest.param(_set_path(["producerStatus", "asOf"], "14-11-2026"), id="as-of-form"),
    pytest.param(_drop_path(["counts", "cellsByState"]), id="counts-member"),
    pytest.param(_set_path(["counts", "rows"], "41"), id="counts-type"),
    pytest.param(_rows_as_object, id="rows-type"),
    pytest.param(_extra_deployable_member, id="deployable-extra-member"),
    pytest.param(_drop_path(["exclusionRows", 0, "source", "path"]), id="exclusion-source-member"),
    pytest.param(_set_path(["exclusionRows", 0, "source", "mainPin"], 12345678), id="exclusion-main-pin-type"),
    pytest.param(_swap_in(_first_module, "nodeClass", "kind"), id="row-member-order"),
    pytest.param(_swap_in(lambda record: _first_module(record)["cells"], "sourceCommit", "artifactDigest"),
                 id="cells-order"),
    pytest.param(_swap_in(lambda record: record["counts"]["cellsByState"], "NOT_RUN", "NOT_SELECTED"),
                 id="cells-by-state-order"),
]


@pytest.mark.parametrize("mutate", SHAPE_CASES)
def test_re_shape(mutate):
    """Section 5 (RE_SHAPE, MET008-C2-1 form (a)): a shape refusal returns ["RE_SHAPE"] alone."""
    record = _record()
    mutate(record)
    # CONTRACT_289 section 5 (RE_SHAPE alone)
    assert _validate(record) == ["RE_SHAPE"]


def test_re_shape_for_a_record_that_is_not_an_object():
    """Section 5 (RE_SHAPE): the JSON types at every level, the top level included."""
    # CONTRACT_289 section 5 (RE_SHAPE alone)
    assert _validate([_record()]) == ["RE_SHAPE"]


def test_a_shape_refusal_stands_alone():
    """Section 5: when RE_SHAPE applies, the list is ["RE_SHAPE"] alone, whatever else is wrong."""
    record = _record()
    record["basis"]["profile"]["sha256"] = "0" * 64
    _swap_list("rows", 0, 1)(record)
    _set_cell(_first_module, "deploymentProfile", "state", "QUALIFIED")(record)
    record["exclusionRows"][0]["side"] = "CONSUMER"
    record["notes"] = "extra"
    # CONTRACT_289 section 5 (RE_SHAPE alone)
    assert _validate(record) == ["RE_SHAPE"]


BASIS_CASES = [
    pytest.param(_set_path(["basis", "profile", "sha256"], "0" * 64), None, id="profile-digest"),
    pytest.param(_set_path(["basis", "deployableRecord", "sha256"], "f" * 64), None, id="deployable-record-digest"),
    pytest.param(_set_path(["basis", "releaseLock", "sha256"], "a" * 64), None, id="lock-digest"),
    pytest.param(_set_path(["basis", "profile", "id"], "profile.other-amd64"), None, id="profile-id"),
    pytest.param(_set_path(["basis", "deployableRecord", "path"], CATALOG_PATH), None, id="catalog-path"),
    pytest.param(_set_path(["basis", "releaseLock", "path"], RECORD), None, id="lock-path"),
    pytest.param(None, LOCK, id="served-lock-bytes"),
    pytest.param(None, PLACEMENT, id="served-deployable-record-bytes"),
]


@pytest.mark.parametrize("mutate, served_path", BASIS_CASES)
def test_re_basis(mutate, served_path):
    """Section 5 (RE_BASIS): three pins at the named paths, each digest the reader's bytes, the profile id."""
    record = _record()
    if mutate is not None:
        mutate(record)
    served = {served_path: _disk(served_path) + b"\n"} if served_path else None
    result = _validate(record, served)
    # CONTRACT_289 section 5 (RE_BASIS)
    assert "RE_BASIS" in result, result
    # CONTRACT_289 section 5 (RE_PROJECTION: the record's bytes no longer equal the projection's)
    assert "RE_PROJECTION" in result, result


def test_a_fourth_basis_pin_is_refused():
    """Section 5 (RE_BASIS: a catalog path or any fourth pin refuses; the closed member set is RE_SHAPE's)."""
    record = _record()
    record["basis"]["catalog"] = {"path": CATALOG_PATH, "sha256": "0" * 64}
    result = _validate(record)
    # CONTRACT_289 section 5 (refused: RE_SHAPE alone for the closed member set, or RE_BASIS)
    assert result == ["RE_SHAPE"] or "RE_BASIS" in result, result


CLOSURE_CASES = [
    pytest.param(_swap_list("rows", 0, 1), id="rows-swapped"),
    pytest.param(_reverse_list("rows"), id="rows-reversed"),
    pytest.param(_pop_list("rows", -1), id="row-missing"),
    pytest.param(_duplicate_last_row, id="row-duplicated"),
    pytest.param(_flip_module_class, id="module-node-class"),
    pytest.param(_fact_as_closure, id="tenant-fact-node-class"),
    pytest.param(_rename_module, id="row-renamed"),
]


@pytest.mark.parametrize("mutate", CLOSURE_CASES)
def test_re_closure(mutate):
    """Section 5 (RE_CLOSURE): the 41 ids in closure.nodes order, module classes, tenant facts as TENANT_FACT."""
    record = _record()
    mutate(record)
    result = _validate(record)
    # CONTRACT_289 section 5 (RE_CLOSURE)
    assert "RE_CLOSURE" in result, result
    # CONTRACT_289 section 5 (RE_PROJECTION)
    assert "RE_PROJECTION" in result, result


PROJECTION_ONLY = [
    pytest.param(_set_row(_first_module, "kind", "ORACLE_KIND"), id="row-kind"),
    pytest.param(_set_path(["counts", "cellsByState", "NOT_RUN"], 91), id="counts-value"),
    pytest.param(_set_path(["producerStatus", "source", "sha256"], "a" * 64), id="source-digest"),
    pytest.param(_set_path(["producerStatus", "source", "commit"], "b" * 40), id="source-commit"),
    pytest.param(_set_path(["exclusionRows", 0, "artifact"], "an oracle artifact"), id="exclusion-artifact"),
    pytest.param(_set_path(["exclusionRows", 0, "source", "note"], "an oracle note"), id="exclusion-note"),
    pytest.param(_set_cell(_first_module, "deploymentProfile", "nextAction", "an oracle next action"),
                 id="cell-next-action"),
    pytest.param(_set_cell(_first_module, "runtimeCampaign", "requiredSource", "an oracle required source"),
                 id="cell-required-source"),
]


@pytest.mark.parametrize("mutate", PROJECTION_ONLY)
def test_re_projection_alone(mutate):
    """Section 5 (RE_PROJECTION): a change that no other code checks is refused by RE_PROJECTION alone."""
    record = _record()
    mutate(record)
    # CONTRACT_289 section 5 (RE_PROJECTION; RE_SHAPE checks types only, the other codes do not read these values)
    assert _validate(record) == ["RE_PROJECTION"]


@pytest.mark.parametrize("path, mutate", GUARD_CASES)
def test_re_projection_on_a_broken_premise(path, mutate):
    """Sections 3.3 and 5: an exception from project refuses RE_PROJECTION."""
    result = _validate(_record(), _served(path, mutate))
    # CONTRACT_289 section 5 (RE_PROJECTION)
    assert "RE_PROJECTION" in result, result


CELLS_CASES = [
    pytest.param(_set_cell(_first_module, "deploymentProfile", "reference", "architecture/repositories.yaml"),
                 id="reference-outside-basis"),
    pytest.param(_set_cell(_first_module, "sourceCommit", "reference", LOCK + "#sourceCommit"), id="lock-fragment"),
    pytest.param(_other_row_fragment, id="fragment-names-another-row"),
    pytest.param(_set_cell(_first_module, "customerAcceptance", "reference", "packet:UAT-CAMPAIGN-001"),
                 id="unknown-packet-uat"),
    pytest.param(_set_cell(_first_module, "executionMode", "reference", "packet:CAP-CATALOG-001"),
                 id="unknown-packet-cap"),
    pytest.param(_set_cell(_first_module, "deploymentProfile", "reference", "packet:conf-a2-001"),
                 id="malformed-packet-lowercase"),
    pytest.param(_set_cell(_first_module, "deploymentProfile", "reference", "packet:CONFA2001"),
                 id="malformed-packet-no-hyphen"),
    pytest.param(_set_cell(_first_module, "deploymentProfile", "state", "QUALIFIED"), id="qualified-cell"),
    pytest.param(_set_cell(_first_module, "containment", "state", "FAILED"), id="failed-cell"),
    pytest.param(_qualified_exclusion_cell, id="qualified-exclusion-cell"),
    pytest.param(_set_path(["producerStatus", "statuses", "CAP-CATALOG-001"], "BLOCKED"), id="status-cap-blocked"),
    pytest.param(_set_path(["producerStatus", "statuses", "CONF-A2-001"], "READY"), id="status-a2-ready"),
    pytest.param(_set_cell(_first_fact, "sourceCommit", "producer", "R00"), id="not-selected-with-producer"),
    pytest.param(_set_cell(_first_module, "deploymentProfile", "producer", None), id="blocked-without-producer"),
    pytest.param(_set_cell(_first_module, "runtimeCampaign", "requiredSource", None),
                 id="blocked-without-required-source"),
    pytest.param(_set_cell(_first_module, "deploymentProfile", "owner", "R1"), id="owner-pattern"),
    pytest.param(_set_cell(_first_module, "deploymentProfile", "date", "2026-11-15"), id="date-not-as-of"),
    pytest.param(_set_cell(_first_module, "deploymentProfile", "date", "2026/11/14"), id="date-form"),
    pytest.param(_set_cell(_first_module, "deploymentProfile", "nextAction", ""), id="empty-next-action"),
    pytest.param(_set_cell(_first_module, "deploymentProfile", "state", "NOT_RUN"), id="state-against-rule"),
    pytest.param(_set_path(["producerStatus", "asOf"], "2026-11-13"), id="as-of-changed"),
    pytest.param(_scope_row_not_run, id="scope-row-state"),
]


@pytest.mark.parametrize("mutate", CELLS_CASES)
def test_re_cells(mutate):
    """Section 5 (RE_CELLS): reference forms and resolution, the pairing, owner, date, nextAction, no QUALIFIED or
    FAILED cell, and each state by the three-branch rule."""
    record = _record()
    mutate(record)
    result = _validate(record)
    # CONTRACT_289 section 5 (RE_CELLS)
    assert "RE_CELLS" in result, result
    # CONTRACT_289 section 5 (RE_PROJECTION)
    assert "RE_PROJECTION" in result, result


DOMAINS_CASES = [
    pytest.param(_share_reference(_first_module), id="shared-reference"),
    pytest.param(_share_producer(_first_module), id="shared-producer"),
    pytest.param(_share_producer(_last_module), id="shared-producer-last-module"),
]


@pytest.mark.parametrize("mutate", DOMAINS_CASES)
def test_re_domains(mutate):
    """Section 5 (RE_DOMAINS): on module rows, tenantAcceptance and customerAcceptance share no non-null producer
    or reference."""
    record = _record()
    mutate(record)
    result = _validate(record)
    # CONTRACT_289 section 5 (RE_DOMAINS)
    assert "RE_DOMAINS" in result, result


EXCLUSION_CASES = [
    pytest.param(_swap_list("exclusionRows", 0, 1), id="first-two-swapped"),
    pytest.param(_swap_list("exclusionRows", 0, 8), id="first-and-last-swapped"),
    pytest.param(_reverse_list("exclusionRows"), id="reversed"),
    pytest.param(_pop_list("exclusionRows", 6), id="row-missing"),
    pytest.param(_set_path(["exclusionRows", 0, "id"], "distribution.Bundle"), id="id-uppercase"),
    pytest.param(_set_path(["exclusionRows", 0, "id"], "distribution.bundle_x"), id="id-underscore"),
    pytest.param(_set_path(["exclusionRows", 0, "id"], "distribution."), id="id-empty-key"),
    pytest.param(_set_path(["exclusionRows", 0, "id"], "packaging.bundle"), id="id-unknown-registry"),
    pytest.param(_set_path(["exclusionRows", 0, "id"], "operator.bundle"), id="id-other-registry"),
    pytest.param(_set_path(["exclusionRows", 0, "repository", "id"], "control-plane"), id="repository-id"),
    pytest.param(_set_path(["exclusionRows", 0, "repository", "name"], "mas-harness-control-plane"),
                 id="repository-name"),
    pytest.param(_set_path(["exclusionRows", 0, "repository", "rNumber"], "R04"), id="repository-rnumber"),
    pytest.param(_duplicate_exclusion_id, id="duplicate-id"),
    pytest.param(_exclusion_names_a_fact, id="id-names-a-tenant-fact"),
    pytest.param(_set_path(["exclusionRows", 0, "side"], "CONSUMER"), id="side"),
    pytest.param(_set_path(["exclusionRows", 0, "rider"], RIDERS["control-plane"]), id="rider-r04-on-r11"),
    pytest.param(_set_path(["exclusionRows", 8, "rider"], RIDERS["distribution"]), id="rider-r11-on-r04"),
    pytest.param(_set_path(["exclusionRows", 0, "source", "registryRow"], "control-plane"), id="source-registry-row"),
    pytest.param(_set_path(["exclusionRows", 0, "source", "mainPin"], "FE49981E"), id="main-pin-uppercase"),
    pytest.param(_set_path(["exclusionRows", 0, "source", "mainPin"], "fe4998"), id="main-pin-short"),
    pytest.param(_set_path(["exclusionRows", 0, "source", "mainPin"], "f" * 41), id="main-pin-long"),
]


@pytest.mark.parametrize("mutate", EXCLUSION_CASES)
def test_re_exclusions(mutate):
    """Section 5 (RE_EXCLUSIONS, MET008-C1-19): the nine ids in order and each refusal section 5 lists."""
    record = _record()
    mutate(record)
    result = _validate(record)
    # CONTRACT_289 section 5 (RE_EXCLUSIONS)
    assert "RE_EXCLUSIONS" in result, result
    # CONTRACT_289 section 5 (RE_PROJECTION)
    assert "RE_PROJECTION" in result, result


def test_codes_come_in_section_5_order():
    """Section 5: every code that applies, each once, in section 5's order (RE_PROFILE passes on the live tree)."""
    record = _record()
    record["basis"]["profile"]["id"] = "profile.other-amd64"
    _swap_list("rows", 0, 1)(record)
    module = _first_module(record)
    _cell(module, "deploymentProfile")["state"] = "QUALIFIED"
    _cell(module, "customerAcceptance")["reference"] = _cell(module, "tenantAcceptance")["reference"]
    record["exclusionRows"][0]["side"] = "CONSUMER"
    # CONTRACT_289 section 5 (the order of the codes)
    assert _validate(record) == ["RE_BASIS", "RE_CLOSURE", "RE_PROJECTION", "RE_CELLS", "RE_DOMAINS", "RE_EXCLUSIONS"]


# ==============================================================================================================
# 4. The head layer (section 6)
# ==============================================================================================================

V1_SUBJECTS = [
    RECORD,
    SCHEMA,
    "scripts/release_evidence.py",
    "scripts/validate_release_evidence.py",
    "tests/test_release_evidence.py",
]  # section 6 (V1: the record, the schema, the projection, the checker and their tests)


def _packet_files():
    return {name: _disk(name) for name in head().PACKET_FILES}


def test_v1_live():
    """Section 6 (V1): validate_packet_files passes; check_packet_files accepts the live bytes of PACKET_FILES."""
    head().validate_packet_files()
    files = _packet_files()
    # CONTRACT_289 section 6 (V1 pins the record, the schema, the projection, the checker and their tests)
    assert set(V1_SUBJECTS) <= {str(name) for name in files}
    # CONTRACT_289 section 6 (V1; operator-stated: a check returns None)
    assert head().check_packet_files(files) is None


@pytest.mark.parametrize("subject", V1_SUBJECTS)
def test_v1_refuses_changed_bytes(subject):
    """Section 6 (V1): a pinned file whose bytes differ from its digest is refused."""
    files = _packet_files()
    key = next(name for name in files if str(name) == subject)
    files[key] = files[key] + b"\n"
    message = _refusal(head().check_packet_files, files)
    # CONTRACT_289 section 6 (operator-stated: the ValueError names MET-008)
    assert "MET-008" in message


def test_e1_live():
    """Section 6 (E1): the era checker accepts the record through the era reader; check_evidence accepts []."""
    head().validate_evidence({})
    _era_projection, era_checker = head()._era_checker()
    record = _record()
    refusals = era_checker.validate(record, head()._era_read)
    # CONTRACT_289 section 6 (E1: the checker, from its era-verified bytes, accepts the record)
    assert refusals == []
    # CONTRACT_289 section 6 (E1; operator-stated: a check returns None)
    assert head().check_evidence(record, refusals) is None


ERA_SUBJECTS = list(BASIS_PATHS) + [RECORD, SCHEMA] + list(PACKET_YAMLS)  # section 6 (the era reader)


@pytest.mark.parametrize("path", ERA_SUBJECTS)
def test_e1_era_reader_binds_its_files(path):
    """Section 6 (the era reader binds the basis files, the record, the schema and the three packet YAMLs)."""
    # CONTRACT_289 section 6 (289 leaves each at the bytes the era reader binds; sections 1 and 6)
    assert head()._era_read(path) == _disk(path)


def test_e1_era_reader_refuses_an_unbound_path():
    """Section 6 (the era reader binds by digest; operator-stated: a path outside ERA_SHA256 raises ValueError)."""
    # CONTRACT_289 section 6 (operator-stated ValueError)
    with pytest.raises(ValueError):
        head()._era_read("architecture/met-008-oracle-absent.json")


E1_CASES = [
    pytest.param(_noop, ["RE_CELLS"], id="checker-refusal"),
    pytest.param(_pop_list("rows", -1), [], id="forty-rows"),
    pytest.param(_set_cell(_first_module, "deploymentProfile", "state", "QUALIFIED"), [], id="qualified-column"),
    pytest.param(_set_cell(_first_module, "containment", "state", "FAILED"), [], id="failed-domain"),
    pytest.param(_set_cell(_first_fact, "tenantAcceptance", "state", "QUALIFIED"), [], id="qualified-tenant-fact"),
]


@pytest.mark.parametrize("mutate, refusals", E1_CASES)
def test_e1_refusals(mutate, refusals):
    """Section 6 (E1) with sections 3.2 and 3.3: a checker refusal, a row count other than 41, or a QUALIFIED or
    FAILED cell is refused."""
    record = _record()
    mutate(record)
    message = _refusal(head().check_evidence, record, list(refusals))
    # CONTRACT_289 section 6 (operator-stated: the ValueError names MET-008)
    assert "MET-008" in message


def test_e1_refuses_through_the_era_checker():
    """Section 6 (E1): a record the era checker refuses fails check_evidence."""
    _era_projection, era_checker = head()._era_checker()
    record = _record()
    record["exclusionRows"][0]["side"] = "CONSUMER"
    refusals = era_checker.validate(record, head()._era_read)
    # CONTRACT_289 section 5 (RE_EXCLUSIONS refuses a side other than PRODUCER)
    assert "RE_EXCLUSIONS" in refusals
    message = _refusal(head().check_evidence, record, refusals)
    # CONTRACT_289 section 6 (operator-stated: the ValueError names MET-008)
    assert "MET-008" in message


def _base_inputs():
    authority = head().authority()
    files = {name: _disk(name) for name in head().BASE_FILES}
    return files, copy.deepcopy(authority["changedFiles"]), copy.deepcopy(authority["newFiles"])


def test_e2_live():
    """Section 6 (E2): release-profile.json at its base bytes; the authority names it nowhere."""
    head().validate_base_files()
    files, changed, new = _base_inputs()
    # CONTRACT_289 section 6 (E2 pins release-profile.json only, MON-289-DRY-RULE D5)
    assert {str(name) for name in files} == {PROFILE}
    # CONTRACT_289 section 6 (this step's authority names it nowhere)
    assert PROFILE not in changed and PROFILE not in new
    # CONTRACT_289 section 6 (E2; operator-stated: a check returns None)
    assert head().check_base_files(files, changed, new) is None


@pytest.mark.parametrize("case", ["bytes", "changed-names-it", "new-names-it"])
def test_e2_refusals(case):
    """Section 6 (E2): changed profile bytes, or an authority that names the profile, is refused."""
    files, changed, new = _base_inputs()
    key = next(name for name in files if str(name) == PROFILE)
    digest = _sha(files[key])
    if case == "bytes":
        files[key] = files[key] + b"\n"
    elif case == "changed-names-it":
        changed[PROFILE] = {"beforeSha256": digest, "afterSha256": digest, "reverseHunks": []}
    else:
        new[PROFILE] = digest
    message = _refusal(head().check_base_files, files, changed, new)
    # CONTRACT_289 section 6 (operator-stated: the ValueError names MET-008)
    assert "MET-008" in message


def _errata_inputs():
    classes = copy.deepcopy(json.loads(_disk(HUNK_RECORD))["classes"])
    changed = copy.deepcopy(head().authority()["changedFiles"])
    befores = {path: head()._undo_this_layer(path, _disk(path)) for path in head().ERRATA_LINES}
    return classes, changed, befores


def test_e3_table():
    """Section 6 (E3's spans, MET008-C1-14): ERRATA_LINES holds the 20 spans over the 7 files."""
    actual = {
        str(path): sorted(tuple(span) for span in spans) for path, spans in head().ERRATA_LINES.items()
    }
    # CONTRACT_289 section 6 (the spans table)
    assert actual == {path: sorted(spans) for path, spans in ERRATA_SPANS.items()}
    # CONTRACT_289 section 6 (20 spans over 7 files)
    assert (sum(len(spans) for spans in actual.values()), len(actual)) == (20, 7)


def test_e3_live():
    """Section 6 (E3) with sections 8.1 and 16: class other only on the seven files; [PC-1] and [E-1] classes."""
    head().validate_errata()
    classes, changed, befores = _errata_inputs()
    # CONTRACT_289 section 6 (E3; operator-stated: a check returns None)
    assert head().check_errata(classes, changed, befores) is None
    with_other = {path for path, kinds in classes.items() if "other" in kinds}
    # CONTRACT_289 section 6 (class-other hunks only on the seven files)
    assert with_other == set(ERRATA_SPANS)
    # CONTRACT_289 section 8.1 (2 canonical reverse hunks, all class other)
    assert classes[PC1_ORACLE] == ["other"] * 2
    # CONTRACT_289 section 8.1 (5 canonical reverse hunks, all class other)
    assert classes[PC1_IDENTITY] == ["other"] * 5
    # CONTRACT_289 section 16 ([E-1]: the two hunks are classed cascade)
    assert classes[CASCADE_FILE] == ["cascade", "cascade"]
    for path, kinds in classes.items():
        # CONTRACT_289 section 6 (operator-stated: one class per reverse hunk)
        assert len(kinds) == len(changed[path]["reverseHunks"]), path


def test_e3_refuses_class_other_outside_the_seven_files():
    """Section 6 (E3): a class-other hunk on a file E3 does not name is refused."""
    classes, changed, befores = _errata_inputs()
    classes[CASCADE_FILE][0] = "other"
    message = _refusal(head().check_errata, classes, changed, befores)
    # CONTRACT_289 section 6 (operator-stated: the ValueError names MET-008)
    assert "MET-008" in message


def _one_line_hunk(before, line_number):
    """A reverse hunk whose insert is exactly base line `line_number` (1-based): its span is (n, n)."""
    lines = before.split(b"\n")
    offset = sum(len(line) + 1 for line in lines[: line_number - 1])
    return {
        "at": offset,
        "removeBase64": _b64(b"# met-008 oracle: a synthetic replacement line\n"),
        "insertBase64": _b64(lines[line_number - 1] + b"\n"),
    }


@pytest.mark.parametrize(
    "line_number, refused",
    [pytest.param(SYNTHETIC_LINE, False, id="inside-span-control"), pytest.param(1, True, id="outside-span")],
)
def test_e3_span_rule(line_number, refused):
    """Section 6 (E3): a class-other hunk must lie inside one of its file's named spans; one outside is refused
    (the hunk inside the file's one span is the construction's control)."""
    classes, changed, befores = _errata_inputs()
    changed[SYNTHETIC_FILE]["reverseHunks"] = [_one_line_hunk(befores[SYNTHETIC_FILE], line_number)]
    classes[SYNTHETIC_FILE] = ["other"]
    if refused:
        message = _refusal(head().check_errata, classes, changed, befores)
        # CONTRACT_289 section 6 (operator-stated: the ValueError names MET-008)
        assert "MET-008" in message
    else:
        # CONTRACT_289 section 6 (a hunk whose base lines lie in one named span passes)
        assert head().check_errata(classes, changed, befores) is None


def _registry_inputs():
    raw = _disk(head().REGISTRY_PATH)
    briefs = {head().PACKET_BRIEF: _disk(head().PACKET_BRIEF)}
    return raw, briefs


def test_v4_live():
    """Section 6 (V4): the registry differs from the base by this packet's one rider."""
    head().validate_registry()
    raw, briefs = _registry_inputs()
    # CONTRACT_289 section 6 (V4; operator-stated: a check returns None)
    assert head().check_registry(raw, briefs) is None


def test_v4_refuses_the_base_registry():
    """Section 6 (V4): the base registry, without the packet's rider, is refused."""
    raw, briefs = _registry_inputs()
    base = head()._undo_this_layer(head().REGISTRY_PATH, raw)
    # CONTRACT_289 section 6 (V4: the registry differs from the base by the rider)
    assert base != raw
    message = _refusal(head().check_registry, base, briefs)
    # CONTRACT_289 section 6 (operator-stated: the ValueError names MET-008)
    assert "MET-008" in message


def test_v4_refuses_a_second_difference():
    """Section 6 (V4): a registry that differs from the base by more than the one rider is refused."""
    raw, briefs = _registry_inputs()
    try:
        data = json.loads(raw)
    except ValueError:
        data = None
    if isinstance(data, dict):
        data["met008OracleExtra"] = "an extra difference"
        mutated = _dump_like(raw, data)
    elif isinstance(data, list):
        data.append({"met008OracleExtra": "an extra difference"})
        mutated = _dump_like(raw, data)
    else:
        mutated = raw + b"met-008 oracle: an extra difference\n"
    message = _refusal(head().check_registry, mutated, briefs)
    # CONTRACT_289 section 6 (operator-stated: the ValueError names MET-008)
    assert "MET-008" in message


@functools.lru_cache(maxsize=None)
def _hunk_inputs():
    """V6's arguments as the operator states them (afters: every changed file with reverse hunks, by the
    authority's own keys)."""
    raw = _disk(head().HUNK_RECORD_PATH)
    authority = head().authority()
    changed = authority["changedFiles"]
    afters = {path: _disk(path) for path, entry in changed.items() if entry["reverseHunks"]}
    classify = head()._era_rule(head().READER_PATH, head().READER_NAME).classify
    record = json.loads(raw)
    stated = record["hunkClassContext"] if "hunkClassContext" in record else head().HUNK_CONTEXT
    context = head()._v24_context(authority, stated)
    return raw, changed, afters, classify, context


def test_v6_live():
    """Section 6 (V6, D8): the hunk-class record under v2.5's classes, steps [1, 1] and countPairs []."""
    head().validate_hunk_record()
    raw, changed, afters, classify, context = _hunk_inputs()
    # CONTRACT_289 section 6 (the hunk-class record's path)
    assert str(head().HUNK_RECORD_PATH) == HUNK_RECORD
    # CONTRACT_289 section 6 (V6; operator-stated: a check returns None)
    assert head().check_hunk_record(raw, changed, afters, classify, context, head().HUNK_RULE_SHA256) is None
    record = json.loads(raw)
    steps = _find_holder(record, "steps")
    pairs = _find_holder(record, "countPairs")
    # CONTRACT_289 section 6 (steps [1, 1]; also section 1)
    assert steps is not None and steps["steps"] == [1, 1]
    # CONTRACT_289 section 6 (countPairs []; also section 8)
    assert pairs is not None and pairs["countPairs"] == []


def _v6_steps(record):
    _find_holder(record, "steps")["steps"] = [1, 2]


def _v6_pairs(record):
    _find_holder(record, "countPairs")["countPairs"] = [[300, 301]]


def _v6_outcome(record):
    record["outcome"] = "PASS"


def _v6_vocabulary(record):
    classes = record["classes"]
    path = next(path for path, kinds in classes.items() if kinds)
    classes[path][0] = "met008-oracle-unknown-class"


@pytest.mark.parametrize(
    "mutate",
    [
        pytest.param(_v6_steps, id="steps"),
        pytest.param(_v6_pairs, id="count-pairs"),
        pytest.param(_v6_outcome, id="outcome-statement"),
        pytest.param(_v6_vocabulary, id="vocabulary"),
    ],
)
def test_v6_refuses_a_changed_record(mutate):
    """Section 6 (V6): steps other than [1, 1], countPairs other than [], an outcome member, or a class outside
    the vocabulary is refused."""
    raw, changed, afters, classify, context = _hunk_inputs()
    record = json.loads(raw)
    mutate(record)
    message = _refusal(
        head().check_hunk_record, _dump_like(raw, record), changed, afters, classify, context,
        head().HUNK_RULE_SHA256)
    # CONTRACT_289 section 6 (operator-stated: the ValueError names MET-008)
    assert "MET-008" in message


def test_v6_refuses_another_rule_digest():
    """Section 6 (V6): the record is checked against v2.5's rule digest; another digest is refused."""
    raw, changed, afters, classify, context = _hunk_inputs()
    other = "f" * 64 if _hex(head().HUNK_RULE_SHA256) == "0" * 64 else "0" * 64
    message = _refusal(head().check_hunk_record, raw, changed, afters, classify, context, other)
    # CONTRACT_289 section 6 (operator-stated: the ValueError names MET-008)
    assert "MET-008" in message


def test_authority_form_and_pc1_entries():
    """Sections 6, 8 and 8.1: the authority's schemaVersion and eight members, [PC-1]'s entries, the pinned bases."""
    authority = head().authority()
    changed = authority["changedFiles"]
    oracle = changed[PC1_ORACLE]
    identity = changed[PC1_IDENTITY]
    # CONTRACT_289 section 6 (the authority's schemaVersion)
    assert authority["schemaVersion"] == AUTHORITY_SCHEMA
    # CONTRACT_289 section 6 (the eight-member K = 0 form)
    assert len(authority) == 8
    # CONTRACT_289 section 8.1 (fc95bcd7 to c245f7d2)
    assert _hex(oracle["beforeSha256"]).startswith("fc95bcd7") and _hex(oracle["afterSha256"]).startswith("c245f7d2")
    # CONTRACT_289 section 8.1 (35a2094d to 982a13fa)
    assert _hex(identity["beforeSha256"]).startswith("35a2094d")
    # CONTRACT_289 section 8.1 (35a2094d to 982a13fa)
    assert _hex(identity["afterSha256"]).startswith("982a13fa")
    # CONTRACT_289 section 8.1 (2 and 5 canonical reverse hunks)
    assert (len(oracle["reverseHunks"]), len(identity["reverseHunks"])) == (2, 5)
    # CONTRACT_289 section 8 (the pinned base digest of ci/parallel_suite.py)
    assert _hex(changed["ci/parallel_suite.py"]["beforeSha256"]).startswith("9f212f31")
    # CONTRACT_289 section 8 (the pinned base digest of the PERF035 doc)
    assert _hex(changed["docs/alpha-2/PARALLEL_SUITE_PERF035.md"]["beforeSha256"]).startswith("57241b5c")


@pytest.mark.parametrize("path", sorted(ERRATA_SPANS))
def test_authority_records_the_errata_files(path):
    """Sections 6 and 16 ([E-2]): each E3 file's entry records its after-digest; undoing the layer gives its before."""
    entry = head().authority()["changedFiles"][path]
    current = _disk(path)
    # CONTRACT_289 section 16 ([E-2]: the authority records each changed file's after-digest)
    assert _hex(entry["afterSha256"]) == _sha(current)
    # CONTRACT_289 section 6 (operator-stated: _undo_this_layer returns the before bytes)
    assert _hex(entry["beforeSha256"]) == _sha(head()._undo_this_layer(path, current))
    # CONTRACT_289 section 6 (operator-stated: each hunk is {at, removeBase64, insertBase64})
    assert all(sorted(hunk) == ["at", "insertBase64", "removeBase64"] for hunk in entry["reverseHunks"])


# ==============================================================================================================
# 5. c-B's reader (section 7)
# ==============================================================================================================


def test_suite_constants():
    """Section 7: WORKERS = 12 and DEADLINE_SECONDS = 900 stay; the two variable names."""
    module = suite()
    # CONTRACT_289 section 7 (WORKERS = 12)
    assert module.WORKERS == 12
    # CONTRACT_289 section 7 (DEADLINE_SECONDS = 900)
    assert module.DEADLINE_SECONDS == 900
    # CONTRACT_289 section 7 (the workers variable)
    assert module.WORKERS_ENV == WORKERS_NAME
    # CONTRACT_289 section 7 (the deadline variable)
    assert module.DEADLINE_ENV == DEADLINE_NAME


ACCEPTED = [
    pytest.param({}, (12, 900), id="both-unset"),
    pytest.param({"PLANEON_UNRELATED_NAME": "7"}, (12, 900), id="unrelated-name"),
    pytest.param({WORKERS_NAME: "1"}, (1, 900), id="workers-1"),
    pytest.param({WORKERS_NAME: "64"}, (64, 900), id="workers-64"),
    pytest.param({WORKERS_NAME: "12"}, (12, 900), id="workers-12"),
    pytest.param({WORKERS_NAME: "32"}, (32, 900), id="workers-32"),
    pytest.param({WORKERS_NAME: "064"}, (64, 900), id="workers-leading-zero"),
    pytest.param({DEADLINE_NAME: "900"}, (12, 900), id="deadline-900"),
    pytest.param({DEADLINE_NAME: "3600"}, (12, 3600), id="deadline-3600"),
    pytest.param({DEADLINE_NAME: "1500"}, (12, 1500), id="deadline-1500"),
    pytest.param({WORKERS_NAME: "1", DEADLINE_NAME: "3600"}, (1, 3600), id="both-set"),
]


@pytest.mark.parametrize("environ, expected", ACCEPTED)
def test_configured_accepts(environ, expected):
    """Section 7 (MET008-C1-21, MET008-C2-3): an unset name gives its default; a value matching [0-9]+ within its
    bounds gives its integer."""
    given = dict(environ)
    result = suite().configured(given)
    # CONTRACT_289 section 7 (workers 1 to 64, the deadline 900 to 3,600 s; defaults 12 and 900)
    assert tuple(result) == expected
    # CONTRACT_289 section 7 (integers)
    assert all(type(value) is int for value in result)
    # CONTRACT_289 section 7 (the reader takes a mapping and reads it)
    assert given == environ


def _value_id(value):
    if value == "":
        return "empty"
    return value.encode("unicode_escape").decode("ascii").replace("\\", "x").replace(" ", "_sp_")


MALFORMED_BOTH = ["", " 12", "+12", "1_2", "12.0", "١٢"]  # section 7 (C12's vectors for both names)
REFUSED_WORKERS = ["0", "65", "twelve", "-4", "100", "12 ", "12\n", "１２"] + MALFORMED_BOTH
REFUSED_DEADLINE = [
    "899", "3601", "1e3", "0", " 900", "+900", "9_00", "900.0", "900\n", "٩٠٠",
] + MALFORMED_BOTH
REFUSED = (
    [pytest.param(WORKERS_NAME, value, id="workers-" + _value_id(value)) for value in REFUSED_WORKERS]
    + [pytest.param(DEADLINE_NAME, value, id="deadline-" + _value_id(value)) for value in REFUSED_DEADLINE]
)


@pytest.mark.parametrize("name, value", REFUSED)
def test_configured_refuses(name, value):
    """Section 7 (Q-289-2, MET008-C1-21): any other set value, the empty string included, raises
    pytest.UsageError naming the variable and its bounds."""
    # CONTRACT_289 section 7 (pytest.UsageError)
    with pytest.raises(pytest.UsageError) as info:
        suite().configured({name: value})
    message = str(info.value)
    # CONTRACT_289 section 7 (naming the variable)
    assert name in message
    if name == WORKERS_NAME:
        # CONTRACT_289 section 7 (and its bounds: 1 to 64)
        assert "64" in message
    else:
        # CONTRACT_289 section 7 (and its bounds: 900 to 3,600 s)
        assert "900" in message and ("3600" in message or "3,600" in message)


@pytest.mark.parametrize(
    "bad, good, good_value",
    [
        pytest.param(WORKERS_NAME, DEADLINE_NAME, "1200", id="workers-refused"),
        pytest.param(DEADLINE_NAME, WORKERS_NAME, "8", id="deadline-refused"),
    ],
)
def test_configured_names_the_refused_variable(bad, good, good_value):
    """Section 7: with one name valid and the other refused, the error names the refused variable."""
    # CONTRACT_289 section 7 (pytest.UsageError)
    with pytest.raises(pytest.UsageError) as info:
        suite().configured({good: good_value, bad: "abc"})
    # CONTRACT_289 section 7 (naming the variable)
    assert bad in str(info.value)


def test_default_deadline_fits_the_verify_cap():
    """Section 7 (Q-289-T1 (b)): the default deadline plus 60 + 120 + 90 s of setup fits under the 1,500 s cap."""
    # CONTRACT_289 section 7 (900 + 270 = 1,170 <= 1,500)
    assert suite().configured({})[1] + 60 + 120 + 90 <= 1500
