#!/usr/bin/env python3
"""Release evidence (architecture/release-evidence.json, RELEASE-EVIDENCE-001, MET-008): the projection.

project(read) builds the capability evidence matrix through an injected byte reader from three records that already
exist: the first-release profile (architecture/release-profile.json, RELEASE-PROFILE-001), TECH-TRUTH-001's deployable
record (architecture/language-placement.json) and the release lock (release/repos.lock.json, ADR 0005). It reads
nothing else: which cells carry a packet reference and which carry null is fixed by the cell table below, and it never
probes for a packet or reads the bridge roadmap.

- One closure row per node of the profile's closure.nodes, in order; then the release-profile errata rider's nine
  exclusion rows (producer-side artifacts outside the tenant closure).
- Every cell is one state of the closed set with its reference, producer, required source, owner, date and next action.
  A state is never inherited from a parent or a sibling, and the six claim domains are separate cells.
- The state rule has three branches, in order: NOT_SELECTED where the column or domain does not apply to the row (the
  class table); otherwise BLOCKED where the producer cannot run (the lock is inert; a tenant fact is unattested; the
  consulted producer's roadmap status is BLOCKED or WAITING_OWNER, or it carries an external blocker; the
  independentAssurance cells consult CONF-A2-001); otherwise NOT_RUN.
- The producers' statuses are a dated snapshot held here as a constant table (PRODUCER_STATUS), with its provenance;
  the next MET packet re-projects them.

It fills a cell only from a record that already exists, and claims no evidence: at this era no cell is QUALIFIED or
FAILED. It raises ValueError when a premise of its states does not hold: the lock is not INERT_LOCK, a module's exit
evidence is not at CONF-A2-001, or a tenant fact's attestation requirement is not SIGNED_ENVIRONMENT_FACT. Standard
library only; data only.
"""
from __future__ import annotations

import hashlib
import json

SCHEMA_VERSION = "harness.planeon.ai/release-evidence/v1"
RECORD_PATH = "architecture/release-evidence.json"
SCHEMA_PATH = "architecture/release-evidence/schema.json"
PROFILE_PATH = "architecture/release-profile.json"
DEPLOYABLE_RECORD_PATH = "architecture/language-placement.json"
LOCK_PATH = "release/repos.lock.json"
AS_OF = "2026-11-14"
STATES = ("NOT_RUN", "NOT_SELECTED", "BLOCKED", "FAILED", "QUALIFIED")
COLUMNS = ("sourceCommit", "artifactDigest", "deploymentProfile", "runtimeCampaign", "independentAssurance",
           "tenantAcceptance", "executionMode", "qualificationBundle")
DOMAINS = ("containment", "applicationAuthorization", "effectSemantics", "retrievalQuality", "deploymentRecovery",
           "customerAcceptance")
NODE_CLASSES = ("SELECTED", "CLOSURE", "TENANT_FACT")
ROADMAP_STATUSES = ("BLOCKED", "WAITING_OWNER", "READY", "IN_PROGRESS", "DONE")
INERT_LOCK = "INERT_LOCK"
EXIT_AT = "CONF-A2-001"
UNATTESTED = "SIGNED_ENVIRONMENT_FACT"
GROUNDING = "GROUNDING_EVALUATION"
HUMAN_PROBES = "human-probes item"  # the role key of the roadmap item whose id is never written
PRODUCER_STATUS = {
    "source": {"repository": "harness-onion-roadmap", "path": "roadmap/roadmap.json",
               "commit": "1cc8073d1a38988d0dc99c9b26daaa5e93388a41",
               "sha256": "bf78bd61498508dd34de29947be5bd5838dfcc0ae57c32198054370875044356"},
    "asOf": AS_OF,
    "statuses": {"CAP-CATALOG-001": "READY", "CONF-A2-001": "BLOCKED", "CONF-LINUX-001": "BLOCKED",
                 "CONF-WG-001": "BLOCKED", "RO-IMPL-R04": "BLOCKED", "RO-IMPL-R11": "BLOCKED",
                 "UAT-CAMPAIGN-001": "READY", HUMAN_PROBES: "WAITING_OWNER"},
}
EXTERNAL_BLOCKERS = frozenset()  # consulted producers carrying an externalBlockers entry at this era: none
TENANT_NOT_SELECTED = ("sourceCommit", "artifactDigest", "executionMode", "qualificationBundle")
ARTIFACT_NOT_SELECTED_COLUMNS = ("executionMode", "qualificationBundle")
ARTIFACT_DOMAIN = "deploymentRecovery"
EXCLUSIONS = (  # (id, registry id, artifact), the rider's order
    ("distribution.bundle", "distribution", "the signed OCI bundle"),
    ("distribution.bundle-lock", "distribution", "bundle.lock.json"),
    ("distribution.helm-profile", "distribution", "the profile's Helm chart set"),
    ("distribution.sbom-licence", "distribution", "SPDX SBOM and licence closure"),
    ("distribution.vulnerability-custody", "distribution", "vulnerability evidence and model custody"),
    ("distribution.signatures-trust", "distribution", "signatures, trust bundle, promotion record"),
    ("distribution.airgap-archive", "distribution", "the air-gap export archive"),
    ("control-plane.control-web", "control-plane", "control-web"),
    ("control-plane.profile-compiler-worker", "control-plane", "profile-compiler-worker"),
)
NOT_SELECTED_ROWS = frozenset({"distribution.airgap-archive"})  # enterprise-release scope: every cell NOT_SELECTED
RIDER = {"distribution": "RELEASE-PROFILE-001 errata (2026-10-31): R11 finding 2, Q-R11-FIRST",
         "control-plane": "RELEASE-PROFILE-001 errata (2026-10-31): F-R04-2"}
SOURCE = {
    "distribution": {"registryRow": "distribution", "mainPin": "fe49981e",
                     "note": "R11 main a60de413 since 2026-11-08 (DIST-TRANSPORT-002); the named artifacts are unchanged there",
                     "path": "."},
    "control-plane": {"registryRow": "control-plane", "mainPin": None,
                      "note": "no verified pin: no record names R04's artifacts at a pin; Build-R04's closure-proof packet records it",
                      "path": "."},
}
CLOSURE_PROOF = {  # registry id -> (owner, producer, next action) of an exclusion row's BLOCKED cells
    "distribution": ("R11", "Build-R11's closure-proof packet (Q-R11-FIRST)",
                     "the closure-proof packet, after bundle v9 and R11's adoption of v9's hosted-runner digest"),
    "control-plane": ("R04", "Build-R04's closure-proof packet (F-R04-2)", "the closure-proof packet"),
}
# a cell's producer -> its statuses key (the producer the rule consults); a tenant fact's supplier has none
STATUS_KEY = {"R11's release set": "RO-IMPL-R11", CLOSURE_PROOF["distribution"][1]: "RO-IMPL-R11",
              CLOSURE_PROOF["control-plane"][1]: "RO-IMPL-R04", "CONF-WG-001 (the candidate)": "CONF-WG-001",
              "CONF-A2-001": "CONF-A2-001", "CONF-LINUX-001": "CONF-LINUX-001", "CAP-CATALOG-001": "CAP-CATALOG-001",
              "UAT-CAMPAIGN-001": "UAT-CAMPAIGN-001"}
# the module rows' consulted producer per column or domain: "e" is the module's exitEvidence.at
MODULE_CONSULTS = {"deploymentProfile": "e", "runtimeCampaign": "e", "independentAssurance": EXIT_AT,
                   "tenantAcceptance": "CONF-WG-001", "executionMode": "CAP-CATALOG-001",
                   "qualificationBundle": "CAP-CATALOG-001", "containment": "CONF-LINUX-001",
                   "applicationAuthorization": "e", "effectSemantics": "e", "retrievalQuality": "e",
                   "deploymentRecovery": "e", "customerAcceptance": "UAT-CAMPAIGN-001"}
LOCK_COLUMNS = ("sourceCommit", "artifactDigest")


def digest(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def rule(key: str, statuses) -> str:
    """Branches 2c and 3 for a consulted producer's statuses key."""
    if key not in statuses:
        raise ValueError("no status for the consulted producer %r" % (key,))
    return "BLOCKED" if statuses[key] in ("BLOCKED", "WAITING_OWNER") or key in EXTERNAL_BLOCKERS else "NOT_RUN"


def _cell(state, reference, producer, required, owner, action):
    return {"state": state, "reference": reference, "producer": producer, "requiredSource": required, "owner": owner,
            "date": AS_OF, "nextAction": action}


def _not_selected(reference, action):
    return _cell("NOT_SELECTED", reference, None, None, "R00", action)


def _module_cells(module, profile_id, statuses):
    e = module["exitEvidence"]["at"]
    pe = "packet:" + e
    run = "unblock and run " + e
    lock = "publish the first product release"
    st = lambda key: rule(e if key == "e" else key, statuses)
    cells = {
        "sourceCommit": _cell("BLOCKED", LOCK_PATH, "R11's release set", "a release-lock repository entry", "R11", lock),
        "artifactDigest": _cell("BLOCKED", LOCK_PATH, "R11's release set", "a release-lock artifact digest", "R11", lock),
        "deploymentProfile": _cell(st("e"), pe, e, "a deployment record of " + profile_id, "R12", run),
        "runtimeCampaign": _cell(st("e"), pe, e, "a campaign record of " + e, "R12", run),
        "independentAssurance": _cell(st(EXIT_AT), pe, e, "an assurance record bound to the artifact digest", "R12", run),
        "tenantAcceptance": _cell(st("CONF-WG-001"), "packet:CONF-WG-001", "CONF-WG-001 (the candidate)",
                                  "a tenant's own acceptance record from an independent producer (ADR 0005, "
                                  "TENANT_ACCEPTANCE after the candidate)", "R12",
                                  "unblock and run CONF-WG-001; the tenant accepts after the candidate"),
        "executionMode": _cell(st("CAP-CATALOG-001"), None, "CAP-CATALOG-001",
                               "a capability catalogue row with its execution mode", "R00", "publish CAP-CATALOG-001"),
        "qualificationBundle": _cell(st("CAP-CATALOG-001"), None, "CAP-CATALOG-001", "a qualification bundle reference",
                                     "R00", "publish CAP-CATALOG-001"),
    }
    grounded = GROUNDING in module["exitEvidence"]["evidenceKinds"]
    domains = {
        "containment": _cell(st("CONF-LINUX-001"), "packet:CONF-LINUX-001", "CONF-LINUX-001",
                             "a containment campaign record", "R12",
                             "unblock CONF-LINUX-001 (it needs existing Linux capacity or owner-approved cloud spend); "
                             "the human-authored probe input is BLOCKED on a human author named by the owner"),
        "applicationAuthorization": _cell(st("e"), pe, e, "an authorization campaign record", "R12", run),
        "effectSemantics": _cell(st("e"), pe, e, "an effect-semantics campaign record", "R12", run),
        "retrievalQuality": (_cell(st("e"), pe, e, "a grounding evaluation record", "R12", run) if grounded else
                             _not_selected(PROFILE_PATH + "#" + module["id"],
                                           "none: the module's exit evidence holds no GROUNDING_EVALUATION")),
        "deploymentRecovery": _cell(st("e"), pe, e, "a deployment and recovery record", "R12", run),
        "customerAcceptance": _cell(st("UAT-CAMPAIGN-001"), None, "UAT-CAMPAIGN-001",
                                    "a customer workflow acceptance record", "R12", "run UAT-CAMPAIGN-001"),
    }
    return cells, domains


def _fact_cells(fact):
    reference = PROFILE_PATH + "#" + fact["id"]
    blocked = lambda: _cell("BLOCKED", reference, fact["supplier"]["name"], fact["attestation"]["requirement"], "TENANT",
                            "obtain the signed environment fact")
    none = lambda: _not_selected(None, "none: a tenant fact has no source commit, artifact digest, execution mode or "
                                       "qualification bundle")
    return ({c: (none() if c in TENANT_NOT_SELECTED else blocked()) for c in COLUMNS},
            {d: blocked() for d in DOMAINS})


def _exclusion_cells(xid, registry):
    if xid in NOT_SELECTED_ROWS:
        none = lambda: _not_selected(None, "none: enterprise-release scope, not selected for "
                                           "profile.banking-readonly-amd64")
        return {c: none() for c in COLUMNS}, {d: none() for d in DOMAINS}
    owner, producer, action = CLOSURE_PROOF[registry]
    blocked = lambda: _cell("BLOCKED", LOCK_PATH, producer, "an artifact record for repositoryId " + registry +
                            " in a non-inert release-set lock", owner, action)
    no_mode = lambda: _not_selected(None, "none: an artifact row has no execution mode or qualification bundle")
    no_domain = lambda: _not_selected(None, "none: an artifact row answers deployment and recovery only")
    return ({c: (no_mode() if c in ARTIFACT_NOT_SELECTED_COLUMNS else blocked()) for c in COLUMNS},
            {d: (blocked() if d == ARTIFACT_DOMAIN else no_domain()) for d in DOMAINS})


def project(read) -> dict:
    raw = {path: read(path) for path in (PROFILE_PATH, DEPLOYABLE_RECORD_PATH, LOCK_PATH)}
    profile, placement, lock = (json.loads(raw[p]) for p in (PROFILE_PATH, DEPLOYABLE_RECORD_PATH, LOCK_PATH))
    if lock.get("documentKind") != INERT_LOCK:
        raise ValueError("the release lock is not INERT_LOCK: this projection has no rule for its cells")
    if any(m["exitEvidence"]["at"] != EXIT_AT for m in profile["modules"]):
        raise ValueError("a module's exit evidence is not at CONF-A2-001: this projection's states do not hold")
    if any(f["attestation"]["requirement"] != UNATTESTED for f in profile["tenantFacts"]):
        raise ValueError("a tenant fact's attestation requirement is not SIGNED_ENVIRONMENT_FACT: clause 2b does not hold")
    statuses = PRODUCER_STATUS["statuses"]
    profile_id = profile["profile"]["id"]
    entries = {d["id"]: d for d in placement["deployables"]}
    outside = {d["id"]: d for d in placement["outsideCatalogue"]}
    by_name = {r["name"]: r for r in placement["repositories"]}
    by_id = {r["id"]: r for r in placement["repositories"]}
    modules = {m["id"]: m for m in profile["modules"]}
    facts = {f["id"]: f for f in profile["tenantFacts"]}
    rows = []
    for node in profile["closure"]["nodes"]:
        if node in modules:
            m = modules[node]
            cells, domains = _module_cells(m, profile_id, statuses)
            deployables = []
            for d in m["deployables"]:
                entry, out = entries.get(d["name"]), outside.get(d["name"])
                deployables.append({"name": d["name"], "type": d["type"],
                                    "deployableRecord": "ENTRY" if entry else "OUTSIDE_CATALOGUE" if out else "ABSENT",
                                    "plannedLanguage": (entry or out or {}).get("plannedLanguage"),
                                    "status": entry["status"] if entry else None})
            registry = by_name.get(m["owner"]["name"])
            readiness = m["readiness"]
            rows.append({"id": node, "nodeClass": m["class"], "kind": m["kind"],
                         "owningService": readiness.get("serviceId") if readiness.get("source") == "SERVICES" else None,
                         "owner": {"type": m["owner"]["type"], "name": m["owner"]["name"],
                                   "rNumber": registry["rNumber"] if registry else None},
                         "implementation": m.get("implementation"), "deployables": deployables,
                         "cells": cells, "claimDomains": domains})
        else:
            f = facts[node]
            cells, domains = _fact_cells(f)
            rows.append({"id": node, "nodeClass": "TENANT_FACT", "kind": "EXTERNAL", "owningService": None,
                         "owner": {"type": f["supplier"]["type"], "name": f["supplier"]["name"], "rNumber": None},
                         "implementation": None, "deployables": [], "cells": cells, "claimDomains": domains})
    exclusion_rows = []
    for xid, registry, artifact in EXCLUSIONS:
        repository = by_id[registry]
        cells, domains = _exclusion_cells(xid, registry)
        exclusion_rows.append({"id": xid, "repository": {"id": registry, "name": repository["name"],
                                                         "rNumber": repository["rNumber"]},
                               "artifact": artifact, "side": "PRODUCER", "rider": RIDER[registry],
                               "source": dict(SOURCE[registry]), "cells": cells, "claimDomains": domains})
    counts = {state: 0 for state in STATES}
    for row in rows + exclusion_rows:
        for cell in list(row["cells"].values()) + list(row["claimDomains"].values()):
            counts[cell["state"]] += 1
    return {
        "schemaVersion": SCHEMA_VERSION,
        "basis": {"profile": {"path": PROFILE_PATH, "id": profile_id, "sha256": digest(raw[PROFILE_PATH])},
                  "deployableRecord": {"path": DEPLOYABLE_RECORD_PATH, "sha256": digest(raw[DEPLOYABLE_RECORD_PATH])},
                  "releaseLock": {"path": LOCK_PATH, "sha256": digest(raw[LOCK_PATH])}},
        "producerStatus": {"source": dict(PRODUCER_STATUS["source"]), "asOf": PRODUCER_STATUS["asOf"],
                           "statuses": dict(sorted(statuses.items()))},
        "states": list(STATES), "columns": list(COLUMNS), "claimDomains": list(DOMAINS),
        "rows": rows,
        "exclusionRows": exclusion_rows,
        "counts": {"rows": len(rows), "exclusionRows": len(exclusion_rows), "cellsByState": counts},
    }


def serialize(record) -> bytes:
    return (json.dumps(record, indent=2, ensure_ascii=False) + "\n").encode("utf-8")
