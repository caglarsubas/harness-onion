"""D5a oracle tests for the probe-kit scope amendment, MET-LIVE-002 (planeon.internal.probe-kit-scope/v1).

Black-box tests by an independent test author, written from the contract text. Sources:
- architecture/probe-kit-scope/README.md, the adopted contract text. Every expected value below is transcribed
  from it: the inputs table, the supersession table, the 12 statements that stay true, the fixed values, the class
  lists and path rules, the predecessor table, the declared search and the record's closed shape.
- architecture/probe-kit-scope/amendment.json, the record under test, read from ROOT.
- The base bytes at 2043cc27, read only with `git -C ROOT show 2043cc27:<path>` for paths the record names, and
  the README's declared search (its two `git grep -l -E` runs).
- scripts/probe_kit_scope.py, the reference model, used only through its public names: check, hits_for,
  path_class, R and the upper-case constants.

The declared search and the class path rules are re-implemented here from the README's text; neither is imported
from the model. The model mutations below are the author's own, not taken from any vector file.
"""

import bisect
import copy
import fnmatch
import hashlib
import json
import os
import re
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from scripts import probe_kit_scope  # noqa: E402

RECORD_FILE = ROOT / "architecture" / "probe-kit-scope" / "amendment.json"
GIT_ENV = dict(os.environ, GIT_OPTIONAL_LOCKS="0")

# README, first paragraph and "The fixed values".
SCHEMA = "planeon.internal.probe-kit-scope/v1"
PACKET = "MET-LIVE-002"
SLOT = 260
WORK_ITEM = "LINUX-PROBE-KIT-SCOPE"
BASE = "2043cc27883448e3ff030b7868110e295f32fe09"
BASE_REF = "2043cc27"
KIT = "LINUX-PROBE-KIT-001"
DEFERRED = "DEFERRED_UNOWNED"
KAP = "KAP_LEG"
R12 = "R12_SUCCESSOR"
HS53 = "architecture/host-interface-amendment-hs53/amendment.json"
CI_RECORD = "architecture/completion-integration.json"
CI_GUIDE = "docs/alpha-2/COMPLETION_INTEGRATION.md"

# README "Inputs, by sha256 at the base": short names and digest prefixes.
ABBREV = {
    "BH": "docs/alpha-2/BROKER_HANDOFF_READINESS.md",
    "PCR": "docs/alpha-2/PROXY_CONTRACT_READINESS.md",
    "POR": "docs/alpha-2/POLICY_OBSERVATION_READINESS.md",
    "NQ": "docs/alpha-2/NATIVE_QUALIFICATION_READINESS.md",
    "COR": "docs/alpha-2/CREDENTIAL_ORDERING_REPAIR.md",
    "TLC": "docs/TRUSTED_LIVE_CAMPAIGN_RUNNER_CONTRACT.md",
    "PCA": "architecture/proxy-contract-amendment.json",
    "I05 v1": "architecture/i05-gate-channel/README.md",
    "I05 v2": "architecture/i05-gate-channel-v2/README.md",
    "I05 v3": "architecture/i05-gate-channel-v3/README.md",
    "I05 guide": "docs/alpha-2/I05_GATE_CHANNEL.md",
    "LBRM": "architecture/live-backend-roadmap.json",
    "BHA": "architecture/broker-handoff-amendment.json",
    "NQA": "architecture/native-qualification-amendment.json",
    "CI": CI_RECORD,
    "HS53": HS53,
}
INPUT_PREFIXES = {
    "BH": "2cc6ebef252efb33",
    "PCR": "3e3bf310ebd8a7b1",
    "POR": "65778040919c5eb7",
    "NQ": "60bed4c5358527da",
    "COR": "b2ed7fe5be1a8b23",
    "TLC": "3f1bf16f6ec5d1e2",
    "PCA": "6c93e7db962cffa0",
    "I05 v1": "dc9aa22017b2cdf7",
    "I05 v2": "1cb07cef90b0881c",
    "I05 v3": "f82f43330125640d",
    "I05 guide": "97d1172fcde8e2f0",
    "LBRM": "06d55fab0d0e56cb",
    "BHA": "1b5843241dc2574b",
    "NQA": "e935cbd3045522cf",
    "CI": "0b36ddc4626430b2",
    "HS53": "e4255685a38f183d",
}
GATE_DOCUMENTS = ("TLC", "COR")

# README "The supersession": (id, pinned text, lines, quote or (start, end), moved items, movedTo, replacement
# text, kept items). Line breaks shown as the return symbol in the README are "\n" here.
README_SUPERSEDES = [
    ('S-01', 'I05 v2', '133-133', 'it stays carried to the I04 owner (R01) and CONF-LIVE-003', ['KAP_LEG'], 'DEFERRED_UNOWNED', 'It stays carried to the I04 owner (R01) and the deferred, unowned KAP leg.', []),
    ('S-02', 'I05 v2', '273-273', '(R01, CONF-LIVE-003)', ['KAP_LEG'], 'DEFERRED_UNOWNED', '(R01, the deferred and unowned KAP leg)', []),
    ('S-03', 'I05 v3', '135-135', 'it stays carried to the I04 owner (R01) and CONF-LIVE-003', ['KAP_LEG'], 'DEFERRED_UNOWNED', 'It stays carried to the I04 owner (R01) and the deferred, unowned KAP leg.', []),
    ('S-04', 'I05 v3', '326-326', '(R01, CONF-LIVE-003)', ['KAP_LEG'], 'DEFERRED_UNOWNED', '(R01, the deferred and unowned KAP leg)', []),
    ('S-05', 'I05 v1', '115-116', 'it is carried to the I04 owner\n   (R01) and CONF-LIVE-003', ['KAP_LEG'], 'DEFERRED_UNOWNED', 'It is carried to the I04 owner (R01) and the deferred, unowned KAP leg.', []),
    ('S-06', 'I05 v1', '277-277', '(R01, CONF-LIVE-003)', ['KAP_LEG'], 'DEFERRED_UNOWNED', '(R01, the deferred and unowned KAP leg)', []),
    ('S-07', 'PCA', '253-253', 'Product implementation remains in the eight existing CONF-LIVE-003 paths', ['ADMISSION_MODULE', 'SERVER', 'UID_LEDGER'], 'LINUX-PROBE-KIT-001', "The server-side product implementation is LINUX-PROBE-KIT-001's; the client stays in the eight paths with the R12 successor.", ['CLIENT']),
    ('S-08', 'PCA', '253-253', 'fixed probes, packaging', ['CASE_RECIPES', 'RECEIPT_CANDIDATES', 'SERVER', 'WORKER_ENTRY'], 'LINUX-PROBE-KIT-001', "The fixed probes, the unsigned receipt candidates and the server and worker packaging are LINUX-PROBE-KIT-001's; the client packaging stays with the R12 successor.", ['CLIENT']),
    ('S-09', 'TLC', '477-478', "Product implementation remains\nin that packet's eight existing paths", ['ADMISSION_MODULE', 'SERVER', 'UID_LEDGER'], 'LINUX-PROBE-KIT-001', "The server-side product implementation is LINUX-PROBE-KIT-001's; the client stays in the eight paths with the R12 successor.", ['CLIENT']),
    ('S-10', 'TLC', '479-480', 'CONF-LIVE-004 owns actual probes, CONF-LIVE-005 the fixed client/server\ncandidate packaging', ['CASE_RECIPES', 'RECEIPT_CANDIDATES', 'SERVER', 'WORKER_ENTRY'], 'LINUX-PROBE-KIT-001', "The actual probes, the unsigned receipt candidates and the server and worker packaging are LINUX-PROBE-KIT-001's; the client packaging stays with the R12 successor.", ['CLIENT']),
    ('S-11', 'BH', '35-35', 'Fixed server/broker transport and server/observer/broker custody checks; resource admission', ['ADMISSION_MODULE', 'SERVER'], 'LINUX-PROBE-KIT-001', "The fixed server transport, the server-side custody checks and resource admission are LINUX-PROBE-KIT-001's.", []),
    ('S-12', 'BH', '35-35', 'UID ledger and cleanup', ['UID_LEDGER'], 'LINUX-PROBE-KIT-001', "The UID ledger and cleanup are LINUX-PROBE-KIT-001's.", []),
    ('S-13', 'BH', '35-35', 'server-only TLS API leg', ['KAP_LEG'], 'DEFERRED_UNOWNED', 'The server-only TLS API leg (the KAP leg) is deferred and unowned (owner Q-LPK0-3).', []),
    ('S-14', 'BH', '36-36', 'Fixed worker entry, ten probe recipes, bounded resource-action requests and unsigned receipt candidate', ['CASE_RECIPES', 'RECEIPT_CANDIDATES', 'WORKER_ENTRY'], 'LINUX-PROBE-KIT-001', "The fixed worker entry, the ten probe recipes, the bounded resource-action requests and the unsigned receipt candidates are LINUX-PROBE-KIT-001's; the resource-bearing cases stay behind the deferred KAP leg.", []),
    ('S-15', 'BH', '37-37', 'Reproducible client/server/worker source candidates and installation handoff', ['SERVER', 'WORKER_ENTRY'], 'LINUX-PROBE-KIT-001', "The server and worker candidates are LINUX-PROBE-KIT-001's; the client candidate and the narrowed handoff stay with the R12 successor.", ['CANDIDATE_HANDOFF', 'CLIENT']),
    ('S-16', 'BH', '43-44', 'The fixed worker is packaged by the existing 005 builder/package module from\nthe existing 004 modules', ['WORKER_ENTRY'], 'LINUX-PROBE-KIT-001', 'The fixed worker is packaged by LINUX-PROBE-KIT-001 from its own modules.', []),
    ('S-17', 'BH', '45-45', 'No future packet must edit 003 to add an unspecified execution interface.', ['WORKER_ENTRY'], 'LINUX-PROBE-KIT-001', 'No future packet must edit LINUX-PROBE-KIT-001 to add an unspecified execution interface; the worker ABI is unchanged.', []),
    ('S-18', 'BH', '95-95', '005 packages this entry in addition to the already planned client/server entries;', ['SERVER', 'WORKER_ENTRY'], 'LINUX-PROBE-KIT-001', 'LINUX-PROBE-KIT-001 packages the worker and server entries; the client entry stays with the R12 successor.', ['CLIENT']),
    ('S-19', 'BH', '216-219', ('003 resolves a manifestDigest from its own immutable pr', ' validating actual post-defaulting manifests.'), ['ADMISSION_MODULE', 'UID_LEDGER'], 'LINUX-PROBE-KIT-001', "Manifest resolution, grants, create intent and the returned UID record are LINUX-PROBE-KIT-001's.", []),
    ('S-20', 'BH', '251-253', ('003 tests real fixed client/server factories using OS-m', 'er credentials if any prerequisite\nis absent.'), ['SERVER'], 'LINUX-PROBE-KIT-001', "LINUX-PROBE-KIT-001 tests the real fixed server factories; the R12 successor tests the client's.", ['CLIENT']),
    ('S-21', 'BH', '253-253', '004 tests all ten fixed recipes and the private worker ABI.', ['CASE_RECIPES', 'WORKER_ENTRY'], 'LINUX-PROBE-KIT-001', 'LINUX-PROBE-KIT-001 tests the ten fixed recipes and the private worker ABI.', []),
    ('S-22', 'BH', '253-255', ('005 builds\nreproducible inert candidates for the three ', 'server as\nexternal unavailable prerequisites.'), ['SERVER', 'WORKER_ENTRY'], 'LINUX-PROBE-KIT-001', "LINUX-PROBE-KIT-001 builds the server and worker candidates; the R12 successor builds the client's.", ['CLIENT']),
    ('S-23', 'COR', '122-127', 'CONF-LIVE-003 must separately test the actual fixed guard with mocked OS I/O:', ['SERVER', 'UID_LEDGER'], 'LINUX-PROBE-KIT-001', 'Each listed case is tested by the owner of the side it exercises: server-side refusal, policy effects and exact-UID cleanup by LINUX-PROBE-KIT-001, client-side cases by the R12 successor.', ['CLIENT']),
    ('S-24', 'I05 guide', '58-58', '(R01, CONF-LIVE-003)', ['KAP_LEG'], 'DEFERRED_UNOWNED', '(R01, the deferred and unowned KAP leg)', []),
    ('S-25', 'NQ', '38-38', ('Record parser, fixed native inspector, server/observer/', ' credential ordering, transport and admission'), ['ADMISSION_MODULE', 'RECORD_INSPECTOR', 'SERVER'], 'LINUX-PROBE-KIT-001', "The record parser, the native inspector, the server-side ownership, transport and admission are LINUX-PROBE-KIT-001's; the client's credential ordering and transport stay with the R12 successor.", ['CLIENT']),
    ('S-26', 'NQ', '39-39', 'Fixed worker; inherited broker-only control; qualified kernel/code checks through the same003-owned reader', ['RECORD_INSPECTOR', 'WORKER_ENTRY'], 'LINUX-PROBE-KIT-001', "The fixed worker and its qualified checks through the kit-owned reader are LINUX-PROBE-KIT-001's.", []),
    ('S-27', 'NQ', '40-40', 'Inert reproducible entries', ['SERVER', 'WORKER_ENTRY'], 'LINUX-PROBE-KIT-001', "The server and worker entries are LINUX-PROBE-KIT-001's; the client entry and the narrowed handoff stay with the R12 successor.", ['CANDIDATE_HANDOFF', 'CLIENT']),
    ('S-28', 'NQ', '44-45', 'No future packet may need an unspecified callback or edit003 to close\nthis boundary.', ['RECORD_INSPECTOR'], 'LINUX-PROBE-KIT-001', "The boundary is closed in LINUX-PROBE-KIT-001's inspector.", []),
    ('S-29', 'NQ', '238-240', ('Fixed consumer interface in live_proxy_server.py: a pri', 'eck_peer(role, retained_peer)`\nand `close()`.'), ['RECORD_INSPECTOR'], 'LINUX-PROBE-KIT-001', "The fixed consumer interface is LINUX-PROBE-KIT-001's.", []),
    ('S-30', 'NQ', '242-243', ("004's installed worker may use the same fixed reader fo", 'xact installed factory and parent/FD3 guards.'), ['WORKER_ENTRY'], 'LINUX-PROBE-KIT-001', "LINUX-PROBE-KIT-001's installed worker may use the same fixed reader.", []),
    ('S-31', 'NQ', '245-245', 'No future require_server_containment callback in packet004.', ['WORKER_ENTRY'], 'LINUX-PROBE-KIT-001', "No such callback exists in LINUX-PROBE-KIT-001's worker.", []),
    ('S-32', 'NQ', '256-257', ('Product003 must exercise the real factories through OS-', '\nall refusal gates before server credentials.'), ['SERVER'], 'LINUX-PROBE-KIT-001', "LINUX-PROBE-KIT-001 exercises the server's real factories through OS-mocked calls; the R12 successor exercises the client's.", ['CLIENT']),
    ('S-33', 'POR', '32-32', 'Fixed local channel consumer in live_proxy_server.py; data checks in live_mutation_admission.py', ['ADMISSION_MODULE', 'SERVER'], 'LINUX-PROBE-KIT-001', "The fixed local channel consumer and the data checks are LINUX-PROBE-KIT-001's.", []),
    ('S-34', 'POR', '33-33', 'Fixed probe adapters', ['CASE_RECIPES'], 'LINUX-PROBE-KIT-001', "The fixed probe adapters are LINUX-PROBE-KIT-001's.", []),
    ('S-35', 'POR', '34-34', 'Client/server candidate packaging and handoff', ['SERVER'], 'LINUX-PROBE-KIT-001', "The server candidate's packaging is LINUX-PROBE-KIT-001's; the client's and the narrowed handoff stay with the R12 successor.", ['CANDIDATE_HANDOFF', 'CLIENT']),
    ('S-36', 'POR', '167-168', ('CONF-LIVE-003 implements real fixed-path transport/vali', 'd negative tests in its existing three tests.'), ['ADMISSION_MODULE', 'SERVER'], 'LINUX-PROBE-KIT-001', "The server side and admission, with their negative tests, are LINUX-PROBE-KIT-001's; the client module and its tests stay with the R12 successor.", ['CLIENT']),
    ('S-37', 'PCR', '41-41', 'Client, server, admission, three tests, one fixture and one guide', ['ADMISSION_MODULE', 'SERVER'], 'LINUX-PROBE-KIT-001', "The server and admission modules and their tests are LINUX-PROBE-KIT-001's; the client and its tests stay with the R12 successor.", ['CLIENT']),
    ('S-38', 'PCR', '42-42', 'Actual fixed probes and native observations', ['CASE_RECIPES'], 'LINUX-PROBE-KIT-001', "The actual fixed probes are LINUX-PROBE-KIT-001's.", []),
    ('S-39', 'PCR', '43-43', 'Reproducible candidate archives and independent operator handoff', ['SERVER', 'WORKER_ENTRY'], 'LINUX-PROBE-KIT-001', "The server and worker archives are LINUX-PROBE-KIT-001's; the client archive and the narrowed handoff stay with the R12 successor.", ['CANDIDATE_HANDOFF', 'CLIENT']),
    ('S-40', 'PCR', '54-56', ('CONF-LIVE-003\nimplements equivalent stdlib validation i', 'dent negative tests in its three owned tests.'), ['ADMISSION_MODULE', 'SERVER'], 'LINUX-PROBE-KIT-001', "The server and admission modules' validation and their negative tests are LINUX-PROBE-KIT-001's; the client module and its tests stay with the R12 successor.", ['CLIENT']),
    ('S-41', 'PCR', '174-174', 'CONF-LIVE-003 defines a fixed `NativeProxyServer()` factory and `main()`;', ['SERVER'], 'LINUX-PROBE-KIT-001', 'LINUX-PROBE-KIT-001 defines the fixed server factory and main.', []),
    ('S-42', 'PCR', '176-176', 'CONF-LIVE-005 packages a separate fixed entry point that invokes that main:', ['SERVER'], 'LINUX-PROBE-KIT-001', "LINUX-PROBE-KIT-001 packages the server's fixed entry point.", []),
    ('S-43', 'PCR', '190-191', 'The new server\nchecks are owned only by CONF-LIVE-003.', ['SERVER'], 'LINUX-PROBE-KIT-001', 'The new server checks are owned by LINUX-PROBE-KIT-001.', []),
    ('S-44', 'PCR', '226-227', ('Only preinstalled fixed CONF-LIVE-004 adapters may subm', 'selected from the server-owned signed profile'), ['WORKER_ENTRY'], 'LINUX-PROBE-KIT-001', "Only LINUX-PROBE-KIT-001's preinstalled fixed adapters may submit such a manifest.", []),
    ('S-45', 'PCR', '307-313', 'CONF-LIVE-003 must independently cover every closed nested object', ['ADMISSION_MODULE', 'SERVER', 'UID_LEDGER'], 'LINUX-PROBE-KIT-001', "Each listed case is covered by the owner of the code it exercises: the server, admission, UID-ledger and cleanup cases by LINUX-PROBE-KIT-001, the client's cases by the R12 successor.", ['CLIENT']),
]
# README "The supersession": "PCR:307-313 and COR:122-127 keep their cited sentence ranges."
SENTENCE_RANGES = {("PCR", "307-313"), ("COR", "122-127")}
# README "Unquoted cells": every row with keptItems, as the README lists them (pinned text, id, kept items).
KEPT_ROWS = [
    ("PCA", "253-253", "S-07", ["CLIENT"]),
    ("PCA", "253-253", "S-08", ["CLIENT"]),
    ("TLC", "477-478", "S-09", ["CLIENT"]),
    ("TLC", "479-480", "S-10", ["CLIENT"]),
    ("BH", "37-37", "S-15", ["CANDIDATE_HANDOFF", "CLIENT"]),
    ("BH", "95-95", "S-18", ["CLIENT"]),
    ("BH", "251-253", "S-20", ["CLIENT"]),
    ("BH", "253-255", "S-22", ["CLIENT"]),
    ("COR", "122-127", "S-23", ["CLIENT"]),
    ("NQ", "38-38", "S-25", ["CLIENT"]),
    ("NQ", "40-40", "S-27", ["CANDIDATE_HANDOFF", "CLIENT"]),
    ("NQ", "256-257", "S-32", ["CLIENT"]),
    ("POR", "34-34", "S-35", ["CANDIDATE_HANDOFF", "CLIENT"]),
    ("POR", "167-168", "S-36", ["CLIENT"]),
    ("PCR", "41-41", "S-37", ["CLIENT"]),
    ("PCR", "43-43", "S-39", ["CANDIDATE_HANDOFF", "CLIENT"]),
    ("PCR", "54-56", "S-40", ["CLIENT"]),
    ("PCR", "307-313", "S-45", ["CLIENT"]),
]

# README "Statements that stay true", in full.
README_STAYS_TRUE = [
    ('PCA', '253-253', 'and final hook remain with CONF-LIVE-004/005/006'),
    ('TLC', '478-479', 'preserve all 127 predecessor files and\n279 test IDs'),
    ('TLC', '480-480', 'and CONF-LIVE-006 the already-bounded final hook'),
    ('BH', '40-42', 'Existing product paths remain exact: 003 has eight, 004 six, 005 five and 006\nfive additions plus its already-approved final launcher-hook edit. Stages remain\n110/120/127/135/141/146/151. Every product command set remains eight commands.'),
    ('COR', '102-103', 'CONF-LIVE-003 still owns its exact eight paths and all eight cumulative\ncommands'),
    ('NQ', '43-44', 'Exact product paths/stages110/120/127/135/141/146/151 and all eight commands are\nunchanged.'),
    ('POR', '168-169', 'Its own fixture\npins this authority and the unchanged 127-file/279-ID baseline.'),
    ('PCR', '191-191', 'No new root key or signature role.'),
    ('PCR', '41-41', 'eight existing paths'),
    ('PCR', '42-42', 'in six existing paths'),
    ('PCR', '43-43', 'in five existing paths'),
    ('PCR', '56-57', 'It must pin this authority\nand preserve the immediate 127-file/279-ID baseline in its owned fixture.'),
]

# README "What moves, what R12 keeps, what is deferred, what stays unchanged" and "The fixed values".
FROM_PACKET = {
    "ADMISSION_MODULE": "CONF-LIVE-003",
    "CASE_RECIPES": "CONF-LIVE-004",
    "RECEIPT_CANDIDATES": "CONF-LIVE-004",
    "RECORD_INSPECTOR": "CONF-LIVE-003",
    "SERVER": "CONF-LIVE-003",
    "UID_LEDGER": "CONF-LIVE-003",
    "WORKER_ENTRY": "CONF-LIVE-004",
}
MOVED_STATUS = "SUPERSEDED_UNACCEPTED_HISTORY"
RETAINED_PACKETS = {
    "CLIENT": {"CONF-LIVE-003"},
    "CANDIDATE_HANDOFF": {"CONF-LIVE-005"},
    "RECEIPT_VERIFICATION": {"CONF-LIVE-004"},
    "EVIDENCE_VERIFICATION": {"CONF-LIVE-006", "CONF-LINUX-001"},
    "R12_OTHER": {"CONF-LIVE-001", "CONF-LIVE-002", "CONF-LIVE-006"},
}
DELIVERABLE_TOKENS = ("KEPT_R12", "SUPERSEDED_UNACCEPTED_HISTORY")
UNCHANGED_IDS = ["CONF_LIVE_006_PATHS", "INSTALLED_IDENTITIES", "ROLES", "SIGNING_DUTIES", "WIRE_AND_BINDING",
                 "WORKER_ENTRY_NAME"]
UNCHANGED_TERMS = {
    "CONF_LIVE_006_PATHS": ["CONF-LIVE-006", "paths", "eight commands"],
    "INSTALLED_IDENTITIES": ["executables", "manifests", "trust anchor", "TLS key", "state paths", "units"],
    "ROLES": ["SERVER", "WORKER", "native-profile v4", "v5's kept record"],
    "SIGNING_DUTIES": ["no new key or signature role"],
    "WIRE_AND_BINDING": ["binding", "socket ABI", "proxy profile", "endpoint tuple", "caseId", "worker digests"],
    "WORKER_ENTRY_NAME": ["workerEntry: live_fixed_probes.broker_worker_main", "argv", "FD3",
                          "installed identity string only"],
}
DEFERRED_ROW = {"item": KAP, "status": DEFERRED, "authority": "Q-LPK0-3",
                "sourceClauses": ["BH:210-214", "BH:35", "PCR:207-225"]}
PACKET_DISPOSITIONS = {
    "CONF-LIVE-003": "CONSUMED",
    "CONF-LIVE-004": "NOT_DISPATCHABLE_AS_WRITTEN",
    "CONF-LIVE-005": "NOT_DISPATCHABLE_AS_WRITTEN",
    "CONF-LIVE-006": "UNCHANGED",
}
RETIRED_IDS = ["CONF-FIX-007", "CONF-FIX-008", "CONF-FIX-009", "CONF-FIX-010"]
RETIRED_STATUS = "NON_DISPATCHABLE_RETAINED_HISTORY"
OWNER_QUOTES = [
    ("Q-PK-2", "Move them (Recommended)"),
    ("Q-LPK0-3", "Server side, KAP stays (Recommended)"),
    ("Q-LPK0-3", "KAP stays deferred and unowned, as your LX-D1 says"),
    ("R-S1-5", "Retire 008 too (Recommended)"),
    ("Q-LPK0-4", "Retain as history (Recommended)"),
]

# README "The predecessor table".
PREDECESSORS = {
    "EVOLUTION_SURFACE_GATE_PACKET": ["MET-LIVE-002"],
    "LINUX-PROBE-KIT-ADMISSION": ["EVOLUTION_SURFACE_GATE_PACKET", "MET-LIVE-002"],
    "LINUX-PROBE-KIT-001": ["LINUX-PROBE-KIT-ADMISSION", "NEUTRAL_INTERFACE_CONTRACT"],
    "R12_SUCCESSOR": ["MET-LIVE-002", "NEUTRAL_INTERFACE_CONTRACT"],
    "CONF-LIVE-006": ["LINUX-PROBE-KIT-001", "R12_SUCCESSOR"],
}
PLACEHOLDERS = ["EVOLUTION_SURFACE_GATE_PACKET", "NEUTRAL_INTERFACE_CONTRACT", "R12_SUCCESSOR"]

# README "completion-integration.json" and "LBRM, BHA and NQA" rules: the four amends rows' entries.
AMENDS_ENTRIES = {
    "BHA": [],
    "CI": ["effectivePredecessors.CONF-LIVE-004"],
    "LBRM": [],
    "NQA": [],
}

# README "Not amended" and "The fixed values": class lists, counts and path rules.
LINEAGE_GUIDE = ["docs/alpha-2/CONFORMANCE_COMPLETION.md", "docs/alpha-2/CONFORMANCE_PUBLICATION.md",
                 "docs/alpha-2/LOCAL_ACCEPTANCE_REVALIDATION.md", "docs/alpha-2/SUCCESSOR_CHECKPOINT_REPAIR.md"]
LIVING_CATALOG = ["docs/DEVELOPMENT_STATUS.md", "docs/MASTER_DEVELOPMENT_PLAN.md", "docs/READINESS_INDEX.md",
                  "docs/adr/0004-sol-high-packet-boundary.md", "docs/alpha-2/COMPLETION_INTEGRATION.md",
                  "docs/alpha-2/LIVE_BACKEND_READINESS.md", "docs/repositories/00-harness-engineering.md",
                  "docs/repositories/12-mas-harness-conformance-labs.md", "task-packets/README.md"]
CLOSED_RECORD = ["architecture/backend-timing.json", "architecture/broker-handoff-amendment.json",
                 "architecture/completion-integration.json", "architecture/conformance-completion.json",
                 "architecture/conformance-publication.json", "architecture/live-backend-roadmap.json",
                 "architecture/local-acceptance.json", "architecture/native-qualification-amendment.json",
                 "architecture/proxy-diagnostics.json", "architecture/unified-roadmap-backlog.json"]
PINNED_COUNTS = {"MERGED_PACKET_YAML": 32, "CLOSED_RECORD": 10, "INPUTS_PINNED": 1, "LINEAGE_GUIDE": 4}
NAMED_COUNTS = {"LIVING_CATALOG": 9, "HISTORY_SNAPSHOT": 1, "INPUTS_SNAPSHOT": 19, "ROUND_SNAPSHOT": 16,
                "REVIEW_RECORD": 3, "AUTHORITY_TEXT": 92, "RECORD_EMBEDDED_TEXT": 23}
INVENTORY_FILES = 278
HIT_LINES = 2423

# README "The inventory": the declared search.
PATHSPECS = ["docs", "architecture", "task-packets", ":!architecture/enforcement-test-plan",
             ":!docs/alpha-2/ENFORCEMENT_TEST_PLAN.md", ":!architecture/artifact-edges", ":!tools"]
ERE_LONG = "CONF-LIVE-00[345]"
ERE_SHORT = "(^|[^[:alnum:]_./:-])00[345]([^[:alnum:]_]|$)|(packet|packets|edit|Product|product|same|Native)00[345]"
STANDALONE = r"(?<![\w./:-])00[345](?!\w)"
GLUED_WORDS = ["packet", "packets", "edit", "Product", "product", "same", "Native"]
LONG_RE = re.compile(ERE_LONG)
STANDALONE_RE = re.compile(STANDALONE)
GLUED_RE = re.compile("(?:%s)00[345]" % "|".join(GLUED_WORDS))
LINE_DISPOSITIONS = {"QUOTED", "UNCHANGED_TRUE", "NOT_OWNERSHIP"}
NOT_OWNERSHIP_REASONS = {"STATUS_LINE", "REVIEW_HISTORY", "IDENTIFIER_INDEX", "DIGEST_PIN", "ORDERING_PREREQUISITE",
                         "STAGE_OR_COUNT"}

# README "The record's closed shape".
TOP_MEMBERS = {"amends", "base", "crossInputs", "deferred", "dispositions", "effectivePredecessors", "inventory",
               "moved", "notAmended", "ownerDecisions", "packet", "retained", "retiredHistory", "schemaVersion",
               "slot", "staysTrue", "supersedes", "unchanged", "workItem"}
ROW_MEMBERS = {
    "ownerDecisions": {"id", "quote", "section"},
    "crossInputs": {"path", "sha256"},
    "amends": {"packet", "path", "sha256", "supersededEntries"},
    "dispositions": {"deliverables", "disposition", "packet", "text"},
    "moved": {"fromClauses", "fromPacket", "item", "items", "status", "to"},
    "retained": {"item", "packet", "text"},
    "deferred": {"authority", "item", "sourceClauses", "status", "text"},
    "unchanged": {"id", "text"},
    "retiredHistory": {"branchModified", "dispatchable", "head", "id", "pr", "status"},
    "supersedes": {"id", "lines", "path", "quote", "replacement", "sha256"},
    "staysTrue": {"lines", "path", "quote"},
}
DELIVERABLE_MEMBERS = {"deliverable", "status"}
REPLACEMENT_MEMBERS = {"keptBy", "keptItems", "movedItems", "movedTo", "text"}
EDGE_MEMBERS = {"after", "item"}
NOT_AMENDED_MEMBERS = {"class", "path", "sha256"}
INVENTORY_MEMBERS = {"commit", "files", "pathspecs", "patterns", "searchDigest"}
CLASSED_FILE_MEMBERS = {"class", "disposition", "hitLines", "path", "sha256"}
LINES_FILE_MEMBERS = {"disposition", "hitLines", "lines", "path", "sha256"}

HEX64 = re.compile(r"^[0-9a-f]{64}$")
RANGE = re.compile(r"^[1-9][0-9]*-[1-9][0-9]*$")


def _load_record():
    return json.loads(RECORD_FILE.read_text(encoding="utf-8"))


RECORD = _load_record()


def _recorded_paths(record):
    paths = set()
    for key in ("supersedes", "staysTrue", "amends", "crossInputs"):
        paths.update(row["path"] for row in record[key])
    for key in ("pinned", "named"):
        paths.update(row["path"] for row in record["notAmended"][key])
    paths.update(row["path"] for row in record["inventory"]["files"])
    return frozenset(paths)


RECORDED = _recorded_paths(RECORD)
OWN_ROW_PATHS = RECORDED - {row["path"] for row in RECORD["crossInputs"]}
_BASE_BYTES = {}


def base_bytes(path):
    """The base bytes of a recorded path, by `git show`; no other path is ever read."""
    assert path in RECORDED, "not a recorded path: %s" % path
    if path not in _BASE_BYTES:
        _BASE_BYTES[path] = subprocess.run(["git", "-C", str(ROOT), "show", "%s:%s" % (BASE_REF, path)],
                                           capture_output=True, check=True, env=GIT_ENV).stdout
    return _BASE_BYTES[path]


def base_text(path):
    return base_bytes(path).decode("utf-8")


def sha256_hex(data):
    return hashlib.sha256(data).hexdigest()


def parse_range(text):
    first, last = text.split("-")
    return int(first), int(last)


def occurrences(text, needle):
    found, start = [], text.find(needle)
    while start != -1:
        found.append(start)
        start = text.find(needle, start + 1)
    return found


def line_starts(text):
    starts = [0]
    for line in text.split("\n"):
        starts.append(starts[-1] + len(line) + 1)
    return starts


def locate(path, lines, quote):
    """Find the quote within its cited lines: (count, absolute start, absolute end, first-byte line, last-byte line)."""
    text = base_text(path)
    all_lines = text.split("\n")
    starts = line_starts(text)
    first, last = parse_range(lines)
    window = "\n".join(all_lines[first - 1:last])
    found = occurrences(window, quote)
    if len(found) != 1 or last > len(all_lines):
        return len(found), None, None, None, None
    begin = starts[first - 1] + found[0]
    end = begin + len(quote)
    return 1, begin, end, bisect.bisect_right(starts, begin), bisect.bisect_right(starts, end - 1)


def overlaps(a, b):
    return a[0] < b[1] and b[0] < a[1]


def supersedes_paths(record):
    return {row["path"] for row in record["supersedes"]}


def oracle_hits(path, data, quoted_paths):
    """The README's declared search for one file, re-implemented from its text."""
    lines = data.decode("utf-8").split("\n")
    marks = [bool(LONG_RE.search(line) or GLUED_RE.search(line)) for line in lines]
    holds = list(marks)
    if path.endswith(".md"):
        start = 0
        while start < len(lines):
            if not lines[start].strip():
                start += 1
                continue
            end = start
            while end < len(lines) and lines[end].strip():
                end += 1
            paragraph = any(marks[start:end])
            for index in range(start, end):
                holds[index] = paragraph
            start = end
    hits = []
    for number, line in enumerate(lines, 1):
        if LONG_RE.search(line):
            hits.append(number)
        elif STANDALONE_RE.search(line) or GLUED_RE.search(line):
            if path in quoted_paths or holds[number - 1]:
                hits.append(number)
    return hits


def readme_class(path):
    """The README's class path rules, in precedence order; None for a path in no class. Rule 5's exception is
    read as written: a path below architecture/broker-handoff-inputs/ deeper than one level has no class."""
    parts = path.split("/")
    arch = parts[0] == "architecture"
    if arch and len(parts) >= 4 and parts[1] == "broker-handoff-inputs":
        return None
    if arch and len(parts) == 3 and parts[1] == "broker-handoff-inputs":
        return "INPUTS_PINNED"
    if arch and len(parts) >= 4 and fnmatch.fnmatchcase(parts[2], "round*"):
        return "ROUND_SNAPSHOT"
    if arch and len(parts) >= 2 and fnmatch.fnmatchcase(parts[-1], "review-round*.json"):
        return "REVIEW_RECORD"
    if arch and len(parts) == 2 and fnmatch.fnmatchcase(parts[1], "*-authority.json"):
        return "AUTHORITY_TEXT"
    if arch and len(parts) >= 3 and fnmatch.fnmatchcase(parts[1], "*-inputs"):
        return "INPUTS_SNAPSHOT"
    if parts[:2] == ["docs", "history"] and len(parts) == 3:
        return "HISTORY_SNAPSHOT"
    if parts[0] == "task-packets" and len(parts) == 2 and fnmatch.fnmatchcase(parts[1], "*.yaml"):
        return "MERGED_PACKET_YAML"
    if path in LINEAGE_GUIDE:
        return "LINEAGE_GUIDE"
    if path in LIVING_CATALOG:
        return "LIVING_CATALOG"
    if path in CLOSED_RECORD:
        return "CLOSED_RECORD"
    if arch and len(parts) == 2 and fnmatch.fnmatchcase(parts[1], "*.json"):
        return "RECORD_EMBEDDED_TEXT"
    return None


_HITS = {}


def recomputed_hits():
    if not _HITS:
        quoted = supersedes_paths(RECORD)
        for row in RECORD["inventory"]["files"]:
            _HITS[row["path"]] = oracle_hits(row["path"], base_bytes(row["path"]), quoted)
    return _HITS


def strictly_sorted(values):
    return all(a < b for a, b in zip(values, values[1:]))


def is_int(value):
    return isinstance(value, int) and not isinstance(value, bool)


def is_str_list(value):
    return isinstance(value, list) and all(isinstance(item, str) for item in value)


# --------------------------------------------------------------------------------------------------------------
# README first paragraph and "Inputs, by sha256 at the base"
# --------------------------------------------------------------------------------------------------------------

def test_header_values():
    """README first paragraph: schema, packet, slot, work item and the base commit."""
    assert RECORD["schemaVersion"] == SCHEMA
    assert RECORD["packet"] == PACKET
    assert RECORD["slot"] == SLOT and is_int(RECORD["slot"])
    assert RECORD["workItem"] == WORK_ITEM
    assert RECORD["base"] == BASE
    assert RECORD["inventory"]["commit"] == BASE


def test_inputs_digests_match_base_and_record():
    """README "Inputs, by sha256 at the base": each input's base sha256 has the listed prefix, and the record's
    full digests for those paths equal the base bytes' digest."""
    digests = {}
    for row in RECORD["supersedes"] + RECORD["amends"] + RECORD["crossInputs"]:
        digests.setdefault(row["path"], set()).add(row["sha256"])
    for key in ("pinned", "named"):
        for row in RECORD["notAmended"][key]:
            digests.setdefault(row["path"], set()).add(row["sha256"])
    for name, prefix in INPUT_PREFIXES.items():
        path = ABBREV[name]
        actual = sha256_hex(base_bytes(path))
        assert actual.startswith(prefix), name
        assert digests.get(path) == {actual}, name
    quoted = {row["path"] for row in RECORD["supersedes"] + RECORD["staysTrue"]}
    assert quoted <= {ABBREV[name] for name in INPUT_PREFIXES}
    assert {row["path"] for row in RECORD["crossInputs"]} == {HS53}


def test_every_record_digest_equals_base_bytes():
    """README "Not amended" ("each with its base sha256") and "Inputs": every sha256 in the record equals the
    sha256 of the path's bytes at the base."""
    rows = RECORD["supersedes"] + RECORD["amends"] + RECORD["crossInputs"] + RECORD["inventory"]["files"]
    rows += RECORD["notAmended"]["pinned"] + RECORD["notAmended"]["named"]
    for row in rows:
        assert HEX64.match(row["sha256"]), row["path"]
        assert row["sha256"] == sha256_hex(base_bytes(row["path"])), row["path"]


# --------------------------------------------------------------------------------------------------------------
# README "What moves, what R12 keeps, what is deferred, what stays unchanged"
# --------------------------------------------------------------------------------------------------------------

def test_moved_rows():
    """README "What moves": the seven moved items go to LINUX-PROBE-KIT-001, each SUPERSEDED_UNACCEPTED_HISTORY,
    with the fixed fromPacket, and each moved row lists exactly the supersedes rows that carry it."""
    moved = {row["item"]: row for row in RECORD["moved"]}
    assert set(moved) == set(FROM_PACKET)
    for item, row in moved.items():
        assert row["to"] == KIT, item
        assert row["status"] == MOVED_STATUS, item
        assert row["fromPacket"] == FROM_PACKET[item], item
        carriers = sorted(s["id"] for s in RECORD["supersedes"] if item in s["replacement"]["movedItems"])
        assert carriers, item
        assert row["items"] == carriers, item
        assert row["fromClauses"] and is_str_list(row["fromClauses"]), item


def test_retained_rows():
    """README "Retained by R12": the five kept items and their packets; no kept item is moved."""
    retained = {row["item"]: row for row in RECORD["retained"]}
    assert set(retained) == set(RETAINED_PACKETS)
    for item, row in retained.items():
        assert row["packet"] in RETAINED_PACKETS[item], item
    assert not set(retained) & set(FROM_PACKET)
    kept = {k for s in RECORD["supersedes"] for k in s["replacement"]["keptItems"]}
    assert kept <= set(retained)


def test_deferred_row():
    """README "Deferred" and "The fixed values": KAP_LEG, DEFERRED_UNOWNED, Q-LPK0-3, BH:210-214, BH:35,
    PCR:207-225; the role rule and the resource-bearing cases stay behind the leg."""
    assert len(RECORD["deferred"]) == 1
    row = RECORD["deferred"][0]
    assert {key: row[key] for key in DEFERRED_ROW} == DEFERRED_ROW
    assert "serverOwnsApiCredential" in row["text"]
    assert "resource-bearing cases" in row["text"]
    assert KAP not in {r["item"] for r in RECORD["moved"]}


def test_unchanged_rows():
    """README "Unchanged" and "The fixed values": the six unchanged ids, each naming what the README lists."""
    assert [row["id"] for row in RECORD["unchanged"]] == UNCHANGED_IDS
    for row in RECORD["unchanged"]:
        for term in UNCHANGED_TERMS[row["id"]]:
            assert term in row["text"], (row["id"], term)


# --------------------------------------------------------------------------------------------------------------
# README "The dispositions and the retired history"
# --------------------------------------------------------------------------------------------------------------

def test_packet_dispositions():
    """README "The packet dispositions": 003 CONSUMED with deliverable 1 kept and 2-4 superseded history;
    004 and 005 NOT_DISPATCHABLE_AS_WRITTEN from R12_SUCCESSOR; 006 UNCHANGED, deliverable 3 by digest."""
    rows = {row["packet"]: row for row in RECORD["dispositions"]}
    assert {packet: row["disposition"] for packet, row in rows.items()} == PACKET_DISPOSITIONS
    statuses = {d["deliverable"]: d["status"] for d in rows["CONF-LIVE-003"]["deliverables"]}
    assert statuses == {1: "KEPT_R12", 2: MOVED_STATUS, 3: MOVED_STATUS, 4: MOVED_STATUS}
    for packet in ("CONF-LIVE-004", "CONF-LIVE-005"):
        assert R12 in rows[packet]["text"], packet
    assert "deliverable 3" in rows["CONF-LIVE-006"]["text"]
    assert "by digest" in rows["CONF-LIVE-006"]["text"]
    used = {d["status"] for row in RECORD["dispositions"] for d in row["deliverables"]}
    assert used <= set(DELIVERABLE_TOKENS)


def test_retired_history():
    """README "retiredHistory": MET-REPAIR-018's retiredPacket shape exactly; CONF-FIX-007 carries 018's own
    values from completion-integration.json at the base; 008-010 are NON_DISPATCHABLE_RETAINED_HISTORY, not
    dispatchable, with pr and head null."""
    retired_packet = json.loads(base_bytes(CI_RECORD))["retiredPacket"]
    rows = RECORD["retiredHistory"]
    assert [row["id"] for row in rows] == RETIRED_IDS
    for row in rows:
        assert set(row) == set(retired_packet), row["id"]
        for key, value in retired_packet.items():
            if row[key] is not None and value is not None:
                assert type(row[key]) is type(value), (row["id"], key)
    assert rows[0] == retired_packet
    for row in rows[1:]:
        assert row["status"] == RETIRED_STATUS
        assert row["dispatchable"] is False
        assert row["pr"] is None and row["head"] is None


# --------------------------------------------------------------------------------------------------------------
# README "The supersession"
# --------------------------------------------------------------------------------------------------------------

def test_supersession_table_row_by_row():
    """README "The supersession" table, row by row: id, path and lines, quote (or its start ... end), moved items,
    movedTo, replacement text, kept items and keptBy."""
    rows = RECORD["supersedes"]
    assert len(rows) == len(README_SUPERSEDES) == 45
    for row, expected in zip(rows, README_SUPERSEDES):
        sid, name, lines, quote, moved, moved_to, text, kept = expected
        assert row["id"] == sid
        assert row["path"] == ABBREV[name], sid
        assert row["lines"] == lines, sid
        if isinstance(quote, tuple):
            start, end = quote
            assert row["quote"].startswith(start), sid
            assert row["quote"].endswith(end), sid
            assert len(row["quote"]) > len(start) + len(end), sid
        else:
            assert row["quote"] == quote, sid
        replacement = row["replacement"]
        assert replacement["movedItems"] == moved, sid
        assert replacement["movedTo"] == moved_to, sid
        assert replacement["text"] == text, sid
        assert replacement["keptItems"] == kept, sid
        assert replacement["keptBy"] == (R12 if kept else None), sid


def test_supersedes_quote_occurs_once_within_lines():
    """README "The supersession": each quote occurs exactly once within its cited lines at the base."""
    for row in RECORD["supersedes"]:
        count = locate(row["path"], row["lines"], row["quote"])[0]
        assert count == 1, row["id"]


def test_supersedes_lines_run_from_quote_first_byte_to_last():
    """README "The supersession": a row's lines run from the quote's first byte to its last, except PCR:307-313
    and COR:122-127, which keep their cited sentence ranges (the quote starts on the first cited line)."""
    reverse = {path: name for name, path in ABBREV.items()}
    exceptions = set()
    for row in RECORD["supersedes"]:
        first, last = parse_range(row["lines"])
        _, _, _, first_line, last_line = locate(row["path"], row["lines"], row["quote"])
        key = (reverse[row["path"]], row["lines"])
        assert first_line == first, row["id"]
        if key in SENTENCE_RANGES:
            assert last_line <= last, row["id"]
            if last_line < last:
                exceptions.add(key)
        else:
            assert last_line == last, row["id"]
    assert exceptions == SENTENCE_RANGES


def test_kap_leg_only_alone():
    """README "The KAP leg only ever appears alone in a row, with movedTo DEFERRED_UNOWNED"; every other row moves
    to LINUX-PROBE-KIT-001."""
    kap_rows = 0
    for row in RECORD["supersedes"]:
        replacement = row["replacement"]
        if KAP in replacement["movedItems"] or replacement["movedTo"] == DEFERRED:
            kap_rows += 1
            assert replacement["movedItems"] == [KAP], row["id"]
            assert replacement["movedTo"] == DEFERRED, row["id"]
            assert replacement["keptItems"] == [] and replacement["keptBy"] is None, row["id"]
        else:
            assert replacement["movedTo"] == KIT, row["id"]
            assert set(replacement["movedItems"]) <= set(FROM_PACKET), row["id"]
    assert kap_rows == 8


def test_gate_documents_superseded_by_quote_only():
    """README "The gate documents TLC and COR are superseded by quote only and never edited": they carry quotes,
    are no amends row and no notAmended entry, and are line-level files in the inventory."""
    files = {row["path"]: row for row in RECORD["inventory"]["files"]}
    not_amended = {row["path"] for key in ("pinned", "named") for row in RECORD["notAmended"][key]}
    for name in GATE_DOCUMENTS:
        path = ABBREV[name]
        assert path in supersedes_paths(RECORD), name
        assert path not in {row["path"] for row in RECORD["amends"]}, name
        assert path not in not_amended, name
        assert files[path]["disposition"] == "LINES", name


def test_unquoted_cells_rows_with_kept_items():
    """README "Unquoted cells": a cell that describes a kept item binds R12_SUCCESSOR on every row with keptItems;
    the README's list of those rows equals the record's rows with keptItems, in order, each kept by R12_SUCCESSOR."""
    reverse = {path: name for name, path in ABBREV.items()}
    rows = [(reverse[row["path"]], row["lines"], row["id"], row["replacement"]["keptItems"])
            for row in RECORD["supersedes"] if row["replacement"]["keptItems"]]
    assert rows == KEPT_ROWS
    for row in RECORD["supersedes"]:
        if row["replacement"]["keptItems"]:
            assert row["replacement"]["keptBy"] == R12, row["id"]


def test_completion_integration_superseded_through_amends():
    """README "completion-integration.json": its effectivePredecessors.CONF-LIVE-004 entry is superseded through
    amends; COMPLETION_INTEGRATION.md lines 258-261 restate it and the guide is a named living catalog."""
    base_record = json.loads(base_bytes(CI_RECORD))
    assert "CONF-LIVE-004" in base_record["effectivePredecessors"]
    guide = base_text(CI_GUIDE).split("\n")
    assert any("CONF-LIVE-004" in line for line in guide[257:261])
    named = {row["path"]: row["class"] for row in RECORD["notAmended"]["named"]}
    assert named.get(CI_GUIDE) == "LIVING_CATALOG"
    files = {row["path"]: row for row in RECORD["inventory"]["files"]}
    assert files[CI_GUIDE]["disposition"] == "NAMED"
    assert {258, 259, 260, 261} & set(files[CI_GUIDE]["hitLines"])


def test_amends_rows():
    """README "completion-integration.json" and "LBRM, BHA and NQA": four amends rows; only CI supersedes an
    entry (effectivePredecessors.CONF-LIVE-004), which its base record holds; each row names its record's own
    packet id at the base."""
    rows = {row["path"]: row for row in RECORD["amends"]}
    assert set(rows) == {ABBREV[name] for name in AMENDS_ENTRIES}
    for name, entries in AMENDS_ENTRIES.items():
        row = rows[ABBREV[name]]
        assert row["supersededEntries"] == entries, name
        base_record = json.loads(base_bytes(row["path"]))
        assert row["packet"] == base_record["packetId"], name
        for entry in entries:
            node = base_record
            for part in entry.split("."):
                assert isinstance(node, dict) and part in node, (name, entry)
                node = node[part]
    assert rows[ABBREV["BHA"]]["packet"] == "MET-REPAIR-014"
    assert rows[ABBREV["LBRM"]]["packet"] == "MET-LIVE-001"
    assert rows[ABBREV["CI"]]["packet"] == "MET-REPAIR-018"


# --------------------------------------------------------------------------------------------------------------
# README "Statements that stay true" and the HS53 rule
# --------------------------------------------------------------------------------------------------------------

def test_stays_true_spans_in_full():
    """README "Statements that stay true": the 12 spans, in full, each occurring once within its lines."""
    expected = [{"path": ABBREV[name], "lines": lines, "quote": quote} for name, lines, quote in README_STAYS_TRUE]
    assert RECORD["staysTrue"] == expected
    for row in RECORD["staysTrue"]:
        assert locate(row["path"], row["lines"], row["quote"])[0] == 1, (row["path"], row["lines"])


def test_no_supersedes_quote_overlaps_a_stays_true_span():
    """README "Statements that stay true": no quote may overlap these 12 spans."""
    stays = [(row["path"], locate(row["path"], row["lines"], row["quote"])[1:3]) for row in RECORD["staysTrue"]]
    shared = 0
    for row in RECORD["supersedes"]:
        span = locate(row["path"], row["lines"], row["quote"])[1:3]
        for path, stay in stays:
            if path == row["path"]:
                shared += 1
                assert not overlaps(span, stay), (row["id"], path)
    assert shared > 0


def test_no_quote_overlaps_an_hs53_supersedes_quote():
    """README "HS53": no quote overlaps an HS53 supersedes quote in the same file; the HS53 record is read by the
    path and digest the inputs table gives."""
    data = base_bytes(HS53)
    assert sha256_hex(data).startswith(INPUT_PREFIXES["HS53"])
    assert RECORD["crossInputs"] == [{"path": HS53, "sha256": sha256_hex(data)}]
    hs53_rows = json.loads(data)["supersedes"]
    ours = [(row["path"], locate(row["path"], row["lines"], row["quote"])[1:3])
            for row in RECORD["supersedes"] + RECORD["staysTrue"]]
    our_paths = {path for path, _ in ours}
    compared = 0
    for hs_row in hs53_rows:
        if hs_row["path"] not in our_paths:
            continue
        text = base_text(hs_row["path"])
        for start in occurrences(text, hs_row["quote"]):
            hs_span = (start, start + len(hs_row["quote"]))
            for path, span in ours:
                if path == hs_row["path"]:
                    compared += 1
                    assert not overlaps(span, hs_span), (path, hs_row["quote"][:40])
    assert compared > 0


# --------------------------------------------------------------------------------------------------------------
# README "The predecessor table" and "Reader duties"
# --------------------------------------------------------------------------------------------------------------

def test_predecessor_table_and_placeholders():
    """README "The predecessor table": five rows, three placeholders, R12_SUCCESSOR one unsplit placeholder, and
    no cycle."""
    edges = RECORD["effectivePredecessors"]["edges"]
    assert {edge["item"]: edge["after"] for edge in edges} == PREDECESSORS
    assert len(edges) == len(PREDECESSORS)
    assert RECORD["effectivePredecessors"]["placeholders"] == PLACEHOLDERS
    names = {edge["item"] for edge in edges} | {a for edge in edges for a in edge["after"]}
    assert [name for name in names if name.startswith(R12)] == [R12]
    graph = {edge["item"]: edge["after"] for edge in edges}
    state = {}

    def visit(node):
        assert state.get(node) != 1, "cycle at %s" % node
        if state.get(node) == 2:
            return
        state[node] = 1
        for nxt in graph.get(node, []):
            visit(nxt)
        state[node] = 2

    for node in graph:
        visit(node)


def test_owner_decisions_shape_and_cited_quotes():
    """README "Reader duties" (owner decisions; the model checks only their shape) and the decisions the README
    quotes: Q-PK-2, Q-LPK0-3 (answer and option), Q-LPK0-4 and R-S1-5."""
    rows = RECORD["ownerDecisions"]
    for row in rows:
        assert set(row) == ROW_MEMBERS["ownerDecisions"]
        assert all(isinstance(row[key], str) and row[key] for key in row)
    for decision, quote in OWNER_QUOTES:
        assert any(row["id"].split(" ")[0] == decision and row["quote"] == quote for row in rows), decision


# --------------------------------------------------------------------------------------------------------------
# README "Not amended" and the class path rules
# --------------------------------------------------------------------------------------------------------------

def test_not_amended_counts_and_class_lists():
    """README "Not amended" and "The fixed values": 47 pinned and 163 named with their per-class counts, and the
    LINEAGE_GUIDE, LIVING_CATALOG and CLOSED_RECORD lists."""
    pinned = RECORD["notAmended"]["pinned"]
    named = RECORD["notAmended"]["named"]
    assert len(pinned) == 47 and len(named) == 163
    count = {}
    for row in pinned:
        count[row["class"]] = count.get(row["class"], 0) + 1
    assert count == PINNED_COUNTS
    count = {}
    for row in named:
        count[row["class"]] = count.get(row["class"], 0) + 1
    assert count == NAMED_COUNTS
    every = pinned + named
    for name, listed in (("LINEAGE_GUIDE", LINEAGE_GUIDE), ("LIVING_CATALOG", LIVING_CATALOG),
                         ("CLOSED_RECORD", CLOSED_RECORD)):
        assert sorted(row["path"] for row in every if row["class"] == name) == sorted(listed), name
    assert not {row["path"] for row in pinned} & {row["path"] for row in named}


def test_not_amended_classes_meet_path_rules():
    """README "The class path rules, in precedence order": every notAmended entry's class is the first rule its
    exact path meets."""
    for row in RECORD["notAmended"]["pinned"] + RECORD["notAmended"]["named"]:
        assert readme_class(row["path"]) == row["class"], row["path"]


def test_model_path_class_agrees_with_readme_rules():
    """README "The class path rules": the model's path_class agrees with the rules on every recorded path and on
    precedence cases, including rule 5's exception for architecture/broker-handoff-inputs/."""
    probes = [
        "architecture/broker-handoff-inputs/x.json", "architecture/broker-handoff-inputs/x.md",
        "architecture/broker-handoff-inputs/sub/x.json", "architecture/broker-handoff-inputs/a/b/x.json",
        "architecture/handoff-inputs/sub/x.json",
        "architecture/foo/round-1/x.md", "architecture/foo/round2/review-round2.json",
        "architecture/a-inputs/round1/x.json", "architecture/foo/bar/review-round3.json",
        "architecture/foo/review-round3.json", "architecture/review-round3.json",
        "architecture/a-inputs/review-round1.json", "architecture/a-inputs/sub/x.md",
        "architecture/x-authority.json", "architecture/sub/x-authority.json", "architecture/a-inputs/x.md",
        "docs/history/x.md", "docs/history/a/b.md", "task-packets/NEW-001.yaml", "task-packets/sub/NEW-001.yaml",
        "task-packets/README.md", "docs/alpha-2/CONFORMANCE_COMPLETION.md", "architecture/completion-integration.json",
        "architecture/new-record.json", "architecture/sub/new.json", "docs/alpha-2/NEW.md", "architecture/README.md",
    ]
    for path in sorted(RECORDED) + probes:
        assert probe_kit_scope.path_class(path) == readme_class(path), path


def test_class_rule5_exception_depths():
    """README "The class path rules", rule 5: INPUTS_SNAPSHOT is architecture/*-inputs/** except
    architecture/broker-handoff-inputs/; a path there deeper than one level has no class, one level is INPUTS_PINNED
    (rule 1), and another *-inputs directory stays INPUTS_SNAPSHOT at any depth."""
    expected = {
        "architecture/broker-handoff-inputs/sub/x.json": None,
        "architecture/broker-handoff-inputs/a/b/x.json": None,
        "architecture/broker-handoff-inputs/meta-after.json": "INPUTS_PINNED",
        "architecture/handoff-inputs/sub/x.json": "INPUTS_SNAPSHOT",
        "architecture/handoff-inputs/x.json": "INPUTS_SNAPSHOT",
    }
    for path, klass in expected.items():
        assert readme_class(path) == klass, path
        assert probe_kit_scope.path_class(path) == klass, path


# --------------------------------------------------------------------------------------------------------------
# README "The inventory": the declared search, re-implemented
# --------------------------------------------------------------------------------------------------------------

def test_declared_search_values():
    """README "The declared search" and "The fixed values": the pathspecs, the two EREs, the long, standalone and
    glued forms, at the base commit."""
    inventory = RECORD["inventory"]
    assert inventory["commit"] == BASE
    assert inventory["pathspecs"] == PATHSPECS
    patterns = inventory["patterns"]
    assert set(patterns) == {"ereLong", "ereShort", "long", "standalone", "glued"}
    assert patterns["ereLong"] == ERE_LONG and patterns["long"] == ERE_LONG
    assert patterns["ereShort"] == ERE_SHORT
    assert patterns["standalone"] == STANDALONE
    assert re.compile(patterns["glued"]).pattern == patterns["glued"]
    assert patterns["glued"] == GLUED_RE.pattern
    assert ERE_SHORT.endswith("(%s)00[345]" % "|".join(GLUED_WORDS))


def test_declared_search_candidate_files():
    """README "Candidate files are the union of two git grep -l -E runs at the commit": every recorded inventory
    file is a candidate, and the long-form run finds exactly the recorded files."""
    found = []
    for pattern in (ERE_LONG, ERE_SHORT):
        out = subprocess.run(["git", "-C", str(ROOT), "grep", "-l", "-E", pattern, BASE_REF, "--"] + PATHSPECS,
                             capture_output=True, check=True, env=GIT_ENV).stdout.decode("utf-8")
        found.append({line.split(":", 1)[1] for line in out.split("\n") if line})
    inventory = {row["path"] for row in RECORD["inventory"]["files"]}
    assert found[0] == inventory
    assert inventory <= found[0] | found[1]


def test_declared_search_recomputes_every_hit_and_the_digest():
    """README "The declared search": each recorded file's hit lines, recomputed from its base bytes, equal the
    record; 278 files, 2,423 hit lines, and searchDigest is the sha256 of the compact [[path, line], ...] list."""
    files = RECORD["inventory"]["files"]
    hits = recomputed_hits()
    assert len(files) == INVENTORY_FILES
    for row in files:
        assert hits[row["path"]], row["path"]
        assert row["hitLines"] == hits[row["path"]], row["path"]
    pairs = [[path, line] for path in sorted(hits) for line in hits[path]]
    assert len(pairs) == HIT_LINES
    digest = sha256_hex(json.dumps(pairs, separators=(",", ":")).encode("utf-8"))
    assert RECORD["inventory"]["searchDigest"] == digest


def test_model_hits_for_agrees_with_the_declared_search():
    """README "The declared search": the model's hits_for returns the same hit lines as this re-implementation."""
    quoted = supersedes_paths(RECORD)
    for path, lines in recomputed_hits().items():
        assert list(probe_kit_scope.hits_for(path, base_bytes(path), quoted)) == lines, path


def test_inventory_file_dispositions():
    """README "File-level dispositions" and "LINES marks a file given line-level dispositions": notAmended files
    are PINNED or NAMED as a whole; supersedes files and hit files in no class are LINES."""
    pinned = {row["path"]: row for row in RECORD["notAmended"]["pinned"]}
    named = {row["path"]: row for row in RECORD["notAmended"]["named"]}
    quoted = supersedes_paths(RECORD)
    seen = set()
    for row in RECORD["inventory"]["files"]:
        path = row["path"]
        seen.add(path)
        if path in quoted or readme_class(path) is None:
            assert row["disposition"] == "LINES", path
            assert path not in pinned and path not in named, path
        elif path in pinned:
            assert row["disposition"] == "PINNED", path
            assert (row["class"], row["sha256"]) == (pinned[path]["class"], pinned[path]["sha256"]), path
        else:
            assert row["disposition"] == "NAMED", path
            assert path in named, path
            assert (row["class"], row["sha256"]) == (named[path]["class"], named[path]["sha256"]), path
    assert set(pinned) | set(named) <= seen
    assert quoted <= seen


def test_line_level_dispositions():
    """README "Line-level dispositions": every hit line of a LINES file has exactly one disposition from the
    vocabulary, NOT_OWNERSHIP with a listed reason, and QUOTED exactly where it lies inside a supersedes row."""
    ranges = {}
    for row in RECORD["supersedes"]:
        ranges.setdefault(row["path"], []).append(parse_range(row["lines"]))
    quoted_lines = 0
    for row in RECORD["inventory"]["files"]:
        if row["disposition"] != "LINES":
            continue
        assert [line["line"] for line in row["lines"]] == row["hitLines"], row["path"]
        for line in row["lines"]:
            assert line["disposition"] in LINE_DISPOSITIONS, (row["path"], line["line"])
            if line["disposition"] == "NOT_OWNERSHIP":
                assert line["reason"] in NOT_OWNERSHIP_REASONS, (row["path"], line["line"])
            else:
                assert "reason" not in line, (row["path"], line["line"])
            inside = any(a <= line["line"] <= b for a, b in ranges.get(row["path"], []))
            assert (line["disposition"] == "QUOTED") == inside, (row["path"], line["line"])
            quoted_lines += line["disposition"] == "QUOTED"
    assert quoted_lines > 0


# --------------------------------------------------------------------------------------------------------------
# README "The record's closed shape"
# --------------------------------------------------------------------------------------------------------------

def test_closed_shape_and_types():
    """README "The record's closed shape": every member and row type is closed, with the listed row members."""
    assert set(RECORD) == TOP_MEMBERS
    for key, members in ROW_MEMBERS.items():
        assert isinstance(RECORD[key], list), key
        for row in RECORD[key]:
            assert set(row) == members, key
    for row in RECORD["dispositions"]:
        for item in row["deliverables"]:
            assert set(item) == DELIVERABLE_MEMBERS and is_int(item["deliverable"])
    for row in RECORD["supersedes"]:
        assert set(row["replacement"]) == REPLACEMENT_MEMBERS, row["id"]
        assert RANGE.match(row["lines"]), row["id"]
        first, last = parse_range(row["lines"])
        assert first <= last, row["id"]
        assert is_str_list(row["replacement"]["movedItems"]) and is_str_list(row["replacement"]["keptItems"])
    for row in RECORD["staysTrue"]:
        assert RANGE.match(row["lines"]) and isinstance(row["quote"], str)
    for row in RECORD["retiredHistory"]:
        assert isinstance(row["branchModified"], bool) and isinstance(row["dispatchable"], bool)
        assert row["pr"] is None or is_int(row["pr"])
        assert row["head"] is None or isinstance(row["head"], str)
    predecessors = RECORD["effectivePredecessors"]
    assert set(predecessors) == {"edges", "placeholders"}
    for edge in predecessors["edges"]:
        assert set(edge) == EDGE_MEMBERS and is_str_list(edge["after"])
    assert set(RECORD["notAmended"]) == {"pinned", "named"}
    for key in ("pinned", "named"):
        for row in RECORD["notAmended"][key]:
            assert set(row) == NOT_AMENDED_MEMBERS, row["path"]
    inventory = RECORD["inventory"]
    assert set(inventory) == INVENTORY_MEMBERS
    for row in inventory["files"]:
        if row["disposition"] in ("PINNED", "NAMED"):
            assert set(row) == CLASSED_FILE_MEMBERS, row["path"]
        else:
            assert row["disposition"] == "LINES", row["path"]
            assert set(row) == LINES_FILE_MEMBERS, row["path"]
            for line in row["lines"]:
                extra = {"reason"} if line["disposition"] == "NOT_OWNERSHIP" else set()
                assert set(line) == {"disposition", "line"} | extra, (row["path"], line)
                assert is_int(line["line"])
        assert all(is_int(n) for n in row["hitLines"]), row["path"]


def test_sort_orders():
    """README "The record's closed shape", "Sorted by" column, and "every list is sorted" (no duplicate rows), with
    its two exceptions: inventory.pathspecs keeps the declared search's order, and staysTrue sorts by (path, lines
    as text, quote), so PCR's 191-191 comes before 41-41."""
    record = RECORD
    assert record["inventory"]["pathspecs"] == PATHSPECS
    pcr_lines = [r["lines"] for r in record["staysTrue"] if r["path"] == ABBREV["PCR"]]
    assert pcr_lines.index("191-191") < pcr_lines.index("41-41")
    assert strictly_sorted([(r["id"], r["quote"]) for r in record["ownerDecisions"]])
    for key in ("crossInputs", "amends"):
        assert strictly_sorted([r["path"] for r in record[key]]), key
    assert strictly_sorted([r["packet"] for r in record["dispositions"]])
    for row in record["dispositions"]:
        assert strictly_sorted([d["deliverable"] for d in row["deliverables"]])
    assert strictly_sorted([r["item"] for r in record["moved"]])
    for row in record["moved"]:
        assert strictly_sorted(row["fromClauses"]) and strictly_sorted(row["items"]), row["item"]
    for key in ("retained", "deferred"):
        assert strictly_sorted([r["item"] for r in record[key]]), key
    for row in record["deferred"]:
        assert strictly_sorted(row["sourceClauses"])
    assert strictly_sorted([r["id"] for r in record["unchanged"]])
    assert strictly_sorted([r["id"] for r in record["retiredHistory"]])
    assert strictly_sorted([(r["path"], parse_range(r["lines"])[0], r["quote"]) for r in record["supersedes"]])
    assert [r["id"] for r in record["supersedes"]] == ["S-%02d" % n for n in range(1, 46)]
    for row in record["supersedes"]:
        replacement = row["replacement"]
        assert strictly_sorted(replacement["movedItems"]) and strictly_sorted(replacement["keptItems"]), row["id"]
    for row in record["amends"]:
        assert strictly_sorted(row["supersededEntries"])
    assert strictly_sorted([(r["path"], r["lines"], r["quote"]) for r in record["staysTrue"]])
    edges = record["effectivePredecessors"]["edges"]
    assert strictly_sorted([e["item"] for e in edges])
    for edge in edges:
        assert strictly_sorted(edge["after"]), edge["item"]
    assert strictly_sorted(record["effectivePredecessors"]["placeholders"])
    for key in ("pinned", "named"):
        assert strictly_sorted([r["path"] for r in record["notAmended"][key]]), key
    files = record["inventory"]["files"]
    assert strictly_sorted([r["path"] for r in files])
    for row in files:
        assert strictly_sorted(row["hitLines"]), row["path"]
        if row["disposition"] == "LINES":
            assert strictly_sorted([line["line"] for line in row["lines"]]), row["path"]


# --------------------------------------------------------------------------------------------------------------
# The model, black-box
# --------------------------------------------------------------------------------------------------------------

def test_model_fixed_constants_equal_readme():
    """README "The fixed values" and "The fixed tables": the model's public constants hold the README's values."""
    m = probe_kit_scope
    assert m.SCHEMA == SCHEMA and m.KIT == KIT and m.DEFERRED == DEFERRED and m.KAP_LEG == KAP
    assert m.BASE == BASE and m.PATHSPECS == PATHSPECS
    assert m.PATTERNS == RECORD["inventory"]["patterns"]
    assert m.LONG.pattern == ERE_LONG and m.STANDALONE.pattern == STANDALONE
    assert m.GLUED.pattern == GLUED_RE.pattern
    assert m.MOVED_FROM == FROM_PACKET and set(m.MOVED_ITEMS) == set(FROM_PACKET)
    assert set(m.RETAINED_ITEMS) == set(RETAINED_PACKETS)
    assert m.PACKET_DISPOSITIONS == PACKET_DISPOSITIONS
    assert set(m.DELIVERABLE_STATUSES) == set(DELIVERABLE_TOKENS)
    assert list(m.UNCHANGED_IDS) == UNCHANGED_IDS
    assert m.DEFERRED_ROW == DEFERRED_ROW
    assert list(m.RETIRED_IDS) == RETIRED_IDS and m.RETIRED_STATUS == RETIRED_STATUS
    assert set(m.RETIRED_KEYS) == set(json.loads(base_bytes(CI_RECORD))["retiredPacket"])
    assert m.COMPLETION_INTEGRATION == CI_RECORD
    assert list(m.PLACEHOLDERS) == PLACEHOLDERS and m.R12_SUCCESSOR == R12
    assert set(m.CLASSES) == set(PINNED_COUNTS) | set(NAMED_COUNTS)
    assert set(m.PINNED_CLASSES) == set(PINNED_COUNTS)
    assert list(m.CLOSED_RECORDS) == CLOSED_RECORD
    assert list(m.LINEAGE_GUIDES) == LINEAGE_GUIDE
    assert list(m.LIVING_CATALOGS) == LIVING_CATALOG
    assert set(m.LINE_DISPOSITIONS) == LINE_DISPOSITIONS
    assert set(m.NOT_OWNERSHIP_REASONS) == NOT_OWNERSHIP_REASONS
    assert set(m.MEMBERS) == TOP_MEMBERS
    assert m.HS53 == HS53 and tuple(m.CROSS_INPUTS) == (HS53,)
    assert set(m.SENTENCE_RANGES) == {(ABBREV[name], lines) for name, lines in SENTENCE_RANGES}
    assert [(item, list(after)) for item, after in m.PINNED_EDGES] == sorted(PREDECESSORS.items())
    expected_amends = sorted((ABBREV[name], json.loads(base_bytes(ABBREV[name]))["packetId"], entries)
                             for name, entries in AMENDS_ENTRIES.items())
    assert [(path, packet, list(entries)) for path, packet, entries in m.PINNED_AMENDS] == expected_amends
    assert len(m.PINNED_SUPERSEDES) == 45 and len(m.PINNED_STAYS) == 12


def test_model_accepts_the_adopted_record():
    """README "The fixed values" ("the model checks each one"): check(record, read, changed, gate) is [] for the
    adopted record."""
    assert probe_kit_scope.check(copy.deepcopy(RECORD), base_bytes, [], []) == []


def test_model_reads_only_recorded_paths():
    """README "The model and the layer read only the recorded paths, at the base" and "HS53 ... is the one file
    the model reads beyond the record's own rows"."""
    seen = []

    def read(path):
        seen.append(path)
        return base_bytes(path)

    assert probe_kit_scope.check(copy.deepcopy(RECORD), read, [], []) == []
    assert set(seen) <= RECORDED
    assert set(seen) - OWN_ROW_PATHS == {HS53}


def test_model_accepts_named_and_unrelated_changed_files():
    """README "The changed files": only supersedes, amends, pinned, crossInputs and gate paths are refused; a
    named (governed, not byte-checked) file and an unrelated file may change."""
    changed = ["docs/DEVELOPMENT_STATUS.md", "architecture/accounting-scope-authority.json", "docs/NEW_NOTE.md"]
    assert probe_kit_scope.check(copy.deepcopy(RECORD), base_bytes, changed, []) == []


MUTATIONS = []


def mutation(name, rule, *expected):
    def register(func):
        MUTATIONS.append((name, rule, expected, func))
        return func
    return register


def srow(record, sid):
    return next(row for row in record["supersedes"] if row["id"] == sid)


def mrow(record, item):
    return next(row for row in record["moved"] if row["item"] == item)


def first_file(record, predicate):
    return next(row for row in record["inventory"]["files"] if predicate(row))


@mutation("moved-item-also-kept", "a moved item kept", "replacement", "vocabulary", "pinnedTable")
def _m01(rec):
    row = srow(rec, "S-41")["replacement"]
    row["keptItems"], row["keptBy"] = ["SERVER"], R12


@mutation("moved-item-returned-to-r12", "a moved item kept", "replacement", "vocabulary", "pinnedTable", "link")
def _m02(rec):
    row = srow(rec, "S-07")["replacement"]
    row["movedItems"], row["keptItems"] = ["ADMISSION_MODULE", "UID_LEDGER"], ["CLIENT", "SERVER"]


@mutation("kap-leg-moved-to-kit", "the KAP leg moved", "kap")
def _m03(rec):
    srow(rec, "S-13")["replacement"]["movedTo"] = KIT


@mutation("kap-leg-mixed-with-item", "the KAP leg moved", "kap")
def _m04(rec):
    srow(rec, "S-13")["replacement"]["movedItems"] = [KAP, "UID_LEDGER"]


@mutation("kap-leg-listed-as-moved", "the KAP leg moved", "kap", "vocabulary", "pinnedTable")
def _m05(rec):
    rec["moved"].append({"fromClauses": ["BH:35"], "fromPacket": "CONF-LIVE-003", "item": KAP, "items": ["S-13"],
                         "status": MOVED_STATUS, "to": KIT})
    rec["moved"].sort(key=lambda row: row["item"])


@mutation("supersedes-row-dropped", "a dropped or added row", "pinnedTable")
def _m06(rec):
    rec["supersedes"] = [row for row in rec["supersedes"] if row["id"] != "S-45"]


@mutation("supersedes-row-added", "a dropped or added row", "pinnedTable")
def _m07(rec):
    s45 = srow(rec, "S-45")
    rec["supersedes"].append({"id": "S-46", "path": s45["path"], "sha256": s45["sha256"], "lines": "313-313",
                              "quote": "exact-UID cleanup",
                              "replacement": {"text": "The exact-UID cleanup is LINUX-PROBE-KIT-001's.",
                                              "movedItems": ["UID_LEDGER"], "movedTo": KIT, "keptItems": [],
                                              "keptBy": None}})
    mrow(rec, "UID_LEDGER")["items"].append("S-46")


@mutation("stays-true-row-dropped", "a dropped or added row", "pinnedTable")
def _m08(rec):
    rec["staysTrue"].pop()


@mutation("amends-row-dropped", "a dropped or added row", "pinnedTable", "amends")
def _m09(rec):
    rec["amends"] = [row for row in rec["amends"] if row["path"] != ABBREV["LBRM"]]


@mutation("quote-overlaps-stays-true", "an overlap", "overlap")
def _m10(rec):
    srow(rec, "S-08")["quote"] = "fixed probes, packaging and"


@mutation("quote-overlaps-hs53", "an overlap", "hs53")
def _m11(rec):
    srow(rec, "S-35")["quote"] = "Client/server candidate packaging and handoff | Documents the observer"


@mutation("two-quotes-overlap", "an overlap", "spans")
def _m12(rec):
    srow(rec, "S-12")["quote"] = "leg, UID ledger and cleanup"


@mutation("pinned-yaml-edited", "a pinned file edited", "pinned")
def _m13(rec):
    return ["task-packets/CONF-LIVE-004.yaml"], []


@mutation("cross-input-edited", "a pinned file edited (crossInputs)", "pinned")
def _m14(rec):
    return [HS53], []


@mutation("cross-input-edited-casefolded", "a pinned file edited (crossInputs, case-folded)", "pinned")
def _m15(rec):
    return ["ARCHITECTURE/Host-Interface-Amendment-HS53/AMENDMENT.JSON"], []


@mutation("supersedes-file-edited-casefolded", "a pinned file edited (case-folded)", "pinned")
def _m16(rec):
    return ["Docs/Alpha-2/Broker_Handoff_Readiness.MD"], []


@mutation("gate-document-edited", "a pinned file edited (gate document)", "pinned")
def _m17(rec):
    return [ABBREV["TLC"]], []


@mutation("amends-record-edited-casefolded", "a pinned file edited (amends, case-folded)", "pinned")
def _m18(rec):
    return ["architecture/Completion-Integration.json"], []


@mutation("gate-path-changed", "a gate path", "gate")
def _m19(rec):
    return ["docs/alpha-2/GATE_EXAMPLE.md"], ["docs/alpha-2/GATE_EXAMPLE.md"]


@mutation("classed-file-filed-line-level", "a classed file filed line-level", "lineFile")
def _m20(rec):
    row = first_file(rec, lambda f: f["disposition"] == "NAMED")
    rec["notAmended"]["named"] = [e for e in rec["notAmended"]["named"] if e["path"] != row["path"]]
    del row["class"]
    row["disposition"] = "LINES"
    row["lines"] = [{"disposition": "NOT_OWNERSHIP", "line": n, "reason": "STATUS_LINE"} for n in row["hitLines"]]


@mutation("covered-line-not-quoted", "a covered line not QUOTED", "covered")
def _m21(rec):
    row = first_file(rec, lambda f: f["disposition"] == "LINES"
                     and any(line["disposition"] == "QUOTED" for line in f["lines"]))
    index = next(i for i, line in enumerate(row["lines"]) if line["disposition"] == "QUOTED")
    row["lines"][index] = {"disposition": "UNCHANGED_TRUE", "line": row["lines"][index]["line"]}


@mutation("quoted-line-outside-rows", "a covered line not QUOTED (QUOTED outside a row)", "disposition")
def _m22(rec):
    quoted = supersedes_paths(rec)
    row = first_file(rec, lambda f: f["disposition"] == "LINES" and f["path"] not in quoted)
    row["lines"][0] = {"disposition": "QUOTED", "line": row["lines"][0]["line"]}


@mutation("unsorted-not-amended", "an unsorted list", "order")
def _m23(rec):
    pinned = rec["notAmended"]["pinned"]
    pinned[0], pinned[1] = pinned[1], pinned[0]


@mutation("unsorted-moved-items", "an unsorted list", "order")
def _m24(rec):
    mrow(rec, "SERVER")["items"].reverse()


@mutation("unsorted-supersedes", "an unsorted list", "order")
def _m25(rec):
    rows = rec["supersedes"]
    index = next(i for i, row in enumerate(rows) if row["id"] == "S-11")
    rows[index], rows[index + 1] = rows[index + 1], rows[index]
    rows[index]["id"], rows[index + 1]["id"] = "S-11", "S-12"


@mutation("duplicate-stays-true-row", "an unsorted list (duplicate row)", "order")
def _m26(rec):
    rec["staysTrue"].insert(1, copy.deepcopy(rec["staysTrue"][0]))


@mutation("extra-top-member", "an extra member", "shape")
def _m27(rec):
    rec["adoption"] = "ADOPTED"


@mutation("extra-row-member", "an extra member", "shape")
def _m28(rec):
    srow(rec, "S-01")["note"] = "extra"


@mutation("extra-line-row-member", "an extra member", "shape", "disposition")
def _m29(rec):
    row = first_file(rec, lambda f: f["disposition"] == "LINES")
    row["lines"][0]["note"] = "extra"


@mutation("wrong-type-slot", "a wrong type", "shape")
def _m30(rec):
    rec["slot"] = "260"


@mutation("wrong-type-quote", "a wrong type", "shape")
def _m31(rec):
    srow(rec, "S-01")["quote"] = [srow(rec, "S-01")["quote"]]


@mutation("wrong-type-deliverable", "a wrong type", "shape")
def _m32(rec):
    rec["dispositions"][0]["deliverables"][0]["deliverable"] = "1"


@mutation("wrong-type-replacement", "a wrong type", "shape")
def _m32b(rec):
    srow(rec, "S-02")["replacement"] = srow(rec, "S-02")["replacement"]["text"]


@mutation("wrong-type-placeholders", "a wrong type", "shape")
def _m32c(rec):
    rec["effectivePredecessors"]["placeholders"] = " ".join(PLACEHOLDERS)


@mutation("wrong-type-hit-line", "a wrong type", "shape")
def _m33(rec):
    row = first_file(rec, lambda f: f["disposition"] == "NAMED")
    row["hitLines"][0] = str(row["hitLines"][0])


@mutation("changed-base", "a changed base", "pinnedTable")
def _m34(rec):
    rec["base"] = "f" * 40


@mutation("changed-inventory-commit", "a changed base", "pinnedTable", "shape")
def _m35(rec):
    rec["inventory"]["commit"] = "f" * 40


@mutation("changed-standalone-pattern", "a changed pattern", "pinnedTable")
def _m36(rec):
    rec["inventory"]["patterns"]["standalone"] = r"(?<![\w.:-])00[345](?!\w)"


@mutation("changed-ere-short", "a changed pattern", "pinnedTable")
def _m37(rec):
    rec["inventory"]["patterns"]["ereShort"] = ERE_SHORT.replace("|Native", "")


@mutation("changed-pathspecs", "a changed pattern", "pinnedTable")
def _m38(rec):
    rec["inventory"]["pathspecs"].remove(":!tools")


@mutation("moved-row-unlinked", "a moved item kept (link)", "link")
def _m39(rec):
    mrow(rec, "SERVER")["items"].remove("S-45")


@mutation("disposition-changed", "the dispositions", "dispositions")
def _m40(rec):
    next(r for r in rec["dispositions"] if r["packet"] == "CONF-LIVE-006")["disposition"] = "CONSUMED"


@mutation("deliverable-status-changed", "the dispositions", "dispositions")
def _m41(rec):
    rec["dispositions"][0]["deliverables"][0]["status"] = MOVED_STATUS


@mutation("retired-pr-added", "retiredHistory", "retired")
def _m42(rec):
    rec["retiredHistory"][1]["pr"] = 7


@mutation("retired-007-head-changed", "retiredHistory", "retired")
def _m43(rec):
    rec["retiredHistory"][0]["head"] = "0" * 40


@mutation("predecessor-cycle", "the predecessor table", "predecessors", "pinnedTable")
def _m44(rec):
    edges = rec["effectivePredecessors"]["edges"]
    edges.append({"item": "MET-LIVE-002", "after": ["CONF-LIVE-006"]})
    edges.sort(key=lambda edge: edge["item"])


@mutation("placeholder-split", "the predecessor table (R12_SUCCESSOR unsplit)", "predecessors", "pinnedTable",
          "vocabulary", "shape")
def _m45(rec):
    rec["effectivePredecessors"]["placeholders"].append("R12_SUCCESSOR_B")


@mutation("amends-unheld-entry", "the amends rows", "amends", "pinnedTable")
def _m46(rec):
    next(r for r in rec["amends"] if r["path"] == CI_RECORD)["supersededEntries"] = [
        "effectivePredecessors.CONF-LIVE-005"]


@mutation("pinned-sha-wrong", "a changed base (digest)", "sha")
def _m47(rec):
    rec["notAmended"]["pinned"][0]["sha256"] = "0" * 64


@mutation("supersedes-sha-wrong", "a changed base (digest)", "sha")
def _m48(rec):
    srow(rec, "S-01")["sha256"] = "0" * 64


@mutation("cross-input-sha-wrong", "a changed base (crossInputs digest)", "sha")
def _m49(rec):
    rec["crossInputs"][0]["sha256"] = "0" * 64


@mutation("inventory-hit-dropped", "the declared search", "inventory")
def _m50(rec):
    row = first_file(rec, lambda f: f["disposition"] == "NAMED" and len(f["hitLines"]) > 1)
    row["hitLines"].pop()


@mutation("search-digest-wrong", "the declared search", "digest")
def _m51(rec):
    rec["inventory"]["searchDigest"] = "0" * 64


@mutation("reason-outside-vocabulary", "line-level dispositions", "vocabulary", "disposition")
def _m52(rec):
    row = first_file(rec, lambda f: f["disposition"] == "LINES"
                     and any(line["disposition"] == "NOT_OWNERSHIP" for line in f["lines"]))
    next(line for line in row["lines"] if line["disposition"] == "NOT_OWNERSHIP")["reason"] = "OTHER_REASON"


@mutation("moved-status-outside-vocabulary", "a wrong value", "vocabulary")
def _m53(rec):
    mrow(rec, "SERVER")["status"] = "MOVED"


@mutation("file-in-two-places", "a classed file filed twice", "twice", "class")
def _m54(rec):
    entry = dict(next(e for e in rec["notAmended"]["pinned"] if e["path"] == "architecture/backend-timing.json"))
    entry["class"] = "RECORD_EMBEDDED_TEXT"
    rec["notAmended"]["named"].append(entry)
    rec["notAmended"]["named"].sort(key=lambda e: e["path"])


@mutation("class-rule-failed", "the class path rules with precedence", "class")
def _m55(rec):
    entry = next(e for e in rec["notAmended"]["named"] if e["class"] == "AUTHORITY_TEXT")
    entry["class"] = "RECORD_EMBEDDED_TEXT"
    first_file(rec, lambda f: f["path"] == entry["path"])["class"] = "RECORD_EMBEDDED_TEXT"


@mutation("unchanged-id-dropped", "the unchanged ids", "unchanged")
def _m56(rec):
    rec["unchanged"] = [row for row in rec["unchanged"] if row["id"] != "WORKER_ENTRY_NAME"]


@mutation("worker-entry-name-changed", "the unchanged ids", "unchanged")
def _m57(rec):
    row = next(r for r in rec["unchanged"] if r["id"] == "WORKER_ENTRY_NAME")
    row["text"] = row["text"].replace("live_fixed_probes.broker_worker_main", "kit_probes.worker_main")


@mutation("quote-outside-lines", "the quote occurs once within its lines", "quote")
def _m58(rec):
    srow(rec, "S-41")["lines"] = "175-175"


@mutation("lines-not-tight", "lines run from the quote's first byte to its last", "lines")
def _m59(rec):
    srow(rec, "S-41")["lines"] = "173-174"


@mutation("sentence-range-on-another-row", "lines run from the quote's first byte to its last", "lines")
def _m60(rec):
    srow(rec, "S-43")["lines"] = "190-192"


@mutation("stays-true-quote-changed", "the 12 stays-true spans", "pinnedTable")
def _m61(rec):
    next(r for r in rec["staysTrue"] if r["lines"] == "191-191")["quote"] = "No new root key or signature role"


@mutation("from-packet-changed", "fromPacket", "pinnedTable")
def _m62(rec):
    mrow(rec, "WORKER_ENTRY")["fromPacket"] = "CONF-LIVE-003"


@mutation("deferred-authority-changed", "the deferred row", "pinnedTable", "kap")
def _m63(rec):
    rec["deferred"][0]["authority"] = "Q-LPK0-4"


@mutation("owner-decision-missing-section", "owner decisions' shape", "shape")
def _m64(rec):
    del rec["ownerDecisions"][0]["section"]


def run_mutation(func):
    record = copy.deepcopy(RECORD)
    returned = func(record)
    changed, gate = returned if returned else ([], [])
    return probe_kit_scope.check(record, base_bytes, changed, gate)


@pytest.mark.parametrize("name,rule,expected,func", MUTATIONS, ids=[m[0] for m in MUTATIONS])
def test_model_refuses_mutation(name, rule, expected, func):
    """README rules, one mutation each (the author's own): each is refused with a text from
    probe_kit_scope.R's values, including the refusal that names the broken rule. A wrong type refuses with the
    shape text (README "The record's closed shape")."""
    result = run_mutation(func)
    texts = set(probe_kit_scope.R.values())
    assert result, name
    assert set(result) <= texts, (name, result)
    assert any(probe_kit_scope.R[key] in result for key in expected), (name, result)
    if rule == "a wrong type":
        assert probe_kit_scope.R["shape"] in result, (name, result)


def test_mutations_cover_every_readme_rule():
    """Brief coverage: at least 15 mutations, covering each README rule the brief lists."""
    rules = {rule for _, rule, _, _ in MUTATIONS}
    required = ["a moved item kept", "the KAP leg moved", "a dropped or added row", "an overlap",
                "a pinned file edited", "a pinned file edited (crossInputs)",
                "a pinned file edited (crossInputs, case-folded)", "a classed file filed line-level",
                "a covered line not QUOTED", "an unsorted list", "an extra member", "a wrong type", "a changed base",
                "a changed pattern", "a gate path"]
    assert len(MUTATIONS) >= 15
    for rule in required:
        assert rule in rules, rule


# --------------------------------------------------------------------------------------------------------------
# README "The record's closed shape": exact types and forms refuse with the shape text alone
# --------------------------------------------------------------------------------------------------------------

SHAPE_TEXT = "the record's shape is not the closed shape"
RECORD_TEXT = RECORD_FILE.read_text(encoding="utf-8")

# Wrong values for each type the README's closed-shape table and fixed values give a member. Bool and int are kept
# apart ("0 is not false"); lines ("first-last"), digests (64 hex) and commits (40 hex) have fixed forms.
WRONG = {
    "str": [1, None],
    "int": ["1", True, 1.0],
    "bool": ["false", 0, 1],
    "list": ["x", {}],
    "object": [[], "x"],
    "row": ["x", []],
    "commit": [1, BASE_REF, "g" * 40, BASE + "0"],
    "digest": [1, "0" * 63, "g" * 64, "0" * 65],
    "lines": [133, "133", "133-133-133", "a-b", "133-"],
    "str|null": [0, [R12]],
    "int|null": ["18", True, 18.0],
    "commit|null": [0, "25fab12c", "g" * 40],
    "str item": [1, None],
    "int item": ["1", True],
}


def _index(rows, predicate):
    return next(i for i, row in enumerate(rows) if predicate(row))


_FILES = RECORD["inventory"]["files"]
_CLASSED = _index(_FILES, lambda f: f["disposition"] in ("PINNED", "NAMED"))
_LINES = _index(_FILES, lambda f: f["disposition"] == "LINES")
_NOT_OWN = _index(_FILES, lambda f: f["disposition"] == "LINES"
                  and any(line["disposition"] == "NOT_OWNERSHIP" for line in f["lines"]))
_NOT_OWN_LINE = _index(_FILES[_NOT_OWN]["lines"], lambda line: line["disposition"] == "NOT_OWNERSHIP")
_KEPT = _index(RECORD["supersedes"], lambda row: row["replacement"]["keptBy"] is not None)
_ENTRY = _index(RECORD["amends"], lambda row: row["supersededEntries"])


def _fields():
    fields = [(("schemaVersion",), "str"), (("packet",), "str"), (("workItem",), "str"), (("slot",), "int"),
              (("base",), "commit")]
    for key in ("amends", "crossInputs", "deferred", "dispositions", "moved", "ownerDecisions", "retained",
                "retiredHistory", "staysTrue", "supersedes", "unchanged"):
        fields += [((key,), "list"), ((key, 0), "row")]
    fields += [(("effectivePredecessors",), "object"), (("inventory",), "object"), (("notAmended",), "object")]
    fields += [(("ownerDecisions", 0, key), "str") for key in ("id", "quote", "section")]
    fields += [(("crossInputs", 0, "path"), "str"), (("crossInputs", 0, "sha256"), "digest")]
    fields += [(("amends", 0, "packet"), "str"), (("amends", 0, "path"), "str"), (("amends", 0, "sha256"), "digest"),
               (("amends", 0, "supersededEntries"), "list"), (("amends", _ENTRY, "supersededEntries", 0), "str item")]
    d = ("dispositions", 0)
    fields += [(d + ("deliverables",), "list"), (d + ("deliverables", 0), "row"),
               (d + ("deliverables", 0, "deliverable"), "int"), (d + ("deliverables", 0, "status"), "str"),
               (d + ("disposition",), "str"), (d + ("packet",), "str"), (d + ("text",), "str")]
    m = ("moved", 0)
    fields += [(m + ("fromClauses",), "list"), (m + ("fromClauses", 0), "str item"), (m + ("fromPacket",), "str"),
               (m + ("item",), "str"), (m + ("items",), "list"), (m + ("items", 0), "str item"),
               (m + ("status",), "str"), (m + ("to",), "str")]
    fields += [(("retained", 0, key), "str") for key in ("item", "packet", "text")]
    fields += [(("deferred", 0, key), "str") for key in ("authority", "item", "status", "text")]
    fields += [(("deferred", 0, "sourceClauses"), "list"), (("deferred", 0, "sourceClauses", 0), "str item")]
    fields += [(("unchanged", 0, key), "str") for key in ("id", "text")]
    for index in (0, 1):
        r = ("retiredHistory", index)
        fields += [(r + ("branchModified",), "bool"), (r + ("dispatchable",), "bool"),
                   (r + ("head",), "commit|null"), (r + ("pr",), "int|null")]
    fields += [(("retiredHistory", 0, "id"), "str"), (("retiredHistory", 0, "status"), "str")]
    s = ("supersedes", 0)
    fields += [(s + ("id",), "str"), (s + ("lines",), "lines"), (s + ("path",), "str"), (s + ("quote",), "str"),
               (s + ("replacement",), "object"), (s + ("sha256",), "digest")]
    rp = s + ("replacement",)
    fields += [(rp + ("keptBy",), "str|null"), (rp + ("keptItems",), "list"), (rp + ("movedItems",), "list"),
               (rp + ("movedItems", 0), "str item"), (rp + ("movedTo",), "str"), (rp + ("text",), "str")]
    kp = ("supersedes", _KEPT, "replacement")
    fields += [(kp + ("keptBy",), "str|null"), (kp + ("keptItems", 0), "str item")]
    fields += [(("staysTrue", 0, "lines"), "lines"), (("staysTrue", 0, "path"), "str"),
               (("staysTrue", 0, "quote"), "str")]
    e = ("effectivePredecessors",)
    fields += [(e + ("edges",), "list"), (e + ("placeholders",), "list"), (e + ("placeholders", 0), "str item"),
               (e + ("edges", 0), "row"), (e + ("edges", 0, "after"), "list"), (e + ("edges", 0, "after", 0), "str item"),
               (e + ("edges", 0, "item"), "str")]
    for key in ("pinned", "named"):
        n = ("notAmended", key)
        fields += [(n, "list"), (n + (0,), "row"), (n + (0, "class"), "str"), (n + (0, "path"), "str"),
                   (n + (0, "sha256"), "digest")]
    i = ("inventory",)
    fields += [(i + ("commit",), "commit"), (i + ("files",), "list"), (i + ("pathspecs",), "list"),
               (i + ("pathspecs", 0), "str item"), (i + ("patterns",), "object"), (i + ("searchDigest",), "digest")]
    c = ("inventory", "files", _CLASSED)
    fields += [(c, "row"), (c + ("class",), "str"), (c + ("disposition",), "str"), (c + ("hitLines",), "list"),
               (c + ("hitLines", 0), "int item"), (c + ("path",), "str"), (c + ("sha256",), "digest")]
    f = ("inventory", "files", _LINES)
    fields += [(f + ("disposition",), "str"), (f + ("hitLines",), "list"), (f + ("hitLines", 0), "int item"),
               (f + ("lines",), "list"), (f + ("lines", 0), "row"), (f + ("lines", 0, "disposition"), "str"),
               (f + ("lines", 0, "line"), "int"), (f + ("path",), "str"), (f + ("sha256",), "digest")]
    fields.append((("inventory", "files", _NOT_OWN, "lines", _NOT_OWN_LINE, "reason"), "str"))
    return fields


def _get(record, path):
    node = record
    for key in path:
        node = node[key]
    return node


def _set(record, path, value):
    _get(record, path[:-1])[path[-1]] = value


WRONG_CASES = []
for _path, _kind in _fields():
    for _number, _value in enumerate(WRONG[_kind]):
        _label = "%s=%s#%d" % (".".join(str(part) for part in _path), _kind.replace(" ", "-"), _number)
        WRONG_CASES.append((_label, _path, _kind, _value))


def test_shape_text_is_the_models_shape_refusal():
    """README "The record's closed shape": the shape text is R's shape value."""
    assert probe_kit_scope.R["shape"] == SHAPE_TEXT


def test_wrong_type_cases_cover_every_closed_shape_member():
    """README "The record's closed shape": the wrong-type cases name every member the table lists, and every case
    really changes the value's type or form."""
    named = set(TOP_MEMBERS)
    for members in ROW_MEMBERS.values():
        named |= members
    named |= DELIVERABLE_MEMBERS | REPLACEMENT_MEMBERS | EDGE_MEMBERS | NOT_AMENDED_MEMBERS | INVENTORY_MEMBERS
    named |= CLASSED_FILE_MEMBERS | LINES_FILE_MEMBERS | {"disposition", "line", "reason", "pinned", "named",
                                                          "edges", "placeholders"}
    covered = {part for _, path, _, _ in WRONG_CASES for part in path if isinstance(part, str)}
    assert named <= covered, sorted(named - covered)
    labels = [label for label, _, _, _ in WRONG_CASES]
    assert len(labels) == len(set(labels))
    for label, path, _, value in WRONG_CASES:
        original = _get(RECORD, path)
        assert type(original) is not type(value) or original != value, label


@pytest.mark.parametrize("label,path,kind,value", WRONG_CASES, ids=[case[0] for case in WRONG_CASES])
def test_model_refuses_wrong_type_or_form_with_shape_text_alone(label, path, kind, value):
    """README "The record's closed shape": every member has an exact type, with bool and int kept apart (0 is not
    false), and lines, digests and commits have fixed forms; a member of the wrong type or form refuses with the
    shape text alone. The types come from the README's closed-shape table and fixed values."""
    record = json.loads(RECORD_TEXT)
    _set(record, path, value)
    assert probe_kit_scope.check(record, base_bytes, [], []) == [SHAPE_TEXT], label
