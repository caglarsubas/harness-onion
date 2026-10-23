"""The probe-kit scope amendment's reference model (MET-LIVE-002; DESIGN rev 3 section 5 with BUILD_RULES S3-1..S3-17).

Standard library only. `check(record, read, changed_files, gate_paths)` returns the sorted list of refusal texts (empty when
the record holds). `read(path)` returns a file's bytes at the record's base commit, or None. The model never lists a
directory and reads only through `read`. The head layer binds `read` git-free (MON-260-READ (a)): each recorded path
from the tree, bound by the record's sha256, with 259's recorded reverse hunks applied to the three living catalogs; the
head layer's test compares each read with `git show <base>:<path>` (S3-17).
"""

import hashlib
import json
import re

SCHEMA = "planeon.internal.probe-kit-scope/v1"
KIT = "LINUX-PROBE-KIT-001"
DEFERRED = "DEFERRED_UNOWNED"
R12_SUCCESSOR = "R12_SUCCESSOR"
MOVED_ITEMS = ("ADMISSION_MODULE", "CASE_RECIPES", "RECEIPT_CANDIDATES", "RECORD_INSPECTOR", "SERVER", "UID_LEDGER",
               "WORKER_ENTRY")
KAP_LEG = "KAP_LEG"
RETAINED_ITEMS = ("CANDIDATE_HANDOFF", "CLIENT", "EVIDENCE_VERIFICATION", "R12_OTHER", "RECEIPT_VERIFICATION")
PACKET_DISPOSITIONS = {"CONF-LIVE-003": "CONSUMED", "CONF-LIVE-004": "NOT_DISPATCHABLE_AS_WRITTEN",
                       "CONF-LIVE-005": "NOT_DISPATCHABLE_AS_WRITTEN", "CONF-LIVE-006": "UNCHANGED"}
DELIVERABLE_STATUSES = ("KEPT_R12", "SUPERSEDED_UNACCEPTED_HISTORY")
UNCHANGED_IDS = ("CONF_LIVE_006_PATHS", "INSTALLED_IDENTITIES", "ROLES", "SIGNING_DUTIES", "WIRE_AND_BINDING",
                 "WORKER_ENTRY_NAME")
RETIRED_KEYS = ("branchModified", "dispatchable", "head", "id", "pr", "status")
RETIRED_IDS = ("CONF-FIX-007", "CONF-FIX-008", "CONF-FIX-009", "CONF-FIX-010")
RETIRED_STATUS = "NON_DISPATCHABLE_RETAINED_HISTORY"
COMPLETION_INTEGRATION = "architecture/completion-integration.json"
HS53 = "architecture/host-interface-amendment-hs53/amendment.json"
PLACEHOLDERS = ("EVOLUTION_SURFACE_GATE_PACKET", "NEUTRAL_INTERFACE_CONTRACT", R12_SUCCESSOR)
ROADMAP_IDS = ("LINUX-HOST-AUTH-001", "LINUX-PROBE-KIT-001", "LINUX-PROBE-KIT-ADMISSION", "LINUX-PROBE-KIT-SCOPE")
SENTENCE_RANGES = {("docs/alpha-2/PROXY_CONTRACT_READINESS.md", "307-313"),
                   ("docs/alpha-2/CREDENTIAL_ORDERING_REPAIR.md", "122-127")}
CLASSES = ("AUTHORITY_TEXT", "CLOSED_RECORD", "HISTORY_SNAPSHOT", "INPUTS_PINNED", "INPUTS_SNAPSHOT", "LINEAGE_GUIDE",
           "LIVING_CATALOG", "MERGED_PACKET_YAML", "RECORD_EMBEDDED_TEXT", "REVIEW_RECORD", "ROUND_SNAPSHOT")
PINNED_CLASSES = ("CLOSED_RECORD", "INPUTS_PINNED", "LINEAGE_GUIDE", "MERGED_PACKET_YAML")
CLOSED_RECORDS = ("architecture/backend-timing.json", "architecture/broker-handoff-amendment.json",
                  "architecture/completion-integration.json", "architecture/conformance-completion.json",
                  "architecture/conformance-publication.json", "architecture/live-backend-roadmap.json",
                  "architecture/local-acceptance.json", "architecture/native-qualification-amendment.json",
                  "architecture/proxy-diagnostics.json", "architecture/unified-roadmap-backlog.json")
LINEAGE_GUIDES = tuple("docs/alpha-2/%s.md" % name for name in ("CONFORMANCE_COMPLETION", "CONFORMANCE_PUBLICATION",
                                                               "LOCAL_ACCEPTANCE_REVALIDATION",
                                                               "SUCCESSOR_CHECKPOINT_REPAIR"))
LIVING_CATALOGS = ("docs/DEVELOPMENT_STATUS.md", "docs/MASTER_DEVELOPMENT_PLAN.md", "docs/READINESS_INDEX.md",
                   "docs/adr/0004-sol-high-packet-boundary.md", "docs/alpha-2/COMPLETION_INTEGRATION.md",
                   "docs/alpha-2/LIVE_BACKEND_READINESS.md", "docs/repositories/00-harness-engineering.md",
                   "docs/repositories/12-mas-harness-conformance-labs.md", "task-packets/README.md")
LINE_DISPOSITIONS = ("NOT_OWNERSHIP", "QUOTED", "UNCHANGED_TRUE")
NOT_OWNERSHIP_REASONS = ("DIGEST_PIN", "IDENTIFIER_INDEX", "ORDERING_PREREQUISITE", "REVIEW_HISTORY", "STAGE_OR_COUNT",
                         "STATUS_LINE")
LONG = re.compile(r"CONF-LIVE-00[345]")
STANDALONE = re.compile(r"(?<![\w./:-])00[345](?!\w)")
GLUED = re.compile(r"(?:packet|packets|edit|Product|product|same|Native)00[345]")
MEMBERS = ("amends", "base", "crossInputs", "deferred", "dispositions", "effectivePredecessors", "inventory", "moved",
           "notAmended", "ownerDecisions", "packet", "retained", "retiredHistory", "schemaVersion", "slot", "staysTrue",
           "supersedes", "unchanged", "workItem")
MOVED_FROM = {"ADMISSION_MODULE": "CONF-LIVE-003", "CASE_RECIPES": "CONF-LIVE-004", "RECEIPT_CANDIDATES": "CONF-LIVE-004",
              "RECORD_INSPECTOR": "CONF-LIVE-003", "SERVER": "CONF-LIVE-003", "UID_LEDGER": "CONF-LIVE-003",
              "WORKER_ENTRY": "CONF-LIVE-004"}
DEFERRED_ROW = {"item": KAP_LEG, "status": DEFERRED, "authority": "Q-LPK0-3",
                "sourceClauses": ["BH:210-214", "BH:35", "PCR:207-225"]}
CROSS_INPUTS = (HS53,)
# The declared search, pinned (contract review r2, C2-4).
BASE = "2043cc27883448e3ff030b7868110e295f32fe09"
PATHSPECS = ["docs", "architecture", "task-packets", ":!architecture/enforcement-test-plan",
             ":!docs/alpha-2/ENFORCEMENT_TEST_PLAN.md", ":!architecture/artifact-edges", ":!tools"]
PATTERNS = {"ereLong": "CONF-LIVE-00[345]",
            "ereShort": "(^|[^[:alnum:]_./:-])00[345]([^[:alnum:]_]|$)|(packet|packets|edit|Product|product|same|Native)00[345]",
            "glued": "(?:packet|packets|edit|Product|product|same|Native)00[345]", "long": "CONF-LIVE-00[345]",
            "standalone": "(?<![\\w./:-])00[345](?!\\w)"}
# The strict-type pass (D5a oracle findings; the monitor's R-OR-A): every member's exact type, bool and int kept apart,
# checked before any other check. A mismatch refuses with the shape text alone.
STR, INT, BOOL = "str", "int", "bool"
LINES_FORM = re.compile(r"[1-9][0-9]*-[1-9][0-9]*")
HEX64 = re.compile(r"[0-9a-f]{64}")
HEX40 = re.compile(r"[0-9a-f]{40}")
LINE_ROW = ("one of", {"disposition": STR, "line": INT}, {"disposition": STR, "line": INT, "reason": STR})
FILE_ROW = ("one of", {"class": STR, "disposition": STR, "hitLines": [INT], "path": STR, "sha256": "hex64"},
            {"disposition": STR, "hitLines": [INT], "lines": [LINE_ROW], "path": STR, "sha256": "hex64"})
RECORD_TYPE = {
    "schemaVersion": STR, "packet": STR, "slot": INT, "workItem": STR, "base": "hex40",
    "ownerDecisions": [{"id": STR, "quote": STR, "section": STR}],
    "crossInputs": [{"path": STR, "sha256": "hex64"}],
    "amends": [{"packet": STR, "path": STR, "sha256": "hex64", "supersededEntries": [STR]}],
    "dispositions": [{"deliverables": [{"deliverable": INT, "status": STR}], "disposition": STR, "packet": STR, "text": STR}],
    "moved": [{"fromClauses": [STR], "fromPacket": STR, "item": STR, "items": [STR], "status": STR, "to": STR}],
    "retained": [{"item": STR, "packet": STR, "text": STR}],
    "deferred": [{"authority": STR, "item": STR, "sourceClauses": [STR], "status": STR, "text": STR}],
    "unchanged": [{"id": STR, "text": STR}],
    "retiredHistory": [{"branchModified": BOOL, "dispatchable": BOOL, "head": ("or null", "hex40"), "id": STR,
                        "pr": ("or null", INT), "status": STR}],
    "supersedes": [{"id": STR, "lines": "lines", "path": STR, "quote": STR, "sha256": "hex64",
                    "replacement": {"keptBy": ("or null", STR), "keptItems": [STR], "movedItems": [STR], "movedTo": STR,
                                    "text": STR}}],
    "staysTrue": [{"lines": "lines", "path": STR, "quote": STR}],
    "effectivePredecessors": {"edges": [{"after": [STR], "item": STR}], "placeholders": [STR]},
    "notAmended": {"named": [{"class": STR, "path": STR, "sha256": "hex64"}],
                   "pinned": [{"class": STR, "path": STR, "sha256": "hex64"}]},
    "inventory": {"commit": "hex40", "files": [FILE_ROW], "pathspecs": [STR],
                  "patterns": {"ereLong": STR, "ereShort": STR, "glued": STR, "long": STR, "standalone": STR},
                  "searchDigest": "hex64"},
}


def typed(value, spec):
    """Whether `value` has exactly the type `spec` describes: str, int and bool by exact Python type, the formats
    lines ("a-b"), hex64 and hex40, ("or null", spec), ("one of", spec...), [spec] for a list and {key: spec} for an
    object with exactly those keys."""
    if spec == STR:
        return type(value) is str
    if spec == INT:
        return type(value) is int
    if spec == BOOL:
        return type(value) is bool
    if spec == "lines":
        return type(value) is str and LINES_FORM.fullmatch(value) is not None
    if spec == "hex64":
        return type(value) is str and HEX64.fullmatch(value) is not None
    if spec == "hex40":
        return type(value) is str and HEX40.fullmatch(value) is not None
    if isinstance(spec, tuple) and spec[0] == "or null":
        return value is None or typed(value, spec[1])
    if isinstance(spec, tuple) and spec[0] == "one of":
        return any(typed(value, option) for option in spec[1:])
    if isinstance(spec, list):
        return type(value) is list and all(typed(item, spec[0]) for item in value)
    if isinstance(spec, dict):
        return type(value) is dict and tuple(sorted(value)) == tuple(sorted(spec)) and \
            all(typed(value[key], spec[key]) for key in spec)
    return False

# The tables the design and the build rules fix exactly (BUILD_RULES S3-2, S3-4; DESIGN rev 3 sections 3.2, 3.7, 3.8;
# contract review r1, C1-3 and C1-7). Written by the contract build.
PINNED_SUPERSEDES = [
    ('architecture/i05-gate-channel-v2/README.md', '133-133', '49609fdeee9d0a917398d3929a6155a2e0996c3acc454dd64da5ddc43db1493e', ['KAP_LEG'], []),
    ('architecture/i05-gate-channel-v2/README.md', '273-273', '33466867a9772a9c1a55de6bc929ab7ad24021fa0a545665d760d1a900014980', ['KAP_LEG'], []),
    ('architecture/i05-gate-channel-v3/README.md', '135-135', '49609fdeee9d0a917398d3929a6155a2e0996c3acc454dd64da5ddc43db1493e', ['KAP_LEG'], []),
    ('architecture/i05-gate-channel-v3/README.md', '326-326', '33466867a9772a9c1a55de6bc929ab7ad24021fa0a545665d760d1a900014980', ['KAP_LEG'], []),
    ('architecture/i05-gate-channel/README.md', '115-116', '78fe8e49e42d389d2b6113a0a87ae2ce96e3b0cf133d7ecd4312376d7d6f80d2', ['KAP_LEG'], []),
    ('architecture/i05-gate-channel/README.md', '277-277', '33466867a9772a9c1a55de6bc929ab7ad24021fa0a545665d760d1a900014980', ['KAP_LEG'], []),
    ('architecture/proxy-contract-amendment.json', '253-253', '8cb0c549a6e8068b99c0c476bdcdb5fee244f96a79430f9a792a6bb76b00ec23', ['ADMISSION_MODULE', 'SERVER', 'UID_LEDGER'], ['CLIENT']),
    ('architecture/proxy-contract-amendment.json', '253-253', '8653b49b66137349caf6c4ecb41fc48cee2c1c409a3b2da478c865af8e52a5ae', ['CASE_RECIPES', 'RECEIPT_CANDIDATES', 'SERVER', 'WORKER_ENTRY'], ['CLIENT']),
    ('docs/TRUSTED_LIVE_CAMPAIGN_RUNNER_CONTRACT.md', '477-478', 'a3ae6e7f4bb582e8c3b89f18e2ed0fe1cce7e3abb595a1cc5221fb483063eab5', ['ADMISSION_MODULE', 'SERVER', 'UID_LEDGER'], ['CLIENT']),
    ('docs/TRUSTED_LIVE_CAMPAIGN_RUNNER_CONTRACT.md', '479-480', '5c3ddf72982896df24d5922a2d0f48454f1b328f5e4cae8023867b66141c1f68', ['CASE_RECIPES', 'RECEIPT_CANDIDATES', 'SERVER', 'WORKER_ENTRY'], ['CLIENT']),
    ('docs/alpha-2/BROKER_HANDOFF_READINESS.md', '35-35', '95c624cce61dd18a7970153f81b73a6b4e2a0ef1d408452b0bea1aa282fd6531', ['ADMISSION_MODULE', 'SERVER'], []),
    ('docs/alpha-2/BROKER_HANDOFF_READINESS.md', '35-35', 'b208c6adc3478d12ae7c5b196946ea89c97e46eb0cbee9759749142beffcefd6', ['UID_LEDGER'], []),
    ('docs/alpha-2/BROKER_HANDOFF_READINESS.md', '35-35', '4f3a63ecfdd1312cabe0e4fcddce4f3934da7d263704647fd7154b7f8ba10bac', ['KAP_LEG'], []),
    ('docs/alpha-2/BROKER_HANDOFF_READINESS.md', '36-36', '55c522be86df796e22b89695ddcba40126b5da4563f3e5f670fd801a74c1a53b', ['CASE_RECIPES', 'RECEIPT_CANDIDATES', 'WORKER_ENTRY'], []),
    ('docs/alpha-2/BROKER_HANDOFF_READINESS.md', '37-37', 'ac2a21a9c8b4ab16c9ac931514cdada2df61f5f149648e696a266667793afd22', ['SERVER', 'WORKER_ENTRY'], ['CANDIDATE_HANDOFF', 'CLIENT']),
    ('docs/alpha-2/BROKER_HANDOFF_READINESS.md', '43-44', '4124e4c9e4ad6512b19ee6042bd7c7807a68e1459a579d2b4a6c284267b5e2cb', ['WORKER_ENTRY'], []),
    ('docs/alpha-2/BROKER_HANDOFF_READINESS.md', '45-45', '6c14236c3e12de4965e5e36ecc1b0c036f06488b1e3339829dee549158017af3', ['WORKER_ENTRY'], []),
    ('docs/alpha-2/BROKER_HANDOFF_READINESS.md', '95-95', 'd6f48a5479b29fbce15d114a1278482c5b8e7be63de532395c683286aae145e4', ['SERVER', 'WORKER_ENTRY'], ['CLIENT']),
    ('docs/alpha-2/BROKER_HANDOFF_READINESS.md', '216-219', 'd63bcf15dfe2c1f82d1dc3e13c9f61bdd37e9444e2664f62a13eae804da3b461', ['ADMISSION_MODULE', 'UID_LEDGER'], []),
    ('docs/alpha-2/BROKER_HANDOFF_READINESS.md', '251-253', 'd7403975d34f425de3fbacdc2f00a9952b0aab6c201eede47054eafba9f503cd', ['SERVER'], ['CLIENT']),
    ('docs/alpha-2/BROKER_HANDOFF_READINESS.md', '253-253', '992d476bb349cfcd394358ddb00c19ff08d06e2f12f918170117af24c42acd8f', ['CASE_RECIPES', 'WORKER_ENTRY'], []),
    ('docs/alpha-2/BROKER_HANDOFF_READINESS.md', '253-255', '07df374d46076f83b7c8ee928ced28633cce87423d0a20b7b54c1d4131f501fe', ['SERVER', 'WORKER_ENTRY'], ['CLIENT']),
    ('docs/alpha-2/CREDENTIAL_ORDERING_REPAIR.md', '122-127', '7bf1065c20c7fa30bdb0843c20a6582c83642b1db498a66cc684705248120fea', ['SERVER', 'UID_LEDGER'], ['CLIENT']),
    ('docs/alpha-2/I05_GATE_CHANNEL.md', '58-58', '33466867a9772a9c1a55de6bc929ab7ad24021fa0a545665d760d1a900014980', ['KAP_LEG'], []),
    ('docs/alpha-2/NATIVE_QUALIFICATION_READINESS.md', '38-38', 'f9c89dda0df84284c908f4de2eac1b1a3053d8e360683c83eec6fde23c098f64', ['ADMISSION_MODULE', 'RECORD_INSPECTOR', 'SERVER'], ['CLIENT']),
    ('docs/alpha-2/NATIVE_QUALIFICATION_READINESS.md', '39-39', '72bf3d10293d2a3e6124a3ef3fada5e71037ec24806f93216f1c09311b64ab56', ['RECORD_INSPECTOR', 'WORKER_ENTRY'], []),
    ('docs/alpha-2/NATIVE_QUALIFICATION_READINESS.md', '40-40', 'b461110c92e9c82dde3d213500c6d94534d5a6c91e22a11f735afd96dc8c4d06', ['SERVER', 'WORKER_ENTRY'], ['CANDIDATE_HANDOFF', 'CLIENT']),
    ('docs/alpha-2/NATIVE_QUALIFICATION_READINESS.md', '44-45', '27f2396df2cc1a204890ba1a5f9f51f085e6a63959d2a0eb138df3395773743f', ['RECORD_INSPECTOR'], []),
    ('docs/alpha-2/NATIVE_QUALIFICATION_READINESS.md', '238-240', '89ce7c9f06325771e25647905bc42a9ace4fac768c04b1bf933439165b3c3eeb', ['RECORD_INSPECTOR'], []),
    ('docs/alpha-2/NATIVE_QUALIFICATION_READINESS.md', '242-243', 'f39fd65db3da01ac66be65b05e75b63f81daa3e70e5f5834c147fbb02a02831b', ['WORKER_ENTRY'], []),
    ('docs/alpha-2/NATIVE_QUALIFICATION_READINESS.md', '245-245', 'c3be5d43dfb633cf04e84521673f4b3ff0a2d8d2931abce6d8f60f18a8dd5d70', ['WORKER_ENTRY'], []),
    ('docs/alpha-2/NATIVE_QUALIFICATION_READINESS.md', '256-257', '99df921c4111f317f3f0bb90b1857b6a1053a58b2e84d28f612aae755483e407', ['SERVER'], ['CLIENT']),
    ('docs/alpha-2/POLICY_OBSERVATION_READINESS.md', '32-32', '0e02d208b7e7d1fbd4f050af0f38706a27e0496cf057635e8b9f9aa8591c06d7', ['ADMISSION_MODULE', 'SERVER'], []),
    ('docs/alpha-2/POLICY_OBSERVATION_READINESS.md', '33-33', '3914327f2f1273ca95b6ecf5eeaeaf89c3ec45c0192035c53f5abd10acdff6cf', ['CASE_RECIPES'], []),
    ('docs/alpha-2/POLICY_OBSERVATION_READINESS.md', '34-34', '222f97afbb95669ea55f70cf6a4560af1a50563f69c1c362e4ea84f0d1905551', ['SERVER'], ['CANDIDATE_HANDOFF', 'CLIENT']),
    ('docs/alpha-2/POLICY_OBSERVATION_READINESS.md', '167-168', '9010256e7d35db603c6a864885818e51932168797d136d5e966ec6aacda2d26b', ['ADMISSION_MODULE', 'SERVER'], ['CLIENT']),
    ('docs/alpha-2/PROXY_CONTRACT_READINESS.md', '41-41', '4c90fd0ed37e945ed3b13cb9b15380b7d4f707913638f831c8b6726a80dadb79', ['ADMISSION_MODULE', 'SERVER'], ['CLIENT']),
    ('docs/alpha-2/PROXY_CONTRACT_READINESS.md', '42-42', 'a6a5538980e4d4678f3b1e2b439a006da758487f2070a494ed65e7994b2d8f90', ['CASE_RECIPES'], []),
    ('docs/alpha-2/PROXY_CONTRACT_READINESS.md', '43-43', '19c8bc89757f4b06087da0bf1bf5b12a80ca72f516d89b6de571e88b9f0b0631', ['SERVER', 'WORKER_ENTRY'], ['CANDIDATE_HANDOFF', 'CLIENT']),
    ('docs/alpha-2/PROXY_CONTRACT_READINESS.md', '54-56', 'a4774147336fefc478ec68bedf52e43381083af0b951b5521ec4121dfe24bd35', ['ADMISSION_MODULE', 'SERVER'], ['CLIENT']),
    ('docs/alpha-2/PROXY_CONTRACT_READINESS.md', '174-174', 'c70fc680325d8da14ce3d96b490f56fb7102b44789ad1879c3bc7d20f3d46a52', ['SERVER'], []),
    ('docs/alpha-2/PROXY_CONTRACT_READINESS.md', '176-176', 'bcf5fd9e30b010ec42b3271f9d0a4156f1f05811514ec47ed50a3b48ad9f1ecc', ['SERVER'], []),
    ('docs/alpha-2/PROXY_CONTRACT_READINESS.md', '190-191', '2338c95e19bafe9ceadd82e4fd39def03486e03f12d0343b3f8dcd457ce65ef8', ['SERVER'], []),
    ('docs/alpha-2/PROXY_CONTRACT_READINESS.md', '226-227', 'eb4b8a3c9dc22424e35f94194010f28183f5eaf1f6e15c7e03b5ac6e3cc60610', ['WORKER_ENTRY'], []),
    ('docs/alpha-2/PROXY_CONTRACT_READINESS.md', '307-313', '35c9f8bae2a4b3548fb986faad0203df26685fb915e18a65dd4a790f9c227fbb', ['ADMISSION_MODULE', 'SERVER', 'UID_LEDGER'], ['CLIENT']),
]
PINNED_STAYS = [
    ('architecture/proxy-contract-amendment.json', '253-253', 'and final hook remain with CONF-LIVE-004/005/006'),
    ('docs/TRUSTED_LIVE_CAMPAIGN_RUNNER_CONTRACT.md', '478-479', 'preserve all 127 predecessor files and\n279 test IDs'),
    ('docs/TRUSTED_LIVE_CAMPAIGN_RUNNER_CONTRACT.md', '480-480', 'and CONF-LIVE-006 the already-bounded final hook'),
    ('docs/alpha-2/BROKER_HANDOFF_READINESS.md', '40-42', 'Existing product paths remain exact: 003 has eight, 004 six, 005 five and 006\nfive additions plus its already-approved final launcher-hook edit. Stages remain\n110/120/127/135/141/146/151. Every product command set remains eight commands.'),
    ('docs/alpha-2/CREDENTIAL_ORDERING_REPAIR.md', '102-103', 'CONF-LIVE-003 still owns its exact eight paths and all eight cumulative\ncommands'),
    ('docs/alpha-2/NATIVE_QUALIFICATION_READINESS.md', '43-44', 'Exact product paths/stages110/120/127/135/141/146/151 and all eight commands are\nunchanged.'),
    ('docs/alpha-2/POLICY_OBSERVATION_READINESS.md', '168-169', 'Its own fixture\npins this authority and the unchanged 127-file/279-ID baseline.'),
    ('docs/alpha-2/PROXY_CONTRACT_READINESS.md', '191-191', 'No new root key or signature role.'),
    ('docs/alpha-2/PROXY_CONTRACT_READINESS.md', '41-41', 'eight existing paths'),
    ('docs/alpha-2/PROXY_CONTRACT_READINESS.md', '42-42', 'in six existing paths'),
    ('docs/alpha-2/PROXY_CONTRACT_READINESS.md', '43-43', 'in five existing paths'),
    ('docs/alpha-2/PROXY_CONTRACT_READINESS.md', '56-57', 'It must pin this authority\nand preserve the immediate 127-file/279-ID baseline in its owned fixture.'),
]
PINNED_EDGES = [('CONF-LIVE-006', ['LINUX-PROBE-KIT-001', 'R12_SUCCESSOR']), ('EVOLUTION_SURFACE_GATE_PACKET', ['MET-LIVE-002']), ('LINUX-PROBE-KIT-001', ['LINUX-PROBE-KIT-ADMISSION', 'NEUTRAL_INTERFACE_CONTRACT']), ('LINUX-PROBE-KIT-ADMISSION', ['EVOLUTION_SURFACE_GATE_PACKET', 'MET-LIVE-002']), ('R12_SUCCESSOR', ['MET-LIVE-002', 'NEUTRAL_INTERFACE_CONTRACT'])]
PINNED_AMENDS = [('architecture/broker-handoff-amendment.json', 'MET-REPAIR-014', []), ('architecture/completion-integration.json', 'MET-REPAIR-018', ['effectivePredecessors.CONF-LIVE-004']), ('architecture/live-backend-roadmap.json', 'MET-LIVE-001', []), ('architecture/native-qualification-amendment.json', 'MET-REPAIR-015', [])]

# Refusal texts (pinned; the vectors name them).
R = {
    "shape": "the record's shape is not the closed shape",
    "vocabulary": "a value is outside its closed vocabulary",
    "order": "a list is not sorted or holds a duplicate row",
    "sha": "a sha256 does not equal the base bytes",
    "quote": "a quote does not occur exactly once within its cited lines",
    "lines": "a row's lines do not run from its quote's first byte to its last",
    "overlap": "a quote overlaps a statement that stays true",
    "hs53": "a quote overlaps an HS53 supersedes quote in the same file",
    "replacement": "a replacement's structured members are inconsistent",
    "kap": "the KAP leg is mixed with another item or moved to the kit",
    "link": "a moved item is not linked to exactly its supersedes rows",
    "dispositions": "the four packet dispositions are not exactly as decided",
    "unchanged": "unchanged does not name the worker entry, the roles and every required identity",
    "retired": "retiredHistory is not exactly CONF-FIX-007..010 in MET-REPAIR-018's shape",
    "predecessors": "effectivePredecessors names an unknown item or holds a cycle",
    "amends": "an amends row names an entry its record does not hold",
    "class": "a file is in a class whose path rule it fails",
    "twice": "a file is in more than one place",
    "inventory": "the inventory's hits do not equal the hits recomputed from the base bytes",
    "disposition": "an inventory hit has no valid disposition",
    "digest": "the inventory's searchDigest does not equal its hit list's digest",
    "gate": "a gate-material path is among the packet's changed files",
    "pinned": "a pinned, quoted or amended path is among the packet's changed files",
    "pinnedTable": "a row differs from the table the design and the build rules fix",
    "lineFile": "a classed file is filed as a line-level file",
    "covered": "a hit line inside a supersedes row's lines is not QUOTED",
    "spans": "two supersedes quotes overlap in one file",
}


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def sha(data):
    return hashlib.sha256(data).hexdigest()


def text_lines(data):
    return data.decode("utf-8").split("\n")


def hits_for(path, data, supersedes_paths):
    """The declared search's hit lines in one file (DESIGN rev 3 section 3.10, BUILD_RULES S3-1 and S3-9)."""
    lines = text_lines(data)
    md = path.endswith(".md")
    out = []
    for index, line in enumerate(lines):
        if LONG.search(line):
            out.append(index + 1)
            continue
        if not (STANDALONE.search(line) or GLUED.search(line)):
            continue
        if path in supersedes_paths:
            out.append(index + 1)
            continue
        if md:
            start = index
            while start > 0 and lines[start - 1].strip():
                start -= 1
            end = index
            while end + 1 < len(lines) and lines[end + 1].strip():
                end += 1
            block = lines[start:end + 1]
        else:
            block = [line]
        if any(LONG.search(item) or GLUED.search(item) for item in block):
            out.append(index + 1)
    return out


def path_class(path):
    """The class a path's rule gives it (BUILD_RULES S3-10), or None. RECORD_EMBEDDED_TEXT is any other
    one-level architecture/*.json path."""
    parts = path.split("/")
    if len(parts) == 3 and parts[:2] == ["architecture", "broker-handoff-inputs"]:
        return "INPUTS_PINNED"
    if parts[:2] == ["architecture", "broker-handoff-inputs"]:
        return None
    if len(parts) >= 4 and parts[0] == "architecture" and re.fullmatch(r"round.*", parts[2]):
        return "ROUND_SNAPSHOT"
    if parts[0] == "architecture" and re.fullmatch(r"review-round.*\.json", parts[-1]):
        return "REVIEW_RECORD"
    if len(parts) == 2 and parts[0] == "architecture" and parts[1].endswith("-authority.json"):
        return "AUTHORITY_TEXT"
    if len(parts) >= 3 and parts[0] == "architecture" and parts[1].endswith("-inputs"):
        return "INPUTS_SNAPSHOT"
    if len(parts) == 3 and parts[:2] == ["docs", "history"]:
        return "HISTORY_SNAPSHOT"
    if len(parts) == 2 and parts[0] == "task-packets" and path.endswith(".yaml"):
        return "MERGED_PACKET_YAML"
    if path in LINEAGE_GUIDES:
        return "LINEAGE_GUIDE"
    if path in LIVING_CATALOGS:
        return "LIVING_CATALOG"
    if path in CLOSED_RECORDS:
        return "CLOSED_RECORD"
    if len(parts) == 2 and parts[0] == "architecture" and path.endswith(".json"):
        return "RECORD_EMBEDDED_TEXT"
    return None


def span(lines, first, last, quote):
    """(start, end) character offsets of the one occurrence of `quote` within lines first..last of a file, or None."""
    offsets = [0]
    for line in lines:
        offsets.append(offsets[-1] + len(line) + 1)
    if not (1 <= first <= last <= len(lines)):
        return None
    segment = "\n".join(lines[first - 1:last])
    if not quote or segment.count(quote) != 1:
        return None
    start = offsets[first - 1] + segment.index(quote)
    return start, start + len(quote)


def line_of(lines, offset):
    total = 0
    for number, line in enumerate(lines, 1):
        if offset < total + len(line) + 1:
            return number
        total += len(line) + 1
    return len(lines)


def parse_lines(text):
    match = re.fullmatch(r"([1-9][0-9]*)-([1-9][0-9]*)", text) if isinstance(text, str) else None
    if not match:
        return None
    first, last = int(match.group(1)), int(match.group(2))
    return (first, last) if first <= last else None


def same_typed(a, b):
    """Equality that keeps bool, int, str and null apart (0 is not False)."""
    if type(a) is not type(b):
        return False
    if isinstance(a, dict):
        return a.keys() == b.keys() and all(same_typed(a[k], b[k]) for k in a)
    if isinstance(a, list):
        return len(a) == len(b) and all(same_typed(x, y) for x, y in zip(a, b))
    return a == b


def check(record, read, changed_files, gate_paths):
    """The refusal texts for `record` (empty when it holds). A member of the wrong type refuses with the shape text
    instead of raising (contract review r2, C2-5)."""
    try:
        return _check(record, read, changed_files, gate_paths)
    except (TypeError, AttributeError, KeyError, ValueError, IndexError, UnicodeDecodeError):
        return [R["shape"]]


def _check(record, read, changed_files, gate_paths):
    """The refusal texts for `record` (empty when it holds). `gate_paths` are the changed files the caller has already
    matched against the evolution-surface record's gate rules (prefix and under+name rules, case-folded)."""
    refusals = set()

    def refuse(key):
        refusals.add(R[key])

    def rows_of(rows, members, key):
        """Every row a dict with exactly `members`; the list sorted by `key` with no duplicate key."""
        if not isinstance(rows, list) or not all(isinstance(row, dict) and tuple(sorted(row)) == members for row in rows):
            refuse("shape")
            return False
        keys = [key(row) for row in rows]
        if keys != sorted(keys) or len(set(map(repr, keys))) != len(keys):
            refuse("order")
        return True

    if not isinstance(record, dict) or tuple(sorted(record)) != MEMBERS or not typed(record, RECORD_TYPE):
        return [R["shape"]]
    if (record["schemaVersion"] != SCHEMA or record["packet"] != "MET-LIVE-002" or record["slot"] != 260
            or record["workItem"] != "LINUX-PROBE-KIT-SCOPE" or not re.fullmatch(r"[0-9a-f]{40}", str(record["base"]))):
        refuse("shape")
    if record["base"] != BASE:
        refuse("pinnedTable")
    known_paths = set()
    cache = {}

    def base(path):
        if path not in cache:
            cache[path] = read(path) if path in known_paths else None
        return cache[path]

    # crossInputs: the one record the model reads beyond the record's own rows (C1-8).
    cross = record["crossInputs"]
    if rows_of(cross, ("path", "sha256"), lambda row: row["path"]):
        if tuple(row["path"] for row in cross) != CROSS_INPUTS:
            refuse("pinnedTable")
        for row in cross:
            known_paths.add(row["path"])
            data = base(row["path"])
            if data is None or sha(data) != row["sha256"]:
                refuse("sha")
    for group in ("amends", "supersedes"):
        known_paths.update(row.get("path") for row in record[group] if isinstance(row, dict))
    na = record["notAmended"]
    if isinstance(na, dict):
        known_paths.update(row.get("path") for group in na.values() if isinstance(group, list) for row in group
                           if isinstance(row, dict))
    inv = record["inventory"]
    if isinstance(inv, dict) and isinstance(inv.get("files"), list):
        known_paths.update(row.get("path") for row in inv["files"] if isinstance(row, dict))

    # Owner decisions: shape only; the section check runs in the contract build (BUILD_RULES S3-6).
    decisions = record["ownerDecisions"]
    if rows_of(decisions, ("id", "quote", "section"), lambda row: (row["id"], row["quote"])) and \
            not all(isinstance(row[k], str) and row[k] for row in decisions for k in row):
        refuse("shape")

    # amends, pinned (C1-7)
    amends = record["amends"]
    if rows_of(amends, ("packet", "path", "sha256", "supersededEntries"), lambda row: row["path"]):
        if [(row["path"], row["packet"], row["supersededEntries"]) for row in amends] != PINNED_AMENDS:
            refuse("pinnedTable")
        for row in amends:
            data = base(row["path"])
            if data is None or sha(data) != row["sha256"]:
                refuse("sha")
                continue
            for entry in row["supersededEntries"]:
                parts = entry.split(".", 1)
                value = json.loads(data.decode("utf-8"))
                if len(parts) != 2 or not isinstance(value.get(parts[0]), dict) or parts[1] not in value[parts[0]]:
                    refuse("amends")

    # dispositions
    rows = record["dispositions"]
    if rows_of(rows, ("deliverables", "disposition", "packet", "text"), lambda row: row["packet"]):
        if [(row["packet"], row["disposition"]) for row in rows] != sorted(PACKET_DISPOSITIONS.items()):
            refuse("dispositions")
        for row in rows:
            if rows_of(row["deliverables"], ("deliverable", "status"), lambda d: d["deliverable"]):
                if any(d["status"] not in DELIVERABLE_STATUSES for d in row["deliverables"]):
                    refuse("vocabulary")
        consumed = [row for row in rows if row["packet"] == "CONF-LIVE-003"]
        if consumed and [(d.get("deliverable"), d.get("status")) for d in consumed[0]["deliverables"]] != [
                (1, "KEPT_R12"), (2, "SUPERSEDED_UNACCEPTED_HISTORY"), (3, "SUPERSEDED_UNACCEPTED_HISTORY"),
                (4, "SUPERSEDED_UNACCEPTED_HISTORY")]:
            refuse("dispositions")
    else:
        refuse("dispositions")

    # supersedes: content order and uniqueness (C1-2), the pinned rows (C1-3), quotes, lines, replacements
    supersedes = record["supersedes"]
    spans = {}
    rep_members = ("keptBy", "keptItems", "movedItems", "movedTo", "text")
    ok = rows_of(supersedes, ("id", "lines", "path", "quote", "replacement", "sha256"),
                 lambda row: (row["path"], (parse_lines(row["lines"]) or (0, 0))[0], row["quote"]))
    if ok:
        if [row["id"] for row in supersedes] != ["S-%02d" % n for n in range(1, len(supersedes) + 1)]:
            refuse("order")
        if not all(isinstance(row["replacement"], dict) and tuple(sorted(row["replacement"])) == rep_members
                   for row in supersedes):
            refuse("shape")
            ok = False
    if ok:
        table = [(row["path"], row["lines"], sha(row["quote"].encode("utf-8")), row["replacement"]["movedItems"],
                  row["replacement"]["keptItems"]) for row in supersedes]
        if table != PINNED_SUPERSEDES:
            refuse("pinnedTable")
        for row in supersedes:
            data = base(row["path"])
            if data is None or sha(data) != row["sha256"]:
                refuse("sha")
                continue
            lines = text_lines(data)
            bounds = parse_lines(row["lines"])
            found = span(lines, bounds[0], bounds[1], row["quote"]) if bounds else None
            if found is None:
                refuse("quote")
                continue
            if (row["path"], row["lines"]) not in SENTENCE_RANGES and \
                    (line_of(lines, found[0]) != bounds[0] or line_of(lines, found[1] - 1) != bounds[1]):
                refuse("lines")
            for start, end in spans.get(row["path"], []):
                if start < found[1] and found[0] < end:
                    refuse("spans")
            spans.setdefault(row["path"], []).append(found)
            rep = row["replacement"]
            moved, kept = rep["movedItems"], rep["keptItems"]
            if not isinstance(moved, list) or not isinstance(kept, list) or not moved or \
                    moved != sorted(set(moved)) or kept != sorted(set(kept)):
                refuse("replacement")
                continue
            if any(item not in MOVED_ITEMS + (KAP_LEG,) for item in moved) or any(item not in RETAINED_ITEMS for item in kept):
                refuse("vocabulary")
            if KAP_LEG in moved:
                if moved != [KAP_LEG] or rep["movedTo"] != DEFERRED or kept or rep["keptBy"] is not None:
                    refuse("kap")
            elif rep["movedTo"] != KIT:
                refuse("replacement" if rep["movedTo"] == DEFERRED else "vocabulary")
            if set(moved) & set(kept):
                refuse("replacement")
            if (rep["keptBy"] == R12_SUCCESSOR) != bool(kept) or rep["keptBy"] not in (None, R12_SUCCESSOR):
                refuse("replacement")
            if not isinstance(rep["text"], str) or not rep["text"]:
                refuse("replacement")

    # staysTrue: exactly the pinned spans (C1-3), each found once and overlapped by no quote
    stays = record["staysTrue"]
    if rows_of(stays, ("lines", "path", "quote"), lambda row: (row["path"], row["lines"], row["quote"])):
        if [(row["path"], row["lines"], row["quote"]) for row in stays] != PINNED_STAYS:
            refuse("pinnedTable")
        for row in stays:
            data = base(row["path"])
            bounds = parse_lines(row["lines"])
            found = span(text_lines(data), bounds[0], bounds[1], row["quote"]) if data is not None and bounds else None
            if found is None:
                refuse("quote")
                continue
            for start, end in spans.get(row["path"], []):
                if start < found[1] and found[0] < end:
                    refuse("overlap")
    hs53 = base(HS53)
    if hs53 is not None:
        for row in json.loads(hs53.decode("utf-8")).get("supersedes", []):
            if row.get("path") not in spans:
                continue
            data = base(row["path"])
            if data is None:
                continue
            text = data.decode("utf-8")
            start = text.find(row.get("quote", "\0"))
            while start >= 0:
                end = start + len(row["quote"])
                for first, last in spans[row["path"]]:
                    if first < end and start < last:
                        refuse("hs53")
                start = text.find(row["quote"], start + 1)

    # moved (with fromPacket, C1-6), retained, deferred (C1-6)
    by_item = {}
    for row in supersedes if isinstance(supersedes, list) else []:
        rep = row.get("replacement") if isinstance(row, dict) else None
        for item in rep.get("movedItems", []) if isinstance(rep, dict) else []:
            by_item.setdefault(item, set()).add(row.get("id"))
    moved_rows = record["moved"]
    if rows_of(moved_rows, ("fromClauses", "fromPacket", "item", "items", "status", "to"), lambda row: row["item"]):
        for row in moved_rows:
            if row["item"] not in MOVED_ITEMS or row["to"] != KIT or row["status"] != "SUPERSEDED_UNACCEPTED_HISTORY":
                refuse("kap" if row["item"] == KAP_LEG else "vocabulary")
                continue
            if MOVED_FROM.get(row["item"]) != row["fromPacket"]:
                refuse("pinnedTable")
            if not isinstance(row["fromClauses"], list) or row["fromClauses"] != sorted(set(row["fromClauses"])) \
                    or not row["fromClauses"] or row["items"] != sorted(set(row["items"])):
                refuse("order")
            if sorted(row["items"]) != sorted(by_item.get(row["item"], set())) or not row["items"]:
                refuse("link")
        if [row["item"] for row in moved_rows] != sorted(MOVED_ITEMS):
            refuse("link")
    retained = record["retained"]
    if rows_of(retained, ("item", "packet", "text"), lambda row: row["item"]) and \
            [row["item"] for row in retained] != sorted(RETAINED_ITEMS):
        refuse("vocabulary")
    deferred = record["deferred"]
    if rows_of(deferred, ("authority", "item", "sourceClauses", "status", "text"), lambda row: row["item"]):
        if [{k: row[k] for k in DEFERRED_ROW} for row in deferred] != [DEFERRED_ROW]:
            refuse("kap")
    else:
        refuse("kap")

    # unchanged
    unchanged = record["unchanged"]
    if rows_of(unchanged, ("id", "text"), lambda row: row["id"]):
        texts = {row["id"]: row["text"] for row in unchanged}
        if tuple(texts) != UNCHANGED_IDS or "live_fixed_probes.broker_worker_main" not in texts.get("WORKER_ENTRY_NAME", "") \
                or not all(word in texts.get("ROLES", "") for word in ("SERVER", "WORKER")):
            refuse("unchanged")
    else:
        refuse("unchanged")

    # retiredHistory
    retired = record["retiredHistory"]
    expected = {}
    completion = base(COMPLETION_INTEGRATION)
    if completion is not None:
        expected["CONF-FIX-007"] = json.loads(completion.decode("utf-8")).get("retiredPacket")
    for ident in RETIRED_IDS[1:]:
        expected[ident] = {"branchModified": False, "dispatchable": False, "head": None, "id": ident, "pr": None,
                           "status": RETIRED_STATUS}
    if not isinstance(retired, list) or \
            [row.get("id") if isinstance(row, dict) else None for row in retired] != list(RETIRED_IDS) or \
            any(sorted(row) != sorted(RETIRED_KEYS) or not same_typed(row, expected.get(row["id"])) for row in retired):
        refuse("retired")

    # effectivePredecessors, pinned (C1-7): known items, acyclic, exactly the six edges
    graph = record["effectivePredecessors"]
    if not isinstance(graph, dict) or tuple(sorted(graph)) != ("edges", "placeholders") or \
            graph["placeholders"] != sorted(PLACEHOLDERS):
        refuse("shape")
    else:
        edges = graph["edges"]
        if rows_of(edges, ("after", "item"), lambda row: row["item"]):
            if any(row["after"] != sorted(set(row["after"])) for row in edges):
                refuse("order")
            known = set(PLACEHOLDERS) | set(ROADMAP_IDS) | {record["packet"]}
            pinned_paths = {row.get("path") for row in na.get("pinned", [])} if isinstance(na, dict) else set()
            for node in {row["item"] for row in edges} | {item for row in edges for item in row["after"]}:
                if node not in known and "task-packets/%s.yaml" % node not in pinned_paths:
                    refuse("predecessors")
            after = {row["item"]: set(row["after"]) for row in edges}
            state = {}

            def cyclic(node):
                if state.get(node) == 1:
                    return True
                if state.get(node) == 2:
                    return False
                state[node] = 1
                if any(cyclic(other) for other in after.get(node, ())):
                    return True
                state[node] = 2
                return False

            if any(cyclic(node) for node in list(after)):
                refuse("predecessors")
            if [(row["item"], row["after"]) for row in edges] != PINNED_EDGES:
                refuse("pinnedTable")

    # notAmended
    places = []
    if not isinstance(na, dict) or tuple(sorted(na)) != ("named", "pinned"):
        return sorted(refusals | {R["shape"]})
    group_of = {}
    for group in ("pinned", "named"):
        if not rows_of(na[group], ("class", "path", "sha256"), lambda row: row["path"]):
            continue
        for row in na[group]:
            if row["class"] not in CLASSES:
                refuse("vocabulary")
                continue
            if (row["class"] in PINNED_CLASSES) != (group == "pinned") or path_class(row["path"]) != row["class"]:
                refuse("class")
            data = base(row["path"])
            if data is None or sha(data) != row["sha256"]:
                refuse("sha")
            places.append(row["path"])
            group_of[row["path"]] = (group, row["class"])
    supersedes_paths = {row.get("path") for row in supersedes if isinstance(row, dict)}
    places.extend(sorted(supersedes_paths))

    # inventory
    if not isinstance(inv, dict) or tuple(sorted(inv)) != ("commit", "files", "pathspecs", "patterns", "searchDigest") \
            or inv["commit"] != record["base"]:
        return sorted(refusals | {R["shape"]})
    if inv["pathspecs"] != PATHSPECS or inv["patterns"] != PATTERNS:
        refuse("pinnedTable")
    line_files, hitlist, ranges = [], [], {}
    for row in supersedes if isinstance(supersedes, list) else []:
        bounds = parse_lines(row.get("lines")) if isinstance(row, dict) else None
        if bounds:
            ranges.setdefault(row["path"], []).append(bounds)
    file_members = {"PINNED": ("class", "disposition", "hitLines", "path", "sha256"),
                    "NAMED": ("class", "disposition", "hitLines", "path", "sha256"),
                    "LINES": ("disposition", "hitLines", "lines", "path", "sha256")}
    keys = []
    for row in inv["files"]:
        if not isinstance(row, dict) or tuple(sorted(row)) != file_members.get(row.get("disposition")):
            refuse("shape")
            continue
        path = row["path"]
        if not isinstance(path, str) or not isinstance(row["hitLines"], list) or \
                not all(type(line) is int for line in row["hitLines"]):
            refuse("shape")
            continue
        keys.append(path)
        data = base(path)
        if data is None or sha(data) != row["sha256"]:
            refuse("sha")
            continue
        recomputed = hits_for(path, data, supersedes_paths)
        if recomputed != row["hitLines"] or not recomputed:
            refuse("inventory")
        hitlist.extend([path, line] for line in row["hitLines"])
        if row["disposition"] in ("PINNED", "NAMED"):
            expected_group = "pinned" if row["disposition"] == "PINNED" else "named"
            if group_of.get(path) != (expected_group, row["class"]):
                refuse("disposition")
            continue
        if path in group_of:
            refuse("twice")
        if path not in supersedes_paths:
            line_files.append(path)
            if path_class(path) is not None:
                refuse("lineFile")
        given = row["lines"]
        if not isinstance(given, list) or [entry.get("line") if isinstance(entry, dict) else None for entry in given] \
                != row["hitLines"]:
            refuse("disposition")
            continue
        for entry in given:
            kind = entry.get("disposition")
            members = ("disposition", "line", "reason") if kind == "NOT_OWNERSHIP" else ("disposition", "line")
            if tuple(sorted(entry)) != members or kind not in LINE_DISPOSITIONS:
                refuse("disposition")
                continue
            if kind == "NOT_OWNERSHIP" and entry["reason"] not in NOT_OWNERSHIP_REASONS:
                refuse("disposition")
            covered = any(first <= entry["line"] <= last for first, last in ranges.get(path, []))
            if kind == "QUOTED" and not covered:
                refuse("disposition")
            if covered and kind != "QUOTED":
                refuse("covered")
    places.extend(line_files)
    if len(places) != len(set(places)):
        refuse("twice")
    if keys != sorted(keys) or len(set(keys)) != len(keys):
        refuse("order")
    inventoried = set(keys)
    if not set(group_of) <= inventoried or not supersedes_paths <= inventoried:
        refuse("inventory")
    if sha(json.dumps(hitlist, separators=(",", ":")).encode()) != inv["searchDigest"]:
        refuse("digest")

    # changed files (BUILD_RULES S3-7; C1-12: compared case-folded)
    changed = {path.casefold() for path in changed_files}
    if changed & {path.casefold() for path in gate_paths}:
        refuse("gate")
    protected = supersedes_paths | {row.get("path") for row in amends if isinstance(row, dict)} | \
        {path for path, (group, _) in group_of.items() if group == "pinned"} | \
        {row.get("path") for row in cross if isinstance(row, dict)}
    if changed & {path.casefold() for path in protected if isinstance(path, str)}:
        refuse("pinned")
    return sorted(refusals)
