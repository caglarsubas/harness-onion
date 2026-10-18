#!/usr/bin/env python3
"""Validate the MET-ENFORCE-029 compiled filter programs v2 and the exact 240-to-239 projection."""
from __future__ import annotations

import ast
import base64
import binascii
import copy
import hashlib
import json
import stat
import types
from functools import lru_cache
from pathlib import Path
from types import MappingProxyType
from typing import Any

try:
    from safe_yaml import safe_load
    import validate_chain_depth_headroom as successor
except ImportError:
    from scripts.safe_yaml import safe_load
    from scripts import validate_chain_depth_headroom as successor


ROOT = Path(__file__).resolve().parents[1]
AUTHORITY_PATH = "architecture/compiled-filter-programs-v2-authority.json"
AUTHORITY_SHA256 = "db3575d44eff7b084165e55423d45a3a8d5405826d2cc5f4902e00f4055f3afa"
VALIDATOR_PATH = "scripts/validate_compiled_filter_programs_v2.py"
BASE_COMMIT = "5e83b257677d7596f479e66cbe8431e6b8a99ec4"
NEW_PACKET = "MET-ENFORCE-029"
PREVIOUS_PACKET = "MET-ENFORCE-028"
MAX_FILE_BYTES = 16_777_216
# Test routes cover the top-level ci/test_ files as well as tests/.
TEST_PREFIXES = ("tests/", "ci/test_")


def require(ok: bool, message: str) -> None:
    if not ok:
        raise ValueError(message)


def digest(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def canonical(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, ensure_ascii=False,
                      separators=(",", ":"), allow_nan=False).encode("utf-8")


def parse(raw: bytes) -> Any:
    def unique(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            require(key not in result, "duplicate compiled-filter-programs-v2 authority member")
            result[key] = value
        return result

    def no_constant(_value: str) -> Any:
        raise ValueError("nonfinite compiled-filter-programs-v2 authority number")

    return json.loads(raw, object_pairs_hook=unique, parse_constant=no_constant)


def _path(path: Any) -> None:
    require(type(path) is str and bool(path) and not path.startswith("/")
            and "\\" not in path and not any(ord(char) < 32 for char in path)
            and all(part not in ("", ".", "..") for part in path.split("/")),
            "relative source path")


def regular_bytes(path: str) -> bytes:
    _path(path)
    parent = ROOT
    for part in path.split("/")[:-1]:
        parent /= part
        require(stat.S_ISDIR(parent.lstat().st_mode), "linked source ancestor")
    target = parent / path.split("/")[-1]
    before = target.lstat()
    require(stat.S_ISREG(before.st_mode) and before.st_nlink == 1
            and before.st_size <= MAX_FILE_BYTES, "bounded regular source file")
    raw = target.read_bytes()
    after = target.lstat()
    identity = lambda row: (row.st_dev, row.st_ino, row.st_mode, row.st_nlink,
                            row.st_size, row.st_mtime_ns, row.st_ctime_ns)
    require(identity(before) == identity(after) and len(raw) == before.st_size,
            "source changed during read")
    return raw


# Exact bytes most recently proven to hash to the pin. Every call still reads
# the complete file; byte-identical input implies the identical digest, while
# any other bytes or pin are hashed in full before they are accepted.
_VERIFIED_AUTHORITY: tuple[str, bytes] | None = None


def _checked_authority_raw() -> bytes:
    """Newest first: every newer authority, then this one, each read exactly once."""
    successor._checked_authority_raw()
    return _checked_own_authority_raw()


def _checked_own_authority_raw() -> bytes:
    """Fresh complete read of this layer's authority only; callers reach newer
    authorities through exactly one successor route per public call."""
    global _VERIFIED_AUTHORITY
    raw = regular_bytes(AUTHORITY_PATH)
    if type(raw) is not bytes or _VERIFIED_AUTHORITY != (AUTHORITY_SHA256, raw):
        require(digest(raw) == AUTHORITY_SHA256, "compiled filter programs v2 history authority digest")
        if type(raw) is bytes:
            _VERIFIED_AUTHORITY = (AUTHORITY_SHA256, raw)
    return raw


def fresh_authority() -> None:
    """Re-read the complete pinned authority without reparsing its JSON."""
    _checked_authority_raw()


def _sha(value: Any) -> bool:
    return type(value) is str and len(value) == 64 and all(c in "0123456789abcdef" for c in value)


def authority() -> dict[str, Any]:
    value = parse(_checked_authority_raw())
    require(type(value) is dict and set(value) == {
        "schemaVersion", "authorityPacket", "acceptedBase", "baselinePackets",
        "packetSha256", "changedFiles", "newFiles", "validatorNormalizedSha256",
    }, "closed compiled filter programs v2 history authority")
    require(value["schemaVersion"] == "harness.planeon.ai/compiled-filter-programs-v2-authority/v1"
            and value["authorityPacket"] == NEW_PACKET
            and value["acceptedBase"] == BASE_COMMIT
            and type(value["baselinePackets"]) is dict
            and len(value["baselinePackets"]) == 239
            and NEW_PACKET not in value["baselinePackets"]
            and type(value["changedFiles"]) is dict
            and type(value["newFiles"]) is dict
            and _sha(value["packetSha256"])
            and _sha(value["validatorNormalizedSha256"]),
            "accepted 239-packet base")
    for name, expected in value["baselinePackets"].items():
        require(type(name) is str and name and "/" not in name
                and all(char in "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-" for char in name)
                and _sha(expected), "predecessor packet identity")
    for path, expected in value["newFiles"].items():
        _path(path)
        require(_sha(expected), "new source digest")
    for path in value["changedFiles"]:
        _path(path)
    special = {AUTHORITY_PATH, VALIDATOR_PATH, "task-packets/" + NEW_PACKET + ".yaml"}
    require(not (set(value["changedFiles"]) & set(value["newFiles"]))
            and not (special & (set(value["changedFiles"]) | set(value["newFiles"])))
            and all(not path.startswith("task-packets/") or path == "task-packets/README.md"
                    for path in set(value["changedFiles"]) | set(value["newFiles"])),
            "disjoint source routes and immutable predecessor packets")
    return value


def _base64(value: Any) -> bytes:
    require(type(value) is str, "inverse hunk encoding")
    try:
        raw = base64.b64decode(value, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise ValueError("inverse hunk encoding") from exc
    require(base64.b64encode(raw).decode("ascii") == value, "noncanonical inverse hunk")
    return raw


def _rules() -> MappingProxyType:
    changed = authority()["changedFiles"]
    frozen = {}
    for path, rule in changed.items():
        require(type(rule) is dict
                and set(rule) == {"beforeSha256", "afterSha256", "reverseHunks"}
                and _sha(rule["beforeSha256"]) and _sha(rule["afterSha256"])
                and rule["beforeSha256"] != rule["afterSha256"]
                and type(rule["reverseHunks"]) is list
                and 0 < len(rule["reverseHunks"]) <= 4096, "closed inverse route")
        hunks = []
        prior_at, prior_end, total = -1, 0, 0
        for hunk in rule["reverseHunks"]:
            require(type(hunk) is dict
                    and set(hunk) == {"at", "removeBase64", "insertBase64"}
                    and type(hunk["at"]) is int
                    and 0 <= hunk["at"] <= MAX_FILE_BYTES
                    and prior_at < hunk["at"] and hunk["at"] >= prior_end,
                    "ordered inverse hunk")
            removed, inserted = _base64(hunk["removeBase64"]), _base64(hunk["insertBase64"])
            require(removed != inserted, "effective inverse hunk")
            total += len(removed) + len(inserted)
            require(total <= MAX_FILE_BYTES and hunk["at"] + len(removed) <= MAX_FILE_BYTES,
                    "bounded inverse payload")
            hunks.append((hunk["at"], removed, inserted))
            prior_at, prior_end = hunk["at"], hunk["at"] + len(removed)
        frozen[path] = MappingProxyType({"beforeSha256": rule["beforeSha256"],
                                         "afterSha256": rule["afterSha256"],
                                         "reverseHunks": tuple(hunks)})
    return MappingProxyType(frozen)


_PROJECTION_RULES = _rules()


def _packet_byte_rules() -> MappingProxyType:
    record = authority()
    return MappingProxyType(dict(record["baselinePackets"],
                                 **{NEW_PACKET: record["packetSha256"]}))


_PACKET_BYTE_RULES = _packet_byte_rules()


def _new_packet_rule() -> tuple[str, str]:
    checksum = _PACKET_BYTE_RULES[NEW_PACKET]
    raw = regular_bytes("task-packets/" + NEW_PACKET + ".yaml")
    require(digest(raw) == checksum, "packet YAML drift: " + NEW_PACKET)
    return checksum, digest(canonical(safe_load(raw)))


_NEW_PACKET_RULE = _new_packet_rule()


@lru_cache(maxsize=1)
def _packet_rules_for(source_root: Path, authority_sha: str) -> MappingProxyType:
    """Freeze expected payload digests once per exact source-root/authority pin."""
    require(source_root == ROOT and authority_sha == AUTHORITY_SHA256,
            "packet source identity changed")
    _checked_authority_raw()
    own_raw = regular_bytes("task-packets/" + NEW_PACKET + ".yaml")
    require(digest(own_raw) == _NEW_PACKET_RULE[0],
            "packet YAML drift: " + NEW_PACKET)
    rules = {NEW_PACKET: _NEW_PACKET_RULE}
    for name, checksum in _PACKET_BYTE_RULES.items():
        if name == NEW_PACKET:
            continue
        raw = regular_bytes("task-packets/" + name + ".yaml")
        require(digest(raw) == checksum, "packet YAML drift: " + name)
        rules[name] = (checksum, digest(canonical(safe_load(raw))))
    return MappingProxyType(rules)


def _packet_rules() -> MappingProxyType:
    return _packet_rules_for(ROOT, AUTHORITY_SHA256)


# Only expected parsed-data digests are cached, never a validation verdict.
# Historical traversal checks just this layer's packet. Full payload validation
# hashes every supplied packet anew, and validate() rereads every on-disk YAML.


def _inverse(raw: bytes, hunks: tuple[tuple[int, bytes, bytes], ...]) -> bytes:
    cursor, chunks = 0, []
    for at, removed, inserted in hunks:
        require(type(at) is int and cursor <= at and at + len(removed) <= len(raw),
                "inverse hunk bounds")
        require(raw[at:at + len(removed)] == removed, "inverse hunk current bytes")
        chunks.extend((raw[cursor:at], inserted))
        cursor = at + len(removed)
    chunks.append(raw[cursor:])
    before = b"".join(chunks)
    require(len(before) <= MAX_FILE_BYTES, "bounded predecessor bytes")
    return before


def historical_bytes(path: str, raw: bytes) -> bytes:
    """Undo the newer successor, then this step; every authority is read once."""
    _path(path)
    require(type(raw) is bytes and len(raw) <= MAX_FILE_BYTES, "bounded source bytes required")
    rule = _PROJECTION_RULES.get(path)
    # An exact 239-era byte string is already older than the successor layer.
    # Every newer authority and this one are still rechecked before this fast return.
    if rule is not None and digest(raw) == rule["beforeSha256"]:
        _checked_authority_raw()
        return raw
    # The successor route freshly rechecks every newer authority exactly once.
    raw = successor.historical_bytes(path, raw)
    _checked_own_authority_raw()
    return _undo_this_layer(path, raw)


def _undo_this_layer(path: str, raw: bytes) -> bytes:
    """Apply only this layer's reviewed inverse; callers have already rechecked authorities."""
    rule = _PROJECTION_RULES.get(path)
    if rule is None:
        return raw
    current_sha = digest(raw)
    require(current_sha in (rule["beforeSha256"], rule["afterSha256"]),
            "unreviewed current source: " + path)
    if current_sha == rule["beforeSha256"]:
        return raw
    before = _inverse(raw, rule["reverseHunks"])
    require(digest(before) == rule["beforeSha256"], "predecessor bytes: " + path)
    return before


def historical_test_bytes(raw: bytes) -> bytes:
    require(type(raw) is bytes and len(raw) <= MAX_FILE_BYTES, "bounded test bytes required")
    raw = successor.historical_test_bytes(raw)
    _checked_own_authority_raw()
    current_sha = digest(raw)
    matches = [path for path, rule in _PROJECTION_RULES.items()
               if path.startswith(TEST_PREFIXES) and current_sha == rule["afterSha256"]]
    require(len(matches) <= 1, "ambiguous current test")
    return _undo_this_layer(matches[0], raw) if matches else raw


def current_test_bytes(before: bytes) -> bytes:
    require(type(before) is bytes and len(before) <= MAX_FILE_BYTES, "bounded test bytes required")
    before_sha = digest(before)
    matches = [path for path, rule in _PROJECTION_RULES.items()
               if path.startswith(TEST_PREFIXES) and before_sha == rule["beforeSha256"]]
    require(len(matches) <= 1, "ambiguous predecessor test")
    if not matches:
        current = successor.current_test_bytes(before)
        _checked_own_authority_raw()
        return current
    current = successor.historical_bytes(matches[0], regular_bytes(matches[0]))
    _checked_own_authority_raw()
    require(digest(current) == _PROJECTION_RULES[matches[0]]["afterSha256"],
            "current test drift")
    return successor.current_test_bytes(current)


def historical_catalog(packets: dict[str, Any]) -> dict[str, Any]:
    """Remove only this layer, leaving predecessor checks to their owners."""
    packets = successor.historical_catalog(packets)
    _checked_own_authority_raw()
    require(type(packets) is dict, "packet mapping")
    current_ids = set(_PACKET_BYTE_RULES)
    require(NEW_PACKET in current_ids and set(packets) == current_ids,
            "unexpected packet addition or loss")
    packet_raw = regular_bytes("task-packets/" + NEW_PACKET + ".yaml")
    require(digest(packet_raw) == _NEW_PACKET_RULE[0],
            "packet YAML drift: " + NEW_PACKET)
    try:
        supplied_sha = digest(canonical(packets[NEW_PACKET]))
    except (TypeError, ValueError, RecursionError) as exc:
        raise ValueError("changed packet payload: " + NEW_PACKET) from exc
    require(supplied_sha == _NEW_PACKET_RULE[1],
            "changed packet payload: " + NEW_PACKET)
    return {name: packets[name] for name in current_ids - {NEW_PACKET}}


def validate_packet_payloads(packets: dict[str, Any]) -> None:
    """Check all current payloads separately from the inherited traversal."""
    record = authority()
    rules = _packet_rules()
    require(type(packets) is dict, "packet mapping")
    old = set(record["baselinePackets"])
    require(set(packets) == old | {NEW_PACKET}, "unexpected packet addition or loss")
    require(set(rules) == old | {NEW_PACKET}
            and all(rules[name][0] == expected
                    for name, expected in record["baselinePackets"].items())
            and rules[NEW_PACKET][0] == record["packetSha256"],
            "pinned packet data inventory")
    for name, (_byte_sha, payload_sha) in rules.items():
        try:
            supplied_sha = digest(canonical(packets[name]))
        except (TypeError, ValueError, RecursionError) as exc:
            raise ValueError("changed packet payload: " + name) from exc
        require(supplied_sha == payload_sha, "changed packet payload: " + name)


# MET-ENFORCE-029 (roadmap PROGRAMS-REPUBLISH; owner decisions Q-HE3A-1 (c) and Q-HE3A-1b (a), 2026-10-13, and the lane
# monitor's owner-delegated Q-HE3D-3 (a) and Q-PR-1..10 (a), 2026-10-15) publishes the compiled seccomp filter programs v2
# (architecture/compiled-filter-programs-v2/): the EFFECT_GATE programs republished from the adopted seccomp allowlists v4
# on both architectures, an index of all fourteen v4 programs (twelve at MET-ENFORCE-025's paths), the publisher
# scripts/compiled_filter_programs_v2.py, the operator -> harness-engineering edge record v3 (v2's 31 rows plus the two
# programs, registered for R10's HE-003A2 under host-enforcement/contracts/seccomp-v4/) and a status record that adopts
# them after one independent review round and discharges allowlists v4's open republication item. MET-ENFORCE-025's
# programs and publisher, the v1, v2 and EDGE-2 edge records, allowlists v3 and v4 with both models, the repository
# registry and the W03 plan v2 stay byte-identical. Repository bytes are read only through reviewed_bytes, and the
# contract's file modes and directory listing only through reviewed_mode and reviewed_tree, so a later bridged successor
# projects its own edits away first. Every reviewed file of this era, and every input it is checked against, is bound by
# digest before anything is parsed and on every later read; the v4 model and safe_yaml are executed from this era's
# bytes, never imported. The publisher's claims are checked here independently of it, together with what it does not
# check (review notes R1-1, R1-3, R1-6 and R1-7): all fourteen programs are the v4 model's output with v4's digests and
# lengths; the twelve programs of the other roles are byte-identical to MET-ENFORCE-025's files; each EFFECT_GATE program
# is MET-ENFORCE-025's v3 program with exactly the six-instruction readlinkat block inserted; every v4 EFFECT_GATE decision
# vector replays through the published bytes; and the index, edge record v3, both README status lines, the status record
# and the contract's closed file set and modes are restated here.
CONTRACT_DIR = "architecture/compiled-filter-programs-v2/"
PROGRAMS_DIR = CONTRACT_DIR + "programs/"
INDEX_PATH = CONTRACT_DIR + "index.json"
STATUS_PATH = CONTRACT_DIR + "status.json"
README_PATH = CONTRACT_DIR + "README.md"
REVIEW_BRIEF_PATH = CONTRACT_DIR + "REVIEW_BRIEF.md"
REVIEW_RECORD = CONTRACT_DIR + "review-round1.json"
PUBLISHER = "scripts/compiled_filter_programs_v2.py"
EDGES_DIR = "architecture/artifact-edges/"
V2_EDGE = EDGES_DIR + "operator-harness-engineering-v2.json"
V3_EDGE = EDGES_DIR + "operator-harness-engineering-v3.json"
V3_README = EDGES_DIR + "README-v3.md"
V4_MODEL = "scripts/seccomp_allowlists_v4.py"
V4_DIR = "architecture/seccomp-allowlists-v4/"
V4_SOURCES = (V4_MODEL, V4_DIR + "allowlists.json", V4_DIR + "syscalls.json", V4_DIR + "vectors.json")
V4_STATUS = V4_DIR + "status.json"
V4_PACKET = "MET-ENFORCE-027"
V4_COMMIT = "e7516160468c213862b337b344d240fde5f7328c"
# The SHA-256 of each v4 source the publisher pins (allowlists v4's reviewed round-3 subject).
V4_SOURCE_SHA256 = {'architecture/seccomp-allowlists-v4/allowlists.json': '4dcfb2dfea82eabd04024b35d9dac4bb487b6c0051f7e6e16bbd00426cf6b2ff',
 'architecture/seccomp-allowlists-v4/syscalls.json': 'd759e341afcbcf2dccd8eafce136a303d2275efceeac1525ef2200b6e65fe53d',
 'architecture/seccomp-allowlists-v4/vectors.json': '9a918c15bbcb6378b282df9a5da8389289bf505f9f8eb5e1a50b9c5bb6f92187',
 'scripts/seccomp_allowlists_v4.py': 'f88e3eab1a154260b2a33d7a1eadb5a78f29d49579219d3aaf55041ec861e9bf'}
PREDECESSOR_DIR = "architecture/compiled-filter-programs/"
PREDECESSOR_INDEX = PREDECESSOR_DIR + "index.json"
PREDECESSOR_INDEX_SHA256 = "9136ce1f450ad8bba0810e23ab5324e9e156cb851b1afefbf2f3f84b28d2cef7"
PREDECESSOR_PACKET = "MET-ENFORCE-025"
HS43_RECORD = "architecture/host-interface-amendment-hs43/amendment.json"
REPOSITORIES = "architecture/repositories.yaml"
SAFE_YAML = "scripts/safe_yaml.py"
# The nine contract files in the status record's order; the review record joined them at adoption. Review note R1-1: this
# is the complete file set, and each is a regular file of git mode 100644.
CONTRACT_FILES = (README_PATH, REVIEW_BRIEF_PATH, INDEX_PATH, PROGRAMS_DIR + "EFFECT_GATE.aarch64.bpf",
                  PROGRAMS_DIR + "EFFECT_GATE.x86_64.bpf", STATUS_PATH, V3_README, V3_EDGE, PUBLISHER)
NEW_FILES = CONTRACT_FILES + (REVIEW_RECORD,)
# The contract directory's complete tree: its seven files and the programs folder.
CONTRACT_TREE = frozenset({path for path in NEW_FILES if path.startswith(CONTRACT_DIR)} | {PROGRAMS_DIR[:-1]})
# MET-ENFORCE-029 is written in exactly these files (review note R1-6).
NAMING_FILES = frozenset({README_PATH, STATUS_PATH, REVIEW_RECORD, V3_README, V3_EDGE, PUBLISHER})
ARCHES = ("aarch64", "x86_64")
ROLES = ("BROKER", "EFFECT_GATE", "HOST_CONTAINMENT", "OBSERVER", "POLICY_WRITER", "SERVER", "WORKER")
GATE = "EFFECT_GATE"
# v4's instruction count (aarch64, x86_64) and SHA-256 per program; only EFFECT_GATE's differ from v3's.
PROGRAM_LENGTHS = {"BROKER": (311, 326), "EFFECT_GATE": (189, 200), "HOST_CONTAINMENT": (130, 141), "OBSERVER": (227, 238),
                   "POLICY_WRITER": (115, 126), "SERVER": (261, 276), "WORKER": (172, 187)}
PROGRAM_SHA256 = {'BROKER': ('bc9c5a3797277ca753b5168e8e55132e1878fed2a726de361fd7d80e0fababf8',
            '95221bd0db753aa22ead2eb49eeac8dae3d24c3dad72811de86c9392f4894dcc'),
 'EFFECT_GATE': ('8de80a2b597b84d9f5ace818e76ef15d4b15a5b02013bb479ca4fdf73df3d044',
                 '4e516f1682098c90edd568f8f214d3de01b404a2c144104596fc4e3262f6e7a3'),
 'HOST_CONTAINMENT': ('d9d57ecb4919ad453684be62b6e2b65c9818033c47291e8e7240f7c2224880eb',
                      'd0d0db066e8942bbe987bd89a8441ab4e84b1cb9933b3bad24d8fb6eb0a51292'),
 'OBSERVER': ('d31c841042de456bb784e8412f61429be7700aea2ffa508af2637283ebcb3707',
              'e793aae5ad04a7c82a67d3f102b837064e645a585b83ace0586169a1746eb25a'),
 'POLICY_WRITER': ('e3bf65e0ff60d6766eac92672ad21a3c34097e183f03de416c9ad2ba50d71a5b',
                   '0f690b0e2f18b1b092bc42f4042dc334cafa3aae81fb96851f569ba71f20d1bf'),
 'SERVER': ('a1bcb2de10f5a54d32578d9f26e3d7db69b0cfad8d868feea1914585fbb7f05a',
            '2e7af1da50b7d5df3cdcf8c18eb545f4972b2309b68d9eecba2e5f6ba5d1d8a7'),
 'WORKER': ('cc04a4710495d3794b0d295613a2f2bd330524a328cb6963a819565bac2acb40',
            '5616c9099324e441674f8e589b6c705ae95f6a4a697f10e761565d0735689d45')}
# MET-ENFORCE-025's v3 EFFECT_GATE programs, into which v4's one rule inserts its block.
V3_GATE_LENGTHS = {"aarch64": 183, "x86_64": 194}
V3_GATE_SHA256 = {'aarch64': '0ccbd7d090212fe52d366a2d68515670de40557cbc6fd07531653b404bb7105a',
 'x86_64': 'ee85e9d225ad687aec82f83cb7d7c1be95f16df5f68eec5b56ee913d6cd86115'}
# Where the block enters (instruction index, readlinkat syscall number), and its six instructions (code, jt, jf, k; None is
# the syscall number), as include/uapi/linux/filter.h, bpf_common.h and seccomp.h at v6.12 encode them: JEQ_K nr 0/5,
# LD_W_ABS arg 0's low word, AND_K bit 31, JEQ_K 0 0/1, RET ALLOW, RET KILL_PROCESS.
BLOCK_AT = {"aarch64": (34, 78), "x86_64": (173, 267)}
READLINKAT_BLOCK = ((0x15, 0, 5, None), (0x20, 0, 0, 0x10), (0x54, 0, 0, 0x80000000), (0x15, 0, 1, 0),
                    (0x06, 0, 0, 0x7FFF0000), (0x06, 0, 0, 0x80000000))
INSTRUCTION_BYTES = 8
# v4's EFFECT_GATE decision vectors per architecture, and how many of them test readlinkat (review note R1-7).
GATE_DECISIONS = {"aarch64": 195, "x86_64": 206}
GATE_READLINKAT_DECISIONS = {"aarch64": 10, "x86_64": 10}
INDEX_SCHEMA = "planeon.internal.compiled-filter-programs/v2"
INDEX_KEYS = ("schemaVersion", "evidenceClass", "format", "source", "predecessor", "programs")
INDEX_ROW_KEYS = ("role", "arch", "path", "instructions", "bytes", "sha256")
# Edge record v3: edge record v2's 31 rows, unchanged and in order, then the two EFFECT_GATE programs for R10's HE-003A2,
# the packet Q-HE3D-3 (a) names (review note R1-3), under host-enforcement/contracts/seccomp-v4/.
V2_EDGE_SHA256 = "749e70f174d638468bf45d7316e8f5201c3323f6348a78c7b9a22d3a571ccc32"
V2_ROWS = 31
EDGE_KEYS = ("schemaVersion", "graph", "consumer", "provider", "artifact", "ownerDecision", "rules", "notArtifacts",
             "statuses", "artifacts", "supersedes", "ownerDecisions", "notes")
PROGRAM_ROW_KEYS = ("providerPath", "providerCommit", "sha256", "mode", "consumerPath", "consumerPacket", "relation",
                    "status", "providerPacket")
V3_ARTIFACT = "w03-transport-effect-gate-contracts-and-compiled-filter-programs-v4-republication"
CONSUMER_PACKET = "HE-003A2"
CONSUMER_DIR = "host-enforcement/contracts/seccomp-v4/"
# The owner's decisions, verbatim: Q-HE3A-1 and Q-HE3A-1b as the HS43 amendment records them, and the lane monitor's two.
Q_HE3D_3 = ("the writer exe check isn't in HE-003D. It goes in HE-003A2 after the seccomp and programs chain merges; the "
            "enrolled path comes from the configuration (G4).")
Q_PR = ("[lane monitor] PROGRAMS-REPUBLISH: Q-PR-1..10 = (a), all of them. Monitor (owner-delegated), 2026-10-15; record "
        "verbatim.\n- a new architecture/compiled-filter-programs-v2/;\n- only EFFECT_GATE re-emitted, with the other 12 "
        "proven equal to 232's bytes;\n- edge record v3 = v2's 31 rows plus 2;\n- the R10 consumer path "
        "contracts/seccomp-v4/;\n- the other rows unchanged;\n- the pinned v4 model plus the exact 6-instruction-block layer "
        "check;\n- v4 vector replay;\n- a status.json adoption discharging v4's obligation;\n- no riders;\n- MET-ENFORCE-029, "
        "with the contract reviewed on 9f251d5 and rebased unchanged onto 239's merge at mechanics time.\nGo ahead with the "
        "contract design and the independent review, as light work.")
# (id, date, the edge record's prefix) in the records' order; the status record holds each decision text, the edge record
# its prefix and text. Q-HE3A-1 and Q-HE3A-1b are the HS43 record's texts; the monitor's two are restated with their
# (status, edge) texts.
DECISIONS = (("Q-HE3A-1", "2026-10-13", "Q-HE3A-1 = (c) (2026-10-13, owner via the lane monitor, verbatim as "
              "architecture/host-interface-amendment-hs43/amendment.json records it): "),
             ("Q-HE3A-1b", "2026-10-13", "Q-HE3A-1b = (a) (2026-10-13, owner via the lane monitor, verbatim as "
              "architecture/host-interface-amendment-hs43/amendment.json records it): "),
             ("Q-HE3D-3", "2026-10-15", "Q-HE3D-3 = (a) (2026-10-15, the lane monitor under the owner's delegation, "
              "HE-003D decisions, verbatim): "),
             ("Q-PR-1..10", "2026-10-15", "Q-PR-1..10 = (a) (2026-10-15, the lane monitor under the owner's delegation, "
              "PROGRAMS-REPUBLISH decisions, verbatim): "))
MONITOR_DECISIONS = {"Q-HE3D-3": ("(a): " + Q_HE3D_3, Q_HE3D_3), "Q-PR-1..10": (Q_PR, Q_PR)}
# Both READMEs keep their candidate status line after adoption (review notes R1-4 and R1-7).
CANDIDATE = "SUCCESSOR_CANDIDATE_AWAITING_INDEPENDENT_REVIEW"
STATUS_LINE = "Status: **" + CANDIDATE + "**"
STATUS_KEYS = ("schemaVersion", "packet", "roadmapItem", "contractState", "evidenceClass", "base", "rebase", "predecessor",
               "source", "contractFiles", "reviewRounds", "keptCopies", "ownerDecisions", "discharges", "openObligations",
               "carriedToR10", "reviewerIndependence", "readmeStatusNote", "carriedNotes", "adoptionEdit")
ROUND_KEYS = ("round", "record", "recordSha256", "subject", "verdict", "findings")
RECORD_KEYS = ("round", "subject", "reviewer", "verdict", "findings", "checksRun", "actions")
REVIEW_BASE = "9f251d5d07772cbfb9987c422f3fca79748fad34"
REVIEWED_SUBJECT = {"commit": "325ad78446ee3d5a2882c48a582e3152fc50184f", "tree": "6b874264f478fcbeacc56f7751e22c7e3e4d5f25", "base": REVIEW_BASE}
REVIEW_FINDINGS = ("R1-1", "R1-2", "R1-3", "R1-4", "R1-5", "R1-6", "R1-7")
# R1-4 is resolved by readmeStatusNote; the other notes are carried.
CARRIED = ("R1-1", "R1-2", "R1-3", "R1-5", "R1-6", "R1-7")
# The round-1 subject's bytes of every contract file the adoption left unchanged: status.json alone was edited.
REVIEWED_SHA256 = {'architecture/artifact-edges/README-v3.md': 'd6edd8cc7f8b209c1cf7bd0a16a941e0661ef040f8920cbdbda4c323c0f0f011',
 'architecture/artifact-edges/operator-harness-engineering-v3.json': '106ea91aa09c2d377adf3b514a228331d6a805bd1a17e641ecaa23b3c39115f3',
 'architecture/compiled-filter-programs-v2/README.md': 'c0661972d3f92bffde4098d5313269e12c4ef7ce4f428fc80ad9cbd9d9339fbb',
 'architecture/compiled-filter-programs-v2/REVIEW_BRIEF.md': '217258cb03947edaf3aed3b1a7ed0293cfe161eac371300e827d7aa0fd018cbb',
 'architecture/compiled-filter-programs-v2/index.json': '59581bbfb75e81f364382833b94be6c42f4e2a658c49711b4e72712434ef69cb',
 'architecture/compiled-filter-programs-v2/programs/EFFECT_GATE.aarch64.bpf': '8de80a2b597b84d9f5ace818e76ef15d4b15a5b02013bb479ca4fdf73df3d044',
 'architecture/compiled-filter-programs-v2/programs/EFFECT_GATE.x86_64.bpf': '4e516f1682098c90edd568f8f214d3de01b404a2c144104596fc4e3262f6e7a3',
 'scripts/compiled_filter_programs_v2.py': '1d7f24fd24f6ab645d6ad11d7d0d69663596ff605059b6b77bb5ede9b24cb259'}
OPEN_ITEM = "the compiled filter programs and the edge record are republished from v4 (Q-HE3A-1b)"
# MET-ENFORCE-025's programs and publisher, the v1, v2 and EDGE-2 edge records and their READMEs, allowlists v3 and v4
# with both models, the repository registry and the W03 plan v2: no file changed or added.
FROZEN_DIRS = (PREDECESSOR_DIR, "architecture/seccomp-allowlists-v3/", V4_DIR, "architecture/w03-plan-v2/")
FROZEN_PATHS = (
    "architecture/artifact-edges/README-v2.md",
    "architecture/artifact-edges/README.md",
    "architecture/artifact-edges/conformance-labs-harness-engineering.json",
    "architecture/artifact-edges/operator-harness-engineering-v2.json",
    "architecture/artifact-edges/operator-harness-engineering.json",
    "architecture/compiled-filter-programs/README.md",
    "architecture/compiled-filter-programs/index.json",
    "architecture/compiled-filter-programs/programs/BROKER.aarch64.bpf",
    "architecture/compiled-filter-programs/programs/BROKER.x86_64.bpf",
    "architecture/compiled-filter-programs/programs/EFFECT_GATE.aarch64.bpf",
    "architecture/compiled-filter-programs/programs/EFFECT_GATE.x86_64.bpf",
    "architecture/compiled-filter-programs/programs/HOST_CONTAINMENT.aarch64.bpf",
    "architecture/compiled-filter-programs/programs/HOST_CONTAINMENT.x86_64.bpf",
    "architecture/compiled-filter-programs/programs/OBSERVER.aarch64.bpf",
    "architecture/compiled-filter-programs/programs/OBSERVER.x86_64.bpf",
    "architecture/compiled-filter-programs/programs/POLICY_WRITER.aarch64.bpf",
    "architecture/compiled-filter-programs/programs/POLICY_WRITER.x86_64.bpf",
    "architecture/compiled-filter-programs/programs/SERVER.aarch64.bpf",
    "architecture/compiled-filter-programs/programs/SERVER.x86_64.bpf",
    "architecture/compiled-filter-programs/programs/WORKER.aarch64.bpf",
    "architecture/compiled-filter-programs/programs/WORKER.x86_64.bpf",
    "architecture/compiled-filter-programs/reviews/review-round1.json",
    "architecture/compiled-filter-programs/reviews/review-round2.json",
    "architecture/compiled-filter-programs/reviews/review-round3.json",
    "architecture/compiled-filter-programs/reviews/review-round4.json",
    "architecture/compiled-filter-programs/rounds/round1/architecture/artifact-edges/README-v2.md",
    "architecture/compiled-filter-programs/rounds/round1/architecture/artifact-edges/conformance-labs-harness-engineering.json",
    "architecture/compiled-filter-programs/rounds/round1/architecture/artifact-edges/operator-harness-engineering-v2.json",
    "architecture/compiled-filter-programs/rounds/round1/architecture/compiled-filter-programs/README.md",
    "architecture/compiled-filter-programs/rounds/round1/architecture/w03-obligation-amendment-1/README.md",
    "architecture/compiled-filter-programs/rounds/round1/architecture/w03-obligation-amendment-1/amendment.json",
    "architecture/compiled-filter-programs/rounds/round1/scripts/compiled_filter_programs.py",
    "architecture/compiled-filter-programs/rounds/round2/architecture/artifact-edges/README-v2.md",
    "architecture/compiled-filter-programs/rounds/round2/architecture/artifact-edges/conformance-labs-harness-engineering.json",
    "architecture/compiled-filter-programs/rounds/round2/architecture/w03-obligation-amendment-1/README.md",
    "architecture/compiled-filter-programs/rounds/round2/architecture/w03-obligation-amendment-1/amendment.json",
    "architecture/compiled-filter-programs/rounds/round3/architecture/w03-obligation-amendment-1/README.md",
    "architecture/compiled-filter-programs/rounds/round3/architecture/w03-obligation-amendment-1/amendment.json",
    "architecture/compiled-filter-programs/status.json",
    "architecture/repositories.yaml",
    "architecture/seccomp-allowlists-v3/README.md",
    "architecture/seccomp-allowlists-v3/REVIEW_BRIEF.md",
    "architecture/seccomp-allowlists-v3/allowlists.json",
    "architecture/seccomp-allowlists-v3/review-round1.json",
    "architecture/seccomp-allowlists-v3/review-round2.json",
    "architecture/seccomp-allowlists-v3/round1/architecture/seccomp-allowlists-v3/README.md",
    "architecture/seccomp-allowlists-v3/round1/architecture/seccomp-allowlists-v3/REVIEW_BRIEF.md",
    "architecture/seccomp-allowlists-v3/source-index.json",
    "architecture/seccomp-allowlists-v3/status.json",
    "architecture/seccomp-allowlists-v3/syscalls.json",
    "architecture/seccomp-allowlists-v3/vectors.json",
    "architecture/seccomp-allowlists-v4/README.md",
    "architecture/seccomp-allowlists-v4/REVIEW_BRIEF.md",
    "architecture/seccomp-allowlists-v4/allowlists.json",
    "architecture/seccomp-allowlists-v4/review-round1.json",
    "architecture/seccomp-allowlists-v4/review-round2.json",
    "architecture/seccomp-allowlists-v4/review-round3.json",
    "architecture/seccomp-allowlists-v4/round1/architecture/seccomp-allowlists-v4/README.md",
    "architecture/seccomp-allowlists-v4/round1/architecture/seccomp-allowlists-v4/REVIEW_BRIEF.md",
    "architecture/seccomp-allowlists-v4/round1/architecture/seccomp-allowlists-v4/allowlists.json",
    "architecture/seccomp-allowlists-v4/round1/architecture/seccomp-allowlists-v4/syscalls.json",
    "architecture/seccomp-allowlists-v4/round1/architecture/seccomp-allowlists-v4/vectors.json",
    "architecture/seccomp-allowlists-v4/round1/scripts/seccomp_allowlists_v4.py",
    "architecture/seccomp-allowlists-v4/round2/architecture/seccomp-allowlists-v4/README.md",
    "architecture/seccomp-allowlists-v4/round2/architecture/seccomp-allowlists-v4/REVIEW_BRIEF.md",
    "architecture/seccomp-allowlists-v4/round2/architecture/seccomp-allowlists-v4/allowlists.json",
    "architecture/seccomp-allowlists-v4/round2/architecture/seccomp-allowlists-v4/syscalls.json",
    "architecture/seccomp-allowlists-v4/round2/architecture/seccomp-allowlists-v4/vectors.json",
    "architecture/seccomp-allowlists-v4/source-index.json",
    "architecture/seccomp-allowlists-v4/status.json",
    "architecture/seccomp-allowlists-v4/syscalls.json",
    "architecture/seccomp-allowlists-v4/vectors.json",
    "architecture/w03-plan-v2/README.md",
    "architecture/w03-plan-v2/plan.json",
    "architecture/w03-plan-v2/review-round1.json",
    "architecture/w03-plan-v2/review-round2.json",
    "architecture/w03-plan-v2/review-round3.json",
    "architecture/w03-plan-v2/review-round4.json",
    "architecture/w03-plan-v2/round1/README.md",
    "architecture/w03-plan-v2/round1/artifact-edges/README.md",
    "architecture/w03-plan-v2/round1/artifact-edges/operator-harness-engineering.json",
    "architecture/w03-plan-v2/round1/i05-gate-channel-v3-supplement/README.md",
    "architecture/w03-plan-v2/round1/i05-gate-channel-v3-supplement/vectors.json",
    "architecture/w03-plan-v2/round1/plan.json",
    "architecture/w03-plan-v2/round1/scripts/w03_plan_v2.py",
    "architecture/w03-plan-v2/round2/README.md",
    "architecture/w03-plan-v2/round2/artifact-edges/README.md",
    "architecture/w03-plan-v2/round2/artifact-edges/operator-harness-engineering.json",
    "architecture/w03-plan-v2/round2/i05-gate-channel-v3-supplement/README.md",
    "architecture/w03-plan-v2/round2/i05-gate-channel-v3-supplement/vectors.json",
    "architecture/w03-plan-v2/round2/plan.json",
    "architecture/w03-plan-v2/round2/scripts/w03_plan_v2.py",
    "architecture/w03-plan-v2/round3/README.md",
    "architecture/w03-plan-v2/round3/artifact-edges/README.md",
    "architecture/w03-plan-v2/round3/artifact-edges/operator-harness-engineering.json",
    "architecture/w03-plan-v2/round3/i05-gate-channel-v3-supplement/README.md",
    "architecture/w03-plan-v2/round3/i05-gate-channel-v3-supplement/vectors.json",
    "architecture/w03-plan-v2/round3/plan.json",
    "architecture/w03-plan-v2/round3/scripts/w03_plan_v2.py",
    "architecture/w03-plan-v2/status.json",
    "scripts/compiled_filter_programs.py",
    "scripts/seccomp_allowlists_v3.py",
    "scripts/seccomp_allowlists_v4.py",
)
# The adopted bytes of every contract file and of every input it is checked against.
ERA_SHA256 = MappingProxyType({
    "architecture/artifact-edges/README-v3.md": "d6edd8cc7f8b209c1cf7bd0a16a941e0661ef040f8920cbdbda4c323c0f0f011",
    "architecture/artifact-edges/operator-harness-engineering-v2.json": "749e70f174d638468bf45d7316e8f5201c3323f6348a78c7b9a22d3a571ccc32",
    "architecture/artifact-edges/operator-harness-engineering-v3.json": "106ea91aa09c2d377adf3b514a228331d6a805bd1a17e641ecaa23b3c39115f3",
    "architecture/compiled-filter-programs-v2/README.md": "c0661972d3f92bffde4098d5313269e12c4ef7ce4f428fc80ad9cbd9d9339fbb",
    "architecture/compiled-filter-programs-v2/REVIEW_BRIEF.md": "217258cb03947edaf3aed3b1a7ed0293cfe161eac371300e827d7aa0fd018cbb",
    "architecture/compiled-filter-programs-v2/index.json": "59581bbfb75e81f364382833b94be6c42f4e2a658c49711b4e72712434ef69cb",
    "architecture/compiled-filter-programs-v2/programs/EFFECT_GATE.aarch64.bpf": "8de80a2b597b84d9f5ace818e76ef15d4b15a5b02013bb479ca4fdf73df3d044",
    "architecture/compiled-filter-programs-v2/programs/EFFECT_GATE.x86_64.bpf": "4e516f1682098c90edd568f8f214d3de01b404a2c144104596fc4e3262f6e7a3",
    "architecture/compiled-filter-programs-v2/review-round1.json": "19d910b9e42e0a1bf94875211394c481c25e9234a95c0c20cf26ee0318465412",
    "architecture/compiled-filter-programs-v2/status.json": "829fdbad7853f2133d26464d422651308aec2b764aa86a4701c60a95a0fe1b48",
    "architecture/compiled-filter-programs/index.json": "9136ce1f450ad8bba0810e23ab5324e9e156cb851b1afefbf2f3f84b28d2cef7",
    "architecture/compiled-filter-programs/programs/BROKER.aarch64.bpf": "bc9c5a3797277ca753b5168e8e55132e1878fed2a726de361fd7d80e0fababf8",
    "architecture/compiled-filter-programs/programs/BROKER.x86_64.bpf": "95221bd0db753aa22ead2eb49eeac8dae3d24c3dad72811de86c9392f4894dcc",
    "architecture/compiled-filter-programs/programs/EFFECT_GATE.aarch64.bpf": "0ccbd7d090212fe52d366a2d68515670de40557cbc6fd07531653b404bb7105a",
    "architecture/compiled-filter-programs/programs/EFFECT_GATE.x86_64.bpf": "ee85e9d225ad687aec82f83cb7d7c1be95f16df5f68eec5b56ee913d6cd86115",
    "architecture/compiled-filter-programs/programs/HOST_CONTAINMENT.aarch64.bpf": "d9d57ecb4919ad453684be62b6e2b65c9818033c47291e8e7240f7c2224880eb",
    "architecture/compiled-filter-programs/programs/HOST_CONTAINMENT.x86_64.bpf": "d0d0db066e8942bbe987bd89a8441ab4e84b1cb9933b3bad24d8fb6eb0a51292",
    "architecture/compiled-filter-programs/programs/OBSERVER.aarch64.bpf": "d31c841042de456bb784e8412f61429be7700aea2ffa508af2637283ebcb3707",
    "architecture/compiled-filter-programs/programs/OBSERVER.x86_64.bpf": "e793aae5ad04a7c82a67d3f102b837064e645a585b83ace0586169a1746eb25a",
    "architecture/compiled-filter-programs/programs/POLICY_WRITER.aarch64.bpf": "e3bf65e0ff60d6766eac92672ad21a3c34097e183f03de416c9ad2ba50d71a5b",
    "architecture/compiled-filter-programs/programs/POLICY_WRITER.x86_64.bpf": "0f690b0e2f18b1b092bc42f4042dc334cafa3aae81fb96851f569ba71f20d1bf",
    "architecture/compiled-filter-programs/programs/SERVER.aarch64.bpf": "a1bcb2de10f5a54d32578d9f26e3d7db69b0cfad8d868feea1914585fbb7f05a",
    "architecture/compiled-filter-programs/programs/SERVER.x86_64.bpf": "2e7af1da50b7d5df3cdcf8c18eb545f4972b2309b68d9eecba2e5f6ba5d1d8a7",
    "architecture/compiled-filter-programs/programs/WORKER.aarch64.bpf": "cc04a4710495d3794b0d295613a2f2bd330524a328cb6963a819565bac2acb40",
    "architecture/compiled-filter-programs/programs/WORKER.x86_64.bpf": "5616c9099324e441674f8e589b6c705ae95f6a4a697f10e761565d0735689d45",
    "architecture/host-interface-amendment-hs43/amendment.json": "6a3719cdc659d7ccfde3598bdec06a31896fa82de810cf73ccc1f7ca3dc7f24c",
    "architecture/repositories.yaml": "02190a668c6a9114b3733724bec4e552c553867e789b0802f6aaa6759148051d",
    "architecture/seccomp-allowlists-v4/allowlists.json": "4dcfb2dfea82eabd04024b35d9dac4bb487b6c0051f7e6e16bbd00426cf6b2ff",
    "architecture/seccomp-allowlists-v4/status.json": "b2f82f66bf9ebb6cc52b7f8e9503250604e7b46310bccdd14e635f3ff08a21dc",
    "architecture/seccomp-allowlists-v4/syscalls.json": "d759e341afcbcf2dccd8eafce136a303d2275efceeac1525ef2200b6e65fe53d",
    "architecture/seccomp-allowlists-v4/vectors.json": "9a918c15bbcb6378b282df9a5da8389289bf505f9f8eb5e1a50b9c5bb6f92187",
    "scripts/compiled_filter_programs_v2.py": "1d7f24fd24f6ab645d6ad11d7d0d69663596ff605059b6b77bb5ede9b24cb259",
    "scripts/safe_yaml.py": "99c673560e65e58cdc1abe86e53472feaf93e546dd76cb9f3ba051beef5c49d7",
    "scripts/seccomp_allowlists_v4.py": "f88e3eab1a154260b2a33d7a1eadb5a78f29d49579219d3aaf55041ec861e9bf",
})


def reviewed_bytes(path: str) -> bytes:
    """This packet's reviewed bytes of path; a bridged successor projects newer bytes back first."""
    return successor.historical_bytes(path, regular_bytes(path))


def reviewed_mode(path: str) -> int:
    """The lstat mode of path in this packet's tree; a bridged successor projects a newer mode back first."""
    _path(path)
    return (ROOT / path).lstat().st_mode


def reviewed_tree(directory: str) -> dict[str, int]:
    """Every entry under directory in this packet's tree, by repository path, with its lstat mode; a bridged successor
    that adds an entry there projects it away first."""
    entries: dict[str, int] = {}
    pending = [directory.rstrip("/")]
    while pending:
        folder = pending.pop()
        for entry in sorted((ROOT / folder).iterdir()):
            relative = folder + "/" + entry.name
            entries[relative] = entry.lstat().st_mode
            if stat.S_ISDIR(entries[relative]):
                pending.append(relative)
    return entries


def _verified(path: str) -> bytes:
    """reviewed_bytes, checked against its era digest on every read; a path outside the era is refused."""
    expected = ERA_SHA256.get(path)
    require(expected is not None, "MET-ENFORCE-029 reviewed bytes are bound: " + path)
    raw = reviewed_bytes(path)
    require(type(raw) is bytes and digest(raw) == expected, "unreviewed compiled filter programs v2 source: " + path)
    return raw


def _json(path: str) -> Any:
    return parse(_verified(path))


def _holds(check: Any) -> bool:
    """A structural check over a module's result or a record; a malformed one does not hold."""
    try:
        return check() is True
    except (KeyError, TypeError, AttributeError, IndexError, ValueError):
        return False


def _bound(check: Any, message: str) -> None:
    require(_holds(check), message)


def _era_model(path: str, name: str) -> types.ModuleType:
    """A reference module of this era, executed from its verified bytes (no import, no bytecode)."""
    module = types.ModuleType(name)
    module.__file__ = str(ROOT / path)
    exec(compile(_verified(path), path, "exec", dont_inherit=True), module.__dict__)
    return module


def readlinkat_block(nr: int) -> bytes:
    """The six instructions v4's rule adds, encoded here independently of the model and the publisher."""
    return b"".join(code.to_bytes(2, "little") + bytes((jt, jf)) + (nr if k is None else k).to_bytes(4, "little")
                    for code, jt, jf, k in READLINKAT_BLOCK)


def _decode(raw: bytes) -> list[tuple[int, int, int, int]]:
    """The kernel's struct sock_filter array: little-endian u16 code, u8 jt, u8 jf, u32 k."""
    require(len(raw) % INSTRUCTION_BYTES == 0, "a program is a whole number of instructions")
    return [(int.from_bytes(raw[at:at + 2], "little"), raw[at + 2], raw[at + 3], int.from_bytes(raw[at + 4:at + 8], "little"))
            for at in range(0, len(raw), INSTRUCTION_BYTES)]


def _decision_texts(hs43: Any) -> dict[str, tuple[str, str]]:
    """(status record text, edge record text) per decision; Q-HE3A-1 and Q-HE3A-1b as the HS43 record holds them."""
    recorded = {row["id"]: row for row in hs43["ownerDecisions"]}
    texts = dict(MONITOR_DECISIONS)
    for name, date, _prefix in DECISIONS:
        if name not in texts:
            require(recorded[name]["date"] == date and recorded[name]["state"] == "OWNER_DECIDED"
                    and type(recorded[name]["decision"]) is str, "the HS43 record's owner decision " + name)
            texts[name] = (recorded[name]["decision"], recorded[name]["decision"])
    return texts


def validate_contract_files() -> None:
    """No frozen predecessor is changed or extended; the contract's ten files are new here, each once; the contract
    directory holds exactly its seven files and programs/; every contract file is a regular file of git mode 100644, not a
    symlink and not executable (review note R1-1)."""
    new = authority()["newFiles"]
    for path in list(_PROJECTION_RULES) + list(new):
        require(path not in FROZEN_PATHS and not path.startswith(FROZEN_DIRS),
                "the predecessor programs, edge records, allowlists, registry and W03 plan stay byte-identical")
    require(len(set(NEW_FILES)) == len(NEW_FILES) and set(NEW_FILES) <= set(new)
            and {path for path in new if path.startswith((CONTRACT_DIR, EDGES_DIR))} == set(NEW_FILES) - {PUBLISHER},
            "the contract's ten files are new in this packet, each once")
    require(stat.S_ISDIR(reviewed_mode(CONTRACT_DIR[:-1])), "the contract directory is a directory, not a link")
    tree = reviewed_tree(CONTRACT_DIR)
    require(set(tree) == CONTRACT_TREE and stat.S_ISDIR(tree[PROGRAMS_DIR[:-1]]),
            "the contract directory holds exactly its seven files and programs/")
    for path in NEW_FILES:
        mode = tree[path] if path in tree else reviewed_mode(path)
        require(stat.S_ISREG(mode) and not mode & 0o111, "a contract file is a regular file of git mode 100644: " + path)


def validate_status() -> None:
    """Adopted after one independent review round bound to its record and subject; every other adopted byte is the
    reviewed subject's; the decisions are verbatim; allowlists v4's open item is discharged here; the notes are carried."""
    status = _json(STATUS_PATH)
    record = _json(REVIEW_RECORD)
    hs43 = _json(HS43_RECORD)
    v4_status = _json(V4_STATUS)
    for path, expected in REVIEWED_SHA256.items():
        require(digest(_verified(path)) == expected, "the adopted contract is the reviewed round-1 subject: " + path)
    _bound(lambda: tuple(status) == STATUS_KEYS
           and status["schemaVersion"] == "planeon.internal." + NEW_PACKET.lower() + "-status/v1"
           and status["packet"] == NEW_PACKET and status["roadmapItem"] == "PROGRAMS-REPUBLISH"
           and status["contractState"] == "ADOPTED_DATA_CONTRACT" and status["evidenceClass"] == "DATA_CHECK_ONLY"
           and status["base"] == REVIEW_BASE and type(status["rebase"]) is str and status["rebase"] != ""
           and status["predecessor"] == {"directory": PREDECESSOR_DIR, "packet": PREDECESSOR_PACKET,
                                         "status": PREDECESSOR_DIR + "status.json"}
           and status["source"] == {"directory": V4_DIR, "packet": V4_PACKET, "commit": V4_COMMIT}
           and status["contractFiles"] == list(CONTRACT_FILES) and status["keptCopies"] == []
           and status["reviewerIndependence"] == "SEPARATE_AGENT_NOT_AUTHOR"
           and all(type(status[key]) is str and status[key] != "" for key in ("readmeStatusNote", "adoptionEdit"))
           and all(text in status["readmeStatusNote"] for text in (V3_README, CANDIDATE))
           and type(status["openObligations"]) is list and len(status["openObligations"]) == 2
           and all(type(text) is str and text != "" for text in status["openObligations"])
           and set(status["carriedToR10"]) == {"packet", "items"} and status["carriedToR10"]["packet"] == CONSUMER_PACKET
           and type(status["carriedToR10"]["items"]) is list and len(status["carriedToR10"]["items"]) == 8
           and all(type(text) is str and text != "" for text in status["carriedToR10"]["items"])
           and tuple(status["carriedNotes"]) == CARRIED
           and all(type(text) is str and text != "" for text in status["carriedNotes"].values()),
           "adopted MET-ENFORCE-029 status")
    texts = _decision_texts(hs43)
    _bound(lambda: len(status["ownerDecisions"]) == len(DECISIONS)
           and all(tuple(row) == ("id", "date", "decision", "source") and (row["id"], row["date"]) == (name, date)
                   and row["decision"] == texts[name][0] and type(row["source"]) is str and row["source"] != ""
                   for row, (name, date, _prefix) in zip(status["ownerDecisions"], DECISIONS)),
           "the owner's decisions, verbatim")
    _bound(lambda: status["discharges"]["record"] == V4_STATUS and status["discharges"]["openObligation"] == OPEN_ITEM
           and set(status["discharges"]) == {"record", "openObligation", "how"} and type(status["discharges"]["how"]) is str
           and v4_status["openObligations"].count(OPEN_ITEM) == 1 and v4_status["contractState"] == "ADOPTED_DATA_CONTRACT",
           "allowlists v4's open republication item is discharged in this record only")
    rows = status["reviewRounds"]
    _bound(lambda: len(rows) == 1 and tuple(rows[0]) == ROUND_KEYS and rows[0]["round"] == 1
           and rows[0]["record"] == REVIEW_RECORD and rows[0]["recordSha256"] == "sha256:" + digest(_verified(REVIEW_RECORD))
           and rows[0]["subject"] == REVIEWED_SUBJECT and rows[0]["verdict"] == "PASS_FOR_SOURCE_PUBLICATION"
           and rows[0]["findings"] == [name + " NOTE" for name in REVIEW_FINDINGS],
           "review round 1 is bound to its record and subject")
    _bound(lambda: tuple(record) == RECORD_KEYS and record["round"] == 1 and record["subject"] == REVIEWED_SUBJECT
           and record["reviewer"] == "SEPARATE_AGENT_NOT_AUTHOR" and record["verdict"] == "PASS_FOR_SOURCE_PUBLICATION"
           and [(row["id"], row["severity"]) for row in record["findings"]] == [(name, "NOTE") for name in REVIEW_FINDINGS]
           and record["actions"] == {"filesEdited": False, "networkAccessed": "none", "personalDataSent": False},
           "the round-1 record passes this subject with notes only, edits nothing and sends no personal data")


def validate_readmes() -> None:
    """Both READMEs keep their candidate status line (review notes R1-4 and R1-7) and name this packet in their title;
    MET-ENFORCE-029 is written in exactly the restated files (review note R1-6)."""
    for path in (README_PATH, V3_README):
        text = _verified(path).decode("utf-8")
        lines = text.splitlines()
        require([line for line in lines if line.startswith("Status:")] == [line for line in lines
                                                                        if line.startswith(STATUS_LINE)]
                and len([line for line in lines if line.startswith("Status:")]) == 1
                and lines[0].startswith("# ") and lines[0].endswith("(" + NEW_PACKET + ")"),
                "the README keeps its candidate status line: " + path)
    require({path for path in NEW_FILES if NEW_PACKET.encode("ascii") in _verified(path)} == NAMING_FILES,
            "MET-ENFORCE-029 is written in exactly the restated contract files")


def validate_programs() -> tuple[types.ModuleType, dict, dict, dict]:
    """The v4 model, executed from this era's bytes on the v4 policy and syscall table, compiles every program to v4's
    digest and length; the twelve programs of the other roles are MET-ENFORCE-025's files byte for byte, and each
    EFFECT_GATE program is MET-ENFORCE-025's v3 program with exactly the readlinkat block at the restated index; the index
    names all fourteen exactly."""
    v4 = _era_model(V4_MODEL, "_met_enforce_029_seccomp_allowlists_v4")
    policy, table, vectors = (_json(path) for path in V4_SOURCES[1:])
    predecessor = _json(PREDECESSOR_INDEX)
    index = _json(INDEX_PATH)
    require(all(ERA_SHA256[path] == expected for path, expected in V4_SOURCE_SHA256.items())
            and ERA_SHA256[PREDECESSOR_INDEX] == PREDECESSOR_INDEX_SHA256, "the pinned v4 sources and predecessor index")
    _bound(lambda: tuple(sorted(policy["roles"])) == ROLES and len(predecessor["programs"]) == 2 * len(ROLES),
           "the seven roles of the v4 policy and MET-ENFORCE-025's fourteen programs")
    earlier = {(row["role"], row["arch"]): row for row in predecessor["programs"]}
    published, rows = {}, []
    for role in ROLES:
        for position, arch in enumerate(ARCHES):
            program = v4.compile_filter(policy, table, role, arch)
            compiled = v4.program_bytes(program)
            _bound(lambda: len(program) == PROGRAM_LENGTHS[role][position] == vectors["programLengths"][role][arch]
                   and len(compiled) == INSTRUCTION_BYTES * len(program)
                   and digest(compiled) == PROGRAM_SHA256[role][position]
                   and "sha256:" + digest(compiled) == vectors["filterDigests"][role][arch],
                   "the v4 model's program has v4's digest and length: %s %s" % (role, arch))
            v3_path = PREDECESSOR_DIR + "programs/%s.%s.bpf" % (role, arch)
            v3 = _verified(v3_path)
            _bound(lambda: earlier[role, arch]["path"] == v3_path[len(PREDECESSOR_DIR):]
                   and earlier[role, arch]["sha256"] == "sha256:" + digest(v3) and earlier[role, arch]["bytes"] == len(v3),
                   "MET-ENFORCE-025's index names its program: " + v3_path)
            if role == GATE:
                path = PROGRAMS_DIR + "%s.%s.bpf" % (role, arch)
                data = _verified(path)
                at, nr = BLOCK_AT[arch]
                block = readlinkat_block(nr)
                _bound(lambda: table["syscalls"]["readlinkat"][arch]["nr"] == nr, "readlinkat's number on " + arch)
                require(compiled == data, "the pinned v4 model compiles exactly the published program: " + path)
                require(digest(v3) == V3_GATE_SHA256[arch] and len(v3) == INSTRUCTION_BYTES * V3_GATE_LENGTHS[arch]
                        and len(data) == len(v3) + len(block)
                        and data[:INSTRUCTION_BYTES * at] == v3[:INSTRUCTION_BYTES * at]
                        and data[INSTRUCTION_BYTES * at:INSTRUCTION_BYTES * at + len(block)] == block
                        and data[INSTRUCTION_BYTES * at + len(block):] == v3[INSTRUCTION_BYTES * at:],
                        "v3's EFFECT_GATE program with exactly the six-instruction readlinkat block at %d: %s" % (at, path))
                published[arch] = data
            else:
                path = v3_path
                require(compiled == v3, "byte-identical to MET-ENFORCE-025's program: " + path)
            rows.append({"role": role, "arch": arch, "path": path, "instructions": len(program), "bytes": len(compiled),
                         "sha256": "sha256:" + digest(compiled)})
    expected = {"schemaVersion": INDEX_SCHEMA, "evidenceClass": "DATA_CHECK_ONLY", "format": predecessor["format"],
                "source": {"contract": V4_DIR, "packet": V4_PACKET, "commit": V4_COMMIT,
                           "files": {path: "sha256:" + V4_SOURCE_SHA256[path] for path in V4_SOURCES}},
                "predecessor": {"path": PREDECESSOR_INDEX, "sha256": "sha256:" + PREDECESSOR_INDEX_SHA256,
                                "packet": PREDECESSOR_PACKET},
                "programs": rows}
    _bound(lambda: index == expected and tuple(index) == INDEX_KEYS
           and all(tuple(row) == INDEX_ROW_KEYS for row in index["programs"])
           and len({row["path"] for row in index["programs"]}) == len(rows) == 2 * len(ROLES),
           "the index names exactly the fourteen v4 programs at their repository paths")
    return v4, table, vectors, published


def replay_gate_vectors(v4: types.ModuleType, table: dict, vectors: dict, published: dict) -> dict:
    """Every v4 EFFECT_GATE decision vector, run through the published bytes with the era model's interpreter, gives its
    recorded action; the counts per architecture, and of readlinkat, are restated (review note R1-7)."""
    gate = {arch: _decode(published[arch]) for arch in ARCHES}
    counts = {arch: 0 for arch in ARCHES}
    readlinkat = {arch: 0 for arch in ARCHES}
    for row in vectors["decisionChecks"]:
        if row.get("role") != GATE:
            continue
        arch = row["arch"]
        _bound(lambda: v4.action_name(v4.run_filter(gate[arch], v4.seccomp_data(row["nr"], row["auditArch"], row["args"])))
               == row["expect"], "decision vector %s through the published bytes" % row.get("id"))
        counts[arch] += 1
        readlinkat[arch] += row["nr"] == BLOCK_AT[arch][1]
    require(counts == GATE_DECISIONS and readlinkat == GATE_READLINKAT_DECISIONS
            and all(table["syscalls"]["readlinkat"][arch]["nr"] == BLOCK_AT[arch][1] for arch in ARCHES),
            "the replay covers v4's EFFECT_GATE decision vectors")
    return counts


def _no_cycle(registry: Any, consumer: str) -> bool:
    """harness-engineering consumes no repository in any graph of the registry, so an edge from consumer to it cannot
    close a cycle."""
    ids = {row["id"] for row in registry["repositories"]}
    return ({consumer, "harness-engineering"} <= ids
            and not any(row["consumer"] == "harness-engineering" for body in registry["dependencyGraphs"].values()
                        for row in body["edges"]))


def validate_edge_record() -> None:
    """Edge record v3 is v2's 31 rows unchanged and in order plus exactly the two EFFECT_GATE rows for HE-003A2, with v2's
    key sets, ownerDecision, rules, notArtifacts and statuses; it supersedes v2 by its digest; every provider path holds
    the recorded bytes; the edge cannot close a cycle."""
    v2 = _json(V2_EDGE)
    v3 = _json(V3_EDGE)
    texts = _decision_texts(_json(HS43_RECORD))
    registry = _era_model(SAFE_YAML, "_met_enforce_029_safe_yaml").safe_load(_verified(REPOSITORIES))
    require(ERA_SHA256[V2_EDGE] == V2_EDGE_SHA256, "edge record v2 is the one v3 supersedes")

    def new_row(row: Any, arch: str) -> bool:
        return (tuple(row) == PROGRAM_ROW_KEYS and row["providerPath"] == PROGRAMS_DIR + "%s.%s.bpf" % (GATE, arch)
                and row["providerCommit"] is None and row["providerPacket"] == NEW_PACKET
                and row["sha256"] == PROGRAM_SHA256[GATE][ARCHES.index(arch)] and row["mode"] == "100644"
                and row["consumerPath"] == CONSUMER_DIR + "%s.%s.bpf" % (GATE, arch)
                and row["consumerPacket"] == CONSUMER_PACKET and row["relation"] == "BYTE_IDENTICAL"
                and row["status"] == "REGISTERED_BEFORE_USE")

    _bound(lambda: tuple(v3) == EDGE_KEYS and tuple(v2) == EDGE_KEYS
           and v3["schemaVersion"] == v2["schemaVersion"] == "planeon.internal.artifact-edge-registry/v2"
           and (v3["graph"], v3["consumer"], v3["provider"]) == ("buildArtifact", "operator", "harness-engineering")
           == (v2["graph"], v2["consumer"], v2["provider"]) and v3["artifact"] == V3_ARTIFACT
           and all(v3[key] == v2[key] for key in ("ownerDecision", "rules", "notArtifacts", "statuses"))
           and v3["supersedes"] == {"path": V2_EDGE, "sha256": "sha256:" + V2_EDGE_SHA256, "packet": PREDECESSOR_PACKET}
           and len(v3["ownerDecisions"]) == len(DECISIONS)
           and all(text == prefix + texts[name][1] for text, (name, _date, prefix) in zip(v3["ownerDecisions"], DECISIONS))
           and type(v3["notes"]) is list and len(v3["notes"]) == 5
           and all(type(note) is str and note != "" for note in v3["notes"])
           and len(v2["artifacts"]) == V2_ROWS and v3["artifacts"][:V2_ROWS] == v2["artifacts"]
           and all(list(row) == list(old) for row, old in zip(v3["artifacts"], v2["artifacts"]))
           and len(v3["artifacts"]) == V2_ROWS + len(ARCHES)
           and all(new_row(row, arch) for row, arch in zip(v3["artifacts"][V2_ROWS:], ARCHES)),
           "edge record v3 is v2's 31 rows plus exactly the two EFFECT_GATE rows")
    paths = [row["providerPath"] for row in v3["artifacts"]]
    require(len(set(paths)) == len(paths), "each provider path is registered once")
    for row in v3["artifacts"]:
        path = row["providerPath"]
        raw = _verified(path) if path in ERA_SHA256 else reviewed_bytes(path)
        require(digest(raw) == row["sha256"], "a registered artifact matches its provider bytes: " + path)
    _bound(lambda: _no_cycle(registry, "operator"), "the edge cannot close a cycle in the repository registry")


def validate_compiled_filter_programs_v2() -> None:
    """The contract's files, then every reviewed byte, the adoption record and the READMEs; then the programs, the index,
    the replay and edge record v3."""
    validate_contract_files()
    for path in ERA_SHA256:
        _verified(path)
    validate_status()
    validate_readmes()
    v4, table, vectors, published = validate_programs()
    replay_gate_vectors(v4, table, vectors, published)
    validate_edge_record()


def validate() -> None:
    record = authority()
    validator_raw = successor.historical_bytes(VALIDATOR_PATH, regular_bytes(VALIDATOR_PATH))
    literal = b'AUTHORITY_SHA256 = "' + AUTHORITY_SHA256.encode("ascii") + b'"'
    placeholder = b'AUTHORITY_SHA256 = "TO_BE_PINNED_AFTER_SOURCE_FREEZE"'
    require(validator_raw.count(literal) == 1
            and digest(validator_raw.replace(literal, placeholder))
            == record["validatorNormalizedSha256"], "compiled filter programs v2 validator drift")
    paths = sorted((ROOT / "task-packets").glob("*.yaml"))
    old = set(record["baselinePackets"])
    require(len(paths) == 249
            and {path.stem for path in paths} == old | {NEW_PACKET, successor.NEW_PACKET, successor.successor.NEW_PACKET, successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.successor.successor.successor.NEW_PACKET},
            "closed 249-packet catalog retaining the 240-packet checkpoint")
    packets = {}
    for path in paths:
        if path.stem in (successor.NEW_PACKET, successor.successor.NEW_PACKET, successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.successor.successor.successor.NEW_PACKET):
            continue
        raw = regular_bytes("task-packets/" + path.name)
        expected = record["packetSha256"] if path.stem == NEW_PACKET else record["baselinePackets"][path.stem]
        require(digest(raw) == expected, "packet YAML drift: " + path.stem)
        packets[path.stem] = safe_load(raw)
    validate_packet_payloads(packets)
    packet = packets[NEW_PACKET]
    previous = packets[PREVIOUS_PACKET]
    commands = packet["offlineAcceptanceCommands"]
    require(packet["id"] == NEW_PACKET and packet["repository"] == "Harness-Engineering"
            and packet["predecessors"] == [PREVIOUS_PACKET]
            and packet["warmSourceAccess"] == "PROHIBITED_DURING_IMPLEMENTATION"
            and packet["sourceReuse"] == packet["prefetchCommands"] == []
            and packet["offlineExecution"] == previous["offlineExecution"]
            and "liveCampaignExecution" not in packet
            and len(commands) == 64
            and commands == previous["offlineAcceptanceCommands"]
            and not any(VALIDATOR_PATH in argv for argv in commands),
            "closed source-only compiled-filter-programs-v2 packet and inherited commands")
    require(len(packet["allowedPaths"]) == len(set(packet["allowedPaths"]))
            and set(packet["allowedPaths"]) == set(record["changedFiles"])
            | set(record["newFiles"]) | {AUTHORITY_PATH, VALIDATOR_PATH,
                                         "task-packets/" + NEW_PACKET + ".yaml"},
            "unreviewed or omitted compiled-filter-programs-v2 packet path")
    for path, rule in record["changedFiles"].items():
        current = successor.historical_bytes(path, regular_bytes(path))
        require(digest(current) == rule["afterSha256"]
                and digest(historical_bytes(path, current)) == rule["beforeSha256"],
                "unreviewed current source: " + path)
    for path, expected in record["newFiles"].items():
        require(digest(successor.historical_bytes(path, regular_bytes(path))) == expected,
                "new source drift: " + path)
    validate_compiled_filter_programs_v2()


if __name__ == "__main__":
    validate()
    print("Compiled filter programs v2 valid: 249 current specifications; 240-packet checkpoint and exact 239-packet predecessor; contract reviewed.")
