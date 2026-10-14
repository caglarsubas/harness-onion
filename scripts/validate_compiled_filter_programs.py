#!/usr/bin/env python3
"""Validate the MET-ENFORCE-025 compiled filter programs, edge records and amendment, and the exact 232-to-231 projection."""
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
    import validate_run_events as successor
except ImportError:
    from scripts.safe_yaml import safe_load
    from scripts import validate_run_events as successor


ROOT = Path(__file__).resolve().parents[1]
AUTHORITY_PATH = "architecture/compiled-filter-programs-authority.json"
AUTHORITY_SHA256 = "22663b7c7d86080eff031f96e466845add842f906d3439cc05c33ffe65911b72"
VALIDATOR_PATH = "scripts/validate_compiled_filter_programs.py"
BASE_COMMIT = "6e7bfb3cfb3cd04dc55fc6276591fb02905e5d99"
NEW_PACKET = "MET-ENFORCE-025"
PREVIOUS_PACKET = "MET-MAS-006"
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
            require(key not in result, "duplicate compiled-filter-programs authority member")
            result[key] = value
        return result

    def no_constant(_value: str) -> Any:
        raise ValueError("nonfinite compiled-filter-programs authority number")

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
        require(digest(raw) == AUTHORITY_SHA256, "compiled filter programs history authority digest")
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
    }, "closed compiled filter programs history authority")
    require(value["schemaVersion"] == "harness.planeon.ai/compiled-filter-programs-authority/v1"
            and value["authorityPacket"] == NEW_PACKET
            and value["acceptedBase"] == BASE_COMMIT
            and type(value["baselinePackets"]) is dict
            and len(value["baselinePackets"]) == 231
            and NEW_PACKET not in value["baselinePackets"]
            and type(value["changedFiles"]) is dict
            and type(value["newFiles"]) is dict
            and _sha(value["packetSha256"])
            and _sha(value["validatorNormalizedSha256"]),
            "accepted 231-packet base")
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
    # An exact 231-era byte string is already older than the successor layer.
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


# MET-ENFORCE-025 publishes the W02d v3 contract's compiled seccomp programs as data (architecture/compiled-filter-programs/:
# seven roles on two architectures, recompiled by the pinned v3 compiler), the operator -> harness-engineering edge record
# v2 that registers them for R10's packets, EDGE-2 (the conformance-labs -> harness-engineering record of HE-000's four
# transport files) and W03-PLAN-AMEND-1 (an obligation-register amendment of the W03 plan v2), adopted after four
# independent review rounds; the v3 contract, the v1 edge record and the W03 plan v2 stay byte-identical. Repository bytes
# are read only through reviewed_bytes, so a later bridged successor projects its own edits away first. Every reviewed file
# of this era, and every input it is checked against, is bound by digest before anything is parsed, every later read is
# checked against that digest again, and the v3 compiler and safe_yaml are executed from this era's reviewed bytes, so a
# later revision of either cannot change how this layer judges its era. The owner's decisions, the programs' digests and
# lengths, the role-to-packet registration, each record's exact key set (review note R2-1) and the amendment's changes are
# restated here independently of the reviewed files.
PROGRAMS_DIR = "architecture/compiled-filter-programs/"
INDEX_PATH = PROGRAMS_DIR + "index.json"
STATUS_PATH = PROGRAMS_DIR + "status.json"
PUBLISHER = "scripts/compiled_filter_programs.py"
V3_COMPILER = "scripts/seccomp_allowlists_v3.py"
V3_DIR = "architecture/seccomp-allowlists-v3/"
V3_SOURCES = (V3_COMPILER, V3_DIR + "allowlists.json", V3_DIR + "syscalls.json", V3_DIR + "vectors.json")
V3_COMMIT = "5fab673e250e7dd0f2ce9c19f6ce9da8cce9321c"
EDGES_DIR = "architecture/artifact-edges/"
V1_EDGE = EDGES_DIR + "operator-harness-engineering.json"
V2_EDGE = EDGES_DIR + "operator-harness-engineering-v2.json"
EDGE_2 = EDGES_DIR + "conformance-labs-harness-engineering.json"
AMENDMENT_DIR = "architecture/w03-obligation-amendment-1/"
AMENDMENT = AMENDMENT_DIR + "amendment.json"
PLAN_V2 = "architecture/w03-plan-v2/plan.json"
REPOSITORIES = "architecture/repositories.yaml"
SAFE_YAML = "scripts/safe_yaml.py"
READMES = (PROGRAMS_DIR + "README.md", EDGES_DIR + "README-v2.md", AMENDMENT_DIR + "README.md")
ARCHES = ("aarch64", "x86_64")
ROLES = ("BROKER", "EFFECT_GATE", "HOST_CONTAINMENT", "OBSERVER", "POLICY_WRITER", "SERVER", "WORKER")
CONTENT_FILES = frozenset([PROGRAMS_DIR + "programs/%s.%s.bpf" % (role, arch) for role in ROLES for arch in ARCHES]
                          + [PROGRAMS_DIR + "index.json", PUBLISHER, V2_EDGE, EDGE_2, AMENDMENT, *READMES])
# Instruction counts (aarch64, x86_64) and SHA-256 per program, as the v3 contract's programLengths and filterDigests.
PROGRAM_LENGTHS = {"BROKER": (311, 326), "EFFECT_GATE": (183, 194), "HOST_CONTAINMENT": (130, 141), "OBSERVER": (227, 238),
                   "POLICY_WRITER": (115, 126), "SERVER": (261, 276), "WORKER": (172, 187)}
PROGRAM_SHA256 = {
    "BROKER": ('bc9c5a3797277ca753b5168e8e55132e1878fed2a726de361fd7d80e0fababf8', '95221bd0db753aa22ead2eb49eeac8dae3d24c3dad72811de86c9392f4894dcc'),
    "EFFECT_GATE": ('0ccbd7d090212fe52d366a2d68515670de40557cbc6fd07531653b404bb7105a', 'ee85e9d225ad687aec82f83cb7d7c1be95f16df5f68eec5b56ee913d6cd86115'),
    "HOST_CONTAINMENT": ('d9d57ecb4919ad453684be62b6e2b65c9818033c47291e8e7240f7c2224880eb', 'd0d0db066e8942bbe987bd89a8441ab4e84b1cb9933b3bad24d8fb6eb0a51292'),
    "OBSERVER": ('d31c841042de456bb784e8412f61429be7700aea2ffa508af2637283ebcb3707', 'e793aae5ad04a7c82a67d3f102b837064e645a585b83ace0586169a1746eb25a'),
    "POLICY_WRITER": ('e3bf65e0ff60d6766eac92672ad21a3c34097e183f03de416c9ad2ba50d71a5b', '0f690b0e2f18b1b092bc42f4042dc334cafa3aae81fb96851f569ba71f20d1bf'),
    "SERVER": ('a1bcb2de10f5a54d32578d9f26e3d7db69b0cfad8d868feea1914585fbb7f05a', '2e7af1da50b7d5df3cdcf8c18eb545f4972b2309b68d9eecba2e5f6ba5d1d8a7'),
    "WORKER": ('cc04a4710495d3794b0d295613a2f2bd330524a328cb6963a819565bac2acb40', '5616c9099324e441674f8e589b6c705ae95f6a4a697f10e761565d0735689d45')
}
# The consumer packet of each role's two programs (W03 plan v2's SEC-4 and HI-7 packets); SERVER's are published but not
# registered (no W03 packet installs that role's program).
ROLE_PACKETS = {"BROKER": "HE-005", "EFFECT_GATE": "HE-002S", "HOST_CONTAINMENT": "HE-006", "OBSERVER": "HE-004",
                "POLICY_WRITER": "HE-007", "SERVER": None, "WORKER": "HE-005"}
CONSUMER_DIR = "host-enforcement/contracts/seccomp-v3/"
INDEX_KEYS = ("schemaVersion", "evidenceClass", "format", "source", "programs")
INDEX_ROW_KEYS = ("role", "arch", "path", "instructions", "bytes", "sha256")
# Each record's exact key set (review note R2-1): v1's keys, and the schema v2 additions each v2 record carries.
V1_KEYS = ("schemaVersion", "graph", "consumer", "provider", "artifact", "ownerDecision", "rules", "notArtifacts", "statuses",
           "artifacts")
V2_KEYS = V1_KEYS + ("supersedes", "ownerDecisions", "notes")
EDGE_2_KEYS = V1_KEYS + ("notes",)
ARTIFACT_KEYS = ("providerPath", "providerCommit", "sha256", "mode", "consumerPath", "consumerPacket", "relation", "status")
PROGRAM_ROW_KEYS = ARTIFACT_KEYS + ("providerPacket",)
UNREGISTERED_ROW_KEYS = PROGRAM_ROW_KEYS + ("note",)
EDGE_2_ROW_KEYS = ARTIFACT_KEYS + ("consumerCommit",)
V2_ARTIFACT = "w03-transport-effect-gate-contracts-and-compiled-filter-programs"
V2_DECISIONS = ("Q-HE2S-1 = (a) (2026-10-13, ", "Q-HE2S-2 = (a), all 14 (2026-10-13, ")
UNREGISTERED = "PUBLISHED_UNREGISTERED"
# EDGE-2: R12's CONF-CI-001 merge commit, at which the four transport files were read, and the provider commit of v1.
EDGE_2_ARTIFACT = "offline-transport-files"
EDGE_2_CONSUMER_COMMIT = "9766c9cb02383968499a109c36f4b7a18ec532b0"
TRANSPORT_COMMIT = "0e747049cba3eca9ec5b0334e0314525d053a83c"
TRANSPORT_FILES = ("ci/verify-offline.sh", "ci/warm-source-isolation.sh", "ci/network_canary.py", "ci/run_packet_argv.py")
AMENDMENT_KEYS = ("schemaVersion", "id", "amends", "ownerDecision", "ownerDecisions", "changes", "shareRule", "unchanged")
# (obligation, change, packets after the change, packets added, the packets with a share); I07-6 is new, the others are
# plan v2's. HI-7's HE-008 share completes HE-008's existing part for EFFECT_GATE (packet review P1-F3).
AMENDMENT_CHANGES = (("I07-6", "ADDED", ("HE-003",), None, None),
                     ("I07-4", "NARROWED", ("HE-002B",), None, None),
                     ("SEC-4", "PACKETS_ADDED", ("HE-002S", "HE-003", "HE-004", "HE-005", "HE-006", "HE-007", "HE-008"),
                      ("HE-003", "HE-008"), ("HE-003", "HE-008")),
                     ("HI-7", "PACKETS_ADDED", ("HE-002S", "HE-003", "HE-004", "HE-005", "HE-006", "HE-007", "HE-008"),
                      ("HE-003",), ("HE-003", "HE-008")),
                     ("SEC-QW4", "PACKETS_ADDED", ("W03-0", "W02D-V3", "HE-002S", "T04"), ("HE-002S",), ("HE-002S",)))
SHARE_RULE_START = "A share adds to the named packet's part of the obligation as plan v2 states it; it never narrows it."
AMENDMENT_DECISIONS = ("Q-HE2S-3 = (a) (2026-10-13, ", "Q-HE2S-4 = (a) (2026-10-13, ", "Q-HE2S-5 = (a) (2026-10-13, ",
                       "Q-HE2S-7 = (a) \"Keep gate dumpable\" (2026-10-13, ", "Q-HE2S-8 = (a) (2026-10-13, ",
                       "Amendment scope = yes (2026-10-13, ")
REVIEW_BASE = "82804a0cdaa3d005e7d9f7daa9c886b3bc1c6f0f"
REVIEWED_SUBJECT = {"commit": "abe53d68950d95fd8ce1b0ce2da490d164744156", "tree": "d4e6bb4ffb3c33f07dff46a6b198401ccc2b8961"}
ROUNDS = ((1, "CHANGES_REQUIRED"), (2, "PASS_FOR_SOURCE_PUBLICATION"), (3, "CHANGES_REQUIRED"),
          (4, "PASS_FOR_SOURCE_PUBLICATION"))
# Each round's subject (commit, tree), all on REVIEW_BASE; every round's subject held exactly the 22 content files.
ROUND_SUBJECTS = (("9522dd93f8241dedeb97bc356be4900a91e1ff71", "d02fb37e3eb20501f9de95e0f789b86678eb65f8"),
                  ("3f637171826e7f912fb93f2fc28102ccd18583eb", "c1973eaec81e6ff961d1534b351564d6414aaf07"),
                  ("0b37f6351e572fa12b58e37b4ebce1a777d85806", "666aca4661e8bc63a230eb012341f03ec7894c27"),
                  ("abe53d68950d95fd8ce1b0ce2da490d164744156", "d4e6bb4ffb3c33f07dff46a6b198401ccc2b8961"))
LAST_ROUND = len(ROUNDS)
REVIEW_SCHEMA = "harness.planeon.ai/met-enforce-025-review/v1"
STATUS_KEYS = ("schemaVersion", "packet", "contractState", "evidenceClass", "base", "adoptedSubject", "reviewRounds",
               "carriedNotes", "ownerDecisions", "adoptionEdit")
ROW_KEYS = ("round", "subject", "subjectTree", "verdict", "record", "severities")
SEVERITIES = ("MAJOR", "MINOR", "NOTE")
DECISIONS = ["Q-HE2S-1 (a)", "Q-HE2S-2 (a), all 14", "A13", "Q-HE2B-2 (a)", "Q-HE2S-3 (a)", "Q-HE2S-4 (a)", "Q-HE2S-5 (a)",
             "Q-HE2S-7 (a)", "Q-HE2S-8 (a)", "amendment scope = yes"]
CARRIED = ("R2-1", "R4-1", "R4-2", "R4-3", "HE-002S-D2", "Q-HE2S-9", "Q-HE2S-10")
ADOPTION_EDIT = "the status line of the three READMEs; every other adopted byte is round 4's subject"
STATUS_LINE = ("Status: **CANDIDATE** (under independent review).",
               "Status: **ADOPTED** (independent review round 4: PASS_FOR_SOURCE_PUBLICATION; rounds and review records in "
               "`architecture/compiled-filter-programs/status.json`).")
# The reviewed (round 4) bytes of the three READMEs, before the status-line edit.
REVIEWED_READMES = {
    "architecture/artifact-edges/README-v2.md": "3e199b370430c3a642e6e31827df8b8cc6828ab7189a3e39504d2b6304165fd0",
    "architecture/compiled-filter-programs/README.md": "59caa9cc9cec961457569f71ddf54ff3fff5f58ed8fa30005685112cf5bf248c",
    "architecture/w03-obligation-amendment-1/README.md": "cb6f50648207c81b02f8759148d755d2b4051ee68af9e27d46ced3cf87adca5e"
}
# The v3 contract, the v1 edge record and its README, and the W03 plan v2 stay byte-identical (and the repository registry).
FROZEN_PATHS = (V1_EDGE, EDGES_DIR + "README.md", REPOSITORIES)
FROZEN_PREFIXES = (V3_DIR, V3_COMPILER, "architecture/w03-plan-v2/")
# The adopted bytes of every reviewed file, round copy and review record, and the status record; the accepted base's v3
# sources, v1 edge record and README, W03 plan v2, repository registry and safe_yaml.
ERA_SHA256 = MappingProxyType({
    "architecture/artifact-edges/README-v2.md": "0cded3e3499b8afe64c82a021a8a499c9b2fce5671ea5ae434b3330c26db3a2b",
    "architecture/artifact-edges/README.md": "5d62a665da2c6e75dce900cb4ef52e74aa14e537bdaeededb7568589339daa9f",
    "architecture/artifact-edges/conformance-labs-harness-engineering.json": "06eb22afc4fad682a20507b2db8a868ae7df1370ef2c6357ad20a2cc0c9dfa17",
    "architecture/artifact-edges/operator-harness-engineering-v2.json": "749e70f174d638468bf45d7316e8f5201c3323f6348a78c7b9a22d3a571ccc32",
    "architecture/artifact-edges/operator-harness-engineering.json": "54bdc2d22676720419f51cd1bad5eedc909e6f848ed09cd363e351889af9d1fe",
    "architecture/compiled-filter-programs/README.md": "bb6b68216c20b9a34bfdc50aaaf6ffd556ac540921b3a5312b0203164f482c52",
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
    "architecture/compiled-filter-programs/reviews/review-round1.json": "04456f1a6ae1413bcee5cd9800dcd4da10a5478febf05bb70c8b992612f8fda5",
    "architecture/compiled-filter-programs/reviews/review-round2.json": "7da105f1b0485790e1959d30d08abbb6d11bd077d741d37ef7da06a346d86a6b",
    "architecture/compiled-filter-programs/reviews/review-round3.json": "5c6be3c9d2d5eca3a62e23cb420a94e3decbe6c9f03a8aa9b3f60079f239f56d",
    "architecture/compiled-filter-programs/reviews/review-round4.json": "853520a74b591cd0966c94e08328b1f56a1aa1c2d9e3da6c344c438f848206a6",
    "architecture/compiled-filter-programs/rounds/round1/architecture/artifact-edges/README-v2.md": "b6297d9f231450c7e0ec317a94144d4c95432cc7f9c99045c998ca0c09fc2b13",
    "architecture/compiled-filter-programs/rounds/round1/architecture/artifact-edges/conformance-labs-harness-engineering.json": "9c22c5d6a8757633285c7c68a86559eed8f7a2d32bef9b3a36c5190ed1d821ec",
    "architecture/compiled-filter-programs/rounds/round1/architecture/artifact-edges/operator-harness-engineering-v2.json": "099fd98591be64b8032afffb4ab20a569fb20cdb0c2d7e7bc702fbfc5296c2f0",
    "architecture/compiled-filter-programs/rounds/round1/architecture/compiled-filter-programs/README.md": "a3fb2a01797a21f0291d71324ddea0ec3ae8769d1236109cfc9e82e88f8ab003",
    "architecture/compiled-filter-programs/rounds/round1/architecture/w03-obligation-amendment-1/README.md": "786657192878b5aa308757ac108fe9095838d380ebe95e6a10466868c91e77f5",
    "architecture/compiled-filter-programs/rounds/round1/architecture/w03-obligation-amendment-1/amendment.json": "e81f029c4b756cbe6f597479b32e1240ecf9d011ce7a3d26c39425dbb1e181bd",
    "architecture/compiled-filter-programs/rounds/round1/scripts/compiled_filter_programs.py": "0198f6da676f672476edc793742cc6209e1b9101920dacf53dfa1141c4665a51",
    "architecture/compiled-filter-programs/rounds/round2/architecture/artifact-edges/README-v2.md": "eb9daf4d52658ecb26c2394d39db370358fc2812f82afc0d764ee4f0c447eaf6",
    "architecture/compiled-filter-programs/rounds/round2/architecture/artifact-edges/conformance-labs-harness-engineering.json": "b098dc2c4d1a2fd255553dd953b555c4791d04125240c6b8b10007260e593e99",
    "architecture/compiled-filter-programs/rounds/round2/architecture/w03-obligation-amendment-1/README.md": "510ffad5fc89e81c868161577ca67c34a0122d8925cb4a485c74b7a8d8f7dd81",
    "architecture/compiled-filter-programs/rounds/round2/architecture/w03-obligation-amendment-1/amendment.json": "9b8fa36b09b8719ab77c25d24bb80522c0b7563c2a02fb3f1f94750faa27010e",
    "architecture/compiled-filter-programs/rounds/round3/architecture/w03-obligation-amendment-1/README.md": "e04fa2b5870a61667fd2bfa277772559760f5218294e03f6692d444f8485d98f",
    "architecture/compiled-filter-programs/rounds/round3/architecture/w03-obligation-amendment-1/amendment.json": "25728039e6dc5f840ae2aabc14cf77c5820281324a352c612f7b81ce8d253429",
    "architecture/compiled-filter-programs/status.json": "f2af6196ea28cebda5530e0792f7cadceb004f8aec01f2857a49823a845ac6c1",
    "architecture/repositories.yaml": "02190a668c6a9114b3733724bec4e552c553867e789b0802f6aaa6759148051d",
    "architecture/seccomp-allowlists-v3/allowlists.json": "397e79541a7cfaa4f435703703f48f9e1ef54d81a659709d5c80358e0c5bcf66",
    "architecture/seccomp-allowlists-v3/syscalls.json": "863f1df9bc55b7776520790a7314f6fa4b0480f2d58672db0f1f244aa36c7503",
    "architecture/seccomp-allowlists-v3/vectors.json": "18353cb347dc8d4575b650fe4b4ece31f5bf9ca1ce490d1c50a9ae2962f25df8",
    "architecture/w03-obligation-amendment-1/README.md": "3e2e46c9f37349b732c56620a732555c291bec85e459ce7454b7fd1ecbb1cd4c",
    "architecture/w03-obligation-amendment-1/amendment.json": "2a98e28989f41d69b27a580db8113e56d5adc1fcc1a4b96517997ce7b01f4bd2",
    "architecture/w03-plan-v2/plan.json": "a00470238431347da82cc47b1f1b6cf7cd51042d56694eea68d1373a3aaefb67",
    "scripts/compiled_filter_programs.py": "311c297459b7e3a67aeafdef1e0d19cf9d566e11154117d5d6dc1fcfff2ea7d4",
    "scripts/safe_yaml.py": "99c673560e65e58cdc1abe86e53472feaf93e546dd76cb9f3ba051beef5c49d7",
    "scripts/seccomp_allowlists_v3.py": "65c1190cf3878222b5cf1dfe032addc1e79b4e2a940ec0d97e0af3a5b8da9c81"
})


def reviewed_bytes(path: str) -> bytes:
    """This packet's reviewed bytes of path; a bridged successor projects newer bytes back first."""
    return successor.historical_bytes(path, regular_bytes(path))


def _verified(path: str) -> bytes:
    """reviewed_bytes, checked against its era digest on every read; a path outside the era is refused."""
    expected = ERA_SHA256.get(path)
    require(expected is not None, "MET-ENFORCE-025 reviewed bytes are bound: " + path)
    raw = reviewed_bytes(path)
    require(digest(raw) == expected, "MET-ENFORCE-025 reviewed bytes are bound: " + path)
    return raw


def _json(path: str) -> Any:
    return parse(_verified(path))


def _bound(check: Any, message: str) -> None:
    """A structural check over a module's result or a record; a malformed one is refused, not raised."""
    try:
        holds = check()
    except (KeyError, TypeError, AttributeError, IndexError, ValueError):
        holds = False
    require(holds is True, message)


def _hex(value: Any, length: int) -> bool:
    return type(value) is str and len(value) == length and set(value) <= set("0123456789abcdef")


def _era_model(path: str, name: str) -> types.ModuleType:
    """A reference module of this era, executed from its verified bytes."""
    module = types.ModuleType(name)
    module.__file__ = str(ROOT / path)
    exec(compile(_verified(path), path, "exec", dont_inherit=True), module.__dict__)
    return module


def _program_path(role: str, arch: str) -> str:
    return PROGRAMS_DIR + "programs/%s.%s.bpf" % (role, arch)


def _reviewed_digest(path: str) -> Any:
    """The digest of path's round-4 (reviewed) bytes: the adopted digest, except a README's before its status-line edit."""
    return REVIEWED_READMES[path] if path in READMES else ERA_SHA256.get(path)


def validate_era_bytes() -> None:
    """Every reviewed file of this era is bound by digest before anything is parsed or executed; the v3 contract, the v1
    edge record and the W03 plan v2 are frozen."""
    for path in _PROJECTION_RULES:
        require(path not in FROZEN_PATHS and not path.startswith(FROZEN_PREFIXES),
                "the v3 contract, the v1 edge record and the W03 plan v2 stay byte-identical")
    for path, expected in ERA_SHA256.items():
        require(digest(reviewed_bytes(path)) == expected, "MET-ENFORCE-025 reviewed bytes are bound: " + path)


def validate_compiled_filter_programs_status() -> None:
    """Adopted after four independent review rounds, each bound to its record; an earlier round's files that differ from
    the adopted ones are snapshotted, the others bound by the adopted digest; the last round passed this subject with
    notes only, each carried; the three READMEs' status lines are the one adoption edit."""
    status = _json(STATUS_PATH)
    _bound(lambda: type(status) is dict and set(status) == set(STATUS_KEYS)
           and status["schemaVersion"] == "planeon.internal.met-enforce-025-status/v1"
           and status["packet"] == "MET-ENFORCE-025" and status["contractState"] == "ADOPTED"
           and status["evidenceClass"] == "DATA_CHECK_ONLY" and status["base"] == REVIEW_BASE
           and status["adoptedSubject"] == REVIEWED_SUBJECT["commit"] and status["ownerDecisions"] == DECISIONS
           and status["adoptionEdit"] == ADOPTION_EDIT and tuple(status["carriedNotes"]) == CARRIED
           and all(type(note) is str and note for note in status["carriedNotes"].values()),
           "adopted MET-ENFORCE-025 status")
    for path in READMES:
        readme = _verified(path).decode("utf-8")
        _bound(lambda: readme.count(STATUS_LINE[1]) == 1 and STATUS_LINE[0] not in readme
               and digest(readme.replace(STATUS_LINE[1], STATUS_LINE[0]).encode("utf-8")) == REVIEWED_READMES[path],
               "the README's status line is the one adoption edit: " + path)
    rows = status["reviewRounds"]
    require(type(rows) is list and all(type(row) is dict for row in rows)
            and [(row.get("round"), row.get("verdict")) for row in rows] == list(ROUNDS), "review rounds in order")
    previous: list = []
    for row in rows:
        number = row["round"]
        earlier = number < LAST_ROUND
        _bound(lambda: set(row) == set(ROW_KEYS) | ({"snapshot", "unchangedFromAdopted"} if earlier else set())
               and row["record"] == PROGRAMS_DIR + "reviews/review-round%d.json" % number
               and (row["subject"], row["subjectTree"]) == ROUND_SUBJECTS[number - 1], "review round %d row" % number)
        if earlier:
            snapshot, unchanged = row["snapshot"], row["unchangedFromAdopted"]
            directory = PROGRAMS_DIR + "rounds/round%d/" % number
            _bound(lambda: set(snapshot) == {"directory", "files"} and snapshot["directory"] == directory
                   and not set(snapshot["files"]) & set(unchanged)
                   and set(snapshot["files"]) | set(unchanged) == CONTENT_FILES
                   and all(digest(_verified(directory + path)) == value and _reviewed_digest(path) != value
                           for path, value in snapshot["files"].items())
                   and all(_reviewed_digest(path) == value for path, value in unchanged.items()),
                   "review round %d snapshot" % number)
        record = _json(row["record"])
        require(type(record) is dict and record.get("schemaVersion") == REVIEW_SCHEMA and record.get("round") == number
                and record.get("subjectCommit") == row["subject"] and record.get("subjectTree") == row["subjectTree"]
                and record.get("verdict") == row["verdict"], "review round %d identity" % number)
        actions = record.get("actions")
        require(type(actions) is dict and actions.get("filesEdited") is False and actions.get("personalDataSent") is False
                and type(actions.get("networkAccessed")) is str,
                "review round %d edited nothing and sent no personal data" % number)
        findings = record.get("findings")
        dispositions = record.get("dispositions")
        _bound(lambda: type(findings) is list and all(item["severity"] in SEVERITIES for item in findings)
               and row["severities"] == sorted({item["severity"] for item in findings})
               and type(dispositions) is list
               and all(set(item) == {"finding", "status", "evidence"} for item in dispositions)
               and (number > 1 or dispositions == []), "review round %d severities and dispositions" % number)
        if number > 1:   # every finding of the previous round has a recorded disposition
            require({item.get("id") for item in previous} <= {item.get("finding") for item in dispositions},
                    "review round %d disposes of every round %d finding" % (number, number - 1))
        previous = findings
    final = rows[-1]
    require(final["subject"] == REVIEWED_SUBJECT["commit"] and final["subjectTree"] == REVIEWED_SUBJECT["tree"]
            and final["verdict"] == "PASS_FOR_SOURCE_PUBLICATION" and set(final["severities"]) <= {"NOTE"},
            "the passing round reviewed this subject and left notes only")
    require({item["id"] for item in previous} <= set(status["carriedNotes"]), "every note of the passing round is carried")


def validate_programs() -> None:
    """The v3 compiler, executed from this era's reviewed bytes on the v3 policy and syscall table, compiles exactly the
    published programs, whose digests and lengths are v3's and restated here; the index names each of them."""
    v3 = _era_model(V3_COMPILER, "_met_enforce_025_seccomp_allowlists_v3")
    policy = _json(V3_DIR + "allowlists.json")
    table = _json(V3_DIR + "syscalls.json")
    vectors = _json(V3_DIR + "vectors.json")
    index = _json(INDEX_PATH)
    _bound(lambda: tuple(sorted(policy["roles"])) == ROLES, "the seven roles of the v3 policy")
    rows = []
    for role in ROLES:
        for position, arch in enumerate(ARCHES):
            path = _program_path(role, arch)
            data = _verified(path)
            program = v3.compile_filter(policy, table, role, arch)
            compiled = v3.program_bytes(program)
            require(compiled == data, "the pinned v3 compiler compiles exactly the published program: " + path)
            _bound(lambda: len(program) == PROGRAM_LENGTHS[role][position] == vectors["programLengths"][role][arch]
                   and len(data) == 8 * len(program)
                   and digest(data) == PROGRAM_SHA256[role][position]
                   and "sha256:" + digest(data) == vectors["filterDigests"][role][arch],
                   "the program's digest and length are v3's: " + path)
            rows.append({"role": role, "arch": arch, "path": path[len(PROGRAMS_DIR):], "instructions": len(program),
                         "bytes": len(data), "sha256": "sha256:" + digest(data)})
    _bound(lambda: type(index) is dict and set(index) == set(INDEX_KEYS)
           and index["schemaVersion"] == "planeon.internal.compiled-filter-programs/v1"
           and index["evidenceClass"] == "DATA_CHECK_ONLY" and type(index["format"]) is str
           and index["source"] == {"contract": V3_DIR, "packet": "MET-ENFORCE-020", "commit": V3_COMMIT,
                                   "files": {path: "sha256:" + ERA_SHA256[path] for path in V3_SOURCES}}
           and all(set(row) == set(INDEX_ROW_KEYS) for row in index["programs"]) and index["programs"] == rows,
           "the index names exactly the fourteen programs")


def _no_cycle(registry: Any, consumer: str) -> bool:
    """harness-engineering consumes no repository in any graph of the registry (conditional edges included), so an edge
    from consumer to it cannot close a cycle."""
    ids = {row["id"] for row in registry["repositories"]}
    return ({consumer, "harness-engineering"} <= ids
            and not any(row["consumer"] == "harness-engineering" for body in registry["dependencyGraphs"].values()
                        for row in body["edges"]))


def validate_edge_records() -> None:
    """The v2 operator record carries v1's 17 artefacts unchanged and registers the fourteen programs, each by its
    published digest, for the restated consumer packet (SERVER's published, not registered); EDGE-2 records HE-000's four
    transport files in R12, each byte-identical to v1's provider file. Each record has its exact key set (R2-1), every
    provider path still holds the recorded bytes, and neither edge can close a cycle."""
    v1 = _json(V1_EDGE)
    v2 = _json(V2_EDGE)
    edge_2 = _json(EDGE_2)
    registry = _era_model(SAFE_YAML, "_met_enforce_025_safe_yaml").safe_load(_verified(REPOSITORIES))
    identity = {"graph": "buildArtifact", "consumer": "operator", "provider": "harness-engineering"}

    def program_row(row: Any, role: str, arch: str) -> bool:
        position = ARCHES.index(arch)
        packet = ROLE_PACKETS[role]
        common = (row["providerPath"] == _program_path(role, arch) and row["providerCommit"] is None
                  and row["providerPacket"] == "MET-ENFORCE-025" and row["sha256"] == PROGRAM_SHA256[role][position]
                  and row["mode"] == "100644")
        if packet is None:
            return (common and set(row) == set(UNREGISTERED_ROW_KEYS) and row["status"] == UNREGISTERED
                    and row["consumerPath"] is None and row["consumerPacket"] is None and row["relation"] is None
                    and type(row["note"]) is str and row["note"] != "")
        return (common and set(row) == set(PROGRAM_ROW_KEYS) and row["status"] == "REGISTERED_BEFORE_USE"
                and row["consumerPath"] == CONSUMER_DIR + "%s.%s.bpf" % (role, arch) and row["consumerPacket"] == packet
                and row["relation"] == "BYTE_IDENTICAL")

    _bound(lambda: set(v1) == set(V1_KEYS) and set(v2) == set(V2_KEYS)
           and v2["schemaVersion"] == "planeon.internal.artifact-edge-registry/v2"
           and {key: v2[key] for key in identity} == identity and v2["artifact"] == V2_ARTIFACT
           and v2["ownerDecision"] == v1["ownerDecision"] and v2["rules"] == v1["rules"]
           and v2["notArtifacts"] == v1["notArtifacts"]
           and set(v2["statuses"]) == {"IN_USE", "REGISTERED_BEFORE_USE", UNREGISTERED}
           and all(v2["statuses"][key] == v1["statuses"][key] for key in v1["statuses"])
           and type(v2["statuses"][UNREGISTERED]) is str
           and v2["supersedes"] == {"path": V1_EDGE, "sha256": "sha256:" + ERA_SHA256[V1_EDGE], "packet": "MET-ENFORCE-024"}
           and len(v2["ownerDecisions"]) == len(V2_DECISIONS)
           and all(text.startswith(prefix) for text, prefix in zip(v2["ownerDecisions"], V2_DECISIONS))
           and type(v2["notes"]) is list and all(type(note) is str and note for note in v2["notes"])
           and v2["artifacts"][:len(v1["artifacts"])] == v1["artifacts"]
           and len(v2["artifacts"]) == len(v1["artifacts"]) + 2 * len(ROLES)
           and all(program_row(row, role, arch) for row, (role, arch) in
                   zip(v2["artifacts"][len(v1["artifacts"]):], [(r, a) for r in ROLES for a in ARCHES])),
           "the operator -> harness-engineering edge record v2")
    v1_rows = {row["providerPath"]: row for row in v1["artifacts"]}
    _bound(lambda: set(edge_2) == set(EDGE_2_KEYS) and edge_2["schemaVersion"] == "planeon.internal.artifact-edge-registry/v2"
           and (edge_2["graph"], edge_2["consumer"], edge_2["provider"])
           == ("buildArtifact", "conformance-labs", "harness-engineering")
           and edge_2["artifact"] == EDGE_2_ARTIFACT and edge_2["ownerDecision"].startswith("A13 (2026-10-11, ")
           and edge_2["rules"] == v1["rules"] and edge_2["notArtifacts"] == []
           and edge_2["statuses"] == {"IN_USE": v1["statuses"]["IN_USE"]}
           and type(edge_2["notes"]) is list and all(type(note) is str and note for note in edge_2["notes"])
           and [row["providerPath"] for row in edge_2["artifacts"]] == list(TRANSPORT_FILES)
           and all(set(row) == set(EDGE_2_ROW_KEYS)
                   and row["providerCommit"] == TRANSPORT_COMMIT == v1_rows[row["providerPath"]]["providerCommit"]
                   and row["sha256"] == v1_rows[row["providerPath"]]["sha256"]
                   and row["mode"] == v1_rows[row["providerPath"]]["mode"]
                   and row["consumerPath"] == row["providerPath"] and row["consumerPacket"] == "CONF-CI-001"
                   and row["consumerCommit"] == EDGE_2_CONSUMER_COMMIT and row["relation"] == "BYTE_IDENTICAL"
                   and row["status"] == "IN_USE" for row in edge_2["artifacts"]),
           "the conformance-labs -> harness-engineering edge record (EDGE-2)")
    for row in v2["artifacts"] + edge_2["artifacts"]:
        path = row["providerPath"]
        require(type(path) is str and digest(reviewed_bytes(path)) == row["sha256"],
                "a registered artifact matches its provider bytes: %s" % path)
    _bound(lambda: _no_cycle(registry, "operator") and _no_cycle(registry, "conformance-labs"),
           "neither edge can close a cycle in the repository registry")


def validate_amendment() -> None:
    """W03-PLAN-AMEND-1 binds plan v2 by digest and changes exactly the restated obligations: I07-6 added, I07-4 narrowed,
    and packets added to SEC-4, HI-7 and SEC-QW4, each added packet with its share; plan v2 is unchanged."""
    amendment = _json(AMENDMENT)
    plan = _json(PLAN_V2)
    obligations = {row["id"]: row for row in plan["obligations"]}

    def change(row: Any, expected: tuple) -> bool:
        obligation, kind, packets, added, shared = expected
        base = obligations.get(obligation)
        if (row["obligation"], row["change"], tuple(row["packets"]), row["scope"]) != (obligation, kind, packets, "W03"):
            return False
        if type(row["source"]) is not str or not row["source"]:
            return False
        if kind == "ADDED":
            return base is None and set(row) == {"obligation", "change", "text", "source", "packets", "scope"} \
                and type(row["text"]) is str and row["text"] != ""
        if base is None or base["scope"] != "W03":
            return False
        if kind == "NARROWED":
            return set(row) == {"obligation", "change", "ownership", "source", "packets", "scope"} \
                and tuple(base["packets"]) == packets and type(row["ownership"]) is str and row["ownership"] != ""
        return (set(row) == {"obligation", "change", "packetsAdded", "packets", "shares", "source", "scope"}
                and tuple(row["packetsAdded"]) == added and not set(added) & set(base["packets"])
                and set(packets) == set(base["packets"]) | set(added)
                and set(added) <= set(row["shares"]) == set(shared) and set(shared) <= set(packets)
                and all(type(text) is str and text for text in row["shares"].values()))

    _bound(lambda: set(amendment) == set(AMENDMENT_KEYS)
           and amendment["schemaVersion"] == "planeon.internal.w03-obligation-amendment/v1"
           and amendment["id"] == "W03-PLAN-AMEND-1"
           and amendment["amends"] == {"path": PLAN_V2, "sha256": "sha256:" + ERA_SHA256[PLAN_V2],
                                       "packet": "MET-ENFORCE-024"}
           and amendment["ownerDecision"].startswith("Q-HE2B-2 = (a) \"HE-003 owns both\" (2026-10-13, ")
           and len(amendment["ownerDecisions"]) == len(AMENDMENT_DECISIONS)
           and all(text.startswith(prefix) for text, prefix in zip(amendment["ownerDecisions"], AMENDMENT_DECISIONS))
           and type(amendment["shareRule"]) is str and amendment["shareRule"].startswith(SHARE_RULE_START)
           and type(amendment["unchanged"]) is str and amendment["unchanged"] != ""
           and len(amendment["changes"]) == len(AMENDMENT_CHANGES)
           and all(change(row, expected) for row, expected in zip(amendment["changes"], AMENDMENT_CHANGES)),
           "W03-PLAN-AMEND-1 amends exactly the restated obligations of plan v2")


def validate_compiled_filter_programs() -> None:
    """Every reviewed byte and the adoption record first; then the programs, the edge records and the amendment."""
    validate_era_bytes()
    validate_compiled_filter_programs_status()
    validate_programs()
    validate_edge_records()
    validate_amendment()


def validate() -> None:
    record = authority()
    validator_raw = successor.historical_bytes(VALIDATOR_PATH, regular_bytes(VALIDATOR_PATH))
    literal = b'AUTHORITY_SHA256 = "' + AUTHORITY_SHA256.encode("ascii") + b'"'
    placeholder = b'AUTHORITY_SHA256 = "TO_BE_PINNED_AFTER_SOURCE_FREEZE"'
    require(validator_raw.count(literal) == 1
            and digest(validator_raw.replace(literal, placeholder))
            == record["validatorNormalizedSha256"], "compiled filter programs validator drift")
    paths = sorted((ROOT / "task-packets").glob("*.yaml"))
    old = set(record["baselinePackets"])
    require(len(paths) == 233
            and {path.stem for path in paths} == old | {NEW_PACKET, successor.NEW_PACKET},
            "closed 233-packet catalog retaining the 232-packet checkpoint")
    packets = {}
    for path in paths:
        if path.stem == successor.NEW_PACKET:
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
            "closed source-only compiled-filter-programs packet and inherited commands")
    require(len(packet["allowedPaths"]) == len(set(packet["allowedPaths"]))
            and set(packet["allowedPaths"]) == set(record["changedFiles"])
            | set(record["newFiles"]) | {AUTHORITY_PATH, VALIDATOR_PATH,
                                         "task-packets/" + NEW_PACKET + ".yaml"},
            "unreviewed or omitted compiled-filter-programs packet path")
    for path, rule in record["changedFiles"].items():
        current = successor.historical_bytes(path, regular_bytes(path))
        require(digest(current) == rule["afterSha256"]
                and digest(historical_bytes(path, current)) == rule["beforeSha256"],
                "unreviewed current source: " + path)
    for path, expected in record["newFiles"].items():
        require(digest(successor.historical_bytes(path, regular_bytes(path))) == expected,
                "new source drift: " + path)
    validate_compiled_filter_programs()


if __name__ == "__main__":
    validate()
    print("Compiled filter programs valid: 233 current specifications; 232-packet checkpoint and exact 231-packet predecessor; content reviewed.")
