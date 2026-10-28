#!/usr/bin/env python3
"""Validate the MET-LIVE-003 neutral Linux probe interface (Q-PK-6) as harness-onion data (the four v1/ handoff files byte-identical, the closed binding record with LPK-0's NEUTRAL_INTERFACE_CONTRACT placeholder bound, the reference model and its vectors; DATA_CHECK_ONLY, no gate path) with its adoption records and D5a oracle, and the exact 262-to-261 projection."""
from __future__ import annotations

import ast
import base64
import binascii
import builtins
import copy
import difflib
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
    import validate_linux_probe_kit_admission as successor
except ImportError:
    from scripts.safe_yaml import safe_load
    from scripts import validate_linux_probe_kit_admission as successor


ROOT = Path(__file__).resolve().parents[1]
AUTHORITY_PATH = "architecture/linux-probe-interface-authority.json"
AUTHORITY_SHA256 = "d3b7ad79a666d47664a70c610dcfc9f1fe9f5f01314b5bd4707eb02e65e7f6db"
VALIDATOR_PATH = "scripts/validate_linux_probe_interface.py"
BASE_COMMIT = "b8db30e5dfc4c820b70553cd1439359d73f4573a"
NEW_PACKET = "MET-LIVE-003"
PREVIOUS_PACKET = "MET-GOV-003"
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
            require(key not in result, "duplicate linux-probe-interface authority member")
            result[key] = value
        return result

    def no_constant(_value: str) -> Any:
        raise ValueError("nonfinite linux-probe-interface authority number")

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
        require(digest(raw) == AUTHORITY_SHA256, "linux probe interface history authority digest")
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
    }, "closed linux probe interface history authority")
    require(value["schemaVersion"] == "harness.planeon.ai/linux-probe-interface-authority/v1"
            and value["authorityPacket"] == NEW_PACKET
            and value["acceptedBase"] == BASE_COMMIT
            and type(value["baselinePackets"]) is dict
            and len(value["baselinePackets"]) == 261
            and NEW_PACKET not in value["baselinePackets"]
            and type(value["changedFiles"]) is dict
            and type(value["newFiles"]) is dict
            and _sha(value["packetSha256"])
            and _sha(value["validatorNormalizedSha256"]),
            "accepted 261-packet base")
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
    # An exact 261-era byte string is already older than the successor layer.
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


# MET-LIVE-003 (roadmap LINUX-PROBE-INTERFACE; owner decisions Q-PK-6 "Neutral contract (Recommended)" and "Keep them in
# R12 (Recommended)" on R12's acceptance rules; the lane monitor's owner-delegated rulings, among them the adoptions
# MON-LIVE003-ADOPT-C2 to MON-LIVE003-ADOPT-C6, MON-LIVE003-ORACLE-KEEP, MON-LIVE003-R1-PATH and the 260 plan ruling on
# the history file names) brings the neutral Linux probe interface contract into harness-onion as data, byte-identical:
# the four v1/ handoff files under architecture/linux-probe-interface/ (the unit R12 vendors back), the closed binding
# record binding.json (their digests, the source, the three review digests and the binding of LPK-0's
# NEUTRAL_INTERFACE_CONTRACT placeholder), its vectors, the replay script, the README and a standard-library reference
# model (scripts/linux_probe_interface.py), with the adoption records: status.json, the redacted history of its one light
# review (review-history-*, not review-round*.json records, with no merge authority), the D5a oracle test and its oracle
# identity. It is data only, and no gate path: it changes no earlier contract, the review-record brief registry or the
# evolution surface record. Repository bytes and modes are read only through reviewed_bytes and reviewed_mode, so a later
# bridged successor projects its own edits away first; a path outside this era is refused before it is read, every era
# file is bound by digest on every read, and no directory is listed. Each refusal is a pure check over the values read,
# so every one has a failing case on plain data. Checked here: the freeze (this packet edits no existing file but chain
# validators, tests and the three living catalogs); the files this packet adds (exactly its own, each once; git mode
# 100644; no absolute local path); the adoption (the status record's closed shape and values; the nine adopted files are
# the adopted subject's bytes; the adoptions c2 to c6 with their check digests; the light review bound to its published
# record and brief; the brief redaction as stated; the oracle identity binding the oracle file with ruling KEEP); the
# contract (the four v1/ files are the monitor-verified handoff digests the binding's files rows state; the binding's
# source and reviews equal the MANIFEST's, whose last verdict is PASS_FOR_HANDOFF, and the source commit is never
# resolved; A8's forward pin: the placeholder binding names LPK-0's merged amendment.json by this era's digest, the
# placeholder is among that record's effective predecessors, and the interface digest is probe-interface.json's; the
# reference model, executed from this era's verified bytes, returns no refusal for the binding; the vectors replay as
# replay.py replays them, with every model call through the model's check: one positive, 28 negatives and 15 validator
# vectors, no mismatch); the registry (261's merged briefs.json, unchanged, holding this packet's one PACKET series entry
# and no CONTRACT series); and the derived gate check (the gate paths among the packet's changed files, by the
# evolution surface record's 31 exact or prefix gate entries lower-cased, which equals case-folding on this era's
# all-ASCII gate entries and paths, are none). Last, this layer's own inverse hunks are the canonical byte-minimal ones,
# recomputed from its era's bytes (MET-PERF-040's carried rule).
CONTRACT_DIR = "architecture/linux-probe-interface"
BINDING_PATH = CONTRACT_DIR + "/binding.json"
VECTORS_PATH = CONTRACT_DIR + "/vectors.json"
README_PATH = CONTRACT_DIR + "/README.md"
REPLAY_PATH = CONTRACT_DIR + "/replay.py"
STATUS_PATH = CONTRACT_DIR + "/status.json"
ORACLE_IDENTITY_PATH = CONTRACT_DIR + "/oracle-identity.json"
V1_DIR = CONTRACT_DIR + "/v1/"
V1_NAMES = ("MANIFEST.json", "README.md", "probe-interface.json", "probe-interface.schema.json")
V1_FILES = tuple(V1_DIR + name for name in V1_NAMES)
INSTANCE_NAME = "probe-interface.json"
SCHEMA_NAME = "probe-interface.schema.json"
MODEL_PATH = "scripts/linux_probe_interface.py"
ORACLE_TEST = "tests/test_linux_probe_interface_oracle.py"
HEAD_TEST = "tests/test_linux_probe_interface.py"
PACKET_PATH = "task-packets/" + NEW_PACKET + ".yaml"
HISTORY = ("light-r1",)
HISTORY_RECORDS = tuple(CONTRACT_DIR + "/review-history-%s.json" % name for name in HISTORY)
HISTORY_BRIEFS = tuple(CONTRACT_DIR + "/review-history-%s-brief.md" % name for name in HISTORY)
# The nine adopted contract files (status.json's adoptedSubject) and the adoption records.
CONTRACT_FILES = (BINDING_PATH, VECTORS_PATH, README_PATH, REPLAY_PATH, MODEL_PATH) + V1_FILES
ADOPTION_FILES = (STATUS_PATH,) + HISTORY_RECORDS + HISTORY_BRIEFS + (ORACLE_IDENTITY_PATH, ORACLE_TEST)
NEW_FILES = CONTRACT_FILES + ADOPTION_FILES
LIVING_CATALOGS = ("docs/MASTER_DEVELOPMENT_PLAN.md", "docs/repositories/00-harness-engineering.md",
                   "task-packets/README.md")
# LPK-0's merged record and its placeholder (A8's forward pin; DESIGN rev 2 section 2).
LPK0_RECORD = "architecture/probe-kit-scope/amendment.json"
PLACEHOLDER = "NEUTRAL_INTERFACE_CONTRACT"
REGISTRY_PATH = "architecture/review-record/briefs.json"
PACKET_BRIEF = "architecture/review-briefs/REVIEW_BRIEF_PACKET.md"
SURFACE_RECORD = "architecture/evolution-surface/evolution-surface.json"
SURFACE_MODEL = "scripts/evolution_surface.py"
GATE_MATERIAL = 31
# The adopted subject (candidate c6, MON-LIVE003-ADOPT-C6), by the digests status.json names.
ADOPTED_SUBJECT = MappingProxyType({'architecture/linux-probe-interface/binding.json': '246fc243621d431fbe6cbbe9934ebb6945b95dd312453dfe6c3b0b02d8951bc9',
 'architecture/linux-probe-interface/vectors.json': 'b1b4ff4f6c12e08eaaaef382c4c451179d959ed6841b40343bd7a5cdf20688b4',
 'architecture/linux-probe-interface/README.md': '494ee85b43f5fed6411b29e32f9c93ae2350d5cf5a87e4a9ef6931fdad5ac805',
 'architecture/linux-probe-interface/replay.py': 'cbfa353fa514363e06c03c76d6fc10a15b96ad010639d871f51a6f5a9c01273b',
 'scripts/linux_probe_interface.py': '276370904c14f0dcdb715ef8415f788e5b07b39adcb80d6b19a38a1dfa7d0010',
 'architecture/linux-probe-interface/v1/MANIFEST.json': '67cedd0cc251c61bfd42bc0f100d90923d3bafebb8b38c4e2ae7da891973a9a8',
 'architecture/linux-probe-interface/v1/README.md': '049773616005f017bda9a79f22448fc16258ea61d5351ea108a5050213819da3',
 'architecture/linux-probe-interface/v1/probe-interface.json': '8c630b41bed90cd10781edc66ba122d2c4caf06fbf5adfaa2be996e3d90233be',
 'architecture/linux-probe-interface/v1/probe-interface.schema.json': '2ae672a9912061810f00436e4939c0d4a45074e345b01e3fb04387fed8a5ab69'})
# The four v1/ files' monitor-verified handoff digests, in the binding's order (the model pins the same table).
HANDOFF_SHA256 = MappingProxyType({'MANIFEST.json': '67cedd0cc251c61bfd42bc0f100d90923d3bafebb8b38c4e2ae7da891973a9a8',
 'README.md': '049773616005f017bda9a79f22448fc16258ea61d5351ea108a5050213819da3',
 'probe-interface.json': '8c630b41bed90cd10781edc66ba122d2c4caf06fbf5adfaa2be996e3d90233be',
 'probe-interface.schema.json': '2ae672a9912061810f00436e4939c0d4a45074e345b01e3fb04387fed8a5ab69'})
# The source members the binding and the MANIFEST both state, and the passing verdict of the last review.
SOURCE_MEMBERS = ("commit", "readAt", "repository", "tree")
HANDOFF_VERDICT = "PASS_FOR_HANDOFF"
# The status record written at adoption: its closed key sets and its values, restated.
STATUS_SCHEMA = "planeon.internal.linux-probe-interface-status/v1"
WORK_ITEM = 'LINUX-PROBE-INTERFACE (the neutral Linux probe interface as harness-onion data)'
SLOT = 262
STATUS_KEYS = ('schemaVersion',
 'workItem',
 'packet',
 'slot',
 'status',
 'baseMain',
 'adoptedSubject',
 'adoptions',
 'design',
 'independentReviewers',
 'reviews',
 'reviewHistoryNote',
 'briefRedactions',
 'predecessorPin',
 'oracle',
 'slips',
 'nonClaims')
ADOPTION_KEYS = ("candidate", "ruling", "by", "date", "adoptionCheckSha256", "change")
ADOPTIONS = ({'candidate': 'c2',
  'ruling': 'MON-LIVE003-ADOPT-C2',
  'by': 'the lane monitor, owner-delegated (2026-10-22)',
  'date': '2026-10-22',
  'adoptionCheckSha256': '6f09bcbeeac098ac6e0a3dc48a046dbb6bef675139c4252cb95dcc7c4a028b6f',
  'change': "the first adoption, after the light review's R-L1-A (L1-1 to L1-11 applied)"},
 {'candidate': 'c3',
  'ruling': 'MON-LIVE003-ADOPT-C3',
  'by': 'the lane monitor, owner-delegated (2026-10-22)',
  'date': '2026-10-23',
  'adoptionCheckSha256': 'c6d7c8631879995f5c2cf7b261edc26f912a7cf9198e3ed40ab1837c8f74a1a7',
  'change': "README only: the two-sentence fix from the D5a oracle's run (86/86)"},
 {'candidate': 'c4',
  'ruling': 'MON-LIVE003-ADOPT-C4',
  'by': 'the lane monitor, owner-delegated (2026-10-22)',
  'date': '2026-10-23',
  'adoptionCheckSha256': '26ea40206c5b7fc5a5f381a7c8ebb06b00805c20b4af06ae1bb6df19df4598c4',
  'change': "slot 263 -> 262 and the consequent placeholderBinding.recordSha256 (LPK-0 c6's record) (monitor "
            'slot re-sequence 2026-10-23); README slot texts follow'},
 {'candidate': 'c5',
  'ruling': 'MON-LIVE003-ADOPT-C5',
  'by': 'the lane monitor, owner-delegated (2026-10-22)',
  'date': '2026-10-23',
  'adoptionCheckSha256': '44b4c65d40871028010e968ace228004f879ae43f58c306435bbe7b5b87bc9a3',
  'change': "README errata only: line 43 names LPK-0's record as 3de2d73e (was cf49670d), found by the D5a "
            'oracle on c4'},
 {'candidate': 'c6',
  'ruling': 'MON-LIVE003-ADOPT-C6',
  'by': 'the lane monitor, owner-delegated (2026-10-22)',
  'date': '2026-10-23',
  'adoptionCheckSha256': '7f3d998d3d9fa3bdb27992e5063abf29be24332e774e4340b80b9ebe3940c7c6',
  'change': 'README errata only: the review-history sentence (260 plan item 2)'})
STATUS_DESIGN = {'path': "DESIGN.rev2.md (kept with the lane's records)",
 'sha256': '6d2ed5c5affc5568fbf04ac659625a94ba7f27b8fafac5fa49a0e2da012db1c3',
 'note': "written for slot 263; the monitor's 2026-10-23 re-sequence made it 262 (c4)"}
INDEPENDENT_REVIEWERS = 'SEPARATE_AGENTS_NOT_AUTHOR (one fresh agent for the light round)'
REVIEW_ROWS = ({'review': 'light round 1',
  'record': 'architecture/linux-probe-interface/review-history-light-r1.json',
  'recordSha256': '1fd7115d93c2c0b3f9e3d648316403b6a67057743013b92a0141d443d99fefa4',
  'verdict': 'CHANGES_REQUIRED',
  'subject': 'candidate c1 (binding 275a6d588ad1540152c4417b192255ce0b994547c60df113f39bc85974cba8bc)',
  'brief': 'architecture/linux-probe-interface/review-history-light-r1-brief.md',
  'briefReviewedSha256': 'fa2dc4b7d2eee49977ecf66374dbf6519db8b215b53715905138cf6db786f16b',
  'briefPublishedSha256': '96e4552665fcc4288cb71d24d70c92ad30a48684f8810c1198c4d809ed742f02',
  'closure': 'R-L1-A: L1-1 to L1-11 applied as candidate c2 with no second review, consistent with one light '
             'review (the lane monitor, 2026-10-22)'},)
REVIEW_HISTORY_NOTE = ('Published as review-history-<kind>-r<n>.json and -brief.md: a redacted record from before review-record '
 "v2, not a review-round*.json record, with no merge authority. This packet's merge authority is its v2 "
 'MET-LIVE-003/packet series (the monitor, 2026-10-23).')
REDACTION_KEYS = ("brief", "reviewedSha256", "publishedSha256", "substitutions")
SUBSTITUTIONS = ({'fromSha256': '1eedbfd71339d2596624d83bc7c0daa404c937e39dd76bf8af995e65b0181c67',
  'from': "the lane's CI state directory (home-relative)",
  'to': '<workspace>/',
  'count': 3},
 {'fromSha256': 'c955eccd4877ecd86f04647fba45d5d4709507b644e193fc7ac9a182d0459ec8',
  'from': "the session's temporary directory",
  'to': '<scratch>/',
  'count': 2})
STATUS_PIN = {'record': 'architecture/probe-kit-scope/amendment.json',
 'sha256': '3de2d73e0413388ba286899cdd364c876dfbd869510c88537da8b1c91726ef8b',
 'atBase': 'b8db30e5dfc4c820b70553cd1439359d73f4573a',
 'check': 'A8: binding.placeholderBinding.recordSha256 equals the merged record'}
STATUS_ORACLE = {'test': 'tests/test_linux_probe_interface_oracle.py',
 'sha256': 'e706dab917ef5b16192130dcddf776a6f8ff4467f3af03fb1422bd673088ece3',
 'identity': 'architecture/linux-probe-interface/oracle-identity.json',
 'result': '86/86 on c5; README-only change since (c6)'}
SLIPS = ({'id': 'MON-LIVE003-R1-PATH',
  'ruling': 'KEEP, the lane monitor under owner delegation',
  'what': "the light review's reviewer put a home path on a command line; nothing was written outside its "
          'WORK folder and the outputs are clean'},)
NON_CLAIMS = ('FORM_ONLY: the binding records the interface form only, not R12 acceptance of any probe output.',
 'No R12 file changes in this packet; R12 vendors v1/ back in its own packet, and its files stay '
 'authoritative until then.',
 "R12's acceptance rules, the status and count thresholds, stay in R12.")
# The D5a oracle test and its identity (MON-LIVE003-ORACLE-KEEP; the 260 plan ruling's item 3).
ORACLE_SHA256 = "e706dab917ef5b16192130dcddf776a6f8ff4467f3af03fb1422bd673088ece3"
IDENTITY_SHA256 = "180ae881c1ef587e21ef3f3be522217920f92b2d622c77c854a5161ba73f78e2"
ORACLE_SCHEMA = "planeon.oracle-identity/v1"
ORACLE_RULING = MappingProxyType({'decision': 'KEEP',
 'by': 'LANE_MONITOR',
 'ref': 'MON-LIVE003-ORACLE-KEEP; disclosed interruptions: a 429 stop and resume, the slot re-derivation, '
        'and the parser-marker resume after MON-LIVE003-ADOPT-C5',
 'date': '2026-10-23'})
# The registry is 261's merged file, unchanged: 260 registered this packet's PACKET series; this packet publishes no v2
# contract rounds, so it has no CONTRACT series.
REGISTRY_SHA256 = "4cc369e76bc3092dd9085b393a79c2d8b641ea47a1ddb61e62c033965544ce62"
REGISTRY_ENTRY = ("PACKET", NEW_PACKET + "/packet", PACKET_BRIEF)
# The replay (replay.py's run over this era's bytes): one positive, 28 negatives and 15 validator vectors, no mismatch.
REPLAY_COUNTS = MappingProxyType({"positive": 1, "negatives": 28, "validatorVectors": 15, "mismatches": []})
# The model's refusal texts the validator vectors' derivation reads (the test checks each equals the model's own).
SHAPE_REFUSAL = "the record's shape is not the closed shape"
KEYWORD_REFUSAL = "the schema uses a keyword outside the supported set"
CONFORMANCE_REFUSAL = "probe-interface.json does not conform to its schema"
# Every file this era's check reads, with its digest: the files this packet adds, LPK-0's merged record, the registry and
# the generic PACKET brief, and the evolution surface record and its model.
ERA_SHA256 = MappingProxyType({
    "architecture/evolution-surface/evolution-surface.json": "188c75d4be1b4c0eebfd01b9454873a09c903238ebdc05219126c734b0d245bd",
    "architecture/linux-probe-interface/README.md": "494ee85b43f5fed6411b29e32f9c93ae2350d5cf5a87e4a9ef6931fdad5ac805",
    "architecture/linux-probe-interface/binding.json": "246fc243621d431fbe6cbbe9934ebb6945b95dd312453dfe6c3b0b02d8951bc9",
    "architecture/linux-probe-interface/oracle-identity.json": "180ae881c1ef587e21ef3f3be522217920f92b2d622c77c854a5161ba73f78e2",
    "architecture/linux-probe-interface/replay.py": "cbfa353fa514363e06c03c76d6fc10a15b96ad010639d871f51a6f5a9c01273b",
    "architecture/linux-probe-interface/review-history-light-r1-brief.md": "96e4552665fcc4288cb71d24d70c92ad30a48684f8810c1198c4d809ed742f02",
    "architecture/linux-probe-interface/review-history-light-r1.json": "1fd7115d93c2c0b3f9e3d648316403b6a67057743013b92a0141d443d99fefa4",
    "architecture/linux-probe-interface/status.json": "a03fe813c562d3730c20d212d2966045bf8c1581da1053d4fe25fdc764843b29",
    "architecture/linux-probe-interface/v1/MANIFEST.json": "67cedd0cc251c61bfd42bc0f100d90923d3bafebb8b38c4e2ae7da891973a9a8",
    "architecture/linux-probe-interface/v1/README.md": "049773616005f017bda9a79f22448fc16258ea61d5351ea108a5050213819da3",
    "architecture/linux-probe-interface/v1/probe-interface.json": "8c630b41bed90cd10781edc66ba122d2c4caf06fbf5adfaa2be996e3d90233be",
    "architecture/linux-probe-interface/v1/probe-interface.schema.json": "2ae672a9912061810f00436e4939c0d4a45074e345b01e3fb04387fed8a5ab69",
    "architecture/linux-probe-interface/vectors.json": "b1b4ff4f6c12e08eaaaef382c4c451179d959ed6841b40343bd7a5cdf20688b4",
    "architecture/probe-kit-scope/amendment.json": "3de2d73e0413388ba286899cdd364c876dfbd869510c88537da8b1c91726ef8b",
    "architecture/review-briefs/REVIEW_BRIEF_PACKET.md": "6dcff68d7e6b01823f1740063e94910edcc159a71a6ee803f1b66c62fd06e274",
    "architecture/review-record/briefs.json": "4cc369e76bc3092dd9085b393a79c2d8b641ea47a1ddb61e62c033965544ce62",
    "scripts/evolution_surface.py": "f38fa6d00ec5fbbbcab8ff01d0e56824e805327b872dc1e23e579e522a681fd9",
    "scripts/linux_probe_interface.py": "276370904c14f0dcdb715ef8415f788e5b07b39adcb80d6b19a38a1dfa7d0010",
    "tests/test_linux_probe_interface_oracle.py": "e706dab917ef5b16192130dcddf776a6f8ff4467f3af03fb1422bd673088ece3",
})
# Absolute local path markers, matched case-insensitively; spelled in parts, so this file holds none of them. A marker
# counts when a path character follows it.
LOCAL_PATH_MARKERS = (b"/" + b"users/", b"/" + b"private/", b".local" + b"/state")
PATH_BYTES = b"abcdefghijklmnopqrstuvwxyz0123456789_.-/"


def reviewed_bytes(path: str) -> bytes:
    """This packet's reviewed bytes of path; a bridged successor projects newer bytes back first."""
    return successor.historical_bytes(path, regular_bytes(path))


def reviewed_mode(path: str) -> int:
    """The lstat mode of path in this packet's tree; a bridged successor projects a newer mode back first."""
    _path(path)
    return (ROOT / path).lstat().st_mode


def _era_bytes(path: Any, raw: Any) -> bytes:
    """An era file's bytes, checked against its era digest; a path outside the era is refused."""
    expected = ERA_SHA256.get(path) if type(path) is str else None
    require(expected is not None, "MET-LIVE-003 reviewed bytes are bound: " + str(path))
    require(type(raw) is bytes and digest(raw) == expected, "unreviewed LINUX-PROBE-INTERFACE source: " + path)
    return raw


def _verified(path: str) -> bytes:
    """reviewed_bytes, checked against its era digest on every read; a path outside the era is refused before it is
    read."""
    require(type(path) is str and path in ERA_SHA256, "MET-LIVE-003 reviewed bytes are bound: " + str(path))
    return _era_bytes(path, reviewed_bytes(path))


def _json(path: str) -> Any:
    return parse(_verified(path))


def _holds(check: Any) -> bool:
    """A structural check over this era's data; a malformed value does not hold."""
    try:
        return check() is True
    except (KeyError, TypeError, AttributeError, IndexError, ValueError):
        return False


def _bound(check: Any, message: str) -> None:
    require(_holds(check), message)


def _git_mode(mode: int) -> str | None:
    """The git mode of a regular file from its lstat mode; anything else has none."""
    if not stat.S_ISREG(mode):
        return None
    return "100755" if mode & 0o100 else "100644"


def _local_path(raw: bytes) -> bool:
    """Whether raw holds an absolute local path: a marker, case-insensitively, followed by a path character."""
    low = raw.lower()
    for marker in LOCAL_PATH_MARKERS:
        at = low.find(marker)
        while at >= 0:
            end = at + len(marker)
            if end < len(low) and low[end:end + 1] in PATH_BYTES:
                return True
            at = low.find(marker, at + 1)
    return False


def _era_model(path: str, name: str) -> types.ModuleType:
    """A standard-library reference module of this era, executed from its verified bytes (no import, no bytecode)."""
    module = types.ModuleType(name)
    module.__file__ = str(ROOT / path)
    exec(compile(_verified(path), path, "exec", dont_inherit=True), module.__dict__)
    return module


def era_models() -> tuple:
    """(the probe interface model, the evolution surface model), each executed from this era's verified bytes."""
    return (_era_model(MODEL_PATH, "_met_live_003_linux_probe_interface"),
            _era_model(SURFACE_MODEL, "_met_live_003_evolution_surface"))


def check_freeze(changed: Any) -> None:
    """This packet edits no existing file but chain validators (scripts/validate_*.py, one level deep), tests and the
    three living catalogs: no model, no earlier contract or record, no registry and no conftest change."""
    for path in list(changed):
        require(type(path) is str and path not in ("conftest.py", "tests/conftest.py")
                and ((path.startswith("scripts/validate_") and path.endswith(".py") and path.count("/") == 1)
                     or path.startswith("tests/") or path in LIVING_CATALOGS),
                "this packet edits only chain validators, tests and the three living catalogs: " + str(path))


def check_new_files(added: Any) -> None:
    """The packet adds exactly the nine contract files, the status record, the review history, the oracle identity, the
    oracle test and the layer's test, each once."""
    _bound(lambda: len(set(NEW_FILES)) == len(NEW_FILES) and type(added) is list
           and sorted(added) == sorted(NEW_FILES + (HEAD_TEST,)),
           "this packet adds exactly its contract files, adoption records, oracle test and layer test, each once")


def check_added_file(path: str, mode: Any, raw: Any) -> None:
    """A file this packet adds is a regular file of git mode 100644 (not a link, not executable) and holds no absolute
    local path."""
    require(type(mode) is int and _git_mode(mode) == "100644",
            "a file this packet adds is a regular file of git mode 100644: " + path)
    require(type(raw) is bytes and not _local_path(raw), "no absolute local path in a file this packet adds: " + path)


def validate_files() -> None:
    """The freeze and the files this packet adds, from this era's authority and modes."""
    record = authority()
    check_freeze(list(_PROJECTION_RULES))
    check_new_files(list(record["newFiles"]))
    for path in NEW_FILES:
        check_added_file(path, reviewed_mode(path), _verified(path))


def check_status(status: Any) -> None:
    """The status record's closed shape and values: LINUX-PROBE-INTERFACE adopted as MET-LIVE-003 at slot 262 on this
    era's base, its design, reviewers, review history note, predecessor pin, oracle row, slips and non-claims as
    adopted."""
    _bound(lambda: type(status) is dict and tuple(status) == STATUS_KEYS and status["schemaVersion"] == STATUS_SCHEMA
           and status["workItem"] == WORK_ITEM and status["packet"] == NEW_PACKET and type(status["slot"]) is int
           and status["slot"] == SLOT and status["status"] == "ADOPTED" and status["baseMain"] == BASE_COMMIT
           and status["design"] == STATUS_DESIGN and status["independentReviewers"] == INDEPENDENT_REVIEWERS
           and status["reviewHistoryNote"] == REVIEW_HISTORY_NOTE and status["predecessorPin"] == STATUS_PIN
           and status["oracle"] == STATUS_ORACLE and status["slips"] == list(SLIPS)
           and status["nonClaims"] == list(NON_CLAIMS), "adopted LINUX-PROBE-INTERFACE status")


def check_adoptions(adoptions: Any) -> None:
    """The adoptions run c2 to c6 in order, each with its ruling, date, change and ADOPTION_CHECK digest."""
    _bound(lambda: type(adoptions) is list and [row["candidate"] for row in adoptions] == ["c%d" % n for n in range(2, 7)]
           and all(type(row) is dict and tuple(row) == ADOPTION_KEYS for row in adoptions)
           and adoptions == list(ADOPTIONS),
           "the adoptions run c2 to c6 with their rulings and ADOPTION_CHECK digests")


def check_subject(subject: Any, files: Any) -> None:
    """The nine adopted files are the adopted subject's bytes, by the digests status.json names."""
    _bound(lambda: type(subject) is dict and tuple(subject) == tuple(ADOPTED_SUBJECT) and subject == dict(ADOPTED_SUBJECT),
           "status.json names the adopted subject by digest")
    for path in ADOPTED_SUBJECT:
        require(type(files) is dict and type(files.get(path)) is bytes and digest(files[path]) == ADOPTED_SUBJECT[path],
                "the adopted files are the adopted subject's bytes: " + path)


def check_review_lists(status: Any) -> None:
    """status.json records every review and every brief redaction, one each."""
    _bound(lambda: type(status["reviews"]) is list and len(status["reviews"]) == len(REVIEW_ROWS)
           and type(status["briefRedactions"]) is list and len(status["briefRedactions"]) == len(REVIEW_ROWS),
           "every review and brief redaction is recorded")


def check_review(number: int, row: Any, record_raw: Any, brief_raw: Any) -> None:
    """Review `number` is its row as adopted, bound by sha256 to its published record, whose verdict is the row's and whose
    brief digest is the reviewed brief's, and to its published brief."""
    _bound(lambda: 1 <= number <= len(REVIEW_ROWS) and row == REVIEW_ROWS[number - 1]
           and tuple(row) == tuple(REVIEW_ROWS[number - 1])
           and row["record"] == HISTORY_RECORDS[number - 1] and row["brief"] == HISTORY_BRIEFS[number - 1]
           and type(record_raw) is bytes and digest(record_raw) == row["recordSha256"]
           and parse(record_raw)["verdict"] == row["verdict"]
           and parse(record_raw)["brief"]["sha256"] == row["briefReviewedSha256"]
           and type(brief_raw) is bytes and digest(brief_raw) == row["briefPublishedSha256"],
           "a review is bound to its published record and brief: review %d" % number)


def check_redaction(number: int, redaction: Any, row: Any, brief_raw: Any) -> None:
    """Brief redaction `number` names its review's brief and its reviewed and published digests, and the two stated
    substitutions; the published brief holds each placeholder exactly as many times as stated."""
    _bound(lambda: type(redaction) is dict and tuple(redaction) == REDACTION_KEYS and redaction["brief"] == row["brief"]
           and redaction["reviewedSha256"] == row["briefReviewedSha256"]
           and redaction["publishedSha256"] == row["briefPublishedSha256"]
           and redaction["substitutions"] == list(SUBSTITUTIONS)
           and type(brief_raw) is bytes and digest(brief_raw) == redaction["publishedSha256"]
           and all(brief_raw.count(item["to"].encode("utf-8")) == item["count"] for item in SUBSTITUTIONS),
           "a brief redaction is as stated: brief %d" % number)


def check_oracle_identity(identity_raw: Any, oracle_raw: Any, oracle_row: Any) -> None:
    """The D5a oracle file is the oracle agent's bytes, and its identity binds it by sha256 with ruling KEEP by the lane
    monitor (MON-LIVE003-ORACLE-KEEP), as status.json's oracle row names it (check_tree checks the identity in full, in
    the suite)."""
    _bound(lambda: type(oracle_raw) is bytes and digest(oracle_raw) == ORACLE_SHA256
           and type(identity_raw) is bytes and digest(identity_raw) == IDENTITY_SHA256
           and (lambda identity: identity["schemaVersion"] == ORACLE_SCHEMA
                and identity["file"] == {"path": ORACLE_TEST, "sha256": digest(oracle_raw)}
                and identity["ruling"] == dict(ORACLE_RULING))(parse(identity_raw))
           and oracle_row == STATUS_ORACLE and oracle_row["test"] == ORACLE_TEST
           and oracle_row["identity"] == ORACLE_IDENTITY_PATH and oracle_row["sha256"] == digest(oracle_raw),
           "the oracle identity binds the oracle file, with ruling KEEP by the lane monitor")


def validate_adoption() -> None:
    """The status record, the adopted files, every review with its record and brief, every brief redaction, the
    adoptions and the oracle identity."""
    status = _json(STATUS_PATH)
    check_status(status)
    check_adoptions(status["adoptions"])
    check_subject(status["adoptedSubject"], {path: _verified(path) for path in ADOPTED_SUBJECT})
    check_review_lists(status)
    for number, row in enumerate(status["reviews"], 1):
        brief = _verified(HISTORY_BRIEFS[number - 1])
        check_review(number, row, _verified(HISTORY_RECORDS[number - 1]), brief)
        check_redaction(number, status["briefRedactions"][number - 1], row, brief)
    check_oracle_identity(_verified(ORACLE_IDENTITY_PATH), _verified(ORACLE_TEST), status["oracle"])


def check_handoff(binding: Any, files: Any) -> None:
    """The four v1/ files are the monitor-verified handoff bytes, and the binding's files rows state exactly their paths
    and digests, in order."""
    _bound(lambda: type(files) is dict and sorted(files) == sorted(V1_NAMES)
           and all(type(files[name]) is bytes and digest(files[name]) == HANDOFF_SHA256[name] for name in V1_NAMES)
           and binding["files"] == [{"path": V1_DIR + name, "sha256": HANDOFF_SHA256[name]} for name in V1_NAMES],
           "the four v1/ files are the handoff bytes the binding states")


def check_source(binding: Any, manifest_raw: Any) -> None:
    """The binding's source and reviews equal the MANIFEST's (each review's round, record digest and verdict), and the
    last verdict is PASS_FOR_HANDOFF; the source commit is never resolved."""
    _bound(lambda: (lambda manifest: type(binding["source"]) is dict and sorted(binding["source"]) == list(SOURCE_MEMBERS)
                    and binding["source"] == manifest["source"] and sorted(manifest["source"]) == list(SOURCE_MEMBERS)
                    and type(binding["reviews"]) is list and len(binding["reviews"]) > 0
                    and binding["reviews"] == [{"round": row["round"], "recordSha256": row["recordSha256"],
                                                "verdict": row["verdict"]} for row in manifest["reviews"]]
                    and binding["reviews"][-1]["verdict"] == HANDOFF_VERDICT
                    and manifest["verdict"] == HANDOFF_VERDICT)(parse(manifest_raw)),
           "the binding's source and reviews are the MANIFEST's, the last verdict PASS_FOR_HANDOFF")


def check_placeholder(binding: Any, pin: Any, lpk0_raw: Any, interface_raw: Any) -> None:
    """A8's forward pin: the placeholder binding names LPK-0's merged amendment.json by this era's digest, binds its
    NEUTRAL_INTERFACE_CONTRACT placeholder, which is among that record's effective predecessors, to this packet, and
    names probe-interface.json's digest; status.json's predecessor pin names the same record and digest."""
    _bound(lambda: type(lpk0_raw) is bytes and type(interface_raw) is bytes
           and binding["placeholderBinding"] == {"record": LPK0_RECORD, "recordSha256": digest(lpk0_raw),
                                                 "placeholder": PLACEHOLDER, "boundTo": NEW_PACKET,
                                                 "interfaceSha256": digest(interface_raw)}
           and PLACEHOLDER in parse(lpk0_raw)["effectivePredecessors"]["placeholders"]
           and pin["record"] == LPK0_RECORD and pin["sha256"] == digest(lpk0_raw),
           "the placeholder binding names LPK-0's merged record and the interface by this era's digests")


def check_model(refusals: Any) -> None:
    """The reference model returns no refusal for the adopted binding."""
    _bound(lambda: refusals == [], "the reference model returns no refusal for the adopted binding")


def _apply(document: Any, ops: Any) -> Any:
    """replay.py's JSON-pointer applier, restated: set, delete and append on a deep copy."""
    document = copy.deepcopy(document)
    for op in ops:
        parts = [part.replace("~1", "/").replace("~0", "~") for part in op["path"].split("/")[1:]]
        node = document
        for part in parts[:-1]:
            node = node[int(part)] if isinstance(node, list) else node[part]
        key = parts[-1] if parts else None
        key = int(key) if isinstance(node, list) and key not in (None, "-") else key
        if op["op"] == "set" and not parts:
            document = op["value"]
        elif op["op"] == "set":
            node[key] = op["value"]
        elif op["op"] == "delete":
            del node[key]
        elif op["op"] == "append":
            node.append(op["value"])
    return document


def _v1_files(base: Any, overrides: Any) -> Any:
    """replay.py's files_for, restated: the v1/ files with a vector's overrides (JSON pointer ops, raw text, or a deeply
    nested array)."""
    out = dict(base)
    for name, change in overrides.items():
        if "ops" in change:
            out[name] = json.dumps(_apply(json.loads(base[name]), change["ops"]), ensure_ascii=False).encode("utf-8")
        elif "text" in change:
            out[name] = change["text"].encode("utf-8")
        elif "nestedArray" in change:
            out[name] = ("[" * change["nestedArray"] + "]" * change["nestedArray"]).encode()
    return out


def _reader(files: Any, lpk0: Any) -> Any:
    """replay.py's reader, restated: a v1/ path from the given files, LPK-0's record from the given bytes, else None."""
    def read(path: str) -> Any:
        if path.startswith(V1_DIR):
            return files.get(path[len(V1_DIR):])
        if path == LPK0_RECORD:
            return lpk0
        return None
    return read


def replay(model: Any, record: Any, vectors: Any, base: Any, lpk0: Any) -> dict:
    """replay.py's run over this era's bytes, with every model call through the model's check (its one public entry): the
    positive and the negatives as replay.py runs them; each validator vector as the conformance verdict of check over the
    bound record with the vector's instance and schema in place of the v1/ files (valid exactly when check does not refuse
    conformance, since check validates exactly those parsed values), and a mismatch when check refuses the shape or the
    keyword set, where it would not reach the validator."""
    bad = []
    got = model.check(record, _reader(base, lpk0))
    if got != vectors["positive"]["refusals"]:
        bad.append(("positive", got))
    for vector in vectors["negatives"]:
        got = model.check(_apply(record, vector["recordOps"]), _reader(_v1_files(base, vector["fileOverrides"]), lpk0))
        if got != vector["refusals"]:
            bad.append((vector["label"], got))
    instance, schema = json.loads(base[INSTANCE_NAME]), json.loads(base[SCHEMA_NAME])
    for vector in vectors["validatorVectors"]:
        files = dict(base)
        files[INSTANCE_NAME] = json.dumps(_apply(instance, vector["instanceOps"]), ensure_ascii=False).encode("utf-8")
        files[SCHEMA_NAME] = json.dumps(_apply(schema, vector["schemaOps"]), ensure_ascii=False).encode("utf-8")
        refusals = model.check(record, _reader(files, lpk0))
        verdict = None if SHAPE_REFUSAL in refusals or KEYWORD_REFUSAL in refusals else CONFORMANCE_REFUSAL not in refusals
        if verdict != vector["valid"]:
            bad.append((vector["label"], verdict))
    return {"positive": 1, "negatives": len(vectors["negatives"]), "validatorVectors": len(vectors["validatorVectors"]),
            "mismatches": bad}


def check_replay(result: Any) -> None:
    """The vectors replay with one positive, 28 negatives and 15 validator vectors, and no mismatch."""
    _bound(lambda: result == dict(REPLAY_COUNTS),
           "the vectors replay with one positive, 28 negatives and 15 validator vectors, and no mismatch")


def validate_contract(model: Any) -> None:
    """The four v1/ files and the binding's files rows; the source and reviews against the MANIFEST; A8's forward pin; the
    reference model over the binding; and the vectors' replay."""
    binding = _json(BINDING_PATH)
    files = {name: _verified(V1_DIR + name) for name in V1_NAMES}
    lpk0 = _verified(LPK0_RECORD)
    check_handoff(binding, files)
    check_source(binding, files["MANIFEST.json"])
    check_placeholder(binding, _json(STATUS_PATH)["predecessorPin"], lpk0, files[INSTANCE_NAME])
    check_model(model.check(binding, _reader(files, lpk0)))
    check_replay(replay(model, binding, _json(VECTORS_PATH), files, lpk0))


def check_registry(raw: Any, brief_raw: Any) -> None:
    """The registry is 261's merged file (by digest), unchanged, and holds exactly one series of this packet: its PACKET
    series, pinning the generic PACKET brief by the sha256 of the brief's bytes (no CONTRACT series)."""
    _bound(lambda: type(raw) is bytes and digest(raw) == REGISTRY_SHA256 and type(brief_raw) is bytes
           and [(entry["kind"], entry["series"], entry["path"], entry["sha256"], entry["version"])
                for entry in parse(raw)["briefs"] if entry["series"].startswith(NEW_PACKET + "/")]
           == [REGISTRY_ENTRY + (digest(brief_raw), 1)],
           "the registry is 261's, unchanged, with exactly this packet's PACKET series pinning its brief")


def validate_registry() -> None:
    """briefs.json and the generic PACKET brief, both unchanged since the base."""
    check_registry(_verified(REGISTRY_PATH), _verified(PACKET_BRIEF))


def check_gate_list(gate: Any) -> None:
    """The evolution surface record, run by its model from this era's bytes, derives 31 gate-material entries, each an
    exact path or a prefix (no under-plus-name entry is left in the derived list at this era)."""
    _bound(lambda: type(gate) is list and len(gate) == GATE_MATERIAL
           and all(type(entry) is dict and len(entry) == 1 and ("exact" in entry or "prefix" in entry)
                   for entry in gate),
           "the evolution surface record derives 31 exact or prefix gate entries")


def gate_paths(gate: list, paths: list) -> list:
    """The paths a gate entry matches: an exact path, or a path under a prefix, each compared lower-cased, which equals
    case-folding on this era's all-ASCII gate entries and changed paths (260's packet review r1's R1-2)."""
    return [path for path in paths
            if any(("exact" in entry and path.lower() == entry["exact"].lower())
                   or ("prefix" in entry and path.lower().startswith(entry["prefix"].lower())) for entry in gate)]


def check_gate_hits(gate: Any, changed: Any) -> None:
    """The derived gate check: the gate paths among the packet's changed files, by the record's gate entries, are none."""
    _bound(lambda: type(changed) is list and changed == sorted(changed) and gate_paths(gate, changed) == [],
           "the packet's changed files hold no gate path")


def validate_gate(es: Any) -> None:
    """The gate list derived from this era's evolution surface record against the packet's changed files."""
    gate = es.check(_json(SURFACE_RECORD))["gateMaterial"]
    check_gate_list(gate)
    record = authority()
    check_gate_hits(gate, sorted(set(record["changedFiles"]) | set(record["newFiles"])
                                 | {AUTHORITY_PATH, VALIDATOR_PATH, PACKET_PATH}))


def validate_linux_probe_interface() -> None:
    """Every reviewed byte first; then the freeze and the files this packet adds, the adoption, the contract under the
    reference model with the vectors' replay, the registry and the derived gate check; last, this layer's canonical
    hunks."""
    for path in ERA_SHA256:
        _verified(path)
    validate_files()
    validate_adoption()
    model, es = era_models()
    validate_contract(model)
    validate_registry()
    validate_gate(es)
    validate_canonical_hunks()


def _trim(at: int, removed: bytes, inserted: bytes) -> tuple[int, bytes, bytes]:
    head = 0
    while head < min(len(removed), len(inserted)) and removed[head] == inserted[head]:
        head += 1
    tail = 0
    while (tail < min(len(removed), len(inserted)) - head
           and removed[len(removed) - 1 - tail] == inserted[len(inserted) - 1 - tail]):
        tail += 1
    return at + head, removed[head:len(removed) - tail], inserted[head:len(inserted) - tail]


def canonical_hunks(after: bytes, before: bytes) -> tuple[tuple[int, bytes, bytes], ...]:
    """The canonical byte-minimal reverse hunks (record authorityHunks.algorithm) that turn after back into before."""
    current, previous = after.splitlines(keepends=True), before.splitlines(keepends=True)
    offsets = [0]
    for line in current:
        offsets.append(offsets[-1] + len(line))
    runs = []
    for tag, a, b, c, d in difflib.SequenceMatcher(None, current, previous, autojunk=False).get_opcodes():
        if tag == "equal":
            continue
        if b - a == d - c:
            runs += [_trim(offsets[a + i], current[a + i], previous[c + i]) for i in range(b - a)
                     if current[a + i] != previous[c + i]]
        else:
            runs.append(_trim(offsets[a], b"".join(current[a:b]), b"".join(previous[c:d])))
    merged: list[tuple[int, bytes, bytes]] = []
    for at, removed, inserted in runs:
        if merged and at <= merged[-1][0] + len(merged[-1][1]):
            prior_at, prior_removed, prior_inserted = merged[-1]
            merged[-1] = (prior_at, after[prior_at:at + len(removed)],
                          prior_inserted + after[prior_at + len(prior_removed):at] + inserted)
        else:
            merged.append((at, removed, inserted))
    return tuple(merged)


def check_canonical_hunks(path: str, rule: Any, after: Any) -> None:
    """Q-PERF40-4 for one path: the rule's hunks are the canonical byte-minimal ones, from this era's bytes."""
    require(type(after) is bytes and digest(after) == rule["afterSha256"], "unreviewed current source: " + path)
    before = _undo_this_layer(path, after)
    require(canonical_hunks(after, before) == rule["reverseHunks"], "canonical byte-minimal inverse hunks: " + path)


def validate_canonical_hunks() -> None:
    """Q-PERF40-4: every hunk of this layer's authority is the canonical byte-minimal one, from this era's bytes."""
    for path, rule in _PROJECTION_RULES.items():
        check_canonical_hunks(path, rule, reviewed_bytes(path))


def validate() -> None:
    record = authority()
    validator_raw = successor.historical_bytes(VALIDATOR_PATH, regular_bytes(VALIDATOR_PATH))
    literal = b'AUTHORITY_SHA256 = "' + AUTHORITY_SHA256.encode("ascii") + b'"'
    placeholder = b'AUTHORITY_SHA256 = "TO_BE_PINNED_AFTER_SOURCE_FREEZE"'
    require(validator_raw.count(literal) == 1
            and digest(validator_raw.replace(literal, placeholder))
            == record["validatorNormalizedSha256"], "linux probe interface validator drift")
    paths = sorted((ROOT / "task-packets").glob("*.yaml"))
    old = set(record["baselinePackets"])
    require(len(paths) == 269
            and {path.stem for path in paths} == old | {NEW_PACKET, successor.NEW_PACKET, successor.successor.NEW_PACKET, successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.successor.NEW_PACKET},
            "closed 269-packet catalog retaining the 262-packet checkpoint")
    packets = {}
    for path in paths:
        if path.stem in (successor.NEW_PACKET, successor.successor.NEW_PACKET, successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.successor.NEW_PACKET):
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
            "closed source-only linux-probe-interface packet and inherited commands")
    require(len(packet["allowedPaths"]) == len(set(packet["allowedPaths"]))
            and set(packet["allowedPaths"]) == set(record["changedFiles"])
            | set(record["newFiles"]) | {AUTHORITY_PATH, VALIDATOR_PATH,
                                         "task-packets/" + NEW_PACKET + ".yaml"},
            "unreviewed or omitted linux-probe-interface packet path")
    for path, rule in record["changedFiles"].items():
        current = successor.historical_bytes(path, regular_bytes(path))
        require(digest(current) == rule["afterSha256"]
                and digest(historical_bytes(path, current)) == rule["beforeSha256"],
                "unreviewed current source: " + path)
    for path, expected in record["newFiles"].items():
        require(digest(successor.historical_bytes(path, regular_bytes(path))) == expected,
                "new source drift: " + path)
    validate_linux_probe_interface()


if __name__ == "__main__":
    validate()
    print("Linux probe interface valid: 269 current specifications; 262-packet checkpoint and exact 261-packet predecessor; contract reviewed.")
