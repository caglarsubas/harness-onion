#!/usr/bin/env python3
"""Validate the MET-LIVE-002 probe-kit scope amendment (the CAMPAIGN_PROXY server side, the worker entry, the case recipes and the receipt candidates moved from R12's CONF-LIVE-003/004/005 to the operator-side probe kit; DATA_CHECK_ONLY) with the review-record brief registry rider, and the exact 260-to-259 projection."""
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
    import validate_linux_probe_kit_gate as successor
except ImportError:
    from scripts.safe_yaml import safe_load
    from scripts import validate_linux_probe_kit_gate as successor


ROOT = Path(__file__).resolve().parents[1]
AUTHORITY_PATH = "architecture/probe-kit-scope-authority.json"
AUTHORITY_SHA256 = "6725d384ebafd763b5feb294ffe4eafdd3548ec62d9fb83ddb13620e41aebc4a"
VALIDATOR_PATH = "scripts/validate_probe_kit_scope.py"
BASE_COMMIT = "b516619404e177893143dd37f19f8673a4173fba"
NEW_PACKET = "MET-LIVE-002"
PREVIOUS_PACKET = "MET-GOV-002"
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
            require(key not in result, "duplicate probe-kit-scope authority member")
            result[key] = value
        return result

    def no_constant(_value: str) -> Any:
        raise ValueError("nonfinite probe-kit-scope authority number")

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
        require(digest(raw) == AUTHORITY_SHA256, "probe kit scope history authority digest")
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
    }, "closed probe kit scope history authority")
    require(value["schemaVersion"] == "harness.planeon.ai/probe-kit-scope-authority/v1"
            and value["authorityPacket"] == NEW_PACKET
            and value["acceptedBase"] == BASE_COMMIT
            and type(value["baselinePackets"]) is dict
            and len(value["baselinePackets"]) == 259
            and NEW_PACKET not in value["baselinePackets"]
            and type(value["changedFiles"]) is dict
            and type(value["newFiles"]) is dict
            and _sha(value["packetSha256"])
            and _sha(value["validatorNormalizedSha256"]),
            "accepted 259-packet base")
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
    # An exact 259-era byte string is already older than the successor layer.
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


# MET-LIVE-002 (roadmap LINUX-PROBE-KIT-SCOPE, LPK-0; owner decisions Q-PK-2 "Move them (Recommended)", Q-LPK0-3,
# Q-LPK0-4 and the registry decision "Batch, carried by 260 (Recommended)"; the lane monitor's owner-delegated rulings,
# among them Q-LPK0-CAP, the adoptions c3 to c11, Q-260-1 (a), MON-260-READ (a), MON-260-TREE (a), MON-260-RIDER-DIR
# (a), MON-260-R1-1 and MON-260-R2-1) adopts the probe-kit scope amendment: the closed record
# architecture/probe-kit-scope/amendment.json, which moves the CAMPAIGN_PROXY server side, the worker entry, the ten
# case recipes and the unsigned receipt candidates from R12's CONF-LIVE-003/004/005 to the operator-side probe kit and
# keeps the KAP leg deferred and unowned, with its README, vectors, replay script, a standard-library reference model
# (scripts/probe_kit_scope.py), the kit's prose page and the redacted review history of its three design and two
# contract rounds (review-history-*, not review-round*.json records, with no merge authority). It also carries the
# owner-ruled review-record brief registry batch, the registry rider: five entries appended to
# architecture/review-record/briefs.json, each pinning one of the two generic briefs in architecture/review-briefs/ by
# sha256. Repository bytes and modes are read only through reviewed_bytes and reviewed_mode, so a later bridged
# successor projects its own edits away first; a path outside this era is refused before it is read, and every era file
# is bound by digest on every read. The record's base bytes are read git-free (MON-260-READ (a)): every path the record
# names is read from the tree and bound by the record's own sha256, and the three living catalogs 259 changed are
# rebuilt to their exact base bytes (this layer's own edits undone, then 259's recorded reverse hunks); the comparison
# with `git show <base>:<path>` runs in this layer's test. Each refusal is a pure check over the values read, so every
# one has a failing case on plain data. Checked here: the freeze (this packet edits no existing file but chain
# validators, tests, the three living catalogs and the registry); the files this packet adds (exactly its own, each
# once; mode 100644; no absolute local path); the adoption (the status record's closed shape and values; the six adopted
# files are the adopted subject's bytes, with amendment.json pinned; the five reviews bound to their published records
# and briefs; each brief redaction as stated; the adoptions c3 to c11 with their check digests; the oracle identity
# binding the oracle file with ruling KEEP); the registry rider (the registry is the base's with exactly the five ruled
# entries appended; the rider is among the changed files, and briefs.json is exactly the gate path among them, by the
# evolution surface record's 31 gate entries, lower-cased, which equals case-folding on this era's all-ASCII gate
# entries (packet review r1's R1-2)); and the reference model, executed from this era's verified bytes, returning no
# refusal for the adopted record over its base bytes, with the changed files less the rider and their gate paths (so no
# predecessor path is changed, S3-7). Last, this layer's own inverse hunks are the canonical byte-minimal ones,
# recomputed from its era's bytes (MET-PERF-040's carried rule).
CONTRACT_DIR = "architecture/probe-kit-scope"
AMENDMENT_PATH = CONTRACT_DIR + "/amendment.json"
VECTORS_PATH = CONTRACT_DIR + "/vectors.json"
README_PATH = CONTRACT_DIR + "/README.md"
REPLAY_PATH = CONTRACT_DIR + "/replay.py"
STATUS_PATH = CONTRACT_DIR + "/status.json"
ORACLE_IDENTITY_PATH = CONTRACT_DIR + "/oracle-identity.json"
MODEL_PATH = "scripts/probe_kit_scope.py"
DOCS_PATH = "docs/linux-probe-kit/README.md"
ORACLE_TEST = "tests/test_probe_kit_scope_oracle.py"
HEAD_TEST = "tests/test_probe_kit_scope.py"
PACKET_PATH = "task-packets/" + NEW_PACKET + ".yaml"
HISTORY = ("design-r1", "design-r2", "design-r3", "contract-r1", "contract-r2")
HISTORY_RECORDS = tuple(CONTRACT_DIR + "/review-history-%s.json" % name for name in HISTORY)
HISTORY_BRIEFS = tuple(CONTRACT_DIR + "/review-history-%s-brief.md" % name for name in HISTORY)
CONTRACT_FILES = (README_PATH, AMENDMENT_PATH, VECTORS_PATH, REPLAY_PATH, STATUS_PATH, ORACLE_IDENTITY_PATH) \
    + HISTORY_RECORDS + HISTORY_BRIEFS
REGISTRY_PATH = "architecture/review-record/briefs.json"
BRIEFS_DIR = "architecture/review-briefs"
PACKET_BRIEF = BRIEFS_DIR + "/REVIEW_BRIEF_PACKET.md"
CONTRACT_BRIEF = BRIEFS_DIR + "/REVIEW_BRIEF_CONTRACT.md"
NEW_FILES = CONTRACT_FILES + (MODEL_PATH, DOCS_PATH, ORACLE_TEST, PACKET_BRIEF, CONTRACT_BRIEF)
# The registry rider (Q-260-1 (a), MON-260-RIDER-DIR (a)): exactly these three paths, of which briefs.json alone is gate
# material; the five ruled entries (the monitor's exact series list), each pinning its generic brief by sha256.
REGISTRY_RIDER = (REGISTRY_PATH, PACKET_BRIEF, CONTRACT_BRIEF)
RIDER_GATE_PATHS = (REGISTRY_PATH,)
REGISTRY_ENTRIES = (("PACKET", "MET-LIVE-002/packet", PACKET_BRIEF), ("PACKET", "MET-GOV-003/packet", PACKET_BRIEF),
                    ("PACKET", "MET-LIVE-003/packet", PACKET_BRIEF), ("PACKET", "MET-LINUX-008/packet", PACKET_BRIEF),
                    ("CONTRACT", "MET-LINUX-008/contract", CONTRACT_BRIEF))
# briefs.json at this packet's base (259's era pin), reached through this layer's own inverse.
BASE_REGISTRY_SHA256 = "f389bae17a83924c873d29c2e13628b664f8586b47a59bf4093ac247928fc7c1"
SURFACE_RECORD = "architecture/evolution-surface/evolution-surface.json"
SURFACE_MODEL = "scripts/evolution_surface.py"
GATE_MATERIAL = 31
# The record's base reads (MON-260-READ (a)): the three living catalogs 259 changed are rebuilt from 259's authority.
PREDECESSOR_AUTHORITY = "architecture/review-record-authority.json"
LIVING_CATALOGS = ("docs/MASTER_DEVELOPMENT_PLAN.md", "docs/repositories/00-harness-engineering.md",
                   "task-packets/README.md")
RECORDED_PATHS = 279
# The record's base commit: the base bytes are its bytes, which this layer's test compares with git show (S3-17).
RECORD_BASE = "2043cc27883448e3ff030b7868110e295f32fe09"
# The adopted record, pinned (README "The layer"), and the adopted subject, by the digests status.json names.
AMENDMENT_SHA256 = "3de2d73e0413388ba286899cdd364c876dfbd869510c88537da8b1c91726ef8b"
ADOPTED_SUBJECT = MappingProxyType({'architecture/probe-kit-scope/amendment.json': '3de2d73e0413388ba286899cdd364c876dfbd869510c88537da8b1c91726ef8b',
 'architecture/probe-kit-scope/vectors.json': '0346be761c98eee78760324e8418b0653b4f3945385670d80ce3fecf9cbb840e',
 'architecture/probe-kit-scope/README.md': 'b2761f010983fbac4f84e6b7653a3a5a7c26dd7c758e1ab7ee1d5f1d94c6dd0c',
 'architecture/probe-kit-scope/replay.py': '2e88f95102afa2a6791719bbe7326356659dedac7fe6fb1151cccb7ce02c2b3b',
 'scripts/probe_kit_scope.py': 'ff2856f1cc3725f3d0f60087bd36446ab57e980063e03789f34c380e84a2f648',
 'docs/linux-probe-kit/README.md': '66d28efbb0b180fc1013fc669ad00fca1fd12a108f0cdfc8150cdf22a50e9241'})
# The status record written at adoption: its closed key sets and its values, restated.
STATUS_SCHEMA = "planeon.internal.probe-kit-scope-status/v1"
WORK_ITEM = "LINUX-PROBE-KIT-SCOPE (LPK-0, the probe-kit scope amendment)"
SLOT = 260
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
 'oracle',
 'registryRider',
 'slips',
 'nonClaims')
ADOPTION_KEYS = ("candidate", "ruling", "by", "date", "adoptionCheckSha256", "change")
ADOPTIONS = ({'candidate': 'c3',
  'ruling': 'MON-LPK0-ADOPT-C3',
  'by': 'the lane monitor, owner-delegated (2026-10-22)',
  'date': '2026-10-22',
  'adoptionCheckSha256': 'ed82fb16e9db4ee457a0c01ccd8d30cf740b2bee63f7d5d196b1f15cecebfaa2',
  'change': "the first adoption, after contract round 2's PASS_FOR_ADOPTION and its folded findings"},
 {'candidate': 'c4',
  'ruling': 'MON-LPK0-ADOPT-C4',
  'by': 'the lane monitor, owner-delegated (2026-10-22)',
  'date': '2026-10-23',
  'adoptionCheckSha256': '3d65ea33dec43967e5413e77d64fc0627cf3d9db33113f3d40d863f188ab5816',
  'change': "the model's strict-type pass after the D5a oracle's findings; vectors regenerated"},
 {'candidate': 'c5',
  'ruling': 'MON-LPK0-ADOPT-C5',
  'by': 'the lane monitor, owner-delegated (2026-10-22)',
  'date': '2026-10-23',
  'adoptionCheckSha256': '40426626d4712f967e5e71b16c59ff7fb014d62aec31d35068a2bb861918dd71',
  'change': "README wording only (the oracle's three c4 notes)"},
 {'candidate': 'c6',
  'ruling': 'MON-LPK0-ADOPT-C6',
  'by': 'the lane monitor, owner-delegated (2026-10-22)',
  'date': '2026-10-23',
  'adoptionCheckSha256': '51e5225fb0b4ee2701ca704ca3228760ae80ceb17afc84bfe055d9fcc6f3a060',
  'change': 'slot 261 -> 260 and the edge {MET-LIVE-002 after LINUX-HOST-AUTH-001} dropped (monitor slot '
            're-sequence 2026-10-23 (packet-readiness)); model pins and README slot texts follow; vectors '
            'unchanged'},
 {'candidate': 'c7',
  'ruling': 'MON-LPK0-ADOPT-C7',
  'by': 'the lane monitor, owner-delegated (2026-10-22)',
  'date': '2026-10-23',
  'adoptionCheckSha256': 'a4c118b1ebe23418a7a88a3f1b0a80b519fd0f46df32a199a920dec2bb86a57a',
  'change': "README errata only: 'the five predecessor rows' (was six), found by the D5a oracle on c6"},
 {'candidate': 'c8',
  'ruling': 'MON-LPK0-ADOPT-C8',
  'by': 'the lane monitor, owner-delegated (2026-10-22)',
  'date': '2026-10-23',
  'adoptionCheckSha256': '42ca6a334f2bc2ef1991872c1eaea15437b953f32f8c193c7e5126ff47582dd2',
  'change': 'README errata only: the registry-rider paragraph (Q-260-1 (a)) and the review-history sentence'},
 {'candidate': 'c9',
  'ruling': 'MON-260-RIDER-DIR (a)',
  'by': 'the lane monitor, owner-delegated (2026-10-22)',
  'date': '2026-10-23',
  'adoptionCheckSha256': '5e45b26643a9196c7aec3bd5d9d571a498defd919d4b402ab18b5fb12e2745de',
  'change': 'the two generic briefs move to architecture/review-briefs/ (byte-identical); the five registry '
            'entries point at the new paths; README errata: the registry-rider paragraph'},
 {'candidate': 'c10',
  'ruling': 'MON-260-R1-1',
  'by': 'the lane monitor, owner-delegated (2026-10-22)',
  'date': '2026-10-23',
  'adoptionCheckSha256': '16cb83d1c0db3ade3d4b4c53b9895155cd0453a17995f37bc9c67d8a89a5cf5f',
  'change': 'README errata: the head layer reads the base git-free (MON-260-READ (a)) and only its test uses '
            "git show; exact gate entries named; the model's docstring matches"},
 {'candidate': 'c11',
  'ruling': 'MON-260-R2-1',
  'by': 'the lane monitor, owner-delegated (2026-10-22)',
  'date': '2026-10-23',
  'adoptionCheckSha256': '6fba22e39650f900716bb9c940034ab75ff21f7acaebb1149be898b7569dc7a8',
  'change': "docstring and README errata: exact gate entries in the model's _check docstring; the undo-first "
            'step of the git-free base read in the README and the module docstring'})
STATUS_DESIGN = {'path': "DESIGN.rev3.md (kept with the lane's records)",
 'sha256': '80add650443ccf1a90a4d4d22075d7a38709a03d23471ca1b3f2f37937ac0ae9',
 'buildRules': 'BUILD_RULES.md c71a3345ccb93cbb2f8c5a29f11aa30048dd2ba412b73809d3a65ba4a2e9d48b'}
INDEPENDENT_REVIEWERS = 'SEPARATE_AGENTS_NOT_AUTHOR (one fresh agent per round)'
REVIEW_ROWS = ({'review': 'design round 1',
  'record': 'architecture/probe-kit-scope/review-history-design-r1.json',
  'recordSha256': 'b7ecb662b2d5bacee1cca76016bbd8516728ded0f895ee236e7317a0d7cc6c87',
  'verdict': 'CHANGES_REQUIRED',
  'subject': {'DESIGN.md rev 1': '181364e6bb6bacf65f2b645bce69088c69d4c6c74e0a7a8f495d10cc31825756'},
  'brief': 'architecture/probe-kit-scope/review-history-design-r1-brief.md',
  'briefReviewedSha256': '3b12843f4d9e52f2f94ee02b63206519c563ee3a61077c0ad27e2a5652b76312',
  'briefPublishedSha256': 'dc4b3eeb5eb2a66f41b50c8812d753d1ecd328a0efda65799cdd7d72af5e975e'},
 {'review': 'design round 2',
  'record': 'architecture/probe-kit-scope/review-history-design-r2.json',
  'recordSha256': 'aea54d76ce5dcdac78ad5e34934010b6d30f478a5fcb3b34396d06913dcef5fb',
  'verdict': 'CHANGES_REQUIRED',
  'subject': {'DESIGN.md rev 2': '4b490770e6efb6b681f044e630f7aabaf115c07f4e0332106007c3f9d515b892'},
  'brief': 'architecture/probe-kit-scope/review-history-design-r2-brief.md',
  'briefReviewedSha256': '453355467e66ac0b234cc55d954320b8b8cccdbfcc48c4094b0b96a00ae9a958',
  'briefPublishedSha256': '3a01113015057b1b212eb8dd87c514f59b19d80c9ebd6ed7ab87c3931da7a350'},
 {'review': 'design round 3',
  'record': 'architecture/probe-kit-scope/review-history-design-r3.json',
  'recordSha256': 'e59b44a608b963836bc4ec119e4d74d4448af8f5ac4f3a2db65ed0a1141b2c1b',
  'verdict': 'CHANGES_REQUIRED',
  'subject': {'DESIGN.md rev 3': '80add650443ccf1a90a4d4d22075d7a38709a03d23471ca1b3f2f37937ac0ae9'},
  'brief': 'architecture/probe-kit-scope/review-history-design-r3-brief.md',
  'briefReviewedSha256': '87677df76c2d115902d80fb1d66449c589d694f4192acb9ecbb7c7dea8b42945',
  'briefPublishedSha256': '7883e2b114e3960e70815b60c188cad0309208d8b634bcddcb0da5a5f84b3d53',
  'closure': "the design closed under Q-LPK0-CAP: round 3's findings became BUILD_RULES S3-1..S3-17 "
             '(BUILD_RULES.md c71a3345ccb93cbb2f8c5a29f11aa30048dd2ba412b73809d3a65ba4a2e9d48b, kept with '
             "the lane's records)"},
 {'review': 'contract round 1',
  'record': 'architecture/probe-kit-scope/review-history-contract-r1.json',
  'recordSha256': '3c78152585e6fa47ccfe5a41c9bf4ba9a4b8d898ee4286105f5bf4ff73c72cb0',
  'verdict': 'CHANGES_REQUIRED',
  'subject': 'candidate c1 (amendment 596fd442951d59c9ef4743eb3179bd73fdb6707c7eba71ff3f79c8e658bd072a)',
  'brief': 'architecture/probe-kit-scope/review-history-contract-r1-brief.md',
  'briefReviewedSha256': '6cea3e1b12ec641d7c552c390b24f69da6afeb1b6653225d8d28644922f82c25',
  'briefPublishedSha256': 'f12cb90ce3c069ab69ec725a375aafe584e9de6ef056b8f588adde0dd2eaf6ab'},
 {'review': 'contract round 2',
  'record': 'architecture/probe-kit-scope/review-history-contract-r2.json',
  'recordSha256': 'c043d6ed411dae183c5a21ebd4569de54c4205d383b6f1c5172c8610441767d5',
  'verdict': 'PASS_FOR_ADOPTION',
  'subject': 'candidate c2 (amendment ac6351bb9362eb6077da572db3745aa26d17df370f51fd7fd932b0bd0ce17140)',
  'brief': 'architecture/probe-kit-scope/review-history-contract-r2-brief.md',
  'briefReviewedSha256': 'b73ff9e9f80d36a7598af316fdad2a84e5a7509cdf614c6455807f30f0572a3e',
  'briefPublishedSha256': '65f7b9f18abe449e2feecb0d9c3950a660020c04462d452cf96817513fbef64c'})
REVIEW_HISTORY_NOTE = ('Published as review-history-<kind>-r<n>.json and -brief.md: redacted records from before review-record v2, '
 "not review-round*.json records, with no merge authority. This packet's merge authority is its v2 "
 'MET-LIVE-002/packet series (the monitor, 2026-10-23).')
REDACTION_KEYS = ("brief", "reviewedSha256", "publishedSha256", "substitutions")
SUBSTITUTIONS = ({'fromSha256': '1eedbfd71339d2596624d83bc7c0daa404c937e39dd76bf8af995e65b0181c67',
  'from': "the lane's CI state directory (home-relative)",
  'to': '<workspace>/',
  'count': 4},
 {'fromSha256': 'c955eccd4877ecd86f04647fba45d5d4709507b644e193fc7ac9a182d0459ec8',
  'from': "the session's temporary directory",
  'to': '<scratch>/',
  'count': 2})
STATUS_ORACLE = {'test': 'tests/test_probe_kit_scope_oracle.py',
 'sha256': 'f4a9772d55a08f4dcef1b18fbb6cc102388522418b48e6b372c49edb5374dd30',
 'identity': 'architecture/probe-kit-scope/oracle-identity.json',
 'result': '410/410 on c6; README-only changes since (c7, c8)'}
STATUS_RIDER = {'decision': 'owner, 2026-10-23: "Batch, carried by 260 (Recommended)"',
 'paths': ['architecture/review-record/briefs.json',
           'architecture/review-briefs/REVIEW_BRIEF_CONTRACT.md',
           'architecture/review-briefs/REVIEW_BRIEF_PACKET.md'],
 'entries': [{'kind': 'PACKET', 'series': 'MET-LIVE-002/packet'},
             {'kind': 'PACKET', 'series': 'MET-GOV-003/packet'},
             {'kind': 'PACKET', 'series': 'MET-LIVE-003/packet'},
             {'kind': 'PACKET', 'series': 'MET-LINUX-008/packet'},
             {'kind': 'CONTRACT', 'series': 'MET-LINUX-008/contract'}]}
SLIPS = ({'id': 'MON-LPK0-R1-SCRATCH',
  'ruling': 'KEEP, the lane monitor under owner delegation',
  'what': "design review round 1's reviewer deleted 12 scratch copies that held the legacy term"},
 {'id': 'MON-LPK0-R3-SLIPS',
  'ruling': 'KEEP, the lane monitor under owner delegation',
  'what': "design review round 3's reviewer deviations: legacy-term lines in scratch were deleted and the "
          'WORK folder checked'},
 {'id': 'MON-LPK0-CR1-CACHE',
  'ruling': 'KEEP, the lane monitor under owner delegation',
  'what': "contract review round 1's reviewer deleted a cache folder in its scratch"},
 {'id': 'MON-LPK0-PIN-RESTORE',
  'ruling': 'KEEP, the lane monitor under owner delegation',
  'what': "the author appended to the lane's decision record while contract round 2 pinned it, and restored "
          'the pinned bytes at once; the note moved to a .pending file'})
NON_CLAIMS = ('DATA_CHECK_ONLY: the model returns refusal texts, never a protected handle or native acceptance.',
 "No R12 file changes in this packet; R12's successor narrows CONF-LIVE-004 and 005 in its own packets.",
 'The kit directory itself is classified by MET-GOV-003 (slot 261), not here.')
ORACLE_REF = ('MON-LPK0-ORACLE-KEEP; disclosed interruptions: a 429 stop and resume, and the slot/edge re-derivation '
 'resume after MON-LPK0-ADOPT-C6')
# Every file this era's check reads, with its digest: the files this packet adds, the registry, the evolution surface
# record and its model, and 259's authority (for the living catalogs' base bytes).
ERA_SHA256 = MappingProxyType({
    "architecture/evolution-surface/evolution-surface.json": "b1759fe4bae0d9dc111f0c4ca3cc23e891cf89d572b73929ee01f5ec7616a277",
    "architecture/probe-kit-scope/README.md": "b2761f010983fbac4f84e6b7653a3a5a7c26dd7c758e1ab7ee1d5f1d94c6dd0c",
    "architecture/probe-kit-scope/amendment.json": "3de2d73e0413388ba286899cdd364c876dfbd869510c88537da8b1c91726ef8b",
    "architecture/probe-kit-scope/oracle-identity.json": "772c4207243d8d52e15d41f1b8cd8b494b37fab5633796b54be90593cb195fd9",
    "architecture/probe-kit-scope/replay.py": "2e88f95102afa2a6791719bbe7326356659dedac7fe6fb1151cccb7ce02c2b3b",
    "architecture/probe-kit-scope/review-history-contract-r1-brief.md": "f12cb90ce3c069ab69ec725a375aafe584e9de6ef056b8f588adde0dd2eaf6ab",
    "architecture/probe-kit-scope/review-history-contract-r1.json": "3c78152585e6fa47ccfe5a41c9bf4ba9a4b8d898ee4286105f5bf4ff73c72cb0",
    "architecture/probe-kit-scope/review-history-contract-r2-brief.md": "65f7b9f18abe449e2feecb0d9c3950a660020c04462d452cf96817513fbef64c",
    "architecture/probe-kit-scope/review-history-contract-r2.json": "c043d6ed411dae183c5a21ebd4569de54c4205d383b6f1c5172c8610441767d5",
    "architecture/probe-kit-scope/review-history-design-r1-brief.md": "dc4b3eeb5eb2a66f41b50c8812d753d1ecd328a0efda65799cdd7d72af5e975e",
    "architecture/probe-kit-scope/review-history-design-r1.json": "b7ecb662b2d5bacee1cca76016bbd8516728ded0f895ee236e7317a0d7cc6c87",
    "architecture/probe-kit-scope/review-history-design-r2-brief.md": "3a01113015057b1b212eb8dd87c514f59b19d80c9ebd6ed7ab87c3931da7a350",
    "architecture/probe-kit-scope/review-history-design-r2.json": "aea54d76ce5dcdac78ad5e34934010b6d30f478a5fcb3b34396d06913dcef5fb",
    "architecture/probe-kit-scope/review-history-design-r3-brief.md": "7883e2b114e3960e70815b60c188cad0309208d8b634bcddcb0da5a5f84b3d53",
    "architecture/probe-kit-scope/review-history-design-r3.json": "e59b44a608b963836bc4ec119e4d74d4448af8f5ac4f3a2db65ed0a1141b2c1b",
    "architecture/probe-kit-scope/status.json": "7682567a79bc01269382603e1cea205a79485d4d035bbe6ef09d5da7cba42228",
    "architecture/probe-kit-scope/vectors.json": "0346be761c98eee78760324e8418b0653b4f3945385670d80ce3fecf9cbb840e",
    "architecture/review-briefs/REVIEW_BRIEF_CONTRACT.md": "1f09d23451bf265e32e44742ca362dabf5a1090c2208c1349cbf491670798aec",
    "architecture/review-briefs/REVIEW_BRIEF_PACKET.md": "6dcff68d7e6b01823f1740063e94910edcc159a71a6ee803f1b66c62fd06e274",
    "architecture/review-record-authority.json": "4372a77b18dae5ac2a8052ebc6c9d8cbf8e6f0552895cf05e905d634e36bd878",
    "architecture/review-record/briefs.json": "d359813a0eab9323628d9dc051af40b45e0f643fbea496dd906e8e8d6f964e44",
    "docs/linux-probe-kit/README.md": "66d28efbb0b180fc1013fc669ad00fca1fd12a108f0cdfc8150cdf22a50e9241",
    "scripts/evolution_surface.py": "f38fa6d00ec5fbbbcab8ff01d0e56824e805327b872dc1e23e579e522a681fd9",
    "scripts/probe_kit_scope.py": "ff2856f1cc3725f3d0f60087bd36446ab57e980063e03789f34c380e84a2f648",
    "tests/test_probe_kit_scope_oracle.py": "f4a9772d55a08f4dcef1b18fbb6cc102388522418b48e6b372c49edb5374dd30",
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
    require(expected is not None, "MET-LIVE-002 reviewed bytes are bound: " + str(path))
    require(type(raw) is bytes and digest(raw) == expected, "unreviewed LINUX-PROBE-KIT-SCOPE source: " + path)
    return raw


def _verified(path: str) -> bytes:
    """reviewed_bytes, checked against its era digest on every read; a path outside the era is refused before it is
    read."""
    require(type(path) is str and path in ERA_SHA256, "MET-LIVE-002 reviewed bytes are bound: " + str(path))
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
    """(the probe-kit scope model, the evolution surface model), each executed from this era's verified bytes."""
    return (_era_model(MODEL_PATH, "_met_live_002_probe_kit_scope"),
            _era_model(SURFACE_MODEL, "_met_live_002_evolution_surface"))


def check_freeze(changed: Any) -> None:
    """This packet edits no existing file but chain validators (scripts/validate_*.py, one level deep), tests, the three
    living catalogs and the registry: no model, no earlier contract or record and no conftest change."""
    for path in list(changed):
        require(type(path) is str and path not in ("conftest.py", "tests/conftest.py")
                and ((path.startswith("scripts/validate_") and path.endswith(".py") and path.count("/") == 1)
                     or path.startswith("tests/") or path in LIVING_CATALOGS or path == REGISTRY_PATH),
                "this packet edits only chain validators, tests, the three living catalogs and the registry: "
                + str(path))


def check_new_files(added: Any) -> None:
    """The packet adds exactly the contract's files, the model, the kit's page, the oracle test, the two generic briefs
    and the layer's test, each once."""
    _bound(lambda: len(set(NEW_FILES)) == len(NEW_FILES) and type(added) is list
           and sorted(added) == sorted(NEW_FILES + (HEAD_TEST,)),
           "this packet adds exactly its contract files, model, page, oracle test, generic briefs and layer test, "
           "each once")


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
    """The status record's closed shape and values: LINUX-PROBE-KIT-SCOPE adopted as MET-LIVE-002 at slot 260 on this
    era's base, its design and its build rules, its review history note, oracle row, registry rider, slips and
    non-claims as adopted."""
    _bound(lambda: type(status) is dict and tuple(status) == STATUS_KEYS and status["schemaVersion"] == STATUS_SCHEMA
           and status["workItem"] == WORK_ITEM and status["packet"] == NEW_PACKET and type(status["slot"]) is int
           and status["slot"] == SLOT and status["status"] == "ADOPTED" and status["baseMain"] == BASE_COMMIT
           and status["design"] == STATUS_DESIGN and status["independentReviewers"] == INDEPENDENT_REVIEWERS
           and status["reviewHistoryNote"] == REVIEW_HISTORY_NOTE and status["oracle"] == STATUS_ORACLE
           and status["registryRider"] == STATUS_RIDER and status["slips"] == list(SLIPS)
           and status["nonClaims"] == list(NON_CLAIMS), "adopted LINUX-PROBE-KIT-SCOPE status")


def check_adoptions(adoptions: Any) -> None:
    """The adoptions run c3 to c11 in order, each with its ruling, date, change and ADOPTION_CHECK digest."""
    _bound(lambda: type(adoptions) is list and [row["candidate"] for row in adoptions] == ["c%d" % n for n in range(3, 12)]
           and all(type(row) is dict and tuple(row) == ADOPTION_KEYS for row in adoptions)
           and adoptions == list(ADOPTIONS),
           "the adoptions run c3 to c11 with their rulings and ADOPTION_CHECK digests")


def check_subject(subject: Any, files: Any) -> None:
    """The six adopted files are the adopted subject's bytes, by the digests status.json names."""
    _bound(lambda: type(subject) is dict and tuple(subject) == tuple(ADOPTED_SUBJECT) and subject == dict(ADOPTED_SUBJECT),
           "status.json names the adopted subject by digest")
    for path in ADOPTED_SUBJECT:
        require(type(files) is dict and type(files.get(path)) is bytes and digest(files[path]) == ADOPTED_SUBJECT[path],
                "the adopted files are the adopted subject's bytes: " + path)


def check_pin(raw: Any) -> None:
    """amendment.json is the adopted record this layer pins by sha256 (README "The layer"), so a dropped or added row
    also fails at verify time."""
    require(type(raw) is bytes and digest(raw) == AMENDMENT_SHA256, "the layer pins the adopted amendment.json")


def check_review_lists(status: Any) -> None:
    """status.json records every review and every brief redaction, one each."""
    _bound(lambda: type(status["reviews"]) is list and len(status["reviews"]) == len(REVIEW_ROWS)
           and type(status["briefRedactions"]) is list and len(status["briefRedactions"]) == len(REVIEW_ROWS),
           "every review and brief redaction is recorded")


def check_review(number: int, row: Any, record_raw: Any, brief_raw: Any) -> None:
    """Review `number` is its row as adopted, bound by sha256 to its published record, whose verdict is the row's, and to
    its published brief."""
    _bound(lambda: 1 <= number <= len(REVIEW_ROWS) and row == REVIEW_ROWS[number - 1]
           and tuple(row) == tuple(REVIEW_ROWS[number - 1])
           and row["record"] == HISTORY_RECORDS[number - 1] and row["brief"] == HISTORY_BRIEFS[number - 1]
           and type(record_raw) is bytes and digest(record_raw) == row["recordSha256"]
           and parse(record_raw)["verdict"] == row["verdict"]
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
    """The oracle identity binds the oracle file's sha256 with ruling KEEP and its ref, and status.json names the same
    file and digest (check_tree checks the identity in full, in the suite)."""
    _bound(lambda: type(oracle_raw) is bytes
           and (lambda identity: identity["file"] == {"path": ORACLE_TEST, "sha256": digest(oracle_raw)}
                and identity["ruling"]["decision"] == "KEEP" and identity["ruling"]["ref"] == ORACLE_REF)(
               parse(identity_raw))
           and oracle_row["test"] == ORACLE_TEST and oracle_row["identity"] == ORACLE_IDENTITY_PATH
           and oracle_row["sha256"] == digest(oracle_raw),
           "the oracle identity binds the oracle file, with ruling KEEP")


def validate_adoption() -> None:
    """The status record, the adopted files, every review with its record and brief, every brief redaction, the
    adoptions and the oracle identity."""
    status = _json(STATUS_PATH)
    check_status(status)
    check_adoptions(status["adoptions"])
    check_subject(status["adoptedSubject"], {path: _verified(path) for path in ADOPTED_SUBJECT})
    check_pin(_verified(AMENDMENT_PATH))
    check_review_lists(status)
    for number, row in enumerate(status["reviews"], 1):
        brief = _verified(HISTORY_BRIEFS[number - 1])
        check_review(number, row, _verified(HISTORY_RECORDS[number - 1]), brief)
        check_redaction(number, status["briefRedactions"][number - 1], row, brief)
    check_oracle_identity(_verified(ORACLE_IDENTITY_PATH), _verified(ORACLE_TEST), status["oracle"])


def check_registry(raw: Any, base_raw: Any, briefs: Any) -> None:
    """The registry is the base's (by digest) with exactly the five ruled entries appended, each pinning its generic brief
    by the sha256 of the brief's bytes; its schema and kinds are unchanged."""
    _bound(lambda: type(base_raw) is bytes and digest(base_raw) == BASE_REGISTRY_SHA256
           and (lambda registry, base: tuple(registry) == tuple(base)
                and registry["schemaVersion"] == base["schemaVersion"] and registry["kinds"] == base["kinds"]
                and registry["briefs"] == base["briefs"] + [
                    {"kind": kind, "series": series, "path": path, "sha256": digest(briefs[path]), "version": 1}
                    for kind, series, path in REGISTRY_ENTRIES])(parse(raw), parse(base_raw)),
           "the registry is the base's with exactly the five ruled entries appended, each pinning its brief")


def validate_registry() -> None:
    """briefs.json against its base bytes (this layer's own inverse) and the two generic briefs."""
    raw = _verified(REGISTRY_PATH)
    check_registry(raw, _undo_this_layer(REGISTRY_PATH, raw),
                   {path: _verified(path) for path in (PACKET_BRIEF, CONTRACT_BRIEF)})


def check_gate_list(gate: Any) -> None:
    """The evolution surface record, run by its model from this era's bytes, derives 31 gate-material entries, each an
    exact path or a prefix (no under-plus-name entry is left in the derived list at this era)."""
    _bound(lambda: type(gate) is list and len(gate) == GATE_MATERIAL
           and all(type(entry) is dict and len(entry) == 1 and ("exact" in entry or "prefix" in entry)
                   for entry in gate),
           "the evolution surface record derives 31 exact or prefix gate entries")


def gate_paths(gate: list, paths: list) -> list:
    """The paths a gate entry matches: an exact path, or a path under a prefix, each compared lower-cased, which equals
    case-folding on this era's all-ASCII gate entries and changed paths (packet review r1's R1-2)."""
    return [path for path in paths
            if any(("exact" in entry and path.lower() == entry["exact"].lower())
                   or ("prefix" in entry and path.lower().startswith(entry["prefix"].lower())) for entry in gate)]


def check_rider(changed: Any, gate: Any) -> None:
    """The registry rider is among the packet's changed files, and briefs.json is exactly the gate path among them."""
    _bound(lambda: set(REGISTRY_RIDER) <= set(changed) and gate_paths(gate, changed) == list(RIDER_GATE_PATHS),
           "the registry rider is among the changed files, and briefs.json is exactly the gate path among them")


def recorded_sha256(record: Any) -> dict:
    """Every path the record names (crossInputs, amends, supersedes, notAmended and the inventory) with its recorded
    sha256, one per path."""
    found: dict[str, str] = {}
    for row in (list(record["crossInputs"]) + list(record["amends"]) + list(record["supersedes"])
                + list(record["notAmended"]["pinned"]) + list(record["notAmended"]["named"])
                + list(record["inventory"]["files"])):
        require(found.get(row["path"], row["sha256"]) == row["sha256"], "one recorded sha256 per path: " + row["path"])
        found[row["path"]] = row["sha256"]
    return found


def check_living(rules: Any, recorded: Any) -> None:
    """The record names this many paths, and the ones 259's authority changed are exactly the three living catalogs."""
    _bound(lambda: len(recorded) == RECORDED_PATHS
           and sorted(path for path in recorded if path in rules) == sorted(LIVING_CATALOGS),
           "the recorded paths 259 changed are exactly the three living catalogs")


def _rebuilt(raw: Any, rule: Any) -> Any:
    """raw with 259's recorded reverse hunks applied; None when raw is not 259's era bytes or the result is not its
    base bytes."""
    try:
        if digest(raw) != rule["afterSha256"]:
            return None
        before = _inverse(raw, tuple((hunk["at"], _base64(hunk["removeBase64"]), _base64(hunk["insertBase64"]))
                                     for hunk in rule["reverseHunks"]))
    except (KeyError, TypeError, AttributeError, IndexError, ValueError):
        return None
    return before if digest(before) == rule["beforeSha256"] else None


def base_bytes(path: str, raw: Any, rule: Any) -> bytes:
    """A recorded path's bytes at the record's base, from this era's bytes (MON-260-READ (a)): this layer's own edits
    undone; then, for a path 259 changed, 259's recorded reverse hunks applied. Never a git read."""
    raw = _undo_this_layer(path, raw)
    if rule is None:
        return raw
    before = _rebuilt(raw, rule)
    require(before is not None, "a living catalog is rebuilt to its base bytes: " + path)
    return before


def check_base_reads(recorded: Any, reads: Any) -> None:
    """Every recorded path is read once, and its base bytes are the record's sha256."""
    require(type(reads) is dict and sorted(reads) == sorted(recorded), "every recorded path is read once")
    for path in sorted(recorded):
        require(type(reads[path]) is bytes and digest(reads[path]) == recorded[path],
                "the recorded base bytes are bound: " + path)


def check_model(refusals: Any) -> None:
    """The reference model returns no refusal for the adopted record."""
    _bound(lambda: refusals == [], "the reference model returns no refusal for the adopted record")


def validate_scope(models: tuple) -> None:
    """The gate list and the registry rider; then the reference model over the record's base bytes, read git-free from
    this era's bytes, with the packet's changed files less the rider and their gate paths."""
    model, es = models
    gate = es.check(_json(SURFACE_RECORD))["gateMaterial"]
    check_gate_list(gate)
    record = authority()
    changed = sorted(set(record["changedFiles"]) | set(record["newFiles"]) | {AUTHORITY_PATH, VALIDATOR_PATH, PACKET_PATH})
    check_rider(changed, gate)
    scope = [path for path in changed if path not in REGISTRY_RIDER]
    amendment = _json(AMENDMENT_PATH)
    recorded = recorded_sha256(amendment)
    rules = parse(_verified(PREDECESSOR_AUTHORITY))["changedFiles"]
    check_living(rules, recorded)
    reads = {path: base_bytes(path, reviewed_bytes(path), rules.get(path)) for path in sorted(recorded)}
    check_base_reads(recorded, reads)
    check_model(model.check(amendment, reads.get, scope, gate_paths(gate, scope)))


def validate_probe_kit_scope() -> None:
    """Every reviewed byte first; then the freeze and the files this packet adds, the adoption, the registry, the
    registry rider and the reference model over the record's base bytes; last, this layer's canonical hunks."""
    for path in ERA_SHA256:
        _verified(path)
    validate_files()
    validate_adoption()
    validate_registry()
    validate_scope(era_models())
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
            == record["validatorNormalizedSha256"], "probe kit scope validator drift")
    paths = sorted((ROOT / "task-packets").glob("*.yaml"))
    old = set(record["baselinePackets"])
    require(len(paths) == 267
            and {path.stem for path in paths} == old | {NEW_PACKET, successor.NEW_PACKET, successor.successor.NEW_PACKET, successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.successor.NEW_PACKET},
            "closed 267-packet catalog retaining the 260-packet checkpoint")
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
            "closed source-only probe-kit-scope packet and inherited commands")
    require(len(packet["allowedPaths"]) == len(set(packet["allowedPaths"]))
            and set(packet["allowedPaths"]) == set(record["changedFiles"])
            | set(record["newFiles"]) | {AUTHORITY_PATH, VALIDATOR_PATH,
                                         "task-packets/" + NEW_PACKET + ".yaml"},
            "unreviewed or omitted probe-kit-scope packet path")
    for path, rule in record["changedFiles"].items():
        current = successor.historical_bytes(path, regular_bytes(path))
        require(digest(current) == rule["afterSha256"]
                and digest(historical_bytes(path, current)) == rule["beforeSha256"],
                "unreviewed current source: " + path)
    for path, expected in record["newFiles"].items():
        require(digest(successor.historical_bytes(path, regular_bytes(path))) == expected,
                "new source drift: " + path)
    validate_probe_kit_scope()


if __name__ == "__main__":
    validate()
    print("Probe kit scope valid: 267 current specifications; 260-packet checkpoint and exact 259-packet predecessor; contract reviewed.")
