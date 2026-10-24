#!/usr/bin/env python3
"""Validate the MET-ENFORCE-036 compiled filter programs v3 and edge record v6 and the exact 249-to-248 projection."""
from __future__ import annotations

import ast
import base64
import binascii
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
    import validate_w03_plan_amend_3 as successor
except ImportError:
    from scripts.safe_yaml import safe_load
    from scripts import validate_w03_plan_amend_3 as successor


ROOT = Path(__file__).resolve().parents[1]
AUTHORITY_PATH = "architecture/compiled-filter-programs-v3-authority.json"
AUTHORITY_SHA256 = "a0bf122ee176cac7d519ee1f07a14b05300ba82c7beae3761a7bb43f5ccb1586"
VALIDATOR_PATH = "scripts/validate_compiled_filter_programs_v3.py"
BASE_COMMIT = "f4bb0000df9ec4bdaac54d3e6488d691e2001f28"
NEW_PACKET = "MET-ENFORCE-036"
PREVIOUS_PACKET = "MET-ENFORCE-035"
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
            require(key not in result, "duplicate compiled-filter-programs-v3 authority member")
            result[key] = value
        return result

    def no_constant(_value: str) -> Any:
        raise ValueError("nonfinite compiled-filter-programs-v3 authority number")

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
        require(digest(raw) == AUTHORITY_SHA256, "compiled filter programs v3 history authority digest")
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
    }, "closed compiled filter programs v3 history authority")
    require(value["schemaVersion"] == "harness.planeon.ai/compiled-filter-programs-v3-authority/v1"
            and value["authorityPacket"] == NEW_PACKET
            and value["acceptedBase"] == BASE_COMMIT
            and type(value["baselinePackets"]) is dict
            and len(value["baselinePackets"]) == 248
            and NEW_PACKET not in value["baselinePackets"]
            and type(value["changedFiles"]) is dict
            and type(value["newFiles"]) is dict
            and _sha(value["packetSha256"])
            and _sha(value["validatorNormalizedSha256"]),
            "accepted 248-packet base")
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
    # An exact 248-era byte string is already older than the successor layer.
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


# MET-ENFORCE-036 (roadmap SECCOMP-OBSERVER-LISTENER, packet 2; the lane monitor's owner-delegated Q-SOL-1 (a) and F-SOL-1,
# 2026-10-17, as HS53's amendment record holds them, and Q-P2-1..4 (a), 2026-10-18) publishes the compiled seccomp filter
# programs v3 (architecture/compiled-filter-programs-v3/): OBSERVER's programs republished from the adopted seccomp
# allowlists v5 on both architectures, an index of all fourteen v5 programs (two here, the other twelve at the paths
# MET-ENFORCE-029's index lists), the publisher scripts/compiled_filter_programs_v3.py, the operator -> harness-engineering
# edge record v6 (v5's 54 rows plus the two programs, registered for R10's HE-004-I01 under
# host-enforcement/contracts/seccomp-v5/) and a status record that adopts them after independent review and discharges
# HS53's O-PROGRAMS-V3-OBSERVER and allowlists v5's open republication item. The compiled filter programs v1 and v2 with
# their publishers, edge records v1 to v5 and EDGE-2, allowlists v3 to v5 with their models, HS43, HS53 and the repository
# registry stay byte-identical. Repository bytes are read only through reviewed_bytes, and the contract's file modes and
# directory listing only through reviewed_mode and reviewed_tree, so a later bridged successor projects its own edits away
# first. Every reviewed file of this era, and every input it is checked against, is bound by digest before anything is
# parsed and on every later read; the v5 model and safe_yaml are executed from this era's bytes, never imported. The
# publisher's claims are checked here independently of it, together with what it does not check: all fourteen programs
# are the v5 model's output with v5's digests and lengths; the twelve programs of the other roles are byte-identical to
# the files MET-ENFORCE-029's index lists; each OBSERVER program is the earlier program with exactly the four-instruction
# bind/listen pair and the eleven-instruction accept4 block inserted; every v5 OBSERVER decision vector replays through
# the published bytes; the index, edge record v6, both README status lines, the status record, the review binding and the
# contract's closed file set and modes are restated here; no new contract file holds an absolute local path; and this
# layer's own inverse hunks are canonical.
CONTRACT_DIR = "architecture/compiled-filter-programs-v3/"
PROGRAMS_DIR = CONTRACT_DIR + "programs/"
INDEX_PATH = CONTRACT_DIR + "index.json"
STATUS_PATH = CONTRACT_DIR + "status.json"
README_PATH = CONTRACT_DIR + "README.md"
REVIEW_BRIEF_PATH = CONTRACT_DIR + "REVIEW_BRIEF.md"
PUBLISHER = "scripts/compiled_filter_programs_v3.py"
EDGES_DIR = "architecture/artifact-edges/"
V5_EDGE = EDGES_DIR + "operator-harness-engineering-v5.json"
V6_EDGE = EDGES_DIR + "operator-harness-engineering-v6.json"
V6_README = EDGES_DIR + "README-v6.md"
V5_MODEL = "scripts/seccomp_allowlists_v5.py"
V5_DIR = "architecture/seccomp-allowlists-v5/"
V5_SOURCES = (V5_MODEL, V5_DIR + "allowlists.json", V5_DIR + "syscalls.json", V5_DIR + "vectors.json")
V5_STATUS = V5_DIR + "status.json"
V5_PACKET = "MET-ENFORCE-035"
V5_COMMIT = "f4bb0000df9ec4bdaac54d3e6488d691e2001f28"
# The SHA-256 of each v5 source the publisher pins (MET-ENFORCE-035's merged bytes).
V5_SOURCE_SHA256 = {'architecture/seccomp-allowlists-v5/allowlists.json': '879909a86037b153a951770b4a47a8c075364fbd7cf9a44405537807621b55a8',
 'architecture/seccomp-allowlists-v5/syscalls.json': 'fe9a603e780b576f666a219da119eedad5271a675998aba2d6d581fb53ebac07',
 'architecture/seccomp-allowlists-v5/vectors.json': '4539410a9bb66e2aca62931567253c3c70b382672cc2b8f8207d4ea3d4661ecd',
 'scripts/seccomp_allowlists_v5.py': 'fc57bb40f4f2537005e46689d9fc39a0dd98d4ebe141f9aace961e9520f1e0a7'}
PREDECESSOR_DIR = "architecture/compiled-filter-programs-v2/"
PREDECESSOR_INDEX = PREDECESSOR_DIR + "index.json"
PREDECESSOR_INDEX_SHA256 = "59581bbfb75e81f364382833b94be6c42f4e2a658c49711b4e72712434ef69cb"
PREDECESSOR_PACKET = "MET-ENFORCE-029"
FIRST_DIR = "architecture/compiled-filter-programs/"
HS53_RECORD = "architecture/host-interface-amendment-hs53/amendment.json"
HS53_STATUS = "architecture/host-interface-amendment-hs53/status.json"
REPOSITORIES = "architecture/repositories.yaml"
SAFE_YAML = "scripts/safe_yaml.py"
# The nine contract files in the status record's order; the review records joined them at adoption. Each is a regular
# file of git mode 100644, and the contract directory holds nothing else.
CONTRACT_FILES = (README_PATH, REVIEW_BRIEF_PATH, INDEX_PATH, PROGRAMS_DIR + "OBSERVER.aarch64.bpf",
                  PROGRAMS_DIR + "OBSERVER.x86_64.bpf", STATUS_PATH, V6_README, V6_EDGE, PUBLISHER)
# (round, record, subject commit, subject tree, verdict, findings as (id, severity)), in order.
ROUNDS = (
    (1, 'architecture/compiled-filter-programs-v3/review-round1.json', 'c79873ee31e64fbf6cdf6dbc2a90b07b6706246d', 'f5bc4bc953ad22797f49bdf2be75c8632ffdebcf', 'CHANGES_REQUIRED', (('P3R1-1', 'MINOR'), ('P3R1-2', 'NOTE'), ('P3R1-3', 'NOTE'), ('P3R1-4', 'NOTE'), ('P3R1-5', 'NOTE'), ('P3R1-6', 'NOTE'))),
    (2, 'architecture/compiled-filter-programs-v3/review-round2.json', 'e52a884d9e4564652c1f034b84ab391a661b01ed', '5a35eee8f8e81d0a079c300508ee9a6b0bab3b89', 'PASS_FOR_SOURCE_PUBLICATION', (('P3R2-1', 'NOTE'), ('P3R2-2', 'NOTE'))),
)
REVIEW_RECORDS = tuple(row[1] for row in ROUNDS)
NEW_FILES = CONTRACT_FILES + REVIEW_RECORDS
CONTRACT_TREE = frozenset({path for path in NEW_FILES if path.startswith(CONTRACT_DIR)} | {PROGRAMS_DIR[:-1]})
# MET-ENFORCE-036 is written in exactly these files.
NAMING_FILES = frozenset(['architecture/artifact-edges/README-v6.md',
 'architecture/artifact-edges/operator-harness-engineering-v6.json',
 'architecture/compiled-filter-programs-v3/README.md',
 'architecture/compiled-filter-programs-v3/review-round1.json',
 'architecture/compiled-filter-programs-v3/status.json',
 'scripts/compiled_filter_programs_v3.py'])
ARCHES = ("aarch64", "x86_64")
ROLES = ("BROKER", "EFFECT_GATE", "HOST_CONTAINMENT", "OBSERVER", "POLICY_WRITER", "SERVER", "WORKER")
ROLE = "OBSERVER"
# v5's instruction count (aarch64, x86_64) and SHA-256 per program; only OBSERVER's differ from v4's.
PROGRAM_LENGTHS = {"BROKER": (311, 326), "EFFECT_GATE": (189, 200), "HOST_CONTAINMENT": (130, 141), "OBSERVER": (242, 253),
                   "POLICY_WRITER": (115, 126), "SERVER": (261, 276), "WORKER": (172, 187)}
PROGRAM_SHA256 = {'BROKER': ('bc9c5a3797277ca753b5168e8e55132e1878fed2a726de361fd7d80e0fababf8',
            '95221bd0db753aa22ead2eb49eeac8dae3d24c3dad72811de86c9392f4894dcc'),
 'EFFECT_GATE': ('8de80a2b597b84d9f5ace818e76ef15d4b15a5b02013bb479ca4fdf73df3d044',
                 '4e516f1682098c90edd568f8f214d3de01b404a2c144104596fc4e3262f6e7a3'),
 'HOST_CONTAINMENT': ('d9d57ecb4919ad453684be62b6e2b65c9818033c47291e8e7240f7c2224880eb',
                      'd0d0db066e8942bbe987bd89a8441ab4e84b1cb9933b3bad24d8fb6eb0a51292'),
 'OBSERVER': ('887bf07824d7c1e6ec6db991473935d31500e0c78fac345058972a0f777ad184',
              'a20d2a956393b3af72799eaad5fa2c4a3cd82f38bf3842c0dea7c42012e525b9'),
 'POLICY_WRITER': ('e3bf65e0ff60d6766eac92672ad21a3c34097e183f03de416c9ad2ba50d71a5b',
                   '0f690b0e2f18b1b092bc42f4042dc334cafa3aae81fb96851f569ba71f20d1bf'),
 'SERVER': ('a1bcb2de10f5a54d32578d9f26e3d7db69b0cfad8d868feea1914585fbb7f05a',
            '2e7af1da50b7d5df3cdcf8c18eb545f4972b2309b68d9eecba2e5f6ba5d1d8a7'),
 'WORKER': ('cc04a4710495d3794b0d295613a2f2bd330524a328cb6963a819565bac2acb40',
            '5616c9099324e441674f8e589b6c705ae95f6a4a697f10e761565d0735689d45')}
# The earlier OBSERVER programs (MET-ENFORCE-025's, which MET-ENFORCE-029's index lists), into which v5's rules insert.
EARLIER_LENGTHS = {"aarch64": 227, "x86_64": 238}
EARLIER_SHA256 = {'aarch64': 'd31c841042de456bb784e8412f61429be7700aea2ffa508af2637283ebcb3707',
 'x86_64': 'e793aae5ad04a7c82a67d3f102b837064e645a585b83ace0586169a1746eb25a'}
# Where the blocks enter: the instruction index in the earlier program, then the syscall numbers, as the v5 table holds
# them. The instructions (code, jt, jf, k; a name is that syscall's number) are encoded as include/uapi/linux/filter.h,
# bpf_common.h and seccomp.h at v6.12 define them: JEQ_K nr then RET ALLOW for bind and listen; for accept4, JEQ_K nr
# 0/10, then per allowed flag value LD_W_ABS args[3]'s low word (16 + 3 * 8), JEQ_K value 0/1 and RET ALLOW, and last
# RET KILL_PROCESS.
PAIR_AT = {"aarch64": (134, 200, 201), "x86_64": (110, 49, 50)}
ACCEPT4_AT = {"aarch64": (175, 242), "x86_64": (184, 288)}
ALLOW, KILL_PROCESS = 0x7FFF0000, 0x80000000
LISTENER_PAIR = ((0x15, 0, 1, "bind"), (0x06, 0, 0, ALLOW), (0x15, 0, 1, "listen"), (0x06, 0, 0, ALLOW))
ACCEPT4_BLOCK = ((0x15, 0, 10, "accept4"),
                 *((code, 0, jf, k) for value in (0, 0x80000, 0x80800)
                   for code, jf, k in ((0x20, 0, 0x28), (0x15, 1, value), (0x06, 0, ALLOW))),
                 (0x06, 0, 0, KILL_PROCESS))
INSTRUCTION_BYTES = 8
# v5's OBSERVER decision vectors per architecture, and how many of them test bind, listen or accept4.
OBSERVER_DECISIONS = {"aarch64": 256, "x86_64": 267}
LISTENER_DECISIONS = {"aarch64": 22, "x86_64": 22}
INDEX_SCHEMA = "planeon.internal.compiled-filter-programs/v3"
INDEX_KEYS = ("schemaVersion", "evidenceClass", "format", "source", "predecessor", "programs")
INDEX_ROW_KEYS = ("role", "arch", "path", "instructions", "bytes", "sha256")
# Edge record v6: edge record v5's 54 rows, unchanged and in order, then the two OBSERVER programs for R10's HE-004-I01
# under host-enforcement/contracts/seccomp-v5/ (Q-P2-2 (a)).
V5_EDGE_SHA256 = "89b47ef8f865b31911eb8da2b08a5a3c22b2d92a62599cb6fdfccbfe7f79e3c0"
V5_EDGE_PACKET = "MET-ENFORCE-033"
V5_ROWS = 54
EDGE_KEYS = ("schemaVersion", "graph", "consumer", "provider", "artifact", "ownerDecision", "rules", "notArtifacts",
             "statuses", "artifacts", "supersedes", "ownerDecisions", "notes")
PROGRAM_ROW_KEYS = ("providerPath", "providerCommit", "sha256", "mode", "consumerPath", "consumerPacket", "relation",
                    "status", "providerPacket")
V6_ARTIFACT = "observer-compiled-filter-programs-seccomp-v5-republication"
CONSUMER_PACKET = "HE-004-I01"
CONSUMER_DIR = "host-enforcement/contracts/seccomp-v5/"
# The lane monitor's two messages, verbatim; Q-SOL-1 and F-SOL-1's note are read from HS53's record.
Q_P2 = "SLOT 249 = MET-ENFORCE-036 is confirmed (not on main, unclaimed), branch codex/met-enforce-036-observer-programs-v3, and harness-onion-obsprog is registered as your worktree. Monitor decisions, consistent with 240's owner-approved PROGRAMS-REPUBLISH pattern (I'll tell the owner): Q-P2-1 (a): only OBSERVER's two programs plus the index of 14. Q-P2-3 (a): keep the seccomp-v3 OBSERVER rows for HE-004 unchanged. Q-P2-4 (a): one or two light contract-review rounds, then adoption, then mechanics on template 248, then the packet review. Q-P2-2: I've asked the primary for the HE-004-I01 vendor path(s), path level only, and will relay the answer. Until then, draft the rows as (a) with the seccomp-v5/ path. GO for the contract draft and the contract review rounds (light work). The pre-check, dry run and push need my word."
Q_P2_2 = "Q-P2-2 = (a), with the primary lane's facts at path level: HE-004-I01 vendors host-enforcement/contracts/seccomp-v5/OBSERVER.x86_64.bpf and host-enforcement/contracts/seccomp-v5/OBSERVER.aarch64.bpf, mode 100644, REGISTERED_BEFORE_USE. This follows R10's convention contracts/seccomp-v<N>/<ROLE>.<arch>.bpf, where N is the seccomp contract version compiled from. No other file is decided. R10 has never vendored allowlists or spec texts, so v5's allowlists and HS53's effective spec need no rows. A possible I01 wire vector comes in a later edge record. The v3 OBSERVER rows stay unchanged, per Q-P2-3 (a). Register the two .bpf rows only."
F_SOL_1_NOTE_START = "Note: "
# (id, date, the status record's source, the edge record's prefix) in the records' order.
DECISIONS = (
    ("Q-SOL-1", "2026-10-17",
     "lane monitor (owner-delegated); quoted verbatim as architecture/host-interface-amendment-hs53/amendment.json records it",
     "Q-SOL-1 (lane monitor, owner-delegated, 2026-10-17, as HS53's amendment record holds it, verbatim): "),
    ("F-SOL-1", "2026-10-17",
     "lane monitor; the note of F-SOL-1, quoted verbatim as architecture/host-interface-amendment-hs53/amendment.json "
     "records it",
     "F-SOL-1's note (lane monitor, 2026-10-17, as HS53's amendment record holds it, verbatim): "),
    ("Q-P2-1..4", "2026-10-18",
     "the lane monitor under the owner's delegation, consistent with PROGRAMS-REPUBLISH's owner-approved pattern; the "
     "message quoted verbatim",
     "Q-P2-1..4 (lane monitor, owner-delegated, consistent with 240's owner-approved PROGRAMS-REPUBLISH pattern, "
     "2026-10-18, verbatim): "),
    ("Q-P2-2", "2026-10-18",
     "the lane monitor, relaying the primary lane's facts at path level; the message quoted verbatim",
     "Q-P2-2 (lane monitor, relaying the primary lane's facts at path level, 2026-10-18, verbatim): "))
# Both READMEs keep their candidate status line after adoption; the adoption is recorded in the status record only.
CANDIDATE = "SUCCESSOR_CANDIDATE_AWAITING_INDEPENDENT_REVIEW"
STATUS_LINE = "Status: **" + CANDIDATE + "**"
STATUS_KEYS = ("schemaVersion", "packet", "roadmapItem", "roadmapPacket", "contractState", "evidenceClass", "base", "rebase",
               "predecessor", "source", "contractFiles", "reviewRounds", "keptCopies", "ownerDecisions", "discharges",
               "dischargeHow", "openObligations", "carriedToR10", "reviewerIndependence", "readmeStatusNote",
               "carriedNotes", "adoptionEdit")
ROUND_KEYS = ("round", "record", "recordSha256", "subject", "verdict", "findings")
RECORD_KEYS = ("round", "subjectCommit", "subjectTree", "base", "verdict", "findings", "checked")
FINDING_KEYS = ("id", "severity", "file", "line", "summary", "evidence")
REVIEW_BASE = V5_COMMIT
CARRIED = ('P3R1-2', 'P3R1-3', 'P3R1-4', 'P3R2-1', 'P3R2-2')
# The passing round's subject bytes of every contract file the adoption left unchanged: status.json alone was edited.
REVIEWED_SHA256 = {'architecture/artifact-edges/README-v6.md': 'ce15ee36e15964a08fc83a495f2bd453ebe375c77e37d386f00c2803ec4e73f7',
 'architecture/artifact-edges/operator-harness-engineering-v6.json': '0ac7c2da62de87837f5a36a967a2c5b9c286ecab2e03f335a8eebbd32df9d24d',
 'architecture/compiled-filter-programs-v3/README.md': '2b9afcc9c8187f04b64d8c060a1b185b95e0f9d7a9ea71f01004d4574dcd309d',
 'architecture/compiled-filter-programs-v3/REVIEW_BRIEF.md': '7103e102e24ceed2223e6a8a22742261fbf16ce7df94b06db56654317c30c39d',
 'architecture/compiled-filter-programs-v3/index.json': '1622d307e71d1f23085ca4a614d7c99bf732289011b80c2f63bf8845bfebee25',
 'architecture/compiled-filter-programs-v3/programs/OBSERVER.aarch64.bpf': '887bf07824d7c1e6ec6db991473935d31500e0c78fac345058972a0f777ad184',
 'architecture/compiled-filter-programs-v3/programs/OBSERVER.x86_64.bpf': 'a20d2a956393b3af72799eaad5fa2c4a3cd82f38bf3842c0dea7c42012e525b9',
 'scripts/compiled_filter_programs_v3.py': '59d994489312d9c7b8de5d18f70979d810e974779e85d1b24de945f2bb34c2bb'}
V5_OPEN_ITEM = "OBSERVER's compiled programs and the edge record are republished from v5 (O-PROGRAMS-V3-OBSERVER)"
HS53_OBLIGATION = "O-PROGRAMS-V3-OBSERVER"
LOCAL_PATH_MARKERS = (b"/users/", b"/private/", b"/home/", b".local/state", b"/tmp/claude")
PATH_FOLLOWERS = frozenset(b"abcdefghijklmnopqrstuvwxyz0123456789._-~/")
# The compiled filter programs v1 and v2 with their publishers, edge records v1 to v5 with their READMEs and EDGE-2,
# allowlists v3 to v5 with their models, HS43, HS53 and the repository registry: no file changed or added.
FROZEN_DIRS = (FIRST_DIR, PREDECESSOR_DIR, "architecture/seccomp-allowlists-v3/", "architecture/seccomp-allowlists-v4/",
               V5_DIR, "architecture/host-interface-amendment-hs43/", "architecture/host-interface-amendment-hs53/")
FROZEN_PATHS = (
    "architecture/artifact-edges/README-v2.md",
    "architecture/artifact-edges/README-v3.md",
    "architecture/artifact-edges/README-v4.md",
    "architecture/artifact-edges/README-v5.md",
    "architecture/artifact-edges/README.md",
    "architecture/artifact-edges/conformance-labs-harness-engineering.json",
    "architecture/artifact-edges/operator-harness-engineering-v2.json",
    "architecture/artifact-edges/operator-harness-engineering-v3.json",
    "architecture/artifact-edges/operator-harness-engineering-v4.json",
    "architecture/artifact-edges/operator-harness-engineering-v5.json",
    "architecture/artifact-edges/operator-harness-engineering.json",
    "architecture/compiled-filter-programs-v2/README.md",
    "architecture/compiled-filter-programs-v2/REVIEW_BRIEF.md",
    "architecture/compiled-filter-programs-v2/index.json",
    "architecture/compiled-filter-programs-v2/programs/EFFECT_GATE.aarch64.bpf",
    "architecture/compiled-filter-programs-v2/programs/EFFECT_GATE.x86_64.bpf",
    "architecture/compiled-filter-programs-v2/review-round1.json",
    "architecture/compiled-filter-programs-v2/status.json",
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
    "architecture/host-interface-amendment-hs43/HOST_INTERFACE_SPEC.md",
    "architecture/host-interface-amendment-hs43/README.md",
    "architecture/host-interface-amendment-hs43/REVIEW_BRIEF.md",
    "architecture/host-interface-amendment-hs43/amendment.json",
    "architecture/host-interface-amendment-hs43/review-round1.json",
    "architecture/host-interface-amendment-hs43/review-round2.json",
    "architecture/host-interface-amendment-hs43/review-round3.json",
    "architecture/host-interface-amendment-hs43/review-round4.json",
    "architecture/host-interface-amendment-hs43/round1/architecture/host-interface-amendment-hs43/HOST_INTERFACE_SPEC.md",
    "architecture/host-interface-amendment-hs43/round1/architecture/host-interface-amendment-hs43/README.md",
    "architecture/host-interface-amendment-hs43/round1/architecture/host-interface-amendment-hs43/REVIEW_BRIEF.md",
    "architecture/host-interface-amendment-hs43/round1/architecture/host-interface-amendment-hs43/amendment.json",
    "architecture/host-interface-amendment-hs43/round1/scripts/host_interface_amendment_v2.py",
    "architecture/host-interface-amendment-hs43/round2/architecture/host-interface-amendment-hs43/HOST_INTERFACE_SPEC.md",
    "architecture/host-interface-amendment-hs43/round2/architecture/host-interface-amendment-hs43/README.md",
    "architecture/host-interface-amendment-hs43/round2/architecture/host-interface-amendment-hs43/REVIEW_BRIEF.md",
    "architecture/host-interface-amendment-hs43/round2/architecture/host-interface-amendment-hs43/amendment.json",
    "architecture/host-interface-amendment-hs43/round2/scripts/host_interface_amendment_v2.py",
    "architecture/host-interface-amendment-hs43/round3/architecture/host-interface-amendment-hs43/HOST_INTERFACE_SPEC.md",
    "architecture/host-interface-amendment-hs43/round3/architecture/host-interface-amendment-hs43/README.md",
    "architecture/host-interface-amendment-hs43/round3/architecture/host-interface-amendment-hs43/REVIEW_BRIEF.md",
    "architecture/host-interface-amendment-hs43/round3/architecture/host-interface-amendment-hs43/amendment.json",
    "architecture/host-interface-amendment-hs43/round3/scripts/host_interface_amendment_v2.py",
    "architecture/host-interface-amendment-hs43/source-index.json",
    "architecture/host-interface-amendment-hs43/status.json",
    "architecture/host-interface-amendment-hs53/HOST_INTERFACE_SPEC.md",
    "architecture/host-interface-amendment-hs53/README.md",
    "architecture/host-interface-amendment-hs53/REVIEW_BRIEF.md",
    "architecture/host-interface-amendment-hs53/amendment.json",
    "architecture/host-interface-amendment-hs53/review-round1.json",
    "architecture/host-interface-amendment-hs53/review-round2.json",
    "architecture/host-interface-amendment-hs53/review-round3.json",
    "architecture/host-interface-amendment-hs53/review-round4.json",
    "architecture/host-interface-amendment-hs53/review-round5.json",
    "architecture/host-interface-amendment-hs53/review-round6.json",
    "architecture/host-interface-amendment-hs53/review-round7.json",
    "architecture/host-interface-amendment-hs53/review-round8.json",
    "architecture/host-interface-amendment-hs53/round1/architecture/host-interface-amendment-hs53/HOST_INTERFACE_SPEC.md",
    "architecture/host-interface-amendment-hs53/round1/architecture/host-interface-amendment-hs53/README.md",
    "architecture/host-interface-amendment-hs53/round1/architecture/host-interface-amendment-hs53/REVIEW_BRIEF.md",
    "architecture/host-interface-amendment-hs53/round1/architecture/host-interface-amendment-hs53/amendment.json",
    "architecture/host-interface-amendment-hs53/round1/architecture/seccomp-allowlists-v5/README.md",
    "architecture/host-interface-amendment-hs53/round1/architecture/seccomp-allowlists-v5/REVIEW_BRIEF.md",
    "architecture/host-interface-amendment-hs53/round1/architecture/seccomp-allowlists-v5/allowlists.json",
    "architecture/host-interface-amendment-hs53/round1/scripts/host_interface_amendment_v3.py",
    "architecture/host-interface-amendment-hs53/round1/scripts/seccomp_allowlists_v5.py",
    "architecture/host-interface-amendment-hs53/round2/architecture/host-interface-amendment-hs53/HOST_INTERFACE_SPEC.md",
    "architecture/host-interface-amendment-hs53/round2/architecture/host-interface-amendment-hs53/README.md",
    "architecture/host-interface-amendment-hs53/round2/architecture/host-interface-amendment-hs53/REVIEW_BRIEF.md",
    "architecture/host-interface-amendment-hs53/round2/architecture/host-interface-amendment-hs53/amendment.json",
    "architecture/host-interface-amendment-hs53/round2/architecture/seccomp-allowlists-v5/README.md",
    "architecture/host-interface-amendment-hs53/round2/architecture/seccomp-allowlists-v5/REVIEW_BRIEF.md",
    "architecture/host-interface-amendment-hs53/round2/architecture/seccomp-allowlists-v5/allowlists.json",
    "architecture/host-interface-amendment-hs53/round2/scripts/host_interface_amendment_v3.py",
    "architecture/host-interface-amendment-hs53/round3/architecture/host-interface-amendment-hs53/HOST_INTERFACE_SPEC.md",
    "architecture/host-interface-amendment-hs53/round3/architecture/host-interface-amendment-hs53/README.md",
    "architecture/host-interface-amendment-hs53/round3/architecture/host-interface-amendment-hs53/REVIEW_BRIEF.md",
    "architecture/host-interface-amendment-hs53/round3/architecture/host-interface-amendment-hs53/amendment.json",
    "architecture/host-interface-amendment-hs53/round3/architecture/seccomp-allowlists-v5/README.md",
    "architecture/host-interface-amendment-hs53/round3/architecture/seccomp-allowlists-v5/REVIEW_BRIEF.md",
    "architecture/host-interface-amendment-hs53/round3/architecture/seccomp-allowlists-v5/allowlists.json",
    "architecture/host-interface-amendment-hs53/round3/scripts/host_interface_amendment_v3.py",
    "architecture/host-interface-amendment-hs53/round4/architecture/host-interface-amendment-hs53/HOST_INTERFACE_SPEC.md",
    "architecture/host-interface-amendment-hs53/round4/architecture/host-interface-amendment-hs53/README.md",
    "architecture/host-interface-amendment-hs53/round4/architecture/host-interface-amendment-hs53/REVIEW_BRIEF.md",
    "architecture/host-interface-amendment-hs53/round4/architecture/host-interface-amendment-hs53/amendment.json",
    "architecture/host-interface-amendment-hs53/round4/architecture/seccomp-allowlists-v5/README.md",
    "architecture/host-interface-amendment-hs53/round4/architecture/seccomp-allowlists-v5/REVIEW_BRIEF.md",
    "architecture/host-interface-amendment-hs53/round4/scripts/host_interface_amendment_v3.py",
    "architecture/host-interface-amendment-hs53/round5/architecture/host-interface-amendment-hs53/HOST_INTERFACE_SPEC.md",
    "architecture/host-interface-amendment-hs53/round5/architecture/host-interface-amendment-hs53/README.md",
    "architecture/host-interface-amendment-hs53/round5/architecture/host-interface-amendment-hs53/REVIEW_BRIEF.md",
    "architecture/host-interface-amendment-hs53/round5/architecture/host-interface-amendment-hs53/amendment.json",
    "architecture/host-interface-amendment-hs53/round5/architecture/seccomp-allowlists-v5/README.md",
    "architecture/host-interface-amendment-hs53/round5/architecture/seccomp-allowlists-v5/REVIEW_BRIEF.md",
    "architecture/host-interface-amendment-hs53/round5/scripts/host_interface_amendment_v3.py",
    "architecture/host-interface-amendment-hs53/round6/architecture/host-interface-amendment-hs53/README.md",
    "architecture/host-interface-amendment-hs53/round6/architecture/host-interface-amendment-hs53/REVIEW_BRIEF.md",
    "architecture/host-interface-amendment-hs53/round6/architecture/host-interface-amendment-hs53/amendment.json",
    "architecture/host-interface-amendment-hs53/round6/architecture/seccomp-allowlists-v5/README.md",
    "architecture/host-interface-amendment-hs53/round6/architecture/seccomp-allowlists-v5/REVIEW_BRIEF.md",
    "architecture/host-interface-amendment-hs53/round6/scripts/host_interface_amendment_v3.py",
    "architecture/host-interface-amendment-hs53/round7/architecture/host-interface-amendment-hs53/README.md",
    "architecture/host-interface-amendment-hs53/round7/architecture/host-interface-amendment-hs53/REVIEW_BRIEF.md",
    "architecture/host-interface-amendment-hs53/round7/architecture/seccomp-allowlists-v5/README.md",
    "architecture/host-interface-amendment-hs53/round7/architecture/seccomp-allowlists-v5/REVIEW_BRIEF.md",
    "architecture/host-interface-amendment-hs53/source-index.json",
    "architecture/host-interface-amendment-hs53/status.json",
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
    "architecture/seccomp-allowlists-v5/README.md",
    "architecture/seccomp-allowlists-v5/REVIEW_BRIEF.md",
    "architecture/seccomp-allowlists-v5/allowlists.json",
    "architecture/seccomp-allowlists-v5/status.json",
    "architecture/seccomp-allowlists-v5/syscalls.json",
    "architecture/seccomp-allowlists-v5/vectors.json",
    "scripts/compiled_filter_programs.py",
    "scripts/compiled_filter_programs_v2.py",
    "scripts/host_interface_amendment_v2.py",
    "scripts/host_interface_amendment_v3.py",
    "scripts/seccomp_allowlists_v3.py",
    "scripts/seccomp_allowlists_v4.py",
    "scripts/seccomp_allowlists_v5.py",
)
# The adopted bytes of every contract file and of every input it is checked against.
ERA_SHA256 = MappingProxyType({
    "architecture/admission-semantics-v3/README.md": "c3106482b4ff79649cbef7c65797c6fcd6b64f8419e871ae7d89eecad3ff98ab",
    "architecture/admission-semantics-v3/admission-manifests/planeon-a2.json": "1096b3cc71c4fe6b5a17ed61e8bf8c17ee17fcf52b192503534d60aed9ce4741",
    "architecture/admission-semantics-v3/vectors.json": "a3e2dc9818742ae2188e0e83cf91bb833be836115975b3fb23d5f280f6928cc1",
    "architecture/artifact-edges/README-v6.md": "ce15ee36e15964a08fc83a495f2bd453ebe375c77e37d386f00c2803ec4e73f7",
    "architecture/artifact-edges/operator-harness-engineering-v5.json": "89b47ef8f865b31911eb8da2b08a5a3c22b2d92a62599cb6fdfccbfe7f79e3c0",
    "architecture/artifact-edges/operator-harness-engineering-v6.json": "0ac7c2da62de87837f5a36a967a2c5b9c286ecab2e03f335a8eebbd32df9d24d",
    "architecture/compiled-filter-programs-v2/index.json": "59581bbfb75e81f364382833b94be6c42f4e2a658c49711b4e72712434ef69cb",
    "architecture/compiled-filter-programs-v2/programs/EFFECT_GATE.aarch64.bpf": "8de80a2b597b84d9f5ace818e76ef15d4b15a5b02013bb479ca4fdf73df3d044",
    "architecture/compiled-filter-programs-v2/programs/EFFECT_GATE.x86_64.bpf": "4e516f1682098c90edd568f8f214d3de01b404a2c144104596fc4e3262f6e7a3",
    "architecture/compiled-filter-programs-v3/README.md": "2b9afcc9c8187f04b64d8c060a1b185b95e0f9d7a9ea71f01004d4574dcd309d",
    "architecture/compiled-filter-programs-v3/REVIEW_BRIEF.md": "7103e102e24ceed2223e6a8a22742261fbf16ce7df94b06db56654317c30c39d",
    "architecture/compiled-filter-programs-v3/index.json": "1622d307e71d1f23085ca4a614d7c99bf732289011b80c2f63bf8845bfebee25",
    "architecture/compiled-filter-programs-v3/programs/OBSERVER.aarch64.bpf": "887bf07824d7c1e6ec6db991473935d31500e0c78fac345058972a0f777ad184",
    "architecture/compiled-filter-programs-v3/programs/OBSERVER.x86_64.bpf": "a20d2a956393b3af72799eaad5fa2c4a3cd82f38bf3842c0dea7c42012e525b9",
    "architecture/compiled-filter-programs-v3/review-round1.json": "7df04fd0ca592ad6e8600521a280e3bf78b685c721196826f93ead00160c3d4a",
    "architecture/compiled-filter-programs-v3/review-round2.json": "55f7698fceda8bdadd7ca411b69d956c1f65fcb12862246391846aca387a6cb3",
    "architecture/compiled-filter-programs-v3/status.json": "83231e468c94369a9a36e690d1a5a0969ad61d9fa935363a610aff68a77a8654",
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
    "architecture/host-interface-amendment-hs53/amendment.json": "e4255685a38f183d9cd5e5411ee83cc3dee6442e578831296d9789109824d763",
    "architecture/host-interface-amendment-hs53/status.json": "753a984c2ca721c4e53b873118ff2b513391a722633fa19b905e3dc6e4234c93",
    "architecture/i05-gate-channel-v2/README.md": "1cb07cef90b0881c42370d8bbaeea08c6abc48478bed3939286b651601d2cca3",
    "architecture/i05-gate-channel-v3-supplement/vectors.json": "1c00bdb3ea112af6098a09158cce3e4a7a6098c9670f490ead4ca65d8bdbb5ac",
    "architecture/i05-gate-channel-v3/README.md": "f82f43330125640d3ac946d2afc9a1804a21e5e60a7ac4b94e5d6cb6ed2ea3aa",
    "architecture/i05-gate-channel-v3/channel.schema.json": "3bfee13c9d32e82fe5ab908eb6f716bc11881f9d57b324f8ea4a21a3ad35356f",
    "architecture/i05-gate-channel-v3/outcome-mapping.json": "4466f379f1cc669e047cffd8afa5fa88b2cc7648a51e2d38b17f0bd5e2252a3a",
    "architecture/i05-gate-channel-v3/vectors.json": "ab75d86fe54ade7ee2695ef84b200d0473e14e4112e64e7702032593658763ed",
    "architecture/i05-gate-channel-v4/README.md": "b0af1f8784c7e9bcdd3793a1002d1000e222a13e5a7613b50b04ce5a116ed04d",
    "architecture/i05-gate-channel-v4/vectors.json": "f314610f7ee3feb08533cb535f0a4c19fc991384b852b99a50a1646b0739b1e9",
    "architecture/i05-gate-channel/README.md": "dc9aa22017b2cdf71f886fb7890aff3f6e7095b9afc25bd37645cb0dee23b498",
    "architecture/i06-backend-profile-v2/README.md": "553880b957586dbfa50eabc4a99d51735eef2a1b0a82641ea51d8e3ea8cf72eb",
    "architecture/i06-backend-profile-v2/criteria.json": "026206c57d3025c0f0129b6615e46c83d5a8000ddc3288f000a1fe4570050cda",
    "architecture/i06-backend-profile-v2/vectors.json": "1a5e168f0d8fff233f5072b1440e75a633b38e428f87b2893a96e579122a430e",
    "architecture/i06-backend-profile-v3/README.md": "9ee406f43060f266a7b5dd2679aa8352f0815584c45e33d0ab193ea7f90c0c77",
    "architecture/i06-backend-profile-v3/criteria.json": "752533c57b5f93e4c4158a9c17b52eb88d236a3632ab0b66b669e8f8041f57c7",
    "architecture/i06-backend-profile-v3/vectors.json": "4752b648abdd82d21ea622a1b26c721143577478c0a2491204e0d584c1d6f081",
    "architecture/i06-backend-profile/README.md": "ccf952d40b4f6229c0cdea79f976253cd4abb19438c1eebc5794e748a708e4b7",
    "architecture/i06-backend-profile/identity-closure.json": "0a9b82ffa2d63bf48a8850574cdf3ece02bf1913f33a72cbb96ed30a40f1f3bb",
    "architecture/i06-backend-profile/upstream-bootstrap-rbac-v1.37.1.json": "7529c2a713af2fb90163175924c264d95f4242d7e0c26b1452c77febb13ed50e",
    "architecture/i06-backend-profile/writer-inventory.json": "8e6b3b7565cfc93a61162b84d740cffb2871eb66ab85e8c4e80ac813f1af3077",
    "architecture/i07-policy-write-v2/README.md": "cde20d7fee8661cd9314350849870fe5b0838b7914a60237d0eeb1f5dca39d39",
    "architecture/i07-policy-write-v3/README.md": "a8c51a725b99d84351aba7a326196e7078c239ba4e28d3eaec1cf09fb3dca43d",
    "architecture/i07-policy-write-v3/channel.schema.json": "c68721a1002fccc7d6e59eeee9016a0a0f4a7428fad714e5a3d90a362d30ce09",
    "architecture/i07-policy-write-v3/policy-kinds.json": "4e427204b89959cb855d8641c3fa6f95d358b0b6a6a7730bfc7776adc4a173c0",
    "architecture/i07-policy-write-v3/vectors.json": "c4c24c5ff15618aa2f0fe0f016011359bc4316220c6e40d5168f9ee24b6f736d",
    "architecture/i07-policy-write/README.md": "9e5cb3d1023bc12b9e2643ae42dde5a87640cf04fc8ac1aa88350c65b12ba2dc",
    "architecture/native-profile-v2/qualification.schema.json": "55bd641fd229f21e04ec00813bcfe600890584e982e290a210720ac5cb160ab0",
    "architecture/native-profile-v3/qualification.schema.json": "ae5cbb6aa39f4edfa2d9919f25e55bad9ab214a99ca927c5afe7e2d943946ac5",
    "architecture/native-profile-v4/README.md": "a4205a5388dc83827bb39670bcc9477b030f29829128abf19f7578321c170174",
    "architecture/native-profile-v4/qualification.schema.json": "c3e91c087ebc6a13e8a96a066f80710ac968c8def434d1d1b97415811715ed10",
    "architecture/native-profile-v4/vectors.json": "dede64ab3202a9e28094f062b5dad868c13ca02423e2380af8666ecf2e7a86e6",
    "architecture/native-qualification-inputs/qualification.schema.json": "bef248bfa82b234124c014f98e40c5791bced3171bb118b7ed1bb7b8daaf95c3",
    "architecture/repositories.yaml": "02190a668c6a9114b3733724bec4e552c553867e789b0802f6aaa6759148051d",
    "architecture/seccomp-allowlists-v5/allowlists.json": "879909a86037b153a951770b4a47a8c075364fbd7cf9a44405537807621b55a8",
    "architecture/seccomp-allowlists-v5/status.json": "3abd0a6e1241529c21751ed93ce9a48852391c00143bd29382465f2f6267ca02",
    "architecture/seccomp-allowlists-v5/syscalls.json": "fe9a603e780b576f666a219da119eedad5271a675998aba2d6d581fb53ebac07",
    "architecture/seccomp-allowlists-v5/vectors.json": "4539410a9bb66e2aca62931567253c3c70b382672cc2b8f8207d4ea3d4661ecd",
    "ci/network_canary.py": "1be4a837c4a5baee900db20007c4841361b8c823a1b5e521badcf28890d82099",
    "ci/run_packet_argv.py": "c2ed0852fa499f194bc91291c32d08b303ea79be3ba7ca6cb29a786d585929f5",
    "ci/verify-offline.sh": "778cb0faf59786dc31559e5d96a399d1e3bb26a4576e0ee9ff70e1f6546bd114",
    "ci/warm-source-isolation.sh": "f717f62fb1c9fdaec9eb594c733f25b17394bae6b90a311b9ccc08d4eaf9233b",
    "scripts/compiled_filter_programs_v3.py": "59d994489312d9c7b8de5d18f70979d810e974779e85d1b24de945f2bb34c2bb",
    "scripts/safe_yaml.py": "99c673560e65e58cdc1abe86e53472feaf93e546dd76cb9f3ba051beef5c49d7",
    "scripts/seccomp_allowlists_v5.py": "fc57bb40f4f2537005e46689d9fc39a0dd98d4ebe141f9aace961e9520f1e0a7",
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
    require(expected is not None, "MET-ENFORCE-036 reviewed bytes are bound: " + path)
    raw = reviewed_bytes(path)
    require(type(raw) is bytes and digest(raw) == expected, "unreviewed compiled filter programs v3 source: " + path)
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


def local_paths(raw: bytes) -> list:
    """Every marker occurrence followed by a path character: an absolute local path, not a quoted pattern."""
    low, hits = raw.lower(), []
    for marker in LOCAL_PATH_MARKERS:
        at = low.find(marker)
        while at != -1:
            end = at + len(marker)
            if end < len(low) and (low[end] in PATH_FOLLOWERS or low[end] >= 0x80):
                hits.append((marker, at))
            at = low.find(marker, at + 1)
    return hits


def encode(block: tuple, numbers: dict[str, int]) -> bytes:
    """The restated instructions, encoded here independently of the model and the publisher."""
    return b"".join(code.to_bytes(2, "little") + bytes((jt, jf)) + (numbers[k] if type(k) is str else k).to_bytes(4, "little")
                    for code, jt, jf, k in block)


def _decode(raw: bytes) -> list[tuple[int, int, int, int]]:
    """The kernel's struct sock_filter array: little-endian u16 code, u8 jt, u8 jf, u32 k."""
    require(len(raw) % INSTRUCTION_BYTES == 0, "a program is a whole number of instructions")
    return [(int.from_bytes(raw[at:at + 2], "little"), raw[at + 2], raw[at + 3], int.from_bytes(raw[at + 4:at + 8], "little"))
            for at in range(0, len(raw), INSTRUCTION_BYTES)]


def _decision_texts(hs53: Any) -> dict[str, str]:
    """The status record's text per decision: Q-SOL-1 and F-SOL-1's note as HS53's record holds them, and the lane
    monitor's two messages."""
    recorded = {row["id"]: row for row in hs53["ownerDecisions"]}
    for name in ("Q-SOL-1", "F-SOL-1"):
        require(recorded[name]["date"] == "2026-10-17" and recorded[name]["state"] == "OWNER_DECIDED"
                and type(recorded[name]["decision"]) is str, "HS53's record holds decision " + name)
    note = recorded["F-SOL-1"]["decision"]
    require(note.count(F_SOL_1_NOTE_START) == 1, "F-SOL-1's note")
    return {"Q-SOL-1": recorded["Q-SOL-1"]["decision"], "F-SOL-1": note[note.index(F_SOL_1_NOTE_START):],
            "Q-P2-1..4": Q_P2, "Q-P2-2": Q_P2_2}


def validate_contract_files() -> None:
    """No frozen predecessor is changed or extended; the contract's files are new here, each once; the contract directory
    holds exactly its files and programs/; every contract file is a regular file of git mode 100644, not a symlink and not
    executable; and none holds an absolute local path."""
    new = authority()["newFiles"]
    for path in list(_PROJECTION_RULES) + list(new):
        require(path not in FROZEN_PATHS and not path.startswith(FROZEN_DIRS),
                "the earlier programs, edge records, allowlists, HS43, HS53 and the registry stay byte-identical")
    require(len(set(NEW_FILES)) == len(NEW_FILES) and set(NEW_FILES) <= set(new)
            and {path for path in new if path.startswith((CONTRACT_DIR, EDGES_DIR))} == set(NEW_FILES) - {PUBLISHER},
            "the contract's files are new in this packet, each once")
    require(stat.S_ISDIR(reviewed_mode(CONTRACT_DIR[:-1])), "the contract directory is a directory, not a link")
    tree = reviewed_tree(CONTRACT_DIR)
    require(set(tree) == CONTRACT_TREE and stat.S_ISDIR(tree[PROGRAMS_DIR[:-1]]),
            "the contract directory holds exactly its files and programs/")
    for path in NEW_FILES:
        mode = tree[path] if path in tree else reviewed_mode(path)
        require(stat.S_ISREG(mode) and not mode & 0o111, "a contract file is a regular file of git mode 100644: " + path)
        require(not local_paths(_verified(path)), "no absolute local path in a contract file: " + path)


def validate_status() -> None:
    """Adopted after independent review bound to its records and subjects; every other adopted byte is the passing
    subject's; the decisions are verbatim; HS53's obligation and allowlists v5's open item are discharged here; the notes
    are carried."""
    status = _json(STATUS_PATH)
    hs53 = _json(HS53_RECORD)
    hs53_status = _json(HS53_STATUS)
    v5_status = _json(V5_STATUS)
    for path, expected in REVIEWED_SHA256.items():
        require(digest(_verified(path)) == expected, "the adopted contract is the reviewed subject: " + path)
    _bound(lambda: tuple(status) == STATUS_KEYS
           and status["schemaVersion"] == "planeon.internal." + NEW_PACKET.lower() + "-status/v1"
           and status["packet"] == NEW_PACKET and status["roadmapItem"] == "SECCOMP-OBSERVER-LISTENER"
           and status["roadmapPacket"] == "packet 2 of 2 (Q-SOL-1 (a))"
           and status["contractState"] == "ADOPTED_DATA_CONTRACT" and status["evidenceClass"] == "DATA_CHECK_ONLY"
           and status["base"] == REVIEW_BASE and type(status["rebase"]) is str and status["rebase"] != ""
           and status["predecessor"] == {"directory": PREDECESSOR_DIR, "packet": PREDECESSOR_PACKET,
                                         "status": PREDECESSOR_DIR + "status.json"}
           and status["source"] == {"directory": V5_DIR, "packet": V5_PACKET, "commit": V5_COMMIT}
           and status["contractFiles"] == list(CONTRACT_FILES) and status["keptCopies"] == []
           and status["reviewerIndependence"] == "SEPARATE_AGENT_NOT_AUTHOR"
           and all(type(status[key]) is str and status[key] != ""
                   for key in ("dischargeHow", "readmeStatusNote", "adoptionEdit"))
           and all(text in status["readmeStatusNote"] for text in (V6_README, CANDIDATE))
           and type(status["openObligations"]) is list and len(status["openObligations"]) == 2
           and all(type(text) is str and text != "" for text in status["openObligations"])
           and set(status["carriedToR10"]) == {"packet", "items"} and status["carriedToR10"]["packet"] == CONSUMER_PACKET
           and type(status["carriedToR10"]["items"]) is list and len(status["carriedToR10"]["items"]) == 4
           and all(type(text) is str and text != "" for text in status["carriedToR10"]["items"])
           and tuple(status["carriedNotes"]) == CARRIED
           and all(type(text) is str and text != "" for text in status["carriedNotes"].values()),
           "adopted MET-ENFORCE-036 status")
    texts = _decision_texts(hs53)
    _bound(lambda: len(status["ownerDecisions"]) == len(DECISIONS)
           and all(tuple(row) == ("id", "date", "decision", "source") and (row["id"], row["date"]) == (name, date)
                   and row["decision"] == texts[name] and row["source"] == source
                   for row, (name, date, source, _prefix) in zip(status["ownerDecisions"], DECISIONS)),
           "the decisions, verbatim")
    obligation = {row["id"]: row for row in hs53["obligations"]}[HS53_OBLIGATION]
    _bound(lambda: status["discharges"] == [{"record": HS53_RECORD, "obligation": HS53_OBLIGATION,
                                             "text": obligation["text"]},
                                            {"record": V5_STATUS, "openObligation": V5_OPEN_ITEM}]
           and hs53_status["obligations"].count(HS53_OBLIGATION) == 1
           and v5_status["openObligations"].count(V5_OPEN_ITEM) == 1
           and hs53_status["contractState"] == "ADOPTED_AMENDMENT" and v5_status["contractState"] == "ADOPTED_DATA_CONTRACT",
           "HS53's obligation and allowlists v5's open item are discharged in this record only")
    rows = status["reviewRounds"]
    _bound(lambda: len(rows) == len(ROUNDS) and all(
        tuple(row) == ROUND_KEYS and row["round"] == number and row["record"] == record
        and row["recordSha256"] == "sha256:" + digest(_verified(record))
        and row["subject"] == {"commit": commit, "tree": tree, "base": REVIEW_BASE} and row["verdict"] == verdict
        and row["findings"] == ["%s %s" % finding for finding in findings]
        for row, (number, record, commit, tree, verdict, findings) in zip(rows, ROUNDS)),
           "every review round is bound to its record and subject")
    for number, record_path, commit, tree, verdict, findings in ROUNDS:
        record = _json(record_path)
        _bound(lambda: tuple(record) == RECORD_KEYS and record["round"] == number
               and (record["subjectCommit"], record["subjectTree"], record["base"]) == (commit, tree, REVIEW_BASE)
               and record["verdict"] == verdict
               and [(row["id"], row["severity"]) for row in record["findings"]] == list(findings)
               and all(tuple(row) == FINDING_KEYS for row in record["findings"])
               and type(record["checked"]) is list and record["checked"] != [],
               "the round-%d record is its round's" % number)
    _bound(lambda: ROUNDS[-1][4] == "PASS_FOR_SOURCE_PUBLICATION"
           and all(row[4] == "CHANGES_REQUIRED" for row in ROUNDS[:-1])
           and all(severity == "NOTE" for _id, severity in ROUNDS[-1][5]),
           "the last round passes with notes only")


def validate_readmes() -> None:
    """Both READMEs keep their candidate status line and name this packet in their title; MET-ENFORCE-036 is written in
    exactly the restated files."""
    for path in (README_PATH, V6_README):
        text = _verified(path).decode("utf-8")
        lines = text.splitlines()
        require([line for line in lines if line.startswith("Status:")] == [line for line in lines
                                                                        if line.startswith(STATUS_LINE)]
                and len([line for line in lines if line.startswith("Status:")]) == 1
                and lines[0].startswith("# ") and lines[0].endswith("(" + NEW_PACKET + ")"),
                "the README keeps its candidate status line: " + path)
    require({path for path in NEW_FILES if NEW_PACKET.encode("ascii") in _verified(path)} == NAMING_FILES,
            "MET-ENFORCE-036 is written in exactly the restated contract files")


def validate_programs() -> tuple[types.ModuleType, dict, dict, dict]:
    """The v5 model, executed from this era's bytes on the v5 policy and syscall table, compiles every program to v5's
    digest and length; the twelve programs of the other roles are the files MET-ENFORCE-029's index lists, byte for byte,
    and each OBSERVER program is the earlier program with exactly the bind/listen pair and the accept4 block at the
    restated indexes; the index names all fourteen exactly."""
    v5 = _era_model(V5_MODEL, "_met_enforce_036_seccomp_allowlists_v5")
    policy, table, vectors = (_json(path) for path in V5_SOURCES[1:])
    predecessor = _json(PREDECESSOR_INDEX)
    index = _json(INDEX_PATH)
    require(all(ERA_SHA256[path] == expected for path, expected in V5_SOURCE_SHA256.items())
            and ERA_SHA256[PREDECESSOR_INDEX] == PREDECESSOR_INDEX_SHA256, "the pinned v5 sources and predecessor index")
    _bound(lambda: tuple(sorted(policy["roles"])) == ROLES and len(predecessor["programs"]) == 2 * len(ROLES),
           "the seven roles of the v5 policy and MET-ENFORCE-029's fourteen programs")
    earlier = {(row["role"], row["arch"]): row for row in predecessor["programs"]}
    published, rows = {}, []
    for role in ROLES:
        for position, arch in enumerate(ARCHES):
            program = v5.compile_filter(policy, table, role, arch)
            compiled = v5.program_bytes(program)
            _bound(lambda: len(program) == PROGRAM_LENGTHS[role][position] == vectors["programLengths"][role][arch]
                   and len(compiled) == INSTRUCTION_BYTES * len(program)
                   and digest(compiled) == PROGRAM_SHA256[role][position]
                   and "sha256:" + digest(compiled) == vectors["filterDigests"][role][arch],
                   "the v5 model's program has v5's digest and length: %s %s" % (role, arch))
            row = earlier[role, arch]
            _bound(lambda: type(row["path"]) is str and row["path"].startswith((FIRST_DIR, PREDECESSOR_DIR)),
                   "MET-ENFORCE-029's index names a program path: %s %s" % (role, arch))
            prior = _verified(row["path"])
            _bound(lambda: row["sha256"] == "sha256:" + digest(prior) and row["bytes"] == len(prior)
                   == INSTRUCTION_BYTES * row["instructions"], "MET-ENFORCE-029's index names its program: " + row["path"])
            if role == ROLE:
                path = PROGRAMS_DIR + "%s.%s.bpf" % (role, arch)
                data = _verified(path)
                pair_at, bind, listen = PAIR_AT[arch]
                accept_at, accept4 = ACCEPT4_AT[arch]
                numbers = {"bind": bind, "listen": listen, "accept4": accept4}
                _bound(lambda: all(table["syscalls"][name][arch]["nr"] == nr for name, nr in numbers.items()),
                       "bind, listen and accept4's numbers on " + arch)
                pair, block = encode(LISTENER_PAIR, numbers), encode(ACCEPT4_BLOCK, numbers)
                cut, end = INSTRUCTION_BYTES * pair_at, INSTRUCTION_BYTES * accept_at
                require(compiled == data, "the pinned v5 model compiles exactly the published program: " + path)
                require(row["path"] == FIRST_DIR + "programs/%s.%s.bpf" % (role, arch)
                        and digest(prior) == EARLIER_SHA256[arch] and len(prior) == INSTRUCTION_BYTES * EARLIER_LENGTHS[arch]
                        and len(pair) == 4 * INSTRUCTION_BYTES and len(block) == 11 * INSTRUCTION_BYTES
                        and cut < end <= len(prior) and len(data) == len(prior) + len(pair) + len(block)
                        and data == prior[:cut] + pair + prior[cut:end] + block + prior[end:],
                        "the earlier OBSERVER program with exactly the bind/listen pair at %d and the accept4 block at %d: %s"
                        % (pair_at, accept_at, path))
                published[arch] = data
            else:
                path = row["path"]
                require(compiled == prior, "byte-identical to the program MET-ENFORCE-029 indexes: " + path)
            rows.append({"role": role, "arch": arch, "path": path, "instructions": len(program), "bytes": len(compiled),
                         "sha256": "sha256:" + digest(compiled)})
    expected = {"schemaVersion": INDEX_SCHEMA, "evidenceClass": "DATA_CHECK_ONLY", "format": predecessor["format"],
                "source": {"contract": V5_DIR, "packet": V5_PACKET, "commit": V5_COMMIT,
                           "files": {path: "sha256:" + V5_SOURCE_SHA256[path] for path in V5_SOURCES}},
                "predecessor": {"path": PREDECESSOR_INDEX, "sha256": "sha256:" + PREDECESSOR_INDEX_SHA256,
                                "packet": PREDECESSOR_PACKET},
                "programs": rows}
    _bound(lambda: index == expected and tuple(index) == INDEX_KEYS
           and all(tuple(row) == INDEX_ROW_KEYS for row in index["programs"])
           and len({row["path"] for row in index["programs"]}) == len(rows) == 2 * len(ROLES),
           "the index names exactly the fourteen v5 programs at their repository paths")
    return v5, table, vectors, published


def replay_observer_vectors(v5: types.ModuleType, table: dict, vectors: dict, published: dict) -> dict:
    """Every v5 OBSERVER decision vector, run through the published bytes with the era model's interpreter, gives its
    recorded action; the counts per architecture, and of the listener calls, are restated."""
    observer = {arch: _decode(published[arch]) for arch in ARCHES}
    counts = {arch: 0 for arch in ARCHES}
    listener = {arch: 0 for arch in ARCHES}
    numbers = {arch: {PAIR_AT[arch][1], PAIR_AT[arch][2], ACCEPT4_AT[arch][1]} for arch in ARCHES}
    for row in vectors["decisionChecks"]:
        if row.get("role") != ROLE:
            continue
        arch = row["arch"]
        _bound(lambda: v5.action_name(v5.run_filter(observer[arch], v5.seccomp_data(row["nr"], row["auditArch"],
                                                                                      row["args"]))) == row["expect"],
               "decision vector %s through the published bytes" % row.get("id"))
        counts[arch] += 1
        listener[arch] += row["nr"] in numbers[arch]
    require(counts == OBSERVER_DECISIONS and listener == LISTENER_DECISIONS,
            "the replay covers v5's OBSERVER decision vectors")
    return counts


def _no_cycle(registry: Any, consumer: str) -> bool:
    """harness-engineering consumes no repository in any graph of the registry, so an edge from consumer to it cannot
    close a cycle."""
    ids = {row["id"] for row in registry["repositories"]}
    return ({consumer, "harness-engineering"} <= ids
            and not any(row["consumer"] == "harness-engineering" for body in registry["dependencyGraphs"].values()
                        for row in body["edges"]))


def validate_edge_record() -> None:
    """Edge record v6 is v5's 54 rows unchanged and in order plus exactly the two OBSERVER rows for HE-004-I01, with v5's
    key sets, ownerDecision, rules, notArtifacts and statuses; it supersedes v5 by its digest; every provider path holds
    the recorded bytes; the edge cannot close a cycle."""
    v5 = _json(V5_EDGE)
    v6 = _json(V6_EDGE)
    texts = _decision_texts(_json(HS53_RECORD))
    registry = _era_model(SAFE_YAML, "_met_enforce_036_safe_yaml").safe_load(_verified(REPOSITORIES))
    require(ERA_SHA256[V5_EDGE] == V5_EDGE_SHA256, "edge record v5 is the one v6 supersedes")

    def new_row(row: Any, arch: str) -> bool:
        return (tuple(row) == PROGRAM_ROW_KEYS and row["providerPath"] == PROGRAMS_DIR + "%s.%s.bpf" % (ROLE, arch)
                and row["providerCommit"] is None and row["providerPacket"] == NEW_PACKET
                and row["sha256"] == PROGRAM_SHA256[ROLE][ARCHES.index(arch)] and row["mode"] == "100644"
                and row["consumerPath"] == CONSUMER_DIR + "%s.%s.bpf" % (ROLE, arch)
                and row["consumerPacket"] == CONSUMER_PACKET and row["relation"] == "BYTE_IDENTICAL"
                and row["status"] == "REGISTERED_BEFORE_USE")

    _bound(lambda: tuple(v6) == EDGE_KEYS and tuple(v5) == EDGE_KEYS
           and v6["schemaVersion"] == v5["schemaVersion"] == "planeon.internal.artifact-edge-registry/v2"
           and (v6["graph"], v6["consumer"], v6["provider"]) == ("buildArtifact", "operator", "harness-engineering")
           == (v5["graph"], v5["consumer"], v5["provider"]) and v6["artifact"] == V6_ARTIFACT
           and all(v6[key] == v5[key] for key in ("ownerDecision", "rules", "notArtifacts", "statuses"))
           and v6["supersedes"] == {"path": V5_EDGE, "sha256": "sha256:" + V5_EDGE_SHA256, "packet": V5_EDGE_PACKET}
           and v6["ownerDecisions"] == [prefix + '"' + texts[name] + '"' for name, _date, _source, prefix in DECISIONS]
           and type(v6["notes"]) is list and len(v6["notes"]) == 5
           and all(type(note) is str and note != "" for note in v6["notes"])
           and len(v5["artifacts"]) == V5_ROWS and v6["artifacts"][:V5_ROWS] == v5["artifacts"]
           and all(list(row) == list(old) for row, old in zip(v6["artifacts"], v5["artifacts"]))
           and len(v6["artifacts"]) == V5_ROWS + len(ARCHES)
           and all(new_row(row, arch) for row, arch in zip(v6["artifacts"][V5_ROWS:], ARCHES)),
           "edge record v6 is v5's 54 rows plus exactly the two OBSERVER rows")
    paths = [row["providerPath"] for row in v6["artifacts"]]
    require(len(set(paths)) == len(paths), "each provider path is registered once")
    for row in v6["artifacts"]:
        require(digest(_verified(row["providerPath"])) == row["sha256"],
                "a registered artifact matches its provider bytes: " + row["providerPath"])
    _bound(lambda: _no_cycle(registry, "operator"), "the edge cannot close a cycle in the repository registry")


def validate_compiled_filter_programs_v3() -> None:
    """The contract's files, then every reviewed byte, the adoption record and the READMEs; then the programs, the index,
    the replay and edge record v6; last, this layer's canonical hunks."""
    for path in ERA_SHA256:
        _verified(path)
    validate_contract_files()
    validate_status()
    validate_readmes()
    v5, table, vectors, published = validate_programs()
    replay_observer_vectors(v5, table, vectors, published)
    validate_edge_record()
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


def validate_canonical_hunks() -> None:
    """Q-PERF40-4: every hunk of this layer's authority is the canonical byte-minimal one, from this era's bytes."""
    for path, rule in _PROJECTION_RULES.items():
        after = reviewed_bytes(path)
        require(type(after) is bytes and digest(after) == rule["afterSha256"], "unreviewed current source: " + path)
        before = _undo_this_layer(path, after)
        require(canonical_hunks(after, before) == rule["reverseHunks"], "canonical byte-minimal inverse hunks: " + path)


def validate() -> None:
    record = authority()
    validator_raw = successor.historical_bytes(VALIDATOR_PATH, regular_bytes(VALIDATOR_PATH))
    literal = b'AUTHORITY_SHA256 = "' + AUTHORITY_SHA256.encode("ascii") + b'"'
    placeholder = b'AUTHORITY_SHA256 = "TO_BE_PINNED_AFTER_SOURCE_FREEZE"'
    require(validator_raw.count(literal) == 1
            and digest(validator_raw.replace(literal, placeholder))
            == record["validatorNormalizedSha256"], "compiled filter programs v3 validator drift")
    paths = sorted((ROOT / "task-packets").glob("*.yaml"))
    old = set(record["baselinePackets"])
    require(len(paths) == 265
            and {path.stem for path in paths} == old | {NEW_PACKET, successor.NEW_PACKET, successor.successor.NEW_PACKET, successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.NEW_PACKET},
            "closed 265-packet catalog retaining the 249-packet checkpoint")
    packets = {}
    for path in paths:
        if path.stem in (successor.NEW_PACKET, successor.successor.NEW_PACKET, successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.NEW_PACKET):
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
            "closed source-only compiled-filter-programs-v3 packet and inherited commands")
    require(len(packet["allowedPaths"]) == len(set(packet["allowedPaths"]))
            and set(packet["allowedPaths"]) == set(record["changedFiles"])
            | set(record["newFiles"]) | {AUTHORITY_PATH, VALIDATOR_PATH,
                                         "task-packets/" + NEW_PACKET + ".yaml"},
            "unreviewed or omitted compiled-filter-programs-v3 packet path")
    for path, rule in record["changedFiles"].items():
        current = successor.historical_bytes(path, regular_bytes(path))
        require(digest(current) == rule["afterSha256"]
                and digest(historical_bytes(path, current)) == rule["beforeSha256"],
                "unreviewed current source: " + path)
    for path, expected in record["newFiles"].items():
        require(digest(successor.historical_bytes(path, regular_bytes(path))) == expected,
                "new source drift: " + path)
    validate_compiled_filter_programs_v3()


if __name__ == "__main__":
    validate()
    print("Compiled filter programs v3 valid: 265 current specifications; 249-packet checkpoint and exact 248-packet predecessor; contract reviewed.")
