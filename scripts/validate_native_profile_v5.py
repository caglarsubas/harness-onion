#!/usr/bin/env python3
"""Validate the MET-ENFORCE-038 capture-only native-profile v5 and edge record v7 and the exact 252-to-251 projection."""
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
    import validate_diagnostic_caps as successor
except ImportError:
    from scripts.safe_yaml import safe_load
    from scripts import validate_diagnostic_caps as successor


ROOT = Path(__file__).resolve().parents[1]
AUTHORITY_PATH = "architecture/native-profile-v5-authority.json"
AUTHORITY_SHA256 = "b1b03db348d27e92002664576c2f1f1936148f99a2a95e83d031740ccd3d5c0a"
VALIDATOR_PATH = "scripts/validate_native_profile_v5.py"
BASE_COMMIT = "35b733b523f46b2ccba095ea046efe5d42bfa583"
NEW_PACKET = "MET-ENFORCE-038"
PREVIOUS_PACKET = "MET-LINUX-007"
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
            require(key not in result, "duplicate native-profile-v5 authority member")
            result[key] = value
        return result

    def no_constant(_value: str) -> Any:
        raise ValueError("nonfinite native-profile-v5 authority number")

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
        require(digest(raw) == AUTHORITY_SHA256, "native profile v5 history authority digest")
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
    }, "closed native profile v5 history authority")
    require(value["schemaVersion"] == "harness.planeon.ai/native-profile-v5-authority/v1"
            and value["authorityPacket"] == NEW_PACKET
            and value["acceptedBase"] == BASE_COMMIT
            and type(value["baselinePackets"]) is dict
            and len(value["baselinePackets"]) == 251
            and NEW_PACKET not in value["baselinePackets"]
            and type(value["changedFiles"]) is dict
            and type(value["newFiles"]) is dict
            and _sha(value["packetSha256"])
            and _sha(value["validatorNormalizedSha256"]),
            "accepted 251-packet base")
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
    # An exact 251-era byte string is already older than the successor layer.
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


# MET-ENFORCE-038 (roadmap NATIVE-PROFILE-V5; candidate 4 adopted by the lane monitor, owner-delegated, 2026-10-19,
# after four independent contract review rounds, the last two PASS_FOR_ADOPTION) publishes the capture-only
# native-profile v5 (owner decision Q-NPE-1 (c)): native-profile v4's three capture variants without the seven host,
# policy and boot fields, which become record-only with four named T04 proofs, while the record contract stays
# native-profile v4's; and the operator -> harness-engineering edge record v7 (v6's 56 rows plus 6 for HE-004D2).
# Repository bytes and modes are read only through reviewed_bytes and reviewed_mode, and the contract directory's listing
# only through reviewed_tree, so a later bridged successor projects its own edits away first; a path outside this era is
# refused before it is read, and every era file is bound by digest on every read. Checked here: the freeze (E1-7:
# native-profile v4's and I06 v3's models by exact path and digest; native-profile v1 to v4, I06 v1 to v3 with their
# models, the W02 notes errata and edge records v1 to v6 byte-identical; the packet adds new files only); the adoption
# (the adopted files are candidate 4's bytes except edge record v7's three providerPacket values and the status record's
# adoption fields, without which the record is candidate 4's byte for byte; four review rounds bound to their published
# records and subject candidates, rounds 1 to 3 also to the source index; the verbatim adoption decision; the closed
# findings as the later rounds resolved them); the source index's pins; edge record v7 (it supersedes v6 by digest and
# packet, carries v6's 56 rows exactly and in order, and registers the three native-profile v5 files and the three
# history vectors with their bytes and modes); the evidenceClasses constant against the v5 model, as native-profile v4's
# layer checks v4's, with its eight host rows naming exactly the status record's four proofs (README "Open items"); and
# the v5 model, executed from this era's bytes with this era's v4 model as its import, replaying every vector over its
# pinned inputs (284 checks). This layer's own inverse hunks are the canonical byte-minimal ones, recomputed from its
# era's bytes (MET-PERF-040's carried rule).
NP5_DIR = "architecture/native-profile-v5/"
NP4_DIR = "architecture/native-profile-v4/"
EDGES_DIR = "architecture/artifact-edges/"
NP5_README = NP5_DIR + "README.md"
NP5_SCHEMA = NP5_DIR + "qualification.schema.json"
NP5_VECTORS = NP5_DIR + "vectors.json"
NP5_INDEX = NP5_DIR + "source-index.json"
STATUS_PATH = NP5_DIR + "status.json"
NP5_MODEL = "scripts/native_qualification_v5.py"
NP4_MODEL = "scripts/native_qualification_v4.py"
I06_MODEL = "scripts/i06_backend_profile_v3.py"
NP4_SCHEMA = NP4_DIR + "qualification.schema.json"
NP4_VECTORS = NP4_DIR + "vectors.json"
V6_EDGE = EDGES_DIR + "operator-harness-engineering-v6.json"
V7_EDGE = EDGES_DIR + "operator-harness-engineering-v7.json"
V7_README = EDGES_DIR + "README-v7.md"
# The adopted subject, and candidate 4's eight files (the subject and the status record) with their reviewed digests
# (r4 PASS_FOR_ADOPTION); edge record v7 and the status record differ from candidate 4 only by the adoption edits.
SUBJECT = (NP5_README, NP5_SCHEMA, NP5_VECTORS, NP5_INDEX, NP5_MODEL, V7_EDGE, V7_README)
CANDIDATE_FILES = SUBJECT + (STATUS_PATH,)
CANDIDATE_SHA256 = MappingProxyType({
    NP5_README: "76b584ca769f0afdd5142fcf3f96e3b5b2d053a172d5713f970dc77594e77692",
    NP5_SCHEMA: "70bda12463cee83301bc10fa6285023dc0e07b281a87ca70d44ec746cf262113",
    NP5_VECTORS: "b630c362b20bfa7b362bb2ee28734a403303a0dc54b2d627c11a332b226333a1",
    NP5_INDEX: "68cd8f2777405b9a5c6605c99f96d03de317d0444c562f8b0b019a57a4f9fd08",
    NP5_MODEL: "d9926f4d18c82a5da31b903fea47c42319d29268a63a26171a7e71aa4c2480a5",
    V7_EDGE: "8e7b001e3b980aa242472a03226d51e6a8410006d6dd6afd99f9d18f28bc2031",
    V7_README: "7131d500eac2085871254a250a4a84c24b17456891dd5f3b2478d85153f1a378",
    STATUS_PATH: "654d117f7cd319a1bc749fa81945c9e075e824902cfb4f42cec6fe444dd7da81",
})
CANDIDATE_LINES = 697
TBD = b'"providerPacket": "TBD"'
ASSIGNED = ('"providerPacket": "%s"' % NEW_PACKET).encode("ascii")
REVIEW_BASE = "f560209d04b7e0f07b2480219718a8a6dbdb21ef"
REVIEW_BASE_TREE = "bc8509228d89bfd2aa1a4f9279d07b5874352282"
RECORDS = tuple(NP5_DIR + "review-round%d.json" % number for number in (1, 2, 3, 4))
NEW_FILES = CANDIDATE_FILES + RECORDS
CONTRACT_TREE = frozenset(path for path in NEW_FILES if path.startswith(NP5_DIR))
# (round, verdict, the subject candidate's contract builder SHA-256, the round's finding ids) in order; round n reviewed
# candidate n, and round 4 the adopted candidate 4.
ROUNDS = ((1, "CHANGES_REQUIRED", "9eed3c45900d7c03993887e8958022c15b2c082e4150d1ba512d8d64ce68cf6a",
           tuple("E1-%d" % number for number in range(1, 11))),
          (2, "CHANGES_REQUIRED", "d8c23d0bba6af32e2fb7f420e46e0ebd03af445192ea1e330ecc824488d46d82", ("E2-1", "E2-2", "E2-3")),
          (3, "PASS_FOR_ADOPTION", "33cf3f06f298f82f5747fcc2c2fd17ac19ca54412a5d8f628ba547133d71eff2", ("E3-1",)),
          (4, "PASS_FOR_ADOPTION", "ba42bea8a337b5bcaf70572887c349d0280ad2dff3c6400f978d139274572187", ("E4-1", "E4-2")))
# Each round's subject candidate, file by file (no round copy is published; the digests are restated here).
ROUND_SUBJECTS = MappingProxyType({
    1: MappingProxyType({
        NP5_README: "4fa497cc0909408a9b950fe63603b912b1e7eac3b518f9eb23cc1b5468c0b5c5",
        NP5_SCHEMA: "70bda12463cee83301bc10fa6285023dc0e07b281a87ca70d44ec746cf262113",
        NP5_VECTORS: "f9f7e870d5c941254daef9ac9c77f2801420385e971e84295eca3b70ffa371b4",
        NP5_INDEX: "937f3da39a76f35de4ed3dcfebb7db87f3a28b808edc6899bc1f5f59449eb6ba",
        NP5_MODEL: "84143a477addb7942923641d18ec6ffa73e1e96217ddb312291c50e40495f3e8",
        V7_EDGE: "a3fb46eed4bfd6275d4468a372c2a39700df1562581bf5ddeec290f7465c0b1f",
        V7_README: "f1d43d984649779244e67c7cddbfaa364953605ba9020176e93c74a4c7eb67d1",
        STATUS_PATH: "ba35f3903554762a9a2004e4c5f5ef5350b9c51183a99e682c81f003b8a7d9ad",
    }),
    2: MappingProxyType({
        NP5_README: "f9e5fae359f16e1786ecc121c91f26738da2e0f0af1dc0df110ec10850cfacce",
        NP5_SCHEMA: "70bda12463cee83301bc10fa6285023dc0e07b281a87ca70d44ec746cf262113",
        NP5_VECTORS: "f9f7e870d5c941254daef9ac9c77f2801420385e971e84295eca3b70ffa371b4",
        NP5_INDEX: "ead145988ecf45988ac539e81f85fdd29cbcf084f5cd85927c3fe05e69f5aa05",
        NP5_MODEL: "c0f0b8d94acee59dd3b6b555671d449b6ff25a9c8dbb9ff40a73c8c0847cd718",
        V7_EDGE: "e51c6f440bf7ae134ba472775ce558f5483c0375cf87f1cf9e8a6880cacdb007",
        V7_README: "acb595b09654ec9abdd1f88eafb6cd726fa379e26355d1190960794369c38c51",
        STATUS_PATH: "1be1dc03ae5ef99c03b343800b3bec586ef58a6bc627d7fdc73093ce1e9e7647",
    }),
    3: MappingProxyType({
        NP5_README: "01733f4bf1be9bc06e0df737d11a005bc3049562c8e085424acc9a12fa270cb1",
        NP5_SCHEMA: "70bda12463cee83301bc10fa6285023dc0e07b281a87ca70d44ec746cf262113",
        NP5_VECTORS: "f9f7e870d5c941254daef9ac9c77f2801420385e971e84295eca3b70ffa371b4",
        NP5_INDEX: "eb2944b6be266e33348d286dce1d56ffc429ad868d5dcd244cadc29e652aa63c",
        NP5_MODEL: "7f1c3a589e0234f174f5b53ec6c39a8b790b998f793931ed781789f796d8a4cc",
        V7_EDGE: "20b07665d34aa5407f2b0225495e53fb2b7bd47de638b83485ac3aa5f5185c52",
        V7_README: "3c1edbffb93df7b29e065ce43c66f380a532c0bd39053de89d941fecb2db9857",
        STATUS_PATH: "47797b4779d6d4430d55bf3f997ec4a019e1e2c431018df527e3f811cd5cbd37",
    }),
    4: MappingProxyType({
        NP5_README: "76b584ca769f0afdd5142fcf3f96e3b5b2d053a172d5713f970dc77594e77692",
        NP5_SCHEMA: "70bda12463cee83301bc10fa6285023dc0e07b281a87ca70d44ec746cf262113",
        NP5_VECTORS: "b630c362b20bfa7b362bb2ee28734a403303a0dc54b2d627c11a332b226333a1",
        NP5_INDEX: "68cd8f2777405b9a5c6605c99f96d03de317d0444c562f8b0b019a57a4f9fd08",
        NP5_MODEL: "d9926f4d18c82a5da31b903fea47c42319d29268a63a26171a7e71aa4c2480a5",
        V7_EDGE: "8e7b001e3b980aa242472a03226d51e6a8410006d6dd6afd99f9d18f28bc2031",
        V7_README: "7131d500eac2085871254a250a4a84c24b17456891dd5f3b2478d85153f1a378",
        STATUS_PATH: "654d117f7cd319a1bc749fa81945c9e075e824902cfb4f42cec6fe444dd7da81",
    }),
})
# A review record names its subject candidate, the candidate's builder and one of its files in its subject line.
SUBJECT_LINE = "tools/w03/npv4-errata candidate %d (build_contract.py sha256 %s, %s sha256 %s)"
SUBJECT_NAMES = MappingProxyType({1: (NP5_VECTORS, "vectors.json"), 2: (NP5_README, "README"), 3: (NP5_README, "README"),
                                  4: (NP5_README, "README")})
STATUS_KEYS = ("schemaVersion", "workItem", "packet", "slot", "status", "candidate", "baseMain", "reviewBase",
               "supersedes", "keeps", "contracts", "ownerDecisions", "scopeErratum", "discharges", "hostProofs", "counts",
               "carried", "nonClaims", "rounds", "adoption", "adoptedSubject", "adoptionEdit", "independentReviewer",
               "readmeStatusNote", "recordPaths", "closedFindings")
# The keys the adoption added and candidate 4's values of the keys it changed: removing the one and restoring the other
# (the carried rows without the adoption's three and without their actions, candidate 4's three non-claims and its three
# earlier rounds) gives candidate 4's status record back, byte for byte.
ADOPTION_KEYS = frozenset({"reviewBase", "adoptedSubject", "adoptionEdit", "independentReviewer", "readmeStatusNote",
                           "recordPaths", "closedFindings"})
CANDIDATE_VALUES = MappingProxyType({"packet": "TBD", "status": "CONTRACT_CANDIDATE", "baseMain": REVIEW_BASE,
                                     "adoption": None})
ADOPTION_CARRIED = 3
CANDIDATE_NON_CLAIMS = 3
ROUND_KEYS = ("round", "subjectBuilderSha256", "verdict", "recordSha256", "record", "candidate", "subjectSha256",
              "severities")
EDIT_KEYS = ("path", "replaced", "with", "count", "rows", "candidateSha256", "adoptedSha256", "lineCount")
# The first line of the decisions record's 2026-10-19 adoption section, verbatim (the lane monitor's owner-delegated
# adoption).
ADOPTION = {'decidedBy': 'the lane monitor, owner-delegated',
 'date': '2026-10-19',
 'decision': 'Monitor: ADOPT candidate 4 for slot 252 (NATIVE-PROFILE-V5), on r4 PASS_FOR_ADOPTION (b8356184). The '
             'files: README 76b584ca, schema 70bda124, vectors b630c362, status 654d117f, source-index 68cd8f27, '
             'model d9926f4d, edge v7 8e7b001e (62 rows), README-v7 7131d500, builder ba42bea8. Carry E4-1 and '
             'E4-2; record the mechanics base 35b733b in status.json at adoption.'}
ACTIONS = {"filesEdited": False, "networkAccessed": "none", "personalDataSent": False, "inventoryToolingAttempted": False}
CLOSED_FINDINGS = {'E1-1': 'CLOSED in round 4 (OPEN_BY_DESIGN in rounds 2 and 3, pending Q-NPE-9; candidate 4 applies Q-NPE-9 (a) '
         'and round 4 checked Q03: PASS)',
 'E1-2': 'CLOSED in round 2',
 'E1-3': 'CLOSED in round 2',
 'E1-4': 'CLOSED in round 3 (PARTLY in round 2; its remainder, E2-1, RESOLVED in round 3)',
 'E1-5': 'CLOSED in round 2',
 'E1-6': 'CLOSED in round 2',
 'E1-7': "CLOSED in round 2 (README open items); the freeze it requires is DISCHARGED by this packet's layer (see "
         'carried)',
 'E1-8': 'CLOSED in round 2',
 'E1-9': 'CLOSED in round 2',
 'E1-10': 'CLOSED in round 2',
 'E2-1': 'CLOSED in round 3',
 'E2-2': 'CLOSED in round 3',
 'E2-3': 'CLOSED in round 3',
 'E3-1': 'CLOSED in round 4 (applied in candidate 4; round 4 checked E3-1: PASS)',
 'E4-1': "CARRIED as the monitor's adoption directs (see carried)",
 'E4-2': "CARRIED as the monitor's adoption directs (see carried)"}
CARRIED = (("E4-1 (contract review round 4, NOTE): the README's 2026-10-19 quote block leaves out two lines of the decisions "
  "record without marking them (the D2 design decisions Q-HE4D2-1, 2 and 4-11, and the line recording 251's merge "
  'as 35b733b and the mechanics GO), as the Q-NEXT-D2 block leaves out its line (ii)',
  'a later revision of the native-profile v5 README'),
 ("E4-2 (contract review round 4, NOTE): the contract builder does not cross-check the HE-004 decisions record's "
  'copy of the quoted decision lines',
  'the contract builder (operator tooling, outside the repository)'),
 ("E1-7 (contract review round 1, NOTE): the freeze of native-profile v4's model, which v5 binds by name",
  "this packet's layer validator (scripts/validate_native_profile_v5.py)"),
 ('T04-HOST-BOOT, T04-POLICY-STABLE, T04-HOST-LOCKS and T04-BOOT-ENTRY', 'T04'),
 ('the real reads of the seven host facts and any off-host attestation of them', 'HE-008 and T04'),
 ('observed booleans', 'a later candidate (Q-NPE-2 (a))'),
 ('the ClusterRole I06 successor (OBS-RBAC-1)', 'its own slot after 252, before HE-008 (Q-NPE-5 (a))'),
 ("HE-004D1's re-vendor of the capture contract", "HE-004D2 (edge v7's consumer label)"))
NON_CLAIMS = ['Native-profile v1 to v4, I06 v3, the W02 notes errata and edge records v1 to v6 are byte-identical.',
 'No capture route was exercised on a host; dropping the fields proves none of the host facts.',
 "The record contract is native-profile v4's, unchanged.",
 'The six files edge record v7 registers are not used before HE-004D2.',
 'No R10 file changes in this packet, and no I06 v3 or native-profile v4 file or model changes.']
HOST_PROOFS = ("T04-HOST-BOOT", "T04-POLICY-STABLE", "T04-HOST-LOCKS", "T04-BOOT-ENTRY")
# The source index: its closed keys, its subject (the contract's files that adoption does not rewrite) and its inputs.
INDEX_KEYS = ("schemaVersion", "round", "baseMain", "baseTree", "subject", "predecessorInputs", "earlierRounds")
INDEX_SUBJECT = (NP5_README, NP5_SCHEMA, NP5_VECTORS, NP5_MODEL, V7_README)
INDEX_INPUTS = (
    "architecture/native-profile-v4/README.md",
    "architecture/native-profile-v4/qualification.schema.json",
    "architecture/native-profile-v4/vectors.json",
    "architecture/native-profile-v4/status.json",
    "scripts/native_qualification_v4.py",
    "architecture/i06-backend-profile-v3/criteria.json",
    "architecture/i06-backend-profile-v3/vectors.json",
    "architecture/i06-backend-profile-v3/README.md",
    "scripts/i06_backend_profile_v3.py",
    "architecture/native-qualification-inputs/qualification.schema.json",
    "architecture/native-qualification-inputs/vectors.json",
    "architecture/native-profile-v2/qualification.schema.json",
    "architecture/native-profile-v2/vectors.json",
    "architecture/native-profile-v3/qualification.schema.json",
    "architecture/native-profile-v3/vectors.json",
    "architecture/artifact-edges/operator-harness-engineering-v6.json",
    "architecture/artifact-edges/README-v6.md",
    "architecture/w03-obligation-amendment-3/amendment.json",
    "architecture/w03-plan-v2/plan.json",
)
EDGE_V6_SHA256 = "0ac7c2da62de87837f5a36a967a2c5b9c286ecab2e03f335a8eebbd32df9d24d"
V6_PACKET = "MET-ENFORCE-036"
V6_ROWS = 56
EDGE_ARTIFACT = "native-profile-v5-captures"
EDGE_KEYS = ("schemaVersion", "graph", "consumer", "provider", "artifact", "ownerDecision", "rules", "notArtifacts",
             "statuses", "artifacts", "supersedes", "ownerDecisions", "notes")
EDGE_ROW_KEYS = ("providerPath", "providerCommit", "sha256", "mode", "consumerPath", "consumerPacket", "relation", "status")
CONSUMER_PREFIX = "host-enforcement/contracts/"
# Edge record v7's six new rows: (provider path, provider commit, consumer path, consumer packet). The three files this
# packet publishes carry providerCommit null and providerPacket NEW_PACKET; each history row's commit is its file's
# last-change commit at the accepted base, with the row's bytes and mode, as the packet's builder proved from git; those
# files are frozen in this era.
NEW_ROWS = (('architecture/native-profile-v5/qualification.schema.json',
  None,
  'host-enforcement/contracts/native-profile-v5/qualification.schema.json',
  'HE-004D2'),
 ('architecture/native-profile-v5/vectors.json',
  None,
  'host-enforcement/contracts/native-profile-v5/vectors.json',
  'HE-004D2'),
 ('architecture/native-profile-v5/README.md',
  None,
  'host-enforcement/contracts/native-profile-v5/README.md',
  'HE-004D2'),
 ('architecture/native-qualification-inputs/vectors.json',
  '3f52d53c39b2565cb74d527fdcb4215ff0e37b76',
  'host-enforcement/contracts/native-profile-v1/vectors.json',
  'HE-004D2'),
 ('architecture/native-profile-v2/vectors.json',
  '46bcc3e383ec5d9cf0c0d722636d264942b435de',
  'host-enforcement/contracts/native-profile-v2/vectors.json',
  'HE-004D2'),
 ('architecture/native-profile-v3/vectors.json',
  'a29c93c7813ff71eb8179c4e8611032d972e3a36',
  'host-enforcement/contracts/native-profile-v3/vectors.json',
  'HE-004D2'))
# The v5 model's pinned inputs and the vectors' counts (README "Counts": 284 checks).
NP5_INPUTS = {"v1Schema": "architecture/native-qualification-inputs/qualification.schema.json",
              "v1Vectors": "architecture/native-qualification-inputs/vectors.json",
              "v2Schema": "architecture/native-profile-v2/qualification.schema.json",
              "v2Vectors": "architecture/native-profile-v2/vectors.json",
              "v3Schema": "architecture/native-profile-v3/qualification.schema.json",
              "v3Vectors": "architecture/native-profile-v3/vectors.json",
              "v4Schema": NP4_SCHEMA, "v4Vectors": NP4_VECTORS}
NP5_COUNTS = {"positive": 5, "negative": 266, "accepted": 7, "crossVersion": 6}
NP5_CHECKS = 284
# The freeze (contract review round 1, E1-7): v5 binds native-profile v4's model by name, so both models stay these
# bytes at these exact paths.
MODEL_FREEZE = MappingProxyType({NP4_MODEL: "f7c718072d1ffbb9b8bbc310e6141d476ea5f25296f70ff8c1bc9ada3db02387",
                                 I06_MODEL: "dfb00e90199d436ae63b79261f2e04870d7861cb0f7a424971657a4d777754de"})
# Native-profile v1 to v4 and I06 v1 to v3 (their directories), the W02 notes errata: no file under them changes or is
# added here; their models, the files the contract pins or reads and edge records v1 to v6 are bound by digest below.
FROZEN_PREFIXES = ("architecture/native-qualification-inputs/", "architecture/native-profile-v2/",
                   "architecture/native-profile-v3/", NP4_DIR, "architecture/i06-backend-profile/",
                   "architecture/i06-backend-profile-v2/", "architecture/i06-backend-profile-v3/",
                   "architecture/w02-notes-errata/")
FROZEN_PATHS = (
    "architecture/artifact-edges/README-v2.md",
    "architecture/artifact-edges/README-v3.md",
    "architecture/artifact-edges/README-v4.md",
    "architecture/artifact-edges/README-v5.md",
    "architecture/artifact-edges/README-v6.md",
    "architecture/artifact-edges/README.md",
    "architecture/artifact-edges/operator-harness-engineering-v2.json",
    "architecture/artifact-edges/operator-harness-engineering-v3.json",
    "architecture/artifact-edges/operator-harness-engineering-v4.json",
    "architecture/artifact-edges/operator-harness-engineering-v5.json",
    "architecture/artifact-edges/operator-harness-engineering-v6.json",
    "architecture/artifact-edges/operator-harness-engineering.json",
    "architecture/i06-backend-profile-v3/README.md",
    "architecture/i06-backend-profile-v3/REVIEW_BRIEF.md",
    "architecture/i06-backend-profile-v3/criteria.json",
    "architecture/i06-backend-profile-v3/source-index.json",
    "architecture/i06-backend-profile-v3/vectors.json",
    "architecture/native-profile-v2/qualification.schema.json",
    "architecture/native-profile-v2/vectors.json",
    "architecture/native-profile-v3/qualification.schema.json",
    "architecture/native-profile-v3/vectors.json",
    "architecture/native-profile-v4/README.md",
    "architecture/native-profile-v4/REVIEW_BRIEF.md",
    "architecture/native-profile-v4/qualification.schema.json",
    "architecture/native-profile-v4/source-index.json",
    "architecture/native-profile-v4/status.json",
    "architecture/native-profile-v4/vectors.json",
    "architecture/native-qualification-inputs/qualification.schema.json",
    "architecture/native-qualification-inputs/vectors.json",
    "architecture/repositories.yaml",
    "architecture/w03-obligation-amendment-3/amendment.json",
    "architecture/w03-plan-v2/plan.json",
    "scripts/i06_backend_profile.py",
    "scripts/i06_backend_profile_v2.py",
    "scripts/i06_backend_profile_v3.py",
    "scripts/native_qualification_v2.py",
    "scripts/native_qualification_v3.py",
    "scripts/native_qualification_v4.py",
)
FROZEN_MESSAGE = ("native-profile v1 to v4, I06 v1 to v3 (their models included), the W02 notes errata and edge records "
                  "v1 to v6 stay byte-identical")
ERA_SHA256 = MappingProxyType({
    "architecture/artifact-edges/README-v2.md": "0cded3e3499b8afe64c82a021a8a499c9b2fce5671ea5ae434b3330c26db3a2b",
    "architecture/artifact-edges/README-v3.md": "d6edd8cc7f8b209c1cf7bd0a16a941e0661ef040f8920cbdbda4c323c0f0f011",
    "architecture/artifact-edges/README-v4.md": "11e6bbefc27d82d359c7f48a873374786a760881693fd7d9ec7e88916ab2558b",
    "architecture/artifact-edges/README-v5.md": "6409a17c2fb0b5ae5df3055c86a3e4cb1e2cb3deacd490c4d547cc1d50a9b6ad",
    "architecture/artifact-edges/README-v6.md": "ce15ee36e15964a08fc83a495f2bd453ebe375c77e37d386f00c2803ec4e73f7",
    "architecture/artifact-edges/README-v7.md": "7131d500eac2085871254a250a4a84c24b17456891dd5f3b2478d85153f1a378",
    "architecture/artifact-edges/README.md": "5d62a665da2c6e75dce900cb4ef52e74aa14e537bdaeededb7568589339daa9f",
    "architecture/artifact-edges/operator-harness-engineering-v2.json": "749e70f174d638468bf45d7316e8f5201c3323f6348a78c7b9a22d3a571ccc32",
    "architecture/artifact-edges/operator-harness-engineering-v3.json": "106ea91aa09c2d377adf3b514a228331d6a805bd1a17e641ecaa23b3c39115f3",
    "architecture/artifact-edges/operator-harness-engineering-v4.json": "e30772ff8826650c46d1a8d384625929975e47f2de5cc9030680b5fdb5e7fc86",
    "architecture/artifact-edges/operator-harness-engineering-v5.json": "89b47ef8f865b31911eb8da2b08a5a3c22b2d92a62599cb6fdfccbfe7f79e3c0",
    "architecture/artifact-edges/operator-harness-engineering-v6.json": "0ac7c2da62de87837f5a36a967a2c5b9c286ecab2e03f335a8eebbd32df9d24d",
    "architecture/artifact-edges/operator-harness-engineering-v7.json": "6af45e361a66331a9ee0216d3eea42f3a17770fd3c7d33e78e2a025d301bfa92",
    "architecture/artifact-edges/operator-harness-engineering.json": "54bdc2d22676720419f51cd1bad5eedc909e6f848ed09cd363e351889af9d1fe",
    "architecture/i06-backend-profile-v3/README.md": "9ee406f43060f266a7b5dd2679aa8352f0815584c45e33d0ab193ea7f90c0c77",
    "architecture/i06-backend-profile-v3/REVIEW_BRIEF.md": "ca7bbf5e858c940b32058acf8475242fb1ad898afb92584bfac7f79914f93891",
    "architecture/i06-backend-profile-v3/criteria.json": "752533c57b5f93e4c4158a9c17b52eb88d236a3632ab0b66b669e8f8041f57c7",
    "architecture/i06-backend-profile-v3/source-index.json": "7740a01dcd1a9fe41a106532d5ddde37a1cce70e2244c6638d480953532a14c1",
    "architecture/i06-backend-profile-v3/vectors.json": "4752b648abdd82d21ea622a1b26c721143577478c0a2491204e0d584c1d6f081",
    "architecture/native-profile-v2/qualification.schema.json": "55bd641fd229f21e04ec00813bcfe600890584e982e290a210720ac5cb160ab0",
    "architecture/native-profile-v2/vectors.json": "6d58d1f36b7bce5739b94dd89512d358b96878c70e1de7cf8f399050b881b396",
    "architecture/native-profile-v3/qualification.schema.json": "ae5cbb6aa39f4edfa2d9919f25e55bad9ab214a99ca927c5afe7e2d943946ac5",
    "architecture/native-profile-v3/vectors.json": "14af47a69c972039294be8659c31332acd5326bfb0a3a38384a2c6bf9d11fe6d",
    "architecture/native-profile-v4/README.md": "a4205a5388dc83827bb39670bcc9477b030f29829128abf19f7578321c170174",
    "architecture/native-profile-v4/REVIEW_BRIEF.md": "293b9fc1f4affd9be0ff5d38bbc15dae902c22f5761a0ecdbc82d4f9c24fefea",
    "architecture/native-profile-v4/qualification.schema.json": "c3e91c087ebc6a13e8a96a066f80710ac968c8def434d1d1b97415811715ed10",
    "architecture/native-profile-v4/source-index.json": "6e2c325054ffd5edee3d71c4163dd38bef42b6b255bbdeae5e2c37814ef178fb",
    "architecture/native-profile-v4/status.json": "b998d1151cfe7fada1d4e30829064ceaad5d9c1220f407c6c865bc47c197143c",
    "architecture/native-profile-v4/vectors.json": "dede64ab3202a9e28094f062b5dad868c13ca02423e2380af8666ecf2e7a86e6",
    "architecture/native-profile-v5/README.md": "76b584ca769f0afdd5142fcf3f96e3b5b2d053a172d5713f970dc77594e77692",
    "architecture/native-profile-v5/qualification.schema.json": "70bda12463cee83301bc10fa6285023dc0e07b281a87ca70d44ec746cf262113",
    "architecture/native-profile-v5/review-round1.json": "0626a1f6f2bc878b25256dfa071b47ffe73f67a423c3c183e6b8d898235e8aab",
    "architecture/native-profile-v5/review-round2.json": "695cf190ea0f277b574f43b8c00ffdefeb20650403e7166319e5371524f7a44f",
    "architecture/native-profile-v5/review-round3.json": "3b5f9dec0c436618057910e8fb10257cb21cc363bc12ac7441be3831f33bcc32",
    "architecture/native-profile-v5/review-round4.json": "b8356184bd7ec0f4f50c9e6463ca6c6403e037d2f8a1eaa0a6bd3dcb552bda4f",
    "architecture/native-profile-v5/source-index.json": "68cd8f2777405b9a5c6605c99f96d03de317d0444c562f8b0b019a57a4f9fd08",
    "architecture/native-profile-v5/status.json": "13c78f09c5c50ae4f531b2cef69b4f735bc9499358db914dfdfbb1648fc7dad0",
    "architecture/native-profile-v5/vectors.json": "b630c362b20bfa7b362bb2ee28734a403303a0dc54b2d627c11a332b226333a1",
    "architecture/native-qualification-inputs/qualification.schema.json": "bef248bfa82b234124c014f98e40c5791bced3171bb118b7ed1bb7b8daaf95c3",
    "architecture/native-qualification-inputs/vectors.json": "cd1be009b721bb596887335184a33ab8e1f24aed8215477b63e28f058110748f",
    "architecture/repositories.yaml": "02190a668c6a9114b3733724bec4e552c553867e789b0802f6aaa6759148051d",
    "architecture/w03-obligation-amendment-3/amendment.json": "ddf5e9abd4c23d4fb09031693466079c68ea2a07c8068a5cdcde0b9bb7d2882b",
    "architecture/w03-plan-v2/plan.json": "a00470238431347da82cc47b1f1b6cf7cd51042d56694eea68d1373a3aaefb67",
    "scripts/i06_backend_profile.py": "bea3c953573478be5b03ab81b4ebd859da62d1eaa2a1be8f361b9dd39a98555e",
    "scripts/i06_backend_profile_v2.py": "58ceb7a6817aab512a56f9f2a614868ce27660d174be353c5629cc8de335e426",
    "scripts/i06_backend_profile_v3.py": "dfb00e90199d436ae63b79261f2e04870d7861cb0f7a424971657a4d777754de",
    "scripts/native_qualification_v2.py": "c72b6e18044f685c646756a1574bd81cd24f1475d7eda326778d70d1314ef68b",
    "scripts/native_qualification_v3.py": "2ef5c14ad5d8c962cf3703ccd076059685ed8dcc852059e4f863e8d9dc8965ad",
    "scripts/native_qualification_v4.py": "f7c718072d1ffbb9b8bbc310e6141d476ea5f25296f70ff8c1bc9ada3db02387",
    "scripts/native_qualification_v5.py": "d9926f4d18c82a5da31b903fea47c42319d29268a63a26171a7e71aa4c2480a5",
})
# Absolute local path markers, matched case-insensitively; spelled in parts, so this file holds none of them.
LOCAL_PATH_MARKERS = (b"/" + b"users/", b"/" + b"private/", b".local" + b"/state")
# The evidenceClasses cross-check's scope (README "Open items"), in its docstring and its refusal messages.
EVIDENCE_SCOPE = ("README 'Open items': evidenceClasses agrees with the v5 model as native-profile v4's layer checks v4's "
                  "- each role's capture class, for every capability set the record schema admits, against its column, "
                  "and every exact capture path the class tables name, probed through the v5 model's capture checks "
                  "(deleted where its class requires it, added where its class forbids it, so each host field present "
                  "in a capture is refused) - and its eight OUT_OF_SCOPE_HOST rows name exactly the four proofs of the "
                  "status record's hostProofs; the remaining cells, which name no exact path, are prose pinned by the "
                  "schema digest.")
EVIDENCE_COLUMNS = MappingProxyType({"OBSERVED_TARGET": "OBSERVED", "LABEL_BOUND_TARGET": "LABEL_BOUND",
                                     "OBSERVER_OWN": "DECLARED_T04"})
CAPABILITY = "CAP_NET_BIND_SERVICE"
TARGET_SUFFIXES = (("", None), (" (its own capture)", None),
                   (" whose recorded capabilities include " + CAPABILITY, True),
                   (" whose recorded capabilities exclude " + CAPABILITY, False))
EVIDENCE_TABLES = ("capture", "lifecycleCapture", "backendCapture")
EVIDENCE_KEYS = frozenset({"classes", "captureTargets", "capture", "lifecycleCapture", "backendCapture", "capturer"})
ABSENCE_NOTES = ("", "; corroborated by process.seccompFilters and cgroupMembers[].seccompFilters", "; no corroboration")
PROSE_FIELDS = MappingProxyType({
    "cgroupMembers[] (process fields)": "a group of every member's process fields",
    "process.cgroup (inode, limits)": "a group of the role cgroup's fields",
    "cgroupMembers (count)": "a count, not a path",
    "files[] (device, inode, uid, gid, nlink, contentDigest, measuredVerity)": "a group of the file measurements' fields",
    "bpfPrograms.*.pinLabel": "a wildcard over the hooks",
    "bpfPrograms.*.program.pinLabel": "a wildcard over the hooks",
    "sealMarker (path, digest, uid, mode)": "a group of the seal marker's fields",
    "process (pid, startTicks, processLabel, cgroupPath)": "a group of the backend process's fields",
    "executable (path, contentDigest, measuredVerity)": "a group of the backend executable's fields"})
# An added field carries the record's declared value: the role's own field, the seal marker's label, the label of the
# file the capture's first file entry names; a field the record does not declare there carries its value in another
# capture of the same positive that holds it, and a dropped host field the value native-profile v4's same positive
# capture holds (filled from the record, owner Q-HE4D1-1 (a)).
DECLARED_ROLE_FIELDS = MappingProxyType({
    "process.uid": ("uid",), "process.gid": ("gid",), "process.processLabel": ("processLabel",),
    "process.namespaceInodes": ("namespaceInodes",), "process.seccompMode": ("seccompMode",),
    "process.noNewPrivs": ("noNewPrivs",), "process.capPermitted": ("capabilities",),
    "process.capEffective": ("capabilities",), "process.capBounding": ("capabilities",),
    "process.rlimitCore": ("rlimitCore",), "process.seccompFilterDigest": ("seccompFilterDigest",),
    "process.seccompDefaultAction": ("seccompDefaultAction",), "process.cgroup.path": ("cgroup", "path"),
    "process.cgroup.selinuxLabel": ("cgroup", "selinuxLabel")})
DECLARED_SEAL_LABEL = ("sealMarker.selinuxLabel",)
DECLARED_FILE_LABEL = "files[].entry.selinuxLabel"
ROLE_SCOPED_FIELDS = MappingProxyType({"cgroupFrozenBefore": ("WORKER",), "cgroupFrozenAfter": ("WORKER",)})
CAPTURE_ROLES = ("SERVER", "OBSERVER", "BROKER", "WORKER", "EFFECT_GATE")
# The fields v5 drops from each capture variant (README "The host facts"), restated against the model's HOST_FIELDS;
# each is a class-table row of its own (or with the fields its proof covers) whose every cell is HOST_CELL.
HOST_FIELDS = MappingProxyType({"capture": ("host", "selinuxBefore", "selinuxAfter", "kernelPolicyDigest", "booleansObserved",
                                            "hardeningObserved", "bootEntryObserved"),
                                "lifecycleCapture": ("host", "booleansObserved", "bootEntryObserved"),
                                "backendCapture": ("host",)})
HOST_CELL = "OUT_OF_SCOPE_HOST (absent)"
# Each dropped field's proof (README "The host facts"): every host row names its fields' one proof.
FIELD_PROOFS = MappingProxyType({"host": "T04-HOST-BOOT", "selinuxBefore": "T04-POLICY-STABLE",
                                 "selinuxAfter": "T04-POLICY-STABLE", "kernelPolicyDigest": "T04-POLICY-STABLE",
                                 "booleansObserved": "T04-HOST-LOCKS", "hardeningObserved": "T04-HOST-LOCKS",
                                 "bootEntryObserved": "T04-BOOT-ENTRY"})
HOST_ROWS = MappingProxyType({"capture": 4, "lifecycleCapture": 3, "backendCapture": 1})


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
    """reviewed_bytes, checked against its era digest on every read; a path outside the era is refused before it is
    read."""
    expected = ERA_SHA256.get(path) if type(path) is str else None
    require(expected is not None, "MET-ENFORCE-038 reviewed bytes are bound: " + str(path))
    raw = reviewed_bytes(path)
    require(type(raw) is bytes and digest(raw) == expected, "unreviewed NATIVE-PROFILE-V5 source: " + path)
    return raw


def _json(path: str) -> Any:
    return parse(_verified(path))


def _holds(check: Any) -> bool:
    """A structural check over a module's result or this era's data; a malformed value does not hold."""
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


def _texts(values: Any) -> bool:
    return type(values) is list and len(values) > 0 and all(type(text) is str and text.strip() != "" for text in values)


def _dump(value: Any) -> bytes:
    """A record's bytes as the contract builder writes them (indent 1, UTF-8, a final newline)."""
    return (json.dumps(value, indent=1, ensure_ascii=False) + "\n").encode("utf-8")


def _era_import(era: dict) -> Any:
    """An import function that resolves the named modules to this era's copies and everything else normally."""
    def era_import(name, globals=None, locals=None, fromlist=(), level=0):
        if level == 0 and name in era:
            return era[name]
        return builtins.__import__(name, globals, locals, fromlist, level)
    return era_import


def _era_model(path: str, name: str, imports: dict | None = None) -> types.ModuleType:
    """A reference module of this era, executed from its verified bytes (no import, no bytecode); named imports resolve
    to this era's copies."""
    module = types.ModuleType(name)
    module.__file__ = str(ROOT / path)
    if imports:
        namespace = dict(vars(builtins))
        namespace["__import__"] = _era_import(imports)
        module.__dict__["__builtins__"] = namespace
    exec(compile(_verified(path), path, "exec", dont_inherit=True), module.__dict__)
    return module


def era_modules() -> types.SimpleNamespace:
    """This era's native-profile v4 model and the v5 model with it as its import."""
    np4 = _era_model(NP4_MODEL, "_met_enforce_038_native_qualification_v4")
    np5 = _era_model(NP5_MODEL, "_met_enforce_038_native_qualification_v5", {"native_qualification_v4": np4})
    require(np5.v4 is np4, "native-profile v5 runs this era's native-profile v4 model")
    return types.SimpleNamespace(np4=np4, np5=np5)


def validate_freeze() -> None:
    """E1-7: native-profile v4's and I06 v3's models are these bytes at these exact paths; no file this packet changes or
    adds is a frozen path, sits under a predecessor's directory, or is an edge record other than v7's two files."""
    for path, expected in MODEL_FREEZE.items():
        require(ERA_SHA256.get(path) == expected and digest(_verified(path)) == expected,
                "native-profile v4's and I06 v3's models are frozen by exact path and digest: " + path)
    for path in list(_PROJECTION_RULES) + list(authority()["newFiles"]):
        require(path not in FROZEN_PATHS and not path.startswith(FROZEN_PREFIXES)
                and (not path.startswith(EDGES_DIR) or path in (V7_EDGE, V7_README)), FROZEN_MESSAGE)


def validate_contract_files() -> None:
    """The packet adds the contract's files as new files, each once; the contract directory holds exactly its files;
    every contract file is a regular file of git mode 100644, not a link and not executable; and none holds an absolute
    local path."""
    new = authority()["newFiles"]
    require(len(set(NEW_FILES)) == len(NEW_FILES) and not set(NEW_FILES) & set(_PROJECTION_RULES)
            and {path for path in new if path.startswith(NP5_DIR) or path in (NP5_MODEL, V7_EDGE, V7_README)}
            == set(NEW_FILES), "the contract's files are new in this packet, each once")
    require(stat.S_ISDIR(reviewed_mode(NP5_DIR[:-1])), "the contract directory is a directory, not a link")
    tree = reviewed_tree(NP5_DIR)
    require(set(tree) == CONTRACT_TREE, "the contract directory holds exactly its files")
    for path in NEW_FILES:
        mode = reviewed_mode(path)
        require(stat.S_ISREG(mode) and not mode & 0o111, "a contract file is a regular file of git mode 100644: " + path)
        raw = _verified(path).lower()
        require(not any(marker in raw for marker in LOCAL_PATH_MARKERS),
                "no absolute local path in a file this packet adds: " + path)


def candidate_status(status: dict) -> bytes:
    """The status record without its adoption fields and with candidate 4's values restored: candidate 4's bytes exactly
    when the adoption only added those fields."""
    reverted = {key: value for key, value in status.items() if key not in ADOPTION_KEYS}
    reverted.update(CANDIDATE_VALUES)
    reverted["carried"] = [{"item": row["item"], "to": row["to"]} for row in status["carried"][ADOPTION_CARRIED:]]
    reverted["nonClaims"] = status["nonClaims"][:CANDIDATE_NON_CLAIMS]
    reverted["rounds"] = [{key: row[key] for key in ROUND_KEYS[:4]} for row in status["rounds"][:3]]
    return _dump(reverted)


def validate_adoption() -> dict:
    """Adopted after four independent review rounds, each bound to its published record and its subject candidate's
    exact files; the adopted files are candidate 4's bytes except edge record v7's three providerPacket values and the
    status record's adoption fields; the closed findings are the later rounds' resolutions."""
    status = _json(STATUS_PATH)
    _bound(lambda: type(status) is dict and tuple(status) == STATUS_KEYS
           and status["schemaVersion"] == "planeon.internal.native-profile-v5-status/v1"
           and status["workItem"] == "NATIVE-PROFILE-V5" and status["packet"] == NEW_PACKET and status["slot"] == 252
           and status["status"] == "ADOPTED" and status["candidate"] == 4 and status["adoption"] == ADOPTION
           and status["baseMain"] == BASE_COMMIT and status["reviewBase"] == REVIEW_BASE
           and status["independentReviewer"] == "SEPARATE_AGENT_NOT_AUTHOR"
           and all(type(status[key]) is str and status[key].strip() != "" for key in ("readmeStatusNote", "recordPaths"))
           and "no README line moved" in status["readmeStatusNote"]
           and status["closedFindings"] == CLOSED_FINDINGS and tuple(status["closedFindings"]) == tuple(CLOSED_FINDINGS)
           and status["nonClaims"] == NON_CLAIMS and type(status["carried"]) is list
           and all(type(row) is dict and tuple(row) == ("item", "to", "action") and type(row["action"]) is str
                   and row["action"].strip() != "" for row in status["carried"])
           and [(row["item"], row["to"]) for row in status["carried"]] == list(CARRIED)
           and [row["proof"] for row in status["hostProofs"]] == list(HOST_PROOFS),
           "adopted NATIVE-PROFILE-V5 status")
    _bound(lambda: digest(candidate_status(status)) == CANDIDATE_SHA256[STATUS_PATH],
           "the status record is candidate 4's with only the adoption fields added")
    for path in SUBJECT:
        if path != V7_EDGE:
            require(digest(_verified(path)) == CANDIDATE_SHA256[path], "the adopted files are candidate 4: " + path)
    edge = _verified(V7_EDGE)
    _bound(lambda: edge.count(ASSIGNED) == 3 and TBD not in edge and edge.count(b"\n") == CANDIDATE_LINES
           and digest(edge.replace(ASSIGNED, TBD)) == CANDIDATE_SHA256[V7_EDGE],
           "edge record v7 is candidate 4 with exactly three providerPacket values set, on the same lines")
    edit = status["adoptionEdit"]
    _bound(lambda: type(status["adoptedSubject"]) is dict and tuple(status["adoptedSubject"]) == SUBJECT
           and status["adoptedSubject"] == {path: digest(_verified(path)) for path in SUBJECT}
           and type(edit) is dict and tuple(edit) == EDIT_KEYS
           and edit == {"path": V7_EDGE, "replaced": TBD.decode("ascii"), "with": ASSIGNED.decode("ascii"), "count": 3,
                        "rows": [row[0] for row in NEW_ROWS if row[1] is None],
                        "candidateSha256": CANDIDATE_SHA256[V7_EDGE], "adoptedSha256": digest(edge),
                        "lineCount": CANDIDATE_LINES},
           "the status records the adopted files and the one adoption edit")
    rounds = status["rounds"]
    _bound(lambda: type(rounds) is list and len(rounds) == len(ROUNDS)
           and all(type(row) is dict and tuple(row) == ROUND_KEYS for row in rounds)
           and [(row["round"], row["verdict"], row["subjectBuilderSha256"], row["record"], row["candidate"])
                for row in rounds] == [(number, verdict, builder, RECORDS[number - 1], number)
                                       for number, verdict, builder, _ids in ROUNDS],
           "four review rounds in order, the last on the adopted candidate 4")
    records = []
    for (number, verdict, builder, ids), row in zip(ROUNDS, rounds):
        record = _json(row["record"])
        path, label = SUBJECT_NAMES[number]
        _bound(lambda: type(record) is dict and digest(_verified(row["record"])) == row["recordSha256"]
               and type(row["subjectSha256"]) is dict and tuple(row["subjectSha256"]) == CANDIDATE_FILES
               and row["subjectSha256"] == dict(ROUND_SUBJECTS[number])
               and record["round"] == number and record["verdict"] == verdict
               and record["subject"] == SUBJECT_LINE % (number, builder, label, ROUND_SUBJECTS[number][path])
               and record["reviewer"] == "independent agent" and record["actions"] == ACTIONS
               and tuple(finding["id"] for finding in record["findings"]) == ids
               and row["severities"] == sorted({finding["severity"] for finding in record["findings"]}),
               "review round %d is bound to its record and its subject candidate" % number)
        records.append(record)
    _bound(lambda: rounds[-1]["subjectSha256"] == dict(CANDIDATE_SHA256)
           and rounds[2]["severities"] == rounds[3]["severities"] == ["NOTE"],
           "the passing rounds left NOTEs only, and the last reviewed candidate 4")
    second, third, fourth = records[1:]
    resolved2 = {item["id"]: item["status"] for item in second["roundOneDispositions"]}
    resolved3 = {item["id"]: item["status"] for item in third["roundTwoDispositions"]}
    first_closure = {"RESOLVED": "CLOSED in round 2", "PARTLY": "CLOSED in round 3", "OPEN_BY_DESIGN": "CLOSED in round 4"}
    _bound(lambda: list(CLOSED_FINDINGS) == [name for row in ROUNDS for name in row[3]]
           and tuple(resolved2) == ROUNDS[0][3] and tuple(resolved3) == ROUNDS[1][3]
           and all(CLOSED_FINDINGS[name].split(" (")[0] == first_closure[resolved2[name]] for name in ROUNDS[0][3])
           and all(resolved3[name] == "RESOLVED" and CLOSED_FINDINGS[name] == "CLOSED in round 3" for name in ROUNDS[1][3])
           and all(CLOSED_FINDINGS[name].startswith("CLOSED in round 4 (") for name in ROUNDS[2][3])
           and all(CLOSED_FINDINGS[name].startswith("CARRIED ") for name in ROUNDS[3][3])
           and any(check["check"].startswith("Q03 (Q-NPE-9 (a))") and check["result"].startswith("PASS")
                   for check in fourth["checks"])
           and any(check["check"] == "E3-1" and check["result"].startswith("PASS") for check in fourth["checks"]),
           "the closed findings are the later rounds' resolutions")
    return status


def validate_source_index(status: dict) -> None:
    """The source index is round 4 over the review base; its earlier rounds are the status record's rounds 1 to 3; and
    every pin it holds (subject and predecessor inputs) holds over this era's bytes."""
    index = _json(NP5_INDEX)
    _bound(lambda: type(index) is dict and tuple(index) == INDEX_KEYS
           and index["schemaVersion"] == "planeon.internal.native-profile-v5-index/v1" and index["round"] == 4
           and index["baseMain"] == REVIEW_BASE and index["baseTree"] == REVIEW_BASE_TREE
           and tuple(row["path"] for row in index["subject"]) == INDEX_SUBJECT
           and tuple(row["path"] for row in index["predecessorInputs"]) == INDEX_INPUTS
           and index["earlierRounds"] == [{key: row[key] for key in ROUND_KEYS[:4]} for row in status["rounds"][:3]],
           "the source index is round 4 over the review base; rounds 1 to 3 are the published records")
    for key in ("subject", "predecessorInputs"):
        for row in index[key]:
            _bound(lambda: type(row) is dict and tuple(row) == ("path", "sha256") and row["path"] in ERA_SHA256
                   and digest(_verified(row["path"])) == row["sha256"],
                   "every source-index pin holds: %s" % (row.get("path") if type(row) is dict else row,))


def validate_edge_record_v7() -> None:
    """Edge record v7 supersedes v6 by its digest and packet and keeps v6's edge, rules, statuses and 56 rows exactly and
    in order; each of its six new rows registers its provider file's exact bytes and mode before use, under the R10
    contracts directory: the three files this packet publishes with providerCommit null and providerPacket NEW_PACKET,
    the three history vectors at their last-change commits."""
    v6, v7 = _json(V6_EDGE), _json(V7_EDGE)
    _bound(lambda: digest(_verified(V6_EDGE)) == EDGE_V6_SHA256 and type(v7) is dict and tuple(v7) == EDGE_KEYS
           and v7["schemaVersion"] == v6["schemaVersion"] == "planeon.internal.artifact-edge-registry/v2"
           and all(v7[key] == v6[key] for key in ("graph", "consumer", "provider", "ownerDecision", "rules",
                                                   "notArtifacts", "statuses"))
           and v7["supersedes"] == {"path": V6_EDGE, "sha256": "sha256:" + EDGE_V6_SHA256, "packet": V6_PACKET}
           and v7["artifact"] == EDGE_ARTIFACT and _texts(v7["ownerDecisions"]) and _texts(v7["notes"]),
           "edge record v7 supersedes v6 by its digest and packet and keeps v6's edge, rules and statuses")
    _bound(lambda: len(v6["artifacts"]) == V6_ROWS and v7["artifacts"][:V6_ROWS] == v6["artifacts"]
           and all(list(row) == list(old) for row, old in zip(v7["artifacts"], v6["artifacts"]))
           and len(v7["artifacts"]) == V6_ROWS + len(NEW_ROWS),
           "edge record v7 carries v6's 56 rows exactly and in order")
    for number, (row, (path, commit, consumer, packet)) in enumerate(zip(v7["artifacts"][V6_ROWS:], NEW_ROWS),
                                                                      V6_ROWS + 1):
        published = commit is None
        _bound(lambda: tuple(row) == EDGE_ROW_KEYS + (("providerPacket",) if published else ())
               and row["providerPath"] == path and row["providerCommit"] == commit
               and published == (path in NEW_FILES) and (not published or row["providerPacket"] == NEW_PACKET)
               and row["consumerPath"] == consumer and consumer.startswith(CONSUMER_PREFIX)
               and row["consumerPacket"] == packet and row["relation"] == "BYTE_IDENTICAL"
               and row["status"] == "REGISTERED_BEFORE_USE"
               and row["sha256"] == digest(_verified(path)) and row["mode"] == _git_mode(reviewed_mode(path)) == "100644",
               "edge record v7 row %d registers its provider's exact bytes and mode before use: %s" % (number, path))
    providers = [row["providerPath"] for row in v7["artifacts"]]
    consumers = [row["consumerPath"] for row in v7["artifacts"][V6_ROWS:]]
    _bound(lambda: len(set(providers)) == len(providers) and len(set(consumers)) == len(consumers)
           and not set(consumers) & {row["consumerPath"] for row in v6["artifacts"]},
           "each provider path, and each new consumer path, is registered once")


def _evidence_message(detail: str) -> str:
    return "evidenceClasses against the model: %s. %s" % (detail, EVIDENCE_SCOPE)


def schema_admitted(record_schema: dict) -> dict:
    """Per capture role, the CAP_NET_BIND_SERVICE values (recorded or not) of the capability sets the record schema
    (native-profile v4's) admits, read from each role's capabilities constant or enum."""
    admitted = {}
    for role in CAPTURE_ROLES:
        rule = record_schema["$defs"]["roles"]["properties"][role]["properties"]["capabilities"]
        sets = rule["enum"] if set(rule) == {"enum"} else [rule["const"]] if set(rule) == {"const"} else None
        admitted[role] = sorted({CAPABILITY in capabilities for capabilities in sets})
    return admitted


def _target_pairs(text: Any, admitted: dict) -> list:
    """The (role, CAP_NET_BIND_SERVICE recorded) pairs one captureTargets text lists, read with the closed grammar."""
    require(type(text) is str, "captureTargets text")
    pairs = []
    for item in text.split("; "):
        read = [(role, holds) for role in CAPTURE_ROLES for suffix, holds in TARGET_SUFFIXES if item == role + suffix]
        require(len(read) == 1, "captureTargets text outside the grammar")
        role, holds = read[0]
        require(holds is None or holds in admitted[role], "a condition naming a capability set the schema forbids")
        pairs += [(role, value) for value in (admitted[role] if holds is None else (holds,))]
    return pairs


def _capture_path(field: Any) -> tuple | None:
    """The capture path a field names exactly: dot-separated names, a name ending in [] standing for each element
    (probed on the first); None for any other text."""
    if type(field) is not str:
        return None
    path: list = []
    for name in field.split("."):
        each = name.endswith("[]")
        name = name[:-2] if each else name
        if not (name and name.isascii() and name.isalpha()):
            return None
        path += [name, 0] if each else [name]
    return tuple(path)


def _cell_present(cell: Any, classes: Any) -> bool:
    """A class-table cell read with the closed grammar: True for a class alone (the field is in the capture), False for
    a class marked absent with a listed note (it is not); any other cell refuses."""
    require(type(cell) is str and type(classes) is list, "class table cell")
    if cell in classes:
        return True
    marked = [name for name in classes for note in ABSENCE_NOTES if cell == name + " (absent" + note + ")"]
    require(len(marked) == 1, "class table cell outside the grammar")
    return False


def evidence_cells(table: dict) -> tuple[list, list]:
    """Every row field of the three class tables, read with the closed grammar: the exact capture paths, each with
    (table, row number, field, path, presence per P1 column or None), and the prose fields (table, row number, field)."""
    exact, prose = [], []
    for name in EVIDENCE_TABLES:
        for number, row in enumerate(table[name], 1):
            cells = ({column: row[column] for column in EVIDENCE_COLUMNS} if name == "capture" else {None: row["class"]})
            presence = {column: _cell_present(cell, table["classes"]) for column, cell in cells.items()}
            require(type(row["fields"]) is list and len(row["fields"]) > 0, "class table row")
            for field in row["fields"]:
                path = _capture_path(field)
                require(field in PROSE_FIELDS or path is not None,
                        "a class table field neither an exact capture path nor listed prose")
                if field in PROSE_FIELDS:
                    prose.append((name, number, field))
                else:
                    exact.append((name, number, field, path, presence))
    return exact, prose


def _has(value: Any, path: tuple) -> bool:
    for key in path:
        if not ((type(value) is dict and key in value) or (type(value) is list and type(key) is int and key < len(value))):
            return False
        value = value[key]
    return True


def _at(value: Any, path: tuple) -> Any:
    for key in path:
        value = value[key]
    return value


def _declared(record: dict, role: str | None, field: str, capture: dict, others: list) -> Any:
    """The value an added field carries: the record's declared value, or, where the record declares none, the value in
    another capture of the same positive (or, last, native-profile v4's same positive capture) that holds the field."""
    if field in DECLARED_ROLE_FIELDS:
        return _at(record["roles"][role], DECLARED_ROLE_FIELDS[field])
    if field in DECLARED_SEAL_LABEL:
        return record["hardening"]["sealMarker"]["selinuxLabel"]
    if field == DECLARED_FILE_LABEL:
        path = capture["files"][0]["entry"]["path"]
        rows = [row for row in record["files"] if row["path"] == path]
        require(len(rows) == 1, "the record declares the file")
        return rows[0]["selinuxLabel"]
    path = _capture_path(field)
    holders = [other for other in others if path is not None and _has(other, path)]
    require(len(holders) > 0, "another capture holds the field")
    return _at(holders[0], path)


def _probe(capture: dict, path: tuple, value: Any, delete: bool) -> dict:
    """The capture with one field deleted, or added with the given value; only the containers on the path are copied,
    so the positive is never changed."""
    probe = dict(capture)
    node = probe
    for key in path[:-1]:
        child = node[key]
        child = list(child) if type(child) is list else dict(child)
        node[key] = child
        node = child
    if delete:
        del node[path[-1]]
    else:
        node[path[-1]] = copy.deepcopy(value)
    return probe


def validate_host_rows(m: types.SimpleNamespace, status: dict) -> None:
    """The class table's eight OUT_OF_SCOPE_HOST rows: every cell of each reads HOST_CELL, their fields are exactly the
    model's dropped fields per variant, each names its fields' one proof (FIELD_PROOFS), and together they name exactly
    the four proofs of the status record's hostProofs."""
    table = {}
    _bound(lambda: table.update(_json(NP5_SCHEMA)["$defs"]["evidenceClasses"]["const"]) is None
           and dict(m.np5.HOST_FIELDS) == dict(HOST_FIELDS) and "OUT_OF_SCOPE_HOST" in table["classes"],
           _evidence_message("the dropped fields are the model's"))
    proofs = []
    for name in EVIDENCE_TABLES:
        def cells(row: dict) -> list:
            return [row[column] for column in EVIDENCE_COLUMNS] if name == "capture" else [row["class"]]
        rows = [row for row in table[name] if HOST_CELL in cells(row)]
        _bound(lambda: len(rows) == HOST_ROWS[name] and all(set(cells(row)) == {HOST_CELL} for row in rows)
               and sorted(field for row in rows for field in row["fields"]) == sorted(HOST_FIELDS[name])
               and all(type(row["proofs"]) is list and len(row["proofs"]) == 1
                       and all(FIELD_PROOFS[field] == row["proofs"][0] for field in row["fields"]) for row in rows),
               _evidence_message("the %s host rows hold exactly the dropped fields, each row its fields' one proof"
                                 % name))
        proofs += [row["proofs"][0] for row in rows]
    _bound(lambda: len(proofs) == sum(HOST_ROWS.values()) and set(proofs) == set(HOST_PROOFS) == set(FIELD_PROOFS.values())
           == {row["proof"] for row in status["hostProofs"]},
           _evidence_message("the eight host rows name exactly the four proofs of hostProofs"))


def validate_evidence_classes(m: types.SimpleNamespace) -> None:
    """The v5 schema's evidenceClasses constant against this era's v5 model, through the model's own functions.
    README 'Open items': evidenceClasses agrees with the v5 model as native-profile v4's layer checks v4's - each role's capture class, for every capability set the record schema admits, against its column, and every exact capture path the class tables name, probed through the v5 model's capture checks (deleted where its class requires it, added where its class forbids it, so each host field present in a capture is refused) - and its eight OUT_OF_SCOPE_HOST rows name exactly the four proofs of the status record's hostProofs; the remaining cells, which name no exact path, are prose pinned by the schema digest.
    (a) capture_class (v4's, bound in v5), called for the 5 roles on every positive record with each capability set the
    record schema admits for the role, gives the class EVIDENCE_COLUMNS fixes for the column whose captureTargets text,
    read with the closed grammar, lists that role and capability set; the columns list every admitted role and set
    exactly once. (b) Every row field of the three class tables is an exact capture path or a listed prose field, and
    every cell is a class alone or marked absent. On every v5 positive, whose captures the model accepts, each exact path
    is probed through the v5 model's check for its capture: deleted where its cell requires the field, added where its
    cell forbids it (with the record's declared value, another capture's, or native-profile v4's same positive capture's),
    each of which must be refused; the WORKER-only frozen bracket's two paths are probed on the WORKER captures only.
    For the CONSISTENCY_ONLY and ENTRY_BOUND cells the probes test presence only, not the consistency those classes
    state."""
    schema, record_schema = _json(NP5_SCHEMA), _json(NP4_SCHEMA)
    positives, sources = _json(NP5_VECTORS)["positive"], _json(NP4_VECTORS)["positive"]
    table, pairs, admitted = {}, {}, {}
    _bound(lambda: table.update(schema["$defs"]["evidenceClasses"]["const"]) is None and set(table) == EVIDENCE_KEYS
           and all(type(table[name]) is list and all(type(row) is dict for row in table[name]) for name in EVIDENCE_TABLES)
           and admitted.update(schema_admitted(record_schema)) is None
           and tuple(m.np5.ROLES) == CAPTURE_ROLES and tuple(table["captureTargets"]) == tuple(EVIDENCE_COLUMNS)
           and set(EVIDENCE_COLUMNS.values()) <= set(table["classes"]) and len(positives) == len(sources) > 0,
           _evidence_message("the capture columns are the fixed column-to-class map"))
    for column in EVIDENCE_COLUMNS:
        _bound(lambda: pairs.update({column: _target_pairs(table["captureTargets"][column], admitted)}) is None,
               _evidence_message("captureTargets text outside the closed grammar or naming a capability set the schema "
                                 "forbids: " + column))
    named = [pair for rows in pairs.values() for pair in rows]
    _bound(lambda: len(named) == len(set(named))
           and set(named) == {(role, holds) for role in CAPTURE_ROLES for holds in admitted[role]},
           _evidence_message("the capture columns list every role and admitted capability set exactly once"))

    def decided(p: dict, role: str, holds: bool) -> Any:
        row = p["record"]["roles"][role]
        capabilities = [name for name in row["capabilities"] if name != CAPABILITY] + ([CAPABILITY] if holds else [])
        record = dict(p["record"], roles=dict(p["record"]["roles"], **{role: dict(row, capabilities=capabilities)}))
        return m.np5.capture_class(record, role)

    for column, rows in pairs.items():
        for role, holds in rows:
            _bound(lambda: all(decided(p, role, holds) == EVIDENCE_COLUMNS[column] for p in positives),
                   _evidence_message("capture_class decides the role's column: %s %s %s, listed in %s"
                                     % (role, "with" if holds else "without", CAPABILITY, column)))
    for name in EVIDENCE_TABLES:
        for number, row in enumerate(table[name], 1):
            _bound(lambda: evidence_cells(dict(table, **{other: [] for other in EVIDENCE_TABLES if other != name},
                                               **{name: [row]})) is not None,
                   _evidence_message("a class table row outside the closed grammar: %s row %d" % (name, number)))
    exact, prose = evidence_cells(table)
    _bound(lambda: sorted(field for _name, _number, field in prose) == sorted(PROSE_FIELDS),
           _evidence_message("the prose fields are exactly the listed ones"))
    _bound(lambda: set(ROLE_SCOPED_FIELDS) <= {field for name, _number, field, _path, _presence in exact if name == "capture"}
           and all(set(roles) <= set(CAPTURE_ROLES) for roles in ROLE_SCOPED_FIELDS.values()),
           _evidence_message("the role-scoped fields are exact P1 paths of known roles"))
    scoped_probes = {field: 0 for field in ROLE_SCOPED_FIELDS}
    columns = {name: column for column, name in EVIDENCE_COLUMNS.items()}

    def refuses(check: Any, *args: Any) -> bool:
        return m.np5.explain(check, *args) is not None

    for p, source in zip(positives, sources):
        record = p["record"]
        for capture in p["captures"]:
            role, column = capture["role"], []
            own = [other for other in source["captures"] if other["role"] == role]
            _bound(lambda: column.append(columns[m.np5.capture_class(record, role)]) is None and len(own) == 1
                   and m.np5.explain(m.np5.check_capture, record, capture, role, record_schema, schema) is None,
                   _evidence_message("check_capture accepts the positive capture: " + role))
            for name, _number, field, path, presence in exact:
                if name != "capture" or role not in ROLE_SCOPED_FIELDS.get(field, CAPTURE_ROLES):
                    continue
                if field in scoped_probes:
                    scoped_probes[field] += 1
                required = presence[column[0]]
                _bound(lambda: refuses(m.np5.check_capture, record, _probe(
                           capture, path, None if required else _declared(record, role, field, capture,
                                                                          p["captures"] + own), required),
                           role, record_schema, schema),
                       _evidence_message("check_capture refuses %s %s for %s" % (field, "deleted" if required else "added",
                                                                                role)))
        _bound(lambda: all(count > 0 for count in scoped_probes.values()),
               _evidence_message("every role-scoped field is probed on its roles' captures"))
        lifecycle = p["lifecycle"]
        _bound(lambda: m.np5.explain(m.np5.check_lifecycle_capture, record, lifecycle, record_schema, schema) is None,
               _evidence_message("check_lifecycle_capture accepts the positive lifecycle capture"))
        for name, _number, field, path, presence in exact:
            if name != "lifecycleCapture":
                continue
            required = presence[None]
            _bound(lambda: refuses(m.np5.check_lifecycle_capture, record, _probe(
                       lifecycle, path, None if required else _declared(record, None, field, lifecycle,
                                                                        [source["lifecycle"]]), required),
                       record_schema, schema),
                   _evidence_message("check_lifecycle_capture refuses %s %s" % (field, "deleted" if required else "added")))
        for backend in p["backendCaptures"]:
            component = backend["component"]
            own = [other for other in source["backendCaptures"] if other["component"] == component]
            _bound(lambda: len(own) == 1
                   and m.np5.explain(m.np5.check_backend_capture, record, backend, record_schema, schema) is None,
                   _evidence_message("check_backend_capture accepts the positive backend capture: " + str(component)))
            for name, _number, field, path, presence in exact:
                if name != "backendCapture":
                    continue
                required = presence[None]
                _bound(lambda: refuses(m.np5.check_backend_capture, record, _probe(
                           backend, path, None if required else _declared(record, None, field, backend, own), required),
                           record_schema, schema),
                       _evidence_message("check_backend_capture refuses %s %s for %s"
                                         % (field, "deleted" if required else "added", component)))


def replay_model(m: types.SimpleNamespace) -> None:
    """The v5 model replays every vector over its pinned inputs, read through this era's verified bytes."""
    vectors = _json(NP5_VECTORS)
    _bound(lambda: dict(m.np5.V5_INPUTS) == NP5_INPUTS and m.np5.SCHEMA_PATH == NP5_SCHEMA
           and dict(m.np5.VECTOR_COUNTS) == NP5_COUNTS and {key: len(vectors[key]) for key in NP5_COUNTS} == NP5_COUNTS,
           "the model's pinned inputs and the vectors' counts")
    files = {path: _verified(path) for path in list(NP5_INPUTS.values()) + [NP5_SCHEMA]}
    _bound(lambda: m.np5.check_vectors(vectors, files) == NP5_CHECKS,
           "native-profile v5 replays every vector over its pinned inputs")


def validate_native_profile_v5() -> None:
    """Every reviewed byte first; then the freeze, the contract's files, the adoption record, the source index and edge
    record v7; then the v5 model from this era's bytes, the class table against it and its replay; last, this layer's
    canonical hunks."""
    for path in ERA_SHA256:
        _verified(path)
    validate_freeze()
    validate_contract_files()
    status = validate_adoption()
    validate_source_index(status)
    validate_edge_record_v7()
    models = era_modules()
    validate_host_rows(models, status)
    validate_evidence_classes(models)
    replay_model(models)
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
            == record["validatorNormalizedSha256"], "native profile v5 validator drift")
    paths = sorted((ROOT / "task-packets").glob("*.yaml"))
    old = set(record["baselinePackets"])
    require(len(paths) == 257
            and {path.stem for path in paths} == old | {NEW_PACKET, successor.NEW_PACKET, successor.successor.NEW_PACKET, successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.NEW_PACKET},
            "closed 257-packet catalog retaining the 252-packet checkpoint")
    packets = {}
    for path in paths:
        if path.stem in (successor.NEW_PACKET, successor.successor.NEW_PACKET, successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.NEW_PACKET):
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
            "closed source-only native-profile-v5 packet and inherited commands")
    require(len(packet["allowedPaths"]) == len(set(packet["allowedPaths"]))
            and set(packet["allowedPaths"]) == set(record["changedFiles"])
            | set(record["newFiles"]) | {AUTHORITY_PATH, VALIDATOR_PATH,
                                         "task-packets/" + NEW_PACKET + ".yaml"},
            "unreviewed or omitted native-profile-v5 packet path")
    for path, rule in record["changedFiles"].items():
        current = successor.historical_bytes(path, regular_bytes(path))
        require(digest(current) == rule["afterSha256"]
                and digest(historical_bytes(path, current)) == rule["beforeSha256"],
                "unreviewed current source: " + path)
    for path, expected in record["newFiles"].items():
        require(digest(successor.historical_bytes(path, regular_bytes(path))) == expected,
                "new source drift: " + path)
    validate_native_profile_v5()


if __name__ == "__main__":
    validate()
    print("Native-profile v5 valid: 257 current specifications; 252-packet checkpoint and exact 251-packet predecessor; contract reviewed.")
