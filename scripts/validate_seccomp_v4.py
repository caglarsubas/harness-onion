#!/usr/bin/env python3
"""Validate the MET-ENFORCE-027 seccomp allowlists v4 and the exact 237-to-236 projection."""
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
    import validate_pytest_headroom as successor
except ImportError:
    from scripts.safe_yaml import safe_load
    from scripts import validate_pytest_headroom as successor


ROOT = Path(__file__).resolve().parents[1]
AUTHORITY_PATH = "architecture/seccomp-v4-authority.json"
AUTHORITY_SHA256 = "c7863228891d180c000e3171b90f11daee63cfdeac427f110475bc07f79be633"
VALIDATOR_PATH = "scripts/validate_seccomp_v4.py"
BASE_COMMIT = "0879eb1454fe9d0cb939c3fd08cf9267603ca8fd"
NEW_PACKET = "MET-ENFORCE-027"
PREVIOUS_PACKET = "MET-ENFORCE-026"
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
            require(key not in result, "duplicate seccomp-v4 authority member")
            result[key] = value
        return result

    def no_constant(_value: str) -> Any:
        raise ValueError("nonfinite seccomp-v4 authority number")

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
        require(digest(raw) == AUTHORITY_SHA256, "seccomp v4 history authority digest")
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
    }, "closed seccomp v4 history authority")
    require(value["schemaVersion"] == "harness.planeon.ai/seccomp-v4-authority/v1"
            and value["authorityPacket"] == NEW_PACKET
            and value["acceptedBase"] == BASE_COMMIT
            and type(value["baselinePackets"]) is dict
            and len(value["baselinePackets"]) == 236
            and NEW_PACKET not in value["baselinePackets"]
            and type(value["changedFiles"]) is dict
            and type(value["newFiles"]) is dict
            and _sha(value["packetSha256"])
            and _sha(value["validatorNormalizedSha256"]),
            "accepted 236-packet base")
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
    # An exact 236-era byte string is already older than the successor layer.
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


# MET-ENFORCE-027 (roadmap SECCOMP-V3-READLINKAT; owner decisions Q-HE3A-1 (c), Q-HE3A-1b (a), HS43-START,
# SECCOMP-DIRFD-DIRECTION and SEC-RL-START, 2026-10-13 to 2026-10-15) publishes the W02d successor
# planeon.internal.seccomp-allowlists/v4, which carries out HS43 obligation O-SECCOMP-V3-READLINKAT in data: v3 plus one
# EFFECT_GATE rule, readlinkat only with a non-negative dirfd ((arg0 & 0x80000000) == 0), and no readlink for the gate.
# Repository bytes are read only through reviewed_bytes, so a later bridged successor projects its own edits away first.
# Every reviewed file of this era is bound by digest before anything is parsed and on every later read. The review
# binding is checked first; then the v4 model, executed from this era's bytes (it imports only the standard library),
# replays every decision through the reference decision and the compiled program, the worker's stacked filters and every
# policy mutation, and the published digests are checked. The gate's rule and dirfd outcomes, the decisions, the
# obligation and the six unchanged roles' digests are restated here independently of the record.
V4_DIR = "architecture/seccomp-allowlists-v4/"
V3_DIR = "architecture/seccomp-allowlists-v3/"
V4_MODEL = "scripts/seccomp_allowlists_v4.py"
STATUS = V4_DIR + "status.json"
INDEX = V4_DIR + "source-index.json"
HS43_RECORD = "architecture/host-interface-amendment-hs43/amendment.json"
SUBJECT = (V4_DIR + "README.md", V4_DIR + "REVIEW_BRIEF.md", V4_DIR + "syscalls.json", V4_DIR + "allowlists.json",
           V4_DIR + "vectors.json", V4_MODEL)
# The adopted v3 contract and the HS43 amendment stay byte-identical: v4 succeeds v3 and answers HS43.
FROZEN_PATHS = (
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
    "scripts/host_interface_amendment_v2.py",
    "scripts/seccomp_allowlists_v3.py",
)
ERA_SHA256 = MappingProxyType({
    "architecture/host-interface-amendment-hs43/amendment.json": "6a3719cdc659d7ccfde3598bdec06a31896fa82de810cf73ccc1f7ca3dc7f24c",
    "architecture/seccomp-allowlists-v3/vectors.json": "18353cb347dc8d4575b650fe4b4ece31f5bf9ca1ce490d1c50a9ae2962f25df8",
    "architecture/seccomp-allowlists-v4/README.md": "bdca37825c2e6a6f7d8797c256fab7e891fb26b6660dcb78a84f3613cde54f25",
    "architecture/seccomp-allowlists-v4/REVIEW_BRIEF.md": "4fb717b9f0c2de80b432a20ea8846b8d68d2772a97c69bb7bac33cac7e401105",
    "architecture/seccomp-allowlists-v4/allowlists.json": "4dcfb2dfea82eabd04024b35d9dac4bb487b6c0051f7e6e16bbd00426cf6b2ff",
    "architecture/seccomp-allowlists-v4/review-round1.json": "8739fb46e9d6719d1ff41165f57dfa92a4a60582cf1f8c6c7884bb66fedc0b6c",
    "architecture/seccomp-allowlists-v4/review-round2.json": "39dce3f3e8f2424a7f3c4dcabf172b589b3e7ce8eb7153297f68d6fcd536a7f2",
    "architecture/seccomp-allowlists-v4/review-round3.json": "3ca2648f1827febe0b9121644d6d16f988f8eb64e23507c2f043caabb5f634cb",
    "architecture/seccomp-allowlists-v4/round1/architecture/seccomp-allowlists-v4/README.md": "02564ce8393b5853b569246e8f709f6e8bad2cba1fea999bafffc11036117cd3",
    "architecture/seccomp-allowlists-v4/round1/architecture/seccomp-allowlists-v4/REVIEW_BRIEF.md": "a9f91fe198b1c6ec4864f290137a962643ba01fc65676e0ef97c9bee526a4d1d",
    "architecture/seccomp-allowlists-v4/round1/architecture/seccomp-allowlists-v4/allowlists.json": "a7b7980af7b76d407cc042a4d239aeb43209610f79af9f1da720e11cba0c1753",
    "architecture/seccomp-allowlists-v4/round1/architecture/seccomp-allowlists-v4/syscalls.json": "cd15c9c13d21223517706e17b9b19109567dc2f20f89a2d53bae5524cc71cc7d",
    "architecture/seccomp-allowlists-v4/round1/architecture/seccomp-allowlists-v4/vectors.json": "c4b8826e7215231197a9a549984f4bb8ae16ebdba47947ca438d1fbca3a9af81",
    "architecture/seccomp-allowlists-v4/round1/scripts/seccomp_allowlists_v4.py": "62e6f9435c2282be4ab048086f1042d649e5cd0d5abce9fed9a74404264916e1",
    "architecture/seccomp-allowlists-v4/round2/architecture/seccomp-allowlists-v4/README.md": "42e4ed95b3c2f216590648d66deca383d9a7d378c14c66051c2e6cdc958a7ff4",
    "architecture/seccomp-allowlists-v4/round2/architecture/seccomp-allowlists-v4/REVIEW_BRIEF.md": "a9f91fe198b1c6ec4864f290137a962643ba01fc65676e0ef97c9bee526a4d1d",
    "architecture/seccomp-allowlists-v4/round2/architecture/seccomp-allowlists-v4/allowlists.json": "455bb489df568718f2dc9b9e0d15fbbcfdedf25d852aa3118e529e787c710e36",
    "architecture/seccomp-allowlists-v4/round2/architecture/seccomp-allowlists-v4/syscalls.json": "ec2457d89e02fd3d9b4fb9957aee4c99ffe4a19471fc1ac4b3e963f55b89fd92",
    "architecture/seccomp-allowlists-v4/round2/architecture/seccomp-allowlists-v4/vectors.json": "ac8daa0c6c13d84825565b7e52fa23564731585584f7d46a66363b50bed71816",
    "architecture/seccomp-allowlists-v4/source-index.json": "55dedc426bb3d06acffcb94c7cde97a72e90f103ac04063027ab2c7ada0d2849",
    "architecture/seccomp-allowlists-v4/status.json": "b2f82f66bf9ebb6cc52b7f8e9503250604e7b46310bccdd14e635f3ff08a21dc",
    "architecture/seccomp-allowlists-v4/syscalls.json": "d759e341afcbcf2dccd8eafce136a303d2275efceeac1525ef2200b6e65fe53d",
    "architecture/seccomp-allowlists-v4/vectors.json": "9a918c15bbcb6378b282df9a5da8389289bf505f9f8eb5e1a50b9c5bb6f92187",
    "scripts/seccomp_allowlists_v4.py": "f88e3eab1a154260b2a33d7a1eadb5a78f29d49579219d3aaf55041ec861e9bf",
})
REVIEW_VERDICTS = ("CHANGES_REQUIRED", "CHANGES_REQUIRED", "PASS_FOR_SOURCE_PUBLICATION")
PASS_SUBJECT = "bebd9974c49bf89bcab8ddb60d1a09556291a482"
OBLIGATION = "O-SECCOMP-V3-READLINKAT"
V3_DECISIONS = ("W02d-Q1", "W02d-Q2", "W02d-Q3", "W01-AMEND-QW1", "W01-AMEND-QW2", "W01-AMEND-QW3", "W02d-V3",
                "W01-AMEND-QW4")
# Quoted as HS43's record holds them; SEC-RL-START starts this slot.
HS43_DECISIONS = ("Q-HE3A-1", "Q-HE3A-1b", "HS43-START", "SECCOMP-DIRFD-DIRECTION")
V4_DECISIONS = V3_DECISIONS + HS43_DECISIONS + ("SEC-RL-START",)
GATE = "EFFECT_GATE"
GATE_READLINKAT = [[{"arg": 0, "mask": 0x80000000, "eq": 0}]]
# dirfd -> the gate's action: AT_FDCWD sign- and zero-extended, -1 and the lowest negative int are killed.
GATE_DIRFDS = ((0xFFFFFFFFFFFFFF9C, "KILL_PROCESS"), (0xFFFFFF9C, "KILL_PROCESS"), (0xFFFFFFFFFFFFFFFF, "KILL_PROCESS"),
               (0x80000000, "KILL_PROCESS"), (3, "ALLOW"), (0x7FFFFFFF, "ALLOW"))
FLOORS = {"decisionChecks": 2971, "workerStackChecks": 355, "policyMutations": 23}
OBLIGATIONS_E = tuple("E%02d" % number for number in range(1, 13))
V4_FALSE = ("nativeAcceptance", "tenantAcceptance", "filtersInstalled", "roleCodeExists", "traceValidated",
            "distributionSelected", "productExecution", "runnerActivated", "phaseComplete")
STATUS_KEYS = frozenset({"schemaVersion", "contract", "kernel", "supersedes", "discharges", "ownerDecisions", "reviewRounds",
                         "closedFindings", "carriedFindings", "carriedToW03", "openObligations", "contractState",
                         "obligations", "independentReviewer", "readmeStatusNote", *V4_FALSE})
ROUND_KEYS = frozenset({"round", "record", "recordSha256", "verdict", "subjectCommit", "subjectSha256", "subjectDirectory"})


def reviewed_bytes(path: str) -> bytes:
    """This packet's reviewed bytes of path; a bridged successor projects newer bytes back first."""
    return successor.historical_bytes(path, regular_bytes(path))


def _verified(path: str) -> bytes:
    """reviewed_bytes, checked against its era digest on every read; a path outside the era is refused."""
    expected = ERA_SHA256.get(path)
    require(expected is not None, "MET-ENFORCE-027 reviewed bytes are bound: " + path)
    raw = reviewed_bytes(path)
    require(type(raw) is bytes and digest(raw) == expected, "unreviewed seccomp v4 source: " + path)
    return raw


def _json(path: str) -> Any:
    return parse(_verified(path))


def _era_model() -> types.ModuleType:
    """The v4 reference model of this era, executed from its verified bytes."""
    module = types.ModuleType("_met_enforce_027_seccomp_allowlists_v4")
    module.__file__ = str(ROOT / V4_MODEL)
    exec(compile(_verified(V4_MODEL), V4_MODEL, "exec", dont_inherit=True), module.__dict__)
    return module


def validate_v4_status(policy: dict) -> dict:
    """The status is closed, its rounds are bound to their exact subject bytes, and the last round passes with notes."""
    status = _json(STATUS)
    require(type(status) is dict and set(status) == STATUS_KEYS and status["schemaVersion"] == "planeon.internal.seccomp-allowlists-status/v4"
            and status["contract"] == "planeon.internal.seccomp-allowlists/v4"
            and status["supersedes"] == {"directory": V3_DIR, "contract": "planeon.internal.seccomp-allowlists/v3",
                                         "status": V3_DIR + "status.json"}
            and status["discharges"]["obligation"] == OBLIGATION and status["discharges"]["record"] == HS43_RECORD
            and status["contractState"] == "ADOPTED_DATA_CONTRACT"
            and status["obligations"] == {name: "OPEN_UNPROVEN" for name in OBLIGATIONS_E}
            and status["independentReviewer"] == "SEPARATE_AGENT_NOT_AUTHOR"
            and all(status[flag] is False for flag in V4_FALSE)
            and status["ownerDecisions"] == policy["ownerDecisions"], "adopted after the round-3 pass, nothing installed")
    rounds = status["reviewRounds"]
    require(type(rounds) is list and all(type(row) is dict and set(row) == ROUND_KEYS | ({"keptCopies"} if number < len(rounds)
                                                                                    else set())
                                         for number, row in enumerate(rounds, 1))
            and tuple(row["verdict"] for row in rounds) == REVIEW_VERDICTS
            and rounds[-1]["subjectCommit"] == PASS_SUBJECT and rounds[-1]["subjectDirectory"] == "CURRENT",
            "adopted after the round-3 pass, nothing installed")
    for number, row in enumerate(rounds, 1):
        record = parse(_verified(row["record"]))
        kept = row.get("keptCopies", [])
        require(row["round"] == number and row["record"] == V4_DIR + "review-round%d.json" % number
                and digest(_verified(row["record"])) == row["recordSha256"]
                and record["round"] == number and record["subject"] == row["subjectCommit"]
                and record["verdict"] == row["verdict"]
                and row["subjectDirectory"] == (V4_DIR + "round%d/" % number if number < len(rounds) else "CURRENT")
                and set(kept) <= set(SUBJECT)
                and row["subjectSha256"] == {path: digest(_verified(row["subjectDirectory"] + path if path in kept
                                                                    else path)) for path in SUBJECT},
                "review round %d is bound to its exact subject bytes" % number)
    final = parse(_verified(rounds[-1]["record"]))
    require(all(type(row) is dict and row.get("severity") == "NOTE" for row in final["findings"])
            and {row["id"] for row in final["findings"]} == set(status["carriedFindings"]),
            "the final round passes with notes only, all carried")
    index = _json(INDEX)
    require(index["subjectCommit"] == PASS_SUBJECT
            and [row["path"] for row in index["subject"]] == list(SUBJECT)
            and all(digest(_verified(row["path"])) == row["sha256"] for row in index["subject"]),
            "the reviewed subject is the published one")
    return status


def validate_v4_vectors(model: types.ModuleType, table: dict, policy: dict, vectors: dict) -> int:
    """Every decision replays through both the reference decision and the compiled program; the worker's stacked filters
    decide as its own; every mutation is refused with its stated message; the digests are the compiled programs'."""
    require(table.get("schemaVersion") == "planeon.internal.seccomp-syscall-table/v4"
            and table.get("kernel") == {"tag": "v6.12", "commit": "adc218676eef25575469234709c2d87185ca223a"}
            and policy.get("schemaVersion") == "planeon.internal.seccomp-allowlists/v4" and policy.get("mode") == 2
            and policy.get("defaultAction") == "KILL_PROCESS"
            and tuple(row.get("id") for row in policy["ownerDecisions"]) == V4_DECISIONS, "closed v4 table and policy")
    model.check_policy(policy, table)
    require(type(vectors) is dict and set(vectors) == {"evidenceClass", "filterDigests", "programLengths", "decisionChecks",
                                                       "workerStackChecks", "policyMutations"}
            and vectors["evidenceClass"] == "DATA_CHECK_ONLY"
            and all(len(vectors[key]) >= floor for key, floor in FLOORS.items()), "closed v4 vectors")
    programs = {(role, arch): model.compile_filter(policy, table, role, arch) for role in model.ROLES for arch in model.ARCHES}
    require(vectors["filterDigests"] == {role: {arch: "sha256:" + digest(model.program_bytes(programs[role, arch]))
                                                for arch in model.ARCHES} for role in model.ROLES}
            and vectors["programLengths"] == {role: {arch: len(programs[role, arch]) for arch in model.ARCHES}
                                              for role in model.ROLES}, "the published v4 digests are the compiled programs'")
    checks, by_id = 0, {}
    for row in vectors["decisionChecks"]:
        data = model.seccomp_data(row["nr"], row["auditArch"], row["args"])
        expect = model.action_name(model.decide(policy, table, row["role"], row["arch"], row["auditArch"], row["nr"], row["args"]))
        require(expect == row["expect"] == model.action_name(model.run_filter(programs[row["role"], row["arch"]], data)),
                "v4 decision check " + row["id"])
        by_id[row["id"]] = row
        checks += 1
    for row in vectors["workerStackChecks"]:
        base = by_id[row["decision"]]
        require(base["role"] == "WORKER" and row["expect"] == "SAME_AS_WORKER"
                and model.decide_stack(policy, table, ["BROKER", "WORKER"], base["arch"], base["auditArch"], base["nr"], base["args"])
                == model.decide(policy, table, "WORKER", base["arch"], base["auditArch"], base["nr"], base["args"]),
                "v4 worker stack check " + row["id"])
        checks += 1
    for row in vectors["policyMutations"]:
        changed = copy.deepcopy(policy)
        changed["roles"][row["role"]]["duties"].append(row["addDuty"])
        try:
            model.check_policy(changed, table)
            refused = None
        except ValueError as exc:
            refused = str(exc)
        require(refused is not None and refused == row["expect"], "v4 policy mutation " + row["id"])
        checks += 1
    return checks


def validate_v4_gate(model: types.ModuleType, table: dict, policy: dict, vectors: dict) -> None:
    """The gate's one new rule, its dirfd outcomes and the six unchanged roles, restated independently of the record."""
    rules = [rule for duty in policy["roles"][GATE]["duties"] for rule in duty["rules"]
             if rule["name"] in ("readlinkat", "readlink")]
    require(rules == [{"name": "readlinkat", "when": GATE_READLINKAT}]
            and any(duty["source"].endswith("obligation " + OBLIGATION) for duty in policy["roles"][GATE]["duties"]),
            "the gate's readlinkat rule as restated")
    for arch in model.ARCHES:
        audit, nr = table["arches"][arch]["auditArch"], table["syscalls"]["readlinkat"][arch]["nr"]
        program = model.compile_filter(policy, table, GATE, arch)
        for dirfd, expected in GATE_DIRFDS:
            args = [dirfd, 0, 0, 0, 0, 0]
            require(model.action_name(model.decide(policy, table, GATE, arch, audit, nr, args)) == expected
                    == model.action_name(model.run_filter(program, model.seccomp_data(nr, audit, args))),
                    "the gate's dirfd outcome as restated: %s %#x" % (arch, dirfd))
    v3 = _json(V3_DIR + "vectors.json")["filterDigests"]
    require({role for role in model.ROLES if vectors["filterDigests"][role] != v3[role]} == {GATE},
            "only the gate's digests change from v3")
    record = _json(HS43_RECORD)
    quoted = {row["id"]: (row["id"], row["date"], row["decision"]) for row in record["ownerDecisions"]}
    require(any(row["id"] == OBLIGATION for row in record["obligations"])
            and [(row["id"], row["date"], row["decision"]) for row in policy["ownerDecisions"] if row["id"] in HS43_DECISIONS]
            == [quoted.get(name) for name in HS43_DECISIONS], "the HS43 decisions and obligation as recorded there")


def validate_seccomp_v4() -> None:
    """Every reviewed byte and the review binding first; then the full v4 replay and the restatements, from this era."""
    for path in FROZEN_PATHS:
        require(path not in _PROJECTION_RULES, "the v3 contract and the HS43 amendment stay byte-identical")
    for path in ERA_SHA256:
        _verified(path)
    table, policy, vectors = _json(V4_DIR + "syscalls.json"), _json(V4_DIR + "allowlists.json"), _json(V4_DIR + "vectors.json")
    validate_v4_status(policy)
    model = _era_model()
    checks = validate_v4_vectors(model, table, policy, vectors)
    require(checks >= sum(FLOORS.values()), "every v4 vector replays")
    validate_v4_gate(model, table, policy, vectors)


def validate() -> None:
    record = authority()
    validator_raw = successor.historical_bytes(VALIDATOR_PATH, regular_bytes(VALIDATOR_PATH))
    literal = b'AUTHORITY_SHA256 = "' + AUTHORITY_SHA256.encode("ascii") + b'"'
    placeholder = b'AUTHORITY_SHA256 = "TO_BE_PINNED_AFTER_SOURCE_FREEZE"'
    require(validator_raw.count(literal) == 1
            and digest(validator_raw.replace(literal, placeholder))
            == record["validatorNormalizedSha256"], "seccomp v4 validator drift")
    paths = sorted((ROOT / "task-packets").glob("*.yaml"))
    old = set(record["baselinePackets"])
    require(len(paths) == 244
            and {path.stem for path in paths} == old | {NEW_PACKET, successor.NEW_PACKET, successor.successor.NEW_PACKET, successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.successor.NEW_PACKET},
            "closed 244-packet catalog retaining the 237-packet checkpoint")
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
            "closed source-only seccomp-v4 packet and inherited commands")
    require(len(packet["allowedPaths"]) == len(set(packet["allowedPaths"]))
            and set(packet["allowedPaths"]) == set(record["changedFiles"])
            | set(record["newFiles"]) | {AUTHORITY_PATH, VALIDATOR_PATH,
                                         "task-packets/" + NEW_PACKET + ".yaml"},
            "unreviewed or omitted seccomp-v4 packet path")
    for path, rule in record["changedFiles"].items():
        current = successor.historical_bytes(path, regular_bytes(path))
        require(digest(current) == rule["afterSha256"]
                and digest(historical_bytes(path, current)) == rule["beforeSha256"],
                "unreviewed current source: " + path)
    for path, expected in record["newFiles"].items():
        require(digest(successor.historical_bytes(path, regular_bytes(path))) == expected,
                "new source drift: " + path)
    validate_seccomp_v4()


if __name__ == "__main__":
    validate()
    print("Seccomp allowlists v4 valid: 244 current specifications; 237-packet checkpoint and exact 236-packet predecessor; contract reviewed.")
