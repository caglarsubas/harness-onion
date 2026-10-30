#!/usr/bin/env python3
"""Validate the MET-LINUX-008 Linux host-authority contract (LINUX-HOST-AUTH-001), adopted as candidate c8 after its in-tree CONTRACT rounds 1 to 3 (the status ADOPTED at slot 266 with a passing allowed-paths derivation and no gate class, the adopted subject pinned by its bytes with the adoption's two edits, the rounds and the D5a oracle bound by digest, and the registry's two pre-registered series), and the exact 266-to-265 projection."""
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
    import validate_met_gov_004 as successor
except ImportError:
    from scripts.safe_yaml import safe_load
    from scripts import validate_met_gov_004 as successor


ROOT = Path(__file__).resolve().parents[1]
AUTHORITY_PATH = "architecture/met-linux-008-authority.json"
AUTHORITY_SHA256 = "eff557b8cb66dfd17ee1f35ba738ebe268c95b92dae363610aa2a216582b29f8"
VALIDATOR_PATH = "scripts/validate_met_linux_008.py"
BASE_COMMIT = "f9882c1a4d0c2576e773841fe96e1f2e5958473f"
NEW_PACKET = "MET-LINUX-008"
PREVIOUS_PACKET = "MET-ENFORCE-042"
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
            require(key not in result, "duplicate linux-host-authority authority member")
            result[key] = value
        return result

    def no_constant(_value: str) -> Any:
        raise ValueError("nonfinite linux-host-authority authority number")

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
        require(digest(raw) == AUTHORITY_SHA256, "linux host authority history authority digest")
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
    }, "closed linux host authority history authority")
    require(value["schemaVersion"] == "harness.planeon.ai/met-linux-008-authority/v1"
            and value["authorityPacket"] == NEW_PACKET
            and value["acceptedBase"] == BASE_COMMIT
            and type(value["baselinePackets"]) is dict
            and len(value["baselinePackets"]) == 265
            and NEW_PACKET not in value["baselinePackets"]
            and type(value["changedFiles"]) is dict
            and type(value["newFiles"]) is dict
            and _sha(value["packetSha256"])
            and _sha(value["validatorNormalizedSha256"]),
            "accepted 265-packet base")
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
    # An exact 265-era byte string is already older than the successor layer.
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


# MET-LINUX-008 (roadmap LINUX-HOST-AUTH-001; the lane monitor's owner-delegated rulings, among them MON-LHA-CR1-KEEP,
# MON-LHA-CR2-KEEP, MON-LHA-C8, MON-LHA-ORACLE-KEEP, MON-LHA-C8-ADOPTED and MON-LHA-266-GO-1-3) publishes the Linux
# host-authority contract for the owner's per-run Linux hosts, their recipe and key custody, adopted as candidate c8
# after the in-tree CONTRACT rounds 1 to 3 of the MET-LINUX-008/contract series: the records under
# architecture/linux-host-authority/ (the host authority, the host recipe, the launcher install, the custody model and the
# drop manifest, each with its schema, the vectors, the README and the oracle identity), the checker
# scripts/linux_host_authority.py with its tests tests/test_linux_host_authority.py, and the D5a oracle
# tests/test_linux_host_authority_oracle.py, with the adoption records (status.json and the three rounds' records with
# their identities). Both of its review series were registered before this packet, so the registry is read and not
# changed, and the evolution surface record at this base gives the packet no gate class. Repository bytes are read only
# through reviewed_bytes, so a later bridged successor projects its own edits away first; a path outside this era is
# refused before it is read, every era file is bound by digest on every read, and no directory is listed. Each refusal
# is a pure check over the values read, so every one has a failing case on plain data. Checked here: the status
# (status.json in its own schema: ADOPTED for MET-LINUX-008 at slot 266, with the allowed-paths derivation passing at this
# era's base and no gate class); the adopted subject (exactly its fifteen files, each digest equal to this era's bytes of
# its path, except the adoption's two own edits, which equal the digests the status records for them instead); the
# reviews (each round's record and identity named by path and equal to their digests); the oracle (the oracle test and
# its identity named by path and equal to their digests); and the registry (exactly one MET-LINUX-008/packet and one
# MET-LINUX-008/contract entry, each pointing at its generic brief with the sha256 of that brief's bytes). No chain
# validator or chain test is pinned here. Last, this layer's own inverse hunks are the canonical byte-minimal ones,
# recomputed from its era's bytes (MET-PERF-040's carried rule).
CONTRACT_DIR = "architecture/linux-host-authority/"
STATUS_PATH = CONTRACT_DIR + "status.json"
STATUS_SCHEMA = "planeon.internal.linux-host-authority-status/v1"
STATUS = "ADOPTED"
SLOT = 266
REGISTRY_PATH = "architecture/review-record/briefs.json"
PACKET_BRIEF = "architecture/review-briefs/REVIEW_BRIEF_PACKET.md"
CONTRACT_BRIEF = "architecture/review-briefs/REVIEW_BRIEF_CONTRACT.md"
# The adopted subject as status.json binds it: non-chain files, each pinned by its bytes.
SUBJECT_PATHS = ("architecture/linux-host-authority/README.md",
                 "architecture/linux-host-authority/custody-model.json",
                 "architecture/linux-host-authority/custody-model.schema.json",
                 "architecture/linux-host-authority/drop-manifest.schema.json",
                 "architecture/linux-host-authority/host-authority.json",
                 "architecture/linux-host-authority/host-authority.schema.json",
                 "architecture/linux-host-authority/host-recipe.json",
                 "architecture/linux-host-authority/host-recipe.schema.json",
                 "architecture/linux-host-authority/launcher-install.json",
                 "architecture/linux-host-authority/launcher-install.schema.json",
                 "architecture/linux-host-authority/oracle-identity.json",
                 "architecture/linux-host-authority/vectors.json",
                 "scripts/linux_host_authority.py",
                 "tests/test_linux_host_authority.py",
                 "tests/test_linux_host_authority_oracle.py")
# The adoption's own edits as status.json binds them: two subject files pinned at their post-adoption bytes.
EDITED_PATHS = ("architecture/linux-host-authority/README.md", "tests/test_linux_host_authority.py")
# The three CONTRACT rounds as status.json binds them: each round's record and identity by path.
ROUNDS = (1, 2, 3)
REVIEW_RECORDS = tuple(CONTRACT_DIR + "review-round%d.json" % n for n in ROUNDS)
REVIEW_IDENTITIES = tuple(CONTRACT_DIR + "review-identity-round%d.json" % n for n in ROUNDS)
# The D5a oracle as status.json binds it: the oracle test and its identity by path.
ORACLE_TEST = "tests/test_linux_host_authority_oracle.py"
ORACLE_IDENTITY = CONTRACT_DIR + "oracle-identity.json"
# The registry: this packet's two series, each pinning its generic brief (PACKET first, as the registry holds them).
REGISTRY_ENTRIES = (("PACKET", NEW_PACKET + "/packet", PACKET_BRIEF), ("CONTRACT", NEW_PACKET + "/contract", CONTRACT_BRIEF))
# Every file this era's check reads, with its digest: the status, the adopted subject, the rounds' records and
# identities, the registry and the two generic briefs.
ERA_SHA256 = MappingProxyType({
    "architecture/linux-host-authority/README.md": "2f6799111f396ba6a21ab72c7d16cc51f963c53e4125df9d2a9b9193747ab037",
    "architecture/linux-host-authority/custody-model.json": "cc1cac42ae84dd68d6099be3b4b6fa4808f562a002ea6cf94db59f505290f314",
    "architecture/linux-host-authority/custody-model.schema.json": "d171ee0f4d4d36e6e01664d4cd2cf0fed83dfbbdd94104c32698a64ecdd029eb",
    "architecture/linux-host-authority/drop-manifest.schema.json": "1bf22618fe4500248bbb8bc0bda932b6bc4db050e33c2d34f684a606aa515954",
    "architecture/linux-host-authority/host-authority.json": "21c0a06202917afc10b5009a565340963404b998e917073fb1621736465bac77",
    "architecture/linux-host-authority/host-authority.schema.json": "154db399e499968e961a1d44e104d0849a3587a3c28b2a085320f690bd1ae784",
    "architecture/linux-host-authority/host-recipe.json": "b5640709d74ada0525d24d4db34be983626e1c3c5462ba905ffba3a48593dcff",
    "architecture/linux-host-authority/host-recipe.schema.json": "daa2066ab3a15257d3f9568b05f1f760c3d1e38580f815998cbf697e763703a9",
    "architecture/linux-host-authority/launcher-install.json": "082d2255738769ff1a50dfe29064ce6207d2d563796763418e71f4bf9f8f1334",
    "architecture/linux-host-authority/launcher-install.schema.json": "e0174afe8498a99e42a670d159154601f24fa64561df59ec2ff13f65ebb77a57",
    "architecture/linux-host-authority/oracle-identity.json": "d5c739c4a837ba80ebd88ca828b643f2b289ee1f34c07353e9e0ca6ab3ba5d0d",
    "architecture/linux-host-authority/review-identity-round1.json": "38805656a69cf74601ae064e743faaf6ea763ece9a51a3ffea8091071d502109",
    "architecture/linux-host-authority/review-identity-round2.json": "58290de9023eeee517ddbeabfc67eab7b4a13dfde7238766cbf68dcb5f4e9211",
    "architecture/linux-host-authority/review-identity-round3.json": "293731d024108df5e970873b25c2611fd1e138d44b5b504b097de210d6e38547",
    "architecture/linux-host-authority/review-round1.json": "b4f78a30967db80397f62b4b699258b86ef6b042fb997d5c3ec8bbc6d895a212",
    "architecture/linux-host-authority/review-round2.json": "f9b4b2fbb284bf6ffffde8c6925cd38380ee06b26ebbfd764686c526fef6d4d7",
    "architecture/linux-host-authority/review-round3.json": "78c52c4e568bd460c476552a736419bed7438763fc2a7d7004d3a4a62fe80e28",
    "architecture/linux-host-authority/status.json": "1eba96e36a59a5b45c593f19a3ab1f892e664935d41b030b47b81163c6d5f569",
    "architecture/linux-host-authority/vectors.json": "351e18ee3e79caf85da2aa7810050fc11e1c1ff64af9c86a54fef4427ebdf208",
    "architecture/review-briefs/REVIEW_BRIEF_CONTRACT.md": "1f09d23451bf265e32e44742ca362dabf5a1090c2208c1349cbf491670798aec",
    "architecture/review-briefs/REVIEW_BRIEF_PACKET.md": "6dcff68d7e6b01823f1740063e94910edcc159a71a6ee803f1b66c62fd06e274",
    "architecture/review-record/briefs.json": "0b5ef207c92b68b89c537aedb32bbd88e03be6f2ba19bd78b5d2a9963f861e20",
    "scripts/linux_host_authority.py": "c96d414ee39273261a324fee7f307ee90bb460e2b3191f0a5362f1b449d5b3b4",
    "tests/test_linux_host_authority.py": "bbcd37d62469c90080699a54b082532a0cfbd6a7231cfbad8f2088d84ffa458f",
    "tests/test_linux_host_authority_oracle.py": "212cdebe9bcaf0c837365a60c5abca14762ea3e56bf8870cbfab85604509a53e",
})


def reviewed_bytes(path: str) -> bytes:
    """This packet's reviewed bytes of path; a bridged successor projects newer bytes back first."""
    return successor.historical_bytes(path, regular_bytes(path))


def _era_bytes(path: Any, raw: Any) -> bytes:
    """An era file's bytes, checked against its era digest; a path outside the era is refused."""
    expected = ERA_SHA256.get(path) if type(path) is str else None
    require(expected is not None, "MET-LINUX-008 reviewed bytes are bound: " + str(path))
    require(type(raw) is bytes and digest(raw) == expected, "unreviewed LINUX-HOST-AUTH source: " + path)
    return raw


def _verified(path: str) -> bytes:
    """reviewed_bytes, checked against its era digest on every read; a path outside the era is refused before it is
    read."""
    require(type(path) is str and path in ERA_SHA256, "MET-LINUX-008 reviewed bytes are bound: " + str(path))
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


def check_status(status: Any) -> None:
    """status.json in its own schema: LINUX-HOST-AUTH ADOPTED for MET-LINUX-008 at slot 266, with the allowed-paths
    derivation passing at this era's base, no gate class, an adopted-subject mapping with its adoption edits, a reviews
    list and the oracle."""
    _bound(lambda: type(status) is dict and status["schemaVersion"] == STATUS_SCHEMA and status["packet"] == NEW_PACKET
           and type(status["slot"]) is int and status["slot"] == SLOT and status["status"] == STATUS
           and type(status["allowedPathsDerivation"]) is dict
           and status["allowedPathsDerivation"]["pass"] is True
           and status["allowedPathsDerivation"]["atBase"] == BASE_COMMIT
           and type(status["gate"]) is dict and type(status["gate"]["classes"]) is list
           and status["gate"]["classes"] == []
           and type(status["adoptedSubject"]) is dict and type(status["adoptionEdits"]) is dict
           and type(status["adoptionEdits"]["files"]) is dict
           and type(status["reviews"]) is list and type(status["oracle"]) is dict,
           "adopted LINUX-HOST-AUTH status: MET-LINUX-008 at slot 266 with a passing derivation and no gate class")


def check_subject(subject: Any, edits: Any, files: Any) -> None:
    """The adopted subject names exactly its fifteen files and the adoption edits exactly its two edited files; each
    digest equals this era's bytes of its path, the edited files' post-adoption digests instead of the subject's."""
    _bound(lambda: type(subject) is dict and sorted(subject) == sorted(SUBJECT_PATHS)
           and len(subject) == len(SUBJECT_PATHS) and type(edits) is dict and sorted(edits) == sorted(EDITED_PATHS)
           and len(edits) == len(EDITED_PATHS) and type(files) is dict and sorted(files) == sorted(SUBJECT_PATHS),
           "the adopted subject names exactly its fifteen files and its two adoption edits")
    for path in SUBJECT_PATHS:
        if path in EDITED_PATHS:
            _bound(lambda: _sha(subject[path]) and _sha(edits[path]) and subject[path] != edits[path]
                   and type(files[path]) is bytes and edits[path] == digest(files[path]),
                   "an adoption edit's digest is this era's bytes: " + path)
        else:
            _bound(lambda: _sha(subject[path]) and type(files[path]) is bytes and subject[path] == digest(files[path]),
                   "the adopted subject's digest is this era's bytes: " + path)


def check_reviews(reviews: Any, files: Any) -> None:
    """The reviews name exactly the CONTRACT rounds' records and identities, in round order, and each round's record and
    identity equal their digests."""
    _bound(lambda: type(reviews) is list and len(reviews) == len(ROUNDS) and type(files) is dict
           and [(row["record"], row["identity"]) for row in reviews] == list(zip(REVIEW_RECORDS, REVIEW_IDENTITIES)),
           "the status names exactly the CONTRACT rounds' records and identities")
    for n, row in zip(ROUNDS, reviews):
        _bound(lambda: _sha(row["recordSha256"]) and type(files[row["record"]]) is bytes
               and row["recordSha256"] == digest(files[row["record"]])
               and _sha(row["identitySha256"]) and type(files[row["identity"]]) is bytes
               and row["identitySha256"] == digest(files[row["identity"]]),
               "a CONTRACT round's record and identity equal their digests: round %d" % n)


def check_oracle(oracle: Any, files: Any) -> None:
    """The status names exactly the D5a oracle test and its identity, and both equal their digests."""
    _bound(lambda: type(oracle) is dict and oracle["test"] == ORACLE_TEST and oracle["identity"] == ORACLE_IDENTITY
           and type(files) is dict and sorted(files) == sorted((ORACLE_TEST, ORACLE_IDENTITY)),
           "the status names exactly the oracle test and its identity")
    _bound(lambda: _sha(oracle["sha256"]) and type(files[ORACLE_TEST]) is bytes
           and oracle["sha256"] == digest(files[ORACLE_TEST])
           and _sha(oracle["identitySha256"]) and type(files[ORACLE_IDENTITY]) is bytes
           and oracle["identitySha256"] == digest(files[ORACLE_IDENTITY]),
           "the oracle test and its identity equal their digests")


def validate_status() -> None:
    """status.json, the adopted subject's bytes, every round's record and identity, and the oracle, each read through
    the era."""
    status = _json(STATUS_PATH)
    check_status(status)
    check_subject(status["adoptedSubject"], status["adoptionEdits"]["files"],
                  {path: _verified(path) for path in SUBJECT_PATHS})
    check_reviews(status["reviews"], {path: _verified(path) for path in REVIEW_RECORDS + REVIEW_IDENTITIES})
    check_oracle(status["oracle"], {path: _verified(path) for path in (ORACLE_TEST, ORACLE_IDENTITY)})


def check_registry(raw: Any, packet_brief_raw: Any, contract_brief_raw: Any) -> None:
    """The registry holds exactly two series of this packet, its PACKET and CONTRACT series, each pointing at its generic
    brief with the sha256 of the brief's bytes."""
    _bound(lambda: type(raw) is bytes and type(packet_brief_raw) is bytes and type(contract_brief_raw) is bytes
           and [(entry["kind"], entry["series"], entry["path"], entry["sha256"], entry["version"])
                for entry in parse(raw)["briefs"] if entry["series"].startswith(NEW_PACKET + "/")]
           == [REGISTRY_ENTRIES[0] + (digest(packet_brief_raw), 1), REGISTRY_ENTRIES[1] + (digest(contract_brief_raw), 1)],
           "the registry holds exactly this packet's PACKET and CONTRACT series, each pinning its generic brief")


def validate_registry() -> None:
    """briefs.json with this packet's two series, and the two generic briefs."""
    check_registry(_verified(REGISTRY_PATH), _verified(PACKET_BRIEF), _verified(CONTRACT_BRIEF))


def validate_met_linux_008() -> None:
    """Every reviewed byte first; then the status, the adopted subject, the reviews and the oracle, and the registry;
    last, this layer's canonical hunks."""
    for path in ERA_SHA256:
        _verified(path)
    validate_status()
    validate_registry()
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
            == record["validatorNormalizedSha256"], "linux host authority validator drift")
    paths = sorted((ROOT / "task-packets").glob("*.yaml"))
    old = set(record["baselinePackets"])
    require(len(paths) == 271
            and {path.stem for path in paths} == old | {NEW_PACKET, successor.NEW_PACKET, successor.successor.NEW_PACKET, successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.NEW_PACKET},
            "closed 271-packet catalog retaining the 266-packet checkpoint")
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
            "closed source-only linux-host-authority packet and inherited commands")
    require(len(packet["allowedPaths"]) == len(set(packet["allowedPaths"]))
            and set(packet["allowedPaths"]) == set(record["changedFiles"])
            | set(record["newFiles"]) | {AUTHORITY_PATH, VALIDATOR_PATH,
                                         "task-packets/" + NEW_PACKET + ".yaml"},
            "unreviewed or omitted linux-host-authority packet path")
    for path, rule in record["changedFiles"].items():
        current = successor.historical_bytes(path, regular_bytes(path))
        require(digest(current) == rule["afterSha256"]
                and digest(historical_bytes(path, current)) == rule["beforeSha256"],
                "unreviewed current source: " + path)
    for path, expected in record["newFiles"].items():
        require(digest(successor.historical_bytes(path, regular_bytes(path))) == expected,
                "new source drift: " + path)
    validate_met_linux_008()


if __name__ == "__main__":
    validate()
    print("Linux host authority valid: 271 current specifications; 266-packet checkpoint and exact 265-packet predecessor; contract reviewed.")
