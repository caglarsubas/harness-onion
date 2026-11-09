#!/usr/bin/env python3
"""Validate MET-REGISTRY-001 (R13 mas-harness-research-lab's registration): the seventh publishing step (K = 1), publishing LAB-REPO-001, R13's first product packet (V1: this packet's files by digest; V2: the product; R1-R7: the registration; V4: the registry rider; V6: the hunk-class record)."""
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
    import validate_met_adopt_008 as successor
except ImportError:
    from scripts.safe_yaml import safe_load
    from scripts import validate_met_adopt_008 as successor


ROOT = Path(__file__).resolve().parents[1]
AUTHORITY_PATH = "architecture/repository-registration-authority.json"
AUTHORITY_SHA256 = "b47b230940ec8be731df545e1aa1163e074f80370d34ec40dcef312b1fc0f203"
VALIDATOR_PATH = "scripts/validate_met_registry_001.py"
BASE_COMMIT = "e515f0b83ca4b3cda9dca02acb6ac0db623b66df"
NEW_PACKET = "MET-REGISTRY-001"
PREVIOUS_PACKET = "MET-VERIFY-007"
PRODUCT_PACKETS = ("LAB-REPO-001",)
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
            require(key not in result, "duplicate repository-registration authority member")
            result[key] = value
        return result

    def no_constant(_value: str) -> Any:
        raise ValueError("nonfinite repository-registration authority number")

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
        require(digest(raw) == AUTHORITY_SHA256, "repository registration history authority digest")
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
        "packetSha256", "changedFiles", "newFiles", "validatorNormalizedSha256", "productPackets",
        "productComparators",
    }, "closed repository registration history authority")
    require(value["schemaVersion"] == "harness.planeon.ai/repository-registration-authority/v1"
            and value["authorityPacket"] == NEW_PACKET
            and value["acceptedBase"] == BASE_COMMIT
            and type(value["baselinePackets"]) is dict
            and len(value["baselinePackets"]) == 293
            and NEW_PACKET not in value["baselinePackets"]
            and type(value["changedFiles"]) is dict
            and type(value["newFiles"]) is dict
            and _sha(value["packetSha256"])
            and _sha(value["validatorNormalizedSha256"]),
            "accepted 293-packet base")
    require(type(value["productPackets"]) is dict
            and list(value["productPackets"]) == list(PRODUCT_PACKETS)
            and all(_sha(sha) for sha in value["productPackets"].values())
            and not set(PRODUCT_PACKETS) & (set(value["baselinePackets"]) | {NEW_PACKET}),
            "product packets")
    require(type(value["productComparators"]) is dict
            and list(value["productComparators"]) == [p for p in PRODUCT_PACKETS if p in value["productComparators"]]
            and all(type(pin) is dict and set(pin) == {"packet", "sha256"} and type(pin["packet"]) is str
                    and _sha(pin["sha256"]) and value["baselinePackets"].get(pin["packet"]) == pin["sha256"]
                    for pin in value["productComparators"].values()),
            "product comparators")
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
                                 **{NEW_PACKET: record["packetSha256"]},
                                 **record["productPackets"]))


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
    # An exact 293-era byte string is already older than the successor layer.
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
    require(NEW_PACKET in current_ids and set(packets) == current_ids | set(PRODUCT_PACKETS),
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
    return {name: packets[name] for name in current_ids - {NEW_PACKET} - set(PRODUCT_PACKETS)}


def validate_packet_payloads(packets: dict[str, Any]) -> None:
    """Check all current payloads separately from the inherited traversal."""
    record = authority()
    rules = _packet_rules()
    require(type(packets) is dict, "packet mapping")
    old = set(record["baselinePackets"])
    require(set(packets) == old | {NEW_PACKET} | set(PRODUCT_PACKETS), "unexpected packet addition or loss")
    require(set(rules) == old | {NEW_PACKET} | set(PRODUCT_PACKETS)
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


# MET-REGISTRY-001 (R13 mas-harness-research-lab's registration; the lane monitor's rulings MON-284-RULED,
# MON-284-CR1-RULED, MON-284-CR1-VIS, MON-284-CR2-RULED, MON-284-C1-ERRATA, MON-284-ARGV-RULED and
# MON-284-DEPTH-RULED): the semantic block. This
# packet's files are the registration's (CONTRACT_284 section 3), bound by digest in the era with the registry,
# the packet brief, the reader, chain_identity_v2 and the product-packet rule (V1); the product is R13's first
# packet in the generic first-packet form (V2); the registration holds (R1-R7); the registry differs from the
# base by this packet's one rider (V4); the authority's hunk-class record is re-checked by the reader's class
# rule (V6).
PACKET_FILES = ('architecture/repository-registration/language-placement.json', 'architecture/repository-registration/repositories.json', 'architecture/repository-registration/rule.json', 'docs/adr/0001-repository-boundaries.md', 'architecture/repository-registration/language-placement.schema.json', 'docs/repositories/13-mas-harness-research-lab.md', 'architecture/repository-registration/repositories.schema.json', 'scripts/check_release_lock.py', 'scripts/language_placement.py', 'scripts/repository_registration.py', 'scripts/validate_architecture.py', 'scripts/validate_readiness.py', 'tests/conftest.py', 'tests/test_release_lock_registration.py')
HUNK_RECORD_PATH = "architecture/chain-checkpoint/hunk-classes/284.json"
REGISTRY_BASE_SHA256 = "5d5155fd617ad70128b8690fd05a0137514c801251c15ec13b4233c97c451436"
HUNK_CONTEXT = MappingProxyType({"newPacket": NEW_PACKET, "prevValidator": "scripts/validate_met_verify_007.py",
                                 "prevTest": "tests/test_met_verify_007.py", "steps": (1, 2)})
ERA_SHA256 = MappingProxyType({
    "architecture/chain-product-packets/rule.json": "5e6e6821eace0e50e416c21ab2e605a165b2e69e455cf3fa6b051f7db99fb4d4",
    "architecture/language-placement.json": "5e4c76bddea19135bc6b6eea5b806af8277723a7b1b475d01643e25bd2e9efa1",
    "architecture/repositories.yaml": "02190a668c6a9114b3733724bec4e552c553867e789b0802f6aaa6759148051d",
    "architecture/repository-registration/language-placement.json": "17fc67ef9b89bff17ee5034cf3c54decfba08de293c4afddbe58e24a3ec9d95f",
    "architecture/repository-registration/language-placement.schema.json": "26c4e8746effcdab309da74e1bf864bab2932d9e796a31bedc66a4186282bf26",
    "architecture/repository-registration/repositories.json": "9c129674c8116b47cded71c87921631d85f9407c6d7291f62cd7e801ed42396c",
    "architecture/repository-registration/repositories.schema.json": "b2d0723862553ef864d41bc9bed8a907c2124c2e19f4b52c5774ffa4e851075c",
    "architecture/repository-registration/rule.json": "4405e9da30db3181eb257b2a0e47bc7bcdda0f6e35e29e4f16de564a2bd1445f",
    "architecture/review-briefs/REVIEW_BRIEF_PACKET.md": "6dcff68d7e6b01823f1740063e94910edcc159a71a6ee803f1b66c62fd06e274",
    "architecture/review-record/briefs.json": "7327c7ba1324ae4296e21a73fae9756eab689dcd6337390a91bc28e8eab5078e",
    "ci/chain_checkpoint.py": "b66d601e387c181d627d2e210fe5db40bf6ae3ec2e12f1369b0215d9a57b046b",
    "docs/adr/0001-repository-boundaries.md": "baccff6895870c080602d548bb80869b22053f38e2402d31366299422bb217bc",
    "docs/adr/0010-language-placement.md": "e4c7504ba4ca75fdc0d54b1a6a3703a00d22294dbebcf58c5fb4c8ca38bf3da1",
    "docs/repositories/13-mas-harness-research-lab.md": "bc19f6a5100c36abfea3dd767932a9c18e4d6ef3c1a65723eba4b067b33bdeb7",
    "release/evidence-policy.yaml": "ead30b57628a7479152c94f6a9496d90ec9d60701d7214cfcf3e36765dbda069",
    "release/fixture-release-set.yaml": "7597ebe4754a501de67dc2ee620dba4a8413e8b87761437d562194bac595b2f9",
    "release/repos.lock.json": "6067ca5e86c759c3efd914b037243e82577b40448d084df339b0abbf0d2999c4",
    "schemas/repositories.schema.json": "8b1841a75925c2b059909424656cf85d20691c50d5585da5b9ae7e5971271f27",
    "scripts/chain_identity_v2.py": "23fe723ae060b13727118b5808541d0b40bfee22ac5e803955e324f4dd6d9a55",
    "scripts/check_release_lock.py": "d6138729a61d78cb0382cd26ecd6fc7b4a60d2de08100f71522ba499658d2c0c",
    "scripts/language_placement.py": "6146ebb2331c2970d073031d557ee5de4fe103665c725b8e02953690ec0f00f9",
    "scripts/repository_registration.py": "e8635f23dbf10572da331237483c8245ee590f9f423f54d6c8ce28b11c01736c",
    "scripts/validate_architecture.py": "161c6628845edbd9dfa7197407b786358438ae81ecfef19901dcb1686a97207f",
    "scripts/validate_readiness.py": "f60e7fdbfd5c2fa62aaa9416fad0a5b1494f5280b0ff53a2360a40f21084bf0c",
    "tests/conftest.py": "1b67efa897df8c7fdbd4c3cc3bd5b6ccd8f1e1bdce32b135f273f943570301b1",
    "tests/test_release_lock.py": "41f1e77372f5536d2812041fb32e79f2bc7b8ccd3f776e59bc5f0bc5a0b10521",
    "tests/test_release_lock_registration.py": "87fcc780c30d8269b6314d5b2d79799826ae45b5793f9922c585d0970c8d063e",
})
FROZEN_SHA256 = MappingProxyType({
    "architecture/repositories.yaml": "02190a668c6a9114b3733724bec4e552c553867e789b0802f6aaa6759148051d",
    "release/evidence-policy.yaml": "ead30b57628a7479152c94f6a9496d90ec9d60701d7214cfcf3e36765dbda069",
    "release/fixture-release-set.yaml": "7597ebe4754a501de67dc2ee620dba4a8413e8b87761437d562194bac595b2f9",
    "release/repos.lock.json": "6067ca5e86c759c3efd914b037243e82577b40448d084df339b0abbf0d2999c4",
    "schemas/repositories.schema.json": "8b1841a75925c2b059909424656cf85d20691c50d5585da5b9ae7e5971271f27",
    "tests/test_release_lock.py": "41f1e77372f5536d2812041fb32e79f2bc7b8ccd3f776e59bc5f0bc5a0b10521",
    "architecture/language-placement.json": "5e4c76bddea19135bc6b6eea5b806af8277723a7b1b475d01643e25bd2e9efa1",
    "docs/adr/0010-language-placement.md": "e4c7504ba4ca75fdc0d54b1a6a3703a00d22294dbebcf58c5fb4c8ca38bf3da1",
})
REGISTRY_PATH = "architecture/review-record/briefs.json"
PACKET_BRIEF = "architecture/review-briefs/REVIEW_BRIEF_PACKET.md"
READER_PATH = "ci/chain_checkpoint.py"
READER_NAME = "_met_registry_001_chain_checkpoint"
RIDERS = (("PACKET", NEW_PACKET + "/packet", PACKET_BRIEF, 1),)
HUNK_RECORD_MEMBERS = frozenset({"authorityPath", "hunkClassVocabulary", "hunkClassRuleSha256", "hunkClassContext",
                                 "classes"})
HUNK_VOCABULARY = ("bridge", "cascade", "other", "record", "register")     # chainmech v2.3 (MON-282-W2-RULED)
HUNK_RULE_SHA256 = "007112479ff663fea703347aed5e8f8ee9ff39a540118002dfd7b42ac592748f"


def reviewed_bytes(path: str) -> bytes:
    """This packet's reviewed bytes of path; a bridged successor projects newer bytes back first."""
    return successor.historical_bytes(path, regular_bytes(path))


def _era_bytes(path: Any, raw: Any) -> bytes:
    """An era file's bytes, checked against its era digest; a path outside the era is refused."""
    expected = ERA_SHA256.get(path) if type(path) is str else None
    require(expected is not None, "MET-REGISTRY-001 reviewed bytes are bound: " + str(path))
    require(type(raw) is bytes and digest(raw) == expected, "unreviewed MET-REGISTRY-001 source: " + path)
    return raw


def _verified(path: str) -> bytes:
    """reviewed_bytes, checked against its era digest on every read; a path outside the era is refused before it is
    read."""
    require(type(path) is str and path in ERA_SHA256, "MET-REGISTRY-001 reviewed bytes are bound: " + str(path))
    return _era_bytes(path, reviewed_bytes(path))


def _bound_read(path: str, expected: Any) -> bytes:
    """reviewed_bytes of a file named by an era-verified record, checked against the digest that record gives it."""
    require(type(path) is str and _sha(expected), "MET-REGISTRY-001 bound read: " + str(path))
    _path(path)
    raw = reviewed_bytes(path)
    require(type(raw) is bytes and digest(raw) == expected, "MET-REGISTRY-001 bound file drift: " + path)
    return raw


def _parsed(raw: Any) -> Any:
    """raw as this layer's strict JSON, or None when it is not bytes holding such JSON."""
    try:
        return parse(raw) if type(raw) is bytes else None
    except ValueError:
        return None


def _holds(check: Any) -> bool:
    """A structural check over this era's data; a malformed value does not hold."""
    try:
        return check() is True
    except (KeyError, TypeError, AttributeError, IndexError, ValueError):
        return False


def _bound(check: Any, message: str) -> None:
    require(_holds(check), message)


def _era_model(path: str, name: str) -> types.ModuleType:
    """A reference module of this era, executed from its verified bytes (no import, no bytecode); it imports only the
    standard library."""
    module = types.ModuleType(name)
    module.__file__ = str(ROOT / path)
    exec(compile(_verified(path), path, "exec", dont_inherit=True), module.__dict__)
    return module


def check_registry(raw: Any, briefs: Any) -> None:
    """V4: the registry differs from the base by exactly this packet's one rider, appended last and pointing at the
    generic packet brief with the sha256 of the brief's bytes; nothing else in it changes."""
    registry = _parsed(raw)
    _bound(lambda: type(registry) is dict and type(registry["briefs"]) is list and type(briefs) is dict
           and all(type(briefs[rider[2]]) is bytes for rider in RIDERS)
           and [entry for entry in registry["briefs"] if entry["series"].startswith(NEW_PACKET + "/")]
           == registry["briefs"][-len(RIDERS):]
           == [{"kind": rider[0], "series": rider[1], "path": rider[2], "sha256": digest(briefs[rider[2]]),
                "version": rider[3]} for rider in RIDERS]
           and digest(canonical(dict(registry, briefs=[entry for entry in registry["briefs"]
                                                      if not entry["series"].startswith(NEW_PACKET + "/")])))
           == REGISTRY_BASE_SHA256,
           "the registry differs from the base by exactly the MET-REGISTRY-001 packet rider, pinning the generic packet "
           "brief")


def validate_registry() -> None:
    """V4 over briefs.json and the generic packet brief."""
    check_registry(_verified(REGISTRY_PATH), {PACKET_BRIEF: _verified(PACKET_BRIEF)})


def check_hunk_record(raw: Any, changed: Any, afters: Any, classify: Any, rule_sha: Any) -> None:
    """V6 (MON-282-W1-A2 condition 8): the record's closed members; it names this layer's authority; the closed
    vocabulary and the pinned rule's sha256 (chainmech v2.3's), which the reader's copy of the rule also carries; the context is this
    step's names; it lists one class per reverse hunk for exactly the changed files; and every class equals the rule's
    class at its position, under this step's context."""
    record = _parsed(raw)
    _bound(lambda: type(record) is dict and set(record) == HUNK_RECORD_MEMBERS
           and record["authorityPath"] == AUTHORITY_PATH,
           "the hunk-class record is closed and names this layer's authority")
    _bound(lambda: record["hunkClassVocabulary"] == list(HUNK_VOCABULARY)
           and record["hunkClassRuleSha256"] == HUNK_RULE_SHA256 == rule_sha,
           "the hunk-class record's vocabulary and rule digest are the pinned ones")
    _bound(lambda: type(record["hunkClassContext"]) is dict and set(record["hunkClassContext"]) == set(HUNK_CONTEXT)
           and all(record["hunkClassContext"][k] == (list(v) if type(v) is tuple else v) for k, v in HUNK_CONTEXT.items()),
           "the hunk-class record's context is this step's names")
    classes = record.get("classes") if type(record) is dict else None
    _bound(lambda: type(changed) is dict and type(classes) is dict and set(classes) == set(changed)
           and all(type(classes[p]) is list and all(type(c) is str for c in classes[p])
                   and len(classes[p]) == len(changed[p]["reverseHunks"]) for p in changed),
           "the hunk-class record lists one class per hunk for exactly the changed files")
    steps = tuple(HUNK_CONTEXT["steps"])
    for path, entry in changed.items():
        seen = set()
        for position, (cls, hunk) in enumerate(zip(classes[path], entry["reverseHunks"])):
            _bound(lambda: cls in HUNK_VOCABULARY and cls == classify(
                path, afters[path], hunk["at"], _base64(hunk["removeBase64"]), _base64(hunk["insertBase64"]),
                HUNK_CONTEXT["prevValidator"], HUNK_CONTEXT["prevTest"], NEW_PACKET, steps, seen=seen),
                   "a recorded class re-checks by position: %s hunk %d" % (path, position))


def validate_hunk_record() -> None:
    """V6 over the authority's hunk-class record (bound by its newFiles digest), the changed files (bound by their
    afterSha256) and the reader's copy of the class rule, executed from its era-verified bytes."""
    record = authority()
    raw = _bound_read(HUNK_RECORD_PATH, record["newFiles"].get(HUNK_RECORD_PATH))
    afters = {path: _bound_read(path, entry["afterSha256"]) for path, entry in record["changedFiles"].items()}
    reader = _era_model(READER_PATH, READER_NAME)
    rule_sha = HUNK_RULE_SHA256 if _verified(READER_PATH).decode("utf-8").count(
        'RULE_SHA256 = "' + HUNK_RULE_SHA256 + '"') == 1 else None
    check_hunk_record(raw, record["changedFiles"], afters, reader.classify, rule_sha)


# V2, the product (CONTRACT_284 section 2, C1-4 and C2-4): the generic first-packet form. A product whose repository
# has no earlier YAML in the chain carries no comparator pin and no predecessor; its main is named by the YAML's own
# 12-hex prefix, and it names the transport runner's digest.
RUNNER_SHA256 = "c8ac40f0b85f327b75748cde7c8498a02fdf48c004dbf3259660b92cc289646f"
PRODUCT_FACTS = MappingProxyType({
    "LAB-REPO-001": MappingProxyType({
        "repository": "mas-harness-research-lab", "predecessors": (),
        "allowedPaths": ('.gitignore', 'README.md', 'LICENSE', 'ci/verify-offline.sh', 'ci/warm-source-isolation.sh', 'ci/network_canary.py', 'ci/run_packet_argv.py', 'ci/zero_bill_scan.py', 'research/'),
        "mainPin": "cc92594d6daa"}),
})


def check_products(raws: Any, record: Any) -> None:
    """V2 on plain data: raws maps each product id to its YAML bytes, record is the authority's value."""
    _bound(lambda: list(raws) == list(PRODUCT_PACKETS) == list(PRODUCT_FACTS) == list(record["productPackets"])
           and record["productComparators"] == {}, "MET-REGISTRY-001 product set (a first packet has no comparator)")
    for name in PRODUCT_PACKETS:
        raw, facts = raws[name], PRODUCT_FACTS[name]
        _bound(lambda: type(raw) is bytes and digest(raw) == record["productPackets"][name],
               "MET-REGISTRY-001 product bytes: " + name)
        packet = safe_load(raw.decode("utf-8"))
        _bound(lambda: packet["id"] == name and packet["repository"] == facts["repository"]
               and tuple(packet["predecessors"]) == facts["predecessors"] == ()
               and tuple(packet["allowedPaths"]) == facts["allowedPaths"], "MET-REGISTRY-001 product facts: " + name)
        _bound(lambda: raw.count(facts["mainPin"].encode()) >= 1 and raw.count(RUNNER_SHA256.encode()) >= 1,
               "MET-REGISTRY-001 product pins: " + name)


def validate_products() -> None:
    record = authority()
    check_products({name: _bound_read("task-packets/%s.yaml" % name, record["productPackets"][name])
                    for name in PRODUCT_PACKETS}, record)


# R1-R7 and D1, the registration (CONTRACT_284 rev 5 section 6; VIS-284-ARGV, VIS-284-DEPTH), read from the
# era-bound bytes, never by running the readers.
R13_ROW = {"id": "research-lab", "name": "mas-harness-research-lab", "kind": "meta", "dependsOn": [],
           "releaseSet": "EXCLUDED"}
SUCCESSOR_REGISTRY = "architecture/repository-registration/repositories.json"
SUCCESSOR_SCHEMA = "architecture/repository-registration/repositories.schema.json"
SUCCESSOR_RECORD, SUCCESSOR_MODULE = "architecture/repository-registration/rule.json", "scripts/repository_registration.py"
SUCCESSOR_PLACEMENT = "architecture/repository-registration/language-placement.json"
PLACEMENT_SCHEMA = "architecture/repository-registration/language-placement.schema.json"
V2_RULE, V2_MODULE = "architecture/chain-product-packets/rule.json", "scripts/chain_identity_v2.py"
PLAN_13 = "docs/repositories/13-mas-harness-research-lab.md"
PLAN_13_SHA256 = "bc19f6a5100c36abfea3dd767932a9c18e4d6ef3c1a65723eba4b067b33bdeb7"
RELEASE_FILES = ("release/repos.lock.json", "release/fixture-release-set.yaml")
COMPOSING_READERS = ("scripts/validate_readiness.py", "scripts/validate_architecture.py", "scripts/check_release_lock.py",
                     "scripts/language_placement.py")


def _assigned(tree: Any, name: str) -> Any:
    found = [n.value for n in tree.body if isinstance(n, ast.Assign) and len(n.targets) == 1
             and isinstance(n.targets[0], ast.Name) and n.targets[0].id == name]
    return found[0] if len(found) == 1 else None


def _names(node: Any) -> list:
    if isinstance(node, ast.Call) and getattr(node.func, "id", None) == "frozenset" and len(node.args) == 1:
        node = node.args[0]
    if not isinstance(node, ast.Set) or not all(isinstance(e, ast.Constant) and type(e.value) is str for e in node.elts):
        return []
    return [e.value for e in node.elts]


def _calls(tree: Any, name: str) -> int:
    return sum(1 for n in ast.walk(tree) if isinstance(n, ast.Call)
               and (getattr(n.func, "id", None) == name or getattr(n.func, "attr", None) == name))


def _constants(node: Any) -> list:
    return [e.value for e in node] if all(isinstance(e, ast.Constant) for e in node) else []


def _placement_lazy(tree: Any) -> bool:
    # VIS-284-LPORACLE: language placement composes once, through the module imported by _composition_module, inside the
    # one `if` whose test is the record's predicate (lexists); it never calls registry_rows nor imports the module eagerly.
    def named(node: Any) -> list:
        return [a.name for a in node.names] + ([node.module] if isinstance(node, ast.ImportFrom) and node.module else [])
    # VIS-284-LPORACLE-2: and once more for the placement, inside its own `if` on its own record's predicate.
    def guarded(name: str) -> list:
        # the identity allow-list admits no `If` attribute name: the node's class is read from its repr
        return [n for n in ast.walk(tree) if str(type(n)) == "<class 'ast.If'>" and _calls(n.test, "lexists") == 1
                and _calls(n, name) == 1 and _calls(n, "_composition_module") == 1]
    eager = [n for n in ast.walk(tree) if isinstance(n, (ast.Import, ast.ImportFrom))
             and any("repository_registration" in name for name in named(n))]
    return (len(guarded("composed_rows")) == 1 and len(guarded("composed_placement_rows")) == 1
            and _calls(tree, "composed_rows") == 1 and _calls(tree, "composed_placement_rows") == 1
            and _calls(tree, "registry_rows") == 0 and _calls(tree, "placement_rows") == 0
            and _calls(tree, "import_module") == 1 and not eager)


def check_registration(raws: Any) -> None:
    # R1-R7 and D1 on plain data: raws maps each era path to its bytes.
    _bound(lambda: all(digest(raws[path]) == expected for path, expected in FROZEN_SHA256.items())
           and set(json.loads(raws[SUCCESSOR_REGISTRY])) == {"schema", "repositories"}
           and json.loads(raws[SUCCESSOR_REGISTRY])["repositories"] == [R13_ROW]
           and set(json.loads(raws[SUCCESSOR_PLACEMENT])) == {"schema", "decision", "repositories"},
           "MET-REGISTRY-001 R1 registry")
    _bound(lambda: (lambda schema, row: json.loads(raws[SUCCESSOR_REGISTRY])["schema"]
                    == {"path": SUCCESSOR_SCHEMA, "sha256": digest(raws[SUCCESSOR_SCHEMA])}
                    and raws[SUCCESSOR_MODULE].count(("REGISTRY_SCHEMA_SHA256 = \"%s\"\n"
                                                      % digest(raws[SUCCESSOR_SCHEMA])).encode()) == 1
                    and schema["additionalProperties"] is False and schema["required"] == ["schema", "repositories"]
                    and list(schema["properties"]) == ["schema", "repositories"]
                    and schema["properties"]["repositories"]["items"] == {"$ref": "#/$defs/repository"}
                    and row["additionalProperties"] is False and row["required"] == ["id", "name", "kind", "dependsOn"]
                    and set(row["properties"]) == {"id", "name", "kind", "dependsOn", "releaseSet"}
                    and row["properties"]["releaseSet"] == {"enum": ["EXCLUDED"]})(
                        json.loads(raws[SUCCESSOR_SCHEMA]), json.loads(raws[SUCCESSOR_SCHEMA])["$defs"]["repository"])
           and (lambda schema: json.loads(raws[SUCCESSOR_PLACEMENT])["schema"]
                == {"path": PLACEMENT_SCHEMA, "sha256": digest(raws[PLACEMENT_SCHEMA])}
                and raws[SUCCESSOR_MODULE].count(("PLACEMENT_SCHEMA_SHA256 = \"%s\"\n"
                                                  % digest(raws[PLACEMENT_SCHEMA])).encode()) == 1
                and schema["additionalProperties"] is False and schema["required"] == ["schema", "decision", "repositories"]
                and schema["$defs"]["placement"]["additionalProperties"] is False
                and schema["$defs"]["placement"]["required"] == ["id", "name", "rNumber", "languages", "toolchain",
                                                                  "sources"])(json.loads(raws[PLACEMENT_SCHEMA])),
           "MET-REGISTRY-001 R2 schema")
    _bound(lambda: (lambda tree, arch: len(_names(_assigned(tree, "EXPECTED_REPOSITORIES")))
                    == len(set(_names(_assigned(tree, "EXPECTED_REPOSITORIES")))) == 13
                    and R13_ROW["name"] not in _names(_assigned(tree, "EXPECTED_REPOSITORIES"))
                    and _assigned(tree, "PHASE_ZERO_INVENTORY_REPOSITORIES") is None
                    and len(_assigned(arch, "EXPECTED_REPOSITORIES").keys) == 13
                    and _constants(_assigned(arch, "EXPECTED_SUCCESSOR_REPOSITORIES").keys) == [R13_ROW["id"]]
                    and _constants(_assigned(arch, "EXPECTED_SUCCESSOR_REPOSITORIES").values) == [R13_ROW["name"]]
                    and all(_calls(ast.parse(raws[path]), "registry_rows") == 1 for path in COMPOSING_READERS[:3])
                    and _placement_lazy(ast.parse(raws["scripts/language_placement.py"])))(
                        ast.parse(raws["scripts/validate_readiness.py"]), ast.parse(raws["scripts/validate_architecture.py"])),
           "MET-REGISTRY-001 R3 constants")
    _bound(lambda: json.loads(raws[SUCCESSOR_RECORD])["extends"] == [
        {"path": V2_RULE, "sha256": digest(raws[V2_RULE]), "clause": "productRepository.allowedNames"},
        {"path": SUCCESSOR_MODULE, "sha256": digest(raws[SUCCESSOR_MODULE]), "clause": "R8 clause 2"}]
           and json.loads(raws[SUCCESSOR_RECORD])["allowedNames"] == [{"fromSlot": 284, "add": ["mas-harness-research-lab"]}]
           and raws[SUCCESSOR_MODULE].count(("V2_SHA256 = \"%s\"" % digest(raws[V2_MODULE])).encode()) == 1
           and raws[SUCCESSOR_MODULE].count(b"\ndef registry_rows(root, safe_load):") == 1
           and raws[SUCCESSOR_MODULE].count(b"\ndef record_present(root):") == 1
           and raws[SUCCESSOR_MODULE].count(b"\ndef composed_rows(") == 1
           and raws[SUCCESSOR_MODULE].count(b"\ndef placement_rows(root):") == 1
           and raws[SUCCESSOR_MODULE].count(b"\ndef placement_record_present(root):") == 1
           and raws[SUCCESSOR_MODULE].count(b"\ndef composed_placement_rows(") == 1,
           "MET-REGISTRY-001 R4 successor record and function")
    _bound(lambda: (lambda lock, reference: all(raws[p].count(reference) == 1 for p in RELEASE_FILES)
                    and lock.count(b'raise ReleaseLockError("releaseSet EXCLUDED on a product repository")') == 1
                    and lock.count(b"    repositories = registry_with_successors()\n") == 1
                    and lock.index(b"    repositories = registry_with_successors()\n")
                    < lock.index(b"releaseSet EXCLUDED on a product") < lock.index(b'if document["documentKind"] == "INERT_LOCK":')
                    and lock.count(b"\nREGISTRATION_ROOT = ROOT  # MET-REGISTRY-001") == 1
                    and lock.count(b"            REGISTRATION_ROOT, lambda raw:") == 1
                    and lock.count(b"if actual_repositories != expected_repositories:") == 1)(
                        raws["scripts/check_release_lock.py"],
                        b"sha256:" + digest(raws["architecture/repositories.yaml"]).encode()),
           "MET-REGISTRY-001 R5 release lock")
    _bound(lambda: digest(raws[PLAN_13]) == PLAN_13_SHA256, "MET-REGISTRY-001 R6 plan")
    _bound(lambda: (lambda placement: raws["docs/adr/0001-repository-boundaries.md"].count(b"exactly fourteen repositories") == 1
                    and raws["docs/adr/0001-repository-boundaries.md"].count(b"`" + SUCCESSOR_REGISTRY.encode() + b"`") == 1
                    and [(r["id"], r["name"], r["rNumber"], r["languages"], r["toolchain"]) for r in placement["repositories"]]
                    == [("research-lab", "mas-harness-research-lab", "R13", ["PYTHON"], "Python 3.12.14")]
                    and placement["decision"]["packet"] == "LAB-REPO-001" and placement["decision"]["policy"] == "LANG-D1"
                    and raws["scripts/language_placement.py"].count(b'\n    "research-lab": ("PYTHON",),\n') == 1
                    and raws["scripts/language_placement.py"].count(b'\n        "research-lab": "Python 3.12.14",\n') == 1
                    and raws["scripts/language_placement.py"].count(b"\nREPOSITORY_COUNT = 13\n") == 1
                    and raws["scripts/language_placement.py"].count(b"\nCOMPOSED_REPOSITORY_COUNT = 14  #") == 1)(
                        json.loads(raws[SUCCESSOR_PLACEMENT])),
           "MET-REGISTRY-001 R7 ADRs and language placement")
    _bound(lambda: raws["scripts/validate_readiness.py"].count(
               b"\nsys.setrecursionlimit(max(_CHAIN_IMPORT_LIMIT, 2000))\ntry:\n") == 1
           and raws["scripts/validate_readiness.py"].count(b"\nfinally:\n    sys.setrecursionlimit(_CHAIN_IMPORT_LIMIT)\n") == 1
           and raws["tests/conftest.py"].count(b"        sys.setrecursionlimit(max(limit, 2000))\n") == 1
           and raws["tests/conftest.py"].count(b"        sys.setrecursionlimit(limit)\n") == 1,
           "MET-REGISTRY-001 D1 bounded raise")


def validate_registration() -> None:
    check_registration({path: _verified(path) for path in ERA_SHA256})


def validate_met_registry_001(packets: dict[str, Any]) -> None:
    """V1, every era file first; then V2 (the product), R1-R7 (the registration), V4 (the registry) and V6 (the
    hunk-class record); last, this layer's canonical hunks."""
    for path in ERA_SHA256:
        _verified(path)
    validate_products()
    validate_registration()
    validate_registry()
    validate_hunk_record()
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
            == record["validatorNormalizedSha256"], "repository registration validator drift")
    paths = sorted((ROOT / "task-packets").glob("*.yaml"))
    old = set(record["baselinePackets"])
    require(len(paths) == 296
            and {path.stem for path in paths} == old | {NEW_PACKET, successor.NEW_PACKET} | set(PRODUCT_PACKETS),
            "closed 296-packet catalog retaining the 295-packet checkpoint")
    packets = {}
    for path in paths:
        if path.stem == successor.NEW_PACKET:
            continue
        raw = regular_bytes("task-packets/" + path.name)
        expected = (record["packetSha256"] if path.stem == NEW_PACKET
                    else record["productPackets"][path.stem] if path.stem in PRODUCT_PACKETS
                    else record["baselinePackets"][path.stem])
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
            "closed source-only repository-registration packet and inherited commands")
    require(len(packet["allowedPaths"]) == len(set(packet["allowedPaths"]))
            and set(packet["allowedPaths"]) == set(record["changedFiles"])
            | set(record["newFiles"]) | {AUTHORITY_PATH, VALIDATOR_PATH,
                                         "task-packets/" + NEW_PACKET + ".yaml"}
            | {"task-packets/" + name + ".yaml" for name in PRODUCT_PACKETS},
            "unreviewed or omitted repository-registration packet path")
    for path, rule in record["changedFiles"].items():
        current = successor.historical_bytes(path, regular_bytes(path))
        require(digest(current) == rule["afterSha256"]
                and digest(historical_bytes(path, current)) == rule["beforeSha256"],
                "unreviewed current source: " + path)
    for path, expected in record["newFiles"].items():
        require(digest(successor.historical_bytes(path, regular_bytes(path))) == expected,
                "new source drift: " + path)
    validate_met_registry_001(packets)


if __name__ == "__main__":
    validate()
    print("Repository registration valid: 296 current specifications at slot 284; 295-packet checkpoint and exact 293-packet predecessor; contract reviewed.")
