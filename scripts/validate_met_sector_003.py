#!/usr/bin/env python3
"""Validate MET-SECTOR-003 (IND-BANK-001-PUBLISH): the first publishing step, publishing the product packet IND-BANK-001 (V1-V4: the product's adopted bytes and facts; the sector record at the base's bytes and this packet's allowedPaths naming the product; the registry's MET-SECTOR-003 packet rider as the one change from the base; no unordered same-repository ownership diagnostic naming the product), and the exact 274-to-273 projection with the product forms."""
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
    import validate_met_verify_005 as successor
except ImportError:
    from scripts.safe_yaml import safe_load
    from scripts import validate_met_verify_005 as successor


ROOT = Path(__file__).resolve().parents[1]
AUTHORITY_PATH = "architecture/ind-bank-001-publish-authority.json"
AUTHORITY_SHA256 = "e4685c0c91e48b423b1a5489a99f7ebdc91630b61dcd83e1ff1aff64609cd1a2"
VALIDATOR_PATH = "scripts/validate_met_sector_003.py"
BASE_COMMIT = "64e5700dbb84902660b08768b42ff1ad5f1fb2e6"
NEW_PACKET = "MET-SECTOR-003"
PREVIOUS_PACKET = "MET-PERF-044"
PRODUCT_PACKETS = ("IND-BANK-001",)
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
            require(key not in result, "duplicate ind-bank-001-publish authority member")
            result[key] = value
        return result

    def no_constant(_value: str) -> Any:
        raise ValueError("nonfinite ind-bank-001-publish authority number")

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
        require(digest(raw) == AUTHORITY_SHA256, "ind bank 001 publish history authority digest")
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
    }, "closed ind bank 001 publish history authority")
    require(value["schemaVersion"] == "harness.planeon.ai/ind-bank-001-publish-authority/v1"
            and value["authorityPacket"] == NEW_PACKET
            and value["acceptedBase"] == BASE_COMMIT
            and type(value["baselinePackets"]) is dict
            and len(value["baselinePackets"]) == 273
            and NEW_PACKET not in value["baselinePackets"]
            and type(value["changedFiles"]) is dict
            and type(value["newFiles"]) is dict
            and _sha(value["packetSha256"])
            and _sha(value["validatorNormalizedSha256"]),
            "accepted 273-packet base")
    require(type(value["productPackets"]) is dict
            and list(value["productPackets"]) == list(PRODUCT_PACKETS)
            and all(_sha(sha) for sha in value["productPackets"].values())
            and not set(PRODUCT_PACKETS) & (set(value["baselinePackets"]) | {NEW_PACKET}),
            "product packets")
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
    # An exact 273-era byte string is already older than the successor layer.
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


# MET-SECTOR-003 (roadmap IND-BANK-001-PUBLISH; the owner's Q-SEC3-TWO and the lane monitor's owner-delegated rulings
# MON-IB1, MON-SEC3-CR1, MON-SEC3-CR2 (errata E1), MON-VB-D2, MON-VB-R03-YES, GO-274-REBASE, Q-274-D1 to Q-274-D3 (a),
# Q-274-V4-1 (a), Q-274-V4-R03, Q-274-V4-2 (a) with MON-274-V4-XCHECK, MON-274-CR4-KEEP and GO-274-ADOPT-C5) is the
# first publishing step of the product-packet vocabulary (CHAIN-PRODUCT-PUBLISH-001): this meta packet publishes the
# product packet task-packets/IND-BANK-001.yaml (PRODUCT_PACKETS, K = 1), the banking business-domain packet for
# mas-harness-industry-packs adopted as candidate c5, so the catalog holds C = 275 packets at slot S = 274. The product
# is not a chain packet: its bytes are pinned by the authority's productPackets, and the class functions above carry
# the product forms F1-F7. Its review series is registered by this packet's own rider in
# architecture/review-record/briefs.json (MET-SECTOR-003/packet, which the evolution surface record at this base classes
# as gate material, so the owner approves the PR). Repository bytes are read only through reviewed_bytes, so a later
# bridged successor projects its own edits away first; a path outside this era is refused before it is read and every
# era file is bound by digest on every read. Each refusal is a pure check over the values read, so every one has a
# failing case on plain data. Checked here: V1, the product (its bytes equal the sha256 pinned below, and its parsed
# facts: its id, its repository, predecessors exactly IND-001 and IND-FIX-001, 19 allowedPaths, no prefetch, 8
# acceptance argv, warm-source access prohibited, no source reuse, and seven contracts strings, the first six c4's and
# the seventh the disclosure Q-274-V4-R03 ruled); V2, the sector record and this packet's paths
# (architecture/sector-direction.json is the base's bytes, and this packet's allowedPaths names the product, R11); V3,
# the registry (it differs from the base by exactly the one rider, pointing at the generic packet brief with the sha256
# of that brief's bytes); and V4, the order (closer-free, Q-274-V4-2 (a): no unordered same-repository ownership
# diagnostic names a product, restating scripts/validate_packet_ownership.py's rule exactly: two packets of one
# repository, neither in the other's transitive predecessor closure, whose allowed paths are equal or one a "/"-prefix
# of the other, each path's trailing "/" stripped; the head test compares this verdict with that module's,
# MON-274-V4-XCHECK). No chain validator or chain test is pinned here. Last, this layer's own inverse hunks are the
# canonical byte-minimal ones, recomputed from its era's bytes (MET-PERF-040's carried rule).
PRODUCT_PATH = "task-packets/" + PRODUCT_PACKETS[0] + ".yaml"
PRODUCT_REPOSITORY = "mas-harness-industry-packs"
PRODUCT_PREDECESSORS = ("IND-001", "IND-FIX-001")
PRODUCT_ALLOWED_PATHS = 19
PRODUCT_ARGV = 8
# V1: the first six contracts strings as adopted in candidate c4 (the digest of their canonical JSON list), and the
# seventh, the disclosure ruled in Q-274-V4-R03, verbatim.
PRODUCT_C4_CONTRACTS_SHA256 = "4109a5ba98f174256f9defec85ef84c6a4013ff38d937066bb3607e5d14db288"
PRODUCT_DISCLOSURE = (
    "Predecessors add IND-FIX-001 beyond the sector-direction authority's predecessorIds [IND-001], "
    "because this packet deletes or rewrites IND-FIX-001's files at its merge 118296af; IND-001 stays "
    "explicit for its OBLIGATION_TRANSFERRED disposition; the retained edge to IND-WG-005 stays "
    "historical."
)
SECTOR_DIRECTION_PATH = "architecture/sector-direction.json"
REGISTRY_PATH = "architecture/review-record/briefs.json"
PACKET_BRIEF = "architecture/review-briefs/REVIEW_BRIEF_PACKET.md"
# V3: the registry at the base (the digest of its canonical JSON) and this packet's one rider (kind, series, path,
# version), appended last; the rider's sha256 is the generic packet brief's.
REGISTRY_BASE_SHA256 = "4fe1965fd83bbf2a35e1013b8003ed1ff499f28cb375007906ddcdda96ad42be"
RIDERS = (("PACKET", NEW_PACKET + "/packet", PACKET_BRIEF, 1),)
# Every file this era's check reads, with its digest: the product, the sector record (the base's bytes), the registry
# and the generic packet brief.
ERA_SHA256 = MappingProxyType({
    "architecture/review-briefs/REVIEW_BRIEF_PACKET.md": "6dcff68d7e6b01823f1740063e94910edcc159a71a6ee803f1b66c62fd06e274",
    "architecture/review-record/briefs.json": "1a15f9a077d004f041ddd993ebeeae55086ba2d19d05fe303abba154b072e69a",
    "architecture/sector-direction.json": "cfc39b4adbfb2771e27cc5498d94530d5691130736a8791288ce296253fc2efe",
    "task-packets/IND-BANK-001.yaml": "4a7cbd12501f38fb3404afece8d38ddb7d14e0c38e6e429929be03dcd7d81957",
})


def reviewed_bytes(path: str) -> bytes:
    """This packet's reviewed bytes of path; a bridged successor projects newer bytes back first."""
    return successor.historical_bytes(path, regular_bytes(path))


def _era_bytes(path: Any, raw: Any) -> bytes:
    """An era file's bytes, checked against its era digest; a path outside the era is refused."""
    expected = ERA_SHA256.get(path) if type(path) is str else None
    require(expected is not None, "MET-SECTOR-003 reviewed bytes are bound: " + str(path))
    require(type(raw) is bytes and digest(raw) == expected, "unreviewed IND-BANK-001-PUBLISH source: " + path)
    return raw


def _verified(path: str) -> bytes:
    """reviewed_bytes, checked against its era digest on every read; a path outside the era is refused before it is
    read."""
    require(type(path) is str and path in ERA_SHA256, "MET-SECTOR-003 reviewed bytes are bound: " + str(path))
    return _era_bytes(path, reviewed_bytes(path))


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


def check_product_bytes(raw: Any) -> None:
    """V1: the product's bytes equal the sha256 pinned for it."""
    _bound(lambda: type(raw) is bytes and digest(raw) == ERA_SHA256[PRODUCT_PATH],
           "the product's bytes equal its pinned digest: " + PRODUCT_PATH)


def check_product_facts(packet: Any) -> None:
    """V1: the product's parsed facts are the adopted ones: its id and repository, predecessors exactly IND-001 and
    IND-FIX-001, 19 distinct allowedPaths, no prefetch, 8 acceptance argv, warm-source access prohibited, no source
    reuse, and seven contracts strings (the first six c4's, the seventh the ruled disclosure)."""
    _bound(lambda: type(packet) is dict and packet["id"] == PRODUCT_PACKETS[0]
           and packet["repository"] == PRODUCT_REPOSITORY
           and packet["predecessors"] == list(PRODUCT_PREDECESSORS)
           and len(packet["allowedPaths"]) == len(set(packet["allowedPaths"])) == PRODUCT_ALLOWED_PATHS
           and packet["prefetchCommands"] == [] and len(packet["offlineAcceptanceCommands"]) == PRODUCT_ARGV
           and packet["warmSourceAccess"] == "PROHIBITED_DURING_IMPLEMENTATION" and packet["sourceReuse"] == []
           and len(packet["contracts"]) == 7
           and digest(canonical(packet["contracts"][:6])) == PRODUCT_C4_CONTRACTS_SHA256
           and packet["contracts"][6] == PRODUCT_DISCLOSURE,
           "the product's facts are the adopted ones: " + PRODUCT_PATH)


def validate_product() -> None:
    """V1 over the product, read through the era."""
    raw = _verified(PRODUCT_PATH)
    check_product_bytes(raw)
    check_product_facts(safe_load(raw))


def check_sector_record(raw: Any) -> None:
    """V2: the sector-direction record is the base's bytes (Q-SEC3-3 (b)); publication is read from task-packets/."""
    _bound(lambda: type(raw) is bytes and digest(raw) == ERA_SHA256[SECTOR_DIRECTION_PATH],
           "architecture/sector-direction.json is the base's bytes")


def check_own_paths(packet: Any) -> None:
    """V2: this packet's allowedPaths names every product it publishes (R11)."""
    _bound(lambda: type(packet) is dict and all("task-packets/" + name + ".yaml" in packet["allowedPaths"]
                                                for name in PRODUCT_PACKETS),
           "the meta packet's allowedPaths names the product")


def check_registry(raw: Any, briefs: Any) -> None:
    """V3: the registry differs from the base by exactly this packet's one rider, appended last and pointing at the
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
           "the registry differs from the base by exactly the MET-SECTOR-003 packet rider, pinning the generic packet "
           "brief")


def validate_registry() -> None:
    """V3 over briefs.json and the generic packet brief."""
    check_registry(_verified(REGISTRY_PATH), {PACKET_BRIEF: _verified(PACKET_BRIEF)})


def _closure(packets: Any, name: str) -> set[str]:
    """The transitive predecessor closure of one packet (validate_packet_ownership's packet_ancestors); an id outside
    the catalog is kept and has no predecessors."""
    result: set[str] = set()
    pending = [name]
    seen: set[str] = set()
    while pending:
        current = pending.pop()
        if current in seen:
            continue
        seen.add(current)
        for predecessor in packets[current]["predecessors"] if current in packets else []:
            result.add(predecessor)
            pending.append(predecessor)
    return result


def _overlap(left: str, right: str) -> bool:
    """validate_packet_ownership's paths_overlap: equal, or one a "/"-prefix of the other, trailing "/" stripped."""
    left, right = str(Path(left)).rstrip("/"), str(Path(right)).rstrip("/")
    return left == right or left.startswith(right + "/") or right.startswith(left + "/")


def order_diagnostics(packets: Any) -> list[str]:
    """V4: the "unordered same-repository packets" diagnostics that name a product, in validate_packet_ownership's own
    wording and pair order (ids sorted, paths in each packet's order)."""
    diagnostics = []
    for product in PRODUCT_PACKETS:
        for other in sorted(packets):
            if other == product or packets[other]["repository"] != packets[product]["repository"]:
                continue
            if other in _closure(packets, product) or product in _closure(packets, other):
                continue
            left, right = sorted((product, other))
            for left_path in packets[left]["allowedPaths"]:
                for right_path in packets[right]["allowedPaths"]:
                    if _overlap(left_path, right_path):
                        diagnostics.append("unordered same-repository packets " + left + " and " + right
                                           + " overlap at " + repr(left_path) + " and " + repr(right_path))
    return diagnostics


def check_order(packets: Any) -> None:
    """V4, closer-free: no unordered same-repository ownership diagnostic names a product."""
    _bound(lambda: type(packets) is dict and all(name in packets for name in PRODUCT_PACKETS)
           and order_diagnostics(packets) == [],
           "no unordered same-repository ownership diagnostic names the product")


def validate_met_sector_003(packets: dict[str, Any]) -> None:
    """Every reviewed byte first; then V1 (the product), V2 (the sector record and this packet's paths), V3 (the
    registry) and V4 (the order, over the packets validate() read); last, this layer's canonical hunks."""
    for path in ERA_SHA256:
        _verified(path)
    validate_product()
    check_sector_record(_verified(SECTOR_DIRECTION_PATH))
    check_own_paths(packets[NEW_PACKET])
    validate_registry()
    check_order(packets)
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
            == record["validatorNormalizedSha256"], "ind bank 001 publish validator drift")
    paths = sorted((ROOT / "task-packets").glob("*.yaml"))
    old = set(record["baselinePackets"])
    require(len(paths) == 278
            and {path.stem for path in paths} == old | {NEW_PACKET, successor.NEW_PACKET, *successor.PRODUCT_PACKETS} | set(PRODUCT_PACKETS),
            "closed 278-packet catalog retaining the 275-packet checkpoint")
    packets = {}
    for path in paths:
        if path.stem == successor.NEW_PACKET:
            continue
        if path.stem in successor.PRODUCT_PACKETS:
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
            "closed source-only ind-bank-001-publish packet and inherited commands")
    require(len(packet["allowedPaths"]) == len(set(packet["allowedPaths"]))
            and set(packet["allowedPaths"]) == set(record["changedFiles"])
            | set(record["newFiles"]) | {AUTHORITY_PATH, VALIDATOR_PATH,
                                         "task-packets/" + NEW_PACKET + ".yaml"}
            | {"task-packets/" + name + ".yaml" for name in PRODUCT_PACKETS},
            "unreviewed or omitted ind-bank-001-publish packet path")
    for path, rule in record["changedFiles"].items():
        current = successor.historical_bytes(path, regular_bytes(path))
        require(digest(current) == rule["afterSha256"]
                and digest(historical_bytes(path, current)) == rule["beforeSha256"],
                "unreviewed current source: " + path)
    for path, expected in record["newFiles"].items():
        require(digest(successor.historical_bytes(path, regular_bytes(path))) == expected,
                "new source drift: " + path)
    validate_met_sector_003(packets)


if __name__ == "__main__":
    validate()
    print("IND-BANK-001 publish valid: 278 current specifications at slot 274; 275-packet checkpoint and exact 273-packet predecessor; contract reviewed.")
