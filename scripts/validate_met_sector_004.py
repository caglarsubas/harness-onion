#!/usr/bin/env python3
"""Validate MET-SECTOR-004 (IND-BANK-002-PUBLISH): the third publishing step, publishing the product packet IND-BANK-002 (V1-V5: the product's frozen bytes and facts; this packet's allowedPaths, R03's plan changed by exactly R03's own item 9 and this repository's meta item; the registry's MET-SECTOR-004 packet rider as the one change from the base; no new ownership diagnostic, 275's closer still outermost; one added YAML per repository), and the exact 276-to-275 projection with the product forms."""
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
    import validate_met_perf_045 as successor
except ImportError:
    from scripts.safe_yaml import safe_load
    from scripts import validate_met_perf_045 as successor


ROOT = Path(__file__).resolve().parents[1]
AUTHORITY_PATH = "architecture/ind-bank-002-publish-authority.json"
AUTHORITY_SHA256 = "f96b51d9319b0a9fb0f8324e6d796c3e6ff01e59bcada7bb029b1d9fd9f47a84"
VALIDATOR_PATH = "scripts/validate_met_sector_004.py"
BASE_COMMIT = "a7ccefedf05016adb71132f51e4578396a90df9e"
NEW_PACKET = "MET-SECTOR-004"
PREVIOUS_PACKET = "MET-VERIFY-005"
PRODUCT_PACKETS = ("IND-BANK-002",)
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
            require(key not in result, "duplicate ind-bank-002-publish authority member")
            result[key] = value
        return result

    def no_constant(_value: str) -> Any:
        raise ValueError("nonfinite ind-bank-002-publish authority number")

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
        require(digest(raw) == AUTHORITY_SHA256, "ind bank 002 publish history authority digest")
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
    }, "closed ind bank 002 publish history authority")
    require(value["schemaVersion"] == "harness.planeon.ai/ind-bank-002-publish-authority/v1"
            and value["authorityPacket"] == NEW_PACKET
            and value["acceptedBase"] == BASE_COMMIT
            and type(value["baselinePackets"]) is dict
            and len(value["baselinePackets"]) == 278
            and NEW_PACKET not in value["baselinePackets"]
            and type(value["changedFiles"]) is dict
            and type(value["newFiles"]) is dict
            and _sha(value["packetSha256"])
            and _sha(value["validatorNormalizedSha256"]),
            "accepted 278-packet base")
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
    # An exact 278-era byte string is already older than the successor layer.
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


# MET-SECTOR-004 (IND-BANK-002-PUBLISH; the lane monitor's owner-delegated rulings Q-276-ID, MON-276-PLAN, MON-276-C1-GO,
# R03-ITEM9 with MON-276-ITEM9-R03, MON-276-CR1-KEEP, MON-276-ORDER-2 and MON-276-MECH-PLAN-OK) is the third publishing
# step of the product-packet vocabulary (CHAIN-PRODUCT-PUBLISH-001): this meta packet publishes one product packet,
# task-packets/IND-BANK-002.yaml (R03's banking data readiness packet), so the catalog holds C = 280 packets at slot
# S = 276 (K = 1). The product is not a chain packet: its bytes are pinned by the authority's productPackets, and the
# class functions above carry the product forms F1-F7. Its review series is registered by this packet's own rider in
# architecture/review-record/briefs.json (MET-SECTOR-004/packet, gate material, so the owner approves the PR).
# Repository bytes are read only through reviewed_bytes, so a later bridged successor projects its own edits away
# first; a path outside this era is refused before it is read and every era file is bound by digest on every read.
# Each refusal is a pure check over the values read, so every one has a failing case on plain data. Checked here: V1,
# the product (its bytes equal the sha256 pinned below; its parsed facts: id, repository, branch, predecessors,
# allowedPaths and acceptance argv exactly as frozen, no prefetch, warm-source access prohibited, no source reuse, and
# R03's main and contracts commits written in full in its contracts); V2, this packet's paths and the two plans (its
# allowedPaths names the product; R03's plan differs from the base by exactly R03's own item 9; this repository's plan
# carries the meta item once, naming the product); V3, the registry (the base plus exactly this packet's rider); V4,
# ownership (the product adds no diagnostic: of validate_packet_ownership's diagnostics none names it and their count
# stays the base's; the head may not import validate_packet_ownership, so check_ownership is a pure check the head test
# feeds with that module's live diagnostics, and 275's close_bootstrap_transport_dispatch stays the outermost closer of
# validate_dispatch_ownership, checked on that file's reviewed bytes); and V5, one added YAML per repository. No chain
# validator or chain test is pinned here. Last, this layer's own inverse hunks are the canonical byte-minimal ones,
# recomputed from its era's bytes (MET-PERF-040's carried rule).
PRODUCT_PATHS = MappingProxyType({name: "task-packets/" + name + ".yaml" for name in PRODUCT_PACKETS})
# V1: the product's frozen facts; allowedPaths and acceptance argv by the digest of their canonical JSON lists.
PRODUCT_FACTS = MappingProxyType({
    "IND-BANK-002": MappingProxyType({"repository": "mas-harness-industry-packs", "branch": "codex/ind-bank-002-data-readiness",
                                     "predecessors": ("IND-BANK-001",),
                                     "allowedPaths": "6b733642fe1b5c3c999e4f270ec5a56822909db75b3a1fa495014720cc3a9dd8",
                                     "commands": "b67081375477682250aff41fa3625808a5e0c398db6a047f54dc282bc3baa702"}),
})
# V1: R03's main and contracts commits, each written in full in the product's contracts (Q-IB2-4).
PRODUCT_PINS = ("bab45acfa34a0fb44d86aaf4e039ea0dfff9690f", "2146278a95344cd2a8e22596b2f315b46edffc88")
# V2: R03's plan, the base's bytes plus exactly R03's own item 9 (R03-ITEM9); this repository's plan, its meta item.
PLAN_PATHS = ("docs/repositories/03-mas-harness-industry-packs.md",)
PLAN_BASE_SHA256 = MappingProxyType({
    "docs/repositories/03-mas-harness-industry-packs.md": "3cfbb64a1be81f17b3bf41ed9896e8eca1e68d2a91d6fab2fa09ea47f797672c",
})
PLAN_INSERT_SHA256 = MappingProxyType({
    "docs/repositories/03-mas-harness-industry-packs.md": ("15ac3919bccad499de4222d8a7dca7dfc9812d4e17ecdc42c8e1d6fd8ee3c0f0",),
})
OWN_PLAN_PATH = "docs/repositories/00-harness-engineering.md"
OWN_ITEM_PREFIX = "150. `MET-SECTOR-004`: "
OWN_ITEM_SHA256 = "2b7ee11415bb33e3bf09c602f71fd580a0e8aa52e13962318b7dac906c99813b"
REGISTRY_PATH = "architecture/review-record/briefs.json"
PACKET_BRIEF = "architecture/review-briefs/REVIEW_BRIEF_PACKET.md"
# V3: the registry at the base (the digest of its canonical JSON) and this packet's one rider (kind, series, path,
# version), appended last; the rider's sha256 is the generic packet brief's.
REGISTRY_BASE_SHA256 = "84921b40126e821f31caf6b2cb2e0cfe06fb84ca7f3308eb4268f13fb2d911ed"
RIDERS = (("PACKET", NEW_PACKET + "/packet", PACKET_BRIEF, 1),)
# V4: no new ownership diagnostic: the base's count, none naming the product; 275's closer stays outermost.
OWNERSHIP_COUNT = 119
CHAIN_PATH = "scripts/validate_conformance_reference_measurement.py"
CLOSER_NAME = "close_bootstrap_transport_dispatch"
CLOSED_BEFORE = "close_traversal_dispatch"
# V5: one added YAML per repository.
ADDED_REPOSITORIES = MappingProxyType({
    "MET-SECTOR-004": "Harness-Engineering",
    "IND-BANK-002": "mas-harness-industry-packs",
})
# Every file this era's check reads, with its digest: the product, the two plans, the registry, the generic packet
# brief and the dispatch chain.
ERA_SHA256 = MappingProxyType({
    "architecture/review-briefs/REVIEW_BRIEF_PACKET.md": "6dcff68d7e6b01823f1740063e94910edcc159a71a6ee803f1b66c62fd06e274",
    "architecture/review-record/briefs.json": "cd23a982fd56a4ee55b742776e76f25682fe20931b90832576c4e3d72d32c0fe",
    "docs/repositories/00-harness-engineering.md": "10744d754d3d7121f527a353fd883ead668a0a5e7d60992b3a29cdb53f262117",
    "docs/repositories/03-mas-harness-industry-packs.md": "968254f241530d64f82c728bba4a89d1d7c6c52516b1bf659a156ff8f6b67412",
    "scripts/validate_conformance_reference_measurement.py": "863ae71fe33ac77b353e9067c3149772ea7cf2a12e79a565be1572dd970f3f93",
    "task-packets/IND-BANK-002.yaml": "6af9cfe2c3c3577f1644473737d995c76393de9f504738245303d3ec9abda7d5",
})


def reviewed_bytes(path: str) -> bytes:
    """This packet's reviewed bytes of path; a bridged successor projects newer bytes back first."""
    return successor.historical_bytes(path, regular_bytes(path))


def _era_bytes(path: Any, raw: Any) -> bytes:
    """An era file's bytes, checked against its era digest; a path outside the era is refused."""
    expected = ERA_SHA256.get(path) if type(path) is str else None
    require(expected is not None, "MET-SECTOR-004 reviewed bytes are bound: " + str(path))
    require(type(raw) is bytes and digest(raw) == expected, "unreviewed IND-BANK-002-PUBLISH source: " + path)
    return raw


def _verified(path: str) -> bytes:
    """reviewed_bytes, checked against its era digest on every read; a path outside the era is refused before it is
    read."""
    require(type(path) is str and path in ERA_SHA256, "MET-SECTOR-004 reviewed bytes are bound: " + str(path))
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


def check_product_bytes(name: Any, raw: Any) -> None:
    """V1: the product's bytes equal the sha256 pinned for it."""
    _bound(lambda: type(raw) is bytes and digest(raw) == ERA_SHA256[PRODUCT_PATHS[name]],
           "the product's bytes equal its pinned digest: " + str(name))


def check_product_facts(name: Any, packet: Any) -> None:
    """V1: the product's parsed facts are the frozen ones: id, repository, branch, predecessors, allowedPaths and
    acceptance argv (by canonical digest, in order), no prefetch, warm-source access prohibited, no source reuse, and
    R03's main and contracts commits written in full in its contracts."""
    _bound(lambda: type(packet) is dict and packet["id"] == name
           and packet["repository"] == PRODUCT_FACTS[name]["repository"]
           and packet["branch"] == PRODUCT_FACTS[name]["branch"]
           and packet["predecessors"] == list(PRODUCT_FACTS[name]["predecessors"])
           and digest(canonical(packet["allowedPaths"])) == PRODUCT_FACTS[name]["allowedPaths"]
           and digest(canonical(packet["offlineAcceptanceCommands"])) == PRODUCT_FACTS[name]["commands"]
           and packet["prefetchCommands"] == []
           and packet["warmSourceAccess"] == "PROHIBITED_DURING_IMPLEMENTATION" and packet["sourceReuse"] == []
           and all(pin in " ".join(packet["contracts"]) for pin in PRODUCT_PINS),
           "the product's facts are the frozen ones: " + str(name))


def validate_products() -> None:
    """V1 over the product, read through the era."""
    for name in PRODUCT_PACKETS:
        raw = _verified(PRODUCT_PATHS[name])
        check_product_bytes(name, raw)
        check_product_facts(name, safe_load(raw))


def check_own_paths(packet: Any) -> None:
    """V2: this packet's allowedPaths names every product it publishes."""
    _bound(lambda: type(packet) is dict and all(PRODUCT_PATHS[name] in packet["allowedPaths"]
                                                for name in PRODUCT_PACKETS),
           "the meta packet's allowedPaths names the product")


def check_plan(path: Any, raw: Any, inserts: Any) -> None:
    """V2: a repository plan is the base's bytes plus exactly its yes'd texts: each insert occurs once, and with every
    insert removed the plan's digest is the base's."""
    def holds() -> bool:
        text = raw.decode("utf-8")
        if type(inserts) is not list or len(inserts) != len(PLAN_INSERT_SHA256[path]):
            return False
        rest = text
        for insert, expected in zip(inserts, PLAN_INSERT_SHA256[path]):
            if type(insert) is not str or digest(insert.encode("utf-8")) != expected or text.count(insert) != 1:
                return False
            rest = rest.replace(insert, "", 1)
        return digest(rest.encode("utf-8")) == PLAN_BASE_SHA256[path]
    _bound(holds, "the plan differs from the base by exactly its yes'd texts: " + str(path))


def plan_inserts(path: str, raw: bytes) -> list[str]:
    """The yes'd texts in a plan, found by digest: every line of the plan whose digest is one of the pinned inserts
    (R03's item 9 is one line)."""
    lines = raw.decode("utf-8").splitlines(keepends=True)
    found = []
    for expected in PLAN_INSERT_SHA256[path]:
        hits = [line for line in lines if digest(line.encode("utf-8")) == expected]
        found.append(hits[0] if len(hits) == 1 else "")
    return found


def check_own_plan_item(raw: Any) -> None:
    """V2: this repository's plan holds the meta item exactly once, with its pinned text, naming every product."""
    def holds() -> bool:
        items = [line for line in raw.decode("utf-8").splitlines(keepends=True) if line.startswith(OWN_ITEM_PREFIX)]
        return (len(items) == 1 and digest(items[0].encode("utf-8")) == OWN_ITEM_SHA256
                and all(name in items[0] for name in PRODUCT_PACKETS))
    _bound(holds, "this repository's plan holds the MET-SECTOR-004 item once, naming the product")


def validate_plans() -> None:
    """V2 over R03's plan and this repository's plan."""
    for path in PLAN_PATHS:
        raw = _verified(path)
        check_plan(path, raw, plan_inserts(path, raw))
    check_own_plan_item(_verified(OWN_PLAN_PATH))


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
           "the registry differs from the base by exactly the MET-SECTOR-004 packet rider, pinning the generic packet "
           "brief")


def validate_registry() -> None:
    """V3 over briefs.json and the generic packet brief."""
    check_registry(_verified(REGISTRY_PATH), {PACKET_BRIEF: _verified(PACKET_BRIEF)})


def check_ownership(diagnostics: Any) -> None:
    """V4: validate_packet_ownership's diagnostics keep the base's count and none names the product."""
    _bound(lambda: type(diagnostics) is list and all(type(item) is str for item in diagnostics)
           and len(diagnostics) == OWNERSHIP_COUNT
           and not [item for item in diagnostics if any(name in item for name in PRODUCT_PACKETS)],
           "the product adds no ownership diagnostic: 119 diagnostics, none naming it")


def check_closer_position(raw: Any) -> None:
    """V4: validate_dispatch_ownership's return still calls 275's close_bootstrap_transport_dispatch exactly once,
    outermost, around close_traversal_dispatch; no other call of it exists in the chain file."""
    def holds() -> bool:
        try:
            tree = ast.parse(raw.decode("utf-8"))
        except SyntaxError:
            return False
        names = [node.func.id for node in ast.walk(tree) if isinstance(node, ast.Call)
                 and isinstance(node.func, ast.Name) and node.func.id == CLOSER_NAME]
        chain = [node for node in tree.body if isinstance(node, ast.FunctionDef)
                 and node.name == "validate_dispatch_ownership"]
        returns = [node.value for node in ast.walk(chain[0]) if isinstance(node, ast.Return)
                   and isinstance(node.value, ast.Call) and isinstance(node.value.func, ast.Name)
                   and node.value.func.id.startswith("close_")]
        return (len(names) == 1 and len(chain) == 1 and len(returns) == 1
                and returns[0].func.id == CLOSER_NAME and len(returns[0].args) == 2
                and isinstance(returns[0].args[1], ast.Call) and isinstance(returns[0].args[1].func, ast.Name)
                and returns[0].args[1].func.id == CLOSED_BEFORE)
    _bound(holds, "close_bootstrap_transport_dispatch stays the outermost closer of validate_dispatch_ownership")


def validate_ownership() -> None:
    """V4 over the dispatch chain's reviewed bytes: 275's closer is still its outermost call."""
    check_closer_position(_verified(CHAIN_PATH))


def check_one_per_repository(packets: Any) -> None:
    """V5: the YAMLs this packet adds (itself and its product) name each of their two repositories exactly once."""
    _bound(lambda: type(packets) is dict
           and {name: packets[name]["repository"] for name in (NEW_PACKET, *PRODUCT_PACKETS)} == dict(ADDED_REPOSITORIES)
           and len(set(ADDED_REPOSITORIES.values())) == len(ADDED_REPOSITORIES) == 1 + len(PRODUCT_PACKETS),
           "one added YAML per repository")


def validate_met_sector_004(packets: dict[str, Any]) -> None:
    """Every reviewed byte first; then V1 (the product), V2 (this packet's paths and the two plans), V3 (the registry),
    V4 (275's closer still outermost) and V5 (one added YAML per repository), over the packets validate() read; last,
    this layer's canonical hunks."""
    for path in ERA_SHA256:
        _verified(path)
    validate_products()
    check_own_paths(packets[NEW_PACKET])
    validate_plans()
    validate_registry()
    validate_ownership()
    check_one_per_repository(packets)
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
            == record["validatorNormalizedSha256"], "ind bank 002 publish validator drift")
    paths = sorted((ROOT / "task-packets").glob("*.yaml"))
    old = set(record["baselinePackets"])
    require(len(paths) == 286
            and {path.stem for path in paths} == old | {NEW_PACKET, successor.NEW_PACKET, successor.successor.NEW_PACKET, *successor.successor.PRODUCT_PACKETS, successor.successor.successor.NEW_PACKET, *successor.successor.successor.PRODUCT_PACKETS} | set(PRODUCT_PACKETS),
            "closed 286-packet catalog retaining the 280-packet checkpoint")
    packets = {}
    for path in paths:
        if path.stem in (successor.NEW_PACKET, successor.successor.NEW_PACKET, *successor.successor.PRODUCT_PACKETS, successor.successor.successor.NEW_PACKET, *successor.successor.successor.PRODUCT_PACKETS):
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
            "closed source-only ind-bank-002-publish packet and inherited commands")
    require(len(packet["allowedPaths"]) == len(set(packet["allowedPaths"]))
            and set(packet["allowedPaths"]) == set(record["changedFiles"])
            | set(record["newFiles"]) | {AUTHORITY_PATH, VALIDATOR_PATH,
                                         "task-packets/" + NEW_PACKET + ".yaml"}
            | {"task-packets/" + name + ".yaml" for name in PRODUCT_PACKETS},
            "unreviewed or omitted ind-bank-002-publish packet path")
    for path, rule in record["changedFiles"].items():
        current = successor.historical_bytes(path, regular_bytes(path))
        require(digest(current) == rule["afterSha256"]
                and digest(historical_bytes(path, current)) == rule["beforeSha256"],
                "unreviewed current source: " + path)
    for path, expected in record["newFiles"].items():
        require(digest(successor.historical_bytes(path, regular_bytes(path))) == expected,
                "new source drift: " + path)
    validate_met_sector_004(packets)


if __name__ == "__main__":
    validate()
    print("IND-BANK-002 publish valid: 286 current specifications at slot 276; 280-packet checkpoint and exact 278-packet predecessor; contract reviewed.")
