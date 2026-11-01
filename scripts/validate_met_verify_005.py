#!/usr/bin/env python3
"""Validate MET-VERIFY-005 (VERIFIER-EXT-R04-R11): the second publishing step, publishing the product packets DIST-TRANSPORT-001 and CTRL-TRANSPORT-001 (V1-V5: the products' frozen bytes and facts; this packet's allowedPaths and R04's and R11's plans changed by exactly their yes'd texts; the registry's MET-VERIFY-005 packet rider as the one change from the base; one ownership diagnostic, closed by close_bootstrap_transport_dispatch outermost; one added YAML per repository), and the exact 275-to-274 projection with the product forms."""
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
except ImportError:
    from scripts.safe_yaml import safe_load


ROOT = Path(__file__).resolve().parents[1]
AUTHORITY_PATH = "architecture/transport-bootstraps-publish-authority.json"
AUTHORITY_SHA256 = "eff10083bc5046ce4b92f0dd00c2fe461e2993dca8dfe0a35f55d46c04eed7d9"
VALIDATOR_PATH = "scripts/validate_met_verify_005.py"
BASE_COMMIT = "57bb1033e4a68cbb38610987060aedd8e879c7e6"
NEW_PACKET = "MET-VERIFY-005"
PREVIOUS_PACKET = "MET-SECTOR-003"
PRODUCT_PACKETS = ("DIST-TRANSPORT-001", "CTRL-TRANSPORT-001")
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
            require(key not in result, "duplicate transport-bootstraps-publish authority member")
            result[key] = value
        return result

    def no_constant(_value: str) -> Any:
        raise ValueError("nonfinite transport-bootstraps-publish authority number")

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
    global _VERIFIED_AUTHORITY
    raw = regular_bytes(AUTHORITY_PATH)
    if type(raw) is not bytes or _VERIFIED_AUTHORITY != (AUTHORITY_SHA256, raw):
        require(digest(raw) == AUTHORITY_SHA256, "transport bootstraps publish history authority digest")
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
    }, "closed transport bootstraps publish history authority")
    require(value["schemaVersion"] == "harness.planeon.ai/transport-bootstraps-publish-authority/v1"
            and value["authorityPacket"] == NEW_PACKET
            and value["acceptedBase"] == BASE_COMMIT
            and type(value["baselinePackets"]) is dict
            and len(value["baselinePackets"]) == 275
            and NEW_PACKET not in value["baselinePackets"]
            and type(value["changedFiles"]) is dict
            and type(value["newFiles"]) is dict
            and _sha(value["packetSha256"])
            and _sha(value["validatorNormalizedSha256"]),
            "accepted 275-packet base")
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
    """Recheck the pinned authority and undo only this reviewed successor."""
    _checked_authority_raw()
    _path(path)
    require(type(raw) is bytes and len(raw) <= MAX_FILE_BYTES, "bounded source bytes required")
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
    _checked_authority_raw()
    require(type(raw) is bytes and len(raw) <= MAX_FILE_BYTES, "bounded test bytes required")
    current_sha = digest(raw)
    matches = [path for path, rule in _PROJECTION_RULES.items()
               if path.startswith(TEST_PREFIXES) and current_sha == rule["afterSha256"]]
    require(len(matches) <= 1, "ambiguous current test")
    return _undo_this_layer(matches[0], raw) if matches else raw


def current_test_bytes(before: bytes) -> bytes:
    _checked_authority_raw()
    require(type(before) is bytes and len(before) <= MAX_FILE_BYTES, "bounded test bytes required")
    before_sha = digest(before)
    matches = [path for path, rule in _PROJECTION_RULES.items()
               if path.startswith(TEST_PREFIXES) and before_sha == rule["beforeSha256"]]
    require(len(matches) <= 1, "ambiguous predecessor test")
    if not matches:
        return before
    current = regular_bytes(matches[0])
    require(digest(current) == _PROJECTION_RULES[matches[0]]["afterSha256"],
            "current test drift")
    return current


def historical_catalog(packets: dict[str, Any]) -> dict[str, Any]:
    """Remove only this layer, leaving predecessor checks to their owners."""
    _checked_authority_raw()
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


# MET-VERIFY-005 (VERIFIER-EXT-R04-R11 section 5 step 2; the lane monitor's owner-delegated rulings Q-275-ID, Q-275-ORDER,
# Q-275-R04BASE, Q-275-OWN-1 (c), Q-275-PLANSEC, Q-275-K2 (a), MON-275-K1-BRIDGE-FORM, MON-275-C1-A and MON-275-CR1-KEEP)
# is the second publishing step of the product-packet vocabulary (CHAIN-PRODUCT-PUBLISH-001): this meta packet publishes
# two product packets in install order, task-packets/DIST-TRANSPORT-001.yaml (R11's transport bootstrap) and
# task-packets/CTRL-TRANSPORT-001.yaml (R04's), so the catalog holds C = 278 packets at slot S = 275 (K = 2). The
# products are not chain packets: their bytes are pinned by the authority's productPackets, and the class functions
# above carry the product forms F1-F7. Its review series is registered by this packet's own rider in
# architecture/review-record/briefs.json (MET-VERIFY-005/packet, gate material, so the owner approves the PR).
# Repository bytes are read only through reviewed_bytes, so a later bridged successor projects its own edits away
# first; a path outside this era is refused before it is read and every era file is bound by digest on every read.
# Each refusal is a pure check over the values read, so every one has a failing case on plain data. Checked here: V1,
# each product (its bytes equal the sha256 pinned below; its parsed facts: id, repository, branch, predecessors,
# allowedPaths and acceptance argv exactly as frozen, no prefetch, warm-source access prohibited, no source reuse, the
# "verifiable only once" contract, and the four transport files' sha256 as harness-onion holds them); V2, this
# packet's paths and the two plans (its allowedPaths names both products; R04's plan differs from the base by exactly
# item 12 and the transport-correction section, R11's by exactly item 9, each the yes'd text); V3, the registry (the
# base plus exactly this packet's rider); V4, ownership (the closer below removes exactly one message,
# DIST-TRANSPORT-001's overlap with the DIST-FIX-001 bootstrap correction, only for DIST's id and final sha256, and
# validate_dispatch_ownership calls it outermost, checked on that file's reviewed bytes; the head may not import
# validate_packet_ownership, so check_ownership is a pure check the head test feeds with that module's live
# diagnostics, as 274's MON-274-V4-XCHECK did, and the dispatch chain enforces the set at run time); and V5, one
# added YAML per repository. No chain validator or chain test is pinned here. Last, this layer's own inverse hunks
# are the canonical byte-minimal ones, recomputed from its era's bytes (MET-PERF-040's carried rule).
PRODUCT_PATHS = MappingProxyType({name: "task-packets/" + name + ".yaml" for name in PRODUCT_PACKETS})
# V1: each product's frozen facts; allowedPaths and acceptance argv by the digest of their canonical JSON lists.
PRODUCT_FACTS = MappingProxyType({
    "DIST-TRANSPORT-001": MappingProxyType({"repository": "mas-harness-distribution", "branch": "codex/dist-transport-001-verifier-bootstrap",
                                     "predecessors": ("DIST-004",),
                                     "allowedPaths": "aa718fb21517149f627994afb0623f005bbb45aca9a10b043d7dfbf5847068b2",
                                     "commands": "7d2c140dcc2355584bc5ef0dad53020ce33452c19d915dffe4eb13baef01dfa2"}),
    "CTRL-TRANSPORT-001": MappingProxyType({"repository": "mas-harness-control-plane", "branch": "codex/ctrl-transport-001-verifier-bootstrap",
                                     "predecessors": ("CTRL-FIX-003",),
                                     "allowedPaths": "b2632a7179ace757eeb878d3ac462cfa67022f9350c89694083d7a0b7c6007b4",
                                     "commands": "391fad31c486f17c3f941c8bdaf30523949fcfe9df680a68a4806e65034cbb73"}),
})
ONLY_ONCE = "verifiable only once VERIFIER-EXT-R04-R11 is installed"
ONLY_ONCE_FORMS = (ONLY_ONCE, "V" + ONLY_ONCE[1:])  # DIST writes it mid-sentence, CTRL at a sentence start
TRANSPORT_PATHS = ("ci/verify-offline.sh", "ci/warm-source-isolation.sh", "ci/network_canary.py", "ci/run_packet_argv.py")
# V2: the two plans, each the base's bytes plus exactly its yes'd texts (R04 item 12 and the section; R11 item 9).
PLAN_PATHS = ("docs/repositories/04-mas-harness-control-plane.md", "docs/repositories/11-mas-harness-distribution.md")
PLAN_BASE_SHA256 = MappingProxyType({
    "docs/repositories/04-mas-harness-control-plane.md": "1de910ca13ab48b5129db80a75d02d5bda64574f6e7c8a2417b4ba4c63f6735d",
    "docs/repositories/11-mas-harness-distribution.md": "2ede19ddcaddbec5ba698b9e6cefcb224833a932d887ec217ed347abef777684",
})
PLAN_INSERT_SHA256 = MappingProxyType({
    "docs/repositories/04-mas-harness-control-plane.md": ("7ac2d14bed3787a023b05508b439f484e473fcf7303b1c36af06fbe5b40b9257", "cf8ecc67573cb448f299a68db44bffb38a658503205c1d0acaa45f62b6fddd8f",),
    "docs/repositories/11-mas-harness-distribution.md": ("518174d2bb925d36268b557fcffd4979eebc881498bf889186d0fbb23ce3620a",),
})
REGISTRY_PATH = "architecture/review-record/briefs.json"
PACKET_BRIEF = "architecture/review-briefs/REVIEW_BRIEF_PACKET.md"
# V3: the registry at the base (the digest of its canonical JSON) and this packet's one rider (kind, series, path,
# version), appended last; the rider's sha256 is the generic packet brief's.
REGISTRY_BASE_SHA256 = "c7223b0e3d05f96760f75ba68e47a42aebb11d51fa167a59e1d746d85aeebc91"
RIDERS = (("PACKET", NEW_PACKET + "/packet", PACKET_BRIEF, 1),)
# V4: the one ownership diagnostic the products add (Q-275-OWN-1 (c)), the product it names, and the chain that closes it.
OVERLAP = "product packet DIST-TRANSPORT-001 overlaps the DIST-FIX-001 bootstrap correction"
OVERLAP_PRODUCT = "DIST-TRANSPORT-001"
OVERLAP_PREDECESSORS = ("DIST-004",)
CHAIN_PATH = "scripts/validate_conformance_reference_measurement.py"
CLOSER_NAME = "close_bootstrap_transport_dispatch"
CLOSED_BEFORE = "close_traversal_dispatch"
# V5: one added YAML per repository.
ADDED_REPOSITORIES = MappingProxyType({
    "MET-VERIFY-005": "Harness-Engineering",
    "DIST-TRANSPORT-001": "mas-harness-distribution",
    "CTRL-TRANSPORT-001": "mas-harness-control-plane",
})
# Every file this era's check reads, with its digest: the products, the four transport files, the two plans, the
# registry, the generic packet brief and the dispatch chain.
ERA_SHA256 = MappingProxyType({
    "architecture/review-briefs/REVIEW_BRIEF_PACKET.md": "6dcff68d7e6b01823f1740063e94910edcc159a71a6ee803f1b66c62fd06e274",
    "architecture/review-record/briefs.json": "567af21db8698bb839cf50eca8311641787b7ddd77128301a8e2da1364660468",
    "ci/network_canary.py": "1be4a837c4a5baee900db20007c4841361b8c823a1b5e521badcf28890d82099",
    "ci/run_packet_argv.py": "c2ed0852fa499f194bc91291c32d08b303ea79be3ba7ca6cb29a786d585929f5",
    "ci/verify-offline.sh": "778cb0faf59786dc31559e5d96a399d1e3bb26a4576e0ee9ff70e1f6546bd114",
    "ci/warm-source-isolation.sh": "f717f62fb1c9fdaec9eb594c733f25b17394bae6b90a311b9ccc08d4eaf9233b",
    "docs/repositories/04-mas-harness-control-plane.md": "21e8d62d93252f92406569db4ea734834b4ab9d4ba13118f24deb4ee5b35bc74",
    "docs/repositories/11-mas-harness-distribution.md": "3b384263aac2bd41a3158f391f2ab60208043bb59354f2a3e547632c969f8d4a",
    "scripts/validate_conformance_reference_measurement.py": "638e5a0786ed62ca4ff2bae4d62f3db5d52f1176966eede9bff87733253989d1",
    "task-packets/CTRL-TRANSPORT-001.yaml": "729dd73afedc70460543fb55f2708805c31fb7d758f691b15a4a67a2cac3a3f6",
    "task-packets/DIST-TRANSPORT-001.yaml": "9da0fdeed10743e3b65505415334290803b3a4f1da1e1c5ea9268d12dfaf44a9",
})


def reviewed_bytes(path: str) -> bytes:
    """This packet's reviewed bytes of path; a bridged successor projects newer bytes back first."""
    return regular_bytes(path)


def _era_bytes(path: Any, raw: Any) -> bytes:
    """An era file's bytes, checked against its era digest; a path outside the era is refused."""
    expected = ERA_SHA256.get(path) if type(path) is str else None
    require(expected is not None, "MET-VERIFY-005 reviewed bytes are bound: " + str(path))
    require(type(raw) is bytes and digest(raw) == expected, "unreviewed VERIFIER-EXT-R04-R11 source: " + path)
    return raw


def _verified(path: str) -> bytes:
    """reviewed_bytes, checked against its era digest on every read; a path outside the era is refused before it is
    read."""
    require(type(path) is str and path in ERA_SHA256, "MET-VERIFY-005 reviewed bytes are bound: " + str(path))
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
    """V1: a product's bytes equal the sha256 pinned for it."""
    _bound(lambda: type(raw) is bytes and digest(raw) == ERA_SHA256[PRODUCT_PATHS[name]],
           "the product's bytes equal its pinned digest: " + str(name))


def check_product_facts(name: Any, packet: Any, transport: Any) -> None:
    """V1: a product's parsed facts are the frozen ones: id, repository, branch, predecessors, allowedPaths and
    acceptance argv (by canonical digest, in order), no prefetch, warm-source access prohibited, no source reuse, the
    "verifiable only once" contract, and every transport file's sha256 (as harness-onion holds it) named in it."""
    _bound(lambda: type(packet) is dict and type(transport) is dict and packet["id"] == name
           and packet["repository"] == PRODUCT_FACTS[name]["repository"]
           and packet["branch"] == PRODUCT_FACTS[name]["branch"]
           and packet["predecessors"] == list(PRODUCT_FACTS[name]["predecessors"])
           and digest(canonical(packet["allowedPaths"])) == PRODUCT_FACTS[name]["allowedPaths"]
           and digest(canonical(packet["offlineAcceptanceCommands"])) == PRODUCT_FACTS[name]["commands"]
           and packet["prefetchCommands"] == []
           and packet["warmSourceAccess"] == "PROHIBITED_DURING_IMPLEMENTATION" and packet["sourceReuse"] == []
           and sum(any(form in " ".join(item.split()) for form in ONLY_ONCE_FORMS) for item in packet["contracts"]) == 1
           and set(transport) == set(TRANSPORT_PATHS)
           and all(digest(transport[path]) in " ".join(packet["contracts"]) for path in TRANSPORT_PATHS),
           "the product's facts are the frozen ones: " + str(name))


def validate_products() -> None:
    """V1 over both products, read through the era."""
    transport = {path: _verified(path) for path in TRANSPORT_PATHS}
    for name in PRODUCT_PACKETS:
        raw = _verified(PRODUCT_PATHS[name])
        check_product_bytes(name, raw)
        check_product_facts(name, safe_load(raw), transport)


def check_own_paths(packet: Any) -> None:
    """V2: this packet's allowedPaths names every product it publishes (R11)."""
    _bound(lambda: type(packet) is dict and all(PRODUCT_PATHS[name] in packet["allowedPaths"]
                                                for name in PRODUCT_PACKETS),
           "the meta packet's allowedPaths names both products")


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
    """The yes'd texts in a plan, found by digest: every line run of the plan whose digest is one of the pinned inserts
    (items are one line; R04's section is its 24 lines plus the blank line after it)."""
    lines = raw.decode("utf-8").splitlines(keepends=True)
    found = []
    for expected in PLAN_INSERT_SHA256[path]:
        hits = [("".join(lines[i:j])) for i in range(len(lines)) for j in (i + 1, i + 25)
                if j <= len(lines) and digest("".join(lines[i:j]).encode("utf-8")) == expected]
        found.append(hits[0] if len(hits) == 1 else "")
    return found


def validate_plans() -> None:
    """V2 over R04's and R11's plans."""
    for path in PLAN_PATHS:
        raw = _verified(path)
        check_plan(path, raw, plan_inserts(path, raw))


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
           "the registry differs from the base by exactly the MET-VERIFY-005 packet rider, pinning the generic packet "
           "brief")


def validate_registry() -> None:
    """V3 over briefs.json and the generic packet brief."""
    check_registry(_verified(REGISTRY_PATH), {PACKET_BRIEF: _verified(PACKET_BRIEF)})


def check_ownership(diagnostics: Any) -> None:
    """V4: of validate_packet_ownership's diagnostics, exactly one names a product: the DIST-FIX-001 overlap, once."""
    _bound(lambda: type(diagnostics) is list and all(type(item) is str for item in diagnostics)
           and [item for item in diagnostics if any(name in item for name in PRODUCT_PACKETS)] == [OVERLAP],
           "exactly one ownership diagnostic names a product: the DIST-FIX-001 bootstrap correction overlap")


def check_closer_position(raw: Any) -> None:
    """V4: validate_dispatch_ownership's return calls close_bootstrap_transport_dispatch exactly once, outermost, around
    the previous outermost closer; no other call of it exists in the chain file."""
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
    _bound(holds, "close_bootstrap_transport_dispatch is the outermost closer of validate_dispatch_ownership")


def close_bootstrap_transport_dispatch(packets: Any, errors: Any) -> list[str]:
    """Q-275-OWN-1 (c): remove exactly the one DIST-FIX-001 correction-path overlap, only for DIST-TRANSPORT-001's final
    bytes and its predecessors, and only when the message is present once; otherwise add a refusal. Called outermost
    in validate_dispatch_ownership; a second call finds no message and refuses."""
    try:
        require(type(errors) is list and all(type(item) is str for item in errors), "diagnostic list")
        raw = _verified(PRODUCT_PATHS[OVERLAP_PRODUCT])
        require(type(packets) is dict and canonical(packets.get(OVERLAP_PRODUCT)) == canonical(safe_load(raw))
                and packets[OVERLAP_PRODUCT]["predecessors"] == list(OVERLAP_PREDECESSORS), "exact final product")
        require(errors.count(OVERLAP) == 1, "exact single bootstrap transport overlap")
        return [item for item in errors if item != OVERLAP]
    except (ValueError, TypeError, KeyError, OSError, RecursionError):
        return list(errors) + ["missing or changed closed bootstrap transport dispatch"]


def validate_ownership() -> None:
    """V4 over the dispatch chain's reviewed bytes: the closer is its outermost call."""
    check_closer_position(_verified(CHAIN_PATH))


def check_one_per_repository(packets: Any) -> None:
    """V5: the YAMLs this packet adds (itself and its products) name each of their three repositories exactly once."""
    _bound(lambda: type(packets) is dict
           and {name: packets[name]["repository"] for name in (NEW_PACKET, *PRODUCT_PACKETS)} == dict(ADDED_REPOSITORIES)
           and len(set(ADDED_REPOSITORIES.values())) == len(ADDED_REPOSITORIES) == 1 + len(PRODUCT_PACKETS),
           "one added YAML per repository")


def validate_met_verify_005(packets: dict[str, Any]) -> None:
    """Every reviewed byte first; then V1 (the products), V2 (this packet's paths and the two plans), V3 (the registry),
    V4 (the closer's position) and V5 (one added YAML per repository), over the packets validate() read; last, this
    layer's canonical hunks."""
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
    validator_raw = regular_bytes(VALIDATOR_PATH)
    literal = b'AUTHORITY_SHA256 = "' + AUTHORITY_SHA256.encode("ascii") + b'"'
    placeholder = b'AUTHORITY_SHA256 = "TO_BE_PINNED_AFTER_SOURCE_FREEZE"'
    require(validator_raw.count(literal) == 1
            and digest(validator_raw.replace(literal, placeholder))
            == record["validatorNormalizedSha256"], "transport bootstraps publish validator drift")
    paths = sorted((ROOT / "task-packets").glob("*.yaml"))
    old = set(record["baselinePackets"])
    require(len(paths) == 278 and {path.stem for path in paths} == old | {NEW_PACKET} | set(PRODUCT_PACKETS),
            "closed 278-packet catalog")
    packets = {}
    for path in paths:
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
            "closed source-only transport-bootstraps-publish packet and inherited commands")
    require(len(packet["allowedPaths"]) == len(set(packet["allowedPaths"]))
            and set(packet["allowedPaths"]) == set(record["changedFiles"])
            | set(record["newFiles"]) | {AUTHORITY_PATH, VALIDATOR_PATH,
                                         "task-packets/" + NEW_PACKET + ".yaml"}
            | {"task-packets/" + name + ".yaml" for name in PRODUCT_PACKETS},
            "unreviewed or omitted transport-bootstraps-publish packet path")
    for path, rule in record["changedFiles"].items():
        current = regular_bytes(path)
        require(digest(current) == rule["afterSha256"]
                and digest(historical_bytes(path, current)) == rule["beforeSha256"],
                "unreviewed current source: " + path)
    for path, expected in record["newFiles"].items():
        require(digest(regular_bytes(path)) == expected, "new source drift: " + path)
    validate_met_verify_005(packets)


if __name__ == "__main__":
    validate()
    print("Transport bootstraps publish valid: 278 current specifications at slot 275; exact 275-packet predecessor; contract reviewed.")
