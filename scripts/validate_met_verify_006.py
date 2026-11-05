#!/usr/bin/env python3
"""Validate MET-VERIFY-006 (DIST-005A-CTRL-FIX-004-PUBLISH): the fifth publishing step, publishing the product packets DIST-005A and CTRL-FIX-004 with one exact-pair supersession closer and the full head-test weights refresh (V1-V9: the products' frozen bytes and facts, DIST-005A's six-edit difference and CTRL-FIX-004's key order; this packet's allowedPaths, R04's and R11's plans changed by exactly their own items 13 and 10 and this repository's meta item; the registry's MET-VERIFY-006 packet rider as the one change from the base; the raw ownership count 139 with exactly the 20 listed messages, the closer outermost around 275's, its pinned pair list; one added YAML per repository and one YAML per product branch; the productComparators pins and the inheritance predicate; DIST-005, CTRL-INTEGRATE-001, R6 and the chain-inheritance records unchanged, the 279 decisions record; the ownership validator unchanged; the weights table computed from its pinned inputs), and the exact 279-to-278 projection with the product forms F1-F7, F6' and F9."""
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
    import validate_met_perf_046 as successor
except ImportError:
    from scripts.safe_yaml import safe_load
    from scripts import validate_met_perf_046 as successor


ROOT = Path(__file__).resolve().parents[1]
AUTHORITY_PATH = "architecture/dist-005a-ctrl-fix-004-publish-authority.json"
AUTHORITY_SHA256 = "e220814d9b1fcc8de2be8a734cbc161bd736c230e38020e8c52b87772b882604"
VALIDATOR_PATH = "scripts/validate_met_verify_006.py"
BASE_COMMIT = "afee03b93da691cb113da495e3be7e39695756aa"
NEW_PACKET = "MET-VERIFY-006"
PREVIOUS_PACKET = "MET-SECTOR-005"
PRODUCT_PACKETS = ("DIST-005A", "CTRL-FIX-004")
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
            require(key not in result, "duplicate dist-005a-ctrl-fix-004-publish authority member")
            result[key] = value
        return result

    def no_constant(_value: str) -> Any:
        raise ValueError("nonfinite dist-005a-ctrl-fix-004-publish authority number")

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
        require(digest(raw) == AUTHORITY_SHA256, "dist 005a ctrl fix 004 publish history authority digest")
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
    }, "closed dist 005a ctrl fix 004 publish history authority")
    require(value["schemaVersion"] == "harness.planeon.ai/dist-005a-ctrl-fix-004-publish-authority/v1"
            and value["authorityPacket"] == NEW_PACKET
            and value["acceptedBase"] == BASE_COMMIT
            and type(value["baselinePackets"]) is dict
            and len(value["baselinePackets"]) == 283
            and NEW_PACKET not in value["baselinePackets"]
            and type(value["changedFiles"]) is dict
            and type(value["newFiles"]) is dict
            and _sha(value["packetSha256"])
            and _sha(value["validatorNormalizedSha256"]),
            "accepted 283-packet base")
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
    # An exact 283-era byte string is already older than the successor layer.
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


# MET-VERIFY-006 (DIST-005A-CTRL-FIX-004-PUBLISH; the lane monitor's owner-delegated rulings MON-279-START, MON-279-OWN2,
# MON-279-OWN2-P1, MON-279-P1-SITES, MON-279-CR3-RULINGS, MON-279-C1-SCOPE, MON-279-DEC and MON-279-PAIRS) is the fifth
# publishing step of the product-packet vocabulary (CHAIN-PRODUCT-PUBLISH-001): this meta packet publishes two product
# packets in install order, task-packets/DIST-005A.yaml (the acceptance-command successor of DIST-005, Q-VX45-6 (a),
# after DIST-TRANSPORT-001) and task-packets/CTRL-FIX-004.yaml (the page-not-found status fix, after CTRL-TRANSPORT-001),
# so the catalog holds C = 286 packets at slot S = 279 (K = 2), under the R13 inheritance guard
# (architecture/chain-inheritance/, unchanged). The products are not chain packets: their bytes are pinned by the
# authority's productPackets, and the class functions above carry the product forms F1-F7 with F6' and F9 from the cut.
# Its review series is registered by this packet's own rider in architecture/review-record/briefs.json
# (MET-VERIFY-006/packet, gate material, so the owner approves the PR).
# Repository bytes are read only through reviewed_bytes, so a later bridged successor projects its own edits away
# first; a path outside this era is refused before it is read and every era file is bound by digest on every read.
# Each refusal is a pure check over the values read, so every one has a failing case on plain data. Checked here: V1,
# the products (bytes, parsed facts, R11's and R04's mains in full in their contracts; DIST-005A's six-edit difference
# from DIST-005; CTRL-FIX-004's key order as CTRL-TRANSPORT-001's); V2, this packet's paths and the three plans (R04's
# and R11's plans differ from the base by exactly their own items 13 and 10; this repository's plan carries the meta
# item once); V3, the registry (the base plus exactly this packet's rider); V4, ownership (the raw diagnostics are the
# base's 119 plus exactly the 20 listed superseded-successor messages; the two allowed-list strings cover exactly 12
# and 8 of them; this layer's close_superseded_successor_overlaps is the outermost call of validate_dispatch_ownership,
# around 275's close_bootstrap_transport_dispatch; the head may not import the ownership validators, so the counting
# checks are pure checks the head test feeds with their live results); V5, one added YAML per repository and one YAML
# per product branch; V6, the productComparators pin and the inheritance predicate; V7, the superseded YAMLs, R6 and the
# chain-inheritance records unchanged, and the 279 decisions record at its pin (MON-279-DEC); V8, the ownership
# validator byte-identical to the base; and V9, the weights table (MON-279-W5B: every entry equals its value computed
# from the pinned inputs record, 278's dry-run END sums x kappa, plus the three head-test entries). No chain validator or chain test is pinned here. Last, this layer's own inverse hunks are the canonical
# byte-minimal ones, recomputed from its era's bytes (MET-PERF-040's carried rule).
PRODUCT_PATHS = MappingProxyType({name: "task-packets/" + name + ".yaml" for name in PRODUCT_PACKETS})
# V1: the products' frozen facts; allowedPaths and acceptance argv by the digest of their canonical JSON lists.
PRODUCT_FACTS = MappingProxyType({
    "DIST-005A": MappingProxyType({"repository": "mas-harness-distribution", "branch": "codex/dist-005a-repro-security",
                                 "predecessors": ("DIST-TRANSPORT-001",),
                                 "allowedPaths": "1e4249f9ebcec7ee4af788555dd9ba0b66bec147bc9e44c6b7192de3a5417999",
                                 "commands": "83289dd2554998460f8ccbfaa2246dea3698f7c5831da9b2bd5d9e81e102f68d"}),
    "CTRL-FIX-004": MappingProxyType({"repository": "mas-harness-control-plane", "branch": "codex/ctrl-fix-004-page-not-found-status",
                                 "predecessors": ("CTRL-TRANSPORT-001",),
                                 "allowedPaths": "dfddec2523afbcec846fd1ecfd547537c641e1ff6ee082594d952e427bcab066",
                                 "commands": "405274438bee9cc815240c939b6cf6dc735012e6cb95917eac41998ce41dfee5"}),
})
# V1: each product's repository main, written in full in its contracts (R11 for DIST-005A, R04 for CTRL-FIX-004).
PRODUCT_PINS = MappingProxyType({
    "DIST-005A": ("e28ea6a2375b8e0dab0865c2bda1c824ab1ca340",),
    "CTRL-FIX-004": ("e46641d609cef2224b6f0069076d14e45d3d7f24",),
})
# V1: DIST-005A's difference from DIST-005 (E1-E6): exactly these 1-based lines, these keys, the key order kept.
PRODUCT_BASE = MappingProxyType({"DIST-005A": "DIST-005"})
DIFF_LINES = (1, 3, 5, 6, 9, 13)
DIFF_KEYS = ("allowedPaths", "branch", "contracts", "id", "offlineAcceptanceCommands", "predecessors")
# V1: CTRL-FIX-004's keys are in CTRL-TRANSPORT-001's order.
KEY_ORDER_BASE = MappingProxyType({"CTRL-FIX-004": "CTRL-TRANSPORT-001"})
# V2: R04's and R11's plans, the base's bytes plus exactly their own items; this repository's plan, its meta item.
PLAN_PATHS = ("docs/repositories/04-mas-harness-control-plane.md", "docs/repositories/11-mas-harness-distribution.md")
PLAN_BASE_SHA256 = MappingProxyType({
    "docs/repositories/04-mas-harness-control-plane.md": "21e8d62d93252f92406569db4ea734834b4ab9d4ba13118f24deb4ee5b35bc74",
    "docs/repositories/11-mas-harness-distribution.md": "3b384263aac2bd41a3158f391f2ab60208043bb59354f2a3e547632c969f8d4a",
})
PLAN_INSERT_SHA256 = MappingProxyType({
    "docs/repositories/04-mas-harness-control-plane.md": ("8897eeed433c954ca90dd9ea178ec6206206922a75c6072dbd8a83a64e098c90",),
    "docs/repositories/11-mas-harness-distribution.md": ("053c7e441a3602342f00ea80c3e12540818acd09583c4f78cf763db58132c892",),
})
OWN_PLAN_PATH = "docs/repositories/00-harness-engineering.md"
OWN_ITEM_PREFIX = "153. `MET-VERIFY-006`: "
OWN_ITEM_SHA256 = "cc76e710adad563301dde8cb1437f48a694c9c5d29d3b0ad75bb7cd7cfedce4b"
REGISTRY_PATH = "architecture/review-record/briefs.json"
PACKET_BRIEF = "architecture/review-briefs/REVIEW_BRIEF_PACKET.md"
# V3: the registry at the base (the digest of its canonical JSON) and this packet's one rider (kind, series, path,
# version), appended last; the rider's sha256 is the generic packet brief's.
REGISTRY_BASE_SHA256 = "2d47468a5b71dd9d35c100f9c5abffb52e27a7ecaf5394d89ff535a870c381a9"
RIDERS = (("PACKET", NEW_PACKET + "/packet", PACKET_BRIEF, 1),)
# V4: the raw ownership count (the base's 119 plus the 20 listed messages), the closer and its pinned pair list.
OWNERSHIP_COUNT = 139
CHAIN_PATH = "scripts/validate_conformance_reference_measurement.py"
CLOSER_NAME = "close_superseded_successor_overlaps"
CLOSED_BEFORE = "close_bootstrap_transport_dispatch"
PAIRS_PATH = "architecture/dist-005a-ctrl-fix-004-publish-pairs.json"
PAIRS_SHA256 = "00e80307ec3e5336d1ebb3843eaa5af75b5db8b76e08687821e00be930fca46f"
# The four listed packets, each with the sha256 its pairs name (the products and the two superseded-overlap packets).
PAIR_PACKETS = MappingProxyType({
    "CTRL-FIX-004": "c6e837fa926ad89a782b90d8bc7782ba42612a713ca754e497ca05d5feb73760",
    "CTRL-INTEGRATE-001": "28441f4febf41c7228b516ca8f674785d28842aa6c3443f8fefebeb4a6e7de95",
    "DIST-005": "1cf1826b8c69c2030112899344577e0c5ea761b528eb978655cb098b29434d4f",
    "DIST-005A": "6e9c228fdefe20abd981726915968a09609cd1559f7c9ae347e99fc25cbf3702",
})
# The two allowed-list strings and how many listed messages each covers exactly (CONTRACT_279 s5's coverage check).
PAIR_STRINGS = MappingProxyType({"CTRL-FIX-004 and CTRL-INTEGRATE-001": 12, "DIST-005 and DIST-005A": 8})
# V5: one added YAML per repository; each product branch on exactly one catalog YAML.
ADDED_REPOSITORIES = MappingProxyType({
    "MET-VERIFY-006": "Harness-Engineering",
    "DIST-005A": "mas-harness-distribution",
    "CTRL-FIX-004": "mas-harness-control-plane",
})
PRODUCT_BRANCH = MappingProxyType({
    "DIST-005A": "codex/dist-005a-repro-security",
    "CTRL-FIX-004": "codex/ctrl-fix-004-page-not-found-status",
})
# V6 (R13 at the head): the pins this layer's authority holds, and the comparators they name.
COMPARATORS = MappingProxyType({
    "DIST-005A": MappingProxyType({"packet": "DIST-TRANSPORT-001",
                                 "sha256": "9da0fdeed10743e3b65505415334290803b3a4f1da1e1c5ea9268d12dfaf44a9"}),
    "CTRL-FIX-004": MappingProxyType({"packet": "CTRL-TRANSPORT-001",
                                 "sha256": "729dd73afedc70460543fb55f2708805c31fb7d758f691b15a4a67a2cac3a3f6"}),
})
# V7: the superseded YAMLs stay at their published bytes; the frozen product-packet rule still lists R6; the
# chain-inheritance records stay byte-identical; the 279 decisions record sits at its pin (MON-279-DEC).
SUPERSEDED = MappingProxyType({
    "DIST-005": "1cf1826b8c69c2030112899344577e0c5ea761b528eb978655cb098b29434d4f",
    "CTRL-INTEGRATE-001": "28441f4febf41c7228b516ca8f674785d28842aa6c3443f8fefebeb4a6e7de95",
})
V2_RULE_PATH = "architecture/chain-product-packets/rule.json"
V3_RECORDS = ("architecture/chain-inheritance/decisions.md", "architecture/chain-inheritance/rule.json")
DECISIONS_PATH = "architecture/dist-005a-ctrl-fix-004-publish-decisions.md"
DECISIONS_HEADS = ("## MON-279-OWN2\n", "## MON-279-OWN2-P1\n", "## MON-279-P1-SITES\n", "## MON-279-C1-SCOPE\n",
                   "## The exact-pair list\n", "## Known debt\n", "## R04's read findings (MON-279-R04-DRAFT)\n",
                   "## R11's E5 question and its answer\n")
# V8: the ownership validator is the base's bytes (278's rule (b) unchanged).
OWNERSHIP_PATH = "scripts/validate_packet_ownership.py"
# V9 (MON-279-W5B, the full refresh): the weights table is computed from the pinned inputs record: each dry-run file's
# round(dryRunUs / 1000000 x kappa, 1) and the three head tests' W2 entries, nothing else.
WEIGHTS_PATH = "ci/parallel_suite_weights.json"
WEIGHTS_INPUTS_PATH = "architecture/dist-005a-ctrl-fix-004-publish-weights.json"
WEIGHTS_BASE_COUNT = 182
WEIGHT_KEYS = ("tests/test_met_perf_045.py", "tests/test_met_sector_005.py", "tests/test_met_verify_006.py")
# Every file this era's check reads, with its digest.
ERA_SHA256 = MappingProxyType({
    "architecture/chain-inheritance/decisions.md": "c0d334380200f7de008de31fbd7268cd6a154cda19dfedf4bb9e8a53db9a3f9d",
    "architecture/chain-inheritance/rule.json": "ed2a4d41df9a3624ee4c0d835bd1586b075dfe32feffd7eb0d09cce9731a9b10",
    "architecture/chain-product-packets/rule.json": "5e6e6821eace0e50e416c21ab2e605a165b2e69e455cf3fa6b051f7db99fb4d4",
    "architecture/dist-005a-ctrl-fix-004-publish-decisions.md": "62c8cc3f8fe8cc48caca2448f1bf6f800a9123ca337c62dc00ea198316084d7c",
    "architecture/dist-005a-ctrl-fix-004-publish-pairs.json": "00e80307ec3e5336d1ebb3843eaa5af75b5db8b76e08687821e00be930fca46f",
    "architecture/dist-005a-ctrl-fix-004-publish-weights.json": "bcbc2ec42504b7c64fc6cec22f1f6491fbf0a8b6b38cca9ffd71543741bc06ef",
    "architecture/review-briefs/REVIEW_BRIEF_PACKET.md": "6dcff68d7e6b01823f1740063e94910edcc159a71a6ee803f1b66c62fd06e274",
    "architecture/review-record/briefs.json": "8baca623569ec894d3a6930a64496fb635d756a5dfb3c007789fcb60c2d8ab8e",
    "ci/parallel_suite_weights.json": "8e4050ce8a6a88faa357bb97e6b858003c27951bf0b71249dea68dfd3a2a1a32",
    "docs/repositories/00-harness-engineering.md": "5a0ba0264594d5070dac4fbf55e999f6859bcd49fe2482ec7b6213cf97a06a2d",
    "docs/repositories/04-mas-harness-control-plane.md": "6ec928e32addccc3acd3c0dbb7d776b58e24290712cd8796d7e807b0b48c4167",
    "docs/repositories/11-mas-harness-distribution.md": "21438fd08b9aefc11ad10f7b690967552a5a937c2209d2fea08d9bdaf60c4bc5",
    "scripts/validate_conformance_reference_measurement.py": "e2e80e1e4dff5b1bf45fb542fb2c4196e072c2c63fed1aa83f71aec084028b06",
    "scripts/validate_packet_ownership.py": "19bfe8ea3b3fe530a2684553644cd1632e07e756ab6ce2aa770a168ea1f95cab",
    "task-packets/CTRL-FIX-004.yaml": "c6e837fa926ad89a782b90d8bc7782ba42612a713ca754e497ca05d5feb73760",
    "task-packets/CTRL-INTEGRATE-001.yaml": "28441f4febf41c7228b516ca8f674785d28842aa6c3443f8fefebeb4a6e7de95",
    "task-packets/CTRL-TRANSPORT-001.yaml": "729dd73afedc70460543fb55f2708805c31fb7d758f691b15a4a67a2cac3a3f6",
    "task-packets/DIST-005.yaml": "1cf1826b8c69c2030112899344577e0c5ea761b528eb978655cb098b29434d4f",
    "task-packets/DIST-005A.yaml": "6e9c228fdefe20abd981726915968a09609cd1559f7c9ae347e99fc25cbf3702",
    "task-packets/DIST-TRANSPORT-001.yaml": "9da0fdeed10743e3b65505415334290803b3a4f1da1e1c5ea9268d12dfaf44a9",
})


def reviewed_bytes(path: str) -> bytes:
    """This packet's reviewed bytes of path; a bridged successor projects newer bytes back first."""
    return successor.historical_bytes(path, regular_bytes(path))


def _era_bytes(path: Any, raw: Any) -> bytes:
    """An era file's bytes, checked against its era digest; a path outside the era is refused."""
    expected = ERA_SHA256.get(path) if type(path) is str else None
    require(expected is not None, "MET-VERIFY-006 reviewed bytes are bound: " + str(path))
    require(type(raw) is bytes and digest(raw) == expected, "unreviewed DIST-005A-CTRL-FIX-004-PUBLISH source: " + path)
    return raw


def _verified(path: str) -> bytes:
    """reviewed_bytes, checked against its era digest on every read; a path outside the era is refused before it is
    read."""
    require(type(path) is str and path in ERA_SHA256, "MET-VERIFY-006 reviewed bytes are bound: " + str(path))
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


def check_product_facts(name: Any, packet: Any) -> None:
    """V1: a product's parsed facts are the frozen ones: id, repository, branch, predecessors, allowedPaths and
    acceptance argv (by canonical digest, in order), no prefetch, warm-source access prohibited, no source reuse, and
    its repository's main written in full in its contracts."""
    _bound(lambda: type(packet) is dict and packet["id"] == name
           and packet["repository"] == PRODUCT_FACTS[name]["repository"]
           and packet["branch"] == PRODUCT_FACTS[name]["branch"]
           and packet["predecessors"] == list(PRODUCT_FACTS[name]["predecessors"])
           and digest(canonical(packet["allowedPaths"])) == PRODUCT_FACTS[name]["allowedPaths"]
           and digest(canonical(packet["offlineAcceptanceCommands"])) == PRODUCT_FACTS[name]["commands"]
           and packet["prefetchCommands"] == []
           and packet["warmSourceAccess"] == "PROHIBITED_DURING_IMPLEMENTATION" and packet["sourceReuse"] == []
           and all(pin in " ".join(packet["contracts"]) for pin in PRODUCT_PINS[name]),
           "the product's facts are the frozen ones: " + str(name))


def check_product_diff(raw: Any, base_raw: Any) -> None:
    """V1: DIST-005A is DIST-005's bytes with exactly the six counted edits: the same line count, differing at exactly
    DIFF_LINES; parsed, exactly DIFF_KEYS differ, and the key order is kept."""
    def holds() -> bool:
        new, old = raw.decode("utf-8").splitlines(), base_raw.decode("utf-8").splitlines()
        a, b = safe_load(raw), safe_load(base_raw)
        return (len(new) == len(old) and tuple(i + 1 for i, (x, y) in enumerate(zip(new, old)) if x != y) == DIFF_LINES
                and list(a) == list(b) and tuple(sorted(k for k in a if a[k] != b[k])) == DIFF_KEYS)
    _bound(holds, "DIST-005A is DIST-005's bytes with exactly the six counted edits")


def check_key_order(packet: Any, base_packet: Any) -> None:
    """V1: CTRL-FIX-004's keys are CTRL-TRANSPORT-001's, in the same order."""
    _bound(lambda: type(packet) is dict and type(base_packet) is dict and list(packet) == list(base_packet),
           "CTRL-FIX-004 keeps CTRL-TRANSPORT-001's key order")


def validate_products() -> None:
    """V1 over both products, read through the era."""
    for name in PRODUCT_PACKETS:
        raw = _verified(PRODUCT_PATHS[name])
        check_product_bytes(name, raw)
        check_product_facts(name, safe_load(raw))
    for name, base_name in PRODUCT_BASE.items():
        check_product_diff(_verified(PRODUCT_PATHS[name]), _verified("task-packets/" + base_name + ".yaml"))
    for name, base_name in KEY_ORDER_BASE.items():
        check_key_order(safe_load(_verified(PRODUCT_PATHS[name])), safe_load(_verified("task-packets/" + base_name + ".yaml")))


def check_own_paths(packet: Any) -> None:
    """V2: this packet's allowedPaths names every product it publishes."""
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
    """The yes'd texts in a plan, found by digest: every line of the plan whose digest is one of the pinned inserts
    (R04's item 13 and R11's item 10 are one line each)."""
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
    _bound(holds, "this repository's plan holds the MET-VERIFY-006 item once, naming both products")


def validate_plans() -> None:
    """V2 over R04's and R11's plans and this repository's plan."""
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
           "the registry differs from the base by exactly the MET-VERIFY-006 packet rider, pinning the generic packet "
           "brief")


def validate_registry() -> None:
    """V3 over briefs.json and the generic packet brief."""
    check_registry(_verified(REGISTRY_PATH), {PACKET_BRIEF: _verified(PACKET_BRIEF)})


def pair_messages() -> tuple[str, ...]:
    """The 20 listed messages, from the era-bound pair list (MON-279-PAIRS; its shape is check_pairs')."""
    return tuple(entry["message"] for entry in parse(_verified(PAIRS_PATH))["pairs"])


def check_pairs(record: Any) -> None:
    """V4: the pair list is 20 distinct messages, each keyed by exactly two of the four listed packets with their pinned
    sha256, CTRL-FIX-004 or DIST-005A among them, its overlap named in its message."""
    def holds() -> bool:
        pairs = record["pairs"]
        keys = [tuple(sorted((q["id"], q["sha256"]) for q in entry["packets"])) for entry in pairs]
        return (type(pairs) is list and len(pairs) == 20 and len({entry["message"] for entry in pairs}) == 20
                and all(len(key) == 2 and all(PAIR_PACKETS.get(pid) == psha for pid, psha in key)
                        and any(pid in PRODUCT_PACKETS for pid, _ in key) for key in keys)
                and all(all(type(path) is str and path in entry["message"] for path in entry["overlap"])
                        for entry in pairs)
                and {pid for key in keys for pid, _ in key} == set(PAIR_PACKETS))
    _bound(holds, "the pair list keys 20 exact messages by the four listed packets")


def check_ownership(diagnostics: Any, messages: Any) -> None:
    """V4: validate_packet_ownership's diagnostics are 139: the base's 119 plus exactly the 20 listed messages, each
    once; no other diagnostic names a product."""
    _bound(lambda: type(diagnostics) is list and all(type(item) is str for item in diagnostics)
           and type(messages) is tuple and len(messages) == 20
           and len(diagnostics) == OWNERSHIP_COUNT and all(diagnostics.count(item) == 1 for item in messages)
           and sorted(item for item in diagnostics if any(name in item for name in PRODUCT_PACKETS)) == sorted(messages),
           "the products add exactly the 20 listed ownership diagnostics: 139, none other naming them")


def check_pair_coverage(diagnostics: Any, messages: Any) -> None:
    """V4: each allowed-list string covers exactly its listed messages (12 CTRL, 8 DIST) and nothing else."""
    _bound(lambda: type(diagnostics) is list and type(messages) is tuple and all(
        sorted(item for item in diagnostics if text in item) == sorted(item for item in messages if text in item)
        and len([item for item in messages if text in item]) == count for text, count in PAIR_STRINGS.items())
        and sum(PAIR_STRINGS.values()) == len(messages),
        "the two allowed-list strings cover exactly the 12 and 8 listed messages")


def check_dispatch(closed: Any) -> None:
    """V4: the dispatch chain, with this layer's closer outermost, closes the live catalog to no diagnostic."""
    _bound(lambda: closed == [], "the dispatch chain closes every ownership diagnostic")


def check_closer_position(raw: Any) -> None:
    """V4: validate_dispatch_ownership's return calls this layer's close_superseded_successor_overlaps exactly once,
    outermost, around 275's close_bootstrap_transport_dispatch; no other call of it exists in the chain file."""
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
    _bound(holds, "close_superseded_successor_overlaps is the outermost closer of validate_dispatch_ownership")


def close_superseded_successor_overlaps(packets: Any, errors: Any) -> list[str]:
    """MON-279-OWN2 (ii)+(vi), placement P1: remove exactly the 20 listed superseded-successor overlap messages, read
    from the era-bound pair list (MON-279-PAIRS), each only when it is present exactly once, and only while each of the
    four listed packets in packets equals its verified YAML bytes, parsed (275's in-memory binding); otherwise add a
    refusal. Called outermost in validate_dispatch_ownership; a second call finds no message and refuses. It carries
    no predecessor semantics."""
    try:
        require(type(errors) is list and all(type(item) is str for item in errors), "diagnostic list")
        raw = _verified(PAIRS_PATH)
        require(digest(raw) == PAIRS_SHA256, "exact pair list")
        record = parse(raw)
        check_pairs(record)
        for name, expected in PAIR_PACKETS.items():
            packet_raw = _verified("task-packets/" + name + ".yaml")
            require(digest(packet_raw) == expected and type(packets) is dict
                    and canonical(packets.get(name)) == canonical(safe_load(packet_raw)), "exact listed packet")
        messages = [entry["message"] for entry in record["pairs"]]
        require(all(errors.count(item) == 1 for item in messages), "exact single superseded-successor overlaps")
        return [item for item in errors if item not in messages]
    except (ValueError, TypeError, KeyError, OSError, RecursionError):
        return list(errors) + ["missing or changed closed superseded-successor dispatch"]


def validate_ownership() -> None:
    """V4 over the dispatch chain's reviewed bytes and the pair list: the closer is its outermost call."""
    check_closer_position(_verified(CHAIN_PATH))
    check_pairs(_parsed(_verified(PAIRS_PATH)))


def check_one_per_repository(packets: Any) -> None:
    """V5: the YAMLs this packet adds (itself and its products) name each of their three repositories exactly once."""
    _bound(lambda: type(packets) is dict
           and {name: packets[name]["repository"] for name in (NEW_PACKET, *PRODUCT_PACKETS)} == dict(ADDED_REPOSITORIES)
           and len(set(ADDED_REPOSITORIES.values())) == len(ADDED_REPOSITORIES) == 1 + len(PRODUCT_PACKETS),
           "one added YAML per repository")


def check_branch_unique(packets: Any) -> None:
    """V5: exactly one catalog YAML carries each product's branch, and it is that product."""
    _bound(lambda: type(packets) is dict and all(
        [name for name, packet in packets.items() if type(packet) is dict and packet.get("branch") == branch] == [product]
        for product, branch in PRODUCT_BRANCH.items()), "exactly one YAML carries each product's branch")


def check_comparators(value: Any) -> None:
    """V6: the authority's productComparators is exactly the pinned comparator for every product, in install order."""
    _bound(lambda: type(value) is dict and list(value) == list(PRODUCT_PACKETS)
           and {name: dict(pin) for name, pin in value.items()} == {k: dict(v) for k, v in COMPARATORS.items()},
           "productComparators pins each product's comparator")


def check_inheritance(name: Any, packet: Any, comparator: Any) -> None:
    """V6: the comparator names the product's repository, is the product's one predecessor, and every one of its argv
    is in the product's list, byte-exact and in order (the verifier's require_inherits)."""
    def holds() -> bool:
        it = iter(packet["offlineAcceptanceCommands"])
        return (comparator["repository"] == packet["repository"] and packet["predecessors"] == [comparator["id"]]
                and comparator["id"] == COMPARATORS[name]["packet"]
                and all(any(argv == cand for cand in it) for argv in comparator["offlineAcceptanceCommands"]))
    _bound(holds, "the product keeps every command of its comparator in order: " + str(name))


def validate_comparators() -> None:
    """V6 over the authority and the reviewed product and comparator bytes."""
    check_comparators(authority()["productComparators"])
    for name in PRODUCT_PACKETS:
        base_name = COMPARATORS[name]["packet"]
        check_inheritance(name, safe_load(_verified(PRODUCT_PATHS[name])),
                          safe_load(_verified("task-packets/" + base_name + ".yaml")))


def check_superseded(raws: Any, rule_raw: Any) -> None:
    """V7: DIST-005 and CTRL-INTEGRATE-001 are their published bytes, and the frozen product-packet rule still lists
    R6."""
    rule = _parsed(rule_raw)
    _bound(lambda: type(raws) is dict and sorted(raws) == sorted(SUPERSEDED)
           and all(type(raws[name]) is bytes and digest(raws[name]) == SUPERSEDED[name] for name in SUPERSEDED)
           and "R6" in rule["refusals"],
           "DIST-005 and CTRL-INTEGRATE-001 stay at their published bytes and R6 stays listed")


def check_decisions(raw: Any, records: Any) -> None:
    """V7 (MON-279-DEC): the 279 decisions record holds each of its sections once, in order, and the chain-inheritance
    records it replaces as a target are their base bytes (bound by the era digests)."""
    def holds() -> bool:
        text = raw.decode("utf-8")
        at = [text.find(head) for head in DECISIONS_HEADS]
        return (all(text.count(head) == 1 for head in DECISIONS_HEADS) and at == sorted(at) and min(at) > 0
                and type(records) is dict and sorted(records) == sorted(V3_RECORDS)
                and all(type(records[path]) is bytes and digest(records[path]) == ERA_SHA256[path] for path in V3_RECORDS))
    _bound(holds, "the 279 decisions record holds its sections once, and the chain-inheritance records are unchanged")


def validate_records() -> None:
    """V7 over the reviewed bytes."""
    check_superseded({name: _verified("task-packets/" + name + ".yaml") for name in SUPERSEDED}, _verified(V2_RULE_PATH))
    check_decisions(_verified(DECISIONS_PATH), {path: _verified(path) for path in V3_RECORDS})


def check_ownership_validator(raw: Any) -> None:
    """V8: validate_packet_ownership is the base's bytes (278's rule (b) unchanged; P1 adds no closer inside it)."""
    _bound(lambda: type(raw) is bytes and digest(raw) == ERA_SHA256[OWNERSHIP_PATH],
           "validate_packet_ownership is byte-identical to the base")


def check_weights(raw: Any, inputs_raw: Any) -> None:
    """V9 (MON-279-W5B): every entry of the weights table equals its value computed from the inputs record
    (round(dryRunUs / 1000000 x kappa, 1) for its 182 dry-run files, headTests for the three head tests, each a
    non-negative float), the table holds exactly those keys, and it is written in its own serializer form
    (json.dumps(indent=1, sort_keys=True) plus a newline)."""
    def holds() -> bool:
        table, inputs = _parsed(raw), _parsed(inputs_raw)
        expected = {key: float(round(us / 1000000 * inputs["kappa"], 1)) for key, us in inputs["dryRunUs"].items()}
        expected.update(inputs["headTests"])
        return (type(table) is dict and len(inputs["dryRunUs"]) == WEIGHTS_BASE_COUNT
                and sorted(inputs["headTests"]) == sorted(WEIGHT_KEYS) and table == expected
                and all(type(value) is float and value >= 0 for value in table.values())
                and raw == (json.dumps(table, indent=1, sort_keys=True) + "\n").encode("utf-8"))
    _bound(holds, "every weights-table entry equals its value computed from the pinned inputs")


def validate_weights() -> None:
    """V9 over the reviewed table and its reviewed inputs record."""
    check_weights(_verified(WEIGHTS_PATH), _verified(WEIGHTS_INPUTS_PATH))


def validate_met_verify_006(packets: dict[str, Any]) -> None:
    """Every reviewed byte first; then V1 (the products, DIST-005A's six-edit difference, CTRL-FIX-004's key order), V2
    (this packet's paths and the three plans), V3 (the registry), V4 (the closer outermost and its pair list), V5 (one
    added YAML per repository; one YAML per product branch), V6 (the productComparators pins and the inheritance
    predicate), V7 (the superseded YAMLs, R6, the chain-inheritance records and the decisions record), V8 (the ownership
    validator) and V9 (the weights table), over the packets validate() read; last, this layer's canonical hunks."""
    for path in ERA_SHA256:
        _verified(path)
    validate_products()
    check_own_paths(packets[NEW_PACKET])
    validate_plans()
    validate_registry()
    validate_ownership()
    check_one_per_repository(packets)
    check_branch_unique(packets)
    validate_comparators()
    validate_records()
    check_ownership_validator(_verified(OWNERSHIP_PATH))
    validate_weights()
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
            == record["validatorNormalizedSha256"], "dist 005a ctrl fix 004 publish validator drift")
    paths = sorted((ROOT / "task-packets").glob("*.yaml"))
    old = set(record["baselinePackets"])
    require(len(paths) == 287
            and {path.stem for path in paths} == old | {NEW_PACKET, successor.NEW_PACKET} | set(PRODUCT_PACKETS),
            "closed 287-packet catalog retaining the 286-packet checkpoint")
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
            "closed source-only dist-005a-ctrl-fix-004-publish packet and inherited commands")
    require(len(packet["allowedPaths"]) == len(set(packet["allowedPaths"]))
            and set(packet["allowedPaths"]) == set(record["changedFiles"])
            | set(record["newFiles"]) | {AUTHORITY_PATH, VALIDATOR_PATH,
                                         "task-packets/" + NEW_PACKET + ".yaml"}
            | {"task-packets/" + name + ".yaml" for name in PRODUCT_PACKETS},
            "unreviewed or omitted dist-005a-ctrl-fix-004-publish packet path")
    for path, rule in record["changedFiles"].items():
        current = successor.historical_bytes(path, regular_bytes(path))
        require(digest(current) == rule["afterSha256"]
                and digest(historical_bytes(path, current)) == rule["beforeSha256"],
                "unreviewed current source: " + path)
    for path, expected in record["newFiles"].items():
        require(digest(successor.historical_bytes(path, regular_bytes(path))) == expected,
                "new source drift: " + path)
    validate_met_verify_006(packets)


if __name__ == "__main__":
    validate()
    print("DIST-005A and CTRL-FIX-004 publish valid: 287 current specifications at slot 279; 286-packet checkpoint and exact 283-packet predecessor; contract reviewed.")
