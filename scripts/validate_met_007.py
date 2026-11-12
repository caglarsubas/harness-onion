#!/usr/bin/env python3
"""Validate MET-007 (DATA-CORRECTNESS-001 and R14's registration row, K = 1, publishing LAB-SYNC-001): V1 this packet's files by digest; E1 the model replays every vector and the record passes its checker; E2 the catalog, the graph, their schemas, the service-edge record and the registry with its schema unchanged; E3 the authored edits at their named lines; E4 raw == effective; V4 the registry rider; V5 the product LAB-SYNC-001; V6 the hunk-class record under v2.5."""
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
AUTHORITY_PATH = "architecture/data-correctness-authority.json"
AUTHORITY_SHA256 = "7becf818fe5f1fcdbccbdf58bfa1323b7e283507e39b311766bfc28578af520c"
VALIDATOR_PATH = "scripts/validate_met_007.py"
BASE_COMMIT = "4875648cffb3f838650d96a5291445b3634bf9b3"
NEW_PACKET = "MET-007"
PREVIOUS_PACKET = "MET-006"
PRODUCT_PACKETS = ("LAB-SYNC-001",)
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
            require(key not in result, "duplicate data-correctness authority member")
            result[key] = value
        return result

    def no_constant(_value: str) -> Any:
        raise ValueError("nonfinite data-correctness authority number")

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
        require(digest(raw) == AUTHORITY_SHA256, "data correctness history authority digest")
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
    }, "closed data correctness history authority")
    require(value["schemaVersion"] == "harness.planeon.ai/data-correctness-authority/v1"
            and value["authorityPacket"] == NEW_PACKET
            and value["acceptedBase"] == BASE_COMMIT
            and type(value["baselinePackets"]) is dict
            and len(value["baselinePackets"]) == 298
            and NEW_PACKET not in value["baselinePackets"]
            and type(value["changedFiles"]) is dict
            and type(value["newFiles"]) is dict
            and _sha(value["packetSha256"])
            and _sha(value["validatorNormalizedSha256"]),
            "accepted 298-packet base")
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


# MET-007 (DATA-CORRECTNESS-001 and R14's registration row; the lane monitor's owner-delegated rulings MON-288-SCOPE,
# MON-288-SCOPE-CORR, MON-288-LAB-SYNC, MON-288-LAB-SYNC-INPUTS, MON-288-DESIGN-GO, MON-288-RULINGS, MON-288-CR1-RULE,
# MON-288-Q2-RULE, MON-288-CR2-RULE, MON-288-C1R2-RULE, MON-288-C2-RULE, MON-288-C2R2-RULE, MON-288-RD1-RULE,
# MON-288-C2R3-RULE, MON-288-RD2-RULE, MON-288-C3-BRIEF, MON-288-C3-CLASS, MON-288-BP14, MON-288-C3-CLEAR,
# MON-288-PRECHECK-RULE, MON-288-O287-CLEAR, MON-288-C4-RULE, MON-288-AB-RULE and MON-288-O3-CLEAR)
# adds, in a K = 1 step publishing the
# product packet LAB-SYNC-001: part A, architecture/data-correctness/record.json with its schema, its thirteen
# vectors, the reference model scripts/data_correctness.py, the checker scripts/validate_data_correctness.py and
# their tests; part B, R14 mas-harness-reference-lab's rows in the two successor records, its plan page and the
# allowed names from slot 288 (rule-288.json and scripts/repository_registration_288.py), with the freeze sweep's
# authored edits at their named lines (048-D1 (b)); part C, LAB-SYNC-001, R13's PR as a LAB packet; and the class
# rule v2.5 in ci/chain_checkpoint.py (CONTRACT_288 rev 4 section 8.1), whose new digest this layer pins among its
# packet files. Repository bytes are read only through reviewed_bytes; an era file is refused unless bound by
# digest on every read, a changed file by the authority's afterSha256. Each refusal is a pure check over the values
# read. Checked here (CONTRACT_288 rev 4 section 8): V1 the packet's files; E1 the model and the checker from their
# era bytes; E2 seven base files unchanged; E3 class-other hunks only at the named spans, read under v2.5; E4 raw
# == effective; V4 the registry rider; V5 the product; V6 the hunk-class record under v2.5. Last, this layer's own
# inverse hunks are the canonical ones.
PACKET_FILES = ('architecture/data-correctness/record.json', 'architecture/data-correctness/schema.json', 'architecture/data-correctness/vectors/rf1-concurrent-reservations.json', 'architecture/data-correctness/vectors/rf2-paused-holder.json', 'architecture/data-correctness/vectors/rf3-skew-and-jump.json', 'architecture/data-correctness/vectors/rf4-replay-per-class.json', 'architecture/data-correctness/vectors/rf4-retry-after-unknown.json', 'architecture/data-correctness/vectors/rf4-receipt-key-restart.json', 'architecture/data-correctness/vectors/rf4-receipt-key-per-attempt.json', 'architecture/data-correctness/vectors/neg-bounded-not-exactly-once.json', 'architecture/data-correctness/vectors/neg-exception-path-dedup.json', 'architecture/data-correctness/vectors/rf5-mixed-versions.json', 'architecture/data-correctness/vectors/rf5-reader-drops-previous-version.json', 'architecture/data-correctness/vectors/rf6-deletion-through-derived.json', 'architecture/data-correctness/vectors/rf7-log-only-replay-diverges.json', 'scripts/data_correctness.py', 'scripts/validate_data_correctness.py', 'tests/test_data_correctness.py', 'architecture/repository-registration/rule-288.json', 'scripts/repository_registration_288.py', 'ci/chain_checkpoint.py')
BASE_FILES = ('architecture/services.yaml', 'architecture/dependency-graph.yaml', 'schemas/services.schema.json', 'schemas/dependency-graph.schema.json', 'architecture/service-edges.yaml', 'architecture/repositories.yaml', 'schemas/repositories.schema.json')
VECTORS = ('architecture/data-correctness/vectors/rf1-concurrent-reservations.json', 'architecture/data-correctness/vectors/rf2-paused-holder.json', 'architecture/data-correctness/vectors/rf3-skew-and-jump.json', 'architecture/data-correctness/vectors/rf4-replay-per-class.json', 'architecture/data-correctness/vectors/rf4-retry-after-unknown.json', 'architecture/data-correctness/vectors/rf4-receipt-key-restart.json', 'architecture/data-correctness/vectors/rf4-receipt-key-per-attempt.json', 'architecture/data-correctness/vectors/neg-bounded-not-exactly-once.json', 'architecture/data-correctness/vectors/neg-exception-path-dedup.json', 'architecture/data-correctness/vectors/rf5-mixed-versions.json', 'architecture/data-correctness/vectors/rf5-reader-drops-previous-version.json', 'architecture/data-correctness/vectors/rf6-deletion-through-derived.json', 'architecture/data-correctness/vectors/rf7-log-only-replay-diverges.json')
REGISTRY_BASE_SHA256 = "ff5aa32b5b4c9acb5a03083ef3762e6ab3c8964eb25878edff100e214c228121"
BASE_SHA256 = MappingProxyType({
    "architecture/services.yaml": "857376b5e2b10a2a2542124a7d36b770eca531d15e463d68415416b887dd90a6",
    "architecture/dependency-graph.yaml": "47986eff1832f2ed990bb9ceb2cd9aab574475df0bc20f2a39ac91c985cfd50f",
    "schemas/services.schema.json": "7aa4eedb210650120496ea5858cbde3067dfa7d9c3b5b54bf39e3655f4010f0a",
    "schemas/dependency-graph.schema.json": "9c6f18bcc26e2b574297ba3e50d2e440f67f9bb78b3b5b7cfffa179c7141c870",
    "architecture/service-edges.yaml": "20a4b631c54dd8dbe72930b85893b0f57dbd743c7f8dc2a01298796f374444a6",
    "architecture/repositories.yaml": "02190a668c6a9114b3733724bec4e552c553867e789b0802f6aaa6759148051d",
    "schemas/repositories.schema.json": "8b1841a75925c2b059909424656cf85d20691c50d5585da5b9ae7e5971271f27",
})
ERA_SHA256 = MappingProxyType({
    "architecture/authority-map.json": "1a5de06452d7133d90520b4b89670b2b0486e341fb2e20f2bf46a6ea86462440",
    "architecture/chain-product-packets/rule.json": "5e6e6821eace0e50e416c21ab2e605a165b2e69e455cf3fa6b051f7db99fb4d4",
    "architecture/data-correctness/record.json": "7a3d2aa8785d18322606ea9d394606e6394412012fd00fbe03a4b4ed0c7d6370",
    "architecture/data-correctness/schema.json": "f0e5e0968b6f184154f557b756e6a69a565c888a264a3652f58d2e3387f2258d",
    "architecture/data-correctness/vectors/neg-bounded-not-exactly-once.json": "975e128a281f7a32fbf6cf0835f38074d6318e9e4c806bc052a970450fd17670",
    "architecture/data-correctness/vectors/neg-exception-path-dedup.json": "92279bb7bfbb8742953d9180401bd1405040dd6d00c2903696b3cb88fa5bf6a1",
    "architecture/data-correctness/vectors/rf1-concurrent-reservations.json": "9fdb78ca49910e49b274b0240565a95571d28909663748e0a57577b8e81e9fcb",
    "architecture/data-correctness/vectors/rf2-paused-holder.json": "3bcd4f7f787b5008c6c869c5a64274a8c470f95f825b0188594c395a122d77f0",
    "architecture/data-correctness/vectors/rf3-skew-and-jump.json": "4c88c67e45c3caa6883a0569fdaef2037ed8ac4cfa03cee42c85d2054ef86622",
    "architecture/data-correctness/vectors/rf4-receipt-key-per-attempt.json": "bb0f1a6ba23051b621095973adc98ab81a648402d6073c239a24f9067bcf8b5f",
    "architecture/data-correctness/vectors/rf4-receipt-key-restart.json": "f8c01547bc17e5c96d3270e61a50bd9d37a161168d75c4cfa9a95190a5a5d4ac",
    "architecture/data-correctness/vectors/rf4-replay-per-class.json": "00ae3a52bf1df74e20d82a9e08aabf1c14c48c9746ec37e67dae6adf435b6ea3",
    "architecture/data-correctness/vectors/rf4-retry-after-unknown.json": "8a549031fca07a77d7419bd05559dd3305cf1aa477baff60cda261ef1c7e7598",
    "architecture/data-correctness/vectors/rf5-mixed-versions.json": "9532d688d7111ebbee29ad2db392a44e08d509698f77bb32088837c497adb198",
    "architecture/data-correctness/vectors/rf5-reader-drops-previous-version.json": "71f15bc9ae5d946a1b9ede4ab3a4f73849011b570d64f349ce14e5dffea2927a",
    "architecture/data-correctness/vectors/rf6-deletion-through-derived.json": "a1293ffdf8b47f8820c398e3e68ac355139bca55ded77b8f04d1eeef935b4c75",
    "architecture/data-correctness/vectors/rf7-log-only-replay-diverges.json": "d6f638f9d6a403b21774456eac6e09a0288ee44ab0b31f9e461244306f680e81",
    "architecture/dependency-graph.yaml": "47986eff1832f2ed990bb9ceb2cd9aab574475df0bc20f2a39ac91c985cfd50f",
    "architecture/providers.yaml": "9e2b43dac1ca4531dcdeb3a1b6ead8002d7384e2a0d0e6b57e972accb8631c02",
    "architecture/repositories.yaml": "02190a668c6a9114b3733724bec4e552c553867e789b0802f6aaa6759148051d",
    "architecture/repository-registration/rule-288.json": "413c6e798ba749d7ce46f6bfa30e8af2c1cda5347f94d9afca083a1e036a2e44",
    "architecture/repository-registration/rule.json": "4405e9da30db3181eb257b2a0e47bc7bcdda0f6e35e29e4f16de564a2bd1445f",
    "architecture/review-briefs/REVIEW_BRIEF_PACKET.md": "6dcff68d7e6b01823f1740063e94910edcc159a71a6ee803f1b66c62fd06e274",
    "architecture/review-record/briefs.json": "37c3b033b4c7c824ea6490014961348ae204b3dc793facdd4936d92a366065dd",
    "architecture/sector-catalog/overlay.json": "296c973e8902a822da2bdc0ad3603170deb6a91cffc2d37ca9332ddf1834c4e4",
    "architecture/sector-direction.json": "cfc39b4adbfb2771e27cc5498d94530d5691130736a8791288ce296253fc2efe",
    "architecture/service-edges.yaml": "20a4b631c54dd8dbe72930b85893b0f57dbd743c7f8dc2a01298796f374444a6",
    "architecture/services.yaml": "857376b5e2b10a2a2542124a7d36b770eca531d15e463d68415416b887dd90a6",
    "ci/chain_checkpoint.py": "8c8789073698f4e7441b6fda6e7fae8675ad9e8cdd3b30c1a4471809fdc874a0",
    "docs/PROVIDER_MODULE_CATALOG.md": "1723f1ea35ecc87529c2d680f7e51fda61923a368f1e241b7a82982b10935b1d",
    "docs/repositories/11-mas-harness-distribution.md": "aacdefc0ee7262840c3ed24b70f431d2758fd4ac17780f0de4710275924c4c97",
    "schemas/dependency-graph.schema.json": "9c6f18bcc26e2b574297ba3e50d2e440f67f9bb78b3b5b7cfffa179c7141c870",
    "schemas/repositories.schema.json": "8b1841a75925c2b059909424656cf85d20691c50d5585da5b9ae7e5971271f27",
    "schemas/services.schema.json": "7aa4eedb210650120496ea5858cbde3067dfa7d9c3b5b54bf39e3655f4010f0a",
    "scripts/data_correctness.py": "dd795c8ab2ff7ee9c130cc0683749bf498cd085079abb508fc495299fa6e0f27",
    "scripts/repository_registration.py": "e8635f23dbf10572da331237483c8245ee590f9f423f54d6c8ce28b11c01736c",
    "scripts/repository_registration_288.py": "6aff2571fa8db90c52d26124d74289021877f6347fe6f60bdf5f9348b1fb5d4f",
    "scripts/validate_data_correctness.py": "dbb8c3e45894c34536e4022968c9697948f56ce08641575ff2074727fab7535d",
    "task-packets/IND-BANK-001.yaml": "4a7cbd12501f38fb3404afece8d38ddb7d14e0c38e6e429929be03dcd7d81957",
    "task-packets/IND-BANK-002.yaml": "6af9cfe2c3c3577f1644473737d995c76393de9f504738245303d3ec9abda7d5",
    "tests/test_data_correctness.py": "46fb2f335ae269a44dcb839fc6a6047ba4bddf61dbe8b054fbc51deffa8d3a1c",
})
ERRATA_LINES = MappingProxyType({
    "architecture/chain-checkpoint/README.md": ((87, 87), (230, 231)),
    "architecture/chain-checkpoint/oracle-identity.json": ((5, 5), (28, 29), (44, 44)),
    "architecture/oracle-identity-met-006.json": ((5, 5), (8, 8), (28, 29), (39, 39)),
    "architecture/oracle-identity-met-perf-049.json": ((5, 5), (8, 8), (28, 29), (37, 37)),
    "architecture/oracle-identity-met-registry-001.json": ((5, 5), (8, 8), (28, 29), (35, 35)),
    "architecture/repository-registration/language-placement.json": ((11, 48),),
    "architecture/repository-registration/repositories.json": ((6, 14),),
    "ci/chain_checkpoint.py": ((10, 11), (68, 68), (71, 72), (98, 99), (483, 484), (486, 486), (573, 573), (599, 599), (659, 659), (678, 678), (687, 687), (699, 699), (804, 804), (818, 818), (1104, 1104), (1206, 1206)),
    "docs/MASTER_DEVELOPMENT_PLAN.md": ((3136, 3136),),
    "docs/adr/0001-repository-boundaries.md": ((29, 29), (33, 35), (65, 65)),
    "docs/repositories/13-mas-harness-research-lab.md": ((69, 70),),
    "scripts/language_placement.py": ((104, 104), (186, 187), (231, 232)),
    "scripts/validate_architecture.py": ((403, 416),),
    "scripts/validate_readiness.py": ((694, 695), (4083, 4085), (5336, 5337), (5347, 5347)),
    "task-packets/README.md": ((1795, 1796),),
    "tests/test_chain_checkpoint.py": ((45, 45), (244, 244), (662, 662), (666, 666), (1150, 1151)),
    "tests/test_language_placement.py": ((59, 59), (63, 63), (315, 315), (319, 319), (652, 652), (1203, 1203), (1242, 1242), (1245, 1245)),
    "tests/test_met_006_oracle.py": ((1829, 1829), (2086, 2086)),
    "tests/test_met_perf_047_oracle.py": ((131, 131),),
    "tests/test_met_perf_049_oracle.py": ((60, 60),),
    "tests/test_met_registry_001_oracle.py": ((126, 126), (283, 284), (288, 289)),
    "tests/test_packet_declaration_consistency.py": ((77, 77),),
    "tests/test_release_lock_registration.py": ((28, 29), (80, 81), (105, 105), (120, 120), (205, 205), (219, 219)),
    "tests/test_sector_catalog.py": ((748, 774),),
    "tests/test_task_packets.py": ((86, 86), (89, 90), (105, 105)),
})
VECTOR_EXPECT = MappingProxyType({
    "architecture/data-correctness/vectors/rf1-concurrent-reservations.json": {"refuse": "DC_WRITE_SKEW"},
    "architecture/data-correctness/vectors/rf2-paused-holder.json": {"refuse": "DC_FENCE"},
    "architecture/data-correctness/vectors/rf3-skew-and-jump.json": {"refuse": "DC_CLOCK"},
    "architecture/data-correctness/vectors/rf4-replay-per-class.json": "ACCEPT",
    "architecture/data-correctness/vectors/rf4-retry-after-unknown.json": {"refuse": "DC_OPID"},
    "architecture/data-correctness/vectors/rf4-receipt-key-restart.json": "ACCEPT",
    "architecture/data-correctness/vectors/rf4-receipt-key-per-attempt.json": {"refuse": "DC_OPID"},
    "architecture/data-correctness/vectors/neg-bounded-not-exactly-once.json": {"refuse": "DC_OPID"},
    "architecture/data-correctness/vectors/neg-exception-path-dedup.json": {"refuse": "DC_OPID"},
    "architecture/data-correctness/vectors/rf5-mixed-versions.json": "ACCEPT",
    "architecture/data-correctness/vectors/rf5-reader-drops-previous-version.json": {"refuse": "DC_VERSION"},
    "architecture/data-correctness/vectors/rf6-deletion-through-derived.json": {"refuse": "DC_DERIVED"},
    "architecture/data-correctness/vectors/rf7-log-only-replay-diverges.json": {"refuse": "DC_REPLAY_STATE"},
})
PRODUCT_FACTS = MappingProxyType({
    "LAB-SYNC-001": MappingProxyType({
        "repository": "mas-harness-research-lab", "predecessors": ('LAB-REPO-001',), "allowedPaths": ('research/',),
        "head": "9992d1755f71edc2ac25eacd8aceff9f06a76af7", "base": "2e977f4f5a3162bd2ec3e939b9c2c16c8956a994",
        "binding": "4694ddcb18be59f45253648f405bae1c3c39f34e74bdf54d45b2615649f1a3d2",
        "comparator": "LAB-REPO-001"}),
})
COMPARATOR_SHA256 = "8ae5c7fd1efbf8a7b3d38881030184dc13bbc19ec080cd44748d6636740ebf9e"
REGISTRY_PATH = "architecture/review-record/briefs.json"
PACKET_BRIEF = "architecture/review-briefs/REVIEW_BRIEF_PACKET.md"
READER_PATH = "ci/chain_checkpoint.py"
RIDERS = (("PACKET", NEW_PACKET + "/packet", PACKET_BRIEF, 1),)
HUNK_RECORD_MEMBERS = frozenset({"authorityPath", "hunkClassVocabulary", "hunkClassRuleSha256", "hunkClassContext",
                                 "classes", "outcomeStatements"})
HUNK_VOCABULARY = ("bridge", "cascade", "other", "record", "register")     # chainmech v2.5 keeps v2.3's vocabulary
NORMALISED = ("bridge", "cascade", "record", "register")                   # the mechanics forms v2.5 normalises
HUNK_RULE_SHA256 = "106e577175d692a5d627b2b21a0adfab8c4cb9cc4e06d7d45d97be5ef663c778"


def reviewed_bytes(path: str) -> bytes:
    """This packet's reviewed bytes of path; a bridged successor projects newer bytes back first."""
    return regular_bytes(path)


def _era_bytes(path: Any, raw: Any) -> bytes:
    """An era file's bytes, checked against its era digest; a path outside the era is refused."""
    expected = ERA_SHA256.get(path) if type(path) is str else None
    require(expected is not None, "MET-007 reviewed bytes are bound: " + str(path))
    require(type(raw) is bytes and digest(raw) == expected, "unreviewed MET-007 source: " + path)
    return raw


def _verified(path: str) -> bytes:
    """reviewed_bytes, checked against its era digest on every read; a path outside the era is refused before it is
    read."""
    require(type(path) is str and path in ERA_SHA256, "MET-007 reviewed bytes are bound: " + str(path))
    return _era_bytes(path, reviewed_bytes(path))


def _bound_read(path: str, expected: Any) -> bytes:
    """reviewed_bytes of a file named by an era-verified record, checked against the digest that record gives it."""
    require(type(path) is str and _sha(expected), "MET-007 bound read: " + str(path))
    _path(path)
    raw = reviewed_bytes(path)
    require(type(raw) is bytes and digest(raw) == expected, "MET-007 bound file drift: " + path)
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
           "the registry differs from the base by exactly the MET-007 packet rider, pinning the generic packet "
           "brief")


def validate_registry() -> None:
    """V4 over briefs.json and the generic packet brief."""
    check_registry(_verified(REGISTRY_PATH), {PACKET_BRIEF: _verified(PACKET_BRIEF)})


def check_packet_files(files: Any) -> None:
    """V1: the packet's files are exactly these, and each one's bytes equal the sha256 pinned for it."""
    _bound(lambda: type(files) is dict and sorted(files) == sorted(PACKET_FILES) and len(files) == len(PACKET_FILES),
           "MET-007 V1 the packet files are exactly the twenty-one")
    for path in PACKET_FILES:
        _bound(lambda: type(files[path]) is bytes and digest(files[path]) == ERA_SHA256[path],
               "MET-007 V1 a packet file's bytes equal its pinned digest: " + path)


def validate_packet_files() -> None:
    check_packet_files({path: _verified(path) for path in PACKET_FILES})


def _v25_source(path: str) -> bytes:
    """The reader's era-verified bytes with one alias line: its v2.5 copy answers as `classify` (the identity rule's
    attribute names hold `classify`, not `classify_v25`)."""
    return _verified(path) + b"\nclassify = classify_v25\n"


def _era_rule(path: str, name: str) -> types.ModuleType:
    """The reader's v2.5 rule as an era model, executed from its verified bytes plus the alias line (no import, no
    bytecode); it imports only the standard library."""
    module = types.ModuleType(name)
    module.__file__ = str(ROOT / path)
    exec(compile(_v25_source(path), path, "exec", dont_inherit=True), module.__dict__)
    return module


def _v24_context(record: Any, context: Any) -> dict:
    """v2.5's inputs from this step's authority and the record's context (the reader's context_v24 form): the catalog
    pair from the authority's baselinePackets size, then countPairs; the products in the authority's productPackets key
    order (K = 1); the new tests from newFiles."""
    n = len(record["baselinePackets"])
    return {"prevValidator": context["prevValidator"], "prevTest": context["prevTest"], "newPacket": context["newPacket"],
            "products": list(record["productPackets"]), "steps": context["steps"],
            "pairs": [[n, n + context["steps"][1]]] + [list(pair) for pair in context["countPairs"]],
            "newTests": [p for p in record["newFiles"] if p.startswith("tests/") and p.endswith(".py")]}


def check_hunk_record(raw: Any, changed: Any, afters: Any, classify: Any, context: Any, rule_sha: Any) -> None:
    """V6 under v2.5: the record's six closed members; it names this layer's authority; the closed vocabulary and v2.5's
    digest, which the reader's copy carries; the context is this step's names with countPairs; no outcome statement; one
    class per reverse hunk for exactly the changed files; and
    every class equals v2.5's class at its position."""
    record = _parsed(raw)
    _bound(lambda: type(record) is dict and set(record) == HUNK_RECORD_MEMBERS and record["authorityPath"] == AUTHORITY_PATH
           and record["outcomeStatements"] == [],
           "MET-007 V6 the hunk-class record is closed and names this layer's authority")
    _bound(lambda: record["hunkClassVocabulary"] == list(HUNK_VOCABULARY)
           and record["hunkClassRuleSha256"] == HUNK_RULE_SHA256 == rule_sha,
           "MET-007 V6 the hunk-class record's vocabulary and rule digest are v2.5's")
    _bound(lambda: type(record["hunkClassContext"]) is dict and set(record["hunkClassContext"]) == set(HUNK_CONTEXT)
           and record["hunkClassContext"] == {"newPacket": NEW_PACKET, "prevValidator": HUNK_CONTEXT["prevValidator"],
                                              "prevTest": HUNK_CONTEXT["prevTest"], "steps": [1, 2], "countPairs": [[315, 317]]},
           "MET-007 V6 the hunk-class record's context is this step's names")
    classes = record.get("classes") if type(record) is dict else None
    _bound(lambda: type(changed) is dict and type(classes) is dict and set(classes) == set(changed)
           and all(type(classes[p]) is list and all(type(c) is str for c in classes[p])
                   and len(classes[p]) == len(changed[p].get("reverseHunks", [])) for p in changed),
           "MET-007 V6 the hunk-class record lists one class per hunk for exactly the changed files")
    for path, entry in changed.items():
        seen = set()
        for position, (cls, hunk) in enumerate(zip(classes[path], entry.get("reverseHunks", []))):
            _bound(lambda: cls in HUNK_VOCABULARY and cls == classify(
                path, afters[path], hunk["at"], _base64(hunk["removeBase64"]), _base64(hunk["insertBase64"]), context,
                seen=seen),
                   "MET-007 V6 a recorded class re-checks by position: %s hunk %d" % (path, position))


def validate_hunk_record() -> None:
    """V6 over the hunk-class record (bound by its newFiles digest), the changed files (bound by their afterSha256) and
    the reader's copy of v2.5, executed from its era-verified bytes."""
    record = authority()
    raw = _bound_read(HUNK_RECORD_PATH, record["newFiles"].get(HUNK_RECORD_PATH))
    afters = {path: _bound_read(path, entry["afterSha256"]) for path, entry in record["changedFiles"].items()
              if "reverseHunks" in entry}
    rule = _era_rule(READER_PATH, READER_NAME)
    side = _parsed(raw)
    rule_sha = HUNK_RULE_SHA256 if _verified(READER_PATH).count(
        b'RULE_V25_SHA256 = "' + HUNK_RULE_SHA256.encode("ascii") + b'"') == 1 else None
    context = _v24_context(record, side["hunkClassContext"]) if _holds(
        lambda: _v24_context(record, side["hunkClassContext"]) is not None) else None
    check_hunk_record(raw, record["changedFiles"], afters, rule.classify, context, rule_sha)


def _era_import(era: dict) -> Any:
    """An import function that resolves the named modules to this era's executed copies and everything else normally."""
    def era_import(name, globals=None, locals=None, fromlist=(), level=0):
        if level == 0 and name in era:
            return era[name]
        return builtins.__import__(name, globals, locals, fromlist, level)
    return era_import


def _era_model(path: str, name: str, imports: dict | None = None) -> types.ModuleType:
    """A reference module of this era, executed from its reviewed bytes; named imports resolve to this era's copies."""
    module = types.ModuleType(name)
    module.__file__ = str(ROOT / path)
    if imports:
        namespace = dict(vars(builtins))
        namespace["__import__"] = _era_import(imports)
        module.__dict__["__builtins__"] = namespace
    exec(compile(_verified(path), path, "exec", dont_inherit=True), module.__dict__)
    return module


MODEL_PATH = "scripts/data_correctness.py"
MODEL_NAME = "_met_007_data_correctness"
CHECKER_PATH = "scripts/validate_data_correctness.py"
CHECKER_NAME = "_met_007_validate_data_correctness"
CATALOG_PATH = "architecture/services.yaml"
RECORD_PATH = "architecture/data-correctness/record.json"
RULE_284_PATH = "architecture/repository-registration/rule.json"
RULE_288_PATH = "architecture/repository-registration/rule-288.json"
V2_RULE_PATH = "architecture/chain-product-packets/rule.json"
REGISTRATION_284_PATH = "scripts/repository_registration.py"
REGISTRATION_288_PATH = "scripts/repository_registration_288.py"
SLOT = 288
HUNK_RECORD_PATH = "architecture/chain-checkpoint/hunk-classes/288.json"
READER_NAME = "_met_007_chain_checkpoint"
HUNK_CONTEXT = MappingProxyType({"newPacket": NEW_PACKET, "prevValidator": "scripts/validate_met_006.py",
                                 "prevTest": "tests/test_met_006.py", "steps": (1, 2), "countPairs": ((315, 317),)})


def _era_read(path: Any) -> Any:
    """The checker's injected reader: an era file's verified bytes, None for any other path."""
    return _verified(path) if type(path) is str and path in ERA_SHA256 else None


def _replayed(model: Any, raw: Any) -> Any:
    """The era model's outcome for one vector's bytes, or None when the model refuses the vector itself."""
    try:
        return model.replay(parse(raw))
    except (KeyError, TypeError, ValueError, AttributeError, IndexError):
        return None


def check_correctness(replays: Any, refusals: Any) -> None:
    """E1: every vector replays to its expectation (CONTRACT_288 section 4's table) through the era model, and the record
    passes the checker (DC_SHAPE to DC_VECTORS) on this era's bytes."""
    _bound(lambda: type(replays) is dict and list(replays) == list(VECTORS)
           and all(replays[path] == VECTOR_EXPECT[path] for path in VECTORS),
           "MET-007 E1 every vector replays to its expectation through the era model")
    _bound(lambda: type(refusals) is list and refusals == [],
           "MET-007 E1 the record passes its checker (DC_SHAPE to DC_VECTORS)")


def _era_checker() -> tuple:
    """The model and the checker, each executed from its era-verified bytes (no import from this layer); the checker's
    import of the model, in either of its two forms, resolves to the era model's executed copy."""
    model = _era_model(MODEL_PATH, MODEL_NAME)
    checker = _era_model(CHECKER_PATH, CHECKER_NAME, {"data_correctness": model,
                                                      "scripts": types.SimpleNamespace(data_correctness=model)})
    return model, checker


def validate_correctness(packets: Any) -> None:
    """E1: the era model replays every vector; the era checker reads only era files."""
    model, checker = _era_checker()
    replays = {path: _replayed(model, _verified(path)) for path in VECTORS}
    check_correctness(replays, checker.check(_era_read, frozenset(packets)))


def check_base_files(files: Any, changed: Any, new: Any) -> None:
    """E2 (Q-288-B1): the catalog, the graph, both catalog schemas, the service-edge record, the registry and its schema
    equal their base bytes, and this step's authority names none of them."""
    _bound(lambda: type(files) is dict and sorted(files) == sorted(BASE_SHA256)
           and all(type(files[path]) is bytes and digest(files[path]) == BASE_SHA256[path] for path in BASE_SHA256),
           "MET-007 E2 the seven base files equal their base bytes")
    _bound(lambda: type(changed) is dict and type(new) is dict and not set(BASE_SHA256) & (set(changed) | set(new)),
           "MET-007 E2 this step changes none of the seven base files")


def validate_base_files() -> None:
    record = authority()
    check_base_files({path: _verified(path) for path in BASE_FILES}, record["changedFiles"], record["newFiles"])


def check_errata(classes: Any, changed: Any, befores: Any) -> None:
    """E3: class-other (authored) hunks fall only on the named files; each carries one, and each such hunk lies inside one
    of its file's named base-line spans: placed in the before bytes by its offset plus the earlier hunks' shift, its
    before-text is there, and the base lines it spans are within the span; every other hunk is a mechanics form v2.5
    normalises."""
    _bound(lambda: type(classes) is dict and type(changed) is dict
           and all(cls in NORMALISED or (cls == "other" and path in ERRATA_LINES) for path in classes for cls in classes[path]),
           "MET-007 E3 class-other hunks fall only on the named files")
    for path, spans in ERRATA_LINES.items():
        _bound(lambda: "other" in classes[path] and type(befores[path]) is bytes,
               "MET-007 E3 the named file carries its authored hunk: " + path)
        before, shift = befores[path], 0
        for position, (cls, hunk) in enumerate(zip(classes[path], changed[path]["reverseHunks"])):
            removed, inserted = _base64(hunk["removeBase64"]), _base64(hunk["insertBase64"])
            at = hunk["at"] + shift
            shift += len(inserted) - len(removed)
            if cls == "other":
                start = before[:at].count(b"\n") + 1
                end = start + inserted[:-1].count(b"\n")
                _bound(lambda: before[at:at + len(inserted)] == inserted
                       and any(first <= start and end <= last for first, last in spans),
                       "MET-007 E3 an authored hunk lies at its named lines: %s hunk %d" % (path, position))


def validate_errata() -> None:
    """E3 over the hunk-class record (bound by its newFiles digest) and each named file's before bytes, projected back
    through this layer's own hunks from its afterSha256-bound bytes."""
    record = authority()
    side = _parsed(_bound_read(HUNK_RECORD_PATH, record["newFiles"].get(HUNK_RECORD_PATH)))
    befores = {path: _undo_this_layer(path, _bound_read(path, record["changedFiles"][path]["afterSha256"]))
               for path in ERRATA_LINES if path in record["changedFiles"]}
    check_errata(side.get("classes") if type(side) is dict else None, record["changedFiles"], befores)


def _entries(services: Any) -> list:
    """Each service's id with its dependency entries, in order (the checker's deps form)."""
    return [(service["id"], [d["id"] if type(d) is dict else d for d in service.get("dependencies", [])])
            for service in services]


def check_parity(raw_catalog: Any, basis: Any, refusals: Any) -> None:
    """E4 (SECTOR-D1): the effective catalog equals the raw catalog in service names and dependency entries, in order:
    the raw catalog's 28 services and 129 entries are the record's basis, which pins the effective view with the parity
    RAW_EQUALS_EFFECTIVE, and the era checker's DC_BASIS (the effective catalog through its overlay reader over era bytes,
    its counts and its parity with the raw catalog, in order) refuses nothing."""
    _bound(lambda: len(raw_catalog["services"]) == 28 and sum(len(e) for _, e in _entries(raw_catalog["services"])) == 129
           and type(basis) is dict and basis == {"view": "EFFECTIVE", "sha256": basis["sha256"], "services": 28,
                                                 "dependencyEntries": 129, "parity": "RAW_EQUALS_EFFECTIVE"}
           and type(refusals) is list and [code for code, _ in refusals if code == "DC_BASIS"] == [],
           "MET-007 E4 the effective catalog equals the raw catalog (28 services, 129 dependency entries, in order)")


def validate_parity(packets: Any) -> None:
    """E4 over era bytes only: the raw catalog, the record's basis and the era checker's refusals."""
    _model, checker = _era_checker()
    check_parity(safe_load(_verified(CATALOG_PATH)), parse(_verified(RECORD_PATH))["basis"]["catalog"],
                 checker.check(_era_read, frozenset(packets)))


def check_products(raws: Any, comparators: Any, record: Any, allowed: Any) -> None:
    """V5 on plain data: raws maps each product id to its YAML bytes and comparators to its comparator's bytes; record is
    the authority's value; allowed is R8 clause 2's names at slot 288 (None when the successor refused)."""
    _bound(lambda: list(raws) == list(PRODUCT_PACKETS) == list(PRODUCT_FACTS) == list(record["productPackets"])
           == list(record["productComparators"]) == list(comparators), "MET-007 V5 product set")
    for name in PRODUCT_PACKETS:
        raw, facts = raws[name], PRODUCT_FACTS[name]
        _bound(lambda: type(raw) is bytes and digest(raw) == record["productPackets"][name],
               "MET-007 V5 product bytes: " + name)
        packet = safe_load(raw.decode("utf-8"))
        _bound(lambda: packet["id"] == name and packet["repository"] == facts["repository"]
               and tuple(packet["predecessors"]) == facts["predecessors"]
               and tuple(packet["allowedPaths"]) == facts["allowedPaths"], "MET-007 V5 product facts: " + name)
        _bound(lambda: raw.count(facts["head"].encode()) >= 1 and raw.count(facts["base"].encode()) >= 1
               and raw.count(facts["binding"].encode()) >= 1, "MET-007 V5 product pins: " + name)
        _bound(lambda: record["productComparators"][name] == {"packet": facts["comparator"], "sha256": COMPARATOR_SHA256}
               and type(comparators[name]) is bytes and digest(comparators[name]) == COMPARATOR_SHA256
               and facts["comparator"] == facts["predecessors"][-1], "MET-007 V5 product comparator: " + name)
        inherited = safe_load(comparators[name].decode("utf-8"))["offlineAcceptanceCommands"]
        commands = packet["offlineAcceptanceCommands"]
        _bound(lambda: type(inherited) is list and len(inherited) == 6 and type(commands) is list
               and [argv for argv in commands if argv in inherited] == inherited,
               "MET-007 V5 the product keeps its comparator's commands byte-exact and in order (R13): " + name)
        _bound(lambda: type(allowed) is list and packet["repository"] in allowed,
               "MET-007 V5 R8 clause 2 admits the product's repository at slot 288: " + name)


def _allowed_names() -> Any:
    """R8 clause 2's names at slot 288 through scripts/repository_registration_288.py and the 284 module it pins, both
    executed from their era-verified bytes; None when either refuses."""
    try:
        base = _era_model(REGISTRATION_284_PATH, "_met_007_registration_284")
        return _era_model(REGISTRATION_288_PATH, "_met_007_registration_288").check(
            base, _verified(RULE_288_PATH), _verified(RULE_284_PATH), _verified(REGISTRATION_284_PATH),
            _verified(REGISTRATION_288_PATH), parse(_verified(V2_RULE_PATH)), SLOT)
    except (KeyError, TypeError, ValueError, AttributeError, IndexError):
        return None


def validate_products() -> None:
    """V5 over the product YAML (bound by productPackets), its comparator (bound by productComparators) and the allowed
    names at slot 288."""
    record = authority()
    check_products({name: _bound_read("task-packets/%s.yaml" % name, record["productPackets"][name])
                    for name in PRODUCT_PACKETS},
                   {name: _bound_read("task-packets/%s.yaml" % pin["packet"], pin["sha256"])
                    for name, pin in record["productComparators"].items()}, record, _allowed_names())


def validate_met_007(packets: dict[str, Any]) -> None:
    """Every era file first; then V1, E1 (the model and the checker), E2 (the base files), E3 (the authored edits), E4
    (raw == effective), V4 (the registry), V5 (the product) and V6 (the hunk-class record); last, this layer's canonical
    hunks."""
    for path in ERA_SHA256:
        _verified(path)
    validate_packet_files()
    validate_correctness(packets)
    validate_base_files()
    validate_errata()
    validate_parity(packets)
    validate_registry()
    validate_products()
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
    validator_raw = regular_bytes(VALIDATOR_PATH)
    literal = b'AUTHORITY_SHA256 = "' + AUTHORITY_SHA256.encode("ascii") + b'"'
    placeholder = b'AUTHORITY_SHA256 = "TO_BE_PINNED_AFTER_SOURCE_FREEZE"'
    require(validator_raw.count(literal) == 1
            and digest(validator_raw.replace(literal, placeholder))
            == record["validatorNormalizedSha256"], "data correctness validator drift")
    paths = sorted((ROOT / "task-packets").glob("*.yaml"))
    old = set(record["baselinePackets"])
    require(len(paths) == 300 and {path.stem for path in paths} == old | {NEW_PACKET} | set(PRODUCT_PACKETS),
            "closed 300-packet catalog")
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
            "closed source-only data-correctness packet and inherited commands")
    require(len(packet["allowedPaths"]) == len(set(packet["allowedPaths"]))
            and set(packet["allowedPaths"]) == set(record["changedFiles"])
            | set(record["newFiles"]) | {AUTHORITY_PATH, VALIDATOR_PATH,
                                         "task-packets/" + NEW_PACKET + ".yaml"}
            | {"task-packets/" + name + ".yaml" for name in PRODUCT_PACKETS},
            "unreviewed or omitted data-correctness packet path")
    for path, rule in record["changedFiles"].items():
        current = regular_bytes(path)
        require(digest(current) == rule["afterSha256"]
                and digest(historical_bytes(path, current)) == rule["beforeSha256"],
                "unreviewed current source: " + path)
    for path, expected in record["newFiles"].items():
        require(digest(regular_bytes(path)) == expected, "new source drift: " + path)
    validate_met_007(packets)


if __name__ == "__main__":
    validate()
    print("Data correctness valid: 300 current specifications at slot 288; exact 298-packet predecessor; contract reviewed.")
