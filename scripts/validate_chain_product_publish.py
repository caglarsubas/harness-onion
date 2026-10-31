#!/usr/bin/env python3
"""Validate MET-PERF-044 (CHAIN-PRODUCT-PUBLISH-001): the product-packet vocabulary extension, its four records, its v2 identity model and its D5a oracle (V1-V4: the seven packet files, each equal to its adopted digest; the closed record set, the records directory holding exactly its four records and rule.json citing decisions.md by its digest; the oracle identity binding the oracle's bytes; and the registry's MET-PERF-044 packet rider as the one change from the base), and the exact 273-to-272 projection."""
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
AUTHORITY_PATH = "architecture/chain-product-publish-authority.json"
AUTHORITY_SHA256 = "2cce05cf1c8b098d22516fd78eb4dd5094da2bf721f5441e5654bd22a31c9369"
VALIDATOR_PATH = "scripts/validate_chain_product_publish.py"
BASE_COMMIT = "8f5cc7e9678d8cd13f6dda3ae5d205eada9f55e8"
NEW_PACKET = "MET-PERF-044"
PREVIOUS_PACKET = "MET-ADOPT-006"
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
            require(key not in result, "duplicate chain-product-publish authority member")
            result[key] = value
        return result

    def no_constant(_value: str) -> Any:
        raise ValueError("nonfinite chain-product-publish authority number")

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
        require(digest(raw) == AUTHORITY_SHA256, "chain product publish history authority digest")
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
    }, "closed chain product publish history authority")
    require(value["schemaVersion"] == "harness.planeon.ai/chain-product-publish-authority/v1"
            and value["authorityPacket"] == NEW_PACKET
            and value["acceptedBase"] == BASE_COMMIT
            and type(value["baselinePackets"]) is dict
            and len(value["baselinePackets"]) == 272
            and NEW_PACKET not in value["baselinePackets"]
            and type(value["changedFiles"]) is dict
            and type(value["newFiles"]) is dict
            and _sha(value["packetSha256"])
            and _sha(value["validatorNormalizedSha256"]),
            "accepted 272-packet base")
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


# MET-PERF-044 (roadmap CHAIN-PRODUCT-PUBLISH-001; the owner's Q-SEC3-TWO and Q-CPP-2, and the lane monitor's
# owner-delegated rulings MON-CPP-D2 (Q-CPP-1 (a) with its two conditions, Q-CPP-3 to Q-CPP-6 (a)), MON-CPP-DR1 to
# MON-CPP-DR3 (errata E1), MON-CPP-E1-OK, MON-CPP-C1-OK, MON-CPP-CR1R-KEEP to MON-CPP-CR4-KEEP, GO-CPP-ADOPT-C4,
# MON-CPP-ORACLE-KEEP, MON-273-GATESET, Q-273-V2TOOLS (a), MON-273-RIDERS, Q-273-NS and GO-273-MECH) adopts candidate
# c4: the product-packet vocabulary extension (the records architecture/chain-product-packets/rule.json, vectors.json,
# README.md and decisions.md, the owner-decision record rule.json cites by path and digest), the identity model
# scripts/chain_identity_v2.py, which takes the slot and the catalog count apart and reads each layer's product list
# from its source by AST, and the D5a oracle tests/test_met_perf_044_oracle.py with its identity. It publishes no
# product (K = 0), so this step is explained by the existing vocabulary; tests/test_chain_compaction.py runs the v2
# model on the live chain and keeps the v1 = v2 regression on the K = 0 era. Its review series is registered by this
# packet's own rider in architecture/review-record/briefs.json (MET-PERF-044/packet, which the evolution surface record
# at this base classes as gate material, so the owner approves the PR). Repository bytes are read only through
# reviewed_bytes, so a later bridged successor projects its own edits away first; a path outside this era is refused
# before it is read and every era file is bound by digest on every read. The one directory listed is the closed records
# directory, as layer 255 lists its own. Each refusal is a pure check over the values read, so every one has a failing
# case on plain data. Checked here: V1, the packet's files (exactly the seven, each equal to the sha256 of its adopted
# bytes, pinned below); V2, the closed record set (architecture/chain-product-packets/ holds exactly the four records,
# each a regular file of git mode 100644, and rule.json's owner-decision evidence names decisions.md with the sha256 of
# its bytes); V3, the oracle binding (the identity names the oracle test, its file.sha256 equals the oracle test's bytes
# and its ruling is KEEP); and V4, the registry (it differs from the base by exactly the one rider, pointing at the
# generic packet brief with the sha256 of that brief's bytes). No chain validator or chain test is pinned here. Last,
# this layer's own inverse hunks are the canonical byte-minimal ones, recomputed from its era's bytes (MET-PERF-040's
# carried rule).
RECORD_DIR = "architecture/chain-product-packets"
README_PATH = RECORD_DIR + "/README.md"
DECISIONS_PATH = RECORD_DIR + "/decisions.md"
RULE_PATH = RECORD_DIR + "/rule.json"
VECTORS_PATH = RECORD_DIR + "/vectors.json"
RECORDS = (README_PATH, DECISIONS_PATH, RULE_PATH, VECTORS_PATH)
MODEL_PATH = "scripts/chain_identity_v2.py"
ORACLE_IDENTITY = "architecture/oracle-identity-met-perf-044.json"
ORACLE_SCHEMA = "planeon.oracle-identity/v1"
ORACLE_TEST = "tests/test_met_perf_044_oracle.py"
REGISTRY_PATH = "architecture/review-record/briefs.json"
PACKET_BRIEF = "architecture/review-briefs/REVIEW_BRIEF_PACKET.md"
# V1: the packet's files, named by path; each is pinned below by the sha256 of its adopted bytes.
PACKET_FILES = (
    "architecture/chain-product-packets/README.md",
    "architecture/chain-product-packets/decisions.md",
    "architecture/chain-product-packets/rule.json",
    "architecture/chain-product-packets/vectors.json",
    "architecture/oracle-identity-met-perf-044.json",
    "scripts/chain_identity_v2.py",
    "tests/test_met_perf_044_oracle.py",
)
# V4: the registry at the base (the digest of its canonical JSON) and this packet's one rider (kind, series, path,
# version), appended last; the rider's sha256 is the generic packet brief's.
REGISTRY_BASE_SHA256 = "6719dfc3f3fdb504b9689a09179e695c7a5eb80fe44b5f5b57cd7eb820a89692"
RIDERS = (("PACKET", NEW_PACKET + "/packet", PACKET_BRIEF, 1),)
# Every file this era's check reads, with its digest: the packet's files, the registry and the generic packet brief.
ERA_SHA256 = MappingProxyType({
    "architecture/chain-product-packets/README.md": "434b1f0e1dc21f28f65b04c247e84653e25fbcd0231e4584208b19f338f81ef0",
    "architecture/chain-product-packets/decisions.md": "bc4a940b236d7dc8d5066aefa752a706307fbd1b2e4c202d924d6483f89ac7c3",
    "architecture/chain-product-packets/rule.json": "5e6e6821eace0e50e416c21ab2e605a165b2e69e455cf3fa6b051f7db99fb4d4",
    "architecture/chain-product-packets/vectors.json": "26438ebc76d21221790e2bfa9b9cd08b91bf333c729c38ddccbff085b2bf2342",
    "architecture/oracle-identity-met-perf-044.json": "03f81dd952ad37058556f675c323baa5c1ef789ae23b4e90067a56dd936b164f",
    "architecture/review-briefs/REVIEW_BRIEF_PACKET.md": "6dcff68d7e6b01823f1740063e94910edcc159a71a6ee803f1b66c62fd06e274",
    "architecture/review-record/briefs.json": "83791b51c698d90c92680a8ae098ed7d91791d5a84112b3b3761d8deb3d91c77",
    "scripts/chain_identity_v2.py": "23fe723ae060b13727118b5808541d0b40bfee22ac5e803955e324f4dd6d9a55",
    "tests/test_met_perf_044_oracle.py": "c2c0c56d8d3de4b018a71db00486af75f6c1464b0e1d7776e95e58e7c01aa0e2",
})


def reviewed_bytes(path: str) -> bytes:
    """This packet's reviewed bytes of path; a bridged successor projects newer bytes back first."""
    return regular_bytes(path)


def reviewed_tree(directory: str) -> dict[str, int]:
    """Every entry under directory in this packet's tree, by repository path, with its lstat mode (layer 255's form);
    no later packet adds an entry there, since every later layer inherits this listing."""
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


def _git_mode(mode: int) -> str | None:
    """The git mode of a regular file from its lstat mode; anything else has none."""
    if not stat.S_ISREG(mode):
        return None
    return "100755" if mode & 0o100 else "100644"


def _era_bytes(path: Any, raw: Any) -> bytes:
    """An era file's bytes, checked against its era digest; a path outside the era is refused."""
    expected = ERA_SHA256.get(path) if type(path) is str else None
    require(expected is not None, "MET-PERF-044 reviewed bytes are bound: " + str(path))
    require(type(raw) is bytes and digest(raw) == expected, "unreviewed CHAIN-PRODUCT-PUBLISH-001 source: " + path)
    return raw


def _verified(path: str) -> bytes:
    """reviewed_bytes, checked against its era digest on every read; a path outside the era is refused before it is
    read."""
    require(type(path) is str and path in ERA_SHA256, "MET-PERF-044 reviewed bytes are bound: " + str(path))
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


def check_packet_files(files: Any) -> None:
    """V1: the packet's files are exactly the seven, and each one's bytes equal the sha256 pinned for it."""
    _bound(lambda: type(files) is dict and sorted(files) == sorted(PACKET_FILES) and len(files) == len(PACKET_FILES),
           "the packet files are exactly the seven")
    for path in PACKET_FILES:
        _bound(lambda: type(files[path]) is bytes and digest(files[path]) == ERA_SHA256[path],
               "a packet file's bytes equal its pinned digest: " + path)


def validate_packet_files() -> None:
    """V1 over the seven files, each read through the era."""
    check_packet_files({path: _verified(path) for path in PACKET_FILES})


def check_records_tree(tree: Any) -> None:
    """V2: the records directory holds exactly the four records, each a regular file of git mode 100644."""
    _bound(lambda: type(tree) is dict and sorted(tree) == sorted(RECORDS)
           and all(_git_mode(mode) == "100644" for mode in tree.values()),
           "the product-packet records directory holds exactly its four records, each of mode 100644")


def check_decisions_binding(rule_raw: Any, decisions_raw: Any) -> None:
    """V2: rule.json's owner-decision evidence names decisions.md by path and its sha256 equals decisions.md's bytes
    (Q-CPP-1 (a), condition 2)."""
    rule = _parsed(rule_raw)
    _bound(lambda: type(rule["evidence"]["ownerDecision"]["record"]) is dict
           and rule["evidence"]["ownerDecision"]["record"]["path"] == DECISIONS_PATH
           and _sha(rule["evidence"]["ownerDecision"]["record"]["sha256"]) and type(decisions_raw) is bytes
           and rule["evidence"]["ownerDecision"]["record"]["sha256"] == digest(decisions_raw),
           "rule.json's owner-decision evidence names decisions.md with the sha256 of its bytes")


def validate_records() -> None:
    """V2 over the listed records directory and the two records, each read through the era."""
    check_records_tree(reviewed_tree(RECORD_DIR))
    check_decisions_binding(_verified(RULE_PATH), _verified(DECISIONS_PATH))


def check_oracle(identity_raw: Any, oracle_raw: Any) -> None:
    """V3: the oracle identity names the D5a oracle test and is kept, and its file.sha256 equals the oracle test's
    bytes."""
    identity = _parsed(identity_raw)
    _bound(lambda: type(identity) is dict and identity["schemaVersion"] == ORACLE_SCHEMA
           and type(identity["file"]) is dict and identity["file"]["path"] == ORACLE_TEST
           and type(identity["ruling"]) is dict and identity["ruling"]["decision"] == "KEEP",
           "the oracle identity names the oracle test and its ruling is KEEP")
    _bound(lambda: _sha(identity["file"]["sha256"]) and type(oracle_raw) is bytes
           and identity["file"]["sha256"] == digest(oracle_raw),
           "the oracle identity's sha256 equals the oracle test's bytes")


def validate_oracle() -> None:
    """V3 over the identity and the oracle test (hashed only)."""
    check_oracle(_verified(ORACLE_IDENTITY), _verified(ORACLE_TEST))


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
           "the registry differs from the base by exactly the MET-PERF-044 packet rider, pinning the generic packet "
           "brief")


def validate_registry() -> None:
    """V4 over briefs.json and the generic packet brief."""
    check_registry(_verified(REGISTRY_PATH), {PACKET_BRIEF: _verified(PACKET_BRIEF)})


def validate_chain_product_publish() -> None:
    """Every reviewed byte first; then V1 (the packet's files), V2 (the closed record set), V3 (the oracle) and V4 (the
    registry); last, this layer's canonical hunks."""
    for path in ERA_SHA256:
        _verified(path)
    validate_packet_files()
    validate_records()
    validate_oracle()
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
    validator_raw = regular_bytes(VALIDATOR_PATH)
    literal = b'AUTHORITY_SHA256 = "' + AUTHORITY_SHA256.encode("ascii") + b'"'
    placeholder = b'AUTHORITY_SHA256 = "TO_BE_PINNED_AFTER_SOURCE_FREEZE"'
    require(validator_raw.count(literal) == 1
            and digest(validator_raw.replace(literal, placeholder))
            == record["validatorNormalizedSha256"], "chain product publish validator drift")
    paths = sorted((ROOT / "task-packets").glob("*.yaml"))
    old = set(record["baselinePackets"])
    require(len(paths) == 273 and {path.stem for path in paths} == old | {NEW_PACKET},
            "closed 273-packet catalog")
    packets = {}
    for path in paths:
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
            "closed source-only chain-product-publish packet and inherited commands")
    require(len(packet["allowedPaths"]) == len(set(packet["allowedPaths"]))
            and set(packet["allowedPaths"]) == set(record["changedFiles"])
            | set(record["newFiles"]) | {AUTHORITY_PATH, VALIDATOR_PATH,
                                         "task-packets/" + NEW_PACKET + ".yaml"},
            "unreviewed or omitted chain-product-publish packet path")
    for path, rule in record["changedFiles"].items():
        current = regular_bytes(path)
        require(digest(current) == rule["afterSha256"]
                and digest(historical_bytes(path, current)) == rule["beforeSha256"],
                "unreviewed current source: " + path)
    for path, expected in record["newFiles"].items():
        require(digest(regular_bytes(path)) == expected, "new source drift: " + path)
    validate_chain_product_publish()


if __name__ == "__main__":
    validate()
    print("Chain product publish valid: 273 current specifications; exact 272-packet predecessor; contract reviewed.")
