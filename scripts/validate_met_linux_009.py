#!/usr/bin/env python3
"""Validate the MET-LINUX-009 signed root-alias contract for the native runner kit (LINUX-ROOT-ALIASES), adopted as candidate c3 after its in-tree CONTRACT rounds 1 and 2 (the status ADOPTED at slot 264 with a passing allowed-paths derivation, the adopted subject pinned by its bytes, the rounds bound by digest and the registry rider; gate material: GATE_CI, GATE_VERIFIER_DOCS and GATE_REVIEW_PROCESS), and the exact 264-to-263 projection."""
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
    import validate_policy_observation_digests_v2 as successor
except ImportError:
    from scripts.safe_yaml import safe_load
    from scripts import validate_policy_observation_digests_v2 as successor


ROOT = Path(__file__).resolve().parents[1]
AUTHORITY_PATH = "architecture/met-linux-009-authority.json"
AUTHORITY_SHA256 = "dbb2ccdbcf2f88070014ac72b1a8cec78aabb370cd24f552c967d9b42cf4403f"
VALIDATOR_PATH = "scripts/validate_met_linux_009.py"
BASE_COMMIT = "675daccbc8a060d88245f79bf124f0cc6c59d0c2"
NEW_PACKET = "MET-LINUX-009"
PREVIOUS_PACKET = "MET-LIVE-004"
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
            require(key not in result, "duplicate linux-root-aliases authority member")
            result[key] = value
        return result

    def no_constant(_value: str) -> Any:
        raise ValueError("nonfinite linux-root-aliases authority number")

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
        require(digest(raw) == AUTHORITY_SHA256, "linux root aliases history authority digest")
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
    }, "closed linux root aliases history authority")
    require(value["schemaVersion"] == "harness.planeon.ai/met-linux-009-authority/v1"
            and value["authorityPacket"] == NEW_PACKET
            and value["acceptedBase"] == BASE_COMMIT
            and type(value["baselinePackets"]) is dict
            and len(value["baselinePackets"]) == 263
            and NEW_PACKET not in value["baselinePackets"]
            and type(value["changedFiles"]) is dict
            and type(value["newFiles"]) is dict
            and _sha(value["packetSha256"])
            and _sha(value["validatorNormalizedSha256"]),
            "accepted 263-packet base")
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
    # An exact 263-era byte string is already older than the successor layer.
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


# MET-LINUX-009 (roadmap LINUX-ROOT-ALIASES; the lane monitor's owner-delegated rulings, among them MON-RA2-NEXT,
# MON-RA-SERIES, MON-RA-R1-KEEP, MON-RA-R2-KEEP, MON-RA-ORACLE-KEEP and MON-RA-SLOT-264) publishes the signed root-alias
# contract for the native runner kit, adopted as candidate c3 after the in-tree CONTRACT rounds 1 and 2 of the
# MET-LINUX-009/contract series: the kit files ci/linux-runner/common.py, launcher.py and prepare.py, the two
# docs/linux-runner/ documents, the vectors tests/linux_runner/test_root_aliases.py, the D5a oracle
# tests/test_met_linux_009_oracle.py with its oracle identity, and the adoption records under architecture/linux-root-aliases/
# (status.json and the two rounds' records with their identities), with the registry rider: briefs.json gains this
# packet's PACKET and CONTRACT series. It is gate material (GATE_CI, GATE_VERIFIER_DOCS and GATE_REVIEW_PROCESS): the
# owner approves the merge per PR, bound to the head. Repository bytes are read only through reviewed_bytes, so a later
# bridged successor projects its own edits away first; a path outside this era is refused before it is read, every era
# file is bound by digest on every read, and no directory is listed. Each refusal is a pure check over the values read,
# so every one has a failing case on plain data. Checked here: the status (status.json in its own schema: ADOPTED for
# MET-LINUX-009 at slot 264 on this era's base, with the allowed-paths derivation passing at this base); the adopted
# subject (exactly its nine files, each digest equal to this era's bytes of its path); the reviews (each round's record
# and identity named by path and equal to their digests); and the registry (exactly one MET-LINUX-009/packet and one
# MET-LINUX-009/contract entry, each pointing at its generic brief with the sha256 of that brief's bytes). No chain
# validator or chain test is pinned here. Last, this layer's own inverse hunks are the canonical byte-minimal ones,
# recomputed from its era's bytes (MET-PERF-040's carried rule).
CONTRACT_DIR = "architecture/linux-root-aliases/"
STATUS_PATH = CONTRACT_DIR + "status.json"
STATUS_SCHEMA = "planeon.internal.linux-root-aliases-status/v1"
STATUS = "ADOPTED"
SLOT = 264
REGISTRY_PATH = "architecture/review-record/briefs.json"
PACKET_BRIEF = "architecture/review-briefs/REVIEW_BRIEF_PACKET.md"
CONTRACT_BRIEF = "architecture/review-briefs/REVIEW_BRIEF_CONTRACT.md"
# The adopted subject as status.json binds it: non-chain files, each pinned by its bytes.
SUBJECT_PATHS = ("ci/linux-runner/common.py",
                 "ci/linux-runner/launcher.py",
                 "ci/linux-runner/prepare.py",
                 "docs/linux-runner/BUILD_INPUTS.md",
                 "docs/linux-runner/OPERATOR.md",
                 "tests/linux_runner/test_root_aliases.py",
                 "tests/test_met_linux_009_oracle.py",
                 "architecture/linux-root-aliases/oracle-identity.json",
                 "architecture/review-record/briefs.json")
# The two CONTRACT rounds as status.json binds them: each round's record and identity by path.
ROUNDS = (1, 2)
REVIEW_RECORDS = tuple(CONTRACT_DIR + "review-round%d.json" % n for n in ROUNDS)
REVIEW_IDENTITIES = tuple(CONTRACT_DIR + "review-identity-round%d.json" % n for n in ROUNDS)
# The registry rider: this packet's two series, each pinning its generic brief (PACKET first, as the rider adds them).
REGISTRY_ENTRIES = (("PACKET", NEW_PACKET + "/packet", PACKET_BRIEF), ("CONTRACT", NEW_PACKET + "/contract", CONTRACT_BRIEF))
# Every file this era's check reads, with its digest: the status, the adopted subject, the rounds' records and
# identities, and the two generic briefs.
ERA_SHA256 = MappingProxyType({
    "architecture/linux-root-aliases/oracle-identity.json": "bb77851269a730c922c614eaab0bb32c2ae27f4fd14884189892d56c3adccb00",
    "architecture/linux-root-aliases/review-identity-round1.json": "44ae105ef54033384df151e59e7e12917191156fbc3f411d423864b428843639",
    "architecture/linux-root-aliases/review-identity-round2.json": "5d9425c5f35d8df7dc213ce17dda9988b75948bd5fd41bd9d3adfc4a104870fb",
    "architecture/linux-root-aliases/review-round1.json": "4abfb43fe075469076a2e36d10619c4a37b74e8f918f1c0a3348955a12b1b9df",
    "architecture/linux-root-aliases/review-round2.json": "f09b270ac2371e9b4e2514002af448917c11341ff4fcf2b82af4802e375241ed",
    "architecture/linux-root-aliases/status.json": "c0cde8a8c7ba45731c7db34086038bbe83f777835d37328ad9387f57d259fc1f",
    "architecture/review-briefs/REVIEW_BRIEF_CONTRACT.md": "1f09d23451bf265e32e44742ca362dabf5a1090c2208c1349cbf491670798aec",
    "architecture/review-briefs/REVIEW_BRIEF_PACKET.md": "6dcff68d7e6b01823f1740063e94910edcc159a71a6ee803f1b66c62fd06e274",
    "architecture/review-record/briefs.json": "b3681815203c426db5ceabbd52b49ba281be21c2df017b865181848a0e8ad8db",
    "ci/linux-runner/common.py": "a1c3eb5bc0677b314aced135ca59df20d7d163982d408ae202d17ee56453a616",
    "ci/linux-runner/launcher.py": "8055194a640ddadc9997fdd36bb8e82f3c229b844f955832eca1b16ffa97c2a3",
    "ci/linux-runner/prepare.py": "e5c6e9f4292da6db2dfc1d09dc03f25f65df7eb0cbaab1b54c064aa0983433ad",
    "docs/linux-runner/BUILD_INPUTS.md": "5f5344dd42ab271a5e09b17f41a37172706a42e8f703d4d34106f48e2f4daccc",
    "docs/linux-runner/OPERATOR.md": "30a59f557ea1a3129fe0d11f86801ed282cffba3f580359b550a8335924fec28",
    "tests/linux_runner/test_root_aliases.py": "a984cc2f9f8d11e87e219a5f6bfa2693bcea489b651dc7587c7d78520376e174",
    "tests/test_met_linux_009_oracle.py": "72af8f4f2e695b9f96a6a3b2984f6fef4969ab5d7ec5db570107272303c3b2a4",
})


def reviewed_bytes(path: str) -> bytes:
    """This packet's reviewed bytes of path; a bridged successor projects newer bytes back first."""
    return successor.historical_bytes(path, regular_bytes(path))


def _era_bytes(path: Any, raw: Any) -> bytes:
    """An era file's bytes, checked against its era digest; a path outside the era is refused."""
    expected = ERA_SHA256.get(path) if type(path) is str else None
    require(expected is not None, "MET-LINUX-009 reviewed bytes are bound: " + str(path))
    require(type(raw) is bytes and digest(raw) == expected, "unreviewed LINUX-ROOT-ALIASES source: " + path)
    return raw


def _verified(path: str) -> bytes:
    """reviewed_bytes, checked against its era digest on every read; a path outside the era is refused before it is
    read."""
    require(type(path) is str and path in ERA_SHA256, "MET-LINUX-009 reviewed bytes are bound: " + str(path))
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
    """status.json in its own schema: LINUX-ROOT-ALIASES ADOPTED for MET-LINUX-009 at slot 264 on this era's base, with
    the allowed-paths derivation passing at this base, an adopted-subject mapping and a reviews list."""
    _bound(lambda: type(status) is dict and status["schemaVersion"] == STATUS_SCHEMA and status["packet"] == NEW_PACKET
           and type(status["slot"]) is int and status["slot"] == SLOT and status["status"] == STATUS
           and status["baseMain"] == BASE_COMMIT and type(status["allowedPathsDerivation"]) is dict
           and status["allowedPathsDerivation"]["pass"] is True
           and status["allowedPathsDerivation"]["atBase"] == BASE_COMMIT
           and type(status["adoptedSubject"]) is dict and type(status["reviews"]) is list,
           "adopted LINUX-ROOT-ALIASES status: MET-LINUX-009 at slot 264 with a passing derivation")


def check_subject(subject: Any, files: Any) -> None:
    """The adopted subject names exactly its nine files, and each digest equals this era's bytes of its path."""
    _bound(lambda: type(subject) is dict and sorted(subject) == sorted(SUBJECT_PATHS)
           and len(subject) == len(SUBJECT_PATHS) and type(files) is dict and sorted(files) == sorted(SUBJECT_PATHS),
           "the adopted subject names exactly its nine files")
    for path in SUBJECT_PATHS:
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


def validate_status() -> None:
    """status.json, the adopted subject's bytes and every round's record and identity, each read through the era."""
    status = _json(STATUS_PATH)
    check_status(status)
    check_subject(status["adoptedSubject"], {path: _verified(path) for path in SUBJECT_PATHS})
    check_reviews(status["reviews"], {path: _verified(path) for path in REVIEW_RECORDS + REVIEW_IDENTITIES})


def check_registry(raw: Any, packet_brief_raw: Any, contract_brief_raw: Any) -> None:
    """The registry holds exactly two series of this packet, its PACKET and CONTRACT series, each pointing at its generic
    brief with the sha256 of the brief's bytes."""
    _bound(lambda: type(raw) is bytes and type(packet_brief_raw) is bytes and type(contract_brief_raw) is bytes
           and [(entry["kind"], entry["series"], entry["path"], entry["sha256"], entry["version"])
                for entry in parse(raw)["briefs"] if entry["series"].startswith(NEW_PACKET + "/")]
           == [REGISTRY_ENTRIES[0] + (digest(packet_brief_raw), 1), REGISTRY_ENTRIES[1] + (digest(contract_brief_raw), 1)],
           "the registry holds exactly this packet's PACKET and CONTRACT series, each pinning its generic brief")


def validate_registry() -> None:
    """briefs.json with this packet's rider, and the two generic briefs."""
    check_registry(_verified(REGISTRY_PATH), _verified(PACKET_BRIEF), _verified(CONTRACT_BRIEF))


def validate_met_linux_009() -> None:
    """Every reviewed byte first; then the status, the adopted subject and the reviews, and the registry; last, this
    layer's canonical hunks."""
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
            == record["validatorNormalizedSha256"], "linux root aliases validator drift")
    paths = sorted((ROOT / "task-packets").glob("*.yaml"))
    old = set(record["baselinePackets"])
    require(len(paths) == 268
            and {path.stem for path in paths} == old | {NEW_PACKET, successor.NEW_PACKET, successor.successor.NEW_PACKET, successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.NEW_PACKET},
            "closed 268-packet catalog retaining the 264-packet checkpoint")
    packets = {}
    for path in paths:
        if path.stem in (successor.NEW_PACKET, successor.successor.NEW_PACKET, successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.NEW_PACKET):
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
            "closed source-only linux-root-aliases packet and inherited commands")
    require(len(packet["allowedPaths"]) == len(set(packet["allowedPaths"]))
            and set(packet["allowedPaths"]) == set(record["changedFiles"])
            | set(record["newFiles"]) | {AUTHORITY_PATH, VALIDATOR_PATH,
                                         "task-packets/" + NEW_PACKET + ".yaml"},
            "unreviewed or omitted linux-root-aliases packet path")
    for path, rule in record["changedFiles"].items():
        current = successor.historical_bytes(path, regular_bytes(path))
        require(digest(current) == rule["afterSha256"]
                and digest(historical_bytes(path, current)) == rule["beforeSha256"],
                "unreviewed current source: " + path)
    for path, expected in record["newFiles"].items():
        require(digest(successor.historical_bytes(path, regular_bytes(path))) == expected,
                "new source drift: " + path)
    validate_met_linux_009()


if __name__ == "__main__":
    validate()
    print("Linux root aliases valid: 268 current specifications; 264-packet checkpoint and exact 263-packet predecessor; contract reviewed.")
