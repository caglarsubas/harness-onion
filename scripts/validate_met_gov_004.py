#!/usr/bin/env python3
"""Validate the MET-GOV-004 language-placement ADR (LANG-PLACEMENT-ADR-001): ADR 0010, its data and its checker with the D5a oracle (the adopted files pinned by their bytes, the data's LANG-D2 (a) policy digest, the oracle identity bound to the oracle test's bytes, and the registry's MET-GOV-004/packet rider), and the exact 267-to-266 projection."""
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
    import validate_met_adopt_005 as successor
except ImportError:
    from scripts.safe_yaml import safe_load
    from scripts import validate_met_adopt_005 as successor


ROOT = Path(__file__).resolve().parents[1]
AUTHORITY_PATH = "architecture/met-gov-004-authority.json"
AUTHORITY_SHA256 = "31dd409b130844a008e3da19dae7fcece70dfec5a191a740569e5929e2c55cff"
VALIDATOR_PATH = "scripts/validate_met_gov_004.py"
BASE_COMMIT = "9184f5b636e6226c1b9040b54b90508966ca001b"
NEW_PACKET = "MET-GOV-004"
PREVIOUS_PACKET = "MET-LINUX-008"
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
            require(key not in result, "duplicate language-placement authority member")
            result[key] = value
        return result

    def no_constant(_value: str) -> Any:
        raise ValueError("nonfinite language-placement authority number")

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
        require(digest(raw) == AUTHORITY_SHA256, "language placement history authority digest")
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
    }, "closed language placement history authority")
    require(value["schemaVersion"] == "harness.planeon.ai/met-gov-004-authority/v1"
            and value["authorityPacket"] == NEW_PACKET
            and value["acceptedBase"] == BASE_COMMIT
            and type(value["baselinePackets"]) is dict
            and len(value["baselinePackets"]) == 266
            and NEW_PACKET not in value["baselinePackets"]
            and type(value["changedFiles"]) is dict
            and type(value["newFiles"]) is dict
            and _sha(value["packetSha256"])
            and _sha(value["validatorNormalizedSha256"]),
            "accepted 266-packet base")
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
    # An exact 266-era byte string is already older than the successor layer.
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


# MET-GOV-004 (roadmap LANG-PLACEMENT-ADR-001; the owner's language policy LANG-D2 (a) and the lane monitor's
# owner-delegated rulings, among them MON-GOV4-C1 and MON-GOV4-ADOPTED) publishes the language-placement ADR 0010
# and its data: docs/adr/0010-language-placement.md (the policy as one digest-bound line, and the four tables
# rendered from the data), architecture/language-placement.json (the planned language of every catalogued repository
# and deployable, the rows outside the catalogue and the pending exceptions, each bound to its source spans), the
# checker scripts/language_placement.py with its tests tests/test_language_placement.py, and the D5a oracle
# tests/test_language_placement_oracle.py with its identity architecture/oracle-identity-language-placement.json.
# The ADR is cited by one line in docs/DEVELOPMENT_STATUS.md, pinned with the adopted files.
# Its review series is registered by this packet's own rider in architecture/review-record/briefs.json (the
# MET-GOV-004/packet entry, which the evolution surface record at this base classes as gate material, so the owner
# approves the PR). Repository bytes are read only through reviewed_bytes, so a later bridged successor projects its own
# edits away first; a path outside this era is refused before it is read, every era file is bound by digest on every
# read, and no directory is listed. Each refusal is a pure check over the values read, so every one has a failing case
# on plain data. Checked here: the adopted files (exactly its seven files, each equal to the sha256 pinned below
# for its adopted bytes); the data's policy pin (language-placement.json in its own schema, naming the ADR, with
# policySha256 equal to the LANG-D2 (a) digest); the oracle (its identity names the oracle test, and its file.sha256
# equals the oracle test's bytes); and the registry (exactly one MET-GOV-004 entry, its PACKET series, pointing at the
# generic packet brief with the sha256 of that brief's bytes). No chain validator or chain test is pinned here. Last,
# this layer's own inverse hunks are the canonical byte-minimal ones, recomputed from its era's bytes (MET-PERF-040's
# carried rule).
ADR_PATH = "docs/adr/0010-language-placement.md"
DATA_PATH = "architecture/language-placement.json"
DATA_SCHEMA = "planeon.internal.language-placement/v1"
CHECKER_PATH = "scripts/language_placement.py"
CHECKER_TEST = "tests/test_language_placement.py"
ORACLE_TEST = "tests/test_language_placement_oracle.py"
ORACLE_IDENTITY = "architecture/oracle-identity-language-placement.json"
ORACLE_SCHEMA = "planeon.oracle-identity/v1"
REGISTRY_PATH = "architecture/review-record/briefs.json"
PACKET_BRIEF = "architecture/review-briefs/REVIEW_BRIEF_PACKET.md"
# The owner's language policy LANG-D2 (a): the sha256 of its UTF-8 text, as the decision and the roadmap item record it.
POLICY_SHA256 = "4b0a8a4b9e043823cfa884bdb883ae5b8f796877ead7bdbc413b318082fbc441"
# The adopted files: non-chain files, each pinned below by the sha256 of its adopted bytes.
ADOPTED_PATHS = (ADR_PATH, DATA_PATH, CHECKER_PATH, CHECKER_TEST, ORACLE_TEST, ORACLE_IDENTITY,
                 "docs/DEVELOPMENT_STATUS.md")
# The registry: this packet's one series, pinning the generic packet brief.
REGISTRY_ENTRY = ("PACKET", NEW_PACKET + "/packet", PACKET_BRIEF)
# Every file this era's check reads, with its digest: the adopted files, the registry and the generic packet brief.
ERA_SHA256 = MappingProxyType({
    "architecture/language-placement.json": "ec6df386eddd9e14c1d0ba8f838602588ff92b61f81f81047f19feda5654e815",
    "architecture/oracle-identity-language-placement.json": "65350c9e0a400779d298e662ef06b37e1230afd2074ab5b1fbfd06b327dae916",
    "architecture/review-briefs/REVIEW_BRIEF_PACKET.md": "6dcff68d7e6b01823f1740063e94910edcc159a71a6ee803f1b66c62fd06e274",
    "architecture/review-record/briefs.json": "fe2b8b225f029deb5aec407b4ae1b99ff632a2cb80983185deb2d8d9ded9f5d3",
    "docs/DEVELOPMENT_STATUS.md": "3cd2630bc525a81098a92f9c43c5695de5803df76002415174d54e61bff14684",
    "docs/adr/0010-language-placement.md": "42bce8d3ef7174fc0d69ac48b51391021a6feebdab0a936ccb2a36b97ae913d2",
    "scripts/language_placement.py": "10e13ea2b9d9468b1cdbc83a24fb0040d5b05f8e14fc4815c4b261a69cb9f93f",
    "tests/test_language_placement.py": "02c36d838729b96a9beec358cf3b8bfc4811fcc160468101ace94010a4c98239",
    "tests/test_language_placement_oracle.py": "4fa51e886cca2e814a822430428df5f287c838ecdfb00d8a3942149c5dc5d6c6",
})


def reviewed_bytes(path: str) -> bytes:
    """This packet's reviewed bytes of path; a bridged successor projects newer bytes back first."""
    return successor.historical_bytes(path, regular_bytes(path))


def _era_bytes(path: Any, raw: Any) -> bytes:
    """An era file's bytes, checked against its era digest; a path outside the era is refused."""
    expected = ERA_SHA256.get(path) if type(path) is str else None
    require(expected is not None, "MET-GOV-004 reviewed bytes are bound: " + str(path))
    require(type(raw) is bytes and digest(raw) == expected, "unreviewed LANG-PLACEMENT source: " + path)
    return raw


def _verified(path: str) -> bytes:
    """reviewed_bytes, checked against its era digest on every read; a path outside the era is refused before it is
    read."""
    require(type(path) is str and path in ERA_SHA256, "MET-GOV-004 reviewed bytes are bound: " + str(path))
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


def check_adopted(files: Any) -> None:
    """The adopted files are exactly the packet's seven, and each one's bytes equal the sha256 pinned for it."""
    _bound(lambda: type(files) is dict and sorted(files) == sorted(ADOPTED_PATHS) and len(files) == len(ADOPTED_PATHS),
           "the adopted files are exactly the packet's seven")
    for path in ADOPTED_PATHS:
        _bound(lambda: type(files[path]) is bytes and digest(files[path]) == ERA_SHA256[path],
               "an adopted file's bytes equal its pinned digest: " + path)


def check_policy(raw: Any) -> None:
    """language-placement.json in its own schema names the ADR and pins the LANG-D2 (a) policy digest."""
    data = _parsed(raw)
    _bound(lambda: type(data) is dict and data["schemaVersion"] == DATA_SCHEMA and data["adr"] == ADR_PATH
           and type(data["policySha256"]) is str and data["policySha256"] == POLICY_SHA256,
           "the language-placement data names the ADR and pins the LANG-D2 (a) policy digest")


def check_oracle(identity_raw: Any, oracle_raw: Any) -> None:
    """The oracle identity names the D5a oracle test, and its file.sha256 equals the oracle test's bytes."""
    identity = _parsed(identity_raw)
    _bound(lambda: type(identity) is dict and identity["schemaVersion"] == ORACLE_SCHEMA
           and type(identity["file"]) is dict and identity["file"]["path"] == ORACLE_TEST,
           "the oracle identity names the oracle test")
    _bound(lambda: _sha(identity["file"]["sha256"]) and type(oracle_raw) is bytes
           and identity["file"]["sha256"] == digest(oracle_raw),
           "the oracle identity's sha256 equals the oracle test's bytes")


def validate_adopted() -> None:
    """The adopted files, the data's policy pin and the oracle identity, each read through the era."""
    files = {path: _verified(path) for path in ADOPTED_PATHS}
    check_adopted(files)
    check_policy(files[DATA_PATH])
    check_oracle(files[ORACLE_IDENTITY], files[ORACLE_TEST])


def check_registry(raw: Any, packet_brief_raw: Any) -> None:
    """The registry holds exactly one series of this packet, its PACKET series, pointing at the generic packet brief
    with the sha256 of the brief's bytes."""
    _bound(lambda: type(raw) is bytes and type(packet_brief_raw) is bytes
           and [(entry["kind"], entry["series"], entry["path"], entry["sha256"], entry["version"])
                for entry in parse(raw)["briefs"] if entry["series"].startswith(NEW_PACKET + "/")]
           == [REGISTRY_ENTRY + (digest(packet_brief_raw), 1)],
           "the registry holds exactly this packet's PACKET series, pinning the generic packet brief")


def validate_registry() -> None:
    """briefs.json with this packet's one series, and the generic packet brief."""
    check_registry(_verified(REGISTRY_PATH), _verified(PACKET_BRIEF))


def validate_met_gov_004() -> None:
    """Every reviewed byte first; then the adopted files, the policy pin and the oracle, and the registry; last, this
    layer's canonical hunks."""
    for path in ERA_SHA256:
        _verified(path)
    validate_adopted()
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
            == record["validatorNormalizedSha256"], "language placement validator drift")
    paths = sorted((ROOT / "task-packets").glob("*.yaml"))
    old = set(record["baselinePackets"])
    require(len(paths) == 275
            and {path.stem for path in paths} == old | {NEW_PACKET, successor.NEW_PACKET, successor.successor.NEW_PACKET, successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.successor.NEW_PACKET, *successor.successor.successor.successor.successor.successor.successor.PRODUCT_PACKETS},
            "closed 275-packet catalog retaining the 267-packet checkpoint")
    packets = {}
    for path in paths:
        if path.stem in (successor.NEW_PACKET, successor.successor.NEW_PACKET, successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.successor.NEW_PACKET, *successor.successor.successor.successor.successor.successor.successor.PRODUCT_PACKETS):
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
            "closed source-only language-placement packet and inherited commands")
    require(len(packet["allowedPaths"]) == len(set(packet["allowedPaths"]))
            and set(packet["allowedPaths"]) == set(record["changedFiles"])
            | set(record["newFiles"]) | {AUTHORITY_PATH, VALIDATOR_PATH,
                                         "task-packets/" + NEW_PACKET + ".yaml"},
            "unreviewed or omitted language-placement packet path")
    for path, rule in record["changedFiles"].items():
        current = successor.historical_bytes(path, regular_bytes(path))
        require(digest(current) == rule["afterSha256"]
                and digest(historical_bytes(path, current)) == rule["beforeSha256"],
                "unreviewed current source: " + path)
    for path, expected in record["newFiles"].items():
        require(digest(successor.historical_bytes(path, regular_bytes(path))) == expected,
                "new source drift: " + path)
    validate_met_gov_004()


if __name__ == "__main__":
    validate()
    print("Language placement valid: 275 current specifications; 267-packet checkpoint and exact 266-packet predecessor; contract reviewed.")
