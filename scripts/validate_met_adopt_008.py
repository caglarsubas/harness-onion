#!/usr/bin/env python3
"""Validate MET-ADOPT-008 (AUTHORITY-MAP-001-F, issue #237): a down usage ledger refuses every mutation of an existing reservation, an exact commit replay included (K = 0; V1: this packet's files by digest; A1-A5: the fix and VB-11; V4: the registry rider; V6: the hunk-class record)."""
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
    import validate_met_perf_049 as successor
except ImportError:
    from scripts.safe_yaml import safe_load
    from scripts import validate_met_perf_049 as successor


ROOT = Path(__file__).resolve().parents[1]
AUTHORITY_PATH = "architecture/authority-map-f-authority.json"
AUTHORITY_SHA256 = "e1bdcbf9750e8168829c18b63087f316d098526c4da87bc62cabf665d209dd4b"
VALIDATOR_PATH = "scripts/validate_met_adopt_008.py"
BASE_COMMIT = "98d1f6f1f87bf988d2b12c97132d66b8cf5f351c"
NEW_PACKET = "MET-ADOPT-008"
PREVIOUS_PACKET = "MET-REGISTRY-001"
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
            require(key not in result, "duplicate authority-map-f authority member")
            result[key] = value
        return result

    def no_constant(_value: str) -> Any:
        raise ValueError("nonfinite authority-map-f authority number")

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
        require(digest(raw) == AUTHORITY_SHA256, "authority map fix history authority digest")
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
    }, "closed authority map fix history authority")
    require(value["schemaVersion"] == "harness.planeon.ai/authority-map-f-authority/v1"
            and value["authorityPacket"] == NEW_PACKET
            and value["acceptedBase"] == BASE_COMMIT
            and type(value["baselinePackets"]) is dict
            and len(value["baselinePackets"]) == 295
            and NEW_PACKET not in value["baselinePackets"]
            and type(value["changedFiles"]) is dict
            and type(value["newFiles"]) is dict
            and _sha(value["packetSha256"])
            and _sha(value["validatorNormalizedSha256"]),
            "accepted 295-packet base")
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
    # An exact 295-era byte string is already older than the successor layer.
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


# MET-ADOPT-008 (AUTHORITY-MAP-001-F, issue #237; the lane monitor's rulings MON-285-PLAN, MON-285-Q-RELAY,
# MON-285-CR1-RULE, MON-285-RULE-RELAY and MON-285-E1): the semantic block. This packet's files are c1's
# (CONTRACT_285 section 3), bound by digest in the era with the registry, the packet brief and the reader (V1);
# the fix holds (A1-A5); the registry differs from the base by this packet's one rider (V4); the authority's
# hunk-class record is re-checked by the reader's class rule (V6).
PACKET_FILES = ('scripts/authority_map.py', 'architecture/authority-map/budget-vectors.json', 'architecture/authority-map.json', 'architecture/authority-map/README.md', 'tests/test_authority_map.py')
HUNK_RECORD_PATH = "architecture/chain-checkpoint/hunk-classes/285.json"
REGISTRY_BASE_SHA256 = "c38f16aaf617f5305ef675510a38c9c11b7c93ddf7d965ae93e8d48a1e966ec7"
HUNK_CONTEXT = MappingProxyType({"newPacket": NEW_PACKET, "prevValidator": "scripts/validate_met_registry_001.py",
                                 "prevTest": "tests/test_met_registry_001.py", "steps": (1, 1)})
ERA_SHA256 = MappingProxyType({
    "architecture/authority-map.json": "1a5de06452d7133d90520b4b89670b2b0486e341fb2e20f2bf46a6ea86462440",
    "architecture/authority-map/README.md": "c089e9816c3a30b36f64176942aa0e383dca0898b6529d360aa63e68cb89aea7",
    "architecture/authority-map/budget-vectors.json": "4c57bb1bbe752486020225919b6d5cffc071be458e90f98ed61f6f1706bdf58c",
    "architecture/review-briefs/REVIEW_BRIEF_PACKET.md": "6dcff68d7e6b01823f1740063e94910edcc159a71a6ee803f1b66c62fd06e274",
    "architecture/review-record/briefs.json": "98c1358e6a4a21c4e09a6abad4aed8da9ea3d2d24c4412eef288e12ed772c1aa",
    "ci/chain_checkpoint.py": "b66d601e387c181d627d2e210fe5db40bf6ae3ec2e12f1369b0215d9a57b046b",
    "scripts/authority_map.py": "a96dd56c90f8db5ed7d8721eb3f76269ddf665f90fb1dd767dbfc06003191629",
    "tests/test_authority_map.py": "7679916581fa527e1522b2b50a696debab1d544d64ed989b7598d5ff886419e7",
})
REGISTRY_PATH = "architecture/review-record/briefs.json"
PACKET_BRIEF = "architecture/review-briefs/REVIEW_BRIEF_PACKET.md"
READER_PATH = "ci/chain_checkpoint.py"
READER_NAME = "_met_adopt_008_chain_checkpoint"
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
    require(expected is not None, "MET-ADOPT-008 reviewed bytes are bound: " + str(path))
    require(type(raw) is bytes and digest(raw) == expected, "unreviewed MET-ADOPT-008 source: " + path)
    return raw


def _verified(path: str) -> bytes:
    """reviewed_bytes, checked against its era digest on every read; a path outside the era is refused before it is
    read."""
    require(type(path) is str and path in ERA_SHA256, "MET-ADOPT-008 reviewed bytes are bound: " + str(path))
    return _era_bytes(path, reviewed_bytes(path))


def _bound_read(path: str, expected: Any) -> bytes:
    """reviewed_bytes of a file named by an era-verified record, checked against the digest that record gives it."""
    require(type(path) is str and _sha(expected), "MET-ADOPT-008 bound read: " + str(path))
    _path(path)
    raw = reviewed_bytes(path)
    require(type(raw) is bytes and digest(raw) == expected, "MET-ADOPT-008 bound file drift: " + path)
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
           "the registry differs from the base by exactly the MET-ADOPT-008 packet rider, pinning the generic packet "
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


# A1-A5, the fix (CONTRACT_285 sections 3 and 6), read from the era-bound bytes; A5 runs the era's own model.
MODEL_PATH, VECTORS_PATH, MAP_PATH = "scripts/authority_map.py", "architecture/authority-map/budget-vectors.json", \
    "architecture/authority-map.json"
MODEL_NAME = "authority_map_met_adopt_008"
GUARD = (b'        if not self.up and op in ("reserve", "consume", "commit", "cancel", "expire"):\n'
         b'            return "refused"  # AM-02 (FIN:177): a down ledger refuses every mutation, an exact commit replay too\n'
         b'        key = s["key"]\n'
         b'        if op == "reserve":\n'
         b'            prior = self.res.get(key)\n')
ADVISORY = (b'        if op == "advisory":  # :177: advisory-only callers proceed only if the profile allows and outbox '
            b'capacity exists\n'
            b'            return "proceeds" if (not self.up and s["profileAllows"] is True and s["outboxCapacity"] is True) \\\n'
            b'                or self.up else "refused"\n')
STATE_FORM = (b'    return _canonical([ledger.committed, ledger.res, sorted([list(k), v] for k, v in '
              b'ledger.transitions.items())])\n')
INVARIANT = (b'            before = _ledger_state(ledger)\n'
             b'            got.append(ledger.step(s))\n'
             b'            require(got[-1] != "refused" or _ledger_state(ledger) == before, "AM_BUDGET",\n'
             b'                    "%s: a refused step changes no state" % v["id"])\n')
VECTORS_PREFIX = MappingProxyType({"length": 5776, "sha256": "d28850fdd4407c283b01a748ef044d5a94b0ccb9fb7e92814df4dbe1b37e4a8f"})
VECTORS_SUFFIX = MappingProxyType({"length": 332, "sha256": "157784fd5a21466a18190d0e35e50fa83854daaf9e0104093f1e98d242a4c65d"})
VB11 = {"id": "VB-11", "name": "ledger loss with an open reservation", "root": 1000, "steps": [{"op": "reserve", "key": "k1", "amount": 100}, {"op": "commit", "key": "k1", "transition": "t1", "amount": 40}, {"op": "reserve", "key": "k2", "amount": 100}, {"op": "consume", "key": "k2", "amount": 20}, {"op": "ledger_down"}, {"op": "reserve", "key": "k3", "amount": 10}, {"op": "consume", "key": "k2", "amount": 10}, {"op": "commit", "key": "k2", "transition": "t2", "amount": 40}, {"op": "cancel", "key": "k2"}, {"op": "expire", "key": "k2"}, {"op": "commit", "key": "k1", "transition": "t1", "amount": 40}], "results": ["reserved", "committed", "reserved", "consumed", "down", "refused", "refused", "refused", "refused", "refused", "refused"], "final": {"k1": {"state": "COMMITTED", "committed": 40, "returned": 60}, "k2": {"state": "RESERVED", "committed": 0, "returned": 0}}}


def check_fix(raws: Any, budget: Any) -> None:
    """A1-A5 on plain data: raws maps each era path to its bytes; budget is the era model's vector replay."""
    model, vectors = raws[MODEL_PATH], raws[VECTORS_PATH]
    _bound(lambda: model.count(GUARD) == 1 and model.count(b"            if not self.up:\n") == 0
           and model.count(ADVISORY) == 1 and model.index(ADVISORY) < model.index(GUARD),
           "MET-ADOPT-008 A1 the down-ledger guard")
    _bound(lambda: model.count(STATE_FORM) == 1 and model.count(INVARIANT) == 1
           and model.count(b'["VB-%02d" % k for k in range(1, 12)]') == 1
           and model.count(b'"vectors are VB-01 to VB-11")') == 1 and model.count(b'"budgetVectors": 11,') == 1,
           "MET-ADOPT-008 A2 the vectors and the refused-step invariant")
    _bound(lambda: len(vectors) > VECTORS_PREFIX["length"] + VECTORS_SUFFIX["length"]
           and digest(vectors[:VECTORS_PREFIX["length"]]) == VECTORS_PREFIX["sha256"]
           and digest(vectors[len(vectors) - VECTORS_SUFFIX["length"]:]) == VECTORS_SUFFIX["sha256"]
           and json.loads(vectors)["vectors"][10:] == [VB11],
           "MET-ADOPT-008 A3 VB-11 and the base vectors")
    _bound(lambda: [row["sha256"] for row in json.loads(raws[MAP_PATH])["vectorFiles"]
                    if row["path"] == VECTORS_PATH] == [digest(vectors)],
           "MET-ADOPT-008 A4 the map's vectors digest")
    _bound(lambda: budget(vectors) is None, "MET-ADOPT-008 A5 the model replays every vector")


def _replay(model: Any, packets: Any) -> Any:
    """A5: the era model's own check over the head's bytes and the catalog's ids replays every budget vector (with F2's
    invariant) and counts 11; None when it does."""
    result = model.check(regular_bytes, frozenset(packets))
    return None if result["budgetVectors"] == 11 else result


def validate_fix(packets: Any) -> None:
    model = _era_model(MODEL_PATH, MODEL_NAME)
    check_fix({path: _verified(path) for path in (MODEL_PATH, VECTORS_PATH, MAP_PATH)}, lambda raw: _replay(model, packets))


def validate_met_adopt_008(packets: dict[str, Any]) -> None:
    """V1, every era file first; then A1-A5 (the fix), V4 (the registry) and V6 (the hunk-class record); last,
    this layer's canonical hunks."""
    for path in ERA_SHA256:
        _verified(path)
    validate_fix(packets)
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
            == record["validatorNormalizedSha256"], "authority map fix validator drift")
    paths = sorted((ROOT / "task-packets").glob("*.yaml"))
    old = set(record["baselinePackets"])
    require(len(paths) == 297
            and {path.stem for path in paths} == old | {NEW_PACKET, successor.NEW_PACKET},
            "closed 297-packet catalog retaining the 296-packet checkpoint")
    packets = {}
    for path in paths:
        if path.stem == successor.NEW_PACKET:
            continue
        raw = regular_bytes("task-packets/" + path.name)
        expected = (record["packetSha256"] if path.stem == NEW_PACKET
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
            "closed source-only authority-map-f packet and inherited commands")
    require(len(packet["allowedPaths"]) == len(set(packet["allowedPaths"]))
            and set(packet["allowedPaths"]) == set(record["changedFiles"])
            | set(record["newFiles"]) | {AUTHORITY_PATH, VALIDATOR_PATH,
                                         "task-packets/" + NEW_PACKET + ".yaml"},
            "unreviewed or omitted authority-map-f packet path")
    for path, rule in record["changedFiles"].items():
        current = successor.historical_bytes(path, regular_bytes(path))
        require(digest(current) == rule["afterSha256"]
                and digest(historical_bytes(path, current)) == rule["beforeSha256"],
                "unreviewed current source: " + path)
    for path, expected in record["newFiles"].items():
        require(digest(successor.historical_bytes(path, regular_bytes(path))) == expected,
                "new source drift: " + path)
    validate_met_adopt_008(packets)


if __name__ == "__main__":
    validate()
    print("Authority map fix valid: 297 current specifications at slot 285; 296-packet checkpoint and exact 295-packet predecessor; contract reviewed.")
