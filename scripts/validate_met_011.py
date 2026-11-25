#!/usr/bin/env python3
"""Validate MET-011 (CHAIN-COMPACTION-002's third checkpoint, the ledger rewrite at slot 293, K = 0): V1 this packet's files by digest; E3 the authored edits at their named lines; C1 the ledger; C2 its inline reverse hunks; V6a record.json's classes; V4 the registry rider; V6 the hunk-class record under v2.5."""
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
    import validate_met_012 as successor
except ImportError:
    from scripts.safe_yaml import safe_load
    from scripts import validate_met_012 as successor


ROOT = Path(__file__).resolve().parents[1]
AUTHORITY_PATH = "architecture/ledger-rewrite-293-authority.json"
AUTHORITY_SHA256 = "a441f76555ed05905357e12b894b61e21d32cec409db03f83e1cb2fdffe92778"
VALIDATOR_PATH = "scripts/validate_met_011.py"
BASE_COMMIT = "19b176bef5c80f0a1ebcc3fa5aa27d9d7cf56b48"
NEW_PACKET = "MET-011"
PREVIOUS_PACKET = "MET-010"
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
            require(key not in result, "duplicate ledger-rewrite authority member")
            result[key] = value
        return result

    def no_constant(_value: str) -> Any:
        raise ValueError("nonfinite ledger-rewrite authority number")

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
        require(digest(raw) == AUTHORITY_SHA256, "ledger rewrite history authority digest")
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
    }, "closed ledger rewrite history authority")
    require(value["schemaVersion"] == "harness.planeon.ai/ledger-rewrite-authority/v1"
            and value["authorityPacket"] == NEW_PACKET
            and value["acceptedBase"] == BASE_COMMIT
            and type(value["baselinePackets"]) is dict
            and len(value["baselinePackets"]) == 313
            and NEW_PACKET not in value["baselinePackets"]
            and type(value["changedFiles"]) is dict
            and type(value["newFiles"]) is dict
            and _sha(value["packetSha256"])
            and _sha(value["validatorNormalizedSha256"]),
            "accepted 313-packet base")
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
    # An exact 313-era byte string is already older than the successor layer.
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


# MET-011 (CHAIN-COMPACTION-002's third checkpoint; CONTRACT_293 a1eb6910, the rulings of its section 2) records,
# in a K = 0 step, the ledger of chain layers 189-292 over the 313-packet baseline (slot 293), written by a full
# writing run under the owner's head-bound approval, its line-run reverse hunks inline in the authority (back to
# slot 286's record), with the writer's one exclusion line (ledger_hunks=False: three excluded files); the catalog
# check is 286's exact form (rule v4, clause D). Repository bytes are read only through reviewed_bytes; an era
# file is refused unless bound by digest on every read; the ledger is bound by the authority (never an era file),
# a changed file by the authority's afterSha256. Each refusal is a pure check over the values read. Checked here
# (section 5, in this order): V1 the packet's two files by digest; E3 class-other hunks only at the spans the
# counted rule derives (record.json outside by path); C1 the ledger; C2 its inline entry; V6a record.json's
# classes; V4 the registry rider; V6 the hunk-class record under v2.5. Last, this layer's own inverse hunks are
# the canonical ones, record.json's skipped (C2 replays them).
PACKET_FILES = ('architecture/chain-checkpoint/README.md', 'scripts/chain_checkpoint_writer.py')
REGISTRY_BASE_SHA256 = "b78006f11f82d41bec7ae8a7dc3a4b98258626e922d21f7c33fca2122d92e580"
PREVIOUS_CHECKPOINT = (286, "993b4618bf4ad9b6440a3e41bdbeb238cc50455f7f151584cbd6e394277e5084")
CHECK_PAIRS = (
    (('ids', ['CTRL-FIX-004', 'CTRL-INTEGRATE-001']), ('layerSlot', 279), ('pairsPath', 'architecture/dist-005a-ctrl-fix-004-publish-pairs.json'), ('type', 'supersession')),
    (('ids', ['DIST-005', 'DIST-005A']), ('layerSlot', 279), ('pairsPath', 'architecture/dist-005a-ctrl-fix-004-publish-pairs.json'), ('type', 'supersession')),
)
ERA_SHA256 = MappingProxyType({
    "architecture/chain-checkpoint/README.md": "0586f41c2721244f41032ebe1ef3ae9bae1277ba529909160b8eec0981a50214",
    "architecture/review-briefs/REVIEW_BRIEF_PACKET.md": "6dcff68d7e6b01823f1740063e94910edcc159a71a6ee803f1b66c62fd06e274",
    "architecture/review-record/briefs.json": "acb03375f10646c2a432a357d3c2d7ee9b6264263744f63dd8b78480f5a8cc4e",
    "ci/chain_checkpoint.py": "8c8789073698f4e7441b6fda6e7fae8675ad9e8cdd3b30c1a4471809fdc874a0",
    "scripts/chain_checkpoint_writer.py": "9e3226884b818668e972f86e2c0dd7f930bd45abf35481ba45e18a4aa6a36ccf",
})
ERRATA_LINES = MappingProxyType({
    "architecture/chain-checkpoint/README.md": ((251, 281),),
    "architecture/oracle-identity-met-009.json": ((5, 5), (28, 29), (44, 46)),
    "architecture/oracle-identity-met-010.json": ((5, 5), (28, 29), (41, 44)),
    "scripts/chain_checkpoint_writer.py": ((14, 15), (179, 179), (314, 314)),
    "tests/test_ci_performance.py": ((50, 50), (109, 109), (169, 169)),
    "tests/test_credential_lifecycle.py": ((126, 126), (362, 362)),
    "tests/test_met_008.py": ((118, 124), (137, 137), (142, 143), (280, 281), (286, 286), (1130, 1133)),
    "tests/test_met_009.py": ((120, 126), (139, 142), (280, 281), (286, 286), (1130, 1133)),
    "tests/test_met_009_oracle.py": ((127, 134), (636, 638), (642, 644)),
    "tests/test_met_010_oracle.py": ((432, 441),),
    "tests/test_met_perf_049.py": ((134, 134), (143, 144), (1376, 1376)),
    "tests/test_met_perf_050.py": ((119, 125), (138, 138), (142, 143), (281, 282), (287, 287), (1140, 1143)),
})
REGISTRY_PATH = "architecture/review-record/briefs.json"
PACKET_BRIEF = "architecture/review-briefs/REVIEW_BRIEF_PACKET.md"
READER_PATH = "ci/chain_checkpoint.py"
RIDERS = (("PACKET", NEW_PACKET + "/packet", PACKET_BRIEF, 1),)
HUNK_RECORD_MEMBERS = frozenset({"authorityPath", "hunkClassVocabulary", "hunkClassRuleSha256", "hunkClassContext",
                                 "classes", "outcomeStatements"})
HUNK_VOCABULARY = ("bridge", "cascade", "other", "record", "register")     # chainmech v2.5 keeps v2.3's vocabulary
NORMALISED = ("bridge", "cascade", "record", "register")                   # the mechanics forms v2.5 normalises
HUNK_RULE_SHA256 = "106e577175d692a5d627b2b21a0adfab8c4cb9cc4e06d7d45d97be5ef663c778"
CHECKPOINT_DIR = "architecture/chain-checkpoint"
LEDGER_PATH = CHECKPOINT_DIR + "/record.json"
LEDGER_SCHEMA = "harness.planeon.ai/chain-checkpoint/v1"
CHECKPOINT_SLOT, CHECKPOINT_BASELINE = 293, 313
FIRST_LAYER, PREVIOUS_LAYER = (189, "validate_unified_roadmap"), "validate_met_010"
SIZE_CAP = 16_777_216
WORKERS_COUNT = 12
LEDGER_MEMBERS = frozenset({"schemaVersion", "checkpointSlot", "checkpointBaseline", "writingCommit", "writingTree",
                            "parameters", "normalisedRecordClass", "layers", "checkPairs", "fullRunProof", "writingRun",
                            "sizeBound", "sizeBytes", "exclusion"})
RUN_MEMBERS = frozenset({"statedDifferences", "captureEnv", "captureObservesOnly", "outsideReads", "argvRunSummarySha256",
                         "verifyReference"})
EXCLUSION_FILES = ("architecture/chain-checkpoint/hunk-classes/293.json", "architecture/chain-checkpoint/record.json",
                   "architecture/ledger-rewrite-293-authority.json")
PARAMETERS = MappingProxyType({"cadenceSlots": 10, "sampleFraction": 0.1, "fullRunOn": "owner-named slot", "nShadow": 10,
                               "shadowCapSeconds": 15, "workers": WORKERS_COUNT})
SHADOW_IN = ("verify", "dryRunOnly")
STATED = ("direct: argv 63 runs outside ci/run_packet_argv.py, with -p scripts.chain_checkpoint_writer and the capture "
          "variables",
          "serial: the -p option keeps ci/parallel_suite.py's serial loop (one process); the verify runs 12 workers")
CAPTURE_ENV = ("CHAIN_CHECKPOINT_CAPTURE_DIR", "CHAIN_CHECKPOINT_CAPTURE_ROOT")
VERIFY_REFERENCE = "the previous checkpoint: slot %d, record.json sha256 %s" % PREVIOUS_CHECKPOINT
LAYER_MEMBERS = frozenset({"slot", "module", "validatorPath", "validatorSha256", "authorityPath", "authoritySha256",
                           "inputs", "nodes", "seconds"})
TEST_MEMBERS = frozenset({"testFilePath", "testFileSha256"})
ENTRY_KEYS = frozenset({"beforeSha256", "afterSha256", "reverseHunks"})
SLOT = 293
HUNK_RECORD_PATH = "architecture/chain-checkpoint/hunk-classes/293.json"
READER_NAME = "_met_011_chain_checkpoint"
HUNK_CONTEXT = MappingProxyType({"newPacket": NEW_PACKET, "prevValidator": "scripts/validate_met_010.py",
                                 "prevTest": "tests/test_met_010.py", "steps": (1, 1), "countPairs": ()})



def reviewed_bytes(path: str) -> bytes:
    """This packet's reviewed bytes of path; a bridged successor projects newer bytes back first."""
    return successor.historical_bytes(path, regular_bytes(path))


def _era_bytes(path: Any, raw: Any) -> bytes:
    """An era file's bytes, checked against its era digest; a path outside the era is refused."""
    expected = ERA_SHA256.get(path) if type(path) is str else None
    require(expected is not None, "MET-011 reviewed bytes are bound: " + str(path))
    require(type(raw) is bytes and digest(raw) == expected, "unreviewed MET-011 source: " + path)
    return raw


def _verified(path: str) -> bytes:
    """reviewed_bytes, checked against its era digest on every read; a path outside the era is refused before it is
    read."""
    require(type(path) is str and path in ERA_SHA256, "MET-011 reviewed bytes are bound: " + str(path))
    return _era_bytes(path, reviewed_bytes(path))


def _bound_read(path: str, expected: Any) -> bytes:
    """reviewed_bytes of a file named by an era-verified record, checked against the digest that record gives it."""
    require(type(path) is str and _sha(expected), "MET-011 bound read: " + str(path))
    _path(path)
    raw = reviewed_bytes(path)
    require(type(raw) is bytes and digest(raw) == expected, "MET-011 bound file drift: " + path)
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


def check_packet_files(files: Any) -> None:
    """V1: the packet's files are exactly these, and each one's bytes equal the sha256 pinned for it."""
    _bound(lambda: type(files) is dict and sorted(files) == sorted(PACKET_FILES) and len(files) == len(PACKET_FILES),
           "MET-011 V1 the packet files are exactly the two")
    for path in PACKET_FILES:
        _bound(lambda: type(files[path]) is bytes and digest(files[path]) == ERA_SHA256[path],
               "MET-011 V1 a packet file's bytes equal its pinned digest: " + path)


def validate_packet_files() -> None:
    check_packet_files({path: _verified(path) for path in PACKET_FILES})


def check_errata(classes: Any, changed: Any, befores: Any) -> None:
    """E3: class-other (authored) hunks fall only on the named files; each carries one, and each such hunk lies inside one
    of its file's named base-line spans: placed in the before bytes by its offset plus the earlier hunks' shift, its
    before-text is there, and the base lines it spans are within the span; every other hunk is a mechanics form v2.5
    normalises. record.json is outside E3 by path (V6a pins its classes)."""
    _bound(lambda: type(classes) is dict and type(changed) is dict
           and all(cls in NORMALISED or (cls == "other" and path in ERRATA_LINES) for path in classes if path != LEDGER_PATH
               for cls in classes[path]),
           "MET-011 E3 class-other hunks fall only on the named files")
    for path, spans in ERRATA_LINES.items():
        _bound(lambda: "other" in classes[path] and type(befores[path]) is bytes,
               "MET-011 E3 the named file carries its authored hunk: " + path)
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
                       "MET-011 E3 an authored hunk lies at its named lines: %s hunk %d" % (path, position))


def validate_errata() -> None:
    """E3 over the hunk-class record (bound by its newFiles digest) and each named file's before bytes, projected back
    through this layer's own hunks from its afterSha256-bound bytes."""
    record = authority()
    side = _parsed(_bound_read(HUNK_RECORD_PATH, record["newFiles"].get(HUNK_RECORD_PATH)))
    befores = {path: _undo_this_layer(path, _bound_read(path, record["changedFiles"][path]["afterSha256"]))
               for path in ERRATA_LINES if path in record["changedFiles"]}
    check_errata(side.get("classes") if type(side) is dict else None, record["changedFiles"], befores)


def _absent(path: str) -> bool:
    """True when nothing (no file, link or directory) is at path."""
    try:
        (ROOT / path).lstat()
    except FileNotFoundError:
        return True
    return False


def _layer_holds(layer: Any) -> bool:
    keys = set(layer) if type(layer) is dict else set()
    return (type(layer) is dict and keys - TEST_MEMBERS == LAYER_MEMBERS and keys & TEST_MEMBERS in (set(), TEST_MEMBERS)
            and type(layer["slot"]) is int and type(layer["module"]) is str
            and layer["validatorPath"] == "scripts/" + layer["module"] + ".py"
            and _sha(layer["validatorSha256"]) and type(layer["authorityPath"]) is str
            and _sha(layer["authoritySha256"]) and type(layer["inputs"]) is dict
            and all(type(p) is str and _sha(d) for p, d in layer["inputs"].items())
            and type(layer["nodes"]) is list and type(layer["seconds"]) in (int, float)
            and (not keys & TEST_MEMBERS or (type(layer["testFilePath"]) is str and _sha(layer["testFileSha256"]))))


def _attested(layer: dict) -> dict:
    files = {layer["validatorPath"]: layer["validatorSha256"], layer["authorityPath"]: layer["authoritySha256"],
             **layer["inputs"]}
    if "testFilePath" in layer:
        files[layer["testFilePath"]] = layer["testFileSha256"]
    return files


def check_walk(layers: Any, sources: Any) -> None:
    """C1's chain walk: the ledger's layers are consecutive from 189 to 292 (this layer's predecessor), and each layer's
    reviewed validator binds the next one, the last binding this layer's validator."""
    _bound(lambda: type(layers) is list and type(sources) is dict and [layer["slot"] for layer in layers]
           == list(range(FIRST_LAYER[0], CHECKPOINT_SLOT)) and (layers[0]["slot"], layers[0]["module"]) == FIRST_LAYER
           and layers[-1]["module"] == PREVIOUS_LAYER,
           "MET-011 C1 the ledger's layers are the chain walk 189-292")
    names = [layer["module"] for layer in layers] + [VALIDATOR_PATH[len("scripts/"):-len(".py")]]
    for index, layer in enumerate(layers):
        bind = " " + names[index + 1] + " import " if index == 0 else "import " + names[index + 1] + " as successor\n"
        _bound(lambda: sources[layer["validatorPath"]].decode("utf-8").count(bind) >= 1,
               "MET-011 C1 the chain walk: slot %s binds its successor" % layer["slot"])


def check_ledger(raw: Any, walk: Any, baseline: Any, entry: Any, side_absent: Any) -> None:
    """C1: the ledger is named by this step's authority (its record.json entry's afterSha256, in the three-key form); its
    closed members; slot 293 over the 313-packet baseline; the owner's parameters with WORKERS 12; the full-run proof;
    both stated differences, the capture variables and the verify reference to slot 286's record; ruled check pairs;
    sizeBytes <= sizeBound <= 16 MiB; the exclusion equal to the write set (three files, E-7) with no ledger-hunks path
    on disk; normalisedRecordClass true (E-14); the base's check pairs (E-3); and the layers, the chain walk 189-292."""
    ledger = _parsed(raw)
    _bound(lambda: type(entry) is dict and set(entry) == ENTRY_KEYS and _sha(entry["afterSha256"])
           and type(raw) is bytes and digest(raw) == entry["afterSha256"]
           and entry["beforeSha256"] == PREVIOUS_CHECKPOINT[1],
           "MET-011 C1 the ledger is named by this step's authority over slot 286's record")
    _bound(lambda: type(ledger) is dict and set(ledger) == LEDGER_MEMBERS and ledger["schemaVersion"] == LEDGER_SCHEMA
           and ledger["checkpointSlot"] == CHECKPOINT_SLOT and ledger["checkpointBaseline"] == CHECKPOINT_BASELINE == baseline,
           "MET-011 C1 the ledger is the closed slot-293 checkpoint over the 313-packet baseline")
    _bound(lambda: type(ledger["parameters"]) is dict and set(ledger["parameters"]) == set(PARAMETERS) | {"shadowIn"}
           and all(ledger["parameters"][k] == v and type(ledger["parameters"][k]) is type(v) for k, v in PARAMETERS.items())
           and ledger["parameters"]["shadowIn"] in SHADOW_IN and ledger["normalisedRecordClass"] is True,
           "MET-011 C1 the ledger's parameters are the owner's numbers")
    proof = ledger.get("fullRunProof") if type(ledger) is dict else None
    _bound(lambda: type(proof) is dict and set(proof) == {"collected", "executed", "deselected", "attested"}
           and type(proof["collected"]) is int and proof["collected"] > 0 and proof["executed"] == proof["collected"]
           and proof["deselected"] == 0 and proof["attested"] == 0,
           "MET-011 C1 the ledger's full-run proof: every collected node executed")
    run = ledger.get("writingRun") if type(ledger) is dict else None
    _bound(lambda: type(run) is dict and set(run) == RUN_MEMBERS and run["statedDifferences"] == list(STATED)
           and run["captureEnv"] == list(CAPTURE_ENV) and run["captureObservesOnly"] is True
           and type(run["outsideReads"]) is int and _sha(run["argvRunSummarySha256"])
           and run["verifyReference"] == VERIFY_REFERENCE,
           "MET-011 C1 the writing run states both differences, the capture variables and the verify reference")
    _bound(lambda: ledger["checkPairs"] == [dict(pair) for pair in CHECK_PAIRS],
           "MET-011 C1 the ledger's check pairs are the base's two ruled supersessions")
    _bound(lambda: type(ledger["sizeBound"]) is int and ledger["sizeBytes"] == len(raw) <= ledger["sizeBound"] <= SIZE_CAP,
           "MET-011 C1 the ledger's size is its length, within its bound, within 16 MiB")
    _bound(lambda: type(ledger["layers"]) is list and all(_layer_holds(layer) for layer in ledger["layers"]),
           "MET-011 C1 the ledger's layers have their closed members")
    _bound(lambda: ledger["exclusion"] == {"files": list(EXCLUSION_FILES), "pinLine": VALIDATOR_PATH}
           and not any(set(_attested(layer)) & set(EXCLUSION_FILES) for layer in ledger["layers"]) and side_absent is True,
           "MET-011 C1 the ledger's exclusion is this step's write set, and no layer attests an excluded file; no ledger-hunks path")
    check_walk(ledger["layers"], walk)


def _ledger() -> tuple:
    """The ledger's reviewed bytes and its record.json entry in this step's authority."""
    entry = authority()["changedFiles"].get(LEDGER_PATH)
    _path(LEDGER_PATH)
    return reviewed_bytes(LEDGER_PATH), entry


def validate_ledger() -> None:
    raw, entry = _ledger()
    ledger = _parsed(raw)
    require(type(ledger) is dict and type(ledger.get("layers")) is list,
            "MET-011 C1 the ledger is the closed slot-293 checkpoint over the 313-packet baseline")
    walk = {layer["validatorPath"]: _bound_read(layer["validatorPath"], layer["validatorSha256"])
            for layer in ledger["layers"] if _layer_holds(layer)}
    check_ledger(raw, walk, len(authority()["baselinePackets"]), entry, _absent(CHECKPOINT_DIR + "/ledger-hunks"))


def check_inline(entry: Any, live: Any) -> None:
    """C2 (MON-286-INLINE-GO): the ledger's changedFiles entry is the plain three-key form over slot 286's record, its
    afterSha256 the live ledger's, with 1 to 4,096 reverse hunks (the writer's line-run hunks); and those hunks reproduce
    slot 286's record byte-exactly from the live ledger, in one ascending pass (no overlap; the removed bytes present)."""
    _bound(lambda: type(entry) is dict and set(entry) == ENTRY_KEYS and entry["beforeSha256"] == PREVIOUS_CHECKPOINT[1]
           and type(live) is bytes and _sha(entry["afterSha256"]) and digest(live) == entry["afterSha256"]
           and type(entry["reverseHunks"]) is list and 0 < len(entry["reverseHunks"]) <= 4096,
           "MET-011 C2 the record.json entry is the plain three-key form over slot 286's record")

    def replayed() -> bool:
        hunks = entry["reverseHunks"]
        if not all(type(h) is dict and set(h) == {"at", "removeBase64", "insertBase64"} and type(h["at"]) is int for h in hunks):
            return False
        chunks, cursor = [], 0
        for hunk in sorted(hunks, key=lambda h: h["at"]):
            remove, insert = _base64(hunk["removeBase64"]), _base64(hunk["insertBase64"])
            if hunk["at"] < cursor or live[hunk["at"]:hunk["at"] + len(remove)] != remove:
                return False
            chunks.extend((live[cursor:hunk["at"]], insert))
            cursor = hunk["at"] + len(remove)
        chunks.append(live[cursor:])
        return digest(b"".join(chunks)) == PREVIOUS_CHECKPOINT[1]
    _bound(replayed, "MET-011 C2 the record.json entry's reverse hunks reproduce slot 286's record")


def validate_inline() -> None:
    raw, entry = _ledger()
    check_inline(entry, raw)


def check_ledger_classes(classes: Any, changed: Any) -> None:
    """V6a (MON-286-V6A): record.json's classes in the hunk-class record are exactly one "other" per reverse hunk of
    its changedFiles entry (never re-classified: record.json is excluded and the reader never re-checks it)."""
    _bound(lambda: type(classes) is dict and type(changed) is dict and LEDGER_PATH in changed
           and classes[LEDGER_PATH] == ["other"] * len(changed[LEDGER_PATH]["reverseHunks"]),
           "MET-011 V6a record.json's classes are exactly one other per hunk")


def validate_ledger_classes() -> None:
    """V6a over the hunk-class record (bound by its newFiles digest) and the authority's changedFiles."""
    record = authority()
    side = _parsed(_bound_read(HUNK_RECORD_PATH, record["newFiles"].get(HUNK_RECORD_PATH)))
    check_ledger_classes(side.get("classes") if type(side) is dict else None, record["changedFiles"])


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
           "the registry differs from the base by exactly the MET-011 packet rider, pinning the generic packet "
           "brief")


def validate_registry() -> None:
    """V4 over briefs.json and the generic packet brief."""
    check_registry(_verified(REGISTRY_PATH), {PACKET_BRIEF: _verified(PACKET_BRIEF)})


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
    pair from the authority's baselinePackets size, then countPairs; no products (K = 0); the new tests from newFiles."""
    n = len(record["baselinePackets"])
    return {"prevValidator": context["prevValidator"], "prevTest": context["prevTest"], "newPacket": context["newPacket"],
            "products": [], "steps": context["steps"],
            "pairs": [[n, n + context["steps"][1]]] + [list(pair) for pair in context["countPairs"]],
            "newTests": [p for p in record["newFiles"] if p.startswith("tests/") and p.endswith(".py")]}


def check_hunk_record(raw: Any, changed: Any, afters: Any, classify: Any, context: Any, rule_sha: Any) -> None:
    """V6 under v2.5: the record's six closed members; it names this layer's authority; the closed vocabulary and v2.5's
    digest, which the reader's copy carries; the context is this step's names with countPairs; no outcome statement; one
    class per reverse hunk for exactly the changed files; and every class equals v2.5's class at its position, but
    record.json's line-run hunks, which V6a pins (one "other" per hunk) and which are never re-classified."""
    record = _parsed(raw)
    _bound(lambda: type(record) is dict and set(record) == HUNK_RECORD_MEMBERS and record["authorityPath"] == AUTHORITY_PATH
           and record["outcomeStatements"] == [],
           "MET-011 V6 the hunk-class record is closed and names this layer's authority")
    _bound(lambda: record["hunkClassVocabulary"] == list(HUNK_VOCABULARY)
           and record["hunkClassRuleSha256"] == HUNK_RULE_SHA256 == rule_sha,
           "MET-011 V6 the hunk-class record's vocabulary and rule digest are v2.5's")
    _bound(lambda: type(record["hunkClassContext"]) is dict and set(record["hunkClassContext"]) == set(HUNK_CONTEXT)
           and record["hunkClassContext"] == {"newPacket": NEW_PACKET, "prevValidator": HUNK_CONTEXT["prevValidator"],
                                              "prevTest": HUNK_CONTEXT["prevTest"], "steps": [1, 1], "countPairs": []},
           "MET-011 V6 the hunk-class record's context is this step's names")
    classes = record.get("classes") if type(record) is dict else None
    _bound(lambda: type(changed) is dict and type(classes) is dict and set(classes) == set(changed)
           and all(type(classes[p]) is list and all(type(c) is str for c in classes[p])
                   and len(classes[p]) == len(changed[p].get("reverseHunks", [])) for p in changed),
           "MET-011 V6 the hunk-class record lists one class per hunk for exactly the changed files")
    for path, entry in changed.items():
        if path == LEDGER_PATH:
            continue    # V6a pins them (MON-286-V6A): never re-classified
        seen = set()
        for position, (cls, hunk) in enumerate(zip(classes[path], entry.get("reverseHunks", []))):
            _bound(lambda: cls in HUNK_VOCABULARY and cls == classify(
                path, afters[path], hunk["at"], _base64(hunk["removeBase64"]), _base64(hunk["insertBase64"]), context,
                seen=seen),
                   "MET-011 V6 a recorded class re-checks by position: %s hunk %d" % (path, position))


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


def validate_met_011(packets: dict[str, Any]) -> None:
    """Every era file first; then V1 (the two packet files), E3 (the authored edits), C1 (the ledger), C2 (the inline
    entry), V6a (record.json's classes), V4 (the registry) and V6 (the hunk-class record); last, this layer's
    canonical hunks."""
    for path in ERA_SHA256:
        _verified(path)
    validate_packet_files()
    validate_errata()
    validate_ledger()
    validate_inline()
    validate_ledger_classes()
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
        if path == LEDGER_PATH:
            continue    # MET-011: the ledger's line-run hunks; C2 replays them to slot 286's record
        check_canonical_hunks(path, rule, reviewed_bytes(path))


def validate() -> None:
    record = authority()
    validator_raw = successor.historical_bytes(VALIDATOR_PATH, regular_bytes(VALIDATOR_PATH))
    literal = b'AUTHORITY_SHA256 = "' + AUTHORITY_SHA256.encode("ascii") + b'"'
    placeholder = b'AUTHORITY_SHA256 = "TO_BE_PINNED_AFTER_SOURCE_FREEZE"'
    require(validator_raw.count(literal) == 1
            and digest(validator_raw.replace(literal, placeholder))
            == record["validatorNormalizedSha256"], "ledger rewrite validator drift")
    paths = sorted((ROOT / "task-packets").glob("*.yaml"))
    old = set(record["baselinePackets"])
    require(len(paths) == 322
            and {path.stem for path in paths} == old | {NEW_PACKET, successor.NEW_PACKET, *successor.PRODUCT_PACKETS, successor.successor.NEW_PACKET, successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.NEW_PACKET, *successor.successor.successor.successor.PRODUCT_PACKETS},
            "closed 322-packet catalog retaining the 314-packet checkpoint")
    packets = {}
    for path in paths:
        if path.stem in (successor.NEW_PACKET, successor.successor.NEW_PACKET, successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.NEW_PACKET, *successor.successor.successor.successor.PRODUCT_PACKETS):
            continue
        if path.stem in successor.PRODUCT_PACKETS:
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
            "closed source-only ledger-rewrite packet and inherited commands")
    require(len(packet["allowedPaths"]) == len(set(packet["allowedPaths"]))
            and set(packet["allowedPaths"]) == set(record["changedFiles"])
            | set(record["newFiles"]) | {AUTHORITY_PATH, VALIDATOR_PATH,
                                         "task-packets/" + NEW_PACKET + ".yaml"},
            "unreviewed or omitted ledger-rewrite packet path")
    for path, rule in record["changedFiles"].items():
        current = successor.historical_bytes(path, regular_bytes(path))
        require(digest(current) == rule["afterSha256"]
                and digest(historical_bytes(path, current)) == rule["beforeSha256"],
                "unreviewed current source: " + path)
    for path, expected in record["newFiles"].items():
        require(digest(successor.historical_bytes(path, regular_bytes(path))) == expected,
                "new source drift: " + path)
    validate_met_011(packets)


if __name__ == "__main__":
    validate()
    print("Ledger rewrite valid: 322 current specifications at slot 293; 314-packet checkpoint and exact 313-packet predecessor; contract reviewed.")
