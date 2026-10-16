#!/usr/bin/env python3
"""Validate the MET-ENFORCE-030 I05 gate channel v4 and the exact 242-to-241 projection."""
from __future__ import annotations

import ast
import base64
import binascii
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
    import validate_license_amendment_v2 as successor
except ImportError:
    from scripts.safe_yaml import safe_load
    from scripts import validate_license_amendment_v2 as successor


ROOT = Path(__file__).resolve().parents[1]
AUTHORITY_PATH = "architecture/i05-gate-channel-v4-authority.json"
AUTHORITY_SHA256 = "885c8da08e6b31c067317464e423286581dec2dac2e6a64aa3ee7b9358a27b8f"
VALIDATOR_PATH = "scripts/validate_i05_gate_channel_v4.py"
BASE_COMMIT = "3cba1171e2e9c1dda8fd9e9130f45a68f2ab27d6"
NEW_PACKET = "MET-ENFORCE-030"
PREVIOUS_PACKET = "MET-PERF-040"
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
            require(key not in result, "duplicate i05-gate-channel-v4 authority member")
            result[key] = value
        return result

    def no_constant(_value: str) -> Any:
        raise ValueError("nonfinite i05-gate-channel-v4 authority number")

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
        require(digest(raw) == AUTHORITY_SHA256, "I05 gate channel v4 history authority digest")
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
    }, "closed I05 gate channel v4 history authority")
    require(value["schemaVersion"] == "harness.planeon.ai/i05-gate-channel-v4-authority/v1"
            and value["authorityPacket"] == NEW_PACKET
            and value["acceptedBase"] == BASE_COMMIT
            and type(value["baselinePackets"]) is dict
            and len(value["baselinePackets"]) == 241
            and NEW_PACKET not in value["baselinePackets"]
            and type(value["changedFiles"]) is dict
            and type(value["newFiles"]) is dict
            and _sha(value["packetSha256"])
            and _sha(value["validatorNormalizedSha256"]),
            "accepted 241-packet base")
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
    # An exact 241-era byte string is already older than the successor layer.
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


# MET-ENFORCE-030 (roadmap I05-OBSERVED-WORKERS; owner decisions Q-HE3D-2 (a) and Q-I5-4 (a), and the lane monitor's
# owner-delegated Q-I5-1..3 (a), with its confirmations Q-I5-READINGS, 2026-10-16) publishes the I05 gate channel v4: a
# model, vectors and README successor in which the gate observes the broker's probe-worker cgroup at every BIND (two
# cgroup.procs reads around a pidfd-confirmed stat read), refuses any failure with the existing WORKER_NOT_OBSERVED and
# keeps the v3 wire byte for byte. Repository bytes are read only through reviewed_bytes, so a later bridged successor
# projects its own edits away first. Every reviewed file of this era, and every input the vectors pin, is bound by digest
# before anything is parsed and on every later read. The v4 model is executed from this era's bytes (standard library
# only); its five review rounds are bound to their exact subject bytes; every v3 and supplement vector and every v4 vector
# replays (277 checks); the v3 contract, its supplement and its model stay byte-identical. This layer's own inverse hunks
# are the canonical byte-minimal ones, recomputed here from its era's bytes (MET-PERF-040's carried rule).
V4_DIR = "architecture/i05-gate-channel-v4/"
V4_MODEL = "scripts/i05_gate_channel_v4.py"
STATUS = V4_DIR + "status.json"
INDEX = V4_DIR + "source-index.json"
SUBJECT = (V4_DIR + "README.md", V4_DIR + "REVIEW_BRIEF.md", V4_DIR + "vectors.json", V4_MODEL)
# The adopted v3 contract, its supplement and its model stay byte-identical.
FROZEN_PATHS = (
    "architecture/i05-gate-channel-v3-supplement/README.md",
    "architecture/i05-gate-channel-v3-supplement/status.json",
    "architecture/i05-gate-channel-v3-supplement/vectors.json",
    "architecture/i05-gate-channel-v3/README.md",
    "architecture/i05-gate-channel-v3/channel.schema.json",
    "architecture/i05-gate-channel-v3/outcome-mapping.json",
    "architecture/i05-gate-channel-v3/status.json",
    "architecture/i05-gate-channel-v3/vectors.json",
    "scripts/i05_gate_channel_v3.py",
)
ERA_SHA256 = MappingProxyType({
    "architecture/i05-gate-channel-v3-supplement/README.md": "c90eacd3692af35fa2f35083779780e93acb4c1b14dbf7b790f28a42ec099ed3",
    "architecture/i05-gate-channel-v3-supplement/vectors.json": "1c00bdb3ea112af6098a09158cce3e4a7a6098c9670f490ead4ca65d8bdbb5ac",
    "architecture/i05-gate-channel-v3/README.md": "f82f43330125640d3ac946d2afc9a1804a21e5e60a7ac4b94e5d6cb6ed2ea3aa",
    "architecture/i05-gate-channel-v3/channel.schema.json": "3bfee13c9d32e82fe5ab908eb6f716bc11881f9d57b324f8ea4a21a3ad35356f",
    "architecture/i05-gate-channel-v3/outcome-mapping.json": "4466f379f1cc669e047cffd8afa5fa88b2cc7648a51e2d38b17f0bd5e2252a3a",
    "architecture/i05-gate-channel-v3/status.json": "7cd5302ba7fe8bbb47b2859c4311e247ae6d730cf37d31d8c7140a61e3e8c5c4",
    "architecture/i05-gate-channel-v3/vectors.json": "ab75d86fe54ade7ee2695ef84b200d0473e14e4112e64e7702032593658763ed",
    "architecture/i05-gate-channel-v4/README.md": "b0af1f8784c7e9bcdd3793a1002d1000e222a13e5a7613b50b04ce5a116ed04d",
    "architecture/i05-gate-channel-v4/REVIEW_BRIEF.md": "6a4fc9d6c40644e9aab1728b3cd75671359191209060e251bbd9ad738ca49b41",
    "architecture/i05-gate-channel-v4/review-round1.json": "84487e57ceacc3ab4912f8e330911c525f46d87ed5386a6dc120850fa952d635",
    "architecture/i05-gate-channel-v4/review-round2.json": "b843768262c7d3314f38f1bfb6fd51656e1227c17880c7dc56fbc2e25c0f5632",
    "architecture/i05-gate-channel-v4/review-round3.json": "8d5b2be8692fd5ba5d0821b28ef4503c0ca4989f0e3bc9c87ebee59c1000dadc",
    "architecture/i05-gate-channel-v4/review-round4.json": "b2160bd504407d2b6cc9387c3e878a7992e91b6cf446ae4b7174ee11d533cfcf",
    "architecture/i05-gate-channel-v4/review-round5.json": "8b9ba30264fde2e62e7f807bc23d4c6f1868ae1b172e6fef1cee3557c3425b30",
    "architecture/i05-gate-channel-v4/round1/architecture/i05-gate-channel-v4/README.md": "d369074c583006aacce11f94e275b6a5a648a3867870d56b713071fbfaf95a2c",
    "architecture/i05-gate-channel-v4/round1/architecture/i05-gate-channel-v4/REVIEW_BRIEF.md": "f50ca92c667bf49416065f753f2cde48788364dbe3010843bc8f29e221af9486",
    "architecture/i05-gate-channel-v4/round1/architecture/i05-gate-channel-v4/vectors.json": "7129f402aa56b95c0fb08f041d2c3d37f2a9b7a1d643f063cfc03b995adee0f2",
    "architecture/i05-gate-channel-v4/round1/scripts/i05_gate_channel_v4.py": "ee926fd09153501babde997a77182de61abf39214f06e94921780996edbca3d4",
    "architecture/i05-gate-channel-v4/round2/architecture/i05-gate-channel-v4/README.md": "e3d2e970881457eabcf734dbebc1873cc267483fd281be0ce75d666feb5f1ead",
    "architecture/i05-gate-channel-v4/round2/architecture/i05-gate-channel-v4/REVIEW_BRIEF.md": "115292495be3dce7cbcbf992faf5bfe315ecceaa33ac0775d92f8681623961db",
    "architecture/i05-gate-channel-v4/round2/architecture/i05-gate-channel-v4/vectors.json": "471abc60ce3d46ba5ec8788b251287974d61958cd8834e154478e3c760ee3faa",
    "architecture/i05-gate-channel-v4/round2/scripts/i05_gate_channel_v4.py": "ff5517f11bbc625228c9c414acd8b9ae036f9aa8a2bca3cbd58905b65c72503e",
    "architecture/i05-gate-channel-v4/round3/architecture/i05-gate-channel-v4/README.md": "5ea2461dc841ab6038b57296d103ec69c37c546da65c95444900353d23b918bc",
    "architecture/i05-gate-channel-v4/round3/architecture/i05-gate-channel-v4/REVIEW_BRIEF.md": "ce61e3a68f450ab14120d6163fc764ec87722af197d4826b36a8f62a998aa9ac",
    "architecture/i05-gate-channel-v4/round3/architecture/i05-gate-channel-v4/vectors.json": "40b48f251b0531394d7871d66b237a3c36bd88b8b41a385ba53c46e3ee09ef0c",
    "architecture/i05-gate-channel-v4/round3/scripts/i05_gate_channel_v4.py": "a137082d080588c479f85a4917c544ff49cd11fa5e6d0b196884880e0d57dcd0",
    "architecture/i05-gate-channel-v4/round4/architecture/i05-gate-channel-v4/README.md": "be04f097fc04f4b6ea56331c7a2a2b65df31f823b0441b779577bea993bdbccd",
    "architecture/i05-gate-channel-v4/round4/architecture/i05-gate-channel-v4/REVIEW_BRIEF.md": "5ba5934e023ae48b3079f2b225dcd711593ed55715c3d7de2dbd7ca4f14e347d",
    "architecture/i05-gate-channel-v4/round4/architecture/i05-gate-channel-v4/vectors.json": "9da5e3b8bde00694fd099c02700db43d639b3bc88f36b2c3d746cb4c1b3a4025",
    "architecture/i05-gate-channel-v4/round4/scripts/i05_gate_channel_v4.py": "3a69d832b8d63131e13bac76e7877b322e72930afcdf1d8c316b2ddc2c3cfca1",
    "architecture/i05-gate-channel-v4/source-index.json": "068bb20b91a6c3a0ec8cccc8f72a2a34089806ff9937fc044e503724c917cd99",
    "architecture/i05-gate-channel-v4/status.json": "0464ab80dad0796b1298b96d013e8d198f7f1d345897b6e40a332e0b72243c29",
    "architecture/i05-gate-channel-v4/vectors.json": "f314610f7ee3feb08533cb535f0a4c19fc991384b852b99a50a1646b0739b1e9",
    "architecture/seccomp-allowlists-v4/allowlists.json": "4dcfb2dfea82eabd04024b35d9dac4bb487b6c0051f7e6e16bbd00426cf6b2ff",
    "architecture/selinux-matrix-v3/README.md": "0070f3b5be1d68eb6d1e76e9aceed496b5c1ecce91f8cd3b69c81ffdee1e9167",
    "architecture/selinux-matrix-v3/matrix.json": "01e4f3cfd75250dc6fd74f666cfa53758f83b7a07d7a39a0ca180f5588496b73",
    "scripts/i05_gate_channel_v3.py": "2c7985b539c0ce8eb79eaabfa1f1ab7d43bdca7515defc590a76ecb1697ca959",
    "scripts/i05_gate_channel_v4.py": "95c690cdb0744833f16fa6ac5372c2d8e3404fde9fb19a8fa4e9a0334246ae0d",
})
REVIEW_VERDICTS = ("CHANGES_REQUIRED", "CHANGES_REQUIRED", "CHANGES_REQUIRED", "CHANGES_REQUIRED", "PASS_FOR_SOURCE_PUBLICATION")
PASS_SUBJECT = "35b108b3409cad5398ee6b5e1940427eaec8ea5c"
OWNER_DECISIONS = ("SEQ-241-242", "Q-I5-DECISIONS", "SLOT241-FACTS", "Q-I5-READINGS", "B-DEFAULTS")
MODEL_VERSION = "planeon.internal.effect-gate-model/v4"
FRAME_VERSION = "planeon.internal.effect-gate-frame/v3"
VECTOR_CHECKS = 277
FALSE_FLAGS = ("gateInstalled", "observationImplemented", "nativeAcceptance", "tenantAcceptance", "productExecution",
               "runnerActivated", "phaseComplete")
STATUS_KEYS = frozenset({"schemaVersion", "contract", "frame", "supersedes", "reviewRounds", "ownerDecisions",
                         "contractState", "readmeStatusNote", "obligations", "independentReviewer", "closedFindings",
                         "carriedFindings", *FALSE_FLAGS})
ROUND_KEYS = frozenset({"round", "record", "recordSha256", "verdict", "subjectCommit", "subjectTree", "subjectSha256",
                        "subjectDirectory"})


def reviewed_bytes(path: str) -> bytes:
    """This packet's reviewed bytes of path; a bridged successor projects newer bytes back first."""
    return successor.historical_bytes(path, regular_bytes(path))


def _verified(path: str) -> bytes:
    """reviewed_bytes, checked against its era digest on every read; a path outside the era is refused first."""
    expected = ERA_SHA256.get(path)
    require(expected is not None, "MET-ENFORCE-030 reviewed bytes are bound: " + path)
    raw = reviewed_bytes(path)
    require(type(raw) is bytes and digest(raw) == expected, "unreviewed I05 gate channel v4 source: " + path)
    return raw


def _json(path: str) -> Any:
    return parse(_verified(path))


def _era_model() -> types.ModuleType:
    """The v4 model of this era, executed from its verified bytes."""
    module = types.ModuleType("_met_enforce_030_i05_gate_channel_v4")
    module.__file__ = str(ROOT / V4_MODEL)
    exec(compile(_verified(V4_MODEL), V4_MODEL, "exec", dont_inherit=True), module.__dict__)
    return module


def validate_v4_status() -> None:
    """The status is closed, its five rounds are bound to their exact subject bytes, and the last passes with notes."""
    status = _json(STATUS)
    require(type(status) is dict and set(status) == STATUS_KEYS
            and status["schemaVersion"] == "planeon.internal.i05-gate-channel-v4-status/v1"
            and status["contract"] == MODEL_VERSION and status["frame"] == FRAME_VERSION
            and status["contractState"] == "ADOPTED_DATA_CONTRACT"
            and status["obligations"] == {"E%02d" % n: "OPEN_UNPROVEN" for n in range(1, 13)}
            and status["independentReviewer"] == "SEPARATE_AGENT_NOT_AUTHOR"
            and all(status[flag] is False for flag in FALSE_FLAGS)
            and tuple(row["id"] for row in status["ownerDecisions"]) == OWNER_DECISIONS,
            "adopted after the round-5 pass, nothing installed")
    rounds = status["reviewRounds"]
    require(type(rounds) is list and len(rounds) == len(REVIEW_VERDICTS)
            and all(type(row) is dict and set(row) == ROUND_KEYS | ({"keptCopies"} if n < len(rounds) else set())
                    for n, row in enumerate(rounds, 1))
            and tuple(row["verdict"] for row in rounds) == REVIEW_VERDICTS
            and rounds[-1]["subjectCommit"] == PASS_SUBJECT and rounds[-1]["subjectDirectory"] == "CURRENT",
            "adopted after the round-5 pass, nothing installed")
    for number, row in enumerate(rounds, 1):
        record = parse(_verified(row["record"]))
        kept = row.get("keptCopies", [])
        directory = row["subjectDirectory"]
        require(row["round"] == number and row["record"] == V4_DIR + "review-round%d.json" % number
                and digest(_verified(row["record"])) == row["recordSha256"]
                and record["round"] == number and record["subject"] == row["subjectCommit"]
                and record["verdict"] == row["verdict"]
                and directory == (V4_DIR + "round%d/" % number if number < len(rounds) else "CURRENT")
                and set(kept) <= set(SUBJECT)
                and row["subjectSha256"] == {path: digest(_verified(directory + path if path in kept else path))
                                             for path in SUBJECT},
                "review round %d is bound to its exact subject bytes" % number)
    final = parse(_verified(rounds[-1]["record"]))
    require(all(type(row) is dict and row.get("severity") == "NOTE" for row in final["findings"])
            and {row["id"] for row in final["findings"]} <= set(status["carriedFindings"]),
            "the final round passes with notes only, all carried")
    index = _json(INDEX)
    require(index["subjectCommit"] == PASS_SUBJECT and [row["path"] for row in index["subject"]] == list(SUBJECT)
            and all(digest(_verified(row["path"])) == row["sha256"] for row in index["subject"] + index["predecessorInputs"]),
            "the reviewed subject and its inputs are the published ones")


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


def validate_canonical_hunks() -> None:
    """Q-PERF40-4: every hunk of this layer's authority is the canonical byte-minimal one, from this era's bytes."""
    for path, rule in _PROJECTION_RULES.items():
        after = reviewed_bytes(path)
        require(type(after) is bytes and digest(after) == rule["afterSha256"], "unreviewed current source: " + path)
        before = _undo_this_layer(path, after)
        require(canonical_hunks(after, before) == rule["reverseHunks"], "canonical byte-minimal inverse hunks: " + path)


def validate_i05_gate_channel_v4() -> None:
    """Every reviewed byte and the review binding first; then every v3, supplement and v4 vector through the era model."""
    for path in FROZEN_PATHS:
        require(path not in _PROJECTION_RULES, "the I05 v3 contract, its supplement and its model stay byte-identical")
    for path in ERA_SHA256:
        _verified(path)
    validate_v4_status()
    model = _era_model()
    require(model.MODEL_VERSION == MODEL_VERSION and model.FRAME_VERSION == FRAME_VERSION, "the v4 model keeps the v3 frame")
    files = {path: _verified(path) for path in model.V3_FILES.values()}
    require(model.check_vectors(_json(V4_DIR + "vectors.json"), files) == VECTOR_CHECKS,
            "every v3, supplement and v4 vector replays")
    validate_canonical_hunks()


def validate() -> None:
    record = authority()
    validator_raw = successor.historical_bytes(VALIDATOR_PATH, regular_bytes(VALIDATOR_PATH))
    literal = b'AUTHORITY_SHA256 = "' + AUTHORITY_SHA256.encode("ascii") + b'"'
    placeholder = b'AUTHORITY_SHA256 = "TO_BE_PINNED_AFTER_SOURCE_FREEZE"'
    require(validator_raw.count(literal) == 1
            and digest(validator_raw.replace(literal, placeholder))
            == record["validatorNormalizedSha256"], "I05 gate channel v4 validator drift")
    paths = sorted((ROOT / "task-packets").glob("*.yaml"))
    old = set(record["baselinePackets"])
    require(len(paths) == 243
            and {path.stem for path in paths} == old | {NEW_PACKET, successor.NEW_PACKET},
            "closed 243-packet catalog retaining the 242-packet checkpoint")
    packets = {}
    for path in paths:
        if path.stem == successor.NEW_PACKET:
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
            "closed source-only i05-gate-channel-v4 packet and inherited commands")
    require(len(packet["allowedPaths"]) == len(set(packet["allowedPaths"]))
            and set(packet["allowedPaths"]) == set(record["changedFiles"])
            | set(record["newFiles"]) | {AUTHORITY_PATH, VALIDATOR_PATH,
                                         "task-packets/" + NEW_PACKET + ".yaml"},
            "unreviewed or omitted i05-gate-channel-v4 packet path")
    for path, rule in record["changedFiles"].items():
        current = successor.historical_bytes(path, regular_bytes(path))
        require(digest(current) == rule["afterSha256"]
                and digest(historical_bytes(path, current)) == rule["beforeSha256"],
                "unreviewed current source: " + path)
    for path, expected in record["newFiles"].items():
        require(digest(successor.historical_bytes(path, regular_bytes(path))) == expected,
                "new source drift: " + path)
    validate_i05_gate_channel_v4()


if __name__ == "__main__":
    validate()
    print("I05 gate channel v4 valid: 243 current specifications; 242-packet checkpoint and exact 241-packet predecessor; contract reviewed.")
