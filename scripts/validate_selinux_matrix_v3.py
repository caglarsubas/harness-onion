#!/usr/bin/env python3
"""Validate the MET-ENFORCE-028 SELinux matrix v5 and the exact 239-to-238 projection."""
from __future__ import annotations

import ast
import base64
import binascii
import copy
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
    import validate_compiled_filter_programs_v2 as successor
except ImportError:
    from scripts.safe_yaml import safe_load
    from scripts import validate_compiled_filter_programs_v2 as successor


ROOT = Path(__file__).resolve().parents[1]
AUTHORITY_PATH = "architecture/selinux-matrix-v3-authority.json"
AUTHORITY_SHA256 = "9bd941a975f743a78a8306d1036fe43113d75538efb8eb351810b94ff328b6b8"
VALIDATOR_PATH = "scripts/validate_selinux_matrix_v3.py"
BASE_COMMIT = "9f251d5d07772cbfb9987c422f3fca79748fad34"
NEW_PACKET = "MET-ENFORCE-028"
PREVIOUS_PACKET = "MET-PERF-039"
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
            require(key not in result, "duplicate selinux-matrix-v3 authority member")
            result[key] = value
        return result

    def no_constant(_value: str) -> Any:
        raise ValueError("nonfinite selinux-matrix-v3 authority number")

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
        require(digest(raw) == AUTHORITY_SHA256, "SELinux matrix v5 history authority digest")
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
    }, "closed SELinux matrix v5 history authority")
    require(value["schemaVersion"] == "harness.planeon.ai/selinux-matrix-v3-authority/v1"
            and value["authorityPacket"] == NEW_PACKET
            and value["acceptedBase"] == BASE_COMMIT
            and type(value["baselinePackets"]) is dict
            and len(value["baselinePackets"]) == 238
            and NEW_PACKET not in value["baselinePackets"]
            and type(value["changedFiles"]) is dict
            and type(value["newFiles"]) is dict
            and _sha(value["packetSha256"])
            and _sha(value["validatorNormalizedSha256"]),
            "accepted 238-packet base")
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
    # An exact 238-era byte string is already older than the successor layer.
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


# MET-ENFORCE-028 (roadmap SELINUX-MATRIX-I04-KEYCERT; owner decisions Q-HE3D-2 (a), Q-MX-2 (b) and Q-MX-3 (b), and the
# lane monitor's owner-delegated Q-MX-1 (a), Q-MX-4 (a) and Q-MX-5 (a), 2026-10-15) publishes the SELinux matrix v5
# (planeon.internal.selinux-matrix/v5), the successor of the byte-identical v4: the gate's I04 key type and its chain and
# client CA type, no capability for the gate (HS43 H5), the gate's observedWorkers source (READ on the probe-worker cgroup,
# dir search on its two parents, /proc on the worker) and the HS43 /proc narrowing (the observer takes the native
# profile's captures; the writer's /proc for the gate and the observer, the gate's for the broker and the observer).
# Repository bytes are read only through reviewed_bytes, so a later bridged successor projects its own edits away first.
# Every reviewed file of this era is bound by digest before anything is parsed and on every later read. The evaluator is
# executed from this era's bytes (it imports only the standard library), the four review rounds are bound to their exact
# subject bytes, the matrix is checked to be v4 plus exactly the changes restated here, every assertion must hold, and
# every access and mutation vector replays.
V5_DIR = "architecture/selinux-matrix-v3/"
V4_DIR = "architecture/selinux-matrix-v2/"
V5_MODEL = "scripts/selinux_matrix_v3.py"
STATUS = V5_DIR + "status.json"
INDEX = V5_DIR + "source-index.json"
SUBJECT = (V5_DIR + "README.md", V5_DIR + "REVIEW_BRIEF.md", V5_DIR + "matrix.json", V5_DIR + "vectors.json", V5_MODEL)
# The adopted v3 and v4 matrices and evaluators, HS43, the resolved W01 design and the native profile v3 stay byte-identical.
FROZEN_PATHS = (
    "architecture/host-interface-amendment-hs43/HOST_INTERFACE_SPEC.md",
    "architecture/host-interface-amendment-hs43/README.md",
    "architecture/host-interface-amendment-hs43/REVIEW_BRIEF.md",
    "architecture/host-interface-amendment-hs43/amendment.json",
    "architecture/host-interface-amendment-hs43/review-round1.json",
    "architecture/host-interface-amendment-hs43/review-round2.json",
    "architecture/host-interface-amendment-hs43/review-round3.json",
    "architecture/host-interface-amendment-hs43/review-round4.json",
    "architecture/host-interface-amendment-hs43/round1/architecture/host-interface-amendment-hs43/HOST_INTERFACE_SPEC.md",
    "architecture/host-interface-amendment-hs43/round1/architecture/host-interface-amendment-hs43/README.md",
    "architecture/host-interface-amendment-hs43/round1/architecture/host-interface-amendment-hs43/REVIEW_BRIEF.md",
    "architecture/host-interface-amendment-hs43/round1/architecture/host-interface-amendment-hs43/amendment.json",
    "architecture/host-interface-amendment-hs43/round1/scripts/host_interface_amendment_v2.py",
    "architecture/host-interface-amendment-hs43/round2/architecture/host-interface-amendment-hs43/HOST_INTERFACE_SPEC.md",
    "architecture/host-interface-amendment-hs43/round2/architecture/host-interface-amendment-hs43/README.md",
    "architecture/host-interface-amendment-hs43/round2/architecture/host-interface-amendment-hs43/REVIEW_BRIEF.md",
    "architecture/host-interface-amendment-hs43/round2/architecture/host-interface-amendment-hs43/amendment.json",
    "architecture/host-interface-amendment-hs43/round2/scripts/host_interface_amendment_v2.py",
    "architecture/host-interface-amendment-hs43/round3/architecture/host-interface-amendment-hs43/HOST_INTERFACE_SPEC.md",
    "architecture/host-interface-amendment-hs43/round3/architecture/host-interface-amendment-hs43/README.md",
    "architecture/host-interface-amendment-hs43/round3/architecture/host-interface-amendment-hs43/REVIEW_BRIEF.md",
    "architecture/host-interface-amendment-hs43/round3/architecture/host-interface-amendment-hs43/amendment.json",
    "architecture/host-interface-amendment-hs43/round3/scripts/host_interface_amendment_v2.py",
    "architecture/host-interface-amendment-hs43/source-index.json",
    "architecture/host-interface-amendment-hs43/status.json",
    "architecture/host-interface-inputs/resolved/HOST_INTERFACE_SPEC.md",
    "architecture/native-profile-v3/README.md",
    "architecture/native-profile-v3/REVIEW_BRIEF.md",
    "architecture/native-profile-v3/qualification.schema.json",
    "architecture/native-profile-v3/review-round1.json",
    "architecture/native-profile-v3/review-round2.json",
    "architecture/native-profile-v3/review-round3.json",
    "architecture/native-profile-v3/review-round4.json",
    "architecture/native-profile-v3/review-round5.json",
    "architecture/native-profile-v3/review-round6.json",
    "architecture/native-profile-v3/round1/README.md",
    "architecture/native-profile-v3/round1/REVIEW_BRIEF.md",
    "architecture/native-profile-v3/round1/native_qualification_v3.py",
    "architecture/native-profile-v3/round1/qualification.schema.json",
    "architecture/native-profile-v3/round1/vectors.json",
    "architecture/native-profile-v3/round2/README.md",
    "architecture/native-profile-v3/round2/REVIEW_BRIEF.md",
    "architecture/native-profile-v3/round2/native_qualification_v3.py",
    "architecture/native-profile-v3/round2/qualification.schema.json",
    "architecture/native-profile-v3/round2/vectors.json",
    "architecture/native-profile-v3/round3/README.md",
    "architecture/native-profile-v3/round3/REVIEW_BRIEF.md",
    "architecture/native-profile-v3/round3/native_qualification_v3.py",
    "architecture/native-profile-v3/round3/qualification.schema.json",
    "architecture/native-profile-v3/round3/vectors.json",
    "architecture/native-profile-v3/round4/README.md",
    "architecture/native-profile-v3/round4/REVIEW_BRIEF.md",
    "architecture/native-profile-v3/round4/native_qualification_v3.py",
    "architecture/native-profile-v3/round4/qualification.schema.json",
    "architecture/native-profile-v3/round4/vectors.json",
    "architecture/native-profile-v3/round5/README.md",
    "architecture/native-profile-v3/round5/REVIEW_BRIEF.md",
    "architecture/native-profile-v3/round5/native_qualification_v3.py",
    "architecture/native-profile-v3/round5/qualification.schema.json",
    "architecture/native-profile-v3/round5/vectors.json",
    "architecture/native-profile-v3/source-index.json",
    "architecture/native-profile-v3/status.json",
    "architecture/native-profile-v3/vectors.json",
    "architecture/selinux-matrix-v2/README.md",
    "architecture/selinux-matrix-v2/REVIEW_BRIEF.md",
    "architecture/selinux-matrix-v2/matrix.json",
    "architecture/selinux-matrix-v2/review-round1.json",
    "architecture/selinux-matrix-v2/review-round2.json",
    "architecture/selinux-matrix-v2/round1/architecture/selinux-matrix-v2/README.md",
    "architecture/selinux-matrix-v2/round1/architecture/selinux-matrix-v2/REVIEW_BRIEF.md",
    "architecture/selinux-matrix-v2/round1/scripts/selinux_matrix_v2.py",
    "architecture/selinux-matrix-v2/source-index.json",
    "architecture/selinux-matrix-v2/status.json",
    "architecture/selinux-matrix-v2/vectors.json",
    "architecture/selinux-matrix/README.md",
    "architecture/selinux-matrix/REVIEW_BRIEF.md",
    "architecture/selinux-matrix/matrix.json",
    "architecture/selinux-matrix/review-round1.json",
    "architecture/selinux-matrix/review-round2.json",
    "architecture/selinux-matrix/review-round3.json",
    "architecture/selinux-matrix/round1/README.md",
    "architecture/selinux-matrix/round1/REVIEW_BRIEF.md",
    "architecture/selinux-matrix/round1/matrix.json",
    "architecture/selinux-matrix/round1/selinux_matrix.py",
    "architecture/selinux-matrix/round1/vectors.json",
    "architecture/selinux-matrix/round2/README.md",
    "architecture/selinux-matrix/round2/REVIEW_BRIEF.md",
    "architecture/selinux-matrix/round2/matrix.json",
    "architecture/selinux-matrix/round2/selinux_matrix.py",
    "architecture/selinux-matrix/round2/vectors.json",
    "architecture/selinux-matrix/source-index.json",
    "architecture/selinux-matrix/status.json",
    "architecture/selinux-matrix/vectors.json",
    "scripts/host_interface_amendment_v2.py",
    "scripts/native_qualification_v3.py",
    "scripts/selinux_matrix.py",
    "scripts/selinux_matrix_v2.py",
)
ERA_SHA256 = MappingProxyType({
    "architecture/selinux-matrix-v2/matrix.json": "1d2f27e53d7b1a77d1c80b5e167fd477bc5c25dd78250399edc33de8397eebff",
    "architecture/selinux-matrix-v2/vectors.json": "e6a0afb937443d6f6cb941ba06e9bd46d9bda5b8f1bcdf97d6dba0b634f25961",
    "architecture/selinux-matrix-v3/README.md": "0070f3b5be1d68eb6d1e76e9aceed496b5c1ecce91f8cd3b69c81ffdee1e9167",
    "architecture/selinux-matrix-v3/REVIEW_BRIEF.md": "67a06e40712fbe731026af18effa9b53394b6d2202c2fdddec57337a89b94102",
    "architecture/selinux-matrix-v3/matrix.json": "01e4f3cfd75250dc6fd74f666cfa53758f83b7a07d7a39a0ca180f5588496b73",
    "architecture/selinux-matrix-v3/review-round1.json": "94a1fce3b7531432a87be81f466af4671fea3c3881ba13409407e834e9576736",
    "architecture/selinux-matrix-v3/review-round2.json": "0e0cbc69ea49f5a5a88607e7043a51cb78ea862aa7bb51fe589809bdf05eea9b",
    "architecture/selinux-matrix-v3/review-round3.json": "ddab1e126bf69be0156902959070c6a5b4b42dcb8698a2a3f9657251e80cd894",
    "architecture/selinux-matrix-v3/review-round4.json": "dae36843afa3e31acb116c96704ceafcadfb002290254c781dfff3b25e4b8aa9",
    "architecture/selinux-matrix-v3/round1/architecture/selinux-matrix-v3/README.md": "21ee0417cf07d829df3a3fceae59769ef0197754b3a779e4808ba8f31861d117",
    "architecture/selinux-matrix-v3/round1/architecture/selinux-matrix-v3/REVIEW_BRIEF.md": "61034f5810425e1cca134ab0e7db5caf69efc944bec47c614b14153c130fd127",
    "architecture/selinux-matrix-v3/round1/architecture/selinux-matrix-v3/matrix.json": "c1d457c885d942ca10a5b50a66d053cbfad365a16ec81e47de6b240be11844db",
    "architecture/selinux-matrix-v3/round1/architecture/selinux-matrix-v3/vectors.json": "3a4de3e076fc535f10372efffe52a86893b367d0d51641d92d32c3c5df46b708",
    "architecture/selinux-matrix-v3/round1/scripts/selinux_matrix_v3.py": "01f817a981b18b24cbf7d3646862789800e29695d73e94bdb99b8078b4bf3854",
    "architecture/selinux-matrix-v3/round2/architecture/selinux-matrix-v3/README.md": "472c54892c6beff22b20ca64b2f66ed203df7180663f1f439d07d72169ba414d",
    "architecture/selinux-matrix-v3/round2/architecture/selinux-matrix-v3/REVIEW_BRIEF.md": "e6c8fb9c620436e6a6161c2e6a147a5a465462d451223ac538d8fe74c7c35d71",
    "architecture/selinux-matrix-v3/round2/architecture/selinux-matrix-v3/matrix.json": "7822250b885e25c1fe9de3043bd52bee9099981cafa9b48da90fdba4774a246d",
    "architecture/selinux-matrix-v3/round2/architecture/selinux-matrix-v3/vectors.json": "f654471103078af97501d649c1ed7facd0ab856c2d938a4523a8f7e07a3a88cb",
    "architecture/selinux-matrix-v3/round2/scripts/selinux_matrix_v3.py": "85d4185c029c17aa078eccf15259f8dab15e60260544861590c95609f57fc5ef",
    "architecture/selinux-matrix-v3/round3/architecture/selinux-matrix-v3/README.md": "a75a361c79aa2a0fa92d708c014963162671e9ea7e6d76763228fec2b1b5e7e7",
    "architecture/selinux-matrix-v3/round3/architecture/selinux-matrix-v3/REVIEW_BRIEF.md": "e677f26639eccb8b347842cc0458ecb555562a0d0eab2500a1bee73ac3f8aacc",
    "architecture/selinux-matrix-v3/round3/architecture/selinux-matrix-v3/matrix.json": "42a534679d9e3353ba0946742a15ba19ff3af38c306e3af1c8bee0fb36b35790",
    "architecture/selinux-matrix-v3/round3/architecture/selinux-matrix-v3/vectors.json": "c7916ca99b4fafe05b1bbe85635ab51306ed12d9e56d82b03282a55f7f658944",
    "architecture/selinux-matrix-v3/round3/scripts/selinux_matrix_v3.py": "85d4185c029c17aa078eccf15259f8dab15e60260544861590c95609f57fc5ef",
    "architecture/selinux-matrix-v3/source-index.json": "c101e23ff4f97cc567bf21250b191395f282b52f00c4bc8bed1360d3ffbaebd3",
    "architecture/selinux-matrix-v3/status.json": "bf6664e2390b9a6ddeb7acb5e452c0f111bb856b57545f66482f00e34759e30f",
    "architecture/selinux-matrix-v3/vectors.json": "e1c2bc892bbc60baa54dc033ef829ea406066f7ebde5d3e83c28e3076e8cde5c",
    "scripts/selinux_matrix_v3.py": "86ea304f2177cf71b148233259d6ae5686d6aef7f1fa2294f9be421749776fcb",
})
REVIEW_VERDICTS = ("CHANGES_REQUIRED", "CHANGES_REQUIRED", "CHANGES_REQUIRED", "PASS_FOR_SOURCE_PUBLICATION")
PASS_SUBJECT = "9c87690d1bc4708093cddc5e40314a44fabbdd09"
GATE, WORKER, WRITER = "planeon_gate_t", "planeon_worker_t", "planeon_policy_writer_t"
SERVER, BROKER, OBSERVER = "planeon_server_t", "planeon_broker_t", "planeon_observer_t"
I04_TYPES = ({'access': {'READ': [{'domain': 'planeon_gate_t'}],
             'RELABEL': [{'domain': 'planeon_maint_t', 'when': {'planeon_maintenance_mode': 1}}],
             'WRITE': [{'domain': 'planeon_maint_t', 'when': {'planeon_maintenance_mode': 1}}]},
  'category': 'CREDENTIAL',
  'classes': ['file'],
  'label': 'system_u:object_r:planeon_gate_i04_key_t:s0',
  'name': 'planeon_gate_i04_key_t'},
 {'access': {'READ': [{'domain': 'planeon_gate_t'}],
             'RELABEL': [{'domain': 'planeon_maint_t', 'when': {'planeon_maintenance_mode': 1}}],
             'WRITE': [{'domain': 'planeon_maint_t', 'when': {'planeon_maintenance_mode': 1}}]},
  'category': 'CREDENTIAL',
  'classes': ['file'],
  'label': 'system_u:object_r:planeon_gate_i04_cert_t:s0',
  'name': 'planeon_gate_i04_cert_t'})
GATE_CGROUP_READ = {"planeon_cgroup_slice_t": {"domain": GATE, "classes": ["dir"], "perms": ["search"]},
                    "planeon_cgroup_delegate_t": {"domain": GATE, "classes": ["dir"], "perms": ["search"]},
                    "planeon_cgroup_worker_t": {"domain": GATE}}
PROC_REMOVED = ((SERVER, WRITER), (BROKER, WRITER), (SERVER, GATE))
PROC_ADDED = ((GATE, WORKER),)
CHANGED_ASSERTIONS = frozenset({"A09", "A12", "A13", "A36", "A38", "A39", "A48", "A59.planeon_worker_t",
                                "A59.planeon_policy_writer_t", "A59.planeon_gate_t"})
NEW_ASSERTIONS = ('A67',
 'A38.planeon_cgroup_slice_t',
 'A38S.planeon_cgroup_slice_t',
 'A39.planeon_cgroup_slice_t',
 'A38.planeon_cgroup_contain_t',
 'A39.planeon_cgroup_contain_t',
 'A38.planeon_cgroup_server_t',
 'A39.planeon_cgroup_server_t',
 'A38.planeon_cgroup_observer_t',
 'A39.planeon_cgroup_observer_t',
 'A38.planeon_cgroup_gate_t',
 'A39.planeon_cgroup_gate_t',
 'A38.planeon_cgroup_delegate_t',
 'A38S.planeon_cgroup_delegate_t',
 'A39.planeon_cgroup_delegate_t',
 'A38.planeon_cgroup_broker_t',
 'A39.planeon_cgroup_broker_t',
 'A38.planeon_cgroup_worker_t',
 'A39.planeon_cgroup_worker_t',
 'A68.capability',
 'A68.capability2',
 'A68.cap_userns',
 'A68.cap2_userns')
PROC_PEERS = {WRITER: [GATE, OBSERVER], GATE: [BROKER, OBSERVER], WORKER: [BROKER, GATE, OBSERVER, SERVER]}
V5_CHANGES = ("C680", "C687", "C694", "C1700", "C1707", "C1714", "C1719", "C1722", "C1727", "C1730", "C1735", "C1738", "M24")
COUNTS = {"assertions": 132, "types": 58, "accessChecks": 2435, "mutationChecks": 76}
OWNER_DECISIONS = ("E1", "W02e-F-LANE", "Q-HE3D-2", "SLOT240-FACTS", "SLOT240-FACTS-2-AND-Q-MX", "Q-MX-2-3-OWNER",
                   "XR4-4-MONITOR", "SLOT-SWAP-239")
HS43_OBLIGATIONS = ("O-MATRIX-GATE-NETBIND", "O-MATRIX-WRITER-PROCACCESS", "O-MATRIX-GATE-PROCACCESS")
FALSE_FLAGS = ("nativeAcceptance", "tenantAcceptance", "policyModuleWritten", "policyLoaded", "distributionSelected",
               "seccompFiltersDefined", "w02aSchemaConstantsFixed", "productExecution", "runnerActivated", "phaseComplete")
STATUS_KEYS = frozenset({"schemaVersion", "contract", "supersedes", "reviewRounds", "closedFindings", "carriedFindings",
                         "carriedElsewhere", "ownerDecisions", "ownerDecisionNotes", "contractState", "obligations",
                         "hs43Obligations", "independentReviewer", "readmeStatusNote", "slotNote", "f2", *FALSE_FLAGS})
ROUND_KEYS = frozenset({"round", "record", "recordSha256", "verdict", "subjectCommit", "subjectSha256", "subjectDirectory"})


def reviewed_bytes(path: str) -> bytes:
    """This packet's reviewed bytes of path; a bridged successor projects newer bytes back first."""
    return successor.historical_bytes(path, regular_bytes(path))


def _verified(path: str) -> bytes:
    """reviewed_bytes, checked against its era digest on every read; a path outside the era is refused."""
    expected = ERA_SHA256.get(path)
    require(expected is not None, "MET-ENFORCE-028 reviewed bytes are bound: " + path)
    raw = reviewed_bytes(path)
    require(type(raw) is bytes and digest(raw) == expected, "unreviewed SELinux matrix v5 source: " + path)
    return raw


def _json(path: str) -> Any:
    return parse(_verified(path))


def _era_model() -> types.ModuleType:
    """The v5 evaluator of this era, executed from its verified bytes."""
    module = types.ModuleType("_met_enforce_028_selinux_matrix_v3")
    module.__file__ = str(ROOT / V5_MODEL)
    exec(compile(_verified(V5_MODEL), V5_MODEL, "exec", dont_inherit=True), module.__dict__)
    return module


def validate_v5_status() -> None:
    """The status is closed, its four rounds are bound to their exact subject bytes, and the last passes with notes."""
    status = _json(STATUS)
    require(type(status) is dict and set(status) == STATUS_KEYS
            and status["schemaVersion"] == "planeon.internal.selinux-matrix-v3-status/v1"
            and status["contract"] == "planeon.internal.selinux-matrix/v5"
            and status["supersedes"] == "planeon.internal.selinux-matrix/v4"
            and status["contractState"] == "ADOPTED_DATA_CONTRACT"
            and status["obligations"] == {"E%02d" % n: "OPEN_UNPROVEN" for n in range(1, 13)}
            and tuple(status["hs43Obligations"]) == HS43_OBLIGATIONS
            and all(value.startswith("DISCHARGED_IN_DATA") for value in status["hs43Obligations"].values())
            and status["independentReviewer"] == "SEPARATE_AGENT_NOT_AUTHOR" and status["f2"] == "CLOSED_DESIGN"
            and all(status[flag] is False for flag in FALSE_FLAGS)
            and tuple(row["id"] for row in status["ownerDecisions"]) == OWNER_DECISIONS,
            "adopted after the round-4 pass, nothing installed")
    rounds = status["reviewRounds"]
    require(type(rounds) is list and len(rounds) == len(REVIEW_VERDICTS)
            and all(type(row) is dict and set(row) == ROUND_KEYS | ({"keptCopies"} if n < len(rounds) else set())
                    for n, row in enumerate(rounds, 1))
            and tuple(row["verdict"] for row in rounds) == REVIEW_VERDICTS
            and rounds[-1]["subjectCommit"] == PASS_SUBJECT and rounds[-1]["subjectDirectory"] == "CURRENT",
            "adopted after the round-4 pass, nothing installed")
    for number, row in enumerate(rounds, 1):
        record = parse(_verified(row["record"]))
        kept = row.get("keptCopies", [])
        require(row["round"] == number and row["record"] == V5_DIR + "review-round%d.json" % number
                and digest(_verified(row["record"])) == row["recordSha256"]
                and record["round"] == number and record["subject"] == row["subjectCommit"]
                and record["verdict"] == row["verdict"]
                and row["subjectDirectory"] == (V5_DIR + "round%d/" % number if number < len(rounds) else "CURRENT")
                and set(kept) <= set(SUBJECT)
                and row["subjectSha256"] == {path: digest(_verified(row["subjectDirectory"] + path if path in kept else path))
                                             for path in SUBJECT},
                "review round %d is bound to its exact subject bytes" % number)
    final = parse(_verified(rounds[-1]["record"]))
    require(all(type(row) is dict and row.get("severity") == "NOTE" for row in final["findings"])
            and {row["id"] for row in final["findings"]} == set(status["carriedFindings"]),
            "the final round passes with notes only, all carried")
    index = _json(INDEX)
    require(index["subjectCommit"] == PASS_SUBJECT and [row["path"] for row in index["subject"]] == list(SUBJECT)
            and all(digest(_verified(row["path"])) == row["sha256"] for row in index["subject"]),
            "the reviewed subject is the published one")


def validate_v5_successor(matrix: dict, v4: dict) -> None:
    """v5 is v4 plus exactly the restated changes; every v4 type and assertion keeps its index."""
    fixed = set(v4) - {"schemaVersion", "types", "capabilities", "procAccess", "assertions"}
    require(matrix["schemaVersion"] == "planeon.internal.selinux-matrix/v5" and set(matrix) == set(v4)
            and all(matrix[key] == v4[key] for key in fixed), "v5 changes only types, capabilities, /proc and assertions")
    expected_types = []
    for row in v4["types"]:
        row = copy.deepcopy(row)
        if row["name"] in GATE_CGROUP_READ:
            row["access"]["READ"].append(GATE_CGROUP_READ[row["name"]])
        expected_types.append(row)
    require(matrix["types"] == expected_types + list(I04_TYPES),
            "the v4 types, the gate's three cgroup grants and the two I04 types appended")
    require(matrix["capabilities"] == {d: caps for d, caps in v4["capabilities"].items() if d != GATE},
            "the gate holds no capability; every other domain's capabilities are v4's")
    require(matrix["procAccess"] == [e for e in v4["procAccess"] if (e["domain"], e["target"]) not in PROC_REMOVED]
            + [{"domain": d, "target": t} for d, t in PROC_ADDED], "the three narrowed /proc pairs and the gate's worker pair")
    old = [a["id"] for a in v4["assertions"]]
    new = [a["id"] for a in matrix["assertions"]]
    byid = {a["id"]: a for a in matrix["assertions"]}
    require(new[:len(old)] == old and tuple(new[len(old):]) == NEW_ASSERTIONS
            and all(byid[i] == a for i, a in zip(old, v4["assertions"]) if i not in CHANGED_ASSERTIONS)
            and all(byid[i] != a for i, a in zip(old, v4["assertions"]) if i in CHANGED_ASSERTIONS),
            "every v4 assertion keeps its index; exactly the disclosed ones change")
    for target, peers in PROC_PEERS.items():
        require(byid["A59." + target]["allow"] == peers
                and sorted(e["domain"] for e in matrix["procAccess"] if e["target"] == target) == peers,
                "the /proc peers as restated: " + target)
    require(byid["A09"]["allow"] == [GATE] and "planeon_gate_i04_key_t" in byid["A09"]["targets"]
            and byid["A67"]["allow"] == [GATE] and byid["A67"]["targets"] == ["planeon_gate_i04_cert_t"]
            and GATE not in byid["A48"]["allow"]
            and all(byid["A68." + cls]["allow"] == [] and byid["A68." + cls]["sources"] == [GATE]
                    for cls in ("capability", "capability2", "cap_userns", "cap2_userns")),
            "the I04 types, the gate's capabilities and the new assertions as restated")


def replay_v5_vectors(model: types.ModuleType, matrix: dict, vectors: dict, v4_vectors: dict) -> int:
    """Every access and mutation vector replays; every v4 vector keeps its identifier and position, unchanged apart from
    the listed v5 changes."""
    require(type(vectors) is dict and set(vectors) == {"evidenceClass", "accessChecks", "mutationChecks", "w02aSlots", "v5Changes"}
            and vectors["evidenceClass"] == "DATA_CHECK_ONLY" and vectors["w02aSlots"] == v4_vectors["w02aSlots"]
            == model.w02a_slots(matrix)
            and len(vectors["accessChecks"]) == COUNTS["accessChecks"] and len(vectors["mutationChecks"]) == COUNTS["mutationChecks"]
            and tuple(row["id"] for row in vectors["v5Changes"]) == V5_CHANGES, "closed matrix v5 vectors")
    # MET-PERF-040 (239 packet review P2-1): the cheap identifier and position checks run before the replay.
    changed = set(V5_CHANGES)
    for key in ("accessChecks", "mutationChecks"):
        old, new = v4_vectors[key], vectors[key][:len(v4_vectors[key])]
        ids = [r["id"] for r in vectors[key]]
        require(len(set(ids)) == len(ids) and [r["id"] for r in new] == [r["id"] for r in old]
                and {o["id"] for o, n in zip(old, new) if o != n} == {o["id"] for o in old} & changed,
                "every v4 %s vector is kept at its position; only the listed ones change" % key)
    for row in vectors["accessChecks"]:
        require(model.allowed(matrix, row["state"], row["source"], row["target"], row["class"], row["perm"]) is row["expect"],
                "access check " + row["id"])
    for row in vectors["mutationChecks"]:
        mutated = model.apply_ops(matrix, row["ops"])
        try:
            model.check_matrix(mutated)
            ok = row["expect"] == {"failedAssertions": model.failed_assertions(mutated)} and row["expect"]["failedAssertions"] != []
        except ValueError as exc:
            ok = set(row["expect"]) == {"matrixError"} and row["expect"]["matrixError"] == str(exc)
        require(ok, "mutation check " + row["id"])
    return len(vectors["accessChecks"]) + len(vectors["mutationChecks"])


def validate_selinux_matrix_v3() -> None:
    """Every reviewed byte and the review binding first; then v5 against v4, every assertion and the full replay."""
    for path in FROZEN_PATHS:
        require(path not in _PROJECTION_RULES, "the v3 and v4 matrices, HS43, W01 and the native profile stay byte-identical")
    for path in ERA_SHA256:
        _verified(path)
    validate_v5_status()
    matrix, v4 = _json(V5_DIR + "matrix.json"), _json(V4_DIR + "matrix.json")
    model = _era_model()
    model.check_matrix(matrix)
    require(model.failed_assertions(matrix) == [] and len(matrix["assertions"]) == COUNTS["assertions"]
            and len(matrix["types"]) == COUNTS["types"], "every deny assertion holds")
    validate_v5_successor(matrix, v4)
    replay_v5_vectors(model, matrix, _json(V5_DIR + "vectors.json"), _json(V4_DIR + "vectors.json"))


def validate() -> None:
    record = authority()
    validator_raw = successor.historical_bytes(VALIDATOR_PATH, regular_bytes(VALIDATOR_PATH))
    literal = b'AUTHORITY_SHA256 = "' + AUTHORITY_SHA256.encode("ascii") + b'"'
    placeholder = b'AUTHORITY_SHA256 = "TO_BE_PINNED_AFTER_SOURCE_FREEZE"'
    require(validator_raw.count(literal) == 1
            and digest(validator_raw.replace(literal, placeholder))
            == record["validatorNormalizedSha256"], "SELinux matrix v5 validator drift")
    paths = sorted((ROOT / "task-packets").glob("*.yaml"))
    old = set(record["baselinePackets"])
    require(len(paths) == 264
            and {path.stem for path in paths} == old | {NEW_PACKET, successor.NEW_PACKET, successor.successor.NEW_PACKET, successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.NEW_PACKET},
            "closed 264-packet catalog retaining the 239-packet checkpoint")
    packets = {}
    for path in paths:
        if path.stem in (successor.NEW_PACKET, successor.successor.NEW_PACKET, successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.NEW_PACKET):
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
            "closed source-only selinux-matrix-v3 packet and inherited commands")
    require(len(packet["allowedPaths"]) == len(set(packet["allowedPaths"]))
            and set(packet["allowedPaths"]) == set(record["changedFiles"])
            | set(record["newFiles"]) | {AUTHORITY_PATH, VALIDATOR_PATH,
                                         "task-packets/" + NEW_PACKET + ".yaml"},
            "unreviewed or omitted selinux-matrix-v3 packet path")
    for path, rule in record["changedFiles"].items():
        current = successor.historical_bytes(path, regular_bytes(path))
        require(digest(current) == rule["afterSha256"]
                and digest(historical_bytes(path, current)) == rule["beforeSha256"],
                "unreviewed current source: " + path)
    for path, expected in record["newFiles"].items():
        require(digest(successor.historical_bytes(path, regular_bytes(path))) == expected,
                "new source drift: " + path)
    validate_selinux_matrix_v3()


if __name__ == "__main__":
    validate()
    print("SELinux matrix v5 valid: 264 current specifications; 239-packet checkpoint and exact 238-packet predecessor; contract reviewed.")
