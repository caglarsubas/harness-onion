#!/usr/bin/env python3
"""Validate the MET-ENFORCE-035 W01 amendment HS53 and seccomp allowlists v5 and the exact 248-to-247 projection."""
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
    import validate_compiled_filter_programs_v3 as successor
except ImportError:
    from scripts.safe_yaml import safe_load
    from scripts import validate_compiled_filter_programs_v3 as successor


ROOT = Path(__file__).resolve().parents[1]
AUTHORITY_PATH = "architecture/seccomp-observer-listener-authority.json"
AUTHORITY_SHA256 = "5f7aedbd77a28ed4bd6d47430cafbfe5970aa902806bbfc8e853c6881d3baf15"
VALIDATOR_PATH = "scripts/validate_seccomp_observer_listener.py"
BASE_COMMIT = "422bd18a9b6974f5200120185d940d92288634b2"
NEW_PACKET = "MET-ENFORCE-035"
PREVIOUS_PACKET = "MET-ENFORCE-034"
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
            require(key not in result, "duplicate seccomp-observer-listener authority member")
            result[key] = value
        return result

    def no_constant(_value: str) -> Any:
        raise ValueError("nonfinite seccomp-observer-listener authority number")

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
        require(digest(raw) == AUTHORITY_SHA256, "seccomp observer listener history authority digest")
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
    }, "closed seccomp observer listener history authority")
    require(value["schemaVersion"] == "harness.planeon.ai/seccomp-observer-listener-authority/v1"
            and value["authorityPacket"] == NEW_PACKET
            and value["acceptedBase"] == BASE_COMMIT
            and type(value["baselinePackets"]) is dict
            and len(value["baselinePackets"]) == 247
            and NEW_PACKET not in value["baselinePackets"]
            and type(value["changedFiles"]) is dict
            and type(value["newFiles"]) is dict
            and _sha(value["packetSha256"])
            and _sha(value["validatorNormalizedSha256"]),
            "accepted 247-packet base")
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
    # An exact 247-era byte string is already older than the successor layer.
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


# MET-ENFORCE-035 (roadmap SECCOMP-OBSERVER-LISTENER, packet 1; owner decisions Q-SOL-2/4 and SOL-SYSTEMD-CLEANS, and the
# lane monitor's owner-delegated Q-SOL-1/3/5, F-SOL-1, Q-SOL-7 (a), Q-MX6-R6, SOL6-1 (a) and LOCAL-PATHS (b), 2026-10-16
# to 2026-10-18) publishes W01 amendment HS53 on top of the byte-identical HS43 effective text and the seccomp allowlists
# v5, the successor of the byte-identical v4, reviewed together: OBSERVER gets the I01 AF_UNIX SOCK_SEQPACKET listener
# (bind, listen, accept4 with flags 0, SOCK_CLOEXEC or SOCK_CLOEXEC|SOCK_NONBLOCK), the TCP-listen boundary is SELinux's,
# the socket's directory and mode come from the units, and systemd clears only the observer's stale path before it starts,
# under matrix v6's init_t grant. Repository bytes are read only through reviewed_bytes, so a later bridged successor
# projects its own edits away first. Every reviewed file of this era is bound by digest before anything is parsed and on
# every later read. The eight review rounds are bound to their exact subject bytes and the published records to the
# monitor's redaction; HS53's model is executed from this era's bytes and its record restated; v5's model replays every
# decision through the reference decision and the compiled program, the worker's stacked filters, every mutation and v4's
# decisions; matrix v6's own evaluator re-checks the init_t grant; and this layer's own inverse hunks are canonical.
HS = "architecture/host-interface-amendment-hs53/"
V5 = "architecture/seccomp-allowlists-v5/"
V4 = "architecture/seccomp-allowlists-v4/"
MX6 = "architecture/selinux-matrix-v4/"
HS_MODEL = "scripts/host_interface_amendment_v3.py"
V5_MODEL = "scripts/seccomp_allowlists_v5.py"
MX6_MODEL = "scripts/selinux_matrix_v4.py"
HS_STATUS, INDEX, V5_STATUS = HS + "status.json", HS + "source-index.json", V5 + "status.json"
SUBJECT = (HS + "amendment.json", HS + "HOST_INTERFACE_SPEC.md", HS + "README.md", HS + "REVIEW_BRIEF.md", HS_MODEL,
           V5 + "README.md", V5 + "REVIEW_BRIEF.md", V5 + "syscalls.json", V5 + "allowlists.json", V5 + "vectors.json",
           V5_MODEL)
DIGEST_ONLY = (V5 + "vectors.json",)
# HS43, the W01 inputs and catalog files HS53 reads, seccomp v4, matrix v5 and matrix v6 stay byte-identical.
FROZEN_PATHS = (
    "architecture/host-interface-amendment-hs43/amendment.json",
    "architecture/host-interface-amendment-hs43/HOST_INTERFACE_SPEC.md",
    "architecture/host-interface-inputs/corrected/HOST_INTERFACE_SPEC.md",
    "architecture/policy-observation-amendment.json",
    "architecture/seccomp-allowlists/README.md",
    "docs/alpha-2/BROKER_HANDOFF_READINESS.md",
    "docs/alpha-2/POLICY_OBSERVATION_READINESS.md",
    "architecture/seccomp-allowlists-v4/README.md",
    "architecture/seccomp-allowlists-v4/status.json",
    "architecture/seccomp-allowlists-v4/syscalls.json",
    "architecture/seccomp-allowlists-v4/allowlists.json",
    "architecture/seccomp-allowlists-v4/vectors.json",
    "scripts/seccomp_allowlists_v4.py",
    "architecture/selinux-matrix-v3/matrix.json",
    "architecture/selinux-matrix-v4/matrix.json",
    "architecture/selinux-matrix-v4/README.md",
    "scripts/selinux_matrix_v4.py",
)
ERA_SHA256 = MappingProxyType({
    "architecture/host-interface-amendment-hs43/HOST_INTERFACE_SPEC.md": "b4f46b3a79c45691d7029a79849a555aca5ca7a6e6c600958147935f806888e9",
    "architecture/host-interface-amendment-hs43/amendment.json": "6a3719cdc659d7ccfde3598bdec06a31896fa82de810cf73ccc1f7ca3dc7f24c",
    "architecture/host-interface-amendment-hs53/HOST_INTERFACE_SPEC.md": "fa7f36fb7d291ab5ffccfc51f9bae7b99ad1a2ef466fc0793dbe6e4182af1e75",
    "architecture/host-interface-amendment-hs53/README.md": "ece0b242ec28b90ff891570d4d72438c3e244e922f7580435c05cd90ad64f676",
    "architecture/host-interface-amendment-hs53/REVIEW_BRIEF.md": "310f57b8d3e079f82de1ac53cb03a3ab8d5745acb98b654a72a046e11106d9be",
    "architecture/host-interface-amendment-hs53/amendment.json": "e4255685a38f183d9cd5e5411ee83cc3dee6442e578831296d9789109824d763",
    "architecture/host-interface-amendment-hs53/review-round1.json": "3c61bfe50e8dcceb8588ed73d308b1ba3cbcc5780cc5c4cfe2dd2235746cbebb",
    "architecture/host-interface-amendment-hs53/review-round2.json": "f5eb711f951e8a6d831f505c09481f6584ae3cf0e923089827e8281b00706fa3",
    "architecture/host-interface-amendment-hs53/review-round3.json": "88213cff08c2ed6206d04c1a8a6bc8583a0c5519b743d805d44bebede4fc6409",
    "architecture/host-interface-amendment-hs53/review-round4.json": "5a8b8552e0b3dcc3669192298a2d2f540368b2d7844de693d7fbdaa214e24d1f",
    "architecture/host-interface-amendment-hs53/review-round5.json": "ba55a54bbcb4752cae0daa64bd91ca2e3932a9e7d12a3d8aa96e12fb60bf89de",
    "architecture/host-interface-amendment-hs53/review-round6.json": "27764aaa83b46d3a8d4a87108649ac821954a5c5f64aa7d12e2f34ea634b8615",
    "architecture/host-interface-amendment-hs53/review-round7.json": "897df943326a299f41bd351325f00ff89abc111b84e9f0aee74151825bec288a",
    "architecture/host-interface-amendment-hs53/review-round8.json": "360b8cd6934043bd7af06712611660c09f86f5544a6cac81623834916a1a04ab",
    "architecture/host-interface-amendment-hs53/round1/architecture/host-interface-amendment-hs53/HOST_INTERFACE_SPEC.md": "bbbe89aa3bf6c8f688dcbeb42ed422ca036e5247dac5513b17fcd312dbe292ea",
    "architecture/host-interface-amendment-hs53/round1/architecture/host-interface-amendment-hs53/README.md": "24dcd85a58cf1d2987e32fc88f0e991730dee1bc154678af02a2f11fa7301654",
    "architecture/host-interface-amendment-hs53/round1/architecture/host-interface-amendment-hs53/REVIEW_BRIEF.md": "f3622edb011ab66aa7973de80ab5fb065568793fdf2746cb93749bb1b40cecaa",
    "architecture/host-interface-amendment-hs53/round1/architecture/host-interface-amendment-hs53/amendment.json": "d2b302bf308eafc71853e3a0cd1dee99725a3d446a1889af36982db07eadd794",
    "architecture/host-interface-amendment-hs53/round1/architecture/seccomp-allowlists-v5/README.md": "3d0665d4f5a5dc8d349a155b2dc9b601f8cb9efbd51cbfdb94bcc021d0a0d82b",
    "architecture/host-interface-amendment-hs53/round1/architecture/seccomp-allowlists-v5/REVIEW_BRIEF.md": "97ce5e1efa5a860f23bc297b89e935ff95c4844c89f03dedb5524c101d6b39fc",
    "architecture/host-interface-amendment-hs53/round1/architecture/seccomp-allowlists-v5/allowlists.json": "bc62df4339088358a48e50ff37bed3594b41e399d232606a9691f25454b39911",
    "architecture/host-interface-amendment-hs53/round1/scripts/host_interface_amendment_v3.py": "6d054c78f6d849265abf85923f4c6f3b06866c4f2535657e74a37d71db8e4c3e",
    "architecture/host-interface-amendment-hs53/round1/scripts/seccomp_allowlists_v5.py": "3bc130c346ed5de004ab074fb40cc72fdb74d47406817c975519235c80a65907",
    "architecture/host-interface-amendment-hs53/round2/architecture/host-interface-amendment-hs53/HOST_INTERFACE_SPEC.md": "132ff8b14b5dcfc452fe2a4fefb6c3c143543a69bd56ee716d0177bba93af1e3",
    "architecture/host-interface-amendment-hs53/round2/architecture/host-interface-amendment-hs53/README.md": "87628a1f4143263573733bfda61c651174fa9e5a138f2187dbdb22ea4d97006b",
    "architecture/host-interface-amendment-hs53/round2/architecture/host-interface-amendment-hs53/REVIEW_BRIEF.md": "32f2e1c5e3b6f32ca0a1c3fa082948356f5a45ca0d73dc852efbfd205698fdb2",
    "architecture/host-interface-amendment-hs53/round2/architecture/host-interface-amendment-hs53/amendment.json": "de7f386b8cddc298a1133c73ced640105e66fe6f77248c32e2909212e709534e",
    "architecture/host-interface-amendment-hs53/round2/architecture/seccomp-allowlists-v5/README.md": "5aa7d50d9a5ce1e98543da17958cdda2d23c0c56aded7a4103183d9b48e11fd1",
    "architecture/host-interface-amendment-hs53/round2/architecture/seccomp-allowlists-v5/REVIEW_BRIEF.md": "1d01dc9699173ad70877be7ea1b060ef9b464fc4cbb68ba4d8f1c406289f1561",
    "architecture/host-interface-amendment-hs53/round2/architecture/seccomp-allowlists-v5/allowlists.json": "34681900bcc6a98ab331cff03472d373720d3d4e9e036e3cfefaa5795d3a3997",
    "architecture/host-interface-amendment-hs53/round2/scripts/host_interface_amendment_v3.py": "df50863f7004b849da0bd4f40d8826973b81f59a2dcf0362ca70fe4cfd98c512",
    "architecture/host-interface-amendment-hs53/round3/architecture/host-interface-amendment-hs53/HOST_INTERFACE_SPEC.md": "dd9760ec622a8f0ed0a4c3f39e70523210bc1e471e0823d6f2dc2e12c6a62b65",
    "architecture/host-interface-amendment-hs53/round3/architecture/host-interface-amendment-hs53/README.md": "c9920f8f41ba68749738f3f0321bc4857b71c1baa90eaee223c024897012da46",
    "architecture/host-interface-amendment-hs53/round3/architecture/host-interface-amendment-hs53/REVIEW_BRIEF.md": "5da8d9dcd9d1cf900d1a23146ccf8d78efc6f62d1ba0b1d19420fb3e95579388",
    "architecture/host-interface-amendment-hs53/round3/architecture/host-interface-amendment-hs53/amendment.json": "991a913c70a9c190989fe9ab9c3ab8c5d12b3eb99e01cc80384f58721b02c212",
    "architecture/host-interface-amendment-hs53/round3/architecture/seccomp-allowlists-v5/README.md": "c2388f3bcb60a4e6f2261bda09335a7260f20a0eb05fc5d38975a4057bbdf64e",
    "architecture/host-interface-amendment-hs53/round3/architecture/seccomp-allowlists-v5/REVIEW_BRIEF.md": "a869d94145c8c1f3fa7b9745acf921d26ec1e210991cd52fe0786b2c3d7a7526",
    "architecture/host-interface-amendment-hs53/round3/architecture/seccomp-allowlists-v5/allowlists.json": "f326b407aad2489c4349829864f0084f0835e25613a4a2ad44da7ebeb12de3ae",
    "architecture/host-interface-amendment-hs53/round3/scripts/host_interface_amendment_v3.py": "c46aeefffcb00e7972fe6657b83517a916584bf31f2a448ace5d1afb54f98285",
    "architecture/host-interface-amendment-hs53/round4/architecture/host-interface-amendment-hs53/HOST_INTERFACE_SPEC.md": "1847fc69fb219f6f5db3561289a6f0bd65f6569a42b730c11cb299a7554b6371",
    "architecture/host-interface-amendment-hs53/round4/architecture/host-interface-amendment-hs53/README.md": "03f8706cbe6a6ba3a09d06a76306a91a9bbde2baf68e0380c5524e97041c19d2",
    "architecture/host-interface-amendment-hs53/round4/architecture/host-interface-amendment-hs53/REVIEW_BRIEF.md": "c0c91d6df5b7e1d0b8ead3220ab31ce8d9e57891b34ebb24ffa9837ad4607bed",
    "architecture/host-interface-amendment-hs53/round4/architecture/host-interface-amendment-hs53/amendment.json": "8ce40f7c7245154ad569d9d7e01ad8a57ef940ba02891df242aa59c5995fe8ab",
    "architecture/host-interface-amendment-hs53/round4/architecture/seccomp-allowlists-v5/README.md": "a53840583d3f1fc30fdb0303ef94595f2c79f691fbeb69226c81e82263c57c7f",
    "architecture/host-interface-amendment-hs53/round4/architecture/seccomp-allowlists-v5/REVIEW_BRIEF.md": "0f86034c6f4ad0ee70306b4edbc9749099f2075f6cc0e4a67d427436ee220c02",
    "architecture/host-interface-amendment-hs53/round4/scripts/host_interface_amendment_v3.py": "dadadc45f7f703404d9c872cf45bf2b84c43570e17aa8e534b15e4df418f0286",
    "architecture/host-interface-amendment-hs53/round5/architecture/host-interface-amendment-hs53/HOST_INTERFACE_SPEC.md": "0359f36e6a23c87bf26ec9c90092638d9d438c600f6d2e709842b70c3e17aad3",
    "architecture/host-interface-amendment-hs53/round5/architecture/host-interface-amendment-hs53/README.md": "dd06f2a29a883b69c231c7826891d1062929b41f48fa4c2b95c10098e9173236",
    "architecture/host-interface-amendment-hs53/round5/architecture/host-interface-amendment-hs53/REVIEW_BRIEF.md": "e12cade23c8f9b5df8c95df15adf6592a92e92af2e0f76ceaaee78c2be8cc2b4",
    "architecture/host-interface-amendment-hs53/round5/architecture/host-interface-amendment-hs53/amendment.json": "0c4d40fe6891e49cae9483ab58d7e79fc735cceba63bb190b99f7a9757362858",
    "architecture/host-interface-amendment-hs53/round5/architecture/seccomp-allowlists-v5/README.md": "b64b564147ffd0c68f4de276bae672b18235a591467925c59a9d65a9f1e987ef",
    "architecture/host-interface-amendment-hs53/round5/architecture/seccomp-allowlists-v5/REVIEW_BRIEF.md": "51c2a5f57759c90ce59015f5b43991ea7935cc4939a99c6fbf22022972b6089d",
    "architecture/host-interface-amendment-hs53/round5/scripts/host_interface_amendment_v3.py": "ef2186a76e6e956d2f0426ecaf8ed56fa039dfbcea8536360b537f204cff30b9",
    "architecture/host-interface-amendment-hs53/round6/architecture/host-interface-amendment-hs53/README.md": "0c833856fb6507ba1559e1687c67e8700b8fe745f936ac5d1cd173fb15fcaf69",
    "architecture/host-interface-amendment-hs53/round6/architecture/host-interface-amendment-hs53/REVIEW_BRIEF.md": "66fc6aea6b95fcce9a814535ff67e6aae2ff6de7f5641469d52f18ba5217b815",
    "architecture/host-interface-amendment-hs53/round6/architecture/host-interface-amendment-hs53/amendment.json": "ca8e8d61795f1ae0479c16f04d23b6cd0e20ff9866b9921f2c67d8d7a3d1ca6e",
    "architecture/host-interface-amendment-hs53/round6/architecture/seccomp-allowlists-v5/README.md": "f9ffc01a22605f57194e0d0f5a3590ba8a7c7612361c7a28f439f880d6fd2149",
    "architecture/host-interface-amendment-hs53/round6/architecture/seccomp-allowlists-v5/REVIEW_BRIEF.md": "886d5fa34a7336d5f14fe0ef261ffc39faf7590f77b077aeba5c165e2e94bff5",
    "architecture/host-interface-amendment-hs53/round6/scripts/host_interface_amendment_v3.py": "8ced0ec22d7d66b90cc4ea5e706e9f24e91c512c371f12836ad20c5601ed4a13",
    "architecture/host-interface-amendment-hs53/round7/architecture/host-interface-amendment-hs53/README.md": "36971ffb8d791d8db124b2be96cdcd62cd725c5b5d995f0cfc4ce62b18ccfdfe",
    "architecture/host-interface-amendment-hs53/round7/architecture/host-interface-amendment-hs53/REVIEW_BRIEF.md": "cf15d278ad473f71d684b89fca61afcb0c801f21372653977d9ea0fcb47788ff",
    "architecture/host-interface-amendment-hs53/round7/architecture/seccomp-allowlists-v5/README.md": "61363c7a85d95ff97ffabe64fc90d1ccf97ad89ad1bd9631a35ed8b7df43105b",
    "architecture/host-interface-amendment-hs53/round7/architecture/seccomp-allowlists-v5/REVIEW_BRIEF.md": "ae09a534fd20e1f393ab3deb9ad3d82910dedf150d3ceb751a8e69657c501c9c",
    "architecture/host-interface-amendment-hs53/source-index.json": "e775f028747b0d655305d1031e8385fe1ccf5ea5c4fc30c8d2aff328813523dd",
    "architecture/host-interface-amendment-hs53/status.json": "753a984c2ca721c4e53b873118ff2b513391a722633fa19b905e3dc6e4234c93",
    "architecture/host-interface-inputs/corrected/HOST_INTERFACE_SPEC.md": "1b0bee7e46e3cd730b3f878179ac36d0f062ce70ed6c843788ab634aead16ef0",
    "architecture/policy-observation-amendment.json": "0df7e72a65fc5eb1c20d59b8c62ebff377f160214192d681ea7f3d29b57e38c7",
    "architecture/seccomp-allowlists-v4/README.md": "bdca37825c2e6a6f7d8797c256fab7e891fb26b6660dcb78a84f3613cde54f25",
    "architecture/seccomp-allowlists-v4/allowlists.json": "4dcfb2dfea82eabd04024b35d9dac4bb487b6c0051f7e6e16bbd00426cf6b2ff",
    "architecture/seccomp-allowlists-v4/status.json": "b2f82f66bf9ebb6cc52b7f8e9503250604e7b46310bccdd14e635f3ff08a21dc",
    "architecture/seccomp-allowlists-v4/syscalls.json": "d759e341afcbcf2dccd8eafce136a303d2275efceeac1525ef2200b6e65fe53d",
    "architecture/seccomp-allowlists-v4/vectors.json": "9a918c15bbcb6378b282df9a5da8389289bf505f9f8eb5e1a50b9c5bb6f92187",
    "architecture/seccomp-allowlists-v5/README.md": "b9fe31df72c029ac2d8df97c2719c37cbd6d87e173c923a40bb07830d285e7df",
    "architecture/seccomp-allowlists-v5/REVIEW_BRIEF.md": "e5d71eccde2d81247d9a4f2622e1140a44ae81d82cbd639f608cd1664a62027f",
    "architecture/seccomp-allowlists-v5/allowlists.json": "879909a86037b153a951770b4a47a8c075364fbd7cf9a44405537807621b55a8",
    "architecture/seccomp-allowlists-v5/status.json": "3abd0a6e1241529c21751ed93ce9a48852391c00143bd29382465f2f6267ca02",
    "architecture/seccomp-allowlists-v5/syscalls.json": "fe9a603e780b576f666a219da119eedad5271a675998aba2d6d581fb53ebac07",
    "architecture/seccomp-allowlists-v5/vectors.json": "4539410a9bb66e2aca62931567253c3c70b382672cc2b8f8207d4ea3d4661ecd",
    "architecture/seccomp-allowlists/README.md": "510b41f0b13b1463f2b79651d438880c9342026aab6127da7de363df7d475139",
    "architecture/selinux-matrix-v3/matrix.json": "01e4f3cfd75250dc6fd74f666cfa53758f83b7a07d7a39a0ca180f5588496b73",
    "architecture/selinux-matrix-v4/README.md": "70c537948532496737ec6228306db015f2c93b6df4bdeb0c476d3481b1861c40",
    "architecture/selinux-matrix-v4/matrix.json": "3d2830b879f953ce4ae72e63bf7adb85f83e620ae5925297010d8224012b3149",
    "docs/alpha-2/BROKER_HANDOFF_READINESS.md": "2cc6ebef252efb33744208378b29248d89597e5a0be7c4a1a113adc9d63b9fc3",
    "docs/alpha-2/POLICY_OBSERVATION_READINESS.md": "65778040919c5eb7335f2c104d983ca920b877b1b123f961556a6bcae36d232c",
    "scripts/host_interface_amendment_v3.py": "86abc79670c4534602b023855ce74e99eab8d6497bdfe745a8c52d18bd4468c0",
    "scripts/seccomp_allowlists_v4.py": "f88e3eab1a154260b2a33d7a1eadb5a78f29d49579219d3aaf55041ec861e9bf",
    "scripts/seccomp_allowlists_v5.py": "fc57bb40f4f2537005e46689d9fc39a0dd98d4ebe141f9aace961e9520f1e0a7",
    "scripts/selinux_matrix_v4.py": "6bad8c5325e2677cc86caf320e734d677bce2aca50e1640ed5c49e4b158d809a",
})
ROUND_COMMITS = (
    "97b294d3282b8b1e555c84ad1ae3847f053e8603", "55c380a1f5358e3a8cace8d4f862aa44144188a4",
    "5d75b55f35f4aa4f4014d93fafb8a91c8b339364", "69a3b8f9dbb1a4a091ac1e6bb1e9c4a85cc05bdd",
    "08355e022ed839bbcfa4cbf071c45d49acac5429", "065c4ca46ff5f0196aff48604656c358be78ed44",
    "ab83c9c0ebc970d2172a280e796141b833810052", "c97a2df22b6ebe7e1905afb1aae2292721aba12e",
)
REVIEW_VERDICTS = ("CHANGES_REQUIRED",) * 7 + ("PASS_FOR_SOURCE_PUBLICATION",)
PASS_SUBJECT = ROUND_COMMITS[-1]
AUTHORING_BASE = "75669de34d6305abca3bf2ddf3699f1dbb888c6e"
MATRIX_V6_MERGE = "422bd18a9b6974f5200120185d940d92288634b2"
CARRIED_EARLIER = {"SOL6-2": 6, "SOL6-3": 6, "SOL6-5": 6, "SOL7-2": 7, "SOL7-3": 7}
ANSWERED_WITHOUT_CHANGE = {"SOL1-9": "NOTE answered in candidate 2's README table without a change"}
CARRIED = ("SOL6-2", "SOL6-3", "SOL6-5", "SOL7-2", "SOL7-3", "SOL8-1", "SOL8-2", "SOL8-3", "SOL8-4", "SOL8-5")
DESIGN_LABEL = "HOST-INTERFACE-DRAFT-002-HS53"
ITEMS = ("E1", "E2", "H1", "H2", "H3", "E3")
DECISIONS = ("Q-SOL-1", "Q-SOL-2", "Q-SOL-3", "Q-SOL-4", "F-SOL-1", "Q-SOL-5", "SOL-SYSTEMD-CLEANS", "Q-SOL-7", "Q-MX6-R6")
OBLIGATIONS = ("O-SECCOMP-V5-OBSERVER-LISTENER", "O-W03-OBSERVER-UNIT", "O-W03-OBSERVER-PRESTART", "O-W03-OBSERVER-TCP",
               "O-T04-HS53", "O-MATRIX-OBSERVER-TCP", "O-MATRIX-OBSERVER-SOCK-CLEAR", "O-PROGRAMS-V3-OBSERVER",
               "O-R10-HE004-I01")
RESIDUALS = ("R-OBSERVER-TCP-LISTEN",)
SUPERSEDED_COUNT, NOT_AMENDED_COUNT = 8, 9
REVIEW_DECISIONS = ("SOL2-6-CONFIRM", "SOL4-7-ACCEPT", "SOL6-1-MONITOR")
V4_DECISIONS = ("W02d-Q1", "W02d-Q2", "W02d-Q3", "W01-AMEND-QW1", "W01-AMEND-QW2", "W01-AMEND-QW3", "W02d-V3",
                "W01-AMEND-QW4", "Q-HE3A-1", "Q-HE3A-1b", "HS43-START", "SECCOMP-DIRFD-DIRECTION", "SEC-RL-START")
V5_DECISIONS = V4_DECISIONS + ("Q-SOL-1", "Q-SOL-2", "Q-SOL-3", "Q-SOL-4", "F-SOL-1", "Q-SOL-5", "SOL-SYSTEMD-CLEANS",
                               "Q-SOL-7")
OBSERVER = "OBSERVER"
# The OBSERVER listener rules (HS53 H1, Q-SOL-2): bind and listen unconditioned, accept4 only with the three flag values.
FULL = 0xFFFFFFFF
OBSERVER_LISTENER = [{"name": "bind"}, {"name": "listen"},
                     {"name": "accept4", "when": [[{"arg": 3, "eq": value, "mask": FULL}] for value in (0, 0x80000, 0x80800)]}]
V4_FLIPS = (("D0490", "x86_64", "accept4"), ("D0497", "x86_64", "bind"), ("D0575", "x86_64", "listen"),
            ("D0738", "aarch64", "accept4"), ("D0739", "aarch64", "bind"), ("D0816", "aarch64", "listen"))
COUNTS = {"decisionChecks": 3069, "workerStackChecks": 365, "policyMutations": 29, "v4Decisions": 2971,
          "v4Mutations": 23}
LISTENER_SOCKETS = ("planeon_i05_sock_t", "planeon_i07_sock_t", "planeon_observer_sock_t", "planeon_broker_sock_t")
SOCK_FILE_PERMS = ("getattr", "unlink", "read", "write", "create", "setattr", "rename", "link", "append", "ioctl", "lock",
                   "open", "relabelfrom", "relabelto")
# LOCAL-PATHS (b): the reviewers' scratch prefix (in hex, so this file holds no path) became <scratch>/ in rounds 1-7.
REDACTION_FROM, REDACTION_TO = bytes.fromhex("2f707269766174652f746d702f"), b"<scratch>/"
LOCAL_PATH_MARKERS = (b"/users/", b"/private/", b"/home/", b".local/state", b"/tmp/claude")
PATH_FOLLOWERS = frozenset(b"abcdefghijklmnopqrstuvwxyz0123456789._-~/")
HS_FALSE = ("implementationReady", "filtersInstalled", "roleCodeChanged", "nativeAcceptance", "tenantAcceptance",
            "productExecution", "runnerActivated", "phaseComplete")
V5_FALSE = ("nativeAcceptance", "tenantAcceptance", "filtersInstalled", "roleCodeExists", "traceValidated",
            "distributionSelected", "productExecution", "runnerActivated", "phaseComplete")
HS_STATUS_KEYS = frozenset({"schemaVersion", "designLabel", "amends", "effective", "jointReview", "reviewRounds",
                            "closedFindings", "carriedFindings", "ownerDecisions", "reviewDecisions", "supersededClauses",
                            "residuals", "obligations", "matrixV6InitTGrant", "enforcementObligations", "contractState",
                            "independentReviewer", "readmeStatusNote", "postReviewRedactions", *HS_FALSE})
V5_STATUS_KEYS = frozenset({"schemaVersion", "contract", "kernel", "supersedes", "discharges", "ownerDecisions",
                            "jointReview", "carriedToW03", "openObligations", "contractState", "obligations",
                            "independentReviewer", "readmeStatusNote", *V5_FALSE})
ROUND_KEYS = frozenset({"round", "record", "recordSha256", "verdict", "subjectCommit", "subjectTree", "subjectSha256",
                        "subjectDirectory"})


def reviewed_bytes(path: str) -> bytes:
    """This packet's reviewed bytes of path; a bridged successor projects newer bytes back first."""
    return successor.historical_bytes(path, regular_bytes(path))


def _verified(path: str) -> bytes:
    """reviewed_bytes, checked against its era digest on every read; a path outside the era is refused."""
    expected = ERA_SHA256.get(path)
    require(expected is not None, "MET-ENFORCE-035 reviewed bytes are bound: " + path)
    raw = reviewed_bytes(path)
    require(type(raw) is bytes and digest(raw) == expected, "unreviewed seccomp observer listener source: " + path)
    return raw


def _json(path: str) -> Any:
    return parse(_verified(path))


def _era_model(path: str, name: str) -> types.ModuleType:
    """A reference model of this era, executed from its verified bytes."""
    module = types.ModuleType(name)
    module.__file__ = str(ROOT / path)
    exec(compile(_verified(path), path, "exec", dont_inherit=True), module.__dict__)
    return module


def local_paths(raw: bytes) -> list:
    """Every marker occurrence followed by a path character: an absolute local path, not a quoted pattern."""
    low, hits = raw.lower(), []
    for marker in LOCAL_PATH_MARKERS:
        at = low.find(marker)
        while at != -1:
            end = at + len(marker)
            if end < len(low) and (low[end] in PATH_FOLLOWERS or low[end] >= 0x80):
                hits.append((marker, at))
            at = low.find(marker, at + 1)
    return hits


def validate_sol_review() -> dict:
    """The HS53 status is closed, its eight rounds are bound to their exact subject bytes, every earlier finding is closed
    or carried, the published records carry exactly the monitor's redaction, and the index binds subject and inputs."""
    status = _json(HS_STATUS)
    require(type(status) is dict and set(status) == HS_STATUS_KEYS
            and status["schemaVersion"] == "planeon.internal.host-interface-amendment-status/v1"
            and status["designLabel"] == DESIGN_LABEL and status["contractState"] == "ADOPTED_AMENDMENT"
            and status["jointReview"] == {"with": V5, "status": V5_STATUS}
            and status["ownerDecisions"] == list(DECISIONS) and status["obligations"] == list(OBLIGATIONS)
            and status["residuals"] == list(RESIDUALS) and status["supersededClauses"] == SUPERSEDED_COUNT
            and tuple(row["id"] for row in status["reviewDecisions"]) == REVIEW_DECISIONS
            and status["enforcementObligations"] == "E01-E12 OPEN_UNPROVEN"
            and all(status[flag] is False for flag in HS_FALSE),
            "adopted after the round-8 pass, reviewed with seccomp v5, nothing installed")
    rounds = status["reviewRounds"]
    require(type(rounds) is list and len(rounds) == len(ROUND_COMMITS)
            and all(type(row) is dict and set(row) == ROUND_KEYS | ({"keptCopies", "digestOnly"} if n < len(rounds) else set())
                    for n, row in enumerate(rounds, 1))
            and tuple(row["verdict"] for row in rounds) == REVIEW_VERDICTS
            and tuple(row["subjectCommit"] for row in rounds) == ROUND_COMMITS
            and rounds[-1]["subjectDirectory"] == "CURRENT", "the eight review rounds as restated")
    records = {}
    for number, row in enumerate(rounds, 1):
        raw = _verified(row["record"])
        record = parse(raw)
        records[number] = record
        kept = row.get("keptCopies", [])
        require(row["round"] == number and row["record"] == HS + "review-round%d.json" % number
                and digest(raw) == row["recordSha256"] and record["round"] == number
                and record["subjectCommit"] == row["subjectCommit"] and record["subjectTree"] == row["subjectTree"]
                and record["verdict"] == row["verdict"]
                and row["subjectDirectory"] == (HS + "round%d/" % number if number < len(rounds) else "CURRENT")
                and set(kept) <= set(SUBJECT) and set(kept).isdisjoint(DIGEST_ONLY)
                and row.get("digestOnly", list(DIGEST_ONLY)) == list(DIGEST_ONLY)
                and set(row["subjectSha256"]) == set(SUBJECT)
                and all(digest(_verified(row["subjectDirectory"] + path if path in kept else path)) == row["subjectSha256"][path]
                        for path in SUBJECT if number == len(rounds) or path not in DIGEST_ONLY),
                "review round %d is bound to its exact subject bytes" % number)
    require(all(type(row) is dict and row.get("severity") == "NOTE" for row in records[len(rounds)]["findings"]),
            "the final round passes with notes only")
    earlier = {f["id"]: (n, f) for n in range(1, len(rounds)) for f in records[n]["findings"]}
    require(all(earlier[fid][0] == n and earlier[fid][1]["severity"] == "NOTE" for fid, n in CARRIED_EARLIER.items())
            and set(status["carriedFindings"]) == set(CARRIED)
            == set(CARRIED_EARLIER) | {f["id"] for f in records[len(rounds)]["findings"]}
            and status["closedFindings"] == {fid: ANSWERED_WITHOUT_CHANGE.get(fid, "CLOSED in round %d" % (n + 1))
                                             for fid, (n, _) in earlier.items() if fid not in CARRIED_EARLIER},
            "every earlier finding closed in the next round or answered, except the restated carried notes")
    redaction = status["postReviewRedactions"]
    files = redaction["files"]
    require(set(redaction) == {"decision", "replacement", "placeholder", "files"}
            and redaction["replacement"] == {"replacedHex": REDACTION_FROM.hex(), "replacedLength": len(REDACTION_FROM),
                                             "replacedForm": redaction["replacement"]["replacedForm"],
                                             "by": REDACTION_TO.decode()}
            and [row["path"] for row in files] == [row["record"] for row in rounds[:-1]]
            and all(set(row) == {"path", "beforeSha256", "afterSha256", "count"} and row["count"] == 1
                    and row["afterSha256"] == ERA_SHA256[row["path"]] != row["beforeSha256"]
                    and digest(_verified(row["path"]).replace(REDACTION_TO, REDACTION_FROM)) == row["beforeSha256"]
                    for row in files)
            and all(REDACTION_FROM not in _verified(row["path"]) and _verified(row["path"]).count(REDACTION_TO) == row["count"]
                    for row in files)
            and REDACTION_FROM not in _verified(rounds[-1]["record"]), "the records carry exactly the monitor's redaction")
    index = _json(INDEX)
    require(type(index) is dict and index["schemaVersion"] == "planeon.internal.host-interface-amendment-hs53-index/v1"
            and index["round"] == len(rounds) and index["subjectCommit"] == PASS_SUBJECT
            and index["baseCommit"] == AUTHORING_BASE
            and [row["path"] for row in index["subject"]] == list(SUBJECT)
            and all(digest(_verified(row["path"])) == row["sha256"] for row in index["subject"])
            and [row["path"] for row in index["predecessorInputs"]] == list(FROZEN_PATHS)
            and all(digest(_verified(row["path"])) == row["sha256"] for row in index["predecessorInputs"])
            and [row["commit"] for row in index["predecessorInputs"] if "commit" in row] == [MATRIX_V6_MERGE] * 3
            and [row["path"] for row in index["earlierRounds"]] == [row["record"] for row in rounds[:-1]]
            and all(digest(_verified(row["path"])) == row["sha256"] for row in index["earlierRounds"]),
            "the reviewed subject and its inputs are the published ones")
    return status


def validate_hs53(model: types.ModuleType) -> None:
    """HS53's own model passes on this era's bytes, and its record is as restated."""
    record = model.check(_verified)
    require(record["designLabel"] == DESIGN_LABEL and tuple(item["id"] for item in record["items"]) == ITEMS
            and tuple(row["id"] for row in record["ownerDecisions"]) == DECISIONS
            and tuple(row["id"] for row in record["obligations"]) == OBLIGATIONS
            and tuple(row["id"] for row in record["residuals"]) == RESIDUALS
            and len(record["supersedes"]) == SUPERSEDED_COUNT and len(record["notAmended"]) == NOT_AMENDED_COUNT,
            "the HS53 record as restated")
    status = _json(HS_STATUS)
    require(status["effective"] == record["effective"] and status["amends"]["designLabel"] == record["base"]["designLabel"]
            and status["amends"]["path"] == record["base"]["path"] and status["amends"]["sha256"] == record["base"]["sha256"],
            "the status names the record's base and effective text")


def validate_v5_status(policy: dict) -> None:
    status = _json(V5_STATUS)
    require(type(status) is dict and set(status) == V5_STATUS_KEYS
            and status["schemaVersion"] == "planeon.internal.seccomp-allowlists-status/v5"
            and status["contract"] == "planeon.internal.seccomp-allowlists/v5"
            and status["supersedes"] == {"directory": V4, "contract": "planeon.internal.seccomp-allowlists/v4",
                                         "status": V4 + "status.json"}
            and status["discharges"]["obligation"] == OBLIGATIONS[0] and status["discharges"]["record"] == HS + "amendment.json"
            and status["jointReview"] == {"with": HS, "status": HS_STATUS, "sourceIndex": INDEX,
                                          "rounds": len(ROUND_COMMITS), "passSubject": PASS_SUBJECT}
            and status["ownerDecisions"] == policy["ownerDecisions"]
            and status["carriedToW03"] == _json(V4 + "status.json")["carriedToW03"]
            and status["contractState"] == "ADOPTED_DATA_CONTRACT"
            and status["obligations"] == {"E%02d" % n: "OPEN_UNPROVEN" for n in range(1, 13)}
            and status["independentReviewer"] == "SEPARATE_AGENT_NOT_AUTHOR"
            and all(status[flag] is False for flag in V5_FALSE), "v5 adopted with the joint review, nothing installed")


def replay_v5(model: types.ModuleType, table: dict, policy: dict, vectors: dict, v4_vectors: dict) -> int:
    """Every decision replays through the reference decision and the compiled program; the worker's stacked filters decide
    as its own; every mutation is refused with its stated message; the digests are the compiled programs'; v4's decisions
    flip exactly as v5Changes lists; and every v4 vector keeps its identifier and position."""
    require(table.get("schemaVersion") == "planeon.internal.seccomp-syscall-table/v5"
            and table.get("kernel") == {"commit": "adc218676eef25575469234709c2d87185ca223a", "tag": "v6.12"}
            and policy.get("schemaVersion") == "planeon.internal.seccomp-allowlists/v5" and policy.get("mode") == 2
            and policy.get("defaultAction") == "KILL_PROCESS"
            and tuple(row.get("id") for row in policy["ownerDecisions"]) == V5_DECISIONS, "closed v5 table and policy")
    model.check_policy(policy, table)
    require(type(vectors) is dict and set(vectors) == {"evidenceClass", "filterDigests", "programLengths", "decisionChecks",
                                                       "workerStackChecks", "policyMutations", "v5Changes"}
            and vectors["evidenceClass"] == "DATA_CHECK_ONLY"
            and all(len(vectors[key]) == COUNTS[key] for key in ("decisionChecks", "workerStackChecks", "policyMutations")),
            "closed v5 vectors")
    programs = {(role, arch): model.compile_filter(policy, table, role, arch) for role in model.ROLES for arch in model.ARCHES}
    require(vectors["filterDigests"] == {role: {arch: "sha256:" + digest(model.program_bytes(programs[role, arch]))
                                                for arch in model.ARCHES} for role in model.ROLES}
            and vectors["programLengths"] == {role: {arch: len(programs[role, arch]) for arch in model.ARCHES}
                                              for role in model.ROLES}, "the published v5 digests are the compiled programs'")
    v4_raw = _verified(V4 + "vectors.json")
    require({role for role in model.ROLES if vectors["filterDigests"][role] != v4_vectors["filterDigests"][role]} == {OBSERVER},
            "only OBSERVER's digests change from v4")
    for key in ("decisionChecks", "policyMutations"):
        ids = [row["id"] for row in vectors[key]]
        require(len(set(ids)) == len(ids) and ids[:len(v4_vectors[key])] == [row["id"] for row in v4_vectors[key]],
                "every v4 %s vector keeps its identifier and position" % key)
    checks, by_id = 0, {}
    for row in vectors["decisionChecks"]:
        data = model.seccomp_data(row["nr"], row["auditArch"], row["args"])
        expect = model.action_name(model.decide(policy, table, row["role"], row["arch"], row["auditArch"], row["nr"], row["args"]))
        require(expect == row["expect"] == model.action_name(model.run_filter(programs[row["role"], row["arch"]], data)),
                "v5 decision check " + row["id"])
        by_id[row["id"]] = row
        checks += 1
    for row in vectors["workerStackChecks"]:
        base = by_id[row["decision"]]
        require(base["role"] == "WORKER" and row["expect"] == "SAME_AS_WORKER"
                and model.decide_stack(policy, table, ["BROKER", "WORKER"], base["arch"], base["auditArch"], base["nr"], base["args"])
                == model.decide(policy, table, "WORKER", base["arch"], base["auditArch"], base["nr"], base["args"]),
                "v5 worker stack check " + row["id"])
        checks += 1
    for row in vectors["policyMutations"]:
        changed = copy.deepcopy(policy)
        changed["roles"][row["role"]]["duties"].append(row["addDuty"])
        try:
            model.check_policy(changed, table)
            refused = None
        except ValueError as exc:
            refused = str(exc)
        require(refused is not None and refused == row["expect"], "v5 policy mutation " + row["id"])
        checks += 1
    flips = []
    for row in v4_vectors["decisionChecks"]:
        now = model.action_name(model.decide(policy, table, row["role"], row["arch"], row["auditArch"], row["nr"], row["args"]))
        if now != row["expect"]:
            flips.append((row["id"], row["arch"], row["role"], row["expect"], now))
    changes = vectors["v5Changes"]
    require(len(v4_vectors["decisionChecks"]) == COUNTS["v4Decisions"]
            and len(v4_vectors["policyMutations"]) == COUNTS["v4Mutations"]
            and changes["source"] == V4 + "vectors.json" and changes["sha256"] == digest(v4_raw)
            and changes["decisions"] == COUNTS["v4Decisions"] and changes["unchanged"] == COUNTS["v4Decisions"] - len(V4_FLIPS)
            and [(r["v4Id"], r["arch"], r["syscall"]) for r in changes["changed"]] == list(V4_FLIPS)
            and [(f[0], f[1], f[2], f[3], f[4]) for f in flips]
            == [(r["v4Id"], r["arch"], r["role"], r["v4Expect"], r["v5Expect"]) for r in changes["changed"]]
            and all(r["role"] == OBSERVER and r["v4Expect"] == "KILL_PROCESS" and r["v5Expect"] == "ALLOW"
                    for r in changes["changed"]), "v4's decisions flip exactly as v5Changes lists")
    return checks


def validate_observer_listener(model: types.ModuleType, table: dict, policy: dict) -> None:
    """OBSERVER's listener rules and accept4 outcomes, restated independently of the record."""
    rules = [{key: rule[key] for key in ("name", "when") if key in rule} for duty in policy["roles"][OBSERVER]["duties"]
             for rule in duty["rules"] if rule["name"] in model.LISTENER_CALLS + ("accept",)]
    require(rules == OBSERVER_LISTENER and model.OBSERVER_ACCEPT4_FLAGS == (0, 0x80000, 0x80800),
            "OBSERVER's listener rules as restated")
    for arch in model.ARCHES:
        audit, nr = table["arches"][arch]["auditArch"], table["syscalls"]["accept4"][arch]["nr"]
        program = model.compile_filter(policy, table, OBSERVER, arch)
        for flags, expected in ((0, "ALLOW"), (0x80000, "ALLOW"), (0x80800, "ALLOW"), (0x800, "KILL_PROCESS"),
                                (0x80001, "KILL_PROCESS"), (0x100080000, "ALLOW")):
            args = [3, 0, 0, flags, 0, 0]
            require(model.action_name(model.decide(policy, table, OBSERVER, arch, audit, nr, args)) == expected
                    == model.action_name(model.run_filter(program, model.seccomp_data(nr, audit, args))),
                    "OBSERVER's accept4 outcome as restated: %s %#x" % (arch, flags))


def validate_init_t_grant(status: dict) -> None:
    """Matrix v6's own evaluator, from this era's bytes: init_t may only getattr and unlink the four listener socket files."""
    matrix = _json(MX6 + "matrix.json")
    evaluator = _era_model(MX6_MODEL, "_met_enforce_035_selinux_matrix_v4")
    states = [s if isinstance(s, str) else s["name"] for s in matrix["states"]]
    granted = sorted({perm for state in states for target in LISTENER_SOCKETS for perm in SOCK_FILE_PERMS
                      if evaluator.allowed(matrix, state, "init_t", target, "sock_file", perm)})
    grant = status["matrixV6InitTGrant"]
    require(granted == ["getattr", "unlink"]
            and grant == {"matrix": MX6 + "matrix.json", "commit": MATRIX_V6_MERGE, "evaluator": MX6_MODEL, "states": states,
                          "sockets": list(LISTENER_SOCKETS), "granted": granted, "result": grant["result"]},
            "matrix v6's init_t grant as HS53 relies on it")


def validate_seccomp_observer_listener() -> None:
    """Every reviewed byte and the review binding first; then HS53's model, the full v5 replay, the listener and the
    init_t grant from this era; last, this layer's canonical hunks."""
    for path in FROZEN_PATHS:
        require(path not in _PROJECTION_RULES, "HS43, the W01 inputs, seccomp v4 and matrices v5 and v6 stay byte-identical")
    for path in ERA_SHA256:
        raw = _verified(path)
        require(path in FROZEN_PATHS or not local_paths(raw), "no absolute local path in an era file: " + path)
    status = validate_sol_review()
    validate_hs53(_era_model(HS_MODEL, "_met_enforce_035_host_interface_amendment_v3"))
    table, policy, vectors = _json(V5 + "syscalls.json"), _json(V5 + "allowlists.json"), _json(V5 + "vectors.json")
    validate_v5_status(policy)
    model = _era_model(V5_MODEL, "_met_enforce_035_seccomp_allowlists_v5")
    replay_v5(model, table, policy, vectors, _json(V4 + "vectors.json"))
    validate_observer_listener(model, table, policy)
    validate_init_t_grant(status)
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


def validate_canonical_hunks() -> None:
    """Q-PERF40-4: every hunk of this layer's authority is the canonical byte-minimal one, from this era's bytes."""
    for path, rule in _PROJECTION_RULES.items():
        after = reviewed_bytes(path)
        require(type(after) is bytes and digest(after) == rule["afterSha256"], "unreviewed current source: " + path)
        before = _undo_this_layer(path, after)
        require(canonical_hunks(after, before) == rule["reverseHunks"], "canonical byte-minimal inverse hunks: " + path)


def validate() -> None:
    record = authority()
    validator_raw = successor.historical_bytes(VALIDATOR_PATH, regular_bytes(VALIDATOR_PATH))
    literal = b'AUTHORITY_SHA256 = "' + AUTHORITY_SHA256.encode("ascii") + b'"'
    placeholder = b'AUTHORITY_SHA256 = "TO_BE_PINNED_AFTER_SOURCE_FREEZE"'
    require(validator_raw.count(literal) == 1
            and digest(validator_raw.replace(literal, placeholder))
            == record["validatorNormalizedSha256"], "seccomp observer listener validator drift")
    paths = sorted((ROOT / "task-packets").glob("*.yaml"))
    old = set(record["baselinePackets"])
    require(len(paths) == 249
            and {path.stem for path in paths} == old | {NEW_PACKET, successor.NEW_PACKET},
            "closed 249-packet catalog retaining the 248-packet checkpoint")
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
            "closed source-only seccomp-observer-listener packet and inherited commands")
    require(len(packet["allowedPaths"]) == len(set(packet["allowedPaths"]))
            and set(packet["allowedPaths"]) == set(record["changedFiles"])
            | set(record["newFiles"]) | {AUTHORITY_PATH, VALIDATOR_PATH,
                                         "task-packets/" + NEW_PACKET + ".yaml"},
            "unreviewed or omitted seccomp-observer-listener packet path")
    for path, rule in record["changedFiles"].items():
        current = successor.historical_bytes(path, regular_bytes(path))
        require(digest(current) == rule["afterSha256"]
                and digest(historical_bytes(path, current)) == rule["beforeSha256"],
                "unreviewed current source: " + path)
    for path, expected in record["newFiles"].items():
        require(digest(successor.historical_bytes(path, regular_bytes(path))) == expected,
                "new source drift: " + path)
    validate_seccomp_observer_listener()


if __name__ == "__main__":
    validate()
    print("Seccomp observer listener valid: 249 current specifications; 248-packet checkpoint and exact 247-packet predecessor; contracts reviewed.")
