#!/usr/bin/env python3
"""Validate the MET-ENFORCE-026 host-interface amendment HS43 and the exact 236-to-235 projection."""
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
    import validate_seccomp_v4 as successor
except ImportError:
    from scripts.safe_yaml import safe_load
    from scripts import validate_seccomp_v4 as successor


ROOT = Path(__file__).resolve().parents[1]
AUTHORITY_PATH = "architecture/host-interface-hs43-authority.json"
AUTHORITY_SHA256 = "9d043558269642f2b3e1e67a1b3d99f8723a558fc44dc3aa84199d297077d233"
VALIDATOR_PATH = "scripts/validate_host_interface_hs43.py"
BASE_COMMIT = "8665a9bc847e61a9748380e891925332cbdf4bb5"
NEW_PACKET = "MET-ENFORCE-026"
PREVIOUS_PACKET = "MET-ADOPT-004"
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
            require(key not in result, "duplicate host-interface-hs43 authority member")
            result[key] = value
        return result

    def no_constant(_value: str) -> Any:
        raise ValueError("nonfinite host-interface-hs43 authority number")

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
        require(digest(raw) == AUTHORITY_SHA256, "host interface hs43 history authority digest")
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
    }, "closed host interface hs43 history authority")
    require(value["schemaVersion"] == "harness.planeon.ai/host-interface-hs43-authority/v1"
            and value["authorityPacket"] == NEW_PACKET
            and value["acceptedBase"] == BASE_COMMIT
            and type(value["baselinePackets"]) is dict
            and len(value["baselinePackets"]) == 235
            and NEW_PACKET not in value["baselinePackets"]
            and type(value["changedFiles"]) is dict
            and type(value["newFiles"]) is dict
            and _sha(value["packetSha256"])
            and _sha(value["validatorNormalizedSha256"]),
            "accepted 235-packet base")
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
    # An exact 235-era byte string is already older than the successor layer.
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


# MET-ENFORCE-026 (roadmap HS-4.3-AMEND; owner decisions Q-HE2S-10 (a), Q-HE2S-7 (a), Q-HE2S-9 (a), Q-HE3A-1 (c),
# Q-HE3A-1b (a), HS43-START and Q-HS43-1 (a), and the lane monitor's owner-delegated Q-HS43-2 (a), Q-HS43-3 (a), the
# dirfd direction and three confirmations, 2026-10-13 to 2026-10-15) publishes amendment HS43 of the W01 host-interface
# specification on top of the byte-identical W02D effective text: how the effect gate qualifies the broker and the
# writer (section 4.3), the gate's capability and readlinkat cells (section 5.3) and the BIND digest (section 7), with a
# closed list of the adopted clauses it overrides, two stated residuals and eight obligations. Repository bytes are read
# only through reviewed_bytes, so a later bridged successor projects its own edits away first. Every reviewed file of
# this era is bound by digest before anything is parsed and on every later read, and the amendment's model is executed
# from this era's bytes (it imports only the standard library), so a later revision of it cannot change how this layer
# judges its era. The design label, items, decisions, obligations, residuals, superseded-clause count and review
# verdicts are restated here independently of the record.
AMEND_DIR = "architecture/host-interface-amendment-hs43/"
RECORD = AMEND_DIR + "amendment.json"
EFFECTIVE = AMEND_DIR + "HOST_INTERFACE_SPEC.md"
STATUS = AMEND_DIR + "status.json"
INDEX = AMEND_DIR + "source-index.json"
MODEL = "scripts/host_interface_amendment_v2.py"
# The W02D text and record, the W01 inputs and every file whose clauses HS43 overrides stay byte-identical.
FROZEN_PATHS = ("architecture/host-interface-amendment-w02d/HOST_INTERFACE_SPEC.md",
                "architecture/host-interface-amendment-w02d/amendment.json",
                "architecture/host-interface-inputs/resolved/HOST_INTERFACE_SPEC.md",
                "architecture/host-interface-inputs/corrected/HOST_INTERFACE_SPEC.md",
                "architecture/i05-gate-channel/README.md", "architecture/i05-gate-channel-v2/README.md",
                "architecture/i05-gate-channel-v3/README.md", "architecture/i07-policy-write/README.md",
                "architecture/native-profile-v2/README.md", "architecture/selinux-matrix/README.md",
                "architecture/selinux-matrix-v2/README.md")
ERA_SHA256 = MappingProxyType({
    "architecture/host-interface-amendment-hs43/HOST_INTERFACE_SPEC.md": "b4f46b3a79c45691d7029a79849a555aca5ca7a6e6c600958147935f806888e9",
    "architecture/host-interface-amendment-hs43/README.md": "539f4bd21253d3db73efdf2ecfaeb4cca2015553e19a1e96007e1f2f89f6b781",
    "architecture/host-interface-amendment-hs43/REVIEW_BRIEF.md": "20227ffec301015f15e8b2bb25dea8c8a4eacb2f2e9663cbda11d1c911148f6d",
    "architecture/host-interface-amendment-hs43/amendment.json": "6a3719cdc659d7ccfde3598bdec06a31896fa82de810cf73ccc1f7ca3dc7f24c",
    "architecture/host-interface-amendment-hs43/review-round1.json": "e47b7bbf02eab405a149fe4d32cbe322e2478fa0c02175047382acbc7e1d93b9",
    "architecture/host-interface-amendment-hs43/review-round2.json": "e44df5199a7a36b5d4d4b4f3724ae5c1eb20b381b3f5f17f7320602980069ba1",
    "architecture/host-interface-amendment-hs43/review-round3.json": "59224861c3dbbf167af96350e1716773ffe1cff61aaaf3211541f6e8f2bd5438",
    "architecture/host-interface-amendment-hs43/review-round4.json": "bf6fa6912571e3bdfb344d84e5b1cc54c0e866c25a06a4009788bff05c0190d4",
    "architecture/host-interface-amendment-hs43/round1/architecture/host-interface-amendment-hs43/HOST_INTERFACE_SPEC.md": "45916afb82e528c9d1ba39b338c75d61f49091966066fbfd99a0c21d4d7edbb0",
    "architecture/host-interface-amendment-hs43/round1/architecture/host-interface-amendment-hs43/README.md": "19d3f77506c3cc7138577c1694a0ec646a72f6c1e402e0358a1429bdcc95ff7f",
    "architecture/host-interface-amendment-hs43/round1/architecture/host-interface-amendment-hs43/REVIEW_BRIEF.md": "106aac930f049b505298d75c5e9d0f3107779258ee77ed5d4d8228b08c457c1f",
    "architecture/host-interface-amendment-hs43/round1/architecture/host-interface-amendment-hs43/amendment.json": "57dc52c6640e8c2b904ed8430b78ca69860ff88e7963d3f79e6da52dfa287dbd",
    "architecture/host-interface-amendment-hs43/round1/scripts/host_interface_amendment_v2.py": "b3a820e4b9caa82a669140dd2092ea8fc2cf2ed9c068e735844efa8448bd7dc8",
    "architecture/host-interface-amendment-hs43/round2/architecture/host-interface-amendment-hs43/HOST_INTERFACE_SPEC.md": "665a17924d1497ed8accd4ac388904b0ab219027b5dd23345208d8a503bdb505",
    "architecture/host-interface-amendment-hs43/round2/architecture/host-interface-amendment-hs43/README.md": "8774e935240d48375376fe4cee82fd65d3ffc21915cdd0a5fc3b663eec9b7e17",
    "architecture/host-interface-amendment-hs43/round2/architecture/host-interface-amendment-hs43/REVIEW_BRIEF.md": "20227ffec301015f15e8b2bb25dea8c8a4eacb2f2e9663cbda11d1c911148f6d",
    "architecture/host-interface-amendment-hs43/round2/architecture/host-interface-amendment-hs43/amendment.json": "fefbec5cc2d42c4dc8e8e9de3eb03669ca50bddf49be75448a4c0873aa22d639",
    "architecture/host-interface-amendment-hs43/round2/scripts/host_interface_amendment_v2.py": "6b1476e7b546e0c5cbb6dd03ee0c4865e3e7440cf9228a711ee54eb5f3c0e59e",
    "architecture/host-interface-amendment-hs43/round3/architecture/host-interface-amendment-hs43/HOST_INTERFACE_SPEC.md": "2c54f65e630d603e6673ed182880be6d666ecbd90b5b36a8e6ed52915cc277fe",
    "architecture/host-interface-amendment-hs43/round3/architecture/host-interface-amendment-hs43/README.md": "6e36ab038dc9e55b67b89c106561536608afd049b6f5b0c3a818f3147dce9611",
    "architecture/host-interface-amendment-hs43/round3/architecture/host-interface-amendment-hs43/REVIEW_BRIEF.md": "20227ffec301015f15e8b2bb25dea8c8a4eacb2f2e9663cbda11d1c911148f6d",
    "architecture/host-interface-amendment-hs43/round3/architecture/host-interface-amendment-hs43/amendment.json": "c3d62bdda14db740319dde67ac9b9f71874aafe38e1261b6188a45e9fe5214c7",
    "architecture/host-interface-amendment-hs43/round3/scripts/host_interface_amendment_v2.py": "bf1813376c5cbd9b173e55273dcdd194e8692fbbf501bed3fdc3b3854996f417",
    "architecture/host-interface-amendment-hs43/source-index.json": "dc527309ce0eb31b48d6872d1e72a635c4fbe2f8671d793fa8e4f1f01b02ea98",
    "architecture/host-interface-amendment-hs43/status.json": "be7b3c4685af1012f528dd6f59edcad04306d3f539b0a68ff0749b255f42adbe",
    "architecture/host-interface-amendment-w02d/HOST_INTERFACE_SPEC.md": "2ac2751cbddd7fae20ee92a93a8fc18c7988dd0c96853d1ccb2d08cb3753f83b",
    "architecture/host-interface-amendment-w02d/amendment.json": "8c20ccc25ae504073d89d052b1618c21ab53108dcc44af26f747024709e8f6f9",
    "architecture/host-interface-inputs/corrected/HOST_INTERFACE_SPEC.md": "1b0bee7e46e3cd730b3f878179ac36d0f062ce70ed6c843788ab634aead16ef0",
    "architecture/i05-gate-channel-v2/README.md": "1cb07cef90b0881c42370d8bbaeea08c6abc48478bed3939286b651601d2cca3",
    "architecture/i05-gate-channel-v3/README.md": "f82f43330125640d3ac946d2afc9a1804a21e5e60a7ac4b94e5d6cb6ed2ea3aa",
    "architecture/i05-gate-channel/README.md": "dc9aa22017b2cdf71f886fb7890aff3f6e7095b9afc25bd37645cb0dee23b498",
    "architecture/i07-policy-write/README.md": "9e5cb3d1023bc12b9e2643ae42dde5a87640cf04fc8ac1aa88350c65b12ba2dc",
    "architecture/native-profile-v2/README.md": "7eb2bf5f8e78bf19f942893f57da5e7ca519bdf134c26b98d7b79ef4cc47fc89",
    "architecture/selinux-matrix-v2/README.md": "5a944d166070252b01d727072219a5247dc0f4103d9bea805b51d6d5a6aaea57",
    "architecture/selinux-matrix/README.md": "6cb8603b46a00cfd28b4d3921fe9af37062ccf42503aeda4494516cb1c5a8a4f",
    "scripts/host_interface_amendment_v2.py": "7712622031f7116a0c66db862b9e566775bf47fa0a2d3c3a33d3ef5a65768836",
})
DESIGN_LABEL = "HOST-INTERFACE-DRAFT-002-HS43"
ITEMS = ("E1", "E2", "H1", "H2", "H3", "H5", "H4", "E3")
DECISIONS = ("Q-HE2S-10", "Q-HE2S-7", "Q-HE2S-9", "Q-HE3A-1", "Q-HE3A-1b", "HS43-START", "Q-HS43-1", "Q-HS43-2",
             "Q-HS43-3", "SECCOMP-DIRFD-DIRECTION", "HS43-H5-CONFIRM", "HS43-GATE-RESIDUAL-CONFIRM", "HS43-H4-CONFIRM")
OBLIGATIONS = ("O-SECCOMP-V3-READLINKAT", "O-W03-WRITER-EXE", "O-W03-PEER-EXE", "O-MATRIX-WRITER-PROCACCESS",
               "O-MATRIX-GATE-PROCACCESS", "O-MATRIX-GATE-NETBIND", "O-NATIVE-GATE-NOCAP", "O-T04-HS43")
RESIDUALS = ("R-WRITER-PROC", "R-GATE-PROC")
SUPERSEDED_COUNT = 17
REVIEW_VERDICTS = ("CHANGES_REQUIRED", "CHANGES_REQUIRED", "CHANGES_REQUIRED", "PASS_FOR_SOURCE_PUBLICATION")
PASS_SUBJECT = "0493d704ed8429935cdb3f425731ca0a031a472f"
FALSE_FLAGS = ("implementationReady", "filtersInstalled", "roleCodeChanged", "nativeAcceptance", "tenantAcceptance",
               "productExecution", "runnerActivated", "phaseComplete")


def reviewed_bytes(path: str) -> bytes:
    """This packet's reviewed bytes of path; a bridged successor projects newer bytes back first."""
    return successor.historical_bytes(path, regular_bytes(path))


def _verified(path: str) -> bytes:
    """reviewed_bytes, checked against its era digest on every read; a path outside the era is refused."""
    expected = ERA_SHA256.get(path)
    require(expected is not None, "MET-ENFORCE-026 reviewed bytes are bound: " + path)
    raw = reviewed_bytes(path)
    require(type(raw) is bytes and digest(raw) == expected, "unreviewed host interface hs43 source: " + path)
    return raw


def _era_model() -> types.ModuleType:
    """The amendment's model of this era, executed from its verified bytes."""
    module = types.ModuleType("_met_enforce_026_host_interface_amendment_v2")
    module.__file__ = str(ROOT / MODEL)
    exec(compile(_verified(MODEL), MODEL, "exec", dont_inherit=True), module.__dict__)
    return module


def validate_host_interface_hs43() -> None:
    """Every reviewed byte first; then the model's check from this era and the independent restatements."""
    for path in FROZEN_PATHS:
        require(path not in _PROJECTION_RULES, "the W02D text, the W01 inputs and the overridden contract files stay "
                                               "byte-identical")
    for path in ERA_SHA256:
        _verified(path)
    record = _era_model().check(_verified)
    require(record["designLabel"] == DESIGN_LABEL and tuple(item["id"] for item in record["items"]) == ITEMS
            and tuple(row["id"] for row in record["ownerDecisions"]) == DECISIONS
            and tuple(row["id"] for row in record["obligations"]) == OBLIGATIONS
            and tuple(row["id"] for row in record["residuals"]) == RESIDUALS
            and len(record["supersedes"]) == SUPERSEDED_COUNT, "the amendment record as restated")
    status = parse(_verified(STATUS))
    rounds = status["reviewRounds"]
    require(status["designLabel"] == DESIGN_LABEL and status["contractState"] == "ADOPTED_AMENDMENT"
            and status["effective"] == record["effective"]
            and tuple(row["verdict"] for row in rounds) == REVIEW_VERDICTS
            and rounds[-1]["subjectCommit"] == PASS_SUBJECT and rounds[-1]["subjectDirectory"] == "CURRENT"
            and all(digest(_verified(row["record"])) == row["recordSha256"] for row in rounds)
            and all(status[flag] is False for flag in FALSE_FLAGS), "adopted after the round-4 pass, nothing installed")
    index = parse(_verified(INDEX))
    require(index["subjectCommit"] == PASS_SUBJECT and index["subject"]
            and all(digest(_verified(row["path"])) == row["sha256"] for row in index["subject"]),
            "the reviewed subject is the published one")


def validate() -> None:
    record = authority()
    validator_raw = successor.historical_bytes(VALIDATOR_PATH, regular_bytes(VALIDATOR_PATH))
    literal = b'AUTHORITY_SHA256 = "' + AUTHORITY_SHA256.encode("ascii") + b'"'
    placeholder = b'AUTHORITY_SHA256 = "TO_BE_PINNED_AFTER_SOURCE_FREEZE"'
    require(validator_raw.count(literal) == 1
            and digest(validator_raw.replace(literal, placeholder))
            == record["validatorNormalizedSha256"], "host interface hs43 validator drift")
    paths = sorted((ROOT / "task-packets").glob("*.yaml"))
    old = set(record["baselinePackets"])
    require(len(paths) == 249
            and {path.stem for path in paths} == old | {NEW_PACKET, successor.NEW_PACKET, successor.successor.NEW_PACKET, successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.NEW_PACKET},
            "closed 249-packet catalog retaining the 236-packet checkpoint")
    packets = {}
    for path in paths:
        if path.stem in (successor.NEW_PACKET, successor.successor.NEW_PACKET, successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.NEW_PACKET):
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
            "closed source-only host-interface-hs43 packet and inherited commands")
    require(len(packet["allowedPaths"]) == len(set(packet["allowedPaths"]))
            and set(packet["allowedPaths"]) == set(record["changedFiles"])
            | set(record["newFiles"]) | {AUTHORITY_PATH, VALIDATOR_PATH,
                                         "task-packets/" + NEW_PACKET + ".yaml"},
            "unreviewed or omitted host-interface-hs43 packet path")
    for path, rule in record["changedFiles"].items():
        current = successor.historical_bytes(path, regular_bytes(path))
        require(digest(current) == rule["afterSha256"]
                and digest(historical_bytes(path, current)) == rule["beforeSha256"],
                "unreviewed current source: " + path)
    for path, expected in record["newFiles"].items():
        require(digest(successor.historical_bytes(path, regular_bytes(path))) == expected,
                "new source drift: " + path)
    validate_host_interface_hs43()


if __name__ == "__main__":
    validate()
    print("Host interface HS43 valid: 249 current specifications; 236-packet checkpoint and exact 235-packet predecessor; amendment reviewed.")
