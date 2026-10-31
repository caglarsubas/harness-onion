#!/usr/bin/env python3
"""Validate the MET-ENFORCE-034 SELinux matrix v6 and the exact 247-to-246 projection."""
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
    import validate_seccomp_observer_listener as successor
except ImportError:
    from scripts.safe_yaml import safe_load
    from scripts import validate_seccomp_observer_listener as successor


ROOT = Path(__file__).resolve().parents[1]
AUTHORITY_PATH = "architecture/selinux-matrix-v4-authority.json"
AUTHORITY_SHA256 = "f2a0da22451681340c45c4d91240d898a81116bcc3ead937489194dabba0dda3"
VALIDATOR_PATH = "scripts/validate_selinux_matrix_v4.py"
BASE_COMMIT = "887cbe7a005f6c7c813623dce5072e1c75f1fe58"
NEW_PACKET = "MET-ENFORCE-034"
PREVIOUS_PACKET = "MET-ENFORCE-033"
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
            require(key not in result, "duplicate selinux-matrix-v4 authority member")
            result[key] = value
        return result

    def no_constant(_value: str) -> Any:
        raise ValueError("nonfinite selinux-matrix-v4 authority number")

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
        require(digest(raw) == AUTHORITY_SHA256, "SELinux matrix v6 history authority digest")
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
    }, "closed SELinux matrix v6 history authority")
    require(value["schemaVersion"] == "harness.planeon.ai/selinux-matrix-v4-authority/v1"
            and value["authorityPacket"] == NEW_PACKET
            and value["acceptedBase"] == BASE_COMMIT
            and type(value["baselinePackets"]) is dict
            and len(value["baselinePackets"]) == 246
            and NEW_PACKET not in value["baselinePackets"]
            and type(value["changedFiles"]) is dict
            and type(value["newFiles"]) is dict
            and _sha(value["packetSha256"])
            and _sha(value["validatorNormalizedSha256"]),
            "accepted 246-packet base")
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
    # An exact 246-era byte string is already older than the successor layer.
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


# MET-ENFORCE-034 (roadmap SELINUX-MATRIX-V6; owner decisions Q-MX6-2/3/4/7, "Keep, T04 uses v5" and SOL-SYSTEMD-CLEANS,
# and the lane monitor's owner-delegated Q-MX6-1/5/6/8, Q-MX6D-1/2, Q-MX6-R6 (b) and MX6-R7-ACCEPT, 2026-10-16/17)
# publishes the SELinux matrix v6 (planeon.internal.selinux-matrix/v6), the successor of the byte-identical v5: the
# fail-closed source closures (qualk8s execute_no_trans, process transition and dyntransition, filesystem relabelto),
# the filesystem table and mount sources for context= mounts, entry closures, the /proc reader narrowing (the server reads
# only its observer's and broker's /proc, the broker only the gate's) and systemd's narrowed getattr and unlink on the four
# planeon listener socket types. Repository bytes are read only through reviewed_bytes, so a later bridged successor
# projects its own edits away first. Every reviewed file of this era is bound by digest before anything is parsed and on
# every later read. The evaluator is executed from this era's bytes (it imports only the standard library), the seven
# review rounds are bound to their exact subject bytes, v6 is checked to be v5 plus exactly the changes restated here
# (by rule where the contract states one), the coupling with the merged native-profile v4 is re-checked, every deny
# assertion must hold, every access and mutation vector replays, and this layer's own inverse hunks are the canonical
# byte-minimal ones.
V6_DIR = "architecture/selinux-matrix-v4/"
V5_DIR = "architecture/selinux-matrix-v3/"
V6_MODEL = "scripts/selinux_matrix_v4.py"
NP4_README = "architecture/native-profile-v4/README.md"
NP4_SCHEMA = "architecture/native-profile-v4/qualification.schema.json"
STATUS = V6_DIR + "status.json"
INDEX = V6_DIR + "source-index.json"
SUBJECT = (V6_DIR + "README.md", V6_DIR + "REVIEW_BRIEF.md", V6_DIR + "matrix.json", V6_DIR + "vectors.json", V6_MODEL)
DIGEST_ONLY = (V6_DIR + "vectors.json",)
# The adopted v5 matrix and evaluator, HS43 and the merged native-profile v4 stay byte-identical.
FROZEN_PATHS = (
    "architecture/selinux-matrix-v3/README.md",
    "architecture/selinux-matrix-v3/REVIEW_BRIEF.md",
    "architecture/selinux-matrix-v3/matrix.json",
    "architecture/selinux-matrix-v3/vectors.json",
    "architecture/selinux-matrix-v3/status.json",
    "scripts/selinux_matrix_v3.py",
    "architecture/host-interface-amendment-hs43/HOST_INTERFACE_SPEC.md",
    "architecture/native-profile-v4/README.md",
    "architecture/native-profile-v4/qualification.schema.json",
)
ERA_SHA256 = MappingProxyType({
    "architecture/host-interface-amendment-hs43/HOST_INTERFACE_SPEC.md": "b4f46b3a79c45691d7029a79849a555aca5ca7a6e6c600958147935f806888e9",
    "architecture/native-profile-v4/README.md": "a4205a5388dc83827bb39670bcc9477b030f29829128abf19f7578321c170174",
    "architecture/native-profile-v4/qualification.schema.json": "c3e91c087ebc6a13e8a96a066f80710ac968c8def434d1d1b97415811715ed10",
    "architecture/selinux-matrix-v3/README.md": "0070f3b5be1d68eb6d1e76e9aceed496b5c1ecce91f8cd3b69c81ffdee1e9167",
    "architecture/selinux-matrix-v3/REVIEW_BRIEF.md": "67a06e40712fbe731026af18effa9b53394b6d2202c2fdddec57337a89b94102",
    "architecture/selinux-matrix-v3/matrix.json": "01e4f3cfd75250dc6fd74f666cfa53758f83b7a07d7a39a0ca180f5588496b73",
    "architecture/selinux-matrix-v3/status.json": "bf6664e2390b9a6ddeb7acb5e452c0f111bb856b57545f66482f00e34759e30f",
    "architecture/selinux-matrix-v3/vectors.json": "e1c2bc892bbc60baa54dc033ef829ea406066f7ebde5d3e83c28e3076e8cde5c",
    "architecture/selinux-matrix-v4/README.md": "70c537948532496737ec6228306db015f2c93b6df4bdeb0c476d3481b1861c40",
    "architecture/selinux-matrix-v4/REVIEW_BRIEF.md": "568820b38673cad3d5d227a2cd5b125fe8d74dfa8ec6fa055a31e3923d66c853",
    "architecture/selinux-matrix-v4/matrix.json": "3d2830b879f953ce4ae72e63bf7adb85f83e620ae5925297010d8224012b3149",
    "architecture/selinux-matrix-v4/review-round1.json": "af8f98f5fff373f6a5540d6258ec805f5fede8b1a5d3ce9850456c9099c009af",
    "architecture/selinux-matrix-v4/review-round2.json": "8cc287e6775f6cd555341e4a8e56fcdcaeea6e0d70f091d95434c68ba2bb14fd",
    "architecture/selinux-matrix-v4/review-round3.json": "658e0023d8db01d34f7804cd94d7d5cb6f1ce1b73eed3c3b15596baabb969c08",
    "architecture/selinux-matrix-v4/review-round4.json": "ca6bebf969e10c91ac0d38592412c7c7f3b93001ae093025711ab82bd46c2958",
    "architecture/selinux-matrix-v4/review-round5.json": "613249dc780292d5cc01a440bd17648405d5b2fa1caa6180c272b5428d5a60fc",
    "architecture/selinux-matrix-v4/review-round6.json": "932c283388b7e74a3b673e12e71604c731549016d1ee997e349f8e07e7122283",
    "architecture/selinux-matrix-v4/review-round7.json": "34b3e6cff7738576072b3f601680bccf143aa9e59d2d3c107865cc8f54a489dc",
    "architecture/selinux-matrix-v4/round1/architecture/selinux-matrix-v4/README.md": "21feea969a2bcf741634e9762913bb468a661ece662196d725129380ad1feb19",
    "architecture/selinux-matrix-v4/round1/architecture/selinux-matrix-v4/REVIEW_BRIEF.md": "91dbe58fb455d4f65da04a166f79e7141f7f699842825d9269bc6e716fb87e42",
    "architecture/selinux-matrix-v4/round1/architecture/selinux-matrix-v4/matrix.json": "6af2f1db3abd757324d7b48cd3d329634a594bcc6756b06456413eb9f2cff09c",
    "architecture/selinux-matrix-v4/round1/scripts/selinux_matrix_v4.py": "1829a3ad4706663ff18402b6ccec2fdb1bf4e81af273e70955f040ca511ff640",
    "architecture/selinux-matrix-v4/round2/architecture/selinux-matrix-v4/README.md": "4afa60befec9b7b41f8bf417b2e516df7fa5096c8c56df5e6ee03f56bdde70ed",
    "architecture/selinux-matrix-v4/round2/architecture/selinux-matrix-v4/REVIEW_BRIEF.md": "7f64684b2fbde37cc58de78096f4b2aff550d858ff4dd6bc19cfa4388bf43283",
    "architecture/selinux-matrix-v4/round2/architecture/selinux-matrix-v4/matrix.json": "75252418757c5293fa3eb1ce02c1cf25396c4e311b6f287e8fbd64546d355cb1",
    "architecture/selinux-matrix-v4/round2/scripts/selinux_matrix_v4.py": "17aac0a5d2f9a2b9c5a0d313bb9cc179bd0631823adddb6dd013ed5ba598cd33",
    "architecture/selinux-matrix-v4/round3/architecture/selinux-matrix-v4/README.md": "62fbd28e779d0ee7ce497b63540d2493136c591234097d2d306b9fcc6ffafb88",
    "architecture/selinux-matrix-v4/round3/architecture/selinux-matrix-v4/REVIEW_BRIEF.md": "7dc2c0ca055c44fafd414b0f3efecc5f0fa1c5937cd2f070038776fd4e7d3ab6",
    "architecture/selinux-matrix-v4/round3/architecture/selinux-matrix-v4/matrix.json": "75252418757c5293fa3eb1ce02c1cf25396c4e311b6f287e8fbd64546d355cb1",
    "architecture/selinux-matrix-v4/round3/scripts/selinux_matrix_v4.py": "17aac0a5d2f9a2b9c5a0d313bb9cc179bd0631823adddb6dd013ed5ba598cd33",
    "architecture/selinux-matrix-v4/round4/architecture/selinux-matrix-v4/README.md": "b926a12b0360372a91335f15a23cf2d93714287745edba8e8d9626b6eb1c2cd2",
    "architecture/selinux-matrix-v4/round4/architecture/selinux-matrix-v4/REVIEW_BRIEF.md": "ffec15a90a59ed7baf4ccd55b5464e6524a812c9aeedb46036893dfe35f1c134",
    "architecture/selinux-matrix-v4/round4/architecture/selinux-matrix-v4/matrix.json": "5b4512c59da63c850869b8c5a3a798a60d24a006d8379ef23cc22dccf328df6e",
    "architecture/selinux-matrix-v4/round4/scripts/selinux_matrix_v4.py": "17aac0a5d2f9a2b9c5a0d313bb9cc179bd0631823adddb6dd013ed5ba598cd33",
    "architecture/selinux-matrix-v4/round5/architecture/selinux-matrix-v4/README.md": "318510f07d62c5761beae92a6072e89aacfaa1d827d6bdc0f229eb6c2df4b5a2",
    "architecture/selinux-matrix-v4/round5/architecture/selinux-matrix-v4/REVIEW_BRIEF.md": "c741129e8ead2aa1e1d3c16249ebdbd92b04cdeaa9683b3d2cb25574bd3e6194",
    "architecture/selinux-matrix-v4/round5/architecture/selinux-matrix-v4/matrix.json": "c667323fdb6e922380f58fbbba88c25b25c2ce9d322ebf95c4d0d6dfcf4e77af",
    "architecture/selinux-matrix-v4/round5/scripts/selinux_matrix_v4.py": "f7118ceb0bde6e86472253e9a75a7bb5fd43312a741d5cedd302c48be5710b18",
    "architecture/selinux-matrix-v4/round6/architecture/selinux-matrix-v4/README.md": "8d97d23a7ac60fe2a7707926fee57f03589a6f772326600db4eba9e263e7a83c",
    "architecture/selinux-matrix-v4/round6/architecture/selinux-matrix-v4/REVIEW_BRIEF.md": "996d79c9e0134340a4d732a9b10e049c6892886085079ec8db5054a2703ab99f",
    "architecture/selinux-matrix-v4/round6/architecture/selinux-matrix-v4/matrix.json": "bb7b49e39b559eebd9f7348b902546425e10610188a578afb4b65d13ac7da22d",
    "architecture/selinux-matrix-v4/round6/scripts/selinux_matrix_v4.py": "4299ad1c569c809554eae0756d9665c4ddc247cbd23557024477c1b724cb4046",
    "architecture/selinux-matrix-v4/source-index.json": "24e2c2668db8824f1e638f5cfb372429ba2da0edafda727a2ae66961132446ef",
    "architecture/selinux-matrix-v4/status.json": "1f3b9a82441e684dc26999e9aa9e40d56c810cd2afaf2a7e35c4faa9ca212994",
    "architecture/selinux-matrix-v4/vectors.json": "5782ca26af584ec3b6bd11183455f5022ebf61ccd486133b0ac6a8daa709b39a",
    "scripts/selinux_matrix_v3.py": "86ea304f2177cf71b148233259d6ae5686d6aef7f1fa2294f9be421749776fcb",
    "scripts/selinux_matrix_v4.py": "6bad8c5325e2677cc86caf320e734d677bce2aca50e1640ed5c49e4b158d809a",
})
ROUND_COMMITS = ("7f1a4e1885eef0c4803e5d015d997436d23be0c5", "e398cb5328acb121b2cc473a5057f1febe0d784a",
                 "ce83d913abc48eded33b566bae7a23be20a02724", "6720a5ee834b5f16238993268a771e15e8864aac",
                 "bb202bf4d2c7a628491c55f002e3fe0aa47a8456", "ddbd5e9e3e7e81c7900d2d84f5f533effa19e9fb",
                 "d45a0d8bf79a244fcdccf41e3537450e32d01f4d")
REVIEW_VERDICTS = ("CHANGES_REQUIRED",) * 4 + ("PASS_FOR_SOURCE_PUBLICATION",) * 3
PASS_SUBJECT = ROUND_COMMITS[-1]
AUTHORING_BASE = "b0635f81e5ba3b6538fc0cfd28a78f0fea962f50"
NP4_CANDIDATE = "5a3e6820cf23325dd8c68f8c083d53ac805f2b06"
# The NOTEs of the passing rounds 5 and 6 that the next candidate did not fix, and round 7's; every other finding of
# rounds 1-6 was fixed in the next candidate and re-reviewed in the next round.
CARRIED_EARLIER = {"XV5-1": 5, "XV6-3": 6, "XV6-6": 6}
CARRIED = ("XV5-1", "XV6-3", "XV6-6", "XV7-1", "XV7-2", "XV7-3", "XV7-4")
OWNER_DECISIONS = ("MATRIX-V6-DOSSIER", "Q-MX6-OWNER", "Q-MX6-MONITOR", "MX6-PROVENANCE", "Q-MX6-KEEP-T04-V5",
                   "Q-MX6D-MONITOR", "MX6-LOCK-AND-WORKTREE", "MX6-R1-FIXES-MONITOR", "SOL-SYSTEMD-CLEANS", "Q-MX6-R6",
                   "MX6-R7-ACCEPT")
FALSE_FLAGS = ("nativeAcceptance", "tenantAcceptance", "policyModuleWritten", "policyLoaded", "distributionSelected",
               "seccompFiltersDefined", "productExecution", "runnerActivated", "phaseComplete")
STATUS_KEYS = frozenset({"schemaVersion", "contract", "supersedes", "reviewRounds", "closedFindings", "carriedFindings",
                         "carriedFromV5", "obligationRows", "namedLimitation", "ownerDecisions", "coupling",
                         "contractState", "obligations", "independentReviewer", "readmeStatusNote", *FALSE_FLAGS})
ROUND_KEYS = frozenset({"round", "record", "recordSha256", "verdict", "subjectCommit", "subjectTree", "subjectSha256",
                        "subjectDirectory"})
SERVER, BROKER, OBSERVER, GATE = "planeon_server_t", "planeon_broker_t", "planeon_observer_t", "planeon_gate_t"
# Review MX6-O6 / A69.*: the server reads only its observer's and broker's /proc, the broker only the gate's.
PROC_KEPT = {SERVER: (OBSERVER, BROKER), BROKER: (GATE,)}
# SOL-SYSTEMD-CLEANS: systemd (init_t) may stat (READ, sock_file getattr) and unlink (WRITE, sock_file unlink) the four
# planeon listener socket types, nothing else on them.
LISTENER_SOCKETS = ("planeon_i05_sock_t", "planeon_i07_sock_t", "planeon_observer_sock_t", "planeon_broker_sock_t")
SYSTEMD_CLEANUP = {"READ": {"classes": ["sock_file"], "domain": "init_t", "perms": ["getattr"]},
                   "WRITE": {"classes": ["sock_file"], "domain": "init_t", "perms": ["unlink"]}}
NEW_KEYS = frozenset({"filesystem", "filesystemAssociate", "mountSources"})
CHANGED_KEYS = frozenset({"schemaVersion", "types", "procAccess", "sourceClosures", "assertions"})
MOUNT_SOURCES = ["qualk8s_kubelet_t", "qualk8s_runtime_t"]
FILESYSTEM_ASSOCIATE = [{"filesystem": "qualk8s_container_file_t", "type": "qualk8s_container_file_t"}]
CHANGED_ASSERTIONS = frozenset({"A59", "A59.planeon_server_t", "A59.planeon_observer_t", "A59.planeon_worker_t",
                                "A59.planeon_contain_t"})
NEW_ASSERTIONS = (
    "A60.22.execute_no_trans", "A60.23.execute_no_trans", "A60.24.execute_no_trans", "A60.25.execute_no_trans",
    "A60.26.execute_no_trans", "A60.27.execute_no_trans", "A60.28.execute_no_trans", "A60.29.execute_no_trans",
    "A60.30.execute_no_trans", "A60.31.transition", "A60.32.transition", "A60.33.transition", "A60.34.transition",
    "A60.35.transition", "A60.36.transition", "A60.37.transition", "A60.38.transition", "A60.39.transition",
    "A60.40.transition", "A60.41.transition", "A60.42.transition", "A60.43.transition", "A60.44.transition",
    "A60.45.transition", "A60.46.transition", "A60.47.relabelto", "A60.48.relabelto", "A60.49.entrypoint",
    "A60.50.entrypoint", "A60.51.entrypoint", "A60.52.entrypoint", "A60.53.entrypoint", "A60.54.entrypoint",
    "A60.55.entrypoint", "A60.56.entrypoint", "A60.57.entrypoint", "A60.58.entrypoint", "A60.59.entrypoint",
    "A60.60.entrypoint", "A60.61.entrypoint", "A60.62.entrypoint", "A60.63.entrypoint", "A60.64.entrypoint",
    "A69.planeon_server_t", "A69.planeon_server_t.getattr", "A69.planeon_broker_t", "A69.planeon_broker_t.getattr",
    "A70", "A71", "A72", "A73", "A74", "A75.dir", "A75.file", "A75.sock_file", "A76.dir", "A76.file",
    "A77.planeon_server_exec_t", "A77.planeon_observer_exec_t", "A77.planeon_broker_exec_t",
    "A77.planeon_gate_exec_t", "A77.planeon_worker_exec_t", "A77.planeon_policy_writer_exec_t",
    "A77.planeon_contain_exec_t", "A77.planeon_maint_exec_t", "A77.qualk8s_apiserver_exec_t",
    "A77.qualk8s_controller_manager_exec_t", "A77.qualk8s_scheduler_exec_t", "A77.qualk8s_kubelet_exec_t",
    "A77.qualk8s_runtime_exec_t", "A77.qualk8s_datastore_exec_t", "A77.qualk8s_netpol_exec_t",
    "A77.qualk8s_proxy_exec_t", "A77.qualk8s_container_file_t", "A78.planeon_broker_sock_t",
    "A79.planeon_broker_sock_t", "A78.planeon_i05_sock_t", "A79.planeon_i05_sock_t", "A78.planeon_i07_sock_t",
    "A79.planeon_i07_sock_t", "A78.planeon_observer_sock_t", "A79.planeon_observer_sock_t",
)
V6_CHANGES = (
    "C813", "C815", "C820", "C822", "C827", "C829", "C1623", "C1629", "C1635", "C1641", "C1647", "C1653", "C1680",
    "C1682", "C1686", "C1688", "C1692", "C1694", "C1743", "C1745", "C1750", "C1752", "C1757", "C1759", "M29", "M53",
    "M73", "M74", "M75",
)
# NP4's coupling: the assertions it cites stay v5's (README "Coupling with native-profile v4").
NP4_CITED = ("A12", "A32", "A33", "A37", "A47") + tuple("A60.%d.execute_no_trans" % n for n in range(15, 22))
# Absolute local paths that must not appear in a newly published era file, compared case-insensitively (review P1-3).
LOCAL_PATH_MARKERS = (b"/users/", b"/private/", b"/home/", b".local/state", b"/tmp/claude")
COUNTS = {"assertions": 214, "types": 58, "accessChecks": 4600, "mutationChecks": 116, "sourceClosures": 64,
          "procAccess": 21, "filesystem": 9, "v6Changes": 29, "entryLabels": 16,
          "np4Labels": 23, "np4Patterns": 3}


def reviewed_bytes(path: str) -> bytes:
    """This packet's reviewed bytes of path; a bridged successor projects newer bytes back first."""
    return successor.historical_bytes(path, regular_bytes(path))


def _verified(path: str) -> bytes:
    """reviewed_bytes, checked against its era digest on every read; a path outside the era is refused."""
    expected = ERA_SHA256.get(path)
    require(expected is not None, "MET-ENFORCE-034 reviewed bytes are bound: " + path)
    raw = reviewed_bytes(path)
    require(type(raw) is bytes and digest(raw) == expected, "unreviewed SELinux matrix v6 source: " + path)
    return raw


def _json(path: str) -> Any:
    return parse(_verified(path))


def _era_model() -> types.ModuleType:
    """The v6 evaluator of this era, executed from its verified bytes."""
    module = types.ModuleType("_met_enforce_034_selinux_matrix_v4")
    module.__file__ = str(ROOT / V6_MODEL)
    exec(compile(_verified(V6_MODEL), V6_MODEL, "exec", dont_inherit=True), module.__dict__)
    return module


def validate_v6_status() -> None:
    """The status is closed, its seven rounds are bound to their exact subject bytes, the last passes with notes, every
    other finding is closed and the carry list is exactly the open notes."""
    status = _json(STATUS)
    require(type(status) is dict and set(status) == STATUS_KEYS
            and status["schemaVersion"] == "planeon.internal.selinux-matrix-v4-status/v1"
            and status["contract"] == "planeon.internal.selinux-matrix/v6"
            and status["supersedes"] == "planeon.internal.selinux-matrix/v5"
            and status["contractState"] == "ADOPTED_DATA_CONTRACT"
            and status["obligations"] == {"E%02d" % n: "OPEN_UNPROVEN" for n in range(1, 13)}
            and status["obligationRows"] == ["MX6-O%d" % n for n in range(1, 9)]
            and status["independentReviewer"] == "SEPARATE_AGENT_NOT_AUTHOR"
            and all(status[flag] is False for flag in FALSE_FLAGS)
            and tuple(row["id"] for row in status["ownerDecisions"]) == OWNER_DECISIONS
            and status["coupling"]["nativeProfileV4Candidate"] == NP4_CANDIDATE
            and status["coupling"]["nativeProfileV4Merge"] == BASE_COMMIT,
            "adopted after the round-7 pass, coupled to the merged native-profile v4, nothing installed")
    rounds = status["reviewRounds"]
    require(type(rounds) is list and len(rounds) == len(ROUND_COMMITS)
            and all(type(row) is dict and set(row) == ROUND_KEYS | ({"keptCopies", "digestOnly"} if n < len(rounds) else set())
                    for n, row in enumerate(rounds, 1))
            and tuple(row["verdict"] for row in rounds) == REVIEW_VERDICTS
            and tuple(row["subjectCommit"] for row in rounds) == ROUND_COMMITS
            and rounds[-1]["subjectDirectory"] == "CURRENT", "the seven review rounds as restated")
    records = {}
    for number, row in enumerate(rounds, 1):
        raw = _verified(row["record"])
        record = parse(raw)
        records[number] = record
        kept = row.get("keptCopies", [])
        require(row["round"] == number and row["record"] == V6_DIR + "review-round%d.json" % number
                and digest(raw) == row["recordSha256"] and record["round"] == number
                and record["subjectCommit"] == row["subjectCommit"] and record["subjectTree"] == row["subjectTree"]
                and record["verdict"] == row["verdict"]
                and record["actions"] == {"filesEdited": False, "networkAccessed": "none", "personalDataSent": False}
                and row["subjectDirectory"] == (V6_DIR + "round%d/" % number if number < len(rounds) else "CURRENT")
                and set(kept) <= set(SUBJECT) and set(kept).isdisjoint(DIGEST_ONLY)
                and row.get("digestOnly", list(DIGEST_ONLY)) == list(DIGEST_ONLY)
                and set(row["subjectSha256"]) == set(SUBJECT)
                and all(digest(_verified(row["subjectDirectory"] + path if path in kept else path)) == row["subjectSha256"][path]
                        for path in SUBJECT if number == len(rounds) or path not in DIGEST_ONLY),
                "review round %d is bound to its exact subject bytes" % number)
    final = records[len(rounds)]
    require(all(type(row) is dict and row.get("severity") == "NOTE" for row in final["findings"]),
            "the final round passes with notes only")
    earlier = {f["id"]: (n, f) for n in range(1, len(rounds)) for f in records[n]["findings"]}
    require(all(earlier[fid][0] == n and earlier[fid][1]["severity"] == "NOTE" for fid, n in CARRIED_EARLIER.items())
            and set(status["carriedFindings"]) == set(CARRIED)
            == set(CARRIED_EARLIER) | {f["id"] for f in final["findings"]}
            and status["closedFindings"] == {fid: "CLOSED in round %d" % (n + 1) for fid, (n, _) in earlier.items()
                                             if fid not in CARRIED_EARLIER},
            "every earlier finding closed in the next round except the restated carried notes")
    index = _json(INDEX)
    require(type(index) is dict and index["schemaVersion"] == "planeon.internal.selinux-matrix-v4-index/v1"
            and index["round"] == len(rounds) and index["subjectCommit"] == PASS_SUBJECT
            and index["baseMain"] == AUTHORING_BASE
            and [row["path"] for row in index["subject"]] == list(SUBJECT)
            and all(digest(_verified(row["path"])) == row["sha256"] for row in index["subject"])
            and [row["path"] for row in index["predecessorInputs"]] == list(FROZEN_PATHS)
            and all(digest(_verified(row["path"])) == row["sha256"] for row in index["predecessorInputs"])
            and [row["commit"] for row in index["predecessorInputs"] if "commit" in row] == [BASE_COMMIT, BASE_COMMIT]
            and [row["path"] for row in index["earlierRounds"]] == [row["record"] for row in rounds[:-1]]
            and all(digest(_verified(row["path"])) == row["sha256"] for row in index["earlierRounds"]),
            "the reviewed subject and its inputs are the published ones")


def validate_v6_successor(matrix: dict, v5: dict) -> None:
    """v6 is v5 plus exactly the restated changes; every v5 type, closure and assertion keeps its index."""
    require(matrix["schemaVersion"] == "planeon.internal.selinux-matrix/v6" and set(matrix) == set(v5) | NEW_KEYS
            and all(matrix[key] == v5[key] for key in set(v5) - CHANGED_KEYS),
            "v6 changes only types, /proc, source closures and assertions, and adds the filesystem tables")
    expected_types = []
    for row in v5["types"]:
        row = copy.deepcopy(row)
        if row["name"] in LISTENER_SOCKETS:
            for kind, grant in SYSTEMD_CLEANUP.items():
                row["access"][kind].append(dict(grant))
        expected_types.append(row)
    require(matrix["types"] == expected_types,
            "the v5 types, with systemd's narrowed getattr and unlink on the four listener socket types only")
    require(matrix["procAccess"] == [e for e in v5["procAccess"]
                                     if e["domain"] not in PROC_KEPT or e["target"] in PROC_KEPT[e["domain"]]],
            "the /proc narrowing: the server reads its observer and broker only, the broker the gate only")
    require(matrix["sourceClosures"][:len(v5["sourceClosures"])] == v5["sourceClosures"]
            and len(matrix["sourceClosures"]) == COUNTS["sourceClosures"] and len(matrix["procAccess"]) == COUNTS["procAccess"]
            and matrix["mountSources"] == MOUNT_SOURCES and matrix["filesystemAssociate"] == FILESYSTEM_ASSOCIATE
            and len(matrix["filesystem"]) == COUNTS["filesystem"], "the closures and filesystem tables as restated")
    old = [a["id"] for a in v5["assertions"]]
    new = [a["id"] for a in matrix["assertions"]]
    byid = {a["id"]: a for a in matrix["assertions"]}
    require(new[:len(old)] == old and tuple(new[len(old):]) == NEW_ASSERTIONS
            and all(byid[i] == a for i, a in zip(old, v5["assertions"]) if i not in CHANGED_ASSERTIONS)
            and all(byid[i] != a for i, a in zip(old, v5["assertions"]) if i in CHANGED_ASSERTIONS),
            "every v5 assertion keeps its index; exactly the disclosed ones change")


def validate_np4_coupling(matrix: dict, v5: dict, entry: dict) -> None:
    """The merged native-profile v4's label constants are matrix types, its sixteen entrypoint labels are the vectors'
    nativeProfileV4 block, and the assertions and observer /proc it cites are v5's."""
    schema = _verified(NP4_SCHEMA).decode("utf-8")
    labels, patterns = set(), 0
    for part in schema.split("system_u:object_r:")[1:]:
        name = part.split(":s0", 1)[0]
        if name and set(name) <= set("abcdefghijklmnopqrstuvwxyz0123456789_"):
            labels.add(name)
        else:
            require(name.startswith("[a-z0-9_]+"), "native-profile v4 label constant or pattern")
            patterns += 1
    names = {t["name"] for t in matrix["types"]}
    exec_labels = sorted(label for label in labels if label.endswith("_exec_t"))
    v5_byid = {a["id"]: a for a in v5["assertions"]}
    byid = {a["id"]: a for a in matrix["assertions"]}
    require(labels <= names and len(labels) == COUNTS["np4Labels"] and patterns == COUNTS["np4Patterns"]
            and len(exec_labels) == COUNTS["entryLabels"]
            and entry["nativeProfileV4"] == {"commit": NP4_CANDIDATE, "labels": entry["nativeProfileV4"]["labels"]}
            and sorted(entry["nativeProfileV4"]["labels"]) == exec_labels
            and all(byid[i] == v5_byid[i] for i in NP4_CITED)
            and [e for e in matrix["procAccess"] if e["domain"] == OBSERVER] == [e for e in v5["procAccess"] if e["domain"] == OBSERVER],
            "the coupling with the merged native-profile v4 holds")


def replay_v6_vectors(model: types.ModuleType, matrix: dict, vectors: dict, v5_vectors: dict) -> int:
    """Every access and mutation vector replays; every v5 vector keeps its identifier and position, and v6Changes lists
    exactly the v5 vectors whose expected result changed, with both values."""
    require(type(vectors) is dict
            and set(vectors) == {"evidenceClass", "accessChecks", "mutationChecks", "w02aSlots", "entryTypes", "v6Changes"}
            and vectors["evidenceClass"] == "DATA_CHECK_ONLY" and vectors["w02aSlots"] == v5_vectors["w02aSlots"]
            == model.w02a_slots(matrix)
            and len(vectors["accessChecks"]) == COUNTS["accessChecks"]
            and len(vectors["mutationChecks"]) == COUNTS["mutationChecks"]
            and tuple(row["id"] for row in vectors["v6Changes"]) == V6_CHANGES and len(V6_CHANGES) == COUNTS["v6Changes"],
            "closed matrix v6 vectors")
    entry = vectors["entryTypes"]
    require(set(entry) == {"entered", "nativeProfileV4", "outsideNativeProfileV4"}
            and entry["entered"] == model.entry_types(matrix)
            and entry["outsideNativeProfileV4"] == sorted(set(entry["entered"]) - set(entry["nativeProfileV4"]["labels"])),
            "the entry-type block is derived")
    for key in ("accessChecks", "mutationChecks"):
        ids = [row["id"] for row in vectors[key]]
        require(len(set(ids)) == len(ids) and ids[:len(v5_vectors[key])] == [row["id"] for row in v5_vectors[key]],
                "every v5 %s vector keeps its identifier and position" % key)
    old = {row["id"]: row for row in v5_vectors["accessChecks"] + v5_vectors["mutationChecks"]}
    new = {row["id"]: row for row in vectors["accessChecks"] + vectors["mutationChecks"]}
    require({i for i in old if old[i]["expect"] != new[i]["expect"]} == set(V6_CHANGES)
            and all(set(row) == {"id", "reason", "v5Expect", "v6Expect"} and type(row["reason"]) is str and row["reason"]
                    and row["v5Expect"] == old[row["id"]]["expect"]
                    and row["v6Expect"] == new[row["id"]]["expect"] for row in vectors["v6Changes"]),
            "v6Changes lists exactly the changed v5 expectations")
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


def validate_selinux_matrix_v4() -> None:
    """Every reviewed byte and the review binding first; then v6 against v5, the coupling, every assertion and the full
    replay; last, this layer's canonical hunks."""
    for path in FROZEN_PATHS:
        require(path not in _PROJECTION_RULES, "the v5 matrix, HS43 and the native-profile v4 stay byte-identical")
    for path in ERA_SHA256:
        raw = _verified(path)
        require(path in FROZEN_PATHS or not any(marker in raw.lower() for marker in LOCAL_PATH_MARKERS),
                "no absolute local path in an era file: " + path)
    validate_v6_status()
    matrix, v5 = _json(V6_DIR + "matrix.json"), _json(V5_DIR + "matrix.json")
    vectors, v5_vectors = _json(V6_DIR + "vectors.json"), _json(V5_DIR + "vectors.json")
    validate_v6_successor(matrix, v5)
    validate_np4_coupling(matrix, v5, vectors["entryTypes"])
    model = _era_model()
    model.check_matrix(matrix)
    require(model.failed_assertions(matrix) == [] and len(matrix["assertions"]) == COUNTS["assertions"]
            and len(matrix["types"]) == COUNTS["types"], "every deny assertion holds")
    replay_v6_vectors(model, matrix, vectors, v5_vectors)
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
            == record["validatorNormalizedSha256"], "SELinux matrix v6 validator drift")
    paths = sorted((ROOT / "task-packets").glob("*.yaml"))
    old = set(record["baselinePackets"])
    require(len(paths) == 275
            and {path.stem for path in paths} == old | {NEW_PACKET, successor.NEW_PACKET, successor.successor.NEW_PACKET, successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.NEW_PACKET, *successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.PRODUCT_PACKETS},
            "closed 275-packet catalog retaining the 247-packet checkpoint")
    packets = {}
    for path in paths:
        if path.stem in (successor.NEW_PACKET, successor.successor.NEW_PACKET, successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.NEW_PACKET, *successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.PRODUCT_PACKETS):
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
            "closed source-only selinux-matrix-v4 packet and inherited commands")
    require(len(packet["allowedPaths"]) == len(set(packet["allowedPaths"]))
            and set(packet["allowedPaths"]) == set(record["changedFiles"])
            | set(record["newFiles"]) | {AUTHORITY_PATH, VALIDATOR_PATH,
                                         "task-packets/" + NEW_PACKET + ".yaml"},
            "unreviewed or omitted selinux-matrix-v4 packet path")
    for path, rule in record["changedFiles"].items():
        current = successor.historical_bytes(path, regular_bytes(path))
        require(digest(current) == rule["afterSha256"]
                and digest(historical_bytes(path, current)) == rule["beforeSha256"],
                "unreviewed current source: " + path)
    for path, expected in record["newFiles"].items():
        require(digest(successor.historical_bytes(path, regular_bytes(path))) == expected,
                "new source drift: " + path)
    validate_selinux_matrix_v4()


if __name__ == "__main__":
    validate()
    print("SELinux matrix v6 valid: 275 current specifications; 247-packet checkpoint and exact 246-packet predecessor; contract reviewed.")
