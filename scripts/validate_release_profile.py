#!/usr/bin/env python3
"""Validate MET-ADOPT-006 (RELEASE-PROFILE-001): the first release profile record, its README, its model and its D5a oracle (V1-V4: the five packet files, each equal to its adopted digest; the model, run from its verified bytes with this era's overlay module and YAML loader, accepting the record over this era's reviewed bytes and this layer's packet set; the oracle identity binding the oracle's bytes; and the registry's MET-ADOPT-006 packet rider as the one change from the base), and the exact 272-to-271 projection."""
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
    import validate_chain_product_publish as successor
except ImportError:
    from scripts.safe_yaml import safe_load
    from scripts import validate_chain_product_publish as successor


ROOT = Path(__file__).resolve().parents[1]
AUTHORITY_PATH = "architecture/release-profile-authority.json"
AUTHORITY_SHA256 = "d3bd8852863b8fb318552b274e66a406eb45e12af00a738b9ee8eaaeaa6000f1"
VALIDATOR_PATH = "scripts/validate_release_profile.py"
BASE_COMMIT = "dd000fef649208cd372b5f4fa96b95ae43916661"
NEW_PACKET = "MET-ADOPT-006"
PREVIOUS_PACKET = "MET-ENFORCE-043"
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
            require(key not in result, "duplicate release-profile authority member")
            result[key] = value
        return result

    def no_constant(_value: str) -> Any:
        raise ValueError("nonfinite release-profile authority number")

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
        require(digest(raw) == AUTHORITY_SHA256, "release profile history authority digest")
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
    }, "closed release profile history authority")
    require(value["schemaVersion"] == "harness.planeon.ai/release-profile-authority/v1"
            and value["authorityPacket"] == NEW_PACKET
            and value["acceptedBase"] == BASE_COMMIT
            and type(value["baselinePackets"]) is dict
            and len(value["baselinePackets"]) == 271
            and NEW_PACKET not in value["baselinePackets"]
            and type(value["changedFiles"]) is dict
            and type(value["newFiles"]) is dict
            and _sha(value["packetSha256"])
            and _sha(value["validatorNormalizedSha256"]),
            "accepted 271-packet base")
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
    # An exact 271-era byte string is already older than the successor layer.
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


# MET-ADOPT-006 (roadmap RELEASE-PROFILE-001; the lane monitor's owner-delegated rulings MON-RP-D1 (Q-RP-1 (a)),
# MON-RP-D2, MON-RP-E1-OK, MON-RP-CR1 to MON-RP-CR5-KEEP, Q-RP-PROJ (a1), GO-RP-ADOPT-C5, MON-RP-ORACLE-KEEP and
# GO-272-MECH-C5) adopts candidate c5: the first release profile record (architecture/release-profile.json, the
# overlay-effective closure of profile.banking-readonly-amd64, and its README), its model scripts/release_profile.py,
# which reads every byte through an injected reader and judges the overlay era against an injected packet set (through
# scripts/sector_catalog.py's effective_bytes_from, added by c3), and the D5a oracle tests/test_met_adopt_006_oracle.py
# with its identity. Its review series is registered by this packet's own rider in architecture/review-record/briefs.json
# (MET-ADOPT-006/packet, which the evolution surface record at this base classes as gate material, so the owner approves
# the PR). Repository bytes are read only through reviewed_bytes, so a later bridged successor projects its own edits
# away first; a path outside this era is refused before it is read, every era file is bound by digest on every read,
# and no directory is listed. The three catalogs are named and pinned only by the V1-verified model's own constants
# (BASE_SHA256 and its path constants), so this layer names no catalog. Each refusal is a pure check over the values read,
# so every one has a failing case on plain data. Checked here: V1, the packet's files (exactly the five, each equal to
# the sha256 of its adopted bytes, pinned below); V2, the model accepts the record (the model, executed from its
# V1-verified bytes in the era-loader form with the overlay module and its YAML loader resolved to this era's verified
# copies, runs check(read, packets) over this era's reviewed bytes and this layer's own packet set, the authority's
# baseline and this packet, without a refusal); V3, the oracle binding (the identity names the oracle test, its
# file.sha256 equals the oracle test's bytes and its ruling is KEEP); and V4, the registry (it differs from the base by
# exactly the one rider, pointing at the generic packet brief with the sha256 of that brief's bytes). No chain validator
# or chain test is pinned here. Last, this layer's own inverse hunks are the canonical byte-minimal ones, recomputed
# from its era's bytes (MET-PERF-040's carried rule).
RECORD_PATH = "architecture/release-profile.json"
ORACLE_IDENTITY = "architecture/release-profile/oracle-identity.json"
ORACLE_SCHEMA = "planeon.oracle-identity/v1"
MODEL_PATH = "scripts/release_profile.py"
MODEL_NAME = "_met_adopt_006_release_profile"
OVERLAY_MODULE_PATH = "scripts/sector_catalog.py"
OVERLAY_MODULE_NAME = "_met_adopt_006_sector_catalog"
LOADER_PATH = "scripts/safe_yaml.py"
LOADER_NAME = "_met_adopt_006_safe_yaml"
ORACLE_TEST = "tests/test_met_adopt_006_oracle.py"
REGISTRY_PATH = "architecture/review-record/briefs.json"
PACKET_BRIEF = "architecture/review-briefs/REVIEW_BRIEF_PACKET.md"
# V1: the packet's files, named by path; each is pinned below by the sha256 of its adopted bytes.
PACKET_FILES = (
    "architecture/release-profile.json",
    "architecture/release-profile/README.md",
    "architecture/release-profile/oracle-identity.json",
    "scripts/release_profile.py",
    "tests/test_met_adopt_006_oracle.py",
)
# V2: the files the model reads besides the record and the catalogs, and the two modules it runs with.
MODEL_INPUTS = (
    "architecture/sector-catalog/overlay.json",
    "architecture/sector-direction.json",
    "docs/alpha-2/HARNESS_PAPER_REPOSITORY_MAP.md",
    "architecture/provider-adoption.json",
    "docs/repositories/11-mas-harness-distribution.md",
    "task-packets/CON-001.yaml",
    "task-packets/EXEC-ORCH-001.yaml",
    "task-packets/EXEC-PROT-001.yaml",
    "task-packets/IND-WG-005.yaml",
    "task-packets/KN-DATA-001.yaml",
    "task-packets/KN-DOM-001.yaml",
    "task-packets/KN-RET-001.yaml",
    "task-packets/MODEL-001.yaml",
    "task-packets/MODEL-LLAMACPP-001.yaml",
    "task-packets/RUN-001.yaml",
    "task-packets/RUN-EXP-001.yaml",
    "task-packets/SDK-001.yaml",
    "task-packets/TRUST-001.yaml",
    "task-packets/TRUST-002.yaml",
    "task-packets/TRUST-EVAL-001.yaml",
    "task-packets/TRUST-GOV-001.yaml",
    "task-packets/TRUST-OBS-001.yaml",
    "task-packets/TRUST-REG-001.yaml",
    "scripts/sector_catalog.py",
    "scripts/safe_yaml.py",
)
# V4: the registry at the base (the digest of its canonical JSON) and this packet's one rider (kind, series, path,
# version), appended last; the rider's sha256 is the generic packet brief's.
REGISTRY_BASE_SHA256 = "7480053565a59b9e5f4ccce42eebfb60fb381976ec5543ed11a09736da5afc91"
RIDERS = (("PACKET", NEW_PACKET + "/packet", PACKET_BRIEF, 1),)
# Every file this era's check reads, with its digest, except the three catalogs (bound by the model's own pins): the
# packet's files, the model's other inputs and modules, the registry and the generic packet brief.
ERA_SHA256 = MappingProxyType({
    "architecture/provider-adoption.json": "f22930f0c32a3f552d955378c2f1bc355811c37123a25a8a3cc64d8ea17a4f47",
    "architecture/release-profile.json": "2997bff1bfbb8415267b681d7437c9e435c9bf7e027f0e89fac4b6b32bafc9b3",
    "architecture/release-profile/README.md": "4836c9fed6076937229813e5a50ff8ab31b9edbe4c2bbb10c5dfa92eb6f0d756",
    "architecture/release-profile/oracle-identity.json": "43702210adce2cec679d1559e7994dcf25bbf4ac4bd42002d03c8f9b9b5126cb",
    "architecture/review-briefs/REVIEW_BRIEF_PACKET.md": "6dcff68d7e6b01823f1740063e94910edcc159a71a6ee803f1b66c62fd06e274",
    "architecture/review-record/briefs.json": "43ac02a138d43f47632f0daca049743627f833eb09564019d16d89d8877e5a30",
    "architecture/sector-catalog/overlay.json": "296c973e8902a822da2bdc0ad3603170deb6a91cffc2d37ca9332ddf1834c4e4",
    "architecture/sector-direction.json": "cfc39b4adbfb2771e27cc5498d94530d5691130736a8791288ce296253fc2efe",
    "docs/alpha-2/HARNESS_PAPER_REPOSITORY_MAP.md": "f6a891e8bdbcc579e60800773addd70ca29a2c4021c2dc95af62be93e91f061d",
    "docs/repositories/11-mas-harness-distribution.md": "2ede19ddcaddbec5ba698b9e6cefcb224833a932d887ec217ed347abef777684",
    "scripts/release_profile.py": "666c65ac5b76ec83250a2457062154519df5361cf883d8f44e6fa4f9eb6f2b1a",
    "scripts/safe_yaml.py": "99c673560e65e58cdc1abe86e53472feaf93e546dd76cb9f3ba051beef5c49d7",
    "scripts/sector_catalog.py": "399f57f47d481cc0c7ace992dcd0e200da346180d98668cd4e9f444e278acb2a",
    "task-packets/CON-001.yaml": "88383a2c8bc66c959df0abc8bc1c8d86a852cac654cd1833327f8b06e2cf41b4",
    "task-packets/EXEC-ORCH-001.yaml": "bab8ff0d2a85f22484c29011836c2458449755634bf27b3462199ef445354d75",
    "task-packets/EXEC-PROT-001.yaml": "8dda3de5062124d3c2080ab5eaf68dd3d9b73f5e0f9c4fe646ec9284263201c2",
    "task-packets/IND-WG-005.yaml": "033db2dd187457a94a8a346baf6aa11bd07ad6ac25cfc3d4d315a60b2e78ae38",
    "task-packets/KN-DATA-001.yaml": "73422c32a67d78cbcb6e74447482022f3552b24fd8ca356da5da91c9c538e0d2",
    "task-packets/KN-DOM-001.yaml": "452fd1e14baa779023ca27511af9b9a8b4281ddc8dea51327b93e594700e9f56",
    "task-packets/KN-RET-001.yaml": "d417da2b27707a0b69590019e556f35cf6d6f737c37858c9099481323415a5b1",
    "task-packets/MODEL-001.yaml": "753847ad57b2247a281b23c8f7db1956da3ae5d33f32433b25e80d44585160c0",
    "task-packets/MODEL-LLAMACPP-001.yaml": "f151b3393cb61b9133f21488fb53f01117e0960078077b6439bdc612adda793d",
    "task-packets/RUN-001.yaml": "4fa60ad4793d2268ccd5f84e0cbc4ce3d45340abf2ba824b30cc895b5a618457",
    "task-packets/RUN-EXP-001.yaml": "2a134a3b0e344b18a35ef3b82f1d34aa74f79ef83ab0730cda2eb740bce4a541",
    "task-packets/SDK-001.yaml": "737990fc853fd50c22d211f0ada320585b304fe116cab881581575a9a6dca941",
    "task-packets/TRUST-001.yaml": "d4fec1372836a3c85458b1e489fabda0869cc38a8bc480a709dc94e0e5fb8b19",
    "task-packets/TRUST-002.yaml": "cf80bc33b5517177e00f2d9e8bddb92c41f1c59b18a0cc2f54688a693a4ac151",
    "task-packets/TRUST-EVAL-001.yaml": "c0f5eaa5e35ea34fff04eb49ae4b500b4dbcc01221e11ece6b95b845c376828c",
    "task-packets/TRUST-GOV-001.yaml": "af7591bd4b20237ad54e942c65d4149540f4dca3d72b6478db6bb9e0afff3221",
    "task-packets/TRUST-OBS-001.yaml": "760c4a519ec39f1a4a9523eca563d4e22597b06c8b8929913a7953d0f30f0290",
    "task-packets/TRUST-REG-001.yaml": "83fc22106c0eeb31b032bd3f5820eb359855d5c928f9bf3be9cd7edf1563427e",
    "tests/test_met_adopt_006_oracle.py": "900051dfbd53e034552ab67771b587fc7a06e86376d34f0af60b5afc440bf71b",
})


def reviewed_bytes(path: str) -> bytes:
    """This packet's reviewed bytes of path; a bridged successor projects newer bytes back first."""
    return successor.historical_bytes(path, regular_bytes(path))


def check_catalog_pins(model_raw: Any) -> MappingProxyType:
    """The three catalogs' paths and base digests, as the model's bytes name them in BASE_SHA256, its keys resolved
    through the model's own path constants (read as literals, never executed); anything else is refused."""
    names, pins = {}, None
    try:
        tree = ast.parse(model_raw) if type(model_raw) is bytes else None
    except (SyntaxError, ValueError):
        tree = None
    for node in tree.body if tree is not None else ():
        if not (isinstance(node, ast.Assign) and len(node.targets) == 1 and isinstance(node.targets[0], ast.Name)):
            continue
        if isinstance(node.value, ast.Constant) and type(node.value.value) is str:
            names[node.targets[0].id] = node.value.value
        elif node.targets[0].id == "BASE_SHA256" and isinstance(node.value, ast.Dict):
            try:
                pins = {names.get(key.id) if isinstance(key, ast.Name) else None: ast.literal_eval(value)
                        for key, value in zip(node.value.keys, node.value.values)}
            except (AttributeError, ValueError):
                pins = None
    require(type(pins) is dict and len(pins) == 3
            and all(type(path) is str and _sha(sha) for path, sha in pins.items())
            and not set(pins) & set(ERA_SHA256), "the model names and pins exactly three catalogs outside the era")
    return MappingProxyType(dict(pins))


def _catalog_pins() -> MappingProxyType:
    """The catalog pins of the V1-verified model, read again on each use (no cache)."""
    return check_catalog_pins(_era_bytes(MODEL_PATH, reviewed_bytes(MODEL_PATH)))


def _era_bytes(path: Any, raw: Any) -> bytes:
    """An era file's bytes, checked against its era digest; a path outside the era is refused."""
    expected = ERA_SHA256.get(path) if type(path) is str else None
    if expected is None and type(path) is str and path != MODEL_PATH:
        expected = _catalog_pins().get(path)
    require(expected is not None, "MET-ADOPT-006 reviewed bytes are bound: " + str(path))
    require(type(raw) is bytes and digest(raw) == expected, "unreviewed RELEASE-PROFILE-001 source: " + path)
    return raw


def _verified(path: str) -> bytes:
    """reviewed_bytes, checked against its era digest on every read; a path outside the era is refused before it is
    read."""
    require(type(path) is str and (path in ERA_SHA256 or path in _catalog_pins()),
            "MET-ADOPT-006 reviewed bytes are bound: " + str(path))
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


def _era_import(era: dict) -> Any:
    """An import function that resolves the named modules to this era's copies and everything else normally."""
    def era_import(name, globals=None, locals=None, fromlist=(), level=0):
        if level == 0 and name in era:
            return era[name]
        return builtins.__import__(name, globals, locals, fromlist, level)
    return era_import


def _era_model(path: str, name: str, imports: dict | None = None) -> types.ModuleType:
    """A reference module of this era, executed from its verified bytes (no import, no bytecode); named imports resolve
    to this era's copies."""
    module = types.ModuleType(name)
    module.__file__ = str(ROOT / path)
    if imports:
        namespace = dict(vars(builtins))
        namespace["__import__"] = _era_import(imports)
        module.__dict__["__builtins__"] = namespace
    exec(compile(_verified(path), path, "exec", dont_inherit=True), module.__dict__)
    return module


def _era_release_profile() -> types.ModuleType:
    """The model with `from scripts import sector_catalog` resolved to this era's overlay module and its
    `from scripts.safe_yaml import safe_load` to this era's YAML loader; the overlay's loader imports (`safe_yaml` and
    its `scripts.safe_yaml` fallback) resolve to the same copy (GO-272-P1-FIX)."""
    loader = _era_model(LOADER_PATH, LOADER_NAME)
    overlay = _era_model(OVERLAY_MODULE_PATH, OVERLAY_MODULE_NAME, {"safe_yaml": loader, "scripts.safe_yaml": loader})
    return _era_model(MODEL_PATH, MODEL_NAME, {"scripts": types.SimpleNamespace(sector_catalog=overlay),
                                               "scripts.safe_yaml": loader})


def _packet_set() -> frozenset:
    """This layer's own packet set: the authority's baseline packets and this packet, never a directory listing."""
    return frozenset(_PACKET_BYTE_RULES)


def check_packet_files(files: Any) -> None:
    """V1: the packet's files are exactly the five, and each one's bytes equal the sha256 pinned for it."""
    _bound(lambda: type(files) is dict and sorted(files) == sorted(PACKET_FILES) and len(files) == len(PACKET_FILES),
           "the packet files are exactly the five")
    for path in PACKET_FILES:
        _bound(lambda: type(files[path]) is bytes and digest(files[path]) == ERA_SHA256[path],
               "a packet file's bytes equal its pinned digest: " + path)


def validate_packet_files() -> None:
    """V1 over the five files, each read through the era."""
    check_packet_files({path: _verified(path) for path in PACKET_FILES})


def check_model(model: Any, read: Any, packets: Any) -> None:
    """V2: the model's check(read, packets), run over the reviewed bytes read gives it and this layer's packet set,
    returns its result without a refusal."""
    _bound(lambda: type(model) is types.ModuleType and type(packets) is frozenset
           and type(model.check(read, packets)) is dict,
           "the release-profile model accepts the record over this era's bytes")


def validate_model() -> None:
    """V2 with the model executed from its V1-verified bytes (slot 265's era-loader form), this era's reader and this
    layer's packet set."""
    check_model(_era_release_profile(), _verified, _packet_set())


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
           "the registry differs from the base by exactly the MET-ADOPT-006 packet rider, pinning the generic packet "
           "brief")


def validate_registry() -> None:
    """V4 over briefs.json and the generic packet brief."""
    check_registry(_verified(REGISTRY_PATH), {PACKET_BRIEF: _verified(PACKET_BRIEF)})


def validate_release_profile() -> None:
    """Every reviewed byte first; then V1 (the packet's files), V2 (the model), V3 (the oracle) and V4 (the registry);
    last, this layer's canonical hunks."""
    for path in ERA_SHA256:
        _verified(path)
    for path in _catalog_pins():
        _verified(path)
    validate_packet_files()
    validate_model()
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
    validator_raw = successor.historical_bytes(VALIDATOR_PATH, regular_bytes(VALIDATOR_PATH))
    literal = b'AUTHORITY_SHA256 = "' + AUTHORITY_SHA256.encode("ascii") + b'"'
    placeholder = b'AUTHORITY_SHA256 = "TO_BE_PINNED_AFTER_SOURCE_FREEZE"'
    require(validator_raw.count(literal) == 1
            and digest(validator_raw.replace(literal, placeholder))
            == record["validatorNormalizedSha256"], "release profile validator drift")
    paths = sorted((ROOT / "task-packets").glob("*.yaml"))
    old = set(record["baselinePackets"])
    require(len(paths) == 278
            and {path.stem for path in paths} == old | {NEW_PACKET, successor.NEW_PACKET, successor.successor.NEW_PACKET, *successor.successor.PRODUCT_PACKETS, successor.successor.successor.NEW_PACKET, *successor.successor.successor.PRODUCT_PACKETS},
            "closed 278-packet catalog retaining the 272-packet checkpoint")
    packets = {}
    for path in paths:
        if path.stem in (successor.NEW_PACKET, successor.successor.NEW_PACKET, *successor.successor.PRODUCT_PACKETS, successor.successor.successor.NEW_PACKET, *successor.successor.successor.PRODUCT_PACKETS):
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
            "closed source-only release-profile packet and inherited commands")
    require(len(packet["allowedPaths"]) == len(set(packet["allowedPaths"]))
            and set(packet["allowedPaths"]) == set(record["changedFiles"])
            | set(record["newFiles"]) | {AUTHORITY_PATH, VALIDATOR_PATH,
                                         "task-packets/" + NEW_PACKET + ".yaml"},
            "unreviewed or omitted release-profile packet path")
    for path, rule in record["changedFiles"].items():
        current = successor.historical_bytes(path, regular_bytes(path))
        require(digest(current) == rule["afterSha256"]
                and digest(historical_bytes(path, current)) == rule["beforeSha256"],
                "unreviewed current source: " + path)
    for path, expected in record["newFiles"].items():
        require(digest(successor.historical_bytes(path, regular_bytes(path))) == expected,
                "new source drift: " + path)
    validate_release_profile()


if __name__ == "__main__":
    validate()
    print("Release profile valid: 278 current specifications; 272-packet checkpoint and exact 271-packet predecessor; contract reviewed.")
