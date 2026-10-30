#!/usr/bin/env python3
"""Validate the MET-ENFORCE-031 license-policy amendment A2 and the exact 243-to-242 projection."""
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
    import validate_w03_plan_amend_2 as successor
except ImportError:
    from scripts.safe_yaml import safe_load
    from scripts import validate_w03_plan_amend_2 as successor


ROOT = Path(__file__).resolve().parents[1]
AUTHORITY_PATH = "architecture/license-amendment-v2-authority.json"
AUTHORITY_SHA256 = "9ab099dcd376bf717fcd648deeb3af0a95222d79974206c49193860f743cd31a"
VALIDATOR_PATH = "scripts/validate_license_amendment_v2.py"
BASE_COMMIT = "fd362f9eb64d6e9928f26fac5e339a50b8dee516"
NEW_PACKET = "MET-ENFORCE-031"
PREVIOUS_PACKET = "MET-ENFORCE-030"
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
            require(key not in result, "duplicate license-amendment-v2 authority member")
            result[key] = value
        return result

    def no_constant(_value: str) -> Any:
        raise ValueError("nonfinite license-amendment-v2 authority number")

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
        require(digest(raw) == AUTHORITY_SHA256, "license amendment v2 history authority digest")
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
    }, "closed license amendment v2 history authority")
    require(value["schemaVersion"] == "harness.planeon.ai/license-amendment-v2-authority/v1"
            and value["authorityPacket"] == NEW_PACKET
            and value["acceptedBase"] == BASE_COMMIT
            and type(value["baselinePackets"]) is dict
            and len(value["baselinePackets"]) == 242
            and NEW_PACKET not in value["baselinePackets"]
            and type(value["changedFiles"]) is dict
            and type(value["newFiles"]) is dict
            and _sha(value["packetSha256"])
            and _sha(value["validatorNormalizedSha256"]),
            "accepted 242-packet base")
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
    # An exact 242-era byte string is already older than the successor layer.
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


# MET-ENFORCE-031 (roadmap LICENCE-POLICY-AMEND; the lane monitor's owner-delegated LIC-ZLIB, 2026-10-15, and L2-1 (a)
# and L2-2 (a), 2026-10-16) publishes license-policy amendment LIC-HOST-A2: Zlib is default-allowed globally, as an
# overlay on the byte-identical base policy and the byte-identical A1. Repository bytes are read only through
# reviewed_bytes, so a later bridged successor projects its own edits away first. A path outside this era is refused
# before it is read (P2-F2), and every era file is bound by digest on every read. The A1 classifier, its safe_yaml (the
# import closure, LR3-2) and the A2 model are executed from this era's bytes; the A2 model gets this era's A1 under the
# import name license_amendment, and its one file read, the running A1 classifier's identity check, is served by the
# verified reads too (LR2-4). Every A1 and A2 vector also replays here, through the era classifier, and the decided
# cases include negative ones (P2-F1). This layer's own inverse hunks are the canonical byte-minimal ones, recomputed
# from its era's bytes (MET-PERF-040's carried rule).
A2_DIR = "legal/license-policy-amendment-v2/"
A1_DIR = "legal/license-policy-amendment/"
A2_MODEL = "scripts/license_amendment_v2.py"
A1_MODEL = "scripts/license_amendment.py"
SAFE_YAML = "scripts/safe_yaml.py"
BASE_POLICY = "legal/third-party-license-policy.yaml"
A1_RECORD = A1_DIR + "amendment.json"
A1_VECTORS = A1_DIR + "vectors.json"
STATUS_PATH = A2_DIR + "status.json"
A2_VECTORS = A2_DIR + "vectors.json"
SUBJECT = (A2_DIR + "README.md", A2_DIR + "REVIEW_BRIEF.md", A2_DIR + "amendment.json", A2_VECTORS, A2_MODEL)
REVIEWED_SUBJECT = {"commit": "2e81e2f1508fe61561741cdaf0d9b13e5e155f64", "tree": "d71b8a707f51782e29931e2be3ba85b69edac230"}
ROUNDS = ((1, "CHANGES_REQUIRED"), (2, "CHANGES_REQUIRED"), (3, "PASS_FOR_SOURCE_PUBLICATION"))
STATUS_KEYS = frozenset({"schemaVersion", "workItem", "amendmentId", "status", "baseMain", "reviewedSubject",
                         "independentReviewer", "readmeStatusNote", "rounds", "closedFindings", "carried", "nonClaims"})
ROW_KEYS = frozenset({"round", "record", "recordSha256", "verdict", "subjectCommit", "subjectTree", "subjectSha256",
                      "snapshot"})
NON_CLAIMS = ["The base policy, A1 and the research-adoption record are byte-identical.",
              "No artifact is released, and no consumer is switched to A2 by this record.",
              "Not legal advice; the decisions recorded in amendment.json are the approving authority."]
CLOSED_FINDINGS = {**{"LR1-%d" % n: "CLOSED in round 2" for n in range(1, 9)},
                   **{"LR2-%d" % n: "CLOSED in round 3" for n in (1, 2, 3, 5)},
                   "LR2-4": "carried to the packet layer (see carried)"}
# The four packet-layer items the adopted status carries to this layer, by their leading id.
CARRIED_HERE = ("P2-F1", "P2-F2", "LR2-4", "LR3-2")
DECISIONS = (("LIC-ZLIB", "2026-10-15", None), ("L2-1", "2026-10-16", "a"), ("L2-2", "2026-10-16", "a"))
A1_CASES = 88
A2_CASES = 34
# Uses the classifier must decide this way, under A1 and under A2: (expression, component, kind, binary it is linked
# into, A1 result, A2 result), each result an outcome and its elections. The first six are Zlib's (LIC-ZLIB, L2-1 (a));
# the last five are P2-F1's negative cases: an explicit-review term outside its decision's scope (twice), a base denied
# term, an unknown term and an open-content term outside ARTIFACT, none of which A2 changes.
DECIDED_CASES = (
    ("Zlib", "zlib-licensed-crate", "CRATE", None, ("UNKNOWN", ()), ("DEFAULT_ALLOWED", ())),
    ("Zlib", "zlib", "HOST_OS_LIBRARY", None, ("UNKNOWN", ()), ("DEFAULT_ALLOWED", ())),
    ("Zlib OR SSPL-1.0", "zlib-licensed-crate", "CRATE", None, ("UNKNOWN", ()),
     ("ACCEPTED_OR", (("SSPL-1.0 OR Zlib", "Zlib"),))),
    ("Zlib AND SSPL-1.0", "zlib-licensed-crate", "CRATE", None, ("DENIED", ()), ("DENIED", ())),
    ("zlib", "zlib-licensed-crate", "CRATE", None, ("UNKNOWN", ()), ("UNKNOWN", ())),
    ("Zlib WITH LLVM-exception", "zlib-licensed-crate", "CRATE", None, ("UNKNOWN", ()), ("UNKNOWN", ())),
    ("GPL-2.0-only", "other-program", "HOST_OS_PROGRAM", None, ("OPTIONAL_EXPLICIT_REVIEW", ()),
     ("OPTIONAL_EXPLICIT_REVIEW", ())),
    ("GPL-2.0-only", "nft", "CRATE", None, ("OPTIONAL_EXPLICIT_REVIEW", ()), ("OPTIONAL_EXPLICIT_REVIEW", ())),
    ("SSPL-1.0", "some-crate", "CRATE", None, ("DENIED", ()), ("DENIED", ())),
    ("WTFPL", "some-crate", "CRATE", None, ("UNKNOWN", ()), ("UNKNOWN", ())),
    ("CC-BY-4.0", "some-crate", "CRATE", None, ("OUT_OF_SCOPE", ()), ("OUT_OF_SCOPE", ())),
)
# The base policy, A1 (record, vectors and classifier) and the classifier's import closure stay byte-identical.
FROZEN_PATHS = (
    "legal/license-policy-amendment/amendment.json",
    "legal/license-policy-amendment/vectors.json",
    "legal/third-party-license-policy.yaml",
    "scripts/license_amendment.py",
    "scripts/safe_yaml.py",
)
ERA_SHA256 = MappingProxyType({
    "legal/license-policy-amendment-v2/README.md": "740ee084dcadaa9f3880f99b04dd6ad3f15c8cb55389864f4f226ee470c7f3ce",
    "legal/license-policy-amendment-v2/REVIEW_BRIEF.md": "b3e5ea8514301708e6438b27cb526bbf9a353fc4255e4b6108beda7f6d93fd83",
    "legal/license-policy-amendment-v2/amendment.json": "05984db7339c60cf0d4b9acc1179bd0b5fbb16c6f2f4dd554889388133e8f3a7",
    "legal/license-policy-amendment-v2/review-round1.json": "0fbbaa289ae5a0bc77aaeb0293910bacecfef9ddcf06ff1ddd90eba66f97689a",
    "legal/license-policy-amendment-v2/review-round2.json": "d75eecb7e012f5dcbcf4b61b747a2dfb5bbd9101806514cdec43ee7b4bc3931e",
    "legal/license-policy-amendment-v2/review-round3.json": "10831f2e1166c7e669f490069d77062a95ab6a76c4e72dfa3c7b44ee128adfb1",
    "legal/license-policy-amendment-v2/round1/legal/license-policy-amendment-v2/README.md": "d2c390a1367b9213ec19e2054c98de54291cc025fc8de24c685b47b9006bcc9a",
    "legal/license-policy-amendment-v2/round1/legal/license-policy-amendment-v2/REVIEW_BRIEF.md": "32cd0720aefaf1201f9a1d0c1f6d15c4ecc71a655050cf633c702e5d6c331324",
    "legal/license-policy-amendment-v2/round1/legal/license-policy-amendment-v2/amendment.json": "d58079a2d9565c7bf358fad0661985bc399ed0828a3de243fe91e7bd3ce12bbd",
    "legal/license-policy-amendment-v2/round1/legal/license-policy-amendment-v2/vectors.json": "fbc93a278671e77cf2ea9534acc37bff03d50de94dedb32db15621f26f820ec0",
    "legal/license-policy-amendment-v2/round1/scripts/license_amendment_v2.py": "45d344ca15a9862ea4ce293e62875592721559e6dc813af662f85e8e1983e149",
    "legal/license-policy-amendment-v2/round2/legal/license-policy-amendment-v2/README.md": "55e99f3035852e1a5ef60cd12cfeead6ac728ffdd20ef8dd9b3ea76511238dcb",
    "legal/license-policy-amendment-v2/round2/legal/license-policy-amendment-v2/REVIEW_BRIEF.md": "8caeef9c9983e5b6901dceeebd628b7c3c56b81176e62ff1dda0fd24d55528ea",
    "legal/license-policy-amendment-v2/round2/legal/license-policy-amendment-v2/amendment.json": "818aaedd4ab01295f57754035ea673baac7762fa4e48f255449e1a05241183e0",
    "legal/license-policy-amendment-v2/round2/scripts/license_amendment_v2.py": "d9a2ff19ce90f0994681f5098afe0b80195c3804196257b122e0289087a46574",
    "legal/license-policy-amendment-v2/status.json": "2b760f53dca5fcd627b7684549bb5402ab8f357a237881ba4cdba72c824821cf",
    "legal/license-policy-amendment-v2/vectors.json": "aaab430c9f011e164915e83677997cfbe6b62b29e3ca923a5c23b7a680ebd6b9",
    "legal/license-policy-amendment/amendment.json": "f6a8c0796857cf40906df3e6bc483122988b91271cc77b3aaed4d4e213d864c2",
    "legal/license-policy-amendment/vectors.json": "fd2af21605c04420f76d148b71cf39e026251931df215e77eafce8c925549b24",
    "legal/third-party-license-policy.yaml": "fa3a4398acafc3960eaaae9f5396d4e96d91e6ff252b83f6c53e1f5f0d8a40d0",
    "scripts/license_amendment.py": "58758a4a7bb6bbcf49daf1880cc423566da306cfd90dceadfa1b4b7c53ec28cd",
    "scripts/license_amendment_v2.py": "0f87f029d3227960a103174d86d3c37c6c8b83e0d0ae766a089288bf85294e14",
    "scripts/safe_yaml.py": "99c673560e65e58cdc1abe86e53472feaf93e546dd76cb9f3ba051beef5c49d7",
})


def reviewed_bytes(path: str) -> bytes:
    """This packet's reviewed bytes of path; a bridged successor projects newer bytes back first."""
    return successor.historical_bytes(path, regular_bytes(path))


def _verified(path: str) -> bytes:
    """reviewed_bytes, checked against its era digest on every read; a path outside the era is refused before it is
    read (P2-F2)."""
    expected = ERA_SHA256.get(path) if type(path) is str else None
    require(expected is not None, "LIC-HOST-A2 reviewed bytes are bound: " + str(path))
    raw = reviewed_bytes(path)
    require(type(raw) is bytes and digest(raw) == expected, "unreviewed LIC-HOST-A2 source: " + path)
    return raw


def _json(path: str) -> Any:
    return parse(_verified(path))


def _bound(check: Any, message: str) -> None:
    """A structural check over a module's result or this era's data; a malformed value is refused, not raised."""
    try:
        holds = check()
    except (KeyError, TypeError, AttributeError, IndexError, ValueError):
        holds = False
    require(holds is True, message)


def _era_import(era: dict) -> Any:
    """An import function that resolves the named modules to this era's copies and everything else normally."""
    def era_import(name, globals=None, locals=None, fromlist=(), level=0):
        if level == 0 and name in era:
            return era[name]
        return builtins.__import__(name, globals, locals, fromlist, level)
    return era_import


def _era_model(path: str, name: str, imports: dict | None = None) -> types.ModuleType:
    """A reference module of this era, executed from its verified bytes; named imports resolve to this era's copies."""
    module = types.ModuleType(name)
    module.__file__ = str(ROOT / path)
    if imports:
        namespace = dict(vars(builtins))
        namespace["__import__"] = _era_import(imports)
        module.__dict__["__builtins__"] = namespace
    exec(compile(_verified(path), path, "exec", dont_inherit=True), module.__dict__)
    return module


def _era_pathlib() -> types.ModuleType:
    """pathlib as the A2 model sees it: Path(...).read_bytes() serves the running A1 classifier's file through this
    era's verified reads and refuses any other path (LR2-4), so the model's identity check reads no unverified byte."""
    module = types.ModuleType("_met_enforce_031_pathlib")

    class EraPath:
        def __init__(self, *parts: Any) -> None:
            self._path = Path(*parts)

        def read_bytes(self) -> bytes:
            relative = (self._path.relative_to(ROOT).as_posix() if self._path.is_absolute()
                        and self._path.is_relative_to(ROOT) else None)
            require(relative == A1_MODEL, "the A2 model reads only the A1 classifier, through the verified reads: "
                    + str(self._path))
            return _verified(relative)

    module.Path = EraPath
    return module


def era_modules() -> tuple[types.ModuleType, types.ModuleType]:
    """This era's A1 classifier (with its era safe_yaml) and the A2 model (with that A1 as license_amendment)."""
    safe_yaml = _era_model(SAFE_YAML, "_met_enforce_031_safe_yaml")
    a1 = _era_model(A1_MODEL, "_met_enforce_031_license_amendment", {"safe_yaml": safe_yaml, "scripts.safe_yaml": safe_yaml})
    a2 = _era_model(A2_MODEL, "_met_enforce_031_license_amendment_v2", {"license_amendment": a1, "pathlib": _era_pathlib()})
    require(a2.a1 is a1 and a2.classify is a1.classify, "the A2 model runs this era's A1 classifier")
    return a1, a2


def validate_amendment_v2_status() -> None:
    """Adopted after three independent review rounds, each bound to its record and its exact subject bytes, the last a
    pass with notes only on the reviewed subject; the four packet-layer items are carried here."""
    status = _json(STATUS_PATH)
    _bound(lambda: type(status) is dict and set(status) == STATUS_KEYS
           and status["schemaVersion"] == "planeon.internal.license-policy-amendment-v2-status/v1"
           and status["workItem"] == "LICENCE-POLICY-AMEND" and status["amendmentId"] == "LIC-HOST-A2"
           and status["status"] == "ADOPTED_FOR_SOURCE_PUBLICATION"
           and status["reviewedSubject"] == REVIEWED_SUBJECT
           and status["independentReviewer"] == "SEPARATE_AGENT_NOT_AUTHOR" and status["nonClaims"] == NON_CLAIMS
           and status["closedFindings"] == CLOSED_FINDINGS
           and type(status["carried"]) is list
           and all(type(row) is dict and set(row) == {"item", "to", "action"} for row in status["carried"])
           and [row["item"].split(" ")[0] for row in status["carried"]
                if row["to"] == "the LIC-HOST-A2 packet layer"] == list(CARRIED_HERE),
           "adopted LIC-HOST-A2 status, its four packet-layer items carried here")
    rounds = status["rounds"]
    _bound(lambda: type(rounds) is list and len(rounds) == len(ROUNDS)
           and all(type(row) is dict and set(row) == ROW_KEYS | ({"keptCopies"} if n < len(ROUNDS) else set())
                   for n, row in enumerate(rounds, 1))
           and [(row["round"], row["verdict"]) for row in rounds] == list(ROUNDS),
           "three review rounds in order")
    for number, row in enumerate(rounds, 1):
        snapshot = row["snapshot"]
        kept = row.get("keptCopies", [])
        record = _json(row["record"]) if row["record"] == A2_DIR + "review-round%d.json" % number else None
        _bound(lambda: type(record) is dict and digest(_verified(row["record"])) == row["recordSha256"]
               and record["round"] == number and record["subject"] == row["subjectCommit"]
               and record["verdict"] == row["verdict"]
               and snapshot == (A2_DIR + "round%d/" % number if number < len(ROUNDS) else None)
               and type(kept) is list and set(kept) <= set(SUBJECT)
               and row["subjectSha256"] == {path: digest(_verified(snapshot + path if path in kept else path))
                                            for path in SUBJECT},
               "review round %d is bound to its record and its exact subject bytes" % number)
    final = _json(rounds[-1]["record"])
    _bound(lambda: rounds[-1]["subjectCommit"] == REVIEWED_SUBJECT["commit"]
           and rounds[-1]["subjectTree"] == REVIEWED_SUBJECT["tree"]
           and type(final["findings"]) is list
           and all(type(row) is dict and row["severity"] == "NOTE" for row in final["findings"]),
           "the passing round reviewed this subject and left notes only")


def _replayed(a1: types.ModuleType, policy: Any, case: dict) -> dict:
    """One vector through the era classifier, here in the validator; a ValueError is REFUSED."""
    try:
        got = a1.classify(policy, case["expression"], case["component"])
    except ValueError:
        return {"outcome": "REFUSED", "elections": []}
    return {"outcome": got["outcome"], "elections": got["elections"]}


def replay_vectors(a1: types.ModuleType, policy1: Any, policy2: Any) -> None:
    """P2-F1: every A1 vector replays to its A1 result under A1 and under A2 (A2 changes none of them), and every A2
    vector to its stated A1 and A2 results, independently of the models' own replay."""
    cases1 = _json(A1_VECTORS)["cases"]
    cases2 = _json(A2_VECTORS)["cases"]
    require(type(cases1) is list and len(cases1) == A1_CASES and type(cases2) is list and len(cases2) == A2_CASES,
            "the A1 and A2 vector counts")
    for case in cases1:
        _bound(lambda: _replayed(a1, policy1, case) == _replayed(a1, policy2, case)
               == {"outcome": case["outcome"], "elections": case["elections"]},
               "A1 vector replays under A1 and A2: %r" % (case.get("expression") if type(case) is dict else case,))
    for case in cases2:
        _bound(lambda: _replayed(a1, policy1, case) == case["a1"] and _replayed(a1, policy2, case) == case["a2"],
               "A2 vector replays under A1 and A2: %r" % (case.get("expression") if type(case) is dict else case,))


def decided_cases_hold(a1: types.ModuleType, policy1: Any, policy2: Any) -> bool:
    for expression, name, kind, linked, under_a1, under_a2 in DECIDED_CASES:
        component = {"name": name, "kind": kind, "custody": "UPSTREAM_PINNED", "crateField": False,
                     "linkedInto": None if linked is None else {"name": linked, "custody": "UPSTREAM_PINNED"}}
        for policy, expected in ((policy1, under_a1), (policy2, under_a2)):
            got = _replayed(a1, policy, {"expression": expression, "component": component})
            if (got["outcome"], tuple((row["group"], row["elected"]) for row in got["elections"])) != expected:
                return False
    return True


def validate_license_amendment_v2() -> None:
    """Every reviewed byte and the adoption record first; then the models from this era's bytes, the validator-side
    replay of every vector, the decided cases and the owner's decisions."""
    for path in FROZEN_PATHS:
        require(path not in _PROJECTION_RULES, "the base policy, A1 and its import closure stay byte-identical")
    for path in ERA_SHA256:
        _verified(path)
    validate_amendment_v2_status()
    a1, a2 = era_modules()
    amendment = a2.check(_verified)
    policy1 = a1.effective_policy(_verified)
    policy2 = a2.effective_policy(_verified)
    replay_vectors(a1, policy1, policy2)
    require(decided_cases_hold(a1, policy1, policy2), "the classifier decides the decided cases under A1 and A2")
    _bound(lambda: [(row["id"], row["date"], row["selected"]) for row in amendment["ownerDecisions"]] == list(DECISIONS)
           and amendment["additionalDefaultAllowedSpdx"] == ["Zlib"]
           and amendment["base"] == {"path": BASE_POLICY, "sha256": ERA_SHA256[BASE_POLICY], "policyVersion": "0.3.0"}
           and amendment["predecessor"]["record"]["sha256"] == ERA_SHA256[A1_RECORD]
           and amendment["predecessor"]["vectors"]["sha256"] == ERA_SHA256[A1_VECTORS]
           and amendment["predecessor"]["model"]["sha256"] == ERA_SHA256[A1_MODEL]
           and [row["id"] for row in amendment["carriedFindings"]] == ["P2-F1", "P2-F2"]
           and _json(A2_VECTORS)["a1Replay"]["changed"] == [],
           "the amendment carries the owner's decisions")
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
            == record["validatorNormalizedSha256"], "license amendment v2 validator drift")
    paths = sorted((ROOT / "task-packets").glob("*.yaml"))
    old = set(record["baselinePackets"])
    require(len(paths) == 271
            and {path.stem for path in paths} == old | {NEW_PACKET, successor.NEW_PACKET, successor.successor.NEW_PACKET, successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.NEW_PACKET},
            "closed 271-packet catalog retaining the 243-packet checkpoint")
    packets = {}
    for path in paths:
        if path.stem in (successor.NEW_PACKET, successor.successor.NEW_PACKET, successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.NEW_PACKET):
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
            "closed source-only license-amendment-v2 packet and inherited commands")
    require(len(packet["allowedPaths"]) == len(set(packet["allowedPaths"]))
            and set(packet["allowedPaths"]) == set(record["changedFiles"])
            | set(record["newFiles"]) | {AUTHORITY_PATH, VALIDATOR_PATH,
                                         "task-packets/" + NEW_PACKET + ".yaml"},
            "unreviewed or omitted license-amendment-v2 packet path")
    for path, rule in record["changedFiles"].items():
        current = successor.historical_bytes(path, regular_bytes(path))
        require(digest(current) == rule["afterSha256"]
                and digest(historical_bytes(path, current)) == rule["beforeSha256"],
                "unreviewed current source: " + path)
    for path, expected in record["newFiles"].items():
        require(digest(successor.historical_bytes(path, regular_bytes(path))) == expected,
                "new source drift: " + path)
    validate_license_amendment_v2()


if __name__ == "__main__":
    validate()
    print("License-policy amendment A2 valid: 271 current specifications; 243-packet checkpoint and exact 242-packet predecessor; contract reviewed.")
