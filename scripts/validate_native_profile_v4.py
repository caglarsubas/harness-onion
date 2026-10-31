#!/usr/bin/env python3
"""Validate the MET-ENFORCE-033 native-profile v4 and I06 v3 and the exact 246-to-245 projection."""
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
    import validate_selinux_matrix_v4 as successor
except ImportError:
    from scripts.safe_yaml import safe_load
    from scripts import validate_selinux_matrix_v4 as successor


ROOT = Path(__file__).resolve().parents[1]
AUTHORITY_PATH = "architecture/native-profile-v4-authority.json"
AUTHORITY_SHA256 = "0170e8989724665959607fa1680da3b9ea877c5d9aeab49d0ffb65c929600227"
VALIDATOR_PATH = "scripts/validate_native_profile_v4.py"
BASE_COMMIT = "75669de34d6305abca3bf2ddf3699f1dbb888c6e"
NEW_PACKET = "MET-ENFORCE-033"
PREVIOUS_PACKET = "MET-MAS-004"
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
            require(key not in result, "duplicate native-profile-v4 authority member")
            result[key] = value
        return result

    def no_constant(_value: str) -> Any:
        raise ValueError("nonfinite native-profile-v4 authority number")

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
        require(digest(raw) == AUTHORITY_SHA256, "native profile v4 history authority digest")
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
    }, "closed native profile v4 history authority")
    require(value["schemaVersion"] == "harness.planeon.ai/native-profile-v4-authority/v1"
            and value["authorityPacket"] == NEW_PACKET
            and value["acceptedBase"] == BASE_COMMIT
            and type(value["baselinePackets"]) is dict
            and len(value["baselinePackets"]) == 245
            and NEW_PACKET not in value["baselinePackets"]
            and type(value["changedFiles"]) is dict
            and type(value["newFiles"]) is dict
            and _sha(value["packetSha256"])
            and _sha(value["validatorNormalizedSha256"]),
            "accepted 245-packet base")
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
    # An exact 245-era byte string is already older than the successor layer.
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


# MET-ENFORCE-033 (roadmap NATIVE-PROFILE-V4; adopted by the lane monitor's owner-delegated decision, 2026-10-16, after
# three independent contract review rounds, the last PASS_FOR_ADOPTION) publishes native-profile v4 (v3 plus
# O-NATIVE-GATE-NOCAP, the capture routes and the restated inspector obligation), the I06 v3 bound to it, and the
# operator -> harness-engineering edge record v5. Repository bytes and modes are read only through reviewed_bytes and
# reviewed_mode, so a later bridged successor projects its own edits away first; a path outside this era is refused before
# it is read, and every era file is bound by digest on every read. The adoption is checked against the status record:
# the 14 adopted files are candidate 3's bytes except edge record v5's six providerPacket values, which name this packet
# on the same lines (no README line moved); three review rounds bound to their published records, rounds 1 and 2 also to
# both source indexes; the verbatim adoption decision; the closed findings as the later rounds resolved them. The
# schema's label constants are cross-checked against matrix v5 (design section 3.4, D1-13), and the evidenceClasses
# constant against the model where the model decides (EVIDENCE_SCOPE states the scope). Both models
# are executed from this era's bytes (I06 v3 with this era's I06 v1 and native-profile v4 models as its imports) and replay
# every vector over their pinned inputs here, in the validator. Native-profile v1 to v3, I06 v1 and v2, the W02 notes
# errata, matrix v5, seccomp v4, HS43, edge records v1 to v4 and every source-index pin stay byte-identical. This layer's
# own inverse hunks are the canonical byte-minimal ones, recomputed from its era's bytes (MET-PERF-040's carried rule).
NP4_DIR = "architecture/native-profile-v4/"
I06_DIR = "architecture/i06-backend-profile-v3/"
EDGES_DIR = "architecture/artifact-edges/"
NP4_MODEL = "scripts/native_qualification_v4.py"
I06_MODEL = "scripts/i06_backend_profile_v3.py"
I06_V1_MODEL = "scripts/i06_backend_profile.py"
NP4_SCHEMA = NP4_DIR + "qualification.schema.json"
NP4_VECTORS = NP4_DIR + "vectors.json"
NP4_INDEX = NP4_DIR + "source-index.json"
I06_VECTORS = I06_DIR + "vectors.json"
I06_INDEX = I06_DIR + "source-index.json"
STATUS_PATH = NP4_DIR + "status.json"
V4_EDGE = EDGES_DIR + "operator-harness-engineering-v4.json"
V5_EDGE = EDGES_DIR + "operator-harness-engineering-v5.json"
# The adopted subject in the review records' order, and candidate 3's bytes (5a3e6820, tree f8ce4ab0) as the review
# rounds name them; edge record v5 differs from candidate 3 only by the adoption edit.
SUBJECT = (NP4_DIR + "README.md", NP4_DIR + "REVIEW_BRIEF.md", NP4_SCHEMA, NP4_VECTORS, NP4_INDEX, NP4_MODEL,
           I06_DIR + "README.md", I06_DIR + "REVIEW_BRIEF.md", I06_DIR + "criteria.json", I06_VECTORS, I06_INDEX, I06_MODEL,
           V5_EDGE, EDGES_DIR + "README-v5.md")
CANDIDATE_SHA256 = MappingProxyType({
    "architecture/native-profile-v4/README.md": "a4205a5388dc83827bb39670bcc9477b030f29829128abf19f7578321c170174",
    "architecture/native-profile-v4/REVIEW_BRIEF.md": "293b9fc1f4affd9be0ff5d38bbc15dae902c22f5761a0ecdbc82d4f9c24fefea",
    "architecture/native-profile-v4/qualification.schema.json": "c3e91c087ebc6a13e8a96a066f80710ac968c8def434d1d1b97415811715ed10",
    "architecture/native-profile-v4/vectors.json": "dede64ab3202a9e28094f062b5dad868c13ca02423e2380af8666ecf2e7a86e6",
    "architecture/native-profile-v4/source-index.json": "6e2c325054ffd5edee3d71c4163dd38bef42b6b255bbdeae5e2c37814ef178fb",
    "scripts/native_qualification_v4.py": "f7c718072d1ffbb9b8bbc310e6141d476ea5f25296f70ff8c1bc9ada3db02387",
    "architecture/i06-backend-profile-v3/README.md": "9ee406f43060f266a7b5dd2679aa8352f0815584c45e33d0ab193ea7f90c0c77",
    "architecture/i06-backend-profile-v3/REVIEW_BRIEF.md": "ca7bbf5e858c940b32058acf8475242fb1ad898afb92584bfac7f79914f93891",
    "architecture/i06-backend-profile-v3/criteria.json": "752533c57b5f93e4c4158a9c17b52eb88d236a3632ab0b66b669e8f8041f57c7",
    "architecture/i06-backend-profile-v3/vectors.json": "4752b648abdd82d21ea622a1b26c721143577478c0a2491204e0d584c1d6f081",
    "architecture/i06-backend-profile-v3/source-index.json": "7740a01dcd1a9fe41a106532d5ddde37a1cce70e2244c6638d480953532a14c1",
    "scripts/i06_backend_profile_v3.py": "dfb00e90199d436ae63b79261f2e04870d7861cb0f7a424971657a4d777754de",
    "architecture/artifact-edges/operator-harness-engineering-v5.json": "bca25c0c221e7a539a1b5ccb0cab4bb4891be60d663ff64f2ac4dd62f8d75438",
    "architecture/artifact-edges/README-v5.md": "6409a17c2fb0b5ae5df3055c86a3e4cb1e2cb3deacd490c4d547cc1d50a9b6ad",
})
CANDIDATE_LINES = 610
TBD = b'"providerPacket": "TBD"'
ASSIGNED = ('"providerPacket": "%s"' % NEW_PACKET).encode("ascii")
REVIEW_BASE = "b0635f81e5ba3b6538fc0cfd28a78f0fea962f50"
REVIEW_BASE_TREE = "6759da49207aa3f4dd9a0d5d7199e1e9c78bfeee"
# (round, verdict, subject commit, subject tree, subject parent)
ROUNDS = ((1, "CHANGES_REQUIRED", "0a2ecd7157e732b8d7965ed6e985203e733b1d19", "e68017219f4736c828818389d2c07b0fcd1ae696",
           REVIEW_BASE),
          (2, "CHANGES_REQUIRED", "3c34a3a5ff5879d2bcf5e6691bc08eeaf59dbf41", "870a6195eb30b973801c0f67cd7321bcf1264398",
           "0a2ecd7157e732b8d7965ed6e985203e733b1d19"),
          (3, "PASS_FOR_ADOPTION", "5a3e6820cf23325dd8c68f8c083d53ac805f2b06", "f8ce4ab0d73588437020e6ee49ac260584b22c58",
           "3c34a3a5ff5879d2bcf5e6691bc08eeaf59dbf41"))
STATUS_KEYS = ("schemaVersion", "workItem", "packet", "status", "adoption", "baseMain", "reviewBase", "contracts",
               "adoptedSubject", "adoptionEdit", "independentReviewer", "readmeStatusNote", "recordPaths", "rounds",
               "closedFindings", "carried", "nonClaims", "evidenceClassesScope")
# The evidenceClasses cross-check's scope, in the words the lane monitor agreed (owner-delegated, 2026-10-17, after
# packet review round 1): this sentence appears in the status record, in validate_evidence_classes's docstring and in
# its refusal messages.
EVIDENCE_SCOPE = ("README line 600's cross-check of `evidenceClasses` 'against the model' is met for what the model "
                  "decides — each role's capture class, for every capability set the schema admits (SERVER with and "
                  "without CAP_NET_BIND_SERVICE), against its column, and every exact capture path the class tables "
                  "name, probed through the model's capture checks (deleted where its class requires it, added where "
                  "its class forbids it) — and the remaining cells, which name no exact path, are prose pinned by the "
                  "schema digest.")
# The fixed column-to-class map of the class table's P1 columns and the model's capture_class results.
EVIDENCE_COLUMNS = MappingProxyType({"OBSERVED_TARGET": "OBSERVED", "LABEL_BOUND_TARGET": "LABEL_BOUND",
                                     "OBSERVER_OWN": "DECLARED_T04"})
CAPABILITY = "CAP_NET_BIND_SERVICE"
# The closed captureTargets grammar: items joined by "; ", each a role followed by one of these suffixes (None: every
# capability set the schema admits for the role; True or False: CAP_NET_BIND_SERVICE recorded or not, which the schema
# must admit for the role). Any other text refuses.
TARGET_SUFFIXES = (("", None), (" (its own capture)", None),
                   (" whose recorded capabilities include " + CAPABILITY, True),
                   (" whose recorded capabilities exclude " + CAPABILITY, False))
# The class tables (the P1 capture rows, the lifecycle and the backend rows) and their closed cell grammar. A field is
# either an exact capture path (dot-separated names; a name ending in "[]" stands for each element and is probed on the
# first), probed through the model, or one of the prose fields listed here with why it names no exact path; any other
# field refuses. A cell is one of the table's classes, alone (the field is in the capture) or marked absent with one of
# the listed notes (the field is not in the capture); any other cell refuses.
EVIDENCE_TABLES = ("capture", "lifecycleCapture", "backendCapture")
EVIDENCE_KEYS = frozenset({"classes", "captureTargets", "capture", "lifecycleCapture", "backendCapture", "capturer"})
ABSENCE_NOTES = ("", "; corroborated by process.seccompFilters and cgroupMembers[].seccompFilters", "; no corroboration")
PROSE_FIELDS = MappingProxyType({
    "cgroupMembers[] (process fields)": "a group of every member's process fields",
    "process.cgroup (inode, limits)": "a group of the role cgroup's fields",
    "cgroupMembers (count)": "a count, not a path",
    "files[] (device, inode, uid, gid, nlink, contentDigest, measuredVerity)": "a group of the file measurements' fields",
    "bpfPrograms.*.pinLabel": "a wildcard over the hooks",
    "bpfPrograms.*.program.pinLabel": "a wildcard over the hooks",
    "sealMarker (path, digest, uid, mode)": "a group of the seal marker's fields",
    "process (pid, startTicks, processLabel, cgroupPath)": "a group of the backend process's fields",
    "executable (path, contentDigest, measuredVerity)": "a group of the backend executable's fields"})
# An added field carries the record's declared value: the role's own field (roles[role]), the seal marker's label, or
# the label of the file the capture's first file entry names. A field the record does not declare carries its value in
# another capture of the same positive that holds it.
DECLARED_ROLE_FIELDS = MappingProxyType({
    "process.uid": ("uid",), "process.gid": ("gid",), "process.processLabel": ("processLabel",),
    "process.namespaceInodes": ("namespaceInodes",), "process.seccompMode": ("seccompMode",),
    "process.noNewPrivs": ("noNewPrivs",), "process.capPermitted": ("capabilities",),
    "process.capEffective": ("capabilities",), "process.capBounding": ("capabilities",),
    "process.rlimitCore": ("rlimitCore",), "process.seccompFilterDigest": ("seccompFilterDigest",),
    "process.seccompDefaultAction": ("seccompDefaultAction",), "process.cgroup.path": ("cgroup", "path"),
    "process.cgroup.selinuxLabel": ("cgroup", "selinuxLabel")})
DECLARED_SEAL_LABEL = ("hardeningObserved.sealMarker.selinuxLabel", "sealMarker.selinuxLabel")
# The WORKER-only frozen bracket (owner Q-NP4D-10 (a)): the class table marks cgroupFrozenBefore and cgroupFrozenAfter
# OBSERVED in every column, and the model holds them in the WORKER capture alone, so these exact paths are probed on the
# WORKER captures only.
ROLE_SCOPED_FIELDS = MappingProxyType({"cgroupFrozenBefore": ("WORKER",), "cgroupFrozenAfter": ("WORKER",)})
DECLARED_FILE_LABEL = "files[].entry.selinuxLabel"
ROW_KEYS = ("round", "record", "recordSha256", "verdict", "subject", "subjectTree", "subjectParent", "subjectSha256",
            "severities")
EDIT_KEYS = ("path", "replaced", "with", "count", "rows", "candidateSha256", "adoptedSha256", "lineCount")
CONTRACTS = {"nativeProfileV4": {"schema": NP4_SCHEMA, "vectors": NP4_VECTORS, "model": NP4_MODEL,
                                 "readme": NP4_DIR + "README.md", "sourceIndex": NP4_INDEX},
             "i06BackendProfileV3": {"criteria": I06_DIR + "criteria.json", "vectors": I06_VECTORS, "model": I06_MODEL,
                                     "readme": I06_DIR + "README.md", "sourceIndex": I06_INDEX},
             "edgeRecordV5": {"record": V5_EDGE, "readme": EDGES_DIR + "README-v5.md"}}
# OWNER_DECISIONS.md line 72, verbatim (the lane monitor's owner-delegated adoption).
ADOPTION = {"decidedBy": "the lane monitor, owner-delegated", "date": "2026-10-16",
            "decision": "[lane monitor] **ADOPTED**: native-profile v4 + I06 v3 contract candidate 3. Monitor decision "
                        "(owner-delegated), 2026-10-16, on r3 PASS_FOR_ADOPTION."}
ACTIONS = {"filesEdited": False, "networkAccessed": "none", "personalDataSent": False, "inventoryToolingAttempted": False}
CLOSED_FINDINGS = {
    "N1-1": "CLOSED in round 3 (PARTLY in round 2; its remainder, N2-1, RESOLVED in round 3)",
    "N1-2": "CLOSED in round 2",
    "N1-3": "CLOSED in round 2",
    "N1-4": "CLOSED in round 2",
    "N1-5": "CLOSED in round 2",
    "N1-6": "CLOSED in round 2 (README-v5's open item); the re-check it requires is DISCHARGED at mechanics (see carried)",
    "N2-1": "CLOSED in round 3",
    "N2-2": "CLOSED in round 3",
    "N2-3": "CLOSED in round 3",
}
CARRIED = (
    ("N1-6 (contract review round 1, NOTE): the edge v4 re-check",
     "the packet mechanics"),
    ("The matrix successor: an execute_no_trans closure for the qualk8s sources and a filesystem-class closure for context= mounts (design sections 3.2, 3.6 and 11)",
     "the parallel lane (routed by the lane monitor at adoption) and T04"),
    ("BROKER-CLONE-INTO-CGROUP (design sections 3.5, 4 and 11)",
     "the parallel lane (routed by the lane monitor at adoption), as a W02d/W03 obligation"),
    ("HE-008 duties (design sections 3.3, 3.4, 5 and 11)",
     "HE-008"),
    ("The T04 proof list (design section 11)",
     "T04"),
    ("HE-004D1 and HE-004D2, the consumers (design sections 8 and 10)",
     "HE-004D1 and HE-004D2"),
    ("W03 obligations (design sections 3.3 and 4)",
     "W03"),
    ("Later decisions (design section 11)",
     "W01, W02-PROD and a later I06 successor"),
)
NON_CLAIMS = [
    "Native-profile v1, v2 and v3, I06 v1 and v2, the W02 notes errata, matrix v5, seccomp v4, HS43 and edge records v1 to v4 are byte-identical.",
    "No capture route was exercised on a host: no real kernel, SELinux policy, bpffs, cgroup, boot loader or TPM was observed, and every declared premise stays a named T04 proof.",
    "I06 v3 is fixture-only: production evidence stays refused (W02-PROD), and OBS-RBAC-1's grants are not in it.",
    "The nine files edge record v5 registers are not used before HE-004D1 and HE-004D2.",
]
# Each source index: its schema, its closed keys, and its subject (the contract's files other than the index itself).
INDEX_KEYS = {NP4_INDEX: ("planeon.internal.native-profile-v4-index/v1",
                          ("schemaVersion", "round", "baseMain", "baseTree", "subject", "predecessorInputs",
                           "earlierRounds"), SUBJECT[:4] + (NP4_MODEL,)),
              I06_INDEX: ("planeon.internal.i06-backend-profile-v3-index/v1",
                          ("schemaVersion", "round", "baseMain", "baseTree", "subject", "predecessorInputs",
                           "bindingInputs", "earlierRounds"), SUBJECT[6:10] + (I06_MODEL,))}
EDGE_V4_SHA256 = "e30772ff8826650c46d1a8d384625929975e47f2de5cc9030680b5fdb5e7fc86"
V4_PACKET = "MET-ENFORCE-032"
V4_ROWS = 45
EDGE_KEYS = ("schemaVersion", "graph", "consumer", "provider", "artifact", "ownerDecision", "rules", "notArtifacts",
             "statuses", "artifacts", "supersedes", "ownerDecisions", "notes")
EDGE_ROW_KEYS = ("providerPath", "providerCommit", "sha256", "mode", "consumerPath", "consumerPacket", "relation", "status")
CONSUMER_PREFIX = "host-enforcement/contracts/"
# Edge record v5's nine new rows: (provider path, provider commit, consumer path, consumer packet). The six files this
# packet publishes carry providerCommit null and providerPacket NEW_PACKET; each of the three earlier schema rows' commit
# is its file's last-change commit at the accepted base, with the row's bytes and mode, as the packet's builder proved
# from git (contract review round 1, N1-6); those files are frozen in this era.
NEW_ROWS = (
    ("architecture/native-profile-v4/qualification.schema.json", None, "host-enforcement/contracts/native-profile-v4/qualification.schema.json", "HE-004D1"),
    ("architecture/native-profile-v4/vectors.json", None, "host-enforcement/contracts/native-profile-v4/vectors.json", "HE-004D1"),
    ("architecture/native-profile-v4/README.md", None, "host-enforcement/contracts/native-profile-v4/README.md", "HE-004D1"),
    ("architecture/native-qualification-inputs/qualification.schema.json", "3f52d53c39b2565cb74d527fdcb4215ff0e37b76", "host-enforcement/contracts/native-profile-v1/qualification.schema.json", "HE-004D2"),
    ("architecture/native-profile-v2/qualification.schema.json", "46bcc3e383ec5d9cf0c0d722636d264942b435de", "host-enforcement/contracts/native-profile-v2/qualification.schema.json", "HE-004D2"),
    ("architecture/native-profile-v3/qualification.schema.json", "a29c93c7813ff71eb8179c4e8611032d972e3a36", "host-enforcement/contracts/native-profile-v3/qualification.schema.json", "HE-004D2"),
    ("architecture/i06-backend-profile-v3/vectors.json", None, "host-enforcement/contracts/i06-v3/vectors.json", "HE-004D2"),
    ("architecture/i06-backend-profile-v3/criteria.json", None, "host-enforcement/contracts/i06-v3/criteria.json", "HE-004D2"),
    ("architecture/i06-backend-profile-v3/README.md", None, "host-enforcement/contracts/i06-v3/README.md", "HE-004D2"),
)
# The models' pinned inputs and the vectors' counts (build/replay.py: 504 and 151 checks).
NP4_INPUTS = {"v1Schema": "architecture/native-qualification-inputs/qualification.schema.json",
              "v1Vectors": "architecture/native-qualification-inputs/vectors.json",
              "v2Schema": "architecture/native-profile-v2/qualification.schema.json",
              "v2Vectors": "architecture/native-profile-v2/vectors.json",
              "v3Schema": "architecture/native-profile-v3/qualification.schema.json",
              "v3Vectors": "architecture/native-profile-v3/vectors.json",
              "erratumVectors": "architecture/w02-notes-errata/native-profile-v3-r6-3-vectors.json"}
I06_INPUTS = {"v1Vectors": "architecture/i06-backend-profile/vectors.json",
              "v2Vectors": "architecture/i06-backend-profile-v2/vectors.json",
              "w02aVectors": NP4_VECTORS, "w02aSchema": NP4_SCHEMA,
              "w02aV2Vectors": "architecture/native-profile-v2/vectors.json",
              "inventory": "architecture/i06-backend-profile/writer-inventory.json",
              "closure": "architecture/i06-backend-profile/identity-closure.json",
              "bootstrap": "architecture/i06-backend-profile/upstream-bootstrap-rbac-v1.37.1.json"}
NP4_COUNTS = {"positive": 5, "negative": 444, "accepted": 18, "crossVersion": 15, "migration": 22}
NP4_CHECKS = 504
I06_COUNTS = {"evidenceAccepted": 7, "snapshotAccepted": 5, "evidenceNegative": 91, "snapshotNegative": 38,
              "crossVersion": 7}
I06_CHECKS = 151
# Native-profile v1 to v3, I06 v1 and v2, the W02 notes errata, matrix v5, seccomp v4 and HS43 stay byte-identical: no
# file under their directories changes here, and their models, every source-index pin and edge records v1 to v4 are
# bound by digest below.
FROZEN_PREFIXES = ("architecture/native-qualification-inputs/", "architecture/native-profile-v2/",
                   "architecture/native-profile-v3/", "architecture/i06-backend-profile/",
                   "architecture/i06-backend-profile-v2/", "architecture/w02-notes-errata/",
                   "architecture/selinux-matrix-v3/", "architecture/seccomp-allowlists-v4/",
                   "architecture/host-interface-amendment-hs43/")
FROZEN_PATHS = (
    "architecture/artifact-edges/README-v2.md",
    "architecture/artifact-edges/README-v3.md",
    "architecture/artifact-edges/README-v4.md",
    "architecture/artifact-edges/README.md",
    "architecture/artifact-edges/operator-harness-engineering-v2.json",
    "architecture/artifact-edges/operator-harness-engineering-v3.json",
    "architecture/artifact-edges/operator-harness-engineering-v4.json",
    "architecture/artifact-edges/operator-harness-engineering.json",
    "architecture/host-interface-amendment-hs43/HOST_INTERFACE_SPEC.md",
    "architecture/host-interface-amendment-hs43/README.md",
    "architecture/host-interface-amendment-hs43/amendment.json",
    "architecture/i06-backend-profile-v2/README.md",
    "architecture/i06-backend-profile-v2/REVIEW_BRIEF.md",
    "architecture/i06-backend-profile-v2/criteria.json",
    "architecture/i06-backend-profile-v2/status.json",
    "architecture/i06-backend-profile-v2/vectors.json",
    "architecture/i06-backend-profile/identity-closure.json",
    "architecture/i06-backend-profile/upstream-bootstrap-rbac-v1.37.1.json",
    "architecture/i06-backend-profile/vectors.json",
    "architecture/i06-backend-profile/writer-inventory.json",
    "architecture/native-profile-v2/qualification.schema.json",
    "architecture/native-profile-v2/vectors.json",
    "architecture/native-profile-v3/README.md",
    "architecture/native-profile-v3/qualification.schema.json",
    "architecture/native-profile-v3/review-round6.json",
    "architecture/native-profile-v3/status.json",
    "architecture/native-profile-v3/vectors.json",
    "architecture/native-qualification-inputs/qualification.schema.json",
    "architecture/native-qualification-inputs/vectors.json",
    "architecture/selinux-matrix-v3/README.md",
    "architecture/selinux-matrix-v3/matrix.json",
    "architecture/selinux-matrix-v3/status.json",
    "architecture/w02-notes-errata/effective/i06-backend-profile-v2/README.md",
    "architecture/w02-notes-errata/effective/i06-backend-profile-v2/REVIEW_BRIEF.md",
    "architecture/w02-notes-errata/effective/i06-backend-profile-v2/criteria.json",
    "architecture/w02-notes-errata/effective/native-profile-v3/README.md",
    "architecture/w02-notes-errata/i06-backend-profile-v2-errata.json",
    "architecture/w02-notes-errata/native-profile-v3-errata.json",
    "architecture/w02-notes-errata/native-profile-v3-r6-3-vectors.json",
    "architecture/w02-notes-errata/status.json",
    "scripts/contract_errata.py",
    "scripts/host_interface_amendment_v2.py",
    "scripts/i06_backend_profile.py",
    "scripts/i06_backend_profile_v2.py",
    "scripts/native_qualification_v2.py",
    "scripts/native_qualification_v3.py",
    "scripts/perf032_followup.py",
    "scripts/seccomp_allowlists_v4.py",
    "scripts/selinux_matrix_v3.py",
)
FROZEN_MESSAGE = ("native-profile v1 to v3, I06 v1 and v2, the W02 notes errata, matrix v5, seccomp v4, HS43 and edge "
                  "records v1 to v4 stay byte-identical")
ERA_SHA256 = MappingProxyType({
    "architecture/artifact-edges/README-v2.md": "0cded3e3499b8afe64c82a021a8a499c9b2fce5671ea5ae434b3330c26db3a2b",
    "architecture/artifact-edges/README-v3.md": "d6edd8cc7f8b209c1cf7bd0a16a941e0661ef040f8920cbdbda4c323c0f0f011",
    "architecture/artifact-edges/README-v4.md": "11e6bbefc27d82d359c7f48a873374786a760881693fd7d9ec7e88916ab2558b",
    "architecture/artifact-edges/README-v5.md": "6409a17c2fb0b5ae5df3055c86a3e4cb1e2cb3deacd490c4d547cc1d50a9b6ad",
    "architecture/artifact-edges/README.md": "5d62a665da2c6e75dce900cb4ef52e74aa14e537bdaeededb7568589339daa9f",
    "architecture/artifact-edges/operator-harness-engineering-v2.json": "749e70f174d638468bf45d7316e8f5201c3323f6348a78c7b9a22d3a571ccc32",
    "architecture/artifact-edges/operator-harness-engineering-v3.json": "106ea91aa09c2d377adf3b514a228331d6a805bd1a17e641ecaa23b3c39115f3",
    "architecture/artifact-edges/operator-harness-engineering-v4.json": "e30772ff8826650c46d1a8d384625929975e47f2de5cc9030680b5fdb5e7fc86",
    "architecture/artifact-edges/operator-harness-engineering-v5.json": "89b47ef8f865b31911eb8da2b08a5a3c22b2d92a62599cb6fdfccbfe7f79e3c0",
    "architecture/artifact-edges/operator-harness-engineering.json": "54bdc2d22676720419f51cd1bad5eedc909e6f848ed09cd363e351889af9d1fe",
    "architecture/host-interface-amendment-hs43/HOST_INTERFACE_SPEC.md": "b4f46b3a79c45691d7029a79849a555aca5ca7a6e6c600958147935f806888e9",
    "architecture/host-interface-amendment-hs43/README.md": "539f4bd21253d3db73efdf2ecfaeb4cca2015553e19a1e96007e1f2f89f6b781",
    "architecture/host-interface-amendment-hs43/amendment.json": "6a3719cdc659d7ccfde3598bdec06a31896fa82de810cf73ccc1f7ca3dc7f24c",
    "architecture/i06-backend-profile-v2/README.md": "553880b957586dbfa50eabc4a99d51735eef2a1b0a82641ea51d8e3ea8cf72eb",
    "architecture/i06-backend-profile-v2/REVIEW_BRIEF.md": "f65c1ef1fbe43013c06f962a2ffde8d231a70392603ecc44850481c5ae8ec739",
    "architecture/i06-backend-profile-v2/criteria.json": "026206c57d3025c0f0129b6615e46c83d5a8000ddc3288f000a1fe4570050cda",
    "architecture/i06-backend-profile-v2/status.json": "44217baf7857b86abfa9c8ccadb953e2678592e437c9caf049096c402abb9c20",
    "architecture/i06-backend-profile-v2/vectors.json": "1a5e168f0d8fff233f5072b1440e75a633b38e428f87b2893a96e579122a430e",
    "architecture/i06-backend-profile-v3/README.md": "9ee406f43060f266a7b5dd2679aa8352f0815584c45e33d0ab193ea7f90c0c77",
    "architecture/i06-backend-profile-v3/REVIEW_BRIEF.md": "ca7bbf5e858c940b32058acf8475242fb1ad898afb92584bfac7f79914f93891",
    "architecture/i06-backend-profile-v3/criteria.json": "752533c57b5f93e4c4158a9c17b52eb88d236a3632ab0b66b669e8f8041f57c7",
    "architecture/i06-backend-profile-v3/source-index.json": "7740a01dcd1a9fe41a106532d5ddde37a1cce70e2244c6638d480953532a14c1",
    "architecture/i06-backend-profile-v3/vectors.json": "4752b648abdd82d21ea622a1b26c721143577478c0a2491204e0d584c1d6f081",
    "architecture/i06-backend-profile/identity-closure.json": "0a9b82ffa2d63bf48a8850574cdf3ece02bf1913f33a72cbb96ed30a40f1f3bb",
    "architecture/i06-backend-profile/upstream-bootstrap-rbac-v1.37.1.json": "7529c2a713af2fb90163175924c264d95f4242d7e0c26b1452c77febb13ed50e",
    "architecture/i06-backend-profile/vectors.json": "b9c57d64eab03f307e10b02152426a10ebac2fd27102e27ef5873b5865be4cee",
    "architecture/i06-backend-profile/writer-inventory.json": "8e6b3b7565cfc93a61162b84d740cffb2871eb66ab85e8c4e80ac813f1af3077",
    "architecture/native-profile-v2/qualification.schema.json": "55bd641fd229f21e04ec00813bcfe600890584e982e290a210720ac5cb160ab0",
    "architecture/native-profile-v2/vectors.json": "6d58d1f36b7bce5739b94dd89512d358b96878c70e1de7cf8f399050b881b396",
    "architecture/native-profile-v3/README.md": "93b6f3897f4011ab85832b4319db44e4e1e94566adf61062a6170d1437dfcf50",
    "architecture/native-profile-v3/qualification.schema.json": "ae5cbb6aa39f4edfa2d9919f25e55bad9ab214a99ca927c5afe7e2d943946ac5",
    "architecture/native-profile-v3/review-round6.json": "dce53008c9b21f670935a6fb0c434678dec2538599fc757c46ac5a54a718c929",
    "architecture/native-profile-v3/status.json": "f242944dd7a03eb64fd4f14d811711f7ed4ccf9bdb00bca82ea8abbaa5cb0538",
    "architecture/native-profile-v3/vectors.json": "14af47a69c972039294be8659c31332acd5326bfb0a3a38384a2c6bf9d11fe6d",
    "architecture/native-profile-v4/README.md": "a4205a5388dc83827bb39670bcc9477b030f29829128abf19f7578321c170174",
    "architecture/native-profile-v4/REVIEW_BRIEF.md": "293b9fc1f4affd9be0ff5d38bbc15dae902c22f5761a0ecdbc82d4f9c24fefea",
    "architecture/native-profile-v4/qualification.schema.json": "c3e91c087ebc6a13e8a96a066f80710ac968c8def434d1d1b97415811715ed10",
    "architecture/native-profile-v4/review-round1.json": "6a22a9ae1d422def7d487780da79b9ddb84d9283dabf53a7c5bfc952463e34d9",
    "architecture/native-profile-v4/review-round2.json": "09d4035d8ab726e432a636aab9176a4d8b0a93041345b6cf7ee04a9aab89066b",
    "architecture/native-profile-v4/review-round3.json": "60f72eef0be1fea1a99ed883ff514aab966a2fee9e3bf84c0b39ac227a38e8a3",
    "architecture/native-profile-v4/source-index.json": "6e2c325054ffd5edee3d71c4163dd38bef42b6b255bbdeae5e2c37814ef178fb",
    "architecture/native-profile-v4/status.json": "b998d1151cfe7fada1d4e30829064ceaad5d9c1220f407c6c865bc47c197143c",
    "architecture/native-profile-v4/vectors.json": "dede64ab3202a9e28094f062b5dad868c13ca02423e2380af8666ecf2e7a86e6",
    "architecture/native-qualification-inputs/qualification.schema.json": "bef248bfa82b234124c014f98e40c5791bced3171bb118b7ed1bb7b8daaf95c3",
    "architecture/native-qualification-inputs/vectors.json": "cd1be009b721bb596887335184a33ab8e1f24aed8215477b63e28f058110748f",
    "architecture/selinux-matrix-v3/README.md": "0070f3b5be1d68eb6d1e76e9aceed496b5c1ecce91f8cd3b69c81ffdee1e9167",
    "architecture/selinux-matrix-v3/matrix.json": "01e4f3cfd75250dc6fd74f666cfa53758f83b7a07d7a39a0ca180f5588496b73",
    "architecture/selinux-matrix-v3/status.json": "bf6664e2390b9a6ddeb7acb5e452c0f111bb856b57545f66482f00e34759e30f",
    "architecture/w02-notes-errata/effective/i06-backend-profile-v2/README.md": "562b00852cb84dc44f4118f8449e19819b2b1dae4d683102b5a1b53890abdd9c",
    "architecture/w02-notes-errata/effective/i06-backend-profile-v2/REVIEW_BRIEF.md": "1634d77c9ebd8fea1a1021a22143dadeb702e66f0b81f592f3319c877abd7a99",
    "architecture/w02-notes-errata/effective/i06-backend-profile-v2/criteria.json": "8d4f5d7837b0f68859f222dec8766d57c2b6cc5fe49f95fddd830836569940b4",
    "architecture/w02-notes-errata/effective/native-profile-v3/README.md": "fd12a0ded9b7de557cb75a8bdeb01c2c3fa85c24035b174282d2274dc6000bd0",
    "architecture/w02-notes-errata/i06-backend-profile-v2-errata.json": "ae59ac046609184015790f9e43ed8d99aece31575011f667f6b28ec30dba5b96",
    "architecture/w02-notes-errata/native-profile-v3-errata.json": "e22e968d931d477d6cd70648d52eea52e5bcda6a76e07b17bd658d004e063961",
    "architecture/w02-notes-errata/native-profile-v3-r6-3-vectors.json": "3b9b6b32b8da1b53cf2b597b8ac9e1f230889364424b14b667e7f985b03fb7a7",
    "architecture/w02-notes-errata/status.json": "8f9c8bbb4d6d582a1c597c56dbd94c791c738202331e259895a3c000d58dd03f",
    "scripts/contract_errata.py": "15bef4f7e34302a3a1bc7d21fc5d17a806fe23753d27578075799e94508db449",
    "scripts/host_interface_amendment_v2.py": "7712622031f7116a0c66db862b9e566775bf47fa0a2d3c3a33d3ef5a65768836",
    "scripts/i06_backend_profile.py": "bea3c953573478be5b03ab81b4ebd859da62d1eaa2a1be8f361b9dd39a98555e",
    "scripts/i06_backend_profile_v2.py": "58ceb7a6817aab512a56f9f2a614868ce27660d174be353c5629cc8de335e426",
    "scripts/i06_backend_profile_v3.py": "dfb00e90199d436ae63b79261f2e04870d7861cb0f7a424971657a4d777754de",
    "scripts/native_qualification_v2.py": "c72b6e18044f685c646756a1574bd81cd24f1475d7eda326778d70d1314ef68b",
    "scripts/native_qualification_v3.py": "2ef5c14ad5d8c962cf3703ccd076059685ed8dcc852059e4f863e8d9dc8965ad",
    "scripts/native_qualification_v4.py": "f7c718072d1ffbb9b8bbc310e6141d476ea5f25296f70ff8c1bc9ada3db02387",
    "scripts/perf032_followup.py": "4c764c6451d8273f18c544aac3c3e72b6fe3992b72f34af6c1a1f87da8a1a2cf",
    "scripts/seccomp_allowlists_v4.py": "f88e3eab1a154260b2a33d7a1eadb5a78f29d49579219d3aaf55041ec861e9bf",
    "scripts/selinux_matrix_v3.py": "86ea304f2177cf71b148233259d6ae5686d6aef7f1fa2294f9be421749776fcb",
})
# The schema's label table (README "Entrypoints and labels"): each subject key's executableLabel constant and the
# interpreted roles' interpreterLabel constant, cross-checked here against matrix v5, which v4's model does not pin
# (design section 3.4, D1-13: "schema constants cross-checked by the layer").
MATRIX = "architecture/selinux-matrix-v3/matrix.json"
MATRIX_VERSION = "planeon.internal.selinux-matrix/v5"
LABEL_SUBJECTS = ("SERVER", "OBSERVER", "BROKER", "WORKER", "EFFECT_GATE", "HOST_CONTAINMENT", "POLICY_WRITER",
                  "APISERVER", "DATASTORE", "CONTROLLER_MANAGER", "SCHEDULER", "KUBELET", "CONTAINER_RUNTIME",
                  "SERVICE_PROXY", "NETWORK_POLICY_AGENT")
INTERPRETED_ROLES = ("SERVER", "WORKER")
INTERPRETER_TYPE = "planeon_interpreter_exec_t"
TYPE_CHARACTERS = frozenset("abcdefghijklmnopqrstuvwxyz0123456789_")
NEW_FILES = SUBJECT + (STATUS_PATH,) + tuple(NP4_DIR + "review-round%d.json" % number for number in (1, 2, 3))
# Absolute local path markers, matched case-insensitively; spelled in parts, so this file holds none of them.
LOCAL_PATH_MARKERS = (b"/" + b"users/", b"/" + b"private/", b".local" + b"/state")


def reviewed_bytes(path: str) -> bytes:
    """This packet's reviewed bytes of path; a bridged successor projects newer bytes back first."""
    return successor.historical_bytes(path, regular_bytes(path))


def reviewed_mode(path: str) -> int:
    """The lstat mode of path in this packet's tree; a bridged successor projects a newer mode back first."""
    _path(path)
    return (ROOT / path).lstat().st_mode


def _verified(path: str) -> bytes:
    """reviewed_bytes, checked against its era digest on every read; a path outside the era is refused before it is
    read."""
    expected = ERA_SHA256.get(path) if type(path) is str else None
    require(expected is not None, "NATIVE-PROFILE-V4 reviewed bytes are bound: " + str(path))
    raw = reviewed_bytes(path)
    require(type(raw) is bytes and digest(raw) == expected, "unreviewed NATIVE-PROFILE-V4 source: " + path)
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


def _git_mode(mode: int) -> str | None:
    """The git mode of a regular file from its lstat mode; anything else has none."""
    if not stat.S_ISREG(mode):
        return None
    return "100755" if mode & 0o100 else "100644"


def _texts(values: Any) -> bool:
    return type(values) is list and len(values) > 0 and all(type(text) is str and text.strip() != "" for text in values)


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


def era_modules() -> types.SimpleNamespace:
    """This era's native-profile v4 model, I06 v1's model, and I06 v3 with those two as its imports."""
    np4 = _era_model(NP4_MODEL, "_met_enforce_033_native_qualification_v4")
    i06v1 = _era_model(I06_V1_MODEL, "_met_enforce_033_i06_backend_profile")
    i06 = _era_model(I06_MODEL, "_met_enforce_033_i06_backend_profile_v3",
                     {"i06_backend_profile": i06v1, "native_qualification_v4": np4})
    require(i06.v1 is i06v1 and i06.w02a is np4, "I06 v3 runs this era's I06 v1 and native-profile v4 models")
    return types.SimpleNamespace(np4=np4, i06v1=i06v1, i06=i06)


def validate_adoption() -> dict:
    """Adopted after three independent review rounds, each bound to its published record and its subject; the adopted
    files are candidate 3's bytes except edge record v5's six providerPacket values; the closed findings are the later
    rounds' resolutions."""
    status = _json(STATUS_PATH)
    _bound(lambda: type(status) is dict and tuple(status) == STATUS_KEYS
           and status["schemaVersion"] == "planeon.internal.native-profile-v4-status/v1"
           and status["workItem"] == "NATIVE-PROFILE-V4" and status["packet"] == NEW_PACKET
           and status["status"] == "ADOPTED" and status["adoption"] == ADOPTION
           and status["baseMain"] == BASE_COMMIT and status["reviewBase"] == REVIEW_BASE
           and status["contracts"] == CONTRACTS and status["independentReviewer"] == "SEPARATE_AGENT_NOT_AUTHOR"
           and all(type(status[key]) is str and status[key] != "" for key in ("readmeStatusNote", "recordPaths"))
           and "no README line moved" in status["readmeStatusNote"]
           and status["closedFindings"] == CLOSED_FINDINGS and status["nonClaims"] == NON_CLAIMS
           and status["evidenceClassesScope"] == EVIDENCE_SCOPE
           and type(status["carried"]) is list
           and all(type(row) is dict and tuple(row) == ("item", "to", "action") and type(row["action"]) is str
                   and row["action"].strip() != "" for row in status["carried"])
           and [(row["item"], row["to"]) for row in status["carried"]] == list(CARRIED),
           "adopted NATIVE-PROFILE-V4 status")
    for path in SUBJECT:
        if path != V5_EDGE:
            require(digest(_verified(path)) == CANDIDATE_SHA256[path], "the adopted files are candidate 3: " + path)
    edge = _verified(V5_EDGE)
    _bound(lambda: edge.count(ASSIGNED) == 6 and TBD not in edge and edge.count(b"\n") == CANDIDATE_LINES
           and digest(edge.replace(ASSIGNED, TBD)) == CANDIDATE_SHA256[V5_EDGE],
           "edge record v5 is candidate 3 with exactly six providerPacket values set, on the same lines")
    edit = status["adoptionEdit"]
    _bound(lambda: type(status["adoptedSubject"]) is dict and tuple(status["adoptedSubject"]) == SUBJECT
           and status["adoptedSubject"] == {path: digest(_verified(path)) for path in SUBJECT}
           and type(edit) is dict and tuple(edit) == EDIT_KEYS
           and edit == {"path": V5_EDGE, "replaced": TBD.decode("ascii"), "with": ASSIGNED.decode("ascii"), "count": 6,
                        "rows": [row[0] for row in NEW_ROWS if row[1] is None],
                        "candidateSha256": CANDIDATE_SHA256[V5_EDGE], "adoptedSha256": digest(edge),
                        "lineCount": CANDIDATE_LINES},
           "the status records the adopted files and the one adoption edit")
    rounds = status["rounds"]
    _bound(lambda: type(rounds) is list and len(rounds) == len(ROUNDS)
           and all(type(row) is dict and tuple(row) == ROW_KEYS for row in rounds)
           and [(row["round"], row["verdict"], row["subject"], row["subjectTree"], row["subjectParent"])
                for row in rounds] == list(ROUNDS),
           "three review rounds in order, the last PASS_FOR_ADOPTION")
    records = []
    for number, row in enumerate(rounds, 1):
        record = _json(row["record"]) if row["record"] == NP4_DIR + "review-round%d.json" % number else None
        _bound(lambda: type(record) is dict and digest(_verified(row["record"])) == row["recordSha256"]
               and record["subject"]["commit"] == row["subject"] and record["subject"]["tree"] == row["subjectTree"]
               and record["subject"]["parent"] == row["subjectParent"] and record["verdict"] == row["verdict"]
               and record["reviewer"] == "independent agent" and record["actions"] == ACTIONS
               and row["severities"] == sorted({item["severity"] for item in record["findings"]})
               and type(row["subjectSha256"]) is dict and tuple(row["subjectSha256"]) == SUBJECT
               and all(_sha(value) for value in row["subjectSha256"].values()),
               "review round %d is bound to its record" % number)
        records.append(record)
    _bound(lambda: rounds[-1]["subjectSha256"] == dict(CANDIDATE_SHA256) and rounds[-1]["severities"] == []
           and records[-1]["findings"] == [],
           "the passing round reviewed candidate 3 and left no finding")
    first, second, third = records
    ids1, ids2 = [item["id"] for item in first["findings"]], [item["id"] for item in second["findings"]]
    resolved2 = {item["id"]: item["status"] for item in second["round1Resolutions"]}
    resolved3 = {item["id"]: item["status"] for item in third["round2Resolutions"]}
    _bound(lambda: list(CLOSED_FINDINGS) == ids1 + ids2 and set(resolved2) == set(ids1) and set(resolved3) == set(ids2)
           and all(value == "RESOLVED" for value in resolved3.values())
           and all(CLOSED_FINDINGS[name].startswith("CLOSED in round 2") == (resolved2[name] == "RESOLVED")
                   and resolved2[name] in ("RESOLVED", "PARTLY") for name in ids1)
           and all(CLOSED_FINDINGS[name] == "CLOSED in round 3" for name in ids2),
           "the closed findings are the later rounds' resolutions")
    for path in NEW_FILES:
        raw = _verified(path).lower()
        require(not any(marker in raw for marker in LOCAL_PATH_MARKERS),
                "no absolute local path in a file this packet adds: " + path)
    return status


def validate_source_indexes(status: dict) -> None:
    """Both source indexes are round 3 over the review base; their earlier rounds are the status record's rounds 1 and
    2; and every pin they hold (subject, predecessor inputs, binding inputs) holds over this era's bytes."""
    for path, (version, keys, subject) in INDEX_KEYS.items():
        index = _json(path)
        _bound(lambda: type(index) is dict and tuple(index) == keys and index["schemaVersion"] == version
               and index["round"] == 3 and index["baseMain"] == REVIEW_BASE and index["baseTree"] == REVIEW_BASE_TREE
               and [row["path"] for row in index["subject"]] == list(subject)
               and [row["path"] for row in index.get("bindingInputs", [])] == ([] if path == NP4_INDEX
                                                                               else [NP4_SCHEMA, NP4_VECTORS, NP4_MODEL])
               and [(row["round"], row["subjectCommit"], row["verdict"], row["recordSha256"])
                    for row in index["earlierRounds"]]
               == [(row["round"], row["subject"], row["verdict"], row["recordSha256"]) for row in status["rounds"][:2]],
               "source index %s: round 3 over the review base; rounds 1 and 2 are the published records" % path)
        for key in ("subject", "predecessorInputs", "bindingInputs"):
            for row in index.get(key, []):
                _bound(lambda: type(row) is dict and tuple(row) == ("path", "sha256") and row["path"] in ERA_SHA256
                       and digest(_verified(row["path"])) == row["sha256"],
                       "every source-index pin holds: %s" % (row.get("path") if type(row) is dict else row,))


def validate_edge_record_v5() -> None:
    """Edge record v5 supersedes v4 by its digest and packet and keeps v4's edge, rules, statuses and 45 rows exactly and
    in order; each of its nine new rows registers its provider file's exact bytes and mode before use, under the R10
    contracts directory: the six files this packet publishes with providerCommit null and providerPacket NEW_PACKET,
    the three earlier schemas at their last-change commits."""
    v4, v5 = _json(V4_EDGE), _json(V5_EDGE)
    _bound(lambda: digest(_verified(V4_EDGE)) == EDGE_V4_SHA256 and type(v5) is dict and tuple(v5) == EDGE_KEYS
           and v5["schemaVersion"] == v4["schemaVersion"] == "planeon.internal.artifact-edge-registry/v2"
           and all(v5[key] == v4[key] for key in ("graph", "consumer", "provider", "ownerDecision", "rules",
                                                    "notArtifacts", "statuses"))
           and v5["supersedes"] == {"path": V4_EDGE, "sha256": "sha256:" + EDGE_V4_SHA256, "packet": V4_PACKET}
           and v5["artifact"] == "native-profile-v4-i06-v3-contracts-and-native-profile-v1-v3-schemas"
           and _texts(v5["ownerDecisions"]) and _texts(v5["notes"]),
           "edge record v5 supersedes v4 by its digest and packet and keeps v4's edge, rules and statuses")
    _bound(lambda: len(v4["artifacts"]) == V4_ROWS and v5["artifacts"][:V4_ROWS] == v4["artifacts"]
           and all(list(row) == list(old) for row, old in zip(v5["artifacts"], v4["artifacts"]))
           and len(v5["artifacts"]) == V4_ROWS + len(NEW_ROWS),
           "edge record v5 carries v4's 45 rows exactly and in order")
    for index, (row, (path, commit, consumer, packet)) in enumerate(zip(v5["artifacts"][V4_ROWS:], NEW_ROWS), V4_ROWS + 1):
        published = commit is None
        _bound(lambda: tuple(row) == EDGE_ROW_KEYS + (("providerPacket",) if published else ())
               and row["providerPath"] == path and row["providerCommit"] == commit and published == (path in SUBJECT)
               and (not published or row["providerPacket"] == NEW_PACKET)
               and row["consumerPath"] == consumer and consumer.startswith(CONSUMER_PREFIX)
               and row["consumerPacket"] == packet and row["relation"] == "BYTE_IDENTICAL"
               and row["status"] == "REGISTERED_BEFORE_USE"
               and row["sha256"] == digest(_verified(path)) and row["mode"] == _git_mode(reviewed_mode(path)) == "100644",
               "edge record v5 row %d registers its provider's exact bytes and mode before use: %s" % (index, path))
    providers = [row["providerPath"] for row in v5["artifacts"]]
    consumers = [row["consumerPath"] for row in v5["artifacts"][V4_ROWS:]]
    _bound(lambda: len(set(providers)) == len(providers) and len(set(consumers)) == len(consumers)
           and not set(consumers) & {row["consumerPath"] for row in v4["artifacts"]},
           "each provider path, and each new consumer path, is registered once")


def _label_type(label: Any) -> str | None:
    """The type of a canonical file context system_u:object_r:<type>:s0; anything else has none."""
    parts = label.split(":") if type(label) is str else []
    canonical_form = (len(parts) == 4 and parts[0] == "system_u" and parts[1] == "object_r" and parts[3] == "s0"
                      and len(parts[2]) > 2 and parts[2].endswith("_t") and set(parts[2]) <= TYPE_CHARACTERS)
    return parts[2] if canonical_form else None


def schema_label_table(schema: dict) -> tuple[dict, dict]:
    """The schema's executableLabel constant per subject key (roles, lifecycle subjects, backend components) and the
    interpreterLabel constant per role, read from the constants where the schema fixes them."""
    defs = schema["$defs"]
    labels = {key: spec["properties"]["executableLabel"]["const"]
              for group in ("roles", "lifecycleSubjects") for key, spec in defs[group]["properties"].items()}
    for key, spec in defs["backendComponents"]["properties"].items():
        consts = [part["properties"]["executableLabel"]["const"] for part in spec["allOf"]
                  if "executableLabel" in part.get("properties", {})]
        labels[key] = consts[0] if len(consts) == 1 else None
    interpreters = {key: spec["properties"]["interpreterLabel"]["const"] for key, spec in defs["roles"]["properties"].items()}
    return labels, interpreters


def validate_label_constants() -> None:
    """The schema's label constants against matrix v5, read from this era's bytes (design section 3.4, D1-13): each of
    the 15 subject keys has exactly one matrix v5 domain; its label is canonical and names a declared type, with that
    type's own label, whose ENTRYPOINT grants name exactly that domain and no other; the interpreted roles' label names
    planeon_interpreter_exec_t, declared, with EXECUTE for their domains and no ENTRYPOINT grant."""
    schema, matrix = _json(NP4_SCHEMA), _json(MATRIX)
    table, declared = {}, {}
    _bound(lambda: table.update(zip(("labels", "interpreters"), schema_label_table(schema))) is None
           and tuple(table["labels"]) == LABEL_SUBJECTS
           and tuple(key for key, label in table["interpreters"].items() if label is not None) == INTERPRETED_ROLES
           and matrix["schemaVersion"] == MATRIX_VERSION,
           "the schema's label table names the 15 subjects and the interpreted roles")
    _bound(lambda: all(type(row) is dict and type(row["name"]) is str and type(row["access"]) is dict
                       for row in matrix["types"])
           and len({row["name"] for row in matrix["types"]}) == len(matrix["types"])
           and declared.update({row["name"]: row for row in matrix["types"]}) is None,
           "matrix v5 declares each type once")

    def granted(name: str, kind: str) -> set:
        return {row["domain"] for row in declared[name]["access"].get(kind, [])}

    for key in LABEL_SUBJECTS:
        label = table["labels"][key]
        _bound(lambda: len([row for row in matrix["domains"] if row["subject"] == key]) == 1
               and _label_type(label) in declared and declared[_label_type(label)]["label"] == label
               and granted(_label_type(label), "ENTRYPOINT")
               == {next(row["name"] for row in matrix["domains"] if row["subject"] == key)},
               "the %s label is canonical and enters exactly its matrix v5 domain: %s" % (key, label))
    interpreter = {label for label in table["interpreters"].values() if label is not None}
    _bound(lambda: len(interpreter) == 1 and _label_type(min(interpreter)) == INTERPRETER_TYPE
           and INTERPRETER_TYPE in declared and declared[INTERPRETER_TYPE]["label"] == min(interpreter)
           and granted(INTERPRETER_TYPE, "ENTRYPOINT") == set()
           and {row["name"] for row in matrix["domains"] if row["subject"] in INTERPRETED_ROLES}
           <= granted(INTERPRETER_TYPE, "EXECUTE"),
           "the interpreter label is canonical, declared, executable by the interpreted roles' domains, and enters none")


CAPTURE_ROLES = LABEL_SUBJECTS[:5]


def _evidence_message(detail: str) -> str:
    return "evidenceClasses against the model: %s. %s" % (detail, EVIDENCE_SCOPE)


def schema_admitted(schema: dict) -> dict:
    """Per capture role, the CAP_NET_BIND_SERVICE values (recorded or not) of the capability sets the schema admits,
    read from each role's capabilities constant or enum."""
    admitted = {}
    for role in CAPTURE_ROLES:
        rule = schema["$defs"]["roles"]["properties"][role]["properties"]["capabilities"]
        sets = rule["enum"] if set(rule) == {"enum"} else [rule["const"]] if set(rule) == {"const"} else None
        admitted[role] = sorted({CAPABILITY in capabilities for capabilities in sets})
    return admitted


def _target_pairs(text: Any, admitted: dict) -> list:
    """The (role, CAP_NET_BIND_SERVICE recorded) pairs one captureTargets text lists, read with the closed grammar: a
    role without a condition stands for every capability set the schema admits for it, and a condition naming a set the
    schema forbids refuses."""
    require(type(text) is str, "captureTargets text")
    pairs = []
    for item in text.split("; "):
        read = [(role, holds) for role in CAPTURE_ROLES for suffix, holds in TARGET_SUFFIXES if item == role + suffix]
        require(len(read) == 1, "captureTargets text outside the grammar")
        role, holds = read[0]
        require(holds is None or holds in admitted[role], "a condition naming a capability set the schema forbids")
        pairs += [(role, value) for value in (admitted[role] if holds is None else (holds,))]
    return pairs


def _capture_path(field: Any) -> tuple | None:
    """The capture path a field names exactly: dot-separated names, a name ending in [] standing for each element
    (probed on the first); None for any other text."""
    if type(field) is not str:
        return None
    path: list = []
    for name in field.split("."):
        each = name.endswith("[]")
        name = name[:-2] if each else name
        if not (name and name.isascii() and name.isalpha()):
            return None
        path += [name, 0] if each else [name]
    return tuple(path)


def _cell_present(cell: Any, classes: Any) -> bool:
    """A class-table cell read with the closed grammar: True for a class alone (the field is in the capture), False for
    a class marked absent with a listed note (it is not); any other cell refuses."""
    require(type(cell) is str and type(classes) is list, "class table cell")
    if cell in classes:
        return True
    marked = [name for name in classes for note in ABSENCE_NOTES if cell == name + " (absent" + note + ")"]
    require(len(marked) == 1, "class table cell outside the grammar")
    return False


def evidence_cells(table: dict) -> tuple[list, list]:
    """Every row field of the three class tables, read with the closed grammar: the exact capture paths, each with
    (table, row number, field, path, presence per P1 column or None), and the prose fields (table, row number, field).
    A field that is neither an exact path nor a listed prose field refuses."""
    exact, prose = [], []
    for name in EVIDENCE_TABLES:
        for number, row in enumerate(table[name], 1):
            cells = ({column: row[column] for column in EVIDENCE_COLUMNS} if name == "capture" else {None: row["class"]})
            presence = {column: _cell_present(cell, table["classes"]) for column, cell in cells.items()}
            require(type(row["fields"]) is list and len(row["fields"]) > 0, "class table row")
            for field in row["fields"]:
                path = _capture_path(field)
                require(field in PROSE_FIELDS or path is not None,
                        "a class table field neither an exact capture path nor listed prose")
                if field in PROSE_FIELDS:
                    prose.append((name, number, field))
                else:
                    exact.append((name, number, field, path, presence))
    return exact, prose


def _has(value: Any, path: tuple) -> bool:
    for key in path:
        if not ((type(value) is dict and key in value) or (type(value) is list and type(key) is int and key < len(value))):
            return False
        value = value[key]
    return True


def _at(value: Any, path: tuple) -> Any:
    for key in path:
        value = value[key]
    return value


def _declared(record: dict, role: str | None, field: str, capture: dict, others: list) -> Any:
    """The value an added field carries: the record's declared value, or, where the record declares none, the value in
    another capture of the same positive that holds the field."""
    if field in DECLARED_ROLE_FIELDS:
        return _at(record["roles"][role], DECLARED_ROLE_FIELDS[field])
    if field in DECLARED_SEAL_LABEL:
        return record["hardening"]["sealMarker"]["selinuxLabel"]
    if field == DECLARED_FILE_LABEL:
        path = capture["files"][0]["entry"]["path"]
        rows = [row for row in record["files"] if row["path"] == path]
        require(len(rows) == 1, "the record declares the file")
        return rows[0]["selinuxLabel"]
    path = _capture_path(field)
    holders = [other for other in others if path is not None and _has(other, path)]
    require(len(holders) > 0, "another capture holds the field")
    return _at(holders[0], path)


def _probe(capture: dict, path: tuple, value: Any, delete: bool) -> dict:
    """The capture with one field deleted, or added with the given value; only the containers on the path are copied,
    so the positive is never changed."""
    probe = dict(capture)
    node = probe
    for key in path[:-1]:
        child = node[key]
        child = list(child) if type(child) is list else dict(child)
        node[key] = child
        node = child
    if delete:
        del node[path[-1]]
    else:
        node[path[-1]] = copy.deepcopy(value)
    return probe


def validate_evidence_classes(m: types.SimpleNamespace) -> None:
    """The schema's evidenceClasses constant against this era's native-profile v4 model, through the model's own
    functions (design section 3.7; README "Open items").
    README line 600's cross-check of `evidenceClasses` 'against the model' is met for what the model decides — each role's capture class, for every capability set the schema admits (SERVER with and without CAP_NET_BIND_SERVICE), against its column, and every exact capture path the class tables name, probed through the model's capture checks (deleted where its class requires it, added where its class forbids it) — and the remaining cells, which name no exact path, are prose pinned by the schema digest.
    (a) capture_class, called for the 5 roles on every positive record with each capability set the schema admits for
    the role (CAP_NET_BIND_SERVICE recorded or not, as the role's capabilities constant or enum allows), gives the class
    EVIDENCE_COLUMNS fixes for the column whose captureTargets text, read with the closed grammar, lists that role and
    capability set: a role listed without a condition stands for every set the schema admits for it, a condition naming
    a set the schema forbids refuses, and the columns list every admitted role and set exactly once. (b) Every row field
    of the three class tables is an exact capture path or a listed prose field, and every cell is a class alone or marked
    absent (the closed grammar). On every positive, whose captures the model accepts, each exact path is probed through
    the model's check for its capture (check_capture for the P1 rows, by the capture's column; check_lifecycle_capture
    and check_backend_capture for the lifecycle and backend rows): deleted where its cell requires the field, which must
    be refused, and added where its cell forbids it, with the record's declared value (or, where the record declares
    none, another capture's), which must be refused; the WORKER-only frozen bracket's two paths are probed on the WORKER
    captures only (ROLE_SCOPED_FIELDS).
    For the OUT_OF_SCOPE_HOST, CONSISTENCY_ONLY and ENTRY_BOUND cells the probes test presence only, not the equality or consistency those classes state."""
    schema, positives = _json(NP4_SCHEMA), _json(NP4_VECTORS)["positive"]
    table, pairs, admitted = {}, {}, {}
    _bound(lambda: table.update(schema["$defs"]["evidenceClasses"]["const"]) is None and set(table) == EVIDENCE_KEYS
           and all(type(table[name]) is list and all(type(row) is dict for row in table[name]) for name in EVIDENCE_TABLES)
           and admitted.update(schema_admitted(schema)) is None
           and tuple(m.np4.ROLES) == CAPTURE_ROLES and tuple(table["captureTargets"]) == tuple(EVIDENCE_COLUMNS)
           and set(EVIDENCE_COLUMNS.values()) <= set(table["classes"]),
           _evidence_message("the capture columns are the fixed column-to-class map"))
    for column in EVIDENCE_COLUMNS:
        _bound(lambda: pairs.update({column: _target_pairs(table["captureTargets"][column], admitted)}) is None,
               _evidence_message("captureTargets text outside the closed grammar or naming a capability set the schema "
                                 "forbids: " + column))
    named = [pair for rows in pairs.values() for pair in rows]
    _bound(lambda: len(named) == len(set(named))
           and set(named) == {(role, holds) for role in CAPTURE_ROLES for holds in admitted[role]},
           _evidence_message("the capture columns list every role and admitted capability set exactly once"))

    def decided(p: dict, role: str, holds: bool) -> Any:
        row = p["record"]["roles"][role]
        capabilities = [name for name in row["capabilities"] if name != CAPABILITY] + ([CAPABILITY] if holds else [])
        record = dict(p["record"], roles=dict(p["record"]["roles"], **{role: dict(row, capabilities=capabilities)}))
        return m.np4.capture_class(record, role)

    for column, rows in pairs.items():
        for role, holds in rows:
            _bound(lambda: len(positives) > 0
                   and all(decided(p, role, holds) == EVIDENCE_COLUMNS[column] for p in positives),
                   _evidence_message("capture_class decides the role's column: %s %s %s, listed in %s"
                                     % (role, "with" if holds else "without", CAPABILITY, column)))
    for name in EVIDENCE_TABLES:
        for number, row in enumerate(table[name], 1):
            _bound(lambda: evidence_cells(dict(table, **{other: [] for other in EVIDENCE_TABLES if other != name},
                                               **{name: [row]})) is not None,
                   _evidence_message("a class table row outside the closed grammar: %s row %d" % (name, number)))
    exact, prose = evidence_cells(table)
    _bound(lambda: sorted(field for _name, _number, field in prose) == sorted(PROSE_FIELDS),
           _evidence_message("the prose fields are exactly the listed ones"))
    _bound(lambda: set(ROLE_SCOPED_FIELDS) <= {field for name, _number, field, _path, _presence in exact if name == "capture"}
           and all(set(roles) <= set(CAPTURE_ROLES) for roles in ROLE_SCOPED_FIELDS.values()),
           _evidence_message("the role-scoped fields are exact P1 paths of known roles"))
    scoped_probes = {field: 0 for field in ROLE_SCOPED_FIELDS}
    columns = {name: column for column, name in EVIDENCE_COLUMNS.items()}

    def refuses(check: Any, *args: Any) -> bool:
        return m.np4.explain(check, *args) is not None

    for p in positives:
        record = p["record"]
        for capture in p["captures"]:
            role, column = capture["role"], []
            _bound(lambda: column.append(columns[m.np4.capture_class(record, role)]) is None
                   and m.np4.explain(m.np4.check_capture, record, capture, role, schema) is None,
                   _evidence_message("check_capture accepts the positive capture: " + role))
            for name, _number, field, path, presence in exact:
                if name != "capture" or role not in ROLE_SCOPED_FIELDS.get(field, CAPTURE_ROLES):
                    continue
                if field in scoped_probes:
                    scoped_probes[field] += 1
                required = presence[column[0]]
                _bound(lambda: refuses(m.np4.check_capture, record, _probe(
                           capture, path, None if required else _declared(record, role, field, capture, p["captures"]),
                           required), role, schema),
                       _evidence_message("check_capture refuses %s %s for %s" % (field, "deleted" if required else "added",
                                                                                role)))
        lifecycle = p["lifecycle"]
        _bound(lambda: all(count > 0 for count in scoped_probes.values()),
               _evidence_message("every role-scoped field is probed on its roles' captures"))
        _bound(lambda: m.np4.explain(m.np4.check_lifecycle_capture, record, lifecycle, schema) is None,
               _evidence_message("check_lifecycle_capture accepts the positive lifecycle capture"))
        for name, _number, field, path, presence in exact:
            if name != "lifecycleCapture":
                continue
            required = presence[None]
            _bound(lambda: refuses(m.np4.check_lifecycle_capture, record, _probe(
                       lifecycle, path, None if required else _declared(record, None, field, lifecycle, []), required),
                       schema),
                   _evidence_message("check_lifecycle_capture refuses %s %s" % (field, "deleted" if required else "added")))
        for backend in p["backendCaptures"]:
            component = backend["component"]
            _bound(lambda: m.np4.explain(m.np4.check_backend_capture, record, backend, schema) is None,
                   _evidence_message("check_backend_capture accepts the positive backend capture: " + str(component)))
            for name, _number, field, path, presence in exact:
                if name != "backendCapture":
                    continue
                required = presence[None]
                _bound(lambda: refuses(m.np4.check_backend_capture, record, _probe(
                           backend, path, None if required else _declared(record, None, field, backend, []), required),
                           schema),
                       _evidence_message("check_backend_capture refuses %s %s for %s"
                                         % (field, "deleted" if required else "added", component)))


def replay_models(m: types.SimpleNamespace) -> None:
    """Both models replay every vector over their pinned inputs, read through this era's verified bytes."""
    np4_vectors, i06_vectors = _json(NP4_VECTORS), _json(I06_VECTORS)
    _bound(lambda: dict(m.np4.V4_INPUTS) == NP4_INPUTS and m.np4.SCHEMA_PATH == NP4_SCHEMA
           and dict(m.i06.V3_INPUTS) == I06_INPUTS
           and {key: len(np4_vectors[key]) for key in NP4_COUNTS} == NP4_COUNTS
           and {key: len(i06_vectors[key]) for key in I06_COUNTS} == I06_COUNTS,
           "the models' pinned inputs and the vectors' counts")
    np4_files = {path: _verified(path) for path in list(NP4_INPUTS.values()) + [NP4_SCHEMA]}
    _bound(lambda: m.np4.check_vectors(np4_vectors, np4_files) == NP4_CHECKS,
           "native-profile v4 replays every vector over its pinned inputs")
    i06_files = {path: _verified(path) for path in I06_INPUTS.values()}
    _bound(lambda: m.i06.check_vectors(i06_vectors, i06_files) == I06_CHECKS,
           "I06 v3 replays every vector over its pinned inputs")


def validate_native_profile_v4() -> None:
    """Every reviewed byte and the adoption record first; then the source indexes, edge record v5, the label constants
    against matrix v5, both models from this era's bytes, the evidenceClasses constant against the model where it
    decides, and the replays."""
    for path in FROZEN_PATHS:
        require(path not in _PROJECTION_RULES, FROZEN_MESSAGE)
    # Neither a file this packet changes nor one it adds may sit under a predecessor's directory (packet review P1-3).
    added = authority()["newFiles"]
    require(not any(path.startswith(FROZEN_PREFIXES) for path in list(_PROJECTION_RULES) + list(added)), FROZEN_MESSAGE)
    for path in ERA_SHA256:
        _verified(path)
    status = validate_adoption()
    validate_source_indexes(status)
    validate_edge_record_v5()
    validate_label_constants()
    models = era_modules()
    validate_evidence_classes(models)
    replay_models(models)
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
            == record["validatorNormalizedSha256"], "native profile v4 validator drift")
    paths = sorted((ROOT / "task-packets").glob("*.yaml"))
    old = set(record["baselinePackets"])
    require(len(paths) == 272
            and {path.stem for path in paths} == old | {NEW_PACKET, successor.NEW_PACKET, successor.successor.NEW_PACKET, successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.NEW_PACKET},
            "closed 272-packet catalog retaining the 246-packet checkpoint")
    packets = {}
    for path in paths:
        if path.stem in (successor.NEW_PACKET, successor.successor.NEW_PACKET, successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.NEW_PACKET):
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
            "closed source-only native-profile-v4 packet and inherited commands")
    require(len(packet["allowedPaths"]) == len(set(packet["allowedPaths"]))
            and set(packet["allowedPaths"]) == set(record["changedFiles"])
            | set(record["newFiles"]) | {AUTHORITY_PATH, VALIDATOR_PATH,
                                         "task-packets/" + NEW_PACKET + ".yaml"},
            "unreviewed or omitted native-profile-v4 packet path")
    for path, rule in record["changedFiles"].items():
        current = successor.historical_bytes(path, regular_bytes(path))
        require(digest(current) == rule["afterSha256"]
                and digest(historical_bytes(path, current)) == rule["beforeSha256"],
                "unreviewed current source: " + path)
    for path, expected in record["newFiles"].items():
        require(digest(successor.historical_bytes(path, regular_bytes(path))) == expected,
                "new source drift: " + path)
    validate_native_profile_v4()


if __name__ == "__main__":
    validate()
    print("Native-profile v4 and I06 v3 valid: 272 current specifications; 246-packet checkpoint and exact 245-packet predecessor; contract reviewed.")
