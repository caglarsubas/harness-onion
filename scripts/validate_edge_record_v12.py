#!/usr/bin/env python3
"""Validate MET-ENFORCE-043 (EDGE-V12): operator edge record v12 with the two broker-handoff-v1 rows, and host-interface amendment HE5 with its v4 model, its CONTRACT rounds and its D5a oracle (V1-V5: the fourteen packet files, each equal to its adopted digest; the v4 model, run from its verified bytes, accepting the HE5 contract; the oracle identity binding the oracle's bytes and the status record binding the identity; the registry's MET-ENFORCE-043 packet and contract riders as the one change from the base; and edge record v12 carrying v11's 79 rows and binding the two provider files), and the exact 271-to-270 projection."""
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
    import validate_release_profile as successor
except ImportError:
    from scripts.safe_yaml import safe_load
    from scripts import validate_release_profile as successor


ROOT = Path(__file__).resolve().parents[1]
AUTHORITY_PATH = "architecture/edge-record-v12-authority.json"
AUTHORITY_SHA256 = "c1cceb09717af96a7ad66232bb906d9844810a164e0cdca59c54f5c4308b7cce"
VALIDATOR_PATH = "scripts/validate_edge_record_v12.py"
BASE_COMMIT = "3238383e48ea36f563bca10c1cc76b5a3bf3871a"
NEW_PACKET = "MET-ENFORCE-043"
PREVIOUS_PACKET = "MET-PERF-043"
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
            require(key not in result, "duplicate edge-record-v12 authority member")
            result[key] = value
        return result

    def no_constant(_value: str) -> Any:
        raise ValueError("nonfinite edge-record-v12 authority number")

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
        require(digest(raw) == AUTHORITY_SHA256, "edge record v12 history authority digest")
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
    }, "closed edge record v12 history authority")
    require(value["schemaVersion"] == "harness.planeon.ai/edge-record-v12-authority/v1"
            and value["authorityPacket"] == NEW_PACKET
            and value["acceptedBase"] == BASE_COMMIT
            and type(value["baselinePackets"]) is dict
            and len(value["baselinePackets"]) == 270
            and NEW_PACKET not in value["baselinePackets"]
            and type(value["changedFiles"]) is dict
            and type(value["newFiles"]) is dict
            and _sha(value["packetSha256"])
            and _sha(value["validatorNormalizedSha256"]),
            "accepted 270-packet base")
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
    # An exact 270-era byte string is already older than the successor layer.
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


# MET-ENFORCE-043 (roadmap EDGE-V12; the lane monitor's owner-delegated rulings MON-EV12-PLAN (Q-EV12-1 (a)),
# MON-EV12-Q2, MON-EV12-MERGE, MON-EV12-CR1, MON-EV12-CR2, MON-EV12-ADOPT, MON-EV12-ORACLE and MON-EV12-MECH-GO, with the
# owner's Q-HE5-12 (b), "Drop post-exec reads", MON-HE005-Q12-OWNER; moved to slot 271 by Q-DIAG-CAP and
# MON-SLOT-270-PERF) adopts candidate c2: operator edge
# record v12 (architecture/artifact-edges/operator-harness-engineering-v12.json and README-v12.md), which carries edge
# record v11's 79 rows and registers the two broker-handoff-v1 inputs, BYTE_IDENTICAL and REGISTERED_BEFORE_USE, for
# R10's HE-005B; and host-interface amendment HE5 (architecture/host-interface-amendment-he5/: its record, effective
# specification, README, status record, source index, CONTRACT rounds 1 and 2 with their identities, and the D5a
# oracle's identity), with its v4 model scripts/host_interface_amendment_v4.py and the D5a oracle
# tests/test_met_enforce_043_oracle.py. Its review series are registered by this packet's own riders in
# architecture/review-record/briefs.json (MET-ENFORCE-043/packet and MET-ENFORCE-043/contract, which the evolution surface
# record at this base classes as gate material, so the owner approves the PR). Repository bytes are read only through
# reviewed_bytes, so a later bridged successor projects its own edits away first; a path outside this era is refused
# before it is read, every era file is bound by digest on every read, and no directory is listed. Each refusal is a pure
# check over the values read, so every one has a failing case on plain data. Checked here: V1, the packet's files
# (exactly the fourteen, each equal to the sha256 of its adopted bytes, pinned below); V2, the model accepts the contract
# (the v4 model, executed from its V1-verified bytes in the era-loader form, runs its check(read) over this era's
# reviewed bytes without a refusal); V3, the oracle binding (the identity names the oracle test, its file.sha256 equals
# the oracle test's bytes and its ruling is KEEP, and the status record's oracle.identitySha256 equals the identity's
# bytes); V4, the registry (it differs from the base by exactly the two riders, each pointing at its generic brief with
# the sha256 of that brief's bytes); and V5, edge record v12's open items (edge record v11 is the pinned one with its 79
# rows, v12's first 79 rows are v11's in order, and the two new rows' sha256 and byte count equal the provider files'
# bytes). No chain validator or chain test is pinned here, and no catalog file is named. Last, this layer's own inverse
# hunks are the canonical byte-minimal ones, recomputed from its era's bytes (MET-PERF-040's carried rule).
EDGE_V12 = "architecture/artifact-edges/operator-harness-engineering-v12.json"
EDGE_README = "architecture/artifact-edges/README-v12.md"
EDGE_V11 = "architecture/artifact-edges/operator-harness-engineering-v11.json"
RECORD_PATH = "architecture/host-interface-amendment-he5/amendment.json"
EFFECTIVE_PATH = "architecture/host-interface-amendment-he5/HOST_INTERFACE_SPEC.md"
STATUS_PATH = "architecture/host-interface-amendment-he5/status.json"
ORACLE_IDENTITY = "architecture/host-interface-amendment-he5/oracle-identity.json"
ORACLE_SCHEMA = "planeon.oracle-identity/v1"
MODEL_PATH = "scripts/host_interface_amendment_v4.py"
MODEL_NAME = "_met_enforce_043_host_interface_amendment_v4"
ORACLE_TEST = "tests/test_met_enforce_043_oracle.py"
REGISTRY_PATH = "architecture/review-record/briefs.json"
PACKET_BRIEF = "architecture/review-briefs/REVIEW_BRIEF_PACKET.md"
CONTRACT_BRIEF = "architecture/review-briefs/REVIEW_BRIEF_CONTRACT.md"
# V1: the packet's files, named by path; each is pinned below by the sha256 of its adopted bytes.
PACKET_FILES = (
    "architecture/artifact-edges/operator-harness-engineering-v12.json",
    "architecture/artifact-edges/README-v12.md",
    "architecture/host-interface-amendment-he5/amendment.json",
    "architecture/host-interface-amendment-he5/HOST_INTERFACE_SPEC.md",
    "architecture/host-interface-amendment-he5/README.md",
    "architecture/host-interface-amendment-he5/status.json",
    "architecture/host-interface-amendment-he5/source-index.json",
    "architecture/host-interface-amendment-he5/review-round1.json",
    "architecture/host-interface-amendment-he5/review-identity-round1.json",
    "architecture/host-interface-amendment-he5/review-round2.json",
    "architecture/host-interface-amendment-he5/review-identity-round2.json",
    "architecture/host-interface-amendment-he5/oracle-identity.json",
    "scripts/host_interface_amendment_v4.py",
    "tests/test_met_enforce_043_oracle.py",
)
# V2: the files the model reads besides the packet's: HS53's record and effective text, and the two texts HE5
# supersedes, each of which stays unchanged.
MODEL_INPUTS = (
    "architecture/host-interface-amendment-hs53/amendment.json",
    "architecture/host-interface-amendment-hs53/HOST_INTERFACE_SPEC.md",
    "docs/alpha-2/BROKER_HANDOFF_READINESS.md",
    "architecture/native-profile-v4/README.md",
)
# V4: the registry at the base (the digest of its canonical JSON) and this packet's two riders (kind, series, path,
# version), in the order they are appended; each rider's sha256 is its generic brief's.
REGISTRY_BASE_SHA256 = "571595b8a54e03987a0134d791f5a0a588c86a76ca356f80ce581b79fcbfd166"
RIDERS = (("PACKET", NEW_PACKET + "/packet", PACKET_BRIEF, 1), ("CONTRACT", NEW_PACKET + "/contract", CONTRACT_BRIEF, 1))
# V5: edge record v11's digest and row count, and the two provider files with their byte counts (README-v12's table).
EDGE_V11_SHA256 = "9188980f0ce211e2939d431d900a7aff77262de3a973009666ed13f3ef3cbd77"
V11_ROWS = 79
PROVIDER_FILES = (
    ("architecture/broker-handoff-inputs/channel.schema.json", 42572),
    ("architecture/broker-handoff-inputs/vectors.json", 47254),
)
# Every file this era's check reads, with its digest: the packet's files, the model's other inputs, the registry, the
# two generic briefs, edge record v11 and the two provider files.
ERA_SHA256 = MappingProxyType({
    "architecture/artifact-edges/README-v12.md": "74449b42e3919a775304d868e8a348d38054d350e0199d463a102c42fc612256",
    "architecture/artifact-edges/operator-harness-engineering-v11.json": "9188980f0ce211e2939d431d900a7aff77262de3a973009666ed13f3ef3cbd77",
    "architecture/artifact-edges/operator-harness-engineering-v12.json": "3587488b040f1c23f95f847dd3f1e15b97fa6ca705b6dca429d1cc6d64f3a5c7",
    "architecture/broker-handoff-inputs/channel.schema.json": "e7e9558fb50b7ba804222065734d1d4fb4694327bb2427a34ef8dffc945d56f9",
    "architecture/broker-handoff-inputs/vectors.json": "80d8da953c41ef544ecf0cd4a0f62b98316b018bfbdc39c550c320f68ab603c4",
    "architecture/host-interface-amendment-he5/HOST_INTERFACE_SPEC.md": "f6e81cecbb775782413aaa4864979c50ce001455c6e512080005a5074ffc9b57",
    "architecture/host-interface-amendment-he5/README.md": "2f4bafbab4cfd932e91420623714a4a489ca550ab23c3a4ae05ad46966a1b089",
    "architecture/host-interface-amendment-he5/amendment.json": "82ca60cd553c177917f4748ff3a6305bc5dd249da1522d4b3e38c1f5b1c52e84",
    "architecture/host-interface-amendment-he5/oracle-identity.json": "2b7970bd3136f4a8f054245285fa7db02b855a52cec9429fb2542bb9e04a7b6b",
    "architecture/host-interface-amendment-he5/review-identity-round1.json": "32e30a0822910f22796344940e71b527cab1752c2c46e183cf40d84181182938",
    "architecture/host-interface-amendment-he5/review-identity-round2.json": "d5054d51188a228428db141aa5fe5407e8520915f5e60be4dad03b64da45acd0",
    "architecture/host-interface-amendment-he5/review-round1.json": "f705d6f33a6625ac11ef4cf1454598e281cc48936b2c4cc55fe23b850a46ba9c",
    "architecture/host-interface-amendment-he5/review-round2.json": "9671326111a54f3eded353be0ecafc6f1d686240d03ba60ece5d9fcc70b311e0",
    "architecture/host-interface-amendment-he5/source-index.json": "63d06372c483be266e1bb37b0958b847dd5d1ce2c0ffce0d372964663c2f703e",
    "architecture/host-interface-amendment-he5/status.json": "fdb21cdc638a5f4a60d661805eaa95f528dc27fd24e7f214a7f585a35ac42697",
    "architecture/host-interface-amendment-hs53/HOST_INTERFACE_SPEC.md": "fa7f36fb7d291ab5ffccfc51f9bae7b99ad1a2ef466fc0793dbe6e4182af1e75",
    "architecture/host-interface-amendment-hs53/amendment.json": "e4255685a38f183d9cd5e5411ee83cc3dee6442e578831296d9789109824d763",
    "architecture/native-profile-v4/README.md": "a4205a5388dc83827bb39670bcc9477b030f29829128abf19f7578321c170174",
    "architecture/review-briefs/REVIEW_BRIEF_CONTRACT.md": "1f09d23451bf265e32e44742ca362dabf5a1090c2208c1349cbf491670798aec",
    "architecture/review-briefs/REVIEW_BRIEF_PACKET.md": "6dcff68d7e6b01823f1740063e94910edcc159a71a6ee803f1b66c62fd06e274",
    "architecture/review-record/briefs.json": "14022229ea689a81879cc7c6a327051777176dec3e90348ecdca48a30f82b0e0",
    "docs/alpha-2/BROKER_HANDOFF_READINESS.md": "2cc6ebef252efb33744208378b29248d89597e5a0be7c4a1a113adc9d63b9fc3",
    "scripts/host_interface_amendment_v4.py": "a09a12f9d574f3c38a30a87dc5ca1884ec7953c1c36ebfe80311f7b1f7223108",
    "tests/test_met_enforce_043_oracle.py": "f578df4ad1831fc54e47eddf74373541da413a75ef0f902b93da36da052455c9",
})


def reviewed_bytes(path: str) -> bytes:
    """This packet's reviewed bytes of path; a bridged successor projects newer bytes back first."""
    return successor.historical_bytes(path, regular_bytes(path))


def _era_bytes(path: Any, raw: Any) -> bytes:
    """An era file's bytes, checked against its era digest; a path outside the era is refused."""
    expected = ERA_SHA256.get(path) if type(path) is str else None
    require(expected is not None, "MET-ENFORCE-043 reviewed bytes are bound: " + str(path))
    require(type(raw) is bytes and digest(raw) == expected, "unreviewed EDGE-V12 source: " + path)
    return raw


def _verified(path: str) -> bytes:
    """reviewed_bytes, checked against its era digest on every read; a path outside the era is refused before it is
    read."""
    require(type(path) is str and path in ERA_SHA256, "MET-ENFORCE-043 reviewed bytes are bound: " + str(path))
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


def check_packet_files(files: Any) -> None:
    """V1: the packet's files are exactly the fourteen, and each one's bytes equal the sha256 pinned for it."""
    _bound(lambda: type(files) is dict and sorted(files) == sorted(PACKET_FILES) and len(files) == len(PACKET_FILES),
           "the packet files are exactly the fourteen")
    for path in PACKET_FILES:
        _bound(lambda: type(files[path]) is bytes and digest(files[path]) == ERA_SHA256[path],
               "a packet file's bytes equal its pinned digest: " + path)


def validate_packet_files() -> None:
    """V1 over the fourteen files, each read through the era."""
    check_packet_files({path: _verified(path) for path in PACKET_FILES})


def check_model(model: Any, read: Any) -> None:
    """V2: the v4 model's check(read), run over the reviewed bytes read gives it, returns the HE5 record without a
    refusal."""
    _bound(lambda: type(model) is types.ModuleType and type(model.check(read)) is dict,
           "the v4 model accepts the HE5 contract over this era's bytes")


def validate_model() -> None:
    """V2 with the model executed from its V1-verified bytes (slot 265's era-loader form) and this era's reader."""
    check_model(_era_model(MODEL_PATH, MODEL_NAME), _verified)


def check_oracle(identity_raw: Any, oracle_raw: Any, status_raw: Any) -> None:
    """V3: the oracle identity names the D5a oracle test and is kept, its file.sha256 equals the oracle test's bytes, and
    the status record's oracle.identitySha256 equals the identity's bytes."""
    identity, status = _parsed(identity_raw), _parsed(status_raw)
    _bound(lambda: type(identity) is dict and identity["schemaVersion"] == ORACLE_SCHEMA
           and type(identity["file"]) is dict and identity["file"]["path"] == ORACLE_TEST
           and type(identity["ruling"]) is dict and identity["ruling"]["decision"] == "KEEP",
           "the oracle identity names the oracle test and its ruling is KEEP")
    _bound(lambda: _sha(identity["file"]["sha256"]) and type(oracle_raw) is bytes
           and identity["file"]["sha256"] == digest(oracle_raw),
           "the oracle identity's sha256 equals the oracle test's bytes")
    _bound(lambda: type(status) is dict and type(status["oracle"]) is dict
           and status["oracle"]["identity"] == ORACLE_IDENTITY and status["oracle"]["tests"] == ORACLE_TEST
           and _sha(status["oracle"]["identitySha256"]) and type(identity_raw) is bytes
           and status["oracle"]["identitySha256"] == digest(identity_raw),
           "the status record's oracle.identitySha256 equals the identity's bytes")


def validate_oracle() -> None:
    """V3 over the identity, the oracle test (hashed only) and the status record."""
    check_oracle(_verified(ORACLE_IDENTITY), _verified(ORACLE_TEST), _verified(STATUS_PATH))


def check_registry(raw: Any, briefs: Any) -> None:
    """V4: the registry differs from the base by exactly this packet's two riders, each pointing at its generic brief
    with the sha256 of the brief's bytes; nothing else in it changes."""
    registry = _parsed(raw)
    _bound(lambda: type(registry) is dict and type(registry["briefs"]) is list and type(briefs) is dict
           and all(type(briefs[rider[2]]) is bytes for rider in RIDERS)
           and [entry for entry in registry["briefs"] if entry["series"].startswith(NEW_PACKET + "/")]
           == [{"kind": rider[0], "series": rider[1], "path": rider[2], "sha256": digest(briefs[rider[2]]),
                "version": rider[3]} for rider in RIDERS]
           and digest(canonical(dict(registry, briefs=[entry for entry in registry["briefs"]
                                                      if not entry["series"].startswith(NEW_PACKET + "/")])))
           == REGISTRY_BASE_SHA256,
           "the registry differs from the base by exactly the MET-ENFORCE-043 packet and contract riders, pinning the "
           "generic briefs")


def validate_registry() -> None:
    """V4 over briefs.json and the two generic briefs."""
    check_registry(_verified(REGISTRY_PATH), {PACKET_BRIEF: _verified(PACKET_BRIEF),
                                              CONTRACT_BRIEF: _verified(CONTRACT_BRIEF)})


def check_edges(v11_raw: Any, v12_raw: Any, providers: Any) -> None:
    """V5: edge record v11 is the pinned one with its 79 rows; v12's first 79 rows are v11's, in order; and v12's two
    new rows name the provider files in order, each row's sha256 and each file's byte count matching its bytes."""
    v11, v12 = _parsed(v11_raw), _parsed(v12_raw)
    _bound(lambda: type(v11_raw) is bytes and digest(v11_raw) == EDGE_V11_SHA256 and type(v11) is dict
           and type(v11["artifacts"]) is list and len(v11["artifacts"]) == V11_ROWS,
           "edge record v11 is the pinned one, with its 79 rows")
    _bound(lambda: type(v12) is dict and type(v12["artifacts"]) is list
           and len(v12["artifacts"]) == V11_ROWS + len(PROVIDER_FILES)
           and v12["artifacts"][:V11_ROWS] == v11["artifacts"],
           "edge record v12's first 79 rows are v11's, in order")
    _bound(lambda: type(providers) is dict and sorted(providers) == sorted(row[0] for row in PROVIDER_FILES)
           and [row["providerPath"] for row in v12["artifacts"][V11_ROWS:]] == [row[0] for row in PROVIDER_FILES]
           and all(type(providers[pin[0]]) is bytes and len(providers[pin[0]]) == pin[1]
                   and digest(providers[pin[0]]) == row["sha256"]
                   for pin, row in zip(PROVIDER_FILES, v12["artifacts"][V11_ROWS:])),
           "edge record v12's two new rows bind the provider files' sha256 and byte count")


def validate_edges() -> None:
    """V5 over edge records v11 and v12 and the two provider files."""
    check_edges(_verified(EDGE_V11), _verified(EDGE_V12), {pin[0]: _verified(pin[0]) for pin in PROVIDER_FILES})


def validate_edge_record_v12() -> None:
    """Every reviewed byte first; then V1 (the packet's files), V2 (the model), V3 (the oracle), V4 (the registry) and
    V5 (edge record v12's open items); last, this layer's canonical hunks."""
    for path in ERA_SHA256:
        _verified(path)
    validate_packet_files()
    validate_model()
    validate_oracle()
    validate_registry()
    validate_edges()
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
            == record["validatorNormalizedSha256"], "edge record v12 validator drift")
    paths = sorted((ROOT / "task-packets").glob("*.yaml"))
    old = set(record["baselinePackets"])
    require(len(paths) == 273
            and {path.stem for path in paths} == old | {NEW_PACKET, successor.NEW_PACKET, successor.successor.NEW_PACKET},
            "closed 273-packet catalog retaining the 271-packet checkpoint")
    packets = {}
    for path in paths:
        if path.stem in (successor.NEW_PACKET, successor.successor.NEW_PACKET):
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
            "closed source-only edge-record-v12 packet and inherited commands")
    require(len(packet["allowedPaths"]) == len(set(packet["allowedPaths"]))
            and set(packet["allowedPaths"]) == set(record["changedFiles"])
            | set(record["newFiles"]) | {AUTHORITY_PATH, VALIDATOR_PATH,
                                         "task-packets/" + NEW_PACKET + ".yaml"},
            "unreviewed or omitted edge-record-v12 packet path")
    for path, rule in record["changedFiles"].items():
        current = successor.historical_bytes(path, regular_bytes(path))
        require(digest(current) == rule["afterSha256"]
                and digest(historical_bytes(path, current)) == rule["beforeSha256"],
                "unreviewed current source: " + path)
    for path, expected in record["newFiles"].items():
        require(digest(successor.historical_bytes(path, regular_bytes(path))) == expected,
                "new source drift: " + path)
    validate_edge_record_v12()


if __name__ == "__main__":
    validate()
    print("Edge record v12 valid: 273 current specifications; 271-packet checkpoint and exact 270-packet predecessor; contract reviewed.")
