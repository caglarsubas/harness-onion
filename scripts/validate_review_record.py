#!/usr/bin/env python3
"""Validate the MET-GOV-002 review record v2 contract (two records per review round bound by the file-byte sha256, the brief registry, the frozen list, oracle identities; gate material) with version 2 of the evolution surface record, and the exact 259-to-258 projection."""
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
    import validate_probe_kit_scope as successor
except ImportError:
    from scripts.safe_yaml import safe_load
    from scripts import validate_probe_kit_scope as successor


ROOT = Path(__file__).resolve().parents[1]
AUTHORITY_PATH = "architecture/review-record-authority.json"
AUTHORITY_SHA256 = "4372a77b18dae5ac2a8052ebc6c9d8cbf8e6f0552895cf05e905d634e36bd878"
VALIDATOR_PATH = "scripts/validate_review_record.py"
BASE_COMMIT = "2043cc27883448e3ff030b7868110e295f32fe09"
NEW_PACKET = "MET-GOV-002"
PREVIOUS_PACKET = "MET-ENFORCE-041"
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
            require(key not in result, "duplicate review-record authority member")
            result[key] = value
        return result

    def no_constant(_value: str) -> Any:
        raise ValueError("nonfinite review-record authority number")

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
        require(digest(raw) == AUTHORITY_SHA256, "review record history authority digest")
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
    }, "closed review record history authority")
    require(value["schemaVersion"] == "harness.planeon.ai/review-record-authority/v1"
            and value["authorityPacket"] == NEW_PACKET
            and value["acceptedBase"] == BASE_COMMIT
            and type(value["baselinePackets"]) is dict
            and len(value["baselinePackets"]) == 258
            and NEW_PACKET not in value["baselinePackets"]
            and type(value["changedFiles"]) is dict
            and type(value["newFiles"]) is dict
            and _sha(value["packetSha256"])
            and _sha(value["validatorNormalizedSha256"]),
            "accepted 258-packet base")
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
    # An exact 258-era byte string is already older than the successor layer.
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


# MET-GOV-002 (roadmap REVIEW-RECORD-V2; owner decisions Q-RR2-1 to Q-RR2-6, Q-RR2-CAP, D-3 and Q-RR2-NAMES; the lane
# monitor's owner-delegated rulings of 2026-10-22, among them Q-RR2-ADOPT-SHAPE (a) and the adoption) adopts the review
# record v2 contract: two records per review round bound by the file-byte sha256 (the reviewer's record and the lane's
# identity), a brief registry, a frozen list of the review records and oracle tests that predate v2, oracle identities
# (D5a), a standard-library reference model and checker (scripts/review_record.py) with replayable vectors, and version 2
# of MET-GOV-001's evolution surface record (the GATE_REVIEW_PROCESS class: the derived gate list grows from 27 to 31).
# The contract was adopted after 6 contract review rounds by separate agents, recorded in the contract's own v2
# form; the last passed for adoption on the subject whose bytes are adopted. Repository bytes and modes are read only
# through reviewed_bytes and reviewed_mode, and the contract directory's listing only through reviewed_tree, so a later
# bridged successor projects its own edits away first; a path outside this era is refused before it is read, and every
# era file is bound by digest on every read. Each refusal is a pure check over the values read, so every one has a
# failing case on plain data. Checked here: the freeze (under architecture/ this packet changes only MET-GOV-001's
# record, vectors and README, and adds only the contract's directory and its authority; it changes no model); the files
# this packet adds (new, each once; the contract directory closed; mode 100644; no absolute local path); the adoption
# (the status record's closed shape and values; the adopted files are the final round's reviewed bytes, the README
# differing from them by its status line alone; every round bound to its published record and identity by digest, each
# record's verdict, subject, base and findings equal to its row's; the rounds form one valid series under the
# contract's rules, restated; the final round passed for adoption on the adopted subject); the model (executed from this
# era's verified bytes, never imported: its vectors replay); the published registry pins the published brief; the frozen
# list was derived at this packet's base; and the evolution surface record v2 (its model,
# from this era's bytes, derives 31 gate-material entries including the four GATE_REVIEW_PROCESS ones, and its vectors
# replay). This layer reads the frozen list only to hash it, scan it for local paths and load it to count its entries
# (Q-RR2-LEGACY (c)). Last, this layer's own inverse
# hunks are the canonical byte-minimal ones, recomputed from its era's bytes (MET-PERF-040's carried rule).
CONTRACT_DIR = "architecture/review-record"
README_PATH = CONTRACT_DIR + "/README.md"
BRIEF_PATH = CONTRACT_DIR + "/REVIEW_BRIEF.md"
REGISTRY_PATH = CONTRACT_DIR + "/briefs.json"
VECTORS_PATH = CONTRACT_DIR + "/vectors.json"
LEGACY_PATH = CONTRACT_DIR + "/legacy-review-records.json"
STATUS_PATH = CONTRACT_DIR + "/status.json"
ORACLE_IDENTITIES = (CONTRACT_DIR + "/oracle-identity-evolution-surface.json", CONTRACT_DIR + "/oracle-identity.json")
MODEL_PATH = "scripts/review_record.py"
SCHEMAS = tuple("schemas/%s.schema.json" % name for name in ("oracle-identity", "review-briefs", "review-identity",
                                                             "review-record"))
SURFACE_DIR = "architecture/evolution-surface"
SURFACE_RECORD = SURFACE_DIR + "/evolution-surface.json"
SURFACE_VECTORS = SURFACE_DIR + "/vectors.json"
SURFACE_README = SURFACE_DIR + "/README.md"
SURFACE_MODEL = "scripts/evolution_surface.py"
ROUNDS = 6
SERIES = "MET-GOV-002/contract"
RECORDS = tuple(CONTRACT_DIR + "/review-round%d.json" % number for number in range(1, ROUNDS + 1))
IDENTITIES = tuple(CONTRACT_DIR + "/review-identity-round%d.json" % number for number in range(1, ROUNDS + 1))
# The adopted subject: the final round's contract files, by the digests status.json's reviewedFiles names at its subject.
# The README differs from its reviewed bytes by the status line alone (the adoption edit). The test files are recorded
# in reviewedFiles too, but this packet's mechanics grow two of them (the layer test and MET-GOV-001's test), so the
# packet review compares those, not this layer.
SUBJECT = (README_PATH, BRIEF_PATH, REGISTRY_PATH, VECTORS_PATH, LEGACY_PATH) + ORACLE_IDENTITIES + SCHEMAS + (
    MODEL_PATH, SURFACE_RECORD, SURFACE_VECTORS, SURFACE_README)
REVIEWED_SHA256 = MappingProxyType({
    "architecture/review-record/README.md": "4040ebc078c9157c69c0a75b588303cd848c041f600d4e440a53e5fa2feeb603",
    "architecture/review-record/REVIEW_BRIEF.md": "72c3816a89a5a40e1b49b17b6db149aaa0150849cc96f60c86bf76061620285e",
    "architecture/review-record/briefs.json": "f389bae17a83924c873d29c2e13628b664f8586b47a59bf4093ac247928fc7c1",
    "architecture/review-record/vectors.json": "502b15998da618c9f992521c4a21259a97434363e2329f3f0becebb5dcbec584",
    "architecture/review-record/legacy-review-records.json": "e33afcf6593458857570045931b0c247c85a3c49b47743538eaea43182b70c9f",
    "architecture/review-record/oracle-identity-evolution-surface.json": "0633c76dbc4ad19834df9a43278d2835a78ce741bd55373a22e0066874c3396f",
    "architecture/review-record/oracle-identity.json": "35ceef8656ae5a4e133200e4e2ad5e2f003a2466759668a4d19a69dba09c8db1",
    "schemas/oracle-identity.schema.json": "6f3df9ec13d02a70167372ac49e24d7d40012c2de1f5d23bc8d16a007aa3b5b1",
    "schemas/review-briefs.schema.json": "b308441c37fac09b3cb966f36347dbe5ecbdbeca74554ab4770e91d41c783280",
    "schemas/review-identity.schema.json": "060457f8ee41d4da248778d5af509f1865304fd3860e9f25d20fff17b06a5051",
    "schemas/review-record.schema.json": "26e25c862458a18222f49fec0fe7a7d3f06a85aab6b624bda9920a3f015f1b40",
    "scripts/review_record.py": "bdcda19bd77f32e489a1baf67fcec1385c35085cb9224aa29f8d6716f5265996",
    "architecture/evolution-surface/evolution-surface.json": "b1759fe4bae0d9dc111f0c4ca3cc23e891cf89d572b73929ee01f5ec7616a277",
    "architecture/evolution-surface/vectors.json": "9c0f7cf1eb0f48dab41e322d8cdffba8568a5db2ddc2a31869f6af8dd9985b56",
    "architecture/evolution-surface/README.md": "922b09a56cd09486d3ab98a8abe8c4875774579beafebff14da294d9e87723c5",
})
TEST_FILES = ("tests/test_evolution_surface.py", "tests/test_evolution_surface_oracle.py", "tests/test_review_record.py",
              "tests/test_review_record_oracle.py", "tests/test_review_records_in_tree.py")
STATUS_FILES = (STATUS_PATH,) + RECORDS + IDENTITIES
NEW_FILES = (README_PATH, BRIEF_PATH, REGISTRY_PATH, VECTORS_PATH, LEGACY_PATH) + ORACLE_IDENTITIES + STATUS_FILES \
    + SCHEMAS + (MODEL_PATH,)
DIRECTORY_FILES = (README_PATH, BRIEF_PATH, REGISTRY_PATH, VECTORS_PATH, LEGACY_PATH) + ORACLE_IDENTITIES + STATUS_FILES
SURFACE_CHANGED = (SURFACE_RECORD, SURFACE_VECTORS, SURFACE_README)
# The status record written at adoption: its closed key sets and its values, restated.
STATUS_SCHEMA = "planeon.internal.review-record-status/v1"
WORK_ITEM = "REVIEW-RECORD-V2 (review record v2)"
SLOT = 259
STATUS_KEYS = ("schemaVersion", "workItem", "packet", "slot", "status", "baseMain", "series", "adoptedSubject",
               "adoption", "rounds", "reviewedFiles", "adoptionEdit", "ownerDecisions", "nonClaims")
ADOPTED_SUBJECT = MappingProxyType({"commit": "8c7ee7ca990649858c2d6c4ff0aed9dcf4b021cd", "tree": "0802156b39cbc95466de0afcc7b025fad38aca99"})
ADOPTION = {"decidedBy": "the lane monitor, owner-delegated (2026-10-22)", "decision": "Q-RR2-ADOPT-SHAPE (a): the final delta round's subject bytes become the adopted bytes; a light adoption commit with no snapshot directories, the final round's per-file digests in status.json, and the v2 rounds plus identities in architecture/review-record/"}
EDIT_KEYS = ("path", "replaced", "with", "reviewedSha256", "adoptedSha256")
ADOPTION_EDIT = {"path": "architecture/review-record/README.md", "replaced": "**Status:** contract candidate, under independent contract review. Not adopted. `legacy-review-records.json` is", "with": "**Status:** ADOPTED_CONTRACT_CANDIDATE (internal, DATA_CHECK_ONLY; independent contract review round 6: PASS_FOR_ADOPTION;\nthe rounds and their v2 records in `status.json`). `legacy-review-records.json` is", "reviewedSha256": "4040ebc078c9157c69c0a75b588303cd848c041f600d4e440a53e5fa2feeb603", "adoptedSha256": "f2427a967062d3bd90da2e1b6ea4c99ec83b014834979eef488d68bc6471787f"}
OWNER_DECISIONS = ("Q-RR2-1..5: \"Accept all five (a) (Recommended)\"",
                   "Q-RR2-6: \"Gate material (Recommended)\"",
                   "Q-RR2-CAP: \"Fold into rev 4, no round (Recommended)\"",
                   "D-3: \"File-byte sha256 (Recommended)\"",
                   "Q-RR2-NAMES: \"Load hashes locally (Recommended)\"")
NON_CLAIMS = ("DATA_CHECK_ONLY: the model checks review records, identities, oracle identities, the registry and the frozen list; it runs nothing and grants no merge.",
              "The monitor's merge check and MONITOR.md section 4 adopt the contract when this packet merges; R10 and R12 keep their current sidecars until their own packets adopt v2.",
              "Name tokens are checked only by local scans that load unpublished digests (Q-RR2-NAMES); the in-suite check covers home paths, e-mails and the legacy term.")
ROUND_KEYS_FULL = ("round", "record", "recordSha256", "identity", "identitySha256", "subject", "verdict", "findings",
                   "ruling")
ROUND_KEYS_DELTA = ROUND_KEYS_FULL + ("base",)
# (round, verdict, subject commit, subject tree, base commit or None, finding ids, ruling ref) in order.
ROUND_ROWS = ((1, "CHANGES_REQUIRED", "0bc5dc1aa263206b94199412648d8d0849c6fe38",
  "4bee7f573c8ab7c1c49f2e22b4e0408534320124",
  None, ("RR2C1-1", "RR2C1-2", "RR2C1-3", "RR2C1-4", "RR2C1-5", "RR2C1-6", "RR2C1-7", "RR2C1-8", "RR2C1-9", "RR2C1-10", "RR2C1-11", "RR2C1-12", "RR2C1-13", "RR2C1-14", "RR2C1-15"),
  "MON-RR2-CR1-SLIPS"),
 (2, "CHANGES_REQUIRED", "45d818eea16b609fc5b26c26c087c7175ecda43a",
  "d067b4a5e6abfb8c8537a06a85045b0dc77d9900",
  "0bc5dc1aa263206b94199412648d8d0849c6fe38", ("RR2C2-1", "RR2C2-2", "RR2C2-3", "RR2C2-4", "RR2C2-5", "RR2C2-6"),
  "MON-RR2-CR2-SLIPS"),
 (3, "CHANGES_REQUIRED", "09d2decd1f5e6d2c642b6642b0be58be0949d9ba",
  "721000278980f3dd9a292a3bed2dc062146f386d",
  "45d818eea16b609fc5b26c26c087c7175ecda43a", ("RR2C3-1", "RR2C3-2", "RR2C3-3"),
  "MON-RR2-CR3-SLIPS"),
 (4, "CHANGES_REQUIRED", "d04f8f64ea7373b4cc1e72d06e2fb31ba90b2431",
  "ecdbb89ad6e47bb95ad1b954ff13e506a83dc8a5",
  "09d2decd1f5e6d2c642b6642b0be58be0949d9ba", ("RR2C4-1", "RR2C4-2", "RR2C4-3", "RR2C4-4"),
  "MON-RR2-CR4-SLIPS"),
 (5, "PASS_FOR_ADOPTION", "16c02fbe31fff5e1d8eb6cc28a121012d2760486",
  "410d64c095b889ce8b793c6b6e078047bf8052de",
  "d04f8f64ea7373b4cc1e72d06e2fb31ba90b2431", ("RR2C5-1", "RR2C5-2", "RR2C5-3", "RR2C5-4"),
  "MON-RR2-CR5-SLIPS"),
 (6, "PASS_FOR_ADOPTION", "8c7ee7ca990649858c2d6c4ff0aed9dcf4b021cd",
  "0802156b39cbc95466de0afcc7b025fad38aca99",
  "16c02fbe31fff5e1d8eb6cc28a121012d2760486", ("RR2C6-1", "RR2C6-2", "RR2C6-3"),
  "MON-RR2-CR6-SLIPS; disclosed process gap: rounds 1-5 could not run tests/test_review_records_in_tree.py (out of every brief's scope), so none found the oracle-name defect"))
# The model's vector replay counts and the frozen list's counts at this era (the builder's count line: 169 review
# records and 2 oracle tests at 2043cc27).
VECTOR_COUNTS = MappingProxyType({"reviews": 62, "series": 10, "oracles": 10, "prOracles": 5, "merges": 15, "registries": 13, "legacy": 7, "trees": 18, "privacy": 5})
LEGACY_RECORDS, LEGACY_ORACLES = 169, 2
# Version 2 of MET-GOV-001's record: the derived gate list and the four GATE_REVIEW_PROCESS entries it adds.
GATE_MATERIAL = 31
GATE_REVIEW_PROCESS = ({"prefix": "architecture/review-record/"}, {"exact": "architecture/review-record-authority.json"},
                       {"exact": "scripts/review_record.py"}, {"exact": "tests/test_review_records_in_tree.py"})
SURFACE_REPLAY = MappingProxyType({"decisions": 44, "invariants": 31, "texts": 5, "paths": 23, "skip": 8, "prs": 9, "coverage": 2, "requests": 10, "derived": 31, "consumerCases": 12})
# Every file this era's check reads, with its digest: the files this packet adds, MET-GOV-001's three changed files and
# its model.
ERA_SHA256 = MappingProxyType({
    "architecture/review-record/README.md": "f2427a967062d3bd90da2e1b6ea4c99ec83b014834979eef488d68bc6471787f",
    "architecture/review-record/REVIEW_BRIEF.md": "72c3816a89a5a40e1b49b17b6db149aaa0150849cc96f60c86bf76061620285e",
    "architecture/review-record/briefs.json": "f389bae17a83924c873d29c2e13628b664f8586b47a59bf4093ac247928fc7c1",
    "architecture/review-record/vectors.json": "502b15998da618c9f992521c4a21259a97434363e2329f3f0becebb5dcbec584",
    "architecture/review-record/legacy-review-records.json": "e33afcf6593458857570045931b0c247c85a3c49b47743538eaea43182b70c9f",
    "architecture/review-record/oracle-identity-evolution-surface.json": "0633c76dbc4ad19834df9a43278d2835a78ce741bd55373a22e0066874c3396f",
    "architecture/review-record/oracle-identity.json": "35ceef8656ae5a4e133200e4e2ad5e2f003a2466759668a4d19a69dba09c8db1",
    "architecture/review-record/status.json": "e2beafaa7bbc69fb2a6321819c2c65c243e69a0aada460f821115726247212f0",
    "architecture/review-record/review-round1.json": "f49805ee04fcabda492e5399eda9bdf86d1943d7b088f45e24f051a9b970d6cc",
    "architecture/review-record/review-round2.json": "7b1a14ffffd1a4482cc978e83c75faf768296991cb2e6c6a80eadf41bdd3b1bd",
    "architecture/review-record/review-round3.json": "786fe2274a55fb9435727839f0775ee6cb4697fc15f04207194f9a18aaa5f82a",
    "architecture/review-record/review-round4.json": "df2aa55b2004637547fc6f1951d696eeabcd198112faf3d2df274a9244bc2180",
    "architecture/review-record/review-round5.json": "b29d531933c3632f366a6c4e8e18a330910c3237bddddda7327920da1451192a",
    "architecture/review-record/review-round6.json": "a25f25eed6303ead29d76dcdabadfd96db62c8aae3d3b0c9ea2e97238cb49162",
    "architecture/review-record/review-identity-round1.json": "c45c53fffc6c38477c737872e17df9323a8a467e86579601b4ebab8b3241aa56",
    "architecture/review-record/review-identity-round2.json": "5407523ff23516b2a4495c6eb6c6b5b2d2c9b58aa25a61b72c86cbe6a61328d8",
    "architecture/review-record/review-identity-round3.json": "3bf8caadb4db12f25bc754803c0cdcb76972ec7e9fdac52a7ef19ea003b1123d",
    "architecture/review-record/review-identity-round4.json": "1947e8ebcb6645577f3483633bf3b78a93d5ace607cd0c849c744a35640d5f22",
    "architecture/review-record/review-identity-round5.json": "71af2465dd829228f924aae892a8b919a6f5ecb56e6fd5b67976ac90d894438c",
    "architecture/review-record/review-identity-round6.json": "905cf7dfaf5462d85d441e9db5dd305d65e5a3dc62929b6f27325d983a467849",
    "schemas/oracle-identity.schema.json": "6f3df9ec13d02a70167372ac49e24d7d40012c2de1f5d23bc8d16a007aa3b5b1",
    "schemas/review-briefs.schema.json": "b308441c37fac09b3cb966f36347dbe5ecbdbeca74554ab4770e91d41c783280",
    "schemas/review-identity.schema.json": "060457f8ee41d4da248778d5af509f1865304fd3860e9f25d20fff17b06a5051",
    "schemas/review-record.schema.json": "26e25c862458a18222f49fec0fe7a7d3f06a85aab6b624bda9920a3f015f1b40",
    "scripts/review_record.py": "bdcda19bd77f32e489a1baf67fcec1385c35085cb9224aa29f8d6716f5265996",
    "architecture/evolution-surface/evolution-surface.json": "b1759fe4bae0d9dc111f0c4ca3cc23e891cf89d572b73929ee01f5ec7616a277",
    "architecture/evolution-surface/vectors.json": "9c0f7cf1eb0f48dab41e322d8cdffba8568a5db2ddc2a31869f6af8dd9985b56",
    "architecture/evolution-surface/README.md": "922b09a56cd09486d3ab98a8abe8c4875774579beafebff14da294d9e87723c5",
    "scripts/evolution_surface.py": "f38fa6d00ec5fbbbcab8ff01d0e56824e805327b872dc1e23e579e522a681fd9",
})
# Absolute local path markers, matched case-insensitively; spelled in parts, so this file holds none of them. A marker
# counts when a path character follows it.
LOCAL_PATH_MARKERS = (b"/" + b"users/", b"/" + b"private/", b".local" + b"/state")
PATH_BYTES = b"abcdefghijklmnopqrstuvwxyz0123456789_.-/"


def reviewed_bytes(path: str) -> bytes:
    """This packet's reviewed bytes of path; a bridged successor projects newer bytes back first."""
    return successor.historical_bytes(path, regular_bytes(path))


def reviewed_mode(path: str) -> int:
    """The lstat mode of path in this packet's tree; a bridged successor projects a newer mode back first."""
    _path(path)
    return (ROOT / path).lstat().st_mode


def reviewed_tree(directory: str) -> dict[str, int]:
    """Every entry under directory in this packet's tree, by repository path, with its lstat mode; a bridged successor
    that adds an entry there projects it away first."""
    entries: dict[str, int] = {}
    pending = [directory.rstrip("/")]
    while pending:
        folder = pending.pop()
        for entry in sorted((ROOT / folder).iterdir()):
            relative = folder + "/" + entry.name
            entries[relative] = entry.lstat().st_mode
            if stat.S_ISDIR(entries[relative]):
                pending.append(relative)
    return entries


def _era_bytes(path: Any, raw: Any) -> bytes:
    """An era file's bytes, checked against its era digest; a path outside the era is refused."""
    expected = ERA_SHA256.get(path) if type(path) is str else None
    require(expected is not None, "MET-GOV-002 reviewed bytes are bound: " + str(path))
    require(type(raw) is bytes and digest(raw) == expected, "unreviewed REVIEW-RECORD-V2 source: " + path)
    return raw


def _verified(path: str) -> bytes:
    """reviewed_bytes, checked against its era digest on every read; a path outside the era is refused before it is
    read."""
    require(type(path) is str and path in ERA_SHA256, "MET-GOV-002 reviewed bytes are bound: " + str(path))
    return _era_bytes(path, reviewed_bytes(path))


def _json(path: str) -> Any:
    return parse(_verified(path))


def _holds(check: Any) -> bool:
    """A structural check over this era's data; a malformed value does not hold."""
    try:
        return check() is True
    except (KeyError, TypeError, AttributeError, IndexError, ValueError):
        return False


def _bound(check: Any, message: str) -> None:
    require(_holds(check), message)


def _git_mode(mode: int) -> str | None:
    """The git mode of a regular file from its lstat mode; anything else has none."""
    if not stat.S_ISREG(mode):
        return None
    return "100755" if mode & 0o100 else "100644"


def _local_path(raw: bytes) -> bool:
    """Whether raw holds an absolute local path: a marker, case-insensitively, followed by a path character."""
    low = raw.lower()
    for marker in LOCAL_PATH_MARKERS:
        at = low.find(marker)
        while at >= 0:
            end = at + len(marker)
            if end < len(low) and low[end:end + 1] in PATH_BYTES:
                return True
            at = low.find(marker, at + 1)
    return False


def _era_model(path: str, name: str) -> types.ModuleType:
    """A standard-library reference module of this era, executed from its verified bytes (no import, no bytecode)."""
    module = types.ModuleType(name)
    module.__file__ = str(ROOT / path)
    exec(compile(_verified(path), path, "exec", dont_inherit=True), module.__dict__)
    return module


def era_models() -> tuple:
    """(the review-record model, the evolution surface model), each executed from this era's verified bytes."""
    return (_era_model(MODEL_PATH, "_met_gov_002_review_record"),
            _era_model(SURFACE_MODEL, "_met_gov_002_evolution_surface"))


def check_freeze(changed: Any, added: Any) -> None:
    """Under architecture/ this packet changes only MET-GOV-001's record, vectors and README, and adds only the contract's
    directory; under scripts/ it changes only chain validators (scripts/validate_*.py, one level deep), so no model, the
    identity checker included, changes; and neither conftest.py changes (packet review r1, P1-2; r2, P2-4)."""
    for path in list(changed):
        require(type(path) is str and (not path.startswith("architecture/") or path in SURFACE_CHANGED)
                and (not path.startswith("scripts/") or (path.startswith("scripts/validate_") and path.endswith(".py")
                                                         and path.count("/") == 1))
                and path not in ("conftest.py", "tests/conftest.py"),
                "under architecture/ only MET-GOV-001's record, vectors and README change, no model changes and no "
                "conftest change: " + str(path))
    for path in list(added):
        require(type(path) is str and (not path.startswith("architecture/") or path.startswith(CONTRACT_DIR + "/")),
                "under architecture/ only the contract's directory is added: " + str(path))


def check_new_files(added: Any, changed: Any) -> None:
    """The packet adds the contract's files, its status record, rounds and identities, the four schemas and the model
    as new files, each once."""
    _bound(lambda: len(set(NEW_FILES)) == len(NEW_FILES) and not set(NEW_FILES) & set(changed)
           and {path for path in added if path.startswith((CONTRACT_DIR + "/", "schemas/")) or path == MODEL_PATH}
           == set(NEW_FILES), "the contract's files, status record, rounds, identities, schemas and model are new in "
           "this packet, each once")


def check_contract_tree(mode: Any, tree: Any) -> None:
    """The contract directory is a directory (not a link) holding exactly its files, each a regular file of git mode
    100644."""
    require(type(mode) is int and stat.S_ISDIR(mode), "the contract directory is a directory, not a link")
    _bound(lambda: type(tree) is dict and sorted(tree) == sorted(DIRECTORY_FILES)
           and all(_git_mode(tree[path]) == "100644" for path in DIRECTORY_FILES),
           "the contract directory holds exactly its files, each of mode 100644")


def check_added_file(path: str, mode: Any, raw: Any) -> None:
    """A file this packet adds is a regular file of git mode 100644 (not a link, not executable) and holds no absolute
    local path."""
    require(type(mode) is int and _git_mode(mode) == "100644",
            "a file this packet adds is a regular file of git mode 100644: " + path)
    require(type(raw) is bytes and not _local_path(raw), "no absolute local path in a file this packet adds: " + path)


def validate_files() -> None:
    """The freeze, the files this packet adds and the contract directory, from this era's authority, modes and
    listing."""
    record = authority()
    check_freeze(list(_PROJECTION_RULES), list(record["newFiles"]))
    check_new_files(list(record["newFiles"]), list(_PROJECTION_RULES))
    check_contract_tree(reviewed_mode(CONTRACT_DIR), reviewed_tree(CONTRACT_DIR))
    for path in NEW_FILES:
        check_added_file(path, reviewed_mode(path), _verified(path))


def check_status(status: Any) -> None:
    """The status record's closed shape and values: REVIEW-RECORD-V2 adopted as MET-GOV-002 at slot 259 on this era's
    base, the adopted subject, the adoption decision, the owner's decisions and the non-claims as adopted."""
    _bound(lambda: type(status) is dict and tuple(status) == STATUS_KEYS and status["schemaVersion"] == STATUS_SCHEMA
           and status["workItem"] == WORK_ITEM and status["packet"] == NEW_PACKET and status["slot"] == SLOT
           and type(status["slot"]) is int and status["status"] == "ADOPTED_CONTRACT_CANDIDATE"
           and status["baseMain"] == BASE_COMMIT and status["series"] == SERIES
           and status["adoptedSubject"] == dict(ADOPTED_SUBJECT) and tuple(status["adoptedSubject"]) == ("commit", "tree")
           and status["adoption"] == ADOPTION and status["ownerDecisions"] == list(OWNER_DECISIONS)
           and status["nonClaims"] == list(NON_CLAIMS), "adopted REVIEW-RECORD-V2 status")


def check_subject(status: Any) -> None:
    """status.json's reviewedFiles names every adopted file at the final round's subject, with this layer's digests."""
    _bound(lambda: all(status["reviewedFiles"][path] == REVIEWED_SHA256[path] for path in SUBJECT)
           and set(status["reviewedFiles"]) == set(SUBJECT) | set(TEST_FILES)
           and sorted(status["reviewedFiles"]) == list(status["reviewedFiles"]),
           "status.json names every adopted file by its reviewed digest")


def check_adopted_file(path: str, raw: Any) -> None:
    """An adopted file is the final round's reviewed bytes (the README apart from its status line)."""
    require(path in REVIEWED_SHA256 and path != README_PATH and type(raw) is bytes
            and digest(raw) == REVIEWED_SHA256[path], "the contract files are the final round's reviewed bytes: " + path)


def check_adoption_edit(edit: Any, readme: Any) -> None:
    """The README's status line is the one adoption edit: the adopted README, with the line put back, is the reviewed
    README by digest."""
    _bound(lambda: type(edit) is dict and tuple(edit) == EDIT_KEYS and edit == ADOPTION_EDIT
           and type(readme) is bytes and digest(readme) == edit["adoptedSha256"]
           and readme.count(edit["with"].encode("utf-8")) == 1 and edit["replaced"].encode("utf-8") not in readme
           and digest(readme.replace(edit["with"].encode("utf-8"), edit["replaced"].encode("utf-8")))
           == edit["reviewedSha256"] == REVIEWED_SHA256[README_PATH],
           "the README's status line is the one adoption edit")


def check_round(number: int, row: Any, record_raw: Any, identity_raw: Any) -> None:
    """Round `number` is bound to its published record and identity by digest; the record's verdict, subject, base and
    findings are the row's, and the identity's ruling ref is the row's."""
    n, verdict, commit, tree, base, ids, ruling = ROUND_ROWS[number - 1]
    _bound(lambda: number == n and type(row) is dict
           and tuple(row) == (ROUND_KEYS_DELTA if base is not None else ROUND_KEYS_FULL)
           and row["round"] == number and row["record"] == RECORDS[number - 1]
           and row["identity"] == IDENTITIES[number - 1]
           and type(record_raw) is bytes and digest(record_raw) == row["recordSha256"]
           and type(identity_raw) is bytes and digest(identity_raw) == row["identitySha256"]
           and row["verdict"] == verdict and row["findings"] == list(ids) and row["ruling"] == ruling
           and row["subject"] == {"repository": "harness-onion", "commit": commit, "tree": tree}
           and (base is None or row["base"]["commit"] == base)
           and parse(record_raw)["verdict"] == verdict and parse(record_raw)["round"] == number
           and parse(record_raw)["subject"] == row["subject"]
           and [finding["id"] for finding in parse(record_raw)["findings"]] == list(ids)
           and parse(record_raw).get("base") == row.get("base")
           and parse(identity_raw)["ruling"]["ref"] == ruling,
           "round %d is bound to its record and identity" % number)


def _counting(ruling: Any, record: Any, identity: Any) -> bool:
    """The contract's ruling rule: KEEP with by, ref and date, or NONE_NEEDED with no disclosure, interruption or relay."""
    if ruling["decision"] == "KEEP":
        return all(key in ruling for key in ("by", "ref", "date"))
    return (ruling["decision"] == "NONE_NEEDED" and not record["disclosures"] and not identity["interruptions"]
            and not identity["operatorRelays"])


def _series_holds(records: Any, identities: Any, registry: Any) -> bool:
    """The contract's series rules, restated over the published rounds: rounds 1 to ROUNDS of SERIES, kind CONTRACT, each
    bound by its identity (the record's path and file-byte digest; the same brief, subject and base; a counting ruling; a
    reviewer who is neither the operator nor an author); round 1 full and each later round's base the previous round's
    subject; the series' one current registered brief; and the last round PASS_FOR_ADOPTION on the adopted subject. The
    reference model's own check_series runs over the same rounds in the in-suite pre-check."""
    briefs = [brief for brief in registry["briefs"] if brief["series"] == SERIES and "supersededAt" not in brief]
    if len(records) != ROUNDS or len(identities) != ROUNDS or len(briefs) != 1:
        return False
    previous = None
    for number, ((path, raw), (identity_path, identity_raw)) in enumerate(zip(records, identities), 1):
        record, identity = parse(raw), parse(identity_raw)
        if not (path == RECORDS[number - 1] and identity_path == IDENTITIES[number - 1]
                and record["series"] == SERIES and record["round"] == number and record["kind"] == "CONTRACT"
                and record["verdict"] in registry["kinds"]["CONTRACT"]["verdicts"]
                and identity["record"] == {"path": path, "sha256": digest(raw)}
                and record["briefSha256"] == identity["briefSha256"] == briefs[0]["sha256"]
                and record["subject"] == identity["subject"] and record.get("base") == identity.get("base")
                and record.get("base") == previous and _counting(identity["ruling"], record, identity)
                and identity["reviewer"]["agentId"] != identity["operator"]["agentId"]
                and identity["reviewer"]["agentId"] not in identity["author"]["agentIds"]):
            return False
        previous = record["subject"]
    return (parse(records[-1][1])["verdict"] == "PASS_FOR_ADOPTION"
            and previous == dict({"repository": "harness-onion"}, **ADOPTED_SUBJECT))


def check_series(records: Any, identities: Any, registry_raw: Any) -> None:
    """The rounds form one valid series under the contract's rules, and the final round passed for adoption on the
    adopted subject."""
    _bound(lambda: _series_holds(records, identities, parse(registry_raw)),
           "the rounds form one valid series, and the last passed for adoption on the adopted subject")


def validate_adoption() -> None:
    """The status record, the adopted files and the README's one edit, every round with its record and identity, and
    the series under the contract's rules as this layer restates them (the reference model's own check_series runs over
    the same rounds in the in-suite pre-check)."""
    status = _json(STATUS_PATH)
    check_status(status)
    check_subject(status)
    for path in SUBJECT:
        if path != README_PATH:
            check_adopted_file(path, _verified(path))
    check_adoption_edit(status["adoptionEdit"], _verified(README_PATH))
    _bound(lambda: type(status["rounds"]) is list and len(status["rounds"]) == ROUNDS, "every round is recorded")
    records, identities = [], []
    for number, row in enumerate(status["rounds"], 1):
        records.append((RECORDS[number - 1], _verified(RECORDS[number - 1])))
        identities.append((IDENTITIES[number - 1], _verified(IDENTITIES[number - 1])))
        check_round(number, row, records[-1][1], identities[-1][1])
    check_series(records, identities, _verified(REGISTRY_PATH))


def _replays(model: Any, *args: Any) -> Any:
    """The model's replay counts, or None when a vector mismatches (each model raises its own Mismatch, a subclass of
    AssertionError raised explicitly, so that python -O cannot skip it)."""
    try:
        return model.replay(*args)
    except AssertionError:
        return None


def check_vector_replay(model: Any, vectors: Any) -> None:
    """The model replays every vector with no mismatch and returns its counts."""
    _bound(lambda: _replays(model, vectors) == dict(VECTOR_COUNTS), "the model replays its vectors with no mismatch")


def check_registry(raw: Any, brief: Any) -> None:
    """The published registry names the four kinds, and its one entry for MET-GOV-002/contract is the published brief
    (the reference model's load rules replay in its vectors and run in the in-suite tests)."""
    _bound(lambda: (lambda registry: registry["schemaVersion"] == "planeon.review-briefs/v1"
                    and sorted(registry["kinds"]) == ["CONTRACT", "DESIGN", "PACKET", "PR"]
                    and [b for b in registry["briefs"] if b["series"] == SERIES]
                    == [{"kind": "CONTRACT", "series": SERIES, "path": BRIEF_PATH, "sha256": digest(brief),
                         "version": 1}])(parse(raw)),
           "the registry pins the published brief for MET-GOV-002/contract")


def check_legacy(raw: Any) -> None:
    """The frozen list was derived at this packet's base and holds the builder's counts, each entry a path and a digest
    (the reference model's load rules replay in its vectors and run in the in-suite tests)."""
    _bound(lambda: (lambda legacy: legacy["schemaVersion"] == "planeon.legacy-review-records/v1"
                    and legacy["baseCommit"] == BASE_COMMIT and len(legacy["entries"]) == LEGACY_RECORDS
                    and len(legacy["oracleTests"]) == LEGACY_ORACLES
                    and all(sorted(entry) == ["path", "sha256"] and len(entry["sha256"]) == 64
                            for entry in legacy["entries"] + legacy["oracleTests"]))(parse(raw)),
           "the frozen list was derived at this packet's base, with the builder's counts")


def check_surface(es: Any, record: Any, vectors: Any) -> None:
    """MET-GOV-001's record is version 2: its model derives 31 gate-material entries, the four GATE_REVIEW_PROCESS ones
    among them, and its vectors replay."""
    _bound(lambda: record["version"] == 2 and (lambda gate: len(gate) == GATE_MATERIAL
                                                and all(entry in gate for entry in GATE_REVIEW_PROCESS))(
                       es.check(record)["gateMaterial"])
           and _replays(es, record, vectors) == dict(SURFACE_REPLAY),
           "the evolution surface record v2 derives 31 gate-material entries and its vectors replay")


def validate_model(models: tuple) -> None:
    """The model, run from this era's bytes, replays its vectors; the published registry and frozen list are read with
    parse (the model's load rules replay in its vectors and run in the in-suite tests); the evolution surface model, from
    this era's bytes, checks record v2."""
    model, es = models
    check_vector_replay(model, _json(VECTORS_PATH))
    check_registry(_verified(REGISTRY_PATH), _verified(BRIEF_PATH))
    check_legacy(_verified(LEGACY_PATH))
    check_surface(es, _json(SURFACE_RECORD), _json(SURFACE_VECTORS))


def validate_review_record() -> None:
    """Every reviewed byte first; then the freeze and the files this packet adds, the adoption and the model; last, this
    layer's canonical hunks."""
    for path in ERA_SHA256:
        _verified(path)
    validate_files()
    validate_adoption()
    validate_model(era_models())
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
            == record["validatorNormalizedSha256"], "review record validator drift")
    paths = sorted((ROOT / "task-packets").glob("*.yaml"))
    old = set(record["baselinePackets"])
    require(len(paths) == 260
            and {path.stem for path in paths} == old | {NEW_PACKET, successor.NEW_PACKET},
            "closed 260-packet catalog retaining the 259-packet checkpoint")
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
            "closed source-only review-record packet and inherited commands")
    require(len(packet["allowedPaths"]) == len(set(packet["allowedPaths"]))
            and set(packet["allowedPaths"]) == set(record["changedFiles"])
            | set(record["newFiles"]) | {AUTHORITY_PATH, VALIDATOR_PATH,
                                         "task-packets/" + NEW_PACKET + ".yaml"},
            "unreviewed or omitted review-record packet path")
    for path, rule in record["changedFiles"].items():
        current = successor.historical_bytes(path, regular_bytes(path))
        require(digest(current) == rule["afterSha256"]
                and digest(historical_bytes(path, current)) == rule["beforeSha256"],
                "unreviewed current source: " + path)
    for path, expected in record["newFiles"].items():
        require(digest(successor.historical_bytes(path, regular_bytes(path))) == expected,
                "new source drift: " + path)
    validate_review_record()


if __name__ == "__main__":
    validate()
    print("Review record valid: 260 current specifications; 259-packet checkpoint and exact 258-packet predecessor; contract reviewed.")
