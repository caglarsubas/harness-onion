#!/usr/bin/env python3
"""Validate the MET-MAS-004 topology and coordination v1 and the exact 245-to-244 projection."""
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
    import validate_native_profile_v4 as successor
except ImportError:
    from scripts.safe_yaml import safe_load
    from scripts import validate_native_profile_v4 as successor


ROOT = Path(__file__).resolve().parents[1]
AUTHORITY_PATH = "architecture/topology-coordination-authority.json"
AUTHORITY_SHA256 = "efdc61a7c7fc32d0160c56456d791420c9863a047dc65d62cdbbe9cc94b22ec4"
VALIDATOR_PATH = "scripts/validate_topology_coordination.py"
BASE_COMMIT = "c69e55f877003735a0937c05a4cff2d448e77f45"
NEW_PACKET = "MET-MAS-004"
PREVIOUS_PACKET = "MET-ENFORCE-032"
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
            require(key not in result, "duplicate topology-coordination authority member")
            result[key] = value
        return result

    def no_constant(_value: str) -> Any:
        raise ValueError("nonfinite topology-coordination authority number")

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
        require(digest(raw) == AUTHORITY_SHA256, "topology coordination history authority digest")
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
    }, "closed topology coordination history authority")
    require(value["schemaVersion"] == "harness.planeon.ai/topology-coordination-authority/v1"
            and value["authorityPacket"] == NEW_PACKET
            and value["acceptedBase"] == BASE_COMMIT
            and type(value["baselinePackets"]) is dict
            and len(value["baselinePackets"]) == 244
            and NEW_PACKET not in value["baselinePackets"]
            and type(value["changedFiles"]) is dict
            and type(value["newFiles"]) is dict
            and _sha(value["packetSha256"])
            and _sha(value["validatorNormalizedSha256"]),
            "accepted 244-packet base")
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
    # An exact 244-era byte string is already older than the successor layer.
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


# MET-MAS-004 (roadmap MAS-RA-004; owner decision "MAS-RA-004" and Q-M4-1..11 (a), 2026-10-16) publishes topology and
# coordination v1: a TopologySpec with its derived role-block vector, a coordinator board on exclusive leased claims with
# an independent verify-before-merge bound to a MAS-RA-001 verdict ledger, a declared selection rule at 45/100 over
# eligible MAS-RA-002 baselines, and the run-events v1 mapping with its gaps. Repository bytes are read only through
# reviewed_bytes, so a later bridged successor projects its own edits away first. A path outside this era is refused
# before it is read, and every era file is bound by digest on every read. The adoption is checked against the status
# record: five review rounds bound to their records, the README's one adoption edit by digest, and the post-review
# redaction of two local paths (monitor decision LOCAL-PATHS) by its placeholders and after digests only (owner P1-3). The topology model and the four models it takes as
# arguments (run manifest, verdict ledger, agent loop, run events) are executed from this era's bytes, and every vector,
# raw text, selection row, kinds case and v1 embedding replays here, in the validator. The MAS-RA-001/002/003/008 models
# and the check-kinds record stay byte-identical. This layer's own inverse hunks are the canonical byte-minimal ones,
# recomputed from its era's bytes (MET-PERF-040's carried rule).
TC_DIR = "architecture/topology-coordination/"
TC_MODEL = "scripts/topology_coordination.py"
RUNS_MODEL = "scripts/run_manifest.py"
LEDGER_MODEL = "scripts/verdict_ledger.py"
LOOP_MODEL = "scripts/agent_loop.py"
EVENTS_MODEL = "scripts/run_events.py"
CHECK_KINDS = "architecture/verdict-ledger/check-kinds.json"
STATUS_PATH = TC_DIR + "status.json"
README_PATH = TC_DIR + "README.md"
BRIEF_PATH = TC_DIR + "REVIEW_BRIEF.md"
TC_VECTORS = TC_DIR + "vectors.json"
SCHEMAS = (TC_DIR + "topology-spec.schema.json", TC_DIR + "board-transcript.schema.json",
           TC_DIR + "topology-run-binding.schema.json")
SUBJECT = (README_PATH, BRIEF_PATH) + SCHEMAS + (TC_VECTORS, TC_MODEL)
REVIEWED_SUBJECT = {"commit": "df0b51c4219df7a57a2924ffc2c24ccb51978095", "tree": "1d7042d37679554d9bf0029b64ce1195cb751fa0"}
ROUNDS = ((1, "CHANGES_REQUIRED"), (2, "CHANGES_REQUIRED"), (3, "CHANGES_REQUIRED"), (4, "CHANGES_REQUIRED"),
          (5, "PASS_FOR_SOURCE_PUBLICATION"))
STATUS_KEYS = frozenset({"schemaVersion", "workItem", "status", "contract", "reviewedSubject", "adoptionEdit", "rounds",
                         "carried", "acceptance", "ownerDecisions", "nonClaims", "postReviewRedactions"})
ROW_KEYS = frozenset({"round", "subject", "subjectTree", "verdict", "record", "snapshot", "severities"})
ADOPTION = {"replaced": "Status: **CONTRACT_CANDIDATE**\n(internal, DATA_CHECK_ONLY; independent review round 5 pending).",
            "with": "Status: **ADOPTED_CONTRACT_CANDIDATE**\n(internal, DATA_CHECK_ONLY; independent review round 5: "
                    "PASS_FOR_SOURCE_PUBLICATION; rounds and review records in `status.json`)."}
REDACTED = (BRIEF_PATH,) + tuple(TC_DIR + "round%d/REVIEW_BRIEF.md" % n for n in (1, 2, 3, 4))
PLACEHOLDERS = ("<workspace>/lane-guard/HOLD_BY_VERIFY", "<scratch>/masra004-review.XXXX")
# The removed strings' placeholder forms; no digest of a removed string or of a pre-redaction file is recorded (owner
# P1-3, "Drop the hashes", 2026-10-17).
FORMS = ("<home>/.local/state/harness-onion-ci/lane-guard/HOLD_BY_VERIFY", "<tmp>/masra004-review.XXXX")
PLACEHOLDER_TEXT = {"<workspace>": "the CI state directory of the operator's account",
                    "<scratch>": "the reviewer's temporary directory",
                    "<home>": "the operator account's home directory (withheld)",
                    "<tmp>": "the session's temporary directory (withheld)"}
REDACTION_DECISION = ("LOCAL-PATHS (lane monitor, owner-delegated, 2026-10-16): no absolute local path in a newly published "
                      "harness-onion file; no semantic change; owner P1-3, 2026-10-17: \"Drop the hashes\"; owner PD1-1, "
                      "2026-10-17: \"Accept, fix wording\"")
# Owner PD1-1 (2026-10-17): exactly this text.
RECORDED_AS = ("no digest of a removed string or of a pre-redaction file; the reviewed subjects' git tree and commit ids stay "
               "in the review records and status")
OWNER_DECISIONS = ["MAS-RA-004 (owner)", "Q-M4-1 (a) (monitor)", "Q-M4-2 (a) (owner)", "Q-M4-3 (a) (owner)",
                   "Q-M4-4 (a) (monitor)", "Q-M4-5 (a) (owner)", "Q-M4-6 (a) (monitor)", "Q-M4-7 (a) (monitor)",
                   "Q-M4-8 (a) (monitor)", "Q-M4-9 (a) (owner)", "Q-M4-10 (a) (monitor)", "Q-M4-11 (a) (monitor)"]
ACCEPTANCE = ["MAS-RA-004-A1", "MAS-RA-004-A2", "MAS-RA-004-A3"]
CARRIED = ("M4R5-1",)
# The counts and constants the vectors restate: cases, raw texts, selection rows, kinds cases and v1 embeddings; the
# selection threshold (Q-M4-5 (a), a named parameter) and the check-kinds pin.
COUNTS = {"cases": 95, "texts": 3, "selection": 18, "kindsCases": 2, "embeddings": 2}
SELECTION_THRESHOLD = (45, 100)
KINDS_DIGEST = "sha256:f9193990d9c9d2e103e18d0a0d5522cd262ab43a28c0cc52cb24bceff8d947e8"
# The MAS-RA-001/002/003/008 models and the check-kinds record this contract takes as arguments stay byte-identical.
FROZEN_PATHS = (
    "architecture/verdict-ledger/check-kinds.json",
    "scripts/agent_loop.py",
    "scripts/run_events.py",
    "scripts/run_manifest.py",
    "scripts/verdict_ledger.py",
)
ERA_SHA256 = MappingProxyType({
    "architecture/topology-coordination/README.md": "890af54aa39c6fbec35615bec8cadb5ffa62c33a5ccce0e21b7af5fcd3fb9c90",
    "architecture/topology-coordination/REVIEW_BRIEF.md": "6eb00d5ecf7329c9215c07b0fc44cb6e1815dd723f26dbbf4597afd5049ab52f",
    "architecture/topology-coordination/board-transcript.schema.json": "8a3cc5b87953e97a4b42362df382f9b101931be1d55de84f441b16020b405b7c",
    "architecture/topology-coordination/review-round1.json": "086592ecf26b92c4272b7c9e478363711e43abe97cb3c9a42bd6f31889904b55",
    "architecture/topology-coordination/review-round2.json": "40fcf361b9a30e05d0cbffbb1a332459accd456614a0e95cc5a12cf64e61760b",
    "architecture/topology-coordination/review-round3.json": "5dbe150451847d1deac0dc0208b5c17503e4eeb732fd1e022703d5045f9bc8b4",
    "architecture/topology-coordination/review-round4.json": "e21270fa189ddcc0ffe9cba4774ee716f0c6e17c1393f8e3462650722341fa23",
    "architecture/topology-coordination/review-round5.json": "9c5e083d855ffa8f4f0d1b495a3037e3d26a0e7d087d76d671b153ff188b8b34",
    "architecture/topology-coordination/round1/README.md": "78d74799483291a71e162af8180093f921113da1cf9532413c8de9cd68603704",
    "architecture/topology-coordination/round1/REVIEW_BRIEF.md": "9fad2ef1b65488a20b176850305a763b52fb654a983d004e59c24ed707bf97ba",
    "architecture/topology-coordination/round1/board-transcript.schema.json": "9e6e58196822dc107df385a80ab2de57b92389435da3fac4f33f5ceae4ca76cd",
    "architecture/topology-coordination/round1/scripts/topology_coordination.py": "2b8081792b79b8f1b12d1620af406db2375980ca82e66a057938c4d5ed281afa",
    "architecture/topology-coordination/round1/topology-spec.schema.json": "f5f1814e03626fadaf6f0ea9e531a19f748f17e0bc9e1acb70044afd903f018f",
    "architecture/topology-coordination/round2/README.md": "cc36ce909db12eccc4d42ab31e8879e29c2617d3ede030781515f198ba34cc1a",
    "architecture/topology-coordination/round2/REVIEW_BRIEF.md": "6eb00d5ecf7329c9215c07b0fc44cb6e1815dd723f26dbbf4597afd5049ab52f",
    "architecture/topology-coordination/round2/board-transcript.schema.json": "de77e152bcc7b7597c9f66d147618dbed3457b8d296ad4b6927717082a9f372d",
    "architecture/topology-coordination/round2/scripts/topology_coordination.py": "1947aee0565548e7aa0a3abc7c1d45321b9a3cfdfb525fea2a28fdf222c400c5",
    "architecture/topology-coordination/round2/topology-run-binding.schema.json": "c7ac9539c82285d580ca605b1d8663029991b45c1b6cc4121a80450b8af69709",
    "architecture/topology-coordination/round2/topology-spec.schema.json": "a326f70fd56d4300aa1bfaa3838a888c90347a75fc84164188e4af42052e82d0",
    "architecture/topology-coordination/round3/README.md": "d841bea7fa75c3a18e8277c6d2ace12b7c0d2667a3cad75387c2ac324b9178b8",
    "architecture/topology-coordination/round3/REVIEW_BRIEF.md": "6eb00d5ecf7329c9215c07b0fc44cb6e1815dd723f26dbbf4597afd5049ab52f",
    "architecture/topology-coordination/round3/board-transcript.schema.json": "8a3cc5b87953e97a4b42362df382f9b101931be1d55de84f441b16020b405b7c",
    "architecture/topology-coordination/round3/scripts/topology_coordination.py": "645056744c1b44399d6feb8c8aff36559a7b7ebd99a7633c29d1857e6ef7d244",
    "architecture/topology-coordination/round3/topology-run-binding.schema.json": "c7ac9539c82285d580ca605b1d8663029991b45c1b6cc4121a80450b8af69709",
    "architecture/topology-coordination/round3/topology-spec.schema.json": "a326f70fd56d4300aa1bfaa3838a888c90347a75fc84164188e4af42052e82d0",
    "architecture/topology-coordination/round4/README.md": "e4fbdc8eccbe86472e851398187e84309b91c2d6dc613dd4099f1252091347e1",
    "architecture/topology-coordination/round4/REVIEW_BRIEF.md": "6eb00d5ecf7329c9215c07b0fc44cb6e1815dd723f26dbbf4597afd5049ab52f",
    "architecture/topology-coordination/round4/board-transcript.schema.json": "8a3cc5b87953e97a4b42362df382f9b101931be1d55de84f441b16020b405b7c",
    "architecture/topology-coordination/round4/scripts/topology_coordination.py": "645056744c1b44399d6feb8c8aff36559a7b7ebd99a7633c29d1857e6ef7d244",
    "architecture/topology-coordination/round4/topology-run-binding.schema.json": "c7ac9539c82285d580ca605b1d8663029991b45c1b6cc4121a80450b8af69709",
    "architecture/topology-coordination/round4/topology-spec.schema.json": "a326f70fd56d4300aa1bfaa3838a888c90347a75fc84164188e4af42052e82d0",
    "architecture/topology-coordination/status.json": "2f0d067e13ace0a5e0dcdd1acf69191004e16240a98db4eb839857c9ec65429e",
    "architecture/topology-coordination/topology-run-binding.schema.json": "c7ac9539c82285d580ca605b1d8663029991b45c1b6cc4121a80450b8af69709",
    "architecture/topology-coordination/topology-spec.schema.json": "a326f70fd56d4300aa1bfaa3838a888c90347a75fc84164188e4af42052e82d0",
    "architecture/topology-coordination/vectors.json": "ad177f611d24862e390ddf55268ebd046036b31e176300dd1a2737456b384ec0",
    "architecture/verdict-ledger/check-kinds.json": "d53c5fb8e125c0c6588a327433870a3e6838328e741b12865691c5c2c6e3a3ac",
    "scripts/agent_loop.py": "f9a1fb1441a39efa6e566b26474f25f30106e4bbf6be4919d31ac69dddc48e68",
    "scripts/run_events.py": "3a6a138071dfafe52a471c5bc2d86cea6730e7008e843025393b8301656c49ef",
    "scripts/run_manifest.py": "f2861b4c23ad51fc5b8cdd9910124b23d2c114bd61786e58d93b20f42f3f423e",
    "scripts/topology_coordination.py": "645056744c1b44399d6feb8c8aff36559a7b7ebd99a7633c29d1857e6ef7d244",
    "scripts/verdict_ledger.py": "5b58a689e7c2d4e3f73ede724c92bd3f1085601114f66f8d4ec20ee808906307",
})


def reviewed_bytes(path: str) -> bytes:
    """This packet's reviewed bytes of path; a bridged successor projects newer bytes back first."""
    return successor.historical_bytes(path, regular_bytes(path))


def _verified(path: str) -> bytes:
    """reviewed_bytes, checked against its era digest on every read; a path outside the era is refused before it is
    read."""
    expected = ERA_SHA256.get(path) if type(path) is str else None
    require(expected is not None, "MAS-RA-004 reviewed bytes are bound: " + str(path))
    raw = reviewed_bytes(path)
    require(type(raw) is bytes and digest(raw) == expected, "unreviewed MAS-RA-004 source: " + path)
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


def _era_model(path: str, name: str) -> types.ModuleType:
    """A reference module of this era, executed from its verified bytes (each is standard-library only)."""
    module = types.ModuleType(name)
    module.__file__ = str(ROOT / path)
    exec(compile(_verified(path), path, "exec", dont_inherit=True), module.__dict__)
    return module


def era_modules() -> types.SimpleNamespace:
    """This era's topology model and the four models it takes as arguments."""
    return types.SimpleNamespace(
        tc=_era_model(TC_MODEL, "_met_mas_004_topology_coordination"),
        runs=_era_model(RUNS_MODEL, "_met_mas_004_run_manifest"),
        ledgers=_era_model(LEDGER_MODEL, "_met_mas_004_verdict_ledger"),
        loop=_era_model(LOOP_MODEL, "_met_mas_004_agent_loop"),
        events=_era_model(EVENTS_MODEL, "_met_mas_004_run_events"))


def _snapshot_paths(row: dict) -> set:
    """The round copies an earlier round's row implies: every subject file present at that round and copied whole."""
    kept = [path for path in SUBJECT if path not in row.get("absent", []) and path not in row.get("digestOnly", {})]
    return {row["snapshot"] + (path[len(TC_DIR):] if path.startswith(TC_DIR) else path) for path in kept}


def validate_topology_status() -> None:
    """Adopted after five independent review rounds, each bound to its record, the last a pass with notes only on the
    reviewed subject; the README's one adoption edit is checked by digest, the post-review redaction by its placeholders,
    forms and after digests."""
    status = _json(STATUS_PATH)
    _bound(lambda: type(status) is dict and set(status) == STATUS_KEYS
           and status["schemaVersion"] == "planeon.internal.topology-coordination-status/v1"
           and status["workItem"] == "MAS-RA-004" and status["status"] == "ADOPTED_CONTRACT_CANDIDATE"
           and status["contract"] == {"schemas": list(SCHEMAS), "vectors": TC_VECTORS, "model": TC_MODEL,
                                      "readme": README_PATH}
           and status["reviewedSubject"] == REVIEWED_SUBJECT
           and status["ownerDecisions"] == OWNER_DECISIONS and status["acceptance"] == ACCEPTANCE
           and type(status["nonClaims"]) is list and len(status["nonClaims"]) == 3
           and all(type(claim) is str and claim for claim in status["nonClaims"])
           and type(status["carried"]) is list and tuple(row["item"] for row in status["carried"]) == CARRIED
           and all(row["severity"] == "NOTE" for row in status["carried"]),
           "adopted MAS-RA-004 status with the owner's decisions and its one carried note")
    rounds = status["rounds"]
    _bound(lambda: type(rounds) is list and len(rounds) == len(ROUNDS)
           and all(type(row) is dict and ROW_KEYS <= set(row) <= ROW_KEYS | {"absent", "digestOnly"}
                   for row in rounds)
           and [(row["round"], row["verdict"]) for row in rounds] == list(ROUNDS),
           "five review rounds in order")
    snapshots = set()
    for number, row in enumerate(rounds, 1):
        record = _json(row["record"]) if row["record"] == TC_DIR + "review-round%d.json" % number else None
        last = number == len(ROUNDS)
        _bound(lambda: type(record) is dict
               and record["schemaVersion"] == "harness.planeon.ai/mas-contract-review/v1" and record["round"] == number
               and record["subjectCommit"] == row["subject"] and record["subjectTree"] == row["subjectTree"]
               and record["verdict"] == row["verdict"]
               and record["actions"] == {"filesEdited": False, "networkAccessed": "none", "personalDataSent": False}
               and row["severities"] == sorted({item["severity"] for item in record["findings"]})
               and row["snapshot"] == (None if last else TC_DIR + "round%d/" % number)
               and (last or set(row.get("digestOnly", {})) == {TC_VECTORS})
               and set(row.get("absent", [])) <= set(SCHEMAS),
               "review round %d is bound to its record" % number)
        if not last:
            snapshots |= _snapshot_paths(row)
    final = _json(rounds[-1]["record"])
    _bound(lambda: rounds[-1]["subject"] == REVIEWED_SUBJECT["commit"]
           and rounds[-1]["subjectTree"] == REVIEWED_SUBJECT["tree"]
           and rounds[-1]["severities"] == ["NOTE"]
           and [item["id"] for item in final["findings"]] == list(CARRIED),
           "the passing round reviewed this subject and left notes only")
    copies = {path for path in ERA_SHA256 if path.startswith(TC_DIR + "round")}
    _bound(lambda: copies == snapshots, "the round copies are exactly the earlier rounds' whole subject files")
    edit = status["adoptionEdit"]
    readme = _verified(README_PATH)
    _bound(lambda: edit == dict(ADOPTION, path=README_PATH, reviewedSha256=edit["reviewedSha256"],
                                adoptedSha256=digest(readme))
           and readme.count(ADOPTION["with"].encode("utf-8")) == 1
           and digest(readme.replace(ADOPTION["with"].encode("utf-8"), ADOPTION["replaced"].encode("utf-8")))
           == edit["reviewedSha256"],
           "the README's one adoption edit")
    # Every stored field is checked exactly (review PD1-3): the record equals the one this era implies.
    expected = {"decision": REDACTION_DECISION, "placeholders": PLACEHOLDER_TEXT, "recordedAs": RECORDED_AS,
                "files": [{"path": path, "afterSha256": digest(_verified(path)),
                           "replaced": [{"fromForm": form, "to": to} for form, to in zip(FORMS, PLACEHOLDERS)]}
                          for path in REDACTED]}
    _bound(lambda: status["postReviewRedactions"] == expected
           and all(_verified(path).count(to.encode("utf-8")) == 1 for path in REDACTED for to in PLACEHOLDERS),
           "the post-review redaction of two local paths, by its placeholders and after digests")
    for path in ERA_SHA256:
        raw = _verified(path)
        require(b"/Users/" not in raw and b"/private/" not in raw, "no absolute local path in an era file: " + path)


def _code(check: Any, document: Any, refused: type) -> Any:
    """One check: None and its facts, or the refusal code."""
    try:
        return None, check(document)
    except refused as refusal:
        return refusal.code, None


def replay_vectors(m: types.SimpleNamespace) -> None:
    """Every case, raw text, selection row, kinds case and v1 embedding replays here, through this era's models,
    independently of the model's own replay."""
    tc = m.tc
    vectors = _json(TC_VECTORS)
    kinds = _json(CHECK_KINDS)
    _bound(lambda: {key: len(vectors[key]) for key in COUNTS} == COUNTS
           and vectors["codes"] == {"topology": list(tc.TOPOLOGY_CODES), "transcript": list(tc.TRANSCRIPT_CODES),
                                    "binding": list(tc.BINDING_CODES), "results": list(tc.RESULTS)}
           and tuple(vectors["selectionThreshold"]) == tuple(tc.SELECTION_THRESHOLD) == SELECTION_THRESHOLD
           and vectors["kindsDigest"] == tc.KINDS_DIGEST == KINDS_DIGEST,
           "the topology vectors' counts, codes, threshold and kinds pin")
    stores = vectors["stores"]
    checks = {"topology": lambda d: tc.check_topology(d, stores, m.runs),
              "transcript": lambda d: tc.check_transcript(d, stores, m.runs, m.ledgers, kinds),
              "binding": lambda d: tc.check_binding(d, stores, m.runs)}
    facts_of = {}
    for row in vectors["cases"]:
        got, facts = _code(checks[row["kind"]], row["document"], tc.Refused)
        _bound(lambda: got == row["expect"]
               and ("facts" not in row or {key: facts[key] for key in row["facts"]} == row["facts"]),
               "topology vector replays: %s" % (row.get("id") if type(row) is dict else row,))
        facts_of[row["id"]] = facts
    for row in vectors["texts"]:
        _bound(lambda: _code(lambda text: checks[row["kind"]](tc.parse(text)), row["text"], tc.Refused)[0]
               == row["expect"], "topology raw text replays: %s" % (row.get("id") if type(row) is dict else row,))
    for row in vectors["selection"]:
        _bound(lambda: list(tc.allowed_outcomes(row["taskShape"], tuple(row["score"]))) == row["allowed"],
               "selection row replays: %r" % (row,))
    for row in vectors["kindsCases"]:
        document = next(case["document"] for case in vectors["cases"] if case["id"] == row["transcript"])
        _bound(lambda: _code(lambda d: tc.check_transcript(d, stores, m.runs, m.ledgers, dict(kinds, **row["change"])),
                             document, tc.Refused)[0] == row["expect"], "kinds case replays: %r" % (row,))
    for row in vectors["embeddings"]:
        log, facts = row["log"], facts_of.get(row["transcript"])
        _bound(lambda: m.events.check_log(log, {}, m.loop) is not None
               and [{"operation": event["operation"], "agentId": event["agentId"],
                     "attributes": dict(event["attributes"], tokens=None) if event["operation"] == "MESSAGE"
                     else event["attributes"]}
                    for event in log["events"] if event["operation"] in ("CLAIM", "MERGE", "MESSAGE")] == facts["mapping"]
               and log["events"][0]["agentId"] == facts["rootAgent"],
               "v1 embedding replays: %s" % (row.get("transcript") if type(row) is dict else row,))


def validate_topology_coordination() -> None:
    """Every reviewed byte and the adoption record first; then the models from this era's bytes and the validator-side
    replay of every vector."""
    for path in FROZEN_PATHS:
        require(path not in _PROJECTION_RULES, "the MAS-RA-001/002/003/008 models and the check kinds stay byte-identical")
    for path in ERA_SHA256:
        _verified(path)
    validate_topology_status()
    replay_vectors(era_modules())
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
            == record["validatorNormalizedSha256"], "topology coordination validator drift")
    paths = sorted((ROOT / "task-packets").glob("*.yaml"))
    old = set(record["baselinePackets"])
    require(len(paths) == 267
            and {path.stem for path in paths} == old | {NEW_PACKET, successor.NEW_PACKET, successor.successor.NEW_PACKET, successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.NEW_PACKET},
            "closed 267-packet catalog retaining the 245-packet checkpoint")
    packets = {}
    for path in paths:
        if path.stem in (successor.NEW_PACKET, successor.successor.NEW_PACKET, successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.NEW_PACKET, successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.successor.NEW_PACKET):
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
            "closed source-only topology-coordination packet and inherited commands")
    require(len(packet["allowedPaths"]) == len(set(packet["allowedPaths"]))
            and set(packet["allowedPaths"]) == set(record["changedFiles"])
            | set(record["newFiles"]) | {AUTHORITY_PATH, VALIDATOR_PATH,
                                         "task-packets/" + NEW_PACKET + ".yaml"},
            "unreviewed or omitted topology-coordination packet path")
    for path, rule in record["changedFiles"].items():
        current = successor.historical_bytes(path, regular_bytes(path))
        require(digest(current) == rule["afterSha256"]
                and digest(historical_bytes(path, current)) == rule["beforeSha256"],
                "unreviewed current source: " + path)
    for path, expected in record["newFiles"].items():
        require(digest(successor.historical_bytes(path, regular_bytes(path))) == expected,
                "new source drift: " + path)
    validate_topology_coordination()


if __name__ == "__main__":
    validate()
    print("Topology and coordination v1 valid: 267 current specifications; 245-packet checkpoint and exact 244-packet predecessor; contract reviewed.")
